# Trace Backend Refactor Status

This document records the current state of the packet-trace backend refactor so
other feature work can proceed without losing the context of what has already
been changed and what is still intentionally pending.

## Why This Refactor Exists

The current trace implementation stores recent events in global pinned LRU maps:

- `TRACE_LOG`
- `TRACE_LOG_V6`

That design works functionally, but it has a retention problem under high churn
on older kernels with high CPU fanout. The concrete issue observed during
testing was:

- on `4.18` with many active CPUs, `TRACE_LOG` retention under `5k` event churn
  was materially below the configured `4096` entries
- on `6.8` with low CPU fanout, retention stayed much closer to the configured
  capacity

The root problem is not trace filtering or API reading; it is the choice of
`LruHashMap` as the storage backend for a high-rate event stream.

The chosen direction is:

- `>= 5.8`: use `ringbuf`
- older kernels or unsupported environments: use `perf event array`
- keep the `/trace` API and CLI behavior stable by buffering recent events in
  userspace inside the agent

## Scope Boundary

This refactor is intended to change only the trace event transport and storage
path.

It should **not** change the correctness of:

- ACL
- QoS
- Mirror
- TCP-RT
- conntrack / policy / statistics logic

It **does** affect:

- trace eBPF event output
- trace userspace collection
- trace cache / flush semantics
- eBPF artifact selection
- runtime map inventory and scrub logic

## Completed Work

### 1. Trace functional fixes already landed before backend refactor

Relevant commit:

- `c2b1432` `Trace XDP ACL drops in packet trace`

This fixed the missing trace event for XDP-side ACL drops by adding explicit
`xdp-drop` trace emission.

### 2. Phase 1 userspace/backend skeleton is complete

Relevant commit:

- `a8d827d` `Add trace backend skeleton and eBPF resolver`

This phase intentionally does **not** switch the dataplane to ringbuf/perf yet.
It only lays down the userspace and artifact-selection structure required for
the later cutover.

#### Files added

- `agent/src/ebpf_binary.rs`
- `agent/src/trace_backend.rs`

#### Files updated

- `agent/src/main.rs`
- `agent/src/control_plane.rs`
- `core/src/common.rs`
- `core/src/trace_ops.rs`
- `ebpf/src/common.rs`

### 3. What Phase 1 changed

#### 3.1 eBPF binary resolver added

`agent/src/ebpf_binary.rs` now resolves the effective eBPF binary path and
declares the intended trace backend.

Selection behavior:

- if config points directly to a file ending with `_ringbuf`, use `ringbuf`
- if config points directly to a file ending with `_perf`, use `perf event`
- otherwise:
  - if kernel `>= 5.8` and sibling `<base>_ringbuf.so` exists, use that
  - else if sibling `<base>_perf.so` exists, use that
  - else fall back to the configured single legacy object and `legacy-map`

This means the agent is already ready for dual-object packaging, even though the
build pipeline has not been updated yet.

#### 3.2 Trace backend manager added

`agent/src/trace_backend.rs` introduces `TraceManager`.

Current responsibilities:

- represent the selected trace backend:
  - `legacy-map`
  - `perf-event-array`
  - `ringbuf`
- preserve the current `/trace` semantics through an agent-side bounded cache
- route `get_trace_events()` and `flush_trace()` through a single abstraction

Current behavior by backend:

- `legacy-map`
  - still reads from `TRACE_LOG` / `TRACE_LOG_V6`
  - still flushes via the existing pinned map delete logic
- `perf-event-array`
  - has a userspace collector skeleton
  - stores recent events in the agent cache
- `ringbuf`
  - has a userspace collector skeleton
  - stores recent events in the agent cache

#### 3.3 ControlPlane moved to backend abstraction

`agent/src/control_plane.rs` no longer calls `trace_ops::get_trace_events()`
and `trace_ops::flush_trace_log()` directly from the HTTP-facing path.

Instead it now uses `TraceManager` for:

- `get_trace_events()`
- `flush_trace()`

The unregister path also clears the trace cache for the tap before the runtime
state is scrubbed.

#### 3.4 Shared trace stream event shape added

`core/src/common.rs` and `ebpf/src/common.rs` now define `TraceStreamEvent`.

This is intentionally separate from the old:

- `TraceEventKey`
- `TraceEvent`
- `TraceEventV6`

Reason:

- map-based trace stored metadata partly in the key
- stream-based trace has no map key
- therefore the stream payload must carry:
  - `tap_id`
  - `cpu_id`
  - `seq`
  - IPv4/IPv6 data
  - trace result metadata

`core/src/trace_ops.rs` now includes `trace_event_entry_from_stream()` so both
legacy and future stream backends can produce the same API-visible event shape.

## What Is Intentionally Not Done Yet

The following items are **not** implemented yet and are still pending:

### 1. eBPF trace output is still legacy

The dataplane still writes trace events into:

- `TRACE_LOG`
- `TRACE_LOG_V6`

There is no active `TRACE_EVENTS` ringbuf/perf event producer in the eBPF
program yet.

This means the new `TraceManager` stream backends are currently scaffolding only.

### 2. Dual artifact packaging is not done yet

The CI and release packaging still build and publish a single eBPF artifact:

- `libebpf_firewall.so`

The following artifacts do **not** exist yet:

- `libebpf_firewall_ringbuf.so`
- `libebpf_firewall_perf.so`

Until CI/package changes land, runtime selection will keep falling back to the
legacy single object in normal deployments.

### 3. Runtime map inventory has not been changed yet

`core/src/ebpf_ops.rs` still treats the trace maps as part of the pinned runtime
inventory:

- `TRACE_FILTER`
- `TRACE_LOG`
- `TRACE_LOG_V6`
- `TRACE_SEQ`

This was intentionally left unchanged in Phase 1, because changing inventory
before the dataplane cutover would risk breaking the current working legacy
trace path.

### 4. Agent-side stream cache is not wired to live eBPF output yet

The cache exists, but it is not fed by real dataplane stream events yet because
the stream-producing maps/program logic are not in place.

## Remaining Work

The refactor is expected to proceed in the following order.

### Phase 2: eBPF event backend split

Implement real stream-producing trace backends in eBPF:

- ringbuf-backed trace event output for newer kernels
- perf-event-array-backed trace event output for older kernels

Expected code areas:

- `ebpf/src/maps.rs`
- `ebpf/src/trace.rs`
- possibly small call-site adjustments in `ebpf/src/lib.rs`

### Phase 3: dual eBPF artifacts and runtime selection

Update build/release flow so CI emits both:

- `*_ringbuf`
- `*_perf`

Expected code areas:

- `.github/workflows/build.yml`
- release packaging logic
- any install/release documentation that currently assumes a single
  `libebpf_firewall.so`

### Phase 4: runtime inventory and scrub cleanup

After dataplane cutover is real, update runtime inventory and scrub paths so
they no longer depend on the legacy trace LRU maps.

Expected code area:

- `core/src/ebpf_ops.rs`

Likely final shape:

- keep `TRACE_FILTER`
- keep sequence state only if still needed
- remove `TRACE_LOG` / `TRACE_LOG_V6` from the legacy-required inventory once
  stream backends are fully adopted

### Phase 5: retest high churn retention

After the backend switch:

- rerun `1k / 2k / 5k` trace churn tests
- compare `4.18` and `6.8`
- verify retention is no longer materially degraded on `4.18` multi-CPU hosts

## Important Cautions For Ongoing Work

While other code changes are happening in parallel, keep these constraints in
mind:

### Do not remove legacy trace maps yet

`TRACE_LOG` and `TRACE_LOG_V6` are still the active dataplane path today.
Removing or de-inventorying them before Phase 2/3 is complete will break trace.

### Do not assume `TraceManager` means stream backend is live

At the current state:

- the userspace abstraction exists
- stream cache exists
- binary selection exists
- but the dataplane still writes legacy map events

### Do not collapse back to a single backend-specific API

The point of the current structure is to keep:

- API shape stable
- CLI stable
- backend selection isolated

Future changes should continue to route trace reads/flushes through
`TraceManager`, not restore direct ControlPlane coupling to a specific storage
backend.

## Current Status Summary

Current status can be summarized as:

- trace functional fixes are in
- userspace backend abstraction is in
- eBPF object selection skeleton is in
- stream event schema is in
- actual ringbuf/perf dataplane output is **not** in yet
- CI dual-object packaging is **not** in yet

In other words:

**Phase 1 scaffolding is complete; Phase 2 dataplane cutover is still pending.**
