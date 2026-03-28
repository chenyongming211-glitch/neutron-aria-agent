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

The remaining gaps after the current landing work are:

### 1. Perf stream dataplane is in, ringbuf dataplane is still pending

The dataplane now writes trace events into:

- `TRACE_LOG`
- `TRACE_LOG_V6`
- `TRACE_EVENTS` via `perf event array`

This means the `perf-event-array` backend is now a real dataplane path. The
`ringbuf` backend is still userspace scaffolding until a dedicated ringbuf eBPF
artifact exists.

### 2. Ringbuf packaging is not done yet

The CI/release flow now publishes:

- `libebpf_firewall.so`
- `libebpf_firewall_perf.so`

For the current perf-first rollout, `_perf` is an explicit packaged sibling of
the perf-capable transitional object so resolver auto mode can pick it while
the default base path stays unchanged.

The following artifact still does **not** exist yet:

- `libebpf_firewall_ringbuf.so`

Until ringbuf packaging lands, `auto` can only choose between the base object
and the packaged perf sibling.

### 3. Runtime inventory rollout is only partially done

`core/src/ebpf_ops.rs` now pins `TRACE_EVENTS` alongside the legacy trace maps
and uses backend-aware critical-map expectations:

- `TRACE_FILTER`
- `TRACE_LOG`
- `TRACE_LOG_V6`
- `TRACE_SEQ`
- `TRACE_EVENTS` for stream backends

That fixes attach/recovery/runtime-metadata validation for the perf backend
without forcing legacy-mode runtimes to fail startup.

### 4. Agent-side stream cache still needs rollout validation

The cache is now fed by live perf events, but it still needs runtime validation
on both the older `4.18` target and a newer kernel before the perf backend
should become the default packaged artifact.

## Remaining Work

The refactor is expected to proceed in the following order.

### Phase 2: eBPF event backend split

Current branch status:

- `perf-event-array` output is implemented in `ebpf/src/maps.rs`,
  `ebpf/src/trace.rs`, and the XDP/TC call sites in `ebpf/src/lib.rs`
- legacy `TRACE_LOG` / `TRACE_LOG_V6` writes are intentionally still kept for
  compatibility during the cutover
- ringbuf output is still pending

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
- perf-event-array dataplane output exists
- legacy map writes are still intentionally kept during cutover

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
- perf-event-array dataplane output is in
- backend-aware critical runtime inventory is in
- perf artifact packaging is in
- ringbuf artifact packaging is **not** in yet
- ringbuf dataplane output is **not** in yet

In other words:

**Phase 2 perf cutover is implemented in code; the remaining work is rollout
validation plus the ringbuf follow-up.**

## Optimization Update

After re-reading both the design notes and the current implementation, the
remaining work should be tightened before more code lands.

The current Phase 1 skeleton is directionally correct, but the original plan is
still too broad in one step. The main issue is that it tries to make two
backend families (`ringbuf` and `perf event array`) production-ready at the
same time, before the runtime semantics are fully nailed down.

The better path is:

- define stream semantics first
- cut over one stream backend first
- only then add the second backend as an optimization

### Why the plan needs tightening

The current code already reveals six concrete gaps that the original plan does
not call out strongly enough:

1. Consumer startup is lazy.
   `TraceManager` only starts stream consumers on first `get_trace_events()`
   call. That means events emitted before the first `/trace` read can still be
   lost.

2. Consumer lifecycle is not robust yet.
   A failed stream task can exit after logging a warning, but the manager still
   treats that runtime as "initialized". There is no restart contract yet, and
   there is also no explicit shutdown/removal contract for runtime tasks when a
   runtime is detached or replaced.

3. Stream `flush` semantics are underspecified.
   For stream backends, `flush` currently clears only the userspace cache. A
   concurrent consumer can repopulate the cache immediately with already queued
   events unless the design defines a generation or watermark boundary.

4. Loss visibility is incomplete.
   The perf backend logs kernel-side lost events, but the design does not yet
   require a stable API/metric surface for:
   - kernel stream loss
   - userspace cache eviction
   - consumer restart/failure state

5. Backend rollout gating is missing.
   The current resolver prefers `ringbuf` on `>= 5.8` whenever the sibling
   artifact exists. That means a "perf first, ringbuf later" rollout can still
   be bypassed accidentally if both artifacts are published before ringbuf is
   declared production-ready.

6. Event ordering semantics are not defined yet.
   Legacy map-backed reads sort by `timestamp desc, seq desc`. The current
   stream cache returns insertion order from asynchronous consumer tasks, which
   is not equivalent under multi-CPU perf readers and would create a user-
   visible behavior change unless ordering is explicitly redefined.

These are not reasons to stop the refactor. They are reasons to narrow the next
phase so the first real cutover is easier to prove correct.

## Optimized Execution Order

The recommended order is now:

### Phase 1.5: Runtime semantics hardening

Before any real dataplane cutover:

- start stream consumers eagerly when a runtime is registered, not on first
  `/trace` read
- add explicit consumer lifecycle ownership:
  - startup
  - runtime refcount / register-unregister boundary
  - shutdown
  - retry / failure state
- define `flush` semantics for stream mode:
  - use a per-CPU watermark derived from pinned `TRACE_SEQ`
  - keep it tap-scoped in userspace
  - do not use "best effort cache clear"
- define event ordering semantics explicitly:
  - preserve legacy newest-first behavior on reads
  - implement that by sorting cached events on read in Phase 1.5
- add an explicit backend rollout gate so `perf-first` remains true in
  production:
  - config override
  - feature flag
  - or resolver preference switch
- add explicit counters for:
  - kernel lost stream events
  - userspace cache evictions
  - consumer restarts / failures

This phase should stay userspace-only as much as possible.

### Phase 2: Perf-event cutover first

Do **not** land ringbuf and perf cutover together.

Instead:

- implement `TRACE_EVENTS` using `perf event array`
- make `perf event array` the first real stream backend
- update managed and standalone runtime pinning/inventory so `TRACE_EVENTS`
  is pinned in both paths
- validate it on both:
  - `4.18`
  - `6.8`

Why perf first:

- it solves the real problem host (`4.18`) directly
- it avoids debugging two kernel transport paths at once
- it lets the team validate the new agent-side cache and flush semantics with a
  single dataplane change

If this phase works, the architecture is proven. Ringbuf can then be treated as
an optimization, not a correctness dependency.

One important implementation detail:

- `TRACE_EVENTS` cannot simply be dropped into a static global
  `CRITICAL_NETWORK_MAP_NAMES` list while legacy and stream artifacts still
  coexist, unless every artifact also exposes that map
- otherwise startup/runtime metadata checks will fail for the legacy object

So this phase should either:

- make critical-map expectations backend-aware
- or ensure all transitional artifacts expose a compatible `TRACE_EVENTS` map

### Phase 3: Packaging and rollout for perf backend

After perf cutover works:

- keep CI publishing the perf-capable artifact and its explicit `_perf` sibling
- ensure `auto` selection still resolves to perf during this phase
- wire runtime selection so normal deployments can actually pick it
- rerun churn retention tests

This is earlier than in the original plan because packaging is not auxiliary.
Without real artifact rollout, the refactor remains scaffolding.

### Phase 4: Add ringbuf as a newer-kernel optimization

Only after perf mode is stable:

- add real ringbuf dataplane output
- validate feature parity against perf mode
- enable `>= 5.8` kernels to prefer ringbuf

At this point ringbuf is a bounded optimization step, not the main cutover.

### Phase 5: Remove legacy trace storage dependence

Only after one stream backend is proven in production-like testing:

- update runtime inventory
- stop treating `TRACE_LOG` / `TRACE_LOG_V6` as active-path requirements
- simplify cleanup logic

## Additional Recommendations

### 1. Make loss visible in API or metrics

Today the design preserves `/trace` payload shape, but not enough operational
state. The final design should expose at least metrics for:

- stream events received
- stream events lost in kernel transport
- stream events dropped by userspace cache truncation
- active consumer health

Without that, retention improvements will be difficult to validate in the
field.

### 2. Keep flush semantics stable before removing legacy maps

Legacy flush removes kernel-stored events.

Stream flush currently removes cached events only.

That semantic difference is acceptable only if it is explicit and race-safe.
The refactor should document exactly what a successful `DELETE /trace` means in
stream mode.

Do not rely on a single tap-wide `seq` watermark unless the dataplane first
introduces a truly global monotonic sequence.

The best fit for the current code is a per-CPU watermark vector keyed by
`cpu_id`, captured from pinned `TRACE_SEQ` at flush time:

- `TRACE_SEQ` already exists and is per-CPU
- each stream event already carries `cpu_id` and `seq`
- reads can discard cached events older than the tap's recorded CPU-local
  watermark

This keeps Phase 1.5 mostly userspace-side while still making `flush` race-safe
against in-flight perf events already queued in the kernel.

### 3. Add a first-read regression test

Because consumer startup is currently lazy, the refactor should add a test for:

- enable trace filter
- emit packets before any `/trace` read
- verify those first events are still available

This is an easy issue to miss and will otherwise reappear later.

### 4. Add detach / re-register lifecycle tests

The stream backend must be tested across:

- tap detach
- tap recreate
- agent restart
- consumer failure / reattach

The current document mentions retention and packaging, but not enough lifecycle
validation.

This matrix should cover both:

- tap-managed shared runtime
- standalone `system` runtime

### 5. Treat runtime task ownership as a first-class API

Because tasks are currently keyed only by runtime pin path, the final design
should expose explicit runtime-scoped hooks such as:

- `register_runtime(pin_path)`
- `unregister_runtime(pin_path)`
- `start_consumers(pin_path)`
- `stop_consumers(pin_path)`

This avoids hiding lifecycle behind the first `/trace` read and makes shared
runtime migration easier to reason about later.

### 6. Preserve read ordering as an explicit contract

If the external `/trace` contract is meant to stay stable, stream-backed reads
should continue to return newest events first.

That likely means one of:

- sort cached events on read using `timestamp` plus a stable tie-breaker
- maintain an explicitly ordered cache on insert
- document and version any intentional behavior change

This needs to be settled before the first real perf cutover, because CLI output
and troubleshooting workflows already depend on readable ordering.

## Updated Recommendation

The refactor should now be treated as:

1. userspace semantics hardening
2. perf-only production cutover
3. packaging and retention validation
4. ringbuf optimization
5. legacy cleanup

That order reduces risk, shortens the path to a real fix on old kernels, and
avoids carrying two half-finished stream backends at once.
