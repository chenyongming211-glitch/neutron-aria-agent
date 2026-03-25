# Aria Firewall Kernel Drop Observability Design

Status: Implemented in v0.8.0 (core path), with deprecation cleanup deferred
Date: 2026-03-25
Scope: Replace CLI/API-facing `drops` semantics with host-global kernel drop attribution while preserving existing firewall rule/QoS drop accounting.

## 1. Background

The current `ariactl drops` command exposes firewall-local drop aggregation backed by `DROP_REASON_STATS`.

That data is still useful, but it represents only drops caused by Aria policy and QoS decisions:

- ACL deny
- ACL port deny
- ACL default deny
- QoS ingress drop
- QoS egress drop

It does not answer the broader operational question "where in the kernel networking stack are packets being dropped?"

The desired end state is:

- `ariactl drops` becomes a kernel drop attribution tool
- firewall-local drop counters remain available from rule and QoS statistics
- kernel drop observability is managed as a host-global subsystem, not a per-instance dataplane feature

## 2. Goals

- Introduce host-global kernel drop observability independent from per-instance shared runtime lifecycle.
- Attribute kernel drops to managed interfaces only, avoiding host-wide noise from unrelated devices.
- Support filtering by Aria instance and interface.
- Preserve backward compatibility during migration.
- Keep the initial implementation small, verifier-safe, and operationally predictable.

## 3. Non-Goals

- No attempt to make the first release a complete kernel drop monitor for every drop path.
- No hot upgrade of live kernel-drop programs in this workstream.
- No removal of existing firewall-local drop accounting from `RULE_STATS` or `QOS_STATS`.
- No attempt to infer synthetic drop reasons from unrelated kernel fields.

## 4. Current State

Today the `drops` command and `/api/v1/{instance}/stats/drops` are backed by:

- `ebpf/src/drops.rs`
- `core/src/drop_ops.rs`
- `agent/src/api_handlers.rs`
- `user/src/main.rs`

The current key space is firewall-specific:

- `tap_id`
- `reason`
- `direction`
- `proto`
- `src_id`
- `dst_id`

This must remain available for rule/QoS observability, but it should no longer be the primary user-facing meaning of "drops".

## 5. High-Level Design

### 5.1 Separate subsystem

Kernel drop observability will be implemented as a dedicated host-global subsystem:

- new manager: `agent/src/kernel_drop_manager.rs`
- new pin namespace: `kernel-drops-global`
- new global maps/programs/links that do not live inside per-instance shared runtime

This follows the same architectural pattern as the existing host-global SSL manager.

### 5.2 Canonical first hook

The first implementation will attach a single canonical tracepoint:

- `tracepoint/skb/kfree_skb`

Rationale:

- one hook avoids duplicate counting across multiple drop paths
- `kfree_skb` exists across a wider kernel range than more specialized variants
- newer kernels expose a drop reason directly in the tracepoint payload
- older kernels do not; in that case reason is treated as unavailable rather than guessed

### 5.3 Managed-interface filtering

A host-global filter map will constrain statistics to interfaces managed by Aria:

- map: `MANAGED_IFINDEX_FILTER`
- key: `ifindex`
- value: `{ tap_id }`

Only events whose `ifindex` exists in this map will be counted toward instance-visible kernel drop statistics.

This keeps the feature focused on Aria-managed networking and prevents unrelated host interfaces from polluting the view.

### 5.4 Conservative capability model

The first release treats BTF/CO-RE support as a feature requirement for full kernel-drop observability.

If the manager cannot safely read the fields required to extract `ifindex`, the subsystem should be reported as unavailable rather than fabricating a weak fallback.

## 6. eBPF Design

### 6.1 New maps

Add the following maps in `ebpf/src/maps.rs`:

- `MANAGED_IFINDEX_FILTER: HashMap<u32, KernelDropFilterValue>`
- `KERNEL_DROP_CONFIG: HashMap<u32, KernelDropConfig>`
- `KERNEL_DROP_STATS: LruPerCpuHashMap<KernelDropKey, KernelDropValue>`
- `KERNEL_DROP_VALUE_BUF: PerCpuArray<KernelDropValue>`

Recommended starting capacity:

- `MANAGED_IFINDEX_FILTER`: 1024
- `KERNEL_DROP_STATS`: 4096

### 6.2 New common structs

Add matching layout definitions in:

- `ebpf/src/common.rs`
- `core/src/common.rs`

Recommended structures:

- `KernelDropFilterValue { tap_id: u32 }`
- `KernelDropConfig { flags, tracepoint field offsets, sk_buff/net_device member offsets }`
- `KernelDropKey { tap_id: u32, ifindex: u32, reason_code: u16, proto: u16 }`
- `KernelDropValue { packets: u64, bytes: u64, last_seen_ns: u64, last_location: u64 }`

`last_location` stays in the value, not the key, to avoid exploding cardinality.

### 6.3 Program structure

Add a dedicated module:

- `ebpf/src/kernel_drops.rs`

Responsibilities:

- read tracepoint context
- use runtime-supplied offsets from `KERNEL_DROP_CONFIG`
- perform null checks before dereferencing `skb->dev`
- read `ifindex`
- read packet length if available
- read protocol if available
- read drop reason if available
- consult `MANAGED_IFINDEX_FILTER`
- update `KERNEL_DROP_STATS`

### 6.4 Safety constraints

The tracepoint program must remain intentionally simple:

- no complex branching
- no stack-heavy temporary structures
- use `KERNEL_DROP_VALUE_BUF` instead of large stack allocations
- always null-check `skb->dev` before reading fields
- do not synthesize reason codes from unrelated fields

### 6.5 Compatibility behavior

There are two runtime modes:

- `reasonful`: kernel tracepoint payload exposes a real drop reason
- `legacy_no_reason`: tracepoint payload does not expose a real drop reason

In `legacy_no_reason` mode:

- `reason_code` is reported as unavailable or zero
- `reason` is rendered as `"unknown"`
- `location` may still be retained as raw metadata for debugging

The initial implementation will populate `KERNEL_DROP_CONFIG` from userspace by:

- parsing `/sys/kernel/tracing/.../kfree_skb/format` for tracepoint payload offsets
- parsing `/sys/kernel/btf/vmlinux` for `sk_buff.dev`, `sk_buff.len`, and `net_device.ifindex`

This keeps the eBPF program verifier-safe while avoiding hard-coded kernel layout offsets.

## 7. Core Library Design

Add:

- `core/src/kernel_drop_ops.rs`

Responsibilities:

- open and read `KERNEL_DROP_STATS`
- support filtering by `tap_id`, `ifindex`, `reason_code`
- flush the map
- expose reason rendering helpers

Export from:

- `core/src/lib.rs`

Recommended API surface:

- `get_kernel_drop_stats(pin_path, filter)`
- `flush_kernel_drop_stats(pin_path, filter)`
- `kernel_drop_reason_name(code) -> String`

## 8. Agent Design

### 8.1 New manager

Add:

- `agent/src/kernel_drop_manager.rs`

Responsibilities:

- own host-global pin namespace
- load/pin kernel-drop programs and maps
- attach tracepoint link
- maintain a small in-memory status view
- maintain `MANAGED_IFINDEX_FILTER`

Recommended public methods:

- `new(ebpf_path, base_pin_path)`
- `ensure_loaded()`
- `sync_managed_iface(iface, ifindex, tap_id)`
- `remove_managed_iface(ifindex)`
- `status_snapshot()`

### 8.2 Lifecycle integration

Managed mode:

- after successful attach/publish, register `(ifindex -> tap_id)` in `MANAGED_IFINDEX_FILTER`
- after successful detach, remove that mapping

System mode:

- register the standalone interface as a special managed interface
- keep user-facing naming at `"system"` while kernel filtering still uses `ifindex`

This integration belongs in the agent lifecycle path, not the control-plane rule logic.

### 8.3 Failure semantics

Kernel drop observability must not block the firewall dataplane:

- manager init failure: warn and continue
- map sync failure: warn and continue
- API should surface unavailability clearly when the subsystem is disabled

## 9. API Design

### 9.1 New canonical endpoint

Add host-global endpoints:

- `GET /api/v1/stats/kernel_drops`
- `DELETE /api/v1/stats/kernel_drops`

Recommended query parameters:

- `instance`
- `iface`
- `ifindex`
- `reason`
- `top`
- `include_unattributed`

### 9.2 Response schema

Add new API types in `api/src/lib.rs`:

- `KernelDropStatsEntry`
- `KernelDropStatsResponse`
- `KernelDropFlushResponse`

Recommended fields:

- `instance: Option<String>`
- `iface: Option<String>`
- `ifindex: u32`
- `reason_code: Option<u16>`
- `reason: String`
- `proto: String`
- `packets: u64`
- `bytes: u64`
- `last_seen_ns: u64`
- `last_location: Option<u64>`
- `source: String`

`source` should distinguish at least:

- `kfree_skb_reasonful`
- `kfree_skb_legacy`

### 9.3 Legacy endpoint policy

Existing endpoint:

- `/api/v1/{instance}/stats/drops`

Compatibility plan:

- keep it temporarily
- preserve old firewall-drop semantics
- mark it deprecated
- do not merge kernel-drop data into the old schema

Recommended response headers:

- `Deprecation: true`
- `Sunset: <date>`
- `Link: </api/v1/stats/kernel_drops?...>; rel="successor-version"`

## 10. CLI Design

CLI command:

- `ariactl drops`

New meaning:

- kernel drop attribution for Aria-managed interfaces

Recommended behavior:

- `ariactl drops list` shows all managed interfaces
- `ariactl drops list --tap <instance>` filters by Aria instance
- `ariactl drops list --iface <name>` filters by interface name
- `ariactl drops flush --force` clears kernel-drop statistics

Firewall-local active drops remain visible through:

- `ariactl stats --rules`
- `ariactl stats --qos`

## 11. Metrics

The implementation now exports:

- `aria_kernel_drop_observability_up`
- `aria_kernel_drop_managed_ifaces`
- `aria_kernel_drop_mode_info`
- `aria_kernel_drop_last_error`
- `aria_kernel_drop_packets_total`
- `aria_kernel_drop_bytes_total`

Labels stay conservative:

- `instance`
- `iface`
- `ifindex`
- `reason`
- `proto`
- `source`

Do not expose high-cardinality raw locations as labels.

## 12. Health

`GET /api/v1/health` now includes:

- `kernel_drop_available`
- `kernel_drop_mode`
- `kernel_drop_managed_ifaces`
- `kernel_drop_last_error`

## 13. Delivery Plan

### Phase 0

- add this design document
- add `KernelDropManager` framework
- initialize it in `aria-agent`

### Phase 1

- add eBPF tracepoint program
- add `MANAGED_IFINDEX_FILTER`
- add `KERNEL_DROP_STATS`

### Phase 2

- add `core/src/kernel_drop_ops.rs`
- integrate manager with attach/detach lifecycle

### Phase 3

- add new API endpoints
- add deprecation headers to old drops endpoint

### Phase 4

- switch `ariactl drops` to the new kernel-drop endpoint

### Phase 5

- document migration
- remove legacy CLI/API path after the deprecation window

## 14. Explicit Design Decisions

- Use a host-global manager, not per-instance shared runtime state.
- Use `tracepoint/skb/kfree_skb` as the canonical first hook.
- Filter to managed interfaces before counting.
- Require real kernel capability for `ifindex` extraction instead of inventing a weak fake fallback.
- Keep old firewall drop accounting intact, but move it out of the primary `drops` UX.
- Keep kernel-drop statistics separate from rule/QoS statistics at the API schema level.

## 15. Open Questions

- Whether the first production release should expose unattributed early drops by default or behind an explicit flag.
- Whether the CLI should show raw `last_location` in a debug mode.
- The exact deprecation window for `/api/v1/{instance}/stats/drops`.
