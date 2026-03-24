# Aria Firewall Global Shared Data Plane Design

Status: Draft
Date: 2026-03-23
Scope: high-density tap deployment, shared XDP/TC data plane, memory scaling, per-instance control-plane compatibility

## 1. Background

The current tap-managed architecture loads one full eBPF object per tap interface.

Evidence in the current tree:

- `agent/src/tap_registry.rs` creates one `FirewallInstance` per tap.
- `agent/src/instance.rs` loads, pins, attaches, and detaches one full XDP/TC runtime per interface.
- `ebpf/src/maps.rs` defines several large preallocated maps:
  - `CT_TABLE_V4 = 262144`
  - `CT_TABLE_V6 = 65536`
  - `RULE_STATS = 65536`
  - `TCPRT_TABLE_V4 = 65536`
  - `SSL_CONN_TABLE = 16384`
  - `SSL_HTTP_TABLE = 16384`

Operational testing on the current build shows that memory consumption scales with the number of tap instances because each tap gets its own full map set.

This becomes the dominant bottleneck on physical hosts with 20-40 tap interfaces.

## 2. Problem Statement

The current architecture has four structural problems:

1. Memory scales roughly linearly with tap count because the data plane is duplicated per interface.
2. Attach and detach are expensive because every new tap loads a full eBPF object and pins a new map namespace.
3. Monitoring and metrics must iterate one map namespace per instance.
4. Per-tap state is stored by instance name, but runtime separation is currently implemented through per-tap pin paths instead of explicit runtime keys.

The fix is not to tune individual map sizes further. The fix is to stop duplicating the entire data plane per tap.

## 3. Design Goals

- Load the tap-managed XDP/TC data plane once per agent process.
- Share one map set across all tap-managed interfaces.
- Preserve per-instance REST and CLI semantics such as `/{instance}/groups`, `/{instance}/policies`, `/{instance}/stats`, and WAL/state replay by instance name.
- Preserve runtime isolation between taps.
- Make memory growth depend primarily on real traffic volume and configured rules, not on tap count.
- Keep room for later density profiles and map size tuning without another architecture change.

## 4. Non-Goals

- No redesign of SSL observability in this document. SSL is already host-global and remains a separate subsystem.
- No change to external policy or group APIs in phase 1.
- No immediate removal of legacy per-tap state directories under the existing state root.
- No in-place reuse of old pinned map layouts with incompatible key schemas.

## 5. Core Design Decisions

### 5.1 Use `tap_id`, not raw `ifindex`, as the primary runtime namespace

Heavy data-plane keys must not be keyed directly by raw `ifindex`.

Reason:

- `ifindex` is runtime-local and can change when an interface is recreated.
- WAL and persisted state are keyed by instance name today.
- We need a stable namespace identifier for persisted policy/state ownership.

Decision:

- Introduce a stable `tap_id: u32` per managed instance.
- Persist `tap_id` in per-instance state.
- Introduce a small runtime map from `ifindex -> tap_id`.
- Use `tap_id` in heavy map keys.

This keeps interface recreation cheap: only the small runtime mapping needs to change.

### 5.2 Load the tap-managed eBPF object once and attach it many times

The tap-managed firewall runtime will move from:

- one `FirewallInstance` loading one `aya::Ebpf` object per tap

to:

- one shared tap data-plane manager loading one `aya::Ebpf`
- one shared pin namespace for tap-managed XDP/TC maps and programs
- one link record per attached interface

Recommended shared pin path:

- `/sys/fs/bpf/aria/global-v2`

`global-v2` is intentional. The shared-map migration changes key layouts and must not reuse the old per-tap pin ABI.

### 5.3 Preserve per-instance control-plane state

Per-instance `state.json` and `state.wal` remain valid and continue to live under per-instance state paths such as:

- `/var/lib/aria-agent/<instance>/state.json`
- `/var/lib/aria-agent/<instance>/state.wal`

The control plane still exposes instance-local semantics, but replay now writes into shared maps with the instance's `tap_id`.

## 6. Shared Runtime Model

### 6.1 New small runtime maps

Introduce at least these maps:

- `IFACE_CTX_MAP: HashMap<u32, IfaceCtx>`
  - key: `ifindex`
  - value: `{ tap_id, flags/version metadata if needed }`
- `TAP_CONFIG_MAP: HashMap<u32, FirewallConfig>`
  - key: `tap_id`
  - value: per-tap runtime feature flags

`IFACE_CTX_MAP` is the fast path from packet context to stable namespace.

`TAP_CONFIG_MAP` replaces the current single-entry `FIREWALL_CONFIG` semantics for tap-managed interfaces.

### 6.2 Shared large data-plane maps

One shared map instance will back all tap-managed interfaces.

Maps that must become tap-aware:

- `POLICY_TABLE`
- `PORT_BITMAP_POOL`
- `CT_TABLE_V4`
- `CT_TABLE_V6`
- `RULE_STATS`
- `FLOW_STATS_V4`
- `FLOW_STATS_V6`
- `QOS_CONFIG`
- `QOS_TOKEN_BUCKET`
- `QOS_STATS`
- `GROUP_STATS`
- `MIRROR_POLICY`
- `MIRROR_GLOBAL`
- `MIRROR_STATS`
- `MIRROR_GLOBAL_STATS`
- `TCPRT_TABLE_V4`
- `TCPRT_TABLE_V6`
- `DROP_REASON_STATS`
- `TRACE_FILTER`
- `TRACE_LOG`

## 7. Required Key-Schema Changes

### 7.1 Heavy map keys

The following structs in both `ebpf/src/common.rs` and `core/src/common.rs` must gain `tap_id`:

- `PolicyKey`
- `PortKey`
- `CtKey4`
- `CtKey6`
- `QosKey`
- `GroupStatsKey`
- `MirrorKey`
- `GlobalMirrorKey`
- `DropKey`

`PortKey` is easy to miss. It must also become tap-aware because `bitmap_idx` is currently allocated per instance, not globally.

### 7.2 Trace data

`TraceEvent` must carry `tap_id`.

`TRACE_FILTER` must stop being a single-entry global filter keyed only by `0`.

Recommended phase-1 behavior:

- key `TRACE_FILTER` by `tap_id`
- keep one per-tap trace filter
- add `tap_id` to `TraceEvent`

### 7.3 LPM trie redesign for group lookup

This is the most important hidden change.

Today the source and destination tries map IP prefix directly to `group_id`:

- `SRC_IPV4_TRIE`
- `DST_IPV4_TRIE`
- `SRC_IPV6_TRIE`
- `DST_IPV6_TRIE`

That does not work in a shared map world because two taps may use overlapping CIDRs with different local group IDs.

The trie key must become tap-aware.

Recommended new layout:

- IPv4 trie key bytes: `tap_id_be || ipv4_addr`
- IPv6 trie key bytes: `tap_id_be || ipv6_addr`
- prefix length:
  - IPv4: `32 + cidr_prefix`
  - IPv6: `32 + cidr_prefix`

Lookup then uses:

- full key `tap_id_be || packet_ip`

This preserves independent group resolution per tap while keeping one shared trie.

## 8. Data-Plane Changes

### 8.1 Entry-point flow

In `ebpf/src/lib.rs`:

- XDP ingress must read interface context from packet context and resolve `tap_id`.
- TC ingress and TC egress must do the same.
- `PipelineCtx` should carry at least:
  - `tap_id`
  - optionally `ifindex` for debugging

All later phases use `tap_id`, not per-tap pin namespaces.

### 8.2 Per-tap config reads

Current helpers such as:

- `policy::acl_enabled()`
- `qos::qos_enabled()`
- `mirror::mirror_enabled()`
- `tcprt::tcprt_enabled()`
- `stats::monitoring_enabled()`

implicitly read a single `FIREWALL_CONFIG` entry.

That must be changed to:

- read `TAP_CONFIG_MAP[tap_id]`
- fall back to sane defaults if missing

### 8.3 Runtime cleanup

Detach must not only remove links.

For a detached tap we also need explicit cleanup of dynamic shared-map state, at minimum:

- conntrack entries
- flow stats
- TCP-RT state
- trace events and trace filter
- drop stats

Policy, groups, QoS, mirror config, and tap config are still removed through normal instance-level control-plane operations or explicit unregister cleanup.

## 9. Control-Plane Changes

### 9.1 Replace per-tap data-plane ownership

`agent/src/tap_registry.rs` and `agent/src/instance.rs` currently assume:

- one instance object per interface
- one pin path per interface
- one eBPF object per interface

This must become:

- one shared tap data-plane manager
- one attached-link record per interface
- one runtime record per instance:
  - `instance name`
  - `tap_id`
  - `ifindex`
  - `state_path`
  - shared `pin_path`

`instance.rs` should either be removed or reduced to link-management only.

### 9.2 Register and unregister semantics

`ControlPlane::register_instance` must stop deriving a per-instance pin path.

Instead it must accept or resolve runtime metadata from the registry:

- shared pin path
- `tap_id`
- current `ifindex`
- per-instance state path

`InstanceState` should gain:

- `tap_id`
- `ifindex`

and continue storing:

- `state`
- `state_path`
- `wal`

### 9.3 User-space map operations

All user-space map helpers that currently rely on `{pin_path}/...` as the namespace boundary must be refactored to use:

- one shared pin path
- one explicit `tap_id`

This affects:

- `core/src/ebpf_ops.rs`
- `core/src/monitoring.rs`
- `core/src/ct_ops.rs`
- `core/src/qos_ops.rs`
- `core/src/mirror_ops.rs`
- `core/src/tcprt_ops.rs`
- `core/src/drop_ops.rs`
- `core/src/trace_ops.rs`

The new contract is:

- pin path selects the shared tap-managed namespace
- `tap_id` selects the logical instance

## 10. Replay and Persistence

### 10.1 Persist `tap_id`

Per-instance state must persist `tap_id`.

Recommended migration:

- if `tap_id` is missing in old state, allocate one during first shared-runtime registration
- compact immediately after successful migration

### 10.2 WAL format

WAL does not need to duplicate `tap_id` on every record if WAL files remain per-instance.

Reason:

- the instance name already identifies the state owner
- replay can load the instance state, recover the persisted `tap_id`, and write shared-map entries with that `tap_id`

### 10.3 Replay contract

Replay must change from:

- replaying an instance into its own pinned maps

to:

- replaying an instance into the shared pinned maps using its `tap_id`

This applies to:

- groups and CIDRs
- policies and port sets
- QoS rules
- mirror rules
- per-tap config

## 11. Monitoring and Metrics

Monitoring APIs currently read one pinned namespace per instance.

Shared-mode monitoring must:

- iterate shared maps once
- filter by `tap_id`
- map `tap_id` back to instance name in the control plane

This applies to:

- `/stats`
- `/conntrack`
- `/tcprt`
- `/trace`
- `/metrics`

This change is required for correctness, not only optimization.

## 12. System Mode Compatibility

The repository still has a separate `system` path in `agent/src/system_manager.rs`.

Recommended approach:

- do not mix `system` mode into the first tap-shared migration
- keep `system` mode isolated during phase 1
- move it to the shared runtime only after tap-managed mode is stable

This avoids coupling the tap-density migration to a second lifecycle migration.

## 13. Migration Strategy

### Phase 0: Temporary memory relief

Optional but recommended before full rollout:

- add low-memory capacity profiles for large maps in `ebpf/src/maps.rs`

This is only a stopgap. It does not fix linear scaling with tap count.

### Phase 1: Shared schema and runtime foundation

- add `tap_id` and new shared-runtime structs
- add `IFACE_CTX_MAP`
- add `TAP_CONFIG_MAP`
- redesign LPM trie keys
- change heavy map keys to include `tap_id`
- change eBPF fast path to resolve `tap_id`

### Phase 2: Shared user-space map API

- refactor `core` map helpers to operate on shared pin path + `tap_id`
- refactor control-plane instance state to carry runtime metadata

### Phase 3: Shared attach lifecycle

- introduce the shared tap data-plane manager
- load tap-managed BPF once
- attach XDP/TC programs per interface without duplicating maps

### Phase 4: Monitoring and cleanup

- adapt monitoring and metrics to shared maps
- add per-tap runtime cleanup on detach
- clean orphaned per-tap pin directories from the old model

## 14. Open Risks

### 14.1 Key ABI break

Pinned maps created by the old schema are not reusable.

Mitigation:

- use a new pin namespace such as `global-v2`

### 14.2 Overlooked per-tap semantics

Current code has per-instance config for:

- `conntrack`
- `monitoring`
- `acl`
- `qos`
- `mirror`
- `tcprt`

These semantics must survive the migration via `TAP_CONFIG_MAP`.

### 14.3 Incomplete detach cleanup

If detach only removes links and leaves shared runtime entries behind, stale tap state will accumulate.

### 14.4 LPM trie migration complexity

The group/CIDR path is the one part that cannot be migrated by a trivial `tap_id` field addition.

It requires explicit trie key redesign and replay changes.

## 15. Initial File-Level Work List

eBPF:

- `ebpf/src/common.rs`
- `ebpf/src/maps.rs`
- `ebpf/src/lib.rs`
- `ebpf/src/policy.rs`
- `ebpf/src/conntrack.rs`
- `ebpf/src/stats.rs`
- `ebpf/src/qos.rs`
- `ebpf/src/mirror.rs`
- `ebpf/src/tcprt.rs`
- `ebpf/src/drops.rs`
- `ebpf/src/trace.rs`

Core:

- `core/src/common.rs`
- `core/src/ebpf_ops.rs`
- `core/src/monitoring.rs`
- `core/src/ct_ops.rs`
- `core/src/qos_ops.rs`
- `core/src/mirror_ops.rs`
- `core/src/tcprt_ops.rs`
- `core/src/drop_ops.rs`
- `core/src/trace_ops.rs`
- `core/src/state.rs`
- `core/src/wal.rs`

Agent:

- `agent/src/tap_registry.rs`
- `agent/src/instance.rs`
- `agent/src/control_plane.rs`
- `agent/src/netlink.rs`
- `agent/src/main.rs`

## 16. Recommendation

This should be treated as the next major architecture workstream for tap-managed mode.

The correct order is:

1. lock the shared-runtime data model and map schemas
2. migrate the user-space map APIs to `tap_id`
3. switch attach lifecycle from per-tap load to shared load
4. then tune capacities

Doing capacity tuning first is acceptable only as a temporary stopgap.
