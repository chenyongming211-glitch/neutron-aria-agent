# 09. Aria RPC And Incremental Sync Detail Plan

Status: planned post-stage-three evolution. This document records the target
sync model and the phased path from the current MVP to incremental RPC. It is a
design record, not an implementation claim.

Normative parents:

- `../openstack-neutron-agent-mode.md` section 1.5 and the port/network event
  sections.
- `../neutron-managed-domains-contract.md`
- `03-neutron-acl-source.md`
- `07-transaction-wal.md`
- `08-stage3-acl-production-hardening.md`

## Goal

Evolve `neutron-aria-agent` from periodic REST full-resync toward an OVS-like
event-driven update model, while keeping Aria's snapshot/WAL/generation safety
model and without replacing OVS L2.

Target end state:

- Neutron RPC notifies local changes quickly.
- Local projected state decides whether an event applies to this host.
- Safe cases apply **port-scoped** snapshots or UDS mutations.
- Full-resync remains the authoritative recovery path.

## Non-Goals

- Do not replace OVS agent RPC topics for tunnel, SG, DVR, or l2population.
- Do not implement tenant-facing features beyond ACL/QoS first-stage scope.
- Do not remove full-resync; it stays for startup, reconnect, capability drift,
  generation mismatch, and N3 lifecycle recovery.
- Do not block OVS L2 when ACL incremental apply fails; use degraded/bypass.

## Current State (Recorded Baseline)

| Phase | Config | Sync behavior | Status |
| --- | --- | --- | --- |
| P0 safe default | `port_source=disabled`, `full_resync_enabled=false`, `rpc_events_enabled=false` | Heartbeat only | shipped |
| P1 MVP production | `port_source=neutronclient`, `full_resync_enabled=true`, `acl.source=neutron`, `rpc_events_enabled=false` | Periodic REST full-resync | stage-two accepted |
| P2 RPC-triggered resync | P1 + `rpc_events_enabled=true` | RPC update/network event -> event merge -> **full-resync**; known local delete -> UDS delete cleanup | skeleton in code; stage-three S3-5 |
| P3 incremental RPC | P2 + port/network indexes + port-scoped apply | RPC event -> filtered **port-scoped** apply | **this plan** |

Code anchors today:

- REST port read: `neutron_client.NeutronPortSource.list_ports_for_host()`
- RPC callbacks: `agent/rpc.py` (`port.update`, `port.delete`, `network.update`)
- Event batching: `agent/event_merge.py`
- Current RPC effect: `AgentService._process_event_batch()` triggers
  `safe_full_resync()` for local port updates and network updates when resync
  is enabled; known projected `port.delete` events use the existing UDS delete
  path and the same durable local delete state.

## Comparison With OVS Agent

OVS agent and Aria solve different layers, so "better" depends on the dimension:

| Dimension | OVS agent (reference) | Aria P1 MVP | Aria P2 | Aria P3 target |
| --- | --- | --- | --- | --- |
| Change notification | RPC fanout | none | RPC fanout | RPC fanout |
| Periodic reconciliation | agent loop + plugin RPC | REST list_ports | REST list_ports + periodic resync | REST/plugin read + periodic resync |
| Read path | plugin RPC, not REST polling | REST `neutronclient` | REST on resync | REST or targeted plugin/API read |
| Apply model | incremental local OVSDB/flow | whole-host snapshot | whole-host snapshot | port-scoped snapshot |
| Failure model | L2 break risk | ACL bypass, OVS unaffected | same | same |
| Recovery | periodic sync/resync | full-resync | full-resync | full-resync + selective replay |

Design intent:

- **Borrow OVS notification semantics**, not the whole OVS state machine.
- **Keep Aria reconciliation semantics** (generation, WAL, UDS contract).
- Incremental RPC is an optimization and latency improvement, not a new control
  plane.

## Phased Target Architecture

```text
Neutron Server
  |  RPC: port.update / port.delete / network.update
  |  REST: ports + aria_acl (until narrower read paths exist)
  v
neutron-aria-agent
  |  RpcCallback -> EventMerger
  |  ProjectedStateStore (host, port_id, binding:host_id, last generation)
  |  NetworkPortIndex (network_id -> local port_ids)   [P3]
  |  AclRevisionCache (policy/rule/binding revisions)  [P3]
  |  Decision:
  |     safe + local + revision newer -> port-scoped snapshot
  |     unknown / overflow / mismatch -> full-resync
  v
aria-datapath UDS
  |  accept port-scoped or full snapshot
  |  WAL + domain reconcile
  v
tap eBPF ACL/QoS
```

## P2: RPC-Triggered Full-Resync (Near Term)

Entry criteria:

- Stage-three ACL production hardening accepted or explicitly waived for the
  target host.
- P1 MVP full-resync, rollback, and heartbeat are stable on that host.

Config:

```ini
[agent]
full_resync_enabled = true

[neutron]
port_source = neutronclient
rpc_events_enabled = true
event_merge_interval = 0.2
```

Config rules:

- `rpc_events_enabled=true` requires `full_resync_enabled=true`.
- `rpc_events_enabled=true` requires `port_source=neutronclient`.

Behavior:

1. Consume the same first-stage RPC set as legacy OVS agent:
   `port.update`, `port.delete`, `network.update`.
2. Merge events in `event_merge_interval`.
3. Filter by local projected state and `binding:host_id`.
4. For local `port.update` and `network.update`, trigger `safe_full_resync()`;
   do not apply unsafe partial deltas.
5. For known projected `port.delete`, call the idempotent UDS delete path and
   persist the pending delete state. Unknown deletes do not mutate local state.
6. Keep periodic `resync_interval` as backup.

Exit criteria:

- RPC on/off A/B shows faster rule convergence than polling-only.
- `neutron_aria_rpc_event_smoke.sh` passes as a package-level preflight before
  real RabbitMQ fanout testing.
- Fanout delete/update on foreign hosts does not mutate local managed ports.
- RPC loss is recovered by periodic or manual full-resync without false ready.

## P3: Incremental RPC (Target Optimization)

### Principles

1. **Locality first**: only ports bound to this host may be incrementally
   applied.
2. **Revision aware**: apply only when Neutron/object revision is newer than the
   cached effective ACL/port revision.
3. **Scope minimal**: default to one port per RPC batch when safe.
4. **Fail open to resync**: ambiguity, queue overflow, capability hash change,
   WAL/generation conflict, or missing index entries trigger full-resync.
5. **Bypass on ACL failure**: incremental ACL failure degrades the ACL domain
   only; OVS L2 must remain baseline.

### Required Local State (New Or Extended)

| Store | Purpose |
| --- | --- |
| `ProjectedPortStore` | Last projected port ids, binding host, eligible/disposition, generation. |
| `NetworkPortIndex` | Map `network_id -> {port_id...}` for local host only. |
| `AclEffectiveCache` | Last effective ACL index per port with policy/rule/binding revisions. |
| `EventDedupWindow` | Suppress duplicate RPC batches within merge interval. |

Existing pieces to extend:

- `agent/state.py`
- `agent/event_loop.py`
- `agent/event_merge.py`
- `agent/effective_acl.py` revision fields already reserved in
  `03-neutron-acl-source.md`

### Event Decision Matrix

| Event | Preconditions | P3 action |
| --- | --- | --- |
| `port.update`, host matches, port eligible, iface known | revision newer, ACL cache hit or readable | port-scoped snapshot for that port |
| `port.update`, host matches, tap not ready | any | record desired state; status degraded; wait for datapath local validation or Netlink path |
| `port.update`, host mismatch | any | ignore; if previously managed locally, schedule delete or full-resync cleanup |
| `port.delete` | port was locally managed | UDS delete port; purge ACL authority |
| `port.delete` | port not locally managed | ignore |
| `network.update` | network index exists | expand to affected local ports; if set small, port-scoped batch; else full-resync |
| `network.update` | no network index | full-resync |
| queue overflow / merge timeout | any | full-resync |
| `aria_acl` binding/policy/rule change without port RPC | revision cache stale | full-resync until ACL object RPC or revision subscription exists |

Note: Neutron may not emit dedicated `aria_acl.*` RPC in v0.9. Until it does,
ACL object changes may still require periodic resync or port/network RPC as the
trigger. Document this as a known latency boundary.

### Port-Scoped Snapshot Contract

Parent design already allows port-scoped snapshots in
`openstack-neutron-agent-mode.md`. P3 must make them explicit in UDS contract
and Python client:

| Field | Rule |
| --- | --- |
| body scope | one port or an explicit bounded port set |
| `generation` | monotonic host generation |
| `desired_hash` | hash of scoped desired state |
| domains | only domains present in `managed_domains` for that port |
| ACL payload | from `EffectiveAclIndex.effective_for_port()` after event |

Rust/datapath requirements:

- Accept scoped snapshot without requiring unrelated ports to be restated.
- Reject stale generation/hash with existing error semantics from
  `07-transaction-wal.md`.
- Preserve attach/acl domain split and bypass semantics.

### Read Path Options

Priority order for P3 implementation:

1. **Targeted REST read** for one port + required `aria_acl` objects (lowest
   integration risk).
2. **Cached effective read** from last full-resync plus revision compare.
3. **Plugin RPC read** only if target Neutron version exposes a stable agent RPC
   for device/effective ACL details.

Do not require plugin RPC to ship P3 if targeted REST read is sufficient.

## Configuration Evolution

| Phase | Key settings |
| --- | --- |
| P1 MVP | `port_source=neutronclient`, `full_resync_enabled=true`, `rpc_events_enabled=false` |
| P2 | add `rpc_events_enabled=true` |
| P3 | add `incremental_rpc_enabled=true` (new), keep `resync_interval` backup |

Proposed new ini keys (names may change at implementation PR):

```ini
[neutron]
rpc_events_enabled = true
incremental_rpc_enabled = false
incremental_max_ports_per_batch = 16
incremental_fallback_full_resync = true
```

Rules:

- `incremental_rpc_enabled=true` requires `rpc_events_enabled=true` and
  `full_resync_enabled=true`.
- If incremental path fails validation, fall back to full-resync when
  `incremental_fallback_full_resync=true`.

Container requirements for P2/P3:

- Same `neutron.conf` / messaging config as OVS agent.
- Same host FQDN semantics as `binding:host_id`.
- RabbitMQ reachable from `neutron_aria_agent` container.

## Work Packages

| ID | Scope | Exit criteria |
| --- | --- | --- |
| P2-1 | Enable RPC-triggered resync in runbook and smoke | rule change converges faster than polling-only on test host |
| P2-2 | Foreign-host fanout filtering tests | no cross-host managed port mutation |
| P3-1 | Projected port store + network index | unit tests for host/network filtering |
| P3-2 | Port-scoped snapshot builder in Python | unit tests + UDS contract tests |
| P3-3 | Rust scoped snapshot apply | WAL/generation tests; no false ready |
| P3-4 | Incremental ACL apply failure semantics | degraded/bypass without OVS loss |
| P3-5 | RPC on/off + incremental on/off smokes | evidence under `docs/evidence/openstack-n05-lite/` |
| P3-6 | Runbook and ini contract update (`01-ini-contract.md`) | config validation + docs |

## Verification And Gates

Minimum tests before declaring P3 ready:

| Gate | Proof |
| --- | --- |
| Locality | RPC for foreign host does not attach/manage local datapath |
| Incremental apply | Neutron API change on one VM port updates only that tap within SLO |
| Resync fallback | forced index loss -> full-resync restores ready state |
| Delete | `port.delete` removes managed state idempotently |
| Migration | old host cleanup + new host apply without stale tap identity |
| ACL bypass | invalid/missing ACL after incremental event -> degraded/bypass |
| Rollback | UDS delete + config disable preserves OVS connectivity |
| Performance | port-scoped p95 target from main design (<= 500ms mock/stage gate) |

Suggested smokes to add or extend:

- `neutron_aria_rpc_event_smoke.sh` for P2 package-level event path preflight.
- `neutron_aria_rpc_incremental_smoke.sh` for P3 real incremental behavior.
- extend `neutron_aria_acl_neutron_source_smoke.sh` with real port binding + traffic
- reuse `neutron_aria_vm_migration_smoke.sh`, `neutron_aria_tap_recreate_smoke.sh`

## Entry Criteria For Starting P3

Do not start P3 implementation until all are true:

1. Stage-two ACL MVP and stage-three N3 fault/lifecycle gates are accepted or
   explicitly waived with written disposition.
2. P2 RPC-triggered full-resync is stable on at least one target host.
3. Rich domain status (`05-domain-status-heartbeat.md`) or an agreed minimal
   subset is available for incremental failure reporting.
4. UDS contract documents port-scoped snapshot limits and errors.
5. `EffectiveAclIndex` revision compare is covered by unit tests.

## Open Questions

| Topic | Question | Default until resolved |
| --- | --- | --- |
| ACL object RPC | Will Neutron emit `aria_acl` object updates directly? | rely on port/network RPC + resync |
| Plugin RPC | Is legacy plugin RPC available for single-port device details? | use targeted REST |
| Body size | Does port-scoped snapshot remove the need for 1 MiB full-body pressure? | keep contract limits until measured |
| QoS | Does incremental RPC include QoS in the same phase? | ACL first, QoS later |
| `default_action=deny` | Rust translator support required before P3 production? | track as datapath prerequisite |

## Relationship To Current Stage Three

Stage three (`08-stage3-acl-production-hardening.md`) intentionally stops at
P2 behavior:

- RPC may trigger full-resync.
- Port-scoped delta apply is explicitly deferred.

This document is the approved place to reopen incremental RPC design after
stage three without revisiting the v0.9 architecture boundaries.
