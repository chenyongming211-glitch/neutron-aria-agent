# 09. Aria RPC And Incremental Sync Detail Plan

Status: P2 RPC-triggered full-resync is implemented with field evidence and an
operator enablement/rollback contract. P3 port-scoped incremental RPC remains a
planned optimization. This document records the phased path from polling-only
MVP to incremental RPC; it is not a claim that P3 is implemented.

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
| P2 RPC-triggered resync | P1 + `rpc_events_enabled=true` | RPC update/network event -> event merge -> **full-resync**; known local delete -> UDS delete cleanup | package smoke passed on 10.58.159; real fanout A/B passed on `ostack2.bj159.net`; multi-host foreign filtering passed on `ostack2/3/4`; source-host cleanup passed on `ostack2` |
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

- RPC on/off A/B shows the real fanout path reaches the event merger and
  triggers full-resync when enabled, while the disabled path ignores the same
  fanout.
- `neutron_aria_rpc_event_smoke.sh` passes as a package-level preflight before
  real RabbitMQ fanout testing.
- Fanout delete/update on foreign hosts does not mutate local managed ports.
- RPC loss is recovered by periodic or manual full-resync without false ready.

Current evidence:

- `../evidence/openstack-n05-lite/20260701-rpc-event-package-smoke/summary.md`
  records package-level P2 preflight success on all three 10.58.159 target
  hosts. It did not subscribe to RabbitMQ or mutate datapath state.
- `../evidence/openstack-n05-lite/20260701-rpc-fanout-ab-smoke/summary.md`
  records real RabbitMQ fanout A/B success on `ostack2.bj159.net`. It proves
  P2 fanout-triggered full-resync on one host, not P3 port-scoped incremental
  apply or multi-host rollout readiness.
- `../evidence/openstack-n05-lite/20260701-rpc-foreign-host-smoke/summary.md`
  records real RabbitMQ foreign-host fanout filtering success across
  `ostack2.bj159.net`, `ostack3.bj159.net`, and `ostack4.bj159.net`. It proves
  foreign-host `port.update` events are consumed but do not trigger local
  full-resync or local managed-port mutation in P2 mode.
- `../evidence/openstack-n05-lite/20260701-rpc-source-cleanup-smoke/summary.md`
  records the source-host cleanup branch on `ostack2.bj159.net`. It proves a
  projected local port receiving a foreign-host `port.update` is deleted with
  `migration_source_cleanup` without triggering another full-resync.

### P2 Operational Enablement Contract

P2 is an operational switch for RPC-triggered full-resync. It is not P3 and it
must not introduce port-scoped incremental apply.

Safe default:

- Keep `[neutron] rpc_events_enabled = false` in packaged defaults.
- Keep `[agent] full_resync_enabled = true` and periodic polling available
  before turning on RPC events.
- Do not disable polling when RPC is enabled; RPC is a latency improvement and
  polling remains the recovery path.

Production entry criteria for enabling `rpc_events_enabled=true` on a host:

1. P1 full-resync with `port_source=neutronclient` and `acl.source=neutron` is
   accepted on that host.
2. Stage-three ACL N3 fault/lifecycle gates are accepted or explicitly waived
   for the target host.
3. The deployed package includes the P2 RPC fixes and passes
   `neutron_aria_rpc_event_smoke.sh`.
4. Real RabbitMQ fanout A/B, multi-host foreign-host filtering, and source-host
   cleanup smokes have pass evidence for the target environment.
5. The container has the same effective `neutron.conf` messaging settings and
   host naming convention as the onsite OVS agent.
6. UDS status, rollback, and full-resync recovery are already accepted; a
   failed RPC event path must be recoverable by polling-only full-resync.

Enablement flow:

1. Enable one compute host first; do not flip the whole cluster at once.
2. Back up the active `neutron-aria-agent.ini`.
3. Set only `[neutron] rpc_events_enabled = true`.
4. Restart only the `neutron_aria_agent` service/container so the config is
   loaded. Do not restart OVS, OVS agent, Neutron server, or datapath for this
   switch.
5. Verify logs show RPC event mode enabled, heartbeat/status remains healthy,
   and a bounded test fanout reaches `event_batch_drained`.
6. Keep the host in a bounded canary window and watch for unexpected
   `managed_ports` growth, extra full-resync loops, or degraded reasons.

Polling-only rollback:

1. Set `[neutron] rpc_events_enabled = false`.
2. Restart only `neutron_aria_agent`.
3. Verify logs show RPC event mode disabled.
4. Confirm periodic/manual full-resync still works and UDS rollback/delete can
   clear any test-managed ports.

Failure disposition:

| Failure | Required action |
| --- | --- |
| RPC consumer import/start failure | Roll back to `rpc_events_enabled=false`; keep polling-only P1. |
| RabbitMQ instability or missed events | Roll back to polling-only; rely on periodic full-resync. |
| Foreign-host event mutates local state | Roll back immediately, run UDS cleanup/rollback, and keep P2 closed until fixed. |
| Source-host cleanup leaves stale managed ports | Roll back, run cleanup smoke, and do not enable P2 on more hosts. |
| Repeated full-resync loop after one event | Roll back to polling-only and inspect event merge/log evidence. |

P2 acceptance is a production operations gate. It closes when the runbook can
enable and roll back RPC events without changing ACL semantics, OVS forwarding,
or the polling/full-resync recovery model.

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
- Current v0.9 config validation rejects `incremental_rpc_enabled=true` until
  the P3 entry gate is explicitly accepted. P3-1 may add inactive read-only
  indexes and decision tests, but production behavior remains P2.
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
| P2-3 | Production canary switch and polling-only rollback runbook | `rpc_events_enabled=true` can be enabled and disabled per host without OVS/datapath restart |
| P3-1 | Projected port store + network index | inactive/read-only unit tests for host/network/revision filtering; no port-scoped apply |
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

Do not start P3 port-scoped apply implementation until all are true:

1. Stage-two ACL MVP and stage-three N3 fault/lifecycle gates are accepted or
   explicitly waived with written disposition.
2. P2 RPC-triggered full-resync is stable on at least one target host.
3. Rich domain status (`05-domain-status-heartbeat.md`) or an agreed minimal
   subset is available for incremental failure reporting.
4. UDS contract documents port-scoped snapshot limits and errors.
5. `EffectiveAclIndex` revision compare is covered by unit tests.

Allowed before the full P3 entry gate:

- Add `incremental_rpc_enabled=false` as an explicit blocked config gate.
- Build an in-memory `ProjectedStateIndex` from accepted full-resync results.
- Unit test local/foreign host decisions, revision relation, network locality,
  delete cleanup, and conservative full-resync fallback.

Still forbidden before the full P3 entry gate:

- Enabling `incremental_rpc_enabled=true` in runtime config.
- Sending port-scoped snapshots over UDS.
- Changing Rust datapath snapshot apply semantics.
- Removing periodic/full-resync recovery.

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
