# 09. Aria RPC And Incremental Sync Detail Plan

Status: P2 RPC-triggered full-resync is implemented with field evidence and an
operator enablement/rollback contract. P3 port-scoped incremental RPC is
implemented behind explicit config gates and has controlled test-host evidence.
Packaged defaults keep P3 disabled; production P3 remains revision-aware and
must retain full-resync rollback.

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
| P3 incremental RPC | P2 + port/network indexes + port-scoped apply | RPC event -> filtered **port-scoped** apply | config-gated implementation and controlled test-host evidence are accepted through P3-6; packaged default remains disabled. Production P3 requires trustworthy revision data; old Neutron without `revision_number` stays on P2 fallback unless a controlled test explicitly enables revisionless experimental mode. |

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
- The Rust P3-3 minimum design and test boundary is recorded in
  `10-rust-scoped-apply.md`. The planner, internal WAL/status boundary, and
  shared runtime apply body, and shared preflight/idempotency checks now have
  tests; do not add the scoped UDS route until route/capability tests are added
  in the same change.

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
| P3 | add `incremental_rpc_enabled=true`, keep `resync_interval` backup |
| P3 legacy test only | optionally add `revisionless_incremental_mode=experimental` on a controlled host with no Neutron port revision |

Implemented ini keys:

```ini
[neutron]
rpc_events_enabled = true
incremental_rpc_enabled = false
revisionless_incremental_mode = disabled
```

Rules:

- `incremental_rpc_enabled=true` requires `rpc_events_enabled=true`,
  `full_resync_enabled=true`, and `port_source=neutronclient`.
- Packaged defaults keep `incremental_rpc_enabled=false`. Test environments may
  enable it after P2/stage-three evidence is accepted; production rollout still
  requires a separate revision-aware rollout decision.
- Packaged defaults keep `revisionless_incremental_mode=disabled`. The only
  allowed non-default value is `experimental`, and only when
  `incremental_rpc_enabled=true` on a controlled test host.
- If the incremental path fails validation, or the event batch includes deletes,
  multiple ports, network updates, overflow, capability drift, or stale/missing
  revision evidence, fall back to full-resync. Full-resync fallback is not a
  separate optional feature flag for v0.9.

Container requirements for P2/P3:

- Same `neutron.conf` / messaging config as OVS agent.
- Same host FQDN semantics as `binding:host_id`.
- RabbitMQ reachable from `neutron_aria_agent` container.
- Neutron API credentials must be injected into the long-running
  `neutron_aria_agent` process when `[neutron] port_source=neutronclient` or
  `[acl] source=neutron` is enabled. Temporary smokes may source `adminrc`, but
  production containers need an explicit env/secret path.
- P3 port-scoped apply requires Neutron port reads or RPC events to expose a
  trustworthy `revision_number`. If the target Neutron returns no port revision,
  keep `incremental_rpc_enabled=false` and use P2 RPC-triggered full-resync.

### Revisionless Legacy Neutron Rule

Some old Neutron deployments expose no `revision_number` for bound ports. The
normative P3 production path does not treat that as safe for scoped apply:
without a revision, the agent cannot prove an RPC event is newer than the last
projected desired state.

Default behavior:

- Keep `incremental_rpc_enabled=false` for production.
- If P2 RPC is enabled, a port update without revision triggers full-resync
  fallback, not port-scoped apply.
- Periodic full-resync remains the authoritative repair path.

Controlled test behavior:

- A test host may set `revisionless_incremental_mode=experimental` together
  with `incremental_rpc_enabled=true`.
- The mode is allowed only for single local `port.update` batches after normal
  locality, capability, and scoped UDS gates pass.
- Same/older revision decisions still fall back to full-resync.
- Any multi-port, delete, network, overflow, capability drift, or validation
  ambiguity falls back to full-resync.
- This mode is for legacy-environment evidence only; it does not close the
  production P3 gate.

## Work Packages

| ID | Scope | Exit criteria |
| --- | --- | --- |
| P2-1 | Enable RPC-triggered resync in runbook and smoke | rule change converges faster than polling-only on test host |
| P2-2 | Foreign-host fanout filtering tests | no cross-host managed port mutation |
| P2-3 | Production canary switch and polling-only rollback runbook | `rpc_events_enabled=true` can be enabled and disabled per host without OVS/datapath restart |
| P3-1 | Projected port store + network index | inactive/read-only unit tests for host/network/revision filtering; no port-scoped apply |
| P3-2 | Port-scoped snapshot builder in Python | pure builder, synchronizer dry-run, and scoped state/projection preservation tests |
| P3-3 | Rust scoped snapshot apply | `ApplyScope::SinglePort` planner tests, internal scoped WAL/status boundary tests, shared runtime apply body extraction, shared preflight/idempotency checks, advertised UDS capability, and Python config-gated single-port submitter are implemented; packaged runtime default remains disabled |
| P3-4 | Incremental ACL apply failure semantics | degraded/bypass without OVS loss |
| P3-5 | RPC on/off + incremental on/off smokes | accepted for the old Neutron test host; evidence under `docs/evidence/openstack-n05-lite/20260702-p3-5-incremental-smoke/` |
| P3-6 | Runbook and ini contract update (`01-ini-contract.md`) | default-off production contract, controlled test enablement, and rollback docs accepted |

## P3-4 Failure Semantics

P3-4 is a failure-behavior gate, not a feature expansion. It covers only ACL
incremental apply after P3-3 has already proven the scoped UDS route and Python
submitter are config-gated.

Required behavior:

- If the scoped UDS call fails, times out, or returns an invalid response, the
  service records `incremental_action=fallback_full_resync`,
  `incremental_reason=port_scoped_apply_error`, includes the error in the
  debug decision, and immediately attempts the normal safe full-resync path.
- If the scoped candidate cannot be safely submitted because the projected port,
  tap, or local binding is not usable, the service records
  `incremental_action=fallback_full_resync` with the specific skipped reason,
  such as `port_not_available_for_host`, and attempts full-resync.
- If the ACL payload itself is missing or invalid, the scoped snapshot must keep
  ACL in `degraded` with `effective_action=bypass`. It must not block OVS L2
  forwarding and must not report a false `ready` status for that ACL domain.
- A scoped failure must not mutate unrelated ports, must not expand QoS/Mirror
  scope, and must not remove periodic/full-resync recovery.

Current local/package evidence:

- Unit tests cover scoped submit exception -> full-resync fallback.
- Unit tests cover scoped dry-run skip -> full-resync fallback.
- Event-loop tests cover UDS port error without false ready/projection advance.
- Event-loop tests cover invalid ACL preservation as degraded/bypass.
- The package smoke embeds the same service-level failure cases.

## P3-6 Default-Off And Rollback Contract

P3-6 closes the operator contract for port-scoped incremental apply. It does not
add a new datapath feature. The contract is: P3 may be tested explicitly, but it
must not become the packaged or production default until a revision-aware
rollout decision is made.

Runtime modes:

| Mode | Allowed scope | Required settings | Expected behavior |
| --- | --- | --- | --- |
| Packaged safe default | All installs | `rpc_events_enabled=false`, `incremental_rpc_enabled=false`, `revisionless_incremental_mode=disabled` | No RPC subscription; no scoped apply. |
| P1 production ACL | Accepted ACL hosts | `full_resync_enabled=true`, `port_source=neutronclient`, `acl.source=neutron`, `rpc_events_enabled=false` | Periodic REST full-resync only. |
| P2 canary | One host at a time after P1/N3 gates | P1 plus `rpc_events_enabled=true`, `incremental_rpc_enabled=false` | RPC event triggers full-resync; no scoped apply. |
| P3 revision-aware test | Controlled test host with trustworthy port revision | P2 plus `incremental_rpc_enabled=true`, `revisionless_incremental_mode=disabled` | Single safe local newer-revision port update may use scoped apply. |
| P3 legacy lab test | Controlled old-Neutron test host only | P2 plus `incremental_rpc_enabled=true`, `revisionless_incremental_mode=experimental` | Single safe local revisionless port update may use scoped apply for evidence only. |

Forbidden defaults:

- Do not ship `incremental_rpc_enabled=true` in packaged defaults.
- Do not ship `revisionless_incremental_mode=experimental` in packaged
  defaults.
- Do not use revisionless experimental mode as production acceptance.
- Do not disable periodic/full-resync recovery when enabling P2 or P3.
- Do not restart OVS, OVS agent, neutron-server, or datapath merely to change
  P2/P3 event flags; restart only `neutron_aria_agent` so it reloads config.

Rollback levels:

| From | Action | Result |
| --- | --- | --- |
| P3 test -> P2 | Set `incremental_rpc_enabled=false` and `revisionless_incremental_mode=disabled`; restart only `neutron_aria_agent`. | RPC can still trigger full-resync, but no scoped apply is submitted. |
| P2 -> polling-only | Set `rpc_events_enabled=false`; restart only `neutron_aria_agent`. | Agent returns to periodic REST full-resync. |
| Any event path -> ACL rollback | Follow the deployment runbook rollback flow only if ACL/datapath state itself must be cleared. | UDS delete/full-resync clears managed state; OVS remains untouched. |

Rollback triggers:

- `port_scoped_apply_fallback` repeats for normal local updates.
- Port-scoped apply occurs for a foreign-host event.
- `managed_ports` remains nonzero after the smoke rollback step.
- Neutron no longer exposes trustworthy port revision and the host is not an
  explicit legacy lab test.
- RabbitMQ consumer startup or fanout behavior becomes unstable.
- Domain status reports false ready, stale pending generation, or unexpected
  ACL blocking for degraded/bypass input.

P3-6 acceptance is the documentation and config contract above plus the P3-5
field evidence. It is not permission to turn on P3 globally.

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

## Entry Criteria For P3 Runtime Enablement

Do not enable P3 runtime port-scoped apply outside a test host until all are true:

1. Stage-two ACL MVP and stage-three N3 fault/lifecycle gates are accepted or
   explicitly waived with written disposition.
2. P2 RPC-triggered full-resync is stable on at least one target host.
3. Rich domain status (`05-domain-status-heartbeat.md`) or an agreed minimal
   subset is available for incremental failure reporting.
4. UDS contract documents port-scoped snapshot limits and errors.
5. `EffectiveAclIndex` revision compare is covered by unit tests.

Current entry-gate evidence:

- Items 1-3 are covered by stage-two/stage-three closure, RPC P2 field
  evidence, and the accepted heartbeat/status subset.
- Item 4 is covered by `docs/neutron-uds-contract.json`
  `p3_port_scoped_snapshot`. The Rust UDS route is implemented and advertised,
  and the Python submitter is config-gated.
- Item 5 is covered by `EffectiveAclIndex.compare_revision_for_port()` unit
  tests for newer/same/older/unknown relations.

This evidence allows P3 runtime testing on a controlled host. P3-5/P3-6 accept
incremental smoke and rollback readiness for the current old-Neutron test
environment. Production rollout still requires a separate revision-aware
rollout decision and must keep packaged defaults disabled.

Allowed before production P3 runtime enablement:

- Keep `incremental_rpc_enabled=false` as the packaged default.
- Add a Python UDS client helper that refuses port-scoped submit unless the
  local capability advertises `supports_port_scoped_snapshot=true`.
- Build an in-memory `ProjectedStateIndex` from accepted full-resync results.
- Build pure Python port-scoped candidate snapshots for unit testing only.
- Wire one safe local newer-revision RPC port-update decision to the scoped
  submitter behind `incremental_rpc_enabled=true`.
- Unit test local/foreign host decisions, revision relation, network locality,
  delete cleanup, and conservative full-resync fallback.
- Publish compact heartbeat/debug summaries for projection index size and the
  last RPC decision batch.

Field evidence:

- `docs/evidence/openstack-n05-lite/20260702-p3-projection-heartbeat-3node/summary.md`
  records the accepted three-node heartbeat/debug gate for the read-only P3-1
  projection index and last event decision summaries.
- `docs/evidence/openstack-n05-lite/20260702-p3-incremental-revision-gate/summary.md`
  records the controlled ostack2 P3 fanout attempt. Real RabbitMQ fanout,
  Neutron port reads, full-resync apply, and rollback worked, but the target
  Neutron returned `revision_number=None` for bound ports, so the port-scoped
  runtime gate remains not accepted for this environment.
- `docs/evidence/openstack-n05-lite/20260702-p3-revisionless-experimental-fanout/summary.md`
  records the controlled legacy-mode follow-up. With
  `revisionless_incremental_mode=experimental`, a projected local port update
  reached `port_scoped_snapshot_complete` and rollback left
  `managed_ports=0`. This is test-host evidence only, not production P3
  acceptance.
- `docs/evidence/openstack-n05-lite/20260702-p3-5-incremental-smoke/summary.md`
  records P3-5. Package RPC event smoke passed, P2 RPC-triggered full-resync
  A/B passed, controlled revisionless experimental port-scoped apply passed,
  default revisionless behavior stayed on full-resync fallback, and final UDS
  state had `managed_ports=0` with no pending generation.

Follow-up decision recorded on 2026-07-02:

- Official P3 remains revision-aware.
- 10.58.159 old Neutron may use
  `revisionless_incremental_mode=experimental` for a scoped-route test only.
- Passing that test proves the implementation path can run in the legacy lab;
  it does not replace revision-aware production acceptance.

Still forbidden before production P3 runtime enablement:

- Enabling `incremental_rpc_enabled=true` in packaged defaults.
- Enabling `revisionless_incremental_mode=experimental` in packaged defaults or
  production rollout.
- Sending port-scoped snapshots from any Python path without advertised
  capability and config gates.
- Removing periodic/full-resync recovery.
- Changing Rust datapath snapshot apply semantics outside the shared
  `ApplyScope::FullHost` / `ApplyScope::SinglePort` path defined in
  `10-rust-scoped-apply.md`.

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
