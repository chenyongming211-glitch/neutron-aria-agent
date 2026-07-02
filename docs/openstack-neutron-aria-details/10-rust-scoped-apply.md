# 10. Rust Scoped Snapshot Apply Minimum Design

Status: P3-3 implementation design package. The Rust single-port planner scope,
pure planner tests, internal scoped WAL/status transaction boundary tests, and
the shared runtime apply body extraction, shared preflight/idempotency checks,
and port-scoped UDS route are implemented for Rust-side testing. Capability
advertisement, Python submitter support, and the production incremental call
chain remain disabled.

## Goal

Define the minimum Rust-side work needed before P3 can move from Python
port-scoped dry-run to real port-scoped apply.

The intent is deliberately narrow: make one Neutron port update safe,
transactional, observable, and recoverable without requiring a full-host
snapshot. It must not expand tenant features, replace full resync, or change
OVS forwarding ownership.

## Current State

| Area | Status | Notes |
| --- | --- | --- |
| Full-host snapshot route | implemented | `PUT /api/v1/neutron/snapshot` applies host-authoritative snapshots. |
| Port delete route | implemented | `DELETE /api/v1/neutron/ports/{port_id}` cleans one Neutron-managed port. |
| WAL generation semantics | implemented for full snapshot/delete | Intent/commit, stale generation, hash conflict, timeout recovery, and replay have stage-one coverage. |
| Python port-scoped builder | implemented as dry-run only | `PortScopedSnapshotBuilder` and `SnapshotSynchronizer.dry_run_port_scoped_snapshot()` construct previews without UDS submit. |
| Rust scoped planner | implemented planner-only | `ApplyScope::SinglePort` and `build_snapshot_plan_for_scope()` have pure tests that prove unrelated ports are not mutated. |
| Rust scoped WAL/status boundary | implemented internally | `SnapshotApplyTransaction`, scope validation, affected-port checks, status seeding, and commit-runtime helpers have unit tests; no external scoped route uses them yet. |
| Rust shared runtime apply body | implemented internally | `apply_snapshot_runtime_transaction()` is the common detach/update/attach/domain reconcile body used by full-host snapshots and covered by a no-eBPF scoped error test. |
| Rust shared preflight/idempotency | implemented internally | `validate_snapshot_preflight()` and `snapshot_early_response_for_scope()` share schema, scope, stale, noop, and hash-conflict handling for full-host and future single-port snapshots. |
| Port-scoped UDS route | implemented, capability-disabled | `PUT /api/v1/neutron/ports/{port_id}/snapshot` reuses the shared snapshot apply path with `ApplyScope::SinglePort`; it is listed in `docs/neutron-uds-contract.json` but not advertised as a supported capability. |
| Rust external port-scoped apply | testable internally | The route can be exercised by Rust tests and direct UDS probes, but no Python submitter or production service-loop path calls it. |

## Non-Negotiable Guardrails

- Port-scoped UDS route is implemented for Rust-side testing, but do not call it
  from Python until the capability and config gates are accepted together.
- Do not advertise `supports_port_scoped_snapshot=true` until route, planner,
  WAL, status, Python client, and rollback tests pass in the same enablement
  window.
- Do not enable `incremental_rpc_enabled=true` in packaged config during this
  design package.
- Do not remove periodic/full-resync recovery. Scoped apply is an optimization,
  not the authority source of last resort.
- Do not implement batch/network scoped apply in P3-3. Single-port apply is the
  only MVP scope.
- Do not expand QoS/Mirror behavior here. Preserve existing domain rules and
  mutate only domains listed in the target port `managed_domains`.

## Minimum API Shape

P3-3 should reuse the existing DTOs where possible:

```text
PUT /api/v1/neutron/ports/{port_id}/snapshot
body: NeutronSnapshotRequest with exactly one NeutronPortSnapshot
```

The normative scope is the path `port_id` plus the single body port. A Python
debug-only `scope` field may exist in dry-run objects, but Rust must not depend
on it for authority. Unknown JSON fields should not create behavior.

Validation rules:

| Rule | Failure |
| --- | --- |
| body contains exactly one port | `PORT_SCOPE_MISMATCH` |
| body port id equals path `port_id` | `PORT_SCOPE_MISMATCH` |
| schema version supported | `UDS_SCHEMA_MISMATCH` |
| generation is not stale | `stale_generation` |
| same generation has same desired hash | idempotent success |
| same generation has different desired hash | `generation_hash_conflict` |
| local tap cannot be resolved | per-port degraded/error such as `PORT_IFACE_NOT_FOUND`, no false ready |

## Scoped Planner

Add a planner that shares the existing full snapshot logic but has explicit
scope:

```text
ApplyScope::FullHost
ApplyScope::SinglePort(port_id)
```

For `FullHost`, current behavior remains unchanged.

For `SinglePort(port_id)`:

- resolve only the requested port through the same local OVS/tap validation;
- never detach, update, or reclassify unrelated `current` ports;
- if the target port is eligible and binding matches, update only that port;
- if the target port is eligible and binding changed, detach the old target
  binding and attach the new target binding;
- if the target port is ineligible or cannot resolve to a local tap, detach or
  mark only that target port as degraded/detached according to the existing
  safe full-snapshot semantics;
- preserve unrelated `runtime.ports` and `runtime.port_statuses`.

This can be implemented as either:

- `build_snapshot_plan(..., ApplyScope)`; or
- a new `build_scoped_snapshot_plan(...)` that internally reuses the same
  resolution helpers.

Do not duplicate ACL compilation or tap resolution logic.

## WAL And Generation Semantics

Port-scoped apply still uses a host-level generation number. The difference is
the affected set, not the transaction model.

Required behavior:

- acquire the same single-writer `apply_lock`;
- use the same stale generation and hash-conflict checks as full snapshots;
- append a snapshot intent with `requested_port_ids=[port_id]`;
- compute `affected_ports` from the scoped plan, and ensure it contains only
  the target port;
- write a normal snapshot commit after classified apply;
- on error, keep `pending_generation=Some(generation)` and do not advance
  `applied_generation`;
- on success, advance `applied_generation` to the scoped generation and update
  only the target port status;
- preserve unrelated managed ports and their statuses across commit/replay.

No new WAL record kind is required for the MVP unless existing snapshot intent
cannot express the affected port/domain set safely.

## Runtime Status Semantics

Scoped apply must not turn unrelated ports stale or invisible.

| Case | Required Status |
| --- | --- |
| target update succeeds | target port status has new generation/hash; unrelated port statuses preserved. |
| target ACL degrades | target domain reports degraded/bypass; unrelated ports keep previous status. |
| target tap missing | target reports detached/degraded or error; no unrelated detach. |
| scoped apply partially fails | `accepted_generation` may advance, `applied_generation` stays at previous value, `pending_generation` is set. |
| full resync after scoped apply | full resync remains authoritative and may replace the scoped desired hash with a full-host desired hash at a newer generation. |

## Implementation Sequence

1. Add pure Rust planner tests for `ApplyScope::SinglePort` without adding the
   route. **Done for planner-only scope.**
2. Add scoped WAL/status unit tests around affected ports and unrelated status
   preservation. **Done for internal transaction-boundary scope.**
3. Extract the shared runtime apply body so full-host and future SinglePort use
   the same detach/update/attach/domain reconcile path. **Done internally, no
   route exposure.**
4. Extract shared preflight/idempotency logic so full-host and future
   SinglePort use the same schema, scope, stale generation, noop, and hash
   conflict checks. **Done internally, no route exposure.**
5. Add the UDS route only after planner, WAL/status, runtime body, and
   preflight/idempotency tests pass. **Done as a Rust-side testable route,
   capability-disabled.**
6. Flip the contract to `rust_route_implemented_capability_disabled` when the
   route lands, while
   keeping capability advertisement and Python submission disabled. **Done.**
7. Add Python UDS client support only after Rust advertises
   `supports_port_scoped_snapshot=true`.
8. Only then consider service-loop submission behind
   `incremental_rpc_enabled=true`.

## Minimum Test Boundary

Rust unit tests before route exposure:

| Test | Expected Result |
| --- | --- |
| scoped planner updates target only | unrelated current ports are not detached or updated. |
| scoped planner attaches target only | unrelated current ports remain untouched. |
| scoped planner detaches changed target binding only | old target binding is detached; unrelated ports remain untouched. |
| scoped planner handles ineligible target | target is ignored/detached/degraded according to safe semantics; unrelated ports remain untouched. |
| scoped body with zero ports | rejected before WAL intent. |
| scoped body with multiple ports | rejected before WAL intent. |
| scoped path/body mismatch | rejected before WAL intent. |
| stale scoped generation | `stale_generation`, no runtime mutation. |
| same generation same scoped hash | idempotent success. |
| same generation different scoped hash | `generation_hash_conflict`. |
| scoped UDS route path/body mismatch | route returns `PORT_SCOPE_MISMATCH` JSON and writes no WAL intent. |
| scoped UDS route stale generation | route returns stale response without attach/update/detach. |
| scoped UDS route hash conflict | route returns `generation_hash_conflict` JSON without attach/update/detach. |
| scoped intent records only target | WAL requested/affected port ids contain no unrelated ports. |
| scoped success preserves unrelated statuses | only target status generation changes. |
| scoped target failure has no false ready | `applied_generation` is not advanced and target is degraded/error. |

Python tests before service-loop submitter:

| Test | Expected Result |
| --- | --- |
| UDS client requires scoped capability | no port-scoped submit when capability is absent. |
| config gate blocks incremental | `incremental_rpc_enabled=true` remains rejected until accepted gate. |
| dry-run can fall back | unsafe decision or missing target returns full-resync fallback reason. |

Smoke tests before production enablement:

- existing P2 fanout/foreign-host/source-cleanup smokes still pass;
- new P3 incremental smoke proves one-port ACL update changes only that port;
- forced index loss falls back to full resync;
- rollback to polling-only keeps OVS connectivity and full-resync recovery.

## Acceptance For Starting Rust Code

Before opening the Rust implementation PR, all of these must be true:

- this plan is linked from plan 09 and the detail README;
- `docs/neutron-uds-contract.json` marks the route
  `rust_route_implemented_capability_disabled`;
- `ci/check_neutron_stage1.py` requires the route to exist while still requiring
  `capability_advertised=false`, `python_submitter_enabled=false`, and
  `incremental_rpc_enabled_default=false`;
- Python P3-2 dry-run tests pass;
- stage-one, stage-two, and stage-three checks pass.

## Non-Goals

- No batch scoped apply.
- No network scoped apply.
- No QoS/Mirror expansion.
- No TCP or OpenAPI exposure.
- No new Rust storage backend.
- No Neutron DB transaction coupling.
