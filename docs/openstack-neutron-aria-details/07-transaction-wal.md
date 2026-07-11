# 07. Transaction, WAL, And Snapshot Apply Detail Plan

Status: stage-one implementation package; snapshot intent/commit crash
consistency is implemented for the current `attach + acl` scope. WAL lifecycle
management (compaction/rotation) remains separate follow-up work.

## Goal

Define the v0.9 transaction boundary for Neutron snapshots, local datapath
apply, WAL durability, timeout recovery, replay, and idempotency.

This plan records the transaction design and the minimum stage-one code/test
prep. It should not be expanded into new tenant features or a broader
multi-writer authority model during this stage.

## Scope

The transaction path covers:

- `PUT /api/v1/neutron/snapshot`;
- `DELETE /api/v1/neutron/ports/{port_id}`;
- generation and desired hash handling;
- WAL intent/commit records;
- partial apply and crash recovery;
- retry and timeout recovery;
- local write gate interaction with Neutron-managed state.

P3 port-scoped snapshot apply reuses this transaction model with a bounded
affected-port set. Its Rust minimum design and tests are recorded separately in
`10-rust-scoped-apply.md` and must not remove full-resync recovery.

## Current State

| Area | Status | Notes |
| --- | --- | --- |
| Rust WAL intent/commit | implemented for snapshot crash consistency | Snapshot admission fsyncs intent before returning `pending`; commit is final before post-commit hooks; pre-commit failure restores attach topology and scrubs ACL to bypass. Delete and WAL lifecycle hardening retain separate backlog items. |
| Python local transaction state | partial | Snapshot/delete prepare and commit state exists. |
| Timeout recovery | partial | Python can query status after timeout and decide whether to converge. Stale local pending snapshot records are cleared only when datapath status proves a newer committed generation. |
| Idempotent generation handling | partial | Same generation replay and desired hash behavior exist in Rust side. |
| Rich transaction status | planned | Needs clearer external status projection and contract tests. |

## Transaction Boundary

Snapshot apply follows this high-level order:

```text
1. Validate schema, host, authority, generation, and supported domains.
2. Acquire single-writer apply lock.
3. Perform Neutron-managed preflight and build the bounded transaction plan.
4. Write and fsync the WAL snapshot intent.
5. Publish only `pending_generation`/`intent_written` and return `pending`;
   accepted/applied remain on the last commit.
6. Move the same apply lock and prepared transaction into background apply.
7. Attach or reconcile runtime in inert/bypass mode.
8. Apply groups/address-sets and the requested ACL domain.
9. Compute per-port and per-domain status.
10. Write and fsync the WAL commit.
11. Immediately publish accepted/applied/status RAM state.
12. Run fallible post-commit observation hooks; a return-error is a warning,
    not a transaction rollback.
```

If any mandatory step before WAL commit fails, the generation must not be
reported as fully committed. Domain degraded states are allowed only when they
are explicitly classified and safe for OVS forwarding.

## WAL Records

Minimum record kinds:

| Record | Purpose |
| --- | --- |
| snapshot intent | Durable record that a generation apply started. |
| snapshot commit | Durable record that the classified result is complete. |
| delete intent | Durable record that a Neutron port delete started. |
| delete commit | Durable record that delete cleanup completed or classified. |

Intent without commit must be recoverable. Recovery may replay, scrub, or wait
for full resync, but must not silently widen permissions.

## Generation And Desired Hash

Rules:

- Older generation with different desired state is stale and must not overwrite
  newer classified state.
- Same generation with same desired hash is idempotent.
- Same generation with different desired hash is a conflict and must be rejected
  or classified as error.
- `accepted_generation` advances only after the classified WAL commit is
  durable; an intent-only `pending` response does not advance it. It does not
  mean every domain is ready.
- Feature readiness must be tracked per domain.

## Timeout Recovery

Client timeout does not prove apply failed.

Required Python behavior:

1. Submit snapshot/delete.
2. On timeout, query UDS status.
3. If status converged to submitted generation/hash, commit local state.
4. If status is older or degraded, full resync or retry according to reason.
5. Never bump generation solely because the HTTP client timed out.

## Crash Recovery

On datapath restart:

- replay committed state;
- inspect intent without commit;
- scrub incomplete Neutron-owned ACL/QoS state when safe;
- preserve local standalone state separately from Neutron-managed state;
- wait for full resync when recovery cannot prove correctness.

A successfully claimed interface proves only that attach and the tap-local
runtime replay/validation succeeded. The tap-local WAL does not share the
Neutron ACL desired hash, so restart recovery does not use attach success as
proof that ACL is current:

- `attach` remains `ready`;
- managed ACL becomes `degraded` with
  `effective_action=unchanged` and
  `reason=acl_restart_replay_requires_resync`;
- only the ACL entry in `domain_desired_hashes` is removed;
- authority becomes `runtime_reconcile_requires_full_resync`;
- same-generation and same-hash shortcuts are disabled until full resync
  executes and commits ACL reconcile.

If an unresolved pending recovery already exists, its pending generation,
authority, and WAL status take precedence. Restart invalidation still removes
the ACL skip hash and marks ACL degraded, but does not overwrite the stronger
recovery classification.

The invalidated state is appended to the Neutron WAL before RAM publication.
If that append fails, RAM still publishes the invalidated hash/status with
`authority_state=wal_runtime_reconcile_commit_failed` and
`wal_status=commit_failed`. The next restart repeats recovery from the older
WAL, while the current process cannot skip ACL using false-ready metadata.

On Python agent restart:

- load pending snapshot/delete state;
- query UDS status;
- commit local state if converged;
- clear stale local pending snapshot state only when UDS status has already
  advanced to a newer applied generation with no runtime pending transaction;
- otherwise mark degraded and trigger full resync when allowed.

For a runtime pending state whose authority is
`blocked_recovery_required`, `wal_commit_failed`,
`wal_recovery_commit_failed`, `pending_recovery_commit_failed`, or
`recovered_pending_full_resync`, Python calls the exact recover-pending
generation/hash before same-hash convergence waiting.
After successful recovery it re-reads status and submits above the refreshed
generation floor. Recovery failure leaves the local pending record intact and
the agent degraded.

## Snapshot Commit Failure Boundary

If datapath mutation succeeds but the snapshot cannot commit, the current
implementation does not attempt an ACL policy preimage rollback. It uses the
approved availability-first boundary:

- recover or retain the last committed attach topology where possible;
- scrub affected Neutron-owned ACL state;
- classify every affected ACL domain as `blocked` with
  `effective_action=bypass`;
- keep accepted/applied on the last committed generation;
- retain the failed generation/hash as pending and set
  `authority_state=blocked_recovery_required`;
- refuse later snapshot mutation until explicit pending recovery succeeds.

The blocked classification is appended to WAL when storage permits. If that
second append also fails, RAM remains blocked with
`wal_status=recovery_commit_failed`, and the original durable intent drives
startup recovery.

## ACL Update And Conntrack Boundary

Neutron ACL replacement uses the approved availability-first sequence:

1. disable the ACL gate;
2. replace and activate the desired ACL bank;
3. strictly clear both `CT_TABLE_V4` and `CT_TABLE_V6` for the tap;
4. enable the ACL gate only when the desired policy is non-empty and every
   prior step succeeded.

Missing or invalid map pins, iterator errors, and entry-removal errors all fail
strict CT clear. An error after gate disable returns ACL `error` with
`effective_action=bypass` and does not enable enforcement. Translation or
pre-disable failure leaves the previous gate untouched and reports
`effective_action=unchanged`. The general management `ct_flush` retains its
legacy lenient behavior; only the Neutron ACL transaction requires strict
clearing.

## Durable Commit Finality

Once snapshot commit fsync succeeds, that commit is final. RAM is published
before `neutron.snapshot.after_commit`; a return-error at that hook is logged
and the committed success response is retained. A process-exit action still
terminates the process, and restart rebuilds RAM from WAL.

Recover-pending replays WAL under the apply lock before constructing a rollback
state. If a valid WAL commit is newer than RAM and no unresolved intent
supersedes it, recovery refreshes RAM and returns `already_committed`; it does
not append the older RAM generation over the durable commit.

## Local Write Gate Interaction

Local persistent writes for domains in `managed_domains` must remain blocked
during:

- normal managed state;
- degraded communication;
- pending transaction recovery;
- WAL replay;
- rejoin pending.

Communication failure is not authority release.

## Implementation Design Package

This package is detailed to file/state/flow/test level. Do not expand to
function-call level until the transaction PR is opened.

### Target Files

| File | Role |
| --- | --- |
| `api/src/lib.rs` | Snapshot/delete/status DTOs, generation, desired hash, and domain status fields. |
| `agent/src/neutron_api.rs` | Rust UDS handlers for snapshot/delete/status and apply orchestration. |
| `agent/src/neutron_wal.rs` | Rust WAL record model, append, replay, scrub, and commit semantics. |
| `agent/src/control_plane.rs` and `core/src/state.rs` | Current Rust control-plane/runtime state paths affected by Neutron-managed domains and local write gate. |
| `openstack/neutron_aria/neutron_aria/agent/state.py` | Python pending snapshot/delete transaction state. |
| `openstack/neutron_aria/neutron_aria/agent/event_loop.py` | Full resync/event loop transaction submission and retry orchestration. |
| `openstack/neutron_aria/neutron_aria/agent/uds_client.py` | Timeout-aware UDS submit/status reconciliation. |
| `openstack/neutron_aria/neutron_aria/tests/unit/` | Python unit tests for prepare/commit/recovery behavior. |
| `deploy/kolla/smoke/` | Smoke coverage for snapshot, delete, timeout, and recovery gates. |

### Snapshot Apply Flow

Python side:

1. Build desired snapshot from authoritative sources.
2. Compute `generation` and `desired_hash`.
3. Persist local pending transaction state.
4. Submit `PUT /api/v1/neutron/snapshot`.
5. If the request returns success with matching generation/hash, commit local
   transaction state.
6. If the request times out, query status before retrying or committing.
7. If status cannot prove convergence, mark degraded and schedule resync
   according to configured gates.

Rust side:

1. Validate request schema, host, authority, generation, desired hash, and
   domains.
2. Acquire the Neutron apply lock.
3. Reject stale generation or same-generation hash conflict.
4. Append snapshot intent to WAL.
5. Apply or reconcile datapath state in safe order.
6. Classify each domain as ready, degraded, bypass, unsupported, or error.
7. Append snapshot commit to WAL.
8. Update in-memory accepted/applied/status state.
9. Return a response that does not overstate readiness.

### Delete Flow

Python side:

1. Persist local pending delete state for the port.
2. Submit `DELETE /api/v1/neutron/ports/{port_id}`.
3. On timeout, query status before considering the delete complete.
4. If convergence cannot be proven, leave the port in pending recovery and
   schedule resync.

Rust side:

1. Validate route, port id, and authority.
2. Acquire the Neutron apply lock.
3. Append delete intent.
4. Remove Neutron-owned state for that port only.
5. Preserve unrelated local standalone state.
6. Append delete commit and update status.

### State Model

| State | Meaning | Required Behavior |
| --- | --- | --- |
| no pending transaction | Agent/datapath agree on current committed state or have not started. | Normal apply path. |
| pending local snapshot | Python has prepared a generation but not committed local state. | Submit or reconcile via status. |
| stale Python pending snapshot | Python still has an older pending generation, while datapath reports a newer applied generation with no runtime pending transaction. | Clear the Python pending fields, record `last_cleared_pending_*`, and run a new full resync using the datapath generation as the floor. |
| WAL intent without commit | Datapath started apply but crashed or failed before commit. | Replay, scrub, or wait for full resync; never claim ready. |
| committed with degraded domain | Generation was classified, but one or more domains are not enforcing. | Report per-domain status and keep local gate active. |
| same generation same hash | Idempotent replay. | Return converged state without widening permissions. |
| same generation different hash | Conflict. | Reject or classify as error. |
| stale generation | Older desired state. | Reject and keep newer classified state. |

### Error And Status Semantics

| Condition | Required Code/Status |
| --- | --- |
| WAL append fails before intent | Request fails; do not modify accepted generation. |
| WAL intent exists but apply fails | Domain or transaction status degraded/error; no false ready. |
| WAL commit fails after datapath mutation | Restore attach where possible, scrub affected ACL to bypass, retain prior accepted/applied, and require pending recovery. |
| WAL commit succeeds, post-commit return-error fires | Keep committed WAL/RAM state and report the classified success; log the hook error. |
| Recover-pending sees newer valid WAL commit than RAM | Refresh RAM and return `already_committed`; do not append a rollback. |
| Same generation, different desired hash | `generation_hash_conflict` stable error. |
| Older generation | `stale_generation` stable status reason. |
| Client timeout | Python marks pending and reconciles with status; timeout is not authority release. |
| Same-generation Python pending hash mismatch | Python keeps the pending record and reports `stale_pending_snapshot_requires_operator`; it must not auto-clear. |
| Older Python pending hash mismatch with newer committed datapath status | Python clears only the stale pending fields and resubmits full snapshot with a newer generation. |
| Recovery in progress | Local writes for managed domains remain blocked. |

### Test Matrix

| Test | Expected Result |
| --- | --- |
| Snapshot intent without commit then restart | Replay/scrub path does not claim ready until proven. |
| Delete intent without commit then restart | Port cleanup is retried or classified without deleting unrelated local state. |
| Same generation and same hash replay | Idempotent success. |
| Same generation with different hash | Rejected or classified as conflict. |
| Older generation after newer commit | Rejected. |
| WAL append failure | No accepted/applied generation is advanced. |
| WAL commit failure after ACL mutation | Affected ACL is scrubbed and reported `blocked/bypass`; prior committed generations remain authoritative. |
| Return-error after WAL commit | WAL and RAM retain the new committed generation. |
| Stale RAM pending with newer WAL commit | Recover-pending returns `already_committed` without regressing WAL. |
| Blocked same-hash remote pending | Python recovers the exact pending generation/hash before submitting a fresh full snapshot. |
| UDS timeout with later convergence | Python commits local transaction only after status proves match. |
| UDS timeout without convergence | Python remains pending/degraded and schedules resync. |
| Stale Python pending with newer datapath generation | Python clears stale pending state, records the clear reason, and full-resyncs at a generation above the datapath floor. |
| Crash after ACL gate disabled | Result is bypass/degraded, not half-enforced ready. |
| Local write during recovery | Rejected for domains in `managed_domains`. |

### Anti-Overengineering Guardrails

- No distributed transaction with Neutron DB.
- No per-rule or per-object multi-writer merge model in v0.9.
- No complex TCP state-machine recovery in the transaction layer.
- No new WAL storage backend unless the current backend cannot satisfy the
  acceptance tests.

## Acceptance

- Intent without commit is tested for snapshot and delete.
- Same generation replay is idempotent.
- Same generation hash conflict is rejected or classified.
- Timeout recovery commits local state only after status proves convergence.
- Crash after ACL gate disabled leaves datapath in bypass, not half-enforced.
- WAL failure prevents false ready/accepted reporting.
- Local writes remain blocked for Neutron-managed domains during recovery.

## Non-Goals

- Do not build a distributed transaction across Neutron DB and datapath.
- Do not guarantee every independent domain is ready when a snapshot is accepted.
- Do not add object-level multi-writer ownership in this phase.
- Do not make break-glass merge local override with Neutron state automatically.
