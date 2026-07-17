# Versioned Rust-Python Status Contract

Status: approved and implemented on the Batch 2C branch. Local Python and
static verification is complete; final Rust/eBPF verification remains owned by
the required GitHub Actions build before merge.

Batch: 2C, after `REVIEW-TXN-028` and `REVIEW-TXN-029`, before
`REVIEW-ACL-046`.

## Decision Summary

Keep `GET /api/v1/neutron/status` and add an independent, additive Status V1
projection. Rust owns the mapping from internal runtime/WAL strings to a stable
transaction state, overall readiness, and required action. Python validates
that projection and the existing generation/hash/domain evidence before it
decides whether a classification, feature-ready projection, poll, or recovery
operation is allowed.

The design separates two concepts that the unversioned response currently
mixes:

- a generation can be safely classified as degraded; and
- only a fully verified ready classification can update feature-ready
  projection or a ready heartbeat.

This preserves the safety result of `REVIEW-TXN-028` without redefining the
parent generation vocabulary. Legacy V0 keeps the exact TXN-028 behavior.
Status V1 may record an exactly verified classified-degraded generation, but it
must not call the existing feature-ready `commit_snapshot()` path, replace the
last feature-ready projection, or call `mark_ready()`.

## Confirmed Problem

The existing snapshot request schema is versioned, but the status response is
not:

- `schema_version_min/max` in capabilities describes accepted snapshot input.
  It does not version `GET /status`.
- Rust `NeutronStatusResponse` exposes generation, hash, authority, WAL, port,
  and domain fields without a status schema version.
- Python `LocalClient.status()` returns decoded JSON without contract
  validation.
- Python then copies Rust implementation tokens into
  `RECOVERY_REQUIRED_AUTHORITY_STATES` and
  `TERMINAL_FAILURE_AUTHORITY_STATES`.

That copied vocabulary has already drifted. Rust can emit
`recovered_pending_full_resync_required`, while the Python recovery set only
contains `recovered_pending_full_resync`. `wal_status` is also unsuitable as a
wire enum because it mixes replay state, reconciliation state, recovery causes,
commit results, and dynamic values such as `background_apply_failed:<code>`.

Two additional compatibility facts are part of the design:

- The legacy `generation` field is currently populated from
  `applied_generation`, despite its older comment. Status V1 must preserve it as
  a deprecated alias of `applied_generation`; changing its meaning would be a
  breaking change.
- `recovery_cause` is already persisted in Rust runtime/WAL state for the
  `inventory_unavailable` barrier, but it is not exposed in the status response.
  Python should not have to rediscover that cause by combining unrelated
  diagnostic strings.

## Status V1 Wire Shape

Capabilities add the following independent fields:

```json
{
  "status_schema_version_min": 1,
  "status_schema_version_max": 1,
  "status_contract_hash": "v0.9-neutron-status-1"
}
```

The status response adds these top-level fields:

```json
{
  "status_schema_version": 1,
  "status_contract_hash": "v0.9-neutron-status-1",
  "transaction_state": "idle|pending|classified|blocked|recovery",
  "overall_readiness": "ready|degraded|blocked|unknown",
  "required_action": "none|poll|recover_pending|full_resync|operator",
  "recovery_cause": null,
  "last_classified_generation": 42
}
```

The existing identity and evidence fields remain required and keep their current
meaning:

- `generation` is a deprecated alias of `applied_generation`;
- `accepted_generation`, `applied_generation`, and `pending_generation`;
- `last_classified_generation`;
- `desired_hash` and `applied_desired_hash`;
- `wal_replay_failures`;
- unique `managed_ports` and `port_statuses` rows;
- unique domain rows for every validated port;
- domain `status`, `effective_action`, and `support_disposition` evidence.

`authority_state` and `wal_status` remain available for diagnostics and
backward compatibility. A V1 Python client must not derive control actions from
their implementation-specific values.

History ownership is deliberately asymmetric so Status V1 does not expand the
Rust WAL shape:

- Rust derives `last_classified_generation` from the current durable
  classified/applied state. It does not persist per-domain feature-ready
  history.
- Python persists two explicit local tracks:
  - the classified track contains generation, desired hash, and projected port
    IDs. It owns generation floors, `ProjectedStateIndex`, scoped/delete event
    routing, and restart reconstruction;
  - the feature-ready track contains the last ready generation/hash/projection
    plus `last_feature_ready_generation_by_domain`. It owns ready evidence and
    heartbeat only.
- Existing unversioned Python state is migrated conservatively by seeding both
  tracks from the current `last_generation`, `last_desired_hash`, and
  `last_projected_port_ids`. Legacy V0 continues updating both tracks only after
  TXN-028 terminal-ready validation.

This preserves the parent vocabulary without asking one Rust status snapshot to
reconstruct per-domain history that the current WAL does not contain.

Status V1 is independent of snapshot `schema_version` and the global UDS
`contract_version`. The first additive rollout does not change the global
`contract_version` or `capability_hash`; `status_contract_hash` owns exact
Status V1 vocabulary drift.

## State, Readiness, and Action Rules

Rust computes the projection in this priority order:

1. WAL/replay uncertainty or unknown internal state;
2. pending transaction identity;
3. recovery phase and persisted recovery cause;
4. whether the generation is structurally classified;
5. port/domain results and runtime health.

It must not select a state or readiness by switching on `authority_state`
alone.

| Runtime evidence | `transaction_state` / `overall_readiness` | `required_action` | Required behavior |
| --- | --- | --- | --- |
| No accepted snapshot, generation 0, and no pending intent | `idle/unknown` | `full_resync` | Not ready; submit the first authoritative full snapshot. |
| Apply is active with a complete pending identity | `pending/unknown` | `poll` | Read only; never submit, recover, or classify while polling. |
| Complete classified identity, no pending intent, zero WAL replay failures, and all requested domains terminal-ready | `classified/ready` | `none` | Eligible for Python's independent feature-ready validation. |
| Complete classified identity with a terminal degraded domain result | `classified/degraded` | `none` | Advance the Python classified generation/hash/projected IDs and clear only its matching pending marker; preserve the feature-ready track and publish degraded. |
| A previously classified baseline has runtime degradation that requires rebuilding | `classified/degraded` | `full_resync` | Preserve the feature-ready projection and retry only through a compatible full resync. |
| Apply/WAL state is unsafe but an exact pending identity is recoverable | `blocked/blocked` | `recover_pending` | Recovery is allowed only after exact generation/hash validation plus a recognized cause/action pair. |
| Contract, WAL, identity, or internal state is unknown or inconsistent | `blocked/blocked` | `operator` | Fail closed; no snapshot, delete, or recovery write. |
| Verified rollback restored the applied baseline and cleared pending | `recovery/degraded` | `full_resync` | Not ready; rebuild through a newer authoritative full snapshot. |

Allowed state/readiness/action triples are closed in V1. Unknown values or an
invalid combination are contract errors. Unknown optional fields in a known
schema may be ignored.

The initial `recovery_cause` vocabulary is also closed: `null` is permitted for
recognized non-generation-0 recovery, and `inventory_unavailable` is the only
typed automatic-recovery cause. Any other value normalizes to
`blocked/blocked/operator`; Python makes no mutating call. Python validates the
vocabulary and state/action pairing, while Rust validates the exact persisted
cause, barrier identity, and WAL lineage.

At the response boundary, V1 domain status is normalized to
`ready`, `not_requested`, `degraded`, or `blocked`. ACL effective action is
one of the parent vocabulary values: `enforce`, `bypass`, `unchanged`,
`cleanup`, or `no_op`. `support_disposition` is required and is one of
`supported`, `unsupported`, `unknown`, or `not_applicable`. A requested ACL can
contribute to ready only as `ready/enforce/supported`; an explicitly unrequested
ACL uses `not_requested` with the parent-compatible bypass/no-op and
not-applicable evidence. Unknown domain values can never contribute to ready.

Rust should implement these as typed response-boundary enums. It must not
replace the existing runtime/WAL string fields with strict enums in this batch,
because historical WAL values must remain replayable.

## Four Shared Scenarios

`idle` and `pending` are supporting non-terminal states. The four cross-language
decision scenarios required by Batch 2C are combinations of the orthogonal
fields above:

### 1. Success

- Rust: `classified/ready/none`,
  `accepted_generation == applied_generation == last_classified_generation == G`,
  `pending_generation == null`, both hashes equal the submitted hash,
  `generation == applied_generation`, zero WAL replay failures, and complete
  full/scoped port and domain support evidence.
- Python: independently verifies the exact target identity and the applicable
  full/scoped evidence. Only then may it update feature-ready local
  state/projection, update the classified track, advance the applicable
  `last_feature_ready_generation_by_domain`, and call `mark_ready()`.
- A producer ready label never overrides a generation, hash, duplicate row,
  missing row, support, or domain mismatch.

### 2. Degraded

- Rust: either `classified/degraded/none` for a safely classified terminal
  generation or `classified/degraded/full_resync` for runtime damage that needs
  rebuilding. A degraded response with an unsafe pending identity is invalid.
- Python: for the `none` case, advances the exact classified
  generation/hash/projected IDs, rebuilds event-routing state from that track,
  and clears only the matching pending marker. For both cases it preserves the
  previous feature-ready track, publishes a degraded heartbeat, and never calls
  `mark_ready()`.
- Legacy V0 degraded behavior is not relaxed. Only an exact, negotiated V1
  classification can use the separate classified-generation path.

### 3. Blocked

- Rust: a protected pending generation/hash is retained when available; the
  state is `blocked/blocked`; the action is `recover_pending` only for a
  recognized, recoverable state and otherwise `operator`.
- Python: does not commit the target, does not replace projection state, and
  preserves local pending state. It must not turn an unknown status contract
  into scoped-to-full fallback or another mutating request.

### 4. Recovery

- Before rollback, the state remains `blocked/blocked/recover_pending`; there is
  no invented persisted “recovery in progress” phase. Python may call the
  existing endpoint only when generation/hash exactly match its expected
  pending identity and `recovery_cause` belongs to the closed V1 vocabulary and
  is valid for that state/action pair. Rust remains responsible for exact
  persisted cause, WAL barrier, and fresh-replay validation.
- After rollback: Python reads status again. A cleared pending intent with
  `recovery/degraded/full_resync` is the only V1 `recovery` state. It restores
  only the last applied baseline; Python realigns the classified track to that
  verified baseline but does not establish or advance feature-ready state.
- Python then creates a fresh full snapshot above the latest generation floor.
  Only that snapshot's later `classified/ready/none` response may become ready.

The generation-0 exception approved with `REVIEW-TXN-029` remains narrow.
Automatic rollback to an empty baseline is allowed only when all of these are
true:

- `recovery_cause == "inventory_unavailable"`;
- `applied_generation == 0` and `applied_desired_hash == null`;
- `managed_ports` and `port_statuses` are empty;
- a complete protected pending generation/hash exists;
- the WAL barrier and replay checks used by the existing two-stage recovery
  path remain valid.

Any other generation-0 blocked state requires `operator` and cannot be inferred
as an empty baseline.

## Version Negotiation and Rolling Compatibility

Python uses two explicit decoders during the compatibility window:

| Capabilities and response | Decoder behavior |
| --- | --- |
| Both omit Status V1 metadata | Legacy V0 adapter; accept only the currently deployed TXN-028 complete identity/domain shape. |
| Capabilities advertise V1 and status returns matching version/hash | Strict V1 validation. |
| Capabilities advertise V1 but status omits or mismatches it | `LocalApiContractError`; blocked/no-write. |
| Either side declares an unknown version/hash | `LocalApiContractError`; blocked/no-write. |
| No prior handshake but status self-declares supported V1 | Validate strict V1; the next write still requires a successful capabilities handshake. |

The Legacy V0 adapter has a closed authority vocabulary; complete field shape
alone is not enough:

| Legacy `authority_state` | Conservative normalized decision |
| --- | --- |
| `ready` with exact TXN-028 identity/domain evidence | `classified/ready/none` |
| `idle` | `idle/unknown/full_resync` |
| `applying` or `accepted` with a complete pending identity | `pending/unknown/poll` |
| `runtime_degraded` or `degraded` with no pending identity and an internally consistent applied baseline | `classified/degraded/full_resync`, without classifying a new local pending generation |
| `runtime_degraded` or `degraded` with a pending identity | `blocked/blocked/operator` |
| `partial`, `blocked_recovery_required`, or `recovered_pending_full_resync` with a complete pending identity | `blocked/blocked/recover_pending` |
| `recovered_pending_full_resync_required` with no pending identity | `recovery/degraded/full_resync` |
| commit failures, WAL uncertainty, malformed combinations, or any unknown token | `blocked/blocked/operator` |

An unknown Legacy V0 token is a no-write contract failure. In particular, it
cannot be converted into recover-pending, snapshot PUT/DELETE, or a scoped-to-
full fallback even when generation/hash fields are otherwise complete.

Rollout order is Python first, then Rust:

1. New Python introduces the strict V1 decoder plus the bounded legacy adapter.
2. New Rust begins advertising and returning V1.
3. After an observed compatibility window, removal of legacy V0 requires a
   separate explicit decision.

The reverse mixed pair is also safe: old Python ignores additive fields from new
Rust and continues using the already strict TXN-028 validation. This depends on
not changing the global contract/capability hash in the additive rollout.

Contract errors have a stronger boundary than ordinary local API errors:

- they cannot be swallowed as an unavailable generation floor;
- they cannot be converted into “continue submit” behavior;
- scoped apply cannot convert them into a full-resync fallback;
- snapshot, delete, and recover-pending writes remain disabled until a supported
  contract is observed.

`required_action=recover_pending` refers only to the already implemented server
and Python endpoint. Batch 2C does not add a new capability flag and does not
silently close `REVIEW-DOC-022`, which separately tracks the missing route and
request/response/error declaration in `docs/neutron-uds-contract.json`. If
route-parity documentation becomes necessary to implement this design, work
must pause for explicit approval to expand scope.

## Single Shared Scenario Source

After design approval, add one machine-readable scenario artifact referenced by
`docs/neutron-uds-contract.json`:

```text
docs/neutron-status-contract-v1-scenarios.json
```

Rust and Python tests must load the same scenario IDs and payloads. The minimum
set is:

1. full classified-ready success;
2. scoped success with unaffected older ports;
3. classified-degraded terminal result that records only classification state;
4. degraded runtime requiring full resync;
5. pending apply requiring polling;
6. blocked recoverable inventory failure;
7. blocked operator-only WAL/contract failure;
8. recovery complete but full resync required;
9. generation-0 inventory-unavailable recovery;
10. legacy V0 success;
11. complete Legacy V0 identity with an unknown authority token and zero
    mutating calls;
12. unknown version/hash/state/readiness/action or recovery cause;
13. producer says ready but identity, domain, support, or duplicate-row evidence is
    invalid;
14. restart after a classified-degraded port-set change, proving scoped update
    and delete routing use classified projected IDs while ready history remains
    unchanged.

The shared artifact records the wire payload and expected Python decision. Rust
also has focused unit tests that construct internal runtime states and prove
they project to the artifact's stable state/readiness/action.

## Implementation Sequence After Approval

No step below is authorized until the user approves this design.

1. RED: add the shared scenario artifact and failing Python contract/client,
   dual-track state migration, event-loop, restart, scoped/delete routing, and
   scoped-fallback tests.
2. RED: add Rust response-serialization and internal-state projection tests
   against the same scenario IDs.
3. Record the intended failing GitHub Build; do not use local Cargo.
4. GREEN: add Rust boundary DTO/projection and capability metadata without
   changing WAL persistence types or the UDS route.
5. GREEN: add Python negotiation, strict V1/legacy adapters, typed contract-error
   propagation, separate classified-versus-feature-ready handling, and action
   handling. Persist the dual tracks in backward-compatible Python local state,
   reconstruct event routing from the classified track, and keep per-domain
   feature-ready history in the feature-ready track/heartbeat without weakening
   Legacy V0 TXN-028 validation.
6. Update `docs/neutron-uds-contract.json` and the Stage 1 static checker so the
   Status V1 constants, Python constants, and shared artifact cannot drift.
   Do not add the independently tracked recover-pending route contract without
   separate approval.
7. Run Python/static checks locally, push, and use GitHub Actions for all Rust,
   eBPF, static-binary, and warning verification.

## Non-Goals

- Do not start or partially fix `REVIEW-ACL-046`.
- Do not change ACL selector/group publication, CT invalidation, rule priority,
  overlap policy, or datapath behavior.
- Do not change the existing WAL recovery algorithm, WAL record shape, or
  persisted string types.
- Do not add a V2 route or change `/api/v1/neutron/status`.
- Do not add QoS, Mirror, rich `details`, UI vocabulary, product DB status, or a
  heartbeat redesign. The existing parent-required `support_disposition` field
  is part of V1, not an optional expansion.
- Do not remove the legacy decoder in the first rollout.
- Do not close unrelated documentation backlog items while implementing this
  contract.
- Do not close or partially repair `REVIEW-DOC-022` without explicit scope
  approval.

## Approval and Implementation Record

The approved implementation scope covered:

1. the independent schema/hash and additive rollout;
2. the transaction/readiness/action vocabulary and exact generation-0
   exception;
3. the separate classified-degraded versus feature-ready handling, including
   Python ownership of the two durable tracks, classified-track event routing,
   and the rule that only classified-ready updates feature-ready projection;
4. the parent-required `support_disposition` evidence;
5. the Python-first legacy compatibility window;
6. the single shared scenario artifact and RED-first implementation sequence.

Approval was received before the shared Python and Rust RED phases. The branch
now contains the shared fixture, Rust projection, Python compatibility and
dual-track state handling, drift checker, and review-driven fail-closed
regressions described above. The 14-scenario vocabulary, Rust WAL shape,
recover-pending route contract, and unrelated ACL backlog remain unchanged.

Local Python, static-contract, warning-hygiene, and change-detection gates are
green. Per repository policy, the final Rust tests, eBPF builds, static binary
checks, and warning verification must pass on GitHub Actions before this PR is
marked ready to merge.
