# D3 Maintenance Control Bounded Repair Plan

## Status

Approved: retain the current D3 implementation and perform one finite
RED/GREEN repair wave for the independent closure-review findings.

The independent review was performed at checkout head
`3285de8ab23953168268af9eb13196e7d31b87a5` against production head
`ad57f6ac382ab09038891d37f94ca0e2163bc301`. It reported no Critical finding,
five Important findings, and `Ready: No`.

## Decision Not To Split D3

The malformed-replay finding touches D3-B durable state and D3-C public
projection, so the closure design requires an explicit refactor decision. The
implementation is retained because the defect can be repaired without changing
the packet gate, the public maintenance request/response shapes, or the
coordinator/store interface:

- reject semantically incomplete checkpoint state at the WAL boundary;
- represent unaddressable corrupt replay as blocked operator recovery with
  unknown ACL truth, not as an addressable maintenance transaction;
- teach the existing Status v4 decoder that exact non-maintenance blocked row.

No behavior-preserving module extraction is required for these changes. A
structural split remains deferred unless the focused GREEN repair requires an
interface change across `model`, `wal`, `coordinator`, and `audit`.

## Constraints

- Work directly on clean synchronized `main`; no branch or worktree.
- Do not run local Cargo, rustfmt, Clippy, or another local Rust compiler.
- Tests precede production changes and must produce exact hosted RED evidence.
- Do not modify `abi/src`, `ebpf/src`, D3-A live authority, workflows, or stack
  limits.
- Keep `maintenance_gate_capable=false`.
- Do not implement Task 5/6 buffering, resync, health, Kolla, or rollback work.
- Field evidence remains `deferred/pending`.
- After GREEN, request one re-review limited to D3-B-2, D3-B-3, D3-C-3, and
  D3-C-4. No new open-ended review wave is authorized.

## Repair 1: Freeze Conservative Abort Terminal Identity (D3-B-2)

### RED

Add a production-seam coordinator test in
`agent/src/neutron_maintenance.rs`:

`neutron_maintenance_conservative_abort_terminal_fences_progress_and_retry_state`

The test must:

1. enter an active transaction;
2. finish a conservative Abort in `maintenance_bypass`;
3. prove matching full-host progress admission and progress preparation are
   rejected without WAL, gate, or RAM mutation;
4. retry the same Abort and receive the exact persisted terminal state.

### GREEN

Treat a persisted terminal action as a writer fence while retaining the
documented Abort-to-Exit recovery path. Do not store a second mutable terminal
copy and do not change request schemas.

## Repair 2: Reject Invalid Checkpoint Rows And Project Corrupt Replay (D3-B-3)

### RED

Add focused tests in `agent/src/neutron_maintenance.rs` and
`agent/src/neutron_api.rs`:

- `neutron_maintenance_checkpoint_rejects_active_state_without_identity`;
- `neutron_maintenance_corrupt_unaddressable_replay_projects_operator_unknown`.

The first test supplies active/checkpoint rows with missing operation ID,
missing ACL domain, inactive retained identity, or incompatible phase identity.
Every row must fail replay.

The second test uses the production coordinator/status projection after a
maintenance replay failure with no last-good transaction. It must remain
fenced, report `blocked/blocked/operator`, report ACL enforcement `unknown`,
carry no fake maintenance transaction identity, and be rejected by all normal
writers.

### GREEN

Add one phase-aware state-row validator used by record decoding/replay. Keep
corrupt replay blocked and gate-unknown internally, but do not fabricate a user
operation ID. Project an unaddressable recovery as the existing operator action
with unknown ACL enforcement and no maintenance action/identity.

## Repair 3: Enforce The 64 KiB Maintenance Limit Before Allocation (D3-B-3)

### RED

Add reader tests in `agent/src/neutron_wal.rs`:

- `neutron_maintenance_wal_reader_caps_type_first_record_at_64k`;
- `neutron_maintenance_wal_reader_rejects_unclassified_record_past_64k`;
- retain an ordinary snapshot record above 64 KiB to prove the shared Neutron
  WAL limit is not globally reduced.

The tests inspect the retained record buffer and require it never to grow past
`MAINTENANCE_WAL_RECORD_MAX_BYTES` for maintenance or unclassified input.

### GREEN

Classify the top-level WAL entry type from a bounded prefix. A record may grow
beyond 64 KiB only after it is positively classified as a known
non-maintenance Neutron entry. Maintenance or still-unclassified input is
drained and rejected at the maintenance boundary. The existing 16 MiB general
Neutron record and 64 MiB file limits remain unchanged.

## Repair 4: Make The Rust Blocked Status Consumable (D3-C-3)

### RED

Add:

- a Rust test in `agent/src/neutron_api.rs` requiring the production
  ACL-runtime-schema-blocked response to report ACL enforcement `unknown`;
- an authoritative legal scenario in
  `docs/neutron-status-contract-v4-scenarios.json` for
  `blocked/blocked/operator`, no maintenance identity, and unknown ACL truth;
- Python contract coverage proving the production
  `_decode_status(..., STATUS_CONTRACT_V4)` accepts that exact scenario while
  continuing to reject ready/classified unknown enforcement.

### GREEN

Emit truthful `unknown` enforcement from the Rust blocked response and accept
it only for the exact non-maintenance `blocked/blocked/operator` Status v4 row.
Do not loosen maintenance action/identity/phase consistency.

## Repair 5: Audit Pre-Handler Admin Rejections (D3-C-4)

### RED

Add one production-router test in `agent/src/neutron_api.rs`:

`neutron_maintenance_admin_extractor_failures_emit_one_attempt_and_result`

Exercise malformed JSON, missing/wrong content type, and over-limit request
bodies on the three mutating admin routes. Each request must emit exactly one
bounded Attempt and one Failure, with no policy body or unbounded rejection
text recorded.

### GREEN

Make each mutating handler receive `Result<Json<T>, JsonRejection>` (or an
equivalent typed rejection seam). For extraction failure, emit the same action's
bounded Attempt/Failure pair and return the normal Axum rejection response.
Valid requests continue to use coordinator-owned Attempt plus exactly one
handler/coordinator result; no middleware-wide duplicate audit is allowed.

## Hosted RED Gate

Commit only tests, fixtures, and this checker wiring. Push to `main` and wait
for the exact-head Actions run to become terminal. Record:

- expected `rust-behavior` failure names for all Rust seams;
- expected `fast-contracts` failure for the new production Status v4 scenario;
- independent `rust-build` and linked stack result.

No production file may be modified before this evidence exists.

## Hosted GREEN Gate

After the genuine RED, implement only the five repairs. Allowed local checks:

```text
git diff --check
python3 -m unittest -v ci.test_neutron_maintenance_contract
python3 ci/check_neutron_stage1.py --fast-contracts
```

Commit and push, then require terminal exact-head success for fast contracts,
database/install, Rust behavior, Rust/eBPF/userspace/agent builds, and linked
`tc_ingress`/`tc_egress <= 480` evidence.

## Re-review And Closure Rule

The re-review may inspect only D3-B-2, D3-B-3, D3-C-3, and D3-C-4 at the GREEN
head. If no Critical/Important remains, record `Ready: Yes` and resume Task 6
of `2026-08-22-d3-maintenance-control-closure.md`. Any remaining blocking
finding stops D3; it does not authorize another broad remediation wave.
