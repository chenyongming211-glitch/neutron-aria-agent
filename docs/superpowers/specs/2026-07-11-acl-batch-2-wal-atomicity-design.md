# ACL Batch 2 WAL Atomicity Design

Date: 2026-07-11

Status: approved for implementation

## Goal

Close the second ACL repair batch by making snapshot admission, WAL intent,
datapath mutation, WAL commit, in-memory status, and pending recovery obey one
crash-consistent transaction order.

The authoritative order is:

```text
validate and plan
  -> WAL intent fsync
  -> publish pending
  -> mutate managed runtime
  -> WAL commit fsync
  -> publish accepted/applied/status
```

No response or in-memory field may claim durable acceptance before the intent
exists. No failed commit may leave uncommitted ACL policy active. No fallible
post-commit operation may regress a transaction that is already durable.

## Scope

This batch fixes three P1 findings:

- `REVIEW-TXN-021`: snapshot submission advances `accepted_generation` and
  returns `accepted` before WAL intent is durable.
- `REVIEW-TXN-022`: a failure after datapath mutation but before WAL commit
  leaves new runtime state live while RAM and replay still describe the old
  committed generation.
- `REVIEW-TXN-025`: WAL commit can succeed, then a post-commit error can return
  before the new committed state is published to RAM.

## Non-Goals

- Do not implement a distributed transaction with Neutron DB.
- Do not add a new WAL backend or WAL compaction; unbounded WAL growth remains
  `REVIEW-OPS-019`.
- Do not persist a full previous ACL preimage or implement exact policy
  rollback. The existing WAL does not contain enough old ACL content for that.
- Do not change ACL priority, stateful, conntrack-foundation, or restart
  hash-skip semantics tracked by `REVIEW-ACL-047`, `REVIEW-ACL-050`,
  `REVIEW-ACL-054`, and `REVIEW-ACL-035`.
- Do not fix delete-specific detach/commit ordering tracked by
  `REVIEW-TXN-024` and `REVIEW-TXN-027`.
- Do not block the OVS forwarding path solely because the ACL enhancement
  transaction cannot commit.

## Confirmed Root Causes

### Admission Before Intent

`accept_neutron_snapshot_submit` currently changes RAM to
`accepted_pending_intent`, advances `accepted_generation`, and returns
`status=accepted`. The background task acquires the apply lock and appends the
WAL intent later. A process exit or scheduling gap between those operations
leaves no durable evidence of the accepted generation.

### Runtime Mutation Before Failed Commit

`apply_snapshot_runtime_transaction` mutates attach and ACL runtime before
`append_snapshot_commit`. Both the `neutron.snapshot.before_commit` fault and a
commit append failure return without undoing those mutations. The error path
only changes a few RAM metadata fields and leaves the original WAL intent
pending.

### Durable Commit Before RAM Publication

After `append_snapshot_commit` succeeds, the
`neutron.snapshot.after_commit` fault runs before `*runtime = next_runtime`.
A return-error action therefore leaves RAM on the older pending state even
though WAL and datapath contain the newer committed generation. The current
recover-pending path reads RAM only and can append that older view over the
newer commit.

## Transaction Invariants

The implementation must preserve all of the following:

1. `accepted_generation` means the generation has a durable classified commit;
   a durable intent alone is represented by `pending_generation`.
2. A `pending` HTTP response is returned only after WAL intent fsync succeeds.
3. The apply lock is held continuously from transaction planning and intent
   append through runtime mutation and commit publication.
4. A pre-commit failure leaves ACL in explicit bypass, not in an uncommitted
   enforcement state.
5. A successful WAL commit is final. Later return-error hooks cannot change it
   back into a failed or pending transaction.
6. Recover-pending must compare durable WAL state with RAM before writing a
   rollback commit and must never reduce a newer committed generation.
7. Recovery failures keep Neutron authority and the apply gate active. They do
   not release the port to local writers.

## Architecture

### 1. Durable Pending Handoff

Keep the asynchronous snapshot API, but move intent creation into the request
path before the response is returned.

For a new snapshot:

1. Perform a fast RAM check for an existing pending transaction so duplicate
   and conflicting requests can return without waiting for a long apply.
2. Acquire an owned apply lock and repeat the generation/hash/pending checks to
   close the race between the fast check and lock acquisition.
3. Load the local interface inventory and build the complete
   `SnapshotApplyTransaction` while the lock is held.
4. Append and fsync the WAL snapshot intent containing the requested ports,
   affected ports, and affected domains.
5. Publish RAM state with the new `pending_generation`, desired hash,
   `authority_state=applying`, and `wal_status=intent_written`. Keep
   `accepted_generation` and `applied_generation` at their last committed
   values.
6. Move the owned lock guard and the already-built transaction into the
   background apply task. There is no unlock/relock window in which delete or
   another snapshot can change the baseline.
7. Return HTTP success with `status=pending`. The response reports the previous
   accepted/applied generations and the durable pending generation remains
   available through the status endpoint.

An intent append failure returns `wal_intent_failed`, leaves RAM generations
unchanged, and does not spawn an apply task.

Same-hash requests observed while the transaction is pending return `pending`
without starting another task. Different-hash requests return the existing
conflict response.

### 2. Shared Pre-Commit Failure Recovery

All failures after runtime mutation and before a successful commit use one
recovery path. This includes the explicit `before_commit` fault and a failed
`append_snapshot_commit`.

This path is only for transaction-level failures that prevent a durable commit.
A per-port/domain error that is deliberately classified and successfully
written as a partial commit keeps the existing classified-partial semantics;
it is not scrubbed merely because `has_error=true`.

The recovery path reuses the existing WAL-intent recovery primitives:

- for a port that existed in the previous committed state, restore/retain its
  attach topology and scrub the Neutron-owned ACL;
- for a newly attached uncommitted port, scrub ACL and detach the Aria runtime;
- for a port detached by the failed transaction, restore the committed attach
  topology when possible;
- mark every affected ACL domain `blocked` with
  `effective_action=bypass` and a stable recovery reason;
- preserve unrelated local domains and OVS forwarding.

The resulting RAM state is based on the previous committed runtime. It keeps
the failed generation in `pending_generation`, keeps accepted/applied at the
previous committed generation, and uses:

```text
authority_state = blocked_recovery_required
wal_status       = commit_failed
```

The implementation attempts to append a classified blocked-recovery state
after scrub. If that append succeeds, restart replay retains the blocked
pending state. If storage still fails, RAM remains blocked and the original
durable intent drives startup recovery.

New snapshot mutation is not allowed while this pending recovery exists.
Status, diagnostics, and the explicit recover-pending endpoint remain allowed.

### 3. Python Recovery From Blocked Pending

The Python agent already knows how to invoke recover-pending when the remote
pending hash differs. It must also recognize a recoverable blocked authority
state even when the remote desired hash equals the local desired hash.

For `blocked_recovery_required`, `wal_commit_failed`, or an equivalent
recovered-pending state:

1. stop normal convergence polling early;
2. keep the Python local snapshot pending and mark runtime degraded;
3. on the next full resync, choose remote recovery before the same-hash wait
   path;
4. call recover-pending with the exact remote generation/hash;
5. re-read remote status and submit a new full snapshot above the resulting
   generation floor.

If remote recovery fails, the agent remains degraded and does not overwrite or
discard either pending record.

### 4. Commit Publication Is Final

After runtime mutation succeeds:

1. build the classified `next_runtime`;
2. append and fsync the snapshot commit;
3. immediately assign `next_runtime` to the in-memory runtime;
4. only then execute the `neutron.snapshot.after_commit` fault point and other
   non-transactional observation/logging work.

A return-error action at `after_commit` is logged as a post-commit warning and
the apply returns the committed success response. It does not call the
background failure marker. A process-exit fault still terminates the process;
startup replay restores the committed WAL state.

### 5. Recover-Pending Anti-Regression Guard

`recover_pending_snapshot` continues to run under the apply lock. Before it
computes a rollback-to-last-applied state, it replays the WAL and compares the
latest valid durable state with RAM.

If WAL proves a newer commit than RAM:

- refresh RAM from that WAL state;
- do not append a rollback commit;
- return a structured `already_committed` recovery response reflecting the
  durable generation.

Only when WAL and RAM agree that the generation is still pending may recovery
clear the pending metadata to the last applied baseline. Blocked/bypass port
status remains conservative until the subsequent full resync commits a new
ready state.

## State Transitions

| Event | Accepted | Applied | Pending | Authority | ACL action |
| --- | ---: | ---: | ---: | --- | --- |
| Last committed baseline | N | N | none | ready/partial | committed result |
| Intent fsynced | N | N | N+1 | applying | unchanged until apply |
| Runtime apply in progress | N | N | N+1 | applying | staged/mutating |
| Commit succeeds | N+1 | N+1 or N on classified partial | none or N+1 | ready/partial | classified result |
| Pre-commit failure recovered | N | N | N+1 | blocked_recovery_required | bypass |
| Recover-pending clears blocked state | N | N | none | recovered_pending_full_resync_required | bypass until resync |
| New full resync commits | N+2 | N+2 | none | ready/partial | newly classified result |

For a classified partial commit, existing semantics may retain
`pending_generation`; that behavior is not widened beyond what this batch
needs. The critical rule is that a failed durable commit never advances
accepted/applied.

## Error And Status Semantics

| Condition | Required result |
| --- | --- |
| Validation or plan failure | Existing 4xx response; no WAL/RAM mutation |
| WAL intent append failure | HTTP 500 `wal_intent_failed`; generations unchanged |
| WAL intent durable | HTTP 200 `pending`; accepted/applied unchanged |
| Same-hash duplicate while pending | HTTP 200 `pending`; no second task |
| Different hash while pending | HTTP 409 `snapshot_apply_in_progress` |
| Apply or commit failure after mutation | Status blocked, pending retained, ACL bypass, no new mutation |
| after-commit return-error | Warning only; committed result remains successful |
| Process exit after commit | Startup WAL replay restores committed result |
| WAL newer than RAM during recovery | RAM refreshed; `already_committed`; no rollback write |

## Files Expected To Change

Runtime and WAL:

- `agent/src/neutron_api.rs`: durable pending handoff, owned-lock apply path,
  shared failure recovery, commit publication order, recovery anti-regression,
  and focused Rust tests.
- `agent/src/neutron_wal.rs`: only small replay/comparison helpers if the
  existing replay result cannot express the required durable-state check.
- `agent/src/fault_injection.rs`: only if a deterministic append-failure test
  needs a narrowly scoped fault point; do not redesign the fault framework.

Python recovery:

- `openstack/neutron_aria/neutron_aria/agent/event_loop.py`: blocked-pending
  classification and automatic recover-before-wait behavior.
- `openstack/neutron_aria/neutron_aria/tests/unit/test_event_loop.py`: pending,
  blocked recovery, and convergence regression tests.

Documentation:

- `docs/openstack-neutron-aria-details/12-review-bug-backlog.md`: close only the
  three verified findings after tests and CI pass.
- `docs/openstack-neutron-aria-details/07-transaction-wal.md` and
  `docs/openstack-neutron-agent-mode.md`: align current transaction status and
  pending response semantics where required.

## Test Strategy

Every behavior change follows red-green-refactor. Rust tests are added before
the implementation but are compiled and executed only by GitHub Actions in
accordance with the checkout policy.

Focused Rust tests:

- a new snapshot cannot return `pending` until the WAL contains its intent;
- intent publication keeps `accepted_generation` at the committed baseline;
- the owned apply lock prevents an intervening mutation between intent and
  commit;
- `before_commit` and commit-append failure paths scrub affected ACL to bypass,
  retain pending, and enter blocked recovery;
- a new snapshot cannot mutate while blocked recovery is pending;
- `after_commit` return-error leaves WAL, RAM, and status on the new committed
  generation;
- recovery reloads a newer valid WAL commit instead of appending an older RAM
  state;
- process restart after intent and after commit follows the corresponding
  replay path.

Focused Python tests:

- a normal `pending` response is polled until committed convergence;
- blocked same-hash pending chooses recover-pending rather than indefinite
  waiting;
- failed recovery leaves the local pending transaction intact and marks the
  agent degraded;
- successful recovery causes a new full snapshot above the remote generation
  floor.

Allowed local validation:

- focused and complete Python unit suites;
- `python3 -m compileall`;
- Neutron Stage 1/2/3 and embedded smoke checks;
- shell syntax and `git diff --check`.

Rust validation:

- do not run local `cargo build`, `cargo check`, or `cargo test`;
- push the branch and manually dispatch the existing GitHub Build workflow;
- inspect and repair CI failures until Rust tests, eBPF, userspace, and agent
  static builds pass.

## Acceptance Criteria

- A snapshot response cannot claim durable pending before intent fsync.
- `accepted_generation` does not advance for intent-only or commit-failed
  transactions.
- The apply lock has no gap between the planned intent and its runtime apply.
- Any post-mutation pre-commit failure leaves affected ACL blocked/bypass and
  preserves OVS forwarding.
- New snapshot mutation is refused until blocked pending recovery is cleared.
- Python automatically recovers same-hash blocked pending state before full
  resync instead of waiting indefinitely.
- A successful commit is immediately visible in RAM and cannot be regressed by
  a post-commit return-error or recover-pending call.
- The three backlog IDs are marked fixed only after local checks and GitHub
  Actions pass.

## Delivery

Implementation is isolated on `codex/acl-batch-2-wal-atomicity`, based on the
green Batch 1 commit. The existing uncommitted `README.md` change is excluded.
The design, implementation plan, TDD slices, backlog closure, and CI follow-up
are committed separately so the transaction changes remain reviewable.
