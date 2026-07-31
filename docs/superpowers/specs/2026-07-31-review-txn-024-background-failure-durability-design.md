# REVIEW-TXN-024 Background Apply Failure Durability Design

Date: 2026-07-31

Status: approved sequence; source design complete; RED and production
implementation pending

Analyzed target:
`v0.9-neutron-agent@98034c15ee344ec2d9d035dfb233d6e971e05278`

Tracked finding:

- `REVIEW-TXN-024`: a background snapshot apply error can leave only an
  in-memory degraded classification after the snapshot intent is durable.

## 1. Executive Decision

Handle every currently reachable snapshot error after the durable intent while
the function still owns the exact `PendingNeutronIntent` and
`runtime_before_apply`.

The existing `before_commit` and snapshot-commit failures already call
`recover_failed_snapshot_transaction`, compensate affected runtime state, and
attempt to persist a blocked recovery commit. The remaining uncovered prefix
is:

```text
append snapshot intent
  -> publish live applying state
  -> neutron.snapshot.after_intent returns error
  -> return before any datapath apply
  -> background wrapper changes RAM only
```

For that prefix, the implementation will durably commit:

```text
complete previous applied baseline
+ pending_generation = failed intent generation
+ desired_hash = failed intent hash
+ authority_state = blocked_recovery_required
```

The previous applied generation, applied hash, ports, and port statuses remain
unchanged because the datapath transaction has not started. The live
`wal_status` records `background_apply_failed:<code>`; restart correctness does
not depend on that diagnostic string because the durable pending identity and
blocked authority are sufficient to require `recover-pending`.

No new WAL entry variant, schema field, generic transaction framework, or
public API is introduced.

## 2. Corrected Current Root Cause

`submit_neutron_snapshot` returns a pending response after the snapshot intent
is fsynced and spawns `apply_neutron_snapshot_for_scope`.

That apply function has three explicit error exits:

1. `neutron.snapshot.after_intent`;
2. `neutron.snapshot.before_commit`; and
3. `append_snapshot_commit`.

The second and third exits already invoke
`recover_failed_snapshot_transaction`, publish a blocked runtime, and attempt
to append the matching blocked snapshot commit.

Only the first exit returns without durable classification. The outer task
then calls `mark_snapshot_background_error`, which has only generation/hash
and the current RAM snapshot. It lacks the authoritative intent and previous
baseline required to write a safe terminal record. Persisting arbitrary RAM
from that outer function would be unsafe because a future error could occur
after partial datapath mutation.

Therefore the fix belongs at the concrete after-intent boundary, not in a
generic background-error catch-all.

## 3. Transaction Ordering

The failure ordering becomes:

```text
snapshot intent fsync
  -> live state = applying
  -> after-intent check fails
  -> construct blocked state from runtime_before_apply
  -> append blocked snapshot commit and fsync
  -> publish blocked state to RAM
  -> return the original apply error
  -> outer background marker observes blocked state and preserves it
```

The blocked snapshot commit resolves the WAL intent but intentionally retains
the pending generation in the committed state. Restart therefore reconstructs
the same blocked pending identity and the existing `recover-pending` API can
atomically restore the last applied baseline.

## 4. WAL Commit Failure

If the blocked snapshot commit itself fails:

```text
original snapshot intent remains pending in WAL
live pending identity remains unchanged
authority_state = pending_recovery_commit_failed
wal_status = commit_failed
```

The outer background marker already preserves
`pending_recovery_commit_failed`. Restart replays the still-pending original
intent and uses the existing incomplete-intent recovery path. The
implementation must not claim that the blocked state was durable.

## 5. Datapath Semantics

No datapath compensation runs for this failure prefix.

That is deliberate:

- the fault occurs before `apply_snapshot_runtime_transaction`;
- the old applied datapath remains authoritative;
- attaching, purging ACL, or detaching here would create a mutation solely as
  part of handling an error that happened before mutation began.

Failures after runtime apply remain routed through
`recover_failed_snapshot_transaction` and retain their current conservative ACL
bypass/blocked recovery behavior.

## 6. Concrete Interface

Add one concrete helper in `agent/src/neutron_api.rs`:

```rust
async fn handle_snapshot_after_intent_fault(
    state: &NeutronApiState,
    intent: &PendingNeutronIntent,
    previous: &NeutronRuntimeState,
    fault: Result<(), String>,
) -> Result<(), SnapshotApplyError>
```

Behavior:

- `Ok(())` returns without changing WAL or RAM;
- `Err(details)` builds and attempts to persist the blocked previous baseline;
- a successful blocked commit is published to RAM only after the append
  succeeds;
- a failed blocked commit publishes only the explicit in-memory
  `pending_recovery_commit_failed` state while retaining the original intent;
  and
- the returned error keeps `code="fault_injection"` and the original details.

`apply_neutron_snapshot_for_scope` calls this helper immediately after intent
admission and before runtime apply.

## 7. RED And GREEN Contracts

Rust behavior tests must prove:

1. after-intent failure durably commits the old applied baseline plus the exact
   failed pending generation/hash;
2. restart reconstructs `blocked_recovery_required` rather than losing the
   failure as generic replay state;
3. `recover-pending` clears that durable pending identity back to the last
   applied baseline and permits later full resync;
4. blocked-commit failure leaves the original intent pending and publishes
   `pending_recovery_commit_failed` only in RAM;
5. the outer background marker cannot overwrite either blocked state; and
6. an `Ok(())` after-intent check performs no extra WAL commit.

The first RED commit contains tests only. Production code follows only after
the hosted Rust behavior job proves the missing helper/contract.

## 8. Explicit Exclusions

This batch does not:

- change delete transaction behavior (`REVIEW-TXN-027`);
- change orphan runtime cleanup (`REVIEW-ACL-045`);
- change snapshot commit-failure compensation;
- add a general failure-record WAL variant;
- persist arbitrary outer-task RAM;
- change Python recovery semantics;
- change Status V1 schema; or
- claim privileged field execution.

## 9. Verification

- Local: `git diff --check`, documentation/static fast contracts only.
- Hosted RED: `rust-behavior` fails on the missing concrete after-intent
  durability helper while `rust-build` remains independently observable.
- Hosted GREEN: `fast-contracts`, `rust-behavior`, and warning-denied
  `rust-build` all pass on the exact production commit.
- Privileged environment: not required because this prefix deliberately
  performs no datapath mutation.
