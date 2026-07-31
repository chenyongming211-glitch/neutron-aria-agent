# REVIEW-TXN-027 Delete Forward-Recovery Implementation Plan

> Execute on the sole `v0.9-neutron-agent` branch. Do not create a worktree or
> branch. Do not run local Cargo commands; use hosted CI for Rust behavior and
> build evidence.

## Goal

Make post-detach delete failures truthful and restart-recoverable without
reusing snapshot rollback or changing the public WAL/status contract.

## Design Source

Follow
`docs/superpowers/specs/2026-07-31-review-txn-027-delete-forward-recovery-design.md`
exactly.

## Task 1: Add RED post-detach behavior tests

- [ ] Add a test for the after-detach fault boundary.
- [ ] Assert the error reports `detached:false`.
- [ ] Assert the live authoritative runtime retains the port.
- [ ] Assert the runtime is operator-blocked with the hashless delete pending
      identity.
- [ ] Assert WAL replay retains the exact unmatched delete intent.
- [ ] Add the equivalent delete-commit append failure test.
- [ ] Add the durable success ordering test.
- [ ] Push the RED commit and record the exact failing hosted CI evidence.

The tests may target a concrete delete-finalization helper so they do not need
privileged TC/eBPF attachment. They must validate runtime and WAL behavior, not
private source text.

## Task 2: Implement the post-detach finalization boundary

- [ ] Add a concrete committed-delete runtime builder.
- [ ] Add a concrete blocked-delete runtime builder.
- [ ] Route both the after-detach fault and delete-commit append failure through
      one concrete finalizer.
- [ ] Publish the port-absent runtime only after `DeleteCommit` succeeds.
- [ ] Return `detached:true` only on that durable success path.
- [ ] Keep the unmatched intent and retained-port blocked runtime on failure.

## Task 3: Make startup delete recovery close forward

- [ ] On successful delete runtime recovery, clear pending state, restore the
      applied snapshot hash identity, and append `DeleteCommit`.
- [ ] Publish the port-absent runtime only after that commit.
- [ ] On runtime recovery failure, do not append a commit that clears the
      intent.
- [ ] On recovery-commit failure, preserve the unmatched intent and publish the
      retained-port blocked runtime.
- [ ] Add RED/GREEN behavior coverage for all three outcomes.

## Task 4: Hosted verification and closure

- [ ] Push the GREEN production commit.
- [ ] Require exact-head `fast-contracts`, `rust-behavior`, and `rust-build`
      success.
- [ ] Update the authoritative backlog row for `REVIEW-TXN-027`.
- [ ] Record RED/GREEN commit ids and hosted build ids in this plan and design.
- [ ] Commit and push the documentation closure.
- [ ] Re-run exact-head hosted CI if the closure commit changes executable
      detection inputs.

## Exclusions

- Do not change snapshot `rollback_to_last_applied`.
- Do not add recovery-cause enum values or a new UDS endpoint.
- Do not implement `REVIEW-ACL-045`.
- Do not add static checkers tied to helper names or source layout.
- Do not claim privileged environment evidence.

## Next Work

After TXN-027 is closed, begin the independent `REVIEW-ACL-045` orphan
managed-runtime scrub design and RED cycle.
