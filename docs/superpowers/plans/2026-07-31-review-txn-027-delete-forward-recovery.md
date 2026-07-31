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

- [x] Add a test for the after-detach fault boundary.
- [x] Assert the error reports `detached:false`.
- [x] Assert the live authoritative runtime retains the port.
- [x] Assert the runtime is operator-blocked with the hashless delete pending
      identity.
- [x] Assert WAL replay retains the exact unmatched delete intent.
- [x] Add the equivalent delete-commit append failure test.
- [x] Add the durable success ordering test.
- [x] Push the RED commit and record the exact failing hosted CI evidence.

The tests may target a concrete delete-finalization helper so they do not need
privileged TC/eBPF attachment. They must validate runtime and WAL behavior, not
private source text.

## Task 2: Implement the post-detach finalization boundary

- [x] Add a concrete committed-delete runtime builder.
- [x] Add a concrete blocked-delete runtime builder.
- [x] Route both the after-detach fault and delete-commit append failure through
      one concrete finalizer.
- [x] Publish the port-absent runtime only after `DeleteCommit` succeeds.
- [x] Return `detached:true` only on that durable success path.
- [x] Keep the unmatched intent and retained-port blocked runtime on failure.

## Task 3: Make startup delete recovery close forward

- [x] On successful delete runtime recovery, clear pending state, restore the
      applied snapshot hash identity, and append `DeleteCommit`.
- [x] Publish the port-absent runtime only after that commit.
- [x] On runtime recovery failure, do not append a commit that clears the
      intent.
- [x] On recovery-commit failure, preserve the unmatched intent and publish the
      retained-port blocked runtime.
- [x] Add RED/GREEN behavior coverage for all three outcomes.

## Task 4: Hosted verification and closure

- [x] Push the GREEN production commit.
- [x] Require exact-head `fast-contracts`, `rust-behavior`, and `rust-build`
      success.
- [x] Update the authoritative backlog row for `REVIEW-TXN-027`.
- [x] Record RED/GREEN commit ids and hosted build ids in this plan and design.
- [x] Commit and push the documentation closure.
- [x] Re-run exact-head hosted CI if the closure commit changes executable
      detection inputs.

Evidence:

- RED `7bfb88f`, Build
  [`30612312902`](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/30612312902):
  `fast-contracts` passed and `rust-behavior` failed only on the missing
  `finalize_detached_neutron_delete` /
  `finalize_recovered_delete_intent` boundaries.
- GREEN production `efb113c`; exact verified head `f8b72b8`, Build
  [`30612826096`](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/30612826096):
  `fast-contracts`, `rust-behavior`, and warning-denied `rust-build` passed.
- The closure is documentation-only, so executable change detection does not
  require another Rust/eBPF build.

## Exclusions

- Do not change snapshot `rollback_to_last_applied`.
- Do not add recovery-cause enum values or a new UDS endpoint.
- Do not implement `REVIEW-ACL-045`.
- Do not add static checkers tied to helper names or source layout.
- Do not claim privileged environment evidence.

## Next Work

After TXN-027 is closed, begin the independent `REVIEW-ACL-045` orphan
managed-runtime scrub design and RED cycle.
