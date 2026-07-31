# REVIEW-ACL-036/037/028 Pending And Delete Transaction Plan

> Execute directly on `v0.9-neutron-agent`. Do not create a branch/worktree.

## Design Source

Follow
`docs/superpowers/specs/2026-07-31-review-acl-036-037-028-pending-delete-design.md`.

## Task 1: RED state-store invariant

- [ ] Add durable and in-memory tests for exact pending reuse.
- [ ] Prove a different pending snapshot cannot be overwritten.
- [ ] Prove conflict leaves the complete state preimage unchanged.

## Task 2: RED scoped event-loop behavior

- [ ] Prove terminal pending is recovered before a new scoped prepare.
- [ ] Prove unresolved snapshot/delete pending blocks UDS mutation.
- [ ] Prove response and terminal-status failures retain pending and degrade
      runtime without changing the committed projection.

## Task 3: RED delete behavior

- [ ] Reject explicit error, malformed, wrong-port, and contradictory responses.
- [ ] Preserve pending delete and committed projection on failure.
- [ ] Accept direct and timeout-recovered success.
- [ ] Remove the deleted port from cached status and recompute summaries.
- [ ] Push RED and record exact hosted failure evidence.

## Task 4: GREEN implementation

- [ ] Add the state-store pending conflict guard.
- [ ] Route scoped events through recovery before prepare.
- [ ] Add one scoped-failure degradation boundary.
- [ ] Add strict delete response validation and failure degradation.
- [ ] Add cached port-status removal on committed delete.
- [ ] Run targeted Python tests and push for exact-head fast-contract CI.

## Task 5: Closure

- [ ] Record commits and Build ids in the design and plan.
- [ ] Update `REVIEW-ACL-036`, `REVIEW-ACL-037`, and `REVIEW-ACL-028` only
      after exact-head hosted GREEN.

## Exclusions

- Do not clear unproven pending state merely to unblock a new event.
- Do not modify Rust snapshot publication.
- Do not absorb status-reporter ordering (`REVIEW-ACL-008/033`).

