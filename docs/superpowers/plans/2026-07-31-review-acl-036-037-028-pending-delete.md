# REVIEW-ACL-036/037/028 Pending And Delete Transaction Plan

> Execute directly on `v0.9-neutron-agent`. Do not create a branch/worktree.

## Design Source

Follow
`docs/superpowers/specs/2026-07-31-review-acl-036-037-028-pending-delete-design.md`.

## Task 1: RED state-store invariant

- [x] Add durable and in-memory tests for exact pending reuse.
- [x] Prove a different pending snapshot cannot be overwritten.
- [x] Prove conflict leaves the complete state preimage unchanged.

## Task 2: RED scoped event-loop behavior

- [x] Prove terminal pending is recovered before a new scoped prepare.
- [x] Prove unresolved snapshot/delete pending blocks UDS mutation.
- [x] Prove response and terminal-status failures retain pending and degrade
      runtime without changing the committed projection.

## Task 3: RED delete behavior

- [x] Reject explicit error, malformed, wrong-port, and contradictory responses.
- [x] Preserve pending delete and committed projection on failure.
- [x] Accept direct and timeout-recovered success.
- [x] Remove the deleted port from cached status and recompute summaries.
- [x] Push RED and record exact hosted failure evidence.

## Task 4: GREEN implementation

- [x] Add the state-store pending conflict guard.
- [x] Route scoped events through recovery before prepare.
- [x] Add one scoped-failure degradation boundary.
- [x] Add strict delete response validation and failure degradation.
- [x] Add cached port-status removal on committed delete.
- [x] Run targeted Python tests and push for exact-head fast-contract CI.

## Task 5: Closure

- [x] Record commits and Build ids in the design and plan.
- [x] Update `REVIEW-ACL-036`, `REVIEW-ACL-037`, and `REVIEW-ACL-028` only
      after exact-head hosted GREEN.

## Evidence

- RED: `c847761`, Build
  [`30615481157`](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/30615481157)
  failed on the 11 intended behaviors with no unittest errors.
- GREEN: `2bd1726`, Build
  [`30615746741`](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/30615746741)
  passed 176 targeted tests and the 515-test fast-contract path.
- Combined exact-head Build
  [`30616520693`](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/30616520693)
  remained GREEN.

## Exclusions

- Do not clear unproven pending state merely to unblock a new event.
- Do not modify Rust snapshot publication.
- Do not absorb status-reporter ordering (`REVIEW-ACL-008/033`).
