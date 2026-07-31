# REVIEW-ACL-008/033 Fail-Safe Status Publication Plan

> Execute directly on `v0.9-neutron-agent`. Do not create a branch/worktree.

## Design Source

Follow
`docs/superpowers/specs/2026-07-31-review-acl-008-033-status-publication-design.md`.

## Task 1: RED global-degradation projection

- [x] Seed ready/enforce cached port status.
- [x] Mark the runtime globally degraded.
- [x] Prove top-level and nested rows become degraded/bypass.
- [x] Prove identity fields remain and aggregates are recomputed.

## Task 2: RED fail-safe publication ordering

- [x] Prove ready publishes port rows then heartbeat.
- [x] Prove ready port-row failure suppresses the new heartbeat.
- [x] Prove degraded publishes heartbeat then port rows.
- [x] Prove degraded port-row failure retains the degraded heartbeat evidence.
- [x] Prove a first-phase failure suppresses the second phase.
- [x] Push RED and record exact hosted failure evidence.

## Task 3: GREEN implementation

- [x] Add conservative cached-port transformation to `mark_degraded`.
- [x] Replace positional composite iteration with explicit fail-safe phases.
- [x] Preserve single-reporter behavior and stable factory construction.
- [x] Run targeted Python tests and push for exact-head fast-contract CI.

## Task 4: Closure

- [x] Record commits and Build ids in the design and plan.
- [x] Update `REVIEW-ACL-008` and `REVIEW-ACL-033` only after exact-head
      hosted GREEN.

## Evidence

- RED: `c847761`, Build
  [`30615481157`](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/30615481157).
- GREEN: `2bd1726`, Build
  [`30615746741`](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/30615746741)
  passed 176 targeted tests and all 515 fast contracts.
- Combined exact-head Build
  [`30616520693`](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/30616520693)
  remained GREEN.

## Exclusions

- Do not claim distributed atomicity across RabbitMQ and SQL.
- Do not add a batch REST resource in this batch.
- Do not hide reporter failures or convert an unexecuted phase into success.
