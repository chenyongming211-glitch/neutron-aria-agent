# REVIEW-ACL-008/033 Fail-Safe Status Publication Plan

> Execute directly on `v0.9-neutron-agent`. Do not create a branch/worktree.

## Design Source

Follow
`docs/superpowers/specs/2026-07-31-review-acl-008-033-status-publication-design.md`.

## Task 1: RED global-degradation projection

- [ ] Seed ready/enforce cached port status.
- [ ] Mark the runtime globally degraded.
- [ ] Prove top-level and nested rows become degraded/bypass.
- [ ] Prove identity fields remain and aggregates are recomputed.

## Task 2: RED fail-safe publication ordering

- [ ] Prove ready publishes port rows then heartbeat.
- [ ] Prove ready port-row failure suppresses the new heartbeat.
- [ ] Prove degraded publishes heartbeat then port rows.
- [ ] Prove degraded port-row failure retains the degraded heartbeat evidence.
- [ ] Prove a first-phase failure suppresses the second phase.
- [ ] Push RED and record exact hosted failure evidence.

## Task 3: GREEN implementation

- [ ] Add conservative cached-port transformation to `mark_degraded`.
- [ ] Replace positional composite iteration with explicit fail-safe phases.
- [ ] Preserve single-reporter behavior and stable factory construction.
- [ ] Run targeted Python tests and push for exact-head fast-contract CI.

## Task 4: Closure

- [ ] Record commits and Build ids in the design and plan.
- [ ] Update `REVIEW-ACL-008` and `REVIEW-ACL-033` only after exact-head
      hosted GREEN.

## Exclusions

- Do not claim distributed atomicity across RabbitMQ and SQL.
- Do not add a batch REST resource in this batch.
- Do not hide reporter failures or convert an unexecuted phase into success.
