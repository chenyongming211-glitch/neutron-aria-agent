# REVIEW-OPS-037 Bounded OVS Admission Plan

> Execute directly on `v0.9-neutron-agent`. Do not create a branch/worktree and
> do not run local Cargo commands.

## Design Source

Follow
`docs/superpowers/specs/2026-07-31-review-ops-037-bounded-ovs-admission-design.md`.

## Task 1: RED bounded-process behavior

- [ ] Add a narrow injectable inventory-command seam.
- [ ] Prove a slow command reaches the deadline and returns non-authoritative
      inventory.
- [ ] Prove the timeout drops/kills the child.
- [ ] Prove ordinary output retains current parsing and eligibility.
- [ ] Push RED and record the exact hosted failure.

## Task 2: RED lock and revalidation behavior

- [ ] Prove OVS discovery runs without holding the mutation guard.
- [ ] Prove an intervening runtime change retries discovery.
- [ ] Prove retry exhaustion writes no WAL intent and changes no runtime.
- [ ] Prove an unchanged admission identity reaches prepared apply.

## Task 3: GREEN implementation

- [ ] Replace synchronous commands with bounded Tokio child execution.
- [ ] Add the two-lock admission/revalidation loop with bounded retries.
- [ ] Preserve pending deduplication and `inventory_unavailable` behavior.
- [ ] Push and require exact-head hosted GREEN.

## Task 4: Closure

- [ ] Record RED/GREEN commits and Build ids in this plan and the design.
- [ ] Update `REVIEW-OPS-037` to fixed only after exact-head CI passes.

## Exclusions

- Do not change WAL publication order or background apply.
- Do not add a generic async transaction framework.
- Do not add Python source-shape checks.
- Do not introduce a user-facing OVS timeout setting in this batch.

