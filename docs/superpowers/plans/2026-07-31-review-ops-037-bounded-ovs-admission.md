# REVIEW-OPS-037 Bounded OVS Admission Plan

> Execute directly on `v0.9-neutron-agent`. Do not create a branch/worktree and
> do not run local Cargo commands.

## Design Source

Follow
`docs/superpowers/specs/2026-07-31-review-ops-037-bounded-ovs-admission-design.md`.

## Task 1: RED bounded-process behavior

- [x] Add a narrow injectable inventory-command seam.
- [x] Prove a slow command reaches the deadline and returns non-authoritative
      inventory.
- [x] Prove the timeout drops/kills the child.
- [x] Prove ordinary output retains current parsing and eligibility.
- [x] Push RED and record the exact hosted failure.

## Task 2: RED lock and revalidation behavior

- [x] Prove OVS discovery runs without holding the mutation guard.
- [x] Prove an intervening runtime change retries discovery.
- [x] Prove retry exhaustion writes no WAL intent and changes no runtime.
- [x] Prove an unchanged admission identity reaches prepared apply.

## Task 3: GREEN implementation

- [x] Replace synchronous commands with bounded Tokio child execution.
- [x] Add the two-lock admission/revalidation loop with bounded retries.
- [x] Preserve pending deduplication and `inventory_unavailable` behavior.
- [x] Push and require exact-head hosted GREEN.

## Task 4: Closure

- [x] Record RED/GREEN commits and Build ids in this plan and the design.
- [x] Update `REVIEW-OPS-037` to fixed only after exact-head CI passes.

## Evidence

- RED: `b127807`, Build
  [`30615820795`](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/30615820795)
  (`rust-behavior` failed on the two missing boundaries; static build cancelled
  after RED).
- GREEN: `f6e0f9b`; filter-proof commit `4b02277`.
- Exact-head GREEN: Build
  [`30616520693`](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/30616520693)
  passed both named OVS admission behaviors and all required build jobs.
- No local Cargo command was run.

## Exclusions

- Do not change WAL publication order or background apply.
- Do not add a generic async transaction framework.
- Do not add Python source-shape checks.
- Do not introduce a user-facing OVS timeout setting in this batch.
