# REVIEW-ACL-045 Orphan Managed-Runtime Scrub Plan

> Execute directly on `v0.9-neutron-agent`. Do not create a branch/worktree and
> do not run local Cargo commands.

## Design Source

Follow
`docs/superpowers/specs/2026-07-31-review-acl-045-orphan-runtime-scrub-design.md`.

## Task 1: RED orphan inventory and retry tests

- [x] Add persisted-live marker inventory beside link-pin inventory.
- [x] Prove the union is normalized and committed interfaces are excluded.
- [x] Prove link removal alone cannot release the retry marker.
- [x] Prove a post-link cleanup failure reports blocked and retains the marker.
- [x] Prove successful cleanup releases the marker last.
- [x] Prove the cleanup identity uses the persisted stable tap id.
- [x] Push RED and record exact hosted failure evidence.

## Task 2: Concrete full orphan cleanup

- [x] Separate link removal from marker release.
- [x] Load the orphan state/WAL and reject missing/unassigned tap ids.
- [x] Add a control-plane orphan scrub that clears kernel-drop/trace/tap-scoped
      runtime and Neutron authority.
- [x] Remove any stale registry instance and interface lock.
- [x] Release the marker only after every required cleanup phase succeeds.
- [x] Preserve the marker and return blocked on any required failure.
- [x] Keep committed sibling runtime and the shared pin directory intact.

## Task 3: Hosted GREEN and source closure

- [x] Push the production implementation.
- [x] Require exact-head `fast-contracts`, `rust-behavior`, and `rust-build`
      success.
- [x] Update the design and plan with RED/GREEN commits and build ids.
- [x] Update `REVIEW-ACL-045` to
      `implementation and hosted CI complete; privileged field evidence
      deferred`.
- [x] Commit and push documentation closure.

Evidence:

- RED: `a9a536e`, Build
  [30613528175](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/30613528175).
- GREEN: `8242c1b`, exact-head Build
  [30613890526](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/30613890526).
- The GREEN run passed `fast-contracts`, `rust-behavior`, warning-denied
  Rust/eBPF build, and static binary verification.

## Task 4: Deferred privileged evidence

- [ ] Seed a real orphan tap and a committed sibling in shared pinned maps.
- [ ] Verify all tap-scoped map families, link pins, kernel-drop binding, trace
      state, tap config, iface context, and marker after cleanup.
- [ ] Inject a mid-cleanup failure and verify marker-retained retry.
- [ ] Record exact commands, kernel/runtime identity, before/after inventory,
      and artifacts.
- [ ] Only then mark `REVIEW-ACL-045` fixed.

## Exclusions

- Do not delete per-interface state/WAL or release stable tap ids.
- Do not change the snapshot/status contract.
- Do not fold in `REVIEW-TXN-026` or later apply-loop defects.
- Do not substitute a static checker for behavior tests.
- Do not mark field evidence passed without a real privileged environment.
