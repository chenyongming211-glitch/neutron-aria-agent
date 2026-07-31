# REVIEW-ACL-045 Orphan Managed-Runtime Scrub Plan

> Execute directly on `v0.9-neutron-agent`. Do not create a branch/worktree and
> do not run local Cargo commands.

## Design Source

Follow
`docs/superpowers/specs/2026-07-31-review-acl-045-orphan-runtime-scrub-design.md`.

## Task 1: RED orphan inventory and retry tests

- [ ] Add persisted-live marker inventory beside link-pin inventory.
- [ ] Prove the union is normalized and committed interfaces are excluded.
- [ ] Prove link removal alone cannot release the retry marker.
- [ ] Prove a post-link cleanup failure reports blocked and retains the marker.
- [ ] Prove successful cleanup releases the marker last.
- [ ] Prove the cleanup identity uses the persisted stable tap id.
- [ ] Push RED and record exact hosted failure evidence.

## Task 2: Concrete full orphan cleanup

- [ ] Separate link removal from marker release.
- [ ] Load the orphan state/WAL and reject missing/unassigned tap ids.
- [ ] Add a control-plane orphan scrub that clears kernel-drop/trace/tap-scoped
      runtime and Neutron authority.
- [ ] Remove any stale registry instance and interface lock.
- [ ] Release the marker only after every required cleanup phase succeeds.
- [ ] Preserve the marker and return blocked on any required failure.
- [ ] Keep committed sibling runtime and the shared pin directory intact.

## Task 3: Hosted GREEN and source closure

- [ ] Push the production implementation.
- [ ] Require exact-head `fast-contracts`, `rust-behavior`, and `rust-build`
      success.
- [ ] Update the design and plan with RED/GREEN commits and build ids.
- [ ] Update `REVIEW-ACL-045` to
      `implementation and hosted CI complete; privileged field evidence
      deferred`.
- [ ] Commit and push documentation closure.

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
