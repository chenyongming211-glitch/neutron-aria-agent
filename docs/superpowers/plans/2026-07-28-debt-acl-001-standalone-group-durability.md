# DEBT-ACL-001 Standalone Group Durability Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Submit and verify the RED behavior contract for ordinary unreferenced standalone group durability before any production implementation.

**Architecture:** Declare the intended concrete `standalone_group` boundary through Rust tests for final-state planning, exact owner compensation, and append/compact rollback classification. Wire the focused test filter into `rust-behavior`, prove the old implementation RED in GitHub Actions, then reassess the GREEN implementation as the next task.

**Tech Stack:** Rust 2021, Tokio, Aya pinned maps, existing `FirewallState`, `WalClient`, GitHub Actions `rust-behavior` and warning-denied `rust-build`.

## Global Constraints

- Work only on local and remote `v0.9-neutron-agent`; create no branch, PR, or worktree.
- Do not run local `cargo build`, `cargo check`, `cargo test`, or Clippy.
- Do not add a Python implementation-shape checker.
- Do not add a generic closure/future transaction framework or a second WAL abstraction.
- Do not rotate the ACL bank, advance fragment epoch, or scrub CT for an unreferenced group.
- Preserve referenced-group ACL-057/066 routing and managed local projection behavior.
- Treat field evidence as `deferred/pending`; this batch has no privileged field claim.
- Follow the approved design in `docs/superpowers/specs/2026-07-28-debt-acl-001-standalone-group-durability-design.md`.

---

### Task 1: Submit the RED standalone group contract

**Files:**
- Create: `agent/src/control_plane/standalone_group.rs`
- Modify: `agent/src/control_plane.rs:31-38`
- Modify: `ci/check_neutron_stage1.py:24-80`

**Interfaces:**
- Consumes: `FirewallState`, active ACL bank, `StandaloneGroupMutation`.
- Produces for later tasks: `build_standalone_group_plan`, `standalone_group_compensation`, `standalone_group_rollback_steps`, and `classify_standalone_group_persistence` with the exact types exercised by the tests below.

- [x] **Step 1: Add the test-only module wiring**

Add this beside the existing `standalone_acl` module declaration in `agent/src/control_plane.rs`:

```rust
mod standalone_group;
```

- [x] **Step 2: Create the RED contract tests with no production definitions**

Create `agent/src/control_plane/standalone_group.rs` containing only the following test module. The unresolved production symbols are intentional in RED:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use aria_core::common::ACL_BANK_PRIMARY;
    use aria_core::state::FirewallState;

    fn state_with_unreferenced_group() -> FirewallState {
        let mut state = FirewallState::default();
        state.add_group("client", "10.0.0.0/24").unwrap();
        state
    }

    #[test]
    fn standalone_group_transaction_add_builds_final_state_and_four_map_targets() {
        let old = FirewallState::default();
        let plan = build_standalone_group_plan(
            &old,
            ACL_BANK_PRIMARY,
            StandaloneGroupMutation::AddCidr {
                name: "client".into(),
                cidr: "10.0.0.0/24".into(),
            },
        )
        .unwrap();

        assert!(plan.semantic_changed);
        assert_eq!(plan.group_id, 1);
        assert_eq!(plan.old_state.next_group_id, 1);
        assert_eq!(plan.final_state.next_group_id, 2);
        assert_eq!(plan.map_targets.len(), 4);
        assert!(plan.map_targets.iter().all(|target| {
            target.desired_owner == Some(1) && target.cidr == "10.0.0.0/24"
        }));
        assert_eq!(
            plan.map_targets
                .iter()
                .map(|target| (target.plane.clone(), target.direction))
                .collect::<Vec<_>>(),
            vec![
                (StandaloneGroupMapPlane::General, "src"),
                (StandaloneGroupMapPlane::General, "dst"),
                (StandaloneGroupMapPlane::ActiveAcl { bank: ACL_BANK_PRIMARY }, "src"),
                (StandaloneGroupMapPlane::ActiveAcl { bank: ACL_BANK_PRIMARY }, "dst"),
            ],
        );
    }

    #[test]
    fn standalone_group_transaction_existing_group_preserves_id_and_allocator() {
        let old = state_with_unreferenced_group();
        let plan = build_standalone_group_plan(
            &old,
            ACL_BANK_PRIMARY,
            StandaloneGroupMutation::AddCidr {
                name: "client".into(),
                cidr: "10.0.1.0/24".into(),
            },
        )
        .unwrap();

        assert_eq!(plan.group_id, old.groups["client"].id);
        assert_eq!(plan.final_state.next_group_id, old.next_group_id);
        assert_eq!(plan.final_state.groups["client"].cidrs.len(), 2);
    }

    #[test]
    fn standalone_group_transaction_duplicate_cidr_is_zero_work_noop() {
        let old = state_with_unreferenced_group();
        let plan = build_standalone_group_plan(
            &old,
            ACL_BANK_PRIMARY,
            StandaloneGroupMutation::AddCidr {
                name: "client".into(),
                cidr: "10.0.0.0/24".into(),
            },
        )
        .unwrap();

        assert!(!plan.semantic_changed);
        assert!(plan.map_targets.is_empty());
        assert_eq!(
            serde_json::to_vec(&plan.old_state).unwrap(),
            serde_json::to_vec(&plan.final_state).unwrap(),
        );
    }

    #[test]
    fn standalone_group_transaction_delete_multicidr_targets_every_owned_key() {
        let mut old = state_with_unreferenced_group();
        old.add_group("client", "10.0.1.0/24").unwrap();
        let group_id = old.groups["client"].id;
        let plan = build_standalone_group_plan(
            &old,
            ACL_BANK_PRIMARY,
            StandaloneGroupMutation::DeleteGroup {
                name: "client".into(),
            },
        )
        .unwrap();

        assert!(plan.semantic_changed);
        assert_eq!(plan.group_id, group_id);
        assert!(!plan.final_state.groups.contains_key("client"));
        assert_eq!(plan.map_targets.len(), 8);
        assert!(plan.map_targets.iter().all(|target| target.desired_owner.is_none()));
    }

    #[test]
    fn standalone_group_transaction_compensation_restores_exact_old_owner() {
        let receipt = StandaloneGroupMapReceipt {
            target: StandaloneGroupMapTarget {
                plane: StandaloneGroupMapPlane::General,
                direction: "src",
                cidr: "10.0.0.0/24".into(),
                desired_owner: Some(7),
            },
            old_owner: Some(3),
        };

        let compensation = standalone_group_compensation(&receipt);
        assert_eq!(compensation.desired_owner, Some(3));
        assert_eq!(compensation.direction, "src");
        assert_eq!(compensation.cidr, "10.0.0.0/24");
    }

    #[test]
    fn standalone_group_transaction_persistence_fallback_and_rollback_are_explicit() {
        assert_eq!(
            classify_standalone_group_persistence(
                Err("append failed".into()),
                Ok(()),
                StandaloneGroupRollbackReport::default(),
            ),
            StandaloneGroupPersistenceDisposition::CommittedByCompact,
        );
        assert_eq!(
            classify_standalone_group_persistence(
                Err("append failed".into()),
                Err("compact failed".into()),
                StandaloneGroupRollbackReport::default(),
            ),
            StandaloneGroupPersistenceDisposition::RolledBack,
        );
    }

    #[test]
    fn standalone_group_transaction_rollback_failure_requires_quiesce() {
        assert_eq!(
            standalone_group_rollback_steps(StandaloneGroupFailurePhase::PersistFinalState),
            vec![
                StandaloneGroupRollbackStep::RestoreMemory,
                StandaloneGroupRollbackStep::RestoreMapsReverse,
                StandaloneGroupRollbackStep::RestoreDurableOldState,
            ],
        );
        assert_eq!(
            classify_standalone_group_persistence(
                Err("append failed".into()),
                Err("compact failed".into()),
                StandaloneGroupRollbackReport {
                    map_errors: vec!["restore src failed".into()],
                    durable_restore_error: Some("restore state failed".into()),
                },
            ),
            StandaloneGroupPersistenceDisposition::RecoveryRequired,
        );
    }
}
```

- [x] **Step 3: Add the focused CI filter**

Append this entry beside `standalone_acl_publication_` in `RUST_TESTS`:

```python
["test", "--locked", "-p", "aria-agent", "standalone_group_transaction_"],
```

- [x] **Step 4: Run only non-Cargo static verification**

Run:

```bash
python3 -m unittest ci.test_ci_lane_contract
python3 ci/check_neutron_stage1.py --fast-contracts
git diff --check
```

Expected: Python/static checks pass and test discovery recognizes the new Rust filter. Do not run Cargo locally.

- [ ] **Step 5: Commit and push RED**

```bash
git add agent/src/control_plane.rs agent/src/control_plane/standalone_group.rs ci/check_neutron_stage1.py docs/superpowers/plans/2026-07-28-debt-acl-001-standalone-group-durability.md
git -c user.name=netmouser -c user.email=chenyongming211@gmail.com commit -m "test: expose standalone group durability gap"
git push origin v0.9-neutron-agent
```

Expected CI: `fast-contracts` passes; `rust-behavior` fails because the concrete standalone group transaction symbols are missing; no unrelated job fails.

### Task 2: Record RED evidence and reassess the next development step

**Files:**
- Modify after CI result: `docs/superpowers/specs/2026-07-28-debt-acl-001-standalone-group-durability-design.md:3-10,350-377`

**Interfaces:**
- Consumes: the Task 1 commit SHA and GitHub Actions job results.
- Produces: durable expected-RED evidence and a fresh recommendation for the next implementation step.

- [ ] **Step 1: Inspect the exact-head run**

Use `gh run list --branch v0.9-neutron-agent` to identify the run whose
`headSha` equals the RED commit, then use `gh run view <run-id> --json jobs`.

Expected classification:

- `fast-contracts`: success;
- `rust-behavior`: failure caused by the missing concrete standalone group
  symbols exercised by `standalone_group_transaction_`;
- `rust-build`: success, because the unresolved RED contract is contained in
  `#[cfg(test)]` and production compilation remains unchanged;
- no Python contract, documentation, or unrelated Rust failure.

- [ ] **Step 2: Record only the verified RED result**

Update the design status with the RED commit and run URL. Do not mark
`DEBT-ACL-001` fixed and do not add GREEN or field claims.

- [ ] **Step 3: Evaluate the next step from current evidence**

Re-read the RED failure and the unchanged production call sites. Recommend
whether the immediate next task is the concrete GREEN transaction described
by the approved spec. If CI exposes a contract or scope error instead, stop
and revise the plan rather than writing production code against a false RED.
