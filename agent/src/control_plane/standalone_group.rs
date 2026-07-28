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
        assert!(plan
            .map_targets
            .iter()
            .all(|target| { target.desired_owner == Some(1) && target.cidr == "10.0.0.0/24" }));
        assert_eq!(
            plan.map_targets
                .iter()
                .map(|target| (target.plane.clone(), target.direction))
                .collect::<Vec<_>>(),
            vec![
                (StandaloneGroupMapPlane::General, "src"),
                (StandaloneGroupMapPlane::General, "dst"),
                (
                    StandaloneGroupMapPlane::ActiveAcl {
                        bank: ACL_BANK_PRIMARY,
                    },
                    "src",
                ),
                (
                    StandaloneGroupMapPlane::ActiveAcl {
                        bank: ACL_BANK_PRIMARY,
                    },
                    "dst",
                ),
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
        assert!(plan
            .map_targets
            .iter()
            .all(|target| target.desired_owner.is_none()));
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
