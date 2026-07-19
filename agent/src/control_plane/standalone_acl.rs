#[cfg(test)]
mod tests {
    use super::*;
    use aria_core::common::{acl_next_bank, ACL_BANK_PRIMARY};
    use aria_core::state::FirewallState;

    fn state_with_groups() -> FirewallState {
        let mut state = FirewallState::default();
        state.add_group("client", "10.0.0.0/24").unwrap();
        state.add_group("server", "10.1.0.0/24").unwrap();
        state
    }

    #[test]
    fn standalone_acl_publication_add_deny_rotates_bank_and_strictly_flushes_ct() {
        let old = state_with_groups();
        let plan = build_standalone_acl_publication_plan(
            &old,
            ACL_BANK_PRIMARY,
            &[StandaloneAclMutation::UpsertPolicy {
                src_group: "client".into(),
                dst_group: "server".into(),
                proto: 6,
                action: 1,
                direction: 0,
                ports: None,
            }],
        )
        .unwrap();

        assert_eq!(plan.old_bank, ACL_BANK_PRIMARY);
        assert_eq!(plan.shadow_bank, acl_next_bank(ACL_BANK_PRIMARY));
        assert_eq!(plan.publication_count, 1);
        assert_eq!(
            plan.steps.last(),
            Some(&StandaloneAclPublicationStep::StrictCtScrub)
        );
        assert_eq!(plan.final_state.rules.len(), 1);
    }

    #[test]
    fn standalone_acl_publication_allow_to_deny_is_one_both_direction_epoch() {
        let mut old = state_with_groups();
        let src = old.groups["client"].id;
        let dst = old.groups["server"].id;
        old.apply_add_rule(src, dst, 6, 0, None, 0).unwrap();
        old.apply_add_rule(src, dst, 6, 0, None, 1).unwrap();

        let plan = build_standalone_acl_publication_plan(
            &old,
            ACL_BANK_PRIMARY,
            &[StandaloneAclMutation::UpsertPolicy {
                src_group: "client".into(),
                dst_group: "server".into(),
                proto: 6,
                action: 1,
                direction: 2,
                ports: None,
            }],
        )
        .unwrap();

        assert_eq!(plan.publication_count, 1);
        assert_eq!(plan.accepted, 1);
        assert!(plan.final_state.rules.iter().all(|rule| rule.action == 1));
    }

    #[test]
    fn standalone_acl_publication_delete_allow_removes_both_directions_once() {
        let mut old = state_with_groups();
        let src = old.groups["client"].id;
        let dst = old.groups["server"].id;
        old.apply_add_rule(src, dst, 6, 0, None, 0).unwrap();
        old.apply_add_rule(src, dst, 6, 0, None, 1).unwrap();

        let plan = build_standalone_acl_publication_plan(
            &old,
            ACL_BANK_PRIMARY,
            &[StandaloneAclMutation::DeletePolicy {
                src_group: "client".into(),
                dst_group: "server".into(),
                proto: 6,
                direction: 2,
            }],
        )
        .unwrap();

        assert_eq!(plan.publication_count, 1);
        assert!(plan.final_state.rules.is_empty());
    }

    #[test]
    fn standalone_acl_publication_referenced_group_expansion_updates_general_before_switch() {
        let mut old = state_with_groups();
        let src = old.groups["client"].id;
        let dst = old.groups["server"].id;
        old.apply_add_rule(src, dst, 6, 1, None, 0).unwrap();

        let plan = build_standalone_acl_publication_plan(
            &old,
            ACL_BANK_PRIMARY,
            &[StandaloneAclMutation::AddReferencedGroupCidr {
                group_name: "client".into(),
                cidr: "10.0.1.0/24".into(),
            }],
        )
        .unwrap();

        assert_eq!(plan.publication_count, 1);
        assert_eq!(plan.general_targets.len(), 2);
        let general = plan
            .steps
            .iter()
            .position(|step| *step == StandaloneAclPublicationStep::ApplyGeneral)
            .unwrap();
        let switch = plan
            .steps
            .iter()
            .position(|step| *step == StandaloneAclPublicationStep::SwitchBank)
            .unwrap();
        assert!(general < switch);
    }

    #[test]
    fn standalone_acl_publication_batch_keeps_item_errors_and_switches_once() {
        let old = state_with_groups();
        let plan = build_standalone_acl_publication_plan(
            &old,
            ACL_BANK_PRIMARY,
            &[
                StandaloneAclMutation::UpsertPolicy {
                    src_group: "client".into(),
                    dst_group: "server".into(),
                    proto: 6,
                    action: 1,
                    direction: 2,
                    ports: None,
                },
                StandaloneAclMutation::UpsertPolicy {
                    src_group: "missing".into(),
                    dst_group: "server".into(),
                    proto: 6,
                    action: 1,
                    direction: 0,
                    ports: None,
                },
            ],
        )
        .unwrap();

        assert_eq!(plan.accepted, 1);
        assert_eq!(plan.errors.len(), 1);
        assert_eq!(plan.publication_count, 1);
        assert_eq!(
            plan.steps
                .iter()
                .filter(|step| **step == StandaloneAclPublicationStep::SwitchBank)
                .count(),
            1
        );
    }

    #[test]
    fn standalone_acl_publication_failures_restore_every_preimage_in_reverse() {
        assert_eq!(
            standalone_acl_rollback_steps(StandaloneAclFailurePhase::StrictCtScrub),
            vec![
                StandaloneAclRollbackStep::RestoreActiveBank,
                StandaloneAclRollbackStep::RestoreGeneralReverse,
                StandaloneAclRollbackStep::ScrubFailedShadow,
                StandaloneAclRollbackStep::CleanupCreatedBitmaps,
                StandaloneAclRollbackStep::RestoreDurableState,
            ],
        );
    }
}
