use super::*;
use aria_core::ebpf_ops::NetworkOwnerPlane;

#[derive(Debug, Clone, PartialEq, Eq)]
enum StandaloneGroupMutation {
    AddCidr { name: String, cidr: String },
    DeleteGroup { name: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum StandaloneGroupMapPlane {
    General,
    ActiveAcl { bank: u8 },
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct StandaloneGroupMapTarget {
    plane: StandaloneGroupMapPlane,
    direction: &'static str,
    cidr: String,
    desired_owner: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct StandaloneGroupMapReceipt {
    target: StandaloneGroupMapTarget,
    old_owner: Option<u32>,
}

#[derive(Debug, Clone)]
struct StandaloneGroupPlan {
    mutation: StandaloneGroupMutation,
    old_state: FirewallState,
    final_state: FirewallState,
    group_id: u32,
    semantic_changed: bool,
    map_targets: Vec<StandaloneGroupMapTarget>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StandaloneGroupFailurePhase {
    ApplyMaps,
    PersistFinalState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StandaloneGroupRollbackStep {
    RestoreMemory,
    RestoreMapsReverse,
    RestoreDurableOldState,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct StandaloneGroupRollbackReport {
    map_errors: Vec<String>,
    durable_restore_error: Option<String>,
}

impl StandaloneGroupRollbackReport {
    fn requires_recovery(&self) -> bool {
        !self.map_errors.is_empty() || self.durable_restore_error.is_some()
    }
}

#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StandaloneGroupPersistenceDisposition {
    CommittedByAppend,
    CommittedByCompact,
    RolledBack,
    RecoveryRequired,
}

fn standalone_group_targets(
    acl_bank: u8,
    cidr: &str,
    desired_owner: Option<u32>,
) -> Vec<StandaloneGroupMapTarget> {
    vec![
        StandaloneGroupMapTarget {
            plane: StandaloneGroupMapPlane::General,
            direction: "src",
            cidr: cidr.to_string(),
            desired_owner,
        },
        StandaloneGroupMapTarget {
            plane: StandaloneGroupMapPlane::General,
            direction: "dst",
            cidr: cidr.to_string(),
            desired_owner,
        },
        StandaloneGroupMapTarget {
            plane: StandaloneGroupMapPlane::ActiveAcl { bank: acl_bank },
            direction: "src",
            cidr: cidr.to_string(),
            desired_owner,
        },
        StandaloneGroupMapTarget {
            plane: StandaloneGroupMapPlane::ActiveAcl { bank: acl_bank },
            direction: "dst",
            cidr: cidr.to_string(),
            desired_owner,
        },
    ]
}

fn build_standalone_group_plan(
    old_state: &FirewallState,
    acl_bank: u8,
    mutation: StandaloneGroupMutation,
) -> Result<StandaloneGroupPlan, String> {
    let mut final_state = old_state.clone();
    match &mutation {
        StandaloneGroupMutation::AddCidr { name, cidr } => {
            let duplicate = old_state
                .groups
                .get(name)
                .is_some_and(|group| group.cidrs.iter().any(|existing| existing == cidr));
            let group_id = final_state.add_group(name, cidr)?;
            let semantic_changed = !duplicate;
            let map_targets = if semantic_changed {
                standalone_group_targets(acl_bank, cidr, Some(group_id))
            } else {
                Vec::new()
            };
            Ok(StandaloneGroupPlan {
                mutation,
                old_state: old_state.clone(),
                final_state,
                group_id,
                semantic_changed,
                map_targets,
            })
        }
        StandaloneGroupMutation::DeleteGroup { name } => {
            let group = old_state
                .groups
                .get(name)
                .ok_or_else(|| format!("group '{}' not found", name))?
                .clone();
            final_state.groups.remove(name);
            let map_targets = group
                .cidrs
                .iter()
                .flat_map(|cidr| standalone_group_targets(acl_bank, cidr, None))
                .collect();
            Ok(StandaloneGroupPlan {
                mutation,
                old_state: old_state.clone(),
                final_state,
                group_id: group.id,
                semantic_changed: true,
                map_targets,
            })
        }
    }
}

fn standalone_group_compensation(receipt: &StandaloneGroupMapReceipt) -> StandaloneGroupMapTarget {
    StandaloneGroupMapTarget {
        desired_owner: receipt.old_owner,
        ..receipt.target.clone()
    }
}

fn standalone_group_rollback_steps(
    phase: StandaloneGroupFailurePhase,
) -> Vec<StandaloneGroupRollbackStep> {
    let mut steps = vec![
        StandaloneGroupRollbackStep::RestoreMemory,
        StandaloneGroupRollbackStep::RestoreMapsReverse,
    ];
    if phase == StandaloneGroupFailurePhase::PersistFinalState {
        steps.push(StandaloneGroupRollbackStep::RestoreDurableOldState);
    }
    steps
}

#[cfg(test)]
fn classify_standalone_group_persistence(
    append: Result<(), String>,
    compact: Result<(), String>,
    rollback: StandaloneGroupRollbackReport,
) -> StandaloneGroupPersistenceDisposition {
    if append.is_ok() {
        return StandaloneGroupPersistenceDisposition::CommittedByAppend;
    }
    if compact.is_ok() {
        return StandaloneGroupPersistenceDisposition::CommittedByCompact;
    }
    if rollback.requires_recovery() {
        StandaloneGroupPersistenceDisposition::RecoveryRequired
    } else {
        StandaloneGroupPersistenceDisposition::RolledBack
    }
}

fn capture_standalone_group_receipt(
    target: &StandaloneGroupMapTarget,
    runtime: TapMapRuntime<'_>,
) -> Result<StandaloneGroupMapReceipt, String> {
    let plane = match &target.plane {
        StandaloneGroupMapPlane::General => NetworkOwnerPlane::General,
        StandaloneGroupMapPlane::ActiveAcl { bank } => NetworkOwnerPlane::AclBank(*bank),
    };
    let old_owner =
        aria_core::ebpf_ops::capture_network_owner(runtime, target.direction, &target.cidr, plane)?;
    Ok(StandaloneGroupMapReceipt {
        target: target.clone(),
        old_owner,
    })
}

fn apply_standalone_group_target(
    target: &StandaloneGroupMapTarget,
    runtime: TapMapRuntime<'_>,
    ebpf_path: &str,
) -> Result<(), String> {
    match (&target.plane, target.desired_owner) {
        (StandaloneGroupMapPlane::General, Some(group_id)) => aria_core::ebpf_ops::add_network(
            target.direction,
            &target.cidr,
            group_id,
            runtime,
            ebpf_path,
        ),
        (StandaloneGroupMapPlane::General, None) => aria_core::ebpf_ops::delete_network(
            target.direction,
            &target.cidr,
            0,
            runtime,
            ebpf_path,
        ),
        (StandaloneGroupMapPlane::ActiveAcl { bank }, Some(group_id)) => {
            aria_core::ebpf_ops::add_acl_network_in_bank(
                target.direction,
                &target.cidr,
                group_id,
                *bank,
                runtime,
                ebpf_path,
            )
        }
        (StandaloneGroupMapPlane::ActiveAcl { bank }, None) => {
            aria_core::ebpf_ops::delete_acl_network_in_bank(
                target.direction,
                &target.cidr,
                0,
                *bank,
                runtime,
                ebpf_path,
            )
        }
    }
}

fn standalone_group_target_needs_apply(
    receipt: &StandaloneGroupMapReceipt,
    deleted_group_id: u32,
) -> bool {
    match receipt.target.desired_owner {
        Some(desired_owner) => receipt.old_owner != Some(desired_owner),
        None => receipt.old_owner == Some(deleted_group_id),
    }
}

fn standalone_group_wal_entry(plan: &StandaloneGroupPlan) -> WalEntry {
    match &plan.mutation {
        StandaloneGroupMutation::AddCidr { name, cidr } => WalEntry::AddGroup {
            name: name.clone(),
            cidr: cidr.clone(),
        },
        StandaloneGroupMutation::DeleteGroup { name } => {
            WalEntry::DeleteGroup { name: name.clone() }
        }
    }
}

async fn persist_standalone_group_final_state(
    state: &mut InstanceState,
    plan: &StandaloneGroupPlan,
) -> Result<(), String> {
    state.state = plan.final_state.clone();
    let entry = standalone_group_wal_entry(plan);
    state.wal_append_strict(&entry).await
}

fn mark_standalone_group_recovery_required(
    instance: &str,
    state: &mut InstanceState,
    errors: &mut Vec<String>,
) {
    state.runtime_health.acl_ready = false;
    state.runtime_health.acl_error = Some("recovery_required".to_string());
    if let Err(error) = ControlPlane::quiesce_tc_acl_runtime_locked(instance, state) {
        state.runtime_health.acl_error = Some(format!("acl_quiesce_failed:{}", error));
        errors.push(format!(
            "quiesce standalone ACL/CT after group rollback fault: {}",
            error
        ));
    }
}

async fn rollback_standalone_group_transaction(
    instance: &str,
    state: &mut InstanceState,
    plan: &StandaloneGroupPlan,
    runtime: TapMapRuntime<'_>,
    ebpf_path: &str,
    phase: StandaloneGroupFailurePhase,
    mut errors: Vec<String>,
    applied: &[StandaloneGroupMapReceipt],
) -> ControlPlaneError {
    let mut report = StandaloneGroupRollbackReport::default();
    for step in standalone_group_rollback_steps(phase) {
        match step {
            StandaloneGroupRollbackStep::RestoreMemory => {
                state.state = plan.old_state.clone();
            }
            StandaloneGroupRollbackStep::RestoreMapsReverse => {
                for receipt in applied.iter().rev() {
                    let compensation = standalone_group_compensation(receipt);
                    if let Err(error) =
                        apply_standalone_group_target(&compensation, runtime, ebpf_path)
                    {
                        report.map_errors.push(format!(
                            "restore standalone group map {:?}: {}",
                            compensation, error
                        ));
                    }
                }
            }
            StandaloneGroupRollbackStep::RestoreDurableOldState => {
                if let Err(error) = state
                    .compact_and_publish_state(plan.old_state.clone())
                    .await
                {
                    report.durable_restore_error = Some(format!(
                        "restore standalone group durable old state: {}",
                        error
                    ));
                }
            }
        }
    }
    errors.extend(report.map_errors.iter().cloned());
    if let Some(error) = &report.durable_restore_error {
        errors.push(error.clone());
    }
    if report.requires_recovery() {
        mark_standalone_group_recovery_required(instance, state, &mut errors);
        return ControlPlaneError::InstanceNotReady(errors.join("; "));
    }
    match phase {
        StandaloneGroupFailurePhase::ApplyMaps => ControlPlaneError::KernelError(errors.join("; ")),
        StandaloneGroupFailurePhase::PersistFinalState => {
            ControlPlaneError::PersistenceError(errors.join("; "))
        }
    }
}

async fn execute_standalone_group_transaction(
    cp: &ControlPlane,
    instance: &str,
    state: &mut InstanceState,
    plan: &StandaloneGroupPlan,
) -> Result<(), ControlPlaneError> {
    if !plan.semantic_changed {
        return Ok(());
    }
    let pin_path = state.pin_path.clone();
    let runtime = TapMapRuntime::new(&pin_path, state.tap_id);
    let receipts = plan
        .map_targets
        .iter()
        .map(|target| capture_standalone_group_receipt(target, runtime))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| {
            ControlPlaneError::KernelError(format!(
                "capture standalone group map preimage: {}",
                error
            ))
        })?;

    let mut applied = Vec::new();
    for receipt in receipts {
        if !standalone_group_target_needs_apply(&receipt, plan.group_id) {
            continue;
        }
        if let Err(error) = apply_standalone_group_target(&receipt.target, runtime, &cp.ebpf_path) {
            return Err(rollback_standalone_group_transaction(
                instance,
                state,
                plan,
                runtime,
                &cp.ebpf_path,
                StandaloneGroupFailurePhase::ApplyMaps,
                vec![format!(
                    "apply standalone group map {:?}: {}",
                    receipt.target, error
                )],
                &applied,
            )
            .await);
        }
        applied.push(receipt);
    }

    if let Err(error) = persist_standalone_group_final_state(state, plan).await {
        return Err(rollback_standalone_group_transaction(
            instance,
            state,
            plan,
            runtime,
            &cp.ebpf_path,
            StandaloneGroupFailurePhase::PersistFinalState,
            vec![format!("persist standalone group final state: {}", error)],
            &applied,
        )
        .await);
    }
    Ok(())
}

impl ControlPlane {
    pub(super) async fn add_group_standalone_locked(
        &self,
        instance: &str,
        state: &mut InstanceState,
        name: &str,
        cidr: &str,
    ) -> Result<u32, ControlPlaneError> {
        if let Some(group) = state.state.groups.get(name) {
            if group.cidrs.iter().any(|existing| existing == cidr) {
                return Ok(group.id);
            }
        }
        Self::check_runtime_maps_ready(&state.pin_path)?;
        let acl_bank = aria_core::ebpf_ops::read_acl_active_bank(state.map_runtime())
            .map_err(ControlPlaneError::KernelError)?;
        let plan = build_standalone_group_plan(
            &state.state,
            acl_bank,
            StandaloneGroupMutation::AddCidr {
                name: name.to_string(),
                cidr: cidr.to_string(),
            },
        )
        .map_err(ControlPlaneError::ValidationError)?;
        execute_standalone_group_transaction(self, instance, state, &plan).await?;
        Ok(plan.group_id)
    }

    pub(super) async fn delete_group_standalone_locked(
        &self,
        instance: &str,
        state: &mut InstanceState,
        name: &str,
    ) -> Result<(), ControlPlaneError> {
        Self::check_runtime_maps_ready(&state.pin_path)?;
        let group = state
            .state
            .groups
            .get(name)
            .ok_or_else(|| ControlPlaneError::GroupNotFound(name.to_string()))?
            .clone();
        if state
            .state
            .rules
            .iter()
            .any(|rule| rule.src_group_id == group.id || rule.dst_group_id == group.id)
        {
            return Err(ControlPlaneError::GroupInUse(format!(
                "Group '{}' is referenced by a policy",
                name
            )));
        }
        if state
            .state
            .qos_rules
            .iter()
            .any(|rule| rule.group_id == group.id)
        {
            return Err(ControlPlaneError::GroupInUse(format!(
                "Group '{}' is referenced by a QoS rule",
                name
            )));
        }
        if state
            .state
            .mirror_rules
            .iter()
            .any(|rule| rule.src_group_id == group.id || rule.dst_group_id == group.id)
        {
            return Err(ControlPlaneError::GroupInUse(format!(
                "Group '{}' is referenced by a mirror rule",
                name
            )));
        }

        let acl_bank = aria_core::ebpf_ops::read_acl_active_bank(state.map_runtime())
            .map_err(ControlPlaneError::KernelError)?;
        let plan = build_standalone_group_plan(
            &state.state,
            acl_bank,
            StandaloneGroupMutation::DeleteGroup {
                name: name.to_string(),
            },
        )
        .map_err(ControlPlaneError::ValidationError)?;
        execute_standalone_group_transaction(self, instance, state, &plan).await?;
        if let Err(error) =
            aria_core::monitoring::clear_group_stats_for_id(state.map_runtime(), plan.group_id)
        {
            warn!(error = %error, group_id = plan.group_id, "failed to clear group stats after group delete");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aria_core::common::ACL_BANK_PRIMARY;

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
