use std::collections::{BTreeMap, BTreeSet};

use super::*;

#[derive(Clone, Debug)]
pub(crate) enum StandaloneAclMutation {
    UpsertPolicy {
        src_group: String,
        dst_group: String,
        proto: u8,
        action: u8,
        direction: u8,
        ports: Option<String>,
    },
    DeletePolicy {
        src_group: String,
        dst_group: String,
        proto: u8,
        direction: u8,
    },
    AddReferencedGroupCidr {
        group_name: String,
        cidr: String,
    },
}

#[derive(Clone, Debug)]
pub(crate) enum StandaloneAclBatchItem {
    Parsed {
        request_index: usize,
        mutation: StandaloneAclMutation,
    },
    Rejected {
        request_index: usize,
        error: String,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum StandaloneAclPublicationStep {
    PersistBitmapGuard,
    StageShadow,
    ApplyGeneral,
    AdvanceFragmentEpoch,
    SwitchBank,
    PersistFinalState,
    StrictCtScrub,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum StandaloneAclFailurePhase {
    StageShadow,
    ApplyGeneral,
    AdvanceFragmentEpoch,
    SwitchBank,
    PersistFinalState,
    StrictCtScrub,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum StandaloneAclRollbackStep {
    RestoreActiveBank,
    RestoreGeneralReverse,
    RestoreDurableState,
    CleanupCreatedBitmaps,
    ScrubFailedShadow,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct StandaloneGeneralTarget {
    pub direction: &'static str,
    pub cidr: String,
    pub group_id: u32,
}

#[derive(Debug)]
pub(super) struct StandaloneAclPublicationPlan {
    pub old_state: FirewallState,
    pub final_state: FirewallState,
    pub old_bank: u8,
    pub shadow_bank: u8,
    pub accepted: usize,
    pub errors: Vec<String>,
    pub semantic_changed: bool,
    pub publication_count: usize,
    pub general_targets: Vec<StandaloneGeneralTarget>,
    pub created_port_sets: Vec<TransactionCreatedPortSet>,
    pub released_port_sets: BTreeMap<u32, String>,
    pub cleanup_pending: Vec<StandaloneCleanupPending>,
    pub steps: Vec<StandaloneAclPublicationStep>,
}

fn resolve_group_id(state: &FirewallState, name: &str) -> Result<u32, String> {
    if name == "any" {
        return Ok(0);
    }
    state
        .groups
        .get(name)
        .map(|group| group.id)
        .ok_or_else(|| format!("Group not found: {}", name))
}

fn state_snapshot(state: &FirewallState) -> Result<Vec<u8>, ControlPlaneError> {
    serde_json::to_vec(state).map_err(|error| {
        ControlPlaneError::ValidationError(format!(
            "serialize standalone ACL publication state: {}",
            error
        ))
    })
}

fn state_semantically_changed(
    old_state: &FirewallState,
    final_state: &FirewallState,
) -> Result<bool, ControlPlaneError> {
    Ok(state_snapshot(old_state)? != state_snapshot(final_state)?)
}

fn live_port_sets(state: &FirewallState) -> BTreeMap<String, (u32, u32)> {
    state
        .port_sets
        .iter()
        .filter(|(_, port_set)| port_set.ref_count > 0)
        .map(|(key, port_set)| (key.clone(), (port_set.bitmap_idx, port_set.ref_count)))
        .collect()
}

fn port_set_delta(
    old_state: &FirewallState,
    final_state: &FirewallState,
) -> (Vec<TransactionCreatedPortSet>, BTreeMap<u32, String>) {
    let old = live_port_sets(old_state);
    let final_sets = live_port_sets(final_state);
    let created_port_sets = final_sets
        .iter()
        .filter(|(ports, (bitmap_idx, _))| {
            old.get(*ports)
                .is_none_or(|(old_bitmap_idx, _)| old_bitmap_idx != bitmap_idx)
        })
        .map(
            |(ports_normalized, (bitmap_idx, _))| TransactionCreatedPortSet {
                bitmap_idx: *bitmap_idx,
                ports_normalized: ports_normalized.clone(),
            },
        )
        .collect();
    let released_port_sets = old
        .iter()
        .filter(|(ports, (bitmap_idx, _))| {
            final_sets
                .get(*ports)
                .is_none_or(|(final_bitmap_idx, _)| final_bitmap_idx != bitmap_idx)
        })
        .map(|(ports_normalized, (bitmap_idx, _))| (*bitmap_idx, ports_normalized.clone()))
        .collect();
    (created_port_sets, released_port_sets)
}

fn apply_mutation(
    state: &mut FirewallState,
    mutation: &StandaloneAclMutation,
) -> Result<Vec<StandaloneGeneralTarget>, String> {
    match mutation {
        StandaloneAclMutation::UpsertPolicy {
            src_group,
            dst_group,
            proto,
            action,
            direction,
            ports,
        } => {
            aria_core::ebpf_ops::validate_policy_ports(*proto, ports.as_deref())?;
            let src_id = resolve_group_id(state, src_group)?;
            let dst_id = resolve_group_id(state, dst_group)?;
            for direction in requested_directions(*direction).map_err(|error| error.to_string())? {
                let result = state.apply_add_rule(
                    src_id,
                    dst_id,
                    *proto,
                    *action,
                    ports.as_deref(),
                    direction,
                )?;
                if let Some((bitmap_idx, ports_normalized)) = result.old_port_set_released {
                    state.quarantine_bitmap_cleanup(bitmap_idx, ports_normalized)?;
                }
            }
            Ok(Vec::new())
        }
        StandaloneAclMutation::DeletePolicy {
            src_group,
            dst_group,
            proto,
            direction,
        } => {
            let src_id = resolve_group_id(state, src_group)?;
            let dst_id = resolve_group_id(state, dst_group)?;
            let directions = requested_directions(*direction).map_err(|error| error.to_string())?;
            let matching: Vec<u8> = directions
                .into_iter()
                .filter(|candidate| {
                    state.rules.iter().any(|rule| {
                        rule.src_group_id == src_id
                            && rule.dst_group_id == dst_id
                            && rule.proto == *proto
                            && rule.direction == *candidate
                    })
                })
                .collect();
            if matching.is_empty() {
                return Err(format!(
                    "Policy not found: src={}, dst={}, proto={}, direction={}",
                    src_group, dst_group, proto, direction
                ));
            }
            for direction in matching {
                let result = state.apply_remove_rule(src_id, dst_id, *proto, direction)?;
                if let (Some(bitmap_idx), Some(ports_normalized)) =
                    (result.bitmap_idx, result.port_set_released)
                {
                    state.quarantine_bitmap_cleanup(bitmap_idx, ports_normalized)?;
                }
            }
            Ok(Vec::new())
        }
        StandaloneAclMutation::AddReferencedGroupCidr { group_name, cidr } => {
            let group_id = state
                .groups
                .get(group_name)
                .map(|group| group.id)
                .ok_or_else(|| format!("Group not found: {}", group_name))?;
            if !state
                .rules
                .iter()
                .any(|rule| rule.src_group_id == group_id || rule.dst_group_id == group_id)
            {
                return Err(format!(
                    "group '{}' is not referenced by an ACL policy",
                    group_name
                ));
            }
            let canonical = aria_core::ebpf_ops::CanonicalNetwork::parse(cidr)?.to_string();
            state.add_group(group_name, &canonical)?;
            Ok(vec![
                StandaloneGeneralTarget {
                    direction: "src",
                    cidr: canonical.clone(),
                    group_id,
                },
                StandaloneGeneralTarget {
                    direction: "dst",
                    cidr: canonical,
                    group_id,
                },
            ])
        }
    }
}

fn publication_steps(semantic_changed: bool) -> Vec<StandaloneAclPublicationStep> {
    if !semantic_changed {
        return Vec::new();
    }
    vec![
        StandaloneAclPublicationStep::PersistBitmapGuard,
        StandaloneAclPublicationStep::StageShadow,
        StandaloneAclPublicationStep::ApplyGeneral,
        StandaloneAclPublicationStep::PersistFinalState,
        StandaloneAclPublicationStep::AdvanceFragmentEpoch,
        StandaloneAclPublicationStep::SwitchBank,
        StandaloneAclPublicationStep::StrictCtScrub,
    ]
}

fn finish_plan(
    old_state: &FirewallState,
    final_state: FirewallState,
    old_bank: u8,
    accepted: usize,
    errors: Vec<String>,
    general_targets: Vec<StandaloneGeneralTarget>,
) -> Result<StandaloneAclPublicationPlan, ControlPlaneError> {
    let semantic_changed = state_semantically_changed(old_state, &final_state)?;
    let (created_port_sets, released_port_sets) = port_set_delta(old_state, &final_state);
    Ok(StandaloneAclPublicationPlan {
        old_state: old_state.clone(),
        final_state,
        old_bank,
        shadow_bank: aria_core::common::acl_next_bank(old_bank),
        accepted,
        errors,
        semantic_changed,
        publication_count: usize::from(semantic_changed),
        general_targets,
        created_port_sets,
        released_port_sets,
        cleanup_pending: Vec::new(),
        steps: publication_steps(semantic_changed),
    })
}

pub(super) fn build_standalone_acl_publication_plan(
    old_state: &FirewallState,
    old_bank: u8,
    mutations: &[StandaloneAclMutation],
) -> Result<StandaloneAclPublicationPlan, ControlPlaneError> {
    let mut working = old_state.clone();
    let mut accepted = 0;
    let mut errors = Vec::new();
    let mut general_targets = Vec::new();
    for mutation in mutations {
        let mut item_state = working.clone();
        match apply_mutation(&mut item_state, mutation) {
            Ok(item_targets) => {
                working = item_state;
                general_targets.extend(item_targets);
                accepted += 1;
            }
            Err(error) => errors.push(error),
        }
    }
    finish_plan(
        old_state,
        working,
        old_bank,
        accepted,
        errors,
        general_targets,
    )
}

pub(super) fn build_standalone_acl_batch_publication_plan(
    old_state: &FirewallState,
    old_bank: u8,
    items: &[StandaloneAclBatchItem],
) -> Result<StandaloneAclPublicationPlan, ControlPlaneError> {
    let mut ordered = items.to_vec();
    ordered.sort_by_key(|item| match item {
        StandaloneAclBatchItem::Parsed { request_index, .. }
        | StandaloneAclBatchItem::Rejected { request_index, .. } => *request_index,
    });
    let mut working = old_state.clone();
    let mut accepted = 0;
    let mut indexed_errors = Vec::new();
    let mut general_targets = Vec::new();
    for item in ordered {
        match item {
            StandaloneAclBatchItem::Rejected {
                request_index,
                error,
            } => indexed_errors.push((request_index, error)),
            StandaloneAclBatchItem::Parsed {
                request_index,
                mutation,
            } => {
                let mut item_state = working.clone();
                match apply_mutation(&mut item_state, &mutation) {
                    Ok(item_targets) => {
                        working = item_state;
                        general_targets.extend(item_targets);
                        accepted += 1;
                    }
                    Err(error) => indexed_errors.push((request_index, error)),
                }
            }
        }
    }
    indexed_errors.sort_by_key(|(request_index, _)| *request_index);
    finish_plan(
        old_state,
        working,
        old_bank,
        accepted,
        indexed_errors.into_iter().map(|(_, error)| error).collect(),
        general_targets,
    )
}

pub(super) fn standalone_acl_rollback_steps(
    failure_phase: StandaloneAclFailurePhase,
) -> Vec<StandaloneAclRollbackStep> {
    use StandaloneAclFailurePhase::*;
    use StandaloneAclRollbackStep::*;
    match failure_phase {
        StageShadow => vec![
            ScrubFailedShadow,
            CleanupCreatedBitmaps,
            RestoreDurableState,
        ],
        ApplyGeneral => vec![
            RestoreGeneralReverse,
            ScrubFailedShadow,
            CleanupCreatedBitmaps,
            RestoreDurableState,
        ],
        AdvanceFragmentEpoch => vec![
            RestoreGeneralReverse,
            ScrubFailedShadow,
            CleanupCreatedBitmaps,
            RestoreDurableState,
        ],
        SwitchBank => vec![
            RestoreActiveBank,
            RestoreGeneralReverse,
            ScrubFailedShadow,
            CleanupCreatedBitmaps,
            RestoreDurableState,
        ],
        PersistFinalState => vec![
            RestoreGeneralReverse,
            ScrubFailedShadow,
            CleanupCreatedBitmaps,
            RestoreDurableState,
        ],
        StrictCtScrub => vec![
            RestoreActiveBank,
            RestoreGeneralReverse,
            ScrubFailedShadow,
            CleanupCreatedBitmaps,
            RestoreDurableState,
        ],
    }
}

fn stage_standalone_shadow_bank(
    plan: &StandaloneAclPublicationPlan,
    runtime: TapMapRuntime<'_>,
    ebpf_path: &str,
) -> Result<(), String> {
    aria_core::ebpf_ops::scrub_acl_bank(runtime, plan.shadow_bank)?;
    let entries = aria_core::ebpf_ops::build_runtime_group_map_entries(
        &plan.final_state,
        GroupProjectionMode::StandaloneCompatibility,
    )?;
    for (direction, networks) in [("src", &entries.acl_src), ("dst", &entries.acl_dst)] {
        for network in networks {
            aria_core::ebpf_ops::add_acl_network_in_bank(
                direction,
                &format!("{}/{}", network.address, network.prefix_len),
                network.group_id,
                plan.shadow_bank,
                runtime,
                ebpf_path,
            )?;
        }
    }

    let created_indices: BTreeSet<u32> = plan
        .created_port_sets
        .iter()
        .map(|port_set| port_set.bitmap_idx)
        .collect();
    let mut programmed_indices = BTreeSet::new();
    for rule in &plan.final_state.rules {
        let is_new_port_set = rule.bitmap_idx.is_some_and(|bitmap_idx| {
            created_indices.contains(&bitmap_idx) && programmed_indices.insert(bitmap_idx)
        });
        aria_core::ebpf_ops::add_policy_in_bank(
            rule.src_group_id,
            rule.dst_group_id,
            rule.proto,
            rule.action,
            rule.ports.as_deref(),
            rule.bitmap_idx,
            is_new_port_set,
            rule.direction,
            plan.shadow_bank,
            runtime,
            ebpf_path,
        )?;
    }
    Ok(())
}

fn actual_general_mutation(
    target: &StandaloneGeneralTarget,
    runtime: TapMapRuntime<'_>,
) -> Result<SharedNetworkMutation, String> {
    match aria_core::ebpf_ops::capture_general_network_owner(
        runtime,
        target.direction,
        &target.cidr,
    )? {
        Some(old_group_id) => Ok(SharedNetworkMutation::Replaced {
            direction: target.direction,
            cidr: target.cidr.clone(),
            old_group_id,
            new_group_id: target.group_id,
        }),
        None => Ok(SharedNetworkMutation::Added {
            direction: target.direction,
            cidr: target.cidr.clone(),
            group_id: target.group_id,
        }),
    }
}

async fn rollback_standalone_publication(
    instance: &str,
    state: &mut InstanceState,
    plan: &StandaloneAclPublicationPlan,
    runtime: TapMapRuntime<'_>,
    ebpf_path: &str,
    phase: StandaloneAclFailurePhase,
    original_error: String,
    general_receipts: &[SharedNetworkMutation],
) -> ControlPlaneError {
    let mut errors = vec![original_error];
    let mut active_bank_restored = true;
    let mut required_preimage_restore_failed = false;
    let mut cleanup = PortSetCleanupReport::default();

    for step in standalone_acl_rollback_steps(phase) {
        match step {
            StandaloneAclRollbackStep::RestoreActiveBank => {
                if let Err(error) = aria_core::ebpf_ops::set_acl_active_bank(runtime, plan.old_bank)
                {
                    active_bank_restored = false;
                    required_preimage_restore_failed = true;
                    errors.push(format!("restore standalone ACL active bank: {}", error));
                }
            }
            StandaloneAclRollbackStep::RestoreGeneralReverse => {
                for receipt in general_receipts.iter().rev() {
                    let compensation = shared_network_compensation(receipt);
                    if let Err(error) =
                        apply_shared_network_mutation(&compensation, runtime, ebpf_path)
                    {
                        required_preimage_restore_failed = true;
                        errors.push(format!(
                            "restore standalone general selector {:?}: {}",
                            compensation, error
                        ));
                    }
                }
            }
            StandaloneAclRollbackStep::ScrubFailedShadow => {
                if active_bank_restored {
                    if let Err(error) =
                        aria_core::ebpf_ops::scrub_acl_bank(runtime, plan.shadow_bank)
                    {
                        errors.push(format!(
                            "scrub failed standalone shadow bank {}: {}",
                            plan.shadow_bank, error
                        ));
                    }
                } else {
                    errors.push(format!(
                        "preserved standalone publication bank {} because active-bank restore failed",
                        plan.shadow_bank
                    ));
                }
            }
            StandaloneAclRollbackStep::CleanupCreatedBitmaps => {
                cleanup = cleanup_transaction_created_port_sets(
                    &plan.created_port_sets,
                    runtime,
                    ebpf_path,
                );
                errors.extend(cleanup.failures.iter().map(|failure| failure.error.clone()));
            }
            StandaloneAclRollbackStep::RestoreDurableState => {
                if let Err(error) = restore_durable_old_state_after_failed_persistence(
                    state,
                    &plan.old_state,
                    &cleanup,
                )
                .await
                {
                    required_preimage_restore_failed = true;
                    errors.push(error);
                }
            }
        }
    }

    if required_preimage_restore_failed {
        state.runtime_health.acl_ready = false;
        state.runtime_health.acl_error = Some("recovery_required".to_string());
        if let Err(error) = ControlPlane::quiesce_tc_acl_runtime_locked(instance, state) {
            state.runtime_health.acl_error = Some(format!("acl_quiesce_failed:{}", error));
            errors.push(format!(
                "quiesce standalone ACL/CT after rollback fault: {}",
                error
            ));
        }
    }

    match phase {
        StandaloneAclFailurePhase::PersistFinalState => {
            ControlPlaneError::PersistenceError(errors.join("; "))
        }
        _ => ControlPlaneError::KernelError(errors.join("; ")),
    }
}

async fn persist_confirmed_standalone_cleanups(
    state: &mut InstanceState,
    mut cleanup: PortSetCleanupReport,
    targets: &[TransactionCreatedPortSet],
    context: &str,
) -> PortSetCleanupReport {
    if cleanup.cleaned_bitmap_indices.is_empty() {
        return cleanup;
    }

    let cleaned = cleanup.cleaned_bitmap_indices.clone();
    let mut reusable_state = state.state.clone();
    let persistence_result = apply_confirmed_port_set_cleanups(&mut reusable_state, &cleanup)
        .map_err(|error| format!("release confirmed {} bitmap cleanup: {}", context, error));
    let persistence_result = match persistence_result {
        Ok(()) => state
            .compact_and_publish_state(reusable_state)
            .await
            .map_err(|error| format!("persist confirmed {} bitmap cleanup: {}", context, error)),
        Err(error) => Err(error),
    };

    if let Err(error) = persistence_result {
        cleanup.cleaned_bitmap_indices.clear();
        for bitmap_idx in cleaned {
            let ports_normalized = targets
                .iter()
                .find(|target| target.bitmap_idx == bitmap_idx)
                .map(|target| target.ports_normalized.clone())
                .unwrap_or_default();
            cleanup.failures.push(PortSetCleanupFailure {
                bitmap_idx,
                ports_normalized,
                error: error.clone(),
            });
        }
    }
    cleanup
}

async fn retry_pending_standalone_bitmap_cleanups(
    state: &mut InstanceState,
    runtime: TapMapRuntime<'_>,
    ebpf_path: &str,
) -> StandaloneCleanupOutcome {
    let targets = pending_bitmap_cleanup_port_sets(&state.state);
    if targets.is_empty() {
        return standalone_cleanup_outcome(&PortSetCleanupReport::default());
    }

    let cleanup = cleanup_port_sets(&targets, runtime, ebpf_path, "pending standalone");
    let cleanup = persist_confirmed_standalone_cleanups(
        state,
        cleanup,
        &targets,
        "pending standalone",
    )
    .await;
    standalone_cleanup_outcome(&cleanup)
}

fn merge_cleanup_pending(
    previous: Vec<StandaloneCleanupPending>,
    current: Vec<StandaloneCleanupPending>,
) -> Vec<StandaloneCleanupPending> {
    let mut merged = BTreeMap::new();
    for pending in previous.into_iter().chain(current) {
        merged.insert(pending.bitmap_idx, pending);
    }
    merged.into_values().collect()
}

async fn execute_standalone_publication(
    cp: &ControlPlane,
    instance: &str,
    state: &mut InstanceState,
    plan: &StandaloneAclPublicationPlan,
) -> Result<StandaloneCleanupOutcome, ControlPlaneError> {
    debug_assert_eq!(plan.publication_count, usize::from(plan.semantic_changed));
    debug_assert_eq!(plan.steps, publication_steps(plan.semantic_changed));
    if !plan.semantic_changed {
        return Ok(standalone_cleanup_outcome(
            &PortSetCleanupReport::default(),
        ));
    }

    let pin_path = state.pin_path.clone();
    let runtime = TapMapRuntime::new(&pin_path, state.tap_id);
    if !plan.created_port_sets.is_empty() {
        let mut allocator_guard = plan.old_state.clone();
        quarantine_port_set_indices(&mut allocator_guard, &plan.created_port_sets)
            .map_err(ControlPlaneError::ValidationError)?;
        state
            .compact_and_publish_state(allocator_guard)
            .await
            .map_err(|error| {
                ControlPlaneError::PersistenceError(format!(
                    "persist standalone transaction-created bitmap quarantine: {}",
                    error
                ))
            })?;
    }

    if let Err(error) = stage_standalone_shadow_bank(plan, runtime, &cp.ebpf_path) {
        return Err(rollback_standalone_publication(
            instance,
            state,
            plan,
            runtime,
            &cp.ebpf_path,
            StandaloneAclFailurePhase::StageShadow,
            format!("stage standalone ACL shadow bank: {}", error),
            &[],
        )
        .await);
    }

    let mut general_receipts = Vec::new();
    for target in &plan.general_targets {
        let mutation = match actual_general_mutation(target, runtime) {
            Ok(mutation) => mutation,
            Err(error) => {
                return Err(rollback_standalone_publication(
                    instance,
                    state,
                    plan,
                    runtime,
                    &cp.ebpf_path,
                    StandaloneAclFailurePhase::ApplyGeneral,
                    format!("capture standalone general selector preimage: {}", error),
                    &general_receipts,
                )
                .await)
            }
        };
        if let Err(error) = apply_shared_network_mutation(&mutation, runtime, &cp.ebpf_path) {
            return Err(rollback_standalone_publication(
                instance,
                state,
                plan,
                runtime,
                &cp.ebpf_path,
                StandaloneAclFailurePhase::ApplyGeneral,
                format!(
                    "apply standalone general selector {:?}: {}",
                    mutation, error
                ),
                &general_receipts,
            )
            .await);
        }
        general_receipts.push(mutation);
    }

    let mut durable_final_state = plan.final_state.clone();
    for (bitmap_idx, ports_normalized) in &plan.released_port_sets {
        if let Err(error) = durable_final_state
            .quarantine_bitmap_cleanup(*bitmap_idx, ports_normalized.clone())
        {
            return Err(rollback_standalone_publication(
                instance,
                state,
                plan,
                runtime,
                &cp.ebpf_path,
                StandaloneAclFailurePhase::PersistFinalState,
                format!(
                    "prepare standalone ACL durable bitmap quarantine: {}",
                    error
                ),
                &general_receipts,
            )
            .await);
        }
    }
    if let Err(error) = state.compact_and_publish_state(durable_final_state).await {
        return Err(rollback_standalone_publication(
            instance,
            state,
            plan,
            runtime,
            &cp.ebpf_path,
            StandaloneAclFailurePhase::PersistFinalState,
            format!("persist standalone ACL final state: {}", error),
            &general_receipts,
        )
        .await);
    }

    if let Err(error) = execute_fragment_epoch_bank_publication(
        &mut || {
            advance_fragment_epoch_action(&pin_path, state.tap_id)
                .map_err(|error| {
                    format!("advance standalone fragment publication epoch: {}", error)
                })
        },
        &mut || aria_core::ebpf_ops::set_acl_active_bank(runtime, plan.shadow_bank),
    ) {
        let failure_phase = match error.phase() {
            FragmentEpochPublicationFailurePhase::Readiness
            | FragmentEpochPublicationFailurePhase::AdvanceEpoch => {
                StandaloneAclFailurePhase::AdvanceFragmentEpoch
            }
            FragmentEpochPublicationFailurePhase::Publish => {
                StandaloneAclFailurePhase::SwitchBank
            }
        };
        return Err(rollback_standalone_publication(
            instance,
            state,
            plan,
            runtime,
            &cp.ebpf_path,
            failure_phase,
            error.to_string(),
            &general_receipts,
        )
        .await);
    }

    if let Err(error) = aria_core::ct_ops::scrub_ct_tables_strict(runtime) {
        return Err(rollback_standalone_publication(
            instance,
            state,
            plan,
            runtime,
            &cp.ebpf_path,
            StandaloneAclFailurePhase::StrictCtScrub,
            format!("strict standalone ACL CT scrub: {}", error),
            &general_receipts,
        )
        .await);
    }

    if let Err(error) = aria_core::ebpf_ops::scrub_acl_bank(runtime, plan.old_bank) {
        warn!(error = %error, bank = plan.old_bank, "failed to scrub previous standalone ACL bank");
    }
    let released = plan
        .released_port_sets
        .iter()
        .map(|(bitmap_idx, ports_normalized)| TransactionCreatedPortSet {
            bitmap_idx: *bitmap_idx,
            ports_normalized: ports_normalized.clone(),
        })
        .collect::<Vec<_>>();
    let released_cleanup = cleanup_port_sets(&released, runtime, &cp.ebpf_path, "released");
    let released_cleanup = persist_confirmed_standalone_cleanups(
        state,
        released_cleanup,
        &released,
        "standalone released",
    )
    .await;
    for failure in &released_cleanup.failures {
        warn!(error = %failure.error, bitmap_idx = failure.bitmap_idx,
            "standalone released port set remains durably quarantined");
    }
    for old_rule in &plan.old_state.rules {
        if !plan.final_state.rules.iter().any(|new_rule| {
            old_rule.src_group_id == new_rule.src_group_id
                && old_rule.dst_group_id == new_rule.dst_group_id
                && old_rule.proto == new_rule.proto
                && old_rule.direction == new_rule.direction
        }) {
            if let Err(error) = aria_core::monitoring::clear_rule_stats_for_policy(
                runtime,
                old_rule.src_group_id,
                old_rule.dst_group_id,
                old_rule.proto,
                old_rule.direction,
            ) {
                warn!(error = %error, "failed to clear rule stats after standalone ACL publication");
            }
        }
    }
    Ok(standalone_cleanup_outcome(&released_cleanup))
}

impl ControlPlane {
    pub(super) async fn apply_standalone_acl_mutations_locked(
        &self,
        instance: &str,
        state: &mut InstanceState,
        mutations: &[StandaloneAclMutation],
    ) -> Result<StandaloneAclPublicationPlan, ControlPlaneError> {
        Self::check_runtime_maps_ready(&state.pin_path)?;
        let pin_path = state.pin_path.clone();
        let runtime = TapMapRuntime::new(&pin_path, state.tap_id);
        let retry = retry_pending_standalone_bitmap_cleanups(state, runtime, &self.ebpf_path).await;
        let old_bank = aria_core::ebpf_ops::read_acl_active_bank(state.map_runtime())
            .map_err(ControlPlaneError::KernelError)?;
        let mut plan = build_standalone_acl_publication_plan(&state.state, old_bank, mutations)?;
        let publication = execute_standalone_publication(self, instance, state, &plan).await?;
        debug_assert!(retry.committed && publication.committed);
        debug_assert!(retry.item_errors.is_empty() && publication.item_errors.is_empty());
        plan.cleanup_pending =
            merge_cleanup_pending(retry.cleanup_pending, publication.cleanup_pending);
        Ok(plan)
    }

    pub(super) async fn apply_standalone_acl_batch_locked(
        &self,
        instance: &str,
        state: &mut InstanceState,
        items: &[StandaloneAclBatchItem],
    ) -> Result<StandaloneAclPublicationPlan, ControlPlaneError> {
        if !items
            .iter()
            .any(|item| matches!(item, StandaloneAclBatchItem::Parsed { .. }))
        {
            return build_standalone_acl_batch_publication_plan(&state.state, 0, items);
        }
        Self::check_runtime_maps_ready(&state.pin_path)?;
        let pin_path = state.pin_path.clone();
        let runtime = TapMapRuntime::new(&pin_path, state.tap_id);
        let retry = retry_pending_standalone_bitmap_cleanups(state, runtime, &self.ebpf_path).await;
        let old_bank = aria_core::ebpf_ops::read_acl_active_bank(state.map_runtime())
            .map_err(ControlPlaneError::KernelError)?;
        let mut plan = build_standalone_acl_batch_publication_plan(&state.state, old_bank, items)?;
        let publication = execute_standalone_publication(self, instance, state, &plan).await?;
        debug_assert!(retry.committed && publication.committed);
        debug_assert!(retry.item_errors.is_empty() && publication.item_errors.is_empty());
        plan.cleanup_pending =
            merge_cleanup_pending(retry.cleanup_pending, publication.cleanup_pending);
        Ok(plan)
    }
}

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

    fn assert_durable_before_bank_publication(persist: usize, epoch: usize, switch: usize) {
        assert!(
            persist < epoch,
            "final state must be durable before fragment epoch advance"
        );
        assert!(
            epoch < switch,
            "fragment epoch must fence the active-bank switch"
        );
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
        let stage = plan
            .steps
            .iter()
            .position(|step| *step == StandaloneAclPublicationStep::StageShadow)
            .unwrap();
        let general = plan
            .steps
            .iter()
            .position(|step| *step == StandaloneAclPublicationStep::ApplyGeneral)
            .unwrap();
        let epoch = plan
            .steps
            .iter()
            .position(|step| *step == StandaloneAclPublicationStep::AdvanceFragmentEpoch)
            .unwrap();
        let switch = plan
            .steps
            .iter()
            .position(|step| *step == StandaloneAclPublicationStep::SwitchBank)
            .unwrap();
        assert!(stage < epoch);
        assert!(general < epoch);
        assert!(epoch < switch);
        assert_eq!(
            plan.steps.last(),
            Some(&StandaloneAclPublicationStep::StrictCtScrub)
        );
        assert_eq!(plan.final_state.rules.len(), 1);
    }

    #[test]
    fn standalone_acl_publication_persists_before_epoch_and_bank_switch() {
        let steps = publication_steps(true);
        let persist = steps
            .iter()
            .position(|step| *step == StandaloneAclPublicationStep::PersistFinalState)
            .expect("standalone publication must persist");
        let epoch = steps
            .iter()
            .position(|step| *step == StandaloneAclPublicationStep::AdvanceFragmentEpoch)
            .expect("standalone publication must advance the fragment epoch");
        let switch = steps
            .iter()
            .position(|step| *step == StandaloneAclPublicationStep::SwitchBank)
            .expect("standalone publication must switch bank");

        assert_durable_before_bank_publication(persist, epoch, switch);
    }

    #[test]
    fn standalone_acl_final_persistence_failure_never_restores_unpublished_bank() {
        assert_eq!(
            standalone_acl_rollback_steps(StandaloneAclFailurePhase::PersistFinalState),
            vec![
                StandaloneAclRollbackStep::RestoreGeneralReverse,
                StandaloneAclRollbackStep::ScrubFailedShadow,
                StandaloneAclRollbackStep::CleanupCreatedBitmaps,
                StandaloneAclRollbackStep::RestoreDurableState,
            ]
        );
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
        assert_eq!(
            plan.steps
                .iter()
                .filter(|step| **step == StandaloneAclPublicationStep::AdvanceFragmentEpoch)
                .count(),
            1
        );
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
        assert_eq!(
            plan.steps
                .iter()
                .filter(|step| **step == StandaloneAclPublicationStep::AdvanceFragmentEpoch)
                .count(),
            1
        );
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
        let epoch = plan
            .steps
            .iter()
            .position(|step| *step == StandaloneAclPublicationStep::AdvanceFragmentEpoch)
            .unwrap();
        let switch = plan
            .steps
            .iter()
            .position(|step| *step == StandaloneAclPublicationStep::SwitchBank)
            .unwrap();
        assert!(general < epoch);
        assert!(epoch < switch);
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
                .filter(|step| **step == StandaloneAclPublicationStep::AdvanceFragmentEpoch)
                .count(),
            1
        );
        assert_eq!(
            plan.steps
                .iter()
                .filter(|step| **step == StandaloneAclPublicationStep::SwitchBank)
                .count(),
            1
        );
    }

    #[test]
    fn standalone_acl_publication_semantic_noop_does_not_advance_fragment_epoch() {
        let old = state_with_groups();
        let plan = build_standalone_acl_publication_plan(&old, ACL_BANK_PRIMARY, &[]).unwrap();

        assert!(!plan.semantic_changed);
        assert_eq!(plan.publication_count, 0);
        assert!(plan.steps.is_empty());
    }

    #[test]
    fn standalone_acl_publication_epoch_failure_is_pre_switch_and_restores_preimages() {
        assert_eq!(
            standalone_acl_rollback_steps(StandaloneAclFailurePhase::AdvanceFragmentEpoch),
            vec![
                StandaloneAclRollbackStep::RestoreGeneralReverse,
                StandaloneAclRollbackStep::ScrubFailedShadow,
                StandaloneAclRollbackStep::CleanupCreatedBitmaps,
                StandaloneAclRollbackStep::RestoreDurableState,
            ],
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
