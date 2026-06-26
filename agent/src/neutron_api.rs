use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{delete, get, put},
    Json, Router,
};
use aria_api::{
    action_from_string, direction_from_string, proto_from_string, ManagedNeutronPort,
    NeutronAclRuleSnapshot, NeutronAclSnapshot, NeutronCapabilitiesResponse, NeutronDeleteResponse,
    NeutronDomainStatus, NeutronPortApplyResult, NeutronPortSnapshot, NeutronPortStatus,
    NeutronSnapshotRequest, NeutronSnapshotResponse, NeutronStatusResponse,
};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::process::Command;
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};
use tracing::{error, warn};

use crate::control_plane::ControlPlane;
use crate::fault_injection;
use crate::neutron_wal::{NeutronWal, NeutronWalState, PendingNeutronIntent};
use crate::tap_registry::TapRegistry;

#[derive(Clone)]
pub(crate) struct NeutronApiState {
    registry: Arc<TapRegistry>,
    control_plane: Arc<ControlPlane>,
    ovs_bridge: String,
    runtime: Arc<RwLock<NeutronRuntimeState>>,
    apply_lock: Arc<Mutex<()>>,
    wal: Arc<NeutronWal>,
    pending_recovery: Option<PendingNeutronIntent>,
}

#[derive(Clone, Default)]
struct NeutronRuntimeState {
    accepted_generation: u64,
    applied_generation: u64,
    pending_generation: Option<u64>,
    desired_hash: Option<String>,
    applied_desired_hash: Option<String>,
    authority_state: String,
    ports: BTreeMap<String, ManagedNeutronPort>,
    port_statuses: BTreeMap<String, NeutronPortStatus>,
    wal_status: String,
    wal_replay_failures: u64,
}

#[derive(Debug)]
struct SnapshotApplyError {
    status: StatusCode,
    code: &'static str,
    details: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct SnapshotPlan {
    attach: Vec<NeutronPortSnapshot>,
    update: Vec<NeutronPortSnapshot>,
    detach: Vec<ManagedNeutronPort>,
    ignored: Vec<NeutronPortApplyResult>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct AclGroupPlan {
    name: String,
    cidrs: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct AclPolicyPlan {
    src_group: String,
    dst_group: String,
    proto: u8,
    action: u8,
    direction: u8,
    ports: Option<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct AclApplyPlan {
    groups: Vec<AclGroupPlan>,
    policies: Vec<AclPolicyPlan>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct DomainReconcileResult {
    domains: Vec<NeutronDomainStatus>,
    ok: bool,
    reason: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct IntentPortRecovery {
    managed_domains: Vec<String>,
    domains: Vec<NeutronDomainStatus>,
    status: String,
    reason: Option<String>,
    ok: bool,
}

impl IntentPortRecovery {
    fn blocked(port: &ManagedNeutronPort, domains: Vec<NeutronDomainStatus>, reason: String) -> Self {
        Self {
            managed_domains: normalize_managed_domains(&port.managed_domains),
            domains,
            status: "blocked".to_string(),
            reason: Some(reason),
            ok: false,
        }
    }
}

impl NeutronApiState {
    fn new(registry: Arc<TapRegistry>, control_plane: Arc<ControlPlane>, ovs_bridge: String) -> Self {
        let wal = Arc::new(NeutronWal::new(&registry.base_state_path));
        let replay = wal.replay();
        let pending_recovery = replay.pending_intent.clone();
        let runtime = NeutronRuntimeState::from_wal_state(replay.state, replay.status, replay.failures);
        Self {
            registry,
            control_plane,
            ovs_bridge,
            runtime: Arc::new(RwLock::new(runtime)),
            apply_lock: Arc::new(Mutex::new(())),
            wal,
            pending_recovery,
        }
    }

    async fn restore_neutron_authorities(&self) {
        let (ports, generation) = {
            let runtime = self.runtime.read().await;
            (
                runtime.ports.values().cloned().collect::<Vec<_>>(),
                runtime.applied_generation,
            )
        };
        for port in ports {
            self.control_plane
                .mark_neutron_port_authority(
                    &port.ifname,
                    &port.port_id,
                    &port.managed_domains,
                    generation,
                )
                .await;
        }
    }

    async fn reconcile_committed_runtime(&self) {
        let _guard = self.apply_lock.lock().await;
        let (ports, generation, desired_hash) = {
            let runtime = self.runtime.read().await;
            (
                runtime.ports.values().cloned().collect::<Vec<_>>(),
                runtime.applied_generation,
                runtime.applied_desired_hash.clone(),
            )
        };
        let committed_ifaces: Vec<String> = ports.iter().map(|port| port.ifname.clone()).collect();
        let results = self
            .registry
            .reconcile_neutron_runtime(&committed_ifaces)
            .await;
        if results.is_empty() {
            return;
        }

        let mut next_runtime = {
            let runtime = self.runtime.read().await;
            runtime.clone()
        };
        let mut degraded = results.iter().any(|result| result.status == "blocked");
        for port in &ports {
            let Some(result) = results.iter().find(|result| {
                result.ifname == port.ifname && result.action == "claim_committed"
            }) else {
                continue;
            };
            next_runtime.port_statuses.insert(
                port.port_id.clone(),
                port_runtime_status(
                    &port.port_id,
                    &port.ifname,
                    generation,
                    desired_hash.clone(),
                    port.managed_domains.clone(),
                    if result.status == "ready" {
                        "ready"
                    } else {
                        "blocked"
                    },
                    result.reason.clone(),
                    runtime_domain_statuses_for(
                        &port.managed_domains,
                        if result.status == "ready" {
                            "ready"
                        } else {
                            "blocked"
                        },
                        result.reason.clone(),
                    ),
                ),
            );
        }
        for result in results
            .iter()
            .filter(|result| result.action == "cleanup_orphan")
        {
            if result.status == "blocked" {
                degraded = true;
            }
        }

        if degraded {
            next_runtime.authority_state = "runtime_degraded".to_string();
            next_runtime.wal_status = "runtime_reconcile_degraded".to_string();
        } else if next_runtime.pending_generation.is_none() {
            next_runtime.authority_state = "ready".to_string();
            next_runtime.wal_status = "runtime_reconciled".to_string();
        } else if next_runtime.wal_status != "intent_recovered" {
            next_runtime.wal_status = "runtime_reconciled".to_string();
        }

        if let Err(e) = self.wal.append_snapshot_commit(next_runtime.to_wal_state()) {
            let mut runtime = self.runtime.write().await;
            runtime.authority_state = "wal_runtime_reconcile_commit_failed".to_string();
            runtime.wal_status = "commit_failed".to_string();
            warn!(error = %e, "failed to commit Neutron runtime reconciliation state");
            return;
        }

        let mut runtime = self.runtime.write().await;
        *runtime = next_runtime;
    }

    async fn recover_incomplete_wal_intent(&self) {
        let Some(intent) = self.pending_recovery.clone() else {
            return;
        };
        let _guard = self.apply_lock.lock().await;
        let current_ports = {
            let runtime = self.runtime.read().await;
            runtime.ports.clone()
        };
        let affected_ports = affected_ports_for_intent(&intent, &current_ports);
        if affected_ports.is_empty() {
            let mut next_runtime = {
                let runtime = self.runtime.read().await;
                runtime.clone()
            };
            next_runtime.pending_generation = Some(intent.generation);
            next_runtime.desired_hash = intent.desired_hash;
            next_runtime.authority_state = "blocked_recovery_required".to_string();
            next_runtime.wal_status = "intent_recovery_blocked".to_string();
            if let Err(e) = self.wal.append_snapshot_commit(next_runtime.to_wal_state()) {
                warn!(error = %e, "failed to commit empty Neutron WAL recovery state");
            } else {
                let mut runtime = self.runtime.write().await;
                *runtime = next_runtime;
            }
            return;
        }

        let mut next_runtime = {
            let runtime = self.runtime.read().await;
            runtime.clone()
        };
        let mut recovery_failed = false;

        for port in affected_ports {
            let committed_before_intent = current_ports.contains_key(&port.port_id);
            let recovery = self
                .recover_intent_port(&intent, &port, committed_before_intent)
                .await;
            if !recovery.ok {
                recovery_failed = true;
            }
            if intent.kind == "delete" && recovery.ok {
                next_runtime.ports.remove(&port.port_id);
            }
            next_runtime.port_statuses.insert(
                port.port_id.clone(),
                port_runtime_status(
                    &port.port_id,
                    &port.ifname,
                    intent.generation,
                    intent.desired_hash.clone(),
                    recovery.managed_domains.clone(),
                    recovery.status.as_str(),
                    recovery.reason.clone(),
                    recovery.domains,
                ),
            );
        }

        next_runtime.pending_generation = Some(intent.generation);
        next_runtime.desired_hash = intent.desired_hash.clone();
        next_runtime.authority_state = if recovery_failed {
            "blocked_recovery_required".to_string()
        } else {
            "recovered_pending_full_resync".to_string()
        };
        next_runtime.wal_status = if recovery_failed {
            "intent_recovery_blocked".to_string()
        } else {
            "intent_recovered".to_string()
        };

        if let Err(e) = self.wal.append_snapshot_commit(next_runtime.to_wal_state()) {
            let mut runtime = self.runtime.write().await;
            runtime.pending_generation = Some(intent.generation);
            runtime.desired_hash = intent.desired_hash;
            runtime.authority_state = "wal_recovery_commit_failed".to_string();
            runtime.wal_status = "commit_failed".to_string();
            warn!(error = %e, "failed to commit Neutron WAL recovery state");
            return;
        }

        let mut runtime = self.runtime.write().await;
        *runtime = next_runtime;
    }

    async fn recover_intent_port(
        &self,
        intent: &PendingNeutronIntent,
        port: &ManagedNeutronPort,
        committed_before_intent: bool,
    ) -> IntentPortRecovery {
        let domains = recovery_domains_for_port(intent, port);
        let mut statuses = Vec::new();
        let mut errors = Vec::new();
        let mut attached_for_recovery = false;

        if domains.iter().any(|domain| domain.as_str() != "attach") && port.ifname.is_empty() {
            let reason = "missing_ifname_for_recovery".to_string();
            for domain in domains {
                statuses.push(domain_status(&domain, "blocked", Some(reason.clone())));
            }
            return IntentPortRecovery::blocked(port, statuses, reason);
        }

        if !port.ifname.is_empty()
            && domains
                .iter()
                .any(|domain| matches!(domain.as_str(), "attach" | "acl"))
        {
            match self.registry.attach(&port.ifname).await {
                Ok(()) => {
                    attached_for_recovery = true;
                    statuses.push(domain_status(
                        "attach",
                        "recovered",
                        Some("attached_for_recovery".to_string()),
                    ));
                }
                Err(e) => {
                    let reason = format!("attach_recovery_failed:{}", e);
                    statuses.push(domain_status("attach", "blocked", Some(reason.clone())));
                    errors.push(reason);
                }
            }
        }

        for domain in domains.iter().filter(|domain| domain.as_str() != "attach") {
            match domain.as_str() {
                "acl" if errors.is_empty() => {
                    match purge_neutron_acl(self, &port.ifname, &port.port_id).await {
                        Ok(()) => statuses.push(domain_status(
                            domain,
                            "recovered",
                            Some("acl_scrubbed_after_incomplete_wal_intent".to_string()),
                        )),
                        Err(e) => {
                            let reason = format!("acl_recovery_failed:{}", e);
                            statuses.push(domain_status(domain, "blocked", Some(reason.clone())));
                            errors.push(reason);
                        }
                    }
                }
                "acl" => statuses.push(domain_status(
                    domain,
                    "blocked",
                    Some("blocked_by_attach_recovery".to_string()),
                )),
                "qos" | "mirror" => statuses.push(domain_status(
                    domain,
                    "recovered",
                    Some(format!("{}_no_runtime_executor", domain)),
                )),
                _ => statuses.push(domain_status(
                    domain,
                    "recovered",
                    Some("no_neutron_recovery_action".to_string()),
                )),
            }
        }

        let should_detach = intent.kind == "delete" || !committed_before_intent;
        if attached_for_recovery && should_detach {
            match self.registry.detach(&port.ifname).await {
                Ok(()) => {
                    self.control_plane
                        .clear_neutron_port_authority(&port.ifname)
                        .await;
                }
                Err(e) => {
                    let reason = format!("detach_recovery_failed:{}", e);
                    statuses.push(domain_status("attach", "blocked", Some(reason.clone())));
                    errors.push(reason);
                }
            }
        }

        if errors.is_empty() {
            IntentPortRecovery {
                managed_domains: domains,
                domains: statuses,
                status: "recovered".to_string(),
                reason: Some("wal_intent_recovered_pending_full_resync".to_string()),
                ok: true,
            }
        } else {
            IntentPortRecovery {
                managed_domains: domains,
                domains: statuses,
                status: "blocked".to_string(),
                reason: Some(errors.join(";")),
                ok: false,
            }
        }
    }
}

impl NeutronRuntimeState {
    fn from_wal_state(state: NeutronWalState, wal_status: String, wal_replay_failures: u64) -> Self {
        Self {
            accepted_generation: state.accepted_generation,
            applied_generation: state.applied_generation,
            pending_generation: state.pending_generation,
            desired_hash: state.desired_hash,
            applied_desired_hash: state.applied_desired_hash,
            authority_state: state.authority_state,
            ports: state.ports,
            port_statuses: state.port_statuses,
            wal_status,
            wal_replay_failures,
        }
    }

    fn to_wal_state(&self) -> NeutronWalState {
        NeutronWalState {
            accepted_generation: self.accepted_generation,
            applied_generation: self.applied_generation,
            pending_generation: self.pending_generation,
            desired_hash: self.desired_hash.clone(),
            applied_desired_hash: self.applied_desired_hash.clone(),
            authority_state: self.authority_state.clone(),
            ports: self.ports.clone(),
            port_statuses: self.port_statuses.clone(),
            status_hash: None,
        }
    }
}

pub(crate) fn build_router(
    registry: Arc<TapRegistry>,
    control_plane: Arc<ControlPlane>,
    ovs_bridge: String,
) -> Router {
    let state = NeutronApiState::new(registry, control_plane, ovs_bridge);
    let restore_state = state.clone();
    tokio::spawn(async move {
        restore_state.recover_incomplete_wal_intent().await;
        restore_state.reconcile_committed_runtime().await;
        restore_state.restore_neutron_authorities().await;
    });
    Router::new()
        .route(
            "/api/v1/neutron/capabilities",
            get(get_neutron_capabilities),
        )
        .route("/api/v1/neutron/status", get(get_neutron_status))
        .route("/api/v1/neutron/snapshot", put(put_neutron_snapshot))
        .route(
            "/api/v1/neutron/ports/{port_id}",
            delete(delete_neutron_port),
        )
        .with_state(state)
}

async fn get_neutron_capabilities() -> impl IntoResponse {
    Json(NeutronCapabilitiesResponse::current())
}

async fn get_neutron_status(State(state): State<NeutronApiState>) -> impl IntoResponse {
    let runtime = state.runtime.read().await;
    let managed_ports = runtime.ports.values().cloned().collect();
    let generation = runtime.applied_generation;
    let accepted_generation = runtime.accepted_generation;
    let applied_generation = runtime.applied_generation;
    let pending_generation = runtime.pending_generation;
    let desired_hash = runtime.desired_hash.clone();
    let applied_desired_hash = runtime.applied_desired_hash.clone();
    let wal_status = runtime.wal_status.clone();
    let wal_replay_failures = runtime.wal_replay_failures;
    let authority_state = if runtime.authority_state.is_empty() {
        "idle".to_string()
    } else {
        runtime.authority_state.clone()
    };
    let port_statuses = runtime.port_statuses.values().cloned().collect();
    drop(runtime);

    Json(NeutronStatusResponse {
        generation,
        accepted_generation,
        applied_generation,
        pending_generation,
        desired_hash,
        applied_desired_hash,
        wal_status,
        wal_replay_failures,
        authority_state,
        managed_ports,
        port_statuses,
        active_instances: state.registry.list().await,
    })
}

async fn put_neutron_snapshot(
    State(state): State<NeutronApiState>,
    Json(snapshot): Json<NeutronSnapshotRequest>,
) -> impl IntoResponse {
    // Keep mutating snapshot apply alive even if the UDS client times out or disconnects.
    let handle = tokio::spawn(apply_neutron_snapshot(state, snapshot));
    match handle.await {
        Ok(Ok(response)) => Json(response).into_response(),
        Ok(Err(error)) => (
            error.status,
            Json(serde_json::json!({
                "error": error.code,
                "details": error.details,
            })),
        )
            .into_response(),
        Err(e) => {
            error!(error = %e, "Neutron snapshot apply task failed");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "error": "snapshot_apply_task_failed",
                    "details": e.to_string(),
                })),
            )
                .into_response()
        }
    }
}

async fn apply_neutron_snapshot(
    state: NeutronApiState,
    snapshot: NeutronSnapshotRequest,
) -> Result<NeutronSnapshotResponse, SnapshotApplyError> {
    let _guard = state.apply_lock.lock().await;
    let requested_hash = snapshot.desired_hash.clone();
    let local_inventory = LocalInterfaceInventory::load(&state.ovs_bridge);
    let early_response = {
        let runtime = state.runtime.read().await;
        if snapshot.generation > 0 && snapshot.generation < runtime.applied_generation {
            Some(neutron_snapshot_response(
                snapshot.generation,
                requested_hash.clone(),
                runtime.accepted_generation,
                runtime.applied_generation,
                "stale",
                vec![transaction_result(
                    "snapshot",
                    "",
                    "ignore",
                    "ignored",
                    Some("stale_generation"),
                )],
                Vec::new(),
            ))
        } else if snapshot_generation_fully_applied(&runtime, snapshot.generation) {
            if hashes_match(&requested_hash, &runtime.applied_desired_hash) {
                if snapshot_has_runtime_drift(&runtime.ports, &snapshot, &local_inventory) {
                    None
                } else {
                    Some(neutron_snapshot_response(
                        snapshot.generation,
                        requested_hash.clone(),
                        runtime.accepted_generation,
                        runtime.applied_generation,
                        "noop",
                        Vec::new(),
                        Vec::new(),
                    ))
                }
            } else if requested_hash.is_some() && runtime.applied_desired_hash.is_some() {
                return Err(SnapshotApplyError {
                    status: StatusCode::CONFLICT,
                    code: "generation_hash_conflict",
                    details: format!(
                        "generation {} already applied with a different desired_hash",
                        snapshot.generation
                    ),
                });
            } else {
                None
            }
        } else {
            None
        }
    };
    if let Some(mut response) = early_response {
        response.active_instances = state.registry.list().await;
        return Ok(response);
    }

    let current_ports = state.runtime.read().await.ports.clone();
    let plan = build_snapshot_plan(&current_ports, &snapshot, &local_inventory);
    let affected_ports = affected_ports_for_plan(&plan);
    let requested_port_ids = snapshot
        .ports
        .iter()
        .map(|port| port.port_id.clone())
        .collect();
    let requested_domains = affected_domains_for_ports(&affected_ports);
    if let Err(e) = state.wal.append_snapshot_intent(
        snapshot.generation,
        requested_hash.clone(),
        requested_port_ids,
        requested_domains,
        affected_ports,
    ) {
        return Err(SnapshotApplyError {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            code: "wal_intent_failed",
            details: e,
        });
    }

    {
        let mut runtime = state.runtime.write().await;
        runtime.accepted_generation = snapshot.generation;
        runtime.pending_generation = Some(snapshot.generation);
        runtime.desired_hash = requested_hash.clone();
        runtime.authority_state = "applying".to_string();
        runtime.wal_status = "intent_written".to_string();
    }
    if let Err(e) = fault_injection::check("neutron.snapshot.after_intent").await {
        return Err(SnapshotApplyError {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            code: "fault_injection",
            details: e,
        });
    }

    let mut next_ports = current_ports;
    let mut next_statuses = BTreeMap::new();
    let mut results = plan.ignored;

    for port in plan.detach {
        if let Err(e) = purge_neutron_acl(&state, &port.ifname, &port.port_id).await {
            warn!(
                port_id = %port.port_id,
                ifname = %port.ifname,
                error = %e,
                "failed to purge Neutron ACL before detach"
            );
        }
        match state.registry.detach(&port.ifname).await {
            Ok(()) => {
                next_ports.remove(&port.port_id);
                next_statuses.insert(
                    port.port_id.clone(),
                    port_runtime_status(
                        &port.port_id,
                        &port.ifname,
                        snapshot.generation,
                        requested_hash.clone(),
                        port.managed_domains.clone(),
                        "detached",
                        None,
                        domain_statuses_for(&port.managed_domains, "detached", None),
                    ),
                );
                state
                    .control_plane
                    .clear_neutron_port_authority(&port.ifname)
                    .await;
                results.push(NeutronPortApplyResult {
                    port_id: port.port_id,
                    ifname: port.ifname,
                    action: "detach".to_string(),
                    status: "ok".to_string(),
                    reason: None,
                });
            }
            Err(e) => {
                next_statuses.insert(
                    port.port_id.clone(),
                    port_runtime_status(
                        &port.port_id,
                        &port.ifname,
                        snapshot.generation,
                        requested_hash.clone(),
                        port.managed_domains.clone(),
                        "error",
                        Some(e.clone()),
                        domain_statuses_for(&port.managed_domains, "error", Some(e.clone())),
                    ),
                );
                results.push(NeutronPortApplyResult {
                    port_id: port.port_id,
                    ifname: port.ifname,
                    action: "detach".to_string(),
                    status: "error".to_string(),
                    reason: Some(e),
                });
            }
        }
    }

    for port in plan.update {
        let managed = managed_port_from_snapshot(&port);
        let domain_result = reconcile_neutron_domains(&state, &port).await;
        if domain_result.ok {
            state
                .control_plane
                .mark_neutron_port_authority(
                    &managed.ifname,
                    &managed.port_id,
                    &managed.managed_domains,
                    snapshot.generation,
                )
                .await;
            next_ports.insert(managed.port_id.clone(), managed.clone());
            next_statuses.insert(
                managed.port_id.clone(),
                port_runtime_status(
                    &managed.port_id,
                    &managed.ifname,
                    snapshot.generation,
                    requested_hash.clone(),
                    managed.managed_domains.clone(),
                    "ready",
                    None,
                    domain_result.domains,
                ),
            );
            results.push(NeutronPortApplyResult {
                port_id: managed.port_id,
                ifname: managed.ifname,
                action: "update".to_string(),
                status: "ok".to_string(),
                reason: None,
            });
        } else {
            next_statuses.insert(
                managed.port_id.clone(),
                port_runtime_status(
                    &managed.port_id,
                    &managed.ifname,
                    snapshot.generation,
                    requested_hash.clone(),
                    managed.managed_domains.clone(),
                    "error",
                    domain_result.reason.clone(),
                    domain_result.domains,
                ),
            );
            results.push(NeutronPortApplyResult {
                port_id: managed.port_id,
                ifname: managed.ifname,
                action: "update".to_string(),
                status: "error".to_string(),
                reason: domain_result.reason,
            });
        }
    }

    for port in plan.attach {
        match state.registry.attach(&port.ifname).await {
            Ok(()) => {
                if let Err(e) = fault_injection::check("neutron.port.after_attach").await {
                    if let Err(detach_err) = state.registry.detach(&port.ifname).await {
                        warn!(
                            port_id = %port.port_id,
                            ifname = %port.ifname,
                            error = %detach_err,
                            "failed to detach after fault injection at port attach"
                        );
                    }
                    results.push(NeutronPortApplyResult {
                        port_id: port.port_id,
                        ifname: port.ifname,
                        action: "attach".to_string(),
                        status: "error".to_string(),
                        reason: Some(e),
                    });
                    continue;
                }
                let managed = managed_port_from_snapshot(&port);
                let domain_result = reconcile_neutron_domains(&state, &port).await;
                if domain_result.ok {
                    state
                        .control_plane
                        .mark_neutron_port_authority(
                            &managed.ifname,
                            &managed.port_id,
                            &managed.managed_domains,
                            snapshot.generation,
                        )
                        .await;
                    next_ports.insert(managed.port_id.clone(), managed.clone());
                    next_statuses.insert(
                        managed.port_id.clone(),
                        port_runtime_status(
                            &managed.port_id,
                            &managed.ifname,
                            snapshot.generation,
                            requested_hash.clone(),
                            managed.managed_domains.clone(),
                            "ready",
                            None,
                            domain_result.domains,
                        ),
                    );
                    results.push(NeutronPortApplyResult {
                        port_id: managed.port_id,
                        ifname: managed.ifname,
                        action: "attach".to_string(),
                        status: "ok".to_string(),
                        reason: None,
                    });
                } else {
                    if let Err(purge_err) =
                        purge_neutron_acl(&state, &port.ifname, &port.port_id).await
                    {
                        warn!(
                            port_id = %port.port_id,
                            ifname = %port.ifname,
                            error = %purge_err,
                            "failed to purge Neutron ACL after domain apply failure"
                        );
                    }
                    if let Err(detach_err) = state.registry.detach(&port.ifname).await {
                        warn!(
                            port_id = %port.port_id,
                            ifname = %port.ifname,
                            error = %detach_err,
                            "failed to detach after Neutron domain apply failure"
                        );
                    }
                    state
                        .control_plane
                        .clear_neutron_port_authority(&port.ifname)
                        .await;
                    next_statuses.insert(
                        managed.port_id.clone(),
                        port_runtime_status(
                            &managed.port_id,
                            &managed.ifname,
                            snapshot.generation,
                            requested_hash.clone(),
                            managed.managed_domains.clone(),
                            "error",
                            domain_result.reason.clone(),
                            domain_result.domains,
                        ),
                    );
                    results.push(NeutronPortApplyResult {
                        port_id: managed.port_id,
                        ifname: managed.ifname,
                        action: "attach".to_string(),
                        status: "error".to_string(),
                        reason: domain_result.reason,
                    });
                }
            }
            Err(e) => {
                next_statuses.insert(
                    port.port_id.clone(),
                    port_runtime_status(
                        &port.port_id,
                        &port.ifname,
                        snapshot.generation,
                        requested_hash.clone(),
                        port.managed_domains.clone(),
                        "error",
                        Some(e.clone()),
                        domain_statuses_for(&port.managed_domains, "error", Some(e.clone())),
                    ),
                );
                results.push(NeutronPortApplyResult {
                    port_id: port.port_id,
                    ifname: port.ifname,
                    action: "attach".to_string(),
                    status: "error".to_string(),
                    reason: Some(e),
                });
            }
        }
    }

    let has_error = results.iter().any(|result| result.status == "error");
    let previous_applied_generation = state.runtime.read().await.applied_generation;
    let mut next_runtime = {
        let runtime = state.runtime.read().await;
        runtime.clone()
    };
    next_runtime.accepted_generation = snapshot.generation;
    next_runtime.desired_hash = requested_hash.clone();
    next_runtime.ports = next_ports;
    next_runtime.port_statuses = next_statuses;
    next_runtime.wal_status = "commit_written".to_string();
    if has_error {
        next_runtime.pending_generation = Some(snapshot.generation);
        next_runtime.authority_state = "partial".to_string();
    } else {
        next_runtime.applied_generation = snapshot.generation;
        next_runtime.applied_desired_hash = requested_hash.clone();
        next_runtime.pending_generation = None;
        next_runtime.authority_state = "ready".to_string();
    }

    if let Err(e) = fault_injection::check("neutron.snapshot.before_commit").await {
        return Err(SnapshotApplyError {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            code: "fault_injection",
            details: e,
        });
    }
    if let Err(e) = state.wal.append_snapshot_commit(next_runtime.to_wal_state()) {
        let mut runtime = state.runtime.write().await;
        runtime.pending_generation = Some(snapshot.generation);
        runtime.authority_state = "wal_commit_failed".to_string();
        runtime.wal_status = "commit_failed".to_string();
        return Err(SnapshotApplyError {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            code: "wal_commit_failed",
            details: e,
        });
    }
    if let Err(e) = fault_injection::check("neutron.snapshot.after_commit").await {
        return Err(SnapshotApplyError {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            code: "fault_injection",
            details: e,
        });
    }

    {
        let mut runtime = state.runtime.write().await;
        *runtime = next_runtime;
    }

    Ok(neutron_snapshot_response(
        snapshot.generation,
        requested_hash,
        snapshot.generation,
        if has_error {
            previous_applied_generation
        } else {
            snapshot.generation
        },
        if has_error { "partial" } else { "ok" },
        results,
        state.registry.list().await,
    ))
}

fn hashes_match(left: &Option<String>, right: &Option<String>) -> bool {
    match (left, right) {
        (Some(left), Some(right)) => left == right,
        (None, None) => true,
        _ => false,
    }
}

fn snapshot_has_runtime_drift(
    current: &BTreeMap<String, ManagedNeutronPort>,
    snapshot: &NeutronSnapshotRequest,
    inventory: &LocalInterfaceInventory,
) -> bool {
    let plan = build_snapshot_plan(current, snapshot, inventory);
    if !plan.attach.is_empty() || !plan.detach.is_empty() {
        return true;
    }
    plan.update.iter().any(|port| {
        current
            .get(&port.port_id)
            .map(|managed| {
                managed.ifname != port.ifname
                    || managed.ifindex != port.ifindex
                    || normalize_managed_domains(&managed.managed_domains)
                        != normalize_managed_domains(&port.managed_domains)
            })
            .unwrap_or(true)
    })
}

fn snapshot_generation_fully_applied(runtime: &NeutronRuntimeState, generation: u64) -> bool {
    generation > 0
        && generation == runtime.applied_generation
        && runtime.pending_generation.is_none()
        && runtime.authority_state == "ready"
}

fn transaction_result(
    port_id: &str,
    ifname: &str,
    action: &str,
    status: &str,
    reason: Option<&str>,
) -> NeutronPortApplyResult {
    NeutronPortApplyResult {
        port_id: port_id.to_string(),
        ifname: ifname.to_string(),
        action: action.to_string(),
        status: status.to_string(),
        reason: reason.map(ToOwned::to_owned),
    }
}

fn neutron_snapshot_response(
    generation: u64,
    desired_hash: Option<String>,
    accepted_generation: u64,
    applied_generation: u64,
    status: &str,
    results: Vec<NeutronPortApplyResult>,
    active_instances: Vec<String>,
) -> NeutronSnapshotResponse {
    NeutronSnapshotResponse {
        generation,
        desired_hash,
        accepted_generation,
        applied_generation,
        status: status.to_string(),
        results,
        active_instances,
    }
}

fn port_runtime_status(
    port_id: &str,
    ifname: &str,
    generation: u64,
    desired_hash: Option<String>,
    managed_domains: Vec<String>,
    status: &str,
    reason: Option<String>,
    domains: Vec<NeutronDomainStatus>,
) -> NeutronPortStatus {
    NeutronPortStatus {
        port_id: port_id.to_string(),
        ifname: ifname.to_string(),
        generation,
        desired_hash,
        status: status.to_string(),
        reason,
        managed_domains,
        domains,
    }
}

fn domain_status(domain: &str, status: &str, reason: Option<String>) -> NeutronDomainStatus {
    NeutronDomainStatus {
        domain: domain.to_string(),
        status: status.to_string(),
        reason,
    }
}

fn domain_statuses_for(
    managed_domains: &[String],
    status: &str,
    reason: Option<String>,
) -> Vec<NeutronDomainStatus> {
    normalize_managed_domains(managed_domains)
        .into_iter()
        .map(|domain| domain_status(&domain, status, reason.clone()))
        .collect()
}

fn runtime_domain_statuses_for(
    managed_domains: &[String],
    status: &str,
    reason: Option<String>,
) -> Vec<NeutronDomainStatus> {
    let mut domains = BTreeSet::new();
    domains.insert("attach".to_string());
    domains.extend(normalize_managed_domains(managed_domains));
    domains
        .into_iter()
        .map(|domain| domain_status(&domain, status, reason.clone()))
        .collect()
}

fn blocked_by_unimplemented_domains(domains: &[String]) -> String {
    format!("blocked_by_unimplemented_domains:{}", domains.join(","))
}

fn unimplemented_domain_reason(domain: &str) -> String {
    format!("{}_transaction_not_implemented", domain)
}

async fn reconcile_neutron_domains(
    state: &NeutronApiState,
    port: &NeutronPortSnapshot,
) -> DomainReconcileResult {
    let domains = normalize_managed_domains(&port.managed_domains);
    if domains.is_empty() {
        return DomainReconcileResult {
            domains: Vec::new(),
            ok: true,
            reason: None,
        };
    }

    let unimplemented: Vec<String> = domains
        .iter()
        .filter(|domain| !matches!(domain.as_str(), "attach" | "acl"))
        .cloned()
        .collect();
    if !unimplemented.is_empty() {
        let blocked_reason = blocked_by_unimplemented_domains(&unimplemented);
        let statuses = domains
            .iter()
            .map(|domain| match domain.as_str() {
                "attach" => domain_status(domain, "ready", None),
                "acl" => domain_status(domain, "blocked", Some(blocked_reason.clone())),
                _ => domain_status(domain, "error", Some(unimplemented_domain_reason(domain))),
            })
            .collect();
        return DomainReconcileResult {
            domains: statuses,
            ok: false,
            reason: Some(blocked_reason),
        };
    }

    let mut statuses = Vec::new();
    let mut errors = Vec::new();
    for domain in domains {
        match domain.as_str() {
            "attach" => statuses.push(domain_status(&domain, "ready", None)),
            "acl" => match reconcile_neutron_acl(state, port).await {
                Ok(()) => statuses.push(domain_status(&domain, "ready", None)),
                Err(e) => {
                    let reason = format!("acl_apply_failed:{}", e);
                    statuses.push(domain_status(&domain, "error", Some(reason.clone())));
                    errors.push(reason);
                }
            },
            _ => {
                let reason = unimplemented_domain_reason(&domain);
                statuses.push(domain_status(&domain, "error", Some(reason.clone())));
                errors.push(reason);
            }
        }
    }

    DomainReconcileResult {
        domains: statuses,
        ok: errors.is_empty(),
        reason: if errors.is_empty() {
            None
        } else {
            Some(errors.join(";"))
        },
    }
}

async fn delete_neutron_port(
    State(state): State<NeutronApiState>,
    Path(port_id): Path<String>,
) -> impl IntoResponse {
    let error_port_id = port_id.clone();
    // Keep mutating delete alive even if the UDS client times out or disconnects.
    let handle = tokio::spawn(apply_delete_neutron_port(state, port_id));
    match handle.await {
        Ok((status, response)) => (status, Json(response)).into_response(),
        Err(e) => {
            error!(error = %e, "Neutron port delete task failed");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(NeutronDeleteResponse {
                    port_id: error_port_id,
                    ifname: None,
                    detached: false,
                    status: "error".to_string(),
                    error: Some(format!("delete_task_failed:{}", e)),
                }),
            )
                .into_response()
        }
    }
}

async fn apply_delete_neutron_port(
    state: NeutronApiState,
    port_id: String,
) -> (StatusCode, NeutronDeleteResponse) {
    let _guard = state.apply_lock.lock().await;
    let port = {
        let runtime = state.runtime.read().await;
        runtime.ports.get(&port_id).cloned()
    };

    let Some(port) = port else {
        return (
            StatusCode::OK,
            NeutronDeleteResponse {
                port_id,
                ifname: None,
                detached: false,
                status: "not_found".to_string(),
                error: None,
            },
        );
    };

    let generation = state.runtime.read().await.accepted_generation;
    if let Err(e) = state
        .wal
        .append_delete_intent(
            port_id.clone(),
            generation,
            affected_domains_for_ports(std::slice::from_ref(&port)),
            port.clone(),
        )
    {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            NeutronDeleteResponse {
                port_id: port.port_id,
                ifname: Some(port.ifname),
                detached: false,
                status: "error".to_string(),
                error: Some(format!("wal_intent_failed:{}", e)),
            },
        );
    }
    if let Err(e) = fault_injection::check("neutron.delete.after_intent").await {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            NeutronDeleteResponse {
                port_id: port.port_id,
                ifname: Some(port.ifname),
                detached: false,
                status: "error".to_string(),
                error: Some(e),
            },
        );
    }

    if let Err(e) = purge_neutron_acl(&state, &port.ifname, &port.port_id).await {
        warn!(
            port_id = %port.port_id,
            ifname = %port.ifname,
            error = %e,
            "failed to purge Neutron ACL during port delete"
        );
    }
    if let Err(e) = fault_injection::check("neutron.delete.after_acl_purge").await {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            NeutronDeleteResponse {
                port_id: port.port_id,
                ifname: Some(port.ifname),
                detached: false,
                status: "error".to_string(),
                error: Some(e),
            },
        );
    }

    match state.registry.detach(&port.ifname).await {
        Ok(()) => {
            let mut next_runtime = {
                let runtime = state.runtime.read().await;
                runtime.clone()
            };
            next_runtime.ports.remove(&port_id);
            next_runtime.port_statuses.remove(&port_id);
            next_runtime.wal_status = "commit_written".to_string();
            if let Err(e) =
                fault_injection::check("neutron.delete.after_detach_before_commit").await
            {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    NeutronDeleteResponse {
                        port_id: port.port_id,
                        ifname: Some(port.ifname),
                        detached: true,
                        status: "error".to_string(),
                        error: Some(e),
                    },
                );
            }
            if let Err(e) = state.wal.append_delete_commit(next_runtime.to_wal_state()) {
                let mut runtime = state.runtime.write().await;
                runtime.pending_generation = Some(generation);
                runtime.authority_state = "wal_commit_failed".to_string();
                runtime.wal_status = "commit_failed".to_string();
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    NeutronDeleteResponse {
                        port_id: port.port_id,
                        ifname: Some(port.ifname),
                        detached: true,
                        status: "error".to_string(),
                        error: Some(format!("wal_commit_failed:{}", e)),
                    },
                );
            }
            {
                let mut runtime = state.runtime.write().await;
                *runtime = next_runtime;
            }
            state
                .control_plane
                .clear_neutron_port_authority(&port.ifname)
                .await;
            (
                StatusCode::OK,
                NeutronDeleteResponse {
                    port_id: port.port_id,
                    ifname: Some(port.ifname),
                    detached: true,
                    status: "ok".to_string(),
                    error: None,
                },
            )
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            NeutronDeleteResponse {
                port_id: port.port_id,
                ifname: Some(port.ifname),
                detached: false,
                status: "error".to_string(),
                error: Some(e),
            },
        ),
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct LocalOvsInterface {
    name: String,
    ifindex: Option<u32>,
    bridge: Option<String>,
    iface_id: Option<String>,
}

#[derive(Clone, Debug, Default)]
struct LocalInterfaceInventory {
    ovs_bridge: String,
    ovs_error: Option<String>,
    by_iface_id: BTreeMap<String, LocalOvsInterface>,
    by_name: BTreeMap<String, LocalOvsInterface>,
}

impl LocalInterfaceInventory {
    fn load(ovs_bridge: &str) -> Self {
        match Self::try_load(ovs_bridge) {
            Ok(inventory) => inventory,
            Err(error) => Self {
                ovs_bridge: ovs_bridge.to_string(),
                ovs_error: Some(error),
                by_iface_id: BTreeMap::new(),
                by_name: BTreeMap::new(),
            },
        }
    }

    fn try_load(ovs_bridge: &str) -> Result<Self, String> {
        let bridge_ports = Self::list_bridge_ports(ovs_bridge)?;
        let output = Command::new("ovs-vsctl")
            .args([
                "--format=json",
                "--columns=name,external_ids",
                "list",
                "Interface",
            ])
            .output()
            .map_err(|e| format!("run ovs-vsctl list Interface: {}", e))?;
        if !output.status.success() {
            return Err(format!(
                "ovs-vsctl list Interface failed: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            ));
        }
        let payload = String::from_utf8_lossy(&output.stdout);
        Self::from_ovs_json(ovs_bridge, &bridge_ports, &payload)
    }

    fn list_bridge_ports(ovs_bridge: &str) -> Result<BTreeSet<String>, String> {
        let output = Command::new("ovs-vsctl")
            .args(["list-ports", ovs_bridge])
            .output()
            .map_err(|e| format!("run ovs-vsctl list-ports {}: {}", ovs_bridge, e))?;
        if !output.status.success() {
            return Err(format!(
                "ovs-vsctl list-ports {} failed: {}",
                ovs_bridge,
                String::from_utf8_lossy(&output.stderr).trim()
            ));
        }
        Ok(String::from_utf8_lossy(&output.stdout)
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .map(ToOwned::to_owned)
            .collect())
    }

    fn from_ovs_json(
        ovs_bridge: &str,
        bridge_ports: &BTreeSet<String>,
        payload: &str,
    ) -> Result<Self, String> {
        let document: Value =
            serde_json::from_str(payload).map_err(|e| format!("parse ovs-vsctl json: {}", e))?;
        let headings = document
            .get("headings")
            .and_then(Value::as_array)
            .ok_or_else(|| "ovs json missing headings".to_string())?;
        let data = document
            .get("data")
            .and_then(Value::as_array)
            .ok_or_else(|| "ovs json missing data".to_string())?;

        let mut name_index = None;
        let mut external_ids_index = None;
        for (index, heading) in headings.iter().enumerate() {
            match heading.as_str() {
                Some("name") => name_index = Some(index),
                Some("external_ids") => external_ids_index = Some(index),
                _ => {}
            }
        }
        let name_index = name_index.ok_or_else(|| "ovs json missing name heading".to_string())?;
        let external_ids_index = external_ids_index
            .ok_or_else(|| "ovs json missing external_ids heading".to_string())?;

        let mut inventory = Self {
            ovs_bridge: ovs_bridge.to_string(),
            ovs_error: None,
            by_iface_id: BTreeMap::new(),
            by_name: BTreeMap::new(),
        };

        for row in data {
            let Some(values) = row.as_array() else {
                continue;
            };
            let Some(name) = values.get(name_index).and_then(Value::as_str) else {
                continue;
            };
            let external_ids = values
                .get(external_ids_index)
                .map(parse_ovs_external_ids)
                .unwrap_or_default();
            let iface_id = external_ids.get("iface-id").cloned();
            let interface = LocalOvsInterface {
                name: name.to_string(),
                ifindex: read_ifindex(name),
                bridge: bridge_ports
                    .contains(name)
                    .then(|| ovs_bridge.to_string()),
                iface_id: iface_id.clone(),
            };
            if let Some(iface_id) = iface_id {
                inventory
                    .by_iface_id
                    .insert(iface_id, interface.clone());
            }
            inventory.by_name.insert(name.to_string(), interface);
        }

        Ok(inventory)
    }

    fn is_authoritative(&self) -> bool {
        self.ovs_error.is_none()
    }
}

fn parse_ovs_external_ids(value: &Value) -> BTreeMap<String, String> {
    let mut result = BTreeMap::new();
    let Some(items) = value.as_array() else {
        return result;
    };
    if items.len() != 2 || items.first().and_then(Value::as_str) != Some("map") {
        return result;
    }
    let Some(entries) = items.get(1).and_then(Value::as_array) else {
        return result;
    };
    for entry in entries {
        let Some(pair) = entry.as_array() else {
            continue;
        };
        if pair.len() != 2 {
            continue;
        }
        if let (Some(key), Some(value)) = (pair[0].as_str(), pair[1].as_str()) {
            result.insert(key.to_string(), value.to_string());
        }
    }
    result
}

fn guess_tap_name(port_id: &str) -> String {
    if port_id.is_empty() {
        return String::new();
    }
    let prefix: String = port_id.chars().take(11).collect();
    format!("tap{}", prefix)
}

fn read_ifindex(ifname: &str) -> Option<u32> {
    let path = format!("/sys/class/net/{}/ifindex", ifname);
    std::fs::read_to_string(path)
        .ok()
        .and_then(|raw| raw.trim().parse::<u32>().ok())
        .filter(|ifindex| *ifindex != 0)
}

fn is_compute_owner(device_owner: Option<&str>) -> bool {
    device_owner
        .map(|owner| owner.is_empty() || owner.starts_with("compute:"))
        .unwrap_or(true)
}

fn is_ovs_vif(vif_type: Option<&str>) -> bool {
    matches!(vif_type, None | Some("") | Some("ovs"))
}

fn is_normal_vnic(vnic_type: Option<&str>) -> bool {
    matches!(vnic_type, None | Some("") | Some("normal"))
}

fn ineligible_port(port: &NeutronPortSnapshot, reason: String) -> NeutronPortSnapshot {
    let mut resolved = port.clone();
    resolved.eligible = false;
    resolved.disposition = Some(reason);
    resolved.managed_domains.clear();
    resolved
}

fn resolve_local_neutron_port(
    port: &NeutronPortSnapshot,
    inventory: &LocalInterfaceInventory,
) -> NeutronPortSnapshot {
    if !port.eligible {
        return ineligible_port(
            port,
            port.disposition
                .clone()
                .unwrap_or_else(|| "not eligible".to_string()),
        );
    }

    if !is_compute_owner(port.device_owner.as_deref()) {
        return ineligible_port(
            port,
            format!(
                "not_applicable_device_owner:{}",
                port.device_owner.as_deref().unwrap_or("")
            ),
        );
    }
    if !is_ovs_vif(port.vif_type.as_deref()) {
        return ineligible_port(
            port,
            format!("unsupported_vif_type:{}", port.vif_type.as_deref().unwrap_or("")),
        );
    }
    if !is_normal_vnic(port.vnic_type.as_deref()) {
        return ineligible_port(
            port,
            format!(
                "unsupported_vnic_type:{}",
                port.vnic_type.as_deref().unwrap_or("")
            ),
        );
    }

    if let Some(error) = &inventory.ovs_error {
        return ineligible_port(port, format!("ovsdb_unavailable:{}", error));
    }

    let by_iface_id = inventory.by_iface_id.get(&port.port_id);
    let requested_name = port.ifname.trim();
    let by_name = (!requested_name.is_empty())
        .then(|| inventory.by_name.get(requested_name))
        .flatten();
    let interface = by_iface_id.or(by_name);

    let Some(interface) = interface else {
        let guessed = if requested_name.is_empty() {
            guess_tap_name(&port.port_id)
        } else {
            requested_name.to_string()
        };
        let mut missing = port.clone();
        missing.ifname = guessed;
        return ineligible_port(&missing, "ovs_iface_id_not_found".to_string());
    };

    if interface.bridge.as_deref() != Some(inventory.ovs_bridge.as_str()) {
        let mut bridge_mismatch = port.clone();
        bridge_mismatch.ifname = interface.name.clone();
        bridge_mismatch.ovs_iface_id = interface.iface_id.clone();
        return ineligible_port(
            &bridge_mismatch,
            format!("not_on_ovs_bridge:{}", inventory.ovs_bridge),
        );
    }

    if interface.iface_id.as_deref() != Some(port.port_id.as_str()) {
        let mut mismatch = port.clone();
        mismatch.ifname = interface.name.clone();
        mismatch.ovs_iface_id = interface.iface_id.clone();
        return ineligible_port(&mismatch, "ovs_iface_id_mismatch".to_string());
    }

    let ifindex = interface.ifindex.or_else(|| read_ifindex(&interface.name));
    if ifindex.is_none() {
        let mut not_ready = port.clone();
        not_ready.ifname = interface.name.clone();
        not_ready.ovs_iface_id = interface.iface_id.clone();
        return ineligible_port(&not_ready, "ifindex_not_ready".to_string());
    }

    let mut resolved = port.clone();
    resolved.ifname = interface.name.clone();
    resolved.ifindex = ifindex;
    resolved.eligible = true;
    resolved.disposition = Some("eligible_ovs_tap".to_string());
    resolved.network_backend = Some("openvswitch".to_string());
    resolved.ovs_iface_id = interface.iface_id.clone();
    resolved
}

fn normalize_managed_domains(domains: &[String]) -> Vec<String> {
    ControlPlane::normalize_neutron_managed_domains(domains)
        .into_iter()
        .collect()
}

fn affected_domains_for_ports(ports: &[ManagedNeutronPort]) -> Vec<String> {
    let mut domains = BTreeSet::new();
    if !ports.is_empty() {
        domains.insert("attach".to_string());
    }
    for port in ports {
        domains.extend(normalize_managed_domains(&port.managed_domains));
    }
    domains.into_iter().collect()
}

fn affected_ports_for_plan(plan: &SnapshotPlan) -> Vec<ManagedNeutronPort> {
    let mut ports = BTreeMap::new();
    for port in &plan.detach {
        ports.insert(port.port_id.clone(), port.clone());
    }
    for port in &plan.update {
        let managed = managed_port_from_snapshot(port);
        ports.insert(managed.port_id.clone(), managed);
    }
    for port in &plan.attach {
        let managed = managed_port_from_snapshot(port);
        ports.insert(managed.port_id.clone(), managed);
    }
    ports.into_values().collect()
}

fn affected_ports_for_intent(
    intent: &PendingNeutronIntent,
    current_ports: &BTreeMap<String, ManagedNeutronPort>,
) -> Vec<ManagedNeutronPort> {
    let mut ports = BTreeMap::new();
    for port in &intent.affected_ports {
        ports.insert(port.port_id.clone(), port.clone());
    }
    for port_id in &intent.port_ids {
        if ports.contains_key(port_id) {
            continue;
        }
        if let Some(port) = current_ports.get(port_id) {
            ports.insert(port_id.clone(), port.clone());
        } else {
            ports.insert(
                port_id.clone(),
                ManagedNeutronPort {
                    port_id: port_id.clone(),
                    ifname: String::new(),
                    ifindex: None,
                    managed_domains: intent.affected_domains.clone(),
                },
            );
        }
    }
    ports.into_values().collect()
}

fn recovery_domains_for_port(
    intent: &PendingNeutronIntent,
    port: &ManagedNeutronPort,
) -> Vec<String> {
    let mut domains = BTreeSet::new();
    if !port.ifname.is_empty() {
        domains.insert("attach".to_string());
    }
    domains.extend(normalize_managed_domains(&port.managed_domains));
    domains.extend(normalize_managed_domains(&intent.affected_domains));
    domains.into_iter().collect()
}

fn managed_port_from_snapshot(port: &NeutronPortSnapshot) -> ManagedNeutronPort {
    ManagedNeutronPort {
        port_id: port.port_id.clone(),
        ifname: port.ifname.clone(),
        ifindex: port.ifindex,
        managed_domains: normalize_managed_domains(&port.managed_domains),
    }
}

fn port_manages_acl(port: &NeutronPortSnapshot) -> bool {
    normalize_managed_domains(&port.managed_domains)
        .iter()
        .any(|domain| domain == "acl")
}

fn neutron_acl_prefix(port_id: &str) -> String {
    format!("neutron:{}:", port_id)
}

fn is_neutron_acl_group(port_id: &str, group_name: &str) -> bool {
    group_name.starts_with(&neutron_acl_prefix(port_id))
}

fn acl_rule_id(rule: &NeutronAclRuleSnapshot, index: usize) -> String {
    rule.id
        .as_deref()
        .filter(|id| !id.trim().is_empty())
        .map(|id| {
            id.chars()
                .map(|ch| {
                    if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.') {
                        ch
                    } else {
                        '_'
                    }
                })
                .collect::<String>()
        })
        .unwrap_or_else(|| format!("rule{}", index))
}

fn normalize_default_action(action: &str) -> String {
    let normalized = action.trim().to_ascii_lowercase();
    if normalized.is_empty() {
        "allow".to_string()
    } else {
        normalized
    }
}

fn neutron_acl_to_datapath_directions(direction: u8) -> Vec<u8> {
    match direction {
        // Neutron ACL direction is VM-port centric. On a Linux tap, traffic
        // entering the VM is observed by the host-side TC egress hook.
        0 => vec![1],
        // Traffic leaving the VM is observed by the host-side TC ingress hook.
        1 => vec![0],
        2 => vec![1, 0],
        other => vec![other],
    }
}

fn ensure_ipv4_cidrs(cidrs: &[String], rule_id: &str) -> Result<(), String> {
    for cidr in cidrs {
        if cidr.contains(':') {
            return Err(format!("rule {} uses IPv6 CIDR {}; unsupported", rule_id, cidr));
        }
    }
    Ok(())
}

fn acl_ports(rule: &NeutronAclRuleSnapshot, proto: u8, rule_id: &str) -> Result<Option<String>, String> {
    if rule.src_port_min.is_some() || rule.src_port_max.is_some() {
        return Err(format!(
            "rule {} uses source port matching; unsupported by current datapath translator",
            rule_id
        ));
    }

    let min = rule.dst_port_min.or(rule.dst_port_max);
    let max = rule.dst_port_max.or(rule.dst_port_min);
    let (Some(min), Some(max)) = (min, max) else {
        return Ok(None);
    };

    if proto != 6 && proto != 17 {
        return Err(format!(
            "rule {} uses L4 ports with protocol {}; only tcp/udp are supported",
            rule_id, proto
        ));
    }
    if min > max {
        return Err(format!(
            "rule {} has invalid destination port range {}-{}",
            rule_id, min, max
        ));
    }
    if min == max {
        Ok(Some(min.to_string()))
    } else {
        Ok(Some(format!("{}-{}", min, max)))
    }
}

fn cidr_group(
    port_id: &str,
    rule_id: &str,
    side: &str,
    cidrs: &[String],
    groups: &mut Vec<AclGroupPlan>,
) -> String {
    if cidrs.is_empty() {
        return "any".to_string();
    }
    let name = format!("{}{}:{}", neutron_acl_prefix(port_id), side, rule_id);
    groups.push(AclGroupPlan {
        name: name.clone(),
        cidrs: cidrs.to_vec(),
    });
    name
}

fn translate_neutron_acl(port_id: &str, acl: &NeutronAclSnapshot) -> Result<AclApplyPlan, String> {
    if !acl.enabled
        || !acl.status.eq_ignore_ascii_case("ready")
        || !acl.effective_action.eq_ignore_ascii_case("enforce")
    {
        return Ok(AclApplyPlan::default());
    }

    let default_action = normalize_default_action(&acl.default_action);
    if !matches!(default_action.as_str(), "allow" | "accept" | "pass") {
        return Err(format!(
            "default_action {} is unsupported in the minimal Neutron ACL translator",
            acl.default_action
        ));
    }

    let mut groups = Vec::new();
    let mut policies = Vec::new();
    let mut seen = BTreeSet::new();
    for (index, rule) in acl.rules.iter().enumerate() {
        let rule_id = acl_rule_id(rule, index);
        if rule
            .ethertype
            .as_deref()
            .map(|ethertype| ethertype.eq_ignore_ascii_case("IPv6"))
            .unwrap_or(false)
        {
            return Err(format!("rule {} uses IPv6 ethertype; unsupported", rule_id));
        }
        ensure_ipv4_cidrs(&rule.src_cidrs, &rule_id)?;
        ensure_ipv4_cidrs(&rule.dst_cidrs, &rule_id)?;

        let proto = proto_from_string(rule.protocol.as_deref().unwrap_or("any"))
            .map_err(|e| format!("rule {} protocol: {}", rule_id, e))?;
        let action = action_from_string(rule.action.as_deref().unwrap_or("allow"))
            .map_err(|e| format!("rule {} action: {}", rule_id, e))?;
        let direction = direction_from_string(rule.direction.as_deref().unwrap_or("ingress"))
            .map_err(|e| format!("rule {} direction: {}", rule_id, e))?;
        let ports = acl_ports(rule, proto, &rule_id)?;
        let src_group = cidr_group(port_id, &rule_id, "src", &rule.src_cidrs, &mut groups);
        let dst_group = cidr_group(port_id, &rule_id, "dst", &rule.dst_cidrs, &mut groups);

        for direction in neutron_acl_to_datapath_directions(direction) {
            let key = (src_group.clone(), dst_group.clone(), proto, direction);
            if !seen.insert(key.clone()) {
                return Err(format!(
                    "duplicate effective ACL key src={} dst={} proto={} direction={}",
                    key.0, key.1, key.2, key.3
                ));
            }
            policies.push(AclPolicyPlan {
                src_group: key.0,
                dst_group: key.1,
                proto,
                action,
                direction,
                ports: ports.clone(),
            });
        }
    }

    Ok(AclApplyPlan { groups, policies })
}

async fn purge_neutron_acl(
    state: &NeutronApiState,
    ifname: &str,
    port_id: &str,
) -> Result<(), String> {
    let (rules, groups_by_name) = match state.control_plane.list_policies(ifname).await {
        Ok(result) => result,
        Err(e) => return Err(e.to_string()),
    };
    let group_names_by_id: BTreeMap<u32, String> = groups_by_name
        .values()
        .map(|group| (group.id, group.name.clone()))
        .collect();

    for rule in rules {
        let src_group = if rule.src_group_id == 0 {
            "any".to_string()
        } else {
            group_names_by_id
                .get(&rule.src_group_id)
                .cloned()
                .unwrap_or_else(|| format!("id:{}", rule.src_group_id))
        };
        let dst_group = if rule.dst_group_id == 0 {
            "any".to_string()
        } else {
            group_names_by_id
                .get(&rule.dst_group_id)
                .cloned()
                .unwrap_or_else(|| format!("id:{}", rule.dst_group_id))
        };
        if is_neutron_acl_group(port_id, &src_group) || is_neutron_acl_group(port_id, &dst_group) {
            state
                .control_plane
                .delete_policy(ifname, &src_group, &dst_group, rule.proto, rule.direction)
                .await
                .map_err(|e| e.to_string())?;
        }
    }

    let groups = state
        .control_plane
        .list_groups(ifname)
        .await
        .map_err(|e| e.to_string())?;
    for group in groups {
        if is_neutron_acl_group(port_id, &group.name) {
            state
                .control_plane
                .delete_group(ifname, &group.name)
                .await
                .map_err(|e| e.to_string())?;
        }
    }

    Ok(())
}

async fn flush_neutron_acl_conntrack(
    state: &NeutronApiState,
    ifname: &str,
    port_id: &str,
) -> Result<(), String> {
    let flushed = state
        .control_plane
        .flush_conntrack(ifname)
        .await
        .map_err(|e| e.to_string())?;
    if flushed > 0 {
        warn!(
            port_id = %port_id,
            ifname = %ifname,
            flushed,
            "flushed conntrack after Neutron ACL reconcile"
        );
    }
    Ok(())
}

async fn reconcile_neutron_acl(
    state: &NeutronApiState,
    port: &NeutronPortSnapshot,
) -> Result<(), String> {
    if !port_manages_acl(port) {
        return Ok(());
    }

    state
        .control_plane
        .update_config(&port.ifname, None, None, Some(false), None, None, None, None)
        .await
        .map_err(|e| e.to_string())?;
    fault_injection::check("neutron.acl.after_disable").await?;

    purge_neutron_acl(state, &port.ifname, &port.port_id).await?;
    fault_injection::check("neutron.acl.after_purge").await?;

    let Some(acl) = &port.acl else {
        flush_neutron_acl_conntrack(state, &port.ifname, &port.port_id).await?;
        return Ok(());
    };

    let plan = translate_neutron_acl(&port.port_id, acl)?;
    if plan.policies.is_empty() {
        flush_neutron_acl_conntrack(state, &port.ifname, &port.port_id).await?;
        return Ok(());
    }

    for group in &plan.groups {
        for cidr in &group.cidrs {
            if let Err(e) = state.control_plane.add_group(&port.ifname, &group.name, cidr).await {
                let _ = purge_neutron_acl(state, &port.ifname, &port.port_id).await;
                let _ = state
                    .control_plane
                    .update_config(&port.ifname, None, None, Some(false), None, None, None, None)
                    .await;
                return Err(e.to_string());
            }
            fault_injection::check("neutron.acl.after_group_write").await?;
        }
    }

    for policy in &plan.policies {
        if let Err(e) = state
            .control_plane
            .add_policy(
                &port.ifname,
                &policy.src_group,
                &policy.dst_group,
                policy.proto,
                policy.action,
                policy.direction,
                policy.ports.as_deref(),
            )
            .await
        {
            let _ = purge_neutron_acl(state, &port.ifname, &port.port_id).await;
            let _ = state
                .control_plane
                .update_config(&port.ifname, None, None, Some(false), None, None, None, None)
                .await;
            return Err(e.to_string());
        }
        fault_injection::check("neutron.acl.after_policy_write").await?;
    }

    flush_neutron_acl_conntrack(state, &port.ifname, &port.port_id).await?;
    fault_injection::check("neutron.acl.before_enable").await?;
    state
        .control_plane
        .update_config(&port.ifname, None, None, Some(true), None, None, None, None)
        .await
        .map_err(|e| e.to_string())?;
    fault_injection::check("neutron.acl.after_enable_before_commit").await
}

fn build_snapshot_plan(
    current: &BTreeMap<String, ManagedNeutronPort>,
    snapshot: &NeutronSnapshotRequest,
    inventory: &LocalInterfaceInventory,
) -> SnapshotPlan {
    let mut desired = BTreeMap::new();
    let mut ignored = Vec::new();

    for port in &snapshot.ports {
        if port.port_id.trim().is_empty() {
            ignored.push(NeutronPortApplyResult {
                port_id: port.port_id.clone(),
                ifname: port.ifname.clone(),
                action: "ignore".to_string(),
                status: "ignored".to_string(),
                reason: Some("missing port_id".to_string()),
            });
            continue;
        }

        let resolved_port = resolve_local_neutron_port(port, inventory);

        if !resolved_port.eligible {
            ignored.push(NeutronPortApplyResult {
                port_id: resolved_port.port_id.clone(),
                ifname: resolved_port.ifname.clone(),
                action: "ignore".to_string(),
                status: "ignored".to_string(),
                reason: Some(
                    resolved_port
                        .disposition
                        .clone()
                        .unwrap_or_else(|| "not eligible".to_string()),
                ),
            });
            continue;
        }

        if resolved_port.ifname.trim().is_empty() {
            ignored.push(NeutronPortApplyResult {
                port_id: resolved_port.port_id.clone(),
                ifname: resolved_port.ifname.clone(),
                action: "ignore".to_string(),
                status: "ignored".to_string(),
                reason: Some("missing ifname".to_string()),
            });
            continue;
        }

        desired.insert(resolved_port.port_id.clone(), resolved_port);
    }

    let desired_ids: BTreeSet<String> = desired.keys().cloned().collect();
    let mut detach = Vec::new();

    if inventory.is_authoritative() {
        for (port_id, managed) in current {
            match desired.get(port_id) {
                Some(port) if port.ifname == managed.ifname => {}
                _ => detach.push(managed.clone()),
            }
        }
    }

    let mut attach = Vec::new();
    let mut update = Vec::new();
    for (port_id, port) in desired {
        match current.get(&port_id) {
            Some(managed) if managed.ifname == port.ifname => {
                update.push(port);
            }
            _ if desired_ids.contains(&port_id) => {
                attach.push(port);
            }
            _ => {}
        }
    }

    SnapshotPlan {
        attach,
        update,
        detach,
        ignored,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn managed(port_id: &str, ifname: &str) -> ManagedNeutronPort {
        ManagedNeutronPort {
            port_id: port_id.to_string(),
            ifname: ifname.to_string(),
            ifindex: None,
            managed_domains: Vec::new(),
        }
    }

    fn port(port_id: &str, ifname: &str, eligible: bool) -> NeutronPortSnapshot {
        NeutronPortSnapshot {
            port_id: port_id.to_string(),
            ifname: ifname.to_string(),
            ifindex: None,
            eligible,
            disposition: None,
            device_owner: None,
            vif_type: None,
            vnic_type: None,
            network_backend: None,
            ovs_iface_id: None,
            managed_domains: Vec::new(),
            acl: None,
            qos: None,
            mirror: None,
        }
    }

    fn iface(
        name: &str,
        port_id: &str,
        ifindex: Option<u32>,
        bridge: Option<&str>,
    ) -> LocalOvsInterface {
        LocalOvsInterface {
            name: name.to_string(),
            ifindex,
            bridge: bridge.map(ToOwned::to_owned),
            iface_id: Some(port_id.to_string()),
        }
    }

    fn inventory(interfaces: Vec<LocalOvsInterface>) -> LocalInterfaceInventory {
        let mut by_iface_id = BTreeMap::new();
        let mut by_name = BTreeMap::new();
        for interface in interfaces {
            if let Some(iface_id) = interface.iface_id.clone() {
                by_iface_id.insert(iface_id, interface.clone());
            }
            by_name.insert(interface.name.clone(), interface);
        }
        LocalInterfaceInventory {
            ovs_bridge: "br-int".to_string(),
            ovs_error: None,
            by_iface_id,
            by_name,
        }
    }

    #[test]
    fn neutron_snapshot_plan_attaches_only_eligible_ports() {
        let current = BTreeMap::new();
        let local = inventory(vec![iface("tap111", "vm-port", Some(11), Some("br-int"))]);
        let snapshot = NeutronSnapshotRequest {
            schema_version: None,
            generation: 1,
            desired_hash: None,
            host: None,
            ports: vec![
                port("vm-port", "tap111", true),
                NeutronPortSnapshot {
                    disposition: Some("service port".to_string()),
                    ..port("dhcp-port", "tap222", false)
                },
            ],
        };

        let plan = build_snapshot_plan(&current, &snapshot, &local);

        let mut expected = port("vm-port", "tap111", true);
        expected.ifindex = Some(11);
        expected.disposition = Some("eligible_ovs_tap".to_string());
        expected.network_backend = Some("openvswitch".to_string());
        expected.ovs_iface_id = Some("vm-port".to_string());
        assert_eq!(plan.attach, vec![expected]);
        assert!(plan.update.is_empty());
        assert!(plan.detach.is_empty());
        assert_eq!(plan.ignored.len(), 1);
        assert_eq!(plan.ignored[0].port_id, "dhcp-port");
    }

    #[test]
    fn neutron_snapshot_plan_detaches_removed_ports() {
        let mut current = BTreeMap::new();
        current.insert("old-port".to_string(), managed("old-port", "tap-old"));
        current.insert("kept-port".to_string(), managed("kept-port", "tap-kept"));
        let local = inventory(vec![iface("tap-kept", "kept-port", Some(12), Some("br-int"))]);
        let snapshot = NeutronSnapshotRequest {
            schema_version: None,
            generation: 2,
            desired_hash: None,
            host: None,
            ports: vec![port("kept-port", "tap-kept", true)],
        };

        let plan = build_snapshot_plan(&current, &snapshot, &local);

        assert!(plan.attach.is_empty());
        assert_eq!(plan.update.len(), 1);
        assert_eq!(plan.update[0].port_id, "kept-port");
        assert_eq!(plan.update[0].ifname, "tap-kept");
        assert_eq!(plan.update[0].ifindex, Some(12));
        assert_eq!(plan.detach, vec![managed("old-port", "tap-old")]);
        assert!(plan.ignored.is_empty());
    }

    #[test]
    fn neutron_snapshot_plan_reattaches_when_ifname_changes() {
        let mut current = BTreeMap::new();
        current.insert("vm-port".to_string(), managed("vm-port", "tap-old"));
        let local = inventory(vec![iface("tap-new", "vm-port", Some(13), Some("br-int"))]);
        let snapshot = NeutronSnapshotRequest {
            schema_version: None,
            generation: 3,
            desired_hash: None,
            host: None,
            ports: vec![port("vm-port", "tap-new", true)],
        };

        let plan = build_snapshot_plan(&current, &snapshot, &local);

        assert_eq!(plan.detach, vec![managed("vm-port", "tap-old")]);
        assert_eq!(plan.attach.len(), 1);
        assert_eq!(plan.attach[0].ifname, "tap-new");
        assert!(plan.update.is_empty());
        assert!(plan.ignored.is_empty());
    }

    #[test]
    fn neutron_snapshot_plan_detaches_previously_managed_ineligible_port() {
        let mut current = BTreeMap::new();
        current.insert("dhcp-port".to_string(), managed("dhcp-port", "tap-dhcp"));
        let local = inventory(vec![iface("tap-dhcp", "dhcp-port", Some(14), Some("br-int"))]);
        let snapshot = NeutronSnapshotRequest {
            schema_version: None,
            generation: 4,
            desired_hash: None,
            host: None,
            ports: vec![NeutronPortSnapshot {
                disposition: Some("device_owner network:dhcp".to_string()),
                ..port("dhcp-port", "tap-dhcp", false)
            }],
        };

        let plan = build_snapshot_plan(&current, &snapshot, &local);

        assert_eq!(plan.detach, vec![managed("dhcp-port", "tap-dhcp")]);
        assert!(plan.attach.is_empty());
        assert!(plan.update.is_empty());
        assert_eq!(plan.ignored[0].reason.as_deref(), Some("device_owner network:dhcp"));
    }

    #[test]
    fn neutron_snapshot_plan_updates_existing_port_domains_without_reattach() {
        let mut current = BTreeMap::new();
        current.insert(
            "vm-port".to_string(),
            ManagedNeutronPort {
                managed_domains: vec!["acl".to_string()],
                ..managed("vm-port", "tap-vm")
            },
        );
        let local = inventory(vec![iface("tap-vm", "vm-port", Some(15), Some("br-int"))]);
        let snapshot = NeutronSnapshotRequest {
            schema_version: None,
            generation: 5,
            desired_hash: None,
            host: None,
            ports: vec![NeutronPortSnapshot {
                managed_domains: vec!["acl".to_string(), "qos".to_string()],
                ..port("vm-port", "tap-vm", true)
            }],
        };

        let plan = build_snapshot_plan(&current, &snapshot, &local);

        assert!(plan.attach.is_empty());
        assert!(plan.detach.is_empty());
        assert_eq!(plan.update.len(), 1);
        assert_eq!(
            normalize_managed_domains(&plan.update[0].managed_domains),
            vec!["acl".to_string(), "qos".to_string()]
        );
    }

    #[test]
    fn domain_statuses_track_each_managed_domain() {
        let domains = domain_statuses_for(
            &[
                "acl".to_string(),
                "qos".to_string(),
                "mirror".to_string(),
            ],
            "error",
            Some("apply_failed".to_string()),
        );

        assert_eq!(
            domains,
            vec![
                NeutronDomainStatus {
                    domain: "acl".to_string(),
                    status: "error".to_string(),
                    reason: Some("apply_failed".to_string()),
                },
                NeutronDomainStatus {
                    domain: "mirror".to_string(),
                    status: "error".to_string(),
                    reason: Some("apply_failed".to_string()),
                },
                NeutronDomainStatus {
                    domain: "qos".to_string(),
                    status: "error".to_string(),
                    reason: Some("apply_failed".to_string()),
                },
            ]
        );
    }

    #[test]
    fn affected_domains_include_attach_and_feature_domains() {
        let ports = vec![ManagedNeutronPort {
            port_id: "vm-port".to_string(),
            ifname: "tap-vm".to_string(),
            ifindex: None,
            managed_domains: vec!["acl".to_string(), "qos".to_string(), "mirror".to_string()],
        }];

        assert_eq!(
            affected_domains_for_ports(&ports),
            vec![
                "acl".to_string(),
                "attach".to_string(),
                "mirror".to_string(),
                "qos".to_string(),
            ]
        );
    }

    #[test]
    fn runtime_domain_statuses_include_attach_domain() {
        let statuses = runtime_domain_statuses_for(
            &["acl".to_string(), "qos".to_string()],
            "blocked",
            Some("runtime_reconcile_failed".to_string()),
        );

        assert_eq!(
            statuses
                .iter()
                .map(|status| status.domain.as_str())
                .collect::<Vec<_>>(),
            vec!["acl", "attach", "qos"]
        );
        assert!(statuses.iter().all(|status| status.status == "blocked"));
    }

    #[test]
    fn snapshot_generation_noop_requires_ready_without_pending() {
        let ready = NeutronRuntimeState {
            applied_generation: 42,
            pending_generation: None,
            authority_state: "ready".to_string(),
            ..Default::default()
        };
        assert!(snapshot_generation_fully_applied(&ready, 42));

        let partial = NeutronRuntimeState {
            accepted_generation: 42,
            applied_generation: 42,
            pending_generation: Some(42),
            authority_state: "partial".to_string(),
            ..Default::default()
        };
        assert!(!snapshot_generation_fully_applied(&partial, 42));

        let blocked = NeutronRuntimeState {
            accepted_generation: 42,
            applied_generation: 42,
            pending_generation: None,
            authority_state: "blocked_recovery_required".to_string(),
            ..Default::default()
        };
        assert!(!snapshot_generation_fully_applied(&blocked, 42));
    }

    #[test]
    fn same_generation_noop_detects_tap_ifindex_drift() {
        let mut current = BTreeMap::new();
        current.insert(
            "vm-port".to_string(),
            ManagedNeutronPort {
                port_id: "vm-port".to_string(),
                ifname: "tap-vm".to_string(),
                ifindex: Some(50),
                managed_domains: vec!["acl".to_string()],
            },
        );
        let local = inventory(vec![iface("tap-vm", "vm-port", Some(51), Some("br-int"))]);
        let snapshot = NeutronSnapshotRequest {
            schema_version: None,
            generation: 42,
            desired_hash: Some("hash-42".to_string()),
            host: None,
            ports: vec![NeutronPortSnapshot {
                managed_domains: vec!["acl".to_string()],
                ..port("vm-port", "", true)
            }],
        };

        assert!(snapshot_has_runtime_drift(&current, &snapshot, &local));

        current.get_mut("vm-port").unwrap().ifindex = Some(51);
        assert!(!snapshot_has_runtime_drift(&current, &snapshot, &local));
    }

    #[test]
    fn pending_intent_ports_fall_back_to_committed_runtime() {
        let intent = PendingNeutronIntent {
            kind: "snapshot".to_string(),
            generation: 17,
            desired_hash: Some("hash-17".to_string()),
            port_ids: vec!["vm-port".to_string()],
            affected_domains: vec!["acl".to_string()],
            affected_ports: Vec::new(),
        };
        let mut current = BTreeMap::new();
        current.insert(
            "vm-port".to_string(),
            ManagedNeutronPort {
                port_id: "vm-port".to_string(),
                ifname: "tap-vm".to_string(),
                ifindex: Some(17),
                managed_domains: vec!["acl".to_string()],
            },
        );

        let ports = affected_ports_for_intent(&intent, &current);

        assert_eq!(1, ports.len());
        assert_eq!("tap-vm", ports[0].ifname);
        assert_eq!(Some(17), ports[0].ifindex);
    }

    #[test]
    fn neutron_snapshot_plan_resolves_candidate_by_ovs_iface_id() {
        let current = BTreeMap::new();
        let local = inventory(vec![iface(
            "tape607e86b-9e",
            "e607e86b-9e5f-4c63-a5df-3dc8986a1b0f",
            Some(27),
            Some("br-int"),
        )]);
        let mut candidate = port("e607e86b-9e5f-4c63-a5df-3dc8986a1b0f", "", true);
        candidate.disposition = Some("pending_local_validation".to_string());
        candidate.managed_domains = vec!["acl".to_string()];
        let snapshot = NeutronSnapshotRequest {
            schema_version: None,
            generation: 6,
            desired_hash: None,
            host: None,
            ports: vec![candidate],
        };

        let plan = build_snapshot_plan(&current, &snapshot, &local);

        assert_eq!(plan.attach.len(), 1);
        assert_eq!(plan.attach[0].ifname, "tape607e86b-9e");
        assert_eq!(plan.attach[0].ifindex, Some(27));
        assert_eq!(
            plan.attach[0].disposition.as_deref(),
            Some("eligible_ovs_tap")
        );
        assert!(plan.ignored.is_empty());
    }

    #[test]
    fn neutron_snapshot_plan_does_not_detach_when_ovsdb_unavailable() {
        let mut current = BTreeMap::new();
        current.insert("vm-port".to_string(), managed("vm-port", "tap-vm"));
        let local = LocalInterfaceInventory {
            ovs_bridge: "br-int".to_string(),
            ovs_error: Some("permission denied".to_string()),
            by_iface_id: BTreeMap::new(),
            by_name: BTreeMap::new(),
        };
        let snapshot = NeutronSnapshotRequest {
            schema_version: None,
            generation: 7,
            desired_hash: None,
            host: None,
            ports: vec![port("vm-port", "", true)],
        };

        let plan = build_snapshot_plan(&current, &snapshot, &local);

        assert!(plan.attach.is_empty());
        assert!(plan.update.is_empty());
        assert!(plan.detach.is_empty());
        assert_eq!(plan.ignored.len(), 1);
        assert_eq!(
            plan.ignored[0].reason.as_deref(),
            Some("ovsdb_unavailable:permission denied")
        );
    }

    #[test]
    fn neutron_acl_translator_builds_drop_icmp_policy() {
        let acl = NeutronAclSnapshot {
            enabled: true,
            status: "ready".to_string(),
            reason: "ready".to_string(),
            effective_action: "enforce".to_string(),
            policy_id: Some("acl-policy".to_string()),
            policy_name: Some("smoke".to_string()),
            binding_id: Some("acl-binding".to_string()),
            source: Some("port".to_string()),
            default_action: "allow".to_string(),
            stateful: true,
            revision: 1,
            rules: vec![NeutronAclRuleSnapshot {
                id: Some("drop-icmp".to_string()),
                direction: Some("ingress".to_string()),
                priority: 100,
                action: Some("drop".to_string()),
                ethertype: Some("IPv4".to_string()),
                protocol: Some("icmp".to_string()),
                src_cidrs: vec!["10.58.159.2/32".to_string()],
                dst_cidrs: Vec::new(),
                src_port_min: None,
                src_port_max: None,
                dst_port_min: None,
                dst_port_max: None,
            }],
        };

        let plan = translate_neutron_acl("port-1", &acl).expect("ACL should translate");

        assert_eq!(
            plan.groups,
            vec![AclGroupPlan {
                name: "neutron:port-1:src:drop-icmp".to_string(),
                cidrs: vec!["10.58.159.2/32".to_string()],
            }]
        );
        assert_eq!(
            plan.policies,
            vec![AclPolicyPlan {
                src_group: "neutron:port-1:src:drop-icmp".to_string(),
                dst_group: "any".to_string(),
                proto: 1,
                action: 1,
                direction: 1,
                ports: None,
            }]
        );
    }

    #[test]
    fn neutron_acl_translator_rejects_default_deny_until_owned_defaults_exist() {
        let acl = NeutronAclSnapshot {
            enabled: true,
            status: "ready".to_string(),
            reason: "ready".to_string(),
            effective_action: "enforce".to_string(),
            policy_id: Some("acl-policy".to_string()),
            policy_name: None,
            binding_id: None,
            source: Some("port".to_string()),
            default_action: "deny".to_string(),
            stateful: true,
            revision: 1,
            rules: Vec::new(),
        };

        let error = translate_neutron_acl("port-1", &acl).expect_err("default deny is guarded");

        assert!(error.contains("default_action deny is unsupported"));
    }
}
