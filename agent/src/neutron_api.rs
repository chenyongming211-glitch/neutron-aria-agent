use aria_api::{
    action_from_string, direction_from_string, proto_from_string, ManagedNeutronPort,
    NeutronAclRuleSnapshot, NeutronAclSnapshot, NeutronCapabilitiesResponse, NeutronDeleteResponse,
    NeutronDomainStatus, NeutronPortApplyResult, NeutronPortSnapshot, NeutronPortStatus,
    NeutronSnapshotRequest, NeutronSnapshotResponse, NeutronStatusResponse,
    NEUTRON_UDS_BODY_MAX_BYTES, NEUTRON_UDS_SCHEMA_VERSION_MAX, NEUTRON_UDS_SCHEMA_VERSION_MIN,
};
use axum::{
    extract::DefaultBodyLimit,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{delete, get, post, put},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::process::Command;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::{Mutex, OwnedMutexGuard, RwLock};
use tracing::{error, info, warn};

use crate::control_plane::{ControlPlane, OwnedAclGroupSpec, OwnedAclPolicySpec};
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

#[derive(Clone, Debug, Default)]
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

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
struct NeutronRecoverPendingRequest {
    expected_pending_generation: u64,
    expected_desired_hash: Option<String>,
    mode: Option<String>,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
struct NeutronRecoverPendingResponse {
    status: String,
    recovered_generation: u64,
    desired_hash: Option<String>,
    applied_generation: u64,
    applied_desired_hash: Option<String>,
    authority_state: String,
    wal_status: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct SnapshotPlan {
    attach: Vec<NeutronPortSnapshot>,
    update: Vec<NeutronPortSnapshot>,
    detach: Vec<ManagedNeutronPort>,
    ignored: Vec<NeutronPortApplyResult>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum ApplyScope {
    FullHost,
    SinglePort(String),
}

fn apply_scope_name(scope: &ApplyScope) -> &'static str {
    match scope {
        ApplyScope::FullHost => "full_host",
        ApplyScope::SinglePort(_) => "port",
    }
}

fn apply_scope_port_id(scope: &ApplyScope) -> Option<&str> {
    match scope {
        ApplyScope::FullHost => None,
        ApplyScope::SinglePort(port_id) => Some(port_id.as_str()),
    }
}

fn elapsed_ms(started_at: Instant) -> u64 {
    let value = started_at.elapsed().as_millis();
    if value > u64::MAX as u128 {
        u64::MAX
    } else {
        value as u64
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum SnapshotScopeError {
    SinglePortBodyCount { actual: usize },
    SinglePortBodyMismatch { expected: String, actual: String },
    ScopeWidened { target: String, actual: String },
}

impl SnapshotScopeError {
    fn code(&self) -> &'static str {
        "PORT_SCOPE_MISMATCH"
    }
}

impl fmt::Display for SnapshotScopeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SinglePortBodyCount { actual } => write!(
                f,
                "single-port snapshot requires exactly one body port, got {}",
                actual
            ),
            Self::SinglePortBodyMismatch { expected, actual } => write!(
                f,
                "single-port snapshot path/body mismatch: expected {}, got {}",
                expected, actual
            ),
            Self::ScopeWidened { target, actual } => write!(
                f,
                "single-port snapshot plan widened scope: target {}, affected {}",
                target, actual
            ),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct SnapshotApplyTransaction {
    scope: ApplyScope,
    plan: SnapshotPlan,
    requested_port_ids: Vec<String>,
    affected_domains: Vec<String>,
    affected_ports: Vec<ManagedNeutronPort>,
}

struct SnapshotRuntimeApplyOutcome {
    next_runtime: NeutronRuntimeState,
    previous_applied_generation: u64,
    results: Vec<NeutronPortApplyResult>,
    has_error: bool,
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

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct AclEffectivePolicyKey {
    src_group: String,
    dst_group: String,
    proto: u8,
    direction: u8,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct AclApplyPlan {
    groups: Vec<AclGroupPlan>,
    policies: Vec<AclPolicyPlan>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct AclPolicyDeleteTarget {
    src_group: String,
    dst_group: String,
    proto: u8,
    direction: u8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AclGateUpdateMode {
    DisableBeforeReplace,
}

impl AclGateUpdateMode {
    fn as_str(self) -> &'static str {
        match self {
            Self::DisableBeforeReplace => "disable_before_replace",
        }
    }
}

fn acl_gate_update_mode(_plan: &AclApplyPlan) -> AclGateUpdateMode {
    AclGateUpdateMode::DisableBeforeReplace
}

#[derive(Debug)]
struct NeutronAclReconcileError {
    details: String,
    effective_action: &'static str,
}

impl NeutronAclReconcileError {
    fn unchanged(details: impl Into<String>) -> Self {
        Self {
            details: details.into(),
            effective_action: "unchanged",
        }
    }

    fn bypass(details: impl Into<String>) -> Self {
        Self {
            details: details.into(),
            effective_action: "bypass",
        }
    }

    fn enforce(details: impl Into<String>) -> Self {
        Self {
            details: details.into(),
            effective_action: "enforce",
        }
    }
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
    fn blocked(
        port: &ManagedNeutronPort,
        domains: Vec<NeutronDomainStatus>,
        reason: String,
    ) -> Self {
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
    fn new(
        registry: Arc<TapRegistry>,
        control_plane: Arc<ControlPlane>,
        ovs_bridge: String,
    ) -> Self {
        let wal = Arc::new(NeutronWal::new(&registry.base_state_path));
        let replay = wal.replay();
        let pending_recovery = replay.pending_intent.clone();
        let runtime =
            NeutronRuntimeState::from_wal_state(replay.state, replay.status, replay.failures);
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
        let mut successfully_claimed_ports = Vec::new();
        for port in &ports {
            let Some(result) = results
                .iter()
                .find(|result| result.ifname == port.ifname && result.action == "claim_committed")
            else {
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
            if result.status == "ready" {
                successfully_claimed_ports.push(port.clone());
            }
        }
        for result in results
            .iter()
            .filter(|result| result.action == "cleanup_orphan")
        {
            if result.status == "blocked" {
                degraded = true;
            }
        }

        let acl_requires_full_resync = invalidate_restarted_acl_runtime(
            &mut next_runtime,
            &successfully_claimed_ports,
        );

        if degraded {
            next_runtime.authority_state = "runtime_degraded".to_string();
            next_runtime.wal_status = "runtime_reconcile_degraded".to_string();
        } else if acl_requires_full_resync && next_runtime.pending_generation.is_none() {
            next_runtime.authority_state =
                "runtime_reconcile_requires_full_resync".to_string();
            next_runtime.wal_status =
                "runtime_reconciled_acl_resync_required".to_string();
        } else if next_runtime.pending_generation.is_none() {
            next_runtime.authority_state = "ready".to_string();
            next_runtime.wal_status = "runtime_reconciled".to_string();
        } else if next_runtime.wal_status != "intent_recovered" {
            next_runtime.wal_status = "runtime_reconciled".to_string();
        }

        if let Err(e) = self.wal.append_snapshot_commit(next_runtime.to_wal_state()) {
            next_runtime.authority_state = "wal_runtime_reconcile_commit_failed".to_string();
            next_runtime.wal_status = "commit_failed".to_string();
            let mut runtime = self.runtime.write().await;
            *runtime = next_runtime;
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

        if let Some(recovery) = blocked_unsupported_recovery(&domains) {
            return recovery;
        }

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
                unsupported => {
                    let reason = format!("unsupported_recovery_domain:{}", unsupported);
                    statuses.push(domain_status(domain, "blocked", Some(reason.clone())));
                    errors.push(reason);
                }
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
    fn from_wal_state(
        state: NeutronWalState,
        wal_status: String,
        wal_replay_failures: u64,
    ) -> Self {
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
        .route(
            "/api/v1/neutron/snapshot/recover-pending",
            post(post_neutron_recover_pending),
        )
        .route("/api/v1/neutron/snapshot", put(put_neutron_snapshot))
        .route(
            "/api/v1/neutron/ports/{port_id}/snapshot",
            put(put_neutron_port_snapshot),
        )
        .route(
            "/api/v1/neutron/ports/{port_id}",
            delete(delete_neutron_port),
        )
        .layer(DefaultBodyLimit::max(NEUTRON_UDS_BODY_MAX_BYTES as usize))
        .with_state(state)
}

async fn post_neutron_recover_pending(
    State(state): State<NeutronApiState>,
    Json(request): Json<NeutronRecoverPendingRequest>,
) -> impl IntoResponse {
    match recover_pending_snapshot(state, request).await {
        Ok(response) => Json(response).into_response(),
        Err(error) => (
            error.status,
            Json(serde_json::json!({
                "error": error.code,
                "details": error.details,
            })),
        )
            .into_response(),
    }
}

async fn recover_pending_snapshot(
    state: NeutronApiState,
    request: NeutronRecoverPendingRequest,
) -> Result<NeutronRecoverPendingResponse, SnapshotApplyError> {
    let mode = request
        .mode
        .as_deref()
        .unwrap_or("rollback_to_last_applied");
    if mode != "rollback_to_last_applied" {
        return Err(SnapshotApplyError {
            status: StatusCode::BAD_REQUEST,
            code: "unsupported_pending_recovery_mode",
            details: format!("unsupported pending recovery mode {}", mode),
        });
    }

    let _guard = state.apply_lock.lock().await;
    let replay = state.wal.replay();
    let mut runtime = state.runtime.write().await;
    validate_pending_recovery_identity(&runtime, &request)?;
    if replay.pending_intent.is_none()
        && wal_state_newer_than_runtime(&replay.state, &runtime)
    {
        let refreshed = NeutronRuntimeState::from_wal_state(
            replay.state,
            replay.status,
            replay.failures,
        );
        let response = NeutronRecoverPendingResponse {
            status: "already_committed".to_string(),
            recovered_generation: refreshed.applied_generation,
            desired_hash: refreshed.desired_hash.clone(),
            applied_generation: refreshed.applied_generation,
            applied_desired_hash: refreshed.applied_desired_hash.clone(),
            authority_state: refreshed.authority_state.clone(),
            wal_status: refreshed.wal_status.clone(),
        };
        *runtime = refreshed;
        return Ok(response);
    }
    let next_runtime = recover_pending_runtime(&runtime, &request)?;
    if let Err(e) = state
        .wal
        .append_snapshot_commit(next_runtime.to_wal_state())
    {
        runtime.authority_state = "pending_recovery_commit_failed".to_string();
        runtime.wal_status = "commit_failed".to_string();
        return Err(SnapshotApplyError {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            code: "pending_recovery_commit_failed",
            details: e,
        });
    }

    let response = NeutronRecoverPendingResponse {
        status: "recovered".to_string(),
        recovered_generation: request.expected_pending_generation,
        desired_hash: next_runtime.desired_hash.clone(),
        applied_generation: next_runtime.applied_generation,
        applied_desired_hash: next_runtime.applied_desired_hash.clone(),
        authority_state: next_runtime.authority_state.clone(),
        wal_status: next_runtime.wal_status.clone(),
    };
    *runtime = next_runtime;
    Ok(response)
}

fn wal_state_newer_than_runtime(
    wal: &NeutronWalState,
    runtime: &NeutronRuntimeState,
) -> bool {
    wal.applied_generation > runtime.applied_generation
        || wal.accepted_generation > runtime.accepted_generation
}

fn recover_pending_runtime(
    runtime: &NeutronRuntimeState,
    request: &NeutronRecoverPendingRequest,
) -> Result<NeutronRuntimeState, SnapshotApplyError> {
    validate_pending_recovery_identity(runtime, request)?;
    if runtime.applied_generation == 0 {
        return Err(SnapshotApplyError {
            status: StatusCode::CONFLICT,
            code: "no_applied_snapshot_to_restore",
            details: "cannot recover pending snapshot without an applied baseline".to_string(),
        });
    }
    if runtime.authority_state == "applying" || runtime.authority_state == "accepted" {
        return Err(SnapshotApplyError {
            status: StatusCode::CONFLICT,
            code: "pending_snapshot_still_active",
            details: format!(
                "pending snapshot is still active in state {}",
                runtime.authority_state
            ),
        });
    }

    let mut next_runtime = runtime.clone();
    next_runtime.accepted_generation = runtime.applied_generation;
    next_runtime.pending_generation = None;
    next_runtime.desired_hash = runtime.applied_desired_hash.clone();
    next_runtime.authority_state = "recovered_pending_full_resync_required".to_string();
    next_runtime.wal_status = "pending_recovered_to_last_applied".to_string();
    Ok(next_runtime)
}

fn validate_pending_recovery_identity(
    runtime: &NeutronRuntimeState,
    request: &NeutronRecoverPendingRequest,
) -> Result<(), SnapshotApplyError> {
    let Some(pending_generation) = runtime.pending_generation else {
        return Err(SnapshotApplyError {
            status: StatusCode::CONFLICT,
            code: "no_pending_snapshot",
            details: "no pending generation exists".to_string(),
        });
    };
    if pending_generation != request.expected_pending_generation {
        return Err(SnapshotApplyError {
            status: StatusCode::CONFLICT,
            code: "pending_generation_mismatch",
            details: format!(
                "pending generation {} does not match expected {}",
                pending_generation, request.expected_pending_generation
            ),
        });
    }
    if !hashes_match(&runtime.desired_hash, &request.expected_desired_hash) {
        return Err(SnapshotApplyError {
            status: StatusCode::CONFLICT,
            code: "pending_desired_hash_mismatch",
            details: "pending desired hash does not match expected hash".to_string(),
        });
    }
    Ok(())
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
    info!(
        generation = snapshot.generation,
        desired_hash = ?snapshot.desired_hash,
        snapshot_ports = snapshot.ports.len(),
        "neutron_snapshot_submit_received"
    );
    submit_neutron_snapshot(state, snapshot, ApplyScope::FullHost).await
}

async fn put_neutron_port_snapshot(
    State(state): State<NeutronApiState>,
    Path(port_id): Path<String>,
    Json(snapshot): Json<NeutronSnapshotRequest>,
) -> impl IntoResponse {
    info!(
        generation = snapshot.generation,
        desired_hash = ?snapshot.desired_hash,
        port_id = %port_id,
        snapshot_ports = snapshot.ports.len(),
        "neutron_port_snapshot_submit_received"
    );
    submit_neutron_snapshot(state, snapshot, ApplyScope::SinglePort(port_id)).await
}

#[derive(Debug)]
struct PreparedSnapshotApply {
    _apply_guard: OwnedMutexGuard<()>,
    intent: PendingNeutronIntent,
    transaction: SnapshotApplyTransaction,
    current_ports: BTreeMap<String, ManagedNeutronPort>,
    runtime_before_apply: NeutronRuntimeState,
    lock_wait_ms: u64,
    preflight_ms: u64,
    wal_intent_ms: u64,
}

#[derive(Debug)]
struct SnapshotSubmitDecision {
    response: NeutronSnapshotResponse,
    prepared: Option<PreparedSnapshotApply>,
}

async fn submit_neutron_snapshot(
    state: NeutronApiState,
    snapshot: NeutronSnapshotRequest,
    scope: ApplyScope,
) -> axum::response::Response {
    let generation = snapshot.generation;
    let desired_hash = snapshot.desired_hash.clone();
    let scope_name = apply_scope_name(&scope);
    let scope_port_id = apply_scope_port_id(&scope).map(|value| value.to_string());
    let decision = match accept_neutron_snapshot_submit(&state, &snapshot, &scope).await {
        Ok(decision) => decision,
        Err(error) => {
            return (
                error.status,
                Json(serde_json::json!({
                    "error": error.code,
                    "details": error.details,
                })),
            )
                .into_response();
        }
    };

    let SnapshotSubmitDecision { response, prepared } = decision;
    if let Some(prepared) = prepared {
        let apply_state = state.clone();
        tokio::spawn(async move {
            match apply_neutron_snapshot_for_scope(
                apply_state.clone(),
                snapshot,
                scope,
                prepared,
            )
            .await
            {
                Ok(response) => {
                    info!(
                        generation = response.generation,
                        desired_hash = ?response.desired_hash,
                        status = %response.status,
                        "neutron_snapshot_background_apply_done"
                    );
                }
                Err(error) => {
                    error!(
                        generation,
                        desired_hash = ?desired_hash,
                        scope = scope_name,
                        scope_port_id = ?scope_port_id,
                        code = error.code,
                        details = %error.details,
                        "neutron_snapshot_background_apply_failed"
                    );
                    mark_snapshot_background_error(
                        &apply_state,
                        generation,
                        desired_hash,
                        error.code,
                        error.details,
                    )
                    .await;
                }
            }
        });
    }

    Json(response).into_response()
}

fn pending_snapshot_submit_response(
    runtime: &NeutronRuntimeState,
    snapshot: &NeutronSnapshotRequest,
    requested_hash: &Option<String>,
) -> Result<Option<NeutronSnapshotResponse>, SnapshotApplyError> {
    let Some(pending_generation) = runtime.pending_generation else {
        return Ok(None);
    };
    if !hashes_match(requested_hash, &runtime.desired_hash) {
        return Err(SnapshotApplyError {
            status: StatusCode::CONFLICT,
            code: "snapshot_apply_in_progress",
            details: format!(
                "pending generation {} is still applying",
                pending_generation
            ),
        });
    }
    info!(
        generation = snapshot.generation,
        desired_hash = ?requested_hash,
        pending_generation,
        "neutron_snapshot_submit_deduplicated_pending"
    );
    Ok(Some(neutron_snapshot_response(
        snapshot.generation,
        requested_hash.clone(),
        runtime.accepted_generation,
        runtime.applied_generation,
        "pending",
        Vec::new(),
        Vec::new(),
    )))
}

async fn accept_neutron_snapshot_submit(
    state: &NeutronApiState,
    snapshot: &NeutronSnapshotRequest,
    scope: &ApplyScope,
) -> Result<SnapshotSubmitDecision, SnapshotApplyError> {
    validate_snapshot_preflight(scope, snapshot)?;
    let requested_hash = snapshot.desired_hash.clone();
    if let Some(mut response) = {
        let runtime = state.runtime.read().await;
        pending_snapshot_submit_response(&runtime, snapshot, &requested_hash)?
    } {
        response.active_instances = state.registry.list().await;
        return Ok(SnapshotSubmitDecision {
            response,
            prepared: None,
        });
    }

    let lock_started = Instant::now();
    let apply_guard = state.apply_lock.clone().lock_owned().await;
    let lock_wait_ms = elapsed_ms(lock_started);
    let preflight_started = Instant::now();
    let local_inventory = LocalInterfaceInventory::load(&state.ovs_bridge);
    let runtime_before_apply = state.runtime.read().await.clone();

    if let Some(mut response) =
        pending_snapshot_submit_response(&runtime_before_apply, snapshot, &requested_hash)?
    {
        response.active_instances = state.registry.list().await;
        return Ok(SnapshotSubmitDecision {
            response,
            prepared: None,
        });
    }
    if let Some(mut response) = snapshot_early_response_for_scope(
        scope,
        &runtime_before_apply,
        snapshot,
        &local_inventory,
        &requested_hash,
    )? {
        response.active_instances = state.registry.list().await;
        return Ok(SnapshotSubmitDecision {
            response,
            prepared: None,
        });
    }

    let current_ports = runtime_before_apply.ports.clone();
    let transaction = build_snapshot_apply_transaction(
        &current_ports,
        snapshot,
        &local_inventory,
        scope.clone(),
    )
    .map_err(snapshot_scope_apply_error)?;
    let intent = PendingNeutronIntent {
        kind: "snapshot".to_string(),
        generation: snapshot.generation,
        desired_hash: requested_hash.clone(),
        port_ids: transaction.requested_port_ids.clone(),
        affected_domains: transaction.affected_domains.clone(),
        affected_ports: transaction.affected_ports.clone(),
    };
    let preflight_ms = elapsed_ms(preflight_started);
    let wal_intent_started = Instant::now();
    state
        .wal
        .append_snapshot_intent(
            intent.generation,
            intent.desired_hash.clone(),
            intent.port_ids.clone(),
            intent.affected_domains.clone(),
            intent.affected_ports.clone(),
        )
        .map_err(|details| SnapshotApplyError {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            code: "wal_intent_failed",
            details,
        })?;
    let wal_intent_ms = elapsed_ms(wal_intent_started);

    {
        let mut runtime = state.runtime.write().await;
        runtime.pending_generation = Some(snapshot.generation);
        runtime.desired_hash = requested_hash.clone();
        runtime.authority_state = "applying".to_string();
        runtime.wal_status = "intent_written".to_string();
    }

    let response = neutron_snapshot_response(
        snapshot.generation,
        requested_hash,
        runtime_before_apply.accepted_generation,
        runtime_before_apply.applied_generation,
        "pending",
        Vec::new(),
        Vec::new(),
    );
    Ok(SnapshotSubmitDecision {
        response,
        prepared: Some(PreparedSnapshotApply {
            _apply_guard: apply_guard,
            intent,
            transaction,
            current_ports,
            runtime_before_apply,
            lock_wait_ms,
            preflight_ms,
            wal_intent_ms,
        }),
    })
}

async fn mark_snapshot_background_error(
    state: &NeutronApiState,
    generation: u64,
    desired_hash: Option<String>,
    code: &'static str,
    details: String,
) {
    let mut runtime = state.runtime.write().await;
    if runtime.pending_generation == Some(generation)
        && hashes_match(&runtime.desired_hash, &desired_hash)
    {
        if matches!(
            runtime.authority_state.as_str(),
            "blocked_recovery_required"
                | "wal_recovery_commit_failed"
                | "pending_recovery_commit_failed"
        ) {
            warn!(
                generation,
                desired_hash = ?desired_hash,
                code,
                details = %details,
                authority_state = %runtime.authority_state,
                wal_status = %runtime.wal_status,
                "neutron_snapshot_background_error_preserved_recovery_state"
            );
            return;
        }
        runtime.authority_state = "degraded".to_string();
        runtime.wal_status = format!("background_apply_failed:{}", code);
        warn!(
            generation,
            desired_hash = ?desired_hash,
            code,
            details = %details,
            "neutron_snapshot_runtime_marked_degraded"
        );
    }
}

fn build_blocked_snapshot_runtime(
    previous: &NeutronRuntimeState,
    intent: &PendingNeutronIntent,
    blocked_statuses: BTreeMap<String, NeutronPortStatus>,
    wal_status: &str,
) -> NeutronRuntimeState {
    let mut blocked = previous.clone();
    blocked.pending_generation = Some(intent.generation);
    blocked.desired_hash = intent.desired_hash.clone();
    blocked.authority_state = "blocked_recovery_required".to_string();
    blocked.wal_status = wal_status.to_string();
    blocked.port_statuses.extend(blocked_statuses);
    blocked
}

async fn recover_failed_snapshot_transaction(
    state: &NeutronApiState,
    intent: &PendingNeutronIntent,
    previous: &NeutronRuntimeState,
    reason: &str,
) -> NeutronRuntimeState {
    let affected_ports = affected_ports_for_intent(intent, &previous.ports);
    let mut blocked_statuses = BTreeMap::new();

    for port in affected_ports {
        let committed_before_intent = previous.ports.contains_key(&port.port_id);
        let mut recovery = state
            .recover_intent_port(intent, &port, committed_before_intent)
            .await;
        let recovery_reason = recovery.reason.clone();
        let mut acl_status_present = false;
        for domain in &mut recovery.domains {
            if domain.domain == "acl" {
                acl_status_present = true;
                domain.status = "blocked".to_string();
                domain.reason = Some("snapshot_commit_failed_acl_bypass".to_string());
                domain.effective_action = Some("bypass".to_string());
            }
        }
        if !acl_status_present
            && recovery
                .managed_domains
                .iter()
                .any(|domain| domain == "acl")
        {
            recovery.domains.push(domain_status_with_action(
                "acl",
                "blocked",
                Some("snapshot_commit_failed_acl_bypass".to_string()),
                Some("bypass".to_string()),
            ));
        }
        recovery.status = "blocked".to_string();
        recovery.reason = Some(match recovery_reason {
            Some(details) if !recovery.ok => {
                format!("snapshot_commit_failed_recovery_required:{}", details)
            }
            _ => "snapshot_commit_failed_recovery_required".to_string(),
        });
        recovery.ok = false;

        blocked_statuses.insert(
            port.port_id.clone(),
            port_runtime_status(
                &port.port_id,
                &port.ifname,
                intent.generation,
                intent.desired_hash.clone(),
                recovery.managed_domains,
                recovery.status.as_str(),
                recovery.reason,
                recovery.domains,
            ),
        );
    }

    let mut blocked = build_blocked_snapshot_runtime(
        previous,
        intent,
        blocked_statuses,
        "commit_failed",
    );
    if let Err(error) = state.wal.append_snapshot_commit(blocked.to_wal_state()) {
        blocked.wal_status = "recovery_commit_failed".to_string();
        warn!(
            generation = intent.generation,
            desired_hash = ?intent.desired_hash,
            reason,
            error = %error,
            "failed to commit blocked Neutron snapshot recovery state"
        );
    }
    blocked
}

async fn publish_committed_snapshot_runtime<F, Fut>(
    state: &NeutronApiState,
    next_runtime: NeutronRuntimeState,
    generation: u64,
    post_commit: F,
) where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = Result<(), String>>,
{
    {
        let mut runtime = state.runtime.write().await;
        *runtime = next_runtime;
    }
    if let Err(error) = post_commit().await {
        warn!(
            generation,
            error = %error,
            "post-commit snapshot hook failed after durable commit"
        );
    }
}

async fn apply_neutron_snapshot_for_scope(
    state: NeutronApiState,
    snapshot: NeutronSnapshotRequest,
    scope: ApplyScope,
    prepared: PreparedSnapshotApply,
) -> Result<NeutronSnapshotResponse, SnapshotApplyError> {
    let profile_started = Instant::now();
    let PreparedSnapshotApply {
        _apply_guard,
        intent,
        transaction,
        current_ports,
        runtime_before_apply,
        lock_wait_ms,
        preflight_ms,
        wal_intent_ms,
    } = prepared;
    let scope_name = apply_scope_name(&scope);
    let scope_port_id = apply_scope_port_id(&scope).map(|value| value.to_string());
    info!(
        generation = snapshot.generation,
        desired_hash = ?snapshot.desired_hash,
        scope = scope_name,
        scope_port_id = ?scope_port_id,
        snapshot_ports = snapshot.ports.len(),
        lock_wait_ms,
        "neutron_snapshot_apply_start"
    );
    let requested_hash = snapshot.desired_hash.clone();
    let plan_attach = transaction.plan.attach.len();
    let plan_update = transaction.plan.update.len();
    let plan_detach = transaction.plan.detach.len();
    let plan_ignored = transaction.plan.ignored.len();
    let requested_ports = transaction.requested_port_ids.len();
    let affected_ports = transaction.affected_ports.len();
    let affected_domains = transaction.affected_domains.len();
    info!(
        generation = snapshot.generation,
        desired_hash = ?requested_hash,
        scope = scope_name,
        scope_port_id = ?scope_port_id,
        snapshot_ports = snapshot.ports.len(),
        requested_ports,
        affected_ports,
        affected_domains,
        plan_attach,
        plan_update,
        plan_detach,
        plan_ignored,
        preflight_ms,
        "neutron_snapshot_apply_plan"
    );
    if let Err(e) = fault_injection::check("neutron.snapshot.after_intent").await {
        return Err(SnapshotApplyError {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            code: "fault_injection",
            details: e,
        });
    }

    let runtime_apply_started = Instant::now();
    let outcome = apply_snapshot_runtime_transaction(
        &state,
        snapshot.generation,
        requested_hash.clone(),
        current_ports,
        runtime_before_apply.clone(),
        transaction,
    )
    .await;
    let SnapshotRuntimeApplyOutcome {
        next_runtime,
        previous_applied_generation,
        results,
        has_error,
    } = outcome;
    let runtime_apply_ms = elapsed_ms(runtime_apply_started);

    if let Err(e) = fault_injection::check("neutron.snapshot.before_commit").await {
        let blocked = recover_failed_snapshot_transaction(
            &state,
            &intent,
            &runtime_before_apply,
            "before_commit_failed",
        )
        .await;
        let mut runtime = state.runtime.write().await;
        *runtime = blocked;
        return Err(SnapshotApplyError {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            code: "fault_injection",
            details: e,
        });
    }
    let wal_commit_started = Instant::now();
    if let Err(e) = state
        .wal
        .append_snapshot_commit(next_runtime.to_wal_state())
    {
        let blocked = recover_failed_snapshot_transaction(
            &state,
            &intent,
            &runtime_before_apply,
            "wal_commit_failed",
        )
        .await;
        let mut runtime = state.runtime.write().await;
        *runtime = blocked;
        return Err(SnapshotApplyError {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            code: "wal_commit_failed",
            details: e,
        });
    }
    let wal_commit_ms = elapsed_ms(wal_commit_started);
    publish_committed_snapshot_runtime(&state, next_runtime, snapshot.generation, || {
        fault_injection::check("neutron.snapshot.after_commit")
    })
    .await;

    info!(
        generation = snapshot.generation,
        desired_hash = ?requested_hash,
        scope = scope_name,
        scope_port_id = ?scope_port_id,
        snapshot_ports = snapshot.ports.len(),
        requested_ports,
        affected_ports,
        affected_domains,
        plan_attach,
        plan_update,
        plan_detach,
        plan_ignored,
        result_count = results.len(),
        has_error,
        lock_wait_ms,
        preflight_ms,
        wal_intent_ms,
        runtime_apply_ms,
        wal_commit_ms,
        total_ms = elapsed_ms(profile_started),
        "neutron_snapshot_apply_done"
    );

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

async fn apply_snapshot_runtime_transaction(
    state: &NeutronApiState,
    generation: u64,
    requested_hash: Option<String>,
    current_ports: BTreeMap<String, ManagedNeutronPort>,
    runtime_before_apply: NeutronRuntimeState,
    transaction: SnapshotApplyTransaction,
) -> SnapshotRuntimeApplyOutcome {
    let profile_started = Instant::now();
    let mut next_ports = current_ports;
    let SnapshotApplyTransaction { scope, plan, .. } = transaction;
    let scope_name = apply_scope_name(&scope);
    let scope_port_id = apply_scope_port_id(&scope).map(|value| value.to_string());
    let SnapshotPlan {
        attach,
        update,
        detach,
        ignored,
    } = plan;
    let detach_count = detach.len();
    let update_count = update.len();
    let attach_count = attach.len();
    let ignored_count = ignored.len();
    info!(
        generation,
        desired_hash = ?requested_hash,
        scope = scope_name,
        scope_port_id = ?scope_port_id,
        attach_count,
        update_count,
        detach_count,
        ignored_count,
        "neutron_snapshot_runtime_apply_start"
    );
    let mut next_statuses = port_status_seed_for_scope(&runtime_before_apply, &scope);
    let mut results = ignored;

    for port in detach {
        let port_started = Instant::now();
        let port_id = port.port_id.clone();
        let ifname = port.ifname.clone();
        let purge_started = Instant::now();
        let mut purge_ms = 0;
        if let Err(e) = purge_neutron_acl(state, &port.ifname, &port.port_id).await {
            warn!(
                port_id = %port.port_id,
                ifname = %port.ifname,
                error = %e,
                "failed to purge Neutron ACL before detach"
            );
        } else {
            purge_ms = elapsed_ms(purge_started);
        }
        let detach_started = Instant::now();
        match state.registry.detach(&port.ifname).await {
            Ok(()) => {
                let detach_ms = elapsed_ms(detach_started);
                next_ports.remove(&port.port_id);
                next_statuses.insert(
                    port.port_id.clone(),
                    port_runtime_status(
                        &port.port_id,
                        &port.ifname,
                        generation,
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
                info!(
                    generation,
                    desired_hash = ?requested_hash,
                    port_id = %port_id,
                    ifname = %ifname,
                    action = "detach",
                    status = "ok",
                    purge_ms,
                    detach_ms,
                    total_ms = elapsed_ms(port_started),
                    "neutron_port_apply_profile"
                );
            }
            Err(e) => {
                let detach_ms = elapsed_ms(detach_started);
                next_statuses.insert(
                    port.port_id.clone(),
                    port_runtime_status(
                        &port.port_id,
                        &port.ifname,
                        generation,
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
                info!(
                    generation,
                    desired_hash = ?requested_hash,
                    port_id = %port_id,
                    ifname = %ifname,
                    action = "detach",
                    status = "error",
                    purge_ms,
                    detach_ms,
                    total_ms = elapsed_ms(port_started),
                    "neutron_port_apply_profile"
                );
            }
        }
    }

    for port in update {
        let port_started = Instant::now();
        let managed = managed_port_from_snapshot(&port);
        let previous_managed = next_ports.get(&port.port_id).cloned();
        let previous_status = runtime_before_apply.port_statuses.get(&port.port_id);
        if can_skip_neutron_domain_reconcile(previous_managed.as_ref(), previous_status, &managed) {
            state
                .control_plane
                .mark_neutron_port_authority(
                    &managed.ifname,
                    &managed.port_id,
                    &managed.managed_domains,
                    generation,
                )
                .await;
            let domains = previous_status
                .map(|status| status.domains.clone())
                .filter(|domains| !domains.is_empty())
                .unwrap_or_else(|| domain_statuses_for(&managed.managed_domains, "ready", None));
            next_ports.insert(managed.port_id.clone(), managed.clone());
            next_statuses.insert(
                managed.port_id.clone(),
                port_runtime_status(
                    &managed.port_id,
                    &managed.ifname,
                    generation,
                    requested_hash.clone(),
                    managed.managed_domains.clone(),
                    "ready",
                    None,
                    domains,
                ),
            );
            results.push(NeutronPortApplyResult {
                port_id: managed.port_id,
                ifname: managed.ifname,
                action: "update".to_string(),
                status: "ok".to_string(),
                reason: None,
            });
            info!(
                generation,
                desired_hash = ?requested_hash,
                port_id = %port.port_id,
                ifname = %port.ifname,
                action = "update",
                status = "skipped",
                domain_hashes = ?managed.domain_desired_hashes,
                domain_ms = 0u64,
                total_ms = elapsed_ms(port_started),
                "neutron_port_apply_profile"
            );
            continue;
        }
        let domain_result = reconcile_neutron_domains(state, &port).await;
        let domain_ms = elapsed_ms(port_started);
        if domain_result.ok {
            state
                .control_plane
                .mark_neutron_port_authority(
                    &managed.ifname,
                    &managed.port_id,
                    &managed.managed_domains,
                    generation,
                )
                .await;
            let (port_status, port_reason) = successful_port_status(&domain_result.domains);
            next_ports.insert(managed.port_id.clone(), managed.clone());
            next_statuses.insert(
                managed.port_id.clone(),
                port_runtime_status(
                    &managed.port_id,
                    &managed.ifname,
                    generation,
                    requested_hash.clone(),
                    managed.managed_domains.clone(),
                    &port_status,
                    port_reason,
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
            info!(
                generation,
                desired_hash = ?requested_hash,
                port_id = %port.port_id,
                ifname = %port.ifname,
                action = "update",
                status = "ok",
                domain_ms,
                total_ms = elapsed_ms(port_started),
                "neutron_port_apply_profile"
            );
        } else {
            next_statuses.insert(
                managed.port_id.clone(),
                port_runtime_status(
                    &managed.port_id,
                    &managed.ifname,
                    generation,
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
            info!(
                generation,
                desired_hash = ?requested_hash,
                port_id = %port.port_id,
                ifname = %port.ifname,
                action = "update",
                status = "error",
                domain_ms,
                total_ms = elapsed_ms(port_started),
                "neutron_port_apply_profile"
            );
        }
    }

    for port in attach {
        let port_started = Instant::now();
        let port_id = port.port_id.clone();
        let ifname = port.ifname.clone();
        let attach_started = Instant::now();
        match state.registry.attach(&port.ifname).await {
            Ok(()) => {
                let attach_ms = elapsed_ms(attach_started);
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
                    info!(
                        generation,
                        desired_hash = ?requested_hash,
                        port_id = %port_id,
                        ifname = %ifname,
                        action = "attach",
                        status = "error",
                        attach_ms,
                        total_ms = elapsed_ms(port_started),
                        "neutron_port_apply_profile"
                    );
                    continue;
                }
                let managed = managed_port_from_snapshot(&port);
                let domain_started = Instant::now();
                let domain_result = reconcile_neutron_domains(state, &port).await;
                let domain_ms = elapsed_ms(domain_started);
                if domain_result.ok {
                    state
                        .control_plane
                        .mark_neutron_port_authority(
                            &managed.ifname,
                            &managed.port_id,
                            &managed.managed_domains,
                            generation,
                        )
                        .await;
                    let (port_status, port_reason) = successful_port_status(&domain_result.domains);
                    next_ports.insert(managed.port_id.clone(), managed.clone());
                    next_statuses.insert(
                        managed.port_id.clone(),
                        port_runtime_status(
                            &managed.port_id,
                            &managed.ifname,
                            generation,
                            requested_hash.clone(),
                            managed.managed_domains.clone(),
                            &port_status,
                            port_reason,
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
                    info!(
                        generation,
                        desired_hash = ?requested_hash,
                        port_id = %port.port_id,
                        ifname = %port.ifname,
                        action = "attach",
                        status = "ok",
                        attach_ms,
                        domain_ms,
                        total_ms = elapsed_ms(port_started),
                        "neutron_port_apply_profile"
                    );
                } else {
                    if let Err(purge_err) =
                        purge_neutron_acl(state, &port.ifname, &port.port_id).await
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
                            generation,
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
                    info!(
                        generation,
                        desired_hash = ?requested_hash,
                        port_id = %port.port_id,
                        ifname = %port.ifname,
                        action = "attach",
                        status = "error",
                        attach_ms,
                        domain_ms,
                        total_ms = elapsed_ms(port_started),
                        "neutron_port_apply_profile"
                    );
                }
            }
            Err(e) => {
                let attach_ms = elapsed_ms(attach_started);
                next_statuses.insert(
                    port.port_id.clone(),
                    port_runtime_status(
                        &port.port_id,
                        &port.ifname,
                        generation,
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
                info!(
                    generation,
                    desired_hash = ?requested_hash,
                    port_id = %port_id,
                    ifname = %ifname,
                    action = "attach",
                    status = "error",
                    attach_ms,
                    total_ms = elapsed_ms(port_started),
                    "neutron_port_apply_profile"
                );
            }
        }
    }

    let has_error = results.iter().any(|result| result.status == "error");
    let previous_applied_generation = runtime_before_apply.applied_generation;
    let next_runtime = build_snapshot_commit_runtime(
        &runtime_before_apply,
        generation,
        requested_hash,
        next_ports,
        next_statuses,
        has_error,
    );
    info!(
        generation,
        scope = scope_name,
        scope_port_id = ?scope_port_id,
        attach_count,
        update_count,
        detach_count,
        ignored_count,
        result_count = results.len(),
        has_error,
        total_ms = elapsed_ms(profile_started),
        "neutron_snapshot_runtime_apply_done"
    );
    SnapshotRuntimeApplyOutcome {
        next_runtime,
        previous_applied_generation,
        results,
        has_error,
    }
}

fn hashes_match(left: &Option<String>, right: &Option<String>) -> bool {
    match (left, right) {
        (Some(left), Some(right)) => left == right,
        (None, None) => true,
        _ => false,
    }
}

fn snapshot_schema_supported(schema_version: Option<u32>) -> bool {
    match schema_version {
        None => true,
        Some(version) => {
            version >= NEUTRON_UDS_SCHEMA_VERSION_MIN && version <= NEUTRON_UDS_SCHEMA_VERSION_MAX
        }
    }
}

fn snapshot_scope_apply_error(error: SnapshotScopeError) -> SnapshotApplyError {
    SnapshotApplyError {
        status: StatusCode::BAD_REQUEST,
        code: error.code(),
        details: error.to_string(),
    }
}

fn snapshot_schema_apply_error(schema_version: Option<u32>) -> SnapshotApplyError {
    SnapshotApplyError {
        status: StatusCode::BAD_REQUEST,
        code: "UDS_SCHEMA_MISMATCH",
        details: format!(
            "unsupported schema_version {:?}; supported range is {}-{}",
            schema_version, NEUTRON_UDS_SCHEMA_VERSION_MIN, NEUTRON_UDS_SCHEMA_VERSION_MAX
        ),
    }
}

fn validate_snapshot_preflight(
    scope: &ApplyScope,
    snapshot: &NeutronSnapshotRequest,
) -> Result<(), SnapshotApplyError> {
    if !snapshot_schema_supported(snapshot.schema_version) {
        return Err(snapshot_schema_apply_error(snapshot.schema_version));
    }
    validate_snapshot_scope(scope, snapshot).map_err(snapshot_scope_apply_error)
}

#[allow(dead_code)]
fn snapshot_has_runtime_drift(
    current: &BTreeMap<String, ManagedNeutronPort>,
    snapshot: &NeutronSnapshotRequest,
    inventory: &LocalInterfaceInventory,
) -> bool {
    snapshot_has_runtime_drift_for_scope(current, snapshot, inventory, ApplyScope::FullHost)
}

fn snapshot_has_runtime_drift_for_scope(
    current: &BTreeMap<String, ManagedNeutronPort>,
    snapshot: &NeutronSnapshotRequest,
    inventory: &LocalInterfaceInventory,
    scope: ApplyScope,
) -> bool {
    let plan = build_snapshot_plan_for_scope(current, snapshot, inventory, scope);
    if !plan.attach.is_empty() || !plan.detach.is_empty() {
        return true;
    }
    plan.update.iter().any(|port| {
        current
            .get(&port.port_id)
            .map(|managed| {
                let desired = managed_port_from_snapshot(port);
                managed.ifname != port.ifname
                    || managed.ifindex != port.ifindex
                    || normalize_managed_domains(&managed.managed_domains)
                        != normalize_managed_domains(&port.managed_domains)
                    || managed.domain_desired_hashes != desired.domain_desired_hashes
            })
            .unwrap_or(true)
    })
}

fn snapshot_early_response_for_scope(
    scope: &ApplyScope,
    runtime: &NeutronRuntimeState,
    snapshot: &NeutronSnapshotRequest,
    inventory: &LocalInterfaceInventory,
    requested_hash: &Option<String>,
) -> Result<Option<NeutronSnapshotResponse>, SnapshotApplyError> {
    if snapshot.generation > 0 && snapshot.generation < runtime.applied_generation {
        return Ok(Some(neutron_snapshot_response(
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
        )));
    }

    if !snapshot_generation_fully_applied(runtime, snapshot.generation) {
        return Ok(None);
    }

    if hashes_match(requested_hash, &runtime.applied_desired_hash) {
        if snapshot_has_runtime_drift_for_scope(&runtime.ports, snapshot, inventory, scope.clone())
        {
            return Ok(None);
        }
        return Ok(Some(neutron_snapshot_response(
            snapshot.generation,
            requested_hash.clone(),
            runtime.accepted_generation,
            runtime.applied_generation,
            "noop",
            Vec::new(),
            Vec::new(),
        )));
    }

    if requested_hash.is_some() && runtime.applied_desired_hash.is_some() {
        return Err(SnapshotApplyError {
            status: StatusCode::CONFLICT,
            code: "generation_hash_conflict",
            details: format!(
                "generation {} already applied with a different desired_hash",
                snapshot.generation
            ),
        });
    }

    Ok(None)
}

fn validate_snapshot_scope(
    scope: &ApplyScope,
    snapshot: &NeutronSnapshotRequest,
) -> Result<(), SnapshotScopeError> {
    match scope {
        ApplyScope::FullHost => Ok(()),
        ApplyScope::SinglePort(target_port_id) => {
            if snapshot.ports.len() != 1 {
                return Err(SnapshotScopeError::SinglePortBodyCount {
                    actual: snapshot.ports.len(),
                });
            }
            let actual_port_id = &snapshot.ports[0].port_id;
            if actual_port_id != target_port_id {
                return Err(SnapshotScopeError::SinglePortBodyMismatch {
                    expected: target_port_id.clone(),
                    actual: actual_port_id.clone(),
                });
            }
            Ok(())
        }
    }
}

fn requested_port_ids_for_scope(
    scope: &ApplyScope,
    snapshot: &NeutronSnapshotRequest,
) -> Vec<String> {
    match scope {
        ApplyScope::FullHost => snapshot
            .ports
            .iter()
            .map(|port| port.port_id.clone())
            .collect(),
        ApplyScope::SinglePort(target_port_id) => vec![target_port_id.clone()],
    }
}

fn build_snapshot_transaction_from_plan(
    scope: ApplyScope,
    snapshot: &NeutronSnapshotRequest,
    plan: SnapshotPlan,
) -> Result<SnapshotApplyTransaction, SnapshotScopeError> {
    validate_snapshot_scope(&scope, snapshot)?;
    let affected_ports = affected_ports_for_plan(&plan);
    if let ApplyScope::SinglePort(target_port_id) = &scope {
        for port in &affected_ports {
            if &port.port_id != target_port_id {
                return Err(SnapshotScopeError::ScopeWidened {
                    target: target_port_id.clone(),
                    actual: port.port_id.clone(),
                });
            }
        }
    }
    let requested_port_ids = requested_port_ids_for_scope(&scope, snapshot);
    let affected_domains = affected_domains_for_ports(&affected_ports);
    Ok(SnapshotApplyTransaction {
        scope,
        plan,
        requested_port_ids,
        affected_domains,
        affected_ports,
    })
}

fn build_snapshot_apply_transaction(
    current: &BTreeMap<String, ManagedNeutronPort>,
    snapshot: &NeutronSnapshotRequest,
    inventory: &LocalInterfaceInventory,
    scope: ApplyScope,
) -> Result<SnapshotApplyTransaction, SnapshotScopeError> {
    validate_snapshot_scope(&scope, snapshot)?;
    let plan = build_snapshot_plan_for_scope(current, snapshot, inventory, scope.clone());
    build_snapshot_transaction_from_plan(scope, snapshot, plan)
}

fn port_status_seed_for_scope(
    runtime: &NeutronRuntimeState,
    scope: &ApplyScope,
) -> BTreeMap<String, NeutronPortStatus> {
    match scope {
        ApplyScope::FullHost => BTreeMap::new(),
        ApplyScope::SinglePort(target_port_id) => runtime
            .port_statuses
            .iter()
            .filter(|(port_id, _)| *port_id != target_port_id)
            .map(|(port_id, status)| (port_id.clone(), status.clone()))
            .collect(),
    }
}

fn build_snapshot_commit_runtime(
    previous: &NeutronRuntimeState,
    generation: u64,
    requested_hash: Option<String>,
    next_ports: BTreeMap<String, ManagedNeutronPort>,
    next_statuses: BTreeMap<String, NeutronPortStatus>,
    has_error: bool,
) -> NeutronRuntimeState {
    let mut next_runtime = previous.clone();
    next_runtime.accepted_generation = generation;
    next_runtime.desired_hash = requested_hash.clone();
    next_runtime.ports = next_ports;
    next_runtime.port_statuses = next_statuses;
    next_runtime.wal_status = "commit_written".to_string();
    if has_error {
        next_runtime.pending_generation = Some(generation);
        next_runtime.authority_state = "partial".to_string();
    } else {
        next_runtime.applied_generation = generation;
        next_runtime.applied_desired_hash = requested_hash;
        next_runtime.pending_generation = None;
        next_runtime.authority_state = "ready".to_string();
    }
    next_runtime
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
    domain_status_with_action(domain, status, reason, None)
}

fn domain_status_with_action(
    domain: &str,
    status: &str,
    reason: Option<String>,
    effective_action: Option<String>,
) -> NeutronDomainStatus {
    NeutronDomainStatus {
        domain: domain.to_string(),
        status: status.to_string(),
        reason,
        effective_action,
    }
}

fn acl_domain_status_for(port: &NeutronPortSnapshot) -> NeutronDomainStatus {
    let Some(acl) = &port.acl else {
        return domain_status("acl", "ready", None);
    };
    let status = if acl.status.trim().is_empty() {
        "ready"
    } else {
        acl.status.trim()
    };
    let reason = if acl.reason.trim().is_empty() || acl.reason.eq_ignore_ascii_case("ready") {
        None
    } else {
        Some(acl.reason.clone())
    };
    let effective_action = if acl.effective_action.trim().is_empty() {
        if acl.enabled && status.eq_ignore_ascii_case("ready") {
            "enforce".to_string()
        } else {
            "bypass".to_string()
        }
    } else {
        acl.effective_action.clone()
    };
    domain_status_with_action("acl", status, reason, Some(effective_action))
}

fn successful_port_status(domains: &[NeutronDomainStatus]) -> (String, Option<String>) {
    for status in [
        "error",
        "blocked",
        "degraded",
        "unsupported",
        "not_requested",
    ] {
        if let Some(domain) = domains
            .iter()
            .find(|domain| domain.status.eq_ignore_ascii_case(status))
        {
            return (domain.status.clone(), domain.reason.clone());
        }
    }
    ("ready".to_string(), None)
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

fn invalidate_restarted_acl_runtime(
    runtime: &mut NeutronRuntimeState,
    successfully_claimed_ports: &[ManagedNeutronPort],
) -> bool {
    let mut invalidated = false;
    for port in successfully_claimed_ports {
        if !normalize_managed_domains(&port.managed_domains)
            .iter()
            .any(|domain| domain == "acl")
        {
            continue;
        }

        if !runtime.port_statuses.contains_key(&port.port_id) {
            continue;
        }
        let Some(restored) = runtime.ports.get_mut(&port.port_id) else {
            continue;
        };
        restored.domain_desired_hashes.remove("acl");

        let reason = "acl_restart_replay_requires_resync".to_string();
        let Some(status) = runtime.port_statuses.get_mut(&port.port_id) else {
            continue;
        };
        let mut domains: BTreeMap<String, NeutronDomainStatus> = status
            .domains
            .drain(..)
            .map(|domain| (domain.domain.clone(), domain))
            .collect();
        domains.insert(
            "attach".to_string(),
            domain_status("attach", "ready", None),
        );
        domains.insert(
            "acl".to_string(),
            domain_status_with_action(
                "acl",
                "degraded",
                Some(reason.clone()),
                Some("unchanged".to_string()),
            ),
        );
        status.status = "degraded".to_string();
        status.reason = Some(reason);
        status.domains = domains.into_values().collect();
        invalidated = true;
    }

    if invalidated && runtime.pending_generation.is_none() {
        runtime.authority_state = "runtime_reconcile_requires_full_resync".to_string();
        runtime.wal_status = "runtime_reconciled_acl_resync_required".to_string();
    }
    invalidated
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
                Ok(()) => statuses.push(acl_domain_status_for(port)),
                Err(e) => {
                    let reason = format!("acl_apply_failed:{}", e.details);
                    statuses.push(domain_status_with_action(
                        &domain,
                        "error",
                        Some(reason.clone()),
                        Some(e.effective_action.to_string()),
                    ));
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
    if let Err(e) = state.wal.append_delete_intent(
        port_id.clone(),
        generation,
        affected_domains_for_ports(std::slice::from_ref(&port)),
        port.clone(),
    ) {
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
                bridge: bridge_ports.contains(name).then(|| ovs_bridge.to_string()),
                iface_id: iface_id.clone(),
            };
            if let Some(iface_id) = iface_id {
                inventory.by_iface_id.insert(iface_id, interface.clone());
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
            format!(
                "unsupported_vif_type:{}",
                port.vif_type.as_deref().unwrap_or("")
            ),
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
                    domain_desired_hashes: BTreeMap::new(),
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

fn blocked_unsupported_recovery(domains: &[String]) -> Option<IntentPortRecovery> {
    let unsupported = domains
        .iter()
        .filter(|domain| !matches!(domain.as_str(), "attach" | "acl"))
        .cloned()
        .collect::<Vec<_>>();
    if unsupported.is_empty() {
        return None;
    }

    let reason = format!("unsupported_recovery_domains:{}", unsupported.join(","));
    let statuses = domains
        .iter()
        .map(|domain| {
            let domain_reason = if matches!(domain.as_str(), "attach" | "acl") {
                "blocked_by_unsupported_recovery_domain".to_string()
            } else {
                format!("unsupported_recovery_domain:{}", domain)
            };
            domain_status(domain, "blocked", Some(domain_reason))
        })
        .collect();

    Some(IntentPortRecovery {
        managed_domains: domains.to_vec(),
        domains: statuses,
        status: "blocked".to_string(),
        reason: Some(reason),
        ok: false,
    })
}

fn managed_port_from_snapshot(port: &NeutronPortSnapshot) -> ManagedNeutronPort {
    ManagedNeutronPort {
        port_id: port.port_id.clone(),
        ifname: port.ifname.clone(),
        ifindex: port.ifindex,
        managed_domains: normalize_managed_domains(&port.managed_domains),
        domain_desired_hashes: domain_desired_hashes_from_snapshot(port),
    }
}

fn port_manages_acl(port: &NeutronPortSnapshot) -> bool {
    normalize_managed_domains(&port.managed_domains)
        .iter()
        .any(|domain| domain == "acl")
}

#[derive(Serialize)]
struct AclDesiredHashPayload<'a> {
    schema: &'static str,
    domain: &'static str,
    acl: &'a Option<NeutronAclSnapshot>,
}

fn stable_json_hash<T: Serialize>(payload: &T) -> String {
    let bytes = match serde_json::to_vec(payload) {
        Ok(bytes) => bytes,
        Err(e) => format!("serialization_error:{}", e).into_bytes(),
    };
    let digest = Sha256::digest(bytes);
    format!(
        "sha256:{}",
        digest
            .iter()
            .map(|byte| format!("{:02x}", byte))
            .collect::<Vec<_>>()
            .join("")
    )
}

fn domain_desired_hashes_from_snapshot(port: &NeutronPortSnapshot) -> BTreeMap<String, String> {
    let mut hashes = BTreeMap::new();
    if port_manages_acl(port) {
        hashes.insert(
            "acl".to_string(),
            stable_json_hash(&AclDesiredHashPayload {
                schema: "neutron-acl-port-v1",
                domain: "acl",
                acl: &port.acl,
            }),
        );
    }
    hashes
}

fn neutron_acl_prefix(port_id: &str) -> String {
    format!("neutron:{}:", port_id)
}

fn is_neutron_acl_group(port_id: &str, group_name: &str) -> bool {
    group_name.starts_with(&neutron_acl_prefix(port_id))
}

fn acl_group_name_for_delete(
    group_id: u32,
    group_names_by_id: &BTreeMap<u32, String>,
) -> String {
    if group_id == 0 {
        "any".to_string()
    } else {
        group_names_by_id
            .get(&group_id)
            .cloned()
            .unwrap_or_else(|| format!("id:{}", group_id))
    }
}

fn acl_policy_delete_targets_for_neutron_domain(
    rules: &[aria_core::state::RuleInfo],
    group_names_by_id: &BTreeMap<u32, String>,
) -> Vec<AclPolicyDeleteTarget> {
    rules
        .iter()
        .map(|rule| AclPolicyDeleteTarget {
            src_group: acl_group_name_for_delete(rule.src_group_id, group_names_by_id),
            dst_group: acl_group_name_for_delete(rule.dst_group_id, group_names_by_id),
            proto: rule.proto,
            direction: rule.direction,
        })
        .collect()
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
            return Err(format!(
                "rule {} uses IPv6 CIDR {}; unsupported",
                rule_id, cidr
            ));
        }
    }
    Ok(())
}

fn acl_ports(
    rule: &NeutronAclRuleSnapshot,
    proto: u8,
    rule_id: &str,
) -> Result<Option<String>, String> {
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

fn parse_acl_port_ranges(ports: &str) -> Result<Vec<(u16, u16)>, String> {
    let mut ranges = Vec::new();
    for part in ports.split(',') {
        let value = part.trim();
        if value.is_empty() {
            continue;
        }
        if value.eq_ignore_ascii_case("all") {
            return Ok(Vec::new());
        }
        if value.contains(':') {
            return Err(format!(
                "port action suffix is unsupported in Neutron ACL port merge: {}",
                value
            ));
        }
        if value.contains('-') {
            let mut pieces = value.split('-');
            let start = pieces
                .next()
                .ok_or_else(|| "missing port range start".to_string())?
                .trim()
                .parse::<u16>()
                .map_err(|_| format!("invalid port range start in {}", value))?;
            let end = pieces
                .next()
                .ok_or_else(|| "missing port range end".to_string())?
                .trim()
                .parse::<u16>()
                .map_err(|_| format!("invalid port range end in {}", value))?;
            if pieces.next().is_some() {
                return Err(format!("invalid port range format {}", value));
            }
            if start > end {
                return Err(format!("invalid port range {}-{}", start, end));
            }
            ranges.push((start, end));
        } else {
            let port = value
                .parse::<u16>()
                .map_err(|_| format!("invalid port {}", value))?;
            ranges.push((port, port));
        }
    }
    Ok(ranges)
}

fn serialize_acl_port_ranges(mut ranges: Vec<(u16, u16)>) -> Option<String> {
    if ranges.is_empty() {
        return None;
    }
    ranges.sort();
    let mut merged: Vec<(u16, u16)> = Vec::new();
    for (start, end) in ranges {
        if let Some((_, previous_end)) = merged.last_mut() {
            if start as u32 <= *previous_end as u32 + 1 {
                if end > *previous_end {
                    *previous_end = end;
                }
                continue;
            }
        }
        merged.push((start, end));
    }
    Some(
        merged
            .iter()
            .map(|(start, end)| {
                if start == end {
                    start.to_string()
                } else {
                    format!("{}-{}", start, end)
                }
            })
            .collect::<Vec<_>>()
            .join(","),
    )
}

fn merge_acl_ports(
    existing: Option<String>,
    incoming: Option<String>,
) -> Result<Option<String>, String> {
    let Some(existing) = existing else {
        return Ok(None);
    };
    let Some(incoming) = incoming else {
        return Ok(None);
    };
    let existing = existing.trim();
    let incoming = incoming.trim();
    if existing.is_empty()
        || incoming.is_empty()
        || existing.eq_ignore_ascii_case("all")
        || incoming.eq_ignore_ascii_case("all")
    {
        return Ok(None);
    }
    let mut ranges = parse_acl_port_ranges(existing)?;
    ranges.extend(parse_acl_port_ranges(incoming)?);
    Ok(serialize_acl_port_ranges(ranges))
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
    let mut policies_by_key = BTreeMap::<AclEffectivePolicyKey, AclPolicyPlan>::new();
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
            let key = AclEffectivePolicyKey {
                src_group: src_group.clone(),
                dst_group: dst_group.clone(),
                proto,
                direction,
            };
            if let Some(existing) = policies_by_key.get_mut(&key) {
                if existing.action != action {
                    return Err(format!(
                        "conflicting effective ACL actions src={} dst={} proto={} direction={} existing_action={} new_action={}",
                        key.src_group,
                        key.dst_group,
                        key.proto,
                        key.direction,
                        existing.action,
                        action
                    ));
                }
                existing.ports = merge_acl_ports(existing.ports.take(), ports.clone())?;
                continue;
            }
            policies_by_key.insert(
                key.clone(),
                AclPolicyPlan {
                    src_group: key.src_group,
                    dst_group: key.dst_group,
                    proto,
                    action,
                    direction,
                    ports: ports.clone(),
                },
            );
        }
    }

    Ok(AclApplyPlan {
        groups,
        policies: policies_by_key.into_values().collect(),
    })
}

async fn purge_neutron_acl(
    state: &NeutronApiState,
    ifname: &str,
    port_id: &str,
) -> Result<(), String> {
    let profile_started = Instant::now();
    let list_policies_started = Instant::now();
    let (rules, groups_by_name) = match state.control_plane.list_policies(ifname).await {
        Ok(result) => result,
        Err(e) => return Err(e.to_string()),
    };
    let list_policies_ms = elapsed_ms(list_policies_started);
    let group_names_by_id: BTreeMap<u32, String> = groups_by_name
        .values()
        .map(|group| (group.id, group.name.clone()))
        .collect();

    let policy_delete_targets =
        acl_policy_delete_targets_for_neutron_domain(&rules, &group_names_by_id);

    let mut policy_delete_count = 0usize;
    for target in policy_delete_targets {
        state
            .control_plane
            .delete_policy(
                ifname,
                &target.src_group,
                &target.dst_group,
                target.proto,
                target.direction,
            )
            .await
            .map_err(|e| e.to_string())?;
        policy_delete_count += 1;
    }

    let list_groups_started = Instant::now();
    let groups = state
        .control_plane
        .list_groups(ifname)
        .await
        .map_err(|e| e.to_string())?;
    let list_groups_ms = elapsed_ms(list_groups_started);
    let mut group_delete_count = 0usize;
    for group in groups {
        if is_neutron_acl_group(port_id, &group.name) {
            state
                .control_plane
                .delete_group(ifname, &group.name)
                .await
                .map_err(|e| e.to_string())?;
            group_delete_count += 1;
        }
    }

    info!(
        port_id = %port_id,
        ifname = %ifname,
        policy_delete_count,
        group_delete_count,
        list_policies_ms,
        list_groups_ms,
        total_ms = elapsed_ms(profile_started),
        "neutron_acl_purge_profile"
    );
    Ok(())
}

async fn flush_neutron_acl_conntrack(
    state: &NeutronApiState,
    ifname: &str,
    port_id: &str,
) -> Result<(), String> {
    let flushed = state
        .control_plane
        .flush_conntrack_strict(ifname)
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
) -> Result<(), NeutronAclReconcileError> {
    if !port_manages_acl(port) {
        return Ok(());
    }

    let profile_started = Instant::now();
    let translate_started = Instant::now();
    let plan = match &port.acl {
        Some(acl) => translate_neutron_acl(&port.port_id, acl)
            .map_err(NeutronAclReconcileError::unchanged)?,
        None => AclApplyPlan::default(),
    };
    let translate_ms = elapsed_ms(translate_started);
    let group_count = plan.groups.len();
    let group_cidr_count: usize = plan.groups.iter().map(|group| group.cidrs.len()).sum();
    let policy_count = plan.policies.len();
    let gate_update_mode = acl_gate_update_mode(&plan);
    let disable_ms = if gate_update_mode == AclGateUpdateMode::DisableBeforeReplace {
        let disable_started = Instant::now();
        state
            .control_plane
            .update_config(
                &port.ifname,
                None,
                None,
                Some(false),
                None,
                None,
                None,
                None,
            )
            .await
            .map_err(|e| NeutronAclReconcileError::unchanged(e.to_string()))?;
        let elapsed = elapsed_ms(disable_started);
        fault_injection::check("neutron.acl.after_disable")
            .await
            .map_err(NeutronAclReconcileError::bypass)?;
        elapsed
    } else {
        0
    };
    let group_specs: Vec<OwnedAclGroupSpec> = plan
        .groups
        .iter()
        .map(|group| OwnedAclGroupSpec {
            name: group.name.clone(),
            cidrs: group.cidrs.clone(),
        })
        .collect();
    let policy_specs: Vec<OwnedAclPolicySpec> = plan
        .policies
        .iter()
        .map(|policy| OwnedAclPolicySpec {
            src_group: policy.src_group.clone(),
            dst_group: policy.dst_group.clone(),
            proto: policy.proto,
            action: policy.action,
            direction: policy.direction,
            ports: policy.ports.clone(),
        })
        .collect();

    let replace_started = Instant::now();
    let replace_report = state
        .control_plane
        .replace_owned_acl(
            &port.ifname,
            &neutron_acl_prefix(&port.port_id),
            true,
            &group_specs,
            &policy_specs,
        )
        .await
        .map_err(|e| NeutronAclReconcileError::bypass(e.to_string()))?;
    let replace_ms = elapsed_ms(replace_started);
    fault_injection::check("neutron.acl.after_purge")
        .await
        .map_err(NeutronAclReconcileError::bypass)?;
    if replace_report.group_cidr_add_count > 0 {
        fault_injection::check("neutron.acl.after_group_write")
            .await
            .map_err(NeutronAclReconcileError::bypass)?;
    }
    if replace_report.policy_add_count > 0 {
        fault_injection::check("neutron.acl.after_policy_write")
            .await
            .map_err(NeutronAclReconcileError::bypass)?;
    }

    let effective_reason = if port.acl.is_none() {
        "no_acl"
    } else if plan.policies.is_empty() {
        "empty_policy"
    } else {
        "enforced"
    };
    if plan.policies.is_empty() {
        let flush_started = Instant::now();
        flush_neutron_acl_conntrack(state, &port.ifname, &port.port_id)
            .await
            .map_err(NeutronAclReconcileError::bypass)?;
        let flush_ms = elapsed_ms(flush_started);
        info!(
            port_id = %port.port_id,
            ifname = %port.ifname,
            status = "bypass",
            reason = effective_reason,
            gate_update_mode = gate_update_mode.as_str(),
            group_count,
            group_cidr_count,
            policy_count,
            disable_ms,
            translate_ms,
            replace_ms,
            group_delete_count = replace_report.group_delete_count,
            group_add_count = replace_report.group_add_count,
            group_cidr_add_count = replace_report.group_cidr_add_count,
            group_cidr_delete_count = replace_report.group_cidr_delete_count,
            policy_delete_count = replace_report.policy_delete_count,
            policy_add_count = replace_report.policy_add_count,
            port_set_delete_count = replace_report.port_set_delete_count,
            compact_ms = replace_report.compact_ms,
            flush_ms,
            total_ms = elapsed_ms(profile_started),
            "neutron_acl_apply_profile"
        );
        return Ok(());
    }

    let flush_started = Instant::now();
    flush_neutron_acl_conntrack(state, &port.ifname, &port.port_id)
        .await
        .map_err(NeutronAclReconcileError::bypass)?;
    let flush_ms = elapsed_ms(flush_started);
    fault_injection::check("neutron.acl.before_enable")
        .await
        .map_err(NeutronAclReconcileError::bypass)?;
    let enable_started = Instant::now();
    state
        .control_plane
        .update_config(&port.ifname, None, None, Some(true), None, None, None, None)
        .await
        .map_err(|e| NeutronAclReconcileError::bypass(e.to_string()))?;
    let enable_ms = elapsed_ms(enable_started);
    info!(
        port_id = %port.port_id,
        ifname = %port.ifname,
        status = "enforced",
        gate_update_mode = gate_update_mode.as_str(),
        group_count,
        group_cidr_count,
        policy_count,
        group_delete_count = replace_report.group_delete_count,
        group_add_count = replace_report.group_add_count,
        group_cidr_add_count = replace_report.group_cidr_add_count,
        group_cidr_delete_count = replace_report.group_cidr_delete_count,
        policy_delete_count = replace_report.policy_delete_count,
        policy_add_count = replace_report.policy_add_count,
        port_set_delete_count = replace_report.port_set_delete_count,
        disable_ms,
        translate_ms,
        replace_ms,
        compact_ms = replace_report.compact_ms,
        flush_ms,
        enable_ms,
        total_ms = elapsed_ms(profile_started),
        "neutron_acl_apply_profile"
    );
    if let Err(error) = fault_injection::check("neutron.acl.after_enable_before_commit").await {
        return match state
            .control_plane
            .update_config(
                &port.ifname,
                None,
                None,
                Some(false),
                None,
                None,
                None,
                None,
            )
            .await
        {
            Ok(()) => Err(NeutronAclReconcileError::bypass(error)),
            Err(disable_error) => Err(NeutronAclReconcileError::enforce(format!(
                "{}; acl_disable_compensation_failed:{}",
                error, disable_error
            ))),
        };
    }
    Ok(())
}

#[allow(dead_code)]
fn build_snapshot_plan(
    current: &BTreeMap<String, ManagedNeutronPort>,
    snapshot: &NeutronSnapshotRequest,
    inventory: &LocalInterfaceInventory,
) -> SnapshotPlan {
    build_snapshot_plan_for_scope(current, snapshot, inventory, ApplyScope::FullHost)
}

fn build_snapshot_plan_for_scope(
    current: &BTreeMap<String, ManagedNeutronPort>,
    snapshot: &NeutronSnapshotRequest,
    inventory: &LocalInterfaceInventory,
    scope: ApplyScope,
) -> SnapshotPlan {
    let mut desired = BTreeMap::new();
    let mut ignored = Vec::new();
    let mut scoped_target_seen = false;

    for port in &snapshot.ports {
        if let ApplyScope::SinglePort(target_port_id) = &scope {
            if &port.port_id != target_port_id {
                continue;
            }
            scoped_target_seen = true;
        }

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

    let mut detach = Vec::new();

    if inventory.is_authoritative() {
        match &scope {
            ApplyScope::FullHost => {
                for (port_id, managed) in current {
                    match desired.get(port_id) {
                        Some(port) if managed_binding_matches(managed, port) => {}
                        _ => detach.push(managed.clone()),
                    }
                }
            }
            ApplyScope::SinglePort(target_port_id) if scoped_target_seen => {
                if let Some(managed) = current.get(target_port_id) {
                    match desired.get(target_port_id) {
                        Some(port) if managed_binding_matches(managed, port) => {}
                        _ => detach.push(managed.clone()),
                    }
                }
            }
            ApplyScope::SinglePort(_) => {}
        }
    }

    let mut attach = Vec::new();
    let mut update = Vec::new();
    for (port_id, port) in desired {
        match current.get(&port_id) {
            Some(managed) if managed_binding_matches(managed, &port) => {
                update.push(port);
            }
            _ => attach.push(port),
        }
    }

    SnapshotPlan {
        attach,
        update,
        detach,
        ignored,
    }
}

fn managed_binding_matches(managed: &ManagedNeutronPort, port: &NeutronPortSnapshot) -> bool {
    if managed.ifname != port.ifname {
        return false;
    }
    match (managed.ifindex, port.ifindex) {
        (Some(managed_ifindex), Some(port_ifindex)) => managed_ifindex == port_ifindex,
        _ => true,
    }
}

fn managed_runtime_binding_matches(
    current: &ManagedNeutronPort,
    desired: &ManagedNeutronPort,
) -> bool {
    if current.ifname != desired.ifname {
        return false;
    }
    match (current.ifindex, desired.ifindex) {
        (Some(current_ifindex), Some(desired_ifindex)) => current_ifindex == desired_ifindex,
        _ => true,
    }
}

fn port_status_ready_for_skip(
    status: Option<&NeutronPortStatus>,
    managed_domains: &[String],
) -> bool {
    let Some(status) = status else {
        return false;
    };
    if !status.status.eq_ignore_ascii_case("ready") {
        return false;
    }
    let domain_statuses: BTreeMap<String, String> = status
        .domains
        .iter()
        .map(|domain| (domain.domain.clone(), domain.status.clone()))
        .collect();
    for domain in managed_domains {
        if domain == "attach" {
            continue;
        }
        match domain_statuses.get(domain) {
            Some(domain_status) if domain_status.eq_ignore_ascii_case("ready") => {}
            _ => return false,
        }
    }
    true
}

fn can_skip_neutron_domain_reconcile(
    current: Option<&ManagedNeutronPort>,
    previous_status: Option<&NeutronPortStatus>,
    desired: &ManagedNeutronPort,
) -> bool {
    let Some(current) = current else {
        return false;
    };
    managed_runtime_binding_matches(current, desired)
        && current.managed_domains == desired.managed_domains
        && current.domain_desired_hashes == desired.domain_desired_hashes
        && port_status_ready_for_skip(previous_status, &desired.managed_domains)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ebpf_binary::TraceBackendKind;
    use crate::kernel_drop_manager::KernelDropManager;
    use crate::ssl_manager::SslManager;
    use crate::trace_backend::TraceManager;
    use std::sync::Arc;

    fn managed(port_id: &str, ifname: &str) -> ManagedNeutronPort {
        ManagedNeutronPort {
            port_id: port_id.to_string(),
            ifname: ifname.to_string(),
            ifindex: None,
            managed_domains: Vec::new(),
            domain_desired_hashes: BTreeMap::new(),
        }
    }

    fn managed_with_ifindex(port_id: &str, ifname: &str, ifindex: u32) -> ManagedNeutronPort {
        ManagedNeutronPort {
            ifindex: Some(ifindex),
            ..managed(port_id, ifname)
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

    fn temp_root(name: &str) -> std::path::PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("aria-neutron-{}-{}", name, nanos));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        root
    }

    fn test_neutron_state(root: &std::path::Path) -> NeutronApiState {
        let ebpf_path = root
            .join("libebpf_firewall.so")
            .to_string_lossy()
            .to_string();
        let pin_path = root.join("pin").to_string_lossy().to_string();
        let state_path = root.join("state").to_string_lossy().to_string();
        let ssl_manager = Arc::new(SslManager::new(&ebpf_path, &pin_path));
        let kernel_drop_manager =
            Arc::new(KernelDropManager::new(&ebpf_path, &pin_path, &state_path));
        let trace_manager = Arc::new(TraceManager::new(TraceBackendKind::LegacyMap));
        let control_plane = Arc::new(ControlPlane::new(
            &ebpf_path,
            &pin_path,
            &state_path,
            ssl_manager,
            kernel_drop_manager,
            trace_manager,
        ));
        let registry = Arc::new(TapRegistry::new(
            &ebpf_path,
            &pin_path,
            &state_path,
            "^tap",
            4096,
            control_plane.clone(),
        ));
        NeutronApiState::new(registry, control_plane, "br-int".to_string())
    }

    fn ready_status(port_id: &str, ifname: &str, generation: u64) -> NeutronPortStatus {
        port_runtime_status(
            port_id,
            ifname,
            generation,
            Some(format!("hash-{}", generation)),
            vec!["acl".to_string()],
            "ready",
            None,
            vec![domain_status_with_action(
                "acl",
                "ready",
                None,
                Some("enforce".to_string()),
            )],
        )
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

    async fn response_json_value(
        response: axum::response::Response,
    ) -> (StatusCode, serde_json::Value) {
        let status = response.status();
        let body = axum::body::to_bytes(response.into_body(), NEUTRON_UDS_BODY_MAX_BYTES as usize)
            .await
            .expect("response body should be readable");
        let value = serde_json::from_slice(body.as_ref()).expect("response should be json");
        (status, value)
    }

    fn ready_acl(rules: Vec<NeutronAclRuleSnapshot>) -> NeutronAclSnapshot {
        NeutronAclSnapshot {
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
            rules,
        }
    }

    fn tcp_rule(id: &str, action: &str, dst_port: u16) -> NeutronAclRuleSnapshot {
        NeutronAclRuleSnapshot {
            id: Some(id.to_string()),
            direction: Some("ingress".to_string()),
            priority: 100,
            action: Some(action.to_string()),
            ethertype: Some("IPv4".to_string()),
            protocol: Some("tcp".to_string()),
            src_cidrs: Vec::new(),
            dst_cidrs: Vec::new(),
            src_port_min: None,
            src_port_max: None,
            dst_port_min: Some(dst_port),
            dst_port_max: Some(dst_port),
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
        let local = inventory(vec![iface(
            "tap-kept",
            "kept-port",
            Some(12),
            Some("br-int"),
        )]);
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
    fn neutron_snapshot_plan_reattaches_when_ifindex_changes() {
        let mut current = BTreeMap::new();
        current.insert(
            "vm-port".to_string(),
            managed_with_ifindex("vm-port", "tap-vm", 52),
        );
        let local = inventory(vec![iface("tap-vm", "vm-port", Some(53), Some("br-int"))]);
        let snapshot = NeutronSnapshotRequest {
            schema_version: None,
            generation: 4,
            desired_hash: None,
            host: None,
            ports: vec![port("vm-port", "tap-vm", true)],
        };

        let plan = build_snapshot_plan(&current, &snapshot, &local);

        assert_eq!(
            plan.detach,
            vec![managed_with_ifindex("vm-port", "tap-vm", 52)]
        );
        assert_eq!(plan.attach.len(), 1);
        assert_eq!(plan.attach[0].ifname, "tap-vm");
        assert_eq!(plan.attach[0].ifindex, Some(53));
        assert!(plan.update.is_empty());
        assert!(plan.ignored.is_empty());
    }

    #[test]
    fn neutron_snapshot_plan_detaches_previously_managed_ineligible_port() {
        let mut current = BTreeMap::new();
        current.insert("dhcp-port".to_string(), managed("dhcp-port", "tap-dhcp"));
        let local = inventory(vec![iface(
            "tap-dhcp",
            "dhcp-port",
            Some(14),
            Some("br-int"),
        )]);
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
        assert_eq!(
            plan.ignored[0].reason.as_deref(),
            Some("device_owner network:dhcp")
        );
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
    fn neutron_snapshot_plan_scoped_updates_target_only() {
        let mut current = BTreeMap::new();
        current.insert(
            "target-port".to_string(),
            ManagedNeutronPort {
                managed_domains: vec!["acl".to_string()],
                ..managed("target-port", "tap-target")
            },
        );
        current.insert(
            "other-port".to_string(),
            ManagedNeutronPort {
                managed_domains: vec!["acl".to_string()],
                ..managed("other-port", "tap-other")
            },
        );
        let local = inventory(vec![
            iface("tap-target", "target-port", Some(21), Some("br-int")),
            iface("tap-other", "other-port", Some(22), Some("br-int")),
        ]);
        let snapshot = NeutronSnapshotRequest {
            schema_version: None,
            generation: 8,
            desired_hash: None,
            host: None,
            ports: vec![NeutronPortSnapshot {
                managed_domains: vec!["acl".to_string(), "qos".to_string()],
                ..port("target-port", "tap-target", true)
            }],
        };

        let plan = build_snapshot_plan_for_scope(
            &current,
            &snapshot,
            &local,
            ApplyScope::SinglePort("target-port".to_string()),
        );

        assert!(plan.attach.is_empty());
        assert!(plan.detach.is_empty());
        assert_eq!(plan.update.len(), 1);
        assert_eq!(plan.update[0].port_id, "target-port");
        assert_eq!(
            normalize_managed_domains(&plan.update[0].managed_domains),
            vec!["acl".to_string(), "qos".to_string()]
        );
        assert!(plan.ignored.is_empty());
    }

    #[test]
    fn neutron_snapshot_plan_scoped_attaches_target_without_detaching_unrelated_ports() {
        let mut current = BTreeMap::new();
        current.insert("other-port".to_string(), managed("other-port", "tap-other"));
        let local = inventory(vec![
            iface("tap-target", "target-port", Some(23), Some("br-int")),
            iface("tap-other", "other-port", Some(24), Some("br-int")),
        ]);
        let snapshot = NeutronSnapshotRequest {
            schema_version: None,
            generation: 9,
            desired_hash: None,
            host: None,
            ports: vec![port("target-port", "tap-target", true)],
        };

        let plan = build_snapshot_plan_for_scope(
            &current,
            &snapshot,
            &local,
            ApplyScope::SinglePort("target-port".to_string()),
        );

        assert_eq!(plan.attach.len(), 1);
        assert_eq!(plan.attach[0].port_id, "target-port");
        assert_eq!(plan.attach[0].ifindex, Some(23));
        assert!(plan.update.is_empty());
        assert!(plan.detach.is_empty());
        assert!(plan.ignored.is_empty());
    }

    #[test]
    fn neutron_snapshot_plan_scoped_detaches_changed_target_binding_only() {
        let mut current = BTreeMap::new();
        current.insert("target-port".to_string(), managed("target-port", "tap-old"));
        current.insert("other-port".to_string(), managed("other-port", "tap-other"));
        let local = inventory(vec![
            iface("tap-new", "target-port", Some(25), Some("br-int")),
            iface("tap-other", "other-port", Some(26), Some("br-int")),
        ]);
        let snapshot = NeutronSnapshotRequest {
            schema_version: None,
            generation: 10,
            desired_hash: None,
            host: None,
            ports: vec![port("target-port", "tap-new", true)],
        };

        let plan = build_snapshot_plan_for_scope(
            &current,
            &snapshot,
            &local,
            ApplyScope::SinglePort("target-port".to_string()),
        );

        assert_eq!(plan.detach, vec![managed("target-port", "tap-old")]);
        assert_eq!(plan.attach.len(), 1);
        assert_eq!(plan.attach[0].port_id, "target-port");
        assert_eq!(plan.attach[0].ifname, "tap-new");
        assert!(plan.update.is_empty());
        assert!(plan.ignored.is_empty());
    }

    #[test]
    fn neutron_snapshot_plan_scoped_detaches_ineligible_target_only() {
        let mut current = BTreeMap::new();
        current.insert(
            "target-port".to_string(),
            managed("target-port", "tap-target"),
        );
        current.insert("other-port".to_string(), managed("other-port", "tap-other"));
        let local = inventory(vec![
            iface("tap-target", "target-port", Some(27), Some("br-int")),
            iface("tap-other", "other-port", Some(28), Some("br-int")),
        ]);
        let snapshot = NeutronSnapshotRequest {
            schema_version: None,
            generation: 11,
            desired_hash: None,
            host: None,
            ports: vec![NeutronPortSnapshot {
                disposition: Some("not_applicable_device_owner:network:dhcp".to_string()),
                ..port("target-port", "tap-target", false)
            }],
        };

        let plan = build_snapshot_plan_for_scope(
            &current,
            &snapshot,
            &local,
            ApplyScope::SinglePort("target-port".to_string()),
        );

        assert_eq!(plan.detach, vec![managed("target-port", "tap-target")]);
        assert!(plan.attach.is_empty());
        assert!(plan.update.is_empty());
        assert_eq!(plan.ignored.len(), 1);
        assert_eq!(plan.ignored[0].port_id, "target-port");
        assert_eq!(
            plan.ignored[0].reason.as_deref(),
            Some("not_applicable_device_owner:network:dhcp")
        );
    }

    #[test]
    fn neutron_snapshot_plan_scoped_ignores_non_target_body_without_mutation() {
        let mut current = BTreeMap::new();
        current.insert(
            "target-port".to_string(),
            managed("target-port", "tap-target"),
        );
        current.insert("other-port".to_string(), managed("other-port", "tap-other"));
        let local = inventory(vec![
            iface("tap-target", "target-port", Some(29), Some("br-int")),
            iface("tap-other", "other-port", Some(30), Some("br-int")),
        ]);
        let snapshot = NeutronSnapshotRequest {
            schema_version: None,
            generation: 12,
            desired_hash: None,
            host: None,
            ports: vec![port("other-port", "tap-other", true)],
        };

        let plan = build_snapshot_plan_for_scope(
            &current,
            &snapshot,
            &local,
            ApplyScope::SinglePort("target-port".to_string()),
        );

        assert!(plan.attach.is_empty());
        assert!(plan.update.is_empty());
        assert!(plan.detach.is_empty());
        assert!(plan.ignored.is_empty());
    }

    #[test]
    fn neutron_snapshot_transaction_scoped_records_only_target_intent() {
        let mut current = BTreeMap::new();
        current.insert(
            "target-port".to_string(),
            ManagedNeutronPort {
                managed_domains: vec!["acl".to_string()],
                ..managed("target-port", "tap-target")
            },
        );
        current.insert(
            "other-port".to_string(),
            ManagedNeutronPort {
                managed_domains: vec!["acl".to_string()],
                ..managed("other-port", "tap-other")
            },
        );
        let local = inventory(vec![
            iface("tap-target", "target-port", Some(31), Some("br-int")),
            iface("tap-other", "other-port", Some(32), Some("br-int")),
        ]);
        let snapshot = NeutronSnapshotRequest {
            schema_version: None,
            generation: 13,
            desired_hash: Some("scoped-hash".to_string()),
            host: None,
            ports: vec![NeutronPortSnapshot {
                managed_domains: vec!["acl".to_string()],
                ..port("target-port", "tap-target", true)
            }],
        };

        let transaction = build_snapshot_apply_transaction(
            &current,
            &snapshot,
            &local,
            ApplyScope::SinglePort("target-port".to_string()),
        )
        .expect("scoped transaction should be valid");

        assert_eq!(transaction.requested_port_ids, vec!["target-port"]);
        assert_eq!(
            transaction
                .affected_ports
                .iter()
                .map(|port| port.port_id.as_str())
                .collect::<Vec<_>>(),
            vec!["target-port"]
        );
        assert_eq!(
            transaction.affected_domains,
            vec!["acl".to_string(), "attach".to_string()]
        );
        assert_eq!(transaction.plan.update.len(), 1);
        assert!(transaction.plan.attach.is_empty());
        assert!(transaction.plan.detach.is_empty());
    }

    #[test]
    fn neutron_snapshot_transaction_scoped_rejects_zero_ports_before_wal() {
        let current = BTreeMap::new();
        let local = inventory(Vec::new());
        let snapshot = NeutronSnapshotRequest {
            schema_version: None,
            generation: 14,
            desired_hash: None,
            host: None,
            ports: Vec::new(),
        };

        let error = build_snapshot_apply_transaction(
            &current,
            &snapshot,
            &local,
            ApplyScope::SinglePort("target-port".to_string()),
        )
        .expect_err("empty scoped body must be rejected");

        assert_eq!(error, SnapshotScopeError::SinglePortBodyCount { actual: 0 });
        assert_eq!(error.code(), "PORT_SCOPE_MISMATCH");
    }

    #[test]
    fn neutron_snapshot_transaction_scoped_rejects_multiple_ports_before_wal() {
        let current = BTreeMap::new();
        let local = inventory(Vec::new());
        let snapshot = NeutronSnapshotRequest {
            schema_version: None,
            generation: 15,
            desired_hash: None,
            host: None,
            ports: vec![
                port("target-port", "tap-target", true),
                port("other-port", "tap-other", true),
            ],
        };

        let error = build_snapshot_apply_transaction(
            &current,
            &snapshot,
            &local,
            ApplyScope::SinglePort("target-port".to_string()),
        )
        .expect_err("multi-port scoped body must be rejected");

        assert_eq!(error, SnapshotScopeError::SinglePortBodyCount { actual: 2 });
    }

    #[test]
    fn neutron_snapshot_transaction_scoped_rejects_path_body_mismatch_before_wal() {
        let current = BTreeMap::new();
        let local = inventory(Vec::new());
        let snapshot = NeutronSnapshotRequest {
            schema_version: None,
            generation: 16,
            desired_hash: None,
            host: None,
            ports: vec![port("other-port", "tap-other", true)],
        };

        let error = build_snapshot_apply_transaction(
            &current,
            &snapshot,
            &local,
            ApplyScope::SinglePort("target-port".to_string()),
        )
        .expect_err("path/body mismatch must be rejected");

        assert_eq!(
            error,
            SnapshotScopeError::SinglePortBodyMismatch {
                expected: "target-port".to_string(),
                actual: "other-port".to_string(),
            }
        );
    }

    #[test]
    fn neutron_snapshot_transaction_scoped_rejects_scope_widening_before_wal() {
        let snapshot = NeutronSnapshotRequest {
            schema_version: None,
            generation: 17,
            desired_hash: None,
            host: None,
            ports: vec![port("target-port", "tap-target", true)],
        };
        let plan = SnapshotPlan {
            attach: vec![NeutronPortSnapshot {
                ifindex: Some(33),
                managed_domains: vec!["acl".to_string()],
                ..port("other-port", "tap-other", true)
            }],
            update: Vec::new(),
            detach: Vec::new(),
            ignored: Vec::new(),
        };

        let error = build_snapshot_transaction_from_plan(
            ApplyScope::SinglePort("target-port".to_string()),
            &snapshot,
            plan,
        )
        .expect_err("widened scoped plan must be rejected");

        assert_eq!(
            error,
            SnapshotScopeError::ScopeWidened {
                target: "target-port".to_string(),
                actual: "other-port".to_string(),
            }
        );
    }

    #[test]
    fn neutron_snapshot_transaction_full_host_preserves_existing_wal_intent_shape() {
        let mut current = BTreeMap::new();
        current.insert(
            "removed-port".to_string(),
            ManagedNeutronPort {
                managed_domains: vec!["acl".to_string()],
                ..managed("removed-port", "tap-removed")
            },
        );
        let local = inventory(vec![iface(
            "tap-kept",
            "kept-port",
            Some(34),
            Some("br-int"),
        )]);
        let snapshot = NeutronSnapshotRequest {
            schema_version: None,
            generation: 18,
            desired_hash: None,
            host: None,
            ports: vec![NeutronPortSnapshot {
                managed_domains: vec!["acl".to_string()],
                ..port("kept-port", "tap-kept", true)
            }],
        };

        let transaction =
            build_snapshot_apply_transaction(&current, &snapshot, &local, ApplyScope::FullHost)
                .expect("full-host transaction should be valid");

        assert_eq!(transaction.requested_port_ids, vec!["kept-port"]);
        assert_eq!(
            transaction
                .affected_ports
                .iter()
                .map(|port| port.port_id.as_str())
                .collect::<Vec<_>>(),
            vec!["kept-port", "removed-port"]
        );
        assert_eq!(
            transaction.affected_domains,
            vec!["acl".to_string(), "attach".to_string()]
        );
    }

    #[test]
    fn neutron_snapshot_transaction_scoped_success_preserves_unrelated_statuses() {
        let mut previous_ports = BTreeMap::new();
        previous_ports.insert(
            "target-port".to_string(),
            ManagedNeutronPort {
                managed_domains: vec!["acl".to_string()],
                ..managed("target-port", "tap-target")
            },
        );
        previous_ports.insert(
            "other-port".to_string(),
            ManagedNeutronPort {
                managed_domains: vec!["acl".to_string()],
                ..managed("other-port", "tap-other")
            },
        );
        let mut previous_statuses = BTreeMap::new();
        previous_statuses.insert(
            "target-port".to_string(),
            ready_status("target-port", "tap-target", 20),
        );
        previous_statuses.insert(
            "other-port".to_string(),
            ready_status("other-port", "tap-other", 20),
        );
        let previous = NeutronRuntimeState {
            accepted_generation: 20,
            applied_generation: 20,
            applied_desired_hash: Some("hash-20".to_string()),
            authority_state: "ready".to_string(),
            ports: previous_ports.clone(),
            port_statuses: previous_statuses,
            ..Default::default()
        };
        let mut next_statuses =
            port_status_seed_for_scope(&previous, &ApplyScope::SinglePort("target-port".into()));
        next_statuses.insert(
            "target-port".to_string(),
            port_runtime_status(
                "target-port",
                "tap-target",
                21,
                Some("hash-21".to_string()),
                vec!["acl".to_string()],
                "ready",
                None,
                vec![domain_status_with_action(
                    "acl",
                    "ready",
                    None,
                    Some("enforce".to_string()),
                )],
            ),
        );

        let next = build_snapshot_commit_runtime(
            &previous,
            21,
            Some("hash-21".to_string()),
            previous_ports,
            next_statuses,
            false,
        );

        assert_eq!(next.accepted_generation, 21);
        assert_eq!(next.applied_generation, 21);
        assert_eq!(next.pending_generation, None);
        assert_eq!(next.authority_state, "ready");
        assert_eq!(
            next.port_statuses
                .get("target-port")
                .map(|status| status.generation),
            Some(21)
        );
        assert_eq!(
            next.port_statuses
                .get("other-port")
                .map(|status| (status.generation, status.desired_hash.clone())),
            Some((20, Some("hash-20".to_string())))
        );
    }

    #[test]
    fn neutron_snapshot_transaction_scoped_failure_keeps_pending_generation() {
        let previous = NeutronRuntimeState {
            accepted_generation: 30,
            applied_generation: 30,
            applied_desired_hash: Some("hash-30".to_string()),
            authority_state: "ready".to_string(),
            ..Default::default()
        };

        let next = build_snapshot_commit_runtime(
            &previous,
            31,
            Some("hash-31".to_string()),
            BTreeMap::new(),
            BTreeMap::new(),
            true,
        );

        assert_eq!(next.accepted_generation, 31);
        assert_eq!(next.applied_generation, 30);
        assert_eq!(next.pending_generation, Some(31));
        assert_eq!(next.desired_hash, Some("hash-31".to_string()));
        assert_eq!(next.applied_desired_hash, Some("hash-30".to_string()));
        assert_eq!(next.authority_state, "partial");
    }

    #[tokio::test]
    async fn neutron_snapshot_transaction_runtime_scoped_error_uses_shared_apply_body() {
        let root = temp_root("runtime-scoped");
        let state = test_neutron_state(&root);
        let mut current_ports = BTreeMap::new();
        current_ports.insert(
            "other-port".to_string(),
            ManagedNeutronPort {
                managed_domains: vec!["acl".to_string()],
                ..managed("other-port", "tap-other")
            },
        );
        let mut previous_statuses = BTreeMap::new();
        previous_statuses.insert(
            "other-port".to_string(),
            ready_status("other-port", "tap-other", 40),
        );
        let previous = NeutronRuntimeState {
            accepted_generation: 40,
            applied_generation: 40,
            applied_desired_hash: Some("hash-40".to_string()),
            authority_state: "ready".to_string(),
            ports: current_ports.clone(),
            port_statuses: previous_statuses,
            ..Default::default()
        };
        let snapshot = NeutronSnapshotRequest {
            schema_version: None,
            generation: 41,
            desired_hash: Some("hash-41".to_string()),
            host: None,
            ports: vec![port("target-port", "tap-target", true)],
        };
        let plan = SnapshotPlan {
            attach: Vec::new(),
            update: Vec::new(),
            detach: Vec::new(),
            ignored: vec![NeutronPortApplyResult {
                port_id: "target-port".to_string(),
                ifname: "tap-target".to_string(),
                action: "update".to_string(),
                status: "error".to_string(),
                reason: Some("tap_missing".to_string()),
            }],
        };
        let transaction = build_snapshot_transaction_from_plan(
            ApplyScope::SinglePort("target-port".to_string()),
            &snapshot,
            plan,
        )
        .expect("scoped transaction should stay within target port");

        let outcome = apply_snapshot_runtime_transaction(
            &state,
            41,
            Some("hash-41".to_string()),
            current_ports,
            previous,
            transaction,
        )
        .await;

        assert!(outcome.has_error);
        assert_eq!(outcome.previous_applied_generation, 40);
        assert_eq!(outcome.results.len(), 1);
        assert_eq!(outcome.results[0].port_id, "target-port");
        assert_eq!(outcome.next_runtime.accepted_generation, 41);
        assert_eq!(outcome.next_runtime.applied_generation, 40);
        assert_eq!(outcome.next_runtime.pending_generation, Some(41));
        assert_eq!(outcome.next_runtime.authority_state, "partial");
        assert_eq!(
            outcome
                .next_runtime
                .port_statuses
                .get("other-port")
                .map(|status| (status.generation, status.desired_hash.clone())),
            Some((40, Some("hash-40".to_string())))
        );

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn neutron_snapshot_preflight_scoped_rejects_mismatch_before_idempotency() {
        let snapshot = NeutronSnapshotRequest {
            schema_version: None,
            generation: 50,
            desired_hash: Some("hash-50".to_string()),
            host: None,
            ports: vec![port("other-port", "tap-other", true)],
        };

        let error = validate_snapshot_preflight(
            &ApplyScope::SinglePort("target-port".to_string()),
            &snapshot,
        )
        .expect_err("scoped path/body mismatch must fail preflight");

        assert_eq!(error.status, axum::http::StatusCode::BAD_REQUEST);
        assert_eq!(error.code, "PORT_SCOPE_MISMATCH");
        assert!(error.details.contains("expected target-port"));
    }

    #[test]
    fn neutron_snapshot_preflight_schema_error_wins_before_scope_error() {
        let snapshot = NeutronSnapshotRequest {
            schema_version: Some(NEUTRON_UDS_SCHEMA_VERSION_MAX + 1),
            generation: 51,
            desired_hash: Some("hash-51".to_string()),
            host: None,
            ports: Vec::new(),
        };

        let error = validate_snapshot_preflight(
            &ApplyScope::SinglePort("target-port".to_string()),
            &snapshot,
        )
        .expect_err("unsupported schema should fail first");

        assert_eq!(error.status, axum::http::StatusCode::BAD_REQUEST);
        assert_eq!(error.code, "UDS_SCHEMA_MISMATCH");
    }

    #[test]
    fn neutron_snapshot_early_response_scoped_stale_generation() {
        let runtime = NeutronRuntimeState {
            accepted_generation: 60,
            applied_generation: 60,
            applied_desired_hash: Some("hash-60".to_string()),
            authority_state: "ready".to_string(),
            ..Default::default()
        };
        let local = inventory(Vec::new());
        let snapshot = NeutronSnapshotRequest {
            schema_version: None,
            generation: 59,
            desired_hash: Some("hash-59".to_string()),
            host: None,
            ports: vec![port("target-port", "tap-target", true)],
        };

        let response = snapshot_early_response_for_scope(
            &ApplyScope::SinglePort("target-port".to_string()),
            &runtime,
            &snapshot,
            &local,
            &snapshot.desired_hash,
        )
        .expect("stale generation should classify, not error")
        .expect("stale generation should return an early response");

        assert_eq!(response.status, "stale");
        assert_eq!(response.applied_generation, 60);
        assert_eq!(
            response.results[0].reason.as_deref(),
            Some("stale_generation")
        );
    }

    #[test]
    fn neutron_snapshot_early_response_scoped_noop_ignores_unrelated_host_drift() {
        let mut ports = BTreeMap::new();
        ports.insert(
            "target-port".to_string(),
            managed_with_ifindex("target-port", "tap-target", 61),
        );
        ports.insert(
            "other-port".to_string(),
            managed_with_ifindex("other-port", "tap-other", 62),
        );
        let runtime = NeutronRuntimeState {
            accepted_generation: 61,
            applied_generation: 61,
            applied_desired_hash: Some("hash-61".to_string()),
            authority_state: "ready".to_string(),
            ports,
            ..Default::default()
        };
        let local = inventory(vec![iface(
            "tap-target",
            "target-port",
            Some(61),
            Some("br-int"),
        )]);
        let snapshot = NeutronSnapshotRequest {
            schema_version: None,
            generation: 61,
            desired_hash: Some("hash-61".to_string()),
            host: None,
            ports: vec![port("target-port", "tap-target", true)],
        };

        let full_host_response = snapshot_early_response_for_scope(
            &ApplyScope::FullHost,
            &runtime,
            &snapshot,
            &local,
            &snapshot.desired_hash,
        )
        .expect("full-host idempotency should not error");
        let scoped_response = snapshot_early_response_for_scope(
            &ApplyScope::SinglePort("target-port".to_string()),
            &runtime,
            &snapshot,
            &local,
            &snapshot.desired_hash,
        )
        .expect("scoped idempotency should not error")
        .expect("scoped target has no drift");

        assert!(full_host_response.is_none());
        assert_eq!(scoped_response.status, "noop");
        assert_eq!(scoped_response.applied_generation, 61);
    }

    #[test]
    fn neutron_snapshot_early_response_scoped_hash_conflict() {
        let runtime = NeutronRuntimeState {
            accepted_generation: 70,
            applied_generation: 70,
            applied_desired_hash: Some("hash-old".to_string()),
            authority_state: "ready".to_string(),
            ..Default::default()
        };
        let local = inventory(Vec::new());
        let snapshot = NeutronSnapshotRequest {
            schema_version: None,
            generation: 70,
            desired_hash: Some("hash-new".to_string()),
            host: None,
            ports: vec![port("target-port", "tap-target", true)],
        };

        let error = snapshot_early_response_for_scope(
            &ApplyScope::SinglePort("target-port".to_string()),
            &runtime,
            &snapshot,
            &local,
            &snapshot.desired_hash,
        )
        .expect_err("same generation with a different hash must conflict");

        assert_eq!(error.status, axum::http::StatusCode::CONFLICT);
        assert_eq!(error.code, "generation_hash_conflict");
    }

    #[tokio::test]
    async fn neutron_snapshot_port_route_rejects_path_body_mismatch() {
        let root = temp_root("port-route-mismatch");
        let state = test_neutron_state(&root);
        let snapshot = NeutronSnapshotRequest {
            schema_version: None,
            generation: 80,
            desired_hash: Some("hash-80".to_string()),
            host: None,
            ports: vec![port("other-port", "tap-other", true)],
        };

        let response = put_neutron_port_snapshot(
            State(state),
            Path("target-port".to_string()),
            Json(snapshot),
        )
        .await
        .into_response();
        let (status, body) = response_json_value(response).await;

        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(
            body.get("error").and_then(|value| value.as_str()),
            Some("PORT_SCOPE_MISMATCH")
        );
        assert!(body
            .get("details")
            .and_then(|value| value.as_str())
            .map(|details| details.contains("expected target-port"))
            .unwrap_or(false));
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn neutron_snapshot_port_route_returns_stale_generation() {
        let root = temp_root("port-route-stale");
        let state = test_neutron_state(&root);
        {
            let mut runtime = state.runtime.write().await;
            runtime.accepted_generation = 90;
            runtime.applied_generation = 90;
            runtime.applied_desired_hash = Some("hash-90".to_string());
            runtime.authority_state = "ready".to_string();
        }
        let snapshot = NeutronSnapshotRequest {
            schema_version: None,
            generation: 89,
            desired_hash: Some("hash-89".to_string()),
            host: None,
            ports: vec![port("target-port", "tap-target", true)],
        };

        let response = put_neutron_port_snapshot(
            State(state),
            Path("target-port".to_string()),
            Json(snapshot),
        )
        .await
        .into_response();
        let (status, body) = response_json_value(response).await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            body.get("status").and_then(|value| value.as_str()),
            Some("stale")
        );
        assert_eq!(
            body.get("applied_generation")
                .and_then(|value| value.as_u64()),
            Some(90)
        );
        assert_eq!(
            body.pointer("/results/0/reason")
                .and_then(|value| value.as_str()),
            Some("stale_generation")
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn neutron_snapshot_port_route_returns_hash_conflict() {
        let root = temp_root("port-route-conflict");
        let state = test_neutron_state(&root);
        {
            let mut runtime = state.runtime.write().await;
            runtime.accepted_generation = 100;
            runtime.applied_generation = 100;
            runtime.applied_desired_hash = Some("hash-old".to_string());
            runtime.authority_state = "ready".to_string();
        }
        let snapshot = NeutronSnapshotRequest {
            schema_version: None,
            generation: 100,
            desired_hash: Some("hash-new".to_string()),
            host: None,
            ports: vec![port("target-port", "tap-target", true)],
        };

        let response = put_neutron_port_snapshot(
            State(state),
            Path("target-port".to_string()),
            Json(snapshot),
        )
        .await
        .into_response();
        let (status, body) = response_json_value(response).await;

        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(
            body.get("error").and_then(|value| value.as_str()),
            Some("generation_hash_conflict")
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn neutron_snapshot_submit_returns_pending_for_same_hash_inflight() {
        let root = temp_root("submit-pending-same-hash");
        let state = test_neutron_state(&root);
        {
            let mut runtime = state.runtime.write().await;
            runtime.accepted_generation = 110;
            runtime.applied_generation = 109;
            runtime.pending_generation = Some(110);
            runtime.desired_hash = Some("hash-110".to_string());
            runtime.applied_desired_hash = Some("hash-109".to_string());
            runtime.authority_state = "applying".to_string();
        }
        let snapshot = NeutronSnapshotRequest {
            schema_version: None,
            generation: 111,
            desired_hash: Some("hash-110".to_string()),
            host: None,
            ports: vec![port("target-port", "tap-target", true)],
        };

        let decision = accept_neutron_snapshot_submit(&state, &snapshot, &ApplyScope::FullHost)
            .await
            .expect("same hash pending should deduplicate");

        assert!(decision.prepared.is_none());
        assert_eq!(decision.response.status, "pending");
        assert_eq!(decision.response.accepted_generation, 110);
        assert_eq!(decision.response.applied_generation, 109);
        let runtime = state.runtime.read().await;
        assert_eq!(runtime.pending_generation, Some(110));
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn neutron_snapshot_submit_rejects_different_hash_inflight() {
        let root = temp_root("submit-pending-different-hash");
        let state = test_neutron_state(&root);
        {
            let mut runtime = state.runtime.write().await;
            runtime.accepted_generation = 120;
            runtime.applied_generation = 119;
            runtime.pending_generation = Some(120);
            runtime.desired_hash = Some("hash-120".to_string());
            runtime.applied_desired_hash = Some("hash-119".to_string());
            runtime.authority_state = "applying".to_string();
        }
        let snapshot = NeutronSnapshotRequest {
            schema_version: None,
            generation: 121,
            desired_hash: Some("hash-121".to_string()),
            host: None,
            ports: vec![port("target-port", "tap-target", true)],
        };

        let error = accept_neutron_snapshot_submit(&state, &snapshot, &ApplyScope::FullHost)
            .await
            .expect_err("different pending hash should be rejected");

        assert_eq!(error.status, StatusCode::CONFLICT);
        assert_eq!(error.code, "snapshot_apply_in_progress");
        let runtime = state.runtime.read().await;
        assert_eq!(runtime.pending_generation, Some(120));
        assert_eq!(runtime.desired_hash.as_deref(), Some("hash-120"));
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn neutron_snapshot_submit_persists_intent_before_pending_response() {
        let root = temp_root("submit-pending-durable");
        let state = test_neutron_state(&root);
        let snapshot = NeutronSnapshotRequest {
            schema_version: None,
            generation: 130,
            desired_hash: Some("hash-130".to_string()),
            host: None,
            ports: vec![port("target-port", "tap-target", true)],
        };

        let decision = accept_neutron_snapshot_submit(&state, &snapshot, &ApplyScope::FullHost)
            .await
            .expect("new snapshot intent should become durable pending");

        assert!(decision.prepared.is_some());
        assert_eq!(decision.response.status, "pending");
        assert_eq!(decision.response.accepted_generation, 0);
        assert_eq!(decision.response.applied_generation, 0);
        let runtime = state.runtime.read().await;
        assert_eq!(runtime.accepted_generation, 0);
        assert_eq!(runtime.pending_generation, Some(130));
        assert_eq!(runtime.authority_state, "applying");
        assert_eq!(runtime.wal_status, "intent_written");
        drop(runtime);

        let replay = state.wal.replay();
        assert_eq!(replay.state.accepted_generation, 0);
        assert_eq!(replay.state.pending_generation, Some(130));
        assert_eq!(
            replay
                .pending_intent
                .as_ref()
                .map(|intent| intent.generation),
            Some(130)
        );
        assert_eq!(
            replay
                .pending_intent
                .as_ref()
                .and_then(|intent| intent.desired_hash.as_deref()),
            Some("hash-130")
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn neutron_snapshot_submit_wal_intent_failure_keeps_runtime_unaccepted() {
        let root = temp_root("submit-intent-failure");
        let invalid_state_path = root.join("not-a-directory");
        std::fs::write(&invalid_state_path, b"regular file").unwrap();
        let mut state = test_neutron_state(&root);
        state.wal = Arc::new(NeutronWal::new(&invalid_state_path));
        let snapshot = NeutronSnapshotRequest {
            schema_version: None,
            generation: 131,
            desired_hash: Some("hash-131".to_string()),
            host: None,
            ports: vec![port("target-port", "tap-target", true)],
        };

        let error = accept_neutron_snapshot_submit(&state, &snapshot, &ApplyScope::FullHost)
            .await
            .expect_err("failed WAL intent must reject snapshot admission");

        assert_eq!(error.status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(error.code, "wal_intent_failed");
        let runtime = state.runtime.read().await;
        assert_eq!(runtime.accepted_generation, 0);
        assert_eq!(runtime.applied_generation, 0);
        assert_eq!(runtime.pending_generation, None);
        assert_eq!(runtime.authority_state, "idle");
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn neutron_snapshot_commit_failure_builds_blocked_bypass_runtime() {
        let mut ports = BTreeMap::new();
        ports.insert(
            "port-1".to_string(),
            ManagedNeutronPort {
                managed_domains: vec!["acl".to_string()],
                ..managed("port-1", "tap-port-1")
            },
        );
        let previous = NeutronRuntimeState {
            accepted_generation: 40,
            applied_generation: 40,
            applied_desired_hash: Some("hash-40".to_string()),
            authority_state: "ready".to_string(),
            ports,
            ..NeutronRuntimeState::default()
        };
        let intent = PendingNeutronIntent {
            kind: "snapshot".to_string(),
            generation: 41,
            desired_hash: Some("hash-41".to_string()),
            port_ids: vec!["port-1".to_string()],
            affected_domains: vec!["acl".to_string(), "attach".to_string()],
            affected_ports: vec![managed("port-1", "tap-port-1")],
        };
        let mut blocked_statuses = BTreeMap::new();
        blocked_statuses.insert(
            "port-1".to_string(),
            port_runtime_status(
                "port-1",
                "tap-port-1",
                41,
                Some("hash-41".to_string()),
                vec!["acl".to_string()],
                "blocked",
                Some("wal_commit_failed".to_string()),
                vec![domain_status_with_action(
                    "acl",
                    "blocked",
                    Some("wal_commit_failed".to_string()),
                    Some("bypass".to_string()),
                )],
            ),
        );

        let blocked = build_blocked_snapshot_runtime(
            &previous,
            &intent,
            blocked_statuses,
            "commit_failed",
        );

        assert_eq!(blocked.accepted_generation, 40);
        assert_eq!(blocked.applied_generation, 40);
        assert_eq!(blocked.pending_generation, Some(41));
        assert_eq!(blocked.desired_hash.as_deref(), Some("hash-41"));
        assert_eq!(blocked.authority_state, "blocked_recovery_required");
        assert_eq!(blocked.wal_status, "commit_failed");
        assert_eq!(blocked.ports, previous.ports);
        let acl = &blocked.port_statuses["port-1"].domains[0];
        assert_eq!(acl.status, "blocked");
        assert_eq!(acl.effective_action.as_deref(), Some("bypass"));
    }

    #[tokio::test]
    async fn neutron_snapshot_background_error_preserves_blocked_recovery() {
        let root = temp_root("background-error-blocked");
        let state = test_neutron_state(&root);
        {
            let mut runtime = state.runtime.write().await;
            runtime.accepted_generation = 40;
            runtime.applied_generation = 40;
            runtime.pending_generation = Some(41);
            runtime.desired_hash = Some("hash-41".to_string());
            runtime.authority_state = "blocked_recovery_required".to_string();
            runtime.wal_status = "recovery_commit_failed".to_string();
        }

        mark_snapshot_background_error(
            &state,
            41,
            Some("hash-41".to_string()),
            "wal_commit_failed",
            "commit failed".to_string(),
        )
        .await;

        let runtime = state.runtime.read().await;
        assert_eq!(runtime.authority_state, "blocked_recovery_required");
        assert_eq!(runtime.wal_status, "recovery_commit_failed");
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn neutron_snapshot_post_commit_error_keeps_durable_runtime() {
        let root = temp_root("post-commit-final");
        let state = test_neutron_state(&root);
        let committed = NeutronRuntimeState {
            accepted_generation: 501,
            applied_generation: 501,
            pending_generation: None,
            desired_hash: Some("hash-501".to_string()),
            applied_desired_hash: Some("hash-501".to_string()),
            authority_state: "ready".to_string(),
            wal_status: "commit_written".to_string(),
            ..NeutronRuntimeState::default()
        };
        state
            .wal
            .append_snapshot_commit(committed.to_wal_state())
            .expect("commit should be durable before the post-commit hook");

        publish_committed_snapshot_runtime(&state, committed, 501, || async {
            Err("after_commit_return_error".to_string())
        })
        .await;

        let runtime = state.runtime.read().await;
        assert_eq!(runtime.accepted_generation, 501);
        assert_eq!(runtime.applied_generation, 501);
        assert_eq!(runtime.pending_generation, None);
        assert_eq!(runtime.authority_state, "ready");
        drop(runtime);
        assert_eq!(state.wal.replay().state.applied_generation, 501);
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn neutron_snapshot_pending_recovery_keeps_newer_wal_commit() {
        let root = temp_root("pending-newer-wal-commit");
        let state = test_neutron_state(&root);
        {
            let mut runtime = state.runtime.write().await;
            runtime.accepted_generation = 500;
            runtime.applied_generation = 500;
            runtime.pending_generation = Some(501);
            runtime.desired_hash = Some("hash-501".to_string());
            runtime.applied_desired_hash = Some("hash-500".to_string());
            runtime.authority_state = "applying".to_string();
            runtime.wal_status = "intent_written".to_string();
        }
        let committed = NeutronRuntimeState {
            accepted_generation: 501,
            applied_generation: 501,
            pending_generation: None,
            desired_hash: Some("hash-501".to_string()),
            applied_desired_hash: Some("hash-501".to_string()),
            authority_state: "ready".to_string(),
            ..NeutronRuntimeState::default()
        };
        state
            .wal
            .append_snapshot_commit(committed.to_wal_state())
            .expect("newer commit should be durable");

        let response = recover_pending_snapshot(
            state.clone(),
            NeutronRecoverPendingRequest {
                expected_pending_generation: 501,
                expected_desired_hash: Some("hash-501".to_string()),
                mode: None,
            },
        )
        .await
        .expect("durable commit should win over stale pending RAM");

        assert_eq!(response.status, "already_committed");
        assert_eq!(response.applied_generation, 501);
        assert_eq!(response.applied_desired_hash.as_deref(), Some("hash-501"));
        let runtime = state.runtime.read().await;
        assert_eq!(runtime.accepted_generation, 501);
        assert_eq!(runtime.applied_generation, 501);
        assert_eq!(runtime.pending_generation, None);
        assert_eq!(runtime.authority_state, "ready");
        drop(runtime);
        assert_eq!(state.wal.replay().state.applied_generation, 501);
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn neutron_pending_recovery_rejects_mismatch_with_newer_wal_commit() {
        let root = temp_root("pending-newer-wal-mismatch");
        let state = test_neutron_state(&root);
        {
            let mut runtime = state.runtime.write().await;
            runtime.accepted_generation = 500;
            runtime.applied_generation = 500;
            runtime.pending_generation = Some(501);
            runtime.desired_hash = Some("hash-501".to_string());
            runtime.applied_desired_hash = Some("hash-500".to_string());
            runtime.authority_state = "applying".to_string();
        }
        state
            .wal
            .append_snapshot_commit(
                NeutronRuntimeState {
                    accepted_generation: 501,
                    applied_generation: 501,
                    desired_hash: Some("hash-501".to_string()),
                    applied_desired_hash: Some("hash-501".to_string()),
                    authority_state: "ready".to_string(),
                    ..NeutronRuntimeState::default()
                }
                .to_wal_state(),
            )
            .expect("newer commit should be durable");

        let error = recover_pending_snapshot(
            state.clone(),
            NeutronRecoverPendingRequest {
                expected_pending_generation: 501,
                expected_desired_hash: Some("wrong-hash".to_string()),
                mode: None,
            },
        )
        .await
        .expect_err("mismatched recovery request must not bypass validation");

        assert_eq!(error.code, "pending_desired_hash_mismatch");
        let runtime = state.runtime.read().await;
        assert_eq!(runtime.applied_generation, 500);
        assert_eq!(runtime.pending_generation, Some(501));
        drop(runtime);
        assert_eq!(state.wal.replay().state.applied_generation, 501);
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn neutron_pending_recovery_writes_wal_and_unblocks_full_resync() {
        let root = temp_root("pending-recovery");
        let state = test_neutron_state(&root);
        {
            let mut runtime = state.runtime.write().await;
            runtime.accepted_generation = 380;
            runtime.applied_generation = 379;
            runtime.pending_generation = Some(380);
            runtime.desired_hash = Some("hash-380".to_string());
            runtime.applied_desired_hash = Some("hash-379".to_string());
            runtime.authority_state = "partial".to_string();
            runtime.wal_status = "commit_written".to_string();
        }

        let response = recover_pending_snapshot(
            state.clone(),
            NeutronRecoverPendingRequest {
                expected_pending_generation: 380,
                expected_desired_hash: Some("hash-380".to_string()),
                mode: None,
            },
        )
        .await
        .expect("matching failed pending snapshot should recover");

        assert_eq!(response.status, "recovered");
        assert_eq!(response.recovered_generation, 380);
        assert_eq!(response.applied_generation, 379);
        assert_eq!(response.desired_hash, Some("hash-379".to_string()));
        assert_eq!(
            response.authority_state,
            "recovered_pending_full_resync_required"
        );

        let runtime = state.runtime.read().await;
        assert_eq!(runtime.accepted_generation, 379);
        assert_eq!(runtime.applied_generation, 379);
        assert_eq!(runtime.pending_generation, None);
        assert_eq!(runtime.desired_hash, Some("hash-379".to_string()));
        assert_eq!(runtime.applied_desired_hash, Some("hash-379".to_string()));
        assert_eq!(
            runtime.authority_state,
            "recovered_pending_full_resync_required"
        );
        drop(runtime);

        let replay = state.wal.replay();
        assert_eq!(replay.state.pending_generation, None);
        assert_eq!(replay.state.desired_hash, Some("hash-379".to_string()));
        assert_eq!(
            replay.state.authority_state,
            "recovered_pending_full_resync_required"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn neutron_pending_recovery_rejects_hash_mismatch() {
        let runtime = NeutronRuntimeState {
            accepted_generation: 380,
            applied_generation: 379,
            pending_generation: Some(380),
            desired_hash: Some("hash-380".to_string()),
            applied_desired_hash: Some("hash-379".to_string()),
            authority_state: "partial".to_string(),
            wal_status: "commit_written".to_string(),
            ..NeutronRuntimeState::default()
        };

        let result = recover_pending_runtime(
            &runtime,
            &NeutronRecoverPendingRequest {
                expected_pending_generation: 380,
                expected_desired_hash: Some("different-hash".to_string()),
                mode: None,
            },
        );
        assert!(
            result.is_err(),
            "hash mismatch must not clear pending state"
        );
        let error = result.err().unwrap();

        assert_eq!(error.code, "pending_desired_hash_mismatch");
    }

    #[test]
    fn domain_statuses_track_each_managed_domain() {
        let domains = domain_statuses_for(
            &["acl".to_string(), "qos".to_string(), "mirror".to_string()],
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
                    effective_action: None,
                },
                NeutronDomainStatus {
                    domain: "mirror".to_string(),
                    status: "error".to_string(),
                    reason: Some("apply_failed".to_string()),
                    effective_action: None,
                },
                NeutronDomainStatus {
                    domain: "qos".to_string(),
                    status: "error".to_string(),
                    reason: Some("apply_failed".to_string()),
                    effective_action: None,
                },
            ]
        );
    }

    #[test]
    fn acl_domain_status_reflects_not_requested_bypass() {
        let mut snapshot = port("vm-port", "tap-vm", true);
        snapshot.managed_domains = vec!["acl".to_string()];
        snapshot.acl = Some(NeutronAclSnapshot {
            enabled: false,
            status: "not_requested".to_string(),
            reason: "no_enabled_binding".to_string(),
            effective_action: "bypass".to_string(),
            policy_id: None,
            policy_name: None,
            binding_id: None,
            source: Some("none".to_string()),
            default_action: "allow".to_string(),
            stateful: true,
            revision: 0,
            rules: Vec::new(),
        });

        let status = acl_domain_status_for(&snapshot);
        let (port_status, reason) = successful_port_status(&[status.clone()]);

        assert_eq!(status.domain, "acl");
        assert_eq!(status.status, "not_requested");
        assert_eq!(status.reason.as_deref(), Some("no_enabled_binding"));
        assert_eq!(status.effective_action.as_deref(), Some("bypass"));
        assert_eq!(port_status, "not_requested");
        assert_eq!(reason.as_deref(), Some("no_enabled_binding"));
    }

    #[test]
    fn port_domain_reconcile_skip_requires_ready_matching_acl_hash() {
        let mut snapshot = port("vm-port", "tap-vm", true);
        snapshot.managed_domains = vec!["acl".to_string()];
        snapshot.acl = Some(NeutronAclSnapshot {
            enabled: true,
            status: "ready".to_string(),
            reason: "ready".to_string(),
            effective_action: "enforce".to_string(),
            policy_id: Some("policy-1".to_string()),
            policy_name: Some("policy".to_string()),
            binding_id: Some("binding-1".to_string()),
            source: Some("port".to_string()),
            default_action: "allow".to_string(),
            stateful: true,
            revision: 1,
            rules: Vec::new(),
        });
        let managed = managed_port_from_snapshot(&snapshot);
        let status = ready_status("vm-port", "tap-vm", 1);

        assert!(can_skip_neutron_domain_reconcile(
            Some(&managed),
            Some(&status),
            &managed
        ));

        let mut changed_snapshot = snapshot.clone();
        changed_snapshot.acl.as_mut().unwrap().revision = 2;
        let changed = managed_port_from_snapshot(&changed_snapshot);
        assert!(!can_skip_neutron_domain_reconcile(
            Some(&managed),
            Some(&status),
            &changed
        ));

        let error_status = port_runtime_status(
            "vm-port",
            "tap-vm",
            1,
            Some("hash-1".to_string()),
            vec!["acl".to_string()],
            "error",
            Some("acl_apply_failed".to_string()),
            vec![domain_status(
                "acl",
                "error",
                Some("acl_apply_failed".to_string()),
            )],
        );
        assert!(!can_skip_neutron_domain_reconcile(
            Some(&managed),
            Some(&error_status),
            &managed
        ));
    }

    #[test]
    fn restart_invalidation_requires_acl_resync_without_losing_binding_or_other_hashes() {
        let mut desired = managed_with_ifindex("vm-port", "tap-vm", 17);
        desired.managed_domains = vec!["acl".to_string()];
        desired
            .domain_desired_hashes
            .insert("acl".to_string(), "acl-hash".to_string());
        desired
            .domain_desired_hashes
            .insert("future-domain".to_string(), "future-hash".to_string());

        let mut runtime = NeutronRuntimeState {
            accepted_generation: 42,
            applied_generation: 42,
            applied_desired_hash: Some("snapshot-hash".to_string()),
            authority_state: "ready".to_string(),
            ports: BTreeMap::from([("vm-port".to_string(), desired.clone())]),
            port_statuses: BTreeMap::from([(
                "vm-port".to_string(),
                ready_status("vm-port", "tap-vm", 42),
            )]),
            ..Default::default()
        };

        assert!(invalidate_restarted_acl_runtime(
            &mut runtime,
            std::slice::from_ref(&desired),
        ));

        let restored = &runtime.ports["vm-port"];
        assert_eq!(restored.ifname, "tap-vm");
        assert_eq!(restored.ifindex, Some(17));
        assert!(!restored.domain_desired_hashes.contains_key("acl"));
        assert_eq!(
            restored.domain_desired_hashes.get("future-domain"),
            Some(&"future-hash".to_string())
        );

        let status = &runtime.port_statuses["vm-port"];
        assert_eq!(status.status, "degraded");
        let attach = status
            .domains
            .iter()
            .find(|domain| domain.domain == "attach")
            .expect("attach status");
        assert_eq!(attach.status, "ready");
        let acl = status
            .domains
            .iter()
            .find(|domain| domain.domain == "acl")
            .expect("ACL status");
        assert_eq!(acl.status, "degraded");
        assert_eq!(
            acl.reason.as_deref(),
            Some("acl_restart_replay_requires_resync")
        );
        assert_eq!(acl.effective_action.as_deref(), Some("unchanged"));
        assert_eq!(
            runtime.authority_state,
            "runtime_reconcile_requires_full_resync"
        );
        assert!(!snapshot_generation_fully_applied(&runtime, 42));
        assert!(!can_skip_neutron_domain_reconcile(
            Some(restored),
            Some(status),
            &desired,
        ));
    }

    #[test]
    fn restart_invalidation_leaves_non_acl_runtime_ready() {
        let restored = managed_with_ifindex("vm-port", "tap-vm", 17);
        let mut runtime = NeutronRuntimeState {
            accepted_generation: 42,
            applied_generation: 42,
            authority_state: "ready".to_string(),
            ports: BTreeMap::from([("vm-port".to_string(), restored.clone())]),
            port_statuses: BTreeMap::from([(
                "vm-port".to_string(),
                port_runtime_status(
                    "vm-port",
                    "tap-vm",
                    42,
                    Some("snapshot-hash".to_string()),
                    Vec::new(),
                    "ready",
                    None,
                    vec![domain_status("attach", "ready", None)],
                ),
            )]),
            ..Default::default()
        };

        assert!(!invalidate_restarted_acl_runtime(
            &mut runtime,
            std::slice::from_ref(&restored),
        ));
        assert_eq!(runtime.authority_state, "ready");
        assert_eq!(runtime.port_statuses["vm-port"].status, "ready");
    }

    #[test]
    fn restart_invalidation_preserves_pending_recovery_authority() {
        let mut restored = managed_with_ifindex("vm-port", "tap-vm", 17);
        restored.managed_domains = vec!["acl".to_string()];
        restored
            .domain_desired_hashes
            .insert("acl".to_string(), "acl-hash".to_string());
        let mut runtime = NeutronRuntimeState {
            accepted_generation: 42,
            applied_generation: 42,
            pending_generation: Some(43),
            authority_state: "blocked_recovery_required".to_string(),
            wal_status: "intent_recovery_blocked".to_string(),
            ports: BTreeMap::from([("vm-port".to_string(), restored.clone())]),
            port_statuses: BTreeMap::from([(
                "vm-port".to_string(),
                ready_status("vm-port", "tap-vm", 42),
            )]),
            ..Default::default()
        };

        assert!(invalidate_restarted_acl_runtime(
            &mut runtime,
            std::slice::from_ref(&restored),
        ));
        assert_eq!(runtime.authority_state, "blocked_recovery_required");
        assert_eq!(runtime.wal_status, "intent_recovery_blocked");
        assert_eq!(runtime.pending_generation, Some(43));
        assert!(!runtime.ports["vm-port"]
            .domain_desired_hashes
            .contains_key("acl"));
    }

    #[test]
    fn affected_domains_include_attach_and_feature_domains() {
        let ports = vec![ManagedNeutronPort {
            port_id: "vm-port".to_string(),
            ifname: "tap-vm".to_string(),
            ifindex: None,
            managed_domains: vec!["acl".to_string(), "qos".to_string(), "mirror".to_string()],
            domain_desired_hashes: BTreeMap::new(),
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
    fn snapshot_schema_supports_absent_or_in_range_only() {
        assert!(snapshot_schema_supported(None));
        assert!(snapshot_schema_supported(Some(
            NEUTRON_UDS_SCHEMA_VERSION_MIN
        )));
        assert!(snapshot_schema_supported(Some(
            NEUTRON_UDS_SCHEMA_VERSION_MAX
        )));
        assert!(!snapshot_schema_supported(Some(
            NEUTRON_UDS_SCHEMA_VERSION_MAX + 1
        )));
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
                domain_desired_hashes: BTreeMap::new(),
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
        assert!(snapshot_has_runtime_drift(&current, &snapshot, &local));
        current.get_mut("vm-port").unwrap().domain_desired_hashes =
            domain_desired_hashes_from_snapshot(&snapshot.ports[0]);
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
                domain_desired_hashes: BTreeMap::new(),
            },
        );

        let ports = affected_ports_for_intent(&intent, &current);

        assert_eq!(1, ports.len());
        assert_eq!("tap-vm", ports[0].ifname);
        assert_eq!(Some(17), ports[0].ifindex);
    }

    #[test]
    fn pending_intent_recovery_blocks_unimplemented_domains() {
        let domains = vec![
            "attach".to_string(),
            "acl".to_string(),
            "qos".to_string(),
            "mirror".to_string(),
        ];

        let recovery = blocked_unsupported_recovery(&domains)
            .expect("qos/mirror recovery must be rejected");

        assert!(!recovery.ok);
        assert_eq!("blocked", recovery.status);
        assert_eq!(domains, recovery.managed_domains);
        assert!(recovery
            .reason
            .as_deref()
            .map(|reason| reason.contains("qos,mirror"))
            .unwrap_or(false));
        assert!(recovery.domains.iter().all(|domain| domain.status == "blocked"));
        assert!(recovery.domains.iter().any(|domain| {
            domain.domain == "qos"
                && domain.reason.as_deref() == Some("unsupported_recovery_domain:qos")
        }));
        assert!(recovery.domains.iter().any(|domain| {
            domain.domain == "mirror"
                && domain.reason.as_deref() == Some("unsupported_recovery_domain:mirror")
        }));
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
    fn neutron_acl_translator_merges_same_tuple_l4_port_rules() {
        let acl = ready_acl(vec![
            tcp_rule("drop-18081", "drop", 18081),
            tcp_rule("drop-8080", "drop", 8080),
        ]);

        let plan = translate_neutron_acl("port-1", &acl).expect("ACL should translate");

        assert_eq!(plan.groups, Vec::new());
        assert_eq!(
            plan.policies,
            vec![AclPolicyPlan {
                src_group: "any".to_string(),
                dst_group: "any".to_string(),
                proto: 6,
                action: 1,
                direction: 1,
                ports: Some("8080,18081".to_string()),
            }]
        );
    }

    #[test]
    fn neutron_acl_translator_carries_conntrack_intent() {
        let stateful = ready_acl(vec![tcp_rule("drop-8080", "drop", 8080)]);
        assert_eq!(
            translate_neutron_acl("port-1", &stateful)
                .expect("stateful ACL should translate")
                .conntrack_enabled,
            Some(true)
        );

        let mut stateless = stateful;
        stateless.stateful = false;
        assert_eq!(
            translate_neutron_acl("port-1", &stateless)
                .expect("stateless ACL should translate")
                .conntrack_enabled,
            Some(false)
        );

        assert_eq!(AclApplyPlan::default().conntrack_enabled, None);
    }

    #[test]
    fn neutron_acl_runtime_transition_is_atomic() {
        let policy = AclPolicyPlan {
            src_group: "any".to_string(),
            dst_group: "any".to_string(),
            proto: 6,
            action: 1,
            direction: 1,
            ports: Some("8080".to_string()),
        };
        let quiesced = AclRuntimeFeatureState {
            conntrack_enabled: false,
            acl_enabled: false,
        };

        let stateful = acl_runtime_transition(
            &AclApplyPlan {
                groups: Vec::new(),
                policies: vec![policy.clone()],
                conntrack_enabled: Some(true),
            },
            false,
        );
        assert_eq!(stateful.quiesce, quiesced);
        assert_eq!(
            stateful.publish,
            AclRuntimeFeatureState {
                conntrack_enabled: true,
                acl_enabled: true,
            }
        );

        let stateless = acl_runtime_transition(
            &AclApplyPlan {
                groups: Vec::new(),
                policies: vec![policy],
                conntrack_enabled: Some(false),
            },
            true,
        );
        assert_eq!(stateless.quiesce, quiesced);
        assert_eq!(
            stateless.publish,
            AclRuntimeFeatureState {
                conntrack_enabled: false,
                acl_enabled: true,
            }
        );

        let empty_stateful = acl_runtime_transition(
            &AclApplyPlan {
                groups: Vec::new(),
                policies: Vec::new(),
                conntrack_enabled: Some(true),
            },
            false,
        );
        assert_eq!(empty_stateful.quiesce, quiesced);
        assert_eq!(
            empty_stateful.publish,
            AclRuntimeFeatureState {
                conntrack_enabled: true,
                acl_enabled: false,
            }
        );

        let missing_payload = acl_runtime_transition(&AclApplyPlan::default(), true);
        assert_eq!(missing_payload.quiesce, quiesced);
        assert_eq!(
            missing_payload.publish,
            AclRuntimeFeatureState {
                conntrack_enabled: true,
                acl_enabled: false,
            }
        );
    }

    #[test]
    fn neutron_acl_translator_rejects_conflicting_actions_for_same_tuple() {
        let acl = ready_acl(vec![
            tcp_rule("drop-8080", "drop", 8080),
            tcp_rule("allow-18081", "allow", 18081),
        ]);

        let error = translate_neutron_acl("port-1", &acl)
            .expect_err("mixed actions for one datapath tuple are unsupported");

        assert!(error.contains("conflicting effective ACL actions"));
    }

    #[test]
    fn neutron_acl_translator_builds_drop_icmp_policy() {
        let acl = ready_acl(vec![NeutronAclRuleSnapshot {
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
        }]);

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

    #[test]
    fn neutron_acl_gate_mode_disables_before_every_replacement() {
        assert_eq!(
            acl_gate_update_mode(&AclApplyPlan::default()),
            AclGateUpdateMode::DisableBeforeReplace
        );

        let plan = AclApplyPlan {
            groups: vec![AclGroupPlan {
                name: "neutron:port-1:src:drop-icmp".to_string(),
                cidrs: vec!["10.58.159.2/32".to_string()],
            }],
            policies: vec![AclPolicyPlan {
                src_group: "neutron:port-1:src:drop-icmp".to_string(),
                dst_group: "any".to_string(),
                proto: 1,
                action: 1,
                direction: 1,
                ports: None,
            }],
        };

        assert_eq!(
            acl_gate_update_mode(&plan),
            AclGateUpdateMode::DisableBeforeReplace
        );
    }

    #[test]
    fn neutron_control_plane_exposes_strict_conntrack_flush() {
        let _strict_flush = ControlPlane::flush_conntrack_strict;
    }

    #[test]
    fn neutron_acl_errors_report_the_proven_effective_action() {
        let pre_disable = NeutronAclReconcileError::unchanged("translation failed");
        assert_eq!(pre_disable.effective_action, "unchanged");

        let post_disable = NeutronAclReconcileError::bypass("strict CT flush failed");
        assert_eq!(post_disable.effective_action, "bypass");
    }

    #[test]
    fn domain_authority_neutron_acl_purge_includes_foreign_acl_policies() {
        let mut group_names_by_id = BTreeMap::new();
        group_names_by_id.insert(
            42,
            "neutron:port-1:dst:drop-icmp".to_string(),
        );
        let rules = vec![
            aria_core::state::RuleInfo {
                name: None,
                src_group_id: 0,
                dst_group_id: 0,
                proto: 1,
                action: 1,
                ports: None,
                bitmap_idx: None,
                direction: 1,
            },
            aria_core::state::RuleInfo {
                name: None,
                src_group_id: 0,
                dst_group_id: 42,
                proto: 1,
                action: 1,
                ports: None,
                bitmap_idx: None,
                direction: 1,
            },
        ];

        let targets = acl_policy_delete_targets_for_neutron_domain(&rules, &group_names_by_id);

        assert_eq!(
            targets,
            vec![
                AclPolicyDeleteTarget {
                    src_group: "any".to_string(),
                    dst_group: "any".to_string(),
                    proto: 1,
                    direction: 1,
                },
                AclPolicyDeleteTarget {
                    src_group: "any".to_string(),
                    dst_group: "neutron:port-1:dst:drop-icmp".to_string(),
                    proto: 1,
                    direction: 1,
                },
            ]
        );
    }
}
