use aria_api::{
    action_from_string, direction_from_string, proto_from_string, ManagedNeutronPort,
    NeutronAclRuleSnapshot, NeutronAclSnapshot, NeutronCapabilitiesResponse, NeutronCounterBucketV1,
    NeutronCounterReasonV1, NeutronDeleteResponse, NeutronDomainStatus, NeutronPortApplyResult,
    NeutronPortCountersV1, NeutronPortSnapshot, NeutronPortStatus, NeutronSnapshotRequest,
    NeutronSnapshotResponse, NeutronStatusCountersV1, NeutronStatusDomainEvidence,
    NeutronStatusDomainState, NeutronStatusEffectiveAction, NeutronStatusOverallReadiness,
    NeutronStatusPortEvidence, NeutronStatusRecoveryCause, NeutronStatusRequiredAction,
    NeutronStatusSupportDisposition, NeutronStatusTransactionState, NeutronStatusV1Response,
    NEUTRON_COUNTERS_SCHEMA_VERSION, NEUTRON_MAX_COUNTER_BUCKET_ROWS_PER_PORT,
    NEUTRON_STATUS_CONTRACT_HASH, NEUTRON_STATUS_SCHEMA_VERSION_MAX, NEUTRON_UDS_BODY_MAX_BYTES,
    NEUTRON_UDS_SCHEMA_VERSION_MAX, NEUTRON_UDS_SCHEMA_VERSION_MIN,
};
use aria_core::port_counters::read_port_counters;
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
use std::cmp::Reverse;
use std::collections::{BTreeMap, BTreeSet, BinaryHeap};
use std::fmt;
use std::future::Future;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::process::Command;
use tokio::sync::{Mutex, OwnedMutexGuard, RwLock};
use tracing::{error, info, warn};

use crate::control_plane::{
    ControlPlane, InstanceRuntimeHealthSnapshot, ManagedAclPublicationMode,
    ManagedProjectionHealth, OwnedAclGroupSpec, OwnedAclPolicySpec, OwnedAclReconcileReport,
};
use crate::fault_injection;
use crate::neutron_wal::{NeutronWal, NeutronWalState, PendingNeutronIntent};
use crate::tap_registry::{RuntimeReconcileResult, TapRegistry};

const NEUTRON_TC_ACL_HEALTH_INTERVAL_SECS: u64 = 10;
const INVENTORY_UNAVAILABLE_RECOVERY_CAUSE: &str = "inventory_unavailable";
const RUNTIME_REBUILD_REQUIRED_REASON: &str = "runtime_rebuild_required";
const OVS_INVENTORY_TIMEOUT: Duration = Duration::from_secs(3);
const SNAPSHOT_ADMISSION_REVALIDATION_ATTEMPTS: usize = 3;

#[derive(Clone)]
pub(crate) struct NeutronApiState {
    registry: Arc<TapRegistry>,
    control_plane: Arc<ControlPlane>,
    ovs_bridge: String,
    runtime: Arc<RwLock<NeutronRuntimeState>>,
    apply_lock: Arc<Mutex<()>>,
    restore_ready: Arc<AtomicBool>,
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
    recovery_cause: Option<String>,
    wal_replay_failures: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct SnapshotAdmissionIdentity {
    accepted_generation: u64,
    applied_generation: u64,
    pending_generation: Option<u64>,
    desired_hash: Option<String>,
    applied_desired_hash: Option<String>,
    authority_state: String,
    ports: BTreeMap<String, ManagedNeutronPort>,
    port_statuses: BTreeMap<String, NeutronPortStatus>,
    wal_status: String,
    recovery_cause: Option<String>,
    wal_replay_failures: u64,
}

impl SnapshotAdmissionIdentity {
    fn capture(runtime: &NeutronRuntimeState) -> Self {
        Self {
            accepted_generation: runtime.accepted_generation,
            applied_generation: runtime.applied_generation,
            pending_generation: runtime.pending_generation,
            desired_hash: runtime.desired_hash.clone(),
            applied_desired_hash: runtime.applied_desired_hash.clone(),
            authority_state: runtime.authority_state.clone(),
            ports: runtime.ports.clone(),
            port_statuses: runtime.port_statuses.clone(),
            wal_status: runtime.wal_status.clone(),
            recovery_cause: runtime.recovery_cause.clone(),
            wal_replay_failures: runtime.wal_replay_failures,
        }
    }
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
    inventory_error: Option<String>,
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

const MAX_ACL_RULES_PER_POLICY: usize = 1000;
const MAX_ACL_SELECTOR_MEMBERS: usize = 2048;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct AclIpv4Cidr {
    network: u32,
    prefix: u8,
}

impl AclIpv4Cidr {
    fn parse(value: &str) -> Result<Self, String> {
        let text = value.trim();
        let mut pieces = text.split('/');
        let address = pieces
            .next()
            .ok_or_else(|| format!("invalid IPv4 CIDR {}", value))?;
        let prefix = pieces
            .next()
            .ok_or_else(|| format!("invalid IPv4 CIDR {}", value))?;
        if pieces.next().is_some() {
            return Err(format!("invalid IPv4 CIDR {}", value));
        }

        let octets: Vec<&str> = address.split('.').collect();
        if octets.len() != 4 {
            return Err(format!("invalid IPv4 CIDR {}", value));
        }
        let mut values = [0u8; 4];
        for (index, octet) in octets.iter().enumerate() {
            if octet.is_empty()
                || !octet.as_bytes().iter().all(u8::is_ascii_digit)
                || (octet.len() > 1 && octet.starts_with('0'))
            {
                return Err(format!("invalid IPv4 CIDR {}", value));
            }
            values[index] = octet
                .parse::<u8>()
                .map_err(|_| format!("invalid IPv4 CIDR {}", value))?;
        }
        if prefix.is_empty() || !prefix.as_bytes().iter().all(u8::is_ascii_digit) {
            return Err(format!("invalid IPv4 CIDR {}", value));
        }
        let prefix = prefix
            .parse::<u8>()
            .map_err(|_| format!("invalid IPv4 CIDR {}", value))?;
        if prefix > 32 {
            return Err(format!("invalid IPv4 CIDR {}", value));
        }
        let address = u32::from_be_bytes(values);
        let mask = if prefix == 0 {
            0
        } else {
            u32::MAX << (32 - prefix)
        };
        Ok(Self {
            network: address & mask,
            prefix,
        })
    }

    fn end(self) -> u32 {
        let host_mask = if self.prefix == 32 {
            0
        } else {
            u32::MAX >> self.prefix
        };
        self.network | host_mask
    }

    fn canonical(self) -> String {
        format!(
            "{}/{}",
            std::net::Ipv4Addr::from(self.network),
            self.prefix
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct AclSelectorId(usize);

impl AclSelectorId {
    const ANY: Self = Self(0);

    fn group_ordinal(self) -> usize {
        self.0 - 1
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct CanonicalAclRule {
    id: String,
    direction: String,
    priority: i64,
    directions: Vec<u8>,
    proto: u8,
    action: u8,
    src_cidrs: Vec<AclIpv4Cidr>,
    dst_cidrs: Vec<AclIpv4Cidr>,
    ports: Vec<(u16, u16)>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct NormalizedAclRule {
    id: String,
    direction: String,
    priority: i64,
    directions: Vec<u8>,
    proto: u8,
    action: u8,
    src_selector_id: AclSelectorId,
    dst_selector_id: AclSelectorId,
    ports: Vec<(u16, u16)>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum AclValidatedTemplate {
    Ready {
        rules: Vec<NormalizedAclRule>,
        src_selectors: Vec<Vec<AclIpv4Cidr>>,
        dst_selectors: Vec<Vec<AclIpv4Cidr>>,
    },
    ForceBypass(String),
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct AclValidationCacheKey {
    policy_id: Option<String>,
    revision: u64,
    content_hash: String,
}

#[derive(Serialize)]
struct AclValidationHashPayload<'a> {
    default_action: &'a str,
    rules: &'a [NeutronAclRuleSnapshot],
}

#[derive(Default)]
struct AclValidationCache {
    entries: BTreeMap<AclValidationCacheKey, Result<AclValidatedTemplate, String>>,
    hits: usize,
    misses: usize,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct AclApplyPlan {
    groups: Vec<AclGroupPlan>,
    policies: Vec<AclPolicyPlan>,
    conntrack_enabled: Option<bool>,
    force_bypass_reason: Option<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct NeutronAclReconcileOutcome {
    force_bypass_reason: Option<String>,
}

impl NeutronAclReconcileOutcome {
    fn from_plan(plan: &AclApplyPlan) -> Self {
        Self {
            force_bypass_reason: plan.force_bypass_reason.clone(),
        }
    }

    fn domain_status(&self, port: &NeutronPortSnapshot) -> NeutronDomainStatus {
        match &self.force_bypass_reason {
            Some(reason) => domain_status_with_action(
                "acl",
                "degraded",
                Some(reason.clone()),
                Some("bypass".to_string()),
            ),
            None => acl_domain_status_for(port),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct AclRuntimeFeatureState {
    conntrack_enabled: bool,
    acl_enabled: bool,
    acl_ingress_hook: u8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct AclRuntimeTransition {
    quiesce: AclRuntimeFeatureState,
    publish: AclRuntimeFeatureState,
}

fn acl_runtime_transition(
    plan: &AclApplyPlan,
    preserved_conntrack_enabled: bool,
) -> AclRuntimeTransition {
    AclRuntimeTransition {
        quiesce: AclRuntimeFeatureState {
            conntrack_enabled: false,
            acl_enabled: false,
            acl_ingress_hook: aria_core::common::ACL_INGRESS_HOOK_TC,
        },
        publish: AclRuntimeFeatureState {
            conntrack_enabled: plan
                .conntrack_enabled
                .unwrap_or(preserved_conntrack_enabled),
            acl_enabled: !plan.policies.is_empty(),
            acl_ingress_hook: aria_core::common::ACL_INGRESS_HOOK_TC,
        },
    }
}

fn acl_runtime_feature_requires_tc(state: AclRuntimeFeatureState) -> bool {
    state.conntrack_enabled || state.acl_enabled
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AclReconcileFailurePhase {
    BeforeQuiesce,
    AfterQuiesce,
    CompensationFailed,
}

fn acl_reconcile_error(
    phase: AclReconcileFailurePhase,
    details: impl Into<String>,
) -> NeutronAclReconcileError {
    match phase {
        AclReconcileFailurePhase::BeforeQuiesce => {
            NeutronAclReconcileError::unchanged(details)
        }
        AclReconcileFailurePhase::AfterQuiesce => NeutronAclReconcileError::bypass(details),
        AclReconcileFailurePhase::CompensationFailed => {
            NeutronAclReconcileError::enforce(details)
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
            restore_ready: Arc::new(AtomicBool::new(false)),
            wal,
            pending_recovery,
        }
    }

    fn mark_restore_ready(&self) {
        self.restore_ready.store(true, Ordering::Release);
    }

    fn require_restore_ready(&self) -> Result<(), SnapshotApplyError> {
        if self.restore_ready.load(Ordering::Acquire) {
            return Ok(());
        }
        Err(SnapshotApplyError {
            status: StatusCode::SERVICE_UNAVAILABLE,
            code: "neutron_runtime_restore_in_progress",
            details: "Neutron runtime restore is still in progress; retry the request"
                .to_string(),
        })
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
            let manages_acl = normalize_managed_domains(&port.managed_domains)
                .iter()
                .any(|domain| domain == "acl");
            let required_publication_mode = required_neutron_publication_mode(manages_acl);
            self.control_plane
                .mark_neutron_port_authority_if_current(
                    &port.ifname,
                    &port.port_id,
                    &port.managed_domains,
                    generation,
                    required_publication_mode,
                    None,
                )
                .await;
        }
    }

    async fn reconcile_committed_runtime(&self) {
        let _guard = self.apply_lock.lock().await;
        let (ports, generation, desired_hash) = {
            let runtime = self.runtime.read().await;
            if runtime.recovery_cause.as_deref() == Some(INVENTORY_UNAVAILABLE_RECOVERY_CAUSE) {
                return;
            }
            (
                runtime.ports.values().cloned().collect::<Vec<_>>(),
                runtime.applied_generation,
                runtime.applied_desired_hash.clone(),
            )
        };
        let committed_ifaces: Vec<(String, bool)> = ports
            .iter()
            .map(|port| {
                (
                    port.ifname.clone(),
                    port.managed_domains.iter().any(|domain| domain == "acl"),
                )
            })
            .collect();
        let missing_ifnames: BTreeSet<String> = ports
            .iter()
            .filter(|port| read_ifindex(&port.ifname).is_none())
            .map(|port| port.ifname.clone())
            .collect();
        let mut results = self
            .registry
            .reconcile_neutron_runtime(&committed_ifaces)
            .await;
        let missing_runtime_requires_full_resync =
            defer_missing_committed_interfaces(&mut results, &missing_ifnames);
        if results.is_empty() {
            return;
        }

        let previous_runtime = {
            let runtime = self.runtime.read().await;
            runtime.clone()
        };
        let Some(mut next_runtime) = project_committed_runtime_reconcile(
            &previous_runtime,
            &ports,
            generation,
            desired_hash,
            &results,
            missing_runtime_requires_full_resync,
        ) else {
            return;
        };

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

    async fn retry_committed_runtime_after_tap_return(&self) {
        let should_retry = {
            let runtime = self.runtime.read().await;
            let live_ifnames: BTreeSet<String> = runtime
                .ports
                .values()
                .filter(|port| read_ifindex(&port.ifname).is_some())
                .map(|port| port.ifname.clone())
                .collect();
            should_retry_committed_runtime_reconcile(&runtime, &live_ifnames)
        };
        if !should_retry {
            return;
        }
        info!("retrying committed Neutron runtime after tap return");
        self.reconcile_committed_runtime().await;
    }

    async fn recover_incomplete_wal_intent(&self) {
        let Some(intent) = self.pending_recovery.clone() else {
            return;
        };
        let _guard = self.apply_lock.lock().await;
        if intent.recovery_cause.as_deref() == Some(INVENTORY_UNAVAILABLE_RECOVERY_CAUSE) {
            let mut next_runtime = {
                let runtime = self.runtime.read().await;
                runtime.clone()
            };
            next_runtime.accepted_generation = intent.generation;
            next_runtime.pending_generation = Some(intent.generation);
            next_runtime.desired_hash = intent.desired_hash.clone();
            next_runtime.authority_state = "blocked_recovery_required".to_string();
            next_runtime.wal_status = INVENTORY_UNAVAILABLE_RECOVERY_CAUSE.to_string();
            next_runtime.recovery_cause = Some(INVENTORY_UNAVAILABLE_RECOVERY_CAUSE.to_string());

            let commit_result = self.wal.append_snapshot_commit(next_runtime.to_wal_state());
            {
                let mut runtime = self.runtime.write().await;
                *runtime = next_runtime;
            }
            if let Err(e) = commit_result {
                warn!(error = %e, "failed to commit inventory-blocked Neutron WAL recovery state");
            }
            return;
        }
        let previous_runtime = {
            let runtime = self.runtime.read().await;
            runtime.clone()
        };
        let current_ports = previous_runtime.ports.clone();
        let affected_ports = affected_ports_for_intent(&intent, &current_ports);
        if affected_ports.is_empty() {
            if intent.kind == "delete" {
                let next_runtime = finalize_recovered_delete_intent(
                    self,
                    &intent,
                    &previous_runtime,
                    previous_runtime.clone(),
                    true,
                );
                let mut runtime = self.runtime.write().await;
                *runtime = next_runtime;
                return;
            }
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

        let mut next_runtime = previous_runtime.clone();
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

        if intent.kind == "delete" {
            let next_runtime = finalize_recovered_delete_intent(
                self,
                &intent,
                &previous_runtime,
                next_runtime,
                recovery_failed,
            );
            let mut runtime = self.runtime.write().await;
            *runtime = next_runtime;
            return;
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
        let acl_managed = domains.iter().any(|domain| domain == "acl");
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
            match self
                .registry
                .attach_neutron(&port.ifname, acl_managed)
                .await
            {
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
                    match purge_neutron_acl_transactionally(self, &port.ifname, &port.port_id).await {
                        Ok(_) => statuses.push(domain_status_with_action(
                            domain,
                            "recovered",
                            Some("acl_scrubbed_after_incomplete_wal_intent".to_string()),
                            Some("bypass".to_string()),
                        )),
                        Err(e) => {
                            let reason = format!("acl_recovery_failed:{}", e.details);
                            statuses.push(domain_status_with_action(
                                domain,
                                "blocked",
                                Some(reason.clone()),
                                Some(e.effective_action.to_string()),
                            ));
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
        if attached_for_recovery && should_detach && errors.is_empty() {
            match self.registry.detach(&port.ifname).await {
                Ok(()) => {}
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

    async fn project_tc_acl_health(&self) {
        let _guard = self.apply_lock.lock().await;
        let health = self.control_plane.list_instance_runtime_health().await;
        let mut next_runtime = {
            let runtime = self.runtime.read().await;
            runtime.clone()
        };
        if !project_tc_acl_link_loss(&mut next_runtime, &health) {
            return;
        }
        if let Err(error) = self.wal.append_snapshot_commit(next_runtime.to_wal_state()) {
            warn!(error = %error, "failed to commit Neutron TC ACL link-loss status");
            return;
        }
        let mut runtime = self.runtime.write().await;
        *runtime = next_runtime;
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
            recovery_cause: state.recovery_cause,
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
            recovery_cause: self.recovery_cause.clone(),
            status_hash: None,
        }
    }
}

fn neutron_status_requires_full_resync(status: &NeutronPortStatus) -> bool {
    status
        .reason
        .as_deref()
        .is_some_and(|reason| reason.contains("requires_resync") || reason.contains("full_resync"))
        || status.domains.iter().any(|domain| {
            domain.reason.as_deref().is_some_and(|reason| {
                reason.contains("requires_resync") || reason.contains("full_resync")
            })
        })
}

fn project_tc_acl_link_loss(
    runtime: &mut NeutronRuntimeState,
    health: &[InstanceRuntimeHealthSnapshot],
) -> bool {
    if neutron_tc_health_projection_blocked(runtime) {
        return false;
    }
    let health_by_instance: BTreeMap<&str, &InstanceRuntimeHealthSnapshot> = health
        .iter()
        .map(|snapshot| (snapshot.name.as_str(), snapshot))
        .collect();
    let committed_ports: Vec<ManagedNeutronPort> = runtime.ports.values().cloned().collect();
    let mut changed = false;

    for port in committed_ports {
        if !normalize_managed_domains(&port.managed_domains)
            .iter()
            .any(|domain| domain == "acl")
        {
            continue;
        }
        let Some(snapshot) = health_by_instance.get(port.ifname.as_str()) else {
            continue;
        };
        if snapshot.acl_ready {
            continue;
        }
        let Some(runtime_reason) = snapshot.readiness_reason.as_deref() else {
            continue;
        };
        if !runtime_reason.starts_with("missing_tc_")
            && !runtime_reason.starts_with("acl_quiesce_failed:")
        {
            continue;
        }
        let Some(status) = runtime.port_statuses.get_mut(&port.port_id) else {
            continue;
        };
        if neutron_status_requires_full_resync(status) {
            continue;
        }
        let already_projected = status.status == "degraded"
            && status.reason.as_deref() == Some("tc_acl_link_lost")
            && status.domains.iter().any(|domain| {
                domain.domain == "acl"
                    && domain.status == "degraded"
                    && domain.reason.as_deref() == Some("tc_acl_link_lost")
                    && domain.effective_action.as_deref() == Some("bypass")
            });
        if already_projected {
            continue;
        }

        let mut domains: BTreeMap<String, NeutronDomainStatus> = status
            .domains
            .drain(..)
            .map(|domain| (domain.domain.clone(), domain))
            .collect();
        domains.insert(
            "acl".to_string(),
            domain_status_with_action(
                "acl",
                "degraded",
                Some("tc_acl_link_lost".to_string()),
                Some("bypass".to_string()),
            ),
        );
        status.status = "degraded".to_string();
        status.reason = Some("tc_acl_link_lost".to_string());
        status.domains = domains.into_values().collect();
        changed = true;
    }

    if changed {
        runtime.authority_state = "runtime_degraded".to_string();
        runtime.wal_status = "tc_acl_link_lost".to_string();
    }
    changed
}

fn neutron_tc_health_projection_blocked(runtime: &NeutronRuntimeState) -> bool {
    runtime.pending_generation.is_some()
        || matches!(
            runtime.authority_state.as_str(),
            "blocked_recovery_required"
                | "recovered_pending_full_resync_required"
                | "recovered_pending_full_resync"
                | "wal_recovery_commit_failed"
                | "pending_recovery_commit_failed"
                | "runtime_reconcile_requires_full_resync"
                | "wal_runtime_reconcile_commit_failed"
        )
        || matches!(
            runtime.wal_status.as_str(),
            "commit_failed"
                | "intent_recovery_blocked"
                | "intent_recovered"
                | "pending_recovered_to_last_applied"
                | "runtime_reconciled_acl_resync_required"
        )
}

pub(crate) struct NeutronBackgroundTasks {
    restore_task: tokio::task::JoinHandle<()>,
    health_task: tokio::task::JoinHandle<()>,
}

impl NeutronBackgroundTasks {
    pub(crate) async fn abort(self) {
        let Self {
            restore_task,
            health_task,
        } = self;
        restore_task.abort();
        health_task.abort();
        if let Err(error) = restore_task.await {
            if !error.is_cancelled() {
                warn!(error = %error, "Neutron restore task failed during shutdown");
            }
        }
        if let Err(error) = health_task.await {
            if !error.is_cancelled() {
                warn!(error = %error, "Neutron health task failed during shutdown");
            }
        }
    }
}

pub(crate) struct NeutronRouterRuntime {
    pub(crate) router: Router,
    pub(crate) background: NeutronBackgroundTasks,
}

pub(crate) fn build_router(
    registry: Arc<TapRegistry>,
    control_plane: Arc<ControlPlane>,
    ovs_bridge: String,
) -> NeutronRouterRuntime {
    let state = NeutronApiState::new(registry, control_plane, ovs_bridge);
    let restore_state = state.clone();
    let restore_task = tokio::spawn(async move {
        restore_state.recover_incomplete_wal_intent().await;
        restore_state.reconcile_committed_runtime().await;
        restore_state.restore_neutron_authorities().await;
        restore_state.mark_restore_ready();
        info!("Neutron runtime restore completed; mutating UDS routes are ready");
    });
    let health_state = state.clone();
    let health_task = tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(
            NEUTRON_TC_ACL_HEALTH_INTERVAL_SECS,
        ));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        interval.tick().await;
        loop {
            interval.tick().await;
            health_state
                .retry_committed_runtime_after_tap_return()
                .await;
            health_state.project_tc_acl_health().await;
        }
    });
    let router = Router::new()
        .route("/readyz", get(get_neutron_readiness))
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
        .with_state(state);
    NeutronRouterRuntime {
        router,
        background: NeutronBackgroundTasks {
            restore_task,
            health_task,
        },
    }
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

fn is_typed_inventory_recovery(runtime: &NeutronRuntimeState) -> bool {
    runtime.recovery_cause.as_deref() == Some(INVENTORY_UNAVAILABLE_RECOVERY_CAUSE)
        && runtime.wal_status == INVENTORY_UNAVAILABLE_RECOVERY_CAUSE
        && runtime.authority_state == "blocked_recovery_required"
}

async fn recover_pending_snapshot(
    state: NeutronApiState,
    request: NeutronRecoverPendingRequest,
) -> Result<NeutronRecoverPendingResponse, SnapshotApplyError> {
    state.require_restore_ready()?;
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
    let mut replay = state.wal.replay();
    let mut runtime = state.runtime.write().await;
    validate_pending_recovery_identity(&runtime, &request)?;
    let protected_inventory_intent = replay
        .pending_intent
        .as_ref()
        .and_then(|intent| intent.recovery_cause.as_deref())
        == Some(INVENTORY_UNAVAILABLE_RECOVERY_CAUSE);
    let inventory_recovery = protected_inventory_intent
        || runtime.recovery_cause.as_deref() == Some(INVENTORY_UNAVAILABLE_RECOVERY_CAUSE)
        || replay.state.recovery_cause.as_deref()
            == Some(INVENTORY_UNAVAILABLE_RECOVERY_CAUSE);
    if protected_inventory_intent {
        if !is_typed_inventory_recovery(&runtime) {
            return Err(SnapshotApplyError {
                status: StatusCode::INTERNAL_SERVER_ERROR,
                code: "pending_recovery_commit_failed",
                details: "protected inventory intent requires a typed blocked live state"
                    .to_string(),
            });
        }
        let intent = replay
            .pending_intent
            .as_ref()
            .expect("protected inventory recovery requires a pending intent");
        let verified = state
            .wal
            .append_verified_protected_inventory_commit(intent, runtime.to_wal_state())
            .map_err(|e| SnapshotApplyError {
                status: StatusCode::INTERNAL_SERVER_ERROR,
                code: "pending_recovery_commit_failed",
                details: e,
            })?;
        let verified_runtime = NeutronRuntimeState::from_wal_state(
            verified.state.clone(),
            verified.status.clone(),
            verified.failures,
        );
        validate_pending_recovery_identity(&verified_runtime, &request)?;
        *runtime = verified_runtime;
        replay = verified;
    }
    if inventory_recovery && !is_typed_inventory_recovery(&runtime) {
        return Err(SnapshotApplyError {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            code: "pending_recovery_commit_failed",
            details: "inventory recovery requires a clean typed blocked live state".to_string(),
        });
    }
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
    let next_runtime = if runtime.applied_generation == 0 {
        let replay_runtime = NeutronRuntimeState::from_wal_state(
            replay.state,
            replay.status,
            replay.failures,
        );
        recover_pending_runtime(&replay_runtime, &request)?
    } else {
        recover_pending_runtime(&runtime, &request)?
    };
    let commit_result = if inventory_recovery {
        state
            .wal
            .append_snapshot_commit_after_verified_inventory_barrier(
                runtime.to_wal_state(),
                next_runtime.to_wal_state(),
            )
    } else {
        state
            .wal
            .append_snapshot_commit(next_runtime.to_wal_state())
    };
    if let Err(e) = commit_result {
        if !inventory_recovery {
            runtime.authority_state = "pending_recovery_commit_failed".to_string();
            runtime.wal_status = "commit_failed".to_string();
        }
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
    let inventory_empty_baseline = runtime.applied_generation == 0
        && runtime.authority_state == "blocked_recovery_required"
        && runtime.wal_status == INVENTORY_UNAVAILABLE_RECOVERY_CAUSE
        && runtime.applied_desired_hash.is_none()
        && runtime.ports.is_empty()
        && runtime.port_statuses.is_empty();
    if runtime.applied_generation == 0 && !inventory_empty_baseline {
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
    next_runtime.recovery_cause = None;
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

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum StatusV1EvidenceClass {
    Ready,
    TerminalDegraded,
    FullResync,
    Blocked,
}

struct NeutronStatusV1Projection {
    transaction_state: NeutronStatusTransactionState,
    overall_readiness: NeutronStatusOverallReadiness,
    required_action: NeutronStatusRequiredAction,
    recovery_cause: Option<NeutronStatusRecoveryCause>,
    last_classified_generation: u64,
    port_statuses: Vec<NeutronStatusPortEvidence>,
}

struct ProjectedStatusV1PortRow {
    evidence: NeutronStatusPortEvidence,
    domain_class: StatusV1EvidenceClass,
    domain_names: BTreeSet<String>,
    domains_valid: bool,
}

fn status_v1_reason_requires_full_resync(reason: Option<&str>) -> bool {
    matches!(
        reason,
        Some("runtime_rebuild_required")
            | Some("acl_restart_replay_requires_resync")
            | Some("tc_acl_link_lost")
    )
}

fn status_v1_effective_action(action: Option<&str>) -> Option<NeutronStatusEffectiveAction> {
    match action {
        Some("enforce") => Some(NeutronStatusEffectiveAction::Enforce),
        Some("bypass") => Some(NeutronStatusEffectiveAction::Bypass),
        Some("unchanged") => Some(NeutronStatusEffectiveAction::Unchanged),
        Some("cleanup") => Some(NeutronStatusEffectiveAction::Cleanup),
        Some("no_op") => Some(NeutronStatusEffectiveAction::NoOp),
        Some(_) | None => None,
    }
}

fn status_v1_reason_is_unsupported(reason: Option<&str>) -> bool {
    reason.is_some_and(|reason| {
        reason == "acl_not_supported"
            || reason.starts_with("acl_rule_limit_exceeded:")
            || reason.starts_with("acl_selector_member_limit_exceeded:")
            || reason.starts_with("unsupported_acl_")
            || reason.starts_with("invalid_acl_priority:")
            || reason.starts_with("duplicate_acl_priority:")
            || reason.ends_with("_transaction_not_implemented")
            || reason.starts_with("blocked_by_unimplemented_domains:")
            || reason.starts_with("unsupported_recovery_domain:")
    })
}

fn status_v1_support_disposition(
    domain: &str,
    status: &str,
    reason: Option<&str>,
) -> NeutronStatusSupportDisposition {
    if domain == "acl" && status == "not_requested" {
        NeutronStatusSupportDisposition::NotApplicable
    } else if status == "unsupported" || status_v1_reason_is_unsupported(reason) {
        NeutronStatusSupportDisposition::Unsupported
    } else if status_v1_reason_requires_full_resync(reason)
        || matches!((domain, status), ("attach", "ready") | ("acl", "ready"))
    {
        NeutronStatusSupportDisposition::Supported
    } else {
        NeutronStatusSupportDisposition::Unknown
    }
}

fn status_v1_normalized_unique_domains(domains: &[String]) -> Option<Vec<String>> {
    let normalized = normalize_managed_domains(domains);
    (normalized.len() == domains.len()).then_some(normalized)
}

fn project_status_v1_domain(
    domain: &NeutronDomainStatus,
) -> (NeutronStatusDomainEvidence, StatusV1EvidenceClass) {
    let normalized_names = normalize_managed_domains(std::slice::from_ref(&domain.domain));
    let domain_name_valid = normalized_names.len() == 1;
    let domain_name = normalized_names
        .into_iter()
        .next()
        .unwrap_or_else(|| domain.domain.clone());
    let action = status_v1_effective_action(domain.effective_action.as_deref());
    let action_valid = domain.effective_action.is_none() || action.is_some();
    let support = status_v1_support_disposition(
        &domain_name,
        domain.status.as_str(),
        domain.reason.as_deref(),
    );

    let (status, mut evidence_class) = match domain.status.as_str() {
        "ready" => {
            let valid = match domain_name.as_str() {
                "acl" => {
                    action == Some(NeutronStatusEffectiveAction::Enforce)
                        && support == NeutronStatusSupportDisposition::Supported
                }
                "attach" => {
                    action.is_none() && support == NeutronStatusSupportDisposition::Supported
                }
                _ => false,
            };
            (
                NeutronStatusDomainState::Ready,
                if valid {
                    StatusV1EvidenceClass::Ready
                } else {
                    StatusV1EvidenceClass::Blocked
                },
            )
        }
        "not_requested" => {
            let valid = domain_name == "acl"
                && matches!(
                    action,
                    Some(NeutronStatusEffectiveAction::Bypass)
                        | Some(NeutronStatusEffectiveAction::NoOp)
                )
                && support == NeutronStatusSupportDisposition::NotApplicable;
            (
                NeutronStatusDomainState::NotRequested,
                if valid {
                    StatusV1EvidenceClass::Ready
                } else {
                    StatusV1EvidenceClass::Blocked
                },
            )
        }
        "degraded" | "unsupported" => {
            let terminal = domain_name == "acl"
                && matches!(
                    action,
                    Some(NeutronStatusEffectiveAction::Bypass)
                        | Some(NeutronStatusEffectiveAction::Unchanged)
                );
            let evidence_class = if !terminal {
                StatusV1EvidenceClass::Blocked
            } else if status_v1_reason_requires_full_resync(domain.reason.as_deref()) {
                StatusV1EvidenceClass::FullResync
            } else {
                StatusV1EvidenceClass::TerminalDegraded
            };
            (NeutronStatusDomainState::Degraded, evidence_class)
        }
        "blocked" | "error" | "recovered" | "detached" => (
            NeutronStatusDomainState::Blocked,
            StatusV1EvidenceClass::Blocked,
        ),
        _ => (
            NeutronStatusDomainState::Blocked,
            StatusV1EvidenceClass::Blocked,
        ),
    };

    if !domain_name_valid || !action_valid {
        evidence_class = StatusV1EvidenceClass::Blocked;
    }

    (
        NeutronStatusDomainEvidence {
            domain: domain_name,
            status,
            reason: domain.reason.clone(),
            effective_action: action,
            support_disposition: support,
        },
        evidence_class,
    )
}

fn project_status_v1_port_row(status: &NeutronPortStatus) -> ProjectedStatusV1PortRow {
    let mut domain_class = StatusV1EvidenceClass::Ready;
    let mut domain_names = BTreeSet::new();
    let mut domains_valid = true;
    let mut domains = Vec::with_capacity(status.domains.len());
    for domain in &status.domains {
        let (evidence, evidence_class) = project_status_v1_domain(domain);
        if evidence.domain.trim().is_empty() || !domain_names.insert(evidence.domain.clone()) {
            domains_valid = false;
        }
        domain_class = domain_class.max(evidence_class);
        domains.push(evidence);
    }
    if !domains_valid {
        domain_class = StatusV1EvidenceClass::Blocked;
    }

    ProjectedStatusV1PortRow {
        evidence: NeutronStatusPortEvidence {
            port_id: status.port_id.clone(),
            ifname: status.ifname.clone(),
            generation: status.generation,
            desired_hash: status.desired_hash.clone(),
            status: status.status.clone(),
            reason: status.reason.clone(),
            managed_domains: status.managed_domains.clone(),
            domains,
        },
        domain_class,
        domain_names,
        domains_valid,
    }
}

fn status_v1_port_top_level_class(
    status: &NeutronPortStatus,
    projected: &ProjectedStatusV1PortRow,
) -> StatusV1EvidenceClass {
    match status.status.as_str() {
        "ready" if projected.domain_class == StatusV1EvidenceClass::Ready => {
            StatusV1EvidenceClass::Ready
        }
        "not_requested"
            if projected.evidence.domains.len() == 1
                && projected.evidence.domains[0].domain == "acl"
                && projected.evidence.domains[0].status
                    == NeutronStatusDomainState::NotRequested
                && matches!(
                    projected.evidence.domains[0].effective_action,
                    Some(NeutronStatusEffectiveAction::Bypass)
                        | Some(NeutronStatusEffectiveAction::NoOp)
                )
                && projected.evidence.domains[0].support_disposition
                    == NeutronStatusSupportDisposition::NotApplicable =>
        {
            StatusV1EvidenceClass::Ready
        }
        "degraded" | "unsupported"
            if matches!(
                projected.domain_class,
                StatusV1EvidenceClass::TerminalDegraded | StatusV1EvidenceClass::FullResync
            ) =>
        {
            if projected.domain_class == StatusV1EvidenceClass::FullResync
                || status_v1_reason_requires_full_resync(status.reason.as_deref())
            {
                StatusV1EvidenceClass::FullResync
            } else {
                StatusV1EvidenceClass::TerminalDegraded
            }
        }
        _ => StatusV1EvidenceClass::Blocked,
    }
}

fn status_v1_allows_empty_ifname(
    status: &NeutronPortStatus,
    projected: &ProjectedStatusV1PortRow,
    status_domains: &[String],
) -> bool {
    if !matches!(status.status.as_str(), "degraded" | "unsupported")
        || status_domains.len() != 1
        || status_domains[0] != "acl"
        || projected.evidence.domains.len() != 1
    {
        return false;
    }

    let acl = &projected.evidence.domains[0];
    acl.domain == "acl"
        && acl.status == NeutronStatusDomainState::Degraded
        && acl.effective_action == Some(NeutronStatusEffectiveAction::Bypass)
        && acl.support_disposition == NeutronStatusSupportDisposition::Unsupported
}

fn project_status_v1_detached_tombstone(
    runtime: &NeutronRuntimeState,
    status_map_key: &str,
    status: &NeutronPortStatus,
) -> Option<NeutronStatusPortEvidence> {
    if status_map_key.is_empty()
        || status_map_key != status.port_id.as_str()
        || status.ifname.is_empty()
        || status.status != "detached"
        || status.generation == 0
        || status.generation > runtime.applied_generation
    {
        return None;
    }
    let desired_hash = status
        .desired_hash
        .as_deref()
        .filter(|hash| !hash.trim().is_empty())?;
    if status.generation == runtime.applied_generation
        && runtime.applied_desired_hash.as_deref() != Some(desired_hash)
    {
        return None;
    }

    let managed_domains = status_v1_normalized_unique_domains(&status.managed_domains)?;
    let managed_domain_set = managed_domains.iter().cloned().collect::<BTreeSet<_>>();
    let mut domain_names = BTreeSet::new();
    let mut domains = Vec::with_capacity(status.domains.len());
    for domain in &status.domains {
        let normalized = status_v1_normalized_unique_domains(std::slice::from_ref(&domain.domain))?;
        let domain_name = normalized.into_iter().next()?;
        if !domain_names.insert(domain_name.clone())
            || !managed_domain_set.contains(&domain_name)
            || domain.status != "detached"
            || domain.effective_action.is_some()
        {
            return None;
        }
        domains.push(NeutronStatusDomainEvidence {
            domain: domain_name,
            status: NeutronStatusDomainState::NotRequested,
            reason: domain.reason.clone(),
            effective_action: Some(NeutronStatusEffectiveAction::Cleanup),
            support_disposition: NeutronStatusSupportDisposition::NotApplicable,
        });
    }

    Some(NeutronStatusPortEvidence {
        port_id: status.port_id.clone(),
        ifname: status.ifname.clone(),
        generation: status.generation,
        desired_hash: status.desired_hash.clone(),
        status: status.status.clone(),
        reason: status.reason.clone(),
        managed_domains,
        domains,
    })
}

fn project_status_v1_ports(
    runtime: &NeutronRuntimeState,
) -> (Vec<NeutronStatusPortEvidence>, StatusV1EvidenceClass) {
    let mut projected_rows = Vec::with_capacity(runtime.port_statuses.len());
    let mut aggregate = StatusV1EvidenceClass::Ready;

    for (managed_key, managed) in &runtime.ports {
        let Some(status) = runtime.port_statuses.get(managed_key) else {
            aggregate = StatusV1EvidenceClass::Blocked;
            continue;
        };
        let mut projected = project_status_v1_port_row(status);
        let managed_domains = status_v1_normalized_unique_domains(&managed.managed_domains);
        let status_domains = status_v1_normalized_unique_domains(&status.managed_domains);
        let top_level_class = status_v1_port_top_level_class(status, &projected);
        let mut ifname_valid =
            managed.ifname.as_str() == status.ifname.as_str() && !managed.ifname.is_empty();

        let mut valid = !managed_key.is_empty()
            && managed_key.as_str() == managed.port_id.as_str()
            && status.port_id.as_str() == managed_key.as_str()
            && projected.domains_valid
            && status.generation > 0
            && status.generation <= runtime.applied_generation
            && status
                .desired_hash
                .as_deref()
                .is_some_and(|hash| !hash.trim().is_empty());

        match (&managed_domains, &status_domains) {
            (Some(managed_domains), Some(status_domains)) if managed_domains == status_domains => {
                if managed.ifname.as_str() == status.ifname.as_str()
                    && managed.ifname.is_empty()
                    && status_v1_allows_empty_ifname(status, &projected, status_domains)
                {
                    ifname_valid = true;
                }
                let status_domain_set = status_domains.iter().cloned().collect::<BTreeSet<_>>();
                if !status_domain_set
                    .iter()
                    .all(|domain| projected.domain_names.contains(domain))
                    || projected
                        .domain_names
                        .iter()
                        .any(|domain| domain != "attach" && !status_domain_set.contains(domain))
                {
                    valid = false;
                }
                projected.evidence.managed_domains = status_domains.clone();
                projected
                    .evidence
                    .domains
                    .retain(|domain| status_domain_set.contains(&domain.domain));
            }
            _ => valid = false,
        }

        valid = valid && ifname_valid;

        if status.generation == runtime.applied_generation
            && status.desired_hash != runtime.applied_desired_hash
        {
            valid = false;
        }
        if valid {
            if top_level_class != StatusV1EvidenceClass::Blocked {
                aggregate = aggregate.max(top_level_class);
            } else {
                aggregate = StatusV1EvidenceClass::Blocked;
            }
            projected_rows.push(projected.evidence);
        } else {
            aggregate = StatusV1EvidenceClass::Blocked;
        }
    }

    for (status_key, status) in &runtime.port_statuses {
        if runtime.ports.contains_key(status_key) {
            continue;
        }
        match project_status_v1_detached_tombstone(runtime, status_key, status) {
            Some(tombstone) => projected_rows.push(tombstone),
            None => {
                aggregate = StatusV1EvidenceClass::Blocked;
            }
        }
    }

    projected_rows.sort_by(|left, right| left.port_id.cmp(&right.port_id));
    (projected_rows, aggregate)
}

fn status_v1_has_complete_pending_identity(runtime: &NeutronRuntimeState) -> bool {
    let Some(pending_generation) = runtime.pending_generation else {
        return false;
    };
    pending_generation > 0
        && (runtime.accepted_generation == runtime.applied_generation
            || runtime.accepted_generation == pending_generation)
        && pending_generation >= runtime.applied_generation
        && (pending_generation != runtime.applied_generation || runtime.applied_generation > 0)
        && runtime
            .desired_hash
            .as_deref()
            .is_some_and(|hash| !hash.trim().is_empty())
        && (runtime.applied_generation == 0
            || runtime
                .applied_desired_hash
                .as_deref()
                .is_some_and(|hash| !hash.trim().is_empty()))
        && (pending_generation != runtime.applied_generation
            || runtime.desired_hash == runtime.applied_desired_hash)
}

fn status_v1_has_classified_identity(runtime: &NeutronRuntimeState) -> bool {
    runtime.pending_generation.is_none()
        && runtime.accepted_generation == runtime.applied_generation
        && runtime.desired_hash == runtime.applied_desired_hash
        && if runtime.applied_generation == 0 {
            runtime.desired_hash.is_none() && runtime.applied_desired_hash.is_none()
        } else {
            runtime
                .applied_desired_hash
                .as_deref()
                .is_some_and(|hash| !hash.trim().is_empty())
        }
}

fn status_v1_is_generation_zero_inventory_recovery(runtime: &NeutronRuntimeState) -> bool {
    runtime.recovery_cause.as_deref() == Some(INVENTORY_UNAVAILABLE_RECOVERY_CAUSE)
        && status_v1_has_complete_pending_identity(runtime)
        && runtime
            .pending_generation
            .is_some_and(|pending| pending > 0 && pending == runtime.accepted_generation)
        && runtime.applied_generation == 0
        && runtime.applied_desired_hash.is_none()
        && runtime.ports.is_empty()
        && runtime.port_statuses.is_empty()
}

fn project_neutron_status_v1(runtime: &NeutronRuntimeState) -> NeutronStatusV1Projection {
    let (port_statuses, evidence_class) = project_status_v1_ports(runtime);
    let operator_blocked = || -> (
        NeutronStatusTransactionState,
        NeutronStatusOverallReadiness,
        NeutronStatusRequiredAction,
        Option<NeutronStatusRecoveryCause>,
    ) {
        (
            NeutronStatusTransactionState::Blocked,
            NeutronStatusOverallReadiness::Blocked,
            NeutronStatusRequiredAction::Operator,
            None,
        )
    };
    let unknown_recovery_cause = runtime
        .recovery_cause
        .as_deref()
        .is_some_and(|cause| cause != INVENTORY_UNAVAILABLE_RECOVERY_CAUSE);
    let idle = runtime.accepted_generation == 0
        && runtime.applied_generation == 0
        && runtime.pending_generation.is_none()
        && runtime.desired_hash.is_none()
        && runtime.applied_desired_hash.is_none()
        && runtime.ports.is_empty()
        && runtime.port_statuses.is_empty()
        && runtime.recovery_cause.is_none()
        && matches!(runtime.authority_state.as_str(), "" | "idle");

    let (transaction_state, overall_readiness, required_action, recovery_cause) =
        if runtime.wal_replay_failures > 0 || unknown_recovery_cause {
            operator_blocked()
        } else if idle {
            (
                NeutronStatusTransactionState::Idle,
                NeutronStatusOverallReadiness::Unknown,
                NeutronStatusRequiredAction::FullResync,
                None,
            )
        } else if runtime.pending_generation.is_some() {
            if !status_v1_has_complete_pending_identity(runtime) {
                operator_blocked()
            } else if runtime.recovery_cause.as_deref()
                == Some(INVENTORY_UNAVAILABLE_RECOVERY_CAUSE)
            {
                let protected_inventory_identity =
                    runtime.pending_generation == Some(runtime.accepted_generation);
                let allowed_baseline = protected_inventory_identity
                    && (runtime.applied_generation > 0
                        || status_v1_is_generation_zero_inventory_recovery(runtime));
                if allowed_baseline && runtime.authority_state == "blocked_recovery_required" {
                    (
                        NeutronStatusTransactionState::Blocked,
                        NeutronStatusOverallReadiness::Blocked,
                        NeutronStatusRequiredAction::RecoverPending,
                        Some(NeutronStatusRecoveryCause::InventoryUnavailable),
                    )
                } else {
                    operator_blocked()
                }
            } else if runtime.recovery_cause.is_some() {
                operator_blocked()
            } else {
                match runtime.authority_state.as_str() {
                    "applying" | "accepted" => (
                        NeutronStatusTransactionState::Pending,
                        NeutronStatusOverallReadiness::Unknown,
                        NeutronStatusRequiredAction::Poll,
                        None,
                    ),
                    "partial" | "blocked_recovery_required" | "recovered_pending_full_resync"
                        if runtime.applied_generation > 0 =>
                    {
                        (
                            NeutronStatusTransactionState::Blocked,
                            NeutronStatusOverallReadiness::Blocked,
                            NeutronStatusRequiredAction::RecoverPending,
                            None,
                        )
                    }
                    _ => operator_blocked(),
                }
            }
        } else if runtime.recovery_cause.is_some() {
            operator_blocked()
        } else if runtime.authority_state == "recovered_pending_full_resync_required"
            && status_v1_has_classified_identity(runtime)
            && evidence_class != StatusV1EvidenceClass::Blocked
        {
            (
                NeutronStatusTransactionState::Recovery,
                NeutronStatusOverallReadiness::Degraded,
                NeutronStatusRequiredAction::FullResync,
                None,
            )
        } else if runtime.applied_generation > 0 && status_v1_has_classified_identity(runtime) {
            match (runtime.authority_state.as_str(), evidence_class) {
                ("ready", StatusV1EvidenceClass::Ready) => (
                    NeutronStatusTransactionState::Classified,
                    NeutronStatusOverallReadiness::Ready,
                    NeutronStatusRequiredAction::None,
                    None,
                ),
                ("ready" | "runtime_degraded", StatusV1EvidenceClass::TerminalDegraded) => (
                    NeutronStatusTransactionState::Classified,
                    NeutronStatusOverallReadiness::Degraded,
                    NeutronStatusRequiredAction::None,
                    None,
                ),
                ("ready" | "runtime_degraded", StatusV1EvidenceClass::FullResync) => (
                    NeutronStatusTransactionState::Classified,
                    NeutronStatusOverallReadiness::Degraded,
                    NeutronStatusRequiredAction::FullResync,
                    None,
                ),
                (
                    "runtime_reconcile_requires_full_resync" | "degraded",
                    StatusV1EvidenceClass::Ready
                    | StatusV1EvidenceClass::TerminalDegraded
                    | StatusV1EvidenceClass::FullResync,
                ) => (
                    NeutronStatusTransactionState::Classified,
                    NeutronStatusOverallReadiness::Degraded,
                    NeutronStatusRequiredAction::FullResync,
                    None,
                ),
                _ => operator_blocked(),
            }
        } else {
            operator_blocked()
        };

    NeutronStatusV1Projection {
        transaction_state,
        overall_readiness,
        required_action,
        recovery_cause,
        last_classified_generation: runtime.applied_generation,
        port_statuses,
    }
}

fn project_neutron_status_v2(
    runtime: &NeutronRuntimeState,
    durable_partial_retryable: bool,
) -> NeutronStatusV1Projection {
    let mut projection = project_neutron_status_v1(runtime);
    if durable_partial_retryable {
        projection.transaction_state = NeutronStatusTransactionState::Blocked;
        projection.overall_readiness = NeutronStatusOverallReadiness::Blocked;
        projection.required_action = NeutronStatusRequiredAction::RetrySnapshot;
        projection.recovery_cause = None;
    }
    projection
}

/// Build the optional counters v1 section for a status response.
///
/// Best-effort by design: reads the shared managed pin path maps once and maps
/// rows back to managed ports via the registry's ifname -> tap_id snapshot.
/// Any tap id without a managed port is dropped; ports without a tap id are
/// skipped. Map iteration is bounded (512 rows/port) and fast enough for the
/// status handler; a read failure degrades only this section.
fn build_neutron_counters_section(
    state: &NeutronApiState,
    ports: &BTreeMap<String, ManagedNeutronPort>,
    tap_ids: &std::collections::HashMap<String, u32>,
) -> Option<NeutronStatusCountersV1> {
    let sampled_at_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    let error_section = |reason: String| NeutronStatusCountersV1 {
        counters_schema_version: NEUTRON_COUNTERS_SCHEMA_VERSION,
        sampled_at_ms,
        counters_error: Some(reason),
        ports: Vec::new(),
    };

    let mut tap_to_port: BTreeMap<u32, String> = BTreeMap::new();
    let mut tap_list: Vec<u32> = Vec::new();
    for port in ports.values() {
        if let Some(tap_id) = tap_ids.get(&port.ifname).copied() {
            tap_to_port.insert(tap_id, port.port_id.clone());
            tap_list.push(tap_id);
        }
    }
    if tap_list.is_empty() {
        return Some(NeutronStatusCountersV1 {
            counters_schema_version: NEUTRON_COUNTERS_SCHEMA_VERSION,
            sampled_at_ms,
            counters_error: None,
            ports: Vec::new(),
        });
    }
    tap_list.sort_unstable();
    tap_list.dedup();

    let pin_path = state.control_plane.managed_pin_path();
    let summaries = match read_port_counters(&pin_path, &tap_list) {
        Ok(summaries) => summaries,
        Err(error) => return Some(error_section(error)),
    };
    let mut counter_ports = Vec::new();
    for summary in summaries {
        let Some(port_id) = tap_to_port.get(&summary.tap_id) else {
            continue;
        };
        let mut buckets: Vec<NeutronCounterBucketV1> = summary
            .buckets
            .iter()
            .take(NEUTRON_MAX_COUNTER_BUCKET_ROWS_PER_PORT)
            .map(|b| NeutronCounterBucketV1 {
                src_id: b.src_id,
                dst_id: b.dst_id,
                proto: b.proto,
                direction: b.direction,
                packets: b.packets,
                bytes: b.bytes,
                dropped_packets: b.dropped_packets,
                dropped_bytes: b.dropped_bytes,
            })
            .collect();
        buckets.sort_by(|a, b| b.bytes.cmp(&a.bytes));
        let reasons: Vec<NeutronCounterReasonV1> = summary
            .reasons
            .iter()
            .map(|r| NeutronCounterReasonV1 {
                reason: r.reason,
                direction: r.direction,
                proto: r.proto,
                packets: r.packets,
                bytes: r.bytes,
            })
            .collect();
        counter_ports.push(NeutronPortCountersV1 {
            port_id: port_id.clone(),
            tap_id: summary.tap_id,
            policy_packets: summary.policy_packets,
            policy_bytes: summary.policy_bytes,
            policy_allow_packets: summary.policy_allow_packets,
            policy_dropped_packets: summary.policy_dropped_packets,
            policy_dropped_bytes: summary.policy_dropped_bytes,
            drop_packets: summary.drop_packets,
            drop_bytes: summary.drop_bytes,
            truncated: summary.truncated,
            buckets,
            reasons,
        });
    }
    Some(NeutronStatusCountersV1 {
        counters_schema_version: NEUTRON_COUNTERS_SCHEMA_VERSION,
        sampled_at_ms,
        counters_error: None,
        ports: counter_ports,
    })
}

async fn build_neutron_status_response(state: &NeutronApiState) -> NeutronStatusV1Response {
    let runtime = state.runtime.read().await;
    let durable_partial_retryable =
        validate_durable_partial_retry_barrier(state, &runtime).is_ok();
    let projection = project_neutron_status_v2(&runtime, durable_partial_retryable);
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
    let counters_ports = runtime.ports.clone();
    let counters_tap_ids = state.registry.tap_ids_by_ifname().await;
    drop(runtime);

    let counters = build_neutron_counters_section(state, &counters_ports, &counters_tap_ids);

    NeutronStatusV1Response {
        status_schema_version: NEUTRON_STATUS_SCHEMA_VERSION_MAX,
        status_contract_hash: NEUTRON_STATUS_CONTRACT_HASH.to_string(),
        transaction_state: projection.transaction_state,
        overall_readiness: projection.overall_readiness,
        required_action: projection.required_action,
        recovery_cause: projection.recovery_cause,
        last_classified_generation: projection.last_classified_generation,
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
        port_statuses: projection.port_statuses,
        active_instances: state.registry.list().await,
        counters,
    }
}

async fn get_neutron_status(State(state): State<NeutronApiState>) -> impl IntoResponse {
    Json(build_neutron_status_response(&state).await)
}

async fn get_neutron_readiness(State(state): State<NeutronApiState>) -> impl IntoResponse {
    let response = build_neutron_status_response(&state).await;
    let status = if response.overall_readiness == NeutronStatusOverallReadiness::Ready {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    (status, Json(response))
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
    same_generation_retry: bool,
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

#[derive(Debug)]
enum PendingSnapshotDisposition {
    None,
    Deduplicated(NeutronSnapshotResponse),
    RetryablePartial,
}

fn snapshot_retry_not_safe(details: impl Into<String>) -> SnapshotApplyError {
    SnapshotApplyError {
        status: StatusCode::CONFLICT,
        code: "snapshot_retry_not_safe",
        details: details.into(),
    }
}

fn validate_durable_partial_retry_barrier(
    state: &NeutronApiState,
    runtime: &NeutronRuntimeState,
) -> Result<(), SnapshotApplyError> {
    if runtime.authority_state != "partial"
        || runtime.recovery_cause.is_some()
        || runtime.wal_replay_failures > 0
        || runtime.pending_generation != Some(runtime.accepted_generation)
        || !status_v1_has_complete_pending_identity(runtime)
    {
        return Err(snapshot_retry_not_safe(
            "pending snapshot is not a complete ordinary partial transaction",
        ));
    }

    let replay = state.wal.replay();
    if replay.failures > 0 {
        return Err(snapshot_retry_not_safe(format!(
            "Neutron WAL replay reported {} failure(s)",
            replay.failures
        )));
    }
    if replay.pending_intent.is_some() {
        return Err(snapshot_retry_not_safe(
            "Neutron WAL contains an unresolved intent",
        ));
    }

    let mut durable_state = replay.state;
    durable_state.status_hash = None;
    if durable_state != runtime.to_wal_state() {
        return Err(snapshot_retry_not_safe(
            "durable Neutron WAL state does not match the live partial state",
        ));
    }
    Ok(())
}

fn pending_snapshot_submit_disposition(
    runtime: &NeutronRuntimeState,
    snapshot: &NeutronSnapshotRequest,
    requested_hash: &Option<String>,
) -> Result<PendingSnapshotDisposition, SnapshotApplyError> {
    let Some(pending_generation) = runtime.pending_generation else {
        return Ok(PendingSnapshotDisposition::None);
    };
    if snapshot.generation != pending_generation
        || !hashes_match(requested_hash, &runtime.desired_hash)
    {
        return Err(SnapshotApplyError {
            status: StatusCode::CONFLICT,
            code: "snapshot_apply_in_progress",
            details: format!(
                "pending generation {} is still applying",
                pending_generation
            ),
        });
    }
    if runtime.authority_state == "partial" {
        info!(
            generation = snapshot.generation,
            desired_hash = ?requested_hash,
            pending_generation,
            retry_disposition = "retryable_partial",
            "neutron_snapshot_submit_retry_candidate"
        );
        return Ok(PendingSnapshotDisposition::RetryablePartial);
    }
    if !matches!(runtime.authority_state.as_str(), "applying" | "accepted") {
        return Err(snapshot_retry_not_safe(format!(
            "pending generation {} is in non-retryable state {}",
            pending_generation, runtime.authority_state
        )));
    }
    info!(
        generation = snapshot.generation,
        desired_hash = ?requested_hash,
        pending_generation,
        retry_disposition = "deduplicated",
        "neutron_snapshot_submit_deduplicated_pending"
    );
    Ok(PendingSnapshotDisposition::Deduplicated(
        neutron_snapshot_response(
            pending_generation,
            requested_hash.clone(),
            runtime.accepted_generation,
            runtime.applied_generation,
            "pending",
            Vec::new(),
            Vec::new(),
        ),
    ))
}

async fn accept_neutron_snapshot_submit(
    state: &NeutronApiState,
    snapshot: &NeutronSnapshotRequest,
    scope: &ApplyScope,
) -> Result<SnapshotSubmitDecision, SnapshotApplyError> {
    validate_snapshot_preflight(scope, snapshot)?;
    state.require_restore_ready()?;
    let requested_hash = snapshot.desired_hash.clone();
    if let PendingSnapshotDisposition::Deduplicated(mut response) = {
        let runtime = state.runtime.read().await;
        pending_snapshot_submit_disposition(&runtime, snapshot, &requested_hash)?
    } {
        response.active_instances = state.registry.list().await;
        return Ok(SnapshotSubmitDecision {
            response,
            prepared: None,
        });
    }

    let mut lock_wait_ms = 0;
    let mut admission_attempt = 0;
    let (apply_guard, local_inventory, runtime_before_apply) = loop {
        admission_attempt += 1;
        let lock_started = Instant::now();
        let observation_guard = state.apply_lock.clone().lock_owned().await;
        lock_wait_ms += elapsed_ms(lock_started);
        let observed_runtime = state.runtime.read().await.clone();
        match pending_snapshot_submit_disposition(
            &observed_runtime,
            snapshot,
            &requested_hash,
        )? {
            PendingSnapshotDisposition::Deduplicated(mut response) => {
                drop(observation_guard);
                response.active_instances = state.registry.list().await;
                return Ok(SnapshotSubmitDecision {
                    response,
                    prepared: None,
                });
            }
            PendingSnapshotDisposition::RetryablePartial => {
                validate_durable_partial_retry_barrier(state, &observed_runtime)?;
            }
            PendingSnapshotDisposition::None => {}
        }
        let observed_identity = SnapshotAdmissionIdentity::capture(&observed_runtime);
        drop(observation_guard);

        let local_inventory = LocalInterfaceInventory::load(&state.ovs_bridge).await;

        let lock_started = Instant::now();
        let apply_guard = state.apply_lock.clone().lock_owned().await;
        lock_wait_ms += elapsed_ms(lock_started);
        let runtime_before_apply = state.runtime.read().await.clone();
        if SnapshotAdmissionIdentity::capture(&runtime_before_apply) == observed_identity {
            if matches!(
                pending_snapshot_submit_disposition(
                    &runtime_before_apply,
                    snapshot,
                    &requested_hash,
                )?,
                PendingSnapshotDisposition::RetryablePartial
            ) {
                validate_durable_partial_retry_barrier(state, &runtime_before_apply)?;
            }
            break (apply_guard, local_inventory, runtime_before_apply);
        }
        drop(apply_guard);
        if admission_attempt >= SNAPSHOT_ADMISSION_REVALIDATION_ATTEMPTS {
            return Err(SnapshotApplyError {
                status: StatusCode::CONFLICT,
                code: "snapshot_admission_changed",
                details: format!(
                    "snapshot admission changed during OVS discovery after {} attempts",
                    admission_attempt
                ),
            });
        }
    };
    let preflight_started = Instant::now();

    if let Some(mut response) = snapshot_early_response_for_scope(
        scope,
        &runtime_before_apply,
        snapshot,
        &local_inventory,
        &requested_hash,
    )? {
        let verification_targets = managed_acl_projection_verification_targets(
            scope,
            &runtime_before_apply,
            snapshot,
        );
        if response.status != "noop"
            || verify_managed_acl_noop_projection(
                state,
                &verification_targets,
                snapshot.generation,
            )
            .await
        {
            response.active_instances = state.registry.list().await;
            return Ok(SnapshotSubmitDecision {
                response,
                prepared: None,
            });
        }
    }

    let current_ports = runtime_before_apply.ports.clone();
    let same_generation_retry = runtime_before_apply.authority_state == "partial"
        && runtime_before_apply.pending_generation == Some(snapshot.generation)
        && hashes_match(&runtime_before_apply.desired_hash, &requested_hash);
    let transaction = build_snapshot_apply_transaction(
        &current_ports,
        snapshot,
        &local_inventory,
        scope.clone(),
    )
    .map_err(snapshot_scope_apply_error)?;
    let recovery_cause = transaction
        .plan
        .inventory_error
        .is_some()
        .then(|| INVENTORY_UNAVAILABLE_RECOVERY_CAUSE.to_string());
    let recovery_port_ids = if recovery_cause.is_some() {
        Vec::new()
    } else {
        transaction.requested_port_ids.clone()
    };
    let intent = PendingNeutronIntent {
        kind: "snapshot".to_string(),
        generation: snapshot.generation,
        desired_hash: requested_hash.clone(),
        port_ids: recovery_port_ids,
        affected_domains: transaction.affected_domains.clone(),
        affected_ports: transaction.affected_ports.clone(),
        recovery_cause,
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
            intent.recovery_cause.clone(),
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
            same_generation_retry,
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

async fn handle_snapshot_after_intent_fault(
    state: &NeutronApiState,
    intent: &PendingNeutronIntent,
    previous: &NeutronRuntimeState,
    fault: Result<(), String>,
) -> Result<(), SnapshotApplyError> {
    let Err(details) = fault else {
        return Ok(());
    };

    let mut blocked = build_blocked_snapshot_runtime(
        previous,
        intent,
        BTreeMap::new(),
        "background_apply_failed:fault_injection",
    );
    if let Err(error) = state.wal.append_snapshot_commit(blocked.to_wal_state()) {
        blocked.authority_state = "pending_recovery_commit_failed".to_string();
        blocked.wal_status = "commit_failed".to_string();
        warn!(
            generation = intent.generation,
            desired_hash = ?intent.desired_hash,
            error = %error,
            "failed to commit preapply snapshot failure state"
        );
    }
    {
        let mut runtime = state.runtime.write().await;
        *runtime = blocked;
    }

    Err(SnapshotApplyError {
        status: StatusCode::INTERNAL_SERVER_ERROR,
        code: "fault_injection",
        details,
    })
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

    let inventory_unavailable =
        intent.recovery_cause.as_deref() == Some(INVENTORY_UNAVAILABLE_RECOVERY_CAUSE);
    let wal_status = if inventory_unavailable {
        INVENTORY_UNAVAILABLE_RECOVERY_CAUSE
    } else {
        "commit_failed"
    };
    let mut blocked =
        build_blocked_snapshot_runtime(previous, intent, blocked_statuses, wal_status);
    if inventory_unavailable {
        blocked.accepted_generation = intent.generation;
        blocked.recovery_cause = Some(INVENTORY_UNAVAILABLE_RECOVERY_CAUSE.to_string());
    }
    if let Err(error) = state.wal.append_snapshot_commit(blocked.to_wal_state()) {
        if !inventory_unavailable {
            blocked.wal_status = "recovery_commit_failed".to_string();
        }
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
        same_generation_retry,
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
        same_generation_retry,
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
    handle_snapshot_after_intent_fault(
        &state,
        &intent,
        &runtime_before_apply,
        fault_injection::check("neutron.snapshot.after_intent").await,
    )
    .await?;

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
    let SnapshotApplyTransaction { scope, plan, .. } = transaction;
    let full_resync = matches!(&scope, ApplyScope::FullHost);
    let scope_name = apply_scope_name(&scope);
    let scope_port_id = apply_scope_port_id(&scope).map(|value| value.to_string());
    let SnapshotPlan {
        attach,
        update,
        detach,
        ignored,
        inventory_error,
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
    let mut results = ignored;
    if let Some(reason) = inventory_error {
        results.push(transaction_result(
            "snapshot",
            "",
            "ignore",
            "error",
            Some(reason.as_str()),
        ));
        let previous_applied_generation = runtime_before_apply.applied_generation;
        let mut next_runtime = runtime_before_apply.clone();
        next_runtime.accepted_generation = generation;
        next_runtime.desired_hash = requested_hash;
        next_runtime.pending_generation = Some(generation);
        next_runtime.authority_state = "blocked_recovery_required".to_string();
        next_runtime.wal_status = INVENTORY_UNAVAILABLE_RECOVERY_CAUSE.to_string();
        next_runtime.recovery_cause = Some(INVENTORY_UNAVAILABLE_RECOVERY_CAUSE.to_string());
        return SnapshotRuntimeApplyOutcome {
            next_runtime,
            previous_applied_generation,
            results,
            has_error: true,
        };
    }

    let mut next_ports = current_ports;
    let mut next_statuses = port_status_seed_for_scope(&runtime_before_apply, &scope);
    let mut acl_validation_cache = AclValidationCache::default();

    for port in detach {
        let port_started = Instant::now();
        let port_id = port.port_id.clone();
        let ifname = port.ifname.clone();
        let purge_started = Instant::now();
        if let Err(e) = purge_neutron_acl_transactionally(state, &port.ifname, &port.port_id).await {
            let reason = format!("neutron_acl_purge_failed:{}", e.details);
            warn!(port_id = %port.port_id, ifname = %port.ifname, error = %e.details,
                "keeping attached Neutron interface quiesced after ACL purge failure");
            next_statuses.insert(
                port.port_id.clone(),
                port_runtime_status(
                    &port.port_id,
                    &port.ifname,
                    generation,
                    requested_hash.clone(),
                    port.managed_domains.clone(),
                    "error",
                    Some(reason.clone()),
                    domain_statuses_for(&port.managed_domains, "error", Some(reason.clone())),
                ),
            );
            results.push(NeutronPortApplyResult {
                port_id: port.port_id,
                ifname: port.ifname,
                action: "detach".to_string(),
                status: "error".to_string(),
                reason: Some(reason),
            });
            continue;
        }
        let purge_ms = elapsed_ms(purge_started);
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
        let unsupported_managed_domains =
            unsupported_neutron_managed_domains(&port.managed_domains);
        if !unsupported_managed_domains.is_empty() {
            let reason = blocked_by_unimplemented_domains(&unsupported_managed_domains);
            next_statuses.insert(
                managed.port_id.clone(),
                port_runtime_status(
                    &managed.port_id,
                    &managed.ifname,
                    generation,
                    requested_hash.clone(),
                    managed.managed_domains.clone(),
                    "error",
                    Some(reason.clone()),
                    domain_statuses_for(&managed.managed_domains, "error", Some(reason.clone())),
                ),
            );
            results.push(NeutronPortApplyResult {
                port_id: managed.port_id,
                ifname: managed.ifname,
                action: "update".to_string(),
                status: "error".to_string(),
                reason: Some(reason),
            });
            info!(
                generation,
                desired_hash = ?requested_hash,
                port_id = %port.port_id,
                ifname = %port.ifname,
                action = "update",
                status = "error",
                total_ms = elapsed_ms(port_started),
                "neutron_port_apply_profile"
            );
            continue;
        }
        let previous_managed = next_ports.get(&port.port_id).cloned();
        let previous_status = runtime_before_apply.port_statuses.get(&port.port_id);
        if let Err(error) = state
            .registry
            .attach_neutron(&port.ifname, port_manages_acl(&port))
            .await
        {
            let reason = format!("managed_acl_ownership_sync_failed:{}", error);
            next_statuses.insert(
                managed.port_id.clone(),
                port_runtime_status(
                    &managed.port_id,
                    &managed.ifname,
                    generation,
                    requested_hash.clone(),
                    managed.managed_domains.clone(),
                    "error",
                    Some(reason.clone()),
                    domain_statuses_for(&managed.managed_domains, "error", Some(reason.clone())),
                ),
            );
            results.push(NeutronPortApplyResult {
                port_id: managed.port_id,
                ifname: managed.ifname,
                action: "update".to_string(),
                status: "error".to_string(),
                reason: Some(reason),
            });
            info!(
                generation,
                desired_hash = ?requested_hash,
                port_id = %port.port_id,
                ifname = %port.ifname,
                action = "update",
                status = "error",
                total_ms = elapsed_ms(port_started),
                "neutron_port_apply_profile"
            );
            continue;
        }
        let projection_health = state
            .control_plane
            .managed_projection_health(&managed.ifname)
            .await;
        let requires_managed_acl = normalize_managed_domains(&managed.managed_domains)
            .iter()
            .any(|domain| domain == "acl");
        let required_publication_mode = required_neutron_publication_mode(requires_managed_acl);
        let required_projection_health =
            requires_managed_acl.then_some(ManagedProjectionHealth::Verified);
        if can_skip_neutron_domain_reconcile(
            previous_managed.as_ref(),
            previous_status,
            &managed,
            full_resync,
            projection_health,
        ) && state
            .control_plane
            .mark_neutron_port_authority_if_current(
                &managed.ifname,
                &managed.port_id,
                &managed.managed_domains,
                generation,
                required_publication_mode,
                required_projection_health,
            )
            .await
        {
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
        let mut domain_result =
            reconcile_neutron_domains(state, &port, &mut acl_validation_cache, full_resync).await;
        if domain_result.ok
            && !state
                .control_plane
                .mark_neutron_port_authority_if_current(
                    &managed.ifname,
                    &managed.port_id,
                    &managed.managed_domains,
                    generation,
                    required_publication_mode,
                    required_projection_health,
                )
                .await
        {
            let reason = "managed_instance_detached_during_authority_commit".to_string();
            domain_result = DomainReconcileResult {
                domains: domain_statuses_for(
                    &managed.managed_domains,
                    "error",
                    Some(reason.clone()),
                ),
                ok: false,
                reason: Some(reason),
            };
        }
        let domain_ms = elapsed_ms(port_started);
        if domain_result.ok {
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

    for port in &attach {
        let port_started = Instant::now();
        let port_id = port.port_id.clone();
        let ifname = port.ifname.clone();
        let managed = managed_port_from_snapshot(port);
        let unsupported_managed_domains =
            unsupported_neutron_managed_domains(&port.managed_domains);
        if !unsupported_managed_domains.is_empty() {
            let reason = blocked_by_unimplemented_domains(&unsupported_managed_domains);
            next_statuses.insert(
                managed.port_id.clone(),
                port_runtime_status(
                    &managed.port_id,
                    &managed.ifname,
                    generation,
                    requested_hash.clone(),
                    managed.managed_domains.clone(),
                    "error",
                    Some(reason.clone()),
                    domain_statuses_for(&managed.managed_domains, "error", Some(reason.clone())),
                ),
            );
            results.push(NeutronPortApplyResult {
                port_id: managed.port_id,
                ifname: managed.ifname,
                action: "attach".to_string(),
                status: "error".to_string(),
                reason: Some(reason),
            });
            info!(
                generation,
                desired_hash = ?requested_hash,
                port_id = %port_id,
                ifname = %ifname,
                action = "attach",
                status = "error",
                total_ms = elapsed_ms(port_started),
                "neutron_port_apply_profile"
            );
            continue;
        }
        let attach_started = Instant::now();
        match state
            .registry
            .attach_neutron(&port.ifname, port_manages_acl(port))
            .await
        {
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
                        port_id: port.port_id.clone(),
                        ifname: port.ifname.clone(),
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
                let manages_acl = port_manages_acl(port);
                let required_publication_mode = required_neutron_publication_mode(manages_acl);
                let required_projection_health =
                    manages_acl.then_some(ManagedProjectionHealth::Verified);
                let domain_started = Instant::now();
                let mut domain_result =
                    reconcile_neutron_domains(state, port, &mut acl_validation_cache, full_resync)
                        .await;
                if domain_result.ok
                    && !state
                        .control_plane
                        .mark_neutron_port_authority_if_current(
                            &managed.ifname,
                            &managed.port_id,
                            &managed.managed_domains,
                            generation,
                            required_publication_mode,
                            required_projection_health,
                        )
                        .await
                {
                    let reason = "managed_instance_detached_during_authority_commit".to_string();
                    domain_result = DomainReconcileResult {
                        domains: domain_statuses_for(
                            &managed.managed_domains,
                            "error",
                            Some(reason.clone()),
                        ),
                        ok: false,
                        reason: Some(reason),
                    };
                }
                let domain_ms = elapsed_ms(domain_started);
                if domain_result.ok {
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
                    let domain_error_reason = domain_result
                        .reason
                        .clone()
                        .unwrap_or_else(|| "unknown_domain_reconcile_error".to_string());
                    let purge_failed = if let Err(purge_err) =
                        purge_neutron_acl_transactionally(state, &port.ifname, &port.port_id).await
                    {
                        warn!(
                            port_id = %port.port_id,
                            ifname = %port.ifname,
                            error = %purge_err.details,
                            "keeping attached Neutron interface quiesced after ACL purge failure"
                        );
                        true
                    } else {
                        false
                    };
                    if !purge_failed {
                        if let Err(detach_err) = state.registry.detach(&port.ifname).await {
                        warn!(
                            port_id = %port.port_id,
                            ifname = %port.ifname,
                            error = %detach_err,
                            "failed to detach after Neutron domain apply failure"
                        );
                        }
                    }
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
                        reason = %domain_error_reason,
                        attach_ms,
                        domain_ms,
                        total_ms = elapsed_ms(port_started),
                        "neutron_port_apply_profile"
                    );
                }
            }
            Err(e) => {
                let attach_ms = elapsed_ms(attach_started);
                let attach_error_reason = e.clone();
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
                    port_id: port.port_id.clone(),
                    ifname: port.ifname.clone(),
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
                    reason = %attach_error_reason,
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
    if snapshot.generation == 0 {
        return Err(SnapshotApplyError {
            status: StatusCode::BAD_REQUEST,
            code: "INVALID_SNAPSHOT_GENERATION",
            details: "snapshot generation zero is reserved; submitted generations must start at one"
                .to_string(),
        });
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
    if plan.inventory_error.is_some() {
        return true;
    }
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

fn managed_acl_projection_verification_targets(
    scope: &ApplyScope,
    runtime: &NeutronRuntimeState,
    snapshot: &NeutronSnapshotRequest,
) -> Vec<String> {
    snapshot
        .ports
        .iter()
        .filter(|port| match scope {
            ApplyScope::FullHost => true,
            ApplyScope::SinglePort(target_port_id) => &port.port_id == target_port_id,
        })
        .filter(|port| {
            normalize_managed_domains(&port.managed_domains)
                .iter()
                .any(|domain| domain == "acl")
        })
        .filter_map(|port| runtime.ports.get(&port.port_id))
        .map(|port| port.ifname.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

async fn verify_managed_acl_noop_projection(
    state: &NeutronApiState,
    targets: &[String],
    generation: u64,
) -> bool {
    for ifname in targets {
        if let Err(error) = state
            .control_plane
            .verify_and_mark_managed_projection(ifname)
            .await
        {
            warn!(
                generation,
                ifname = %ifname,
                error = %error,
                "same-generation managed ACL projection requires reconcile"
            );
            return false;
        }
    }
    true
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
    next_runtime.recovery_cause = None;
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

fn defer_missing_committed_interfaces(
    results: &mut [RuntimeReconcileResult],
    missing_ifnames: &BTreeSet<String>,
) -> bool {
    let mut deferred = false;
    for result in results {
        if result.action == "claim_committed"
            && result.status == "blocked"
            && missing_ifnames.contains(&result.ifname)
        {
            result.status = "deferred".to_string();
            result.reason = Some(RUNTIME_REBUILD_REQUIRED_REASON.to_string());
            deferred = true;
        }
    }
    deferred
}

fn project_committed_runtime_reconcile(
    previous_runtime: &NeutronRuntimeState,
    ports: &[ManagedNeutronPort],
    generation: u64,
    desired_hash: Option<String>,
    results: &[RuntimeReconcileResult],
    missing_runtime_requires_full_resync: bool,
) -> Option<NeutronRuntimeState> {
    if results.is_empty() {
        return None;
    }

    let mut next_runtime = previous_runtime.clone();
    let mut degraded = results.iter().any(|result| result.status == "blocked");
    let mut successfully_claimed_ports = Vec::new();
    for port in ports {
        let Some(result) = results
            .iter()
            .find(|result| result.ifname == port.ifname && result.action == "claim_committed")
        else {
            continue;
        };
        if result.status == "deferred" {
            if let Some(managed) = next_runtime.ports.get_mut(&port.port_id) {
                managed.ifindex = None;
                managed.domain_desired_hashes.remove("acl");
            }
            next_runtime.port_statuses.insert(
                port.port_id.clone(),
                runtime_rebuild_port_status(port, generation, desired_hash.clone()),
            );
            continue;
        }
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

    let acl_requires_full_resync =
        invalidate_restarted_acl_runtime(&mut next_runtime, &successfully_claimed_ports);

    if degraded {
        next_runtime.authority_state = "runtime_degraded".to_string();
        next_runtime.wal_status = "runtime_reconcile_degraded".to_string();
    } else if (acl_requires_full_resync || missing_runtime_requires_full_resync)
        && next_runtime.pending_generation.is_none()
    {
        next_runtime.authority_state = "runtime_reconcile_requires_full_resync".to_string();
        next_runtime.wal_status = "runtime_reconciled_acl_resync_required".to_string();
    } else if next_runtime.pending_generation.is_none() {
        next_runtime.authority_state = "ready".to_string();
        next_runtime.wal_status = "runtime_reconciled".to_string();
    } else if next_runtime.wal_status != "intent_recovered" {
        next_runtime.wal_status = "runtime_reconciled".to_string();
    }

    Some(next_runtime)
}

fn runtime_rebuild_port_status(
    port: &ManagedNeutronPort,
    generation: u64,
    desired_hash: Option<String>,
) -> NeutronPortStatus {
    let domains = normalize_managed_domains(&port.managed_domains)
        .into_iter()
        .map(|domain| {
            if domain == "acl" {
                domain_status_with_action(
                    &domain,
                    "degraded",
                    Some(RUNTIME_REBUILD_REQUIRED_REASON.to_string()),
                    Some("bypass".to_string()),
                )
            } else {
                domain_status(
                    &domain,
                    "blocked",
                    Some(RUNTIME_REBUILD_REQUIRED_REASON.to_string()),
                )
            }
        })
        .collect();
    port_runtime_status(
        &port.port_id,
        &port.ifname,
        generation,
        desired_hash,
        port.managed_domains.clone(),
        "degraded",
        Some(RUNTIME_REBUILD_REQUIRED_REASON.to_string()),
        domains,
    )
}

fn should_retry_committed_runtime_reconcile(
    runtime: &NeutronRuntimeState,
    live_ifnames: &BTreeSet<String>,
) -> bool {
    if runtime.pending_generation.is_some()
        || !matches!(
            runtime.authority_state.as_str(),
            "recovered_pending_full_resync_required"
                | "runtime_reconcile_requires_full_resync"
        )
    {
        return false;
    }

    runtime.ports.values().any(|port| {
        if !live_ifnames.contains(&port.ifname) {
            return false;
        }
        match runtime.port_statuses.get(&port.port_id) {
            None => true,
            Some(status) => status.reason.as_deref() == Some(RUNTIME_REBUILD_REQUIRED_REASON),
        }
    })
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
    acl_validation_cache: &mut AclValidationCache,
    full_resync: bool,
) -> DomainReconcileResult {
    let domains = normalize_managed_domains(&port.managed_domains);
    if domains.is_empty() {
        return DomainReconcileResult {
            domains: Vec::new(),
            ok: true,
            reason: None,
        };
    }

    let unimplemented = unsupported_neutron_managed_domains(&port.managed_domains);
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
            "acl" => match reconcile_neutron_acl(
                state,
                port,
                acl_validation_cache,
                full_resync,
            )
            .await
            {
                Ok(outcome) => statuses.push(outcome.domain_status(port)),
                Err(error) => {
                    let reason = format!("acl_apply_failed:{}", error.details);
                    statuses.push(domain_status_with_action(
                        &domain,
                        "error",
                        Some(reason.clone()),
                        Some(error.effective_action.to_string()),
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
    if let Err(error) = state.require_restore_ready() {
        return (
            error.status,
            Json(serde_json::json!({
                "error": error.code,
                "details": error.details,
            })),
        )
            .into_response();
    }
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

fn build_committed_delete_runtime(
    previous: &NeutronRuntimeState,
    port_id: &str,
) -> NeutronRuntimeState {
    let mut committed = previous.clone();
    committed.ports.remove(port_id);
    committed.port_statuses.remove(port_id);
    committed.pending_generation = None;
    committed.desired_hash = committed.applied_desired_hash.clone();
    committed.wal_status = "commit_written".to_string();
    committed.recovery_cause = None;
    committed
}

fn build_blocked_delete_runtime(
    previous: &NeutronRuntimeState,
    port: &ManagedNeutronPort,
    generation: u64,
    wal_status: &str,
    reason: &str,
    acl_effective_action: &'static str,
) -> NeutronRuntimeState {
    let mut blocked = previous.clone();
    blocked.pending_generation = Some(generation);
    blocked.desired_hash = None;
    blocked.authority_state = "blocked_recovery_required".to_string();
    blocked.wal_status = wal_status.to_string();
    blocked.recovery_cause = None;
    blocked.ports.insert(port.port_id.clone(), port.clone());

    let domains = runtime_domain_statuses_for(
        &port.managed_domains,
        "blocked",
        Some(reason.to_string()),
    )
    .into_iter()
    .map(|domain| {
        if domain.domain == "acl" {
            domain_status_with_action(
                "acl",
                "blocked",
                Some(reason.to_string()),
                Some(acl_effective_action.to_string()),
            )
        } else {
            domain
        }
    })
    .collect();
    blocked.port_statuses.insert(
        port.port_id.clone(),
        port_runtime_status(
            &port.port_id,
            &port.ifname,
            generation,
            None,
            port.managed_domains.clone(),
            "blocked",
            Some(reason.to_string()),
            domains,
        ),
    );
    blocked
}

async fn publish_blocked_delete_failure(
    state: &NeutronApiState,
    previous: &NeutronRuntimeState,
    port: &ManagedNeutronPort,
    generation: u64,
    wal_status: &str,
    reason: String,
    acl_effective_action: &'static str,
) -> String {
    let mut blocked = build_blocked_delete_runtime(
        previous,
        port,
        generation,
        wal_status,
        &reason,
        acl_effective_action,
    );
    let response_error = match state.wal.append_snapshot_commit(blocked.to_wal_state()) {
        Ok(()) => reason,
        Err(error) => {
            blocked.wal_status = "delete_blocked_checkpoint_failed".to_string();
            format!(
                "{}; delete_blocked_checkpoint_failed:{}",
                reason, error
            )
        }
    };
    {
        let mut runtime = state.runtime.write().await;
        *runtime = blocked;
    }
    response_error
}

fn failed_neutron_delete(
    port: &ManagedNeutronPort,
    error: String,
) -> (StatusCode, NeutronDeleteResponse) {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        NeutronDeleteResponse {
            port_id: port.port_id.clone(),
            ifname: Some(port.ifname.clone()),
            detached: false,
            status: "error".to_string(),
            error: Some(error),
        },
    )
}

async fn finalize_detached_neutron_delete(
    state: &NeutronApiState,
    previous: &NeutronRuntimeState,
    port: &ManagedNeutronPort,
    generation: u64,
    precommit: Result<(), String>,
) -> (StatusCode, NeutronDeleteResponse) {
    if let Err(error) = precommit {
        let error = publish_blocked_delete_failure(
            state,
            previous,
            port,
            generation,
            "delete_after_detach_failed",
            error,
            "bypass",
        )
        .await;
        return failed_neutron_delete(port, error);
    }

    let committed = build_committed_delete_runtime(previous, &port.port_id);
    if let Err(error) = state.wal.append_delete_commit(committed.to_wal_state()) {
        let error = publish_blocked_delete_failure(
            state,
            previous,
            port,
            generation,
            "delete_commit_failed",
            format!("wal_commit_failed:{}", error),
            "bypass",
        )
        .await;
        return failed_neutron_delete(port, error);
    }

    {
        let mut runtime = state.runtime.write().await;
        *runtime = committed;
    }
    (
        StatusCode::OK,
        NeutronDeleteResponse {
            port_id: port.port_id.clone(),
            ifname: Some(port.ifname.clone()),
            detached: true,
            status: "ok".to_string(),
            error: None,
        },
    )
}

fn finalize_recovered_delete_intent(
    state: &NeutronApiState,
    intent: &PendingNeutronIntent,
    previous: &NeutronRuntimeState,
    recovered: NeutronRuntimeState,
    recovery_failed: bool,
) -> NeutronRuntimeState {
    let recovered_statuses = recovered.port_statuses;
    let blocked = |wal_status: &str, default_acl_action: &'static str| {
        let port = intent.port_ids.iter().find_map(|port_id| {
            previous
                .ports
                .get(port_id)
                .or_else(|| {
                    intent
                        .affected_ports
                        .iter()
                        .find(|port| &port.port_id == port_id)
                })
        });
        let Some(port) = port else {
            let mut blocked = previous.clone();
            blocked.pending_generation = Some(intent.generation);
            blocked.desired_hash = None;
            blocked.authority_state = "blocked_recovery_required".to_string();
            blocked.wal_status = wal_status.to_string();
            blocked.recovery_cause = None;
            return blocked;
        };
        let recovered_status = recovered_statuses.get(&port.port_id);
        let reason = recovered_status
            .and_then(|status| status.reason.as_deref())
            .unwrap_or(wal_status);
        let recovered_acl_action = recovered_status
            .and_then(|status| {
                status
                    .domains
                    .iter()
                    .find(|domain| domain.domain == "acl")
            })
            .and_then(|domain| domain.effective_action.as_deref());
        let acl_effective_action = match recovered_acl_action {
            Some("unchanged") => "unchanged",
            Some("bypass") => "bypass",
            _ => default_acl_action,
        };
        let mut blocked = build_blocked_delete_runtime(
            previous,
            port,
            intent.generation,
            wal_status,
            reason,
            acl_effective_action,
        );
        if let Some(status) = blocked.port_statuses.get_mut(&port.port_id) {
            status.reason = Some(reason.to_string());
        }
        blocked
    };

    if recovery_failed {
        return blocked("intent_recovery_blocked", "unchanged");
    }

    let mut committed = previous.clone();
    for port_id in &intent.port_ids {
        committed.ports.remove(port_id);
        committed.port_statuses.remove(port_id);
    }
    committed.pending_generation = None;
    committed.desired_hash = committed.applied_desired_hash.clone();
    committed.wal_status = "commit_written".to_string();
    committed.recovery_cause = None;

    if let Err(error) = state.wal.append_delete_commit(committed.to_wal_state()) {
        warn!(
            generation = intent.generation,
            port_ids = ?intent.port_ids,
            error = %error,
            "failed to commit recovered Neutron delete intent"
        );
        return blocked("delete_recovery_commit_failed", "bypass");
    }
    committed
}

async fn apply_delete_neutron_port(
    state: NeutronApiState,
    port_id: String,
) -> (StatusCode, NeutronDeleteResponse) {
    let _guard = state.apply_lock.lock().await;
    let previous = {
        let runtime = state.runtime.read().await;
        runtime.clone()
    };
    let port = previous.ports.get(&port_id).cloned();

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

    let generation = previous.accepted_generation;
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
        let error = publish_blocked_delete_failure(
            &state,
            &previous,
            &port,
            generation,
            "delete_after_intent_failed",
            e,
            "unchanged",
        )
        .await;
        return failed_neutron_delete(&port, error);
    }

    if detached_port_cleanup_requires_acl_purge(read_ifindex(&port.ifname).is_some()) {
        if let Err(error) =
            purge_neutron_acl_transactionally(&state, &port.ifname, &port.port_id).await
        {
            let effective_action = error.effective_action;
            let details = error.details;
            warn!(
                port_id = %port.port_id,
                ifname = %port.ifname,
                error = %details,
                "keeping attached Neutron interface quiesced after ACL purge failure"
            );
            let error = publish_blocked_delete_failure(
                &state,
                &previous,
                &port,
                generation,
                "delete_acl_purge_failed",
                format!("neutron_acl_purge_failed:{}", details),
                effective_action,
            )
            .await;
            return failed_neutron_delete(&port, error);
        }
    } else {
        info!(
            port_id = %port.port_id,
            ifname = %port.ifname,
            "skipping ACL purge because the detached interface is already absent"
        );
    }
    if let Err(e) = fault_injection::check("neutron.delete.after_acl_purge").await {
        let error = publish_blocked_delete_failure(
            &state,
            &previous,
            &port,
            generation,
            "delete_after_acl_purge_failed",
            e,
            "bypass",
        )
        .await;
        return failed_neutron_delete(&port, error);
    }

    match state.registry.detach(&port.ifname).await {
        Ok(()) => {
            finalize_detached_neutron_delete(
                &state,
                &previous,
                &port,
                generation,
                fault_injection::check("neutron.delete.after_detach_before_commit").await,
            )
            .await
        }
        Err(e) => {
            let error = publish_blocked_delete_failure(
                &state,
                &previous,
                &port,
                generation,
                "delete_detach_failed",
                e,
                "bypass",
            )
            .await;
            failed_neutron_delete(&port, error)
        }
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
    async fn load(ovs_bridge: &str) -> Self {
        match Self::try_load(ovs_bridge, Instant::now() + OVS_INVENTORY_TIMEOUT).await {
            Ok(inventory) => inventory,
            Err(error) => {
                warn!(
                    ovs_bridge,
                    error = %error,
                    "failed to load OVS interface inventory"
                );
                Self {
                    ovs_bridge: ovs_bridge.to_string(),
                    ovs_error: Some(error),
                    by_iface_id: BTreeMap::new(),
                    by_name: BTreeMap::new(),
                }
            }
        }
    }

    async fn try_load(ovs_bridge: &str, deadline: Instant) -> Result<Self, String> {
        let bridge_ports = Self::list_bridge_ports(ovs_bridge, deadline).await?;
        let args = [
            "--format=json",
            "--columns=name,external_ids",
            "list",
            "Interface",
        ];
        let output = run_bounded_process(
            "ovs-vsctl",
            &args,
            remaining_ovs_inventory_time(deadline, "list Interface")?,
        )
        .await?;
        if !output.status.success() {
            return Err(format!(
                "ovs-vsctl list Interface failed: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            ));
        }
        let payload = String::from_utf8_lossy(&output.stdout);
        Self::from_ovs_json(ovs_bridge, &bridge_ports, &payload)
    }

    async fn list_bridge_ports(
        ovs_bridge: &str,
        deadline: Instant,
    ) -> Result<BTreeSet<String>, String> {
        let args = ["list-ports", ovs_bridge];
        let output = run_bounded_process(
            "ovs-vsctl",
            &args,
            remaining_ovs_inventory_time(deadline, "list-ports")?,
        )
        .await?;
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

fn remaining_ovs_inventory_time(deadline: Instant, command: &str) -> Result<Duration, String> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|remaining| !remaining.is_zero())
        .ok_or_else(|| format!("ovs-vsctl {} timed out", command))
}

async fn run_bounded_process(
    program: &str,
    args: &[&str],
    timeout_duration: Duration,
) -> Result<std::process::Output, String> {
    let mut command = Command::new(program);
    command
        .args(args)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true);
    let child = command
        .spawn()
        .map_err(|error| format!("run {}: {}", program, error))?;
    tokio::time::timeout(timeout_duration, child.wait_with_output())
        .await
        .map_err(|_| {
            format!(
                "{} timed out after {} ms",
                program,
                timeout_duration.as_millis()
            )
        })?
        .map_err(|error| format!("wait for {}: {}", program, error))
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

fn detached_port_cleanup_requires_acl_purge(interface_exists: bool) -> bool {
    interface_exists
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

const IMPLEMENTED_NEUTRON_DOMAINS: &[&str] = &["attach", "acl"];

fn implemented_neutron_domains() -> &'static [&'static str] {
    IMPLEMENTED_NEUTRON_DOMAINS
}

fn unsupported_neutron_managed_domains(domains: &[String]) -> Vec<String> {
    normalize_managed_domains(domains)
        .into_iter()
        .filter(|domain| !implemented_neutron_domains().contains(&domain.as_str()))
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

fn required_neutron_publication_mode(manages_acl: bool) -> ManagedAclPublicationMode {
    if manages_acl {
        ManagedAclPublicationMode::ManagedAcl
    } else {
        ManagedAclPublicationMode::NeutronAttachOwnedStandaloneAcl
    }
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

fn canonical_acl_cidrs(
    cidrs: &[String],
    rule_id: &str,
) -> Result<Vec<AclIpv4Cidr>, String> {
    ensure_ipv4_cidrs(cidrs, rule_id)?;
    let mut normalized = BTreeSet::new();
    for cidr in cidrs {
        normalized.insert(AclIpv4Cidr::parse(cidr)?);
    }
    Ok(normalized.into_iter().collect())
}

fn normalized_acl_direction(direction: u8) -> String {
    match direction {
        0 => "ingress".to_string(),
        1 => "egress".to_string(),
        2 => "both".to_string(),
        other => other.to_string(),
    }
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

fn normalize_acl_rule(
    rule: &NeutronAclRuleSnapshot,
    index: usize,
) -> Result<CanonicalAclRule, String> {
    let rule_id = acl_rule_id(rule, index);
    if rule
        .ethertype
        .as_deref()
        .map(|ethertype| ethertype.eq_ignore_ascii_case("IPv6"))
        .unwrap_or(false)
    {
        return Err(format!("rule {} uses IPv6 ethertype; unsupported", rule_id));
    }

    let src_cidrs = canonical_acl_cidrs(&rule.src_cidrs, &rule_id)?;
    let dst_cidrs = canonical_acl_cidrs(&rule.dst_cidrs, &rule_id)?;
    let proto = proto_from_string(rule.protocol.as_deref().unwrap_or("any").trim())
        .map_err(|e| format!("rule {} protocol: {}", rule_id, e))?;
    let action = action_from_string(rule.action.as_deref().unwrap_or("allow").trim())
        .map_err(|e| format!("rule {} action: {}", rule_id, e))?;
    let direction = direction_from_string(rule.direction.as_deref().unwrap_or("ingress").trim())
        .map_err(|e| format!("rule {} direction: {}", rule_id, e))?;
    let ports = match acl_ports(rule, proto, &rule_id)? {
        Some(ports) => parse_acl_port_ranges(&ports)?,
        None => Vec::new(),
    };
    let mut directions = neutron_acl_to_datapath_directions(direction);
    directions.sort_unstable();
    directions.dedup();

    Ok(CanonicalAclRule {
        id: rule_id,
        direction: normalized_acl_direction(direction),
        priority: rule.priority,
        directions,
        proto,
        action,
        src_cidrs,
        dst_cidrs,
        ports,
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AclSelectorRelation {
    Identical,
    Disjoint,
    Intersecting,
}

fn acl_selector_relation(
    left: AclSelectorId,
    right: AclSelectorId,
) -> AclSelectorRelation {
    if left == right {
        AclSelectorRelation::Identical
    } else if left == AclSelectorId::ANY || right == AclSelectorId::ANY {
        AclSelectorRelation::Intersecting
    } else {
        AclSelectorRelation::Disjoint
    }
}

fn acl_selector_tables(
    rules: &[CanonicalAclRule],
) -> (Vec<Vec<AclIpv4Cidr>>, Vec<Vec<AclIpv4Cidr>>) {
    let mut src_selectors = BTreeSet::new();
    let mut dst_selectors = BTreeSet::new();
    for rule in rules {
        if !rule.src_cidrs.is_empty() && !src_selectors.contains(&rule.src_cidrs) {
            src_selectors.insert(rule.src_cidrs.clone());
        }
        if !rule.dst_cidrs.is_empty() && !dst_selectors.contains(&rule.dst_cidrs) {
            dst_selectors.insert(rule.dst_cidrs.clone());
        }
    }

    let mut src_table = vec![Vec::new()];
    src_table.extend(src_selectors);
    let mut dst_table = vec![Vec::new()];
    dst_table.extend(dst_selectors);
    (src_table, dst_table)
}

fn acl_selector_id(
    selector: &[AclIpv4Cidr],
    selectors: &[Vec<AclIpv4Cidr>],
) -> AclSelectorId {
    if selector.is_empty() {
        return AclSelectorId::ANY;
    }
    let ordinal = selectors[1..]
        .binary_search_by(|candidate| candidate.as_slice().cmp(selector))
        .expect("canonical ACL selector must be interned");
    AclSelectorId(ordinal + 1)
}

fn intern_acl_rules(
    canonical_rules: Vec<CanonicalAclRule>,
) -> (
    Vec<NormalizedAclRule>,
    Vec<Vec<AclIpv4Cidr>>,
    Vec<Vec<AclIpv4Cidr>>,
) {
    let (src_selectors, dst_selectors) = acl_selector_tables(&canonical_rules);
    let rules = canonical_rules
        .into_iter()
        .map(|rule| NormalizedAclRule {
            id: rule.id,
            direction: rule.direction,
            priority: rule.priority,
            directions: rule.directions,
            proto: rule.proto,
            action: rule.action,
            src_selector_id: acl_selector_id(&rule.src_cidrs, &src_selectors),
            dst_selector_id: acl_selector_id(&rule.dst_cidrs, &dst_selectors),
            ports: rule.ports,
        })
        .collect();
    (rules, src_selectors, dst_selectors)
}

fn acl_selector_intervals(selector: &[AclIpv4Cidr]) -> Vec<(u32, u32)> {
    let mut intervals = selector
        .iter()
        .map(|cidr| (cidr.network, cidr.end()))
        .collect::<Vec<_>>();
    intervals.sort_unstable();
    let mut merged = Vec::<(u32, u32)>::new();
    for (start, end) in intervals {
        if let Some((_, active_end)) = merged.last_mut() {
            if start <= *active_end {
                *active_end = (*active_end).max(end);
                continue;
            }
        }
        merged.push((start, end));
    }
    merged
}

fn acl_selector_best_overlap(
    selectors: &[Vec<AclIpv4Cidr>],
    first_rule_indexes: &[Option<usize>],
) -> Option<(usize, usize)> {
    let mut intervals = Vec::new();
    for (selector_index, selector) in selectors.iter().enumerate().skip(1) {
        if first_rule_indexes
            .get(selector_index)
            .copied()
            .flatten()
            .is_none()
        {
            continue;
        }
        let selector_id = AclSelectorId(selector_index);
        for (start, end) in acl_selector_intervals(selector) {
            intervals.push((start, end, selector_id));
        }
    }
    intervals.sort_unstable();

    let mut active_ends = BinaryHeap::<Reverse<(u32, AclSelectorId)>>::new();
    let mut active_counts = BTreeMap::<AclSelectorId, usize>::new();
    let mut active_selectors = BTreeSet::<(usize, AclSelectorId)>::new();
    let mut best = None;
    for (start, end, selector_id) in intervals {
        while active_ends
            .peek()
            .map(|Reverse((active_end, _))| *active_end < start)
            .unwrap_or(false)
        {
            let Reverse((_, expired_selector_id)) = active_ends
                .pop()
                .expect("active ACL interval heap cannot be empty after peek");
            let remove_selector = {
                let count = active_counts
                    .get_mut(&expired_selector_id)
                    .expect("active ACL selector must have a count");
                *count -= 1;
                *count == 0
            };
            if remove_selector {
                active_counts.remove(&expired_selector_id);
                let first_rule_index = first_rule_indexes[expired_selector_id.0]
                    .expect("active ACL selector must have a first rule index");
                active_selectors.remove(&(first_rule_index, expired_selector_id));
            }
        }

        let first_rule_index = first_rule_indexes[selector_id.0]
            .expect("swept ACL selector must have a first rule index");
        if let Some((other_first_rule_index, _)) = active_selectors
            .iter()
            .copied()
            .find(|(_, other_id)| *other_id != selector_id)
        {
            let candidate = if first_rule_index < other_first_rule_index {
                (first_rule_index, other_first_rule_index)
            } else {
                (other_first_rule_index, first_rule_index)
            };
            best = Some(best.map_or(candidate, |current: (usize, usize)| {
                current.min(candidate)
            }));
        }

        let count = active_counts.entry(selector_id).or_insert(0);
        if *count == 0 {
            active_selectors.insert((first_rule_index, selector_id));
        }
        *count += 1;
        active_ends.push(Reverse((end, selector_id)));
    }
    best
}

fn acl_priority_overlap_reason(
    rules: &[NormalizedAclRule],
    src_selectors: &[Vec<AclIpv4Cidr>],
    dst_selectors: &[Vec<AclIpv4Cidr>],
) -> Option<String> {
    let mut priorities = BTreeMap::<(String, i64), String>::new();
    for rule in rules {
        if rule.priority < 0 {
            return Some(format!(
                "invalid_acl_priority:{}:{}",
                rule.id, rule.priority
            ));
        }
        let key = (rule.direction.clone(), rule.priority);
        if let Some(first_id) = priorities.get(&key) {
            return Some(format!(
                "duplicate_acl_priority:{}:{}:{}:{}",
                rule.direction, rule.priority, first_id, rule.id
            ));
        }
        priorities.insert(key, rule.id.clone());
    }

    let mut ordered: Vec<&NormalizedAclRule> = rules.iter().collect();
    ordered.sort_by(|left, right| {
        left.direction
            .cmp(&right.direction)
            .then_with(|| left.priority.cmp(&right.priority))
            .then_with(|| left.id.cmp(&right.id))
    });
    let mut src_first_rule_indexes = vec![None; src_selectors.len()];
    let mut dst_first_rule_indexes = vec![None; dst_selectors.len()];
    for (rule_index, rule) in ordered.iter().enumerate() {
        if rule.src_selector_id != AclSelectorId::ANY
            && src_first_rule_indexes[rule.src_selector_id.0].is_none()
        {
            src_first_rule_indexes[rule.src_selector_id.0] = Some(rule_index);
        }
        if rule.dst_selector_id != AclSelectorId::ANY
            && dst_first_rule_indexes[rule.dst_selector_id.0].is_none()
        {
            dst_first_rule_indexes[rule.dst_selector_id.0] = Some(rule_index);
        }
    }
    let src_best = acl_selector_best_overlap(src_selectors, &src_first_rule_indexes);
    let dst_best = acl_selector_best_overlap(dst_selectors, &dst_first_rule_indexes);
    let cidr_candidate = match (src_best, dst_best) {
        (Some(src), Some(dst)) if src <= dst => Some((src.0, src.1, "src")),
        (Some(_), Some(dst)) => Some((dst.0, dst.1, "dst")),
        (Some(src), None) => Some((src.0, src.1, "src")),
        (None, Some(dst)) => Some((dst.0, dst.1, "dst")),
        (None, None) => None,
    };

    for (left_index, left) in ordered.iter().enumerate() {
        for (right_index, right) in ordered.iter().enumerate().skip(left_index + 1) {
            if let Some((cidr_left_index, cidr_right_index, side)) = cidr_candidate {
                if (left_index, right_index) == (cidr_left_index, cidr_right_index) {
                    return Some(format!(
                        "unsupported_acl_cidr_overlap:{}:{}:{}:{}:{}",
                        side, left.id, left.priority, right.id, right.priority
                    ));
                }
            }

            let src_relation =
                acl_selector_relation(left.src_selector_id, right.src_selector_id);
            let dst_relation =
                acl_selector_relation(left.dst_selector_id, right.dst_selector_id);

            if !left
                .directions
                .iter()
                .any(|direction| right.directions.contains(direction))
            {
                continue;
            }
            if left.proto != 0 && right.proto != 0 && left.proto != right.proto {
                continue;
            }
            if src_relation == AclSelectorRelation::Disjoint {
                continue;
            }
            if dst_relation == AclSelectorRelation::Disjoint {
                continue;
            }

            let same_key = left.proto == right.proto
                && left.src_selector_id == right.src_selector_id
                && left.dst_selector_id == right.dst_selector_id;
            let same_behavior = left.action == right.action && left.ports == right.ports;
            if same_behavior || (same_key && left.action == right.action) {
                continue;
            }
            return Some(format!(
                "unsupported_acl_priority_overlap:{}:{}:{}:{}",
                left.id, left.priority, right.id, right.priority
            ));
        }
    }
    None
}

fn force_bypass_acl_plan(acl: &NeutronAclSnapshot, reason: String) -> AclApplyPlan {
    AclApplyPlan {
        conntrack_enabled: Some(acl.stateful),
        force_bypass_reason: Some(reason),
        ..AclApplyPlan::default()
    }
}

fn acl_runtime_limit_reason(acl: &NeutronAclSnapshot) -> Option<String> {
    if acl.rules.len() > MAX_ACL_RULES_PER_POLICY {
        return Some(format!(
            "acl_rule_limit_exceeded:{}:{}",
            acl.rules.len(),
            MAX_ACL_RULES_PER_POLICY,
        ));
    }
    for (index, rule) in acl.rules.iter().enumerate() {
        let rule_id = acl_rule_id(rule, index);
        for (side, members) in [("src", &rule.src_cidrs), ("dst", &rule.dst_cidrs)] {
            if members.len() > MAX_ACL_SELECTOR_MEMBERS {
                return Some(format!(
                    "acl_selector_member_limit_exceeded:{}:{}:{}:{}",
                    side,
                    rule_id,
                    members.len(),
                    MAX_ACL_SELECTOR_MEMBERS,
                ));
            }
        }
    }
    None
}

fn acl_validation_cache_key(acl: &NeutronAclSnapshot) -> AclValidationCacheKey {
    AclValidationCacheKey {
        policy_id: acl.policy_id.clone(),
        revision: acl.revision,
        content_hash: stable_json_hash(&AclValidationHashPayload {
            default_action: &acl.default_action,
            rules: &acl.rules,
        }),
    }
}

fn validate_neutron_acl_template(
    acl: &NeutronAclSnapshot,
) -> Result<AclValidatedTemplate, String> {
    let default_action = normalize_default_action(&acl.default_action);
    if !matches!(default_action.as_str(), "allow" | "accept" | "pass") {
        return Err(format!(
            "default_action {} is unsupported in the minimal Neutron ACL translator",
            acl.default_action
        ));
    }
    if let Some(reason) = acl_runtime_limit_reason(acl) {
        return Ok(AclValidatedTemplate::ForceBypass(reason));
    }

    let mut canonical_rules = Vec::new();
    for (index, rule) in acl.rules.iter().enumerate() {
        canonical_rules.push(normalize_acl_rule(rule, index)?);
    }
    let (rules, src_selectors, dst_selectors) = intern_acl_rules(canonical_rules);
    if let Some(reason) = acl_priority_overlap_reason(
        &rules,
        &src_selectors,
        &dst_selectors,
    ) {
        return Ok(AclValidatedTemplate::ForceBypass(reason));
    }
    Ok(AclValidatedTemplate::Ready {
        rules,
        src_selectors,
        dst_selectors,
    })
}

fn cached_neutron_acl_template(
    acl: &NeutronAclSnapshot,
    cache: &mut AclValidationCache,
) -> Result<AclValidatedTemplate, String> {
    let key = acl_validation_cache_key(acl);
    if let Some(template) = cache.entries.get(&key) {
        cache.hits += 1;
        return template.clone();
    }
    cache.misses += 1;
    let template = validate_neutron_acl_template(acl);
    cache.entries.insert(key, template.clone());
    template
}

fn acl_selector_registry(
    port_id: &str,
    side: &str,
    selectors: &[Vec<AclIpv4Cidr>],
) -> Vec<AclGroupPlan> {
    let mut groups = Vec::new();
    for (selector_index, selector) in selectors.iter().enumerate().skip(1) {
        let selector_id = AclSelectorId(selector_index);
        let name = format!(
            "{}{}:selector:{}",
            neutron_acl_prefix(port_id),
            side,
            selector_id.group_ordinal()
        );
        groups.push(AclGroupPlan {
            name,
            cidrs: selector.iter().map(|cidr| cidr.canonical()).collect(),
        });
    }
    groups
}

fn acl_group_for_selector(
    port_id: &str,
    side: &str,
    selector_id: AclSelectorId,
) -> String {
    if selector_id == AclSelectorId::ANY {
        "any".to_string()
    } else {
        format!(
            "{}{}:selector:{}",
            neutron_acl_prefix(port_id),
            side,
            selector_id.group_ordinal(),
        )
    }
}

fn render_neutron_acl_plan(
    port_id: &str,
    acl: &NeutronAclSnapshot,
    normalized_rules: &[NormalizedAclRule],
    src_selectors: &[Vec<AclIpv4Cidr>],
    dst_selectors: &[Vec<AclIpv4Cidr>],
) -> Result<AclApplyPlan, String> {
    let mut groups = acl_selector_registry(port_id, "src", src_selectors);
    let mut dst_groups = acl_selector_registry(port_id, "dst", dst_selectors);
    groups.append(&mut dst_groups);

    let mut policies_by_key = BTreeMap::<AclEffectivePolicyKey, AclPolicyPlan>::new();
    for rule in normalized_rules {
        let ports = serialize_acl_port_ranges(rule.ports.clone());
        let src_group = acl_group_for_selector(port_id, "src", rule.src_selector_id);
        let dst_group = acl_group_for_selector(port_id, "dst", rule.dst_selector_id);

        for direction in &rule.directions {
            let key = AclEffectivePolicyKey {
                src_group: src_group.clone(),
                dst_group: dst_group.clone(),
                proto: rule.proto,
                direction: *direction,
            };
            if let Some(existing) = policies_by_key.get_mut(&key) {
                if existing.action != rule.action {
                    return Err(format!(
                        "conflicting effective ACL actions src={} dst={} proto={} direction={} existing_action={} new_action={}",
                        key.src_group,
                        key.dst_group,
                        key.proto,
                        key.direction,
                        existing.action,
                        rule.action
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
                    proto: rule.proto,
                    action: rule.action,
                    direction: *direction,
                    ports: ports.clone(),
                },
            );
        }
    }

    Ok(AclApplyPlan {
        groups,
        policies: policies_by_key.into_values().collect(),
        conntrack_enabled: Some(acl.stateful),
        force_bypass_reason: None,
    })
}

fn translate_neutron_acl_with_cache(
    port_id: &str,
    acl: &NeutronAclSnapshot,
    cache: &mut AclValidationCache,
) -> Result<AclApplyPlan, String> {
    if !acl.enabled
        || !acl.status.eq_ignore_ascii_case("ready")
        || !acl.effective_action.eq_ignore_ascii_case("enforce")
    {
        return Ok(AclApplyPlan {
            conntrack_enabled: Some(acl.stateful),
            ..AclApplyPlan::default()
        });
    }

    match cached_neutron_acl_template(acl, cache)? {
        AclValidatedTemplate::Ready {
            rules,
            src_selectors,
            dst_selectors,
        } => render_neutron_acl_plan(
            port_id,
            acl,
            &rules,
            &src_selectors,
            &dst_selectors,
        ),
        AclValidatedTemplate::ForceBypass(reason) => Ok(force_bypass_acl_plan(acl, reason)),
    }
}

#[cfg(test)]
async fn execute_neutron_acl_detach_cleanup<
    Quiesce,
    QuiesceFuture,
    Purge,
    PurgeFuture,
    Detach,
    DetachFuture,
>(
    quiesce: Quiesce,
    purge: Purge,
    detach: Detach,
) -> Result<(), String>
where
    Quiesce: FnOnce() -> QuiesceFuture,
    QuiesceFuture: Future<Output = Result<(), String>>,
    Purge: FnOnce() -> PurgeFuture,
    PurgeFuture: Future<Output = Result<(), String>>,
    Detach: FnOnce() -> DetachFuture,
    DetachFuture: Future<Output = Result<(), String>>,
{
    quiesce().await?;
    purge().await?;
    detach().await
}

async fn purge_neutron_acl_transactionally(
    state: &NeutronApiState,
    ifname: &str,
    port_id: &str,
) -> Result<OwnedAclReconcileReport, NeutronAclReconcileError> {
    state
        .registry
        .update_neutron_acl_runtime_gate(ifname, false, false, false)
        .await
        .map_err(|error| {
            acl_reconcile_error(
                AclReconcileFailurePhase::BeforeQuiesce,
                error.to_string(),
            )
        })?;
    state
        .control_plane
        .replace_owned_acl_and_flush(
            ifname,
            &neutron_acl_prefix(port_id),
            true,
            &[],
            &[],
            false,
        )
        .await
        .map_err(|error| {
            acl_reconcile_error(
                AclReconcileFailurePhase::AfterQuiesce,
                error.to_string(),
            )
        })
}

async fn check_managed_acl_precommit_fault() -> Result<(), String> {
    fault_injection::check("neutron.acl.after_enable_before_commit").await
}

async fn requiesce_managed_acl_runtime_gate(
    state: &NeutronApiState,
    ifname: &str,
) -> Result<(), String> {
    state
        .registry
        .update_neutron_acl_runtime_gate(ifname, false, false, false)
        .await
        .map_err(|error| error.to_string())
}

async fn execute_managed_acl_post_replace_completion<
    PublishGate,
    PublishGateFuture,
    PrecommitFault,
    PrecommitFaultFuture,
    VerifyAndMark,
    VerifyAndMarkFuture,
    RequiesceGate,
    RequiesceGateFuture,
>(
    _plan: &AclApplyPlan,
    publish_gate: PublishGate,
    precommit_fault: PrecommitFault,
    verify_and_mark: VerifyAndMark,
    requiesce_gate: RequiesceGate,
) -> Result<(), NeutronAclReconcileError>
where
    PublishGate: FnOnce() -> PublishGateFuture,
    PublishGateFuture: Future<Output = Result<(), String>>,
    PrecommitFault: FnOnce() -> PrecommitFaultFuture,
    PrecommitFaultFuture: Future<Output = Result<(), String>>,
    VerifyAndMark: FnOnce() -> VerifyAndMarkFuture,
    VerifyAndMarkFuture: Future<Output = Result<(), String>>,
    RequiesceGate: FnOnce() -> RequiesceGateFuture,
    RequiesceGateFuture: Future<Output = Result<(), String>>,
{
    let completion_result = async {
        publish_gate().await?;
        precommit_fault().await?;
        verify_and_mark().await?;
        Ok::<(), String>(())
    }
    .await;

    let Err(error) = completion_result else {
        return Ok(());
    };
    match requiesce_gate().await {
        Ok(()) => Err(acl_reconcile_error(
            AclReconcileFailurePhase::AfterQuiesce,
            error,
        )),
        Err(compensation_error) => Err(acl_reconcile_error(
            AclReconcileFailurePhase::CompensationFailed,
            format!(
                "{}; acl_requiesce_compensation_failed:{}",
                error, compensation_error
            ),
        )),
    }
}

async fn reconcile_neutron_acl(
    state: &NeutronApiState,
    port: &NeutronPortSnapshot,
    acl_validation_cache: &mut AclValidationCache,
    full_resync: bool,
) -> Result<NeutronAclReconcileOutcome, NeutronAclReconcileError> {
    if !port_manages_acl(port) {
        return Ok(NeutronAclReconcileOutcome::default());
    }

    let profile_started = Instant::now();
    let translate_started = Instant::now();
    let plan = match &port.acl {
        Some(acl) => translate_neutron_acl_with_cache(
            &port.port_id,
            acl,
            acl_validation_cache,
        )
        .map_err(|error| {
            acl_reconcile_error(AclReconcileFailurePhase::BeforeQuiesce, error)
        })?,
        None => AclApplyPlan::default(),
    };
    let outcome = NeutronAclReconcileOutcome::from_plan(&plan);
    let translate_ms = elapsed_ms(translate_started);
    let preserved_conntrack_enabled = if plan.conntrack_enabled.is_none() {
        state
            .control_plane
            .get_config(&port.ifname)
            .await
            .map_err(|error| {
                acl_reconcile_error(
                    AclReconcileFailurePhase::BeforeQuiesce,
                    error.to_string(),
                )
            })?
            .conntrack_enabled
            != 0
    } else {
        false
    };
    let transition = acl_runtime_transition(&plan, preserved_conntrack_enabled);
    let require_tc_acl_links = acl_runtime_feature_requires_tc(transition.publish);
    let group_count = plan.groups.len();
    let group_cidr_count: usize = plan.groups.iter().map(|group| group.cidrs.len()).sum();
    let policy_count = plan.policies.len();
    let gate_update_mode = acl_gate_update_mode(&plan);
    if require_tc_acl_links {
        state
            .control_plane
            .require_tc_acl_ready(&port.ifname)
            .await
            .map_err(|error| {
                acl_reconcile_error(
                    AclReconcileFailurePhase::BeforeQuiesce,
                    error.to_string(),
                )
            })?;
    }
    let disable_ms = if gate_update_mode == AclGateUpdateMode::DisableBeforeReplace {
        let disable_started = Instant::now();
        state
            .registry
            .update_neutron_acl_runtime_gate(
                &port.ifname,
                transition.quiesce.conntrack_enabled,
                transition.quiesce.acl_enabled,
                false,
            )
            .await
            .map_err(|error| {
                acl_reconcile_error(
                    AclReconcileFailurePhase::BeforeQuiesce,
                    error.to_string(),
                )
            })?;
        let elapsed = elapsed_ms(disable_started);
        fault_injection::check("neutron.acl.after_disable")
            .await
            .map_err(|error| {
                acl_reconcile_error(AclReconcileFailurePhase::AfterQuiesce, error)
            })?;
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
        .replace_owned_acl_and_flush(
            &port.ifname,
            &neutron_acl_prefix(&port.port_id),
            true,
            &group_specs,
            &policy_specs,
            require_tc_acl_links,
        )
        .await
        .map_err(|error| {
            acl_reconcile_error(
                AclReconcileFailurePhase::AfterQuiesce,
                error.to_string(),
            )
        })?;
    let replace_ms = elapsed_ms(replace_started);
    fault_injection::check("neutron.acl.after_purge")
        .await
        .map_err(|error| {
            acl_reconcile_error(AclReconcileFailurePhase::AfterQuiesce, error)
        })?;
    if replace_report.group_cidr_add_count > 0 {
        fault_injection::check("neutron.acl.after_group_write")
            .await
            .map_err(|error| {
                acl_reconcile_error(AclReconcileFailurePhase::AfterQuiesce, error)
            })?;
    }
    if replace_report.policy_add_count > 0 {
        fault_injection::check("neutron.acl.after_policy_write")
            .await
            .map_err(|error| {
                acl_reconcile_error(AclReconcileFailurePhase::AfterQuiesce, error)
            })?;
    }

    let effective_reason = if port.acl.is_none() {
        "no_acl"
    } else if plan.policies.is_empty() {
        "empty_policy"
    } else {
        "enforced"
    };

    // Strict CT scrubbing is part of replace_owned_acl_and_flush while the
    // publication locks and rollback preimages are still owned.  The outer
    // completion phase only controls gate publication and later compensation.
    let flush_ms = 0;
    let publish_ms = Arc::new(AtomicU64::new(0));
    let publish_timing = Arc::clone(&publish_ms);
    let publish_state = state;
    let publish_ifname = port.ifname.clone();
    let check_before_enable = !plan.policies.is_empty();
    let verify_state = state;
    let verify_ifname = port.ifname.clone();
    let requiesce_state = state;
    let requiesce_ifname = port.ifname.clone();
    execute_managed_acl_post_replace_completion(
        &plan,
        move || async move {
            let publish_started = Instant::now();
            let result = async {
                if check_before_enable {
                    fault_injection::check("neutron.acl.before_enable").await?;
                }
                publish_state
                    .registry
                    .update_neutron_acl_runtime_gate(
                        &publish_ifname,
                        transition.publish.conntrack_enabled,
                        transition.publish.acl_enabled,
                        full_resync,
                    )
                    .await
                    .map_err(|error| error.to_string())
            }
            .await;
            publish_timing.store(elapsed_ms(publish_started), Ordering::Relaxed);
            result
        },
        check_managed_acl_precommit_fault,
        move || async move {
            verify_state
                .control_plane
                .verify_and_mark_managed_projection(&verify_ifname)
                .await
        },
        move || async move {
            requiesce_managed_acl_runtime_gate(requiesce_state, &requiesce_ifname).await
        },
    )
    .await?;
    let publish_ms = publish_ms.load(Ordering::Relaxed);

    if plan.policies.is_empty() {
        info!(
            port_id = %port.port_id,
            ifname = %port.ifname,
            status = "bypass",
            selector_repair_performed = replace_report.selector_repair_performed,
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
            publish_ms,
            total_ms = elapsed_ms(profile_started),
            "neutron_acl_apply_profile"
        );
    } else {
        info!(
            port_id = %port.port_id,
            ifname = %port.ifname,
            status = "enforced",
            selector_repair_performed = replace_report.selector_repair_performed,
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
            publish_ms,
            total_ms = elapsed_ms(profile_started),
            "neutron_acl_apply_profile"
        );
    }
    Ok(outcome)
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
    let mut inventory_error = inventory
        .ovs_error
        .as_ref()
        .map(|details| format!("ovsdb_unavailable:{}", details));
    let mut desired = BTreeMap::new();
    let mut ignored = Vec::new();
    let mut deferred_committed_ports = BTreeSet::new();
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
            let disposition = resolved_port
                .disposition
                .clone()
                .unwrap_or_else(|| "not eligible".to_string());
            if disposition == "ifindex_not_ready"
                && current
                    .get(&resolved_port.port_id)
                    .is_some_and(|managed| managed.ifname == resolved_port.ifname)
            {
                deferred_committed_ports.insert(resolved_port.port_id.clone());
                if inventory_error.is_none() {
                    inventory_error = Some(format!(
                        "local_port_not_ready:{}:{}",
                        resolved_port.port_id, disposition
                    ));
                }
            }
            ignored.push(NeutronPortApplyResult {
                port_id: resolved_port.port_id.clone(),
                ifname: resolved_port.ifname.clone(),
                action: "ignore".to_string(),
                status: "ignored".to_string(),
                reason: Some(disposition),
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
                    if deferred_committed_ports.contains(port_id) {
                        continue;
                    }
                    match desired.get(port_id) {
                        Some(port) if managed_binding_matches(managed, port) => {}
                        _ => detach.push(managed.clone()),
                    }
                }
            }
            ApplyScope::SinglePort(target_port_id) if scoped_target_seen => {
                if let Some(managed) = current.get(target_port_id) {
                    if !deferred_committed_ports.contains(target_port_id) {
                        match desired.get(target_port_id) {
                            Some(port) if managed_binding_matches(managed, port) => {}
                            _ => detach.push(managed.clone()),
                        }
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
        inventory_error,
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
    full_resync: bool,
    projection_health: Option<ManagedProjectionHealth>,
) -> bool {
    let manages_acl = normalize_managed_domains(&desired.managed_domains)
        .iter()
        .any(|domain| domain == "acl");
    if manages_acl && (full_resync || projection_health != Some(ManagedProjectionHealth::Verified))
    {
        return false;
    }
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
    use std::sync::{Arc, OnceLock};

    const STATUS_V1_SCENARIOS_JSON: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../docs/neutron-status-contract-v1-scenarios.json"
    ));

    static STATUS_V1_SCENARIOS: OnceLock<Value> = OnceLock::new();

    #[derive(Deserialize)]
    struct StatusV1RuntimeSeed {
        accepted_generation: u64,
        applied_generation: u64,
        pending_generation: Option<u64>,
        desired_hash: Option<String>,
        applied_desired_hash: Option<String>,
        authority_state: String,
        wal_status: String,
        wal_replay_failures: u64,
        recovery_cause: Option<String>,
        managed_ports: Vec<ManagedNeutronPort>,
        port_statuses: Vec<NeutronPortStatus>,
    }

    fn rust_status_v1_scenario_ids() -> &'static [&'static str] {
        &[
            "full-classified-ready",
            "scoped-classified-ready",
            "classified-degraded-terminal",
            "classified-degraded-full-resync",
            "pending-poll",
            "blocked-recoverable-inventory",
            "blocked-operator",
            "recovery-full-resync",
            "generation-zero-inventory-recovery",
            "restart-classified-routing",
        ]
    }

    fn shared_status_v1_scenarios() -> &'static Value {
        STATUS_V1_SCENARIOS.get_or_init(|| {
            let fixture: Value = serde_json::from_str(STATUS_V1_SCENARIOS_JSON)
                .expect("shared Status V1 scenarios must be valid JSON");
            assert_eq!(
                fixture
                    .get("fixture_schema_version")
                    .and_then(Value::as_u64),
                Some(1),
                "shared Status V1 fixture schema must be version 1"
            );

            let scenarios = fixture
                .get("scenarios")
                .and_then(Value::as_array)
                .expect("shared Status V1 scenarios must be an array");
            let mut fixture_ids = BTreeSet::new();
            for scenario in scenarios {
                let id = scenario
                    .get("id")
                    .and_then(Value::as_str)
                    .expect("every shared Status V1 scenario must have a string id");
                assert!(
                    fixture_ids.insert(id),
                    "shared Status V1 scenario id must be unique: {id}"
                );
            }

            let producer_ids = rust_status_v1_scenario_ids();
            assert_eq!(
                producer_ids.len(),
                10,
                "Rust Status V1 producer selection must contain exactly ten ids"
            );
            assert_eq!(
                producer_ids.iter().copied().collect::<BTreeSet<_>>().len(),
                producer_ids.len(),
                "Rust Status V1 producer ids must be unique"
            );
            for id in producer_ids {
                assert!(
                    fixture_ids.contains(id),
                    "Rust Status V1 producer scenario must exist: {id}"
                );
            }
            drop(fixture_ids);

            fixture
        })
    }

    fn shared_status_v1_scenario(id: &str) -> &'static Value {
        let matches = shared_status_v1_scenarios()
            .get("scenarios")
            .and_then(Value::as_array)
            .expect("shared Status V1 scenarios must be an array")
            .iter()
            .filter(|scenario| scenario.get("id").and_then(Value::as_str) == Some(id))
            .collect::<Vec<_>>();
        assert_eq!(
            matches.len(),
            1,
            "shared Status V1 scenario id must match exactly once: {id}"
        );
        matches[0]
    }

    #[derive(Serialize)]
    struct TestSnapshotIntentHashPayload<'a> {
        generation: u64,
        desired_hash: &'a Option<String>,
        port_ids: &'a [String],
        affected_domains: &'a [String],
        affected_ports: &'a [ManagedNeutronPort],
        recovery_cause: &'a str,
    }

    fn translate_neutron_acl_for_test(
        port_id: &str,
        acl: &NeutronAclSnapshot,
    ) -> Result<AclApplyPlan, String> {
        let mut cache = AclValidationCache::default();
        translate_neutron_acl_with_cache(port_id, acl, &mut cache)
    }

    #[test]
    fn neutron_tc_acl_health_projection_is_deduplicated_and_preserves_resync() {
        let port = ManagedNeutronPort {
            port_id: "port-health".to_string(),
            ifname: "tap-health".to_string(),
            ifindex: Some(17),
            managed_domains: vec!["acl".to_string()],
            domain_desired_hashes: BTreeMap::new(),
        };
        let mut runtime = NeutronRuntimeState::default();
        runtime.ports.insert(port.port_id.clone(), port.clone());
        runtime.port_statuses.insert(
            port.port_id.clone(),
            port_runtime_status(
                &port.port_id,
                &port.ifname,
                9,
                Some("hash-9".to_string()),
                port.managed_domains.clone(),
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
        let health = vec![InstanceRuntimeHealthSnapshot {
            name: port.ifname.clone(),
            active: true,
            acl_ready: false,
            xdp_ready: true,
            readiness_reason: Some("missing_tc_egress".to_string()),
            cleanup_pending_count: 0,
            maintenance_reason: None,
        }];

        let recovery_only = vec![InstanceRuntimeHealthSnapshot {
            readiness_reason: Some("recovery_required".to_string()),
            ..health[0].clone()
        }];
        assert!(!project_tc_acl_link_loss(&mut runtime, &recovery_only));
        assert_eq!(
            runtime.port_statuses.get(&port.port_id).unwrap().status,
            "ready"
        );

        assert!(project_tc_acl_link_loss(&mut runtime, &health));
        assert_eq!(runtime.authority_state, "runtime_degraded");
        let status = runtime.port_statuses.get(&port.port_id).unwrap();
        assert_eq!(status.reason.as_deref(), Some("tc_acl_link_lost"));
        assert!(status.domains.iter().any(|domain| {
            domain.domain == "acl"
                && domain.status == "degraded"
                && domain.effective_action.as_deref() == Some("bypass")
        }));
        assert!(!project_tc_acl_link_loss(&mut runtime, &health));

        let mut resync_runtime = NeutronRuntimeState::default();
        resync_runtime
            .ports
            .insert(port.port_id.clone(), port.clone());
        resync_runtime.port_statuses.insert(
            port.port_id.clone(),
            port_runtime_status(
                &port.port_id,
                &port.ifname,
                9,
                Some("hash-9".to_string()),
                port.managed_domains,
                "degraded",
                Some("acl_restart_replay_requires_resync".to_string()),
                vec![domain_status_with_action(
                    "acl",
                    "degraded",
                    Some("acl_restart_replay_requires_resync".to_string()),
                    Some("unchanged".to_string()),
                )],
            ),
        );
        assert!(!project_tc_acl_link_loss(&mut resync_runtime, &health));
        assert_eq!(
            resync_runtime
                .port_statuses
                .get("port-health")
                .unwrap()
                .reason
                .as_deref(),
            Some("acl_restart_replay_requires_resync")
        );
    }

    fn tc_health_projection_fixture(
        status_reason: Option<String>,
        domains: Vec<NeutronDomainStatus>,
    ) -> (
        NeutronRuntimeState,
        ManagedNeutronPort,
        Vec<InstanceRuntimeHealthSnapshot>,
    ) {
        let port = ManagedNeutronPort {
            port_id: "port-health-guard".to_string(),
            ifname: "tap-health-guard".to_string(),
            ifindex: Some(19),
            managed_domains: vec!["acl".to_string()],
            domain_desired_hashes: BTreeMap::new(),
        };
        let mut runtime = NeutronRuntimeState::default();
        runtime.ports.insert(port.port_id.clone(), port.clone());
        runtime.port_statuses.insert(
            port.port_id.clone(),
            port_runtime_status(
                &port.port_id,
                &port.ifname,
                11,
                Some("hash-11".to_string()),
                port.managed_domains.clone(),
                if status_reason.is_some() {
                    "blocked"
                } else {
                    "ready"
                },
                status_reason,
                domains,
            ),
        );
        let health = vec![InstanceRuntimeHealthSnapshot {
            name: port.ifname.clone(),
            active: true,
            acl_ready: false,
            xdp_ready: true,
            readiness_reason: Some("missing_tc_ingress".to_string()),
            cleanup_pending_count: 0,
            maintenance_reason: None,
        }];
        (runtime, port, health)
    }

    #[test]
    fn neutron_tc_acl_health_projection_preserves_pending_generation_state() {
        let (mut runtime, port, health) = tc_health_projection_fixture(
            None,
            vec![domain_status_with_action(
                "acl",
                "ready",
                None,
                Some("enforce".to_string()),
            )],
        );
        runtime.pending_generation = Some(12);
        runtime.authority_state = "applying".to_string();
        runtime.wal_status = "intent_written".to_string();

        assert!(!project_tc_acl_link_loss(&mut runtime, &health));
        assert_eq!(runtime.pending_generation, Some(12));
        assert_eq!(runtime.authority_state, "applying");
        assert_eq!(runtime.wal_status, "intent_written");
        assert_eq!(
            runtime.port_statuses.get(&port.port_id).unwrap().status,
            "ready"
        );
    }

    #[test]
    fn neutron_tc_acl_health_projection_preserves_recovery_failures() {
        for reason in [
            "attach_recovery_failed:link unavailable",
            "acl_recovery_failed:map unavailable",
        ] {
            let (mut runtime, port, health) = tc_health_projection_fixture(
                Some(reason.to_string()),
                vec![domain_status_with_action(
                    "acl",
                    "blocked",
                    Some(reason.to_string()),
                    Some("unchanged".to_string()),
                )],
            );
            runtime.authority_state = "blocked_recovery_required".to_string();
            runtime.wal_status = "intent_recovery_blocked".to_string();

            assert!(!project_tc_acl_link_loss(&mut runtime, &health));
            assert_eq!(runtime.authority_state, "blocked_recovery_required");
            assert_eq!(runtime.wal_status, "intent_recovery_blocked");
            let status = runtime.port_statuses.get(&port.port_id).unwrap();
            assert_eq!(status.status, "blocked");
            assert_eq!(status.reason.as_deref(), Some(reason));
            assert_eq!(
                status.domains[0].reason.as_deref(),
                Some(reason),
                "domain recovery evidence must be preserved"
            );
        }
    }
    use crate::kernel_drop_manager::KernelDropManager;
    use crate::ssl_manager::SslManager;
    use crate::trace_backend::TraceManager;

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
        let control_plane = Arc::new(ControlPlane::new_with_fragment_tracking(
            &ebpf_path,
            &pin_path,
            &state_path,
            ssl_manager,
            kernel_drop_manager,
            trace_manager,
            crate::FragmentTrackingSettings::default(),
        ));
        let registry = Arc::new(TapRegistry::new(
            &ebpf_path,
            &pin_path,
            &state_path,
            regex::Regex::new("^tap").unwrap(),
            4096,
            control_plane.clone(),
        ));
        let state =
            NeutronApiState::new(registry, control_plane, "br-int".to_string());
        state.mark_restore_ready();
        state
    }

    #[test]
    fn neutron_runtime_restore_gate_rejects_mutations_until_ready() {
        let root = temp_root("runtime-restore-gate");
        let state = test_neutron_state(&root);
        state.restore_ready.store(false, Ordering::Release);

        let error = state.require_restore_ready().unwrap_err();

        assert_eq!(error.status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(error.code, "neutron_runtime_restore_in_progress");
        state.mark_restore_ready();
        assert!(state.require_restore_ready().is_ok());
    }

    #[tokio::test]
    async fn neutron_snapshot_ovs_inventory_command_timeout_is_bounded_and_stops_command_sequence() {
        let root = temp_root("ovs-command-timeout");
        let marker = root.join("command-finished");
        let script = format!(
            "sleep 0.20; printf finished > '{}'",
            marker.display()
        );
        let started = Instant::now();

        let error = run_bounded_process(
            "sh",
            &["-c", script.as_str()],
            std::time::Duration::from_millis(20),
        )
        .await
        .expect_err("slow OVS command must time out");

        assert!(
            started.elapsed() < std::time::Duration::from_millis(150),
            "bounded command exceeded its deadline envelope"
        );
        assert!(error.contains("timed out"));
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
        assert!(
            !marker.exists(),
            "timed-out command sequence continued after cancellation"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn neutron_snapshot_ovs_inventory_command_captures_output() {
        let output = run_bounded_process(
            "sh",
            &["-c", "printf ovs-out; printf ovs-error >&2"],
            std::time::Duration::from_secs(1),
        )
        .await
        .expect("bounded command should complete");

        assert_eq!(output.stdout, b"ovs-out");
        assert_eq!(output.stderr, b"ovs-error");
    }

    #[test]
    fn neutron_snapshot_admission_identity_detects_intervening_runtime_change() {
        let mut runtime = NeutronRuntimeState {
            accepted_generation: 40,
            applied_generation: 40,
            applied_desired_hash: Some("hash-40".to_string()),
            authority_state: "ready".to_string(),
            wal_status: "commit_written".to_string(),
            ..NeutronRuntimeState::default()
        };
        runtime
            .ports
            .insert("port-a".to_string(), managed("port-a", "tap-a"));
        let before = SnapshotAdmissionIdentity::capture(&runtime);

        runtime.accepted_generation = 41;
        runtime.pending_generation = Some(41);
        runtime.desired_hash = Some("hash-41".to_string());
        runtime.authority_state = "applying".to_string();
        runtime.wal_status = "intent_written".to_string();
        runtime
            .ports
            .insert("port-b".to_string(), managed("port-b", "tap-b"));
        let after = SnapshotAdmissionIdentity::capture(&runtime);

        assert_ne!(before, after);
    }

    struct WalParentReplacement {
        live: std::path::PathBuf,
        backup: std::path::PathBuf,
        active: bool,
    }

    impl WalParentReplacement {
        fn install(live: &std::path::Path, backup: &std::path::Path) -> Self {
            std::fs::rename(live, backup)
                .expect("WAL parent should move to the backup path");
            if let Err(error) = std::fs::write(live, b"not a directory") {
                let _ = std::fs::rename(backup, live);
                panic!("regular-file WAL parent fixture should be writable: {error}");
            }
            Self {
                live: live.to_path_buf(),
                backup: backup.to_path_buf(),
                active: true,
            }
        }

        fn restore(&mut self) {
            std::fs::remove_file(&self.live)
                .expect("regular-file WAL parent fixture should be removable");
            std::fs::rename(&self.backup, &self.live)
                .expect("WAL parent backup should be restorable");
            self.active = false;
        }
    }

    impl Drop for WalParentReplacement {
        fn drop(&mut self) {
            if self.active {
                let _ = std::fs::remove_file(&self.live);
                let _ = std::fs::rename(&self.backup, &self.live);
            }
        }
    }

    async fn apply_with_both_wal_commits_blocked(
        state: &NeutronApiState,
        root: &std::path::Path,
        snapshot: NeutronSnapshotRequest,
        prepared: PreparedSnapshotApply,
    ) -> (SnapshotApplyError, std::path::PathBuf, Vec<u8>) {
        let state_path = state.registry.base_state_path.clone();
        let backup_path = root.join("state-double-append-backup");
        let wal_path = state_path.join("neutron-snapshot.wal");
        let wal_before = std::fs::read(&wal_path).expect("pending WAL should be readable");
        let mut replacement = WalParentReplacement::install(&state_path, &backup_path);

        let result = apply_neutron_snapshot_for_scope(
            state.clone(),
            snapshot,
            ApplyScope::FullHost,
            prepared,
        )
        .await;
        replacement.restore();

        let error = result.expect_err("both snapshot commit attempts should fail");
        assert_eq!(
            std::fs::read(&wal_path).expect("restored WAL should be readable"),
            wal_before,
            "neither the normal nor fallback commit may reach the WAL"
        );
        (error, wal_path, wal_before)
    }

    fn assert_recovered_replay(
        replay: &crate::neutron_wal::NeutronWalReplay,
        baseline: &NeutronRuntimeState,
    ) {
        assert_eq!(replay.status, "replayed");
        assert_eq!(replay.failures, 0);
        assert!(replay.pending_intent.is_none());
        assert_eq!(replay.state.accepted_generation, baseline.applied_generation);
        assert_eq!(replay.state.applied_generation, baseline.applied_generation);
        assert_eq!(replay.state.pending_generation, None);
        assert_eq!(replay.state.desired_hash, baseline.applied_desired_hash);
        assert_eq!(
            replay.state.applied_desired_hash,
            baseline.applied_desired_hash
        );
        assert_eq!(replay.state.recovery_cause, None);
        assert_eq!(replay.state.ports, baseline.ports);
        assert_eq!(replay.state.port_statuses, baseline.port_statuses);
        assert_eq!(
            replay.state.authority_state,
            "recovered_pending_full_resync_required"
        );
        assert!(replay.state.status_hash.is_some());
    }

    fn assert_two_stage_recovery_wal(
        wal_path: &std::path::Path,
        expected_entries: usize,
        pending_generation: u64,
        applied_generation: u64,
    ) {
        let raw = std::fs::read_to_string(wal_path).expect("final WAL should be readable");
        let entries = raw
            .lines()
            .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(entries.len(), expected_entries);
        let barrier = &entries[entries.len() - 2]["state"];
        assert_eq!(
            barrier["recovery_cause"].as_str(),
            Some(INVENTORY_UNAVAILABLE_RECOVERY_CAUSE)
        );
        assert_eq!(
            barrier["accepted_generation"].as_u64(),
            Some(pending_generation)
        );
        assert_eq!(
            barrier["applied_generation"].as_u64(),
            Some(applied_generation)
        );
        assert_eq!(
            barrier["pending_generation"].as_u64(),
            Some(pending_generation)
        );
        assert!(barrier["status_hash"].as_str().is_some());
        let rollback = &entries[entries.len() - 1]["state"];
        assert!(rollback.get("recovery_cause").is_none());
        assert!(rollback["pending_generation"].is_null());
        assert_eq!(
            rollback["accepted_generation"].as_u64(),
            Some(applied_generation)
        );
        assert_eq!(
            rollback["applied_generation"].as_u64(),
            Some(applied_generation)
        );
    }

    fn test_snapshot_intent_hash(
        generation: u64,
        desired_hash: &Option<String>,
        port_ids: &[String],
        affected_domains: &[String],
        affected_ports: &[ManagedNeutronPort],
        recovery_cause: &str,
    ) -> String {
        let payload = TestSnapshotIntentHashPayload {
            generation,
            desired_hash,
            port_ids,
            affected_domains,
            affected_ports,
            recovery_cause,
        };
        let bytes = serde_json::to_vec(&payload).expect("intent hash payload should serialize");
        Sha256::digest(bytes)
            .iter()
            .map(|byte| format!("{:02x}", byte))
            .collect::<Vec<_>>()
            .join("")
    }

    fn append_hashed_inventory_snapshot_intent(
        state: &NeutronApiState,
        generation: u64,
        desired_hash: Option<String>,
        port_ids: Vec<String>,
        affected_domains: Vec<String>,
        affected_ports: Vec<ManagedNeutronPort>,
    ) -> serde_json::Value {
        use std::io::Write as _;

        let recovery_cause = INVENTORY_UNAVAILABLE_RECOVERY_CAUSE;
        let intent_hash = test_snapshot_intent_hash(
            generation,
            &desired_hash,
            &port_ids,
            &affected_domains,
            &affected_ports,
            recovery_cause,
        );
        let intent = serde_json::json!({
            "type": "snapshot_intent",
            "generation": generation,
            "desired_hash": desired_hash,
            "port_ids": port_ids,
            "affected_domains": affected_domains,
            "affected_ports": affected_ports,
            "recovery_cause": recovery_cause,
            "intent_hash": intent_hash,
        });
        let wal_path = state.registry.base_state_path.join("neutron-snapshot.wal");
        std::fs::create_dir_all(
            wal_path
                .parent()
                .expect("Neutron WAL path should have a parent"),
        )
        .expect("Neutron WAL directory should be creatable");
        let mut wal = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&wal_path)
            .expect("Neutron WAL should be appendable");
        let raw = serde_json::to_string(&intent).expect("snapshot intent should serialize");
        wal.write_all(raw.as_bytes())
            .expect("snapshot intent should be writable");
        wal.write_all(b"\n")
            .expect("snapshot intent newline should be writable");
        wal.sync_all()
            .expect("snapshot intent should be durable for restart replay");
        intent
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

    fn unavailable_inventory(details: &str) -> LocalInterfaceInventory {
        LocalInterfaceInventory {
            ovs_bridge: "br-int".to_string(),
            ovs_error: Some(details.to_string()),
            by_iface_id: BTreeMap::new(),
            by_name: BTreeMap::new(),
        }
    }

    fn committed_runtime(generation: u64) -> NeutronRuntimeState {
        let port = ManagedNeutronPort {
            managed_domains: vec!["acl".to_string()],
            ..managed("committed-port", "tap-committed")
        };
        let mut ports = BTreeMap::new();
        ports.insert(port.port_id.clone(), port);
        let mut port_statuses = BTreeMap::new();
        port_statuses.insert(
            "committed-port".to_string(),
            ready_status("committed-port", "tap-committed", generation),
        );
        NeutronRuntimeState {
            accepted_generation: generation,
            applied_generation: generation,
            desired_hash: Some(format!("hash-{}", generation)),
            applied_desired_hash: Some(format!("hash-{}", generation)),
            authority_state: "ready".to_string(),
            ports,
            port_statuses,
            wal_status: "commit_written".to_string(),
            ..NeutronRuntimeState::default()
        }
    }

    fn status_v1_runtime_seed(id: &str) -> StatusV1RuntimeSeed {
        let status = shared_status_v1_scenario(id)
            .get("status")
            .filter(|status| status.is_object())
            .unwrap_or_else(|| panic!("Rust Status V1 producer scenario must have status: {id}"));
        for field in [
            "accepted_generation",
            "applied_generation",
            "pending_generation",
            "desired_hash",
            "applied_desired_hash",
            "authority_state",
            "wal_status",
            "wal_replay_failures",
            "recovery_cause",
            "managed_ports",
            "port_statuses",
        ] {
            assert!(
                status.get(field).is_some(),
                "Rust Status V1 runtime seed {id} must explicitly declare {field}"
            );
        }
        serde_json::from_value(status.clone())
            .unwrap_or_else(|error| panic!("Status V1 runtime seed must decode for {id}: {error}"))
    }

    fn runtime_from_status_v1_seed(seed: StatusV1RuntimeSeed) -> NeutronRuntimeState {
        let StatusV1RuntimeSeed {
            accepted_generation,
            applied_generation,
            pending_generation,
            desired_hash,
            applied_desired_hash,
            authority_state,
            wal_status,
            wal_replay_failures,
            recovery_cause,
            managed_ports,
            port_statuses,
        } = seed;

        let mut ports = BTreeMap::new();
        for port in managed_ports {
            let port_id = port.port_id.clone();
            assert!(
                ports.insert(port_id.clone(), port).is_none(),
                "Status V1 runtime seed contains duplicate managed port id: {port_id}"
            );
        }
        let mut statuses = BTreeMap::new();
        for status in port_statuses {
            let port_id = status.port_id.clone();
            assert!(
                statuses.insert(port_id.clone(), status).is_none(),
                "Status V1 runtime seed contains duplicate port status id: {port_id}"
            );
        }

        NeutronRuntimeState {
            accepted_generation,
            applied_generation,
            pending_generation,
            desired_hash,
            applied_desired_hash,
            authority_state,
            ports,
            port_statuses: statuses,
            wal_status,
            recovery_cause,
            wal_replay_failures,
        }
    }

    async fn status_v1_json_for_runtime(id: &str, runtime: NeutronRuntimeState) -> Value {
        let projection = project_neutron_status_v1(&runtime);
        serde_json::to_value(NeutronStatusV1Response {
            status_schema_version: 1,
            status_contract_hash: "v0.9-neutron-status-1".to_string(),
            transaction_state: projection.transaction_state,
            overall_readiness: projection.overall_readiness,
            required_action: projection.required_action,
            recovery_cause: projection.recovery_cause,
            last_classified_generation: projection.last_classified_generation,
            generation: runtime.applied_generation,
            accepted_generation: runtime.accepted_generation,
            applied_generation: runtime.applied_generation,
            pending_generation: runtime.pending_generation,
            desired_hash: runtime.desired_hash.clone(),
            applied_desired_hash: runtime.applied_desired_hash.clone(),
            wal_status: runtime.wal_status.clone(),
            wal_replay_failures: runtime.wal_replay_failures,
            authority_state: if runtime.authority_state.is_empty() {
                "idle".to_string()
            } else {
                runtime.authority_state.clone()
            },
            managed_ports: runtime.ports.values().cloned().collect(),
            port_statuses: projection.port_statuses,
            active_instances: Vec::new(),
            counters: None,
        })
        .unwrap_or_else(|error| panic!("Status V1 projection must serialize for {id}: {error}"))
    }

    fn expected_status_v1_projection(id: &str) -> &'static Value {
        let fixture = shared_status_v1_scenarios();
        let contract = fixture
            .get("status_contract")
            .and_then(Value::as_object)
            .expect("shared Status V1 contract declaration must be an object");
        let scenario = shared_status_v1_scenario(id);
        let status = scenario
            .get("status")
            .filter(|status| status.is_object())
            .unwrap_or_else(|| panic!("Rust Status V1 producer scenario must have status: {id}"));
        assert_eq!(
            status.get("status_schema_version"),
            contract.get("version"),
            "Status V1 response schema must match the shared declaration: {id}"
        );
        assert_eq!(
            status.get("status_contract_hash"),
            contract.get("hash"),
            "Status V1 response hash must match the shared declaration: {id}"
        );

        let projection = scenario
            .get("expected_projection")
            .filter(|projection| projection.is_object())
            .unwrap_or_else(|| panic!("Rust Status V1 producer projection must exist: {id}"));
        for field in [
            "transaction_state",
            "overall_readiness",
            "required_action",
            "recovery_cause",
            "last_classified_generation",
        ] {
            assert!(
                projection.get(field).is_some(),
                "Status V1 expected projection {id} must declare {field}"
            );
        }
        projection
    }

    fn canonicalized_managed_ports(value: Option<&Value>, context: &str) -> Result<Value, String> {
        let rows = value
            .and_then(Value::as_array)
            .ok_or_else(|| format!("{context}: managed_ports must be an array"))?;
        let mut canonical = Vec::with_capacity(rows.len());
        for row in rows {
            let object = row
                .as_object()
                .ok_or_else(|| format!("{context}: managed port row must be an object"))?;
            let mut required = serde_json::Map::new();
            for field in ["port_id", "ifname", "managed_domains"] {
                required.insert(
                    field.to_string(),
                    object.get(field).cloned().ok_or_else(|| {
                        format!("{context}: managed port row must include {field}")
                    })?,
                );
            }
            canonical.push(Value::Object(required));
        }
        canonical.sort_by(|left, right| {
            left.get("port_id")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .cmp(
                    right
                        .get("port_id")
                        .and_then(Value::as_str)
                        .unwrap_or_default(),
                )
        });
        Ok(Value::Array(canonical))
    }

    fn canonicalized_port_statuses(value: Option<&Value>, context: &str) -> Result<Value, String> {
        let mut rows = value
            .and_then(Value::as_array)
            .cloned()
            .ok_or_else(|| format!("{context}: port_statuses must be an array"))?;
        for row in &mut rows {
            let object = row
                .as_object_mut()
                .ok_or_else(|| format!("{context}: port status row must be an object"))?;
            let domains = object
                .get_mut("domains")
                .and_then(Value::as_array_mut)
                .ok_or_else(|| format!("{context}: port status domains must be an array"))?;
            domains.sort_by(|left, right| {
                left.get("domain")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .cmp(
                        right
                            .get("domain")
                            .and_then(Value::as_str)
                            .unwrap_or_default(),
                    )
            });
        }
        rows.sort_by(|left, right| {
            left.get("port_id")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .cmp(
                    right
                        .get("port_id")
                        .and_then(Value::as_str)
                        .unwrap_or_default(),
                )
        });
        Ok(Value::Array(rows))
    }

    fn status_v1_projection_field_mismatches(
        id: &str,
        expected: &Value,
        actual: &Value,
    ) -> Vec<String> {
        let expected_status = shared_status_v1_scenario(id)
            .get("status")
            .expect("Rust Status V1 producer status must exist");
        let mut mismatches = Vec::new();
        for field in ["status_schema_version", "status_contract_hash"] {
            if actual.get(field) != expected_status.get(field) {
                mismatches.push(format!(
                    "{field}: expected {:?}, got {:?}",
                    expected_status.get(field),
                    actual.get(field)
                ));
            }
        }
        for field in [
            "transaction_state",
            "overall_readiness",
            "required_action",
            "recovery_cause",
            "last_classified_generation",
        ] {
            if actual.get(field) != expected.get(field) {
                mismatches.push(format!(
                    "{field}: expected {:?}, got {:?}",
                    expected.get(field),
                    actual.get(field)
                ));
            }
        }
        mismatches
    }

    fn assert_status_v1_projection(
        id: &str,
        expected: &Value,
        actual: &Value,
    ) -> Result<(), String> {
        let expected_status = shared_status_v1_scenario(id)
            .get("status")
            .expect("Rust Status V1 producer status must exist");
        let mut mismatches = status_v1_projection_field_mismatches(id, expected, actual);

        for field in [
            "generation",
            "accepted_generation",
            "applied_generation",
            "pending_generation",
            "desired_hash",
            "applied_desired_hash",
            "wal_status",
            "wal_replay_failures",
            "authority_state",
        ] {
            if actual.get(field) != expected_status.get(field) {
                mismatches.push(format!(
                    "{field}: expected {:?}, got {:?}",
                    expected_status.get(field),
                    actual.get(field)
                ));
            }
        }
        if actual.get("generation") != actual.get("applied_generation") {
            mismatches.push(format!(
                "generation alias mismatch: generation {:?}, applied_generation {:?}",
                actual.get("generation"),
                actual.get("applied_generation")
            ));
        }

        match (
            canonicalized_managed_ports(expected_status.get("managed_ports"), id),
            canonicalized_managed_ports(actual.get("managed_ports"), id),
        ) {
            (Ok(expected_ports), Ok(actual_ports)) if expected_ports != actual_ports => {
                mismatches.push(format!(
                    "managed_ports: expected {expected_ports}, got {actual_ports}"
                ));
            }
            (Err(error), _) | (_, Err(error)) => mismatches.push(error),
            _ => {}
        }

        match (
            canonicalized_port_statuses(expected_status.get("port_statuses"), id),
            canonicalized_port_statuses(actual.get("port_statuses"), id),
        ) {
            (Ok(expected_statuses), Ok(actual_statuses))
                if expected_statuses != actual_statuses =>
            {
                mismatches.push(format!(
                    "port_statuses: expected {expected_statuses}, got {actual_statuses}"
                ));
            }
            (Err(error), _) | (_, Err(error)) => mismatches.push(error),
            _ => {}
        }

        if mismatches.is_empty() {
            Ok(())
        } else {
            Err(format!("{id}:\n{}", mismatches.join("\n")))
        }
    }

    fn inventory_snapshot(
        generation: u64,
        ports: Vec<NeutronPortSnapshot>,
    ) -> NeutronSnapshotRequest {
        NeutronSnapshotRequest {
            schema_version: None,
            generation,
            desired_hash: Some(format!("hash-{}", generation)),
            host: None,
            ports,
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

    async fn neutron_readiness_responses_for_runtime(
        id: &str,
        runtime: NeutronRuntimeState,
    ) -> ((StatusCode, Value), (StatusCode, Value)) {
        let root = temp_root(&format!("readiness-{id}"));
        let state = test_neutron_state(&root);
        {
            let mut stored_runtime = state.runtime.write().await;
            *stored_runtime = runtime;
        }
        let status_response =
            get_neutron_status(State(state.clone())).await.into_response();
        let readiness_response = get_neutron_readiness(State(state)).await.into_response();
        let status = response_json_value(status_response).await;
        let readiness = response_json_value(readiness_response).await;
        std::fs::remove_dir_all(&root)
            .expect("Neutron readiness temporary root should be removable");
        (status, readiness)
    }

    #[tokio::test]
    async fn neutron_readiness_returns_success_only_for_exact_ready() {
        for (id, expected_status) in [
            ("full-classified-ready", StatusCode::OK),
            ("pending-poll", StatusCode::SERVICE_UNAVAILABLE),
            (
                "classified-degraded-terminal",
                StatusCode::SERVICE_UNAVAILABLE,
            ),
            (
                "blocked-recoverable-inventory",
                StatusCode::SERVICE_UNAVAILABLE,
            ),
            ("blocked-operator", StatusCode::SERVICE_UNAVAILABLE),
        ] {
            let runtime = runtime_from_status_v1_seed(status_v1_runtime_seed(id));
            let ((status_code, status_body), (readiness_code, readiness_body)) =
                neutron_readiness_responses_for_runtime(id, runtime).await;

            assert_eq!(
                status_code,
                StatusCode::OK,
                "Status V1 inspection must remain readable for {id}"
            );
            assert_eq!(
                readiness_code, expected_status,
                "readiness status must follow overall_readiness for {id}"
            );
            assert_eq!(
                readiness_body, status_body,
                "readiness and status inspection must share one Status V1 body for {id}"
            );
        }
    }

    #[tokio::test]
    async fn neutron_readiness_cold_start_requires_full_resync() {
        let ((status_code, status_body), (readiness_code, readiness_body)) =
            neutron_readiness_responses_for_runtime(
                "cold-start",
                NeutronRuntimeState::default(),
            )
            .await;

        assert_eq!(status_code, StatusCode::OK);
        assert_eq!(readiness_code, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(readiness_body, status_body);
        assert_eq!(
            readiness_body
                .get("transaction_state")
                .and_then(Value::as_str),
            Some("idle")
        );
        assert_eq!(
            readiness_body
                .get("overall_readiness")
                .and_then(Value::as_str),
            Some("unknown")
        );
        assert_eq!(
            readiness_body
                .get("required_action")
                .and_then(Value::as_str),
            Some("full_resync")
        );
    }

    #[tokio::test]
    async fn neutron_snapshot_status_v1_runtime_projection_matches_shared_scenarios() {
        let mut mismatches = Vec::new();

        for id in rust_status_v1_scenario_ids() {
            let runtime = runtime_from_status_v1_seed(status_v1_runtime_seed(id));
            let actual = status_v1_json_for_runtime(id, runtime).await;
            let expected = expected_status_v1_projection(id);
            if let Err(mismatch) = assert_status_v1_projection(id, expected, &actual) {
                mismatches.push(mismatch);
            }
        }

        assert!(
            mismatches.is_empty(),
            "Neutron runtime projection drifted from the shared Status V1 scenarios:\n{}",
            mismatches.join("\n\n")
        );
    }

    #[test]
    fn neutron_snapshot_status_v1_restart_projection_hides_supplemental_attach() {
        let mut restored = managed_with_ifindex("restart-port", "tap-restart", 17);
        restored.managed_domains = vec!["acl".to_string()];
        restored
            .domain_desired_hashes
            .insert("acl".to_string(), "acl-hash".to_string());
        let mut runtime = NeutronRuntimeState {
            accepted_generation: 42,
            applied_generation: 42,
            desired_hash: Some("hash-42".to_string()),
            applied_desired_hash: Some("hash-42".to_string()),
            authority_state: "ready".to_string(),
            ports: BTreeMap::from([("restart-port".to_string(), restored.clone())]),
            port_statuses: BTreeMap::from([(
                "restart-port".to_string(),
                ready_status("restart-port", "tap-restart", 42),
            )]),
            wal_status: "commit_written".to_string(),
            ..Default::default()
        };

        assert!(invalidate_restarted_acl_runtime(
            &mut runtime,
            std::slice::from_ref(&restored),
        ));
        assert!(runtime.port_statuses["restart-port"]
            .domains
            .iter()
            .any(|domain| domain.domain == "attach" && domain.status == "ready"));

        let projection = project_neutron_status_v1(&runtime);

        assert_eq!(
            projection.transaction_state,
            NeutronStatusTransactionState::Classified
        );
        assert_eq!(
            projection.overall_readiness,
            NeutronStatusOverallReadiness::Degraded
        );
        assert_eq!(
            projection.required_action,
            NeutronStatusRequiredAction::FullResync
        );
        assert_eq!(projection.port_statuses.len(), 1);
        let wire_row = &projection.port_statuses[0];
        assert_eq!(wire_row.managed_domains, vec!["acl".to_string()]);
        assert_eq!(
            wire_row
                .domains
                .iter()
                .map(|domain| domain.domain.as_str())
                .collect::<Vec<_>>(),
            vec!["acl"]
        );
        assert!(runtime.port_statuses["restart-port"]
            .domains
            .iter()
            .any(|domain| domain.domain == "attach" && domain.status == "ready"));
    }

    #[test]
    fn neutron_snapshot_status_v1_empty_ifname_exception_is_exact() {
        let positive =
            runtime_from_status_v1_seed(status_v1_runtime_seed("classified-degraded-terminal"));
        let positive_projection = project_neutron_status_v1(&positive);
        assert_eq!(
            positive_projection.transaction_state,
            NeutronStatusTransactionState::Classified
        );
        assert_eq!(
            positive_projection.overall_readiness,
            NeutronStatusOverallReadiness::Degraded
        );
        assert_eq!(
            positive_projection.required_action,
            NeutronStatusRequiredAction::None
        );

        let mut exact_unsupported_full_resync =
            runtime_from_status_v1_seed(status_v1_runtime_seed("classified-degraded-terminal"));
        exact_unsupported_full_resync
            .port_statuses
            .values_mut()
            .next()
            .expect("terminal-degraded scenario must contain a status row")
            .reason = Some("acl_restart_replay_requires_resync".to_string());
        let exact_unsupported_projection =
            project_neutron_status_v1(&exact_unsupported_full_resync);
        assert_eq!(
            exact_unsupported_projection.transaction_state,
            NeutronStatusTransactionState::Classified
        );
        assert_eq!(
            exact_unsupported_projection.overall_readiness,
            NeutronStatusOverallReadiness::Degraded
        );
        assert_eq!(
            exact_unsupported_projection.required_action,
            NeutronStatusRequiredAction::FullResync
        );

        let mut full_resync =
            runtime_from_status_v1_seed(status_v1_runtime_seed("classified-degraded-full-resync"));
        let port_id = full_resync
            .ports
            .keys()
            .next()
            .expect("full-resync scenario must contain a managed port")
            .clone();
        full_resync
            .ports
            .get_mut(&port_id)
            .expect("managed port must remain addressable")
            .ifname
            .clear();
        full_resync
            .port_statuses
            .get_mut(&port_id)
            .expect("port status must remain addressable")
            .ifname
            .clear();

        let blocked = project_neutron_status_v1(&full_resync);

        assert_eq!(
            blocked.transaction_state,
            NeutronStatusTransactionState::Blocked
        );
        assert_eq!(
            blocked.overall_readiness,
            NeutronStatusOverallReadiness::Blocked
        );
        assert_eq!(
            blocked.required_action,
            NeutronStatusRequiredAction::Operator
        );
    }

    #[tokio::test]
    async fn neutron_snapshot_status_v1_real_admission_polls_with_baseline_accepted_generation() {
        let root = temp_root("status-v1-real-admission-pending-identity");
        let state = test_neutron_state(&root);
        let baseline = committed_runtime(42);
        state
            .wal
            .append_snapshot_commit(baseline.to_wal_state())
            .expect("classified baseline should be durable before admission");
        {
            let mut runtime = state.runtime.write().await;
            *runtime = baseline.clone();
        }
        let snapshot = NeutronSnapshotRequest {
            schema_version: None,
            generation: 45,
            desired_hash: Some("hash-pending-45".to_string()),
            host: None,
            ports: vec![port("committed-port", "tap-committed", true)],
        };

        let decision = accept_neutron_snapshot_submit(&state, &snapshot, &ApplyScope::FullHost)
            .await
            .expect("newer snapshot intent should be admitted");
        assert_eq!(decision.response.status, "pending");
        assert_eq!(decision.response.accepted_generation, 42);
        assert_eq!(decision.response.applied_generation, 42);
        let prepared = decision
            .prepared
            .expect("admission must retain a prepared transaction until apply");
        assert_eq!(prepared.intent.generation, 45);
        assert_eq!(
            prepared.intent.desired_hash.as_deref(),
            Some("hash-pending-45")
        );
        assert_eq!(prepared.runtime_before_apply.accepted_generation, 42);
        assert_eq!(prepared.runtime_before_apply.applied_generation, 42);

        {
            let runtime = state.runtime.read().await;
            assert_eq!(runtime.accepted_generation, 42);
            assert_eq!(runtime.applied_generation, 42);
            assert_eq!(runtime.pending_generation, Some(45));
            assert_eq!(runtime.desired_hash.as_deref(), Some("hash-pending-45"));
            assert_eq!(runtime.applied_desired_hash, baseline.applied_desired_hash);
            assert_eq!(runtime.authority_state, "applying");
            assert_eq!(runtime.wal_status, "intent_written");
        }

        let response = get_neutron_status(State(state.clone()))
            .await
            .into_response();
        let (status, actual) = response_json_value(response).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(actual["accepted_generation"], serde_json::json!(42));
        assert_eq!(actual["applied_generation"], serde_json::json!(42));
        assert_eq!(actual["pending_generation"], serde_json::json!(45));
        assert_eq!(actual["desired_hash"], serde_json::json!("hash-pending-45"));
        let mismatches = status_v1_expected_projection_mismatches(
            "real-admission-baseline-accepted",
            &actual,
            "pending",
            "unknown",
            "poll",
            None,
            42,
        );

        drop(prepared);
        std::fs::remove_dir_all(&root)
            .expect("real admission Status V1 temporary root should be removable");
        assert!(
            mismatches.is_empty(),
            "real admitted B/B/N intent must remain poll-only without rewriting accepted:\n{}",
            mismatches.join("\n")
        );
    }

    #[tokio::test]
    async fn neutron_snapshot_status_v1_real_wal_recovery_keeps_baseline_accepted_generation() {
        let root = temp_root("status-v1-real-wal-recovery-pending-identity");
        let initial = test_neutron_state(&root);
        let baseline = committed_runtime(52);
        initial
            .wal
            .append_snapshot_commit(baseline.to_wal_state())
            .expect("classified baseline should be durable before the intent");
        initial
            .wal
            .append_snapshot_intent(
                55,
                Some("hash-recovery-55".to_string()),
                Vec::new(),
                Vec::new(),
                Vec::new(),
                None,
            )
            .expect("ordinary cause-free snapshot intent should be durable");
        drop(initial);

        let restarted = test_neutron_state(&root);
        let replayed_intent = restarted
            .pending_recovery
            .as_ref()
            .expect("restart must retain the unmatched non-inventory intent");
        assert_eq!(replayed_intent.kind, "snapshot");
        assert_eq!(replayed_intent.generation, 55);
        assert_eq!(replayed_intent.recovery_cause, None);
        {
            let runtime = restarted.runtime.read().await;
            assert_eq!(runtime.accepted_generation, 52);
            assert_eq!(runtime.applied_generation, 52);
            assert_eq!(runtime.pending_generation, Some(55));
            assert_eq!(runtime.authority_state, "wal_intent_without_commit");
        }

        restarted.recover_incomplete_wal_intent().await;
        {
            let runtime = restarted.runtime.read().await;
            assert_eq!(runtime.accepted_generation, 52);
            assert_eq!(runtime.applied_generation, 52);
            assert_eq!(runtime.pending_generation, Some(55));
            assert_eq!(runtime.desired_hash.as_deref(), Some("hash-recovery-55"));
            assert_eq!(runtime.applied_desired_hash, baseline.applied_desired_hash);
            assert_eq!(runtime.authority_state, "blocked_recovery_required");
            assert_eq!(runtime.wal_status, "intent_recovery_blocked");
            assert_eq!(runtime.recovery_cause, None);
        }

        let response = get_neutron_status(State(restarted.clone()))
            .await
            .into_response();
        let (status, actual) = response_json_value(response).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(actual["accepted_generation"], serde_json::json!(52));
        assert_eq!(actual["applied_generation"], serde_json::json!(52));
        assert_eq!(actual["pending_generation"], serde_json::json!(55));
        assert_eq!(
            actual["desired_hash"],
            serde_json::json!("hash-recovery-55")
        );
        let mismatches = status_v1_expected_projection_mismatches(
            "real-wal-recovery-baseline-accepted",
            &actual,
            "blocked",
            "blocked",
            "recover_pending",
            None,
            52,
        );

        std::fs::remove_dir_all(&root)
            .expect("real WAL recovery Status V1 temporary root should be removable");
        assert!(
            mismatches.is_empty(),
            "real recovered B/B/N intent must remain recoverable without rewriting accepted:\n{}",
            mismatches.join("\n")
        );
    }

    #[tokio::test]
    async fn neutron_snapshot_status_v1_projection_prioritizes_uncertainty_over_pending_and_recovery(
    ) {
        let expected = expected_status_v1_projection("blocked-operator");
        let mut mismatches = Vec::new();

        let mut uncertain_seed = status_v1_runtime_seed("pending-poll");
        uncertain_seed.wal_replay_failures = 1;
        let uncertain = status_v1_json_for_runtime(
            "wal-uncertainty-over-pending",
            runtime_from_status_v1_seed(uncertain_seed),
        )
        .await;
        let uncertain_mismatches =
            status_v1_projection_field_mismatches("blocked-operator", expected, &uncertain);
        if !uncertain_mismatches.is_empty() {
            mismatches.push(format!(
                "wal uncertainty must normalize ahead of pending:\n{}",
                uncertain_mismatches.join("\n")
            ));
        }

        let mut recognized_recovery_seed =
            status_v1_runtime_seed("blocked-recoverable-inventory");
        recognized_recovery_seed.wal_replay_failures = 1;
        let recognized_recovery = status_v1_json_for_runtime(
            "wal-uncertainty-over-recognized-recovery",
            runtime_from_status_v1_seed(recognized_recovery_seed),
        )
        .await;
        let recognized_recovery_mismatches = status_v1_projection_field_mismatches(
            "blocked-operator",
            expected,
            &recognized_recovery,
        );
        if !recognized_recovery_mismatches.is_empty() {
            mismatches.push(format!(
                "WAL uncertainty must normalize ahead of recognized recovery:\n{}",
                recognized_recovery_mismatches.join("\n")
            ));
        }

        let mut unknown_cause_seed = status_v1_runtime_seed("blocked-recoverable-inventory");
        unknown_cause_seed.recovery_cause = Some("inventory_timeout".to_string());
        let unknown_cause = status_v1_json_for_runtime(
            "unknown-recovery-cause",
            runtime_from_status_v1_seed(unknown_cause_seed),
        )
        .await;
        let unknown_cause_mismatches =
            status_v1_projection_field_mismatches("blocked-operator", expected, &unknown_cause);
        if !unknown_cause_mismatches.is_empty() {
            mismatches.push(format!(
                "unknown recovery cause must normalize to operator-only blocked:\n{}",
                unknown_cause_mismatches.join("\n")
            ));
        }

        assert!(
            mismatches.is_empty(),
            "Status V1 projection precedence is not fail-closed:\n{}",
            mismatches.join("\n\n")
        );
    }

    fn status_v1_expected_projection_mismatches(
        label: &str,
        actual: &Value,
        transaction_state: &str,
        overall_readiness: &str,
        required_action: &str,
        recovery_cause: Option<&str>,
        last_classified_generation: u64,
    ) -> Vec<String> {
        let expected_recovery_cause = recovery_cause
            .map(|cause| Value::String(cause.to_string()))
            .unwrap_or(Value::Null);
        let expected = [
            (
                "transaction_state",
                Value::String(transaction_state.to_string()),
            ),
            (
                "overall_readiness",
                Value::String(overall_readiness.to_string()),
            ),
            (
                "required_action",
                Value::String(required_action.to_string()),
            ),
            ("recovery_cause", expected_recovery_cause),
            (
                "last_classified_generation",
                Value::Number(last_classified_generation.into()),
            ),
        ];
        let mut mismatches = Vec::new();
        for (field, expected_value) in expected {
            if actual.get(field) != Some(&expected_value) {
                mismatches.push(format!(
                    "{label}.{field}: expected {expected_value}, got {:?}",
                    actual.get(field)
                ));
            }
        }
        mismatches
    }

    fn status_v1_ready_runtime(
        port_id: &str,
        ifname: &str,
        generation: u64,
        domain: &str,
    ) -> NeutronRuntimeState {
        let managed_port = ManagedNeutronPort {
            managed_domains: vec![domain.to_string()],
            ..managed(port_id, ifname)
        };
        let domain_status = if domain == "acl" {
            domain_status_with_action("acl", "ready", None, Some("enforce".to_string()))
        } else {
            domain_status(domain, "ready", None)
        };
        let mut ports = BTreeMap::new();
        ports.insert(port_id.to_string(), managed_port);
        let mut statuses = BTreeMap::new();
        statuses.insert(
            port_id.to_string(),
            port_runtime_status(
                port_id,
                ifname,
                generation,
                Some(format!("hash-{generation}")),
                vec![domain.to_string()],
                "ready",
                None,
                vec![domain_status],
            ),
        );
        build_snapshot_commit_runtime(
            &NeutronRuntimeState::default(),
            generation,
            Some(format!("hash-{generation}")),
            ports,
            statuses,
            false,
        )
    }

    fn status_v1_runtime_with_raw_port_evidence(
        label: &str,
        generation: u64,
        status: &str,
        reason: &str,
        effective_action: &str,
    ) -> NeutronRuntimeState {
        let port_id = format!("port-{label}");
        let ifname = format!("tap-{label}");
        let managed_port = ManagedNeutronPort {
            managed_domains: vec!["acl".to_string()],
            ..managed(&port_id, &ifname)
        };
        let mut ports = BTreeMap::new();
        ports.insert(port_id.clone(), managed_port);
        let mut statuses = BTreeMap::new();
        statuses.insert(
            port_id.clone(),
            port_runtime_status(
                &port_id,
                &ifname,
                generation,
                Some(format!("hash-{generation}")),
                vec!["acl".to_string()],
                status,
                Some(reason.to_string()),
                vec![domain_status_with_action(
                    "acl",
                    status,
                    Some(reason.to_string()),
                    Some(effective_action.to_string()),
                )],
            ),
        );
        build_snapshot_commit_runtime(
            &NeutronRuntimeState::default(),
            generation,
            Some(format!("hash-{generation}")),
            ports,
            statuses,
            false,
        )
    }

    #[tokio::test]
    async fn neutron_snapshot_status_v1_real_terminal_degraded_commit_stays_classified() {
        let generation = 60;
        let desired_hash = format!("hash-{generation}");
        let port_snapshot = NeutronPortSnapshot {
            managed_domains: vec!["acl".to_string()],
            ..port("terminal-degraded", "tap-terminal-degraded", true)
        };
        let plan = AclApplyPlan {
            force_bypass_reason: Some("acl_rule_limit_exceeded:1001:1000".to_string()),
            ..AclApplyPlan::default()
        };
        let outcome = NeutronAclReconcileOutcome::from_plan(&plan);
        let domains = vec![outcome.domain_status(&port_snapshot)];
        let (port_status, port_reason) = successful_port_status(&domains);
        let managed_port = ManagedNeutronPort {
            managed_domains: vec!["acl".to_string()],
            ..managed(&port_snapshot.port_id, &port_snapshot.ifname)
        };
        let mut ports = BTreeMap::new();
        ports.insert(managed_port.port_id.clone(), managed_port);
        let mut statuses = BTreeMap::new();
        statuses.insert(
            port_snapshot.port_id.clone(),
            port_runtime_status(
                &port_snapshot.port_id,
                &port_snapshot.ifname,
                generation,
                Some(desired_hash.clone()),
                vec!["acl".to_string()],
                &port_status,
                port_reason,
                domains,
            ),
        );
        let runtime = build_snapshot_commit_runtime(
            &NeutronRuntimeState::default(),
            generation,
            Some(desired_hash.clone()),
            ports,
            statuses,
            false,
        );

        let committed_status = runtime
            .port_statuses
            .get(&port_snapshot.port_id)
            .expect("terminal-degraded commit must retain its port evidence");
        assert_eq!(runtime.authority_state, "ready");
        assert_eq!(runtime.pending_generation, None);
        assert_eq!(runtime.accepted_generation, generation);
        assert_eq!(runtime.applied_generation, generation);
        assert_eq!(runtime.desired_hash.as_deref(), Some(desired_hash.as_str()));
        assert_eq!(
            runtime.applied_desired_hash.as_deref(),
            Some(desired_hash.as_str())
        );
        assert_eq!(committed_status.status, "degraded");
        assert_eq!(
            committed_status.reason.as_deref(),
            Some("acl_rule_limit_exceeded:1001:1000")
        );
        assert!(committed_status.domains.iter().any(|domain| {
            domain.domain == "acl"
                && domain.status == "degraded"
                && domain.effective_action.as_deref() == Some("bypass")
        }));

        let actual = status_v1_json_for_runtime("real-terminal-degraded", runtime).await;
        let mut mismatches = status_v1_expected_projection_mismatches(
            "real-terminal-degraded",
            &actual,
            "classified",
            "degraded",
            "none",
            None,
            generation,
        );
        if actual.get("overall_readiness").and_then(Value::as_str) == Some("ready") {
            mismatches.push(
                "real-terminal-degraded: terminal-degraded evidence must never emit ready"
                    .to_string(),
            );
        }
        assert!(
            mismatches.is_empty(),
            "authority_state=ready + port degraded + ACL degraded/bypass real commit did not stay classified:\n{}",
            mismatches.join("\n")
        );
    }

    #[tokio::test]
    async fn neutron_snapshot_status_v1_rebuild_reasons_are_exact_and_severity_gated() {
        let cases = [
            (
                "exact-runtime-rebuild-required",
                "degraded",
                "runtime_rebuild_required",
                "unchanged",
                "classified",
                "degraded",
                "full_resync",
            ),
            (
                "exact-acl-restart-replay",
                "degraded",
                "acl_restart_replay_requires_resync",
                "unchanged",
                "classified",
                "degraded",
                "full_resync",
            ),
            (
                "exact-tc-acl-link-lost",
                "degraded",
                "tc_acl_link_lost",
                "bypass",
                "classified",
                "degraded",
                "full_resync",
            ),
            (
                "diagnostic-substring-is-not-owned",
                "degraded",
                "acl_apply_failed:operator requested full_resync manually",
                "bypass",
                "classified",
                "degraded",
                "none",
            ),
            (
                "raw-blocked-outranks-owned-reason",
                "blocked",
                "runtime_rebuild_required",
                "unchanged",
                "blocked",
                "blocked",
                "operator",
            ),
            (
                "raw-error-outranks-owned-reason",
                "error",
                "acl_restart_replay_requires_resync",
                "unchanged",
                "blocked",
                "blocked",
                "operator",
            ),
            (
                "raw-recovered-outranks-owned-reason",
                "recovered",
                "tc_acl_link_lost",
                "unchanged",
                "blocked",
                "blocked",
                "operator",
            ),
        ];
        let mut mismatches = Vec::new();

        for (
            index,
            (
                label,
                raw_status,
                reason,
                effective_action,
                expected_state,
                expected_readiness,
                expected_action,
            ),
        ) in cases.into_iter().enumerate()
        {
            let generation = 70 + index as u64;
            let runtime = status_v1_runtime_with_raw_port_evidence(
                label,
                generation,
                raw_status,
                reason,
                effective_action,
            );
            let actual = status_v1_json_for_runtime(label, runtime).await;
            mismatches.extend(status_v1_expected_projection_mismatches(
                label,
                &actual,
                expected_state,
                expected_readiness,
                expected_action,
                None,
                generation,
            ));

            let expected_port_id = format!("port-{label}");
            let returned_row = actual
                .get("port_statuses")
                .and_then(Value::as_array)
                .and_then(|rows| {
                    rows.iter().find(|row| {
                        row.get("port_id").and_then(Value::as_str)
                            == Some(expected_port_id.as_str())
                    })
                });
            match returned_row {
                Some(row) => {
                    if row.get("reason").and_then(Value::as_str) != Some(reason) {
                        mismatches.push(format!(
                            "{label}: top-level reason expected {reason}, got {:?}",
                            row.get("reason")
                        ));
                    }
                    match row
                        .get("domains")
                        .and_then(Value::as_array)
                        .and_then(|domains| domains.first())
                    {
                        Some(domain) => {
                            for (field, expected) in [
                                ("reason", reason),
                                ("effective_action", effective_action),
                            ] {
                                if domain.get(field).and_then(Value::as_str) != Some(expected) {
                                    mismatches.push(format!(
                                        "{label}: domain {field} expected {expected}, got {:?}",
                                        domain.get(field)
                                    ));
                                }
                            }
                        }
                        None => mismatches.push(format!(
                            "{label}: projected reason evidence must retain an ACL domain row"
                        )),
                    }
                }
                None => mismatches.push(format!(
                    "{label}: projected reason evidence must retain port {expected_port_id}"
                )),
            }
        }

        assert!(
            mismatches.is_empty(),
            "Status V1 rebuild reasons were not exact and severity-gated:\n{}",
            mismatches.join("\n")
        );
    }

    #[tokio::test]
    async fn neutron_snapshot_status_v1_detached_tombstones_are_diagnostic_only() {
        let detached_port = ManagedNeutronPort {
            managed_domains: vec!["acl".to_string()],
            ..managed("detached-port", "tap-detached")
        };
        let mut previous_ports = BTreeMap::new();
        previous_ports.insert(detached_port.port_id.clone(), detached_port.clone());
        let mut previous_statuses = BTreeMap::new();
        previous_statuses.insert(
            detached_port.port_id.clone(),
            ready_status(&detached_port.port_id, &detached_port.ifname, 80),
        );
        let previous = build_snapshot_commit_runtime(
            &NeutronRuntimeState::default(),
            80,
            Some("hash-80".to_string()),
            previous_ports,
            previous_statuses,
            false,
        );

        let mut detached_statuses = BTreeMap::new();
        detached_statuses.insert(
            detached_port.port_id.clone(),
            port_runtime_status(
                &detached_port.port_id,
                &detached_port.ifname,
                81,
                Some("hash-81".to_string()),
                detached_port.managed_domains.clone(),
                "detached",
                None,
                domain_statuses_for(&detached_port.managed_domains, "detached", None),
            ),
        );
        let detached_runtime = build_snapshot_commit_runtime(
            &previous,
            81,
            Some("hash-81".to_string()),
            BTreeMap::new(),
            detached_statuses,
            false,
        );

        let ready_port = ManagedNeutronPort {
            managed_domains: vec!["acl".to_string()],
            ..managed("ready-port", "tap-ready")
        };
        let mut scoped_ports = BTreeMap::new();
        scoped_ports.insert(ready_port.port_id.clone(), ready_port.clone());
        let mut scoped_statuses = port_status_seed_for_scope(
            &detached_runtime,
            &ApplyScope::SinglePort(ready_port.port_id.clone()),
        );
        scoped_statuses.insert(
            ready_port.port_id.clone(),
            ready_status(&ready_port.port_id, &ready_port.ifname, 82),
        );
        let scoped_runtime = build_snapshot_commit_runtime(
            &detached_runtime,
            82,
            Some("hash-82".to_string()),
            scoped_ports,
            scoped_statuses,
            false,
        );

        let mut orphan_runtime = scoped_runtime.clone();
        orphan_runtime.port_statuses.insert(
            "orphan-port".to_string(),
            ready_status("orphan-port", "tap-orphan", 82),
        );

        let mut mismatches = Vec::new();
        if !detached_runtime.ports.is_empty() {
            mismatches.push(
                "full-host-detach setup: detached port must be absent from runtime.ports"
                    .to_string(),
            );
        }
        match detached_runtime.port_statuses.get("detached-port") {
            Some(status)
                if status.status == "detached"
                    && status
                        .domains
                        .iter()
                        .all(|domain| domain.status == "detached") => {}
            other => mismatches.push(format!(
                "full-host-detach setup: expected raw detached tombstone, got {other:?}"
            )),
        }
        match scoped_runtime.port_statuses.get("detached-port") {
            Some(status)
                if status.generation == 81
                    && status.desired_hash.as_deref() == Some("hash-81") => {}
            other => mismatches.push(format!(
                "scoped-preserved setup: expected older generation-81 tombstone, got {other:?}"
            )),
        }

        let cases = [
            (
                "full-host-detach",
                detached_runtime,
                "classified",
                "ready",
                "none",
                81,
                true,
            ),
            (
                "scoped-preserved-detach",
                scoped_runtime,
                "classified",
                "ready",
                "none",
                82,
                true,
            ),
            (
                "non-detached-orphan",
                orphan_runtime,
                "blocked",
                "blocked",
                "operator",
                82,
                false,
            ),
        ];

        for (
            label,
            runtime,
            expected_state,
            expected_readiness,
            expected_action,
            expected_generation,
            check_tombstone,
        ) in cases
        {
            let actual = status_v1_json_for_runtime(label, runtime).await;
            mismatches.extend(status_v1_expected_projection_mismatches(
                label,
                &actual,
                expected_state,
                expected_readiness,
                expected_action,
                None,
                expected_generation,
            ));

            match (
                actual.get("managed_ports").and_then(Value::as_array),
                actual.get("port_statuses").and_then(Value::as_array),
            ) {
                (Some(managed_rows), Some(status_rows)) => {
                    for managed_row in managed_rows {
                        let Some(port_id) = managed_row.get("port_id").and_then(Value::as_str)
                        else {
                            mismatches.push(format!(
                                "{label}: managed row is missing a string port_id: {managed_row}"
                            ));
                            continue;
                        };
                        let matching_rows = status_rows
                            .iter()
                            .filter(|row| {
                                row.get("port_id").and_then(Value::as_str) == Some(port_id)
                            })
                            .count();
                        if matching_rows != 1 {
                            mismatches.push(format!(
                                "{label}: managed port {port_id} must have exactly one status row, got {matching_rows}"
                            ));
                        }
                    }

                    if check_tombstone {
                        let tombstones = status_rows
                            .iter()
                            .filter(|row| {
                                row.get("port_id").and_then(Value::as_str)
                                    == Some("detached-port")
                            })
                            .collect::<Vec<_>>();
                        if tombstones.len() != 1 {
                            mismatches.push(format!(
                                "{label}: expected exactly one detached diagnostic row, got {}",
                                tombstones.len()
                            ));
                        } else {
                            let tombstone = tombstones[0];
                            if tombstone.get("status").and_then(Value::as_str)
                                != Some("detached")
                            {
                                mismatches.push(format!(
                                    "{label}: tombstone top-level status must remain detached, got {:?}",
                                    tombstone.get("status")
                                ));
                            }
                            match tombstone.get("domains").and_then(Value::as_array) {
                                Some(domains) if !domains.is_empty() => {
                                    for domain in domains {
                                        for (field, expected) in [
                                            ("status", "not_requested"),
                                            ("effective_action", "cleanup"),
                                            ("support_disposition", "not_applicable"),
                                        ] {
                                            if domain.get(field).and_then(Value::as_str)
                                                != Some(expected)
                                            {
                                                mismatches.push(format!(
                                                    "{label}: tombstone domain {field} expected {expected}, got {:?}",
                                                    domain.get(field)
                                                ));
                                            }
                                        }
                                    }
                                }
                                other => mismatches.push(format!(
                                    "{label}: tombstone must retain normalized domain evidence, got {other:?}"
                                )),
                            }
                        }
                    }
                }
                other => mismatches.push(format!(
                    "{label}: managed_ports and port_statuses must both be arrays, got {other:?}"
                )),
            }
        }

        assert!(
            mismatches.is_empty(),
            "detached tombstone handling was not narrow and diagnostic-only:\n{}",
            mismatches.join("\n")
        );
    }

    #[tokio::test]
    async fn neutron_snapshot_status_v1_rejects_malformed_identity_and_row_matrix() {
        struct MatrixCase {
            label: &'static str,
            runtime: NeutronRuntimeState,
            expected_state: &'static str,
            expected_readiness: &'static str,
            expected_action: &'static str,
            expected_generation: u64,
            historical_control: bool,
        }

        let base = status_v1_ready_runtime("matrix-port", "tap-matrix", 90, "acl");
        let blocked_case = |label: &'static str, runtime: NeutronRuntimeState| MatrixCase {
            label,
            runtime,
            expected_state: "blocked",
            expected_readiness: "blocked",
            expected_action: "operator",
            expected_generation: 90,
            historical_control: false,
        };

        let mut generation_zero_pending = runtime_from_status_v1_seed(
            status_v1_runtime_seed("generation-zero-inventory-recovery"),
        );
        generation_zero_pending.accepted_generation = 0;
        generation_zero_pending.pending_generation = Some(0);

        let mut middle_pending_generation =
            runtime_from_status_v1_seed(status_v1_runtime_seed("pending-poll"));
        middle_pending_generation.accepted_generation = 43;

        let mut baseline_accepted_inventory =
            runtime_from_status_v1_seed(status_v1_runtime_seed("blocked-recoverable-inventory"));
        baseline_accepted_inventory.accepted_generation =
            baseline_accepted_inventory.applied_generation;

        let mut same_generation_pending_hash_mismatch = base.clone();
        same_generation_pending_hash_mismatch.accepted_generation =
            same_generation_pending_hash_mismatch.applied_generation;
        same_generation_pending_hash_mismatch.pending_generation =
            Some(same_generation_pending_hash_mismatch.applied_generation);
        same_generation_pending_hash_mismatch.desired_hash =
            Some("hash-pending-mismatch".to_string());
        same_generation_pending_hash_mismatch.recovery_cause = None;
        same_generation_pending_hash_mismatch.authority_state =
            "blocked_recovery_required".to_string();

        let mut managed_map_key_mismatch = base.clone();
        let managed_row = managed_map_key_mismatch
            .ports
            .remove("matrix-port")
            .expect("matrix baseline must contain its managed row");
        managed_map_key_mismatch
            .ports
            .insert("managed-map-alias".to_string(), managed_row);

        let mut status_map_key_mismatch = base.clone();
        let status_row = status_map_key_mismatch
            .port_statuses
            .remove("matrix-port")
            .expect("matrix baseline must contain its status row");
        status_map_key_mismatch
            .port_statuses
            .insert("status-map-alias".to_string(), status_row);

        let mut status_embedded_id_mismatch = base.clone();
        status_embedded_id_mismatch
            .port_statuses
            .get_mut("matrix-port")
            .expect("matrix baseline must contain its status row")
            .port_id = "embedded-status-alias".to_string();

        let mut zero_row_generation = base.clone();
        zero_row_generation
            .port_statuses
            .get_mut("matrix-port")
            .expect("matrix baseline must contain its status row")
            .generation = 0;

        let mut future_row_generation = base.clone();
        future_row_generation
            .port_statuses
            .get_mut("matrix-port")
            .expect("matrix baseline must contain its status row")
            .generation = 91;

        let mut null_row_hash = base.clone();
        null_row_hash
            .port_statuses
            .get_mut("matrix-port")
            .expect("matrix baseline must contain its status row")
            .desired_hash = None;

        let mut blank_row_hash = base.clone();
        blank_row_hash
            .port_statuses
            .get_mut("matrix-port")
            .expect("matrix baseline must contain its status row")
            .desired_hash = Some("   ".to_string());

        let mut current_row_hash_mismatch = base.clone();
        current_row_hash_mismatch
            .port_statuses
            .get_mut("matrix-port")
            .expect("matrix baseline must contain its status row")
            .desired_hash = Some("hash-current-mismatch".to_string());

        let mut ready_with_degraded_domain = base.clone();
        ready_with_degraded_domain
            .port_statuses
            .get_mut("matrix-port")
            .expect("matrix baseline must contain its status row")
            .domains[0]
            .status = "degraded".to_string();

        let mut ready_with_blocked_domain = base.clone();
        ready_with_blocked_domain
            .port_statuses
            .get_mut("matrix-port")
            .expect("matrix baseline must contain its status row")
            .domains[0]
            .status = "blocked".to_string();

        let mut attach_not_requested =
            status_v1_ready_runtime("matrix-attach", "tap-matrix-attach", 90, "attach");
        let attach_status = attach_not_requested
            .port_statuses
            .get_mut("matrix-attach")
            .expect("attach matrix baseline must contain its status row");
        attach_status.status = "not_requested".to_string();
        attach_status.domains[0].status = "not_requested".to_string();

        let mut degraded_without_degraded_domain = base.clone();
        degraded_without_degraded_domain
            .port_statuses
            .get_mut("matrix-port")
            .expect("matrix baseline must contain its status row")
            .status = "degraded".to_string();

        let mut unsupported_without_degraded_domain = base.clone();
        unsupported_without_degraded_domain
            .port_statuses
            .get_mut("matrix-port")
            .expect("matrix baseline must contain its status row")
            .status = "unsupported".to_string();

        let mut non_detached_orphan = base.clone();
        non_detached_orphan.port_statuses.insert(
            "matrix-orphan".to_string(),
            ready_status("matrix-orphan", "tap-matrix-orphan", 90),
        );

        let scoped_target = ManagedNeutronPort {
            managed_domains: vec!["acl".to_string()],
            ..managed("matrix-port", "tap-matrix")
        };
        let scoped_older = ManagedNeutronPort {
            managed_domains: vec!["acl".to_string()],
            ..managed("matrix-old", "tap-matrix-old")
        };
        let mut scoped_previous_ports = BTreeMap::new();
        scoped_previous_ports.insert(scoped_target.port_id.clone(), scoped_target.clone());
        scoped_previous_ports.insert(scoped_older.port_id.clone(), scoped_older.clone());
        let mut scoped_previous_statuses = BTreeMap::new();
        scoped_previous_statuses.insert(
            scoped_target.port_id.clone(),
            ready_status(&scoped_target.port_id, &scoped_target.ifname, 89),
        );
        scoped_previous_statuses.insert(
            scoped_older.port_id.clone(),
            ready_status(&scoped_older.port_id, &scoped_older.ifname, 89),
        );
        let scoped_previous = build_snapshot_commit_runtime(
            &NeutronRuntimeState::default(),
            89,
            Some("hash-89".to_string()),
            scoped_previous_ports.clone(),
            scoped_previous_statuses,
            false,
        );
        let mut scoped_next_statuses = port_status_seed_for_scope(
            &scoped_previous,
            &ApplyScope::SinglePort(scoped_target.port_id.clone()),
        );
        scoped_next_statuses.insert(
            scoped_target.port_id.clone(),
            ready_status(&scoped_target.port_id, &scoped_target.ifname, 90),
        );
        let historical_scoped_control = build_snapshot_commit_runtime(
            &scoped_previous,
            90,
            Some("hash-90".to_string()),
            scoped_previous_ports,
            scoped_next_statuses,
            false,
        );

        let cases = vec![
            MatrixCase {
                label: "generation-zero-pending-zero",
                runtime: generation_zero_pending,
                expected_state: "blocked",
                expected_readiness: "blocked",
                expected_action: "operator",
                expected_generation: 0,
                historical_control: false,
            },
            MatrixCase {
                label: "middle-pending-generation",
                runtime: middle_pending_generation,
                expected_state: "blocked",
                expected_readiness: "blocked",
                expected_action: "operator",
                expected_generation: 42,
                historical_control: false,
            },
            MatrixCase {
                label: "inventory-recovery-with-baseline-accepted",
                runtime: baseline_accepted_inventory,
                expected_state: "blocked",
                expected_readiness: "blocked",
                expected_action: "operator",
                expected_generation: 42,
                historical_control: false,
            },
            blocked_case(
                "same-generation-pending-hash-mismatch",
                same_generation_pending_hash_mismatch,
            ),
            blocked_case("managed-map-key-mismatch", managed_map_key_mismatch),
            blocked_case("status-map-key-mismatch", status_map_key_mismatch),
            blocked_case("status-embedded-id-mismatch", status_embedded_id_mismatch),
            blocked_case("managed-row-generation-zero", zero_row_generation),
            blocked_case("managed-row-generation-future", future_row_generation),
            blocked_case("managed-row-hash-null", null_row_hash),
            blocked_case("managed-row-hash-blank", blank_row_hash),
            blocked_case(
                "current-generation-row-hash-mismatch",
                current_row_hash_mismatch,
            ),
            blocked_case("ready-with-degraded-domain", ready_with_degraded_domain),
            blocked_case("ready-with-blocked-domain", ready_with_blocked_domain),
            blocked_case("attach-not-requested", attach_not_requested),
            blocked_case(
                "degraded-without-terminal-degraded-domain",
                degraded_without_degraded_domain,
            ),
            blocked_case(
                "unsupported-without-terminal-degraded-domain",
                unsupported_without_degraded_domain,
            ),
            blocked_case("non-detached-extra-status-row", non_detached_orphan),
            MatrixCase {
                label: "older-scoped-row-with-historical-hash",
                runtime: historical_scoped_control,
                expected_state: "classified",
                expected_readiness: "ready",
                expected_action: "none",
                expected_generation: 90,
                historical_control: true,
            },
        ];
        let mut mismatches = Vec::new();

        for case in cases {
            let actual = status_v1_json_for_runtime(case.label, case.runtime).await;
            mismatches.extend(status_v1_expected_projection_mismatches(
                case.label,
                &actual,
                case.expected_state,
                case.expected_readiness,
                case.expected_action,
                None,
                case.expected_generation,
            ));

            if case.label == "managed-row-generation-future" {
                match actual.get("port_statuses").and_then(Value::as_array) {
                    Some(rows) if rows.is_empty() => {}
                    other => mismatches.push(format!(
                        "{}: future-generation rows must stay internal, got {other:?}",
                        case.label
                    )),
                }
            }

            if case.historical_control {
                let historical_rows = actual
                    .get("port_statuses")
                    .and_then(Value::as_array)
                    .map(|rows| {
                        rows.iter()
                            .filter(|row| {
                                row.get("port_id").and_then(Value::as_str) == Some("matrix-old")
                            })
                            .collect::<Vec<_>>()
                    });
                match historical_rows {
                    Some(rows)
                        if rows.len() == 1
                            && rows[0].get("generation").and_then(Value::as_u64) == Some(89)
                            && rows[0].get("desired_hash").and_then(Value::as_str)
                                == Some("hash-89") => {}
                    other => mismatches.push(format!(
                        "{}: older scoped row and historical hash must be preserved, got {other:?}",
                        case.label
                    )),
                }
            }
        }

        assert!(
            mismatches.is_empty(),
            "Status V1 accepted a malformed identity/row/top-level matrix or rejected the scoped control:\n{}",
            mismatches.join("\n")
        );
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

    fn acl_rule_with(
        id: &str,
        priority: i64,
        protocol: &str,
        action: &str,
        src_cidrs: &[&str],
        dst_cidrs: &[&str],
        dst_port: Option<u16>,
    ) -> NeutronAclRuleSnapshot {
        NeutronAclRuleSnapshot {
            id: Some(id.to_string()),
            direction: Some("egress".to_string()),
            priority,
            action: Some(action.to_string()),
            ethertype: Some("IPv4".to_string()),
            protocol: Some(protocol.to_string()),
            src_cidrs: src_cidrs.iter().map(|value| value.to_string()).collect(),
            dst_cidrs: dst_cidrs.iter().map(|value| value.to_string()).collect(),
            src_port_min: None,
            src_port_max: None,
            dst_port_min: dst_port,
            dst_port_max: dst_port,
        }
    }

    fn numbered_acl_rules(count: usize) -> Vec<NeutronAclRuleSnapshot> {
        (0..count)
            .map(|index| {
                acl_rule_with(
                    &format!("rule-{}", index),
                    index as i64,
                    "tcp",
                    "drop",
                    &[],
                    &[],
                    None,
                )
            })
            .collect()
    }

    fn numbered_acl_members(count: usize) -> Vec<String> {
        (0..count)
            .map(|index| {
                format!(
                    "10.{}.{}.{}/32",
                    (index >> 16) & 0xff,
                    (index >> 8) & 0xff,
                    index & 0xff,
                )
            })
            .collect()
    }

    fn normalized_acl_rule_with_selectors(
        id: &str,
        priority: i64,
        proto: u8,
        src_selector_id: usize,
        dst_selector_id: usize,
    ) -> NormalizedAclRule {
        NormalizedAclRule {
            id: id.to_string(),
            direction: "egress".to_string(),
            priority,
            directions: vec![0],
            proto,
            action: 1,
            src_selector_id: AclSelectorId(src_selector_id),
            dst_selector_id: AclSelectorId(dst_selector_id),
            ports: Vec::new(),
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
            inventory_error: None,
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
            inventory_error: None,
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

    #[tokio::test]
    async fn neutron_snapshot_transaction_ovsdb_unavailable_preserves_committed_runtime() {
        let root = temp_root("inventory-unavailable-transaction");
        let state = test_neutron_state(&root);
        let previous = committed_runtime(80);
        let current_ports = previous.ports.clone();
        let snapshot = inventory_snapshot(
            81,
            vec![NeutronPortSnapshot {
                managed_domains: vec!["acl".to_string()],
                ..port("committed-port", "tap-committed", true)
            }],
        );
        let local = unavailable_inventory("permission denied");
        let transaction = build_snapshot_apply_transaction(
            &current_ports,
            &snapshot,
            &local,
            ApplyScope::FullHost,
        )
        .expect("inventory failure remains a valid transaction plan");

        let outcome = apply_snapshot_runtime_transaction(
            &state,
            snapshot.generation,
            snapshot.desired_hash.clone(),
            current_ports,
            previous.clone(),
            transaction,
        )
        .await;

        assert!(
            outcome.has_error,
            "inventory loss must fail the transaction"
        );
        assert_eq!(outcome.previous_applied_generation, 80);
        assert!(outcome.results.iter().any(|result| {
            result.port_id == "snapshot"
                && result.ifname.is_empty()
                && result.action == "ignore"
                && result.status == "error"
                && result.reason.as_deref() == Some("ovsdb_unavailable:permission denied")
        }));
        assert!(outcome.results.iter().any(|result| {
            result.port_id == "committed-port"
                && result.status == "ignored"
                && result.reason.as_deref() == Some("ovsdb_unavailable:permission denied")
        }));
        assert_eq!(outcome.next_runtime.accepted_generation, 81);
        assert_eq!(
            outcome.next_runtime.desired_hash.as_deref(),
            Some("hash-81")
        );
        assert_eq!(outcome.next_runtime.pending_generation, Some(81));
        assert_eq!(
            outcome.next_runtime.authority_state,
            "blocked_recovery_required"
        );
        assert_eq!(outcome.next_runtime.wal_status, "inventory_unavailable");
        assert_eq!(outcome.next_runtime.applied_generation, 80);
        assert_eq!(
            outcome.next_runtime.applied_desired_hash,
            previous.applied_desired_hash
        );
        assert_eq!(outcome.next_runtime.ports, previous.ports);
        assert_eq!(outcome.next_runtime.port_statuses, previous.port_statuses);
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn neutron_snapshot_transaction_empty_snapshot_ovsdb_unavailable_preserves_committed_runtime(
    ) {
        let root = temp_root("inventory-unavailable-empty-transaction");
        let state = test_neutron_state(&root);
        let previous = committed_runtime(82);
        let current_ports = previous.ports.clone();
        let snapshot = inventory_snapshot(83, Vec::new());
        let local = unavailable_inventory("database offline");
        let transaction = build_snapshot_apply_transaction(
            &current_ports,
            &snapshot,
            &local,
            ApplyScope::FullHost,
        )
        .expect("empty snapshot still carries transaction-level inventory authority");

        let outcome = apply_snapshot_runtime_transaction(
            &state,
            snapshot.generation,
            snapshot.desired_hash.clone(),
            current_ports,
            previous.clone(),
            transaction,
        )
        .await;

        assert!(
            outcome.has_error,
            "empty bodies must not hide inventory loss"
        );
        assert_eq!(outcome.results.len(), 1);
        assert_eq!(outcome.results[0].port_id, "snapshot");
        assert_eq!(outcome.results[0].status, "error");
        assert_eq!(
            outcome.results[0].reason.as_deref(),
            Some("ovsdb_unavailable:database offline")
        );
        assert_eq!(outcome.next_runtime.accepted_generation, 83);
        assert_eq!(
            outcome.next_runtime.desired_hash.as_deref(),
            Some("hash-83")
        );
        assert_eq!(outcome.next_runtime.pending_generation, Some(83));
        assert_eq!(
            outcome.next_runtime.authority_state,
            "blocked_recovery_required"
        );
        assert_eq!(outcome.next_runtime.wal_status, "inventory_unavailable");
        assert_eq!(outcome.next_runtime.applied_generation, 82);
        assert_eq!(
            outcome.next_runtime.applied_desired_hash,
            previous.applied_desired_hash
        );
        assert_eq!(outcome.next_runtime.ports, previous.ports);
        assert_eq!(outcome.next_runtime.port_statuses, previous.port_statuses);
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn neutron_snapshot_transaction_authoritative_ignored_ports_commit() {
        let root = temp_root("authoritative-ignored-ports");
        let state = test_neutron_state(&root);
        let mut dhcp = port("dhcp-port", "tap-dhcp", true);
        dhcp.device_owner = Some("network:dhcp".to_string());
        let mut direct = port("direct-port", "tap-direct", true);
        direct.device_owner = Some("compute:nova".to_string());
        direct.vif_type = Some("ovs".to_string());
        direct.vnic_type = Some("direct".to_string());
        let mut router = port("router-port", "tap-router", true);
        router.device_owner = Some("network:router_interface".to_string());
        let snapshot = inventory_snapshot(84, vec![dhcp, direct, router]);
        let local = inventory(Vec::new());
        let transaction = build_snapshot_apply_transaction(
            &BTreeMap::new(),
            &snapshot,
            &local,
            ApplyScope::FullHost,
        )
        .expect("authoritative ignored ports remain a valid transaction");

        let outcome = apply_snapshot_runtime_transaction(
            &state,
            snapshot.generation,
            snapshot.desired_hash.clone(),
            BTreeMap::new(),
            NeutronRuntimeState::default(),
            transaction,
        )
        .await;

        assert!(!outcome.has_error);
        assert_eq!(outcome.results.len(), 3);
        assert!(outcome
            .results
            .iter()
            .all(|result| result.action == "ignore" && result.status == "ignored"));
        assert!(outcome.results.iter().any(|result| {
            result.port_id == "dhcp-port"
                && result.reason.as_deref() == Some("not_applicable_device_owner:network:dhcp")
        }));
        assert!(outcome.results.iter().any(|result| {
            result.port_id == "direct-port"
                && result.reason.as_deref() == Some("unsupported_vnic_type:direct")
        }));
        assert!(outcome.results.iter().any(|result| {
            result.port_id == "router-port"
                && result.reason.as_deref()
                    == Some("not_applicable_device_owner:network:router_interface")
        }));
        assert_eq!(outcome.next_runtime.accepted_generation, 84);
        assert_eq!(outcome.next_runtime.applied_generation, 84);
        assert_eq!(outcome.next_runtime.pending_generation, None);
        assert_eq!(outcome.next_runtime.authority_state, "ready");
        assert!(outcome.next_runtime.ports.is_empty());
        assert!(outcome.next_runtime.port_statuses.is_empty());
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn neutron_snapshot_ovsdb_unavailable_wal_commit_and_recovery_preserve_last_applied() {
        let root = temp_root("inventory-unavailable-wal-recovery");
        let state = test_neutron_state(&root);
        let previous = committed_runtime(90);
        state
            .wal
            .append_snapshot_commit(previous.to_wal_state())
            .expect("baseline commit should be durable");
        let snapshot = inventory_snapshot(
            91,
            vec![NeutronPortSnapshot {
                managed_domains: vec!["acl".to_string()],
                ..port("committed-port", "tap-committed", true)
            }],
        );
        let local = unavailable_inventory("connection refused");
        let transaction = build_snapshot_apply_transaction(
            &previous.ports,
            &snapshot,
            &local,
            ApplyScope::FullHost,
        )
        .expect("inventory failure should produce a durable transaction");
        state
            .wal
            .append_snapshot_intent(
                snapshot.generation,
                snapshot.desired_hash.clone(),
                Vec::new(),
                transaction.affected_domains.clone(),
                transaction.affected_ports.clone(),
                Some(INVENTORY_UNAVAILABLE_RECOVERY_CAUSE.to_string()),
            )
            .expect("inventory-failed snapshot intent should be durable");

        let outcome = apply_snapshot_runtime_transaction(
            &state,
            snapshot.generation,
            snapshot.desired_hash.clone(),
            previous.ports.clone(),
            previous.clone(),
            transaction,
        )
        .await;
        state
            .wal
            .append_snapshot_commit(outcome.next_runtime.to_wal_state())
            .expect("blocked inventory state should be durable");

        let replay = state.wal.replay();
        assert_eq!(replay.status, "inventory_unavailable");
        assert_eq!(replay.failures, 0);
        assert_eq!(replay.state.accepted_generation, 91);
        assert_eq!(replay.state.applied_generation, 90);
        assert_eq!(replay.state.pending_generation, Some(91));
        assert_eq!(replay.state.desired_hash.as_deref(), Some("hash-91"));
        assert_eq!(
            replay.state.applied_desired_hash,
            previous.applied_desired_hash
        );
        assert_eq!(replay.state.authority_state, "blocked_recovery_required");
        assert_eq!(replay.state.ports, previous.ports);
        assert_eq!(replay.state.port_statuses, previous.port_statuses);
        let wal_path = state
            .registry
            .base_state_path
            .join("neutron-snapshot.wal");
        let wal_before_reconcile =
            std::fs::read_to_string(&wal_path).expect("blocked WAL should be readable");

        let restarted = NeutronRuntimeState::from_wal_state(
            replay.state.clone(),
            replay.status.clone(),
            replay.failures,
        );
        assert_eq!(restarted.wal_status, "inventory_unavailable");
        let before_reconcile = restarted.clone();
        {
            let mut runtime = state.runtime.write().await;
            *runtime = restarted;
        }
        state.reconcile_committed_runtime().await;
        let wal_after_reconcile =
            std::fs::read_to_string(&wal_path).expect("reconciled WAL should be readable");
        assert_eq!(
            wal_after_reconcile, wal_before_reconcile,
            "background reconciliation must not append or rewrite inventory-blocked WAL"
        );
        let runtime_after_reconcile = {
            let runtime = state.runtime.read().await;
            assert_eq!(
                runtime.accepted_generation,
                before_reconcile.accepted_generation
            );
            assert_eq!(
                runtime.applied_generation,
                before_reconcile.applied_generation
            );
            assert_eq!(
                runtime.pending_generation,
                before_reconcile.pending_generation
            );
            assert_eq!(runtime.desired_hash, before_reconcile.desired_hash);
            assert_eq!(
                runtime.applied_desired_hash,
                before_reconcile.applied_desired_hash
            );
            assert_eq!(runtime.authority_state, before_reconcile.authority_state);
            assert_eq!(runtime.wal_status, before_reconcile.wal_status);
            assert_eq!(runtime.ports, before_reconcile.ports);
            assert_eq!(runtime.port_statuses, before_reconcile.port_statuses);
            assert_eq!(
                runtime.wal_replay_failures,
                before_reconcile.wal_replay_failures
            );
            runtime.clone()
        };
        state
            .wal
            .append_snapshot_commit(runtime_after_reconcile.to_wal_state())
            .expect("restarted inventory cause should remain persistable");
        let recommitted_raw =
            std::fs::read_to_string(&wal_path).expect("recommitted WAL should be readable");
        assert!(
            recommitted_raw
                .lines()
                .last()
                .is_some_and(|line| line.contains(r#""recovery_cause":"inventory_unavailable""#)),
            "runtime round-trip must persist the inventory cause again"
        );
        let replay_after_recommit = state.wal.replay();
        assert_eq!(replay_after_recommit.status, "inventory_unavailable");
        assert_eq!(replay_after_recommit.state.accepted_generation, 91);
        assert_eq!(replay_after_recommit.state.applied_generation, 90);
        assert_eq!(replay_after_recommit.state.pending_generation, Some(91));

        let recovered = recover_pending_snapshot(
            state.clone(),
            NeutronRecoverPendingRequest {
                expected_pending_generation: 91,
                expected_desired_hash: Some("hash-91".to_string()),
                mode: None,
            },
        )
        .await
        .expect("inventory-only pending state should roll back to the last applied snapshot");
        assert_eq!(recovered.applied_generation, 90);
        assert_eq!(recovered.desired_hash.as_deref(), Some("hash-90"));
        assert_eq!(
            recovered.authority_state,
            "recovered_pending_full_resync_required"
        );
        let recovered_replay = state.wal.replay();
        assert_eq!(recovered_replay.status, "replayed");
        assert_eq!(recovered_replay.state.applied_generation, 90);
        assert_eq!(recovered_replay.state.pending_generation, None);
        assert_eq!(
            recovered_replay.state.desired_hash.as_deref(),
            Some("hash-90")
        );
        assert_eq!(recovered_replay.state.ports, previous.ports);
        assert_eq!(recovered_replay.state.port_statuses, previous.port_statuses);
        let recovered_raw =
            std::fs::read_to_string(&wal_path).expect("recovered WAL should be readable");
        let last_entry: serde_json::Value = serde_json::from_str(
            recovered_raw
                .lines()
                .last()
                .expect("recovery must append a final commit"),
        )
        .expect("final WAL entry should be valid JSON");
        assert_eq!(
            last_entry.get("type").and_then(serde_json::Value::as_str),
            Some("snapshot_commit")
        );
        let recovered_state = last_entry
            .get("state")
            .and_then(serde_json::Value::as_object)
            .expect("final snapshot commit should carry state");
        assert!(
            !recovered_state.contains_key("recovery_cause"),
            "successful recovery must omit the cleared inventory cause"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn neutron_snapshot_inventory_unavailable_wal_round_trip_rehydrates_status() {
        let root = temp_root("inventory-unavailable-wal-round-trip");
        let state = test_neutron_state(&root);
        let previous = committed_runtime(100);
        let snapshot = inventory_snapshot(101, Vec::new());
        let local = unavailable_inventory("transaction timed out");
        let transaction = build_snapshot_apply_transaction(
            &previous.ports,
            &snapshot,
            &local,
            ApplyScope::FullHost,
        )
        .expect("empty outage snapshot should retain transaction authority");
        let outcome = apply_snapshot_runtime_transaction(
            &state,
            snapshot.generation,
            snapshot.desired_hash.clone(),
            previous.ports.clone(),
            previous.clone(),
            transaction,
        )
        .await;
        state
            .wal
            .append_snapshot_commit(outcome.next_runtime.to_wal_state())
            .expect("inventory recovery cause should commit through the runtime API");

        let raw =
            std::fs::read_to_string(state.registry.base_state_path.join("neutron-snapshot.wal"))
                .expect("WAL text should be readable");
        assert!(
            raw.contains(r#""recovery_cause":"inventory_unavailable""#),
            "typed recovery cause must be explicit in the WAL JSON"
        );
        let replay = state.wal.replay();
        assert_eq!(replay.status, "inventory_unavailable");
        assert_eq!(replay.failures, 0);
        assert_eq!(replay.state.applied_generation, 100);
        assert_eq!(replay.state.pending_generation, Some(101));
        let restarted =
            NeutronRuntimeState::from_wal_state(replay.state, replay.status, replay.failures);
        assert_eq!(restarted.wal_status, "inventory_unavailable");
        assert_eq!(restarted.applied_generation, 100);
        assert_eq!(restarted.pending_generation, Some(101));
        assert_eq!(restarted.ports, previous.ports);
        assert_eq!(restarted.port_statuses, previous.port_statuses);
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn neutron_snapshot_authoritative_success_clears_inventory_recovery_cause() {
        let root = temp_root("inventory-cause-cleared-by-success");
        let state = test_neutron_state(&root);
        let previous = committed_runtime(110);
        let outage = inventory_snapshot(111, Vec::new());
        let outage_transaction = build_snapshot_apply_transaction(
            &previous.ports,
            &outage,
            &unavailable_inventory("connection reset"),
            ApplyScope::FullHost,
        )
        .expect("inventory outage should remain a valid transaction");
        let outage_outcome = apply_snapshot_runtime_transaction(
            &state,
            outage.generation,
            outage.desired_hash.clone(),
            previous.ports.clone(),
            previous.clone(),
            outage_transaction,
        )
        .await;

        let successful = build_snapshot_commit_runtime(
            &outage_outcome.next_runtime,
            112,
            Some("hash-112".to_string()),
            previous.ports.clone(),
            previous.port_statuses.clone(),
            false,
        );
        assert_eq!(successful.accepted_generation, 112);
        assert_eq!(successful.applied_generation, 112);
        assert_eq!(successful.pending_generation, None);
        assert_eq!(successful.authority_state, "ready");
        let serialized = serde_json::to_string(&successful.to_wal_state())
            .expect("successful runtime state should serialize");
        assert!(
            !serialized.contains(r#""recovery_cause""#),
            "a later authoritative success must omit the cleared inventory cause"
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

    #[tokio::test]
    async fn snapshot_generation_retry_zero_rejected_before_restore_and_wal() {
        let root = temp_root("generation-zero-preflight");
        let state = test_neutron_state(&root);
        state.restore_ready.store(false, Ordering::Release);
        let before = {
            let runtime = state.runtime.read().await;
            SnapshotAdmissionIdentity::capture(&runtime)
        };
        let wal_path = state
            .registry
            .base_state_path
            .join("neutron-snapshot.wal");
        assert!(!wal_path.exists());

        let full = put_neutron_snapshot(
            State(state.clone()),
            Json(NeutronSnapshotRequest {
                schema_version: None,
                generation: 0,
                desired_hash: Some("hash-zero-full".to_string()),
                host: None,
                ports: Vec::new(),
            }),
        )
        .await
        .into_response();
        let (full_status, full_body) = response_json_value(full).await;
        let scoped = put_neutron_port_snapshot(
            State(state.clone()),
            Path("target-port".to_string()),
            Json(NeutronSnapshotRequest {
                schema_version: None,
                generation: 0,
                desired_hash: Some("hash-zero-scoped".to_string()),
                host: None,
                ports: vec![port("target-port", "tap-target", true)],
            }),
        )
        .await
        .into_response();
        let (scoped_status, scoped_body) = response_json_value(scoped).await;

        for (status, body) in [(full_status, full_body), (scoped_status, scoped_body)] {
            assert_eq!(status, StatusCode::BAD_REQUEST);
            assert_eq!(
                body.get("error").and_then(Value::as_str),
                Some("INVALID_SNAPSHOT_GENERATION")
            );
        }
        let after = {
            let runtime = state.runtime.read().await;
            SnapshotAdmissionIdentity::capture(&runtime)
        };
        assert_eq!(after, before);
        assert!(!wal_path.exists());
        let _ = std::fs::remove_dir_all(root);
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
    fn neutron_snapshot_same_generation_noop_rejects_ovsdb_unavailable() {
        let previous = committed_runtime(62);
        let snapshot = inventory_snapshot(
            62,
            vec![NeutronPortSnapshot {
                managed_domains: vec!["acl".to_string()],
                ..port("committed-port", "tap-committed", true)
            }],
        );
        let local = unavailable_inventory("connection refused");

        let response = snapshot_early_response_for_scope(
            &ApplyScope::FullHost,
            &previous,
            &snapshot,
            &local,
            &snapshot.desired_hash,
        )
        .expect("inventory failure must enter the transaction path, not return an error");

        assert!(
            response.is_none(),
            "non-authoritative inventory must not produce a same-generation noop"
        );
    }

    #[test]
    fn neutron_snapshot_same_generation_noop_verifies_only_scoped_managed_acl_projection() {
        let mut runtime = NeutronRuntimeState::default();
        let mut target = managed_with_ifindex("target-port", "tap-target", 63);
        target.managed_domains = vec!["acl".to_string()];
        let mut unrelated = managed_with_ifindex("other-port", "tap-other", 64);
        unrelated.managed_domains = vec!["acl".to_string()];
        runtime.ports.insert(target.port_id.clone(), target);
        runtime.ports.insert(unrelated.port_id.clone(), unrelated);

        let mut target_snapshot = port("target-port", "tap-target", true);
        target_snapshot.managed_domains = vec!["acl".to_string()];
        let snapshot = NeutronSnapshotRequest {
            schema_version: None,
            generation: 63,
            desired_hash: Some("hash-63".to_string()),
            host: None,
            ports: vec![target_snapshot],
        };

        assert_eq!(
            managed_acl_projection_verification_targets(
                &ApplyScope::SinglePort("target-port".to_string()),
                &runtime,
                &snapshot,
            ),
            vec!["tap-target".to_string()]
        );

        let mut non_acl_snapshot = snapshot.clone();
        non_acl_snapshot.ports[0].managed_domains = vec!["qos".to_string()];
        assert!(managed_acl_projection_verification_targets(
            &ApplyScope::SinglePort("target-port".to_string()),
            &runtime,
            &non_acl_snapshot,
        )
        .is_empty());
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
    async fn snapshot_generation_retry_cross_generation_same_hash_conflicts() {
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

        let error = accept_neutron_snapshot_submit(&state, &snapshot, &ApplyScope::FullHost)
            .await
            .expect_err("same hash with a different generation must conflict");

        assert_eq!(error.status, StatusCode::CONFLICT);
        assert_eq!(error.code, "snapshot_apply_in_progress");
        let runtime = state.runtime.read().await;
        assert_eq!(runtime.pending_generation, Some(110));
        assert_eq!(runtime.desired_hash.as_deref(), Some("hash-110"));
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn snapshot_generation_retry_exact_active_identity_deduplicates() {
        let root = temp_root("submit-pending-exact-identity");
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
            generation: 110,
            desired_hash: Some("hash-110".to_string()),
            host: None,
            ports: vec![port("target-port", "tap-target", true)],
        };

        let decision = accept_neutron_snapshot_submit(&state, &snapshot, &ApplyScope::FullHost)
            .await
            .expect("exact active transaction identity should deduplicate");

        assert!(decision.prepared.is_none());
        assert_eq!(decision.response.status, "pending");
        assert_eq!(decision.response.generation, 110);
        assert_eq!(decision.response.accepted_generation, 110);
        assert_eq!(state.runtime.read().await.pending_generation, Some(110));
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn snapshot_generation_retry_same_generation_different_hash_conflicts() {
        let root = temp_root("submit-pending-same-generation-different-hash");
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
            generation: 110,
            desired_hash: Some("different-hash".to_string()),
            host: None,
            ports: vec![port("target-port", "tap-target", true)],
        };

        let error = accept_neutron_snapshot_submit(&state, &snapshot, &ApplyScope::FullHost)
            .await
            .expect_err("same generation with a different hash must conflict");

        assert_eq!(error.status, StatusCode::CONFLICT);
        assert_eq!(error.code, "snapshot_apply_in_progress");
        assert_eq!(state.runtime.read().await.pending_generation, Some(110));
        let _ = std::fs::remove_dir_all(root);
    }

    fn retryable_partial_runtime(generation: u64, desired_hash: &str) -> NeutronRuntimeState {
        NeutronRuntimeState {
            accepted_generation: generation,
            applied_generation: 0,
            pending_generation: Some(generation),
            desired_hash: Some(desired_hash.to_string()),
            applied_desired_hash: None,
            authority_state: "partial".to_string(),
            wal_status: "commit_written".to_string(),
            ..NeutronRuntimeState::default()
        }
    }

    async fn apply_durable_partial_retry_with_results(
        state: &NeutronApiState,
        snapshot: NeutronSnapshotRequest,
        ignored: Vec<NeutronPortApplyResult>,
    ) -> NeutronSnapshotResponse {
        let decision = accept_neutron_snapshot_submit(state, &snapshot, &ApplyScope::FullHost)
            .await
            .expect("exact durable partial identity should be retryable");
        assert_eq!(decision.response.generation, snapshot.generation);
        assert_eq!(decision.response.desired_hash, snapshot.desired_hash);
        assert_eq!(
            state
                .wal
                .replay()
                .pending_intent
                .as_ref()
                .map(|intent| intent.generation),
            Some(snapshot.generation)
        );
        let mut prepared = decision
            .prepared
            .expect("durable partial must prepare one same-generation apply");
        prepared.transaction = build_snapshot_transaction_from_plan(
            ApplyScope::FullHost,
            &snapshot,
            SnapshotPlan {
                attach: Vec::new(),
                update: Vec::new(),
                detach: Vec::new(),
                ignored,
                inventory_error: None,
            },
        )
        .expect("test retry plan should remain within full-host scope");
        apply_neutron_snapshot_for_scope(
            state.clone(),
            snapshot,
            ApplyScope::FullHost,
            prepared,
        )
        .await
        .expect("same-generation retry result should be durably committed")
    }

    #[tokio::test]
    async fn snapshot_generation_retry_durable_partial_reenters_exact_identity() {
        let root = temp_root("durable-partial-retry");
        let state = test_neutron_state(&root);
        let partial = retryable_partial_runtime(1, "hash-1");
        state
            .wal
            .append_snapshot_commit(partial.to_wal_state())
            .expect("ordinary partial commit should be durable");
        *state.runtime.write().await = partial;
        let snapshot = inventory_snapshot(1, Vec::new());

        let response =
            apply_durable_partial_retry_with_results(&state, snapshot, Vec::new()).await;

        assert_eq!(response.status, "ok");
        assert_eq!(response.generation, 1);
        let runtime = state.runtime.read().await;
        assert_eq!(runtime.accepted_generation, 1);
        assert_eq!(runtime.applied_generation, 1);
        assert_eq!(runtime.pending_generation, None);
        assert_eq!(runtime.authority_state, "ready");
        drop(runtime);
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn snapshot_generation_retry_repeated_failure_stays_partial_at_same_generation() {
        let root = temp_root("durable-partial-retry-fails-again");
        let state = test_neutron_state(&root);
        let partial = retryable_partial_runtime(1, "hash-1");
        state
            .wal
            .append_snapshot_commit(partial.to_wal_state())
            .expect("ordinary partial commit should be durable");
        *state.runtime.write().await = partial;
        let snapshot = inventory_snapshot(1, Vec::new());
        let response = apply_durable_partial_retry_with_results(
            &state,
            snapshot,
            vec![NeutronPortApplyResult {
                port_id: "transient-port".to_string(),
                ifname: "tap-transient".to_string(),
                action: "update".to_string(),
                status: "error".to_string(),
                reason: Some("transient_failure".to_string()),
            }],
        )
        .await;

        assert_eq!(response.status, "partial");
        assert_eq!(response.generation, 1);
        let runtime = state.runtime.read().await;
        assert_eq!(runtime.accepted_generation, 1);
        assert_eq!(runtime.applied_generation, 0);
        assert_eq!(runtime.pending_generation, Some(1));
        assert_eq!(runtime.authority_state, "partial");
        drop(runtime);
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn snapshot_generation_retry_unsafe_wal_states_never_append_retry_intent() {
        for case in [
            "unresolved-intent",
            "committed-live-mismatch",
            "replay-failure",
            "non-partial-authority",
            "accepted-pending-mismatch",
            "committed-ports-mismatch",
            "committed-statuses-mismatch",
        ] {
            let root = temp_root(case);
            let state = test_neutron_state(&root);
            let mut partial = retryable_partial_runtime(1, "hash-1");
            if case == "unresolved-intent" {
                state
                    .wal
                    .append_snapshot_intent(
                        1,
                        Some("hash-1".to_string()),
                        Vec::new(),
                        Vec::new(),
                        Vec::new(),
                        None,
                    )
                    .expect("unresolved intent fixture should be durable");
            } else if case == "committed-live-mismatch" {
                state
                    .wal
                    .append_snapshot_commit(
                        retryable_partial_runtime(1, "different-hash").to_wal_state(),
                    )
                    .expect("mismatched commit fixture should be durable");
            } else {
                if case == "non-partial-authority" {
                    partial.authority_state = "degraded".to_string();
                } else if case == "accepted-pending-mismatch" {
                    partial.accepted_generation = 0;
                }
                let durable = partial.clone();
                state
                    .wal
                    .append_snapshot_commit(durable.to_wal_state())
                    .expect("unsafe committed fixture should be durable");
                if case == "replay-failure" {
                    let wal_path = state
                        .registry
                        .base_state_path
                        .join("neutron-snapshot.wal");
                    let mut wal = std::fs::OpenOptions::new()
                        .append(true)
                        .open(wal_path)
                        .expect("WAL should be appendable for corruption fixture");
                    use std::io::Write as _;
                    wal.write_all(b"{malformed-retry-tail\n")
                        .expect("corrupt WAL tail should be durable");
                    wal.flush().expect("corrupt WAL tail should be visible");
                } else if case == "committed-ports-mismatch" {
                    partial.ports.insert(
                        "unexpected-port".to_string(),
                        managed("unexpected-port", "tap-unexpected"),
                    );
                } else if case == "committed-statuses-mismatch" {
                    partial.port_statuses.insert(
                        "unexpected-port".to_string(),
                        ready_status("unexpected-port", "tap-unexpected", 1),
                    );
                }
            }
            *state.runtime.write().await = partial.clone();
            let before = SnapshotAdmissionIdentity::capture(&partial);
            let before_statuses = partial.port_statuses.clone();

            let error = accept_neutron_snapshot_submit(
                &state,
                &inventory_snapshot(1, Vec::new()),
                &ApplyScope::FullHost,
            )
            .await
            .expect_err("unsafe WAL state must reject a same-generation retry");

            assert_eq!(error.status, StatusCode::CONFLICT, "{case}");
            assert_eq!(error.code, "snapshot_retry_not_safe", "{case}");
            let after = {
                let runtime = state.runtime.read().await;
                SnapshotAdmissionIdentity::capture(&runtime)
            };
            assert_eq!(after, before, "{case}");
            assert_eq!(
                state.runtime.read().await.port_statuses,
                before_statuses,
                "{case}"
            );
            let replay = state.wal.replay();
            if case == "unresolved-intent" {
                assert!(replay.pending_intent.is_some());
            } else {
                assert!(replay.pending_intent.is_none());
            }
            let _ = std::fs::remove_dir_all(root);
        }
    }

    #[tokio::test]
    async fn snapshot_generation_retry_status_v2_marks_first_partial_retryable() {
        let root = temp_root("status-v2-first-partial");
        let state = test_neutron_state(&root);
        let partial = retryable_partial_runtime(1, "hash-1");
        state
            .wal
            .append_snapshot_commit(partial.to_wal_state())
            .expect("Status V2 retry fixture must be a durable partial commit");
        *state.runtime.write().await = partial;

        let response = get_neutron_status(State(state)).await.into_response();
        let (status, body) = response_json_value(response).await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["status_schema_version"], 3);
        assert_eq!(body["status_contract_hash"], "v0.9-neutron-status-3");
        assert_eq!(body["transaction_state"], "blocked");
        assert_eq!(body["overall_readiness"], "blocked");
        assert_eq!(body["required_action"], "retry_snapshot");
        assert_eq!(body["applied_generation"], 0);
        assert_eq!(body["pending_generation"], 1);
        assert!(body["port_statuses"]
            .as_array()
            .expect("Status V2 port rows must be an array")
            .iter()
            .all(|row| row["generation"].as_u64().unwrap_or(u64::MAX) <= 0));
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
    async fn neutron_snapshot_apply_serializes_startup_runtime_reconcile() {
        let root = temp_root("submit-serializes-startup-reconcile");
        let state = test_neutron_state(&root);
        let snapshot = NeutronSnapshotRequest {
            schema_version: None,
            generation: 131,
            desired_hash: Some("hash-131".to_string()),
            host: None,
            ports: vec![port("target-port", "tap-target", true)],
        };

        let decision = accept_neutron_snapshot_submit(&state, &snapshot, &ApplyScope::FullHost)
            .await
            .expect("snapshot admission should prepare an apply");
        let prepared = decision
            .prepared
            .expect("new snapshot must retain the apply barrier");
        assert!(
            state.apply_lock.try_lock().is_err(),
            "prepared apply must retain the shared startup recovery barrier"
        );

        let reconcile_state = state.clone();
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let mut reconcile = tokio::spawn(async move {
            let _ = started_tx.send(());
            reconcile_state.reconcile_committed_runtime().await;
        });
        started_rx
            .await
            .expect("startup reconcile task should begin polling the barrier");
        tokio::task::yield_now().await;
        assert!(
            !reconcile.is_finished(),
            "startup reconcile must not overwrite an admitted snapshot"
        );

        drop(prepared);
        tokio::time::timeout(std::time::Duration::from_secs(1), &mut reconcile)
            .await
            .expect("startup reconcile should resume after snapshot apply releases the barrier")
            .expect("startup reconcile task should not panic");
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn neutron_snapshot_inventory_unavailable_intent_has_no_datapath_recovery_scope() {
        let root = temp_root("inventory-unavailable-intent-recovery-scope");
        let mut state = test_neutron_state(&root);
        state.ovs_bridge = "br-int-definitely-missing-txn029".to_string();
        let previous = committed_runtime(130);
        {
            let mut runtime = state.runtime.write().await;
            *runtime = previous.clone();
        }
        let snapshot = inventory_snapshot(
            131,
            vec![NeutronPortSnapshot {
                managed_domains: vec!["acl".to_string()],
                ..port("committed-port", "tap-committed", true)
            }],
        );

        let decision = accept_neutron_snapshot_submit(&state, &snapshot, &ApplyScope::FullHost)
            .await
            .expect("unavailable inventory should persist a pending intent");
        let prepared = decision
            .prepared
            .expect("unavailable inventory should enter the transaction path");

        assert!(prepared.transaction.plan.inventory_error.is_some());
        assert!(prepared.transaction.plan.attach.is_empty());
        assert!(prepared.transaction.plan.update.is_empty());
        assert!(prepared.transaction.plan.detach.is_empty());
        assert!(prepared.intent.affected_ports.is_empty());
        assert!(
            prepared.intent.port_ids.is_empty(),
            "an inventory-blocked intent must not give commit-failure recovery datapath scope"
        );
        assert!(
            affected_ports_for_intent(&prepared.intent, &previous.ports).is_empty(),
            "immediate recovery must have no attach or ACL cleanup candidates"
        );
        let replay = state.wal.replay();
        assert_eq!(replay.status, "intent_without_commit");
        let replayed_intent = replay
            .pending_intent
            .expect("the inventory-blocked intent should survive restart replay");
        assert!(replayed_intent.port_ids.is_empty());
        assert!(replayed_intent.affected_ports.is_empty());
        assert!(
            affected_ports_for_intent(&replayed_intent, &previous.ports).is_empty(),
            "restart recovery must have no attach or ACL cleanup candidates"
        );

        let blocked = recover_failed_snapshot_transaction(
            &state,
            &prepared.intent,
            &previous,
            "before_commit_failed",
        )
        .await;
        assert_eq!(blocked.applied_generation, previous.applied_generation);
        assert_eq!(blocked.applied_desired_hash, previous.applied_desired_hash);
        assert_eq!(blocked.ports, previous.ports);
        assert_eq!(blocked.port_statuses, previous.port_statuses);
        assert_eq!(blocked.pending_generation, Some(131));
        assert_eq!(blocked.authority_state, "blocked_recovery_required");
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn neutron_wal_inventory_unavailable_admission_writes_hashed_cause_intent() {
        let root = temp_root("inventory-unavailable-hashed-intent");
        let mut state = test_neutron_state(&root);
        state.ovs_bridge = "br-int-definitely-missing-txn029-hash".to_string();
        let previous = committed_runtime(140);
        {
            let mut runtime = state.runtime.write().await;
            *runtime = previous;
        }
        let snapshot = inventory_snapshot(
            141,
            vec![NeutronPortSnapshot {
                managed_domains: vec!["acl".to_string()],
                ..port("committed-port", "tap-committed", true)
            }],
        );

        let decision = accept_neutron_snapshot_submit(&state, &snapshot, &ApplyScope::FullHost)
            .await
            .expect("inventory outage should persist a pending snapshot intent");
        let prepared = decision
            .prepared
            .expect("inventory outage should enter the transaction path");
        assert!(prepared.transaction.plan.inventory_error.is_some());
        assert!(prepared.intent.port_ids.is_empty());
        assert!(prepared.intent.affected_ports.is_empty());

        let wal_path = state.registry.base_state_path.join("neutron-snapshot.wal");
        let raw = std::fs::read_to_string(&wal_path).expect("snapshot intent should be durable");
        let intent: serde_json::Value = serde_json::from_str(
            raw.lines()
                .last()
                .expect("snapshot admission should append an intent"),
        )
        .expect("snapshot intent should be valid JSON");
        let raw_recovery_cause = intent
            .get("recovery_cause")
            .and_then(serde_json::Value::as_str)
            .expect("inventory intent must carry its recovery cause");
        assert_eq!(
            raw_recovery_cause,
            INVENTORY_UNAVAILABLE_RECOVERY_CAUSE
        );
        let intent_hash = intent
            .get("intent_hash")
            .and_then(serde_json::Value::as_str)
            .expect("inventory intent must carry an integrity hash");
        assert!(!intent_hash.trim().is_empty());
        let raw_generation = intent["generation"]
            .as_u64()
            .expect("snapshot intent generation should be numeric");
        let raw_desired_hash: Option<String> =
            serde_json::from_value(intent["desired_hash"].clone())
                .expect("snapshot intent desired hash should deserialize");
        let raw_port_ids: Vec<String> = serde_json::from_value(intent["port_ids"].clone())
            .expect("snapshot intent port IDs should deserialize");
        let raw_affected_domains: Vec<String> =
            serde_json::from_value(intent["affected_domains"].clone())
                .expect("snapshot intent affected domains should deserialize");
        let raw_affected_ports: Vec<ManagedNeutronPort> =
            serde_json::from_value(intent["affected_ports"].clone())
                .expect("snapshot intent affected ports should deserialize");
        let expected_hash = test_snapshot_intent_hash(
            raw_generation,
            &raw_desired_hash,
            &raw_port_ids,
            &raw_affected_domains,
            &raw_affected_ports,
            raw_recovery_cause,
        );
        assert_eq!(intent_hash, expected_hash.as_str());
        assert!(intent["port_ids"]
            .as_array()
            .is_some_and(|port_ids| port_ids.is_empty()));
        assert!(intent["affected_ports"]
            .as_array()
            .is_some_and(|ports| ports.is_empty()));
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn neutron_wal_inventory_unavailable_restart_chain_preserves_intent_cause() {
        let root = temp_root("inventory-unavailable-restart-chain");
        let initial = test_neutron_state(&root);
        let previous = committed_runtime(150);
        initial
            .wal
            .append_snapshot_commit(previous.to_wal_state())
            .expect("committed baseline should be durable");
        let raw_intent = append_hashed_inventory_snapshot_intent(
            &initial,
            151,
            Some("hash-151".to_string()),
            Vec::new(),
            Vec::new(),
            Vec::new(),
        );
        assert_eq!(
            raw_intent
                .get("recovery_cause")
                .and_then(serde_json::Value::as_str),
            Some(INVENTORY_UNAVAILABLE_RECOVERY_CAUSE)
        );
        assert!(raw_intent
            .get("intent_hash")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|hash| !hash.is_empty()));
        drop(initial);

        let restarted = test_neutron_state(&root);
        let replay_before_recovery = restarted.wal.replay();
        assert_eq!("intent_without_commit", replay_before_recovery.status);
        assert_eq!(0, replay_before_recovery.failures);
        assert_eq!(
            Some(151),
            replay_before_recovery
                .pending_intent
                .as_ref()
                .map(|intent| intent.generation)
        );
        let wal_path = restarted
            .registry
            .base_state_path
            .join("neutron-snapshot.wal");
        let wal_before_recovery =
            std::fs::read_to_string(&wal_path).expect("pending intent WAL should be readable");
        restarted.recover_incomplete_wal_intent().await;

        let wal_before_reconcile =
            std::fs::read_to_string(&wal_path).expect("recovery commit should be durable");
        assert_ne!(
            wal_before_reconcile, wal_before_recovery,
            "incomplete-intent recovery must append a durable commit"
        );
        let recovery_commit: serde_json::Value = serde_json::from_str(
            wal_before_reconcile
                .lines()
                .last()
                .expect("incomplete-intent recovery should append a commit"),
        )
        .expect("recovery commit should be valid JSON");
        let runtime_before_reconcile = {
            let runtime = restarted.runtime.read().await;
            (
                runtime.to_wal_state(),
                runtime.wal_status.clone(),
                runtime.wal_replay_failures,
            )
        };
        let registry_port_path = restarted.registry.base_state_path.join("tap-committed");
        assert!(!registry_port_path.exists());
        assert!(restarted.registry.list().await.is_empty());

        restarted.reconcile_committed_runtime().await;

        let wal_after_reconcile =
            std::fs::read_to_string(&wal_path).expect("WAL should remain readable");
        assert_eq!(
            wal_after_reconcile, wal_before_reconcile,
            "inventory recovery reconciliation must not append or rewrite WAL"
        );
        assert!(
            !registry_port_path.exists(),
            "inventory recovery reconciliation must not enter registry attach"
        );
        assert!(restarted.registry.list().await.is_empty());
        {
            let runtime = restarted.runtime.read().await;
            assert_eq!(runtime.to_wal_state(), runtime_before_reconcile.0);
            assert_eq!(runtime.wal_status, runtime_before_reconcile.1);
            assert_eq!(runtime.wal_replay_failures, runtime_before_reconcile.2);
            assert_eq!(runtime.accepted_generation, 151);
            assert_eq!(runtime.applied_generation, previous.applied_generation);
            assert_eq!(runtime.applied_desired_hash, previous.applied_desired_hash);
            assert_eq!(runtime.ports, previous.ports);
            assert_eq!(runtime.port_statuses, previous.port_statuses);
            assert_eq!(runtime.pending_generation, Some(151));
            assert_eq!(runtime.desired_hash.as_deref(), Some("hash-151"));
            assert_eq!(runtime.authority_state, "blocked_recovery_required");
            assert_eq!(
                runtime.recovery_cause.as_deref(),
                Some(INVENTORY_UNAVAILABLE_RECOVERY_CAUSE)
            );
            assert_eq!(runtime.wal_status, INVENTORY_UNAVAILABLE_RECOVERY_CAUSE);
        }
        assert_eq!(
            recovery_commit["state"]["recovery_cause"].as_str(),
            Some(INVENTORY_UNAVAILABLE_RECOVERY_CAUSE)
        );

        let replay_after_reconcile = restarted.wal.replay();
        assert_eq!(0, replay_after_reconcile.failures);
        assert_eq!(
            replay_after_reconcile.status,
            INVENTORY_UNAVAILABLE_RECOVERY_CAUSE
        );
        assert_eq!(
            replay_after_reconcile.state.recovery_cause.as_deref(),
            Some(INVENTORY_UNAVAILABLE_RECOVERY_CAUSE)
        );
        assert_eq!(
            replay_after_reconcile.state.applied_generation,
            previous.applied_generation
        );
        assert_eq!(replay_after_reconcile.state.accepted_generation, 151);
        assert_eq!(
            replay_after_reconcile.state.applied_desired_hash,
            previous.applied_desired_hash
        );
        assert_eq!(replay_after_reconcile.state.ports, previous.ports);
        assert_eq!(
            replay_after_reconcile.state.port_statuses,
            previous.port_statuses
        );
        assert_eq!(replay_after_reconcile.state.pending_generation, Some(151));
        assert_eq!(
            replay_after_reconcile.state.desired_hash.as_deref(),
            Some("hash-151")
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn neutron_wal_rejected_cause_free_closer_startup_skips_datapath_reconcile() {
        let root = temp_root("protected-intent-rejected-closer-startup");
        let initial = test_neutron_state(&root);
        let previous = committed_runtime(155);
        initial
            .wal
            .append_snapshot_commit(previous.to_wal_state())
            .expect("committed baseline should be durable");
        append_hashed_inventory_snapshot_intent(
            &initial,
            156,
            Some("hash-156".to_string()),
            Vec::new(),
            vec!["acl".to_string()],
            Vec::new(),
        );

        let mut cause_free_closer = previous.clone();
        cause_free_closer.accepted_generation = 156;
        cause_free_closer.pending_generation = Some(156);
        cause_free_closer.desired_hash = Some("hash-156".to_string());
        cause_free_closer.authority_state = "blocked_recovery_required".to_string();
        cause_free_closer.wal_status = "legacy_cause_free_closer".to_string();
        cause_free_closer.recovery_cause = None;
        initial
            .wal
            .append_snapshot_commit(cause_free_closer.to_wal_state())
            .expect("cause-free closer should be structurally valid and status-hashed");

        let wal_path = initial
            .registry
            .base_state_path
            .join("neutron-snapshot.wal");
        let wal_before_restart =
            std::fs::read_to_string(&wal_path).expect("startup WAL should be readable");
        let raw_closer: serde_json::Value = serde_json::from_str(
            wal_before_restart
                .lines()
                .last()
                .expect("cause-free closer should be the latest entry"),
        )
        .expect("cause-free closer should be valid JSON");
        assert!(raw_closer["state"]["status_hash"].as_str().is_some());
        assert!(raw_closer["state"].get("recovery_cause").is_none());
        drop(initial);

        let restarted = test_neutron_state(&root);
        let registry_port_path = restarted.registry.base_state_path.join("tap-committed");
        assert!(!registry_port_path.exists());
        assert!(restarted.registry.list().await.is_empty());

        restarted.recover_incomplete_wal_intent().await;
        let wal_after_recovery =
            std::fs::read_to_string(&wal_path).expect("recovery WAL should be readable");
        restarted.reconcile_committed_runtime().await;
        let wal_after_reconcile =
            std::fs::read_to_string(&wal_path).expect("reconciled WAL should be readable");

        assert_ne!(
            wal_after_recovery, wal_before_restart,
            "rejected closer must leave the protected intent available for startup recovery"
        );
        assert_eq!(
            wal_after_reconcile, wal_after_recovery,
            "protected startup recovery must return before registry/datapath reconciliation"
        );
        assert!(!registry_port_path.exists());
        assert!(restarted.registry.list().await.is_empty());
        let runtime = restarted.runtime.read().await;
        assert_eq!(runtime.accepted_generation, 156);
        assert_eq!(runtime.applied_generation, previous.applied_generation);
        assert_eq!(runtime.applied_desired_hash, previous.applied_desired_hash);
        assert_eq!(runtime.ports, previous.ports);
        assert_eq!(runtime.port_statuses, previous.port_statuses);
        assert_eq!(runtime.pending_generation, Some(156));
        assert_eq!(runtime.desired_hash.as_deref(), Some("hash-156"));
        assert_eq!(runtime.authority_state, "blocked_recovery_required");
        assert_eq!(
            runtime.recovery_cause.as_deref(),
            Some(INVENTORY_UNAVAILABLE_RECOVERY_CAUSE)
        );
        assert_eq!(runtime.wal_status, INVENTORY_UNAVAILABLE_RECOVERY_CAUSE);
        assert_eq!(runtime.wal_replay_failures, 1);
        drop(runtime);
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn neutron_wal_inventory_unavailable_commit_failure_preserves_intent_cause() {
        let root = temp_root("inventory-unavailable-commit-failure-cause");
        let mut state = test_neutron_state(&root);
        state.ovs_bridge = "br-int-definitely-missing-txn029-commit".to_string();
        let previous = committed_runtime(160);
        state
            .wal
            .append_snapshot_commit(previous.to_wal_state())
            .expect("committed baseline should be durable");
        {
            let mut runtime = state.runtime.write().await;
            *runtime = previous.clone();
        }
        let snapshot = inventory_snapshot(
            161,
            vec![NeutronPortSnapshot {
                managed_domains: vec!["acl".to_string()],
                ..port("committed-port", "tap-committed", true)
            }],
        );
        let decision = accept_neutron_snapshot_submit(&state, &snapshot, &ApplyScope::FullHost)
            .await
            .expect("inventory outage should persist a pending snapshot intent");
        let prepared = decision
            .prepared
            .expect("inventory outage should enter the transaction path");
        assert!(prepared.transaction.plan.inventory_error.is_some());
        assert!(prepared.intent.port_ids.is_empty());
        assert!(prepared.intent.affected_ports.is_empty());
        assert!(affected_ports_for_intent(&prepared.intent, &previous.ports).is_empty());

        let blocked = recover_failed_snapshot_transaction(
            &state,
            &prepared.intent,
            &previous,
            "inventory_commit_failed",
        )
        .await;

        assert_eq!(
            blocked.recovery_cause.as_deref(),
            Some(INVENTORY_UNAVAILABLE_RECOVERY_CAUSE)
        );
        assert_eq!(blocked.wal_status, INVENTORY_UNAVAILABLE_RECOVERY_CAUSE);
        assert_eq!(blocked.accepted_generation, 161);
        assert_eq!(blocked.applied_generation, previous.applied_generation);
        assert_eq!(blocked.applied_desired_hash, previous.applied_desired_hash);
        assert_eq!(blocked.ports, previous.ports);
        assert_eq!(blocked.port_statuses, previous.port_statuses);
        assert_eq!(blocked.pending_generation, Some(161));
        assert_eq!(blocked.desired_hash.as_deref(), Some("hash-161"));
        assert_eq!(blocked.authority_state, "blocked_recovery_required");

        let wal_path = state.registry.base_state_path.join("neutron-snapshot.wal");
        let raw = std::fs::read_to_string(&wal_path).expect("blocked commit should be durable");
        let blocked_commit: serde_json::Value = serde_json::from_str(
            raw.lines()
                .last()
                .expect("commit-failure recovery should append a commit"),
        )
        .expect("blocked commit should be valid JSON");
        assert_eq!(
            blocked_commit["state"]["recovery_cause"].as_str(),
            Some(INVENTORY_UNAVAILABLE_RECOVERY_CAUSE)
        );

        let replay = state.wal.replay();
        assert_eq!(0, replay.failures);
        assert_eq!(replay.status, INVENTORY_UNAVAILABLE_RECOVERY_CAUSE);
        assert_eq!(
            replay.state.recovery_cause.as_deref(),
            Some(INVENTORY_UNAVAILABLE_RECOVERY_CAUSE)
        );
        assert_eq!(replay.state.accepted_generation, 161);
        assert_eq!(replay.state.applied_generation, previous.applied_generation);
        assert_eq!(
            replay.state.applied_desired_hash,
            previous.applied_desired_hash
        );
        assert_eq!(replay.state.ports, previous.ports);
        assert_eq!(replay.state.port_statuses, previous.port_statuses);
        assert_eq!(replay.state.pending_generation, Some(161));
        assert_eq!(replay.state.desired_hash.as_deref(), Some("hash-161"));
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn neutron_wal_inventory_unavailable_double_append_failure_recovers_baseline() {
        let root = temp_root("inventory-double-append-baseline");
        let mut state = test_neutron_state(&root);
        state.ovs_bridge = "br-int-definitely-missing-txn029-double-baseline".to_string();
        let previous = committed_runtime(200);
        state
            .wal
            .append_snapshot_commit(previous.to_wal_state())
            .expect("committed baseline should be durable");
        {
            let mut runtime = state.runtime.write().await;
            *runtime = previous.clone();
        }
        let snapshot = inventory_snapshot(
            201,
            vec![NeutronPortSnapshot {
                managed_domains: vec!["acl".to_string()],
                ..port("committed-port", "tap-committed", true)
            }],
        );
        let decision = accept_neutron_snapshot_submit(&state, &snapshot, &ApplyScope::FullHost)
            .await
            .expect("inventory outage should persist a pending snapshot intent");
        let prepared = decision
            .prepared
            .expect("inventory outage should enter the transaction path");
        assert!(prepared.transaction.plan.inventory_error.is_some());
        assert_eq!(
            prepared.intent.recovery_cause.as_deref(),
            Some(INVENTORY_UNAVAILABLE_RECOVERY_CAUSE)
        );
        assert!(prepared.intent.port_ids.is_empty());
        assert!(prepared.intent.affected_ports.is_empty());

        let (error, wal_path, wal_before) = apply_with_both_wal_commits_blocked(
            &state,
            &root,
            snapshot,
            prepared,
        )
        .await;
        assert_eq!(error.code, "wal_commit_failed");
        assert_eq!(2, wal_before.split(|byte| *byte == b'\n').count() - 1);
        {
            let runtime = state.runtime.read().await;
            assert_eq!(runtime.accepted_generation, 201);
            assert_eq!(runtime.applied_generation, previous.applied_generation);
            assert_eq!(runtime.pending_generation, Some(201));
            assert_eq!(runtime.desired_hash.as_deref(), Some("hash-201"));
            assert_eq!(runtime.applied_desired_hash, previous.applied_desired_hash);
            assert_eq!(runtime.authority_state, "blocked_recovery_required");
            assert_eq!(runtime.wal_status, INVENTORY_UNAVAILABLE_RECOVERY_CAUSE);
            assert_eq!(
                runtime.recovery_cause.as_deref(),
                Some(INVENTORY_UNAVAILABLE_RECOVERY_CAUSE)
            );
            assert_eq!(runtime.ports, previous.ports);
            assert_eq!(runtime.port_statuses, previous.port_statuses);
        }
        let replay_before = state.wal.replay();
        assert_eq!(replay_before.status, "intent_without_commit");
        assert_eq!(replay_before.failures, 0);
        assert_eq!(
            replay_before
                .pending_intent
                .as_ref()
                .and_then(|intent| intent.recovery_cause.as_deref()),
            Some(INVENTORY_UNAVAILABLE_RECOVERY_CAUSE)
        );
        assert_eq!(replay_before.state.recovery_cause, None);

        let recovered = recover_pending_snapshot(
            state.clone(),
            NeutronRecoverPendingRequest {
                expected_pending_generation: 201,
                expected_desired_hash: Some("hash-201".to_string()),
                mode: None,
            },
        )
        .await
        .expect("typed blocked state should recover the committed baseline durably");

        assert_eq!(recovered.status, "recovered");
        assert_eq!(recovered.applied_generation, previous.applied_generation);
        assert_eq!(recovered.desired_hash, previous.applied_desired_hash);
        assert_eq!(
            recovered.authority_state,
            "recovered_pending_full_resync_required"
        );
        assert_recovered_replay(&state.wal.replay(), &previous);
        assert_two_stage_recovery_wal(&wal_path, 4, 201, 200);

        drop(state);
        let restarted = test_neutron_state(&root);
        assert!(restarted.pending_recovery.is_none());
        {
            let runtime = restarted.runtime.read().await;
            assert_eq!(runtime.accepted_generation, previous.applied_generation);
            assert_eq!(runtime.applied_generation, previous.applied_generation);
            assert_eq!(runtime.pending_generation, None);
            assert_eq!(runtime.desired_hash, previous.applied_desired_hash);
            assert_eq!(runtime.applied_desired_hash, previous.applied_desired_hash);
            assert_eq!(runtime.recovery_cause, None);
            assert_eq!(
                runtime.authority_state,
                "recovered_pending_full_resync_required"
            );
            assert_eq!(runtime.wal_status, "replayed");
            assert_eq!(runtime.wal_replay_failures, 0);
            assert_eq!(runtime.ports, previous.ports);
            assert_eq!(runtime.port_statuses, previous.port_statuses);
        }
        let wal_before_startup =
            std::fs::read(&wal_path).expect("restarted WAL should be readable");
        restarted.recover_incomplete_wal_intent().await;
        assert_eq!(
            std::fs::read(&wal_path).expect("WAL should remain readable"),
            wal_before_startup
        );
        drop(restarted);
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn neutron_wal_inventory_unavailable_double_append_failure_recovers_generation_zero() {
        let root = temp_root("inventory-double-append-generation-zero");
        let mut state = test_neutron_state(&root);
        state.ovs_bridge = "br-int-definitely-missing-txn029-double-zero".to_string();
        let snapshot = inventory_snapshot(1, Vec::new());
        let decision = accept_neutron_snapshot_submit(&state, &snapshot, &ApplyScope::FullHost)
            .await
            .expect("inventory outage should persist a generation-0 intent");
        let prepared = decision
            .prepared
            .expect("inventory outage should enter the transaction path");
        assert!(prepared.transaction.plan.inventory_error.is_some());
        assert_eq!(
            prepared.intent.recovery_cause.as_deref(),
            Some(INVENTORY_UNAVAILABLE_RECOVERY_CAUSE)
        );
        assert!(prepared.intent.port_ids.is_empty());
        assert!(prepared.intent.affected_ports.is_empty());

        let (error, wal_path, wal_before) = apply_with_both_wal_commits_blocked(
            &state,
            &root,
            snapshot,
            prepared,
        )
        .await;
        assert_eq!(error.code, "wal_commit_failed");
        assert_eq!(1, wal_before.split(|byte| *byte == b'\n').count() - 1);
        {
            let runtime = state.runtime.read().await;
            assert_eq!(runtime.accepted_generation, 1);
            assert_eq!(runtime.applied_generation, 0);
            assert_eq!(runtime.pending_generation, Some(1));
            assert_eq!(runtime.desired_hash.as_deref(), Some("hash-1"));
            assert_eq!(runtime.applied_desired_hash, None);
            assert_eq!(runtime.authority_state, "blocked_recovery_required");
            assert_eq!(runtime.wal_status, INVENTORY_UNAVAILABLE_RECOVERY_CAUSE);
            assert_eq!(
                runtime.recovery_cause.as_deref(),
                Some(INVENTORY_UNAVAILABLE_RECOVERY_CAUSE)
            );
            assert!(runtime.ports.is_empty());
            assert!(runtime.port_statuses.is_empty());
        }
        let replay_before = state.wal.replay();
        assert_eq!(replay_before.status, "intent_without_commit");
        assert_eq!(replay_before.failures, 0);
        assert_eq!(
            replay_before
                .pending_intent
                .as_ref()
                .and_then(|intent| intent.recovery_cause.as_deref()),
            Some(INVENTORY_UNAVAILABLE_RECOVERY_CAUSE)
        );
        assert_eq!(replay_before.state.recovery_cause, None);

        let recovered = recover_pending_snapshot(
            state.clone(),
            NeutronRecoverPendingRequest {
                expected_pending_generation: 1,
                expected_desired_hash: Some("hash-1".to_string()),
                mode: None,
            },
        )
        .await
        .expect("typed inventory cause should authorize generation-0 recovery");

        assert_eq!(recovered.status, "recovered");
        assert_eq!(recovered.applied_generation, 0);
        assert_eq!(recovered.desired_hash, None);
        assert_eq!(recovered.applied_desired_hash, None);
        assert_eq!(
            recovered.authority_state,
            "recovered_pending_full_resync_required"
        );
        let empty_baseline = NeutronRuntimeState::default();
        assert_recovered_replay(&state.wal.replay(), &empty_baseline);
        assert_two_stage_recovery_wal(&wal_path, 3, 1, 0);

        drop(state);
        let restarted = test_neutron_state(&root);
        assert!(restarted.pending_recovery.is_none());
        {
            let runtime = restarted.runtime.read().await;
            assert_eq!(runtime.accepted_generation, 0);
            assert_eq!(runtime.applied_generation, 0);
            assert_eq!(runtime.pending_generation, None);
            assert_eq!(runtime.desired_hash, None);
            assert_eq!(runtime.applied_desired_hash, None);
            assert_eq!(runtime.recovery_cause, None);
            assert_eq!(
                runtime.authority_state,
                "recovered_pending_full_resync_required"
            );
            assert_eq!(runtime.wal_status, "replayed");
            assert_eq!(runtime.wal_replay_failures, 0);
            assert!(runtime.ports.is_empty());
            assert!(runtime.port_statuses.is_empty());
        }
        let wal_before_startup =
            std::fs::read(&wal_path).expect("restarted WAL should be readable");
        restarted.recover_incomplete_wal_intent().await;
        assert_eq!(
            std::fs::read(&wal_path).expect("WAL should remain readable"),
            wal_before_startup
        );
        drop(restarted);
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn neutron_wal_inventory_recovery_phase_two_failure_preserves_retry_state() {
        let root = temp_root("inventory-recovery-phase-two-retry");
        let state = test_neutron_state(&root);
        let previous = committed_runtime(210);
        state
            .wal
            .append_snapshot_commit(previous.to_wal_state())
            .expect("committed baseline should be durable");
        let intent = PendingNeutronIntent {
            kind: "snapshot".to_string(),
            generation: 211,
            desired_hash: Some("hash-211".to_string()),
            port_ids: Vec::new(),
            affected_domains: vec!["acl".to_string()],
            affected_ports: Vec::new(),
            recovery_cause: Some(INVENTORY_UNAVAILABLE_RECOVERY_CAUSE.to_string()),
        };
        state
            .wal
            .append_snapshot_intent(
                intent.generation,
                intent.desired_hash.clone(),
                intent.port_ids.clone(),
                intent.affected_domains.clone(),
                intent.affected_ports.clone(),
                intent.recovery_cause.clone(),
            )
            .expect("protected inventory intent should be durable");
        let mut blocked = previous.clone();
        blocked.accepted_generation = intent.generation;
        blocked.pending_generation = Some(intent.generation);
        blocked.desired_hash = intent.desired_hash.clone();
        blocked.authority_state = "blocked_recovery_required".to_string();
        blocked.wal_status = INVENTORY_UNAVAILABLE_RECOVERY_CAUSE.to_string();
        blocked.recovery_cause = Some(INVENTORY_UNAVAILABLE_RECOVERY_CAUSE.to_string());
        state
            .wal
            .append_verified_protected_inventory_commit(&intent, blocked.to_wal_state())
            .expect("phase-one typed barrier should be durable");
        {
            let mut runtime = state.runtime.write().await;
            *runtime = blocked.clone();
        }

        let state_path = state.registry.base_state_path.clone();
        let backup_path = root.join("state-phase-two-backup");
        let wal_path = state_path.join("neutron-snapshot.wal");
        let mut replacement = WalParentReplacement::install(&state_path, &backup_path);
        let error = recover_pending_snapshot(
            state.clone(),
            NeutronRecoverPendingRequest {
                expected_pending_generation: intent.generation,
                expected_desired_hash: intent.desired_hash.clone(),
                mode: None,
            },
        )
        .await
        .expect_err("phase-two WAL failure must remain recoverable");
        replacement.restore();

        assert_eq!(error.code, "pending_recovery_commit_failed");
        {
            let runtime = state.runtime.read().await;
            assert_eq!(runtime.to_wal_state(), blocked.to_wal_state());
            assert_eq!(runtime.wal_status, INVENTORY_UNAVAILABLE_RECOVERY_CAUSE);
            assert_eq!(runtime.wal_replay_failures, 0);
        }
        let barrier_replay = state.wal.replay();
        assert_eq!(barrier_replay.status, INVENTORY_UNAVAILABLE_RECOVERY_CAUSE);
        assert_eq!(barrier_replay.failures, 0);
        assert!(barrier_replay.pending_intent.is_none());
        let mut barrier_state = barrier_replay.state;
        assert!(barrier_state.status_hash.take().is_some());
        assert_eq!(barrier_state, blocked.to_wal_state());

        let recovered = recover_pending_snapshot(
            state.clone(),
            NeutronRecoverPendingRequest {
                expected_pending_generation: intent.generation,
                expected_desired_hash: intent.desired_hash.clone(),
                mode: None,
            },
        )
        .await
        .expect("phase-two recovery should succeed after WAL access is restored");

        assert_eq!(recovered.status, "recovered");
        assert_recovered_replay(&state.wal.replay(), &previous);
        assert_two_stage_recovery_wal(&wal_path, 4, intent.generation, 210);
        drop(state);
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn neutron_wal_inventory_recovery_rejects_corrupt_nonzero_barrier_replay() {
        let root = temp_root("inventory-recovery-corrupt-nonzero-barrier");
        let state = test_neutron_state(&root);
        let previous = committed_runtime(220);
        state
            .wal
            .append_snapshot_commit(previous.to_wal_state())
            .expect("committed baseline should be durable");
        let intent = PendingNeutronIntent {
            kind: "snapshot".to_string(),
            generation: 221,
            desired_hash: Some("hash-221".to_string()),
            port_ids: Vec::new(),
            affected_domains: vec!["acl".to_string()],
            affected_ports: Vec::new(),
            recovery_cause: Some(INVENTORY_UNAVAILABLE_RECOVERY_CAUSE.to_string()),
        };
        state
            .wal
            .append_snapshot_intent(
                intent.generation,
                intent.desired_hash.clone(),
                intent.port_ids.clone(),
                intent.affected_domains.clone(),
                intent.affected_ports.clone(),
                intent.recovery_cause.clone(),
            )
            .expect("protected inventory intent should be durable");
        let mut blocked = previous.clone();
        blocked.accepted_generation = intent.generation;
        blocked.pending_generation = Some(intent.generation);
        blocked.desired_hash = intent.desired_hash.clone();
        blocked.authority_state = "blocked_recovery_required".to_string();
        blocked.wal_status = INVENTORY_UNAVAILABLE_RECOVERY_CAUSE.to_string();
        blocked.recovery_cause = Some(INVENTORY_UNAVAILABLE_RECOVERY_CAUSE.to_string());
        state
            .wal
            .append_verified_protected_inventory_commit(&intent, blocked.to_wal_state())
            .expect("phase-one typed barrier should be durable");
        {
            let mut runtime = state.runtime.write().await;
            *runtime = blocked.clone();
        }

        let wal_path = state
            .registry
            .base_state_path
            .join("neutron-snapshot.wal");
        let mut wal_file = std::fs::OpenOptions::new()
            .append(true)
            .open(&wal_path)
            .expect("WAL should be appendable for corruption fixture");
        use std::io::Write as _;
        wal_file
            .write_all(b"{malformed-wal-tail\n")
            .expect("corrupt WAL fixture should be written");
        wal_file
            .sync_all()
            .expect("corrupt WAL fixture should be durable");
        drop(wal_file);
        let wal_before_recovery = std::fs::read(&wal_path).expect("WAL should be readable");
        let replay_before = state.wal.replay();
        assert_eq!(replay_before.status, "replayed_with_errors");
        assert_eq!(replay_before.failures, 1);
        assert_eq!(
            replay_before.state.recovery_cause.as_deref(),
            Some(INVENTORY_UNAVAILABLE_RECOVERY_CAUSE)
        );

        let request = NeutronRecoverPendingRequest {
            expected_pending_generation: intent.generation,
            expected_desired_hash: intent.desired_hash.clone(),
            mode: None,
        };
        let error = recover_pending_snapshot(state.clone(), request.clone())
            .await
            .expect_err("corrupt barrier replay must veto phase-two recovery");

        assert_eq!(error.status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(error.code, "pending_recovery_commit_failed");
        assert_eq!(
            std::fs::read(&wal_path).expect("WAL should remain readable"),
            wal_before_recovery
        );
        {
            let runtime = state.runtime.read().await;
            assert_eq!(runtime.to_wal_state(), blocked.to_wal_state());
            assert_eq!(runtime.wal_status, INVENTORY_UNAVAILABLE_RECOVERY_CAUSE);
            assert_eq!(runtime.wal_replay_failures, 0);
        }
        let replay_after = state.wal.replay();
        assert_eq!(replay_after.status, "replayed_with_errors");
        assert_eq!(replay_after.failures, 1);
        assert_eq!(
            replay_after.state.recovery_cause.as_deref(),
            Some(INVENTORY_UNAVAILABLE_RECOVERY_CAUSE)
        );

        drop(state);
        let restarted = test_neutron_state(&root);
        assert!(restarted.pending_recovery.is_none());
        {
            let runtime = restarted.runtime.read().await;
            assert_eq!(runtime.to_wal_state(), blocked.to_wal_state());
            assert_eq!(runtime.wal_status, "replayed_with_errors");
            assert_eq!(runtime.wal_replay_failures, 1);
        }
        let restart_error = recover_pending_snapshot(restarted.clone(), request)
            .await
            .expect_err("restart must not route corrupt inventory recovery generically");
        assert_eq!(restart_error.status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(restart_error.code, "pending_recovery_commit_failed");
        assert_eq!(
            std::fs::read(&wal_path).expect("WAL should remain readable"),
            wal_before_recovery
        );
        {
            let runtime = restarted.runtime.read().await;
            assert_eq!(runtime.to_wal_state(), blocked.to_wal_state());
            assert_eq!(runtime.wal_status, "replayed_with_errors");
            assert_eq!(runtime.wal_replay_failures, 1);
        }
        drop(restarted);
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
        let mut intent = PendingNeutronIntent::default();
        intent.kind = "snapshot".to_string();
        intent.generation = 41;
        intent.desired_hash = Some("hash-41".to_string());
        intent.port_ids = vec!["port-1".to_string()];
        intent.affected_domains = vec!["acl".to_string(), "attach".to_string()];
        intent.affected_ports = vec![managed("port-1", "tap-port-1")];
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
    async fn neutron_snapshot_after_intent_failure_is_durable_across_restart() {
        let root = temp_root("after-intent-durable");
        let state = test_neutron_state(&root);
        let previous = committed_runtime(40);
        state
            .wal
            .append_snapshot_commit(previous.to_wal_state())
            .unwrap();
        {
            let mut runtime = state.runtime.write().await;
            *runtime = previous.clone();
            runtime.pending_generation = Some(41);
            runtime.desired_hash = Some("hash-41".to_string());
            runtime.authority_state = "applying".to_string();
            runtime.wal_status = "intent_written".to_string();
        }
        let intent = PendingNeutronIntent {
            kind: "snapshot".to_string(),
            generation: 41,
            desired_hash: Some("hash-41".to_string()),
            ..PendingNeutronIntent::default()
        };
        state
            .wal
            .append_snapshot_intent(
                intent.generation,
                intent.desired_hash.clone(),
                intent.port_ids.clone(),
                intent.affected_domains.clone(),
                intent.affected_ports.clone(),
                intent.recovery_cause.clone(),
            )
            .unwrap();

        let error = handle_snapshot_after_intent_fault(
            &state,
            &intent,
            &previous,
            Err("forced after-intent failure".to_string()),
        )
        .await
        .expect_err("after-intent failure must be returned");
        assert_eq!(error.code, "fault_injection");

        let replay = state.wal.replay();
        assert!(replay.pending_intent.is_none());
        assert_eq!(replay.state.applied_generation, 40);
        assert_eq!(replay.state.pending_generation, Some(41));
        assert_eq!(
            replay.state.authority_state,
            "blocked_recovery_required"
        );

        let restarted = test_neutron_state(&root);
        {
            let runtime = restarted.runtime.read().await;
            assert_eq!(runtime.applied_generation, 40);
            assert_eq!(runtime.pending_generation, Some(41));
            assert_eq!(runtime.authority_state, "blocked_recovery_required");
        }
        let recovered = recover_pending_snapshot(
            restarted.clone(),
            NeutronRecoverPendingRequest {
                expected_pending_generation: 41,
                expected_desired_hash: Some("hash-41".to_string()),
                mode: Some("rollback_to_last_applied".to_string()),
            },
        )
        .await
        .expect("durable blocked failure must be recoverable");
        assert_eq!(recovered.status, "recovered");
        assert_eq!(recovered.applied_generation, 40);

        let runtime = restarted.runtime.read().await;
        assert_eq!(runtime.pending_generation, None);
        assert_eq!(runtime.accepted_generation, 40);
        assert_eq!(runtime.applied_generation, 40);
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn neutron_snapshot_after_intent_blocked_commit_failure_retains_intent() {
        let root = temp_root("after-intent-commit-failed");
        let state = test_neutron_state(&root);
        let previous = committed_runtime(50);
        state
            .wal
            .append_snapshot_commit(previous.to_wal_state())
            .unwrap();
        let intent = PendingNeutronIntent {
            kind: "snapshot".to_string(),
            generation: 51,
            desired_hash: Some("hash-51".to_string()),
            ..PendingNeutronIntent::default()
        };
        state
            .wal
            .append_snapshot_intent(
                intent.generation,
                intent.desired_hash.clone(),
                intent.port_ids.clone(),
                intent.affected_domains.clone(),
                intent.affected_ports.clone(),
                intent.recovery_cause.clone(),
            )
            .unwrap();
        let backup = root.join("after-intent-state-backup");
        let mut replacement =
            WalParentReplacement::install(&state.registry.base_state_path, &backup);

        let error = handle_snapshot_after_intent_fault(
            &state,
            &intent,
            &previous,
            Err("forced after-intent failure".to_string()),
        )
        .await
        .expect_err("primary failure must remain visible");
        replacement.restore();

        assert_eq!(error.code, "fault_injection");
        {
            let runtime = state.runtime.read().await;
            assert_eq!(runtime.pending_generation, Some(51));
            assert_eq!(
                runtime.authority_state,
                "pending_recovery_commit_failed"
            );
            assert_eq!(runtime.wal_status, "commit_failed");
        }
        let replay = state.wal.replay();
        assert_eq!(
            replay
                .pending_intent
                .as_ref()
                .map(|pending| pending.generation),
            Some(51)
        );
        assert_eq!(replay.state.applied_generation, 50);
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn neutron_delete_after_detach_fault_retains_forward_recovery_intent() {
        let root = temp_root("delete-after-detach-fault");
        let state = test_neutron_state(&root);
        let previous = committed_runtime(60);
        let port = previous.ports["committed-port"].clone();
        state
            .wal
            .append_snapshot_commit(previous.to_wal_state())
            .unwrap();
        state
            .wal
            .append_delete_intent(
                port.port_id.clone(),
                previous.accepted_generation,
                vec!["acl".to_string(), "attach".to_string()],
                port.clone(),
            )
            .unwrap();
        {
            let mut runtime = state.runtime.write().await;
            *runtime = previous.clone();
        }

        let (status, response) = finalize_detached_neutron_delete(
            &state,
            &previous,
            &port,
            previous.accepted_generation,
            Err("fault injection triggered after detach".to_string()),
        )
        .await;

        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert!(!response.detached);
        assert_eq!(response.status, "error");
        {
            let runtime = state.runtime.read().await;
            assert!(runtime.ports.contains_key(&port.port_id));
            assert_eq!(
                runtime.pending_generation,
                Some(previous.accepted_generation)
            );
            assert_eq!(runtime.desired_hash, None);
            assert_eq!(runtime.authority_state, "blocked_recovery_required");
            assert_eq!(runtime.wal_status, "delete_after_detach_failed");
            let projected = project_neutron_status_v1(&runtime);
            assert_eq!(
                projected.required_action,
                NeutronStatusRequiredAction::Operator
            );
        }
        let replay = state.wal.replay();
        let pending = replay
            .pending_intent
            .expect("after-detach failure must retain the delete intent");
        assert_eq!(pending.kind, "delete");
        assert_eq!(pending.port_ids, vec![port.port_id.clone()]);
        assert_eq!(pending.affected_ports, vec![port]);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn neutron_delete_failure_status_is_phase_aware_and_never_ready_enforce() {
        let previous = committed_runtime(65);
        let port = previous.ports["committed-port"].clone();

        let before = build_blocked_delete_runtime(
            &previous,
            &port,
            65,
            "delete_after_intent_failed",
            "forced after-intent failure",
            "unchanged",
        );
        let after = build_blocked_delete_runtime(
            &previous,
            &port,
            65,
            "delete_detach_failed",
            "forced detach failure",
            "bypass",
        );

        for (runtime, action) in [(&before, "unchanged"), (&after, "bypass")] {
            assert!(runtime.ports.contains_key(&port.port_id));
            assert_eq!(runtime.pending_generation, Some(65));
            assert_eq!(runtime.desired_hash, None);
            assert_eq!(runtime.authority_state, "blocked_recovery_required");
            let status = runtime.port_statuses.get(&port.port_id).unwrap();
            assert_ne!(status.status, "ready");
            let acl = status
                .domains
                .iter()
                .find(|domain| domain.domain == "acl")
                .expect("blocked delete status must include ACL evidence");
            assert_ne!(acl.status, "ready");
            assert_eq!(acl.effective_action.as_deref(), Some(action));
            assert_ne!(acl.effective_action.as_deref(), Some("enforce"));
        }
    }

    #[tokio::test]
    async fn neutron_delete_blocked_checkpoint_failure_keeps_truthful_ram_and_intent() {
        let root = temp_root("delete-blocked-checkpoint-failed");
        let state = test_neutron_state(&root);
        let previous = committed_runtime(66);
        let port = previous.ports["committed-port"].clone();
        state
            .wal
            .append_snapshot_commit(previous.to_wal_state())
            .unwrap();
        state
            .wal
            .append_delete_intent(
                port.port_id.clone(),
                66,
                vec!["attach".to_string(), "acl".to_string()],
                port.clone(),
            )
            .unwrap();
        {
            let mut runtime = state.runtime.write().await;
            *runtime = previous.clone();
        }
        let backup = root.join("delete-blocked-checkpoint-state-backup");
        let mut replacement =
            WalParentReplacement::install(&state.registry.base_state_path, &backup);

        let error = publish_blocked_delete_failure(
            &state,
            &previous,
            &port,
            66,
            "delete_detach_failed",
            "forced detach failure".to_string(),
            "bypass",
        )
        .await;
        replacement.restore();

        assert!(error.contains("forced detach failure"));
        assert!(error.contains("delete_blocked_checkpoint_failed:"));
        {
            let runtime = state.runtime.read().await;
            assert!(runtime.ports.contains_key(&port.port_id));
            assert_eq!(runtime.pending_generation, Some(66));
            assert_eq!(runtime.authority_state, "blocked_recovery_required");
            assert_eq!(runtime.wal_status, "delete_blocked_checkpoint_failed");
            let status = runtime.port_statuses.get(&port.port_id).unwrap();
            assert_ne!(status.status, "ready");
            let acl = status
                .domains
                .iter()
                .find(|domain| domain.domain == "acl")
                .expect("blocked delete status must include ACL evidence");
            assert_eq!(acl.effective_action.as_deref(), Some("bypass"));
        }
        let replay = state.wal.replay();
        assert_eq!(
            replay
                .pending_intent
                .as_ref()
                .map(|intent| intent.kind.as_str()),
            Some("delete")
        );
        assert!(replay.state.ports.contains_key(&port.port_id));
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn neutron_delete_commit_failure_retains_forward_recovery_intent() {
        let root = temp_root("delete-commit-failed");
        let state = test_neutron_state(&root);
        let previous = committed_runtime(61);
        let port = previous.ports["committed-port"].clone();
        state
            .wal
            .append_snapshot_commit(previous.to_wal_state())
            .unwrap();
        state
            .wal
            .append_delete_intent(
                port.port_id.clone(),
                previous.accepted_generation,
                vec!["acl".to_string(), "attach".to_string()],
                port.clone(),
            )
            .unwrap();
        {
            let mut runtime = state.runtime.write().await;
            *runtime = previous.clone();
        }
        let backup = root.join("delete-commit-state-backup");
        let mut replacement =
            WalParentReplacement::install(&state.registry.base_state_path, &backup);

        let (status, response) = finalize_detached_neutron_delete(
            &state,
            &previous,
            &port,
            previous.accepted_generation,
            Ok(()),
        )
        .await;
        replacement.restore();

        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert!(!response.detached);
        assert!(response
            .error
            .as_deref()
            .is_some_and(|error| error.starts_with("wal_commit_failed:")));
        {
            let runtime = state.runtime.read().await;
            assert!(runtime.ports.contains_key(&port.port_id));
            assert_eq!(
                runtime.pending_generation,
                Some(previous.accepted_generation)
            );
            assert_eq!(runtime.desired_hash, None);
            assert_eq!(runtime.authority_state, "blocked_recovery_required");
            assert_eq!(
                runtime.wal_status,
                "delete_blocked_checkpoint_failed"
            );
        }
        let replay = state.wal.replay();
        assert_eq!(
            replay
                .pending_intent
                .as_ref()
                .map(|pending| pending.kind.as_str()),
            Some("delete")
        );
        assert!(replay.state.ports.contains_key(&port.port_id));
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn neutron_delete_publishes_absence_only_after_durable_commit() {
        let root = temp_root("delete-durable-success");
        let state = test_neutron_state(&root);
        let previous = committed_runtime(62);
        let port = previous.ports["committed-port"].clone();
        state
            .wal
            .append_snapshot_commit(previous.to_wal_state())
            .unwrap();
        state
            .wal
            .append_delete_intent(
                port.port_id.clone(),
                previous.accepted_generation,
                vec!["acl".to_string(), "attach".to_string()],
                port.clone(),
            )
            .unwrap();
        {
            let mut runtime = state.runtime.write().await;
            *runtime = previous.clone();
        }

        let (status, response) = finalize_detached_neutron_delete(
            &state,
            &previous,
            &port,
            previous.accepted_generation,
            Ok(()),
        )
        .await;

        assert_eq!(status, StatusCode::OK);
        assert!(response.detached);
        assert_eq!(response.status, "ok");
        let runtime = state.runtime.read().await;
        assert!(!runtime.ports.contains_key(&port.port_id));
        assert!(!runtime.port_statuses.contains_key(&port.port_id));
        assert_eq!(runtime.pending_generation, None);
        drop(runtime);
        let replay = state.wal.replay();
        assert!(replay.pending_intent.is_none());
        assert!(!replay.state.ports.contains_key(&port.port_id));
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn neutron_delete_startup_recovery_closes_forward_with_delete_commit() {
        let root = temp_root("delete-recovery-forward-commit");
        let state = test_neutron_state(&root);
        let previous = committed_runtime(63);
        let port = previous.ports["committed-port"].clone();
        state
            .wal
            .append_snapshot_commit(previous.to_wal_state())
            .unwrap();
        state
            .wal
            .append_delete_intent(
                port.port_id.clone(),
                previous.accepted_generation,
                vec!["acl".to_string(), "attach".to_string()],
                port.clone(),
            )
            .unwrap();
        let intent = state
            .wal
            .replay()
            .pending_intent
            .expect("delete intent should be pending before recovery");
        let mut recovered = previous.clone();
        recovered.ports.remove(&port.port_id);
        recovered.port_statuses.remove(&port.port_id);

        let finalized =
            finalize_recovered_delete_intent(&state, &intent, &previous, recovered, false);

        assert!(!finalized.ports.contains_key(&port.port_id));
        assert_eq!(finalized.pending_generation, None);
        assert_eq!(finalized.desired_hash, previous.applied_desired_hash);
        assert_eq!(finalized.authority_state, "ready");
        let replay = state.wal.replay();
        assert!(replay.pending_intent.is_none());
        assert!(!replay.state.ports.contains_key(&port.port_id));
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn neutron_delete_startup_recovery_failure_preserves_delete_intent() {
        let root = temp_root("delete-recovery-remains-pending");
        let state = test_neutron_state(&root);
        let previous = committed_runtime(64);
        let port = previous.ports["committed-port"].clone();
        state
            .wal
            .append_snapshot_commit(previous.to_wal_state())
            .unwrap();
        state
            .wal
            .append_delete_intent(
                port.port_id.clone(),
                previous.accepted_generation,
                vec!["acl".to_string(), "attach".to_string()],
                port.clone(),
            )
            .unwrap();
        let intent = state
            .wal
            .replay()
            .pending_intent
            .expect("delete intent should be pending before recovery");
        let mut failed_recovery = previous.clone();
        failed_recovery.port_statuses.insert(
            port.port_id.clone(),
            port_runtime_status(
                &port.port_id,
                &port.ifname,
                intent.generation,
                None,
                port.managed_domains.clone(),
                "blocked",
                Some("detach_recovery_failed".to_string()),
                vec![domain_status(
                    "attach",
                    "blocked",
                    Some("detach_recovery_failed".to_string()),
                )],
            ),
        );

        let finalized = finalize_recovered_delete_intent(
            &state,
            &intent,
            &previous,
            failed_recovery,
            true,
        );

        assert!(finalized.ports.contains_key(&port.port_id));
        assert_eq!(finalized.pending_generation, Some(intent.generation));
        assert_eq!(finalized.desired_hash, None);
        assert_eq!(finalized.authority_state, "blocked_recovery_required");
        assert_eq!(finalized.wal_status, "intent_recovery_blocked");
        assert_eq!(
            state
                .wal
                .replay()
                .pending_intent
                .as_ref()
                .map(|pending| pending.kind.as_str()),
            Some("delete")
        );
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
    fn neutron_snapshot_inventory_unavailable_cold_start_recovers_empty_baseline() {
        let runtime = NeutronRuntimeState {
            accepted_generation: 1,
            applied_generation: 0,
            pending_generation: Some(1),
            desired_hash: Some("hash-1".to_string()),
            applied_desired_hash: None,
            authority_state: "blocked_recovery_required".to_string(),
            ports: BTreeMap::new(),
            port_statuses: BTreeMap::new(),
            wal_status: "inventory_unavailable".to_string(),
            ..NeutronRuntimeState::default()
        };

        let recovered = recover_pending_runtime(
            &runtime,
            &NeutronRecoverPendingRequest {
                expected_pending_generation: 1,
                expected_desired_hash: Some("hash-1".to_string()),
                mode: None,
            },
        )
        .expect("the exact inventory-only cold-start state can restore the empty baseline");

        assert_eq!(recovered.accepted_generation, 0);
        assert_eq!(recovered.applied_generation, 0);
        assert_eq!(recovered.pending_generation, None);
        assert_eq!(recovered.desired_hash, None);
        assert_eq!(recovered.applied_desired_hash, None);
        assert!(recovered.ports.is_empty());
        assert!(recovered.port_statuses.is_empty());
        assert_eq!(
            recovered.authority_state,
            "recovered_pending_full_resync_required"
        );
        assert_eq!(recovered.wal_status, "pending_recovered_to_last_applied");
    }

    #[tokio::test]
    async fn neutron_snapshot_inventory_unavailable_clean_wal_allows_live_cold_start_recovery() {
        let root = temp_root("inventory-unavailable-live-clean-wal");
        let state = test_neutron_state(&root);
        let snapshot = inventory_snapshot(1, Vec::new());
        let transaction = build_snapshot_apply_transaction(
            &BTreeMap::new(),
            &snapshot,
            &unavailable_inventory("connection refused"),
            ApplyScope::FullHost,
        )
        .expect("inventory outage should produce a blocked transaction");
        let outcome = apply_snapshot_runtime_transaction(
            &state,
            snapshot.generation,
            snapshot.desired_hash.clone(),
            BTreeMap::new(),
            NeutronRuntimeState::default(),
            transaction,
        )
        .await;
        state
            .wal
            .append_snapshot_commit(outcome.next_runtime.to_wal_state())
            .expect("inventory-blocked state should be durable");
        {
            let mut runtime = state.runtime.write().await;
            *runtime = outcome.next_runtime;
        }

        let recovered = recover_pending_snapshot(
            state.clone(),
            NeutronRecoverPendingRequest {
                expected_pending_generation: 1,
                expected_desired_hash: Some("hash-1".to_string()),
                mode: None,
            },
        )
        .await
        .expect("a clean durable inventory cause should authorize empty-baseline recovery");

        assert_eq!(recovered.status, "recovered");
        assert_eq!(recovered.applied_generation, 0);
        assert_eq!(recovered.desired_hash, None);
        assert_eq!(recovered.applied_desired_hash, None);
        assert_eq!(
            recovered.authority_state,
            "recovered_pending_full_resync_required"
        );
        assert_eq!(recovered.wal_status, "pending_recovered_to_last_applied");
        let replay = state.wal.replay();
        assert_eq!(replay.status, "replayed");
        assert_eq!(replay.failures, 0);
        assert_eq!(replay.state.pending_generation, None);
        assert_eq!(replay.state.recovery_cause, None);
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn neutron_snapshot_inventory_unavailable_live_recovery_rejects_corrupt_wal() {
        let root = temp_root("inventory-unavailable-live-corrupt-wal");
        let state = test_neutron_state(&root);
        let snapshot = inventory_snapshot(1, Vec::new());
        let transaction = build_snapshot_apply_transaction(
            &BTreeMap::new(),
            &snapshot,
            &unavailable_inventory("connection refused"),
            ApplyScope::FullHost,
        )
        .expect("inventory outage should produce a blocked transaction");
        let outcome = apply_snapshot_runtime_transaction(
            &state,
            snapshot.generation,
            snapshot.desired_hash.clone(),
            BTreeMap::new(),
            NeutronRuntimeState::default(),
            transaction,
        )
        .await;
        state
            .wal
            .append_snapshot_commit(outcome.next_runtime.to_wal_state())
            .expect("inventory-blocked state should be durable");
        {
            let mut runtime = state.runtime.write().await;
            *runtime = outcome.next_runtime.clone();
        }

        let wal_path = state
            .registry
            .base_state_path
            .join("neutron-snapshot.wal");
        let mut wal_file = std::fs::OpenOptions::new()
            .append(true)
            .open(&wal_path)
            .expect("WAL should be appendable for corruption fixture");
        use std::io::Write as _;
        wal_file
            .write_all(b"{malformed-wal-tail\n")
            .expect("corrupt WAL fixture should be written");
        wal_file
            .flush()
            .expect("corrupt WAL fixture should be visible to replay");
        let replay = state.wal.replay();
        assert_eq!(replay.status, "replayed_with_errors");
        assert_eq!(replay.failures, 1);

        let error = recover_pending_snapshot(
            state.clone(),
            NeutronRecoverPendingRequest {
                expected_pending_generation: 1,
                expected_desired_hash: Some("hash-1".to_string()),
                mode: None,
            },
        )
        .await
        .expect_err("fresh WAL corruption must veto the generation-0 exception");

        assert_eq!(error.status, StatusCode::CONFLICT);
        assert_eq!(error.code, "no_applied_snapshot_to_restore");
        let runtime = state.runtime.read().await;
        assert_eq!(runtime.applied_generation, 0);
        assert_eq!(runtime.pending_generation, Some(1));
        assert_eq!(runtime.wal_status, "inventory_unavailable");
        assert_eq!(
            runtime.recovery_cause.as_deref(),
            Some(INVENTORY_UNAVAILABLE_RECOVERY_CAUSE)
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn neutron_snapshot_generic_cold_start_partial_remains_unrecoverable() {
        let exact_inventory_state = NeutronRuntimeState {
            accepted_generation: 1,
            applied_generation: 0,
            pending_generation: Some(1),
            desired_hash: Some("hash-1".to_string()),
            applied_desired_hash: None,
            authority_state: "blocked_recovery_required".to_string(),
            ports: BTreeMap::new(),
            port_statuses: BTreeMap::new(),
            wal_status: "inventory_unavailable".to_string(),
            ..NeutronRuntimeState::default()
        };

        let mut wrong_cause = exact_inventory_state.clone();
        wrong_cause.wal_status = "commit_written".to_string();
        let mut wrong_authority = exact_inventory_state.clone();
        wrong_authority.authority_state = "partial".to_string();
        let mut nonempty_applied_hash = exact_inventory_state.clone();
        nonempty_applied_hash.applied_desired_hash = Some("unexpected-baseline".to_string());
        let mut nonempty_ports = exact_inventory_state.clone();
        nonempty_ports.ports.insert(
            "unexpected-port".to_string(),
            managed("unexpected-port", "tap-unexpected"),
        );
        let mut nonempty_statuses = exact_inventory_state;
        nonempty_statuses.port_statuses.insert(
            "unexpected-port".to_string(),
            ready_status("unexpected-port", "tap-unexpected", 0),
        );

        for (case, runtime) in [
            ("blocked with a generic WAL status", wrong_cause),
            ("partial authority with inventory status", wrong_authority),
            ("non-empty applied hash", nonempty_applied_hash),
            ("non-empty committed ports", nonempty_ports),
            ("non-empty committed statuses", nonempty_statuses),
        ] {
            let error = recover_pending_runtime(
                &runtime,
                &NeutronRecoverPendingRequest {
                    expected_pending_generation: 1,
                    expected_desired_hash: Some("hash-1".to_string()),
                    mode: None,
                },
            )
            .expect_err(case);

            assert_eq!(error.code, "no_applied_snapshot_to_restore", "{}", case);
            assert_eq!(error.status, StatusCode::CONFLICT, "{}", case);
            assert_eq!(runtime.applied_generation, 0, "{}", case);
            assert_eq!(runtime.pending_generation, Some(1), "{}", case);
        }
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

    fn managed_projection_health_skip_fixture(
        managed_domains: Vec<String>,
    ) -> (ManagedNeutronPort, NeutronPortStatus) {
        let mut managed = managed("vm-port", "tap-vm");
        managed.managed_domains = managed_domains.clone();
        managed.domain_desired_hashes = managed_domains
            .iter()
            .map(|domain| (domain.clone(), format!("{}-hash", domain)))
            .collect();
        let status = port_runtime_status(
            "vm-port",
            "tap-vm",
            1,
            Some("snapshot-hash".to_string()),
            managed_domains.clone(),
            "ready",
            None,
            domain_statuses_for(&managed_domains, "ready", None),
        );
        (managed, status)
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum ManagedProjectionOuterSkipFailurePoint {
        Publish,
        Precommit,
        Verify,
        Compensation,
    }

    async fn run_managed_projection_outer_skip_completion(
        plan: &AclApplyPlan,
        failure: Option<ManagedProjectionOuterSkipFailurePoint>,
    ) -> (
        Result<(), NeutronAclReconcileError>,
        Vec<&'static str>,
        ManagedProjectionHealth,
    ) {
        let trace = Arc::new(std::sync::Mutex::new(Vec::new()));
        let health = Arc::new(std::sync::Mutex::new(ManagedProjectionHealth::Verified));

        let publish_trace = Arc::clone(&trace);
        let precommit_trace = Arc::clone(&trace);
        let verify_trace = Arc::clone(&trace);
        let verify_health = Arc::clone(&health);
        let compensation_trace = Arc::clone(&trace);
        let compensation_health = Arc::clone(&health);

        let result = execute_managed_acl_post_replace_completion(
            plan,
            move || {
                let trace = Arc::clone(&publish_trace);
                async move {
                    trace.lock().expect("publish trace lock").push("publish");
                    if failure == Some(ManagedProjectionOuterSkipFailurePoint::Publish) {
                        Err("forced gate publish failure".to_string())
                    } else {
                        Ok(())
                    }
                }
            },
            move || {
                let trace = Arc::clone(&precommit_trace);
                async move {
                    trace
                        .lock()
                        .expect("precommit trace lock")
                        .push("precommit");
                    if failure == Some(ManagedProjectionOuterSkipFailurePoint::Precommit) {
                        Err("forced precommit failure".to_string())
                    } else {
                        Ok(())
                    }
                }
            },
            move || {
                let trace = Arc::clone(&verify_trace);
                let health = Arc::clone(&verify_health);
                async move {
                    trace.lock().expect("verify trace lock").push("verify");
                    if failure == Some(ManagedProjectionOuterSkipFailurePoint::Verify)
                        || failure == Some(ManagedProjectionOuterSkipFailurePoint::Compensation)
                    {
                        return Err("forced projection verification failure".to_string());
                    }
                    *health.lock().expect("verify health lock") = ManagedProjectionHealth::Verified;
                    Ok(())
                }
            },
            move || {
                let trace = Arc::clone(&compensation_trace);
                let health = Arc::clone(&compensation_health);
                async move {
                    trace
                        .lock()
                        .expect("compensation trace lock")
                        .push("quiesce");
                    *health.lock().expect("compensation health lock") =
                        ManagedProjectionHealth::Unverified;
                    if failure == Some(ManagedProjectionOuterSkipFailurePoint::Compensation) {
                        Err("forced quiesce compensation failure".to_string())
                    } else {
                        Ok(())
                    }
                }
            },
        )
        .await;

        let observed_trace = trace.lock().expect("completion trace lock").clone();
        let observed_health = *health.lock().expect("completion health lock");
        (result, observed_trace, observed_health)
    }

    async fn run_neutron_acl_detach_cleanup_test(
        purge_error: Option<&'static str>,
    ) -> (Result<(), String>, Vec<&'static str>) {
        let events = Arc::new(std::sync::Mutex::new(Vec::new()));
        let quiesce_events = Arc::clone(&events);
        let purge_events = Arc::clone(&events);
        let detach_events = Arc::clone(&events);

        let result = execute_neutron_acl_detach_cleanup(
            move || {
                let events = Arc::clone(&quiesce_events);
                async move {
                    events.lock().expect("quiesce events").push("quiesce");
                    Ok::<(), String>(())
                }
            },
            move || {
                let events = Arc::clone(&purge_events);
                async move {
                    events
                        .lock()
                        .expect("purge events")
                        .push("replace-empty-and-strict-flush");
                    match purge_error {
                        Some(error) => Err(error.to_string()),
                        None => Ok(()),
                    }
                }
            },
            move || {
                let events = Arc::clone(&detach_events);
                async move {
                    events.lock().expect("detach events").push("detach");
                    Ok::<(), String>(())
                }
            },
        )
        .await;

        let observed = events.lock().expect("ordered detach events").clone();
        (result, observed)
    }

    #[tokio::test]
    async fn neutron_acl_detach_quiesces_before_owned_projection_removal() {
        let (result, events) = run_neutron_acl_detach_cleanup_test(None).await;

        result.expect("a complete quiesced purge may detach");

        assert_eq!(
            events,
            vec!["quiesce", "replace-empty-and-strict-flush", "detach"],
        );
    }

    #[tokio::test]
    async fn neutron_acl_purge_failure_aborts_detach_without_partial_owned_state() {
        let (result, events) = run_neutron_acl_detach_cleanup_test(Some(
            "forced atomic owned purge failure",
        ))
        .await;
        let error = result.expect_err("failed owned purge must abort detach");

        assert!(error.contains("forced atomic owned purge failure"), "{error}");
        assert_eq!(
            events,
            vec!["quiesce", "replace-empty-and-strict-flush"],
            "detach must not run after any owned-purge failure",
        );
    }

    #[test]
    fn detached_port_cleanup_skips_acl_purge_only_after_interface_disappears() {
        assert!(detached_port_cleanup_requires_acl_purge(true));
        assert!(!detached_port_cleanup_requires_acl_purge(false));
    }

    #[test]
    fn managed_projection_outer_skip_required_publication_mode_maps_both_ownership_states_exactly()
    {
        assert_eq!(
            required_neutron_publication_mode(true),
            ManagedAclPublicationMode::ManagedAcl
        );
        assert_eq!(
            required_neutron_publication_mode(false),
            ManagedAclPublicationMode::NeutronAttachOwnedStandaloneAcl
        );
    }

    #[test]
    fn managed_projection_outer_skip_non_acl_authority_commit_requires_attach_owned_mode() {
        let required_mode = Some(required_neutron_publication_mode(false));

        assert!(
            crate::control_plane::managed_neutron_authority_confirmation_allowed(
                true,
                Some(ManagedAclPublicationMode::NeutronAttachOwnedStandaloneAcl),
                required_mode,
                None,
                None,
            )
        );
        assert!(
            !crate::control_plane::managed_neutron_authority_confirmation_allowed(
                true,
                Some(ManagedAclPublicationMode::ManagedAcl),
                required_mode,
                Some(ManagedProjectionHealth::Verified),
                None,
            )
        );
        assert!(
            !crate::control_plane::managed_neutron_authority_confirmation_allowed(
                true,
                Some(ManagedAclPublicationMode::StandaloneCompatibility),
                required_mode,
                None,
                None,
            )
        );
    }

    #[tokio::test]
    async fn managed_projection_outer_skip_empty_and_nonempty_acl_share_one_completion_executor() {
        let empty = AclApplyPlan::default();
        let nonempty = AclApplyPlan {
            groups: vec![AclGroupPlan {
                name: "neutron:port-1:src:selector:0".to_string(),
                cidrs: vec!["192.0.2.2/32".to_string()],
            }],
            policies: vec![AclPolicyPlan {
                src_group: "neutron:port-1:src:selector:0".to_string(),
                dst_group: "any".to_string(),
                proto: 6,
                action: 1,
                direction: 1,
                ports: None,
            }],
            conntrack_enabled: Some(true),
            force_bypass_reason: None,
        };

        for (label, plan) in [("empty", &empty), ("nonempty", &nonempty)] {
            let (result, trace, health) =
                run_managed_projection_outer_skip_completion(plan, None).await;
            assert!(result.is_ok(), "{label} completion must succeed");
            assert_eq!(
                trace,
                vec!["publish", "precommit", "verify"],
                "{label} ACL completion must use the same ordered executor"
            );
            assert_eq!(
                health,
                ManagedProjectionHealth::Verified,
                "{label} ACL completion may verify only after every prior step"
            );
        }
    }

    #[tokio::test]
    async fn managed_projection_outer_skip_completion_failures_requiesce_and_never_verify() {
        let cases = [
            (
                ManagedProjectionOuterSkipFailurePoint::Publish,
                vec!["publish", "quiesce"],
                "forced gate publish failure",
            ),
            (
                ManagedProjectionOuterSkipFailurePoint::Precommit,
                vec!["publish", "precommit", "quiesce"],
                "forced precommit failure",
            ),
            (
                ManagedProjectionOuterSkipFailurePoint::Verify,
                vec!["publish", "precommit", "verify", "quiesce"],
                "forced projection verification failure",
            ),
        ];

        for (failure, expected_trace, expected_error) in cases {
            let (result, trace, health) = run_managed_projection_outer_skip_completion(
                &AclApplyPlan::default(),
                Some(failure),
            )
            .await;
            let error = result.expect_err("injected completion step must fail");
            assert_eq!(trace, expected_trace, "failure point {failure:?}");
            assert_eq!(
                health,
                ManagedProjectionHealth::Unverified,
                "failure point {failure:?} must not publish verified health"
            );
            assert!(error.details.contains(expected_error));
            assert_eq!(error.effective_action, "bypass");
        }
    }

    #[tokio::test]
    async fn managed_projection_outer_skip_compensation_failure_stays_unverified_and_visible() {
        let (result, trace, health) = run_managed_projection_outer_skip_completion(
            &AclApplyPlan::default(),
            Some(ManagedProjectionOuterSkipFailurePoint::Compensation),
        )
        .await;
        let error = result.expect_err("failed requiesce must fail completion");

        assert_eq!(
            trace,
            vec!["publish", "precommit", "verify", "quiesce"]
        );
        assert_eq!(health, ManagedProjectionHealth::Unverified);
        assert!(error
            .details
            .contains("forced projection verification failure"));
        assert!(error
            .details
            .contains("forced quiesce compensation failure"));
        assert_eq!(error.effective_action, "enforce");
    }

    #[test]
    fn managed_projection_outer_skip_clean_noop_preserves_only_prior_verified_health() {
        let (managed, status) = managed_projection_health_skip_fixture(vec!["acl".to_string()]);
        for (health, may_skip) in [
            (ManagedProjectionHealth::Verified, true),
            (ManagedProjectionHealth::Unverified, false),
            (ManagedProjectionHealth::RepairRequired, false),
        ] {
            assert_eq!(
                can_skip_neutron_domain_reconcile(
                    Some(&managed),
                    Some(&status),
                    &managed,
                    false,
                    Some(health),
                ),
                may_skip,
                "clean equal ACL reconcile with prior {health:?}"
            );
        }
    }

    #[test]
    fn managed_projection_attach_repair_supported_domain_aliases_pass_preflight() {
        let cases = [
            Vec::<String>::new(),
            vec!["attach".to_string()],
            vec!["attach".to_string(), "acl".to_string()],
            vec![
                " ACL ".to_string(),
                "policy".to_string(),
                "groups".to_string(),
                "address-sets".to_string(),
                "aria-acl".to_string(),
            ],
        ];

        for domains in cases {
            assert_eq!(
                unsupported_neutron_managed_domains(&domains),
                Vec::<String>::new(),
                "normalized attach/ACL domains must pass preflight: {domains:?}"
            );
        }
    }

    #[test]
    fn domain_authority_implemented_domains_match_advertised_capabilities() {
        assert_eq!(
            implemented_neutron_domains(),
            aria_api::NEUTRON_SUPPORTED_DOMAINS,
            "capabilities must advertise exactly the domains implemented by runtime reconcile",
        );
    }

    #[test]
    fn managed_projection_attach_repair_unsupported_domains_are_deterministic() {
        let domains = vec![
            "qos".to_string(),
            "aria-qos".to_string(),
            "mirror".to_string(),
            "aria_mirror".to_string(),
            "config".to_string(),
            "conntrack".to_string(),
            "unknown-domain".to_string(),
            "QOS".to_string(),
            "attach".to_string(),
            "acl".to_string(),
        ];

        assert_eq!(
            unsupported_neutron_managed_domains(&domains),
            vec![
                "config".to_string(),
                "conntrack".to_string(),
                "mirror".to_string(),
                "qos".to_string(),
                "unknown_domain".to_string(),
            ]
        );
    }

    #[test]
    fn managed_projection_health_verified_acl_may_skip_equal_scoped_reconcile() {
        let (managed, status) = managed_projection_health_skip_fixture(vec!["acl".to_string()]);

        assert!(can_skip_neutron_domain_reconcile(
            Some(&managed),
            Some(&status),
            &managed,
            false,
            Some(crate::control_plane::ManagedProjectionHealth::Verified),
        ));
    }

    #[test]
    fn managed_projection_health_unverified_acl_cannot_skip_equal_reconcile() {
        let (managed, status) = managed_projection_health_skip_fixture(vec!["acl".to_string()]);

        assert!(!can_skip_neutron_domain_reconcile(
            Some(&managed),
            Some(&status),
            &managed,
            false,
            Some(crate::control_plane::ManagedProjectionHealth::Unverified),
        ));
    }

    #[test]
    fn managed_projection_health_missing_acl_evidence_cannot_skip_equal_reconcile() {
        let (managed, status) = managed_projection_health_skip_fixture(vec!["acl".to_string()]);

        assert!(!can_skip_neutron_domain_reconcile(
            Some(&managed),
            Some(&status),
            &managed,
            false,
            None,
        ));
    }

    #[test]
    fn managed_projection_health_repair_required_acl_cannot_skip_equal_reconcile() {
        let (managed, status) = managed_projection_health_skip_fixture(vec!["acl".to_string()]);

        assert!(!can_skip_neutron_domain_reconcile(
            Some(&managed),
            Some(&status),
            &managed,
            false,
            Some(crate::control_plane::ManagedProjectionHealth::RepairRequired),
        ));
    }

    #[test]
    fn managed_projection_health_full_resync_cannot_skip_even_when_verified() {
        let (managed, status) = managed_projection_health_skip_fixture(vec!["acl".to_string()]);

        assert!(!can_skip_neutron_domain_reconcile(
            Some(&managed),
            Some(&status),
            &managed,
            true,
            Some(crate::control_plane::ManagedProjectionHealth::Verified),
        ));
    }

    #[test]
    fn managed_projection_health_non_acl_skip_does_not_require_acl_evidence() {
        let (managed, status) = managed_projection_health_skip_fixture(vec!["qos".to_string()]);

        assert!(can_skip_neutron_domain_reconcile(
            Some(&managed),
            Some(&status),
            &managed,
            false,
            None,
        ));
    }

    #[test]
    fn neutron_acl_full_host_resync_republishes_after_unprojected_health_loss() {
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
            &managed,
            false,
            Some(ManagedProjectionHealth::Verified),
        ));
        // The detector may already have quiesced the live gate while the
        // projector has not yet replaced this still-ready status. A full-host
        // authoritative resync must therefore reconcile and republish ACL.
        assert!(!can_skip_neutron_domain_reconcile(
            Some(&managed),
            Some(&status),
            &managed,
            true,
            Some(ManagedProjectionHealth::Verified),
        ));

        let mut changed_snapshot = snapshot.clone();
        changed_snapshot.acl.as_mut().unwrap().revision = 2;
        let changed = managed_port_from_snapshot(&changed_snapshot);
        assert!(!can_skip_neutron_domain_reconcile(
            Some(&managed),
            Some(&status),
            &changed,
            false,
            Some(ManagedProjectionHealth::Verified),
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
            &managed,
            false,
            Some(ManagedProjectionHealth::Verified),
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
            false,
            Some(ManagedProjectionHealth::Unverified),
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
    fn neutron_snapshot_restart_partial_status_remains_blocked_after_runtime_reconcile_and_acl_invalidation(
    ) {
        let mut restored = managed_with_ifindex("vm-port", "tap-vm", 17);
        restored.managed_domains = vec!["acl".to_string()];
        restored
            .domain_desired_hashes
            .insert("acl".to_string(), "acl-hash-43".to_string());
        let prior_error = port_runtime_status(
            "vm-port",
            "tap-vm",
            43,
            Some("hash-43".to_string()),
            vec!["acl".to_string()],
            "error",
            Some("acl_apply_failed".to_string()),
            vec![domain_status_with_action(
                "acl",
                "error",
                Some("acl_apply_failed".to_string()),
                Some("unchanged".to_string()),
            )],
        );
        let before_restart = NeutronRuntimeState {
            accepted_generation: 43,
            applied_generation: 42,
            pending_generation: Some(43),
            desired_hash: Some("hash-43".to_string()),
            applied_desired_hash: Some("hash-42".to_string()),
            authority_state: "partial".to_string(),
            wal_status: "commit_written".to_string(),
            ports: BTreeMap::from([("vm-port".to_string(), restored.clone())]),
            port_statuses: BTreeMap::from([("vm-port".to_string(), prior_error)]),
            ..Default::default()
        };
        let reconcile_results = vec![crate::tap_registry::RuntimeReconcileResult {
            ifname: "tap-vm".to_string(),
            action: "claim_committed".to_string(),
            status: "ready".to_string(),
            reason: Some("runtime_reconciled".to_string()),
        }];

        let after_restart = project_committed_runtime_reconcile(
            &before_restart,
            std::slice::from_ref(&restored),
            42,
            Some("hash-42".to_string()),
            &reconcile_results,
            false,
        )
        .expect("a committed runtime reconcile result must project status");

        assert_eq!(after_restart.pending_generation, Some(43));
        assert_eq!(after_restart.authority_state, "partial");
        assert_eq!(after_restart.wal_status, "runtime_reconciled");
        let status = &after_restart.port_statuses["vm-port"];
        assert_eq!(status.generation, 42);
        assert_eq!(status.desired_hash.as_deref(), Some("hash-42"));
        assert_eq!(status.status, "degraded");
        assert_eq!(
            status.reason.as_deref(),
            Some("acl_restart_replay_requires_resync")
        );
        let acl = status
            .domains
            .iter()
            .find(|domain| domain.domain == "acl")
            .expect("ACL restart status");
        assert_eq!(acl.status, "degraded");
        assert_eq!(acl.effective_action.as_deref(), Some("unchanged"));

        let projection = project_neutron_status_v1(&after_restart);
        assert_eq!(
            projection.transaction_state,
            NeutronStatusTransactionState::Blocked
        );
        assert_eq!(
            projection.overall_readiness,
            NeutronStatusOverallReadiness::Blocked
        );
        assert_eq!(
            projection.required_action,
            NeutronStatusRequiredAction::RecoverPending
        );
    }

    #[test]
    fn restart_missing_committed_tap_is_deferred_for_full_resync() {
        let mut results = vec![
            crate::tap_registry::RuntimeReconcileResult {
                ifname: "tap-missing".to_string(),
                action: "claim_committed".to_string(),
                status: "blocked".to_string(),
                reason: Some("attach failed: interface not found".to_string()),
            },
            crate::tap_registry::RuntimeReconcileResult {
                ifname: "tap-present".to_string(),
                action: "claim_committed".to_string(),
                status: "blocked".to_string(),
                reason: Some("attach failed: verifier rejected program".to_string()),
            },
        ];
        let missing_ifnames = BTreeSet::from(["tap-missing".to_string()]);

        assert!(defer_missing_committed_interfaces(
            &mut results,
            &missing_ifnames,
        ));
        assert_eq!(results[0].status, "deferred");
        assert_eq!(
            results[0].reason.as_deref(),
            Some("runtime_rebuild_required")
        );
        assert_eq!(results[1].status, "blocked");
        assert_eq!(
            results[1].reason.as_deref(),
            Some("attach failed: verifier rejected program")
        );
    }

    #[test]
    fn restart_missing_tap_projects_degraded_full_resync_not_operator() {
        let mut port = managed("vm-port", "tap-missing");
        port.managed_domains = vec!["acl".to_string()];
        let status = runtime_rebuild_port_status(&port, 42, Some("hash-42".to_string()));
        let runtime = NeutronRuntimeState {
            accepted_generation: 42,
            applied_generation: 42,
            desired_hash: Some("hash-42".to_string()),
            applied_desired_hash: Some("hash-42".to_string()),
            authority_state: "runtime_reconcile_requires_full_resync".to_string(),
            wal_status: "runtime_reconcile_requires_full_resync".to_string(),
            ports: BTreeMap::from([(port.port_id.clone(), port)]),
            port_statuses: BTreeMap::from([("vm-port".to_string(), status)]),
            ..Default::default()
        };

        let projection = project_neutron_status_v1(&runtime);
        assert_eq!(
            projection.transaction_state,
            NeutronStatusTransactionState::Classified
        );
        assert_eq!(
            projection.overall_readiness,
            NeutronStatusOverallReadiness::Degraded
        );
        assert_eq!(
            projection.required_action,
            NeutronStatusRequiredAction::FullResync
        );
    }

    #[test]
    fn recovered_inventory_retries_runtime_reconcile_once_tap_returns() {
        let mut port = managed("vm-port", "tap-vm");
        port.ifindex = None;
        port.managed_domains = vec!["acl".to_string()];
        let mut runtime = NeutronRuntimeState {
            accepted_generation: 42,
            applied_generation: 42,
            desired_hash: Some("hash-42".to_string()),
            applied_desired_hash: Some("hash-42".to_string()),
            authority_state: "recovered_pending_full_resync_required".to_string(),
            ports: BTreeMap::from([(port.port_id.clone(), port.clone())]),
            ..Default::default()
        };

        assert!(!should_retry_committed_runtime_reconcile(
            &runtime,
            &BTreeSet::new(),
        ));

        let live_ifnames = BTreeSet::from(["tap-vm".to_string()]);
        assert!(should_retry_committed_runtime_reconcile(
            &runtime,
            &live_ifnames,
        ));

        runtime.port_statuses.insert(
            "vm-port".to_string(),
            runtime_rebuild_port_status(
                &port,
                runtime.applied_generation,
                runtime.applied_desired_hash.clone(),
            ),
        );
        runtime.authority_state = "runtime_reconcile_requires_full_resync".to_string();
        assert!(should_retry_committed_runtime_reconcile(
            &runtime,
            &live_ifnames,
        ));

        runtime.port_statuses.insert(
            "vm-port".to_string(),
            port_runtime_status(
                "vm-port",
                "tap-vm",
                42,
                Some("hash-42".to_string()),
                vec!["acl".to_string()],
                "degraded",
                Some("acl_restart_replay_requires_resync".to_string()),
                vec![domain_status_with_action(
                    "acl",
                    "degraded",
                    Some("acl_restart_replay_requires_resync".to_string()),
                    Some("unchanged".to_string()),
                )],
            ),
        );
        assert!(!should_retry_committed_runtime_reconcile(
            &runtime,
            &live_ifnames,
        ));
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
        let mut intent = PendingNeutronIntent::default();
        intent.kind = "snapshot".to_string();
        intent.generation = 17;
        intent.desired_hash = Some("hash-17".to_string());
        intent.port_ids = vec!["vm-port".to_string()];
        intent.affected_domains = vec!["acl".to_string()];
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
        assert_eq!(
            plan.inventory_error.as_deref(),
            Some("ovsdb_unavailable:permission denied")
        );
        assert_eq!(plan.ignored.len(), 1);
        assert_eq!(
            plan.ignored[0].reason.as_deref(),
            Some("ovsdb_unavailable:permission denied")
        );
    }

    #[test]
    fn neutron_snapshot_plan_defers_committed_port_until_ifindex_is_ready() {
        let mut current = BTreeMap::new();
        current.insert(
            "vm-port".to_string(),
            ManagedNeutronPort {
                ifindex: None,
                managed_domains: vec!["acl".to_string()],
                ..managed("vm-port", "tap-vm")
            },
        );
        let local = inventory(vec![iface(
            "tap-vm",
            "vm-port",
            None,
            Some("br-int"),
        )]);
        let snapshot = inventory_snapshot(
            8,
            vec![NeutronPortSnapshot {
                managed_domains: vec!["acl".to_string()],
                ..port("vm-port", "tap-vm", true)
            }],
        );

        let plan = build_snapshot_plan(&current, &snapshot, &local);

        assert!(plan.attach.is_empty());
        assert!(plan.update.is_empty());
        assert!(plan.detach.is_empty());
        assert_eq!(
            plan.inventory_error.as_deref(),
            Some("local_port_not_ready:vm-port:ifindex_not_ready")
        );
        assert_eq!(plan.ignored.len(), 1);
        assert_eq!(plan.ignored[0].port_id, "vm-port");
        assert_eq!(
            plan.ignored[0].reason.as_deref(),
            Some("ifindex_not_ready")
        );
    }

    #[tokio::test]
    async fn neutron_snapshot_ifindex_not_ready_preserves_committed_runtime_for_retry() {
        let root = temp_root("ifindex-not-ready-transaction");
        let state = test_neutron_state(&root);
        let mut previous = committed_runtime(85);
        let committed = ManagedNeutronPort {
            port_id: "vm-port".to_string(),
            ifname: "tap-vm".to_string(),
            ifindex: None,
            managed_domains: vec!["acl".to_string()],
            domain_desired_hashes: BTreeMap::new(),
        };
        previous.ports = BTreeMap::from([("vm-port".to_string(), committed.clone())]);
        previous.port_statuses = BTreeMap::from([(
            "vm-port".to_string(),
            runtime_rebuild_port_status(
                &committed,
                previous.applied_generation,
                previous.applied_desired_hash.clone(),
            ),
        )]);
        previous.authority_state = "runtime_reconcile_requires_full_resync".to_string();
        let snapshot = inventory_snapshot(
            86,
            vec![NeutronPortSnapshot {
                managed_domains: vec!["acl".to_string()],
                ..port("vm-port", "tap-vm", true)
            }],
        );
        let local = inventory(vec![iface(
            "tap-vm",
            "vm-port",
            None,
            Some("br-int"),
        )]);
        let transaction = build_snapshot_apply_transaction(
            &previous.ports,
            &snapshot,
            &local,
            ApplyScope::FullHost,
        )
        .expect("transient local inventory remains a retriable transaction");

        let outcome = apply_snapshot_runtime_transaction(
            &state,
            snapshot.generation,
            snapshot.desired_hash.clone(),
            previous.ports.clone(),
            previous.clone(),
            transaction,
        )
        .await;

        assert!(outcome.has_error);
        assert_eq!(outcome.next_runtime.applied_generation, 85);
        assert_eq!(outcome.next_runtime.ports, previous.ports);
        assert_eq!(outcome.next_runtime.port_statuses, previous.port_statuses);
        assert_eq!(
            outcome.next_runtime.recovery_cause.as_deref(),
            Some(INVENTORY_UNAVAILABLE_RECOVERY_CAUSE)
        );
        assert_eq!(
            outcome.next_runtime.authority_state,
            "blocked_recovery_required"
        );
        assert!(outcome.results.iter().any(|result| {
            result.port_id == "snapshot"
                && result.status == "error"
                && result.reason.as_deref()
                    == Some("local_port_not_ready:vm-port:ifindex_not_ready")
        }));
        assert!(!outcome.results.iter().any(|result| result.action == "detach"));
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn neutron_acl_translator_merges_same_tuple_l4_port_rules() {
        let mut drop_8080 = tcp_rule("drop-8080", "drop", 8080);
        drop_8080.priority = 101;
        let acl = ready_acl(vec![
            tcp_rule("drop-18081", "drop", 18081),
            drop_8080,
        ]);

        let plan =
            translate_neutron_acl_for_test("port-1", &acl).expect("ACL should translate");

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
    fn neutron_acl_translator_trims_protocol_before_parsing() {
        let acl = ready_acl(vec![acl_rule_with(
            "trimmed-protocol",
            10,
            " TCP ",
            "drop",
            &[],
            &[],
            None,
        )]);

        let plan = translate_neutron_acl_for_test("port-1", &acl)
            .expect("protocol whitespace and case should normalize");

        assert_eq!(plan.policies.len(), 1);
        assert_eq!(plan.policies[0].proto, 6);
        assert_eq!(plan.force_bypass_reason, None);
    }

    #[test]
    fn neutron_acl_translator_trims_action_before_parsing() {
        let acl = ready_acl(vec![acl_rule_with(
            "trimmed-action",
            10,
            "tcp",
            " DENY ",
            &[],
            &[],
            None,
        )]);

        let plan = translate_neutron_acl_for_test("port-1", &acl)
            .expect("action whitespace and case should normalize");

        assert_eq!(plan.policies.len(), 1);
        assert_eq!(plan.policies[0].action, 1);
        assert_eq!(plan.force_bypass_reason, None);
    }

    #[test]
    fn neutron_acl_translator_trims_direction_before_parsing() {
        let mut rule = acl_rule_with(
            "trimmed-direction",
            10,
            "tcp",
            "drop",
            &[],
            &[],
            None,
        );
        rule.direction = Some(" InGrEsS ".to_string());
        let acl = ready_acl(vec![rule]);

        let plan = translate_neutron_acl_for_test("port-1", &acl)
            .expect("direction whitespace and case should normalize");

        assert_eq!(plan.policies.len(), 1);
        assert_eq!(plan.policies[0].direction, 1);
        assert_eq!(plan.force_bypass_reason, None);
    }

    #[test]
    fn neutron_acl_cidrs_match_python_strict_grammar() {
        assert_eq!(
            AclIpv4Cidr::parse(" 10.1.2.3/24 ")
                .unwrap()
                .canonical(),
            "10.1.2.0/24"
        );
        assert!(AclIpv4Cidr::parse("10.1/16").is_err());
        assert!(AclIpv4Cidr::parse("010.1.2.3/24").is_err());
    }

    #[test]
    fn neutron_acl_runtime_limits_accept_boundary_and_force_bypass_overflow() {
        let accepted = ready_acl(numbered_acl_rules(MAX_ACL_RULES_PER_POLICY));
        assert_eq!(
            translate_neutron_acl_for_test("port-1", &accepted)
                .unwrap()
                .force_bypass_reason,
            None
        );

        let rejected = ready_acl(numbered_acl_rules(MAX_ACL_RULES_PER_POLICY + 1));
        assert_eq!(
            translate_neutron_acl_for_test("port-1", &rejected)
                .unwrap()
                .force_bypass_reason
                .as_deref(),
            Some("acl_rule_limit_exceeded:1001:1000")
        );
    }

    #[test]
    fn neutron_acl_selector_limit_accepts_2048_and_force_bypasses_2049() {
        let mut accepted_rule = acl_rule_with(
            "accepted-members",
            10,
            "tcp",
            "drop",
            &[],
            &[],
            None,
        );
        accepted_rule.src_cidrs = numbered_acl_members(MAX_ACL_SELECTOR_MEMBERS);
        let accepted = ready_acl(vec![accepted_rule]);
        assert_eq!(
            translate_neutron_acl_for_test("port-1", &accepted)
                .unwrap()
                .force_bypass_reason,
            None,
        );

        let mut rejected_rule = acl_rule_with(
            "rejected-members",
            10,
            "tcp",
            "drop",
            &[],
            &[],
            None,
        );
        rejected_rule.src_cidrs = numbered_acl_members(MAX_ACL_SELECTOR_MEMBERS + 1);
        let rejected = ready_acl(vec![rejected_rule]);
        assert_eq!(
            translate_neutron_acl_for_test("port-1", &rejected)
                .unwrap()
                .force_bypass_reason
                .as_deref(),
            Some("acl_selector_member_limit_exceeded:src:rejected-members:2049:2048"),
        );
    }

    #[test]
    fn neutron_acl_normalized_rules_store_only_selector_ids() {
        let rule = normalized_acl_rule_with_selectors("id-only", 10, 6, 1, 2);

        assert_eq!(rule.src_selector_id, AclSelectorId(1));
        assert_eq!(rule.dst_selector_id, AclSelectorId(2));
    }

    #[test]
    fn neutron_acl_shared_large_selector_is_stored_once_for_1000_rules() {
        let selector = numbered_acl_members(MAX_ACL_SELECTOR_MEMBERS)
            .iter()
            .map(|cidr| AclIpv4Cidr::parse(cidr).unwrap())
            .collect::<Vec<_>>();
        let rules = (0..MAX_ACL_RULES_PER_POLICY)
            .map(|index| {
                normalized_acl_rule_with_selectors(
                    &format!("shared-{}", index),
                    index as i64,
                    if index % 2 == 0 { 6 } else { 17 },
                    1,
                    0,
                )
            })
            .collect::<Vec<_>>();
        let template = AclValidatedTemplate::Ready {
            rules,
            src_selectors: vec![Vec::new(), selector.clone()],
            dst_selectors: vec![Vec::new()],
        };

        let AclValidatedTemplate::Ready {
            rules,
            src_selectors,
            dst_selectors,
        } = template
        else {
            panic!("expected ready template");
        };
        assert_eq!(rules.len(), MAX_ACL_RULES_PER_POLICY);
        assert!(rules.iter().all(|rule| rule.src_selector_id == AclSelectorId(1)));
        assert_eq!(src_selectors, vec![Vec::new(), selector]);
        assert_eq!(dst_selectors, vec![Vec::new()]);
    }

    #[test]
    fn neutron_acl_1000_disjoint_selectors_pass_interval_sweep() {
        let mut src_selectors = vec![Vec::new()];
        let mut rules = Vec::new();
        let members = numbered_acl_members(MAX_ACL_RULES_PER_POLICY);
        for index in 0..MAX_ACL_RULES_PER_POLICY {
            src_selectors.push(vec![AclIpv4Cidr::parse(&members[index]).unwrap()]);
            rules.push(normalized_acl_rule_with_selectors(
                &format!("disjoint-{}", index),
                index as i64,
                6,
                index + 1,
                0,
            ));
        }

        assert_eq!(
            acl_priority_overlap_reason(&rules, &src_selectors, &[Vec::new()]),
            None,
        );
    }

    #[test]
    fn neutron_acl_cross_selector_nesting_keeps_stable_overlap_reason() {
        let src_selectors = vec![
            Vec::new(),
            vec![AclIpv4Cidr::parse("10.0.0.0/8").unwrap()],
            vec![AclIpv4Cidr::parse("10.1.0.0/16").unwrap()],
        ];
        let rules = vec![
            normalized_acl_rule_with_selectors("broad", 10, 6, 1, 0),
            normalized_acl_rule_with_selectors("narrow", 20, 17, 2, 0),
        ];

        assert_eq!(
            acl_priority_overlap_reason(&rules, &src_selectors, &[Vec::new()]),
            Some("unsupported_acl_cidr_overlap:src:broad:10:narrow:20".to_string()),
        );
    }

    #[test]
    fn neutron_acl_overlap_reason_uses_earliest_rule_pair_not_address_order() {
        let src_selectors = vec![
            Vec::new(),
            vec![
                AclIpv4Cidr::parse("10.0.0.0/8").unwrap(),
                AclIpv4Cidr::parse("192.0.2.0/24").unwrap(),
            ],
            vec![AclIpv4Cidr::parse("192.0.2.128/25").unwrap()],
            vec![AclIpv4Cidr::parse("10.1.0.0/16").unwrap()],
        ];
        let rules = vec![
            normalized_acl_rule_with_selectors("first", 10, 6, 1, 0),
            normalized_acl_rule_with_selectors("second", 20, 17, 2, 0),
            normalized_acl_rule_with_selectors("third", 30, 1, 3, 0),
        ];

        assert_eq!(
            acl_priority_overlap_reason(&rules, &src_selectors, &[Vec::new()]),
            Some("unsupported_acl_cidr_overlap:src:first:10:second:20".to_string()),
        );
    }

    #[test]
    fn neutron_acl_earlier_destination_pair_beats_later_source_conflict() {
        let src_selectors = vec![
            Vec::new(),
            vec![AclIpv4Cidr::parse("10.0.0.0/8").unwrap()],
            vec![AclIpv4Cidr::parse("10.1.0.0/16").unwrap()],
        ];
        let dst_selectors = vec![
            Vec::new(),
            vec![AclIpv4Cidr::parse("192.0.2.0/24").unwrap()],
            vec![AclIpv4Cidr::parse("192.0.2.128/25").unwrap()],
        ];
        let rules = vec![
            normalized_acl_rule_with_selectors("first", 10, 6, 1, 1),
            normalized_acl_rule_with_selectors("second", 20, 17, 0, 2),
            normalized_acl_rule_with_selectors("third", 30, 1, 2, 0),
        ];

        assert_eq!(
            acl_priority_overlap_reason(&rules, &src_selectors, &dst_selectors),
            Some("unsupported_acl_cidr_overlap:dst:first:10:second:20".to_string()),
        );
    }

    #[test]
    fn neutron_acl_earlier_priority_pair_beats_later_cidr_pair() {
        let src_selectors = vec![
            Vec::new(),
            vec![AclIpv4Cidr::parse("10.0.0.0/32").unwrap()],
            vec![AclIpv4Cidr::parse("10.0.0.0/31").unwrap()],
        ];
        let dst_selectors = vec![
            Vec::new(),
            vec![AclIpv4Cidr::parse("192.0.2.0/24").unwrap()],
        ];
        let mut first = normalized_acl_rule_with_selectors("first", 10, 17, 1, 0);
        first.action = 0;
        let second = normalized_acl_rule_with_selectors("second", 20, 0, 0, 1);
        let mut third = normalized_acl_rule_with_selectors("third", 30, 6, 2, 0);
        third.action = 0;

        assert_eq!(
            acl_priority_overlap_reason(
                &[first, second, third],
                &src_selectors,
                &dst_selectors,
            ),
            Some("unsupported_acl_priority_overlap:first:10:second:20".to_string()),
        );
    }

    #[test]
    fn neutron_acl_same_rule_pair_source_cidr_overlap_beats_destination() {
        let src_selectors = vec![
            Vec::new(),
            vec![AclIpv4Cidr::parse("10.0.0.0/24").unwrap()],
            vec![AclIpv4Cidr::parse("10.0.0.128/25").unwrap()],
        ];
        let dst_selectors = vec![
            Vec::new(),
            vec![AclIpv4Cidr::parse("192.0.2.0/24").unwrap()],
            vec![AclIpv4Cidr::parse("192.0.2.128/25").unwrap()],
        ];
        let rules = vec![
            normalized_acl_rule_with_selectors("first", 10, 6, 1, 1),
            normalized_acl_rule_with_selectors("second", 20, 17, 2, 2),
        ];

        assert_eq!(
            acl_priority_overlap_reason(&rules, &src_selectors, &dst_selectors),
            Some("unsupported_acl_cidr_overlap:src:first:10:second:20".to_string()),
        );
    }

    #[test]
    fn neutron_acl_selector_sweep_reactivates_multi_gap_selectors_stably() {
        let selectors = vec![
            Vec::new(),
            vec![
                AclIpv4Cidr::parse("0.0.0.0/32").unwrap(),
                AclIpv4Cidr::parse("0.0.0.4/32").unwrap(),
            ],
            vec![
                AclIpv4Cidr::parse("0.0.0.0/31").unwrap(),
                AclIpv4Cidr::parse("0.0.0.4/31").unwrap(),
            ],
        ];
        let first_rule_indexes = vec![None, Some(1), Some(0)];

        assert_eq!(
            acl_selector_best_overlap(&selectors, &first_rule_indexes),
            Some((0, 1)),
        );
    }

    #[test]
    fn neutron_acl_selector_sweep_returns_only_best_rule_pair_rank() {
        let selectors = vec![
            Vec::new(),
            vec![
                AclIpv4Cidr::parse("10.0.0.0/8").unwrap(),
                AclIpv4Cidr::parse("192.0.2.0/24").unwrap(),
            ],
            vec![AclIpv4Cidr::parse("192.0.2.128/25").unwrap()],
            vec![AclIpv4Cidr::parse("10.1.0.0/16").unwrap()],
        ];
        let first_rule_indexes = vec![None, Some(0), Some(1), Some(2)];

        assert_eq!(
            acl_selector_best_overlap(&selectors, &first_rule_indexes),
            Some((0, 1)),
        );
    }

    #[test]
    fn neutron_acl_selector_sweep_repeated_overlap_keeps_one_best_candidate() {
        let mut selectors = vec![Vec::new()];
        for member in numbered_acl_members(MAX_ACL_RULES_PER_POLICY) {
            selectors.push(vec![
                AclIpv4Cidr::parse("10.0.0.0/8").unwrap(),
                AclIpv4Cidr::parse(&member).unwrap(),
            ]);
        }
        let first_rule_indexes = (0..selectors.len())
            .map(|selector_index| selector_index.checked_sub(1))
            .collect::<Vec<_>>();

        assert_eq!(
            acl_selector_best_overlap(&selectors, &first_rule_indexes),
            Some((0, 1)),
        );
    }

    #[test]
    fn neutron_acl_same_selector_internal_nesting_is_accepted() {
        let src_selectors = vec![
            Vec::new(),
            vec![
                AclIpv4Cidr::parse("10.0.0.0/8").unwrap(),
                AclIpv4Cidr::parse("10.1.0.0/16").unwrap(),
            ],
        ];
        let rules = vec![
            normalized_acl_rule_with_selectors("tcp", 10, 6, 1, 0),
            normalized_acl_rule_with_selectors("udp", 20, 17, 1, 0),
        ];

        assert_eq!(
            acl_priority_overlap_reason(&rules, &src_selectors, &[Vec::new()]),
            None,
        );
    }

    #[test]
    fn neutron_acl_source_and_destination_selector_spaces_are_independent() {
        let acl = ready_acl(vec![
            acl_rule_with("source", 10, "tcp", "drop", &["192.0.2.0/24"], &[], None),
            acl_rule_with(
                "destination",
                20,
                "udp",
                "drop",
                &[],
                &["192.0.2.0/24"],
                None,
            ),
        ]);

        let AclValidatedTemplate::Ready {
            rules,
            src_selectors,
            dst_selectors,
        } = validate_neutron_acl_template(&acl).unwrap()
        else {
            panic!("expected ready template");
        };
        assert_eq!(src_selectors, dst_selectors);
        assert_eq!(src_selectors.len(), 2);
        assert_eq!(rules[0].src_selector_id, AclSelectorId(1));
        assert_eq!(rules[0].dst_selector_id, AclSelectorId(0));
        assert_eq!(rules[1].src_selector_id, AclSelectorId(0));
        assert_eq!(rules[1].dst_selector_id, AclSelectorId(1));
    }

    #[test]
    fn neutron_acl_validation_cache_is_content_safe_and_port_specific() {
        let acl = ready_acl(vec![acl_rule_with(
            "cached",
            10,
            "tcp",
            "drop",
            &["10.1.2.3/24"],
            &[],
            None,
        )]);
        let mut cache = AclValidationCache::default();
        let first = translate_neutron_acl_with_cache("port-1", &acl, &mut cache).unwrap();
        let second = translate_neutron_acl_with_cache("port-2", &acl, &mut cache).unwrap();
        assert_eq!(cache.misses, 1);
        assert_eq!(cache.hits, 1);
        assert!(first
            .groups
            .iter()
            .all(|group| group.name.starts_with("neutron:port-1:")));
        assert!(second
            .groups
            .iter()
            .all(|group| group.name.starts_with("neutron:port-2:")));
        assert_eq!(first.groups[0].name, "neutron:port-1:src:selector:0");
        assert_eq!(second.groups[0].name, "neutron:port-2:src:selector:0");

        let mut changed_revision = acl.clone();
        changed_revision.revision += 1;
        translate_neutron_acl_with_cache("port-3", &changed_revision, &mut cache).unwrap();
        assert_eq!(cache.misses, 2);

        let mut changed_rules = acl;
        changed_rules.rules[0].action = Some("allow".to_string());
        translate_neutron_acl_with_cache("port-4", &changed_rules, &mut cache).unwrap();
        assert_eq!(cache.misses, 3);
    }

    #[test]
    fn neutron_acl_translator_force_bypasses_nested_cidrs() {
        let acl = ready_acl(vec![
            acl_rule_with("broad", 10, "tcp", "allow", &["10.0.0.0/8"], &[], None),
            acl_rule_with("narrow", 20, "udp", "allow", &["10.1.0.0/16"], &[], None),
        ]);
        let plan = translate_neutron_acl_for_test("port-1", &acl).unwrap();
        assert!(plan.groups.is_empty());
        assert!(plan.policies.is_empty());
        assert_eq!(
            plan.force_bypass_reason.as_deref(),
            Some("unsupported_acl_cidr_overlap:src:broad:10:narrow:20")
        );
    }

    #[test]
    fn neutron_acl_translator_reuses_canonical_cidr_groups() {
        let acl = ready_acl(vec![
            acl_rule_with("tcp", 10, "tcp", "drop", &["10.1.2.3/24"], &[], Some(80)),
            acl_rule_with("udp", 20, "udp", "drop", &["10.1.2.0/24"], &[], Some(53)),
        ]);
        let plan = translate_neutron_acl_for_test("port-1", &acl).unwrap();
        assert_eq!(plan.groups.len(), 1);
        assert_eq!(plan.groups[0].cidrs, vec!["10.1.2.0/24"]);
        assert_eq!(plan.policies[0].src_group, plan.policies[1].src_group);
        assert_eq!(plan.force_bypass_reason, None);
    }

    #[test]
    fn neutron_acl_translator_force_bypasses_priority_fallback_conflict() {
        let acl = ready_acl(vec![
            acl_rule_with("wildcard", 10, "any", "allow", &[], &[], None),
            acl_rule_with("tcp-drop", 20, "tcp", "drop", &[], &[], None),
        ]);
        let plan = translate_neutron_acl_for_test("port-1", &acl).unwrap();
        assert_eq!(
            plan.force_bypass_reason.as_deref(),
            Some("unsupported_acl_priority_overlap:wildcard:10:tcp-drop:20")
        );
    }

    #[test]
    fn neutron_acl_translator_force_bypasses_invalid_and_duplicate_priority() {
        let negative = ready_acl(vec![acl_rule_with(
            "negative", -1, "tcp", "drop", &[], &[], None,
        )]);
        assert_eq!(
            translate_neutron_acl_for_test("port-1", &negative)
                .unwrap()
                .force_bypass_reason
                .as_deref(),
            Some("invalid_acl_priority:negative:-1")
        );

        let duplicate = ready_acl(vec![
            acl_rule_with("first", 10, "tcp", "drop", &[], &[], None),
            acl_rule_with("second", 10, "udp", "drop", &[], &[], None),
        ]);
        assert_eq!(
            translate_neutron_acl_for_test("port-1", &duplicate)
                .unwrap()
                .force_bypass_reason
                .as_deref(),
            Some("duplicate_acl_priority:egress:10:first:second")
        );
    }

    #[test]
    fn neutron_acl_translator_keeps_disjoint_cidrs_separate() {
        let acl = ready_acl(vec![
            acl_rule_with("tcp-left", 10, "tcp", "drop", &["10.1.0.0/16"], &[], None),
            acl_rule_with("udp-right", 20, "udp", "drop", &["10.2.0.0/16"], &[], None),
        ]);
        let plan = translate_neutron_acl_for_test("port-1", &acl).unwrap();
        assert_eq!(plan.groups.len(), 2);
        assert_eq!(plan.policies.len(), 2);
        assert_eq!(plan.force_bypass_reason, None);
    }

    #[test]
    fn neutron_acl_force_bypass_outcome_overrides_optimistic_snapshot() {
        let acl = ready_acl(vec![
            acl_rule_with("wildcard", 10, "any", "allow", &[], &[], None),
            acl_rule_with("tcp-drop", 20, "tcp", "drop", &[], &[], None),
        ]);
        let plan = translate_neutron_acl_for_test("port-1", &acl).unwrap();
        let outcome = NeutronAclReconcileOutcome::from_plan(&plan);
        let mut snapshot = port("port-1", "tap-port-1", true);
        snapshot.managed_domains = vec!["acl".to_string()];
        snapshot.acl = Some(acl);

        let status = outcome.domain_status(&snapshot);
        assert_eq!(status.status, "degraded");
        assert_eq!(status.effective_action.as_deref(), Some("bypass"));
        assert_eq!(
            status.reason.as_deref(),
            Some("unsupported_acl_priority_overlap:wildcard:10:tcp-drop:20")
        );
    }

    #[test]
    fn neutron_acl_translator_carries_conntrack_intent() {
        let stateful = ready_acl(vec![tcp_rule("drop-8080", "drop", 8080)]);
        assert_eq!(
            translate_neutron_acl_for_test("port-1", &stateful)
                .expect("stateful ACL should translate")
                .conntrack_enabled,
            Some(true)
        );

        let mut stateless = stateful;
        stateless.stateful = false;
        assert_eq!(
            translate_neutron_acl_for_test("port-1", &stateless)
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
            acl_ingress_hook: aria_core::common::ACL_INGRESS_HOOK_TC,
        };

        let stateful = acl_runtime_transition(
            &AclApplyPlan {
                groups: Vec::new(),
                policies: vec![policy.clone()],
                conntrack_enabled: Some(true),
                force_bypass_reason: None,
            },
            false,
        );
        assert_eq!(stateful.quiesce, quiesced);
        assert_eq!(
            stateful.publish,
            AclRuntimeFeatureState {
                conntrack_enabled: true,
                acl_enabled: true,
                acl_ingress_hook: aria_core::common::ACL_INGRESS_HOOK_TC,
            }
        );

        let stateless = acl_runtime_transition(
            &AclApplyPlan {
                groups: Vec::new(),
                policies: vec![policy],
                conntrack_enabled: Some(false),
                force_bypass_reason: None,
            },
            true,
        );
        assert_eq!(stateless.quiesce, quiesced);
        assert_eq!(
            stateless.publish,
            AclRuntimeFeatureState {
                conntrack_enabled: false,
                acl_enabled: true,
                acl_ingress_hook: aria_core::common::ACL_INGRESS_HOOK_TC,
            }
        );

        let empty_stateful = acl_runtime_transition(
            &AclApplyPlan {
                groups: Vec::new(),
                policies: Vec::new(),
                conntrack_enabled: Some(true),
                force_bypass_reason: None,
            },
            false,
        );
        assert_eq!(empty_stateful.quiesce, quiesced);
        assert_eq!(
            empty_stateful.publish,
            AclRuntimeFeatureState {
                conntrack_enabled: true,
                acl_enabled: false,
                acl_ingress_hook: aria_core::common::ACL_INGRESS_HOOK_TC,
            }
        );

        let missing_payload = acl_runtime_transition(&AclApplyPlan::default(), true);
        assert_eq!(missing_payload.quiesce, quiesced);
        assert_eq!(
            missing_payload.publish,
            AclRuntimeFeatureState {
                conntrack_enabled: true,
                acl_enabled: false,
                acl_ingress_hook: aria_core::common::ACL_INGRESS_HOOK_TC,
            }
        );
    }

    #[test]
    fn managed_projection_repair_quiesced_replace_uses_publish_tc_requirement() {
        let transition = acl_runtime_transition(
            &AclApplyPlan {
                groups: Vec::new(),
                policies: Vec::new(),
                conntrack_enabled: Some(true),
                force_bypass_reason: None,
            },
            false,
        );

        assert!(!acl_runtime_feature_requires_tc(transition.quiesce));
        assert!(acl_runtime_feature_requires_tc(transition.publish));
    }

    #[test]
    fn neutron_acl_translator_force_bypasses_conflicting_actions_for_same_tuple() {
        let mut allow_18081 = tcp_rule("allow-18081", "allow", 18081);
        allow_18081.priority = 101;
        let acl = ready_acl(vec![
            tcp_rule("drop-8080", "drop", 8080),
            allow_18081,
        ]);

        let plan = translate_neutron_acl_for_test("port-1", &acl).unwrap();

        assert!(plan.groups.is_empty());
        assert!(plan.policies.is_empty());
        assert_eq!(
            plan.force_bypass_reason.as_deref(),
            Some("unsupported_acl_priority_overlap:drop-8080:100:allow-18081:101")
        );
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
            src_cidrs: vec!["192.0.2.2/32".to_string()],
            dst_cidrs: Vec::new(),
            src_port_min: None,
            src_port_max: None,
            dst_port_min: None,
            dst_port_max: None,
        }]);

        let plan =
            translate_neutron_acl_for_test("port-1", &acl).expect("ACL should translate");

        assert_eq!(
            plan.groups,
            vec![AclGroupPlan {
                name: "neutron:port-1:src:selector:0".to_string(),
                cidrs: vec!["192.0.2.2/32".to_string()],
            }]
        );
        assert_eq!(
            plan.policies,
            vec![AclPolicyPlan {
                src_group: "neutron:port-1:src:selector:0".to_string(),
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

        let error = translate_neutron_acl_for_test("port-1", &acl)
            .expect_err("default deny is guarded");

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
                name: "neutron:port-1:src:selector:0".to_string(),
                cidrs: vec!["192.0.2.2/32".to_string()],
            }],
            policies: vec![AclPolicyPlan {
                src_group: "neutron:port-1:src:selector:0".to_string(),
                dst_group: "any".to_string(),
                proto: 1,
                action: 1,
                direction: 1,
                ports: None,
            }],
            conntrack_enabled: Some(true),
            force_bypass_reason: None,
        };

        assert_eq!(
            acl_gate_update_mode(&plan),
            AclGateUpdateMode::DisableBeforeReplace
        );
    }

    #[test]
    fn neutron_acl_reconcile_failure_phase_reports_the_proven_effective_action() {
        let pre_disable = acl_reconcile_error(AclReconcileFailurePhase::BeforeQuiesce, "x");
        assert_eq!(pre_disable.effective_action, "unchanged");

        let post_disable = acl_reconcile_error(AclReconcileFailurePhase::AfterQuiesce, "x");
        assert_eq!(post_disable.effective_action, "bypass");

        let compensation =
            acl_reconcile_error(AclReconcileFailurePhase::CompensationFailed, "x");
        assert_eq!(compensation.effective_action, "enforce");
    }

    #[test]
    fn managed_projection_repair_fatal_after_quiesce_keeps_gate_in_bypass() {
        let transition = acl_runtime_transition(&AclApplyPlan::default(), true);
        let error = acl_reconcile_error(
            AclReconcileFailurePhase::AfterQuiesce,
            "unknown active selector",
        );

        assert!(!transition.quiesce.conntrack_enabled);
        assert!(!transition.quiesce.acl_enabled);
        assert_eq!(error.effective_action, "bypass");
        assert!(error.details.contains("unknown active selector"));
    }

}
