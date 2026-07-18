use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fs;
use std::future::Future;
use std::path::Path;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::{Mutex, RwLock};
use tracing::{error, info, warn};

use crate::instance::{
    preexisting_tc_acl_runtime_is_healthy, FirewallInstance, RuntimePinState, TcAclLinkHealth,
};
use crate::kernel_drop_manager::{KernelDropManager, KernelDropStatusSnapshot};
use crate::service_chain::{self, ServiceChain};
use crate::ssl_manager::SslManager;
use crate::tap_registry::ManagedAttachMode;
use crate::trace_backend::{TraceManager, TraceRuntimeStatusSnapshot};
use aria_core::common::TapMapRuntime;
use aria_core::ebpf_ops::{
    classify_runtime_gate_state, compile_managed_group_projection, ensure_fq_qdisc,
    replay_managed_state_to_pinned_maps, replay_state_to_pinned_maps,
    validate_managed_pinned_runtime_state, validate_pinned_runtime_state, FqQdiscState,
    GroupProjectionMode, ProjectionDrift, RuntimeGateDisposition, TraceMapMode,
};
use aria_core::state::{FirewallState, GroupInfo, MirrorRuleInfo, QosRuleInfo, RuleInfo};
use aria_core::wal::{WalClient, WalEntry};

mod observability;
mod ssl;
mod tcprt;
mod trace;

const WAL_COMPACT_THRESHOLD: u64 = 1000;
pub const MANAGED_SHARED_PIN_NAMESPACE: &str = "global-v2";
const FQ_QDISC_MARKER: &str = ".fq-root-qdisc-owned";

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(crate) enum ManagedAclPublicationMode {
    StandaloneCompatibility,
    NeutronAttachOwnedStandaloneAcl,
    ManagedAcl,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(crate) enum ManagedProjectionHealth {
    Unverified,
    RepairRequired,
    Verified,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
struct ManagedAclLifecycle {
    publication_mode: ManagedAclPublicationMode,
    projection_health: ManagedProjectionHealth,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(crate) enum ManagedAclPromotionAction {
    Preserve,
    Promote {
        next_mode: ManagedAclPublicationMode,
        next_health: ManagedProjectionHealth,
        quiesce_acl_ct: bool,
    },
}

/// Per-instance in-memory state
struct InstanceState {
    state: FirewallState,
    runtime_health: RuntimeHealthState,
    managed_acl_publication_mode: ManagedAclPublicationMode,
    managed_projection_health: ManagedProjectionHealth,
    tap_id: u32,
    ifindex: Option<u32>,
    pin_path: String,
    state_path: String,
    wal: WalClient,
    ssl_sync_pending: bool,
    last_ssl_sync_error: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RuntimeHealthState {
    acl_ready: bool,
    xdp_ready: bool,
    acl_error: Option<String>,
}

impl RuntimeHealthState {
    fn readiness_reason(&self) -> Option<String> {
        self.acl_error
            .clone()
            .or_else(|| (!self.xdp_ready).then(|| "xdp_ddos_hook_unavailable".to_string()))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RuntimeHealthTransition {
    next: RuntimeHealthState,
    changed: bool,
    quiesce_acl_ct: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InstanceRuntimeHealthSnapshot {
    pub name: String,
    pub active: bool,
    pub acl_ready: bool,
    pub xdp_ready: bool,
    pub readiness_reason: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TcAclHealthChange {
    pub instance: String,
    pub acl_ready: bool,
    pub xdp_ready: bool,
    pub reason: Option<String>,
    pub quiesced: bool,
}

fn missing_tc_reason(health: TcAclLinkHealth) -> Option<&'static str> {
    match (health.ingress, health.egress) {
        (false, false) => Some("missing_tc_ingress_and_egress"),
        (false, true) => Some("missing_tc_ingress"),
        (true, false) => Some("missing_tc_egress"),
        (true, true) => None,
    }
}

fn apply_tc_health_observation(
    current: RuntimeHealthState,
    observed: TcAclLinkHealth,
) -> RuntimeHealthTransition {
    let mut next = current.clone();
    next.xdp_ready = observed.xdp_ready();
    let retry_failed_quiesce = current
        .acl_error
        .as_deref()
        .is_some_and(|error| error.starts_with("acl_quiesce_failed:"));
    let quiesce_acl_ct = if let Some(reason) = missing_tc_reason(observed) {
        next.acl_ready = false;
        next.acl_error = Some(reason.to_string());
        current.acl_ready
            || current.acl_error.as_deref() == Some("recovery_required")
            || retry_failed_quiesce
    } else if !current.acl_ready {
        next.acl_ready = false;
        next.acl_error = Some("recovery_required".to_string());
        retry_failed_quiesce
    } else {
        next.acl_ready = true;
        next.acl_error = None;
        false
    };
    RuntimeHealthTransition {
        changed: next != current,
        next,
        quiesce_acl_ct,
    }
}

fn apply_tc_health_quiesce_result(
    mut next: RuntimeHealthState,
    result: Result<(), String>,
) -> (RuntimeHealthState, bool) {
    match result {
        Ok(()) => (next, true),
        Err(error) => {
            next.acl_ready = false;
            next.acl_error = Some(format!("acl_quiesce_failed:{}", error));
            (next, false)
        }
    }
}

fn apply_recovery_publication_quiesce_result(
    mut health: RuntimeHealthState,
    readiness_error: ControlPlaneError,
    quiesce_result: Result<(), String>,
) -> (RuntimeHealthState, ControlPlaneError) {
    health.acl_ready = false;
    match quiesce_result {
        Ok(()) => (health, readiness_error),
        Err(error) => {
            health.acl_error = Some(format!("acl_quiesce_failed:{}", error));
            (
                health,
                ControlPlaneError::InstanceNotReady(format!(
                    "{}; acl_quiesce_failed:{}",
                    readiness_error, error
                )),
            )
        }
    }
}

fn initial_runtime_health(
    desired_conntrack: bool,
    desired_acl: bool,
    health: TcAclLinkHealth,
    enforcement_published: bool,
) -> RuntimeHealthState {
    let enforcement_required = desired_conntrack || desired_acl;
    let acl_ready = !enforcement_required || (health.acl_ready() && enforcement_published);
    let acl_error = if acl_ready {
        None
    } else {
        missing_tc_reason(health)
            .map(str::to_string)
            .or_else(|| Some("recovery_required".to_string()))
    };
    RuntimeHealthState {
        acl_ready,
        xdp_ready: health.xdp_ready(),
        acl_error,
    }
}

#[derive(Debug, Clone)]
struct KernelDropInstanceView {
    instance_name: String,
    tap_id: u32,
    ifindex: Option<u32>,
    iface_name: Option<String>,
}

#[derive(Debug, Clone)]
struct ResolvedKernelDropQuery {
    tap_id: Option<u32>,
    ifindex: Option<u32>,
    include_unattributed: bool,
    by_tap: HashMap<u32, String>,
    by_ifindex: HashMap<u32, String>,
    iface_name_by_ifindex: HashMap<u32, String>,
}

impl InstanceState {
    fn map_runtime(&self) -> TapMapRuntime<'_> {
        TapMapRuntime::new(&self.pin_path, self.tap_id)
    }

    fn wal_needs_compact(&self, threshold: u64) -> bool {
        self.wal.needs_compact(threshold)
    }

    /// Serialize state then compact WAL. Avoids borrow conflict between wal and state.
    async fn do_compact(&mut self) {
        match serde_json::to_string_pretty(&self.state) {
            Ok(json) => {
                if let Err(e) = self.wal.compact(json).await {
                    error!(state_path = %self.state_path, error = %e, "failed to compact state");
                }
            }
            Err(e) => {
                error!(state_path = %self.state_path, error = %e, "failed to serialize state for compact");
            }
        }
    }

    /// Publish an in-memory state only after its complete snapshot is durable.
    /// On any serialization/compact error, `self.state` remains the previously
    /// acknowledged allocator state.
    async fn compact_and_publish_state(&mut self, next: FirewallState) -> Result<(), String> {
        let json = serde_json::to_string_pretty(&next)
            .map_err(|error| format!("failed to serialize state for compact: {}", error))?;
        self.wal.compact(json).await?;
        self.state = next;
        Ok(())
    }

    /// Strictly append a WAL entry. If append fails, a successful full compact
    /// is the only fallback that may acknowledge durable persistence.
    async fn wal_append_strict(&mut self, entry: &WalEntry) -> Result<(), String> {
        if let Err(append_error) = self.wal.append(entry.clone()).await {
            error!(
                state_path = %self.state_path,
                error = %append_error,
                "WAL append failed; attempting compact fallback"
            );
            let json = serde_json::to_string_pretty(&self.state).map_err(|serialize_error| {
                format!(
                    "WAL append failed: {}; compact fallback serialization failed: {}",
                    append_error, serialize_error
                )
            })?;
            self.wal.compact(json).await.map_err(|compact_error| {
                format!(
                    "WAL append failed: {}; compact fallback failed: {}",
                    append_error, compact_error
                )
            })?;
        }
        Ok(())
    }

    /// Best-effort wrapper retained for legacy mutation paths whose public
    /// error contract predates strict persistence acknowledgement.
    async fn wal_append(&mut self, entry: &WalEntry) {
        if let Err(error) = self.wal_append_strict(entry).await {
            error!(state_path = %self.state_path, error = %error, "state persistence failed");
        }
    }

    async fn recover_gate_persistence_failure<F>(
        &mut self,
        requested_conntrack: bool,
        requested_acl: bool,
        persistence_error: impl Into<String>,
        mut update_kernel_gate: F,
    ) -> ControlPlaneError
    where
        F: FnMut(bool, bool) -> Result<(), String>,
    {
        let mut errors = vec![persistence_error.into()];
        self.state.conntrack_enabled = false;
        self.state.acl_enabled = false;

        if neutron_acl_gate_requires_tc(requested_conntrack, requested_acl) {
            if let Err(error) = update_kernel_gate(false, false) {
                errors.push(format!("kernel gate quiesce failed: {}", error));
            }
        }

        if let Err(error) = self
            .wal_append_strict(&WalEntry::UpdateConfig {
                conntrack: Some(false),
                monitoring: None,
                acl: Some(false),
                qos: None,
                mirror: None,
                tcprt: None,
                ssl: None,
            })
            .await
        {
            errors.push(format!("disabled gate persistence failed: {}", error));
        }

        ControlPlaneError::PersistenceError(errors.join("; "))
    }

    async fn recover_local_config_persistence_failure<F>(
        &mut self,
        old_state: FirewallState,
        attempted_enable: bool,
        persistence_error: impl Into<String>,
        mut restore_kernel_config: F,
    ) -> ControlPlaneError
    where
        F: FnMut(&FirewallState) -> Result<(), String>,
    {
        let mut errors = vec![persistence_error.into()];
        self.state = old_state;
        if attempted_enable {
            self.state.conntrack_enabled = false;
            self.state.acl_enabled = false;
        }

        if let Err(error) = restore_kernel_config(&self.state) {
            errors.push(format!("kernel config rollback failed: {}", error));
        }

        if let Err(error) = self
            .wal_append_strict(&WalEntry::UpdateConfig {
                conntrack: Some(self.state.conntrack_enabled),
                monitoring: Some(self.state.monitoring_enabled),
                acl: Some(self.state.acl_enabled),
                qos: Some(self.state.qos_enabled),
                mirror: Some(self.state.mirror_enabled),
                tcprt: Some(self.state.tcprt_enabled),
                ssl: None,
            })
            .await
        {
            errors.push(format!("rollback config persistence failed: {}", error));
        }

        ControlPlaneError::PersistenceError(errors.join("; "))
    }

    async fn shutdown_wal(&mut self) {
        self.wal.shutdown().await;
    }
}

pub struct PreparedManagedInstance {
    name: String,
    state: FirewallState,
    tap_id: u32,
    ifindex: u32,
    pin_path: String,
    state_path: String,
    wal: WalClient,
    desired_ssl_enabled: Option<bool>,
    preserve_existing_runtime: bool,
    iface_ctx_synced: bool,
    tap_config_written: bool,
    managed_acl_lifecycle: ManagedAclLifecycle,
    activation: ManagedRuntimeActivation,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
enum ManagedRuntimeActivation {
    PreserveVerifiedLive,
    RestoreStandalone { conntrack: bool, acl: bool },
    AwaitNeutronResync { require_tc_acl_links: bool },
}

fn managed_group_projection_mode(mode: ManagedAttachMode) -> GroupProjectionMode {
    match mode {
        ManagedAttachMode::StandaloneRestoreAfterTcAttach => {
            GroupProjectionMode::StandaloneCompatibility
        }
        ManagedAttachMode::NeutronResyncRequired { acl_managed: true } => {
            GroupProjectionMode::Managed
        }
        ManagedAttachMode::NeutronResyncRequired { acl_managed: false } => {
            GroupProjectionMode::StandaloneCompatibility
        }
    }
}

fn preexisting_projection_verification(drift: ProjectionDrift) -> Result<bool, String> {
    match drift {
        ProjectionDrift::Clean => Ok(true),
        ProjectionDrift::RepairRequired(_) => Ok(false),
        ProjectionDrift::Fatal(error) => Err(error),
    }
}

fn managed_acl_registration_lifecycle(
    mode: ManagedAttachMode,
    projection_drift: Option<ProjectionDrift>,
    gate_disposition: Option<RuntimeGateDisposition>,
) -> Result<ManagedAclLifecycle, String> {
    let publication_mode = match mode {
        ManagedAttachMode::StandaloneRestoreAfterTcAttach => {
            ManagedAclPublicationMode::StandaloneCompatibility
        }
        ManagedAttachMode::NeutronResyncRequired { acl_managed: false } => {
            ManagedAclPublicationMode::NeutronAttachOwnedStandaloneAcl
        }
        ManagedAttachMode::NeutronResyncRequired { acl_managed: true } => {
            ManagedAclPublicationMode::ManagedAcl
        }
    };
    let projection_health = match projection_drift {
        None => ManagedProjectionHealth::Unverified,
        Some(ProjectionDrift::Clean) => {
            if gate_disposition == Some(RuntimeGateDisposition::Desired) {
                ManagedProjectionHealth::Verified
            } else {
                ManagedProjectionHealth::Unverified
            }
        }
        Some(ProjectionDrift::RepairRequired(_)) => ManagedProjectionHealth::RepairRequired,
        Some(ProjectionDrift::Fatal(error)) => return Err(error),
    };
    Ok(ManagedAclLifecycle {
        publication_mode,
        projection_health,
    })
}

pub(crate) fn managed_acl_promotion_action(
    current_mode: ManagedAclPublicationMode,
    current_health: ManagedProjectionHealth,
    requested_mode: ManagedAttachMode,
) -> ManagedAclPromotionAction {
    match requested_mode {
        ManagedAttachMode::NeutronResyncRequired { acl_managed: true }
            if current_mode != ManagedAclPublicationMode::ManagedAcl =>
        {
            ManagedAclPromotionAction::Promote {
                next_mode: ManagedAclPublicationMode::ManagedAcl,
                next_health: ManagedProjectionHealth::Unverified,
                quiesce_acl_ct: true,
            }
        }
        ManagedAttachMode::NeutronResyncRequired { acl_managed: false }
            if current_mode == ManagedAclPublicationMode::StandaloneCompatibility =>
        {
            ManagedAclPromotionAction::Promote {
                next_mode: ManagedAclPublicationMode::NeutronAttachOwnedStandaloneAcl,
                next_health: current_health,
                quiesce_acl_ct: false,
            }
        }
        _ => ManagedAclPromotionAction::Preserve,
    }
}

#[cfg(test)]
pub(crate) fn managed_acl_ownership_after_detach(
    _publication_mode: ManagedAclPublicationMode,
    _projection_health: ManagedProjectionHealth,
) -> Option<(ManagedAclPublicationMode, ManagedProjectionHealth)> {
    None
}

pub(crate) fn managed_neutron_authority_confirmation_allowed(
    instance_exists: bool,
    current_publication_mode: Option<ManagedAclPublicationMode>,
    required_publication_mode: Option<ManagedAclPublicationMode>,
    current_projection_health: Option<ManagedProjectionHealth>,
    required_projection_health: Option<ManagedProjectionHealth>,
) -> bool {
    let neutron_owned = matches!(
        current_publication_mode,
        Some(ManagedAclPublicationMode::NeutronAttachOwnedStandaloneAcl)
            | Some(ManagedAclPublicationMode::ManagedAcl)
    );
    instance_exists
        && neutron_owned
        && required_publication_mode
            .map(|required| current_publication_mode == Some(required))
            .unwrap_or(true)
        && required_projection_health
            .map(|required| current_projection_health == Some(required))
            .unwrap_or(true)
}

struct PreexistingRuntimeValidation {
    projection_drift: ProjectionDrift,
    gate_disposition: Option<RuntimeGateDisposition>,
}

impl PreexistingRuntimeValidation {
    fn fatal(error: String) -> Self {
        Self {
            projection_drift: ProjectionDrift::Fatal(error),
            gate_disposition: None,
        }
    }
}

fn managed_runtime_activation(
    mode: ManagedAttachMode,
    preexisting_live_verified: bool,
    desired_conntrack: bool,
    desired_acl: bool,
) -> ManagedRuntimeActivation {
    if preexisting_live_verified {
        return ManagedRuntimeActivation::PreserveVerifiedLive;
    }
    match mode {
        ManagedAttachMode::StandaloneRestoreAfterTcAttach => {
            ManagedRuntimeActivation::RestoreStandalone {
                conntrack: desired_conntrack,
                acl: desired_acl,
            }
        }
        ManagedAttachMode::NeutronResyncRequired { acl_managed } => {
            ManagedRuntimeActivation::AwaitNeutronResync {
                require_tc_acl_links: acl_managed,
            }
        }
    }
}

fn neutron_acl_gate_requires_tc(conntrack_enabled: bool, acl_enabled: bool) -> bool {
    conntrack_enabled || acl_enabled
}

fn neutron_acl_gate_requires_full_resync(
    conntrack_enabled: bool,
    acl_enabled: bool,
    runtime_ready: bool,
    allow_recovery_publication: bool,
) -> bool {
    neutron_acl_gate_requires_tc(conntrack_enabled, acl_enabled)
        && !runtime_ready
        && !allow_recovery_publication
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
enum NeutronGateHealthCommitAction {
    ClearDisabled,
    VerifyRecoveryPublication,
    Preserve,
}

fn neutron_gate_health_commit_action(
    conntrack_enabled: bool,
    acl_enabled: bool,
    allow_recovery_publication: bool,
) -> NeutronGateHealthCommitAction {
    if !neutron_acl_gate_requires_tc(conntrack_enabled, acl_enabled) {
        NeutronGateHealthCommitAction::ClearDisabled
    } else if allow_recovery_publication {
        NeutronGateHealthCommitAction::VerifyRecoveryPublication
    } else {
        NeutronGateHealthCommitAction::Preserve
    }
}

fn config_update_requires_tc(conntrack: Option<bool>, acl: Option<bool>) -> bool {
    conntrack == Some(true) || acl == Some(true)
}

impl PreparedManagedInstance {
    pub fn requires_tc_acl_links(&self) -> bool {
        match self.activation {
            ManagedRuntimeActivation::PreserveVerifiedLive => {
                self.state.conntrack_enabled || self.state.acl_enabled
            }
            ManagedRuntimeActivation::RestoreStandalone { conntrack, acl } => conntrack || acl,
            ManagedRuntimeActivation::AwaitNeutronResync {
                require_tc_acl_links,
            } => require_tc_acl_links,
        }
    }
}

pub struct ControlPlane {
    instances: RwLock<HashMap<String, Arc<tokio::sync::RwLock<InstanceState>>>>,
    neutron_authorities: RwLock<HashMap<String, NeutronPortAuthority>>,
    tap_id_lock: Mutex<()>,
    runtime_lifecycle_lock: Mutex<()>,
    pub ebpf_path: String,
    pub base_pin_path: String,
    pub base_state_path: String,
    ssl_manager: Arc<SslManager>,
    kernel_drop_manager: Arc<KernelDropManager>,
    trace_manager: Arc<TraceManager>,
    chains: RwLock<Vec<ServiceChain>>,
}

#[derive(Clone, Debug)]
pub struct OwnedAclGroupSpec {
    pub name: String,
    pub cidrs: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct OwnedAclPolicySpec {
    pub src_group: String,
    pub dst_group: String,
    pub proto: u8,
    pub action: u8,
    pub direction: u8,
    pub ports: Option<String>,
}

#[derive(Clone, Debug, Default)]
pub struct OwnedAclReconcileReport {
    pub group_delete_count: usize,
    pub group_add_count: usize,
    pub group_cidr_add_count: usize,
    pub group_cidr_delete_count: usize,
    pub policy_delete_count: usize,
    pub policy_add_count: usize,
    pub port_set_delete_count: usize,
    pub compact_ms: u128,
    pub selector_repair_performed: bool,
}

#[derive(Clone, Debug)]
struct OwnedAclPolicyRuntimeAdd {
    rule: RuleInfo,
    is_new_port_set: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct TransactionCreatedPortSet {
    bitmap_idx: u32,
    ports_normalized: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct PortSetCleanupFailure {
    bitmap_idx: u32,
    error: String,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct PortSetCleanupReport {
    cleaned_bitmap_indices: Vec<u32>,
    failures: Vec<PortSetCleanupFailure>,
}

fn transaction_created_port_sets(
    state: &FirewallState,
    runtime_adds: &[OwnedAclPolicyRuntimeAdd],
) -> Result<Vec<TransactionCreatedPortSet>, ControlPlaneError> {
    let mut created = BTreeMap::<u32, String>::new();
    for add in runtime_adds.iter().filter(|add| add.is_new_port_set) {
        let Some(bitmap_idx) = add.rule.bitmap_idx else {
            continue;
        };
        let ports_normalized = state
            .port_sets
            .values()
            .find(|port_set| port_set.bitmap_idx == bitmap_idx)
            .map(|port_set| port_set.ports_normalized.clone())
            .ok_or_else(|| {
                ControlPlaneError::ValidationError(format!(
                    "transaction-created port set {} is missing allocation metadata",
                    bitmap_idx
                ))
            })?;
        created.insert(bitmap_idx, ports_normalized);
    }
    Ok(created
        .into_iter()
        .map(|(bitmap_idx, ports_normalized)| TransactionCreatedPortSet {
            bitmap_idx,
            ports_normalized,
        })
        .collect())
}

fn execute_transaction_port_set_cleanup<F>(
    port_sets: &[TransactionCreatedPortSet],
    mut cleanup: F,
) -> PortSetCleanupReport
where
    F: FnMut(&TransactionCreatedPortSet) -> Result<(), String>,
{
    let mut report = PortSetCleanupReport::default();
    for port_set in port_sets {
        match cleanup(port_set) {
            Ok(()) => report.cleaned_bitmap_indices.push(port_set.bitmap_idx),
            Err(error) => report.failures.push(PortSetCleanupFailure {
                bitmap_idx: port_set.bitmap_idx,
                error,
            }),
        }
    }
    report
}

fn cleanup_port_sets(
    port_sets: &[TransactionCreatedPortSet],
    runtime: TapMapRuntime<'_>,
    ebpf_path: &str,
    cleanup_context: &str,
) -> PortSetCleanupReport {
    execute_transaction_port_set_cleanup(port_sets, |port_set| {
        aria_core::ebpf_ops::delete_port_set(
            port_set.bitmap_idx,
            &port_set.ports_normalized,
            runtime,
            ebpf_path,
        )
        .map_err(|error| {
            format!(
                "cleanup {} port set {} ({}): {}",
                cleanup_context, port_set.bitmap_idx, port_set.ports_normalized, error
            )
        })
    })
}

fn cleanup_transaction_created_port_sets(
    port_sets: &[TransactionCreatedPortSet],
    runtime: TapMapRuntime<'_>,
    ebpf_path: &str,
) -> PortSetCleanupReport {
    cleanup_port_sets(port_sets, runtime, ebpf_path, "transaction-created")
}

fn quarantine_port_set_indices(
    state: &mut FirewallState,
    port_sets: &[TransactionCreatedPortSet],
) -> Result<(), String> {
    let mut errors = Vec::new();
    for port_set in port_sets {
        if let Err(error) = state.quarantine_bitmap_index(port_set.bitmap_idx) {
            errors.push(format!(
                "quarantine bitmap index {}: {}",
                port_set.bitmap_idx, error
            ));
        }
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors.join("; "))
    }
}

fn quarantine_owned_acl_released_port_set(
    state: &mut FirewallState,
    released_port_sets: &mut BTreeMap<u32, String>,
    released: Option<(u32, String)>,
) -> Result<(), String> {
    if let Some((bitmap_idx, ports_normalized)) = released {
        // Quarantine before recording the cleanup target. This keeps the
        // released index out of the allocator for the rest of this diff.
        state.quarantine_bitmap_index(bitmap_idx)?;
        released_port_sets.insert(bitmap_idx, ports_normalized);
    }
    Ok(())
}

fn apply_confirmed_port_set_cleanups(
    state: &mut FirewallState,
    cleanup: &PortSetCleanupReport,
) -> Result<(), String> {
    let mut errors = Vec::new();
    for bitmap_idx in &cleanup.cleaned_bitmap_indices {
        match state.release_quarantined_bitmap_index(*bitmap_idx) {
            Ok(true) => {}
            Ok(false) => errors.push(format!(
                "cleaned bitmap index {} had no durable quarantine",
                bitmap_idx
            )),
            Err(error) => errors.push(format!(
                "release cleaned bitmap index {}: {}",
                bitmap_idx, error
            )),
        }
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors.join("; "))
    }
}

fn old_state_with_failed_cleanup_quarantines(
    old_state: &FirewallState,
    cleanup: &PortSetCleanupReport,
) -> Result<FirewallState, String> {
    let mut recovery_state = old_state.clone();
    for failure in &cleanup.failures {
        recovery_state
            .quarantine_bitmap_index(failure.bitmap_idx)
            .map_err(|error| {
                format!(
                    "preserve failed bitmap cleanup quarantine {}: {}",
                    failure.bitmap_idx, error
                )
            })?;
    }
    Ok(recovery_state)
}

fn failed_persistence_recovery_state(
    old_state: &FirewallState,
    cleanup: &PortSetCleanupReport,
) -> Result<FirewallState, String> {
    old_state_with_failed_cleanup_quarantines(old_state, cleanup)
}

async fn restore_old_state_after_created_cleanup(
    state: &mut InstanceState,
    old_state: &FirewallState,
    created_port_sets: &[TransactionCreatedPortSet],
    cleanup: &PortSetCleanupReport,
) -> Result<(), String> {
    if created_port_sets.is_empty() {
        return Ok(());
    }
    let recovery_state = old_state_with_failed_cleanup_quarantines(old_state, cleanup)?;
    state
        .compact_and_publish_state(recovery_state)
        .await
        .map_err(|error| format!("restore durable old ACL allocator state: {}", error))
}

async fn restore_durable_old_state_after_failed_persistence(
    state: &mut InstanceState,
    old_state: &FirewallState,
    cleanup: &PortSetCleanupReport,
) -> Result<(), String> {
    let recovery_state = failed_persistence_recovery_state(old_state, cleanup)?;
    state
        .compact_and_publish_state(recovery_state)
        .await
        .map_err(|error| {
            format!(
                "restore durable old ACL state after failed persistence: {}",
                error
            )
        })
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
struct OwnedAclPolicyKey {
    src_group: String,
    dst_group: String,
    proto: u8,
    direction: u8,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct OwnedAclPolicyValue {
    action: u8,
    ports: Option<String>,
}

#[derive(Clone, Debug)]
struct ExistingOwnedAclPolicy {
    key: OwnedAclPolicyKey,
    value: OwnedAclPolicyValue,
    rule: RuleInfo,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum SharedNetworkMutation {
    Added {
        direction: &'static str,
        cidr: String,
        group_id: u32,
    },
    Deleted {
        direction: &'static str,
        cidr: String,
        group_id: u32,
    },
    Replaced {
        direction: &'static str,
        cidr: String,
        old_group_id: u32,
        new_group_id: u32,
    },
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
enum ManagedLocalProjectionOrder {
    GeneralThenDomain,
    DomainThenGeneral,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
struct ManagedQosDirectionPlan {
    direction: u8,
    effective_mode: u8,
}

#[derive(Clone, Debug)]
enum ManagedLocalDomainOperation {
    EnsureFqQdisc {
        cleanup_on_rollback: bool,
    },
    CleanupOwnedFqQdisc,
    QosUpsert(QosRuleInfo),
    QosDelete {
        group_id: u32,
        direction: u8,
    },
    MirrorUpsert(MirrorRuleInfo),
    MirrorDelete {
        src_group_id: u32,
        dst_group_id: u32,
        proto: u8,
        direction: u8,
        is_global: bool,
    },
}

#[derive(Clone, Debug)]
enum ManagedLocalDomainReceipt {
    FqQdisc {
        state: FqQdiscState,
        cleanup_on_rollback: bool,
    },
    QosUpsert {
        applied: QosRuleInfo,
        previous: Option<QosRuleInfo>,
    },
    QosDelete {
        deleted: QosRuleInfo,
    },
    MirrorUpsert {
        applied: MirrorRuleInfo,
        previous: Option<MirrorRuleInfo>,
    },
    MirrorDelete {
        deleted: MirrorRuleInfo,
    },
}

#[derive(Clone, Debug)]
enum ManagedLocalProjectionOperation {
    General(SharedNetworkMutation),
    Domain(ManagedLocalDomainOperation),
}

#[derive(Clone, Debug)]
enum ManagedLocalProjectionReceipt {
    General(SharedNetworkMutation),
    Domain(ManagedLocalDomainReceipt),
}

#[derive(Clone, Debug)]
struct ManagedLocalProjectionRuntime {
    instance: String,
    pin_path: String,
    state_path: String,
    ebpf_path: String,
    tap_id: u32,
    attached_iface: Option<String>,
    qos_enabled: bool,
    mirror_enabled: bool,
}

impl ManagedLocalProjectionRuntime {
    fn map_runtime(&self) -> TapMapRuntime<'_> {
        TapMapRuntime::new(&self.pin_path, self.tap_id)
    }

    fn iface(&self) -> Result<String, String> {
        if self.instance == "system" {
            self.attached_iface.clone().ok_or_else(|| {
                "system interface is not attached for managed local projection".to_string()
            })
        } else {
            Ok(self.instance.clone())
        }
    }
}

type ManagedLocalFuture<T> = Pin<Box<dyn Future<Output = T> + Send>>;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
enum ManagedLocalProjectionFailureKind {
    Kernel,
    Persistence,
}

#[derive(Debug)]
struct ManagedLocalProjectionFailure {
    kind: ManagedLocalProjectionFailureKind,
    message: String,
}

impl ManagedLocalProjectionFailure {
    #[cfg(test)]
    fn contains(&self, pattern: &str) -> bool {
        self.message.contains(pattern)
    }

    fn into_control_plane_error(self) -> ControlPlaneError {
        match self.kind {
            ManagedLocalProjectionFailureKind::Kernel => {
                ControlPlaneError::KernelError(self.message)
            }
            ManagedLocalProjectionFailureKind::Persistence => {
                ControlPlaneError::PersistenceError(self.message)
            }
        }
    }
}

fn shared_network_compensation(mutation: &SharedNetworkMutation) -> SharedNetworkMutation {
    match mutation {
        SharedNetworkMutation::Added {
            direction,
            cidr,
            group_id,
        } => SharedNetworkMutation::Deleted {
            direction,
            cidr: cidr.clone(),
            group_id: *group_id,
        },
        SharedNetworkMutation::Deleted {
            direction,
            cidr,
            group_id,
        } => SharedNetworkMutation::Added {
            direction,
            cidr: cidr.clone(),
            group_id: *group_id,
        },
        SharedNetworkMutation::Replaced {
            direction,
            cidr,
            old_group_id,
            new_group_id,
        } => SharedNetworkMutation::Replaced {
            direction,
            cidr: cidr.clone(),
            old_group_id: *new_group_id,
            new_group_id: *old_group_id,
        },
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
enum ManagedAclPublicationFailurePhase {
    General,
    Shadow,
    VerifyTc,
    SwitchBank,
    Persist,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum ManagedAclPublicationCompensation {
    RestoreActiveBank,
    RestoreGeneral(SharedNetworkMutation),
}

fn managed_acl_publication_compensations(
    mutations: &[SharedNetworkMutation],
    phase: ManagedAclPublicationFailurePhase,
) -> Vec<ManagedAclPublicationCompensation> {
    let mut compensations = Vec::new();
    if phase == ManagedAclPublicationFailurePhase::Persist {
        compensations.push(ManagedAclPublicationCompensation::RestoreActiveBank);
    }
    compensations.extend(mutations.iter().rev().map(|mutation| {
        ManagedAclPublicationCompensation::RestoreGeneral(shared_network_compensation(mutation))
    }));
    compensations
}

fn execute_managed_acl_publication_compensations<F>(
    compensations: &[ManagedAclPublicationCompensation],
    mut compensate: F,
) -> Result<(), String>
where
    F: FnMut(&ManagedAclPublicationCompensation) -> Result<(), String>,
{
    let mut errors = Vec::new();
    for compensation in compensations.iter() {
        if let Err(error) = compensate(compensation) {
            errors.push(error);
        }
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors.join("; "))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum ManagedAclPublicationDecision {
    Noop,
    Publish {
        selector_repair_performed: bool,
        repair_plan: Option<aria_core::ebpf_ops::ProjectionRepairPlan>,
        pre_mutation_health: ManagedProjectionHealth,
    },
}

fn managed_acl_publication_decision(
    drift: ProjectionDrift,
    semantic_changed: bool,
) -> Result<ManagedAclPublicationDecision, String> {
    match drift {
        ProjectionDrift::Clean if !semantic_changed => Ok(ManagedAclPublicationDecision::Noop),
        ProjectionDrift::Clean => Ok(ManagedAclPublicationDecision::Publish {
            selector_repair_performed: false,
            repair_plan: None,
            pre_mutation_health: ManagedProjectionHealth::Unverified,
        }),
        ProjectionDrift::RepairRequired(repair_plan) => {
            Ok(ManagedAclPublicationDecision::Publish {
                selector_repair_performed: true,
                repair_plan: Some(repair_plan),
                pre_mutation_health: ManagedProjectionHealth::Unverified,
            })
        }
        ProjectionDrift::Fatal(error) => Err(error),
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum ManagedAclPublicationStep {
    InvalidateProjectionHealth,
    ApplyGeneral(SharedNetworkMutation),
    StageShadow,
    VerifyTc,
    SwitchBank,
    Persist,
}

fn shared_network_mutation_from_projection(
    mutation: aria_core::ebpf_ops::ProjectionMutation,
) -> SharedNetworkMutation {
    use aria_core::ebpf_ops::{ProjectionDirection, ProjectionMutation};

    let direction = |direction| match direction {
        ProjectionDirection::Src => "src",
        ProjectionDirection::Dst => "dst",
    };
    match mutation {
        ProjectionMutation::Added {
            direction: projection_direction,
            entry,
        } => SharedNetworkMutation::Added {
            direction: direction(projection_direction),
            cidr: entry.network.to_string(),
            group_id: entry.group_id,
        },
        ProjectionMutation::Deleted {
            direction: projection_direction,
            entry,
        } => SharedNetworkMutation::Deleted {
            direction: direction(projection_direction),
            cidr: entry.network.to_string(),
            group_id: entry.group_id,
        },
        ProjectionMutation::Replaced {
            direction: projection_direction,
            network,
            old_group_id,
            new_group_id,
        } => SharedNetworkMutation::Replaced {
            direction: direction(projection_direction),
            cidr: network.to_string(),
            old_group_id,
            new_group_id,
        },
    }
}

fn managed_acl_publication_steps(
    decision: &ManagedAclPublicationDecision,
    clean_semantic_mutations: Vec<SharedNetworkMutation>,
) -> Vec<ManagedAclPublicationStep> {
    let repair_plan = match decision {
        ManagedAclPublicationDecision::Noop => return Vec::new(),
        ManagedAclPublicationDecision::Publish { repair_plan, .. } => repair_plan,
    };

    let general_mutations = repair_plan
        .as_ref()
        .map_or(clean_semantic_mutations, |plan| {
            plan.general_mutations
                .iter()
                .cloned()
                .map(shared_network_mutation_from_projection)
                .collect()
        });
    let mut steps = vec![ManagedAclPublicationStep::InvalidateProjectionHealth];
    steps.extend(
        general_mutations
            .into_iter()
            .map(ManagedAclPublicationStep::ApplyGeneral),
    );
    steps.push(ManagedAclPublicationStep::StageShadow);
    steps.push(ManagedAclPublicationStep::VerifyTc);
    steps.push(ManagedAclPublicationStep::SwitchBank);
    steps.push(ManagedAclPublicationStep::Persist);
    steps
}

fn managed_general_projection_mutations(
    committed: &aria_core::ebpf_ops::ManagedGroupProjection,
    proposed: &aria_core::ebpf_ops::ManagedGroupProjection,
) -> Vec<SharedNetworkMutation> {
    use aria_core::ebpf_ops::CanonicalNetwork;

    let committed: BTreeMap<CanonicalNetwork, u32> = committed
        .general
        .iter()
        .map(|entry| (entry.network, entry.group_id))
        .collect();
    let proposed: BTreeMap<CanonicalNetwork, u32> = proposed
        .general
        .iter()
        .map(|entry| (entry.network, entry.group_id))
        .collect();
    let mut mutations = Vec::new();
    for direction in ["src", "dst"] {
        for (network, new_group_id) in &proposed {
            match committed.get(network) {
                Some(old_group_id) if old_group_id != new_group_id => {
                    mutations.push(SharedNetworkMutation::Replaced {
                        direction,
                        cidr: network.to_string(),
                        old_group_id: *old_group_id,
                        new_group_id: *new_group_id,
                    });
                }
                None => mutations.push(SharedNetworkMutation::Added {
                    direction,
                    cidr: network.to_string(),
                    group_id: *new_group_id,
                }),
                Some(_) => {}
            }
        }
        for (network, old_group_id) in &committed {
            if !proposed.contains_key(network) {
                mutations.push(SharedNetworkMutation::Deleted {
                    direction,
                    cidr: network.to_string(),
                    group_id: *old_group_id,
                });
            }
        }
    }
    mutations
}

fn managed_acl_shadow_network_plan(
    projection: &aria_core::ebpf_ops::ManagedGroupProjection,
) -> Vec<(&'static str, String, u32)> {
    let source_entries = projection
        .acl_src
        .iter()
        .map(|entry| ("src", entry.network.to_string(), entry.group_id));
    let destination_entries = projection
        .acl_dst
        .iter()
        .map(|entry| ("dst", entry.network.to_string(), entry.group_id));
    source_entries.chain(destination_entries).collect()
}

fn group_delete_rollback_restores_acl_bank(mode: ManagedAclPublicationMode) -> bool {
    mode != ManagedAclPublicationMode::ManagedAcl
}

#[cfg(test)]
fn execute_shared_network_rollback<F>(
    mutations: &[SharedNetworkMutation],
    mut rollback: F,
) -> Result<(), String>
where
    F: FnMut(&SharedNetworkMutation) -> Result<(), String>,
{
    let mut errors = Vec::new();
    for mutation in mutations.iter().rev() {
        if let Err(error) = rollback(mutation) {
            errors.push(error);
        }
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors.join("; "))
    }
}

fn apply_shared_network_mutation(
    mutation: &SharedNetworkMutation,
    runtime: TapMapRuntime<'_>,
    ebpf_path: &str,
) -> Result<(), String> {
    match mutation {
        SharedNetworkMutation::Added {
            direction,
            cidr,
            group_id,
        } => aria_core::ebpf_ops::add_network(direction, cidr, *group_id, runtime, ebpf_path),
        SharedNetworkMutation::Deleted {
            direction,
            cidr,
            group_id,
        } => aria_core::ebpf_ops::delete_network(direction, cidr, *group_id, runtime, ebpf_path),
        SharedNetworkMutation::Replaced {
            direction,
            cidr,
            new_group_id,
            ..
        } => aria_core::ebpf_ops::add_network(direction, cidr, *new_group_id, runtime, ebpf_path),
    }
}

fn managed_local_projection_admission(
    mode: ManagedAclPublicationMode,
    health: ManagedProjectionHealth,
) -> Result<(), ControlPlaneError> {
    match mode {
        ManagedAclPublicationMode::ManagedAcl => match health {
            ManagedProjectionHealth::Verified => Ok(()),
            ManagedProjectionHealth::Unverified => Err(ControlPlaneError::InstanceNotReady(
                "managed ACL projection is unverified".to_string(),
            )),
            ManagedProjectionHealth::RepairRequired => Err(ControlPlaneError::InstanceNotReady(
                "managed ACL projection requires repair".to_string(),
            )),
        },
        ManagedAclPublicationMode::StandaloneCompatibility
        | ManagedAclPublicationMode::NeutronAttachOwnedStandaloneAcl => Ok(()),
    }
}

fn validate_managed_group_mutation(
    state: &FirewallState,
    group_id: u32,
) -> Result<(), ControlPlaneError> {
    if state
        .rules
        .iter()
        .any(|rule| rule.src_group_id == group_id || rule.dst_group_id == group_id)
    {
        return Err(ControlPlaneError::GroupInUse(format!(
            "group ID {} is referenced by a managed ACL rule",
            group_id
        )));
    }
    Ok(())
}

fn managed_general_state_mutations(
    old_state: &FirewallState,
    final_state: &FirewallState,
) -> Result<Vec<SharedNetworkMutation>, ControlPlaneError> {
    let committed_projection =
        compile_managed_group_projection(old_state).map_err(ControlPlaneError::ValidationError)?;
    let proposed_projection = compile_managed_group_projection(final_state)
        .map_err(ControlPlaneError::ValidationError)?;
    Ok(managed_general_projection_mutations(
        &committed_projection,
        &proposed_projection,
    ))
}

fn managed_qos_direction_plans(
    direction: u8,
    mode: u8,
) -> Result<Vec<ManagedQosDirectionPlan>, ControlPlaneError> {
    ControlPlane::requested_directions(direction).map(|directions| {
        directions
            .into_iter()
            .map(|direction| ManagedQosDirectionPlan {
                direction,
                effective_mode: if direction == 0 && mode == 1 { 0 } else { mode },
            })
            .collect()
    })
}

fn requested_directions(direction: u8) -> Result<Vec<u8>, ControlPlaneError> {
    match direction {
        0 => Ok(vec![0]),
        1 => Ok(vec![1]),
        2 => Ok(vec![0, 1]),
        _ => Err(ControlPlaneError::ValidationError(format!(
            "Invalid direction '{}': must be ingress, egress, or both",
            direction
        ))),
    }
}

fn merge_managed_local_projection_operations(
    order: ManagedLocalProjectionOrder,
    general: Vec<SharedNetworkMutation>,
    domain: Vec<ManagedLocalDomainOperation>,
) -> Vec<ManagedLocalProjectionOperation> {
    let general = general
        .into_iter()
        .map(ManagedLocalProjectionOperation::General);
    let domain = domain
        .into_iter()
        .map(ManagedLocalProjectionOperation::Domain);
    match order {
        ManagedLocalProjectionOrder::GeneralThenDomain => general.chain(domain).collect(),
        ManagedLocalProjectionOrder::DomainThenGeneral => domain.chain(general).collect(),
    }
}

fn reconcile_retained_owned_groups(
    old_state: &FirewallState,
    final_state: &mut FirewallState,
    owner_prefix: &str,
) -> Result<Vec<u32>, ControlPlaneError> {
    let mut removed_group_ids = Vec::new();
    let has_acl_reference = |state: &FirewallState, group_id: u32| {
        state
            .rules
            .iter()
            .any(|rule| rule.src_group_id == group_id || rule.dst_group_id == group_id)
    };
    let has_explicit_general_reference = |state: &FirewallState, group_id: u32| {
        state.qos_rules.iter().any(|rule| rule.group_id == group_id)
            || state
                .mirror_rules
                .iter()
                .any(|rule| rule.src_group_id == group_id || rule.dst_group_id == group_id)
    };

    for old_group in old_state
        .groups
        .values()
        .filter(|group| group.name.starts_with(owner_prefix))
    {
        let final_acl_reference = has_acl_reference(final_state, old_group.id);
        let final_explicit_reference = has_explicit_general_reference(final_state, old_group.id);
        if final_acl_reference || final_explicit_reference {
            final_state
                .groups
                .entry(old_group.name.clone())
                .or_insert_with(|| old_group.clone());
            continue;
        }

        let was_retained_only = !has_acl_reference(old_state, old_group.id)
            && has_explicit_general_reference(old_state, old_group.id);
        if was_retained_only && final_state.groups.remove(&old_group.name).is_some() {
            removed_group_ids.push(old_group.id);
        }
    }
    Ok(removed_group_ids)
}

fn clear_removed_retained_owned_group_stats(removed_group_ids: &[u32], runtime: TapMapRuntime<'_>) {
    for group_id in removed_group_ids {
        if let Err(error) = aria_core::monitoring::clear_group_stats_for_id(runtime, *group_id) {
            warn!(
                error = %error,
                group_id,
                "failed to clear retained-owned group stats after final reference removal"
            );
        }
    }
}

fn plan_managed_local_qos_upserts(
    old_state: &FirewallState,
    group_name: &str,
    group_id: u32,
    rate_bps: u64,
    burst_bytes: u64,
    priority: u8,
    direction_plans: &[ManagedQosDirectionPlan],
) -> Result<Vec<ManagedLocalDomainOperation>, ControlPlaneError> {
    let mut operations = Vec::new();
    if direction_plans.iter().any(|plan| plan.effective_mode == 1) {
        operations.push(ManagedLocalDomainOperation::EnsureFqQdisc {
            cleanup_on_rollback: !old_state.qos_rules.iter().any(|rule| rule.mode == 1),
        });
    }
    operations.extend(direction_plans.iter().map(|plan| {
        ManagedLocalDomainOperation::QosUpsert(QosRuleInfo {
            group_name: group_name.to_string(),
            group_id,
            direction: plan.direction,
            rate_bps,
            burst_bytes,
            priority,
            mode: plan.effective_mode,
        })
    }));
    Ok(operations)
}

fn plan_managed_local_qos_delete(
    old_state: &FirewallState,
    group_id: u32,
    directions: &[u8],
) -> Result<Vec<ManagedLocalDomainOperation>, ControlPlaneError> {
    let operations = directions
        .iter()
        .filter(|direction| {
            old_state
                .qos_rules
                .iter()
                .any(|rule| rule.group_id == group_id && rule.direction == **direction)
        })
        .map(|direction| ManagedLocalDomainOperation::QosDelete {
            group_id,
            direction: *direction,
        })
        .collect::<Vec<_>>();
    if operations.is_empty() {
        return Err(ControlPlaneError::PolicyNotFound(format!(
            "QoS rule not found for group ID {}",
            group_id
        )));
    }
    Ok(operations)
}

fn resolve_managed_mirror_target_ifindex(target_iface: &str) -> Result<u32, ControlPlaneError> {
    aria_core::mirror_ops::resolve_ifindex(target_iface).map_err(ControlPlaneError::ValidationError)
}

fn plan_managed_local_mirror_upserts(
    old_state: &FirewallState,
    src_group_name: &str,
    src_group_id: u32,
    dst_group_name: &str,
    dst_group_id: u32,
    proto: u8,
    target_iface: &str,
    target_ifindex: u32,
    directions: &[u8],
) -> Result<Vec<ManagedLocalDomainOperation>, ControlPlaneError> {
    let _ = old_state;
    let is_global = src_group_id == 0 && dst_group_id == 0 && proto == 0;
    Ok(directions
        .iter()
        .map(|direction| {
            ManagedLocalDomainOperation::MirrorUpsert(MirrorRuleInfo {
                src_group_name: src_group_name.to_string(),
                src_group_id,
                dst_group_name: dst_group_name.to_string(),
                dst_group_id,
                proto,
                direction: *direction,
                target_iface: target_iface.to_string(),
                target_ifindex,
                is_global,
            })
        })
        .collect())
}

fn plan_managed_local_mirror_delete(
    old_state: &FirewallState,
    src_group_id: u32,
    dst_group_id: u32,
    proto: u8,
    directions: &[u8],
) -> Result<Vec<ManagedLocalDomainOperation>, ControlPlaneError> {
    let is_global = src_group_id == 0 && dst_group_id == 0 && proto == 0;
    let operations = directions
        .iter()
        .filter(|direction| {
            old_state.mirror_rules.iter().any(|rule| {
                rule.direction == **direction
                    && if is_global {
                        rule.is_global
                    } else {
                        !rule.is_global
                            && rule.src_group_id == src_group_id
                            && rule.dst_group_id == dst_group_id
                            && rule.proto == proto
                    }
            })
        })
        .map(|direction| ManagedLocalDomainOperation::MirrorDelete {
            src_group_id,
            dst_group_id,
            proto,
            direction: *direction,
            is_global,
        })
        .collect::<Vec<_>>();
    if operations.is_empty() {
        return Err(ControlPlaneError::PolicyNotFound(
            "Mirror rule not found".to_string(),
        ));
    }
    Ok(operations)
}

fn clear_managed_mirror_stats_after_delete(
    instance: &str,
    src_group_id: u32,
    dst_group_id: u32,
    proto: u8,
    is_global: bool,
    directions: &[u8],
    runtime: TapMapRuntime<'_>,
) {
    for direction in directions {
        let clear_result = if is_global {
            aria_core::mirror_ops::clear_global_mirror_stats(*direction, runtime)
        } else {
            aria_core::mirror_ops::clear_mirror_rule_stats(
                src_group_id,
                dst_group_id,
                proto,
                *direction,
                runtime,
            )
        };
        if let Err(error) = clear_result {
            warn!(
                instance,
                src_group_id,
                dst_group_id,
                proto,
                direction,
                is_global,
                error = %error,
                "failed to clear mirror stats after delete"
            );
        }
    }
}

fn managed_local_state_after_domain_operations(
    old_state: &FirewallState,
    operations: &[ManagedLocalDomainOperation],
) -> Result<FirewallState, ControlPlaneError> {
    let mut final_state = old_state.clone();
    for operation in operations {
        match operation {
            ManagedLocalDomainOperation::EnsureFqQdisc { .. }
            | ManagedLocalDomainOperation::CleanupOwnedFqQdisc => {}
            ManagedLocalDomainOperation::QosUpsert(rule) => {
                final_state.qos_rules.retain(|existing| {
                    existing.group_id != rule.group_id || existing.direction != rule.direction
                });
                final_state.qos_rules.push(rule.clone());
            }
            ManagedLocalDomainOperation::QosDelete {
                group_id,
                direction,
            } => final_state.qos_rules.retain(|existing| {
                existing.group_id != *group_id || existing.direction != *direction
            }),
            ManagedLocalDomainOperation::MirrorUpsert(rule) => {
                if rule.is_global {
                    final_state.mirror_rules.retain(|existing| {
                        !(existing.is_global && existing.direction == rule.direction)
                    });
                } else {
                    final_state.mirror_rules.retain(|existing| {
                        existing.is_global
                            || existing.src_group_id != rule.src_group_id
                            || existing.dst_group_id != rule.dst_group_id
                            || existing.proto != rule.proto
                            || existing.direction != rule.direction
                    });
                }
                final_state.mirror_rules.push(rule.clone());
            }
            ManagedLocalDomainOperation::MirrorDelete {
                src_group_id,
                dst_group_id,
                proto,
                direction,
                is_global,
            } => final_state.mirror_rules.retain(|existing| {
                if *is_global {
                    !(existing.is_global && existing.direction == *direction)
                } else {
                    existing.is_global
                        || existing.src_group_id != *src_group_id
                        || existing.dst_group_id != *dst_group_id
                        || existing.proto != *proto
                        || existing.direction != *direction
                }
            }),
        }
    }
    Ok(final_state)
}

fn managed_local_fq_qdisc_apply_receipt(
    state: FqQdiscState,
    cleanup_on_rollback: bool,
) -> ManagedLocalDomainReceipt {
    let cleanup_on_rollback = cleanup_on_rollback && matches!(state, FqQdiscState::InstalledNow);
    ManagedLocalDomainReceipt::FqQdisc {
        state,
        cleanup_on_rollback,
    }
}

fn build_managed_local_domain_receipt(
    operation: &ManagedLocalDomainOperation,
    old_state: &FirewallState,
) -> Result<ManagedLocalDomainReceipt, String> {
    match operation {
        ManagedLocalDomainOperation::QosUpsert(rule) => {
            let previous_qos_rule = old_state
                .qos_rules
                .iter()
                .find(|existing| {
                    existing.group_id == rule.group_id && existing.direction == rule.direction
                })
                .cloned();
            Ok(ManagedLocalDomainReceipt::QosUpsert {
                applied: rule.clone(),
                previous: previous_qos_rule,
            })
        }
        ManagedLocalDomainOperation::QosDelete {
            group_id,
            direction,
        } => old_state
            .qos_rules
            .iter()
            .find(|rule| rule.group_id == *group_id && rule.direction == *direction)
            .cloned()
            .map(|deleted| ManagedLocalDomainReceipt::QosDelete { deleted })
            .ok_or_else(|| {
                format!(
                    "missing QoS preimage for group ID {} direction {}",
                    group_id, direction
                )
            }),
        ManagedLocalDomainOperation::MirrorUpsert(rule) => {
            let previous_rule_with_target_ifindex = old_state
                .mirror_rules
                .iter()
                .find(|existing| {
                    if rule.is_global {
                        existing.is_global && existing.direction == rule.direction
                    } else {
                        !existing.is_global
                            && existing.src_group_id == rule.src_group_id
                            && existing.dst_group_id == rule.dst_group_id
                            && existing.proto == rule.proto
                            && existing.direction == rule.direction
                    }
                })
                .cloned();
            Ok(ManagedLocalDomainReceipt::MirrorUpsert {
                applied: rule.clone(),
                previous: previous_rule_with_target_ifindex,
            })
        }
        ManagedLocalDomainOperation::MirrorDelete {
            src_group_id,
            dst_group_id,
            proto,
            direction,
            is_global,
        } => old_state
            .mirror_rules
            .iter()
            .find(|rule| {
                if *is_global {
                    rule.is_global && rule.direction == *direction
                } else {
                    !rule.is_global
                        && rule.src_group_id == *src_group_id
                        && rule.dst_group_id == *dst_group_id
                        && rule.proto == *proto
                        && rule.direction == *direction
                }
            })
            .cloned()
            .map(|deleted| ManagedLocalDomainReceipt::MirrorDelete { deleted })
            .ok_or_else(|| "missing Mirror preimage for managed delete".to_string()),
        ManagedLocalDomainOperation::EnsureFqQdisc { .. }
        | ManagedLocalDomainOperation::CleanupOwnedFqQdisc => {
            Err("FQ qdisc operations do not use QoS/Mirror preimage receipts".to_string())
        }
    }
}

fn apply_managed_local_domain_raw(
    operation: &ManagedLocalDomainOperation,
    runtime: &ManagedLocalProjectionRuntime,
) -> Result<(), String> {
    match operation {
        ManagedLocalDomainOperation::QosUpsert(rule) => aria_core::qos_ops::add_qos_rule(
            rule.group_id,
            rule.direction,
            rule.rate_bps,
            rule.burst_bytes,
            rule.priority,
            rule.mode,
            runtime.map_runtime(),
            runtime.qos_enabled,
        ),
        ManagedLocalDomainOperation::QosDelete {
            group_id,
            direction,
        } => aria_core::qos_ops::delete_qos_rule(
            *group_id,
            *direction,
            runtime.map_runtime(),
            runtime.qos_enabled,
        ),
        ManagedLocalDomainOperation::MirrorUpsert(rule) => {
            if rule.is_global {
                aria_core::mirror_ops::add_global_mirror(
                    rule.direction,
                    rule.target_ifindex,
                    runtime.map_runtime(),
                    runtime.mirror_enabled,
                )
            } else {
                aria_core::mirror_ops::add_mirror_rule(
                    rule.src_group_id,
                    rule.dst_group_id,
                    rule.proto,
                    rule.direction,
                    rule.target_ifindex,
                    runtime.map_runtime(),
                    runtime.mirror_enabled,
                )
            }
        }
        ManagedLocalDomainOperation::MirrorDelete {
            src_group_id,
            dst_group_id,
            proto,
            direction,
            is_global,
        } => {
            if *is_global {
                aria_core::mirror_ops::delete_global_mirror(
                    *direction,
                    runtime.map_runtime(),
                    runtime.mirror_enabled,
                )
            } else {
                aria_core::mirror_ops::delete_mirror_rule(
                    *src_group_id,
                    *dst_group_id,
                    *proto,
                    *direction,
                    runtime.map_runtime(),
                    runtime.mirror_enabled,
                )
            }
        }
        ManagedLocalDomainOperation::CleanupOwnedFqQdisc => {
            let iface = runtime.iface()?;
            aria_core::ebpf_ops::cleanup_root_qdisc(&iface)?;
            let marker_path = ControlPlane::fq_qdisc_marker_path(&runtime.state_path);
            match fs::remove_file(&marker_path) {
                Ok(()) => Ok(()),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
                Err(error) => Err(format!(
                    "failed to remove FQ qdisc ownership marker {}: {}",
                    marker_path.display(),
                    error
                )),
            }
        }
        ManagedLocalDomainOperation::EnsureFqQdisc { .. } => {
            Err("FQ qdisc ensure must use its ownership-aware apply path".to_string())
        }
    }
}

fn domain_apply_failure(apply_error: String, compensation_error: Option<String>) -> String {
    match compensation_error {
        Some(compensation_error) => format!(
            "{}; current-operation compensation failed: {}",
            apply_error, compensation_error
        ),
        None => apply_error,
    }
}

fn mark_owned_fq_qdisc(state_path: &str, iface: &str) -> Result<(), ControlPlaneError> {
    ControlPlane::mark_owned_fq_qdisc(state_path, iface)
}

fn rollback_installed_fq_qdisc(
    instance: &str,
    iface: &str,
    state_path: &str,
) -> Result<(), String> {
    ControlPlane::rollback_installed_fq_qdisc(instance, iface, state_path)
}

async fn apply_managed_local_projection_operation_transactionally<
    O,
    R,
    RawApply,
    RawApplyFuture,
    Compensate,
    CompensateFuture,
>(
    operation: &O,
    receipt: R,
    mut raw_apply: RawApply,
    mut compensate: Compensate,
) -> Result<R, String>
where
    RawApply: FnMut(&O) -> RawApplyFuture,
    RawApplyFuture: Future<Output = Result<(), String>>,
    Compensate: FnMut(&R) -> CompensateFuture,
    CompensateFuture: Future<Output = Result<(), String>>,
{
    match raw_apply(operation).await {
        Ok(()) => Ok(receipt),
        Err(apply_error) => {
            let compensation_error = compensate(&receipt).await.err();
            Err(domain_apply_failure(apply_error, compensation_error))
        }
    }
}

fn managed_local_domain_compensation_operations(
    receipt: &ManagedLocalDomainReceipt,
) -> Vec<ManagedLocalDomainOperation> {
    match receipt {
        ManagedLocalDomainReceipt::FqQdisc {
            state: FqQdiscState::InstalledNow,
            cleanup_on_rollback: true,
        } => vec![ManagedLocalDomainOperation::CleanupOwnedFqQdisc],
        ManagedLocalDomainReceipt::FqQdisc {
            state: FqQdiscState::InstalledNow,
            cleanup_on_rollback: false,
        }
        | ManagedLocalDomainReceipt::FqQdisc {
            state: FqQdiscState::AlreadyPresent,
            cleanup_on_rollback: _,
        } => Vec::new(),
        ManagedLocalDomainReceipt::QosUpsert { applied, previous } => previous
            .clone()
            .map(ManagedLocalDomainOperation::QosUpsert)
            .into_iter()
            .chain(
                previous
                    .is_none()
                    .then(|| ManagedLocalDomainOperation::QosDelete {
                        group_id: applied.group_id,
                        direction: applied.direction,
                    }),
            )
            .collect(),
        ManagedLocalDomainReceipt::QosDelete { deleted } => {
            vec![ManagedLocalDomainOperation::QosUpsert(deleted.clone())]
        }
        ManagedLocalDomainReceipt::MirrorUpsert { applied, previous } => {
            let _target_ifindex = applied.target_ifindex;
            previous
                .clone()
                .map(ManagedLocalDomainOperation::MirrorUpsert)
                .into_iter()
                .chain(
                    previous
                        .is_none()
                        .then(|| ManagedLocalDomainOperation::MirrorDelete {
                            src_group_id: applied.src_group_id,
                            dst_group_id: applied.dst_group_id,
                            proto: applied.proto,
                            direction: applied.direction,
                            is_global: applied.is_global,
                        }),
                )
                .collect()
        }
        ManagedLocalDomainReceipt::MirrorDelete { deleted } => {
            vec![ManagedLocalDomainOperation::MirrorUpsert(deleted.clone())]
        }
    }
}

fn compensate_managed_local_domain_receipt(
    receipt: &ManagedLocalDomainReceipt,
    runtime: &ManagedLocalProjectionRuntime,
) -> Result<(), String> {
    let mut errors = Vec::new();
    for operation in managed_local_domain_compensation_operations(receipt) {
        if let Err(error) = apply_managed_local_domain_raw(&operation, runtime) {
            errors.push(error);
        }
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors.join("; "))
    }
}

async fn apply_managed_local_domain_operation(
    operation: &ManagedLocalDomainOperation,
    runtime: &ManagedLocalProjectionRuntime,
    old_state: &FirewallState,
) -> Result<ManagedLocalDomainReceipt, String> {
    if let ManagedLocalDomainOperation::EnsureFqQdisc {
        cleanup_on_rollback,
    } = operation
    {
        let iface = runtime.iface()?;
        let state = ensure_fq_qdisc(&iface)?;
        if matches!(state, FqQdiscState::InstalledNow) {
            if let Err(marker_error) = mark_owned_fq_qdisc(&runtime.state_path, &iface) {
                let marker_error = marker_error.to_string();
                let rollback_error =
                    rollback_installed_fq_qdisc(&runtime.instance, &iface, &runtime.state_path)
                        .err();
                let marker_error = domain_apply_failure(marker_error, rollback_error);
                return Err(marker_error);
            }
        }
        return Ok(managed_local_fq_qdisc_apply_receipt(
            state,
            *cleanup_on_rollback,
        ));
    }

    let receipt: ManagedLocalDomainReceipt =
        build_managed_local_domain_receipt(operation, old_state)?;
    apply_managed_local_projection_operation_transactionally(
        operation,
        receipt,
        |operation| std::future::ready(apply_managed_local_domain_raw(operation, runtime)),
        |receipt| std::future::ready(compensate_managed_local_domain_receipt(receipt, runtime)),
    )
    .await
}

fn managed_local_projection_apply(
    runtime: ManagedLocalProjectionRuntime,
    old_state: &FirewallState,
) -> impl FnMut(
    &ManagedLocalProjectionOperation,
) -> ManagedLocalFuture<Result<ManagedLocalProjectionReceipt, String>> {
    let old_state = Arc::new(old_state.clone());
    move |operation| {
        let operation = operation.clone();
        let runtime = runtime.clone();
        let old_state = Arc::clone(&old_state);
        Box::pin(async move {
            match operation {
                ManagedLocalProjectionOperation::General(mutation) => {
                    apply_shared_network_mutation(
                        &mutation,
                        runtime.map_runtime(),
                        &runtime.ebpf_path,
                    )?;
                    Ok(ManagedLocalProjectionReceipt::General(mutation))
                }
                ManagedLocalProjectionOperation::Domain(operation) => {
                    let receipt =
                        apply_managed_local_domain_operation(&operation, &runtime, &old_state)
                            .await?;
                    Ok(ManagedLocalProjectionReceipt::Domain(receipt))
                }
            }
        })
    }
}

fn managed_local_projection_compensate(
    runtime: ManagedLocalProjectionRuntime,
) -> impl FnMut(&ManagedLocalProjectionReceipt) -> ManagedLocalFuture<Result<(), String>> {
    move |receipt| {
        let receipt = receipt.clone();
        let runtime = runtime.clone();
        Box::pin(async move {
            match receipt {
                ManagedLocalProjectionReceipt::General(mutation) => apply_shared_network_mutation(
                    &shared_network_compensation(&mutation),
                    runtime.map_runtime(),
                    &runtime.ebpf_path,
                ),
                ManagedLocalProjectionReceipt::Domain(receipt) => {
                    compensate_managed_local_domain_receipt(&receipt, &runtime)
                }
            }
        })
    }
}

fn managed_local_projection_persist(
    wal: &WalClient,
    final_state: &FirewallState,
) -> Result<impl FnMut() -> ManagedLocalFuture<Result<(), String>>, ControlPlaneError> {
    let wal = wal.clone();
    let snapshot = serde_json::to_string_pretty(final_state).map_err(|error| {
        ControlPlaneError::PersistenceError(format!(
            "failed to serialize managed local final state: {}",
            error
        ))
    })?;
    Ok(move || -> ManagedLocalFuture<Result<(), String>> {
        let wal = wal.clone();
        let snapshot = snapshot.clone();
        Box::pin(async move { wal.compact(snapshot).await })
    })
}

fn managed_local_projection_restore(
    wal: &WalClient,
    old_state: &FirewallState,
) -> Result<impl FnMut() -> ManagedLocalFuture<Result<(), String>>, ControlPlaneError> {
    let wal = wal.clone();
    let snapshot = serde_json::to_string_pretty(old_state).map_err(|error| {
        ControlPlaneError::PersistenceError(format!(
            "failed to serialize managed local rollback state: {}",
            error
        ))
    })?;
    Ok(move || -> ManagedLocalFuture<Result<(), String>> {
        let wal = wal.clone();
        let snapshot = snapshot.clone();
        Box::pin(async move { wal.compact(snapshot).await })
    })
}

async fn execute_managed_local_projection_compensations<R, Compensate, CompensateFuture>(
    applied: &[R],
    mut compensate: Compensate,
) -> Vec<String>
where
    Compensate: FnMut(&R) -> CompensateFuture,
    CompensateFuture: Future<Output = Result<(), String>>,
{
    let mut compensation_errors = Vec::new();
    for receipt in applied.iter().rev() {
        if let Err(error) = compensate(receipt).await {
            compensation_errors.push(error);
        }
    }
    compensation_errors
}

fn transaction_failure(
    kind: ManagedLocalProjectionFailureKind,
    error: String,
    compensation_errors: Vec<String>,
    restore_error: Option<String>,
) -> ManagedLocalProjectionFailure {
    let mut errors = vec![error];
    errors.extend(compensation_errors);
    if let Some(restore_error) = restore_error {
        errors.push(restore_error);
    }
    ManagedLocalProjectionFailure {
        kind,
        message: errors.join("; "),
    }
}

async fn execute_managed_local_projection_transaction<
    O,
    R,
    SetHealth,
    Apply,
    ApplyFuture,
    Persist,
    PersistFuture,
    Compensate,
    CompensateFuture,
    RestoreDurable,
    RestoreDurableFuture,
>(
    operations: &[O],
    mut set_health: SetHealth,
    mut apply: Apply,
    mut persist: Persist,
    mut compensate: Compensate,
    mut restore_durable: RestoreDurable,
) -> Result<(), ManagedLocalProjectionFailure>
where
    SetHealth: FnMut(ManagedProjectionHealth),
    Apply: FnMut(&O) -> ApplyFuture,
    ApplyFuture: Future<Output = Result<R, String>>,
    Persist: FnMut() -> PersistFuture,
    PersistFuture: Future<Output = Result<(), String>>,
    Compensate: FnMut(&R) -> CompensateFuture,
    CompensateFuture: Future<Output = Result<(), String>>,
    RestoreDurable: FnMut() -> RestoreDurableFuture,
    RestoreDurableFuture: Future<Output = Result<(), String>>,
{
    set_health(ManagedProjectionHealth::Unverified);
    let mut applied = Vec::new();
    for operation in operations {
        match apply(operation).await {
            Ok(receipt) => applied.push(receipt),
            Err(error) => {
                let compensation_errors =
                    execute_managed_local_projection_compensations(&applied, &mut compensate).await;
                return Err(transaction_failure(
                    ManagedLocalProjectionFailureKind::Kernel,
                    error,
                    compensation_errors,
                    None,
                ));
            }
        }
    }
    if let Err(error) = persist().await {
        let compensation_errors =
            execute_managed_local_projection_compensations(&applied, &mut compensate).await;
        let restore_error = restore_durable().await.err();
        return Err(transaction_failure(
            ManagedLocalProjectionFailureKind::Persistence,
            error,
            compensation_errors,
            restore_error,
        ));
    }
    Ok(())
}

fn apply_managed_acl_publication_compensation(
    compensation: &ManagedAclPublicationCompensation,
    runtime: TapMapRuntime<'_>,
    ebpf_path: &str,
    previous_active_bank: u8,
) -> Result<(), String> {
    match compensation {
        ManagedAclPublicationCompensation::RestoreActiveBank => {
            aria_core::ebpf_ops::set_acl_active_bank(runtime, previous_active_bank)
                .map_err(|error| format!("restore active ACL bank: {}", error))
        }
        ManagedAclPublicationCompensation::RestoreGeneral(mutation) => {
            apply_shared_network_mutation(mutation, runtime, ebpf_path)
                .map_err(|error| format!("restore shared selector {:?}: {}", mutation, error))
        }
    }
}

async fn rollback_owned_acl_prepublication(
    original: ControlPlaneError,
    mutations: &[SharedNetworkMutation],
    failure_phase: ManagedAclPublicationFailurePhase,
    created_port_sets: &[TransactionCreatedPortSet],
    runtime: TapMapRuntime<'_>,
    ebpf_path: &str,
    previous_active_bank: u8,
    shadow_bank: u8,
    state: &mut InstanceState,
    old_state: &FirewallState,
) -> ControlPlaneError {
    let mut rollback_errors = Vec::new();
    let compensations = managed_acl_publication_compensations(mutations, failure_phase);
    if let Err(error) =
        execute_managed_acl_publication_compensations(&compensations, |compensation| {
            apply_managed_acl_publication_compensation(
                compensation,
                runtime,
                ebpf_path,
                previous_active_bank,
            )
        })
    {
        rollback_errors.push(error);
    }
    if let Err(error) = aria_core::ebpf_ops::scrub_acl_bank(runtime, shadow_bank) {
        rollback_errors.push(format!("scrub shadow bank {}: {}", shadow_bank, error));
    }
    let cleanup = cleanup_transaction_created_port_sets(created_port_sets, runtime, ebpf_path);
    for failure in &cleanup.failures {
        rollback_errors.push(failure.error.clone());
    }
    if let Err(error) =
        restore_old_state_after_created_cleanup(state, old_state, created_port_sets, &cleanup).await
    {
        rollback_errors.push(error);
    }
    if rollback_errors.is_empty() {
        original
    } else {
        ControlPlaneError::KernelError(format!(
            "{}; owned ACL rollback failed: {}",
            original,
            rollback_errors.join("; ")
        ))
    }
}

fn prepare_system_publication_state(
    mut state: FirewallState,
    iface: &str,
    global_ssl_enabled: Option<bool>,
) -> FirewallState {
    state.tap_id = aria_core::common::TAP_ID_UNASSIGNED;
    state.attached_iface = Some(iface.to_string());
    if let Some(enabled) = global_ssl_enabled {
        state.ssl_enabled = enabled;
    }
    state
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NeutronPortAuthority {
    pub port_id: String,
    pub managed_domains: BTreeSet<String>,
    pub generation: u64,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum LocalWriteDomain {
    Acl,
    Qos,
    Mirror,
    Config,
    Conntrack,
    Tcprt,
    Trace,
    Drops,
    Ssl,
}

impl LocalWriteDomain {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Acl => "acl",
            Self::Qos => "qos",
            Self::Mirror => "mirror",
            Self::Config => "config",
            Self::Conntrack => "conntrack",
            Self::Tcprt => "tcprt",
            Self::Trace => "trace",
            Self::Drops => "drops",
            Self::Ssl => "ssl",
        }
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
enum SslSyncStatus {
    InSync,
    Repaired,
    Pending,
}

#[derive(Debug)]
pub enum ControlPlaneError {
    InstanceNotFound(String),
    GroupNotFound(String),
    PolicyNotFound(String),
    GroupInUse(String),
    ValidationError(String),
    KernelError(String),
    PersistenceError(String),
    InstanceNotReady(String),
    LocalWriteBlocked {
        instance: String,
        domain: String,
        dependency_of: Option<String>,
    },
}

impl std::fmt::Display for ControlPlaneError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InstanceNotFound(s) => write!(f, "Instance not found: {}", s),
            Self::GroupNotFound(s) => write!(f, "Group not found: {}", s),
            Self::PolicyNotFound(s) => write!(f, "Policy not found: {}", s),
            Self::GroupInUse(s) => write!(f, "Group in use: {}", s),
            Self::ValidationError(s) => write!(f, "Validation error: {}", s),
            Self::KernelError(s) => write!(f, "Kernel error: {}", s),
            Self::PersistenceError(s) => write!(f, "Persistence error: {}", s),
            Self::InstanceNotReady(s) => write!(f, "Instance not ready: {}", s),
            Self::LocalWriteBlocked {
                instance,
                domain,
                dependency_of: Some(dependency),
            } => write!(
                f,
                "LOCAL_WRITE_BLOCKED_FOR_NEUTRON_MANAGED_DOMAIN: instance '{}' domain '{}' is managed by Neutron as a dependency of '{}'; update this domain through Neutron",
                instance, domain, dependency
            ),
            Self::LocalWriteBlocked {
                instance,
                domain,
                dependency_of: None,
            } => write!(
                f,
                "LOCAL_WRITE_BLOCKED_FOR_NEUTRON_MANAGED_DOMAIN: instance '{}' domain '{}' is managed by Neutron; update this domain through Neutron",
                instance, domain
            ),
        }
    }
}

impl ControlPlaneError {
    pub fn status_code(&self) -> u16 {
        match self {
            Self::ValidationError(_) => 400,
            Self::InstanceNotFound(_) | Self::GroupNotFound(_) | Self::PolicyNotFound(_) => 404,
            Self::GroupInUse(_) | Self::LocalWriteBlocked { .. } => 409,
            Self::KernelError(_) => 500,
            Self::PersistenceError(_) | Self::InstanceNotReady(_) => 503,
        }
    }
}

impl ControlPlane {
    fn tc_acl_link_health_locked(
        instance: &str,
        state: &InstanceState,
        trace_map_mode: TraceMapMode,
    ) -> Result<TcAclLinkHealth, ControlPlaneError> {
        let iface = Self::runtime_iface_name(instance, state)?;
        Ok(FirewallInstance::new(
            &iface,
            state.pin_path.clone().into(),
            state.state_path.clone().into(),
            instance != "system",
            trace_map_mode,
        )
        .tc_acl_link_health())
    }

    fn runtime_iface_name(
        instance: &str,
        state: &InstanceState,
    ) -> Result<String, ControlPlaneError> {
        if instance == "system" {
            state.state.attached_iface.clone().ok_or_else(|| {
                ControlPlaneError::InstanceNotReady("system interface is not attached".to_string())
            })
        } else {
            Ok(instance.to_string())
        }
    }

    fn require_tc_acl_ready_locked(
        instance: &str,
        state: &InstanceState,
        trace_map_mode: TraceMapMode,
    ) -> Result<(), ControlPlaneError> {
        let health = Self::tc_acl_link_health_locked(instance, state, trace_map_mode)?;
        if health.acl_ready() {
            Ok(())
        } else {
            Err(ControlPlaneError::InstanceNotReady(format!(
                "missing live TCX ACL attachments: {}",
                health.missing_tc().join(", ")
            )))
        }
    }

    fn mark_tc_acl_runtime_ready_locked(
        instance: &str,
        state: &mut InstanceState,
        xdp_ready: bool,
        trace_map_mode: TraceMapMode,
    ) -> Result<(), ControlPlaneError> {
        let health = match Self::tc_acl_link_health_locked(instance, state, trace_map_mode) {
            Ok(health) => health,
            Err(error) => {
                state.runtime_health.acl_ready = false;
                state.runtime_health.xdp_ready = xdp_ready;
                state.runtime_health.acl_error = Some("recovery_required".to_string());
                return Err(error);
            }
        };
        if let Some(reason) = missing_tc_reason(health) {
            state.runtime_health.acl_ready = false;
            state.runtime_health.xdp_ready = xdp_ready;
            state.runtime_health.acl_error = Some(reason.to_string());
            return Err(ControlPlaneError::InstanceNotReady(format!(
                "missing live TCX ACL attachments: {}",
                health.missing_tc().join(", ")
            )));
        }
        state.runtime_health = RuntimeHealthState {
            acl_ready: true,
            xdp_ready,
            acl_error: None,
        };
        Ok(())
    }

    fn fq_qdisc_marker_path(state_path: &str) -> std::path::PathBuf {
        Path::new(state_path).join(FQ_QDISC_MARKER)
    }

    fn mark_owned_fq_qdisc(state_path: &str, iface: &str) -> Result<(), ControlPlaneError> {
        let marker_path = Self::fq_qdisc_marker_path(state_path);
        fs::write(&marker_path, b"owned\n").map_err(|e| {
            ControlPlaneError::KernelError(format!(
                "[{}] failed to persist FQ qdisc ownership marker {}: {}",
                iface,
                marker_path.display(),
                e
            ))
        })
    }

    fn rollback_installed_fq_qdisc(
        instance: &str,
        iface: &str,
        state_path: &str,
    ) -> Result<(), String> {
        aria_core::ebpf_ops::cleanup_root_qdisc(iface).map_err(|error| {
            format!(
                "[{}] failed to roll back FQ qdisc on {}: {}",
                instance, iface, error
            )
        })?;

        let marker_path = Self::fq_qdisc_marker_path(state_path);
        match fs::remove_file(&marker_path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(format!(
                "[{}] failed to remove FQ qdisc marker {} after rollback: {}",
                instance,
                marker_path.display(),
                error
            )),
        }
    }

    fn requested_directions(direction: u8) -> Result<Vec<u8>, ControlPlaneError> {
        requested_directions(direction)
    }

    fn owned_acl_group_name_by_id(state: &FirewallState, id: u32) -> String {
        if id == 0 {
            return "any".to_string();
        }
        state
            .groups
            .values()
            .find(|group| group.id == id)
            .map(|group| group.name.clone())
            .unwrap_or_else(|| format!("id:{}", id))
    }

    fn owned_acl_rule_matches_prefix(state: &FirewallState, rule: &RuleInfo, prefix: &str) -> bool {
        let src_group = Self::owned_acl_group_name_by_id(state, rule.src_group_id);
        let dst_group = Self::owned_acl_group_name_by_id(state, rule.dst_group_id);
        src_group.starts_with(prefix) || dst_group.starts_with(prefix)
    }

    fn owned_acl_rule_in_replace_scope(
        state: &FirewallState,
        rule: &RuleInfo,
        prefix: &str,
        exclusive_policy_domain: bool,
    ) -> bool {
        exclusive_policy_domain || Self::owned_acl_rule_matches_prefix(state, rule, prefix)
    }

    fn owned_acl_policy_key_from_rule(state: &FirewallState, rule: &RuleInfo) -> OwnedAclPolicyKey {
        OwnedAclPolicyKey {
            src_group: Self::owned_acl_group_name_by_id(state, rule.src_group_id),
            dst_group: Self::owned_acl_group_name_by_id(state, rule.dst_group_id),
            proto: rule.proto,
            direction: rule.direction,
        }
    }

    fn owned_acl_policy_value_from_rule(rule: &RuleInfo) -> OwnedAclPolicyValue {
        OwnedAclPolicyValue {
            action: rule.action,
            ports: rule.ports.clone(),
        }
    }

    fn owned_acl_policy_key_from_spec(policy: &OwnedAclPolicySpec) -> OwnedAclPolicyKey {
        OwnedAclPolicyKey {
            src_group: policy.src_group.clone(),
            dst_group: policy.dst_group.clone(),
            proto: policy.proto,
            direction: policy.direction,
        }
    }

    fn owned_acl_policy_value_from_spec(policy: &OwnedAclPolicySpec) -> OwnedAclPolicyValue {
        OwnedAclPolicyValue {
            action: policy.action,
            ports: policy.ports.clone(),
        }
    }

    fn stage_acl_shadow_bank(
        state: &FirewallState,
        projection: &aria_core::ebpf_ops::ManagedGroupProjection,
        runtime: TapMapRuntime<'_>,
        bank: u8,
        ebpf_path: &str,
        new_port_sets_by_key: &BTreeMap<OwnedAclPolicyKey, bool>,
    ) -> Result<(), ControlPlaneError> {
        aria_core::ebpf_ops::scrub_acl_bank(runtime, bank)
            .map_err(ControlPlaneError::KernelError)?;

        for (direction, cidr, group_id) in managed_acl_shadow_network_plan(projection) {
            aria_core::ebpf_ops::add_acl_network_in_bank(
                direction, &cidr, group_id, bank, runtime, ebpf_path,
            )
            .map_err(|error| {
                ControlPlaneError::KernelError(format!(
                    "stage shadow bank {} {} group {} cidr {}: {}",
                    bank, direction, group_id, cidr, error
                ))
            })?;
        }

        for rule in &state.rules {
            let key = Self::owned_acl_policy_key_from_rule(state, rule);
            let is_new_port_set = new_port_sets_by_key.get(&key).copied().unwrap_or(false);
            aria_core::ebpf_ops::add_policy_in_bank(
                rule.src_group_id,
                rule.dst_group_id,
                rule.proto,
                rule.action,
                rule.ports.as_deref(),
                rule.bitmap_idx,
                is_new_port_set,
                rule.direction,
                bank,
                runtime,
                ebpf_path,
            )
            .map_err(|e| {
                ControlPlaneError::KernelError(format!(
                    "stage shadow bank {} policy src={} dst={} proto={} direction={}: {}",
                    bank, rule.src_group_id, rule.dst_group_id, rule.proto, rule.direction, e
                ))
            })?;
        }

        Ok(())
    }

    fn owned_acl_validate_group_specs(
        owner_prefix: &str,
        groups: &[OwnedAclGroupSpec],
    ) -> Result<(), ControlPlaneError> {
        for group in groups {
            if !group.name.starts_with(owner_prefix) {
                return Err(ControlPlaneError::ValidationError(format!(
                    "owned ACL group '{}' is outside owner prefix '{}'",
                    group.name, owner_prefix
                )));
            }
            if group.cidrs.is_empty() {
                return Err(ControlPlaneError::ValidationError(format!(
                    "owned ACL group '{}' must contain at least one CIDR",
                    group.name
                )));
            }
        }
        Ok(())
    }

    fn owned_acl_validate_policy_specs(
        owner_prefix: &str,
        policies: &[OwnedAclPolicySpec],
    ) -> Result<(), ControlPlaneError> {
        for policy in policies {
            if policy.src_group != "any" && !policy.src_group.starts_with(owner_prefix) {
                return Err(ControlPlaneError::ValidationError(format!(
                    "owned ACL policy src_group '{}' is outside owner prefix '{}'",
                    policy.src_group, owner_prefix
                )));
            }
            if policy.dst_group != "any" && !policy.dst_group.starts_with(owner_prefix) {
                return Err(ControlPlaneError::ValidationError(format!(
                    "owned ACL policy dst_group '{}' is outside owner prefix '{}'",
                    policy.dst_group, owner_prefix
                )));
            }
            Self::validate_policy_ports(policy.proto, policy.ports.as_deref())?;
        }
        Ok(())
    }

    fn expected_runtime_flags(state: &FirewallState) -> (u8, u8, u8, u8, u8, u8, u8) {
        (
            state.conntrack_enabled as u8,
            state.monitoring_enabled as u8,
            state.acl_enabled as u8,
            (state.qos_enabled && !state.qos_rules.is_empty()) as u8,
            (state.mirror_enabled && !state.mirror_rules.is_empty()) as u8,
            state.tcprt_enabled as u8,
            state.ssl_enabled as u8,
        )
    }

    fn validate_policy_ports(proto: u8, ports: Option<&str>) -> Result<(), ControlPlaneError> {
        aria_core::ebpf_ops::validate_policy_ports(proto, ports)
            .map_err(ControlPlaneError::ValidationError)
    }

    fn validate_preexisting_live_runtime(
        &self,
        name: &str,
        pin_path: &str,
        state_path: &str,
        tap_id: u32,
        ifindex: u32,
        state: &FirewallState,
        pin_state: &RuntimePinState,
        projection_mode: GroupProjectionMode,
    ) -> PreexistingRuntimeValidation {
        let runtime_instance = FirewallInstance::new(
            name,
            pin_path.to_string().into(),
            state_path.to_string().into(),
            true,
            self.trace_map_mode(),
        );
        if let Err(error) = preexisting_tc_acl_runtime_is_healthy(
            state.conntrack_enabled || state.acl_enabled,
            pin_state.preexisting_live_links,
            pin_state.preexisting_tc_ingress_link,
            pin_state.preexisting_tc_egress_link,
            runtime_instance.tc_acl_link_health(),
        ) {
            return PreexistingRuntimeValidation::fatal(error);
        }

        let iface_ctx = match aria_core::ebpf_ops::read_iface_ctx(pin_path, ifindex) {
            Ok(iface_ctx) => iface_ctx,
            Err(error) => return PreexistingRuntimeValidation::fatal(error),
        };
        if iface_ctx.tap_id != tap_id {
            return PreexistingRuntimeValidation::fatal(format!(
                "preexisting live runtime mismatch for {}: IFACE_CTX_MAP ifindex {} points to tap_id {}, expected {}",
                name, ifindex, iface_ctx.tap_id, tap_id
            ));
        }

        let runtime = TapMapRuntime::new(pin_path, tap_id);
        let actual = match aria_core::ebpf_ops::read_runtime_config(runtime) {
            Ok(actual) => actual,
            Err(error) => return PreexistingRuntimeValidation::fatal(error),
        };
        let expected = Self::expected_runtime_flags(state);
        let actual_flags = (
            actual.conntrack_enabled,
            actual.monitoring_enabled,
            actual.acl_enabled,
            actual.qos_enabled,
            actual.mirror_enabled,
            actual.tcprt_enabled,
            actual.ssl_enabled,
        );

        let actual_non_gate = (
            actual.monitoring_enabled,
            actual.qos_enabled,
            actual.mirror_enabled,
            actual.tcprt_enabled,
            actual.ssl_enabled,
        );
        let expected_non_gate = (expected.1, expected.3, expected.4, expected.5, expected.6);
        if actual_non_gate != expected_non_gate {
            return PreexistingRuntimeValidation::fatal(format!(
                "preexisting live runtime mismatch for {}: actual flags {:?}, expected {:?}; detach and reattach to rebuild safely",
                name, actual_flags, expected
            ));
        }

        let gate_disposition = match classify_runtime_gate_state(
            projection_mode,
            actual.conntrack_enabled,
            actual.acl_enabled,
            expected.0,
            expected.2,
        ) {
            Ok(disposition) => disposition,
            Err(error) => {
                return PreexistingRuntimeValidation::fatal(format!(
                    "preexisting live runtime mismatch for {}: {}; actual flags {:?}, expected {:?}",
                    name, error, actual_flags, expected
                ));
            }
        };

        let projection_drift = match projection_mode {
            GroupProjectionMode::StandaloneCompatibility => {
                validate_pinned_runtime_state(runtime, state)
                    .map_or_else(ProjectionDrift::Fatal, |()| ProjectionDrift::Clean)
            }
            GroupProjectionMode::Managed => validate_managed_pinned_runtime_state(runtime, state),
        };
        PreexistingRuntimeValidation {
            projection_drift,
            gate_disposition: Some(gate_disposition),
        }
    }

    async fn cleanup_failed_managed_registration(
        name: &str,
        pin_path: &str,
        tap_id: u32,
        ifindex: u32,
        wal: WalClient,
        preserve_existing_runtime: bool,
        iface_ctx_synced: bool,
        tap_config_written: bool,
    ) {
        if !preserve_existing_runtime && iface_ctx_synced {
            if let Err(e) = aria_core::ebpf_ops::clear_iface_ctx(pin_path, ifindex) {
                warn!(instance = %name, tap_id, ifindex, error = %e, "failed to clear iface context after register failure");
            }
        }
        if !preserve_existing_runtime
            && tap_config_written
            && tap_id != aria_core::common::TAP_ID_UNASSIGNED
        {
            let runtime = TapMapRuntime::new(pin_path, tap_id);
            if let Err(e) = aria_core::ebpf_ops::delete_tap_config(runtime) {
                warn!(instance = %name, tap_id, error = %e, "failed to clear tap runtime config after register failure");
            }
        }
        if !preserve_existing_runtime && tap_id != aria_core::common::TAP_ID_UNASSIGNED {
            let runtime = TapMapRuntime::new(pin_path, tap_id);
            if let Err(e) = aria_core::ebpf_ops::scrub_managed_runtime_state(runtime) {
                warn!(instance = %name, tap_id, error = %e, "failed to scrub tap runtime state after register failure");
            }
        }
        wal.shutdown().await;
    }

    fn rollback_policy_deletes(
        runtime: TapMapRuntime<'_>,
        ebpf_path: &str,
        deleted_rules: &[RuleInfo],
    ) -> Result<(), String> {
        let bank = aria_core::ebpf_ops::read_acl_active_bank(runtime).unwrap_or(0);
        for rule in deleted_rules {
            aria_core::ebpf_ops::add_policy_in_bank(
                rule.src_group_id,
                rule.dst_group_id,
                rule.proto,
                rule.action,
                rule.ports.as_deref(),
                rule.bitmap_idx,
                false,
                rule.direction,
                bank,
                runtime,
                ebpf_path,
            )?;
        }
        Ok(())
    }

    fn rollback_group_deletes(
        runtime: TapMapRuntime<'_>,
        ebpf_path: &str,
        publication_mode: ManagedAclPublicationMode,
        group_id: u32,
        deleted_networks: &[(&'static str, String)],
    ) -> Result<(), String> {
        let restore_acl_bank = group_delete_rollback_restores_acl_bank(publication_mode);
        let bank = if restore_acl_bank {
            aria_core::ebpf_ops::read_acl_active_bank(runtime).unwrap_or(0)
        } else {
            0
        };
        for (direction, cidr) in deleted_networks.iter().rev() {
            aria_core::ebpf_ops::add_network(direction, cidr, group_id, runtime, ebpf_path)?;
            if restore_acl_bank {
                aria_core::ebpf_ops::add_acl_network_in_bank(
                    direction, cidr, group_id, bank, runtime, ebpf_path,
                )?;
            }
        }
        Ok(())
    }

    fn rollback_qos_deletes(
        runtime: TapMapRuntime<'_>,
        deleted_rules: &[QosRuleInfo],
        user_qos_enabled: bool,
    ) -> Result<(), String> {
        for rule in deleted_rules {
            aria_core::qos_ops::add_qos_rule(
                rule.group_id,
                rule.direction,
                rule.rate_bps,
                rule.burst_bytes,
                rule.priority,
                rule.mode,
                runtime,
                user_qos_enabled,
            )?;
        }
        Ok(())
    }

    fn rollback_mirror_deletes(
        runtime: TapMapRuntime<'_>,
        deleted_rules: &[MirrorRuleInfo],
        user_mirror_enabled: bool,
    ) -> Result<(), String> {
        for rule in deleted_rules {
            if rule.is_global {
                aria_core::mirror_ops::add_global_mirror(
                    rule.direction,
                    rule.target_ifindex,
                    runtime,
                    user_mirror_enabled,
                )?;
            } else {
                aria_core::mirror_ops::add_mirror_rule(
                    rule.src_group_id,
                    rule.dst_group_id,
                    rule.proto,
                    rule.direction,
                    rule.target_ifindex,
                    runtime,
                    user_mirror_enabled,
                )?;
            }
        }
        Ok(())
    }

    pub fn new(
        ebpf_path: &str,
        base_pin_path: &str,
        base_state_path: &str,
        ssl_manager: Arc<SslManager>,
        kernel_drop_manager: Arc<KernelDropManager>,
        trace_manager: Arc<TraceManager>,
    ) -> Self {
        let chains = service_chain::load_chains(base_state_path);
        Self {
            instances: RwLock::new(HashMap::new()),
            neutron_authorities: RwLock::new(HashMap::new()),
            tap_id_lock: Mutex::new(()),
            runtime_lifecycle_lock: Mutex::new(()),
            ebpf_path: ebpf_path.to_string(),
            base_pin_path: base_pin_path.to_string(),
            base_state_path: base_state_path.to_string(),
            ssl_manager,
            kernel_drop_manager,
            trace_manager,
            chains: RwLock::new(chains),
        }
    }

    pub fn managed_pin_path(&self) -> String {
        format!("{}/{}", self.base_pin_path, MANAGED_SHARED_PIN_NAMESPACE)
    }

    pub fn trace_map_mode(&self) -> TraceMapMode {
        self.trace_manager.map_mode()
    }

    pub(crate) async fn lock_runtime_lifecycle(&self) -> tokio::sync::MutexGuard<'_, ()> {
        self.runtime_lifecycle_lock.lock().await
    }

    pub(crate) async fn managed_projection_health(
        &self,
        instance: &str,
    ) -> Option<ManagedProjectionHealth> {
        let instance = {
            let instances = self.instances.read().await;
            instances.get(instance).cloned()
        }?;
        let state = instance.read().await;
        (state.managed_acl_publication_mode == ManagedAclPublicationMode::ManagedAcl)
            .then_some(state.managed_projection_health)
    }

    /// Promote ACL ownership while the caller holds the runtime lifecycle lock.
    ///
    /// This helper must not reacquire that lock. Registry callers additionally
    /// hold the per-interface lock, preserving iface -> lifecycle -> instance.
    pub(crate) async fn promote_managed_acl_ownership_serialized(
        &self,
        instance: &str,
        requested_mode: ManagedAttachMode,
    ) -> Result<(), String> {
        let instance_state = self
            .get_instance(instance)
            .await
            .map_err(|error| error.to_string())?;
        let mut state = instance_state.write().await;
        let action = managed_acl_promotion_action(
            state.managed_acl_publication_mode,
            state.managed_projection_health,
            requested_mode,
        );
        let ManagedAclPromotionAction::Promote {
            next_mode,
            next_health,
            quiesce_acl_ct,
        } = action
        else {
            return Ok(());
        };

        if quiesce_acl_ct {
            aria_core::ebpf_ops::update_acl_runtime_gate(
                state.map_runtime(),
                false,
                false,
                aria_core::common::ACL_INGRESS_HOOK_TC,
            )
            .map_err(|error| {
                format!(
                    "failed to quiesce ACL/CT while promoting managed ACL ownership for {}: {}",
                    instance, error
                )
            })?;
        }

        state.managed_acl_publication_mode = next_mode;
        state.managed_projection_health = next_health;
        info!(
            instance = %instance,
            publication_mode = ?next_mode,
            projection_health = ?next_health,
            quiesced = quiesce_acl_ct,
            "promoted managed ACL ownership"
        );
        Ok(())
    }

    pub fn trace_backend_name(&self) -> &'static str {
        self.trace_manager.backend().as_str()
    }

    fn normalize_domain_name(domain: &str) -> Option<String> {
        let normalized = domain.trim().to_ascii_lowercase().replace('-', "_");
        match normalized.as_str() {
            "" => None,
            "policy" | "policies" | "group" | "groups" | "address_set" | "address_sets"
            | "aria_acl" => Some("acl".to_string()),
            "aria_qos" => Some("qos".to_string()),
            "aria_mirror" => Some("mirror".to_string()),
            "acl" | "qos" | "mirror" | "config" | "conntrack" | "tcprt" | "trace" | "drops"
            | "ssl" => Some(normalized),
            _ => Some(normalized),
        }
    }

    pub fn normalize_neutron_managed_domains(domains: &[String]) -> BTreeSet<String> {
        domains
            .iter()
            .filter_map(|domain| Self::normalize_domain_name(domain))
            .collect()
    }

    pub async fn mark_neutron_port_authority(
        &self,
        instance: &str,
        port_id: &str,
        managed_domains: &[String],
        generation: u64,
    ) {
        let authority = NeutronPortAuthority {
            port_id: port_id.to_string(),
            managed_domains: Self::normalize_neutron_managed_domains(managed_domains),
            generation,
        };
        let mut authorities = self.neutron_authorities.write().await;
        authorities.insert(instance.to_string(), authority.clone());
        info!(
            instance = %instance,
            port_id = %authority.port_id,
            generation,
            managed_domains = ?authority.managed_domains,
            "marked Neutron port authority"
        );
    }

    pub(crate) async fn mark_neutron_port_authority_if_current(
        &self,
        instance: &str,
        port_id: &str,
        managed_domains: &[String],
        generation: u64,
        required_publication_mode: Option<ManagedAclPublicationMode>,
        required_projection_health: Option<ManagedProjectionHealth>,
    ) -> bool {
        let _lifecycle_guard = self.lock_runtime_lifecycle().await;
        let instance_state = {
            let instances = self.instances.read().await;
            instances.get(instance).cloned()
        };
        let (current_publication_mode, current_projection_health) = match &instance_state {
            Some(instance_state) => {
                let state = instance_state.read().await;
                (
                    Some(state.managed_acl_publication_mode),
                    (state.managed_acl_publication_mode == ManagedAclPublicationMode::ManagedAcl)
                        .then_some(state.managed_projection_health),
                )
            }
            None => (None, None),
        };
        if !managed_neutron_authority_confirmation_allowed(
            instance_state.is_some(),
            current_publication_mode,
            required_publication_mode,
            current_projection_health,
            required_projection_health,
        ) {
            return false;
        }

        self.mark_neutron_port_authority(instance, port_id, managed_domains, generation)
            .await;
        true
    }

    pub async fn clear_neutron_port_authority(&self, instance: &str) {
        let mut authorities = self.neutron_authorities.write().await;
        if let Some(authority) = authorities.remove(instance) {
            info!(
                instance = %instance,
                port_id = %authority.port_id,
                managed_domains = ?authority.managed_domains,
                "cleared Neutron port authority"
            );
        }
    }

    #[allow(dead_code)]
    pub async fn get_neutron_port_authority(&self, instance: &str) -> Option<NeutronPortAuthority> {
        self.neutron_authorities.read().await.get(instance).cloned()
    }

    pub async fn ensure_local_write_allowed(
        &self,
        instance: &str,
        domain: LocalWriteDomain,
    ) -> Result<(), ControlPlaneError> {
        let domain_name = domain.as_str();
        let authorities = self.neutron_authorities.read().await;
        let block = authorities.get(instance).and_then(|authority| {
            if authority.managed_domains.contains(domain_name) {
                Some(None)
            } else if domain == LocalWriteDomain::Conntrack
                && authority.managed_domains.contains("acl")
            {
                Some(Some("acl".to_string()))
            } else {
                None
            }
        });
        if let Some(dependency_of) = block {
            return Err(ControlPlaneError::LocalWriteBlocked {
                instance: instance.to_string(),
                domain: domain_name.to_string(),
                dependency_of,
            });
        }
        Ok(())
    }

    pub async fn ensure_local_group_write_allowed(
        &self,
        instance: &str,
        group_name: &str,
    ) -> Result<(), ControlPlaneError> {
        if group_name
            .trim()
            .to_ascii_lowercase()
            .starts_with("neutron:")
        {
            let authorities = self.neutron_authorities.read().await;
            if authorities.contains_key(instance) {
                return Err(ControlPlaneError::LocalWriteBlocked {
                    instance: instance.to_string(),
                    domain: "acl".to_string(),
                    dependency_of: None,
                });
            }
        }
        Ok(())
    }

    pub async fn get_trace_runtime_status(&self) -> HashMap<String, TraceRuntimeStatusSnapshot> {
        self.trace_manager.runtime_status().await
    }

    /// Prepare tap-scoped runtime state before any interface link goes live.
    pub async fn prepare_managed_registration(
        &self,
        name: &str,
        pin_state: &RuntimePinState,
        mode: ManagedAttachMode,
    ) -> Result<PreparedManagedInstance, String> {
        let pin_path = self.managed_pin_path();
        let state_path = format!("{}/{}", self.base_state_path, name);
        let projection_mode = managed_group_projection_mode(mode);
        let mut managed_acl_lifecycle = managed_acl_registration_lifecycle(mode, None, None)?;
        let ifindex = Self::resolve_ifindex(name)?;
        let global_ssl_enabled = match self.read_ssl_global_config().await {
            Ok(enabled) => Some(enabled),
            Err(e) => {
                warn!(instance = %name, error = %e, "failed to read global SSL config during register");
                None
            }
        };

        // If already registered, compact before replacing
        let replacing_existing = {
            let instances = self.instances.read().await;
            if let Some(existing) = instances.get(name) {
                let mut st = existing.write().await;
                st.do_compact().await;
                true
            } else {
                false
            }
        };

        let mut state = aria_core::wal::load_with_wal(&state_path);
        let tap_id_assigned = self.ensure_managed_tap_id(name, &mut state).await?;
        if tap_id_assigned {
            let state_manager = aria_core::state::StateManager::new(&state_path);
            state_manager
                .set_tap_id(state.tap_id)
                .map_err(|e| format!("failed to persist tap_id for {}: {}", name, e))?;
            info!(instance = %name, tap_id = state.tap_id, "prepared managed tap state");
        }
        let ssl_changed = global_ssl_enabled
            .map(|enabled| state.ssl_enabled != enabled)
            .unwrap_or(false);
        if let Some(enabled) = global_ssl_enabled {
            if ssl_changed {
                state.ssl_enabled = enabled;
            }
        }

        let wal = match WalClient::open(&state_path) {
            Ok(w) => w,
            Err(e) => {
                return Err(format!("failed to open WAL for {}: {}", name, e));
            }
        };

        // Compact on startup if WAL had replayed entries
        if wal.entry_count() > 0 || ssl_changed || tap_id_assigned {
            match serde_json::to_string_pretty(&state) {
                Ok(json) => {
                    if let Err(e) = wal.compact(json).await {
                        error!(instance = %name, error = %e, "failed to compact WAL on register");
                    }
                }
                Err(e) => {
                    error!(instance = %name, error = %e, "failed to serialize state on register");
                }
            }
        }

        let tap_id = state.tap_id;
        let mut preexisting_live_verified = false;
        let preserve_existing_runtime = replacing_existing || pin_state.preexisting_live_links;
        let mut iface_ctx_synced = false;
        let mut tap_config_written = false;

        if pin_state.preexisting_live_links {
            let preexisting_validation = self.validate_preexisting_live_runtime(
                name,
                &pin_path,
                &state_path,
                tap_id,
                ifindex,
                &state,
                pin_state,
                projection_mode,
            );
            let gate_disposition = preexisting_validation.gate_disposition;
            let projection_drift = preexisting_validation.projection_drift;
            let lifecycle_projection_drift = projection_drift.clone();
            preexisting_live_verified = match preexisting_projection_verification(projection_drift)
            {
                Ok(projection_verified) => {
                    projection_verified && gate_disposition == Some(RuntimeGateDisposition::Desired)
                }
                Err(e) => {
                    let quiesce_error = aria_core::ebpf_ops::update_acl_runtime_gate(
                        TapMapRuntime::new(&pin_path, tap_id),
                        false,
                        false,
                        aria_core::common::ACL_INGRESS_HOOK_TC,
                    )
                    .err();
                    wal.shutdown().await;
                    return Err(match quiesce_error {
                        Some(quiesce_error) => format!(
                            "preexisting live runtime mismatch for {}: {}; failed to quiesce surviving ACL/CT path: {}",
                            name, e, quiesce_error
                        ),
                        None => format!(
                            "preexisting live runtime mismatch for {}: {}; ACL/CT gate quiesced",
                            name, e
                        ),
                    });
                }
            };
            managed_acl_lifecycle = managed_acl_registration_lifecycle(
                mode,
                Some(lifecycle_projection_drift),
                gate_disposition,
            )
            .map_err(|error| {
                format!(
                    "failed to classify managed ACL lifecycle for {}: {}",
                    name, error
                )
            })?;

            if !preexisting_live_verified {
                if let Err(e) = aria_core::ebpf_ops::update_acl_runtime_gate(
                    TapMapRuntime::new(&pin_path, tap_id),
                    false,
                    false,
                    aria_core::common::ACL_INGRESS_HOOK_TC,
                ) {
                    wal.shutdown().await;
                    return Err(format!(
                        "preexisting live runtime for {} requires projection repair but failed to quiesce ACL/CT: {}",
                        name, e
                    ));
                }
                info!(instance = %name, tap_id, "quiesced repairable preexisting ACL projection pending Neutron resync");
            }
        } else if !replacing_existing {
            if let Err(e) = aria_core::ebpf_ops::scrub_managed_runtime_state(TapMapRuntime::new(
                &pin_path, tap_id,
            )) {
                wal.shutdown().await;
                return Err(format!("failed to scrub stale tap runtime state: {}", e));
            }
        } else {
            info!(instance = %name, tap_id, "skipping pre-replay scrub while replacing existing registered instance");
        }

        let activation = managed_runtime_activation(
            mode,
            preexisting_live_verified,
            state.conntrack_enabled,
            state.acl_enabled,
        );

        if !pin_state.preexisting_live_links {
            if let Err(e) = aria_core::ebpf_ops::write_tap_config(
                TapMapRuntime::new(&pin_path, tap_id),
                aria_core::common::TapConfig {
                    conntrack_enabled: state.conntrack_enabled as u8,
                    monitoring_enabled: state.monitoring_enabled as u8,
                    acl_enabled: state.acl_enabled as u8,
                    qos_enabled: (state.qos_enabled && !state.qos_rules.is_empty()) as u8,
                    mirror_enabled: (state.mirror_enabled && !state.mirror_rules.is_empty()) as u8,
                    tcprt_enabled: state.tcprt_enabled as u8,
                    acl_active_bank: aria_core::common::ACL_BANK_PRIMARY,
                    acl_ingress_hook: aria_core::common::ACL_INGRESS_HOOK_TC,
                },
            ) {
                Self::cleanup_failed_managed_registration(
                    name,
                    &pin_path,
                    tap_id,
                    ifindex,
                    wal,
                    preserve_existing_runtime,
                    iface_ctx_synced,
                    tap_config_written,
                )
                .await;
                return Err(e);
            }
            tap_config_written = tap_id != aria_core::common::TAP_ID_UNASSIGNED;

            let replay_result = match projection_mode {
                GroupProjectionMode::StandaloneCompatibility => {
                    replay_state_to_pinned_maps(&pin_path, &state_path)
                }
                GroupProjectionMode::Managed => {
                    replay_managed_state_to_pinned_maps(&pin_path, &state_path, &state)
                }
            };
            if let Err(e) = replay_result {
                Self::cleanup_failed_managed_registration(
                    name,
                    &pin_path,
                    tap_id,
                    ifindex,
                    wal,
                    preserve_existing_runtime,
                    iface_ctx_synced,
                    tap_config_written,
                )
                .await;
                return Err(e);
            }

            if let Err(e) = aria_core::ebpf_ops::update_acl_runtime_gate(
                TapMapRuntime::new(&pin_path, tap_id),
                false,
                false,
                aria_core::common::ACL_INGRESS_HOOK_TC,
            ) {
                Self::cleanup_failed_managed_registration(
                    name,
                    &pin_path,
                    tap_id,
                    ifindex,
                    wal,
                    preserve_existing_runtime,
                    iface_ctx_synced,
                    tap_config_written,
                )
                .await;
                return Err(format!("failed to quiesce managed runtime gate: {}", e));
            }

            if let Err(e) =
                aria_core::ebpf_ops::sync_iface_ctx(TapMapRuntime::new(&pin_path, tap_id), ifindex)
            {
                Self::cleanup_failed_managed_registration(
                    name,
                    &pin_path,
                    tap_id,
                    ifindex,
                    wal,
                    preserve_existing_runtime,
                    iface_ctx_synced,
                    tap_config_written,
                )
                .await;
                return Err(e);
            }
            iface_ctx_synced = true;
        }

        Ok(PreparedManagedInstance {
            name: name.to_string(),
            state,
            tap_id,
            ifindex,
            pin_path,
            state_path,
            wal,
            desired_ssl_enabled: if pin_state.preexisting_live_links {
                None
            } else {
                global_ssl_enabled
            },
            preserve_existing_runtime,
            iface_ctx_synced,
            tap_config_written,
            managed_acl_lifecycle,
            activation,
        })
    }

    pub async fn activate_managed_registration(
        &self,
        prepared: &PreparedManagedInstance,
    ) -> Result<(), String> {
        let runtime = TapMapRuntime::new(&prepared.pin_path, prepared.tap_id);
        match prepared.activation {
            ManagedRuntimeActivation::PreserveVerifiedLive => Ok(()),
            ManagedRuntimeActivation::RestoreStandalone { conntrack, acl } => {
                aria_core::ebpf_ops::update_acl_runtime_gate(
                    runtime,
                    conntrack,
                    acl,
                    aria_core::common::ACL_INGRESS_HOOK_TC,
                )
            }
            ManagedRuntimeActivation::AwaitNeutronResync { .. } => {
                aria_core::ebpf_ops::update_acl_runtime_gate(
                    runtime,
                    false,
                    false,
                    aria_core::common::ACL_INGRESS_HOOK_TC,
                )
            }
        }
    }

    pub fn quiesce_managed_registration(
        &self,
        prepared: &PreparedManagedInstance,
    ) -> Result<(), String> {
        aria_core::ebpf_ops::update_acl_runtime_gate(
            TapMapRuntime::new(&prepared.pin_path, prepared.tap_id),
            false,
            false,
            aria_core::common::ACL_INGRESS_HOOK_TC,
        )
    }

    pub async fn publish_managed_instance(&self, prepared: PreparedManagedInstance) {
        let PreparedManagedInstance {
            name,
            state,
            tap_id,
            ifindex,
            pin_path,
            state_path,
            wal,
            desired_ssl_enabled,
            managed_acl_lifecycle,
            activation,
            ..
        } = prepared;

        let runtime = FirewallInstance::new(
            &name,
            pin_path.clone().into(),
            state_path.clone().into(),
            true,
            self.trace_map_mode(),
        );
        let link_health = runtime.tc_acl_link_health();
        let enforcement_published = !matches!(
            activation,
            ManagedRuntimeActivation::AwaitNeutronResync { .. }
        ) && runtime.require_tc_acl_runtime().is_ok();
        let runtime_health = initial_runtime_health(
            state.conntrack_enabled,
            state.acl_enabled,
            link_health,
            enforcement_published,
        );

        let instance = Arc::new(tokio::sync::RwLock::new(InstanceState {
            state,
            runtime_health,
            managed_acl_publication_mode: managed_acl_lifecycle.publication_mode,
            managed_projection_health: managed_acl_lifecycle.projection_health,
            tap_id,
            ifindex: Some(ifindex),
            pin_path,
            state_path,
            wal,
            ssl_sync_pending: false,
            last_ssl_sync_error: None,
        }));

        let mut instances = self.instances.write().await;
        instances.insert(name.to_string(), instance.clone());
        drop(instances);

        let trace_pin_path = {
            let state = instance.read().await;
            state.pin_path.clone()
        };
        if let Err(e) = self
            .trace_manager
            .register_tap(&trace_pin_path, tap_id)
            .await
        {
            warn!(
                instance = %name,
                tap_id,
                error = %e,
                "failed to register trace runtime for managed instance"
            );
        }

        if let Some(enabled) = desired_ssl_enabled {
            let _ = self
                .reconcile_instance_ssl_state(&name, &instance, enabled)
                .await;
        }

        if let Err(e) = self
            .kernel_drop_manager
            .sync_managed_iface(&name, ifindex, tap_id)
            .await
        {
            warn!(
                instance = %name,
                ifindex,
                tap_id,
                error = %e,
                "failed to register managed interface with kernel drop manager"
            );
        }

        info!(instance = %name, tap_id, ifindex, "registered instance");
    }

    pub async fn abort_managed_registration(&self, prepared: PreparedManagedInstance) {
        Self::cleanup_failed_managed_registration(
            &prepared.name,
            &prepared.pin_path,
            prepared.tap_id,
            prepared.ifindex,
            prepared.wal,
            prepared.preserve_existing_runtime,
            prepared.iface_ctx_synced,
            prepared.tap_config_written,
        )
        .await;
    }

    /// Register the "system" instance (standalone mode)
    pub async fn register_system_instance(
        &self,
        pin_path: &str,
        state_path: &str,
        approved_state: FirewallState,
        iface: &str,
    ) -> Result<(), String> {
        let global_ssl_enabled = match self.read_ssl_global_config().await {
            Ok(enabled) => Some(enabled),
            Err(e) => {
                warn!(error = %e, "failed to read global SSL config during system register");
                None
            }
        };
        let tap_id_reset = approved_state.tap_id != aria_core::common::TAP_ID_UNASSIGNED;
        let ssl_changed = global_ssl_enabled
            .map(|enabled| approved_state.ssl_enabled != enabled)
            .unwrap_or(false);
        let iface_changed = approved_state.attached_iface.as_deref() != Some(iface);
        let state = prepare_system_publication_state(approved_state, iface, global_ssl_enabled);
        let ifindex = match state.attached_iface.as_deref() {
            Some(iface) => match Self::resolve_ifindex(iface) {
                Ok(ifindex) => Some(ifindex),
                Err(e) => {
                    warn!(
                        instance = "system",
                        iface = %iface,
                        error = %e,
                        "failed to resolve system interface ifindex for kernel drop manager"
                    );
                    None
                }
            },
            None => None,
        };

        let wal = match WalClient::open(state_path) {
            Ok(w) => w,
            Err(e) => {
                return Err(format!("failed to open WAL for system: {}", e));
            }
        };

        // Compact on startup if WAL had replayed entries
        if wal.entry_count() > 0 || ssl_changed || tap_id_reset || iface_changed {
            let json = serde_json::to_string_pretty(&state)
                .map_err(|e| format!("failed to serialize approved system state: {}", e))?;
            wal.compact(json)
                .await
                .map_err(|e| format!("failed to persist approved system state: {}", e))?;
        }

        let tap_id = state.tap_id;
        let runtime = TapMapRuntime::new(pin_path, tap_id);
        let runtime_instance = FirewallInstance::new(
            iface,
            pin_path.to_string().into(),
            state_path.to_string().into(),
            false,
            self.trace_map_mode(),
        );
        let system_link_health = runtime_instance.tc_acl_link_health();
        let enforcement_required = state.conntrack_enabled || state.acl_enabled;
        if enforcement_required && !system_link_health.acl_ready() {
            return Err(format!(
                "system ACL/CT gate remains quiesced; exact live TCX validation failed: {}",
                system_link_health.missing_tc().join(", ")
            ));
        }
        aria_core::ebpf_ops::update_runtime_config(
            runtime,
            Some(state.conntrack_enabled),
            Some(state.monitoring_enabled),
            Some(state.acl_enabled),
            Some(state.qos_enabled && !state.qos_rules.is_empty()),
            Some(state.mirror_enabled && !state.mirror_rules.is_empty()),
            Some(state.tcprt_enabled),
            None,
        )?;
        let runtime_health = initial_runtime_health(
            state.conntrack_enabled,
            state.acl_enabled,
            system_link_health,
            false,
        );
        let instance = Arc::new(tokio::sync::RwLock::new(InstanceState {
            state,
            runtime_health,
            managed_acl_publication_mode: ManagedAclPublicationMode::StandaloneCompatibility,
            managed_projection_health: ManagedProjectionHealth::Unverified,
            tap_id,
            ifindex,
            pin_path: pin_path.to_string(),
            state_path: state_path.to_string(),
            wal,
            ssl_sync_pending: false,
            last_ssl_sync_error: None,
        }));

        let mut instances = self.instances.write().await;
        instances.insert("system".to_string(), instance.clone());
        drop(instances);

        if enforcement_required {
            if let Err(error) = self
                .mark_tc_acl_runtime_ready("system", system_link_health.xdp_ready())
                .await
            {
                self.unregister_instance("system").await;
                return Err(format!(
                    "failed to publish system TC ACL runtime health: {}",
                    error
                ));
            }
        }

        if let Err(e) = self.trace_manager.register_tap(pin_path, tap_id).await {
            warn!(
                instance = "system",
                tap_id,
                error = %e,
                "failed to register trace runtime for system instance"
            );
        }

        if let Some(enabled) = global_ssl_enabled {
            let _ = self
                .reconcile_instance_ssl_state("system", &instance, enabled)
                .await;
        }

        if let Some(ifindex) = ifindex {
            if let Err(e) = self
                .kernel_drop_manager
                .sync_managed_iface("system", ifindex, tap_id)
                .await
            {
                warn!(
                    instance = "system",
                    ifindex,
                    tap_id,
                    error = %e,
                    "failed to register system interface with kernel drop manager"
                );
            }
        }

        info!(instance = "system", tap_id, ifindex = ?ifindex, "registered system instance");
        Ok(())
    }

    /// Unregister an instance (called when TapRegistry detaches)
    pub async fn unregister_instance(&self, name: &str) {
        // Compact before removing
        self.compact_instance(name).await;
        let removed = {
            let mut instances = self.instances.write().await;
            instances.remove(name)
        };
        if let Some(inst) = removed {
            let mut state = inst.write().await;
            let tap_id = state.tap_id;
            let ifindex = state.ifindex;
            if let Some(ifindex) = ifindex {
                if let Err(e) = self.kernel_drop_manager.remove_managed_iface(ifindex).await {
                    warn!(
                        instance = %name,
                        ifindex,
                        error = %e,
                        "failed to remove managed interface from kernel drop manager"
                    );
                }
            }
            if tap_id != aria_core::common::TAP_ID_UNASSIGNED {
                self.trace_manager
                    .unregister_tap(&state.pin_path, tap_id)
                    .await;
                if let Err(e) =
                    aria_core::ebpf_ops::scrub_managed_runtime_state(state.map_runtime())
                {
                    warn!(
                        instance = %name,
                        tap_id,
                        ifindex = ?ifindex,
                        error = %e,
                        "failed to scrub managed runtime state during unregister"
                    );
                }
            } else if name == "system" {
                self.trace_manager
                    .unregister_tap(&state.pin_path, tap_id)
                    .await;
            } else if name != "system" {
                if let Some(ifindex) = ifindex {
                    if let Err(e) = aria_core::ebpf_ops::clear_iface_ctx(&state.pin_path, ifindex) {
                        warn!(instance = %name, tap_id, ifindex, error = %e, "failed to clear iface context");
                    }
                }
            }
            state.shutdown_wal().await;
            info!(instance = %name, tap_id, ifindex = ?ifindex, "unregistered instance");
        } else {
            info!(instance = %name, "unregistered instance");
        }
        self.clear_neutron_port_authority(name).await;
    }

    /// List all registered instance names
    pub async fn list_instances(&self) -> Vec<String> {
        let instances = self.instances.read().await;
        let mut names: Vec<String> = instances.keys().cloned().collect();
        names.sort();
        names
    }

    fn runtime_link_health_locked(&self, instance: &str, state: &InstanceState) -> TcAclLinkHealth {
        let Ok(iface) = Self::runtime_iface_name(instance, state) else {
            return TcAclLinkHealth::new(false, false, false);
        };
        let runtime = FirewallInstance::new(
            &iface,
            state.pin_path.clone().into(),
            state.state_path.clone().into(),
            instance != "system",
            self.trace_map_mode(),
        );
        let pinned = runtime.tc_acl_link_health();
        let ifindex_matches = Self::resolve_ifindex(&iface)
            .ok()
            .is_some_and(|actual| state.ifindex.map_or(true, |expected| expected == actual));
        TcAclLinkHealth::new(
            ifindex_matches && pinned.ingress,
            ifindex_matches && pinned.egress,
            ifindex_matches && pinned.xdp,
        )
    }

    fn runtime_xdp_health_locked(&self, instance: &str, state: &InstanceState) -> bool {
        let Ok(iface) = Self::runtime_iface_name(instance, state) else {
            return false;
        };
        let ifindex_matches = Self::resolve_ifindex(&iface)
            .ok()
            .is_some_and(|actual| state.ifindex.map_or(true, |expected| expected == actual));
        if !ifindex_matches {
            return false;
        }
        FirewallInstance::new(
            &iface,
            state.pin_path.clone().into(),
            state.state_path.clone().into(),
            instance != "system",
            self.trace_map_mode(),
        )
        .xdp_link_health()
    }

    fn quiesce_tc_acl_runtime_locked(instance: &str, state: &InstanceState) -> Result<(), String> {
        let runtime = state.map_runtime();
        aria_core::ebpf_ops::read_runtime_config(runtime)
            .map_err(|error| format!("runtime gate read failed: {}", error))?;
        if instance == "system" {
            aria_core::ebpf_ops::update_runtime_config(
                runtime,
                Some(false),
                None,
                Some(false),
                None,
                None,
                None,
                None,
            )
        } else {
            aria_core::ebpf_ops::update_acl_runtime_gate(
                runtime,
                false,
                false,
                aria_core::common::ACL_INGRESS_HOOK_TC,
            )
        }
        .map_err(|error| format!("runtime gate write failed: {}", error))
    }

    pub async fn list_instance_runtime_health(&self) -> Vec<InstanceRuntimeHealthSnapshot> {
        let instances = self.instance_entries().await;
        let mut snapshots = Vec::with_capacity(instances.len());
        for (name, instance) in instances {
            let state = instance.read().await;
            snapshots.push(InstanceRuntimeHealthSnapshot {
                name,
                active: true,
                acl_ready: state.runtime_health.acl_ready,
                xdp_ready: state.runtime_health.xdp_ready,
                readiness_reason: state.runtime_health.readiness_reason(),
            });
        }
        snapshots.sort_by(|left, right| left.name.cmp(&right.name));
        snapshots
    }

    pub async fn reconcile_tc_acl_health(&self) -> Vec<TcAclHealthChange> {
        let instances = self.instance_entries().await;
        let mut changes = Vec::new();

        for (name, instance) in instances {
            if let Some(change) = self
                .reconcile_tc_acl_health_candidate(&name, &instance)
                .await
            {
                changes.push(change);
            }
        }

        changes.sort_by(|left, right| left.instance.cmp(&right.instance));
        changes
    }

    async fn reconcile_tc_acl_health_candidate(
        &self,
        name: &str,
        instance: &Arc<tokio::sync::RwLock<InstanceState>>,
    ) -> Option<TcAclHealthChange> {
        let _lifecycle_guard = self.lock_runtime_lifecycle().await;
        let is_current = {
            let instances = self.instances.read().await;
            instances
                .get(name)
                .is_some_and(|current| Arc::ptr_eq(current, instance))
        };
        if !is_current {
            return None;
        }

        let mut state = instance.write().await;
        let desired_enforcement = state.state.conntrack_enabled || state.state.acl_enabled;
        if !desired_enforcement {
            let xdp_ready = self.runtime_xdp_health_locked(name, &state);
            if state.runtime_health.xdp_ready == xdp_ready {
                return None;
            }
            state.runtime_health.xdp_ready = xdp_ready;
            return Some(TcAclHealthChange {
                instance: name.to_string(),
                acl_ready: state.runtime_health.acl_ready,
                xdp_ready: state.runtime_health.xdp_ready,
                reason: state.runtime_health.readiness_reason(),
                quiesced: false,
            });
        }

        let observed = self.runtime_link_health_locked(name, &state);
        let transition = apply_tc_health_observation(state.runtime_health.clone(), observed);
        if !transition.changed && !transition.quiesce_acl_ct {
            return None;
        }

        let (next, quiesced) = if transition.quiesce_acl_ct {
            apply_tc_health_quiesce_result(
                transition.next,
                Self::quiesce_tc_acl_runtime_locked(name, &state),
            )
        } else {
            (transition.next, false)
        };

        if next == state.runtime_health {
            return None;
        }
        state.runtime_health = next;
        let change = TcAclHealthChange {
            instance: name.to_string(),
            acl_ready: state.runtime_health.acl_ready,
            xdp_ready: state.runtime_health.xdp_ready,
            reason: state.runtime_health.readiness_reason(),
            quiesced,
        };
        if !change.acl_ready {
            warn!(
                instance = %change.instance,
                reason = ?change.reason,
                quiesced = change.quiesced,
                "TC ACL runtime health changed"
            );
        } else {
            info!(
                instance = %change.instance,
                xdp_ready = change.xdp_ready,
                "runtime link health changed"
            );
        }
        Some(change)
    }

    pub async fn mark_tc_acl_runtime_ready(
        &self,
        instance: &str,
        xdp_ready: bool,
    ) -> Result<(), ControlPlaneError> {
        let inst = self.get_instance(instance).await?;
        let mut state = inst.write().await;
        let observed = self.runtime_link_health_locked(instance, &state);
        if !observed.acl_ready() {
            return Err(ControlPlaneError::InstanceNotReady(
                missing_tc_reason(observed)
                    .unwrap_or("missing_tc_ingress_and_egress")
                    .to_string(),
            ));
        }
        Self::mark_tc_acl_runtime_ready_locked(
            instance,
            &mut state,
            xdp_ready,
            self.trace_map_mode(),
        )
    }

    async fn get_instance(
        &self,
        name: &str,
    ) -> Result<Arc<tokio::sync::RwLock<InstanceState>>, ControlPlaneError> {
        let instances = self.instances.read().await;
        instances
            .get(name)
            .cloned()
            .ok_or_else(|| ControlPlaneError::InstanceNotFound(name.to_string()))
    }

    async fn snapshot_kernel_drop_instances(&self) -> Vec<KernelDropInstanceView> {
        let instances: Vec<(String, Arc<tokio::sync::RwLock<InstanceState>>)> = {
            let instances = self.instances.read().await;
            instances
                .iter()
                .map(|(name, inst)| (name.clone(), inst.clone()))
                .collect()
        };

        let mut snapshot = Vec::with_capacity(instances.len());
        for (name, inst) in instances {
            let state = inst.read().await;
            let iface_name = if name == "system" {
                state.state.attached_iface.clone()
            } else {
                Some(name.clone())
            };
            snapshot.push(KernelDropInstanceView {
                instance_name: name,
                tap_id: state.tap_id,
                ifindex: state.ifindex,
                iface_name,
            });
        }

        snapshot
    }

    async fn resolve_kernel_drop_query(
        &self,
        query: &aria_api::KernelDropQuery,
    ) -> Result<ResolvedKernelDropQuery, ControlPlaneError> {
        let instances = self.snapshot_kernel_drop_instances().await;

        let mut by_tap = HashMap::new();
        let mut by_ifindex = HashMap::new();
        let mut iface_name_by_ifindex = HashMap::new();
        for inst in &instances {
            by_tap.insert(inst.tap_id, inst.instance_name.clone());
            if let Some(ifindex) = inst.ifindex {
                by_ifindex.insert(ifindex, inst.instance_name.clone());
                if let Some(iface_name) = &inst.iface_name {
                    iface_name_by_ifindex.insert(ifindex, iface_name.clone());
                }
            }
        }

        let instance_match = if let Some(instance_name) = &query.instance {
            Some(
                instances
                    .iter()
                    .find(|inst| inst.instance_name == *instance_name)
                    .cloned()
                    .ok_or_else(|| ControlPlaneError::InstanceNotFound(instance_name.clone()))?,
            )
        } else {
            None
        };

        let iface_match = if let Some(iface_name) = &query.iface {
            let matches: Vec<KernelDropInstanceView> = instances
                .iter()
                .filter(|inst| inst.iface_name.as_deref() == Some(iface_name.as_str()))
                .cloned()
                .collect();
            match matches.as_slice() {
                [] => {
                    return Err(ControlPlaneError::ValidationError(format!(
                        "Interface '{}' is not attached to an active instance",
                        iface_name
                    )));
                }
                [inst] => Some(inst.clone()),
                _ => {
                    return Err(ControlPlaneError::ValidationError(format!(
                        "Interface '{}' maps to multiple active instances",
                        iface_name
                    )));
                }
            }
        } else {
            None
        };

        if let (Some(instance), Some(iface)) = (&instance_match, &iface_match) {
            if instance.ifindex != iface.ifindex {
                return Err(ControlPlaneError::ValidationError(format!(
                    "Instance '{}' does not match interface '{}'",
                    instance.instance_name,
                    query.iface.as_deref().unwrap_or_default()
                )));
            }
        }

        if let (Some(instance), Some(ifindex)) = (&instance_match, query.ifindex) {
            if instance.ifindex != Some(ifindex) {
                return Err(ControlPlaneError::ValidationError(format!(
                    "Instance '{}' does not match ifindex {}",
                    instance.instance_name, ifindex
                )));
            }
        }

        if let (Some(iface), Some(ifindex)) = (&iface_match, query.ifindex) {
            if iface.ifindex != Some(ifindex) {
                return Err(ControlPlaneError::ValidationError(format!(
                    "Interface '{}' does not match ifindex {}",
                    query.iface.as_deref().unwrap_or_default(),
                    ifindex
                )));
            }
        }

        let resolved_tap = instance_match
            .as_ref()
            .or(iface_match.as_ref())
            .and_then(|inst| {
                (inst.tap_id != aria_core::common::TAP_ID_UNASSIGNED || inst.ifindex.is_some())
                    .then_some(inst.tap_id)
            });

        let resolved_ifindex = query
            .ifindex
            .or_else(|| instance_match.as_ref().and_then(|inst| inst.ifindex))
            .or_else(|| iface_match.as_ref().and_then(|inst| inst.ifindex));

        if query.instance.is_some() && resolved_tap.is_none() && resolved_ifindex.is_none() {
            return Err(ControlPlaneError::InstanceNotReady(format!(
                "Instance '{}' does not have a resolved kernel-drop filter target yet",
                query.instance.as_deref().unwrap_or_default()
            )));
        }

        if query.iface.is_some() && resolved_tap.is_none() && resolved_ifindex.is_none() {
            return Err(ControlPlaneError::InstanceNotReady(format!(
                "Interface '{}' does not have a resolved kernel-drop filter target yet",
                query.iface.as_deref().unwrap_or_default()
            )));
        }

        Ok(ResolvedKernelDropQuery {
            tap_id: resolved_tap,
            ifindex: resolved_ifindex,
            include_unattributed: query.include_unattributed && resolved_ifindex.is_none(),
            by_tap,
            by_ifindex,
            iface_name_by_ifindex,
        })
    }

    fn check_runtime_maps_ready(pin_path: &str) -> Result<(), ControlPlaneError> {
        let cfg_path = format!("{}/FIREWALL_CONFIG", pin_path);
        if !std::path::Path::new(&cfg_path).exists() {
            return Err(ControlPlaneError::InstanceNotReady(
                "Pinned firewall maps not ready".to_string(),
            ));
        }
        Ok(())
    }

    async fn publish_acl_projection_locked(
        &self,
        instance: &str,
        state: &mut InstanceState,
        old_state: &FirewallState,
        final_state: &FirewallState,
        proposed_projection: &aria_core::ebpf_ops::ManagedGroupProjection,
        semantic_changed: bool,
        require_tc_acl_links: bool,
        clean_semantic_mutations: Vec<SharedNetworkMutation>,
        current_acl_bank: u8,
        next_acl_bank: u8,
        new_port_sets_by_key: &BTreeMap<OwnedAclPolicyKey, bool>,
        created_port_sets: &[TransactionCreatedPortSet],
        released_port_sets: &BTreeMap<u32, String>,
        report: &mut OwnedAclReconcileReport,
    ) -> Result<bool, ControlPlaneError> {
        let runtime_pin_path = state.pin_path.clone();
        let runtime_tap_id = state.tap_id;
        let runtime = TapMapRuntime::new(&runtime_pin_path, runtime_tap_id);

        let projection_drift =
            proposed_projection.plan_managed_pinned_projection(runtime, old_state);
        if matches!(
            &projection_drift,
            ProjectionDrift::RepairRequired(_) | ProjectionDrift::Fatal(_)
        ) {
            state.managed_projection_health = ManagedProjectionHealth::Unverified;
        }
        let decision = managed_acl_publication_decision(projection_drift, semantic_changed)
            .map_err(ControlPlaneError::KernelError)?;
        if decision == ManagedAclPublicationDecision::Noop {
            return Ok(false);
        }
        let steps = managed_acl_publication_steps(&decision, clean_semantic_mutations);
        let ManagedAclPublicationDecision::Publish {
            selector_repair_performed,
            pre_mutation_health,
            ..
        } = &decision
        else {
            unreachable!("no-op publication returned before step planning");
        };
        report.selector_repair_performed = *selector_repair_performed;

        let mut durable_final_state = final_state.clone();
        for bitmap_idx in released_port_sets.keys() {
            durable_final_state
                .quarantine_bitmap_index(*bitmap_idx)
                .map_err(ControlPlaneError::ValidationError)?;
        }

        let mut durable_final_state = Some(durable_final_state);
        let mut applied_shared_mutations = Vec::new();
        for step in steps {
            match step {
                ManagedAclPublicationStep::InvalidateProjectionHealth => {
                    state.managed_projection_health = *pre_mutation_health;
                    // Reserve every transaction-created index durably before the first
                    // kernel mutation. A crash or rollback-cleanup fault can therefore
                    // never expose a stale bitmap through the old free-list/next cursor.
                    if !created_port_sets.is_empty() {
                        let mut allocator_guard_state = old_state.clone();
                        quarantine_port_set_indices(&mut allocator_guard_state, created_port_sets)
                            .map_err(ControlPlaneError::ValidationError)?;
                        state
                            .compact_and_publish_state(allocator_guard_state)
                            .await
                            .map_err(|error| {
                                ControlPlaneError::PersistenceError(format!(
                                    "persist transaction-created bitmap quarantine before ACL staging: {}",
                                    error
                                ))
                            })?;
                    }
                }
                ManagedAclPublicationStep::ApplyGeneral(mutation) => {
                    if let Err(error) =
                        apply_shared_network_mutation(&mutation, runtime, &self.ebpf_path)
                    {
                        return Err(rollback_owned_acl_prepublication(
                            ControlPlaneError::KernelError(format!(
                                "apply managed general selector {:?}: {}",
                                mutation, error
                            )),
                            &applied_shared_mutations,
                            ManagedAclPublicationFailurePhase::General,
                            created_port_sets,
                            runtime,
                            &self.ebpf_path,
                            current_acl_bank,
                            next_acl_bank,
                            state,
                            old_state,
                        )
                        .await);
                    }
                    applied_shared_mutations.push(mutation);
                }
                ManagedAclPublicationStep::StageShadow => {
                    if let Err(error) = Self::stage_acl_shadow_bank(
                        final_state,
                        proposed_projection,
                        runtime,
                        next_acl_bank,
                        &self.ebpf_path,
                        new_port_sets_by_key,
                    ) {
                        return Err(rollback_owned_acl_prepublication(
                            error,
                            &applied_shared_mutations,
                            ManagedAclPublicationFailurePhase::Shadow,
                            created_port_sets,
                            runtime,
                            &self.ebpf_path,
                            current_acl_bank,
                            next_acl_bank,
                            state,
                            old_state,
                        )
                        .await);
                    }
                }
                ManagedAclPublicationStep::VerifyTc => {
                    if require_tc_acl_links {
                        if let Err(error) = Self::require_tc_acl_ready_locked(
                            instance,
                            state,
                            self.trace_map_mode(),
                        ) {
                            return Err(rollback_owned_acl_prepublication(
                                error,
                                &applied_shared_mutations,
                                ManagedAclPublicationFailurePhase::VerifyTc,
                                created_port_sets,
                                runtime,
                                &self.ebpf_path,
                                current_acl_bank,
                                next_acl_bank,
                                state,
                                old_state,
                            )
                            .await);
                        }
                    }
                }
                ManagedAclPublicationStep::SwitchBank => {
                    if let Err(error) =
                        aria_core::ebpf_ops::set_acl_active_bank(runtime, next_acl_bank)
                    {
                        return Err(rollback_owned_acl_prepublication(
                            ControlPlaneError::KernelError(error),
                            &applied_shared_mutations,
                            ManagedAclPublicationFailurePhase::SwitchBank,
                            created_port_sets,
                            runtime,
                            &self.ebpf_path,
                            current_acl_bank,
                            next_acl_bank,
                            state,
                            old_state,
                        )
                        .await);
                    }
                }
                ManagedAclPublicationStep::Persist => {
                    let compact_started = Instant::now();
                    let durable_final_state = durable_final_state
                        .take()
                        .expect("publication plan contains exactly one persistence step");
                    if let Err(error) = state.compact_and_publish_state(durable_final_state).await {
                        let mut recovery_errors =
                            vec![format!("owned ACL persistence failed: {}", error)];
                        let compensations = managed_acl_publication_compensations(
                            &applied_shared_mutations,
                            ManagedAclPublicationFailurePhase::Persist,
                        );
                        let mut active_bank_restored = true;
                        if let Err(compensation_error) =
                            execute_managed_acl_publication_compensations(
                                &compensations,
                                |compensation| {
                                    let result = apply_managed_acl_publication_compensation(
                                        compensation,
                                        runtime,
                                        &self.ebpf_path,
                                        current_acl_bank,
                                    );
                                    if matches!(
                                        compensation,
                                        ManagedAclPublicationCompensation::RestoreActiveBank
                                    ) && result.is_err()
                                    {
                                        active_bank_restored = false;
                                    }
                                    result
                                },
                            )
                        {
                            recovery_errors.push(compensation_error);
                        }
                        if active_bank_restored {
                            if let Err(scrub_error) =
                                aria_core::ebpf_ops::scrub_acl_bank(runtime, next_acl_bank)
                            {
                                recovery_errors.push(format!(
                                    "scrub failed publication bank {}: {}",
                                    next_acl_bank, scrub_error
                                ));
                            }
                        } else {
                            recovery_errors.push(format!(
                                "preserved publication bank {} because active-bank restore failed",
                                next_acl_bank
                            ));
                        }
                        let cleanup = cleanup_transaction_created_port_sets(
                            created_port_sets,
                            runtime,
                            &self.ebpf_path,
                        );
                        for failure in &cleanup.failures {
                            recovery_errors.push(failure.error.clone());
                        }
                        if let Err(recovery_error) =
                            restore_durable_old_state_after_failed_persistence(
                                state, old_state, &cleanup,
                            )
                            .await
                        {
                            recovery_errors.push(recovery_error);
                        }
                        return Err(ControlPlaneError::PersistenceError(
                            recovery_errors.join("; "),
                        ));
                    }
                    report.compact_ms = compact_started.elapsed().as_millis();
                }
            }
        }

        Ok(true)
    }

    // ── Groups ──

    pub async fn replace_owned_acl(
        &self,
        instance: &str,
        owner_prefix: &str,
        exclusive_policy_domain: bool,
        groups: &[OwnedAclGroupSpec],
        policies: &[OwnedAclPolicySpec],
        require_tc_acl_links: bool,
    ) -> Result<OwnedAclReconcileReport, ControlPlaneError> {
        let _lifecycle_guard = self.lock_runtime_lifecycle().await;
        let inst = self.get_instance(instance).await?;
        let mut state = inst.write().await;
        let previous_projection_health = state.managed_projection_health;
        // The Neutron caller has already quiesced ACL/CT. Keep every error
        // after the instance lock fail-closed, then restore the prior health
        // only when a clean equal reconcile proves that publication is a no-op.
        state.managed_projection_health = ManagedProjectionHealth::Unverified;
        Self::owned_acl_validate_group_specs(owner_prefix, groups)?;
        Self::owned_acl_validate_policy_specs(owner_prefix, policies)?;
        Self::check_runtime_maps_ready(&state.pin_path)?;
        if require_tc_acl_links {
            Self::require_tc_acl_ready_locked(instance, &state, self.trace_map_mode())?;
        }
        let current_acl_bank = aria_core::ebpf_ops::read_acl_active_bank(state.map_runtime())
            .map_err(ControlPlaneError::KernelError)?;
        let next_acl_bank = aria_core::common::acl_next_bank(current_acl_bank);

        let old_state = state.state.clone();
        let old_owned_policies: Vec<ExistingOwnedAclPolicy> = old_state
            .rules
            .iter()
            .filter(|rule| {
                Self::owned_acl_rule_in_replace_scope(
                    &old_state,
                    rule,
                    owner_prefix,
                    exclusive_policy_domain,
                )
            })
            .map(|rule| ExistingOwnedAclPolicy {
                key: Self::owned_acl_policy_key_from_rule(&old_state, rule),
                value: Self::owned_acl_policy_value_from_rule(rule),
                rule: rule.clone(),
            })
            .collect();
        let old_owned_groups: Vec<GroupInfo> = old_state
            .groups
            .values()
            .filter(|group| group.name.starts_with(owner_prefix))
            .cloned()
            .collect();
        let old_groups_by_name: BTreeMap<String, GroupInfo> = old_owned_groups
            .iter()
            .map(|group| (group.name.clone(), group.clone()))
            .collect();
        let old_policies_by_key: BTreeMap<OwnedAclPolicyKey, ExistingOwnedAclPolicy> =
            old_owned_policies
                .iter()
                .map(|policy| (policy.key.clone(), policy.clone()))
                .collect();

        let mut desired_groups = BTreeMap::<String, BTreeSet<String>>::new();
        for group in groups {
            let entry = desired_groups.entry(group.name.clone()).or_default();
            for cidr in &group.cidrs {
                entry.insert(cidr.clone());
            }
        }

        let mut desired_policies = BTreeMap::<OwnedAclPolicyKey, OwnedAclPolicySpec>::new();
        for policy in policies {
            let key = Self::owned_acl_policy_key_from_spec(policy);
            if desired_policies
                .insert(key.clone(), policy.clone())
                .is_some()
            {
                return Err(ControlPlaneError::ValidationError(format!(
                    "duplicate owned ACL policy src={} dst={} proto={} direction={}",
                    key.src_group, key.dst_group, key.proto, key.direction
                )));
            }
        }

        let mut final_state = old_state.clone();
        let mut group_cidr_adds = Vec::<(String, u32, String)>::new();
        let mut group_cidr_deletes = Vec::<(String, u32, String)>::new();
        let mut group_deletes = Vec::<GroupInfo>::new();
        for (name, cidrs) in &desired_groups {
            let old_cidrs: BTreeSet<String> = old_groups_by_name
                .get(name)
                .map(|group| group.cidrs.iter().cloned().collect())
                .unwrap_or_default();
            for cidr in cidrs {
                let group_id = final_state
                    .add_group(name, cidr)
                    .map_err(ControlPlaneError::ValidationError)?;
                if !old_cidrs.contains(cidr) {
                    group_cidr_adds.push((name.clone(), group_id, cidr.clone()));
                }
            }
        }
        for old_group in &old_owned_groups {
            match desired_groups.get(&old_group.name) {
                Some(desired_cidrs) => {
                    if let Some(group) = final_state.groups.get_mut(&old_group.name) {
                        group.cidrs.retain(|cidr| {
                            if desired_cidrs.contains(cidr) {
                                true
                            } else {
                                group_cidr_deletes.push((
                                    old_group.name.clone(),
                                    old_group.id,
                                    cidr.clone(),
                                ));
                                false
                            }
                        });
                    }
                }
                None => {
                    group_deletes.push(old_group.clone());
                    for cidr in &old_group.cidrs {
                        group_cidr_deletes.push((
                            old_group.name.clone(),
                            old_group.id,
                            cidr.clone(),
                        ));
                    }
                }
            }
        }

        let mut runtime_adds = Vec::<OwnedAclPolicyRuntimeAdd>::new();
        let mut policy_deletes = Vec::<ExistingOwnedAclPolicy>::new();
        let mut released_port_sets = BTreeMap::<u32, String>::new();
        for (key, existing) in &old_policies_by_key {
            if !desired_policies.contains_key(key) {
                policy_deletes.push(existing.clone());
            }
        }
        for (key, policy) in &desired_policies {
            let desired_value = Self::owned_acl_policy_value_from_spec(policy);
            if old_policies_by_key.get(key).map(|existing| &existing.value) == Some(&desired_value)
            {
                continue;
            }

            let src_id = self.resolve_group_id(&final_state, &policy.src_group)?;
            let dst_id = self.resolve_group_id(&final_state, &policy.dst_group)?;
            let add_result = final_state
                .apply_add_rule(
                    src_id,
                    dst_id,
                    policy.proto,
                    policy.action,
                    policy.ports.as_deref(),
                    policy.direction,
                )
                .map_err(ControlPlaneError::ValidationError)?;
            quarantine_owned_acl_released_port_set(
                &mut final_state,
                &mut released_port_sets,
                add_result.old_port_set_released.clone(),
            )
            .map_err(ControlPlaneError::ValidationError)?;
            let rule = final_state
                .rules
                .iter()
                .find(|rule| {
                    rule.src_group_id == src_id
                        && rule.dst_group_id == dst_id
                        && rule.proto == policy.proto
                        && rule.direction == policy.direction
                })
                .cloned()
                .ok_or_else(|| {
                    ControlPlaneError::ValidationError(format!(
                        "failed to materialize owned ACL policy src={} dst={} proto={} direction={}",
                        policy.src_group, policy.dst_group, policy.proto, policy.direction
                    ))
                })?;
            runtime_adds.push(OwnedAclPolicyRuntimeAdd {
                rule,
                is_new_port_set: add_result.is_new_port_set,
            });
        }
        for existing in &policy_deletes {
            let rule = &existing.rule;
            let remove_result = final_state
                .apply_remove_rule(
                    rule.src_group_id,
                    rule.dst_group_id,
                    rule.proto,
                    rule.direction,
                )
                .map_err(ControlPlaneError::ValidationError)?;
            quarantine_owned_acl_released_port_set(
                &mut final_state,
                &mut released_port_sets,
                remove_result
                    .bitmap_idx
                    .zip(remove_result.port_set_released),
            )
            .map_err(ControlPlaneError::ValidationError)?;
        }
        for group in &group_deletes {
            final_state.groups.remove(&group.name);
        }
        let _removed_retained_group_ids =
            reconcile_retained_owned_groups(&old_state, &mut final_state, owner_prefix)?;
        group_deletes.retain(|group| !final_state.groups.contains_key(&group.name));
        group_cidr_deletes.retain(|(name, _, cidr)| {
            !final_state
                .groups
                .get(name)
                .is_some_and(|group| group.cidrs.contains(cidr))
        });

        let mut report = OwnedAclReconcileReport {
            group_delete_count: group_deletes.len(),
            group_add_count: desired_groups
                .keys()
                .filter(|name| !old_groups_by_name.contains_key(*name))
                .count(),
            group_cidr_add_count: group_cidr_adds.len(),
            group_cidr_delete_count: group_cidr_deletes.len(),
            policy_delete_count: policy_deletes.len(),
            policy_add_count: runtime_adds.len(),
            port_set_delete_count: released_port_sets.len(),
            compact_ms: 0,
            selector_repair_performed: false,
        };
        let new_port_sets_by_key: BTreeMap<OwnedAclPolicyKey, bool> = runtime_adds
            .iter()
            .map(|add| {
                (
                    Self::owned_acl_policy_key_from_rule(&final_state, &add.rule),
                    add.is_new_port_set,
                )
            })
            .collect();
        let created_port_sets = transaction_created_port_sets(&final_state, &runtime_adds)?;
        let semantic_changed = !(runtime_adds.is_empty()
            && policy_deletes.is_empty()
            && group_cidr_adds.is_empty()
            && group_cidr_deletes.is_empty()
            && group_deletes.is_empty()
            && released_port_sets.is_empty());
        let clean_semantic_mutations = managed_general_state_mutations(&old_state, &final_state)?;
        let proposed_projection = compile_managed_group_projection(&final_state)
            .map_err(ControlPlaneError::ValidationError)?;
        let publication_performed = self
            .publish_acl_projection_locked(
                instance,
                &mut state,
                &old_state,
                &final_state,
                &proposed_projection,
                semantic_changed,
                require_tc_acl_links,
                clean_semantic_mutations,
                current_acl_bank,
                next_acl_bank,
                &new_port_sets_by_key,
                &created_port_sets,
                &released_port_sets,
                &mut report,
            )
            .await?;
        if !publication_performed {
            state.managed_projection_health = previous_projection_health;
            return Ok(report);
        }

        let runtime_pin_path = state.pin_path.clone();
        let runtime_tap_id = state.tap_id;
        let runtime = TapMapRuntime::new(&runtime_pin_path, runtime_tap_id);

        let released_cleanup_targets = released_port_sets
            .iter()
            .map(|(bitmap_idx, ports_normalized)| TransactionCreatedPortSet {
                bitmap_idx: *bitmap_idx,
                ports_normalized: ports_normalized.clone(),
            })
            .collect::<Vec<_>>();
        let released_cleanup = cleanup_port_sets(
            &released_cleanup_targets,
            runtime,
            &self.ebpf_path,
            "released",
        );
        if !released_cleanup.cleaned_bitmap_indices.is_empty() {
            let mut reusable_state = state.state.clone();
            apply_confirmed_port_set_cleanups(&mut reusable_state, &released_cleanup)
                .map_err(ControlPlaneError::PersistenceError)?;
            state
                .compact_and_publish_state(reusable_state)
                .await
                .map_err(|error| {
                    ControlPlaneError::PersistenceError(format!(
                        "persist confirmed released bitmap cleanup: {}",
                        error
                    ))
                })?;
        }
        for failure in &released_cleanup.failures {
            warn!(
                error = %failure.error,
                bitmap_idx = failure.bitmap_idx,
                "released port set remains durably quarantined after cleanup failure"
            );
        }
        if let Err(e) = aria_core::ebpf_ops::scrub_acl_bank(runtime, current_acl_bank) {
            warn!(
                error = %e,
                bank = current_acl_bank,
                "failed to scrub previous ACL shadow bank after switch"
            );
        }

        for existing in &policy_deletes {
            let rule = &existing.rule;
            if let Err(e) = aria_core::monitoring::clear_rule_stats_for_policy(
                runtime,
                rule.src_group_id,
                rule.dst_group_id,
                rule.proto,
                rule.direction,
            ) {
                warn!(error = %e, "failed to clear rule stats after owned ACL diff delete");
            }
        }
        for group in &group_deletes {
            if let Err(e) = aria_core::monitoring::clear_group_stats_for_id(runtime, group.id) {
                warn!(error = %e, group_id = group.id, "failed to clear group stats after owned ACL diff delete");
            }
        }

        Ok(report)
    }

    async fn managed_local_owner_prefix_snapshot(&self, instance: &str) -> Option<String> {
        let authorities = self.neutron_authorities.read().await;
        authorities
            .get(instance)
            .map(|authority| format!("neutron:{}:", authority.port_id))
    }

    fn require_managed_local_owner_prefix(
        instance: &str,
        owner_prefix: Option<String>,
    ) -> Result<String, ControlPlaneError> {
        owner_prefix.ok_or_else(|| {
            ControlPlaneError::InstanceNotReady(format!(
                "managed ACL authority is unavailable for instance '{}'",
                instance
            ))
        })
    }

    fn managed_local_projection_runtime(
        &self,
        instance: &str,
        state: &InstanceState,
    ) -> ManagedLocalProjectionRuntime {
        ManagedLocalProjectionRuntime {
            instance: instance.to_string(),
            pin_path: state.pin_path.clone(),
            state_path: state.state_path.clone(),
            ebpf_path: self.ebpf_path.clone(),
            tap_id: state.tap_id,
            attached_iface: state.state.attached_iface.clone(),
            qos_enabled: state.state.qos_enabled,
            mirror_enabled: state.state.mirror_enabled,
        }
    }

    fn cleanup_owned_fq_qdisc_if_unused(instance: &str, state: &InstanceState) {
        if state.state.qos_rules.iter().any(|rule| rule.mode == 1) {
            return;
        }
        let marker_path = Self::fq_qdisc_marker_path(&state.state_path);
        if !marker_path.exists() {
            return;
        }
        let Ok(iface) = Self::runtime_iface_name(instance, state) else {
            return;
        };
        if let Err(error) = aria_core::ebpf_ops::cleanup_root_qdisc(&iface) {
            warn!(instance = %instance, iface = %iface, error = %error,
                "failed to remove owned fq qdisc after last shaping rule deleted");
            return;
        }
        if let Err(error) = fs::remove_file(&marker_path) {
            if error.kind() != std::io::ErrorKind::NotFound {
                warn!(instance = %instance, path = %marker_path.display(), error = %error,
                    "failed to remove fq qdisc ownership marker");
            }
        }
    }

    async fn add_group_standalone_locked(
        &self,
        state: &mut InstanceState,
        name: &str,
        cidr: &str,
    ) -> Result<u32, ControlPlaneError> {
        Self::check_runtime_maps_ready(&state.pin_path)?;
        let was_new_group = !state.state.groups.contains_key(name);
        let id = state
            .state
            .add_group(name, cidr)
            .map_err(ControlPlaneError::ValidationError)?;
        let acl_bank = aria_core::ebpf_ops::read_acl_active_bank(state.map_runtime())
            .map_err(ControlPlaneError::KernelError)?;

        if let Err(error) =
            aria_core::ebpf_ops::add_network("src", cidr, id, state.map_runtime(), &self.ebpf_path)
        {
            state.state.rollback_add_group(name, cidr, was_new_group);
            return Err(ControlPlaneError::KernelError(format!("src: {}", error)));
        }
        if let Err(error) =
            aria_core::ebpf_ops::add_network("dst", cidr, id, state.map_runtime(), &self.ebpf_path)
        {
            let mut errors = vec![format!("dst: {}", error)];
            if let Err(cleanup_error) = aria_core::ebpf_ops::delete_network(
                "src",
                cidr,
                id,
                state.map_runtime(),
                &self.ebpf_path,
            ) {
                errors.push(format!("rollback src network: {}", cleanup_error));
            }
            state.state.rollback_add_group(name, cidr, was_new_group);
            return Err(ControlPlaneError::KernelError(errors.join("; ")));
        }
        if let Err(error) = aria_core::ebpf_ops::add_acl_network_in_bank(
            "src",
            cidr,
            id,
            acl_bank,
            state.map_runtime(),
            &self.ebpf_path,
        ) {
            let mut errors = vec![format!("acl src: {}", error)];
            for direction in ["src", "dst"] {
                if let Err(cleanup_error) = aria_core::ebpf_ops::delete_network(
                    direction,
                    cidr,
                    id,
                    state.map_runtime(),
                    &self.ebpf_path,
                ) {
                    errors.push(format!("rollback {} network: {}", direction, cleanup_error));
                }
            }
            state.state.rollback_add_group(name, cidr, was_new_group);
            return Err(ControlPlaneError::KernelError(errors.join("; ")));
        }
        if let Err(error) = aria_core::ebpf_ops::add_acl_network_in_bank(
            "dst",
            cidr,
            id,
            acl_bank,
            state.map_runtime(),
            &self.ebpf_path,
        ) {
            let mut errors = vec![format!("acl dst: {}", error)];
            if let Err(cleanup_error) = aria_core::ebpf_ops::delete_acl_network_in_bank(
                "src",
                cidr,
                id,
                acl_bank,
                state.map_runtime(),
                &self.ebpf_path,
            ) {
                errors.push(format!("rollback ACL src network: {}", cleanup_error));
            }
            for direction in ["src", "dst"] {
                if let Err(cleanup_error) = aria_core::ebpf_ops::delete_network(
                    direction,
                    cidr,
                    id,
                    state.map_runtime(),
                    &self.ebpf_path,
                ) {
                    errors.push(format!("rollback {} network: {}", direction, cleanup_error));
                }
            }
            state.state.rollback_add_group(name, cidr, was_new_group);
            return Err(ControlPlaneError::KernelError(errors.join("; ")));
        }

        state
            .wal_append(&WalEntry::AddGroup {
                name: name.to_string(),
                cidr: cidr.to_string(),
            })
            .await;
        Ok(id)
    }

    async fn delete_group_standalone_locked(
        &self,
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

        let mut errors = Vec::new();
        let mut deleted_networks = Vec::new();
        let acl_bank = aria_core::ebpf_ops::read_acl_active_bank(state.map_runtime())
            .map_err(ControlPlaneError::KernelError)?;
        for cidr in &group.cidrs {
            for direction in ["src", "dst"] {
                match aria_core::ebpf_ops::delete_network(
                    direction,
                    cidr,
                    group.id,
                    state.map_runtime(),
                    &self.ebpf_path,
                ) {
                    Ok(()) => deleted_networks.push((direction, cidr.clone())),
                    Err(error) => errors.push(format!("{} {}: {}", direction, cidr, error)),
                }
                if let Err(error) = aria_core::ebpf_ops::delete_acl_network_in_bank(
                    direction,
                    cidr,
                    group.id,
                    acl_bank,
                    state.map_runtime(),
                    &self.ebpf_path,
                ) {
                    errors.push(format!("acl {} {}: {}", direction, cidr, error));
                }
            }
        }
        if !errors.is_empty() {
            let rollback = Self::rollback_group_deletes(
                state.map_runtime(),
                &self.ebpf_path,
                state.managed_acl_publication_mode,
                group.id,
                &deleted_networks,
            );
            if let Err(rollback_error) = rollback {
                errors.push(format!("rollback failed: {}", rollback_error));
            }
            return Err(ControlPlaneError::KernelError(errors.join("; ")));
        }

        state.state.groups.remove(name);
        state
            .wal_append(&WalEntry::DeleteGroup {
                name: name.to_string(),
            })
            .await;
        if let Err(error) =
            aria_core::monitoring::clear_group_stats_for_id(state.map_runtime(), group.id)
        {
            warn!(error = %error, group_id = group.id, "failed to clear group stats after group delete");
        }
        Ok(())
    }

    pub async fn list_groups(&self, instance: &str) -> Result<Vec<GroupInfo>, ControlPlaneError> {
        let inst = self.get_instance(instance).await?;
        let state = inst.read().await;
        Ok(state.state.groups.values().cloned().collect())
    }

    pub async fn add_group(
        &self,
        instance: &str,
        name: &str,
        cidr: &str,
    ) -> Result<u32, ControlPlaneError> {
        let _lifecycle_guard = self.lock_runtime_lifecycle().await;
        let owner_prefix = self.managed_local_owner_prefix_snapshot(instance).await;
        let inst = self.get_instance(instance).await?;
        let mut state = inst.write().await;
        match state.managed_acl_publication_mode {
            ManagedAclPublicationMode::StandaloneCompatibility
            | ManagedAclPublicationMode::NeutronAttachOwnedStandaloneAcl => {
                return self
                    .add_group_standalone_locked(&mut state, name, cidr)
                    .await;
            }
            ManagedAclPublicationMode::ManagedAcl => {}
        }
        managed_local_projection_admission(
            state.managed_acl_publication_mode,
            state.managed_projection_health,
        )?;
        let _owner_prefix = Self::require_managed_local_owner_prefix(instance, owner_prefix)?;
        Self::check_runtime_maps_ready(&state.pin_path)?;
        let old_state = state.state.clone();
        let domain_operations = Vec::new();
        let mut final_state = old_state.clone();
        let id = final_state
            .add_group(name, cidr)
            .map_err(ControlPlaneError::ValidationError)?;
        validate_managed_group_mutation(&final_state, id)?;
        let general_mutations = managed_general_state_mutations(&old_state, &final_state)?;
        let projection_order = ManagedLocalProjectionOrder::GeneralThenDomain;
        let operations = merge_managed_local_projection_operations(
            projection_order,
            general_mutations,
            domain_operations,
        );
        let runtime = self.managed_local_projection_runtime(instance, &state);
        let apply_projection_operation =
            managed_local_projection_apply(runtime.clone(), &old_state);
        let compensate_projection_receipt = managed_local_projection_compensate(runtime);
        let persist_final_state = managed_local_projection_persist(&state.wal, &final_state)?;
        let restore_old_state = managed_local_projection_restore(&state.wal, &old_state)?;
        let set_projection_health = |health| {
            state.managed_projection_health = health;
        };
        execute_managed_local_projection_transaction(
            &operations,
            set_projection_health,
            apply_projection_operation,
            persist_final_state,
            compensate_projection_receipt,
            restore_old_state,
        )
        .await
        .map_err(ManagedLocalProjectionFailure::into_control_plane_error)?;
        state.state = final_state;
        Ok(id)
    }

    pub async fn delete_group(&self, instance: &str, name: &str) -> Result<(), ControlPlaneError> {
        let _lifecycle_guard = self.lock_runtime_lifecycle().await;
        let owner_prefix = self.managed_local_owner_prefix_snapshot(instance).await;
        let inst = self.get_instance(instance).await?;
        let mut state = inst.write().await;
        match state.managed_acl_publication_mode {
            ManagedAclPublicationMode::StandaloneCompatibility
            | ManagedAclPublicationMode::NeutronAttachOwnedStandaloneAcl => {
                return self.delete_group_standalone_locked(&mut state, name).await;
            }
            ManagedAclPublicationMode::ManagedAcl => {}
        }
        managed_local_projection_admission(
            state.managed_acl_publication_mode,
            state.managed_projection_health,
        )?;
        let _owner_prefix = Self::require_managed_local_owner_prefix(instance, owner_prefix)?;
        Self::check_runtime_maps_ready(&state.pin_path)?;
        let old_state = state.state.clone();
        let group = old_state
            .groups
            .get(name)
            .ok_or_else(|| ControlPlaneError::GroupNotFound(name.to_string()))?
            .clone();
        validate_managed_group_mutation(&old_state, group.id)?;
        if old_state
            .qos_rules
            .iter()
            .any(|rule| rule.group_id == group.id)
        {
            return Err(ControlPlaneError::GroupInUse(format!(
                "Group '{}' is referenced by a QoS rule",
                name
            )));
        }
        if old_state
            .mirror_rules
            .iter()
            .any(|rule| rule.src_group_id == group.id || rule.dst_group_id == group.id)
        {
            return Err(ControlPlaneError::GroupInUse(format!(
                "Group '{}' is referenced by a mirror rule",
                name
            )));
        }
        let domain_operations = Vec::new();
        let mut final_state = old_state.clone();
        final_state.groups.remove(name);
        let general_mutations = managed_general_state_mutations(&old_state, &final_state)?;
        let projection_order = ManagedLocalProjectionOrder::GeneralThenDomain;
        let operations = merge_managed_local_projection_operations(
            projection_order,
            general_mutations,
            domain_operations,
        );
        let runtime = self.managed_local_projection_runtime(instance, &state);
        let apply_projection_operation =
            managed_local_projection_apply(runtime.clone(), &old_state);
        let compensate_projection_receipt = managed_local_projection_compensate(runtime);
        let persist_final_state = managed_local_projection_persist(&state.wal, &final_state)?;
        let restore_old_state = managed_local_projection_restore(&state.wal, &old_state)?;
        let set_projection_health = |health| {
            state.managed_projection_health = health;
        };
        execute_managed_local_projection_transaction(
            &operations,
            set_projection_health,
            apply_projection_operation,
            persist_final_state,
            compensate_projection_receipt,
            restore_old_state,
        )
        .await
        .map_err(ManagedLocalProjectionFailure::into_control_plane_error)?;
        state.state = final_state;
        if let Err(e) =
            aria_core::monitoring::clear_group_stats_for_id(state.map_runtime(), group.id)
        {
            warn!(error = %e, group_id = group.id, "failed to clear group stats after group delete");
        }
        Ok(())
    }

    // ── Groups with Stats (Aggregation) ──

    pub async fn list_groups_with_stats(
        &self,
        instance: &str,
    ) -> Result<(Vec<GroupInfo>, Vec<aria_core::monitoring::GroupStatsEntry>), ControlPlaneError>
    {
        // Get groups configuration
        let inst = self.get_instance(instance).await?;
        let state = inst.read().await;
        let groups: Vec<_> = state.state.groups.values().cloned().collect();
        let stats = aria_core::monitoring::get_group_stats(state.map_runtime())
            .map_err(|e| ControlPlaneError::KernelError(e))?;

        Ok((groups, stats))
    }

    // ── Policies ──

    pub async fn list_policies(
        &self,
        instance: &str,
    ) -> Result<(Vec<RuleInfo>, HashMap<String, GroupInfo>), ControlPlaneError> {
        let inst = self.get_instance(instance).await?;
        let state = inst.read().await;
        Ok((state.state.rules.clone(), state.state.groups.clone()))
    }

    pub async fn add_policy(
        &self,
        instance: &str,
        src_group: &str,
        dst_group: &str,
        proto: u8,
        action: u8,
        direction: u8,
        ports: Option<&str>,
    ) -> Result<(), ControlPlaneError> {
        let inst = self.get_instance(instance).await?;
        let mut state = inst.write().await;
        Self::check_runtime_maps_ready(&state.pin_path)?;

        let src_id = self.resolve_group_id(&state.state, src_group)?;
        let dst_id = self.resolve_group_id(&state.state, dst_group)?;
        Self::validate_policy_ports(proto, ports)?;

        // Snapshot state for rollback (clone the parts that apply_add_rule mutates)
        let snapshot_rules = state.state.rules.clone();
        let snapshot_port_sets = state.state.port_sets.clone();
        let snapshot_free_indices = state.state.free_bitmap_indices.clone();
        let snapshot_next_bitmap_idx = state.state.next_bitmap_idx;

        // Operate directly on in-memory state (no StateManager disk round-trip)
        let add_result = state
            .state
            .apply_add_rule(src_id, dst_id, proto, action, ports, direction)
            .map_err(|e| ControlPlaneError::ValidationError(e))?;
        let acl_bank = aria_core::ebpf_ops::read_acl_active_bank(state.map_runtime())
            .map_err(ControlPlaneError::KernelError)?;

        // Write to kernel
        if let Err(e) = aria_core::ebpf_ops::add_policy_in_bank(
            src_id,
            dst_id,
            proto,
            action,
            ports,
            add_result.bitmap_idx,
            add_result.is_new_port_set,
            direction,
            acl_bank,
            state.map_runtime(),
            &self.ebpf_path,
        ) {
            if add_result.is_new_port_set {
                if let (Some(idx), Some(ports_str)) = (add_result.bitmap_idx, ports) {
                    if let Err(cleanup_err) = aria_core::ebpf_ops::delete_port_set(
                        idx,
                        ports_str,
                        state.map_runtime(),
                        &self.ebpf_path,
                    ) {
                        warn!(error = %cleanup_err, "failed to clean new port bitmap after add_policy error");
                    }
                }
            }
            // Rollback: restore snapshotted state
            state.state.rules = snapshot_rules;
            state.state.port_sets = snapshot_port_sets;
            state.state.free_bitmap_indices = snapshot_free_indices;
            state.state.next_bitmap_idx = snapshot_next_bitmap_idx;
            return Err(ControlPlaneError::KernelError(e));
        }

        // Clean up old port set if replaced
        if let Some((old_idx, ref ports_normalized)) = add_result.old_port_set_released {
            if let Err(e) = aria_core::ebpf_ops::delete_port_set(
                old_idx,
                ports_normalized,
                state.map_runtime(),
                &self.ebpf_path,
            ) {
                warn!(error = %e, "failed to clean old port bitmap");
            }
        }

        state
            .wal_append(&WalEntry::AddRule {
                src_id,
                dst_id,
                proto,
                action,
                ports: ports.map(|s| s.to_string()),
                direction,
            })
            .await;
        Ok(())
    }

    pub async fn delete_policy(
        &self,
        instance: &str,
        src_group: &str,
        dst_group: &str,
        proto: u8,
        direction: u8,
    ) -> Result<(), ControlPlaneError> {
        let inst = self.get_instance(instance).await?;
        let mut state = inst.write().await;
        Self::check_runtime_maps_ready(&state.pin_path)?;

        let src_id = self.resolve_group_id(&state.state, src_group)?;
        let dst_id = self.resolve_group_id(&state.state, dst_group)?;

        let target_directions = Self::requested_directions(direction)?;
        let matching_rules: Vec<RuleInfo> = target_directions
            .iter()
            .filter_map(|dir| {
                state
                    .state
                    .rules
                    .iter()
                    .find(|r| {
                        r.src_group_id == src_id
                            && r.dst_group_id == dst_id
                            && r.proto == proto
                            && r.direction == *dir
                    })
                    .cloned()
            })
            .collect();
        if matching_rules.is_empty() {
            return Err(ControlPlaneError::PolicyNotFound(format!(
                "Policy not found: src={}, dst={}, proto={}, direction={}",
                src_group, dst_group, proto, direction
            )));
        }

        let mut deleted_rules: Vec<RuleInfo> = Vec::new();
        let acl_bank = aria_core::ebpf_ops::read_acl_active_bank(state.map_runtime())
            .map_err(ControlPlaneError::KernelError)?;
        for rule in &matching_rules {
            if let Err(e) = aria_core::ebpf_ops::delete_policy_in_bank(
                rule.src_group_id,
                rule.dst_group_id,
                rule.proto,
                rule.direction,
                acl_bank,
                state.map_runtime(),
                &self.ebpf_path,
            ) {
                let rollback = Self::rollback_policy_deletes(
                    state.map_runtime(),
                    &self.ebpf_path,
                    &deleted_rules,
                );
                let error = match rollback {
                    Ok(()) => e,
                    Err(rollback_err) => format!("{}; rollback failed: {}", e, rollback_err),
                };
                return Err(ControlPlaneError::KernelError(error));
            }
            deleted_rules.push(rule.clone());
        }

        let mut released_port_sets: Vec<(u32, String)> = Vec::new();
        for rule in &matching_rules {
            let remove_result = state
                .state
                .apply_remove_rule(
                    rule.src_group_id,
                    rule.dst_group_id,
                    rule.proto,
                    rule.direction,
                )
                .map_err(|e| ControlPlaneError::PolicyNotFound(e))?;

            if let (Some(idx), Some(ports_normalized)) =
                (remove_result.bitmap_idx, remove_result.port_set_released)
            {
                released_port_sets.push((idx, ports_normalized));
            }

            state
                .wal_append(&WalEntry::RemoveRule {
                    src_id: rule.src_group_id,
                    dst_id: rule.dst_group_id,
                    proto: rule.proto,
                    direction: rule.direction,
                })
                .await;
        }

        for (idx, ports_normalized) in released_port_sets {
            if let Err(e) = aria_core::ebpf_ops::delete_port_set(
                idx,
                &ports_normalized,
                state.map_runtime(),
                &self.ebpf_path,
            ) {
                warn!(error = %e, bitmap_idx = idx, "failed to clean port bitmap");
            }
        }

        // Clear stale RULE_STATS entries so deleted rules no longer appear in API responses.
        for rule in &matching_rules {
            if let Err(e) = aria_core::monitoring::clear_rule_stats_for_policy(
                state.map_runtime(),
                rule.src_group_id,
                rule.dst_group_id,
                rule.proto,
                rule.direction,
            ) {
                warn!(error = %e, "failed to clear rule stats after policy delete");
            }
        }
        Ok(())
    }

    // ── Policies with Stats (Aggregation) ──

    #[allow(dead_code)]
    pub async fn list_policies_with_stats(
        &self,
        instance: &str,
    ) -> Result<
        (
            Vec<aria_core::state::RuleInfo>,
            Vec<aria_core::monitoring::RuleStatsEntry>,
        ),
        ControlPlaneError,
    > {
        // Get policies configuration
        let inst = self.get_instance(instance).await?;
        let state = inst.read().await;
        let rules = state.state.rules.clone();
        let stats = aria_core::monitoring::get_rule_stats(state.map_runtime())
            .map_err(|e| ControlPlaneError::KernelError(e))?;

        Ok((rules, stats))
    }

    // ── QoS ──

    async fn add_qos_standalone_locked(
        &self,
        instance: &str,
        state: &mut InstanceState,
        group_name: &str,
        direction: u8,
        rate_bps: u64,
        burst_bytes: u64,
        priority: u8,
        mode: u8,
    ) -> Result<(), ControlPlaneError> {
        Self::check_runtime_maps_ready(&state.pin_path)?;
        let group_id = if group_name == "default" || group_name == "any" {
            0
        } else {
            state
                .state
                .groups
                .get(group_name)
                .map(|group| group.id)
                .ok_or_else(|| ControlPlaneError::GroupNotFound(group_name.to_string()))?
        };
        let direction_plans = managed_qos_direction_plans(direction, mode)?;
        let mut applied = Vec::<QosRuleInfo>::new();

        for plan in direction_plans {
            let mut installed_fq = None;
            if plan.effective_mode == 1 {
                let iface = Self::runtime_iface_name(instance, state)?;
                match aria_core::ebpf_ops::ensure_fq_qdisc(&iface) {
                    Ok(aria_core::ebpf_ops::FqQdiscState::InstalledNow) => {
                        if let Err(marker_error) =
                            Self::mark_owned_fq_qdisc(&state.state_path, &iface)
                        {
                            let rollback_error = Self::rollback_installed_fq_qdisc(
                                instance,
                                &iface,
                                &state.state_path,
                            )
                            .err();
                            return Err(ControlPlaneError::KernelError(domain_apply_failure(
                                marker_error.to_string(),
                                rollback_error,
                            )));
                        }
                        installed_fq = Some(iface);
                    }
                    Ok(aria_core::ebpf_ops::FqQdiscState::AlreadyPresent) => {}
                    Err(error) => {
                        return Err(ControlPlaneError::KernelError(format!(
                            "failed to prepare FQ qdisc for QoS shaping: {}",
                            error
                        )));
                    }
                }
            }

            let apply_result = aria_core::qos_ops::add_qos_rule(
                group_id,
                plan.direction,
                rate_bps,
                burst_bytes,
                priority,
                plan.effective_mode,
                state.map_runtime(),
                state.state.qos_enabled,
            );
            if let Err(error) = apply_result {
                let mut errors = vec![error];
                for previous in applied.iter().rev() {
                    if let Err(rollback_error) = aria_core::qos_ops::delete_qos_rule(
                        previous.group_id,
                        previous.direction,
                        state.map_runtime(),
                        state.state.qos_enabled,
                    ) {
                        errors.push(format!(
                            "rollback QoS direction {}: {}",
                            previous.direction, rollback_error
                        ));
                        continue;
                    }
                    state.state.qos_rules.retain(|rule| {
                        rule.group_id != previous.group_id || rule.direction != previous.direction
                    });
                    state
                        .wal_append(&WalEntry::DeleteQos {
                            group_id: previous.group_id,
                            direction: previous.direction,
                        })
                        .await;
                }
                if let Some(iface) = installed_fq {
                    if let Err(rollback_error) =
                        Self::rollback_installed_fq_qdisc(instance, &iface, &state.state_path)
                    {
                        errors.push(rollback_error);
                    }
                }
                return Err(ControlPlaneError::KernelError(errors.join("; ")));
            }

            state
                .state
                .qos_rules
                .retain(|rule| rule.group_id != group_id || rule.direction != plan.direction);
            let rule = QosRuleInfo {
                group_name: group_name.to_string(),
                group_id,
                direction: plan.direction,
                rate_bps,
                burst_bytes,
                priority,
                mode: plan.effective_mode,
            };
            state.state.qos_rules.push(rule.clone());
            state
                .wal_append(&WalEntry::AddQos {
                    group_name: rule.group_name.clone(),
                    group_id: rule.group_id,
                    direction: rule.direction,
                    rate_bps: rule.rate_bps,
                    burst_bytes: rule.burst_bytes,
                    priority: rule.priority,
                    mode: rule.mode,
                })
                .await;
            applied.push(rule);
        }
        Ok(())
    }

    async fn delete_qos_standalone_locked(
        &self,
        instance: &str,
        state: &mut InstanceState,
        group_name: &str,
        direction: u8,
    ) -> Result<(), ControlPlaneError> {
        Self::check_runtime_maps_ready(&state.pin_path)?;
        let group_id = if group_name == "default" || group_name == "any" {
            0
        } else {
            state
                .state
                .groups
                .get(group_name)
                .map(|group| group.id)
                .ok_or_else(|| ControlPlaneError::GroupNotFound(group_name.to_string()))?
        };
        let target_directions = Self::requested_directions(direction)?;
        let matching_rules = target_directions
            .iter()
            .filter_map(|direction| {
                state
                    .state
                    .qos_rules
                    .iter()
                    .find(|rule| rule.group_id == group_id && rule.direction == *direction)
                    .cloned()
            })
            .collect::<Vec<_>>();
        if matching_rules.is_empty() {
            return Err(ControlPlaneError::PolicyNotFound(format!(
                "QoS rule not found: group={}, direction={}",
                group_name, direction
            )));
        }

        let mut deleted_rules = Vec::new();
        for rule in &matching_rules {
            if let Err(error) = aria_core::qos_ops::delete_qos_rule(
                rule.group_id,
                rule.direction,
                state.map_runtime(),
                state.state.qos_enabled,
            ) {
                let rollback = Self::rollback_qos_deletes(
                    state.map_runtime(),
                    &deleted_rules,
                    state.state.qos_enabled,
                );
                let error = match rollback {
                    Ok(()) => error,
                    Err(rollback_error) => {
                        format!("{}; rollback failed: {}", error, rollback_error)
                    }
                };
                return Err(ControlPlaneError::KernelError(error));
            }
            deleted_rules.push(rule.clone());
        }

        for rule in &matching_rules {
            state.state.qos_rules.retain(|existing| {
                existing.group_id != rule.group_id || existing.direction != rule.direction
            });
            state
                .wal_append(&WalEntry::DeleteQos {
                    group_id: rule.group_id,
                    direction: rule.direction,
                })
                .await;
            if let Err(error) = aria_core::monitoring::clear_qos_stats_for_rule(
                state.map_runtime(),
                rule.group_id,
                rule.direction,
            ) {
                warn!(error = %error, group_id = rule.group_id, direction = rule.direction,
                    "failed to clear qos stats after qos rule delete");
            }
        }
        Self::cleanup_owned_fq_qdisc_if_unused(instance, state);
        Ok(())
    }

    pub async fn list_qos(&self, instance: &str) -> Result<Vec<QosRuleInfo>, ControlPlaneError> {
        let inst = self.get_instance(instance).await?;
        let state = inst.read().await;
        Ok(state.state.qos_rules.clone())
    }

    pub async fn add_qos(
        &self,
        instance: &str,
        group_name: &str,
        direction: u8,
        rate_bps: u64,
        burst_bytes: u64,
        priority: u8,
        mode: u8,
    ) -> Result<(), ControlPlaneError> {
        let _lifecycle_guard = self.lock_runtime_lifecycle().await;
        let owner_prefix = self.managed_local_owner_prefix_snapshot(instance).await;
        let inst = self.get_instance(instance).await?;
        let mut state = inst.write().await;
        match state.managed_acl_publication_mode {
            ManagedAclPublicationMode::StandaloneCompatibility
            | ManagedAclPublicationMode::NeutronAttachOwnedStandaloneAcl => {
                return self
                    .add_qos_standalone_locked(
                        instance,
                        &mut state,
                        group_name,
                        direction,
                        rate_bps,
                        burst_bytes,
                        priority,
                        mode,
                    )
                    .await;
            }
            ManagedAclPublicationMode::ManagedAcl => {}
        }
        managed_local_projection_admission(
            state.managed_acl_publication_mode,
            state.managed_projection_health,
        )?;
        let _owner_prefix = Self::require_managed_local_owner_prefix(instance, owner_prefix)?;
        Self::check_runtime_maps_ready(&state.pin_path)?;
        let old_state = state.state.clone();
        let group_id = if group_name == "default" || group_name == "any" {
            0
        } else {
            old_state
                .groups
                .get(group_name)
                .map(|group| group.id)
                .ok_or_else(|| ControlPlaneError::GroupNotFound(group_name.to_string()))?
        };
        let direction_plans = managed_qos_direction_plans(direction, mode)?;
        let domain_operations = plan_managed_local_qos_upserts(
            &old_state,
            group_name,
            group_id,
            rate_bps,
            burst_bytes,
            priority,
            &direction_plans,
        )?;
        let final_state =
            managed_local_state_after_domain_operations(&old_state, &domain_operations)?;
        let general_mutations = managed_general_state_mutations(&old_state, &final_state)?;
        let projection_order = ManagedLocalProjectionOrder::GeneralThenDomain;
        let operations = merge_managed_local_projection_operations(
            projection_order,
            general_mutations,
            domain_operations,
        );
        let runtime = self.managed_local_projection_runtime(instance, &state);
        let apply_projection_operation =
            managed_local_projection_apply(runtime.clone(), &old_state);
        let compensate_projection_receipt = managed_local_projection_compensate(runtime);
        let persist_final_state = managed_local_projection_persist(&state.wal, &final_state)?;
        let restore_old_state = managed_local_projection_restore(&state.wal, &old_state)?;
        let set_projection_health = |health| {
            state.managed_projection_health = health;
        };
        execute_managed_local_projection_transaction(
            &operations,
            set_projection_health,
            apply_projection_operation,
            persist_final_state,
            compensate_projection_receipt,
            restore_old_state,
        )
        .await
        .map_err(ManagedLocalProjectionFailure::into_control_plane_error)?;
        state.state = final_state;
        Self::cleanup_owned_fq_qdisc_if_unused(instance, &state);
        Ok(())
    }

    pub async fn delete_qos(
        &self,
        instance: &str,
        group_name: &str,
        direction: u8,
    ) -> Result<(), ControlPlaneError> {
        let _lifecycle_guard = self.lock_runtime_lifecycle().await;
        let owner_prefix = self.managed_local_owner_prefix_snapshot(instance).await;
        let inst = self.get_instance(instance).await?;
        let mut state = inst.write().await;
        match state.managed_acl_publication_mode {
            ManagedAclPublicationMode::StandaloneCompatibility
            | ManagedAclPublicationMode::NeutronAttachOwnedStandaloneAcl => {
                return self
                    .delete_qos_standalone_locked(instance, &mut state, group_name, direction)
                    .await;
            }
            ManagedAclPublicationMode::ManagedAcl => {}
        }
        managed_local_projection_admission(
            state.managed_acl_publication_mode,
            state.managed_projection_health,
        )?;
        let owner_prefix = Self::require_managed_local_owner_prefix(instance, owner_prefix)?;
        Self::check_runtime_maps_ready(&state.pin_path)?;
        let old_state = state.state.clone();
        let group_id = if group_name == "default" || group_name == "any" {
            0
        } else {
            old_state
                .groups
                .get(group_name)
                .map(|group| group.id)
                .ok_or_else(|| ControlPlaneError::GroupNotFound(group_name.to_string()))?
        };
        let directions = requested_directions(direction)?;
        let domain_operations = plan_managed_local_qos_delete(&old_state, group_id, &directions)?;
        let mut final_state =
            managed_local_state_after_domain_operations(&old_state, &domain_operations)?;
        let removed_retained_group_ids =
            reconcile_retained_owned_groups(&old_state, &mut final_state, &owner_prefix)?;
        let general_mutations = managed_general_state_mutations(&old_state, &final_state)?;
        let projection_order = ManagedLocalProjectionOrder::DomainThenGeneral;
        let operations = merge_managed_local_projection_operations(
            projection_order,
            general_mutations,
            domain_operations,
        );
        let runtime = self.managed_local_projection_runtime(instance, &state);
        let apply_projection_operation =
            managed_local_projection_apply(runtime.clone(), &old_state);
        let compensate_projection_receipt = managed_local_projection_compensate(runtime);
        let persist_final_state = managed_local_projection_persist(&state.wal, &final_state)?;
        let restore_old_state = managed_local_projection_restore(&state.wal, &old_state)?;
        let set_projection_health = |health| {
            state.managed_projection_health = health;
        };
        execute_managed_local_projection_transaction(
            &operations,
            set_projection_health,
            apply_projection_operation,
            persist_final_state,
            compensate_projection_receipt,
            restore_old_state,
        )
        .await
        .map_err(ManagedLocalProjectionFailure::into_control_plane_error)?;
        state.state = final_state;
        clear_removed_retained_owned_group_stats(&removed_retained_group_ids, state.map_runtime());
        for deleted_direction in directions {
            if let Err(error) = aria_core::monitoring::clear_qos_stats_for_rule(
                state.map_runtime(),
                group_id,
                deleted_direction,
            ) {
                warn!(error = %error, group_id, direction = deleted_direction,
                    "failed to clear qos stats after qos rule delete");
            }
        }
        Self::cleanup_owned_fq_qdisc_if_unused(instance, &state);
        Ok(())
    }

    // ── QoS with Stats (Aggregation) ──

    #[allow(dead_code)]
    pub async fn list_qos_with_stats(
        &self,
        instance: &str,
    ) -> Result<(Vec<QosRuleInfo>, Vec<aria_core::monitoring::QosStatsEntry>), ControlPlaneError>
    {
        // Get QoS configuration
        let inst = self.get_instance(instance).await?;
        let state = inst.read().await;
        let rules = state.state.qos_rules.clone();
        let stats = aria_core::monitoring::get_qos_stats(state.map_runtime())
            .map_err(|e| ControlPlaneError::KernelError(e))?;

        Ok((rules, stats))
    }

    // ── Mirror ──

    async fn add_mirror_standalone_locked(
        &self,
        state: &mut InstanceState,
        src_group: &str,
        dst_group: &str,
        proto: u8,
        direction: u8,
        target_iface: &str,
    ) -> Result<(), ControlPlaneError> {
        Self::check_runtime_maps_ready(&state.pin_path)?;
        let src_id = self.resolve_group_id(&state.state, src_group)?;
        let dst_id = self.resolve_group_id(&state.state, dst_group)?;
        let target_ifindex = aria_core::mirror_ops::resolve_ifindex(target_iface)
            .map_err(ControlPlaneError::ValidationError)?;
        let is_global = src_id == 0 && dst_id == 0 && proto == 0;
        let directions = requested_directions(direction)?;
        let mut applied = Vec::<MirrorRuleInfo>::new();

        for direction in directions {
            let result = if is_global {
                aria_core::mirror_ops::add_global_mirror(
                    direction,
                    target_ifindex,
                    state.map_runtime(),
                    state.state.mirror_enabled,
                )
            } else {
                aria_core::mirror_ops::add_mirror_rule(
                    src_id,
                    dst_id,
                    proto,
                    direction,
                    target_ifindex,
                    state.map_runtime(),
                    state.state.mirror_enabled,
                )
            };
            if let Err(error) = result {
                let mut errors = vec![error];
                for previous in applied.iter().rev() {
                    let rollback = if previous.is_global {
                        aria_core::mirror_ops::delete_global_mirror(
                            previous.direction,
                            state.map_runtime(),
                            state.state.mirror_enabled,
                        )
                    } else {
                        aria_core::mirror_ops::delete_mirror_rule(
                            previous.src_group_id,
                            previous.dst_group_id,
                            previous.proto,
                            previous.direction,
                            state.map_runtime(),
                            state.state.mirror_enabled,
                        )
                    };
                    if let Err(rollback_error) = rollback {
                        errors.push(format!(
                            "rollback Mirror direction {}: {}",
                            previous.direction, rollback_error
                        ));
                        continue;
                    }
                    if previous.is_global {
                        state.state.mirror_rules.retain(|rule| {
                            !(rule.is_global && rule.direction == previous.direction)
                        });
                    } else {
                        state.state.mirror_rules.retain(|rule| {
                            rule.is_global
                                || rule.src_group_id != previous.src_group_id
                                || rule.dst_group_id != previous.dst_group_id
                                || rule.proto != previous.proto
                                || rule.direction != previous.direction
                        });
                    }
                    state
                        .wal_append(&WalEntry::DeleteMirror {
                            src_group_id: previous.src_group_id,
                            dst_group_id: previous.dst_group_id,
                            proto: previous.proto,
                            direction: previous.direction,
                            is_global: previous.is_global,
                        })
                        .await;
                }
                return Err(ControlPlaneError::KernelError(errors.join("; ")));
            }

            if is_global {
                state
                    .state
                    .mirror_rules
                    .retain(|rule| !(rule.is_global && rule.direction == direction));
            } else {
                state.state.mirror_rules.retain(|rule| {
                    rule.is_global
                        || rule.src_group_id != src_id
                        || rule.dst_group_id != dst_id
                        || rule.proto != proto
                        || rule.direction != direction
                });
            }
            let rule = MirrorRuleInfo {
                src_group_name: src_group.to_string(),
                src_group_id: src_id,
                dst_group_name: dst_group.to_string(),
                dst_group_id: dst_id,
                proto,
                direction,
                target_iface: target_iface.to_string(),
                target_ifindex,
                is_global,
            };
            state.state.mirror_rules.push(rule.clone());
            state
                .wal_append(&WalEntry::AddMirror {
                    src_group_name: rule.src_group_name.clone(),
                    src_group_id: rule.src_group_id,
                    dst_group_name: rule.dst_group_name.clone(),
                    dst_group_id: rule.dst_group_id,
                    proto: rule.proto,
                    direction: rule.direction,
                    target_iface: rule.target_iface.clone(),
                    target_ifindex: rule.target_ifindex,
                    is_global: rule.is_global,
                })
                .await;
            applied.push(rule);
        }
        Ok(())
    }

    async fn delete_mirror_standalone_locked(
        &self,
        state: &mut InstanceState,
        src_group: &str,
        dst_group: &str,
        proto: u8,
        direction: u8,
    ) -> Result<(), ControlPlaneError> {
        Self::check_runtime_maps_ready(&state.pin_path)?;
        let src_id = self.resolve_group_id(&state.state, src_group)?;
        let dst_id = self.resolve_group_id(&state.state, dst_group)?;
        let is_global = src_id == 0 && dst_id == 0 && proto == 0;
        let target_directions = Self::requested_directions(direction)?;
        let matching_rules = target_directions
            .iter()
            .filter_map(|direction| {
                state
                    .state
                    .mirror_rules
                    .iter()
                    .find(|rule| {
                        if is_global {
                            rule.is_global && rule.direction == *direction
                        } else {
                            !rule.is_global
                                && rule.src_group_id == src_id
                                && rule.dst_group_id == dst_id
                                && rule.proto == proto
                                && rule.direction == *direction
                        }
                    })
                    .cloned()
            })
            .collect::<Vec<_>>();
        if matching_rules.is_empty() {
            return Err(ControlPlaneError::PolicyNotFound(
                "Mirror rule not found".to_string(),
            ));
        }

        let mut deleted_rules = Vec::new();
        for rule in &matching_rules {
            let result = if rule.is_global {
                aria_core::mirror_ops::delete_global_mirror(
                    rule.direction,
                    state.map_runtime(),
                    state.state.mirror_enabled,
                )
            } else {
                aria_core::mirror_ops::delete_mirror_rule(
                    rule.src_group_id,
                    rule.dst_group_id,
                    rule.proto,
                    rule.direction,
                    state.map_runtime(),
                    state.state.mirror_enabled,
                )
            };
            if let Err(error) = result {
                let rollback = Self::rollback_mirror_deletes(
                    state.map_runtime(),
                    &deleted_rules,
                    state.state.mirror_enabled,
                );
                let error = match rollback {
                    Ok(()) => error,
                    Err(rollback_error) => {
                        format!("{}; rollback failed: {}", error, rollback_error)
                    }
                };
                return Err(ControlPlaneError::KernelError(error));
            }
            deleted_rules.push(rule.clone());
        }

        for rule in &matching_rules {
            if rule.is_global {
                state.state.mirror_rules.retain(|existing| {
                    !(existing.is_global && existing.direction == rule.direction)
                });
            } else {
                state.state.mirror_rules.retain(|existing| {
                    existing.is_global
                        || existing.src_group_id != rule.src_group_id
                        || existing.dst_group_id != rule.dst_group_id
                        || existing.proto != rule.proto
                        || existing.direction != rule.direction
                });
            }
            state
                .wal_append(&WalEntry::DeleteMirror {
                    src_group_id: rule.src_group_id,
                    dst_group_id: rule.dst_group_id,
                    proto: rule.proto,
                    direction: rule.direction,
                    is_global: rule.is_global,
                })
                .await;
            let clear_result = if rule.is_global {
                aria_core::mirror_ops::clear_global_mirror_stats(
                    rule.direction,
                    state.map_runtime(),
                )
            } else {
                aria_core::mirror_ops::clear_mirror_rule_stats(
                    rule.src_group_id,
                    rule.dst_group_id,
                    rule.proto,
                    rule.direction,
                    state.map_runtime(),
                )
            };
            if let Err(error) = clear_result {
                warn!(error = %error, direction = rule.direction,
                    "failed to clear mirror stats after delete");
            }
        }
        Ok(())
    }

    pub async fn list_mirror(
        &self,
        instance: &str,
    ) -> Result<Vec<MirrorRuleInfo>, ControlPlaneError> {
        let inst = self.get_instance(instance).await?;
        let state = inst.read().await;
        Ok(state.state.mirror_rules.clone())
    }

    pub async fn add_mirror(
        &self,
        instance: &str,
        src_group: &str,
        dst_group: &str,
        proto: u8,
        direction: u8,
        target_iface: &str,
    ) -> Result<(), ControlPlaneError> {
        let _lifecycle_guard = self.lock_runtime_lifecycle().await;
        let owner_prefix = self.managed_local_owner_prefix_snapshot(instance).await;
        let inst = self.get_instance(instance).await?;
        let mut state = inst.write().await;
        match state.managed_acl_publication_mode {
            ManagedAclPublicationMode::StandaloneCompatibility
            | ManagedAclPublicationMode::NeutronAttachOwnedStandaloneAcl => {
                return self
                    .add_mirror_standalone_locked(
                        &mut state,
                        src_group,
                        dst_group,
                        proto,
                        direction,
                        target_iface,
                    )
                    .await;
            }
            ManagedAclPublicationMode::ManagedAcl => {}
        }
        managed_local_projection_admission(
            state.managed_acl_publication_mode,
            state.managed_projection_health,
        )?;
        let _owner_prefix = Self::require_managed_local_owner_prefix(instance, owner_prefix)?;
        Self::check_runtime_maps_ready(&state.pin_path)?;
        let old_state = state.state.clone();
        let src_id = self.resolve_group_id(&old_state, src_group)?;
        let dst_id = self.resolve_group_id(&old_state, dst_group)?;
        let directions = requested_directions(direction)?;
        let target_ifindex = resolve_managed_mirror_target_ifindex(target_iface)?;
        let domain_operations = plan_managed_local_mirror_upserts(
            &old_state,
            src_group,
            src_id,
            dst_group,
            dst_id,
            proto,
            target_iface,
            target_ifindex,
            &directions,
        )?;
        let final_state =
            managed_local_state_after_domain_operations(&old_state, &domain_operations)?;
        let general_mutations = managed_general_state_mutations(&old_state, &final_state)?;
        let projection_order = ManagedLocalProjectionOrder::GeneralThenDomain;
        let operations = merge_managed_local_projection_operations(
            projection_order,
            general_mutations,
            domain_operations,
        );
        let runtime = self.managed_local_projection_runtime(instance, &state);
        let apply_projection_operation =
            managed_local_projection_apply(runtime.clone(), &old_state);
        let compensate_projection_receipt = managed_local_projection_compensate(runtime);
        let persist_final_state = managed_local_projection_persist(&state.wal, &final_state)?;
        let restore_old_state = managed_local_projection_restore(&state.wal, &old_state)?;
        let set_projection_health = |health| {
            state.managed_projection_health = health;
        };
        execute_managed_local_projection_transaction(
            &operations,
            set_projection_health,
            apply_projection_operation,
            persist_final_state,
            compensate_projection_receipt,
            restore_old_state,
        )
        .await
        .map_err(ManagedLocalProjectionFailure::into_control_plane_error)?;
        state.state = final_state;
        Ok(())
    }

    pub async fn delete_mirror(
        &self,
        instance: &str,
        src_group: &str,
        dst_group: &str,
        proto: u8,
        direction: u8,
    ) -> Result<(), ControlPlaneError> {
        let _lifecycle_guard = self.lock_runtime_lifecycle().await;
        let owner_prefix = self.managed_local_owner_prefix_snapshot(instance).await;
        let inst = self.get_instance(instance).await?;
        let mut state = inst.write().await;
        match state.managed_acl_publication_mode {
            ManagedAclPublicationMode::StandaloneCompatibility
            | ManagedAclPublicationMode::NeutronAttachOwnedStandaloneAcl => {
                return self
                    .delete_mirror_standalone_locked(
                        &mut state, src_group, dst_group, proto, direction,
                    )
                    .await;
            }
            ManagedAclPublicationMode::ManagedAcl => {}
        }
        managed_local_projection_admission(
            state.managed_acl_publication_mode,
            state.managed_projection_health,
        )?;
        let owner_prefix = Self::require_managed_local_owner_prefix(instance, owner_prefix)?;
        Self::check_runtime_maps_ready(&state.pin_path)?;
        let old_state = state.state.clone();
        let src_id = self.resolve_group_id(&old_state, src_group)?;
        let dst_id = self.resolve_group_id(&old_state, dst_group)?;
        let is_global = src_id == 0 && dst_id == 0 && proto == 0;
        let directions = requested_directions(direction)?;
        let domain_operations =
            plan_managed_local_mirror_delete(&old_state, src_id, dst_id, proto, &directions)?;
        let mut final_state =
            managed_local_state_after_domain_operations(&old_state, &domain_operations)?;
        let removed_retained_group_ids =
            reconcile_retained_owned_groups(&old_state, &mut final_state, &owner_prefix)?;
        let general_mutations = managed_general_state_mutations(&old_state, &final_state)?;
        let projection_order = ManagedLocalProjectionOrder::DomainThenGeneral;
        let operations = merge_managed_local_projection_operations(
            projection_order,
            general_mutations,
            domain_operations,
        );
        let runtime = self.managed_local_projection_runtime(instance, &state);
        let apply_projection_operation =
            managed_local_projection_apply(runtime.clone(), &old_state);
        let compensate_projection_receipt = managed_local_projection_compensate(runtime);
        let persist_final_state = managed_local_projection_persist(&state.wal, &final_state)?;
        let restore_old_state = managed_local_projection_restore(&state.wal, &old_state)?;
        let set_projection_health = |health| {
            state.managed_projection_health = health;
        };
        execute_managed_local_projection_transaction(
            &operations,
            set_projection_health,
            apply_projection_operation,
            persist_final_state,
            compensate_projection_receipt,
            restore_old_state,
        )
        .await
        .map_err(ManagedLocalProjectionFailure::into_control_plane_error)?;
        state.state = final_state;
        clear_removed_retained_owned_group_stats(&removed_retained_group_ids, state.map_runtime());
        clear_managed_mirror_stats_after_delete(
            instance,
            src_id,
            dst_id,
            proto,
            is_global,
            &directions,
            state.map_runtime(),
        );
        Ok(())
    }

    pub async fn get_mirror_stats(
        &self,
        instance: &str,
    ) -> Result<
        (
            Vec<aria_core::monitoring::MirrorStatsEntry>,
            HashMap<String, GroupInfo>,
        ),
        ControlPlaneError,
    > {
        let inst = self.get_instance(instance).await?;
        let state = inst.read().await;
        let stats = aria_core::monitoring::get_mirror_stats(state.map_runtime())
            .map_err(|e| ControlPlaneError::KernelError(e))?;
        Ok((stats, state.state.groups.clone()))
    }

    // ── Mirror with Stats (Aggregation) ──

    #[allow(dead_code)]
    pub async fn list_mirror_with_stats(
        &self,
        instance: &str,
    ) -> Result<
        (
            Vec<MirrorRuleInfo>,
            Vec<aria_core::monitoring::MirrorStatsEntry>,
        ),
        ControlPlaneError,
    > {
        // Get mirror configuration
        let inst = self.get_instance(instance).await?;
        let state = inst.read().await;
        let rules = state.state.mirror_rules.clone();
        let stats = aria_core::monitoring::get_mirror_stats(state.map_runtime())
            .map_err(|e| ControlPlaneError::KernelError(e))?;

        Ok((rules, stats))
    }

    // ── Conntrack ──

    pub async fn list_conntrack(
        &self,
        instance: &str,
    ) -> Result<Vec<aria_core::ct_ops::CtEntry>, ControlPlaneError> {
        let inst = self.get_instance(instance).await?;
        let state = inst.read().await;
        aria_core::ct_ops::ct_list(state.map_runtime())
            .map_err(|e| ControlPlaneError::KernelError(e))
    }

    pub async fn flush_conntrack(&self, instance: &str) -> Result<u64, ControlPlaneError> {
        let inst = self.get_instance(instance).await?;
        let state = inst.read().await;
        aria_core::ct_ops::ct_flush(state.map_runtime())
            .map_err(|e| ControlPlaneError::KernelError(e))
    }

    pub async fn flush_conntrack_strict(&self, instance: &str) -> Result<u64, ControlPlaneError> {
        let inst = self.get_instance(instance).await?;
        let state = inst.read().await;
        aria_core::ct_ops::scrub_ct_tables_strict(state.map_runtime())
            .map_err(ControlPlaneError::KernelError)
    }

    pub async fn require_tc_acl_ready(&self, instance: &str) -> Result<(), ControlPlaneError> {
        let inst = self.get_instance(instance).await?;
        let state = inst.read().await;
        Self::require_tc_acl_ready_locked(instance, &state, self.trace_map_mode())
    }

    pub(crate) async fn update_neutron_acl_runtime_gate_serialized(
        &self,
        instance: &str,
        conntrack_enabled: bool,
        acl_enabled: bool,
        allow_recovery_publication: bool,
    ) -> Result<(), ControlPlaneError> {
        let inst = self.get_instance(instance).await?;
        let mut state = inst.write().await;
        if neutron_acl_gate_requires_tc(conntrack_enabled, acl_enabled) {
            Self::require_tc_acl_ready_locked(instance, &state, self.trace_map_mode())?;
            if neutron_acl_gate_requires_full_resync(
                conntrack_enabled,
                acl_enabled,
                state.runtime_health.acl_ready,
                allow_recovery_publication,
            ) {
                return Err(ControlPlaneError::InstanceNotReady(
                    "tc_acl_full_resync_required".to_string(),
                ));
            }
        }
        aria_core::ebpf_ops::update_acl_runtime_gate(
            state.map_runtime(),
            conntrack_enabled,
            acl_enabled,
            aria_core::common::ACL_INGRESS_HOOK_TC,
        )
        .map_err(ControlPlaneError::KernelError)?;

        state.state.conntrack_enabled = conntrack_enabled;
        state.state.acl_enabled = acl_enabled;
        let persistence_result = state
            .wal_append_strict(&WalEntry::UpdateConfig {
                conntrack: Some(conntrack_enabled),
                monitoring: None,
                acl: Some(acl_enabled),
                qos: None,
                mirror: None,
                tcprt: None,
                ssl: None,
            })
            .await;
        if let Err(persistence_error) = persistence_result {
            let pin_path = state.pin_path.clone();
            let tap_id = state.tap_id;
            let recovery_error = state
                .recover_gate_persistence_failure(
                    conntrack_enabled,
                    acl_enabled,
                    persistence_error,
                    |safe_conntrack, safe_acl| {
                        aria_core::ebpf_ops::update_acl_runtime_gate(
                            TapMapRuntime::new(&pin_path, tap_id),
                            safe_conntrack,
                            safe_acl,
                            aria_core::common::ACL_INGRESS_HOOK_TC,
                        )
                    },
                )
                .await;
            return Err(recovery_error);
        }
        match neutron_gate_health_commit_action(
            conntrack_enabled,
            acl_enabled,
            allow_recovery_publication,
        ) {
            NeutronGateHealthCommitAction::ClearDisabled => {
                state.runtime_health.acl_ready = true;
                state.runtime_health.acl_error = None;
            }
            NeutronGateHealthCommitAction::VerifyRecoveryPublication => {
                let xdp_ready = self.runtime_xdp_health_locked(instance, &state);
                if let Err(readiness_error) = Self::mark_tc_acl_runtime_ready_locked(
                    instance,
                    &mut state,
                    xdp_ready,
                    self.trace_map_mode(),
                ) {
                    let quiesce_result = Self::quiesce_tc_acl_runtime_locked(instance, &state);
                    let (health, error) = apply_recovery_publication_quiesce_result(
                        state.runtime_health.clone(),
                        readiness_error,
                        quiesce_result,
                    );
                    state.runtime_health = health;
                    return Err(error);
                }
            }
            NeutronGateHealthCommitAction::Preserve => {}
        }
        Ok(())
    }

    // ── Config ──

    pub async fn get_config(
        &self,
        instance: &str,
    ) -> Result<aria_core::common::FirewallConfig, ControlPlaneError> {
        let inst = self.get_instance(instance).await?;
        let mut cfg = {
            let state = inst.read().await;
            aria_core::ebpf_ops::read_runtime_config(state.map_runtime())
                .map_err(|e| ControlPlaneError::KernelError(e))?
        };
        if let Ok(enabled) = self.get_ssl_global_config().await {
            cfg.ssl_enabled = if enabled { 1 } else { 0 };
        }
        Ok(cfg)
    }

    pub async fn update_config(
        &self,
        instance: &str,
        conntrack: Option<bool>,
        monitoring: Option<bool>,
        acl: Option<bool>,
        qos: Option<bool>,
        mirror: Option<bool>,
        tcprt: Option<bool>,
        ssl: Option<bool>,
    ) -> Result<(), ControlPlaneError> {
        let _lifecycle_guard = self.lock_runtime_lifecycle().await;
        let inst = self.get_instance(instance).await?;
        let only_ssl = ssl.is_some()
            && conntrack.is_none()
            && monitoring.is_none()
            && acl.is_none()
            && qos.is_none()
            && mirror.is_none()
            && tcprt.is_none();

        if let Some(enabled) = ssl {
            self.set_ssl_global_config(enabled).await?;
            if only_ssl {
                return Ok(());
            }
        }

        let mut state = inst.write().await;
        Self::check_runtime_maps_ready(&state.pin_path)?;
        if config_update_requires_tc(conntrack, acl) {
            Self::require_tc_acl_ready_locked(instance, &state, self.trace_map_mode())?;
        }
        let old_state = state.state.clone();
        let attempted_enable = conntrack == Some(true) || acl == Some(true);

        // For QoS, the kernel flag = user_wants_qos && has_rules
        let kernel_qos = qos.map(|q| q && !state.state.qos_rules.is_empty());
        // For mirror, the kernel flag = user_wants_mirror && has_rules
        let kernel_mirror = mirror.map(|m| m && !state.state.mirror_rules.is_empty());

        if let Err(e) = aria_core::ebpf_ops::update_runtime_config(
            state.map_runtime(),
            conntrack,
            monitoring,
            acl,
            kernel_qos,
            kernel_mirror,
            tcprt,
            None,
        ) {
            return Err(ControlPlaneError::KernelError(e));
        }

        if let Some(ct) = conntrack {
            state.state.conntrack_enabled = ct;
        }
        if let Some(mon) = monitoring {
            state.state.monitoring_enabled = mon;
        }
        if let Some(a) = acl {
            state.state.acl_enabled = a;
        }
        if let Some(q) = qos {
            state.state.qos_enabled = q;
        }
        if let Some(m) = mirror {
            state.state.mirror_enabled = m;
        }
        if let Some(t) = tcprt {
            state.state.tcprt_enabled = t;
        }
        let persistence_result = state
            .wal_append_strict(&WalEntry::UpdateConfig {
                conntrack,
                monitoring,
                acl,
                qos,
                mirror,
                tcprt,
                ssl: None,
            })
            .await;
        if let Err(persistence_error) = persistence_result {
            let pin_path = state.pin_path.clone();
            let tap_id = state.tap_id;
            let recovery_error = state
                .recover_local_config_persistence_failure(
                    old_state,
                    attempted_enable,
                    persistence_error,
                    |safe_state| {
                        aria_core::ebpf_ops::update_runtime_config(
                            TapMapRuntime::new(&pin_path, tap_id),
                            Some(safe_state.conntrack_enabled),
                            Some(safe_state.monitoring_enabled),
                            Some(safe_state.acl_enabled),
                            Some(safe_state.qos_enabled && !safe_state.qos_rules.is_empty()),
                            Some(safe_state.mirror_enabled && !safe_state.mirror_rules.is_empty()),
                            Some(safe_state.tcprt_enabled),
                            None,
                        )
                    },
                )
                .await;
            return Err(recovery_error);
        }
        if attempted_enable {
            let xdp_ready = state.runtime_health.xdp_ready;
            Self::mark_tc_acl_runtime_ready_locked(
                instance,
                &mut state,
                xdp_ready,
                self.trace_map_mode(),
            )?;
        } else if !state.state.conntrack_enabled && !state.state.acl_enabled {
            state.runtime_health.acl_ready = true;
            state.runtime_health.acl_error = None;
        }
        Ok(())
    }

    // ── Global SSL Observability Config ──
    // SSL uprobe is process-level, not tied to any network interface

    pub async fn get_ssl_global_config(&self) -> Result<bool, ControlPlaneError> {
        self.ssl_manager
            .ensure_loaded()
            .await
            .map_err(ControlPlaneError::KernelError)?;
        aria_core::ssl_ops::get_ssl_global_config(self.ssl_manager.pin_path())
            .map_err(|e| ControlPlaneError::KernelError(e))
    }

    pub async fn set_ssl_global_config(&self, enabled: bool) -> Result<(), ControlPlaneError> {
        self.ssl_manager
            .ensure_loaded()
            .await
            .map_err(ControlPlaneError::KernelError)?;
        aria_core::ssl_ops::set_ssl_global_config(self.ssl_manager.pin_path(), enabled)
            .map_err(ControlPlaneError::KernelError)?;
        info!(enabled, "updated global SSL config");
        self.reconcile_ssl_runtime_state_with_desired(enabled).await;
        Ok(())
    }

    pub async fn get_ssl_errors(
        &self,
    ) -> Result<Vec<aria_core::ssl_ops::SslErrorEntry>, ControlPlaneError> {
        self.ssl_manager
            .ensure_loaded()
            .await
            .map_err(ControlPlaneError::KernelError)?;
        aria_core::ssl_ops::get_ssl_errors(self.ssl_manager.pin_path())
            .map_err(|e| ControlPlaneError::KernelError(e))
    }

    pub async fn flush_ssl_errors(&self) -> Result<u64, ControlPlaneError> {
        self.ssl_manager
            .ensure_loaded()
            .await
            .map_err(ControlPlaneError::KernelError)?;
        aria_core::ssl_ops::flush_ssl_errors(self.ssl_manager.pin_path())
            .map_err(|e| ControlPlaneError::KernelError(e))
    }

    pub async fn batch_query_tcprt(
        &self,
        tuples: &[(String, String, u16, u16)],
    ) -> Result<Vec<(String, aria_core::tcprt_ops::TcpRtEntry)>, ControlPlaneError> {
        let instances = self.instances.read().await;
        let mut results = Vec::new();
        for (name, inst) in instances.iter() {
            let state = inst.read().await;
            let entries = aria_core::tcprt_ops::lookup_tcprt_flows(state.map_runtime(), tuples)
                .unwrap_or_default();
            for entry in entries {
                results.push((name.clone(), entry));
            }
        }
        Ok(results)
    }

    pub async fn filter_tcprt(
        &self,
        dst_ip: &str,
        dst_port: u16,
    ) -> Result<Vec<(String, Vec<aria_core::tcprt_ops::TcpRtEntry>)>, ControlPlaneError> {
        let instances = self.instances.read().await;
        let mut results = Vec::new();
        for (name, inst) in instances.iter() {
            let state = inst.read().await;
            let entries =
                aria_core::tcprt_ops::filter_tcprt_flows(state.map_runtime(), dst_ip, dst_port)
                    .unwrap_or_default();
            if !entries.is_empty() {
                results.push((name.clone(), entries));
            }
        }
        Ok(results)
    }

    // ── Service Chains ──

    pub async fn list_chains(&self) -> Vec<ServiceChain> {
        let chains = self.chains.read().await;
        chains.clone()
    }

    pub async fn get_chain(&self, name: &str) -> Result<ServiceChain, ControlPlaneError> {
        let chains = self.chains.read().await;
        chains
            .iter()
            .find(|c| c.name == name)
            .cloned()
            .ok_or_else(|| {
                ControlPlaneError::InstanceNotFound(format!("Service chain '{}' not found", name))
            })
    }

    pub async fn create_chain(&self, chain: ServiceChain) -> Result<(), ControlPlaneError> {
        let mut chains = self.chains.write().await;
        // Upsert: replace if exists
        chains.retain(|c| c.name != chain.name);
        chains.push(chain);
        service_chain::save_chains(&self.base_state_path, &chains)
            .map_err(|e| ControlPlaneError::KernelError(e))
    }

    pub async fn delete_chain(&self, name: &str) -> Result<(), ControlPlaneError> {
        let mut chains = self.chains.write().await;
        let before = chains.len();
        chains.retain(|c| c.name != name);
        if chains.len() == before {
            return Err(ControlPlaneError::InstanceNotFound(format!(
                "Service chain '{}' not found",
                name
            )));
        }
        service_chain::save_chains(&self.base_state_path, &chains)
            .map_err(|e| ControlPlaneError::KernelError(e))
    }

    // ── Compact (WAL persistence) ──

    /// Compact all instances unconditionally (used on shutdown)
    pub async fn compact_all(&self) {
        let instances = self.instances.read().await;
        for (_name, inst) in instances.iter() {
            let mut state = inst.write().await;
            state.do_compact().await;
        }
    }

    /// Compact instances whose WAL exceeds the entry count threshold or time interval
    pub async fn compact_if_needed(&self) {
        let instances = self.instances.read().await;
        for (_name, inst) in instances.iter() {
            let mut state = inst.write().await;
            if state.wal_needs_compact(WAL_COMPACT_THRESHOLD) {
                state.do_compact().await;
            }
        }
    }

    /// Compact a specific instance
    async fn compact_instance(&self, name: &str) {
        let instances = self.instances.read().await;
        if let Some(inst) = instances.get(name) {
            let mut state = inst.write().await;
            state.do_compact().await;
        }
    }

    // ── Helpers ──

    async fn read_ssl_global_config(&self) -> Result<bool, String> {
        self.ssl_manager.ensure_loaded().await?;
        aria_core::ssl_ops::get_ssl_global_config(self.ssl_manager.pin_path())
    }

    fn resolve_ifindex(iface: &str) -> Result<u32, String> {
        let path = format!("/sys/class/net/{}/ifindex", iface);
        let raw = std::fs::read_to_string(&path)
            .map_err(|e| format!("failed to read ifindex for {}: {}", iface, e))?;
        raw.trim()
            .parse::<u32>()
            .map_err(|e| format!("invalid ifindex for {}: {}", iface, e))
    }

    async fn ensure_managed_tap_id(
        &self,
        name: &str,
        state: &mut FirewallState,
    ) -> Result<bool, String> {
        if state.tap_id != aria_core::common::TAP_ID_UNASSIGNED {
            return Ok(false);
        }

        let _guard = self.tap_id_lock.lock().await;
        if state.tap_id != aria_core::common::TAP_ID_UNASSIGNED {
            return Ok(false);
        }

        state.tap_id = self.next_available_tap_id(Some(name)).await?;
        Ok(true)
    }

    async fn next_available_tap_id(&self, exclude_name: Option<&str>) -> Result<u32, String> {
        let mut used = HashSet::new();

        for (name, inst) in self.instance_entries().await {
            if exclude_name == Some(name.as_str()) {
                continue;
            }
            let state = inst.read().await;
            if state.tap_id != aria_core::common::TAP_ID_UNASSIGNED {
                used.insert(state.tap_id);
            }
        }

        let state_root = std::path::Path::new(&self.base_state_path);
        if state_root.exists() {
            let entries = std::fs::read_dir(state_root).map_err(|e| {
                format!("failed to scan state root {}: {}", self.base_state_path, e)
            })?;
            for entry in entries {
                let entry = entry.map_err(|e| format!("failed to read state dir entry: {}", e))?;
                let file_type = entry
                    .file_type()
                    .map_err(|e| format!("failed to inspect state dir entry: {}", e))?;
                if !file_type.is_dir() {
                    continue;
                }

                let entry_name = entry.file_name().to_string_lossy().to_string();
                if exclude_name == Some(entry_name.as_str()) {
                    continue;
                }

                let state_path = entry.path().to_string_lossy().to_string();
                let state = aria_core::wal::load_with_wal(&state_path);
                if state.tap_id != aria_core::common::TAP_ID_UNASSIGNED {
                    used.insert(state.tap_id);
                }
            }
        }

        let mut next = aria_core::common::FIRST_MANAGED_TAP_ID;
        while used.contains(&next) {
            next += 1;
        }

        Ok(next)
    }

    fn sync_pinned_ssl_config(
        &self,
        runtime: TapMapRuntime<'_>,
        enabled: bool,
    ) -> Result<(), String> {
        let cfg_path = format!("{}/FIREWALL_CONFIG", runtime.pin_path);
        if !std::path::Path::new(&cfg_path).exists() {
            return Err("FIREWALL_CONFIG map not ready".to_string());
        }
        aria_core::ebpf_ops::update_firewall_config(
            runtime,
            None,
            None,
            None,
            None,
            None,
            None,
            Some(enabled),
        )
    }

    pub async fn reconcile_ssl_runtime_state(&self) {
        let desired = match self.read_ssl_global_config().await {
            Ok(enabled) => enabled,
            Err(e) => {
                warn!(error = %e, "failed to read global SSL config during periodic reconcile");
                return;
            }
        };

        self.reconcile_ssl_runtime_state_with_desired(desired).await;
    }

    async fn reconcile_ssl_runtime_state_with_desired(&self, enabled: bool) {
        let instances = self.instance_entries().await;
        let mut repaired_instances = 0usize;

        for (name, inst) in instances {
            if self
                .reconcile_instance_ssl_state(&name, &inst, enabled)
                .await
                == SslSyncStatus::Repaired
            {
                repaired_instances += 1;
            }
        }

        if repaired_instances > 0 {
            info!(
                enabled,
                repaired_instances, "reconciled runtime SSL config on pending instances"
            );
        }
    }

    async fn instance_entries(&self) -> Vec<(String, Arc<tokio::sync::RwLock<InstanceState>>)> {
        let instances = self.instances.read().await;
        instances
            .iter()
            .map(|(name, inst)| (name.clone(), inst.clone()))
            .collect()
    }

    async fn reconcile_instance_ssl_state(
        &self,
        name: &str,
        inst: &Arc<tokio::sync::RwLock<InstanceState>>,
        enabled: bool,
    ) -> SslSyncStatus {
        let mut state = inst.write().await;

        if state.state.ssl_enabled != enabled {
            state.state.ssl_enabled = enabled;
            state
                .wal_append(&WalEntry::UpdateConfig {
                    conntrack: None,
                    monitoring: None,
                    acl: None,
                    qos: None,
                    mirror: None,
                    tcprt: None,
                    ssl: Some(enabled),
                })
                .await;
        }

        match aria_core::ebpf_ops::read_runtime_config(state.map_runtime()) {
            Ok(cfg) if (cfg.ssl_enabled != 0) == enabled => {
                if state.ssl_sync_pending {
                    state.ssl_sync_pending = false;
                    state.last_ssl_sync_error = None;
                    info!(instance = %name, enabled, "runtime SSL config reconciled");
                    return SslSyncStatus::Repaired;
                }
                return SslSyncStatus::InSync;
            }
            Ok(_) | Err(_) => {}
        }

        match self.sync_pinned_ssl_config(state.map_runtime(), enabled) {
            Ok(()) => {
                let repaired = state.ssl_sync_pending;
                state.ssl_sync_pending = false;
                state.last_ssl_sync_error = None;
                if repaired {
                    info!(instance = %name, enabled, "runtime SSL config reconciled");
                    SslSyncStatus::Repaired
                } else {
                    SslSyncStatus::InSync
                }
            }
            Err(e) => {
                let should_log = !state.ssl_sync_pending
                    || state.last_ssl_sync_error.as_deref() != Some(e.as_str());
                state.ssl_sync_pending = true;
                state.last_ssl_sync_error = Some(e.clone());
                if should_log {
                    warn!(instance = %name, enabled, error = %e, "failed to sync runtime SSL config");
                }
                SslSyncStatus::Pending
            }
        }
    }

    fn resolve_group_id(
        &self,
        state: &FirewallState,
        name: &str,
    ) -> Result<u32, ControlPlaneError> {
        if name == "any" {
            Ok(0)
        } else {
            state
                .groups
                .get(name)
                .map(|g| g.id)
                .ok_or_else(|| ControlPlaneError::GroupNotFound(name.to_string()))
        }
    }

    /// Find group name by id
    #[allow(dead_code)]
    pub fn group_name_by_id(state: &FirewallState, id: u32) -> String {
        if id == 0 {
            return "any".to_string();
        }
        state
            .groups
            .values()
            .find(|g| g.id == id)
            .map(|g| g.name.clone())
            .unwrap_or_else(|| format!("id:{}", id))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tc_health_loss_is_deduplicated_and_never_auto_restores_ready() {
        let ready = RuntimeHealthState {
            acl_ready: true,
            xdp_ready: true,
            acl_error: None,
        };
        let lost = apply_tc_health_observation(
            ready,
            crate::instance::TcAclLinkHealth::new(true, false, true),
        );
        assert!(lost.changed);
        assert!(!lost.next.acl_ready);
        assert_eq!(lost.next.acl_error.as_deref(), Some("missing_tc_egress"));

        let repeated = apply_tc_health_observation(
            lost.next.clone(),
            crate::instance::TcAclLinkHealth::new(true, false, true),
        );
        assert!(!repeated.changed);

        let links_returned = apply_tc_health_observation(
            lost.next,
            crate::instance::TcAclLinkHealth::new(true, true, true),
        );
        assert!(!links_returned.next.acl_ready);
        assert_eq!(
            links_returned.next.acl_error.as_deref(),
            Some("recovery_required")
        );
    }

    #[test]
    fn tc_health_loss_keeps_xdp_independent_and_disabled_acl_ready() {
        let xdp_lost = apply_tc_health_observation(
            RuntimeHealthState {
                acl_ready: true,
                xdp_ready: true,
                acl_error: None,
            },
            TcAclLinkHealth::new(true, true, false),
        );
        assert!(xdp_lost.next.acl_ready);
        assert!(!xdp_lost.next.xdp_ready);
        assert!(!xdp_lost.quiesce_acl_ct);

        let disabled = initial_runtime_health(
            false,
            false,
            TcAclLinkHealth::new(false, false, false),
            false,
        );
        assert!(disabled.acl_ready);
        assert!(!disabled.xdp_ready);
    }

    #[test]
    fn tc_health_loss_quiesce_failure_retries_until_success_without_reason_loss() {
        let failed_state = RuntimeHealthState {
            acl_ready: false,
            xdp_ready: true,
            acl_error: Some("acl_quiesce_failed:map unavailable".to_string()),
        };

        let missing_retry = apply_tc_health_observation(
            failed_state.clone(),
            TcAclLinkHealth::new(false, true, true),
        );
        assert!(missing_retry.quiesce_acl_ct);
        assert_eq!(
            missing_retry.next.acl_error.as_deref(),
            Some("missing_tc_ingress")
        );
        let (missing_failed_again, quiesced) =
            apply_tc_health_quiesce_result(missing_retry.next, Err("map unavailable".to_string()));
        assert!(!quiesced);
        assert_eq!(missing_failed_again, failed_state);

        let healthy_retry = apply_tc_health_observation(
            failed_state.clone(),
            TcAclLinkHealth::new(true, true, true),
        );
        assert!(healthy_retry.quiesce_acl_ct);
        assert_eq!(
            healthy_retry.next.acl_error.as_deref(),
            Some("recovery_required")
        );
        let (healthy_failed_again, quiesced) = apply_tc_health_quiesce_result(
            healthy_retry.next.clone(),
            Err("map unavailable".to_string()),
        );
        assert!(!quiesced);
        assert_eq!(healthy_failed_again, failed_state);

        let (recovery_required, quiesced) =
            apply_tc_health_quiesce_result(healthy_retry.next, Ok(()));
        assert!(quiesced);
        assert_eq!(
            recovery_required.acl_error.as_deref(),
            Some("recovery_required")
        );
    }

    #[test]
    fn local_config_enable_requires_dual_tc_but_disable_does_not() {
        assert!(config_update_requires_tc(Some(true), None));
        assert!(config_update_requires_tc(None, Some(true)));
        assert!(!config_update_requires_tc(Some(false), Some(false)));
        assert!(!config_update_requires_tc(None, None));
    }
    use crate::tap_registry::ManagedAttachMode;

    fn test_control_plane() -> ControlPlane {
        let base = std::env::temp_dir().join(format!(
            "aria-control-plane-domain-test-{}",
            std::process::id()
        ));
        let base = base.to_string_lossy().to_string();
        let ebpf_path = "/tmp/libebpf_firewall.so";

        ControlPlane::new(
            ebpf_path,
            &base,
            &base,
            Arc::new(crate::ssl_manager::SslManager::new(ebpf_path, &base)),
            Arc::new(crate::kernel_drop_manager::KernelDropManager::new(
                ebpf_path, &base, &base,
            )),
            Arc::new(crate::trace_backend::TraceManager::new(
                crate::ebpf_binary::TraceBackendKind::LegacyMap,
            )),
        )
    }

    #[test]
    fn standalone_review_publication_uses_approved_snapshot_not_reload() {
        let mut approved = FirewallState::default();
        approved.conntrack_enabled = true;
        approved.acl_enabled = false;
        approved.monitoring_enabled = true;

        let published = prepare_system_publication_state(approved, "eth-review", Some(true));

        assert!(published.conntrack_enabled);
        assert!(!published.acl_enabled);
        assert!(published.monitoring_enabled);
        assert!(published.ssl_enabled);
        assert_eq!(published.attached_iface.as_deref(), Some("eth-review"));
        assert_eq!(published.tap_id, aria_core::common::TAP_ID_UNASSIGNED);
    }

    #[tokio::test]
    async fn standalone_review_lifecycle_serializes_detach_and_enable() {
        let control_plane = Arc::new(test_control_plane());
        let held = control_plane.lock_runtime_lifecycle().await;
        let waiter_control_plane = control_plane.clone();
        let mut waiter = tokio::spawn(async move {
            let _guard = waiter_control_plane.lock_runtime_lifecycle().await;
            true
        });

        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(20), &mut waiter)
                .await
                .is_err()
        );
        drop(held);
        assert!(
            tokio::time::timeout(std::time::Duration::from_secs(1), waiter)
                .await
                .unwrap()
                .unwrap()
        );
    }

    #[test]
    fn domain_authority_normalizes_neutron_domain_aliases() {
        let domains = vec![
            "aria-acl".to_string(),
            "policies".to_string(),
            "address_sets".to_string(),
            "aria_qos".to_string(),
            "aria-mirror".to_string(),
            "trace".to_string(),
            "".to_string(),
        ];

        let normalized = ControlPlane::normalize_neutron_managed_domains(&domains);

        assert!(normalized.contains("acl"));
        assert!(normalized.contains("qos"));
        assert!(normalized.contains("mirror"));
        assert!(normalized.contains("trace"));
        assert_eq!(normalized.len(), 4);
    }

    #[test]
    fn managed_runtime_activation_distinguishes_standalone_and_neutron() {
        assert_eq!(
            managed_runtime_activation(
                ManagedAttachMode::StandaloneRestoreAfterTcAttach,
                false,
                true,
                true,
            ),
            ManagedRuntimeActivation::RestoreStandalone {
                conntrack: true,
                acl: true,
            }
        );
        assert_eq!(
            managed_runtime_activation(
                ManagedAttachMode::NeutronResyncRequired { acl_managed: true },
                false,
                true,
                true,
            ),
            ManagedRuntimeActivation::AwaitNeutronResync {
                require_tc_acl_links: true,
            }
        );
        assert_eq!(
            managed_runtime_activation(
                ManagedAttachMode::NeutronResyncRequired { acl_managed: false },
                false,
                false,
                false,
            ),
            ManagedRuntimeActivation::AwaitNeutronResync {
                require_tc_acl_links: false,
            }
        );
        assert_eq!(
            managed_runtime_activation(
                ManagedAttachMode::NeutronResyncRequired { acl_managed: true },
                true,
                true,
                true,
            ),
            ManagedRuntimeActivation::PreserveVerifiedLive
        );
    }

    #[test]
    fn managed_projection_replay_mode_follows_attach_mode() {
        assert_eq!(
            managed_group_projection_mode(ManagedAttachMode::StandaloneRestoreAfterTcAttach),
            aria_core::ebpf_ops::GroupProjectionMode::StandaloneCompatibility
        );
        assert_eq!(
            managed_group_projection_mode(ManagedAttachMode::NeutronResyncRequired {
                acl_managed: false,
            }),
            aria_core::ebpf_ops::GroupProjectionMode::StandaloneCompatibility
        );
        assert_eq!(
            managed_group_projection_mode(ManagedAttachMode::NeutronResyncRequired {
                acl_managed: true,
            }),
            aria_core::ebpf_ops::GroupProjectionMode::Managed
        );
    }

    #[test]
    fn managed_projection_inventory_handoff_preserves_closed_results() {
        assert_eq!(
            preexisting_projection_verification(aria_core::ebpf_ops::ProjectionDrift::Clean),
            Ok(true)
        );
        assert_eq!(
            preexisting_projection_verification(
                aria_core::ebpf_ops::ProjectionDrift::RepairRequired(
                    aria_core::ebpf_ops::ProjectionRepairPlan {
                        general_mutations: Vec::new(),
                    },
                ),
            ),
            Ok(false)
        );
        assert_eq!(
            preexisting_projection_verification(aria_core::ebpf_ops::ProjectionDrift::Fatal(
                "unknown runtime entry".to_string(),
            )),
            Err("unknown runtime entry".to_string())
        );
    }

    #[test]
    fn managed_projection_health_fresh_managed_replay_starts_unverified() {
        let lifecycle = managed_acl_registration_lifecycle(
            ManagedAttachMode::NeutronResyncRequired { acl_managed: true },
            None,
            None,
        )
        .expect("fresh managed replay must have a lifecycle state");

        assert_eq!(
            lifecycle.publication_mode,
            ManagedAclPublicationMode::ManagedAcl
        );
        assert_eq!(
            lifecycle.projection_health,
            ManagedProjectionHealth::Unverified
        );
    }

    #[test]
    fn managed_projection_health_attach_owned_standalone_starts_unverified() {
        let lifecycle = managed_acl_registration_lifecycle(
            ManagedAttachMode::NeutronResyncRequired { acl_managed: false },
            None,
            None,
        )
        .expect("Neutron-owned standalone-compatible attach must have lifecycle state");

        assert_eq!(
            lifecycle.publication_mode,
            ManagedAclPublicationMode::NeutronAttachOwnedStandaloneAcl
        );
        assert_eq!(
            lifecycle.projection_health,
            ManagedProjectionHealth::Unverified
        );
    }

    #[test]
    fn managed_projection_health_promotion_starts_unverified() {
        let action = managed_acl_promotion_action(
            ManagedAclPublicationMode::StandaloneCompatibility,
            ManagedProjectionHealth::Unverified,
            ManagedAttachMode::NeutronResyncRequired { acl_managed: true },
        );

        assert_eq!(
            action,
            ManagedAclPromotionAction::Promote {
                next_mode: ManagedAclPublicationMode::ManagedAcl,
                next_health: ManagedProjectionHealth::Unverified,
                quiesce_acl_ct: true,
            }
        );
    }

    #[test]
    fn managed_projection_health_preexisting_exact_desired_runtime_is_verified() {
        let lifecycle = managed_acl_registration_lifecycle(
            ManagedAttachMode::NeutronResyncRequired { acl_managed: true },
            Some(aria_core::ebpf_ops::ProjectionDrift::Clean),
            Some(aria_core::ebpf_ops::RuntimeGateDisposition::Desired),
        )
        .expect("exact preexisting managed runtime must be accepted");

        assert_eq!(
            lifecycle.projection_health,
            ManagedProjectionHealth::Verified
        );
    }

    #[test]
    fn managed_projection_health_preexisting_quiesced_clean_runtime_is_unverified() {
        let lifecycle = managed_acl_registration_lifecycle(
            ManagedAttachMode::NeutronResyncRequired { acl_managed: true },
            Some(aria_core::ebpf_ops::ProjectionDrift::Clean),
            Some(aria_core::ebpf_ops::RuntimeGateDisposition::ManagedQuiesced),
        )
        .expect("clean but quiesced managed runtime must await resync");

        assert_eq!(
            lifecycle.projection_health,
            ManagedProjectionHealth::Unverified
        );
    }

    #[test]
    fn managed_projection_health_preexisting_repairable_runtime_requires_repair() {
        let lifecycle = managed_acl_registration_lifecycle(
            ManagedAttachMode::NeutronResyncRequired { acl_managed: true },
            Some(aria_core::ebpf_ops::ProjectionDrift::RepairRequired(
                aria_core::ebpf_ops::ProjectionRepairPlan {
                    general_mutations: Vec::new(),
                },
            )),
            Some(aria_core::ebpf_ops::RuntimeGateDisposition::ManagedQuiesced),
        )
        .expect("explainable managed drift must be admitted for repair");

        assert_eq!(
            lifecycle.projection_health,
            ManagedProjectionHealth::RepairRequired
        );
    }

    #[tokio::test]
    async fn managed_projection_attach_repair_fresh_neutron_state_restarts_clean() {
        for acl_managed in [true, false] {
            let mode = ManagedAttachMode::NeutronResyncRequired { acl_managed };
            let mut state = FirewallState::default();
            state.tap_id = 41;
            assert!(state.conntrack_enabled);
            assert!(state.acl_enabled);
            let persisted = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
            let persisted_capture = persisted.clone();

            persist_fresh_managed_registration_gate_state(
                &mut state,
                mode,
                true,
                move |snapshot: FirewallState| {
                    persisted_capture.borrow_mut().push(snapshot);
                    std::future::ready(Ok::<(), String>(()))
                },
            )
            .await
            .expect("fresh Neutron registration gate state must persist");

            assert!(!state.conntrack_enabled);
            assert!(!state.acl_enabled);
            let persisted_snapshot = {
                let snapshots = persisted.borrow();
                assert_eq!(snapshots.len(), 1);
                snapshots[0].clone()
            };
            assert_eq!(
                serde_json::to_value(&persisted_snapshot).unwrap(),
                serde_json::to_value(&state).unwrap(),
                "persistence must receive the exact mutated in-memory snapshot"
            );

            let reloaded: FirewallState = serde_json::from_slice(
                &serde_json::to_vec(&persisted_snapshot).expect("snapshot must serialize"),
            )
            .expect("persisted snapshot must reload");
            let projection_mode = managed_group_projection_mode(mode);
            let gate_disposition = classify_runtime_gate_state(
                projection_mode,
                0,
                0,
                reloaded.conntrack_enabled as u8,
                reloaded.acl_enabled as u8,
            )
            .expect("false/false replay must validate as the exact desired gate");
            assert_eq!(
                gate_disposition,
                aria_core::ebpf_ops::RuntimeGateDisposition::Desired
            );
            let lifecycle = managed_acl_registration_lifecycle(
                mode,
                Some(ProjectionDrift::Clean),
                Some(gate_disposition),
            )
            .expect("reloaded fresh state must classify clean");
            assert_eq!(
                lifecycle.publication_mode,
                if acl_managed {
                    ManagedAclPublicationMode::ManagedAcl
                } else {
                    ManagedAclPublicationMode::NeutronAttachOwnedStandaloneAcl
                }
            );
            assert_eq!(
                lifecycle.projection_health,
                ManagedProjectionHealth::Verified
            );
            assert_eq!(
                managed_runtime_activation(
                    mode,
                    false,
                    reloaded.conntrack_enabled,
                    reloaded.acl_enabled,
                ),
                ManagedRuntimeActivation::AwaitNeutronResync {
                    require_tc_acl_links: acl_managed,
                },
                "fresh replay must remain fail-closed until Neutron resync"
            );
            assert_eq!(
                managed_runtime_activation(
                    mode,
                    true,
                    reloaded.conntrack_enabled,
                    reloaded.acl_enabled,
                ),
                ManagedRuntimeActivation::PreserveVerifiedLive,
                "the next exact restart must not require another repair"
            );
        }
    }

    #[tokio::test]
    async fn managed_projection_attach_repair_fresh_state_persistence_is_strict_and_scoped() {
        for acl_managed in [true, false] {
            let mut state = FirewallState::default();
            let captured = std::rc::Rc::new(std::cell::RefCell::new(None));
            let captured_snapshot = captured.clone();

            let error = persist_fresh_managed_registration_gate_state(
                &mut state,
                ManagedAttachMode::NeutronResyncRequired { acl_managed },
                true,
                move |snapshot: FirewallState| {
                    *captured_snapshot.borrow_mut() = Some(snapshot);
                    std::future::ready(Err("forced fresh gate persistence failure".to_string()))
                },
            )
            .await
            .expect_err("fresh gate persistence failure must abort registration");

            assert_eq!(error, "forced fresh gate persistence failure");
            assert!(!state.conntrack_enabled);
            assert!(!state.acl_enabled);
            let captured = captured
                .borrow()
                .clone()
                .expect("the fail-closed snapshot must reach persistence");
            assert!(!captured.conntrack_enabled);
            assert!(!captured.acl_enabled);
            assert_eq!(
                serde_json::to_value(captured).unwrap(),
                serde_json::to_value(&state).unwrap()
            );
        }

        for (mode, fresh_registration) in [
            (ManagedAttachMode::StandaloneRestoreAfterTcAttach, true),
            (
                ManagedAttachMode::NeutronResyncRequired { acl_managed: true },
                false,
            ),
            (
                ManagedAttachMode::NeutronResyncRequired { acl_managed: false },
                false,
            ),
        ] {
            let mut state = FirewallState::default();
            state.conntrack_enabled = true;
            state.acl_enabled = false;
            let original = serde_json::to_value(&state).unwrap();
            let persist_calls = std::rc::Rc::new(std::cell::Cell::new(0));
            let observed_calls = persist_calls.clone();

            persist_fresh_managed_registration_gate_state(
                &mut state,
                mode,
                fresh_registration,
                move |_snapshot: FirewallState| {
                    observed_calls.set(observed_calls.get() + 1);
                    std::future::ready(Err("unexpected persistence".to_string()))
                },
            )
            .await
            .expect("standalone restore and non-fresh registration must be no-ops");

            assert_eq!(persist_calls.get(), 0);
            assert_eq!(serde_json::to_value(&state).unwrap(), original);
            assert!(state.conntrack_enabled);
            assert!(!state.acl_enabled);
        }
    }

    #[test]
    fn managed_projection_attach_repair_demotion_target_purges_exclusive_acl_state() {
        let owner_prefix = "neutron:port-1:";
        let acl_only_name = "neutron:port-1:src:acl-only";
        let retained_name = "neutron:port-1:dst:retained";
        let mut old_state = FirewallState::default();
        managed_cross_domain_insert_group(&mut old_state, acl_only_name, 30, &["10.0.0.0/24"]);
        managed_cross_domain_insert_group(&mut old_state, retained_name, 31, &["10.0.1.0/24"]);
        managed_cross_domain_insert_group(&mut old_state, "local-observer", 40, &["192.0.2.0/24"]);
        old_state
            .qos_rules
            .push(managed_cross_domain_qos_reference(retained_name, 31));
        old_state
            .mirror_rules
            .push(managed_cross_domain_mirror_reference(retained_name, 31));
        let released_bitmap = old_state
            .apply_add_rule(30, 31, libc::IPPROTO_TCP as u8, 1, Some("443"), 0)
            .expect("owned ACL port policy must materialize")
            .bitmap_idx
            .expect("port policy must allocate a bitmap");
        old_state
            .apply_add_rule(40, 0, libc::IPPROTO_UDP as u8, 0, None, 1)
            .expect("exclusive ACL-domain fixture must include a non-prefix rule");

        let target = build_managed_acl_demotion_target(&old_state, owner_prefix)
            .expect("valid managed state must produce a standalone demotion target");

        assert!(target.publication_required);
        assert!(target.final_state.rules.is_empty());
        assert_eq!(
            target
                .released_port_sets
                .keys()
                .copied()
                .collect::<Vec<_>>(),
            vec![released_bitmap]
        );
        assert!(target
            .final_state
            .is_bitmap_index_quarantined(released_bitmap));
        assert!(!target
            .final_state
            .free_bitmap_indices
            .contains(&released_bitmap));
        assert!(!target.final_state.groups.contains_key(acl_only_name));
        let retained = &target.final_state.groups[retained_name];
        assert_eq!(retained.id, 31);
        assert_eq!(retained.cidrs, vec!["10.0.1.0/24".to_string()]);
        assert_eq!(target.final_state.qos_rules[0].group_id, 31);
        assert_eq!(target.final_state.mirror_rules[0].src_group_id, 31);
        assert_eq!(target.final_state.groups["local-observer"].id, 40);
        assert!(!target.final_state.conntrack_enabled);
        assert!(!target.final_state.acl_enabled);

        let expected_shadow = aria_core::ebpf_ops::build_runtime_group_map_entries(
            &target.final_state,
            GroupProjectionMode::StandaloneCompatibility,
        )
        .expect("the final state must compile as an all-group standalone projection");
        assert_eq!(target.standalone_shadow_entries, expected_shadow);
        assert_eq!(
            target.standalone_shadow_entries.acl_src,
            target.standalone_shadow_entries.general_src
        );
        assert_eq!(
            target.standalone_shadow_entries.acl_dst,
            target.standalone_shadow_entries.general_dst
        );
        for group_id in [31, 40] {
            assert!(target
                .standalone_shadow_entries
                .acl_src
                .iter()
                .any(|entry| entry.group_id == group_id));
            assert!(target
                .standalone_shadow_entries
                .acl_dst
                .iter()
                .any(|entry| entry.group_id == group_id));
        }
    }

    #[test]
    fn managed_projection_attach_repair_empty_demotion_target_is_deterministic() {
        let old_state = FirewallState::default();

        let first = build_managed_acl_demotion_target(&old_state, "neutron:port-1:")
            .expect("an empty managed ACL must still produce a demotion target");
        let second = build_managed_acl_demotion_target(&old_state, "neutron:port-1:")
            .expect("the same empty state must remain valid");

        assert!(first.publication_required);
        assert!(!first.final_state.conntrack_enabled);
        assert!(!first.final_state.acl_enabled);
        assert!(first.final_state.rules.is_empty());
        assert!(first.released_port_sets.is_empty());
        assert_eq!(
            first.standalone_shadow_entries,
            aria_core::ebpf_ops::build_runtime_group_map_entries(
                &first.final_state,
                GroupProjectionMode::StandaloneCompatibility,
            )
            .expect("the empty standalone projection must compile")
        );
        assert_eq!(
            serde_json::to_value(&first.final_state).unwrap(),
            serde_json::to_value(&second.final_state).unwrap()
        );
        assert_eq!(
            first.standalone_shadow_entries,
            second.standalone_shadow_entries
        );
        assert_eq!(first.released_port_sets, second.released_port_sets);
        assert!(second.publication_required);
    }

    #[derive(Copy, Clone, Debug, Eq, PartialEq)]
    enum ManagedAclDemotionInjectedFailure {
        None,
        Publish,
        Persist,
        StrictFlush,
    }

    #[derive(Clone, Debug, Eq, PartialEq)]
    enum ManagedAclDemotionTestEvent {
        Quiesce,
        SetHealth(ManagedProjectionHealth),
        PublishPersistStandaloneProjection,
        StrictFlush,
        CommitMode(ManagedAclPublicationMode),
        Compensate(ManagedAclDemotionTestReceipt),
        RestoreDurable,
    }

    #[derive(Copy, Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
    enum ManagedAclDemotionTestReceipt {
        GeneralSrc,
        GeneralDst,
        ActiveBank,
    }

    impl ManagedAclDemotionTestReceipt {
        fn label(self) -> &'static str {
            match self {
                Self::GeneralSrc => "general-src",
                Self::GeneralDst => "general-dst",
                Self::ActiveBank => "active-bank",
            }
        }
    }

    struct ManagedAclDemotionTestOutcome {
        result: Result<(), String>,
        events: Vec<ManagedAclDemotionTestEvent>,
        publication_mode: ManagedAclPublicationMode,
        projection_health: ManagedProjectionHealth,
    }

    async fn run_managed_acl_demotion_test(
        failure: ManagedAclDemotionInjectedFailure,
        failed_compensations: &[ManagedAclDemotionTestReceipt],
        fail_durable_restore: bool,
    ) -> ManagedAclDemotionTestOutcome {
        // The shared publisher owns staging, bank switch, persistence, and its
        // internal failure rollback. A successful receipt is retained only so
        // a later strict-flush failure can restore the pre-demotion projection.
        let events = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
        let publication_mode =
            std::rc::Rc::new(std::cell::Cell::new(ManagedAclPublicationMode::ManagedAcl));
        let projection_health =
            std::rc::Rc::new(std::cell::Cell::new(ManagedProjectionHealth::Verified));
        let failed_compensations = std::rc::Rc::new(
            failed_compensations
                .iter()
                .copied()
                .collect::<std::collections::BTreeSet<_>>(),
        );

        let quiesce_events = events.clone();
        let health_events = events.clone();
        let health_state = projection_health.clone();
        let publish_events = events.clone();
        let flush_events = events.clone();
        let commit_events = events.clone();
        let committed_mode = publication_mode.clone();
        let compensation_events = events.clone();
        let compensation_failures = failed_compensations.clone();
        let restore_events = events.clone();

        let result = execute_managed_acl_demotion_transaction(
            move || {
                quiesce_events
                    .borrow_mut()
                    .push(ManagedAclDemotionTestEvent::Quiesce);
                std::future::ready(Ok::<(), String>(()))
            },
            move |health| {
                health_state.set(health);
                health_events
                    .borrow_mut()
                    .push(ManagedAclDemotionTestEvent::SetHealth(health));
            },
            move || {
                publish_events
                    .borrow_mut()
                    .push(ManagedAclDemotionTestEvent::PublishPersistStandaloneProjection);
                std::future::ready(match failure {
                    ManagedAclDemotionInjectedFailure::Publish => {
                        Err("forced shared publication failure".to_string())
                    }
                    ManagedAclDemotionInjectedFailure::Persist => {
                        Err("forced persistence failure".to_string())
                    }
                    ManagedAclDemotionInjectedFailure::None
                    | ManagedAclDemotionInjectedFailure::StrictFlush => Ok(vec![
                        ManagedAclDemotionTestReceipt::GeneralSrc,
                        ManagedAclDemotionTestReceipt::GeneralDst,
                        ManagedAclDemotionTestReceipt::ActiveBank,
                    ]),
                })
            },
            move || {
                flush_events
                    .borrow_mut()
                    .push(ManagedAclDemotionTestEvent::StrictFlush);
                std::future::ready(
                    if failure == ManagedAclDemotionInjectedFailure::StrictFlush {
                        Err("forced strict flush failure".to_string())
                    } else {
                        Ok(())
                    },
                )
            },
            move |mode| {
                committed_mode.set(mode);
                commit_events
                    .borrow_mut()
                    .push(ManagedAclDemotionTestEvent::CommitMode(mode));
            },
            move |receipt: &ManagedAclDemotionTestReceipt| {
                compensation_events
                    .borrow_mut()
                    .push(ManagedAclDemotionTestEvent::Compensate(*receipt));
                std::future::ready(if compensation_failures.contains(receipt) {
                    Err(format!("forced {} compensation failure", receipt.label()))
                } else {
                    Ok(())
                })
            },
            move || {
                restore_events
                    .borrow_mut()
                    .push(ManagedAclDemotionTestEvent::RestoreDurable);
                std::future::ready(if fail_durable_restore {
                    Err("forced durable restore failure".to_string())
                } else {
                    Ok(())
                })
            },
        )
        .await;

        let events_snapshot = events.borrow().clone();
        let final_mode = publication_mode.get();
        let final_health = projection_health.get();
        ManagedAclDemotionTestOutcome {
            result,
            events: events_snapshot,
            publication_mode: final_mode,
            projection_health: final_health,
        }
    }

    #[tokio::test]
    async fn managed_projection_attach_repair_demotion_commits_mode_after_strict_flush() {
        let outcome =
            run_managed_acl_demotion_test(ManagedAclDemotionInjectedFailure::None, &[], false)
                .await;

        assert_eq!(outcome.result, Ok(()));
        assert_eq!(
            outcome.events,
            vec![
                ManagedAclDemotionTestEvent::Quiesce,
                ManagedAclDemotionTestEvent::SetHealth(ManagedProjectionHealth::Unverified),
                ManagedAclDemotionTestEvent::PublishPersistStandaloneProjection,
                ManagedAclDemotionTestEvent::StrictFlush,
                ManagedAclDemotionTestEvent::CommitMode(
                    ManagedAclPublicationMode::NeutronAttachOwnedStandaloneAcl,
                ),
            ]
        );
        assert_eq!(
            outcome.publication_mode,
            ManagedAclPublicationMode::NeutronAttachOwnedStandaloneAcl
        );
        assert_eq!(
            outcome.projection_health,
            ManagedProjectionHealth::Unverified
        );
        assert!(managed_neutron_authority_confirmation_allowed(
            true,
            Some(outcome.publication_mode),
            None,
            None,
            None,
        ));
    }

    #[tokio::test]
    async fn managed_projection_attach_repair_demotion_failure_preserves_mode_and_health() {
        for (failure, expected_error) in [
            (
                ManagedAclDemotionInjectedFailure::Publish,
                "forced shared publication failure",
            ),
            (
                ManagedAclDemotionInjectedFailure::Persist,
                "forced persistence failure",
            ),
            (
                ManagedAclDemotionInjectedFailure::StrictFlush,
                "forced strict flush failure",
            ),
        ] {
            let outcome = run_managed_acl_demotion_test(failure, &[], false).await;

            let error = outcome.result.expect_err("demotion fault must fail closed");
            assert!(error.contains(expected_error), "{error}");
            assert_eq!(
                outcome.publication_mode,
                ManagedAclPublicationMode::ManagedAcl
            );
            assert_eq!(
                outcome.projection_health,
                ManagedProjectionHealth::Unverified
            );
            assert!(!outcome
                .events
                .iter()
                .any(|event| matches!(event, ManagedAclDemotionTestEvent::CommitMode(_))));
            assert!(managed_neutron_authority_confirmation_allowed(
                true,
                Some(outcome.publication_mode),
                None,
                Some(outcome.projection_health),
                None,
            ));
        }
    }

    #[tokio::test]
    async fn managed_projection_attach_repair_demotion_compensation_is_reverse_attempt_all() {
        let outcome = run_managed_acl_demotion_test(
            ManagedAclDemotionInjectedFailure::StrictFlush,
            &[
                ManagedAclDemotionTestReceipt::ActiveBank,
                ManagedAclDemotionTestReceipt::GeneralDst,
            ],
            true,
        )
        .await;

        let error = outcome
            .result
            .expect_err("strict flush failure must roll back the demotion publication");
        assert!(error.contains("forced strict flush failure"), "{error}");
        assert!(
            error.contains("forced active-bank compensation failure"),
            "{error}"
        );
        assert!(
            error.contains("forced general-dst compensation failure"),
            "{error}"
        );
        assert!(error.contains("forced durable restore failure"), "{error}");
        let compensation_events: Vec<_> = outcome
            .events
            .iter()
            .filter(|event| {
                matches!(
                    event,
                    ManagedAclDemotionTestEvent::Compensate(_)
                        | ManagedAclDemotionTestEvent::RestoreDurable
                )
            })
            .cloned()
            .collect();
        assert_eq!(
            compensation_events,
            vec![
                ManagedAclDemotionTestEvent::Compensate(ManagedAclDemotionTestReceipt::ActiveBank,),
                ManagedAclDemotionTestEvent::Compensate(ManagedAclDemotionTestReceipt::GeneralDst,),
                ManagedAclDemotionTestEvent::Compensate(ManagedAclDemotionTestReceipt::GeneralSrc,),
                ManagedAclDemotionTestEvent::RestoreDurable,
            ]
        );
        assert_eq!(
            outcome.publication_mode,
            ManagedAclPublicationMode::ManagedAcl
        );
        assert_eq!(
            outcome.projection_health,
            ManagedProjectionHealth::Unverified
        );
    }

    #[test]
    fn neutron_acl_gate_serialization_requires_tc_only_for_enabling_writes() {
        assert!(!neutron_acl_gate_requires_tc(false, false));
        assert!(neutron_acl_gate_requires_tc(true, false));
        assert!(neutron_acl_gate_requires_tc(false, true));
        assert!(neutron_acl_gate_requires_tc(true, true));
        assert!(neutron_acl_gate_requires_full_resync(
            false, true, false, false
        ));
        assert!(!neutron_acl_gate_requires_full_resync(
            false, true, false, true
        ));
        assert!(!neutron_acl_gate_requires_full_resync(
            false, false, false, false
        ));
        assert_eq!(
            neutron_gate_health_commit_action(false, false, false),
            NeutronGateHealthCommitAction::ClearDisabled
        );
        assert_eq!(
            neutron_gate_health_commit_action(false, false, true),
            NeutronGateHealthCommitAction::ClearDisabled
        );
        assert_eq!(
            neutron_gate_health_commit_action(true, false, true),
            NeutronGateHealthCommitAction::VerifyRecoveryPublication
        );
        assert_eq!(
            neutron_gate_health_commit_action(false, true, true),
            NeutronGateHealthCommitAction::VerifyRecoveryPublication
        );
        assert_eq!(
            neutron_gate_health_commit_action(true, true, false),
            NeutronGateHealthCommitAction::Preserve
        );
    }

    #[test]
    fn tc_health_reconcile_recovery_publication_failure_is_fail_closed() {
        let failed_health = RuntimeHealthState {
            acl_ready: false,
            xdp_ready: true,
            acl_error: Some("missing_tc_ingress".to_string()),
        };
        let readiness_error = ControlPlaneError::InstanceNotReady(
            "missing live TCX ACL attachments: ingress".to_string(),
        );
        let (quiesced_health, preserved) = apply_recovery_publication_quiesce_result(
            failed_health.clone(),
            readiness_error,
            Ok(()),
        );
        assert!(!quiesced_health.acl_ready);
        assert_eq!(
            quiesced_health.acl_error.as_deref(),
            Some("missing_tc_ingress")
        );
        assert!(matches!(preserved, ControlPlaneError::InstanceNotReady(_)));
        assert!(preserved
            .to_string()
            .contains("missing live TCX ACL attachments: ingress"));
        assert!(!preserved.to_string().contains("acl_quiesce_failed"));

        let readiness_error = ControlPlaneError::InstanceNotReady(
            "missing live TCX ACL attachments: egress".to_string(),
        );
        let (failed_quiesce_health, combined) = apply_recovery_publication_quiesce_result(
            failed_health,
            readiness_error,
            Err("runtime gate write failed: map unavailable".to_string()),
        );
        assert!(!failed_quiesce_health.acl_ready);
        assert!(failed_quiesce_health
            .acl_error
            .as_deref()
            .is_some_and(|reason| reason.starts_with("acl_quiesce_failed:")));
        assert!(matches!(combined, ControlPlaneError::InstanceNotReady(_)));
        assert!(combined
            .to_string()
            .contains("missing live TCX ACL attachments: egress"));
        assert!(combined.to_string().contains("acl_quiesce_failed"));
        assert!(combined.to_string().contains("map unavailable"));
    }

    async fn stopped_wal_instance_state(test_name: &str) -> InstanceState {
        let state_path = std::env::temp_dir().join(format!(
            "aria-managed-failure-path-{}-{}",
            std::process::id(),
            test_name
        ));
        if state_path.exists() {
            std::fs::remove_dir_all(&state_path).unwrap();
        }
        let state_path_string = state_path.to_string_lossy().into_owned();
        let wal = WalClient::open(&state_path_string).unwrap();
        wal.shutdown().await;
        InstanceState {
            state: FirewallState::default(),
            runtime_health: RuntimeHealthState {
                acl_ready: true,
                xdp_ready: false,
                acl_error: None,
            },
            managed_acl_publication_mode: ManagedAclPublicationMode::StandaloneCompatibility,
            managed_projection_health: ManagedProjectionHealth::Unverified,
            tap_id: 7,
            ifindex: Some(11),
            pin_path: state_path_string.clone(),
            state_path: state_path_string,
            wal,
            ssl_sync_pending: false,
            last_ssl_sync_error: None,
        }
    }

    #[tokio::test]
    async fn tc_health_reconcile_skips_stale_same_name_candidate_before_transition_or_quiesce() {
        let control_plane = test_control_plane();
        let shared_pin_path = std::env::temp_dir()
            .join(format!(
                "aria-tc-health-stale-candidate-{}",
                std::process::id()
            ))
            .to_string_lossy()
            .into_owned();

        let mut stale_state = stopped_wal_instance_state("tc-health-stale-old").await;
        stale_state.state.acl_enabled = true;
        stale_state.pin_path = shared_pin_path.clone();
        let stale = Arc::new(tokio::sync::RwLock::new(stale_state));

        let mut replacement_state = stopped_wal_instance_state("tc-health-stale-current").await;
        replacement_state.state.acl_enabled = true;
        replacement_state.pin_path = shared_pin_path;
        let replacement = Arc::new(tokio::sync::RwLock::new(replacement_state));

        control_plane
            .instances
            .write()
            .await
            .insert("tap-reused".to_string(), replacement.clone());

        let stale_change = control_plane
            .reconcile_tc_acl_health_candidate("tap-reused", &stale)
            .await;
        assert!(stale_change.is_none());
        let stale_health = stale.read().await.runtime_health.clone();
        assert!(stale_health.acl_ready);
        assert!(stale_health.acl_error.is_none());

        let current_change = control_plane
            .reconcile_tc_acl_health_candidate("tap-reused", &replacement)
            .await
            .expect("the current same-name Arc must enter health reconciliation");
        assert!(!current_change.acl_ready);
        assert!(!current_change.quiesced);
        assert!(current_change
            .reason
            .as_deref()
            .is_some_and(|reason| reason.starts_with("acl_quiesce_failed:")));
        let current_health = replacement.read().await.runtime_health.clone();
        assert!(!current_health.acl_ready);
        assert!(current_health
            .acl_error
            .as_deref()
            .is_some_and(|reason| reason.starts_with("acl_quiesce_failed:")));
    }

    #[tokio::test]
    async fn managed_failure_path_strict_wal_failure_propagates() {
        let mut state = stopped_wal_instance_state("strict-wal").await;
        let error = state
            .wal_append_strict(&WalEntry::UpdateConfig {
                conntrack: Some(true),
                monitoring: None,
                acl: Some(true),
                qos: None,
                mirror: None,
                tcprt: None,
                ssl: None,
            })
            .await
            .unwrap_err();

        assert!(error.contains("WAL append failed"));
        assert!(error.contains("compact fallback failed"));
    }

    #[tokio::test]
    async fn managed_failure_path_enabling_persistence_failure_quiesces() {
        let mut state = stopped_wal_instance_state("enable-quiesce").await;
        state.state.conntrack_enabled = true;
        state.state.acl_enabled = true;
        let mut kernel_writes = Vec::new();

        let error = state
            .recover_gate_persistence_failure(
                true,
                true,
                "forced persistence failure",
                |ct, acl| {
                    kernel_writes.push((ct, acl));
                    Ok(())
                },
            )
            .await;

        assert_eq!(kernel_writes, vec![(false, false)]);
        assert!(!state.state.conntrack_enabled);
        assert!(!state.state.acl_enabled);
        assert!(matches!(&error, ControlPlaneError::PersistenceError(_)));
        assert!(error.to_string().contains("forced persistence failure"));
    }

    #[tokio::test]
    async fn managed_failure_path_disabling_persistence_failure_stays_disabled() {
        let mut state = stopped_wal_instance_state("disable-stays-disabled").await;
        state.state.conntrack_enabled = false;
        state.state.acl_enabled = false;
        let mut kernel_write_count = 0;

        let error = state
            .recover_gate_persistence_failure(false, false, "forced persistence failure", |_, _| {
                kernel_write_count += 1;
                Ok(())
            })
            .await;

        assert_eq!(kernel_write_count, 0);
        assert!(!state.state.conntrack_enabled);
        assert!(!state.state.acl_enabled);
        assert!(matches!(error, ControlPlaneError::PersistenceError(_)));
    }

    #[tokio::test]
    async fn managed_failure_path_kernel_quiesce_failure_stays_disabled() {
        let mut state = stopped_wal_instance_state("kernel-quiesce-failure").await;
        state.state.conntrack_enabled = true;
        state.state.acl_enabled = true;

        let error = state
            .recover_gate_persistence_failure(
                true,
                true,
                "forced persistence failure",
                |ct, acl| {
                    assert_eq!((ct, acl), (false, false));
                    Err("forced kernel quiesce failure".to_string())
                },
            )
            .await;

        assert_eq!(error.status_code(), 503);
        assert!(error.to_string().contains("forced persistence failure"));
        assert!(error.to_string().contains("forced kernel quiesce failure"));
        assert!(!state.state.conntrack_enabled);
        assert!(!state.state.acl_enabled);
    }

    #[tokio::test]
    async fn standalone_review_local_persistence_failure_is_fail_closed() {
        let mut state = stopped_wal_instance_state("local-config-enable").await;
        let mut old_state = FirewallState::default();
        old_state.monitoring_enabled = true;
        state.state = old_state.clone();
        state.state.conntrack_enabled = true;
        state.state.acl_enabled = true;
        state.state.monitoring_enabled = false;
        let mut kernel_states = Vec::new();

        let error = state
            .recover_local_config_persistence_failure(
                old_state,
                true,
                "forced local persistence failure",
                |safe_state| {
                    kernel_states.push((
                        safe_state.conntrack_enabled,
                        safe_state.acl_enabled,
                        safe_state.monitoring_enabled,
                    ));
                    Ok(())
                },
            )
            .await;

        assert_eq!(kernel_states, vec![(false, false, true)]);
        assert!(!state.state.conntrack_enabled);
        assert!(!state.state.acl_enabled);
        assert!(state.state.monitoring_enabled);
        assert_eq!(error.status_code(), 503);
        assert!(error
            .to_string()
            .contains("forced local persistence failure"));
        assert!(error.to_string().contains("compact fallback failed"));
    }

    #[test]
    fn standalone_review_bank_rollback_attempts_all_shared_mutations() {
        let mutations = vec![
            SharedNetworkMutation::Added {
                direction: "src",
                cidr: "10.0.0.0/24".to_string(),
                group_id: 7,
            },
            SharedNetworkMutation::Deleted {
                direction: "dst",
                cidr: "10.0.1.0/24".to_string(),
                group_id: 8,
            },
        ];
        let mut attempted = Vec::new();

        let error = execute_shared_network_rollback(&mutations, |mutation| {
            attempted.push((*mutation).clone());
            if attempted.len() == 1 {
                Err("forced first rollback failure".to_string())
            } else {
                Ok(())
            }
        })
        .unwrap_err();

        assert_eq!(attempted, vec![mutations[1].clone(), mutations[0].clone()]);
        assert!(error.contains("forced first rollback failure"));
    }

    #[test]
    fn standalone_review_port_set_rollback_cleans_recycled_bitmap() {
        let mut baseline = FirewallState::default();
        baseline.free_bitmap_indices.push(7);
        baseline.next_bitmap_idx = 8;
        let mut staged = baseline.clone();
        let add = staged
            .apply_add_rule(1, 2, libc::IPPROTO_TCP as u8, 1, Some("80"), 0)
            .unwrap();
        let rule = staged.rules.last().unwrap().clone();
        let runtime_adds = vec![OwnedAclPolicyRuntimeAdd {
            rule,
            is_new_port_set: add.is_new_port_set,
        }];
        let created = transaction_created_port_sets(&staged, &runtime_adds).unwrap();
        let mut cleaned = Vec::new();

        let cleanup = execute_transaction_port_set_cleanup(&created, |port_set| {
            cleaned.push(port_set.clone());
            Ok(())
        });

        assert_eq!(created.len(), 1);
        assert_eq!(created[0].bitmap_idx, 7);
        assert_eq!(cleaned, created);
        assert_eq!(cleanup.cleaned_bitmap_indices, vec![7]);
        assert!(cleanup.failures.is_empty());
        let mut retry = baseline;
        let retry_add = retry
            .apply_add_rule(1, 2, libc::IPPROTO_TCP as u8, 1, Some("443"), 0)
            .unwrap();
        assert_eq!(retry_add.bitmap_idx, Some(7));
        assert!(retry_add.is_new_port_set);
    }

    #[test]
    fn standalone_review_port_set_cleanup_attempts_every_created_set() {
        let created = vec![
            TransactionCreatedPortSet {
                bitmap_idx: 7,
                ports_normalized: "80:1".to_string(),
            },
            TransactionCreatedPortSet {
                bitmap_idx: 8,
                ports_normalized: "443:1".to_string(),
            },
        ];
        let mut attempted = Vec::new();

        let cleanup = execute_transaction_port_set_cleanup(&created, |port_set| {
            attempted.push(port_set.clone());
            if attempted.len() == 1 {
                Err("forced first bitmap cleanup failure".to_string())
            } else {
                Ok(())
            }
        });

        assert_eq!(attempted, created);
        assert_eq!(cleanup.cleaned_bitmap_indices, vec![8]);
        assert_eq!(cleanup.failures.len(), 1);
        assert_eq!(cleanup.failures[0].bitmap_idx, 7);
        assert!(cleanup.failures[0]
            .error
            .contains("forced first bitmap cleanup failure"));
    }

    #[test]
    fn standalone_review_failed_cleanup_quarantine_survives_retry_and_restart() {
        let created = vec![
            TransactionCreatedPortSet {
                bitmap_idx: 7,
                ports_normalized: "80:1".to_string(),
            },
            TransactionCreatedPortSet {
                bitmap_idx: 8,
                ports_normalized: "443:1".to_string(),
            },
        ];
        let cleanup = execute_transaction_port_set_cleanup(&created, |port_set| {
            if port_set.bitmap_idx == 7 {
                Err("forced durable quarantine".to_string())
            } else {
                Ok(())
            }
        });

        let mut guarded = FirewallState::default();
        guarded.free_bitmap_indices.extend([7, 8]);
        guarded.next_bitmap_idx = 9;
        quarantine_port_set_indices(&mut guarded, &created).unwrap();
        apply_confirmed_port_set_cleanups(&mut guarded, &cleanup).unwrap();

        let json = serde_json::to_string(&guarded).unwrap();
        let mut restarted: FirewallState = serde_json::from_str(&json).unwrap();
        let first_retry = restarted
            .apply_add_rule(1, 2, libc::IPPROTO_TCP as u8, 1, Some("8443"), 0)
            .unwrap();
        let second_retry = restarted
            .apply_add_rule(3, 4, libc::IPPROTO_TCP as u8, 1, Some("9443"), 0)
            .unwrap();

        assert_eq!(cleanup.failures[0].bitmap_idx, 7);
        assert!(restarted.is_bitmap_index_quarantined(7));
        assert_eq!(first_retry.bitmap_idx, Some(8));
        assert_eq!(second_retry.bitmap_idx, Some(9));
    }

    #[test]
    fn standalone_review_rollback_recovery_persists_only_failed_cleanup_quarantine() {
        let mut old_state = FirewallState::default();
        old_state.free_bitmap_indices.extend([7, 8]);
        old_state.next_bitmap_idx = 9;
        let cleanup = PortSetCleanupReport {
            cleaned_bitmap_indices: vec![8],
            failures: vec![PortSetCleanupFailure {
                bitmap_idx: 7,
                error: "forced rollback cleanup failure".to_string(),
            }],
        };

        let recovered = old_state_with_failed_cleanup_quarantines(&old_state, &cleanup).unwrap();
        let json = serde_json::to_string(&recovered).unwrap();
        let mut restarted: FirewallState = serde_json::from_str(&json).unwrap();
        let first_retry = restarted
            .apply_add_rule(1, 2, libc::IPPROTO_TCP as u8, 1, Some("8443"), 0)
            .unwrap();
        let second_retry = restarted
            .apply_add_rule(3, 4, libc::IPPROTO_TCP as u8, 1, Some("9443"), 0)
            .unwrap();

        assert!(restarted.is_bitmap_index_quarantined(7));
        assert!(!restarted.is_bitmap_index_quarantined(8));
        assert_eq!(first_retry.bitmap_idx, Some(8));
        assert_eq!(second_retry.bitmap_idx, Some(9));
    }

    #[test]
    fn managed_general_delta_persistence_failure_restores_old_snapshot_without_created_port_sets() {
        let mut old_state = FirewallState::default();
        old_state.next_group_id = 41;
        old_state.conntrack_enabled = true;
        let cleanup = PortSetCleanupReport::default();

        let recovered = failed_persistence_recovery_state(&old_state, &cleanup)
            .expect("empty created-port-set cleanup must still produce the old durable snapshot");

        assert_eq!(
            serde_json::to_value(recovered).unwrap(),
            serde_json::to_value(old_state).unwrap()
        );
    }

    #[test]
    fn standalone_review_same_diff_release_is_quarantined_before_later_allocation() {
        let mut old_state = FirewallState::default();
        let old_add = old_state
            .apply_add_rule(1, 2, libc::IPPROTO_TCP as u8, 1, Some("80"), 0)
            .unwrap();
        let released_idx = old_add.bitmap_idx.unwrap();
        assert_eq!(released_idx, 0);

        let mut final_state = old_state.clone();
        let mut released_port_sets = BTreeMap::new();
        let mut runtime_adds = Vec::new();

        // This is the earlier BTreeMap-sorted policy update. It allocates a
        // fresh bitmap and releases the old policy's index.
        let early_update = final_state
            .apply_add_rule(1, 2, libc::IPPROTO_TCP as u8, 1, Some("443"), 0)
            .unwrap();
        quarantine_owned_acl_released_port_set(
            &mut final_state,
            &mut released_port_sets,
            early_update.old_port_set_released.clone(),
        )
        .unwrap();
        runtime_adds.push(OwnedAclPolicyRuntimeAdd {
            rule: final_state
                .rules
                .iter()
                .find(|rule| rule.src_group_id == 1 && rule.dst_group_id == 2)
                .unwrap()
                .clone(),
            is_new_port_set: early_update.is_new_port_set,
        });

        // This later sorted policy must not consume the just-released index.
        let later_add = final_state
            .apply_add_rule(3, 4, libc::IPPROTO_TCP as u8, 1, Some("8443"), 0)
            .unwrap();
        quarantine_owned_acl_released_port_set(
            &mut final_state,
            &mut released_port_sets,
            later_add.old_port_set_released.clone(),
        )
        .unwrap();
        runtime_adds.push(OwnedAclPolicyRuntimeAdd {
            rule: final_state
                .rules
                .iter()
                .find(|rule| rule.src_group_id == 3 && rule.dst_group_id == 4)
                .unwrap()
                .clone(),
            is_new_port_set: later_add.is_new_port_set,
        });

        assert_ne!(later_add.bitmap_idx, Some(released_idx));
        assert_eq!(later_add.bitmap_idx, Some(2));
        assert_eq!(released_port_sets.len(), 1);
        assert!(final_state.is_bitmap_index_quarantined(released_idx));

        let created = transaction_created_port_sets(&final_state, &runtime_adds).unwrap();
        assert_eq!(
            created
                .iter()
                .map(|port_set| port_set.bitmap_idx)
                .collect::<Vec<_>>(),
            vec![1, 2]
        );
        let mut allocator_guard = old_state.clone();
        quarantine_port_set_indices(&mut allocator_guard, &created)
            .expect("created guard must not collide with the live old bitmap index");

        let mut durable_final_state = final_state.clone();
        durable_final_state
            .quarantine_bitmap_index(released_idx)
            .expect("same-index quarantine must be idempotent");
        let cleanup = PortSetCleanupReport {
            cleaned_bitmap_indices: vec![released_idx],
            failures: Vec::new(),
        };
        apply_confirmed_port_set_cleanups(&mut durable_final_state, &cleanup).unwrap();
        let after_cleanup = durable_final_state
            .apply_add_rule(5, 6, libc::IPPROTO_TCP as u8, 1, Some("9443"), 0)
            .unwrap();
        assert_eq!(after_cleanup.bitmap_idx, Some(released_idx));
    }

    #[test]
    fn standalone_review_same_diff_normalized_port_dedup_keeps_release_quarantined() {
        let mut final_state = FirewallState::default();
        final_state
            .apply_add_rule(1, 2, libc::IPPROTO_TCP as u8, 1, Some("80"), 0)
            .unwrap();
        let early_update = final_state
            .apply_add_rule(1, 2, libc::IPPROTO_TCP as u8, 1, Some("443"), 0)
            .unwrap();
        let mut released_port_sets = BTreeMap::new();
        quarantine_owned_acl_released_port_set(
            &mut final_state,
            &mut released_port_sets,
            early_update.old_port_set_released,
        )
        .unwrap();

        let same_ports_later = final_state
            .apply_add_rule(3, 4, libc::IPPROTO_TCP as u8, 1, Some("443"), 0)
            .unwrap();

        assert_eq!(same_ports_later.bitmap_idx, early_update.bitmap_idx);
        assert!(!same_ports_later.is_new_port_set);
        assert_eq!(released_port_sets.len(), 1);
        assert!(final_state.is_bitmap_index_quarantined(0));
    }

    #[test]
    fn standalone_review_bank_map_helpers_use_required_maps_without_xdp_sentinel() {
        let pin_dir = std::env::temp_dir().join(format!(
            "aria-xdp-independent-bank-maps-{}",
            std::process::id()
        ));
        if pin_dir.exists() {
            std::fs::remove_dir_all(&pin_dir).unwrap();
        }
        std::fs::create_dir_all(&pin_dir).unwrap();
        let pin_path = pin_dir.to_string_lossy().into_owned();
        let runtime = TapMapRuntime::new(&pin_path, 17);

        let failures = vec![
            (
                "bank network add",
                aria_core::ebpf_ops::add_acl_network_in_bank(
                    "src",
                    "10.0.0.0/24",
                    7,
                    1,
                    runtime,
                    "/tmp/unused-ebpf",
                )
                .unwrap_err(),
                "ACL_SRC_IPV4_TRIE",
            ),
            (
                "bank network delete",
                aria_core::ebpf_ops::delete_acl_network_in_bank(
                    "dst",
                    "10.0.1.0/24",
                    8,
                    1,
                    runtime,
                    "/tmp/unused-ebpf",
                )
                .unwrap_err(),
                "ACL_DST_IPV4_TRIE",
            ),
            (
                "bank policy add",
                aria_core::ebpf_ops::add_policy_in_bank(
                    7,
                    8,
                    libc::IPPROTO_TCP as u8,
                    1,
                    None,
                    None,
                    false,
                    0,
                    1,
                    runtime,
                    "/tmp/unused-ebpf",
                )
                .unwrap_err(),
                "POLICY_TABLE",
            ),
            (
                "bank policy delete",
                aria_core::ebpf_ops::delete_policy_in_bank(
                    7,
                    8,
                    libc::IPPROTO_TCP as u8,
                    0,
                    1,
                    runtime,
                    "/tmp/unused-ebpf",
                )
                .unwrap_err(),
                "POLICY_TABLE",
            ),
        ];
        std::fs::remove_dir_all(&pin_dir).unwrap();

        for (operation, error, required_map) in failures {
            assert!(
                error.contains(required_map),
                "{} must fail on its required map, got: {}",
                operation,
                error
            );
            assert!(
                !error.contains("Firewall not started"),
                "{} must not use XDP as an ACL runtime sentinel: {}",
                operation,
                error
            );
        }
    }

    #[test]
    fn standalone_review_bank_rollback_port_set_cleanup_requires_map_without_xdp() {
        let pin_dir = std::env::temp_dir().join(format!(
            "aria-xdp-independent-port-cleanup-{}",
            std::process::id()
        ));
        if pin_dir.exists() {
            std::fs::remove_dir_all(&pin_dir).unwrap();
        }
        std::fs::create_dir_all(&pin_dir).unwrap();
        let pin_path = pin_dir.to_string_lossy().into_owned();
        let result = aria_core::ebpf_ops::delete_port_set(
            9,
            "80:1",
            TapMapRuntime::new(&pin_path, 17),
            "/tmp/unused-ebpf",
        );
        std::fs::remove_dir_all(&pin_dir).unwrap();

        let error = result.expect_err(
            "port-set rollback must not silently succeed when XDP and PORT_BITMAP_POOL are absent",
        );
        assert!(
            error.contains("PORT_BITMAP_POOL"),
            "port-set rollback must fail on its required map, got: {}",
            error
        );
        assert!(!error.contains("Firewall not started"));
    }

    #[test]
    fn domain_authority_domain_labels_are_stable() {
        assert_eq!(LocalWriteDomain::Acl.as_str(), "acl");
        assert_eq!(LocalWriteDomain::Qos.as_str(), "qos");
        assert_eq!(LocalWriteDomain::Mirror.as_str(), "mirror");
        assert_eq!(LocalWriteDomain::Config.as_str(), "config");
        assert_eq!(LocalWriteDomain::Conntrack.as_str(), "conntrack");
        assert_eq!(LocalWriteDomain::Tcprt.as_str(), "tcprt");
        assert_eq!(LocalWriteDomain::Trace.as_str(), "trace");
        assert_eq!(LocalWriteDomain::Drops.as_str(), "drops");
        assert_eq!(LocalWriteDomain::Ssl.as_str(), "ssl");
    }

    #[tokio::test]
    async fn domain_authority_blocks_only_selected_domains() {
        let cp = test_control_plane();
        let managed_domains = vec!["acl".to_string(), "mirror".to_string()];
        cp.mark_neutron_port_authority("tap-vm", "port-vm", &managed_domains, 7)
            .await;

        assert!(cp
            .ensure_local_write_allowed("tap-vm", LocalWriteDomain::Acl)
            .await
            .is_err());
        assert!(cp
            .ensure_local_write_allowed("tap-vm", LocalWriteDomain::Mirror)
            .await
            .is_err());
        assert!(cp
            .ensure_local_write_allowed("tap-vm", LocalWriteDomain::Qos)
            .await
            .is_ok());
        assert!(cp
            .ensure_local_write_allowed("tap-vm", LocalWriteDomain::Trace)
            .await
            .is_ok());
        assert!(cp
            .ensure_local_group_write_allowed("tap-vm", "neutron:acl-source")
            .await
            .is_err());
        assert!(cp
            .ensure_local_group_write_allowed("tap-vm", "local-qos-group")
            .await
            .is_ok());
    }

    #[tokio::test]
    async fn domain_authority_blocks_conntrack_as_acl_dependency() {
        let cp = test_control_plane();
        cp.mark_neutron_port_authority("tap-vm", "port-vm", &["acl".to_string()], 7)
            .await;

        let error = cp
            .ensure_local_write_allowed("tap-vm", LocalWriteDomain::Conntrack)
            .await
            .expect_err("ACL authority must protect its CT dependency");

        assert_eq!(error.status_code(), 409);
        assert!(error.to_string().contains("dependency of 'acl'"));
        assert!(cp
            .ensure_local_write_allowed("tap-vm", LocalWriteDomain::Qos)
            .await
            .is_ok());
        assert!(cp
            .ensure_local_write_allowed("tap-vm", LocalWriteDomain::Trace)
            .await
            .is_ok());
    }

    fn managed_acl_shadow_fixture() -> aria_core::ebpf_ops::ManagedGroupProjection {
        let mut state = FirewallState::default();
        for (name, id, cidrs) in [
            ("acl-source", 10, vec!["10.0.0.0/24"]),
            ("acl-destination", 11, vec!["2001:db8::/64"]),
            ("local-exact", 20, vec!["10.0.0.0/24"]),
            ("local-more-specific", 30, vec!["10.0.0.7/32"]),
        ] {
            state.groups.insert(
                name.to_string(),
                GroupInfo {
                    id,
                    name: name.to_string(),
                    cidrs: cidrs.into_iter().map(str::to_string).collect(),
                },
            );
        }
        state.rules.push(RuleInfo {
            name: None,
            src_group_id: 10,
            dst_group_id: 11,
            proto: libc::IPPROTO_TCP as u8,
            action: 0,
            ports: None,
            bitmap_idx: None,
            direction: 0,
        });

        aria_core::ebpf_ops::compile_managed_group_projection(&state)
            .expect("managed shadow fixture must compile")
    }

    #[test]
    fn managed_acl_shadow_uses_direction_specific_projection_entries() {
        let projection = managed_acl_shadow_fixture();
        let writes: BTreeSet<_> = managed_acl_shadow_network_plan(&projection)
            .into_iter()
            .collect();

        assert_eq!(
            writes,
            BTreeSet::from([
                ("src", "10.0.0.0/24".to_string(), 10),
                ("dst", "2001:db8::/64".to_string(), 11),
            ])
        );
    }

    #[test]
    fn managed_acl_shadow_excludes_exact_local_alias() {
        let writes = managed_acl_shadow_network_plan(&managed_acl_shadow_fixture());

        assert!(writes.iter().all(|(_, _, group_id)| *group_id != 20));
    }

    #[test]
    fn managed_acl_shadow_excludes_more_specific_local_alias() {
        let writes = managed_acl_shadow_network_plan(&managed_acl_shadow_fixture());

        assert!(writes.iter().all(|(_, _, group_id)| *group_id != 30));
    }

    fn managed_replacement(direction: &'static str) -> SharedNetworkMutation {
        SharedNetworkMutation::Replaced {
            direction,
            cidr: "10.0.0.0/24".to_string(),
            old_group_id: 41,
            new_group_id: 71,
        }
    }

    fn managed_replacement_compensations(
        mutations: &[SharedNetworkMutation],
    ) -> Vec<ManagedAclPublicationCompensation> {
        managed_acl_publication_compensations(mutations, ManagedAclPublicationFailurePhase::General)
    }

    fn managed_expected_restore(direction: &'static str) -> SharedNetworkMutation {
        SharedNetworkMutation::Replaced {
            direction,
            cidr: "10.0.0.0/24".to_string(),
            old_group_id: 71,
            new_group_id: 41,
        }
    }

    fn managed_expected_general_restore(
        direction: &'static str,
    ) -> ManagedAclPublicationCompensation {
        ManagedAclPublicationCompensation::RestoreGeneral(managed_expected_restore(direction))
    }

    fn managed_publication_step_counts(
        decision: &ManagedAclPublicationDecision,
        general_mutations: Vec<SharedNetworkMutation>,
    ) -> (usize, usize, usize) {
        let steps = managed_acl_publication_steps(decision, general_mutations);
        let general_writes = steps
            .iter()
            .filter(|step| matches!(step, ManagedAclPublicationStep::ApplyGeneral(_)))
            .count();
        let shadow_stages = steps
            .iter()
            .filter(|step| matches!(step, ManagedAclPublicationStep::StageShadow))
            .count();
        let bank_switches = steps
            .iter()
            .filter(|step| matches!(step, ManagedAclPublicationStep::SwitchBank))
            .count();
        (general_writes, shadow_stages, bank_switches)
    }

    #[test]
    fn managed_general_delta_replacement_compensation_upserts_old_value() {
        assert_eq!(
            shared_network_compensation(&managed_replacement("src")),
            managed_expected_restore("src")
        );
    }

    #[test]
    fn managed_general_delta_source_only_failure_restores_preimage() {
        assert_eq!(
            managed_replacement_compensations(&[managed_replacement("src")]),
            vec![managed_expected_general_restore("src")]
        );
    }

    #[test]
    fn managed_general_delta_destination_failure_restores_source_preimage() {
        let applied_before_destination_failure = vec![managed_replacement("src")];

        assert_eq!(
            managed_replacement_compensations(&applied_before_destination_failure),
            vec![managed_expected_general_restore("src")]
        );
    }

    #[test]
    fn managed_general_delta_shadow_failure_restores_both_preimages() {
        let applied = vec![managed_replacement("src"), managed_replacement("dst")];

        assert_eq!(
            managed_acl_publication_compensations(
                &applied,
                ManagedAclPublicationFailurePhase::Shadow,
            ),
            vec![
                managed_expected_general_restore("dst"),
                managed_expected_general_restore("src")
            ]
        );
    }

    #[test]
    fn managed_general_delta_persistence_failure_restores_both_preimages() {
        let applied = vec![managed_replacement("src"), managed_replacement("dst")];

        assert_eq!(
            managed_acl_publication_compensations(
                &applied,
                ManagedAclPublicationFailurePhase::Persist,
            ),
            vec![
                ManagedAclPublicationCompensation::RestoreActiveBank,
                managed_expected_general_restore("dst"),
                managed_expected_general_restore("src")
            ]
        );
    }

    #[test]
    fn managed_general_delta_compensation_failure_attempts_every_preimage() {
        let applied = vec![managed_replacement("src"), managed_replacement("dst")];
        let compensations = managed_acl_publication_compensations(
            &applied,
            ManagedAclPublicationFailurePhase::Persist,
        );
        let mut attempted = Vec::new();

        let error = execute_managed_acl_publication_compensations(&compensations, |compensation| {
            attempted.push(compensation.clone());
            if attempted.len() == 1 {
                Err("forced bank compensation failure".to_string())
            } else {
                Ok(())
            }
        })
        .expect_err("one failed compensation must remain visible");

        assert_eq!(
            attempted,
            vec![
                ManagedAclPublicationCompensation::RestoreActiveBank,
                managed_expected_general_restore("dst"),
                managed_expected_general_restore("src")
            ]
        );
        assert!(error.contains("forced bank compensation failure"));
    }

    #[test]
    fn managed_general_delta_general_compensation_failure_attempts_every_preimage() {
        let applied = vec![managed_replacement("src"), managed_replacement("dst")];
        let compensations = managed_acl_publication_compensations(
            &applied,
            ManagedAclPublicationFailurePhase::Shadow,
        );
        let mut attempted = Vec::new();

        let error = execute_managed_acl_publication_compensations(&compensations, |compensation| {
            attempted.push(compensation.clone());
            if attempted.len() == 1 {
                Err("forced destination compensation failure".to_string())
            } else {
                Ok(())
            }
        })
        .expect_err("one failed preimage restore must remain visible");

        assert_eq!(
            attempted,
            vec![
                managed_expected_general_restore("dst"),
                managed_expected_general_restore("src")
            ]
        );
        assert!(error.contains("forced destination compensation failure"));
    }

    #[test]
    fn managed_general_delta_managed_group_delete_rollback_is_general_only() {
        assert!(!group_delete_rollback_restores_acl_bank(
            ManagedAclPublicationMode::ManagedAcl
        ));
        assert!(group_delete_rollback_restores_acl_bank(
            ManagedAclPublicationMode::StandaloneCompatibility
        ));
        assert!(group_delete_rollback_restores_acl_bank(
            ManagedAclPublicationMode::NeutronAttachOwnedStandaloneAcl
        ));
    }

    #[test]
    fn managed_projection_repair_verified_invalidates_before_first_mutation() {
        let decision = managed_acl_publication_decision(ProjectionDrift::Clean, true)
            .expect("a real ACL change must publish");

        assert!(matches!(
            &decision,
            ManagedAclPublicationDecision::Publish {
                selector_repair_performed: false,
                repair_plan: None,
                pre_mutation_health: ManagedProjectionHealth::Unverified,
            }
        ));
        let semantic_mutation = SharedNetworkMutation::Added {
            direction: "src",
            cidr: "198.51.100.0/24".to_string(),
            group_id: 88,
        };
        let steps = managed_acl_publication_steps(&decision, vec![semantic_mutation.clone()]);
        assert!(matches!(
            steps.first(),
            Some(ManagedAclPublicationStep::InvalidateProjectionHealth)
        ));
        assert_eq!(
            steps.get(1),
            Some(&ManagedAclPublicationStep::ApplyGeneral(semantic_mutation))
        );
    }

    #[test]
    fn managed_projection_repair_clean_equal_reconcile_is_noop() {
        let decision = managed_acl_publication_decision(ProjectionDrift::Clean, false)
            .expect("clean inventory must be accepted");

        assert_eq!(decision, ManagedAclPublicationDecision::Noop);
        assert!(managed_acl_publication_steps(&decision, Vec::new()).is_empty());
    }

    #[test]
    fn managed_projection_repair_equal_drift_returns_one_publication() {
        let repair_plan = aria_core::ebpf_ops::ProjectionRepairPlan {
            general_mutations: Vec::new(),
        };
        let decision = managed_acl_publication_decision(
            ProjectionDrift::RepairRequired(repair_plan.clone()),
            false,
        )
        .expect("explainable equal drift must publish once");

        assert_eq!(
            decision,
            ManagedAclPublicationDecision::Publish {
                selector_repair_performed: true,
                repair_plan: Some(repair_plan),
                pre_mutation_health: ManagedProjectionHealth::Unverified,
            }
        );
        assert_eq!(
            managed_publication_step_counts(&decision, Vec::new()),
            (0, 1, 1)
        );
        assert_eq!(
            managed_acl_publication_decision(ProjectionDrift::Clean, false)
                .expect("the repaired next equal snapshot must be clean"),
            ManagedAclPublicationDecision::Noop
        );
    }

    #[test]
    fn managed_projection_repair_and_real_change_share_one_transaction() {
        let repair_plan = aria_core::ebpf_ops::ProjectionRepairPlan {
            general_mutations: vec![
                aria_core::ebpf_ops::ProjectionMutation::Replaced {
                    direction: aria_core::ebpf_ops::ProjectionDirection::Src,
                    network: aria_core::ebpf_ops::CanonicalNetwork::parse("10.0.0.0/24")
                        .expect("valid test CIDR"),
                    old_group_id: 41,
                    new_group_id: 71,
                },
                aria_core::ebpf_ops::ProjectionMutation::Replaced {
                    direction: aria_core::ebpf_ops::ProjectionDirection::Dst,
                    network: aria_core::ebpf_ops::CanonicalNetwork::parse("10.0.0.0/24")
                        .expect("valid test CIDR"),
                    old_group_id: 42,
                    new_group_id: 72,
                },
            ],
        };

        let decision = managed_acl_publication_decision(
            ProjectionDrift::RepairRequired(repair_plan.clone()),
            true,
        )
        .expect("repair plus desired change must remain one publication");
        assert_eq!(
            decision,
            ManagedAclPublicationDecision::Publish {
                selector_repair_performed: true,
                repair_plan: Some(repair_plan),
                pre_mutation_health: ManagedProjectionHealth::Unverified,
            }
        );
        assert_eq!(
            managed_publication_step_counts(
                &decision,
                vec![SharedNetworkMutation::Added {
                    direction: "src",
                    cidr: "203.0.113.0/24".to_string(),
                    group_id: 999,
                }],
            ),
            (2, 1, 1)
        );
        let applied: Vec<_> = managed_acl_publication_steps(&decision, Vec::new())
            .into_iter()
            .filter_map(|step| match step {
                ManagedAclPublicationStep::ApplyGeneral(mutation) => Some(mutation),
                _ => None,
            })
            .collect();
        assert_eq!(
            applied,
            vec![
                SharedNetworkMutation::Replaced {
                    direction: "src",
                    cidr: "10.0.0.0/24".to_string(),
                    old_group_id: 41,
                    new_group_id: 71,
                },
                SharedNetworkMutation::Replaced {
                    direction: "dst",
                    cidr: "10.0.0.0/24".to_string(),
                    old_group_id: 42,
                    new_group_id: 72,
                },
            ]
        );
    }

    #[test]
    fn managed_projection_repair_fatal_capture_aborts_before_publication() {
        let error = managed_acl_publication_decision(
            ProjectionDrift::Fatal("unknown active selector".to_string()),
            true,
        )
        .expect_err("unknown runtime drift must fail closed");

        assert!(error.contains("unknown active selector"));
    }

    fn managed_cross_domain_insert_group(
        state: &mut FirewallState,
        name: &str,
        group_id: u32,
        cidrs: &[&str],
    ) {
        state.groups.insert(
            name.to_string(),
            GroupInfo {
                id: group_id,
                name: name.to_string(),
                cidrs: cidrs.iter().map(|cidr| (*cidr).to_string()).collect(),
            },
        );
        state.next_group_id = state.next_group_id.max(group_id.saturating_add(1));
    }

    fn managed_cross_domain_acl_rule(group_id: u32) -> RuleInfo {
        RuleInfo {
            name: None,
            src_group_id: group_id,
            dst_group_id: 0,
            proto: libc::IPPROTO_TCP as u8,
            action: 0,
            ports: None,
            bitmap_idx: None,
            direction: 0,
        }
    }

    fn managed_cross_domain_qos_reference(name: &str, group_id: u32) -> QosRuleInfo {
        QosRuleInfo {
            group_name: name.to_string(),
            group_id,
            direction: 0,
            rate_bps: 1_000_000,
            burst_bytes: 64_000,
            priority: 1,
            mode: 0,
        }
    }

    fn managed_cross_domain_mirror_reference(name: &str, group_id: u32) -> MirrorRuleInfo {
        MirrorRuleInfo {
            src_group_name: name.to_string(),
            src_group_id: group_id,
            dst_group_name: "any".to_string(),
            dst_group_id: 0,
            proto: 0,
            direction: 0,
            target_iface: "mirror0".to_string(),
            target_ifindex: 42,
            is_global: false,
        }
    }

    fn managed_cross_domain_projection(
        state: &FirewallState,
    ) -> aria_core::ebpf_ops::ManagedGroupProjection {
        aria_core::ebpf_ops::compile_managed_group_projection(state)
            .expect("managed cross-domain fixture must compile")
    }

    fn managed_cross_domain_has_projection_entry(
        entries: &[aria_core::ebpf_ops::ProjectionEntry],
        cidr: &str,
        group_id: u32,
    ) -> bool {
        let network = aria_core::ebpf_ops::CanonicalNetwork::parse(cidr)
            .expect("test projection CIDR must be valid");
        entries
            .iter()
            .any(|entry| entry.network == network && entry.group_id == group_id)
    }

    fn managed_cross_domain_replacements(
        cidr: &str,
        old_group_id: u32,
        new_group_id: u32,
    ) -> Vec<SharedNetworkMutation> {
        vec![
            SharedNetworkMutation::Replaced {
                direction: "src",
                cidr: cidr.to_string(),
                old_group_id,
                new_group_id,
            },
            SharedNetworkMutation::Replaced {
                direction: "dst",
                cidr: cidr.to_string(),
                old_group_id,
                new_group_id,
            },
        ]
    }

    fn managed_cross_domain_exact_alias_fixture(
        acl_name: &str,
        acl_group_id: u32,
        local_group_id: u32,
    ) -> FirewallState {
        let mut state = FirewallState::default();
        managed_cross_domain_insert_group(&mut state, acl_name, acl_group_id, &["10.0.0.0/24"]);
        managed_cross_domain_insert_group(
            &mut state,
            "local-exact",
            local_group_id,
            &["10.0.0.0/24"],
        );
        state
            .rules
            .push(managed_cross_domain_acl_rule(acl_group_id));
        state
    }

    #[test]
    fn managed_local_group_projection_rejects_acl_referenced_id_regardless_of_name() {
        let mut state = FirewallState::default();
        managed_cross_domain_insert_group(&mut state, "ordinary-local-name", 30, &["10.0.0.0/24"]);
        state.rules.push(managed_cross_domain_acl_rule(30));

        let error = validate_managed_group_mutation(&state, 30)
            .expect_err("an ACL-referenced group ID must reject local CIDR mutation");

        assert!(matches!(error, ControlPlaneError::GroupInUse(_)));
        assert!(!state
            .groups
            .get("ordinary-local-name")
            .expect("fixture group exists")
            .name
            .starts_with("neutron:"));
    }

    #[test]
    fn managed_local_group_projection_unreferenced_add_delete_is_general_only() {
        let mut committed = FirewallState::default();
        managed_cross_domain_insert_group(
            &mut committed,
            "ordinary-acl-selector",
            30,
            &["10.0.0.0/24"],
        );
        committed.rules.push(managed_cross_domain_acl_rule(30));

        let mut with_local = committed.clone();
        managed_cross_domain_insert_group(
            &mut with_local,
            "local-general-only",
            40,
            &["192.0.2.0/24"],
        );
        validate_managed_group_mutation(&with_local, 40)
            .expect("an ACL-unreferenced group ID must remain locally mutable");
        let add_mutations = managed_general_state_mutations(&committed, &with_local)
            .expect("valid local add must produce a general delta");
        assert_eq!(
            add_mutations,
            vec![
                SharedNetworkMutation::Added {
                    direction: "src",
                    cidr: "192.0.2.0/24".to_string(),
                    group_id: 40,
                },
                SharedNetworkMutation::Added {
                    direction: "dst",
                    cidr: "192.0.2.0/24".to_string(),
                    group_id: 40,
                },
            ]
        );
        let committed_projection = managed_cross_domain_projection(&committed);
        let with_local_projection = managed_cross_domain_projection(&with_local);
        assert_eq!(committed_projection.acl_src, with_local_projection.acl_src);
        assert_eq!(committed_projection.acl_dst, with_local_projection.acl_dst);

        let delete_mutations = managed_general_state_mutations(&with_local, &committed)
            .expect("valid local delete must produce a general delta");
        assert_eq!(
            delete_mutations,
            vec![
                SharedNetworkMutation::Deleted {
                    direction: "src",
                    cidr: "192.0.2.0/24".to_string(),
                    group_id: 40,
                },
                SharedNetworkMutation::Deleted {
                    direction: "dst",
                    cidr: "192.0.2.0/24".to_string(),
                    group_id: 40,
                },
            ]
        );
    }

    #[test]
    fn managed_local_group_projection_exact_winner_uses_replaced_preimages() {
        let mut committed = FirewallState::default();
        managed_cross_domain_insert_group(
            &mut committed,
            "ordinary-acl-selector",
            30,
            &["10.0.0.0/24"],
        );
        committed.rules.push(managed_cross_domain_acl_rule(30));

        let mut with_local_winner = committed.clone();
        managed_cross_domain_insert_group(
            &mut with_local_winner,
            "local-exact-winner",
            40,
            &["10.0.0.0/24"],
        );
        let add_mutations = managed_general_state_mutations(&committed, &with_local_winner)
            .expect("exact local winner add must compile");
        let delete_mutations = managed_general_state_mutations(&with_local_winner, &committed)
            .expect("exact local winner delete must compile");

        assert_eq!(
            add_mutations,
            managed_cross_domain_replacements("10.0.0.0/24", 30, 40)
        );
        assert_eq!(
            delete_mutations,
            managed_cross_domain_replacements("10.0.0.0/24", 40, 30)
        );
        assert_eq!(
            shared_network_compensation(&add_mutations[0]),
            delete_mutations[0]
        );
        assert_eq!(
            shared_network_compensation(&add_mutations[1]),
            delete_mutations[1]
        );

        let committed_projection = managed_cross_domain_projection(&committed);
        let local_projection = managed_cross_domain_projection(&with_local_winner);
        assert_eq!(committed_projection.acl_src, local_projection.acl_src);
        assert_eq!(committed_projection.acl_dst, local_projection.acl_dst);
    }

    #[test]
    fn managed_local_group_projection_unready_rejects_before_effects() {
        for health in [
            ManagedProjectionHealth::Unverified,
            ManagedProjectionHealth::RepairRequired,
        ] {
            let error =
                managed_local_projection_admission(ManagedAclPublicationMode::ManagedAcl, health)
                    .expect_err("non-verified managed projection must reject local mutation");
            assert_eq!(error.status_code(), 503);
        }

        managed_local_projection_admission(
            ManagedAclPublicationMode::ManagedAcl,
            ManagedProjectionHealth::Verified,
        )
        .expect("verified managed projection may plan one local mutation");
        managed_local_projection_admission(
            ManagedAclPublicationMode::StandaloneCompatibility,
            ManagedProjectionHealth::Unverified,
        )
        .expect("standalone compatibility keeps its existing direct mutation path");
    }

    #[tokio::test]
    async fn managed_local_group_projection_partial_general_failure_compensates_applied_in_reverse()
    {
        let mutations = managed_cross_domain_replacements("10.0.0.0/24", 20, 30);
        let trace = std::cell::RefCell::new(vec!["health:verified"]);
        let compensation_attempts = std::cell::RefCell::new(Vec::new());
        let durable_restore_attempted = std::cell::Cell::new(false);

        let error = execute_managed_local_projection_transaction(
            &mutations,
            |health| match health {
                ManagedProjectionHealth::Unverified => trace.borrow_mut().push("health:unverified"),
                ManagedProjectionHealth::RepairRequired => {
                    trace.borrow_mut().push("health:repair-required")
                }
                ManagedProjectionHealth::Verified => trace.borrow_mut().push("health:verified"),
            },
            |mutation| {
                trace.borrow_mut().push(match mutation {
                    SharedNetworkMutation::Replaced {
                        direction: "src", ..
                    } => "apply:src",
                    SharedNetworkMutation::Replaced {
                        direction: "dst", ..
                    } => "apply:dst",
                    _ => "apply:unexpected",
                });
                if matches!(
                    mutation,
                    SharedNetworkMutation::Replaced {
                        direction: "dst",
                        ..
                    }
                ) {
                    std::future::ready(Err("forced destination general apply failure".to_string()))
                } else {
                    std::future::ready(Ok(mutation.clone()))
                }
            },
            || {
                trace.borrow_mut().push("persist");
                std::future::ready(Ok(()))
            },
            |mutation| {
                compensation_attempts
                    .borrow_mut()
                    .push(shared_network_compensation(mutation));
                trace.borrow_mut().push(match mutation {
                    SharedNetworkMutation::Replaced {
                        direction: "src", ..
                    } => "compensate:src",
                    SharedNetworkMutation::Replaced {
                        direction: "dst", ..
                    } => "compensate:dst",
                    _ => "compensate:unexpected",
                });
                std::future::ready(Ok(()))
            },
            || {
                durable_restore_attempted.set(true);
                trace.borrow_mut().push("restore-durable");
                std::future::ready(Ok(()))
            },
        )
        .await
        .expect_err("second-direction failure must abort the shared transaction");

        assert!(error.contains("forced destination general apply failure"));
        assert_eq!(
            trace.into_inner(),
            vec![
                "health:verified",
                "health:unverified",
                "apply:src",
                "apply:dst",
                "compensate:src",
            ]
        );
        assert_eq!(
            compensation_attempts.into_inner(),
            vec![SharedNetworkMutation::Replaced {
                direction: "src",
                cidr: "10.0.0.0/24".to_string(),
                old_group_id: 30,
                new_group_id: 20,
            }]
        );
        assert!(!durable_restore_attempted.get());
    }

    #[tokio::test]
    async fn managed_local_group_projection_success_never_runs_compensation_or_durable_restore() {
        let mutations = vec![SharedNetworkMutation::Added {
            direction: "src",
            cidr: "198.51.100.0/24".to_string(),
            group_id: 70,
        }];
        let health_trace = std::cell::RefCell::new(vec![ManagedProjectionHealth::Verified]);
        let phase_trace = std::cell::RefCell::new(Vec::new());
        let compensation_attempted = std::cell::Cell::new(false);
        let durable_restore_attempted = std::cell::Cell::new(false);

        execute_managed_local_projection_transaction(
            &mutations,
            |health| health_trace.borrow_mut().push(health),
            |mutation| {
                phase_trace.borrow_mut().push("apply");
                std::future::ready(Ok::<SharedNetworkMutation, String>(mutation.clone()))
            },
            || {
                phase_trace.borrow_mut().push("persist");
                std::future::ready(Ok::<(), String>(()))
            },
            |_receipt| {
                compensation_attempted.set(true);
                std::future::ready(Ok::<(), String>(()))
            },
            || {
                durable_restore_attempted.set(true);
                std::future::ready(Ok::<(), String>(()))
            },
        )
        .await
        .expect("a fully applied and persisted transaction must succeed");

        assert_eq!(phase_trace.into_inner(), vec!["apply", "persist"]);
        assert!(!compensation_attempted.get());
        assert!(!durable_restore_attempted.get());
        assert_eq!(
            health_trace.into_inner(),
            vec![
                ManagedProjectionHealth::Verified,
                ManagedProjectionHealth::Unverified,
            ]
        );
    }

    #[test]
    fn managed_dual_use_group_reference_count_transitions_change_only_first_and_last() {
        let zero =
            managed_cross_domain_exact_alias_fixture("neutron:port-1:src:selector:0", 30, 20);
        let mut one = zero.clone();
        one.qos_rules.push(managed_cross_domain_qos_reference(
            "neutron:port-1:src:selector:0",
            30,
        ));
        let mut two = one.clone();
        two.mirror_rules.push(managed_cross_domain_mirror_reference(
            "neutron:port-1:src:selector:0",
            30,
        ));
        let mut back_to_one = two.clone();
        back_to_one.qos_rules.clear();
        let mut back_to_zero = back_to_one.clone();
        back_to_zero.mirror_rules.clear();

        assert_eq!(
            managed_general_state_mutations(&zero, &one).expect("0 to 1 must compile"),
            managed_cross_domain_replacements("10.0.0.0/24", 20, 30)
        );
        assert!(managed_general_state_mutations(&one, &two)
            .expect("1 to 2 must compile")
            .is_empty());
        assert!(managed_general_state_mutations(&two, &back_to_one)
            .expect("2 to 1 must compile")
            .is_empty());
        assert_eq!(
            managed_general_state_mutations(&back_to_one, &back_to_zero)
                .expect("1 to 0 must compile"),
            managed_cross_domain_replacements("10.0.0.0/24", 30, 20)
        );
    }

    #[test]
    fn managed_dual_use_group_owned_selector_removal_retains_until_final_reference() {
        let owner_prefix = "neutron:port-1:";
        let owned_name = "neutron:port-1:src:selector:0";
        let old = {
            let mut state = managed_cross_domain_exact_alias_fixture(owned_name, 30, 20);
            state
                .qos_rules
                .push(managed_cross_domain_qos_reference(owned_name, 30));
            state
                .mirror_rules
                .push(managed_cross_domain_mirror_reference(owned_name, 30));
            state
        };

        let mut after_acl_remove = old.clone();
        after_acl_remove.rules.clear();
        after_acl_remove.groups.remove(owned_name);
        let removed_after_acl =
            reconcile_retained_owned_groups(&old, &mut after_acl_remove, owner_prefix)
                .expect("external references must retain removed owned group data");
        assert!(removed_after_acl.is_empty());
        let retained = after_acl_remove
            .groups
            .get(owned_name)
            .expect("dual-used owned group must remain persisted");
        assert_eq!(retained.id, 30);
        assert_eq!(retained.cidrs, vec!["10.0.0.0/24".to_string()]);
        let retained_projection = managed_cross_domain_projection(&after_acl_remove);
        assert!(retained_projection.acl_src.is_empty());
        assert!(managed_cross_domain_has_projection_entry(
            &retained_projection.general,
            "10.0.0.0/24",
            30,
        ));

        let mut one_reference = after_acl_remove.clone();
        one_reference.qos_rules.clear();
        let removed_with_one_reference =
            reconcile_retained_owned_groups(&after_acl_remove, &mut one_reference, owner_prefix)
                .expect("one remaining external reference must retain the group");
        assert!(removed_with_one_reference.is_empty());
        assert!(one_reference.groups.contains_key(owned_name));

        let mut no_references = one_reference.clone();
        no_references.mirror_rules.clear();
        let removed_after_final_reference =
            reconcile_retained_owned_groups(&one_reference, &mut no_references, owner_prefix)
                .expect("last external reference removal must garbage-collect retained group");
        assert_eq!(removed_after_final_reference, vec![30]);
        assert!(!no_references.groups.contains_key(owned_name));
        assert_eq!(
            managed_general_state_mutations(&one_reference, &no_references)
                .expect("retained-owned GC must compile"),
            managed_cross_domain_replacements("10.0.0.0/24", 30, 20)
        );
    }

    #[test]
    fn managed_dual_use_group_mirror_destination_only_retains_owned_selector() {
        let owner_prefix = "neutron:port-1:";
        let owned_name = "neutron:port-1:dst:selector:0";
        let zero = managed_cross_domain_exact_alias_fixture(owned_name, 30, 20);
        let mut dual_used = zero.clone();
        let mut destination_reference = managed_cross_domain_mirror_reference("any", 0);
        destination_reference.dst_group_name = owned_name.to_string();
        destination_reference.dst_group_id = 30;
        dual_used.mirror_rules.push(destination_reference);

        assert_eq!(
            managed_general_state_mutations(&zero, &dual_used)
                .expect("a destination-only Mirror reference must promote general identity"),
            managed_cross_domain_replacements("10.0.0.0/24", 20, 30)
        );

        let mut after_acl_remove = dual_used.clone();
        after_acl_remove.rules.clear();
        after_acl_remove.groups.remove(owned_name);
        let removed_group_ids =
            reconcile_retained_owned_groups(&dual_used, &mut after_acl_remove, owner_prefix)
                .expect("a destination-only Mirror reference must retain removed owned data");
        assert!(removed_group_ids.is_empty());

        assert_eq!(after_acl_remove.groups[owned_name].id, 30);
        assert!(managed_cross_domain_has_projection_entry(
            &managed_cross_domain_projection(&after_acl_remove).general,
            "10.0.0.0/24",
            30,
        ));
    }

    #[test]
    fn managed_dual_use_group_last_explicit_reference_never_collects_acl_referenced_group() {
        let owned_name = "neutron:port-1:src:selector:0";
        let old = {
            let mut state = managed_cross_domain_exact_alias_fixture(owned_name, 30, 20);
            state
                .qos_rules
                .push(managed_cross_domain_qos_reference(owned_name, 30));
            state
        };
        let mut final_state = old.clone();
        final_state.qos_rules.clear();

        let removed_group_ids =
            reconcile_retained_owned_groups(&old, &mut final_state, "neutron:port-1:")
                .expect("removing the last explicit reference must preserve an ACL-owned group");
        assert!(removed_group_ids.is_empty());

        assert!(final_state.groups.contains_key(owned_name));
        assert!(final_state
            .rules
            .iter()
            .any(|rule| rule.src_group_id == 30 || rule.dst_group_id == 30));
        assert_eq!(
            managed_general_state_mutations(&old, &final_state)
                .expect("last explicit reference removal must only demote general identity"),
            managed_cross_domain_replacements("10.0.0.0/24", 30, 20)
        );
    }

    #[test]
    fn managed_dual_use_group_acl_cidr_update_changes_shared_general_identity() {
        let owned_name = "neutron:port-1:src:selector:0";
        let mut old = FirewallState::default();
        managed_cross_domain_insert_group(&mut old, owned_name, 30, &["10.0.0.0/24"]);
        old.rules.push(managed_cross_domain_acl_rule(30));
        old.qos_rules
            .push(managed_cross_domain_qos_reference(owned_name, 30));

        let mut updated = old.clone();
        updated
            .groups
            .get_mut(owned_name)
            .expect("owned fixture group exists")
            .cidrs = vec!["10.0.1.0/24".to_string()];
        let removed_group_ids =
            reconcile_retained_owned_groups(&old, &mut updated, "neutron:port-1:")
                .expect("dual-use CIDR update must preserve shared identity");
        assert!(removed_group_ids.is_empty());

        assert_eq!(updated.groups[owned_name].id, 30);
        assert_eq!(
            managed_general_state_mutations(&old, &updated)
                .expect("dual-use CIDR update must compile"),
            vec![
                SharedNetworkMutation::Added {
                    direction: "src",
                    cidr: "10.0.1.0/24".to_string(),
                    group_id: 30,
                },
                SharedNetworkMutation::Deleted {
                    direction: "src",
                    cidr: "10.0.0.0/24".to_string(),
                    group_id: 30,
                },
                SharedNetworkMutation::Added {
                    direction: "dst",
                    cidr: "10.0.1.0/24".to_string(),
                    group_id: 30,
                },
                SharedNetworkMutation::Deleted {
                    direction: "dst",
                    cidr: "10.0.0.0/24".to_string(),
                    group_id: 30,
                },
            ]
        );
        let projection = managed_cross_domain_projection(&updated);
        assert!(managed_cross_domain_has_projection_entry(
            &projection.acl_src,
            "10.0.1.0/24",
            30,
        ));
        assert!(managed_cross_domain_has_projection_entry(
            &projection.general,
            "10.0.1.0/24",
            30,
        ));
    }

    #[test]
    fn managed_dual_use_group_direction_two_qos_plan_preserves_direction_semantics() {
        assert_eq!(
            ControlPlane::requested_directions(2)
                .expect("direction 2 must be a valid both-direction request"),
            vec![0, 1]
        );

        let plans = managed_qos_direction_plans(2, 1)
            .expect("both-direction shaping must produce one plan per direction");
        assert_eq!(
            plans
                .iter()
                .map(|plan| (plan.direction, plan.effective_mode))
                .collect::<Vec<_>>(),
            vec![(0, 0), (1, 1)]
        );
    }

    #[test]
    fn managed_dual_use_group_merge_orders_general_and_both_direction_domain_operations() {
        let plans = managed_qos_direction_plans(2, 1)
            .expect("both-direction shaping must produce domain plans");
        let mut add_domain = vec![ManagedLocalDomainOperation::EnsureFqQdisc {
            cleanup_on_rollback: true,
        }];
        add_domain.extend(plans.iter().map(|plan| {
            let mut rule = managed_cross_domain_qos_reference("dual-use", 30);
            rule.direction = plan.direction;
            rule.mode = plan.effective_mode;
            ManagedLocalDomainOperation::QosUpsert(rule)
        }));
        let delete_domain = plans
            .iter()
            .map(|plan| ManagedLocalDomainOperation::QosDelete {
                group_id: 30,
                direction: plan.direction,
            })
            .collect::<Vec<_>>();
        let expected_add_general = managed_cross_domain_replacements("10.0.0.0/24", 20, 30);
        let add_merged = merge_managed_local_projection_operations(
            ManagedLocalProjectionOrder::GeneralThenDomain,
            managed_cross_domain_replacements("10.0.0.0/24", 20, 30),
            add_domain,
        );

        assert_eq!(add_merged.len(), 5);
        match &add_merged[0] {
            ManagedLocalProjectionOperation::General(actual) => {
                assert_eq!(actual, &expected_add_general[0]);
            }
            _ => panic!("add must start with the source general operation"),
        }
        match &add_merged[1] {
            ManagedLocalProjectionOperation::General(actual) => {
                assert_eq!(actual, &expected_add_general[1]);
            }
            _ => panic!("add must apply the destination general operation second"),
        }
        match &add_merged[2] {
            ManagedLocalProjectionOperation::Domain(
                ManagedLocalDomainOperation::EnsureFqQdisc {
                    cleanup_on_rollback,
                },
            ) => assert!(*cleanup_on_rollback),
            _ => panic!("FQ preparation must precede every direction-specific QoS add"),
        }
        match (&add_merged[3], &add_merged[4]) {
            (
                ManagedLocalProjectionOperation::Domain(ManagedLocalDomainOperation::QosUpsert(
                    ingress,
                )),
                ManagedLocalProjectionOperation::Domain(ManagedLocalDomainOperation::QosUpsert(
                    egress,
                )),
            ) => {
                assert_eq!((ingress.direction, ingress.mode), (0, 0));
                assert_eq!((egress.direction, egress.mode), (1, 1));
            }
            _ => panic!("both direction-specific QoS add plans must follow general operations"),
        }

        let expected_delete_general = managed_cross_domain_replacements("10.0.0.0/24", 30, 20);
        let delete_merged = merge_managed_local_projection_operations(
            ManagedLocalProjectionOrder::DomainThenGeneral,
            managed_cross_domain_replacements("10.0.0.0/24", 30, 20),
            delete_domain,
        );

        assert_eq!(delete_merged.len(), 4);
        match (&delete_merged[0], &delete_merged[1]) {
            (
                ManagedLocalProjectionOperation::Domain(ManagedLocalDomainOperation::QosDelete {
                    group_id: first_group,
                    direction: first_direction,
                }),
                ManagedLocalProjectionOperation::Domain(ManagedLocalDomainOperation::QosDelete {
                    group_id: second_group,
                    direction: second_direction,
                }),
            ) => {
                assert_eq!((*first_group, *first_direction), (30, 0));
                assert_eq!((*second_group, *second_direction), (30, 1));
            }
            _ => panic!("both direction-specific QoS deletes must precede general operations"),
        }
        match &delete_merged[2] {
            ManagedLocalProjectionOperation::General(actual) => {
                assert_eq!(actual, &expected_delete_general[0]);
            }
            _ => panic!("delete must demote source general identity after domain cleanup"),
        }
        match &delete_merged[3] {
            ManagedLocalProjectionOperation::General(actual) => {
                assert_eq!(actual, &expected_delete_general[1]);
            }
            _ => panic!("delete must demote destination general identity last"),
        }
    }

    #[tokio::test]
    async fn managed_dual_use_group_compensation_helper_is_reverse_attempt_all_and_visible() {
        let applied = managed_cross_domain_replacements("10.0.0.0/24", 20, 30);
        let attempts = std::cell::RefCell::new(Vec::new());

        let errors = execute_managed_local_projection_compensations(&applied, |mutation| {
            let compensation = shared_network_compensation(mutation);
            let fail = matches!(
                &compensation,
                SharedNetworkMutation::Replaced {
                    direction: "dst",
                    ..
                }
            );
            attempts.borrow_mut().push(compensation);
            if fail {
                std::future::ready(Err("forced destination compensation failure".to_string()))
            } else {
                std::future::ready(Ok(()))
            }
        })
        .await;

        assert_eq!(
            errors,
            vec!["forced destination compensation failure".to_string()]
        );
        assert_eq!(
            attempts.into_inner(),
            applied
                .iter()
                .rev()
                .map(shared_network_compensation)
                .collect::<Vec<_>>()
        );
    }

    #[tokio::test]
    async fn managed_dual_use_group_qos_receipt_restores_previous_rule_after_later_failure() {
        let mut previous = managed_cross_domain_qos_reference("dual-use", 30);
        previous.direction = 1;
        previous.rate_bps = 1_000_000;
        previous.burst_bytes = 64_000;
        previous.mode = 0;
        let mut replacement = previous.clone();
        replacement.rate_bps = 8_000_000;
        replacement.burst_bytes = 256_000;
        replacement.mode = 1;
        let mut later = replacement.clone();
        later.direction = 0;
        later.mode = 0;
        let operations = vec![
            ManagedLocalProjectionOperation::Domain(ManagedLocalDomainOperation::EnsureFqQdisc {
                cleanup_on_rollback: true,
            }),
            ManagedLocalProjectionOperation::Domain(ManagedLocalDomainOperation::QosUpsert(
                replacement.clone(),
            )),
            ManagedLocalProjectionOperation::Domain(ManagedLocalDomainOperation::QosUpsert(later)),
        ];
        let compensation_operations = std::cell::RefCell::new(Vec::new());
        let persist_attempted = std::cell::Cell::new(false);
        let durable_restore_attempted = std::cell::Cell::new(false);

        let error = execute_managed_local_projection_transaction(
            &operations,
            |_health| {},
            |operation| match operation {
                ManagedLocalProjectionOperation::Domain(
                    ManagedLocalDomainOperation::EnsureFqQdisc {
                        cleanup_on_rollback,
                    },
                ) => std::future::ready(Ok(ManagedLocalDomainReceipt::FqQdisc {
                    state: aria_core::ebpf_ops::FqQdiscState::InstalledNow,
                    cleanup_on_rollback: *cleanup_on_rollback,
                })),
                ManagedLocalProjectionOperation::Domain(
                    ManagedLocalDomainOperation::QosUpsert(applied),
                ) if applied.direction == 1 => {
                    std::future::ready(Ok(ManagedLocalDomainReceipt::QosUpsert {
                        applied: applied.clone(),
                        previous: Some(previous.clone()),
                    }))
                }
                ManagedLocalProjectionOperation::Domain(
                    ManagedLocalDomainOperation::QosUpsert(_),
                ) => std::future::ready(Err("forced later QoS apply failure".to_string())),
                _ => std::future::ready(Err("unexpected non-QoS operation".to_string())),
            },
            || {
                persist_attempted.set(true);
                std::future::ready(Ok::<(), String>(()))
            },
            |receipt| {
                compensation_operations
                    .borrow_mut()
                    .extend(managed_local_domain_compensation_operations(receipt));
                std::future::ready(Ok::<(), String>(()))
            },
            || {
                durable_restore_attempted.set(true);
                std::future::ready(Ok::<(), String>(()))
            },
        )
        .await
        .expect_err("a later domain failure must compensate the applied QoS receipt");

        assert!(error.contains("forced later QoS apply failure"));
        assert!(!persist_attempted.get());
        assert!(!durable_restore_attempted.get());
        let compensation_operations = compensation_operations.into_inner();
        assert_eq!(compensation_operations.len(), 2);
        match &compensation_operations[0] {
            ManagedLocalDomainOperation::QosUpsert(restored) => {
                assert_eq!(restored.group_id, previous.group_id);
                assert_eq!(restored.direction, previous.direction);
                assert_eq!(restored.rate_bps, previous.rate_bps);
                assert_eq!(restored.burst_bytes, previous.burst_bytes);
                assert_eq!(restored.priority, previous.priority);
                assert_eq!(restored.mode, previous.mode);
            }
            _ => panic!("QoS replacement compensation must restore the complete prior rule"),
        }
        assert!(matches!(
            &compensation_operations[1],
            ManagedLocalDomainOperation::CleanupOwnedFqQdisc
        ));

        let delete_compensation =
            managed_local_domain_compensation_operations(&ManagedLocalDomainReceipt::QosDelete {
                deleted: previous.clone(),
            });
        assert_eq!(delete_compensation.len(), 1);
        match &delete_compensation[0] {
            ManagedLocalDomainOperation::QosUpsert(restored) => {
                assert_eq!(restored.group_id, previous.group_id);
                assert_eq!(restored.direction, previous.direction);
                assert_eq!(restored.rate_bps, previous.rate_bps);
                assert_eq!(restored.burst_bytes, previous.burst_bytes);
                assert_eq!(restored.priority, previous.priority);
                assert_eq!(restored.mode, previous.mode);
            }
            _ => panic!("QoS delete compensation must restore the complete deleted rule"),
        }
    }

    #[tokio::test]
    async fn managed_dual_use_group_mirror_receipt_restores_previous_rule_after_later_failure() {
        let mut previous = managed_cross_domain_mirror_reference("dual-use", 30);
        previous.proto = libc::IPPROTO_TCP as u8;
        previous.direction = 1;
        previous.target_iface = "mirror-old".to_string();
        previous.target_ifindex = 42;
        let mut replacement = previous.clone();
        replacement.target_iface = "mirror-new".to_string();
        replacement.target_ifindex = 84;
        let mut later = replacement.clone();
        later.direction = 0;
        let operations = vec![
            ManagedLocalProjectionOperation::Domain(ManagedLocalDomainOperation::MirrorUpsert(
                replacement,
            )),
            ManagedLocalProjectionOperation::Domain(ManagedLocalDomainOperation::MirrorUpsert(
                later,
            )),
        ];
        let compensation_operations = std::cell::RefCell::new(Vec::new());
        let persist_attempted = std::cell::Cell::new(false);
        let durable_restore_attempted = std::cell::Cell::new(false);

        let error = execute_managed_local_projection_transaction(
            &operations,
            |_health| {},
            |operation| match operation {
                ManagedLocalProjectionOperation::Domain(
                    ManagedLocalDomainOperation::MirrorUpsert(applied),
                ) if applied.direction == 1 => {
                    std::future::ready(Ok(ManagedLocalDomainReceipt::MirrorUpsert {
                        applied: applied.clone(),
                        previous: Some(previous.clone()),
                    }))
                }
                ManagedLocalProjectionOperation::Domain(
                    ManagedLocalDomainOperation::MirrorUpsert(_),
                ) => std::future::ready(Err("forced later Mirror apply failure".to_string())),
                _ => std::future::ready(Err("unexpected non-Mirror operation".to_string())),
            },
            || {
                persist_attempted.set(true);
                std::future::ready(Ok::<(), String>(()))
            },
            |receipt| {
                compensation_operations
                    .borrow_mut()
                    .extend(managed_local_domain_compensation_operations(receipt));
                std::future::ready(Ok::<(), String>(()))
            },
            || {
                durable_restore_attempted.set(true);
                std::future::ready(Ok::<(), String>(()))
            },
        )
        .await
        .expect_err("a later domain failure must compensate the applied Mirror receipt");

        assert!(error.contains("forced later Mirror apply failure"));
        assert!(!persist_attempted.get());
        assert!(!durable_restore_attempted.get());
        let compensation_operations = compensation_operations.into_inner();
        assert_eq!(compensation_operations.len(), 1);
        match &compensation_operations[0] {
            ManagedLocalDomainOperation::MirrorUpsert(restored) => {
                assert_eq!(restored.src_group_name, previous.src_group_name);
                assert_eq!(restored.src_group_id, previous.src_group_id);
                assert_eq!(restored.dst_group_name, previous.dst_group_name);
                assert_eq!(restored.dst_group_id, previous.dst_group_id);
                assert_eq!(restored.proto, previous.proto);
                assert_eq!(restored.direction, previous.direction);
                assert_eq!(restored.target_iface, previous.target_iface);
                assert_eq!(restored.target_ifindex, previous.target_ifindex);
                assert_eq!(restored.is_global, previous.is_global);
            }
            _ => panic!("Mirror replacement compensation must restore the complete prior rule"),
        }

        let delete_compensation = managed_local_domain_compensation_operations(
            &ManagedLocalDomainReceipt::MirrorDelete {
                deleted: previous.clone(),
            },
        );
        assert_eq!(delete_compensation.len(), 1);
        match &delete_compensation[0] {
            ManagedLocalDomainOperation::MirrorUpsert(restored) => {
                assert_eq!(restored.src_group_name, previous.src_group_name);
                assert_eq!(restored.src_group_id, previous.src_group_id);
                assert_eq!(restored.dst_group_name, previous.dst_group_name);
                assert_eq!(restored.dst_group_id, previous.dst_group_id);
                assert_eq!(restored.proto, previous.proto);
                assert_eq!(restored.direction, previous.direction);
                assert_eq!(restored.target_iface, previous.target_iface);
                assert_eq!(restored.target_ifindex, previous.target_ifindex);
                assert_eq!(restored.is_global, previous.is_global);
            }
            _ => panic!("Mirror delete compensation must restore the complete deleted rule"),
        }
    }

    #[tokio::test]
    async fn managed_dual_use_group_current_domain_apply_failure_compensates_its_receipt() {
        let mut previous_qos = managed_cross_domain_qos_reference("dual-use", 30);
        previous_qos.direction = 1;
        previous_qos.mode = 0;
        let mut replacement_qos = previous_qos.clone();
        replacement_qos.rate_bps = 8_000_000;
        replacement_qos.burst_bytes = 256_000;
        replacement_qos.mode = 1;
        let qos_operation = ManagedLocalDomainOperation::QosUpsert(replacement_qos.clone());
        let qos_trace = std::cell::RefCell::new(Vec::new());
        let qos_compensation = std::cell::RefCell::new(Vec::new());

        let qos_result = apply_managed_local_projection_operation_transactionally(
            &qos_operation,
            ManagedLocalDomainReceipt::QosUpsert {
                applied: replacement_qos,
                previous: Some(previous_qos.clone()),
            },
            |_operation| {
                qos_trace.borrow_mut().push("raw-write:qos");
                std::future::ready(Err("raw QoS apply failed after write".to_string()))
            },
            |receipt| {
                qos_trace.borrow_mut().push("compensate:qos");
                qos_compensation
                    .borrow_mut()
                    .extend(managed_local_domain_compensation_operations(receipt));
                std::future::ready(Err("QoS current-operation compensation failed".to_string()))
            },
        )
        .await;
        let qos_error = match qos_result {
            Ok(_) => panic!("a raw QoS apply failure must remain visible"),
            Err(error) => error,
        };

        assert!(qos_error.contains("raw QoS apply failed after write"));
        assert!(qos_error.contains("QoS current-operation compensation failed"));
        assert_eq!(
            qos_trace.into_inner(),
            vec!["raw-write:qos", "compensate:qos"]
        );
        let qos_compensation = qos_compensation.into_inner();
        assert_eq!(qos_compensation.len(), 1);
        match &qos_compensation[0] {
            ManagedLocalDomainOperation::QosUpsert(restored) => {
                assert_eq!(restored.group_id, previous_qos.group_id);
                assert_eq!(restored.direction, previous_qos.direction);
                assert_eq!(restored.rate_bps, previous_qos.rate_bps);
                assert_eq!(restored.burst_bytes, previous_qos.burst_bytes);
                assert_eq!(restored.priority, previous_qos.priority);
                assert_eq!(restored.mode, previous_qos.mode);
            }
            _ => panic!("current QoS replacement failure must restore its preimage"),
        }

        let mut previous_mirror = managed_cross_domain_mirror_reference("dual-use", 30);
        previous_mirror.proto = libc::IPPROTO_TCP as u8;
        previous_mirror.direction = 1;
        previous_mirror.target_iface = "mirror-old".to_string();
        previous_mirror.target_ifindex = 42;
        let mut replacement_mirror = previous_mirror.clone();
        replacement_mirror.target_iface = "mirror-new".to_string();
        replacement_mirror.target_ifindex = 84;
        let mirror_operation =
            ManagedLocalDomainOperation::MirrorUpsert(replacement_mirror.clone());
        let mirror_trace = std::cell::RefCell::new(Vec::new());
        let mirror_compensation = std::cell::RefCell::new(Vec::new());

        let mirror_result = apply_managed_local_projection_operation_transactionally(
            &mirror_operation,
            ManagedLocalDomainReceipt::MirrorUpsert {
                applied: replacement_mirror,
                previous: Some(previous_mirror.clone()),
            },
            |_operation| {
                mirror_trace.borrow_mut().push("raw-write:mirror");
                std::future::ready(Err("raw Mirror apply failed after write".to_string()))
            },
            |receipt| {
                mirror_trace.borrow_mut().push("compensate:mirror");
                mirror_compensation
                    .borrow_mut()
                    .extend(managed_local_domain_compensation_operations(receipt));
                std::future::ready(Err(
                    "Mirror current-operation compensation failed".to_string()
                ))
            },
        )
        .await;
        let mirror_error = match mirror_result {
            Ok(_) => panic!("a raw Mirror apply failure must remain visible"),
            Err(error) => error,
        };

        assert!(mirror_error.contains("raw Mirror apply failed after write"));
        assert!(mirror_error.contains("Mirror current-operation compensation failed"));
        assert_eq!(
            mirror_trace.into_inner(),
            vec!["raw-write:mirror", "compensate:mirror"]
        );
        let mirror_compensation = mirror_compensation.into_inner();
        assert_eq!(mirror_compensation.len(), 1);
        match &mirror_compensation[0] {
            ManagedLocalDomainOperation::MirrorUpsert(restored) => {
                assert_eq!(restored.src_group_name, previous_mirror.src_group_name);
                assert_eq!(restored.src_group_id, previous_mirror.src_group_id);
                assert_eq!(restored.dst_group_name, previous_mirror.dst_group_name);
                assert_eq!(restored.dst_group_id, previous_mirror.dst_group_id);
                assert_eq!(restored.proto, previous_mirror.proto);
                assert_eq!(restored.direction, previous_mirror.direction);
                assert_eq!(restored.target_iface, previous_mirror.target_iface);
                assert_eq!(restored.target_ifindex, previous_mirror.target_ifindex);
                assert_eq!(restored.is_global, previous_mirror.is_global);
            }
            _ => panic!("current Mirror replacement failure must restore its preimage"),
        }
    }

    #[tokio::test]
    async fn managed_dual_use_group_fq_receipt_cleans_only_qdisc_installed_by_transaction() {
        for (state, cleanup_requested, cleanup_expected) in [
            (aria_core::ebpf_ops::FqQdiscState::InstalledNow, true, true),
            (
                aria_core::ebpf_ops::FqQdiscState::InstalledNow,
                false,
                false,
            ),
            (
                aria_core::ebpf_ops::FqQdiscState::AlreadyPresent,
                true,
                false,
            ),
        ] {
            let receipt = managed_local_fq_qdisc_apply_receipt(state, cleanup_requested);
            match receipt {
                ManagedLocalDomainReceipt::FqQdisc {
                    state: receipt_state,
                    cleanup_on_rollback,
                } => {
                    assert_eq!(receipt_state, state);
                    assert_eq!(cleanup_on_rollback, cleanup_expected);
                }
                _ => panic!("FQ apply helper must return its actual ownership receipt"),
            }
        }

        let mut applied = managed_cross_domain_qos_reference("dual-use", 30);
        applied.direction = 1;
        applied.mode = 1;
        let operations = vec![
            ManagedLocalProjectionOperation::Domain(ManagedLocalDomainOperation::EnsureFqQdisc {
                cleanup_on_rollback: true,
            }),
            ManagedLocalProjectionOperation::Domain(ManagedLocalDomainOperation::QosUpsert(
                applied,
            )),
        ];
        let compensation_operations = std::cell::RefCell::new(Vec::new());
        let persist_attempted = std::cell::Cell::new(false);
        let durable_restore_attempted = std::cell::Cell::new(false);

        let error = execute_managed_local_projection_transaction(
            &operations,
            |_health| {},
            |operation| match operation {
                ManagedLocalProjectionOperation::Domain(
                    ManagedLocalDomainOperation::EnsureFqQdisc {
                        cleanup_on_rollback,
                    },
                ) => std::future::ready(Ok(ManagedLocalDomainReceipt::FqQdisc {
                    state: aria_core::ebpf_ops::FqQdiscState::InstalledNow,
                    cleanup_on_rollback: *cleanup_on_rollback,
                })),
                ManagedLocalProjectionOperation::Domain(
                    ManagedLocalDomainOperation::QosUpsert(_),
                ) => std::future::ready(Err("forced QoS apply after FQ prepare".to_string())),
                _ => std::future::ready(Err("unexpected non-FQ/QoS operation".to_string())),
            },
            || {
                persist_attempted.set(true);
                std::future::ready(Ok::<(), String>(()))
            },
            |receipt| {
                compensation_operations
                    .borrow_mut()
                    .extend(managed_local_domain_compensation_operations(receipt));
                std::future::ready(Ok::<(), String>(()))
            },
            || {
                durable_restore_attempted.set(true);
                std::future::ready(Ok::<(), String>(()))
            },
        )
        .await
        .expect_err("QoS failure after FQ preparation must compensate the FQ receipt");

        assert!(error.contains("forced QoS apply after FQ prepare"));
        assert!(!persist_attempted.get());
        assert!(!durable_restore_attempted.get());
        let compensation_operations = compensation_operations.into_inner();
        assert_eq!(compensation_operations.len(), 1);
        assert!(matches!(
            &compensation_operations[0],
            ManagedLocalDomainOperation::CleanupOwnedFqQdisc
        ));

        let repaired_with_old_shaping = ManagedLocalDomainReceipt::FqQdisc {
            state: aria_core::ebpf_ops::FqQdiscState::InstalledNow,
            cleanup_on_rollback: false,
        };
        let preexisting = ManagedLocalDomainReceipt::FqQdisc {
            state: aria_core::ebpf_ops::FqQdiscState::AlreadyPresent,
            cleanup_on_rollback: false,
        };
        for receipt in [&repaired_with_old_shaping, &preexisting] {
            let compensation = managed_local_domain_compensation_operations(receipt);
            assert!(compensation.is_empty());
        }
    }

    #[tokio::test]
    async fn managed_dual_use_group_persistence_failure_reuses_applied_journal_and_stays_unverified(
    ) {
        let mutations = managed_cross_domain_replacements("10.0.0.0/24", 20, 30);
        let health_trace = std::cell::RefCell::new(vec![ManagedProjectionHealth::Verified]);
        let applied = std::cell::RefCell::new(Vec::new());
        let compensation_attempts = std::cell::RefCell::new(Vec::new());
        let phase_trace = std::cell::RefCell::new(Vec::new());

        let error = execute_managed_local_projection_transaction(
            &mutations,
            |health| health_trace.borrow_mut().push(health),
            |mutation| {
                applied.borrow_mut().push(mutation.clone());
                std::future::ready(Ok(mutation.clone()))
            },
            || {
                phase_trace.borrow_mut().push("persist");
                std::future::ready(Err("forced persistence failure".to_string()))
            },
            |mutation| {
                let compensation = shared_network_compensation(mutation);
                let fail = matches!(
                    &compensation,
                    SharedNetworkMutation::Replaced {
                        direction: "dst",
                        ..
                    }
                );
                phase_trace.borrow_mut().push(match &compensation {
                    SharedNetworkMutation::Replaced {
                        direction: "src", ..
                    } => "compensate:src",
                    SharedNetworkMutation::Replaced {
                        direction: "dst", ..
                    } => "compensate:dst",
                    _ => "compensate:unexpected",
                });
                compensation_attempts.borrow_mut().push(compensation);
                if fail {
                    std::future::ready(Err("forced destination compensation failure".to_string()))
                } else {
                    std::future::ready(Ok(()))
                }
            },
            || {
                phase_trace.borrow_mut().push("restore-durable");
                std::future::ready(Err("forced durable restore failure".to_string()))
            },
        )
        .await
        .expect_err("persistence failure must abort the shared transaction");

        assert!(error.contains("forced persistence failure"));
        assert!(error.contains("forced destination compensation failure"));
        assert!(error.contains("forced durable restore failure"));
        assert_eq!(
            compensation_attempts.into_inner(),
            applied
                .borrow()
                .iter()
                .rev()
                .map(shared_network_compensation)
                .collect::<Vec<_>>()
        );
        assert_eq!(
            phase_trace.into_inner(),
            vec![
                "persist",
                "compensate:dst",
                "compensate:src",
                "restore-durable",
            ]
        );
        assert_eq!(
            health_trace.into_inner(),
            vec![
                ManagedProjectionHealth::Verified,
                ManagedProjectionHealth::Unverified,
            ]
        );
    }

    #[test]
    fn domain_authority_exclusive_acl_replace_claims_foreign_rules() {
        let state = FirewallState::default();
        let foreign_rule = RuleInfo {
            name: None,
            src_group_id: 0,
            dst_group_id: 0,
            proto: libc::IPPROTO_ICMP as u8,
            action: 1,
            ports: None,
            bitmap_idx: None,
            direction: 1,
        };

        assert!(!ControlPlane::owned_acl_rule_in_replace_scope(
            &state,
            &foreign_rule,
            "neutron:port-1:",
            false,
        ));
        assert!(ControlPlane::owned_acl_rule_in_replace_scope(
            &state,
            &foreign_rule,
            "neutron:port-1:",
            true,
        ));
    }
}
