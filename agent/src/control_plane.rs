use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fs;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::{Mutex, RwLock};
use tracing::{error, info, warn};

use crate::instance::{
    preexisting_tc_acl_runtime_is_healthy, FirewallInstance,
    ManagedMaintenanceRuntimeIdentity, ManagedTcProgramIdentity, RuntimePinState,
    TcAclLinkHealth,
};
use crate::kernel_drop_manager::{KernelDropManager, KernelDropStatusSnapshot};
use crate::service_chain::{self, ServiceChain};
use crate::ssl_manager::SslManager;
use crate::tap_registry::ManagedAttachMode;
use crate::trace_backend::{TraceManager, TraceRuntimeStatusSnapshot};
use crate::FragmentTrackingSettings;
use aria_core::common::{FirewallConfig, TapMapRuntime, IP_FAMILY_V4, IP_FAMILY_V6};
use aria_core::ebpf_ops::{
    classify_runtime_gate_state, compile_managed_group_projection, ensure_fq_qdisc,
    lookup_iface_ctx, lookup_runtime_config, migrate_state_for_replay,
    replay_managed_state_to_pinned_maps,
    validate_managed_pinned_runtime_state, validate_pinned_runtime_state, FqQdiscState,
    GroupProjectionMode, ManagedReplayRoute, ProjectionDrift, RuntimeGateDisposition,
    RuntimeGroupMapEntries, TraceMapMode,
};
use aya::maps::{HashMap as BpfHashMap, Map, MapData};
use aria_core::state::{
    FirewallState, GroupInfo, LocalProjectionRecovery, MirrorRuleInfo, QosRuleInfo, RuleInfo,
};
use aria_core::wal::{WalClient, WalEntry};

mod observability;
mod ssl;
mod standalone_acl;
mod standalone_group;
mod tcprt;
mod trace;

pub(crate) use standalone_acl::{
    standalone_policy_family_protocols, StandaloneAclBatchItem, StandaloneAclMutation,
};

const WAL_COMPACT_THRESHOLD: u64 = 1000;
pub const MANAGED_SHARED_PIN_NAMESPACE: &str = "global-v2";
const FQ_QDISC_MARKER: &str = ".fq-root-qdisc-owned";
const MANAGED_RUNTIME_IDENTITY_MISSING_PREFIX: &str =
    "managed_runtime_identity_missing:";

pub(crate) fn managed_runtime_identity_missing(error: &str) -> bool {
    error.starts_with(MANAGED_RUNTIME_IDENTITY_MISSING_PREFIX)
}

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
    Demote {
        next_mode: ManagedAclPublicationMode,
        next_health: ManagedProjectionHealth,
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
    pub cleanup_pending_count: usize,
    pub maintenance_reason: Option<String>,
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

    async fn persist_local_projection_recovery(
        &mut self,
        domain: LocalWriteDomain,
        failure: ManagedLocalProjectionFailure,
    ) -> ControlPlaneError {
        let mut recovery_state = self.state.clone();
        recovery_state.mark_local_projection_recovery(
            domain.as_str(),
            LocalProjectionRecovery::new(failure.message.clone()),
        );
        let persist_error = self
            .compact_and_publish_state(recovery_state.clone())
            .await
            .err();
        // Keep the in-memory admission fence even when persistence itself is
        // unavailable. The durable write is retried during startup recovery.
        self.state = recovery_state;
        let mut message = failure.message;
        if let Some(error) = persist_error {
            message.push_str("; persist recovery record: ");
            message.push_str(&error);
        }
        ControlPlaneError::InstanceNotReady(format!(
            "local projection recovery required for {}: {}",
            domain.as_str(),
            message
        ))
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
            self.state.conntrack_enabled = false;
            self.state.acl_enabled = false;
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

fn managed_replay_route(mode: ManagedAttachMode) -> ManagedReplayRoute {
    let projection_mode = match mode {
        ManagedAttachMode::StandaloneRestoreAfterTcAttach => {
            GroupProjectionMode::StandaloneCompatibility
        }
        ManagedAttachMode::NeutronResyncRequired { acl_managed: true } => {
            GroupProjectionMode::Managed
        }
        ManagedAttachMode::NeutronResyncRequired { acl_managed: false } => {
            GroupProjectionMode::StandaloneCompatibility
        }
    };
    ManagedReplayRoute::new(projection_mode, mode.legacy_acl_migration_authority())
}

async fn persist_fresh_managed_registration_gate_state<Persist, PersistFuture>(
    state: &mut FirewallState,
    mode: ManagedAttachMode,
    fresh_registration: bool,
    persist: Persist,
) -> Result<(), String>
where
    Persist: FnOnce(FirewallState) -> PersistFuture,
    PersistFuture: Future<Output = Result<(), String>>,
{
    if !fresh_registration || matches!(mode, ManagedAttachMode::StandaloneRestoreAfterTcAttach) {
        return Ok(());
    }

    // A freshly created Neutron-owned runtime is always published quiesced.
    // Persist that exact gate state before replay so the first restart cannot
    // compare live false/false against stale durable true flags.
    state.conntrack_enabled = false;
    state.acl_enabled = false;
    persist(state.clone()).await
}

fn preexisting_projection_verification(drift: ProjectionDrift) -> Result<bool, String> {
    match drift {
        ProjectionDrift::Clean => Ok(true),
        ProjectionDrift::RepairRequired(_) => Ok(false),
        ProjectionDrift::Fatal(error) => Err(error),
    }
}

fn classify_preexisting_runtime_gate(
    projection_mode: GroupProjectionMode,
    actual_conntrack: u8,
    actual_acl: u8,
    expected_conntrack: u8,
    expected_acl: u8,
    tc_runtime_complete: bool,
) -> Result<RuntimeGateDisposition, String> {
    if !tc_runtime_complete && actual_conntrack == 0 && actual_acl == 0 {
        return Ok(RuntimeGateDisposition::ManagedQuiesced);
    }
    classify_runtime_gate_state(
        projection_mode,
        actual_conntrack,
        actual_acl,
        expected_conntrack,
        expected_acl,
    )
}

fn preexisting_projection_validation_state<'a>(
    state: &'a FirewallState,
    projection_mode: GroupProjectionMode,
    tc_runtime_complete: bool,
    gate_disposition: RuntimeGateDisposition,
) -> std::borrow::Cow<'a, FirewallState> {
    if projection_mode == GroupProjectionMode::StandaloneCompatibility
        && !tc_runtime_complete
        && gate_disposition == RuntimeGateDisposition::ManagedQuiesced
    {
        let mut validation_state = state.clone();
        validation_state.conntrack_enabled = false;
        validation_state.acl_enabled = false;
        return std::borrow::Cow::Owned(validation_state);
    }
    std::borrow::Cow::Borrowed(state)
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
            if current_mode == ManagedAclPublicationMode::ManagedAcl =>
        {
            ManagedAclPromotionAction::Demote {
                next_mode: ManagedAclPublicationMode::NeutronAttachOwnedStandaloneAcl,
                next_health: ManagedProjectionHealth::Unverified,
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

fn quiesce_managed_acl_demotion_before_build<Quiesce>(
    current_mode: ManagedAclPublicationMode,
    projection_health: &mut ManagedProjectionHealth,
    quiesce_acl_ct: Quiesce,
) -> Result<(), String>
where
    Quiesce: FnOnce() -> Result<(), String>,
{
    if current_mode != ManagedAclPublicationMode::ManagedAcl {
        return Err("managed ACL demotion requires current ManagedAcl mode".to_string());
    }
    let quiesce_result = quiesce_acl_ct();
    // Even an uncertain kernel-gate write invalidates skip eligibility. This
    // assignment intentionally happens for both success and failure.
    *projection_health = ManagedProjectionHealth::Unverified;
    quiesce_result
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
    actual_gate: Option<(bool, bool)>,
    runtime_identity_missing: bool,
}

impl PreexistingRuntimeValidation {
    fn fatal(error: String) -> Self {
        Self {
            projection_drift: ProjectionDrift::Fatal(error),
            gate_disposition: None,
            actual_gate: None,
            runtime_identity_missing: false,
        }
    }

    fn missing_identity(error: String) -> Self {
        Self {
            projection_drift: ProjectionDrift::Fatal(error),
            gate_disposition: None,
            actual_gate: None,
            runtime_identity_missing: true,
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

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
enum ManagedAclGatePublicationStep {
    AdvanceFragmentEpoch,
    PublishGate,
    Persist,
    VerifyReadiness,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
enum FragmentEpochGateTransition {
    SemanticChange,
    EqualState,
    FreshInitialization,
    EpochAlreadyAdvanced,
}

impl FragmentEpochGateTransition {
    fn requires_epoch(self) -> bool {
        self == Self::SemanticChange
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
enum FragmentEpochPublicationFailurePhase {
    Readiness,
    AdvanceEpoch,
    Publish,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct FragmentEpochPublicationFailure {
    phase: FragmentEpochPublicationFailurePhase,
    epoch_advanced: bool,
    error: String,
}

impl FragmentEpochPublicationFailure {
    fn new(
        phase: FragmentEpochPublicationFailurePhase,
        epoch_advanced: bool,
        error: String,
    ) -> Self {
        Self {
            phase,
            epoch_advanced,
            error,
        }
    }

    fn phase(&self) -> FragmentEpochPublicationFailurePhase {
        self.phase
    }

    pub(crate) fn epoch_advanced(&self) -> bool {
        self.epoch_advanced
    }
}

impl std::fmt::Display for FragmentEpochPublicationFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.error)
    }
}

fn execute_fragment_epoch_gate_transition(
    transition: FragmentEpochGateTransition,
    advance_epoch: &mut dyn FnMut() -> Result<(), String>,
    write_gate: &mut dyn FnMut() -> Result<(), String>,
) -> Result<(), FragmentEpochPublicationFailure> {
    let mut epoch_advanced = transition == FragmentEpochGateTransition::EpochAlreadyAdvanced;
    if transition.requires_epoch() {
        advance_epoch().map_err(|error| {
            FragmentEpochPublicationFailure::new(
                FragmentEpochPublicationFailurePhase::AdvanceEpoch,
                false,
                error,
            )
        })?;
        epoch_advanced = true;
    }
    write_gate().map_err(|error| {
        FragmentEpochPublicationFailure::new(
            FragmentEpochPublicationFailurePhase::Publish,
            epoch_advanced,
            error,
        )
    })
}

fn execute_guarded_fragment_epoch_gate_transition(
    enforcement_required: bool,
    transition: FragmentEpochGateTransition,
    require_readiness: &mut dyn FnMut() -> Result<(), String>,
    advance_epoch: &mut dyn FnMut() -> Result<(), String>,
    write_gate: &mut dyn FnMut() -> Result<(), String>,
) -> Result<(), FragmentEpochPublicationFailure> {
    if enforcement_required {
        require_readiness().map_err(|error| {
            FragmentEpochPublicationFailure::new(
                FragmentEpochPublicationFailurePhase::Readiness,
                false,
                error,
            )
        })?;
    }
    execute_fragment_epoch_gate_transition(transition, advance_epoch, write_gate)
}

fn execute_local_config_persistence_gate_rollback(
    restore_conntrack: bool,
    restore_acl: bool,
    read_live_gate: &mut dyn FnMut() -> Result<(bool, bool), String>,
    require_readiness: &mut dyn FnMut() -> Result<(), String>,
    advance_epoch: &mut dyn FnMut() -> Result<(), String>,
    write_config: &mut dyn FnMut(bool, bool) -> Result<(), String>,
) -> Result<(), String> {
    if !neutron_acl_gate_requires_tc(restore_conntrack, restore_acl) {
        return write_config(false, false);
    }

    let rollback_result = read_live_gate().and_then(|_| {
        execute_guarded_fragment_epoch_gate_transition(
            true,
            FragmentEpochGateTransition::SemanticChange,
            require_readiness,
            advance_epoch,
            &mut || write_config(restore_conntrack, restore_acl),
        )
        .map_err(|error| error.to_string())
    });

    if let Err(rollback_error) = rollback_result {
        let mut errors = vec![rollback_error];
        if let Err(quiesce_error) = write_config(false, false) {
            errors.push(format!(
                "kernel config fail-closed compensation failed: {}",
                quiesce_error
            ));
        }
        return Err(errors.join("; "));
    }

    Ok(())
}

fn execute_fragment_epoch_bank_publication(
    advance_epoch: &mut dyn FnMut() -> Result<(), String>,
    switch_bank: &mut dyn FnMut() -> Result<(), String>,
) -> Result<(), FragmentEpochPublicationFailure> {
    execute_fragment_epoch_gate_transition(
        FragmentEpochGateTransition::SemanticChange,
        advance_epoch,
        switch_bank,
    )
}

fn advance_fragment_epoch_action(pin_path: &str, tap_id: u32) -> Result<(), String> {
    aria_core::ebpf_ops::advance_fragment_epoch_strict(pin_path, tap_id).map(|_| ())
}

fn require_fragment_runtime_ready(
    settings: FragmentTrackingSettings,
    pin_path: &str,
    tap_id: u32,
    conntrack_enabled: bool,
    acl_enabled: bool,
) -> Result<(), String> {
    settings.require_acl_ct_ready(conntrack_enabled, acl_enabled)?;
    if !neutron_acl_gate_requires_tc(conntrack_enabled, acl_enabled) {
        return Ok(());
    }
    let runtime_mode = if tap_id == aria_core::common::TAP_ID_UNASSIGNED {
        aria_core::common::FRAGMENT_RUNTIME_MODE_STANDALONE
    } else {
        aria_core::common::FRAGMENT_RUNTIME_MODE_MANAGED
    };
    aria_core::ebpf_ops::validate_fragment_runtime_configured_strict(
        pin_path,
        &settings.runtime_config(runtime_mode)?,
        settings.max_entries,
    )
}

fn execute_pinned_acl_gate_transition(
    pin_path: &str,
    tap_id: u32,
    transition: FragmentEpochGateTransition,
    conntrack_enabled: bool,
    acl_enabled: bool,
) -> Result<(), FragmentEpochPublicationFailure> {
    execute_fragment_epoch_gate_transition(
        transition,
        &mut || advance_fragment_epoch_action(pin_path, tap_id),
        &mut || {
            aria_core::ebpf_ops::update_acl_runtime_gate(
                TapMapRuntime::new(pin_path, tap_id),
                conntrack_enabled,
                acl_enabled,
                aria_core::common::ACL_INGRESS_HOOK_TC,
            )
        },
    )
}

fn acl_ct_config_gate_transition(
    current_conntrack: bool,
    current_acl: bool,
    requested_conntrack: Option<bool>,
    requested_acl: Option<bool>,
) -> FragmentEpochGateTransition {
    let next_conntrack = requested_conntrack.unwrap_or(current_conntrack);
    let next_acl = requested_acl.unwrap_or(current_acl);
    if current_conntrack == next_conntrack && current_acl == next_acl {
        FragmentEpochGateTransition::EqualState
    } else {
        FragmentEpochGateTransition::SemanticChange
    }
}

fn read_live_acl_ct_gate_transition(
    requested_conntrack: Option<bool>,
    requested_acl: Option<bool>,
    read_gate: &mut dyn FnMut() -> Result<(bool, bool), String>,
) -> Result<FragmentEpochGateTransition, String> {
    let (actual_conntrack, actual_acl) = read_gate()?;
    Ok(acl_ct_config_gate_transition(
        actual_conntrack,
        actual_acl,
        requested_conntrack,
        requested_acl,
    ))
}

fn read_pinned_acl_ct_gate_transition(
    runtime: TapMapRuntime<'_>,
    requested_conntrack: Option<bool>,
    requested_acl: Option<bool>,
) -> Result<FragmentEpochGateTransition, String> {
    read_live_acl_ct_gate_transition(requested_conntrack, requested_acl, &mut || {
        aria_core::ebpf_ops::read_runtime_config(runtime).map(|actual| {
            (
                actual.conntrack_enabled != 0,
                actual.acl_enabled != 0,
            )
        })
    })
}

fn managed_registration_cleanup_gate_transition(
    preserve_existing_runtime: bool,
    activation_error: Option<&FragmentEpochPublicationFailure>,
) -> FragmentEpochGateTransition {
    if activation_error.is_some_and(FragmentEpochPublicationFailure::epoch_advanced) {
        FragmentEpochGateTransition::EpochAlreadyAdvanced
    } else if preserve_existing_runtime {
        FragmentEpochGateTransition::SemanticChange
    } else {
        FragmentEpochGateTransition::FreshInitialization
    }
}

fn managed_acl_gate_publication_steps_from_live(
    actual_conntrack: bool,
    actual_acl: bool,
    durable_conntrack: bool,
    durable_acl: bool,
    requested_conntrack: bool,
    requested_acl: bool,
    recovery_publication: bool,
) -> Vec<ManagedAclGatePublicationStep> {
    let kernel_changed = actual_conntrack != requested_conntrack || actual_acl != requested_acl;
    let durable_changed =
        durable_conntrack != requested_conntrack || durable_acl != requested_acl;
    if !kernel_changed && !durable_changed && !recovery_publication {
        return Vec::new();
    }

    let mut steps = vec![ManagedAclGatePublicationStep::AdvanceFragmentEpoch];
    if kernel_changed {
        steps.push(ManagedAclGatePublicationStep::PublishGate);
    }
    if durable_changed {
        steps.push(ManagedAclGatePublicationStep::Persist);
    }
    if recovery_publication {
        steps.push(ManagedAclGatePublicationStep::VerifyReadiness);
    }
    steps
}

fn verify_acl_gate_before_readiness(
    expected_conntrack: bool,
    expected_acl: bool,
    read_gate: &mut dyn FnMut() -> Result<(bool, bool), String>,
) -> Result<(), String> {
    let (actual_conntrack, actual_acl) = read_gate()?;
    if actual_conntrack == expected_conntrack && actual_acl == expected_acl {
        Ok(())
    } else {
        Err(format!(
            "managed ACL runtime gate drifted before readiness: actual conntrack={} acl={}, expected conntrack={} acl={}",
            actual_conntrack, actual_acl, expected_conntrack, expected_acl
        ))
    }
}

fn managed_projection_health_before_runtime_gate_write(
    publication_mode: ManagedAclPublicationMode,
    current_health: ManagedProjectionHealth,
) -> ManagedProjectionHealth {
    if publication_mode == ManagedAclPublicationMode::ManagedAcl {
        ManagedProjectionHealth::Unverified
    } else {
        current_health
    }
}

fn validate_managed_projection_runtime_gate(
    state: &FirewallState,
    actual: &aria_core::common::FirewallConfig,
) -> Result<(), String> {
    let expected_conntrack = state.conntrack_enabled as u8;
    let expected_acl = state.acl_enabled as u8;
    if actual.conntrack_enabled == expected_conntrack && actual.acl_enabled == expected_acl {
        Ok(())
    } else {
        Err(format!(
            "managed ACL runtime gate mismatch: actual conntrack={} acl={}, expected conntrack={} acl={}",
            actual.conntrack_enabled, actual.acl_enabled, expected_conntrack, expected_acl
        ))
    }
}

fn require_clean_managed_projection_inventory(drift: ProjectionDrift) -> Result<(), String> {
    match drift {
        ProjectionDrift::Clean => Ok(()),
        ProjectionDrift::RepairRequired(_) => {
            Err("managed ACL runtime inventory requires projection repair".to_string())
        }
        ProjectionDrift::Fatal(error) => Err(format!(
            "managed ACL runtime inventory is invalid: {}",
            error
        )),
    }
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

#[cfg(test)]
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

#[derive(Clone, Debug, Eq, PartialEq)]
struct ManagedMaintenanceAuthorityFacts {
    configured_pin_path: PathBuf,
    configured_mode: TraceMapMode,
    firewall_config_map_id: u32,
    ingress_program: ManagedTcProgramIdentity,
    egress_program: ManagedTcProgramIdentity,
    live_owner_count: usize,
    complete_mode_inventory: bool,
}

trait ManagedMaintenanceAuthoritySource {
    fn configured_pin_path(&self) -> PathBuf;
    fn configured_mode(&self) -> TraceMapMode;
    fn current_firewall_config_map_id(&self) -> Result<u32, String>;
    fn live_runtime_identity(&self) -> Result<ManagedMaintenanceRuntimeIdentity, String>;
}

fn acquire_managed_maintenance_authority_facts<Source>(
    source: &Source,
) -> Result<ManagedMaintenanceAuthorityFacts, String>
where
    Source: ManagedMaintenanceAuthoritySource,
{
    let configured_pin_path = source.configured_pin_path();
    let configured_mode = source.configured_mode();
    let runtime = source.live_runtime_identity()?;
    if configured_mode != runtime.trace_map_mode {
        return Err("persisted runtime mode does not match configured runtime mode".to_string());
    }
    if !runtime.complete_mode_inventory {
        return Err("mode-aware inventory is incomplete".to_string());
    }
    if runtime.live_owner_count == 0 {
        return Err("live Aria runtime identity is absent".to_string());
    }
    let firewall_config_map_id = source.current_firewall_config_map_id()?;
    let ingress_uses_map = runtime
        .ingress_program
        .map_ids
        .contains(&firewall_config_map_id);
    let egress_uses_map = runtime
        .egress_program
        .map_ids
        .contains(&firewall_config_map_id);
    if !ingress_uses_map && !egress_uses_map {
        return Err(
            "FIREWALL_CONFIG map identity is absent from both live TC programs".to_string(),
        );
    }
    if !ingress_uses_map {
        return Err("FIREWALL_CONFIG map identity is absent from live tc_ingress".to_string());
    }
    if !egress_uses_map {
        return Err("FIREWALL_CONFIG map identity is absent from live tc_egress".to_string());
    }
    Ok(ManagedMaintenanceAuthorityFacts {
        configured_pin_path,
        configured_mode,
        firewall_config_map_id,
        ingress_program: runtime.ingress_program,
        egress_program: runtime.egress_program,
        live_owner_count: runtime.live_owner_count,
        complete_mode_inventory: runtime.complete_mode_inventory,
    })
}

pub(crate) struct ManagedFirewallConfigAuthority {
    facts: ManagedMaintenanceAuthorityFacts,
    authority_seal: std::sync::Weak<()>,
}

struct ManagedFirewallConfigStore {
    pin_path: PathBuf,
    trace_mode: TraceMapMode,
    expected_map_id: u32,
    map: Option<BpfHashMap<MapData, u32, FirewallConfig>>,
}

impl ManagedFirewallConfigStore {
    fn new(pin_path: PathBuf, trace_mode: TraceMapMode, expected_map_id: u32) -> Self {
        Self {
            pin_path,
            trace_mode,
            expected_map_id,
            map: None,
        }
    }

    fn current_firewall_config_map_id(&self) -> Result<u32, String> {
        aria_core::ebpf_ops::validate_managed_pin_path_security(&self.pin_path, self.trace_mode)
    }
}

impl aria_core::ebpf_ops::FirewallConfigStore for ManagedFirewallConfigStore {
    fn revalidate_current_pin(&mut self) -> Result<(), String> {
        let current_id = self.current_firewall_config_map_id()?;
        if current_id != self.expected_map_id {
            return Err(format!(
                "FIREWALL_CONFIG map identity changed: expected {}, current {}",
                self.expected_map_id, current_id
            ));
        }
        let map_data = MapData::from_pin(self.pin_path.join("FIREWALL_CONFIG"))
            .map_err(|error| format!("reopen canonical current FIREWALL_CONFIG: {:?}", error))?;
        let opened_id = map_data
            .info()
            .map_err(|error| format!("inspect reopened current FIREWALL_CONFIG: {:?}", error))?
            .id();
        if opened_id != self.expected_map_id {
            return Err(format!(
                "FIREWALL_CONFIG map identity changed while reopening: expected {}, current {}",
                self.expected_map_id, opened_id
            ));
        }
        self.map = Some(
            BpfHashMap::<_, u32, FirewallConfig>::try_from(Map::HashMap(map_data))
                .map_err(|error| format!("convert current FIREWALL_CONFIG: {:?}", error))?,
        );
        Ok(())
    }

    fn read_key_zero(&mut self) -> Result<Option<FirewallConfig>, String> {
        let map = self
            .map
            .as_mut()
            .ok_or_else(|| "current FIREWALL_CONFIG was not revalidated".to_string())?;
        match map.get(&0u32, 0) {
            Ok(config) => Ok(Some(config)),
            Err(aya::maps::MapError::KeyNotFound) => Ok(None),
            Err(error) => Err(format!("read FIREWALL_CONFIG key 0: {}", error)),
        }
    }

    fn write_key_zero(&mut self, config: FirewallConfig) -> Result<(), String> {
        self.map
            .as_mut()
            .ok_or_else(|| "current FIREWALL_CONFIG was not revalidated".to_string())?
            .insert(&0u32, &config, 0)
            .map_err(|error| format!("write FIREWALL_CONFIG key 0: {:?}", error))
    }

    fn validate_current_pin_after_readback(&mut self) -> Result<(), String> {
        let current_id = self.current_firewall_config_map_id()?;
        if current_id != self.expected_map_id {
            return Err(format!(
                "FIREWALL_CONFIG current pin replaced during update: expected {}, current {}",
                self.expected_map_id, current_id
            ));
        }
        Ok(())
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
    fragment_tracking: FragmentTrackingSettings,
    chains: RwLock<Vec<ServiceChain>>,
    maintenance_authority_seal: Arc<()>,
}

struct ControlPlaneManagedMaintenanceAuthoritySource<'a> {
    control_plane: &'a ControlPlane,
}

impl ControlPlaneManagedMaintenanceAuthoritySource<'_> {
    fn recovery_runtime(&self) -> FirewallInstance {
        FirewallInstance::new(
            "__managed_maintenance_recovery__",
            PathBuf::from(self.control_plane.managed_pin_path()),
            PathBuf::from(&self.control_plane.base_state_path)
                .join("__managed_maintenance_recovery__"),
            true,
            self.control_plane.trace_map_mode(),
        )
    }
}

impl ManagedMaintenanceAuthoritySource for ControlPlaneManagedMaintenanceAuthoritySource<'_> {
    fn configured_pin_path(&self) -> PathBuf {
        PathBuf::from(self.control_plane.managed_pin_path())
    }

    fn configured_mode(&self) -> TraceMapMode {
        self.control_plane.trace_map_mode()
    }

    fn current_firewall_config_map_id(&self) -> Result<u32, String> {
        let runtime = self.recovery_runtime();
        aria_core::ebpf_ops::validate_managed_pin_path_security(
            &runtime.pin_path,
            self.configured_mode(),
        )
    }

    fn live_runtime_identity(&self) -> Result<ManagedMaintenanceRuntimeIdentity, String> {
        self.recovery_runtime()
            .managed_maintenance_runtime_identity(&self.control_plane.ebpf_path)
    }
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
    pub ip_family: u8,
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
    ports_normalized: String,
    error: String,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct PortSetCleanupReport {
    cleaned_bitmap_indices: Vec<u32>,
    failures: Vec<PortSetCleanupFailure>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct StandaloneCleanupPending {
    pub bitmap_idx: u32,
    pub ports_normalized: String,
    pub error: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct StandaloneCleanupOutcome {
    pub committed: bool,
    pub cleanup_pending: Vec<StandaloneCleanupPending>,
    pub item_errors: Vec<String>,
}

fn standalone_cleanup_outcome(cleanup: &PortSetCleanupReport) -> StandaloneCleanupOutcome {
    StandaloneCleanupOutcome {
        committed: true,
        cleanup_pending: cleanup
            .failures
            .iter()
            .map(|failure| StandaloneCleanupPending {
                bitmap_idx: failure.bitmap_idx,
                ports_normalized: failure.ports_normalized.clone(),
                error: failure.error.clone(),
            })
            .collect(),
        item_errors: Vec::new(),
    }
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
                ports_normalized: port_set.ports_normalized.clone(),
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

fn pending_bitmap_cleanup_port_sets(state: &FirewallState) -> Vec<TransactionCreatedPortSet> {
    state
        .pending_bitmap_cleanup_targets()
        .into_iter()
        .map(|(bitmap_idx, ports_normalized)| TransactionCreatedPortSet {
            bitmap_idx,
            ports_normalized,
        })
        .collect()
}

fn quarantine_port_set_indices(
    state: &mut FirewallState,
    port_sets: &[TransactionCreatedPortSet],
) -> Result<(), String> {
    let mut errors = Vec::new();
    for port_set in port_sets {
        if let Err(error) = state.quarantine_bitmap_cleanup(
            port_set.bitmap_idx,
            port_set.ports_normalized.clone(),
        ) {
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
        state.quarantine_bitmap_cleanup(bitmap_idx, ports_normalized.clone())?;
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
            .quarantine_bitmap_cleanup(
                failure.bitmap_idx,
                failure.ports_normalized.clone(),
            )
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
    ip_family: u8,
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

#[derive(Clone, Debug, Eq, PartialEq)]
enum ManagedAclPublicationReceipt {
    General(SharedNetworkMutation),
    ActiveBank {
        previous_bank: u8,
        published_bank: u8,
    },
}

#[derive(Clone, Debug)]
struct ManagedOwnedAclRollbackContext {
    receipts: Vec<ManagedAclPublicationReceipt>,
    old_state: FirewallState,
    created_port_sets: Vec<TransactionCreatedPortSet>,
}

#[derive(Clone, Debug)]
struct ManagedAclDemotionTarget {
    final_state: FirewallState,
    standalone_shadow_entries: RuntimeGroupMapEntries,
    released_port_sets: BTreeMap<u32, String>,
    publication_required: bool,
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
    recovery_required: bool,
}

impl ManagedLocalProjectionFailure {
    #[cfg(test)]
    fn contains(&self, pattern: &str) -> bool {
        self.message.contains(pattern)
    }

    fn recovery_required(&self) -> bool {
        self.recovery_required
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

#[derive(Debug)]
struct ManagedLocalApplyFailure {
    message: String,
    recovery_required: bool,
}

impl ManagedLocalApplyFailure {
    fn clean(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            recovery_required: false,
        }
    }

    fn recovery_required(
        apply: impl Into<String>,
        compensation: impl Into<String>,
    ) -> Self {
        Self {
            message: format!(
                "{}; current-operation compensation failed: {}",
                apply.into(),
                compensation.into()
            ),
            recovery_required: true,
        }
    }

    #[cfg(test)]
    fn contains(&self, pattern: &str) -> bool {
        self.message.contains(pattern)
    }
}

impl From<String> for ManagedLocalApplyFailure {
    fn from(message: String) -> Self {
        Self::clean(message)
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
    AdvanceFragmentEpoch,
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
    if phase == ManagedAclPublicationFailurePhase::SwitchBank {
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
    AdvanceFragmentEpoch,
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
    steps.push(ManagedAclPublicationStep::Persist);
    steps.push(ManagedAclPublicationStep::AdvanceFragmentEpoch);
    steps.push(ManagedAclPublicationStep::SwitchBank);
    steps
}

fn execute_acl_family_staging<F>(mut stage_family: F) -> Result<(), ControlPlaneError>
where
    F: FnMut(u8) -> Result<(), ControlPlaneError>,
{
    stage_family(IP_FAMILY_V4)?;
    stage_family(IP_FAMILY_V6)?;
    Ok(())
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

fn local_projection_recovery_admission(
    state: &FirewallState,
    domain: LocalWriteDomain,
) -> Result<(), ControlPlaneError> {
    if state.local_projection_recovery_required(domain.as_str()) {
        return Err(ControlPlaneError::InstanceNotReady(format!(
            "local projection recovery required for {}",
            domain.as_str()
        )));
    }
    Ok(())
}

fn local_projection_maintenance_reason(
    state: &FirewallState,
    cleanup_pending_count: usize,
) -> Option<String> {
    state
        .local_projection_recoveries
        .keys()
        .next()
        .map(|domain| format!("local_projection_recovery_required:{}", domain))
        .or_else(|| {
            (cleanup_pending_count > 0).then(|| "bitmap_cleanup_pending".to_string())
        })
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
    aria_core::ebpf_ops::validate_general_group_overlap_transition(
        old_state,
        final_state,
        aria_core::ebpf_ops::GeneralGroupScope::Managed,
    )
    .map_err(ControlPlaneError::GroupConflict)?;
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

fn build_managed_acl_demotion_target(
    old_state: &FirewallState,
    owner_prefix: &str,
) -> Result<ManagedAclDemotionTarget, String> {
    let mut final_state = old_state.clone();
    let existing_rules = final_state.rules.clone();
    let mut released_port_sets = BTreeMap::new();

    // Neutron is the exclusive ACL policy owner in ManagedAcl mode. Demotion
    // removes the complete policy domain, including legacy rules whose group
    // names do not carry the current port prefix.
    for rule in existing_rules {
        let remove_result = final_state.apply_remove_rule(
            rule.src_group_id,
            rule.dst_group_id,
            rule.proto,
            rule.direction,
            rule.ip_family,
        )?;
        quarantine_owned_acl_released_port_set(
            &mut final_state,
            &mut released_port_sets,
            remove_result
                .bitmap_idx
                .zip(remove_result.port_set_released),
        )?;
    }

    final_state
        .groups
        .retain(|name, _| !name.starts_with(owner_prefix));
    let _removed_retained_group_ids =
        reconcile_retained_owned_groups(old_state, &mut final_state, owner_prefix)
            .map_err(|error| error.to_string())?;
    final_state.conntrack_enabled = false;
    final_state.acl_enabled = false;

    let standalone_shadow_entries = aria_core::ebpf_ops::build_runtime_group_map_entries(
        &final_state,
        GroupProjectionMode::StandaloneCompatibility,
    )?;
    validate_standalone_demotion_shadow_entries(&standalone_shadow_entries)?;

    Ok(ManagedAclDemotionTarget {
        final_state,
        standalone_shadow_entries,
        released_port_sets,
        // Even an empty managed policy must rotate through a clean shadow bank
        // before ownership can enter attach-owned standalone compatibility.
        publication_required: true,
    })
}

fn validate_standalone_demotion_shadow_entries(
    entries: &RuntimeGroupMapEntries,
) -> Result<(), String> {
    for (direction, network_entries) in [
        ("general_src", entries.general_src.as_slice()),
        ("general_dst", entries.general_dst.as_slice()),
        ("acl_src", entries.acl_src.as_slice()),
        ("acl_dst", entries.acl_dst.as_slice()),
    ] {
        let mut owners = BTreeMap::<aria_core::ebpf_ops::CanonicalNetwork, BTreeSet<u32>>::new();
        for entry in network_entries {
            let network =
                aria_core::ebpf_ops::CanonicalNetwork::from_ip(entry.address, entry.prefix_len)?;
            owners.entry(network).or_default().insert(entry.group_id);
        }
        if let Some((network, group_ids)) = owners.iter().find(|(_, group_ids)| group_ids.len() > 1)
        {
            return Err(format!(
                "standalone demotion {} canonical selector {} has conflicting group IDs {:?}",
                direction,
                network,
                group_ids.iter().copied().collect::<Vec<_>>()
            ));
        }
    }
    Ok(())
}

fn managed_acl_demotion_owner_prefix(authority_port_id: Option<&str>) -> String {
    authority_port_id
        .map(str::trim)
        .filter(|port_id| !port_id.is_empty())
        .map(|port_id| format!("neutron:{}:", port_id))
        // A failed first apply may leave a ManagedAcl instance after cleanup
        // while authority has not committed yet. The neutron: namespace is
        // reserved from local mutation once managed ownership exists, so the
        // fallback can recover all Neutron-owned groups without touching local
        // non-Neutron groups. Dual-use groups remain retained by the target.
        .unwrap_or_else(|| "neutron:".to_string())
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

fn qos_runtime_equal(left: &QosRuleInfo, right: &QosRuleInfo) -> bool {
    left.group_id == right.group_id
        && left.direction == right.direction
        && left.rate_bps == right.rate_bps
        && left.burst_bytes == right.burst_bytes
        && left.priority == right.priority
        && left.mode == right.mode
}

fn mirror_runtime_equal(left: &MirrorRuleInfo, right: &MirrorRuleInfo) -> bool {
    left.is_global == right.is_global
        && left.src_group_id == right.src_group_id
        && left.dst_group_id == right.dst_group_id
        && left.proto == right.proto
        && left.direction == right.direction
        && left.target_ifindex == right.target_ifindex
}

fn mirror_runtime_key(rule: &MirrorRuleInfo) -> (bool, u32, u32, u8, u8) {
    (
        rule.is_global,
        rule.src_group_id,
        rule.dst_group_id,
        rule.proto,
        rule.direction,
    )
}

fn plan_local_projection_runtime_repair(
    desired: &FirewallState,
    actual_qos: &[QosRuleInfo],
    actual_mirror: &[MirrorRuleInfo],
    actual_global_mirror: &[MirrorRuleInfo],
) -> Result<Vec<ManagedLocalDomainOperation>, ControlPlaneError> {
    let actual_qos = actual_qos
        .iter()
        .map(|rule| ((rule.group_id, rule.direction), rule))
        .collect::<BTreeMap<_, _>>();
    let mut desired_qos = desired.qos_rules.iter().collect::<Vec<_>>();
    desired_qos.sort_by_key(|rule| (rule.group_id, rule.direction));

    let mut desired_mirror = desired
        .mirror_rules
        .iter()
        .map(|rule| {
            let mut resolved = rule.clone();
            resolved.target_ifindex = resolve_managed_mirror_target_ifindex(&rule.target_iface)?;
            Ok(resolved)
        })
        .collect::<Result<Vec<_>, ControlPlaneError>>()?;
    desired_mirror.sort_by_key(mirror_runtime_key);
    let actual_mirror = actual_mirror
        .iter()
        .chain(actual_global_mirror.iter())
        .map(|rule| (mirror_runtime_key(rule), rule))
        .collect::<BTreeMap<_, _>>();

    let mut operations = Vec::new();
    for rule in desired_qos {
        let key = (rule.group_id, rule.direction);
        if !actual_qos
            .get(&key)
            .is_some_and(|actual| qos_runtime_equal(rule, actual))
        {
            operations.push(ManagedLocalDomainOperation::QosUpsert(rule.clone()));
        }
    }
    for rule in &desired_mirror {
        let key = mirror_runtime_key(rule);
        if !actual_mirror
            .get(&key)
            .is_some_and(|actual| mirror_runtime_equal(rule, actual))
        {
            operations.push(ManagedLocalDomainOperation::MirrorUpsert(rule.clone()));
        }
    }

    let desired_qos_keys = desired
        .qos_rules
        .iter()
        .map(|rule| (rule.group_id, rule.direction))
        .collect::<BTreeSet<_>>();
    for (group_id, direction) in actual_qos.keys() {
        if !desired_qos_keys.contains(&(*group_id, *direction)) {
            operations.push(ManagedLocalDomainOperation::QosDelete {
                group_id: *group_id,
                direction: *direction,
            });
        }
    }

    let desired_mirror_keys = desired_mirror
        .iter()
        .map(mirror_runtime_key)
        .collect::<BTreeSet<_>>();
    for (is_global, src_group_id, dst_group_id, proto, direction) in actual_mirror.keys() {
        if !desired_mirror_keys.contains(&(
            *is_global,
            *src_group_id,
            *dst_group_id,
            *proto,
            *direction,
        )) {
            operations.push(ManagedLocalDomainOperation::MirrorDelete {
                src_group_id: *src_group_id,
                dst_group_id: *dst_group_id,
                proto: *proto,
                direction: *direction,
                is_global: *is_global,
            });
        }
    }
    Ok(operations)
}

fn capture_local_projection_runtime(
    runtime: TapMapRuntime<'_>,
) -> Result<(Vec<QosRuleInfo>, Vec<MirrorRuleInfo>, Vec<MirrorRuleInfo>), String> {
    let qos = aria_core::qos_ops::list_qos_rules(runtime)?
        .into_iter()
        .map(|(key, config)| QosRuleInfo {
            group_name: String::new(),
            group_id: key.group_id,
            direction: key.direction,
            rate_bps: config.rate_bps,
            burst_bytes: config.burst_bytes,
            priority: config.priority,
            mode: config.mode,
        })
        .collect();
    let mirror = aria_core::mirror_ops::list_mirror_rules(runtime)?
        .into_iter()
        .map(|(key, config)| MirrorRuleInfo {
            src_group_name: String::new(),
            src_group_id: key.src_id,
            dst_group_name: String::new(),
            dst_group_id: key.dst_id,
            proto: key.proto,
            direction: key.direction,
            target_iface: String::new(),
            target_ifindex: config.target_ifindex,
            is_global: false,
        })
        .collect();
    let global_mirror = aria_core::mirror_ops::list_global_mirrors(runtime)?
        .into_iter()
        .map(|(key, config)| MirrorRuleInfo {
            src_group_name: "any".to_string(),
            src_group_id: 0,
            dst_group_name: "any".to_string(),
            dst_group_id: 0,
            proto: 0,
            direction: key.direction,
            target_iface: String::new(),
            target_ifindex: config.target_ifindex,
            is_global: true,
        })
        .collect();
    Ok((qos, mirror, global_mirror))
}

async fn clear_local_projection_recovery_records(
    state: &mut FirewallState,
    wal: &WalClient,
) -> Result<(), String> {
    let mut recovered = state.clone();
    if recovered.local_projection_recovery_required(LocalWriteDomain::Mirror.as_str()) {
        for rule in &mut recovered.mirror_rules {
            rule.target_ifindex = aria_core::mirror_ops::resolve_ifindex(&rule.target_iface)?;
        }
    }
    recovered.clear_local_projection_recovery(LocalWriteDomain::Qos.as_str());
    recovered.clear_local_projection_recovery(LocalWriteDomain::Mirror.as_str());
    let snapshot = serde_json::to_string_pretty(&recovered)
        .map_err(|error| format!("serialize recovered local projection state: {}", error))?;
    wal.compact(snapshot)
        .await
        .map_err(|error| format!("persist recovered local projection state: {}", error))?;
    *state = recovered;
    Ok(())
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

fn domain_apply_failure(
    apply_error: String,
    compensation_error: Option<String>,
) -> ManagedLocalApplyFailure {
    match compensation_error {
        Some(compensation_error) => {
            ManagedLocalApplyFailure::recovery_required(apply_error, compensation_error)
        }
        None => ManagedLocalApplyFailure::clean(apply_error),
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
) -> Result<R, ManagedLocalApplyFailure>
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
) -> Result<ManagedLocalDomainReceipt, ManagedLocalApplyFailure> {
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
) -> ManagedLocalFuture<Result<ManagedLocalProjectionReceipt, ManagedLocalApplyFailure>> {
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
    error: ManagedLocalApplyFailure,
    compensation_errors: Vec<String>,
    restore_error: Option<String>,
) -> ManagedLocalProjectionFailure {
    let recovery_required = error.recovery_required
        || !compensation_errors.is_empty()
        || restore_error.is_some();
    let mut errors = vec![error.message];
    errors.extend(compensation_errors);
    if let Some(restore_error) = restore_error {
        errors.push(restore_error);
    }
    ManagedLocalProjectionFailure {
        kind,
        message: errors.join("; "),
        recovery_required,
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
    ApplyFuture: Future<Output = Result<R, ManagedLocalApplyFailure>>,
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
                let failure = transaction_failure(
                    ManagedLocalProjectionFailureKind::Kernel,
                    error,
                    compensation_errors,
                    None,
                );
                set_health(if failure.recovery_required() {
                    ManagedProjectionHealth::RepairRequired
                } else {
                    ManagedProjectionHealth::Verified
                });
                return Err(failure);
            }
        }
    }
    if let Err(error) = persist().await {
        let compensation_errors =
            execute_managed_local_projection_compensations(&applied, &mut compensate).await;
        let restore_error = restore_durable().await.err();
        let failure = transaction_failure(
            ManagedLocalProjectionFailureKind::Persistence,
            ManagedLocalApplyFailure::clean(error),
            compensation_errors,
            restore_error,
        );
        set_health(if failure.recovery_required() {
            ManagedProjectionHealth::RepairRequired
        } else {
            ManagedProjectionHealth::Verified
        });
        return Err(failure);
    }
    set_health(ManagedProjectionHealth::Verified);
    Ok(())
}

async fn execute_managed_acl_demotion_transaction<
    Receipt,
    Quiesce,
    QuiesceFuture,
    SetHealth,
    Publish,
    PublishFuture,
    StrictFlush,
    StrictFlushFuture,
    CommitMode,
    Compensate,
    CompensateFuture,
    RestoreDurable,
    RestoreDurableFuture,
>(
    mut quiesce_acl_ct: Quiesce,
    mut set_projection_health: SetHealth,
    mut publish_and_persist: Publish,
    mut strict_flush: StrictFlush,
    mut commit_mode: CommitMode,
    mut compensate: Compensate,
    mut restore_durable_old_state: RestoreDurable,
) -> Result<(), String>
where
    Quiesce: FnMut() -> QuiesceFuture,
    QuiesceFuture: Future<Output = Result<(), String>>,
    SetHealth: FnMut(ManagedProjectionHealth),
    Publish: FnMut() -> PublishFuture,
    PublishFuture: Future<Output = Result<Vec<Receipt>, String>>,
    StrictFlush: FnMut() -> StrictFlushFuture,
    StrictFlushFuture: Future<Output = Result<(), String>>,
    CommitMode: FnMut(ManagedAclPublicationMode),
    Compensate: FnMut(&Receipt) -> CompensateFuture,
    CompensateFuture: Future<Output = Result<(), String>>,
    RestoreDurable: FnMut() -> RestoreDurableFuture,
    RestoreDurableFuture: Future<Output = Result<(), String>>,
{
    quiesce_acl_ct().await?;
    set_projection_health(ManagedProjectionHealth::Unverified);

    let receipts = publish_and_persist().await?;
    if let Err(flush_error) = strict_flush().await {
        let mut errors = vec![flush_error];
        for receipt in receipts.iter().rev() {
            if let Err(error) = compensate(receipt).await {
                errors.push(error);
            }
        }
        if let Err(error) = restore_durable_old_state().await {
            errors.push(error);
        }
        return Err(errors.join("; "));
    }

    commit_mode(ManagedAclPublicationMode::NeutronAttachOwnedStandaloneAcl);
    Ok(())
}

/// Finish a Neutron-owned publication while its runtime and instance locks are
/// still held.  Publication receipts are deliberately replayed in reverse: the
/// bank preimage must be restored before its failed shadow is scrubbed, then
/// the shared selector preimages and finally the durable snapshot.
async fn execute_managed_owned_acl_publication_transaction<
    Receipt,
    SetHealth,
    Publish,
    PublishFuture,
    StrictFlush,
    StrictFlushFuture,
    Compensate,
    CompensateFuture,
    RestoreDurable,
    RestoreDurableFuture,
>(
    mut set_projection_health: SetHealth,
    mut publish_and_persist: Publish,
    mut strict_flush: StrictFlush,
    mut compensate: Compensate,
    mut restore_durable_old_state: RestoreDurable,
) -> Result<(), String>
where
    SetHealth: FnMut(ManagedProjectionHealth),
    Publish: FnMut() -> PublishFuture,
    PublishFuture: Future<Output = Result<Vec<Receipt>, String>>,
    StrictFlush: FnMut() -> StrictFlushFuture,
    StrictFlushFuture: Future<Output = Result<(), String>>,
    Compensate: FnMut(&Receipt) -> CompensateFuture,
    CompensateFuture: Future<Output = Result<(), String>>,
    RestoreDurable: FnMut() -> RestoreDurableFuture,
    RestoreDurableFuture: Future<Output = Result<(), String>>,
{
    set_projection_health(ManagedProjectionHealth::Unverified);
    let receipts = publish_and_persist().await?;
    if let Err(flush_error) = strict_flush().await {
        let mut errors = vec![flush_error];
        for receipt in receipts.iter().rev() {
            if let Err(error) = compensate(receipt).await {
                errors.push(error);
            }
        }
        if let Err(error) = restore_durable_old_state().await {
            errors.push(error);
        }
        return Err(errors.join("; "));
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

fn compensate_managed_acl_publication(
    receipt: &ManagedAclPublicationReceipt,
    runtime: TapMapRuntime<'_>,
    ebpf_path: &str,
) -> Result<(), String> {
    match receipt {
        ManagedAclPublicationReceipt::General(mutation) => {
            let compensation = shared_network_compensation(mutation);
            apply_shared_network_mutation(&compensation, runtime, ebpf_path).map_err(|error| {
                format!(
                    "restore managed demotion selector {:?}: {}",
                    compensation, error
                )
            })
        }
        ManagedAclPublicationReceipt::ActiveBank {
            previous_bank,
            published_bank,
        } => {
            aria_core::ebpf_ops::set_acl_active_bank(runtime, *previous_bank)
                .map_err(|error| format!("restore managed demotion ACL bank: {}", error))?;
            aria_core::ebpf_ops::scrub_acl_bank(runtime, *published_bank)
                .map(|_| ())
                .map_err(|error| {
                    format!(
                        "scrub rolled-back managed demotion bank {}: {}",
                        published_bank, error
                    )
                })
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

async fn rollback_owned_acl_after_durable_commit(
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
    state.managed_projection_health = ManagedProjectionHealth::Unverified;
    let persistence_failure = matches!(&original, ControlPlaneError::PersistenceError(_));
    let mut rollback_errors = Vec::new();
    let compensations = managed_acl_publication_compensations(mutations, failure_phase);
    let mut active_bank_restored = true;
    if let Err(error) =
        execute_managed_acl_publication_compensations(&compensations, |compensation| {
            let result = apply_managed_acl_publication_compensation(
                compensation,
                runtime,
                ebpf_path,
                previous_active_bank,
            );
            if matches!(
                compensation,
                ManagedAclPublicationCompensation::RestoreActiveBank
            ) && result.is_err()
            {
                active_bank_restored = false;
            }
            result
        })
    {
        rollback_errors.push(error);
    }
    if active_bank_restored {
        if let Err(error) = aria_core::ebpf_ops::scrub_acl_bank(runtime, shadow_bank) {
            rollback_errors.push(format!("scrub shadow bank {}: {}", shadow_bank, error));
        }
    } else {
        rollback_errors.push(format!(
            "preserved publication bank {} because active-bank restore failed",
            shadow_bank
        ));
    }
    let cleanup = cleanup_transaction_created_port_sets(created_port_sets, runtime, ebpf_path);
    for failure in &cleanup.failures {
        rollback_errors.push(failure.error.clone());
    }
    if let Err(error) =
        restore_durable_old_state_after_failed_persistence(state, old_state, &cleanup).await
    {
        rollback_errors.push(error);
    }
    if rollback_errors.is_empty() {
        original
    } else {
        let message = format!(
            "{}; owned ACL rollback failed: {}",
            original,
            rollback_errors.join("; ")
        );
        if persistence_failure {
            ControlPlaneError::PersistenceError(message)
        } else {
            ControlPlaneError::KernelError(message)
        }
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
    GroupConflict(String),
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
            Self::GroupConflict(s) => write!(f, "{}", s),
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
            Self::GroupInUse(_)
            | Self::GroupConflict(_)
            | Self::LocalWriteBlocked { .. } => 409,
            Self::KernelError(_) => 500,
            Self::PersistenceError(_) | Self::InstanceNotReady(_) => 503,
        }
    }
}

fn local_write_block_reason(
    domain: LocalWriteDomain,
    publication_mode: Option<ManagedAclPublicationMode>,
    authority: Option<&NeutronPortAuthority>,
) -> Option<Option<String>> {
    match (publication_mode, domain) {
        (Some(ManagedAclPublicationMode::ManagedAcl), LocalWriteDomain::Acl) => Some(None),
        (Some(ManagedAclPublicationMode::ManagedAcl), LocalWriteDomain::Conntrack) => {
            Some(Some("acl".to_string()))
        }
        _ => authority.and_then(|authority| {
            let domain_name = domain.as_str();
            if authority.managed_domains.contains(domain_name) {
                Some(None)
            } else if domain == LocalWriteDomain::Conntrack
                && authority.managed_domains.contains("acl")
            {
                Some(Some("acl".to_string()))
            } else {
                None
            }
        }),
    }
}

fn ensure_serialized_local_write_allowed(
    instance: &str,
    domain: LocalWriteDomain,
    publication_mode: Option<ManagedAclPublicationMode>,
    authority: Option<&NeutronPortAuthority>,
) -> Result<(), ControlPlaneError> {
    if let Some(dependency_of) = local_write_block_reason(domain, publication_mode, authority) {
        return Err(ControlPlaneError::LocalWriteBlocked {
            instance: instance.to_string(),
            domain: domain.as_str().to_string(),
            dependency_of,
        });
    }
    Ok(())
}

fn requested_local_config_write_domains(
    conntrack: Option<bool>,
    monitoring: Option<bool>,
    acl: Option<bool>,
    qos: Option<bool>,
    mirror: Option<bool>,
    tcprt: Option<bool>,
    ssl: Option<bool>,
) -> Vec<LocalWriteDomain> {
    let mut domains = Vec::new();
    if conntrack.is_some() {
        domains.push(LocalWriteDomain::Conntrack);
    }
    if monitoring.is_some() {
        domains.push(LocalWriteDomain::Config);
    }
    if acl.is_some() {
        domains.push(LocalWriteDomain::Acl);
    }
    if qos.is_some() {
        domains.push(LocalWriteDomain::Qos);
    }
    if mirror.is_some() {
        domains.push(LocalWriteDomain::Mirror);
    }
    if tcprt.is_some() {
        domains.push(LocalWriteDomain::Tcprt);
    }
    if ssl.is_some() {
        domains.push(LocalWriteDomain::Ssl);
    }
    domains
}

fn local_group_write_block_reason(
    group_name: &str,
    publication_mode: Option<ManagedAclPublicationMode>,
    authority: Option<&NeutronPortAuthority>,
) -> bool {
    group_name
        .trim()
        .to_ascii_lowercase()
        .starts_with("neutron:")
        && (publication_mode == Some(ManagedAclPublicationMode::ManagedAcl) || authority.is_some())
}

fn ensure_serialized_local_group_write_allowed(
    instance: &str,
    group_name: &str,
    publication_mode: Option<ManagedAclPublicationMode>,
    authority: Option<&NeutronPortAuthority>,
) -> Result<(), ControlPlaneError> {
    if local_group_write_block_reason(group_name, publication_mode, authority) {
        return Err(ControlPlaneError::LocalWriteBlocked {
            instance: instance.to_string(),
            domain: LocalWriteDomain::Acl.as_str().to_string(),
            dependency_of: None,
        });
    }
    Ok(())
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
            ip_family: rule.ip_family,
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
            ip_family: policy.ip_family,
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

        let network_plan = managed_acl_shadow_network_plan(projection);
        execute_acl_family_staging(|family| {
            for (direction, cidr, group_id) in &network_plan {
                let cidr_family = if cidr.contains(':') {
                    IP_FAMILY_V6
                } else {
                    IP_FAMILY_V4
                };
                if cidr_family != family {
                    continue;
                }
                aria_core::ebpf_ops::add_acl_network_in_bank(
                    direction, cidr, *group_id, bank, runtime, ebpf_path,
                )
                .map_err(|error| {
                    ControlPlaneError::KernelError(format!(
                        "stage shadow bank {} family {} {} group {} cidr {}: {}",
                        bank, family, direction, group_id, cidr, error
                    ))
                })?;
            }

            for rule in state.rules.iter().filter(|rule| rule.ip_family == family) {
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
                    rule.ip_family,
                    runtime,
                    ebpf_path,
                )
                .map_err(|e| {
                    ControlPlaneError::KernelError(format!(
                        "stage shadow bank {} family {} policy src={} dst={} proto={} direction={}: {}",
                        bank,
                        family,
                        rule.src_group_id,
                        rule.dst_group_id,
                        rule.proto,
                        rule.direction,
                        e
                    ))
                })?;
            }
            Ok(())
        })
    }

    fn stage_standalone_acl_shadow_bank(
        state: &FirewallState,
        entries: &RuntimeGroupMapEntries,
        runtime: TapMapRuntime<'_>,
        bank: u8,
        ebpf_path: &str,
    ) -> Result<(), ControlPlaneError> {
        if !state.rules.is_empty() {
            return Err(ControlPlaneError::ValidationError(
                "standalone-compatible demotion shadow requires an empty ACL policy domain"
                    .to_string(),
            ));
        }

        aria_core::ebpf_ops::scrub_acl_bank(runtime, bank)
            .map_err(ControlPlaneError::KernelError)?;
        let write_entries = |direction: &'static str,
                             network_entries: &[aria_core::ebpf_ops::RuntimeNetworkEntry]|
         -> Result<(), ControlPlaneError> {
            for entry in network_entries {
                let cidr = format!("{}/{}", entry.address, entry.prefix_len);
                aria_core::ebpf_ops::add_acl_network_in_bank(
                    direction,
                    &cidr,
                    entry.group_id,
                    bank,
                    runtime,
                    ebpf_path,
                )
                .map_err(|error| {
                    ControlPlaneError::KernelError(format!(
                        "stage standalone shadow bank {} {} group {} cidr {}: {}",
                        bank, direction, entry.group_id, cidr, error
                    ))
                })?;
            }
            Ok(())
        };
        write_entries("src", &entries.acl_src)?;
        write_entries("dst", &entries.acl_dst)?;
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
            if policy.ip_family != IP_FAMILY_V4 && policy.ip_family != IP_FAMILY_V6 {
                return Err(ControlPlaneError::ValidationError(format!(
                    "invalid ACL IP family {}",
                    policy.ip_family
                )));
            }
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
        let iface_ctx = match lookup_iface_ctx(pin_path, ifindex) {
            Ok(Some(iface_ctx)) => iface_ctx,
            Ok(None) => {
                return PreexistingRuntimeValidation::missing_identity(format!(
                    "preexisting live runtime for {} is missing IFACE_CTX_MAP identity for ifindex {}",
                    name, ifindex
                ))
            }
            Err(error) => return PreexistingRuntimeValidation::fatal(error),
        };
        if iface_ctx.tap_id != tap_id {
            return PreexistingRuntimeValidation::fatal(format!(
                "preexisting live runtime mismatch for {}: IFACE_CTX_MAP ifindex {} points to tap_id {}, expected {}",
                name, ifindex, iface_ctx.tap_id, tap_id
            ));
        }

        let runtime = TapMapRuntime::new(pin_path, tap_id);
        let actual = match lookup_runtime_config(runtime) {
            Ok(Some(actual)) => actual,
            Ok(None) => {
                return PreexistingRuntimeValidation::missing_identity(format!(
                    "preexisting live runtime for {} is missing TAP_CONFIG_MAP identity for tap_id {}",
                    name, tap_id
                ))
            }
            Err(error) => return PreexistingRuntimeValidation::fatal(error),
        };
        let tc_runtime_complete = match preexisting_tc_acl_runtime_is_healthy(
            state.conntrack_enabled || state.acl_enabled,
            actual.conntrack_enabled == 0 && actual.acl_enabled == 0,
            pin_state.preexisting_live_links,
            pin_state.preexisting_tc_ingress_link,
            pin_state.preexisting_tc_egress_link,
            runtime_instance.tc_acl_link_health(),
        ) {
            Ok(complete) => complete,
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

        let gate_disposition = match classify_preexisting_runtime_gate(
            projection_mode,
            actual.conntrack_enabled,
            actual.acl_enabled,
            expected.0,
            expected.2,
            tc_runtime_complete,
        ) {
            Ok(disposition) => disposition,
            Err(error) => {
                return PreexistingRuntimeValidation::fatal(format!(
                    "preexisting live runtime mismatch for {}: {}; actual flags {:?}, expected {:?}",
                    name, error, actual_flags, expected
                ));
            }
        };

        let projection_validation_state = preexisting_projection_validation_state(
            state,
            projection_mode,
            tc_runtime_complete,
            gate_disposition,
        );
        let projection_drift = match projection_mode {
            GroupProjectionMode::StandaloneCompatibility => {
                validate_pinned_runtime_state(runtime, &projection_validation_state)
                    .map_or_else(ProjectionDrift::Fatal, |()| ProjectionDrift::Clean)
            }
            GroupProjectionMode::Managed => validate_managed_pinned_runtime_state(runtime, state),
        };
        PreexistingRuntimeValidation {
            projection_drift,
            gate_disposition: Some(gate_disposition),
            actual_gate: Some((
                actual.conntrack_enabled != 0,
                actual.acl_enabled != 0,
            )),
            runtime_identity_missing: false,
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

    pub(crate) fn new_with_fragment_tracking(
        ebpf_path: &str,
        base_pin_path: &str,
        base_state_path: &str,
        ssl_manager: Arc<SslManager>,
        kernel_drop_manager: Arc<KernelDropManager>,
        trace_manager: Arc<TraceManager>,
        fragment_tracking: FragmentTrackingSettings,
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
            fragment_tracking,
            chains: RwLock::new(chains),
            maintenance_authority_seal: Arc::new(()),
        }
    }

    pub(crate) fn fragment_tracking_settings(&self) -> FragmentTrackingSettings {
        self.fragment_tracking
    }

    pub fn managed_pin_path(&self) -> String {
        format!("{}/{}", self.base_pin_path, MANAGED_SHARED_PIN_NAMESPACE)
    }

    pub fn trace_map_mode(&self) -> TraceMapMode {
        self.trace_manager.map_mode()
    }

    async fn current_managed_maintenance_authority_facts(
        &self,
    ) -> Result<ManagedMaintenanceAuthorityFacts, String> {
        acquire_managed_maintenance_authority_facts(
            &ControlPlaneManagedMaintenanceAuthoritySource {
                control_plane: self,
            },
        )
    }

    pub(crate) async fn mint_managed_maintenance_authority(
        &self,
    ) -> Result<ManagedFirewallConfigAuthority, String> {
        let facts = self.current_managed_maintenance_authority_facts().await?;
        Ok(ManagedFirewallConfigAuthority {
            facts,
            authority_seal: Arc::downgrade(&self.maintenance_authority_seal),
        })
    }

    pub(crate) async fn set_acl_maintenance_bypass(
        &self,
        authority: &ManagedFirewallConfigAuthority,
        enabled: bool,
    ) -> Result<(), String> {
        let _lifecycle_guard = self.runtime_lifecycle_lock.lock().await;
        let authority_seal = authority
            .authority_seal
            .upgrade()
            .ok_or_else(|| "managed maintenance authority owner expired".to_string())?;
        if !Arc::ptr_eq(&authority_seal, &self.maintenance_authority_seal) {
            return Err("managed maintenance authority belongs to another control plane".to_string());
        }
        let current = self.current_managed_maintenance_authority_facts().await?;
        if current != authority.facts {
            return Err("live Aria runtime identity changed after authority mint".to_string());
        }

        let mut store = ManagedFirewallConfigStore::new(
            current.configured_pin_path,
            current.configured_mode,
            current.firewall_config_map_id,
        );
        aria_core::ebpf_ops::serialized_shared_firewall_config_rmw(
            &mut store,
            "ACL maintenance bypass update",
            |current| {
                let current = current.ok_or_else(|| {
                    "ACL maintenance bypass update requires initialized FIREWALL_CONFIG key 0"
                        .to_string()
                })?;
                Ok(aria_core::ebpf_ops::firewall_config_with_acl_maintenance_bypass(
                    current, enabled,
                ))
            },
        )?;
        Ok(())
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

    pub(crate) async fn verify_and_mark_managed_projection(
        &self,
        instance: &str,
    ) -> Result<(), String> {
        let _runtime_guard = self.lock_runtime_lifecycle().await;
        let instance_state = self
            .get_instance(instance)
            .await
            .map_err(|error| error.to_string())?;
        let mut state = instance_state.write().await;
        if state.managed_acl_publication_mode != ManagedAclPublicationMode::ManagedAcl {
            return Err(format!(
                "managed ACL mode changed before projection verification for '{}'",
                instance
            ));
        }

        state.managed_projection_health = ManagedProjectionHealth::Unverified;

        let actual_gate = aria_core::ebpf_ops::read_runtime_config(state.map_runtime())
            .map_err(|error| format!("read managed ACL runtime gate: {}", error))?;
        validate_managed_projection_runtime_gate(&state.state, &actual_gate)?;
        require_clean_managed_projection_inventory(validate_managed_pinned_runtime_state(
            state.map_runtime(),
            &state.state,
        ))?;
        if neutron_acl_gate_requires_tc(state.state.conntrack_enabled, state.state.acl_enabled) {
            Self::require_tc_acl_ready_locked(instance, &state, self.trace_map_mode())
                .map_err(|error| error.to_string())?;
        }

        state.managed_projection_health = ManagedProjectionHealth::Verified;
        Ok(())
    }

    /// Reconcile ACL ownership while the caller holds the runtime lifecycle lock.
    ///
    /// This helper must not reacquire that lock. Registry callers additionally
    /// hold the per-interface lock, preserving iface -> lifecycle -> instance.
    pub(crate) async fn reconcile_managed_acl_ownership_serialized(
        &self,
        instance: &str,
        requested_mode: ManagedAttachMode,
    ) -> Result<(), String> {
        let instance_state = self
            .get_instance(instance)
            .await
            .map_err(|error| error.to_string())?;
        let action = {
            let state = instance_state.read().await;
            managed_acl_promotion_action(
                state.managed_acl_publication_mode,
                state.managed_projection_health,
                requested_mode,
            )
        };

        match action {
            ManagedAclPromotionAction::Preserve => Ok(()),
            ManagedAclPromotionAction::Promote {
                next_mode,
                next_health,
                quiesce_acl_ct,
            } => {
                let mut state = instance_state.write().await;
                if quiesce_acl_ct {
                    let transition = read_pinned_acl_ct_gate_transition(
                        state.map_runtime(),
                        Some(false),
                        Some(false),
                    )
                    .map_err(|error| {
                        format!("read live gate before managed ACL promotion: {}", error)
                    })?;
                    let pin_path = state.pin_path.clone();
                    let tap_id = state.tap_id;
                    execute_pinned_acl_gate_transition(
                        &pin_path,
                        tap_id,
                        transition,
                        false,
                        false,
                    )
                    .map_err(|error| {
                        format!(
                            "failed to fence ACL/CT while promoting managed ACL ownership for {}: {}",
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
            ManagedAclPromotionAction::Demote {
                next_mode,
                next_health,
            } => {
                self.execute_managed_acl_demotion_serialized(instance, next_mode, next_health)
                    .await
            }
        }
    }

    async fn execute_managed_acl_demotion_serialized(
        &self,
        instance: &str,
        next_mode: ManagedAclPublicationMode,
        next_health: ManagedProjectionHealth,
    ) -> Result<(), String> {
        if next_mode != ManagedAclPublicationMode::NeutronAttachOwnedStandaloneAcl
            || next_health != ManagedProjectionHealth::Unverified
        {
            return Err("invalid managed ACL demotion target lifecycle".to_string());
        }

        let instance_state = self
            .get_instance(instance)
            .await
            .map_err(|error| error.to_string())?;
        let (old_state, demotion_epoch_advanced) = {
            let mut state = instance_state.write().await;
            let current_mode = state.managed_acl_publication_mode;
            let runtime_pin_path = state.pin_path.clone();
            let runtime_tap_id = state.tap_id;
            let transition = read_pinned_acl_ct_gate_transition(
                state.map_runtime(),
                Some(false),
                Some(false),
            )
            .map_err(|error| format!("read live gate before managed ACL demotion: {}", error))?;
            quiesce_managed_acl_demotion_before_build(
                current_mode,
                &mut state.managed_projection_health,
                || {
                    execute_pinned_acl_gate_transition(
                        &runtime_pin_path,
                        runtime_tap_id,
                        transition,
                        false,
                        false,
                    )
                    .map_err(|error| {
                        format!("quiesce managed ACL demotion before target build: {}", error)
                    })
                },
            )?;
            state.managed_projection_health = ManagedProjectionHealth::Unverified;
            (
                state.state.clone(),
                transition == FragmentEpochGateTransition::SemanticChange,
            )
        };
        let authority_port_id = {
            let authorities = self.neutron_authorities.read().await;
            authorities
                .get(instance)
                .map(|authority| authority.port_id.clone())
        };
        let owner_prefix = managed_acl_demotion_owner_prefix(authority_port_id.as_deref());
        let target = build_managed_acl_demotion_target(&old_state, &owner_prefix)?;
        if !target.publication_required {
            return Err("managed ACL demotion must force projection publication".to_string());
        }
        let proposed_projection = compile_managed_group_projection(&target.final_state)?;
        let clean_semantic_mutations =
            managed_general_state_mutations(&old_state, &target.final_state)
                .map_err(|error| error.to_string())?;
        let mut quiesced_committed_state = old_state.clone();
        quiesced_committed_state.conntrack_enabled = false;
        quiesced_committed_state.acl_enabled = false;

        let target = Arc::new(target);
        let managed_acl_projection_health = Arc::new(std::sync::Mutex::new(next_health));
        let managed_acl_publication_mode =
            Arc::new(std::sync::Mutex::new(ManagedAclPublicationMode::ManagedAcl));

        let quiesce_instance = instance_state.clone();
        let managed_acl_projection_health_update = managed_acl_projection_health.clone();
        let publish_instance = instance_state.clone();
        let publish_target = target.clone();
        let publish_old_state = old_state.clone();
        let publish_committed_state = quiesced_committed_state.clone();
        let publish_projection = proposed_projection.clone();
        let publish_mutations = clean_semantic_mutations.clone();
        let publish_projection_health = managed_acl_projection_health.clone();
        let strict_flush_instance = instance_state.clone();
        let managed_acl_publication_mode_update = managed_acl_publication_mode.clone();
        let compensate_instance = instance_state.clone();
        let compensate_ebpf_path = self.ebpf_path.clone();
        let restore_instance = instance_state.clone();
        let restore_old_state = old_state.clone();

        execute_managed_acl_demotion_transaction(
            move || {
                let quiesce_instance = quiesce_instance.clone();
                async move {
                    let state = quiesce_instance.read().await;
                    let pin_path = state.pin_path.clone();
                    let tap_id = state.tap_id;
                    let transition = if demotion_epoch_advanced {
                        FragmentEpochGateTransition::EpochAlreadyAdvanced
                    } else {
                        FragmentEpochGateTransition::EqualState
                    };
                    execute_pinned_acl_gate_transition(
                        &pin_path,
                        tap_id,
                        transition,
                        false,
                        false,
                    )
                    .map_err(|error| format!("quiesce managed ACL demotion gate: {}", error))
                }
            },
            move |health| {
                *managed_acl_projection_health_update
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner()) = health;
            },
            move || {
                let publish_instance = publish_instance.clone();
                let publish_target = publish_target.clone();
                let publish_old_state = publish_old_state.clone();
                let publish_committed_state = publish_committed_state.clone();
                let publish_projection = publish_projection.clone();
                let publish_mutations = publish_mutations.clone();
                let publish_projection_health = publish_projection_health.clone();
                async move {
                    let mut state = publish_instance.write().await;
                    state.managed_projection_health = *publish_projection_health
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner());
                    if state.managed_acl_publication_mode != ManagedAclPublicationMode::ManagedAcl {
                        return Err("managed ACL mode changed during demotion".to_string());
                    }

                    let current_acl_bank =
                        aria_core::ebpf_ops::read_acl_active_bank(state.map_runtime())?;
                    let next_acl_bank = aria_core::common::acl_next_bank(current_acl_bank);
                    let new_port_sets_by_key = BTreeMap::new();
                    let created_port_sets = Vec::new();
                    let mut report = OwnedAclReconcileReport::default();
                    let mut receipts = Vec::new();
                    let publication_performed = self
                        .publish_acl_projection_locked(
                            instance,
                            &mut state,
                            &publish_old_state,
                            &publish_target.final_state,
                            &publish_projection,
                            true,
                            Some(&publish_committed_state),
                            Some(&publish_target.standalone_shadow_entries),
                            true,
                            publish_mutations,
                            current_acl_bank,
                            next_acl_bank,
                            &new_port_sets_by_key,
                            &created_port_sets,
                            &publish_target.released_port_sets,
                            &mut report,
                            Some(&mut receipts),
                        )
                        .await
                        .map_err(|error| error.to_string())?;
                    if !publication_performed {
                        return Err(
                            "forced managed ACL demotion publication returned no-op".to_string()
                        );
                    }
                    Ok(receipts)
                }
            },
            move || {
                let strict_flush_instance = strict_flush_instance.clone();
                async move {
                    let state = strict_flush_instance.read().await;
                    aria_core::ct_ops::scrub_ct_tables_strict(state.map_runtime())
                        .map(|_| ())
                        .map_err(|error| format!("strict managed ACL demotion CT flush: {}", error))
                }
            },
            move |mode| {
                debug_assert_eq!(
                    mode,
                    ManagedAclPublicationMode::NeutronAttachOwnedStandaloneAcl
                );
                *managed_acl_publication_mode_update
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner()) = mode;
            },
            move |receipt| {
                let compensate_instance = compensate_instance.clone();
                let compensate_ebpf_path = compensate_ebpf_path.clone();
                let receipt = receipt.clone();
                async move {
                    let state = compensate_instance.read().await;
                    compensate_managed_acl_publication(
                        &receipt,
                        state.map_runtime(),
                        &compensate_ebpf_path,
                    )
                }
            },
            move || {
                let restore_instance = restore_instance.clone();
                let restore_old_state = restore_old_state.clone();
                async move {
                    let mut state = restore_instance.write().await;
                    state
                        .compact_and_publish_state(restore_old_state)
                        .await
                        .map_err(|error| {
                            format!("restore durable old_state after demotion: {}", error)
                        })
                }
            },
        )
        .await?;

        let committed_mode = *managed_acl_publication_mode
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let committed_health = *managed_acl_projection_health
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut state = instance_state.write().await;
        state.managed_acl_publication_mode = committed_mode;
        state.managed_projection_health = committed_health;

        let runtime_pin_path = state.pin_path.clone();
        let runtime_tap_id = state.tap_id;
        let runtime = TapMapRuntime::new(&runtime_pin_path, runtime_tap_id);
        let released_cleanup_targets = target
            .released_port_sets
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
            "managed ACL demotion released",
        );
        if !released_cleanup.cleaned_bitmap_indices.is_empty() {
            let mut reusable_state = state.state.clone();
            match apply_confirmed_port_set_cleanups(&mut reusable_state, &released_cleanup) {
                Ok(()) => {
                    if let Err(error) = state.compact_and_publish_state(reusable_state).await {
                        warn!(
                            instance = %instance,
                            error = %error,
                            "failed to persist managed ACL demotion bitmap cleanup"
                        );
                    }
                }
                Err(error) => warn!(
                    instance = %instance,
                    error = %error,
                    "failed to release managed ACL demotion bitmap quarantine"
                ),
            }
        }
        for failure in &released_cleanup.failures {
            warn!(
                instance = %instance,
                bitmap_idx = failure.bitmap_idx,
                error = %failure.error,
                "managed ACL demotion port set remains durably quarantined"
            );
        }
        match aria_core::ebpf_ops::read_acl_active_bank(runtime) {
            Ok(active_bank) => {
                let previous_bank = aria_core::common::acl_next_bank(active_bank);
                if let Err(error) = aria_core::ebpf_ops::scrub_acl_bank(runtime, previous_bank) {
                    warn!(
                        instance = %instance,
                        bank = previous_bank,
                        error = %error,
                        "failed to scrub previous managed ACL bank after demotion"
                    );
                }
            }
            Err(error) => warn!(
                instance = %instance,
                error = %error,
                "failed to read active ACL bank after managed demotion"
            ),
        }

        info!(
            instance = %instance,
            publication_mode = ?committed_mode,
            projection_health = ?committed_health,
            "demoted managed ACL ownership to attach-owned standalone compatibility"
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
        required_publication_mode: ManagedAclPublicationMode,
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
            Some(required_publication_mode),
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

    pub(crate) async fn neutron_authority_names(&self) -> BTreeSet<String> {
        self.neutron_authorities
            .read()
            .await
            .keys()
            .cloned()
            .collect()
    }

    pub(crate) async fn active_instance_ifindex(&self, instance: &str) -> Option<u32> {
        let state = {
            let instances = self.instances.read().await;
            instances.get(instance).cloned()
        }?;
        let ifindex = state.read().await.ifindex;
        ifindex
    }

    async fn local_publication_mode_snapshot(
        &self,
        instance: &str,
    ) -> Option<ManagedAclPublicationMode> {
        let instance_state = {
            let instances = self.instances.read().await;
            instances.get(instance).cloned()
        }?;
        let state = instance_state.read().await;
        Some(state.managed_acl_publication_mode)
    }

    pub async fn ensure_local_write_allowed(
        &self,
        instance: &str,
        domain: LocalWriteDomain,
    ) -> Result<(), ControlPlaneError> {
        if matches!(domain, LocalWriteDomain::Qos | LocalWriteDomain::Mirror) {
            let instance_state = {
                let instances = self.instances.read().await;
                instances.get(instance).cloned()
            };
            if let Some(instance_state) = instance_state {
                let state = instance_state.read().await;
                local_projection_recovery_admission(&state.state, domain)?;
            }
        }
        let publication_mode =
            if matches!(domain, LocalWriteDomain::Acl | LocalWriteDomain::Conntrack) {
                self.local_publication_mode_snapshot(instance).await
            } else {
                None
            };
        let authority = self.neutron_authorities.read().await.get(instance).cloned();
        ensure_serialized_local_write_allowed(
            instance,
            domain,
            publication_mode,
            authority.as_ref(),
        )
    }

    pub async fn ensure_local_group_write_allowed(
        &self,
        instance: &str,
        group_name: &str,
    ) -> Result<(), ControlPlaneError> {
        let publication_mode = self.local_publication_mode_snapshot(instance).await;
        let authority = self.neutron_authorities.read().await.get(instance).cloned();
        ensure_serialized_local_group_write_allowed(
            instance,
            group_name,
            publication_mode,
            authority.as_ref(),
        )
    }

    pub async fn get_trace_runtime_status(&self) -> HashMap<String, TraceRuntimeStatusSnapshot> {
        self.trace_manager.runtime_status().await
    }

    async fn repair_preexisting_local_projection(
        &self,
        name: &str,
        pin_path: &str,
        state_path: &str,
        projection_mode: GroupProjectionMode,
        state: &mut FirewallState,
        wal: &WalClient,
    ) -> Result<(), String> {
        let repair_qos = state.local_projection_recovery_required(LocalWriteDomain::Qos.as_str());
        let repair_mirror =
            state.local_projection_recovery_required(LocalWriteDomain::Mirror.as_str());
        if !repair_qos && !repair_mirror {
            return Ok(());
        }

        let runtime = TapMapRuntime::new(pin_path, state.tap_id);
        let (actual_qos, actual_mirror, actual_global_mirror) =
            capture_local_projection_runtime(runtime)?;
        let mut repair_desired = state.clone();
        if !repair_qos {
            repair_desired.qos_rules.clear();
        }
        if !repair_mirror {
            repair_desired.mirror_rules.clear();
        }
        let mut operations = plan_local_projection_runtime_repair(
            &repair_desired,
            if repair_qos { &actual_qos } else { &[] },
            if repair_mirror { &actual_mirror } else { &[] },
            if repair_mirror {
                &actual_global_mirror
            } else {
                &[]
            },
        )
        .map_err(|error| error.to_string())?;
        operations.retain(|operation| match operation {
            ManagedLocalDomainOperation::EnsureFqQdisc { .. }
            | ManagedLocalDomainOperation::CleanupOwnedFqQdisc => repair_qos,
            ManagedLocalDomainOperation::QosUpsert(_)
            | ManagedLocalDomainOperation::QosDelete { .. } => repair_qos,
            ManagedLocalDomainOperation::MirrorUpsert(_)
            | ManagedLocalDomainOperation::MirrorDelete { .. } => repair_mirror,
        });

        if repair_qos
            && operations.iter().any(|operation| {
                matches!(
                    operation,
                    ManagedLocalDomainOperation::QosUpsert(rule) if rule.mode == 1
                )
            })
        {
            let qdisc = ensure_fq_qdisc(name)?;
            if matches!(qdisc, FqQdiscState::InstalledNow) {
                if let Err(error) = mark_owned_fq_qdisc(state_path, name) {
                    let rollback = rollback_installed_fq_qdisc(name, name, state_path).err();
                    return Err(domain_apply_failure(error.to_string(), rollback).message);
                }
            }
        }

        let runtime_state = ManagedLocalProjectionRuntime {
            instance: name.to_string(),
            pin_path: pin_path.to_string(),
            state_path: state_path.to_string(),
            ebpf_path: self.ebpf_path.clone(),
            tap_id: state.tap_id,
            attached_iface: state.attached_iface.clone(),
            qos_enabled: state.qos_enabled,
            mirror_enabled: state.mirror_enabled,
        };
        for operation in &operations {
            apply_managed_local_domain_raw(operation, &runtime_state)?;
        }
        match projection_mode {
            GroupProjectionMode::StandaloneCompatibility => {
                validate_pinned_runtime_state(runtime, state)?;
            }
            GroupProjectionMode::Managed => {
                match validate_managed_pinned_runtime_state(runtime, state) {
                    ProjectionDrift::Clean => {}
                    ProjectionDrift::RepairRequired(plan) => {
                        return Err(format!(
                            "local projection recovery validation still requires repair: {:?}",
                            plan
                        ));
                    }
                    ProjectionDrift::Fatal(error) => {
                        return Err(format!(
                            "local projection recovery validation failed: {}",
                            error
                        ));
                    }
                }
            }
        }
        clear_local_projection_recovery_records(state, wal).await
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
        let replay_route = managed_replay_route(mode);
        let projection_mode = replay_route.projection_mode();
        let mut managed_acl_lifecycle = managed_acl_registration_lifecycle(mode, None, None)?;
        let ifindex = Self::resolve_ifindex(name)?;
        let global_ssl_enabled = match self.read_ssl_global_config().await {
            Ok(enabled) => Some(enabled),
            Err(e) => {
                warn!(instance = %name, error = %e, "failed to read global SSL config during register");
                None
            }
        };

        let migration_authority = mode.legacy_acl_migration_authority();
        let mut state = aria_core::wal::load_with_wal_for_authority(
            &state_path,
            migration_authority,
        )
            .map_err(|error| format!("failed to load state for {}: {}", name, error))?;
        state = migrate_state_for_replay(&state_path, &state, migration_authority)?;

        // Do not compact an existing instance until the replacement's durable
        // ACL family projection has been fully validated.
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
        let registration_is_fresh = !pin_state.preexisting_live_links && !replacing_existing;

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

        let fresh_registration_wal = wal.clone();
        persist_fresh_managed_registration_gate_state(
            &mut state,
            mode,
            registration_is_fresh,
            move |snapshot: FirewallState| {
                let wal = fresh_registration_wal.clone();
                async move {
                    let json = match serde_json::to_string_pretty(&snapshot) {
                        Ok(json) => json,
                        Err(error) => {
                            wal.shutdown().await;
                            return Err(format!(
                                "failed to serialize fresh managed gate state: {}",
                                error
                            ));
                        }
                    };
                    match wal.compact(json).await {
                        Ok(()) => Ok(()),
                        Err(error) => {
                            wal.shutdown().await;
                            Err(format!(
                                "failed to persist fresh managed gate state: {}",
                                error
                            ))
                        }
                    }
                }
            },
        )
        .await?;

        let tap_id = state.tap_id;
        let mut preexisting_live_verified = false;
        let preserve_existing_runtime = replacing_existing || pin_state.preexisting_live_links;
        let mut iface_ctx_synced = false;
        let mut tap_config_written = false;

        if pin_state.preexisting_live_links {
            if let Err(error) = self
                .repair_preexisting_local_projection(
                    name,
                    &pin_path,
                    &state_path,
                    projection_mode,
                    &mut state,
                    &wal,
                )
                .await
            {
                wal.shutdown().await;
                return Err(format!(
                    "failed to recover preexisting local projection for {}: {}",
                    name, error
                ));
            }
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
            let actual_gate = preexisting_validation.actual_gate;
            let gate_disposition = preexisting_validation.gate_disposition;
            let runtime_identity_missing = preexisting_validation.runtime_identity_missing;
            let projection_drift = preexisting_validation.projection_drift;
            let lifecycle_projection_drift = projection_drift.clone();
            preexisting_live_verified = match preexisting_projection_verification(projection_drift)
            {
                Ok(projection_verified) => {
                    projection_verified && gate_disposition == Some(RuntimeGateDisposition::Desired)
                }
                Err(e) => {
                    if runtime_identity_missing
                        && matches!(mode, ManagedAttachMode::NeutronResyncRequired { .. })
                    {
                        wal.shutdown().await;
                        return Err(format!(
                            "{}{}",
                            MANAGED_RUNTIME_IDENTITY_MISSING_PREFIX, e
                        ));
                    }
                    let transition = actual_gate.map_or(
                        FragmentEpochGateTransition::SemanticChange,
                        |(conntrack, acl)| {
                            acl_ct_config_gate_transition(
                                conntrack,
                                acl,
                                Some(false),
                                Some(false),
                            )
                        },
                    );
                    let quiesce_error = execute_pinned_acl_gate_transition(
                        &pin_path,
                        tap_id,
                        transition,
                        false,
                        false,
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
                let transition = actual_gate.map_or(
                    FragmentEpochGateTransition::SemanticChange,
                    |(conntrack, acl)| {
                        acl_ct_config_gate_transition(
                            conntrack,
                            acl,
                            Some(false),
                            Some(false),
                        )
                    },
                );
                if let Err(e) = execute_pinned_acl_gate_transition(
                    &pin_path,
                    tap_id,
                    transition,
                    false,
                    false,
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

            let replay_result = replay_managed_state_to_pinned_maps(
                &pin_path,
                &state_path,
                &state,
                replay_route,
            );
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

            if !state.local_projection_recoveries.is_empty() {
                if let Err(error) = clear_local_projection_recovery_records(&mut state, &wal).await
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
                    return Err(error);
                }
            }
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

    pub(crate) async fn activate_managed_registration(
        &self,
        prepared: &PreparedManagedInstance,
    ) -> Result<(), FragmentEpochPublicationFailure> {
        let runtime = TapMapRuntime::new(&prepared.pin_path, prepared.tap_id);
        let (conntrack_enabled, acl_enabled) = match prepared.activation {
            ManagedRuntimeActivation::PreserveVerifiedLive => (
                prepared.state.conntrack_enabled,
                prepared.state.acl_enabled,
            ),
            ManagedRuntimeActivation::RestoreStandalone { conntrack, acl } => (conntrack, acl),
            ManagedRuntimeActivation::AwaitNeutronResync { .. } => (false, false),
        };
        execute_guarded_fragment_epoch_gate_transition(
            neutron_acl_gate_requires_tc(conntrack_enabled, acl_enabled),
            FragmentEpochGateTransition::SemanticChange,
            &mut || {
                require_fragment_runtime_ready(
                    self.fragment_tracking,
                    &prepared.pin_path,
                    prepared.tap_id,
                    conntrack_enabled,
                    acl_enabled,
                )
            },
            &mut || {
                advance_fragment_epoch_action(&prepared.pin_path, prepared.tap_id).map_err(|error| {
                    format!(
                        "advance managed registration fragment epoch for {}: {}",
                        prepared.name, error
                    )
                })
            },
            &mut || match prepared.activation {
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
            },
        )
    }

    pub fn quiesce_managed_registration(
        &self,
        prepared: &PreparedManagedInstance,
        activation_error: Option<&FragmentEpochPublicationFailure>,
    ) -> Result<(), String> {
        let runtime = TapMapRuntime::new(&prepared.pin_path, prepared.tap_id);
        let base_transition = managed_registration_cleanup_gate_transition(
            prepared.preserve_existing_runtime,
            activation_error,
        );
        let transition = if base_transition == FragmentEpochGateTransition::SemanticChange {
            aria_core::ebpf_ops::read_runtime_config(runtime).map_or(
                FragmentEpochGateTransition::SemanticChange,
                |actual| {
                    acl_ct_config_gate_transition(
                        actual.conntrack_enabled != 0,
                        actual.acl_enabled != 0,
                        Some(false),
                        Some(false),
                    )
                },
            )
        } else {
            base_transition
        };
        execute_pinned_acl_gate_transition(
            &prepared.pin_path,
            prepared.tap_id,
            transition,
            false,
            false,
        )
        .map_err(|error| {
            format!(
                "quiesce managed registration {} with fragment fence: {}",
                prepared.name, error
            )
        })
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
        let mut state = prepare_system_publication_state(approved_state, iface, global_ssl_enabled);
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
        execute_guarded_fragment_epoch_gate_transition(
            enforcement_required,
            FragmentEpochGateTransition::SemanticChange,
            &mut || {
                require_fragment_runtime_ready(
                    self.fragment_tracking,
                    pin_path,
                    tap_id,
                    state.conntrack_enabled,
                    state.acl_enabled,
                )
            },
            &mut || {
                advance_fragment_epoch_action(pin_path, tap_id)
                    .map_err(|error| format!("advance system fragment recovery epoch: {}", error))
            },
            &mut || {
                aria_core::ebpf_ops::update_runtime_config(
                    runtime,
                    Some(state.conntrack_enabled),
                    Some(state.monitoring_enabled),
                    Some(state.acl_enabled),
                    Some(state.qos_enabled && !state.qos_rules.is_empty()),
                    Some(state.mirror_enabled && !state.mirror_rules.is_empty()),
                    Some(state.tcprt_enabled),
                    None,
                )
            },
        )
        .map_err(|error| error.to_string())?;
        if !state.local_projection_recoveries.is_empty() {
            if let Err(error) = clear_local_projection_recovery_records(&mut state, &wal).await {
                wal.shutdown().await;
                return Err(error);
            }
        }
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

    async fn unregister_instance_with_authority_policy(
        &self,
        name: &str,
        preserve_neutron_authority: bool,
    ) {
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
        if !preserve_neutron_authority {
            self.clear_neutron_port_authority(name).await;
        }
    }

    /// Unregister an instance after an explicit ownership detach.
    pub async fn unregister_instance(&self, name: &str) {
        self.unregister_instance_with_authority_policy(name, false)
            .await;
    }

    /// Unregister runtime links after the Linux interface disappeared while
    /// retaining Neutron ownership for an authority-aware replacement attach.
    pub(crate) async fn unregister_instance_after_link_loss(&self, name: &str) {
        self.unregister_instance_with_authority_policy(name, true)
            .await;
    }

    pub(crate) async fn scrub_orphaned_managed_runtime_serialized(
        &self,
        name: &str,
        tap_id: u32,
    ) -> Result<u64, String> {
        if tap_id == aria_core::common::TAP_ID_UNASSIGNED {
            return Err(format!(
                "orphan runtime cleanup for {} requires an assigned tap_id",
                name
            ));
        }

        let stale_instance = {
            let instances = self.instances.read().await;
            instances.get(name).cloned()
        };
        if let Some(instance) = &stale_instance {
            let state = instance.read().await;
            if state.tap_id != tap_id {
                return Err(format!(
                    "orphan runtime identity mismatch for {}: registered tap_id {}, persisted tap_id {}",
                    name, state.tap_id, tap_id
                ));
            }
        }

        let mut removed = self
            .kernel_drop_manager
            .remove_managed_tap(tap_id)
            .await
            .map_err(|error| format!("kernel_drop:{}", error))?;

        let pin_path = self.managed_pin_path();
        self.trace_manager.unregister_tap(&pin_path, tap_id).await;
        if Path::new(&pin_path).exists() {
            removed += aria_core::ebpf_ops::scrub_managed_runtime_state(TapMapRuntime::new(
                &pin_path, tap_id,
            ))
            .map_err(|error| format!("managed_maps:{}", error))?;
        }

        if let Some(instance) = stale_instance {
            let removed_instance = {
                let mut instances = self.instances.write().await;
                instances.remove(name)
            };
            if let Some(removed_instance) = removed_instance {
                let mut state = removed_instance.write().await;
                state.shutdown_wal().await;
            } else {
                let mut state = instance.write().await;
                state.shutdown_wal().await;
            }
        }
        self.clear_neutron_port_authority(name).await;
        info!(
            instance = %name,
            tap_id,
            removed_entries = removed,
            "scrubbed orphaned managed runtime"
        );
        Ok(removed)
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
        let actual = aria_core::ebpf_ops::read_runtime_config(runtime)
            .map_err(|error| format!("runtime gate read failed: {}", error))?;
        let transition = acl_ct_config_gate_transition(
            actual.conntrack_enabled != 0,
            actual.acl_enabled != 0,
            Some(false),
            Some(false),
        );
        execute_fragment_epoch_gate_transition(
            transition,
            &mut || {
                advance_fragment_epoch_action(&state.pin_path, state.tap_id)
                    .map_err(|error| format!("runtime epoch advance failed: {}", error))
            },
            &mut || {
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
            },
        )
        .map_err(|error| error.to_string())
    }

    pub async fn list_instance_runtime_health(&self) -> Vec<InstanceRuntimeHealthSnapshot> {
        let instances = self.instance_entries().await;
        let mut snapshots = Vec::with_capacity(instances.len());
        for (name, instance) in instances {
            let state = instance.read().await;
            let cleanup_pending_count = state.state.pending_bitmap_cleanup_count();
            snapshots.push(InstanceRuntimeHealthSnapshot {
                name,
                active: true,
                acl_ready: state.runtime_health.acl_ready,
                xdp_ready: state.runtime_health.xdp_ready,
                readiness_reason: state.runtime_health.readiness_reason(),
                cleanup_pending_count,
                maintenance_reason: local_projection_maintenance_reason(
                    &state.state,
                    cleanup_pending_count,
                ),
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
        committed_projection_state: Option<&FirewallState>,
        standalone_shadow_entries: Option<&RuntimeGroupMapEntries>,
        require_tc_acl_links: bool,
        clean_semantic_mutations: Vec<SharedNetworkMutation>,
        current_acl_bank: u8,
        next_acl_bank: u8,
        new_port_sets_by_key: &BTreeMap<OwnedAclPolicyKey, bool>,
        created_port_sets: &[TransactionCreatedPortSet],
        released_port_sets: &BTreeMap<u32, String>,
        report: &mut OwnedAclReconcileReport,
        publication_receipts: Option<&mut Vec<ManagedAclPublicationReceipt>>,
    ) -> Result<bool, ControlPlaneError> {
        let runtime_pin_path = state.pin_path.clone();
        let runtime_tap_id = state.tap_id;
        let runtime = TapMapRuntime::new(&runtime_pin_path, runtime_tap_id);

        let projection_drift = proposed_projection.plan_managed_pinned_projection(
            runtime,
            committed_projection_state.unwrap_or(old_state),
        );
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
        for (bitmap_idx, ports_normalized) in released_port_sets {
            durable_final_state
                .quarantine_bitmap_cleanup(*bitmap_idx, ports_normalized.clone())
                .map_err(ControlPlaneError::ValidationError)?;
        }

        let mut durable_final_state = Some(durable_final_state);
        let mut applied_shared_mutations = Vec::new();
        let mut bank_committed = false;
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
                    let stage_result = match standalone_shadow_entries {
                        Some(entries) => Self::stage_standalone_acl_shadow_bank(
                            final_state,
                            entries,
                            runtime,
                            next_acl_bank,
                            &self.ebpf_path,
                        ),
                        None => Self::stage_acl_shadow_bank(
                            final_state,
                            proposed_projection,
                            runtime,
                            next_acl_bank,
                            &self.ebpf_path,
                            new_port_sets_by_key,
                        ),
                    };
                    if let Err(error) = stage_result {
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
                ManagedAclPublicationStep::Persist => {
                    let compact_started = Instant::now();
                    let durable_final_state = durable_final_state
                        .take()
                        .expect("publication plan contains exactly one persistence step");
                    if let Err(error) = state.compact_and_publish_state(durable_final_state).await {
                        return Err(rollback_owned_acl_after_durable_commit(
                            ControlPlaneError::PersistenceError(format!(
                                "owned ACL persistence failed: {}",
                                error
                            )),
                            &applied_shared_mutations,
                            ManagedAclPublicationFailurePhase::Persist,
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
                    report.compact_ms = compact_started.elapsed().as_millis();
                }
                ManagedAclPublicationStep::AdvanceFragmentEpoch => {
                    if let Err(error) = execute_fragment_epoch_bank_publication(
                        &mut || {
                            advance_fragment_epoch_action(
                                &runtime_pin_path,
                                runtime_tap_id,
                            )
                            .map_err(|error| {
                                format!(
                                    "advance managed fragment publication epoch: {}",
                                    error
                                )
                            })
                        },
                        &mut || {
                            aria_core::ebpf_ops::set_acl_active_bank(runtime, next_acl_bank)
                        },
                    ) {
                        let failure_phase = match error.phase() {
                            FragmentEpochPublicationFailurePhase::Readiness
                            | FragmentEpochPublicationFailurePhase::AdvanceEpoch => {
                                ManagedAclPublicationFailurePhase::AdvanceFragmentEpoch
                            }
                            FragmentEpochPublicationFailurePhase::Publish => {
                                ManagedAclPublicationFailurePhase::SwitchBank
                            }
                        };
                        return Err(rollback_owned_acl_after_durable_commit(
                            ControlPlaneError::KernelError(error.to_string()),
                            &applied_shared_mutations,
                            failure_phase,
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
                    bank_committed = true;
                }
                ManagedAclPublicationStep::SwitchBank => {
                    debug_assert!(bank_committed, "bank switch must be fenced by fragment epoch");
                }
            }
        }

        if let Some(receipts) = publication_receipts {
            receipts.extend(
                applied_shared_mutations
                    .iter()
                    .cloned()
                    .map(ManagedAclPublicationReceipt::General),
            );
            receipts.push(ManagedAclPublicationReceipt::ActiveBank {
                previous_bank: current_acl_bank,
                published_bank: next_acl_bank,
            });
        }

        Ok(true)
    }

    // ── Groups ──

    async fn replace_owned_acl_locked(
        &self,
        instance: &str,
        state: &mut InstanceState,
        owner_prefix: &str,
        exclusive_policy_domain: bool,
        groups: &[OwnedAclGroupSpec],
        policies: &[OwnedAclPolicySpec],
        require_tc_acl_links: bool,
    ) -> Result<(OwnedAclReconcileReport, Option<ManagedOwnedAclRollbackContext>), ControlPlaneError> {
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
                    policy.ip_family,
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
                        && rule.ip_family == policy.ip_family
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
                    rule.ip_family,
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
        let mut receipts = Vec::new();
        let publication_performed = self
            .publish_acl_projection_locked(
                instance,
                state,
                &old_state,
                &final_state,
                &proposed_projection,
                semantic_changed,
                None,
                None,
                require_tc_acl_links,
                clean_semantic_mutations,
                current_acl_bank,
                next_acl_bank,
                &new_port_sets_by_key,
                &created_port_sets,
                &released_port_sets,
                &mut report,
                Some(&mut receipts),
            )
            .await?;
        if !publication_performed {
            state.managed_projection_health = previous_projection_health;
            return Ok((report, None));
        }
        Ok((
            report,
            Some(ManagedOwnedAclRollbackContext {
                receipts,
                old_state,
                created_port_sets,
            }),
        ))
    }

    async fn complete_owned_acl_publication_locked(
        &self,
        state: &mut InstanceState,
        rollback: &ManagedOwnedAclRollbackContext,
    ) -> Result<(), ControlPlaneError> {
        let runtime_pin_path = state.pin_path.clone();
        let runtime = TapMapRuntime::new(&runtime_pin_path, state.tap_id);
        let released = pending_bitmap_cleanup_port_sets(&state.state);
        let released_cleanup = cleanup_port_sets(&released, runtime, &self.ebpf_path, "released");
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

        if let Ok(active_bank) = aria_core::ebpf_ops::read_acl_active_bank(runtime) {
            let previous_bank = aria_core::common::acl_next_bank(active_bank);
            if let Err(error) = aria_core::ebpf_ops::scrub_acl_bank(runtime, previous_bank) {
                warn!(error = %error, bank = previous_bank,
                    "failed to scrub previous ACL shadow bank after owned publication");
            }
        }

        for rule in rollback.old_state.rules.iter().filter(|old_rule| {
            !state.state.rules.iter().any(|current_rule| {
                current_rule.src_group_id == old_rule.src_group_id
                    && current_rule.dst_group_id == old_rule.dst_group_id
                    && current_rule.proto == old_rule.proto
                    && current_rule.direction == old_rule.direction
                    && current_rule.ip_family == old_rule.ip_family
            })
        }) {
            if let Err(error) = aria_core::monitoring::clear_rule_stats_for_policy(
                runtime,
                rule.src_group_id,
                rule.dst_group_id,
                rule.proto,
                rule.direction,
                rule.ip_family,
            ) {
                warn!(error = %error, "failed to clear rule stats after owned ACL diff delete");
            }
        }
        for group in rollback.old_state.groups.values().filter(|old_group| {
            !state.state.groups.values().any(|current_group| current_group.id == old_group.id)
        }) {
            if let Err(error) = aria_core::monitoring::clear_group_stats_for_id(runtime, group.id) {
                warn!(error = %error, group_id = group.id,
                    "failed to clear group stats after owned ACL diff delete");
            }
        }
        Ok(())
    }

    async fn rollback_owned_acl_after_strict_flush_locked(
        &self,
        state: &mut InstanceState,
        rollback: &ManagedOwnedAclRollbackContext,
        flush_error: String,
    ) -> ControlPlaneError {
        state.managed_projection_health = ManagedProjectionHealth::Unverified;
        let runtime_pin_path = state.pin_path.clone();
        let runtime = TapMapRuntime::new(&runtime_pin_path, state.tap_id);
        let mut errors = vec![flush_error];
        for receipt in rollback.receipts.iter().rev() {
            if let Err(error) = compensate_managed_acl_publication(
                receipt,
                runtime,
                &self.ebpf_path,
            ) {
                errors.push(error);
            }
        }
        let cleanup = cleanup_transaction_created_port_sets(
            &rollback.created_port_sets,
            runtime,
            &self.ebpf_path,
        );
        errors.extend(cleanup.failures.iter().map(|failure| failure.error.clone()));
        if let Err(error) = restore_durable_old_state_after_failed_persistence(
            state,
            &rollback.old_state,
            &cleanup,
        )
        .await
        {
            errors.push(error);
        }
        ControlPlaneError::KernelError(errors.join("; "))
    }

    pub async fn replace_owned_acl_and_flush(
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
        let (report, rollback) = self
            .replace_owned_acl_locked(
                instance,
                &mut state,
                owner_prefix,
                exclusive_policy_domain,
                groups,
                policies,
                require_tc_acl_links,
            )
            .await?;
        let Some(rollback) = rollback else {
            // A semantically clean owned reconcile still closes the CT epoch.
            // It has no publication preimages to restore, but it must not let
            // an empty Neutron purge report success and detach with stale CT.
            state.managed_projection_health = ManagedProjectionHealth::Unverified;
            let runtime_pin_path = state.pin_path.clone();
            let runtime = TapMapRuntime::new(&runtime_pin_path, state.tap_id);
            execute_managed_owned_acl_publication_transaction(
                |_| {},
                || std::future::ready(Ok::<Vec<ManagedAclPublicationReceipt>, String>(Vec::new())),
                || {
                    std::future::ready(
                        aria_core::ct_ops::scrub_ct_tables_strict(runtime)
                            .map(|_| ())
                            .map_err(|error| {
                                format!("strict managed owned ACL CT flush: {}", error)
                            }),
                    )
                },
                |_| std::future::ready(Ok::<(), String>(())),
                || std::future::ready(Ok::<(), String>(())),
            )
            .await
            .map_err(ControlPlaneError::KernelError)?;
            return Ok(report);
        };
        if let Err(error) = aria_core::ct_ops::scrub_ct_tables_strict(state.map_runtime()) {
            return Err(
                self.rollback_owned_acl_after_strict_flush_locked(
                    &mut state,
                    &rollback,
                    format!("strict managed owned ACL CT flush: {}", error),
                )
                .await,
            );
        }
        self.complete_owned_acl_publication_locked(&mut state, &rollback)
            .await?;
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

    async fn execute_local_projection_publication_locked(
        &self,
        instance: &str,
        state: &mut InstanceState,
        domain: LocalWriteDomain,
        old_state: FirewallState,
        final_state: FirewallState,
        operations: Vec<ManagedLocalProjectionOperation>,
    ) -> Result<(), ControlPlaneError> {
        local_projection_recovery_admission(&state.state, domain)?;
        let runtime = self.managed_local_projection_runtime(instance, state);
        let apply_projection_operation =
            managed_local_projection_apply(runtime.clone(), &old_state);
        let compensate_projection_receipt = managed_local_projection_compensate(runtime);
        let persist_final_state = managed_local_projection_persist(&state.wal, &final_state)?;
        let restore_old_state = managed_local_projection_restore(&state.wal, &old_state)?;
        let result = execute_managed_local_projection_transaction(
            &operations,
            |health| state.managed_projection_health = health,
            apply_projection_operation,
            persist_final_state,
            compensate_projection_receipt,
            restore_old_state,
        )
        .await;

        match result {
            Ok(()) => {
                state.state = final_state;
                Ok(())
            }
            Err(failure) if failure.recovery_required() => {
                Err(state.persist_local_projection_recovery(domain, failure).await)
            }
            Err(failure) => Err(failure.into_control_plane_error()),
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
        let inst = self.get_instance(instance).await?;
        let mut state = inst.write().await;
        let authority = self.neutron_authorities.read().await.get(instance).cloned();
        ensure_serialized_local_group_write_allowed(
            instance,
            name,
            Some(state.managed_acl_publication_mode),
            authority.as_ref(),
        )?;
        let owner_prefix = authority
            .as_ref()
            .map(|authority| format!("neutron:{}:", authority.port_id));
        match state.managed_acl_publication_mode {
            ManagedAclPublicationMode::StandaloneCompatibility
            | ManagedAclPublicationMode::NeutronAttachOwnedStandaloneAcl => {
                if let Some(group) = state.state.groups.get(name) {
                    let referenced =
                        state.state.rules.iter().any(|rule| {
                            rule.src_group_id == group.id || rule.dst_group_id == group.id
                        });
                    if referenced && !group.cidrs.iter().any(|existing| existing == cidr) {
                        let group_id = group.id;
                        let plan = self
                            .apply_standalone_acl_mutations_locked(
                                instance,
                                &mut state,
                                &[StandaloneAclMutation::AddReferencedGroupCidr {
                                    group_name: name.to_string(),
                                    cidr: cidr.to_string(),
                                }],
                            )
                            .await?;
                        if plan.accepted == 0 {
                            return Err(ControlPlaneError::ValidationError(plan.errors.join("; ")));
                        }
                        return Ok(group_id);
                    }
                }
                return self
                    .add_group_standalone_locked(instance, &mut state, name, cidr)
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
        let inst = self.get_instance(instance).await?;
        let mut state = inst.write().await;
        let authority = self.neutron_authorities.read().await.get(instance).cloned();
        ensure_serialized_local_group_write_allowed(
            instance,
            name,
            Some(state.managed_acl_publication_mode),
            authority.as_ref(),
        )?;
        let owner_prefix = authority
            .as_ref()
            .map(|authority| format!("neutron:{}:", authority.port_id));
        self.delete_group_locked(instance, &mut state, name, owner_prefix)
            .await
    }

    async fn delete_group_locked(
        &self,
        instance: &str,
        state: &mut InstanceState,
        name: &str,
        owner_prefix: Option<String>,
    ) -> Result<(), ControlPlaneError> {
        match state.managed_acl_publication_mode {
            ManagedAclPublicationMode::StandaloneCompatibility
            | ManagedAclPublicationMode::NeutronAttachOwnedStandaloneAcl => {
                return self
                    .delete_group_standalone_locked(instance, state, name)
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
        let runtime = self.managed_local_projection_runtime(instance, state);
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

    pub async fn add_policy_family_protocols(
        &self,
        instance: &str,
        src_group: &str,
        dst_group: &str,
        action: u8,
        direction: u8,
        ports: Option<&str>,
        family_protocols: &[(u8, u8)],
    ) -> Result<Vec<StandaloneCleanupPending>, ControlPlaneError> {
        let _lifecycle_guard = self.lock_runtime_lifecycle().await;
        let inst = self.get_instance(instance).await?;
        let mut state = inst.write().await;
        let authority = self.neutron_authorities.read().await.get(instance).cloned();
        ensure_serialized_local_write_allowed(
            instance,
            LocalWriteDomain::Acl,
            Some(state.managed_acl_publication_mode),
            authority.as_ref(),
        )?;
        Self::check_runtime_maps_ready(&state.pin_path)?;
        self.resolve_group_id(&state.state, src_group)?;
        self.resolve_group_id(&state.state, dst_group)?;
        Self::requested_directions(direction)?;
        let plan = self
            .apply_standalone_acl_mutations_locked(
                instance,
                &mut state,
                &[StandaloneAclMutation::UpsertPolicyFamilyProtocols {
                    src_group: src_group.to_string(),
                    dst_group: dst_group.to_string(),
                    action,
                    direction,
                    ports: ports.map(str::to_string),
                    family_protocols: family_protocols.to_vec(),
                }],
            )
            .await?;
        if plan.accepted == 0 {
            return Err(ControlPlaneError::ValidationError(plan.errors.join("; ")));
        }
        Ok(plan.cleanup_pending)
    }

    pub async fn batch_add_policies(
        &self,
        instance: &str,
        items: Vec<StandaloneAclBatchItem>,
    ) -> Result<(usize, Vec<String>, Vec<StandaloneCleanupPending>), ControlPlaneError> {
        let _lifecycle_guard = self.lock_runtime_lifecycle().await;
        let inst = self.get_instance(instance).await?;
        let mut state = inst.write().await;
        let authority = self.neutron_authorities.read().await.get(instance).cloned();
        ensure_serialized_local_write_allowed(
            instance,
            LocalWriteDomain::Acl,
            Some(state.managed_acl_publication_mode),
            authority.as_ref(),
        )?;
        let plan = self
            .apply_standalone_acl_batch_locked(instance, &mut state, &items)
            .await?;
        Ok((plan.accepted, plan.errors, plan.cleanup_pending))
    }

    pub async fn delete_policy_family_protocols(
        &self,
        instance: &str,
        src_group: &str,
        dst_group: &str,
        direction: u8,
        family_protocols: &[(u8, u8)],
    ) -> Result<Vec<StandaloneCleanupPending>, ControlPlaneError> {
        let _lifecycle_guard = self.lock_runtime_lifecycle().await;
        let inst = self.get_instance(instance).await?;
        let mut state = inst.write().await;
        let authority = self.neutron_authorities.read().await.get(instance).cloned();
        ensure_serialized_local_write_allowed(
            instance,
            LocalWriteDomain::Acl,
            Some(state.managed_acl_publication_mode),
            authority.as_ref(),
        )?;
        Self::check_runtime_maps_ready(&state.pin_path)?;
        self.resolve_group_id(&state.state, src_group)?;
        self.resolve_group_id(&state.state, dst_group)?;
        Self::requested_directions(direction)?;
        let plan = self
            .apply_standalone_acl_mutations_locked(
                instance,
                &mut state,
                &[StandaloneAclMutation::DeletePolicyFamilyProtocols {
                    src_group: src_group.to_string(),
                    dst_group: dst_group.to_string(),
                    direction,
                    family_protocols: family_protocols.to_vec(),
                }],
            )
            .await?;
        if plan.accepted == 0 {
            return Err(ControlPlaneError::PolicyNotFound(plan.errors.join("; ")));
        }
        Ok(plan.cleanup_pending)
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
        local_projection_recovery_admission(&state.state, LocalWriteDomain::Qos)?;
        let is_managed = state.managed_acl_publication_mode == ManagedAclPublicationMode::ManagedAcl;
        if is_managed {
            managed_local_projection_admission(
                state.managed_acl_publication_mode,
                state.managed_projection_health,
            )?;
            let _owner_prefix =
                Self::require_managed_local_owner_prefix(instance, owner_prefix)?;
        }
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
        let general_mutations = if is_managed {
            managed_general_state_mutations(&old_state, &final_state)?
        } else {
            Vec::new()
        };
        let projection_order = ManagedLocalProjectionOrder::GeneralThenDomain;
        let operations = merge_managed_local_projection_operations(
            projection_order,
            general_mutations,
            domain_operations,
        );
        self.execute_local_projection_publication_locked(
            instance,
            &mut state,
            LocalWriteDomain::Qos,
            old_state,
            final_state,
            operations,
        )
        .await?;
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
        local_projection_recovery_admission(&state.state, LocalWriteDomain::Qos)?;
        let is_managed = state.managed_acl_publication_mode == ManagedAclPublicationMode::ManagedAcl;
        let owner_prefix = if is_managed {
            managed_local_projection_admission(
                state.managed_acl_publication_mode,
                state.managed_projection_health,
            )?;
            Some(Self::require_managed_local_owner_prefix(instance, owner_prefix)?)
        } else {
            None
        };
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
        let removed_retained_group_ids = if let Some(owner_prefix) = owner_prefix.as_deref() {
            reconcile_retained_owned_groups(&old_state, &mut final_state, owner_prefix)?
        } else {
            Vec::new()
        };
        let general_mutations = if is_managed {
            managed_general_state_mutations(&old_state, &final_state)?
        } else {
            Vec::new()
        };
        let projection_order = ManagedLocalProjectionOrder::DomainThenGeneral;
        let operations = merge_managed_local_projection_operations(
            projection_order,
            general_mutations,
            domain_operations,
        );
        self.execute_local_projection_publication_locked(
            instance,
            &mut state,
            LocalWriteDomain::Qos,
            old_state,
            final_state,
            operations,
        )
        .await?;
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
        local_projection_recovery_admission(&state.state, LocalWriteDomain::Mirror)?;
        let is_managed = state.managed_acl_publication_mode == ManagedAclPublicationMode::ManagedAcl;
        if is_managed {
            managed_local_projection_admission(
                state.managed_acl_publication_mode,
                state.managed_projection_health,
            )?;
            let _owner_prefix =
                Self::require_managed_local_owner_prefix(instance, owner_prefix)?;
        }
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
        let general_mutations = if is_managed {
            managed_general_state_mutations(&old_state, &final_state)?
        } else {
            Vec::new()
        };
        let projection_order = ManagedLocalProjectionOrder::GeneralThenDomain;
        let operations = merge_managed_local_projection_operations(
            projection_order,
            general_mutations,
            domain_operations,
        );
        self.execute_local_projection_publication_locked(
            instance,
            &mut state,
            LocalWriteDomain::Mirror,
            old_state,
            final_state,
            operations,
        )
        .await?;
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
        local_projection_recovery_admission(&state.state, LocalWriteDomain::Mirror)?;
        let is_managed = state.managed_acl_publication_mode == ManagedAclPublicationMode::ManagedAcl;
        let owner_prefix = if is_managed {
            managed_local_projection_admission(
                state.managed_acl_publication_mode,
                state.managed_projection_health,
            )?;
            Some(Self::require_managed_local_owner_prefix(instance, owner_prefix)?)
        } else {
            None
        };
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
        let removed_retained_group_ids = if let Some(owner_prefix) = owner_prefix.as_deref() {
            reconcile_retained_owned_groups(&old_state, &mut final_state, owner_prefix)?
        } else {
            Vec::new()
        };
        let general_mutations = if is_managed {
            managed_general_state_mutations(&old_state, &final_state)?
        } else {
            Vec::new()
        };
        let projection_order = ManagedLocalProjectionOrder::DomainThenGeneral;
        let operations = merge_managed_local_projection_operations(
            projection_order,
            general_mutations,
            domain_operations,
        );
        self.execute_local_projection_publication_locked(
            instance,
            &mut state,
            LocalWriteDomain::Mirror,
            old_state,
            final_state,
            operations,
        )
        .await?;
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
        let _lifecycle_guard = self.lock_runtime_lifecycle().await;
        let inst = self.get_instance(instance).await?;
        let state = inst.read().await;
        let authority = self.neutron_authorities.read().await.get(instance).cloned();
        ensure_serialized_local_write_allowed(
            instance,
            LocalWriteDomain::Conntrack,
            Some(state.managed_acl_publication_mode),
            authority.as_ref(),
        )?;
        aria_core::ct_ops::ct_flush(state.map_runtime())
            .map_err(|e| ControlPlaneError::KernelError(e))
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
        let actual_gate = aria_core::ebpf_ops::read_runtime_config(state.map_runtime())
            .map_err(ControlPlaneError::KernelError)?;
        let gate_steps = managed_acl_gate_publication_steps_from_live(
            actual_gate.conntrack_enabled != 0,
            actual_gate.acl_enabled != 0,
            state.state.conntrack_enabled,
            state.state.acl_enabled,
            conntrack_enabled,
            acl_enabled,
            allow_recovery_publication,
        );
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
        if gate_steps.is_empty() {
            return Ok(());
        }

        let publish_gate = gate_steps.contains(&ManagedAclGatePublicationStep::PublishGate);
        let persist = gate_steps.contains(&ManagedAclGatePublicationStep::Persist);
        let pin_path = state.pin_path.clone();
        let tap_id = state.tap_id;
        execute_guarded_fragment_epoch_gate_transition(
            neutron_acl_gate_requires_tc(conntrack_enabled, acl_enabled),
            FragmentEpochGateTransition::SemanticChange,
            &mut || {
                require_fragment_runtime_ready(
                    self.fragment_tracking,
                    &pin_path,
                    tap_id,
                    conntrack_enabled,
                    acl_enabled,
                )
            },
            &mut || {
                advance_fragment_epoch_action(&pin_path, tap_id)
                    .map_err(|error| format!("advance managed gate fragment epoch: {}", error))
            },
            &mut || {
                if publish_gate {
                    aria_core::ebpf_ops::update_acl_runtime_gate(
                        TapMapRuntime::new(&pin_path, tap_id),
                        conntrack_enabled,
                        acl_enabled,
                        aria_core::common::ACL_INGRESS_HOOK_TC,
                    )
                } else {
                    Ok(())
                }
            },
        )
        .map_err(|error| ControlPlaneError::KernelError(error.to_string()))?;

        if publish_gate {
            state.managed_projection_health = managed_projection_health_before_runtime_gate_write(
                state.managed_acl_publication_mode,
                state.managed_projection_health,
            );
        }

        if persist {
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
                let readiness_result = verify_acl_gate_before_readiness(
                    conntrack_enabled,
                    acl_enabled,
                    &mut || {
                        aria_core::ebpf_ops::read_runtime_config(state.map_runtime())
                            .map(|actual| {
                                (
                                    actual.conntrack_enabled != 0,
                                    actual.acl_enabled != 0,
                                )
                            })
                            .map_err(|error| {
                                format!("read managed recovery runtime gate: {}", error)
                            })
                    },
                )
                .map_err(ControlPlaneError::KernelError)
                .and_then(|_| {
                    let xdp_ready = self.runtime_xdp_health_locked(instance, &state);
                    Self::mark_tc_acl_runtime_ready_locked(
                        instance,
                        &mut state,
                        xdp_ready,
                        self.trace_map_mode(),
                    )
                });
                if let Err(readiness_error) = readiness_result {
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
        let publication_mode = {
            let state = inst.read().await;
            state.managed_acl_publication_mode
        };
        let authority = self.neutron_authorities.read().await.get(instance).cloned();
        let requested_domains = requested_local_config_write_domains(
            conntrack, monitoring, acl, qos, mirror, tcprt, ssl,
        );
        for domain in requested_domains {
            ensure_serialized_local_write_allowed(
                instance,
                domain,
                Some(publication_mode),
                authority.as_ref(),
            )?;
        }
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
        let gate_transition = read_pinned_acl_ct_gate_transition(
            state.map_runtime(),
            conntrack,
            acl,
        )
        .map_err(|error| {
            ControlPlaneError::KernelError(format!(
                "read live gate before local config update: {}",
                error
            ))
        })?;
        let next_conntrack = conntrack.unwrap_or(state.state.conntrack_enabled);
        let next_acl = acl.unwrap_or(state.state.acl_enabled);
        if neutron_acl_gate_requires_tc(next_conntrack, next_acl) {
            Self::require_tc_acl_ready_locked(instance, &state, self.trace_map_mode())?;
        }
        let old_state = state.state.clone();
        let attempted_enable = conntrack == Some(true) || acl == Some(true);

        // For QoS, the kernel flag = user_wants_qos && has_rules
        let kernel_qos = qos.map(|q| q && !state.state.qos_rules.is_empty());
        // For mirror, the kernel flag = user_wants_mirror && has_rules
        let kernel_mirror = mirror.map(|m| m && !state.state.mirror_rules.is_empty());

        let pin_path = state.pin_path.clone();
        let tap_id = state.tap_id;
        execute_guarded_fragment_epoch_gate_transition(
            neutron_acl_gate_requires_tc(next_conntrack, next_acl),
            gate_transition,
            &mut || {
                require_fragment_runtime_ready(
                    self.fragment_tracking,
                    &pin_path,
                    tap_id,
                    next_conntrack,
                    next_acl,
                )
            },
            &mut || {
                advance_fragment_epoch_action(&pin_path, tap_id)
                    .map_err(|error| format!("advance local config fragment epoch: {}", error))
            },
            &mut || {
                aria_core::ebpf_ops::update_runtime_config(
                    TapMapRuntime::new(&pin_path, tap_id),
                    conntrack,
                    monitoring,
                    acl,
                    kernel_qos,
                    kernel_mirror,
                    tcprt,
                    None,
                )
            },
        )
        .map_err(|error| ControlPlaneError::KernelError(error.to_string()))?;

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
                        execute_local_config_persistence_gate_rollback(
                            safe_state.conntrack_enabled,
                            safe_state.acl_enabled,
                            &mut || {
                                aria_core::ebpf_ops::read_runtime_config(TapMapRuntime::new(
                                    &pin_path, tap_id,
                                ))
                                .map(|actual| {
                                    (
                                        actual.conntrack_enabled != 0,
                                        actual.acl_enabled != 0,
                                    )
                                })
                                .map_err(|error| {
                                    format!(
                                        "read live gate before local config rollback: {}",
                                        error
                                    )
                                })
                            },
                            &mut || {
                                require_fragment_runtime_ready(
                                    self.fragment_tracking,
                                    &pin_path,
                                    tap_id,
                                    safe_state.conntrack_enabled,
                                    safe_state.acl_enabled,
                                )
                            },
                            &mut || {
                                advance_fragment_epoch_action(&pin_path, tap_id).map_err(|error| {
                                    format!(
                                        "advance local config rollback fragment epoch: {}",
                                        error
                                    )
                                })
                            },
                            &mut |safe_conntrack, safe_acl| {
                                aria_core::ebpf_ops::update_runtime_config(
                                    TapMapRuntime::new(&pin_path, tap_id),
                                    Some(safe_conntrack),
                                    Some(safe_state.monitoring_enabled),
                                    Some(safe_acl),
                                    Some(
                                        safe_state.qos_enabled && !safe_state.qos_rules.is_empty(),
                                    ),
                                    Some(
                                        safe_state.mirror_enabled
                                            && !safe_state.mirror_rules.is_empty(),
                                    ),
                                    Some(safe_state.tcprt_enabled),
                                    None,
                                )
                            },
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
                let tap_id = aria_core::state::StateManager::new(&state_path)
                    .get_tap_id()
                    .map_err(|error| {
                        format!("failed to read managed tap id {}: {}", entry_name, error)
                    })?;
                if tap_id != aria_core::common::TAP_ID_UNASSIGNED {
                    used.insert(tap_id);
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

    #[derive(Clone)]
    struct FakeManagedMaintenanceAuthoritySource {
        configured_pin_path: PathBuf,
        configured_mode: TraceMapMode,
        firewall_config_map_id: u32,
        registered_instance_count: usize,
        runtime_identity: Result<ManagedMaintenanceRuntimeIdentity, String>,
    }

    impl ManagedMaintenanceAuthoritySource for FakeManagedMaintenanceAuthoritySource {
        fn configured_pin_path(&self) -> PathBuf {
            self.configured_pin_path.clone()
        }

        fn configured_mode(&self) -> TraceMapMode {
            self.configured_mode
        }

        fn current_firewall_config_map_id(&self) -> Result<u32, String> {
            Ok(self.firewall_config_map_id)
        }

        fn live_runtime_identity(&self) -> Result<ManagedMaintenanceRuntimeIdentity, String> {
            self.runtime_identity.clone()
        }
    }

    fn maintenance_tc_program(
        id: u32,
        tag: u64,
        map_ids: &[u32],
    ) -> ManagedTcProgramIdentity {
        ManagedTcProgramIdentity {
            id,
            tag,
            map_ids: map_ids.to_vec(),
        }
    }

    fn maintenance_live_runtime_identity(
        ingress_map_ids: &[u32],
        egress_map_ids: &[u32],
    ) -> ManagedMaintenanceRuntimeIdentity {
        ManagedMaintenanceRuntimeIdentity {
            trace_map_mode: TraceMapMode::Stream,
            ingress_program: maintenance_tc_program(701, 0x7010, ingress_map_ids),
            egress_program: maintenance_tc_program(702, 0x7020, egress_map_ids),
            live_owner_count: 1,
            complete_mode_inventory: true,
        }
    }

    fn maintenance_authority_source(
        map_id: u32,
        ingress_map_ids: &[u32],
        egress_map_ids: &[u32],
    ) -> FakeManagedMaintenanceAuthoritySource {
        FakeManagedMaintenanceAuthoritySource {
            configured_pin_path: PathBuf::from("/sys/fs/bpf/aria/global-v2"),
            configured_mode: TraceMapMode::Stream,
            firewall_config_map_id: map_id,
            registered_instance_count: 0,
            runtime_identity: Ok(maintenance_live_runtime_identity(
                ingress_map_ids,
                egress_map_ids,
            )),
        }
    }

    #[test]
    fn maintenance_authority_rejects_canonical_map_replaced_before_mint() {
        let source = maintenance_authority_source(999, &[410, 411], &[410, 412]);
        let error = acquire_managed_maintenance_authority_facts(&source)
            .expect_err("replacement map absent from both live programs must fail closed");
        assert!(error.contains("both live TC programs"));
    }

    #[test]
    fn maintenance_authority_rejects_one_direction_only_map_reference() {
        let source = maintenance_authority_source(410, &[410, 411], &[412]);
        let error = acquire_managed_maintenance_authority_facts(&source)
            .expect_err("one-direction-only FIREWALL_CONFIG reference must fail closed");
        assert!(error.contains("tc_egress"));
    }

    #[test]
    fn maintenance_authority_accepts_pre_reconciliation_live_runtime_without_instances() {
        let source = maintenance_authority_source(410, &[410, 411], &[410, 412]);
        let facts = acquire_managed_maintenance_authority_facts(&source)
            .expect("persisted live runtime authority must not require a registered instance");
        assert_eq!(source.registered_instance_count, 0);
        assert_eq!(facts.firewall_config_map_id, 410);
        assert_eq!(facts.ingress_program.id, 701);
        assert_eq!(facts.egress_program.id, 702);
    }

    #[test]
    fn maintenance_authority_pre_reconciliation_rejects_missing_or_mismatched_live_facts() {
        let mut missing = maintenance_authority_source(410, &[410], &[410]);
        missing.runtime_identity = Err("persisted live runtime is absent".to_string());
        assert!(acquire_managed_maintenance_authority_facts(&missing)
            .unwrap_err()
            .contains("absent"));

        let mut mismatched = maintenance_authority_source(410, &[410], &[410]);
        mismatched.runtime_identity = Ok(ManagedMaintenanceRuntimeIdentity {
            trace_map_mode: TraceMapMode::Legacy,
            ..maintenance_live_runtime_identity(&[410], &[410])
        });
        assert!(acquire_managed_maintenance_authority_facts(&mismatched)
            .unwrap_err()
            .contains("runtime mode"));
    }

    #[test]
    fn maintenance_authority_rejects_current_pin_or_live_owner_replacement() {
        let original = acquire_managed_maintenance_authority_facts(
            &maintenance_authority_source(410, &[410], &[410]),
        )
        .unwrap();
        let mut replaced_owner = maintenance_authority_source(410, &[410], &[410]);
        replaced_owner.runtime_identity = Ok(ManagedMaintenanceRuntimeIdentity {
            ingress_program: maintenance_tc_program(999, 0x9990, &[410]),
            ..maintenance_live_runtime_identity(&[410], &[410])
        });
        let current = acquire_managed_maintenance_authority_facts(&replaced_owner).unwrap();
        assert_ne!(current, original);
    }

    #[test]
    fn maintenance_authority_rejects_mode_metadata_or_inventory_drift() {
        let mut wrong_mode = maintenance_authority_source(410, &[410], &[410]);
        wrong_mode.runtime_identity = Ok(ManagedMaintenanceRuntimeIdentity {
            trace_map_mode: TraceMapMode::Legacy,
            ..maintenance_live_runtime_identity(&[410], &[410])
        });
        assert!(acquire_managed_maintenance_authority_facts(&wrong_mode)
            .unwrap_err()
            .contains("runtime mode"));

        let mut incomplete = maintenance_authority_source(410, &[410], &[410]);
        incomplete.runtime_identity = Ok(ManagedMaintenanceRuntimeIdentity {
            complete_mode_inventory: false,
            ..maintenance_live_runtime_identity(&[410], &[410])
        });
        assert!(acquire_managed_maintenance_authority_facts(&incomplete)
            .unwrap_err()
            .contains("mode-aware inventory"));
    }

    #[test]
    fn neutron_acl_maintenance_gate_has_no_ovs_tc_or_qdisc_lifecycle_side_effects() {
        let source = include_str!("control_plane.rs");
        let setter = source
            .split("pub(crate) async fn set_acl_maintenance_bypass(")
            .nth(1)
            .expect("agent-owned ACL maintenance setter must exist")
            .split("pub async fn")
            .next()
            .unwrap();

        assert!(setter.contains("FIREWALL_CONFIG"));
        for forbidden in [
            "attach_tc_",
            "detach_tc_",
            "ensure_fq_qdisc",
            "setup_fq_qdisc",
            "cleanup_root_qdisc",
            "ovs",
            "OVS",
        ] {
            assert!(
                !setter.contains(forbidden),
                "forbidden lifecycle call: {forbidden}"
            );
        }
    }

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

        ControlPlane::new_with_fragment_tracking(
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
            crate::FragmentTrackingSettings::default(),
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
    fn managed_registration_loads_family_state_before_wal_or_runtime_use() {
        let source = include_str!("control_plane.rs");
        let prepare = source
            .split("pub async fn prepare_managed_registration(")
            .nth(1)
            .unwrap()
            .split("pub async fn commit_managed_registration(")
            .next()
            .unwrap();
        let load = prepare.find("aria_core::wal::load_with_wal").unwrap();
        let existing_compact = prepare.find("st.do_compact().await").unwrap();
        let wal_open = prepare.find("WalClient::open").unwrap();
        let runtime_write = prepare.find("write_tap_config").unwrap();

        assert!(load < existing_compact);
        assert!(load < wal_open);
        assert!(load < runtime_write);
    }

    #[test]
    fn managed_projection_replay_mode_follows_attach_mode() {
        use aria_core::ebpf_ops::{FragmentRuntimeIdentity, GroupProjectionMode};

        let cases = [
            (
                ManagedAttachMode::StandaloneRestoreAfterTcAttach,
                GroupProjectionMode::StandaloneCompatibility,
            ),
            (
                ManagedAttachMode::NeutronResyncRequired { acl_managed: false },
                GroupProjectionMode::StandaloneCompatibility,
            ),
            (
                ManagedAttachMode::NeutronResyncRequired { acl_managed: true },
                GroupProjectionMode::Managed,
            ),
        ];

        for (attach_mode, expected_projection) in cases {
            let route = managed_replay_route(attach_mode);
            assert_eq!(route.fragment_runtime_identity(), FragmentRuntimeIdentity::Managed);
            assert_eq!(route.projection_mode(), expected_projection);
            assert_eq!(
                route.legacy_acl_migration_authority(),
                attach_mode.legacy_acl_migration_authority()
            );
        }
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
    fn incomplete_tc_runtime_accepts_only_an_explicitly_quiesced_gate_for_recovery() {
        assert_eq!(
            classify_preexisting_runtime_gate(
                GroupProjectionMode::StandaloneCompatibility,
                0,
                0,
                1,
                1,
                false,
            ),
            Ok(RuntimeGateDisposition::ManagedQuiesced)
        );
        assert!(classify_preexisting_runtime_gate(
            GroupProjectionMode::StandaloneCompatibility,
            0,
            0,
            1,
            1,
            true,
        )
        .is_err());
    }

    #[test]
    fn quiesced_incomplete_tc_projection_validation_changes_only_gate_expectations() {
        let mut state = FirewallState::default();
        state.tap_id = 42;
        state.monitoring_enabled = true;
        state.qos_enabled = false;
        state.mirror_enabled = false;
        state.tcprt_enabled = true;
        state.ssl_enabled = true;

        let validation_state = preexisting_projection_validation_state(
            &state,
            GroupProjectionMode::StandaloneCompatibility,
            false,
            RuntimeGateDisposition::ManagedQuiesced,
        );

        assert!(!validation_state.conntrack_enabled);
        assert!(!validation_state.acl_enabled);
        assert_eq!(validation_state.tap_id, state.tap_id);
        assert_eq!(validation_state.monitoring_enabled, state.monitoring_enabled);
        assert_eq!(validation_state.qos_enabled, state.qos_enabled);
        assert_eq!(validation_state.mirror_enabled, state.mirror_enabled);
        assert_eq!(validation_state.tcprt_enabled, state.tcprt_enabled);
        assert_eq!(validation_state.ssl_enabled, state.ssl_enabled);
        assert!(state.conntrack_enabled);
        assert!(state.acl_enabled);

        assert!(matches!(
            preexisting_projection_validation_state(
                &state,
                GroupProjectionMode::StandaloneCompatibility,
                true,
                RuntimeGateDisposition::Desired,
            ),
            std::borrow::Cow::Borrowed(_)
        ));
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

    #[test]
    fn managed_projection_attach_repair_demotion_owner_scope_has_reserved_fallback() {
        assert_eq!(
            managed_acl_demotion_owner_prefix(Some("port-1")),
            "neutron:port-1:"
        );
        assert_eq!(
            managed_acl_demotion_owner_prefix(Some(" port-2 ")),
            "neutron:port-2:"
        );
        assert_eq!(managed_acl_demotion_owner_prefix(None), "neutron:");
        assert_eq!(managed_acl_demotion_owner_prefix(Some("   ")), "neutron:");
    }

    #[test]
    fn managed_projection_attach_repair_demotion_quiesces_before_target_build() {
        let events = std::cell::RefCell::new(Vec::new());
        let mut health = ManagedProjectionHealth::Verified;
        quiesce_managed_acl_demotion_before_build(
            ManagedAclPublicationMode::ManagedAcl,
            &mut health,
            || {
                events.borrow_mut().push("quiesce");
                Ok(())
            },
        )
        .expect("pre-build quiesce must succeed");
        assert_eq!(health, ManagedProjectionHealth::Unverified);
        events.borrow_mut().push("build");
        assert_eq!(*events.borrow(), vec!["quiesce", "build"]);

        let mut failed_health = ManagedProjectionHealth::Verified;
        let error = quiesce_managed_acl_demotion_before_build(
            ManagedAclPublicationMode::ManagedAcl,
            &mut failed_health,
            || Err("forced pre-build quiesce failure".to_string()),
        )
        .expect_err("uncertain pre-build gate state must fail closed");
        assert_eq!(error, "forced pre-build quiesce failure");
        assert_eq!(failed_health, ManagedProjectionHealth::Unverified);
    }

    #[test]
    fn managed_projection_attach_repair_verification_requires_clean_inventory() {
        assert_eq!(
            require_clean_managed_projection_inventory(ProjectionDrift::Clean),
            Ok(())
        );

        let repair_error = require_clean_managed_projection_inventory(
            ProjectionDrift::RepairRequired(aria_core::ebpf_ops::ProjectionRepairPlan {
                general_mutations: Vec::new(),
            }),
        )
        .expect_err("repairable drift must not be marked Verified");
        assert!(repair_error.contains("requires projection repair"));

        let fatal_error = require_clean_managed_projection_inventory(ProjectionDrift::Fatal(
            "acl ingress hook is not TC".to_string(),
        ))
        .expect_err("fatal inventory drift must not be marked Verified");
        assert!(fatal_error.contains("acl ingress hook is not TC"));
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
            let projection_mode = managed_replay_route(mode).projection_mode();
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
            .apply_add_rule(
                30,
                31,
                libc::IPPROTO_TCP as u8,
                1,
                Some("443"),
                0,
                IP_FAMILY_V4,
            )
            .expect("owned ACL port policy must materialize")
            .bitmap_idx
            .expect("port policy must allocate a bitmap");
        old_state
            .apply_add_rule(40, 0, libc::IPPROTO_UDP as u8, 0, None, 1, IP_FAMILY_V4)
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

    #[test]
    fn managed_projection_attach_repair_demotion_rejects_canonical_alias() {
        let mut old_state = FirewallState::default();
        managed_cross_domain_insert_group(
            &mut old_state,
            "local-alias-a",
            40,
            &["198.51.100.1/24"],
        );
        managed_cross_domain_insert_group(
            &mut old_state,
            "local-alias-b",
            41,
            &["198.51.100.2/24"],
        );

        let error = build_managed_acl_demotion_target(&old_state, "neutron:port-1:")
            .expect_err("one standalone LPM key cannot represent two group IDs");
        assert!(error.contains("general_src"), "{error}");
        assert!(error.contains("198.51.100.0/24"), "{error}");
        assert!(error.contains("[40, 41]"), "{error}");
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
    fn managed_projection_outer_skip_runtime_gate_writes_invalidate_prior_verified_health() {
        assert_eq!(
            managed_projection_health_before_runtime_gate_write(
                ManagedAclPublicationMode::ManagedAcl,
                ManagedProjectionHealth::Verified,
            ),
            ManagedProjectionHealth::Unverified
        );
        assert_eq!(
            managed_projection_health_before_runtime_gate_write(
                ManagedAclPublicationMode::ManagedAcl,
                ManagedProjectionHealth::RepairRequired,
            ),
            ManagedProjectionHealth::Unverified
        );
        assert_eq!(
            managed_projection_health_before_runtime_gate_write(
                ManagedAclPublicationMode::NeutronAttachOwnedStandaloneAcl,
                ManagedProjectionHealth::Verified,
            ),
            ManagedProjectionHealth::Verified
        );
        assert_eq!(
            managed_projection_health_before_runtime_gate_write(
                ManagedAclPublicationMode::StandaloneCompatibility,
                ManagedProjectionHealth::RepairRequired,
            ),
            ManagedProjectionHealth::RepairRequired
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

    #[tokio::test]
    async fn fragment_loader_local_disable_persistence_rollback_failure_persists_fail_closed() {
        let mut state = stopped_wal_instance_state("local-config-disable-rollback").await;
        let mut old_state = FirewallState::default();
        old_state.conntrack_enabled = true;
        old_state.acl_enabled = true;
        state.state = old_state.clone();
        state.state.conntrack_enabled = false;
        state.state.acl_enabled = false;

        let error = state
            .recover_local_config_persistence_failure(
                old_state,
                false,
                "forced disabling persistence failure",
                |restore_state| {
                    assert!(restore_state.conntrack_enabled);
                    assert!(restore_state.acl_enabled);
                    Err("forced guarded rollback failure".to_string())
                },
            )
            .await;

        assert!(!state.state.conntrack_enabled);
        assert!(!state.state.acl_enabled);
        assert!(error
            .to_string()
            .contains("forced disabling persistence failure"));
        assert!(error
            .to_string()
            .contains("forced guarded rollback failure"));
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
            .apply_add_rule(
                1,
                2,
                libc::IPPROTO_TCP as u8,
                1,
                Some("80"),
                0,
                IP_FAMILY_V4,
            )
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
            .apply_add_rule(
                1,
                2,
                libc::IPPROTO_TCP as u8,
                1,
                Some("443"),
                0,
                IP_FAMILY_V4,
            )
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
            .apply_add_rule(
                1,
                2,
                libc::IPPROTO_TCP as u8,
                1,
                Some("8443"),
                0,
                IP_FAMILY_V4,
            )
            .unwrap();
        let second_retry = restarted
            .apply_add_rule(
                3,
                4,
                libc::IPPROTO_TCP as u8,
                1,
                Some("9443"),
                0,
                IP_FAMILY_V4,
            )
            .unwrap();

        assert_eq!(cleanup.failures[0].bitmap_idx, 7);
        assert!(restarted.is_bitmap_index_quarantined(7));
        assert_eq!(first_retry.bitmap_idx, Some(8));
        assert_eq!(second_retry.bitmap_idx, Some(9));
    }

    #[test]
    fn standalone_review_cleanup_failure_is_a_committed_pending_outcome() {
        let cleanup = PortSetCleanupReport {
            cleaned_bitmap_indices: Vec::new(),
            failures: vec![PortSetCleanupFailure {
                bitmap_idx: 7,
                ports_normalized: "80:1".to_string(),
                error: "forced retired bitmap cleanup failure".to_string(),
            }],
        };

        let outcome = standalone_cleanup_outcome(&cleanup);

        assert!(outcome.committed);
        assert_eq!(outcome.cleanup_pending.len(), 1);
        assert_eq!(outcome.cleanup_pending[0].bitmap_idx, 7);
        assert_eq!(outcome.cleanup_pending[0].ports_normalized, "80:1");
        assert!(outcome.cleanup_pending[0]
            .error
            .contains("forced retired bitmap cleanup failure"));
    }

    #[test]
    fn standalone_review_cleanup_outcome_does_not_mix_item_errors() {
        let cleanup = PortSetCleanupReport {
            cleaned_bitmap_indices: vec![8],
            failures: vec![PortSetCleanupFailure {
                bitmap_idx: 7,
                ports_normalized: "80:1".to_string(),
                error: "cleanup pending".to_string(),
            }],
        };

        let outcome = standalone_cleanup_outcome(&cleanup);

        assert!(outcome.committed);
        assert_eq!(outcome.cleanup_pending.len(), 1);
        assert!(outcome.item_errors.is_empty());
    }

    #[test]
    fn standalone_review_pending_cleanup_retry_uses_persisted_exact_target() {
        let mut state = FirewallState::default();
        state
            .quarantine_bitmap_cleanup(7, "80:1".to_string())
            .unwrap();

        let restarted: FirewallState =
            serde_json::from_str(&serde_json::to_string(&state).unwrap()).unwrap();

        assert_eq!(
            pending_bitmap_cleanup_port_sets(&restarted),
            vec![TransactionCreatedPortSet {
                bitmap_idx: 7,
                ports_normalized: "80:1".to_string(),
            }]
        );
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
                ports_normalized: "80:1".to_string(),
                error: "forced rollback cleanup failure".to_string(),
            }],
        };

        let recovered = old_state_with_failed_cleanup_quarantines(&old_state, &cleanup).unwrap();
        let json = serde_json::to_string(&recovered).unwrap();
        let mut restarted: FirewallState = serde_json::from_str(&json).unwrap();
        let first_retry = restarted
            .apply_add_rule(
                1,
                2,
                libc::IPPROTO_TCP as u8,
                1,
                Some("8443"),
                0,
                IP_FAMILY_V4,
            )
            .unwrap();
        let second_retry = restarted
            .apply_add_rule(
                3,
                4,
                libc::IPPROTO_TCP as u8,
                1,
                Some("9443"),
                0,
                IP_FAMILY_V4,
            )
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
            .apply_add_rule(
                1,
                2,
                libc::IPPROTO_TCP as u8,
                1,
                Some("80"),
                0,
                IP_FAMILY_V4,
            )
            .unwrap();
        let released_idx = old_add.bitmap_idx.unwrap();
        assert_eq!(released_idx, 0);

        let mut final_state = old_state.clone();
        let mut released_port_sets = BTreeMap::new();
        let mut runtime_adds = Vec::new();

        // This is the earlier BTreeMap-sorted policy update. It allocates a
        // fresh bitmap and releases the old policy's index.
        let early_update = final_state
            .apply_add_rule(
                1,
                2,
                libc::IPPROTO_TCP as u8,
                1,
                Some("443"),
                0,
                IP_FAMILY_V4,
            )
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
            .apply_add_rule(
                3,
                4,
                libc::IPPROTO_TCP as u8,
                1,
                Some("8443"),
                0,
                IP_FAMILY_V4,
            )
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
            .quarantine_bitmap_cleanup(released_idx, "80:1".to_string())
            .expect("same-index quarantine must be idempotent");
        let cleanup = PortSetCleanupReport {
            cleaned_bitmap_indices: vec![released_idx],
            failures: Vec::new(),
        };
        apply_confirmed_port_set_cleanups(&mut durable_final_state, &cleanup).unwrap();
        let after_cleanup = durable_final_state
            .apply_add_rule(
                5,
                6,
                libc::IPPROTO_TCP as u8,
                1,
                Some("9443"),
                0,
                IP_FAMILY_V4,
            )
            .unwrap();
        assert_eq!(after_cleanup.bitmap_idx, Some(released_idx));
    }

    #[test]
    fn standalone_review_same_diff_normalized_port_dedup_keeps_release_quarantined() {
        let mut final_state = FirewallState::default();
        final_state
            .apply_add_rule(
                1,
                2,
                libc::IPPROTO_TCP as u8,
                1,
                Some("80"),
                0,
                IP_FAMILY_V4,
            )
            .unwrap();
        let early_update = final_state
            .apply_add_rule(
                1,
                2,
                libc::IPPROTO_TCP as u8,
                1,
                Some("443"),
                0,
                IP_FAMILY_V4,
            )
            .unwrap();
        let mut released_port_sets = BTreeMap::new();
        quarantine_owned_acl_released_port_set(
            &mut final_state,
            &mut released_port_sets,
            early_update.old_port_set_released,
        )
        .unwrap();

        let same_ports_later = final_state
            .apply_add_rule(
                3,
                4,
                libc::IPPROTO_TCP as u8,
                1,
                Some("443"),
                0,
                IP_FAMILY_V4,
            )
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
                    IP_FAMILY_V4,
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
                    IP_FAMILY_V4,
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

    async fn install_verified_managed_acl_instance_without_authority(
        cp: &ControlPlane,
        instance: &str,
        test_name: &str,
    ) {
        let mut state = stopped_wal_instance_state(test_name).await;
        state.managed_acl_publication_mode = ManagedAclPublicationMode::ManagedAcl;
        state.managed_projection_health = ManagedProjectionHealth::Verified;
        state.state.groups.insert(
            "policy-src".to_string(),
            GroupInfo {
                id: 41,
                name: "policy-src".to_string(),
                cidrs: vec!["10.41.0.0/24".to_string()],
            },
        );
        state.state.groups.insert(
            "policy-dst".to_string(),
            GroupInfo {
                id: 42,
                name: "policy-dst".to_string(),
                cidrs: vec!["10.42.0.0/24".to_string()],
            },
        );
        state.state.groups.insert(
            "neutron:owned".to_string(),
            GroupInfo {
                id: 43,
                name: "neutron:owned".to_string(),
                cidrs: vec!["10.43.0.0/24".to_string()],
            },
        );
        state.state.groups.insert(
            "neutron:purge-port:src:selector:0".to_string(),
            GroupInfo {
                id: 44,
                name: "neutron:purge-port:src:selector:0".to_string(),
                cidrs: vec!["10.44.0.0/24".to_string()],
            },
        );
        state.state.rules.push(RuleInfo {
            name: None,
            src_group_id: 41,
            dst_group_id: 42,
            proto: libc::IPPROTO_TCP as u8,
            action: 0,
            ports: None,
            bitmap_idx: None,
            direction: 0,
            ip_family: IP_FAMILY_V4,
        });
        cp.instances.write().await.insert(
            instance.to_string(),
            Arc::new(tokio::sync::RwLock::new(state)),
        );

        assert!(
            cp.get_neutron_port_authority(instance).await.is_none(),
            "fixture must exercise the post-promotion/pre-authority window"
        );
    }

    fn assert_local_write_blocked(
        error: ControlPlaneError,
        expected_instance: &str,
        expected_domain: &str,
        expected_dependency: Option<&str>,
    ) {
        assert_eq!(error.status_code(), 409);
        match error {
            ControlPlaneError::LocalWriteBlocked {
                instance,
                domain,
                dependency_of,
            } => {
                assert_eq!(instance, expected_instance);
                assert_eq!(domain, expected_domain);
                assert_eq!(dependency_of.as_deref(), expected_dependency);
            }
            other => panic!("expected LocalWriteBlocked, got: {other}"),
        }
    }

    fn assert_not_local_write_blocked(error: ControlPlaneError, expected_status: u16) {
        assert_eq!(error.status_code(), expected_status);
        assert!(
            !matches!(error, ControlPlaneError::LocalWriteBlocked { .. }),
            "standalone or non-reserved local write must not be authority-blocked"
        );
    }

    #[tokio::test]
    async fn domain_authority_managed_acl_policy_write_add_blocks_before_authority_commit() {
        let cp = test_control_plane();
        let instance = "tap-managed-policy-add-gap";
        self::install_verified_managed_acl_instance_without_authority(
            &cp,
            instance,
            "managed-policy-add-authority-gap",
        )
        .await;

        let add_error = cp
            .add_policy_family_protocols(
                instance,
                "policy-src",
                "policy-dst",
                0,
                0,
                None,
                &[(IP_FAMILY_V4, libc::IPPROTO_TCP as u8)],
            )
            .await
            .expect_err("ManagedAcl must block add_policy before authority commits");
        self::assert_local_write_blocked(add_error, instance, "acl", None);
    }

    #[tokio::test]
    async fn domain_authority_managed_acl_policy_write_delete_blocks_before_authority_commit() {
        let cp = test_control_plane();
        let instance = "tap-managed-policy-delete-gap";
        self::install_verified_managed_acl_instance_without_authority(
            &cp,
            instance,
            "managed-policy-delete-authority-gap",
        )
        .await;

        let delete_error = cp
            .delete_policy_family_protocols(
                instance,
                "policy-src",
                "policy-dst",
                0,
                &[(IP_FAMILY_V4, libc::IPPROTO_TCP as u8)],
            )
            .await
            .expect_err("ManagedAcl must block delete_policy before authority commits");
        self::assert_local_write_blocked(delete_error, instance, "acl", None);
    }

    #[tokio::test]
    async fn domain_authority_managed_acl_config_acl_blocks_before_authority_commit() {
        let cp = test_control_plane();
        let instance = "tap-managed-acl-config-gap";
        self::install_verified_managed_acl_instance_without_authority(
            &cp,
            instance,
            "managed-acl-config-authority-gap",
        )
        .await;

        let error = cp
            .update_config(instance, None, None, Some(false), None, None, None, None)
            .await
            .expect_err("ManagedAcl must block ACL config before authority commits");
        self::assert_local_write_blocked(error, instance, "acl", None);
    }

    #[tokio::test]
    async fn domain_authority_managed_acl_config_conntrack_blocks_before_authority_commit() {
        let cp = test_control_plane();
        let instance = "tap-managed-conntrack-gap";
        self::install_verified_managed_acl_instance_without_authority(
            &cp,
            instance,
            "managed-conntrack-authority-gap",
        )
        .await;

        let error = cp
            .update_config(instance, Some(false), None, None, None, None, None, None)
            .await
            .expect_err("ManagedAcl must protect conntrack as an ACL dependency");
        self::assert_local_write_blocked(error, instance, "conntrack", Some("acl"));
    }

    #[tokio::test]
    async fn domain_authority_managed_acl_public_flush_blocks_before_authority_commit() {
        let cp = test_control_plane();
        let instance = "tap-managed-public-ct-flush-gap";
        self::install_verified_managed_acl_instance_without_authority(
            &cp,
            instance,
            "managed-public-ct-flush-authority-gap",
        )
        .await;

        let error = cp
            .flush_conntrack(instance)
            .await
            .expect_err("ManagedAcl must protect public CT flush as an ACL dependency");
        self::assert_local_write_blocked(error, instance, "conntrack", Some("acl"));
    }

    #[tokio::test]
    async fn domain_authority_standalone_public_flush_preserves_lenient_missing_map_behavior() {
        let cp = test_control_plane();
        let instance = "tap-standalone-public-ct-flush";
        self::install_verified_managed_acl_instance_without_authority(
            &cp,
            instance,
            "standalone-public-ct-flush",
        )
        .await;
        {
            let instance_state = cp.get_instance(instance).await.unwrap();
            let mut state = instance_state.write().await;
            state.managed_acl_publication_mode = ManagedAclPublicationMode::StandaloneCompatibility;
            state.managed_projection_health = ManagedProjectionHealth::Unverified;
        }

        let flushed = cp
            .flush_conntrack(instance)
            .await
            .expect("standalone public CT flush must retain lenient missing-map behavior");
        assert_eq!(flushed, 0);
    }

    #[tokio::test]
    async fn domain_authority_standalone_public_flush_blocks_committed_acl_dependency() {
        let cp = test_control_plane();
        let instance = "tap-standalone-authoritative-ct-flush";
        self::install_verified_managed_acl_instance_without_authority(
            &cp,
            instance,
            "standalone-authoritative-ct-flush",
        )
        .await;
        {
            let instance_state = cp.get_instance(instance).await.unwrap();
            let mut state = instance_state.write().await;
            state.managed_acl_publication_mode = ManagedAclPublicationMode::StandaloneCompatibility;
            state.managed_projection_health = ManagedProjectionHealth::Unverified;
        }
        cp.mark_neutron_port_authority(instance, "port-ct", &["acl".to_string()], 17)
            .await;

        let error = cp
            .flush_conntrack(instance)
            .await
            .expect_err("committed ACL authority must protect its public CT dependency");
        self::assert_local_write_blocked(error, instance, "conntrack", Some("acl"));
    }

    #[tokio::test]
    async fn domain_authority_managed_acl_config_monitoring_remains_local_before_authority_commit()
    {
        let cp = test_control_plane();
        let instance = "tap-managed-monitoring-gap";
        self::install_verified_managed_acl_instance_without_authority(
            &cp,
            instance,
            "managed-monitoring-authority-gap",
        )
        .await;

        let error = cp
            .update_config(instance, None, Some(false), None, None, None, None, None)
            .await
            .expect_err("unmanaged monitoring config must continue to the missing-map boundary");
        self::assert_not_local_write_blocked(error, 503);
    }

    #[tokio::test]
    async fn domain_authority_managed_acl_group_namespace_survives_missing_authority() {
        let cp = test_control_plane();
        let instance = "tap-managed-group-gap";
        self::install_verified_managed_acl_instance_without_authority(
            &cp,
            instance,
            "managed-group-authority-gap",
        )
        .await;

        let add_error = cp
            .add_group(instance, "neutron:new", "10.44.0.0/24")
            .await
            .expect_err("ManagedAcl must reserve neutron: names on add without authority");
        self::assert_local_write_blocked(add_error, instance, "acl", None);

        let delete_error = cp
            .delete_group(instance, "neutron:owned")
            .await
            .expect_err("ManagedAcl must reserve neutron: names on delete without authority");
        self::assert_local_write_blocked(delete_error, instance, "acl", None);
    }

    #[tokio::test]
    async fn domain_authority_standalone_without_authority_preserves_policy_and_config_admission() {
        let cp = test_control_plane();
        let instance = "tap-standalone-authority-none";
        self::install_verified_managed_acl_instance_without_authority(
            &cp,
            instance,
            "standalone-authority-none",
        )
        .await;
        {
            let instance_state = cp.get_instance(instance).await.unwrap();
            let mut state = instance_state.write().await;
            state.managed_acl_publication_mode = ManagedAclPublicationMode::StandaloneCompatibility;
            state.managed_projection_health = ManagedProjectionHealth::Unverified;
        }

        let add_error = cp
            .add_policy_family_protocols(
                instance,
                "policy-src",
                "policy-dst",
                0,
                0,
                None,
                &[(IP_FAMILY_V4, libc::IPPROTO_TCP as u8)],
            )
            .await
            .expect_err("missing maps must remain the first standalone add failure");
        self::assert_not_local_write_blocked(add_error, 503);

        let delete_error = cp
            .delete_policy_family_protocols(
                instance,
                "policy-src",
                "policy-dst",
                0,
                &[(IP_FAMILY_V4, libc::IPPROTO_TCP as u8)],
            )
            .await
            .expect_err("missing maps must remain the first standalone delete failure");
        self::assert_not_local_write_blocked(delete_error, 503);

        let acl_error = cp
            .update_config(instance, None, None, Some(false), None, None, None, None)
            .await
            .expect_err("missing maps must remain the first standalone ACL config failure");
        self::assert_not_local_write_blocked(acl_error, 503);

        let conntrack_error = cp
            .update_config(instance, Some(false), None, None, None, None, None, None)
            .await
            .expect_err("missing maps must remain the first standalone CT config failure");
        self::assert_not_local_write_blocked(conntrack_error, 503);
    }

    #[tokio::test]
    async fn domain_authority_managed_acl_without_authority_allows_non_reserved_group_name() {
        let cp = test_control_plane();
        let instance = "tap-managed-local-group-gap";
        self::install_verified_managed_acl_instance_without_authority(
            &cp,
            instance,
            "managed-local-group-authority-gap",
        )
        .await;

        let error = cp
            .add_group(instance, "local:qos", "10.45.0.0/24")
            .await
            .expect_err("authority absence must preserve the existing managed 503 path");
        self::assert_not_local_write_blocked(error, 503);
    }

    #[tokio::test]
    async fn domain_authority_committed_qos_blocks_config_at_real_entry() {
        let cp = test_control_plane();
        let instance = "tap-managed-qos-authority";
        self::install_verified_managed_acl_instance_without_authority(
            &cp,
            instance,
            "managed-qos-committed-authority",
        )
        .await;
        cp.mark_neutron_port_authority(instance, "port-qos", &["qos".to_string()], 9)
            .await;

        let error = cp
            .update_config(instance, None, None, None, Some(false), None, None, None)
            .await
            .expect_err("committed QoS authority must block the real config entry");
        self::assert_local_write_blocked(error, instance, "qos", None);
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
            ip_family: IP_FAMILY_V4,
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

    #[test]
    fn managed_acl_shadow_ipv6_failure_does_not_complete_atomic_stage() {
        let mut staged_families = Vec::new();
        let mut bank_switched = false;

        let stage_result = execute_acl_family_staging(|family| {
            staged_families.push(family);
            if family == IP_FAMILY_V6 {
                return Err(ControlPlaneError::KernelError(
                    "forced IPv6 staging failure".to_string(),
                ));
            }
            Ok(())
        });
        if stage_result.is_ok() {
            bank_switched = true;
        }

        assert!(stage_result.is_err());
        assert_eq!(staged_families, vec![IP_FAMILY_V4, IP_FAMILY_V6]);
        assert!(!bank_switched, "a partial dual-family stage must not publish");
    }

    fn managed_replacement(direction: &'static str) -> SharedNetworkMutation {
        SharedNetworkMutation::Replaced {
            direction,
            cidr: "10.0.0.0/24".to_string(),
            old_group_id: 41,
            new_group_id: 71,
        }
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
    ) -> (usize, usize, usize, usize) {
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
        let epoch_advances = steps
            .iter()
            .filter(|step| matches!(step, ManagedAclPublicationStep::AdvanceFragmentEpoch))
            .count();
        (general_writes, shadow_stages, epoch_advances, bank_switches)
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
    fn neutron_acl_epoch_failure_is_pre_switch_and_restores_general_preimages() {
        let applied = vec![managed_replacement("src"), managed_replacement("dst")];

        assert_eq!(
            managed_acl_publication_compensations(
                &applied,
                ManagedAclPublicationFailurePhase::AdvanceFragmentEpoch,
            ),
            vec![
                managed_expected_general_restore("dst"),
                managed_expected_general_restore("src")
            ]
        );
    }

    #[test]
    fn managed_general_delta_persistence_failure_restores_only_general_preimages() {
        let applied = vec![managed_replacement("src"), managed_replacement("dst")];

        assert_eq!(
            managed_acl_publication_compensations(
                &applied,
                ManagedAclPublicationFailurePhase::Persist,
            ),
            vec![
                managed_expected_general_restore("dst"),
                managed_expected_general_restore("src")
            ]
        );
    }

    #[test]
    fn managed_general_delta_persists_before_epoch_and_bank_switch() {
        let decision = managed_acl_publication_decision(ProjectionDrift::Clean, true)
            .expect("a semantic ACL change must publish");
        let steps = managed_acl_publication_steps(&decision, Vec::new());
        let persist = steps
            .iter()
            .position(|step| matches!(step, ManagedAclPublicationStep::Persist))
            .expect("managed publication must persist");
        let epoch = steps
            .iter()
            .position(|step| matches!(step, ManagedAclPublicationStep::AdvanceFragmentEpoch))
            .expect("managed publication must advance the fragment epoch");
        let switch = steps
            .iter()
            .position(|step| matches!(step, ManagedAclPublicationStep::SwitchBank))
            .expect("managed publication must switch bank");

        assert_durable_before_bank_publication(persist, epoch, switch);
    }

    #[test]
    fn managed_general_delta_persistence_failure_does_not_restore_unpublished_bank() {
        let compensations = managed_acl_publication_compensations(
            &[managed_replacement("src")],
            ManagedAclPublicationFailurePhase::Persist,
        );

        assert_eq!(
            compensations,
            vec![managed_expected_general_restore("src")]
        );
    }

    #[test]
    fn managed_general_delta_uncertain_bank_switch_failure_restores_old_bank_first() {
        let compensations = managed_acl_publication_compensations(
            &[managed_replacement("src"), managed_replacement("dst")],
            ManagedAclPublicationFailurePhase::SwitchBank,
        );

        assert_eq!(
            compensations,
            vec![
                ManagedAclPublicationCompensation::RestoreActiveBank,
                managed_expected_general_restore("dst"),
                managed_expected_general_restore("src"),
            ]
        );
    }

    async fn run_managed_owned_acl_strict_flush_test(
        fail_bank_restore: bool,
        fail_durable_restore: bool,
    ) -> (
        Result<(), String>,
        Vec<String>,
        ManagedProjectionHealth,
        u8,
    ) {
        const BANK_OLD: u8 = 1 << 0;
        const GENERAL_SRC_OLD: u8 = 1 << 1;
        const GENERAL_DST_OLD: u8 = 1 << 2;
        const DURABLE_OLD: u8 = 1 << 3;

        let events = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
        let health = std::rc::Rc::new(std::cell::Cell::new(ManagedProjectionHealth::Verified));
        let restored_preimages = std::rc::Rc::new(std::cell::Cell::new(
            BANK_OLD | GENERAL_SRC_OLD | GENERAL_DST_OLD | DURABLE_OLD,
        ));
        let health_events = events.clone();
        let health_state = health.clone();
        let publish_events = events.clone();
        let publish_preimages = restored_preimages.clone();
        let flush_events = events.clone();
        let compensation_events = events.clone();
        let compensation_preimages = restored_preimages.clone();
        let restore_events = events.clone();
        let restore_preimages = restored_preimages.clone();

        let result = execute_managed_owned_acl_publication_transaction(
            move |next_health| {
                health_state.set(next_health);
                health_events
                    .borrow_mut()
                    .push(format!("health:{next_health:?}"));
            },
            move || {
                publish_preimages.set(0);
                publish_events.borrow_mut().push("publish".to_string());
                std::future::ready(Ok::<_, String>(vec![
                    ManagedAclDemotionTestReceipt::GeneralSrc,
                    ManagedAclDemotionTestReceipt::GeneralDst,
                    ManagedAclDemotionTestReceipt::ActiveBank,
                ]))
            },
            move || {
                flush_events.borrow_mut().push("strict-flush".to_string());
                std::future::ready(Err::<(), String>(
                    "forced strict flush failure".to_string(),
                ))
            },
            move |receipt: &ManagedAclDemotionTestReceipt| {
                compensation_events
                    .borrow_mut()
                    .push(format!("restore:{}", receipt.label()));
                let bit = match receipt {
                    ManagedAclDemotionTestReceipt::GeneralSrc => GENERAL_SRC_OLD,
                    ManagedAclDemotionTestReceipt::GeneralDst => GENERAL_DST_OLD,
                    ManagedAclDemotionTestReceipt::ActiveBank => BANK_OLD,
                };
                if *receipt == ManagedAclDemotionTestReceipt::ActiveBank && fail_bank_restore {
                    return std::future::ready(Err(
                        "forced active-bank restore failure".to_string(),
                    ));
                }
                compensation_preimages.set(compensation_preimages.get() | bit);
                std::future::ready(Ok(()))
            },
            move || {
                restore_events
                    .borrow_mut()
                    .push("restore:durable".to_string());
                if fail_durable_restore {
                    return std::future::ready(Err(
                        "forced durable restore failure".to_string(),
                    ));
                }
                restore_preimages.set(restore_preimages.get() | DURABLE_OLD);
                std::future::ready(Ok(()))
            },
        )
        .await;

        let observed_events = events.borrow().clone();
        let observed_health = health.get();
        let observed_preimages = restored_preimages.get();
        (result, observed_events, observed_health, observed_preimages)
    }

    #[tokio::test]
    async fn managed_owned_acl_noop_reconcile_still_strictly_flushes_conntrack() {
        // This is the same transaction executor used by the no-op branch of
        // replace_owned_acl_and_flush: no publication receipt exists, but CT
        // scrub remains mandatory and a failure leaves the projection unsafe.
        let events = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
        let health = std::rc::Rc::new(std::cell::Cell::new(ManagedProjectionHealth::Verified));
        let health_events = events.clone();
        let health_state = health.clone();
        let flush_events = events.clone();

        let result = execute_managed_owned_acl_publication_transaction(
            move |next_health| {
                health_state.set(next_health);
                health_events
                    .borrow_mut()
                    .push(format!("health:{next_health:?}"));
            },
            || std::future::ready(Ok::<Vec<ManagedAclPublicationReceipt>, String>(Vec::new())),
            move || {
                flush_events.borrow_mut().push("strict-flush".to_string());
                std::future::ready(Err::<(), String>(
                    "forced no-op strict flush failure".to_string(),
                ))
            },
            |_| std::future::ready(Ok::<(), String>(())),
            || std::future::ready(Ok::<(), String>(())),
        )
        .await;

        let error = result.expect_err("no-op owned reconcile must not skip strict CT flush");
        assert!(error.contains("forced no-op strict flush failure"), "{error}");
        assert_eq!(
            events.borrow().as_slice(),
            ["health:Unverified", "strict-flush"],
        );
        assert_eq!(health.get(), ManagedProjectionHealth::Unverified);
    }

    #[tokio::test]
    async fn managed_owned_acl_strict_flush_failure_restores_old_publication() {
        let (result, events, health, restored_preimages) =
            run_managed_owned_acl_strict_flush_test(false, false).await;
        let error = result.expect_err("strict CT flush failure must roll back publication");

        assert!(error.contains("forced strict flush failure"), "{error}");
        assert_eq!(
            events,
            vec![
                "health:Unverified",
                "publish",
                "strict-flush",
                "restore:active-bank",
                "restore:general-dst",
                "restore:general-src",
                "restore:durable",
            ]
        );
        assert_eq!(health, ManagedProjectionHealth::Unverified);
        assert_eq!(restored_preimages, 0b1111, "every preimage must be old");
    }

    #[tokio::test]
    async fn managed_owned_acl_strict_flush_rollback_failure_stays_unverified() {
        let (result, events, health, restored_preimages) =
            run_managed_owned_acl_strict_flush_test(true, true).await;
        let error = result.expect_err("failed rollback must remain visible");

        assert!(error.contains("forced strict flush failure"), "{error}");
        assert!(
            error.contains("forced active-bank restore failure"),
            "{error}"
        );
        assert!(error.contains("forced durable restore failure"), "{error}");
        assert_eq!(
            events,
            vec![
                "health:Unverified",
                "publish",
                "strict-flush",
                "restore:active-bank",
                "restore:general-dst",
                "restore:general-src",
                "restore:durable",
            ],
            "rollback must attempt every compensation after an earlier failure",
        );
        assert_eq!(health, ManagedProjectionHealth::Unverified);
        assert_eq!(
            restored_preimages, 0b0110,
            "successful general restores remain visible while failed bank/durable restores stay unresolved",
        );
    }

    #[test]
    fn managed_bank_switch_compensation_failure_attempts_every_preimage() {
        let applied = vec![managed_replacement("src"), managed_replacement("dst")];
        let compensations = managed_acl_publication_compensations(
            &applied,
            ManagedAclPublicationFailurePhase::SwitchBank,
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
        let stage = steps
            .iter()
            .position(|step| matches!(step, ManagedAclPublicationStep::StageShadow))
            .unwrap();
        let epoch = steps
            .iter()
            .position(|step| matches!(step, ManagedAclPublicationStep::AdvanceFragmentEpoch))
            .unwrap();
        let switch = steps
            .iter()
            .position(|step| matches!(step, ManagedAclPublicationStep::SwitchBank))
            .unwrap();
        assert!(stage < epoch);
        assert!(epoch < switch);
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
            (0, 1, 1, 1)
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
            (2, 1, 1, 1)
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
    fn neutron_acl_gate_disable_and_enable_each_fence_once() {
        for steps in [
            managed_acl_gate_publication_steps_from_live(
                true, true, true, true, false, false, false,
            ),
            managed_acl_gate_publication_steps_from_live(
                false, false, false, false, true, true, false,
            ),
        ] {
            assert_eq!(
                steps,
                vec![
                    ManagedAclGatePublicationStep::AdvanceFragmentEpoch,
                    ManagedAclGatePublicationStep::PublishGate,
                    ManagedAclGatePublicationStep::Persist,
                ]
            );
        }
    }

    #[test]
    fn neutron_acl_gate_semantic_noop_does_not_advance_epoch() {
        assert!(managed_acl_gate_publication_steps_from_live(
            false, false, false, false, false, false, false,
        )
        .is_empty());
        assert!(managed_acl_gate_publication_steps_from_live(
            true, true, true, true, true, true, false,
        )
        .is_empty());
    }

    #[test]
    fn neutron_acl_fragment_epoch_gate_executor_orders_live_transition() {
        use std::cell::RefCell;

        let events = RefCell::new(Vec::new());
        let mut advance = || {
            events.borrow_mut().push("advance_epoch");
            Ok(())
        };
        let mut write_gate = || {
            events.borrow_mut().push("write_gate");
            Ok(())
        };

        execute_fragment_epoch_gate_transition(
            FragmentEpochGateTransition::SemanticChange,
            &mut advance,
            &mut write_gate,
        )
        .expect("live ACL/CT transition must publish");

        assert_eq!(*events.borrow(), vec!["advance_epoch", "write_gate"]);
    }

    #[test]
    fn fragment_loader_config_guarded_gate_admits_before_epoch_and_publish() {
        use std::cell::RefCell;

        let events = RefCell::new(Vec::new());
        let mut require_ready = || {
            events.borrow_mut().push("fragment_readiness");
            Ok(())
        };
        let mut advance = || {
            events.borrow_mut().push("advance_epoch");
            Ok(())
        };
        let mut write_gate = || {
            events.borrow_mut().push("write_gate");
            Ok(())
        };

        execute_guarded_fragment_epoch_gate_transition(
            true,
            FragmentEpochGateTransition::SemanticChange,
            &mut require_ready,
            &mut advance,
            &mut write_gate,
        )
        .expect("verified fragment readiness must allow the ACL/CT gate");

        assert_eq!(
            *events.borrow(),
            vec!["fragment_readiness", "advance_epoch", "write_gate"]
        );
    }

    #[test]
    fn fragment_loader_config_guarded_gate_rejects_before_epoch_and_publish() {
        use std::cell::RefCell;

        let events = RefCell::new(Vec::new());
        let mut require_ready = || {
            events.borrow_mut().push("fragment_readiness");
            Err("fragment tracking disabled after field evidence".to_string())
        };
        let mut advance = || {
            events.borrow_mut().push("advance_epoch");
            Ok(())
        };
        let mut write_gate = || {
            events.borrow_mut().push("write_gate");
            Ok(())
        };

        let error = execute_guarded_fragment_epoch_gate_transition(
            true,
            FragmentEpochGateTransition::SemanticChange,
            &mut require_ready,
            &mut advance,
            &mut write_gate,
        )
        .expect_err("ACL/CT gate must not cross failed fragment readiness");

        assert_eq!(
            error.phase(),
            FragmentEpochPublicationFailurePhase::Readiness
        );
        assert!(!error.epoch_advanced());
        assert_eq!(*events.borrow(), vec!["fragment_readiness"]);
    }

    #[test]
    fn fragment_loader_config_guarded_gate_allows_quiesce_without_activation_admission() {
        use std::cell::RefCell;

        let events = RefCell::new(Vec::new());
        let mut require_ready = || -> Result<(), String> {
            panic!("quiescing ACL/CT must not require enabled fragment tracking")
        };
        let mut advance = || {
            events.borrow_mut().push("advance_epoch");
            Ok(())
        };
        let mut write_gate = || {
            events.borrow_mut().push("write_gate");
            Ok(())
        };

        execute_guarded_fragment_epoch_gate_transition(
            false,
            FragmentEpochGateTransition::SemanticChange,
            &mut require_ready,
            &mut advance,
            &mut write_gate,
        )
        .expect("quiesce must remain available when tracking is disabled");

        assert_eq!(*events.borrow(), vec!["advance_epoch", "write_gate"]);
    }

    #[test]
    fn fragment_loader_local_persistence_rollback_revalidates_before_restoring_enabled_gate() {
        use std::cell::RefCell;

        let events = RefCell::new(Vec::new());
        execute_local_config_persistence_gate_rollback(
            true,
            true,
            &mut || {
                events.borrow_mut().push("read_live_gate");
                Ok((false, false))
            },
            &mut || {
                events.borrow_mut().push("fragment_readiness");
                Ok(())
            },
            &mut || {
                events.borrow_mut().push("advance_epoch");
                Ok(())
            },
            &mut |conntrack, acl| {
                events.borrow_mut().push(if conntrack || acl {
                    "write_enabled_gate"
                } else {
                    "write_disabled_gate"
                });
                Ok(())
            },
        )
        .unwrap();

        assert_eq!(
            *events.borrow(),
            vec![
                "read_live_gate",
                "fragment_readiness",
                "advance_epoch",
                "write_enabled_gate",
            ]
        );
    }

    #[test]
    fn fragment_loader_local_persistence_rollback_readiness_failure_never_writes_enabled() {
        use std::cell::RefCell;

        let events = RefCell::new(Vec::new());
        let error = execute_local_config_persistence_gate_rollback(
            true,
            true,
            &mut || {
                events.borrow_mut().push("read_live_gate");
                Ok((false, false))
            },
            &mut || {
                events.borrow_mut().push("fragment_readiness");
                Err("forced readiness failure".to_string())
            },
            &mut || {
                events.borrow_mut().push("advance_epoch");
                Ok(())
            },
            &mut |conntrack, acl| {
                events.borrow_mut().push(if conntrack || acl {
                    "write_enabled_gate"
                } else {
                    "write_disabled_gate"
                });
                Ok(())
            },
        )
        .unwrap_err();

        assert!(error.contains("forced readiness failure"));
        assert_eq!(
            *events.borrow(),
            vec![
                "read_live_gate",
                "fragment_readiness",
                "write_disabled_gate",
            ]
        );
    }

    #[test]
    fn fragment_loader_local_persistence_rollback_epoch_failure_never_writes_enabled() {
        use std::cell::RefCell;

        let events = RefCell::new(Vec::new());
        let error = execute_local_config_persistence_gate_rollback(
            true,
            false,
            &mut || {
                events.borrow_mut().push("read_live_gate");
                Ok((false, false))
            },
            &mut || {
                events.borrow_mut().push("fragment_readiness");
                Ok(())
            },
            &mut || {
                events.borrow_mut().push("advance_epoch");
                Err("forced epoch failure".to_string())
            },
            &mut |conntrack, acl| {
                events.borrow_mut().push(if conntrack || acl {
                    "write_enabled_gate"
                } else {
                    "write_disabled_gate"
                });
                Ok(())
            },
        )
        .unwrap_err();

        assert!(error.contains("forced epoch failure"));
        assert_eq!(
            *events.borrow(),
            vec![
                "read_live_gate",
                "fragment_readiness",
                "advance_epoch",
                "write_disabled_gate",
            ]
        );
    }

    #[test]
    fn fragment_loader_local_persistence_rollback_publish_failure_compensates_disabled() {
        use std::cell::RefCell;

        let events = RefCell::new(Vec::new());
        let error = execute_local_config_persistence_gate_rollback(
            false,
            true,
            &mut || {
                events.borrow_mut().push("read_live_gate");
                Ok((false, false))
            },
            &mut || {
                events.borrow_mut().push("fragment_readiness");
                Ok(())
            },
            &mut || {
                events.borrow_mut().push("advance_epoch");
                Ok(())
            },
            &mut |conntrack, acl| {
                events.borrow_mut().push(if conntrack || acl {
                    "write_enabled_gate"
                } else {
                    "write_disabled_gate"
                });
                if conntrack || acl {
                    Err("forced enabled gate write failure".to_string())
                } else {
                    Ok(())
                }
            },
        )
        .unwrap_err();

        assert!(error.contains("forced enabled gate write failure"));
        assert_eq!(
            *events.borrow(),
            vec![
                "read_live_gate",
                "fragment_readiness",
                "advance_epoch",
                "write_enabled_gate",
                "write_disabled_gate",
            ]
        );
    }

    #[test]
    fn neutron_acl_fragment_epoch_gate_executor_stops_on_epoch_failure() {
        use std::cell::RefCell;

        let events = RefCell::new(Vec::new());
        let mut advance = || {
            events.borrow_mut().push("advance_epoch");
            Err("epoch unavailable".to_string())
        };
        let mut write_gate = || {
            events.borrow_mut().push("write_gate");
            Ok(())
        };

        let error = execute_fragment_epoch_gate_transition(
            FragmentEpochGateTransition::SemanticChange,
            &mut advance,
            &mut write_gate,
        )
        .expect_err("gate write must not cross a failed epoch fence");

        assert_eq!(error.phase(), FragmentEpochPublicationFailurePhase::AdvanceEpoch);
        assert!(!error.epoch_advanced());
        assert_eq!(*events.borrow(), vec!["advance_epoch"]);
    }

    #[test]
    fn neutron_acl_fragment_epoch_gate_executor_does_not_rollback_epoch_on_gate_failure() {
        use std::cell::RefCell;

        let events = RefCell::new(Vec::new());
        let mut advance = || {
            events.borrow_mut().push("advance_epoch");
            Ok(())
        };
        let mut write_gate = || {
            events.borrow_mut().push("write_gate");
            Err("gate unavailable".to_string())
        };

        let error = execute_fragment_epoch_gate_transition(
            FragmentEpochGateTransition::SemanticChange,
            &mut advance,
            &mut write_gate,
        )
        .expect_err("gate failure must be reported");

        assert_eq!(error.phase(), FragmentEpochPublicationFailurePhase::Publish);
        assert!(error.epoch_advanced());
        assert_eq!(*events.borrow(), vec!["advance_epoch", "write_gate"]);
    }

    #[test]
    fn neutron_acl_fragment_epoch_gate_executor_skips_extra_epoch_for_non_transitions() {
        use std::cell::RefCell;

        for transition in [
            FragmentEpochGateTransition::EqualState,
            FragmentEpochGateTransition::FreshInitialization,
            FragmentEpochGateTransition::EpochAlreadyAdvanced,
        ] {
            let events = RefCell::new(Vec::new());
            let mut advance = || {
                events.borrow_mut().push("advance_epoch");
                Ok(())
            };
            let mut write_gate = || {
                events.borrow_mut().push("write_gate");
                Ok(())
            };

            execute_fragment_epoch_gate_transition(
                transition,
                &mut advance,
                &mut write_gate,
            )
            .expect("non-transition gate write must remain available");

            assert_eq!(*events.borrow(), vec!["write_gate"]);
        }
    }

    #[test]
    fn neutron_acl_fragment_epoch_gate_executor_demotion_quiesces_twice_but_fences_once() {
        use std::cell::RefCell;

        let events = RefCell::new(Vec::new());
        for transition in [
            FragmentEpochGateTransition::SemanticChange,
            FragmentEpochGateTransition::EpochAlreadyAdvanced,
        ] {
            let mut advance = || {
                events.borrow_mut().push("advance_epoch");
                Ok(())
            };
            let mut write_gate = || {
                events.borrow_mut().push("write_gate");
                Ok(())
            };
            execute_fragment_epoch_gate_transition(
                transition,
                &mut advance,
                &mut write_gate,
            )
            .expect("demotion quiesce must succeed");
        }

        assert_eq!(
            *events.borrow(),
            vec!["advance_epoch", "write_gate", "write_gate"]
        );
    }

    #[test]
    fn neutron_acl_fragment_epoch_bank_executor_enforces_commit_boundary() {
        use std::cell::RefCell;

        let events = RefCell::new(Vec::new());
        let mut advance = || {
            events.borrow_mut().push("advance_epoch");
            Ok(())
        };
        let mut switch_bank = || {
            events.borrow_mut().push("switch_bank");
            Ok(())
        };

        execute_fragment_epoch_bank_publication(&mut advance, &mut switch_bank)
            .expect("bank publication must commit");
        assert_eq!(*events.borrow(), vec!["advance_epoch", "switch_bank"]);
    }

    #[test]
    fn neutron_acl_fragment_epoch_bank_executor_preserves_failure_phase() {
        use std::cell::RefCell;

        let events = RefCell::new(Vec::new());
        let mut advance = || {
            events.borrow_mut().push("advance_epoch");
            Err("epoch unavailable".to_string())
        };
        let mut switch_bank = || {
            events.borrow_mut().push("switch_bank");
            Ok(())
        };
        let advance_error = execute_fragment_epoch_bank_publication(
            &mut advance,
            &mut switch_bank,
        )
        .expect_err("failed epoch must prevent bank switch");
        assert_eq!(
            advance_error.phase(),
            FragmentEpochPublicationFailurePhase::AdvanceEpoch
        );
        assert!(!advance_error.epoch_advanced());
        assert_eq!(*events.borrow(), vec!["advance_epoch"]);

        events.borrow_mut().clear();
        let mut advance = || {
            events.borrow_mut().push("advance_epoch");
            Ok(())
        };
        let mut switch_bank = || {
            events.borrow_mut().push("switch_bank");
            Err("switch unavailable".to_string())
        };
        let switch_error = execute_fragment_epoch_bank_publication(
            &mut advance,
            &mut switch_bank,
        )
        .expect_err("failed bank switch must be reported");
        assert_eq!(
            switch_error.phase(),
            FragmentEpochPublicationFailurePhase::Publish
        );
        assert!(switch_error.epoch_advanced());
        assert_eq!(*events.borrow(), vec!["advance_epoch", "switch_bank"]);
    }

    #[test]
    fn neutron_acl_live_gate_classification_ignores_equal_durable_state() {
        use std::cell::RefCell;

        let durable = (true, true);
        let requested = (Some(durable.0), Some(durable.1));
        let events = RefCell::new(Vec::new());
        let mut read_live = || {
            events.borrow_mut().push("read_live_gate");
            Ok((false, false))
        };
        let transition = read_live_acl_ct_gate_transition(
            requested.0,
            requested.1,
            &mut read_live,
        )
        .expect("live gate classification must succeed");
        let mut advance = || {
            events.borrow_mut().push("advance_epoch");
            Ok(())
        };
        let mut write_gate = || {
            events.borrow_mut().push("write_gate");
            Ok(())
        };

        execute_fragment_epoch_gate_transition(transition, &mut advance, &mut write_gate)
            .expect("live drift must be fenced and repaired");

        assert_eq!(transition, FragmentEpochGateTransition::SemanticChange);
        assert_eq!(
            *events.borrow(),
            vec!["read_live_gate", "advance_epoch", "write_gate"]
        );
    }

    #[test]
    fn neutron_acl_live_gate_read_failure_aborts_before_epoch_or_write() {
        use std::cell::RefCell;

        let events = RefCell::new(Vec::new());
        let result = (|| -> Result<(), String> {
            let transition = read_live_acl_ct_gate_transition(
                Some(true),
                Some(true),
                &mut || {
                    events.borrow_mut().push("read_live_gate");
                    Err("FIREWALL_CONFIG unavailable".to_string())
                },
            )?;
            execute_fragment_epoch_gate_transition(
                transition,
                &mut || {
                    events.borrow_mut().push("advance_epoch");
                    Ok(())
                },
                &mut || {
                    events.borrow_mut().push("write_gate");
                    Ok(())
                },
            )
            .map_err(|error| error.to_string())
        })();

        assert_eq!(result, Err("FIREWALL_CONFIG unavailable".to_string()));
        assert_eq!(*events.borrow(), vec!["read_live_gate"]);
    }

    #[test]
    fn neutron_acl_managed_registration_cleanup_uses_typed_activation_phase() {
        let mut failed_advance = || Err("epoch unavailable".to_string());
        let mut unreachable_gate = || panic!("gate must not run after failed epoch");
        let advance_error = execute_fragment_epoch_gate_transition(
            FragmentEpochGateTransition::SemanticChange,
            &mut failed_advance,
            &mut unreachable_gate,
        )
        .expect_err("advance phase must fail");

        let mut successful_advance = || Ok(());
        let mut failed_gate = || Err("gate unavailable".to_string());
        let gate_error = execute_fragment_epoch_gate_transition(
            FragmentEpochGateTransition::SemanticChange,
            &mut successful_advance,
            &mut failed_gate,
        )
        .expect_err("gate phase must fail");

        assert_eq!(
            managed_registration_cleanup_gate_transition(true, Some(&advance_error)),
            FragmentEpochGateTransition::SemanticChange
        );
        assert_eq!(
            managed_registration_cleanup_gate_transition(true, Some(&gate_error)),
            FragmentEpochGateTransition::EpochAlreadyAdvanced
        );
        assert_eq!(
            managed_registration_cleanup_gate_transition(false, None),
            FragmentEpochGateTransition::FreshInitialization
        );
        assert_eq!(
            managed_registration_cleanup_gate_transition(true, None),
            FragmentEpochGateTransition::SemanticChange
        );
    }

    #[test]
    fn neutron_acl_recovery_readiness_establishes_epoch_even_when_gate_is_unchanged() {
        assert_eq!(
            managed_acl_gate_publication_steps_from_live(
                false, false, false, false, false, false, true,
            ),
            vec![
                ManagedAclGatePublicationStep::AdvanceFragmentEpoch,
                ManagedAclGatePublicationStep::VerifyReadiness,
            ]
        );
    }

    #[test]
    fn neutron_acl_recovery_repairs_quiesced_kernel_gate_without_repersisting_durable_state() {
        assert_eq!(
            managed_acl_gate_publication_steps_from_live(
                false, false, // live kernel gate after health-loss quiesce
                true, true, // durable desired gate
                true, true, // requested recovery gate
                true,
            ),
            vec![
                ManagedAclGatePublicationStep::AdvanceFragmentEpoch,
                ManagedAclGatePublicationStep::PublishGate,
                ManagedAclGatePublicationStep::VerifyReadiness,
            ]
        );
    }

    #[test]
    fn neutron_acl_gate_planning_splits_kernel_durable_and_recovery_changes() {
        let steps = |actual_conntrack,
                     actual_acl,
                     durable_conntrack,
                     durable_acl,
                     requested_conntrack,
                     requested_acl,
                     recovery| {
            managed_acl_gate_publication_steps_from_live(
                actual_conntrack,
                actual_acl,
                durable_conntrack,
                durable_acl,
                requested_conntrack,
                requested_acl,
                recovery,
            )
        };

        assert!(steps(false, false, false, false, false, false, false).is_empty());
        assert_eq!(
            steps(false, false, false, false, true, true, false),
            vec![
                ManagedAclGatePublicationStep::AdvanceFragmentEpoch,
                ManagedAclGatePublicationStep::PublishGate,
                ManagedAclGatePublicationStep::Persist,
            ]
        );
        assert_eq!(
            steps(false, false, true, true, true, true, false),
            vec![
                ManagedAclGatePublicationStep::AdvanceFragmentEpoch,
                ManagedAclGatePublicationStep::PublishGate,
            ]
        );
        assert_eq!(
            steps(true, true, false, false, true, true, false),
            vec![
                ManagedAclGatePublicationStep::AdvanceFragmentEpoch,
                ManagedAclGatePublicationStep::Persist,
            ]
        );
        assert_eq!(
            steps(true, true, true, true, true, true, true),
            vec![
                ManagedAclGatePublicationStep::AdvanceFragmentEpoch,
                ManagedAclGatePublicationStep::VerifyReadiness,
            ]
        );
    }

    #[test]
    fn neutron_acl_recovery_readiness_rechecks_live_gate_immediately_before_commit() {
        use std::cell::RefCell;

        let events = RefCell::new(Vec::new());
        let mut matching_read = || {
            events.borrow_mut().push("read_live_gate");
            Ok((true, true))
        };
        verify_acl_gate_before_readiness(true, true, &mut matching_read)
            .expect("matching live gate may publish readiness");
        assert_eq!(*events.borrow(), vec!["read_live_gate"]);

        let mut drifted_read = || Ok((false, false));
        let error = verify_acl_gate_before_readiness(true, true, &mut drifted_read)
            .expect_err("quiesced live gate must not be marked ready");
        assert!(error.contains("actual conntrack=false acl=false"));

        let mut failed_read = || Err("FIREWALL_CONFIG unavailable".to_string());
        assert!(verify_acl_gate_before_readiness(true, true, &mut failed_read).is_err());
    }

    #[test]
    fn neutron_acl_fragment_epoch_action_is_strict_on_missing_pin_path() {
        let error = advance_fragment_epoch_action(
            "/proc/aria-firewall-task5-definitely-missing",
            u32::MAX,
        )
        .expect_err("missing pinned epoch map must fail strictly");
        assert!(!error.is_empty());
    }

    #[test]
    fn neutron_acl_pinned_gate_stops_at_advance_phase_on_missing_pin_path() {
        let error = execute_pinned_acl_gate_transition(
            "/proc/aria-firewall-task5-definitely-missing",
            u32::MAX,
            FragmentEpochGateTransition::SemanticChange,
            true,
            true,
        )
        .expect_err("missing pinned epoch map must block the gate write");

        assert_eq!(error.phase(), FragmentEpochPublicationFailurePhase::AdvanceEpoch);
        assert!(!error.epoch_advanced);
        assert!(!error.epoch_advanced());
    }

    #[test]
    fn neutron_acl_fragment_failure_records_explicit_epoch_ownership() {
        let failure = |transition, advance_result: Result<(), String>| {
            let mut advance = || advance_result.clone();
            let mut fail_gate = || Err("gate unavailable".to_string());
            execute_fragment_epoch_gate_transition(
                transition,
                &mut advance,
                &mut fail_gate,
            )
            .expect_err("fixture gate write must fail")
        };

        let mut failed_advance = || Err("epoch unavailable".to_string());
        let mut unreachable_gate = || panic!("gate must not run");
        let advance_error = execute_fragment_epoch_gate_transition(
            FragmentEpochGateTransition::SemanticChange,
            &mut failed_advance,
            &mut unreachable_gate,
        )
        .expect_err("fixture epoch advance must fail");

        assert!(!advance_error.epoch_advanced);
        assert!(failure(FragmentEpochGateTransition::SemanticChange, Ok(())).epoch_advanced);
        assert!(failure(FragmentEpochGateTransition::EpochAlreadyAdvanced, Ok(())).epoch_advanced);
        assert!(!failure(FragmentEpochGateTransition::EqualState, Ok(())).epoch_advanced);
        assert!(!failure(FragmentEpochGateTransition::FreshInitialization, Ok(())).epoch_advanced);
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
            ip_family: IP_FAMILY_V4,
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

    fn local_projection_qos_both_fixture() -> FirewallState {
        let mut state = FirewallState::default();
        state.qos_rules = vec![
            QosRuleInfo {
                group_name: "web".to_string(),
                group_id: 7,
                direction: 0,
                rate_bps: 1_000_000,
                burst_bytes: 64_000,
                priority: 1,
                mode: 0,
            },
            QosRuleInfo {
                group_name: "web".to_string(),
                group_id: 7,
                direction: 1,
                rate_bps: 2_000_000,
                burst_bytes: 128_000,
                priority: 2,
                mode: 1,
            },
        ];
        state
    }

    fn local_projection_mirror_both_fixture() -> FirewallState {
        let mut state = FirewallState::default();
        state.mirror_rules = vec![
            MirrorRuleInfo {
                src_group_name: "src".to_string(),
                src_group_id: 8,
                dst_group_name: "dst".to_string(),
                dst_group_id: 9,
                proto: libc::IPPROTO_TCP as u8,
                direction: 0,
                target_iface: "mirror-old-ingress".to_string(),
                target_ifindex: 42,
                is_global: false,
            },
            MirrorRuleInfo {
                src_group_name: "src".to_string(),
                src_group_id: 8,
                dst_group_name: "dst".to_string(),
                dst_group_id: 9,
                proto: libc::IPPROTO_TCP as u8,
                direction: 1,
                target_iface: "mirror-old-egress".to_string(),
                target_ifindex: 43,
                is_global: false,
            },
        ];
        state
    }

    fn assert_same_qos_rule(actual: &QosRuleInfo, expected: &QosRuleInfo) {
        assert_eq!(actual.group_name, expected.group_name);
        assert_eq!(actual.group_id, expected.group_id);
        assert_eq!(actual.direction, expected.direction);
        assert_eq!(actual.rate_bps, expected.rate_bps);
        assert_eq!(actual.burst_bytes, expected.burst_bytes);
        assert_eq!(actual.priority, expected.priority);
        assert_eq!(actual.mode, expected.mode);
    }

    fn assert_same_mirror_rule(actual: &MirrorRuleInfo, expected: &MirrorRuleInfo) {
        assert_eq!(actual.src_group_name, expected.src_group_name);
        assert_eq!(actual.src_group_id, expected.src_group_id);
        assert_eq!(actual.dst_group_name, expected.dst_group_name);
        assert_eq!(actual.dst_group_id, expected.dst_group_id);
        assert_eq!(actual.proto, expected.proto);
        assert_eq!(actual.direction, expected.direction);
        assert_eq!(actual.target_iface, expected.target_iface);
        assert_eq!(actual.target_ifindex, expected.target_ifindex);
        assert_eq!(actual.is_global, expected.is_global);
    }

    fn assert_qos_rule(
        state: &FirewallState,
        group_id: u32,
        direction: u8,
        rate_bps: u64,
        burst_bytes: u64,
        priority: u8,
        mode: u8,
    ) {
        let rule = state
            .qos_rules
            .iter()
            .find(|rule| rule.group_id == group_id && rule.direction == direction)
            .expect("expected QoS direction in final state");
        assert_eq!(rule.rate_bps, rate_bps);
        assert_eq!(rule.burst_bytes, burst_bytes);
        assert_eq!(rule.priority, priority);
        assert_eq!(rule.mode, mode);
    }

    fn assert_mirror_targets(
        state: &FirewallState,
        src_group_id: u32,
        dst_group_id: u32,
        proto: u8,
        expected: &[(u8, u32)],
    ) {
        for (direction, target_ifindex) in expected {
            let rule = state
                .mirror_rules
                .iter()
                .find(|rule| {
                    rule.src_group_id == src_group_id
                        && rule.dst_group_id == dst_group_id
                        && rule.proto == proto
                        && rule.direction == *direction
                })
                .expect("expected Mirror direction in final state");
            assert_eq!(rule.target_ifindex, *target_ifindex);
        }
    }

    fn assert_receipts_restore_complete_qos_preimages(
        old_state: &FirewallState,
        operations: &[ManagedLocalDomainOperation],
    ) {
        for operation in operations {
            let (group_id, direction) = match operation {
                ManagedLocalDomainOperation::QosUpsert(rule) => (rule.group_id, rule.direction),
                ManagedLocalDomainOperation::QosDelete {
                    group_id,
                    direction,
                } => (*group_id, *direction),
                _ => continue,
            };
            let expected = old_state
                .qos_rules
                .iter()
                .find(|rule| rule.group_id == group_id && rule.direction == direction)
                .expect("fixture must contain an exact QoS preimage");
            let receipt = build_managed_local_domain_receipt(operation, old_state)
                .expect("QoS receipt must capture its preimage");
            let compensation = managed_local_domain_compensation_operations(&receipt);
            let restored = compensation
                .iter()
                .find_map(|operation| match operation {
                    ManagedLocalDomainOperation::QosUpsert(rule) => Some(rule),
                    _ => None,
                })
                .expect("QoS compensation must restore the old rule");
            assert_same_qos_rule(restored, expected);
        }
    }

    fn assert_receipts_restore_complete_mirror_preimages(
        old_state: &FirewallState,
        operations: &[ManagedLocalDomainOperation],
    ) {
        for operation in operations {
            let (src_group_id, dst_group_id, proto, direction, is_global) = match operation {
                ManagedLocalDomainOperation::MirrorUpsert(rule) => (
                    rule.src_group_id,
                    rule.dst_group_id,
                    rule.proto,
                    rule.direction,
                    rule.is_global,
                ),
                ManagedLocalDomainOperation::MirrorDelete {
                    src_group_id,
                    dst_group_id,
                    proto,
                    direction,
                    is_global,
                } => (*src_group_id, *dst_group_id, *proto, *direction, *is_global),
                _ => continue,
            };
            let expected = old_state
                .mirror_rules
                .iter()
                .find(|rule| {
                    rule.direction == direction
                        && if is_global {
                            rule.is_global
                        } else {
                            !rule.is_global
                                && rule.src_group_id == src_group_id
                                && rule.dst_group_id == dst_group_id
                                && rule.proto == proto
                        }
                })
                .expect("fixture must contain an exact Mirror preimage");
            let receipt = build_managed_local_domain_receipt(operation, old_state)
                .expect("Mirror receipt must capture its preimage");
            let compensation = managed_local_domain_compensation_operations(&receipt);
            let restored = compensation
                .iter()
                .find_map(|operation| match operation {
                    ManagedLocalDomainOperation::MirrorUpsert(rule) => Some(rule),
                    _ => None,
                })
                .expect("Mirror compensation must restore the old rule");
            assert_same_mirror_rule(restored, expected);
        }
    }

    fn actual_qos(group_id: u32, direction: u8, rate_bps: u64) -> QosRuleInfo {
        QosRuleInfo {
            group_name: format!("actual-{group_id}"),
            group_id,
            direction,
            rate_bps,
            burst_bytes: 1,
            priority: 1,
            mode: 0,
        }
    }

    #[tokio::test]
    async fn local_projection_clean_compensation_restores_verified_health() {
        let health = std::cell::RefCell::new(Vec::new());
        let failure = execute_managed_local_projection_transaction(
            &["ingress", "egress"],
            |next| health.borrow_mut().push(next),
            |direction| {
                if *direction == "egress" {
                    std::future::ready(Err(ManagedLocalApplyFailure::clean(
                        "forced egress failure",
                    )))
                } else {
                    std::future::ready(Ok(*direction))
                }
            },
            || std::future::ready(Ok::<(), String>(())),
            |_receipt| std::future::ready(Ok::<(), String>(())),
            || std::future::ready(Ok::<(), String>(())),
        )
        .await
        .expect_err("later direction must fail");

        assert!(!failure.recovery_required());
        assert!(failure.contains("forced egress failure"));
        assert_eq!(
            health.into_inner(),
            vec![
                ManagedProjectionHealth::Unverified,
                ManagedProjectionHealth::Verified,
            ]
        );
    }

    #[tokio::test]
    async fn local_projection_compensation_failure_is_attempt_all_and_recovery_required() {
        let attempts = std::cell::RefCell::new(Vec::new());
        let failure = execute_managed_local_projection_transaction(
            &["first", "second", "third"],
            |_health| {},
            |operation| {
                if *operation == "third" {
                    std::future::ready(Err(ManagedLocalApplyFailure::recovery_required(
                        "third write failed",
                        "third self-compensation failed",
                    )))
                } else {
                    std::future::ready(Ok(*operation))
                }
            },
            || std::future::ready(Ok::<(), String>(())),
            |receipt| {
                attempts.borrow_mut().push(*receipt);
                std::future::ready(if *receipt == "second" {
                    Err("second compensation failed".to_string())
                } else {
                    Ok(())
                })
            },
            || std::future::ready(Ok::<(), String>(())),
        )
        .await
        .expect_err("compensation failure must remain visible");

        assert!(failure.recovery_required());
        assert!(failure.contains("third write failed"));
        assert!(failure.contains("third self-compensation failed"));
        assert!(failure.contains("second compensation failed"));
        assert_eq!(attempts.into_inner(), vec!["second", "first"]);
    }

    #[test]
    fn standalone_qos_both_plan_is_one_final_state_with_exact_preimages() {
        let old = local_projection_qos_both_fixture();
        let plans = managed_qos_direction_plans(2, 1).unwrap();
        let operations = plan_managed_local_qos_upserts(
            &old,
            "web",
            7,
            8_000_000,
            256_000,
            4,
            &plans,
        )
        .unwrap();
        let final_state = managed_local_state_after_domain_operations(&old, &operations).unwrap();

        assert_eq!(final_state.qos_rules.len(), old.qos_rules.len());
        assert_qos_rule(&final_state, 7, 0, 8_000_000, 256_000, 4, 0);
        assert_qos_rule(&final_state, 7, 1, 8_000_000, 256_000, 4, 1);
        assert_receipts_restore_complete_qos_preimages(&old, &operations);
    }

    #[test]
    fn standalone_mirror_both_plan_is_one_final_state_with_exact_preimages() {
        let old = local_projection_mirror_both_fixture();
        let operations = plan_managed_local_mirror_upserts(
            &old,
            "src",
            8,
            "dst",
            9,
            libc::IPPROTO_TCP as u8,
            "mirror-new",
            84,
            &[0, 1],
        )
        .unwrap();
        let final_state = managed_local_state_after_domain_operations(&old, &operations).unwrap();

        assert_mirror_targets(
            &final_state,
            8,
            9,
            libc::IPPROTO_TCP as u8,
            &[(0, 84), (1, 84)],
        );
        assert_receipts_restore_complete_mirror_preimages(&old, &operations);
    }

    #[test]
    fn standalone_qos_both_delete_receipts_restore_exact_rules() {
        let old = local_projection_qos_both_fixture();
        let operations = plan_managed_local_qos_delete(&old, 7, &[0, 1]).unwrap();
        let final_state = managed_local_state_after_domain_operations(&old, &operations).unwrap();

        assert!(!final_state
            .qos_rules
            .iter()
            .any(|rule| rule.group_id == 7));
        assert_receipts_restore_complete_qos_preimages(&old, &operations);
    }

    #[test]
    fn standalone_mirror_both_delete_receipts_restore_exact_rules() {
        let old = local_projection_mirror_both_fixture();
        let operations = plan_managed_local_mirror_delete(
            &old,
            8,
            9,
            libc::IPPROTO_TCP as u8,
            &[0, 1],
        )
        .unwrap();
        let final_state = managed_local_state_after_domain_operations(&old, &operations).unwrap();

        assert!(!final_state.mirror_rules.iter().any(|rule| {
            rule.src_group_id == 8
                && rule.dst_group_id == 9
                && rule.proto == libc::IPPROTO_TCP as u8
        }));
        assert_receipts_restore_complete_mirror_preimages(&old, &operations);
    }

    #[test]
    fn local_projection_recovery_admission_is_domain_scoped() {
        let mut state = FirewallState::default();
        state.mark_local_projection_recovery(
            "qos",
            LocalProjectionRecovery::new("forced rollback failure"),
        );

        assert!(local_projection_recovery_admission(&state, LocalWriteDomain::Qos).is_err());
        assert!(local_projection_recovery_admission(&state, LocalWriteDomain::Mirror).is_ok());
    }

    #[test]
    fn local_projection_recovery_is_the_stable_maintenance_reason() {
        let mut state = FirewallState::default();
        state.mark_local_projection_recovery(
            "mirror",
            LocalProjectionRecovery::new("forced rollback failure"),
        );

        assert_eq!(
            local_projection_maintenance_reason(&state, 3).as_deref(),
            Some("local_projection_recovery_required:mirror")
        );
    }

    #[test]
    fn managed_startup_recovery_plan_repairs_expected_before_deleting_extra() {
        let desired = local_projection_qos_both_fixture();
        let actual = vec![actual_qos(7, 0, 99), actual_qos(100, 1, 1)];
        let operations = plan_local_projection_runtime_repair(&desired, &actual, &[], &[]).unwrap();

        assert!(matches!(
            operations[0],
            ManagedLocalDomainOperation::QosUpsert(_)
        ));
        assert!(matches!(
            operations.last().unwrap(),
            ManagedLocalDomainOperation::QosDelete { .. }
        ));
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
    fn managed_local_group_projection_rejects_new_general_overlap_before_operations() {
        let mut committed = FirewallState::default();
        managed_cross_domain_insert_group(
            &mut committed,
            "broad-general",
            10,
            &["10.0.0.0/8"],
        );
        let mut proposed = committed.clone();
        managed_cross_domain_insert_group(
            &mut proposed,
            "narrow-general",
            20,
            &["10.1.0.0/16"],
        );

        let error = managed_general_state_mutations(&committed, &proposed)
            .expect_err("new cross-group general overlap must reject before operations");

        assert!(matches!(error, ControlPlaneError::GroupConflict(_)));
        assert_eq!(error.status_code(), 409);
        assert!(error
            .to_string()
            .contains("general_group_overlap:broad-general:10.0.0.0/8:narrow-general:10.1.0.0/16"));
        assert_eq!(committed.next_group_id, 11);
        assert!(!committed.groups.contains_key("narrow-general"));
    }

    #[test]
    fn managed_local_group_projection_rejects_qos_promotion_into_overlap() {
        let mut committed = FirewallState::default();
        managed_cross_domain_insert_group(
            &mut committed,
            "general",
            10,
            &["10.0.0.0/8"],
        );
        managed_cross_domain_insert_group(
            &mut committed,
            "acl-only",
            20,
            &["10.1.0.0/16"],
        );
        committed.rules.push(managed_cross_domain_acl_rule(20));
        managed_general_state_mutations(&FirewallState::default(), &committed)
            .expect("ACL-only overlap must retain ACL-046 isolation");

        let mut promoted = committed.clone();
        promoted
            .qos_rules
            .push(managed_cross_domain_qos_reference("acl-only", 20));
        let error = managed_general_state_mutations(&committed, &promoted)
            .expect_err("QoS promotion must not publish ambiguous membership");

        assert!(matches!(error, ControlPlaneError::GroupConflict(_)));
        assert_eq!(error.status_code(), 409);
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
                    std::future::ready(Err(ManagedLocalApplyFailure::clean(
                        "forced destination general apply failure",
                    )))
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
                "health:verified",
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
    async fn managed_local_group_projection_success_restores_verified_and_reopens_admission() {
        let mutations = vec![SharedNetworkMutation::Added {
            direction: "src",
            cidr: "198.51.100.0/24".to_string(),
            group_id: 70,
        }];
        let health_trace = std::cell::RefCell::new(vec![ManagedProjectionHealth::Verified]);
        let current_health = std::cell::Cell::new(ManagedProjectionHealth::Verified);
        let phase_trace = std::cell::RefCell::new(Vec::new());
        let compensation_attempted = std::cell::Cell::new(false);
        let durable_restore_attempted = std::cell::Cell::new(false);

        execute_managed_local_projection_transaction(
            &mutations,
            |health| {
                current_health.set(health);
                health_trace.borrow_mut().push(health);
            },
            |mutation| {
                phase_trace.borrow_mut().push("apply");
                std::future::ready(Ok::<SharedNetworkMutation, ManagedLocalApplyFailure>(
                    mutation.clone(),
                ))
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
                ManagedProjectionHealth::Verified,
            ]
        );
        managed_local_projection_admission(
            ManagedAclPublicationMode::ManagedAcl,
            current_health.get(),
        )
        .expect("successful persistence must re-admit the next managed mutation");
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

        let promotion_error = managed_general_state_mutations(&zero, &one)
            .expect_err("0 to 1 exact-alias promotion must reject ambiguous membership");
        assert!(matches!(
            promotion_error,
            ControlPlaneError::GroupConflict(_)
        ));
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

        let promotion_error = managed_general_state_mutations(&zero, &dual_used)
            .expect_err("destination-only Mirror promotion must reject an exact alias");
        assert!(matches!(
            promotion_error,
            ControlPlaneError::GroupConflict(_)
        ));

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
                ) => std::future::ready(Err(ManagedLocalApplyFailure::clean(
                    "forced later QoS apply failure",
                ))),
                _ => std::future::ready(Err(ManagedLocalApplyFailure::clean(
                    "unexpected non-QoS operation",
                ))),
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
                ) => std::future::ready(Err(ManagedLocalApplyFailure::clean(
                    "forced later Mirror apply failure",
                ))),
                _ => std::future::ready(Err(ManagedLocalApplyFailure::clean(
                    "unexpected non-Mirror operation",
                ))),
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
                ) => std::future::ready(Err(ManagedLocalApplyFailure::clean(
                    "forced QoS apply after FQ prepare",
                ))),
                _ => std::future::ready(Err(ManagedLocalApplyFailure::clean(
                    "unexpected non-FQ/QoS operation",
                ))),
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
    async fn managed_dual_use_group_persistence_failure_reuses_applied_journal_and_requires_repair(
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
        assert!(error.recovery_required());
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
                ManagedProjectionHealth::RepairRequired,
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
            ip_family: IP_FAMILY_V4,
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
