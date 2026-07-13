use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fs;
use std::path::Path;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::{Mutex, RwLock};
use tracing::{error, info, warn};

use crate::instance::{FirewallInstance, RuntimePinState};
use crate::kernel_drop_manager::{KernelDropManager, KernelDropStatusSnapshot};
use crate::service_chain::{self, ServiceChain};
use crate::ssl_manager::SslManager;
use crate::tap_registry::ManagedAttachMode;
use crate::trace_backend::{TraceManager, TraceRuntimeStatusSnapshot};
use aria_core::common::TapMapRuntime;
use aria_core::ebpf_ops::TraceMapMode;
use aria_core::state::{FirewallState, GroupInfo, MirrorRuleInfo, QosRuleInfo, RuleInfo};
use aria_core::wal::{WalClient, WalEntry};

mod observability;
mod ssl;
mod tcprt;
mod trace;

const WAL_COMPACT_THRESHOLD: u64 = 1000;
pub const MANAGED_SHARED_PIN_NAMESPACE: &str = "global-v2";
const FQ_QDISC_MARKER: &str = ".fq-root-qdisc-owned";

/// Per-instance in-memory state
struct InstanceState {
    state: FirewallState,
    tap_id: u32,
    ifindex: Option<u32>,
    pin_path: String,
    state_path: String,
    wal: WalClient,
    ssl_sync_pending: bool,
    last_ssl_sync_error: Option<String>,
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
    activation: ManagedRuntimeActivation,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
enum ManagedRuntimeActivation {
    PreserveVerifiedLive,
    RestoreStandalone {
        conntrack: bool,
        acl: bool,
    },
    AwaitNeutronResync {
        require_tc_acl_links: bool,
    },
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
}

#[derive(Clone, Debug)]
struct OwnedAclPolicyRuntimeAdd {
    rule: RuleInfo,
    is_new_port_set: bool,
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
        let iface = Self::runtime_iface_name(instance, state)?;
        FirewallInstance::new(
            &iface,
            state.pin_path.clone().into(),
            state.state_path.clone().into(),
            instance != "system",
            trace_map_mode,
        )
        .require_tc_acl_links()
        .map_err(ControlPlaneError::InstanceNotReady)
    }

    fn fq_qdisc_marker_path(state: &InstanceState) -> std::path::PathBuf {
        Path::new(&state.state_path).join(FQ_QDISC_MARKER)
    }

    fn mark_owned_fq_qdisc(state: &InstanceState, iface: &str) -> Result<(), ControlPlaneError> {
        let marker_path = Self::fq_qdisc_marker_path(state);
        fs::write(&marker_path, b"owned\n").map_err(|e| {
            ControlPlaneError::KernelError(format!(
                "[{}] failed to persist FQ qdisc ownership marker {}: {}",
                iface,
                marker_path.display(),
                e
            ))
        })
    }

    fn rollback_installed_fq_qdisc(instance: &str, state: &InstanceState) {
        let Ok(iface) = Self::runtime_iface_name(instance, state) else {
            return;
        };

        if let Err(e) = aria_core::ebpf_ops::cleanup_root_qdisc(&iface) {
            warn!(instance = %instance, iface = %iface, error = %e, "failed to roll back FQ qdisc after QoS add failure");
        }

        let marker_path = Self::fq_qdisc_marker_path(state);
        if let Err(e) = fs::remove_file(&marker_path) {
            if e.kind() != std::io::ErrorKind::NotFound {
                warn!(instance = %instance, iface = %iface, path = %marker_path.display(), error = %e, "failed to remove FQ qdisc marker after QoS add failure");
            }
        }
    }

    fn requested_directions(direction: u8) -> Vec<u8> {
        if direction == 2 {
            vec![0, 1]
        } else {
            vec![direction]
        }
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
        runtime: TapMapRuntime<'_>,
        bank: u8,
        ebpf_path: &str,
        new_port_sets_by_key: &BTreeMap<OwnedAclPolicyKey, bool>,
    ) -> Result<(), ControlPlaneError> {
        aria_core::ebpf_ops::scrub_acl_bank(runtime, bank)
            .map_err(ControlPlaneError::KernelError)?;

        for group in state.groups.values() {
            for cidr in &group.cidrs {
                aria_core::ebpf_ops::add_acl_network_in_bank(
                    "src", cidr, group.id, bank, runtime, ebpf_path,
                )
                .map_err(|e| {
                    ControlPlaneError::KernelError(format!(
                        "stage shadow bank {} src group {} cidr {}: {}",
                        bank, group.name, cidr, e
                    ))
                })?;
                aria_core::ebpf_ops::add_acl_network_in_bank(
                    "dst", cidr, group.id, bank, runtime, ebpf_path,
                )
                .map_err(|e| {
                    ControlPlaneError::KernelError(format!(
                        "stage shadow bank {} dst group {} cidr {}: {}",
                        bank, group.name, cidr, e
                    ))
                })?;
            }
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
        tap_id: u32,
        ifindex: u32,
        state: &FirewallState,
    ) -> Result<(), String> {
        let iface_ctx = aria_core::ebpf_ops::read_iface_ctx(pin_path, ifindex)?;
        if iface_ctx.tap_id != tap_id {
            return Err(format!(
                "preexisting live runtime mismatch for {}: IFACE_CTX_MAP ifindex {} points to tap_id {}, expected {}",
                name, ifindex, iface_ctx.tap_id, tap_id
            ));
        }

        let runtime = TapMapRuntime::new(pin_path, tap_id);
        let actual = aria_core::ebpf_ops::read_runtime_config(runtime)?;
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

        if actual_flags != expected {
            return Err(format!(
                "preexisting live runtime mismatch for {}: actual flags {:?}, expected {:?}; detach and reattach to rebuild safely",
                name, actual_flags, expected
            ));
        }

        aria_core::ebpf_ops::validate_pinned_runtime_state(runtime, state).map_err(|e| {
            format!(
                "preexisting live runtime mismatch for {}: {}; detach and reattach to rebuild safely",
                name, e
            )
        })?;

        Ok(())
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
        group_id: u32,
        deleted_networks: &[(&'static str, String)],
    ) -> Result<(), String> {
        let bank = aria_core::ebpf_ops::read_acl_active_bank(runtime).unwrap_or(0);
        for (direction, cidr) in deleted_networks.iter().rev() {
            aria_core::ebpf_ops::add_network(direction, cidr, group_id, runtime, ebpf_path)?;
            aria_core::ebpf_ops::add_acl_network_in_bank(
                direction, cidr, group_id, bank, runtime, ebpf_path,
            )?;
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
        let activation = managed_runtime_activation(
            mode,
            pin_state.preexisting_live_links,
            state.conntrack_enabled,
            state.acl_enabled,
        );
        let preserve_existing_runtime = replacing_existing || pin_state.preexisting_live_links;
        let mut iface_ctx_synced = false;
        let mut tap_config_written = false;

        if pin_state.preexisting_live_links {
            if let Err(e) =
                self.validate_preexisting_live_runtime(name, &pin_path, tap_id, ifindex, &state)
            {
                wal.shutdown().await;
                return Err(e);
            }
            if (state.conntrack_enabled || state.acl_enabled)
                && !(pin_state.preexisting_tc_ingress_link
                    && pin_state.preexisting_tc_egress_link)
            {
                let mut missing = Vec::new();
                if !pin_state.preexisting_tc_ingress_link {
                    missing.push("tc_ingress");
                }
                if !pin_state.preexisting_tc_egress_link {
                    missing.push("tc_egress");
                }
                wal.shutdown().await;
                return Err(format!(
                    "preexisting live runtime mismatch for {}: missing pinned TC ACL links: {}; detach and reattach to rebuild safely",
                    name,
                    missing.join(", ")
                ));
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

            if let Err(e) = aria_core::ebpf_ops::replay_state_to_pinned_maps(&pin_path, &state_path)
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
            ..
        } = prepared;

        let instance = Arc::new(tokio::sync::RwLock::new(InstanceState {
            state,
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
    ) -> Result<(), String> {
        let global_ssl_enabled = match self.read_ssl_global_config().await {
            Ok(enabled) => Some(enabled),
            Err(e) => {
                warn!(error = %e, "failed to read global SSL config during system register");
                None
            }
        };
        let mut state = aria_core::wal::load_with_wal(state_path);
        let tap_id_reset = if state.tap_id != aria_core::common::TAP_ID_UNASSIGNED {
            state.tap_id = aria_core::common::TAP_ID_UNASSIGNED;
            true
        } else {
            false
        };
        let ssl_changed = global_ssl_enabled
            .map(|enabled| state.ssl_enabled != enabled)
            .unwrap_or(false);
        if let Some(enabled) = global_ssl_enabled {
            if ssl_changed {
                state.ssl_enabled = enabled;
            }
        }
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
        if wal.entry_count() > 0 || ssl_changed || tap_id_reset {
            match serde_json::to_string_pretty(&state) {
                Ok(json) => {
                    if let Err(e) = wal.compact(json).await {
                        error!(instance = "system", error = %e, "failed to compact WAL on system register");
                    }
                }
                Err(e) => {
                    error!(instance = "system", error = %e, "failed to serialize state on system register");
                }
            }
        }

        let tap_id = state.tap_id;
        let runtime = TapMapRuntime::new(pin_path, tap_id);
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
        let instance = Arc::new(tokio::sync::RwLock::new(InstanceState {
            state,
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
        let mut instances = self.instances.write().await;
        if let Some(inst) = instances.remove(name) {
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
            return;
        }
        info!(instance = %name, "unregistered instance");
    }

    /// List all registered instance names
    pub async fn list_instances(&self) -> Vec<String> {
        let instances = self.instances.read().await;
        let mut names: Vec<String> = instances.keys().cloned().collect();
        names.sort();
        names
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

    // ── Groups ──

    pub async fn replace_owned_acl(
        &self,
        instance: &str,
        owner_prefix: &str,
        exclusive_policy_domain: bool,
        groups: &[OwnedAclGroupSpec],
        policies: &[OwnedAclPolicySpec],
    ) -> Result<OwnedAclReconcileReport, ControlPlaneError> {
        Self::owned_acl_validate_group_specs(owner_prefix, groups)?;
        Self::owned_acl_validate_policy_specs(owner_prefix, policies)?;

        let inst = self.get_instance(instance).await?;
        let mut state = inst.write().await;
        Self::check_runtime_maps_ready(&state.pin_path)?;
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
            if let Some((idx, ports_normalized)) = add_result.old_port_set_released {
                released_port_sets.insert(idx, ports_normalized);
            }
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
            if let (Some(idx), Some(ports_normalized)) =
                (remove_result.bitmap_idx, remove_result.port_set_released)
            {
                released_port_sets.insert(idx, ports_normalized);
            }
        }
        for group in &group_deletes {
            final_state.groups.remove(&group.name);
        }

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

        for (name, group_id, cidr) in &group_cidr_adds {
            aria_core::ebpf_ops::add_network(
                "src",
                cidr,
                *group_id,
                state.map_runtime(),
                &self.ebpf_path,
            )
            .map_err(|e| ControlPlaneError::KernelError(format!("src {}: {}", name, e)))?;
            aria_core::ebpf_ops::add_network(
                "dst",
                cidr,
                *group_id,
                state.map_runtime(),
                &self.ebpf_path,
            )
            .map_err(|e| ControlPlaneError::KernelError(format!("dst {}: {}", name, e)))?;
        }

        for (name, group_id, cidr) in &group_cidr_deletes {
            aria_core::ebpf_ops::delete_network(
                "src",
                cidr,
                *group_id,
                state.map_runtime(),
                &self.ebpf_path,
            )
            .map_err(|e| ControlPlaneError::KernelError(format!("src {}: {}", name, e)))?;
            aria_core::ebpf_ops::delete_network(
                "dst",
                cidr,
                *group_id,
                state.map_runtime(),
                &self.ebpf_path,
            )
            .map_err(|e| ControlPlaneError::KernelError(format!("dst {}: {}", name, e)))?;
        }

        Self::stage_acl_shadow_bank(
            &final_state,
            state.map_runtime(),
            next_acl_bank,
            &self.ebpf_path,
            &new_port_sets_by_key,
        )?;
        if state.state.conntrack_enabled || state.state.acl_enabled {
            Self::require_tc_acl_ready_locked(instance, &state, self.trace_map_mode())?;
        }
        aria_core::ebpf_ops::set_acl_active_bank(state.map_runtime(), next_acl_bank)
            .map_err(ControlPlaneError::KernelError)?;

        for (idx, ports_normalized) in &released_port_sets {
            if let Err(e) = aria_core::ebpf_ops::delete_port_set(
                *idx,
                ports_normalized,
                state.map_runtime(),
                &self.ebpf_path,
            ) {
                warn!(
                    error = %e,
                    bitmap_idx = *idx,
                    "failed to clean released port set after ACL shadow bank switch"
                );
            }
        }
        if let Err(e) = aria_core::ebpf_ops::scrub_acl_bank(state.map_runtime(), current_acl_bank) {
            warn!(
                error = %e,
                bank = current_acl_bank,
                "failed to scrub previous ACL shadow bank after switch"
            );
        }

        for existing in &policy_deletes {
            let rule = &existing.rule;
            if let Err(e) = aria_core::monitoring::clear_rule_stats_for_policy(
                state.map_runtime(),
                rule.src_group_id,
                rule.dst_group_id,
                rule.proto,
                rule.direction,
            ) {
                warn!(error = %e, "failed to clear rule stats after owned ACL diff delete");
            }
        }
        for group in &group_deletes {
            if let Err(e) =
                aria_core::monitoring::clear_group_stats_for_id(state.map_runtime(), group.id)
            {
                warn!(error = %e, group_id = group.id, "failed to clear group stats after owned ACL diff delete");
            }
        }

        if runtime_adds.is_empty()
            && policy_deletes.is_empty()
            && group_cidr_adds.is_empty()
            && group_cidr_deletes.is_empty()
            && group_deletes.is_empty()
            && released_port_sets.is_empty()
        {
            return Ok(report);
        }

        state.state = final_state;
        let compact_started = Instant::now();
        let json = serde_json::to_string_pretty(&state.state)
            .map_err(|e| ControlPlaneError::ValidationError(e.to_string()))?;
        state
            .wal
            .compact(json)
            .await
            .map_err(ControlPlaneError::KernelError)?;
        report.compact_ms = compact_started.elapsed().as_millis();
        Ok(report)
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
        let inst = self.get_instance(instance).await?;
        let mut state = inst.write().await;
        Self::check_runtime_maps_ready(&state.pin_path)?;

        // Check if this is a new group (for rollback)
        let was_new_group = !state.state.groups.contains_key(name);

        // Modify in-memory state
        let id = state
            .state
            .add_group(name, cidr)
            .map_err(|e| ControlPlaneError::ValidationError(e))?;
        let acl_bank = aria_core::ebpf_ops::read_acl_active_bank(state.map_runtime())
            .map_err(ControlPlaneError::KernelError)?;

        // Write to kernel maps
        if let Err(e) =
            aria_core::ebpf_ops::add_network("src", cidr, id, state.map_runtime(), &self.ebpf_path)
        {
            state.state.rollback_add_group(name, cidr, was_new_group);
            return Err(ControlPlaneError::KernelError(format!("src: {}", e)));
        }
        if let Err(e) =
            aria_core::ebpf_ops::add_network("dst", cidr, id, state.map_runtime(), &self.ebpf_path)
        {
            let _ = aria_core::ebpf_ops::delete_network(
                "src",
                cidr,
                id,
                state.map_runtime(),
                &self.ebpf_path,
            );
            state.state.rollback_add_group(name, cidr, was_new_group);
            return Err(ControlPlaneError::KernelError(format!("dst: {}", e)));
        }
        if let Err(e) = aria_core::ebpf_ops::add_acl_network_in_bank(
            "src",
            cidr,
            id,
            acl_bank,
            state.map_runtime(),
            &self.ebpf_path,
        ) {
            let _ = aria_core::ebpf_ops::delete_network(
                "src",
                cidr,
                id,
                state.map_runtime(),
                &self.ebpf_path,
            );
            let _ = aria_core::ebpf_ops::delete_network(
                "dst",
                cidr,
                id,
                state.map_runtime(),
                &self.ebpf_path,
            );
            state.state.rollback_add_group(name, cidr, was_new_group);
            return Err(ControlPlaneError::KernelError(format!("acl src: {}", e)));
        }
        if let Err(e) = aria_core::ebpf_ops::add_acl_network_in_bank(
            "dst",
            cidr,
            id,
            acl_bank,
            state.map_runtime(),
            &self.ebpf_path,
        ) {
            let _ = aria_core::ebpf_ops::delete_acl_network_in_bank(
                "src",
                cidr,
                id,
                acl_bank,
                state.map_runtime(),
                &self.ebpf_path,
            );
            let _ = aria_core::ebpf_ops::delete_network(
                "src",
                cidr,
                id,
                state.map_runtime(),
                &self.ebpf_path,
            );
            let _ = aria_core::ebpf_ops::delete_network(
                "dst",
                cidr,
                id,
                state.map_runtime(),
                &self.ebpf_path,
            );
            state.state.rollback_add_group(name, cidr, was_new_group);
            return Err(ControlPlaneError::KernelError(format!("acl dst: {}", e)));
        }

        state
            .wal_append(&WalEntry::AddGroup {
                name: name.to_string(),
                cidr: cidr.to_string(),
            })
            .await;
        Ok(id)
    }

    pub async fn delete_group(&self, instance: &str, name: &str) -> Result<(), ControlPlaneError> {
        let inst = self.get_instance(instance).await?;
        let mut state = inst.write().await;
        Self::check_runtime_maps_ready(&state.pin_path)?;

        let group = state
            .state
            .groups
            .get(name)
            .ok_or_else(|| ControlPlaneError::GroupNotFound(name.to_string()))?
            .clone();

        // Check if group is referenced by any rule
        for rule in &state.state.rules {
            if rule.src_group_id == group.id || rule.dst_group_id == group.id {
                return Err(ControlPlaneError::GroupInUse(format!(
                    "Group '{}' is referenced by a policy",
                    name
                )));
            }
        }

        // Also check QoS rules
        for qos in &state.state.qos_rules {
            if qos.group_id == group.id {
                return Err(ControlPlaneError::GroupInUse(format!(
                    "Group '{}' is referenced by a QoS rule",
                    name
                )));
            }
        }

        // Also check mirror rules
        for mr in &state.state.mirror_rules {
            if mr.src_group_id == group.id || mr.dst_group_id == group.id {
                return Err(ControlPlaneError::GroupInUse(format!(
                    "Group '{}' is referenced by a mirror rule",
                    name
                )));
            }
        }

        // Delete from kernel
        let mut errors = Vec::new();
        let mut deleted_networks: Vec<(&'static str, String)> = Vec::new();
        let acl_bank = aria_core::ebpf_ops::read_acl_active_bank(state.map_runtime())
            .map_err(ControlPlaneError::KernelError)?;
        for cidr in &group.cidrs {
            match aria_core::ebpf_ops::delete_network(
                "src",
                cidr,
                group.id,
                state.map_runtime(),
                &self.ebpf_path,
            ) {
                Ok(()) => deleted_networks.push(("src", cidr.clone())),
                Err(e) => errors.push(format!("src {}: {}", cidr, e)),
            }
            match aria_core::ebpf_ops::delete_network(
                "dst",
                cidr,
                group.id,
                state.map_runtime(),
                &self.ebpf_path,
            ) {
                Ok(()) => deleted_networks.push(("dst", cidr.clone())),
                Err(e) => errors.push(format!("dst {}: {}", cidr, e)),
            }
            match aria_core::ebpf_ops::delete_acl_network_in_bank(
                "src",
                cidr,
                group.id,
                acl_bank,
                state.map_runtime(),
                &self.ebpf_path,
            ) {
                Ok(()) => {}
                Err(e) => errors.push(format!("acl src {}: {}", cidr, e)),
            }
            match aria_core::ebpf_ops::delete_acl_network_in_bank(
                "dst",
                cidr,
                group.id,
                acl_bank,
                state.map_runtime(),
                &self.ebpf_path,
            ) {
                Ok(()) => {}
                Err(e) => errors.push(format!("acl dst {}: {}", cidr, e)),
            }
        }
        if !errors.is_empty() {
            let rollback = Self::rollback_group_deletes(
                state.map_runtime(),
                &self.ebpf_path,
                group.id,
                &deleted_networks,
            );
            let error = match rollback {
                Ok(()) => errors.join("; "),
                Err(rollback_err) => {
                    format!("{}; rollback failed: {}", errors.join("; "), rollback_err)
                }
            };
            return Err(ControlPlaneError::KernelError(error));
        }

        state.state.groups.remove(name);
        state
            .wal_append(&WalEntry::DeleteGroup {
                name: name.to_string(),
            })
            .await;

        // Clear stale GROUP_STATS entries so the deleted group no longer appears in API responses.
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

        let target_directions = Self::requested_directions(direction);
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
        let inst = self.get_instance(instance).await?;
        let mut state = inst.write().await;
        Self::check_runtime_maps_ready(&state.pin_path)?;

        let group_id = if group_name == "default" || group_name == "any" {
            0
        } else {
            state
                .state
                .groups
                .get(group_name)
                .map(|g| g.id)
                .ok_or_else(|| ControlPlaneError::GroupNotFound(group_name.to_string()))?
        };

        let fq_state = if mode == 1 {
            let iface = Self::runtime_iface_name(instance, &state)?;
            match aria_core::ebpf_ops::ensure_fq_qdisc(&iface) {
                Ok(aria_core::ebpf_ops::FqQdiscState::InstalledNow) => {
                    Self::mark_owned_fq_qdisc(&state, &iface)?;
                    Some(aria_core::ebpf_ops::FqQdiscState::InstalledNow)
                }
                Ok(aria_core::ebpf_ops::FqQdiscState::AlreadyPresent) => {
                    Some(aria_core::ebpf_ops::FqQdiscState::AlreadyPresent)
                }
                Err(e) => {
                    return Err(ControlPlaneError::KernelError(format!(
                        "[{}] failed to prepare FQ qdisc for QoS shaping: {}",
                        iface, e
                    )));
                }
            }
        } else {
            None
        };

        // Write to kernel
        if let Err(e) = aria_core::qos_ops::add_qos_rule(
            group_id,
            direction,
            rate_bps,
            burst_bytes,
            priority,
            mode,
            state.map_runtime(),
            state.state.qos_enabled,
        ) {
            if matches!(
                fq_state,
                Some(aria_core::ebpf_ops::FqQdiscState::InstalledNow)
            ) {
                Self::rollback_installed_fq_qdisc(instance, &state);
            }
            return Err(ControlPlaneError::KernelError(e));
        }

        // Update in-memory state
        state
            .state
            .qos_rules
            .retain(|r| !(r.group_id == group_id && r.direction == direction));
        state.state.qos_rules.push(QosRuleInfo {
            group_name: group_name.to_string(),
            group_id,
            direction,
            rate_bps,
            burst_bytes,
            priority,
            mode,
        });

        state
            .wal_append(&WalEntry::AddQos {
                group_name: group_name.to_string(),
                group_id,
                direction,
                rate_bps,
                burst_bytes,
                priority,
                mode,
            })
            .await;
        Ok(())
    }

    pub async fn delete_qos(
        &self,
        instance: &str,
        group_name: &str,
        direction: u8,
    ) -> Result<(), ControlPlaneError> {
        let inst = self.get_instance(instance).await?;
        let mut state = inst.write().await;
        Self::check_runtime_maps_ready(&state.pin_path)?;

        let group_id = if group_name == "default" || group_name == "any" {
            0
        } else {
            state
                .state
                .groups
                .get(group_name)
                .map(|g| g.id)
                .ok_or_else(|| ControlPlaneError::GroupNotFound(group_name.to_string()))?
        };

        let target_directions = Self::requested_directions(direction);
        let matching_rules: Vec<QosRuleInfo> = target_directions
            .iter()
            .filter_map(|dir| {
                state
                    .state
                    .qos_rules
                    .iter()
                    .find(|r| r.group_id == group_id && r.direction == *dir)
                    .cloned()
            })
            .collect();
        if matching_rules.is_empty() {
            return Err(ControlPlaneError::PolicyNotFound(format!(
                "QoS rule not found: group={}, direction={}",
                group_name, direction
            )));
        }

        let mut deleted_rules: Vec<QosRuleInfo> = Vec::new();
        for rule in &matching_rules {
            if let Err(e) = aria_core::qos_ops::delete_qos_rule(
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
                    Ok(()) => e,
                    Err(rollback_err) => format!("{}; rollback failed: {}", e, rollback_err),
                };
                return Err(ControlPlaneError::KernelError(error));
            }
            deleted_rules.push(rule.clone());
        }

        for rule in &matching_rules {
            state
                .state
                .qos_rules
                .retain(|r| !(r.group_id == rule.group_id && r.direction == rule.direction));
            state
                .wal_append(&WalEntry::DeleteQos {
                    group_id: rule.group_id,
                    direction: rule.direction,
                })
                .await;

            // Clear stale QOS_STATS entries so deleted rules no longer appear in API responses.
            if let Err(e) = aria_core::monitoring::clear_qos_stats_for_rule(
                state.map_runtime(),
                rule.group_id,
                rule.direction,
            ) {
                warn!(error = %e, group_id = rule.group_id, direction = rule.direction,
                    "failed to clear qos stats after qos rule delete");
            }
        }

        // If no shaping rules remain, clean up the owned fq qdisc.
        let has_shaping = state.state.qos_rules.iter().any(|r| r.mode == 1);
        if !has_shaping {
            let marker_path = Self::fq_qdisc_marker_path(&state);
            if marker_path.exists() {
                if let Ok(iface) = Self::runtime_iface_name(instance, &state) {
                    if let Err(e) = aria_core::ebpf_ops::cleanup_root_qdisc(&iface) {
                        warn!(instance = %instance, iface = %iface, error = %e,
                            "failed to remove owned fq qdisc after last shaping rule deleted");
                    }
                }
                if let Err(e) = fs::remove_file(&marker_path) {
                    if e.kind() != std::io::ErrorKind::NotFound {
                        warn!(instance = %instance, path = %marker_path.display(), error = %e,
                            "failed to remove fq qdisc ownership marker");
                    }
                }
            }
        }

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
        let inst = self.get_instance(instance).await?;
        let mut state = inst.write().await;
        Self::check_runtime_maps_ready(&state.pin_path)?;

        let src_id = self.resolve_group_id(&state.state, src_group)?;
        let dst_id = self.resolve_group_id(&state.state, dst_group)?;

        let target_ifindex = aria_core::mirror_ops::resolve_ifindex(target_iface)
            .map_err(|e| ControlPlaneError::ValidationError(e))?;

        let is_global = src_id == 0 && dst_id == 0 && proto == 0;

        if is_global {
            if let Err(e) = aria_core::mirror_ops::add_global_mirror(
                direction,
                target_ifindex,
                state.map_runtime(),
                state.state.mirror_enabled,
            ) {
                return Err(ControlPlaneError::KernelError(e));
            }
        } else {
            if let Err(e) = aria_core::mirror_ops::add_mirror_rule(
                src_id,
                dst_id,
                proto,
                direction,
                target_ifindex,
                state.map_runtime(),
                state.state.mirror_enabled,
            ) {
                return Err(ControlPlaneError::KernelError(e));
            }
        }

        // Update in-memory state
        if is_global {
            state
                .state
                .mirror_rules
                .retain(|r| !(r.is_global && r.direction == direction));
        } else {
            state.state.mirror_rules.retain(|r| {
                !(r.src_group_id == src_id
                    && r.dst_group_id == dst_id
                    && r.proto == proto
                    && r.direction == direction
                    && !r.is_global)
            });
        }
        state.state.mirror_rules.push(MirrorRuleInfo {
            src_group_name: src_group.to_string(),
            src_group_id: src_id,
            dst_group_name: dst_group.to_string(),
            dst_group_id: dst_id,
            proto,
            direction,
            target_iface: target_iface.to_string(),
            target_ifindex,
            is_global,
        });

        state
            .wal_append(&WalEntry::AddMirror {
                src_group_name: src_group.to_string(),
                src_group_id: src_id,
                dst_group_name: dst_group.to_string(),
                dst_group_id: dst_id,
                proto,
                direction,
                target_iface: target_iface.to_string(),
                target_ifindex,
                is_global,
            })
            .await;
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
        let inst = self.get_instance(instance).await?;
        let mut state = inst.write().await;
        Self::check_runtime_maps_ready(&state.pin_path)?;

        let src_id = self.resolve_group_id(&state.state, src_group)?;
        let dst_id = self.resolve_group_id(&state.state, dst_group)?;

        let is_global = src_id == 0 && dst_id == 0 && proto == 0;

        let target_directions = Self::requested_directions(direction);
        let matching_rules: Vec<MirrorRuleInfo> = target_directions
            .iter()
            .filter_map(|dir| {
                state
                    .state
                    .mirror_rules
                    .iter()
                    .find(|r| {
                        if is_global {
                            r.is_global && r.direction == *dir
                        } else {
                            !r.is_global
                                && r.src_group_id == src_id
                                && r.dst_group_id == dst_id
                                && r.proto == proto
                                && r.direction == *dir
                        }
                    })
                    .cloned()
            })
            .collect();
        if matching_rules.is_empty() {
            return Err(ControlPlaneError::PolicyNotFound(
                "Mirror rule not found".to_string(),
            ));
        }

        let mut deleted_rules: Vec<MirrorRuleInfo> = Vec::new();
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
            if let Err(e) = result {
                let rollback = Self::rollback_mirror_deletes(
                    state.map_runtime(),
                    &deleted_rules,
                    state.state.mirror_enabled,
                );
                let error = match rollback {
                    Ok(()) => e,
                    Err(rollback_err) => format!("{}; rollback failed: {}", e, rollback_err),
                };
                return Err(ControlPlaneError::KernelError(error));
            }
            deleted_rules.push(rule.clone());
        }

        for rule in &matching_rules {
            let clear_stats_result = if rule.is_global {
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
            if let Err(e) = clear_stats_result {
                warn!(
                    instance,
                    src_group_id = rule.src_group_id,
                    dst_group_id = rule.dst_group_id,
                    proto = rule.proto,
                    direction = rule.direction,
                    is_global = rule.is_global,
                    error = %e,
                    "failed to clear mirror stats after delete"
                );
            }

            if rule.is_global {
                state
                    .state
                    .mirror_rules
                    .retain(|r| !(r.is_global && r.direction == rule.direction));
            } else {
                state.state.mirror_rules.retain(|r| {
                    !(r.src_group_id == rule.src_group_id
                        && r.dst_group_id == rule.dst_group_id
                        && r.proto == rule.proto
                        && r.direction == rule.direction
                        && !r.is_global)
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
        }
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

    pub async fn flush_conntrack_strict(
        &self,
        instance: &str,
    ) -> Result<u64, ControlPlaneError> {
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
    ) -> Result<(), ControlPlaneError> {
        let inst = self.get_instance(instance).await?;
        let mut state = inst.write().await;
        if neutron_acl_gate_requires_tc(conntrack_enabled, acl_enabled) {
            Self::require_tc_acl_ready_locked(instance, &state, self.trace_map_mode())?;
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
        state
            .wal_append(&WalEntry::UpdateConfig {
                conntrack,
                monitoring,
                acl,
                qos,
                mirror,
                tcprt,
                ssl: None,
            })
            .await;
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

        assert!(tokio::time::timeout(std::time::Duration::from_millis(20), &mut waiter)
            .await
            .is_err());
        drop(held);
        assert!(tokio::time::timeout(std::time::Duration::from_secs(1), waiter)
            .await
            .unwrap()
            .unwrap());
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
    fn neutron_acl_gate_serialization_requires_tc_only_for_enabling_writes() {
        assert!(!neutron_acl_gate_requires_tc(false, false));
        assert!(neutron_acl_gate_requires_tc(true, false));
        assert!(neutron_acl_gate_requires_tc(false, true));
        assert!(neutron_acl_gate_requires_tc(true, true));
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
            .recover_gate_persistence_failure(true, true, "forced persistence failure", |ct, acl| {
                kernel_writes.push((ct, acl));
                Ok(())
            })
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
        assert!(error.to_string().contains("forced local persistence failure"));
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
            attempted.push(mutation.clone());
            if attempted.len() == 1 {
                Err("forced first rollback failure".to_string())
            } else {
                Ok(())
            }
        })
        .unwrap_err();

        assert_eq!(
            attempted,
            vec![mutations[1].clone(), mutations[0].clone()]
        );
        assert!(error.contains("forced first rollback failure"));
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
        cp.mark_neutron_port_authority(
            "tap-vm",
            "port-vm",
            &["acl".to_string()],
            7,
        )
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
