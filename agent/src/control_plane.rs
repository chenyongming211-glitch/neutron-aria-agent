use std::collections::{BTreeSet, HashMap, HashSet};
use std::fs;
use std::path::Path;
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};
use tracing::{error, info, warn};

use crate::instance::RuntimePinState;
use crate::kernel_drop_manager::{KernelDropManager, KernelDropStatusSnapshot};
use crate::service_chain::{self, ServiceChain};
use crate::ssl_manager::SslManager;
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

    /// Append a WAL entry. If append fails, attempt a full compact as fallback
    /// to ensure the current state is persisted despite the individual write failure.
    async fn wal_append(&mut self, entry: &WalEntry) {
        if let Err(e) = self.wal.append(entry.clone()).await {
            error!(
                state_path = %self.state_path,
                error = %e,
                "WAL append failed; attempting compact fallback"
            );
            self.do_compact().await;
        }
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
    InstanceNotReady(String),
    LocalWriteBlocked { instance: String, domain: String },
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
            Self::InstanceNotReady(s) => write!(f, "Instance not ready: {}", s),
            Self::LocalWriteBlocked { instance, domain } => write!(
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
            Self::InstanceNotReady(_) => 503,
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
        for rule in deleted_rules {
            aria_core::ebpf_ops::add_policy(
                rule.src_group_id,
                rule.dst_group_id,
                rule.proto,
                rule.action,
                rule.ports.as_deref(),
                rule.bitmap_idx,
                false,
                rule.direction,
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
        for (direction, cidr) in deleted_networks.iter().rev() {
            aria_core::ebpf_ops::add_network(direction, cidr, group_id, runtime, ebpf_path)?;
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
        if authorities
            .get(instance)
            .map(|authority| authority.managed_domains.contains(domain_name))
            .unwrap_or(false)
        {
            return Err(ControlPlaneError::LocalWriteBlocked {
                instance: instance.to_string(),
                domain: domain_name.to_string(),
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
        let preserve_existing_runtime = replacing_existing || pin_state.preexisting_xdp_link;
        let mut iface_ctx_synced = false;
        let mut tap_config_written = false;

        if pin_state.preexisting_xdp_link {
            if let Err(e) =
                self.validate_preexisting_live_runtime(name, &pin_path, tap_id, ifindex, &state)
            {
                wal.shutdown().await;
                return Err(e);
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

        if !pin_state.preexisting_xdp_link {
            if let Err(e) = aria_core::ebpf_ops::update_runtime_config(
                TapMapRuntime::new(&pin_path, tap_id),
                Some(state.conntrack_enabled),
                Some(state.monitoring_enabled),
                Some(state.acl_enabled),
                Some(state.qos_enabled && !state.qos_rules.is_empty()),
                Some(state.mirror_enabled && !state.mirror_rules.is_empty()),
                Some(state.tcprt_enabled),
                None,
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
            desired_ssl_enabled: if pin_state.preexisting_xdp_link {
                None
            } else {
                global_ssl_enabled
            },
            preserve_existing_runtime,
            iface_ctx_synced,
            tap_config_written,
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

    fn check_xdp_ready(pin_path: &str) -> Result<(), ControlPlaneError> {
        let cfg_path = format!("{}/FIREWALL_CONFIG", pin_path);
        if !std::path::Path::new(&cfg_path).exists() {
            return Err(ControlPlaneError::InstanceNotReady(
                "Pinned firewall maps not ready".to_string(),
            ));
        }
        Ok(())
    }

    // ── Groups ──

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
        Self::check_xdp_ready(&state.pin_path)?;

        // Check if this is a new group (for rollback)
        let was_new_group = !state.state.groups.contains_key(name);

        // Modify in-memory state
        let id = state
            .state
            .add_group(name, cidr)
            .map_err(|e| ControlPlaneError::ValidationError(e))?;

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
        Self::check_xdp_ready(&state.pin_path)?;

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
        Self::check_xdp_ready(&state.pin_path)?;

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

        // Write to kernel
        if let Err(e) = aria_core::ebpf_ops::add_policy(
            src_id,
            dst_id,
            proto,
            action,
            ports,
            add_result.bitmap_idx,
            add_result.is_new_port_set,
            direction,
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
        Self::check_xdp_ready(&state.pin_path)?;

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
        for rule in &matching_rules {
            if let Err(e) = aria_core::ebpf_ops::delete_policy(
                rule.src_group_id,
                rule.dst_group_id,
                rule.proto,
                rule.direction,
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
        Self::check_xdp_ready(&state.pin_path)?;

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
        Self::check_xdp_ready(&state.pin_path)?;

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
        Self::check_xdp_ready(&state.pin_path)?;

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
        Self::check_xdp_ready(&state.pin_path)?;

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
        Self::check_xdp_ready(&state.pin_path)?;

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

        assert!(
            cp.ensure_local_write_allowed("tap-vm", LocalWriteDomain::Acl)
                .await
                .is_err()
        );
        assert!(
            cp.ensure_local_write_allowed("tap-vm", LocalWriteDomain::Mirror)
                .await
                .is_err()
        );
        assert!(
            cp.ensure_local_write_allowed("tap-vm", LocalWriteDomain::Qos)
                .await
                .is_ok()
        );
        assert!(
            cp.ensure_local_write_allowed("tap-vm", LocalWriteDomain::Trace)
                .await
                .is_ok()
        );
        assert!(
            cp.ensure_local_group_write_allowed("tap-vm", "neutron:acl-source")
                .await
                .is_err()
        );
        assert!(
            cp.ensure_local_group_write_allowed("tap-vm", "local-qos-group")
                .await
                .is_ok()
        );
    }
}
