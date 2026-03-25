use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};
use tracing::{error, info, warn};

use aria_core::common::TapMapRuntime;
use aria_core::state::{FirewallState, GroupInfo, RuleInfo, QosRuleInfo, MirrorRuleInfo};
use aria_core::wal::{WalClient, WalEntry};
use crate::service_chain::{ServiceChain, self};
use crate::ssl_manager::SslManager;

const WAL_COMPACT_THRESHOLD: u64 = 1000;
pub const MANAGED_SHARED_PIN_NAMESPACE: &str = "global-v2";

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

pub struct ControlPlane {
    instances: RwLock<HashMap<String, Arc<tokio::sync::RwLock<InstanceState>>>>,
    tap_id_lock: Mutex<()>,
    pub ebpf_path: String,
    pub base_pin_path: String,
    pub base_state_path: String,
    ssl_manager: Arc<SslManager>,
    chains: RwLock<Vec<ServiceChain>>,
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
        }
    }
}

impl ControlPlaneError {
    pub fn status_code(&self) -> u16 {
        match self {
            Self::ValidationError(_) => 400,
            Self::InstanceNotFound(_) | Self::GroupNotFound(_) | Self::PolicyNotFound(_) => 404,
            Self::GroupInUse(_) => 409,
            Self::KernelError(_) => 500,
            Self::InstanceNotReady(_) => 503,
        }
    }
}

impl ControlPlane {
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
        if !preserve_existing_runtime && tap_config_written && tap_id != aria_core::common::TAP_ID_UNASSIGNED {
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

    pub fn new(
        ebpf_path: &str,
        base_pin_path: &str,
        base_state_path: &str,
        ssl_manager: Arc<SslManager>,
    ) -> Self {
        let chains = service_chain::load_chains(base_state_path);
        Self {
            instances: RwLock::new(HashMap::new()),
            tap_id_lock: Mutex::new(()),
            ebpf_path: ebpf_path.to_string(),
            base_pin_path: base_pin_path.to_string(),
            base_state_path: base_state_path.to_string(),
            ssl_manager,
            chains: RwLock::new(chains),
        }
    }

    pub fn managed_pin_path(&self) -> String {
        format!("{}/{}", self.base_pin_path, MANAGED_SHARED_PIN_NAMESPACE)
    }

    pub async fn prepare_managed_instance(&self, name: &str) -> Result<u32, String> {
        let state_path = format!("{}/{}", self.base_state_path, name);
        let mut state = aria_core::wal::load_with_wal(&state_path);
        let tap_id_assigned = self.ensure_managed_tap_id(name, &mut state).await?;

        if tap_id_assigned {
            let state_manager = aria_core::state::StateManager::new(&state_path);
            state_manager
                .set_tap_id(state.tap_id)
                .map_err(|e| format!("failed to persist tap_id for {}: {}", name, e))?;
            info!(instance = %name, tap_id = state.tap_id, "prepared managed tap state");
        }

        Ok(state.tap_id)
    }

    /// Register an instance (called when TapRegistry attaches a tap).
    /// Replays persisted state into pinned maps before exposing the instance via API.
    pub async fn register_instance(&self, name: &str) -> Result<(), String> {
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
        let runtime = TapMapRuntime::new(&pin_path, tap_id);
        if !replacing_existing {
            if let Err(e) = aria_core::ebpf_ops::scrub_managed_runtime_state(runtime) {
                wal.shutdown().await;
                return Err(format!("failed to scrub stale tap runtime state: {}", e));
            }
        } else {
            info!(instance = %name, tap_id, "skipping pre-replay scrub while replacing existing registered instance");
        }
        if let Err(e) = aria_core::ebpf_ops::sync_iface_ctx(runtime, ifindex) {
            wal.shutdown().await;
            return Err(e);
        }

        let mut tap_config_written = false;
        if let Err(e) = aria_core::ebpf_ops::update_runtime_config(
            runtime,
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
                replacing_existing,
                true,
                tap_config_written,
            )
            .await;
            return Err(e);
        }
        tap_config_written = tap_id != aria_core::common::TAP_ID_UNASSIGNED;

        if let Err(e) = aria_core::ebpf_ops::replay_state_to_pinned_maps(&pin_path, &state_path) {
            Self::cleanup_failed_managed_registration(
                name,
                &pin_path,
                tap_id,
                ifindex,
                wal,
                replacing_existing,
                true,
                tap_config_written,
            )
            .await;
            return Err(e);
        }

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

        if let Some(enabled) = global_ssl_enabled {
            let _ = self
                .reconcile_instance_ssl_state(name, &instance, enabled)
                .await;
        }

        info!(instance = %name, tap_id, ifindex, "registered instance");
        Ok(())
    }

    /// Register the "system" instance (standalone mode)
    pub async fn register_system_instance(&self, pin_path: &str, state_path: &str) -> Result<(), String> {
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
            ifindex: None,
            pin_path: pin_path.to_string(),
            state_path: state_path.to_string(),
            wal,
            ssl_sync_pending: false,
            last_ssl_sync_error: None,
        }));

        let mut instances = self.instances.write().await;
        instances.insert("system".to_string(), instance.clone());
        drop(instances);

        if let Some(enabled) = global_ssl_enabled {
            let _ = self
                .reconcile_instance_ssl_state("system", &instance, enabled)
                .await;
        }

        info!(instance = "system", tap_id, "registered system instance");
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
                if let Err(e) = aria_core::ebpf_ops::clear_iface_ctx(&state.pin_path, ifindex) {
                    warn!(instance = %name, tap_id, ifindex, error = %e, "failed to clear iface context");
                }
            }
            if tap_id != aria_core::common::TAP_ID_UNASSIGNED {
                if let Err(e) = aria_core::ebpf_ops::delete_tap_config(state.map_runtime()) {
                    warn!(instance = %name, tap_id, error = %e, "failed to clear tap runtime config");
                }
                if let Err(e) = aria_core::trace_ops::clear_trace_filter(state.map_runtime()) {
                    warn!(instance = %name, tap_id, error = %e, "failed to clear trace filter");
                }
                if let Err(e) = aria_core::trace_ops::flush_trace_log(state.map_runtime()) {
                    warn!(instance = %name, tap_id, error = %e, "failed to flush trace log");
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

    async fn get_instance(&self, name: &str) -> Result<Arc<tokio::sync::RwLock<InstanceState>>, ControlPlaneError> {
        let instances = self.instances.read().await;
        instances.get(name).cloned().ok_or_else(|| ControlPlaneError::InstanceNotFound(name.to_string()))
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

    pub async fn add_group(&self, instance: &str, name: &str, cidr: &str) -> Result<u32, ControlPlaneError> {
        let inst = self.get_instance(instance).await?;
        let mut state = inst.write().await;
        Self::check_xdp_ready(&state.pin_path)?;

        // Check if this is a new group (for rollback)
        let was_new_group = !state.state.groups.contains_key(name);

        // Modify in-memory state
        let id = state.state.add_group(name, cidr)
            .map_err(|e| ControlPlaneError::ValidationError(e))?;

        // Write to kernel maps
        if let Err(e) = aria_core::ebpf_ops::add_network("src", cidr, id, state.map_runtime(), &self.ebpf_path) {
            state.state.rollback_add_group(name, cidr, was_new_group);
            return Err(ControlPlaneError::KernelError(format!("src: {}", e)));
        }
        if let Err(e) = aria_core::ebpf_ops::add_network("dst", cidr, id, state.map_runtime(), &self.ebpf_path) {
            let _ = aria_core::ebpf_ops::delete_network("src", cidr, id, state.map_runtime(), &self.ebpf_path);
            state.state.rollback_add_group(name, cidr, was_new_group);
            return Err(ControlPlaneError::KernelError(format!("dst: {}", e)));
        }

        state.wal_append(&WalEntry::AddGroup {
            name: name.to_string(),
            cidr: cidr.to_string(),
        }).await;
        Ok(id)
    }

    pub async fn delete_group(&self, instance: &str, name: &str) -> Result<(), ControlPlaneError> {
        let inst = self.get_instance(instance).await?;
        let mut state = inst.write().await;
        Self::check_xdp_ready(&state.pin_path)?;

        let group = state.state.groups.get(name)
            .ok_or_else(|| ControlPlaneError::GroupNotFound(name.to_string()))?
            .clone();

        // Check if group is referenced by any rule
        for rule in &state.state.rules {
            if rule.src_group_id == group.id || rule.dst_group_id == group.id {
                return Err(ControlPlaneError::GroupInUse(
                    format!("Group '{}' is referenced by a policy", name)
                ));
            }
        }

        // Also check QoS rules
        for qos in &state.state.qos_rules {
            if qos.group_id == group.id {
                return Err(ControlPlaneError::GroupInUse(
                    format!("Group '{}' is referenced by a QoS rule", name)
                ));
            }
        }

        // Also check mirror rules
        for mr in &state.state.mirror_rules {
            if mr.src_group_id == group.id || mr.dst_group_id == group.id {
                return Err(ControlPlaneError::GroupInUse(
                    format!("Group '{}' is referenced by a mirror rule", name)
                ));
            }
        }

        // Delete from kernel
        let mut errors = Vec::new();
        for cidr in &group.cidrs {
            if let Err(e) = aria_core::ebpf_ops::delete_network("src", cidr, group.id, state.map_runtime(), &self.ebpf_path) {
                errors.push(format!("src {}: {}", cidr, e));
            }
            if let Err(e) = aria_core::ebpf_ops::delete_network("dst", cidr, group.id, state.map_runtime(), &self.ebpf_path) {
                errors.push(format!("dst {}: {}", cidr, e));
            }
        }
        if !errors.is_empty() {
            return Err(ControlPlaneError::KernelError(errors.join("; ")));
        }

        state.state.groups.remove(name);
        state.wal_append(&WalEntry::DeleteGroup {
            name: name.to_string(),
        }).await;
        Ok(())
    }

    // ── Groups with Stats (Aggregation) ──

    pub async fn list_groups_with_stats(&self, instance: &str) -> Result<(Vec<GroupInfo>, Vec<aria_core::monitoring::GroupStatsEntry>), ControlPlaneError> {
        // Get groups configuration
        let inst = self.get_instance(instance).await?;
        let state = inst.read().await;
        let groups: Vec<_> = state.state.groups.values().cloned().collect();
        let stats = aria_core::monitoring::get_group_stats(state.map_runtime())
            .map_err(|e| ControlPlaneError::KernelError(e))?;

        Ok((groups, stats))
    }

    // ── Policies ──

    pub async fn list_policies(&self, instance: &str) -> Result<(Vec<RuleInfo>, HashMap<String, GroupInfo>), ControlPlaneError> {
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

        // Snapshot state for rollback (clone the parts that apply_add_rule mutates)
        let snapshot_rules = state.state.rules.clone();
        let snapshot_port_sets = state.state.port_sets.clone();
        let snapshot_free_indices = state.state.free_bitmap_indices.clone();
        let snapshot_next_bitmap_idx = state.state.next_bitmap_idx;

        // Operate directly on in-memory state (no StateManager disk round-trip)
        let add_result = state.state.apply_add_rule(src_id, dst_id, proto, action, ports, direction)
            .map_err(|e| ControlPlaneError::ValidationError(e))?;

        // Write to kernel
        if let Err(e) = aria_core::ebpf_ops::add_policy(
            src_id, dst_id, proto, action, ports,
            add_result.bitmap_idx, add_result.is_new_port_set,
            direction, state.map_runtime(), &self.ebpf_path,
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
            if let Err(e) = aria_core::ebpf_ops::delete_port_set(old_idx, ports_normalized, state.map_runtime(), &self.ebpf_path) {
                warn!(error = %e, "failed to clean old port bitmap");
            }
        }

        state.wal_append(&WalEntry::AddRule {
            src_id,
            dst_id,
            proto,
            action,
            ports: ports.map(|s| s.to_string()),
            direction,
        }).await;
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

        // Validate rule exists in state before touching kernel
        let rule_exists = state.state.rules.iter().any(|r| {
            r.src_group_id == src_id
                && r.dst_group_id == dst_id
                && r.proto == proto
                && r.direction == direction
        });
        if !rule_exists {
            return Err(ControlPlaneError::PolicyNotFound(
                format!("Policy not found: src={}, dst={}, proto={}, direction={}", src_group, dst_group, proto, direction)
            ));
        }

        // Delete from kernel
        if let Err(e) = aria_core::ebpf_ops::delete_policy(src_id, dst_id, proto, direction, state.map_runtime(), &self.ebpf_path) {
            return Err(ControlPlaneError::KernelError(e));
        }

        // Remove from in-memory state
        let remove_result = state.state.apply_remove_rule(src_id, dst_id, proto, direction)
            .map_err(|e| ControlPlaneError::PolicyNotFound(e))?;

        if let (Some(idx), Some(ref ports_normalized)) = (remove_result.bitmap_idx, &remove_result.port_set_released) {
            if let Err(e) = aria_core::ebpf_ops::delete_port_set(idx, ports_normalized, state.map_runtime(), &self.ebpf_path) {
                warn!(error = %e, "failed to clean port bitmap");
            }
        }

        state.wal_append(&WalEntry::RemoveRule {
            src_id,
            dst_id,
            proto,
            direction,
        }).await;
        Ok(())
    }

    // ── Policies with Stats (Aggregation) ──

    pub async fn list_policies_with_stats(&self, instance: &str) -> Result<(Vec<aria_core::state::RuleInfo>, Vec<aria_core::monitoring::RuleStatsEntry>), ControlPlaneError> {
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
            state.state.groups.get(group_name)
                .map(|g| g.id)
                .ok_or_else(|| ControlPlaneError::GroupNotFound(group_name.to_string()))?
        };

        // Write to kernel
        if let Err(e) = aria_core::qos_ops::add_qos_rule(group_id, direction, rate_bps, burst_bytes, priority, mode, state.map_runtime(), state.state.qos_enabled) {
            return Err(ControlPlaneError::KernelError(e));
        }

        // Update in-memory state
        state.state.qos_rules.retain(|r| !(r.group_id == group_id && r.direction == direction));
        state.state.qos_rules.push(QosRuleInfo {
            group_name: group_name.to_string(),
            group_id,
            direction,
            rate_bps,
            burst_bytes,
            priority,
            mode,
        });

        state.wal_append(&WalEntry::AddQos {
            group_name: group_name.to_string(),
            group_id,
            direction,
            rate_bps,
            burst_bytes,
            priority,
            mode,
        }).await;
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
            state.state.groups.get(group_name)
                .map(|g| g.id)
                .ok_or_else(|| ControlPlaneError::GroupNotFound(group_name.to_string()))?
        };

        // Validate rule exists in state BEFORE deleting from kernel
        let exists = state.state.qos_rules.iter().any(|r| r.group_id == group_id && r.direction == direction);
        if !exists {
            return Err(ControlPlaneError::PolicyNotFound(
                format!("QoS rule not found: group={}, direction={}", group_name, direction)
            ));
        }

        if let Err(e) = aria_core::qos_ops::delete_qos_rule(group_id, direction, state.map_runtime(), state.state.qos_enabled) {
            return Err(ControlPlaneError::KernelError(e));
        }

        state.state.qos_rules.retain(|r| !(r.group_id == group_id && r.direction == direction));
        state.wal_append(&WalEntry::DeleteQos {
            group_id,
            direction,
        }).await;
        Ok(())
    }

    // ── QoS with Stats (Aggregation) ──

    pub async fn list_qos_with_stats(&self, instance: &str) -> Result<(Vec<QosRuleInfo>, Vec<aria_core::monitoring::QosStatsEntry>), ControlPlaneError> {
        // Get QoS configuration
        let inst = self.get_instance(instance).await?;
        let state = inst.read().await;
        let rules = state.state.qos_rules.clone();
        let stats = aria_core::monitoring::get_qos_stats(state.map_runtime())
            .map_err(|e| ControlPlaneError::KernelError(e))?;

        Ok((rules, stats))
    }

    // ── Mirror ──

    pub async fn list_mirror(&self, instance: &str) -> Result<Vec<MirrorRuleInfo>, ControlPlaneError> {
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
            if let Err(e) = aria_core::mirror_ops::add_global_mirror(direction, target_ifindex, state.map_runtime(), state.state.mirror_enabled) {
                return Err(ControlPlaneError::KernelError(e));
            }
        } else {
            if let Err(e) = aria_core::mirror_ops::add_mirror_rule(src_id, dst_id, proto, direction, target_ifindex, state.map_runtime(), state.state.mirror_enabled) {
                return Err(ControlPlaneError::KernelError(e));
            }
        }

        // Update in-memory state
        if is_global {
            state.state.mirror_rules.retain(|r| !(r.is_global && r.direction == direction));
        } else {
            state.state.mirror_rules.retain(|r| !(r.src_group_id == src_id && r.dst_group_id == dst_id && r.proto == proto && r.direction == direction && !r.is_global));
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

        state.wal_append(&WalEntry::AddMirror {
            src_group_name: src_group.to_string(),
            src_group_id: src_id,
            dst_group_name: dst_group.to_string(),
            dst_group_id: dst_id,
            proto,
            direction,
            target_iface: target_iface.to_string(),
            target_ifindex,
            is_global,
        }).await;
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

        // Validate rule exists
        let exists = if is_global {
            state.state.mirror_rules.iter().any(|r| r.is_global && r.direction == direction)
        } else {
            state.state.mirror_rules.iter().any(|r| r.src_group_id == src_id && r.dst_group_id == dst_id && r.proto == proto && r.direction == direction && !r.is_global)
        };
        if !exists {
            return Err(ControlPlaneError::PolicyNotFound("Mirror rule not found".to_string()));
        }

        if is_global {
            if let Err(e) = aria_core::mirror_ops::delete_global_mirror(direction, state.map_runtime(), state.state.mirror_enabled) {
                return Err(ControlPlaneError::KernelError(e));
            }
        } else {
            if let Err(e) = aria_core::mirror_ops::delete_mirror_rule(src_id, dst_id, proto, direction, state.map_runtime(), state.state.mirror_enabled) {
                return Err(ControlPlaneError::KernelError(e));
            }
        }

        if is_global {
            state.state.mirror_rules.retain(|r| !(r.is_global && r.direction == direction));
        } else {
            state.state.mirror_rules.retain(|r| !(r.src_group_id == src_id && r.dst_group_id == dst_id && r.proto == proto && r.direction == direction && !r.is_global));
        }

        state.wal_append(&WalEntry::DeleteMirror {
            src_group_id: src_id,
            dst_group_id: dst_id,
            proto,
            direction,
            is_global,
        }).await;
        Ok(())
    }

    pub async fn get_mirror_stats(&self, instance: &str) -> Result<(Vec<aria_core::monitoring::MirrorStatsEntry>, HashMap<String, GroupInfo>), ControlPlaneError> {
        let inst = self.get_instance(instance).await?;
        let state = inst.read().await;
        let stats = aria_core::monitoring::get_mirror_stats(state.map_runtime())
            .map_err(|e| ControlPlaneError::KernelError(e))?;
        Ok((stats, state.state.groups.clone()))
    }

    // ── Mirror with Stats (Aggregation) ──

    pub async fn list_mirror_with_stats(&self, instance: &str) -> Result<(Vec<MirrorRuleInfo>, Vec<aria_core::monitoring::MirrorStatsEntry>), ControlPlaneError> {
        // Get mirror configuration
        let inst = self.get_instance(instance).await?;
        let state = inst.read().await;
        let rules = state.state.mirror_rules.clone();
        let stats = aria_core::monitoring::get_mirror_stats(state.map_runtime())
            .map_err(|e| ControlPlaneError::KernelError(e))?;

        Ok((rules, stats))
    }

    // ── Conntrack ──

    pub async fn list_conntrack(&self, instance: &str) -> Result<Vec<aria_core::ct_ops::CtEntry>, ControlPlaneError> {
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

    pub async fn get_config(&self, instance: &str) -> Result<aria_core::common::FirewallConfig, ControlPlaneError> {
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
        state.wal_append(&WalEntry::UpdateConfig {
            conntrack,
            monitoring,
            acl,
            qos,
            mirror,
            tcprt,
            ssl: None,
        }).await;
        Ok(())
    }

    // ── Global SSL Observability Config ──
    // SSL uprobe is process-level, not tied to any network interface

    pub async fn get_ssl_global_config(&self) -> Result<bool, ControlPlaneError> {
        self.ssl_manager.ensure_loaded().await
            .map_err(ControlPlaneError::KernelError)?;
        aria_core::ssl_ops::get_ssl_global_config(self.ssl_manager.pin_path())
            .map_err(|e| ControlPlaneError::KernelError(e))
    }

    pub async fn set_ssl_global_config(&self, enabled: bool) -> Result<(), ControlPlaneError> {
        self.ssl_manager.ensure_loaded().await
            .map_err(ControlPlaneError::KernelError)?;
        aria_core::ssl_ops::set_ssl_global_config(self.ssl_manager.pin_path(), enabled)
            .map_err(ControlPlaneError::KernelError)?;
        info!(enabled, "updated global SSL config");
        self.reconcile_ssl_runtime_state_with_desired(enabled).await;
        Ok(())
    }

    pub async fn get_ssl_errors(&self) -> Result<Vec<aria_core::ssl_ops::SslErrorEntry>, ControlPlaneError> {
        self.ssl_manager.ensure_loaded().await
            .map_err(ControlPlaneError::KernelError)?;
        aria_core::ssl_ops::get_ssl_errors(self.ssl_manager.pin_path())
            .map_err(|e| ControlPlaneError::KernelError(e))
    }

    pub async fn flush_ssl_errors(&self) -> Result<u64, ControlPlaneError> {
        self.ssl_manager.ensure_loaded().await
            .map_err(ControlPlaneError::KernelError)?;
        aria_core::ssl_ops::flush_ssl_errors(self.ssl_manager.pin_path())
            .map_err(|e| ControlPlaneError::KernelError(e))
    }

    // ── Stats ──

    pub async fn get_stats_overview(&self, instance: &str) -> Result<(usize, usize, usize, usize, u64, u64), ControlPlaneError> {
        let inst = self.get_instance(instance).await?;
        let state = inst.read().await;

        let ct_summary = aria_core::monitoring::get_conntrack_stats(state.map_runtime()).unwrap_or(
            aria_core::monitoring::ConntrackSummary {
                total_v4: 0, total_v6: 0, new_count: 0, established_count: 0,
            }
        );

        Ok((
            state.state.groups.len(),
            state.state.rules.len(),
            state.state.qos_rules.len(),
            state.state.mirror_rules.len(),
            ct_summary.total_v4,
            ct_summary.total_v6,
        ))
    }

    pub async fn get_ct_contract_stats(&self, instance: &str) -> Result<Vec<aria_core::ct_contract_ops::CtContractStatsEntry>, ControlPlaneError> {
        let inst = self.get_instance(instance).await?;
        let state = inst.read().await;
        aria_core::ct_contract_ops::get_ct_contract_stats(state.map_runtime())
            .map_err(ControlPlaneError::KernelError)
    }

    pub async fn get_rule_stats(&self, instance: &str) -> Result<(Vec<aria_core::monitoring::RuleStatsEntry>, HashMap<String, GroupInfo>), ControlPlaneError> {
        let inst = self.get_instance(instance).await?;
        let state = inst.read().await;
        let stats = aria_core::monitoring::get_rule_stats(state.map_runtime())
            .map_err(|e| ControlPlaneError::KernelError(e))?;
        Ok((stats, state.state.groups.clone()))
    }

    pub async fn get_top_flows(&self, instance: &str, top: usize) -> Result<(Vec<aria_core::monitoring::FlowStatsEntry>, Vec<aria_core::monitoring::FlowStatsEntryV6>), ControlPlaneError> {
        let inst = self.get_instance(instance).await?;
        let state = inst.read().await;
        let v4 = aria_core::monitoring::get_top_flows_v4(state.map_runtime(), top)
            .map_err(|e| ControlPlaneError::KernelError(e))?;
        let v6 = aria_core::monitoring::get_top_flows_v6(state.map_runtime(), top)
            .map_err(|e| ControlPlaneError::KernelError(e))?;
        Ok((v4, v6))
    }

    pub async fn get_qos_stats(&self, instance: &str) -> Result<(Vec<aria_core::monitoring::QosStatsEntry>, HashMap<String, GroupInfo>), ControlPlaneError> {
        let inst = self.get_instance(instance).await?;
        let state = inst.read().await;
        let stats = aria_core::monitoring::get_qos_stats(state.map_runtime())
            .map_err(|e| ControlPlaneError::KernelError(e))?;
        Ok((stats, state.state.groups.clone()))
    }

    pub async fn get_group_stats(&self, instance: &str) -> Result<(Vec<aria_core::monitoring::GroupStatsEntry>, HashMap<String, GroupInfo>), ControlPlaneError> {
        let inst = self.get_instance(instance).await?;
        let state = inst.read().await;
        let stats = aria_core::monitoring::get_group_stats(state.map_runtime())
            .map_err(|e| ControlPlaneError::KernelError(e))?;
        Ok((stats, state.state.groups.clone()))
    }

    // ── TCP-RT ──

    pub async fn list_tcprt(&self, instance: &str, top: usize) -> Result<Vec<aria_core::tcprt_ops::TcpRtEntry>, ControlPlaneError> {
        let inst = self.get_instance(instance).await?;
        let state = inst.read().await;
        aria_core::monitoring::get_tcprt_stats(state.map_runtime(), top)
            .map_err(|e| ControlPlaneError::KernelError(e))
    }

    pub async fn get_tcprt_metrics_summary(
        &self,
        instance: &str,
    ) -> Result<Option<aria_core::monitoring::TcprtMetricsSummary>, ControlPlaneError> {
        let inst = self.get_instance(instance).await?;
        let state = inst.read().await;
        aria_core::monitoring::get_tcprt_metrics_summary(state.map_runtime())
            .map_err(ControlPlaneError::KernelError)
    }

    pub async fn flush_tcprt(&self, instance: &str) -> Result<u64, ControlPlaneError> {
        let inst = self.get_instance(instance).await?;
        let state = inst.read().await;
        aria_core::tcprt_ops::flush_tcprt(state.map_runtime())
            .map_err(|e| ControlPlaneError::KernelError(e))
    }

    // ── SSL ──

    pub async fn list_ssl(&self, instance: &str, top: usize) -> Result<Vec<aria_core::ssl_ops::SslConnEntry>, ControlPlaneError> {
        self.get_instance(instance).await?;
        self.list_ssl_global(top).await
    }

    pub async fn list_ssl_global(&self, top: usize) -> Result<Vec<aria_core::ssl_ops::SslConnEntry>, ControlPlaneError> {
        self.ssl_manager.ensure_loaded().await
            .map_err(ControlPlaneError::KernelError)?;
        let mut entries = aria_core::ssl_ops::get_ssl_conns(self.ssl_manager.pin_path())
            .map_err(ControlPlaneError::KernelError)?;
        entries.truncate(top);
        Ok(entries)
    }

    pub async fn get_ssl_metrics_summary(
        &self,
    ) -> Result<Option<aria_core::ssl_ops::SslMetricsSummary>, ControlPlaneError> {
        self.ssl_manager.ensure_loaded().await
            .map_err(ControlPlaneError::KernelError)?;
        aria_core::ssl_ops::get_ssl_metrics_summary(self.ssl_manager.pin_path())
            .map_err(ControlPlaneError::KernelError)
    }

    pub async fn flush_ssl(&self, instance: &str) -> Result<u64, ControlPlaneError> {
        self.get_instance(instance).await?;
        self.flush_ssl_global().await
    }

    pub async fn flush_ssl_global(&self) -> Result<u64, ControlPlaneError> {
        self.ssl_manager.ensure_loaded().await
            .map_err(ControlPlaneError::KernelError)?;
        aria_core::ssl_ops::flush_ssl_conns(self.ssl_manager.pin_path())
            .map_err(ControlPlaneError::KernelError)
    }

    // ── SSL HTTP ──

    pub async fn list_ssl_http(&self, instance: &str, top: usize) -> Result<Vec<aria_core::ssl_ops::SslHttpEntry>, ControlPlaneError> {
        self.get_instance(instance).await?;
        self.list_ssl_http_global(top).await
    }

    pub async fn list_ssl_http_global(&self, top: usize) -> Result<Vec<aria_core::ssl_ops::SslHttpEntry>, ControlPlaneError> {
        self.ssl_manager.ensure_loaded().await
            .map_err(ControlPlaneError::KernelError)?;
        let mut entries = aria_core::ssl_ops::get_ssl_http_events(self.ssl_manager.pin_path())
            .map_err(ControlPlaneError::KernelError)?;
        entries.truncate(top);
        Ok(entries)
    }

    pub async fn get_ssl_http_metrics_summary(
        &self,
    ) -> Result<Option<aria_core::ssl_ops::SslHttpMetricsSummary>, ControlPlaneError> {
        self.ssl_manager.ensure_loaded().await
            .map_err(ControlPlaneError::KernelError)?;
        aria_core::ssl_ops::get_ssl_http_metrics_summary(self.ssl_manager.pin_path())
            .map_err(ControlPlaneError::KernelError)
    }

    pub async fn flush_ssl_http(&self, instance: &str) -> Result<u64, ControlPlaneError> {
        self.get_instance(instance).await?;
        self.flush_ssl_http_global().await
    }

    pub async fn flush_ssl_http_global(&self) -> Result<u64, ControlPlaneError> {
        self.ssl_manager.ensure_loaded().await
            .map_err(ControlPlaneError::KernelError)?;
        aria_core::ssl_ops::flush_ssl_http_events(self.ssl_manager.pin_path())
            .map_err(ControlPlaneError::KernelError)
    }

    pub async fn batch_query_tcprt(&self, tuples: &[(String, String, u16, u16)])
        -> Result<Vec<(String, aria_core::tcprt_ops::TcpRtEntry)>, ControlPlaneError>
    {
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

    pub async fn filter_tcprt(&self, dst_ip: &str, dst_port: u16)
        -> Result<Vec<(String, Vec<aria_core::tcprt_ops::TcpRtEntry>)>, ControlPlaneError>
    {
        let instances = self.instances.read().await;
        let mut results = Vec::new();
        for (name, inst) in instances.iter() {
            let state = inst.read().await;
            let entries = aria_core::tcprt_ops::filter_tcprt_flows(state.map_runtime(), dst_ip, dst_port)
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
        chains.iter()
            .find(|c| c.name == name)
            .cloned()
            .ok_or_else(|| ControlPlaneError::InstanceNotFound(format!("Service chain '{}' not found", name)))
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
            return Err(ControlPlaneError::InstanceNotFound(format!("Service chain '{}' not found", name)));
        }
        service_chain::save_chains(&self.base_state_path, &chains)
            .map_err(|e| ControlPlaneError::KernelError(e))
    }

    // ── Drop Reason Profiler ──

    pub async fn get_drop_stats(&self, instance: &str) -> Result<(Vec<aria_core::drop_ops::DropStatsEntry>, HashMap<String, GroupInfo>), ControlPlaneError> {
        let inst = self.get_instance(instance).await?;
        let state = inst.read().await;
        let stats = aria_core::drop_ops::get_drop_stats(state.map_runtime())
            .map_err(|e| ControlPlaneError::KernelError(e))?;
        Ok((stats, state.state.groups.clone()))
    }

    pub async fn flush_drop_stats(&self, instance: &str) -> Result<u64, ControlPlaneError> {
        let inst = self.get_instance(instance).await?;
        let state = inst.read().await;
        aria_core::drop_ops::flush_drop_stats(state.map_runtime())
            .map_err(|e| ControlPlaneError::KernelError(e))
    }

    // ── Packet Trace ──

    pub async fn start_trace(
        &self,
        instance: &str,
        src_ip: u32,
        dst_ip: u32,
        src_ip_v6: [u8; 16],
        dst_ip_v6: [u8; 16],
        src_port: u16,
        dst_port: u16,
        proto: u8,
        is_ipv6: u8,
    ) -> Result<(), ControlPlaneError> {
        let inst = self.get_instance(instance).await?;
        let state = inst.read().await;
        aria_core::trace_ops::set_trace_filter(state.map_runtime(), src_ip, dst_ip, src_ip_v6, dst_ip_v6, src_port, dst_port, proto, is_ipv6, true)
            .map_err(|e| ControlPlaneError::KernelError(e))
    }

    pub async fn stop_trace(&self, instance: &str) -> Result<(), ControlPlaneError> {
        let inst = self.get_instance(instance).await?;
        let state = inst.read().await;
        aria_core::trace_ops::clear_trace_filter(state.map_runtime())
            .map_err(|e| ControlPlaneError::KernelError(e))
    }

    pub async fn get_trace_events(&self, instance: &str, limit: usize) -> Result<(Vec<aria_core::trace_ops::TraceEventEntry>, HashMap<String, GroupInfo>), ControlPlaneError> {
        let inst = self.get_instance(instance).await?;
        let state = inst.read().await;
        let events = aria_core::trace_ops::get_trace_events(state.map_runtime(), limit)
            .map_err(|e| ControlPlaneError::KernelError(e))?;
        Ok((events, state.state.groups.clone()))
    }

    pub async fn flush_trace(&self, instance: &str) -> Result<u64, ControlPlaneError> {
        let inst = self.get_instance(instance).await?;
        let state = inst.read().await;
        aria_core::trace_ops::flush_trace_log(state.map_runtime())
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
            let entries = std::fs::read_dir(state_root)
                .map_err(|e| format!("failed to scan state root {}: {}", self.base_state_path, e))?;
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

    fn sync_pinned_ssl_config(&self, runtime: TapMapRuntime<'_>, enabled: bool) -> Result<(), String> {
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
            info!(enabled, repaired_instances, "reconciled runtime SSL config on pending instances");
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

    fn resolve_group_id(&self, state: &FirewallState, name: &str) -> Result<u32, ControlPlaneError> {
        if name == "any" {
            Ok(0)
        } else {
            state.groups.get(name)
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
        state.groups.values()
            .find(|g| g.id == id)
            .map(|g| g.name.clone())
            .unwrap_or_else(|| format!("id:{}", id))
    }
}
