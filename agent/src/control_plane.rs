use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

use aria_core::state::{FirewallState, GroupInfo, RuleInfo, QosRuleInfo};
use aria_core::wal::{WalEntry, WalWriter};

const WAL_COMPACT_THRESHOLD: u64 = 1000;

/// Per-instance in-memory state
struct InstanceState {
    state: FirewallState,
    pin_path: String,
    state_path: String,
    wal: WalWriter,
}

pub struct ControlPlane {
    instances: RwLock<HashMap<String, Arc<tokio::sync::RwLock<InstanceState>>>>,
    pub ebpf_path: String,
    pub base_pin_path: String,
    pub base_state_path: String,
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
    pub fn new(ebpf_path: &str, base_pin_path: &str, base_state_path: &str) -> Self {
        Self {
            instances: RwLock::new(HashMap::new()),
            ebpf_path: ebpf_path.to_string(),
            base_pin_path: base_pin_path.to_string(),
            base_state_path: base_state_path.to_string(),
        }
    }

    /// Register an instance (called when TapRegistry attaches a tap).
    /// If already registered, compacts state first to avoid data loss.
    pub async fn register_instance(&self, name: &str) {
        let pin_path = format!("{}/{}", self.base_pin_path, name);
        let state_path = format!("{}/{}", self.base_state_path, name);

        // If already registered, compact before replacing
        {
            let instances = self.instances.read().await;
            if let Some(existing) = instances.get(name) {
                let mut st = existing.write().await;
                if let Err(e) = st.wal.compact(&st.state) {
                    eprintln!("[ControlPlane] Failed to compact {} on re-register: {}", name, e);
                }
            }
        }

        let state = aria_core::wal::load_with_wal(&state_path);

        let wal = match WalWriter::open(&state_path) {
            Ok(w) => w,
            Err(e) => {
                eprintln!("[ControlPlane] Failed to open WAL for {}: {}", name, e);
                return;
            }
        };

        let instance = Arc::new(tokio::sync::RwLock::new(InstanceState {
            state,
            pin_path,
            state_path,
            wal,
        }));

        let mut instances = self.instances.write().await;
        instances.insert(name.to_string(), instance);
        println!("[ControlPlane] Registered instance: {}", name);
    }

    /// Register the "system" instance (standalone mode)
    pub async fn register_system_instance(&self, pin_path: &str, state_path: &str) {
        let state = aria_core::wal::load_with_wal(state_path);

        let wal = match WalWriter::open(state_path) {
            Ok(w) => w,
            Err(e) => {
                eprintln!("[ControlPlane] Failed to open WAL for system: {}", e);
                return;
            }
        };

        let instance = Arc::new(tokio::sync::RwLock::new(InstanceState {
            state,
            pin_path: pin_path.to_string(),
            state_path: state_path.to_string(),
            wal,
        }));

        let mut instances = self.instances.write().await;
        instances.insert("system".to_string(), instance);
        println!("[ControlPlane] Registered system instance");
    }

    /// Unregister an instance (called when TapRegistry detaches)
    pub async fn unregister_instance(&self, name: &str) {
        // Compact before removing
        self.compact_instance(name).await;
        let mut instances = self.instances.write().await;
        instances.remove(name);
        println!("[ControlPlane] Unregistered instance: {}", name);
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
        let prog_path = format!("{}/xdp_firewall", pin_path);
        if !std::path::Path::new(&prog_path).exists() {
            return Err(ControlPlaneError::InstanceNotReady("XDP not attached".to_string()));
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
        if let Err(e) = aria_core::ebpf_ops::add_network("src", cidr, id, &state.pin_path, &self.ebpf_path) {
            state.state.rollback_add_group(name, cidr, was_new_group);
            return Err(ControlPlaneError::KernelError(format!("src: {}", e)));
        }
        if let Err(e) = aria_core::ebpf_ops::add_network("dst", cidr, id, &state.pin_path, &self.ebpf_path) {
            let _ = aria_core::ebpf_ops::delete_network("src", cidr, id, &state.pin_path, &self.ebpf_path);
            state.state.rollback_add_group(name, cidr, was_new_group);
            return Err(ControlPlaneError::KernelError(format!("dst: {}", e)));
        }

        state.wal.append(&WalEntry::AddGroup {
            name: name.to_string(),
            cidr: cidr.to_string(),
        }).map_err(|e| ControlPlaneError::KernelError(format!("WAL append failed: {}", e)))?;
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

        // Delete from kernel
        let mut errors = Vec::new();
        for cidr in &group.cidrs {
            if let Err(e) = aria_core::ebpf_ops::delete_network("src", cidr, group.id, &state.pin_path, &self.ebpf_path) {
                errors.push(format!("src {}: {}", cidr, e));
            }
            if let Err(e) = aria_core::ebpf_ops::delete_network("dst", cidr, group.id, &state.pin_path, &self.ebpf_path) {
                errors.push(format!("dst {}: {}", cidr, e));
            }
        }
        if !errors.is_empty() {
            return Err(ControlPlaneError::KernelError(errors.join("; ")));
        }

        state.state.groups.remove(name);
        state.wal.append(&WalEntry::DeleteGroup {
            name: name.to_string(),
        }).map_err(|e| ControlPlaneError::KernelError(format!("WAL append failed: {}", e)))?;
        Ok(())
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
            direction, &state.pin_path, &self.ebpf_path,
        ) {
            // Rollback: restore snapshotted state
            state.state.rules = snapshot_rules;
            state.state.port_sets = snapshot_port_sets;
            state.state.free_bitmap_indices = snapshot_free_indices;
            state.state.next_bitmap_idx = snapshot_next_bitmap_idx;
            return Err(ControlPlaneError::KernelError(e));
        }

        // Clean up old port set if replaced
        if let Some((old_idx, ref ports_normalized)) = add_result.old_port_set_released {
            if let Err(e) = aria_core::ebpf_ops::delete_port_set(old_idx, ports_normalized, &state.pin_path, &self.ebpf_path) {
                eprintln!("Warning: failed to clean old port bitmap: {}", e);
            }
        }

        state.wal.append(&WalEntry::AddRule {
            src_id: src_id,
            dst_id: dst_id,
            proto,
            action,
            ports: ports.map(|s| s.to_string()),
            direction,
        }).map_err(|e| ControlPlaneError::KernelError(format!("WAL append failed: {}", e)))?;
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
        if let Err(e) = aria_core::ebpf_ops::delete_policy(src_id, dst_id, proto, direction, &state.pin_path, &self.ebpf_path) {
            return Err(ControlPlaneError::KernelError(e));
        }

        // Remove from in-memory state
        let remove_result = state.state.apply_remove_rule(src_id, dst_id, proto, direction)
            .map_err(|e| ControlPlaneError::PolicyNotFound(e))?;

        if let (Some(idx), Some(ref ports_normalized)) = (remove_result.bitmap_idx, &remove_result.port_set_released) {
            if let Err(e) = aria_core::ebpf_ops::delete_port_set(idx, ports_normalized, &state.pin_path, &self.ebpf_path) {
                eprintln!("Warning: failed to clean port bitmap: {}", e);
            }
        }

        state.wal.append(&WalEntry::RemoveRule {
            src_id: src_id,
            dst_id: dst_id,
            proto,
            direction,
        }).map_err(|e| ControlPlaneError::KernelError(format!("WAL append failed: {}", e)))?;
        Ok(())
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
        if let Err(e) = aria_core::qos_ops::add_qos_rule(group_id, direction, rate_bps, burst_bytes, priority, &state.pin_path) {
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
        });

        state.wal.append(&WalEntry::AddQos {
            group_name: group_name.to_string(),
            group_id,
            direction,
            rate_bps,
            burst_bytes,
            priority,
        }).map_err(|e| ControlPlaneError::KernelError(format!("WAL append failed: {}", e)))?;
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

        if let Err(e) = aria_core::qos_ops::delete_qos_rule(group_id, direction, &state.pin_path) {
            return Err(ControlPlaneError::KernelError(e));
        }

        state.state.qos_rules.retain(|r| !(r.group_id == group_id && r.direction == direction));
        state.wal.append(&WalEntry::DeleteQos {
            group_id,
            direction,
        }).map_err(|e| ControlPlaneError::KernelError(format!("WAL append failed: {}", e)))?;
        Ok(())
    }

    // ── Conntrack ──

    pub async fn list_conntrack(&self, instance: &str) -> Result<Vec<aria_core::ct_ops::CtEntry>, ControlPlaneError> {
        let inst = self.get_instance(instance).await?;
        let state = inst.read().await;
        aria_core::ct_ops::ct_list(&state.pin_path)
            .map_err(|e| ControlPlaneError::KernelError(e))
    }

    pub async fn flush_conntrack(&self, instance: &str) -> Result<u64, ControlPlaneError> {
        let inst = self.get_instance(instance).await?;
        let state = inst.read().await;
        aria_core::ct_ops::ct_flush(&state.pin_path)
            .map_err(|e| ControlPlaneError::KernelError(e))
    }

    // ── Config ──

    pub async fn get_config(&self, instance: &str) -> Result<aria_core::common::FirewallConfig, ControlPlaneError> {
        let inst = self.get_instance(instance).await?;
        let state = inst.read().await;
        aria_core::ebpf_ops::read_firewall_config(&state.pin_path)
            .map_err(|e| ControlPlaneError::KernelError(e))
    }

    pub async fn update_config(
        &self,
        instance: &str,
        conntrack: Option<bool>,
        monitoring: Option<bool>,
    ) -> Result<(), ControlPlaneError> {
        let inst = self.get_instance(instance).await?;
        let mut state = inst.write().await;
        Self::check_xdp_ready(&state.pin_path)?;

        if let Err(e) = aria_core::ebpf_ops::update_firewall_config(&state.pin_path, conntrack, monitoring) {
            return Err(ControlPlaneError::KernelError(e));
        }

        if let Some(ct) = conntrack {
            state.state.conntrack_enabled = ct;
        }
        if let Some(mon) = monitoring {
            state.state.monitoring_enabled = mon;
        }

        state.wal.append(&WalEntry::UpdateConfig {
            conntrack,
            monitoring,
        }).map_err(|e| ControlPlaneError::KernelError(format!("WAL append failed: {}", e)))?;
        Ok(())
    }

    // ── Stats ──

    pub async fn get_stats_overview(&self, instance: &str) -> Result<(usize, usize, usize, u64, u64), ControlPlaneError> {
        let inst = self.get_instance(instance).await?;
        let state = inst.read().await;

        let ct_summary = aria_core::monitoring::get_conntrack_stats(&state.pin_path).unwrap_or(
            aria_core::monitoring::ConntrackSummary {
                total_v4: 0, total_v6: 0, new_count: 0, established_count: 0,
            }
        );

        Ok((
            state.state.groups.len(),
            state.state.rules.len(),
            state.state.qos_rules.len(),
            ct_summary.total_v4,
            ct_summary.total_v6,
        ))
    }

    pub async fn get_rule_stats(&self, instance: &str) -> Result<Vec<aria_core::monitoring::RuleStatsEntry>, ControlPlaneError> {
        let inst = self.get_instance(instance).await?;
        let state = inst.read().await;
        aria_core::monitoring::get_rule_stats(&state.pin_path)
            .map_err(|e| ControlPlaneError::KernelError(e))
    }

    pub async fn get_top_flows(&self, instance: &str, top: usize) -> Result<(Vec<aria_core::monitoring::FlowStatsEntry>, Vec<aria_core::monitoring::FlowStatsEntryV6>), ControlPlaneError> {
        let inst = self.get_instance(instance).await?;
        let state = inst.read().await;
        let v4 = aria_core::monitoring::get_top_flows_v4(&state.pin_path, top)
            .map_err(|e| ControlPlaneError::KernelError(e))?;
        let v6 = aria_core::monitoring::get_top_flows_v6(&state.pin_path, top)
            .map_err(|e| ControlPlaneError::KernelError(e))?;
        Ok((v4, v6))
    }

    // ── Compact (WAL persistence) ──

    /// Compact all instances that exceed the WAL entry threshold
    pub async fn compact_all(&self) {
        let instances = self.instances.read().await;
        for (name, inst) in instances.iter() {
            let mut state = inst.write().await;
            if state.wal.entry_count() > 0 {
                if let Err(e) = state.wal.compact(&state.state) {
                    eprintln!("[ControlPlane] Failed to compact {}: {}", name, e);
                }
            }
        }
    }

    /// Compact instances whose WAL exceeds the threshold
    pub async fn compact_if_needed(&self) {
        let instances = self.instances.read().await;
        for (name, inst) in instances.iter() {
            let mut state = inst.write().await;
            if state.wal.entry_count() >= WAL_COMPACT_THRESHOLD {
                if let Err(e) = state.wal.compact(&state.state) {
                    eprintln!("[ControlPlane] Failed to compact {}: {}", name, e);
                }
            }
        }
    }

    /// Compact a specific instance
    async fn compact_instance(&self, name: &str) {
        let instances = self.instances.read().await;
        if let Some(inst) = instances.get(name) {
            let mut state = inst.write().await;
            if state.wal.entry_count() > 0 {
                if let Err(e) = state.wal.compact(&state.state) {
                    eprintln!("[ControlPlane] Failed to compact {}: {}", name, e);
                }
            }
        }
    }

    // ── Helpers ──

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
