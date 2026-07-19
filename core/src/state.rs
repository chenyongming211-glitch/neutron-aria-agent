use fslock::LockFile;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::PathBuf;
use tracing::{info, warn};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupInfo {
    pub id: u32,
    pub name: String,
    pub cidrs: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleInfo {
    pub name: Option<String>,
    pub src_group_id: u32,
    pub dst_group_id: u32,
    pub proto: u8,
    pub action: u8,
    pub ports: Option<String>,
    pub bitmap_idx: Option<u32>,
    #[serde(default)]
    pub direction: u8, // 0=ingress, 1=egress
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QosRuleInfo {
    pub group_name: String,
    pub group_id: u32,
    pub direction: u8,
    pub rate_bps: u64,
    pub burst_bytes: u64,
    pub priority: u8,
    #[serde(default)]
    pub mode: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MirrorRuleInfo {
    pub src_group_name: String,
    pub src_group_id: u32,
    pub dst_group_name: String,
    pub dst_group_id: u32,
    pub proto: u8,
    pub direction: u8,
    pub target_iface: String,
    pub target_ifindex: u32,
    pub is_global: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortSetInfo {
    pub bitmap_idx: u32,
    pub ports_normalized: String,
    pub ref_count: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BitmapCleanupIntent {
    pub ports_normalized: String,
}

pub struct AddRuleResult {
    pub bitmap_idx: Option<u32>,
    pub is_new_port_set: bool,
    /// 如果更新规则导致旧 port set 引用归零，需要清理内核
    pub old_port_set_released: Option<(u32, String)>,
}

pub struct RemoveRuleResult {
    /// 被删除规则的 bitmap_idx（如果有端口过滤）
    pub bitmap_idx: Option<u32>,
    /// 如果 port set 引用计数归零，需要清理内核中的端口条目
    pub port_set_released: Option<String>,
}

fn default_max_port_policies() -> u32 {
    16384
}

/// Reserved `port_sets` key namespace used to persist allocator quarantine
/// without changing the on-disk state schema. Normalized user port sets contain
/// only numeric ranges/actions and therefore cannot collide with this prefix.
const BITMAP_QUARANTINE_PREFIX: &str = "__aria_internal_bitmap_quarantine_v1__:";

fn bitmap_quarantine_key(bitmap_idx: u32) -> String {
    format!("{}{}", BITMAP_QUARANTINE_PREFIX, bitmap_idx)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirewallState {
    pub groups: HashMap<String, GroupInfo>,
    pub rules: Vec<RuleInfo>,
    pub next_group_id: u32,
    pub next_bitmap_idx: u32,
    #[serde(default)]
    pub port_sets: HashMap<String, PortSetInfo>,
    #[serde(default)]
    pub free_bitmap_indices: Vec<u32>,
    #[serde(default)]
    pub pending_bitmap_cleanups: BTreeMap<u32, BitmapCleanupIntent>,
    #[serde(default = "default_max_port_policies")]
    pub max_port_policies: u32,
    /// Stable per-instance namespace id reserved for the future shared data plane.
    #[serde(default)]
    pub tap_id: u32,
    /// XDP 程序挂载的网卡名
    #[serde(default)]
    pub attached_iface: Option<String>,
    #[serde(default)]
    pub qos_rules: Vec<QosRuleInfo>,
    #[serde(default)]
    pub conntrack_enabled: bool,
    #[serde(default)]
    pub monitoring_enabled: bool,
    #[serde(default = "default_true")]
    pub acl_enabled: bool,
    #[serde(default = "default_true")]
    pub qos_enabled: bool,
    #[serde(default)]
    pub mirror_rules: Vec<MirrorRuleInfo>,
    #[serde(default = "default_true")]
    pub mirror_enabled: bool,
    #[serde(default = "default_true")]
    pub tcprt_enabled: bool,
    #[serde(default)]
    pub ssl_enabled: bool,
}

fn default_true() -> bool {
    true
}

impl Default for FirewallState {
    fn default() -> Self {
        Self {
            groups: HashMap::new(),
            rules: Vec::new(),
            next_group_id: 1, // ID 0 保留给通配符 "any"
            next_bitmap_idx: 0,
            port_sets: HashMap::new(),
            free_bitmap_indices: Vec::new(),
            pending_bitmap_cleanups: BTreeMap::new(),
            max_port_policies: default_max_port_policies(),
            tap_id: 0,
            attached_iface: None,
            qos_rules: Vec::new(),
            conntrack_enabled: true,
            monitoring_enabled: true,
            acl_enabled: true,
            qos_enabled: true,
            mirror_rules: Vec::new(),
            mirror_enabled: true,
            tcprt_enabled: true,
            ssl_enabled: false,
        }
    }
}

impl FirewallState {
    fn has_legacy_bitmap_quarantine(&self, bitmap_idx: u32) -> bool {
        let key = bitmap_quarantine_key(bitmap_idx);
        self.port_sets.get(&key).is_some_and(|port_set| {
            port_set.bitmap_idx == bitmap_idx
                && port_set.ref_count == 0
                && port_set.ports_normalized == key
        })
    }

    pub fn is_bitmap_index_quarantined(&self, bitmap_idx: u32) -> bool {
        self.pending_bitmap_cleanups.contains_key(&bitmap_idx)
            || self.has_legacy_bitmap_quarantine(bitmap_idx)
    }

    /// Persistently reserve an index together with the exact kernel keys that
    /// must be deleted before the allocator may reuse it.
    pub fn quarantine_bitmap_cleanup(
        &mut self,
        bitmap_idx: u32,
        ports_normalized: String,
    ) -> Result<(), String> {
        if bitmap_idx >= self.max_port_policies {
            return Err(format!(
                "cannot quarantine bitmap index {} outside allocator limit {}",
                bitmap_idx, self.max_port_policies
            ));
        }
        if ports_normalized.is_empty() || ports_normalized.starts_with(BITMAP_QUARANTINE_PREFIX) {
            return Err(format!(
                "cannot quarantine bitmap index {} without an exact cleanup target",
                bitmap_idx
            ));
        }
        let key = bitmap_quarantine_key(bitmap_idx);
        if self
            .port_sets
            .iter()
            .any(|(existing_key, port_set)| {
                port_set.bitmap_idx == bitmap_idx && existing_key != &key
            })
        {
            return Err(format!(
                "cannot quarantine live bitmap index {}",
                bitmap_idx
            ));
        }
        if let Some(existing) = self.pending_bitmap_cleanups.get(&bitmap_idx) {
            if existing.ports_normalized != ports_normalized {
                return Err(format!(
                    "conflicting cleanup target for bitmap index {}: '{}' != '{}'",
                    bitmap_idx, existing.ports_normalized, ports_normalized
                ));
            }
            return Ok(());
        }

        self.free_bitmap_indices
            .retain(|candidate| *candidate != bitmap_idx);
        self.next_bitmap_idx = self
            .next_bitmap_idx
            .max(bitmap_idx.saturating_add(1));
        self.port_sets.remove(&key);
        self.pending_bitmap_cleanups.insert(
            bitmap_idx,
            BitmapCleanupIntent { ports_normalized },
        );
        Ok(())
    }

    pub fn pending_bitmap_cleanup_targets(&self) -> Vec<(u32, String)> {
        self.pending_bitmap_cleanups
            .iter()
            .map(|(bitmap_idx, intent)| (*bitmap_idx, intent.ports_normalized.clone()))
            .collect()
    }

    pub fn pending_bitmap_cleanup_count(&self) -> usize {
        self.pending_bitmap_cleanups.len()
            + self
                .port_sets
                .values()
                .filter(|port_set| {
                    self.has_legacy_bitmap_quarantine(port_set.bitmap_idx)
                        && !self
                            .pending_bitmap_cleanups
                            .contains_key(&port_set.bitmap_idx)
                })
                .count()
    }

    /// Make a quarantined index reusable only after kernel cleanup has been
    /// explicitly confirmed successful.
    pub fn release_quarantined_bitmap_index(
        &mut self,
        bitmap_idx: u32,
    ) -> Result<bool, String> {
        if !self.is_bitmap_index_quarantined(bitmap_idx) {
            return Ok(false);
        }
        let key = bitmap_quarantine_key(bitmap_idx);
        if self
            .port_sets
            .iter()
            .any(|(existing_key, port_set)| {
                port_set.bitmap_idx == bitmap_idx && existing_key != &key
            })
        {
            return Err(format!(
                "cannot release quarantined bitmap index {} while it is live",
                bitmap_idx
            ));
        }
        self.pending_bitmap_cleanups.remove(&bitmap_idx);
        self.port_sets.remove(&key);
        if !self.free_bitmap_indices.contains(&bitmap_idx) {
            self.free_bitmap_indices.push(bitmap_idx);
        }
        Ok(true)
    }

    fn take_reusable_bitmap_index(&mut self) -> Option<u32> {
        while let Some(candidate) = self.free_bitmap_indices.pop() {
            if candidate < self.max_port_policies
                && !self.is_bitmap_index_quarantined(candidate)
                && !self
                    .port_sets
                    .values()
                    .any(|port_set| port_set.bitmap_idx == candidate)
            {
                return Some(candidate);
            }
        }
        None
    }

    fn take_fresh_bitmap_index(&mut self) -> Option<u32> {
        while self.next_bitmap_idx < self.max_port_policies
            && (self.is_bitmap_index_quarantined(self.next_bitmap_idx)
                || self
                    .port_sets
                    .values()
                    .any(|port_set| port_set.bitmap_idx == self.next_bitmap_idx))
        {
            self.next_bitmap_idx += 1;
        }
        if self.next_bitmap_idx >= self.max_port_policies {
            None
        } else {
            let bitmap_idx = self.next_bitmap_idx;
            self.next_bitmap_idx += 1;
            Some(bitmap_idx)
        }
    }

    /// Add or update a group. Returns the group ID.
    pub fn add_group(&mut self, name: &str, cidr: &str) -> Result<u32, String> {
        if name == "any" {
            return Err("Group name 'any' is reserved and cannot be used".to_string());
        }
        if let Some(existing) = self.groups.get_mut(name) {
            if !existing.cidrs.contains(&cidr.to_string()) {
                existing.cidrs.push(cidr.to_string());
            }
            Ok(existing.id)
        } else {
            let id = self.next_group_id;
            self.next_group_id += 1;
            self.groups.insert(
                name.to_string(),
                GroupInfo {
                    id,
                    name: name.to_string(),
                    cidrs: vec![cidr.to_string()],
                },
            );
            Ok(id)
        }
    }

    /// Rollback a group add: remove the CIDR, and if the group is now empty, remove it and undo next_group_id.
    pub fn rollback_add_group(&mut self, name: &str, cidr: &str, was_new_group: bool) {
        if let Some(g) = self.groups.get_mut(name) {
            g.cidrs.retain(|c| c != cidr);
            if g.cidrs.is_empty() {
                self.groups.remove(name);
                if was_new_group {
                    self.next_group_id -= 1;
                }
            }
        }
    }

    /// Add or update a rule in-memory. Returns AddRuleResult.
    pub fn apply_add_rule(
        &mut self,
        src_group_id: u32,
        dst_group_id: u32,
        proto: u8,
        action: u8,
        ports: Option<&str>,
        direction: u8,
    ) -> Result<AddRuleResult, String> {
        let mut result = AddRuleResult {
            bitmap_idx: None,
            is_new_port_set: false,
            old_port_set_released: None,
        };

        let stored_ports = ports.map(|p| {
            let trimmed = p.trim();
            if trimmed.eq_ignore_ascii_case("all") {
                "all".to_string()
            } else {
                trimmed.to_string()
            }
        });

        let (bitmap_idx, is_new) = if let Some(p) = stored_ports
            .as_deref()
            .filter(|p| !p.is_empty() && !p.eq_ignore_ascii_case("all"))
        {
            let normalized = normalize_ports(p, action)?;

            if let Some(existing_ps) = self.port_sets.get_mut(&normalized) {
                existing_ps.ref_count += 1;
                (Some(existing_ps.bitmap_idx), false)
            } else {
                let idx = if let Some(recycled) = self.take_reusable_bitmap_index() {
                    recycled
                } else {
                    self.take_fresh_bitmap_index().ok_or_else(|| {
                        format!(
                            "Port set limit ({}) reached. Unique port combinations: {}",
                            self.max_port_policies,
                            self.port_sets
                                .values()
                                .filter(|port_set| port_set.ref_count > 0)
                                .count()
                        )
                    })?
                };
                self.port_sets.insert(
                    normalized.clone(),
                    PortSetInfo {
                        bitmap_idx: idx,
                        ports_normalized: normalized,
                        ref_count: 1,
                    },
                );
                (Some(idx), true)
            }
        } else {
            (None, false)
        };

        // 检测重复规则：相同 (src_group_id, dst_group_id, proto, direction) → 更新
        if let Some(existing) = self.rules.iter_mut().find(|r| {
            r.src_group_id == src_group_id
                && r.dst_group_id == dst_group_id
                && r.proto == proto
                && r.direction == direction
        }) {
            // 旧规则有 bitmap → 减引用计数
            if let Some(old_idx) = existing.bitmap_idx {
                if bitmap_idx != Some(old_idx) {
                    let old_ports_normalized = self
                        .port_sets
                        .iter()
                        .find(|(_, ps)| ps.bitmap_idx == old_idx)
                        .map(|(_, ps)| ps.ports_normalized.clone());

                    release_port_set(&mut self.port_sets, &mut self.free_bitmap_indices, old_idx);

                    if self.free_bitmap_indices.contains(&old_idx) {
                        if let Some(ports_norm) = old_ports_normalized {
                            result.old_port_set_released = Some((old_idx, ports_norm));
                        }
                    }
                } else {
                    // 新旧相同 bitmap_idx，撤销上面多加的 ref_count
                    if let Some(key) = self
                        .port_sets
                        .iter()
                        .find(|(_, ps)| ps.bitmap_idx == old_idx)
                        .map(|(k, _)| k.clone())
                    {
                        if let Some(ps) = self.port_sets.get_mut(&key) {
                            ps.ref_count -= 1;
                        }
                    }
                }
            }
            existing.action = action;
            existing.ports = stored_ports.clone();
            existing.bitmap_idx = bitmap_idx;
        } else {
            self.rules.push(RuleInfo {
                name: None,
                src_group_id,
                dst_group_id,
                proto,
                action,
                ports: stored_ports,
                bitmap_idx,
                direction,
            });
        }

        result.bitmap_idx = bitmap_idx;
        result.is_new_port_set = is_new;
        Ok(result)
    }

    /// Remove a rule in-memory. Returns RemoveRuleResult.
    pub fn apply_remove_rule(
        &mut self,
        src_group_id: u32,
        dst_group_id: u32,
        proto: u8,
        direction: u8,
    ) -> Result<RemoveRuleResult, String> {
        let mut result = RemoveRuleResult {
            bitmap_idx: None,
            port_set_released: None,
        };

        if let Some(pos) = self.rules.iter().position(|r| {
            r.src_group_id == src_group_id
                && r.dst_group_id == dst_group_id
                && r.proto == proto
                && r.direction == direction
        }) {
            let rule = self.rules.remove(pos);
            if let Some(idx) = rule.bitmap_idx {
                let ports_normalized = self
                    .port_sets
                    .iter()
                    .find(|(_, ps)| ps.bitmap_idx == idx)
                    .map(|(_, ps)| ps.ports_normalized.clone());

                release_port_set(&mut self.port_sets, &mut self.free_bitmap_indices, idx);

                result.bitmap_idx = Some(idx);
                if self.free_bitmap_indices.contains(&idx) {
                    result.port_set_released = ports_normalized;
                }
            }
        } else {
            return Err(format!(
                "Policy not found: src_id={}, dst_id={}, proto={}, direction={}",
                src_group_id, dst_group_id, proto, direction
            ));
        }

        Ok(result)
    }
}

/// 将用户输入的端口规则归一化为唯一规范形式。
/// 解析 → 按 (start, end, user_action) 排序 → 序列化为 "start[-end]:user_action,..." 形式。
/// 这里持久化的是用户语义：0=pass, 1=drop。
fn normalize_ports(ports_str: &str, default_action: u8) -> Result<String, String> {
    let mut entries: Vec<(u16, u16, u8)> = Vec::new();
    for part in ports_str.split(',') {
        let parts: Vec<&str> = part.trim().split(':').collect();
        let rule_action = match parts.get(1) {
            Some(raw_action) => {
                let action = raw_action
                    .parse::<u8>()
                    .map_err(|_| format!("Invalid action '{}': must be 0 or 1", raw_action))?;
                if action > 1 {
                    return Err(format!("Invalid action {}: must be 0 or 1", action));
                }
                action
            }
            None => default_action,
        };
        if parts[0].contains('-') {
            let range: Vec<&str> = parts[0].split('-').collect();
            if range.len() != 2 {
                return Err("Invalid range format".to_string());
            }
            let start = range[0].trim().parse::<u16>().map_err(|_| "Invalid port")?;
            let end = range[1].trim().parse::<u16>().map_err(|_| "Invalid port")?;
            if start > end {
                return Err(format!("Invalid port range: {}-{}", start, end));
            }
            entries.push((start, end, rule_action));
        } else {
            let port = parts[0].trim().parse::<u16>().map_err(|_| "Invalid port")?;
            entries.push((port, port, rule_action));
        }
    }
    entries.sort();
    let normalized = entries
        .iter()
        .map(|(start, end, act)| {
            if start == end {
                format!("{}:{}", start, act)
            } else {
                format!("{}-{}:{}", start, end, act)
            }
        })
        .collect::<Vec<_>>()
        .join(",");
    Ok(normalized)
}

/// 减少端口集引用计数，计数归零时回收 bitmap_idx
fn release_port_set(
    port_sets: &mut HashMap<String, PortSetInfo>,
    free_indices: &mut Vec<u32>,
    bitmap_idx: u32,
) {
    let key_to_remove = port_sets
        .iter()
        .find(|(_, ps)| ps.bitmap_idx == bitmap_idx && ps.ref_count > 0)
        .map(|(k, _)| k.clone());
    if let Some(key) = key_to_remove {
        if let Some(ps) = port_sets.get_mut(&key) {
            ps.ref_count -= 1;
            if ps.ref_count == 0 {
                free_indices.push(bitmap_idx);
                port_sets.remove(&key);
            }
        }
    }
}

pub struct StateManager {
    state_file: PathBuf,
}

impl StateManager {
    pub fn new(state_path: &str) -> Self {
        let state_file = PathBuf::from(format!("{}/state.json", state_path));
        if let Some(parent) = state_file.parent() {
            std::fs::create_dir_all(parent).ok();
        }
        Self { state_file }
    }

    /// 获取操作级锁，覆盖 state + kernel maps 的整个操作
    pub fn acquire_ops_lock(&self) -> Result<LockFile, String> {
        let lock_path = self.state_file.with_file_name("ops.lock");
        let mut lock =
            LockFile::open(&lock_path).map_err(|e| format!("Failed to open ops lock: {}", e))?;
        lock.lock()
            .map_err(|e| format!("Failed to acquire ops lock: {}", e))?;
        Ok(lock)
    }

    fn with_state<F>(&self, mut f: F) -> Result<(), String>
    where
        F: FnMut(&mut FirewallState) -> Result<(), String>,
    {
        let lock_path = self.state_file.with_extension("lock");
        let mut lock =
            LockFile::open(&lock_path).map_err(|e| format!("Failed to open lock file: {}", e))?;
        lock.lock()
            .map_err(|e| format!("Failed to acquire lock: {}", e))?;

        let mut state = if self.state_file.exists() {
            let mut file = File::open(&self.state_file)
                .map_err(|e| format!("Failed to open state file: {}", e))?;
            let mut contents = String::new();
            file.read_to_string(&mut contents)
                .map_err(|e| format!("Failed to read state file: {}", e))?;
            if contents.is_empty() {
                warn!(path = %self.state_file.display(), "state file is empty; starting with default state");
                FirewallState::default()
            } else {
                serde_json::from_str(&contents)
                    .map_err(|e| format!("Failed to parse state file: {}", e))?
            }
        } else {
            info!(path = %self.state_file.display(), "state file does not exist; creating new state");
            FirewallState::default()
        };

        f(&mut state)?;

        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&self.state_file)
            .map_err(|e| format!("Failed to open state file for writing: {}", e))?;

        let contents = serde_json::to_string_pretty(&state)
            .map_err(|e| format!("Failed to serialize state: {}", e))?;

        file.write_all(contents.as_bytes())
            .map_err(|e| format!("Failed to write state file: {}", e))?;
        file.sync_all()
            .map_err(|e| format!("Failed to sync state file: {}", e))?;

        Ok(())
    }

    pub fn add_group(&self, name: &str, cidr: &str) -> Result<u32, String> {
        if name == "any" {
            return Err("Group name 'any' is reserved and cannot be used".to_string());
        }

        let mut id = 0;
        self.with_state(|state| {
            if let Some(existing) = state.groups.get_mut(name) {
                if !existing.cidrs.contains(&cidr.to_string()) {
                    existing.cidrs.push(cidr.to_string());
                }
                id = existing.id;
            } else {
                id = state.next_group_id;
                state.next_group_id += 1;
                let group = GroupInfo {
                    id,
                    name: name.to_string(),
                    cidrs: vec![cidr.to_string()],
                };
                state.groups.insert(name.to_string(), group);
            }
            Ok(())
        })?;
        Ok(id)
    }

    pub fn remove_cidr_from_group(&self, name: &str, cidr: &str) -> Result<(), String> {
        self.with_state(|state| {
            if let Some(group) = state.groups.get_mut(name) {
                group.cidrs.retain(|c| c != cidr);
                if group.cidrs.is_empty() {
                    state.groups.remove(name);
                }
            }
            Ok(())
        })
    }

    pub fn delete_group(&self, name: &str) -> Result<(), String> {
        self.with_state(|state| {
            state.groups.remove(name);
            Ok(())
        })
    }

    pub fn set_max_port_policies(&self, max: u32) -> Result<(), String> {
        self.with_state(|state| {
            state.max_port_policies = max;
            Ok(())
        })
    }

    pub fn set_attached_iface(&self, iface: &str) -> Result<(), String> {
        self.with_state(|state| {
            state.attached_iface = Some(iface.to_string());
            Ok(())
        })
    }

    pub fn clear_attached_iface(&self) -> Result<(), String> {
        self.with_state(|state| {
            state.attached_iface = None;
            Ok(())
        })
    }

    pub fn get_attached_iface(&self) -> Result<Option<String>, String> {
        let state = self._load_readonly()?;
        Ok(state.attached_iface)
    }

    pub fn set_tap_id(&self, tap_id: u32) -> Result<(), String> {
        self.with_state(|state| {
            state.tap_id = tap_id;
            Ok(())
        })
    }

    pub fn get_tap_id(&self) -> Result<u32, String> {
        let state = self._load_readonly()?;
        Ok(state.tap_id)
    }

    pub fn add_rule(
        &self,
        src_group_id: u32,
        dst_group_id: u32,
        proto: u8,
        action: u8,
        ports: Option<&str>,
        direction: u8,
    ) -> Result<AddRuleResult, String> {
        let mut result = AddRuleResult {
            bitmap_idx: None,
            is_new_port_set: false,
            old_port_set_released: None,
        };
        self.with_state(|state| {
            result = state.apply_add_rule(
                src_group_id,
                dst_group_id,
                proto,
                action,
                ports,
                direction,
            )?;
            Ok(())
        })?;
        Ok(result)
    }

    pub fn remove_rule(
        &self,
        src_group_id: u32,
        dst_group_id: u32,
        proto: u8,
        direction: u8,
    ) -> Result<RemoveRuleResult, String> {
        let mut result = RemoveRuleResult {
            bitmap_idx: None,
            port_set_released: None,
        };
        self.with_state(|state| {
            result = state.apply_remove_rule(src_group_id, dst_group_id, proto, direction)?;
            Ok(())
        })?;
        Ok(result)
    }

    pub fn get_group(&self, name: &str) -> Result<Option<GroupInfo>, String> {
        let state = self._load_readonly()?;
        Ok(state.groups.get(name).cloned())
    }

    pub fn list_groups(&self) -> Result<Vec<GroupInfo>, String> {
        let state = self._load_readonly()?;
        Ok(state.groups.values().cloned().collect())
    }

    pub fn list_rules(&self) -> Result<Vec<RuleInfo>, String> {
        let state = self._load_readonly()?;
        Ok(state.rules.clone())
    }

    #[allow(dead_code)]
    pub fn get_group_by_id(&self, id: u32) -> Result<Option<GroupInfo>, String> {
        let state = self._load_readonly()?;
        Ok(state.groups.values().find(|g| g.id == id).cloned())
    }

    fn _load_readonly(&self) -> Result<FirewallState, String> {
        let lock_path = self.state_file.with_extension("lock");
        let mut lock =
            LockFile::open(&lock_path).map_err(|e| format!("Failed to open lock file: {}", e))?;
        lock.lock()
            .map_err(|e| format!("Failed to acquire lock: {}", e))?;

        let state = if self.state_file.exists() {
            let mut file = File::open(&self.state_file)
                .map_err(|e| format!("Failed to open state file: {}", e))?;
            let mut contents = String::new();
            file.read_to_string(&mut contents)
                .map_err(|e| format!("Failed to read state file: {}", e))?;
            if contents.is_empty() {
                FirewallState::default()
            } else {
                serde_json::from_str(&contents)
                    .map_err(|e| format!("Failed to parse state file: {}", e))?
            }
        } else {
            FirewallState::default()
        };

        Ok(state)
    }

    // --- QoS state management ---

    pub fn add_qos_rule(
        &self,
        group_name: &str,
        group_id: u32,
        direction: u8,
        rate_bps: u64,
        burst_bytes: u64,
        priority: u8,
        mode: u8,
    ) -> Result<(), String> {
        self.with_state(|state| {
            // Remove existing rule with same group+direction
            state
                .qos_rules
                .retain(|r| !(r.group_id == group_id && r.direction == direction));
            state.qos_rules.push(QosRuleInfo {
                group_name: group_name.to_string(),
                group_id,
                direction,
                rate_bps,
                burst_bytes,
                priority,
                mode,
            });
            Ok(())
        })
    }

    pub fn remove_qos_rule(&self, group_id: u32, direction: u8) -> Result<(), String> {
        self.with_state(|state| {
            let before = state.qos_rules.len();
            state
                .qos_rules
                .retain(|r| !(r.group_id == group_id && r.direction == direction));
            if state.qos_rules.len() == before {
                return Err(format!(
                    "QoS rule not found: group_id={}, direction={}",
                    group_id, direction
                ));
            }
            Ok(())
        })
    }

    pub fn list_qos_rules(&self) -> Result<Vec<QosRuleInfo>, String> {
        let state = self._load_readonly()?;
        Ok(state.qos_rules.clone())
    }

    pub fn set_conntrack_enabled(&self, enabled: bool) -> Result<(), String> {
        self.with_state(|state| {
            state.conntrack_enabled = enabled;
            Ok(())
        })
    }

    pub fn set_monitoring_enabled(&self, enabled: bool) -> Result<(), String> {
        self.with_state(|state| {
            state.monitoring_enabled = enabled;
            Ok(())
        })
    }

    pub fn get_config(&self) -> Result<(bool, bool, bool, bool, bool), String> {
        let state = self._load_readonly()?;
        Ok((
            state.conntrack_enabled,
            state.monitoring_enabled,
            state.acl_enabled,
            state.qos_enabled,
            state.mirror_enabled,
        ))
    }

    pub fn set_acl_enabled(&self, enabled: bool) -> Result<(), String> {
        self.with_state(|state| {
            state.acl_enabled = enabled;
            Ok(())
        })
    }

    pub fn set_qos_enabled(&self, enabled: bool) -> Result<(), String> {
        self.with_state(|state| {
            state.qos_enabled = enabled;
            Ok(())
        })
    }

    // --- Mirror state management ---

    pub fn set_mirror_enabled(&self, enabled: bool) -> Result<(), String> {
        self.with_state(|state| {
            state.mirror_enabled = enabled;
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn unique_state_path() -> String {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        format!("/tmp/aria-firewall-test-{}", nanos)
    }

    #[test]
    fn normalize_ports_sorts_and_encodes_actions() {
        let s = "100-200:1,80,443:0";
        let normalized = normalize_ports(s, 0).unwrap();
        // 按 (start,end,act) 排序后应该是 80,100-200,443；act 持久化为用户语义 0=pass 1=drop
        assert_eq!(normalized, "80:0,100-200:1,443:0");
    }

    #[test]
    fn normalize_ports_rejects_invalid_range_and_action() {
        assert!(normalize_ports("200-100", 0).is_err(), "start>end 应报错");
        assert!(normalize_ports("80:2", 0).is_err(), "action>1 应报错");
    }

    #[test]
    fn apply_add_rule_canonicalizes_all_ports_without_bitmap() {
        let mut state = FirewallState::default();

        let result = state
            .apply_add_rule(1, 2, 6, 0, Some(" ALL "), 0)
            .expect("apply_add_rule should accept case-insensitive all");

        assert!(result.bitmap_idx.is_none(), "'all' 不应分配位图");
        assert!(state.port_sets.is_empty(), "'all' 不应创建 port set");
        assert_eq!(state.rules.len(), 1);
        assert_eq!(state.rules[0].ports.as_deref(), Some("all"));
    }

    #[test]
    fn port_sets_refcount_and_reuse_bitmap_idx() {
        let state_path = unique_state_path();
        let mgr = StateManager::new(&state_path);

        // 新建两条规则，端口集字符串相同，应共享同一个 bitmap_idx，ref_count=2
        let r1 = mgr
            .add_rule(1, 2, 6, 0, Some("80,100-200"), 0)
            .expect("add_rule 1");
        let r2 = mgr
            .add_rule(3, 4, 6, 0, Some("80,100-200"), 0)
            .expect("add_rule 2");

        let idx1 = r1.bitmap_idx.expect("bitmap_idx for r1");
        let idx2 = r2.bitmap_idx.expect("bitmap_idx for r2");
        assert_eq!(idx1, idx2, "相同端口集应复用同一 bitmap_idx");

        // 删除第一条规则，不应释放 port set（引用从 2→1）
        let rm1 = mgr.remove_rule(1, 2, 6, 0).expect("remove_rule 1");
        assert_eq!(rm1.bitmap_idx, Some(idx1));
        assert!(
            rm1.port_set_released.is_none(),
            "仍有引用时不应标记 port_set_released"
        );

        // 删除第二条规则，引用归零，应回收 bitmap_idx 并报告释放的端口集
        let rm2 = mgr.remove_rule(3, 4, 6, 0).expect("remove_rule 2");
        assert_eq!(rm2.bitmap_idx, Some(idx1));
        assert!(
            rm2.port_set_released.is_some(),
            "最后一个引用删除后应标记 port_set_released"
        );

        // 再添加一个不同端口集的规则，应复用刚刚回收的 bitmap_idx（free list）
        let r3 = mgr
            .add_rule(5, 6, 6, 0, Some("443"), 0)
            .expect("add_rule 3");
        let idx3 = r3.bitmap_idx.expect("bitmap_idx for r3");
        assert_eq!(
            idx3, idx1,
            "新端口集应优先复用 free_bitmap_indices 中的 idx"
        );
    }

    #[test]
    fn quarantined_bitmap_survives_restart_and_is_not_reused() {
        let mut state = FirewallState::default();
        state.free_bitmap_indices.push(7);
        state.next_bitmap_idx = 8;
        state
            .quarantine_bitmap_cleanup(7, "80:1".to_string())
            .expect("quarantine recycled bitmap index");

        assert!(state.is_bitmap_index_quarantined(7));
        assert!(!state.free_bitmap_indices.contains(&7));

        let json = serde_json::to_string(&state).expect("serialize quarantined allocator");
        let mut restarted: FirewallState =
            serde_json::from_str(&json).expect("deserialize quarantined allocator");
        let retry = restarted
            .apply_add_rule(1, 2, 6, 1, Some("443"), 0)
            .expect("retry allocation");

        assert_eq!(retry.bitmap_idx, Some(8));
        assert!(restarted.is_bitmap_index_quarantined(7));
    }

    #[test]
    fn quarantined_bitmap_preserves_cleanup_target_across_restart() {
        let mut state = FirewallState::default();
        state
            .quarantine_bitmap_cleanup(7, "80:1".to_string())
            .expect("persist exact retired bitmap cleanup target");

        let json = serde_json::to_string(&state).expect("serialize cleanup intent");
        let restarted: FirewallState =
            serde_json::from_str(&json).expect("deserialize cleanup intent");

        assert_eq!(
            restarted.pending_bitmap_cleanup_targets(),
            vec![(7, "80:1".to_string())]
        );
        assert!(restarted.is_bitmap_index_quarantined(7));
    }

    #[test]
    fn quarantined_bitmap_rejects_conflicting_cleanup_target() {
        let mut state = FirewallState::default();
        state
            .quarantine_bitmap_cleanup(7, "80:1".to_string())
            .unwrap();

        let error = state
            .quarantine_bitmap_cleanup(7, "443:1".to_string())
            .expect_err("one bitmap cannot carry two cleanup targets");

        assert!(error.contains("conflicting cleanup target"));
        assert_eq!(
            state.pending_bitmap_cleanup_targets(),
            vec![(7, "80:1".to_string())]
        );
    }

    #[test]
    fn quarantined_fresh_bitmap_advances_next_cursor_across_restart() {
        let mut state = FirewallState::default();
        state
            .quarantine_bitmap_cleanup(0, "80:1".to_string())
            .expect("quarantine fresh bitmap index");
        assert_eq!(state.next_bitmap_idx, 1);

        let json = serde_json::to_string(&state).expect("serialize fresh quarantine");
        let mut restarted: FirewallState =
            serde_json::from_str(&json).expect("deserialize fresh quarantine");
        let retry = restarted
            .apply_add_rule(1, 2, 6, 1, Some("443"), 0)
            .expect("allocate after fresh quarantine");

        assert_eq!(retry.bitmap_idx, Some(1));
        assert!(restarted.is_bitmap_index_quarantined(0));
    }

    #[test]
    fn confirmed_bitmap_cleanup_releases_only_the_successful_quarantine() {
        let mut state = FirewallState::default();
        state.free_bitmap_indices.extend([7, 8]);
        state.next_bitmap_idx = 9;
        state
            .quarantine_bitmap_cleanup(7, "80:1".to_string())
            .unwrap();
        state
            .quarantine_bitmap_cleanup(8, "443:1".to_string())
            .unwrap();

        assert!(state.release_quarantined_bitmap_index(8).unwrap());
        assert!(state.is_bitmap_index_quarantined(7));
        assert!(!state.is_bitmap_index_quarantined(8));

        let first = state
            .apply_add_rule(1, 2, 6, 1, Some("443"), 0)
            .unwrap();
        let second = state
            .apply_add_rule(3, 4, 6, 1, Some("8443"), 0)
            .unwrap();
        assert_eq!(first.bitmap_idx, Some(8));
        assert_eq!(second.bitmap_idx, Some(9));
        assert_ne!(first.bitmap_idx, Some(7));
        assert_ne!(second.bitmap_idx, Some(7));
    }

    #[test]
    fn tap_id_round_trips_in_state_file() {
        let state_path = unique_state_path();
        let mgr = StateManager::new(&state_path);

        assert_eq!(
            mgr.get_tap_id().unwrap(),
            0,
            "default tap_id should be unassigned"
        );

        mgr.set_tap_id(42).expect("set tap_id");
        assert_eq!(mgr.get_tap_id().unwrap(), 42, "tap_id should be persisted");

        let reloaded = StateManager::new(&state_path);
        assert_eq!(
            reloaded.get_tap_id().unwrap(),
            42,
            "tap_id should survive reload"
        );
    }
}
