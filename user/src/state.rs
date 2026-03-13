use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::PathBuf;
use fslock::LockFile;

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
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortSetInfo {
    pub bitmap_idx: u32,
    pub ports_normalized: String,
    pub ref_count: u32,
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
    #[serde(default = "default_max_port_policies")]
    pub max_port_policies: u32,
    /// XDP 程序挂载的网卡名
    #[serde(default)]
    pub attached_iface: Option<String>,
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
            max_port_policies: default_max_port_policies(),
            attached_iface: None,
        }
    }
}

/// 将用户输入的端口规则归一化为唯一规范形式。
/// 解析 → 按 (start, end, bpf_action) 排序 → 序列化为 "start[-end]:bpf_action,..." 形式。
fn normalize_ports(ports_str: &str) -> Result<String, String> {
    let mut entries: Vec<(u16, u16, u8)> = Vec::new();
    for part in ports_str.split(',') {
        let parts: Vec<&str> = part.trim().split(':').collect();
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
            let action: u8 = parts.get(1).and_then(|a| a.parse().ok()).unwrap_or(1);
            if action > 1 {
                return Err(format!("Invalid action {}: must be 0 or 1", action));
            }
            let bpf_action: u8 = if action == 0 { 2 } else { 1 };
            entries.push((start, end, bpf_action));
        } else {
            let port = parts[0].trim().parse::<u16>().map_err(|_| "Invalid port")?;
            let action: u8 = parts.get(1).and_then(|a| a.parse().ok()).unwrap_or(1);
            if action > 1 {
                return Err(format!("Invalid action {}: must be 0 or 1", action));
            }
            let bpf_action: u8 = if action == 0 { 2 } else { 1 };
            entries.push((port, port, bpf_action));
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
        .find(|(_, ps)| ps.bitmap_idx == bitmap_idx)
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
    pub fn new(pin_path: &str) -> Self {
        let state_file = PathBuf::from(format!("{}/state.json", pin_path));
        if let Some(parent) = state_file.parent() {
            std::fs::create_dir_all(parent).ok();
        }
        Self { state_file }
    }

    fn with_state<F>(&self, mut f: F) -> Result<(), String>
    where
        F: FnMut(&mut FirewallState) -> Result<(), String>,
    {
        let lock_path = self.state_file.with_extension("lock");
        let mut lock = LockFile::open(&lock_path)
            .map_err(|e| format!("Failed to open lock file: {}", e))?;
        lock.lock().map_err(|e| format!("Failed to acquire lock: {}", e))?;

        let mut state = if self.state_file.exists() {
            let mut file = File::open(&self.state_file)
                .map_err(|e| format!("Failed to open state file: {}", e))?;
            let mut contents = String::new();
            file.read_to_string(&mut contents)
                .map_err(|e| format!("Failed to read state file: {}", e))?;
            if contents.is_empty() {
                eprintln!("Warning: state file is empty, starting with default state");
                FirewallState::default()
            } else {
                serde_json::from_str(&contents)
                    .map_err(|e| format!("Failed to parse state file: {}", e))?
            }
        } else {
            eprintln!("State file does not exist, creating new state");
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
        file.sync_all().map_err(|e| format!("Failed to sync state file: {}", e))?;

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

    pub fn add_rule(
        &self,
        src_group_id: u32,
        dst_group_id: u32,
        proto: u8,
        action: u8,
        ports: Option<&str>,
    ) -> Result<AddRuleResult, String> {
        let mut result = AddRuleResult {
            bitmap_idx: None,
            is_new_port_set: false,
            old_port_set_released: None,
        };
        self.with_state(|state| {
            let (bitmap_idx, is_new) = if let Some(p) = ports {
                if p != "all" && !p.is_empty() {
                    let normalized = normalize_ports(p)?;

                    if let Some(existing_ps) = state.port_sets.get_mut(&normalized) {
                        existing_ps.ref_count += 1;
                        (Some(existing_ps.bitmap_idx), false)
                    } else {
                        let idx = if let Some(recycled) = state.free_bitmap_indices.pop() {
                            recycled
                        } else {
                            if state.next_bitmap_idx >= state.max_port_policies {
                                return Err(format!(
                                    "Port set limit ({}) reached. Unique port combinations: {}",
                                    state.max_port_policies,
                                    state.port_sets.len()
                                ));
                            }
                            let idx = state.next_bitmap_idx;
                            state.next_bitmap_idx += 1;
                            idx
                        };
                        state.port_sets.insert(
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
                }
            } else {
                (None, false)
            };

            // 检测重复规则：相同 (src_group_id, dst_group_id, proto) → 更新
            if let Some(existing) = state.rules.iter_mut().find(|r| {
                r.src_group_id == src_group_id
                    && r.dst_group_id == dst_group_id
                    && r.proto == proto
            }) {
                // 旧规则有 bitmap → 减引用计数
                if let Some(old_idx) = existing.bitmap_idx {
                    // 只有当新旧 bitmap_idx 不同时才释放旧的
                    if bitmap_idx != Some(old_idx) {
                        // 记录旧 port set 信息，以便清理内核
                        let old_ports_normalized = state.port_sets
                            .iter()
                            .find(|(_, ps)| ps.bitmap_idx == old_idx)
                            .map(|(_, ps)| ps.ports_normalized.clone());

                        release_port_set(&mut state.port_sets, &mut state.free_bitmap_indices, old_idx);

                        // 如果 old_idx 被回收，说明 ref_count 归零
                        if state.free_bitmap_indices.contains(&old_idx) {
                            if let Some(ports_norm) = old_ports_normalized {
                                result.old_port_set_released = Some((old_idx, ports_norm));
                            }
                        }
                    } else {
                        // 新旧相同 bitmap_idx，说明端口集相同，撤销上面多加的 ref_count
                        // (上面已 +1，但实际无需增加，因为是替换同一规则)
                        // 不过上面的逻辑会找到已有 port_set 并 +1，这里需要 -1 还原
                        if let Some(key) = state
                            .port_sets
                            .iter()
                            .find(|(_, ps)| ps.bitmap_idx == old_idx)
                            .map(|(k, _)| k.clone())
                        {
                            if let Some(ps) = state.port_sets.get_mut(&key) {
                                ps.ref_count -= 1;
                            }
                        }
                    }
                }
                existing.action = action;
                existing.ports = ports.map(|s| s.to_string());
                existing.bitmap_idx = bitmap_idx;
            } else {
                state.rules.push(RuleInfo {
                    name: None,
                    src_group_id,
                    dst_group_id,
                    proto,
                    action,
                    ports: ports.map(|s| s.to_string()),
                    bitmap_idx,
                });
            }

            result = AddRuleResult {
                bitmap_idx,
                is_new_port_set: is_new,
                old_port_set_released: result.old_port_set_released.take(),
            };
            Ok(())
        })?;
        Ok(result)
    }

    pub fn remove_rule(&self, src_group_id: u32, dst_group_id: u32, proto: u8) -> Result<RemoveRuleResult, String> {
        let mut result = RemoveRuleResult {
            bitmap_idx: None,
            port_set_released: None,
        };
        self.with_state(|state| {
            if let Some(pos) = state.rules.iter().position(|r| {
                r.src_group_id == src_group_id
                    && r.dst_group_id == dst_group_id
                    && r.proto == proto
            }) {
                let rule = state.rules.remove(pos);
                if let Some(idx) = rule.bitmap_idx {
                    // 查找对应的 port_set，记录 normalized ports 以便清理内核
                    let ports_normalized = state.port_sets
                        .iter()
                        .find(|(_, ps)| ps.bitmap_idx == idx)
                        .map(|(_, ps)| ps.ports_normalized.clone());

                    release_port_set(&mut state.port_sets, &mut state.free_bitmap_indices, idx);

                    result.bitmap_idx = Some(idx);
                    // 如果 idx 被回收（出现在 free list 中），说明 ref_count 归零，需要清理内核
                    if state.free_bitmap_indices.contains(&idx) {
                        result.port_set_released = ports_normalized;
                    }
                }
            } else {
                return Err(format!(
                    "Policy not found: src_id={}, dst_id={}, proto={}",
                    src_group_id, dst_group_id, proto
                ));
            }
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
        let mut lock = LockFile::open(&lock_path)
            .map_err(|e| format!("Failed to open lock file: {}", e))?;
        lock.lock().map_err(|e| format!("Failed to acquire lock: {}", e))?;

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
}
