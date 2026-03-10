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

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FirewallState {
    pub groups: HashMap<String, GroupInfo>,
    pub rules: Vec<RuleInfo>,
    pub next_group_id: u32,
    pub next_bitmap_idx: u32,
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

    pub fn delete_group(&self, name: &str) -> Result<(), String> {
        self.with_state(|state| {
            state.groups.remove(name);
            Ok(())
        })
    }

    pub fn add_rule(
        &self,
        src_group_id: u32,
        dst_group_id: u32,
        proto: u8,
        action: u8,
        ports: Option<&str>,
    ) -> Result<Option<u32>, String> {
        let mut result = None;
        self.with_state(|state| {
            let bitmap_idx = if let Some(p) = ports {
                if p != "all" && !p.is_empty() {
                    // 边界检查：最多 1024 个位图
                    if state.next_bitmap_idx >= 1024 {
                        return Err("Maximum port filtering limits (1024 policies) reached.".to_string());
                    }
                    let idx = state.next_bitmap_idx;
                    state.next_bitmap_idx += 1;
                    Some(idx)
                } else {
                    None
                }
            } else {
                None
            };
            let rule = RuleInfo {
                name: None,
                src_group_id,
                dst_group_id,
                proto,
                action,
                ports: ports.map(|s| s.to_string()),
                bitmap_idx,
            };
            state.rules.push(rule);
            result = bitmap_idx;
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