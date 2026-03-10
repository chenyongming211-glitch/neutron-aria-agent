use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::PathBuf;
use fslock::LockFile;  // 新增

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
        Self { state_file }
    }

    // 内部方法：加载状态（带锁）
    fn load(&self) -> Result<FirewallState, String> {
        // 打开文件（若不存在则创建空状态）
        if !self.state_file.exists() {
            return Ok(FirewallState::default());
        }

        let mut lock = LockFile::open(&self.state_file)
            .map_err(|e| format!("Failed to open lock file: {}", e))?;
        lock.lock().map_err(|e| format!("Failed to acquire lock: {}", e))?;

        let mut file = File::open(&self.state_file)
            .map_err(|e| format!("Failed to open state file: {}", e))?;
        let mut contents = String::new();
        file.read_to_string(&mut contents)
            .map_err(|e| format!("Failed to read state file: {}", e))?;

        let state: FirewallState = serde_json::from_str(&contents)
            .map_err(|e| format!("Failed to parse state: {}", e))?;

        Ok(state)
    }

    // 内部方法：保存状态（带锁）
    fn save(&self, state: &FirewallState) -> Result<(), String> {
        let mut lock = LockFile::open(&self.state_file)
            .map_err(|e| format!("Failed to open lock file: {}", e))?;
        lock.lock().map_err(|e| format!("Failed to acquire lock: {}", e))?;

        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&self.state_file)
            .map_err(|e| format!("Failed to open state file: {}", e))?;

        let contents = serde_json::to_string_pretty(state)
            .map_err(|e| format!("Failed to serialize state: {}", e))?;

        file.write_all(contents.as_bytes())
            .map_err(|e| format!("Failed to write state file: {}", e))?;

        Ok(())
    }

    pub fn add_group(&self, name: &str, cidr: &str) -> Result<u32, String> {
        let mut state = self.load()?;

        let existing_id = state.groups.get(name).map(|g| g.id);
        if let Some(id) = existing_id {
            if let Some(existing) = state.groups.get_mut(name) {
                if !existing.cidrs.contains(&cidr.to_string()) {
                    existing.cidrs.push(cidr.to_string());
                    self.save(&state)?;
                }
            }
            return Ok(id);
        }

        let id = state.next_group_id;
        state.next_group_id += 1;

        let group = GroupInfo {
            id,
            name: name.to_string(),
            cidrs: vec![cidr.to_string()],
        };

        state.groups.insert(name.to_string(), group);
        self.save(&state)?;

        Ok(id)
    }

    pub fn add_rule(
        &self,
        src_group_id: u32,
        dst_group_id: u32,
        proto: u8,
        action: u8,
        ports: Option<&str>,
    ) -> Result<Option<u32>, String> {
        let mut state = self.load()?;

        let bitmap_idx = if ports.is_some() && ports != Some("all") && !ports.unwrap().is_empty() {
            let idx = state.next_bitmap_idx;
            state.next_bitmap_idx += 1;
            Some(idx)
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
        self.save(&state)?;

        Ok(bitmap_idx)
    }

    pub fn get_group(&self, name: &str) -> Result<Option<GroupInfo>, String> {
        let state = self.load()?;
        Ok(state.groups.get(name).cloned())
    }

    pub fn list_groups(&self) -> Result<Vec<GroupInfo>, String> {
        let state = self.load()?;
        Ok(state.groups.values().cloned().collect())
    }

    pub fn list_rules(&self) -> Result<Vec<RuleInfo>, String> {
        let state = self.load()?;
        Ok(state.rules.clone())
    }

    pub fn get_group_by_id(&self, id: u32) -> Result<Option<GroupInfo>, String> {
        let state = self.load()?;
        Ok(state.groups.values().find(|g| g.id == id).cloned())
    }
}