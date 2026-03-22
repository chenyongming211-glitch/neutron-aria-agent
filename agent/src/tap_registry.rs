use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};
use regex::Regex;
use crate::instance::FirewallInstance;
use crate::control_plane::ControlPlane;

pub struct TapRegistry {
    instances: RwLock<HashMap<String, FirewallInstance>>,
    /// Per-iface mutex to serialize attach/detach on the same interface
    iface_locks: RwLock<HashMap<String, Arc<Mutex<()>>>>,
    pub ebpf_path: PathBuf,
    pub base_pin_path: PathBuf,
    pub base_state_path: PathBuf,
    pub iface_pattern: Regex,
    pub max_port_policies: u32,
    control_plane: Arc<ControlPlane>,
}

impl TapRegistry {
    pub fn new(
        ebpf_path: &str,
        base_pin_path: &str,
        base_state_path: &str,
        iface_pattern: &str,
        max_port_policies: u32,
        control_plane: Arc<ControlPlane>,
    ) -> Self {
        Self {
            instances: RwLock::new(HashMap::new()),
            iface_locks: RwLock::new(HashMap::new()),
            ebpf_path: PathBuf::from(ebpf_path),
            base_pin_path: PathBuf::from(base_pin_path),
            base_state_path: PathBuf::from(base_state_path),
            iface_pattern: Regex::new(iface_pattern)
                .unwrap_or_else(|_| Regex::new("^tap").unwrap()),
            max_port_policies,
            control_plane,
        }
    }

    /// Get or create the per-iface mutex for serializing operations
    async fn get_iface_lock(&self, iface: &str) -> Arc<Mutex<()>> {
        let locks = self.iface_locks.read().await;
        if let Some(lock) = locks.get(iface) {
            return lock.clone();
        }
        drop(locks);

        let mut locks = self.iface_locks.write().await;
        locks.entry(iface.to_string())
            .or_insert_with(|| Arc::new(Mutex::new(())))
            .clone()
    }

    /// Check if the interface name matches the configured pattern
    pub fn matches_pattern(&self, iface: &str) -> bool {
        self.iface_pattern.is_match(iface)
    }

    /// Attach XDP firewall to a tap interface. Idempotent: skips if already attached.
    pub async fn attach(&self, iface: &str) -> Result<(), String> {
        // Idempotent check
        {
            let instances = self.instances.read().await;
            if instances.contains_key(iface) {
                return Ok(());
            }
        }

        let iface_lock = self.get_iface_lock(iface).await;
        let _guard = iface_lock.lock().await;

        // Re-check after acquiring lock
        {
            let instances = self.instances.read().await;
            if instances.contains_key(iface) {
                return Ok(());
            }
        }

        let mut instance = FirewallInstance::new(
            iface,
            self.base_pin_path.to_str().unwrap(),
            self.base_state_path.to_str().unwrap(),
        );

        // 为该 tap 实例设置端口策略上限（写入对应 state.json）
        let state_dir = self.base_state_path.join(iface);
        if let Some(state_str) = state_dir.to_str() {
            let sm = aria_core::state::StateManager::new(state_str);
            if let Err(e) = sm.set_max_port_policies(self.max_port_policies) {
                eprintln!("[{}] Warning: failed to set max_port_policies: {}", iface, e);
            }
        }

        instance.attach(self.ebpf_path.to_str().unwrap())?;

        // Register with ControlPlane
        self.control_plane.register_instance(iface).await;

        let mut instances = self.instances.write().await;
        instances.insert(iface.to_string(), instance);

        Ok(())
    }

    /// Detach XDP firewall from a tap interface.
    pub async fn detach(&self, iface: &str) -> Result<(), String> {
        let iface_lock = self.get_iface_lock(iface).await;
        let _guard = iface_lock.lock().await;

        let instance_exists = {
            let instances = self.instances.read().await;
            instances.contains_key(iface)
        };

        if instance_exists {
            let instances = self.instances.read().await;
            let instance = instances.get(iface).expect("instance existence checked above");
            instance.detach()?;
        }

        {
            let mut instances = self.instances.write().await;
            instances.remove(iface);
        }

        if instance_exists {
            self.control_plane.unregister_instance(iface).await;
        }

        // Clean up the per-iface lock
        let mut locks = self.iface_locks.write().await;
        locks.remove(iface);

        Ok(())
    }

    /// List all managed tap interfaces
    pub async fn list(&self) -> Vec<String> {
        let instances = self.instances.read().await;
        let mut names: Vec<String> = instances.keys().cloned().collect();
        names.sort();
        names
    }

    /// Graceful shutdown: unpin all links (XDP detaches), clean up
    pub async fn shutdown(&self) {
        let ifaces: Vec<String> = {
            let instances = self.instances.read().await;
            instances.keys().cloned().collect()
        };

        for iface in &ifaces {
            if let Err(e) = self.detach(iface).await {
                eprintln!("[{}] Warning: shutdown detach failed: {}", iface, e);
            }
        }
        println!("All firewall instances detached");
    }
}
