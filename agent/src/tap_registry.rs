use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};
use regex::Regex;
use tracing::{info, warn};
use crate::instance::FirewallInstance;
use crate::control_plane::{ControlPlane, MANAGED_SHARED_PIN_NAMESPACE};

pub struct TapRegistry {
    instances: RwLock<HashMap<String, FirewallInstance>>,
    /// Per-iface mutex to serialize attach/detach on the same interface
    iface_locks: RwLock<HashMap<String, Arc<Mutex<()>>>>,
    runtime_lock: Mutex<()>,
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
            runtime_lock: Mutex::new(()),
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

    fn cleanup_shared_runtime_dir(&self) {
        let shared_pin_path = self.base_pin_path.join(MANAGED_SHARED_PIN_NAMESPACE);
        if shared_pin_path.exists() {
            if let Err(e) = std::fs::remove_dir_all(&shared_pin_path) {
                warn!(
                    path = %shared_pin_path.display(),
                    error = %e,
                    "failed to remove shared managed pin directory"
                );
            } else {
                info!(path = %shared_pin_path.display(), "removed shared managed pin directory");
            }
        }
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
        let _runtime_guard = self.runtime_lock.lock().await;

        // Re-check after acquiring lock
        {
            let instances = self.instances.read().await;
            if instances.contains_key(iface) {
                return Ok(());
            }
        }

        let known_live_runtime = {
            let instances = self.instances.read().await;
            !instances.is_empty()
        };

        let mut instance = FirewallInstance::new(
            iface,
            PathBuf::from(self.control_plane.managed_pin_path()),
            self.base_state_path.join(iface),
            true,
        );

        // 为该 tap 实例设置端口策略上限（写入对应 state.json）
        let state_dir = self.base_state_path.join(iface);
        if let Some(state_str) = state_dir.to_str() {
            let sm = aria_core::state::StateManager::new(state_str);
            if let Err(e) = sm.set_max_port_policies(self.max_port_policies) {
                warn!(instance = %iface, error = %e, "failed to persist max_port_policies");
            }
        }

        let runtime_pin = instance.ensure_runtime_pinned(
            self.ebpf_path.to_str().unwrap(),
            known_live_runtime,
        )?;

        let prepared = match self
            .control_plane
            .prepare_managed_registration(iface, &runtime_pin)
            .await
        {
            Ok(prepared) => prepared,
            Err(e) => {
                if runtime_pin.created_shared_runtime {
                    self.cleanup_shared_runtime_dir();
                }
                return Err(format!("control-plane prepare failed: {}", e));
            }
        };

        if let Err(e) = instance.reserve_persisted_live_iface() {
            self.control_plane.abort_managed_registration(prepared).await;
            if runtime_pin.created_shared_runtime {
                self.cleanup_shared_runtime_dir();
            }
            return Err(format!("failed to reserve persisted live runtime state: {}", e));
        }

        if let Err(e) = instance.attach_links_from_pinned_runtime(&runtime_pin) {
            if let Err(release_err) = instance.release_persisted_live_iface() {
                warn!(instance = %iface, error = %release_err, "failed to roll back persisted live runtime state");
            }
            self.control_plane.abort_managed_registration(prepared).await;
            if runtime_pin.created_shared_runtime {
                self.cleanup_shared_runtime_dir();
            }
            return Err(format!("interface link attach failed: {}", e));
        }

        self.control_plane.publish_managed_instance(prepared).await;

        let mut instances = self.instances.write().await;
        instances.insert(iface.to_string(), instance);

        Ok(())
    }

    /// Detach XDP firewall from a tap interface.
    pub async fn detach(&self, iface: &str) -> Result<(), String> {
        let iface_lock = self.get_iface_lock(iface).await;
        let _guard = iface_lock.lock().await;
        let _runtime_guard = self.runtime_lock.lock().await;

        let instance_exists = {
            let instances = self.instances.read().await;
            instances.contains_key(iface)
        };

        if instance_exists {
            let instances = self.instances.read().await;
            let instance = instances.get(iface).expect("instance existence checked above");
            instance.detach()?;
            if let Err(e) = instance.release_persisted_live_iface() {
                warn!(instance = %iface, error = %e, "failed to release persisted live runtime state");
            }
        }

        {
            let mut instances = self.instances.write().await;
            instances.remove(iface);
        }

        if instance_exists {
            self.control_plane.unregister_instance(iface).await;
        }

        let should_cleanup_shared_runtime = {
            let instances = self.instances.read().await;
            instances.is_empty()
        };

        if should_cleanup_shared_runtime {
            self.cleanup_shared_runtime_dir();
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
                warn!(instance = %iface, error = %e, "shutdown detach failed");
            }
        }
        info!("all firewall instances detached");
    }
}
