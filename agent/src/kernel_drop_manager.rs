use std::collections::HashMap;

use tokio::sync::Mutex;
use tracing::info;

pub const KERNEL_DROP_PIN_NAMESPACE: &str = "kernel-drops-global";

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum KernelDropMode {
    Disabled,
    ScaffoldOnly,
    KfreeSkbLegacy,
    KfreeSkbReasonful,
}

#[derive(Clone, Debug)]
pub struct KernelDropStatusSnapshot {
    pub loaded: bool,
    pub mode: KernelDropMode,
    pub managed_ifaces: usize,
    pub last_error: Option<String>,
}

struct KernelDropManagerState {
    loaded: bool,
    mode: KernelDropMode,
    managed_ifaces: HashMap<u32, u32>,
    last_error: Option<String>,
}

pub struct KernelDropManager {
    ebpf_path: String,
    base_pin_path: String,
    pin_path: String,
    state: Mutex<KernelDropManagerState>,
}

impl KernelDropManager {
    pub fn new(ebpf_path: &str, base_pin_path: &str) -> Self {
        Self {
            ebpf_path: ebpf_path.to_string(),
            base_pin_path: base_pin_path.to_string(),
            pin_path: format!("{}/{}", base_pin_path, KERNEL_DROP_PIN_NAMESPACE),
            state: Mutex::new(KernelDropManagerState {
                loaded: false,
                mode: KernelDropMode::Disabled,
                managed_ifaces: HashMap::new(),
                last_error: None,
            }),
        }
    }

    pub fn pin_path(&self) -> &str {
        &self.pin_path
    }

    pub async fn ensure_loaded(&self) -> Result<(), String> {
        std::fs::create_dir_all(&self.pin_path)
            .map_err(|e| format!("create kernel-drop pin dir {}: {}", self.pin_path, e))?;

        let mut state = self.state.lock().await;
        state.loaded = true;
        state.mode = KernelDropMode::ScaffoldOnly;
        state.last_error = None;

        info!(
            ebpf_path = %self.ebpf_path,
            base_pin_path = %self.base_pin_path,
            pin_path = %self.pin_path,
            mode = ?state.mode,
            "kernel drop manager scaffold initialized"
        );
        Ok(())
    }

    pub async fn sync_managed_iface(
        &self,
        iface: &str,
        ifindex: u32,
        tap_id: u32,
    ) -> Result<(), String> {
        let mut state = self.state.lock().await;
        state.managed_ifaces.insert(ifindex, tap_id);
        info!(
            iface = %iface,
            ifindex,
            tap_id,
            managed_ifaces = state.managed_ifaces.len(),
            "registered managed interface with kernel drop manager scaffold"
        );
        Ok(())
    }

    pub async fn remove_managed_iface(&self, ifindex: u32) -> Result<(), String> {
        let mut state = self.state.lock().await;
        state.managed_ifaces.remove(&ifindex);
        info!(
            ifindex,
            managed_ifaces = state.managed_ifaces.len(),
            "removed managed interface from kernel drop manager scaffold"
        );
        Ok(())
    }

    pub async fn status_snapshot(&self) -> KernelDropStatusSnapshot {
        let state = self.state.lock().await;
        KernelDropStatusSnapshot {
            loaded: state.loaded,
            mode: state.mode,
            managed_ifaces: state.managed_ifaces.len(),
            last_error: state.last_error.clone(),
        }
    }
}
