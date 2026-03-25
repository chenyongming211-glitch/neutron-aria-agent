use std::collections::HashMap;
use std::path::Path;

use aria_core::common::{KernelDropConfig, KernelDropFilterValue, KERNEL_DROP_FLAG_HAS_REASON};
use aya::maps::{HashMap as BpfHashMap, Map, MapData};
use tokio::sync::Mutex;
use tracing::{info, warn};

use crate::kernel_drop_support::{
    attach_tracepoint_if_needed, load_tracepoint_program, pin_map_if_needed, pin_program_if_needed,
    resolve_kernel_drop_config, KERNEL_DROP_LINK_NAME, KERNEL_DROP_MAP_NAMES,
    KERNEL_DROP_PROGRAM_NAME, KERNEL_DROP_TRACEPOINT_CATEGORY, KERNEL_DROP_TRACEPOINT_NAME,
};

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
        let mut state = self.state.lock().await;
        let need_core_init = !state.loaded || !self.core_pins_ready();
        let need_link_init = !state.loaded || !self.link_pins_ready();

        if !need_core_init && !need_link_init {
            return Ok(());
        }

        match self.load_impl() {
            Ok(mode) => {
                if let Err(e) = self.sync_all_managed_ifaces(&state.managed_ifaces) {
                    state.last_error = Some(e.clone());
                    return Err(e);
                }
                state.loaded = true;
                state.mode = mode;
                state.last_error = None;
            }
            Err(e) => {
                state.loaded = false;
                state.last_error = Some(e.clone());
                return Err(e);
            }
        }

        info!(
            ebpf_path = %self.ebpf_path,
            base_pin_path = %self.base_pin_path,
            pin_path = %self.pin_path,
            mode = ?state.mode,
            "kernel drop manager initialized"
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
        if let Err(e) = self.upsert_managed_iface(ifindex, tap_id) {
            state.last_error = Some(e.clone());
            return Err(e);
        }
        state.last_error = None;
        info!(
            iface = %iface,
            ifindex,
            tap_id,
            managed_ifaces = state.managed_ifaces.len(),
            "registered managed interface with kernel drop manager"
        );
        Ok(())
    }

    pub async fn remove_managed_iface(&self, ifindex: u32) -> Result<(), String> {
        let mut state = self.state.lock().await;
        state.managed_ifaces.remove(&ifindex);
        if let Err(e) = self.delete_managed_iface(ifindex) {
            state.last_error = Some(e.clone());
            return Err(e);
        }
        state.last_error = None;
        info!(
            ifindex,
            managed_ifaces = state.managed_ifaces.len(),
            "removed managed interface from kernel drop manager"
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

    fn load_impl(&self) -> Result<KernelDropMode, String> {
        std::fs::create_dir_all(&self.pin_path)
            .map_err(|e| format!("create kernel-drop pin dir {}: {}", self.pin_path, e))?;

        let config = resolve_kernel_drop_config()?;
        let bpf_bytes = std::fs::read(&self.ebpf_path).map_err(|e| format!("read ebpf: {}", e))?;
        let mut bpf = self.load_bpf_with_pins(&bpf_bytes)?;

        for map_name in KERNEL_DROP_MAP_NAMES {
            pin_map_if_needed(&mut bpf, map_name, &self.pin_path)?;
        }
        self.store_kernel_drop_config(&config)?;

        load_tracepoint_program(&mut bpf, KERNEL_DROP_PROGRAM_NAME)?;
        pin_program_if_needed(&mut bpf, KERNEL_DROP_PROGRAM_NAME, &self.pin_path)?;
        attach_tracepoint_if_needed(
            &mut bpf,
            KERNEL_DROP_PROGRAM_NAME,
            KERNEL_DROP_TRACEPOINT_CATEGORY,
            KERNEL_DROP_TRACEPOINT_NAME,
            &self.pin_path,
        )?;

        Ok(if (config.flags & KERNEL_DROP_FLAG_HAS_REASON) != 0 {
            KernelDropMode::KfreeSkbReasonful
        } else {
            KernelDropMode::KfreeSkbLegacy
        })
    }

    fn load_bpf_with_pins(&self, bpf_bytes: &[u8]) -> Result<aya::Ebpf, String> {
        aya::EbpfLoader::new()
            .map_pin_path(&self.pin_path)
            .load(bpf_bytes)
            .map_err(|e| format!("load kernel-drop ebpf: {:?}", e))
    }

    fn core_pins_ready(&self) -> bool {
        KERNEL_DROP_MAP_NAMES
            .iter()
            .all(|name| Path::new(&format!("{}/{}", self.pin_path, name)).exists())
            && Path::new(&format!("{}/{}", self.pin_path, KERNEL_DROP_PROGRAM_NAME)).exists()
    }

    fn link_pins_ready(&self) -> bool {
        Path::new(&format!("{}/{}", self.pin_path, KERNEL_DROP_LINK_NAME)).exists()
    }

    fn managed_ifindex_filter_path(&self) -> String {
        format!("{}/MANAGED_IFINDEX_FILTER", self.pin_path)
    }

    fn kernel_drop_config_path(&self) -> String {
        format!("{}/KERNEL_DROP_CONFIG", self.pin_path)
    }

    fn open_managed_ifindex_filter(
        &self,
    ) -> Result<BpfHashMap<MapData, u32, KernelDropFilterValue>, String> {
        let map_path = self.managed_ifindex_filter_path();
        let map_data = MapData::from_pin(&map_path)
            .map_err(|e| format!("open MANAGED_IFINDEX_FILTER {}: {:?}", map_path, e))?;
        BpfHashMap::<_, u32, KernelDropFilterValue>::try_from(Map::HashMap(map_data))
            .map_err(|e| format!("convert MANAGED_IFINDEX_FILTER: {:?}", e))
    }

    fn open_kernel_drop_config(
        &self,
    ) -> Result<BpfHashMap<MapData, u32, KernelDropConfig>, String> {
        let map_path = self.kernel_drop_config_path();
        let map_data = MapData::from_pin(&map_path)
            .map_err(|e| format!("open KERNEL_DROP_CONFIG {}: {:?}", map_path, e))?;
        BpfHashMap::<_, u32, KernelDropConfig>::try_from(Map::HashMap(map_data))
            .map_err(|e| format!("convert KERNEL_DROP_CONFIG: {:?}", e))
    }

    fn store_kernel_drop_config(&self, config: &KernelDropConfig) -> Result<(), String> {
        let mut map = self.open_kernel_drop_config()?;
        let key = 0u32;
        map.insert(&key, config, 0)
            .map_err(|e| format!("insert KERNEL_DROP_CONFIG: {:?}", e))
    }

    fn sync_all_managed_ifaces(&self, managed_ifaces: &HashMap<u32, u32>) -> Result<(), String> {
        let mut map = self.open_managed_ifindex_filter()?;
        let existing_keys: Vec<u32> = map.keys().filter_map(|item| item.ok()).collect();
        for ifindex in existing_keys {
            if map.get(&ifindex, 0).is_ok() {
                map.remove(&ifindex).map_err(|e| {
                    format!("remove stale MANAGED_IFINDEX_FILTER {}: {:?}", ifindex, e)
                })?;
            }
        }
        for (ifindex, tap_id) in managed_ifaces {
            let value = KernelDropFilterValue { tap_id: *tap_id };
            map.insert(ifindex, &value, 0).map_err(|e| {
                format!(
                    "insert MANAGED_IFINDEX_FILTER {}=>{}: {:?}",
                    ifindex, tap_id, e
                )
            })?;
        }
        Ok(())
    }

    fn upsert_managed_iface(&self, ifindex: u32, tap_id: u32) -> Result<(), String> {
        let mut map = self.open_managed_ifindex_filter()?;
        let value = KernelDropFilterValue { tap_id };
        map.insert(&ifindex, &value, 0).map_err(|e| {
            format!(
                "insert MANAGED_IFINDEX_FILTER {}=>{}: {:?}",
                ifindex, tap_id, e
            )
        })
    }

    fn delete_managed_iface(&self, ifindex: u32) -> Result<(), String> {
        let mut map = self.open_managed_ifindex_filter()?;
        if map.get(&ifindex, 0).is_err() {
            warn!(
                ifindex,
                "kernel drop managed-iface filter entry already absent"
            );
            return Ok(());
        }
        map.remove(&ifindex)
            .map_err(|e| format!("remove MANAGED_IFINDEX_FILTER {}: {:?}", ifindex, e))
    }
}
