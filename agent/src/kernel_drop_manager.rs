use std::collections::HashMap;
use std::path::Path;

use aria_core::common::KernelDropFilterValue;
use aya::maps::{HashMap as BpfHashMap, Map, MapData};
use tokio::sync::Mutex;
use tracing::{info, warn};

pub const KERNEL_DROP_PIN_NAMESPACE: &str = "kernel-drops-global";
const KERNEL_DROP_MAP_NAMES: &[&str] = &[
    "MANAGED_IFINDEX_FILTER",
    "KERNEL_DROP_STATS",
    "KERNEL_DROP_VALUE_BUF",
];

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
        if state.loaded && self.core_pins_ready() {
            return Ok(());
        }

        match self.load_impl() {
            Ok(()) => {
                if let Err(e) = self.sync_all_managed_ifaces(&state.managed_ifaces) {
                    state.last_error = Some(e.clone());
                    return Err(e);
                }
                state.loaded = true;
                state.mode = KernelDropMode::ScaffoldOnly;
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
            "registered managed interface with kernel drop manager scaffold"
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

    fn load_impl(&self) -> Result<(), String> {
        std::fs::create_dir_all(&self.pin_path)
            .map_err(|e| format!("create kernel-drop pin dir {}: {}", self.pin_path, e))?;

        let bpf_bytes = std::fs::read(&self.ebpf_path)
            .map_err(|e| format!("read ebpf: {}", e))?;
        let mut bpf = self.load_bpf_with_pins(&bpf_bytes)?;

        for map_name in KERNEL_DROP_MAP_NAMES {
            self.pin_map_if_needed(&mut bpf, map_name)?;
        }

        Ok(())
    }

    fn load_bpf_with_pins(&self, bpf_bytes: &[u8]) -> Result<aya::Ebpf, String> {
        aya::EbpfLoader::new()
            .map_pin_path(&self.pin_path)
            .load(bpf_bytes)
            .map_err(|e| format!("load kernel-drop ebpf: {:?}", e))
    }

    fn pin_map_if_needed(&self, bpf: &mut aya::Ebpf, map_name: &str) -> Result<(), String> {
        let target = format!("{}/{}", self.pin_path, map_name);
        if Path::new(&target).exists() {
            return Ok(());
        }

        let map = bpf
            .map_mut(map_name)
            .ok_or_else(|| format!("{} map not found in eBPF binary", map_name))?;
        map.pin(&target)
            .map_err(|e| format!("{} pin: {}", map_name, e))
    }

    fn core_pins_ready(&self) -> bool {
        KERNEL_DROP_MAP_NAMES
            .iter()
            .all(|name| Path::new(&format!("{}/{}", self.pin_path, name)).exists())
    }

    fn managed_ifindex_filter_path(&self) -> String {
        format!("{}/MANAGED_IFINDEX_FILTER", self.pin_path)
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

    fn sync_all_managed_ifaces(&self, managed_ifaces: &HashMap<u32, u32>) -> Result<(), String> {
        let mut map = self.open_managed_ifindex_filter()?;
        let existing_keys: Vec<u32> = map.keys().filter_map(|item| item.ok()).collect();
        for ifindex in existing_keys {
            if map.get(&ifindex, 0).is_ok() {
                map.remove(&ifindex)
                    .map_err(|e| format!("remove stale MANAGED_IFINDEX_FILTER {}: {:?}", ifindex, e))?;
            }
        }
        for (ifindex, tap_id) in managed_ifaces {
            let value = KernelDropFilterValue { tap_id: *tap_id };
            map.insert(ifindex, &value, 0)
                .map_err(|e| format!("insert MANAGED_IFINDEX_FILTER {}=>{}: {:?}", ifindex, tap_id, e))?;
        }
        Ok(())
    }

    fn upsert_managed_iface(&self, ifindex: u32, tap_id: u32) -> Result<(), String> {
        let mut map = self.open_managed_ifindex_filter()?;
        let value = KernelDropFilterValue { tap_id };
        map.insert(&ifindex, &value, 0)
            .map_err(|e| format!("insert MANAGED_IFINDEX_FILTER {}=>{}: {:?}", ifindex, tap_id, e))
    }

    fn delete_managed_iface(&self, ifindex: u32) -> Result<(), String> {
        let mut map = self.open_managed_ifindex_filter()?;
        if map.get(&ifindex, 0).is_err() {
            warn!(ifindex, "kernel drop managed-iface filter entry already absent");
            return Ok(());
        }
        map.remove(&ifindex)
            .map_err(|e| format!("remove MANAGED_IFINDEX_FILTER {}: {:?}", ifindex, e))
    }
}
