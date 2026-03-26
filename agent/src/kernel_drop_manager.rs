use std::collections::HashMap;
use std::path::Path;

use aria_core::common::{KernelDropConfig, KernelDropFilterValue, KERNEL_DROP_FLAG_HAS_REASON};
use aria_core::wal;
use aya::maps::{HashMap as BpfHashMap, Map, MapData};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::sync::Mutex;
use tracing::{info, warn};

use crate::control_plane::MANAGED_SHARED_PIN_NAMESPACE;
use crate::kernel_drop_support::{
    load_tracepoint_program, pin_map_if_needed, replace_pinned_program,
    replace_pinned_tracepoint_link, resolve_kernel_drop_config, KERNEL_DROP_LINK_NAME,
    KERNEL_DROP_MAP_NAMES, KERNEL_DROP_PROGRAM_NAME, KERNEL_DROP_TRACEPOINT_CATEGORY,
    KERNEL_DROP_TRACEPOINT_NAME,
};

pub const KERNEL_DROP_PIN_NAMESPACE: &str = "kernel-drops-global";
const KERNEL_DROP_RUNTIME_METADATA_SCHEMA_VERSION: u32 = 1;
const KERNEL_DROP_MAP_SCHEMA_VERSION: u32 = 1;
const KERNEL_DROP_PERSISTED_LIVE_IFACES_SCHEMA_VERSION: u32 = 2;

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

#[derive(Debug, Clone, Serialize, Deserialize)]
struct KernelDropRuntimeMetadata {
    schema_version: u32,
    map_schema_version: u32,
    ebpf_sha256: String,
    expected_map_pins: Vec<String>,
    program_name: String,
    tracepoint_category: String,
    tracepoint_name: String,
}

#[derive(Debug, Clone)]
enum KernelDropMapInventoryStatus {
    Healthy,
    StaleOrIncomplete(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PersistedLiveIface {
    iface: String,
    ifindex: u32,
    #[serde(default = "default_persisted_live_iface_active")]
    active: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PersistedLiveIfaces {
    schema_version: u32,
    ifaces: Vec<PersistedLiveIface>,
}

fn default_persisted_live_iface_active() -> bool {
    true
}

pub struct KernelDropManager {
    ebpf_path: String,
    base_pin_path: String,
    base_state_path: String,
    pin_path: String,
    state: Mutex<KernelDropManagerState>,
}

impl KernelDropManager {
    pub fn new(ebpf_path: &str, base_pin_path: &str, base_state_path: &str) -> Self {
        Self {
            ebpf_path: ebpf_path.to_string(),
            base_pin_path: base_pin_path.to_string(),
            base_state_path: base_state_path.to_string(),
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
        let recovery_snapshot_authoritative =
            self.seed_recovered_managed_ifaces(&mut state.managed_ifaces)?;
        let need_core_init = !state.loaded || !self.core_pins_ready();
        let need_link_init = !state.loaded || !self.link_pins_ready();

        if !need_core_init && !need_link_init {
            return Ok(());
        }

        match self.load_impl() {
            Ok(mode) => {
                if let Err(e) = self
                    .sync_all_managed_ifaces(&state.managed_ifaces, recovery_snapshot_authoritative)
                {
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
        let expected_metadata = self.expected_runtime_metadata()?;
        if let KernelDropMapInventoryStatus::StaleOrIncomplete(reason) =
            self.validate_runtime_inventory(&expected_metadata)
        {
            info!(reason = %reason, "rebuilding kernel-drop runtime due to stale map inventory");
            self.rebuild_runtime()?;
        }

        let bpf_bytes = std::fs::read(&self.ebpf_path).map_err(|e| format!("read ebpf: {}", e))?;
        let mut bpf = self.load_bpf_with_pins(&bpf_bytes)?;

        for map_name in KERNEL_DROP_MAP_NAMES {
            pin_map_if_needed(&mut bpf, map_name, &self.pin_path)?;
        }
        self.store_kernel_drop_config(&config)?;

        load_tracepoint_program(&mut bpf, KERNEL_DROP_PROGRAM_NAME)?;
        replace_pinned_program(&mut bpf, KERNEL_DROP_PROGRAM_NAME, &self.pin_path)?;
        replace_pinned_tracepoint_link(
            &mut bpf,
            KERNEL_DROP_PROGRAM_NAME,
            KERNEL_DROP_TRACEPOINT_CATEGORY,
            KERNEL_DROP_TRACEPOINT_NAME,
            &self.pin_path,
        )?;
        self.store_runtime_metadata_atomically(&expected_metadata)?;

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

    fn runtime_metadata_path(&self) -> String {
        format!(
            "{}/.{}.runtime.meta.json",
            self.base_state_path, KERNEL_DROP_PIN_NAMESPACE
        )
    }

    fn managed_persisted_live_ifaces_path(&self) -> String {
        format!(
            "{}/.{}.live-ifaces.json",
            self.base_state_path, MANAGED_SHARED_PIN_NAMESPACE
        )
    }

    fn system_state_path(&self) -> String {
        format!("{}/system", self.base_state_path)
    }

    fn compute_ebpf_sha256(&self) -> Result<String, String> {
        let bytes =
            std::fs::read(&self.ebpf_path).map_err(|e| format!("read ebpf for hash: {}", e))?;
        let digest = Sha256::digest(bytes);
        Ok(digest
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<_>>()
            .join(""))
    }

    fn expected_runtime_metadata(&self) -> Result<KernelDropRuntimeMetadata, String> {
        Ok(KernelDropRuntimeMetadata {
            schema_version: KERNEL_DROP_RUNTIME_METADATA_SCHEMA_VERSION,
            map_schema_version: KERNEL_DROP_MAP_SCHEMA_VERSION,
            ebpf_sha256: self.compute_ebpf_sha256()?,
            expected_map_pins: KERNEL_DROP_MAP_NAMES
                .iter()
                .map(|name| (*name).to_string())
                .collect(),
            program_name: KERNEL_DROP_PROGRAM_NAME.to_string(),
            tracepoint_category: KERNEL_DROP_TRACEPOINT_CATEGORY.to_string(),
            tracepoint_name: KERNEL_DROP_TRACEPOINT_NAME.to_string(),
        })
    }

    fn load_runtime_metadata(&self) -> Result<KernelDropRuntimeMetadata, String> {
        let path = self.runtime_metadata_path();
        let raw = std::fs::read_to_string(&path)
            .map_err(|e| format!("read kernel-drop runtime metadata {}: {}", path, e))?;
        serde_json::from_str(&raw)
            .map_err(|e| format!("parse kernel-drop runtime metadata {}: {}", path, e))
    }

    fn store_runtime_metadata_atomically(
        &self,
        metadata: &KernelDropRuntimeMetadata,
    ) -> Result<(), String> {
        let path = self.runtime_metadata_path();
        let tmp_path = format!("{}.tmp", path);
        let json = serde_json::to_string_pretty(metadata)
            .map_err(|e| format!("serialize kernel-drop runtime metadata: {}", e))?;
        if let Some(parent) = Path::new(&path).parent() {
            std::fs::create_dir_all(parent).map_err(|e| {
                format!(
                    "create kernel-drop runtime metadata dir {}: {}",
                    parent.display(),
                    e
                )
            })?;
        }
        std::fs::write(&tmp_path, json)
            .map_err(|e| format!("write kernel-drop runtime metadata tmp {}: {}", tmp_path, e))?;
        std::fs::rename(&tmp_path, &path)
            .map_err(|e| format!("rename kernel-drop runtime metadata {}: {}", path, e))?;
        Ok(())
    }

    fn store_persisted_live_ifaces_atomically(
        &self,
        state: &PersistedLiveIfaces,
    ) -> Result<(), String> {
        let path = self.managed_persisted_live_ifaces_path();
        let tmp_path = format!("{}.tmp", path);
        let json = serde_json::to_string_pretty(state)
            .map_err(|e| format!("serialize kernel-drop persisted live ifaces: {}", e))?;
        if let Some(parent) = Path::new(&path).parent() {
            std::fs::create_dir_all(parent).map_err(|e| {
                format!(
                    "create kernel-drop persisted live ifaces dir {}: {}",
                    parent.display(),
                    e
                )
            })?;
        }
        std::fs::write(&tmp_path, json).map_err(|e| {
            format!(
                "write kernel-drop persisted live ifaces tmp {}: {}",
                tmp_path, e
            )
        })?;
        std::fs::rename(&tmp_path, &path)
            .map_err(|e| format!("rename kernel-drop persisted live ifaces {}: {}", path, e))?;
        Ok(())
    }

    fn current_ifindex_for_iface(iface: &str) -> Option<u32> {
        let path = format!("/sys/class/net/{}/ifindex", iface);
        let raw = std::fs::read_to_string(&path).ok()?;
        raw.trim()
            .parse::<u32>()
            .ok()
            .filter(|ifindex| *ifindex != 0)
    }

    fn load_persisted_live_ifaces(&self) -> Result<(PersistedLiveIfaces, bool), String> {
        let path = self.managed_persisted_live_ifaces_path();
        if !Path::new(&path).exists() {
            return Ok((
                PersistedLiveIfaces {
                    schema_version: KERNEL_DROP_PERSISTED_LIVE_IFACES_SCHEMA_VERSION,
                    ifaces: Vec::new(),
                },
                false,
            ));
        }

        let raw = std::fs::read_to_string(&path)
            .map_err(|e| format!("read kernel-drop persisted live ifaces {}: {}", path, e))?;
        let mut state: PersistedLiveIfaces = serde_json::from_str(&raw)
            .map_err(|e| format!("parse kernel-drop persisted live ifaces {}: {}", path, e))?;
        let original_schema_version = state.schema_version;
        if original_schema_version != 1
            && original_schema_version != KERNEL_DROP_PERSISTED_LIVE_IFACES_SCHEMA_VERSION
        {
            return Err(format!(
                "kernel-drop persisted live ifaces schema {} is unsupported (expected 1 or {})",
                original_schema_version, KERNEL_DROP_PERSISTED_LIVE_IFACES_SCHEMA_VERSION
            ));
        }
        let authoritative =
            original_schema_version == KERNEL_DROP_PERSISTED_LIVE_IFACES_SCHEMA_VERSION;
        if original_schema_version == 1 {
            for entry in &mut state.ifaces {
                entry.active = false;
            }
        }
        state.schema_version = KERNEL_DROP_PERSISTED_LIVE_IFACES_SCHEMA_VERSION;
        if original_schema_version == 1 {
            self.store_persisted_live_ifaces_atomically(&state)?;
        }
        Ok((state, authoritative))
    }

    fn seed_recovered_managed_ifaces(
        &self,
        managed_ifaces: &mut HashMap<u32, u32>,
    ) -> Result<bool, String> {
        let (persisted_live, authoritative_snapshot) = match self.load_persisted_live_ifaces() {
            Ok(state) => state,
            Err(e) => {
                warn!(error = %e, "failed to load persisted live-iface state for kernel-drop recovery");
                (
                    PersistedLiveIfaces {
                        schema_version: KERNEL_DROP_PERSISTED_LIVE_IFACES_SCHEMA_VERSION,
                        ifaces: Vec::new(),
                    },
                    false,
                )
            }
        };
        for persisted in persisted_live.ifaces {
            if !persisted.active {
                continue;
            }
            let Some(current_ifindex) = Self::current_ifindex_for_iface(&persisted.iface) else {
                continue;
            };
            let state_path = format!("{}/{}", self.base_state_path, persisted.iface);
            let state = wal::load_with_wal(&state_path);
            if state.tap_id == aria_core::common::TAP_ID_UNASSIGNED {
                continue;
            }
            managed_ifaces
                .entry(current_ifindex)
                .or_insert(state.tap_id);
        }

        let system_state_path = self.system_state_path();
        if Path::new(&system_state_path).exists() {
            let system_state = wal::load_with_wal(&system_state_path);
            if let Some(iface) = system_state.attached_iface {
                if let Some(current_ifindex) = Self::current_ifindex_for_iface(&iface) {
                    managed_ifaces
                        .entry(current_ifindex)
                        .or_insert(aria_core::common::TAP_ID_UNASSIGNED);
                }
            }
        }

        Ok(authoritative_snapshot)
    }

    fn validate_runtime_inventory(
        &self,
        expected: &KernelDropRuntimeMetadata,
    ) -> KernelDropMapInventoryStatus {
        let metadata = match self.load_runtime_metadata() {
            Ok(metadata) => metadata,
            Err(e) => return KernelDropMapInventoryStatus::StaleOrIncomplete(e),
        };

        if metadata.schema_version != expected.schema_version {
            return KernelDropMapInventoryStatus::StaleOrIncomplete(format!(
                "kernel-drop metadata schema {} != expected {}",
                metadata.schema_version, expected.schema_version
            ));
        }

        if metadata.map_schema_version != expected.map_schema_version {
            return KernelDropMapInventoryStatus::StaleOrIncomplete(format!(
                "kernel-drop map schema {} != expected {}",
                metadata.map_schema_version, expected.map_schema_version
            ));
        }

        if metadata.expected_map_pins != expected.expected_map_pins {
            return KernelDropMapInventoryStatus::StaleOrIncomplete(format!(
                "kernel-drop map inventory {:?} != expected {:?}",
                metadata.expected_map_pins, expected.expected_map_pins
            ));
        }

        for map_name in &metadata.expected_map_pins {
            let path = format!("{}/{}", self.pin_path, map_name);
            if !Path::new(&path).exists() {
                return KernelDropMapInventoryStatus::StaleOrIncomplete(format!(
                    "kernel-drop map pin {} missing",
                    path
                ));
            }
        }

        KernelDropMapInventoryStatus::Healthy
    }

    fn rebuild_runtime(&self) -> Result<(), String> {
        if Path::new(&self.pin_path).exists() {
            std::fs::remove_dir_all(&self.pin_path).map_err(|e| {
                format!("remove stale kernel-drop runtime {}: {}", self.pin_path, e)
            })?;
        }
        let metadata_path = self.runtime_metadata_path();
        if Path::new(&metadata_path).exists() {
            std::fs::remove_file(&metadata_path).map_err(|e| {
                format!(
                    "remove stale kernel-drop runtime metadata {}: {}",
                    metadata_path, e
                )
            })?;
        }
        std::fs::create_dir_all(&self.pin_path)
            .map_err(|e| format!("recreate kernel-drop pin dir {}: {}", self.pin_path, e))?;
        Ok(())
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

    fn sync_all_managed_ifaces(
        &self,
        managed_ifaces: &HashMap<u32, u32>,
        prune_missing: bool,
    ) -> Result<(), String> {
        let mut map = self.open_managed_ifindex_filter()?;
        if prune_missing {
            let existing_keys: Vec<u32> = map.keys().filter_map(|item| item.ok()).collect();
            for ifindex in existing_keys {
                if managed_ifaces.contains_key(&ifindex) {
                    continue;
                }
                if map.get(&ifindex, 0).is_ok() {
                    map.remove(&ifindex).map_err(|e| {
                        format!("remove stale MANAGED_IFINDEX_FILTER {}: {:?}", ifindex, e)
                    })?;
                }
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
