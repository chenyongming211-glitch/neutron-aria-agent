use super::*;
use std::ffi::CString;
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

const MANAGED_SHARED_PIN_NAMESPACE: &str = "global-v2";
const BPF_FS_MAGIC: u64 = 0xcafe4a11;
static FIREWALL_CONFIG_RMW_LOCK: Mutex<()> = Mutex::new(());

pub fn sync_iface_ctx(runtime: TapMapRuntime<'_>, ifindex: u32) -> Result<(), String> {
    let mut map = open_pinned_iface_ctx(runtime.pin_path)?;
    let ctx = IfaceCtx {
        tap_id: runtime.tap_id,
        flags: 0,
    };
    map.insert(&ifindex, &ctx, 0)
        .map_err(|e| format!("IFACE_CTX_MAP insert for ifindex {}: {:?}", ifindex, e))
}

pub fn lookup_iface_ctx(pin_path: &str, ifindex: u32) -> Result<Option<IfaceCtx>, String> {
    let map = open_pinned_iface_ctx(pin_path)?;
    match map.get(&ifindex, 0) {
        Ok(ctx) => Ok(Some(ctx)),
        Err(aya::maps::MapError::KeyNotFound) => Ok(None),
        Err(error) => Err(format!(
            "read IFACE_CTX_MAP for ifindex {}: {:?}",
            ifindex, error
        )),
    }
}

pub fn read_iface_ctx(pin_path: &str, ifindex: u32) -> Result<IfaceCtx, String> {
    lookup_iface_ctx(pin_path, ifindex)?.ok_or_else(|| {
        format!(
            "read IFACE_CTX_MAP for ifindex {}: KeyNotFound",
            ifindex
        )
    })
}

pub fn clear_iface_ctx(pin_path: &str, ifindex: u32) -> Result<(), String> {
    let mut map = open_pinned_iface_ctx(pin_path)?;
    match map.remove(&ifindex) {
        Ok(()) => Ok(()),
        Err(e) => Err(format!(
            "IFACE_CTX_MAP remove for ifindex {}: {:?}",
            ifindex, e
        )),
    }
}

pub fn write_tap_config(runtime: TapMapRuntime<'_>, config: TapConfig) -> Result<(), String> {
    let mut map = open_pinned_tap_config(runtime.pin_path)?;
    map.insert(&runtime.tap_id, &config, 0).map_err(|e| {
        format!(
            "TAP_CONFIG_MAP insert for tap_id {}: {:?}",
            runtime.tap_id, e
        )
    })
}

pub fn delete_tap_config(runtime: TapMapRuntime<'_>) -> Result<(), String> {
    let mut map = open_pinned_tap_config(runtime.pin_path)?;
    match map.remove(&runtime.tap_id) {
        Ok(()) => Ok(()),
        Err(e) => Err(format!(
            "TAP_CONFIG_MAP remove for tap_id {}: {:?}",
            runtime.tap_id, e
        )),
    }
}

fn tap_config_with_acl_bank(current: TapConfig, bank: u8) -> TapConfig {
    TapConfig {
        acl_active_bank: normalize_acl_bank(bank),
        acl_ingress_hook: ACL_INGRESS_HOOK_TC,
        ..current
    }
}

fn firewall_config_with_acl_bank(current: FirewallConfig, bank: u8) -> FirewallConfig {
    FirewallConfig {
        acl_active_bank: normalize_acl_bank(bank),
        ..current
    }
}

fn firewall_config_with_acl_maintenance_bypass(
    current: FirewallConfig,
    enabled: bool,
) -> FirewallConfig {
    FirewallConfig {
        acl_maintenance_bypass: if enabled { 1 } else { 0 },
        ..current
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct FirewallConfigPatch {
    conntrack_enabled: Option<bool>,
    monitoring_enabled: Option<bool>,
    acl_enabled: Option<bool>,
    qos_enabled: Option<bool>,
    mirror_enabled: Option<bool>,
    tcprt_enabled: Option<bool>,
    ssl_enabled: Option<bool>,
}

impl FirewallConfigPatch {
    fn is_full_initialization(self) -> bool {
        self.conntrack_enabled.is_some()
            && self.monitoring_enabled.is_some()
            && self.acl_enabled.is_some()
            && self.qos_enabled.is_some()
            && self.mirror_enabled.is_some()
            && self.tcprt_enabled.is_some()
            && self.ssl_enabled.is_some()
    }
}

fn firewall_config_with_runtime_updates(
    current: Option<FirewallConfig>,
    patch: FirewallConfigPatch,
    detected_num_cpus: u16,
) -> Result<FirewallConfig, String> {
    if current.is_none() && !patch.is_full_initialization() {
        return Err("partial update requires initialized FIREWALL_CONFIG key 0".to_string());
    }
    let current = current.unwrap_or(FirewallConfig {
        conntrack_enabled: 1,
        monitoring_enabled: 1,
        num_cpus: detected_num_cpus,
        qos_enabled: 0,
        acl_enabled: 1,
        mirror_enabled: 0,
        tcprt_enabled: 0,
        ssl_enabled: 0,
        acl_active_bank: ACL_BANK_PRIMARY,
        acl_maintenance_bypass: 0,
        _pad: 0,
    });
    Ok(FirewallConfig {
        conntrack_enabled: patch
            .conntrack_enabled
            .map(u8::from)
            .unwrap_or(current.conntrack_enabled),
        monitoring_enabled: patch
            .monitoring_enabled
            .map(u8::from)
            .unwrap_or(current.monitoring_enabled),
        num_cpus: current.num_cpus,
        qos_enabled: patch
            .qos_enabled
            .map(u8::from)
            .unwrap_or(current.qos_enabled),
        acl_enabled: patch
            .acl_enabled
            .map(u8::from)
            .unwrap_or(current.acl_enabled),
        mirror_enabled: patch
            .mirror_enabled
            .map(u8::from)
            .unwrap_or(current.mirror_enabled),
        tcprt_enabled: patch
            .tcprt_enabled
            .map(u8::from)
            .unwrap_or(current.tcprt_enabled),
        ssl_enabled: patch
            .ssl_enabled
            .map(u8::from)
            .unwrap_or(current.ssl_enabled),
        acl_active_bank: normalize_acl_bank(current.acl_active_bank),
        acl_maintenance_bypass: current.acl_maintenance_bypass,
        _pad: 0,
    })
}

trait FirewallConfigStore {
    fn read_key_zero(&mut self) -> Result<Option<FirewallConfig>, String>;
    fn write_key_zero(&mut self, config: FirewallConfig) -> Result<(), String>;
}

struct PinnedFirewallConfigStore {
    map: aya::maps::HashMap<MapData, u32, FirewallConfig>,
}

impl PinnedFirewallConfigStore {
    fn open(pin_path: &Path) -> Result<Self, String> {
        let map_path = pin_path.join("FIREWALL_CONFIG");
        let map_data = MapData::from_pin(&map_path)
            .map_err(|error| format!("open FIREWALL_CONFIG: {:?}", error))?;
        let map = aya::maps::HashMap::<_, u32, FirewallConfig>::try_from(
            aya::maps::Map::HashMap(map_data),
        )
        .map_err(|error| format!("convert FIREWALL_CONFIG: {:?}", error))?;
        Ok(Self { map })
    }
}

impl FirewallConfigStore for PinnedFirewallConfigStore {
    fn read_key_zero(&mut self) -> Result<Option<FirewallConfig>, String> {
        match self.map.get(&0u32, 0) {
            Ok(config) => Ok(Some(config)),
            Err(aya::maps::MapError::KeyNotFound) => Ok(None),
            Err(error) => Err(format!("read FIREWALL_CONFIG key 0: {}", error)),
        }
    }

    fn write_key_zero(&mut self, config: FirewallConfig) -> Result<(), String> {
        self.map
            .insert(&0u32, &config, 0)
            .map_err(|error| format!("write FIREWALL_CONFIG key 0: {:?}", error))
    }
}

fn serialized_firewall_config_rmw<Store, Transform>(
    update_lock: &Mutex<()>,
    store: &mut Store,
    operation: &str,
    transform: Transform,
) -> Result<FirewallConfig, String>
where
    Store: FirewallConfigStore,
    Transform: FnOnce(Option<FirewallConfig>) -> Result<FirewallConfig, String>,
{
    let _guard = update_lock.lock().map_err(|_| {
        format!(
            "{} FIREWALL_CONFIG serialization lock poisoned; refusing shared-map write",
            operation
        )
    })?;
    let current = store
        .read_key_zero()
        .map_err(|error| format!("{}: {}", operation, error))?;
    let expected = transform(current)?;
    store
        .write_key_zero(expected)
        .map_err(|error| format!("{}: {}", operation, error))?;
    let observed = store
        .read_key_zero()
        .map_err(|error| format!("{} readback: {}", operation, error))?
        .ok_or_else(|| {
            format!(
                "{} FIREWALL_CONFIG full readback mismatch: expected {:?}, observed missing key 0",
                operation, expected
            )
        })?;
    if observed != expected {
        return Err(format!(
            "{} FIREWALL_CONFIG full readback mismatch: expected {:?}, observed {:?}",
            operation, expected, observed
        ));
    }
    Ok(observed)
}

fn tap_config_with_runtime_updates(
    current: TapConfig,
    conntrack_enabled: Option<bool>,
    monitoring_enabled: Option<bool>,
    acl_enabled: Option<bool>,
    qos_enabled: Option<bool>,
    mirror_enabled: Option<bool>,
    tcprt_enabled: Option<bool>,
) -> TapConfig {
    TapConfig {
        conntrack_enabled: conntrack_enabled
            .map(|b| if b { 1 } else { 0 })
            .unwrap_or(current.conntrack_enabled),
        monitoring_enabled: monitoring_enabled
            .map(|b| if b { 1 } else { 0 })
            .unwrap_or(current.monitoring_enabled),
        acl_enabled: acl_enabled
            .map(|b| if b { 1 } else { 0 })
            .unwrap_or(current.acl_enabled),
        qos_enabled: qos_enabled
            .map(|b| if b { 1 } else { 0 })
            .unwrap_or(current.qos_enabled),
        mirror_enabled: mirror_enabled
            .map(|b| if b { 1 } else { 0 })
            .unwrap_or(current.mirror_enabled),
        tcprt_enabled: tcprt_enabled
            .map(|b| if b { 1 } else { 0 })
            .unwrap_or(current.tcprt_enabled),
        acl_active_bank: current.acl_active_bank,
        acl_ingress_hook: ACL_INGRESS_HOOK_TC,
    }
}

fn tap_config_with_acl_runtime_gate(
    current: TapConfig,
    conntrack_enabled: bool,
    acl_enabled: bool,
    _acl_ingress_hook: u8,
) -> TapConfig {
    TapConfig {
        conntrack_enabled: if conntrack_enabled { 1 } else { 0 },
        monitoring_enabled: current.monitoring_enabled,
        acl_enabled: if acl_enabled { 1 } else { 0 },
        qos_enabled: current.qos_enabled,
        mirror_enabled: current.mirror_enabled,
        tcprt_enabled: current.tcprt_enabled,
        acl_active_bank: current.acl_active_bank,
        acl_ingress_hook: ACL_INGRESS_HOOK_TC,
    }
}

fn required_tap_config(
    lookup: Result<TapConfig, aya::maps::MapError>,
    tap_id: u32,
    operation: &str,
) -> Result<TapConfig, String> {
    match lookup {
        Ok(config) => Ok(config),
        Err(aya::maps::MapError::KeyNotFound) => Err(format!(
            "{} requires initialized TAP_CONFIG_MAP for tap_id {}",
            operation, tap_id
        )),
        Err(error) => Err(format!(
            "{} read TAP_CONFIG_MAP for tap_id {}: {}",
            operation, tap_id, error
        )),
    }
}

pub fn set_acl_active_bank(runtime: TapMapRuntime<'_>, bank: u8) -> Result<(), String> {
    if runtime.tap_id == TAP_ID_UNASSIGNED {
        let mut store = PinnedFirewallConfigStore::open(Path::new(runtime.pin_path))?;
        return serialized_firewall_config_rmw(
            &FIREWALL_CONFIG_RMW_LOCK,
            &mut store,
            "standalone active bank update",
            |current| {
                let current = current.ok_or_else(|| {
                    "standalone active bank update requires initialized FIREWALL_CONFIG key 0"
                        .to_string()
                })?;
                Ok(firewall_config_with_acl_bank(current, bank))
            },
        )
        .map(|_| ());
    }

    let mut map = open_pinned_tap_config(runtime.pin_path)?;
    let current = required_tap_config(
        map.get(&runtime.tap_id, 0),
        runtime.tap_id,
        "active bank update",
    )?;
    let cfg = tap_config_with_acl_bank(current, bank);
    map.insert(&runtime.tap_id, &cfg, 0).map_err(|e| {
        format!(
            "TAP_CONFIG_MAP insert for tap_id {}: {:?}",
            runtime.tap_id, e
        )
    })
}

pub fn read_acl_active_bank(runtime: TapMapRuntime<'_>) -> Result<u8, String> {
    if runtime.tap_id == TAP_ID_UNASSIGNED {
        let cfg = read_firewall_config(runtime)?;
        return Ok(normalize_acl_bank(cfg.acl_active_bank));
    }

    let map = open_pinned_tap_config(runtime.pin_path)?;
    let cfg = map
        .get(&runtime.tap_id, 0)
        .map_err(|e| format!("read TAP_CONFIG_MAP for tap_id {}: {:?}", runtime.tap_id, e))?;
    Ok(normalize_acl_bank(cfg.acl_active_bank))
}

pub fn update_acl_runtime_gate(
    runtime: TapMapRuntime<'_>,
    conntrack_enabled: bool,
    acl_enabled: bool,
    acl_ingress_hook: u8,
) -> Result<(), String> {
    if runtime.tap_id == TAP_ID_UNASSIGNED {
        return Err("ACL runtime gate is only supported for per-tap runtime config".to_string());
    }

    let mut map = open_pinned_tap_config(runtime.pin_path)?;
    let current = required_tap_config(
        map.get(&runtime.tap_id, 0),
        runtime.tap_id,
        "ACL runtime gate update",
    )?;
    let cfg = tap_config_with_acl_runtime_gate(
        current,
        conntrack_enabled,
        acl_enabled,
        acl_ingress_hook,
    );
    map.insert(&runtime.tap_id, &cfg, 0).map_err(|e| {
        format!(
            "TAP_CONFIG_MAP insert for tap_id {}: {:?}",
            runtime.tap_id, e
        )
    })
}

pub fn update_runtime_config(
    runtime: TapMapRuntime<'_>,
    conntrack_enabled: Option<bool>,
    monitoring_enabled: Option<bool>,
    acl_enabled: Option<bool>,
    qos_enabled: Option<bool>,
    mirror_enabled: Option<bool>,
    tcprt_enabled: Option<bool>,
    ssl_enabled: Option<bool>,
) -> Result<(), String> {
    if runtime.tap_id == TAP_ID_UNASSIGNED {
        return update_firewall_config(
            runtime,
            conntrack_enabled,
            monitoring_enabled,
            acl_enabled,
            qos_enabled,
            mirror_enabled,
            tcprt_enabled,
            ssl_enabled,
        );
    }

    let mut map = open_pinned_tap_config(runtime.pin_path)?;
    let current = required_tap_config(
        map.get(&runtime.tap_id, 0),
        runtime.tap_id,
        "partial update",
    )?;
    let cfg = tap_config_with_runtime_updates(
        current,
        conntrack_enabled,
        monitoring_enabled,
        acl_enabled,
        qos_enabled,
        mirror_enabled,
        tcprt_enabled,
    );
    map.insert(&runtime.tap_id, &cfg, 0).map_err(|e| {
        format!(
            "TAP_CONFIG_MAP insert for tap_id {}: {:?}",
            runtime.tap_id, e
        )
    })
}

#[cfg(test)]
fn required_firewall_config(
    lookup: Result<FirewallConfig, aya::maps::MapError>,
    full_initialization: bool,
    operation: &str,
) -> Result<Option<FirewallConfig>, String> {
    match lookup {
        Ok(config) => Ok(Some(config)),
        Err(aya::maps::MapError::KeyNotFound) if full_initialization => Ok(None),
        Err(aya::maps::MapError::KeyNotFound) => Err(format!(
            "{} requires initialized FIREWALL_CONFIG key 0",
            operation
        )),
        Err(error) => Err(format!(
            "{} read FIREWALL_CONFIG key 0: {}",
            operation, error
        )),
    }
}

#[derive(Clone, Copy, Debug)]
struct ManagedFirewallConfigProofFacts {
    runtime_tap_id: u32,
    absolute_path: bool,
    path_matches_managed_namespace: bool,
    on_bpffs: bool,
    has_symlink_component: bool,
    root_owned: bool,
    trusted_permissions: bool,
    complete_inventory: bool,
}

fn validate_managed_firewall_config_proof_facts(
    facts: &ManagedFirewallConfigProofFacts,
) -> Result<(), String> {
    let prefix = "managed FIREWALL_CONFIG authority rejected";
    if facts.runtime_tap_id != TAP_ID_UNASSIGNED {
        return Err(format!("{}: runtime must use unassigned tap_id 0", prefix));
    }
    if !facts.absolute_path {
        return Err(format!("{}: authority paths must be absolute", prefix));
    }
    if !facts.path_matches_managed_namespace {
        return Err(format!(
            "{}: runtime path must match the authority's managed namespace",
            prefix
        ));
    }
    if facts.has_symlink_component {
        return Err(format!(
            "{}: symlink components are not trusted",
            prefix
        ));
    }
    if !facts.trusted_permissions {
        return Err(format!(
            "{}: group/world-writable permissions are not trusted",
            prefix
        ));
    }
    if !facts.root_owned {
        return Err(format!("{}: root ownership is required", prefix));
    }
    if !facts.on_bpffs {
        return Err(format!("{}: runtime is not on bpffs", prefix));
    }
    if !facts.complete_inventory {
        return Err(format!(
            "{}: complete managed map inventory is required",
            prefix
        ));
    }
    Ok(())
}

fn absolute_component_paths(path: &Path) -> Vec<PathBuf> {
    let mut current = PathBuf::new();
    let mut paths = Vec::new();
    for component in path.components() {
        current.push(component.as_os_str());
        paths.push(current.clone());
    }
    paths
}

fn path_is_bpffs(path: &Path) -> Result<bool, String> {
    let path = CString::new(path.as_os_str().as_bytes()).map_err(|_| {
        format!(
            "managed FIREWALL_CONFIG authority rejected: path contains a NUL byte: {}",
            path.display()
        )
    })?;
    let mut stats = core::mem::MaybeUninit::<libc::statfs>::uninit();
    let result = unsafe { libc::statfs(path.as_ptr(), stats.as_mut_ptr()) };
    if result != 0 {
        return Err(format!(
            "managed FIREWALL_CONFIG authority rejected: statfs failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    let stats = unsafe { stats.assume_init() };
    Ok(stats.f_type as u64 == BPF_FS_MAGIC)
}

/// Proof that a root-only shared FIREWALL_CONFIG operation targets the
/// authority-owned managed namespace. Fields stay private so callers cannot
/// manufacture this capability from an arbitrary compatible map.
pub struct ManagedFirewallConfigRuntime {
    store: Mutex<PinnedFirewallConfigStore>,
}

impl core::fmt::Debug for ManagedFirewallConfigRuntime {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("ManagedFirewallConfigRuntime")
            .field("verified_store", &"FIREWALL_CONFIG[0]")
            .finish_non_exhaustive()
    }
}

/// Validate the real managed bpffs authority and mint a proof-carrying handle.
/// This is validation, not an assume-managed constructor.
pub fn prove_managed_firewall_config_runtime(
    runtime: TapMapRuntime<'_>,
    authority_base_pin_path: &str,
) -> Result<ManagedFirewallConfigRuntime, String> {
    let runtime_path = Path::new(runtime.pin_path);
    let authority_base = Path::new(authority_base_pin_path);
    let expected_runtime_path = authority_base.join(MANAGED_SHARED_PIN_NAMESPACE);
    let clean_components = |path: &Path| {
        !path.components().any(|component| {
            matches!(
                component,
                std::path::Component::CurDir | std::path::Component::ParentDir
            )
        })
    };

    validate_managed_firewall_config_proof_facts(&ManagedFirewallConfigProofFacts {
        runtime_tap_id: runtime.tap_id,
        absolute_path: runtime_path.is_absolute() && authority_base.is_absolute(),
        path_matches_managed_namespace: runtime_path == expected_runtime_path
            && clean_components(runtime_path)
            && clean_components(authority_base),
        on_bpffs: true,
        has_symlink_component: false,
        root_owned: true,
        trusted_permissions: true,
        complete_inventory: true,
    })?;

    let mut has_symlink_component = false;
    let mut root_owned = true;
    let mut trusted_permissions = true;
    for path in absolute_component_paths(runtime_path) {
        let metadata = fs::symlink_metadata(&path).map_err(|error| {
            format!(
                "managed FIREWALL_CONFIG authority rejected: inspect {}: {}",
                path.display(),
                error
            )
        })?;
        has_symlink_component |= metadata.file_type().is_symlink();
        root_owned &= metadata.uid() == 0;
        trusted_permissions &= metadata.mode() & 0o022 == 0;
    }

    let mut complete_inventory = true;
    for map_name in CRITICAL_NETWORK_MAP_NAMES {
        let map_path = runtime_path.join(map_name);
        match fs::symlink_metadata(&map_path) {
            Ok(metadata) => {
                has_symlink_component |= metadata.file_type().is_symlink();
                root_owned &= metadata.uid() == 0;
                trusted_permissions &= metadata.mode() & 0o022 == 0;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                complete_inventory = false;
            }
            Err(error) => {
                return Err(format!(
                    "managed FIREWALL_CONFIG authority rejected: inspect {}: {}",
                    map_path.display(),
                    error
                ));
            }
        }
    }

    validate_managed_firewall_config_proof_facts(&ManagedFirewallConfigProofFacts {
        runtime_tap_id: runtime.tap_id,
        absolute_path: true,
        path_matches_managed_namespace: true,
        on_bpffs: path_is_bpffs(runtime_path)?,
        has_symlink_component,
        root_owned,
        trusted_permissions,
        complete_inventory,
    })?;

    for map_name in CRITICAL_NETWORK_MAP_NAMES {
        let map_path = runtime_path.join(map_name);
        MapData::from_pin(&map_path).map_err(|error| {
            format!(
                "managed FIREWALL_CONFIG authority rejected: {} is not a readable managed BPF map: {:?}",
                map_path.display(),
                error
            )
        })?;
    }
    let mut store = PinnedFirewallConfigStore::open(runtime_path)?;
    store.read_key_zero()?.ok_or_else(|| {
        "managed FIREWALL_CONFIG authority rejected: FIREWALL_CONFIG key 0 is missing".to_string()
    })?;

    Ok(ManagedFirewallConfigRuntime {
        store: Mutex::new(store),
    })
}

/// Toggle the shared host ACL/conntrack maintenance gate and prove the write.
pub fn set_acl_maintenance_bypass(
    runtime: &ManagedFirewallConfigRuntime,
    enabled: bool,
) -> Result<(), String> {
    let mut store = runtime.store.lock().map_err(|_| {
        "ACL maintenance bypass verified-map lock poisoned; refusing shared-map write".to_string()
    })?;
    serialized_firewall_config_rmw(
        &FIREWALL_CONFIG_RMW_LOCK,
        &mut *store,
        "ACL maintenance bypass update",
        |current| {
            let current = current.ok_or_else(|| {
                "ACL maintenance bypass update requires initialized FIREWALL_CONFIG key 0"
                    .to_string()
            })?;
            Ok(firewall_config_with_acl_maintenance_bypass(
                current, enabled,
            ))
        },
    )
    .map(|_| ())
}

/// Update FIREWALL_CONFIG map at runtime via pinned map.
/// Reads the current config, applies the changes, and writes back.
pub fn update_firewall_config(
    runtime: TapMapRuntime<'_>,
    conntrack_enabled: Option<bool>,
    monitoring_enabled: Option<bool>,
    acl_enabled: Option<bool>,
    qos_enabled: Option<bool>,
    mirror_enabled: Option<bool>,
    tcprt_enabled: Option<bool>,
    ssl_enabled: Option<bool>,
) -> Result<(), String> {
    let patch = FirewallConfigPatch {
        conntrack_enabled,
        monitoring_enabled,
        acl_enabled,
        qos_enabled,
        mirror_enabled,
        tcprt_enabled,
        ssl_enabled,
    };
    let operation = if patch.is_full_initialization() {
        "full initialization"
    } else {
        "partial update"
    };
    let raw_num_cpus = unsafe { libc::sysconf(libc::_SC_NPROCESSORS_ONLN) };
    let detected_num_cpus = if raw_num_cpus > 0 {
        raw_num_cpus as u16
    } else {
        1u16
    };
    let mut store = PinnedFirewallConfigStore::open(Path::new(runtime.pin_path))?;
    serialized_firewall_config_rmw(
        &FIREWALL_CONFIG_RMW_LOCK,
        &mut store,
        operation,
        |current| firewall_config_with_runtime_updates(current, patch, detected_num_cpus),
    )
    .map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::{
        firewall_config_with_acl_bank, firewall_config_with_acl_maintenance_bypass,
        firewall_config_with_runtime_updates, required_firewall_config, required_tap_config,
        serialized_firewall_config_rmw, tap_config_with_acl_bank,
        tap_config_with_acl_runtime_gate, tap_config_with_runtime_updates,
        validate_managed_firewall_config_proof_facts, FirewallConfigPatch,
        FirewallConfigStore, ManagedFirewallConfigProofFacts,
    };
    use crate::common::{
        FirewallConfig, TapConfig, ACL_INGRESS_HOOK_TC, ACL_INGRESS_HOOK_XDP,
    };
    use aya::maps::MapError;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex as StdMutex};
    use std::thread;
    use std::time::Duration;

    #[derive(Clone)]
    struct TestFirewallConfigStore {
        state: Arc<StdMutex<Option<FirewallConfig>>>,
        reads: Arc<AtomicUsize>,
        writes: Arc<AtomicUsize>,
        active_rmw: Arc<AtomicBool>,
        overlap_observed: Arc<AtomicBool>,
        delay_first_read: bool,
        corrupt_full_readback: bool,
        local_reads: usize,
    }

    impl TestFirewallConfigStore {
        fn new(initial: Option<FirewallConfig>) -> Self {
            Self {
                state: Arc::new(StdMutex::new(initial)),
                reads: Arc::new(AtomicUsize::new(0)),
                writes: Arc::new(AtomicUsize::new(0)),
                active_rmw: Arc::new(AtomicBool::new(false)),
                overlap_observed: Arc::new(AtomicBool::new(false)),
                delay_first_read: false,
                corrupt_full_readback: false,
                local_reads: 0,
            }
        }

        fn concurrent_clone(&self) -> Self {
            let mut cloned = self.clone();
            cloned.delay_first_read = true;
            cloned.local_reads = 0;
            cloned
        }

        fn corrupting_clone(&self) -> Self {
            let mut cloned = self.clone();
            cloned.corrupt_full_readback = true;
            cloned.local_reads = 0;
            cloned
        }
    }

    impl FirewallConfigStore for TestFirewallConfigStore {
        fn read_key_zero(&mut self) -> Result<Option<FirewallConfig>, String> {
            self.local_reads += 1;
            self.reads.fetch_add(1, Ordering::SeqCst);
            if self.local_reads == 1 && self.delay_first_read {
                if self.active_rmw.swap(true, Ordering::SeqCst) {
                    self.overlap_observed.store(true, Ordering::SeqCst);
                }
                thread::sleep(Duration::from_millis(25));
            }

            let mut observed = *self.state.lock().unwrap();
            if self.local_reads == 2 {
                self.active_rmw.store(false, Ordering::SeqCst);
                if self.corrupt_full_readback {
                    observed = observed.map(|config| FirewallConfig {
                        ssl_enabled: config.ssl_enabled ^ 1,
                        ..config
                    });
                }
            }
            Ok(observed)
        }

        fn write_key_zero(&mut self, config: FirewallConfig) -> Result<(), String> {
            self.writes.fetch_add(1, Ordering::SeqCst);
            *self.state.lock().unwrap() = Some(config);
            Ok(())
        }
    }

    fn maintenance_test_firewall_config() -> FirewallConfig {
        FirewallConfig {
            conntrack_enabled: 1,
            monitoring_enabled: 1,
            num_cpus: 8,
            qos_enabled: 1,
            acl_enabled: 1,
            mirror_enabled: 1,
            tcprt_enabled: 1,
            ssl_enabled: 0,
            acl_active_bank: 0,
            acl_maintenance_bypass: 0,
            _pad: 0,
        }
    }

    #[test]
    fn acl_projection_maintenance_shared_rmw_serializes_interleaved_gate_ssl_and_bank_updates() {
        let store = TestFirewallConfigStore::new(Some(maintenance_test_firewall_config()));
        let update_lock = Arc::new(StdMutex::new(()));

        let mut gate_store = store.concurrent_clone();
        let gate_lock = Arc::clone(&update_lock);
        let gate = thread::spawn(move || {
            serialized_firewall_config_rmw(
                &gate_lock,
                &mut gate_store,
                "maintenance gate update",
                |current| {
                    Ok(firewall_config_with_acl_maintenance_bypass(
                        current.expect("gate update requires current config"),
                        true,
                    ))
                },
            )
        });

        let mut ssl_store = store.concurrent_clone();
        let ssl_lock = Arc::clone(&update_lock);
        let ssl = thread::spawn(move || {
            serialized_firewall_config_rmw(
                &ssl_lock,
                &mut ssl_store,
                "SSL update",
                |current| {
                    Ok(FirewallConfig {
                        ssl_enabled: 1,
                        ..current.expect("SSL update requires current config")
                    })
                },
            )
        });

        let mut bank_store = store.concurrent_clone();
        let bank_lock = Arc::clone(&update_lock);
        let bank = thread::spawn(move || {
            serialized_firewall_config_rmw(
                &bank_lock,
                &mut bank_store,
                "active bank update",
                |current| {
                    Ok(firewall_config_with_acl_bank(
                        current.expect("bank update requires current config"),
                        1,
                    ))
                },
            )
        });

        gate.join().unwrap().unwrap();
        ssl.join().unwrap().unwrap();
        bank.join().unwrap().unwrap();

        let final_config = store.state.lock().unwrap().unwrap();
        assert_eq!(final_config.acl_maintenance_bypass, 1);
        assert_eq!(final_config.ssl_enabled, 1);
        assert_eq!(final_config.acl_active_bank, 1);
        assert_eq!(final_config.monitoring_enabled, 1);
        assert_eq!(final_config.qos_enabled, 1);
        assert_eq!(final_config.mirror_enabled, 1);
        assert!(!store.overlap_observed.load(Ordering::SeqCst));
        assert_eq!(store.writes.load(Ordering::SeqCst), 3);
        assert_eq!(store.reads.load(Ordering::SeqCst), 6);
    }

    #[test]
    fn acl_projection_maintenance_shared_rmw_poison_fails_closed_before_store_access() {
        let update_lock = Arc::new(StdMutex::new(()));
        let poisoned = Arc::clone(&update_lock);
        let _ = thread::spawn(move || {
            let _guard = poisoned.lock().unwrap();
            panic!("poison shared FIREWALL_CONFIG lock");
        })
        .join();

        let mut store = TestFirewallConfigStore::new(Some(maintenance_test_firewall_config()));
        let error = serialized_firewall_config_rmw(
            &update_lock,
            &mut store,
            "maintenance gate update",
            |current| Ok(current.unwrap()),
        )
        .expect_err("poisoned serialization must fail closed");

        assert!(error.contains("serialization lock poisoned"));
        assert_eq!(store.reads.load(Ordering::SeqCst), 0);
        assert_eq!(store.writes.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn acl_projection_maintenance_shared_rmw_rejects_full_struct_readback_drift() {
        let base = TestFirewallConfigStore::new(Some(maintenance_test_firewall_config()));
        let mut store = base.corrupting_clone();
        let update_lock = StdMutex::new(());
        let error = serialized_firewall_config_rmw(
            &update_lock,
            &mut store,
            "maintenance gate update",
            |current| {
                Ok(firewall_config_with_acl_maintenance_bypass(
                    current.unwrap(),
                    true,
                ))
            },
        )
        .expect_err("unrelated readback drift must fail the whole update");

        assert!(error.contains("full readback mismatch"));
        assert!(error.contains("ssl_enabled"));
        assert_eq!(base.writes.load(Ordering::SeqCst), 1);
        assert_eq!(base.reads.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn acl_projection_maintenance_global_transform_preserves_or_defaults_gate_and_unrelated_flags()
    {
        let current = FirewallConfig {
            acl_maintenance_bypass: 1,
            acl_active_bank: 1,
            ssl_enabled: 1,
            ..maintenance_test_firewall_config()
        };
        let partial = firewall_config_with_runtime_updates(
            Some(current),
            FirewallConfigPatch {
                monitoring_enabled: Some(false),
                ..FirewallConfigPatch::default()
            },
            16,
        )
        .unwrap();
        assert_eq!(partial.monitoring_enabled, 0);
        assert_eq!(partial.acl_maintenance_bypass, 1);
        assert_eq!(partial.acl_active_bank, 1);
        assert_eq!(partial.ssl_enabled, 1);
        assert_eq!(partial.conntrack_enabled, 1);
        assert_eq!(partial.acl_enabled, 1);
        assert_eq!(partial.qos_enabled, 1);
        assert_eq!(partial.mirror_enabled, 1);
        assert_eq!(partial.tcprt_enabled, 1);

        let fresh = firewall_config_with_runtime_updates(
            None,
            FirewallConfigPatch {
                conntrack_enabled: Some(true),
                monitoring_enabled: Some(true),
                acl_enabled: Some(true),
                qos_enabled: Some(false),
                mirror_enabled: Some(false),
                tcprt_enabled: Some(false),
                ssl_enabled: Some(false),
            },
            16,
        )
        .unwrap();
        assert_eq!(fresh.num_cpus, 16);
        assert_eq!(fresh.acl_maintenance_bypass, 0);
        assert_eq!(fresh.acl_active_bank, 0);
        assert_eq!(fresh._pad, 0);

        assert!(firewall_config_with_runtime_updates(
            None,
            FirewallConfigPatch {
                ssl_enabled: Some(true),
                ..FirewallConfigPatch::default()
            },
            16,
        )
        .unwrap_err()
        .contains("requires initialized FIREWALL_CONFIG key 0"));
    }

    #[test]
    fn acl_projection_maintenance_managed_proof_rejects_each_untrusted_authority_fact() {
        let valid = ManagedFirewallConfigProofFacts {
            runtime_tap_id: crate::common::TAP_ID_UNASSIGNED,
            absolute_path: true,
            path_matches_managed_namespace: true,
            on_bpffs: true,
            has_symlink_component: false,
            root_owned: true,
            trusted_permissions: true,
            complete_inventory: true,
        };
        validate_managed_firewall_config_proof_facts(&valid).unwrap();

        let mut cases = Vec::new();
        cases.push((
            ManagedFirewallConfigProofFacts {
                runtime_tap_id: 17,
                ..valid
            },
            "unassigned tap_id",
        ));
        cases.push((
            ManagedFirewallConfigProofFacts {
                absolute_path: false,
                ..valid
            },
            "absolute",
        ));
        cases.push((
            ManagedFirewallConfigProofFacts {
                path_matches_managed_namespace: false,
                ..valid
            },
            "managed namespace",
        ));
        cases.push((
            ManagedFirewallConfigProofFacts {
                on_bpffs: false,
                ..valid
            },
            "bpffs",
        ));
        cases.push((
            ManagedFirewallConfigProofFacts {
                has_symlink_component: true,
                ..valid
            },
            "symlink",
        ));
        cases.push((
            ManagedFirewallConfigProofFacts {
                root_owned: false,
                ..valid
            },
            "root ownership",
        ));
        cases.push((
            ManagedFirewallConfigProofFacts {
                trusted_permissions: false,
                ..valid
            },
            "permissions",
        ));
        cases.push((
            ManagedFirewallConfigProofFacts {
                complete_inventory: false,
                ..valid
            },
            "complete managed map inventory",
        ));

        for (facts, expected) in cases {
            let error = validate_managed_firewall_config_proof_facts(&facts)
                .expect_err("untrusted authority evidence must be rejected");
            assert!(
                error.contains(expected),
                "expected {expected:?} in {error:?}"
            );
        }
    }

    #[test]
    fn acl_ingress_hook_active_bank_update_preserves_tc_mode() {
        let current = TapConfig {
            conntrack_enabled: 1,
            monitoring_enabled: 0,
            acl_enabled: 1,
            qos_enabled: 1,
            mirror_enabled: 1,
            tcprt_enabled: 0,
            acl_active_bank: 0,
            acl_ingress_hook: ACL_INGRESS_HOOK_XDP,
        };

        let next = tap_config_with_acl_bank(current, 1);

        assert_eq!(next.conntrack_enabled, 1);
        assert_eq!(next.monitoring_enabled, 0);
        assert_eq!(next.acl_enabled, 1);
        assert_eq!(next.qos_enabled, 1);
        assert_eq!(next.mirror_enabled, 1);
        assert_eq!(next.tcprt_enabled, 0);
        assert_eq!(next.acl_active_bank, 1);
        assert_eq!(next.acl_ingress_hook, ACL_INGRESS_HOOK_TC);
    }

    #[test]
    fn acl_ingress_hook_partial_feature_update_preserves_tc_mode() {
        let current = TapConfig {
            conntrack_enabled: 1,
            monitoring_enabled: 0,
            acl_enabled: 1,
            qos_enabled: 1,
            mirror_enabled: 1,
            tcprt_enabled: 0,
            acl_active_bank: 1,
            acl_ingress_hook: ACL_INGRESS_HOOK_TC,
        };

        let next = tap_config_with_runtime_updates(
            current,
            None,
            Some(true),
            None,
            None,
            None,
            None,
        );

        assert_eq!(next.conntrack_enabled, 1);
        assert_eq!(next.monitoring_enabled, 1);
        assert_eq!(next.acl_enabled, 1);
        assert_eq!(next.qos_enabled, 1);
        assert_eq!(next.mirror_enabled, 1);
        assert_eq!(next.tcprt_enabled, 0);
        assert_eq!(next.acl_active_bank, 1);
        assert_eq!(next.acl_ingress_hook, ACL_INGRESS_HOOK_TC);
    }

    #[test]
    fn acl_ingress_hook_gate_transformer_preserves_runtime_and_forces_tc() {
        let current = TapConfig {
            conntrack_enabled: 0,
            monitoring_enabled: 0,
            acl_enabled: 0,
            qos_enabled: 1,
            mirror_enabled: 1,
            tcprt_enabled: 1,
            acl_active_bank: 1,
            acl_ingress_hook: ACL_INGRESS_HOOK_XDP,
        };

        let next = tap_config_with_acl_runtime_gate(current, true, true, 255);

        assert_eq!(next.conntrack_enabled, 1);
        assert_eq!(next.monitoring_enabled, 0);
        assert_eq!(next.acl_enabled, 1);
        assert_eq!(next.qos_enabled, 1);
        assert_eq!(next.mirror_enabled, 1);
        assert_eq!(next.tcprt_enabled, 1);
        assert_eq!(next.acl_active_bank, 1);
        assert_eq!(next.acl_ingress_hook, ACL_INGRESS_HOOK_TC);
    }

    #[test]
    fn tap_runtime_config_rejects_missing_and_non_key_not_found_reads() {
        let missing = required_tap_config(Err(MapError::KeyNotFound), 42, "partial update")
            .unwrap_err();
        assert_eq!(
            missing,
            "partial update requires initialized TAP_CONFIG_MAP for tap_id 42"
        );

        let read_error = required_tap_config(
            Err(MapError::InvalidKeySize {
                size: 1,
                expected: 4,
            }),
            42,
            "active bank update",
        )
        .unwrap_err();
        assert_eq!(
            read_error,
            "active bank update read TAP_CONFIG_MAP for tap_id 42: invalid key size 1, expected 4"
        );
    }

    #[test]
    fn global_runtime_partial_update_requires_an_existing_config() {
        let missing = required_firewall_config(
            Err(MapError::KeyNotFound),
            false,
            "partial update",
        )
        .unwrap_err();
        assert_eq!(
            missing,
            "partial update requires initialized FIREWALL_CONFIG key 0"
        );

        let read_error = required_firewall_config(
            Err(MapError::InvalidValueSize {
                size: 1,
                expected: core::mem::size_of::<FirewallConfig>(),
            }),
            false,
            "partial update",
        )
        .unwrap_err();
        assert!(read_error.starts_with("partial update read FIREWALL_CONFIG key 0:"));
    }

    #[test]
    fn global_runtime_full_initialization_only_accepts_key_not_found() {
        assert!(required_firewall_config(
            Err(MapError::KeyNotFound),
            true,
            "full initialization",
        )
        .unwrap()
        .is_none());
        let existing = FirewallConfig {
            conntrack_enabled: 0,
            monitoring_enabled: 1,
            num_cpus: 8,
            qos_enabled: 0,
            acl_enabled: 0,
            mirror_enabled: 0,
            tcprt_enabled: 0,
            ssl_enabled: 0,
            acl_active_bank: 1,
            acl_maintenance_bypass: 0,
            _pad: 0,
        };
        assert_eq!(
            required_firewall_config(Ok(existing), true, "full initialization")
                .unwrap()
                .unwrap()
                .num_cpus,
            8
        );
    }

    #[test]
    fn standalone_active_bank_update_preserves_global_feature_flags() {
        let current = FirewallConfig {
            conntrack_enabled: 1,
            monitoring_enabled: 0,
            num_cpus: 8,
            qos_enabled: 1,
            acl_enabled: 1,
            mirror_enabled: 1,
            tcprt_enabled: 0,
            ssl_enabled: 1,
            acl_active_bank: 0,
            acl_maintenance_bypass: 1,
            _pad: 0,
        };

        let next = firewall_config_with_acl_bank(current, 1);

        assert_eq!(next.conntrack_enabled, 1);
        assert_eq!(next.monitoring_enabled, 0);
        assert_eq!(next.num_cpus, 8);
        assert_eq!(next.qos_enabled, 1);
        assert_eq!(next.acl_enabled, 1);
        assert_eq!(next.mirror_enabled, 1);
        assert_eq!(next.tcprt_enabled, 0);
        assert_eq!(next.ssl_enabled, 1);
        assert_eq!(next.acl_active_bank, 1);
        assert_eq!(next.acl_maintenance_bypass, 1);
    }

    #[test]
    fn tap_runtime_config_acl_maintenance_bypass_changes_only_the_dedicated_byte() {
        let current = FirewallConfig {
            conntrack_enabled: 1,
            monitoring_enabled: 1,
            num_cpus: 8,
            qos_enabled: 1,
            acl_enabled: 1,
            mirror_enabled: 1,
            tcprt_enabled: 1,
            ssl_enabled: 1,
            acl_active_bank: 1,
            acl_maintenance_bypass: 0,
            _pad: 0,
        };

        let bypassed = firewall_config_with_acl_maintenance_bypass(current, true);

        assert_eq!(bypassed.acl_maintenance_bypass, 1);
        assert_eq!(bypassed.conntrack_enabled, current.conntrack_enabled);
        assert_eq!(bypassed.monitoring_enabled, current.monitoring_enabled);
        assert_eq!(bypassed.num_cpus, current.num_cpus);
        assert_eq!(bypassed.qos_enabled, current.qos_enabled);
        assert_eq!(bypassed.acl_enabled, current.acl_enabled);
        assert_eq!(bypassed.mirror_enabled, current.mirror_enabled);
        assert_eq!(bypassed.tcprt_enabled, current.tcprt_enabled);
        assert_eq!(bypassed.ssl_enabled, current.ssl_enabled);
        assert_eq!(bypassed.acl_active_bank, current.acl_active_bank);
        assert_eq!(bypassed._pad, current._pad);
    }

    #[test]
    fn tap_runtime_config_partial_writes_force_tc_and_preserve_unrelated_fields() {
        let current = TapConfig {
            conntrack_enabled: 1,
            monitoring_enabled: 0,
            acl_enabled: 1,
            qos_enabled: 1,
            mirror_enabled: 1,
            tcprt_enabled: 0,
            acl_active_bank: 1,
            acl_ingress_hook: ACL_INGRESS_HOOK_XDP,
        };
        let next = tap_config_with_runtime_updates(
            current,
            None,
            Some(true),
            None,
            None,
            None,
            None,
        );
        assert_eq!(next.conntrack_enabled, 1);
        assert_eq!(next.monitoring_enabled, 1);
        assert_eq!(next.acl_enabled, 1);
        assert_eq!(next.qos_enabled, 1);
        assert_eq!(next.mirror_enabled, 1);
        assert_eq!(next.tcprt_enabled, 0);
        assert_eq!(next.acl_active_bank, 1);
        assert_eq!(next.acl_ingress_hook, ACL_INGRESS_HOOK_TC);
    }
}

/// Read the current FIREWALL_CONFIG from pinned map.
pub fn read_firewall_config(runtime: TapMapRuntime<'_>) -> Result<FirewallConfig, String> {
    let pin_path = runtime.pin_path;
    let map_path = format!("{}/FIREWALL_CONFIG", pin_path);
    let map_data =
        MapData::from_pin(&map_path).map_err(|e| format!("open FIREWALL_CONFIG: {:?}", e))?;
    let map =
        aya::maps::HashMap::<_, u32, FirewallConfig>::try_from(aya::maps::Map::HashMap(map_data))
            .map_err(|e| format!("convert FIREWALL_CONFIG: {:?}", e))?;

    map.get(&0u32, 0)
        .map_err(|e| format!("read FIREWALL_CONFIG: {:?}", e))
}

pub fn lookup_runtime_config(
    runtime: TapMapRuntime<'_>,
) -> Result<Option<FirewallConfig>, String> {
    if runtime.tap_id == TAP_ID_UNASSIGNED {
        return read_firewall_config(runtime).map(Some);
    }

    let global = read_firewall_config(runtime)?;

    let map = open_pinned_tap_config(runtime.pin_path)?;
    let tap_cfg = match map.get(&runtime.tap_id, 0) {
        Ok(config) => config,
        Err(aya::maps::MapError::KeyNotFound) => return Ok(None),
        Err(error) => {
            return Err(format!(
                "read TAP_CONFIG_MAP for tap_id {}: {:?}",
                runtime.tap_id, error
            ))
        }
    };

    Ok(Some(FirewallConfig {
        conntrack_enabled: tap_cfg.conntrack_enabled,
        monitoring_enabled: tap_cfg.monitoring_enabled,
        num_cpus: global.num_cpus,
        qos_enabled: tap_cfg.qos_enabled,
        acl_enabled: tap_cfg.acl_enabled,
        mirror_enabled: tap_cfg.mirror_enabled,
        tcprt_enabled: tap_cfg.tcprt_enabled,
        ssl_enabled: global.ssl_enabled,
        acl_active_bank: tap_cfg.acl_active_bank,
        acl_maintenance_bypass: global.acl_maintenance_bypass,
        _pad: global._pad,
    }))
}

pub fn read_runtime_config(runtime: TapMapRuntime<'_>) -> Result<FirewallConfig, String> {
    lookup_runtime_config(runtime)?.ok_or_else(|| {
        format!(
            "read TAP_CONFIG_MAP for tap_id {}: KeyNotFound",
            runtime.tap_id
        )
    })
}
