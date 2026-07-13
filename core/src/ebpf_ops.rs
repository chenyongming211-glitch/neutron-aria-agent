use crate::common::{
    acl_banked_tap_id, normalize_acl_bank, CtConfig, CtContractKey, CtContractValue, CtKey4, CtKey6,
    FirewallConfig, FlowStatsValue, GlobalMirrorKey, GroupStatsKey, GroupStatsValue, IfaceCtx,
    MirrorConfig, MirrorKey, MirrorStatsValue, PolicyKey, PolicyValue, PortKey, QosConfig, QosKey,
    QosStatsValue, RuleStatsValue, TapConfig, TapMapRuntime, TokenBucket, ACL_BANK_PRIMARY,
    ACL_INGRESS_HOOK_TC, TAP_ID_UNASSIGNED,
};
use crate::state::FirewallState;
use aya::maps::lpm_trie::Key;
use aya::maps::{HashMap, LpmTrie, MapData, PerCpuHashMap};
use std::collections::{BTreeSet, HashSet};
use std::net::IpAddr;
use tracing::{info, warn};

mod attach;
mod inventory;
mod network;
mod policy;
mod replay;
mod runtime;
mod scrub;

pub use attach::{
    attach_tc_egress, attach_tc_ingress, check_fq_qdisc, cleanup_root_qdisc, detach_tc_egress,
    ensure_fq_qdisc, setup_fq_qdisc, FqQdiscState,
};
pub use inventory::{
    critical_network_map_names, show_stats, validate_pinned_runtime_state, TraceMapMode,
    ALL_MAP_NAMES, CRITICAL_NETWORK_MAP_NAMES, NETWORK_MAP_NAMES, SSL_MAP_NAMES,
    STREAM_CRITICAL_NETWORK_MAP_NAMES,
};
pub use network::{
    add_acl_network_in_bank, add_network, delete_acl_network_in_bank, delete_network, parse_cidr,
};
pub(crate) use policy::stored_policy_action;
pub use policy::{
    add_policy, add_policy_in_bank, delete_policy, delete_policy_in_bank, delete_port_set,
    parse_ports, validate_policy_ports,
};
pub use replay::{replay_state, replay_state_from_snapshot, replay_state_to_pinned_maps};
pub use runtime::{
    clear_iface_ctx, delete_tap_config, read_acl_active_bank, read_firewall_config, read_iface_ctx,
    read_runtime_config, set_acl_active_bank, sync_iface_ctx, update_acl_runtime_gate,
    update_firewall_config, update_runtime_config, write_tap_config,
};
pub use scrub::{scrub_acl_bank, scrub_managed_runtime_state, scrub_standalone_runtime_state};

/// 加载一个新的 eBPF 对象，并设置 pin 路径以尝试复用已有 map。
/// 仅用于 standalone/legacy 路径；共享 managed runtime 不能再走这个函数。
pub fn load_bpf_with_pin(pin_path: &str, ebpf_path: &str) -> Result<aya::Ebpf, String> {
    let bpf_bytes = std::fs::read(ebpf_path).map_err(|e| format!("read ebpf: {}", e))?;
    let bpf = aya::EbpfLoader::new()
        .map_pin_path(pin_path)
        .load(&bpf_bytes)
        .map_err(|e| format!("load ebpf: {}", e))?;
    Ok(bpf)
}

const TAP_LPM_PREFIX_BITS: u32 = 32;

fn tap_lpm_key_v4(tap_id: u32, ip: [u8; 4], prefix_len: u8) -> Key<[u8; 8]> {
    let mut bytes = [0u8; 8];
    bytes[..4].copy_from_slice(&tap_id.to_be_bytes());
    bytes[4..].copy_from_slice(&ip);
    Key::new(TAP_LPM_PREFIX_BITS + prefix_len as u32, bytes)
}

fn tap_lpm_key_v6(tap_id: u32, ip: [u8; 16], prefix_len: u8) -> Key<[u8; 20]> {
    let mut bytes = [0u8; 20];
    bytes[..4].copy_from_slice(&tap_id.to_be_bytes());
    bytes[4..].copy_from_slice(&ip);
    Key::new(TAP_LPM_PREFIX_BITS + prefix_len as u32, bytes)
}

/// 从 pin 路径直接打开已有的 map（不加载 eBPF 程序）
fn open_pinned_lpm_v4(
    pin_path: &str,
    map_name: &str,
) -> Result<LpmTrie<MapData, [u8; 8], u32>, String> {
    let map_path = format!("{}/{}", pin_path, map_name);
    let map_data = MapData::from_pin(&map_path)
        .map_err(|e| format!("open pinned map {}: {:?}", map_name, e))?;
    LpmTrie::try_from(aya::maps::Map::LpmTrie(map_data))
        .map_err(|e| format!("convert {} to LpmTrie: {:?}", map_name, e))
}

fn open_pinned_lpm_v6(
    pin_path: &str,
    map_name: &str,
) -> Result<LpmTrie<MapData, [u8; 20], u32>, String> {
    let map_path = format!("{}/{}", pin_path, map_name);
    let map_data = MapData::from_pin(&map_path)
        .map_err(|e| format!("open pinned map {}: {:?}", map_name, e))?;
    LpmTrie::try_from(aya::maps::Map::LpmTrie(map_data))
        .map_err(|e| format!("convert {} to LpmTrie: {:?}", map_name, e))
}

fn open_pinned_policy_table(
    pin_path: &str,
) -> Result<HashMap<MapData, PolicyKey, PolicyValue>, String> {
    let map_path = format!("{}/POLICY_TABLE", pin_path);
    let map_data =
        MapData::from_pin(&map_path).map_err(|e| format!("open pinned POLICY_TABLE: {:?}", e))?;
    HashMap::try_from(aya::maps::Map::HashMap(map_data))
        .map_err(|e| format!("convert POLICY_TABLE to HashMap: {:?}", e))
}

fn open_pinned_port_pool(pin_path: &str) -> Result<HashMap<MapData, PortKey, u8>, String> {
    let map_path = format!("{}/PORT_BITMAP_POOL", pin_path);
    let map_data = MapData::from_pin(&map_path)
        .map_err(|e| format!("open pinned PORT_BITMAP_POOL: {:?}", e))?;
    HashMap::try_from(aya::maps::Map::HashMap(map_data))
        .map_err(|e| format!("convert PORT_BITMAP_POOL to HashMap: {:?}", e))
}

fn open_pinned_iface_ctx(pin_path: &str) -> Result<HashMap<MapData, u32, IfaceCtx>, String> {
    let map_path = format!("{}/IFACE_CTX_MAP", pin_path);
    let map_data =
        MapData::from_pin(&map_path).map_err(|e| format!("open pinned IFACE_CTX_MAP: {:?}", e))?;
    HashMap::try_from(aya::maps::Map::HashMap(map_data))
        .map_err(|e| format!("convert IFACE_CTX_MAP to HashMap: {:?}", e))
}

fn open_pinned_tap_config(pin_path: &str) -> Result<HashMap<MapData, u32, TapConfig>, String> {
    let map_path = format!("{}/TAP_CONFIG_MAP", pin_path);
    let map_data =
        MapData::from_pin(&map_path).map_err(|e| format!("open pinned TAP_CONFIG_MAP: {:?}", e))?;
    HashMap::try_from(aya::maps::Map::HashMap(map_data))
        .map_err(|e| format!("convert TAP_CONFIG_MAP to HashMap: {:?}", e))
}
