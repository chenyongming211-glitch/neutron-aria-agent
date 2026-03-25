use std::collections::HashSet;
use std::net::IpAddr;
use aya::maps::{HashMap, LpmTrie, MapData, PerCpuHashMap};
use aya::maps::lpm_trie::Key;
use tracing::{info, warn};
use crate::common::{
    CtConfig, CtContractKey, CtContractValue, CtKey4, CtKey6,
    FirewallConfig, FlowStatsValue, GlobalMirrorKey, GroupStatsKey, GroupStatsValue, IfaceCtx,
    MirrorConfig, MirrorKey, MirrorStatsValue, PolicyKey, PolicyValue, PortKey, QosConfig,
    QosKey, QosStatsValue, RuleStatsValue, TapConfig, TapMapRuntime,
    TokenBucket, TAP_ID_UNASSIGNED,
};
use crate::state::FirewallState;

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
fn open_pinned_lpm_v4(pin_path: &str, map_name: &str) -> Result<LpmTrie<MapData, [u8; 8], u32>, String> {
    let map_path = format!("{}/{}", pin_path, map_name);
    let map_data = MapData::from_pin(&map_path)
        .map_err(|e| format!("open pinned map {}: {:?}", map_name, e))?;
    LpmTrie::try_from(aya::maps::Map::LpmTrie(map_data))
        .map_err(|e| format!("convert {} to LpmTrie: {:?}", map_name, e))
}

fn open_pinned_lpm_v6(pin_path: &str, map_name: &str) -> Result<LpmTrie<MapData, [u8; 20], u32>, String> {
    let map_path = format!("{}/{}", pin_path, map_name);
    let map_data = MapData::from_pin(&map_path)
        .map_err(|e| format!("open pinned map {}: {:?}", map_name, e))?;
    LpmTrie::try_from(aya::maps::Map::LpmTrie(map_data))
        .map_err(|e| format!("convert {} to LpmTrie: {:?}", map_name, e))
}

fn open_pinned_policy_table(pin_path: &str) -> Result<HashMap<MapData, PolicyKey, PolicyValue>, String> {
    let map_path = format!("{}/POLICY_TABLE", pin_path);
    let map_data = MapData::from_pin(&map_path)
        .map_err(|e| format!("open pinned POLICY_TABLE: {:?}", e))?;
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
    let map_data = MapData::from_pin(&map_path)
        .map_err(|e| format!("open pinned IFACE_CTX_MAP: {:?}", e))?;
    HashMap::try_from(aya::maps::Map::HashMap(map_data))
        .map_err(|e| format!("convert IFACE_CTX_MAP to HashMap: {:?}", e))
}

fn open_pinned_tap_config(pin_path: &str) -> Result<HashMap<MapData, u32, TapConfig>, String> {
    let map_path = format!("{}/TAP_CONFIG_MAP", pin_path);
    let map_data = MapData::from_pin(&map_path)
        .map_err(|e| format!("open pinned TAP_CONFIG_MAP: {:?}", e))?;
    HashMap::try_from(aya::maps::Map::HashMap(map_data))
        .map_err(|e| format!("convert TAP_CONFIG_MAP to HashMap: {:?}", e))
}

trait HasTapId {
    fn tap_id(&self) -> u32;
}

impl HasTapId for PolicyKey {
    fn tap_id(&self) -> u32 { self.tap_id }
}

impl HasTapId for PortKey {
    fn tap_id(&self) -> u32 { self.tap_id }
}

impl HasTapId for CtKey4 {
    fn tap_id(&self) -> u32 { self.tap_id }
}

impl HasTapId for CtKey6 {
    fn tap_id(&self) -> u32 { self.tap_id }
}

impl HasTapId for CtContractKey {
    fn tap_id(&self) -> u32 { self.tap_id }
}

impl HasTapId for QosKey {
    fn tap_id(&self) -> u32 { self.tap_id }
}

impl HasTapId for GroupStatsKey {
    fn tap_id(&self) -> u32 { self.tap_id }
}

impl HasTapId for MirrorKey {
    fn tap_id(&self) -> u32 { self.tap_id }
}

impl HasTapId for GlobalMirrorKey {
    fn tap_id(&self) -> u32 { self.tap_id }
}

fn scrub_hash_map<K, V, F>(
    pin_path: &str,
    map_name: &str,
    tap_id: u32,
    open_map: F,
) -> Result<u64, String>
where
    K: aya::Pod + HasTapId,
    V: aya::Pod,
    F: FnOnce(MapData) -> Result<HashMap<MapData, K, V>, String>,
{
    let map_path = format!("{}/{}", pin_path, map_name);
    let map_data = MapData::from_pin(&map_path)
        .map_err(|e| format!("open pinned {}: {:?}", map_name, e))?;
    let mut map = open_map(map_data)?;
    let keys: Vec<K> = map.iter()
        .filter_map(|item| item.ok().map(|(key, _)| key))
        .filter(|key| key.tap_id() == tap_id)
        .collect();
    let count = keys.len() as u64;
    for key in keys {
        map.remove(&key)
            .map_err(|e| format!("remove {} entry: {:?}", map_name, e))?;
    }
    Ok(count)
}

fn scrub_per_cpu_hash_map<K, V, F>(
    pin_path: &str,
    map_name: &str,
    tap_id: u32,
    open_map: F,
) -> Result<u64, String>
where
    K: aya::Pod + HasTapId,
    V: aya::Pod,
    F: FnOnce(MapData) -> Result<PerCpuHashMap<MapData, K, V>, String>,
{
    let map_path = format!("{}/{}", pin_path, map_name);
    let map_data = MapData::from_pin(&map_path)
        .map_err(|e| format!("open pinned {}: {:?}", map_name, e))?;
    let mut map = open_map(map_data)?;
    let keys: Vec<K> = map.keys()
        .filter_map(|item| item.ok())
        .filter(|key| key.tap_id() == tap_id)
        .collect();
    let count = keys.len() as u64;
    for key in keys {
        map.remove(&key)
            .map_err(|e| format!("remove {} entry: {:?}", map_name, e))?;
    }
    Ok(count)
}

fn scrub_lpm_v4_map(pin_path: &str, map_name: &str, tap_id: u32) -> Result<u64, String> {
    let mut map = open_pinned_lpm_v4(pin_path, map_name)?;
    let tap_prefix = tap_id.to_be_bytes();
    let keys: Vec<Key<[u8; 8]>> = map.iter()
        .filter_map(|item| item.ok().map(|(key, _)| key))
        .filter(|key| {
            let data = key.data();
            data[..4] == tap_prefix[..]
        })
        .collect();
    let count = keys.len() as u64;
    for key in keys {
        map.remove(&key)
            .map_err(|e| format!("remove {} entry: {:?}", map_name, e))?;
    }
    Ok(count)
}

fn scrub_lpm_v6_map(pin_path: &str, map_name: &str, tap_id: u32) -> Result<u64, String> {
    let mut map = open_pinned_lpm_v6(pin_path, map_name)?;
    let tap_prefix = tap_id.to_be_bytes();
    let keys: Vec<Key<[u8; 20]>> = map.iter()
        .filter_map(|item| item.ok().map(|(key, _)| key))
        .filter(|key| {
            let data = key.data();
            data[..4] == tap_prefix[..]
        })
        .collect();
    let count = keys.len() as u64;
    for key in keys {
        map.remove(&key)
            .map_err(|e| format!("remove {} entry: {:?}", map_name, e))?;
    }
    Ok(count)
}

fn scrub_iface_ctx_entries(pin_path: &str, tap_id: u32) -> Result<u64, String> {
    let mut map = open_pinned_iface_ctx(pin_path)?;
    let keys: Vec<u32> = map.iter()
        .filter_map(|item| item.ok())
        .filter_map(|(ifindex, ctx)| (ctx.tap_id == tap_id).then_some(ifindex))
        .collect();
    let count = keys.len() as u64;
    for ifindex in keys {
        map.remove(&ifindex)
            .map_err(|e| format!("remove IFACE_CTX_MAP entry for ifindex {}: {:?}", ifindex, e))?;
    }
    Ok(count)
}

fn scrub_tap_config_entries(pin_path: &str, tap_id: u32) -> Result<u64, String> {
    let mut map = open_pinned_tap_config(pin_path)?;
    let keys: Vec<u32> = map.iter()
        .filter_map(|item| item.ok().map(|(key, _)| key))
        .filter(|key| *key == tap_id)
        .collect();
    let count = keys.len() as u64;
    for key in keys {
        map.remove(&key)
            .map_err(|e| format!("remove TAP_CONFIG_MAP entry for tap_id {}: {:?}", key, e))?;
    }
    Ok(count)
}

fn record_optional_scrub(
    tap_id: u32,
    map_name: &str,
    removed: &mut u64,
    result: Result<u64, String>,
) {
    match result {
        Ok(count) => *removed += count,
        Err(e) => warn!(
            tap_id,
            map = %map_name,
            error = %e,
            "failed to scrub optional managed runtime map"
        ),
    }
}

fn init_ct_config_pinned(pin_path: &str) -> Result<(), String> {
    let map_path = format!("{}/CT_CONFIG", pin_path);
    let map_data = MapData::from_pin(&map_path)
        .map_err(|e| format!("open pinned CT_CONFIG: {:?}", e))?;
    let mut map = aya::maps::HashMap::<_, u32, CtConfig>::try_from(
        aya::maps::Map::HashMap(map_data)
    ).map_err(|e| format!("convert CT_CONFIG to HashMap: {:?}", e))?;

    let config = CtConfig {
        tcp_established_ns: 300_000_000_000,
        tcp_new_ns: 30_000_000_000,
        udp_ns: 60_000_000_000,
        icmp_ns: 30_000_000_000,
    };
    map.insert(&0u32, &config, 0)
        .map_err(|e| format!("CT_CONFIG insert: {:?}", e))
}

pub fn sync_iface_ctx(runtime: TapMapRuntime<'_>, ifindex: u32) -> Result<(), String> {
    let mut map = open_pinned_iface_ctx(runtime.pin_path)?;
    let ctx = IfaceCtx {
        tap_id: runtime.tap_id,
        flags: 0,
    };
    map.insert(&ifindex, &ctx, 0)
        .map_err(|e| format!("IFACE_CTX_MAP insert for ifindex {}: {:?}", ifindex, e))
}

pub fn clear_iface_ctx(pin_path: &str, ifindex: u32) -> Result<(), String> {
    let mut map = open_pinned_iface_ctx(pin_path)?;
    match map.remove(&ifindex) {
        Ok(()) => Ok(()),
        Err(e) => Err(format!("IFACE_CTX_MAP remove for ifindex {}: {:?}", ifindex, e)),
    }
}

pub fn write_tap_config(runtime: TapMapRuntime<'_>, config: TapConfig) -> Result<(), String> {
    let mut map = open_pinned_tap_config(runtime.pin_path)?;
    map.insert(&runtime.tap_id, &config, 0)
        .map_err(|e| format!("TAP_CONFIG_MAP insert for tap_id {}: {:?}", runtime.tap_id, e))
}

pub fn delete_tap_config(runtime: TapMapRuntime<'_>) -> Result<(), String> {
    let mut map = open_pinned_tap_config(runtime.pin_path)?;
    match map.remove(&runtime.tap_id) {
        Ok(()) => Ok(()),
        Err(e) => Err(format!("TAP_CONFIG_MAP remove for tap_id {}: {:?}", runtime.tap_id, e)),
    }
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
    let current = map.get(&runtime.tap_id, 0).ok();
    let cfg = TapConfig {
        conntrack_enabled: conntrack_enabled
            .map(|b| if b { 1 } else { 0 })
            .unwrap_or_else(|| current.as_ref().map(|c| c.conntrack_enabled).unwrap_or(1)),
        monitoring_enabled: monitoring_enabled
            .map(|b| if b { 1 } else { 0 })
            .unwrap_or_else(|| current.as_ref().map(|c| c.monitoring_enabled).unwrap_or(1)),
        acl_enabled: acl_enabled
            .map(|b| if b { 1 } else { 0 })
            .unwrap_or_else(|| current.as_ref().map(|c| c.acl_enabled).unwrap_or(1)),
        qos_enabled: qos_enabled
            .map(|b| if b { 1 } else { 0 })
            .unwrap_or_else(|| current.as_ref().map(|c| c.qos_enabled).unwrap_or(0)),
        mirror_enabled: mirror_enabled
            .map(|b| if b { 1 } else { 0 })
            .unwrap_or_else(|| current.as_ref().map(|c| c.mirror_enabled).unwrap_or(0)),
        tcprt_enabled: tcprt_enabled
            .map(|b| if b { 1 } else { 0 })
            .unwrap_or_else(|| current.as_ref().map(|c| c.tcprt_enabled).unwrap_or(0)),
        pad: [0; 2],
    };
    map.insert(&runtime.tap_id, &cfg, 0)
        .map_err(|e| format!("TAP_CONFIG_MAP insert for tap_id {}: {:?}", runtime.tap_id, e))
}

pub fn parse_cidr(cidr: &str) -> Result<(IpAddr, u8), String> {
    let parts: Vec<&str> = cidr.split('/').collect();
    if parts.len() != 2 {
        return Err("Invalid CIDR format, expected: x.x.x.x/yy or ipv6/prefix".to_string());
    }
    let ip: IpAddr = parts[0].parse()
        .map_err(|e| format!("Invalid IP: {:?}", e))?;
    let prefix: u8 = parts[1].parse()
        .map_err(|e| format!("Invalid prefix: {:?}", e))?;
    match ip {
        IpAddr::V4(_) if prefix > 32 => return Err("IPv4 prefix must be <= 32".to_string()),
        IpAddr::V6(_) if prefix > 128 => return Err("IPv6 prefix must be <= 128".to_string()),
        _ => (),
    }
    Ok((ip, prefix))
}

fn encode_port_action(action: u8) -> Result<u8, String> {
    match action {
        0 => Ok(2), // PASS
        1 => Ok(1), // DROP
        _ => Err(format!("Invalid action {}: must be 0 or 1", action)),
    }
}

fn stored_policy_action(action: u8, has_port_filter: bool) -> u8 {
    if has_port_filter {
        match action {
            0 => 1,
            1 => 0,
            _ => action,
        }
    } else {
        action
    }
}

fn parse_ports_impl(
    ports_str: &str,
    default_action: u8,
    allow_legacy_bpf_actions: bool,
) -> Result<Vec<(u16, u16, u8)>, String> {
    let default_bpf_action = encode_port_action(default_action)?;
    let mut rules = Vec::new();
    for part in ports_str.split(',') {
        let parts: Vec<&str> = part.trim().split(':').collect();
        let rule_action = match parts.get(1) {
            Some(raw_action) => {
                let action = raw_action
                    .parse::<u8>()
                    .map_err(|_| format!("Invalid action '{}': must be 0 or 1", raw_action))?;
                match action {
                    0 | 1 => encode_port_action(action)?,
                    2 if allow_legacy_bpf_actions => 2,
                    _ => return Err(format!("Invalid action {}: must be 0 or 1", action)),
                }
            }
            None => default_bpf_action,
        };

        if parts[0].contains('-') {
            let range: Vec<&str> = parts[0].split('-').collect();
            if range.len() != 2 {
                return Err("Invalid range format".to_string());
            }
            let start = range[0].trim().parse::<u16>().map_err(|_| "Invalid port")?;
            let end = range[1].trim().parse::<u16>().map_err(|_| "Invalid port")?;
            if start > end {
                return Err(format!("Invalid port range: {}-{} (start must be <= end)", start, end));
            }
            rules.push((start, end, rule_action));
        } else {
            let port = parts[0].trim().parse::<u16>().map_err(|_| "Invalid port")?;
            rules.push((port, port, rule_action));
        }
    }
    Ok(rules)
}

pub fn parse_ports(ports_str: &str, default_action: u8) -> Result<Vec<(u16, u16, u8)>, String> {
    parse_ports_impl(ports_str, default_action, false)
}

fn parse_normalized_ports(ports_str: &str) -> Result<Vec<(u16, u16, u8)>, String> {
    parse_ports_impl(ports_str, 0, true)
}

#[cfg(test)]
mod tests {
    use super::{parse_normalized_ports, parse_ports, stored_policy_action};

    #[test]
    fn parse_ports_inherits_rule_action_for_implicit_entries() {
        let r = parse_ports("80,100-200:0", 1).unwrap();
        assert_eq!(r.len(), 2);
        // 规则默认 action=1 (drop) → 隐式端口也应编码成 DROP
        assert_eq!(r[0], (80, 80, 1));
        // 显式 0 → PASS
        assert_eq!(r[1], (100, 200, 2));
    }

    #[test]
    fn parse_ports_rejects_invalid_formats() {
        assert!(parse_ports("200-100", 0).is_err(), "start>end 应报错");
        assert!(parse_ports("80:2", 0).is_err(), "action>1 应报错");
        assert!(parse_ports("bad", 0).is_err(), "非数字端口应报错");
    }

    #[test]
    fn parse_normalized_ports_accepts_legacy_pass_encoding() {
        let r = parse_normalized_ports("80:2,443:1").unwrap();
        assert_eq!(r, vec![(80, 80, 2), (443, 443, 1)]);
    }

    #[test]
    fn stored_policy_action_inverts_when_port_filter_is_present() {
        assert_eq!(stored_policy_action(0, false), 0);
        assert_eq!(stored_policy_action(1, false), 1);
        assert_eq!(stored_policy_action(0, true), 1);
        assert_eq!(stored_policy_action(1, true), 0);
    }
}

pub fn add_network(direction: &str, cidr: &str, id: u32, runtime: TapMapRuntime<'_>, _ebpf_path: &str) -> Result<(), String> {
    let pin_path = runtime.pin_path;
    let prog_path = format!("{}/xdp_firewall", pin_path);
    if !std::path::Path::new(&prog_path).exists() {
        return Err("Firewall not started. Run 'system start' first.".to_string());
    }

    let (ip, prefix_len) = parse_cidr(cidr)?;

    match ip {
        IpAddr::V4(v4) => {
            let map_name = match direction {
                "src" => "SRC_IPV4_TRIE",
                "dst" => "DST_IPV4_TRIE",
                _ => return Err("direction must be 'src' or 'dst'".to_string()),
            };
            let key = tap_lpm_key_v4(runtime.tap_id, v4.octets(), prefix_len);
            let mut lpm_map = open_pinned_lpm_v4(pin_path, map_name)?;
            lpm_map.insert(&key, &id, 0)
                .map_err(|e| format!("LPM insert error: {:?}", e))?;
            info!(cidr = %cidr, id, direction = %direction, map = %map_name, "added IPv4 network");
        }
        IpAddr::V6(v6) => {
            let map_name = match direction {
                "src" => "SRC_IPV6_TRIE",
                "dst" => "DST_IPV6_TRIE",
                _ => return Err("direction must be 'src' or 'dst'".to_string()),
            };
            let key = tap_lpm_key_v6(runtime.tap_id, v6.octets(), prefix_len);
            let mut lpm_map = open_pinned_lpm_v6(pin_path, map_name)?;
            lpm_map.insert(&key, &id, 0)
                .map_err(|e| format!("LPM insert error: {:?}", e))?;
            info!(cidr = %cidr, id, direction = %direction, map = %map_name, "added IPv6 network");
        }
    }
    Ok(())
}

pub fn delete_network(direction: &str, cidr: &str, _id: u32, runtime: TapMapRuntime<'_>, _ebpf_path: &str) -> Result<(), String> {
    let pin_path = runtime.pin_path;
    let prog_path = format!("{}/xdp_firewall", pin_path);
    if !std::path::Path::new(&prog_path).exists() {
        return Err("Firewall not started. Run 'system start' first.".to_string());
    }

    let (ip, prefix_len) = parse_cidr(cidr)?;

    match ip {
        IpAddr::V4(v4) => {
            let map_name = match direction {
                "src" => "SRC_IPV4_TRIE",
                "dst" => "DST_IPV4_TRIE",
                _ => return Err("direction must be 'src' or 'dst'".to_string()),
            };
            let key = tap_lpm_key_v4(runtime.tap_id, v4.octets(), prefix_len);
            let mut lpm_map = open_pinned_lpm_v4(pin_path, map_name)?;
            match lpm_map.remove(&key) {
                Ok(()) => info!(cidr = %cidr, map = %map_name, "deleted IPv4 network"),
                Err(_) => info!(cidr = %cidr, map = %map_name, "IPv4 network not present during delete"),
            }
        }
        IpAddr::V6(v6) => {
            let map_name = match direction {
                "src" => "SRC_IPV6_TRIE",
                "dst" => "DST_IPV6_TRIE",
                _ => return Err("direction must be 'src' or 'dst'".to_string()),
            };
            let key = tap_lpm_key_v6(runtime.tap_id, v6.octets(), prefix_len);
            let mut lpm_map = open_pinned_lpm_v6(pin_path, map_name)?;
            match lpm_map.remove(&key) {
                Ok(()) => info!(cidr = %cidr, map = %map_name, "deleted IPv6 network"),
                Err(_) => info!(cidr = %cidr, map = %map_name, "IPv6 network not present during delete"),
            }
        }
    }
    Ok(())
}

pub fn add_policy(
    src_id: u32,
    dst_id: u32,
    proto: u8,
    action: u8,
    ports: Option<&str>,
    bitmap_idx: Option<u32>,
    is_new_port_set: bool,
    direction: u8,
    runtime: TapMapRuntime<'_>,
    _ebpf_path: &str,
) -> Result<(), String> {
    let pin_path = runtime.pin_path;
    let prog_path = format!("{}/xdp_firewall", pin_path);
    if !std::path::Path::new(&prog_path).exists() {
        return Err("Firewall not started. Run 'system start' first.".to_string());
    }

    let is_all_ports = matches!(ports, Some("all") | Some("") | None);
    let has_port_filter = (ports.is_some() && !is_all_ports) as u8;

    if is_new_port_set {
        if let Some(idx) = bitmap_idx {
            let ports_str = ports.unwrap_or("");
            if !ports_str.is_empty() {
                let rules = parse_ports(ports_str, action)?;
                let mut port_pool = open_pinned_port_pool(pin_path)?;

                for (start, end, rule_action) in rules {
                    for port in start..=end {
                        let key = PortKey { tap_id: runtime.tap_id, idx, port, pad: 0 };
                        if let Err(e) = port_pool.insert(&key, &rule_action, 0) {
                            let _ = delete_port_set(idx, ports_str, runtime, _ebpf_path);
                            return Err(format!("set port bitmap error: {:?}", e));
                        }
                    }
                    info!(bitmap_idx = idx, start_port = start, end_port = end, rule_action, "programmed port bitmap range");
                }
            }
        }
    }

    let mut policy_table = open_pinned_policy_table(pin_path)?;

    let key = PolicyKey {
        tap_id: runtime.tap_id,
        src_id,
        dst_id,
        proto,
        direction,
        pad: [0; 2],
    };
    let value = PolicyValue {
        action: stored_policy_action(action, has_port_filter != 0),
        has_port_filter,
        pad1: [0; 2],
        bitmap_idx: bitmap_idx.unwrap_or(0),
    };
    if let Err(e) = policy_table.insert(&key, &value, 0) {
        if is_new_port_set {
            if let (Some(idx), Some(ports_str)) = (bitmap_idx, ports) {
                let _ = delete_port_set(idx, ports_str, runtime, _ebpf_path);
            }
        }
        return Err(format!("insert error: {:?}", e));
    }

    let dir_str = if direction == 1 { "egress" } else { "ingress" };
    info!(
        src_id,
        dst_id,
        proto,
        action,
        direction = %dir_str,
        ports = ?ports,
        "added policy"
    );
    Ok(())
}

/// 从内核 POLICY_TABLE 中删除指定策略条目
pub fn delete_policy(
    src_id: u32,
    dst_id: u32,
    proto: u8,
    direction: u8,
    runtime: TapMapRuntime<'_>,
    _ebpf_path: &str,
) -> Result<(), String> {
    let pin_path = runtime.pin_path;
    let prog_path = format!("{}/xdp_firewall", pin_path);
    if !std::path::Path::new(&prog_path).exists() {
        return Err("Firewall not started. Run 'system start' first.".to_string());
    }

    let mut policy_table = open_pinned_policy_table(pin_path)?;

    let key = PolicyKey {
        tap_id: runtime.tap_id,
        src_id,
        dst_id,
        proto,
        direction,
        pad: [0; 2],
    };
    policy_table.remove(&key)
        .map_err(|e| format!("remove policy error: {:?}", e))?;

    info!(src_id, dst_id, proto, direction, "deleted policy");
    Ok(())
}

/// 删除指定 bitmap_idx 的所有端口条目。
pub fn delete_port_set(
    bitmap_idx: u32,
    ports_normalized: &str,
    runtime: TapMapRuntime<'_>,
    _ebpf_path: &str,
) -> Result<(), String> {
    let pin_path = runtime.pin_path;
    let prog_path = format!("{}/xdp_firewall", pin_path);
    if !std::path::Path::new(&prog_path).exists() {
        return Ok(()); // firewall not running, nothing to clean
    }

    let mut port_pool = open_pinned_port_pool(pin_path)?;

    let rules = parse_normalized_ports(ports_normalized)?;
    for (start, end, _) in rules {
        for port in start..=end {
            let key = PortKey { tap_id: runtime.tap_id, idx: bitmap_idx, port, pad: 0 };
            let _ = port_pool.remove(&key);
        }
    }

    Ok(())
}

/// Scrub all tap-scoped entries from the shared managed runtime before replay.
/// This makes replay idempotent and cleans up partial state left by failed attach attempts.
pub fn scrub_managed_runtime_state(runtime: TapMapRuntime<'_>) -> Result<u64, String> {
    if runtime.tap_id == TAP_ID_UNASSIGNED {
        return Ok(0);
    }

    let pin_path = runtime.pin_path;
    let tap_id = runtime.tap_id;
    let mut removed = 0u64;

    removed += scrub_iface_ctx_entries(pin_path, tap_id)?;
    removed += scrub_tap_config_entries(pin_path, tap_id)?;

    removed += scrub_lpm_v4_map(pin_path, "SRC_IPV4_TRIE", tap_id)?;
    removed += scrub_lpm_v4_map(pin_path, "DST_IPV4_TRIE", tap_id)?;
    removed += scrub_lpm_v6_map(pin_path, "SRC_IPV6_TRIE", tap_id)?;
    removed += scrub_lpm_v6_map(pin_path, "DST_IPV6_TRIE", tap_id)?;

    removed += scrub_hash_map(pin_path, "POLICY_TABLE", tap_id, |map_data| {
        HashMap::<_, PolicyKey, PolicyValue>::try_from(aya::maps::Map::HashMap(map_data))
            .map_err(|e| format!("convert POLICY_TABLE to HashMap: {:?}", e))
    })?;
    removed += scrub_hash_map(pin_path, "PORT_BITMAP_POOL", tap_id, |map_data| {
        HashMap::<_, PortKey, u8>::try_from(aya::maps::Map::HashMap(map_data))
            .map_err(|e| format!("convert PORT_BITMAP_POOL to HashMap: {:?}", e))
    })?;

    removed += crate::ct_ops::scrub_ct_tables_strict(runtime)?;
    record_optional_scrub(tap_id, "CT_CONTRACT_STATS", &mut removed, scrub_per_cpu_hash_map(pin_path, "CT_CONTRACT_STATS", tap_id, |map_data| {
        PerCpuHashMap::<_, CtContractKey, CtContractValue>::try_from(
            aya::maps::Map::PerCpuHashMap(map_data)
        ).map_err(|e| format!("convert CT_CONTRACT_STATS to PerCpuHashMap: {:?}", e))
    }));

    record_optional_scrub(tap_id, "RULE_STATS", &mut removed, scrub_per_cpu_hash_map(pin_path, "RULE_STATS", tap_id, |map_data| {
        PerCpuHashMap::<_, PolicyKey, RuleStatsValue>::try_from(
            aya::maps::Map::PerCpuHashMap(map_data)
        ).map_err(|e| format!("convert RULE_STATS to PerCpuHashMap: {:?}", e))
    }));
    record_optional_scrub(tap_id, "FLOW_STATS_V4", &mut removed, scrub_per_cpu_hash_map(pin_path, "FLOW_STATS_V4", tap_id, |map_data| {
        PerCpuHashMap::<_, CtKey4, FlowStatsValue>::try_from(
            aya::maps::Map::PerCpuLruHashMap(map_data)
        ).map_err(|e| format!("convert FLOW_STATS_V4 to PerCpuHashMap: {:?}", e))
    }));
    record_optional_scrub(tap_id, "FLOW_STATS_V6", &mut removed, scrub_per_cpu_hash_map(pin_path, "FLOW_STATS_V6", tap_id, |map_data| {
        PerCpuHashMap::<_, CtKey6, FlowStatsValue>::try_from(
            aya::maps::Map::PerCpuLruHashMap(map_data)
        ).map_err(|e| format!("convert FLOW_STATS_V6 to PerCpuHashMap: {:?}", e))
    }));

    removed += scrub_hash_map(pin_path, "QOS_CONFIG", tap_id, |map_data| {
        HashMap::<_, QosKey, QosConfig>::try_from(aya::maps::Map::HashMap(map_data))
            .map_err(|e| format!("convert QOS_CONFIG to HashMap: {:?}", e))
    })?;
    removed += scrub_hash_map(pin_path, "QOS_TOKEN_BUCKET", tap_id, |map_data| {
        HashMap::<_, QosKey, TokenBucket>::try_from(aya::maps::Map::HashMap(map_data))
            .map_err(|e| format!("convert QOS_TOKEN_BUCKET to HashMap: {:?}", e))
    })?;
    record_optional_scrub(tap_id, "QOS_STATS", &mut removed, scrub_per_cpu_hash_map(pin_path, "QOS_STATS", tap_id, |map_data| {
        PerCpuHashMap::<_, QosKey, QosStatsValue>::try_from(
            aya::maps::Map::PerCpuHashMap(map_data)
        ).map_err(|e| format!("convert QOS_STATS to PerCpuHashMap: {:?}", e))
    }));
    record_optional_scrub(tap_id, "GROUP_STATS", &mut removed, scrub_per_cpu_hash_map(pin_path, "GROUP_STATS", tap_id, |map_data| {
        PerCpuHashMap::<_, GroupStatsKey, GroupStatsValue>::try_from(
            aya::maps::Map::PerCpuHashMap(map_data)
        ).map_err(|e| format!("convert GROUP_STATS to PerCpuHashMap: {:?}", e))
    }));

    removed += scrub_hash_map(pin_path, "MIRROR_POLICY", tap_id, |map_data| {
        HashMap::<_, MirrorKey, MirrorConfig>::try_from(aya::maps::Map::HashMap(map_data))
            .map_err(|e| format!("convert MIRROR_POLICY to HashMap: {:?}", e))
    })?;
    removed += scrub_hash_map(pin_path, "MIRROR_GLOBAL", tap_id, |map_data| {
        HashMap::<_, GlobalMirrorKey, MirrorConfig>::try_from(aya::maps::Map::HashMap(map_data))
            .map_err(|e| format!("convert MIRROR_GLOBAL to HashMap: {:?}", e))
    })?;
    record_optional_scrub(tap_id, "MIRROR_STATS", &mut removed, scrub_per_cpu_hash_map(pin_path, "MIRROR_STATS", tap_id, |map_data| {
        PerCpuHashMap::<_, MirrorKey, MirrorStatsValue>::try_from(
            aya::maps::Map::PerCpuHashMap(map_data)
        ).map_err(|e| format!("convert MIRROR_STATS to PerCpuHashMap: {:?}", e))
    }));
    record_optional_scrub(tap_id, "MIRROR_GLOBAL_STATS", &mut removed, scrub_per_cpu_hash_map(pin_path, "MIRROR_GLOBAL_STATS", tap_id, |map_data| {
        PerCpuHashMap::<_, GlobalMirrorKey, MirrorStatsValue>::try_from(
            aya::maps::Map::PerCpuHashMap(map_data)
        ).map_err(|e| format!("convert MIRROR_GLOBAL_STATS to PerCpuHashMap: {:?}", e))
    }));

    removed += crate::tcprt_ops::scrub_tcprt_tables_strict(runtime)?;
    record_optional_scrub(tap_id, "DROP_REASON_STATS", &mut removed, crate::drop_ops::flush_drop_stats(runtime));
    removed += crate::trace_ops::scrub_trace_filter(runtime)?;
    record_optional_scrub(tap_id, "TRACE_LOG", &mut removed, crate::trace_ops::flush_trace_log(runtime));

    info!(tap_id, removed_entries = removed, "scrubbed managed tap runtime state");
    Ok(removed)
}

/// Network-instance map names pinned under each tap/system instance directory.
pub const NETWORK_MAP_NAMES: &[&str] = &[
    "IFACE_CTX_MAP",
    "TAP_CONFIG_MAP",
    "SRC_IPV4_TRIE", "DST_IPV4_TRIE", "SRC_IPV6_TRIE", "DST_IPV6_TRIE",
    "POLICY_TABLE", "PORT_BITMAP_POOL",
    "CT_TABLE_V4", "CT_TABLE_V6", "CT_CONFIG",
    "CT_CONTRACT_STATS",
    "RULE_STATS", "FLOW_STATS_V4", "FLOW_STATS_V6",
    "QOS_CONFIG", "QOS_TOKEN_BUCKET", "QOS_STATS",
    "GROUP_STATS",
    "MIRROR_POLICY", "MIRROR_GLOBAL", "MIRROR_STATS", "MIRROR_GLOBAL_STATS",
    "TCPRT_TABLE_V4", "TCPRT_TABLE_V6",
    "DROP_REASON_STATS",
    "TRACE_FILTER", "TRACE_LOG", "TRACE_LOG_V6", "TRACE_SEQ",
    "FIREWALL_CONFIG",
];

/// Maps required for both dataplane correctness and control-plane management.
/// If any of these fail to pin, startup must fail and roll back.
pub const CRITICAL_NETWORK_MAP_NAMES: &[&str] = &[
    "IFACE_CTX_MAP",
    "TAP_CONFIG_MAP",
    "SRC_IPV4_TRIE", "DST_IPV4_TRIE", "SRC_IPV6_TRIE", "DST_IPV6_TRIE",
    "POLICY_TABLE", "PORT_BITMAP_POOL",
    "CT_TABLE_V4", "CT_TABLE_V6", "CT_CONFIG",
    "QOS_CONFIG", "QOS_TOKEN_BUCKET",
    "MIRROR_POLICY", "MIRROR_GLOBAL",
    "TCPRT_TABLE_V4", "TCPRT_TABLE_V6",
    "TRACE_FILTER", "TRACE_SEQ",
    "FIREWALL_CONFIG",
];

/// Host-global SSL maps pinned under `ssl-global`.
pub const SSL_MAP_NAMES: &[&str] = &[
    "SSL_HANDSHAKE_SCRATCH", "SSL_CONN_TABLE", "SSL_SNI_TABLE", "SSL_SEQ",
    "SSL_HTTP_PARSE_BUF", "SSL_HTTP_SCRATCH", "SSL_HTTP_SCRATCH_BUF", "SSL_READ_SCRATCH",
    "SSL_HTTP_TABLE", "SSL_HTTP_SEQ", "SSL_HTTP_VALUE_BUF",
    "SSL_GLOBAL_CONFIG", "SSL_ERROR_TABLE", "SSL_ERROR_SEQ", "SSL_WRITE_SCRATCH",
];

/// Complete map inventory, used by diagnostics and legacy paths.
pub const ALL_MAP_NAMES: &[&str] = &[
    "IFACE_CTX_MAP",
    "TAP_CONFIG_MAP",
    "SRC_IPV4_TRIE", "DST_IPV4_TRIE", "SRC_IPV6_TRIE", "DST_IPV6_TRIE",
    "POLICY_TABLE", "PORT_BITMAP_POOL",
    "CT_TABLE_V4", "CT_TABLE_V6", "CT_CONFIG",
    "CT_CONTRACT_STATS",
    "RULE_STATS", "FLOW_STATS_V4", "FLOW_STATS_V6",
    "QOS_CONFIG", "QOS_TOKEN_BUCKET", "QOS_STATS",
    "GROUP_STATS",
    "MIRROR_POLICY", "MIRROR_GLOBAL", "MIRROR_STATS", "MIRROR_GLOBAL_STATS",
    "TCPRT_TABLE_V4", "TCPRT_TABLE_V6",
    "DROP_REASON_STATS",
    "TRACE_FILTER", "TRACE_LOG", "TRACE_LOG_V6", "TRACE_SEQ",
    "FIREWALL_CONFIG",
    "SSL_HANDSHAKE_SCRATCH", "SSL_CONN_TABLE", "SSL_SNI_TABLE", "SSL_SEQ",
    "SSL_HTTP_PARSE_BUF", "SSL_HTTP_SCRATCH", "SSL_HTTP_SCRATCH_BUF", "SSL_READ_SCRATCH",
    "SSL_HTTP_TABLE", "SSL_HTTP_SEQ", "SSL_HTTP_VALUE_BUF",
    "SSL_GLOBAL_CONFIG", "SSL_ERROR_TABLE", "SSL_ERROR_SEQ", "SSL_WRITE_SCRATCH",
];

/// 从 snapshot + WAL 重放所有组和规则到已加载的 eBPF maps。
pub fn replay_state(bpf: &mut aya::Ebpf, state_path: &str) {
    let state = crate::wal::load_with_wal(state_path);
    let tap_id = state.tap_id;

    if state.groups.is_empty() && state.rules.is_empty() && state.qos_rules.is_empty() && state.mirror_rules.is_empty() {
        info!(state_path = %state_path, "state is empty; nothing to replay");
        return;
    }

    info!(
        state_path = %state_path,
        groups = state.groups.len(),
        rules = state.rules.len(),
        qos_rules = state.qos_rules.len(),
        mirror_rules = state.mirror_rules.len(),
        "replaying state into eBPF maps"
    );

    let mut errors: Vec<String> = Vec::new();
    let mut group_count: u32 = 0;
    let mut rule_count: u32 = 0;
    let mut bitmap_count: u32 = 0;

    // 收集 IPv4 和 IPv6 条目，按 map 分批写入
    let mut src_ipv4: Vec<([u8; 4], u8, u32)> = Vec::new();
    let mut dst_ipv4: Vec<([u8; 4], u8, u32)> = Vec::new();
    let mut src_ipv6: Vec<([u8; 16], u8, u32)> = Vec::new();
    let mut dst_ipv6: Vec<([u8; 16], u8, u32)> = Vec::new();

    for (name, group) in &state.groups {
        for cidr in &group.cidrs {
            match parse_cidr(cidr) {
                Ok((IpAddr::V4(v4), prefix)) => {
                    src_ipv4.push((v4.octets(), prefix, group.id));
                    dst_ipv4.push((v4.octets(), prefix, group.id));
                    group_count += 1;
                }
                Ok((IpAddr::V6(v6), prefix)) => {
                    src_ipv6.push((v6.octets(), prefix, group.id));
                    dst_ipv6.push((v6.octets(), prefix, group.id));
                    group_count += 1;
                }
                Err(e) => {
                    errors.push(format!("group '{}' cidr '{}': {}", name, cidr, e));
                }
            }
        }
    }

    // 写 SRC_IPV4_TRIE
    {
        match bpf.map_mut("SRC_IPV4_TRIE")
            .ok_or_else(|| "SRC_IPV4_TRIE not found".to_string())
            .and_then(|m| LpmTrie::<_, [u8; 8], u32>::try_from(m).map_err(|e| format!("{:?}", e)))
        {
            Ok(mut map) => {
                for (octets, prefix, id) in &src_ipv4 {
                    let key = tap_lpm_key_v4(tap_id, *octets, *prefix);
                    if let Err(e) = map.insert(&key, id, 0) {
                        errors.push(format!("SRC_IPV4_TRIE id={}: {:?}", id, e));
                    }
                }
            }
            Err(e) => errors.push(format!("SRC_IPV4_TRIE: {}", e)),
        }
    }

    // 写 DST_IPV4_TRIE
    {
        match bpf.map_mut("DST_IPV4_TRIE")
            .ok_or_else(|| "DST_IPV4_TRIE not found".to_string())
            .and_then(|m| LpmTrie::<_, [u8; 8], u32>::try_from(m).map_err(|e| format!("{:?}", e)))
        {
            Ok(mut map) => {
                for (octets, prefix, id) in &dst_ipv4 {
                    let key = tap_lpm_key_v4(tap_id, *octets, *prefix);
                    if let Err(e) = map.insert(&key, id, 0) {
                        errors.push(format!("DST_IPV4_TRIE id={}: {:?}", id, e));
                    }
                }
            }
            Err(e) => errors.push(format!("DST_IPV4_TRIE: {}", e)),
        }
    }

    // 写 SRC_IPV6_TRIE
    {
        match bpf.map_mut("SRC_IPV6_TRIE")
            .ok_or_else(|| "SRC_IPV6_TRIE not found".to_string())
            .and_then(|m| LpmTrie::<_, [u8; 20], u32>::try_from(m).map_err(|e| format!("{:?}", e)))
        {
            Ok(mut map) => {
                for (octets, prefix, id) in &src_ipv6 {
                    let key = tap_lpm_key_v6(tap_id, *octets, *prefix);
                    if let Err(e) = map.insert(&key, id, 0) {
                        errors.push(format!("SRC_IPV6_TRIE id={}: {:?}", id, e));
                    }
                }
            }
            Err(e) => errors.push(format!("SRC_IPV6_TRIE: {}", e)),
        }
    }

    // 写 DST_IPV6_TRIE
    {
        match bpf.map_mut("DST_IPV6_TRIE")
            .ok_or_else(|| "DST_IPV6_TRIE not found".to_string())
            .and_then(|m| LpmTrie::<_, [u8; 20], u32>::try_from(m).map_err(|e| format!("{:?}", e)))
        {
            Ok(mut map) => {
                for (octets, prefix, id) in &dst_ipv6 {
                    let key = tap_lpm_key_v6(tap_id, *octets, *prefix);
                    if let Err(e) = map.insert(&key, id, 0) {
                        errors.push(format!("DST_IPV6_TRIE id={}: {:?}", id, e));
                    }
                }
            }
            Err(e) => errors.push(format!("DST_IPV6_TRIE: {}", e)),
        }
    }

    // 写 PORT_BITMAP_POOL
    {
        let mut written_bitmaps: HashSet<u32> = HashSet::new();
        match bpf.map_mut("PORT_BITMAP_POOL")
            .ok_or_else(|| "PORT_BITMAP_POOL not found".to_string())
            .and_then(|m| aya::maps::HashMap::<_, PortKey, u8>::try_from(m).map_err(|e| format!("{:?}", e)))
        {
            Ok(mut port_pool) => {
                for rule in &state.rules {
                    if let (Some(idx), Some(ref ports)) = (rule.bitmap_idx, &rule.ports) {
                        if !ports.is_empty() && ports != "all" && !written_bitmaps.contains(&idx) {
                            match parse_ports(ports, rule.action) {
                                Ok(port_rules) => {
                                    for (start, end, action) in port_rules {
                                        for port in start..=end {
                                            let key = PortKey { tap_id, idx, port, pad: 0 };
                                            if let Err(e) = port_pool.insert(&key, &action, 0) {
                                                errors.push(format!("PORT_BITMAP_POOL idx={} port={}: {:?}", idx, port, e));
                                            }
                                        }
                                    }
                                    written_bitmaps.insert(idx);
                                    bitmap_count += 1;
                                }
                                Err(e) => errors.push(format!("parse ports '{}': {}", ports, e)),
                            }
                        }
                    }
                }
            }
            Err(e) => errors.push(format!("PORT_BITMAP_POOL: {}", e)),
        }
    }

    // 写 POLICY_TABLE
    {
        match bpf.map_mut("POLICY_TABLE")
            .ok_or_else(|| "POLICY_TABLE not found".to_string())
            .and_then(|m| aya::maps::HashMap::<_, PolicyKey, PolicyValue>::try_from(m).map_err(|e| format!("{:?}", e)))
        {
            Ok(mut policy_table) => {
                for rule in &state.rules {
                    let is_all_ports = match &rule.ports {
                        Some(p) => p == "all" || p.is_empty(),
                        None => true,
                    };
                    let has_port_filter = (rule.ports.is_some() && !is_all_ports) as u8;

                    let key = PolicyKey {
                        tap_id,
                        src_id: rule.src_group_id,
                        dst_id: rule.dst_group_id,
                        proto: rule.proto,
                        direction: rule.direction,
                        pad: [0; 2],
                    };
                    let value = PolicyValue {
                        action: stored_policy_action(rule.action, has_port_filter != 0),
                        has_port_filter,
                        pad1: [0; 2],
                        bitmap_idx: rule.bitmap_idx.unwrap_or(0),
                    };
                    if let Err(e) = policy_table.insert(&key, &value, 0) {
                        errors.push(format!(
                            "POLICY_TABLE src={} dst={} proto={} dir={}: {:?}",
                            rule.src_group_id, rule.dst_group_id, rule.proto, rule.direction, e
                        ));
                    } else {
                        rule_count += 1;
                    }
                }
            }
            Err(e) => errors.push(format!("POLICY_TABLE: {}", e)),
        }
    }

    // 写 CT_CONFIG（初始化默认超时）
    {
        let config = CtConfig {
            tcp_established_ns: 300_000_000_000,
            tcp_new_ns: 30_000_000_000,
            udp_ns: 60_000_000_000,
            icmp_ns: 30_000_000_000,
        };
        match bpf.map_mut("CT_CONFIG")
            .ok_or_else(|| "CT_CONFIG not found".to_string())
            .and_then(|m| aya::maps::HashMap::<_, u32, CtConfig>::try_from(m).map_err(|e| format!("{:?}", e)))
        {
            Ok(mut map) => {
                if let Err(e) = map.insert(&0u32, &config, 0) {
                    errors.push(format!("CT_CONFIG: {:?}", e));
                }
            }
            Err(e) => errors.push(format!("CT_CONFIG: {}", e)),
        }
    }

    // 写 QOS_CONFIG
    if !state.qos_rules.is_empty() {
        match bpf.map_mut("QOS_CONFIG")
            .ok_or_else(|| "QOS_CONFIG not found".to_string())
            .and_then(|m| aya::maps::HashMap::<_, QosKey, QosConfig>::try_from(m).map_err(|e| format!("{:?}", e)))
        {
            Ok(mut map) => {
                for qr in &state.qos_rules {
                    let key = QosKey {
                        tap_id,
                        group_id: qr.group_id,
                        direction: qr.direction,
                        pad: [0; 3],
                    };
                    let config = QosConfig {
                        rate_bps: qr.rate_bps,
                        burst_bytes: qr.burst_bytes,
                        priority: qr.priority,
                        mode: qr.mode,
                        pad: [0; 6],
                    };
                    if let Err(e) = map.insert(&key, &config, 0) {
                        errors.push(format!("QOS_CONFIG group={}: {:?}", qr.group_name, e));
                    }
                }
            }
            Err(e) => errors.push(format!("QOS_CONFIG: {}", e)),
        }
    }

    // 写 MIRROR_POLICY / MIRROR_GLOBAL
    if !state.mirror_rules.is_empty() {
        let mut policy_rules: Vec<(u32, u32, u8, u8, u32)> = Vec::new();
        let mut global_rules: Vec<(u8, u32)> = Vec::new();

        for mr in &state.mirror_rules {
            // Re-resolve ifindex at replay time
            let ifindex = match crate::mirror_ops::resolve_ifindex(&mr.target_iface) {
                Ok(idx) => idx,
                Err(e) => {
                    warn!(target_iface = %mr.target_iface, error = %e, "mirror target not found during replay");
                    continue;
                }
            };
            if mr.is_global {
                global_rules.push((mr.direction, ifindex));
            } else {
                policy_rules.push((mr.src_group_id, mr.dst_group_id, mr.proto, mr.direction, ifindex));
            }
        }

        let mirror_errors = crate::mirror_ops::replay_mirror_rules(bpf, tap_id, &policy_rules, &global_rules);
        errors.extend(mirror_errors);
    }

    // 写 FIREWALL_CONFIG（功能开关）
    {
        let raw_cpus = unsafe { libc::sysconf(libc::_SC_NPROCESSORS_ONLN) };
        let num_cpus = if raw_cpus > 0 { raw_cpus as u16 } else { 1u16 };
        let cfg = FirewallConfig {
            conntrack_enabled: if state.conntrack_enabled { 1 } else { 0 },
            monitoring_enabled: if state.monitoring_enabled { 1 } else { 0 },
            num_cpus,
            qos_enabled: if state.qos_enabled && !state.qos_rules.is_empty() { 1 } else { 0 },
            acl_enabled: if state.acl_enabled { 1 } else { 0 },
            mirror_enabled: if state.mirror_enabled && !state.mirror_rules.is_empty() { 1 } else { 0 },
            tcprt_enabled: if state.tcprt_enabled { 1 } else { 0 },
            ssl_enabled: if state.ssl_enabled { 1 } else { 0 },
        };
        match bpf.map_mut("FIREWALL_CONFIG")
            .ok_or_else(|| "FIREWALL_CONFIG not found".to_string())
            .and_then(|m| aya::maps::HashMap::<_, u32, FirewallConfig>::try_from(m).map_err(|e| format!("{:?}", e)))
        {
            Ok(mut map) => {
                if let Err(e) = map.insert(&0u32, &cfg, 0) {
                    errors.push(format!("FIREWALL_CONFIG: {:?}", e));
                }
            }
            Err(e) => errors.push(format!("FIREWALL_CONFIG: {}", e)),
        }
    }

    if tap_id != TAP_ID_UNASSIGNED {
        let tap_cfg = TapConfig {
            conntrack_enabled: if state.conntrack_enabled { 1 } else { 0 },
            monitoring_enabled: if state.monitoring_enabled { 1 } else { 0 },
            acl_enabled: if state.acl_enabled { 1 } else { 0 },
            qos_enabled: if state.qos_enabled && !state.qos_rules.is_empty() { 1 } else { 0 },
            mirror_enabled: if state.mirror_enabled && !state.mirror_rules.is_empty() { 1 } else { 0 },
            tcprt_enabled: if state.tcprt_enabled { 1 } else { 0 },
            pad: [0; 2],
        };
        match bpf.map_mut("TAP_CONFIG_MAP")
            .ok_or_else(|| "TAP_CONFIG_MAP not found".to_string())
            .and_then(|m| aya::maps::HashMap::<_, u32, TapConfig>::try_from(m).map_err(|e| format!("{:?}", e)))
        {
            Ok(mut map) => {
                if let Err(e) = map.insert(&tap_id, &tap_cfg, 0) {
                    errors.push(format!("TAP_CONFIG_MAP tap_id={}: {:?}", tap_id, e));
                }
            }
            Err(e) => errors.push(format!("TAP_CONFIG_MAP: {}", e)),
        }
    }

    info!(
        group_cidrs = group_count,
        rules = rule_count,
        port_bitmaps = bitmap_count,
        qos_rules = state.qos_rules.len(),
        mirror_rules = state.mirror_rules.len(),
        "replay complete"
    );
    if !errors.is_empty() {
        warn!(error_count = errors.len(), "replay encountered errors");
        for err in &errors {
            warn!(error = %err, "replay error");
        }
    }
}

/// Replay snapshot + WAL directly into already pinned maps without loading a new eBPF object.
pub fn replay_state_to_pinned_maps(pin_path: &str, state_path: &str) -> Result<(), String> {
    let state = crate::wal::load_with_wal(state_path);
    let tap_id = state.tap_id;
    let runtime = TapMapRuntime::new(pin_path, tap_id);

    if state.groups.is_empty() && state.rules.is_empty() && state.qos_rules.is_empty() && state.mirror_rules.is_empty() {
        info!(state_path = %state_path, "state is empty; nothing to replay");
        return Ok(());
    }

    info!(
        state_path = %state_path,
        pin_path = %pin_path,
        groups = state.groups.len(),
        rules = state.rules.len(),
        qos_rules = state.qos_rules.len(),
        mirror_rules = state.mirror_rules.len(),
        "replaying state into pinned maps"
    );

    let mut errors: Vec<String> = Vec::new();
    let mut group_count: u32 = 0;
    let mut rule_count: u32 = 0;
    let mut bitmap_count: u32 = 0;

    if let Err(e) = init_ct_config_pinned(pin_path) {
        errors.push(e);
    }

    if let Err(e) = update_firewall_config(
        runtime,
        Some(state.conntrack_enabled),
        Some(state.monitoring_enabled),
        Some(state.acl_enabled),
        Some(state.qos_enabled && !state.qos_rules.is_empty()),
        Some(state.mirror_enabled && !state.mirror_rules.is_empty()),
        Some(state.tcprt_enabled),
        Some(state.ssl_enabled),
    ) {
        errors.push(format!("FIREWALL_CONFIG: {}", e));
    }

    if tap_id != TAP_ID_UNASSIGNED {
        let tap_cfg = TapConfig {
            conntrack_enabled: if state.conntrack_enabled { 1 } else { 0 },
            monitoring_enabled: if state.monitoring_enabled { 1 } else { 0 },
            acl_enabled: if state.acl_enabled { 1 } else { 0 },
            qos_enabled: if state.qos_enabled && !state.qos_rules.is_empty() { 1 } else { 0 },
            mirror_enabled: if state.mirror_enabled && !state.mirror_rules.is_empty() { 1 } else { 0 },
            tcprt_enabled: if state.tcprt_enabled { 1 } else { 0 },
            pad: [0; 2],
        };
        if let Err(e) = write_tap_config(runtime, tap_cfg) {
            errors.push(format!("TAP_CONFIG_MAP tap_id={}: {}", tap_id, e));
        }
    }

    for (name, group) in &state.groups {
        for cidr in &group.cidrs {
            if let Err(e) = add_network("src", cidr, group.id, runtime, "") {
                errors.push(format!("group '{}' cidr '{}' src: {}", name, cidr, e));
            }
            if let Err(e) = add_network("dst", cidr, group.id, runtime, "") {
                errors.push(format!("group '{}' cidr '{}' dst: {}", name, cidr, e));
            }
            group_count += 1;
        }
    }

    let mut written_bitmaps: HashSet<u32> = HashSet::new();
    for rule in &state.rules {
        let ports = rule.ports.as_deref();
        let write_port_set = match (rule.bitmap_idx, ports) {
            (Some(idx), Some(ports)) if !ports.is_empty() && ports != "all" => written_bitmaps.insert(idx),
            _ => false,
        };

        if write_port_set {
            bitmap_count += 1;
        }

        match add_policy(
            rule.src_group_id,
            rule.dst_group_id,
            rule.proto,
            rule.action,
            ports,
            rule.bitmap_idx,
            write_port_set,
            rule.direction,
            runtime,
            "",
        ) {
            Ok(()) => rule_count += 1,
            Err(e) => errors.push(format!(
                "POLICY_TABLE src={} dst={} proto={} dir={}: {}",
                rule.src_group_id, rule.dst_group_id, rule.proto, rule.direction, e
            )),
        }
    }

    for qr in &state.qos_rules {
        if let Err(e) = crate::qos_ops::add_qos_rule(
            qr.group_id,
            qr.direction,
            qr.rate_bps,
            qr.burst_bytes,
            qr.priority,
            qr.mode,
            runtime,
            state.qos_enabled,
        ) {
            errors.push(format!("QOS_CONFIG group={}: {}", qr.group_name, e));
        }
    }

    for mr in &state.mirror_rules {
        let target_ifindex = match crate::mirror_ops::resolve_ifindex(&mr.target_iface) {
            Ok(idx) => idx,
            Err(e) => {
                errors.push(format!("mirror target '{}' not found: {}", mr.target_iface, e));
                continue;
            }
        };

        let result = if mr.is_global {
            crate::mirror_ops::add_global_mirror(
                mr.direction,
                target_ifindex,
                runtime,
                state.mirror_enabled,
            )
        } else {
            crate::mirror_ops::add_mirror_rule(
                mr.src_group_id,
                mr.dst_group_id,
                mr.proto,
                mr.direction,
                target_ifindex,
                runtime,
                state.mirror_enabled,
            )
        };

        if let Err(e) = result {
            let scope = if mr.is_global { "MIRROR_GLOBAL" } else { "MIRROR_POLICY" };
            errors.push(format!("{} target={} dir={}: {}", scope, mr.target_iface, mr.direction, e));
        }
    }

    info!(
        group_cidrs = group_count,
        rules = rule_count,
        port_bitmaps = bitmap_count,
        qos_rules = state.qos_rules.len(),
        mirror_rules = state.mirror_rules.len(),
        "pinned replay complete"
    );
    if !errors.is_empty() {
        warn!(error_count = errors.len(), "pinned replay encountered errors");
        for err in &errors {
            warn!(error = %err, "pinned replay error");
        }
        let preview = errors.iter().take(3).cloned().collect::<Vec<_>>().join("; ");
        let suffix = if errors.len() > 3 {
            format!("; ... {} more", errors.len() - 3)
        } else {
            String::new()
        };
        return Err(format!(
            "pinned replay encountered {} errors: {}{}",
            errors.len(),
            preview,
            suffix
        ));
    }
    Ok(())
}

pub fn show_stats(pin_path: &str, state_path: &str) -> Result<(), String> {
    if !std::path::Path::new(pin_path).exists() {
        return Err("Firewall not started. Run 'system start' first.".to_string());
    }

    let state_file = format!("{}/state.json", state_path);

    let state: FirewallState = if std::path::Path::new(&state_file).exists() {
        let contents = std::fs::read_to_string(&state_file)
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

    println!("=== Aria Firewall Stats ===");
    println!();

    println!("Groups: {}", state.groups.len());
    let total_cidrs: usize = state.groups.values().map(|g| g.cidrs.len()).sum();
    println!("  Total CIDRs: {}", total_cidrs);
    let ipv4_cidrs = state.groups.values()
        .flat_map(|g| g.cidrs.iter())
        .filter(|c| !c.contains(':'))
        .count();
    let ipv6_cidrs = total_cidrs - ipv4_cidrs;
    println!("  IPv4: {}, IPv6: {}", ipv4_cidrs, ipv6_cidrs);
    println!();

    println!("Policies: {}", state.rules.len());
    let ingress_count = state.rules.iter().filter(|r| r.direction == 0).count();
    let egress_count = state.rules.iter().filter(|r| r.direction == 1).count();
    println!("  Ingress: {}, Egress: {}", ingress_count, egress_count);
    let allow_count = state.rules.iter().filter(|r| r.action == 0).count();
    let drop_count = state.rules.iter().filter(|r| r.action == 1).count();
    println!("  Allow: {}, Drop: {}", allow_count, drop_count);
    let with_ports = state.rules.iter().filter(|r| r.bitmap_idx.is_some()).count();
    println!("  With port filter: {}", with_ports);
    println!();

    println!("QoS rules: {}", state.qos_rules.len());
    println!();

    println!("Port bitmap pool: {}/{} slots used", state.port_sets.len(), state.max_port_policies);
    println!("  Free recycled slots: {}", state.free_bitmap_indices.len());
    println!();

    println!("Kernel maps:");
    for name in NETWORK_MAP_NAMES {
        let path = format!("{}/{}", pin_path, name);
        let status = if std::path::Path::new(&path).exists() { "pinned" } else { "missing" };
        println!("  {}: {}", name, status);
    }

    Ok(())
}

/// Setup TC ingress: add clsact qdisc and attach the tc_ingress classifier program (mirror only).
/// The TC link is pinned to `{pin_path}/tc_ingress_link` to prevent detach on drop.
#[allow(dead_code)]
pub fn attach_tc_ingress(bpf: &mut aya::Ebpf, iface: &str, pin_path: &str) -> Result<(), String> {
    // Add clsact qdisc (idempotent — ignore "File exists")
    if let Err(e) = aya::programs::tc::qdisc_add_clsact(iface) {
        let err_str = format!("{:?}", e);
        if !err_str.contains("File exists") {
            return Err(format!("qdisc_add_clsact failed: {}", err_str));
        }
    }

    let tc_program = bpf
        .program_mut("tc_ingress")
        .ok_or("TC ingress program not found")?;

    let tc: &mut aya::programs::SchedClassifier = tc_program
        .try_into()
        .map_err(|e: aya::programs::ProgramError| format!("tc_ingress try_into error: {:?}", e))?;

    tc.load().map_err(|e| format!("tc_ingress.load error: {:?}", e))?;

    let link_id = tc.attach(iface, aya::programs::tc::TcAttachType::Ingress)
        .map_err(|e| format!("tc_ingress attach error: {:?}", e))?;

    let tc_link = tc.take_link(link_id)
        .map_err(|e| format!("tc_ingress take_link error: {:?}", e))?;
    let fd_link: aya::programs::links::FdLink = tc_link.try_into()
        .map_err(|e: aya::programs::links::LinkError| format!("tc_ingress convert to FdLink error: {:?}", e))?;
    let tc_link_pin = format!("{}/tc_ingress_link", pin_path);
    let _pinned = fd_link.pin(&tc_link_pin)
        .map_err(|e| format!("tc_ingress pin link error: {:?}", e))?;

    info!(iface = %iface, "TC ingress attached with pinned link");
    Ok(())
}

/// Setup TC egress: add clsact qdisc and attach the classifier program.
/// The TC link is pinned to `{pin_path}/tc_egress_link` to prevent detach on drop.
#[allow(dead_code)]
pub fn attach_tc_egress(bpf: &mut aya::Ebpf, iface: &str, pin_path: &str) -> Result<(), String> {
    // Add clsact qdisc using aya's API
    if let Err(e) = aya::programs::tc::qdisc_add_clsact(iface) {
        let err_str = format!("{:?}", e);
        // "File exists" is OK — clsact already added
        if !err_str.contains("File exists") {
            return Err(format!("qdisc_add_clsact failed: {}", err_str));
        }
    }

    let tc_program = bpf
        .program_mut("tc_egress")
        .ok_or("TC egress program not found")?;

    let tc: &mut aya::programs::SchedClassifier = tc_program
        .try_into()
        .map_err(|e: aya::programs::ProgramError| format!("tc try_into error: {:?}", e))?;

    tc.load().map_err(|e| format!("tc.load error: {:?}", e))?;

    let link_id = tc.attach(iface, aya::programs::tc::TcAttachType::Egress)
        .map_err(|e| format!("tc attach error: {:?}", e))?;

    // Pin the TC link so it survives for the lifetime of the process
    let tc_link = tc.take_link(link_id)
        .map_err(|e| format!("tc take_link error: {:?}", e))?;
    let fd_link: aya::programs::links::FdLink = tc_link.try_into()
        .map_err(|e: aya::programs::links::LinkError| format!("tc convert to FdLink error: {:?}", e))?;
    let tc_link_pin = format!("{}/tc_egress_link", pin_path);
    let _pinned = fd_link.pin(&tc_link_pin)
        .map_err(|e| format!("tc pin link error: {:?}", e))?;

    info!(iface = %iface, "TC egress attached with pinned link");
    Ok(())
}

/// Remove TC egress filter and clsact qdisc
pub fn detach_tc_egress(iface: &str) {
    // Remove TC filter using tc command
    let _ = std::process::Command::new("tc")
        .args(["filter", "del", "dev", iface, "egress"])
        .output();

    // Remove clsact qdisc
    let _ = std::process::Command::new("tc")
        .args(["qdisc", "del", "dev", iface, "clsact"])
        .output();
}

/// Setup FQ qdisc for EDT-based QoS
pub fn setup_fq_qdisc(iface: &str) -> Result<(), String> {
    let output = std::process::Command::new("tc")
        .args(["qdisc", "replace", "dev", iface, "root", "fq"])
        .output()
        .map_err(|e| format!("Failed to run tc: {}", e))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("tc qdisc replace fq failed: {}", stderr));
    }
    info!(iface = %iface, "FQ qdisc configured");
    Ok(())
}

/// Check if FQ qdisc is currently active on the interface.
pub fn check_fq_qdisc(iface: &str) -> bool {
    let output = std::process::Command::new("tc")
        .args(["qdisc", "show", "dev", iface])
        .output();
    match output {
        Ok(o) => {
            let stdout = String::from_utf8_lossy(&o.stdout);
            stdout.contains("fq")
        }
        Err(_) => false,
    }
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
    let pin_path = runtime.pin_path;
    let map_path = format!("{}/FIREWALL_CONFIG", pin_path);
    let map_data = MapData::from_pin(&map_path)
        .map_err(|e| format!("open FIREWALL_CONFIG: {:?}", e))?;
    let mut map = aya::maps::HashMap::<_, u32, FirewallConfig>::try_from(
        aya::maps::Map::HashMap(map_data)
    ).map_err(|e| format!("convert FIREWALL_CONFIG: {:?}", e))?;

    // Read current config or use defaults
    let current = map.get(&0u32, 0).ok();
    let num_cpus_val = current.as_ref().map(|c| c.num_cpus).unwrap_or_else(|| {
        let raw = unsafe { libc::sysconf(libc::_SC_NPROCESSORS_ONLN) };
        if raw > 0 { raw as u16 } else { 1u16 }
    });
    let ct = conntrack_enabled.map(|b| if b { 1u8 } else { 0 })
        .unwrap_or_else(|| current.as_ref().map(|c| c.conntrack_enabled).unwrap_or(1));
    let mon = monitoring_enabled.map(|b| if b { 1u8 } else { 0 })
        .unwrap_or_else(|| current.as_ref().map(|c| c.monitoring_enabled).unwrap_or(1));
    let acl = acl_enabled.map(|b| if b { 1u8 } else { 0 })
        .unwrap_or_else(|| current.as_ref().map(|c| c.acl_enabled).unwrap_or(1));
    let qos = qos_enabled.map(|b| if b { 1u8 } else { 0 })
        .unwrap_or_else(|| current.as_ref().map(|c| c.qos_enabled).unwrap_or(0));
    let mir = mirror_enabled.map(|b| if b { 1u8 } else { 0 })
        .unwrap_or_else(|| current.as_ref().map(|c| c.mirror_enabled).unwrap_or(0));
    let tcprt = tcprt_enabled.map(|b| if b { 1u8 } else { 0 })
        .unwrap_or_else(|| current.as_ref().map(|c| c.tcprt_enabled).unwrap_or(1));
    let ssl = ssl_enabled.map(|b| if b { 1u8 } else { 0 })
        .unwrap_or_else(|| current.as_ref().map(|c| c.ssl_enabled).unwrap_or(0));

    let cfg = FirewallConfig {
        conntrack_enabled: ct,
        monitoring_enabled: mon,
        num_cpus: num_cpus_val,
        qos_enabled: qos,
        acl_enabled: acl,
        mirror_enabled: mir,
        tcprt_enabled: tcprt,
        ssl_enabled: ssl,
    };
    map.insert(&0u32, &cfg, 0)
        .map_err(|e| format!("FIREWALL_CONFIG insert: {:?}", e))?;

    Ok(())
}

/// Read the current FIREWALL_CONFIG from pinned map.
pub fn read_firewall_config(runtime: TapMapRuntime<'_>) -> Result<FirewallConfig, String> {
    let pin_path = runtime.pin_path;
    let map_path = format!("{}/FIREWALL_CONFIG", pin_path);
    let map_data = MapData::from_pin(&map_path)
        .map_err(|e| format!("open FIREWALL_CONFIG: {:?}", e))?;
    let map = aya::maps::HashMap::<_, u32, FirewallConfig>::try_from(
        aya::maps::Map::HashMap(map_data)
    ).map_err(|e| format!("convert FIREWALL_CONFIG: {:?}", e))?;

    map.get(&0u32, 0)
        .map_err(|e| format!("read FIREWALL_CONFIG: {:?}", e))
}

pub fn read_runtime_config(runtime: TapMapRuntime<'_>) -> Result<FirewallConfig, String> {
    if runtime.tap_id == TAP_ID_UNASSIGNED {
        return read_firewall_config(runtime);
    }

    let global = read_firewall_config(runtime).unwrap_or_else(|_| {
        let raw = unsafe { libc::sysconf(libc::_SC_NPROCESSORS_ONLN) };
        FirewallConfig {
            conntrack_enabled: 1,
            monitoring_enabled: 1,
            num_cpus: if raw > 0 { raw as u16 } else { 1u16 },
            qos_enabled: 0,
            acl_enabled: 1,
            mirror_enabled: 0,
            tcprt_enabled: 1,
            ssl_enabled: 0,
        }
    });

    let map = open_pinned_tap_config(runtime.pin_path)?;
    let tap_cfg = map.get(&runtime.tap_id, 0)
        .map_err(|e| format!("read TAP_CONFIG_MAP for tap_id {}: {:?}", runtime.tap_id, e))?;

    Ok(FirewallConfig {
        conntrack_enabled: tap_cfg.conntrack_enabled,
        monitoring_enabled: tap_cfg.monitoring_enabled,
        num_cpus: global.num_cpus,
        qos_enabled: tap_cfg.qos_enabled,
        acl_enabled: tap_cfg.acl_enabled,
        mirror_enabled: tap_cfg.mirror_enabled,
        tcprt_enabled: tap_cfg.tcprt_enabled,
        ssl_enabled: global.ssl_enabled,
    })
}
