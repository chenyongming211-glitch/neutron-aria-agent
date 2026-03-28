use std::collections::{BTreeSet, HashSet};
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

mod runtime;
mod network;
mod attach;
mod scrub;

pub use runtime::{
    clear_iface_ctx,
    delete_tap_config,
    read_firewall_config,
    read_iface_ctx,
    read_runtime_config,
    sync_iface_ctx,
    update_firewall_config,
    update_runtime_config,
    write_tap_config,
};
pub use network::{add_network, delete_network, parse_cidr};
pub use attach::{
    attach_tc_egress,
    attach_tc_ingress,
    check_fq_qdisc,
    detach_tc_egress,
    setup_fq_qdisc,
};
pub use scrub::{scrub_managed_runtime_state, scrub_standalone_runtime_state};

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

fn summarize_entries(entries: &BTreeSet<String>) -> String {
    if entries.is_empty() {
        return "none".to_string();
    }
    entries.iter().take(3).cloned().collect::<Vec<_>>().join("; ")
}

fn validate_entry_set(
    map_name: &str,
    tap_id: u32,
    expected: BTreeSet<String>,
    actual: BTreeSet<String>,
) -> Result<(), String> {
    if expected == actual {
        return Ok(());
    }

    let missing: BTreeSet<String> = expected.difference(&actual).cloned().collect();
    let unexpected: BTreeSet<String> = actual.difference(&expected).cloned().collect();

    Err(format!(
        "{} drift for tap_id {}: missing={} ({}) unexpected={} ({})",
        map_name,
        tap_id,
        missing.len(),
        summarize_entries(&missing),
        unexpected.len(),
        summarize_entries(&unexpected),
    ))
}

fn collect_lpm_entries_v4(
    pin_path: &str,
    map_name: &str,
    tap_id: u32,
) -> Result<BTreeSet<String>, String> {
    let map = open_pinned_lpm_v4(pin_path, map_name)?;
    let tap_prefix = tap_id.to_be_bytes();
    let mut entries = BTreeSet::new();
    for item in map.iter() {
        let (key, value) = item.map_err(|e| format!("iterate {}: {:?}", map_name, e))?;
        let data = key.data();
        if data[..4] == tap_prefix {
            entries.insert(format_lpm_entry_v4(&key, value));
        }
    }
    Ok(entries)
}

fn collect_lpm_entries_v6(
    pin_path: &str,
    map_name: &str,
    tap_id: u32,
) -> Result<BTreeSet<String>, String> {
    let map = open_pinned_lpm_v6(pin_path, map_name)?;
    let tap_prefix = tap_id.to_be_bytes();
    let mut entries = BTreeSet::new();
    for item in map.iter() {
        let (key, value) = item.map_err(|e| format!("iterate {}: {:?}", map_name, e))?;
        let data = key.data();
        if data[..4] == tap_prefix {
            entries.insert(format_lpm_entry_v6(&key, value));
        }
    }
    Ok(entries)
}

fn format_lpm_entry_v4(key: &Key<[u8; 8]>, value: u32) -> String {
    let data = key.data();
    format!(
        "prefix_len={} tap_id={} ip={:?}=>{}",
        key.prefix_len(),
        u32::from_be_bytes(data[..4].try_into().unwrap()),
        &data[4..],
        value,
    )
}

fn format_lpm_entry_v6(key: &Key<[u8; 20]>, value: u32) -> String {
    let data = key.data();
    format!(
        "prefix_len={} tap_id={} ip={:?}=>{}",
        key.prefix_len(),
        u32::from_be_bytes(data[..4].try_into().unwrap()),
        &data[4..],
        value,
    )
}

pub fn validate_pinned_runtime_state(
    runtime: TapMapRuntime<'_>,
    state: &FirewallState,
) -> Result<(), String> {
    if runtime.tap_id == TAP_ID_UNASSIGNED {
        return Ok(());
    }
    if state.tap_id != runtime.tap_id {
        return Err(format!(
            "state tap_id {} does not match runtime tap_id {}",
            state.tap_id, runtime.tap_id
        ));
    }

    let pin_path = runtime.pin_path;
    let tap_id = runtime.tap_id;

    let expected_tap_config = TapConfig {
        conntrack_enabled: if state.conntrack_enabled { 1 } else { 0 },
        monitoring_enabled: if state.monitoring_enabled { 1 } else { 0 },
        acl_enabled: if state.acl_enabled { 1 } else { 0 },
        qos_enabled: if state.qos_enabled && !state.qos_rules.is_empty() { 1 } else { 0 },
        mirror_enabled: if state.mirror_enabled && !state.mirror_rules.is_empty() { 1 } else { 0 },
        tcprt_enabled: if state.tcprt_enabled { 1 } else { 0 },
        pad: [0; 2],
    };
    let tap_config_map = open_pinned_tap_config(pin_path)?;
    let actual_tap_config = tap_config_map.get(&tap_id, 0)
        .map_err(|e| format!("read TAP_CONFIG_MAP for tap_id {}: {:?}", tap_id, e))?;
    if actual_tap_config.conntrack_enabled != expected_tap_config.conntrack_enabled
        || actual_tap_config.monitoring_enabled != expected_tap_config.monitoring_enabled
        || actual_tap_config.acl_enabled != expected_tap_config.acl_enabled
        || actual_tap_config.qos_enabled != expected_tap_config.qos_enabled
        || actual_tap_config.mirror_enabled != expected_tap_config.mirror_enabled
        || actual_tap_config.tcprt_enabled != expected_tap_config.tcprt_enabled
    {
        return Err(format!(
            "TAP_CONFIG_MAP drift for tap_id {}: actual={:?} expected={:?}",
            tap_id, actual_tap_config, expected_tap_config
        ));
    }

    let mut expected_src_ipv4 = BTreeSet::new();
    let mut expected_dst_ipv4 = BTreeSet::new();
    let mut expected_src_ipv6 = BTreeSet::new();
    let mut expected_dst_ipv6 = BTreeSet::new();
    for (name, group) in &state.groups {
        for cidr in &group.cidrs {
            let (ip, prefix) = parse_cidr(cidr)
                .map_err(|e| format!("group '{}' cidr '{}': {}", name, cidr, e))?;
            match ip {
                IpAddr::V4(v4) => {
                    expected_src_ipv4.insert(format_lpm_entry_v4(&tap_lpm_key_v4(tap_id, v4.octets(), prefix), group.id));
                    expected_dst_ipv4.insert(format_lpm_entry_v4(&tap_lpm_key_v4(tap_id, v4.octets(), prefix), group.id));
                }
                IpAddr::V6(v6) => {
                    expected_src_ipv6.insert(format_lpm_entry_v6(&tap_lpm_key_v6(tap_id, v6.octets(), prefix), group.id));
                    expected_dst_ipv6.insert(format_lpm_entry_v6(&tap_lpm_key_v6(tap_id, v6.octets(), prefix), group.id));
                }
            }
        }
    }

    validate_entry_set(
        "SRC_IPV4_TRIE",
        tap_id,
        expected_src_ipv4,
        collect_lpm_entries_v4(pin_path, "SRC_IPV4_TRIE", tap_id)?,
    )?;
    validate_entry_set(
        "DST_IPV4_TRIE",
        tap_id,
        expected_dst_ipv4,
        collect_lpm_entries_v4(pin_path, "DST_IPV4_TRIE", tap_id)?,
    )?;
    validate_entry_set(
        "SRC_IPV6_TRIE",
        tap_id,
        expected_src_ipv6,
        collect_lpm_entries_v6(pin_path, "SRC_IPV6_TRIE", tap_id)?,
    )?;
    validate_entry_set(
        "DST_IPV6_TRIE",
        tap_id,
        expected_dst_ipv6,
        collect_lpm_entries_v6(pin_path, "DST_IPV6_TRIE", tap_id)?,
    )?;

    let mut expected_policy = BTreeSet::new();
    let mut expected_ports = BTreeSet::new();
    for rule in &state.rules {
        let ports = rule.ports.as_deref();
        let is_all_ports = matches!(ports, Some("all") | Some("") | None);
        let has_port_filter = (ports.is_some() && !is_all_ports) as u8;
        let policy_key = PolicyKey {
            tap_id,
            src_id: rule.src_group_id,
            dst_id: rule.dst_group_id,
            proto: rule.proto,
            direction: rule.direction,
            pad: [0; 2],
        };
        let policy_value = PolicyValue {
            action: stored_policy_action(rule.action, has_port_filter != 0),
            has_port_filter,
            pad1: [0; 2],
            bitmap_idx: rule.bitmap_idx.unwrap_or(0),
        };
        expected_policy.insert(format!("{:?}=>{:?}", policy_key, policy_value));

        if let (Some(idx), Some(ports_str)) = (rule.bitmap_idx, ports) {
            if !ports_str.is_empty() && ports_str != "all" {
                for (start, end, rule_action) in parse_ports(ports_str, rule.action)? {
                    for port in start..=end {
                        let key = PortKey { tap_id, idx, port, pad: 0 };
                        expected_ports.insert(format!("{:?}=>{}", key, rule_action));
                    }
                }
            }
        }
    }

    let policy_table = open_pinned_policy_table(pin_path)?;
    let mut actual_policy = BTreeSet::new();
    for item in policy_table.iter() {
        let (key, value) = item.map_err(|e| format!("iterate POLICY_TABLE: {:?}", e))?;
        if key.tap_id == tap_id {
            actual_policy.insert(format!("{:?}=>{:?}", key, value));
        }
    }
    validate_entry_set("POLICY_TABLE", tap_id, expected_policy, actual_policy)?;

    let port_pool = open_pinned_port_pool(pin_path)?;
    let mut actual_ports = BTreeSet::new();
    for item in port_pool.iter() {
        let (key, value) = item.map_err(|e| format!("iterate PORT_BITMAP_POOL: {:?}", e))?;
        if key.tap_id == tap_id {
            actual_ports.insert(format!("{:?}=>{}", key, value));
        }
    }
    validate_entry_set("PORT_BITMAP_POOL", tap_id, expected_ports, actual_ports)?;

    let expected_qos: BTreeSet<String> = state.qos_rules.iter().map(|rule| {
        let key = QosKey {
            tap_id,
            group_id: rule.group_id,
            direction: rule.direction,
            pad: [0; 3],
        };
        let value = QosConfig {
            rate_bps: rule.rate_bps,
            burst_bytes: rule.burst_bytes,
            priority: rule.priority,
            mode: rule.mode,
            pad: [0; 6],
        };
        format!("{:?}=>{:?}", key, value)
    }).collect();
    let actual_qos: BTreeSet<String> = crate::qos_ops::list_qos_rules(runtime)?
        .into_iter()
        .map(|(key, value)| format!("{:?}=>{:?}", key, value))
        .collect();
    validate_entry_set("QOS_CONFIG", tap_id, expected_qos, actual_qos)?;

    let mut expected_policy_mirror = BTreeSet::new();
    let mut expected_global_mirror = BTreeSet::new();
    for rule in &state.mirror_rules {
        let target_ifindex = crate::mirror_ops::resolve_ifindex(&rule.target_iface)
            .map_err(|e| format!("resolve mirror target '{}' for validation: {}", rule.target_iface, e))?;
        if rule.is_global {
            let key = GlobalMirrorKey {
                tap_id,
                direction: rule.direction,
                pad: [0; 3],
            };
            let value = MirrorConfig { target_ifindex };
            expected_global_mirror.insert(format!("{:?}=>{:?}", key, value));
        } else {
            let key = MirrorKey {
                tap_id,
                src_id: rule.src_group_id,
                dst_id: rule.dst_group_id,
                proto: rule.proto,
                direction: rule.direction,
                pad: [0; 2],
            };
            let value = MirrorConfig { target_ifindex };
            expected_policy_mirror.insert(format!("{:?}=>{:?}", key, value));
        }
    }
    let actual_policy_mirror: BTreeSet<String> = crate::mirror_ops::list_mirror_rules(runtime)?
        .into_iter()
        .map(|(key, value)| format!("{:?}=>{:?}", key, value))
        .collect();
    validate_entry_set(
        "MIRROR_POLICY",
        tap_id,
        expected_policy_mirror,
        actual_policy_mirror,
    )?;
    let actual_global_mirror: BTreeSet<String> = crate::mirror_ops::list_global_mirrors(runtime)?
        .into_iter()
        .map(|(key, value)| format!("{:?}=>{:?}", key, value))
        .collect();
    validate_entry_set(
        "MIRROR_GLOBAL",
        tap_id,
        expected_global_mirror,
        actual_global_mirror,
    )?;

    Ok(())
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

    validate_policy_ports(proto, ports)?;

    let is_all_ports = match ports {
        Some(p) => {
            let p = p.trim();
            p.is_empty() || p.eq_ignore_ascii_case("all")
        }
        None => true,
    };
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

pub fn validate_policy_ports(proto: u8, ports: Option<&str>) -> Result<(), String> {
    const TCP_PROTO: u8 = libc::IPPROTO_TCP as u8;
    const UDP_PROTO: u8 = libc::IPPROTO_UDP as u8;

    let Some(ports) = ports else {
        return Ok(());
    };

    let ports = ports.trim();
    if ports.is_empty() || ports.eq_ignore_ascii_case("all") {
        return Ok(());
    }

    match proto {
        TCP_PROTO | UDP_PROTO => Ok(()),
        0 => Err(
            "Port filters require a concrete protocol; use 'tcp' or 'udp' instead of 'any'"
                .to_string(),
        ),
        other => Err(format!("Protocol {} does not support port filters", other)),
    }
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
    "TRACE_FILTER", "TRACE_LOG", "TRACE_LOG_V6", "TRACE_SEQ", "TRACE_EVENTS",
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

/// Trace map inventory mode used to validate runtime completeness during the
/// legacy-to-stream transition.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum TraceMapMode {
    Legacy,
    Stream,
}

pub const STREAM_CRITICAL_NETWORK_MAP_NAMES: &[&str] = &[
    "IFACE_CTX_MAP",
    "TAP_CONFIG_MAP",
    "SRC_IPV4_TRIE", "DST_IPV4_TRIE", "SRC_IPV6_TRIE", "DST_IPV6_TRIE",
    "POLICY_TABLE", "PORT_BITMAP_POOL",
    "CT_TABLE_V4", "CT_TABLE_V6", "CT_CONFIG",
    "QOS_CONFIG", "QOS_TOKEN_BUCKET",
    "MIRROR_POLICY", "MIRROR_GLOBAL",
    "TCPRT_TABLE_V4", "TCPRT_TABLE_V6",
    "TRACE_FILTER", "TRACE_SEQ", "TRACE_EVENTS",
    "FIREWALL_CONFIG",
];

pub fn critical_network_map_names(trace_mode: TraceMapMode) -> &'static [&'static str] {
    match trace_mode {
        TraceMapMode::Legacy => CRITICAL_NETWORK_MAP_NAMES,
        TraceMapMode::Stream => STREAM_CRITICAL_NETWORK_MAP_NAMES,
    }
}

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
    "TRACE_FILTER", "TRACE_LOG", "TRACE_LOG_V6", "TRACE_SEQ", "TRACE_EVENTS",
    "FIREWALL_CONFIG",
    "SSL_HANDSHAKE_SCRATCH", "SSL_CONN_TABLE", "SSL_SNI_TABLE", "SSL_SEQ",
    "SSL_HTTP_PARSE_BUF", "SSL_HTTP_SCRATCH", "SSL_HTTP_SCRATCH_BUF", "SSL_READ_SCRATCH",
    "SSL_HTTP_TABLE", "SSL_HTTP_SEQ", "SSL_HTTP_VALUE_BUF",
    "SSL_GLOBAL_CONFIG", "SSL_ERROR_TABLE", "SSL_ERROR_SEQ", "SSL_WRITE_SCRATCH",
];

/// 从 snapshot + WAL 重放所有组和规则到已加载的 eBPF maps。
pub fn replay_state(bpf: &mut aya::Ebpf, state_path: &str) -> Result<(), String> {
    let state = crate::wal::load_with_wal(state_path);
    let tap_id = state.tap_id;
    let has_runtime_objects = !(state.groups.is_empty()
        && state.rules.is_empty()
        && state.qos_rules.is_empty()
        && state.mirror_rules.is_empty());
    let mut valid_rules: Vec<&crate::state::RuleInfo> = Vec::new();

    info!(
        state_path = %state_path,
        groups = state.groups.len(),
        rules = state.rules.len(),
        qos_rules = state.qos_rules.len(),
        mirror_rules = state.mirror_rules.len(),
        "replaying state into eBPF maps"
    );
    if !has_runtime_objects {
        info!(state_path = %state_path, "state has no groups or rules; replay will apply runtime config only");
    }
    for rule in &state.rules {
        match validate_policy_ports(rule.proto, rule.ports.as_deref()) {
            Ok(()) => valid_rules.push(rule),
            Err(e) => warn!(
                state_path = %state_path,
                src_id = rule.src_group_id,
                dst_id = rule.dst_group_id,
                proto = rule.proto,
                direction = rule.direction,
                error = %e,
                "skipping invalid persisted ACL rule during replay"
            ),
        }
    }

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
                for rule in &valid_rules {
                    if let (Some(idx), Some(ref ports)) = (rule.bitmap_idx, &rule.ports) {
                        let ports = ports.trim();
                        if !ports.is_empty()
                            && !ports.eq_ignore_ascii_case("all")
                            && !written_bitmaps.contains(&idx)
                        {
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
                for rule in &valid_rules {
                    let is_all_ports = match &rule.ports {
                        Some(p) => {
                            let p = p.trim();
                            p.is_empty() || p.eq_ignore_ascii_case("all")
                        }
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
        let preview = errors.iter().take(3).cloned().collect::<Vec<_>>().join("; ");
        let suffix = if errors.len() > 3 {
            format!("; ... {} more", errors.len() - 3)
        } else {
            String::new()
        };
        return Err(format!(
            "replay encountered {} errors: {}{}",
            errors.len(),
            preview,
            suffix
        ));
    }
    Ok(())
}

/// Replay snapshot + WAL directly into already pinned maps without loading a new eBPF object.
pub fn replay_state_to_pinned_maps(pin_path: &str, state_path: &str) -> Result<(), String> {
    let state = crate::wal::load_with_wal(state_path);
    let tap_id = state.tap_id;
    let runtime = TapMapRuntime::new(pin_path, tap_id);
    let has_runtime_objects = !(state.groups.is_empty()
        && state.rules.is_empty()
        && state.qos_rules.is_empty()
        && state.mirror_rules.is_empty());
    let mut valid_rules: Vec<&crate::state::RuleInfo> = Vec::new();

    info!(
        state_path = %state_path,
        pin_path = %pin_path,
        groups = state.groups.len(),
        rules = state.rules.len(),
        qos_rules = state.qos_rules.len(),
        mirror_rules = state.mirror_rules.len(),
        "replaying state into pinned maps"
    );
    if !has_runtime_objects {
        info!(state_path = %state_path, pin_path = %pin_path, "state has no groups or rules; replay will apply runtime config only");
    }
    for rule in &state.rules {
        match validate_policy_ports(rule.proto, rule.ports.as_deref()) {
            Ok(()) => valid_rules.push(rule),
            Err(e) => warn!(
                state_path = %state_path,
                pin_path = %pin_path,
                src_id = rule.src_group_id,
                dst_id = rule.dst_group_id,
                proto = rule.proto,
                direction = rule.direction,
                error = %e,
                "skipping invalid persisted ACL rule during pinned replay"
            ),
        }
    }

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
    for rule in &valid_rules {
        let ports = rule.ports.as_deref();
        let write_port_set = match (rule.bitmap_idx, ports) {
            (Some(idx), Some(ports)) => {
                let ports = ports.trim();
                !ports.is_empty()
                    && !ports.eq_ignore_ascii_case("all")
                    && written_bitmaps.insert(idx)
            }
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
