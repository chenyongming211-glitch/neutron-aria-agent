use std::collections::HashSet;
use std::net::IpAddr;
use aya::maps::{HashMap, LpmTrie, MapData};
use aya::maps::lpm_trie::Key;
use crate::common::{PolicyKey, PolicyValue, PortKey, QosKey, QosConfig, CtConfig, FirewallConfig};
use crate::state::FirewallState;

/// 加载 eBPF 程序，并设置 pin 路径以复用已有的 map。
/// 仅用于 system_start / agent attach 中的初始加载和 replay。
pub fn load_bpf_with_pin(pin_path: &str, ebpf_path: &str) -> Result<aya::Ebpf, String> {
    let bpf_bytes = std::fs::read(ebpf_path).map_err(|e| format!("read ebpf: {}", e))?;
    let bpf = aya::EbpfLoader::new()
        .map_pin_path(pin_path)
        .load(&bpf_bytes)
        .map_err(|e| format!("load ebpf: {}", e))?;
    Ok(bpf)
}

/// 从 pin 路径直接打开已有的 map（不加载 eBPF 程序）
fn open_pinned_lpm_v4(pin_path: &str, map_name: &str) -> Result<LpmTrie<MapData, [u8; 4], u32>, String> {
    let map_path = format!("{}/{}", pin_path, map_name);
    let map_data = MapData::from_pin(&map_path)
        .map_err(|e| format!("open pinned map {}: {:?}", map_name, e))?;
    LpmTrie::try_from(aya::maps::Map::LpmTrie(map_data))
        .map_err(|e| format!("convert {} to LpmTrie: {:?}", map_name, e))
}

fn open_pinned_lpm_v6(pin_path: &str, map_name: &str) -> Result<LpmTrie<MapData, [u8; 16], u32>, String> {
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

pub fn parse_ports(ports_str: &str) -> Result<Vec<(u16, u16, u8)>, String> {
    let mut rules = Vec::new();
    for part in ports_str.split(',') {
        let parts: Vec<&str> = part.trim().split(':').collect();

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
            let action = parts.get(1).and_then(|a| a.parse().ok()).unwrap_or(1);
            if action > 1 {
                return Err(format!("Invalid action {}: must be 0 or 1", action));
            }
            let bpf_action = if action == 0 { 2 } else { 1 };
            rules.push((start, end, bpf_action));
        } else {
            let port = parts[0].trim().parse::<u16>().map_err(|_| "Invalid port")?;
            let action = parts.get(1).and_then(|a| a.parse().ok()).unwrap_or(1);
            if action > 1 {
                return Err(format!("Invalid action {}: must be 0 or 1", action));
            }
            let bpf_action = if action == 0 { 2 } else { 1 };
            rules.push((port, port, bpf_action));
        }
    }
    Ok(rules)
}

#[cfg(test)]
mod tests {
    use super::parse_ports;

    #[test]
    fn parse_ports_single_and_range() {
        let r = parse_ports("80,100-200:0").unwrap();
        assert_eq!(r.len(), 2);
        // 默认 action=1 → bpf_action=1
        assert_eq!(r[0], (80, 80, 1));
        // 显式 0 → bpf_action=2
        assert_eq!(r[1], (100, 200, 2));
    }

    #[test]
    fn parse_ports_rejects_invalid_formats() {
        assert!(parse_ports("200-100").is_err(), "start>end 应报错");
        assert!(parse_ports("80:2").is_err(), "action>1 应报错");
        assert!(parse_ports("bad").is_err(), "非数字端口应报错");
    }
}

pub fn add_network(direction: &str, cidr: &str, id: u32, pin_path: &str, _ebpf_path: &str) -> Result<(), String> {
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
            let key = Key::new(prefix_len as u32, v4.octets());
            let mut lpm_map = open_pinned_lpm_v4(pin_path, map_name)?;
            lpm_map.insert(&key, &id, 0)
                .map_err(|e| format!("LPM insert error: {:?}", e))?;
            println!("Added IPv4 network {} -> id {} (direction: {})", cidr, id, direction);
        }
        IpAddr::V6(v6) => {
            let map_name = match direction {
                "src" => "SRC_IPV6_TRIE",
                "dst" => "DST_IPV6_TRIE",
                _ => return Err("direction must be 'src' or 'dst'".to_string()),
            };
            let key = Key::new(prefix_len as u32, v6.octets());
            let mut lpm_map = open_pinned_lpm_v6(pin_path, map_name)?;
            lpm_map.insert(&key, &id, 0)
                .map_err(|e| format!("LPM insert error: {:?}", e))?;
            println!("Added IPv6 network {} -> id {} (direction: {})", cidr, id, direction);
        }
    }
    Ok(())
}

pub fn delete_network(direction: &str, cidr: &str, _id: u32, pin_path: &str, _ebpf_path: &str) -> Result<(), String> {
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
            let key = Key::new(prefix_len as u32, v4.octets());
            let mut lpm_map = open_pinned_lpm_v4(pin_path, map_name)?;
            match lpm_map.remove(&key) {
                Ok(()) => println!("Deleted IPv4 network {} from {}", cidr, map_name),
                Err(_) => println!("IPv4 network {} not found in {}, skipping", cidr, map_name),
            }
        }
        IpAddr::V6(v6) => {
            let map_name = match direction {
                "src" => "SRC_IPV6_TRIE",
                "dst" => "DST_IPV6_TRIE",
                _ => return Err("direction must be 'src' or 'dst'".to_string()),
            };
            let key = Key::new(prefix_len as u32, v6.octets());
            let mut lpm_map = open_pinned_lpm_v6(pin_path, map_name)?;
            match lpm_map.remove(&key) {
                Ok(()) => println!("Deleted IPv6 network {} from {}", cidr, map_name),
                Err(_) => println!("IPv6 network {} not found in {}, skipping", cidr, map_name),
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
    pin_path: &str,
    _ebpf_path: &str,
) -> Result<(), String> {
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
                let rules = parse_ports(ports_str)?;
                let mut port_pool = open_pinned_port_pool(pin_path)?;

                for (start, end, rule_action) in rules {
                    for port in start..=end {
                        let key = PortKey { idx, port, pad: 0 };
                        port_pool.insert(&key, &rule_action, 0)
                            .map_err(|e| format!("set port bitmap error: {:?}", e))?;
                    }
                    println!("  Set ports {}-{} to action {}", start, end, rule_action);
                }
            }
        }
    }

    let mut policy_table = open_pinned_policy_table(pin_path)?;

    let key = PolicyKey {
        src_id,
        dst_id,
        proto,
        direction,
        pad: [0; 2],
    };
    let value = PolicyValue {
        action,
        has_port_filter,
        pad1: [0; 2],
        bitmap_idx: bitmap_idx.unwrap_or(0),
    };
    policy_table.insert(&key, &value, 0)
        .map_err(|e| format!("insert error: {:?}", e))?;

    let dir_str = if direction == 1 { "egress" } else { "ingress" };
    println!("Added policy: src_id={}, dst_id={}, proto={}, action={}, direction={}, ports={:?}",
        src_id, dst_id, proto, action, dir_str, ports);
    Ok(())
}

/// 从内核 POLICY_TABLE 中删除指定策略条目
pub fn delete_policy(
    src_id: u32,
    dst_id: u32,
    proto: u8,
    direction: u8,
    pin_path: &str,
    _ebpf_path: &str,
) -> Result<(), String> {
    let prog_path = format!("{}/xdp_firewall", pin_path);
    if !std::path::Path::new(&prog_path).exists() {
        return Err("Firewall not started. Run 'system start' first.".to_string());
    }

    let mut policy_table = open_pinned_policy_table(pin_path)?;

    let key = PolicyKey {
        src_id,
        dst_id,
        proto,
        direction,
        pad: [0; 2],
    };
    policy_table.remove(&key)
        .map_err(|e| format!("remove policy error: {:?}", e))?;

    println!("Deleted policy: src_id={}, dst_id={}, proto={}, direction={}", src_id, dst_id, proto, direction);
    Ok(())
}

/// 删除指定 bitmap_idx 的所有端口条目。
pub fn delete_port_set(
    bitmap_idx: u32,
    ports_normalized: &str,
    pin_path: &str,
    _ebpf_path: &str,
) -> Result<(), String> {
    let prog_path = format!("{}/xdp_firewall", pin_path);
    if !std::path::Path::new(&prog_path).exists() {
        return Ok(()); // firewall not running, nothing to clean
    }

    let mut port_pool = open_pinned_port_pool(pin_path)?;

    let rules = parse_ports(ports_normalized)?;
    for (start, end, _) in rules {
        for port in start..=end {
            let key = PortKey { idx: bitmap_idx, port, pad: 0 };
            let _ = port_pool.remove(&key);
        }
    }

    Ok(())
}

/// All map names that need to be pinned
pub const ALL_MAP_NAMES: &[&str] = &[
    "SRC_IPV4_TRIE", "DST_IPV4_TRIE", "SRC_IPV6_TRIE", "DST_IPV6_TRIE",
    "POLICY_TABLE", "PORT_BITMAP_POOL",
    "CT_TABLE_V4", "CT_TABLE_V6", "CT_CONFIG",
    "RULE_STATS", "FLOW_STATS_V4", "FLOW_STATS_V6",
    "QOS_CONFIG", "QOS_TOKEN_BUCKET", "QOS_STATS",
    "GROUP_STATS",
    "MIRROR_POLICY", "MIRROR_GLOBAL", "MIRROR_STATS", "MIRROR_GLOBAL_STATS",
    "TCPRT_TABLE_V4", "TCPRT_TABLE_V6",
    "DROP_REASON_STATS",
    "TRACE_FILTER", "TRACE_LOG", "TRACE_SEQ",
    "FIREWALL_CONFIG",
];

/// 从 state.json 重放所有组和规则到已加载的 eBPF maps。
pub fn replay_state(bpf: &mut aya::Ebpf, state_path: &str) {
    let state_file = format!("{}/state.json", state_path);
    if !std::path::Path::new(&state_file).exists() {
        println!("No state file found, skipping replay");
        return;
    }

    let contents = match std::fs::read_to_string(&state_file) {
        Ok(c) if !c.is_empty() => c,
        Ok(_) => {
            println!("State file is empty, skipping replay");
            return;
        }
        Err(e) => {
            eprintln!("Warning: failed to read state file for replay: {}", e);
            return;
        }
    };

    let state: FirewallState = match serde_json::from_str(&contents) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Warning: failed to parse state file for replay: {}", e);
            return;
        }
    };

    if state.groups.is_empty() && state.rules.is_empty() && state.qos_rules.is_empty() && state.mirror_rules.is_empty() {
        println!("State is empty, nothing to replay");
        return;
    }

    println!("Replaying state: {} groups, {} rules, {} QoS rules...",
        state.groups.len(), state.rules.len(), state.qos_rules.len());

    let mut errors: Vec<String> = Vec::new();
    let mut group_count: u32 = 0;
    let mut rule_count: u32 = 0;
    let mut bitmap_count: u32 = 0;

    // 收集 IPv4 和 IPv6 条目，按 map 分批写入
    let mut src_ipv4: Vec<([u8; 4], u32, u32)> = Vec::new();
    let mut dst_ipv4: Vec<([u8; 4], u32, u32)> = Vec::new();
    let mut src_ipv6: Vec<([u8; 16], u32, u32)> = Vec::new();
    let mut dst_ipv6: Vec<([u8; 16], u32, u32)> = Vec::new();

    for (name, group) in &state.groups {
        for cidr in &group.cidrs {
            match parse_cidr(cidr) {
                Ok((IpAddr::V4(v4), prefix)) => {
                    src_ipv4.push((v4.octets(), prefix as u32, group.id));
                    dst_ipv4.push((v4.octets(), prefix as u32, group.id));
                    group_count += 1;
                }
                Ok((IpAddr::V6(v6), prefix)) => {
                    src_ipv6.push((v6.octets(), prefix as u32, group.id));
                    dst_ipv6.push((v6.octets(), prefix as u32, group.id));
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
            .and_then(|m| LpmTrie::<_, [u8; 4], u32>::try_from(m).map_err(|e| format!("{:?}", e)))
        {
            Ok(mut map) => {
                for (octets, prefix, id) in &src_ipv4 {
                    let key = Key::new(*prefix, *octets);
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
            .and_then(|m| LpmTrie::<_, [u8; 4], u32>::try_from(m).map_err(|e| format!("{:?}", e)))
        {
            Ok(mut map) => {
                for (octets, prefix, id) in &dst_ipv4 {
                    let key = Key::new(*prefix, *octets);
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
            .and_then(|m| LpmTrie::<_, [u8; 16], u32>::try_from(m).map_err(|e| format!("{:?}", e)))
        {
            Ok(mut map) => {
                for (octets, prefix, id) in &src_ipv6 {
                    let key = Key::new(*prefix, *octets);
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
            .and_then(|m| LpmTrie::<_, [u8; 16], u32>::try_from(m).map_err(|e| format!("{:?}", e)))
        {
            Ok(mut map) => {
                for (octets, prefix, id) in &dst_ipv6 {
                    let key = Key::new(*prefix, *octets);
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
                            match parse_ports(ports) {
                                Ok(port_rules) => {
                                    for (start, end, action) in port_rules {
                                        for port in start..=end {
                                            let key = PortKey { idx, port, pad: 0 };
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
                        src_id: rule.src_group_id,
                        dst_id: rule.dst_group_id,
                        proto: rule.proto,
                        direction: rule.direction,
                        pad: [0; 2],
                    };
                    let value = PolicyValue {
                        action: rule.action,
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
                    eprintln!("Warning: mirror target '{}' not found during replay: {}", mr.target_iface, e);
                    continue;
                }
            };
            if mr.is_global {
                global_rules.push((mr.direction, ifindex));
            } else {
                policy_rules.push((mr.src_group_id, mr.dst_group_id, mr.proto, mr.direction, ifindex));
            }
        }

        let mirror_errors = crate::mirror_ops::replay_mirror_rules(bpf, &policy_rules, &global_rules);
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

    println!(
        "Replay complete: {} group CIDRs, {} rules, {} port bitmaps, {} QoS rules, {} mirror rules written",
        group_count, rule_count, bitmap_count, state.qos_rules.len(), state.mirror_rules.len()
    );
    if !errors.is_empty() {
        eprintln!("Replay encountered {} errors:", errors.len());
        for err in &errors {
            eprintln!("  {}", err);
        }
    }
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
    for name in ALL_MAP_NAMES {
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

    println!("TC ingress attached to {} (link pinned)", iface);
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

    println!("TC egress attached to {} (link pinned)", iface);
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
    println!("FQ qdisc configured on {}", iface);
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
    pin_path: &str,
    conntrack_enabled: Option<bool>,
    monitoring_enabled: Option<bool>,
    acl_enabled: Option<bool>,
    qos_enabled: Option<bool>,
    mirror_enabled: Option<bool>,
    tcprt_enabled: Option<bool>,
) -> Result<(), String> {
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

    let cfg = FirewallConfig {
        conntrack_enabled: ct,
        monitoring_enabled: mon,
        num_cpus: num_cpus_val,
        qos_enabled: qos,
        acl_enabled: acl,
        mirror_enabled: mir,
        tcprt_enabled: tcprt,
    };
    map.insert(&0u32, &cfg, 0)
        .map_err(|e| format!("FIREWALL_CONFIG insert: {:?}", e))?;

    Ok(())
}

/// Read the current FIREWALL_CONFIG from pinned map.
pub fn read_firewall_config(pin_path: &str) -> Result<FirewallConfig, String> {
    let map_path = format!("{}/FIREWALL_CONFIG", pin_path);
    let map_data = MapData::from_pin(&map_path)
        .map_err(|e| format!("open FIREWALL_CONFIG: {:?}", e))?;
    let map = aya::maps::HashMap::<_, u32, FirewallConfig>::try_from(
        aya::maps::Map::HashMap(map_data)
    ).map_err(|e| format!("convert FIREWALL_CONFIG: {:?}", e))?;

    map.get(&0u32, 0)
        .map_err(|e| format!("read FIREWALL_CONFIG: {:?}", e))
}
