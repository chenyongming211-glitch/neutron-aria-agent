use std::collections::HashSet;
use std::fs;
use std::net::IpAddr;
use aya::maps::{HashMap, LpmTrie};
use aya::maps::lpm_trie::Key;
use tokio::signal::unix::{signal, SignalKind};
use crate::common::{PolicyKey, PolicyValue, PortKey};
use crate::state::FirewallState;

// 加载 eBPF 程序，并设置 pin 路径以复用已有的 map
fn load_bpf_with_pin(pin_path: &str, ebpf_path: &str) -> Result<aya::Ebpf, String> {
    let bpf_bytes = std::fs::read(ebpf_path).map_err(|e| format!("read ebpf: {}", e))?;
    let bpf = aya::EbpfLoader::new()
        .map_pin_path(pin_path)
        .load(&bpf_bytes)
        .map_err(|e| format!("load ebpf: {}", e))?;
    Ok(bpf)
}

fn parse_cidr(cidr: &str) -> Result<(IpAddr, u8), String> {
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

fn parse_ports(ports_str: &str) -> Result<Vec<(u16, u16, u8)>, String> {
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

pub async fn system_start(iface: &str, ebpf_path: &str, pin_path: &str, _max_port_policies: u32, state_path: &str) -> Result<(), String> {
    fs::create_dir_all(pin_path)
        .map_err(|e| format!("Failed to create pin directory: {}", e))?;

    println!("Loading eBPF from: {}", ebpf_path);
    let bpf_bytes = std::fs::read(ebpf_path).map_err(|e| format!("read ebpf: {}", e))?;
    let mut bpf = aya::EbpfLoader::new()
        .map_pin_path(pin_path)
        .load(&bpf_bytes)
        .map_err(|e| format!("load error: {:?}", e))?;

    println!("Attaching XDP to {}...", iface);
    let xdp_program = bpf
        .program_mut("xdp_firewall")
        .ok_or("XDP program not found")?;

    let xdp: &mut aya::programs::Xdp = xdp_program
        .try_into()
        .map_err(|e: aya::programs::ProgramError| format!("try_into error: {:?}", e))?;

    xdp.load().map_err(|e| format!("xdp.load error: {:?}", e))?;

    let link_id = xdp
        .attach(iface, aya::programs::XdpFlags::default())
        .map_err(|e| format!("attach error: {:?}", e))?;

    println!("XDP attached successfully (link_id: {:?})", link_id);

    // 保持 link 存活，但不再尝试 pin
    let _link = xdp.take_link(link_id)
        .map_err(|e| format!("take_link error: {:?}", e))?;

    // 将 maps 和 programs pin 到文件系统，供后续无状态 CLI 使用
    let map_names = ["SRC_IPV4_TRIE", "DST_IPV4_TRIE", "SRC_IPV6_TRIE", "DST_IPV6_TRIE", "POLICY_TABLE", "PORT_BITMAP_POOL"];
    for name in map_names {
        if let Some(map) = bpf.map_mut(name) {
            if let Err(e) = map.pin(format!("{}/{}", pin_path, name)) {
                eprintln!("Warning: failed to pin map {}: {}", name, e);
            }
        }
    }

    for (name, prog) in bpf.programs_mut() {
        prog.pin(format!("{}/{}", pin_path, name))
            .map_err(|e| format!("Failed to pin program {}: {:?}", name, e))?;
    }

    println!("eBPF system started successfully");
    println!("Pin path: {}", pin_path);

    // 从 state.json 重放状态到内核 maps
    replay_state(&mut bpf, state_path);

    println!("Firewall attached to {}. Waiting for stop signal...", iface);

    // 监听 SIGTERM 和 SIGINT 信号，实现优雅退出
    let mut term = signal(SignalKind::terminate())
        .map_err(|e| format!("failed to create signal handler: {}", e))?;
    let mut int = signal(SignalKind::interrupt())
        .map_err(|e| format!("failed to create signal handler: {}", e))?;

    tokio::select! {
        _ = term.recv() => println!("Received SIGTERM"),
        _ = int.recv() => println!("Received SIGINT"),
    }

    println!("Shutting down firewall, XDP detached automatically.");
    Ok(())
}

/// 从 state.json 重放所有组和规则到内核 maps。
/// 在 system_start 中 pin maps 完成后调用，复用已加载的 bpf 对象。
/// 采用容错策略：单条写入失败记录错误但继续重放。
fn replay_state(bpf: &mut aya::Ebpf, state_path: &str) {
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

    if state.groups.is_empty() && state.rules.is_empty() {
        println!("State is empty, nothing to replay");
        return;
    }

    println!("Replaying state: {} groups, {} rules...", state.groups.len(), state.rules.len());

    let mut errors: Vec<String> = Vec::new();
    let mut group_count: u32 = 0;
    let mut rule_count: u32 = 0;
    let mut bitmap_count: u32 = 0;

    // 收集 IPv4 和 IPv6 条目，按 map 分批写入
    let mut src_ipv4: Vec<([u8; 4], u32, u32)> = Vec::new(); // (octets, prefix, id)
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

    // 写 PORT_BITMAP_POOL — 按 bitmap_idx 去重，每个唯一位图只写一次
    {
        let mut written_bitmaps: HashSet<u32> = HashSet::new();
        match bpf.map_mut("PORT_BITMAP_POOL")
            .ok_or_else(|| "PORT_BITMAP_POOL not found".to_string())
            .and_then(|m| HashMap::<_, PortKey, u8>::try_from(m).map_err(|e| format!("{:?}", e)))
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
            .and_then(|m| HashMap::<_, PolicyKey, PolicyValue>::try_from(m).map_err(|e| format!("{:?}", e)))
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
                        pad: [0; 3],
                    };
                    let value = PolicyValue {
                        action: rule.action,
                        has_port_filter,
                        pad1: [0; 2],
                        bitmap_idx: rule.bitmap_idx.unwrap_or(0),
                    };
                    if let Err(e) = policy_table.insert(&key, &value, 0) {
                        errors.push(format!(
                            "POLICY_TABLE src={} dst={} proto={}: {:?}",
                            rule.src_group_id, rule.dst_group_id, rule.proto, e
                        ));
                    } else {
                        rule_count += 1;
                    }
                }
            }
            Err(e) => errors.push(format!("POLICY_TABLE: {}", e)),
        }
    }

    // 打印重放结果
    println!(
        "Replay complete: {} group CIDRs, {} rules, {} port bitmaps written",
        group_count, rule_count, bitmap_count
    );
    if !errors.is_empty() {
        eprintln!("Replay encountered {} errors:", errors.len());
        for err in &errors {
            eprintln!("  {}", err);
        }
    }
}

pub async fn system_stop(pin_path: &str) -> Result<(), String> {
    // 尝试从所有网卡分离 XDP 程序
    let output = std::process::Command::new("ip")
        .args(["link", "show"])
        .output()
        .map_err(|e| format!("Failed to run ip link show: {}", e))?;
    let link_output = String::from_utf8_lossy(&output.stdout);
    for line in link_output.lines() {
        if line.contains("xdp") {
            // 提取网卡名（格式: "N: ifname: <flags>"）
            if let Some(iface) = line.split(':').nth(1).map(|s| s.trim()) {
                let _ = std::process::Command::new("ip")
                    .args(["link", "set", "dev", iface, "xdp", "off"])
                    .output();
                println!("Detached XDP from {}", iface);
            }
        }
    }

    if std::path::Path::new(pin_path).exists() {
        fs::remove_dir_all(pin_path)
            .map_err(|e| format!("Failed to remove pin directory: {}", e))?;
        println!("Removed pinned maps and programs from {}", pin_path);
    }
    println!("eBPF system stopped");
    Ok(())
}

pub async fn add_network(direction: &str, cidr: &str, id: u32, pin_path: &str, ebpf_path: &str) -> Result<(), String> {
    let prog_path = format!("{}/xdp_firewall", pin_path);
    if !std::path::Path::new(&prog_path).exists() {
        return Err("Firewall not started. Run 'system start' first.".to_string());
    }

    let mut bpf = load_bpf_with_pin(pin_path, ebpf_path)?;

    let (ip, prefix_len) = parse_cidr(cidr)?;

    match ip {
        IpAddr::V4(v4) => {
            let map_name = match direction {
                "src" => "SRC_IPV4_TRIE",
                "dst" => "DST_IPV4_TRIE",
                _ => return Err("direction must be 'src' or 'dst'".to_string()),
            };
            let key = Key::new(prefix_len as u32, v4.octets());
            let mut lpm_map: LpmTrie<_, [u8; 4], u32> = bpf.map_mut(map_name)
                .ok_or(format!("map {} not found", map_name))?
                .try_into()
                .map_err(|e| format!("convert to LpmTrie: {:?}", e))?;
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
            let mut lpm_map: LpmTrie<_, [u8; 16], u32> = bpf.map_mut(map_name)
                .ok_or(format!("map {} not found", map_name))?
                .try_into()
                .map_err(|e| format!("convert to LpmTrie: {:?}", e))?;
            lpm_map.insert(&key, &id, 0)
                .map_err(|e| format!("LPM insert error: {:?}", e))?;
            println!("Added IPv6 network {} -> id {} (direction: {})", cidr, id, direction);
        }
    }
    Ok(())
}

pub async fn delete_network(direction: &str, cidr: &str, _id: u32, pin_path: &str, ebpf_path: &str) -> Result<(), String> {
    let prog_path = format!("{}/xdp_firewall", pin_path);
    if !std::path::Path::new(&prog_path).exists() {
        return Err("Firewall not started. Run 'system start' first.".to_string());
    }

    let mut bpf = load_bpf_with_pin(pin_path, ebpf_path)?;

    let (ip, prefix_len) = parse_cidr(cidr)?;

    match ip {
        IpAddr::V4(v4) => {
            let map_name = match direction {
                "src" => "SRC_IPV4_TRIE",
                "dst" => "DST_IPV4_TRIE",
                _ => return Err("direction must be 'src' or 'dst'".to_string()),
            };
            let key = Key::new(prefix_len as u32, v4.octets());
            let mut lpm_map: LpmTrie<_, [u8; 4], u32> = bpf.map_mut(map_name)
                .ok_or(format!("map {} not found", map_name))?
                .try_into()
                .map_err(|e| format!("convert to LpmTrie: {:?}", e))?;
            match lpm_map.remove(&key) {
                Ok(()) => println!("Deleted IPv4 network {} from {}", cidr, map_name),
                Err(e) => {
                    let err_str = format!("{:?}", e);
                    if err_str.contains("No such file or directory") || err_str.contains("os error 2") {
                        println!("IPv4 network {} not found in {}, skipping", cidr, map_name);
                    } else {
                        return Err(format!("LPM remove error: {:?}", e));
                    }
                }
            }
        }
        IpAddr::V6(v6) => {
            let map_name = match direction {
                "src" => "SRC_IPV6_TRIE",
                "dst" => "DST_IPV6_TRIE",
                _ => return Err("direction must be 'src' or 'dst'".to_string()),
            };
            let key = Key::new(prefix_len as u32, v6.octets());
            let mut lpm_map: LpmTrie<_, [u8; 16], u32> = bpf.map_mut(map_name)
                .ok_or(format!("map {} not found", map_name))?
                .try_into()
                .map_err(|e| format!("convert to LpmTrie: {:?}", e))?;
            match lpm_map.remove(&key) {
                Ok(()) => println!("Deleted IPv6 network {} from {}", cidr, map_name),
                Err(e) => {
                    let err_str = format!("{:?}", e);
                    if err_str.contains("No such file or directory") || err_str.contains("os error 2") {
                        println!("IPv6 network {} not found in {}, skipping", cidr, map_name);
                    } else {
                        return Err(format!("LPM remove error: {:?}", e));
                    }
                }
            }
        }
    }
    Ok(())
}

pub async fn add_policy(
    src_id: u32,
    dst_id: u32,
    proto: u8,
    action: u8,
    ports: Option<&str>,
    bitmap_idx: Option<u32>,
    is_new_port_set: bool,
    pin_path: &str,
    ebpf_path: &str,
) -> Result<(), String> {
    let prog_path = format!("{}/xdp_firewall", pin_path);
    if !std::path::Path::new(&prog_path).exists() {
        return Err("Firewall not started. Run 'system start' first.".to_string());
    }

    let mut bpf = load_bpf_with_pin(pin_path, ebpf_path)?;

    let is_all_ports = matches!(ports, Some("all") | Some("") | None);
    let has_port_filter = (ports.is_some() && !is_all_ports) as u8;

    if is_new_port_set {
        if let Some(idx) = bitmap_idx {
            let ports_str = ports.unwrap_or("");
            if !ports_str.is_empty() {
                let rules = parse_ports(ports_str)?;
                let mut port_pool: HashMap<_, PortKey, u8> = bpf.map_mut("PORT_BITMAP_POOL")
                    .ok_or("PORT_BITMAP_POOL not found")?
                    .try_into()
                    .map_err(|e| format!("convert to HashMap: {:?}", e))?;

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

    let mut policy_table: aya::maps::HashMap<_, PolicyKey, PolicyValue> = bpf.map_mut("POLICY_TABLE")
        .ok_or("POLICY_TABLE not found")?
        .try_into()
        .map_err(|e| format!("convert to HashMap: {:?}", e))?;

    let key = PolicyKey {
        src_id,
        dst_id,
        proto,
        pad: [0; 3],
    };
    let value = PolicyValue {
        action,
        has_port_filter,
        pad1: [0; 2],
        bitmap_idx: bitmap_idx.unwrap_or(0),
    };
    policy_table.insert(&key, &value, 0)
        .map_err(|e| format!("insert error: {:?}", e))?;

    println!("Added policy: src_id={}, dst_id={}, proto={}, action={}, ports={:?}",
        src_id, dst_id, proto, action, ports);
    Ok(())
}

pub async fn show_stats(pin_path: &str, state_path: &str) -> Result<(), String> {
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

    // Groups
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

    // Policies
    println!("Policies: {}", state.rules.len());
    let allow_count = state.rules.iter().filter(|r| r.action == 0).count();
    let drop_count = state.rules.iter().filter(|r| r.action == 1).count();
    println!("  Allow: {}, Drop: {}", allow_count, drop_count);
    let with_ports = state.rules.iter().filter(|r| r.bitmap_idx.is_some()).count();
    println!("  With port filter: {}", with_ports);
    println!();

    // Port sets
    println!("Port bitmap pool: {}/{} slots used", state.port_sets.len(), state.max_port_policies);
    println!("  Free recycled slots: {}", state.free_bitmap_indices.len());
    println!();

    // Pinned maps
    let map_names = ["SRC_IPV4_TRIE", "DST_IPV4_TRIE", "SRC_IPV6_TRIE", "DST_IPV6_TRIE", "POLICY_TABLE", "PORT_BITMAP_POOL"];
    println!("Kernel maps:");
    for name in map_names {
        let path = format!("{}/{}", pin_path, name);
        let status = if std::path::Path::new(&path).exists() { "pinned" } else { "missing" };
        println!("  {}: {}", name, status);
    }

    Ok(())
}

/// 删除指定 bitmap_idx 的所有端口条目。
/// ports_normalized 格式: "80:1,443:1,8000-9000:2"
#[allow(dead_code)]
pub fn delete_port_set(
    bitmap_idx: u32,
    ports_normalized: &str,
    pin_path: &str,
    ebpf_path: &str,
) -> Result<(), String> {
    let prog_path = format!("{}/xdp_firewall", pin_path);
    if !std::path::Path::new(&prog_path).exists() {
        return Ok(()); // firewall not running, nothing to clean
    }

    let mut bpf = load_bpf_with_pin(pin_path, ebpf_path)?;
    let mut port_pool: HashMap<_, PortKey, u8> = bpf.map_mut("PORT_BITMAP_POOL")
        .ok_or("PORT_BITMAP_POOL not found")?
        .try_into()
        .map_err(|e| format!("convert to HashMap: {:?}", e))?;

    let rules = parse_ports(ports_normalized)?;
    for (start, end, _) in rules {
        for port in start..=end {
            let key = PortKey { idx: bitmap_idx, port, pad: 0 };
            let _ = port_pool.remove(&key);
        }
    }

    Ok(())
}
