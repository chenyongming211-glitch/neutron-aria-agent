use std::fs;
use std::net::IpAddr;
use aya::maps::{Array, HashMap, LpmTrie};
use aya::maps::lpm_trie::Key;
use aya::Pod;
use tokio::signal::unix::{signal, SignalKind};
use crate::common::{PolicyKey, PolicyValue};

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

pub async fn system_start(iface: &str, ebpf_path: &str, pin_path: &str) -> Result<(), String> {
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
        if let Some(mut map) = bpf.map_mut(name) {
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

pub async fn system_stop(pin_path: &str) -> Result<(), String> {
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
            lpm_map.remove(&key).map_err(|e| format!("LPM remove error: {:?}", e))?;
            println!("Deleted IPv4 network {} from {}", cidr, map_name);
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
            lpm_map.remove(&key).map_err(|e| format!("LPM remove error: {:?}", e))?;
            println!("Deleted IPv6 network {} from {}", cidr, map_name);
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

    if let Some(idx) = bitmap_idx {
        let ports_str = ports.unwrap_or("");
        if !ports_str.is_empty() {
            let rules = parse_ports(ports_str)?;
            let mut port_pool: Array<_, u8> = bpf.map_mut("PORT_BITMAP_POOL")
                .ok_or("PORT_BITMAP_POOL not found")?
                .try_into()
                .map_err(|e| format!("convert to Array: {:?}", e))?;

            for (start, end, rule_action) in rules {
                for port in start..=end {
                    let index = idx * 65536 + port as u32;
                    port_pool.set(index, rule_action, 0)
                        .map_err(|e| format!("set port bitmap error: {:?}", e))?;
                }
                println!("  Set ports {}-{} to action {}", start, end, rule_action);
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

pub async fn show_stats(pin_path: &str) -> Result<(), String> {
    if !std::path::Path::new(pin_path).exists() {
        return Err("Firewall not started. Run 'system start' first.".to_string());
    }
    println!("Stats not implemented yet");
    Ok(())
}