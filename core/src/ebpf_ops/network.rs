use super::*;

pub fn parse_cidr(cidr: &str) -> Result<(IpAddr, u8), String> {
    let parts: Vec<&str> = cidr.split('/').collect();
    if parts.len() != 2 {
        return Err("Invalid CIDR format, expected: x.x.x.x/yy or ipv6/prefix".to_string());
    }
    let ip: IpAddr = parts[0]
        .parse()
        .map_err(|e| format!("Invalid IP: {:?}", e))?;
    let prefix: u8 = parts[1]
        .parse()
        .map_err(|e| format!("Invalid prefix: {:?}", e))?;
    match ip {
        IpAddr::V4(_) if prefix > 32 => Err("IPv4 prefix must be <= 32".to_string()),
        IpAddr::V6(_) if prefix > 128 => Err("IPv6 prefix must be <= 128".to_string()),
        _ => Ok((ip, prefix)),
    }
}

pub fn add_network(
    direction: &str,
    cidr: &str,
    id: u32,
    runtime: TapMapRuntime<'_>,
    _ebpf_path: &str,
) -> Result<(), String> {
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
            lpm_map
                .insert(&key, &id, 0)
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
            lpm_map
                .insert(&key, &id, 0)
                .map_err(|e| format!("LPM insert error: {:?}", e))?;
            info!(cidr = %cidr, id, direction = %direction, map = %map_name, "added IPv6 network");
        }
    }
    Ok(())
}

pub fn delete_network(
    direction: &str,
    cidr: &str,
    _id: u32,
    runtime: TapMapRuntime<'_>,
    _ebpf_path: &str,
) -> Result<(), String> {
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
