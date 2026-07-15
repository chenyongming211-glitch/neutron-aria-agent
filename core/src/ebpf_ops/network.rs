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

fn network_map_name(direction: &str, is_ipv6: bool, acl: bool) -> Result<&'static str, String> {
    match (direction, is_ipv6, acl) {
        ("src", false, false) => Ok("SRC_IPV4_TRIE"),
        ("dst", false, false) => Ok("DST_IPV4_TRIE"),
        ("src", true, false) => Ok("SRC_IPV6_TRIE"),
        ("dst", true, false) => Ok("DST_IPV6_TRIE"),
        ("src", false, true) => Ok("ACL_SRC_IPV4_TRIE"),
        ("dst", false, true) => Ok("ACL_DST_IPV4_TRIE"),
        ("src", true, true) => Ok("ACL_SRC_IPV6_TRIE"),
        ("dst", true, true) => Ok("ACL_DST_IPV6_TRIE"),
        _ => Err("direction must be 'src' or 'dst'".to_string()),
    }
}

pub fn add_network(
    direction: &str,
    cidr: &str,
    id: u32,
    runtime: TapMapRuntime<'_>,
    _ebpf_path: &str,
) -> Result<(), String> {
    add_network_impl(direction, cidr, id, runtime.tap_id, runtime.pin_path, false)
}

pub fn add_acl_network_in_bank(
    direction: &str,
    cidr: &str,
    id: u32,
    bank: u8,
    runtime: TapMapRuntime<'_>,
    _ebpf_path: &str,
) -> Result<(), String> {
    add_network_impl(
        direction,
        cidr,
        id,
        acl_banked_tap_id(runtime.tap_id, bank),
        runtime.pin_path,
        true,
    )
}

fn add_network_impl(
    direction: &str,
    cidr: &str,
    id: u32,
    lpm_tap_id: u32,
    pin_path: &str,
    acl: bool,
) -> Result<(), String> {
    let (ip, prefix_len) = parse_cidr(cidr)?;

    match ip {
        IpAddr::V4(v4) => {
            let map_name = network_map_name(direction, false, acl)?;
            let key = tap_lpm_key_v4(lpm_tap_id, v4.octets(), prefix_len);
            let mut lpm_map = open_pinned_lpm_v4(pin_path, map_name)?;
            lpm_map
                .insert(&key, &id, 0)
                .map_err(|e| format!("LPM insert error: {:?}", e))?;
            info!(cidr = %cidr, id, direction = %direction, map = %map_name, "added IPv4 network");
        }
        IpAddr::V6(v6) => {
            let map_name = network_map_name(direction, true, acl)?;
            let key = tap_lpm_key_v6(lpm_tap_id, v6.octets(), prefix_len);
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
    delete_network_impl(direction, cidr, runtime.tap_id, runtime.pin_path, false)
}

pub fn delete_acl_network_in_bank(
    direction: &str,
    cidr: &str,
    _id: u32,
    bank: u8,
    runtime: TapMapRuntime<'_>,
    _ebpf_path: &str,
) -> Result<(), String> {
    delete_network_impl(
        direction,
        cidr,
        acl_banked_tap_id(runtime.tap_id, bank),
        runtime.pin_path,
        true,
    )
}

fn delete_network_impl(
    direction: &str,
    cidr: &str,
    lpm_tap_id: u32,
    pin_path: &str,
    acl: bool,
) -> Result<(), String> {
    let (ip, prefix_len) = parse_cidr(cidr)?;

    match ip {
        IpAddr::V4(v4) => {
            let map_name = network_map_name(direction, false, acl)?;
            let key = tap_lpm_key_v4(lpm_tap_id, v4.octets(), prefix_len);
            let mut lpm_map = open_pinned_lpm_v4(pin_path, map_name)?;
            let context = format!("LPM delete {}", map_name);
            match classify_map_delete(lpm_map.remove(&key), &context)? {
                true => info!(cidr = %cidr, map = %map_name, "deleted IPv4 network"),
                false => info!(cidr = %cidr, map = %map_name, "IPv4 network not present during delete"),
            }
        }
        IpAddr::V6(v6) => {
            let map_name = network_map_name(direction, true, acl)?;
            let key = tap_lpm_key_v6(lpm_tap_id, v6.octets(), prefix_len);
            let mut lpm_map = open_pinned_lpm_v6(pin_path, map_name)?;
            let context = format!("LPM delete {}", map_name);
            match classify_map_delete(lpm_map.remove(&key), &context)? {
                true => info!(cidr = %cidr, map = %map_name, "deleted IPv6 network"),
                false => info!(cidr = %cidr, map = %map_name, "IPv6 network not present during delete"),
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::network_map_name;

    #[test]
    fn acl_network_maps_are_separate_from_shared_group_maps() {
        assert_eq!(
            network_map_name("src", false, false).unwrap(),
            "SRC_IPV4_TRIE"
        );
        assert_eq!(
            network_map_name("dst", false, false).unwrap(),
            "DST_IPV4_TRIE"
        );
        assert_eq!(
            network_map_name("src", true, false).unwrap(),
            "SRC_IPV6_TRIE"
        );
        assert_eq!(
            network_map_name("dst", true, false).unwrap(),
            "DST_IPV6_TRIE"
        );
        assert_eq!(
            network_map_name("src", false, true).unwrap(),
            "ACL_SRC_IPV4_TRIE"
        );
        assert_eq!(
            network_map_name("dst", false, true).unwrap(),
            "ACL_DST_IPV4_TRIE"
        );
        assert_eq!(
            network_map_name("src", true, true).unwrap(),
            "ACL_SRC_IPV6_TRIE"
        );
        assert_eq!(
            network_map_name("dst", true, true).unwrap(),
            "ACL_DST_IPV6_TRIE"
        );
    }
}
