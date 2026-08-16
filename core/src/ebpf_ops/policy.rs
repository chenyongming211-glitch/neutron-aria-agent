use super::*;

fn encode_port_action(action: u8) -> Result<u8, String> {
    match action {
        0 => Ok(2),
        1 => Ok(1),
        _ => Err(format!("Invalid action {}: must be 0 or 1", action)),
    }
}

pub(crate) fn stored_policy_action(action: u8, has_port_filter: bool) -> u8 {
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
                return Err(format!(
                    "Invalid port range: {}-{} (start must be <= end)",
                    start, end
                ));
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

fn policy_key_for_bank(
    tap_id: u32,
    src_id: u32,
    dst_id: u32,
    proto: u8,
    direction: u8,
    bank: u8,
) -> PolicyKey {
    PolicyKey {
        tap_id,
        src_id,
        dst_id,
        proto,
        direction,
        bank: normalize_acl_bank(bank),
        ip_family: IP_FAMILY_V4,
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
    add_policy_in_bank(
        src_id,
        dst_id,
        proto,
        action,
        ports,
        bitmap_idx,
        is_new_port_set,
        direction,
        0,
        runtime,
        _ebpf_path,
    )
}

pub fn add_policy_in_bank(
    src_id: u32,
    dst_id: u32,
    proto: u8,
    action: u8,
    ports: Option<&str>,
    bitmap_idx: Option<u32>,
    is_new_port_set: bool,
    direction: u8,
    bank: u8,
    runtime: TapMapRuntime<'_>,
    _ebpf_path: &str,
) -> Result<(), String> {
    let pin_path = runtime.pin_path;
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
                        let key = PortKey {
                            tap_id: runtime.tap_id,
                            idx,
                            port,
                            pad: 0,
                        };
                        if let Err(e) = port_pool.insert(&key, &rule_action, 0) {
                            let mut error = format!("set port bitmap error: {:?}", e);
                            if let Err(cleanup_error) =
                                delete_port_set(idx, ports_str, runtime, _ebpf_path)
                            {
                                error.push_str(&format!(
                                    "; rollback port bitmap {} failed: {}",
                                    idx, cleanup_error
                                ));
                            }
                            return Err(error);
                        }
                    }
                    info!(
                        bitmap_idx = idx,
                        start_port = start,
                        end_port = end,
                        rule_action,
                        "programmed port bitmap range"
                    );
                }
            }
        }
    }

    let mut policy_table = open_pinned_policy_table(pin_path)?;

    let bank = normalize_acl_bank(bank);
    let key = policy_key_for_bank(runtime.tap_id, src_id, dst_id, proto, direction, bank);
    let value = PolicyValue {
        action: stored_policy_action(action, has_port_filter != 0),
        has_port_filter,
        pad1: [0; 2],
        bitmap_idx: bitmap_idx.unwrap_or(0),
    };
    if let Err(e) = policy_table.insert(&key, &value, 0) {
        let mut error = format!("insert error: {:?}", e);
        if is_new_port_set {
            if let (Some(idx), Some(ports_str)) = (bitmap_idx, ports) {
                if let Err(cleanup_error) =
                    delete_port_set(idx, ports_str, runtime, _ebpf_path)
                {
                    error.push_str(&format!(
                        "; rollback port bitmap {} failed: {}",
                        idx, cleanup_error
                    ));
                }
            }
        }
        return Err(error);
    }

    let dir_str = if direction == 1 { "egress" } else { "ingress" };
    info!(
        src_id,
        dst_id,
        proto,
        action,
        direction = %dir_str,
        bank,
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

pub fn delete_policy(
    src_id: u32,
    dst_id: u32,
    proto: u8,
    direction: u8,
    runtime: TapMapRuntime<'_>,
    _ebpf_path: &str,
) -> Result<(), String> {
    delete_policy_in_bank(src_id, dst_id, proto, direction, 0, runtime, _ebpf_path)
}

pub fn delete_policy_in_bank(
    src_id: u32,
    dst_id: u32,
    proto: u8,
    direction: u8,
    bank: u8,
    runtime: TapMapRuntime<'_>,
    _ebpf_path: &str,
) -> Result<(), String> {
    let pin_path = runtime.pin_path;
    let mut policy_table = open_pinned_policy_table(pin_path)?;

    let bank = normalize_acl_bank(bank);
    let key = policy_key_for_bank(runtime.tap_id, src_id, dst_id, proto, direction, bank);
    match classify_map_delete(policy_table.remove(&key), "remove policy")? {
        true => info!(src_id, dst_id, proto, direction, bank, "deleted policy"),
        false => info!(src_id, dst_id, proto, direction, bank, "policy not present during delete"),
    }
    Ok(())
}

pub fn delete_port_set(
    bitmap_idx: u32,
    ports_normalized: &str,
    runtime: TapMapRuntime<'_>,
    _ebpf_path: &str,
) -> Result<(), String> {
    let pin_path = runtime.pin_path;
    let mut port_pool = open_pinned_port_pool(pin_path)?;

    let keys = parse_normalized_ports(ports_normalized)?
        .into_iter()
        .flat_map(|(start, end, _)| {
            (start..=end).map(move |port| PortKey {
                tap_id: runtime.tap_id,
                idx: bitmap_idx,
                port,
                pad: 0,
            })
        });
    execute_map_delete_batch(
        keys,
        |key| port_pool.remove(&key),
        "remove port bitmap entry",
    )
}

#[cfg(test)]
mod tests {
    use super::{parse_normalized_ports, parse_ports, policy_key_for_bank, stored_policy_action};
    use crate::common::IP_FAMILY_V4;

    #[test]
    fn parse_ports_inherits_rule_action_for_implicit_entries() {
        let r = parse_ports("80,100-200:0", 1).unwrap();
        assert_eq!(r.len(), 2);
        assert_eq!(r[0], (80, 80, 1));
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

    #[test]
    fn policy_key_for_bank_keeps_default_api_on_primary_bank() {
        let key = policy_key_for_bank(9, 10, 11, 6, 1, 1);
        assert_eq!(key.tap_id, 9);
        assert_eq!(key.src_id, 10);
        assert_eq!(key.dst_id, 11);
        assert_eq!(key.proto, 6);
        assert_eq!(key.direction, 1);
        assert_eq!(key.bank, 1);
        assert_eq!(key.ip_family, IP_FAMILY_V4);

        let normalized = policy_key_for_bank(9, 10, 11, 6, 1, 42);
        assert_eq!(normalized.bank, 0);
    }
}
