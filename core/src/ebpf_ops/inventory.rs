use super::*;

fn summarize_entries(entries: &BTreeSet<String>) -> String {
    if entries.is_empty() {
        return "none".to_string();
    }
    entries
        .iter()
        .take(3)
        .cloned()
        .collect::<Vec<_>>()
        .join("; ")
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
        qos_enabled: if state.qos_enabled && !state.qos_rules.is_empty() {
            1
        } else {
            0
        },
        mirror_enabled: if state.mirror_enabled && !state.mirror_rules.is_empty() {
            1
        } else {
            0
        },
        tcprt_enabled: if state.tcprt_enabled { 1 } else { 0 },
        acl_active_bank: 0,
        acl_ingress_hook: ACL_INGRESS_HOOK_XDP,
    };
    let tap_config_map = open_pinned_tap_config(pin_path)?;
    let actual_tap_config = tap_config_map
        .get(&tap_id, 0)
        .map_err(|e| format!("read TAP_CONFIG_MAP for tap_id {}: {:?}", tap_id, e))?;
    let active_acl_bank = normalize_acl_bank(actual_tap_config.acl_active_bank);
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
            let (ip, prefix) =
                parse_cidr(cidr).map_err(|e| format!("group '{}' cidr '{}': {}", name, cidr, e))?;
            match ip {
                IpAddr::V4(v4) => {
                    expected_src_ipv4.insert(format_lpm_entry_v4(
                        &tap_lpm_key_v4(tap_id, v4.octets(), prefix),
                        group.id,
                    ));
                    expected_dst_ipv4.insert(format_lpm_entry_v4(
                        &tap_lpm_key_v4(tap_id, v4.octets(), prefix),
                        group.id,
                    ));
                }
                IpAddr::V6(v6) => {
                    expected_src_ipv6.insert(format_lpm_entry_v6(
                        &tap_lpm_key_v6(tap_id, v6.octets(), prefix),
                        group.id,
                    ));
                    expected_dst_ipv6.insert(format_lpm_entry_v6(
                        &tap_lpm_key_v6(tap_id, v6.octets(), prefix),
                        group.id,
                    ));
                }
            }
        }
    }

    validate_entry_set(
        "SRC_IPV4_TRIE",
        tap_id,
        expected_src_ipv4.clone(),
        collect_lpm_entries_v4(pin_path, "SRC_IPV4_TRIE", tap_id)?,
    )?;
    validate_entry_set(
        "DST_IPV4_TRIE",
        tap_id,
        expected_dst_ipv4.clone(),
        collect_lpm_entries_v4(pin_path, "DST_IPV4_TRIE", tap_id)?,
    )?;
    validate_entry_set(
        "SRC_IPV6_TRIE",
        tap_id,
        expected_src_ipv6.clone(),
        collect_lpm_entries_v6(pin_path, "SRC_IPV6_TRIE", tap_id)?,
    )?;
    validate_entry_set(
        "DST_IPV6_TRIE",
        tap_id,
        expected_dst_ipv6.clone(),
        collect_lpm_entries_v6(pin_path, "DST_IPV6_TRIE", tap_id)?,
    )?;
    let active_acl_lpm_tap_id = acl_banked_tap_id(tap_id, active_acl_bank);
    validate_entry_set(
        "ACL_SRC_IPV4_TRIE",
        active_acl_lpm_tap_id,
        expected_src_ipv4.clone(),
        collect_lpm_entries_v4(pin_path, "ACL_SRC_IPV4_TRIE", active_acl_lpm_tap_id)?,
    )?;
    validate_entry_set(
        "ACL_DST_IPV4_TRIE",
        active_acl_lpm_tap_id,
        expected_dst_ipv4.clone(),
        collect_lpm_entries_v4(pin_path, "ACL_DST_IPV4_TRIE", active_acl_lpm_tap_id)?,
    )?;
    validate_entry_set(
        "ACL_SRC_IPV6_TRIE",
        active_acl_lpm_tap_id,
        expected_src_ipv6.clone(),
        collect_lpm_entries_v6(pin_path, "ACL_SRC_IPV6_TRIE", active_acl_lpm_tap_id)?,
    )?;
    validate_entry_set(
        "ACL_DST_IPV6_TRIE",
        active_acl_lpm_tap_id,
        expected_dst_ipv6.clone(),
        collect_lpm_entries_v6(pin_path, "ACL_DST_IPV6_TRIE", active_acl_lpm_tap_id)?,
    )?;

    let mut expected_policy = BTreeSet::new();
    let mut expected_ports = BTreeSet::new();
    for rule in &state.rules {
        let ports = rule.ports.as_deref();
        let is_all_ports = match ports {
            Some(p) => {
                let p = p.trim();
                p.is_empty() || p.eq_ignore_ascii_case("all")
            }
            None => true,
        };
        let has_port_filter = (ports.is_some() && !is_all_ports) as u8;
        let policy_key = PolicyKey {
            tap_id,
            src_id: rule.src_group_id,
            dst_id: rule.dst_group_id,
            proto: rule.proto,
            direction: rule.direction,
            bank: active_acl_bank,
            pad: [0; 1],
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
                        let key = PortKey {
                            tap_id,
                            idx,
                            port,
                            pad: 0,
                        };
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

    let expected_qos: BTreeSet<String> = state
        .qos_rules
        .iter()
        .map(|rule| {
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
        })
        .collect();
    let actual_qos: BTreeSet<String> = crate::qos_ops::list_qos_rules(runtime)?
        .into_iter()
        .map(|(key, value)| format!("{:?}=>{:?}", key, value))
        .collect();
    validate_entry_set("QOS_CONFIG", tap_id, expected_qos, actual_qos)?;

    let mut expected_policy_mirror = BTreeSet::new();
    let mut expected_global_mirror = BTreeSet::new();
    for rule in &state.mirror_rules {
        let target_ifindex =
            crate::mirror_ops::resolve_ifindex(&rule.target_iface).map_err(|e| {
                format!(
                    "resolve mirror target '{}' for validation: {}",
                    rule.target_iface, e
                )
            })?;
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

pub const NETWORK_MAP_NAMES: &[&str] = &[
    "IFACE_CTX_MAP",
    "TAP_CONFIG_MAP",
    "SRC_IPV4_TRIE",
    "DST_IPV4_TRIE",
    "SRC_IPV6_TRIE",
    "DST_IPV6_TRIE",
    "ACL_SRC_IPV4_TRIE",
    "ACL_DST_IPV4_TRIE",
    "ACL_SRC_IPV6_TRIE",
    "ACL_DST_IPV6_TRIE",
    "POLICY_TABLE",
    "PORT_BITMAP_POOL",
    "CT_TABLE_V4",
    "CT_TABLE_V6",
    "CT_CONFIG",
    "CT_CONTRACT_STATS",
    "RULE_STATS",
    "FLOW_STATS_V4",
    "FLOW_STATS_V6",
    "QOS_CONFIG",
    "QOS_TOKEN_BUCKET",
    "QOS_STATS",
    "GROUP_STATS",
    "MIRROR_POLICY",
    "MIRROR_GLOBAL",
    "MIRROR_STATS",
    "MIRROR_GLOBAL_STATS",
    "TCPRT_TABLE_V4",
    "TCPRT_TABLE_V6",
    "DROP_REASON_STATS",
    "TRACE_FILTER",
    "TRACE_LOG",
    "TRACE_LOG_V6",
    "TRACE_SEQ",
    "TRACE_EVENTS",
    "FIREWALL_CONFIG",
];

pub const CRITICAL_NETWORK_MAP_NAMES: &[&str] = &[
    "IFACE_CTX_MAP",
    "TAP_CONFIG_MAP",
    "SRC_IPV4_TRIE",
    "DST_IPV4_TRIE",
    "SRC_IPV6_TRIE",
    "DST_IPV6_TRIE",
    "ACL_SRC_IPV4_TRIE",
    "ACL_DST_IPV4_TRIE",
    "ACL_SRC_IPV6_TRIE",
    "ACL_DST_IPV6_TRIE",
    "POLICY_TABLE",
    "PORT_BITMAP_POOL",
    "CT_TABLE_V4",
    "CT_TABLE_V6",
    "CT_CONFIG",
    "QOS_CONFIG",
    "QOS_TOKEN_BUCKET",
    "MIRROR_POLICY",
    "MIRROR_GLOBAL",
    "TCPRT_TABLE_V4",
    "TCPRT_TABLE_V6",
    "TRACE_FILTER",
    "TRACE_SEQ",
    "FIREWALL_CONFIG",
];

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum TraceMapMode {
    Legacy,
    Stream,
}

pub const STREAM_CRITICAL_NETWORK_MAP_NAMES: &[&str] = &[
    "IFACE_CTX_MAP",
    "TAP_CONFIG_MAP",
    "SRC_IPV4_TRIE",
    "DST_IPV4_TRIE",
    "SRC_IPV6_TRIE",
    "DST_IPV6_TRIE",
    "ACL_SRC_IPV4_TRIE",
    "ACL_DST_IPV4_TRIE",
    "ACL_SRC_IPV6_TRIE",
    "ACL_DST_IPV6_TRIE",
    "POLICY_TABLE",
    "PORT_BITMAP_POOL",
    "CT_TABLE_V4",
    "CT_TABLE_V6",
    "CT_CONFIG",
    "QOS_CONFIG",
    "QOS_TOKEN_BUCKET",
    "MIRROR_POLICY",
    "MIRROR_GLOBAL",
    "TCPRT_TABLE_V4",
    "TCPRT_TABLE_V6",
    "TRACE_FILTER",
    "TRACE_SEQ",
    "TRACE_EVENTS",
    "FIREWALL_CONFIG",
];

pub fn critical_network_map_names(trace_mode: TraceMapMode) -> &'static [&'static str] {
    match trace_mode {
        TraceMapMode::Legacy => CRITICAL_NETWORK_MAP_NAMES,
        TraceMapMode::Stream => STREAM_CRITICAL_NETWORK_MAP_NAMES,
    }
}

pub const SSL_MAP_NAMES: &[&str] = &[
    "SSL_HANDSHAKE_SCRATCH",
    "SSL_CONN_TABLE",
    "SSL_SNI_TABLE",
    "SSL_SEQ",
    "SSL_HTTP_PARSE_BUF",
    "SSL_HTTP_SCRATCH",
    "SSL_HTTP_SCRATCH_BUF",
    "SSL_READ_SCRATCH",
    "SSL_HTTP_TABLE",
    "SSL_HTTP_SEQ",
    "SSL_HTTP_VALUE_BUF",
    "SSL_GLOBAL_CONFIG",
    "SSL_ERROR_TABLE",
    "SSL_ERROR_SEQ",
    "SSL_WRITE_SCRATCH",
];

pub const ALL_MAP_NAMES: &[&str] = &[
    "IFACE_CTX_MAP",
    "TAP_CONFIG_MAP",
    "SRC_IPV4_TRIE",
    "DST_IPV4_TRIE",
    "SRC_IPV6_TRIE",
    "DST_IPV6_TRIE",
    "ACL_SRC_IPV4_TRIE",
    "ACL_DST_IPV4_TRIE",
    "ACL_SRC_IPV6_TRIE",
    "ACL_DST_IPV6_TRIE",
    "POLICY_TABLE",
    "PORT_BITMAP_POOL",
    "CT_TABLE_V4",
    "CT_TABLE_V6",
    "CT_CONFIG",
    "CT_CONTRACT_STATS",
    "RULE_STATS",
    "FLOW_STATS_V4",
    "FLOW_STATS_V6",
    "QOS_CONFIG",
    "QOS_TOKEN_BUCKET",
    "QOS_STATS",
    "GROUP_STATS",
    "MIRROR_POLICY",
    "MIRROR_GLOBAL",
    "MIRROR_STATS",
    "MIRROR_GLOBAL_STATS",
    "TCPRT_TABLE_V4",
    "TCPRT_TABLE_V6",
    "DROP_REASON_STATS",
    "TRACE_FILTER",
    "TRACE_LOG",
    "TRACE_LOG_V6",
    "TRACE_SEQ",
    "TRACE_EVENTS",
    "FIREWALL_CONFIG",
    "SSL_HANDSHAKE_SCRATCH",
    "SSL_CONN_TABLE",
    "SSL_SNI_TABLE",
    "SSL_SEQ",
    "SSL_HTTP_PARSE_BUF",
    "SSL_HTTP_SCRATCH",
    "SSL_HTTP_SCRATCH_BUF",
    "SSL_READ_SCRATCH",
    "SSL_HTTP_TABLE",
    "SSL_HTTP_SEQ",
    "SSL_HTTP_VALUE_BUF",
    "SSL_GLOBAL_CONFIG",
    "SSL_ERROR_TABLE",
    "SSL_ERROR_SEQ",
    "SSL_WRITE_SCRATCH",
];

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
    let ipv4_cidrs = state
        .groups
        .values()
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
    let with_ports = state
        .rules
        .iter()
        .filter(|r| r.bitmap_idx.is_some())
        .count();
    println!("  With port filter: {}", with_ports);
    println!();

    println!("QoS rules: {}", state.qos_rules.len());
    println!();

    println!(
        "Port bitmap pool: {}/{} slots used",
        state.port_sets.len(),
        state.max_port_policies
    );
    println!("  Free recycled slots: {}", state.free_bitmap_indices.len());
    println!();

    println!("Kernel maps:");
    for name in NETWORK_MAP_NAMES {
        let path = format!("{}/{}", pin_path, name);
        let status = if std::path::Path::new(&path).exists() {
            "pinned"
        } else {
            "missing"
        };
        println!("  {}: {}", name, status);
    }

    Ok(())
}
