use super::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeGateDisposition {
    Desired,
    ManagedQuiesced,
}

pub fn classify_runtime_gate_state(
    mode: GroupProjectionMode,
    actual_conntrack: u8,
    actual_acl: u8,
    expected_conntrack: u8,
    expected_acl: u8,
) -> Result<RuntimeGateDisposition, String> {
    if actual_conntrack == expected_conntrack && actual_acl == expected_acl {
        return Ok(RuntimeGateDisposition::Desired);
    }
    if mode == GroupProjectionMode::Managed && actual_conntrack == 0 && actual_acl == 0 {
        return Ok(RuntimeGateDisposition::ManagedQuiesced);
    }
    Err(format!(
        "runtime gate drift: actual conntrack={} acl={}, expected conntrack={} acl={}",
        actual_conntrack, actual_acl, expected_conntrack, expected_acl,
    ))
}

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

fn runtime_network_prefix(
    map_name: &str,
    total_prefix_len: u32,
    address_bits: u32,
) -> Result<u8, String> {
    if total_prefix_len < TAP_LPM_PREFIX_BITS
        || total_prefix_len > TAP_LPM_PREFIX_BITS + address_bits
    {
        return Err(format!(
            "{} contains invalid prefix_len {}, expected {}..={}",
            map_name,
            total_prefix_len,
            TAP_LPM_PREFIX_BITS,
            TAP_LPM_PREFIX_BITS + address_bits,
        ));
    }
    Ok((total_prefix_len - TAP_LPM_PREFIX_BITS) as u8)
}

fn collect_runtime_network_entries(
    pin_path: &str,
    ipv4_map_name: &str,
    ipv6_map_name: &str,
    tap_id: u32,
) -> Result<Vec<ProjectionEntry>, String> {
    let tap_prefix = tap_id.to_be_bytes();
    let mut entries = Vec::new();

    let ipv4_map = open_pinned_lpm_v4(pin_path, ipv4_map_name)?;
    for item in ipv4_map.iter() {
        let (key, group_id) =
            item.map_err(|error| format!("iterate {}: {:?}", ipv4_map_name, error))?;
        let prefix_len = runtime_network_prefix(ipv4_map_name, key.prefix_len(), 32)?;
        let data = key.data();
        if data[..4] != tap_prefix {
            continue;
        }
        let address = IpAddr::V4(std::net::Ipv4Addr::from(
            <[u8; 4]>::try_from(&data[4..]).expect("IPv4 LPM key has a fixed address width"),
        ));
        entries.push(ProjectionEntry {
            network: CanonicalNetwork::from_ip(address, prefix_len)?,
            group_id,
        });
    }

    let ipv6_map = open_pinned_lpm_v6(pin_path, ipv6_map_name)?;
    for item in ipv6_map.iter() {
        let (key, group_id) =
            item.map_err(|error| format!("iterate {}: {:?}", ipv6_map_name, error))?;
        let prefix_len = runtime_network_prefix(ipv6_map_name, key.prefix_len(), 128)?;
        let data = key.data();
        if data[..4] != tap_prefix {
            continue;
        }
        let address = IpAddr::V6(std::net::Ipv6Addr::from(
            <[u8; 16]>::try_from(&data[4..]).expect("IPv6 LPM key has a fixed address width"),
        ));
        entries.push(ProjectionEntry {
            network: CanonicalNetwork::from_ip(address, prefix_len)?,
            group_id,
        });
    }

    entries.sort();
    Ok(entries)
}

/// Capture the owner stored at one exact canonical key in a standalone
/// general selector map. This deliberately performs an exact-key scan rather
/// than a longest-prefix packet lookup, because publication rollback must
/// restore the actual overwritten preimage.
pub fn capture_general_network_owner(
    runtime: TapMapRuntime<'_>,
    direction: &str,
    cidr: &str,
) -> Result<Option<u32>, String> {
    let network = CanonicalNetwork::parse(cidr)?;
    let (ipv4_map_name, ipv6_map_name) = match direction {
        "src" => ("SRC_IPV4_TRIE", "SRC_IPV6_TRIE"),
        "dst" => ("DST_IPV4_TRIE", "DST_IPV6_TRIE"),
        _ => return Err("direction must be 'src' or 'dst'".to_string()),
    };
    let entries = collect_runtime_network_entries(
        runtime.pin_path,
        ipv4_map_name,
        ipv6_map_name,
        runtime.tap_id,
    )?;
    Ok(entries
        .into_iter()
        .find(|entry| entry.network == network)
        .map(|entry| entry.group_id))
}

fn capture_runtime_group_map_entries(
    runtime: TapMapRuntime<'_>,
) -> Result<CapturedProjection, String> {
    let pin_path = runtime.pin_path;
    let tap_id = runtime.tap_id;
    let tap_config_map = open_pinned_tap_config(pin_path)?;
    let actual_tap_config = tap_config_map
        .get(&tap_id, 0)
        .map_err(|error| format!("read TAP_CONFIG_MAP for tap_id {}: {:?}", tap_id, error))?;
    if actual_tap_config.acl_active_bank > ACL_BANK_SHADOW {
        return Err(format!(
            "TAP_CONFIG_MAP contains invalid raw ACL bank {} for tap_id {}",
            actual_tap_config.acl_active_bank, tap_id,
        ));
    }
    let active_acl_lpm_tap_id = acl_banked_tap_id(tap_id, actual_tap_config.acl_active_bank);

    Ok(CapturedProjection {
        general_src: collect_runtime_network_entries(
            pin_path,
            "SRC_IPV4_TRIE",
            "SRC_IPV6_TRIE",
            tap_id,
        )?,
        general_dst: collect_runtime_network_entries(
            pin_path,
            "DST_IPV4_TRIE",
            "DST_IPV6_TRIE",
            tap_id,
        )?,
        acl_src: collect_runtime_network_entries(
            pin_path,
            "ACL_SRC_IPV4_TRIE",
            "ACL_SRC_IPV6_TRIE",
            active_acl_lpm_tap_id,
        )?,
        acl_dst: collect_runtime_network_entries(
            pin_path,
            "ACL_DST_IPV4_TRIE",
            "ACL_DST_IPV6_TRIE",
            active_acl_lpm_tap_id,
        )?,
    })
}

fn runtime_entries_as_projection(
    entries: &[RuntimeNetworkEntry],
) -> Result<BTreeSet<ProjectionEntry>, String> {
    entries
        .iter()
        .map(|entry| {
            Ok(ProjectionEntry {
                network: CanonicalNetwork::from_ip(entry.address, entry.prefix_len)?,
                group_id: entry.group_id,
            })
        })
        .collect()
}

fn validate_projection_entry_set(
    label: &str,
    expected: &[RuntimeNetworkEntry],
    captured: &[ProjectionEntry],
) -> Result<(), String> {
    let expected = runtime_entries_as_projection(expected)?;
    let captured: BTreeSet<ProjectionEntry> = captured.iter().copied().collect();
    if expected == captured {
        return Ok(());
    }
    Err(format!(
        "{} drift: expected={:?} captured={:?}",
        label, expected, captured,
    ))
}

fn classify_standalone_inventory_capture(
    captured: &CapturedProjection,
    expected_entries: &RuntimeGroupMapEntries,
    strict_result: Result<(), String>,
) -> ProjectionDrift {
    if let Err(error) = strict_result {
        return ProjectionDrift::Fatal(error);
    }
    for result in [
        validate_projection_entry_set(
            "standalone general source",
            &expected_entries.general_src,
            &captured.general_src,
        ),
        validate_projection_entry_set(
            "standalone general destination",
            &expected_entries.general_dst,
            &captured.general_dst,
        ),
        validate_projection_entry_set(
            "standalone ACL source",
            &expected_entries.acl_src,
            &captured.acl_src,
        ),
        validate_projection_entry_set(
            "standalone ACL destination",
            &expected_entries.acl_dst,
            &captured.acl_dst,
        ),
    ] {
        if let Err(error) = result {
            return ProjectionDrift::Fatal(error);
        }
    }
    ProjectionDrift::Clean
}

pub fn classify_managed_inventory_capture(
    state: &FirewallState,
    captured: &CapturedProjection,
    strict_result: Result<(), String>,
) -> ProjectionDrift {
    if let Err(error) = strict_result {
        return ProjectionDrift::Fatal(error);
    }
    let committed = match compile_managed_group_projection(state) {
        Ok(projection) => projection,
        Err(error) => return ProjectionDrift::Fatal(error),
    };
    plan_projection_drift(captured, &committed, &committed)
}

impl ManagedGroupProjection {
    /// Plan managed projection repair from one live capture directly to this
    /// proposed projection while validating non-projection runtime state
    /// against the committed snapshot.
    pub fn plan_managed_pinned_projection(
        &self,
        runtime: TapMapRuntime<'_>,
        committed_state: &FirewallState,
    ) -> ProjectionDrift {
        let proposed = self;
        if runtime.tap_id == TAP_ID_UNASSIGNED {
            return ProjectionDrift::Fatal(
                "managed runtime inventory requires an assigned tap_id".to_string(),
            );
        }
        if committed_state.tap_id != runtime.tap_id {
            return ProjectionDrift::Fatal(format!(
                "state tap_id {} does not match runtime tap_id {}",
                committed_state.tap_id, runtime.tap_id,
            ));
        }

        let captured = match capture_runtime_group_map_entries(runtime) {
            Ok(entries) => entries,
            Err(error) => return ProjectionDrift::Fatal(error),
        };
        if let Err(error) = validate_strict_pinned_runtime_state(
            runtime,
            committed_state,
            GroupProjectionMode::Managed,
        ) {
            return ProjectionDrift::Fatal(error);
        }
        let committed = match compile_managed_group_projection(committed_state) {
            Ok(projection) => projection,
            Err(error) => return ProjectionDrift::Fatal(error),
        };

        plan_projection_drift(&captured, &committed, proposed)
    }
}

fn validate_strict_pinned_runtime_state(
    runtime: TapMapRuntime<'_>,
    state: &FirewallState,
    mode: GroupProjectionMode,
) -> Result<(), String> {
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
        acl_active_bank: ACL_BANK_PRIMARY,
        acl_ingress_hook: ACL_INGRESS_HOOK_TC,
    };
    let tap_config_map = open_pinned_tap_config(pin_path)?;
    let actual_tap_config = tap_config_map
        .get(&tap_id, 0)
        .map_err(|error| format!("read TAP_CONFIG_MAP for tap_id {}: {:?}", tap_id, error))?;
    if actual_tap_config.acl_active_bank > ACL_BANK_SHADOW {
        return Err(format!(
            "TAP_CONFIG_MAP contains invalid raw ACL bank {} for tap_id {}",
            actual_tap_config.acl_active_bank, tap_id,
        ));
    }
    classify_runtime_gate_state(
        mode,
        actual_tap_config.conntrack_enabled,
        actual_tap_config.acl_enabled,
        expected_tap_config.conntrack_enabled,
        expected_tap_config.acl_enabled,
    )
    .map_err(|error| format!("TAP_CONFIG_MAP drift for tap_id {}: {}", tap_id, error))?;
    if actual_tap_config.monitoring_enabled != expected_tap_config.monitoring_enabled
        || actual_tap_config.qos_enabled != expected_tap_config.qos_enabled
        || actual_tap_config.mirror_enabled != expected_tap_config.mirror_enabled
        || actual_tap_config.tcprt_enabled != expected_tap_config.tcprt_enabled
        || actual_tap_config.acl_ingress_hook != expected_tap_config.acl_ingress_hook
    {
        return Err(format!(
            "TAP_CONFIG_MAP drift for tap_id {}: actual={:?} expected={:?}",
            tap_id, actual_tap_config, expected_tap_config
        ));
    }
    let active_acl_bank = actual_tap_config.acl_active_bank;

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

fn validate_pinned_runtime_state_with_mode(
    runtime: TapMapRuntime<'_>,
    state: &FirewallState,
    mode: GroupProjectionMode,
) -> ProjectionDrift {
    if runtime.tap_id == TAP_ID_UNASSIGNED {
        return match mode {
            GroupProjectionMode::StandaloneCompatibility => ProjectionDrift::Clean,
            GroupProjectionMode::Managed => ProjectionDrift::Fatal(
                "managed runtime inventory requires an assigned tap_id".to_string(),
            ),
        };
    }
    if state.tap_id != runtime.tap_id {
        return ProjectionDrift::Fatal(format!(
            "state tap_id {} does not match runtime tap_id {}",
            state.tap_id, runtime.tap_id,
        ));
    }
    let expected_entries = match build_runtime_group_map_entries(state, mode) {
        Ok(entries) => entries,
        Err(error) => return ProjectionDrift::Fatal(error),
    };
    let captured = match capture_runtime_group_map_entries(runtime) {
        Ok(entries) => entries,
        Err(error) => return ProjectionDrift::Fatal(error),
    };
    let strict_result = validate_strict_pinned_runtime_state(runtime, state, mode);
    match mode {
        GroupProjectionMode::StandaloneCompatibility => {
            classify_standalone_inventory_capture(&captured, &expected_entries, strict_result)
        }
        GroupProjectionMode::Managed => {
            classify_managed_inventory_capture(state, &captured, strict_result)
        }
    }
}

pub fn validate_pinned_runtime_state(
    runtime: TapMapRuntime<'_>,
    state: &FirewallState,
) -> Result<(), String> {
    match validate_pinned_runtime_state_with_mode(
        runtime,
        state,
        GroupProjectionMode::StandaloneCompatibility,
    ) {
        ProjectionDrift::Clean => Ok(()),
        ProjectionDrift::RepairRequired(_) => Err(
            "standalone runtime inventory unexpectedly requires managed projection repair"
                .to_string(),
        ),
        ProjectionDrift::Fatal(error) => Err(error),
    }
}

pub fn validate_managed_pinned_runtime_state(
    runtime: TapMapRuntime<'_>,
    state: &FirewallState,
) -> ProjectionDrift {
    validate_pinned_runtime_state_with_mode(runtime, state, GroupProjectionMode::Managed)
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
    "FRAG_CONTEXT_V4",
    "FRAG_CONTEXT_V6",
    "FRAGMENT_EPOCH",
    "FRAGMENT_CONFIG",
    "FRAGMENT_METRICS",
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
    "FRAG_CONTEXT_V4",
    "FRAG_CONTEXT_V6",
    "FRAGMENT_EPOCH",
    "FRAGMENT_CONFIG",
    "FRAGMENT_METRICS",
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
    "FRAG_CONTEXT_V4",
    "FRAG_CONTEXT_V6",
    "FRAGMENT_EPOCH",
    "FRAGMENT_CONFIG",
    "FRAGMENT_METRICS",
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
    "FRAG_CONTEXT_V4",
    "FRAG_CONTEXT_V6",
    "FRAGMENT_EPOCH",
    "FRAGMENT_CONFIG",
    "FRAGMENT_METRICS",
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
