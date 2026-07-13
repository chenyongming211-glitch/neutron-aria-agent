use super::*;

fn init_ct_config_pinned(pin_path: &str) -> Result<(), String> {
    let map_path = format!("{}/CT_CONFIG", pin_path);
    let map_data =
        MapData::from_pin(&map_path).map_err(|e| format!("open pinned CT_CONFIG: {:?}", e))?;
    let mut map =
        aya::maps::HashMap::<_, u32, CtConfig>::try_from(aya::maps::Map::HashMap(map_data))
            .map_err(|e| format!("convert CT_CONFIG to HashMap: {:?}", e))?;

    let config = CtConfig {
        tcp_established_ns: 300_000_000_000,
        tcp_new_ns: 30_000_000_000,
        udp_ns: 60_000_000_000,
        icmp_ns: 30_000_000_000,
    };
    map.insert(&0u32, &config, 0)
        .map_err(|e| format!("CT_CONFIG insert: {:?}", e))
}

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

    {
        match bpf
            .map_mut("SRC_IPV4_TRIE")
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

    {
        match bpf
            .map_mut("DST_IPV4_TRIE")
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

    {
        match bpf
            .map_mut("SRC_IPV6_TRIE")
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

    {
        match bpf
            .map_mut("DST_IPV6_TRIE")
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

    let acl_tap_id = acl_banked_tap_id(tap_id, 0);
    {
        match bpf
            .map_mut("ACL_SRC_IPV4_TRIE")
            .ok_or_else(|| "ACL_SRC_IPV4_TRIE not found".to_string())
            .and_then(|m| LpmTrie::<_, [u8; 8], u32>::try_from(m).map_err(|e| format!("{:?}", e)))
        {
            Ok(mut map) => {
                for (octets, prefix, id) in &src_ipv4 {
                    let key = tap_lpm_key_v4(acl_tap_id, *octets, *prefix);
                    if let Err(e) = map.insert(&key, id, 0) {
                        errors.push(format!("ACL_SRC_IPV4_TRIE id={}: {:?}", id, e));
                    }
                }
            }
            Err(e) => errors.push(format!("ACL_SRC_IPV4_TRIE: {}", e)),
        }
    }

    {
        match bpf
            .map_mut("ACL_DST_IPV4_TRIE")
            .ok_or_else(|| "ACL_DST_IPV4_TRIE not found".to_string())
            .and_then(|m| LpmTrie::<_, [u8; 8], u32>::try_from(m).map_err(|e| format!("{:?}", e)))
        {
            Ok(mut map) => {
                for (octets, prefix, id) in &dst_ipv4 {
                    let key = tap_lpm_key_v4(acl_tap_id, *octets, *prefix);
                    if let Err(e) = map.insert(&key, id, 0) {
                        errors.push(format!("ACL_DST_IPV4_TRIE id={}: {:?}", id, e));
                    }
                }
            }
            Err(e) => errors.push(format!("ACL_DST_IPV4_TRIE: {}", e)),
        }
    }

    {
        match bpf
            .map_mut("ACL_SRC_IPV6_TRIE")
            .ok_or_else(|| "ACL_SRC_IPV6_TRIE not found".to_string())
            .and_then(|m| LpmTrie::<_, [u8; 20], u32>::try_from(m).map_err(|e| format!("{:?}", e)))
        {
            Ok(mut map) => {
                for (octets, prefix, id) in &src_ipv6 {
                    let key = tap_lpm_key_v6(acl_tap_id, *octets, *prefix);
                    if let Err(e) = map.insert(&key, id, 0) {
                        errors.push(format!("ACL_SRC_IPV6_TRIE id={}: {:?}", id, e));
                    }
                }
            }
            Err(e) => errors.push(format!("ACL_SRC_IPV6_TRIE: {}", e)),
        }
    }

    {
        match bpf
            .map_mut("ACL_DST_IPV6_TRIE")
            .ok_or_else(|| "ACL_DST_IPV6_TRIE not found".to_string())
            .and_then(|m| LpmTrie::<_, [u8; 20], u32>::try_from(m).map_err(|e| format!("{:?}", e)))
        {
            Ok(mut map) => {
                for (octets, prefix, id) in &dst_ipv6 {
                    let key = tap_lpm_key_v6(acl_tap_id, *octets, *prefix);
                    if let Err(e) = map.insert(&key, id, 0) {
                        errors.push(format!("ACL_DST_IPV6_TRIE id={}: {:?}", id, e));
                    }
                }
            }
            Err(e) => errors.push(format!("ACL_DST_IPV6_TRIE: {}", e)),
        }
    }

    {
        let mut written_bitmaps: HashSet<u32> = HashSet::new();
        match bpf
            .map_mut("PORT_BITMAP_POOL")
            .ok_or_else(|| "PORT_BITMAP_POOL not found".to_string())
            .and_then(|m| {
                aya::maps::HashMap::<_, PortKey, u8>::try_from(m).map_err(|e| format!("{:?}", e))
            }) {
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
                                            let key = PortKey {
                                                tap_id,
                                                idx,
                                                port,
                                                pad: 0,
                                            };
                                            if let Err(e) = port_pool.insert(&key, &action, 0) {
                                                errors.push(format!(
                                                    "PORT_BITMAP_POOL idx={} port={}: {:?}",
                                                    idx, port, e
                                                ));
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

    {
        match bpf
            .map_mut("POLICY_TABLE")
            .ok_or_else(|| "POLICY_TABLE not found".to_string())
            .and_then(|m| {
                aya::maps::HashMap::<_, PolicyKey, PolicyValue>::try_from(m)
                    .map_err(|e| format!("{:?}", e))
            }) {
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
                        bank: 0,
                        pad: [0; 1],
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

    {
        let config = CtConfig {
            tcp_established_ns: 300_000_000_000,
            tcp_new_ns: 30_000_000_000,
            udp_ns: 60_000_000_000,
            icmp_ns: 30_000_000_000,
        };
        match bpf
            .map_mut("CT_CONFIG")
            .ok_or_else(|| "CT_CONFIG not found".to_string())
            .and_then(|m| {
                aya::maps::HashMap::<_, u32, CtConfig>::try_from(m).map_err(|e| format!("{:?}", e))
            }) {
            Ok(mut map) => {
                if let Err(e) = map.insert(&0u32, &config, 0) {
                    errors.push(format!("CT_CONFIG: {:?}", e));
                }
            }
            Err(e) => errors.push(format!("CT_CONFIG: {}", e)),
        }
    }

    if !state.qos_rules.is_empty() {
        match bpf
            .map_mut("QOS_CONFIG")
            .ok_or_else(|| "QOS_CONFIG not found".to_string())
            .and_then(|m| {
                aya::maps::HashMap::<_, QosKey, QosConfig>::try_from(m)
                    .map_err(|e| format!("{:?}", e))
            }) {
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

    if !state.mirror_rules.is_empty() {
        let mut policy_rules: Vec<(u32, u32, u8, u8, u32)> = Vec::new();
        let mut global_rules: Vec<(u8, u32)> = Vec::new();

        for mr in &state.mirror_rules {
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
                policy_rules.push((
                    mr.src_group_id,
                    mr.dst_group_id,
                    mr.proto,
                    mr.direction,
                    ifindex,
                ));
            }
        }

        let mirror_errors =
            crate::mirror_ops::replay_mirror_rules(bpf, tap_id, &policy_rules, &global_rules);
        errors.extend(mirror_errors);
    }

    {
        let raw_cpus = unsafe { libc::sysconf(libc::_SC_NPROCESSORS_ONLN) };
        let num_cpus = if raw_cpus > 0 { raw_cpus as u16 } else { 1u16 };
        let cfg = FirewallConfig {
            conntrack_enabled: if state.conntrack_enabled { 1 } else { 0 },
            monitoring_enabled: if state.monitoring_enabled { 1 } else { 0 },
            num_cpus,
            qos_enabled: if state.qos_enabled && !state.qos_rules.is_empty() {
                1
            } else {
                0
            },
            acl_enabled: if state.acl_enabled { 1 } else { 0 },
            mirror_enabled: if state.mirror_enabled && !state.mirror_rules.is_empty() {
                1
            } else {
                0
            },
            tcprt_enabled: if state.tcprt_enabled { 1 } else { 0 },
            ssl_enabled: if state.ssl_enabled { 1 } else { 0 },
        };
        match bpf
            .map_mut("FIREWALL_CONFIG")
            .ok_or_else(|| "FIREWALL_CONFIG not found".to_string())
            .and_then(|m| {
                aya::maps::HashMap::<_, u32, FirewallConfig>::try_from(m)
                    .map_err(|e| format!("{:?}", e))
            }) {
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
            acl_ingress_hook: ACL_INGRESS_HOOK_TC,
        };
        match bpf
            .map_mut("TAP_CONFIG_MAP")
            .ok_or_else(|| "TAP_CONFIG_MAP not found".to_string())
            .and_then(|m| {
                aya::maps::HashMap::<_, u32, TapConfig>::try_from(m).map_err(|e| format!("{:?}", e))
            }) {
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
        let preview = errors
            .iter()
            .take(3)
            .cloned()
            .collect::<Vec<_>>()
            .join("; ");
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
            acl_ingress_hook: ACL_INGRESS_HOOK_TC,
        };
        if let Err(e) = write_tap_config(runtime, tap_cfg) {
            errors.push(format!("TAP_CONFIG_MAP tap_id={}: {}", tap_id, e));
        }
    }

    for (name, group) in &state.groups {
        for cidr in &group.cidrs {
            let mut failed = false;
            if let Err(e) = add_network("src", cidr, group.id, runtime, "") {
                errors.push(format!("group '{}' cidr '{}' src: {}", name, cidr, e));
                failed = true;
            }
            if let Err(e) = add_network("dst", cidr, group.id, runtime, "") {
                errors.push(format!("group '{}' cidr '{}' dst: {}", name, cidr, e));
                failed = true;
            }
            if let Err(e) = add_acl_network_in_bank("src", cidr, group.id, 0, runtime, "") {
                errors.push(format!("group '{}' cidr '{}' acl src: {}", name, cidr, e));
                failed = true;
            }
            if let Err(e) = add_acl_network_in_bank("dst", cidr, group.id, 0, runtime, "") {
                errors.push(format!("group '{}' cidr '{}' acl dst: {}", name, cidr, e));
                failed = true;
            }
            if !failed {
                group_count += 1;
            }
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
                warn!(target_iface = %mr.target_iface, error = %e, "mirror target not found during pinned replay");
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
            let scope = if mr.is_global {
                "MIRROR_GLOBAL"
            } else {
                "MIRROR_POLICY"
            };
            errors.push(format!(
                "{} target={} dir={}: {}",
                scope, mr.target_iface, mr.direction, e
            ));
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
        warn!(
            error_count = errors.len(),
            "pinned replay encountered errors"
        );
        for err in &errors {
            warn!(error = %err, "pinned replay error");
        }
        let preview = errors
            .iter()
            .take(3)
            .cloned()
            .collect::<Vec<_>>()
            .join("; ");
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
