use super::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GroupProjectionMode {
    StandaloneCompatibility,
    Managed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FragmentRuntimeIdentity {
    Managed,
    Standalone,
}

impl FragmentRuntimeIdentity {
    fn runtime_mode(self) -> u8 {
        match self {
            Self::Managed => crate::common::FRAGMENT_RUNTIME_MODE_MANAGED,
            Self::Standalone => crate::common::FRAGMENT_RUNTIME_MODE_STANDALONE,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ManagedReplayRoute {
    projection_mode: GroupProjectionMode,
    legacy_acl_migration_authority: crate::state::LegacyAclMigrationAuthority,
}

impl ManagedReplayRoute {
    pub const fn new(
        projection_mode: GroupProjectionMode,
        legacy_acl_migration_authority: crate::state::LegacyAclMigrationAuthority,
    ) -> Self {
        Self {
            projection_mode,
            legacy_acl_migration_authority,
        }
    }

    pub const fn projection_mode(self) -> GroupProjectionMode {
        self.projection_mode
    }

    pub const fn legacy_acl_migration_authority(
        self,
    ) -> crate::state::LegacyAclMigrationAuthority {
        self.legacy_acl_migration_authority
    }

    pub const fn fragment_runtime_identity(self) -> FragmentRuntimeIdentity {
        FragmentRuntimeIdentity::Managed
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct StandaloneReplayRoute;

impl StandaloneReplayRoute {
    pub const fn new() -> Self {
        Self
    }

    pub const fn projection_mode(self) -> GroupProjectionMode {
        GroupProjectionMode::StandaloneCompatibility
    }

    pub const fn fragment_runtime_identity(self) -> FragmentRuntimeIdentity {
        FragmentRuntimeIdentity::Standalone
    }
}

impl Default for StandaloneReplayRoute {
    fn default() -> Self {
        Self::new()
    }
}

pub fn migrate_state_for_replay(
    state_path: &str,
    state: &crate::state::FirewallState,
    authority: crate::state::LegacyAclMigrationAuthority,
) -> Result<crate::state::FirewallState, String> {
    let mut migrated = state.clone();
    if crate::state::migrate_state_rule_families(&mut migrated, authority)? {
        let state_json = serde_json::to_string(&migrated)
            .map_err(|error| format!("serialize migrated ACL state: {}", error))?;
        let checkpoint_id = crate::wal::WalWriter::open(state_path)?
            .compact_family_migration(&state_json)
            .map_err(|error| format!("checkpoint migrated ACL state: {}", error))?;
        migrated.wal_replay_cursor = crate::state::WalReplayCursor {
            version: crate::state::WAL_REPLAY_CURSOR_VERSION,
            checkpoint_id,
        };
        info!(state_path = %state_path, rules = migrated.rules.len(), "checkpointed concrete ACL rule families before replay");
    }
    Ok(migrated)
}

fn load_state_then_replay<T>(
    state_path: &str,
    authority: crate::state::LegacyAclMigrationAuthority,
    replay: impl FnOnce(&crate::state::FirewallState) -> Result<T, String>,
) -> Result<T, String> {
    let state = crate::wal::load_with_wal_for_authority(state_path, authority)
        .map_err(|error| error.to_string())?;
    replay(&state)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum PinnedReplayRoute {
    Managed(ManagedReplayRoute),
    Standalone(StandaloneReplayRoute),
}

impl PinnedReplayRoute {
    fn projection_mode(self) -> GroupProjectionMode {
        match self {
            Self::Managed(route) => route.projection_mode(),
            Self::Standalone(route) => route.projection_mode(),
        }
    }

    fn fragment_runtime_identity(self) -> FragmentRuntimeIdentity {
        match self {
            Self::Managed(route) => route.fragment_runtime_identity(),
            Self::Standalone(route) => route.fragment_runtime_identity(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RuntimeNetworkEntry {
    pub address: IpAddr,
    pub prefix_len: u8,
    pub group_id: u32,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RuntimeGroupMapEntries {
    pub general_src: Vec<RuntimeNetworkEntry>,
    pub general_dst: Vec<RuntimeNetworkEntry>,
    pub acl_src: Vec<RuntimeNetworkEntry>,
    pub acl_dst: Vec<RuntimeNetworkEntry>,
}

pub fn collect_standalone_runtime_group_map_entries(
    state: &FirewallState,
) -> (RuntimeGroupMapEntries, Vec<String>) {
    let mut entries = Vec::new();
    let mut errors = Vec::new();
    for (name, group) in &state.groups {
        for cidr in &group.cidrs {
            match parse_cidr(cidr) {
                Ok((address, prefix_len)) => entries.push(RuntimeNetworkEntry {
                    address,
                    prefix_len,
                    group_id: group.id,
                }),
                Err(error) => errors.push(format!("group '{}' cidr '{}': {}", name, cidr, error)),
            }
        }
    }
    (
        RuntimeGroupMapEntries {
            general_src: entries.clone(),
            general_dst: entries.clone(),
            acl_src: entries.clone(),
            acl_dst: entries,
        },
        errors,
    )
}

pub fn build_runtime_group_map_entries(
    state: &FirewallState,
    mode: GroupProjectionMode,
) -> Result<RuntimeGroupMapEntries, String> {
    match mode {
        GroupProjectionMode::StandaloneCompatibility => {
            let (entries, errors) = collect_standalone_runtime_group_map_entries(state);
            if errors.is_empty() {
                Ok(entries)
            } else {
                Err(errors.join("; "))
            }
        }
        GroupProjectionMode::Managed => {
            let projection = compile_managed_group_projection(state)?;
            let general = projection
                .general
                .iter()
                .map(|entry| RuntimeNetworkEntry {
                    address: entry.network.network_address(),
                    prefix_len: entry.network.prefix_len(),
                    group_id: entry.group_id,
                })
                .collect::<Vec<_>>();
            let acl_src = projection
                .acl_src
                .iter()
                .map(|entry| RuntimeNetworkEntry {
                    address: entry.network.network_address(),
                    prefix_len: entry.network.prefix_len(),
                    group_id: entry.group_id,
                })
                .collect();
            let acl_dst = projection
                .acl_dst
                .iter()
                .map(|entry| RuntimeNetworkEntry {
                    address: entry.network.network_address(),
                    prefix_len: entry.network.prefix_len(),
                    group_id: entry.group_id,
                })
                .collect();
            Ok(RuntimeGroupMapEntries {
                general_src: general.clone(),
                general_dst: general,
                acl_src,
                acl_dst,
            })
        }
    }
}

fn write_fresh_group_maps(
    bpf: &mut aya::Ebpf,
    ipv4_map_name: &str,
    ipv6_map_name: &str,
    lpm_tap_id: u32,
    entries: &[RuntimeNetworkEntry],
    errors: &mut Vec<String>,
) {
    match bpf
        .map_mut(ipv4_map_name)
        .ok_or_else(|| format!("{} not found", ipv4_map_name))
        .and_then(|map| {
            LpmTrie::<_, [u8; 8], u32>::try_from(map).map_err(|error| format!("{:?}", error))
        }) {
        Ok(mut map) => {
            for entry in entries {
                let IpAddr::V4(address) = entry.address else {
                    continue;
                };
                let key = tap_lpm_key_v4(lpm_tap_id, address.octets(), entry.prefix_len);
                if let Err(error) = map.insert(&key, &entry.group_id, 0) {
                    errors.push(format!(
                        "{} id={}: {:?}",
                        ipv4_map_name, entry.group_id, error
                    ));
                }
            }
        }
        Err(error) => errors.push(format!("{}: {}", ipv4_map_name, error)),
    }

    match bpf
        .map_mut(ipv6_map_name)
        .ok_or_else(|| format!("{} not found", ipv6_map_name))
        .and_then(|map| {
            LpmTrie::<_, [u8; 20], u32>::try_from(map).map_err(|error| format!("{:?}", error))
        }) {
        Ok(mut map) => {
            for entry in entries {
                let IpAddr::V6(address) = entry.address else {
                    continue;
                };
                let key = tap_lpm_key_v6(lpm_tap_id, address.octets(), entry.prefix_len);
                if let Err(error) = map.insert(&key, &entry.group_id, 0) {
                    errors.push(format!(
                        "{} id={}: {:?}",
                        ipv6_map_name, entry.group_id, error
                    ));
                }
            }
        }
        Err(error) => errors.push(format!("{}: {}", ipv6_map_name, error)),
    }
}

fn write_fresh_runtime_group_entries(
    bpf: &mut aya::Ebpf,
    tap_id: u32,
    group_entries: &RuntimeGroupMapEntries,
    errors: &mut Vec<String>,
) {
    let acl_tap_id = acl_banked_tap_id(tap_id, ACL_BANK_PRIMARY);
    write_fresh_group_maps(
        bpf,
        "SRC_IPV4_TRIE",
        "SRC_IPV6_TRIE",
        tap_id,
        &group_entries.general_src,
        errors,
    );
    write_fresh_group_maps(
        bpf,
        "DST_IPV4_TRIE",
        "DST_IPV6_TRIE",
        tap_id,
        &group_entries.general_dst,
        errors,
    );
    write_fresh_group_maps(
        bpf,
        "ACL_SRC_IPV4_TRIE",
        "ACL_SRC_IPV6_TRIE",
        acl_tap_id,
        &group_entries.acl_src,
        errors,
    );
    write_fresh_group_maps(
        bpf,
        "ACL_DST_IPV4_TRIE",
        "ACL_DST_IPV6_TRIE",
        acl_tap_id,
        &group_entries.acl_dst,
        errors,
    );
}

fn write_pinned_group_entries(
    runtime: TapMapRuntime<'_>,
    entries: &[RuntimeNetworkEntry],
    direction: &str,
    acl: bool,
    errors: &mut Vec<String>,
) {
    for entry in entries {
        let cidr = format!("{}/{}", entry.address, entry.prefix_len);
        let result = if acl {
            add_acl_network_in_bank(
                direction,
                &cidr,
                entry.group_id,
                ACL_BANK_PRIMARY,
                runtime,
                "",
            )
        } else {
            add_network(direction, &cidr, entry.group_id, runtime, "")
        };
        if let Err(error) = result {
            let map_scope = if acl { "ACL group" } else { "group" };
            errors.push(format!(
                "{} ID {} cidr '{}' {}: {}",
                map_scope, entry.group_id, cidr, direction, error
            ));
        }
    }
}

fn write_pinned_runtime_group_entries(
    runtime: TapMapRuntime<'_>,
    group_entries: &RuntimeGroupMapEntries,
    errors: &mut Vec<String>,
) {
    write_pinned_group_entries(runtime, &group_entries.general_src, "src", false, errors);
    write_pinned_group_entries(runtime, &group_entries.general_dst, "dst", false, errors);
    write_pinned_group_entries(runtime, &group_entries.acl_src, "src", true, errors);
    write_pinned_group_entries(runtime, &group_entries.acl_dst, "dst", true, errors);
}

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
    load_state_then_replay(
        state_path,
        crate::state::LegacyAclMigrationAuthority::StandaloneInfer,
        |state| replay_state_from_snapshot(bpf, state_path, state),
    )
}

/// Replay one already-approved state snapshot into a freshly loaded eBPF object.
///
/// Standalone startup uses this entry point so replay and control-plane
/// publication cannot observe different WAL snapshots during one lifecycle
/// transaction. `replay_state` remains as the compatibility wrapper for
/// callers that intentionally load by path.
pub fn replay_state_from_snapshot(
    bpf: &mut aya::Ebpf,
    state_path: &str,
    state: &crate::state::FirewallState,
) -> Result<(), String> {
    let state = migrate_state_for_replay(
        state_path,
        state,
        crate::state::LegacyAclMigrationAuthority::StandaloneInfer,
    )?;
    replay_state_from_snapshot_with_mode(
        bpf,
        state_path,
        &state,
        GroupProjectionMode::StandaloneCompatibility,
    )
}

fn fresh_unpinned_firewall_config(state: &crate::state::FirewallState) -> FirewallConfig {
    let raw_cpus = unsafe { libc::sysconf(libc::_SC_NPROCESSORS_ONLN) };
    let num_cpus = if raw_cpus > 0 {
        raw_cpus as u16
    } else {
        1u16
    };
    FirewallConfig {
        conntrack_enabled: u8::from(state.conntrack_enabled),
        monitoring_enabled: u8::from(state.monitoring_enabled),
        num_cpus,
        qos_enabled: u8::from(state.qos_enabled && !state.qos_rules.is_empty()),
        acl_enabled: u8::from(state.acl_enabled),
        mirror_enabled: u8::from(state.mirror_enabled && !state.mirror_rules.is_empty()),
        tcprt_enabled: u8::from(state.tcprt_enabled),
        ssl_enabled: u8::from(state.ssl_enabled),
        acl_active_bank: ACL_BANK_PRIMARY,
        acl_maintenance_bypass: 0,
        _pad: 0,
    }
}

/// Initialize a newly loaded, not-yet-pinned object. This is deliberately a
/// write-only startup boundary; concurrent pinned-map RMW goes through the
/// serialized runtime helper instead.
fn initialize_fresh_unpinned_firewall_config(
    bpf: &mut aya::Ebpf,
    state: &crate::state::FirewallState,
) -> Result<(), String> {
    let cfg = fresh_unpinned_firewall_config(state);
    let map = bpf
        .map_mut("FIREWALL_CONFIG")
        .ok_or_else(|| "FIREWALL_CONFIG not found".to_string())?;
    let mut map = aya::maps::HashMap::<_, u32, FirewallConfig>::try_from(map)
        .map_err(|error| format!("{:?}", error))?;
    map.insert(&0u32, &cfg, 0)
        .map_err(|error| format!("{:?}", error))
}

fn replay_state_from_snapshot_with_mode(
    bpf: &mut aya::Ebpf,
    state_path: &str,
    state: &crate::state::FirewallState,
    mode: GroupProjectionMode,
) -> Result<(), String> {
    let mut projection_errors = Vec::new();
    let group_entries = match build_runtime_group_map_entries(state, mode) {
        Ok(entries) => entries,
        Err(error) if mode == GroupProjectionMode::StandaloneCompatibility => {
            let (entries, parse_errors) = collect_standalone_runtime_group_map_entries(state);
            projection_errors = if parse_errors.is_empty() {
                vec![error]
            } else {
                parse_errors
            };
            entries
        }
        Err(error) => return Err(error),
    };
    let tap_id = state.tap_id;
    let has_runtime_objects = !(group_entries.general_src.is_empty()
        && group_entries.general_dst.is_empty()
        && group_entries.acl_src.is_empty()
        && group_entries.acl_dst.is_empty()
        && state.rules.is_empty()
        && state.qos_rules.is_empty()
        && state.mirror_rules.is_empty());
    let mut valid_rules: Vec<&crate::state::RuleInfo> = Vec::new();

    info!(
        state_path = %state_path,
        group_entries = group_entries.general_src.len(),
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

    let mut errors = projection_errors;
    let group_count = group_entries.general_src.len() as u32;
    let mut rule_count: u32 = 0;
    let mut bitmap_count: u32 = 0;

    write_fresh_runtime_group_entries(bpf, tap_id, &group_entries, &mut errors);

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
                        ip_family: rule.ip_family,
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

    if let Err(error) = initialize_fresh_unpinned_firewall_config(bpf, state) {
        errors.push(format!("FIREWALL_CONFIG: {}", error));
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

pub fn replay_standalone_state_to_pinned_maps(
    pin_path: &str,
    state_path: &str,
) -> Result<(), String> {
    load_state_then_replay(
        state_path,
        crate::state::LegacyAclMigrationAuthority::StandaloneInfer,
        |state| replay_standalone_state_to_pinned_maps_from_snapshot(pin_path, state_path, state),
    )
}

pub fn replay_standalone_state_to_pinned_maps_from_snapshot(
    pin_path: &str,
    state_path: &str,
    state: &FirewallState,
) -> Result<(), String> {
    let state = migrate_state_for_replay(
        state_path,
        state,
        crate::state::LegacyAclMigrationAuthority::StandaloneInfer,
    )?;
    replay_state_to_pinned_maps_from_snapshot_with_mode(
        pin_path,
        state_path,
        &state,
        PinnedReplayRoute::Standalone(StandaloneReplayRoute::new()),
    )
}

pub fn replay_managed_state_to_pinned_maps(
    pin_path: &str,
    state_path: &str,
    state: &FirewallState,
    route: ManagedReplayRoute,
) -> Result<(), String> {
    if route.projection_mode() == GroupProjectionMode::StandaloneCompatibility {
        // Compatibility replay keeps the durable WAL snapshot as its projection
        // authority, matching the legacy standalone-compatible registration path.
        return load_state_then_replay(
            state_path,
            route.legacy_acl_migration_authority(),
            |durable_state| {
                let durable_state = migrate_state_for_replay(
                    state_path,
                    durable_state,
                    route.legacy_acl_migration_authority(),
                )?;
                replay_state_to_pinned_maps_from_snapshot_with_mode(
                    pin_path,
                    state_path,
                    &durable_state,
                    PinnedReplayRoute::Managed(route),
                )
            },
        );
    }
    let state = migrate_state_for_replay(
        state_path,
        state,
        route.legacy_acl_migration_authority(),
    )?;
    replay_state_to_pinned_maps_from_snapshot_with_mode(
        pin_path,
        state_path,
        &state,
        PinnedReplayRoute::Managed(route),
    )
}

fn replay_state_to_pinned_maps_from_snapshot_with_mode(
    pin_path: &str,
    state_path: &str,
    state: &FirewallState,
    route: PinnedReplayRoute,
) -> Result<(), String> {
    let mode = route.projection_mode();
    let mut projection_errors = Vec::new();
    let group_entries = match build_runtime_group_map_entries(state, mode) {
        Ok(entries) => entries,
        Err(error) if mode == GroupProjectionMode::StandaloneCompatibility => {
            let (entries, parse_errors) = collect_standalone_runtime_group_map_entries(state);
            projection_errors = if parse_errors.is_empty() {
                vec![error]
            } else {
                parse_errors
            };
            entries
        }
        Err(error) => return Err(error),
    };
    let tap_id = state.tap_id;
    let runtime = TapMapRuntime::new(pin_path, tap_id);
    validate_fragment_tracking_config_strict(
        pin_path,
        route.fragment_runtime_identity().runtime_mode(),
    )
    .map_err(|error| format!("FRAGMENT_CONFIG: {}", error))?;
    let has_runtime_objects = !(group_entries.general_src.is_empty()
        && group_entries.general_dst.is_empty()
        && group_entries.acl_src.is_empty()
        && group_entries.acl_dst.is_empty()
        && state.rules.is_empty()
        && state.qos_rules.is_empty()
        && state.mirror_rules.is_empty());
    let mut valid_rules: Vec<&crate::state::RuleInfo> = Vec::new();

    info!(
        state_path = %state_path,
        pin_path = %pin_path,
        group_entries = group_entries.general_src.len(),
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

    let mut errors = projection_errors;
    let group_count = group_entries.general_src.len() as u32;
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

    if tap_id == TAP_ID_UNASSIGNED {
        if let Err(e) = set_acl_active_bank(runtime, ACL_BANK_PRIMARY) {
            errors.push(format!("FIREWALL_CONFIG active bank: {}", e));
        }
    } else {
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

    write_pinned_runtime_group_entries(runtime, &group_entries, &mut errors);

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
            rule.ip_family,
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

#[cfg(test)]
mod family_migration_startup_tests {
    use super::*;
    use crate::state::FirewallState;
    use std::fs;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn mixed_legacy_family_load_stops_before_replay_callback() {
        let path = std::env::temp_dir().join(format!(
            "aria-family-fatal-replay-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&path).unwrap();
        let mut state = FirewallState::default();
        let src_id = state.add_group("src", "192.0.2.0/24").unwrap();
        let dst_id = state.add_group("dst", "2001:db8::/64").unwrap();
        fs::write(
            path.join("state.json"),
            serde_json::to_vec_pretty(&state).unwrap(),
        )
        .unwrap();
        fs::write(
            path.join("state.wal"),
            format!(
                "{}\n",
                serde_json::json!({
                    "AddRule": {
                        "src_id": src_id,
                        "dst_id": dst_id,
                        "proto": 6,
                        "action": 1,
                        "ports": null,
                        "direction": 0
                    }
                })
            ),
        )
        .unwrap();
        let replay_called = AtomicBool::new(false);

        let error = load_state_then_replay(
            path.to_str().unwrap(),
            crate::state::LegacyAclMigrationAuthority::StandaloneInfer,
            |_| {
                replay_called.store(true, Ordering::Relaxed);
                Ok(())
            },
        )
        .expect_err("family migration must abort before replay");

        assert_eq!(error, "legacy_acl_rule_mixed_family");
        assert!(!replay_called.load(Ordering::Relaxed));
        let _ = fs::remove_dir_all(path);
    }

    #[test]
    fn wal_checkpoint_malformed_wal_blocks_legacy_family_before_replay_callback() {
        let path = std::env::temp_dir().join(format!(
            "aria-family-wal-fatal-replay-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&path).unwrap();
        let mut state = FirewallState::default();
        state
            .apply_add_rule(
                0,
                0,
                6,
                0,
                Some("80"),
                0,
                crate::common::IP_FAMILY_V4,
            )
            .unwrap();
        state.rules[0].ip_family = 0;
        fs::write(
            path.join("state.json"),
            serde_json::to_vec_pretty(&state).unwrap(),
        )
        .unwrap();
        fs::write(path.join("state.wal"), b"{malformed record}\n").unwrap();
        let snapshot_before = fs::read(path.join("state.json")).unwrap();
        let wal_before = fs::read(path.join("state.wal")).unwrap();
        let replay_called = AtomicBool::new(false);

        let error = load_state_then_replay(
            path.to_str().unwrap(),
            crate::state::LegacyAclMigrationAuthority::StandaloneInfer,
            |_| {
                replay_called.store(true, Ordering::Relaxed);
                Ok(())
            },
        )
        .expect_err("WAL failure must abort family migration before replay");

        assert_eq!(
            error,
            "legacy_acl_family_checkpoint_blocked_by_wal_failure: failure_count=1"
        );
        assert!(!replay_called.load(Ordering::Relaxed));
        assert_eq!(fs::read(path.join("state.json")).unwrap(), snapshot_before);
        assert_eq!(fs::read(path.join("state.wal")).unwrap(), wal_before);
        let _ = fs::remove_dir_all(path);
    }
}

#[cfg(test)]
mod maintenance_replay_tests {
    use super::fresh_unpinned_firewall_config;
    use crate::common::{ACL_BANK_PRIMARY, TAP_ID_UNASSIGNED};
    use crate::state::FirewallState;

    #[test]
    fn acl_projection_maintenance_fresh_unpinned_replay_is_default_only_and_enforcing() {
        let state = FirewallState {
            tap_id: TAP_ID_UNASSIGNED,
            conntrack_enabled: true,
            monitoring_enabled: true,
            acl_enabled: true,
            qos_enabled: true,
            mirror_enabled: true,
            tcprt_enabled: true,
            ssl_enabled: true,
            ..FirewallState::default()
        };

        let config = fresh_unpinned_firewall_config(&state);
        assert_eq!(config.conntrack_enabled, 1);
        assert_eq!(config.monitoring_enabled, 1);
        assert_eq!(config.acl_enabled, 1);
        assert_eq!(config.qos_enabled, 0);
        assert_eq!(config.mirror_enabled, 0);
        assert_eq!(config.tcprt_enabled, 1);
        assert_eq!(config.ssl_enabled, 1);
        assert_eq!(config.acl_active_bank, ACL_BANK_PRIMARY);
        assert_eq!(config.acl_maintenance_bypass, 0);
        assert_eq!(config._pad, 0);
    }
}
