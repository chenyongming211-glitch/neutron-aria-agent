use super::*;

trait HasTapId {
    fn tap_id(&self) -> u32;
}

impl HasTapId for PolicyKey {
    fn tap_id(&self) -> u32 { self.tap_id }
}

impl HasTapId for PortKey {
    fn tap_id(&self) -> u32 { self.tap_id }
}

impl HasTapId for CtKey4 {
    fn tap_id(&self) -> u32 { self.tap_id }
}

impl HasTapId for CtKey6 {
    fn tap_id(&self) -> u32 { self.tap_id }
}

impl HasTapId for CtContractKey {
    fn tap_id(&self) -> u32 { self.tap_id }
}

impl HasTapId for QosKey {
    fn tap_id(&self) -> u32 { self.tap_id }
}

impl HasTapId for GroupStatsKey {
    fn tap_id(&self) -> u32 { self.tap_id }
}

impl HasTapId for MirrorKey {
    fn tap_id(&self) -> u32 { self.tap_id }
}

impl HasTapId for GlobalMirrorKey {
    fn tap_id(&self) -> u32 { self.tap_id }
}

fn scrub_hash_map<K, V, F>(
    pin_path: &str,
    map_name: &str,
    tap_id: u32,
    open_map: F,
) -> Result<u64, String>
where
    K: aya::Pod + HasTapId,
    V: aya::Pod,
    F: FnOnce(MapData) -> Result<HashMap<MapData, K, V>, String>,
{
    let map_path = format!("{}/{}", pin_path, map_name);
    let map_data = MapData::from_pin(&map_path)
        .map_err(|e| format!("open pinned {}: {:?}", map_name, e))?;
    let mut map = open_map(map_data)?;
    let keys: Vec<K> = map
        .iter()
        .filter_map(|item| item.ok().map(|(key, _)| key))
        .filter(|key| key.tap_id() == tap_id)
        .collect();
    let count = keys.len() as u64;
    for key in keys {
        map.remove(&key)
            .map_err(|e| format!("remove {} entry: {:?}", map_name, e))?;
    }
    Ok(count)
}

fn scrub_per_cpu_hash_map<K, V, F>(
    pin_path: &str,
    map_name: &str,
    tap_id: u32,
    open_map: F,
) -> Result<u64, String>
where
    K: aya::Pod + HasTapId,
    V: aya::Pod,
    F: FnOnce(MapData) -> Result<PerCpuHashMap<MapData, K, V>, String>,
{
    let map_path = format!("{}/{}", pin_path, map_name);
    let map_data = MapData::from_pin(&map_path)
        .map_err(|e| format!("open pinned {}: {:?}", map_name, e))?;
    let mut map = open_map(map_data)?;
    let keys: Vec<K> = map
        .keys()
        .filter_map(|item| item.ok())
        .filter(|key| key.tap_id() == tap_id)
        .collect();
    let count = keys.len() as u64;
    for key in keys {
        map.remove(&key)
            .map_err(|e| format!("remove {} entry: {:?}", map_name, e))?;
    }
    Ok(count)
}

fn scrub_lpm_v4_map(pin_path: &str, map_name: &str, tap_id: u32) -> Result<u64, String> {
    let mut map = open_pinned_lpm_v4(pin_path, map_name)?;
    let tap_prefix = tap_id.to_be_bytes();
    let keys: Vec<Key<[u8; 8]>> = map
        .iter()
        .filter_map(|item| item.ok().map(|(key, _)| key))
        .filter(|key| {
            let data = key.data();
            data[..4] == tap_prefix[..]
        })
        .collect();
    let count = keys.len() as u64;
    for key in keys {
        map.remove(&key)
            .map_err(|e| format!("remove {} entry: {:?}", map_name, e))?;
    }
    Ok(count)
}

fn scrub_lpm_v6_map(pin_path: &str, map_name: &str, tap_id: u32) -> Result<u64, String> {
    let mut map = open_pinned_lpm_v6(pin_path, map_name)?;
    let tap_prefix = tap_id.to_be_bytes();
    let keys: Vec<Key<[u8; 20]>> = map
        .iter()
        .filter_map(|item| item.ok().map(|(key, _)| key))
        .filter(|key| {
            let data = key.data();
            data[..4] == tap_prefix[..]
        })
        .collect();
    let count = keys.len() as u64;
    for key in keys {
        map.remove(&key)
            .map_err(|e| format!("remove {} entry: {:?}", map_name, e))?;
    }
    Ok(count)
}

fn scrub_iface_ctx_entries(pin_path: &str, tap_id: u32) -> Result<u64, String> {
    let mut map = open_pinned_iface_ctx(pin_path)?;
    let keys: Vec<u32> = map
        .iter()
        .filter_map(|item| item.ok())
        .filter_map(|(ifindex, ctx)| (ctx.tap_id == tap_id).then_some(ifindex))
        .collect();
    let count = keys.len() as u64;
    for ifindex in keys {
        map.remove(&ifindex)
            .map_err(|e| format!("remove IFACE_CTX_MAP entry for ifindex {}: {:?}", ifindex, e))?;
    }
    Ok(count)
}

fn scrub_tap_config_entries(pin_path: &str, tap_id: u32) -> Result<u64, String> {
    let mut map = open_pinned_tap_config(pin_path)?;
    let keys: Vec<u32> = map
        .iter()
        .filter_map(|item| item.ok().map(|(key, _)| key))
        .filter(|key| *key == tap_id)
        .collect();
    let count = keys.len() as u64;
    for key in keys {
        map.remove(&key)
            .map_err(|e| format!("remove TAP_CONFIG_MAP entry for tap_id {}: {:?}", key, e))?;
    }
    Ok(count)
}

fn record_optional_scrub(
    tap_id: u32,
    map_name: &str,
    removed: &mut u64,
    result: Result<u64, String>,
) {
    match result {
        Ok(count) => *removed += count,
        Err(e) => warn!(
            tap_id,
            map = %map_name,
            error = %e,
            "failed to scrub optional managed runtime map"
        ),
    }
}

fn scrub_runtime_state(runtime: TapMapRuntime<'_>, scope: &'static str) -> Result<u64, String> {
    let pin_path = runtime.pin_path;
    let tap_id = runtime.tap_id;
    let mut removed = 0u64;

    removed += scrub_iface_ctx_entries(pin_path, tap_id)?;
    removed += scrub_tap_config_entries(pin_path, tap_id)?;

    removed += scrub_lpm_v4_map(pin_path, "SRC_IPV4_TRIE", tap_id)?;
    removed += scrub_lpm_v4_map(pin_path, "DST_IPV4_TRIE", tap_id)?;
    removed += scrub_lpm_v6_map(pin_path, "SRC_IPV6_TRIE", tap_id)?;
    removed += scrub_lpm_v6_map(pin_path, "DST_IPV6_TRIE", tap_id)?;

    removed += scrub_hash_map(pin_path, "POLICY_TABLE", tap_id, |map_data| {
        HashMap::<_, PolicyKey, PolicyValue>::try_from(aya::maps::Map::HashMap(map_data))
            .map_err(|e| format!("convert POLICY_TABLE to HashMap: {:?}", e))
    })?;
    removed += scrub_hash_map(pin_path, "PORT_BITMAP_POOL", tap_id, |map_data| {
        HashMap::<_, PortKey, u8>::try_from(aya::maps::Map::HashMap(map_data))
            .map_err(|e| format!("convert PORT_BITMAP_POOL to HashMap: {:?}", e))
    })?;

    removed += crate::ct_ops::scrub_ct_tables_strict(runtime)?;
    record_optional_scrub(
        tap_id,
        "CT_CONTRACT_STATS",
        &mut removed,
        scrub_per_cpu_hash_map(pin_path, "CT_CONTRACT_STATS", tap_id, |map_data| {
            PerCpuHashMap::<_, CtContractKey, CtContractValue>::try_from(
                aya::maps::Map::PerCpuHashMap(map_data),
            )
            .map_err(|e| format!("convert CT_CONTRACT_STATS to PerCpuHashMap: {:?}", e))
        }),
    );

    record_optional_scrub(
        tap_id,
        "RULE_STATS",
        &mut removed,
        scrub_per_cpu_hash_map(pin_path, "RULE_STATS", tap_id, |map_data| {
            PerCpuHashMap::<_, PolicyKey, RuleStatsValue>::try_from(
                aya::maps::Map::PerCpuHashMap(map_data),
            )
            .map_err(|e| format!("convert RULE_STATS to PerCpuHashMap: {:?}", e))
        }),
    );
    record_optional_scrub(
        tap_id,
        "FLOW_STATS_V4",
        &mut removed,
        scrub_per_cpu_hash_map(pin_path, "FLOW_STATS_V4", tap_id, |map_data| {
            PerCpuHashMap::<_, CtKey4, FlowStatsValue>::try_from(
                aya::maps::Map::PerCpuLruHashMap(map_data),
            )
            .map_err(|e| format!("convert FLOW_STATS_V4 to PerCpuHashMap: {:?}", e))
        }),
    );
    record_optional_scrub(
        tap_id,
        "FLOW_STATS_V6",
        &mut removed,
        scrub_per_cpu_hash_map(pin_path, "FLOW_STATS_V6", tap_id, |map_data| {
            PerCpuHashMap::<_, CtKey6, FlowStatsValue>::try_from(
                aya::maps::Map::PerCpuLruHashMap(map_data),
            )
            .map_err(|e| format!("convert FLOW_STATS_V6 to PerCpuHashMap: {:?}", e))
        }),
    );

    removed += scrub_hash_map(pin_path, "QOS_CONFIG", tap_id, |map_data| {
        HashMap::<_, QosKey, QosConfig>::try_from(aya::maps::Map::HashMap(map_data))
            .map_err(|e| format!("convert QOS_CONFIG to HashMap: {:?}", e))
    })?;
    removed += scrub_hash_map(pin_path, "QOS_TOKEN_BUCKET", tap_id, |map_data| {
        HashMap::<_, QosKey, TokenBucket>::try_from(aya::maps::Map::HashMap(map_data))
            .map_err(|e| format!("convert QOS_TOKEN_BUCKET to HashMap: {:?}", e))
    })?;
    record_optional_scrub(
        tap_id,
        "QOS_STATS",
        &mut removed,
        scrub_per_cpu_hash_map(pin_path, "QOS_STATS", tap_id, |map_data| {
            PerCpuHashMap::<_, QosKey, QosStatsValue>::try_from(
                aya::maps::Map::PerCpuHashMap(map_data),
            )
            .map_err(|e| format!("convert QOS_STATS to PerCpuHashMap: {:?}", e))
        }),
    );
    record_optional_scrub(
        tap_id,
        "GROUP_STATS",
        &mut removed,
        scrub_per_cpu_hash_map(pin_path, "GROUP_STATS", tap_id, |map_data| {
            PerCpuHashMap::<_, GroupStatsKey, GroupStatsValue>::try_from(
                aya::maps::Map::PerCpuHashMap(map_data),
            )
            .map_err(|e| format!("convert GROUP_STATS to PerCpuHashMap: {:?}", e))
        }),
    );

    removed += scrub_hash_map(pin_path, "MIRROR_POLICY", tap_id, |map_data| {
        HashMap::<_, MirrorKey, MirrorConfig>::try_from(aya::maps::Map::HashMap(map_data))
            .map_err(|e| format!("convert MIRROR_POLICY to HashMap: {:?}", e))
    })?;
    removed += scrub_hash_map(pin_path, "MIRROR_GLOBAL", tap_id, |map_data| {
        HashMap::<_, GlobalMirrorKey, MirrorConfig>::try_from(aya::maps::Map::HashMap(map_data))
            .map_err(|e| format!("convert MIRROR_GLOBAL to HashMap: {:?}", e))
    })?;
    record_optional_scrub(
        tap_id,
        "MIRROR_STATS",
        &mut removed,
        scrub_per_cpu_hash_map(pin_path, "MIRROR_STATS", tap_id, |map_data| {
            PerCpuHashMap::<_, MirrorKey, MirrorStatsValue>::try_from(
                aya::maps::Map::PerCpuHashMap(map_data),
            )
            .map_err(|e| format!("convert MIRROR_STATS to PerCpuHashMap: {:?}", e))
        }),
    );
    record_optional_scrub(
        tap_id,
        "MIRROR_GLOBAL_STATS",
        &mut removed,
        scrub_per_cpu_hash_map(pin_path, "MIRROR_GLOBAL_STATS", tap_id, |map_data| {
            PerCpuHashMap::<_, GlobalMirrorKey, MirrorStatsValue>::try_from(
                aya::maps::Map::PerCpuHashMap(map_data),
            )
            .map_err(|e| format!("convert MIRROR_GLOBAL_STATS to PerCpuHashMap: {:?}", e))
        }),
    );

    removed += crate::tcprt_ops::scrub_tcprt_tables_strict(runtime)?;
    record_optional_scrub(
        tap_id,
        "DROP_REASON_STATS",
        &mut removed,
        crate::drop_ops::flush_drop_stats(runtime),
    );
    removed += crate::trace_ops::scrub_trace_filter(runtime)?;
    record_optional_scrub(
        tap_id,
        "TRACE_LOG",
        &mut removed,
        crate::trace_ops::flush_trace_log(runtime),
    );

    info!(tap_id, removed_entries = removed, scope, "scrubbed runtime state");
    Ok(removed)
}

/// Scrub all tap-scoped entries from the shared managed runtime before replay.
/// This makes replay idempotent and cleans up partial state left by failed attach attempts.
pub fn scrub_managed_runtime_state(runtime: TapMapRuntime<'_>) -> Result<u64, String> {
    if runtime.tap_id == TAP_ID_UNASSIGNED {
        return Ok(0);
    }

    scrub_runtime_state(runtime, "managed")
}

/// Scrub all standalone tap-scoped entries before replaying persisted system state.
pub fn scrub_standalone_runtime_state(pin_path: &str) -> Result<u64, String> {
    scrub_runtime_state(TapMapRuntime::new(pin_path, TAP_ID_UNASSIGNED), "standalone")
}
