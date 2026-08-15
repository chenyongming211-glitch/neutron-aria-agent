use super::*;

trait HasTapId {
    fn tap_id(&self) -> u32;
}

impl HasTapId for PolicyKey {
    fn tap_id(&self) -> u32 {
        self.tap_id
    }
}

impl HasTapId for PortKey {
    fn tap_id(&self) -> u32 {
        self.tap_id
    }
}

impl HasTapId for CtKey4 {
    fn tap_id(&self) -> u32 {
        self.tap_id
    }
}

impl HasTapId for CtKey6 {
    fn tap_id(&self) -> u32 {
        self.tap_id
    }
}

impl HasTapId for CtContractKey {
    fn tap_id(&self) -> u32 {
        self.tap_id
    }
}

impl HasTapId for QosKey {
    fn tap_id(&self) -> u32 {
        self.tap_id
    }
}

impl HasTapId for GroupStatsKey {
    fn tap_id(&self) -> u32 {
        self.tap_id
    }
}

impl HasTapId for MirrorKey {
    fn tap_id(&self) -> u32 {
        self.tap_id
    }
}

impl HasTapId for GlobalMirrorKey {
    fn tap_id(&self) -> u32 {
        self.tap_id
    }
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
    let map_data =
        MapData::from_pin(&map_path).map_err(|e| format!("open pinned {}: {:?}", map_name, e))?;
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
    let map_data =
        MapData::from_pin(&map_path).map_err(|e| format!("open pinned {}: {:?}", map_name, e))?;
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

fn policy_key_matches_bank(key: &PolicyKey, tap_id: u32, bank: u8) -> bool {
    key.tap_id == tap_id && normalize_acl_bank(key.bank) == normalize_acl_bank(bank)
}

fn scrub_policy_bank_map(pin_path: &str, tap_id: u32, bank: u8) -> Result<u64, String> {
    let map_path = format!("{}/POLICY_TABLE", pin_path);
    let map_data =
        MapData::from_pin(&map_path).map_err(|e| format!("open pinned POLICY_TABLE: {:?}", e))?;
    let mut map = HashMap::<_, PolicyKey, PolicyValue>::try_from(aya::maps::Map::HashMap(map_data))
        .map_err(|e| format!("convert POLICY_TABLE to HashMap: {:?}", e))?;
    let keys: Vec<PolicyKey> = map
        .iter()
        .filter_map(|item| item.ok().map(|(key, _)| key))
        .filter(|key| policy_key_matches_bank(key, tap_id, bank))
        .collect();
    let count = keys.len() as u64;
    for key in keys {
        map.remove(&key)
            .map_err(|e| format!("remove POLICY_TABLE bank entry: {:?}", e))?;
    }
    Ok(count)
}

fn scrub_rule_stats_bank_map(pin_path: &str, tap_id: u32, bank: u8) -> Result<u64, String> {
    let map_path = format!("{}/RULE_STATS", pin_path);
    let map_data =
        MapData::from_pin(&map_path).map_err(|e| format!("open pinned RULE_STATS: {:?}", e))?;
    let mut map = PerCpuHashMap::<_, PolicyKey, RuleStatsValue>::try_from(
        aya::maps::Map::PerCpuHashMap(map_data),
    )
    .map_err(|e| format!("convert RULE_STATS to PerCpuHashMap: {:?}", e))?;
    let keys: Vec<PolicyKey> = map
        .keys()
        .filter_map(|item| item.ok())
        .filter(|key| policy_key_matches_bank(key, tap_id, bank))
        .collect();
    let count = keys.len() as u64;
    for key in keys {
        map.remove(&key)
            .map_err(|e| format!("remove RULE_STATS bank entry: {:?}", e))?;
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
        map.remove(&ifindex).map_err(|e| {
            format!(
                "remove IFACE_CTX_MAP entry for ifindex {}: {:?}",
                ifindex, e
            )
        })?;
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

pub fn scrub_acl_bank(runtime: TapMapRuntime<'_>, bank: u8) -> Result<u64, String> {
    let pin_path = runtime.pin_path;
    let tap_id = runtime.tap_id;
    let bank = normalize_acl_bank(bank);
    let lpm_tap_id = acl_banked_tap_id(tap_id, bank);
    let mut removed = 0u64;

    removed += scrub_lpm_v4_map(pin_path, "ACL_SRC_IPV4_TRIE", lpm_tap_id)?;
    removed += scrub_lpm_v4_map(pin_path, "ACL_DST_IPV4_TRIE", lpm_tap_id)?;
    removed += scrub_lpm_v6_map(pin_path, "ACL_SRC_IPV6_TRIE", lpm_tap_id)?;
    removed += scrub_lpm_v6_map(pin_path, "ACL_DST_IPV6_TRIE", lpm_tap_id)?;
    removed += scrub_policy_bank_map(pin_path, tap_id, bank)?;
    record_optional_scrub(
        tap_id,
        "RULE_STATS",
        &mut removed,
        scrub_rule_stats_bank_map(pin_path, tap_id, bank),
    );

    info!(
        tap_id,
        bank,
        removed_entries = removed,
        "scrubbed ACL shadow bank"
    );
    Ok(removed)
}

fn scrub_runtime_state(runtime: TapMapRuntime<'_>, scope: &'static str) -> Result<u64, String> {
    let pin_path = runtime.pin_path;
    let tap_id = runtime.tap_id;
    let mut removed = 0u64;

    removed += scrub_iface_ctx_entries(pin_path, tap_id)?;
    removed += scrub_tap_config_entries(pin_path, tap_id)?;
    removed += scrub_fragment_contexts_strict(runtime)?;

    removed += scrub_lpm_v4_map(pin_path, "SRC_IPV4_TRIE", tap_id)?;
    removed += scrub_lpm_v4_map(pin_path, "DST_IPV4_TRIE", tap_id)?;
    removed += scrub_lpm_v6_map(pin_path, "SRC_IPV6_TRIE", tap_id)?;
    removed += scrub_lpm_v6_map(pin_path, "DST_IPV6_TRIE", tap_id)?;
    record_optional_scrub(
        tap_id,
        "ACL_SRC_IPV4_TRIE",
        &mut removed,
        scrub_lpm_v4_map(pin_path, "ACL_SRC_IPV4_TRIE", acl_banked_tap_id(tap_id, 0)),
    );
    record_optional_scrub(
        tap_id,
        "ACL_DST_IPV4_TRIE",
        &mut removed,
        scrub_lpm_v4_map(pin_path, "ACL_DST_IPV4_TRIE", acl_banked_tap_id(tap_id, 0)),
    );
    record_optional_scrub(
        tap_id,
        "ACL_SRC_IPV6_TRIE",
        &mut removed,
        scrub_lpm_v6_map(pin_path, "ACL_SRC_IPV6_TRIE", acl_banked_tap_id(tap_id, 0)),
    );
    record_optional_scrub(
        tap_id,
        "ACL_DST_IPV6_TRIE",
        &mut removed,
        scrub_lpm_v6_map(pin_path, "ACL_DST_IPV6_TRIE", acl_banked_tap_id(tap_id, 0)),
    );
    record_optional_scrub(
        tap_id,
        "ACL_SRC_IPV4_TRIE",
        &mut removed,
        scrub_lpm_v4_map(pin_path, "ACL_SRC_IPV4_TRIE", acl_banked_tap_id(tap_id, 1)),
    );
    record_optional_scrub(
        tap_id,
        "ACL_DST_IPV4_TRIE",
        &mut removed,
        scrub_lpm_v4_map(pin_path, "ACL_DST_IPV4_TRIE", acl_banked_tap_id(tap_id, 1)),
    );
    record_optional_scrub(
        tap_id,
        "ACL_SRC_IPV6_TRIE",
        &mut removed,
        scrub_lpm_v6_map(pin_path, "ACL_SRC_IPV6_TRIE", acl_banked_tap_id(tap_id, 1)),
    );
    record_optional_scrub(
        tap_id,
        "ACL_DST_IPV6_TRIE",
        &mut removed,
        scrub_lpm_v6_map(pin_path, "ACL_DST_IPV6_TRIE", acl_banked_tap_id(tap_id, 1)),
    );

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
            PerCpuHashMap::<_, PolicyKey, RuleStatsValue>::try_from(aya::maps::Map::PerCpuHashMap(
                map_data,
            ))
            .map_err(|e| format!("convert RULE_STATS to PerCpuHashMap: {:?}", e))
        }),
    );
    record_optional_scrub(
        tap_id,
        "FLOW_STATS_V4",
        &mut removed,
        scrub_per_cpu_hash_map(pin_path, "FLOW_STATS_V4", tap_id, |map_data| {
            PerCpuHashMap::<_, CtKey4, FlowStatsValue>::try_from(aya::maps::Map::PerCpuLruHashMap(
                map_data,
            ))
            .map_err(|e| format!("convert FLOW_STATS_V4 to PerCpuHashMap: {:?}", e))
        }),
    );
    record_optional_scrub(
        tap_id,
        "FLOW_STATS_V6",
        &mut removed,
        scrub_per_cpu_hash_map(pin_path, "FLOW_STATS_V6", tap_id, |map_data| {
            PerCpuHashMap::<_, CtKey6, FlowStatsValue>::try_from(aya::maps::Map::PerCpuLruHashMap(
                map_data,
            ))
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
            PerCpuHashMap::<_, QosKey, QosStatsValue>::try_from(aya::maps::Map::PerCpuHashMap(
                map_data,
            ))
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

    info!(
        tap_id,
        removed_entries = removed,
        scope,
        "scrubbed runtime state"
    );
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
    scrub_runtime_state(
        TapMapRuntime::new(pin_path, TAP_ID_UNASSIGNED),
        "standalone",
    )
}

#[cfg(test)]
mod tests {
    use super::collect_iterated_items;
    use super::policy_key_matches_bank;
    use crate::common::PolicyKey;

    #[test]
    fn policy_key_matches_bank_requires_same_tap_and_bank() {
        let key = PolicyKey {
            tap_id: 3,
            src_id: 10,
            dst_id: 20,
            proto: 6,
            direction: 1,
            bank: 1,
            pad: [0; 1],
        };

        assert!(policy_key_matches_bank(&key, 3, 1));
        assert!(!policy_key_matches_bank(&key, 3, 0));
        assert!(!policy_key_matches_bank(&key, 4, 1));
    }

    #[test]
    fn scrub_iteration_propagates_first_error() {
        let items = vec![Ok(1u32), Ok(2u32), Err("injected"), Ok(4u32)];
        let result: Result<Vec<u32>, String> = collect_iterated_items(items, "TEST_MAP");

        match result {
            Err(error) => assert!(error.contains("injected")),
            Ok(_) => panic!("expected the iteration error to propagate"),
        }
    }

    #[test]
    fn scrub_iteration_collects_all_healthy_items() {
        let items = vec![Ok(1u32), Ok(2u32), Ok(3u32)];
        let result: Result<Vec<u32>, String> = collect_iterated_items(items, "TEST_MAP");

        assert_eq!(vec![1, 2, 3], result.unwrap());
    }
}
