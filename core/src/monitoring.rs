use crate::common::{
    fragment_metric_index, CtKey4, CtKey6, CtValue, FlowStatsValue, FragmentContextKey4,
    FragmentContextKey6, FragmentContextValue, GlobalMirrorKey, GroupStatsKey, GroupStatsValue,
    MirrorKey, MirrorStatsValue, PolicyKey, QosKey, QosStatsValue, RuleStatsValue, TapMapRuntime,
    TcpRtValue, CT_ESTABLISHED, CT_NEW, FRAGMENT_FAMILY_IPV4, FRAGMENT_FAMILY_IPV6,
    FRAGMENT_METRIC_CONTEXT_EXPIRED, FRAGMENT_METRIC_CONTEXT_HIT, FRAGMENT_METRIC_CONTEXT_INSERTED,
    FRAGMENT_METRIC_CONTEXT_MISSING, FRAGMENT_METRIC_CONTEXT_OVERLAP,
    FRAGMENT_METRIC_CONTEXT_STALE, FRAGMENT_METRIC_CONTEXT_UPDATE_FAILED, FRAGMENT_METRIC_FIRST,
    FRAGMENT_METRIC_INVALID_L4, FRAGMENT_METRIC_NON_INITIAL,
};
use aya::maps::{HashMap, Map, MapData, MapType, PerCpuArray, PerCpuHashMap, PerCpuValues};
use std::collections::HashSet;
use std::hash::Hash;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::Path;

pub struct RuleStatsEntry {
    pub key: PolicyKey,
    pub packets: u64,
    pub bytes: u64,
    pub dropped_packets: u64,
    pub dropped_bytes: u64,
}

pub struct FlowStatsEntry {
    pub src_ip: Ipv4Addr,
    pub dst_ip: Ipv4Addr,
    pub src_port: u16,
    pub dst_port: u16,
    pub proto: u8,
    pub packets: u64,
    pub bytes: u64,
    pub last_seen: u64,
}

pub struct FlowStatsEntryV6 {
    pub src_ip: Ipv6Addr,
    pub dst_ip: Ipv6Addr,
    pub src_port: u16,
    pub dst_port: u16,
    pub proto: u8,
    pub packets: u64,
    pub bytes: u64,
    pub last_seen: u64,
}

pub struct ConntrackSummary {
    pub total_v4: u64,
    pub total_v6: u64,
    pub new_count: u64,
    pub established_count: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FragmentMetricCounter {
    pub family: u8,
    pub metric: u8,
    pub value: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FragmentPressure {
    pub family: u8,
    pub occupancy: u32,
    pub max_entries: u32,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct FragmentMetricsSummary {
    pub counters: Vec<FragmentMetricCounter>,
    pub pressure: Vec<FragmentPressure>,
    pub warnings: Vec<String>,
}

const EXPORTED_FRAGMENT_METRICS: [u8; 10] = [
    FRAGMENT_METRIC_FIRST,
    FRAGMENT_METRIC_NON_INITIAL,
    FRAGMENT_METRIC_CONTEXT_HIT,
    FRAGMENT_METRIC_CONTEXT_MISSING,
    FRAGMENT_METRIC_CONTEXT_EXPIRED,
    FRAGMENT_METRIC_CONTEXT_STALE,
    FRAGMENT_METRIC_CONTEXT_INSERTED,
    FRAGMENT_METRIC_CONTEXT_UPDATE_FAILED,
    FRAGMENT_METRIC_INVALID_L4,
    FRAGMENT_METRIC_CONTEXT_OVERLAP,
];

pub fn fragment_pressure_ratio(occupancy: u32, max_entries: u32) -> Option<f64> {
    (max_entries != 0).then(|| occupancy as f64 / max_entries as f64)
}

fn require_map_type(map_data: &MapData, map_name: &str, expected: MapType) -> Result<(), String> {
    let actual = map_data
        .info()
        .and_then(|info| info.map_type())
        .map_err(|error| format!("inspect pinned {} type: {:?}", map_name, error))?;
    if actual != expected {
        return Err(format!(
            "pinned {} has map type {:?}; expected {:?}",
            map_name, actual, expected
        ));
    }
    Ok(())
}

fn collect_fragment_counters_with<F>(mut read_index: F) -> (Vec<FragmentMetricCounter>, Vec<String>)
where
    F: FnMut(u32) -> Result<u64, String>,
{
    let map_name = "FRAGMENT_METRICS";
    let mut counters = Vec::with_capacity(EXPORTED_FRAGMENT_METRICS.len() * 2);
    let mut warnings = Vec::new();
    for family in [FRAGMENT_FAMILY_IPV4, FRAGMENT_FAMILY_IPV6] {
        for metric in EXPORTED_FRAGMENT_METRICS {
            let Some(index) = fragment_metric_index(metric, family) else {
                warnings.push(format!(
                    "derive {} index for metric {} family {}",
                    map_name, metric, family
                ));
                continue;
            };
            match read_index(index) {
                Ok(value) => counters.push(FragmentMetricCounter {
                    family,
                    metric,
                    value,
                }),
                Err(error) => warnings.push(format!(
                    "read {} metric {} family {} index {}: {}",
                    map_name, metric, family, index, error
                )),
            }
        }
    }
    (counters, warnings)
}

fn collect_fragment_counters(
    pin_path: &str,
) -> Result<(Vec<FragmentMetricCounter>, Vec<String>), String> {
    let map_name = "FRAGMENT_METRICS";
    let map_path = format!("{}/{}", pin_path, map_name);
    let map_data = MapData::from_pin(&map_path)
        .map_err(|error| format!("open pinned {}: {:?}", map_name, error))?;
    require_map_type(&map_data, map_name, MapType::PerCpuArray)?;
    let map = PerCpuArray::<_, u64>::try_from(Map::PerCpuArray(map_data))
        .map_err(|error| format!("convert {} to PerCpuArray<u64>: {:?}", map_name, error))?;

    Ok(collect_fragment_counters_with(|index| {
        map.get(&index, 0)
            .map(|values| values.iter().copied().sum())
            .map_err(|error| format!("{:?}", error))
    }))
}

fn collect_fragment_pressure_with<K, I>(
    map_name: &str,
    family: u8,
    max_entries: u32,
    keys: I,
) -> Result<FragmentPressure, String>
where
    K: Eq + Hash,
    I: IntoIterator<Item = Result<K, String>>,
{
    if max_entries == 0 {
        return Err(format!("pinned {} reports zero capacity", map_name));
    }

    let observation_budget = u64::from(max_entries) + 1;
    let mut keys = keys.into_iter();
    let mut unique_keys = HashSet::new();
    for _ in 0..observation_budget {
        let key = match keys.next() {
            None => {
                return Ok(FragmentPressure {
                    family,
                    occupancy: unique_keys.len() as u32,
                    max_entries,
                });
            }
            Some(Ok(key)) => key,
            Some(Err(error)) => return Err(format!("iterate {}: {}", map_name, error)),
        };
        if !unique_keys.insert(key) {
            return Err(format!(
                "iterate {} returned duplicate key before natural end",
                map_name
            ));
        }
        if unique_keys.len() as u64 > u64::from(max_entries) {
            return Err(format!(
                "iterate {} unique occupancy {} exceeds max_entries {}",
                map_name,
                unique_keys.len(),
                max_entries
            ));
        }
    }

    Err(format!(
        "iterate {} observation budget exhausted after {} entries",
        map_name, observation_budget
    ))
}

fn collect_fragment_pressure_v4(pin_path: &str) -> Result<FragmentPressure, String> {
    let map_name = "FRAG_CONTEXT_V4";
    let map_path = format!("{}/{}", pin_path, map_name);
    let map_data = MapData::from_pin(&map_path)
        .map_err(|error| format!("open pinned {}: {:?}", map_name, error))?;
    require_map_type(&map_data, map_name, MapType::LruHash)?;
    let max_entries = map_data
        .info()
        .map(|info| info.max_entries())
        .map_err(|error| format!("inspect pinned {} capacity: {:?}", map_name, error))?;
    let map = HashMap::<_, FragmentContextKey4, FragmentContextValue>::try_from(Map::LruHashMap(
        map_data,
    ))
    .map_err(|error| format!("convert {} to LruHashMap: {:?}", map_name, error))?;
    collect_fragment_pressure_with(
        map_name,
        FRAGMENT_FAMILY_IPV4,
        max_entries,
        map.keys()
            .map(|item| item.map_err(|error| format!("{:?}", error))),
    )
}

fn collect_fragment_pressure_v6(pin_path: &str) -> Result<FragmentPressure, String> {
    let map_name = "FRAG_CONTEXT_V6";
    let map_path = format!("{}/{}", pin_path, map_name);
    let map_data = MapData::from_pin(&map_path)
        .map_err(|error| format!("open pinned {}: {:?}", map_name, error))?;
    require_map_type(&map_data, map_name, MapType::LruHash)?;
    let max_entries = map_data
        .info()
        .map(|info| info.max_entries())
        .map_err(|error| format!("inspect pinned {} capacity: {:?}", map_name, error))?;
    let map = HashMap::<_, FragmentContextKey6, FragmentContextValue>::try_from(Map::LruHashMap(
        map_data,
    ))
    .map_err(|error| format!("convert {} to LruHashMap: {:?}", map_name, error))?;
    collect_fragment_pressure_with(
        map_name,
        FRAGMENT_FAMILY_IPV6,
        max_entries,
        map.keys()
            .map(|item| item.map_err(|error| format!("{:?}", error))),
    )
}

fn record_fragment_pressure_result(
    summary: &mut FragmentMetricsSummary,
    result: Result<FragmentPressure, String>,
) {
    match result {
        Ok(pressure) => summary.pressure.push(pressure),
        Err(error) => summary.warnings.push(error),
    }
}

pub fn get_fragment_metrics_summary(pin_path: &str) -> FragmentMetricsSummary {
    let mut summary = FragmentMetricsSummary::default();
    match collect_fragment_counters(pin_path) {
        Ok((counters, warnings)) => {
            summary.counters = counters;
            summary.warnings.extend(warnings);
        }
        Err(error) => summary.warnings.push(error),
    }
    record_fragment_pressure_result(&mut summary, collect_fragment_pressure_v4(pin_path));
    record_fragment_pressure_result(&mut summary, collect_fragment_pressure_v6(pin_path));
    summary
}

#[cfg(test)]
mod fragment_observability_tests {
    use super::{
        collect_fragment_counters_with, collect_fragment_pressure_with,
        record_fragment_pressure_result, FragmentMetricsSummary,
    };
    use crate::common::{
        fragment_metric_index, FragmentContextKey4, FRAGMENT_FAMILY_IPV4, FRAGMENT_FAMILY_IPV6,
        FRAGMENT_METRIC_FIRST, FRAGMENT_METRIC_INVALID_L4,
    };

    fn v4_key(fragment_id: u16) -> FragmentContextKey4 {
        FragmentContextKey4 {
            tap_id: 7,
            src_ip: 0xc000_0201,
            dst_ip: 0xc633_6401,
            fragment_id,
            vlan_id: 9,
            proto: 17,
            direction: 1,
            _pad: [0; 2],
        }
    }

    fn pressure_summary(result: Result<super::FragmentPressure, String>) -> FragmentMetricsSummary {
        let mut summary = FragmentMetricsSummary::default();
        record_fragment_pressure_result(&mut summary, result);
        summary
    }

    #[test]
    fn fragment_observability_single_counter_read_failure_omits_only_that_series() {
        let failed_index =
            fragment_metric_index(FRAGMENT_METRIC_FIRST, FRAGMENT_FAMILY_IPV6).unwrap();

        let (counters, warnings) = collect_fragment_counters_with(|index| {
            if index == failed_index {
                Err("synthetic index read failure".to_string())
            } else {
                Ok(index as u64)
            }
        });

        assert_eq!(counters.len(), 19);
        assert!(!counters.iter().any(|counter| {
            counter.family == FRAGMENT_FAMILY_IPV6 && counter.metric == FRAGMENT_METRIC_FIRST
        }));
        assert!(counters.iter().any(|counter| {
            counter.family == FRAGMENT_FAMILY_IPV4
                && counter.metric == FRAGMENT_METRIC_FIRST
                && counter.value == 2
        }));
        assert!(counters.iter().any(|counter| {
            counter.family == FRAGMENT_FAMILY_IPV6
                && counter.metric == FRAGMENT_METRIC_INVALID_L4
                && counter.value == 35
        }));
        assert_eq!(
            warnings,
            vec!["read FRAGMENT_METRICS metric 1 family 6 index 3: synthetic index read failure"]
        );
    }

    #[test]
    fn fragment_observability_duplicate_lru_key_omits_pressure_and_warns() {
        let key = v4_key(1);
        let summary = pressure_summary(collect_fragment_pressure_with(
            "FRAG_CONTEXT_V4",
            FRAGMENT_FAMILY_IPV4,
            2,
            vec![Ok(key), Ok(key)],
        ));

        assert!(summary.pressure.is_empty());
        assert_eq!(summary.warnings.len(), 1);
        assert!(summary.warnings[0].contains("duplicate key"));
    }

    #[test]
    fn fragment_observability_unique_lru_keys_over_capacity_omit_pressure_and_warn() {
        let summary = pressure_summary(collect_fragment_pressure_with(
            "FRAG_CONTEXT_V4",
            FRAGMENT_FAMILY_IPV4,
            2,
            vec![Ok(v4_key(1)), Ok(v4_key(2)), Ok(v4_key(3))],
        ));

        assert!(summary.pressure.is_empty());
        assert_eq!(summary.warnings.len(), 1);
        assert!(summary.warnings[0].contains("exceeds max_entries 2"));
    }

    #[test]
    fn fragment_observability_lru_iteration_error_omits_pressure_and_warns() {
        let summary = pressure_summary(collect_fragment_pressure_with(
            "FRAG_CONTEXT_V4",
            FRAGMENT_FAMILY_IPV4,
            2,
            vec![Ok(v4_key(1)), Err("synthetic iterator failure".to_string())],
        ));

        assert!(summary.pressure.is_empty());
        assert_eq!(summary.warnings.len(), 1);
        assert!(summary.warnings[0].contains("synthetic iterator failure"));
    }

    #[test]
    fn fragment_observability_natural_unique_lru_end_reports_exact_bounded_occupancy() {
        let summary = pressure_summary(collect_fragment_pressure_with(
            "FRAG_CONTEXT_V4",
            FRAGMENT_FAMILY_IPV4,
            3,
            vec![Ok(v4_key(1)), Ok(v4_key(2))],
        ));

        assert!(summary.warnings.is_empty());
        assert_eq!(summary.pressure.len(), 1);
        assert_eq!(summary.pressure[0].occupancy, 2);
        assert_eq!(summary.pressure[0].max_entries, 3);
        assert!(summary.pressure[0].occupancy <= summary.pressure[0].max_entries);
    }
}

fn sum_per_cpu_rule_stats(values: PerCpuValues<RuleStatsValue>) -> (u64, u64, u64, u64) {
    let mut packets = 0u64;
    let mut bytes = 0u64;
    let mut dropped_packets = 0u64;
    let mut dropped_bytes = 0u64;
    for v in values.iter() {
        packets += v.packets;
        bytes += v.bytes;
        dropped_packets += v.dropped_packets;
        dropped_bytes += v.dropped_bytes;
    }
    (packets, bytes, dropped_packets, dropped_bytes)
}

fn sum_per_cpu_flow_stats(values: PerCpuValues<FlowStatsValue>) -> (u64, u64, u64) {
    let mut packets = 0u64;
    let mut bytes = 0u64;
    let mut last_seen = 0u64;
    for v in values.iter() {
        packets += v.packets;
        bytes += v.bytes;
        if v.last_seen > last_seen {
            last_seen = v.last_seen;
        }
    }
    (packets, bytes, last_seen)
}

pub fn get_rule_stats(runtime: TapMapRuntime<'_>) -> Result<Vec<RuleStatsEntry>, String> {
    let pin_path = runtime.pin_path;
    let map_path = format!("{}/RULE_STATS", pin_path);
    let map_data = MapData::from_pin(&map_path).map_err(|e| format!("open RULE_STATS: {:?}", e))?;
    let map = PerCpuHashMap::<_, PolicyKey, RuleStatsValue>::try_from(
        aya::maps::Map::PerCpuHashMap(map_data),
    )
    .map_err(|e| format!("convert RULE_STATS: {:?}", e))?;

    let mut entries = Vec::new();
    for item in map.iter() {
        match item {
            Ok((key, values)) => {
                if key.tap_id != runtime.tap_id {
                    continue;
                }
                let (packets, bytes, dropped_packets, dropped_bytes) =
                    sum_per_cpu_rule_stats(values);
                if packets > 0 {
                    entries.push(RuleStatsEntry {
                        key,
                        packets,
                        bytes,
                        dropped_packets,
                        dropped_bytes,
                    });
                }
            }
            Err(_) => continue,
        }
    }

    entries.sort_by(|a, b| b.bytes.cmp(&a.bytes));
    Ok(entries)
}

pub fn get_top_flows_v4(
    runtime: TapMapRuntime<'_>,
    n: usize,
) -> Result<Vec<FlowStatsEntry>, String> {
    let pin_path = runtime.pin_path;
    let map_path = format!("{}/FLOW_STATS_V4", pin_path);
    let map_data =
        MapData::from_pin(&map_path).map_err(|e| format!("open FLOW_STATS_V4: {:?}", e))?;
    // LruPerCpuHashMap on kernel side → PerCpuLruHashMap enum variant in aya
    let map = PerCpuHashMap::<_, CtKey4, FlowStatsValue>::try_from(
        aya::maps::Map::PerCpuLruHashMap(map_data),
    )
    .map_err(|e| format!("convert FLOW_STATS_V4: {:?}", e))?;

    let mut entries = Vec::new();
    for item in map.iter() {
        match item {
            Ok((key, values)) => {
                if key.tap_id != runtime.tap_id {
                    continue;
                }
                let (packets, bytes, last_seen) = sum_per_cpu_flow_stats(values);
                if packets > 0 {
                    entries.push(FlowStatsEntry {
                        src_ip: Ipv4Addr::from(key.src_ip),
                        dst_ip: Ipv4Addr::from(key.dst_ip),
                        src_port: key.src_port,
                        dst_port: key.dst_port,
                        proto: key.proto,
                        packets,
                        bytes,
                        last_seen,
                    });
                }
            }
            Err(_) => continue,
        }
    }

    entries.sort_by(|a, b| b.bytes.cmp(&a.bytes));
    entries.truncate(n);
    Ok(entries)
}

pub fn get_top_flows_v6(
    runtime: TapMapRuntime<'_>,
    n: usize,
) -> Result<Vec<FlowStatsEntryV6>, String> {
    let pin_path = runtime.pin_path;
    let map_path = format!("{}/FLOW_STATS_V6", pin_path);
    let map_data =
        MapData::from_pin(&map_path).map_err(|e| format!("open FLOW_STATS_V6: {:?}", e))?;
    // 内核端是 LruPerCpuHashMap，这里对应 PerCpuLruHashMap 分支。
    let map = PerCpuHashMap::<_, CtKey6, FlowStatsValue>::try_from(
        aya::maps::Map::PerCpuLruHashMap(map_data),
    )
    .map_err(|e| format!("convert FLOW_STATS_V6: {:?}", e))?;

    let mut entries = Vec::new();
    for item in map.iter() {
        match item {
            Ok((key, values)) => {
                if key.tap_id != runtime.tap_id {
                    continue;
                }
                let (packets, bytes, last_seen) = sum_per_cpu_flow_stats(values);
                if packets > 0 {
                    entries.push(FlowStatsEntryV6 {
                        src_ip: Ipv6Addr::from(key.src_ip),
                        dst_ip: Ipv6Addr::from(key.dst_ip),
                        src_port: key.src_port,
                        dst_port: key.dst_port,
                        proto: key.proto,
                        packets,
                        bytes,
                        last_seen,
                    });
                }
            }
            Err(_) => continue,
        }
    }

    entries.sort_by(|a, b| b.bytes.cmp(&a.bytes));
    entries.truncate(n);
    Ok(entries)
}

pub fn get_conntrack_stats(runtime: TapMapRuntime<'_>) -> Result<ConntrackSummary, String> {
    let pin_path = runtime.pin_path;
    let mut summary = ConntrackSummary {
        total_v4: 0,
        total_v6: 0,
        new_count: 0,
        established_count: 0,
    };

    // CT_TABLE_V4 — LruHashMap on kernel side
    let map_path = format!("{}/CT_TABLE_V4", pin_path);
    if let Ok(map_data) = MapData::from_pin(&map_path) {
        if let Ok(map) =
            HashMap::<_, CtKey4, CtValue>::try_from(aya::maps::Map::LruHashMap(map_data))
        {
            for item in map.iter() {
                if let Ok((key, val)) = item {
                    if key.tap_id != runtime.tap_id {
                        continue;
                    }
                    summary.total_v4 += 1;
                    match val.state {
                        CT_NEW => summary.new_count += 1,
                        CT_ESTABLISHED => summary.established_count += 1,
                        _ => {}
                    }
                }
            }
        }
    }

    // CT_TABLE_V6 — LruHashMap on kernel side
    let map_path = format!("{}/CT_TABLE_V6", pin_path);
    if let Ok(map_data) = MapData::from_pin(&map_path) {
        if let Ok(map) =
            HashMap::<_, CtKey6, CtValue>::try_from(aya::maps::Map::LruHashMap(map_data))
        {
            for item in map.iter() {
                if let Ok((key, val)) = item {
                    if key.tap_id != runtime.tap_id {
                        continue;
                    }
                    summary.total_v6 += 1;
                    match val.state {
                        CT_NEW => summary.new_count += 1,
                        CT_ESTABLISHED => summary.established_count += 1,
                        _ => {}
                    }
                }
            }
        }
    }

    Ok(summary)
}

// --- QoS Statistics ---

pub struct QosStatsEntry {
    pub key: QosKey,
    pub passed_packets: u64,
    pub passed_bytes: u64,
    pub dropped_packets: u64,
    pub dropped_bytes: u64,
    pub shaped_packets: u64,
    pub shaped_bytes: u64,
}

fn sum_per_cpu_qos_stats(values: PerCpuValues<QosStatsValue>) -> (u64, u64, u64, u64, u64, u64) {
    let mut pp = 0u64;
    let mut pb = 0u64;
    let mut dp = 0u64;
    let mut db = 0u64;
    let mut sp = 0u64;
    let mut sb = 0u64;
    for v in values.iter() {
        pp += v.passed_packets;
        pb += v.passed_bytes;
        dp += v.dropped_packets;
        db += v.dropped_bytes;
        sp += v.shaped_packets;
        sb += v.shaped_bytes;
    }
    (pp, pb, dp, db, sp, sb)
}

pub fn get_qos_stats(runtime: TapMapRuntime<'_>) -> Result<Vec<QosStatsEntry>, String> {
    let pin_path = runtime.pin_path;
    let map_path = format!("{}/QOS_STATS", pin_path);
    let map_data = MapData::from_pin(&map_path).map_err(|e| format!("open QOS_STATS: {:?}", e))?;
    let map = PerCpuHashMap::<_, QosKey, QosStatsValue>::try_from(aya::maps::Map::PerCpuHashMap(
        map_data,
    ))
    .map_err(|e| format!("convert QOS_STATS: {:?}", e))?;

    let mut entries = Vec::new();
    for item in map.iter() {
        match item {
            Ok((key, values)) => {
                if key.tap_id != runtime.tap_id {
                    continue;
                }
                let (pp, pb, dp, db, sp, sb) = sum_per_cpu_qos_stats(values);
                if pp > 0 || dp > 0 || sp > 0 {
                    entries.push(QosStatsEntry {
                        key,
                        passed_packets: pp,
                        passed_bytes: pb,
                        dropped_packets: dp,
                        dropped_bytes: db,
                        shaped_packets: sp,
                        shaped_bytes: sb,
                    });
                }
            }
            Err(_) => continue,
        }
    }

    entries.sort_by(|a, b| b.passed_bytes.cmp(&a.passed_bytes));
    Ok(entries)
}

// --- Per-Group Statistics ---

pub struct GroupStatsEntry {
    pub key: GroupStatsKey,
    pub packets: u64,
    pub bytes: u64,
}

fn sum_per_cpu_group_stats(values: PerCpuValues<GroupStatsValue>) -> (u64, u64) {
    let mut packets = 0u64;
    let mut bytes = 0u64;
    for v in values.iter() {
        packets += v.packets;
        bytes += v.bytes;
    }
    (packets, bytes)
}

pub fn get_group_stats(runtime: TapMapRuntime<'_>) -> Result<Vec<GroupStatsEntry>, String> {
    let pin_path = runtime.pin_path;
    let map_path = format!("{}/GROUP_STATS", pin_path);
    let map_data =
        MapData::from_pin(&map_path).map_err(|e| format!("open GROUP_STATS: {:?}", e))?;
    let map = PerCpuHashMap::<_, GroupStatsKey, GroupStatsValue>::try_from(
        aya::maps::Map::PerCpuHashMap(map_data),
    )
    .map_err(|e| format!("convert GROUP_STATS: {:?}", e))?;

    let mut entries = Vec::new();
    for item in map.iter() {
        match item {
            Ok((key, values)) => {
                if key.tap_id != runtime.tap_id {
                    continue;
                }
                let (packets, bytes) = sum_per_cpu_group_stats(values);
                if packets > 0 {
                    entries.push(GroupStatsEntry {
                        key,
                        packets,
                        bytes,
                    });
                }
            }
            Err(_) => continue,
        }
    }

    entries.sort_by(|a, b| b.bytes.cmp(&a.bytes));
    Ok(entries)
}

pub fn format_bytes(bytes: u64) -> String {
    if bytes >= 1_073_741_824 {
        format!("{:.1} GB", bytes as f64 / 1_073_741_824.0)
    } else if bytes >= 1_048_576 {
        format!("{:.1} MB", bytes as f64 / 1_048_576.0)
    } else if bytes >= 1024 {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    } else {
        format!("{} B", bytes)
    }
}

pub fn proto_name(proto: u8) -> &'static str {
    match proto {
        6 => "TCP",
        17 => "UDP",
        1 => "ICMP",
        58 => "ICMPv6",
        0 => "any",
        _ => "other",
    }
}

pub fn direction_name(direction: u8) -> &'static str {
    match direction {
        0 => "ingress",
        1 => "egress",
        _ => "unknown",
    }
}

// --- Mirror Statistics ---

pub struct MirrorStatsEntry {
    pub src_id: u32,
    pub dst_id: u32,
    pub proto: u8,
    pub direction: u8,
    pub mirrored_packets: u64,
    pub mirrored_bytes: u64,
    pub errors: u64,
    pub is_global: bool,
}

fn sum_per_cpu_mirror_stats(values: PerCpuValues<MirrorStatsValue>) -> (u64, u64, u64) {
    let mut mp = 0u64;
    let mut mb = 0u64;
    let mut err = 0u64;
    for v in values.iter() {
        mp += v.mirrored_packets;
        mb += v.mirrored_bytes;
        err += v.errors;
    }
    (mp, mb, err)
}

pub fn get_mirror_stats(runtime: TapMapRuntime<'_>) -> Result<Vec<MirrorStatsEntry>, String> {
    let pin_path = runtime.pin_path;
    let mut entries = Vec::new();

    // Per-rule mirror stats
    let map_path = format!("{}/MIRROR_STATS", pin_path);
    if let Ok(map_data) = MapData::from_pin(&map_path) {
        if let Ok(map) = PerCpuHashMap::<_, MirrorKey, MirrorStatsValue>::try_from(
            aya::maps::Map::PerCpuHashMap(map_data),
        ) {
            for item in map.iter() {
                if let Ok((key, values)) = item {
                    if key.tap_id != runtime.tap_id {
                        continue;
                    }
                    let (mp, mb, err) = sum_per_cpu_mirror_stats(values);
                    if mp > 0 || err > 0 {
                        entries.push(MirrorStatsEntry {
                            src_id: key.src_id,
                            dst_id: key.dst_id,
                            proto: key.proto,
                            direction: key.direction,
                            mirrored_packets: mp,
                            mirrored_bytes: mb,
                            errors: err,
                            is_global: false,
                        });
                    }
                }
            }
        }
    }

    // Global mirror stats
    let map_path = format!("{}/MIRROR_GLOBAL_STATS", pin_path);
    if let Ok(map_data) = MapData::from_pin(&map_path) {
        if let Ok(map) = PerCpuHashMap::<_, GlobalMirrorKey, MirrorStatsValue>::try_from(
            aya::maps::Map::PerCpuHashMap(map_data),
        ) {
            for item in map.iter() {
                if let Ok((key, values)) = item {
                    if key.tap_id != runtime.tap_id {
                        continue;
                    }
                    let (mp, mb, err) = sum_per_cpu_mirror_stats(values);
                    if mp > 0 || err > 0 {
                        entries.push(MirrorStatsEntry {
                            src_id: 0,
                            dst_id: 0,
                            proto: 0,
                            direction: key.direction,
                            mirrored_packets: mp,
                            mirrored_bytes: mb,
                            errors: err,
                            is_global: true,
                        });
                    }
                }
            }
        }
    }

    entries.sort_by(|a, b| b.mirrored_bytes.cmp(&a.mirrored_bytes));
    Ok(entries)
}

// --- TCP-RT Statistics ---

const LATENCY_BUCKET_BOUNDARIES_US: [f64; 9] = [
    1_000.0,
    5_000.0,
    10_000.0,
    50_000.0,
    100_000.0,
    500_000.0,
    1_000_000.0,
    5_000_000.0,
    10_000_000.0,
];

#[derive(Debug, Clone, Default)]
pub struct TcprtMetricsSummary {
    pub flows: u64,
    pub retrans_req: u64,
    pub retrans_resp: u64,
    pub requests: u64,
    pub handshake_sum_us: f64,
    pub art_sum_us: f64,
    pub rtt_client_sum_us: f64,
    pub rtt_server_sum_us: f64,
    pub nqa_sum: f64,
    pub art_count: u64,
    pub art_bucket_counts: [u64; 9],
    pub art_sum_seconds: f64,
}

fn accumulate_tcprt_value(summary: &mut TcprtMetricsSummary, val: &TcpRtValue) {
    let handshake_us = val.handshake_ns as f64 / 1000.0;
    let art_us = val.art_ns as f64 / 1000.0;
    let rtt_client_us = val.rtt_client_ns as f64 / 1000.0;
    let rtt_server_us = val.rtt_server_ns as f64 / 1000.0;

    summary.flows += 1;
    summary.retrans_req += val.retrans_req as u64;
    summary.retrans_resp += val.retrans_resp as u64;
    summary.requests += val.request_count as u64;
    summary.handshake_sum_us += handshake_us;
    summary.art_sum_us += art_us;
    summary.rtt_client_sum_us += rtt_client_us;
    summary.rtt_server_sum_us += rtt_server_us;
    summary.nqa_sum += crate::tcprt_ops::compute_nqa_score(val) as f64;

    if art_us > 0.0 {
        summary.art_count += 1;
        summary.art_sum_seconds += art_us / 1_000_000.0;
        for (idx, boundary) in LATENCY_BUCKET_BOUNDARIES_US.iter().enumerate() {
            if art_us <= *boundary {
                summary.art_bucket_counts[idx] += 1;
            }
        }
    }
}

fn collect_tcprt_metrics_v4(
    runtime: TapMapRuntime<'_>,
    summary: &mut TcprtMetricsSummary,
) -> Result<bool, String> {
    let pin_path = runtime.pin_path;
    let map_path = format!("{}/TCPRT_TABLE_V4", pin_path);
    if !Path::new(&map_path).exists() {
        return Ok(false);
    }

    let map_data =
        MapData::from_pin(&map_path).map_err(|e| format!("open TCPRT_TABLE_V4: {:?}", e))?;
    let map = HashMap::<_, CtKey4, TcpRtValue>::try_from(aya::maps::Map::LruHashMap(map_data))
        .map_err(|e| format!("convert TCPRT_TABLE_V4: {:?}", e))?;

    for item in map.iter() {
        if let Ok((key, val)) = item {
            if key.tap_id != runtime.tap_id {
                continue;
            }
            accumulate_tcprt_value(summary, &val);
        }
    }

    Ok(true)
}

fn collect_tcprt_metrics_v6(
    runtime: TapMapRuntime<'_>,
    summary: &mut TcprtMetricsSummary,
) -> Result<bool, String> {
    let pin_path = runtime.pin_path;
    let map_path = format!("{}/TCPRT_TABLE_V6", pin_path);
    if !Path::new(&map_path).exists() {
        return Ok(false);
    }

    let map_data =
        MapData::from_pin(&map_path).map_err(|e| format!("open TCPRT_TABLE_V6: {:?}", e))?;
    let map = HashMap::<_, CtKey6, TcpRtValue>::try_from(aya::maps::Map::LruHashMap(map_data))
        .map_err(|e| format!("convert TCPRT_TABLE_V6: {:?}", e))?;

    for item in map.iter() {
        if let Ok((key, val)) = item {
            if key.tap_id != runtime.tap_id {
                continue;
            }
            accumulate_tcprt_value(summary, &val);
        }
    }

    Ok(true)
}

/// Best-effort aggregate over a live TCP-RT map. This is not a snapshot read:
/// entries may be added or removed while iteration is in progress.
pub fn get_tcprt_metrics_summary(
    runtime: TapMapRuntime<'_>,
) -> Result<Option<TcprtMetricsSummary>, String> {
    let mut summary = TcprtMetricsSummary::default();
    let mut available = false;

    available |= collect_tcprt_metrics_v4(runtime, &mut summary)?;
    available |= collect_tcprt_metrics_v6(runtime, &mut summary)?;

    if !available {
        return Ok(None);
    }

    Ok(Some(summary))
}

pub fn get_tcprt_stats(
    runtime: TapMapRuntime<'_>,
    top_n: usize,
) -> Result<Vec<crate::tcprt_ops::TcpRtEntry>, String> {
    let mut entries = crate::tcprt_ops::get_tcprt_flows_v4(runtime).unwrap_or_default();
    entries.extend(crate::tcprt_ops::get_tcprt_flows_v6(runtime).unwrap_or_default());
    // Sort by ART descending (slowest responses first)
    entries.sort_by(|a, b| {
        b.art_us
            .partial_cmp(&a.art_us)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    entries.truncate(top_n);
    Ok(entries)
}

/// Remove all RULE_STATS entries for a specific policy key.
/// Called after delete_policy to prevent stale stats from appearing in API responses.
pub fn clear_rule_stats_for_policy(
    runtime: TapMapRuntime<'_>,
    src_id: u32,
    dst_id: u32,
    proto: u8,
    direction: u8,
) -> Result<(), String> {
    let map_path = format!("{}/RULE_STATS", runtime.pin_path);
    let map_data = MapData::from_pin(&map_path).map_err(|e| format!("open RULE_STATS: {:?}", e))?;
    let mut map = PerCpuHashMap::<_, PolicyKey, RuleStatsValue>::try_from(
        aya::maps::Map::PerCpuHashMap(map_data),
    )
    .map_err(|e| format!("convert RULE_STATS: {:?}", e))?;

    for bank in [0u8, 1u8] {
        let key = PolicyKey {
            tap_id: runtime.tap_id,
            src_id,
            dst_id,
            proto,
            direction,
            bank,
            pad: [0; 1],
        };
        let _ = map.remove(&key);
    }
    Ok(())
}

/// Remove all GROUP_STATS entries for a specific group id (both directions).
/// Called after delete_group to prevent stale stats from appearing in API responses.
pub fn clear_group_stats_for_id(runtime: TapMapRuntime<'_>, group_id: u32) -> Result<(), String> {
    let map_path = format!("{}/GROUP_STATS", runtime.pin_path);
    let map_data =
        MapData::from_pin(&map_path).map_err(|e| format!("open GROUP_STATS: {:?}", e))?;
    let mut map = PerCpuHashMap::<_, GroupStatsKey, GroupStatsValue>::try_from(
        aya::maps::Map::PerCpuHashMap(map_data),
    )
    .map_err(|e| format!("convert GROUP_STATS: {:?}", e))?;

    // GROUP_STATS is keyed by (tap_id, group_id, direction); remove both directions.
    for direction in [0u8, 1u8] {
        let key = GroupStatsKey {
            tap_id: runtime.tap_id,
            group_id,
            direction,
            pad: [0; 3],
        };
        let _ = map.remove(&key);
    }
    Ok(())
}

/// Remove the QOS_STATS entry for a specific QoS rule key.
/// Called after delete_qos to prevent stale stats from appearing in API responses.
pub fn clear_qos_stats_for_rule(
    runtime: TapMapRuntime<'_>,
    group_id: u32,
    direction: u8,
) -> Result<(), String> {
    let map_path = format!("{}/QOS_STATS", runtime.pin_path);
    let map_data = MapData::from_pin(&map_path).map_err(|e| format!("open QOS_STATS: {:?}", e))?;
    let mut map = PerCpuHashMap::<_, QosKey, QosStatsValue>::try_from(
        aya::maps::Map::PerCpuHashMap(map_data),
    )
    .map_err(|e| format!("convert QOS_STATS: {:?}", e))?;

    let key = QosKey {
        tap_id: runtime.tap_id,
        group_id,
        direction,
        pad: [0; 3],
    };
    match map.remove(&key) {
        Ok(()) | Err(_) => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_bytes_human_readable() {
        assert_eq!(format_bytes(500), "500 B");
        assert_eq!(format_bytes(2048), "2.0 KB");
        assert_eq!(format_bytes(2_097_152), "2.0 MB");
        assert_eq!(format_bytes(2_147_483_648), "2.0 GB");
    }

    #[test]
    fn proto_and_direction_names() {
        assert_eq!(proto_name(6), "TCP");
        assert_eq!(proto_name(17), "UDP");
        assert_eq!(proto_name(1), "ICMP");
        assert_eq!(proto_name(58), "ICMPv6");
        assert_eq!(proto_name(123), "other");

        assert_eq!(direction_name(0), "ingress");
        assert_eq!(direction_name(1), "egress");
        assert_eq!(direction_name(5), "unknown");
    }
}
