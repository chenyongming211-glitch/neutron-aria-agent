use aya::maps::{HashMap, MapData, PerCpuHashMap, PerCpuValues};
use crate::common::{
    PolicyKey, RuleStatsValue, FlowStatsValue, CtKey4, CtKey6, CtValue, CT_NEW, CT_ESTABLISHED,
    QosKey, QosStatsValue, GroupStatsKey, GroupStatsValue,
    MirrorKey, GlobalMirrorKey, MirrorStatsValue, TcpRtValue,
};
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

pub fn get_rule_stats(pin_path: &str) -> Result<Vec<RuleStatsEntry>, String> {
    let map_path = format!("{}/RULE_STATS", pin_path);
    let map_data = MapData::from_pin(&map_path)
        .map_err(|e| format!("open RULE_STATS: {:?}", e))?;
    let map = PerCpuHashMap::<_, PolicyKey, RuleStatsValue>::try_from(
        aya::maps::Map::PerCpuHashMap(map_data)
    ).map_err(|e| format!("convert RULE_STATS: {:?}", e))?;

    let mut entries = Vec::new();
    for item in map.iter() {
        match item {
            Ok((key, values)) => {
                let (packets, bytes, dropped_packets, dropped_bytes) = sum_per_cpu_rule_stats(values);
                if packets > 0 {
                    entries.push(RuleStatsEntry { key, packets, bytes, dropped_packets, dropped_bytes });
                }
            }
            Err(_) => continue,
        }
    }

    entries.sort_by(|a, b| b.bytes.cmp(&a.bytes));
    Ok(entries)
}

pub fn get_top_flows_v4(pin_path: &str, n: usize) -> Result<Vec<FlowStatsEntry>, String> {
    let map_path = format!("{}/FLOW_STATS_V4", pin_path);
    let map_data = MapData::from_pin(&map_path)
        .map_err(|e| format!("open FLOW_STATS_V4: {:?}", e))?;
    // LruPerCpuHashMap on kernel side → PerCpuLruHashMap enum variant in aya
    let map = PerCpuHashMap::<_, CtKey4, FlowStatsValue>::try_from(
        aya::maps::Map::PerCpuLruHashMap(map_data)
    ).map_err(|e| format!("convert FLOW_STATS_V4: {:?}", e))?;

    let mut entries = Vec::new();
    for item in map.iter() {
        match item {
            Ok((key, values)) => {
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

pub fn get_top_flows_v6(pin_path: &str, n: usize) -> Result<Vec<FlowStatsEntryV6>, String> {
    let map_path = format!("{}/FLOW_STATS_V6", pin_path);
    let map_data = MapData::from_pin(&map_path)
        .map_err(|e| format!("open FLOW_STATS_V6: {:?}", e))?;
    // 内核端是 LruPerCpuHashMap，这里对应 PerCpuLruHashMap 分支。
    let map = PerCpuHashMap::<_, CtKey6, FlowStatsValue>::try_from(
        aya::maps::Map::PerCpuLruHashMap(map_data),
    )
    .map_err(|e| format!("convert FLOW_STATS_V6: {:?}", e))?;

    let mut entries = Vec::new();
    for item in map.iter() {
        match item {
            Ok((key, values)) => {
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

pub fn get_conntrack_stats(pin_path: &str) -> Result<ConntrackSummary, String> {
    let mut summary = ConntrackSummary {
        total_v4: 0,
        total_v6: 0,
        new_count: 0,
        established_count: 0,
    };

    // CT_TABLE_V4 — LruHashMap on kernel side
    let map_path = format!("{}/CT_TABLE_V4", pin_path);
    if let Ok(map_data) = MapData::from_pin(&map_path) {
        if let Ok(map) = HashMap::<_, CtKey4, CtValue>::try_from(
            aya::maps::Map::LruHashMap(map_data)
        ) {
            for item in map.iter() {
                if let Ok((_key, val)) = item {
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
        if let Ok(map) = HashMap::<_, CtKey6, CtValue>::try_from(
            aya::maps::Map::LruHashMap(map_data)
        ) {
            for item in map.iter() {
                if let Ok((_key, val)) = item {
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

pub fn get_qos_stats(pin_path: &str) -> Result<Vec<QosStatsEntry>, String> {
    let map_path = format!("{}/QOS_STATS", pin_path);
    let map_data = MapData::from_pin(&map_path)
        .map_err(|e| format!("open QOS_STATS: {:?}", e))?;
    let map = PerCpuHashMap::<_, QosKey, QosStatsValue>::try_from(
        aya::maps::Map::PerCpuHashMap(map_data)
    ).map_err(|e| format!("convert QOS_STATS: {:?}", e))?;

    let mut entries = Vec::new();
    for item in map.iter() {
        match item {
            Ok((key, values)) => {
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

pub fn get_group_stats(pin_path: &str) -> Result<Vec<GroupStatsEntry>, String> {
    let map_path = format!("{}/GROUP_STATS", pin_path);
    let map_data = MapData::from_pin(&map_path)
        .map_err(|e| format!("open GROUP_STATS: {:?}", e))?;
    let map = PerCpuHashMap::<_, GroupStatsKey, GroupStatsValue>::try_from(
        aya::maps::Map::PerCpuHashMap(map_data)
    ).map_err(|e| format!("convert GROUP_STATS: {:?}", e))?;

    let mut entries = Vec::new();
    for item in map.iter() {
        match item {
            Ok((key, values)) => {
                let (packets, bytes) = sum_per_cpu_group_stats(values);
                if packets > 0 {
                    entries.push(GroupStatsEntry { key, packets, bytes });
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

pub fn get_mirror_stats(pin_path: &str) -> Result<Vec<MirrorStatsEntry>, String> {
    let mut entries = Vec::new();

    // Per-rule mirror stats
    let map_path = format!("{}/MIRROR_STATS", pin_path);
    if let Ok(map_data) = MapData::from_pin(&map_path) {
        if let Ok(map) = PerCpuHashMap::<_, MirrorKey, MirrorStatsValue>::try_from(
            aya::maps::Map::PerCpuHashMap(map_data)
        ) {
            for item in map.iter() {
                if let Ok((key, values)) = item {
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
            aya::maps::Map::PerCpuHashMap(map_data)
        ) {
            for item in map.iter() {
                if let Ok((key, values)) = item {
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

fn collect_tcprt_metrics_v4(pin_path: &str, summary: &mut TcprtMetricsSummary) -> Result<bool, String> {
    let map_path = format!("{}/TCPRT_TABLE_V4", pin_path);
    if !Path::new(&map_path).exists() {
        return Ok(false);
    }

    let map_data = MapData::from_pin(&map_path)
        .map_err(|e| format!("open TCPRT_TABLE_V4: {:?}", e))?;
    let map = HashMap::<_, CtKey4, TcpRtValue>::try_from(
        aya::maps::Map::LruHashMap(map_data)
    ).map_err(|e| format!("convert TCPRT_TABLE_V4: {:?}", e))?;

    for item in map.iter() {
        if let Ok((_key, val)) = item {
            accumulate_tcprt_value(summary, &val);
        }
    }

    Ok(true)
}

fn collect_tcprt_metrics_v6(pin_path: &str, summary: &mut TcprtMetricsSummary) -> Result<bool, String> {
    let map_path = format!("{}/TCPRT_TABLE_V6", pin_path);
    if !Path::new(&map_path).exists() {
        return Ok(false);
    }

    let map_data = MapData::from_pin(&map_path)
        .map_err(|e| format!("open TCPRT_TABLE_V6: {:?}", e))?;
    let map = HashMap::<_, CtKey6, TcpRtValue>::try_from(
        aya::maps::Map::LruHashMap(map_data)
    ).map_err(|e| format!("convert TCPRT_TABLE_V6: {:?}", e))?;

    for item in map.iter() {
        if let Ok((_key, val)) = item {
            accumulate_tcprt_value(summary, &val);
        }
    }

    Ok(true)
}

/// Best-effort aggregate over a live TCP-RT map. This is not a snapshot read:
/// entries may be added or removed while iteration is in progress.
pub fn get_tcprt_metrics_summary(pin_path: &str) -> Result<Option<TcprtMetricsSummary>, String> {
    let mut summary = TcprtMetricsSummary::default();
    let mut available = false;

    available |= collect_tcprt_metrics_v4(pin_path, &mut summary)?;
    available |= collect_tcprt_metrics_v6(pin_path, &mut summary)?;

    if !available {
        return Ok(None);
    }

    Ok(Some(summary))
}

pub fn get_tcprt_stats(pin_path: &str, top_n: usize) -> Result<Vec<crate::tcprt_ops::TcpRtEntry>, String> {
    let mut entries = crate::tcprt_ops::get_tcprt_flows_v4(pin_path).unwrap_or_default();
    entries.extend(crate::tcprt_ops::get_tcprt_flows_v6(pin_path).unwrap_or_default());
    // Sort by ART descending (slowest responses first)
    entries.sort_by(|a, b| b.art_us.partial_cmp(&a.art_us).unwrap_or(std::cmp::Ordering::Equal));
    entries.truncate(top_n);
    Ok(entries)
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
