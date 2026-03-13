use aya::maps::{HashMap, MapData, PerCpuHashMap, PerCpuValues};
use crate::common::{PolicyKey, RuleStatsValue, FlowStatsValue, CtKey4, CtKey6, CtValue, CT_NEW, CT_ESTABLISHED};
use std::net::Ipv4Addr;

pub struct RuleStatsEntry {
    pub key: PolicyKey,
    pub packets: u64,
    pub bytes: u64,
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

pub struct ConntrackSummary {
    pub total_v4: u64,
    pub total_v6: u64,
    pub new_count: u64,
    pub established_count: u64,
}

fn sum_per_cpu_rule_stats(values: PerCpuValues<RuleStatsValue>) -> (u64, u64) {
    let mut packets = 0u64;
    let mut bytes = 0u64;
    for v in values.iter() {
        packets += v.packets;
        bytes += v.bytes;
    }
    (packets, bytes)
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
                let (packets, bytes) = sum_per_cpu_rule_stats(values);
                if packets > 0 {
                    entries.push(RuleStatsEntry { key, packets, bytes });
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
                        src_ip: Ipv4Addr::from(key.src_ip.to_be()),
                        dst_ip: Ipv4Addr::from(key.dst_ip.to_be()),
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
