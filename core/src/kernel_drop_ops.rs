use aya::maps::{Map, MapData, PerCpuHashMap, PerCpuValues};

use crate::common::{
    KernelDropConfig, KernelDropKey, KernelDropValue, KERNEL_DROP_FLAG_HAS_REASON,
};

const KERNEL_DROP_CONFIG_MAP: &str = "KERNEL_DROP_CONFIG";
const KERNEL_DROP_STATS_MAP: &str = "KERNEL_DROP_STATS";

#[derive(Debug, Clone)]
pub struct KernelDropStatsEntry {
    pub tap_id: u32,
    pub ifindex: u32,
    pub reason_code: Option<u16>,
    pub proto: u16,
    pub packets: u64,
    pub bytes: u64,
    pub last_seen_ns: u64,
    pub last_location: Option<u64>,
    pub source: String,
}

#[derive(Debug, Clone, Default)]
pub struct KernelDropQuery {
    pub tap_id: Option<u32>,
    pub ifindex: Option<u32>,
    pub reason_code: Option<u16>,
    pub top: Option<usize>,
    pub include_unattributed: bool,
}

pub fn kernel_drop_reason_name(code: Option<u16>) -> String {
    match code {
        Some(code) => format!("reason_{}", code),
        None => "unknown".to_string(),
    }
}

pub fn kernel_drop_proto_name(proto: u16) -> String {
    match proto {
        0x0800 => "ipv4".to_string(),
        0x86dd => "ipv6".to_string(),
        0x0806 => "arp".to_string(),
        0x8100 => "802.1q".to_string(),
        0x88a8 => "802.1ad".to_string(),
        0 => "unknown".to_string(),
        other => format!("0x{:04x}", other),
    }
}

fn sum_per_cpu_kernel_drop(values: PerCpuValues<KernelDropValue>) -> (u64, u64, u64, u64) {
    let mut packets = 0u64;
    let mut bytes = 0u64;
    let mut last_seen_ns = 0u64;
    let mut last_location = 0u64;

    for value in values.iter() {
        packets += value.packets;
        bytes += value.bytes;
        if value.last_seen_ns >= last_seen_ns {
            last_seen_ns = value.last_seen_ns;
            last_location = value.last_location;
        }
    }

    (packets, bytes, last_seen_ns, last_location)
}

fn should_include_entry(key: &KernelDropKey, query: &KernelDropQuery) -> bool {
    if let Some(tap_id) = query.tap_id {
        if key.tap_id != tap_id {
            return false;
        }
    }
    if let Some(ifindex) = query.ifindex {
        if key.ifindex != ifindex {
            return false;
        }
    }
    if let Some(reason_code) = query.reason_code {
        if key.reason_code != reason_code {
            return false;
        }
    }
    if !query.include_unattributed && key.ifindex == 0 {
        return false;
    }
    true
}

fn open_kernel_drop_config_map(
    pin_path: &str,
) -> Result<aya::maps::HashMap<MapData, u32, KernelDropConfig>, String> {
    let map_path = format!("{}/{}", pin_path, KERNEL_DROP_CONFIG_MAP);
    let map_data = MapData::from_pin(&map_path)
        .map_err(|e| format!("open {}: {:?}", KERNEL_DROP_CONFIG_MAP, e))?;
    aya::maps::HashMap::<_, u32, KernelDropConfig>::try_from(Map::HashMap(map_data))
        .map_err(|e| format!("convert {}: {:?}", KERNEL_DROP_CONFIG_MAP, e))
}

fn kernel_drop_source_label(pin_path: &str) -> String {
    let Ok(map) = open_kernel_drop_config_map(pin_path) else {
        return "kfree_skb_unknown".to_string();
    };
    let Ok(config) = map.get(&0u32, 0) else {
        return "kfree_skb_unknown".to_string();
    };
    if (config.flags & KERNEL_DROP_FLAG_HAS_REASON) != 0 {
        "kfree_skb_reasonful".to_string()
    } else {
        "kfree_skb_legacy".to_string()
    }
}

fn open_kernel_drop_stats_map(
    pin_path: &str,
) -> Result<PerCpuHashMap<MapData, KernelDropKey, KernelDropValue>, String> {
    let map_path = format!("{}/{}", pin_path, KERNEL_DROP_STATS_MAP);
    let map_data = MapData::from_pin(&map_path)
        .map_err(|e| format!("open {}: {:?}", KERNEL_DROP_STATS_MAP, e))?;
    PerCpuHashMap::<_, KernelDropKey, KernelDropValue>::try_from(Map::PerCpuLruHashMap(map_data))
        .map_err(|e| format!("convert {}: {:?}", KERNEL_DROP_STATS_MAP, e))
}

pub fn get_kernel_drop_stats(
    pin_path: &str,
    query: &KernelDropQuery,
) -> Result<Vec<KernelDropStatsEntry>, String> {
    let map = open_kernel_drop_stats_map(pin_path)?;
    let source_label = kernel_drop_source_label(pin_path);
    let mut entries = Vec::new();

    for item in map.iter() {
        let Ok((key, values)) = item else {
            continue;
        };
        if !should_include_entry(&key, query) {
            continue;
        }

        let (packets, bytes, last_seen_ns, last_location) = sum_per_cpu_kernel_drop(values);
        if packets == 0 {
            continue;
        }

        entries.push(KernelDropStatsEntry {
            tap_id: key.tap_id,
            ifindex: key.ifindex,
            reason_code: (key.reason_code != 0).then_some(key.reason_code),
            proto: key.proto,
            packets,
            bytes,
            last_seen_ns,
            last_location: (last_location != 0).then_some(last_location),
            source: source_label.clone(),
        });
    }

    entries.sort_by(|a, b| {
        b.packets
            .cmp(&a.packets)
            .then_with(|| b.bytes.cmp(&a.bytes))
            .then_with(|| b.last_seen_ns.cmp(&a.last_seen_ns))
    });

    if let Some(top) = query.top {
        entries.truncate(top);
    }

    Ok(entries)
}

pub fn flush_kernel_drop_stats(pin_path: &str, query: &KernelDropQuery) -> Result<u64, String> {
    let mut map = open_kernel_drop_stats_map(pin_path)?;
    let keys: Vec<KernelDropKey> = map
        .keys()
        .filter_map(|item| item.ok())
        .filter(|key| should_include_entry(key, query))
        .collect();

    let count = keys.len() as u64;
    for key in keys {
        let _ = map.remove(&key);
    }

    Ok(count)
}
