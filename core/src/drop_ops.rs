use aya::maps::{MapData, PerCpuHashMap, PerCpuValues};
use crate::common::{DropKey, DropValue, TapMapRuntime};

pub struct DropStatsEntry {
    pub reason: u8,
    pub direction: u8,
    pub proto: u8,
    pub src_id: u32,
    pub dst_id: u32,
    pub packets: u64,
    pub bytes: u64,
    pub last_seen: u64,
}

fn sum_per_cpu_drop(values: PerCpuValues<DropValue>) -> (u64, u64, u64) {
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

pub fn get_drop_stats(runtime: TapMapRuntime<'_>) -> Result<Vec<DropStatsEntry>, String> {
    let pin_path = runtime.pin_path;
    let map_path = format!("{}/DROP_REASON_STATS", pin_path);
    let map_data = MapData::from_pin(&map_path)
        .map_err(|e| format!("open DROP_REASON_STATS: {:?}", e))?;
    let map = PerCpuHashMap::<_, DropKey, DropValue>::try_from(
        aya::maps::Map::PerCpuHashMap(map_data)
    ).map_err(|e| format!("convert DROP_REASON_STATS: {:?}", e))?;

    let mut entries = Vec::new();
    for item in map.iter() {
        if let Ok((key, values)) = item {
            let (packets, bytes, last_seen) = sum_per_cpu_drop(values);
            if packets > 0 {
                entries.push(DropStatsEntry {
                    reason: key.reason,
                    direction: key.direction,
                    proto: key.proto,
                    src_id: key.src_id,
                    dst_id: key.dst_id,
                    packets,
                    bytes,
                    last_seen,
                });
            }
        }
    }

    // Sort by packets descending
    entries.sort_by(|a, b| b.packets.cmp(&a.packets));
    Ok(entries)
}

pub fn flush_drop_stats(runtime: TapMapRuntime<'_>) -> Result<u64, String> {
    let pin_path = runtime.pin_path;
    let map_path = format!("{}/DROP_REASON_STATS", pin_path);
    let map_data = MapData::from_pin(&map_path)
        .map_err(|e| format!("open DROP_REASON_STATS: {:?}", e))?;
    let mut map = PerCpuHashMap::<_, DropKey, DropValue>::try_from(
        aya::maps::Map::PerCpuHashMap(map_data)
    ).map_err(|e| format!("convert DROP_REASON_STATS: {:?}", e))?;

    let keys: Vec<DropKey> = map.keys().filter_map(|k| k.ok()).collect();
    let count = keys.len() as u64;
    for key in keys {
        let _ = map.remove(&key);
    }
    Ok(count)
}
