use crate::common::{CtConfig, CtKey4, CtKey6, CtValue, TapMapRuntime};
use aya::maps::{HashMap, MapData};
use std::net::Ipv4Addr;

pub struct CtEntry {
    pub src_ip: String,
    pub dst_ip: String,
    pub src_port: u16,
    pub dst_port: u16,
    pub proto: u8,
    pub state: u8,
    pub pkt_count: u64,
    pub byte_count: u64,
}

pub fn ct_list(runtime: TapMapRuntime<'_>) -> Result<Vec<CtEntry>, String> {
    let pin_path = runtime.pin_path;
    let mut entries = Vec::new();

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
                    entries.push(CtEntry {
                        src_ip: format!("{}", Ipv4Addr::from(key.src_ip)),
                        dst_ip: format!("{}", Ipv4Addr::from(key.dst_ip)),
                        src_port: key.src_port,
                        dst_port: key.dst_port,
                        proto: key.proto,
                        state: val.state,
                        pkt_count: val.pkt_count,
                        byte_count: val.byte_count,
                    });
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
                    let src = std::net::Ipv6Addr::from(key.src_ip);
                    let dst = std::net::Ipv6Addr::from(key.dst_ip);
                    entries.push(CtEntry {
                        src_ip: format!("{}", src),
                        dst_ip: format!("{}", dst),
                        src_port: key.src_port,
                        dst_port: key.dst_port,
                        proto: key.proto,
                        state: val.state,
                        pkt_count: val.pkt_count,
                        byte_count: val.byte_count,
                    });
                }
            }
        }
    }

    Ok(entries)
}

pub fn ct_flush(runtime: TapMapRuntime<'_>) -> Result<u64, String> {
    let pin_path = runtime.pin_path;
    let mut count = 0u64;

    // Flush CT_TABLE_V4
    let map_path = format!("{}/CT_TABLE_V4", pin_path);
    if let Ok(map_data) = MapData::from_pin(&map_path) {
        if let Ok(mut map) =
            HashMap::<_, CtKey4, CtValue>::try_from(aya::maps::Map::LruHashMap(map_data))
        {
            let keys: Vec<CtKey4> = map
                .iter()
                .filter_map(|item| item.ok().map(|(k, _)| k))
                .filter(|key| key.tap_id == runtime.tap_id)
                .collect();
            for key in keys {
                if map.remove(&key).is_ok() {
                    count += 1;
                }
            }
        }
    }

    // Flush CT_TABLE_V6
    let map_path = format!("{}/CT_TABLE_V6", pin_path);
    if let Ok(map_data) = MapData::from_pin(&map_path) {
        if let Ok(mut map) =
            HashMap::<_, CtKey6, CtValue>::try_from(aya::maps::Map::LruHashMap(map_data))
        {
            let keys: Vec<CtKey6> = map
                .iter()
                .filter_map(|item| item.ok().map(|(k, _)| k))
                .filter(|key| key.tap_id == runtime.tap_id)
                .collect();
            for key in keys {
                if map.remove(&key).is_ok() {
                    count += 1;
                }
            }
        }
    }

    Ok(count)
}

fn scrub_ct_table_v4_strict(pin_path: &str, tap_id: u32) -> Result<u64, String> {
    let map_path = format!("{}/CT_TABLE_V4", pin_path);
    let map_data =
        MapData::from_pin(&map_path).map_err(|e| format!("open CT_TABLE_V4: {:?}", e))?;
    let mut map = HashMap::<_, CtKey4, CtValue>::try_from(aya::maps::Map::LruHashMap(map_data))
        .map_err(|e| format!("convert CT_TABLE_V4: {:?}", e))?;

    let keys: Vec<CtKey4> = map
        .iter()
        .filter_map(|item| item.ok().map(|(k, _)| k))
        .filter(|key| key.tap_id == tap_id)
        .collect();
    let count = keys.len() as u64;
    for key in keys {
        map.remove(&key)
            .map_err(|e| format!("remove CT_TABLE_V4 entry: {:?}", e))?;
    }
    Ok(count)
}

fn scrub_ct_table_v6_strict(pin_path: &str, tap_id: u32) -> Result<u64, String> {
    let map_path = format!("{}/CT_TABLE_V6", pin_path);
    let map_data =
        MapData::from_pin(&map_path).map_err(|e| format!("open CT_TABLE_V6: {:?}", e))?;
    let mut map = HashMap::<_, CtKey6, CtValue>::try_from(aya::maps::Map::LruHashMap(map_data))
        .map_err(|e| format!("convert CT_TABLE_V6: {:?}", e))?;

    let keys: Vec<CtKey6> = map
        .iter()
        .filter_map(|item| item.ok().map(|(k, _)| k))
        .filter(|key| key.tap_id == tap_id)
        .collect();
    let count = keys.len() as u64;
    for key in keys {
        map.remove(&key)
            .map_err(|e| format!("remove CT_TABLE_V6 entry: {:?}", e))?;
    }
    Ok(count)
}

/// Strict CT scrub for managed pre-replay.
/// Missing or invalid pinned maps are treated as errors.
pub fn scrub_ct_tables_strict(runtime: TapMapRuntime<'_>) -> Result<u64, String> {
    let pin_path = runtime.pin_path;
    let tap_id = runtime.tap_id;

    let mut count = 0u64;
    count += scrub_ct_table_v4_strict(pin_path, tap_id)?;
    count += scrub_ct_table_v6_strict(pin_path, tap_id)?;
    Ok(count)
}

pub fn init_ct_config(bpf: &mut aya::Ebpf) -> Result<(), String> {
    let config = CtConfig {
        tcp_established_ns: 300_000_000_000, // 300s
        tcp_new_ns: 30_000_000_000,          // 30s
        udp_ns: 60_000_000_000,              // 60s
        icmp_ns: 30_000_000_000,             // 30s
    };

    match bpf
        .map_mut("CT_CONFIG")
        .ok_or_else(|| "CT_CONFIG not found".to_string())
        .and_then(|m| HashMap::<_, u32, CtConfig>::try_from(m).map_err(|e| format!("{:?}", e)))
    {
        Ok(mut map) => {
            map.insert(&0u32, &config, 0)
                .map_err(|e| format!("CT_CONFIG insert: {:?}", e))?;
        }
        Err(e) => return Err(format!("CT_CONFIG: {}", e)),
    }

    Ok(())
}
