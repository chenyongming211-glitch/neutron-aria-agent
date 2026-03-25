use aya::maps::{HashMap, MapData};
use crate::common::{TapMapRuntime, TraceEvent, TraceEventKey, TraceEventV6, TraceFilter};
use std::net::{Ipv4Addr, Ipv6Addr};

pub struct TraceEventEntry {
    pub seq: u64,
    pub timestamp: u64,
    pub src_ip: String,
    pub dst_ip: String,
    pub src_port: u16,
    pub dst_port: u16,
    pub proto: u8,
    pub hook: String,
    pub result: String,
    pub direction: String,
    pub src_id: u32,
    pub dst_id: u32,
    pub pkt_len: u32,
    pub ct_state: String,
    pub drop_reason: String,
}

fn hook_name(hook: u8) -> String {
    match hook {
        1 => "xdp-in".to_string(),
        2 => "xdp-drop".to_string(),
        3 => "tc-egress".to_string(),
        4 => "tc-drop".to_string(),
        5 => "tc-ingress".to_string(),
        _ => format!("hook:{}", hook),
    }
}

fn result_name(result: u8) -> String {
    match result {
        0 => "pass".to_string(),
        1 => "drop:acl".to_string(),
        2 => "drop:port".to_string(),
        3 => "drop:default".to_string(),
        4 => "drop:qos".to_string(),
        _ => format!("result:{}", result),
    }
}

fn ct_state_name(state: u8) -> String {
    match state {
        0 => "none".to_string(),
        1 => "new".to_string(),
        2 => "established".to_string(),
        _ => format!("ct:{}", state),
    }
}

pub fn drop_reason_name(reason: u8) -> String {
    match reason {
        0 => "-".to_string(),
        1 => "acl-deny".to_string(),
        2 => "acl-port-deny".to_string(),
        3 => "acl-default-deny".to_string(),
        4 => "qos-ingress".to_string(),
        5 => "qos-egress".to_string(),
        _ => format!("reason:{}", reason),
    }
}

fn direction_name(dir: u8) -> String {
    match dir {
        0 => "ingress".to_string(),
        1 => "egress".to_string(),
        _ => format!("dir:{}", dir),
    }
}

fn trace_event_entry_from_v4(key: TraceEventKey, event: TraceEvent) -> TraceEventEntry {
    TraceEventEntry {
        seq: key.seq,
        timestamp: event.timestamp,
        src_ip: Ipv4Addr::from(event.src_ip).to_string(),
        dst_ip: Ipv4Addr::from(event.dst_ip).to_string(),
        src_port: event.src_port,
        dst_port: event.dst_port,
        proto: event.proto,
        hook: hook_name(event.hook),
        result: result_name(event.result),
        direction: direction_name(event.direction),
        src_id: event.src_id,
        dst_id: event.dst_id,
        pkt_len: event.pkt_len,
        ct_state: ct_state_name(event.ct_state),
        drop_reason: drop_reason_name(event.drop_reason),
    }
}

fn trace_event_entry_from_v6(key: TraceEventKey, event: TraceEventV6) -> TraceEventEntry {
    TraceEventEntry {
        seq: key.seq,
        timestamp: event.timestamp,
        src_ip: Ipv6Addr::from(event.src_ip).to_string(),
        dst_ip: Ipv6Addr::from(event.dst_ip).to_string(),
        src_port: event.src_port,
        dst_port: event.dst_port,
        proto: event.proto,
        hook: hook_name(event.hook),
        result: result_name(event.result),
        direction: direction_name(event.direction),
        src_id: event.src_id,
        dst_id: event.dst_id,
        pkt_len: event.pkt_len,
        ct_state: ct_state_name(event.ct_state),
        drop_reason: drop_reason_name(event.drop_reason),
    }
}

pub fn set_trace_filter(
    runtime: TapMapRuntime<'_>,
    src_ip: u32,
    dst_ip: u32,
    src_ip_v6: [u8; 16],
    dst_ip_v6: [u8; 16],
    src_port: u16,
    dst_port: u16,
    proto: u8,
    is_ipv6: u8,
    enabled: bool,
) -> Result<(), String> {
    let pin_path = runtime.pin_path;
    let map_path = format!("{}/TRACE_FILTER", pin_path);
    let map_data = MapData::from_pin(&map_path)
        .map_err(|e| format!("open TRACE_FILTER: {:?}", e))?;
    let mut map = HashMap::<_, u32, TraceFilter>::try_from(
        aya::maps::Map::HashMap(map_data)
    ).map_err(|e| format!("convert TRACE_FILTER: {:?}", e))?;

    let filter = TraceFilter {
        src_ip,
        dst_ip,
        src_ip_v6,
        dst_ip_v6,
        src_port,
        dst_port,
        proto,
        enabled: if enabled { 1 } else { 0 },
        is_ipv6,
        pad: [0; 1],
    };
    map.insert(&runtime.tap_id, &filter, 0)
        .map_err(|e| format!("insert TRACE_FILTER: {:?}", e))?;
    Ok(())
}

pub fn clear_trace_filter(runtime: TapMapRuntime<'_>) -> Result<(), String> {
    delete_trace_filter(runtime).map(|_| ())
}

pub fn delete_trace_filter(runtime: TapMapRuntime<'_>) -> Result<bool, String> {
    let pin_path = runtime.pin_path;
    let map_path = format!("{}/TRACE_FILTER", pin_path);
    let map_data = MapData::from_pin(&map_path)
        .map_err(|e| format!("open TRACE_FILTER: {:?}", e))?;
    let mut map = HashMap::<_, u32, TraceFilter>::try_from(
        aya::maps::Map::HashMap(map_data)
    ).map_err(|e| format!("convert TRACE_FILTER: {:?}", e))?;

    if map.get(&runtime.tap_id, 0).is_err() {
        return Ok(false);
    }

    map.remove(&runtime.tap_id)
        .map_err(|e| format!("remove TRACE_FILTER: {:?}", e))?;
    Ok(true)
}

pub fn scrub_trace_filter(runtime: TapMapRuntime<'_>) -> Result<u64, String> {
    delete_trace_filter(runtime).map(|deleted| if deleted { 1 } else { 0 })
}

pub fn get_trace_events(runtime: TapMapRuntime<'_>, limit: usize) -> Result<Vec<TraceEventEntry>, String> {
    let pin_path = runtime.pin_path;
    let map_path = format!("{}/TRACE_LOG", pin_path);
    let map_data = MapData::from_pin(&map_path)
        .map_err(|e| format!("open TRACE_LOG: {:?}", e))?;
    let map = HashMap::<_, TraceEventKey, TraceEvent>::try_from(
        aya::maps::Map::LruHashMap(map_data)
    ).map_err(|e| format!("convert TRACE_LOG: {:?}", e))?;

    let mut entries = Vec::new();
    for item in map.iter() {
        if let Ok((key, event)) = item {
            if key.tap_id != runtime.tap_id {
                continue;
            }
            entries.push(trace_event_entry_from_v4(key, event));
        }
    }

    let v6_map_path = format!("{}/TRACE_LOG_V6", pin_path);
    if let Ok(v6_map_data) = MapData::from_pin(&v6_map_path) {
        if let Ok(v6_map) = HashMap::<_, TraceEventKey, TraceEventV6>::try_from(
            aya::maps::Map::LruHashMap(v6_map_data)
        ) {
            for item in v6_map.iter() {
                if let Ok((key, event)) = item {
                    if key.tap_id != runtime.tap_id {
                        continue;
                    }
                    entries.push(trace_event_entry_from_v6(key, event));
                }
            }
        }
    }

    // Sort by timestamp descending (newest first), then seq as a stable tiebreaker.
    entries.sort_by(|a, b| {
        b.timestamp
            .cmp(&a.timestamp)
            .then_with(|| b.seq.cmp(&a.seq))
    });
    entries.truncate(limit);
    Ok(entries)
}

pub fn flush_trace_log(runtime: TapMapRuntime<'_>) -> Result<u64, String> {
    let pin_path = runtime.pin_path;
    let map_path = format!("{}/TRACE_LOG", pin_path);
    let map_data = MapData::from_pin(&map_path)
        .map_err(|e| format!("open TRACE_LOG: {:?}", e))?;
    let mut map = HashMap::<_, TraceEventKey, TraceEvent>::try_from(
        aya::maps::Map::LruHashMap(map_data)
    ).map_err(|e| format!("convert TRACE_LOG: {:?}", e))?;

    let keys: Vec<TraceEventKey> = map.iter()
        .filter_map(|item| item.ok().map(|(key, _)| key))
        .filter(|key| key.tap_id == runtime.tap_id)
        .collect();
    let mut count = keys.len() as u64;
    for key in keys {
        let _ = map.remove(&key);
    }

    let v6_map_path = format!("{}/TRACE_LOG_V6", pin_path);
    if let Ok(v6_map_data) = MapData::from_pin(&v6_map_path) {
        if let Ok(mut v6_map) = HashMap::<_, TraceEventKey, TraceEventV6>::try_from(
            aya::maps::Map::LruHashMap(v6_map_data)
        ) {
            let keys: Vec<TraceEventKey> = v6_map.iter()
                .filter_map(|item| item.ok().map(|(key, _)| key))
                .filter(|key| key.tap_id == runtime.tap_id)
                .collect();
            count += keys.len() as u64;
            for key in keys {
                let _ = v6_map.remove(&key);
            }
        }
    }

    Ok(count)
}
