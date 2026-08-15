use crate::common::{
    TapMapRuntime, TraceEvent, TraceEventKey, TraceEventV6, TraceFilter, TraceStreamEvent,
    DROP_FRAGMENT_INVALID_L4, DROP_MALFORMED_IP,
};
use crate::ebpf_ops::{
    classify_map_delete, collect_iterated_items, execute_counted_map_delete_batch,
};
use aya::maps::{HashMap, MapData, MapError};
use std::net::{Ipv4Addr, Ipv6Addr};

#[derive(Clone, Debug)]
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
        aria_ebpf_abi::userspace::TRACE_RESULT_DROP_FRAGMENT => {
            "drop:fragment".to_string()
        }
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
        DROP_FRAGMENT_INVALID_L4 => "fragment-invalid-l4".to_string(),
        DROP_MALFORMED_IP => "malformed-ip".to_string(),
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

pub fn trace_event_entry_from_stream(event: TraceStreamEvent) -> TraceEventEntry {
    TraceEventEntry {
        seq: event.seq,
        timestamp: event.timestamp,
        src_ip: if event.is_ipv6 != 0 {
            Ipv6Addr::from(event.src_ip_v6).to_string()
        } else {
            Ipv4Addr::from(event.src_ip).to_string()
        },
        dst_ip: if event.is_ipv6 != 0 {
            Ipv6Addr::from(event.dst_ip_v6).to_string()
        } else {
            Ipv4Addr::from(event.dst_ip).to_string()
        },
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
    let map_data =
        MapData::from_pin(&map_path).map_err(|e| format!("open TRACE_FILTER: {:?}", e))?;
    let mut map = HashMap::<_, u32, TraceFilter>::try_from(aya::maps::Map::HashMap(map_data))
        .map_err(|e| format!("convert TRACE_FILTER: {:?}", e))?;

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

fn delete_trace_filter_entry<F>(remove: F, context: &str) -> Result<bool, String>
where
    F: FnOnce() -> Result<(), MapError>,
{
    classify_map_delete(remove(), context)
}

pub fn delete_trace_filter(runtime: TapMapRuntime<'_>) -> Result<bool, String> {
    let pin_path = runtime.pin_path;
    let map_path = format!("{}/TRACE_FILTER", pin_path);
    let map_data =
        MapData::from_pin(&map_path).map_err(|e| format!("open TRACE_FILTER: {:?}", e))?;
    let mut map = HashMap::<_, u32, TraceFilter>::try_from(aya::maps::Map::HashMap(map_data))
        .map_err(|e| format!("convert TRACE_FILTER: {:?}", e))?;

    delete_trace_filter_entry(
        || map.remove(&runtime.tap_id),
        &format!("remove TRACE_FILTER tap {}", runtime.tap_id),
    )
}

pub fn scrub_trace_filter(runtime: TapMapRuntime<'_>) -> Result<u64, String> {
    delete_trace_filter(runtime).map(|deleted| if deleted { 1 } else { 0 })
}

pub fn get_trace_events(
    runtime: TapMapRuntime<'_>,
    limit: usize,
) -> Result<Vec<TraceEventEntry>, String> {
    let pin_path = runtime.pin_path;
    let map_path = format!("{}/TRACE_LOG", pin_path);
    let map_data = MapData::from_pin(&map_path).map_err(|e| format!("open TRACE_LOG: {:?}", e))?;
    let map =
        HashMap::<_, TraceEventKey, TraceEvent>::try_from(aya::maps::Map::LruHashMap(map_data))
            .map_err(|e| format!("convert TRACE_LOG: {:?}", e))?;

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
            aya::maps::Map::LruHashMap(v6_map_data),
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
    let map_data = MapData::from_pin(&map_path).map_err(|e| format!("open TRACE_LOG: {:?}", e))?;
    let mut map =
        HashMap::<_, TraceEventKey, TraceEvent>::try_from(aya::maps::Map::LruHashMap(map_data))
            .map_err(|e| format!("convert TRACE_LOG: {:?}", e))?;

    let keys: Vec<TraceEventKey> = collect_iterated_items(map.iter(), "TRACE_LOG")?
        .into_iter()
        .map(|(key, _)| key)
        .filter(|key| key.tap_id == runtime.tap_id)
        .collect();

    let v6_map_path = format!("{}/TRACE_LOG_V6", pin_path);
    let mut v6_map = match MapData::from_pin(&v6_map_path) {
        Ok(v6_map_data) => Some(
            HashMap::<_, TraceEventKey, TraceEventV6>::try_from(aya::maps::Map::LruHashMap(
                v6_map_data,
            ))
            .map_err(|e| format!("convert TRACE_LOG_V6: {:?}", e))?,
        ),
        Err(error) if pin_missing(&error) => None,
        Err(error) => return Err(format!("open TRACE_LOG_V6: {:?}", error)),
    };
    let v6_keys = match v6_map.as_ref() {
        Some(map) => collect_iterated_items(map.iter(), "TRACE_LOG_V6")?
            .into_iter()
            .map(|(key, _)| key)
            .filter(|key| key.tap_id == runtime.tap_id)
            .collect(),
        None => Vec::new(),
    };

    let v4_result = execute_counted_map_delete_batch(
        keys,
        |key| map.remove(key),
        "remove TRACE_LOG entry",
    );
    let v6_result = match v6_map.as_mut() {
        Some(map) => execute_counted_map_delete_batch(
            v6_keys,
            |key| map.remove(key),
            "remove TRACE_LOG_V6 entry",
        ),
        None => Ok(0),
    };

    match (v4_result, v6_result) {
        (Ok(v4), Ok(v6)) => Ok(v4 + v6),
        (Err(v4), Ok(_)) => Err(v4),
        (Ok(_), Err(v6)) => Err(v6),
        (Err(v4), Err(v6)) => Err(format!("{}; {}", v4, v6)),
    }
}

fn pin_missing(error: &MapError) -> bool {
    match error {
        MapError::SyscallError(syscall) => {
            syscall.io_error.kind() == std::io::ErrorKind::NotFound
        }
        MapError::PinError { error: pin_error, .. } => match pin_error {
            aya::pin::PinError::SyscallError(syscall) => {
                syscall.io_error.kind() == std::io::ErrorKind::NotFound
            }
            _ => false,
        },
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::{delete_trace_filter_entry, result_name};
    use aria_ebpf_abi::userspace::TRACE_RESULT_DROP_FRAGMENT;
    use aya::maps::MapError;

    #[test]
    fn fragment_observability_names_fragment_drop_separately_from_acl() {
        assert_eq!(result_name(TRACE_RESULT_DROP_FRAGMENT), "drop:fragment");
        assert_ne!(result_name(TRACE_RESULT_DROP_FRAGMENT), "drop:acl");
    }

    #[test]
    fn map_delete_trace_filter_is_idempotent_only_for_missing_key() {
        assert!(!delete_trace_filter_entry(
            || Err(MapError::KeyNotFound),
            "delete TRACE_FILTER tap 42",
        )
        .unwrap());

        let error = delete_trace_filter_entry(
            || {
                Err(MapError::InvalidKeySize {
                    size: 1,
                    expected: 4,
                })
            },
            "delete TRACE_FILTER tap 42",
        )
        .unwrap_err();
        assert!(error.contains("delete TRACE_FILTER tap 42"));
        assert!(error.contains("invalid key size"));
    }
}
