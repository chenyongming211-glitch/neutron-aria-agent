use aya::maps::{HashMap, MapData};
use crate::common::{CtKey4, CtKey6, TcpRtValue};
use std::net::{Ipv4Addr, Ipv6Addr};

pub struct TcpRtEntry {
    pub src_ip: String,
    pub dst_ip: String,
    pub src_port: u16,
    pub dst_port: u16,
    pub handshake_us: f64,
    pub rtt_client_us: f64,
    pub rtt_server_us: f64,
    pub art_us: f64,
    pub retrans_req: u32,
    pub retrans_resp: u32,
    pub request_count: u32,
    pub state: String,
    pub forward_platform_us: f64,
    pub server_network_us: f64,
    pub reverse_platform_us: f64,
}

fn state_name(state: u8) -> String {
    match state {
        0 => "handshake".to_string(),
        1 => "established".to_string(),
        2 => "closing".to_string(),
        _ => "unknown".to_string(),
    }
}

pub fn get_tcprt_flows_v4(pin_path: &str) -> Result<Vec<TcpRtEntry>, String> {
    let map_path = format!("{}/TCPRT_TABLE_V4", pin_path);
    let map_data = MapData::from_pin(&map_path)
        .map_err(|e| format!("open TCPRT_TABLE_V4: {:?}", e))?;
    let map = HashMap::<_, CtKey4, TcpRtValue>::try_from(
        aya::maps::Map::LruHashMap(map_data)
    ).map_err(|e| format!("convert TCPRT_TABLE_V4: {:?}", e))?;

    let mut entries = Vec::new();
    for item in map.iter() {
        if let Ok((key, val)) = item {
            entries.push(value_to_entry(
                Ipv4Addr::from(key.src_ip).to_string(),
                Ipv4Addr::from(key.dst_ip).to_string(),
                key.src_port, key.dst_port, &val,
            ));
        }
    }
    Ok(entries)
}

pub fn get_tcprt_flows_v6(pin_path: &str) -> Result<Vec<TcpRtEntry>, String> {
    let map_path = format!("{}/TCPRT_TABLE_V6", pin_path);
    let map_data = MapData::from_pin(&map_path)
        .map_err(|e| format!("open TCPRT_TABLE_V6: {:?}", e))?;
    let map = HashMap::<_, CtKey6, TcpRtValue>::try_from(
        aya::maps::Map::LruHashMap(map_data)
    ).map_err(|e| format!("convert TCPRT_TABLE_V6: {:?}", e))?;

    let mut entries = Vec::new();
    for item in map.iter() {
        if let Ok((key, val)) = item {
            entries.push(value_to_entry(
                Ipv6Addr::from(key.src_ip).to_string(),
                Ipv6Addr::from(key.dst_ip).to_string(),
                key.src_port, key.dst_port, &val,
            ));
        }
    }
    Ok(entries)
}

fn value_to_entry(src_ip: String, dst_ip: String, src_port: u16, dst_port: u16, val: &TcpRtValue) -> TcpRtEntry {
    let dual = val.syn_ingress_ts > 0 && val.syn_ingress_ts != val.syn_ts;
    TcpRtEntry {
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        handshake_us: val.handshake_ns as f64 / 1000.0,
        rtt_client_us: val.rtt_client_ns as f64 / 1000.0,
        rtt_server_us: val.rtt_server_ns as f64 / 1000.0,
        art_us: val.art_ns as f64 / 1000.0,
        retrans_req: val.retrans_req,
        retrans_resp: val.retrans_resp,
        request_count: val.request_count,
        state: state_name(val.state),
        forward_platform_us: if dual { (val.syn_ts - val.syn_ingress_ts) as f64 / 1000.0 } else { 0.0 },
        server_network_us: if dual && val.synack_ingress_ts > 0 {
            (val.synack_ingress_ts - val.syn_ts) as f64 / 1000.0
        } else { 0.0 },
        reverse_platform_us: if dual && val.synack_ingress_ts > 0 {
            (val.synack_ts - val.synack_ingress_ts) as f64 / 1000.0
        } else { 0.0 },
    }
}

/// O(1) lookup of specific flows by 4-tuple. Returns matching entries.
pub fn lookup_tcprt_flows(pin_path: &str, tuples: &[(String, String, u16, u16)]) -> Result<Vec<TcpRtEntry>, String> {
    let mut entries = Vec::new();

    // Try V4 lookups
    let v4_path = format!("{}/TCPRT_TABLE_V4", pin_path);
    if let Ok(map_data) = MapData::from_pin(&v4_path) {
        if let Ok(map) = HashMap::<_, CtKey4, TcpRtValue>::try_from(
            aya::maps::Map::LruHashMap(map_data)
        ) {
            for (src_ip, dst_ip, src_port, dst_port) in tuples {
                if let (Ok(sip), Ok(dip)) = (src_ip.parse::<Ipv4Addr>(), dst_ip.parse::<Ipv4Addr>()) {
                    let key = CtKey4 {
                        src_ip: u32::from(sip),
                        dst_ip: u32::from(dip),
                        src_port: *src_port,
                        dst_port: *dst_port,
                        proto: 6,
                        pad: [0; 3],
                    };
                    if let Ok(val) = map.get(&key, 0) {
                        entries.push(value_to_entry(src_ip.clone(), dst_ip.clone(), *src_port, *dst_port, &val));
                    }
                }
            }
        }
    }

    // Try V6 lookups
    let v6_path = format!("{}/TCPRT_TABLE_V6", pin_path);
    if let Ok(map_data) = MapData::from_pin(&v6_path) {
        if let Ok(map) = HashMap::<_, CtKey6, TcpRtValue>::try_from(
            aya::maps::Map::LruHashMap(map_data)
        ) {
            for (src_ip, dst_ip, src_port, dst_port) in tuples {
                if let (Ok(sip), Ok(dip)) = (src_ip.parse::<Ipv6Addr>(), dst_ip.parse::<Ipv6Addr>()) {
                    let key = CtKey6 {
                        src_ip: sip.octets(),
                        dst_ip: dip.octets(),
                        src_port: *src_port,
                        dst_port: *dst_port,
                        proto: 6,
                        pad: [0; 3],
                    };
                    if let Ok(val) = map.get(&key, 0) {
                        entries.push(value_to_entry(src_ip.clone(), dst_ip.clone(), *src_port, *dst_port, &val));
                    }
                }
            }
        }
    }

    Ok(entries)
}

/// Filter TCP-RT flows by dst_ip + dst_port (service address). Iterates all entries.
pub fn filter_tcprt_flows(pin_path: &str, dst_ip: &str, dst_port: u16) -> Result<Vec<TcpRtEntry>, String> {
    let mut entries = Vec::new();

    // Filter V4
    let v4_path = format!("{}/TCPRT_TABLE_V4", pin_path);
    if let Ok(map_data) = MapData::from_pin(&v4_path) {
        if let Ok(map) = HashMap::<_, CtKey4, TcpRtValue>::try_from(
            aya::maps::Map::LruHashMap(map_data)
        ) {
            let target_ip: Option<Ipv4Addr> = dst_ip.parse().ok();
            for item in map.iter() {
                if let Ok((key, val)) = item {
                    if key.dst_port != dst_port {
                        continue;
                    }
                    if let Some(tip) = target_ip {
                        if key.dst_ip != u32::from(tip) {
                            continue;
                        }
                    } else {
                        continue;
                    }
                    entries.push(value_to_entry(
                        Ipv4Addr::from(key.src_ip).to_string(),
                        Ipv4Addr::from(key.dst_ip).to_string(),
                        key.src_port, key.dst_port, &val,
                    ));
                }
            }
        }
    }

    // Filter V6
    let v6_path = format!("{}/TCPRT_TABLE_V6", pin_path);
    if let Ok(map_data) = MapData::from_pin(&v6_path) {
        if let Ok(map) = HashMap::<_, CtKey6, TcpRtValue>::try_from(
            aya::maps::Map::LruHashMap(map_data)
        ) {
            let target_ip: Option<Ipv6Addr> = dst_ip.parse().ok();
            for item in map.iter() {
                if let Ok((key, val)) = item {
                    if key.dst_port != dst_port {
                        continue;
                    }
                    if let Some(tip) = target_ip {
                        if key.dst_ip != tip.octets() {
                            continue;
                        }
                    } else {
                        continue;
                    }
                    entries.push(value_to_entry(
                        Ipv6Addr::from(key.src_ip).to_string(),
                        Ipv6Addr::from(key.dst_ip).to_string(),
                        key.src_port, key.dst_port, &val,
                    ));
                }
            }
        }
    }

    Ok(entries)
}

pub fn flush_tcprt(pin_path: &str) -> Result<u64, String> {
    let mut count = 0u64;

    // Flush TCPRT_TABLE_V4
    let map_path = format!("{}/TCPRT_TABLE_V4", pin_path);
    if let Ok(map_data) = MapData::from_pin(&map_path) {
        if let Ok(mut map) = HashMap::<_, CtKey4, TcpRtValue>::try_from(
            aya::maps::Map::LruHashMap(map_data)
        ) {
            let keys: Vec<CtKey4> = map.iter()
                .filter_map(|item| item.ok().map(|(k, _)| k))
                .collect();
            for key in keys {
                if map.remove(&key).is_ok() {
                    count += 1;
                }
            }
        }
    }

    // Flush TCPRT_TABLE_V6
    let map_path = format!("{}/TCPRT_TABLE_V6", pin_path);
    if let Ok(map_data) = MapData::from_pin(&map_path) {
        if let Ok(mut map) = HashMap::<_, CtKey6, TcpRtValue>::try_from(
            aya::maps::Map::LruHashMap(map_data)
        ) {
            let keys: Vec<CtKey6> = map.iter()
                .filter_map(|item| item.ok().map(|(k, _)| k))
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
