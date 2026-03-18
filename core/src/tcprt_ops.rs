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
            entries.push(TcpRtEntry {
                src_ip: Ipv4Addr::from(key.src_ip).to_string(),
                dst_ip: Ipv4Addr::from(key.dst_ip).to_string(),
                src_port: key.src_port,
                dst_port: key.dst_port,
                handshake_us: val.handshake_ns as f64 / 1000.0,
                rtt_client_us: val.rtt_client_ns as f64 / 1000.0,
                rtt_server_us: val.rtt_server_ns as f64 / 1000.0,
                art_us: val.art_ns as f64 / 1000.0,
                retrans_req: val.retrans_req,
                retrans_resp: val.retrans_resp,
                request_count: val.request_count,
                state: state_name(val.state),
            });
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
            entries.push(TcpRtEntry {
                src_ip: Ipv6Addr::from(key.src_ip).to_string(),
                dst_ip: Ipv6Addr::from(key.dst_ip).to_string(),
                src_port: key.src_port,
                dst_port: key.dst_port,
                handshake_us: val.handshake_ns as f64 / 1000.0,
                rtt_client_us: val.rtt_client_ns as f64 / 1000.0,
                rtt_server_us: val.rtt_server_ns as f64 / 1000.0,
                art_us: val.art_ns as f64 / 1000.0,
                retrans_req: val.retrans_req,
                retrans_resp: val.retrans_resp,
                request_count: val.request_count,
                state: state_name(val.state),
            });
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
