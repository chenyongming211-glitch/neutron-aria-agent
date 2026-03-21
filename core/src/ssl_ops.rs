use aya::maps::{HashMap, MapData};
use crate::common::{SslConnValue, SslHttpValue};

pub struct SslConnEntry {
    pub seq: u64,
    pub pid: u32,
    pub tid: u32,
    pub handshake_us: f64,
    pub timestamp: u64,
    pub sni: String,
}

fn sni_from_bytes(bytes: &[u8; 64]) -> String {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(64);
    String::from_utf8_lossy(&bytes[..end]).to_string()
}

pub fn get_ssl_conns(pin_path: &str) -> Result<Vec<SslConnEntry>, String> {
    let map_path = format!("{}/SSL_CONN_TABLE", pin_path);
    let map_data = MapData::from_pin(&map_path)
        .map_err(|e| format!("open SSL_CONN_TABLE: {:?}", e))?;
    let map = HashMap::<_, u64, SslConnValue>::try_from(
        aya::maps::Map::LruHashMap(map_data)
    ).map_err(|e| format!("convert SSL_CONN_TABLE: {:?}", e))?;

    let mut entries = Vec::new();
    for item in map.iter() {
        if let Ok((seq, val)) = item {
            entries.push(SslConnEntry {
                seq,
                pid: val.pid,
                tid: val.tid,
                handshake_us: val.handshake_ns as f64 / 1000.0,
                timestamp: val.timestamp,
                sni: sni_from_bytes(&val.sni),
            });
        }
    }
    // Sort by timestamp descending (newest first)
    entries.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
    Ok(entries)
}

pub fn flush_ssl_conns(pin_path: &str) -> Result<u64, String> {
    let map_path = format!("{}/SSL_CONN_TABLE", pin_path);
    let map_data = MapData::from_pin(&map_path)
        .map_err(|e| format!("open SSL_CONN_TABLE: {:?}", e))?;
    let mut map = HashMap::<_, u64, SslConnValue>::try_from(
        aya::maps::Map::LruHashMap(map_data)
    ).map_err(|e| format!("convert SSL_CONN_TABLE: {:?}", e))?;

    let keys: Vec<u64> = map.iter()
        .filter_map(|item| item.ok().map(|(k, _)| k))
        .collect();
    let mut count = 0u64;
    for key in keys {
        if map.remove(&key).is_ok() {
            count += 1;
        }
    }
    Ok(count)
}

// --- SSL HTTP Events ---

pub struct SslHttpEntry {
    pub seq: u64,
    pub pid: u32,
    pub tid: u32,
    pub method: String,
    pub path: String,
    pub host: String,
    pub status_code: u16,
    pub latency_us: f64,
    pub request_ts: u64,
    pub response_ts: u64,
}

fn bytes_to_string(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).to_string()
}

pub fn get_ssl_http_events(pin_path: &str) -> Result<Vec<SslHttpEntry>, String> {
    let map_path = format!("{}/SSL_HTTP_TABLE", pin_path);
    let map_data = MapData::from_pin(&map_path)
        .map_err(|e| format!("open SSL_HTTP_TABLE: {:?}", e))?;
    let map = HashMap::<_, u64, SslHttpValue>::try_from(
        aya::maps::Map::LruHashMap(map_data)
    ).map_err(|e| format!("convert SSL_HTTP_TABLE: {:?}", e))?;

    let mut entries = Vec::new();
    for item in map.iter() {
        if let Ok((seq, val)) = item {
            entries.push(SslHttpEntry {
                seq,
                pid: val.pid,
                tid: val.tid,
                method: bytes_to_string(&val.method),
                path: bytes_to_string(&val.path),
                host: bytes_to_string(&val.host),
                status_code: val.status_code,
                latency_us: val.latency_ns as f64 / 1000.0,
                request_ts: val.request_ts,
                response_ts: val.response_ts,
            });
        }
    }
    entries.sort_by(|a, b| b.response_ts.cmp(&a.response_ts));
    Ok(entries)
}

pub fn flush_ssl_http_events(pin_path: &str) -> Result<u64, String> {
    let map_path = format!("{}/SSL_HTTP_TABLE", pin_path);
    let map_data = MapData::from_pin(&map_path)
        .map_err(|e| format!("open SSL_HTTP_TABLE: {:?}", e))?;
    let mut map = HashMap::<_, u64, SslHttpValue>::try_from(
        aya::maps::Map::LruHashMap(map_data)
    ).map_err(|e| format!("convert SSL_HTTP_TABLE: {:?}", e))?;

    let keys: Vec<u64> = map.iter()
        .filter_map(|item| item.ok().map(|(k, _)| k))
        .collect();
    let mut count = 0u64;
    for key in keys {
        if map.remove(&key).is_ok() {
            count += 1;
        }
    }
    Ok(count)
}
