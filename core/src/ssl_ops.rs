use aya::maps::{HashMap, MapData};
use crate::common::{SslConnValue, SslHttpValue, SslErrorEvent};

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

/// Parse method, path, and host from raw HTTP request header bytes
/// Robust parsing: case-insensitive Host header, tolerant whitespace
fn parse_http_request(data: &[u8; 256]) -> (String, String, String) {
    let raw = bytes_to_string(data);

    // Parse request line: "METHOD PATH HTTP/1.x"
    // Handle multiple spaces between parts (non-standard but common)
    let first_line = match raw.split("\r\n").next() {
        Some(line) => line,
        None => return (String::new(), String::new(), String::new()),
    };

    // Split by whitespace, filter empty parts (handles multiple spaces)
    let mut parts = first_line.split_whitespace();
    let method = parts.next().unwrap_or("").to_string();
    let path = parts.next().unwrap_or("").to_string();

    // Parse Host header (case-insensitive, tolerant of whitespace)
    let mut host = String::new();
    for line in raw.split("\r\n").skip(1) {
        let line_trimmed = line.trim();
        if line_trimmed.is_empty() {
            continue;
        }

        // Case-insensitive Host header matching
        // Accepts: "Host: example.com", "host: example.com", "HOST: example.com"
        // Also handles: "Host : example.com", "Host:  example.com"
        let line_lower = line_trimmed.to_lowercase();
        if line_lower.starts_with("host") {
            // Find the colon and extract value
            if let Some(colon_pos) = line_trimmed.find(':') {
                let value = line_trimmed[colon_pos + 1..].trim();
                if !value.is_empty() {
                    host = value.to_string();
                    break;
                }
            }
        }
    }

    (method, path, host)
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
            let (method, path, host) = parse_http_request(&val.req_data);
            entries.push(SslHttpEntry {
                seq,
                pid: val.pid,
                tid: val.tid,
                method,
                path,
                host,
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

// --- Global SSL Observability Config ---

/// Get global SSL observability enabled status from the host-global SSL pin path.
pub fn get_ssl_global_config(pin_path: &str) -> Result<bool, String> {
    let map_path = format!("{}/SSL_GLOBAL_CONFIG", pin_path);

    // Map may not exist if no instance has started SSL yet
    if !std::path::Path::new(&map_path).exists() {
        return Ok(false);
    }

    let map_data = MapData::from_pin(&map_path)
        .map_err(|e| format!("open SSL_GLOBAL_CONFIG: {:?}", e))?;
    let map = HashMap::<_, u32, u8>::try_from(
        aya::maps::Map::HashMap(map_data)
    ).map_err(|e| format!("convert SSL_GLOBAL_CONFIG: {:?}", e))?;

    match map.get(&0u32, 0) {
        Ok(v) => Ok(v != 0),
        Err(_) => Ok(false),
    }
}

/// Set global SSL observability enabled status.
/// This affects all processes with SSL uprobes attached.
pub fn set_ssl_global_config(pin_path: &str, enabled: bool) -> Result<(), String> {
    let map_path = format!("{}/SSL_GLOBAL_CONFIG", pin_path);

    // Map may not exist if the global SSL manager has not initialized yet.
    if !std::path::Path::new(&map_path).exists() {
        return Err("SSL_GLOBAL_CONFIG map not found - initialize the global SSL manager first".to_string());
    }

    let map_data = MapData::from_pin(&map_path)
        .map_err(|e| format!("open SSL_GLOBAL_CONFIG: {:?}", e))?;
    let mut map = HashMap::<_, u32, u8>::try_from(
        aya::maps::Map::HashMap(map_data)
    ).map_err(|e| format!("convert SSL_GLOBAL_CONFIG: {:?}", e))?;

    let value: u8 = if enabled { 1 } else { 0 };
    map.insert(&0u32, &value, 0)
        .map_err(|e| format!("SSL_GLOBAL_CONFIG insert: {:?}", e))?;

    Ok(())
}

// --- SSL Error Events ---

pub struct SslErrorEntry {
    pub seq: u64,
    pub pid: u32,
    pub tid: u32,
    pub timestamp: u64,
    pub syscall: String,
    pub ret_code: i32,
    pub error_hint: String,
}

/// Get all SSL error events from map
pub fn get_ssl_errors(pin_path: &str) -> Result<Vec<SslErrorEntry>, String> {
    let map_path = format!("{}/SSL_ERROR_TABLE", pin_path);

    if !std::path::Path::new(&map_path).exists() {
        return Ok(Vec::new());
    }

    let map_data = MapData::from_pin(&map_path)
        .map_err(|e| format!("open SSL_ERROR_TABLE: {:?}", e))?;
    let map = HashMap::<_, u64, SslErrorEvent>::try_from(
        aya::maps::Map::LruHashMap(map_data)
    ).map_err(|e| format!("convert SSL_ERROR_TABLE: {:?}", e))?;

    let mut entries = Vec::new();
    for item in map.iter() {
        if let Ok((seq, val)) = item {
            let syscall = match val.syscall {
                0 => "read",
                1 => "write",
                _ => "unknown",
            }.to_string();

            let error_hint = match val.error_hint {
                0 => "none",
                1 => "zero_return",
                2 => "want_retry",
                3 => "syscall_err",
                _ => "unknown",
            }.to_string();

            entries.push(SslErrorEntry {
                seq,
                pid: val.pid,
                tid: val.tid,
                timestamp: val.timestamp,
                syscall,
                ret_code: val.ret_code,
                error_hint,
            });
        }
    }
    entries.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
    Ok(entries)
}

/// Flush all SSL error events
pub fn flush_ssl_errors(pin_path: &str) -> Result<u64, String> {
    let map_path = format!("{}/SSL_ERROR_TABLE", pin_path);

    if !std::path::Path::new(&map_path).exists() {
        return Ok(0);
    }

    let map_data = MapData::from_pin(&map_path)
        .map_err(|e| format!("open SSL_ERROR_TABLE: {:?}", e))?;
    let mut map = HashMap::<_, u64, SslErrorEvent>::try_from(
        aya::maps::Map::LruHashMap(map_data)
    ).map_err(|e| format!("convert SSL_ERROR_TABLE: {:?}", e))?;

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
