use aya::maps::{HashMap, MapData};
use crate::common::{QosKey, QosConfig, FirewallConfig};

/// Update the qos_enabled flag in FIREWALL_CONFIG map.
/// Called after every add/delete of a QoS rule to keep the flag in sync.
fn sync_qos_enabled(pin_path: &str, enabled: bool) -> Result<(), String> {
    let map_path = format!("{}/FIREWALL_CONFIG", pin_path);
    let map_data = MapData::from_pin(&map_path)
        .map_err(|e| format!("open FIREWALL_CONFIG: {:?}", e))?;
    let mut map = HashMap::<_, u32, FirewallConfig>::try_from(
        aya::maps::Map::HashMap(map_data)
    ).map_err(|e| format!("convert FIREWALL_CONFIG: {:?}", e))?;

    let mut cfg = map.get(&0u32, 0).unwrap_or(FirewallConfig {
        conntrack_enabled: 1,
        monitoring_enabled: 1,
        num_cpus: 1,
        qos_enabled: 0,
        pad: [0; 3],
    });
    cfg.qos_enabled = if enabled { 1 } else { 0 };
    map.insert(&0u32, &cfg, 0)
        .map_err(|e| format!("FIREWALL_CONFIG update qos_enabled: {:?}", e))?;
    Ok(())
}

/// Check if any QoS rules remain in the QOS_CONFIG map.
fn has_qos_rules(pin_path: &str) -> bool {
    let map_path = format!("{}/QOS_CONFIG", pin_path);
    let Ok(map_data) = MapData::from_pin(&map_path) else { return false };
    let Ok(map) = HashMap::<_, QosKey, QosConfig>::try_from(
        aya::maps::Map::HashMap(map_data)
    ) else { return false };
    map.iter().next().is_some()
}

pub fn add_qos_rule(
    group_id: u32,
    direction: u8,
    rate_bps: u64,
    burst_bytes: u64,
    priority: u8,
    mode: u8,
    pin_path: &str,
) -> Result<(), String> {
    let map_path = format!("{}/QOS_CONFIG", pin_path);
    let map_data = MapData::from_pin(&map_path)
        .map_err(|e| format!("open QOS_CONFIG: {:?}", e))?;
    let mut map = HashMap::<_, QosKey, QosConfig>::try_from(
        aya::maps::Map::HashMap(map_data)
    ).map_err(|e| format!("convert QOS_CONFIG: {:?}", e))?;

    let key = QosKey {
        group_id,
        direction,
        pad: [0; 3],
    };
    let config = QosConfig {
        rate_bps,
        burst_bytes,
        priority,
        mode,
        pad: [0; 6],
    };

    map.insert(&key, &config, 0)
        .map_err(|e| format!("QOS_CONFIG insert: {:?}", e))?;

    // After adding a rule, QoS is definitely active
    sync_qos_enabled(pin_path, true)?;

    Ok(())
}

pub fn delete_qos_rule(
    group_id: u32,
    direction: u8,
    pin_path: &str,
) -> Result<(), String> {
    let map_path = format!("{}/QOS_CONFIG", pin_path);
    let map_data = MapData::from_pin(&map_path)
        .map_err(|e| format!("open QOS_CONFIG: {:?}", e))?;
    let mut map = HashMap::<_, QosKey, QosConfig>::try_from(
        aya::maps::Map::HashMap(map_data)
    ).map_err(|e| format!("convert QOS_CONFIG: {:?}", e))?;

    let key = QosKey {
        group_id,
        direction,
        pad: [0; 3],
    };

    map.remove(&key)
        .map_err(|e| format!("QOS_CONFIG remove: {:?}", e))?;

    // After deleting, check if any rules remain
    sync_qos_enabled(pin_path, has_qos_rules(pin_path))?;

    Ok(())
}

pub fn list_qos_rules(pin_path: &str) -> Result<Vec<(QosKey, QosConfig)>, String> {
    let map_path = format!("{}/QOS_CONFIG", pin_path);
    let map_data = MapData::from_pin(&map_path)
        .map_err(|e| format!("open QOS_CONFIG: {:?}", e))?;
    let map = HashMap::<_, QosKey, QosConfig>::try_from(
        aya::maps::Map::HashMap(map_data)
    ).map_err(|e| format!("convert QOS_CONFIG: {:?}", e))?;

    let mut entries = Vec::new();
    for item in map.iter() {
        if let Ok((key, val)) = item {
            entries.push((key, val));
        }
    }

    Ok(entries)
}

pub fn replay_qos_rules(bpf: &mut aya::Ebpf, rules: &[(u32, u8, u64, u64, u8, u8)]) -> Vec<String> {
    let mut errors = Vec::new();

    match bpf.map_mut("QOS_CONFIG")
        .ok_or_else(|| "QOS_CONFIG not found".to_string())
        .and_then(|m| HashMap::<_, QosKey, QosConfig>::try_from(m).map_err(|e| format!("{:?}", e)))
    {
        Ok(mut map) => {
            for &(group_id, direction, rate_bps, burst_bytes, priority, mode) in rules {
                let key = QosKey {
                    group_id,
                    direction,
                    pad: [0; 3],
                };
                let config = QosConfig {
                    rate_bps,
                    burst_bytes,
                    priority,
                    mode,
                    pad: [0; 6],
                };
                if let Err(e) = map.insert(&key, &config, 0) {
                    errors.push(format!("QOS_CONFIG group_id={} dir={}: {:?}", group_id, direction, e));
                }
            }
        }
        Err(e) => errors.push(format!("QOS_CONFIG: {}", e)),
    }

    errors
}

/// Compute a sensible default burst size based on rate (bytes/sec).
///
/// TCP sends in bursts equal to its congestion window (cwnd).  The burst
/// must be large enough to absorb a full cwnd without triggering policer
/// drops, otherwise TCP's congestion control over-reacts and throughput
/// collapses well below the configured rate.
///
/// Empirical testing showed that ~500 ms worth of tokens is the sweet spot:
/// - Small enough that the policer still converges quickly
/// - Large enough to absorb TCP bursts at any rate
///
/// Minimum burst is 5 MB to handle TCP at low rates; capped at 100 MB.
pub fn compute_default_burst(rate_bps: u64) -> u64 {
    // 500ms worth of tokens at the configured rate
    let burst = rate_bps / 2;
    // Clamp: at least 5 MB, at most 100 MB
    let min_burst: u64 = 5 * 1024 * 1024;       // 5 MB
    let max_burst: u64 = 100 * 1024 * 1024;      // 100 MB
    if burst < min_burst {
        min_burst
    } else if burst > max_burst {
        max_burst
    } else {
        burst
    }
}

pub fn parse_rate(rate_str: &str) -> Result<u64, String> {
    let s = rate_str.trim().to_lowercase();
    let bytes_per_sec = if let Some(num) = s.strip_suffix("gbps") {
        let n: f64 = num.trim().parse().map_err(|_| format!("Invalid rate: {}", rate_str))?;
        n * 1_000_000_000.0 / 8.0
    } else if let Some(num) = s.strip_suffix("mbps") {
        let n: f64 = num.trim().parse().map_err(|_| format!("Invalid rate: {}", rate_str))?;
        n * 1_000_000.0 / 8.0
    } else if let Some(num) = s.strip_suffix("kbps") {
        let n: f64 = num.trim().parse().map_err(|_| format!("Invalid rate: {}", rate_str))?;
        n * 1_000.0 / 8.0
    } else if let Some(num) = s.strip_suffix("bps") {
        let n: f64 = num.trim().parse().map_err(|_| format!("Invalid rate: {}", rate_str))?;
        n / 8.0
    } else {
        return s.parse::<u64>().map_err(|_| format!("Invalid rate: {}. Use format like 100mbps, 1gbps", rate_str));
    };
    if bytes_per_sec < 0.0 {
        return Err(format!("Rate must be positive: {}", rate_str));
    }
    Ok(bytes_per_sec as u64)
}

pub fn parse_burst(burst_str: &str) -> Result<u64, String> {
    let s = burst_str.trim().to_lowercase();
    let bytes = if let Some(num) = s.strip_suffix("gb") {
        let n: f64 = num.trim().parse().map_err(|_| format!("Invalid burst: {}", burst_str))?;
        n * 1_073_741_824.0
    } else if let Some(num) = s.strip_suffix("mb") {
        let n: f64 = num.trim().parse().map_err(|_| format!("Invalid burst: {}", burst_str))?;
        n * 1_048_576.0
    } else if let Some(num) = s.strip_suffix("kb") {
        let n: f64 = num.trim().parse().map_err(|_| format!("Invalid burst: {}", burst_str))?;
        n * 1024.0
    } else {
        return s.parse::<u64>().map_err(|_| format!("Invalid burst: {}. Use format like 1mb, 512kb", burst_str));
    };
    if bytes < 0.0 {
        return Err(format!("Burst must be positive: {}", burst_str));
    }
    Ok(bytes as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_rate_supports_common_units() {
        assert_eq!(parse_rate("8bps").unwrap(), 1); // 8 bit/s = 1 B/s
        assert_eq!(parse_rate("1kbps").unwrap(), 1_000 / 8);
        assert_eq!(parse_rate("2mbps").unwrap(), 2_000_000 / 8);
        assert_eq!(parse_rate("1gbps").unwrap(), 1_000_000_000 / 8);

        // bare number → bytes per second
        assert_eq!(parse_rate("1024").unwrap(), 1024);
    }

    #[test]
    fn parse_rate_rejects_invalid() {
        assert!(parse_rate("abc").is_err());
        assert!(parse_rate("10mpbs").is_err()); // typo
    }

    #[test]
    fn parse_burst_supports_common_units() {
        assert_eq!(parse_burst("1kb").unwrap(), 1024);
        assert_eq!(parse_burst("1mb").unwrap(), 1_048_576);
        assert_eq!(parse_burst("1gb").unwrap(), 1_073_741_824);

        // bare number → bytes
        assert_eq!(parse_burst("4096").unwrap(), 4096);
    }

    #[test]
    fn parse_burst_rejects_invalid() {
        assert!(parse_burst("xyz").is_err());
        assert!(parse_burst("10mbps").is_err());
    }

    #[test]
    fn compute_default_burst_tiers() {
        // Low rate (10 Mbps = 1.25 MB/s): clamped to min 5 MB
        let b = compute_default_burst(1_250_000);
        assert_eq!(b, 5 * 1024 * 1024);

        // 100 Mbps = 12.5 MB/s: rate/2 = 6.25 MB
        let b = compute_default_burst(12_500_000);
        assert_eq!(b, 6_250_000);

        // 500 Mbps = 62.5 MB/s: rate/2 = 31.25 MB
        let b = compute_default_burst(62_500_000);
        assert_eq!(b, 31_250_000);

        // 10 Gbps = 1.25 GB/s: rate/2 = 625 MB, capped to 100 MB
        let b = compute_default_burst(1_250_000_000);
        assert_eq!(b, 100 * 1024 * 1024);

        // Very low rate: clamped to min 5 MB
        let b = compute_default_burst(1000);
        assert_eq!(b, 5 * 1024 * 1024);
    }
}
