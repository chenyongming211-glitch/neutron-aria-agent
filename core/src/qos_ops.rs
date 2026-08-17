use aya::maps::{HashMap, MapData};

use crate::common::{QosConfig, QosKey, TapMapRuntime, TokenBucket};

/// Update the qos_enabled flag in FIREWALL_CONFIG map.
/// Called after every add/delete of a QoS rule to keep the flag in sync.
fn sync_qos_enabled(runtime: TapMapRuntime<'_>, enabled: bool) -> Result<(), String> {
    crate::ebpf_ops::update_runtime_config(
        runtime,
        None,
        None,
        None,
        Some(enabled),
        None,
        None,
        None,
    )
}

/// Check if any QoS rules remain in the QOS_CONFIG map.
fn has_qos_rules(runtime: TapMapRuntime<'_>) -> Result<bool, String> {
    let pin_path = runtime.pin_path;
    let map_path = format!("{}/QOS_CONFIG", pin_path);
    let Some(map_data) = crate::pinned_map::open_optional_pin("QOS_CONFIG", &map_path)? else {
        return Ok(false);
    };
    let map = crate::pinned_map::require_map_operation(
        "convert QOS_CONFIG",
        HashMap::<_, QosKey, QosConfig>::try_from(aya::maps::Map::HashMap(map_data)),
    )?;
    for item in map.iter() {
        let (key, _) = crate::pinned_map::require_map_operation("iterate QOS_CONFIG", item)?;
        if key.tap_id == runtime.tap_id {
            return Ok(true);
        }
    }
    Ok(false)
}

fn sync_qos_after_delete_with<HasRules, Sync>(
    user_qos_enabled: bool,
    has_rules: HasRules,
    sync: Sync,
) -> Result<(), String>
where
    HasRules: FnOnce() -> Result<bool, String>,
    Sync: FnOnce(bool) -> Result<(), String>,
{
    let enabled = if user_qos_enabled {
        has_rules()?
    } else {
        false
    };
    sync(enabled)
}

fn clear_qos_token_bucket(runtime: TapMapRuntime<'_>, key: &QosKey) -> Result<(), String> {
    let map_path = format!("{}/QOS_TOKEN_BUCKET", runtime.pin_path);
    let map_data =
        MapData::from_pin(&map_path).map_err(|e| format!("open QOS_TOKEN_BUCKET: {:?}", e))?;
    let mut map = HashMap::<_, QosKey, TokenBucket>::try_from(aya::maps::Map::HashMap(map_data))
        .map_err(|e| format!("convert QOS_TOKEN_BUCKET: {:?}", e))?;

    match map.remove(key) {
        Ok(()) => Ok(()),
        Err(e) => {
            let err = format!("{:?}", e);
            // Some kernel/map combinations report a missing hash key as ENOENT
            // instead of Aya's KeyNotFound variant. Treat both as "nothing to clear".
            if err.contains("KeyNotFound") || err.contains("No such file or directory") {
                Ok(())
            } else {
                Err(format!("QOS_TOKEN_BUCKET remove: {}", err))
            }
        }
    }
}

pub fn add_qos_rule(
    group_id: u32,
    direction: u8,
    rate_bps: u64,
    burst_bytes: u64,
    priority: u8,
    mode: u8,
    runtime: TapMapRuntime<'_>,
    user_qos_enabled: bool,
) -> Result<(), String> {
    let pin_path = runtime.pin_path;
    let map_path = format!("{}/QOS_CONFIG", pin_path);
    let map_data = MapData::from_pin(&map_path).map_err(|e| format!("open QOS_CONFIG: {:?}", e))?;
    let mut map = HashMap::<_, QosKey, QosConfig>::try_from(aya::maps::Map::HashMap(map_data))
        .map_err(|e| format!("convert QOS_CONFIG: {:?}", e))?;

    let key = QosKey {
        tap_id: runtime.tap_id,
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

    clear_qos_token_bucket(runtime, &key)?;
    map.insert(&key, &config, 0)
        .map_err(|e| format!("QOS_CONFIG insert: {:?}", e))?;

    // After adding a rule, QoS is active only if user wants it
    sync_qos_enabled(runtime, user_qos_enabled)?;

    Ok(())
}

pub fn delete_qos_rule(
    group_id: u32,
    direction: u8,
    runtime: TapMapRuntime<'_>,
    user_qos_enabled: bool,
) -> Result<(), String> {
    let pin_path = runtime.pin_path;
    let map_path = format!("{}/QOS_CONFIG", pin_path);
    let map_data = MapData::from_pin(&map_path).map_err(|e| format!("open QOS_CONFIG: {:?}", e))?;
    let mut map = HashMap::<_, QosKey, QosConfig>::try_from(aya::maps::Map::HashMap(map_data))
        .map_err(|e| format!("convert QOS_CONFIG: {:?}", e))?;

    let key = QosKey {
        tap_id: runtime.tap_id,
        group_id,
        direction,
        pad: [0; 3],
    };

    map.remove(&key)
        .map_err(|e| format!("QOS_CONFIG remove: {:?}", e))?;
    clear_qos_token_bucket(runtime, &key)?;

    // After deleting, check if any rules remain and user wants QoS
    sync_qos_after_delete_with(
        user_qos_enabled,
        || has_qos_rules(runtime),
        |enabled| sync_qos_enabled(runtime, enabled),
    )?;

    Ok(())
}

pub fn list_qos_rules(runtime: TapMapRuntime<'_>) -> Result<Vec<(QosKey, QosConfig)>, String> {
    let pin_path = runtime.pin_path;
    let map_path = format!("{}/QOS_CONFIG", pin_path);
    let map_data = MapData::from_pin(&map_path).map_err(|e| format!("open QOS_CONFIG: {:?}", e))?;
    let map = HashMap::<_, QosKey, QosConfig>::try_from(aya::maps::Map::HashMap(map_data))
        .map_err(|e| format!("convert QOS_CONFIG: {:?}", e))?;

    let mut entries = Vec::new();
    for item in map.iter() {
        let (key, val) = crate::pinned_map::require_map_operation("iterate QOS_CONFIG", item)?;
        if key.tap_id == runtime.tap_id {
            entries.push((key, val));
        }
    }

    Ok(entries)
}

pub fn replay_qos_rules(
    bpf: &mut aya::Ebpf,
    tap_id: u32,
    rules: &[(u32, u8, u64, u64, u8, u8)],
) -> Vec<String> {
    let mut errors = Vec::new();

    match bpf
        .map_mut("QOS_CONFIG")
        .ok_or_else(|| "QOS_CONFIG not found".to_string())
        .and_then(|m| HashMap::<_, QosKey, QosConfig>::try_from(m).map_err(|e| format!("{:?}", e)))
    {
        Ok(mut map) => {
            for &(group_id, direction, rate_bps, burst_bytes, priority, mode) in rules {
                let key = QosKey {
                    tap_id,
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
                    errors.push(format!(
                        "QOS_CONFIG group_id={} dir={}: {:?}",
                        group_id, direction, e
                    ));
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
/// We use a fixed 500 ms time window: burst = rate / 2.  This scales
/// linearly from 10 Mbps to 10 Gbps+ without any clamping distortion.
/// Minimum 256 KB to handle at least a few jumbo frames at very low rates.
pub fn compute_default_burst(rate_bps: u64) -> u64 {
    let burst = rate_bps / 2;
    if burst > 256 * 1024 {
        burst
    } else {
        256 * 1024
    }
}

pub fn parse_rate(rate_str: &str) -> Result<u64, String> {
    let s = rate_str.trim().to_lowercase();
    let bytes_per_sec = if let Some(num) = s.strip_suffix("gbps") {
        let n: f64 = num
            .trim()
            .parse()
            .map_err(|_| format!("Invalid rate: {}", rate_str))?;
        n * 1_000_000_000.0 / 8.0
    } else if let Some(num) = s.strip_suffix("mbps") {
        let n: f64 = num
            .trim()
            .parse()
            .map_err(|_| format!("Invalid rate: {}", rate_str))?;
        n * 1_000_000.0 / 8.0
    } else if let Some(num) = s.strip_suffix("kbps") {
        let n: f64 = num
            .trim()
            .parse()
            .map_err(|_| format!("Invalid rate: {}", rate_str))?;
        n * 1_000.0 / 8.0
    } else if let Some(num) = s.strip_suffix("bps") {
        let n: f64 = num
            .trim()
            .parse()
            .map_err(|_| format!("Invalid rate: {}", rate_str))?;
        n / 8.0
    } else {
        return s
            .parse::<u64>()
            .map_err(|_| format!("Invalid rate: {}. Use format like 100mbps, 1gbps", rate_str));
    };
    if bytes_per_sec < 0.0 {
        return Err(format!("Rate must be positive: {}", rate_str));
    }
    Ok(bytes_per_sec as u64)
}

pub fn parse_burst(burst_str: &str) -> Result<u64, String> {
    let s = burst_str.trim().to_lowercase();
    let bytes = if let Some(num) = s.strip_suffix("gb") {
        let n: f64 = num
            .trim()
            .parse()
            .map_err(|_| format!("Invalid burst: {}", burst_str))?;
        n * 1_073_741_824.0
    } else if let Some(num) = s.strip_suffix("mb") {
        let n: f64 = num
            .trim()
            .parse()
            .map_err(|_| format!("Invalid burst: {}", burst_str))?;
        n * 1_048_576.0
    } else if let Some(num) = s.strip_suffix("kb") {
        let n: f64 = num
            .trim()
            .parse()
            .map_err(|_| format!("Invalid burst: {}", burst_str))?;
        n * 1024.0
    } else {
        return s
            .parse::<u64>()
            .map_err(|_| format!("Invalid burst: {}. Use format like 1mb, 512kb", burst_str));
    };
    if bytes < 0.0 {
        return Err(format!("Burst must be positive: {}", burst_str));
    }
    Ok(bytes as u64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    #[test]
    fn map_authority_qos_read_fault_preserves_the_current_enable_flag() {
        let sync_calls = Cell::new(0usize);
        let error = sync_qos_after_delete_with(
            true,
            || Err("open QOS_CONFIG: permission denied".to_string()),
            |_| {
                sync_calls.set(sync_calls.get() + 1);
                Ok(())
            },
        )
        .unwrap_err();

        assert_eq!(error, "open QOS_CONFIG: permission denied");
        assert_eq!(sync_calls.get(), 0);
    }

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
        // 10 Mbps = 1.25 MB/s: rate/2 = 625 KB (500ms window)
        let b = compute_default_burst(1_250_000);
        assert_eq!(b, 625_000);

        // 100 Mbps = 12.5 MB/s: rate/2 = 6.25 MB
        let b = compute_default_burst(12_500_000);
        assert_eq!(b, 6_250_000);

        // 500 Mbps = 62.5 MB/s: rate/2 = 31.25 MB
        let b = compute_default_burst(62_500_000);
        assert_eq!(b, 31_250_000);

        // 10 Gbps = 1.25 GB/s: rate/2 = 625 MB (no cap)
        let b = compute_default_burst(1_250_000_000);
        assert_eq!(b, 625_000_000);

        // Very low rate: minimum 256 KB
        let b = compute_default_burst(1000);
        assert_eq!(b, 256 * 1024);
    }
}
