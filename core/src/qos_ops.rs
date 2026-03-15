use aya::maps::{HashMap, MapData};
use crate::common::{QosKey, QosConfig, DIR_EGRESS};

pub fn add_qos_rule(
    group_id: u32,
    direction: u8,
    rate_bps: u64,
    burst_bytes: u64,
    priority: u8,
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
        pad: [0; 7],
    };

    map.insert(&key, &config, 0)
        .map_err(|e| format!("QOS_CONFIG insert: {:?}", e))?;

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

pub fn replay_qos_rules(bpf: &mut aya::Ebpf, rules: &[(u32, u8, u64, u64, u8)]) -> Vec<String> {
    let mut errors = Vec::new();

    match bpf.map_mut("QOS_CONFIG")
        .ok_or_else(|| "QOS_CONFIG not found".to_string())
        .and_then(|m| HashMap::<_, QosKey, QosConfig>::try_from(m).map_err(|e| format!("{:?}", e)))
    {
        Ok(mut map) => {
            for &(group_id, direction, rate_bps, burst_bytes, priority) in rules {
                let key = QosKey {
                    group_id,
                    direction,
                    pad: [0; 3],
                };
                let config = QosConfig {
                    rate_bps,
                    burst_bytes,
                    priority,
                    pad: [0; 7],
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

pub fn parse_rate(rate_str: &str) -> Result<u64, String> {
    let s = rate_str.trim().to_lowercase();
    if let Some(num) = s.strip_suffix("gbps") {
        let n: f64 = num.trim().parse().map_err(|_| format!("Invalid rate: {}", rate_str))?;
        Ok((n * 1_000_000_000.0 / 8.0) as u64)
    } else if let Some(num) = s.strip_suffix("mbps") {
        let n: f64 = num.trim().parse().map_err(|_| format!("Invalid rate: {}", rate_str))?;
        Ok((n * 1_000_000.0 / 8.0) as u64)
    } else if let Some(num) = s.strip_suffix("kbps") {
        let n: f64 = num.trim().parse().map_err(|_| format!("Invalid rate: {}", rate_str))?;
        Ok((n * 1_000.0 / 8.0) as u64)
    } else if let Some(num) = s.strip_suffix("bps") {
        let n: f64 = num.trim().parse().map_err(|_| format!("Invalid rate: {}", rate_str))?;
        Ok((n / 8.0) as u64)
    } else {
        // Assume bytes per second
        s.parse::<u64>().map_err(|_| format!("Invalid rate: {}. Use format like 100mbps, 1gbps", rate_str))
    }
}

pub fn parse_burst(burst_str: &str) -> Result<u64, String> {
    let s = burst_str.trim().to_lowercase();
    if let Some(num) = s.strip_suffix("gb") {
        let n: f64 = num.trim().parse().map_err(|_| format!("Invalid burst: {}", burst_str))?;
        Ok((n * 1_073_741_824.0) as u64)
    } else if let Some(num) = s.strip_suffix("mb") {
        let n: f64 = num.trim().parse().map_err(|_| format!("Invalid burst: {}", burst_str))?;
        Ok((n * 1_048_576.0) as u64)
    } else if let Some(num) = s.strip_suffix("kb") {
        let n: f64 = num.trim().parse().map_err(|_| format!("Invalid burst: {}", burst_str))?;
        Ok((n * 1024.0) as u64)
    } else {
        s.parse::<u64>().map_err(|_| format!("Invalid burst: {}. Use format like 1mb, 512kb", burst_str))
    }
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
}
