use crate::common::{GlobalMirrorKey, MirrorConfig, MirrorKey, MirrorStatsValue, TapMapRuntime};
use aya::maps::{HashMap, MapData, PerCpuHashMap};

/// Resolve interface name to ifindex.
pub fn resolve_ifindex(iface: &str) -> Result<u32, String> {
    let path = format!("/sys/class/net/{}/ifindex", iface);
    let contents = std::fs::read_to_string(&path)
        .map_err(|e| format!("Interface '{}' not found: {}", iface, e))?;
    contents
        .trim()
        .parse::<u32>()
        .map_err(|e| format!("Invalid ifindex for '{}': {}", iface, e))
}

fn ignore_missing_remove<E: std::fmt::Debug>(
    result: Result<(), E>,
    map_name: &str,
) -> Result<(), String> {
    match result {
        Ok(()) => Ok(()),
        Err(e) => {
            let err = format!("{:?}", e);
            if err.contains("KeyNotFound") || err.contains("No such file or directory") {
                Ok(())
            } else {
                Err(format!("{} remove: {}", map_name, err))
            }
        }
    }
}

/// Update the mirror_enabled flag in FIREWALL_CONFIG map.
fn sync_mirror_enabled(runtime: TapMapRuntime<'_>, enabled: bool) -> Result<(), String> {
    crate::ebpf_ops::update_runtime_config(
        runtime,
        None,
        None,
        None,
        None,
        Some(enabled),
        None,
        None,
    )
}

/// Check if any mirror rules remain in MIRROR_POLICY or MIRROR_GLOBAL maps.
fn has_mirror_rules(runtime: TapMapRuntime<'_>) -> bool {
    let pin_path = runtime.pin_path;
    let policy_path = format!("{}/MIRROR_POLICY", pin_path);
    if let Ok(map_data) = MapData::from_pin(&policy_path) {
        if let Ok(map) =
            HashMap::<_, MirrorKey, MirrorConfig>::try_from(aya::maps::Map::HashMap(map_data))
        {
            for item in map.iter() {
                if let Ok((key, _)) = item {
                    if key.tap_id == runtime.tap_id {
                        return true;
                    }
                }
            }
        }
    }

    let global_path = format!("{}/MIRROR_GLOBAL", pin_path);
    if let Ok(map_data) = MapData::from_pin(&global_path) {
        if let Ok(map) =
            HashMap::<_, GlobalMirrorKey, MirrorConfig>::try_from(aya::maps::Map::HashMap(map_data))
        {
            for item in map.iter() {
                if let Ok((key, _)) = item {
                    if key.tap_id == runtime.tap_id {
                        return true;
                    }
                }
            }
        }
    }

    false
}

pub fn add_mirror_rule(
    src_id: u32,
    dst_id: u32,
    proto: u8,
    direction: u8,
    target_ifindex: u32,
    runtime: TapMapRuntime<'_>,
    user_mirror_enabled: bool,
) -> Result<(), String> {
    let pin_path = runtime.pin_path;
    let map_path = format!("{}/MIRROR_POLICY", pin_path);
    let map_data =
        MapData::from_pin(&map_path).map_err(|e| format!("open MIRROR_POLICY: {:?}", e))?;
    let mut map =
        HashMap::<_, MirrorKey, MirrorConfig>::try_from(aya::maps::Map::HashMap(map_data))
            .map_err(|e| format!("convert MIRROR_POLICY: {:?}", e))?;

    let key = MirrorKey {
        tap_id: runtime.tap_id,
        src_id,
        dst_id,
        proto,
        direction,
        pad: [0; 2],
    };
    let config = MirrorConfig { target_ifindex };

    map.insert(&key, &config, 0)
        .map_err(|e| format!("MIRROR_POLICY insert: {:?}", e))?;

    sync_mirror_enabled(runtime, user_mirror_enabled)?;
    Ok(())
}

pub fn delete_mirror_rule(
    src_id: u32,
    dst_id: u32,
    proto: u8,
    direction: u8,
    runtime: TapMapRuntime<'_>,
    user_mirror_enabled: bool,
) -> Result<(), String> {
    let pin_path = runtime.pin_path;
    let map_path = format!("{}/MIRROR_POLICY", pin_path);
    let map_data =
        MapData::from_pin(&map_path).map_err(|e| format!("open MIRROR_POLICY: {:?}", e))?;
    let mut map =
        HashMap::<_, MirrorKey, MirrorConfig>::try_from(aya::maps::Map::HashMap(map_data))
            .map_err(|e| format!("convert MIRROR_POLICY: {:?}", e))?;

    let key = MirrorKey {
        tap_id: runtime.tap_id,
        src_id,
        dst_id,
        proto,
        direction,
        pad: [0; 2],
    };

    map.remove(&key)
        .map_err(|e| format!("MIRROR_POLICY remove: {:?}", e))?;

    sync_mirror_enabled(runtime, user_mirror_enabled && has_mirror_rules(runtime))?;
    Ok(())
}

pub fn clear_mirror_rule_stats(
    src_id: u32,
    dst_id: u32,
    proto: u8,
    direction: u8,
    runtime: TapMapRuntime<'_>,
) -> Result<(), String> {
    let map_path = format!("{}/MIRROR_STATS", runtime.pin_path);
    let map_data =
        MapData::from_pin(&map_path).map_err(|e| format!("open MIRROR_STATS: {:?}", e))?;
    let mut map = PerCpuHashMap::<_, MirrorKey, MirrorStatsValue>::try_from(
        aya::maps::Map::PerCpuHashMap(map_data),
    )
    .map_err(|e| format!("convert MIRROR_STATS: {:?}", e))?;

    let key = MirrorKey {
        tap_id: runtime.tap_id,
        src_id,
        dst_id,
        proto,
        direction,
        pad: [0; 2],
    };

    ignore_missing_remove(map.remove(&key), "MIRROR_STATS")
}

pub fn add_global_mirror(
    direction: u8,
    target_ifindex: u32,
    runtime: TapMapRuntime<'_>,
    user_mirror_enabled: bool,
) -> Result<(), String> {
    let pin_path = runtime.pin_path;
    let map_path = format!("{}/MIRROR_GLOBAL", pin_path);
    let map_data =
        MapData::from_pin(&map_path).map_err(|e| format!("open MIRROR_GLOBAL: {:?}", e))?;
    let mut map =
        HashMap::<_, GlobalMirrorKey, MirrorConfig>::try_from(aya::maps::Map::HashMap(map_data))
            .map_err(|e| format!("convert MIRROR_GLOBAL: {:?}", e))?;

    let key = GlobalMirrorKey {
        tap_id: runtime.tap_id,
        direction,
        pad: [0; 3],
    };
    let config = MirrorConfig { target_ifindex };

    map.insert(&key, &config, 0)
        .map_err(|e| format!("MIRROR_GLOBAL insert: {:?}", e))?;

    sync_mirror_enabled(runtime, user_mirror_enabled)?;
    Ok(())
}

pub fn delete_global_mirror(
    direction: u8,
    runtime: TapMapRuntime<'_>,
    user_mirror_enabled: bool,
) -> Result<(), String> {
    let pin_path = runtime.pin_path;
    let map_path = format!("{}/MIRROR_GLOBAL", pin_path);
    let map_data =
        MapData::from_pin(&map_path).map_err(|e| format!("open MIRROR_GLOBAL: {:?}", e))?;
    let mut map =
        HashMap::<_, GlobalMirrorKey, MirrorConfig>::try_from(aya::maps::Map::HashMap(map_data))
            .map_err(|e| format!("convert MIRROR_GLOBAL: {:?}", e))?;

    let key = GlobalMirrorKey {
        tap_id: runtime.tap_id,
        direction,
        pad: [0; 3],
    };

    map.remove(&key)
        .map_err(|e| format!("MIRROR_GLOBAL remove: {:?}", e))?;

    sync_mirror_enabled(runtime, user_mirror_enabled && has_mirror_rules(runtime))?;
    Ok(())
}

pub fn clear_global_mirror_stats(direction: u8, runtime: TapMapRuntime<'_>) -> Result<(), String> {
    let map_path = format!("{}/MIRROR_GLOBAL_STATS", runtime.pin_path);
    let map_data =
        MapData::from_pin(&map_path).map_err(|e| format!("open MIRROR_GLOBAL_STATS: {:?}", e))?;
    let mut map = PerCpuHashMap::<_, GlobalMirrorKey, MirrorStatsValue>::try_from(
        aya::maps::Map::PerCpuHashMap(map_data),
    )
    .map_err(|e| format!("convert MIRROR_GLOBAL_STATS: {:?}", e))?;

    let key = GlobalMirrorKey {
        tap_id: runtime.tap_id,
        direction,
        pad: [0; 3],
    };

    ignore_missing_remove(map.remove(&key), "MIRROR_GLOBAL_STATS")
}

pub fn list_mirror_rules(
    runtime: TapMapRuntime<'_>,
) -> Result<Vec<(MirrorKey, MirrorConfig)>, String> {
    let pin_path = runtime.pin_path;
    let map_path = format!("{}/MIRROR_POLICY", pin_path);
    let map_data =
        MapData::from_pin(&map_path).map_err(|e| format!("open MIRROR_POLICY: {:?}", e))?;
    let map = HashMap::<_, MirrorKey, MirrorConfig>::try_from(aya::maps::Map::HashMap(map_data))
        .map_err(|e| format!("convert MIRROR_POLICY: {:?}", e))?;

    let mut entries = Vec::new();
    for item in map.iter() {
        if let Ok((key, val)) = item {
            if key.tap_id == runtime.tap_id {
                entries.push((key, val));
            }
        }
    }
    Ok(entries)
}

pub fn list_global_mirrors(
    runtime: TapMapRuntime<'_>,
) -> Result<Vec<(GlobalMirrorKey, MirrorConfig)>, String> {
    let pin_path = runtime.pin_path;
    let map_path = format!("{}/MIRROR_GLOBAL", pin_path);
    let map_data =
        MapData::from_pin(&map_path).map_err(|e| format!("open MIRROR_GLOBAL: {:?}", e))?;
    let map =
        HashMap::<_, GlobalMirrorKey, MirrorConfig>::try_from(aya::maps::Map::HashMap(map_data))
            .map_err(|e| format!("convert MIRROR_GLOBAL: {:?}", e))?;

    let mut entries = Vec::new();
    for item in map.iter() {
        if let Ok((key, val)) = item {
            if key.tap_id == runtime.tap_id {
                entries.push((key, val));
            }
        }
    }
    Ok(entries)
}

/// Replay mirror rules from state into a freshly loaded eBPF object.
pub fn replay_mirror_rules(
    bpf: &mut aya::Ebpf,
    tap_id: u32,
    rules: &[(u32, u32, u8, u8, u32)], // (src_id, dst_id, proto, direction, target_ifindex)
    global_rules: &[(u8, u32)],        // (direction, target_ifindex)
) -> Vec<String> {
    let mut errors = Vec::new();

    // Replay per-rule mirrors
    match bpf
        .map_mut("MIRROR_POLICY")
        .ok_or_else(|| "MIRROR_POLICY not found".to_string())
        .and_then(|m| {
            HashMap::<_, MirrorKey, MirrorConfig>::try_from(m).map_err(|e| format!("{:?}", e))
        }) {
        Ok(mut map) => {
            for &(src_id, dst_id, proto, direction, target_ifindex) in rules {
                let key = MirrorKey {
                    tap_id,
                    src_id,
                    dst_id,
                    proto,
                    direction,
                    pad: [0; 2],
                };
                let config = MirrorConfig { target_ifindex };
                if let Err(e) = map.insert(&key, &config, 0) {
                    errors.push(format!(
                        "MIRROR_POLICY src={} dst={} dir={}: {:?}",
                        src_id, dst_id, direction, e
                    ));
                }
            }
        }
        Err(e) => errors.push(format!("MIRROR_POLICY: {}", e)),
    }

    // Replay global mirrors
    match bpf
        .map_mut("MIRROR_GLOBAL")
        .ok_or_else(|| "MIRROR_GLOBAL not found".to_string())
        .and_then(|m| {
            HashMap::<_, GlobalMirrorKey, MirrorConfig>::try_from(m).map_err(|e| format!("{:?}", e))
        }) {
        Ok(mut map) => {
            for &(direction, target_ifindex) in global_rules {
                let key = GlobalMirrorKey {
                    tap_id,
                    direction,
                    pad: [0; 3],
                };
                let config = MirrorConfig { target_ifindex };
                if let Err(e) = map.insert(&key, &config, 0) {
                    errors.push(format!("MIRROR_GLOBAL dir={}: {:?}", direction, e));
                }
            }
        }
        Err(e) => errors.push(format!("MIRROR_GLOBAL: {}", e)),
    }

    errors
}
