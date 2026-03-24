use aya::maps::{HashMap, MapData};
use crate::common::{MirrorKey, GlobalMirrorKey, MirrorConfig, FirewallConfig, TapMapRuntime};

/// Resolve interface name to ifindex.
pub fn resolve_ifindex(iface: &str) -> Result<u32, String> {
    let path = format!("/sys/class/net/{}/ifindex", iface);
    let contents = std::fs::read_to_string(&path)
        .map_err(|e| format!("Interface '{}' not found: {}", iface, e))?;
    contents.trim().parse::<u32>()
        .map_err(|e| format!("Invalid ifindex for '{}': {}", iface, e))
}

/// Update the mirror_enabled flag in FIREWALL_CONFIG map.
fn sync_mirror_enabled(runtime: TapMapRuntime<'_>, enabled: bool) -> Result<(), String> {
    let pin_path = runtime.pin_path;
    let map_path = format!("{}/FIREWALL_CONFIG", pin_path);
    let map_data = MapData::from_pin(&map_path)
        .map_err(|e| format!("open FIREWALL_CONFIG: {:?}", e))?;
    let mut map = HashMap::<_, u32, FirewallConfig>::try_from(
        aya::maps::Map::HashMap(map_data)
    ).map_err(|e| format!("convert FIREWALL_CONFIG: {:?}", e))?;

    let mut cfg = map.get(&0u32, 0).unwrap_or(FirewallConfig {
        conntrack_enabled: 1,
        monitoring_enabled: 1,
        num_cpus: {
            let raw = unsafe { libc::sysconf(libc::_SC_NPROCESSORS_ONLN) };
            if raw > 0 { raw as u16 } else { 1 }
        },
        qos_enabled: 0,
        acl_enabled: 1,
        mirror_enabled: 0,
        tcprt_enabled: 1,
        ssl_enabled: 0,
    });
    cfg.mirror_enabled = if enabled { 1 } else { 0 };
    map.insert(&0u32, &cfg, 0)
        .map_err(|e| format!("FIREWALL_CONFIG update mirror_enabled: {:?}", e))?;
    Ok(())
}

/// Check if any mirror rules remain in MIRROR_POLICY or MIRROR_GLOBAL maps.
fn has_mirror_rules(runtime: TapMapRuntime<'_>) -> bool {
    let pin_path = runtime.pin_path;
    let policy_path = format!("{}/MIRROR_POLICY", pin_path);
    if let Ok(map_data) = MapData::from_pin(&policy_path) {
        if let Ok(map) = HashMap::<_, MirrorKey, MirrorConfig>::try_from(
            aya::maps::Map::HashMap(map_data)
        ) {
            if map.iter().next().is_some() {
                return true;
            }
        }
    }

    let global_path = format!("{}/MIRROR_GLOBAL", pin_path);
    if let Ok(map_data) = MapData::from_pin(&global_path) {
        if let Ok(map) = HashMap::<_, GlobalMirrorKey, MirrorConfig>::try_from(
            aya::maps::Map::HashMap(map_data)
        ) {
            if map.iter().next().is_some() {
                return true;
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
    let map_data = MapData::from_pin(&map_path)
        .map_err(|e| format!("open MIRROR_POLICY: {:?}", e))?;
    let mut map = HashMap::<_, MirrorKey, MirrorConfig>::try_from(
        aya::maps::Map::HashMap(map_data)
    ).map_err(|e| format!("convert MIRROR_POLICY: {:?}", e))?;

    let key = MirrorKey {
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
    let map_data = MapData::from_pin(&map_path)
        .map_err(|e| format!("open MIRROR_POLICY: {:?}", e))?;
    let mut map = HashMap::<_, MirrorKey, MirrorConfig>::try_from(
        aya::maps::Map::HashMap(map_data)
    ).map_err(|e| format!("convert MIRROR_POLICY: {:?}", e))?;

    let key = MirrorKey {
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

pub fn add_global_mirror(
    direction: u8,
    target_ifindex: u32,
    runtime: TapMapRuntime<'_>,
    user_mirror_enabled: bool,
) -> Result<(), String> {
    let pin_path = runtime.pin_path;
    let map_path = format!("{}/MIRROR_GLOBAL", pin_path);
    let map_data = MapData::from_pin(&map_path)
        .map_err(|e| format!("open MIRROR_GLOBAL: {:?}", e))?;
    let mut map = HashMap::<_, GlobalMirrorKey, MirrorConfig>::try_from(
        aya::maps::Map::HashMap(map_data)
    ).map_err(|e| format!("convert MIRROR_GLOBAL: {:?}", e))?;

    let key = GlobalMirrorKey {
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
    let map_data = MapData::from_pin(&map_path)
        .map_err(|e| format!("open MIRROR_GLOBAL: {:?}", e))?;
    let mut map = HashMap::<_, GlobalMirrorKey, MirrorConfig>::try_from(
        aya::maps::Map::HashMap(map_data)
    ).map_err(|e| format!("convert MIRROR_GLOBAL: {:?}", e))?;

    let key = GlobalMirrorKey {
        direction,
        pad: [0; 3],
    };

    map.remove(&key)
        .map_err(|e| format!("MIRROR_GLOBAL remove: {:?}", e))?;

    sync_mirror_enabled(runtime, user_mirror_enabled && has_mirror_rules(runtime))?;
    Ok(())
}

pub fn list_mirror_rules(runtime: TapMapRuntime<'_>) -> Result<Vec<(MirrorKey, MirrorConfig)>, String> {
    let pin_path = runtime.pin_path;
    let map_path = format!("{}/MIRROR_POLICY", pin_path);
    let map_data = MapData::from_pin(&map_path)
        .map_err(|e| format!("open MIRROR_POLICY: {:?}", e))?;
    let map = HashMap::<_, MirrorKey, MirrorConfig>::try_from(
        aya::maps::Map::HashMap(map_data)
    ).map_err(|e| format!("convert MIRROR_POLICY: {:?}", e))?;

    let mut entries = Vec::new();
    for item in map.iter() {
        if let Ok((key, val)) = item {
            entries.push((key, val));
        }
    }
    Ok(entries)
}

pub fn list_global_mirrors(runtime: TapMapRuntime<'_>) -> Result<Vec<(GlobalMirrorKey, MirrorConfig)>, String> {
    let pin_path = runtime.pin_path;
    let map_path = format!("{}/MIRROR_GLOBAL", pin_path);
    let map_data = MapData::from_pin(&map_path)
        .map_err(|e| format!("open MIRROR_GLOBAL: {:?}", e))?;
    let map = HashMap::<_, GlobalMirrorKey, MirrorConfig>::try_from(
        aya::maps::Map::HashMap(map_data)
    ).map_err(|e| format!("convert MIRROR_GLOBAL: {:?}", e))?;

    let mut entries = Vec::new();
    for item in map.iter() {
        if let Ok((key, val)) = item {
            entries.push((key, val));
        }
    }
    Ok(entries)
}

/// Replay mirror rules from state into a freshly loaded eBPF object.
pub fn replay_mirror_rules(
    bpf: &mut aya::Ebpf,
    rules: &[(u32, u32, u8, u8, u32)],  // (src_id, dst_id, proto, direction, target_ifindex)
    global_rules: &[(u8, u32)],          // (direction, target_ifindex)
) -> Vec<String> {
    let mut errors = Vec::new();

    // Replay per-rule mirrors
    match bpf.map_mut("MIRROR_POLICY")
        .ok_or_else(|| "MIRROR_POLICY not found".to_string())
        .and_then(|m| HashMap::<_, MirrorKey, MirrorConfig>::try_from(m).map_err(|e| format!("{:?}", e)))
    {
        Ok(mut map) => {
            for &(src_id, dst_id, proto, direction, target_ifindex) in rules {
                let key = MirrorKey { src_id, dst_id, proto, direction, pad: [0; 2] };
                let config = MirrorConfig { target_ifindex };
                if let Err(e) = map.insert(&key, &config, 0) {
                    errors.push(format!("MIRROR_POLICY src={} dst={} dir={}: {:?}", src_id, dst_id, direction, e));
                }
            }
        }
        Err(e) => errors.push(format!("MIRROR_POLICY: {}", e)),
    }

    // Replay global mirrors
    match bpf.map_mut("MIRROR_GLOBAL")
        .ok_or_else(|| "MIRROR_GLOBAL not found".to_string())
        .and_then(|m| HashMap::<_, GlobalMirrorKey, MirrorConfig>::try_from(m).map_err(|e| format!("{:?}", e)))
    {
        Ok(mut map) => {
            for &(direction, target_ifindex) in global_rules {
                let key = GlobalMirrorKey { direction, pad: [0; 3] };
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
