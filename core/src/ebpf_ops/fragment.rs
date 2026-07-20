use crate::common::{
    FragmentConfig, FragmentContextKey4, FragmentContextKey6, FragmentContextValue,
    FragmentEpochValue, TapMapRuntime,
};
use aya::maps::{HashMap, Map, MapData, MapType};
use std::cell::RefCell;

const FRAGMENT_CONFIG_VERSION: u8 = 1;
const FRAGMENT_TIMEOUT_NS: u64 = 30_000_000_000;
const MIN_FRAGMENT_TIMEOUT_NS: u64 = 1_000_000_000;
const MAX_FRAGMENT_TIMEOUT_NS: u64 = 60_000_000_000;

fn require_fragment_map_type(
    map_data: &MapData,
    map_name: &str,
    expected: MapType,
) -> Result<(), String> {
    let actual = map_data
        .info()
        .and_then(|info| info.map_type())
        .map_err(|error| format!("inspect pinned {} type: {:?}", map_name, error))?;
    if actual != expected {
        return Err(format!(
            "pinned {} has map type {:?}; expected {:?}",
            map_name, actual, expected
        ));
    }
    Ok(())
}

fn open_fragment_epoch(
    pin_path: &str,
) -> Result<HashMap<MapData, u32, FragmentEpochValue>, String> {
    let map_path = format!("{}/FRAGMENT_EPOCH", pin_path);
    let map_data = MapData::from_pin(&map_path)
        .map_err(|error| format!("open pinned FRAGMENT_EPOCH: {:?}", error))?;
    require_fragment_map_type(&map_data, "FRAGMENT_EPOCH", MapType::Hash)?;
    HashMap::try_from(Map::HashMap(map_data))
        .map_err(|error| format!("convert FRAGMENT_EPOCH to HashMap: {:?}", error))
}

fn open_fragment_config(pin_path: &str) -> Result<HashMap<MapData, u32, FragmentConfig>, String> {
    let map_path = format!("{}/FRAGMENT_CONFIG", pin_path);
    let map_data = MapData::from_pin(&map_path)
        .map_err(|error| format!("open pinned FRAGMENT_CONFIG: {:?}", error))?;
    require_fragment_map_type(&map_data, "FRAGMENT_CONFIG", MapType::Hash)?;
    HashMap::try_from(Map::HashMap(map_data))
        .map_err(|error| format!("convert FRAGMENT_CONFIG to HashMap: {:?}", error))
}

fn open_fragment_context_v4(
    pin_path: &str,
) -> Result<HashMap<MapData, FragmentContextKey4, FragmentContextValue>, String> {
    let map_path = format!("{}/FRAG_CONTEXT_V4", pin_path);
    let map_data = MapData::from_pin(&map_path)
        .map_err(|error| format!("open pinned FRAG_CONTEXT_V4: {:?}", error))?;
    require_fragment_map_type(&map_data, "FRAG_CONTEXT_V4", MapType::LruHash)?;
    HashMap::try_from(Map::LruHashMap(map_data))
        .map_err(|error| format!("convert FRAG_CONTEXT_V4 to LruHashMap: {:?}", error))
}

fn open_fragment_context_v6(
    pin_path: &str,
) -> Result<HashMap<MapData, FragmentContextKey6, FragmentContextValue>, String> {
    let map_path = format!("{}/FRAG_CONTEXT_V6", pin_path);
    let map_data = MapData::from_pin(&map_path)
        .map_err(|error| format!("open pinned FRAG_CONTEXT_V6: {:?}", error))?;
    require_fragment_map_type(&map_data, "FRAG_CONTEXT_V6", MapType::LruHash)?;
    HashMap::try_from(Map::LruHashMap(map_data))
        .map_err(|error| format!("convert FRAG_CONTEXT_V6 to LruHashMap: {:?}", error))
}

pub(super) fn default_fragment_config() -> FragmentConfig {
    FragmentConfig {
        version: FRAGMENT_CONFIG_VERSION,
        enabled: 0,
        _pad: [0; 6],
        ipv4_timeout_ns: FRAGMENT_TIMEOUT_NS,
        ipv6_timeout_ns: FRAGMENT_TIMEOUT_NS,
    }
}

pub(super) fn validate_fragment_config(config: &FragmentConfig) -> Result<(), String> {
    if config.version != FRAGMENT_CONFIG_VERSION {
        return Err(format!(
            "FRAGMENT_CONFIG version {} is invalid; expected {}",
            config.version, FRAGMENT_CONFIG_VERSION
        ));
    }
    if config.enabled != 0 {
        return Err(format!(
            "FRAGMENT_CONFIG enabled {} is invalid for Task 4; expected disabled value 0",
            config.enabled
        ));
    }
    if config._pad != [0; 6] {
        return Err("FRAGMENT_CONFIG padding must be zero".to_string());
    }
    for (family, timeout_ns) in [
        ("IPv4", config.ipv4_timeout_ns),
        ("IPv6", config.ipv6_timeout_ns),
    ] {
        if !(MIN_FRAGMENT_TIMEOUT_NS..=MAX_FRAGMENT_TIMEOUT_NS).contains(&timeout_ns) {
            return Err(format!(
                "FRAGMENT_CONFIG {} timeout {}ns is invalid; expected {}..={}ns",
                family, timeout_ns, MIN_FRAGMENT_TIMEOUT_NS, MAX_FRAGMENT_TIMEOUT_NS
            ));
        }
    }
    Ok(())
}

fn fragment_configs_equal(left: &FragmentConfig, right: &FragmentConfig) -> bool {
    left.version == right.version
        && left.enabled == right.enabled
        && left._pad == right._pad
        && left.ipv4_timeout_ns == right.ipv4_timeout_ns
        && left.ipv6_timeout_ns == right.ipv6_timeout_ns
}

pub fn configure_fragment_tracking(pin_path: &str, config: FragmentConfig) -> Result<(), String> {
    validate_fragment_config(&config)?;
    let mut map = open_fragment_config(pin_path)?;
    map.insert(&0, &config, 0)
        .map_err(|error| format!("FRAGMENT_CONFIG insert key 0: {:?}", error))?;
    let stored = map
        .get(&0, 0)
        .map_err(|error| format!("FRAGMENT_CONFIG read-back key 0: {:?}", error))?;
    if !fragment_configs_equal(&stored, &config) {
        return Err("FRAGMENT_CONFIG read-back mismatch for key 0".to_string());
    }
    Ok(())
}

pub fn initialize_fragment_tracking_disabled(pin_path: &str) -> Result<(), String> {
    configure_fragment_tracking(pin_path, default_fragment_config())
}

pub fn validate_fragment_tracking_config_strict(pin_path: &str) -> Result<(), String> {
    let map = open_fragment_config(pin_path)?;
    let config = map
        .get(&0, 0)
        .map_err(|error| format!("read FRAGMENT_CONFIG key 0: {:?}", error))?;
    validate_fragment_config(&config)
}

pub fn read_fragment_epoch(pin_path: &str, tap_id: u32) -> Result<Option<u64>, String> {
    let map = open_fragment_epoch(pin_path)?;
    match map.get(&tap_id, 0) {
        Ok(value) => Ok(Some(value.epoch)),
        Err(aya::maps::MapError::KeyNotFound) => Ok(None),
        Err(error) => Err(format!(
            "read FRAGMENT_EPOCH for tap_id {}: {:?}",
            tap_id, error
        )),
    }
}

pub(super) fn advance_fragment_epoch_with<Read, Insert>(
    tap_id: u32,
    mut read: Read,
    mut insert: Insert,
) -> Result<u64, String>
where
    Read: FnMut() -> Result<Option<u64>, String>,
    Insert: FnMut(u64) -> Result<(), String>,
{
    let current = read()?.unwrap_or(0);
    if current == u64::MAX {
        return Err(format!(
            "FRAGMENT_EPOCH for tap_id {} is u64::MAX and cannot advance",
            tap_id
        ));
    }
    let next = current + 1;
    insert(next)?;
    let stored = read()?.ok_or_else(|| {
        format!(
            "FRAGMENT_EPOCH read-back missing for tap_id {} after writing {}",
            tap_id, next
        )
    })?;
    if stored != next {
        return Err(format!(
            "FRAGMENT_EPOCH read-back mismatch for tap_id {}: expected {}, got {}",
            tap_id, next, stored
        ));
    }
    Ok(next)
}

pub fn advance_fragment_epoch_strict(pin_path: &str, tap_id: u32) -> Result<u64, String> {
    let map = RefCell::new(open_fragment_epoch(pin_path)?);
    advance_fragment_epoch_with(
        tap_id,
        || match map.borrow().get(&tap_id, 0) {
            Ok(value) => Ok(Some(value.epoch)),
            Err(aya::maps::MapError::KeyNotFound) => Ok(None),
            Err(error) => Err(format!(
                "read FRAGMENT_EPOCH for tap_id {}: {:?}",
                tap_id, error
            )),
        },
        |epoch| {
            map.borrow_mut()
                .insert(&tap_id, &FragmentEpochValue { epoch }, 0)
                .map_err(|error| {
                    format!("insert FRAGMENT_EPOCH for tap_id {}: {:?}", tap_id, error)
                })
        },
    )
}

pub(super) fn fragment_v4_key_matches_tap(key: &FragmentContextKey4, tap_id: u32) -> bool {
    key.tap_id == tap_id
}

pub(super) fn fragment_v6_key_matches_tap(key: &FragmentContextKey6, tap_id: u32) -> bool {
    key.tap_id == tap_id
}

fn scrub_fragment_context_v4(pin_path: &str, tap_id: Option<u32>) -> Result<u64, String> {
    let mut map = open_fragment_context_v4(pin_path)?;
    let mut keys = Vec::new();
    for item in map.keys() {
        let key = item.map_err(|error| format!("iterate FRAG_CONTEXT_V4: {:?}", error))?;
        if tap_id
            .map(|expected| fragment_v4_key_matches_tap(&key, expected))
            .unwrap_or(true)
        {
            keys.push(key);
        }
    }
    let removed = keys.len() as u64;
    for key in keys {
        map.remove(&key)
            .map_err(|error| format!("remove FRAG_CONTEXT_V4 entry: {:?}", error))?;
    }
    Ok(removed)
}

fn scrub_fragment_context_v6(pin_path: &str, tap_id: Option<u32>) -> Result<u64, String> {
    let mut map = open_fragment_context_v6(pin_path)?;
    let mut keys = Vec::new();
    for item in map.keys() {
        let key = item.map_err(|error| format!("iterate FRAG_CONTEXT_V6: {:?}", error))?;
        if tap_id
            .map(|expected| fragment_v6_key_matches_tap(&key, expected))
            .unwrap_or(true)
        {
            keys.push(key);
        }
    }
    let removed = keys.len() as u64;
    for key in keys {
        map.remove(&key)
            .map_err(|error| format!("remove FRAG_CONTEXT_V6 entry: {:?}", error))?;
    }
    Ok(removed)
}

pub fn scrub_fragment_contexts_strict(runtime: TapMapRuntime<'_>) -> Result<u64, String> {
    let mut removed = scrub_fragment_context_v4(runtime.pin_path, Some(runtime.tap_id))?;
    removed += scrub_fragment_context_v6(runtime.pin_path, Some(runtime.tap_id))?;

    let mut epoch_map = open_fragment_epoch(runtime.pin_path)?;
    match epoch_map.remove(&runtime.tap_id) {
        Ok(()) => removed += 1,
        Err(aya::maps::MapError::KeyNotFound) => {}
        Err(error) => {
            return Err(format!(
                "remove FRAGMENT_EPOCH for tap_id {}: {:?}",
                runtime.tap_id, error
            ));
        }
    }
    Ok(removed)
}

pub fn clear_fragment_contexts_strict(pin_path: &str) -> Result<u64, String> {
    let mut removed = scrub_fragment_context_v4(pin_path, None)?;
    removed += scrub_fragment_context_v6(pin_path, None)?;
    Ok(removed)
}

pub fn recover_fragment_runtime_strict(pin_path: &str) -> Result<u64, String> {
    initialize_fragment_tracking_disabled(pin_path)?;
    let removed = clear_fragment_contexts_strict(pin_path)?;
    Ok(removed)
}
