use crate::common::{
    FragmentConfig, FragmentContextKey4, FragmentContextKey6, FragmentContextValue,
    FragmentEpochValue, TapMapRuntime, FRAGMENT_CONFIG_DISABLED, FRAGMENT_CONFIG_ENABLED,
    FRAGMENT_CONFIG_MAX_TIMEOUT_NS, FRAGMENT_CONFIG_MIN_TIMEOUT_NS, FRAGMENT_CONFIG_VERSION,
    FRAGMENT_RUNTIME_MODE_MANAGED, FRAGMENT_RUNTIME_MODE_STANDALONE,
};
use aya::maps::{HashMap, Map, MapData, MapType, PerCpuArray};
use std::cell::RefCell;

const FRAGMENT_TIMEOUT_NS: u64 = 30_000_000_000;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(super) enum FragmentRemoveOutcome {
    Removed,
    Missing,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(super) enum FragmentRuntimeMapKind {
    ContextV4Lru,
    ContextV6Lru,
    EpochHash,
    ConfigHash,
    MetricsPerCpuArrayU64,
}

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

fn open_fragment_metrics(pin_path: &str) -> Result<PerCpuArray<MapData, u64>, String> {
    let map_path = format!("{}/FRAGMENT_METRICS", pin_path);
    let map_data = MapData::from_pin(&map_path)
        .map_err(|error| format!("open pinned FRAGMENT_METRICS: {:?}", error))?;
    require_fragment_map_type(&map_data, "FRAGMENT_METRICS", MapType::PerCpuArray)?;
    PerCpuArray::try_from(Map::PerCpuArray(map_data))
        .map_err(|error| format!("convert FRAGMENT_METRICS to PerCpuArray<u64>: {:?}", error))
}

fn fragment_runtime_mode_is_valid(runtime_mode: u8) -> bool {
    runtime_mode == FRAGMENT_RUNTIME_MODE_MANAGED
        || runtime_mode == FRAGMENT_RUNTIME_MODE_STANDALONE
}

pub(super) fn default_fragment_config(runtime_mode: u8) -> Result<FragmentConfig, String> {
    if !fragment_runtime_mode_is_valid(runtime_mode) {
        return Err(format!(
            "FRAGMENT_CONFIG runtime mode {} is invalid",
            runtime_mode
        ));
    }
    Ok(FragmentConfig {
        version: FRAGMENT_CONFIG_VERSION,
        enabled: FRAGMENT_CONFIG_DISABLED,
        runtime_mode,
        _pad: [0; 5],
        ipv4_timeout_ns: FRAGMENT_TIMEOUT_NS,
        ipv6_timeout_ns: FRAGMENT_TIMEOUT_NS,
    })
}

pub(super) fn validate_fragment_config(
    config: &FragmentConfig,
    expected_runtime_mode: u8,
) -> Result<(), String> {
    if !fragment_runtime_mode_is_valid(expected_runtime_mode) {
        return Err(format!(
            "expected FRAGMENT_CONFIG runtime mode {} is invalid",
            expected_runtime_mode
        ));
    }
    if config.version != FRAGMENT_CONFIG_VERSION {
        return Err(format!(
            "FRAGMENT_CONFIG version {} is invalid; expected {}",
            config.version, FRAGMENT_CONFIG_VERSION
        ));
    }
    if config.enabled != FRAGMENT_CONFIG_DISABLED && config.enabled != FRAGMENT_CONFIG_ENABLED {
        return Err(format!(
            "FRAGMENT_CONFIG enabled {} is invalid; expected 0 or 1",
            config.enabled
        ));
    }
    if !fragment_runtime_mode_is_valid(config.runtime_mode) {
        return Err(format!(
            "FRAGMENT_CONFIG runtime mode {} is invalid",
            config.runtime_mode
        ));
    }
    if config.runtime_mode != expected_runtime_mode {
        return Err(format!(
            "FRAGMENT_CONFIG runtime mode {} does not match expected {}",
            config.runtime_mode, expected_runtime_mode
        ));
    }
    if config._pad != [0; 5] {
        return Err("FRAGMENT_CONFIG padding must be zero".to_string());
    }
    for (family, timeout_ns) in [
        ("IPv4", config.ipv4_timeout_ns),
        ("IPv6", config.ipv6_timeout_ns),
    ] {
        if !(FRAGMENT_CONFIG_MIN_TIMEOUT_NS..=FRAGMENT_CONFIG_MAX_TIMEOUT_NS).contains(&timeout_ns)
        {
            return Err(format!(
                "FRAGMENT_CONFIG {} timeout {}ns is invalid; expected {}..={}ns",
                family, timeout_ns, FRAGMENT_CONFIG_MIN_TIMEOUT_NS, FRAGMENT_CONFIG_MAX_TIMEOUT_NS
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
pub(super) fn validate_fragment_config_disabled(
    config: &FragmentConfig,
    expected_runtime_mode: u8,
) -> Result<(), String> {
    validate_fragment_config(config, expected_runtime_mode)?;
    if config.enabled != FRAGMENT_CONFIG_DISABLED {
        return Err(format!(
            "FRAGMENT_CONFIG enabled {} is not ready for Task 4; expected disabled value {}",
            config.enabled, FRAGMENT_CONFIG_DISABLED
        ));
    }
    Ok(())
}

fn fragment_configs_equal(left: &FragmentConfig, right: &FragmentConfig) -> bool {
    left.version == right.version
        && left.enabled == right.enabled
        && left.runtime_mode == right.runtime_mode
        && left._pad == right._pad
        && left.ipv4_timeout_ns == right.ipv4_timeout_ns
        && left.ipv6_timeout_ns == right.ipv6_timeout_ns
}

pub fn validate_fragment_runtime_expectation(
    actual_config: &FragmentConfig,
    expected_config: &FragmentConfig,
    actual_v4_max_entries: u32,
    actual_v6_max_entries: u32,
    expected_max_entries: u32,
) -> Result<(), String> {
    if !fragment_configs_equal(actual_config, expected_config) {
        return Err("fragment runtime config does not match the configured contract".to_string());
    }
    if actual_v4_max_entries != expected_max_entries {
        return Err(format!(
            "FRAG_CONTEXT_V4 capacity {} does not match configured {}",
            actual_v4_max_entries, expected_max_entries
        ));
    }
    if actual_v6_max_entries != expected_max_entries {
        return Err(format!(
            "FRAG_CONTEXT_V6 capacity {} does not match configured {}",
            actual_v6_max_entries, expected_max_entries
        ));
    }
    Ok(())
}

fn fragment_context_capacity(pin_path: &str, map_name: &str) -> Result<u32, String> {
    let map_path = format!("{}/{}", pin_path, map_name);
    let map_data = MapData::from_pin(&map_path)
        .map_err(|error| format!("open pinned {}: {:?}", map_name, error))?;
    require_fragment_map_type(&map_data, map_name, MapType::LruHash)?;
    map_data
        .info()
        .map(|info| info.max_entries())
        .map_err(|error| format!("inspect pinned {} capacity: {:?}", map_name, error))
}

pub fn configure_fragment_tracking(
    pin_path: &str,
    expected_runtime_mode: u8,
    config: FragmentConfig,
) -> Result<(), String> {
    validate_fragment_config(&config, expected_runtime_mode)?;
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

pub fn initialize_fragment_tracking_disabled(
    pin_path: &str,
    runtime_mode: u8,
) -> Result<(), String> {
    configure_fragment_tracking(
        pin_path,
        runtime_mode,
        default_fragment_config(runtime_mode)?,
    )
}

pub fn validate_fragment_tracking_config_strict(
    pin_path: &str,
    expected_runtime_mode: u8,
) -> Result<(), String> {
    let map = open_fragment_config(pin_path)?;
    let config = map
        .get(&0, 0)
        .map_err(|error| format!("read FRAGMENT_CONFIG key 0: {:?}", error))?;
    validate_fragment_config(&config, expected_runtime_mode)
}

pub fn validate_fragment_runtime_configured_strict(
    pin_path: &str,
    expected_config: &FragmentConfig,
    expected_max_entries: u32,
) -> Result<(), String> {
    validate_fragment_config(expected_config, expected_config.runtime_mode)?;
    let config_map = open_fragment_config(pin_path)?;
    let actual_config = config_map
        .get(&0, 0)
        .map_err(|error| format!("read FRAGMENT_CONFIG key 0: {:?}", error))?;
    validate_fragment_runtime_expectation(
        &actual_config,
        expected_config,
        fragment_context_capacity(pin_path, "FRAG_CONTEXT_V4")?,
        fragment_context_capacity(pin_path, "FRAG_CONTEXT_V6")?,
        expected_max_entries,
    )
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

pub(super) fn fragment_sweep_with<K, List, Matches, Remove, Verify>(
    map_name: &str,
    list: List,
    matches: Matches,
    mut remove: Remove,
    verify_empty: Verify,
) -> Result<u64, String>
where
    List: FnOnce() -> Result<Vec<K>, String>,
    Matches: Fn(&K) -> bool,
    Remove: FnMut(&K) -> Result<FragmentRemoveOutcome, String>,
    Verify: FnOnce() -> Result<bool, String>,
{
    let keys = list()?;
    let mut removed = 0;
    for key in keys.iter().filter(|key| matches(key)) {
        match remove(key).map_err(|error| format!("{} removal failed: {}", map_name, error))? {
            FragmentRemoveOutcome::Removed => removed += 1,
            FragmentRemoveOutcome::Missing => {}
        }
    }
    if !verify_empty()? {
        return Err(format!(
            "{} still contains entries in the requested fragment scope after sweep",
            map_name
        ));
    }
    Ok(removed)
}

pub(super) fn scrub_fragment_families_with<V4, V6, Epoch>(
    scrub_v4: V4,
    scrub_v6: V6,
    remove_epoch: Epoch,
) -> Result<u64, String>
where
    V4: FnOnce() -> Result<u64, String>,
    V6: FnOnce() -> Result<u64, String>,
    Epoch: FnOnce() -> Result<FragmentRemoveOutcome, String>,
{
    let mut removed = scrub_v4()?;
    removed += scrub_v6()?;
    if remove_epoch()? == FragmentRemoveOutcome::Removed {
        removed += 1;
    }
    Ok(removed)
}

pub(super) fn recover_fragment_runtime_with<Validate, Configure, Scrub>(
    validate_maps: Validate,
    configure: Configure,
    scrub: Scrub,
) -> Result<u64, String>
where
    Validate: FnOnce() -> Result<(), String>,
    Configure: FnOnce() -> Result<(), String>,
    Scrub: FnOnce() -> Result<u64, String>,
{
    validate_maps()?;
    configure()?;
    scrub()
}

pub(super) fn validate_fragment_runtime_maps_with<Validate>(
    mut validate: Validate,
) -> Result<(), String>
where
    Validate: FnMut(&'static str, FragmentRuntimeMapKind) -> Result<(), String>,
{
    for (name, kind) in [
        ("FRAG_CONTEXT_V4", FragmentRuntimeMapKind::ContextV4Lru),
        ("FRAG_CONTEXT_V6", FragmentRuntimeMapKind::ContextV6Lru),
        ("FRAGMENT_EPOCH", FragmentRuntimeMapKind::EpochHash),
        ("FRAGMENT_CONFIG", FragmentRuntimeMapKind::ConfigHash),
        (
            "FRAGMENT_METRICS",
            FragmentRuntimeMapKind::MetricsPerCpuArrayU64,
        ),
    ] {
        validate(name, kind)?;
    }
    Ok(())
}

pub fn validate_fragment_runtime_maps_strict(pin_path: &str) -> Result<(), String> {
    validate_fragment_runtime_maps_with(|_name, kind| {
        match kind {
            FragmentRuntimeMapKind::ContextV4Lru => drop(open_fragment_context_v4(pin_path)?),
            FragmentRuntimeMapKind::ContextV6Lru => drop(open_fragment_context_v6(pin_path)?),
            FragmentRuntimeMapKind::EpochHash => drop(open_fragment_epoch(pin_path)?),
            FragmentRuntimeMapKind::ConfigHash => drop(open_fragment_config(pin_path)?),
            FragmentRuntimeMapKind::MetricsPerCpuArrayU64 => drop(open_fragment_metrics(pin_path)?),
        }
        Ok(())
    })
}

fn scrub_fragment_context_v4(pin_path: &str, tap_id: Option<u32>) -> Result<u64, String> {
    let map = RefCell::new(open_fragment_context_v4(pin_path)?);
    fragment_sweep_with(
        "FRAG_CONTEXT_V4",
        || {
            map.borrow()
                .keys()
                .collect::<Result<Vec<_>, _>>()
                .map_err(|error| format!("iterate FRAG_CONTEXT_V4: {:?}", error))
        },
        |key| {
            tap_id
                .map(|expected| fragment_v4_key_matches_tap(key, expected))
                .unwrap_or(true)
        },
        |key| match map.borrow_mut().remove(key) {
            Ok(()) => Ok(FragmentRemoveOutcome::Removed),
            Err(aya::maps::MapError::KeyNotFound) => Ok(FragmentRemoveOutcome::Missing),
            Err(error) => Err(format!("remove entry: {:?}", error)),
        },
        || {
            for item in map.borrow().keys() {
                let key = item.map_err(|error| format!("verify FRAG_CONTEXT_V4: {:?}", error))?;
                if tap_id
                    .map(|expected| fragment_v4_key_matches_tap(&key, expected))
                    .unwrap_or(true)
                {
                    return Ok(false);
                }
            }
            Ok(true)
        },
    )
}

fn scrub_fragment_context_v6(pin_path: &str, tap_id: Option<u32>) -> Result<u64, String> {
    let map = RefCell::new(open_fragment_context_v6(pin_path)?);
    fragment_sweep_with(
        "FRAG_CONTEXT_V6",
        || {
            map.borrow()
                .keys()
                .collect::<Result<Vec<_>, _>>()
                .map_err(|error| format!("iterate FRAG_CONTEXT_V6: {:?}", error))
        },
        |key| {
            tap_id
                .map(|expected| fragment_v6_key_matches_tap(key, expected))
                .unwrap_or(true)
        },
        |key| match map.borrow_mut().remove(key) {
            Ok(()) => Ok(FragmentRemoveOutcome::Removed),
            Err(aya::maps::MapError::KeyNotFound) => Ok(FragmentRemoveOutcome::Missing),
            Err(error) => Err(format!("remove entry: {:?}", error)),
        },
        || {
            for item in map.borrow().keys() {
                let key = item.map_err(|error| format!("verify FRAG_CONTEXT_V6: {:?}", error))?;
                if tap_id
                    .map(|expected| fragment_v6_key_matches_tap(&key, expected))
                    .unwrap_or(true)
                {
                    return Ok(false);
                }
            }
            Ok(true)
        },
    )
}

pub fn scrub_fragment_contexts_strict(runtime: TapMapRuntime<'_>) -> Result<u64, String> {
    scrub_fragment_families_with(
        || scrub_fragment_context_v4(runtime.pin_path, Some(runtime.tap_id)),
        || scrub_fragment_context_v6(runtime.pin_path, Some(runtime.tap_id)),
        || {
            let mut epoch_map = open_fragment_epoch(runtime.pin_path)?;
            match epoch_map.remove(&runtime.tap_id) {
                Ok(()) => Ok(FragmentRemoveOutcome::Removed),
                Err(aya::maps::MapError::KeyNotFound) => Ok(FragmentRemoveOutcome::Missing),
                Err(error) => Err(format!(
                    "remove FRAGMENT_EPOCH for tap_id {}: {:?}",
                    runtime.tap_id, error
                )),
            }
        },
    )
}

pub fn clear_fragment_contexts_strict(pin_path: &str) -> Result<u64, String> {
    let mut removed = scrub_fragment_context_v4(pin_path, None)?;
    removed += scrub_fragment_context_v6(pin_path, None)?;
    Ok(removed)
}

pub fn recover_fragment_runtime_strict(pin_path: &str, runtime_mode: u8) -> Result<u64, String> {
    recover_fragment_runtime_with(
        || validate_fragment_runtime_maps_strict(pin_path),
        || initialize_fragment_tracking_disabled(pin_path, runtime_mode),
        || clear_fragment_contexts_strict(pin_path),
    )
}

pub fn recover_fragment_runtime_configured_strict(
    pin_path: &str,
    expected_config: FragmentConfig,
    expected_max_entries: u32,
) -> Result<u64, String> {
    recover_fragment_runtime_with(
        || {
            validate_fragment_runtime_maps_strict(pin_path)?;
            let actual_v4_max = fragment_context_capacity(pin_path, "FRAG_CONTEXT_V4")?;
            let actual_v6_max = fragment_context_capacity(pin_path, "FRAG_CONTEXT_V6")?;
            if actual_v4_max != expected_max_entries || actual_v6_max != expected_max_entries {
                return validate_fragment_runtime_expectation(
                    &expected_config,
                    &expected_config,
                    actual_v4_max,
                    actual_v6_max,
                    expected_max_entries,
                );
            }
            Ok(())
        },
        || configure_fragment_tracking(pin_path, expected_config.runtime_mode, expected_config),
        || clear_fragment_contexts_strict(pin_path),
    )
}
