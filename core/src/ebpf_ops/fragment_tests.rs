use super::fragment::{
    advance_fragment_epoch_with, default_fragment_config, fragment_v4_key_matches_tap,
    fragment_v6_key_matches_tap, validate_fragment_config,
};
use super::{
    advance_fragment_epoch_strict, read_fragment_epoch, ALL_MAP_NAMES, CRITICAL_NETWORK_MAP_NAMES,
    NETWORK_MAP_NAMES, STREAM_CRITICAL_NETWORK_MAP_NAMES,
};
use crate::common::{FragmentConfig, FragmentContextKey4, FragmentContextKey6};
use std::cell::RefCell;
use std::collections::BTreeMap;

#[test]
fn fragment_epoch_missing_pinned_map_is_an_error() {
    let missing = format!("/tmp/aria-fragment-map-missing-{}", std::process::id());
    assert!(read_fragment_epoch(&missing, 41).is_err());
    assert!(advance_fragment_epoch_strict(&missing, 41).is_err());
}

#[test]
fn fragment_epoch_absent_entry_starts_at_zero_and_increments_exactly() {
    let entries = RefCell::new(BTreeMap::<u32, u64>::new());
    let next = advance_fragment_epoch_with(
        41,
        || Ok(entries.borrow().get(&41).copied()),
        |value| {
            entries.borrow_mut().insert(41, value);
            Ok(())
        },
    )
    .unwrap();

    assert_eq!(next, 1);
    assert_eq!(entries.borrow().get(&41), Some(&1));
}

#[test]
fn fragment_epoch_rejects_wrap_without_writing() {
    let writes = RefCell::new(Vec::new());
    let error = advance_fragment_epoch_with(
        41,
        || Ok(Some(u64::MAX)),
        |value| {
            writes.borrow_mut().push(value);
            Ok(())
        },
    )
    .unwrap_err();

    assert!(error.contains("u64::MAX"));
    assert!(writes.borrow().is_empty());
}

#[test]
fn fragment_epoch_increment_is_isolated_per_tap_and_verified_by_readback() {
    let entries = RefCell::new(BTreeMap::from([(41u32, 8u64), (42u32, 19u64)]));
    let next = advance_fragment_epoch_with(
        41,
        || Ok(entries.borrow().get(&41).copied()),
        |value| {
            entries.borrow_mut().insert(41, value);
            Ok(())
        },
    )
    .unwrap();

    assert_eq!(next, 9);
    assert_eq!(entries.borrow().get(&41), Some(&9));
    assert_eq!(entries.borrow().get(&42), Some(&19));

    let mismatch = advance_fragment_epoch_with(41, || Ok(Some(8)), |_value| Ok(())).unwrap_err();
    assert!(mismatch.contains("read-back"));
}

#[test]
fn fragment_epoch_config_defaults_disabled_and_rejects_invalid_values() {
    let config = default_fragment_config();
    assert_eq!(config.version, 1);
    assert_eq!(config.enabled, 0);
    assert_eq!(config.ipv4_timeout_ns, 30_000_000_000);
    assert_eq!(config.ipv6_timeout_ns, 30_000_000_000);
    validate_fragment_config(&config).unwrap();

    for invalid in [
        FragmentConfig {
            version: 2,
            ..config
        },
        FragmentConfig {
            enabled: 2,
            ..config
        },
        FragmentConfig {
            ipv4_timeout_ns: 0,
            ..config
        },
        FragmentConfig {
            ipv6_timeout_ns: 60_000_000_001,
            ..config
        },
    ] {
        assert!(validate_fragment_config(&invalid).is_err());
    }
}

#[test]
fn fragment_epoch_context_selection_is_exactly_tap_scoped_for_both_families() {
    let v4_a = FragmentContextKey4 {
        tap_id: 41,
        src_ip: 1,
        dst_ip: 2,
        fragment_id: 3,
        vlan_id: 4,
        proto: 17,
        direction: 1,
        _pad: [0; 2],
    };
    let v4_b = FragmentContextKey4 { tap_id: 42, ..v4_a };
    assert!(fragment_v4_key_matches_tap(&v4_a, 41));
    assert!(!fragment_v4_key_matches_tap(&v4_b, 41));

    let v6_a = FragmentContextKey6 {
        tap_id: 41,
        src_ip: [1; 16],
        dst_ip: [2; 16],
        fragment_id: 3,
        vlan_id: 4,
        proto: 17,
        direction: 1,
    };
    let v6_b = FragmentContextKey6 { tap_id: 42, ..v6_a };
    assert!(fragment_v6_key_matches_tap(&v6_a, 41));
    assert!(!fragment_v6_key_matches_tap(&v6_b, 41));
}

#[test]
fn fragment_epoch_maps_are_in_every_runtime_pin_inventory() {
    let fragment_maps = [
        "FRAG_CONTEXT_V4",
        "FRAG_CONTEXT_V6",
        "FRAGMENT_EPOCH",
        "FRAGMENT_CONFIG",
        "FRAGMENT_METRICS",
    ];
    for map_name in fragment_maps {
        assert!(NETWORK_MAP_NAMES.contains(&map_name));
        assert!(ALL_MAP_NAMES.contains(&map_name));
        assert!(CRITICAL_NETWORK_MAP_NAMES.contains(&map_name));
        assert!(STREAM_CRITICAL_NETWORK_MAP_NAMES.contains(&map_name));
    }
}
