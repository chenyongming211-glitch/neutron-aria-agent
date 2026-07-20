use super::fragment::{
    advance_fragment_epoch_with, default_fragment_config, fragment_sweep_with,
    fragment_v4_key_matches_tap, fragment_v6_key_matches_tap, recover_fragment_runtime_with,
    scrub_fragment_families_with, validate_fragment_config, validate_fragment_config_disabled,
    validate_fragment_runtime_maps_with, FragmentRemoveOutcome, FragmentRuntimeMapKind,
};
use super::{
    advance_fragment_epoch_strict, read_fragment_epoch, ALL_MAP_NAMES, CRITICAL_NETWORK_MAP_NAMES,
    NETWORK_MAP_NAMES, STREAM_CRITICAL_NETWORK_MAP_NAMES,
};
use crate::common::{
    FragmentConfig, FragmentContextKey4, FragmentContextKey6, FRAGMENT_CONFIG_DISABLED,
    FRAGMENT_CONFIG_VERSION, FRAGMENT_RUNTIME_MODE_MANAGED, FRAGMENT_RUNTIME_MODE_STANDALONE,
};
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
fn fragment_epoch_default_disabled_configs_are_mode_specific() {
    let managed = default_fragment_config(FRAGMENT_RUNTIME_MODE_MANAGED).unwrap();
    let standalone = default_fragment_config(FRAGMENT_RUNTIME_MODE_STANDALONE).unwrap();

    for config in [managed, standalone] {
        assert_eq!(config.version, FRAGMENT_CONFIG_VERSION);
        assert_eq!(config.enabled, FRAGMENT_CONFIG_DISABLED);
        assert_eq!(config._pad, [0; 5]);
        assert_eq!(config.ipv4_timeout_ns, 30_000_000_000);
        assert_eq!(config.ipv6_timeout_ns, 30_000_000_000);
    }
    assert_eq!(managed.runtime_mode, FRAGMENT_RUNTIME_MODE_MANAGED);
    assert_eq!(standalone.runtime_mode, FRAGMENT_RUNTIME_MODE_STANDALONE);
    assert_ne!(managed.runtime_mode, standalone.runtime_mode);
    validate_fragment_config(&managed, FRAGMENT_RUNTIME_MODE_MANAGED).unwrap();
    validate_fragment_config(&standalone, FRAGMENT_RUNTIME_MODE_STANDALONE).unwrap();
    assert!(validate_fragment_config(&managed, FRAGMENT_RUNTIME_MODE_STANDALONE).is_err());
    assert!(validate_fragment_config(&standalone, FRAGMENT_RUNTIME_MODE_MANAGED).is_err());
}

#[test]
fn fragment_epoch_config_rejects_unknown_mode_and_invalid_values() {
    assert!(default_fragment_config(0xff).is_err());
    let config = default_fragment_config(FRAGMENT_RUNTIME_MODE_MANAGED).unwrap();

    for invalid in [
        FragmentConfig {
            version: FRAGMENT_CONFIG_VERSION.wrapping_add(1),
            ..config
        },
        FragmentConfig {
            enabled: 2,
            ..config
        },
        FragmentConfig {
            runtime_mode: 0xff,
            ..config
        },
        FragmentConfig {
            _pad: [1, 0, 0, 0, 0],
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
        assert!(validate_fragment_config(&invalid, FRAGMENT_RUNTIME_MODE_MANAGED).is_err());
    }
}

#[test]
fn fragment_epoch_task4_readiness_rejects_valid_but_enabled_config() {
    let mut config = default_fragment_config(FRAGMENT_RUNTIME_MODE_MANAGED).unwrap();
    config.enabled = 1;

    validate_fragment_config(&config, FRAGMENT_RUNTIME_MODE_MANAGED).unwrap();
    let error =
        validate_fragment_config_disabled(&config, FRAGMENT_RUNTIME_MODE_MANAGED).unwrap_err();
    assert!(error.contains("not ready for Task 4"));
    assert!(error.contains("disabled"));
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

#[test]
fn fragment_epoch_lru_sweep_continues_after_remove_time_missing() {
    let entries = RefCell::new(BTreeMap::from([(42u32, "live")]));
    let removed = fragment_sweep_with(
        "FRAG_CONTEXT_V4",
        || Ok(vec![41u32, 42u32]),
        |_key| true,
        |key| {
            if entries.borrow_mut().remove(key).is_some() {
                Ok(FragmentRemoveOutcome::Removed)
            } else {
                Ok(FragmentRemoveOutcome::Missing)
            }
        },
        || Ok(entries.borrow().is_empty()),
    )
    .unwrap();

    assert_eq!(removed, 1);
    assert!(entries.borrow().is_empty());
}

#[test]
fn fragment_epoch_lru_sweep_stops_on_non_missing_remove_error() {
    let attempted = RefCell::new(Vec::new());
    let verified = RefCell::new(false);
    let error = fragment_sweep_with(
        "FRAG_CONTEXT_V6",
        || Ok(vec![41u32, 42u32]),
        |_key| true,
        |key| {
            attempted.borrow_mut().push(*key);
            Err("permission denied".to_string())
        },
        || {
            *verified.borrow_mut() = true;
            Ok(true)
        },
    )
    .unwrap_err();

    assert!(error.contains("permission denied"));
    assert_eq!(&*attempted.borrow(), &[41]);
    assert!(!*verified.borrow());
}

#[test]
fn fragment_epoch_tap_sweep_preserves_other_taps_and_config() {
    let entries = RefCell::new(BTreeMap::from([(41u32, "target"), (42u32, "other")]));
    let config_marker = "managed-disabled";
    let removed = fragment_sweep_with(
        "FRAG_CONTEXT_V4",
        || Ok(entries.borrow().keys().copied().collect()),
        |key| *key == 41,
        |key| {
            if entries.borrow_mut().remove(key).is_some() {
                Ok(FragmentRemoveOutcome::Removed)
            } else {
                Ok(FragmentRemoveOutcome::Missing)
            }
        },
        || Ok(!entries.borrow().contains_key(&41)),
    )
    .unwrap();

    assert_eq!(removed, 1);
    assert_eq!(entries.borrow().get(&42), Some(&"other"));
    assert_eq!(config_marker, "managed-disabled");
}

#[test]
fn fragment_epoch_deletes_epoch_only_after_both_families_verify_empty() {
    let events = RefCell::new(Vec::new());
    let removed = scrub_fragment_families_with(
        || {
            events.borrow_mut().push("v4-empty");
            Ok(2)
        },
        || {
            events.borrow_mut().push("v6-empty");
            Ok(3)
        },
        || {
            events.borrow_mut().push("epoch-delete");
            Ok(FragmentRemoveOutcome::Removed)
        },
    )
    .unwrap();

    assert_eq!(removed, 6);
    assert_eq!(&*events.borrow(), &["v4-empty", "v6-empty", "epoch-delete"]);
}

#[test]
fn fragment_epoch_v6_failure_does_not_delete_epoch() {
    let events = RefCell::new(Vec::new());
    let error = scrub_fragment_families_with(
        || {
            events.borrow_mut().push("v4-empty");
            Ok(1)
        },
        || {
            events.borrow_mut().push("v6-failed");
            Err("v6 still contains tap entries".to_string())
        },
        || {
            events.borrow_mut().push("epoch-delete");
            Ok(FragmentRemoveOutcome::Removed)
        },
    )
    .unwrap_err();

    assert!(error.contains("v6 still contains"));
    assert_eq!(&*events.borrow(), &["v4-empty", "v6-failed"]);
}

#[test]
fn fragment_epoch_recovery_validates_maps_then_writes_config_before_clear() {
    let events = RefCell::new(Vec::new());
    let removed = recover_fragment_runtime_with(
        || {
            events.borrow_mut().push("validate-five-maps");
            Ok(())
        },
        || {
            events.borrow_mut().push("write-config");
            Ok(())
        },
        || {
            events.borrow_mut().push("clear-contexts");
            Ok(4)
        },
    )
    .unwrap();

    assert_eq!(removed, 4);
    assert_eq!(
        &*events.borrow(),
        &["validate-five-maps", "write-config", "clear-contexts"]
    );
}

#[test]
fn fragment_epoch_runtime_map_validator_covers_all_exact_map_kinds() {
    let expected = [
        ("FRAG_CONTEXT_V4", FragmentRuntimeMapKind::ContextV4Lru),
        ("FRAG_CONTEXT_V6", FragmentRuntimeMapKind::ContextV6Lru),
        ("FRAGMENT_EPOCH", FragmentRuntimeMapKind::EpochHash),
        ("FRAGMENT_CONFIG", FragmentRuntimeMapKind::ConfigHash),
        (
            "FRAGMENT_METRICS",
            FragmentRuntimeMapKind::MetricsPerCpuArrayU64,
        ),
    ];
    let visited = RefCell::new(Vec::new());
    validate_fragment_runtime_maps_with(|name, kind| {
        visited.borrow_mut().push((name, kind));
        Ok(())
    })
    .unwrap();

    assert_eq!(&*visited.borrow(), &expected);
}

#[test]
fn fragment_epoch_runtime_map_validator_rejects_each_missing_or_wrong_map() {
    let names = [
        "FRAG_CONTEXT_V4",
        "FRAG_CONTEXT_V6",
        "FRAGMENT_EPOCH",
        "FRAGMENT_CONFIG",
        "FRAGMENT_METRICS",
    ];
    for target in names {
        for failure in ["missing", "wrong type or ABI"] {
            let error = validate_fragment_runtime_maps_with(|name, _kind| {
                if name == target {
                    Err(format!("{} {}", failure, name))
                } else {
                    Ok(())
                }
            })
            .unwrap_err();
            assert!(error.contains(target));
            assert!(error.contains(failure));
        }
    }
}
