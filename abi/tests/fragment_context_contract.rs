use aria_ebpf_abi::{
    fragment_context_disposition, fragment_context_flags_for_l4, fragment_context_l4_proto,
    fragment_install_result, fragment_resolve_decision, fragment_tracking_required, FragmentConfig,
    FragmentContextDisposition, FragmentContextKey4, FragmentContextValue, FragmentEpochValue,
    FragmentInstallDecision, FragmentKind, FragmentResolveDecision, DROP_FRAGMENT_CONTEXT_EXPIRED,
    DROP_FRAGMENT_CONTEXT_MISSING, DROP_FRAGMENT_CONTEXT_UPDATE_FAILED,
    DROP_FRAGMENT_TRACKING_DISABLED, FRAGMENT_CONFIG_DISABLED, FRAGMENT_CONFIG_ENABLED,
    FRAGMENT_CONFIG_VERSION, FRAGMENT_CONTEXT_FLAG_TCP, FRAGMENT_CONTEXT_VERSION,
    FRAGMENT_METRIC_CONTEXT_EXPIRED, FRAGMENT_METRIC_CONTEXT_MISSING,
    FRAGMENT_METRIC_CONTEXT_UPDATE_FAILED, FRAGMENT_METRIC_TRACKING_DISABLED, IPPROTO_ICMP,
    IPPROTO_TCP, IPPROTO_UDP,
};

const SECOND: u64 = 1_000_000_000;

fn enabled_config() -> FragmentConfig {
    FragmentConfig {
        version: FRAGMENT_CONFIG_VERSION,
        enabled: FRAGMENT_CONFIG_ENABLED,
        _pad: [0; 6],
        ipv4_timeout_ns: 30 * SECOND,
        ipv6_timeout_ns: 30 * SECOND,
    }
}

fn current_epoch() -> FragmentEpochValue {
    FragmentEpochValue { epoch: 7 }
}

fn current_value() -> FragmentContextValue {
    FragmentContextValue {
        src_port: 40000,
        dst_port: 53,
        first_payload_end: 1480,
        acl_bank: 0,
        flags: 0,
        version: 1,
        _pad: 0,
        _reserved: [0; 6],
        epoch: 7,
        expires_at_ns: 30_000_000_000,
    }
}

#[test]
fn fragment_context_key4_has_exact_fragment_identity_layout() {
    let key = FragmentContextKey4 {
        tap_id: 77,
        src_ip: 0xc000_020a,
        dst_ip: 0xc633_6435,
        fragment_id: 0x1234,
        vlan_id: 4094,
        proto: 17,
        direction: 1,
        _pad: [0; 2],
    };

    assert_eq!(core::mem::size_of::<FragmentContextKey4>(), 20);
    assert_eq!(core::mem::offset_of!(FragmentContextKey4, tap_id), 0);
    assert_eq!(core::mem::offset_of!(FragmentContextKey4, src_ip), 4);
    assert_eq!(core::mem::offset_of!(FragmentContextKey4, dst_ip), 8);
    assert_eq!(core::mem::offset_of!(FragmentContextKey4, fragment_id), 12);
    assert_eq!(core::mem::offset_of!(FragmentContextKey4, vlan_id), 14);
    assert_eq!(core::mem::offset_of!(FragmentContextKey4, proto), 16);
    assert_eq!(core::mem::offset_of!(FragmentContextKey4, direction), 17);
    assert_eq!(key.fragment_id, 0x1234);
    assert_eq!((key.vlan_id, key.proto, key.direction), (4094, 17, 1));
}

#[test]
fn fragment_context_value_has_no_implicit_pod_padding() {
    let value = current_value();

    assert_eq!(core::mem::size_of::<FragmentContextValue>(), 32);
    assert_eq!(core::mem::offset_of!(FragmentContextValue, _pad), 9);
    assert_eq!(core::mem::offset_of!(FragmentContextValue, _reserved), 10);
    assert_eq!(core::mem::offset_of!(FragmentContextValue, epoch), 16);
    assert_eq!(value._reserved, [0; 6]);
}

#[test]
fn fragment_context_accepts_current_bank_epoch_and_non_overlapping_offset() {
    let value = current_value();

    assert_eq!(
        fragment_context_disposition(&value, 0, 7, 1_000, 1480),
        FragmentContextDisposition::Hit,
    );
}

#[test]
fn fragment_context_expires_at_the_exact_deadline() {
    let value = current_value();

    assert_eq!(
        fragment_context_disposition(&value, 0, 7, 30_000_000_000, 1480),
        FragmentContextDisposition::Expired,
    );
}

#[test]
fn fragment_context_rejects_overlap_with_first_fragment_range() {
    let value = current_value();

    assert_eq!(
        fragment_context_disposition(&value, 0, 7, 1_000, 1472),
        FragmentContextDisposition::Overlap,
    );
}

#[test]
fn fragment_context_rejects_bank_mismatch() {
    let value = current_value();

    assert_eq!(
        fragment_context_disposition(&value, 1, 7, 1_000, 1480),
        FragmentContextDisposition::Stale,
    );
}

#[test]
fn fragment_context_rejects_two_bank_rotation_epoch_reuse() {
    let value = FragmentContextValue {
        src_port: 40000,
        dst_port: 53,
        first_payload_end: 1480,
        acl_bank: 0,
        flags: 0,
        version: 1,
        _pad: 0,
        _reserved: [0; 6],
        epoch: 7,
        expires_at_ns: 30_000_000_000,
    };
    assert_eq!(
        fragment_context_disposition(&value, 0, 9, 1_000, 1480),
        FragmentContextDisposition::Stale,
    );
}

#[test]
fn fragment_tracking_applies_only_to_real_tcp_udp_or_ambiguous_extension_fragments() {
    assert!(fragment_tracking_required(
        FragmentKind::First as u8,
        IPPROTO_TCP,
        false,
    ));
    assert!(fragment_tracking_required(
        FragmentKind::NonInitial as u8,
        IPPROTO_UDP,
        true,
    ));
    assert!(fragment_tracking_required(
        FragmentKind::NonInitial as u8,
        60,
        true,
    ));
    assert!(!fragment_tracking_required(
        FragmentKind::NonInitial as u8,
        60,
        false,
    ));
    assert!(!fragment_tracking_required(
        FragmentKind::Unfragmented as u8,
        IPPROTO_TCP,
        false,
    ));
    assert!(!fragment_tracking_required(
        FragmentKind::Atomic as u8,
        IPPROTO_TCP,
        true,
    ));
    assert!(!fragment_tracking_required(
        FragmentKind::NonInitial as u8,
        IPPROTO_ICMP,
        false,
    ));
}

#[test]
fn fragment_context_preserves_final_l4_protocol_separately_from_key_identity() {
    let mut value = current_value();
    value.flags = fragment_context_flags_for_l4(IPPROTO_TCP).unwrap();

    assert_eq!(value.flags, FRAGMENT_CONTEXT_FLAG_TCP);
    assert_eq!(fragment_context_l4_proto(&value), Some(IPPROTO_TCP));
    assert_eq!(fragment_context_flags_for_l4(IPPROTO_UDP), Some(0));
    assert_eq!(fragment_context_flags_for_l4(IPPROTO_ICMP), None);
}

#[test]
fn fragment_resolve_disabled_mode_fails_closed_with_stable_reason_and_metric() {
    let mut config = enabled_config();
    config.enabled = FRAGMENT_CONFIG_DISABLED;
    let decision = fragment_resolve_decision(
        77,
        false,
        Some(&config),
        Some(&current_epoch()),
        Some(&current_value()),
        0,
        1_000,
        1480,
    );

    assert_eq!(decision, FragmentResolveDecision::DropTrackingDisabled);
    assert_eq!(decision.drop_reason(), DROP_FRAGMENT_TRACKING_DISABLED);
    assert_eq!(decision.metric(), FRAGMENT_METRIC_TRACKING_DISABLED);
    assert!(!decision.delete_context());
}

#[test]
fn fragment_resolve_missing_context_fails_closed_with_stable_reason_and_metric() {
    let decision = fragment_resolve_decision(
        77,
        false,
        Some(&enabled_config()),
        Some(&current_epoch()),
        None,
        0,
        1_000,
        1480,
    );

    assert_eq!(decision, FragmentResolveDecision::DropContextMissing);
    assert_eq!(decision.drop_reason(), DROP_FRAGMENT_CONTEXT_MISSING);
    assert_eq!(decision.metric(), FRAGMENT_METRIC_CONTEXT_MISSING);
    assert!(!decision.delete_context());
}

#[test]
fn fragment_resolve_first_range_overlap_fails_closed() {
    let decision = fragment_resolve_decision(
        77,
        false,
        Some(&enabled_config()),
        Some(&current_epoch()),
        Some(&current_value()),
        0,
        1_000,
        1472,
    );

    assert_eq!(decision, FragmentResolveDecision::DropOverlap);
    assert!(!decision.delete_context());
}

#[test]
fn fragment_resolve_exact_context_hit_returns_authoritative_ports() {
    let value = current_value();
    let decision = fragment_resolve_decision(
        77,
        false,
        Some(&enabled_config()),
        Some(&current_epoch()),
        Some(&value),
        0,
        1_000,
        1480,
    );

    assert_eq!(decision, FragmentResolveDecision::Hit);
    assert_eq!((value.src_port, value.dst_port), (40000, 53));
    assert_eq!(decision.drop_reason(), 0);
}

#[test]
fn fragment_resolve_expired_context_requests_opportunistic_delete() {
    let value = current_value();
    let decision = fragment_resolve_decision(
        77,
        false,
        Some(&enabled_config()),
        Some(&current_epoch()),
        Some(&value),
        0,
        value.expires_at_ns,
        1480,
    );

    assert_eq!(decision, FragmentResolveDecision::DropExpired);
    assert_eq!(decision.drop_reason(), DROP_FRAGMENT_CONTEXT_EXPIRED);
    assert_eq!(decision.metric(), FRAGMENT_METRIC_CONTEXT_EXPIRED);
    assert!(decision.delete_context());
}

#[test]
fn fragment_resolve_rejects_missing_invalid_and_stale_authority() {
    let config = enabled_config();
    let epoch = current_epoch();
    assert_eq!(
        fragment_resolve_decision(77, false, None, Some(&epoch), None, 0, 1_000, 1480),
        FragmentResolveDecision::DropConfigMissing,
    );

    let mut invalid_config = config;
    invalid_config.version = FRAGMENT_CONFIG_VERSION.wrapping_add(1);
    assert_eq!(
        fragment_resolve_decision(
            77,
            false,
            Some(&invalid_config),
            Some(&epoch),
            None,
            0,
            1_000,
            1480,
        ),
        FragmentResolveDecision::DropConfigInvalid,
    );
    assert_eq!(
        fragment_resolve_decision(77, false, Some(&config), None, None, 0, 1_000, 1480),
        FragmentResolveDecision::DropEpochMissing,
    );

    let mut invalid_value = current_value();
    invalid_value.version = FRAGMENT_CONTEXT_VERSION.wrapping_add(1);
    assert_eq!(
        fragment_resolve_decision(
            77,
            false,
            Some(&config),
            Some(&epoch),
            Some(&invalid_value),
            0,
            1_000,
            1480,
        ),
        FragmentResolveDecision::DropContextInvalid,
    );

    let mut stale_value = current_value();
    stale_value.epoch = epoch.epoch + 1;
    assert_eq!(
        fragment_resolve_decision(
            77,
            false,
            Some(&config),
            Some(&epoch),
            Some(&stale_value),
            0,
            1_000,
            1480,
        ),
        FragmentResolveDecision::DropContextStale,
    );
}

#[test]
fn fragment_resolve_tap_zero_cannot_use_context() {
    assert_eq!(
        fragment_resolve_decision(
            0,
            false,
            Some(&enabled_config()),
            Some(&current_epoch()),
            Some(&current_value()),
            0,
            1_000,
            1480,
        ),
        FragmentResolveDecision::DropTapUnassigned,
    );
}

#[test]
fn fragment_insert_failure_drops_before_pass_and_removes_only_owned_ct() {
    let owned = fragment_install_result(false, true);
    assert_eq!(owned, FragmentInstallDecision::DropAndRemoveOwnedCt);
    assert_eq!(owned.drop_reason(), DROP_FRAGMENT_CONTEXT_UPDATE_FAILED);
    assert_eq!(owned.metric(), FRAGMENT_METRIC_CONTEXT_UPDATE_FAILED);
    assert!(owned.remove_created_ct());

    let unowned = fragment_install_result(false, false);
    assert_eq!(unowned, FragmentInstallDecision::DropKeepCt);
    assert!(!unowned.remove_created_ct());
    assert_eq!(
        fragment_install_result(true, true),
        FragmentInstallDecision::Pass,
    );
}
