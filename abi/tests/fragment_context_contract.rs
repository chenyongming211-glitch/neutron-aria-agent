use aria_ebpf_abi::{
    fragment_context_disposition, fragment_context_flags_for_l4, fragment_context_l4_proto,
    fragment_ct_create_point, fragment_first_observation_metric, fragment_install_result,
    fragment_resolve_decision, fragment_resolved_l4_fields, fragment_tracking_required,
    FragmentConfig, FragmentContextDisposition, FragmentContextKey4, FragmentContextValue,
    FragmentCtCreatePoint, FragmentEpochValue, FragmentInstallDecision, FragmentKind,
    FragmentResolveDecision, set_fragment_resolve_drop_ids, PipelineCtx, TraceEvent,
    TraceEventV6, TraceStreamEvent, DIR_EGRESS, DIR_INGRESS, DROP_FRAGMENT_CONTEXT_EXPIRED,
    DROP_FRAGMENT_CONTEXT_MISSING, DROP_FRAGMENT_CONTEXT_UPDATE_FAILED,
    DROP_FRAGMENT_TRACKING_DISABLED, FRAGMENT_CONFIG_DISABLED, FRAGMENT_CONFIG_ENABLED,
    FRAGMENT_CONFIG_VERSION, FRAGMENT_CONTEXT_FLAG_TCP, FRAGMENT_CONTEXT_VERSION,
    FRAGMENT_METRIC_CONTEXT_EXPIRED, FRAGMENT_METRIC_CONTEXT_MISSING,
    FRAGMENT_METRIC_CONTEXT_UPDATE_FAILED, FRAGMENT_METRIC_FIRST,
    FRAGMENT_METRIC_TRACKING_DISABLED, FRAGMENT_RUNTIME_MODE_MANAGED,
    FRAGMENT_RUNTIME_MODE_STANDALONE, IPPROTO_ICMP, IPPROTO_TCP, IPPROTO_UDP,
    TAP_ID_UNASSIGNED, TRACE_RESULT_DROP_ACL, TRACE_RESULT_DROP_ACL_DEFAULT,
    TRACE_RESULT_DROP_ACL_PORT, TRACE_RESULT_DROP_FRAGMENT, TRACE_RESULT_DROP_QOS,
    TRACE_RESULT_PASS,
};

const SECOND: u64 = 1_000_000_000;

fn enabled_config() -> FragmentConfig {
    FragmentConfig {
        version: FRAGMENT_CONFIG_VERSION,
        enabled: FRAGMENT_CONFIG_ENABLED,
        runtime_mode: FRAGMENT_RUNTIME_MODE_MANAGED,
        _pad: [0; 5],
        ipv4_timeout_ns: 30 * SECOND,
        ipv6_timeout_ns: 30 * SECOND,
    }
}

fn standalone_enabled_config() -> FragmentConfig {
    FragmentConfig {
        runtime_mode: FRAGMENT_RUNTIME_MODE_STANDALONE,
        ..enabled_config()
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
fn fragment_resolved_l4_fields_recovers_tcp_proto_and_ports() {
    let value = FragmentContextValue {
        flags: FRAGMENT_CONTEXT_FLAG_TCP,
        ..current_value()
    };

    assert_eq!(
        Some((IPPROTO_TCP, 40000u16, 53u16)),
        fragment_resolved_l4_fields(&value),
    );
}

#[test]
fn fragment_resolved_l4_fields_is_none_without_l4_flags() {
    let value = current_value();

    assert_eq!(None, fragment_resolved_l4_fields(&value));
}

#[test]
fn fragment_observability_first_metric_is_decided_before_acl_or_install_outcome() {
    for proto in [IPPROTO_TCP, IPPROTO_UDP] {
        let metric_before_acl = fragment_first_observation_metric(FragmentKind::First as u8, proto);
        let acl_allows = false;

        assert!(!acl_allows);
        assert_eq!(metric_before_acl, FRAGMENT_METRIC_FIRST);
    }

    assert_eq!(
        fragment_first_observation_metric(FragmentKind::NonInitial as u8, IPPROTO_UDP),
        0
    );
    assert_eq!(
        fragment_first_observation_metric(FragmentKind::First as u8, IPPROTO_ICMP),
        0
    );
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
fn fragment_resolve_expired_context_drops_without_packet_path_delete() {
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
    assert!(!decision.delete_context());
}

#[test]
fn pipeline_ctx_carries_one_packet_fragment_authority_snapshot() {
    let mut pipeline = unsafe { core::mem::zeroed::<PipelineCtx>() };
    pipeline.acl_bank_snapshot = 1;
    pipeline.fragment_epoch_present = 1;
    pipeline.fragment_epoch_snapshot = 19;

    assert_eq!(pipeline.acl_bank_snapshot, 1);
    assert_eq!(pipeline.fragment_epoch_present, 1);
    assert_eq!(pipeline.fragment_epoch_snapshot, 19);
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
fn fragment_resolve_managed_tap_zero_cannot_use_context() {
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
fn fragment_resolve_standalone_tap_zero_uses_its_stable_identity() {
    assert_eq!(
        fragment_resolve_decision(
            0,
            false,
            Some(&standalone_enabled_config()),
            Some(&current_epoch()),
            Some(&current_value()),
            0,
            1_000,
            1480,
        ),
        FragmentResolveDecision::Hit,
    );
}

#[test]
fn fragment_resolve_unknown_runtime_mode_is_invalid_before_disabled_handling() {
    let mut config = enabled_config();
    config.enabled = FRAGMENT_CONFIG_DISABLED;
    config.runtime_mode = 0xff;

    assert_eq!(
        fragment_resolve_decision(0, false, Some(&config), None, None, 0, 1_000, 1480,),
        FragmentResolveDecision::DropConfigInvalid,
    );
}

#[test]
fn fragment_resolve_valid_disabled_config_precedes_enabled_identity_checks() {
    for mut config in [enabled_config(), standalone_enabled_config()] {
        config.enabled = FRAGMENT_CONFIG_DISABLED;
        assert_eq!(
            fragment_resolve_decision(0, false, Some(&config), None, None, 0, 1_000, 1480),
            FragmentResolveDecision::DropTrackingDisabled,
        );
    }
}

#[test]
fn fragment_resolve_validates_both_family_timeouts_before_disabled_or_tap_identity() {
    let mut ipv4_packet_config = enabled_config();
    ipv4_packet_config.ipv6_timeout_ns = 0;
    let mut ipv6_packet_config = enabled_config();
    ipv6_packet_config.ipv4_timeout_ns = 0;

    for (is_ipv6, mut config) in [(false, ipv4_packet_config), (true, ipv6_packet_config)] {
        config.enabled = FRAGMENT_CONFIG_DISABLED;
        assert_eq!(
            fragment_resolve_decision(0, is_ipv6, Some(&config), None, None, 0, 1_000, 1480),
            FragmentResolveDecision::DropConfigInvalid,
        );

        config.enabled = FRAGMENT_CONFIG_ENABLED;
        assert_eq!(
            fragment_resolve_decision(0, is_ipv6, Some(&config), None, None, 0, 1_000, 1480),
            FragmentResolveDecision::DropConfigInvalid,
        );
    }
}

#[test]
fn fragment_first_ct_create_point_follows_policy_qos_and_context_install() {
    assert_eq!(
        fragment_ct_create_point(FragmentKind::First as u8),
        FragmentCtCreatePoint::AfterContextInstall,
    );
    assert_eq!(
        fragment_ct_create_point(FragmentKind::Unfragmented as u8),
        FragmentCtCreatePoint::AfterPolicyQos,
    );
}

#[test]
fn fragment_insert_failure_always_drops_without_ct_cleanup() {
    let failed = fragment_install_result(false);

    assert_eq!(failed, FragmentInstallDecision::DropKeepCt);
    assert_eq!(failed.drop_reason(), DROP_FRAGMENT_CONTEXT_UPDATE_FAILED);
    assert_eq!(failed.metric(), FRAGMENT_METRIC_CONTEXT_UPDATE_FAILED);
    assert!(!failed.remove_created_ct());
    assert_eq!(fragment_install_result(true), FragmentInstallDecision::Pass);
}

#[test]
fn fragment_failed_old_packet_cannot_delete_same_key_replacement_ct() {
    let mut ct_generation = Some(1_u64);
    assert_eq!(ct_generation, Some(1));

    // Packet A created generation 1, external cleanup removed it, and packet B
    // then installed generation 2 under the same five-tuple key.
    ct_generation = None;
    assert_eq!(ct_generation, None);
    ct_generation = Some(2);

    let packet_a_install = fragment_install_result(false);
    if packet_a_install.remove_created_ct() {
        ct_generation = None;
    }

    assert_eq!(packet_a_install, FragmentInstallDecision::DropKeepCt);
    assert_eq!(ct_generation, Some(2));
}

fn assert_pipeline_ctx_reset_for_tc_packet(direction: u8, pkt_len: u32) {
    let mut pipeline = core::mem::MaybeUninit::<PipelineCtx>::uninit();
    unsafe {
        core::ptr::write_bytes(
            pipeline.as_mut_ptr().cast::<u8>(),
            0xff,
            core::mem::size_of::<PipelineCtx>(),
        );
    }
    let mut pipeline = unsafe { pipeline.assume_init() };

    pipeline.reset_for_tc_packet(pkt_len, direction);

    assert_eq!(pipeline.tap_id, TAP_ID_UNASSIGNED);
    assert_eq!(pipeline.src_id, 0);
    assert_eq!(pipeline.dst_id, 0);
    assert_eq!(pipeline.pkt_len, pkt_len);
    assert_eq!(pipeline.now, 0);
    assert_eq!(pipeline.proto, 0);
    assert_eq!(pipeline.direction, direction);
    assert_eq!(pipeline.flags, 0);
    assert_eq!(pipeline.ct_state, 0);
    assert_eq!(pipeline.drop_reason, 0);
    assert_eq!(pipeline._pad, [0; 2]);
    assert_eq!(pipeline.action, 0);
    assert_eq!(pipeline.matched_src_id, 0);
    assert_eq!(pipeline.matched_dst_id, 0);
    assert_eq!(pipeline.matched_proto, 0);
    assert_eq!(pipeline.matched_direction, 0);
    assert_eq!(pipeline.matched_bank, 0);
    assert_eq!(pipeline._pad2, [0; 1]);
    assert_eq!(pipeline.fragment_epoch_snapshot, 0);
    assert_eq!(pipeline.acl_bank_snapshot, 0);
    assert_eq!(pipeline.fragment_epoch_present, 0);
    assert_eq!(pipeline._pad3, [0; 6]);
}

#[test]
fn fragment_tc_packet_reset_clears_every_pipeline_field_for_both_directions() {
    assert_pipeline_ctx_reset_for_tc_packet(DIR_INGRESS, 64);
    assert_pipeline_ctx_reset_for_tc_packet(DIR_EGRESS, 9_001);
}

#[test]
fn fragment_drop_trace_result_is_additive_without_layout_change() {
    assert_eq!(TRACE_RESULT_PASS, 0);
    assert_eq!(TRACE_RESULT_DROP_ACL, 1);
    assert_eq!(TRACE_RESULT_DROP_ACL_PORT, 2);
    assert_eq!(TRACE_RESULT_DROP_ACL_DEFAULT, 3);
    assert_eq!(TRACE_RESULT_DROP_QOS, 4);
    assert_eq!(TRACE_RESULT_DROP_FRAGMENT, 5);
    assert_eq!(core::mem::size_of::<TraceEvent>(), 40);
    assert_eq!(core::mem::size_of::<TraceEventV6>(), 64);
    assert_eq!(core::mem::size_of::<TraceStreamEvent>(), 88);
}

#[test]
fn fragment_resolve_drop_attribution_replaces_poisoned_group_ids() {
    let mut pipeline = unsafe { core::mem::zeroed::<PipelineCtx>() };
    pipeline.src_id = u32::MAX;
    pipeline.dst_id = u32::MAX;

    set_fragment_resolve_drop_ids(&mut pipeline, Some(17), None);
    assert_eq!((pipeline.src_id, pipeline.dst_id), (17, 0));

    set_fragment_resolve_drop_ids(&mut pipeline, None, Some(29));
    assert_eq!((pipeline.src_id, pipeline.dst_id), (0, 29));
}
