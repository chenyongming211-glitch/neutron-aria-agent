use crate::common::{
    fragment_authority_drop_reason, fragment_context_flags_for_l4, fragment_context_l4_proto,
    fragment_first_observation_metric, fragment_install_result, fragment_metric_for_drop_reason,
    fragment_metric_index, fragment_resolve_decision, fragment_tracking_required,
    FragmentConfig, FragmentContextKey4, FragmentContextKey6, FragmentContextValue,
    FragmentInstallDecision, FragmentKind, PipelineCtx, DROP_FRAGMENT_CONFIG_MISSING,
    DROP_FRAGMENT_CONTEXT_INVALID, DROP_FRAGMENT_CONTEXT_MISSING, DROP_FRAGMENT_EPOCH_MISSING,
    DROP_FRAGMENT_EXPIRY_OVERFLOW, FRAGMENT_CONTEXT_VERSION, FRAGMENT_FAMILY_IPV4,
    FRAGMENT_FAMILY_IPV6, FRAGMENT_METRIC_EXPIRY_OVERFLOW, FRAGMENT_METRIC_INVALID_L4,
    FRAGMENT_METRIC_NON_INITIAL,
};
use crate::maps::{
    FRAGMENT_CONFIG, FRAGMENT_EPOCH, FRAGMENT_METRICS, FRAG_CONTEXT_V4, FRAG_CONTEXT_V6,
};
use crate::parser::PacketInfo;
use aria_ebpf_abi::FragmentEpochValue;

const FRAGMENT_CONFIG_KEY: u32 = 0;

#[repr(u8)]
pub enum ResolveOutcome {
    NotRequired = 0,
    Resolved = 1,
    Drop = 2,
}

#[inline(always)]
pub unsafe fn snapshot_authority(p: &mut PipelineCtx) {
    p.acl_bank_snapshot = crate::runtime::acl_active_bank(p.tap_id);
    p.fragment_epoch_snapshot = 0;
    p.fragment_epoch_present = 0;
    if let Some(epoch) = FRAGMENT_EPOCH.get(&p.tap_id) {
        p.fragment_epoch_snapshot = epoch.epoch;
        p.fragment_epoch_present = 1;
    }
}

#[inline(always)]
fn packet_epoch(p: &PipelineCtx) -> Option<FragmentEpochValue> {
    if p.fragment_epoch_present == 0 {
        None
    } else {
        Some(FragmentEpochValue {
            epoch: p.fragment_epoch_snapshot,
        })
    }
}

#[inline(always)]
unsafe fn record_metric(_p: &PipelineCtx, family: u8, metric: u8) {
    let Some(index) = fragment_metric_index(metric, family) else {
        return;
    };
    if let Some(value) = FRAGMENT_METRICS.get_ptr_mut(index) {
        *value = (*value).wrapping_add(1);
    }
}

#[inline(always)]
pub unsafe fn record_first_observation(info: &PacketInfo, p: &PipelineCtx) {
    let metric = fragment_first_observation_metric(info.fragment_kind, p.proto);
    if metric == 0 {
        return;
    }
    let family = if info.is_ipv6 {
        FRAGMENT_FAMILY_IPV6
    } else {
        FRAGMENT_FAMILY_IPV4
    };
    record_metric(p, family, metric);
}

#[inline(always)]
pub unsafe fn record_invalid_l4(family: u8) {
    let Some(index) = fragment_metric_index(FRAGMENT_METRIC_INVALID_L4, family) else {
        return;
    };
    if let Some(value) = FRAGMENT_METRICS.get_ptr_mut(index) {
        *value = (*value).wrapping_add(1);
    }
}

#[inline(always)]
unsafe fn resolve_v4_key(info: &PacketInfo, p: &PipelineCtx) -> FragmentContextKey4 {
    FragmentContextKey4 {
        tap_id: p.tap_id,
        src_ip: info.src_ip,
        dst_ip: info.dst_ip,
        fragment_id: info.fragment_id as u16,
        vlan_id: info.vlan_id,
        proto: info.fragment_proto,
        direction: p.direction,
        _pad: [0; 2],
    }
}

#[inline(always)]
unsafe fn resolve_v6_key(info: &PacketInfo, p: &PipelineCtx) -> FragmentContextKey6 {
    FragmentContextKey6 {
        tap_id: p.tap_id,
        src_ip: info.src_ip_v6,
        dst_ip: info.dst_ip_v6,
        fragment_id: info.fragment_id,
        vlan_id: info.vlan_id,
        proto: info.fragment_proto,
        direction: p.direction,
    }
}

#[inline(never)]
pub unsafe fn resolve_v4(info: &mut PacketInfo, p: &mut PipelineCtx) -> ResolveOutcome {
    if info.fragment_kind != FragmentKind::NonInitial as u8
        || !fragment_tracking_required(info.fragment_kind, info.fragment_proto, false)
    {
        return ResolveOutcome::NotRequired;
    }
    record_metric(p, FRAGMENT_FAMILY_IPV4, FRAGMENT_METRIC_NON_INITIAL);

    let key = resolve_v4_key(info, p);
    let config = match FRAGMENT_CONFIG.get(&FRAGMENT_CONFIG_KEY) {
        Some(config) => config,
        None => {
            record_drop(p, FRAGMENT_FAMILY_IPV4, DROP_FRAGMENT_CONFIG_MISSING);
            return ResolveOutcome::Drop;
        }
    };
    let authority = config_authority_drop_reason(p, false, config);
    if authority != 0 {
        record_drop(p, FRAGMENT_FAMILY_IPV4, authority);
        return ResolveOutcome::Drop;
    }
    let epoch = match packet_epoch(p) {
        Some(epoch) => epoch,
        None => {
            record_drop(p, FRAGMENT_FAMILY_IPV4, DROP_FRAGMENT_EPOCH_MISSING);
            return ResolveOutcome::Drop;
        }
    };
    let value = match FRAG_CONTEXT_V4.get(&key) {
        Some(value) => value,
        None => {
            record_drop(p, FRAGMENT_FAMILY_IPV4, DROP_FRAGMENT_CONTEXT_MISSING);
            return ResolveOutcome::Drop;
        }
    };
    let decision = fragment_resolve_decision(
        p.tap_id,
        false,
        Some(config),
        Some(&epoch),
        Some(value),
        p.acl_bank_snapshot,
        p.now,
        info.fragment_offset,
    );
    record_metric(p, FRAGMENT_FAMILY_IPV4, decision.metric());
    if decision.drop_reason() != 0 {
        p.drop_reason = decision.drop_reason();
        return ResolveOutcome::Drop;
    }

    let proto = match fragment_context_l4_proto(value) {
        Some(proto) => proto,
        None => {
            p.drop_reason = DROP_FRAGMENT_CONTEXT_INVALID;
            return ResolveOutcome::Drop;
        }
    };
    info.src_port = value.src_port;
    info.dst_port = value.dst_port;
    info.proto = proto;
    ResolveOutcome::Resolved
}

#[inline(never)]
pub unsafe fn resolve_v6(info: &mut PacketInfo, p: &mut PipelineCtx) -> ResolveOutcome {
    if info.fragment_kind != FragmentKind::NonInitial as u8
        || !fragment_tracking_required(info.fragment_kind, info.fragment_proto, true)
    {
        return ResolveOutcome::NotRequired;
    }
    record_metric(p, FRAGMENT_FAMILY_IPV6, FRAGMENT_METRIC_NON_INITIAL);

    let key = resolve_v6_key(info, p);
    let config = match FRAGMENT_CONFIG.get(&FRAGMENT_CONFIG_KEY) {
        Some(config) => config,
        None => {
            record_drop(p, FRAGMENT_FAMILY_IPV6, DROP_FRAGMENT_CONFIG_MISSING);
            return ResolveOutcome::Drop;
        }
    };
    let authority = config_authority_drop_reason(p, true, config);
    if authority != 0 {
        record_drop(p, FRAGMENT_FAMILY_IPV6, authority);
        return ResolveOutcome::Drop;
    }
    let epoch = match packet_epoch(p) {
        Some(epoch) => epoch,
        None => {
            record_drop(p, FRAGMENT_FAMILY_IPV6, DROP_FRAGMENT_EPOCH_MISSING);
            return ResolveOutcome::Drop;
        }
    };
    let value = match FRAG_CONTEXT_V6.get(&key) {
        Some(value) => value,
        None => {
            record_drop(p, FRAGMENT_FAMILY_IPV6, DROP_FRAGMENT_CONTEXT_MISSING);
            return ResolveOutcome::Drop;
        }
    };
    let decision = fragment_resolve_decision(
        p.tap_id,
        true,
        Some(config),
        Some(&epoch),
        Some(value),
        p.acl_bank_snapshot,
        p.now,
        info.fragment_offset,
    );
    record_metric(p, FRAGMENT_FAMILY_IPV6, decision.metric());
    if decision.drop_reason() != 0 {
        p.drop_reason = decision.drop_reason();
        return ResolveOutcome::Drop;
    }

    let proto = match fragment_context_l4_proto(value) {
        Some(proto) => proto,
        None => {
            p.drop_reason = DROP_FRAGMENT_CONTEXT_INVALID;
            return ResolveOutcome::Drop;
        }
    };
    info.src_port = value.src_port;
    info.dst_port = value.dst_port;
    info.proto = proto;
    ResolveOutcome::Resolved
}

#[inline(always)]
unsafe fn record_drop(p: &mut PipelineCtx, family: u8, drop_reason: u8) {
    p.drop_reason = drop_reason;
    record_metric(p, family, fragment_metric_for_drop_reason(drop_reason));
}

#[inline(always)]
fn config_authority_drop_reason(
    p: &PipelineCtx,
    is_ipv6: bool,
    config: &FragmentConfig,
) -> u8 {
    let present_epoch = FragmentEpochValue { epoch: 0 };
    fragment_authority_drop_reason(
        p.tap_id,
        is_ipv6,
        Some(config),
        Some(&present_epoch),
    )
}

#[inline(never)]
pub unsafe fn install_allowed_v4(
    info: &PacketInfo,
    p: &mut PipelineCtx,
) -> FragmentInstallDecision {
    if info.fragment_kind != FragmentKind::First as u8 {
        return FragmentInstallDecision::Pass;
    }
    let flags = match fragment_context_flags_for_l4(p.proto) {
        Some(flags) => flags,
        None => return FragmentInstallDecision::Pass,
    };
    if !fragment_tracking_required(info.fragment_kind, info.fragment_proto, false) {
        return FragmentInstallDecision::Pass;
    }
    let config = match FRAGMENT_CONFIG.get(&FRAGMENT_CONFIG_KEY) {
        Some(config) => config,
        None => {
            record_drop(p, FRAGMENT_FAMILY_IPV4, DROP_FRAGMENT_CONFIG_MISSING);
            return fragment_install_result(false);
        }
    };
    let authority = config_authority_drop_reason(p, false, config);
    if authority != 0 {
        record_drop(p, FRAGMENT_FAMILY_IPV4, authority);
        return fragment_install_result(false);
    }
    let epoch = match packet_epoch(p) {
        Some(epoch) => epoch,
        None => {
            record_drop(p, FRAGMENT_FAMILY_IPV4, DROP_FRAGMENT_EPOCH_MISSING);
            return fragment_install_result(false);
        }
    };
    let expires_at_ns = match p.now.checked_add(config.ipv4_timeout_ns) {
        Some(expires_at_ns) => expires_at_ns,
        None => {
            p.drop_reason = DROP_FRAGMENT_EXPIRY_OVERFLOW;
            record_metric(p, FRAGMENT_FAMILY_IPV4, FRAGMENT_METRIC_EXPIRY_OVERFLOW);
            return fragment_install_result(false);
        }
    };
    let key = resolve_v4_key(info, p);
    let value = FragmentContextValue {
        src_port: info.src_port,
        dst_port: info.dst_port,
        first_payload_end: info.first_payload_end,
        acl_bank: p.acl_bank_snapshot,
        flags,
        version: FRAGMENT_CONTEXT_VERSION,
        _pad: 0,
        _reserved: [0; 6],
        epoch: epoch.epoch,
        expires_at_ns,
    };
    // BPF_ANY: a valid first fragment replaces same-key authority for ID reuse.
    let decision = fragment_install_result(FRAG_CONTEXT_V4.insert(&key, &value, 0).is_ok());
    record_metric(p, FRAGMENT_FAMILY_IPV4, decision.metric());
    if decision.drop_reason() != 0 {
        p.drop_reason = decision.drop_reason();
    }
    decision
}

#[inline(never)]
pub unsafe fn install_allowed_v6(
    info: &PacketInfo,
    p: &mut PipelineCtx,
) -> FragmentInstallDecision {
    if info.fragment_kind != FragmentKind::First as u8 {
        return FragmentInstallDecision::Pass;
    }
    let flags = match fragment_context_flags_for_l4(p.proto) {
        Some(flags) => flags,
        None => return FragmentInstallDecision::Pass,
    };
    if !fragment_tracking_required(info.fragment_kind, info.fragment_proto, true) {
        return FragmentInstallDecision::Pass;
    }
    let config = match FRAGMENT_CONFIG.get(&FRAGMENT_CONFIG_KEY) {
        Some(config) => config,
        None => {
            record_drop(p, FRAGMENT_FAMILY_IPV6, DROP_FRAGMENT_CONFIG_MISSING);
            return fragment_install_result(false);
        }
    };
    let authority = config_authority_drop_reason(p, true, config);
    if authority != 0 {
        record_drop(p, FRAGMENT_FAMILY_IPV6, authority);
        return fragment_install_result(false);
    }
    let epoch = match packet_epoch(p) {
        Some(epoch) => epoch,
        None => {
            record_drop(p, FRAGMENT_FAMILY_IPV6, DROP_FRAGMENT_EPOCH_MISSING);
            return fragment_install_result(false);
        }
    };
    let expires_at_ns = match p.now.checked_add(config.ipv6_timeout_ns) {
        Some(expires_at_ns) => expires_at_ns,
        None => {
            p.drop_reason = DROP_FRAGMENT_EXPIRY_OVERFLOW;
            record_metric(p, FRAGMENT_FAMILY_IPV6, FRAGMENT_METRIC_EXPIRY_OVERFLOW);
            return fragment_install_result(false);
        }
    };
    let key = resolve_v6_key(info, p);
    let value = FragmentContextValue {
        src_port: info.src_port,
        dst_port: info.dst_port,
        first_payload_end: info.first_payload_end,
        acl_bank: p.acl_bank_snapshot,
        flags,
        version: FRAGMENT_CONTEXT_VERSION,
        _pad: 0,
        _reserved: [0; 6],
        epoch: epoch.epoch,
        expires_at_ns,
    };
    // BPF_ANY: a valid first fragment replaces same-key authority for ID reuse.
    let decision = fragment_install_result(FRAG_CONTEXT_V6.insert(&key, &value, 0).is_ok());
    record_metric(p, FRAGMENT_FAMILY_IPV6, decision.metric());
    if decision.drop_reason() != 0 {
        p.drop_reason = decision.drop_reason();
    }
    decision
}
