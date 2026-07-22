use crate::common::{
    fragment_authority_drop_reason, fragment_context_flags_for_l4, fragment_context_l4_proto,
    fragment_first_observation_metric, fragment_install_result, fragment_metric_for_drop_reason,
    fragment_metric_index, fragment_resolve_decision, fragment_tracking_required,
    FragmentContextKey4, FragmentContextKey6, FragmentContextValue, FragmentInstallDecision,
    FragmentKind, PipelineCtx, DROP_FRAGMENT_CONTEXT_INVALID, DROP_FRAGMENT_EXPIRY_OVERFLOW,
    FRAGMENT_CONTEXT_VERSION, FRAGMENT_FAMILY_IPV4, FRAGMENT_FAMILY_IPV6,
    FRAGMENT_METRIC_EXPIRY_OVERFLOW, FRAGMENT_METRIC_INVALID_L4, FRAGMENT_METRIC_NON_INITIAL,
};
use crate::maps::{
    FRAGMENT_CONFIG, FRAGMENT_EPOCH, FRAGMENT_METRICS, FRAG_CONTEXT_V4, FRAG_CONTEXT_V6,
};
use crate::parser::PacketInfo;
use aria_ebpf_abi::FragmentEpochValue;

const FRAGMENT_CONFIG_KEY: u32 = 0;

pub enum ResolveOutcome {
    NotRequired,
    Resolved(u8),
    Drop,
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
    let config = FRAGMENT_CONFIG.get(&FRAGMENT_CONFIG_KEY).copied();
    let epoch = packet_epoch(p);
    let value = FRAG_CONTEXT_V4.get(&key).copied();
    let decision = fragment_resolve_decision(
        p.tap_id,
        false,
        config.as_ref(),
        epoch.as_ref(),
        value.as_ref(),
        p.acl_bank_snapshot,
        p.now,
        info.fragment_offset,
    );
    record_metric(p, FRAGMENT_FAMILY_IPV4, decision.metric());
    if decision.drop_reason() != 0 {
        p.drop_reason = decision.drop_reason();
        return ResolveOutcome::Drop;
    }

    let value = match value {
        Some(value) => value,
        None => {
            p.drop_reason = DROP_FRAGMENT_CONTEXT_INVALID;
            return ResolveOutcome::Drop;
        }
    };
    let proto = match fragment_context_l4_proto(&value) {
        Some(proto) => proto,
        None => {
            p.drop_reason = DROP_FRAGMENT_CONTEXT_INVALID;
            return ResolveOutcome::Drop;
        }
    };
    info.src_port = value.src_port;
    info.dst_port = value.dst_port;
    ResolveOutcome::Resolved(proto)
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
    let config = FRAGMENT_CONFIG.get(&FRAGMENT_CONFIG_KEY).copied();
    let epoch = packet_epoch(p);
    let value = FRAG_CONTEXT_V6.get(&key).copied();
    let decision = fragment_resolve_decision(
        p.tap_id,
        true,
        config.as_ref(),
        epoch.as_ref(),
        value.as_ref(),
        p.acl_bank_snapshot,
        p.now,
        info.fragment_offset,
    );
    record_metric(p, FRAGMENT_FAMILY_IPV6, decision.metric());
    if decision.drop_reason() != 0 {
        p.drop_reason = decision.drop_reason();
        return ResolveOutcome::Drop;
    }

    let value = match value {
        Some(value) => value,
        None => {
            p.drop_reason = DROP_FRAGMENT_CONTEXT_INVALID;
            return ResolveOutcome::Drop;
        }
    };
    let proto = match fragment_context_l4_proto(&value) {
        Some(proto) => proto,
        None => {
            p.drop_reason = DROP_FRAGMENT_CONTEXT_INVALID;
            return ResolveOutcome::Drop;
        }
    };
    info.src_port = value.src_port;
    info.dst_port = value.dst_port;
    ResolveOutcome::Resolved(proto)
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
    let config = FRAGMENT_CONFIG.get(&FRAGMENT_CONFIG_KEY).copied();
    let epoch = packet_epoch(p);
    let authority =
        fragment_authority_drop_reason(p.tap_id, false, config.as_ref(), epoch.as_ref());
    if authority != 0 {
        p.drop_reason = authority;
        record_metric(
            p,
            FRAGMENT_FAMILY_IPV4,
            fragment_metric_for_drop_reason(authority),
        );
        return fragment_install_result(false);
    }
    let config = match config {
        Some(config) => config,
        None => return fragment_install_result(false),
    };
    let epoch = match epoch {
        Some(epoch) => epoch,
        None => return fragment_install_result(false),
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
    let config = FRAGMENT_CONFIG.get(&FRAGMENT_CONFIG_KEY).copied();
    let epoch = packet_epoch(p);
    let authority = fragment_authority_drop_reason(p.tap_id, true, config.as_ref(), epoch.as_ref());
    if authority != 0 {
        p.drop_reason = authority;
        record_metric(
            p,
            FRAGMENT_FAMILY_IPV6,
            fragment_metric_for_drop_reason(authority),
        );
        return fragment_install_result(false);
    }
    let config = match config {
        Some(config) => config,
        None => return fragment_install_result(false),
    };
    let epoch = match epoch {
        Some(epoch) => epoch,
        None => return fragment_install_result(false),
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
