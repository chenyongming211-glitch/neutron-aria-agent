#![no_std]
#![no_main]

use aya_ebpf::bindings::__sk_buff;
use aya_ebpf::helpers::bpf_ktime_get_ns;
use aya_ebpf::macros::{classifier, uprobe, uretprobe, xdp};
use aya_ebpf::maps::lpm_trie::Key;
use aya_ebpf::maps::LpmTrie;
use aya_ebpf::programs::{ProbeContext, RetProbeContext, TcContext, XdpContext};
use aya_ebpf::EbpfContext;

mod common;
mod conntrack;
mod ct_contract;
mod drops;
mod fragment;
mod kernel_drops;
mod maps;
mod mirror;
mod parser;
mod policy;
mod qos;
mod runtime;
mod ssl;
mod stats;
mod tcprt;
mod trace;

use common::{
    acl_banked_tap_id, fragment_ct_create_point, set_fragment_resolve_drop_ids, CtKey4, CtKey6,
    FragmentCtCreatePoint, FragmentInstallDecision, FragmentKind, PipelineCtx,
    CT_CONTRACT_FAMILY_IPV4, CT_CONTRACT_FAMILY_IPV6, CT_CONTRACT_HOOK_TC_EGRESS,
    CT_CONTRACT_HOOK_TC_INGRESS, CT_CONTRACT_REASON_CT_DISABLED, CT_CONTRACT_REASON_CT_HIT,
    CT_CONTRACT_REASON_CT_MISS, CT_CONTRACT_REASON_STALE_BANK, DIR_EGRESS, DIR_INGRESS,
    DROP_FRAGMENT_INVALID_L4, DROP_MALFORMED_IP, DROP_QOS_EGRESS, DROP_QOS_INGRESS, FLAG_ACL_ON,
    FLAG_CT_HIT, FLAG_CT_STALE_BANK, FLAG_IS_FORWARD, FLAG_MIRROR_ON, FLAG_POLICY_HIT,
    FLAG_QOS_ON, FLAG_TCPRT_ON, FLAG_TRACING, IPPROTO_TCP, TAP_ID_UNASSIGNED,
    TRACE_RESULT_DROP_ACL, TRACE_RESULT_DROP_ACL_DEFAULT, TRACE_RESULT_DROP_ACL_PORT,
    TRACE_RESULT_DROP_FRAGMENT, TRACE_RESULT_DROP_QOS, TRACE_RESULT_PASS, TRACE_TC_DROP,
    TRACE_TC_EGRESS, TRACE_TC_INGRESS, XDP_PASS,
};
use conntrack::{CtLookupResult, CtMissReason};
use maps::{
    ACL_DST_IPV4_TRIE, ACL_DST_IPV6_TRIE, ACL_SRC_IPV4_TRIE, ACL_SRC_IPV6_TRIE, DST_IPV4_TRIE,
    DST_IPV6_TRIE, SRC_IPV4_TRIE, SRC_IPV6_TRIE,
};

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

const TC_ACT_OK: i32 = 0;
const TC_ACT_SHOT: i32 = 2;

// --- XDP Ingress ---

#[xdp]
pub fn xdp_firewall(ctx: XdpContext) -> u32 {
    let data = ctx.data();
    let data_end = ctx.data_end();
    let frame_len = data_end - data;
    let pkt_len = frame_len as u32;
    unsafe {
        let info_ptr = match maps::PKT_SCRATCH.get_ptr_mut(0) {
            Some(p) => p,
            None => return XDP_PASS,
        };
        if !parser::parse_eth_ipv4(data, data_end, frame_len, 0, info_ptr)
            && !parser::parse_eth_ipv6(data, data_end, frame_len, 0, info_ptr)
        {
            return XDP_PASS;
        }
        let pipe = match maps::PIPE_SCRATCH.get_ptr_mut(0) {
            Some(p) => p,
            None => return XDP_PASS,
        };
        (*pipe).pkt_len = pkt_len;
        (*pipe).tap_id = TAP_ID_UNASSIGNED;
        (*pipe).direction = DIR_INGRESS;
        (*pipe).action = XDP_PASS;
        (*pipe).flags = 0;
        (*pipe).ct_state = 0;
        (*pipe).drop_reason = 0;
        (*pipe).matched_bank = 0;
        match try_xdp_firewall(&ctx, info_ptr, pipe) {
            Ok(ret) => ret,
            Err(_) => XDP_PASS,
        }
    }
}

#[inline(never)]
unsafe fn try_xdp_firewall(
    _ctx: &XdpContext,
    _info: *const parser::PacketInfo,
    pipe: *mut PipelineCtx,
) -> Result<u32, ()> {
    let p = &mut *pipe;
    // Future independent DDoS processing belongs before this boundary.
    p.action = XDP_PASS;
    Ok(XDP_PASS)
}

// --- TC Egress ---

#[classifier]
pub fn tc_egress(ctx: TcContext) -> i32 {
    let pkt_len = ctx.len();
    unsafe {
        let family = parser::ethernet_ip_family(ctx.data(), ctx.data_end(), 0);
        if family == 0 {
            try_raw_global_mirror_tc(&ctx, DIR_EGRESS, pkt_len);
            return TC_ACT_OK;
        }
        let info_ptr = match maps::PKT_SCRATCH.get_ptr_mut(0) {
            Some(p) => p,
            None => return TC_ACT_OK,
        };
        let parse_failure = parse_tc_packet(&ctx, info_ptr, family);
        if parse_failure != 0 {
            let mut proto = 0;
            if parse_failure == DROP_FRAGMENT_INVALID_L4 {
                if let Some((invalid_family, invalid_proto)) =
                    parser::invalid_l4_failure(&*info_ptr)
                {
                    fragment::record_invalid_l4(invalid_family);
                    proto = invalid_proto;
                }
            }
            record_tc_parse_drop(&ctx, DIR_EGRESS, pkt_len, parse_failure, proto);
            return TC_ACT_SHOT;
        }
        let pipe = match maps::PIPE_SCRATCH.get_ptr_mut(0) {
            Some(p) => p,
            None => return TC_ACT_OK,
        };
        (*pipe).reset_for_tc_packet(pkt_len, DIR_EGRESS);
        match try_tc_egress(&ctx, info_ptr, pipe) {
            Ok(ret) => ret,
            Err(_) => TC_ACT_OK,
        }
    }
}

#[inline(never)]
unsafe fn try_tc_egress(
    ctx: &TcContext,
    info: *mut parser::PacketInfo,
    pipe: *mut PipelineCtx,
) -> Result<i32, ()> {
    let info = &mut *info;
    let p = &mut *pipe;

    p.now = bpf_ktime_get_ns();
    p.proto = info.proto;
    load_runtime_ctx_tc(ctx, p);
    fragment::snapshot_authority(p);
    load_feature_flags_tc(p, info);
    fragment::record_first_observation(info, p);

    if info.is_ipv6 {
        return Ok(try_tc_egress_v6(ctx, info, p));
    }

    Ok(try_tc_egress_v4(ctx, info, p))
}

#[inline(never)]
unsafe fn try_tc_egress_v4(
    ctx: &TcContext,
    info: &mut parser::PacketInfo,
    p: &mut PipelineCtx,
) -> i32 {
    match fragment::resolve_v4(info, p) {
        fragment::ResolveOutcome::NotRequired => {}
        fragment::ResolveOutcome::Resolved => {
            p.proto = info.proto;
            refresh_trace_flag_tc(p, info);
        }
        fragment::ResolveOutcome::Drop => {
            refresh_trace_flag_tc(p, info);
            phase_fragment_resolve_drop_v4_tc(ctx, info, p);
            return p.action as i32;
        }
    }
    let ct_key_ptr = match maps::CT_KEY4_SCRATCH.get_ptr_mut(maps::CT_KEY_PRIMARY_SLOT) {
        Some(ptr) => ptr,
        None => return TC_ACT_OK,
    };
    (*ct_key_ptr).tap_id = p.tap_id;
    (*ct_key_ptr).src_ip = info.src_ip;
    (*ct_key_ptr).dst_ip = info.dst_ip;
    (*ct_key_ptr).src_port = info.src_port;
    (*ct_key_ptr).dst_port = info.dst_port;
    (*ct_key_ptr).proto = p.proto;
    (*ct_key_ptr).pad = [0; 3];
    let ct_key = &*ct_key_ptr;
    let miss_reason = phase_ct_v4(info, p, ct_key);
    let ct_hit = (p.flags & FLAG_CT_HIT) != 0;
    let create_point = fragment_ct_create_point(info.fragment_kind);
    if ct_hit {
        phase_ct_fastpath_tc_egress_v4(ctx, info, p, ct_key);
    } else {
        phase_ct_miss_tc_egress_v4(ctx, info, p, miss_reason);
    }
    if p.action == TC_ACT_SHOT as u32 {
        return p.action as i32;
    }
    if !ct_hit && create_point == FragmentCtCreatePoint::AfterPolicyQos {
        phase_ct_create_v4(p, ct_key);
    }
    let install = fragment::install_allowed_v4(info, p);
    if install != FragmentInstallDecision::Pass {
        phase_fragment_drop_tc(ctx, info, p);
        return p.action as i32;
    }
    if !ct_hit && create_point == FragmentCtCreatePoint::AfterContextInstall {
        phase_ct_create_v4(p, ct_key);
    }
    stats::update_flow_stats_v4(ct_key, p.pkt_len, p.now);
    phase_post_accept_tc_egress(ctx, info, p);
    if (p.flags & FLAG_TCPRT_ON) != 0
        && p.proto == IPPROTO_TCP
        && info.fragment_kind != FragmentKind::NonInitial as u8
    {
        if ct_hit {
            if (p.flags & FLAG_IS_FORWARD) != 0 {
                tcprt::track_tcp_rt_v4(ct_key, info, p.now, true, false);
            } else {
                tcprt::track_tcp_rt_v4_rev(p.tap_id, info, p.now, false);
            }
        } else {
            tcprt::track_tcp_rt_v4_auto(p.tap_id, info, p.now, false);
        }
    }
    p.action as i32
}

#[inline(never)]
unsafe fn try_tc_egress_v6(
    ctx: &TcContext,
    info: &mut parser::PacketInfo,
    p: &mut PipelineCtx,
) -> i32 {
    match fragment::resolve_v6(info, p) {
        fragment::ResolveOutcome::NotRequired => {}
        fragment::ResolveOutcome::Resolved => {
            p.proto = info.proto;
            refresh_trace_flag_tc(p, info);
        }
        fragment::ResolveOutcome::Drop => {
            refresh_trace_flag_tc(p, info);
            phase_fragment_resolve_drop_v6_tc(ctx, info, p);
            return p.action as i32;
        }
    }
    let ct_key_ptr = match maps::CT_KEY6_SCRATCH.get_ptr_mut(maps::CT_KEY_PRIMARY_SLOT) {
        Some(ptr) => ptr,
        None => return TC_ACT_OK,
    };
    (*ct_key_ptr).tap_id = p.tap_id;
    (*ct_key_ptr).src_ip = info.src_ip_v6;
    (*ct_key_ptr).dst_ip = info.dst_ip_v6;
    (*ct_key_ptr).src_port = info.src_port;
    (*ct_key_ptr).dst_port = info.dst_port;
    (*ct_key_ptr).proto = p.proto;
    (*ct_key_ptr).pad = [0; 3];
    let ct_key = &*ct_key_ptr;
    let miss_reason = phase_ct_v6(info, p, ct_key);
    let ct_hit = (p.flags & FLAG_CT_HIT) != 0;
    let create_point = fragment_ct_create_point(info.fragment_kind);
    if ct_hit {
        phase_ct_fastpath_tc_egress_v6(ctx, info, p, ct_key);
    } else {
        phase_ct_miss_tc_egress_v6(ctx, info, p, miss_reason);
    }
    if p.action == TC_ACT_SHOT as u32 {
        return p.action as i32;
    }
    if !ct_hit && create_point == FragmentCtCreatePoint::AfterPolicyQos {
        phase_ct_create_v6(p, ct_key);
    }
    let install = fragment::install_allowed_v6(info, p);
    if install != FragmentInstallDecision::Pass {
        phase_fragment_drop_tc(ctx, info, p);
        return p.action as i32;
    }
    if !ct_hit && create_point == FragmentCtCreatePoint::AfterContextInstall {
        phase_ct_create_v6(p, ct_key);
    }
    stats::update_flow_stats_v6(ct_key, p.pkt_len, p.now);
    phase_post_accept_tc_egress(ctx, info, p);
    if (p.flags & FLAG_TCPRT_ON) != 0
        && p.proto == IPPROTO_TCP
        && info.fragment_kind != FragmentKind::NonInitial as u8
    {
        if ct_hit {
            if (p.flags & FLAG_IS_FORWARD) != 0 {
                tcprt::track_tcp_rt_v6(ct_key, info, p.now, true, false);
            } else {
                tcprt::track_tcp_rt_v6_rev(p.tap_id, info, p.now, false);
            }
        } else {
            tcprt::track_tcp_rt_v6_auto(p.tap_id, info, p.now, false);
        }
    }
    p.action as i32
}

// --- TC Ingress ---

#[classifier]
pub fn tc_ingress(ctx: TcContext) -> i32 {
    let pkt_len = ctx.len();
    unsafe {
        let family = parser::ethernet_ip_family(ctx.data(), ctx.data_end(), 0);
        if family == 0 {
            try_raw_global_mirror_tc(&ctx, DIR_INGRESS, pkt_len);
            return TC_ACT_OK;
        }
        let info_ptr = match maps::PKT_SCRATCH.get_ptr_mut(0) {
            Some(p) => p,
            None => return TC_ACT_OK,
        };
        let parse_failure = parse_tc_packet(&ctx, info_ptr, family);
        if parse_failure != 0 {
            let mut proto = 0;
            if parse_failure == DROP_FRAGMENT_INVALID_L4 {
                if let Some((invalid_family, invalid_proto)) =
                    parser::invalid_l4_failure(&*info_ptr)
                {
                    fragment::record_invalid_l4(invalid_family);
                    proto = invalid_proto;
                }
            }
            record_tc_parse_drop(&ctx, DIR_INGRESS, pkt_len, parse_failure, proto);
            return TC_ACT_SHOT;
        }
        let pipe = match maps::PIPE_SCRATCH.get_ptr_mut(0) {
            Some(p) => p,
            None => return TC_ACT_OK,
        };
        (*pipe).reset_for_tc_packet(pkt_len, DIR_INGRESS);
        match try_tc_ingress(&ctx, info_ptr, pipe) {
            Ok(ret) => ret,
            Err(_) => TC_ACT_OK,
        }
    }
}

#[inline(never)]
unsafe fn try_tc_ingress(
    ctx: &TcContext,
    info: *mut parser::PacketInfo,
    pipe: *mut PipelineCtx,
) -> Result<i32, ()> {
    let info = &mut *info;
    let p = &mut *pipe;

    p.now = bpf_ktime_get_ns();
    p.proto = info.proto;
    load_runtime_ctx_tc(ctx, p);
    fragment::snapshot_authority(p);
    load_feature_flags_tc(p, info);
    fragment::record_first_observation(info, p);

    if info.is_ipv6 {
        return Ok(try_tc_ingress_v6(ctx, info, p));
    }

    Ok(try_tc_ingress_v4(ctx, info, p))
}

#[inline(never)]
unsafe fn try_tc_ingress_v4(
    ctx: &TcContext,
    info: &mut parser::PacketInfo,
    p: &mut PipelineCtx,
) -> i32 {
    match fragment::resolve_v4(info, p) {
        fragment::ResolveOutcome::NotRequired => {}
        fragment::ResolveOutcome::Resolved => {
            p.proto = info.proto;
            refresh_trace_flag_tc(p, info);
        }
        fragment::ResolveOutcome::Drop => {
            refresh_trace_flag_tc(p, info);
            phase_fragment_resolve_drop_v4_tc(ctx, info, p);
            return p.action as i32;
        }
    }
    let ct_key_ptr = match maps::CT_KEY4_SCRATCH.get_ptr_mut(maps::CT_KEY_PRIMARY_SLOT) {
        Some(ptr) => ptr,
        None => return TC_ACT_OK,
    };
    (*ct_key_ptr).tap_id = p.tap_id;
    (*ct_key_ptr).src_ip = info.src_ip;
    (*ct_key_ptr).dst_ip = info.dst_ip;
    (*ct_key_ptr).src_port = info.src_port;
    (*ct_key_ptr).dst_port = info.dst_port;
    (*ct_key_ptr).proto = p.proto;
    (*ct_key_ptr).pad = [0; 3];
    let ct_key = &*ct_key_ptr;
    let miss_reason = phase_ct_v4(info, p, ct_key);
    let ct_hit = (p.flags & FLAG_CT_HIT) != 0;
    let create_point = fragment_ct_create_point(info.fragment_kind);
    if ct_hit {
        phase_ct_fastpath_tc_ingress_v4(ctx, info, p, ct_key);
    } else {
        phase_ct_miss_tc_ingress_v4(ctx, info, p, miss_reason);
    }
    if p.action == TC_ACT_SHOT as u32 {
        return p.action as i32;
    }
    if !ct_hit && create_point == FragmentCtCreatePoint::AfterPolicyQos {
        phase_ct_create_v4(p, ct_key);
    }
    let install = fragment::install_allowed_v4(info, p);
    if install != FragmentInstallDecision::Pass {
        phase_fragment_drop_tc(ctx, info, p);
        return p.action as i32;
    }
    if !ct_hit && create_point == FragmentCtCreatePoint::AfterContextInstall {
        phase_ct_create_v4(p, ct_key);
    }
    stats::update_flow_stats_v4(ct_key, p.pkt_len, p.now);
    phase_post_accept_tc_ingress(ctx, info, p);
    if (p.flags & FLAG_TCPRT_ON) != 0
        && p.proto == IPPROTO_TCP
        && info.fragment_kind != FragmentKind::NonInitial as u8
    {
        if ct_hit {
            if (p.flags & FLAG_IS_FORWARD) != 0 {
                tcprt::track_tcp_rt_v4(ct_key, info, p.now, true, true);
            } else {
                tcprt::track_tcp_rt_v4_rev(p.tap_id, info, p.now, true);
            }
        } else {
            tcprt::track_tcp_rt_v4_auto(p.tap_id, info, p.now, true);
        }
    }
    p.action as i32
}

#[inline(never)]
unsafe fn try_tc_ingress_v6(
    ctx: &TcContext,
    info: &mut parser::PacketInfo,
    p: &mut PipelineCtx,
) -> i32 {
    match fragment::resolve_v6(info, p) {
        fragment::ResolveOutcome::NotRequired => {}
        fragment::ResolveOutcome::Resolved => {
            p.proto = info.proto;
            refresh_trace_flag_tc(p, info);
        }
        fragment::ResolveOutcome::Drop => {
            refresh_trace_flag_tc(p, info);
            phase_fragment_resolve_drop_v6_tc(ctx, info, p);
            return p.action as i32;
        }
    }
    let ct_key_ptr = match maps::CT_KEY6_SCRATCH.get_ptr_mut(maps::CT_KEY_PRIMARY_SLOT) {
        Some(ptr) => ptr,
        None => return TC_ACT_OK,
    };
    (*ct_key_ptr).tap_id = p.tap_id;
    (*ct_key_ptr).src_ip = info.src_ip_v6;
    (*ct_key_ptr).dst_ip = info.dst_ip_v6;
    (*ct_key_ptr).src_port = info.src_port;
    (*ct_key_ptr).dst_port = info.dst_port;
    (*ct_key_ptr).proto = p.proto;
    (*ct_key_ptr).pad = [0; 3];
    let ct_key = &*ct_key_ptr;
    let miss_reason = phase_ct_v6(info, p, ct_key);
    let ct_hit = (p.flags & FLAG_CT_HIT) != 0;
    let create_point = fragment_ct_create_point(info.fragment_kind);
    if ct_hit {
        phase_ct_fastpath_tc_ingress_v6(ctx, info, p, ct_key);
    } else {
        phase_ct_miss_tc_ingress_v6(ctx, info, p, miss_reason);
    }
    if p.action == TC_ACT_SHOT as u32 {
        return p.action as i32;
    }
    if !ct_hit && create_point == FragmentCtCreatePoint::AfterPolicyQos {
        phase_ct_create_v6(p, ct_key);
    }
    let install = fragment::install_allowed_v6(info, p);
    if install != FragmentInstallDecision::Pass {
        phase_fragment_drop_tc(ctx, info, p);
        return p.action as i32;
    }
    if !ct_hit && create_point == FragmentCtCreatePoint::AfterContextInstall {
        phase_ct_create_v6(p, ct_key);
    }
    stats::update_flow_stats_v6(ct_key, p.pkt_len, p.now);
    phase_post_accept_tc_ingress(ctx, info, p);
    if (p.flags & FLAG_TCPRT_ON) != 0
        && p.proto == IPPROTO_TCP
        && info.fragment_kind != FragmentKind::NonInitial as u8
    {
        if ct_hit {
            if (p.flags & FLAG_IS_FORWARD) != 0 {
                tcprt::track_tcp_rt_v6(ct_key, info, p.now, true, true);
            } else {
                tcprt::track_tcp_rt_v6_rev(p.tap_id, info, p.now, true);
            }
        } else {
            tcprt::track_tcp_rt_v6_auto(p.tap_id, info, p.now, true);
        }
    }
    p.action as i32
}

// --- Helpers ---

#[inline(always)]
unsafe fn load_feature_flags_tc(p: &mut PipelineCtx, info: &parser::PacketInfo) {
    if qos::qos_enabled(p.tap_id) {
        p.flags |= FLAG_QOS_ON;
    }
    if tcprt::tcprt_enabled(p.tap_id) {
        p.flags |= FLAG_TCPRT_ON;
    }
    if policy::acl_enabled(p.tap_id) {
        p.flags |= FLAG_ACL_ON;
    }
    if mirror::mirror_enabled(p.tap_id) {
        p.flags |= FLAG_MIRROR_ON;
    }
    refresh_trace_flag_tc(p, info);
}

#[inline(always)]
unsafe fn refresh_trace_flag_tc(p: &mut PipelineCtx, info: &parser::PacketInfo) {
    p.flags &= !FLAG_TRACING;
    if trace::should_trace(p.tap_id, info, p.proto) {
        p.flags |= FLAG_TRACING;
    }
}

#[inline(always)]
unsafe fn resolve_tap_id_for_ifindex(ifindex: u32) -> u32 {
    if ifindex == 0 {
        return TAP_ID_UNASSIGNED;
    }
    if let Some(ctx) = maps::IFACE_CTX_MAP.get(&ifindex) {
        ctx.tap_id
    } else {
        TAP_ID_UNASSIGNED
    }
}

#[inline(always)]
unsafe fn load_runtime_ctx_tc(ctx: &TcContext, p: &mut PipelineCtx) {
    let skb = ctx.as_ptr() as *const __sk_buff;
    p.tap_id = resolve_tap_id_for_ifindex((*skb).ifindex);
}

#[inline(always)]
unsafe fn parse_tc_packet(ctx: &TcContext, out: *mut parser::PacketInfo, family: u8) -> u8 {
    let wire_len = ctx.len();
    let mut data = ctx.data();
    let mut data_end = ctx.data_end();
    let pull_len = parser::bounded_tc_pull_len(wire_len);
    if pull_len == 0 {
        return DROP_MALFORMED_IP;
    }
    if data_end - data < pull_len as usize {
        if ctx.pull_data(pull_len).is_err() {
            return DROP_MALFORMED_IP;
        }
        data = ctx.data();
        data_end = ctx.data_end();
    }
    if parse_tc_family(data, data_end, wire_len as usize, out, family) {
        0
    } else {
        parser::tc_parse_failure_reason(&*out)
    }
}

#[inline(always)]
unsafe fn parse_tc_family(
    data: usize,
    data_end: usize,
    wire_len: usize,
    out: *mut parser::PacketInfo,
    family: u8,
) -> bool {
    if family == 4 {
        parser::parse_eth_ipv4(data, data_end, wire_len, 0, out)
    } else {
        parser::parse_eth_ipv6(data, data_end, wire_len, 0, out)
    }
}

#[inline(always)]
unsafe fn record_tc_parse_drop(
    ctx: &TcContext,
    direction: u8,
    pkt_len: u32,
    reason: u8,
    proto: u8,
) {
    let skb = ctx.as_ptr() as *const __sk_buff;
    drops::record_drop(&drops::DropArgs {
        tap_id: resolve_tap_id_for_ifindex((*skb).ifindex),
        src_id: 0,
        dst_id: 0,
        pkt_len,
        now: bpf_ktime_get_ns(),
        reason,
        direction,
        proto,
        _pad: 0,
    });
}

#[inline(always)]
unsafe fn try_raw_global_mirror_tc(ctx: &TcContext, direction: u8, pkt_len: u32) {
    let skb = ctx.as_ptr() as *mut __sk_buff;
    let tap_id = resolve_tap_id_for_ifindex((*skb).ifindex);
    if mirror::mirror_enabled(tap_id) {
        mirror::try_global_mirror_tc(skb, tap_id, direction, pkt_len);
    }
}

#[inline(always)]
unsafe fn set_matched(p: &mut PipelineCtx, m: &conntrack::MatchedPolicy) {
    p.matched_src_id = m.src_id;
    p.matched_dst_id = m.dst_id;
    p.matched_proto = m.proto;
    p.matched_direction = m.direction;
    p.matched_bank = m.bank;
    if m.policy_hit {
        p.flags |= FLAG_POLICY_HIT;
    } else {
        p.flags &= !FLAG_POLICY_HIT;
    }
}

#[inline(always)]
fn get_matched(p: &PipelineCtx) -> conntrack::MatchedPolicy {
    conntrack::MatchedPolicy {
        tap_id: p.tap_id,
        src_id: p.matched_src_id,
        dst_id: p.matched_dst_id,
        proto: p.matched_proto,
        direction: p.matched_direction,
        bank: p.matched_bank,
        policy_hit: (p.flags & FLAG_POLICY_HIT) != 0,
    }
}

/// Inline helper: emit a trace event from PipelineCtx.
#[inline(always)]
unsafe fn do_trace<C: EbpfContext>(
    ctx: &C,
    info: &parser::PacketInfo,
    p: &PipelineCtx,
    hook: u8,
    result: u8,
) {
    trace::trace_event(
        ctx,
        p.tap_id,
        info,
        &trace::TraceArgs {
            hook,
            result,
            direction: p.direction,
            ct_state: p.ct_state,
            drop_reason: p.drop_reason,
            proto: p.proto,
            _pad: [0; 2],
            src_id: p.src_id,
            dst_id: p.dst_id,
            pkt_len: p.pkt_len,
            now: p.now,
        },
    );
}

#[inline(always)]
fn trace_result_from_drop_reason(drop_reason: u8) -> u8 {
    match drop_reason {
        1 => TRACE_RESULT_DROP_ACL,
        2 => TRACE_RESULT_DROP_ACL_PORT,
        3 => TRACE_RESULT_DROP_ACL_DEFAULT,
        _ => TRACE_RESULT_DROP_ACL,
    }
}

/// Inline helper: record a drop from PipelineCtx.
#[inline(always)]
unsafe fn do_drop(p: &PipelineCtx) {
    drops::record_drop(&drops::DropArgs {
        tap_id: p.tap_id,
        reason: p.drop_reason,
        direction: p.direction,
        proto: p.proto,
        src_id: p.src_id,
        dst_id: p.dst_id,
        pkt_len: p.pkt_len,
        now: p.now,
        _pad: 0,
    });
}

#[inline(always)]
unsafe fn phase_fragment_drop_tc(ctx: &TcContext, info: &parser::PacketInfo, p: &mut PipelineCtx) {
    p.action = TC_ACT_SHOT as u32;
    do_drop(p);
    if (p.flags & FLAG_TRACING) != 0 {
        do_trace(ctx, info, p, TRACE_TC_DROP, TRACE_RESULT_DROP_FRAGMENT);
    }
}

unsafe fn lookup_ipv4(map: &LpmTrie<[u8; 8], u32>, tap_id: u32, ip: u32) -> Option<u32> {
    let mut bytes = [0u8; 8];
    bytes[..4].copy_from_slice(&tap_id.to_be_bytes());
    bytes[4..].copy_from_slice(&ip.to_be_bytes());
    let key = Key::new(64, bytes);
    map.get(&key).copied()
}

unsafe fn lookup_ipv6(map: &LpmTrie<[u8; 20], u32>, tap_id: u32, ip: [u8; 16]) -> Option<u32> {
    let mut bytes = [0u8; 20];
    bytes[..4].copy_from_slice(&tap_id.to_be_bytes());
    bytes[4..].copy_from_slice(&ip);
    let key = Key::new(160, bytes);
    map.get(&key).copied()
}

#[inline(never)]
unsafe fn phase_fragment_resolve_drop_v4_tc(
    ctx: &TcContext,
    info: &parser::PacketInfo,
    p: &mut PipelineCtx,
) {
    let src_id = lookup_ipv4(&SRC_IPV4_TRIE, p.tap_id, info.src_ip);
    let dst_id = lookup_ipv4(&DST_IPV4_TRIE, p.tap_id, info.dst_ip);
    set_fragment_resolve_drop_ids(p, src_id, dst_id);
    phase_fragment_drop_tc(ctx, info, p);
}

#[inline(never)]
unsafe fn phase_fragment_resolve_drop_v6_tc(
    ctx: &TcContext,
    info: &parser::PacketInfo,
    p: &mut PipelineCtx,
) {
    let src_id = lookup_ipv6(&SRC_IPV6_TRIE, p.tap_id, info.src_ip_v6);
    let dst_id = lookup_ipv6(&DST_IPV6_TRIE, p.tap_id, info.dst_ip_v6);
    set_fragment_resolve_drop_ids(p, src_id, dst_id);
    phase_fragment_drop_tc(ctx, info, p);
}

// --- Phase functions (each is #[inline(never)] to isolate stack frames) ---

/// Phase: CT lookup for IPv4. Sets p.ct_state, p.matched_*, p.flags (CT_HIT, IS_FORWARD).
#[inline(never)]
unsafe fn phase_ct_v4(
    _info: &parser::PacketInfo,
    p: &mut PipelineCtx,
    ct_key: &CtKey4,
) -> Option<CtMissReason> {
    let validate_acl_bank = if (p.flags & FLAG_ACL_ON) != 0 { 1 } else { 0 };
    let expected_acl_bank = p.acl_bank_snapshot;
    match conntrack::ct_lookup_v4(
        ct_key,
        p.now,
        p.pkt_len,
        validate_acl_bank,
        expected_acl_bank,
    ) {
        CtLookupResult::Hit(matched, is_forward, state) => {
            p.ct_state = state;
            p.flags &= !(FLAG_CT_HIT | FLAG_IS_FORWARD | FLAG_POLICY_HIT | FLAG_CT_STALE_BANK);
            p.flags |= FLAG_CT_HIT;
            if is_forward {
                p.flags |= FLAG_IS_FORWARD;
            }
            set_matched(p, &matched);
            None
        }
        CtLookupResult::Miss(reason) => {
            p.ct_state = 0;
            p.flags &= !(FLAG_CT_HIT | FLAG_IS_FORWARD | FLAG_POLICY_HIT | FLAG_CT_STALE_BANK);
            if let CtMissReason::StaleBank = reason {
                p.flags |= FLAG_CT_STALE_BANK;
            }
            Some(reason)
        }
    }
}

/// Phase: CT lookup for IPv6.
#[inline(never)]
unsafe fn phase_ct_v6(
    _info: &parser::PacketInfo,
    p: &mut PipelineCtx,
    ct_key: &CtKey6,
) -> Option<CtMissReason> {
    let validate_acl_bank = if (p.flags & FLAG_ACL_ON) != 0 { 1 } else { 0 };
    let expected_acl_bank = p.acl_bank_snapshot;
    match conntrack::ct_lookup_v6(
        ct_key,
        p.now,
        p.pkt_len,
        validate_acl_bank,
        expected_acl_bank,
    ) {
        CtLookupResult::Hit(matched, is_forward, state) => {
            p.ct_state = state;
            p.flags &= !(FLAG_CT_HIT | FLAG_IS_FORWARD | FLAG_POLICY_HIT | FLAG_CT_STALE_BANK);
            p.flags |= FLAG_CT_HIT;
            if is_forward {
                p.flags |= FLAG_IS_FORWARD;
            }
            set_matched(p, &matched);
            None
        }
        CtLookupResult::Miss(reason) => {
            p.ct_state = 0;
            p.flags &= !(FLAG_CT_HIT | FLAG_IS_FORWARD | FLAG_POLICY_HIT | FLAG_CT_STALE_BANK);
            if let CtMissReason::StaleBank = reason {
                p.flags |= FLAG_CT_STALE_BANK;
            }
            Some(reason)
        }
    }
}

#[inline(always)]
fn need_tc_post_ids(p: &PipelineCtx) -> bool {
    (p.flags & (FLAG_QOS_ON | FLAG_MIRROR_ON | FLAG_TRACING)) != 0
        || stats::monitoring_enabled(p.tap_id)
}

#[inline(always)]
unsafe fn load_packet_ids_v4(info: &parser::PacketInfo, p: &mut PipelineCtx) {
    p.src_id = lookup_ipv4(&SRC_IPV4_TRIE, p.tap_id, info.src_ip).unwrap_or(0);
    p.dst_id = lookup_ipv4(&DST_IPV4_TRIE, p.tap_id, info.dst_ip).unwrap_or(0);
}

#[inline(always)]
unsafe fn load_packet_ids_v6(info: &parser::PacketInfo, p: &mut PipelineCtx) {
    p.src_id = lookup_ipv6(&SRC_IPV6_TRIE, p.tap_id, info.src_ip_v6).unwrap_or(0);
    p.dst_id = lookup_ipv6(&DST_IPV6_TRIE, p.tap_id, info.dst_ip_v6).unwrap_or(0);
}

#[inline(always)]
unsafe fn load_acl_packet_ids_v4(info: &parser::PacketInfo, p: &mut PipelineCtx) {
    let bank = p.acl_bank_snapshot;
    let lpm_tap_id = acl_banked_tap_id(p.tap_id, bank);
    p.matched_bank = bank;
    p.src_id = lookup_ipv4(&ACL_SRC_IPV4_TRIE, lpm_tap_id, info.src_ip).unwrap_or(0);
    p.dst_id = lookup_ipv4(&ACL_DST_IPV4_TRIE, lpm_tap_id, info.dst_ip).unwrap_or(0);
}

#[inline(always)]
unsafe fn load_acl_packet_ids_v6(info: &parser::PacketInfo, p: &mut PipelineCtx) {
    let bank = p.acl_bank_snapshot;
    let lpm_tap_id = acl_banked_tap_id(p.tap_id, bank);
    p.matched_bank = bank;
    p.src_id = lookup_ipv6(&ACL_SRC_IPV6_TRIE, lpm_tap_id, info.src_ip_v6).unwrap_or(0);
    p.dst_id = lookup_ipv6(&ACL_DST_IPV6_TRIE, lpm_tap_id, info.dst_ip_v6).unwrap_or(0);
}

#[inline(always)]
unsafe fn should_apply_ingress_qos(p: &PipelineCtx) -> bool {
    // Ingress QoS is a standalone feature. TC ingress can enforce policing
    // on both CT hits and CT-miss fallback paths after doing its own ID lookup.
    (p.flags & FLAG_QOS_ON) != 0
}

#[inline(always)]
unsafe fn should_record_tc_ct_contract(p: &PipelineCtx, reason: u8) -> bool {
    reason == CT_CONTRACT_REASON_STALE_BANK || (p.flags & FLAG_TRACING) != 0
}

#[inline(always)]
fn ct_miss_contract_reason(reason: Option<CtMissReason>) -> u8 {
    match reason {
        Some(CtMissReason::Disabled) => CT_CONTRACT_REASON_CT_DISABLED,
        Some(CtMissReason::StaleBank) => CT_CONTRACT_REASON_STALE_BANK,
        Some(CtMissReason::NotFound) | Some(CtMissReason::Expired) | None => {
            CT_CONTRACT_REASON_CT_MISS
        }
    }
}

#[inline(always)]
unsafe fn record_tc_ct_contract(p: &PipelineCtx, hook: u8, family: u8, reason: u8) {
    if !should_record_tc_ct_contract(p, reason) {
        return;
    }
    ct_contract::record_event(&ct_contract::CtContractArgs {
        tap_id: p.tap_id,
        pkt_len: p.pkt_len,
        now: p.now,
        hook,
        family,
        reason,
        _pad: 0,
    });
}

#[inline(always)]
unsafe fn phase_qos_ingress_tc(ctx: &TcContext, info: &parser::PacketInfo, p: &mut PipelineCtx) {
    if !qos::apply_qos_ingress(p.tap_id, p.src_id, p.dst_id, p.pkt_len, p.now) {
        p.drop_reason = DROP_QOS_INGRESS;
        p.action = TC_ACT_SHOT as u32;
        do_drop(p);
        if (p.flags & FLAG_TRACING) != 0 {
            do_trace(ctx, info, p, TRACE_TC_DROP, TRACE_RESULT_DROP_QOS);
        }
    }
}

#[inline(always)]
unsafe fn phase_post_accept_tc_ingress(
    ctx: &TcContext,
    info: &parser::PacketInfo,
    p: &mut PipelineCtx,
) {
    if stats::monitoring_enabled(p.tap_id) {
        stats::update_group_stats(p.tap_id, p.src_id, DIR_EGRESS, p.pkt_len);
        stats::update_group_stats(p.tap_id, p.dst_id, DIR_INGRESS, p.pkt_len);
    }
    if (p.flags & FLAG_MIRROR_ON) != 0 {
        let skb = ctx.as_ptr() as *mut __sk_buff;
        mirror::try_mirror_tc(
            skb,
            p.tap_id,
            p.src_id,
            p.dst_id,
            p.proto,
            DIR_INGRESS,
            p.pkt_len,
        );
    }
    if (p.flags & FLAG_TRACING) != 0 {
        do_trace(ctx, info, p, TRACE_TC_INGRESS, TRACE_RESULT_PASS);
    }
    p.action = TC_ACT_OK as u32;
}

#[inline(always)]
unsafe fn phase_post_accept_tc_egress(
    ctx: &TcContext,
    info: &parser::PacketInfo,
    p: &mut PipelineCtx,
) {
    stats::update_group_stats(p.tap_id, p.src_id, DIR_EGRESS, p.pkt_len);
    stats::update_group_stats(p.tap_id, p.dst_id, DIR_INGRESS, p.pkt_len);
    if (p.flags & FLAG_MIRROR_ON) != 0 {
        let skb = ctx.as_ptr() as *mut __sk_buff;
        mirror::try_mirror_tc(
            skb, p.tap_id, p.src_id, p.dst_id, p.proto, DIR_EGRESS, p.pkt_len,
        );
    }
    if (p.flags & FLAG_TRACING) != 0 {
        do_trace(ctx, info, p, TRACE_TC_EGRESS, TRACE_RESULT_PASS);
    }
    p.action = TC_ACT_OK as u32;
}

/// CT fast-path for TC ingress IPv4.
#[inline(never)]
unsafe fn phase_ct_fastpath_tc_ingress_v4(
    ctx: &TcContext,
    info: &parser::PacketInfo,
    p: &mut PipelineCtx,
    _ct_key: &CtKey4,
) {
    record_tc_ct_contract(
        p,
        CT_CONTRACT_HOOK_TC_INGRESS,
        CT_CONTRACT_FAMILY_IPV4,
        CT_CONTRACT_REASON_CT_HIT,
    );
    if stats::monitoring_enabled(p.tap_id) && (p.flags & FLAG_POLICY_HIT) != 0 {
        let matched = get_matched(p);
        stats::update_rule_stats(&matched.to_policy_key(), p.pkt_len, false);
    }
    if need_tc_post_ids(p) {
        load_packet_ids_v4(info, p);
    }
    if should_apply_ingress_qos(p) {
        phase_qos_ingress_tc(ctx, info, p);
        if p.action == TC_ACT_SHOT as u32 {
            return;
        }
    }
}

/// CT fast-path for TC ingress IPv6.
#[inline(never)]
unsafe fn phase_ct_fastpath_tc_ingress_v6(
    ctx: &TcContext,
    info: &parser::PacketInfo,
    p: &mut PipelineCtx,
    _ct_key: &CtKey6,
) {
    record_tc_ct_contract(
        p,
        CT_CONTRACT_HOOK_TC_INGRESS,
        CT_CONTRACT_FAMILY_IPV6,
        CT_CONTRACT_REASON_CT_HIT,
    );
    if stats::monitoring_enabled(p.tap_id) && (p.flags & FLAG_POLICY_HIT) != 0 {
        let matched = get_matched(p);
        stats::update_rule_stats(&matched.to_policy_key(), p.pkt_len, false);
    }
    if need_tc_post_ids(p) {
        load_packet_ids_v6(info, p);
    }
    if should_apply_ingress_qos(p) {
        phase_qos_ingress_tc(ctx, info, p);
        if p.action == TC_ACT_SHOT as u32 {
            return;
        }
    }
}

/// CT miss fallback for TC ingress IPv4.
#[inline(never)]
unsafe fn phase_ct_miss_tc_ingress_v4(
    ctx: &TcContext,
    info: &parser::PacketInfo,
    p: &mut PipelineCtx,
    miss_reason: Option<CtMissReason>,
) {
    record_tc_ct_contract(
        p,
        CT_CONTRACT_HOOK_TC_INGRESS,
        CT_CONTRACT_FAMILY_IPV4,
        ct_miss_contract_reason(miss_reason),
    );
    if (p.flags & FLAG_ACL_ON) != 0 {
        load_acl_packet_ids_v4(info, p);
        phase_policy_tc(ctx, info, p);
        if p.action == TC_ACT_SHOT as u32 {
            return;
        }
    }
    if need_tc_post_ids(p) {
        load_packet_ids_v4(info, p);
    }
    if should_apply_ingress_qos(p) {
        phase_qos_ingress_tc(ctx, info, p);
        if p.action == TC_ACT_SHOT as u32 {
            return;
        }
    }
}

/// CT miss fallback for TC ingress IPv6.
#[inline(never)]
unsafe fn phase_ct_miss_tc_ingress_v6(
    ctx: &TcContext,
    info: &parser::PacketInfo,
    p: &mut PipelineCtx,
    miss_reason: Option<CtMissReason>,
) {
    record_tc_ct_contract(
        p,
        CT_CONTRACT_HOOK_TC_INGRESS,
        CT_CONTRACT_FAMILY_IPV6,
        ct_miss_contract_reason(miss_reason),
    );
    if (p.flags & FLAG_ACL_ON) != 0 {
        load_acl_packet_ids_v6(info, p);
        phase_policy_tc(ctx, info, p);
        if p.action == TC_ACT_SHOT as u32 {
            return;
        }
    }
    if need_tc_post_ids(p) {
        load_packet_ids_v6(info, p);
    }
    if should_apply_ingress_qos(p) {
        phase_qos_ingress_tc(ctx, info, p);
        if p.action == TC_ACT_SHOT as u32 {
            return;
        }
    }
}

#[inline(never)]
unsafe fn phase_ct_create_v4(p: &PipelineCtx, ct_key: &CtKey4) {
    let matched = get_matched(p);
    let _ = conntrack::ct_create_v4(
        ct_key,
        p.now,
        p.pkt_len,
        &matched,
        (p.flags & FLAG_ACL_ON) != 0,
    );
}

#[inline(never)]
unsafe fn phase_ct_create_v6(p: &PipelineCtx, ct_key: &CtKey6) {
    let matched = get_matched(p);
    let _ = conntrack::ct_create_v6(
        ct_key,
        p.now,
        p.pkt_len,
        &matched,
        (p.flags & FLAG_ACL_ON) != 0,
    );
}

/// CT fast-path for TC egress IPv4.
#[inline(never)]
unsafe fn phase_ct_fastpath_tc_egress_v4(
    ctx: &TcContext,
    info: &parser::PacketInfo,
    p: &mut PipelineCtx,
    _ct_key: &CtKey4,
) {
    record_tc_ct_contract(
        p,
        CT_CONTRACT_HOOK_TC_EGRESS,
        CT_CONTRACT_FAMILY_IPV4,
        CT_CONTRACT_REASON_CT_HIT,
    );
    if stats::monitoring_enabled(p.tap_id) && (p.flags & FLAG_POLICY_HIT) != 0 {
        let matched = get_matched(p);
        stats::update_rule_stats(&matched.to_policy_key(), p.pkt_len, false);
    }
    if need_tc_post_ids(p) {
        load_packet_ids_v4(info, p);
    }
    if (p.flags & FLAG_QOS_ON) != 0 {
        phase_qos_egress_tc(ctx, info, p);
        if p.action == TC_ACT_SHOT as u32 {
            return;
        }
    }
}

/// CT fast-path for TC egress IPv6.
#[inline(never)]
unsafe fn phase_ct_fastpath_tc_egress_v6(
    ctx: &TcContext,
    info: &parser::PacketInfo,
    p: &mut PipelineCtx,
    _ct_key: &CtKey6,
) {
    record_tc_ct_contract(
        p,
        CT_CONTRACT_HOOK_TC_EGRESS,
        CT_CONTRACT_FAMILY_IPV6,
        CT_CONTRACT_REASON_CT_HIT,
    );
    if stats::monitoring_enabled(p.tap_id) && (p.flags & FLAG_POLICY_HIT) != 0 {
        let matched = get_matched(p);
        stats::update_rule_stats(&matched.to_policy_key(), p.pkt_len, false);
    }
    if need_tc_post_ids(p) {
        load_packet_ids_v6(info, p);
    }
    if (p.flags & FLAG_QOS_ON) != 0 {
        phase_qos_egress_tc(ctx, info, p);
        if p.action == TC_ACT_SHOT as u32 {
            return;
        }
    }
}

/// CT miss fallback for TC egress IPv4.
#[inline(never)]
unsafe fn phase_ct_miss_tc_egress_v4(
    ctx: &TcContext,
    info: &parser::PacketInfo,
    p: &mut PipelineCtx,
    miss_reason: Option<CtMissReason>,
) {
    record_tc_ct_contract(
        p,
        CT_CONTRACT_HOOK_TC_EGRESS,
        CT_CONTRACT_FAMILY_IPV4,
        ct_miss_contract_reason(miss_reason),
    );
    if (p.flags & FLAG_ACL_ON) != 0 {
        load_acl_packet_ids_v4(info, p);
        phase_policy_tc(ctx, info, p);
        if p.action == TC_ACT_SHOT as u32 {
            return;
        }
    }
    if need_tc_post_ids(p) {
        load_packet_ids_v4(info, p);
    }
    if (p.flags & FLAG_QOS_ON) != 0 {
        phase_qos_egress_tc(ctx, info, p);
        if p.action == TC_ACT_SHOT as u32 {
            return;
        }
    }
}

/// CT miss fallback for TC egress IPv6.
#[inline(never)]
unsafe fn phase_ct_miss_tc_egress_v6(
    ctx: &TcContext,
    info: &parser::PacketInfo,
    p: &mut PipelineCtx,
    miss_reason: Option<CtMissReason>,
) {
    record_tc_ct_contract(
        p,
        CT_CONTRACT_HOOK_TC_EGRESS,
        CT_CONTRACT_FAMILY_IPV6,
        ct_miss_contract_reason(miss_reason),
    );
    if (p.flags & FLAG_ACL_ON) != 0 {
        load_acl_packet_ids_v6(info, p);
        phase_policy_tc(ctx, info, p);
        if p.action == TC_ACT_SHOT as u32 {
            return;
        }
    }
    if need_tc_post_ids(p) {
        load_packet_ids_v6(info, p);
    }
    if (p.flags & FLAG_QOS_ON) != 0 {
        phase_qos_egress_tc(ctx, info, p);
        if p.action == TC_ACT_SHOT as u32 {
            return;
        }
    }
}

/// Phase: Policy evaluation for TC.
#[inline(always)]
unsafe fn phase_policy_tc(ctx: &TcContext, info: &parser::PacketInfo, p: &mut PipelineCtx) {
    let result = policy::evaluate_policy(p, info.dst_port);

    if result == XDP_PASS {
        p.action = TC_ACT_OK as u32;
    } else {
        p.action = TC_ACT_SHOT as u32;
        if (p.flags & FLAG_TRACING) != 0 {
            let trace_result = trace_result_from_drop_reason(p.drop_reason);
            do_trace(
                ctx,
                info,
                p,
                TRACE_TC_DROP,
                trace_result,
            );
        }
    }
}

/// Phase: QoS egress for TC. Sets p.action = TC_ACT_SHOT if dropped.
#[inline(always)]
unsafe fn phase_qos_egress_tc(ctx: &TcContext, info: &parser::PacketInfo, p: &mut PipelineCtx) {
    let (edt, prio) = qos::apply_qos_egress(p.tap_id, p.src_id, p.dst_id, p.pkt_len, p.now);
    if edt == u64::MAX {
        p.drop_reason = DROP_QOS_EGRESS;
        p.action = TC_ACT_SHOT as u32;
        do_drop(p);
        if (p.flags & FLAG_TRACING) != 0 {
            do_trace(ctx, info, p, TRACE_TC_DROP, TRACE_RESULT_DROP_QOS);
        }
        return;
    }
    apply_edt_prio(ctx, edt, prio);
}

/// Apply EDT timestamp and priority to skb.
#[inline(always)]
unsafe fn apply_edt_prio(ctx: &TcContext, edt: u64, prio: u8) {
    if edt != 0 || prio != 0 {
        let skb = ctx.as_ptr() as *mut __sk_buff;
        if edt != 0 {
            (*skb).tstamp = edt;
        }
        if prio != 0 {
            (*skb).priority = prio as u32;
        }
    }
}

// --- SSL uprobe entry points ---

#[uprobe]
pub fn ssl_handshake_entry(ctx: ProbeContext) -> u32 {
    unsafe { ssl::ssl_handshake_entry_impl(&ctx) }
}

#[uretprobe]
pub fn ssl_handshake_return(ctx: RetProbeContext) -> u32 {
    unsafe { ssl::ssl_handshake_return_impl(&ctx) }
}

#[uprobe]
pub fn ssl_connect_entry(ctx: ProbeContext) -> u32 {
    unsafe { ssl::ssl_connect_entry_impl(&ctx) }
}

#[uretprobe]
pub fn ssl_connect_return(ctx: RetProbeContext) -> u32 {
    unsafe { ssl::ssl_connect_return_impl(&ctx) }
}

#[uprobe]
pub fn ssl_accept_entry(ctx: ProbeContext) -> u32 {
    unsafe { ssl::ssl_accept_entry_impl(&ctx) }
}

#[uretprobe]
pub fn ssl_accept_return(ctx: RetProbeContext) -> u32 {
    unsafe { ssl::ssl_accept_return_impl(&ctx) }
}

#[uprobe]
pub fn ssl_set_connect_state(ctx: ProbeContext) -> u32 {
    unsafe { ssl::ssl_set_connect_state_impl(&ctx) }
}

#[uprobe]
pub fn ssl_set_accept_state(ctx: ProbeContext) -> u32 {
    unsafe { ssl::ssl_set_accept_state_impl(&ctx) }
}

#[uprobe]
pub fn ssl_shutdown_entry(ctx: ProbeContext) -> u32 {
    unsafe { ssl::ssl_shutdown_entry_impl(&ctx) }
}

#[uprobe]
pub fn ssl_free_entry(ctx: ProbeContext) -> u32 {
    unsafe { ssl::ssl_free_entry_impl(&ctx) }
}

#[uprobe]
pub fn ssl_set_sni(ctx: ProbeContext) -> u32 {
    unsafe { ssl::ssl_set_sni_impl(&ctx) }
}

#[uprobe]
pub fn ssl_write_entry(ctx: ProbeContext) -> u32 {
    unsafe { ssl::ssl_write_entry_impl(&ctx) }
}

#[uprobe]
pub fn ssl_write_ex_entry(ctx: ProbeContext) -> u32 {
    unsafe { ssl::ssl_write_entry_impl(&ctx) }
}

#[uretprobe]
pub fn ssl_write_return(ctx: RetProbeContext) -> u32 {
    unsafe { ssl::ssl_write_return_impl(&ctx) }
}

#[uretprobe]
pub fn ssl_write_ex_return(ctx: RetProbeContext) -> u32 {
    unsafe { ssl::ssl_write_return_impl(&ctx) }
}

#[uprobe]
pub fn ssl_read_entry(ctx: ProbeContext) -> u32 {
    unsafe { ssl::ssl_read_entry_impl(&ctx) }
}

#[uprobe]
pub fn ssl_read_ex_entry(ctx: ProbeContext) -> u32 {
    unsafe { ssl::ssl_read_ex_entry_impl(&ctx) }
}

#[uretprobe]
pub fn ssl_read_return(ctx: RetProbeContext) -> u32 {
    unsafe { ssl::ssl_read_return_impl(&ctx) }
}

#[uretprobe]
pub fn ssl_read_ex_return(ctx: RetProbeContext) -> u32 {
    unsafe { ssl::ssl_read_ex_return_impl(&ctx) }
}
