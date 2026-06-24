#![no_std]
#![no_main]

use aya_ebpf::bindings::{__sk_buff, xdp_md};
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
    CtKey4, CtKey6, PipelineCtx, CT_CONTRACT_FAMILY_IPV4, CT_CONTRACT_FAMILY_IPV6,
    CT_CONTRACT_HOOK_TC_INGRESS, CT_CONTRACT_REASON_CT_DISABLED, CT_CONTRACT_REASON_CT_MISS,
    DIR_EGRESS, DIR_INGRESS, DROP_QOS_EGRESS, DROP_QOS_INGRESS, FLAG_ACL_ON, FLAG_CT_HIT,
    FLAG_IS_FORWARD, FLAG_MIRROR_ON, FLAG_QOS_ON, FLAG_TCPRT_ON, FLAG_TRACING, IPPROTO_TCP,
    TAP_ID_UNASSIGNED, TRACE_RESULT_DROP_ACL, TRACE_RESULT_DROP_ACL_DEFAULT,
    TRACE_RESULT_DROP_ACL_PORT, TRACE_RESULT_DROP_QOS, TRACE_RESULT_PASS, TRACE_TC_DROP,
    TRACE_TC_EGRESS, TRACE_TC_INGRESS, TRACE_XDP_DROP, XDP_DROP, XDP_PASS,
};
use conntrack::CtLookupResult;
use maps::{DST_IPV4_TRIE, DST_IPV6_TRIE, SRC_IPV4_TRIE, SRC_IPV6_TRIE};

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
    let pkt_len = (data_end - data) as u32;
    unsafe {
        let info_ptr = match maps::PKT_SCRATCH.get_ptr_mut(0) {
            Some(p) => p,
            None => return XDP_PASS,
        };
        if !parser::parse_eth_ipv4(data, data_end, 0, info_ptr)
            && !parser::parse_eth_ipv6(data, data_end, 0, info_ptr)
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
        match try_xdp_firewall(&ctx, info_ptr, pipe) {
            Ok(ret) => ret,
            Err(_) => XDP_PASS,
        }
    }
}

#[inline(never)]
unsafe fn try_xdp_firewall(
    ctx: &XdpContext,
    info: *const parser::PacketInfo,
    pipe: *mut PipelineCtx,
) -> Result<u32, ()> {
    let info = &*info;
    let p = &mut *pipe;

    p.now = bpf_ktime_get_ns();
    p.proto = info.proto;
    load_runtime_ctx_xdp(ctx, p);
    load_feature_flags_xdp(p, info);

    if info.is_ipv6 {
        let ct_key = CtKey6 {
            tap_id: p.tap_id,
            src_ip: info.src_ip_v6,
            dst_ip: info.dst_ip_v6,
            src_port: info.src_port,
            dst_port: info.dst_port,
            proto: info.proto,
            pad: [0; 3],
        };

        phase_ct_v6(info, p, &ct_key);

        if p.ct_state >= 2 {
            phase_ct_fastpath_xdp_v6(info, p, &ct_key);
            return Ok(p.action);
        }

        if (p.flags & FLAG_ACL_ON) != 0 {
            p.src_id = lookup_ipv6(&SRC_IPV6_TRIE, p.tap_id, info.src_ip_v6).unwrap_or(0);
            p.dst_id = lookup_ipv6(&DST_IPV6_TRIE, p.tap_id, info.dst_ip_v6).unwrap_or(0);
            phase_policy_xdp(ctx, info, p);
            if p.action == XDP_DROP {
                return Ok(p.action);
            }
        }

        phase_post_accept_xdp_v6(info, p, &ct_key);

        return Ok(p.action);
    }

    let ct_key = CtKey4 {
        tap_id: p.tap_id,
        src_ip: info.src_ip,
        dst_ip: info.dst_ip,
        src_port: info.src_port,
        dst_port: info.dst_port,
        proto: info.proto,
        pad: [0; 3],
    };

    phase_ct_v4(info, p, &ct_key);

    if p.ct_state >= 2 {
        phase_ct_fastpath_xdp_v4(info, p, &ct_key);
        return Ok(p.action);
    }

    if (p.flags & FLAG_ACL_ON) != 0 {
        p.src_id = lookup_ipv4(&SRC_IPV4_TRIE, p.tap_id, info.src_ip).unwrap_or(0);
        p.dst_id = lookup_ipv4(&DST_IPV4_TRIE, p.tap_id, info.dst_ip).unwrap_or(0);
        phase_policy_xdp(ctx, info, p);
        if p.action == XDP_DROP {
            return Ok(p.action);
        }
    }

    phase_post_accept_xdp_v4(info, p, &ct_key);

    Ok(p.action)
}

// --- TC Egress ---

#[classifier]
pub fn tc_egress(ctx: TcContext) -> i32 {
    let pkt_len = ctx.len();
    unsafe {
        let info_ptr = match maps::PKT_SCRATCH.get_ptr_mut(0) {
            Some(p) => p,
            None => return TC_ACT_OK,
        };
        if !parse_tc_packet(&ctx, info_ptr) {
            try_raw_global_mirror_tc(&ctx, DIR_EGRESS, pkt_len);
            return TC_ACT_OK;
        }
        let pipe = match maps::PIPE_SCRATCH.get_ptr_mut(0) {
            Some(p) => p,
            None => return TC_ACT_OK,
        };
        (*pipe).pkt_len = pkt_len;
        (*pipe).tap_id = TAP_ID_UNASSIGNED;
        (*pipe).direction = DIR_EGRESS;
        (*pipe).action = 0; // TC_ACT_OK
        (*pipe).flags = 0;
        (*pipe).ct_state = 0;
        (*pipe).drop_reason = 0;
        match try_tc_egress(&ctx, info_ptr, pipe) {
            Ok(ret) => ret,
            Err(_) => TC_ACT_OK,
        }
    }
}

#[inline(never)]
unsafe fn try_tc_egress(
    ctx: &TcContext,
    info: *const parser::PacketInfo,
    pipe: *mut PipelineCtx,
) -> Result<i32, ()> {
    let info = &*info;
    let p = &mut *pipe;

    p.now = bpf_ktime_get_ns();
    p.proto = info.proto;
    load_runtime_ctx_tc(ctx, p);
    load_feature_flags_tc(p, info);

    if info.is_ipv6 {
        let ct_key = CtKey6 {
            tap_id: p.tap_id,
            src_ip: info.src_ip_v6,
            dst_ip: info.dst_ip_v6,
            src_port: info.src_port,
            dst_port: info.dst_port,
            proto: info.proto,
            pad: [0; 3],
        };

        phase_ct_v6(info, p, &ct_key);

        if p.ct_state >= 2 {
            phase_ct_fastpath_tc_v6(ctx, info, p, &ct_key);
            return Ok(p.action as i32);
        }

        p.src_id = lookup_ipv6(&SRC_IPV6_TRIE, p.tap_id, info.src_ip_v6).unwrap_or(0);
        p.dst_id = lookup_ipv6(&DST_IPV6_TRIE, p.tap_id, info.dst_ip_v6).unwrap_or(0);

        if (p.flags & FLAG_ACL_ON) != 0 {
            phase_policy_tc(ctx, info, p);
            if p.action == TC_ACT_SHOT as u32 {
                return Ok(TC_ACT_SHOT);
            }
        }

        phase_flow_tcprt_v6(info, p, &ct_key);

        if (p.flags & FLAG_QOS_ON) != 0 {
            phase_qos_egress_tc(ctx, info, p);
            if p.action == TC_ACT_SHOT as u32 {
                return Ok(TC_ACT_SHOT);
            }
        }

        phase_post_accept_tc_v6(ctx, info, p, &ct_key);

        return Ok(p.action as i32);
    }

    let ct_key = CtKey4 {
        tap_id: p.tap_id,
        src_ip: info.src_ip,
        dst_ip: info.dst_ip,
        src_port: info.src_port,
        dst_port: info.dst_port,
        proto: info.proto,
        pad: [0; 3],
    };

    phase_ct_v4(info, p, &ct_key);

    if p.ct_state >= 2 {
        phase_ct_fastpath_tc_v4(ctx, info, p, &ct_key);
        return Ok(p.action as i32);
    }

    p.src_id = lookup_ipv4(&SRC_IPV4_TRIE, p.tap_id, info.src_ip).unwrap_or(0);
    p.dst_id = lookup_ipv4(&DST_IPV4_TRIE, p.tap_id, info.dst_ip).unwrap_or(0);

    if (p.flags & FLAG_ACL_ON) != 0 {
        phase_policy_tc(ctx, info, p);
        if p.action == TC_ACT_SHOT as u32 {
            return Ok(TC_ACT_SHOT);
        }
    }

    phase_flow_tcprt_v4(info, p, &ct_key);

    if (p.flags & FLAG_QOS_ON) != 0 {
        phase_qos_egress_tc(ctx, info, p);
        if p.action == TC_ACT_SHOT as u32 {
            return Ok(TC_ACT_SHOT);
        }
    }

    phase_post_accept_tc_v4(ctx, info, p, &ct_key);

    Ok(p.action as i32)
}

// --- TC Ingress ---

#[classifier]
pub fn tc_ingress(ctx: TcContext) -> i32 {
    let pkt_len = ctx.len();
    unsafe {
        let info_ptr = match maps::PKT_SCRATCH.get_ptr_mut(0) {
            Some(p) => p,
            None => return TC_ACT_OK,
        };
        if !parse_tc_packet(&ctx, info_ptr) {
            try_raw_global_mirror_tc(&ctx, DIR_INGRESS, pkt_len);
            return TC_ACT_OK;
        }
        let pipe = match maps::PIPE_SCRATCH.get_ptr_mut(0) {
            Some(p) => p,
            None => return TC_ACT_OK,
        };
        (*pipe).pkt_len = pkt_len;
        (*pipe).tap_id = TAP_ID_UNASSIGNED;
        (*pipe).direction = DIR_INGRESS;
        (*pipe).action = 0; // TC_ACT_OK
        (*pipe).flags = 0;
        (*pipe).ct_state = 0;
        (*pipe).drop_reason = 0;
        match try_tc_ingress(&ctx, info_ptr, pipe) {
            Ok(ret) => ret,
            Err(_) => TC_ACT_OK,
        }
    }
}

#[inline(never)]
unsafe fn try_tc_ingress(
    ctx: &TcContext,
    info: *const parser::PacketInfo,
    pipe: *mut PipelineCtx,
) -> Result<i32, ()> {
    let info = &*info;
    let p = &mut *pipe;

    p.now = bpf_ktime_get_ns();
    p.proto = info.proto;
    load_runtime_ctx_tc(ctx, p);
    load_feature_flags_tc(p, info);

    if info.is_ipv6 {
        let ct_key = CtKey6 {
            tap_id: p.tap_id,
            src_ip: info.src_ip_v6,
            dst_ip: info.dst_ip_v6,
            src_port: info.src_port,
            dst_port: info.dst_port,
            proto: info.proto,
            pad: [0; 3],
        };

        phase_ct_v6(info, p, &ct_key);

        if p.ct_state >= 2 {
            phase_ct_fastpath_tc_ingress_v6(ctx, info, p, &ct_key);
        } else {
            phase_ct_miss_tc_ingress_v6(ctx, info, p);
        }

        return Ok(p.action as i32);
    }

    let ct_key = CtKey4 {
        tap_id: p.tap_id,
        src_ip: info.src_ip,
        dst_ip: info.dst_ip,
        src_port: info.src_port,
        dst_port: info.dst_port,
        proto: info.proto,
        pad: [0; 3],
    };

    phase_ct_v4(info, p, &ct_key);

    if p.ct_state >= 2 {
        phase_ct_fastpath_tc_ingress_v4(ctx, info, p, &ct_key);
    } else {
        phase_ct_miss_tc_ingress_v4(ctx, info, p);
    }

    Ok(p.action as i32)
}

// --- Helpers ---

#[inline(always)]
unsafe fn load_feature_flags_xdp(p: &mut PipelineCtx, info: &parser::PacketInfo) {
    if policy::acl_enabled(p.tap_id) {
        p.flags |= FLAG_ACL_ON;
    }
    if trace::should_trace(p.tap_id, info) {
        p.flags |= FLAG_TRACING;
    }
}

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
    if trace::should_trace(p.tap_id, info) {
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
unsafe fn load_runtime_ctx_xdp(ctx: &XdpContext, p: &mut PipelineCtx) {
    let xdp = ctx.as_ptr() as *const xdp_md;
    p.tap_id = resolve_tap_id_for_ifindex((*xdp).ingress_ifindex);
}

#[inline(always)]
unsafe fn load_runtime_ctx_tc(ctx: &TcContext, p: &mut PipelineCtx) {
    let skb = ctx.as_ptr() as *const __sk_buff;
    p.tap_id = resolve_tap_id_for_ifindex((*skb).ifindex);
}

#[inline(always)]
unsafe fn parse_tc_packet(ctx: &TcContext, out: *mut parser::PacketInfo) -> bool {
    let mut data = ctx.data();
    let mut data_end = ctx.data_end();
    let mut parsed = parser::parse_eth_ipv4(data, data_end, 0, out)
        || parser::parse_eth_ipv6(data, data_end, 0, out);
    if !parsed {
        return false;
    }

    let info = &*out;
    // TC direct packet access can stop at the linear head on non-linear skbs.
    // That leaves ports available but zeros TCP seq/flags/payload, which breaks
    // TCP-RT while leaving port-based features apparently healthy. Re-pull only
    // for this suspicious truncated TCP shape and re-parse.
    if info.proto == IPPROTO_TCP && info.tcp_flags == 0 && info.tcp_seq == 0 {
        if ctx.pull_data(0).is_ok() {
            data = ctx.data();
            data_end = ctx.data_end();
            parsed = parser::parse_eth_ipv4(data, data_end, 0, out)
                || parser::parse_eth_ipv6(data, data_end, 0, out);
        }
    }

    parsed
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
}

#[inline(always)]
fn get_matched(p: &PipelineCtx) -> conntrack::MatchedPolicy {
    conntrack::MatchedPolicy {
        tap_id: p.tap_id,
        src_id: p.matched_src_id,
        dst_id: p.matched_dst_id,
        proto: p.matched_proto,
        direction: p.matched_direction,
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
            _pad: [0; 3],
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

// --- Phase functions (each is #[inline(never)] to isolate stack frames) ---

/// Phase: CT lookup for IPv4. Sets p.ct_state, p.matched_*, p.flags (CT_HIT, IS_FORWARD).
#[inline(never)]
unsafe fn phase_ct_v4(_info: &parser::PacketInfo, p: &mut PipelineCtx, ct_key: &CtKey4) {
    match conntrack::ct_lookup_v4(ct_key, p.now, p.pkt_len) {
        CtLookupResult::Established(matched, is_forward)
        | CtLookupResult::SeenReply(matched, is_forward) => {
            p.ct_state = 2;
            p.flags |= FLAG_CT_HIT;
            if is_forward {
                p.flags |= FLAG_IS_FORWARD;
            }
            set_matched(p, &matched);
        }
        CtLookupResult::NotFound => {
            p.ct_state = 0;
        }
    }
}

/// Phase: CT lookup for IPv6.
#[inline(never)]
unsafe fn phase_ct_v6(_info: &parser::PacketInfo, p: &mut PipelineCtx, ct_key: &CtKey6) {
    match conntrack::ct_lookup_v6(ct_key, p.now, p.pkt_len) {
        CtLookupResult::Established(matched, is_forward)
        | CtLookupResult::SeenReply(matched, is_forward) => {
            p.ct_state = 2;
            p.flags |= FLAG_CT_HIT;
            if is_forward {
                p.flags |= FLAG_IS_FORWARD;
            }
            set_matched(p, &matched);
        }
        CtLookupResult::NotFound => {
            p.ct_state = 0;
        }
    }
}

/// CT fast-path for XDP ingress IPv4.
#[inline(never)]
unsafe fn phase_ct_fastpath_xdp_v4(
    _info: &parser::PacketInfo,
    p: &mut PipelineCtx,
    _ct_key: &CtKey4,
) {
    p.action = XDP_PASS;
}

/// CT fast-path for XDP ingress IPv6.
#[inline(never)]
unsafe fn phase_ct_fastpath_xdp_v6(
    _info: &parser::PacketInfo,
    p: &mut PipelineCtx,
    _ct_key: &CtKey6,
) {
    p.action = XDP_PASS;
}

#[inline(always)]
fn need_ingress_ids(p: &PipelineCtx) -> bool {
    (p.flags & (FLAG_ACL_ON | FLAG_QOS_ON | FLAG_MIRROR_ON | FLAG_TRACING)) != 0
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
unsafe fn should_create_ct(p: &PipelineCtx) -> bool {
    (p.flags & FLAG_ACL_ON) != 0
        || stats::monitoring_enabled(p.tap_id)
        || tcprt::tcprt_enabled(p.tap_id)
}

#[inline(always)]
unsafe fn should_apply_ingress_qos(p: &PipelineCtx) -> bool {
    // Ingress QoS is a standalone feature. TC ingress can enforce policing
    // on both CT hits and CT-miss fallback paths after doing its own ID lookup.
    (p.flags & FLAG_QOS_ON) != 0
}

#[inline(always)]
unsafe fn record_tc_ingress_contract_fallback(p: &PipelineCtx, family: u8) {
    let reason = if runtime::conntrack_enabled(p.tap_id) {
        CT_CONTRACT_REASON_CT_MISS
    } else {
        CT_CONTRACT_REASON_CT_DISABLED
    };
    ct_contract::record_event(&ct_contract::CtContractArgs {
        tap_id: p.tap_id,
        pkt_len: p.pkt_len,
        now: p.now,
        hook: CT_CONTRACT_HOOK_TC_INGRESS,
        family,
        reason,
        _pad: 0,
    });
}

#[inline(always)]
unsafe fn phase_qos_ingress_tc(
    ctx: &TcContext,
    info: &parser::PacketInfo,
    p: &mut PipelineCtx,
) {
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
            info.proto,
            DIR_INGRESS,
            p.pkt_len,
        );
    }
    if (p.flags & FLAG_TRACING) != 0 {
        do_trace(ctx, info, p, TRACE_TC_INGRESS, TRACE_RESULT_PASS);
    }
    p.action = TC_ACT_OK as u32;
}

/// CT fast-path for TC ingress IPv4.
#[inline(always)]
unsafe fn phase_ct_fastpath_tc_ingress_v4(
    ctx: &TcContext,
    info: &parser::PacketInfo,
    p: &mut PipelineCtx,
    ct_key: &CtKey4,
) {
    if (p.flags & FLAG_TCPRT_ON) != 0 && info.proto == IPPROTO_TCP {
        if (p.flags & FLAG_IS_FORWARD) != 0 {
            tcprt::track_tcp_rt_v4(ct_key, info, p.now, true, true);
        } else {
            tcprt::track_tcp_rt_v4_rev(p.tap_id, info, p.now, true);
        }
    }

    if stats::monitoring_enabled(p.tap_id) {
        if (p.flags & FLAG_ACL_ON) != 0 {
            let matched = get_matched(p);
            stats::update_rule_stats(&matched.to_policy_key(), p.pkt_len, false);
        }
        stats::update_flow_stats_v4(ct_key, p.pkt_len, p.now);
    }

    if need_ingress_ids(p) {
        load_packet_ids_v4(info, p);
        if (p.flags & FLAG_ACL_ON) != 0 {
            phase_policy_tc(ctx, info, p);
            if p.action == TC_ACT_SHOT as u32 {
                return;
            }
        }
        if should_apply_ingress_qos(p) {
            phase_qos_ingress_tc(ctx, info, p);
            if p.action == TC_ACT_SHOT as u32 {
                return;
            }
        }
        phase_post_accept_tc_ingress(ctx, info, p);
        return;
    }

    p.action = TC_ACT_OK as u32;
}

/// CT fast-path for TC ingress IPv6.
#[inline(always)]
unsafe fn phase_ct_fastpath_tc_ingress_v6(
    ctx: &TcContext,
    info: &parser::PacketInfo,
    p: &mut PipelineCtx,
    ct_key: &CtKey6,
) {
    if (p.flags & FLAG_TCPRT_ON) != 0 && info.proto == IPPROTO_TCP {
        if (p.flags & FLAG_IS_FORWARD) != 0 {
            tcprt::track_tcp_rt_v6(ct_key, info, p.now, true, true);
        } else {
            tcprt::track_tcp_rt_v6_rev(p.tap_id, info, p.now, true);
        }
    }

    if stats::monitoring_enabled(p.tap_id) {
        if (p.flags & FLAG_ACL_ON) != 0 {
            let matched = get_matched(p);
            stats::update_rule_stats(&matched.to_policy_key(), p.pkt_len, false);
        }
        stats::update_flow_stats_v6(ct_key, p.pkt_len, p.now);
    }

    if need_ingress_ids(p) {
        load_packet_ids_v6(info, p);
        if (p.flags & FLAG_ACL_ON) != 0 {
            phase_policy_tc(ctx, info, p);
            if p.action == TC_ACT_SHOT as u32 {
                return;
            }
        }
        if should_apply_ingress_qos(p) {
            phase_qos_ingress_tc(ctx, info, p);
            if p.action == TC_ACT_SHOT as u32 {
                return;
            }
        }
        phase_post_accept_tc_ingress(ctx, info, p);
        return;
    }

    p.action = TC_ACT_OK as u32;
}

/// CT miss fallback for TC ingress IPv4.
#[inline(always)]
unsafe fn phase_ct_miss_tc_ingress_v4(
    ctx: &TcContext,
    info: &parser::PacketInfo,
    p: &mut PipelineCtx,
) {
    if (p.flags & FLAG_TCPRT_ON) != 0 && info.proto == IPPROTO_TCP {
        tcprt::track_tcp_rt_v4_auto(p.tap_id, info, p.now, true);
    }

    let need_ids = need_ingress_ids(p);
    if need_ids {
        record_tc_ingress_contract_fallback(p, CT_CONTRACT_FAMILY_IPV4);
        load_packet_ids_v4(info, p);
        if (p.flags & FLAG_ACL_ON) != 0 {
            phase_policy_tc(ctx, info, p);
            if p.action == TC_ACT_SHOT as u32 {
                return;
            }
        }
        if should_apply_ingress_qos(p) {
            phase_qos_ingress_tc(ctx, info, p);
            if p.action == TC_ACT_SHOT as u32 {
                return;
            }
        }
        phase_post_accept_tc_ingress(ctx, info, p);
        return;
    }

    p.action = TC_ACT_OK as u32;
}

/// CT miss fallback for TC ingress IPv6.
#[inline(always)]
unsafe fn phase_ct_miss_tc_ingress_v6(
    ctx: &TcContext,
    info: &parser::PacketInfo,
    p: &mut PipelineCtx,
) {
    if (p.flags & FLAG_TCPRT_ON) != 0 && info.proto == IPPROTO_TCP {
        tcprt::track_tcp_rt_v6_auto(p.tap_id, info, p.now, true);
    }

    let need_ids = need_ingress_ids(p);
    if need_ids {
        record_tc_ingress_contract_fallback(p, CT_CONTRACT_FAMILY_IPV6);
        load_packet_ids_v6(info, p);
        if (p.flags & FLAG_ACL_ON) != 0 {
            phase_policy_tc(ctx, info, p);
            if p.action == TC_ACT_SHOT as u32 {
                return;
            }
        }
        if should_apply_ingress_qos(p) {
            phase_qos_ingress_tc(ctx, info, p);
            if p.action == TC_ACT_SHOT as u32 {
                return;
            }
        }
        phase_post_accept_tc_ingress(ctx, info, p);
        return;
    }

    p.action = TC_ACT_OK as u32;
}

/// CT fast-path for TC egress IPv4.
#[inline(always)]
unsafe fn phase_ct_fastpath_tc_v4(
    ctx: &TcContext,
    info: &parser::PacketInfo,
    p: &mut PipelineCtx,
    ct_key: &CtKey4,
) {
    let tracing = (p.flags & FLAG_TRACING) != 0;
    if (p.flags & FLAG_ACL_ON) != 0 {
        let matched = get_matched(p);
        stats::update_rule_stats(&matched.to_policy_key(), p.pkt_len, false);
    }
    stats::update_flow_stats_v4(ct_key, p.pkt_len, p.now);

    if (p.flags & FLAG_TCPRT_ON) != 0 && info.proto == IPPROTO_TCP {
        if (p.flags & FLAG_IS_FORWARD) != 0 {
            tcprt::track_tcp_rt_v4(ct_key, info, p.now, true, false);
        } else {
            tcprt::track_tcp_rt_v4_rev(p.tap_id, info, p.now, false);
        }
    }

    let need_ids = (p.flags & FLAG_QOS_ON) != 0
        || (p.flags & FLAG_MIRROR_ON) != 0
        || stats::monitoring_enabled(p.tap_id);
    if need_ids {
        p.dst_id = lookup_ipv4(&DST_IPV4_TRIE, p.tap_id, info.dst_ip).unwrap_or(0);
        p.src_id = lookup_ipv4(&SRC_IPV4_TRIE, p.tap_id, info.src_ip).unwrap_or(0);
        if (p.flags & FLAG_QOS_ON) != 0 {
            let (edt, prio) = qos::apply_qos_egress(p.tap_id, p.src_id, p.dst_id, p.pkt_len, p.now);
            if edt == u64::MAX {
                p.drop_reason = DROP_QOS_EGRESS;
                p.action = TC_ACT_SHOT as u32;
                do_drop(p);
                if tracing {
                    do_trace(ctx, info, p, TRACE_TC_DROP, TRACE_RESULT_DROP_QOS);
                }
                return;
            }
            apply_edt_prio(ctx, edt, prio);
        }
        stats::update_group_stats(p.tap_id, p.src_id, DIR_EGRESS, p.pkt_len);
        stats::update_group_stats(p.tap_id, p.dst_id, DIR_INGRESS, p.pkt_len);
        if (p.flags & FLAG_MIRROR_ON) != 0 {
            let skb = ctx.as_ptr() as *mut __sk_buff;
            mirror::try_mirror_tc(
                skb, p.tap_id, p.src_id, p.dst_id, info.proto, DIR_EGRESS, p.pkt_len,
            );
        }
        if tracing {
            do_trace(ctx, info, p, TRACE_TC_EGRESS, TRACE_RESULT_PASS);
        }
    } else if tracing {
        do_trace(ctx, info, p, TRACE_TC_EGRESS, TRACE_RESULT_PASS);
    }
    p.action = TC_ACT_OK as u32;
}

/// CT fast-path for TC egress IPv6.
#[inline(always)]
unsafe fn phase_ct_fastpath_tc_v6(
    ctx: &TcContext,
    info: &parser::PacketInfo,
    p: &mut PipelineCtx,
    ct_key: &CtKey6,
) {
    let tracing = (p.flags & FLAG_TRACING) != 0;
    if (p.flags & FLAG_ACL_ON) != 0 {
        let matched = get_matched(p);
        stats::update_rule_stats(&matched.to_policy_key(), p.pkt_len, false);
    }
    stats::update_flow_stats_v6(ct_key, p.pkt_len, p.now);

    if (p.flags & FLAG_TCPRT_ON) != 0 && info.proto == IPPROTO_TCP {
        if (p.flags & FLAG_IS_FORWARD) != 0 {
            tcprt::track_tcp_rt_v6(ct_key, info, p.now, true, false);
        } else {
            tcprt::track_tcp_rt_v6_rev(p.tap_id, info, p.now, false);
        }
    }

    let need_ids = (p.flags & FLAG_QOS_ON) != 0
        || (p.flags & FLAG_MIRROR_ON) != 0
        || stats::monitoring_enabled(p.tap_id);
    if need_ids {
        p.dst_id = lookup_ipv6(&DST_IPV6_TRIE, p.tap_id, info.dst_ip_v6).unwrap_or(0);
        p.src_id = lookup_ipv6(&SRC_IPV6_TRIE, p.tap_id, info.src_ip_v6).unwrap_or(0);
        if (p.flags & FLAG_QOS_ON) != 0 {
            let (edt, prio) = qos::apply_qos_egress(p.tap_id, p.src_id, p.dst_id, p.pkt_len, p.now);
            if edt == u64::MAX {
                p.drop_reason = DROP_QOS_EGRESS;
                p.action = TC_ACT_SHOT as u32;
                do_drop(p);
                if tracing {
                    do_trace(ctx, info, p, TRACE_TC_DROP, TRACE_RESULT_DROP_QOS);
                }
                return;
            }
            apply_edt_prio(ctx, edt, prio);
        }
        stats::update_group_stats(p.tap_id, p.src_id, DIR_EGRESS, p.pkt_len);
        stats::update_group_stats(p.tap_id, p.dst_id, DIR_INGRESS, p.pkt_len);
        if (p.flags & FLAG_MIRROR_ON) != 0 {
            let skb = ctx.as_ptr() as *mut __sk_buff;
            mirror::try_mirror_tc(
                skb, p.tap_id, p.src_id, p.dst_id, info.proto, DIR_EGRESS, p.pkt_len,
            );
        }
        if tracing {
            do_trace(ctx, info, p, TRACE_TC_EGRESS, TRACE_RESULT_PASS);
        }
    } else if tracing {
        do_trace(ctx, info, p, TRACE_TC_EGRESS, TRACE_RESULT_PASS);
    }
    p.action = TC_ACT_OK as u32;
}

/// Phase: Policy evaluation for XDP (sets p.action, p.drop_reason, p.matched_*).
#[inline(never)]
unsafe fn phase_policy_xdp(ctx: &XdpContext, info: &parser::PacketInfo, p: &mut PipelineCtx) {
    let args = policy::PolicyArgs {
        tap_id: p.tap_id,
        src_id: p.src_id,
        dst_id: p.dst_id,
        proto: p.proto,
        direction: p.direction,
        dst_port: info.dst_port,
        pkt_len: p.pkt_len,
        now: p.now,
    };
    let (result, drop_reason, matched, policy_hit) = policy::evaluate_policy(&args);
    p.action = result;
    p.drop_reason = drop_reason;
    set_matched(p, &matched);

    if result == XDP_DROP {
        if policy_hit {
            stats::update_rule_stats(&matched.to_policy_key(), p.pkt_len, true);
        }
        policy::record_policy_drop(&args, drop_reason);
        if (p.flags & FLAG_TRACING) != 0 {
            do_trace(ctx, info, p, TRACE_XDP_DROP, trace_result_from_drop_reason(drop_reason));
        }
    }
}

/// Phase: Policy evaluation for TC.
#[inline(always)]
unsafe fn phase_policy_tc(ctx: &TcContext, info: &parser::PacketInfo, p: &mut PipelineCtx) {
    let args = policy::PolicyArgs {
        tap_id: p.tap_id,
        src_id: p.src_id,
        dst_id: p.dst_id,
        proto: info.proto,
        direction: p.direction,
        dst_port: info.dst_port,
        pkt_len: p.pkt_len,
        now: p.now,
    };
    let (result, drop_reason, matched, policy_hit) = policy::evaluate_policy(&args);
    if policy_hit {
        policy::account_policy_result(&args, &matched, result, drop_reason);
    }
    p.drop_reason = drop_reason;
    set_matched(p, &matched);

    if result == XDP_PASS {
        p.action = TC_ACT_OK as u32;
    } else {
        p.action = TC_ACT_SHOT as u32;
        if (p.flags & FLAG_TRACING) != 0 {
            do_trace(ctx, info, p, TRACE_TC_DROP, trace_result_from_drop_reason(drop_reason));
        }
    }
}

/// Phase: Flow stats + TCP-RT for IPv4.
#[inline(never)]
unsafe fn phase_flow_tcprt_v4(info: &parser::PacketInfo, p: &mut PipelineCtx, ct_key: &CtKey4) {
    stats::update_flow_stats_v4(ct_key, p.pkt_len, p.now);
    if (p.flags & FLAG_TCPRT_ON) != 0 && info.proto == IPPROTO_TCP {
        tcprt::track_tcp_rt_v4_auto(p.tap_id, info, p.now, false);
    }
}

/// Phase: Flow stats + TCP-RT for IPv6.
#[inline(never)]
unsafe fn phase_flow_tcprt_v6(info: &parser::PacketInfo, p: &mut PipelineCtx, ct_key: &CtKey6) {
    stats::update_flow_stats_v6(ct_key, p.pkt_len, p.now);
    if (p.flags & FLAG_TCPRT_ON) != 0 && info.proto == IPPROTO_TCP {
        tcprt::track_tcp_rt_v6_auto(p.tap_id, info, p.now, false);
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

/// Phase: Post-accept for XDP ingress IPv4.
#[inline(never)]
unsafe fn phase_post_accept_xdp_v4(
    _info: &parser::PacketInfo,
    p: &mut PipelineCtx,
    ct_key: &CtKey4,
) {
    if should_create_ct(p) {
        let matched = get_matched(p);
        conntrack::ct_create_v4(ct_key, p.now, p.pkt_len, &matched);
        p.ct_state = 1;
    }
    p.action = XDP_PASS;
}

/// Phase: Post-accept for XDP ingress IPv6.
#[inline(never)]
unsafe fn phase_post_accept_xdp_v6(
    _info: &parser::PacketInfo,
    p: &mut PipelineCtx,
    ct_key: &CtKey6,
) {
    if should_create_ct(p) {
        let matched = get_matched(p);
        conntrack::ct_create_v6(ct_key, p.now, p.pkt_len, &matched);
        p.ct_state = 1;
    }
    p.action = XDP_PASS;
}

/// Phase: Post-accept for TC egress IPv4.
#[inline(always)]
unsafe fn phase_post_accept_tc_v4(
    ctx: &TcContext,
    info: &parser::PacketInfo,
    p: &mut PipelineCtx,
    ct_key: &CtKey4,
) {
    stats::update_group_stats(p.tap_id, p.src_id, DIR_EGRESS, p.pkt_len);
    stats::update_group_stats(p.tap_id, p.dst_id, DIR_INGRESS, p.pkt_len);
    if (p.flags & FLAG_MIRROR_ON) != 0 {
        let skb = ctx.as_ptr() as *mut __sk_buff;
        mirror::try_mirror_tc(
            skb, p.tap_id, p.src_id, p.dst_id, info.proto, DIR_EGRESS, p.pkt_len,
        );
    }
    if should_create_ct(p) {
        let matched = get_matched(p);
        conntrack::ct_create_v4(ct_key, p.now, p.pkt_len, &matched);
        p.ct_state = 1;
    }
    if (p.flags & FLAG_TRACING) != 0 {
        do_trace(ctx, info, p, TRACE_TC_EGRESS, TRACE_RESULT_PASS);
    }
    p.action = TC_ACT_OK as u32;
}

/// Phase: Post-accept for TC egress IPv6.
#[inline(always)]
unsafe fn phase_post_accept_tc_v6(
    ctx: &TcContext,
    info: &parser::PacketInfo,
    p: &mut PipelineCtx,
    ct_key: &CtKey6,
) {
    stats::update_group_stats(p.tap_id, p.src_id, DIR_EGRESS, p.pkt_len);
    stats::update_group_stats(p.tap_id, p.dst_id, DIR_INGRESS, p.pkt_len);
    if (p.flags & FLAG_MIRROR_ON) != 0 {
        let skb = ctx.as_ptr() as *mut __sk_buff;
        mirror::try_mirror_tc(
            skb, p.tap_id, p.src_id, p.dst_id, info.proto, DIR_EGRESS, p.pkt_len,
        );
    }
    if should_create_ct(p) {
        let matched = get_matched(p);
        conntrack::ct_create_v6(ct_key, p.now, p.pkt_len, &matched);
        p.ct_state = 1;
    }
    if (p.flags & FLAG_TRACING) != 0 {
        do_trace(ctx, info, p, TRACE_TC_EGRESS, TRACE_RESULT_PASS);
    }
    p.action = TC_ACT_OK as u32;
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
