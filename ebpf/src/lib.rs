#![no_std]
#![no_main]

use aya_ebpf::macros::{xdp, classifier};
use aya_ebpf::programs::{XdpContext, TcContext};
use aya_ebpf::maps::LpmTrie;
use aya_ebpf::maps::lpm_trie::Key;
use aya_ebpf::helpers::bpf_ktime_get_ns;
use aya_ebpf::EbpfContext;
use aya_ebpf::bindings::__sk_buff;

mod common;
mod maps;
mod parser;
mod conntrack;
mod stats;
mod qos;
mod policy;
mod mirror;
mod tcprt;
mod drops;
mod trace;

use common::{
    CtKey4, CtKey6,
    XDP_PASS, XDP_DROP, DIR_INGRESS, DIR_EGRESS,
    IPPROTO_TCP,
    DROP_QOS_INGRESS, DROP_QOS_EGRESS,
    TRACE_XDP_INGRESS, TRACE_XDP_DROP, TRACE_TC_EGRESS, TRACE_TC_DROP, TRACE_TC_INGRESS,
    TRACE_RESULT_PASS, TRACE_RESULT_DROP_QOS,
    PipelineCtx,
    FLAG_QOS_ON, FLAG_TCPRT_ON, FLAG_TRACING, FLAG_ACL_ON, FLAG_MIRROR_ON,
    FLAG_CT_HIT, FLAG_IS_FORWARD,
};
use maps::{
    DST_IPV4_TRIE, SRC_IPV4_TRIE, DST_IPV6_TRIE, SRC_IPV6_TRIE,
};
use conntrack::CtLookupResult;

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
            && !parser::parse_eth_ipv6(data, data_end, 0, info_ptr) {
            return XDP_PASS;
        }
        let pipe = match maps::PIPE_SCRATCH.get_ptr_mut(0) {
            Some(p) => p,
            None => return XDP_PASS,
        };
        (*pipe).pkt_len = pkt_len;
        (*pipe).direction = DIR_INGRESS;
        (*pipe).action = XDP_PASS;
        (*pipe).flags = 0;
        (*pipe).ct_state = 0;
        (*pipe).drop_reason = 0;
        match try_xdp_firewall(info_ptr, pipe) {
            Ok(ret) => ret,
            Err(_) => XDP_PASS,
        }
    }
}

#[inline(never)]
unsafe fn try_xdp_firewall(info: *const parser::PacketInfo, pipe: *mut PipelineCtx) -> Result<u32, ()> {
    let info = &*info;
    let p = &mut *pipe;

    p.now = bpf_ktime_get_ns();
    p.proto = info.proto;
    load_feature_flags(p, info);

    if info.is_ipv6 {
        let ct_key = CtKey6 {
            src_ip: info.src_ip_v6, dst_ip: info.dst_ip_v6,
            src_port: info.src_port, dst_port: info.dst_port,
            proto: info.proto, pad: [0; 3],
        };

        phase_ct_v6(info, p, &ct_key);

        if p.ct_state >= 2 {
            phase_ct_fastpath_xdp_v6(info, p, &ct_key);
            return Ok(p.action);
        }

        p.src_id = lookup_ipv6(&SRC_IPV6_TRIE, info.src_ip_v6).unwrap_or(0);
        p.dst_id = lookup_ipv6(&DST_IPV6_TRIE, info.dst_ip_v6).unwrap_or(0);

        if (p.flags & FLAG_ACL_ON) != 0 {
            phase_policy_xdp(info, p);
            if p.action == XDP_DROP {
                return Ok(p.action);
            }
        }

        phase_flow_tcprt_v6(info, p, &ct_key);

        if (p.flags & FLAG_QOS_ON) != 0 {
            phase_qos_ingress_xdp(info, p);
            if p.action == XDP_DROP {
                return Ok(p.action);
            }
        }

        phase_post_accept_xdp_v6(info, p, &ct_key);

        return Ok(p.action);
    }

    let ct_key = CtKey4 {
        src_ip: info.src_ip, dst_ip: info.dst_ip,
        src_port: info.src_port, dst_port: info.dst_port,
        proto: info.proto, pad: [0; 3],
    };

    phase_ct_v4(info, p, &ct_key);

    if p.ct_state >= 2 {
        phase_ct_fastpath_xdp_v4(info, p, &ct_key);
        return Ok(p.action);
    }

    p.src_id = lookup_ipv4(&SRC_IPV4_TRIE, info.src_ip).unwrap_or(0);
    p.dst_id = lookup_ipv4(&DST_IPV4_TRIE, info.dst_ip).unwrap_or(0);

    if (p.flags & FLAG_ACL_ON) != 0 {
        phase_policy_xdp(info, p);
        if p.action == XDP_DROP {
            return Ok(p.action);
        }
    }

    phase_flow_tcprt_v4(info, p, &ct_key);

    if (p.flags & FLAG_QOS_ON) != 0 {
        phase_qos_ingress_xdp(info, p);
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
    let data = ctx.data();
    let data_end = ctx.data_end();
    let pkt_len = ctx.len();
    unsafe {
        let info_ptr = match maps::PKT_SCRATCH.get_ptr_mut(0) {
            Some(p) => p,
            None => return TC_ACT_OK,
        };
        if !parser::parse_eth_ipv4(data, data_end, 0, info_ptr)
            && !parser::parse_eth_ipv6(data, data_end, 0, info_ptr) {
            return TC_ACT_OK;
        }
        let pipe = match maps::PIPE_SCRATCH.get_ptr_mut(0) {
            Some(p) => p,
            None => return TC_ACT_OK,
        };
        (*pipe).pkt_len = pkt_len;
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
unsafe fn try_tc_egress(ctx: &TcContext, info: *const parser::PacketInfo, pipe: *mut PipelineCtx) -> Result<i32, ()> {
    let info = &*info;
    let p = &mut *pipe;

    p.now = bpf_ktime_get_ns();
    p.proto = info.proto;
    load_feature_flags(p, info);

    if info.is_ipv6 {
        let ct_key = CtKey6 {
            src_ip: info.src_ip_v6, dst_ip: info.dst_ip_v6,
            src_port: info.src_port, dst_port: info.dst_port,
            proto: info.proto, pad: [0; 3],
        };

        phase_ct_v6(info, p, &ct_key);

        if p.ct_state >= 2 {
            phase_ct_fastpath_tc_v6(ctx, info, p, &ct_key);
            return Ok(p.action as i32);
        }

        p.src_id = lookup_ipv6(&SRC_IPV6_TRIE, info.src_ip_v6).unwrap_or(0);
        p.dst_id = lookup_ipv6(&DST_IPV6_TRIE, info.dst_ip_v6).unwrap_or(0);

        if (p.flags & FLAG_ACL_ON) != 0 {
            phase_policy_tc(info, p);
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
        src_ip: info.src_ip, dst_ip: info.dst_ip,
        src_port: info.src_port, dst_port: info.dst_port,
        proto: info.proto, pad: [0; 3],
    };

    phase_ct_v4(info, p, &ct_key);

    if p.ct_state >= 2 {
        phase_ct_fastpath_tc_v4(ctx, info, p, &ct_key);
        return Ok(p.action as i32);
    }

    p.src_id = lookup_ipv4(&SRC_IPV4_TRIE, info.src_ip).unwrap_or(0);
    p.dst_id = lookup_ipv4(&DST_IPV4_TRIE, info.dst_ip).unwrap_or(0);

    if (p.flags & FLAG_ACL_ON) != 0 {
        phase_policy_tc(info, p);
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

// --- TC Ingress (mirror only) ---

#[classifier]
pub fn tc_ingress(ctx: TcContext) -> i32 {
    let data = ctx.data();
    let data_end = ctx.data_end();
    let pkt_len = ctx.len();
    unsafe {
        let info_ptr = match maps::PKT_SCRATCH.get_ptr_mut(0) {
            Some(p) => p,
            None => return TC_ACT_OK,
        };
        if !parser::parse_eth_ipv4(data, data_end, 0, info_ptr)
            && !parser::parse_eth_ipv6(data, data_end, 0, info_ptr) {
            return TC_ACT_OK;
        }
        let pipe = match maps::PIPE_SCRATCH.get_ptr_mut(0) {
            Some(p) => p,
            None => return TC_ACT_OK,
        };
        (*pipe).pkt_len = pkt_len;
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
unsafe fn try_tc_ingress(ctx: &TcContext, info: *const parser::PacketInfo, pipe: *mut PipelineCtx) -> Result<i32, ()> {
    let info = &*info;
    let p = &mut *pipe;

    let tracing = trace::should_trace(info);

    if info.is_ipv6 {
        p.src_id = lookup_ipv6(&SRC_IPV6_TRIE, info.src_ip_v6).unwrap_or(0);
        p.dst_id = lookup_ipv6(&DST_IPV6_TRIE, info.dst_ip_v6).unwrap_or(0);
    } else {
        p.src_id = lookup_ipv4(&SRC_IPV4_TRIE, info.src_ip).unwrap_or(0);
        p.dst_id = lookup_ipv4(&DST_IPV4_TRIE, info.dst_ip).unwrap_or(0);
    }

    if mirror::mirror_enabled() {
        let skb = ctx.as_ptr() as *mut __sk_buff;
        mirror::try_mirror_tc(skb, p.src_id, p.dst_id, info.proto, DIR_INGRESS, p.pkt_len);
    }

    if tracing {
        p.now = bpf_ktime_get_ns();
        trace::trace_event(info, &trace::TraceArgs { hook: TRACE_TC_INGRESS, result: TRACE_RESULT_PASS, direction: DIR_INGRESS, ct_state: 0, drop_reason: 0, _pad: [0;3], src_id: p.src_id, dst_id: p.dst_id, pkt_len: p.pkt_len, now: p.now });
    }

    Ok(TC_ACT_OK)
}

// --- Helpers ---

#[inline(always)]
unsafe fn load_feature_flags(p: &mut PipelineCtx, info: &parser::PacketInfo) {
    if qos::qos_enabled() { p.flags |= FLAG_QOS_ON; }
    if tcprt::tcprt_enabled() { p.flags |= FLAG_TCPRT_ON; }
    if policy::acl_enabled() { p.flags |= FLAG_ACL_ON; }
    if mirror::mirror_enabled() { p.flags |= FLAG_MIRROR_ON; }
    if trace::should_trace(info) { p.flags |= FLAG_TRACING; }
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
        src_id: p.matched_src_id,
        dst_id: p.matched_dst_id,
        proto: p.matched_proto,
        direction: p.matched_direction,
    }
}

/// Inline helper: emit a trace event from PipelineCtx.
#[inline(always)]
unsafe fn do_trace(info: &parser::PacketInfo, p: &PipelineCtx, hook: u8, result: u8) {
    trace::trace_event(info, &trace::TraceArgs {
        hook, result, direction: p.direction, ct_state: p.ct_state,
        drop_reason: p.drop_reason, _pad: [0;3],
        src_id: p.src_id, dst_id: p.dst_id, pkt_len: p.pkt_len, now: p.now,
    });
}

/// Inline helper: record a drop from PipelineCtx.
#[inline(always)]
unsafe fn do_drop(p: &PipelineCtx) {
    drops::record_drop(&drops::DropArgs {
        reason: p.drop_reason, direction: p.direction, proto: p.proto,
        src_id: p.src_id, dst_id: p.dst_id, pkt_len: p.pkt_len, now: p.now, _pad: 0,
    });
}

unsafe fn lookup_ipv4(map: &LpmTrie<[u8; 4], u32>, ip: u32) -> Option<u32> {
    let key = Key::new(32, ip.to_be_bytes());
    map.get(&key).copied()
}

unsafe fn lookup_ipv6(map: &LpmTrie<[u8; 16], u32>, ip: [u8; 16]) -> Option<u32> {
    let key = Key::new(128, ip);
    map.get(&key).copied()
}

// --- Phase functions (each is #[inline(never)] to isolate stack frames) ---

/// Phase: CT lookup for IPv4. Sets p.ct_state, p.matched_*, p.flags (CT_HIT, IS_FORWARD).
#[inline(never)]
unsafe fn phase_ct_v4(_info: &parser::PacketInfo, p: &mut PipelineCtx, ct_key: &CtKey4) {
    match conntrack::ct_lookup_v4(ct_key, p.now, p.pkt_len) {
        CtLookupResult::Established(matched, is_forward) | CtLookupResult::SeenReply(matched, is_forward) => {
            p.ct_state = 2;
            p.flags |= FLAG_CT_HIT;
            if is_forward { p.flags |= FLAG_IS_FORWARD; }
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
        CtLookupResult::Established(matched, is_forward) | CtLookupResult::SeenReply(matched, is_forward) => {
            p.ct_state = 2;
            p.flags |= FLAG_CT_HIT;
            if is_forward { p.flags |= FLAG_IS_FORWARD; }
            set_matched(p, &matched);
        }
        CtLookupResult::NotFound => {
            p.ct_state = 0;
        }
    }
}

/// CT fast-path for XDP ingress IPv4: stats, tcprt, qos, group stats, trace.
#[inline(never)]
unsafe fn phase_ct_fastpath_xdp_v4(info: &parser::PacketInfo, p: &mut PipelineCtx, ct_key: &CtKey4) {
    let tracing = (p.flags & FLAG_TRACING) != 0;
    let matched = get_matched(p);
    stats::update_rule_stats(&matched.to_policy_key(), p.pkt_len, false);
    stats::update_flow_stats_v4(ct_key, p.pkt_len, p.now);

    if (p.flags & FLAG_TCPRT_ON) != 0 && info.proto == IPPROTO_TCP {
        if (p.flags & FLAG_IS_FORWARD) != 0 {
            tcprt::track_tcp_rt_v4(ct_key, info, p.now, true);
        } else {
            tcprt::track_tcp_rt_v4_rev(info, p.now);
        }
    }

    let need_ids = (p.flags & FLAG_QOS_ON) != 0 || stats::monitoring_enabled();
    if need_ids {
        p.src_id = lookup_ipv4(&SRC_IPV4_TRIE, info.src_ip).unwrap_or(0);
        p.dst_id = lookup_ipv4(&DST_IPV4_TRIE, info.dst_ip).unwrap_or(0);
        if (p.flags & FLAG_QOS_ON) != 0 && !qos::apply_qos_ingress(p.src_id, p.dst_id, p.pkt_len, p.now) {
            p.drop_reason = DROP_QOS_INGRESS;
            p.action = XDP_DROP;
            do_drop(p);
            if tracing { do_trace(info, p, TRACE_XDP_DROP, TRACE_RESULT_DROP_QOS); }
            return;
        }
        stats::update_group_stats(p.src_id, DIR_EGRESS, p.pkt_len);
        stats::update_group_stats(p.dst_id, DIR_INGRESS, p.pkt_len);
        if tracing { do_trace(info, p, TRACE_XDP_INGRESS, TRACE_RESULT_PASS); }
    } else if tracing {
        do_trace(info, p, TRACE_XDP_INGRESS, TRACE_RESULT_PASS);
    }
    p.action = XDP_PASS;
}

/// CT fast-path for XDP ingress IPv6.
#[inline(never)]
unsafe fn phase_ct_fastpath_xdp_v6(info: &parser::PacketInfo, p: &mut PipelineCtx, ct_key: &CtKey6) {
    let tracing = (p.flags & FLAG_TRACING) != 0;
    let matched = get_matched(p);
    stats::update_rule_stats(&matched.to_policy_key(), p.pkt_len, false);
    stats::update_flow_stats_v6(ct_key, p.pkt_len, p.now);

    if (p.flags & FLAG_TCPRT_ON) != 0 && info.proto == IPPROTO_TCP {
        if (p.flags & FLAG_IS_FORWARD) != 0 {
            tcprt::track_tcp_rt_v6(ct_key, info, p.now, true);
        } else {
            tcprt::track_tcp_rt_v6_rev(info, p.now);
        }
    }

    let need_ids = (p.flags & FLAG_QOS_ON) != 0 || stats::monitoring_enabled();
    if need_ids {
        p.src_id = lookup_ipv6(&SRC_IPV6_TRIE, info.src_ip_v6).unwrap_or(0);
        p.dst_id = lookup_ipv6(&DST_IPV6_TRIE, info.dst_ip_v6).unwrap_or(0);
        if (p.flags & FLAG_QOS_ON) != 0 && !qos::apply_qos_ingress(p.src_id, p.dst_id, p.pkt_len, p.now) {
            p.drop_reason = DROP_QOS_INGRESS;
            p.action = XDP_DROP;
            do_drop(p);
            if tracing { do_trace(info, p, TRACE_XDP_DROP, TRACE_RESULT_DROP_QOS); }
            return;
        }
        stats::update_group_stats(p.src_id, DIR_EGRESS, p.pkt_len);
        stats::update_group_stats(p.dst_id, DIR_INGRESS, p.pkt_len);
        if tracing { do_trace(info, p, TRACE_XDP_INGRESS, TRACE_RESULT_PASS); }
    } else if tracing {
        do_trace(info, p, TRACE_XDP_INGRESS, TRACE_RESULT_PASS);
    }
    p.action = XDP_PASS;
}

/// CT fast-path for TC egress IPv4 (LEAF — no sub-calls to #[inline(never)]).
#[inline(never)]
unsafe fn phase_ct_fastpath_tc_v4(ctx: &TcContext, info: &parser::PacketInfo, p: &mut PipelineCtx, ct_key: &CtKey4) {
    let tracing = (p.flags & FLAG_TRACING) != 0;
    let matched = get_matched(p);
    stats::update_rule_stats(&matched.to_policy_key(), p.pkt_len, false);
    stats::update_flow_stats_v4(ct_key, p.pkt_len, p.now);

    if (p.flags & FLAG_TCPRT_ON) != 0 && info.proto == IPPROTO_TCP {
        if (p.flags & FLAG_IS_FORWARD) != 0 {
            tcprt::track_tcp_rt_v4(ct_key, info, p.now, true);
        } else {
            tcprt::track_tcp_rt_v4_rev(info, p.now);
        }
    }

    let need_ids = (p.flags & FLAG_QOS_ON) != 0 || (p.flags & FLAG_MIRROR_ON) != 0 || stats::monitoring_enabled();
    if need_ids {
        p.dst_id = lookup_ipv4(&DST_IPV4_TRIE, info.dst_ip).unwrap_or(0);
        p.src_id = lookup_ipv4(&SRC_IPV4_TRIE, info.src_ip).unwrap_or(0);
        if (p.flags & FLAG_QOS_ON) != 0 {
            let (edt, prio) = qos::apply_qos_egress(p.src_id, p.dst_id, p.pkt_len, p.now);
            if edt == u64::MAX {
                p.drop_reason = DROP_QOS_EGRESS;
                p.action = TC_ACT_SHOT as u32;
                do_drop(p);
                if tracing { do_trace(info, p, TRACE_TC_DROP, TRACE_RESULT_DROP_QOS); }
                return;
            }
            apply_edt_prio(ctx, edt, prio);
        }
        stats::update_group_stats(p.src_id, DIR_EGRESS, p.pkt_len);
        stats::update_group_stats(p.dst_id, DIR_INGRESS, p.pkt_len);
        if (p.flags & FLAG_MIRROR_ON) != 0 {
            let skb = ctx.as_ptr() as *mut __sk_buff;
            mirror::try_mirror_tc(skb, p.src_id, p.dst_id, info.proto, DIR_EGRESS, p.pkt_len);
        }
        if tracing { do_trace(info, p, TRACE_TC_EGRESS, TRACE_RESULT_PASS); }
    } else if tracing {
        do_trace(info, p, TRACE_TC_EGRESS, TRACE_RESULT_PASS);
    }
    p.action = TC_ACT_OK as u32;
}

/// CT fast-path for TC egress IPv6 (LEAF — no sub-calls to #[inline(never)]).
#[inline(never)]
unsafe fn phase_ct_fastpath_tc_v6(ctx: &TcContext, info: &parser::PacketInfo, p: &mut PipelineCtx, ct_key: &CtKey6) {
    let tracing = (p.flags & FLAG_TRACING) != 0;
    let matched = get_matched(p);
    stats::update_rule_stats(&matched.to_policy_key(), p.pkt_len, false);
    stats::update_flow_stats_v6(ct_key, p.pkt_len, p.now);

    if (p.flags & FLAG_TCPRT_ON) != 0 && info.proto == IPPROTO_TCP {
        if (p.flags & FLAG_IS_FORWARD) != 0 {
            tcprt::track_tcp_rt_v6(ct_key, info, p.now, true);
        } else {
            tcprt::track_tcp_rt_v6_rev(info, p.now);
        }
    }

    let need_ids = (p.flags & FLAG_QOS_ON) != 0 || (p.flags & FLAG_MIRROR_ON) != 0 || stats::monitoring_enabled();
    if need_ids {
        p.dst_id = lookup_ipv6(&DST_IPV6_TRIE, info.dst_ip_v6).unwrap_or(0);
        p.src_id = lookup_ipv6(&SRC_IPV6_TRIE, info.src_ip_v6).unwrap_or(0);
        if (p.flags & FLAG_QOS_ON) != 0 {
            let (edt, prio) = qos::apply_qos_egress(p.src_id, p.dst_id, p.pkt_len, p.now);
            if edt == u64::MAX {
                p.drop_reason = DROP_QOS_EGRESS;
                p.action = TC_ACT_SHOT as u32;
                do_drop(p);
                if tracing { do_trace(info, p, TRACE_TC_DROP, TRACE_RESULT_DROP_QOS); }
                return;
            }
            apply_edt_prio(ctx, edt, prio);
        }
        stats::update_group_stats(p.src_id, DIR_EGRESS, p.pkt_len);
        stats::update_group_stats(p.dst_id, DIR_INGRESS, p.pkt_len);
        if (p.flags & FLAG_MIRROR_ON) != 0 {
            let skb = ctx.as_ptr() as *mut __sk_buff;
            mirror::try_mirror_tc(skb, p.src_id, p.dst_id, info.proto, DIR_EGRESS, p.pkt_len);
        }
        if tracing { do_trace(info, p, TRACE_TC_EGRESS, TRACE_RESULT_PASS); }
    } else if tracing {
        do_trace(info, p, TRACE_TC_EGRESS, TRACE_RESULT_PASS);
    }
    p.action = TC_ACT_OK as u32;
}

/// Phase: Policy evaluation for XDP (sets p.action, p.drop_reason, p.matched_*).
#[inline(never)]
unsafe fn phase_policy_xdp(info: &parser::PacketInfo, p: &mut PipelineCtx) {
    let (result, drop_reason, matched) = policy::evaluate_policy(&policy::PolicyArgs {
        src_id: p.src_id, dst_id: p.dst_id, proto: info.proto,
        direction: p.direction, dst_port: info.dst_port, pkt_len: p.pkt_len, now: p.now,
    });
    p.action = result;
    p.drop_reason = drop_reason;
    set_matched(p, &matched);

    if result == XDP_DROP && (p.flags & FLAG_TRACING) != 0 {
        let trace_result = match drop_reason { 1 => 1, 2 => 2, 3 => 3, _ => 1 };
        do_trace(info, p, TRACE_XDP_DROP, trace_result);
    }
}

/// Phase: Policy evaluation for TC.
#[inline(never)]
unsafe fn phase_policy_tc(info: &parser::PacketInfo, p: &mut PipelineCtx) {
    let (result, drop_reason, matched) = policy::evaluate_policy(&policy::PolicyArgs {
        src_id: p.src_id, dst_id: p.dst_id, proto: info.proto,
        direction: p.direction, dst_port: info.dst_port, pkt_len: p.pkt_len, now: p.now,
    });
    p.drop_reason = drop_reason;
    set_matched(p, &matched);

    if result == XDP_PASS {
        p.action = TC_ACT_OK as u32;
    } else {
        p.action = TC_ACT_SHOT as u32;
        if (p.flags & FLAG_TRACING) != 0 {
            let trace_result = match drop_reason { 1 => 1, 2 => 2, 3 => 3, _ => 1 };
            do_trace(info, p, TRACE_TC_DROP, trace_result);
        }
    }
}

/// Phase: Flow stats + TCP-RT for IPv4.
#[inline(never)]
unsafe fn phase_flow_tcprt_v4(info: &parser::PacketInfo, p: &mut PipelineCtx, ct_key: &CtKey4) {
    stats::update_flow_stats_v4(ct_key, p.pkt_len, p.now);
    if (p.flags & FLAG_TCPRT_ON) != 0 && info.proto == IPPROTO_TCP {
        tcprt::track_tcp_rt_v4(ct_key, info, p.now, true);
    }
}

/// Phase: Flow stats + TCP-RT for IPv6.
#[inline(never)]
unsafe fn phase_flow_tcprt_v6(info: &parser::PacketInfo, p: &mut PipelineCtx, ct_key: &CtKey6) {
    stats::update_flow_stats_v6(ct_key, p.pkt_len, p.now);
    if (p.flags & FLAG_TCPRT_ON) != 0 && info.proto == IPPROTO_TCP {
        tcprt::track_tcp_rt_v6(ct_key, info, p.now, true);
    }
}

/// Phase: QoS ingress check for XDP. Sets p.action = XDP_DROP if rate-limited.
#[inline(never)]
unsafe fn phase_qos_ingress_xdp(info: &parser::PacketInfo, p: &mut PipelineCtx) {
    if !qos::apply_qos_ingress(p.src_id, p.dst_id, p.pkt_len, p.now) {
        p.drop_reason = DROP_QOS_INGRESS;
        p.action = XDP_DROP;
        do_drop(p);
        if (p.flags & FLAG_TRACING) != 0 {
            do_trace(info, p, TRACE_XDP_DROP, TRACE_RESULT_DROP_QOS);
        }
    }
}

/// Phase: QoS egress for TC. Sets p.action = TC_ACT_SHOT if dropped.
#[inline(never)]
unsafe fn phase_qos_egress_tc(ctx: &TcContext, info: &parser::PacketInfo, p: &mut PipelineCtx) {
    let (edt, prio) = qos::apply_qos_egress(p.src_id, p.dst_id, p.pkt_len, p.now);
    if edt == u64::MAX {
        p.drop_reason = DROP_QOS_EGRESS;
        p.action = TC_ACT_SHOT as u32;
        do_drop(p);
        if (p.flags & FLAG_TRACING) != 0 {
            do_trace(info, p, TRACE_TC_DROP, TRACE_RESULT_DROP_QOS);
        }
        return;
    }
    apply_edt_prio(ctx, edt, prio);
}

/// Phase: Post-accept for XDP ingress IPv4 (group stats, CT create, trace).
#[inline(never)]
unsafe fn phase_post_accept_xdp_v4(info: &parser::PacketInfo, p: &mut PipelineCtx, ct_key: &CtKey4) {
    stats::update_group_stats(p.src_id, DIR_EGRESS, p.pkt_len);
    stats::update_group_stats(p.dst_id, DIR_INGRESS, p.pkt_len);
    if (p.flags & FLAG_ACL_ON) != 0 {
        let matched = get_matched(p);
        conntrack::ct_create_v4(ct_key, p.now, p.pkt_len, &matched);
        p.ct_state = 1;
    }
    if (p.flags & FLAG_TRACING) != 0 {
        do_trace(info, p, TRACE_XDP_INGRESS, TRACE_RESULT_PASS);
    }
    p.action = XDP_PASS;
}

/// Phase: Post-accept for XDP ingress IPv6.
#[inline(never)]
unsafe fn phase_post_accept_xdp_v6(info: &parser::PacketInfo, p: &mut PipelineCtx, ct_key: &CtKey6) {
    stats::update_group_stats(p.src_id, DIR_EGRESS, p.pkt_len);
    stats::update_group_stats(p.dst_id, DIR_INGRESS, p.pkt_len);
    if (p.flags & FLAG_ACL_ON) != 0 {
        let matched = get_matched(p);
        conntrack::ct_create_v6(ct_key, p.now, p.pkt_len, &matched);
        p.ct_state = 1;
    }
    if (p.flags & FLAG_TRACING) != 0 {
        do_trace(info, p, TRACE_XDP_INGRESS, TRACE_RESULT_PASS);
    }
    p.action = XDP_PASS;
}

/// Phase: Post-accept for TC egress IPv4.
#[inline(never)]
unsafe fn phase_post_accept_tc_v4(ctx: &TcContext, info: &parser::PacketInfo, p: &mut PipelineCtx, ct_key: &CtKey4) {
    stats::update_group_stats(p.src_id, DIR_EGRESS, p.pkt_len);
    stats::update_group_stats(p.dst_id, DIR_INGRESS, p.pkt_len);
    if (p.flags & FLAG_MIRROR_ON) != 0 {
        let skb = ctx.as_ptr() as *mut __sk_buff;
        mirror::try_mirror_tc(skb, p.src_id, p.dst_id, info.proto, DIR_EGRESS, p.pkt_len);
    }
    if (p.flags & FLAG_ACL_ON) != 0 {
        let matched = get_matched(p);
        conntrack::ct_create_v4(ct_key, p.now, p.pkt_len, &matched);
        p.ct_state = 1;
    }
    if (p.flags & FLAG_TRACING) != 0 {
        do_trace(info, p, TRACE_TC_EGRESS, TRACE_RESULT_PASS);
    }
    p.action = TC_ACT_OK as u32;
}

/// Phase: Post-accept for TC egress IPv6.
#[inline(never)]
unsafe fn phase_post_accept_tc_v6(ctx: &TcContext, info: &parser::PacketInfo, p: &mut PipelineCtx, ct_key: &CtKey6) {
    stats::update_group_stats(p.src_id, DIR_EGRESS, p.pkt_len);
    stats::update_group_stats(p.dst_id, DIR_INGRESS, p.pkt_len);
    if (p.flags & FLAG_MIRROR_ON) != 0 {
        let skb = ctx.as_ptr() as *mut __sk_buff;
        mirror::try_mirror_tc(skb, p.src_id, p.dst_id, info.proto, DIR_EGRESS, p.pkt_len);
    }
    if (p.flags & FLAG_ACL_ON) != 0 {
        let matched = get_matched(p);
        conntrack::ct_create_v6(ct_key, p.now, p.pkt_len, &matched);
        p.ct_state = 1;
    }
    if (p.flags & FLAG_TRACING) != 0 {
        do_trace(info, p, TRACE_TC_EGRESS, TRACE_RESULT_PASS);
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
