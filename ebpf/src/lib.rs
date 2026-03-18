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
    let parsed = match parser::parse_eth_ipv4(data, data_end, 0) {
        Some(i) => i,
        None => match parser::parse_eth_ipv6(data, data_end, 0) {
            Some(i) => i,
            None => return XDP_PASS,
        },
    };
    let info = unsafe {
        let ptr = match maps::PKT_SCRATCH.get_ptr_mut(0) {
            Some(p) => p,
            None => return XDP_PASS,
        };
        *ptr = parsed;
        &*ptr
    };
    match unsafe { try_xdp_firewall(info, pkt_len) } {
        Ok(ret) => ret,
        Err(_) => XDP_PASS,
    }
}

#[inline(never)]
unsafe fn try_xdp_firewall(info: &parser::PacketInfo, pkt_len: u32) -> Result<u32, ()> {
    if info.is_ipv6 {
        return xdp_ingress_v6(info, pkt_len);
    }

    let now = bpf_ktime_get_ns();
    let qos_on = qos::qos_enabled();
    let tcprt_on = tcprt::tcprt_enabled();
    let tracing = trace::should_trace(info);

    let ct_key = CtKey4 {
        src_ip: info.src_ip,
        dst_ip: info.dst_ip,
        src_port: info.src_port,
        dst_port: info.dst_port,
        proto: info.proto,
        pad: [0; 3],
    };

    match conntrack::ct_lookup_v4(&ct_key, now, pkt_len) {
        CtLookupResult::Established(matched, is_forward) | CtLookupResult::SeenReply(matched, is_forward) => {
            stats::update_rule_stats(&matched.to_policy_key(), pkt_len);
            stats::update_flow_stats_v4(&ct_key, pkt_len, now);
            if tcprt_on && info.proto == IPPROTO_TCP {
                if is_forward {
                    tcprt::track_tcp_rt_v4(&ct_key, &info, now, true);
                } else {
                    let fwd_key = CtKey4 {
                        src_ip: info.dst_ip,
                        dst_ip: info.src_ip,
                        src_port: info.dst_port,
                        dst_port: info.src_port,
                        proto: info.proto,
                        pad: [0; 3],
                    };
                    tcprt::track_tcp_rt_v4(&fwd_key, &info, now, false);
                }
            }
            let need_ids = qos_on || stats::monitoring_enabled();
            if need_ids {
                let src_id = lookup_ipv4(&SRC_IPV4_TRIE, info.src_ip).unwrap_or(0);
                let dst_id = lookup_ipv4(&DST_IPV4_TRIE, info.dst_ip).unwrap_or(0);
                if qos_on && !qos::apply_qos_ingress(src_id, dst_id, pkt_len, now) {
                    drops::record_drop(DROP_QOS_INGRESS, DIR_INGRESS, info.proto, src_id, dst_id, pkt_len, now);
                    if tracing { trace::trace_event(&info, &trace::TraceArgs { hook: TRACE_XDP_DROP, result: TRACE_RESULT_DROP_QOS, direction: DIR_INGRESS, ct_state: 2, drop_reason: DROP_QOS_INGRESS, _pad: [0;3], src_id, dst_id, pkt_len, now }); }
                    return Ok(XDP_DROP);
                }
                // Group stats after QoS
                stats::update_group_stats(src_id, DIR_EGRESS, pkt_len);
                stats::update_group_stats(dst_id, DIR_INGRESS, pkt_len);
                if tracing { trace::trace_event(&info, &trace::TraceArgs { hook: TRACE_XDP_INGRESS, result: TRACE_RESULT_PASS, direction: DIR_INGRESS, ct_state: 2, drop_reason: 0, _pad: [0;3], src_id, dst_id, pkt_len, now }); }
            } else if tracing {
                trace::trace_event(&info, &trace::TraceArgs { hook: TRACE_XDP_INGRESS, result: TRACE_RESULT_PASS, direction: DIR_INGRESS, ct_state: 2, drop_reason: 0, _pad: [0;3], src_id: 0, dst_id: 0, pkt_len, now });
            }
            return Ok(XDP_PASS);
        }
        CtLookupResult::NotFound => {}
    }

    let src_id = lookup_ipv4(&SRC_IPV4_TRIE, info.src_ip).unwrap_or(0);
    let dst_id = lookup_ipv4(&DST_IPV4_TRIE, info.dst_ip).unwrap_or(0);

    if !policy::acl_enabled() {
        stats::update_flow_stats_v4(&ct_key, pkt_len, now);
        if tcprt_on && info.proto == IPPROTO_TCP {
            tcprt::track_tcp_rt_v4(&ct_key, &info, now, true);
        }
        if qos_on && !qos::apply_qos_ingress(src_id, dst_id, pkt_len, now) {
            drops::record_drop(DROP_QOS_INGRESS, DIR_INGRESS, info.proto, src_id, dst_id, pkt_len, now);
            if tracing { trace::trace_event(&info, &trace::TraceArgs { hook: TRACE_XDP_DROP, result: TRACE_RESULT_DROP_QOS, direction: DIR_INGRESS, ct_state: 0, drop_reason: DROP_QOS_INGRESS, _pad: [0;3], src_id, dst_id, pkt_len, now }); }
            return Ok(XDP_DROP);
        }
        stats::update_group_stats(src_id, DIR_EGRESS, pkt_len);
        stats::update_group_stats(dst_id, DIR_INGRESS, pkt_len);
        if tracing { trace::trace_event(&info, &trace::TraceArgs { hook: TRACE_XDP_INGRESS, result: TRACE_RESULT_PASS, direction: DIR_INGRESS, ct_state: 0, drop_reason: 0, _pad: [0;3], src_id, dst_id, pkt_len, now }); }
        return Ok(XDP_PASS);
    }

    let (result, drop_reason, matched) = policy::evaluate_policy(&policy::PolicyArgs { src_id, dst_id, proto: info.proto, direction: DIR_INGRESS, dst_port: info.dst_port, pkt_len, now });

    if result == XDP_PASS {
        stats::update_flow_stats_v4(&ct_key, pkt_len, now);
        if tcprt_on && info.proto == IPPROTO_TCP {
            tcprt::track_tcp_rt_v4(&ct_key, &info, now, true);
        }
        if qos_on && !qos::apply_qos_ingress(src_id, dst_id, pkt_len, now) {
            drops::record_drop(DROP_QOS_INGRESS, DIR_INGRESS, info.proto, src_id, dst_id, pkt_len, now);
            if tracing { trace::trace_event(&info, &trace::TraceArgs { hook: TRACE_XDP_DROP, result: TRACE_RESULT_DROP_QOS, direction: DIR_INGRESS, ct_state: 1, drop_reason: DROP_QOS_INGRESS, _pad: [0;3], src_id, dst_id, pkt_len, now }); }
            return Ok(XDP_DROP);
        }
        // Group stats after QoS
        stats::update_group_stats(src_id, DIR_EGRESS, pkt_len);
        stats::update_group_stats(dst_id, DIR_INGRESS, pkt_len);
        conntrack::ct_create_v4(&ct_key, now, pkt_len, &matched);
        if tracing { trace::trace_event(&info, &trace::TraceArgs { hook: TRACE_XDP_INGRESS, result: TRACE_RESULT_PASS, direction: DIR_INGRESS, ct_state: 1, drop_reason: 0, _pad: [0;3], src_id, dst_id, pkt_len, now }); }
    } else if tracing {
        let trace_result = match drop_reason { 1 => 1, 2 => 2, 3 => 3, _ => 1 };
        trace::trace_event(&info, &trace::TraceArgs { hook: TRACE_XDP_DROP, result: trace_result, direction: DIR_INGRESS, ct_state: 0, drop_reason, _pad: [0;3], src_id, dst_id, pkt_len, now });
    }

    Ok(result)
}

#[inline(never)]
unsafe fn xdp_ingress_v6(info: &parser::PacketInfo, pkt_len: u32) -> Result<u32, ()> {
    let now = bpf_ktime_get_ns();
    let qos_on = qos::qos_enabled();
    let tcprt_on = tcprt::tcprt_enabled();
    let tracing = trace::should_trace(info);

    let ct_key = CtKey6 {
        src_ip: info.src_ip_v6,
        dst_ip: info.dst_ip_v6,
        src_port: info.src_port,
        dst_port: info.dst_port,
        proto: info.proto,
        pad: [0; 3],
    };

    match conntrack::ct_lookup_v6(&ct_key, now, pkt_len) {
        CtLookupResult::Established(matched, is_forward) | CtLookupResult::SeenReply(matched, is_forward) => {
            stats::update_rule_stats(&matched.to_policy_key(), pkt_len);
            stats::update_flow_stats_v6(&ct_key, pkt_len, now);
            if tcprt_on && info.proto == IPPROTO_TCP {
                if is_forward {
                    tcprt::track_tcp_rt_v6(&ct_key, &info, now, true);
                } else {
                    let fwd_key = CtKey6 {
                        src_ip: info.dst_ip_v6,
                        dst_ip: info.src_ip_v6,
                        src_port: info.dst_port,
                        dst_port: info.src_port,
                        proto: info.proto,
                        pad: [0; 3],
                    };
                    tcprt::track_tcp_rt_v6(&fwd_key, &info, now, false);
                }
            }
            let need_ids = qos_on || stats::monitoring_enabled();
            if need_ids {
                let src_id = lookup_ipv6(&SRC_IPV6_TRIE, info.src_ip_v6).unwrap_or(0);
                let dst_id = lookup_ipv6(&DST_IPV6_TRIE, info.dst_ip_v6).unwrap_or(0);
                if qos_on && !qos::apply_qos_ingress(src_id, dst_id, pkt_len, now) {
                    drops::record_drop(DROP_QOS_INGRESS, DIR_INGRESS, info.proto, src_id, dst_id, pkt_len, now);
                    if tracing { trace::trace_event(&info, &trace::TraceArgs { hook: TRACE_XDP_DROP, result: TRACE_RESULT_DROP_QOS, direction: DIR_INGRESS, ct_state: 2, drop_reason: DROP_QOS_INGRESS, _pad: [0;3], src_id, dst_id, pkt_len, now }); }
                    return Ok(XDP_DROP);
                }
                // Group stats after QoS
                stats::update_group_stats(src_id, DIR_EGRESS, pkt_len);
                stats::update_group_stats(dst_id, DIR_INGRESS, pkt_len);
                if tracing { trace::trace_event(&info, &trace::TraceArgs { hook: TRACE_XDP_INGRESS, result: TRACE_RESULT_PASS, direction: DIR_INGRESS, ct_state: 2, drop_reason: 0, _pad: [0;3], src_id, dst_id, pkt_len, now }); }
            } else if tracing {
                trace::trace_event(&info, &trace::TraceArgs { hook: TRACE_XDP_INGRESS, result: TRACE_RESULT_PASS, direction: DIR_INGRESS, ct_state: 2, drop_reason: 0, _pad: [0;3], src_id: 0, dst_id: 0, pkt_len, now });
            }
            return Ok(XDP_PASS);
        }
        CtLookupResult::NotFound => {}
    }

    let src_id = lookup_ipv6(&SRC_IPV6_TRIE, info.src_ip_v6).unwrap_or(0);
    let dst_id = lookup_ipv6(&DST_IPV6_TRIE, info.dst_ip_v6).unwrap_or(0);

    if !policy::acl_enabled() {
        stats::update_flow_stats_v6(&ct_key, pkt_len, now);
        if tcprt_on && info.proto == IPPROTO_TCP {
            tcprt::track_tcp_rt_v6(&ct_key, &info, now, true);
        }
        if qos_on && !qos::apply_qos_ingress(src_id, dst_id, pkt_len, now) {
            drops::record_drop(DROP_QOS_INGRESS, DIR_INGRESS, info.proto, src_id, dst_id, pkt_len, now);
            if tracing { trace::trace_event(&info, &trace::TraceArgs { hook: TRACE_XDP_DROP, result: TRACE_RESULT_DROP_QOS, direction: DIR_INGRESS, ct_state: 0, drop_reason: DROP_QOS_INGRESS, _pad: [0;3], src_id, dst_id, pkt_len, now }); }
            return Ok(XDP_DROP);
        }
        stats::update_group_stats(src_id, DIR_EGRESS, pkt_len);
        stats::update_group_stats(dst_id, DIR_INGRESS, pkt_len);
        if tracing { trace::trace_event(&info, &trace::TraceArgs { hook: TRACE_XDP_INGRESS, result: TRACE_RESULT_PASS, direction: DIR_INGRESS, ct_state: 0, drop_reason: 0, _pad: [0;3], src_id, dst_id, pkt_len, now }); }
        return Ok(XDP_PASS);
    }

    let (result, drop_reason, matched) = policy::evaluate_policy(&policy::PolicyArgs { src_id, dst_id, proto: info.proto, direction: DIR_INGRESS, dst_port: info.dst_port, pkt_len, now });

    if result == XDP_PASS {
        stats::update_flow_stats_v6(&ct_key, pkt_len, now);
        if tcprt_on && info.proto == IPPROTO_TCP {
            tcprt::track_tcp_rt_v6(&ct_key, &info, now, true);
        }
        if qos_on && !qos::apply_qos_ingress(src_id, dst_id, pkt_len, now) {
            drops::record_drop(DROP_QOS_INGRESS, DIR_INGRESS, info.proto, src_id, dst_id, pkt_len, now);
            if tracing { trace::trace_event(&info, &trace::TraceArgs { hook: TRACE_XDP_DROP, result: TRACE_RESULT_DROP_QOS, direction: DIR_INGRESS, ct_state: 1, drop_reason: DROP_QOS_INGRESS, _pad: [0;3], src_id, dst_id, pkt_len, now }); }
            return Ok(XDP_DROP);
        }
        // Group stats after QoS
        stats::update_group_stats(src_id, DIR_EGRESS, pkt_len);
        stats::update_group_stats(dst_id, DIR_INGRESS, pkt_len);
        conntrack::ct_create_v6(&ct_key, now, pkt_len, &matched);
        if tracing { trace::trace_event(&info, &trace::TraceArgs { hook: TRACE_XDP_INGRESS, result: TRACE_RESULT_PASS, direction: DIR_INGRESS, ct_state: 1, drop_reason: 0, _pad: [0;3], src_id, dst_id, pkt_len, now }); }
    } else if tracing {
        let trace_result = match drop_reason { 1 => 1, 2 => 2, 3 => 3, _ => 1 };
        trace::trace_event(&info, &trace::TraceArgs { hook: TRACE_XDP_DROP, result: trace_result, direction: DIR_INGRESS, ct_state: 0, drop_reason, _pad: [0;3], src_id, dst_id, pkt_len, now });
    }

    Ok(result)
}

// --- TC Egress ---

#[classifier]
pub fn tc_egress(ctx: TcContext) -> i32 {
    let data = ctx.data();
    let data_end = ctx.data_end();
    let pkt_len = ctx.len();
    let parsed = match parser::parse_eth_ipv4(data, data_end, 0) {
        Some(i) => i,
        None => match parser::parse_eth_ipv6(data, data_end, 0) {
            Some(i) => i,
            None => return TC_ACT_OK,
        },
    };
    let info = unsafe {
        let ptr = match maps::PKT_SCRATCH.get_ptr_mut(0) {
            Some(p) => p,
            None => return TC_ACT_OK,
        };
        *ptr = parsed;
        &*ptr
    };
    match unsafe { try_tc_egress(&ctx, info, pkt_len) } {
        Ok(ret) => ret,
        Err(_) => TC_ACT_OK,
    }
}

#[inline(never)]
unsafe fn try_tc_egress(ctx: &TcContext, info: &parser::PacketInfo, pkt_len: u32) -> Result<i32, ()> {
    if info.is_ipv6 {
        return tc_egress_v6(ctx, info, pkt_len);
    }

    let now = bpf_ktime_get_ns();
    let qos_on = qos::qos_enabled();
    let mirror_on = mirror::mirror_enabled();
    let tcprt_on = tcprt::tcprt_enabled();
    let tracing = trace::should_trace(&info);

    let ct_key = CtKey4 {
        src_ip: info.src_ip,
        dst_ip: info.dst_ip,
        src_port: info.src_port,
        dst_port: info.dst_port,
        proto: info.proto,
        pad: [0; 3],
    };

    match conntrack::ct_lookup_v4(&ct_key, now, pkt_len) {
        CtLookupResult::Established(matched, is_forward) | CtLookupResult::SeenReply(matched, is_forward) => {
            stats::update_rule_stats(&matched.to_policy_key(), pkt_len);
            stats::update_flow_stats_v4(&ct_key, pkt_len, now);
            if tcprt_on && info.proto == IPPROTO_TCP {
                if is_forward {
                    tcprt::track_tcp_rt_v4(&ct_key, &info, now, true);
                } else {
                    let fwd_key = CtKey4 {
                        src_ip: info.dst_ip,
                        dst_ip: info.src_ip,
                        src_port: info.dst_port,
                        dst_port: info.src_port,
                        proto: info.proto,
                        pad: [0; 3],
                    };
                    tcprt::track_tcp_rt_v4(&fwd_key, &info, now, false);
                }
            }
            let need_ids = qos_on || mirror_on || stats::monitoring_enabled();
            if need_ids {
                let dst_id = lookup_ipv4(&DST_IPV4_TRIE, info.dst_ip).unwrap_or(0);
                let src_id = lookup_ipv4(&SRC_IPV4_TRIE, info.src_ip).unwrap_or(0);
                if qos_on {
                    if let Some(action) = apply_egress_qos(&ctx, &info, src_id, dst_id, info.proto, pkt_len, now, tracing) {
                        return Ok(action);
                    }
                }
                // Group stats after QoS
                stats::update_group_stats(src_id, DIR_EGRESS, pkt_len);
                stats::update_group_stats(dst_id, DIR_INGRESS, pkt_len);
                if mirror_on {
                    let skb = ctx.as_ptr() as *mut __sk_buff;
                    mirror::try_mirror_tc(skb, src_id, dst_id, info.proto, DIR_EGRESS, pkt_len);
                }
                if tracing { trace::trace_event(&info, &trace::TraceArgs { hook: TRACE_TC_EGRESS, result: TRACE_RESULT_PASS, direction: DIR_EGRESS, ct_state: 2, drop_reason: 0, _pad: [0;3], src_id, dst_id, pkt_len, now }); }
            } else if tracing {
                trace::trace_event(&info, &trace::TraceArgs { hook: TRACE_TC_EGRESS, result: TRACE_RESULT_PASS, direction: DIR_EGRESS, ct_state: 2, drop_reason: 0, _pad: [0;3], src_id: 0, dst_id: 0, pkt_len, now });
            }
            return Ok(TC_ACT_OK);
        }
        CtLookupResult::NotFound => {}
    }

    let src_id = lookup_ipv4(&SRC_IPV4_TRIE, info.src_ip).unwrap_or(0);
    let dst_id = lookup_ipv4(&DST_IPV4_TRIE, info.dst_ip).unwrap_or(0);

    if !policy::acl_enabled() {
        stats::update_flow_stats_v4(&ct_key, pkt_len, now);
        if tcprt_on && info.proto == IPPROTO_TCP {
            tcprt::track_tcp_rt_v4(&ct_key, &info, now, true);
        }
        if qos_on {
            if let Some(action) = apply_egress_qos(&ctx, &info, src_id, dst_id, info.proto, pkt_len, now, tracing) {
                return Ok(action);
            }
        }
        stats::update_group_stats(src_id, DIR_EGRESS, pkt_len);
        stats::update_group_stats(dst_id, DIR_INGRESS, pkt_len);
        if mirror_on {
            let skb = ctx.as_ptr() as *mut __sk_buff;
            mirror::try_mirror_tc(skb, src_id, dst_id, info.proto, DIR_EGRESS, pkt_len);
        }
        if tracing { trace::trace_event(&info, &trace::TraceArgs { hook: TRACE_TC_EGRESS, result: TRACE_RESULT_PASS, direction: DIR_EGRESS, ct_state: 0, drop_reason: 0, _pad: [0;3], src_id, dst_id, pkt_len, now }); }
        return Ok(TC_ACT_OK);
    }

    let (result, drop_reason, matched) = policy::evaluate_policy_tc(
        &policy::PolicyArgs { src_id, dst_id, proto: info.proto, direction: DIR_EGRESS, dst_port: info.dst_port, pkt_len, now }, TC_ACT_OK, TC_ACT_SHOT,
    );

    if result == TC_ACT_OK {
        stats::update_flow_stats_v4(&ct_key, pkt_len, now);
        if tcprt_on && info.proto == IPPROTO_TCP {
            tcprt::track_tcp_rt_v4(&ct_key, &info, now, true);
        }
        if qos_on {
            if let Some(action) = apply_egress_qos(&ctx, &info, src_id, dst_id, info.proto, pkt_len, now, tracing) {
                return Ok(action);
            }
        }
        // Group stats after QoS
        stats::update_group_stats(src_id, DIR_EGRESS, pkt_len);
        stats::update_group_stats(dst_id, DIR_INGRESS, pkt_len);
        if mirror_on {
            let skb = ctx.as_ptr() as *mut __sk_buff;
            mirror::try_mirror_tc(skb, src_id, dst_id, info.proto, DIR_EGRESS, pkt_len);
        }
        conntrack::ct_create_v4(&ct_key, now, pkt_len, &matched);
        if tracing { trace::trace_event(&info, &trace::TraceArgs { hook: TRACE_TC_EGRESS, result: TRACE_RESULT_PASS, direction: DIR_EGRESS, ct_state: 1, drop_reason: 0, _pad: [0;3], src_id, dst_id, pkt_len, now }); }
    } else if tracing {
        let trace_result = match drop_reason { 1 => 1, 2 => 2, 3 => 3, _ => 1 };
        trace::trace_event(&info, &trace::TraceArgs { hook: TRACE_TC_DROP, result: trace_result, direction: DIR_EGRESS, ct_state: 0, drop_reason, _pad: [0;3], src_id, dst_id, pkt_len, now });
    }

    Ok(result)
}

#[inline(never)]
unsafe fn tc_egress_v6(ctx: &TcContext, info: &parser::PacketInfo, pkt_len: u32) -> Result<i32, ()> {
    let now = bpf_ktime_get_ns();
    let qos_on = qos::qos_enabled();
    let mirror_on = mirror::mirror_enabled();
    let tcprt_on = tcprt::tcprt_enabled();
    let tracing = trace::should_trace(&info);

    let ct_key = CtKey6 {
        src_ip: info.src_ip_v6,
        dst_ip: info.dst_ip_v6,
        src_port: info.src_port,
        dst_port: info.dst_port,
        proto: info.proto,
        pad: [0; 3],
    };

    match conntrack::ct_lookup_v6(&ct_key, now, pkt_len) {
        CtLookupResult::Established(matched, is_forward) | CtLookupResult::SeenReply(matched, is_forward) => {
            stats::update_rule_stats(&matched.to_policy_key(), pkt_len);
            stats::update_flow_stats_v6(&ct_key, pkt_len, now);
            if tcprt_on && info.proto == IPPROTO_TCP {
                if is_forward {
                    tcprt::track_tcp_rt_v6(&ct_key, &info, now, true);
                } else {
                    let fwd_key = CtKey6 {
                        src_ip: info.dst_ip_v6,
                        dst_ip: info.src_ip_v6,
                        src_port: info.dst_port,
                        dst_port: info.src_port,
                        proto: info.proto,
                        pad: [0; 3],
                    };
                    tcprt::track_tcp_rt_v6(&fwd_key, &info, now, false);
                }
            }
            let need_ids = qos_on || mirror_on || stats::monitoring_enabled();
            if need_ids {
                let dst_id = lookup_ipv6(&DST_IPV6_TRIE, info.dst_ip_v6).unwrap_or(0);
                let src_id = lookup_ipv6(&SRC_IPV6_TRIE, info.src_ip_v6).unwrap_or(0);
                if qos_on {
                    if let Some(action) = apply_egress_qos(&ctx, &info, src_id, dst_id, info.proto, pkt_len, now, tracing) {
                        return Ok(action);
                    }
                }
                // Group stats after QoS
                stats::update_group_stats(src_id, DIR_EGRESS, pkt_len);
                stats::update_group_stats(dst_id, DIR_INGRESS, pkt_len);
                if mirror_on {
                    let skb = ctx.as_ptr() as *mut __sk_buff;
                    mirror::try_mirror_tc(skb, src_id, dst_id, info.proto, DIR_EGRESS, pkt_len);
                }
                if tracing { trace::trace_event(&info, &trace::TraceArgs { hook: TRACE_TC_EGRESS, result: TRACE_RESULT_PASS, direction: DIR_EGRESS, ct_state: 2, drop_reason: 0, _pad: [0;3], src_id, dst_id, pkt_len, now }); }
            } else if tracing {
                trace::trace_event(&info, &trace::TraceArgs { hook: TRACE_TC_EGRESS, result: TRACE_RESULT_PASS, direction: DIR_EGRESS, ct_state: 2, drop_reason: 0, _pad: [0;3], src_id: 0, dst_id: 0, pkt_len, now });
            }
            return Ok(TC_ACT_OK);
        }
        CtLookupResult::NotFound => {}
    }

    let src_id = lookup_ipv6(&SRC_IPV6_TRIE, info.src_ip_v6).unwrap_or(0);
    let dst_id = lookup_ipv6(&DST_IPV6_TRIE, info.dst_ip_v6).unwrap_or(0);

    if !policy::acl_enabled() {
        stats::update_flow_stats_v6(&ct_key, pkt_len, now);
        if tcprt_on && info.proto == IPPROTO_TCP {
            tcprt::track_tcp_rt_v6(&ct_key, &info, now, true);
        }
        if qos_on {
            if let Some(action) = apply_egress_qos(&ctx, &info, src_id, dst_id, info.proto, pkt_len, now, tracing) {
                return Ok(action);
            }
        }
        stats::update_group_stats(src_id, DIR_EGRESS, pkt_len);
        stats::update_group_stats(dst_id, DIR_INGRESS, pkt_len);
        if mirror_on {
            let skb = ctx.as_ptr() as *mut __sk_buff;
            mirror::try_mirror_tc(skb, src_id, dst_id, info.proto, DIR_EGRESS, pkt_len);
        }
        if tracing { trace::trace_event(&info, &trace::TraceArgs { hook: TRACE_TC_EGRESS, result: TRACE_RESULT_PASS, direction: DIR_EGRESS, ct_state: 0, drop_reason: 0, _pad: [0;3], src_id, dst_id, pkt_len, now }); }
        return Ok(TC_ACT_OK);
    }

    let (result, drop_reason, matched) = policy::evaluate_policy_tc(
        &policy::PolicyArgs { src_id, dst_id, proto: info.proto, direction: DIR_EGRESS, dst_port: info.dst_port, pkt_len, now }, TC_ACT_OK, TC_ACT_SHOT,
    );

    if result == TC_ACT_OK {
        stats::update_flow_stats_v6(&ct_key, pkt_len, now);
        if tcprt_on && info.proto == IPPROTO_TCP {
            tcprt::track_tcp_rt_v6(&ct_key, &info, now, true);
        }
        if qos_on {
            if let Some(action) = apply_egress_qos(&ctx, &info, src_id, dst_id, info.proto, pkt_len, now, tracing) {
                return Ok(action);
            }
        }
        // Group stats after QoS
        stats::update_group_stats(src_id, DIR_EGRESS, pkt_len);
        stats::update_group_stats(dst_id, DIR_INGRESS, pkt_len);
        if mirror_on {
            let skb = ctx.as_ptr() as *mut __sk_buff;
            mirror::try_mirror_tc(skb, src_id, dst_id, info.proto, DIR_EGRESS, pkt_len);
        }
        conntrack::ct_create_v6(&ct_key, now, pkt_len, &matched);
        if tracing { trace::trace_event(&info, &trace::TraceArgs { hook: TRACE_TC_EGRESS, result: TRACE_RESULT_PASS, direction: DIR_EGRESS, ct_state: 1, drop_reason: 0, _pad: [0;3], src_id, dst_id, pkt_len, now }); }
    } else if tracing {
        let trace_result = match drop_reason { 1 => 1, 2 => 2, 3 => 3, _ => 1 };
        trace::trace_event(&info, &trace::TraceArgs { hook: TRACE_TC_DROP, result: trace_result, direction: DIR_EGRESS, ct_state: 0, drop_reason, _pad: [0;3], src_id, dst_id, pkt_len, now });
    }

    Ok(result)
}

// --- TC Ingress (mirror only) ---

#[classifier]
pub fn tc_ingress(ctx: TcContext) -> i32 {
    let data = ctx.data();
    let data_end = ctx.data_end();
    let pkt_len = ctx.len();
    let parsed = match parser::parse_eth_ipv4(data, data_end, 0) {
        Some(i) => i,
        None => match parser::parse_eth_ipv6(data, data_end, 0) {
            Some(i) => i,
            None => return TC_ACT_OK,
        },
    };
    let info = unsafe {
        let ptr = match maps::PKT_SCRATCH.get_ptr_mut(0) {
            Some(p) => p,
            None => return TC_ACT_OK,
        };
        *ptr = parsed;
        &*ptr
    };
    match unsafe { try_tc_ingress(&ctx, info, pkt_len) } {
        Ok(ret) => ret,
        Err(_) => TC_ACT_OK,
    }
}

#[inline(never)]
unsafe fn try_tc_ingress(ctx: &TcContext, info: &parser::PacketInfo, pkt_len: u32) -> Result<i32, ()> {
    let tracing = trace::should_trace(info);

    let (src_id, dst_id) = if info.is_ipv6 {
        let s = lookup_ipv6(&SRC_IPV6_TRIE, info.src_ip_v6).unwrap_or(0);
        let d = lookup_ipv6(&DST_IPV6_TRIE, info.dst_ip_v6).unwrap_or(0);
        (s, d)
    } else {
        let s = lookup_ipv4(&SRC_IPV4_TRIE, info.src_ip).unwrap_or(0);
        let d = lookup_ipv4(&DST_IPV4_TRIE, info.dst_ip).unwrap_or(0);
        (s, d)
    };

    if mirror::mirror_enabled() {
        let skb = ctx.as_ptr() as *mut __sk_buff;
        mirror::try_mirror_tc(skb, src_id, dst_id, info.proto, DIR_INGRESS, pkt_len);
    }

    if tracing {
        let now = bpf_ktime_get_ns();
        trace::trace_event(&info, &trace::TraceArgs { hook: TRACE_TC_INGRESS, result: TRACE_RESULT_PASS, direction: DIR_INGRESS, ct_state: 0, drop_reason: 0, _pad: [0;3], src_id, dst_id, pkt_len, now });
    }

    Ok(TC_ACT_OK)
}

// --- Helpers ---

#[inline(always)]
unsafe fn apply_egress_qos(ctx: &TcContext, info: &parser::PacketInfo, src_id: u32, dst_id: u32, proto: u8, pkt_len: u32, now: u64, tracing: bool) -> Option<i32> {
    let (edt, prio) = qos::apply_qos_egress(src_id, dst_id, pkt_len, now);
    if edt == u64::MAX {
        drops::record_drop(DROP_QOS_EGRESS, DIR_EGRESS, proto, src_id, dst_id, pkt_len, now);
        if tracing { trace::trace_event(info, &trace::TraceArgs { hook: TRACE_TC_DROP, result: TRACE_RESULT_DROP_QOS, direction: DIR_EGRESS, ct_state: 0, drop_reason: DROP_QOS_EGRESS, _pad: [0;3], src_id, dst_id, pkt_len, now }); }
        return Some(TC_ACT_SHOT);
    }
    if edt != 0 || prio != 0 {
        let skb = ctx.as_ptr() as *mut __sk_buff;
        if edt != 0 {
            (*skb).tstamp = edt;
        }
        if prio != 0 {
            (*skb).priority = prio as u32;
        }
    }
    None
}

unsafe fn lookup_ipv4(map: &LpmTrie<[u8; 4], u32>, ip: u32) -> Option<u32> {
    let key = Key::new(32, ip.to_be_bytes());
    map.get(&key).copied()
}

unsafe fn lookup_ipv6(map: &LpmTrie<[u8; 16], u32>, ip: [u8; 16]) -> Option<u32> {
    let key = Key::new(128, ip);
    map.get(&key).copied()
}
