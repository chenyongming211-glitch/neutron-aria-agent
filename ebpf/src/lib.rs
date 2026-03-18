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
pub unsafe fn xdp_firewall(ctx: XdpContext) -> u32 {
    let data = ctx.data();
    let data_end = ctx.data_end();
    let pkt_len = (data_end - data) as u32;

    let info = match parser::parse_eth_ipv4(data, data_end, 0) {
        Some(i) => i,
        None => match parser::parse_eth_ipv6(data, data_end, 0) {
            Some(i) => i,
            None => return XDP_PASS,
        },
    };

    let now = bpf_ktime_get_ns();
    let qos_on = qos::qos_enabled();
    let tcprt_on = tcprt::tcprt_enabled();

    let tracing = trace::should_trace(&info);

    if info.is_ipv6 {
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
                        if tracing { trace::trace_event(&info, TRACE_XDP_DROP, TRACE_RESULT_DROP_QOS, DIR_INGRESS, src_id, dst_id, pkt_len, 2, DROP_QOS_INGRESS, now); }
                        return XDP_DROP;
                    }
                    // Group stats after QoS — only count packets that actually pass
                    stats::update_group_stats(src_id, DIR_EGRESS, pkt_len);
                    stats::update_group_stats(dst_id, DIR_INGRESS, pkt_len);
                    if tracing { trace::trace_event(&info, TRACE_XDP_INGRESS, TRACE_RESULT_PASS, DIR_INGRESS, src_id, dst_id, pkt_len, 2, 0, now); }
                } else if tracing {
                    trace::trace_event(&info, TRACE_XDP_INGRESS, TRACE_RESULT_PASS, DIR_INGRESS, 0, 0, pkt_len, 2, 0, now);
                }
                return XDP_PASS;
            }
            CtLookupResult::NotFound => {}
        }

        let src_id = lookup_ipv6(&SRC_IPV6_TRIE, info.src_ip_v6).unwrap_or(0);
        let dst_id = lookup_ipv6(&DST_IPV6_TRIE, info.dst_ip_v6).unwrap_or(0);

        if !policy::acl_enabled() {
            // ACL disabled: skip policy evaluation, still do QoS and group stats
            stats::update_flow_stats_v6(&ct_key, pkt_len, now);
            if tcprt_on && info.proto == IPPROTO_TCP {
                tcprt::track_tcp_rt_v6(&ct_key, &info, now, true);
            }
            if qos_on && !qos::apply_qos_ingress(src_id, dst_id, pkt_len, now) {
                drops::record_drop(DROP_QOS_INGRESS, DIR_INGRESS, info.proto, src_id, dst_id, pkt_len, now);
                if tracing { trace::trace_event(&info, TRACE_XDP_DROP, TRACE_RESULT_DROP_QOS, DIR_INGRESS, src_id, dst_id, pkt_len, 0, DROP_QOS_INGRESS, now); }
                return XDP_DROP;
            }
            stats::update_group_stats(src_id, DIR_EGRESS, pkt_len);
            stats::update_group_stats(dst_id, DIR_INGRESS, pkt_len);
            if tracing { trace::trace_event(&info, TRACE_XDP_INGRESS, TRACE_RESULT_PASS, DIR_INGRESS, src_id, dst_id, pkt_len, 0, 0, now); }
            return XDP_PASS;
        }

        let (result, drop_reason, matched) = policy::evaluate_policy(src_id, dst_id, info.proto, DIR_INGRESS, info.dst_port, pkt_len, now);

        if result == XDP_PASS {
            stats::update_flow_stats_v6(&ct_key, pkt_len, now);
            if tcprt_on && info.proto == IPPROTO_TCP {
                tcprt::track_tcp_rt_v6(&ct_key, &info, now, true);
            }
            if qos_on && !qos::apply_qos_ingress(src_id, dst_id, pkt_len, now) {
                drops::record_drop(DROP_QOS_INGRESS, DIR_INGRESS, info.proto, src_id, dst_id, pkt_len, now);
                if tracing { trace::trace_event(&info, TRACE_XDP_DROP, TRACE_RESULT_DROP_QOS, DIR_INGRESS, src_id, dst_id, pkt_len, 1, DROP_QOS_INGRESS, now); }
                return XDP_DROP;
            }
            // Group stats after QoS
            stats::update_group_stats(src_id, DIR_EGRESS, pkt_len);
            stats::update_group_stats(dst_id, DIR_INGRESS, pkt_len);
            conntrack::ct_create_v6(&ct_key, now, pkt_len, &matched);
            if tracing { trace::trace_event(&info, TRACE_XDP_INGRESS, TRACE_RESULT_PASS, DIR_INGRESS, src_id, dst_id, pkt_len, 1, 0, now); }
        } else if tracing {
            let trace_result = match drop_reason { 1 => 1, 2 => 2, 3 => 3, _ => 1 };
            trace::trace_event(&info, TRACE_XDP_DROP, trace_result, DIR_INGRESS, src_id, dst_id, pkt_len, 0, drop_reason, now);
        }

        result
    } else {
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
                        if tracing { trace::trace_event(&info, TRACE_XDP_DROP, TRACE_RESULT_DROP_QOS, DIR_INGRESS, src_id, dst_id, pkt_len, 2, DROP_QOS_INGRESS, now); }
                        return XDP_DROP;
                    }
                    // Group stats after QoS
                    stats::update_group_stats(src_id, DIR_EGRESS, pkt_len);
                    stats::update_group_stats(dst_id, DIR_INGRESS, pkt_len);
                    if tracing { trace::trace_event(&info, TRACE_XDP_INGRESS, TRACE_RESULT_PASS, DIR_INGRESS, src_id, dst_id, pkt_len, 2, 0, now); }
                } else if tracing {
                    trace::trace_event(&info, TRACE_XDP_INGRESS, TRACE_RESULT_PASS, DIR_INGRESS, 0, 0, pkt_len, 2, 0, now);
                }
                return XDP_PASS;
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
                if tracing { trace::trace_event(&info, TRACE_XDP_DROP, TRACE_RESULT_DROP_QOS, DIR_INGRESS, src_id, dst_id, pkt_len, 0, DROP_QOS_INGRESS, now); }
                return XDP_DROP;
            }
            stats::update_group_stats(src_id, DIR_EGRESS, pkt_len);
            stats::update_group_stats(dst_id, DIR_INGRESS, pkt_len);
            if tracing { trace::trace_event(&info, TRACE_XDP_INGRESS, TRACE_RESULT_PASS, DIR_INGRESS, src_id, dst_id, pkt_len, 0, 0, now); }
            return XDP_PASS;
        }

        let (result, drop_reason, matched) = policy::evaluate_policy(src_id, dst_id, info.proto, DIR_INGRESS, info.dst_port, pkt_len, now);

        if result == XDP_PASS {
            stats::update_flow_stats_v4(&ct_key, pkt_len, now);
            if tcprt_on && info.proto == IPPROTO_TCP {
                tcprt::track_tcp_rt_v4(&ct_key, &info, now, true);
            }
            if qos_on && !qos::apply_qos_ingress(src_id, dst_id, pkt_len, now) {
                drops::record_drop(DROP_QOS_INGRESS, DIR_INGRESS, info.proto, src_id, dst_id, pkt_len, now);
                if tracing { trace::trace_event(&info, TRACE_XDP_DROP, TRACE_RESULT_DROP_QOS, DIR_INGRESS, src_id, dst_id, pkt_len, 1, DROP_QOS_INGRESS, now); }
                return XDP_DROP;
            }
            // Group stats after QoS
            stats::update_group_stats(src_id, DIR_EGRESS, pkt_len);
            stats::update_group_stats(dst_id, DIR_INGRESS, pkt_len);
            conntrack::ct_create_v4(&ct_key, now, pkt_len, &matched);
            if tracing { trace::trace_event(&info, TRACE_XDP_INGRESS, TRACE_RESULT_PASS, DIR_INGRESS, src_id, dst_id, pkt_len, 1, 0, now); }
        } else if tracing {
            let trace_result = match drop_reason { 1 => 1, 2 => 2, 3 => 3, _ => 1 };
            trace::trace_event(&info, TRACE_XDP_DROP, trace_result, DIR_INGRESS, src_id, dst_id, pkt_len, 0, drop_reason, now);
        }

        result
    }
}

// --- TC Egress ---

#[classifier]
pub unsafe fn tc_egress(ctx: TcContext) -> i32 {
    let data = ctx.data();
    let data_end = ctx.data_end();
    let pkt_len = ctx.len();

    let info = match parser::parse_eth_ipv4(data, data_end, 0) {
        Some(i) => i,
        None => match parser::parse_eth_ipv6(data, data_end, 0) {
            Some(i) => i,
            None => return TC_ACT_OK,
        },
    };

    let now = bpf_ktime_get_ns();
    let qos_on = qos::qos_enabled();
    let mirror_on = mirror::mirror_enabled();
    let tcprt_on = tcprt::tcprt_enabled();
    let tracing = trace::should_trace(&info);

    if info.is_ipv6 {
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
                            return action;
                        }
                    }
                    // Group stats after QoS
                    stats::update_group_stats(src_id, DIR_EGRESS, pkt_len);
                    stats::update_group_stats(dst_id, DIR_INGRESS, pkt_len);
                    if mirror_on {
                        let skb = ctx.as_ptr() as *mut __sk_buff;
                        mirror::try_mirror_tc(skb, src_id, dst_id, info.proto, DIR_EGRESS, pkt_len);
                    }
                    if tracing { trace::trace_event(&info, TRACE_TC_EGRESS, TRACE_RESULT_PASS, DIR_EGRESS, src_id, dst_id, pkt_len, 2, 0, now); }
                } else if tracing {
                    trace::trace_event(&info, TRACE_TC_EGRESS, TRACE_RESULT_PASS, DIR_EGRESS, 0, 0, pkt_len, 2, 0, now);
                }
                return TC_ACT_OK;
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
                    return action;
                }
            }
            stats::update_group_stats(src_id, DIR_EGRESS, pkt_len);
            stats::update_group_stats(dst_id, DIR_INGRESS, pkt_len);
            if mirror_on {
                let skb = ctx.as_ptr() as *mut __sk_buff;
                mirror::try_mirror_tc(skb, src_id, dst_id, info.proto, DIR_EGRESS, pkt_len);
            }
            if tracing { trace::trace_event(&info, TRACE_TC_EGRESS, TRACE_RESULT_PASS, DIR_EGRESS, src_id, dst_id, pkt_len, 0, 0, now); }
            return TC_ACT_OK;
        }

        let (result, drop_reason, matched) = policy::evaluate_policy_tc(
            src_id, dst_id, info.proto, DIR_EGRESS, info.dst_port, pkt_len, TC_ACT_OK, TC_ACT_SHOT, now,
        );

        if result == TC_ACT_OK {
            stats::update_flow_stats_v6(&ct_key, pkt_len, now);
            if tcprt_on && info.proto == IPPROTO_TCP {
                tcprt::track_tcp_rt_v6(&ct_key, &info, now, true);
            }
            if qos_on {
                if let Some(action) = apply_egress_qos(&ctx, &info, src_id, dst_id, info.proto, pkt_len, now, tracing) {
                    return action;
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
            if tracing { trace::trace_event(&info, TRACE_TC_EGRESS, TRACE_RESULT_PASS, DIR_EGRESS, src_id, dst_id, pkt_len, 1, 0, now); }
        } else if tracing {
            let trace_result = match drop_reason { 1 => 1, 2 => 2, 3 => 3, _ => 1 };
            trace::trace_event(&info, TRACE_TC_DROP, trace_result, DIR_EGRESS, src_id, dst_id, pkt_len, 0, drop_reason, now);
        }

        result
    } else {
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
                            return action;
                        }
                    }
                    // Group stats after QoS
                    stats::update_group_stats(src_id, DIR_EGRESS, pkt_len);
                    stats::update_group_stats(dst_id, DIR_INGRESS, pkt_len);
                    if mirror_on {
                        let skb = ctx.as_ptr() as *mut __sk_buff;
                        mirror::try_mirror_tc(skb, src_id, dst_id, info.proto, DIR_EGRESS, pkt_len);
                    }
                    if tracing { trace::trace_event(&info, TRACE_TC_EGRESS, TRACE_RESULT_PASS, DIR_EGRESS, src_id, dst_id, pkt_len, 2, 0, now); }
                } else if tracing {
                    trace::trace_event(&info, TRACE_TC_EGRESS, TRACE_RESULT_PASS, DIR_EGRESS, 0, 0, pkt_len, 2, 0, now);
                }
                return TC_ACT_OK;
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
                    return action;
                }
            }
            stats::update_group_stats(src_id, DIR_EGRESS, pkt_len);
            stats::update_group_stats(dst_id, DIR_INGRESS, pkt_len);
            if mirror_on {
                let skb = ctx.as_ptr() as *mut __sk_buff;
                mirror::try_mirror_tc(skb, src_id, dst_id, info.proto, DIR_EGRESS, pkt_len);
            }
            if tracing { trace::trace_event(&info, TRACE_TC_EGRESS, TRACE_RESULT_PASS, DIR_EGRESS, src_id, dst_id, pkt_len, 0, 0, now); }
            return TC_ACT_OK;
        }

        let (result, drop_reason, matched) = policy::evaluate_policy_tc(
            src_id, dst_id, info.proto, DIR_EGRESS, info.dst_port, pkt_len, TC_ACT_OK, TC_ACT_SHOT, now,
        );

        if result == TC_ACT_OK {
            stats::update_flow_stats_v4(&ct_key, pkt_len, now);
            if tcprt_on && info.proto == IPPROTO_TCP {
                tcprt::track_tcp_rt_v4(&ct_key, &info, now, true);
            }
            if qos_on {
                if let Some(action) = apply_egress_qos(&ctx, &info, src_id, dst_id, info.proto, pkt_len, now, tracing) {
                    return action;
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
            if tracing { trace::trace_event(&info, TRACE_TC_EGRESS, TRACE_RESULT_PASS, DIR_EGRESS, src_id, dst_id, pkt_len, 1, 0, now); }
        } else if tracing {
            let trace_result = match drop_reason { 1 => 1, 2 => 2, 3 => 3, _ => 1 };
            trace::trace_event(&info, TRACE_TC_DROP, trace_result, DIR_EGRESS, src_id, dst_id, pkt_len, 0, drop_reason, now);
        }

        result
    }
}

// --- TC Ingress (mirror only) ---

#[classifier]
pub unsafe fn tc_ingress(ctx: TcContext) -> i32 {
    let data = ctx.data();
    let data_end = ctx.data_end();
    let pkt_len = ctx.len();

    let info = match parser::parse_eth_ipv4(data, data_end, 0) {
        Some(i) => i,
        None => match parser::parse_eth_ipv6(data, data_end, 0) {
            Some(i) => i,
            None => return TC_ACT_OK,
        },
    };

    let tracing = trace::should_trace(&info);

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
        trace::trace_event(&info, TRACE_TC_INGRESS, TRACE_RESULT_PASS, DIR_INGRESS, src_id, dst_id, pkt_len, 0, 0, now);
    }

    TC_ACT_OK
}

// --- Helpers ---

#[inline(always)]
unsafe fn apply_egress_qos(ctx: &TcContext, info: &parser::PacketInfo, src_id: u32, dst_id: u32, proto: u8, pkt_len: u32, now: u64, tracing: bool) -> Option<i32> {
    let (edt, prio) = qos::apply_qos_egress(src_id, dst_id, pkt_len, now);
    if edt == u64::MAX {
        drops::record_drop(DROP_QOS_EGRESS, DIR_EGRESS, proto, src_id, dst_id, pkt_len, now);
        if tracing { trace::trace_event(info, TRACE_TC_DROP, TRACE_RESULT_DROP_QOS, DIR_EGRESS, src_id, dst_id, pkt_len, 0, DROP_QOS_EGRESS, now); }
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
