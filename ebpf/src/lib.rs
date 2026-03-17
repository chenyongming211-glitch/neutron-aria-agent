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

use common::{
    CtKey4, CtKey6,
    XDP_PASS, XDP_DROP, DIR_INGRESS, DIR_EGRESS,
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
    unsafe { try_xdp_firewall(ctx) }
}

unsafe fn try_xdp_firewall(ctx: XdpContext) -> u32 {
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
            CtLookupResult::Established(matched) | CtLookupResult::SeenReply(matched) => {
                stats::update_rule_stats(&matched.to_policy_key(), pkt_len);
                stats::update_flow_stats_v6(&ct_key, pkt_len, now);
                let need_ids = qos_on || stats::monitoring_enabled();
                if need_ids {
                    let src_id = lookup_ipv6(&SRC_IPV6_TRIE, info.src_ip_v6).unwrap_or(0);
                    let dst_id = lookup_ipv6(&DST_IPV6_TRIE, info.dst_ip_v6).unwrap_or(0);
                    if qos_on && !qos::apply_qos_ingress(src_id, dst_id, pkt_len, now) {
                        return XDP_DROP;
                    }
                    // Group stats after QoS — only count packets that actually pass
                    stats::update_group_stats(src_id, DIR_EGRESS, pkt_len);
                    stats::update_group_stats(dst_id, DIR_INGRESS, pkt_len);
                }
                return XDP_PASS;
            }
            CtLookupResult::NotFound => {}
        }

        let src_id = lookup_ipv6(&SRC_IPV6_TRIE, info.src_ip_v6).unwrap_or(0);
        let dst_id = lookup_ipv6(&DST_IPV6_TRIE, info.dst_ip_v6).unwrap_or(0);
        let (result, matched) = policy::evaluate_policy(src_id, dst_id, info.proto, DIR_INGRESS, info.dst_port, pkt_len);

        if result == XDP_PASS {
            stats::update_flow_stats_v6(&ct_key, pkt_len, now);
            if qos_on && !qos::apply_qos_ingress(src_id, dst_id, pkt_len, now) {
                return XDP_DROP;
            }
            // Group stats after QoS
            stats::update_group_stats(src_id, DIR_EGRESS, pkt_len);
            stats::update_group_stats(dst_id, DIR_INGRESS, pkt_len);
            conntrack::ct_create_v6(&ct_key, now, pkt_len, &matched);
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
            CtLookupResult::Established(matched) | CtLookupResult::SeenReply(matched) => {
                stats::update_rule_stats(&matched.to_policy_key(), pkt_len);
                stats::update_flow_stats_v4(&ct_key, pkt_len, now);
                let need_ids = qos_on || stats::monitoring_enabled();
                if need_ids {
                    let src_id = lookup_ipv4(&SRC_IPV4_TRIE, info.src_ip).unwrap_or(0);
                    let dst_id = lookup_ipv4(&DST_IPV4_TRIE, info.dst_ip).unwrap_or(0);
                    if qos_on && !qos::apply_qos_ingress(src_id, dst_id, pkt_len, now) {
                        return XDP_DROP;
                    }
                    // Group stats after QoS
                    stats::update_group_stats(src_id, DIR_EGRESS, pkt_len);
                    stats::update_group_stats(dst_id, DIR_INGRESS, pkt_len);
                }
                return XDP_PASS;
            }
            CtLookupResult::NotFound => {}
        }

        let src_id = lookup_ipv4(&SRC_IPV4_TRIE, info.src_ip).unwrap_or(0);
        let dst_id = lookup_ipv4(&DST_IPV4_TRIE, info.dst_ip).unwrap_or(0);
        let (result, matched) = policy::evaluate_policy(src_id, dst_id, info.proto, DIR_INGRESS, info.dst_port, pkt_len);

        if result == XDP_PASS {
            stats::update_flow_stats_v4(&ct_key, pkt_len, now);
            if qos_on && !qos::apply_qos_ingress(src_id, dst_id, pkt_len, now) {
                return XDP_DROP;
            }
            // Group stats after QoS
            stats::update_group_stats(src_id, DIR_EGRESS, pkt_len);
            stats::update_group_stats(dst_id, DIR_INGRESS, pkt_len);
            conntrack::ct_create_v4(&ct_key, now, pkt_len, &matched);
        }

        result
    }
}

// --- TC Egress ---

#[classifier]
pub fn tc_egress(ctx: TcContext) -> i32 {
    unsafe { try_tc_egress(ctx) }
}

unsafe fn try_tc_egress(ctx: TcContext) -> i32 {
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
            CtLookupResult::Established(matched) | CtLookupResult::SeenReply(matched) => {
                stats::update_rule_stats(&matched.to_policy_key(), pkt_len);
                stats::update_flow_stats_v6(&ct_key, pkt_len, now);
                let need_ids = qos_on || stats::monitoring_enabled();
                if need_ids {
                    let dst_id = lookup_ipv6(&DST_IPV6_TRIE, info.dst_ip_v6).unwrap_or(0);
                    let src_id = lookup_ipv6(&SRC_IPV6_TRIE, info.src_ip_v6).unwrap_or(0);
                    if qos_on {
                        if let Some(action) = apply_egress_qos(&ctx, src_id, dst_id, pkt_len, now) {
                            return action;
                        }
                    }
                    // Group stats after QoS
                    stats::update_group_stats(src_id, DIR_EGRESS, pkt_len);
                    stats::update_group_stats(dst_id, DIR_INGRESS, pkt_len);
                }
                return TC_ACT_OK;
            }
            CtLookupResult::NotFound => {}
        }

        let src_id = lookup_ipv6(&SRC_IPV6_TRIE, info.src_ip_v6).unwrap_or(0);
        let dst_id = lookup_ipv6(&DST_IPV6_TRIE, info.dst_ip_v6).unwrap_or(0);
        let (result, matched) = policy::evaluate_policy_tc(
            src_id, dst_id, info.proto, DIR_EGRESS, info.dst_port, pkt_len, TC_ACT_OK, TC_ACT_SHOT,
        );

        if result == TC_ACT_OK {
            stats::update_flow_stats_v6(&ct_key, pkt_len, now);
            if qos_on {
                if let Some(action) = apply_egress_qos(&ctx, src_id, dst_id, pkt_len, now) {
                    return action;
                }
            }
            // Group stats after QoS
            stats::update_group_stats(src_id, DIR_EGRESS, pkt_len);
            stats::update_group_stats(dst_id, DIR_INGRESS, pkt_len);
            conntrack::ct_create_v6(&ct_key, now, pkt_len, &matched);
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
            CtLookupResult::Established(matched) | CtLookupResult::SeenReply(matched) => {
                stats::update_rule_stats(&matched.to_policy_key(), pkt_len);
                stats::update_flow_stats_v4(&ct_key, pkt_len, now);
                let need_ids = qos_on || stats::monitoring_enabled();
                if need_ids {
                    let dst_id = lookup_ipv4(&DST_IPV4_TRIE, info.dst_ip).unwrap_or(0);
                    let src_id = lookup_ipv4(&SRC_IPV4_TRIE, info.src_ip).unwrap_or(0);
                    if qos_on {
                        if let Some(action) = apply_egress_qos(&ctx, src_id, dst_id, pkt_len, now) {
                            return action;
                        }
                    }
                    // Group stats after QoS
                    stats::update_group_stats(src_id, DIR_EGRESS, pkt_len);
                    stats::update_group_stats(dst_id, DIR_INGRESS, pkt_len);
                }
                return TC_ACT_OK;
            }
            CtLookupResult::NotFound => {}
        }

        let src_id = lookup_ipv4(&SRC_IPV4_TRIE, info.src_ip).unwrap_or(0);
        let dst_id = lookup_ipv4(&DST_IPV4_TRIE, info.dst_ip).unwrap_or(0);
        let (result, matched) = policy::evaluate_policy_tc(
            src_id, dst_id, info.proto, DIR_EGRESS, info.dst_port, pkt_len, TC_ACT_OK, TC_ACT_SHOT,
        );

        if result == TC_ACT_OK {
            stats::update_flow_stats_v4(&ct_key, pkt_len, now);
            if qos_on {
                if let Some(action) = apply_egress_qos(&ctx, src_id, dst_id, pkt_len, now) {
                    return action;
                }
            }
            // Group stats after QoS
            stats::update_group_stats(src_id, DIR_EGRESS, pkt_len);
            stats::update_group_stats(dst_id, DIR_INGRESS, pkt_len);
            conntrack::ct_create_v4(&ct_key, now, pkt_len, &matched);
        }

        result
    }
}

// --- Helpers ---

#[inline(always)]
unsafe fn apply_egress_qos(ctx: &TcContext, src_id: u32, dst_id: u32, pkt_len: u32, now: u64) -> Option<i32> {
    let (edt, prio) = qos::apply_qos_egress(src_id, dst_id, pkt_len, now);
    if edt == u64::MAX {
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
