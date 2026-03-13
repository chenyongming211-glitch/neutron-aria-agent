#![no_std]
#![no_main]

use aya_ebpf::macros::{xdp, classifier};
use aya_ebpf::programs::{XdpContext, TcContext};
use aya_ebpf::maps::LpmTrie;
use aya_ebpf::maps::lpm_trie::Key;
use aya_ebpf::helpers::bpf_ktime_get_ns;

mod common;
mod maps;
mod parser;
mod conntrack;
mod stats;
mod qos;

use common::{
    PolicyKey, PolicyValue, PortKey, CtKey4, CtKey6,
    XDP_PASS, XDP_DROP, DIR_INGRESS, DIR_EGRESS,
};
use maps::{
    DST_IPV4_TRIE, SRC_IPV4_TRIE, DST_IPV6_TRIE, SRC_IPV6_TRIE,
    POLICY_TABLE, PORT_BITMAP_POOL,
};
use conntrack::CtLookupResult;

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

// TC action constants
const TC_ACT_OK: i32 = 0;
const TC_ACT_SHOT: i32 = 2;

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

    // Build CT key and check conntrack fast path
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
            CtLookupResult::Established | CtLookupResult::SeenReply => {
                // Fast path: established connection, skip policy
                stats::update_flow_stats_v6(&ct_key, pkt_len, now);
                return XDP_PASS;
            }
            CtLookupResult::NotFound => {}
        }

        // Slow path: policy evaluation
        let src_id = lookup_ipv6(&SRC_IPV6_TRIE, info.src_ip_v6).unwrap_or(0);
        let dst_id = lookup_ipv6(&DST_IPV6_TRIE, info.dst_ip_v6).unwrap_or(0);
        let proto = info.proto;

        let result = evaluate_policy(src_id, dst_id, proto, DIR_INGRESS, info.dst_port, pkt_len);

        if result == XDP_PASS {
            conntrack::ct_create_v6(&ct_key, now, pkt_len);
            stats::update_flow_stats_v6(&ct_key, pkt_len, now);
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
            CtLookupResult::Established | CtLookupResult::SeenReply => {
                stats::update_flow_stats_v4(&ct_key, pkt_len, now);
                return XDP_PASS;
            }
            CtLookupResult::NotFound => {}
        }

        let src_id = lookup_ipv4(&SRC_IPV4_TRIE, info.src_ip).unwrap_or(0);
        let dst_id = lookup_ipv4(&DST_IPV4_TRIE, info.dst_ip).unwrap_or(0);
        let proto = info.proto;

        let result = evaluate_policy(src_id, dst_id, proto, DIR_INGRESS, info.dst_port, pkt_len);

        if result == XDP_PASS {
            conntrack::ct_create_v4(&ct_key, now, pkt_len);
            stats::update_flow_stats_v4(&ct_key, pkt_len, now);
        }

        result
    }
}

/// 8-level fallback policy matching with direction support and rule stats
#[inline(always)]
unsafe fn evaluate_policy(
    src_id: u32,
    dst_id: u32,
    proto: u8,
    direction: u8,
    dst_port: u16,
    pkt_len: u32,
) -> u32 {
    let candidates: [(u32, u32, u8); 8] = [
        (src_id, dst_id, proto),
        (0,      dst_id, proto),
        (src_id, 0,      proto),
        (src_id, dst_id, 0),
        (0,      0,      proto),
        (0,      dst_id, 0),
        (src_id, 0,      0),
        (0,      0,      0),
    ];

    let mut i = 0u8;
    while i < 8 {
        let (s, d, p) = candidates[i as usize];
        let key = PolicyKey {
            src_id: s,
            dst_id: d,
            proto: p,
            direction,
            pad: [0; 2],
        };
        if let Some(policy) = POLICY_TABLE.get(&key) {
            let result = apply_policy(policy, dst_port);
            stats::update_rule_stats(&key, pkt_len);
            return result;
        }
        i += 1;
    }

    XDP_PASS
}

fn apply_policy(policy: &PolicyValue, dst_port: u16) -> u32 {
    if policy.has_port_filter == 0 {
        return if policy.action == 0 { XDP_PASS } else { XDP_DROP };
    }

    // HashMap lookup：(bitmap_idx, port) → action
    let key = PortKey { idx: policy.bitmap_idx, port: dst_port, pad: 0 };
    let rule_action = unsafe { PORT_BITMAP_POOL.get(&key).copied().unwrap_or(0) };

    match rule_action {
        1 => XDP_DROP,
        2 => XDP_PASS,
        _ => if policy.action == 0 { XDP_PASS } else { XDP_DROP },
    }
}

// --- TC Egress Classifier ---

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
            CtLookupResult::Established | CtLookupResult::SeenReply => {
                stats::update_flow_stats_v6(&ct_key, pkt_len, now);
                return TC_ACT_OK;
            }
            CtLookupResult::NotFound => {}
        }

        let src_id = lookup_ipv6(&SRC_IPV6_TRIE, info.src_ip_v6).unwrap_or(0);
        let dst_id = lookup_ipv6(&DST_IPV6_TRIE, info.dst_ip_v6).unwrap_or(0);

        let result = evaluate_policy_tc(src_id, dst_id, info.proto, DIR_EGRESS, info.dst_port, pkt_len);

        if result == TC_ACT_OK {
            conntrack::ct_create_v6(&ct_key, now, pkt_len);
            stats::update_flow_stats_v6(&ct_key, pkt_len, now);
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
            CtLookupResult::Established | CtLookupResult::SeenReply => {
                stats::update_flow_stats_v4(&ct_key, pkt_len, now);
                return TC_ACT_OK;
            }
            CtLookupResult::NotFound => {}
        }

        let src_id = lookup_ipv4(&SRC_IPV4_TRIE, info.src_ip).unwrap_or(0);
        let dst_id = lookup_ipv4(&DST_IPV4_TRIE, info.dst_ip).unwrap_or(0);

        let result = evaluate_policy_tc(src_id, dst_id, info.proto, DIR_EGRESS, info.dst_port, pkt_len);

        if result == TC_ACT_OK {
            conntrack::ct_create_v4(&ct_key, now, pkt_len);
            stats::update_flow_stats_v4(&ct_key, pkt_len, now);
        }

        result
    }
}

/// Evaluate egress policy, returning TC action codes
#[inline(always)]
unsafe fn evaluate_policy_tc(
    src_id: u32,
    dst_id: u32,
    proto: u8,
    direction: u8,
    dst_port: u16,
    pkt_len: u32,
) -> i32 {
    let candidates: [(u32, u32, u8); 8] = [
        (src_id, dst_id, proto),
        (0,      dst_id, proto),
        (src_id, 0,      proto),
        (src_id, dst_id, 0),
        (0,      0,      proto),
        (0,      dst_id, 0),
        (src_id, 0,      0),
        (0,      0,      0),
    ];

    let mut i = 0u8;
    while i < 8 {
        let (s, d, p) = candidates[i as usize];
        let key = PolicyKey {
            src_id: s,
            dst_id: d,
            proto: p,
            direction,
            pad: [0; 2],
        };
        if let Some(policy) = POLICY_TABLE.get(&key) {
            let xdp_result = apply_policy(policy, dst_port);
            stats::update_rule_stats(&key, pkt_len);
            return if xdp_result == XDP_PASS { TC_ACT_OK } else { TC_ACT_SHOT };
        }
        i += 1;
    }

    TC_ACT_OK
}

unsafe fn lookup_ipv4(map: &LpmTrie<[u8; 4], u32>, ip: u32) -> Option<u32> {
    let key = Key::new(32, ip.to_be_bytes());
    map.get(&key).copied()
}

unsafe fn lookup_ipv6(map: &LpmTrie<[u8; 16], u32>, ip: [u8; 16]) -> Option<u32> {
    let key = Key::new(128, ip);
    map.get(&key).copied()
}
