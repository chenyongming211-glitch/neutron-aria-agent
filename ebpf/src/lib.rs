#![no_std]
#![no_main]

use aya_ebpf::macros::xdp;
use aya_ebpf::programs::XdpContext;
use aya_ebpf::maps::LpmTrie;
use aya_ebpf::maps::lpm_trie::Key;

mod common;
mod maps;
mod parser;

use common::{PolicyKey, PolicyValue, XDP_PASS, XDP_DROP};
use maps::{
    DST_IPV4_TRIE, SRC_IPV4_TRIE, DST_IPV6_TRIE, SRC_IPV6_TRIE,
    POLICY_TABLE, PORT_BITMAP_POOL,
};

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[xdp]
pub fn xdp_firewall(ctx: XdpContext) -> u32 {
    unsafe { try_xdp_firewall(ctx) }
}

unsafe fn try_xdp_firewall(ctx: XdpContext) -> u32 {
    let data = ctx.data();
    let data_end = ctx.data_end();

    let info = match parser::parse_eth_ipv4(data, data_end, 0) {
        Some(i) => i,
        None => match parser::parse_eth_ipv6(data, data_end, 0) {
            Some(i) => i,
            None => return XDP_PASS,
        },
    };

    let src_id = if info.is_ipv6 {
        lookup_ipv6(&SRC_IPV6_TRIE, info.src_ip_v6).unwrap_or(0)
    } else {
        lookup_ipv4(&SRC_IPV4_TRIE, info.src_ip).unwrap_or(0)
    };

    let dst_id = if info.is_ipv6 {
        lookup_ipv6(&DST_IPV6_TRIE, info.dst_ip_v6).unwrap_or(0)
    } else {
        lookup_ipv4(&DST_IPV4_TRIE, info.dst_ip).unwrap_or(0)
    };

    let proto = info.proto;

    // 8 级 Fallback 策略匹配
    let key = PolicyKey { src_id, dst_id, proto, pad: [0; 3] };
    if let Some(policy) = POLICY_TABLE.get(&key) {
        return apply_policy(policy, info.dst_port);
    }

    let key = PolicyKey { src_id: 0, dst_id, proto, pad: [0; 3] };
    if let Some(policy) = POLICY_TABLE.get(&key) {
        return apply_policy(policy, info.dst_port);
    }

    let key = PolicyKey { src_id, dst_id: 0, proto, pad: [0; 3] };
    if let Some(policy) = POLICY_TABLE.get(&key) {
        return apply_policy(policy, info.dst_port);
    }

    let key = PolicyKey { src_id, dst_id, proto: 0, pad: [0; 3] };
    if let Some(policy) = POLICY_TABLE.get(&key) {
        return apply_policy(policy, info.dst_port);
    }

    let key = PolicyKey { src_id: 0, dst_id: 0, proto, pad: [0; 3] };
    if let Some(policy) = POLICY_TABLE.get(&key) {
        return apply_policy(policy, info.dst_port);
    }

    let key = PolicyKey { src_id: 0, dst_id, proto: 0, pad: [0; 3] };
    if let Some(policy) = POLICY_TABLE.get(&key) {
        return apply_policy(policy, info.dst_port);
    }

    let key = PolicyKey { src_id, dst_id: 0, proto: 0, pad: [0; 3] };
    if let Some(policy) = POLICY_TABLE.get(&key) {
        return apply_policy(policy, info.dst_port);
    }

    let key = PolicyKey { src_id: 0, dst_id: 0, proto: 0, pad: [0; 3] };
    if let Some(policy) = POLICY_TABLE.get(&key) {
        return apply_policy(policy, info.dst_port);
    }

    XDP_PASS
}

fn apply_policy(policy: &PolicyValue, dst_port: u16) -> u32 {
    if policy.has_port_filter == 0 {
        return if policy.action == 0 { XDP_PASS } else { XDP_DROP };
    }

    // 边界检查：bitmap_idx 必须 < 64（PORT_BITMAP_POOL 容量）
    if policy.bitmap_idx >= 64 {
        return if policy.action == 0 { XDP_PASS } else { XDP_DROP };
    }

    // O(1) 寻址：策略组基址 + 端口号
    let index = (policy.bitmap_idx * 65536) + (dst_port as u32);
    let rule_action = PORT_BITMAP_POOL.get(index).copied().unwrap_or(0);

    match rule_action {
        1 => XDP_DROP,
        2 => XDP_PASS,
        _ => if policy.action == 0 { XDP_PASS } else { XDP_DROP },
    }
}

unsafe fn lookup_ipv4(map: &LpmTrie<[u8; 4], u32>, ip: u32) -> Option<u32> {
    let key = Key::new(32, ip.to_be_bytes());
    map.get(&key).copied()
}

unsafe fn lookup_ipv6(map: &LpmTrie<[u8; 16], u32>, ip: [u8; 16]) -> Option<u32> {
    let key = Key::new(128, ip);
    map.get(&key).copied()
}