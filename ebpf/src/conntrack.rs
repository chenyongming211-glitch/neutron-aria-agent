use crate::common::{
    CtKey4, CtKey6, CtValue, PolicyKey,
    CT_NEW, CT_ESTABLISHED,
    IPPROTO_TCP, IPPROTO_UDP, IPPROTO_ICMP, IPPROTO_ICMPV6,
};
use crate::maps::{CT_TABLE_V4, CT_TABLE_V6, CT_CONFIG, FIREWALL_CONFIG};

const CT_FLAG_SEEN_REPLY: u8 = 1;

// Default timeouts in nanoseconds
const DEFAULT_TCP_ESTABLISHED_NS: u64 = 300_000_000_000; // 300s
const DEFAULT_TCP_NEW_NS: u64 = 30_000_000_000;          // 30s
const DEFAULT_UDP_NS: u64 = 60_000_000_000;              // 60s
const DEFAULT_ICMP_NS: u64 = 30_000_000_000;             // 30s

#[inline(always)]
fn conntrack_enabled() -> bool {
    let key: u32 = 0;
    if let Some(cfg) = unsafe { FIREWALL_CONFIG.get(&key) } {
        cfg.conntrack_enabled != 0
    } else {
        true
    }
}

#[inline(always)]
fn get_timeout(proto: u8, state: u8) -> u64 {
    let config_key: u32 = 0;
    if let Some(cfg) = unsafe { CT_CONFIG.get(&config_key) } {
        match proto {
            IPPROTO_TCP => {
                if state == CT_ESTABLISHED { cfg.tcp_established_ns } else { cfg.tcp_new_ns }
            }
            IPPROTO_UDP => cfg.udp_ns,
            IPPROTO_ICMP | IPPROTO_ICMPV6 => cfg.icmp_ns,
            _ => cfg.udp_ns,
        }
    } else {
        match proto {
            IPPROTO_TCP => {
                if state == CT_ESTABLISHED { DEFAULT_TCP_ESTABLISHED_NS } else { DEFAULT_TCP_NEW_NS }
            }
            IPPROTO_UDP => DEFAULT_UDP_NS,
            IPPROTO_ICMP | IPPROTO_ICMPV6 => DEFAULT_ICMP_NS,
            _ => DEFAULT_UDP_NS,
        }
    }
}

#[inline(always)]
fn reverse_key4(key: &CtKey4) -> CtKey4 {
    CtKey4 {
        src_ip: key.dst_ip,
        dst_ip: key.src_ip,
        src_port: key.dst_port,
        dst_port: key.src_port,
        proto: key.proto,
        pad: [0; 3],
    }
}

#[inline(always)]
fn reverse_key6(key: &CtKey6) -> CtKey6 {
    CtKey6 {
        src_ip: key.dst_ip,
        dst_ip: key.src_ip,
        src_port: key.dst_port,
        dst_port: key.src_port,
        proto: key.proto,
        pad: [0; 3],
    }
}

/// Matched policy info cached in CT entry, returned on fast-path hit.
#[derive(Copy, Clone)]
pub struct MatchedPolicy {
    pub src_id: u32,
    pub dst_id: u32,
    pub proto: u8,
    pub direction: u8,
}

/// CT lookup result
pub enum CtLookupResult {
    /// Established connection — fast path, skip policy. Carries cached matched policy.
    Established(MatchedPolicy),
    /// New entry just seen reply — transition to established
    SeenReply(MatchedPolicy),
    /// Not found or expired — needs policy evaluation
    NotFound,
}

#[inline(always)]
fn extract_matched(entry: &CtValue) -> MatchedPolicy {
    MatchedPolicy {
        src_id: entry.matched_src_id,
        dst_id: entry.matched_dst_id,
        proto: entry.matched_proto,
        direction: entry.direction,
    }
}

/// Lookup CT for IPv4 packet.
#[inline(always)]
pub unsafe fn ct_lookup_v4(key: &CtKey4, now: u64, pkt_len: u32) -> CtLookupResult {
    if !conntrack_enabled() {
        return CtLookupResult::NotFound;
    }
    // Forward lookup
    if let Some(entry) = CT_TABLE_V4.get_ptr_mut(key) {
        let timeout = get_timeout(key.proto, (*entry).state);
        if now.wrapping_sub((*entry).last_seen) > timeout {
            let _ = CT_TABLE_V4.remove(key);
            return CtLookupResult::NotFound;
        }
        (*entry).last_seen = now;
        (*entry).pkt_count += 1;
        (*entry).byte_count += pkt_len as u64;
        let matched = extract_matched(&*entry);
        if (*entry).state == CT_ESTABLISHED {
            return CtLookupResult::Established(matched);
        }
        return CtLookupResult::SeenReply(matched);
    }

    // Reverse lookup
    let rev = reverse_key4(key);
    if let Some(entry) = CT_TABLE_V4.get_ptr_mut(&rev) {
        let timeout = get_timeout(rev.proto, (*entry).state);
        if now.wrapping_sub((*entry).last_seen) > timeout {
            let _ = CT_TABLE_V4.remove(&rev);
            return CtLookupResult::NotFound;
        }
        (*entry).last_seen = now;
        (*entry).pkt_count += 1;
        (*entry).byte_count += pkt_len as u64;
        (*entry).flags |= CT_FLAG_SEEN_REPLY;
        if (*entry).state == CT_NEW {
            (*entry).state = CT_ESTABLISHED;
        }
        let matched = extract_matched(&*entry);
        return CtLookupResult::Established(matched);
    }

    CtLookupResult::NotFound
}

/// Lookup CT for IPv6 packet.
#[inline(always)]
pub unsafe fn ct_lookup_v6(key: &CtKey6, now: u64, pkt_len: u32) -> CtLookupResult {
    if !conntrack_enabled() {
        return CtLookupResult::NotFound;
    }
    // Forward lookup
    if let Some(entry) = CT_TABLE_V6.get_ptr_mut(key) {
        let timeout = get_timeout(key.proto, (*entry).state);
        if now.wrapping_sub((*entry).last_seen) > timeout {
            let _ = CT_TABLE_V6.remove(key);
            return CtLookupResult::NotFound;
        }
        (*entry).last_seen = now;
        (*entry).pkt_count += 1;
        (*entry).byte_count += pkt_len as u64;
        let matched = extract_matched(&*entry);
        if (*entry).state == CT_ESTABLISHED {
            return CtLookupResult::Established(matched);
        }
        return CtLookupResult::SeenReply(matched);
    }

    // Reverse lookup
    let rev = reverse_key6(key);
    if let Some(entry) = CT_TABLE_V6.get_ptr_mut(&rev) {
        let timeout = get_timeout(rev.proto, (*entry).state);
        if now.wrapping_sub((*entry).last_seen) > timeout {
            let _ = CT_TABLE_V6.remove(&rev);
            return CtLookupResult::NotFound;
        }
        (*entry).last_seen = now;
        (*entry).pkt_count += 1;
        (*entry).byte_count += pkt_len as u64;
        (*entry).flags |= CT_FLAG_SEEN_REPLY;
        if (*entry).state == CT_NEW {
            (*entry).state = CT_ESTABLISHED;
        }
        let matched = extract_matched(&*entry);
        return CtLookupResult::Established(matched);
    }

    CtLookupResult::NotFound
}

/// Create a new CT entry for IPv4 with matched policy info.
#[inline(always)]
pub unsafe fn ct_create_v4(key: &CtKey4, now: u64, pkt_len: u32, matched: &MatchedPolicy) {
    if !conntrack_enabled() {
        return;
    }
    let val = CtValue {
        state: CT_NEW,
        flags: 0,
        direction: matched.direction,
        matched_proto: matched.proto,
        matched_src_id: matched.src_id,
        matched_dst_id: matched.dst_id,
        last_seen: now,
        pkt_count: 1,
        byte_count: pkt_len as u64,
    };
    let _ = CT_TABLE_V4.insert(key, &val, 0);
}

/// Create a new CT entry for IPv6 with matched policy info.
#[inline(always)]
pub unsafe fn ct_create_v6(key: &CtKey6, now: u64, pkt_len: u32, matched: &MatchedPolicy) {
    if !conntrack_enabled() {
        return;
    }
    let val = CtValue {
        state: CT_NEW,
        flags: 0,
        direction: matched.direction,
        matched_proto: matched.proto,
        matched_src_id: matched.src_id,
        matched_dst_id: matched.dst_id,
        last_seen: now,
        pkt_count: 1,
        byte_count: pkt_len as u64,
    };
    let _ = CT_TABLE_V6.insert(key, &val, 0);
}
