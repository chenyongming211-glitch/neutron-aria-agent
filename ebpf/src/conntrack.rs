use crate::common::{
    ct_acl_bank_is_current, CtKey4, CtKey6, CtValue, PolicyKey, CT_ESTABLISHED,
    CT_FLAG_POLICY_HIT, CT_FLAG_SEEN_REPLY, CT_NEW, IPPROTO_ICMP, IPPROTO_ICMPV6, IPPROTO_TCP,
    IPPROTO_UDP,
};
use crate::maps::{CT_CONFIG, CT_TABLE_V4, CT_TABLE_V6};

// Default timeouts in nanoseconds
const DEFAULT_TCP_ESTABLISHED_NS: u64 = 300_000_000_000; // 300s
const DEFAULT_TCP_NEW_NS: u64 = 30_000_000_000; // 30s
const DEFAULT_UDP_NS: u64 = 60_000_000_000; // 60s
const DEFAULT_ICMP_NS: u64 = 30_000_000_000; // 30s

#[inline(always)]
fn get_timeout(proto: u8, state: u8) -> u64 {
    let config_key: u32 = 0;
    if let Some(cfg) = unsafe { CT_CONFIG.get(&config_key) } {
        match proto {
            IPPROTO_TCP => {
                if state == CT_ESTABLISHED {
                    cfg.tcp_established_ns
                } else {
                    cfg.tcp_new_ns
                }
            }
            IPPROTO_UDP => cfg.udp_ns,
            IPPROTO_ICMP | IPPROTO_ICMPV6 => cfg.icmp_ns,
            _ => cfg.udp_ns,
        }
    } else {
        match proto {
            IPPROTO_TCP => {
                if state == CT_ESTABLISHED {
                    DEFAULT_TCP_ESTABLISHED_NS
                } else {
                    DEFAULT_TCP_NEW_NS
                }
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
        tap_id: key.tap_id,
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
        tap_id: key.tap_id,
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
    pub tap_id: u32,
    pub src_id: u32,
    pub dst_id: u32,
    pub proto: u8,
    pub direction: u8,
    pub bank: u8,
    pub policy_hit: bool,
}

impl MatchedPolicy {
    #[inline(always)]
    pub fn to_policy_key(&self) -> PolicyKey {
        PolicyKey {
            tap_id: self.tap_id,
            src_id: self.src_id,
            dst_id: self.dst_id,
            proto: self.proto,
            direction: self.direction,
            bank: self.bank,
            pad: [0; 1],
        }
    }
}

/// Why CT lookup could not use a cached policy decision.
#[derive(Copy, Clone)]
pub enum CtMissReason {
    Disabled,
    NotFound,
    Expired,
    StaleBank,
}

/// CT lookup result.
pub enum CtLookupResult {
    /// Current cached policy decision, packet direction, and actual CT state.
    Hit(MatchedPolicy, bool, u8),
    /// Policy must be evaluated for the supplied reason.
    Miss(CtMissReason),
}

#[inline(always)]
fn extract_matched(entry: &CtValue, tap_id: u32) -> MatchedPolicy {
    MatchedPolicy {
        tap_id,
        src_id: entry.matched_src_id,
        dst_id: entry.matched_dst_id,
        proto: entry.matched_proto,
        direction: entry.direction,
        bank: entry.matched_bank,
        policy_hit: (entry.flags & CT_FLAG_POLICY_HIT) != 0,
    }
}

/// Lookup CT for IPv4 packet.
#[inline(always)]
pub unsafe fn ct_lookup_v4(
    key: &CtKey4,
    now: u64,
    pkt_len: u32,
    validate_acl_bank: u8,
    expected_acl_bank: u8,
) -> CtLookupResult {
    if !crate::runtime::conntrack_enabled(key.tap_id) {
        return CtLookupResult::Miss(CtMissReason::Disabled);
    }
    // Forward lookup
    if let Some(entry) = CT_TABLE_V4.get_ptr_mut(key) {
        if !ct_acl_bank_is_current(
            (*entry).matched_bank,
            validate_acl_bank,
            expected_acl_bank,
        ) {
            let _ = CT_TABLE_V4.remove(key);
            return CtLookupResult::Miss(CtMissReason::StaleBank);
        }
        let timeout = get_timeout(key.proto, (*entry).state);
        if now.wrapping_sub((*entry).last_seen) > timeout {
            let _ = CT_TABLE_V4.remove(key);
            return CtLookupResult::Miss(CtMissReason::Expired);
        }
        (*entry).last_seen = now;
        (*entry).pkt_count += 1;
        (*entry).byte_count += pkt_len as u64;
        // Promote to ESTABLISHED when forward direction sees a packet after reply was seen
        if (*entry).state == CT_NEW && ((*entry).flags & CT_FLAG_SEEN_REPLY) != 0 {
            (*entry).state = CT_ESTABLISHED;
        }
        let matched = extract_matched(&*entry, key.tap_id);
        return CtLookupResult::Hit(matched, true, (*entry).state);
    }

    // Reverse lookup — only set SEEN_REPLY flag, do NOT promote state
    let rev = reverse_key4(key);
    if let Some(entry) = CT_TABLE_V4.get_ptr_mut(&rev) {
        if !ct_acl_bank_is_current(
            (*entry).matched_bank,
            validate_acl_bank,
            expected_acl_bank,
        ) {
            let _ = CT_TABLE_V4.remove(&rev);
            return CtLookupResult::Miss(CtMissReason::StaleBank);
        }
        let timeout = get_timeout(rev.proto, (*entry).state);
        if now.wrapping_sub((*entry).last_seen) > timeout {
            let _ = CT_TABLE_V4.remove(&rev);
            return CtLookupResult::Miss(CtMissReason::Expired);
        }
        (*entry).last_seen = now;
        (*entry).pkt_count += 1;
        (*entry).byte_count += pkt_len as u64;
        (*entry).flags |= CT_FLAG_SEEN_REPLY;
        let matched = extract_matched(&*entry, key.tap_id);
        return CtLookupResult::Hit(matched, false, (*entry).state);
    }

    CtLookupResult::Miss(CtMissReason::NotFound)
}

/// Lookup CT for IPv6 packet.
#[inline(always)]
pub unsafe fn ct_lookup_v6(
    key: &CtKey6,
    now: u64,
    pkt_len: u32,
    validate_acl_bank: u8,
    expected_acl_bank: u8,
) -> CtLookupResult {
    if !crate::runtime::conntrack_enabled(key.tap_id) {
        return CtLookupResult::Miss(CtMissReason::Disabled);
    }
    // Forward lookup
    if let Some(entry) = CT_TABLE_V6.get_ptr_mut(key) {
        if !ct_acl_bank_is_current(
            (*entry).matched_bank,
            validate_acl_bank,
            expected_acl_bank,
        ) {
            let _ = CT_TABLE_V6.remove(key);
            return CtLookupResult::Miss(CtMissReason::StaleBank);
        }
        let timeout = get_timeout(key.proto, (*entry).state);
        if now.wrapping_sub((*entry).last_seen) > timeout {
            let _ = CT_TABLE_V6.remove(key);
            return CtLookupResult::Miss(CtMissReason::Expired);
        }
        (*entry).last_seen = now;
        (*entry).pkt_count += 1;
        (*entry).byte_count += pkt_len as u64;
        if (*entry).state == CT_NEW && ((*entry).flags & CT_FLAG_SEEN_REPLY) != 0 {
            (*entry).state = CT_ESTABLISHED;
        }
        let matched = extract_matched(&*entry, key.tap_id);
        return CtLookupResult::Hit(matched, true, (*entry).state);
    }

    // Reverse lookup — only set SEEN_REPLY flag, do NOT promote state
    let rev = reverse_key6(key);
    if let Some(entry) = CT_TABLE_V6.get_ptr_mut(&rev) {
        if !ct_acl_bank_is_current(
            (*entry).matched_bank,
            validate_acl_bank,
            expected_acl_bank,
        ) {
            let _ = CT_TABLE_V6.remove(&rev);
            return CtLookupResult::Miss(CtMissReason::StaleBank);
        }
        let timeout = get_timeout(rev.proto, (*entry).state);
        if now.wrapping_sub((*entry).last_seen) > timeout {
            let _ = CT_TABLE_V6.remove(&rev);
            return CtLookupResult::Miss(CtMissReason::Expired);
        }
        (*entry).last_seen = now;
        (*entry).pkt_count += 1;
        (*entry).byte_count += pkt_len as u64;
        (*entry).flags |= CT_FLAG_SEEN_REPLY;
        let matched = extract_matched(&*entry, key.tap_id);
        return CtLookupResult::Hit(matched, false, (*entry).state);
    }

    CtLookupResult::Miss(CtMissReason::NotFound)
}

/// Create a new CT entry for IPv4 with matched policy info.
#[inline(always)]
pub unsafe fn ct_create_v4(key: &CtKey4, now: u64, pkt_len: u32, matched: &MatchedPolicy) {
    if !crate::runtime::conntrack_enabled(key.tap_id) {
        return;
    }
    let val = CtValue {
        state: CT_NEW,
        flags: if matched.policy_hit {
            CT_FLAG_POLICY_HIT
        } else {
            0
        },
        direction: matched.direction,
        matched_proto: matched.proto,
        matched_src_id: matched.src_id,
        matched_dst_id: matched.dst_id,
        matched_bank: matched.bank,
        _pad: [0; 3],
        last_seen: now,
        pkt_count: 1,
        byte_count: pkt_len as u64,
    };
    let _ = CT_TABLE_V4.insert(key, &val, 0);
}

/// Create a new CT entry for IPv6 with matched policy info.
#[inline(always)]
pub unsafe fn ct_create_v6(key: &CtKey6, now: u64, pkt_len: u32, matched: &MatchedPolicy) {
    if !crate::runtime::conntrack_enabled(key.tap_id) {
        return;
    }
    let val = CtValue {
        state: CT_NEW,
        flags: if matched.policy_hit {
            CT_FLAG_POLICY_HIT
        } else {
            0
        },
        direction: matched.direction,
        matched_proto: matched.proto,
        matched_src_id: matched.src_id,
        matched_dst_id: matched.dst_id,
        matched_bank: matched.bank,
        _pad: [0; 3],
        last_seen: now,
        pkt_count: 1,
        byte_count: pkt_len as u64,
    };
    let _ = CT_TABLE_V6.insert(key, &val, 0);
}
