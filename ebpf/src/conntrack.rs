use crate::common::{
    ct_acl_cache_is_current, ct_apply_confirmed_hit, ct_snapshot_is_stable, CtKey4, CtKey6,
    CtValue, PolicyKey, CT_ESTABLISHED, CT_FLAG_ACL_EVALUATED, CT_FLAG_POLICY_HIT, CT_NEW,
    IPPROTO_ICMP, IPPROTO_ICMPV6, IPPROTO_TCP, IPPROTO_UDP, IP_FAMILY_V4,
};
use crate::maps::{CT_CONFIG, CT_TABLE_V4, CT_TABLE_V6, CT_VALUE_SCRATCH};
use aya_ebpf::bindings::{BPF_EXIST, BPF_NOEXIST};

// Default timeouts in nanoseconds
const DEFAULT_TCP_ESTABLISHED_NS: u64 = 300_000_000_000; // 300s
const DEFAULT_TCP_NEW_NS: u64 = 30_000_000_000; // 30s
const DEFAULT_UDP_NS: u64 = 60_000_000_000; // 60s
const DEFAULT_ICMP_NS: u64 = 30_000_000_000; // 30s

const CT_SNAPSHOT_MISSING: u8 = 0;
const CT_SNAPSHOT_STABLE: u8 = 1;
const CT_SNAPSHOT_CHANGED: u8 = 2;

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
            ip_family: IP_FAMILY_V4,
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

#[inline(always)]
unsafe fn copy_ct_value(dst: *mut CtValue, src: *const CtValue) {
    (*dst).state = (*src).state;
    (*dst).flags = (*src).flags;
    (*dst).direction = (*src).direction;
    (*dst).matched_proto = (*src).matched_proto;
    (*dst).matched_src_id = (*src).matched_src_id;
    (*dst).matched_dst_id = (*src).matched_dst_id;
    (*dst).matched_bank = (*src).matched_bank;
    (*dst).matched_family = (*src).matched_family;
    (*dst)._pad[0] = (*src)._pad[0];
    (*dst)._pad[1] = (*src)._pad[1];
    (*dst).last_seen = (*src).last_seen;
    (*dst).pkt_count = (*src).pkt_count;
    (*dst).byte_count = (*src).byte_count;
}

#[inline(always)]
unsafe fn confirmed_ct_v4_snapshot(key: &CtKey4) -> u8 {
    let first = match CT_VALUE_SCRATCH.get_ptr_mut(0) {
        Some(value) => value,
        None => return CT_SNAPSHOT_CHANGED,
    };
    let first_source = match CT_TABLE_V4.get_ptr(key) {
        Some(value) => value,
        None => return CT_SNAPSHOT_MISSING,
    };
    copy_ct_value(first, first_source);

    let second = match CT_VALUE_SCRATCH.get_ptr_mut(1) {
        Some(value) => value,
        None => return CT_SNAPSHOT_CHANGED,
    };
    let second_source = match CT_TABLE_V4.get_ptr(key) {
        Some(value) => value,
        None => return CT_SNAPSHOT_CHANGED,
    };
    copy_ct_value(second, second_source);

    if ct_snapshot_is_stable(&*first, Some(&*second)) {
        CT_SNAPSHOT_STABLE
    } else {
        CT_SNAPSHOT_CHANGED
    }
}

#[inline(always)]
unsafe fn confirmed_ct_v6_snapshot(key: &CtKey6) -> u8 {
    let first = match CT_VALUE_SCRATCH.get_ptr_mut(0) {
        Some(value) => value,
        None => return CT_SNAPSHOT_CHANGED,
    };
    let first_source = match CT_TABLE_V6.get_ptr(key) {
        Some(value) => value,
        None => return CT_SNAPSHOT_MISSING,
    };
    copy_ct_value(first, first_source);

    let second = match CT_VALUE_SCRATCH.get_ptr_mut(1) {
        Some(value) => value,
        None => return CT_SNAPSHOT_CHANGED,
    };
    let second_source = match CT_TABLE_V6.get_ptr(key) {
        Some(value) => value,
        None => return CT_SNAPSHOT_CHANGED,
    };
    copy_ct_value(second, second_source);

    if ct_snapshot_is_stable(&*first, Some(&*second)) {
        CT_SNAPSHOT_STABLE
    } else {
        CT_SNAPSHOT_CHANGED
    }
}

#[inline(always)]
unsafe fn confirmed_ct_value() -> Option<*mut CtValue> {
    CT_VALUE_SCRATCH.get_ptr_mut(0)
}

#[inline(always)]
unsafe fn finish_ct_v4_hit(
    key: &CtKey4,
    entry: *mut CtValue,
    now: u64,
    pkt_len: u32,
    is_forward: bool,
) -> CtLookupResult {
    ct_apply_confirmed_hit(&mut *entry, now, pkt_len, is_forward);
    let matched = extract_matched(&*entry, key.tap_id);
    let state = (*entry).state;
    let _ = CT_TABLE_V4.insert(key, &*entry, BPF_EXIST as u64);
    CtLookupResult::Hit(matched, is_forward, state)
}

#[inline(always)]
unsafe fn finish_ct_v6_hit(
    key: &CtKey6,
    entry: *mut CtValue,
    now: u64,
    pkt_len: u32,
    is_forward: bool,
) -> CtLookupResult {
    ct_apply_confirmed_hit(&mut *entry, now, pkt_len, is_forward);
    let matched = extract_matched(&*entry, key.tap_id);
    let state = (*entry).state;
    let _ = CT_TABLE_V6.insert(key, &*entry, BPF_EXIST as u64);
    CtLookupResult::Hit(matched, is_forward, state)
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
    let forward_snapshot = confirmed_ct_v4_snapshot(key);
    if forward_snapshot == CT_SNAPSHOT_STABLE {
        let entry = match confirmed_ct_value() {
            Some(value) => value,
            None => return CtLookupResult::Miss(CtMissReason::NotFound),
        };
        if !ct_acl_cache_is_current(
            (*entry).flags,
            (*entry).matched_bank,
            (*entry).matched_family,
            validate_acl_bank,
            expected_acl_bank,
            IP_FAMILY_V4,
        ) {
            let _ = CT_TABLE_V4.remove(key);
            return CtLookupResult::Miss(CtMissReason::StaleBank);
        }
        let timeout = get_timeout(key.proto, (*entry).state);
        if now.wrapping_sub((*entry).last_seen) > timeout {
            let _ = CT_TABLE_V4.remove(key);
            return CtLookupResult::Miss(CtMissReason::Expired);
        }
        return finish_ct_v4_hit(key, entry, now, pkt_len, true);
    } else if forward_snapshot == CT_SNAPSHOT_CHANGED {
        return CtLookupResult::Miss(CtMissReason::NotFound);
    }

    // Reverse lookup — only set SEEN_REPLY flag, do NOT promote state
    let rev = reverse_key4(key);
    if confirmed_ct_v4_snapshot(&rev) == CT_SNAPSHOT_STABLE {
        let entry = match confirmed_ct_value() {
            Some(value) => value,
            None => return CtLookupResult::Miss(CtMissReason::NotFound),
        };
        if !ct_acl_cache_is_current(
            (*entry).flags,
            (*entry).matched_bank,
            (*entry).matched_family,
            validate_acl_bank,
            expected_acl_bank,
            IP_FAMILY_V4,
        ) {
            let _ = CT_TABLE_V4.remove(&rev);
            return CtLookupResult::Miss(CtMissReason::StaleBank);
        }
        let timeout = get_timeout(rev.proto, (*entry).state);
        if now.wrapping_sub((*entry).last_seen) > timeout {
            let _ = CT_TABLE_V4.remove(&rev);
            return CtLookupResult::Miss(CtMissReason::Expired);
        }
        return finish_ct_v4_hit(&rev, entry, now, pkt_len, false);
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
    let forward_snapshot = confirmed_ct_v6_snapshot(key);
    if forward_snapshot == CT_SNAPSHOT_STABLE {
        let entry = match confirmed_ct_value() {
            Some(value) => value,
            None => return CtLookupResult::Miss(CtMissReason::NotFound),
        };
        if !ct_acl_cache_is_current(
            (*entry).flags,
            (*entry).matched_bank,
            (*entry).matched_family,
            validate_acl_bank,
            expected_acl_bank,
            IP_FAMILY_V4,
        ) {
            let _ = CT_TABLE_V6.remove(key);
            return CtLookupResult::Miss(CtMissReason::StaleBank);
        }
        let timeout = get_timeout(key.proto, (*entry).state);
        if now.wrapping_sub((*entry).last_seen) > timeout {
            let _ = CT_TABLE_V6.remove(key);
            return CtLookupResult::Miss(CtMissReason::Expired);
        }
        return finish_ct_v6_hit(key, entry, now, pkt_len, true);
    } else if forward_snapshot == CT_SNAPSHOT_CHANGED {
        return CtLookupResult::Miss(CtMissReason::NotFound);
    }

    // Reverse lookup — only set SEEN_REPLY flag, do NOT promote state
    let rev = reverse_key6(key);
    if confirmed_ct_v6_snapshot(&rev) == CT_SNAPSHOT_STABLE {
        let entry = match confirmed_ct_value() {
            Some(value) => value,
            None => return CtLookupResult::Miss(CtMissReason::NotFound),
        };
        if !ct_acl_cache_is_current(
            (*entry).flags,
            (*entry).matched_bank,
            (*entry).matched_family,
            validate_acl_bank,
            expected_acl_bank,
            IP_FAMILY_V4,
        ) {
            let _ = CT_TABLE_V6.remove(&rev);
            return CtLookupResult::Miss(CtMissReason::StaleBank);
        }
        let timeout = get_timeout(rev.proto, (*entry).state);
        if now.wrapping_sub((*entry).last_seen) > timeout {
            let _ = CT_TABLE_V6.remove(&rev);
            return CtLookupResult::Miss(CtMissReason::Expired);
        }
        return finish_ct_v6_hit(&rev, entry, now, pkt_len, false);
    }

    CtLookupResult::Miss(CtMissReason::NotFound)
}

/// Create a new CT entry for IPv4 with matched policy info.
#[inline(always)]
pub unsafe fn ct_create_v4(
    key: &CtKey4,
    now: u64,
    pkt_len: u32,
    matched: &MatchedPolicy,
    acl_evaluated: bool,
) -> bool {
    if !crate::runtime::conntrack_enabled(key.tap_id) {
        return false;
    }
    let val = CtValue {
        state: CT_NEW,
        flags: (if matched.policy_hit {
            CT_FLAG_POLICY_HIT
        } else {
            0
        }) | if acl_evaluated {
            CT_FLAG_ACL_EVALUATED
        } else {
            0
        },
        direction: matched.direction,
        matched_proto: matched.proto,
        matched_src_id: matched.src_id,
        matched_dst_id: matched.dst_id,
        matched_bank: matched.bank,
        matched_family: IP_FAMILY_V4,
        _pad: [0; 2],
        last_seen: now,
        pkt_count: 1,
        byte_count: pkt_len as u64,
    };
    // Atomic no-overwrite preserves an entry created by a racing packet.
    CT_TABLE_V4.insert(key, &val, BPF_NOEXIST as u64).is_ok()
}

/// Create a new CT entry for IPv6 with matched policy info.
#[inline(always)]
pub unsafe fn ct_create_v6(
    key: &CtKey6,
    now: u64,
    pkt_len: u32,
    matched: &MatchedPolicy,
    acl_evaluated: bool,
) -> bool {
    if !crate::runtime::conntrack_enabled(key.tap_id) {
        return false;
    }
    let val = CtValue {
        state: CT_NEW,
        flags: (if matched.policy_hit {
            CT_FLAG_POLICY_HIT
        } else {
            0
        }) | if acl_evaluated {
            CT_FLAG_ACL_EVALUATED
        } else {
            0
        },
        direction: matched.direction,
        matched_proto: matched.proto,
        matched_src_id: matched.src_id,
        matched_dst_id: matched.dst_id,
        matched_bank: matched.bank,
        matched_family: IP_FAMILY_V4,
        _pad: [0; 2],
        last_seen: now,
        pkt_count: 1,
        byte_count: pkt_len as u64,
    };
    // A racing existing entry is preserved.
    CT_TABLE_V6.insert(key, &val, BPF_NOEXIST as u64).is_ok()
}
