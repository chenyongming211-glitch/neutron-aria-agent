use aria_core::common::{
    ct_acl_family_is_current, drop_family_is_valid, policy_family_is_valid, PolicyKey,
    IP_FAMILY_V4, IP_FAMILY_V6,
};
use aria_core::drop_ops::DropStatsEntry;
use aria_core::monitoring::RuleStatsEntry;
use aria_core::port_counters::aggregate_port_counters;

fn policy_key(ip_family: u8) -> PolicyKey {
    PolicyKey {
        tap_id: 7,
        src_id: 0,
        dst_id: 0,
        proto: 0,
        direction: 0,
        bank: 1,
        ip_family,
    }
}

fn policy_key_bytes(key: PolicyKey) -> [u8; core::mem::size_of::<PolicyKey>()] {
    // PolicyKey is an ABI POD with an asserted 16-byte layout. Reading its
    // initialized bytes proves that family participates in the real map key.
    unsafe { core::mem::transmute(key) }
}

fn rule_row(ip_family: u8) -> RuleStatsEntry {
    RuleStatsEntry {
        key: PolicyKey {
            tap_id: 7,
            src_id: 11,
            dst_id: 12,
            proto: 6,
            direction: 0,
            bank: 1,
            ip_family,
        },
        packets: 1,
        bytes: 64,
        dropped_packets: 0,
        dropped_bytes: 0,
    }
}

fn drop_row(ip_family: u8) -> DropStatsEntry {
    DropStatsEntry {
        reason: 1,
        direction: 0,
        proto: 6,
        ip_family,
        src_id: 11,
        dst_id: 12,
        packets: 1,
        bytes: 64,
        last_seen: 1,
    }
}

#[test]
fn acl_ipv6_wildcard_policy_keys_do_not_alias_ipv4() {
    assert_ne!(
        policy_key_bytes(policy_key(IP_FAMILY_V4)),
        policy_key_bytes(policy_key(IP_FAMILY_V6))
    );
}

#[test]
fn acl_ipv6_ct_family_zero_and_mismatch_are_stale() {
    assert!(!ct_acl_family_is_current(0, IP_FAMILY_V6));
    assert!(!ct_acl_family_is_current(IP_FAMILY_V4, IP_FAMILY_V6));
    assert!(ct_acl_family_is_current(IP_FAMILY_V6, IP_FAMILY_V6));
}

#[test]
fn acl_ipv6_drop_family_zero_is_valid_only_for_drop_accounting() {
    assert!(drop_family_is_valid(0));
    assert!(!policy_family_is_valid(0));
}

#[test]
fn acl_ipv6_counter_bucket_identity_contains_family() {
    let rows = [rule_row(IP_FAMILY_V4), rule_row(IP_FAMILY_V6)];
    let summary = aggregate_port_counters(&rows, &[], 7);

    assert_eq!(summary.buckets.len(), 2);
    assert_eq!(
        summary
            .buckets
            .iter()
            .map(|row| row.ip_family)
            .collect::<Vec<_>>(),
        vec![IP_FAMILY_V4, IP_FAMILY_V6]
    );
}

#[test]
fn acl_ipv6_drop_reason_identity_contains_family() {
    let rows = [drop_row(IP_FAMILY_V4), drop_row(IP_FAMILY_V6)];
    let summary = aggregate_port_counters(&[], &rows, 7);

    assert_eq!(summary.reasons.len(), 2);
    assert_eq!(
        summary
            .reasons
            .iter()
            .map(|row| row.ip_family)
            .collect::<Vec<_>>(),
        vec![IP_FAMILY_V4, IP_FAMILY_V6]
    );
}
