use crate::common::{
    PolicyKey, PolicyValue, PortKey, DROP_ACL_DEFAULT_DENY, DROP_ACL_DENY, DROP_ACL_PORT_DENY,
    XDP_DROP, XDP_PASS,
};
use crate::conntrack::MatchedPolicy;
use crate::drops;
use crate::maps::{POLICY_TABLE, PORT_BITMAP_POOL};
use crate::stats;

/// Packed parameters for evaluate_policy to stay within BPF's 5-argument limit.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct PolicyArgs {
    pub tap_id: u32,
    pub src_id: u32,
    pub dst_id: u32,
    pub pkt_len: u32,
    pub now: u64,
    pub dst_port: u16,
    pub proto: u8,
    pub direction: u8,
    pub bank: u8,
}

/// Check if ACL (policy evaluation) is enabled.
/// When disabled, all traffic is passed without policy evaluation.
#[inline(always)]
pub fn acl_enabled(tap_id: u32) -> bool {
    crate::runtime::acl_enabled(tap_id)
}

/// 8-level fallback policy matching. Returns (XDP action, drop_reason, matched_policy).
///
/// drop_reason is 0 when action is PASS, or one of DROP_ACL_* when action is DROP.
///
/// Tries 8 candidate keys from most-specific to least-specific (wildcarding
/// src_id, dst_id, proto with 0). The matched_policy records the exact key
/// that hit (including wildcards) so the CT fast path can replay rule stats.
/// The final bool indicates whether a policy entry actually matched.
///
/// Priority order (bitmask: bit0=src_wildcard, bit1=dst_wildcard, bit2=proto_wildcard):
///   0b000, 0b001, 0b010, 0b100, 0b011, 0b101, 0b110, 0b111
#[inline(always)]
pub unsafe fn evaluate_policy(args: &PolicyArgs) -> (u32, u8, MatchedPolicy, bool) {
    // Priority-ordered bitmask: which fields to wildcard (0=specific value, 1=wildcard to 0)
    // bit 0: src_id, bit 1: dst_id, bit 2: proto
    const ORDER: [u8; 8] = [0b000, 0b001, 0b010, 0b100, 0b011, 0b101, 0b110, 0b111];

    let mut i = 0u8;
    while i < 8 {
        let mask = ORDER[i as usize];
        let s = if (mask & 1) != 0 { 0 } else { args.src_id };
        let d = if (mask & 2) != 0 { 0 } else { args.dst_id };
        let p = if (mask & 4) != 0 { 0 } else { args.proto };

        let key = PolicyKey {
            tap_id: args.tap_id,
            src_id: s,
            dst_id: d,
            proto: p,
            direction: args.direction,
            bank: args.bank,
            pad: [0; 1],
        };
        if let Some(policy) = POLICY_TABLE.get(&key) {
            let (result, drop_reason) = apply_policy(args.tap_id, policy, args.dst_port);
            let matched = MatchedPolicy {
                tap_id: args.tap_id,
                src_id: s,
                dst_id: d,
                proto: p,
                direction: args.direction,
                bank: args.bank,
            };
            return (result, drop_reason, matched, true);
        }
        i += 1;
    }

    let matched = MatchedPolicy {
        tap_id: args.tap_id,
        src_id: 0,
        dst_id: 0,
        proto: 0,
        direction: args.direction,
        bank: args.bank,
    };
    (XDP_PASS, 0, matched, false)
}

#[inline(always)]
pub unsafe fn account_policy_result(
    args: &PolicyArgs,
    matched: &MatchedPolicy,
    result: u32,
    drop_reason: u8,
) {
    stats::update_rule_stats(&matched.to_policy_key(), args.pkt_len, result == XDP_DROP);
    if result == XDP_DROP {
        record_policy_drop(args, drop_reason);
    }
}

#[inline(always)]
pub unsafe fn record_policy_drop(args: &PolicyArgs, drop_reason: u8) {
    drops::record_drop(&drops::DropArgs {
        tap_id: args.tap_id,
        reason: drop_reason,
        direction: args.direction,
        proto: args.proto,
        src_id: args.src_id,
        dst_id: args.dst_id,
        pkt_len: args.pkt_len,
        now: args.now,
        _pad: 0,
    });
}

/// Returns (XDP action, drop_reason). drop_reason is 0 for PASS.
fn apply_policy(tap_id: u32, policy: &PolicyValue, dst_port: u16) -> (u32, u8) {
    if policy.has_port_filter == 0 {
        return if policy.action == 0 {
            (XDP_PASS, 0)
        } else {
            (XDP_DROP, DROP_ACL_DENY)
        };
    }

    let key = PortKey {
        tap_id,
        idx: policy.bitmap_idx,
        port: dst_port,
        pad: 0,
    };
    let rule_action = unsafe { PORT_BITMAP_POOL.get(&key).copied().unwrap_or(0) };

    match rule_action {
        1 => (XDP_DROP, DROP_ACL_PORT_DENY),
        2 => (XDP_PASS, 0),
        _ => {
            if policy.action == 0 {
                (XDP_PASS, 0)
            } else {
                (XDP_DROP, DROP_ACL_DEFAULT_DENY)
            }
        }
    }
}
