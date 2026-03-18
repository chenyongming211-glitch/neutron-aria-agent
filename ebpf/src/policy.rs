use crate::common::{
    PolicyKey, PolicyValue, PortKey,
    XDP_PASS, XDP_DROP,
    DROP_ACL_DENY, DROP_ACL_PORT_DENY, DROP_ACL_DEFAULT_DENY,
};
use crate::maps::{POLICY_TABLE, PORT_BITMAP_POOL, FIREWALL_CONFIG};
use crate::conntrack::MatchedPolicy;
use crate::stats;
use crate::drops;

/// Check if ACL (policy evaluation) is enabled.
/// When disabled, all traffic is passed without policy evaluation.
#[inline(always)]
pub fn acl_enabled() -> bool {
    let key: u32 = 0;
    if let Some(cfg) = unsafe { FIREWALL_CONFIG.get(&key) } {
        cfg.acl_enabled != 0
    } else {
        true // default: ACL enabled
    }
}

/// 8-level fallback policy matching. Returns (XDP action, drop_reason, matched_policy).
///
/// drop_reason is 0 when action is PASS, or one of DROP_ACL_* when action is DROP.
///
/// Tries 8 candidate keys from most-specific to least-specific (wildcarding
/// src_id, dst_id, proto with 0). The matched_policy records the exact key
/// that hit (including wildcards) so the CT fast path can replay rule stats.
#[inline(always)]
pub unsafe fn evaluate_policy(
    src_id: u32,
    dst_id: u32,
    proto: u8,
    direction: u8,
    dst_port: u16,
    pkt_len: u32,
    now: u64,
) -> (u32, u8, MatchedPolicy) {
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
            let (result, drop_reason) = apply_policy(policy, dst_port);
            stats::update_rule_stats(&key, pkt_len);
            if result == XDP_DROP {
                drops::record_drop(drop_reason, direction, proto, src_id, dst_id, pkt_len, now);
            }
            let matched = MatchedPolicy {
                src_id: s,
                dst_id: d,
                proto: p,
                direction,
            };
            return (result, drop_reason, matched);
        }
        i += 1;
    }

    let matched = MatchedPolicy {
        src_id: 0,
        dst_id: 0,
        proto: 0,
        direction,
    };
    (XDP_PASS, 0, matched)
}

/// Same 8-level fallback, but returns TC action codes (TC_ACT_OK / TC_ACT_SHOT).
#[inline(always)]
pub unsafe fn evaluate_policy_tc(
    src_id: u32,
    dst_id: u32,
    proto: u8,
    direction: u8,
    dst_port: u16,
    pkt_len: u32,
    tc_act_ok: i32,
    tc_act_shot: i32,
    now: u64,
) -> (i32, u8, MatchedPolicy) {
    let (xdp_result, drop_reason, matched) = evaluate_policy(src_id, dst_id, proto, direction, dst_port, pkt_len, now);
    let tc_result = if xdp_result == XDP_PASS { tc_act_ok } else { tc_act_shot };
    (tc_result, drop_reason, matched)
}

/// Returns (XDP action, drop_reason). drop_reason is 0 for PASS.
fn apply_policy(policy: &PolicyValue, dst_port: u16) -> (u32, u8) {
    if policy.has_port_filter == 0 {
        return if policy.action == 0 {
            (XDP_PASS, 0)
        } else {
            (XDP_DROP, DROP_ACL_DENY)
        };
    }

    let key = PortKey { idx: policy.bitmap_idx, port: dst_port, pad: 0 };
    let rule_action = unsafe { PORT_BITMAP_POOL.get(&key).copied().unwrap_or(0) };

    match rule_action {
        1 => (XDP_DROP, DROP_ACL_PORT_DENY),
        2 => (XDP_PASS, 0),
        _ => if policy.action == 0 {
            (XDP_PASS, 0)
        } else {
            (XDP_DROP, DROP_ACL_DEFAULT_DENY)
        },
    }
}
