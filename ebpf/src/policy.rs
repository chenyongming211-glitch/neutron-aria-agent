use crate::common::{
    PipelineCtx, PolicyKey, PolicyValue, PortKey, DROP_ACL_DEFAULT_DENY, DROP_ACL_DENY,
    DROP_ACL_PORT_DENY, FLAG_POLICY_HIT, XDP_DROP, XDP_PASS,
};
use crate::drops;
use crate::maps::{POLICY_TABLE, PORT_BITMAP_POOL};
use crate::stats;

/// Check if ACL (policy evaluation) is enabled.
/// When disabled, all traffic is passed without policy evaluation.
#[inline(always)]
pub fn acl_enabled(tap_id: u32) -> bool {
    crate::runtime::acl_enabled(tap_id)
}

/// 8-level fallback policy matching over the map-backed packet pipeline state.
///
/// Tries 8 candidate keys from most-specific to least-specific (wildcarding
/// src_id, dst_id, proto with 0). The matched_policy records the exact key
/// that hit (including wildcards) so the CT fast path can replay rule stats.
/// The matched key, hit flag, and drop reason are written back to `p`; only
/// the scalar XDP action is returned.
///
/// Priority order (bitmask: bit0=src_wildcard, bit1=dst_wildcard, bit2=proto_wildcard):
///   0b000, 0b001, 0b010, 0b100, 0b011, 0b101, 0b110, 0b111
#[inline(always)]
pub unsafe fn evaluate_policy(p: &mut PipelineCtx, dst_port: u16) -> u32 {
    // Priority-ordered bitmask: which fields to wildcard (0=specific value, 1=wildcard to 0)
    // bit 0: src_id, bit 1: dst_id, bit 2: proto
    const ORDER: [u8; 8] = [0b000, 0b001, 0b010, 0b100, 0b011, 0b101, 0b110, 0b111];

    let mut i = 0u8;
    while i < 8 {
        let mask = ORDER[i as usize];
        let s = if (mask & 1) != 0 { 0 } else { p.src_id };
        let d = if (mask & 2) != 0 { 0 } else { p.dst_id };
        let proto = if (mask & 4) != 0 { 0 } else { p.proto };

        let key = PolicyKey {
            tap_id: p.tap_id,
            src_id: s,
            dst_id: d,
            proto,
            direction: p.direction,
            bank: p.matched_bank,
            pad: [0; 1],
        };
        if let Some(policy) = POLICY_TABLE.get(&key) {
            let (result, drop_reason) = apply_policy(p.tap_id, policy, dst_port);
            p.matched_src_id = s;
            p.matched_dst_id = d;
            p.matched_proto = proto;
            p.matched_direction = p.direction;
            p.flags |= FLAG_POLICY_HIT;
            p.drop_reason = drop_reason;
            stats::update_rule_stats(&key, p.pkt_len, result == XDP_DROP);
            if result == XDP_DROP {
                record_policy_drop(p, drop_reason);
            }
            return result;
        }
        i += 1;
    }

    p.matched_src_id = 0;
    p.matched_dst_id = 0;
    p.matched_proto = 0;
    p.matched_direction = p.direction;
    p.flags &= !FLAG_POLICY_HIT;
    p.drop_reason = 0;
    XDP_PASS
}

#[inline(always)]
unsafe fn record_policy_drop(p: &PipelineCtx, drop_reason: u8) {
    drops::record_drop(&drops::DropArgs {
        tap_id: p.tap_id,
        reason: drop_reason,
        direction: p.direction,
        proto: p.proto,
        src_id: p.src_id,
        dst_id: p.dst_id,
        pkt_len: p.pkt_len,
        now: p.now,
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
