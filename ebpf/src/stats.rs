use crate::common::{CtKey4, CtKey6, GroupStatsKey, PolicyKey};
use crate::maps::{
    FLOW_STATS_BUF, FLOW_STATS_V4, FLOW_STATS_V6, GROUP_STATS, GROUP_STATS_BUF, RULE_STATS,
    RULE_STATS_BUF,
};

#[inline(always)]
pub(crate) fn monitoring_enabled(tap_id: u32) -> bool {
    crate::runtime::monitoring_enabled(tap_id)
}

#[inline(always)]
pub unsafe fn update_rule_stats(key: &PolicyKey, pkt_len: u32, dropped: bool) {
    if !monitoring_enabled(key.tap_id) {
        return;
    }
    if let Some(s) = RULE_STATS.get_ptr_mut(key) {
        (*s).packets += 1;
        (*s).bytes += pkt_len as u64;
        if dropped {
            (*s).dropped_packets += 1;
            (*s).dropped_bytes += pkt_len as u64;
        }
    } else {
        let val = match RULE_STATS_BUF.get_ptr_mut(0) {
            Some(v) => v,
            None => return,
        };
        (*val).packets = 1;
        (*val).bytes = pkt_len as u64;
        (*val).dropped_packets = if dropped { 1 } else { 0 };
        (*val).dropped_bytes = if dropped { pkt_len as u64 } else { 0 };
        let _ = RULE_STATS.insert(key, &*val, 0);
    }
}

#[inline(always)]
pub unsafe fn update_flow_stats_v4(key: &CtKey4, pkt_len: u32, now: u64) {
    if !monitoring_enabled(key.tap_id) {
        return;
    }
    if let Some(s) = FLOW_STATS_V4.get_ptr_mut(key) {
        (*s).packets += 1;
        (*s).bytes += pkt_len as u64;
        (*s).last_seen = now;
    } else {
        let val = match FLOW_STATS_BUF.get_ptr_mut(0) {
            Some(v) => v,
            None => return,
        };
        (*val).packets = 1;
        (*val).bytes = pkt_len as u64;
        (*val).last_seen = now;
        let _ = FLOW_STATS_V4.insert(key, &*val, 0);
    }
}

#[inline(always)]
pub unsafe fn update_flow_stats_v6(key: &CtKey6, pkt_len: u32, now: u64) {
    if !monitoring_enabled(key.tap_id) {
        return;
    }
    if let Some(s) = FLOW_STATS_V6.get_ptr_mut(key) {
        (*s).packets += 1;
        (*s).bytes += pkt_len as u64;
        (*s).last_seen = now;
    } else {
        let val = match FLOW_STATS_BUF.get_ptr_mut(0) {
            Some(v) => v,
            None => return,
        };
        (*val).packets = 1;
        (*val).bytes = pkt_len as u64;
        (*val).last_seen = now;
        let _ = FLOW_STATS_V6.insert(key, &*val, 0);
    }
}

#[inline(always)]
pub unsafe fn update_group_stats(tap_id: u32, group_id: u32, direction: u8, pkt_len: u32) {
    if !monitoring_enabled(tap_id) {
        return;
    }
    let key = GroupStatsKey {
        tap_id,
        group_id,
        direction,
        pad: [0; 3],
    };
    if let Some(s) = GROUP_STATS.get_ptr_mut(&key) {
        (*s).packets += 1;
        (*s).bytes += pkt_len as u64;
    } else {
        let val = match GROUP_STATS_BUF.get_ptr_mut(0) {
            Some(v) => v,
            None => return,
        };
        (*val).packets = 1;
        (*val).bytes = pkt_len as u64;
        let _ = GROUP_STATS.insert(&key, &*val, 0);
    }
}
