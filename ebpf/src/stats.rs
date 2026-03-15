use crate::common::{PolicyKey, RuleStatsValue, FlowStatsValue, CtKey4, CtKey6};
use crate::maps::{RULE_STATS, FLOW_STATS_V4, FLOW_STATS_V6, FIREWALL_CONFIG};

#[inline(always)]
fn monitoring_enabled() -> bool {
    let key: u32 = 0;
    // 默认开启监控；只有明确配置为 0 时才关闭
    if let Some(cfg) = unsafe { FIREWALL_CONFIG.get(&key) } {
        cfg.monitoring_enabled != 0
    } else {
        true
    }
}

#[inline(always)]
pub unsafe fn update_rule_stats(key: &PolicyKey, pkt_len: u32) {
    if !monitoring_enabled() {
        return;
    }
    if let Some(s) = RULE_STATS.get_ptr_mut(key) {
        (*s).packets += 1;
        (*s).bytes += pkt_len as u64;
    } else {
        let val = RuleStatsValue {
            packets: 1,
            bytes: pkt_len as u64,
        };
        let _ = RULE_STATS.insert(key, &val, 0);
    }
}

#[inline(always)]
pub unsafe fn update_flow_stats_v4(key: &CtKey4, pkt_len: u32, now: u64) {
    if !monitoring_enabled() {
        return;
    }
    if let Some(s) = FLOW_STATS_V4.get_ptr_mut(key) {
        (*s).packets += 1;
        (*s).bytes += pkt_len as u64;
        (*s).last_seen = now;
    } else {
        let val = FlowStatsValue {
            packets: 1,
            bytes: pkt_len as u64,
            last_seen: now,
        };
        let _ = FLOW_STATS_V4.insert(key, &val, 0);
    }
}

#[inline(always)]
pub unsafe fn update_flow_stats_v6(key: &CtKey6, pkt_len: u32, now: u64) {
    if !monitoring_enabled() {
        return;
    }
    if let Some(s) = FLOW_STATS_V6.get_ptr_mut(key) {
        (*s).packets += 1;
        (*s).bytes += pkt_len as u64;
        (*s).last_seen = now;
    } else {
        let val = FlowStatsValue {
            packets: 1,
            bytes: pkt_len as u64,
            last_seen: now,
        };
        let _ = FLOW_STATS_V6.insert(key, &val, 0);
    }
}
