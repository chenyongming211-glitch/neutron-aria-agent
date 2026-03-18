use crate::common::{MirrorKey, GlobalMirrorKey, MirrorStatsValue};
use crate::maps::{FIREWALL_CONFIG, MIRROR_POLICY, MIRROR_GLOBAL, MIRROR_STATS, MIRROR_GLOBAL_STATS};
use aya_ebpf::helpers::gen::bpf_clone_redirect;

/// Check if mirror is globally enabled via FIREWALL_CONFIG.
#[inline(always)]
pub fn mirror_enabled() -> bool {
    let key: u32 = 0;
    if let Some(cfg) = unsafe { FIREWALL_CONFIG.get(&key) } {
        cfg.mirror_enabled != 0
    } else {
        false
    }
}

/// Update per-rule mirror stats (MIRROR_STATS).
#[inline(never)]
unsafe fn update_mirror_stats(key: &MirrorKey, pkt_len: u32, success: bool) {
    if let Some(s) = MIRROR_STATS.get_ptr_mut(key) {
        if success {
            (*s).mirrored_packets += 1;
            (*s).mirrored_bytes += pkt_len as u64;
        } else {
            (*s).errors += 1;
        }
    } else {
        let val = if success {
            MirrorStatsValue { mirrored_packets: 1, mirrored_bytes: pkt_len as u64, errors: 0 }
        } else {
            MirrorStatsValue { mirrored_packets: 0, mirrored_bytes: 0, errors: 1 }
        };
        let _ = MIRROR_STATS.insert(key, &val, 0);
    }
}

/// Update global mirror stats (MIRROR_GLOBAL_STATS).
#[inline(never)]
unsafe fn update_global_mirror_stats(key: &GlobalMirrorKey, pkt_len: u32, success: bool) {
    if let Some(s) = MIRROR_GLOBAL_STATS.get_ptr_mut(key) {
        if success {
            (*s).mirrored_packets += 1;
            (*s).mirrored_bytes += pkt_len as u64;
        } else {
            (*s).errors += 1;
        }
    } else {
        let val = if success {
            MirrorStatsValue { mirrored_packets: 1, mirrored_bytes: pkt_len as u64, errors: 0 }
        } else {
            MirrorStatsValue { mirrored_packets: 0, mirrored_bytes: 0, errors: 1 }
        };
        let _ = MIRROR_GLOBAL_STATS.insert(key, &val, 0);
    }
}

/// Try to mirror a packet via TC (bpf_clone_redirect).
/// Two-level lookup:
///   1. Exact match in MIRROR_POLICY[src_id, dst_id, proto, direction]
///   2. Global match in MIRROR_GLOBAL[direction]
///
/// `skb_ptr` must be the raw `*mut __sk_buff` from TcContext.
/// This function always returns — the original packet is never consumed.
#[inline(never)]
pub unsafe fn try_mirror_tc(
    skb_ptr: *mut aya_ebpf::bindings::__sk_buff,
    src_id: u32,
    dst_id: u32,
    proto: u8,
    direction: u8,
    pkt_len: u32,
) {
    // Level 1: per-rule mirror policy
    let policy_key = MirrorKey {
        src_id,
        dst_id,
        proto,
        direction,
        pad: [0; 2],
    };

    if let Some(cfg) = MIRROR_POLICY.get(&policy_key) {
        let ret = bpf_clone_redirect(skb_ptr, cfg.target_ifindex, 0);
        update_mirror_stats(&policy_key, pkt_len, ret == 0);
        return;
    }

    // Level 2: global mirror
    let global_key = GlobalMirrorKey {
        direction,
        pad: [0; 3],
    };

    if let Some(cfg) = MIRROR_GLOBAL.get(&global_key) {
        let ret = bpf_clone_redirect(skb_ptr, cfg.target_ifindex, 0);
        update_global_mirror_stats(&global_key, pkt_len, ret == 0);
    }
}
