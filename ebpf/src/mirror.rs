use crate::common::{GlobalMirrorKey, MirrorKey};
use crate::maps::{
    MIRROR_GLOBAL, MIRROR_GLOBAL_STATS, MIRROR_POLICY, MIRROR_STATS, MIRROR_STATS_BUF,
};
use aya_ebpf::helpers::gen::bpf_clone_redirect;

/// Check if mirror is globally enabled via FIREWALL_CONFIG.
#[inline(always)]
pub fn mirror_enabled(tap_id: u32) -> bool {
    crate::runtime::mirror_enabled(tap_id)
}

/// Update per-rule mirror stats (MIRROR_STATS).
#[inline(always)]
unsafe fn update_mirror_stats(key: &MirrorKey, pkt_len: u32, success: bool) {
    if let Some(s) = MIRROR_STATS.get_ptr_mut(key) {
        if success {
            (*s).mirrored_packets += 1;
            (*s).mirrored_bytes += pkt_len as u64;
        } else {
            (*s).errors += 1;
        }
    } else {
        let val = match MIRROR_STATS_BUF.get_ptr_mut(0) {
            Some(v) => v,
            None => return,
        };
        if success {
            (*val).mirrored_packets = 1;
            (*val).mirrored_bytes = pkt_len as u64;
            (*val).errors = 0;
        } else {
            (*val).mirrored_packets = 0;
            (*val).mirrored_bytes = 0;
            (*val).errors = 1;
        }
        let _ = MIRROR_STATS.insert(key, &*val, 0);
    }
}

/// Update global mirror stats (MIRROR_GLOBAL_STATS).
#[inline(always)]
unsafe fn update_global_mirror_stats(key: &GlobalMirrorKey, pkt_len: u32, success: bool) {
    if let Some(s) = MIRROR_GLOBAL_STATS.get_ptr_mut(key) {
        if success {
            (*s).mirrored_packets += 1;
            (*s).mirrored_bytes += pkt_len as u64;
        } else {
            (*s).errors += 1;
        }
    } else {
        let val = match MIRROR_STATS_BUF.get_ptr_mut(0) {
            Some(v) => v,
            None => return,
        };
        if success {
            (*val).mirrored_packets = 1;
            (*val).mirrored_bytes = pkt_len as u64;
            (*val).errors = 0;
        } else {
            (*val).mirrored_packets = 0;
            (*val).mirrored_bytes = 0;
            (*val).errors = 1;
        }
        let _ = MIRROR_GLOBAL_STATS.insert(key, &*val, 0);
    }
}

/// Try to mirror a packet via TC (bpf_clone_redirect).
/// Two-level lookup:
///   1. 8-level fallback match in MIRROR_POLICY[src_id, dst_id, proto, direction]
///   2. Global match in MIRROR_GLOBAL[direction]
///
/// `skb_ptr` must be the raw `*mut __sk_buff` from TcContext.
/// This function always returns — the original packet is never consumed.
#[inline(always)]
pub unsafe fn try_mirror_tc(
    skb_ptr: *mut aya_ebpf::bindings::__sk_buff,
    tap_id: u32,
    src_id: u32,
    dst_id: u32,
    proto: u8,
    direction: u8,
    pkt_len: u32,
) {
    // bit 0: src_id wildcard, bit 1: dst_id wildcard, bit 2: proto wildcard
    const ORDER: [u8; 8] = [0b000, 0b001, 0b010, 0b100, 0b011, 0b101, 0b110, 0b111];

    let mut i = 0u8;
    while i < 8 {
        let mask = ORDER[i as usize];
        let policy_key = MirrorKey {
            tap_id,
            src_id: if (mask & 1) != 0 { 0 } else { src_id },
            dst_id: if (mask & 2) != 0 { 0 } else { dst_id },
            proto: if (mask & 4) != 0 { 0 } else { proto },
            direction,
            pad: [0; 2],
        };

        if let Some(cfg) = MIRROR_POLICY.get(&policy_key) {
            let ret = bpf_clone_redirect(skb_ptr, cfg.target_ifindex, 0);
            update_mirror_stats(&policy_key, pkt_len, ret == 0);
            return;
        }

        i += 1;
    }

    // Level 2: global mirror
    let global_key = GlobalMirrorKey {
        tap_id,
        direction,
        pad: [0; 3],
    };

    if let Some(cfg) = MIRROR_GLOBAL.get(&global_key) {
        let ret = bpf_clone_redirect(skb_ptr, cfg.target_ifindex, 0);
        update_global_mirror_stats(&global_key, pkt_len, ret == 0);
    }
}
