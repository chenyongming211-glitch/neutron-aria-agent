use crate::common::{DropKey, DropValue};
use crate::maps::DROP_REASON_STATS;

/// Record a drop event in the DROP_REASON_STATS per-CPU hash map.
#[inline(always)]
pub unsafe fn record_drop(
    reason: u8,
    direction: u8,
    proto: u8,
    src_id: u32,
    dst_id: u32,
    pkt_len: u32,
    now: u64,
) {
    let key = DropKey {
        reason,
        direction,
        proto,
        pad: 0,
        src_id,
        dst_id,
    };

    if let Some(v) = DROP_REASON_STATS.get_ptr_mut(&key) {
        (*v).packets += 1;
        (*v).bytes += pkt_len as u64;
        (*v).last_seen = now;
    } else {
        let val = DropValue {
            packets: 1,
            bytes: pkt_len as u64,
            last_seen: now,
        };
        let _ = DROP_REASON_STATS.insert(&key, &val, 0);
    }
}
