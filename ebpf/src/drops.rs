use crate::common::DropKey;
use crate::maps::{DROP_REASON_STATS, DROP_VALUE_BUF};

/// Record a drop event in the DROP_REASON_STATS per-CPU hash map.
#[inline(always)]
pub unsafe fn record_drop(key: &DropKey, pkt_len: u32, now: u64) {
    if let Some(v) = DROP_REASON_STATS.get_ptr_mut(key) {
        (*v).packets += 1;
        (*v).bytes += pkt_len as u64;
        (*v).last_seen = now;
    } else {
        let val = match DROP_VALUE_BUF.get_ptr_mut(0) {
            Some(v) => v,
            None => return,
        };
        (*val).packets = 1;
        (*val).bytes = pkt_len as u64;
        (*val).last_seen = now;
        let _ = DROP_REASON_STATS.insert(key, &*val, 0);
    }
}
