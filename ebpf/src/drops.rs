use crate::common::{DropKey, PipelineCtx};
use crate::maps::{DROP_KEY_SCRATCH, DROP_REASON_STATS, DROP_VALUE_BUF};

/// Record a post-family pipeline drop without materializing a DropKey on the
/// legacy verifier stack.
#[inline(always)]
pub unsafe fn record_pipeline_drop(p: &PipelineCtx, reason: u8) {
    let key = match DROP_KEY_SCRATCH.get_ptr_mut(0) {
        Some(key) => key,
        None => return,
    };
    (*key).tap_id = p.tap_id;
    (*key).reason = reason;
    (*key).direction = p.direction;
    (*key).proto = p.proto;
    (*key).ip_family = p.ip_family;
    (*key).src_id = p.src_id;
    (*key).dst_id = p.dst_id;
    record_drop(&*key, p.pkt_len, p.now);
}

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
