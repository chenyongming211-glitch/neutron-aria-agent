use crate::common::{DropKey, DropValue};
use crate::maps::DROP_REASON_STATS;

#[repr(C)]
#[derive(Copy, Clone)]
pub struct DropArgs {
    pub tap_id: u32,
    pub src_id: u32,
    pub dst_id: u32,
    pub pkt_len: u32,
    pub now: u64,
    pub reason: u8,
    pub direction: u8,
    pub proto: u8,
    pub _pad: u8,
}

/// Record a drop event in the DROP_REASON_STATS per-CPU hash map.
#[inline(always)]
pub unsafe fn record_drop(args: &DropArgs) {
    let key = DropKey {
        tap_id: args.tap_id,
        reason: args.reason,
        direction: args.direction,
        proto: args.proto,
        pad: 0,
        src_id: args.src_id,
        dst_id: args.dst_id,
    };

    if let Some(v) = DROP_REASON_STATS.get_ptr_mut(&key) {
        (*v).packets += 1;
        (*v).bytes += args.pkt_len as u64;
        (*v).last_seen = args.now;
    } else {
        let val = DropValue {
            packets: 1,
            bytes: args.pkt_len as u64,
            last_seen: args.now,
        };
        let _ = DROP_REASON_STATS.insert(&key, &val, 0);
    }
}
