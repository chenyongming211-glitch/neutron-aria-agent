use crate::common::{CtContractKey, TAP_ID_UNASSIGNED};
use crate::maps::{CT_CONTRACT_STATS, CT_CONTRACT_VALUE_BUF};

#[repr(C)]
#[derive(Copy, Clone)]
pub struct CtContractArgs {
    pub tap_id: u32,
    pub pkt_len: u32,
    pub now: u64,
    pub hook: u8,
    pub family: u8,
    pub reason: u8,
    pub _pad: u8,
}

#[inline(always)]
pub unsafe fn record_event(args: &CtContractArgs) {
    if args.tap_id == TAP_ID_UNASSIGNED {
        return;
    }

    let key = CtContractKey {
        tap_id: args.tap_id,
        hook: args.hook,
        family: args.family,
        reason: args.reason,
        pad: 0,
    };

    if let Some(v) = CT_CONTRACT_STATS.get_ptr_mut(&key) {
        (*v).packets += 1;
        (*v).bytes += args.pkt_len as u64;
        (*v).last_seen = args.now;
    } else {
        let val = match CT_CONTRACT_VALUE_BUF.get_ptr_mut(0) {
            Some(v) => v,
            None => return,
        };
        (*val).packets = 1;
        (*val).bytes = args.pkt_len as u64;
        (*val).last_seen = args.now;
        let _ = CT_CONTRACT_STATS.insert(&key, &*val, 0);
    }
}
