use crate::common::{CtContractKey, PipelineCtx};
use crate::maps::{CT_CONTRACT_STATS, CT_CONTRACT_VALUE_BUF};

#[inline(always)]
pub unsafe fn record_event(p: &PipelineCtx, hook: u8, family: u8, reason: u8) {
    let key = CtContractKey {
        tap_id: p.tap_id,
        hook,
        family,
        reason,
        pad: 0,
    };

    if let Some(v) = CT_CONTRACT_STATS.get_ptr_mut(&key) {
        (*v).packets += 1;
        (*v).bytes += p.pkt_len as u64;
        (*v).last_seen = p.now;
    } else {
        let val = match CT_CONTRACT_VALUE_BUF.get_ptr_mut(0) {
            Some(v) => v,
            None => return,
        };
        (*val).packets = 1;
        (*val).bytes = p.pkt_len as u64;
        (*val).last_seen = p.now;
        let _ = CT_CONTRACT_STATS.insert(&key, &*val, 0);
    }
}
