use crate::common::TraceEvent;
use crate::maps::{TRACE_FILTER, TRACE_LOG, TRACE_SEQ};
use crate::parser::PacketInfo;

/// Check if tracing is enabled and packet matches filter.
/// Returns false quickly if filter is not set or not matching (zero overhead path).
#[inline(always)]
pub unsafe fn should_trace(info: &PacketInfo) -> bool {
    // Only trace IPv4 packets (TraceFilter uses u32 IPs)
    if info.is_ipv6 {
        return false;
    }
    let key: u32 = 0;
    let filter = match TRACE_FILTER.get(&key) {
        Some(f) => f,
        None => return false,
    };
    if filter.enabled == 0 {
        return false;
    }
    if filter.src_ip != 0 && filter.src_ip != info.src_ip {
        return false;
    }
    if filter.dst_ip != 0 && filter.dst_ip != info.dst_ip {
        return false;
    }
    if filter.src_port != 0 && filter.src_port != info.src_port {
        return false;
    }
    if filter.dst_port != 0 && filter.dst_port != info.dst_port {
        return false;
    }
    if filter.proto != 0 && filter.proto != info.proto {
        return false;
    }
    true
}

/// Record a trace event into the TRACE_LOG LRU map.
#[inline(always)]
pub unsafe fn trace_event(
    info: &PacketInfo,
    hook: u8,
    result: u8,
    direction: u8,
    src_id: u32,
    dst_id: u32,
    pkt_len: u32,
    ct_state: u8,
    drop_reason: u8,
    now: u64,
) {
    let seq_key: u32 = 0;
    if let Some(seq) = TRACE_SEQ.get_ptr_mut(seq_key) {
        *seq += 1;
        let event = TraceEvent {
            timestamp: now,
            src_ip: info.src_ip,
            dst_ip: info.dst_ip,
            src_port: info.src_port,
            dst_port: info.dst_port,
            proto: info.proto,
            hook,
            result,
            direction,
            src_id,
            dst_id,
            pkt_len,
            ct_state,
            drop_reason,
            pad: [0; 2],
        };
        let _ = TRACE_LOG.insert(seq, &event, 0);
    }
}
