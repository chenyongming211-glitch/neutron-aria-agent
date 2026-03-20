use crate::common::TraceEvent;
use crate::maps::{TRACE_FILTER, TRACE_LOG, TRACE_SEQ};
use crate::parser::PacketInfo;

/// Check if tracing is enabled and packet matches filter.
/// Returns false quickly if filter is not set or not matching (zero overhead path).
#[inline(always)]
pub unsafe fn should_trace(info: &PacketInfo) -> bool {
    let key: u32 = 0;
    let filter = match TRACE_FILTER.get(&key) {
        Some(f) => f,
        None => return false,
    };
    if filter.enabled == 0 {
        return false;
    }
    // is_ipv6: 0=IPv4 only, 1=IPv6 only, 2=both
    if info.is_ipv6 {
        if filter.is_ipv6 == 0 {
            return false;
        }
        // Match IPv6 addresses (all-zero = any)
        if filter.src_ip_v6 != [0u8; 16] && filter.src_ip_v6 != info.src_ip_v6 {
            return false;
        }
        if filter.dst_ip_v6 != [0u8; 16] && filter.dst_ip_v6 != info.dst_ip_v6 {
            return false;
        }
    } else {
        if filter.is_ipv6 == 1 {
            return false;
        }
        if filter.src_ip != 0 && filter.src_ip != info.src_ip {
            return false;
        }
        if filter.dst_ip != 0 && filter.dst_ip != info.dst_ip {
            return false;
        }
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

/// Packed parameters for trace_event to stay within BPF's 5-argument limit.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct TraceArgs {
    pub hook: u8,
    pub result: u8,
    pub direction: u8,
    pub ct_state: u8,
    pub drop_reason: u8,
    pub _pad: [u8; 3],
    pub src_id: u32,
    pub dst_id: u32,
    pub pkt_len: u32,
    pub now: u64,
}

/// Record a trace event into the TRACE_LOG LRU map.
#[inline(always)]
pub unsafe fn trace_event(
    info: &PacketInfo,
    args: &TraceArgs,
) {
    let seq_key: u32 = 0;
    if let Some(seq) = TRACE_SEQ.get_ptr_mut(seq_key) {
        *seq += 1;
        let event = TraceEvent {
            timestamp: args.now,
            src_ip: info.src_ip,
            dst_ip: info.dst_ip,
            src_port: info.src_port,
            dst_port: info.dst_port,
            proto: info.proto,
            hook: args.hook,
            result: args.result,
            direction: args.direction,
            src_id: args.src_id,
            dst_id: args.dst_id,
            pkt_len: args.pkt_len,
            ct_state: args.ct_state,
            drop_reason: args.drop_reason,
            pad: [0; 2],
        };
        let _ = TRACE_LOG.insert(&*seq, &event, 0);
    }
}
