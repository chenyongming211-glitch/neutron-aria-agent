use crate::maps::{TRACE_EVENT_BUF, TRACE_FILTER, TRACE_LOG, TRACE_SEQ};
use crate::common::TraceEventKey;
use crate::parser::PacketInfo;
use aya_ebpf::helpers::bpf_get_smp_processor_id;

/// Check if tracing is enabled and packet matches filter.
/// Returns false quickly if filter is not set or not matching (zero overhead path).
#[inline(always)]
pub unsafe fn should_trace(tap_id: u32, info: &PacketInfo) -> bool {
    let filter = match TRACE_FILTER.get(&tap_id) {
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

#[inline(always)]
unsafe fn next_trace_event_key(tap_id: u32, seq_ptr: *mut u64) -> TraceEventKey {
    let local_seq = *seq_ptr;
    *seq_ptr = local_seq.wrapping_add(1);

    let cpu_id = (bpf_get_smp_processor_id() as u64) & 0xff;
    TraceEventKey {
        tap_id,
        pad: 0,
        seq: ((local_seq & 0x00ff_ffff_ffff_ffff) << 8) | cpu_id,
    }
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
    tap_id: u32,
    info: &PacketInfo,
    args: &TraceArgs,
) {
    let seq_key: u32 = 0;
    if let Some(seq) = TRACE_SEQ.get_ptr_mut(seq_key) {
        if let Some(event) = TRACE_EVENT_BUF.get_ptr_mut(0) {
            let event_key = next_trace_event_key(tap_id, seq);
            (*event).timestamp = args.now;
            (*event).src_ip = info.src_ip;
            (*event).dst_ip = info.dst_ip;
            (*event).src_port = info.src_port;
            (*event).dst_port = info.dst_port;
            (*event).proto = info.proto;
            (*event).hook = args.hook;
            (*event).result = args.result;
            (*event).direction = args.direction;
            (*event).src_id = args.src_id;
            (*event).dst_id = args.dst_id;
            (*event).pkt_len = args.pkt_len;
            (*event).ct_state = args.ct_state;
            (*event).drop_reason = args.drop_reason;
            (*event).pad = [0; 2];
            let _ = TRACE_LOG.insert(&event_key, &*event, 0);
        }
    }
}
