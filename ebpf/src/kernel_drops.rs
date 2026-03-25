use aya_ebpf::helpers::{bpf_ktime_get_ns, bpf_probe_read_kernel};
use aya_ebpf::macros::tracepoint;
use aya_ebpf::programs::TracePointContext;

use crate::common::{
    KernelDropConfig, KernelDropKey, KERNEL_DROP_FLAG_HAS_LOCATION, KERNEL_DROP_FLAG_HAS_PROTOCOL,
    KERNEL_DROP_FLAG_HAS_REASON,
};
use crate::maps::{
    KERNEL_DROP_CONFIG, KERNEL_DROP_STATS, KERNEL_DROP_VALUE_BUF, MANAGED_IFINDEX_FILTER,
};

const KERNEL_DROP_CONFIG_KEY: u32 = 0;

#[tracepoint]
pub fn kernel_drop_trace(ctx: TracePointContext) -> u32 {
    unsafe {
        let _ = try_kernel_drop_trace(&ctx);
    }
    0
}

#[inline(always)]
unsafe fn try_kernel_drop_trace(ctx: &TracePointContext) -> Result<(), i64> {
    let config = match KERNEL_DROP_CONFIG.get(&KERNEL_DROP_CONFIG_KEY) {
        Some(config) => config,
        None => return Ok(()),
    };

    let reason_code = read_reason_code(ctx, config);
    let proto = read_protocol(ctx, config);
    let last_location = read_location(ctx, config);

    let skb_addr = read_trace_value::<u64>(ctx, config.trace_skbaddr_offset as usize)?;
    if skb_addr == 0 {
        return Ok(());
    }

    let bytes =
        read_kernel_u32((skb_addr + config.skb_len_offset as u64) as *const u32).unwrap_or(0);
    let dev_addr =
        read_kernel_u64((skb_addr + config.skb_dev_offset as u64) as *const u64).unwrap_or(0);

    if dev_addr == 0 {
        record_kernel_drop(0, 0, reason_code, proto, bytes, last_location);
        return Ok(());
    }

    let ifindex =
        match read_kernel_u32((dev_addr + config.net_device_ifindex_offset as u64) as *const u32) {
            Ok(ifindex) => ifindex,
            Err(_) => return Ok(()),
        };

    if ifindex == 0 {
        record_kernel_drop(0, 0, reason_code, proto, bytes, last_location);
        return Ok(());
    }

    let tap_id = match MANAGED_IFINDEX_FILTER.get(&ifindex) {
        Some(value) => value.tap_id,
        None => return Ok(()),
    };

    record_kernel_drop(tap_id, ifindex, reason_code, proto, bytes, last_location);
    Ok(())
}

#[inline(always)]
unsafe fn read_trace_value<T: Copy>(ctx: &TracePointContext, offset: usize) -> Result<T, i64> {
    ctx.read_at::<T>(offset)
}

#[inline(always)]
unsafe fn read_kernel_u32(ptr: *const u32) -> Result<u32, i64> {
    bpf_probe_read_kernel(ptr)
}

#[inline(always)]
unsafe fn read_kernel_u64(ptr: *const u64) -> Result<u64, i64> {
    bpf_probe_read_kernel(ptr)
}

#[inline(always)]
unsafe fn read_protocol(ctx: &TracePointContext, config: &KernelDropConfig) -> u16 {
    if (config.flags & KERNEL_DROP_FLAG_HAS_PROTOCOL) == 0 {
        return 0;
    }
    read_trace_value::<u16>(ctx, config.trace_protocol_offset as usize).unwrap_or(0)
}

#[inline(always)]
unsafe fn read_location(ctx: &TracePointContext, config: &KernelDropConfig) -> u64 {
    if (config.flags & KERNEL_DROP_FLAG_HAS_LOCATION) == 0 {
        return 0;
    }
    read_trace_value::<u64>(ctx, config.trace_location_offset as usize).unwrap_or(0)
}

#[inline(always)]
unsafe fn read_reason_code(ctx: &TracePointContext, config: &KernelDropConfig) -> u16 {
    if (config.flags & KERNEL_DROP_FLAG_HAS_REASON) == 0 {
        return 0;
    }
    read_trace_value::<u16>(ctx, config.trace_reason_offset as usize).unwrap_or(0)
}

#[inline(always)]
unsafe fn record_kernel_drop(
    tap_id: u32,
    ifindex: u32,
    reason_code: u16,
    proto: u16,
    bytes: u32,
    last_location: u64,
) {
    let key = KernelDropKey {
        tap_id,
        ifindex,
        reason_code,
        proto,
    };

    let now = bpf_ktime_get_ns();
    if let Some(value) = KERNEL_DROP_STATS.get_ptr_mut(&key) {
        (*value).packets += 1;
        (*value).bytes += bytes as u64;
        (*value).last_seen_ns = now;
        (*value).last_location = last_location;
        return;
    }

    let value = match KERNEL_DROP_VALUE_BUF.get_ptr_mut(0) {
        Some(value) => value,
        None => return,
    };
    (*value).packets = 1;
    (*value).bytes = bytes as u64;
    (*value).last_seen_ns = now;
    (*value).last_location = last_location;
    let _ = KERNEL_DROP_STATS.insert(&key, &*value, 0);
}
