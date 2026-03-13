use crate::common::{QosKey, QosConfig, TokenBucket, DIR_EGRESS};
use crate::maps::{QOS_CONFIG, QOS_TOKEN_BUCKET};

/// Apply QoS rate limiting for egress. Returns the EDT timestamp to write to skb->tstamp,
/// or 0 if no delay needed. Returns u64::MAX if packet should be dropped (no config found
/// is treated as no QoS — pass through).
#[inline(always)]
pub unsafe fn apply_qos_egress(
    _src_id: u32,
    dst_id: u32,
    pkt_len: u32,
    now_ns: u64,
    num_cpus: u32,
) -> (u64, u8) {
    // Try specific group first, then global default (group_id=0)
    let group_ids = [dst_id, 0u32];
    for &gid in &group_ids {
        let qos_key = QosKey {
            group_id: gid,
            direction: DIR_EGRESS,
            pad: [0; 3],
        };

        if let Some(config) = QOS_CONFIG.get(&qos_key) {
            if config.rate_bps == 0 {
                continue;
            }

            let rate_per_cpu = if num_cpus > 0 {
                config.rate_bps / num_cpus as u64
            } else {
                config.rate_bps
            };

            if rate_per_cpu == 0 {
                continue;
            }

            let burst = if config.burst_bytes > 0 {
                config.burst_bytes
            } else {
                // Default burst: 2x rate for 10ms
                rate_per_cpu / 100
            };

            // Get or create token bucket
            if let Some(bucket) = QOS_TOKEN_BUCKET.get_ptr_mut(&qos_key) {
                let elapsed = now_ns.wrapping_sub((*bucket).last_refill_ns);
                // Refill tokens: tokens += rate_per_cpu * elapsed / 1e9
                let refill = rate_per_cpu.saturating_mul(elapsed) / 1_000_000_000;
                let mut tokens = (*bucket).tokens.saturating_add(refill);
                if tokens > burst {
                    tokens = burst;
                }

                let (tstamp, new_tokens) = if tokens >= pkt_len as u64 {
                    (0u64, tokens - pkt_len as u64)
                } else {
                    let deficit = pkt_len as u64 - tokens;
                    let delay_ns = deficit.saturating_mul(1_000_000_000) / rate_per_cpu;
                    (now_ns.saturating_add(delay_ns), 0u64)
                };

                (*bucket).tokens = new_tokens;
                (*bucket).last_refill_ns = now_ns;
                return (tstamp, config.priority);
            } else {
                // First packet: initialize token bucket
                let tokens = if burst >= pkt_len as u64 {
                    burst - pkt_len as u64
                } else {
                    0
                };
                let new_bucket = TokenBucket {
                    tokens,
                    last_refill_ns: now_ns,
                };
                let _ = QOS_TOKEN_BUCKET.insert(&qos_key, &new_bucket, 0);
                return (0, config.priority);
            }
        }
    }

    // No QoS config found — pass through
    (0, 0)
}
