use crate::common::{QosKey, TokenBucket, DIR_EGRESS, DIR_INGRESS};
use crate::maps::{QOS_CONFIG, QOS_TOKEN_BUCKET, FIREWALL_CONFIG};

#[inline(always)]
fn get_num_cpus() -> u32 {
    let key: u32 = 0;
    if let Some(cfg) = unsafe { FIREWALL_CONFIG.get(&key) } {
        if cfg.num_cpus > 0 { cfg.num_cpus as u32 } else { 1 }
    } else {
        1
    }
}

/// Apply QoS rate limiting for egress. Returns (EDT timestamp, priority).
/// EDT=0 means no delay needed. EDT=u64::MAX means packet should be dropped.
/// No QoS config → pass through (0, 0).
#[inline(always)]
pub unsafe fn apply_qos_egress(
    _src_id: u32,
    dst_id: u32,
    pkt_len: u32,
    now_ns: u64,
) -> (u64, u8) {
    let num_cpus = get_num_cpus();

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

            let rate_per_cpu = config.rate_bps / num_cpus as u64;

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

/// Apply QoS policing for ingress. Returns true if packet should pass, false if it should be dropped.
/// Ingress can only police (drop), not shape (delay).
/// Looks up src_id first (rate-limit by source), then fallback to group_id=0.
#[inline(always)]
pub unsafe fn apply_qos_ingress(
    src_id: u32,
    _dst_id: u32,
    pkt_len: u32,
    now_ns: u64,
) -> bool {
    let num_cpus = get_num_cpus();

    let group_ids = [src_id, 0u32];
    for &gid in &group_ids {
        let qos_key = QosKey {
            group_id: gid,
            direction: DIR_INGRESS,
            pad: [0; 3],
        };

        if let Some(config) = QOS_CONFIG.get(&qos_key) {
            if config.rate_bps == 0 {
                continue;
            }

            let rate_per_cpu = config.rate_bps / num_cpus as u64;

            if rate_per_cpu == 0 {
                continue;
            }

            let burst = if config.burst_bytes > 0 {
                config.burst_bytes
            } else {
                rate_per_cpu / 100
            };

            if let Some(bucket) = QOS_TOKEN_BUCKET.get_ptr_mut(&qos_key) {
                let elapsed = now_ns.wrapping_sub((*bucket).last_refill_ns);
                let refill = rate_per_cpu.saturating_mul(elapsed) / 1_000_000_000;
                let mut tokens = (*bucket).tokens.saturating_add(refill);
                if tokens > burst {
                    tokens = burst;
                }

                if tokens >= pkt_len as u64 {
                    (*bucket).tokens = tokens - pkt_len as u64;
                    (*bucket).last_refill_ns = now_ns;
                    return true;
                } else {
                    // No tokens — drop
                    (*bucket).tokens = 0;
                    (*bucket).last_refill_ns = now_ns;
                    return false;
                }
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
                return true;
            }
        }
    }

    // No QoS config — pass through
    true
}
