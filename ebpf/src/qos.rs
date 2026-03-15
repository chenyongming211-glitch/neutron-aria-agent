use crate::common::{QosKey, TokenBucket, DIR_EGRESS, DIR_INGRESS};
use crate::maps::{QOS_CONFIG, QOS_TOKEN_BUCKET, FIREWALL_CONFIG};

/// QoS mode constants
const QOS_MODE_POLICING: u8 = 0;
const QOS_MODE_SHAPING: u8 = 1;

/// Check if QoS is globally enabled. When no QoS rules are configured,
/// the control plane sets this to 0, allowing fast-path to skip LPM lookups entirely.
#[inline(always)]
pub fn qos_enabled() -> bool {
    let key: u32 = 0;
    if let Some(cfg) = unsafe { FIREWALL_CONFIG.get(&key) } {
        cfg.qos_enabled != 0
    } else {
        false
    }
}

/// Compute token refill without 128-bit multiplication.
/// refill = rate * elapsed_ns / 1_000_000_000
///
/// Split elapsed into whole seconds + fractional nanoseconds so each
/// intermediate product stays within u64 for rates up to ~18 GB/s.
#[inline(always)]
fn compute_refill(rate: u64, elapsed_ns: u64) -> u64 {
    let secs = elapsed_ns / 1_000_000_000;
    let frac_ns = elapsed_ns % 1_000_000_000;
    // rate * secs: safe for practical rates (<18 GB/s) and elapsed (<~580 years)
    // rate * frac_ns: frac_ns < 1e9, so product < rate * 1e9, fits u64 for rate < ~18 GB/s
    rate * secs + rate * frac_ns / 1_000_000_000
}

/// Compute EDT delay in nanoseconds without 128-bit multiplication.
/// delay_ns = deficit_bytes * 1_000_000_000 / rate
///
/// deficit is at most one packet (~64 KB), so deficit * 1e9 < 6.5e13, well within u64.
#[inline(always)]
fn compute_delay_ns(deficit: u64, rate: u64) -> u64 {
    deficit * 1_000_000_000 / rate
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

            let rate = config.rate_bps;
            let burst = config.burst_bytes;

            if let Some(bucket) = QOS_TOKEN_BUCKET.get_ptr_mut(&qos_key) {
                let elapsed = now_ns.wrapping_sub((*bucket).last_refill_ns);
                let refill = compute_refill(rate, elapsed);
                let new_tokens = (*bucket).tokens + refill;
                let tokens = if new_tokens > burst { burst } else { new_tokens };

                if config.mode == QOS_MODE_SHAPING {
                    // Shaping mode: use EDT timestamps (requires FQ qdisc)
                    let (tstamp, final_tokens) = if tokens >= pkt_len as u64 {
                        (0u64, tokens - pkt_len as u64)
                    } else {
                        let deficit = pkt_len as u64 - tokens;
                        let delay_ns = compute_delay_ns(deficit, rate);
                        (now_ns + delay_ns, 0u64)
                    };

                    (*bucket).tokens = final_tokens;
                    (*bucket).last_refill_ns = now_ns;
                    return (tstamp, config.priority);
                } else {
                    // Policing mode: drop excess packets (works on veth)
                    if tokens >= pkt_len as u64 {
                        (*bucket).tokens = tokens - pkt_len as u64;
                        (*bucket).last_refill_ns = now_ns;
                        return (0, config.priority);
                    } else {
                        // Deduct packet cost even on drop for accurate accounting
                        (*bucket).tokens = 0;
                        (*bucket).last_refill_ns = now_ns;
                        // u64::MAX signals drop
                        return (u64::MAX, config.priority);
                    }
                }
            } else {
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

    (0, 0)
}

/// Apply QoS policing for ingress. Returns true if packet should pass, false if dropped.
/// Ingress can only police (drop), not shape (delay).
/// Looks up src_id first (rate-limit by source), then fallback to group_id=0.
#[inline(always)]
pub unsafe fn apply_qos_ingress(
    src_id: u32,
    _dst_id: u32,
    pkt_len: u32,
    now_ns: u64,
) -> bool {
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

            let rate = config.rate_bps;
            let burst = config.burst_bytes;

            if let Some(bucket) = QOS_TOKEN_BUCKET.get_ptr_mut(&qos_key) {
                let elapsed = now_ns.wrapping_sub((*bucket).last_refill_ns);
                let refill = compute_refill(rate, elapsed);
                let new_tokens = (*bucket).tokens + refill;
                let tokens = if new_tokens > burst { burst } else { new_tokens };

                if tokens >= pkt_len as u64 {
                    (*bucket).tokens = tokens - pkt_len as u64;
                    (*bucket).last_refill_ns = now_ns;
                    return true;
                } else {
                    // Deduct packet cost even on drop for accurate accounting
                    (*bucket).tokens = 0;
                    (*bucket).last_refill_ns = now_ns;
                    return false;
                }
            } else {
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

    true
}
