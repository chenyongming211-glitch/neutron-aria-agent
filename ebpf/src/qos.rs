use crate::common::{QosKey, TokenBucket, DIR_EGRESS, DIR_INGRESS};
use crate::maps::{QOS_CONFIG, QOS_STATS, QOS_STATS_BUF, QOS_TOKEN_BUCKET};

/// QoS mode constants
const QOS_MODE_SHAPING: u8 = 1;

/// Check if QoS is globally enabled. When no QoS rules are configured,
/// the control plane sets this to 0, allowing fast-path to skip LPM lookups entirely.
#[inline(always)]
pub fn qos_enabled(tap_id: u32) -> bool {
    crate::runtime::qos_enabled(tap_id)
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
    rate * secs + rate * frac_ns / 1_000_000_000
}

/// Compute EDT delay in nanoseconds without 128-bit multiplication.
/// delay_ns = deficit_bytes * 1_000_000_000 / rate
///
/// deficit is at most one packet (~64 KB), so deficit * 1e9 < 6.5e13, well within u64.
#[inline(always)]
fn compute_delay_ns(deficit: u64, rate: u64) -> u64 {
    if rate == 0 {
        return 0;
    }
    deficit * 1_000_000_000 / rate
}

/// Update QoS per-rule statistics.
/// outcome: 0=pass, 1=drop, 2=shaped
#[inline(always)]
unsafe fn update_qos_stats(key: &QosKey, pkt_len: u32, outcome: u8) {
    if let Some(s) = QOS_STATS.get_ptr_mut(key) {
        match outcome {
            0 => {
                (*s).passed_packets += 1;
                (*s).passed_bytes += pkt_len as u64;
            }
            1 => {
                (*s).dropped_packets += 1;
                (*s).dropped_bytes += pkt_len as u64;
            }
            _ => {
                (*s).shaped_packets += 1;
                (*s).shaped_bytes += pkt_len as u64;
            }
        }
    } else {
        let val = match QOS_STATS_BUF.get_ptr_mut(0) {
            Some(v) => v,
            None => return,
        };
        (*val).passed_packets = 0;
        (*val).passed_bytes = 0;
        (*val).dropped_packets = 0;
        (*val).dropped_bytes = 0;
        (*val).shaped_packets = 0;
        (*val).shaped_bytes = 0;
        match outcome {
            0 => {
                (*val).passed_packets = 1;
                (*val).passed_bytes = pkt_len as u64;
            }
            1 => {
                (*val).dropped_packets = 1;
                (*val).dropped_bytes = pkt_len as u64;
            }
            _ => {
                (*val).shaped_packets = 1;
                (*val).shaped_bytes = pkt_len as u64;
            }
        }
        let _ = QOS_STATS.insert(key, &*val, 0);
    }
}

/// Apply QoS rate limiting for egress. Returns (EDT timestamp, priority).
/// EDT=0 means no delay needed. EDT=u64::MAX means packet should be dropped.
/// No QoS config → pass through (0, 0).
///
/// Uses a shared (non-per-CPU) HashMap for the token bucket so that all CPUs
/// coordinate on a single rate limit.  Without bpf_spin_lock the read-modify-
/// write is not atomic, but the race window is only a few nanoseconds, so the
/// worst-case overshoot per race is (num_cpus - 1) × pkt_len — negligible
/// compared to the alternative of per-CPU full-rate buckets which can overshoot
/// by rate × num_cpus indefinitely.
#[inline(always)]
pub unsafe fn apply_qos_egress(
    tap_id: u32,
    _src_id: u32,
    dst_id: u32,
    pkt_len: u32,
    now_ns: u64,
) -> (u64, u8) {
    // Try specific group first, then global default (group_id=0)
    let group_ids = [dst_id, 0u32];
    for &gid in &group_ids {
        let qos_key = QosKey {
            tap_id,
            group_id: gid,
            direction: DIR_EGRESS,
            pad: [0; 3],
        };

        if let Some(config) = QOS_CONFIG.get(&qos_key) {
            if config.rate_bps == 0 {
                continue;
            }

            // Use the full rate per CPU – avoids under-policing when traffic
            // is not evenly distributed across CPUs.
            let rate = config.rate_bps;
            let burst = config.burst_bytes;
            let priority = config.priority;
            let mode = config.mode;

            // Ensure rate is at least 1 to avoid division by zero
            let rate = if rate > 0 { rate } else { 1 };
            let burst = if burst > 0 { burst } else { rate };

            if let Some(bucket) = QOS_TOKEN_BUCKET.get_ptr_mut(&qos_key) {
                let elapsed = now_ns.wrapping_sub((*bucket).last_refill_ns);
                let refill = compute_refill(rate, elapsed);
                let new_tokens = (*bucket).tokens + refill;
                let tokens = if new_tokens > burst {
                    burst
                } else {
                    new_tokens
                };

                let result;
                if mode == QOS_MODE_SHAPING {
                    // Every packet gets an EDT timestamp to enforce rate limit.
                    // Tokens only control stats (pass vs shaped), not whether EDT is set.
                    let pkt_delay_ns = compute_delay_ns(pkt_len as u64, rate);
                    let base = if (*bucket).last_edt > now_ns {
                        (*bucket).last_edt
                    } else {
                        now_ns
                    };
                    let edt = base + pkt_delay_ns;
                    (*bucket).last_edt = edt;

                    if tokens >= pkt_len as u64 {
                        (*bucket).tokens = tokens - pkt_len as u64;
                        update_qos_stats(&qos_key, pkt_len, 0);
                    } else {
                        (*bucket).tokens = 0;
                        update_qos_stats(&qos_key, pkt_len, 2);
                    }
                    result = (edt, priority);
                } else {
                    // Policing mode
                    if tokens >= pkt_len as u64 {
                        (*bucket).tokens = tokens - pkt_len as u64;
                        update_qos_stats(&qos_key, pkt_len, 0);
                        result = (0u64, priority);
                    } else {
                        // Drop: write back refilled tokens (don't deduct pkt_len)
                        // Packet was dropped so no bandwidth was consumed,
                        // but the refill MUST be persisted or it's lost.
                        (*bucket).tokens = tokens;
                        update_qos_stats(&qos_key, pkt_len, 1);
                        result = (u64::MAX, priority);
                    }
                }

                (*bucket).last_refill_ns = now_ns;

                return result;
            } else {
                // First packet: initialize bucket
                let new_bucket = TokenBucket {
                    tokens: if burst >= pkt_len as u64 {
                        burst - pkt_len as u64
                    } else {
                        0
                    },
                    last_refill_ns: now_ns,
                    last_edt: 0,
                };
                let _ = QOS_TOKEN_BUCKET.insert(&qos_key, &new_bucket, 0);
                update_qos_stats(&qos_key, pkt_len, 0);
                return (0, priority);
            }
        }
    }

    (0, 0)
}

/// Apply QoS policing for ingress. Returns true if packet should pass, false if dropped.
/// Ingress can only police (drop), not shape (delay).
/// Looks up src_id first (rate-limit by source), then fallback to group_id=0.
/// See apply_qos_egress for the shared-bucket rationale.
#[inline(always)]
pub unsafe fn apply_qos_ingress(
    tap_id: u32,
    src_id: u32,
    _dst_id: u32,
    pkt_len: u32,
    now_ns: u64,
) -> bool {
    let group_ids = [src_id, 0u32];
    for &gid in &group_ids {
        let qos_key = QosKey {
            tap_id,
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

            let rate = if rate > 0 { rate } else { 1 };
            let burst = if burst > 0 { burst } else { rate };

            if let Some(bucket) = QOS_TOKEN_BUCKET.get_ptr_mut(&qos_key) {
                let elapsed = now_ns.wrapping_sub((*bucket).last_refill_ns);
                let refill = compute_refill(rate, elapsed);
                let new_tokens = (*bucket).tokens + refill;
                let tokens = if new_tokens > burst {
                    burst
                } else {
                    new_tokens
                };

                let pass;
                if tokens >= pkt_len as u64 {
                    (*bucket).tokens = tokens - pkt_len as u64;
                    update_qos_stats(&qos_key, pkt_len, 0);
                    pass = true;
                } else {
                    // Drop: write back refilled tokens (don't deduct pkt_len)
                    (*bucket).tokens = tokens;
                    update_qos_stats(&qos_key, pkt_len, 1);
                    pass = false;
                }

                (*bucket).last_refill_ns = now_ns;
                return pass;
            } else {
                let new_bucket = TokenBucket {
                    tokens: if burst >= pkt_len as u64 {
                        burst - pkt_len as u64
                    } else {
                        0
                    },
                    last_refill_ns: now_ns,
                    last_edt: 0,
                };
                let _ = QOS_TOKEN_BUCKET.insert(&qos_key, &new_bucket, 0);
                update_qos_stats(&qos_key, pkt_len, 0);
                return true;
            }
        }
    }

    true
}
