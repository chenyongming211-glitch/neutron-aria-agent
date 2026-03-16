use crate::common::{QosKey, TokenBucket, DIR_EGRESS, DIR_INGRESS};
use crate::maps::{QOS_CONFIG, QOS_TOKEN_BUCKET, FIREWALL_CONFIG};
use aya_ebpf::helpers::gen::{bpf_spin_lock, bpf_spin_unlock};

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
///
/// Uses global HashMap with bpf_spin_lock for precise cross-CPU rate enforcement.
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
            let priority = config.priority;
            let mode = config.mode;

            if let Some(bucket) = QOS_TOKEN_BUCKET.get_ptr_mut(&qos_key) {
                bpf_spin_lock(&mut (*bucket).lock);

                let elapsed = now_ns.wrapping_sub((*bucket).last_refill_ns);
                let refill = compute_refill(rate, elapsed);
                let new_tokens = (*bucket).tokens + refill;
                let tokens = if new_tokens > burst { burst } else { new_tokens };

                let result;
                if mode == QOS_MODE_SHAPING {
                    if tokens >= pkt_len as u64 {
                        (*bucket).tokens = tokens - pkt_len as u64;
                        // Reset last_edt when not queueing — no backlog
                        if (*bucket).last_edt < now_ns {
                            (*bucket).last_edt = 0;
                        }
                        result = (0u64, priority);
                    } else {
                        let deficit = pkt_len as u64 - tokens;
                        let delay_ns = compute_delay_ns(deficit, rate);
                        (*bucket).tokens = 0;
                        // Stagger from the later of now or last scheduled packet
                        let base = if (*bucket).last_edt > now_ns { (*bucket).last_edt } else { now_ns };
                        let edt = base + delay_ns;
                        (*bucket).last_edt = edt;
                        result = (edt, priority);
                    }
                } else {
                    // Policing mode — don't zero tokens on drop;
                    // packet was dropped so no bandwidth was consumed.
                    if tokens >= pkt_len as u64 {
                        (*bucket).tokens = tokens - pkt_len as u64;
                        result = (0u64, priority);
                    } else {
                        // tokens unchanged — packet dropped, no bandwidth consumed
                        result = (u64::MAX, priority);
                    }
                }

                // Precise last_refill_ns advancement to avoid truncation
                if new_tokens >= burst {
                    // Tokens capped at burst — snap to now, no fractional loss
                    (*bucket).last_refill_ns = now_ns;
                } else if refill > 0 {
                    // Advance only by time consumed for actual refill (preserves remainder)
                    (*bucket).last_refill_ns += refill * 1_000_000_000 / rate;
                }
                // else: refill == 0, don't advance (accumulate fractional nanoseconds)

                bpf_spin_unlock(&mut (*bucket).lock);
                return result;
            } else {
                // First packet: initialize bucket (insert is atomic, no lock needed)
                let new_bucket = TokenBucket {
                    lock: aya_ebpf::bindings::bpf_spin_lock { val: 0 },
                    _pad: 0,
                    tokens: if burst >= pkt_len as u64 { burst - pkt_len as u64 } else { 0 },
                    last_refill_ns: now_ns,
                    last_edt: 0,
                };
                let _ = QOS_TOKEN_BUCKET.insert(&qos_key, &new_bucket, 0);
                return (0, priority);
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
                bpf_spin_lock(&mut (*bucket).lock);

                let elapsed = now_ns.wrapping_sub((*bucket).last_refill_ns);
                let refill = compute_refill(rate, elapsed);
                let new_tokens = (*bucket).tokens + refill;
                let tokens = if new_tokens > burst { burst } else { new_tokens };

                let pass;
                if tokens >= pkt_len as u64 {
                    (*bucket).tokens = tokens - pkt_len as u64;
                    pass = true;
                } else {
                    // tokens unchanged — packet dropped, no bandwidth consumed
                    pass = false;
                }

                // Precise last_refill_ns advancement to avoid truncation
                if new_tokens >= burst {
                    (*bucket).last_refill_ns = now_ns;
                } else if refill > 0 {
                    (*bucket).last_refill_ns += refill * 1_000_000_000 / rate;
                }

                bpf_spin_unlock(&mut (*bucket).lock);
                return pass;
            } else {
                let new_bucket = TokenBucket {
                    lock: aya_ebpf::bindings::bpf_spin_lock { val: 0 },
                    _pad: 0,
                    tokens: if burst >= pkt_len as u64 { burst - pkt_len as u64 } else { 0 },
                    last_refill_ns: now_ns,
                    last_edt: 0,
                };
                let _ = QOS_TOKEN_BUCKET.insert(&qos_key, &new_bucket, 0);
                return true;
            }
        }
    }

    true
}
