use crate::common::{QosKey, TokenBucket, DIR_EGRESS, DIR_INGRESS, bpf_spin_lock};
use crate::maps::{QOS_CONFIG, QOS_TOKEN_BUCKET, FIREWALL_CONFIG};

/// QoS mode constants
const QOS_MODE_POLICING: u8 = 0;
const QOS_MODE_SHAPING: u8 = 1;

// Raw BPF helper function IDs from kernel UAPI headers
const BPF_FUNC_spin_lock: u64 = 93;
const BPF_FUNC_spin_unlock: u64 = 94;

/// Call bpf_spin_lock() kernel helper directly via function pointer cast.
#[inline(always)]
unsafe fn spin_lock(lock: *mut bpf_spin_lock) {
    let f: unsafe extern "C" fn(*mut bpf_spin_lock) -> i64 =
        core::mem::transmute(BPF_FUNC_spin_lock as usize);
    f(lock);
}

/// Call bpf_spin_unlock() kernel helper directly via function pointer cast.
#[inline(always)]
unsafe fn spin_unlock(lock: *mut bpf_spin_lock) {
    let f: unsafe extern "C" fn(*mut bpf_spin_lock) -> i64 =
        core::mem::transmute(BPF_FUNC_spin_unlock as usize);
    f(lock);
}

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
                // Lock protects tokens + last_refill_ns from concurrent CPU access
                spin_lock(&mut (*bucket).lock);

                let elapsed = now_ns.wrapping_sub((*bucket).last_refill_ns);
                let refill = compute_refill(rate, elapsed);
                let new_tokens = (*bucket).tokens + refill;
                let tokens = if new_tokens > burst { burst } else { new_tokens };

                let result;
                if mode == QOS_MODE_SHAPING {
                    if tokens >= pkt_len as u64 {
                        (*bucket).tokens = tokens - pkt_len as u64;
                        result = (0u64, priority);
                    } else {
                        let deficit = pkt_len as u64 - tokens;
                        let delay_ns = compute_delay_ns(deficit, rate);
                        (*bucket).tokens = 0;
                        result = (now_ns + delay_ns, priority);
                    }
                } else {
                    // Policing mode
                    if tokens >= pkt_len as u64 {
                        (*bucket).tokens = tokens - pkt_len as u64;
                        result = (0u64, priority);
                    } else {
                        (*bucket).tokens = 0;
                        result = (u64::MAX, priority);
                    }
                }
                (*bucket).last_refill_ns = now_ns;

                spin_unlock(&mut (*bucket).lock);
                return result;
            } else {
                // First packet: initialize bucket (no lock needed, insert is atomic)
                let tokens = if burst >= pkt_len as u64 {
                    burst - pkt_len as u64
                } else {
                    0
                };
                let new_bucket = TokenBucket {
                    lock: bpf_spin_lock { val: 0 },
                    _pad: 0,
                    tokens,
                    last_refill_ns: now_ns,
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
                spin_lock(&mut (*bucket).lock);

                let elapsed = now_ns.wrapping_sub((*bucket).last_refill_ns);
                let refill = compute_refill(rate, elapsed);
                let new_tokens = (*bucket).tokens + refill;
                let tokens = if new_tokens > burst { burst } else { new_tokens };

                let pass;
                if tokens >= pkt_len as u64 {
                    (*bucket).tokens = tokens - pkt_len as u64;
                    pass = true;
                } else {
                    (*bucket).tokens = 0;
                    pass = false;
                }
                (*bucket).last_refill_ns = now_ns;

                spin_unlock(&mut (*bucket).lock);
                return pass;
            } else {
                let tokens = if burst >= pkt_len as u64 {
                    burst - pkt_len as u64
                } else {
                    0
                };
                let new_bucket = TokenBucket {
                    lock: bpf_spin_lock { val: 0 },
                    _pad: 0,
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
