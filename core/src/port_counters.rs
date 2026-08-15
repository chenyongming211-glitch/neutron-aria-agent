use aya::maps::{MapData, MapError, PerCpuHashMap};
use std::collections::{BTreeMap, BTreeSet};

use crate::common::{DropKey, DropValue, PolicyKey, RuleStatsValue};
use crate::drop_ops::{sum_per_cpu_drop, DropStatsEntry};
use crate::monitoring::{sum_per_cpu_rule_stats, RuleStatsEntry};

pub const MAX_COUNTER_BUCKET_ROWS: usize = 512;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PortCounterBucket {
    pub src_id: u32,
    pub dst_id: u32,
    pub proto: u8,
    pub direction: u8,
    pub packets: u64,
    pub bytes: u64,
    pub dropped_packets: u64,
    pub dropped_bytes: u64,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PortCounterReason {
    pub reason: u8,
    pub direction: u8,
    pub proto: u8,
    pub packets: u64,
    pub bytes: u64,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PortCounterSummary {
    pub tap_id: u32,
    pub policy_packets: u64,
    pub policy_bytes: u64,
    pub policy_allow_packets: u64,
    pub policy_dropped_packets: u64,
    pub policy_dropped_bytes: u64,
    pub drop_packets: u64,
    pub drop_bytes: u64,
    pub truncated: bool,
    pub buckets: Vec<PortCounterBucket>,
    pub reasons: Vec<PortCounterReason>,
}

/// Aggregate per-tap counter rows into a single summary.
///
/// Preconditions (documented contract):
/// - `rule_stats` may contain rows for multiple taps; only rows whose
///   `key.tap_id == tap_id` are counted.
/// - `drop_stats` must already contain rows for a single tap (the caller
///   groups raw DROP_REASON_STATS rows by tap id before calling).
pub fn aggregate_port_counters(
    rule_stats: &[RuleStatsEntry],
    drop_stats: &[DropStatsEntry],
    tap_id: u32,
) -> PortCounterSummary {
    let mut summary = PortCounterSummary {
        tap_id,
        ..Default::default()
    };
    let mut buckets = Vec::new();
    for entry in rule_stats {
        if entry.key.tap_id != tap_id {
            continue;
        }
        summary.policy_packets += entry.packets;
        summary.policy_bytes += entry.bytes;
        summary.policy_dropped_packets += entry.dropped_packets;
        summary.policy_dropped_bytes += entry.dropped_bytes;
        buckets.push(PortCounterBucket {
            src_id: entry.key.src_id,
            dst_id: entry.key.dst_id,
            proto: entry.key.proto,
            direction: entry.key.direction,
            packets: entry.packets,
            bytes: entry.bytes,
            dropped_packets: entry.dropped_packets,
            dropped_bytes: entry.dropped_bytes,
        });
    }
    summary.policy_allow_packets =
        summary.policy_packets.saturating_sub(summary.policy_dropped_packets);
    buckets.sort_by(|a, b| b.bytes.cmp(&a.bytes).then(b.packets.cmp(&a.packets)));
    if buckets.len() > MAX_COUNTER_BUCKET_ROWS {
        buckets.truncate(MAX_COUNTER_BUCKET_ROWS);
        summary.truncated = true;
    }
    summary.buckets = buckets;

    let mut reason_rows: BTreeMap<(u8, u8, u8), PortCounterReason> = BTreeMap::new();
    for entry in drop_stats {
        summary.drop_packets += entry.packets;
        summary.drop_bytes += entry.bytes;
        let row = reason_rows
            .entry((entry.reason, entry.direction, entry.proto))
            .or_insert_with(|| PortCounterReason {
                reason: entry.reason,
                direction: entry.direction,
                proto: entry.proto,
                ..Default::default()
            });
        row.packets += entry.packets;
        row.bytes += entry.bytes;
    }
    let mut reasons: Vec<PortCounterReason> = reason_rows.into_values().collect();
    reasons.sort_by(|a, b| b.packets.cmp(&a.packets));
    summary.reasons = reasons;
    summary
}

/// A pin-open failure counts as "map missing" only for ENOENT; permission,
/// corruption, and wrong-type failures are genuine errors surfaced to the
/// caller (best-effort counters must not silently mask real map faults).
fn pin_missing(error: &MapError) -> bool {
    match error {
        MapError::PinError { error: pin_error, .. } => match pin_error {
            aya::pin::PinError::SyscallError(syscall) => {
                syscall.io_error.kind() == std::io::ErrorKind::NotFound
            }
            _ => false,
        },
        _ => false,
    }
}

fn collect_rule_rows(
    pin_path: &str,
    requested: &BTreeSet<u32>,
) -> Result<BTreeMap<u32, Vec<RuleStatsEntry>>, String> {
    let mut rows: BTreeMap<u32, Vec<RuleStatsEntry>> = BTreeMap::new();
    let rule_path = format!("{}/RULE_STATS", pin_path);
    let rule_map_data = match MapData::from_pin(&rule_path) {
        Ok(data) => data,
        Err(error) if pin_missing(&error) => return Ok(rows),
        Err(error) => return Err(format!("open RULE_STATS: {}", error)),
    };
    let rule_map = PerCpuHashMap::<_, PolicyKey, RuleStatsValue>::try_from(
        aya::maps::Map::PerCpuHashMap(rule_map_data),
    )
    .map_err(|e| format!("convert RULE_STATS: {:?}", e))?;
    for item in rule_map.iter() {
        if let Ok((key, values)) = item {
            if !requested.contains(&key.tap_id) {
                continue;
            }
            let (packets, bytes, dropped_packets, dropped_bytes) =
                sum_per_cpu_rule_stats(values);
            if packets == 0 {
                continue;
            }
            rows.entry(key.tap_id)
                .or_default()
                .push(RuleStatsEntry {
                    key,
                    packets,
                    bytes,
                    dropped_packets,
                    dropped_bytes,
                });
        }
    }
    Ok(rows)
}

fn collect_drop_rows(
    pin_path: &str,
    requested: &BTreeSet<u32>,
) -> Result<BTreeMap<u32, Vec<DropStatsEntry>>, String> {
    let mut rows: BTreeMap<u32, Vec<DropStatsEntry>> = BTreeMap::new();
    let drop_path = format!("{}/DROP_REASON_STATS", pin_path);
    let drop_map_data = match MapData::from_pin(&drop_path) {
        Ok(data) => data,
        Err(error) if pin_missing(&error) => return Ok(rows),
        Err(error) => return Err(format!("open DROP_REASON_STATS: {}", error)),
    };
    let drop_map = PerCpuHashMap::<_, DropKey, DropValue>::try_from(
        aya::maps::Map::PerCpuHashMap(drop_map_data),
    )
    .map_err(|e| format!("convert DROP_REASON_STATS: {:?}", e))?;
    for item in drop_map.iter() {
        if let Ok((key, values)) = item {
            if !requested.contains(&key.tap_id) {
                continue;
            }
            let (packets, bytes, last_seen) = sum_per_cpu_drop(values);
            if packets == 0 {
                continue;
            }
            rows.entry(key.tap_id)
                .or_default()
                .push(DropStatsEntry {
                    reason: key.reason,
                    direction: key.direction,
                    proto: key.proto,
                    src_id: key.src_id,
                    dst_id: key.dst_id,
                    packets,
                    bytes,
                    last_seen,
                });
        }
    }
    Ok(rows)
}

/// Read RULE_STATS and DROP_REASON_STATS once from a shared (multi-tap)
/// managed pin path and aggregate per requested tap id.
///
/// Each map is read independently: a missing RULE_STATS map only zeroes the
/// policy view, a missing DROP_REASON_STATS map only zeroes the drop view.
/// A genuine map error (permissions, corruption, wrong type) yields `Err`.
pub fn read_port_counters(
    pin_path: &str,
    tap_ids: &[u32],
) -> Result<Vec<PortCounterSummary>, String> {
    if tap_ids.is_empty() {
        return Ok(Vec::new());
    }
    let requested: BTreeSet<u32> = tap_ids.iter().copied().collect();
    let rule_rows = collect_rule_rows(pin_path, &requested)?;
    let drop_rows = collect_drop_rows(pin_path, &requested)?;

    let mut summaries = Vec::new();
    for &tap_id in &requested {
        let rule_stats: &[RuleStatsEntry] =
            rule_rows.get(&tap_id).map(|v| v.as_slice()).unwrap_or(&[]);
        let drop_stats: &[DropStatsEntry] =
            drop_rows.get(&tap_id).map(|v| v.as_slice()).unwrap_or(&[]);
        let summary = aggregate_port_counters(rule_stats, drop_stats, tap_id);
        if summary.policy_packets > 0 || summary.drop_packets > 0 {
            summaries.push(summary);
        }
    }
    Ok(summaries)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::PolicyKey;

    fn rule(
        tap: u32,
        src: u32,
        dst: u32,
        proto: u8,
        dir: u8,
        packets: u64,
        bytes: u64,
        dropped_packets: u64,
        dropped_bytes: u64,
    ) -> RuleStatsEntry {
        RuleStatsEntry {
            key: PolicyKey {
                tap_id: tap,
                src_id: src,
                dst_id: dst,
                proto,
                direction: dir,
                bank: 0,
                pad: [0; 1],
            },
            packets,
            bytes,
            dropped_packets,
            dropped_bytes,
        }
    }

    fn drop_entry(reason: u8, dir: u8, proto: u8, packets: u64, bytes: u64) -> DropStatsEntry {
        DropStatsEntry {
            reason,
            direction: dir,
            proto,
            src_id: 0,
            dst_id: 0,
            packets,
            bytes,
            last_seen: 0,
        }
    }

    #[test]
    fn port_counters_policy_view_is_per_tap_and_allow_is_packets_minus_dropped() {
        let rule_stats = vec![
            rule(7, 1, 2, 6, 0, 100, 1000, 30, 300),
            rule(7, 3, 4, 17, 1, 50, 500, 0, 0),
            rule(9, 1, 2, 6, 0, 999, 9999, 0, 0), // other tap ignored
        ];
        let drop_stats = vec![drop_entry(1, 0, 6, 30, 300)];
        let summary = aggregate_port_counters(&rule_stats, &drop_stats, 7);
        assert_eq!(summary.policy_packets, 150);
        assert_eq!(summary.policy_bytes, 1500);
        assert_eq!(summary.policy_dropped_packets, 30);
        assert_eq!(summary.policy_allow_packets, 120);
        assert_eq!(summary.drop_packets, 30);
        assert_eq!(summary.buckets.len(), 2);
        assert!(!summary.truncated);
    }

    #[test]
    fn port_counters_drop_view_groups_reasons_and_is_never_summed_with_policy() {
        let rule_stats = vec![rule(7, 1, 2, 6, 0, 100, 1000, 40, 400)];
        let drop_stats = vec![
            drop_entry(1, 0, 6, 40, 400), // ACL deny: overlaps policy drop by design
            drop_entry(9, 0, 0, 15, 150), // fragment reason, not policy-attributed
        ];
        let summary = aggregate_port_counters(&rule_stats, &drop_stats, 7);
        assert_eq!(summary.policy_dropped_packets, 40);
        assert_eq!(summary.drop_packets, 55);
        assert_eq!(summary.reasons.len(), 2);
        assert_eq!(summary.reasons[0].reason, 1);
        assert_eq!(summary.reasons[1].reason, 9);
    }

    #[test]
    fn port_counters_caps_buckets_at_512_and_sets_truncated() {
        let rule_stats: Vec<RuleStatsEntry> = (0..600)
            .map(|i| rule(7, i as u32, 1, 6, 0, 1, 1, 0, 0))
            .collect();
        let summary = aggregate_port_counters(&rule_stats, &[], 7);
        assert_eq!(summary.buckets.len(), 512);
        assert!(summary.truncated);
    }

    #[test]
    fn port_counters_read_missing_maps_is_empty_ok() {
        let summaries = read_port_counters("/nonexistent/pin/path", &[7]).unwrap();
        assert!(summaries.is_empty());
    }
}
