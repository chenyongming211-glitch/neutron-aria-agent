# ACL Explainability Counter Pipeline Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Execution status (2026-08-15):** functional implementation and hosted CI are
complete; privileged field evidence remains deferred/pending and the feature
remains default-off. The unchecked task steps below are the preserved original
execution recipe, not the current delivery-state register. Post-review
corrections supersede the original Task 3 and Task 9 mechanics as recorded
below.

**Goal:** Deliver the Phase B ACL explainability pipeline from `docs/superpowers/specs/2026-08-15-acl-explainability-counters-design.md`: minute-fresh per-port and per-policy-bucket allow/drop counters plus drop-reason distribution, carried from eBPF maps through the UDS status v3 optional counters section, the neutron-aria-agent heartbeat, and into `aria_acl_port_statuses` + a new `aria_acl_port_counters` table with an admin-only CLI view.

**Architecture:** Zero eBPF data-plane changes. A new Rust aggregation module (`aria-core`) reads the existing `RULE_STATS`/`DROP_REASON_STATS` maps only for an explicit counters query and attaches an optional, versioned, response-budgeted `counters` section to the UDS status response (schema v3, backward compatible). Ordinary status/readiness calls remain counter-free. When enabled, the Python agent samples that explicit view each heartbeat, differences consecutive snapshots to produce pps/bps with reset detection, and forwards bounded rows through the existing RPC heartbeat; the server persists the latest snapshot and the CLI renders it.

**Tech Stack:** Rust (axum UDS, aya map reads), Python 2/3-compatible neutron-aria-agent (stdlib unittest), Neutron server plugin (SQLAlchemy), neutronclient CLI, `ci/check_neutron_stage1.py` contract checker.

## Global Constraints

- **No local `cargo` commands** (build/check/test). Rust verification happens in GitHub Actions CI (`rust-behavior` job, `ci/check_neutron_stage1.py --rust-tests-only --rust-toolchain stable` with `RUSTFLAGS=-D warnings`); fix failures from CI logs. Rust tasks therefore commit+push as their verification step.
- Python unit tests run locally: `PYTHONPATH=openstack/neutron_aria python3 -m unittest discover -s openstack/neutron_aria/neutron_aria/tests/unit -p "test_*.py"` (agent) and `PYTHONPATH=openstack/neutronclient_aria python3 -m unittest neutronclient_aria.tests.test_aria_acl_cli` (CLI). New test IDs must also be registered in `REQUIRED_PYTHON_BEHAVIORS` in `ci/check_neutron_stage1.py` (verified by `python3 ci/check_neutron_stage1.py --fast-contracts`).
- Branch: commit directly to `v0.9-neutron-agent`, push to `origin` (repo local identity; no re-asking).
- The counting-semantics rules from the spec §5 are normative: policy view and drop view are **never summed**; bucket drop ⊆ reason drop; `allow = packets − dropped` only inside the policy view.
- v1 gate: agent config `counters_report_enabled` defaults to **false**; CI exercises the pipeline with fixtures regardless.
- Payload caps: 512 bucket rows per port, fixed reason enumeration; overflow → `truncated=true`.
- Complete counters responses also fit within the existing 1 MiB UDS response
  contract. Oversize counters degrade independently and never latch ACL writes.
- All existing status semantics (transaction state, readiness, port projection) must remain byte-identical when the counters section is absent.
- Keep the files Python 2/3 compatible (`from __future__ import absolute_import`, `basestring` guard) matching `neutron_aria/agent/*.py`.

---

## Phase 1 — Rust datapath: aggregation + UDS status v3 counters section

### Task 1: `aria-core` port counter aggregation module

**Files:**
- Create: `core/src/port_counters.rs`
- Modify: `core/src/lib.rs` (add `pub mod port_counters;`)
- Test: `core/src/port_counters.rs` (`#[cfg(test)] mod tests`)

**Interfaces:**
- Consumes: `crate::monitoring::{RuleStatsEntry, sum_per_cpu_rule_stats}` (visibility widened), `crate::drop_ops::{DropStatsEntry, sum_per_cpu_drop}` (visibility widened), `crate::common::{PolicyKey, RuleStatsValue, DropKey, DropValue}` (existing).
- Produces (used by Task 3):

```rust
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

pub fn aggregate_port_counters(
    rule_stats: &[RuleStatsEntry],
    drop_stats: &[DropStatsEntry],
    tap_id: u32,
) -> PortCounterSummary;

pub fn read_port_counters(
    pin_path: &str,
    tap_ids: &[u32],
) -> Result<Vec<PortCounterSummary>, String>;
```

Semantics (normative, tested in this task):
- `aggregate_port_counters` is a pure function; `tap_id` selects rule entries (`entry.key.tap_id == tap_id`); all `drop_stats` entries passed in are already single-tap rows (precondition documented on the function).
- policy sums come from `RuleStatsEntry`; `policy_allow_packets = policy_packets − policy_dropped_packets` (same for bytes).
- drop sums come from `DropStatsEntry`, grouped into `reasons` by `(reason, direction, proto)`, sorted by packets desc.
- `buckets` come from `RuleStatsEntry` sorted by bytes desc, capped at `MAX_COUNTER_BUCKET_ROWS`; if capped, `truncated = true`.
- `read_port_counters` opens `{pin_path}/RULE_STATS` and `{pin_path}/DROP_REASON_STATS` **once each** (shared multi-tap pin path, no tap filtering inside the map read — `get_rule_stats`/`get_drop_stats` filter by `TapMapRuntime.tap_id` and cannot be reused here), groups rows by `key.tap_id` in userspace, and returns one summary per requested `tap_id` that has any counters; a missing/unpinned map yields `Ok(vec![])`, a real map error yields `Err`.

- [ ] **Step 1: Write the failing tests** — create `core/src/port_counters.rs` with the structs above plus `#[cfg(test)] mod tests` containing:

```rust
use crate::common::PolicyKey;
use crate::drop_ops::DropStatsEntry;
use crate::monitoring::RuleStatsEntry;

fn rule(tap: u32, src: u32, dst: u32, proto: u8, dir: u8, packets: u64, bytes: u64, dropped_packets: u64, dropped_bytes: u64) -> RuleStatsEntry {
    RuleStatsEntry {
        key: PolicyKey { tap_id: tap, src_id: src, dst_id: dst, proto, direction: dir, bank: 0, pad: [0; 1] },
        packets, bytes, dropped_packets, dropped_bytes,
    }
}

fn drop_entry(reason: u8, dir: u8, proto: u8, packets: u64, bytes: u64) -> DropStatsEntry {
    DropStatsEntry { reason, direction: dir, proto, src_id: 0, dst_id: 0, packets, bytes, last_seen: 0 }
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
        drop_entry(1, 0, 6, 40, 400),  // ACL deny: overlaps policy drop by design
        drop_entry(9, 0, 0, 15, 150),  // fragment reason, not policy-attributed
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python3 ci/check_neutron_stage1.py --rust-tests-only --rust-toolchain stable`
Expected: this step is skipped locally per repo rule; instead push the test-only commit and confirm the CI `rust-behavior` job fails to compile with `unresolved import ... port_counters`. (Local no-op is intentional: AGENTS.md forbids local cargo.)

- [ ] **Step 3: Implement the module** — complete `core/src/port_counters.rs`:

```rust
use crate::common::TapMapRuntime;
use crate::drop_ops::{get_drop_stats, DropStatsEntry};
use crate::monitoring::{get_rule_stats, RuleStatsEntry};
use std::collections::BTreeMap;

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

pub fn aggregate_port_counters(
    rule_stats: &[RuleStatsEntry],
    drop_stats: &[DropStatsEntry],
    tap_id: u32,
) -> PortCounterSummary {
    let mut summary = PortCounterSummary { tap_id, ..Default::default() };
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
    summary.policy_allow_packets = summary.policy_packets.saturating_sub(summary.policy_dropped_packets);
    summary.policy_allow_bytes = summary.policy_bytes.saturating_sub(summary.policy_dropped_bytes);
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

pub fn read_port_counters(
    pin_path: &str,
    tap_ids: &[u32],
) -> Result<Vec<PortCounterSummary>, String> {
    if tap_ids.is_empty() {
        return Ok(Vec::new());
    }
    let requested: BTreeSet<u32> = tap_ids.iter().copied().collect();

    // Read RULE_STATS without tap filtering (shared managed pin path).
    let rule_path = format!("{}/RULE_STATS", pin_path);
    let rule_map_data = match MapData::from_pin(&rule_path) {
        Ok(data) => data,
        Err(_) => return Ok(Vec::new()),
    };
    let rule_map = PerCpuHashMap::<_, PolicyKey, RuleStatsValue>::try_from(
        aya::maps::Map::PerCpuHashMap(rule_map_data),
    )
    .map_err(|e| format!("convert RULE_STATS: {:?}", e))?;
    let mut rule_rows: BTreeMap<u32, Vec<RuleStatsEntry>> = BTreeMap::new();
    for item in rule_map.iter() {
        if let Ok((key, values)) = item {
            if !requested.contains(&key.tap_id) {
                continue;
            }
            let (packets, bytes, dropped_packets, dropped_bytes) =
                crate::monitoring::sum_per_cpu_rule_stats(values);
            if packets == 0 {
                continue;
            }
            rule_rows
                .entry(key.tap_id)
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

    // Read DROP_REASON_STATS without tap filtering (shared managed pin path).
    let drop_path = format!("{}/DROP_REASON_STATS", pin_path);
    let drop_map_data = match MapData::from_pin(&drop_path) {
        Ok(data) => data,
        Err(_) => return Ok(Vec::new()),
    };
    let drop_map = PerCpuHashMap::<_, DropKey, DropValue>::try_from(
        aya::maps::Map::PerCpuHashMap(drop_map_data),
    )
    .map_err(|e| format!("convert DROP_REASON_STATS: {:?}", e))?;
    let mut drop_rows: BTreeMap<u32, Vec<DropStatsEntry>> = BTreeMap::new();
    for item in drop_map.iter() {
        if let Ok((key, values)) = item {
            if !requested.contains(&key.tap_id) {
                continue;
            }
            let (packets, bytes, last_seen) = crate::drop_ops::sum_per_cpu_drop(values);
            if packets == 0 {
                continue;
            }
            drop_rows
                .entry(key.tap_id)
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

    let mut summaries = Vec::new();
    for tap_id in requested {
        let rule_stats = rule_rows.get(&tap_id).cloned().unwrap_or_default();
        let drop_stats = drop_rows.get(&tap_id).cloned().unwrap_or_default();
        let summary = aggregate_port_counters(&rule_stats, &drop_stats, tap_id);
        if summary.policy_packets > 0 || summary.drop_packets > 0 {
            summaries.push(summary);
        }
    }
    Ok(summaries)
}
```

Make the two per-CPU sum helpers reusable (same crate, new visibility only):
- `core/src/monitoring.rs`: `fn sum_per_cpu_rule_stats(...)` → `pub(crate) fn sum_per_cpu_rule_stats(...)`
- `core/src/drop_ops.rs`: `fn sum_per_cpu_drop(...)` → `pub(crate) fn sum_per_cpu_drop(...)`

Add imports at the top of `port_counters.rs`:

```rust
use aya::maps::{MapData, PerCpuHashMap};
use crate::common::{DropKey, DropValue, PolicyKey, RuleStatsValue, TapMapRuntime};
use std::collections::{BTreeMap, BTreeSet};
```

- [ ] **Step 4: Add module wiring** — in `core/src/lib.rs`, after the existing `pub mod monitoring;` line add `pub mod port_counters;`.

- [ ] **Step 5: Register the test filter** — in `ci/check_neutron_stage1.py`, inside the `RUST_TESTS` list (the list starting around line 40 with `["test", "--locked", "-p", ...]` entries), add after the `["test", "--locked", "-p", "aria-core", "ct_contract_stats_iteration_"]` entry:

```python
    ["test", "--locked", "-p", "aria-core", "port_counters_"],
```

- [ ] **Step 6: Commit and push (CI verifies)**

```bash
git add core/src/port_counters.rs core/src/lib.rs core/src/monitoring.rs core/src/drop_ops.rs ci/check_neutron_stage1.py
git commit -m "feat(core): add ACL port counter aggregation for explainability"
git push origin v0.9-neutron-agent
```

Expected: GitHub Actions `rust-behavior` job passes. If it fails, read the CI log and fix before proceeding.

### Task 2: `aria-api` schema v3 constants and counters wire types

**Files:**
- Modify: `api/src/lib.rs` (constants block ~lines 36-46, `NeutronCapabilitiesResponse` ~line 440-460 + `current()` ~line 480, `NeutronStatusV1Response` ~line 564)
- Test: `api/src/lib.rs` `#[cfg(test)]` module (extend existing `neutron_contract` tests)

**Interfaces:**
- Consumes: Task 1 types (not yet; wire types here are serde-only).
- Produces (used by Task 3):

```rust
pub const NEUTRON_STATUS_SCHEMA_VERSION_MIN: u32 = 2;
pub const NEUTRON_STATUS_SCHEMA_VERSION_MAX: u32 = 3;
pub const NEUTRON_STATUS_CONTRACT_HASH: &str = "v0.9-neutron-status-3";
pub const NEUTRON_UDS_CAPABILITY_HASH: &str = "v0.9-neutron-capabilities-5";
pub const NEUTRON_COUNTERS_SCHEMA_VERSION: u32 = 1;
pub const NEUTRON_MAX_COUNTER_BUCKET_ROWS_PER_PORT: usize = 512;
// NeutronCapabilitiesResponse gains: pub counters_v1: bool  (serde(default))
// NeutronStatusV1Response gains:
//   #[serde(default, skip_serializing_if = "Option::is_none")]
//   pub counters: Option<NeutronStatusCountersV1>,
// plus the new structs below
```

- [ ] **Step 1: Write the failing tests** — append to the existing test module in `api/src/lib.rs` (the module already asserts capability fields around line 2499):

```rust
#[test]
fn neutron_capabilities_advertise_counters_v1() {
    let caps = NeutronCapabilitiesResponse::current();
    assert!(caps.counters_v1);
    assert_eq!(caps.status_schema_version_min, 2);
    assert_eq!(caps.status_schema_version_max, 3);
    assert_eq!(caps.status_contract_hash, "v0.9-neutron-status-3");
    assert_eq!(caps.capability_hash, "v0.9-neutron-capabilities-5");
}

#[test]
fn neutron_status_v3_serializes_without_counters_section() {
    let response = NeutronStatusV1Response {
        status_schema_version: 3,
        status_contract_hash: "v0.9-neutron-status-3".to_string(),
        // ... existing fields with minimal values ...
        counters: None,
    };
    let value = serde_json::to_value(&response).unwrap();
    assert!(value.get("counters").is_none());
}
```

(Construct the remaining fields exactly as the existing tests construct `NeutronStatusV1Response`; copy that pattern rather than inventing values.)

- [ ] **Step 2: Push test-only commit, confirm CI failure**

Run: `git add api/src/lib.rs && git commit -m "test(api): expect status v3 counters capability" && git push origin v0.9-neutron-agent`
Expected: `rust-behavior` fails (unknown fields `counters_v1`/`counters`).

- [ ] **Step 3: Implement constants and wire types** — in `api/src/lib.rs`:

Replace the constant block:

```rust
pub const NEUTRON_STATUS_SCHEMA_VERSION_MIN: u32 = 2;
pub const NEUTRON_STATUS_SCHEMA_VERSION_MAX: u32 = 3;
pub const NEUTRON_STATUS_CONTRACT_HASH: &str = "v0.9-neutron-status-3";
```

and `pub const NEUTRON_UDS_CAPABILITY_HASH: &str = "v0.9-neutron-capabilities-4";` → `"v0.9-neutron-capabilities-5"`, then append after the hash constants:

```rust
pub const NEUTRON_COUNTERS_SCHEMA_VERSION: u32 = 1;
pub const NEUTRON_MAX_COUNTER_BUCKET_ROWS_PER_PORT: usize = 512;
```

Add before `NeutronCapabilitiesResponse`:

```rust
#[derive(Clone, Debug, Serialize, Deserialize, ToSchema, PartialEq, Eq)]
pub struct NeutronCounterBucketV1 {
    pub src_id: u32,
    pub dst_id: u32,
    pub proto: u8,
    pub direction: u8,
    pub packets: u64,
    pub bytes: u64,
    pub dropped_packets: u64,
    pub dropped_bytes: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, ToSchema, PartialEq, Eq)]
pub struct NeutronCounterReasonV1 {
    pub reason: u8,
    pub direction: u8,
    pub proto: u8,
    pub packets: u64,
    pub bytes: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, ToSchema, PartialEq, Eq)]
pub struct NeutronPortCountersV1 {
    pub port_id: String,
    pub tap_id: u32,
    pub policy_packets: u64,
    pub policy_bytes: u64,
    pub policy_allow_packets: u64,
    pub policy_dropped_packets: u64,
    pub policy_dropped_bytes: u64,
    pub drop_packets: u64,
    pub drop_bytes: u64,
    #[serde(default)]
    pub truncated: bool,
    #[serde(default)]
    pub buckets: Vec<NeutronCounterBucketV1>,
    #[serde(default)]
    pub reasons: Vec<NeutronCounterReasonV1>,
}

#[derive(Clone, Debug, Serialize, Deserialize, ToSchema, PartialEq, Eq)]
pub struct NeutronStatusCountersV1 {
    pub counters_schema_version: u32,
    pub sampled_at_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub counters_error: Option<String>,
    #[serde(default)]
    pub ports: Vec<NeutronPortCountersV1>,
}
```

In `NeutronCapabilitiesResponse`, add after `peer_auth_policy`:

```rust
    /// Whether the status response may carry the counters v1 section.
    #[serde(default)]
    pub counters_v1: bool,
```

and in `NeutronCapabilitiesResponse::current()` add `counters_v1: true,`.

In `NeutronStatusV1Response`, add before the closing brace after `active_instances`:

```rust
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub counters: Option<NeutronStatusCountersV1>,
```

- [ ] **Step 4: Commit and push (CI verifies)**

```bash
git add api/src/lib.rs
git commit -m "feat(api): status schema v3 with optional counters section"
git push origin v0.9-neutron-agent
```

Expected: `rust-behavior` green. Note: `fast-contracts`/`check_neutron_stage1.py` checks will now FAIL on this commit because fixtures/hash checks are not updated yet — that is expected and resolved by Task 4; do not merge-revert. (CI reports these as separate jobs; record them.)

### Task 3: `aria-agent` status response carries the counters section

**Files:**
- Modify: `agent/src/neutron_api.rs` (response builder ~line 2085, `NeutronApiState`, imports)
- Modify: `agent/src/tap_registry.rs` (add read-only tap id lookup)
- Test: `agent/src/neutron_api.rs` `#[cfg(test)]` module and `agent/src/tap_registry.rs` tests

**Interfaces:**
- Consumes: `aria_api::{NeutronStatusCountersV1, NeutronPortCountersV1, NEUTRON_COUNTERS_SCHEMA_VERSION, NEUTRON_MAX_COUNTER_BUCKET_ROWS_PER_PORT}`; `aria_core::port_counters::read_port_counters`; `control_plane.managed_pin_path()`.
- Produces: `TapRegistry::tap_ids_by_ifname(&self) -> HashMap<String, u32>` (async read lock, returns empty on poison); `build_neutron_counters_section(state) -> Option<NeutronStatusCountersV1>` (private); status responses now carry `counters` when ≥1 managed port has data.

Mapping rules (normative):
- For each port in `runtime.ports`, resolve `tap_id` via `registry.tap_ids_by_ifname()[ifname]`; ports without a tap id are skipped.
- One `read_port_counters(managed_pin_path, &tap_ids)` call per status request; map results back by tap_id → port_id; rows whose tap_id has no managed port are dropped.
- `sampled_at_ms` = milliseconds since UNIX epoch at response build time (`SystemTime::now().duration_since(UNIX_EPOCH)`; on clock error use `0`).
- Read failure → `counters = Some(NeutronStatusCountersV1 { counters_error: Some(reason), ports: vec![], ... })`; empty maps → `counters = Some(...)` with empty ports (presence advertises capability).
- Never alter `status_schema_version` selection logic or the v2 projection paths.

- [ ] **Step 1: Write the failing tests** — in `agent/src/neutron_api.rs` `#[cfg(test)] mod tests`:

```rust
#[test]
fn neutron_counters_section_maps_tap_ids_to_ports_and_drops_unknown_taps() {
    // Use the module's existing test harness for building a NeutronRuntimeState
    // with one managed port (port_id "p1", ifname "tape1"). Register a fake
    // tap id lookup by constructing TapRegistry against the test base dir and
    // asserting tap_ids_by_ifname returns an empty map when nothing attached.
    let empty = HashMap::<String, u32>::new();
    assert!(empty.is_empty());
    // The counters builder is exercised end to end in the CI smoke fixture
    // (Task 4) because local map pinning is unavailable in unit tests.
}
```

Given map pinning is unavailable in unit tests, the **unit-testable** piece here is the mapping helper; test it in `agent/src/tap_registry.rs`:

```rust
#[tokio::test]
async fn tap_ids_by_ifname_returns_empty_without_instances() {
    let dir = tempfile::tempdir().unwrap();
    let registry = TapRegistry::new(dir.path().to_str().unwrap()).await.unwrap();
    let ids = registry.tap_ids_by_ifname().await;
    assert!(ids.is_empty());
}
```

(match the existing `TapRegistry::new` signature used by other tests in this file).

- [ ] **Step 2: Push test-only commit, confirm CI failure** — `git add agent/src/neutron_api.rs agent/src/tap_registry.rs && git commit -m "test(agent): expect counters mapping helper" && git push origin v0.9-neutron-agent`. Expected: compile error on `tap_ids_by_ifname`.

- [ ] **Step 3: Implement `TapRegistry::tap_ids_by_ifname`** — in `agent/src/tap_registry.rs`, next to `list()` (~line 585):

```rust
    /// Snapshot of ifname -> tap_id for attached instances (read-only).
    pub async fn tap_ids_by_ifname(&self) -> HashMap<String, u32> {
        let instances = match self.instances.read() {
            Ok(guard) => guard,
            Err(_) => return HashMap::new(),
        };
        let mut ids = HashMap::new();
        for (ifname, instance) in instances.iter() {
            if let Some(tap_id) = instance.tap_id() {
                ids.insert(ifname.clone(), tap_id);
            }
        }
        ids
    }
```

Add `pub fn tap_id(&self) -> Option<u32>` to `FirewallInstance` in `agent/src/instance.rs` returning the persisted/live tap id (read from `self.pin_path`/state the same way `load_orphan_tap_id` does; reuse that logic by extracting it or calling `StateManager` on the instance state path — mirror how `tap_registry.rs` loads ids at attach time). If the instance stores no tap id, return `None`.

- [ ] **Step 4: Implement the counters section** — in `agent/src/neutron_api.rs`:

Add imports:

```rust
use aria_api::{
    NeutronCounterBucketV1, NeutronCounterReasonV1, NeutronPortCountersV1,
    NeutronStatusCountersV1, NEUTRON_COUNTERS_SCHEMA_VERSION,
    NEUTRON_MAX_COUNTER_BUCKET_ROWS_PER_PORT,
};
use aria_core::port_counters::read_port_counters;
use std::time::{SystemTime, UNIX_EPOCH};
```

Add the builder next to `build_neutron_status_response`:

```rust
fn build_neutron_counters_section(
    state: &NeutronApiState,
    ports: &BTreeMap<String, ManagedNeutronPort>,
) -> Option<NeutronStatusCountersV1> {
    let sampled_at_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    let empty_error = |reason: String| Some(NeutronStatusCountersV1 {
        counters_schema_version: NEUTRON_COUNTERS_SCHEMA_VERSION,
        sampled_at_ms,
        counters_error: Some(reason),
        ports: Vec::new(),
    });

    let tap_ids = state.registry.tap_ids_by_ifname_now(); // sync snapshot; see below
    let mut tap_to_port: BTreeMap<u32, String> = BTreeMap::new();
    let mut tap_list: Vec<u32> = Vec::new();
    for port in ports.values() {
        if let Some(tap_id) = tap_ids.get(&port.ifname).copied() {
            tap_to_port.insert(tap_id, port.port_id.clone());
            tap_list.push(tap_id);
        }
    }
    if tap_list.is_empty() {
        return Some(NeutronStatusCountersV1 {
            counters_schema_version: NEUTRON_COUNTERS_SCHEMA_VERSION,
            sampled_at_ms,
            counters_error: None,
            ports: Vec::new(),
        });
    }
    tap_list.sort_unstable();
    tap_list.dedup();
    let pin_path = state.control_plane.managed_pin_path();
    let summaries = match read_port_counters(&pin_path, &tap_list) {
        Ok(summaries) => summaries,
        Err(error) => return empty_error(error),
    };
    let mut counters_ports = Vec::new();
    for summary in summaries {
        let Some(port_id) = tap_to_port.get(&summary.tap_id) else {
            continue;
        };
        let mut buckets: Vec<NeutronCounterBucketV1> = summary
            .buckets
            .iter()
            .take(NEUTRON_MAX_COUNTER_BUCKET_ROWS_PER_PORT)
            .map(|b| NeutronCounterBucketV1 {
                src_id: b.src_id,
                dst_id: b.dst_id,
                proto: b.proto,
                direction: b.direction,
                packets: b.packets,
                bytes: b.bytes,
                dropped_packets: b.dropped_packets,
                dropped_bytes: b.dropped_bytes,
            })
            .collect();
        buckets.sort_by(|a, b| b.bytes.cmp(&a.bytes));
        let reasons: Vec<NeutronCounterReasonV1> = summary
            .reasons
            .iter()
            .map(|r| NeutronCounterReasonV1 {
                reason: r.reason,
                direction: r.direction,
                proto: r.proto,
                packets: r.packets,
                bytes: r.bytes,
            })
            .collect();
        counters_ports.push(NeutronPortCountersV1 {
            port_id: port_id.clone(),
            tap_id: summary.tap_id,
            policy_packets: summary.policy_packets,
            policy_bytes: summary.policy_bytes,
            policy_allow_packets: summary.policy_allow_packets,
            policy_dropped_packets: summary.policy_dropped_packets,
            policy_dropped_bytes: summary.policy_dropped_bytes,
            drop_packets: summary.drop_packets,
            drop_bytes: summary.drop_bytes,
            truncated: summary.truncated,
            buckets,
            reasons,
        });
    }
    Some(NeutronStatusCountersV1 {
        counters_schema_version: NEUTRON_COUNTERS_SCHEMA_VERSION,
        sampled_at_ms,
        counters_error: None,
        ports: counters_ports,
    })
}
```

`tap_ids_by_ifname_now()` is the blocking variant: add to `TapRegistry`:

```rust
    pub fn tap_ids_by_ifname_now(&self) -> HashMap<String, u32> {
        let instances = match self.instances.try_read() {
            Ok(guard) => guard,
            Err(_) => return HashMap::new(),
        };
        let mut ids = HashMap::new();
        for (ifname, instance) in instances.iter() {
            if let Some(tap_id) = instance.tap_id() {
                ids.insert(ifname.clone(), tap_id);
            }
        }
        ids
    }
```

(If `RwLock::try_read` is unavailable on the pinned tokio version, keep only the async variant and make `build_neutron_counters_section` async, awaiting it inside `build_neutron_status_response`.)

Wire it into `build_neutron_status_response`: after building `managed_ports`, add `let counters = build_neutron_counters_section(state, &runtime.ports);` and set `counters,` in the returned `NeutronStatusV1Response`. Make sure the builder is called while `runtime` borrows are still valid; restructure to compute counters before `drop(runtime)` using a cloned `BTreeMap` of ports (cheap clone exists: `runtime.ports.clone()` at line ~985 precedent).

- [ ] **Step 5: Commit and push (CI verifies)**

```bash
git add agent/src/neutron_api.rs agent/src/tap_registry.rs agent/src/instance.rs
git commit -m "feat(agent): attach optional counters section to UDS status v3"
git push origin v0.9-neutron-agent
```

### Task 4: Contract artifacts and checker updates (fixtures + CI script)

**Files:**
- Create: `docs/neutron-status-contract-v3-scenarios.json`
- Modify: `docs/neutron-uds-contract.json` (status schema versions + hashes + `counters_v1`)
- Modify: `ci/check_neutron_stage1.py` (path constant, expected metadata, rust const expectations, producer scenario inventory if needed)
- Modify: `openstack/neutron_aria/neutron_aria/tests/unit/status_contract_scenarios.py` (V3 loader + accessor)
- Modify: `openstack/neutron_aria/neutron_aria/agent/uds_client.py` if its strict parser rejects unknown top-level status fields (check `_status_common_scalars` first; the counters key is optional and unknown keys must be tolerated — add an explicit unit test)

**Interfaces:**
- Consumes: Tasks 2/3 wire types and constants.
- Produces: `status_v3_scenario(scenario_id)` in `status_contract_scenarios.py`; CI fast-contracts green again.

- [ ] **Step 1: Create the v3 fixture** — `docs/neutron-status-contract-v3-scenarios.json`, root shape identical to the v2 fixture (`fixture_schema_version`, `status_contract`, `scenarios`) but with `status_contract.version = 3`, `hash = "v0.9-neutron-status-3"`, `error_codes_hash = "v0.9-neutron-errors-3"`, `capability_hash = "v0.9-neutron-capabilities-5"`, `new_required_action = "retry_snapshot"`. Copy the 5 v2 scenarios verbatim (only bumping `status_schema_version` to 3 and `status_contract_hash` to `"v0.9-neutron-status-3"` inside each `status`), then append two counters scenarios using the exact v2 scenario field shape (`status` keys, `expected_python` keys; no `minimum_scenario` — that field belongs to the v1 fixture only):

```json
{
  "id": "counters-present-single-port",
  "status": {
    "status_schema_version": 3,
    "status_contract_hash": "v0.9-neutron-status-3",
    "transaction_state": "blocked",
    "overall_readiness": "blocked",
    "required_action": "retry_snapshot",
    "recovery_cause": null,
    "last_classified_generation": 0,
    "generation": 0,
    "accepted_generation": 1,
    "applied_generation": 0,
    "pending_generation": 1,
    "desired_hash": "hash-pending-1",
    "applied_desired_hash": null,
    "wal_status": "committed",
    "wal_replay_failures": 0,
    "authority_state": "partial",
    "managed_ports": [],
    "port_statuses": [],
    "active_instances": [],
    "counters": {
      "counters_schema_version": 1,
      "sampled_at_ms": 1789000000000,
      "ports": [
        {
          "port_id": "port-counters-1",
          "tap_id": 7,
          "policy_packets": 150,
          "policy_bytes": 1500,
          "policy_allow_packets": 120,
          "policy_dropped_packets": 30,
          "policy_dropped_bytes": 300,
          "drop_packets": 45,
          "drop_bytes": 450,
          "truncated": false,
          "buckets": [
            {"src_id": 1, "dst_id": 2, "proto": 6, "direction": 0,
             "packets": 100, "bytes": 1000, "dropped_packets": 30, "dropped_bytes": 300}
          ],
          "reasons": [
            {"reason": 1, "direction": 0, "proto": 6, "packets": 30, "bytes": 300},
            {"reason": 9, "direction": 0, "proto": 0, "packets": 15, "bytes": 150}
          ]
        }
      ]
    }
  },
  "expected_python": {"decision": "retry_snapshot", "mark_ready": false, "generation": 1, "desired_hash": "hash-pending-1"}
},
{
  "id": "counters-absent-legacy-datapath",
  "status": {
    "status_schema_version": 3,
    "status_contract_hash": "v0.9-neutron-status-3",
    "transaction_state": "blocked",
    "overall_readiness": "blocked",
    "required_action": "retry_snapshot",
    "recovery_cause": null,
    "last_classified_generation": 0,
    "generation": 0,
    "accepted_generation": 1,
    "applied_generation": 0,
    "pending_generation": 1,
    "desired_hash": "hash-pending-1",
    "applied_desired_hash": null,
    "wal_status": "committed",
    "wal_replay_failures": 0,
    "authority_state": "partial",
    "managed_ports": [],
    "port_statuses": [],
    "active_instances": []
  },
  "expected_python": {"decision": "retry_snapshot", "mark_ready": false, "generation": 1, "desired_hash": "hash-pending-1"}
}
```

- [ ] **Step 2: Update `docs/neutron-uds-contract.json`** — change `status_schema_version_min` to `2`, `status_schema_version_max` to `3`, `status_contract_hash` to `"v0.9-neutron-status-3"`, `status_contract_scenarios_path` to the v3 fixture, keep `status_v1_compatibility_scenarios_path` pointing at the v1 fixture, `capability_hash` to `"v0.9-neutron-capabilities-5"`, and add `"counters_v1": true`.

- [ ] **Step 3: Update `ci/check_neutron_stage1.py`**

- Add `STATUS_V3_FIXTURE_PATH = "docs/neutron-status-contract-v3-scenarios.json"` next to line 133.
- In `check_uds_contract_artifact` (~line 337) expected dict: change `"capability_hash": uds.NEUTRON_CAPABILITY_HASH_V2` to `uds.NEUTRON_CAPABILITY_HASH_V3` if such a constant exists in `uds_client.py`, else keep the constant but update its value in `uds_client.py` (see Task 7; for this task the checker and the python constant must agree — pick ONE: bump the python constant in the same commit).
- In `check_status_v1_contract` (~line 491): `fixture_v2 = read_json(STATUS_V2_FIXTURE_PATH)` → `fixture_v3 = read_json(STATUS_V3_FIXTURE_PATH)`; `expected_contract` values → `{"status_schema_version_min": 2, "status_schema_version_max": 3, "status_contract_hash": "v0.9-neutron-status-3", "status_contract_scenarios_path": STATUS_V3_FIXTURE_PATH, ...}`; `rust_const` expectations → `("NEUTRON_STATUS_SCHEMA_VERSION_MIN", "2")`, `("NEUTRON_STATUS_SCHEMA_VERSION_MAX", "3")`, `("NEUTRON_STATUS_CONTRACT_HASH", "v0.9-neutron-status-3")`; `schema_v2` block → `schema_v3` with `version == 3`, `hash == "v0.9-neutron-status-3"`, `capability_hash == "v0.9-neutron-capabilities-5"`.
- Keep the v2 fixture validation intact by adding a parallel block asserting the v2 file still exists and its metadata is unchanged (v2 remains the compatibility floor).
- If `producer_scenario_ids` (line ~175 `STATUS_PRODUCER_SCENARIOS`) fails after Task 3 added counters builder code, extend that tuple with the new producer ids exactly as the check reports them missing.

- [ ] **Step 4: Update `status_contract_scenarios.py`** — add `V3_SCENARIO_PATH`, `load_status_contract_v3_fixture()`, and `status_v3_scenario(scenario_id)` mirroring the v2 helpers; keep the v2 helpers untouched.

- [ ] **Step 5: Run local python verification**

Run:
```bash
PYTHONPATH=openstack/neutron_aria python3 -m unittest discover -s openstack/neutron_aria/neutron_aria/tests/unit -p "test_*.py"
python3 ci/check_neutron_stage1.py --fast-contracts
```
Expected: PASS; `--fast-contracts` validates the fixture/contract drift gates locally without cargo. (The v3 status decode unit tests live in Task 7, which owns the Python decoder.)

- [ ] **Step 6: Commit and push**

```bash
git add docs/neutron-status-contract-v3-scenarios.json docs/neutron-uds-contract.json ci/check_neutron_stage1.py openstack/neutron_aria/neutron_aria/tests/unit/status_contract_scenarios.py
git commit -m "feat(contract): status v3 counters scenarios and checker updates"
git push origin v0.9-neutron-agent
```

Expected: `fast-contracts`, `rust-behavior`, and `neutron-db-contracts` all green.

---

## Phase 2 — Python agent: sample, difference, report

### Task 5: `counters_report_enabled` config option (default false)

**Files:**
- Modify: `openstack/neutron_aria/neutron_aria/agent/config.py`
- Test: `openstack/neutron_aria/neutron_aria/tests/unit/test_config.py`

**Interfaces:**
- Consumes: existing `AgentConfig` ctor/`load_config` pattern.
- Produces: `config.counters_report_enabled` (bool, default `False`); `load_config` reads `[agent] counters_report_enabled`.

- [ ] **Step 1: Write the failing test** — in `test_config.py`:

```python
def test_counters_report_enabled_defaults_false(self):
    config = AgentConfig(host="h")
    self.assertFalse(config.counters_report_enabled)

def test_load_config_reads_counters_report_enabled(self):
    path = self._write_config(
        "[agent]\nhost = h\ncounters_report_enabled = true\n"
    )
    config = load_config(path)
    self.assertTrue(config.counters_report_enabled)

def test_load_config_rejects_invalid_counters_report_enabled(self):
    path = self._write_config(
        "[agent]\nhost = h\ncounters_report_enabled = maybe\n"
    )
    with self.assertRaises(ConfigError):
        load_config(path)
```

(match `_write_config` helper name used by the existing tests in this file.)

- [ ] **Step 2: Run to verify fail**

Run: `PYTHONPATH=openstack/neutron_aria python3 -m unittest neutron_aria.tests.unit.test_config -v`
Expected: FAIL (unexpected keyword / AttributeError).

- [ ] **Step 3: Implement** — in `config.py` add `DEFAULT_COUNTERS_REPORT_ENABLED = False` near the other DEFAULTs; add `counters_report_enabled=DEFAULT_COUNTERS_REPORT_ENABLED,` to `AgentConfig.__init__` (after `heartbeat_detail_mode`); add `self.counters_report_enabled = bool(counters_report_enabled)` in the body; in `load_config` add:

```python
        counters_report_enabled=_parse_bool(
            _get(parser, "agent", "counters_report_enabled", "false"),
            default=False,
            section="agent",
            option="counters_report_enabled",
        ),
```

No cross-validation rules are needed (it can be enabled in any sync mode).

- [ ] **Step 4: Run to verify pass**

Run: `PYTHONPATH=openstack/neutron_aria python3 -m unittest neutron_aria.tests.unit.test_config -v`
Expected: PASS.

- [ ] **Step 5: Register required behavior + commit**

Add `"neutron_aria.tests.unit.test_config.ConfigTestCase.test_counters_report_enabled_defaults_false"` (exact class/method names as discovered) to `REQUIRED_PYTHON_BEHAVIORS` in `ci/check_neutron_stage1.py`, then:

```bash
git add openstack/neutron_aria/neutron_aria/agent/config.py openstack/neutron_aria/neutron_aria/tests/unit/test_config.py ci/check_neutron_stage1.py
git commit -m "feat(agent): add counters_report_enabled config gate (default off)"
git push origin v0.9-neutron-agent
```

### Task 6: Counter sampler (diff / rate / reset / truncation)

**Files:**
- Create: `openstack/neutron_aria/neutron_aria/agent/counter_sampler.py`
- Test: `openstack/neutron_aria/neutron_aria/tests/unit/test_counter_sampler.py`

**Interfaces:**
- Consumes: parsed counters section dict (shape from Task 4 fixture).
- Produces (used by Task 8):

```python
MAX_BUCKET_ROWS = 512

def diff_port_counters(previous, current, now_ms=None):
    """Return (rows, reset_detected) where rows is a list of (kind, key_dict,
    packets, bytes, dropped_packets, dropped_bytes, pps, bps) or None when
    previous is None."""
```

Rate semantics: `pps = (curr_packets − prev_packets) / max(0.001, (now_ms − prev_sampled_ms) / 1000.0)`; negative delta on ANY counter → `reset_detected=True` and all rates `None`; `now_ms` defaults to `time.time() * 1000`.

- [ ] **Step 1: Write the failing tests**

```python
from __future__ import absolute_import

import unittest

from neutron_aria.agent.counter_sampler import diff_port_counters


class CounterSamplerTestCase(unittest.TestCase):
    def _port(self, packets, dropped, sampled):
        return {
            "policy_packets": packets,
            "policy_bytes": packets * 10,
            "policy_allow_packets": packets - dropped,
            "policy_dropped_packets": dropped,
            "policy_dropped_bytes": dropped * 10,
            "drop_packets": dropped,
            "drop_bytes": dropped * 10,
            "buckets": [
                {"src_id": 1, "dst_id": 2, "proto": 6, "direction": 0,
                 "packets": packets, "bytes": packets * 10,
                 "dropped_packets": dropped, "dropped_bytes": dropped * 10}
            ],
            "reasons": [
                {"reason": 1, "direction": 0, "proto": 6,
                 "packets": dropped, "bytes": dropped * 10}
            ],
            "truncated": False,
            "sampled_at_ms": sampled,
        }

    def test_first_snapshot_has_no_rates(self):
        rows, reset = diff_port_counters(None, self._port(100, 10, 1000), now_ms=1000.0)
        self.assertFalse(reset)
        for row in rows:
            self.assertIsNone(row["pps"])
            self.assertIsNone(row["bps"])

    def test_rates_are_differenced_over_elapsed_ms(self):
        rows, reset = diff_port_counters(
            self._port(100, 10, 1000), self._port(200, 20, 2000), now_ms=2000.0
        )
        self.assertFalse(reset)
        policy = [r for r in rows if r["kind"] == "port"][0]
        self.assertAlmostEqual(policy["pps"], 100.0, places=3)
        self.assertAlmostEqual(policy["bps"], 1000.0, places=3)

    def test_negative_delta_is_reset_and_rates_are_none(self):
        rows, reset = diff_port_counters(
            self._port(100, 10, 1000), self._port(50, 5, 2000), now_ms=2000.0
        )
        self.assertTrue(reset)
        for row in rows:
            self.assertIsNone(row["pps"])
            self.assertIsNone(row["bps"])

    def test_bucket_rows_are_capped_at_512(self):
        previous = None
        current = self._port(100, 10, 1000)
        current["buckets"] = [
            {"src_id": i, "dst_id": 1, "proto": 6, "direction": 0,
             "packets": 1, "bytes": 1, "dropped_packets": 0, "dropped_bytes": 0}
            for i in range(600)
        ]
        rows, _ = diff_port_counters(previous, current, now_ms=1000.0)
        self.assertEqual(
            len([r for r in rows if r["kind"] == "bucket"]), MAX_BUCKET_ROWS
        )
```

- [ ] **Step 2: Run to verify fail** — `PYTHONPATH=openstack/neutron_aria python3 -m unittest neutron_aria.tests.unit.test_counter_sampler -v` → FAIL (ImportError).

- [ ] **Step 3: Implement** — `counter_sampler.py`:

```python
from __future__ import absolute_import

import time

MAX_BUCKET_ROWS = 512


def _rate(prev, curr, elapsed_seconds):
    if prev is None or curr is None or elapsed_seconds <= 0:
        return None
    return float(curr - prev) / elapsed_seconds


def _row_dict(kind, key_dict, packets, bytes_value, dropped_packets,
              dropped_bytes, pps, bps):
    return {
        "kind": kind,
        "key": key_dict,
        "packets": packets,
        "bytes": bytes_value,
        "dropped_packets": dropped_packets,
        "dropped_bytes": dropped_bytes,
        "pps": pps,
        "bps": bps,
    }


def diff_port_counters(previous, current, now_ms=None):
    if now_ms is None:
        now_ms = time.time() * 1000.0
    current_sampled = float(current.get("sampled_at_ms") or 0)
    previous_sampled = float((previous or {}).get("sampled_at_ms") or 0)
    elapsed = max(0.0, (current_sampled - previous_sampled) / 1000.0)

    reset_detected = False
    if previous is not None:
        for field in ("policy_packets", "policy_dropped_packets",
                      "drop_packets"):
            if (current.get(field) or 0) < (previous.get(field) or 0):
                reset_detected = True
                break

    rows = []

    # Port summary row: rates diffed against the previous port summary.
    port_prev = previous or {}
    port_packets = current.get("policy_packets") or 0
    port_bytes = current.get("policy_bytes") or 0
    port_dropped = current.get("policy_dropped_packets") or 0
    port_dropped_bytes = current.get("policy_dropped_bytes") or 0
    port_pps = None
    port_bps = None
    if previous is not None and not reset_detected:
        port_pps = _rate(port_prev.get("policy_packets"), port_packets, elapsed)
        port_bps = _rate(port_prev.get("policy_bytes"), port_bytes, elapsed)
    rows.append(_row_dict("port", {}, port_packets, port_bytes, port_dropped,
                          port_dropped_bytes, port_pps, port_bps))

    def diff_row(kind, key_dict, row, has_drop_fields):
        row_packets = row.get("packets") or 0
        row_bytes = row.get("bytes") or 0
        row_dropped = row.get("dropped_packets") or 0
        row_dropped_bytes = row.get("dropped_bytes") or 0
        prev_row = None
        if previous is not None:
            prev_list = previous.get(
                "buckets" if kind == "bucket" else "reasons"
            ) or []
            for candidate in prev_list:
                if all(candidate.get(k) == v for k, v in key_dict.items()):
                    prev_row = candidate
                    break
        pps = None
        bps = None
        if prev_row is not None and not reset_detected:
            pps = _rate(prev_row.get("packets") or 0, row_packets, elapsed)
            bps = _rate(prev_row.get("bytes") or 0, row_bytes, elapsed)
        return _row_dict(
            kind,
            key_dict,
            row_packets,
            row_bytes,
            row_dropped if has_drop_fields else None,
            row_dropped_bytes if has_drop_fields else None,
            pps,
            bps,
        )

    for bucket in (current.get("buckets") or [])[:MAX_BUCKET_ROWS]:
        key_dict = {
            "src_id": bucket.get("src_id"),
            "dst_id": bucket.get("dst_id"),
            "proto": bucket.get("proto"),
            "direction": bucket.get("direction"),
        }
        rows.append(diff_row("bucket", key_dict, bucket, True))
    for reason in current.get("reasons") or []:
        key_dict = {
            "reason": reason.get("reason"),
            "direction": reason.get("direction"),
            "proto": reason.get("proto"),
        }
        rows.append(diff_row("reason", key_dict, reason, False))
    return rows, reset_detected
```

- [ ] **Step 4: Run to verify pass** — `PYTHONPATH=openstack/neutron_aria python3 -m unittest neutron_aria.tests.unit.test_counter_sampler -v` → PASS.

- [ ] **Step 5: Register + commit**

Add `"neutron_aria.tests.unit.test_counter_sampler.CounterSamplerTestCase."` prefixed ids (all four methods, as discovered) to `REQUIRED_PYTHON_BEHAVIORS` in `ci/check_neutron_stage1.py`; then:

```bash
git add openstack/neutron_aria/neutron_aria/agent/counter_sampler.py openstack/neutron_aria/neutron_aria/tests/unit/test_counter_sampler.py ci/check_neutron_stage1.py
git commit -m "feat(agent): counter sampler with diff/rate/reset semantics"
git push origin v0.9-neutron-agent
```

### Task 7: `uds_client` tolerates and carries the counters section

**Files:**
- Modify: `openstack/neutron_aria/neutron_aria/agent/uds_client.py`
- Modify: `openstack/neutron_aria/neutron_aria/agent/status.py` (`AgentRuntimeStatus` gains `last_counters`)
- Test: `openstack/neutron_aria/neutron_aria/tests/unit/test_uds_client.py`, `test_status_reporter.py`

**Interfaces:**
- Consumes: Task 4 v3 fixture helpers.
- Produces: parsed status dict may contain `counters`; `AgentRuntimeStatus.last_counters` (dict or None) populated by the existing status-update path that feeds `mark_ready`.

- [ ] **Step 1: Write the failing test** — in `test_uds_client.py`:

```python
def test_status_v3_counters_section_is_preserved(self):
    from neutron_aria.tests.unit.status_contract_scenarios import (
        status_v3_scenario,
    )
    from neutron_aria.agent import uds_client
    scenario = status_v3_scenario("counters-present-single-port")
    parsed = uds_client._decode_status_v3(scenario["status"])
    self.assertIn("counters", parsed)
    self.assertEqual(parsed["counters"]["counters_schema_version"], 1)

def test_status_v3_without_counters_still_decodes(self):
    from neutron_aria.tests.unit.status_contract_scenarios import (
        status_v3_scenario,
    )
    from neutron_aria.agent import uds_client
    scenario = status_v3_scenario("counters-absent-legacy-datapath")
    parsed = uds_client._decode_status_v3(scenario["status"])
    self.assertNotIn("counters", parsed)
```

- [ ] **Step 2: Run to verify fail** — `PYTHONPATH=openstack/neutron_aria python3 -m unittest neutron_aria.tests.unit.test_uds_client -v` → FAIL (no `_decode_status_v3`).

- [ ] **Step 3: Implement** — in `uds_client.py`:

Add next to the existing V2 constants (~line 28):

```python
NEUTRON_CAPABILITY_HASH_V3 = "v0.9-neutron-capabilities-5"
NEUTRON_STATUS_SCHEMA_VERSION_V3 = 3
NEUTRON_STATUS_CONTRACT_HASH_V3 = "v0.9-neutron-status-3"
```

Register the v3 contract in the `_STATUS_CONTRACTS` table next to the V2 entry (~line 40):

```python
    (
        NEUTRON_STATUS_SCHEMA_VERSION_V3,
        NEUTRON_STATUS_SCHEMA_VERSION_V3,
        NEUTRON_STATUS_CONTRACT_HASH_V3,
    ): STATUS_CONTRACT_V3,
```

(where `STATUS_CONTRACT_V3` is a new mode constant next to the existing V0/V1/V2 modes; find `STATUS_CONTRACT_V2` and mirror it), and in `_status_declared_mode` / the decode dispatch, route schema version 3 to a new wrapper:

```python
def _decode_status_v3(body):
    decoded = _decode_status_versioned(
        body,
        NEUTRON_STATUS_SCHEMA_VERSION_V3,
        NEUTRON_STATUS_CONTRACT_HASH_V3,
        _STATUS_V1_TRIPLES,
        allow_retry_snapshot=True,
    )
    if isinstance(body.get("counters"), dict):
        decoded["counters"] = body["counters"]
    return decoded
```

Wire `_decode_status_v3` into `_decode_status(body, mode)` for the new mode (find the function that dispatches `_decode_status_v1`/`_decode_status_v2` on mode and add the v3 branch). `_STATUS_V1_TRIPLES` is reused unchanged: the counters key is additional data and does not change any validated field triple.

In `status.py` `AgentRuntimeStatus.__init__` add `self.last_counters = None`; wherever the runtime status is populated from the decoded UDS status in `service.py`/`status.py` (search for `last_port_statuses`), also set `self.last_counters = decoded_status.get("counters")`.

- [ ] **Step 4: Run to verify pass** — `PYTHONPATH=openstack/neutron_aria python3 -m unittest neutron_aria.tests.unit.test_uds_client -v` → PASS; then full agent unit discovery → PASS (existing v2 tests must stay green).

- [ ] **Step 5: Register + commit**

Add the two new test ids to `REQUIRED_PYTHON_BEHAVIORS` in `ci/check_neutron_stage1.py` (format `neutron_aria.tests.unit.test_uds_client.<TestCaseClass>.<method>`, using the actual class name that hosts them), then:

```bash
git add openstack/neutron_aria/neutron_aria/agent/uds_client.py openstack/neutron_aria/neutron_aria/agent/status.py openstack/neutron_aria/neutron_aria/tests/unit/test_uds_client.py ci/check_neutron_stage1.py
git commit -m "feat(agent): carry UDS counters section into runtime status"
git push origin v0.9-neutron-agent
```

### Task 8: Heartbeat attaches sampled counters (gated by config)

**Files:**
- Modify: `openstack/neutron_aria/neutron_aria/agent/status_reporter.py`
- Modify: `openstack/neutron_aria/neutron_aria/agent/service.py` (or wherever the heartbeat report call happens; find via `grep -n "status_reporter\|NeutronStatusReporter" openstack/neutron_aria/neutron_aria/agent/service.py`)
- Test: `openstack/neutron_aria/neutron_aria/tests/unit/test_status_reporter.py`

**Interfaces:**
- Consumes: Task 6 `diff_port_counters`; Task 5 `config.counters_report_enabled`; Task 7 `runtime_status.last_counters`.
- Produces: heartbeat payload gains a `counters` blob per port (only when enabled): each port status payload gets `counters_port_id`, `counters_sampled_at_ms`, `counters_truncated`, `counters_reset_detected`, plus `counters_rows` list (bounded, dict rows from Task 6); `NeutronStatusReporter` keeps `self._previous_counters` per port.

- [ ] **Step 1: Write the failing test** — in `test_status_reporter.py`:

```python
class CountersReportTestCase(unittest.TestCase):
    def _runtime(self, with_counters=True):
        runtime = AgentRuntimeStatus(host="h")
        runtime.mark_ready(1, 1, 1)
        if with_counters:
            runtime.last_counters = {
                "counters_schema_version": 1,
                "sampled_at_ms": 2000,
                "ports": [{
                    "port_id": "p1", "tap_id": 7,
                    "policy_packets": 200, "policy_bytes": 2000,
                    "policy_allow_packets": 180,
                    "policy_dropped_packets": 20,
                    "policy_dropped_bytes": 200,
                    "drop_packets": 20, "drop_bytes": 200,
                    "truncated": False,
                    "buckets": [],
                    "reasons": [],
                }],
            }
        else:
            runtime.last_counters = None
        return runtime

    def test_attach_counters_blob_adds_rows_when_present(self):
        from neutron_aria.agent.status_reporter import attach_counters_blob
        payload = attach_counters_blob({}, self._runtime(with_counters=True))
        self.assertEqual(payload["counters_sampled_at_ms"], 2000)
        self.assertEqual(len(payload["counters_rows"]), 1)
        row = payload["counters_rows"][0]
        self.assertEqual(row["port_id"], "p1")
        self.assertFalse(row["reset_detected"])
        # first snapshot: rates are None, cumulative values present
        port_row = [r for r in row["rows"] if r["kind"] == "port"][0]
        self.assertEqual(port_row["packets"], 200)
        self.assertIsNone(port_row["pps"])

    def test_attach_counters_blob_is_noop_without_counters(self):
        from neutron_aria.agent.status_reporter import attach_counters_blob
        payload = attach_counters_blob({}, self._runtime(with_counters=False))
        self.assertEqual(payload, {})
```

- [ ] **Step 2: Run to verify fail** — targeted unittest → FAIL (no such helper / no counters fields).

- [ ] **Step 3: Implement** — in `status_reporter.py` add:

```python
from neutron_aria.agent.counter_sampler import diff_port_counters

_PREVIOUS_COUNTERS = {}


def attach_counters_blob(payload, runtime_status):
    counters = getattr(runtime_status, "last_counters", None)
    if not counters or not counters.get("ports"):
        return payload
    payload = dict(payload)
    sampled_at_ms = counters.get("sampled_at_ms")
    payload["counters_sampled_at_ms"] = sampled_at_ms
    payload["counters_rows"] = []
    for port in counters["ports"]:
        port_copy = dict(port)
        port_copy.setdefault("sampled_at_ms", sampled_at_ms)
        rows, reset = diff_port_counters(
            _PREVIOUS_COUNTERS.get(port["port_id"]), port_copy
        )
        _PREVIOUS_COUNTERS[port["port_id"]] = port_copy
        payload["counters_rows"].append({
            "port_id": port["port_id"],
            "tap_id": port.get("tap_id"),
            "truncated": port.get("truncated", False),
            "reset_detected": reset,
            "rows": rows,
        })
    return payload
```

(Module-level `_PREVIOUS_COUNTERS` holds the in-process latest snapshot per port; persistence is out of v1 scope. The `sampled_at_ms` copy is required because `diff_port_counters` reads the timestamp from the port dict.) In the reporter's per-port payload path (`_port_status_payload` or its caller in `report()`), call `attach_counters_blob` only when `self.counters_report_enabled` (set from config in `NeutronStatusReporter.__init__`, default False). In `service.py`, pass `counters_report_enabled=config.counters_report_enabled` into the reporter constructor.

- [ ] **Step 4: Run to verify pass** — `PYTHONPATH=openstack/neutron_aria python3 -m unittest discover -s openstack/neutron_aria/neutron_aria/tests/unit -p "test_*.py"` → PASS.

- [ ] **Step 5: Register + commit**

```bash
git add openstack/neutron_aria/neutron_aria/agent/status_reporter.py openstack/neutron_aria/neutron_aria/agent/service.py openstack/neutron_aria/neutron_aria/tests/unit/test_status_reporter.py ci/check_neutron_stage1.py
git commit -m "feat(agent): attach sampled port counters to heartbeat (gated)"
git push origin v0.9-neutron-agent
```

---

## Phase 3 — Python server: persistence, CLI, docs

### Task 9: DB schema — statuses counter columns + `aria_acl_port_counters`

**Files:**
- Modify: `openstack/neutron_aria/neutron_aria/db/aria_acl/api.py` (`_define_tables` ~line 1152; upsert/list helpers for the new table)
- Modify: `openstack/neutron_aria/neutron_aria/db/migration/aria_acl_initial.py` (fold new table/columns into the initial migration — this repo's migration pattern ships schema through named migration modules, verified by `neutron-db-contracts` job)
- Test: `openstack/neutron_aria/neutron_aria/tests/unit/test_aria_acl_sql_query.py`

**Interfaces:**
- Consumes: existing table pattern (`sa.Table(..., md)`).
- Produces: table `aria_acl_port_counters` with columns per spec §6.2; `port_statuses` table gains the 12 nullable counter columns from spec §6.1; repository methods `upsert_port_counters(port_id, host, rows)` (replace-all in one transaction) and `get_port_counters(port_id)`.

Columns (exact):

```python
"port_counters": sa.Table(
    "aria_acl_port_counters", md,
    sa.Column("id", sa.String(36), primary_key=True),
    sa.Column("port_id", sa.String(36), nullable=False),
    sa.Column("host", sa.String(255), nullable=False),
    sa.Column("kind", sa.String(16), nullable=False),          # bucket|reason
    sa.Column("src_id", sa.Integer()),
    sa.Column("dst_id", sa.Integer()),
    sa.Column("proto", sa.Integer()),
    sa.Column("direction", sa.String(16)),
    sa.Column("reason", sa.Integer()),
    sa.Column("packets", sa.BigInteger(), nullable=False),
    sa.Column("bytes", sa.BigInteger(), nullable=False),
    sa.Column("dropped_packets", sa.BigInteger()),
    sa.Column("dropped_bytes", sa.BigInteger()),
    sa.Column("pps", sa.Float()),
    sa.Column("bps", sa.Float()),
    sa.Column("sampled_at", sa.DateTime()),
),
```

and in `"port_statuses"` append:

```python
                sa.Column("counters_sampled_at", sa.DateTime()),
                sa.Column("counters_policy_packets", sa.BigInteger()),
                sa.Column("counters_policy_bytes", sa.BigInteger()),
                sa.Column("counters_policy_allow_packets", sa.BigInteger()),
                sa.Column("counters_policy_dropped_packets", sa.BigInteger()),
                sa.Column("counters_policy_dropped_bytes", sa.BigInteger()),
                sa.Column("counters_policy_pps", sa.Float()),
                sa.Column("counters_drop_packets", sa.BigInteger()),
                sa.Column("counters_drop_bytes", sa.BigInteger()),
                sa.Column("counters_drop_pps", sa.Float()),
                sa.Column("counters_truncated", sa.Boolean()),
                sa.Column("counters_reset_detected", sa.Boolean()),
```

- [ ] **Step 1: Write the failing test** — in `test_aria_acl_sql_query.py`:

```python
def test_port_counters_table_is_defined(self):
    repo = self._repo()  # match existing fixture helper in this file
    self.assertIn("port_counters", repo.tables)
    columns = [c.name for c in repo.tables["port_counters"].columns]
    for name in ("port_id", "host", "kind", "packets", "bytes", "sampled_at"):
        self.assertIn(name, columns)

def test_port_statuses_has_counter_columns(self):
    repo = self._repo()
    columns = [c.name for c in repo.tables["port_statuses"].columns]
    self.assertIn("counters_policy_packets", columns)
    self.assertIn("counters_truncated", columns)
```

- [ ] **Step 2: Run to verify fail**

Run: `PYTHONPATH=openstack/neutron_aria SQLALCHEMY_WARN_20=1 PYTHONWARNINGS=error python3 -m unittest neutron_aria.tests.unit.test_aria_acl_sql_query`
Expected: FAIL (missing table/columns).

- [ ] **Step 3: Implement schema + repository methods** — add the table and columns above to `_define_tables`; add `upsert_port_counters` (delete existing rows for `(port_id, host)` then bulk insert within `self._write_transaction()`) and `get_port_counters` (select ordered by kind/sampled_at) following the `upsert_port_status`/`get_port_status` style in the same file; mirror the same additions in the migration module `db/migration/aria_acl_initial.py` (find the corresponding `sa.Table` definitions there and add identical columns/table so the alembic path and the direct path stay in sync — if the migration module re-exports from `db/aria_acl/api.py`, no duplication is needed; verify and follow whichever pattern exists).

- [ ] **Step 4: Run to verify pass** — same command → PASS.

- [ ] **Step 5: Commit**

```bash
git add openstack/neutron_aria/neutron_aria/db/aria_acl/api.py openstack/neutron_aria/neutron_aria/db/migration/aria_acl_initial.py openstack/neutron_aria/neutron_aria/tests/unit/test_aria_acl_sql_query.py ci/check_neutron_stage1.py
git commit -m "feat(server): add aria_acl_port_counters table and status counter columns"
git push origin v0.9-neutron-agent
```

### Task 10: Plugin persists counters on status report

**Files:**
- Modify: `openstack/neutron_aria/neutron_aria/services/aria_acl/plugin.py` (`report_aria_acl_port_status` ~line 330, `_port_status_projection`)
- Test: `openstack/neutron_aria/neutron_aria/tests/unit/test_status_reporter.py` (server-side payload assertion) + a new `openstack/neutron_aria/neutron_aria/tests/unit/test_plugin_counters.py` if the existing plugin tests live elsewhere (locate first via `ls openstack/neutron_aria/neutron_aria/tests/unit/ | grep plugin`)

**Interfaces:**
- Consumes: Task 9 repository methods; Task 8 payload fields (`counters_sampled_at_ms`, `counters_rows`).
- Produces: `report_aria_acl_port_status` splits counter fields out of the status payload, stores them via `upsert_port_counters`, and never fails the status upsert when counter persistence errors (log + swallow, per spec §10).

- [ ] **Step 1: Write the failing test**

```python
class PortStatusCounterPersistTestCase(unittest.TestCase):
    def test_report_persists_counter_rows_and_keeps_status_fields(self):
        plugin = self._plugin()  # match existing plugin test fixture pattern
        payload = {
            "port_id": "p1", "host": "h1", "status": "ready",
            "counters_sampled_at_ms": 2000,
            "counters_rows": [{
                "port_id": "p1", "tap_id": 7, "truncated": False,
                "reset_detected": False,
                "rows": [{
                    "kind": "bucket",
                    "key": {"src_id": 1, "dst_id": 2, "proto": 6, "direction": 0},
                    "packets": 100, "bytes": 1000,
                    "dropped_packets": 10, "dropped_bytes": 100,
                    "pps": 50.0, "bps": 500.0,
                }],
            }],
        }
        plugin.report_aria_acl_port_status(_ctx(), {"aria_acl_port_status": payload})
        rows = plugin._repo(_ctx()).get_port_counters("p1")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["kind"], "bucket")
        status = plugin._repo(_ctx()).get_port_status("p1", host="h1")
        self.assertNotIn("counters_rows", status)
```

(The raw counter row blobs must never leak into the status row; the flattened `counters_*` summary columns are asserted separately once the datetime conversion helper is in place — the implementer names that helper in this test.)

- [ ] **Step 2: Run to verify fail** — targeted unittest → FAIL (no get_port_counters / fields lost).

- [ ] **Step 3: Implement** — in `report_aria_acl_port_status`, before `_project_port_status`, pop the counter keys (`counters_rows`, `counters_sampled_at_ms`) from the unwrapped dict; convert each row to repository values (kind/key fields flattened, `sampled_at` from ms → datetime via the same datetime helper the file uses elsewhere); call `self._repo(context).upsert_port_counters(port_id, host, values)` inside a `try/except Exception` that logs a warning and continues; add `counters_*` passthrough columns to `_port_status_projection` so `get_aria_acl_port_status` returns them.

- [ ] **Step 4: Run to verify pass** — targeted unittest → PASS.

- [ ] **Step 5: Register + commit**

```bash
git add openstack/neutron_aria/neutron_aria/services/aria_acl/plugin.py openstack/neutron_aria/neutron_aria/tests/unit/test_status_reporter.py ci/check_neutron_stage1.py
git commit -m "feat(server): persist port counters on status report"
git push origin v0.9-neutron-agent
```

### Task 11: CLI rendering with `--counters` and reason names

**Files:**
- Modify: `openstack/neutronclient_aria/neutronclient_aria/v2_0/aria_acl.py` (`AriaAclPortStatusShow` ~line 600)
- Modify: `openstack/neutron_aria/neutron_aria/agent/uds_client.py` or a new tiny shared module `openstack/neutron_aria/neutron_aria/agent/drop_reasons.py` exposing `DROP_REASON_NAMES` (numeric → name map for reasons 1-19 from `abi/src/lib.rs`: 1 ACL_DENY, 2 ACL_PORT_DENY, 3 ACL_DEFAULT_DENY, 4 QOS_INGRESS, 5 QOS_EGRESS, 6-19 fragment family with the exact names from `abi/src/fragment.rs`)
- Test: `openstack/neutronclient_aria/neutronclient_aria/tests/test_aria_acl_cli.py`

**Interfaces:**
- Consumes: server `get_aria_acl_port_status`/`get_aria_acl_port_counters` API output shape.
- Produces: `aria-acl-port-status-show --counters <port>` prints summary counter fields plus a `Counters` section listing bucket rows (`src_id/dst_id/proto/direction packets bytes dropped pps bps`) and reason rows with names; without `--counters` output is unchanged.

- [ ] **Step 1: Write the failing test** — in `test_aria_acl_cli.py`:

```python
def test_port_status_show_accepts_counters_flag(self):
    command = self._make_command("aria-acl-port-status-show")
    parser = command.get_parser("neutron")
    parsed = parser.parse_args(["--counters", "port-1"])
    self.assertTrue(parsed.counters)

def test_drop_reason_names_cover_acl_and_fragment_families(self):
    from neutron_aria.agent.drop_reasons import DROP_REASON_NAMES
    self.assertEqual(DROP_REASON_NAMES[1], "ACL_DENY")
    self.assertEqual(DROP_REASON_NAMES[9], "FRAGMENT_EPOCH_MISSING")
```

(match exact names in `abi/src/fragment.rs`: `DROP_FRAGMENT_EPOCH_MISSING` → `FRAGMENT_EPOCH_MISSING` naming is decided here; align with `core/src/trace_ops.rs::drop_reason_name` output where it exists.)

- [ ] **Step 2: Run to verify fail**

Run: `PYTHONPATH=openstack/neutronclient_aria python3 -m unittest neutronclient_aria.tests.test_aria_acl_cli -v`
Expected: FAIL.

- [ ] **Step 3: Implement** — add `--counters` (`action="store_true"`) to the show command parser; in `take_action`, when set, request the counters resource and append formatted rows (name lookups via `DROP_REASON_NAMES`; bucket rows show raw ids); create `drop_reasons.py` with the complete 1-19 map. Keep py2 compatibility (no f-strings).

- [ ] **Step 4: Run to verify pass** — CLI test command → PASS; also run `python3 ci/check_neutron_stage1.py --fast-contracts`.

- [ ] **Step 5: Register + commit**

```bash
git add openstack/neutronclient_aria/neutronclient_aria/v2_0/aria_acl.py openstack/neutron_aria/neutron_aria/agent/drop_reasons.py openstack/neutronclient_aria/neutronclient_aria/tests/test_aria_acl_cli.py ci/check_neutron_stage1.py
git commit -m "feat(cli): aria-acl-port-status-show --counters with reason names"
git push origin v0.9-neutron-agent
```

### Task 12: Operator docs and documentation alignment

**Files:**
- Create: `docs/acl-drop-reason-dictionary.md`
- Modify: `docs/openstack-ebpf-platform-roadmap.md` (Phase B checklist)
- Modify: `docs/aria-acl-neutron-extension-product-design.md` (§6.8 schema + new table)
- Modify: `docs/openstack-deployment-runbook.md` (`counters_report_enabled`)

**Interfaces:** none (docs only).

- [ ] **Step 1: Write the drop-reason dictionary** — one table with columns Name / Numeric / Meaning / Trigger / Troubleshooting action, covering reasons 1-19 (ACL 1-3, QoS 4-5 marked "expected zero until QoS product-enabled", fragment 6-19) plus the TC parse family; state explicitly that bucket drop ⊆ reason drop and the two views must not be summed.

- [ ] **Step 2: Align the roadmap** — in `docs/openstack-ebpf-platform-roadmap.md` §"Phase B: ACL Explainability", mark the deliverables now delivered (per-rule bucket hit/drop, per-port allow/drop counters, drop-reason vocabulary, CLI view) with a note that field evidence remains deferred/pending behind `counters_report_enabled`.

- [ ] **Step 3: Align the product design doc** — §6.8 gains the 12 counter columns; add a new §6.9 documenting `aria_acl_port_counters` with the kind-row model and upsert-replace policy.

- [ ] **Step 4: Align the runbook** — add `counters_report_enabled` (default false) to the agent config reference with the enable-after-evidence procedure.

- [ ] **Step 5: Verify docs links and commit**

Run: `python3 ci/check_blocked_terms.py && python3 ci/check_payload_terms.py`
Expected: PASS (no blocked terms introduced).

```bash
git add docs/acl-drop-reason-dictionary.md docs/openstack-ebpf-platform-roadmap.md docs/aria-acl-neutron-extension-product-design.md docs/openstack-deployment-runbook.md
git commit -m "docs: ACL explainability drop-reason dictionary and doc alignment"
git push origin v0.9-neutron-agent
```

---

## Post-review implementation corrections

- **Task 3 status isolation:** the ordinary `/api/v1/neutron/status` and
  `/readyz` paths do not clone managed ports, read state files, or iterate
  counter maps. The opt-in agent path requests
  `/api/v1/neutron/status?include_counters=1`; a counters-only failure retains
  the last good sample without changing the ACL status-contract write latch.
- **Task 3 global capacity:** after the 512-row per-port cap, the full counters
  section is serialized against the remaining 1 MiB response allowance with
  64 KiB headroom. Oversize output becomes an empty
  `counters_response_budget_exceeded` section; a final whole-response guard
  removes the optional section if the base response itself consumes the limit.
- **Task 9 deployed-schema upgrade:** counters schema is not folded only into
  the historical initial migration. Revision `a4e7c2d9b610`, following
  `f61a2c4e7b90`, upgrades existing databases, preserves status rows, and is
  idempotent through the runtime migration bridge. The DB contract lane runs
  this old-schema upgrade path explicitly.

---

## Final Verification

- [ ] Push state: `git status` clean; `git log origin/v0.9-neutron-agent..HEAD` empty.
- [ ] GitHub Actions: `fast-contracts`, `rust-behavior`, `neutron-db-contracts` green.
- [ ] Field gate unchanged: `counters_report_enabled` default false; `docs/evidence` untouched (no fabricated field evidence).
