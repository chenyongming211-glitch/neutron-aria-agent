# ACL Batch 6 TC Conntrack Fast-Path Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the code portion of `REVIEW-ACL-055` by giving all live TC ingress/egress IPv4/IPv6 paths a current-bank conntrack fast path, then deliver real-tap smoke evidence needed to move the item from `likely-fixed` to `fixed`.

**Architecture:** CT lookup validates cached ACL bank ownership before mutating an entry. A current-bank hit skips ACL and runs only the existing non-ACL hooks; miss, expiry, disabled CT, and stale bank run current-bank ACL and create CT only after every drop-capable stage accepts. Existing map/DTO/WAL layouts remain unchanged, and TC contract metrics provide hit/miss/disabled/stale evidence.

**Tech Stack:** Rust `no_std` Aya eBPF, Rust userspace/Aya map readers, Python static-contract gates, Bash Kolla smoke tests, GitHub Actions.

## Global Constraints

- Implement only `REVIEW-ACL-055` on `codex/acl-batch-6-tc-ct-fast-path`, based on Batch 5 head `44cda25`.
- `stateful=false` remains `conntrack_enabled=false`; it must never create or hit CT.
- A stale `matched_bank` is removed before CT state, time, flags, or counters mutate, then the packet is evaluated against the current active ACL bank.
- Current-bank CT hits skip ACL selector lookup and `phase_policy_tc` but retain applicable QoS, Mirror, statistics, trace, and TCP-RT hooks.
- ACL or QoS drops never create CT. Packet-time CT insert failure cannot authorize a fast path; a later packet must miss and revalidate.
- Do not change `CtKey4`, `CtKey6`, `CtValue`, `PolicyKey`, `PolicyValue`, pinned map layouts, WAL, UDS DTOs, selector semantics, priority semantics, or the 1000/2048 runtime limits.
- Do not add source-port ACL matching, ordered priority resolution, new IPv6 product behavior, QoS, or Mirror functionality.
- Preserve Batch 4 strict CT scrub/publication failure semantics and all Batch 1-5 behavior.
- GitHub Actions is the Rust/eBPF authority. Never run local `cargo build`, `cargo check`, or `cargo test`.
- The main checkout's local `78a0346` and dirty `README.md` are external state and must not be modified, reset, pushed, or cherry-picked wholesale.
- Mark `REVIEW-ACL-055` `likely-fixed` after code/CI gates; mark it `fixed` only after real managed-tap traffic evidence succeeds.

## File Map

| File | Responsibility |
| --- | --- |
| `ebpf/src/common.rs` | Pure bank validation helper, internal stale flag, CT hook/reason constants; no struct layout changes. |
| `ebpf/src/conntrack.rs` | Bank-aware forward/reverse lookup and explicit `StaleBank`. |
| `core/src/common.rs` | Userspace mirror constants and exact eBPF common-helper test inclusion. |
| `ebpf/src/lib.rs` | Four live TC CT hit/miss pipelines and CT contract event recording. |
| `agent/src/api_handlers/metrics.rs` | Prometheus hook/reason labels and mapping regressions. |
| `ci/check_tc_ct_fastpath.py` | Function-body-aware source contract, not file-wide marker checks. |
| `ci/check_neutron_stage1.py` | Runs the new contract and smoke syntax gate. |
| `.github/workflows/build.yml` | Persists the exact Rust bank/metric tests in CI. |
| `deploy/kolla/smoke/neutron_aria_acl_tc_ct_fastpath_smoke.sh` | Real-tap stateful/stateless hit/miss evidence. |
| `docs/openstack-neutron-aria-details/12-review-bug-backlog.md` | `likely-fixed`/`fixed` evidence and counts. |
| `docs/superpowers/specs/2026-07-12-acl-batch-6-tc-conntrack-fast-path-design.md` | Final status and CI/runtime evidence. |

---

### Task 1: Bank-Aware CT Lookup And Metrics Contract

**Files:**
- Modify: `ebpf/src/common.rs`
- Modify: `ebpf/src/conntrack.rs`
- Modify: `ebpf/src/lib.rs`
- Modify: `core/src/common.rs`
- Modify: `agent/src/api_handlers/metrics.rs`
- Modify: `.github/workflows/build.yml`

**Interfaces:**
- Produces `ct_acl_bank_is_current(validate_acl_bank: u8, expected_acl_bank: u8, matched_acl_bank: u8) -> bool` in the exact eBPF common source.
- Changes `ct_lookup_v4` / `ct_lookup_v6` to consume `validate_acl_bank: u8` and `expected_acl_bank: u8` after the existing packet length argument.
- Adds `CtLookupResult::StaleBank` without changing pinned map values.
- Adds `FLAG_CT_STALE_BANK`, `CT_CONTRACT_HOOK_TC_EGRESS`, `CT_CONTRACT_REASON_CT_HIT`, and `CT_CONTRACT_REASON_STALE_BANK`.

- [ ] **Step 1: Add Rust RED contracts before production code**

In `core/src/common.rs` test scope, include and execute the exact eBPF common source:

```rust
#[cfg(test)]
#[path = "../../ebpf/src/common.rs"]
mod ebpf_common_contract;

#[test]
fn neutron_acl_tc_ct_bank_contract_accepts_only_current_bank_when_required() {
    assert!(ebpf_common_contract::ct_acl_bank_is_current(0, 1, 0));
    assert!(ebpf_common_contract::ct_acl_bank_is_current(1, 3, 1));
    assert!(!ebpf_common_contract::ct_acl_bank_is_current(1, 0, 1));
}
```

Add `neutron_acl_tc_ct_metric_labels_cover_live_paths` beside the private
mapping helpers in `agent/src/api_handlers/metrics.rs`:

```rust
#[test]
fn neutron_acl_tc_ct_metric_labels_cover_live_paths() {
    assert_eq!(ct_contract_hook_to_string(
        aria_core::common::CT_CONTRACT_HOOK_TC_INGRESS), "tc_ingress");
    assert_eq!(ct_contract_hook_to_string(
        aria_core::common::CT_CONTRACT_HOOK_TC_EGRESS), "tc_egress");
    assert_eq!(ct_contract_reason_to_string(
        aria_core::common::CT_CONTRACT_REASON_CT_HIT), "ct_hit");
    assert_eq!(ct_contract_reason_to_string(
        aria_core::common::CT_CONTRACT_REASON_CT_MISS), "ct_miss");
    assert_eq!(ct_contract_reason_to_string(
        aria_core::common::CT_CONTRACT_REASON_CT_DISABLED), "ct_disabled");
    assert_eq!(ct_contract_reason_to_string(
        aria_core::common::CT_CONTRACT_REASON_STALE_BANK), "stale_bank");
}
```

Add Build commands:

```yaml
cargo +stable test --locked -p aria-core neutron_acl_tc_ct_bank_
cargo +stable test --locked -p aria-agent neutron_acl_tc_ct_metric_
```

- [ ] **Step 2: Commit and prove Rust RED in GitHub Actions**

```bash
git add core/src/common.rs agent/src/api_handlers/metrics.rs .github/workflows/build.yml
git commit -m "test: require bank-aware TC conntrack contracts"
git push -u origin codex/acl-batch-6-tc-ct-fast-path
gh workflow run build.yml --ref codex/acl-batch-6-tc-ct-fast-path
```

Expected: Build reaches Rust and fails only because the helper/constants are
missing. Do not modify production code until the run proves those failures.

- [ ] **Step 3: Implement the pure decision, constants, and labels**

Add to both common constant surfaces, with the helper defined only in the eBPF
source and the userspace values mirrored exactly:

```rust
pub const FLAG_CT_STALE_BANK: u16 = 1 << 8;
pub const CT_CONTRACT_HOOK_TC_EGRESS: u8 = 2;
pub const CT_CONTRACT_REASON_CT_HIT: u8 = 3;
pub const CT_CONTRACT_REASON_STALE_BANK: u8 = 4;

#[inline(always)]
pub fn ct_acl_bank_is_current(
    validate_acl_bank: u8,
    expected_acl_bank: u8,
    matched_acl_bank: u8,
) -> bool {
    validate_acl_bank == 0
        || normalize_acl_bank(expected_acl_bank)
            == normalize_acl_bank(matched_acl_bank)
}
```

Map the new labels and change Prometheus HELP text to “Packets handled through
the TC conntrack path”. Do not rename metrics.

- [ ] **Step 4: Implement bank-aware forward/reverse lookup**

Change both lookup signatures:

```rust
pub unsafe fn ct_lookup_v4(
    key: &CtKey4,
    now: u64,
    pkt_len: u32,
    validate_acl_bank: u8,
    expected_acl_bank: u8,
) -> CtLookupResult
```

Use the same shape for V6. Before timeout/state/counter mutation in each
forward and reverse branch:

```rust
if !ct_acl_bank_is_current(
    validate_acl_bank,
    expected_acl_bank,
    (*entry).matched_bank,
) {
    let _ = CT_TABLE_V4.remove(actual_entry_key);
    return CtLookupResult::StaleBank;
}
```

Use `key` for the forward entry and `rev` for the reverse entry. Repeat with
`CT_TABLE_V6`. Update `phase_ct_v4/v6` call sites to pass ACL-on and current
bank. On stale, set `ct_state=0`, clear hit/forward flags, and set
`FLAG_CT_STALE_BANK`. XDP continues through current-bank policy evaluation.

- [ ] **Step 5: Run allowed local gates, commit GREEN, and require Build GREEN**

```bash
python3 ci/check_neutron_stage1.py
python3 ci/check_neutron_stage2_acl.py
git diff --check
git add ebpf/src/common.rs ebpf/src/conntrack.rs ebpf/src/lib.rs \
  core/src/common.rs agent/src/api_handlers/metrics.rs .github/workflows/build.yml
git commit -m "fix: reject stale ACL banks in conntrack"
git push origin codex/acl-batch-6-tc-ct-fast-path
gh workflow run build.yml --ref codex/acl-batch-6-tc-ct-fast-path
```

Expected: bank and metric tests pass; the complete eBPF/static Build is green.

---

### Task 2: Wire All Four Live TC Paths

**Files:**
- Create: `ci/check_tc_ct_fastpath.py`
- Modify: `ebpf/src/lib.rs`
- Modify: `ci/check_neutron_stage1.py`

**Interfaces:**
- Consumes the bank-aware `phase_ct_v4/v6` behavior from Task 1.
- Produces live TC functions that select a CT hit fast path or current-bank ACL miss path.
- Produces `record_tc_ct_event(p: &PipelineCtx, hook: u8, family: u8, reason: u8)` over the unchanged `CT_CONTRACT_STATS` map.

- [ ] **Step 1: Write the function-body-aware RED checker**

Create `ci/check_tc_ct_fastpath.py` with a brace-balanced extractor:

```python
def function_body(source, signature):
    start = source.index(signature)
    open_brace = source.index("{", start)
    depth = 0
    for index in range(open_brace, len(source)):
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
            if depth == 0:
                return source[open_brace + 1:index]
    raise AssertionError("unterminated function %s" % signature)
```

For `try_tc_ingress_v4/v6` and `try_tc_egress_v4/v6`, require family-correct
`CtKey`, `phase_ct_v*`, a `ct_state >= 2` branch, hit helper, and miss helper.
Extract each hit helper and reject both `load_acl_packet_ids_` and
`phase_policy_tc`. Extract miss helpers and require ACL evaluation plus
`ct_create_v4/v6`, with the create text after both ACL and QoS drop checks.

The script exits nonzero with one error per violated function contract.

- [ ] **Step 2: Run and commit static RED evidence**

```bash
python3 ci/check_tc_ct_fastpath.py
```

Expected: fail for all four current live paths and ingress hit helpers. Commit
the checker before production edits:

```bash
git add ci/check_tc_ct_fastpath.py
git commit -m "test: require live TC conntrack fast paths"
```

- [ ] **Step 3: Implement the four live path selectors**

Use these exact helper names:

| Live path | Hit helper | Miss helper | Hook | Family |
| --- | --- | --- | --- | --- |
| `try_tc_ingress_v4` | `phase_ct_fastpath_tc_ingress_v4` | `phase_ct_miss_tc_ingress_v4` | `CT_CONTRACT_HOOK_TC_INGRESS` | `CT_CONTRACT_FAMILY_IPV4` |
| `try_tc_ingress_v6` | `phase_ct_fastpath_tc_ingress_v6` | `phase_ct_miss_tc_ingress_v6` | `CT_CONTRACT_HOOK_TC_INGRESS` | `CT_CONTRACT_FAMILY_IPV6` |
| `try_tc_egress_v4` | `phase_ct_fastpath_tc_egress_v4` | `phase_ct_miss_tc_egress_v4` | `CT_CONTRACT_HOOK_TC_EGRESS` | `CT_CONTRACT_FAMILY_IPV4` |
| `try_tc_egress_v6` | `phase_ct_fastpath_tc_egress_v6` | `phase_ct_miss_tc_egress_v6` | `CT_CONTRACT_HOOK_TC_EGRESS` | `CT_CONTRACT_FAMILY_IPV6` |

Rename the existing egress hit helpers from `phase_ct_fastpath_tc_v4/v6` to
the explicit names in the table. Add the two egress miss helpers and add the
family CT key parameter to both ingress miss helpers.

Add exact family key constructors used by both directions:

```rust
#[inline(always)]
fn tc_ct_key_v4(info: &parser::PacketInfo, tap_id: u32) -> CtKey4 {
    CtKey4 {
        tap_id,
        src_ip: info.src_ip,
        dst_ip: info.dst_ip,
        src_port: info.src_port,
        dst_port: info.dst_port,
        proto: info.proto,
        pad: [0; 3],
    }
}

#[inline(always)]
fn tc_ct_key_v6(info: &parser::PacketInfo, tap_id: u32) -> CtKey6 {
    CtKey6 {
        tap_id,
        src_ip: info.src_ip_v6,
        dst_ip: info.dst_ip_v6,
        src_port: info.src_port,
        dst_port: info.dst_port,
        proto: info.proto,
        pad: [0; 3],
    }
}
```

The IPv4 egress live path is exactly:

```rust
let ct_key = tc_ct_key_v4(info, p.tap_id);
phase_ct_v4(info, p, &ct_key);
if p.ct_state >= 2 {
    record_tc_ct_event(p, CT_CONTRACT_HOOK_TC_EGRESS, CT_CONTRACT_FAMILY_IPV4,
        CT_CONTRACT_REASON_CT_HIT);
    phase_ct_fastpath_tc_egress_v4(ctx, info, p, &ct_key);
    return p.action as i32;
}

let reason = if (p.flags & FLAG_CT_STALE_BANK) != 0 {
    CT_CONTRACT_REASON_STALE_BANK
} else if runtime::conntrack_enabled(p.tap_id) {
    CT_CONTRACT_REASON_CT_MISS
} else {
    CT_CONTRACT_REASON_CT_DISABLED
};
record_tc_ct_event(
    p,
    CT_CONTRACT_HOOK_TC_EGRESS,
    CT_CONTRACT_FAMILY_IPV4,
    reason,
);
phase_ct_miss_tc_egress_v4(ctx, info, p, &ct_key);
p.action as i32
```

The other three live paths call `tc_ct_key_v4` or `tc_ct_key_v6` according to
the table, then use the exact hit helper, miss helper, hook constant, and
family constant from that row.

Every hit helper must omit ACL selector loads and `phase_policy_tc`. Every miss
helper must load current-bank ACL IDs, call `phase_policy_tc`, return on ACL
drop, run the existing direction-specific QoS stage, return on QoS drop, and
only then call `ct_create_v4` or `ct_create_v6`. Preserve the current
direction-specific order of TCP-RT, group/flow/rule stats, QoS, Mirror, and
Trace calls.

- [ ] **Step 4: Make the checker persistent and verify GREEN**

Invoke `ci/check_tc_ct_fastpath.py` from `ci/check_neutron_stage1.py`, then run:

```bash
python3 ci/check_tc_ct_fastpath.py
python3 ci/check_neutron_stage1.py
python3 ci/check_neutron_stage2_acl.py
git diff --check
```

Expected: all commands exit zero. Commit and push:

```bash
git add ebpf/src/lib.rs ci/check_tc_ct_fastpath.py ci/check_neutron_stage1.py
git commit -m "fix: connect live TC paths to conntrack"
git push origin codex/acl-batch-6-tc-ct-fast-path
gh workflow run build.yml --ref codex/acl-batch-6-tc-ct-fast-path
```

Require the complete Build to pass, including the BPF target and static
binaries.

---

### Task 3: Real-Tap Smoke And Evidence Boundary

**Files:**
- Create: `deploy/kolla/smoke/neutron_aria_acl_tc_ct_fastpath_smoke.sh`
- Modify: `ci/check_neutron_stage1.py`
- Modify: `docs/openstack-neutron-aria-details/12-review-bug-backlog.md`
- Modify: `docs/superpowers/specs/2026-07-12-acl-batch-6-tc-conntrack-fast-path-design.md`

**Interfaces:**
- Consumes Prometheus `aria_ct_contract_packets_total` labels.
- Requires `EXPECTED_IFNAME`, `VM_IP`, `TRAFFIC_DIRECTION`, and existing Kolla/Neutron endpoint variables.
- Produces a timestamped evidence directory with before/after metrics, traffic logs, and a summary JSON.

- [ ] **Step 1: Add a RED smoke contract to Stage 1**

Before creating the script, require its path and exact safety markers in
`ci/check_neutron_stage1.py`:

```python
TC_CT_SMOKE = os.path.join(
    "deploy", "kolla", "smoke",
    "neutron_aria_acl_tc_ct_fastpath_smoke.sh",
)
for marker in (
    "aria_ct_contract_packets_total",
    "ct_hit", "ct_miss", "ct_disabled", "stale_bank",
    "MIN_HIT_PACKETS", "MAX_MISS_PACKETS",
    "summary.json", "stateful", "stateless",
):
    require(marker in _read_repo_text(TC_CT_SMOKE),
            "TC CT fast-path smoke missing %s" % marker)
```

Run `python3 ci/check_neutron_stage1.py`; expect failure because the script is
absent. Commit the guard separately:

```bash
git add ci/check_neutron_stage1.py
git commit -m "test: require TC conntrack fast-path smoke"
```

- [ ] **Step 2: Implement the bounded smoke**

The script must:

```bash
set -euo pipefail
DATAPATH_HTTP="${DATAPATH_HTTP:-http://127.0.0.1:8080}"
WORK_DIR="${WORK_DIR:-/tmp/neutron-aria-acl-tc-ct-$(date +%Y%m%d%H%M%S)-$(hostname -s)}"
MIN_HIT_PACKETS="${MIN_HIT_PACKETS:-8}"
MAX_MISS_PACKETS="${MAX_MISS_PACKETS:-2}"
TRAFFIC_PACKETS="${TRAFFIC_PACKETS:-12}"
: "${EXPECTED_IFNAME:?EXPECTED_IFNAME is required}"
: "${VM_IP:?VM_IP is required}"
mkdir -p "${WORK_DIR}"
```

Fetch `/metrics` before/after each phase, parse exact instance/hook/family/
reason counter deltas with Python, run controlled ping/guest-ping using the
existing ACL active/live-egress helpers' environment conventions, and fail
unless:

- stateful warm traffic has hit delta at least `MIN_HIT_PACKETS` and miss
  delta at most `MAX_MISS_PACKETS` per exercised hook;
- reply traffic also produces hits;
- stateless traffic produces zero hit delta and positive `ct_disabled` delta;
- deny traffic produces no new CT entry/hit;
- a bank transition never produces an unvalidated hit before miss/stale
  revalidation.

Always write `before.prom`, `after.prom`, traffic logs, policy/status payloads,
and `summary.json`; cleanup must restore created ACL objects even on failure.

- [ ] **Step 3: Verify smoke syntax and mark code state accurately**

```bash
bash -n deploy/kolla/smoke/neutron_aria_acl_tc_ct_fastpath_smoke.sh
python3 ci/check_neutron_stage1.py
python3 ci/check_neutron_stage2_acl.py
git diff --check
```

If no real managed-tap environment is available, update `REVIEW-ACL-055` to
`likely-fixed`, record the exact GREEN Build URL, and explicitly leave runtime
smoke evidence pending. Mark `fixed` only after the script succeeds and the
evidence directory is attached.

- [ ] **Step 4: Commit, push, and run final Build**

```bash
git add deploy/kolla/smoke/neutron_aria_acl_tc_ct_fastpath_smoke.sh \
  ci/check_neutron_stage1.py \
  docs/openstack-neutron-aria-details/12-review-bug-backlog.md \
  docs/superpowers/specs/2026-07-12-acl-batch-6-tc-conntrack-fast-path-design.md
git commit -m "test: add TC conntrack fast-path smoke evidence"
git push origin codex/acl-batch-6-tc-ct-fast-path
gh workflow run build.yml --ref codex/acl-batch-6-tc-ct-fast-path
```

Require the final workflow to pass. Review `44cda25..HEAD` for scope, ABI
layout stability, stale forward/reverse deletion order, hit-path ACL absence,
drop-before-create ordering, stateless guards, metric cost, and honest backlog
state before declaring the code batch complete.
