# ACL Batch 6 TC-Unified ACL/CT Datapath Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make TC ingress and TC egress the authoritative ACL/conntrack hooks for Neutron-managed taps while XDP remains attached, bypasses Neutron ACL/CT, and is reserved for a future independent DDoS layer.

**Architecture:** Reuse the final byte of the 8-byte `TapConfig` as an ingress ACL hook selector: legacy zero keeps XDP ingress ACL, while Neutron publishes TC ingress ACL. Both TC directions use one bank-aware CT decision contract, skip ACL on current-bank hits, and create CT only after ACL and QoS accept. XDP returns before ACL/CT in Neutron TC mode; future DDoS logic remains a separate pre-ACL boundary and is not implemented here.

**Tech Stack:** Rust `no_std` Aya eBPF, Rust Aya userspace/agent, Python static-contract gates, Bash Kolla smoke, GitHub Actions.

## Global Constraints

- Implement on `codex/acl-batch-6-tc-ct-fast-path`, based on Batch 5 head `44cda25` and the approved TC-unified design.
- Neutron ACL ingress and egress are enforced in TC; XDP performs no ACL or CT work for Neutron TC-mode taps.
- Keep XDP attached and preserve legacy zero-valued standalone XDP ingress behavior.
- Do not implement a DDoS rules API, DDoS maps, DDoS agent domain, rate limiter, or mitigation policy in Batch 6.
- `TapConfig` remains exactly 8 bytes. `CtKey4`, `CtKey6`, `CtValue`, `PolicyKey`, and `PolicyValue` keep their current sizes and offsets.
- `stateful=false` remains `conntrack_enabled=false` and never creates or hits CT.
- Stale ACL-bank CT entries are deleted before state, flags, time, packet, or byte mutation.
- ACL and QoS drops on a miss never create CT. CT-hit counters describe CT-observed traffic even when later QoS drops.
- Routine CT contract hit/miss/disabled writes are Trace-filter gated; stale-bank events remain unconditional.
- QoS/Mirror managed domains remain rejected; do not add their Neutron payload or recovery executors.
- Preserve selector interning, priority-independent semantics, source-port exclusion, 1000-rule/2048-member limits, strict CT scrub, shadow-bank publication, and Batch 1-5 behavior.
- Record fragment-safe ACL/CT parsing as a separate backlog defect; do not fix parser fragments in this implementation.
- Never run local `cargo build`, `cargo check`, or `cargo test`. GitHub Actions is the Rust/eBPF authority.
- Do not touch the main checkout's external `78a0346` commit or dirty `README.md`.
- Mark the ACL item `likely-fixed` after code/CI gates and `fixed` only after real managed-tap evidence.

## File Map

| File | Responsibility |
| --- | --- |
| `ebpf/src/common.rs` | Hook-mode constants, normalization, unchanged 8-byte `TapConfig`, CT/pipeline internal flags. |
| `core/src/common.rs` | Userspace mirror of hook constants/layout and host-side pure contracts. |
| `ebpf/src/runtime.rs` | Per-tap ingress-hook read. |
| `core/src/ebpf_ops/runtime.rs` | Hook-preserving updates and atomic ACL gate publication. |
| `core/src/ebpf_ops/replay.rs` | Initialize fresh generic runtime to legacy XDP mode; Neutron resync republishes TC mode. |
| `agent/src/instance.rs` | Validate live TC ingress/egress program/link presence. |
| `agent/src/control_plane.rs` | Expose TC ACL readiness and atomic ACL runtime gate operations. |
| `agent/src/neutron_api.rs` | TC-mode preflight, quiesce, publish, compensation, and tests. |
| `ebpf/src/conntrack.rs` | Explicit bank-aware hit/miss outcome and cached policy-hit bit. |
| `ebpf/src/lib.rs` | XDP TC-mode bypass and live TC ingress/egress ACL/CT pipelines. |
| `agent/src/api_handlers/metrics.rs` | CT contract diagnostic labels/help. |
| `ci/check_tc_acl_datapath.py` | Function-body-aware XDP/TC/CT ordering contract. |
| `ci/check_neutron_stage1.py` | Persistent static checker and smoke syntax gate. |
| `.github/workflows/build.yml` | Exact Rust contracts and eBPF/static build gates. |
| `deploy/kolla/smoke/neutron_aria_acl_tc_datapath_smoke.sh` | Real managed-tap TC-mode evidence. |
| `docs/openstack-neutron-aria-details/12-review-bug-backlog.md` | Batch status and separate fragment finding. |
| `docs/superpowers/specs/2026-07-12-acl-batch-6-tc-unified-datapath-design.md` | Final design/evidence state. |

---

### Task 1: ABI-Compatible Ingress Hook Mode

**Files:**
- Modify: `ebpf/src/common.rs`
- Modify: `core/src/common.rs`
- Modify: `ebpf/src/runtime.rs`
- Modify: `core/src/ebpf_ops/runtime.rs`
- Modify: `core/src/ebpf_ops/replay.rs`
- Modify: `.github/workflows/build.yml`

**Interfaces:**
- Produces `ACL_INGRESS_HOOK_XDP`, `ACL_INGRESS_HOOK_TC`, and `normalize_acl_ingress_hook(u8) -> u8` in both common surfaces.
- Replaces `TapConfig.pad: [u8; 1]` with `TapConfig.acl_ingress_hook: u8` at the same offset.
- Produces `runtime::acl_ingress_hook(tap_id: u32) -> u8` in eBPF.
- Produces `update_acl_runtime_gate(runtime, conntrack_enabled, acl_enabled, acl_ingress_hook)` in core.

- [ ] **Step 1: Add host-side RED tests for layout and normalization**

In `core/src/common.rs`, extend the existing layout test and add exact mode tests:

```rust
#[test]
fn acl_ingress_hook_reuses_tap_config_padding_without_abi_change() {
    assert_eq!(core::mem::size_of::<TapConfig>(), 8);
    assert_eq!(ACL_INGRESS_HOOK_XDP, 0);
    assert_eq!(ACL_INGRESS_HOOK_TC, 1);
    assert_eq!(normalize_acl_ingress_hook(0), ACL_INGRESS_HOOK_XDP);
    assert_eq!(normalize_acl_ingress_hook(1), ACL_INGRESS_HOOK_TC);
    assert_eq!(normalize_acl_ingress_hook(255), ACL_INGRESS_HOOK_XDP);
}
```

Add tests in `core/src/ebpf_ops/runtime.rs` requiring active-bank updates and
partial feature updates to preserve `acl_ingress_hook=TC`.

- [ ] **Step 2: Persist Rust RED in GitHub**

Add this command to `.github/workflows/build.yml` beside the exact ACL tests:

```yaml
cargo +stable test --locked -p aria-core acl_ingress_hook_
```

Commit and run Build:

```bash
git add core/src/common.rs core/src/ebpf_ops/runtime.rs .github/workflows/build.yml
git commit -m "test: require ABI-stable ACL ingress hook mode"
git push -u origin codex/acl-batch-6-tc-ct-fast-path
gh workflow run build.yml --ref codex/acl-batch-6-tc-ct-fast-path
```

Expected: Rust fails only because the constants, field, and normalization are
missing. Do not add production fields before the RED run reaches these tests.

- [ ] **Step 3: Implement constants and the unchanged layout**

In both common files add:

```rust
pub const ACL_INGRESS_HOOK_XDP: u8 = 0;
pub const ACL_INGRESS_HOOK_TC: u8 = 1;

#[inline(always)]
pub fn normalize_acl_ingress_hook(value: u8) -> u8 {
    if value == ACL_INGRESS_HOOK_TC {
        ACL_INGRESS_HOOK_TC
    } else {
        ACL_INGRESS_HOOK_XDP
    }
}
```

Change only the final field of both `TapConfig` definitions:

```rust
pub acl_active_bank: u8,
pub acl_ingress_hook: u8,
```

Update every `TapConfig` initializer. Generic/legacy defaults use
`ACL_INGRESS_HOOK_XDP`; transformations of an existing config preserve and
normalize its current value.

- [ ] **Step 4: Add runtime readers and atomic gate writer**

In `ebpf/src/runtime.rs` add:

```rust
#[inline(always)]
pub fn acl_ingress_hook(tap_id: u32) -> u8 {
    if tap_id != TAP_ID_UNASSIGNED {
        if let Some(cfg) = unsafe { TAP_CONFIG_MAP.get(&tap_id) } {
            return normalize_acl_ingress_hook(cfg.acl_ingress_hook);
        }
    }
    ACL_INGRESS_HOOK_XDP
}
```

In `core/src/ebpf_ops/runtime.rs` add one read-modify-write operation:

```rust
pub fn update_acl_runtime_gate(
    runtime: TapMapRuntime<'_>,
    conntrack_enabled: bool,
    acl_enabled: bool,
    acl_ingress_hook: u8,
) -> Result<(), String>
```

It must reject `TAP_ID_UNASSIGNED`, preserve monitoring/QoS/Mirror/TCPRT and
the active bank, normalize the hook, and perform one `TAP_CONFIG_MAP.insert`.
Export it from `core/src/ebpf_ops.rs`.

- [ ] **Step 5: Keep hook mode runtime-derived and restart-safe**

Update fresh `TapConfig` initializers in replay to
`ACL_INGRESS_HOOK_XDP`. Do not add the hook to `FirewallState`, `WalEntry`,
REST, UDS, or the Neutron snapshot. The existing restart invalidation must keep
ACL disabled until Neutron full-resync calls the atomic TC-mode gate writer.

Add a Stage 1 source assertion that the restart path still invokes
`invalidate_restarted_acl_runtime` before a managed ACL can become ready.

- [ ] **Step 6: Run allowed gates, commit GREEN, require Build GREEN**

```bash
python3 ci/check_neutron_stage1.py
python3 ci/check_neutron_stage2_acl.py
git diff --check
git add ebpf/src/common.rs core/src/common.rs ebpf/src/runtime.rs \
  core/src/ebpf_ops/runtime.rs core/src/ebpf_ops/replay.rs core/src/ebpf_ops.rs \
  ci/check_neutron_stage1.py
git commit -m "feat: add ABI-compatible ACL ingress hook mode"
git push origin codex/acl-batch-6-tc-ct-fast-path
gh workflow run build.yml --ref codex/acl-batch-6-tc-ct-fast-path
```

Expected: full Build succeeds, including the BPF target and layout tests.

---

### Task 2: Conditional TC ACL Readiness And Atomic Neutron Publication

**Files:**
- Modify: `agent/src/instance.rs`
- Modify: `agent/src/control_plane.rs`
- Modify: `agent/src/neutron_api.rs`
- Modify: `.github/workflows/build.yml`

**Interfaces:**
- Consumes `update_acl_runtime_gate` and `ACL_INGRESS_HOOK_TC` from Task 1.
- Produces `FirewallInstance::require_tc_acl_links() -> Result<(), String>`.
- Produces `ControlPlane::require_tc_acl_ready(instance: &str)` and
  `ControlPlane::update_neutron_acl_runtime_gate(instance, conntrack, acl)`.
- Extends `AclRuntimeFeatureState` with `acl_ingress_hook: u8`.

- [ ] **Step 1: Write RED tests for link requirements and transitions**

Add an `agent/src/instance.rs` pure helper test around exact presence booleans:

```rust
#[test]
fn neutron_tc_acl_requires_both_direction_links() {
    assert!(tc_acl_links_complete(true, true));
    assert!(!tc_acl_links_complete(true, false));
    assert!(!tc_acl_links_complete(false, true));
    assert!(!tc_acl_links_complete(false, false));
}
```

Extend `neutron_acl_runtime_transition_is_atomic` so every quiesce/publish
state equals `ACL_INGRESS_HOOK_TC`, including stateful, stateless, empty, and
missing-payload plans.

Add Build commands:

```yaml
cargo +stable test --locked -p aria-agent neutron_tc_acl_
cargo +stable test --locked -p aria-agent neutron_acl_runtime_transition_is_atomic
```

- [ ] **Step 2: Commit and prove RED in GitHub**

```bash
git add agent/src/instance.rs agent/src/neutron_api.rs .github/workflows/build.yml
git commit -m "test: require bidirectional TC readiness for Neutron ACL"
git push origin codex/acl-batch-6-tc-ct-fast-path
gh workflow run build.yml --ref codex/acl-batch-6-tc-ct-fast-path
```

Expected: the two new contract families fail because the helper and hook field
are not wired.

- [ ] **Step 3: Implement exact TC link validation**

Add:

```rust
fn tc_acl_links_complete(ingress: bool, egress: bool) -> bool {
    ingress && egress
}

pub fn require_tc_acl_links(&self) -> Result<(), String>
```

`require_tc_acl_links` checks the interface-specific pinned link paths for
`tc_ingress` and `tc_egress`. Its error names both missing links in stable
lexical order. It does not make TC globally required for standalone runtime
metadata.

Expose a control-plane async wrapper that resolves the instance and returns
`InstanceNotReady` with the same stable reason.

- [ ] **Step 4: Add one atomic Neutron gate operation**

Add to `ControlPlane`:

```rust
pub async fn update_neutron_acl_runtime_gate(
    &self,
    instance: &str,
    conntrack_enabled: bool,
    acl_enabled: bool,
) -> Result<(), ControlPlaneError>
```

It calls `update_acl_runtime_gate(..., ACL_INGRESS_HOOK_TC)`, then updates
`state.state.conntrack_enabled` and `state.state.acl_enabled` through the
existing internal config persistence path. The hook remains runtime-derived
and is republished by Neutron full-resync after restart. This method must not
call the generic local config authority path or advertise a new Neutron
managed domain.

- [ ] **Step 5: Rewire Neutron quiesce, publish, and compensation**

Extend the pure transition:

```rust
AclRuntimeFeatureState {
    conntrack_enabled,
    acl_enabled,
    acl_ingress_hook: ACL_INGRESS_HOOK_TC,
}
```

In `reconcile_neutron_acl`:

1. translate and validate the plan;
2. if policies are non-empty, call `require_tc_acl_ready` before quiesce;
3. quiesce with `update_neutron_acl_runtime_gate(false, false)`;
4. stage/switch ACL bank and strictly flush CT as today;
5. publish desired CT/ACL with `update_neutron_acl_runtime_gate`;
6. compensate with the same operation using `false, false`.

Empty/bypass still publishes TC hook mode but does not require links because it
does not claim enforcement.

- [ ] **Step 6: Verify order contracts and GREEN**

Add source assertions to the existing Stage 1 ACL guard requiring
`require_tc_acl_ready` before the first quiesce call and requiring all Neutron
gate writes to use `update_neutron_acl_runtime_gate`.

Run:

```bash
python3 ci/check_neutron_stage1.py
python3 ci/check_neutron_stage2_acl.py
git diff --check
git add agent/src/instance.rs agent/src/control_plane.rs agent/src/neutron_api.rs \
  ci/check_neutron_stage1.py
git commit -m "fix: gate Neutron ACL on bidirectional TC readiness"
git push origin codex/acl-batch-6-tc-ct-fast-path
gh workflow run build.yml --ref codex/acl-batch-6-tc-ct-fast-path
```

Expected: Rust transition/readiness tests, Python stages, and full Build pass.

---

### Task 3: Bank-Aware CT Decision And Cached Policy-Hit Contract

**Files:**
- Modify: `ebpf/src/common.rs`
- Modify: `ebpf/src/conntrack.rs`
- Modify: `ebpf/src/lib.rs`
- Modify: `core/src/common.rs`
- Modify: `.github/workflows/build.yml`

**Interfaces:**
- Consumes the existing active ACL bank and stable CT map layouts.
- Produces `CT_FLAG_POLICY_HIT`, `FLAG_POLICY_HIT`, and explicit disabled,
  missing/expired, stale, and hit lookup outcomes.
- Produces a `MatchedPolicy` result that carries actual policy-hit state without
  changing `CtValue` layout.

- [ ] **Step 1: Add pure RED contracts**

Include the exact eBPF common source in core test scope and add:

```rust
#[test]
fn tc_ct_bank_accepts_only_current_bank_when_acl_is_active() {
    assert!(ct_acl_bank_is_current(0, 1, 0));
    assert!(ct_acl_bank_is_current(1, 1, 1));
    assert!(!ct_acl_bank_is_current(1, 1, 0));
}

#[test]
fn ct_policy_hit_uses_an_unused_flag_without_layout_change() {
    assert_eq!(CT_FLAG_POLICY_HIT, 2);
    assert_eq!(core::mem::size_of::<CtValue>(), 40);
}
```

Add exact Build selector:

```yaml
cargo +stable test --locked -p aria-core tc_ct_
```

- [ ] **Step 2: Commit RED and run GitHub Build**

```bash
git add core/src/common.rs .github/workflows/build.yml
git commit -m "test: require bank-aware TC conntrack decisions"
git push origin codex/acl-batch-6-tc-ct-fast-path
gh workflow run build.yml --ref codex/acl-batch-6-tc-ct-fast-path
```

Expected: fail on missing bank helper and policy-hit constants only.

- [ ] **Step 3: Implement explicit lookup outcomes**

Use BPF-friendly variants equivalent to:

```rust
pub enum CtMissReason {
    Disabled,
    NotFound,
    Expired,
    StaleBank,
}

pub enum CtLookupResult {
    Hit(MatchedPolicy, bool, u8), // matched, is_forward, actual state
    Miss(CtMissReason),
}
```

`ct_lookup_v4/v6` receives `validate_acl_bank` and `expected_acl_bank`.
Forward and reverse branches execute in this order:

```text
lookup entry
-> validate matched bank; delete and return StaleBank on mismatch
-> validate timeout; delete and return Expired
-> update last_seen/counters/state
-> extract matched policy and return actual state
```

Disabled and absent entries return distinct reasons. Callers do not re-read
runtime flags to guess the miss reason.

- [ ] **Step 4: Preserve actual policy-hit state**

Define bit 1 of `CtValue.flags` as `CT_FLAG_POLICY_HIT`. Add an internal
`policy_hit` field to `MatchedPolicy`; this is not a pinned-map type.

On ACL evaluation, set/clear `FLAG_POLICY_HIT` in `PipelineCtx`. On CT create,
copy it into `CtValue.flags`. On lookup, restore it. Rule stats on a CT hit run
only when `policy_hit` is true.

Keep bit 0 reply semantics unchanged.

- [ ] **Step 5: Preserve real CT state in PipelineCtx**

Update `phase_ct_v4/v6` so:

- `FLAG_CT_HIT` controls hit selection;
- `p.ct_state` receives the actual `CT_NEW` or `CT_ESTABLISHED` value;
- every miss clears `FLAG_CT_HIT`, `FLAG_IS_FORWARD`, and cached policy-hit;
- stale sets `FLAG_CT_STALE_BANK` for diagnostics.

Do not use `p.ct_state >= 2` as the fast-path condition after this task.

- [ ] **Step 6: Run allowed gates, commit, and require Build GREEN**

```bash
python3 ci/check_neutron_stage1.py
python3 ci/check_neutron_stage2_acl.py
git diff --check
git add ebpf/src/common.rs ebpf/src/conntrack.rs ebpf/src/lib.rs core/src/common.rs
git commit -m "fix: make conntrack bank and policy decisions explicit"
git push origin codex/acl-batch-6-tc-ct-fast-path
gh workflow run build.yml --ref codex/acl-batch-6-tc-ct-fast-path
```

Expected: full Build and BPF target pass with unchanged CT value size.

---

### Task 4: XDP Bypass And Unified Live TC ACL/CT Paths

**Files:**
- Create: `ci/check_tc_acl_datapath.py`
- Modify: `ebpf/src/lib.rs`
- Modify: `ci/check_neutron_stage1.py`

**Interfaces:**
- Consumes hook mode from Task 1, readiness from Task 2, and CT outcomes from Task 3.
- Produces TC-mode XDP bypass before CT/ACL.
- Produces live IPv4/IPv6 TC ingress and egress hit/miss pipelines.
- Preserves legacy XDP ingress mode and non-ACL TC post-processing.

- [ ] **Step 1: Create a function-body-aware RED checker**

Create `ci/check_tc_acl_datapath.py` with a brace-balanced function extractor.
It must inspect individual bodies and report one error per violated contract.

Required assertions:

1. `try_xdp_firewall` checks `ACL_INGRESS_HOOK_TC` before any `phase_ct_v4`,
   `phase_ct_v6`, ACL selector, policy, or CT create call.
2. `try_tc_ingress_v4/v6` select TC ACL/CT only for TC hook mode.
3. Legacy TC ingress has no CT lookup and no ACL policy call.
4. `try_tc_egress_v4/v6` always constructs a family-correct CT key and calls
   the family-correct CT phase.
5. Every hit helper rejects ACL selector loads and `phase_policy_tc`.
6. Every miss helper orders ACL drop, QoS drop, passed-flow post-processing,
   then CT create.
7. Hit branches use `FLAG_CT_HIT`, not `ct_state >= 2`.

Run:

```bash
python3 ci/check_tc_acl_datapath.py
```

Expected: nonzero with failures naming XDP and all four live TC family paths.

- [ ] **Step 2: Commit static RED evidence**

```bash
git add ci/check_tc_acl_datapath.py
git commit -m "test: require TC-unified ACL datapath"
```

- [ ] **Step 3: Add XDP TC-mode bypass**

After resolving `tap_id`, before constructing any CT key:

```rust
if runtime::acl_ingress_hook(p.tap_id) == ACL_INGRESS_HOOK_TC {
    p.action = XDP_PASS;
    return Ok(XDP_PASS);
}
```

Place a concise comment that future DDoS processing belongs before this
return and is independent of ACL/CT. Do not add an empty DDoS function, map, or
feature flag.

- [ ] **Step 4: Implement TC ingress mode selection**

For each family, construct one CT key. In TC ingress mode:

```text
phase_ct
-> FLAG_CT_HIT: TC ingress hit helper
-> miss reason: TC ingress miss helper
```

In legacy XDP mode, call a non-ACL TC ingress post-processing helper that runs
the existing QoS/flow/group/Mirror/Trace/TCPRT behavior without ACL or CT.

TC ingress hit helpers:

- account cached rule only when monitoring and policy-hit are true;
- always reapply ingress QoS when enabled;
- stop on QoS drop;
- update passed flow/group stats after QoS;
- run Mirror, Trace, and TCPRT;
- never reload ACL selectors or call policy evaluation.

TC ingress miss helpers:

- load current-bank ACL selectors and evaluate ACL when enabled;
- stop on ACL drop;
- load ordinary group IDs required by non-ACL features;
- apply ingress QoS and stop on drop;
- update passed stats/Mirror/Trace/TCPRT;
- create CT last when enabled.

- [ ] **Step 5: Implement TC egress using the same decision contract**

Rename egress helpers to explicit names:

```text
phase_ct_fastpath_tc_egress_v4
phase_ct_fastpath_tc_egress_v6
phase_ct_miss_tc_egress_v4
phase_ct_miss_tc_egress_v6
```

Both live egress family functions perform CT lookup regardless of ingress hook
mode. Hit/miss ordering matches ingress, using egress QoS and direction.

Delete superseded dead helpers after all live callers use the new names. Keep
`#[inline(never)]` boundaries where needed for verifier stack isolation; do not
collapse the whole pipeline into one large generic function.

- [ ] **Step 6: Make the checker persistent and verify local GREEN**

Invoke `ci/check_tc_acl_datapath.py` from `ci/check_neutron_stage1.py` and run:

```bash
python3 ci/check_tc_acl_datapath.py
python3 ci/check_neutron_stage1.py
python3 ci/check_neutron_stage2_acl.py
git diff --check
```

Expected: all commands exit zero.

- [ ] **Step 7: Commit, push, and require BPF Build GREEN**

```bash
git add ebpf/src/lib.rs ci/check_tc_acl_datapath.py ci/check_neutron_stage1.py
git commit -m "fix: unify Neutron ACL and conntrack in TC"
git push origin codex/acl-batch-6-tc-ct-fast-path
gh workflow run build.yml --ref codex/acl-batch-6-tc-ct-fast-path
```

Expected: nightly BPF release build, artifact discovery, Rust tests, and static
binaries all succeed.

---

### Task 5: Diagnostic Metrics, Real-Tap Evidence, And Backlog State

**Files:**
- Modify: `ebpf/src/common.rs`
- Modify: `core/src/common.rs`
- Modify: `ebpf/src/lib.rs`
- Modify: `agent/src/api_handlers/metrics.rs`
- Create: `deploy/kolla/smoke/neutron_aria_acl_tc_datapath_smoke.sh`
- Modify: `ci/check_neutron_stage1.py`
- Modify: `docs/openstack-neutron-aria-details/12-review-bug-backlog.md`
- Modify: `docs/superpowers/specs/2026-07-12-acl-batch-6-tc-unified-datapath-design.md`

**Interfaces:**
- Produces hook labels `tc_ingress` and `tc_egress` and reasons `ct_hit`,
  `ct_miss`, `ct_disabled`, and `stale_bank` over the existing CT contract map.
- Produces a Trace-filter-gated diagnostic event helper.
- Produces a real-tap smoke evidence directory and honest closure state.

- [ ] **Step 1: Add RED metric and smoke contracts**

Add agent tests requiring exact hook/reason labels. Add Stage 1 requirements
for the smoke path and these markers:

```python
for marker in (
    "ACL_INGRESS_HOOK_TC",
    "aria_ct_contract_packets_total",
    "ct_hit", "ct_miss", "ct_disabled", "stale_bank",
    "TRACE_FILTER",
    "XDP_NO_ACL_CT",
    "TC_INGRESS_HIT", "TC_EGRESS_HIT",
    "STATELESS_ZERO_CT",
    "NO_INGRESS_DOUBLE_COUNT",
    "TC_LINK_REQUIRED",
    "summary.json",
):
    require(marker in smoke_source, f"TC ACL smoke missing {marker}")
```

Run Stage 1 and expect failure because the script is absent. Commit the RED
guard and metric tests.

- [ ] **Step 2: Implement low-overhead CT contract recording**

Add TC ingress/egress hook constants and the four reason constants to both
common surfaces without changing `CtContractKey` or `CtContractValue`.

Add:

```rust
unsafe fn should_record_tc_ct_contract(p: &PipelineCtx, reason: u8) -> bool {
    reason == CT_CONTRACT_REASON_STALE_BANK || (p.flags & FLAG_TRACING) != 0
}
```

Every routine hit/miss/disabled event calls `record_event` only through this
guard. Stale-bank remains unconditional. Update Prometheus HELP text to say
these are diagnostic TC conntrack decisions and that routine reasons require a
matching Trace filter.

- [ ] **Step 3: Implement the bounded real-tap smoke**

The script begins with:

```bash
set -euo pipefail
DATAPATH_HTTP="${DATAPATH_HTTP:-http://127.0.0.1:8080}"
WORK_DIR="${WORK_DIR:-/tmp/neutron-aria-acl-tc-$(date +%Y%m%d%H%M%S)-$(hostname -s)}"
TRAFFIC_PACKETS="${TRAFFIC_PACKETS:-12}"
MIN_HIT_PACKETS="${MIN_HIT_PACKETS:-8}"
: "${EXPECTED_IFNAME:?EXPECTED_IFNAME is required}"
: "${VM_IP:?VM_IP is required}"
mkdir -p "${WORK_DIR}"
```

It must:

1. capture status, link inventory, runtime config, CT list, and metrics before;
2. enable a narrow Trace filter for the controlled flow;
3. prove runtime hook mode is TC;
4. run stateful forward/reply traffic through TC ingress and egress;
5. require first miss followed by at least `MIN_HIT_PACKETS` hits;
6. prove XDP produces no ACL/CT contract change in TC mode;
7. compare CT packet/byte deltas with generated traffic and reject ingress
   double counting;
8. publish stateless ACL and require zero CT entries/hits;
9. publish deny ACL and require no CT creation;
10. perform a bank transition and require stale/miss revalidation before hit;
11. require both interface-specific TC link pins to exist before the test
    accepts an `enforced` status; missing-link rejection remains covered by the
    exact Rust readiness matrix and is not simulated by deleting a live pin;
12. disable the Trace filter and restore created ACL objects in `trap` cleanup;
13. always write raw payloads, traffic logs, counter deltas, and `summary.json`.

The smoke must not mutate production interfaces without the explicit
`EXPECTED_IFNAME` guard and existing Kolla endpoint credentials.

- [ ] **Step 4: Register the separate fragment defect**

Add a new open P1 ACL entry describing:

```text
IPv4 non-first fragments are parsed as if payload bytes were TCP/UDP ports,
while IPv6 non-first fragments use zero ports. Port ACL and CT keys can diverge
across fragments. A separate design must define fragment allow/drop/reassembly
semantics before implementation.
```

Do not include parser changes or mark this item likely fixed.

- [ ] **Step 5: Run final allowed verification**

```bash
bash -n deploy/kolla/smoke/neutron_aria_acl_tc_datapath_smoke.sh
python3 ci/check_tc_acl_datapath.py
python3 ci/check_neutron_stage1.py
python3 ci/check_neutron_stage2_acl.py
python3 ci/check_stage2_acceptance_evidence.py
python3 ci/check_stage3_readiness.py
git diff --check
```

Expected: every command exits zero. No local Cargo command is run.

- [ ] **Step 6: Update evidence state, commit, and require final Build**

If real managed-tap execution is unavailable, record `likely-fixed`, the exact
GREEN Build URL, and `real-tap smoke pending`. Use `fixed` only when the smoke
produces a passing `summary.json` and preserved evidence directory.

```bash
git add ebpf/src/common.rs core/src/common.rs ebpf/src/lib.rs \
  agent/src/api_handlers/metrics.rs \
  deploy/kolla/smoke/neutron_aria_acl_tc_datapath_smoke.sh \
  ci/check_neutron_stage1.py \
  docs/openstack-neutron-aria-details/12-review-bug-backlog.md \
  docs/superpowers/specs/2026-07-12-acl-batch-6-tc-unified-datapath-design.md
git commit -m "test: add TC-unified ACL runtime evidence"
git push origin codex/acl-batch-6-tc-ct-fast-path
gh workflow run build.yml --ref codex/acl-batch-6-tc-ct-fast-path
```

Require final Build GREEN, then review `44cda25..HEAD` for:

- unchanged pinned-map sizes/offsets;
- XDP return before ACL/CT in TC mode;
- one authoritative CT lookup per direction;
- stale deletion before mutation;
- policy-hit preservation and no phantom wildcard rule stats;
- ACL/QoS drop before CT create;
- routine metrics Trace gating;
- bidirectional TC readiness before enforcement publication;
- honest backlog and real-tap evidence state;
- no DDoS feature expansion beyond the documented XDP boundary.

## Completion Definition

Batch 6 code is complete only when Tasks 1-5 pass their independent review and
GitHub Build gates. The ACL item is operationally complete only after the
managed-tap smoke proves TC ingress/egress stateful, stateless, deny, bank
transition, counter, XDP bypass, and missing-link behavior.
