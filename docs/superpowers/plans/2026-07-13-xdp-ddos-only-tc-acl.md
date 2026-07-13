# XDP DDoS-Only And TC-Unified ACL/CT Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Remove ACL/CT from XDP in every runtime mode, make TC ingress and TC egress the only ACL/CT authorities, and make Neutron and standalone recovery fail explicitly when dual-TC readiness is unavailable.

**Architecture:** Preserve the eight-byte `TapConfig` ABI but retire `acl_ingress_hook` as a datapath selector. Normalize all userspace writes to TC, keep XDP as an ACL/CT-neutral `XDP_PASS` hook, enforce dual-TC readiness around every ACL/CT activation, and use event checks plus a ten-second safety poll to quiesce and report lost TC links without automatic ready restoration.

**Tech Stack:** Rust, Aya/Aya eBPF, Tokio, bpffs pinned maps/links, Python source-contract checkers, Bash guarded smoke tests, GitHub Actions.

## Global Constraints

- Implement only the approved design in `docs/superpowers/specs/2026-07-13-xdp-ddos-only-tc-acl-design.md`.
- Work only in `/private/tmp/aria-firewall-acl-batch5-rust-red` on `codex/acl-batch-6-tc-ct-fast-path`.
- Preserve `TapConfig` at exactly eight bytes and preserve all existing field offsets.
- Keep `ACL_INGRESS_HOOK_XDP=0` and `ACL_INGRESS_HOOK_TC=1` for mixed-version source/ABI compatibility, but never use the field for a datapath verdict or readiness decision.
- XDP must not read or update ACL, ACL bank, ACL rule statistics, or ACL conntrack state in any runtime mode.
- TC ingress and TC egress are the only ACL/CT authority paths for Neutron, tap-managed standalone, and system standalone.
- Enabling either ACL or CT requires verified TC ingress and TC egress links.
- XDP attach health is reported independently and never blocks or restores TC ACL readiness.
- The health poll interval is exactly ten seconds by default and uses `MissedTickBehavior::Skip`.
- The health poll detects, revalidates, quiesces, and deduplicates. It does not loop on automatic reattach and does not restore ready by observation alone.
- Do not implement DDoS rules, maps, APIs, rate limiting, mitigation state, or DDoS metrics.
- Do not expand Neutron managed domains beyond `attach` and `acl`; QoS/Mirror remain unchanged.
- Never run local `cargo build`, `cargo check`, or `cargo test`. GitHub Actions is the Rust/eBPF authority.
- Local validation may run Python checkers, shell syntax checks, embedded-Python extraction, and `git diff --check`.
- Preserve unrelated user changes. Do not reset or clean the worktree destructively.
- Each task uses a RED commit and GitHub Build that fails for the intended missing behavior, followed by a GREEN commit and a complete passing GitHub Build.
- After each GREEN build, dispatch a fresh specification reviewer and then a fresh code-quality reviewer before starting the next task.

---

## File And Responsibility Map

| File | Responsibility in this plan |
| --- | --- |
| `core/src/common.rs` | Host-side ABI constants, `TapConfig`, and TC normalization contract. |
| `ebpf/src/common.rs` | eBPF-side mirrored ABI constants and TC normalization contract. |
| `core/src/ebpf_ops/runtime.rs` | Strict per-tap config reads, partial updates, ACL gate writes, and active-bank writes. |
| `core/src/ebpf_ops/replay.rs` | Explicit full initialization of replayed per-tap state with TC compatibility byte. |
| `core/src/ebpf_ops/inventory.rs` | Inventory/default runtime config normalization. |
| `ebpf/src/runtime.rs` | Runtime feature flag reads; remove ingress-hook selection from the eBPF runtime API. |
| `ebpf/src/lib.rs` | XDP pass-only entry and unconditional TC ingress ACL/CT path. |
| `ci/check_tc_acl_datapath.py` | Function-body and mutation contracts for XDP neutrality and TC ordering. |
| `agent/src/instance.rs` | Link inventory, independent XDP health, dual-TC readiness, and attach outcomes. |
| `agent/src/tap_registry.rs` | Explicit standalone/Neutron attach modes and serialized managed-link lifecycle. |
| `agent/src/control_plane.rs` | Quiesced replay, activation publication, local enable guard, health state, and runtime quiesce. |
| `agent/src/neutron_api.rs` | Neutron-only attach calls, full-resync publication, and health-loss status projection. |
| `agent/src/system_manager.rs` | Quiesced system standalone startup, dual-TC hard boundary, and best-effort XDP attach. |
| `agent/src/main.rs` | Ten-second runtime health task lifecycle. |
| `api/src/lib.rs` | Additive instance readiness fields for independent ACL and XDP health. |
| `agent/src/api_handlers/system.rs` | Project per-instance ACL/XDP health into `/api/v1/instances`. |
| `.github/workflows/build.yml` | Exact Rust test filters and persistent source-contract gates. |
| `ci/check_neutron_stage1.py` | Persistent source/CI assertions for all-mode TC readiness and health wiring. |
| `ci/check_tc_acl_smoke.py` | Neutron smoke structure and mutation checks after selector retirement. |
| `deploy/kolla/smoke/neutron_aria_acl_tc_datapath_smoke.sh` | Guarded Neutron managed-tap runtime evidence. |
| `deploy/smoke/aria_standalone_acl_tc_datapath_smoke.sh` | Guarded disposable netns evidence for system and tap-managed standalone. |
| `ci/check_standalone_tc_acl_smoke.py` | Structure and negative-mutation contract for the standalone smoke. |
| `docs/openstack-neutron-aria-details/12-review-bug-backlog.md` | Evidence/status transition for `REVIEW-ACL-055`. |
| `docs/superpowers/specs/2026-07-13-xdp-ddos-only-tc-acl-design.md` | Final implementation/CI evidence state. |

## Shared Execution Protocol

Use these commands after every commit that requires GitHub Rust/eBPF evidence:

```bash
git push origin codex/acl-batch-6-tc-ct-fast-path
gh workflow run build.yml --ref codex/acl-batch-6-tc-ct-fast-path
run_id="$(gh run list --workflow build.yml --branch codex/acl-batch-6-tc-ct-fast-path --event workflow_dispatch --limit 1 --json databaseId --jq '.[0].databaseId')"
gh run watch "${run_id}" --exit-status
```

For a RED commit, the final command must exit non-zero at the named new contract while unrelated earlier gates remain green. For a GREEN commit, it must exit zero for the entire workflow. Record every run ID and failing/passing step in `.superpowers/sdd/progress.md`.

Local checks common to all tasks:

```bash
python3 ci/check_tc_acl_datapath.py --self-test
python3 ci/check_tc_acl_smoke.py --self-test
python3 ci/check_neutron_stage1.py
python3 ci/check_neutron_stage2_acl.py
python3 ci/check_stage3_readiness.py
python3 ci/check_blocked_terms.py
git diff --check
```

Run only the checks relevant to the current task until the final task. Do not add Cargo to `PATH` and do not invoke Cargo locally.

---

### Task 1: Retire The Selector In Userspace And Make Per-Tap Map Updates Strict

**Files:**

- Modify: `core/src/common.rs`
- Modify: `ebpf/src/common.rs`
- Modify: `core/src/ebpf_ops/runtime.rs`
- Modify: `core/src/ebpf_ops/replay.rs`
- Modify: `core/src/ebpf_ops/inventory.rs`
- Modify: `agent/src/control_plane.rs`
- Modify: `.github/workflows/build.yml`

**Interfaces:**

- Consumes: existing `TapConfig`, `TapMapRuntime`, and `aya::maps::MapError`.
- Produces: `normalize_acl_ingress_hook(u8) -> u8` that always returns TC; strict `required_tap_config(...) -> Result<TapConfig, String>`; explicit full initialization through `write_tap_config`; partial updates that require an existing key.

- [ ] **Step 1: Write the RED ABI and strict-read tests**

Replace the old selector assertions in `core/src/common.rs` with this contract:

```rust
#[test]
fn acl_ingress_hook_byte_is_abi_only_and_normalizes_to_tc() {
    assert_eq!(core::mem::size_of::<TapConfig>(), 8);
    assert_eq!(ACL_INGRESS_HOOK_XDP, 0);
    assert_eq!(ACL_INGRESS_HOOK_TC, 1);
    assert_eq!(normalize_acl_ingress_hook(0), ACL_INGRESS_HOOK_TC);
    assert_eq!(normalize_acl_ingress_hook(1), ACL_INGRESS_HOOK_TC);
    assert_eq!(normalize_acl_ingress_hook(255), ACL_INGRESS_HOOK_TC);
}
```

In `core/src/ebpf_ops/runtime.rs`, add pure lookup tests using an extracted `required_tap_config` helper:

```rust
#[test]
fn tap_runtime_config_rejects_missing_and_non_key_not_found_reads() {
    let missing = required_tap_config(Err(MapError::KeyNotFound), 42, "partial update")
        .unwrap_err();
    assert_eq!(
        missing,
        "partial update requires initialized TAP_CONFIG_MAP for tap_id 42"
    );

    let read_error = required_tap_config(
        Err(MapError::InvalidKeySize { size: 1, expected: 4 }),
        42,
        "active bank update",
    )
    .unwrap_err();
    assert_eq!(
        read_error,
        "active bank update read TAP_CONFIG_MAP for tap_id 42: invalid key size 1, expected 4"
    );
}

#[test]
fn tap_runtime_partial_writes_force_tc_and_preserve_unrelated_fields() {
    let current = TapConfig {
        conntrack_enabled: 1,
        monitoring_enabled: 0,
        acl_enabled: 1,
        qos_enabled: 1,
        mirror_enabled: 1,
        tcprt_enabled: 0,
        acl_active_bank: 1,
        acl_ingress_hook: ACL_INGRESS_HOOK_XDP,
    };
    let next = tap_config_with_runtime_updates(
        current,
        None,
        Some(true),
        None,
        None,
        None,
        None,
    );
    assert_eq!(next.conntrack_enabled, 1);
    assert_eq!(next.monitoring_enabled, 1);
    assert_eq!(next.acl_enabled, 1);
    assert_eq!(next.qos_enabled, 1);
    assert_eq!(next.mirror_enabled, 1);
    assert_eq!(next.tcprt_enabled, 0);
    assert_eq!(next.acl_active_bank, 1);
    assert_eq!(next.acl_ingress_hook, ACL_INGRESS_HOOK_TC);
}
```

Add this exact workflow command beside the existing `aria-core acl_ingress_hook_` filter:

```yaml
cargo +stable test --locked -p aria-core tap_runtime_config_
```

- [ ] **Step 2: Commit and prove RED in GitHub Actions**

```bash
git add core/src/common.rs core/src/ebpf_ops/runtime.rs .github/workflows/build.yml
git commit -m "test: require TC-only runtime config semantics"
```

Run the shared GitHub protocol. Expected: failure in the new normalization or strict per-tap config tests because zero still normalizes to XDP and missing keys still synthesize defaults.

- [ ] **Step 3: Implement TC normalization and strict per-tap reads**

In both `core/src/common.rs` and `ebpf/src/common.rs`, retain both constants but replace normalization with:

```rust
#[inline(always)]
pub fn normalize_acl_ingress_hook(_value: u8) -> u8 {
    ACL_INGRESS_HOOK_TC
}
```

Change `TapConfig::default`, replay config creation, and inventory config creation to write `ACL_INGRESS_HOOK_TC`.

In `core/src/ebpf_ops/runtime.rs`, use this exact classifier:

```rust
fn required_tap_config(
    lookup: Result<TapConfig, aya::maps::MapError>,
    tap_id: u32,
    operation: &str,
) -> Result<TapConfig, String> {
    match lookup {
        Ok(config) => Ok(config),
        Err(aya::maps::MapError::KeyNotFound) => Err(format!(
            "{} requires initialized TAP_CONFIG_MAP for tap_id {}",
            operation, tap_id
        )),
        Err(error) => Err(format!(
            "{} read TAP_CONFIG_MAP for tap_id {}: {}",
            operation, tap_id, error
        )),
    }
}
```

Apply it to `set_acl_active_bank`, `update_acl_runtime_gate`, and the per-tap branch of `update_runtime_config`. Change the three pure transformers to consume `TapConfig`, not `Option<TapConfig>`, and always write `ACL_INGRESS_HOOK_TC`:

```rust
fn tap_config_with_acl_bank(current: TapConfig, bank: u8) -> TapConfig {
    TapConfig {
        acl_active_bank: normalize_acl_bank(bank),
        acl_ingress_hook: ACL_INGRESS_HOOK_TC,
        ..current
    }
}
```

Use the same explicit-field pattern for runtime and gate updates because `TapConfig` is not declared with `Default`-safe struct update semantics in every mirrored context. Preserve all unrelated bytes exactly.

In `ControlPlane::prepare_managed_registration`, replace the pre-replay partial `update_runtime_config` call with an explicit full initialization:

```rust
aria_core::ebpf_ops::write_tap_config(
    TapMapRuntime::new(&pin_path, tap_id),
    aria_core::common::TapConfig {
        conntrack_enabled: state.conntrack_enabled as u8,
        monitoring_enabled: state.monitoring_enabled as u8,
        acl_enabled: state.acl_enabled as u8,
        qos_enabled: (state.qos_enabled && !state.qos_rules.is_empty()) as u8,
        mirror_enabled: (state.mirror_enabled && !state.mirror_rules.is_empty()) as u8,
        tcprt_enabled: state.tcprt_enabled as u8,
        acl_active_bank: aria_core::common::ACL_BANK_PRIMARY,
        acl_ingress_hook: aria_core::common::ACL_INGRESS_HOOK_TC,
    },
)?;
```

Keep system standalone on `FIREWALL_CONFIG`; `tap_id == TAP_ID_UNASSIGNED` remains the explicit global-config initialization path.

- [ ] **Step 4: Run allowed local source checks**

```bash
python3 ci/check_neutron_stage1.py
python3 ci/check_blocked_terms.py
git diff --check
```

Expected: all pass with Rust tests skipped locally when Cargo is unavailable.

- [ ] **Step 5: Commit and prove GREEN in GitHub Actions**

```bash
git add core/src/common.rs ebpf/src/common.rs core/src/ebpf_ops/runtime.rs \
  core/src/ebpf_ops/replay.rs core/src/ebpf_ops/inventory.rs \
  agent/src/control_plane.rs .github/workflows/build.yml
git commit -m "fix: make TC the only stored ACL ingress mode"
```

Run the shared GitHub protocol. Expected: complete Build passes, including the new exact core tests.

---

### Task 2: Make XDP ACL/CT-Neutral And TC Ingress Unconditional

**Files:**

- Modify: `ebpf/src/lib.rs`
- Modify: `ebpf/src/runtime.rs`
- Modify: `ci/check_tc_acl_datapath.py`
- Modify: `ci/check_neutron_stage1.py`

**Interfaces:**

- Consumes: existing TC CT hit/miss helpers and the Task 1 ABI constants.
- Produces: pass-only `try_xdp_firewall`; unconditional `try_tc_ingress_v4/v6`; no callable `runtime::acl_ingress_hook`; mutation checker that rejects any XDP ACL/CT call or legacy TC branch.

- [ ] **Step 1: Rewrite the source checker as the RED contract**

Make `check_xdp` reject every ACL/CT marker anywhere in `try_xdp_firewall` and require one final pass:

```python
def check_xdp(source, errors):
    body = _body_or_error(source, "try_xdp_firewall", errors, "XDP")
    if body is None:
        return
    forbidden = (
        "load_runtime_ctx_xdp(",
        "load_feature_flags_xdp(",
        "runtime::acl_ingress_hook(",
        "CtKey4 {",
        "CtKey6 {",
        "phase_ct_",
        "load_acl_packet_ids_",
        "phase_policy_xdp(",
        "conntrack::ct_create_",
        "stats::update_rule_stats",
    )
    if any(term in body for term in forbidden) or "return Ok(XDP_PASS)" not in body:
        errors.append("XDP: all runtime modes must return PASS without ACL/CT work")
```

For each ingress family, require the CT key, `phase_ct_v*`, `FLAG_CT_HIT`, hit helper, and miss helper directly in the wrapper. Reject `acl_ingress_hook` and `phase_legacy_tc_ingress_*`. Remove `check_legacy_ingress`; instead fail if either legacy helper definition is present in the source.

Replace the old “move feature flags before bypass” mutation with an injected forbidden call:

```python
def _inject_xdp_acl_read(body):
    anchor = "    p.action = XDP_PASS;\n"
    if anchor not in body:
        raise ValueError("XDP PASS mutation anchor drifted")
    return body.replace(
        anchor,
        anchor + "    load_feature_flags_xdp(p, info);\n",
        1,
    )
```

Expected checker result against current code:

```bash
python3 ci/check_tc_acl_datapath.py --self-test
```

Expected: FAIL with `XDP: all runtime modes must return PASS without ACL/CT work` and ingress legacy-branch errors.

- [ ] **Step 2: Commit the RED checker and prove the expected failure**

```bash
git add ci/check_tc_acl_datapath.py ci/check_neutron_stage1.py
git commit -m "test: require XDP-neutral ACL datapath"
```

Push and run GitHub Build. Expected: Stage 1 fails at `ci/check_tc_acl_datapath.py`; earlier core tests stay green.

- [ ] **Step 3: Replace the XDP implementation with the pass-only boundary**

Keep the existing XDP entry function and minimal parser/scratch initialization, but replace `try_xdp_firewall` with:

```rust
#[inline(never)]
unsafe fn try_xdp_firewall(
    _ctx: &XdpContext,
    _info: *const parser::PacketInfo,
    pipe: *mut PipelineCtx,
) -> Result<u32, ()> {
    let p = &mut *pipe;
    // Future independent DDoS processing belongs before this boundary.
    p.action = XDP_PASS;
    Ok(XDP_PASS)
}
```

Remove the now-unreferenced XDP ACL helpers:

- `load_feature_flags_xdp`;
- `phase_ct_fastpath_xdp_v4` and `phase_ct_fastpath_xdp_v6`;
- `phase_policy_xdp`;
- `phase_post_accept_xdp_v4` and `phase_post_accept_xdp_v6`.

Remove imports used only by those helpers. Do not remove shared TC CT, policy, trace, or statistics code.

- [ ] **Step 4: Remove the TC ingress selector and legacy branch**

Use these exact wrapper bodies:

```rust
let miss_reason = phase_ct_v4(info, p, &ct_key);
if (p.flags & FLAG_CT_HIT) != 0 {
    phase_ct_fastpath_tc_ingress_v4(ctx, info, p, &ct_key);
} else {
    phase_ct_miss_tc_ingress_v4(ctx, info, p, &ct_key, miss_reason);
}
p.action as i32
```

```rust
let miss_reason = phase_ct_v6(info, p, &ct_key);
if (p.flags & FLAG_CT_HIT) != 0 {
    phase_ct_fastpath_tc_ingress_v6(ctx, info, p, &ct_key);
} else {
    phase_ct_miss_tc_ingress_v6(ctx, info, p, &ct_key, miss_reason);
}
p.action as i32
```

Delete `phase_legacy_tc_ingress_v4` and `phase_legacy_tc_ingress_v6`. Delete `acl_ingress_hook` from `ebpf/src/runtime.rs` and remove its selector-related imports. Keep the ABI byte and constants in both common modules.

- [ ] **Step 5: Run the allowed datapath checks**

```bash
python3 ci/check_tc_acl_datapath.py --self-test
python3 ci/check_neutron_stage1.py
python3 ci/check_blocked_terms.py
git diff --check
```

Expected: all pass locally; no Cargo command is run.

- [ ] **Step 6: Commit and prove GREEN in GitHub Actions**

```bash
git add ebpf/src/lib.rs ebpf/src/runtime.rs ci/check_tc_acl_datapath.py \
  ci/check_neutron_stage1.py
git commit -m "fix: reserve XDP for future DDoS processing"
```

Run the shared GitHub protocol. Expected: complete Build passes, including nightly eBPF compilation and checker mutation self-tests.

---

### Task 3: Make Managed Tap Attach Quiesced, Mode-Aware, And Dual-TC Safe

**Files:**

- Modify: `agent/src/instance.rs`
- Modify: `agent/src/tap_registry.rs`
- Modify: `agent/src/control_plane.rs`
- Modify: `agent/src/neutron_api.rs`
- Modify: `ci/check_neutron_stage1.py`
- Modify: `.github/workflows/build.yml`

**Interfaces:**

- Consumes: Task 1 strict gate writes and Task 2 TC-only datapath.
- Produces: `ManagedAttachMode::{StandaloneRestoreAfterTcAttach, NeutronResyncRequired { acl_managed }}`; independent `RuntimePinState` live-link fields; `TcAclLinkHealth`; prepared activation action; `TapRegistry::attach_neutron`.

- [ ] **Step 1: Add RED pure transition and callsite tests**

In `agent/src/instance.rs`, add tests around a new pure health type:

```rust
#[test]
fn tc_acl_link_health_requires_both_directions_but_not_xdp() {
    assert!(TcAclLinkHealth::new(true, true, false).acl_ready());
    assert!(!TcAclLinkHealth::new(true, false, true).acl_ready());
    assert!(!TcAclLinkHealth::new(false, true, true).acl_ready());
    assert!(TcAclLinkHealth::new(true, true, true).xdp_ready());
    assert!(!TcAclLinkHealth::new(true, true, false).xdp_ready());
}
```

In `agent/src/control_plane.rs`, add pure activation tests:

```rust
#[test]
fn managed_runtime_activation_distinguishes_standalone_and_neutron() {
    assert_eq!(
        managed_runtime_activation(
            ManagedAttachMode::StandaloneRestoreAfterTcAttach,
            false,
            true,
            true,
        ),
        ManagedRuntimeActivation::RestoreStandalone { conntrack: true, acl: true }
    );
    assert_eq!(
        managed_runtime_activation(
            ManagedAttachMode::NeutronResyncRequired { acl_managed: true },
            false,
            true,
            true,
        ),
        ManagedRuntimeActivation::AwaitNeutronResync { require_tc_acl_links: true }
    );
    assert_eq!(
        managed_runtime_activation(
            ManagedAttachMode::NeutronResyncRequired { acl_managed: false },
            false,
            false,
            false,
        ),
        ManagedRuntimeActivation::AwaitNeutronResync { require_tc_acl_links: false }
    );
    assert_eq!(
        managed_runtime_activation(
            ManagedAttachMode::NeutronResyncRequired { acl_managed: true },
            true,
            true,
            true,
        ),
        ManagedRuntimeActivation::PreserveVerifiedLive
    );
}
```

Add a source contract in `ci/check_neutron_stage1.py` requiring all three Neutron callsites to use `attach_neutron`:

```python
for marker in (
    "let acl_managed = domains.iter().any(|domain| domain == \"acl\")",
    "state.registry.attach_neutron(&port.ifname, port_manages_acl(port)).await",
    ".reconcile_neutron_runtime(&committed_ifaces)",
):
    if marker not in neutron_api_source:
        raise SystemExit("ERROR: Neutron attach path missing %s" % marker)
if neutron_api_source.count(".attach_neutron(") < 2:
    raise SystemExit("ERROR: recovery and snapshot attach must use Neutron mode")
```

Add this workflow filter:

```yaml
cargo +stable test --locked -p aria-agent managed_runtime_activation_
```

- [ ] **Step 2: Commit RED and prove the missing managed-attach contract**

```bash
git add agent/src/instance.rs agent/src/control_plane.rs \
  ci/check_neutron_stage1.py .github/workflows/build.yml
git commit -m "test: require mode-aware dual-TC attach"
```

Push and run GitHub Build. Expected: Rust/source tests fail because the mode, activation enum, and `attach_neutron` path do not yet exist.

- [ ] **Step 3: Introduce link health and live-runtime identity independent of XDP**

In `agent/src/instance.rs`, define:

```rust
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct TcAclLinkHealth {
    pub ingress: bool,
    pub egress: bool,
    pub xdp: bool,
}

impl TcAclLinkHealth {
    pub fn new(ingress: bool, egress: bool, xdp: bool) -> Self {
        Self { ingress, egress, xdp }
    }

    pub fn acl_ready(self) -> bool {
        self.ingress && self.egress
    }

    pub fn xdp_ready(self) -> bool {
        self.xdp
    }

    pub fn missing_tc(self) -> Vec<&'static str> {
        let mut missing = Vec::new();
        if !self.ingress { missing.push("tc_ingress"); }
        if !self.egress { missing.push("tc_egress"); }
        missing
    }
}
```

Expose `FirewallInstance::tc_acl_link_health()` using the three existing link-pin path helpers. Make `require_tc_acl_links()` consume this health value.

Replace `RuntimePinState.preexisting_xdp_link` as the sole live-runtime signal with explicit fields:

```rust
pub struct RuntimePinState {
    pub created_shared_runtime: bool,
    pub reused_existing_runtime: bool,
    pub preexisting_live_links: bool,
    pub preexisting_xdp_link: bool,
    pub preexisting_tc_ingress_link: bool,
    pub preexisting_tc_egress_link: bool,
}
```

`preexisting_live_links` is true when any of the three link pins exists. Use it for preexisting-runtime validation and cleanup preservation so a TC-live/XDP-missing runtime is never scrubbed as dormant.

- [ ] **Step 4: Add explicit attach mode and activation action**

Define in `agent/src/tap_registry.rs`:

```rust
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum ManagedAttachMode {
    StandaloneRestoreAfterTcAttach,
    NeutronResyncRequired { acl_managed: bool },
}
```

Keep `attach(iface)` as standalone and add:

```rust
pub async fn attach(&self, iface: &str) -> Result<(), String> {
    self.attach_with_mode(iface, ManagedAttachMode::StandaloneRestoreAfterTcAttach).await
}

pub async fn attach_neutron(&self, iface: &str, acl_managed: bool) -> Result<(), String> {
    self.attach_with_mode(
        iface,
        ManagedAttachMode::NeutronResyncRequired { acl_managed },
    ).await
}
```

Move the existing body into private `attach_with_mode` and pass the mode to `prepare_managed_registration`.

Define the prepared action in `agent/src/control_plane.rs`:

```rust
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
enum ManagedRuntimeActivation {
    PreserveVerifiedLive,
    RestoreStandalone { conntrack: bool, acl: bool },
    AwaitNeutronResync { require_tc_acl_links: bool },
}

fn managed_runtime_activation(
    mode: ManagedAttachMode,
    preexisting_live_verified: bool,
    desired_conntrack: bool,
    desired_acl: bool,
) -> ManagedRuntimeActivation {
    if preexisting_live_verified {
        return ManagedRuntimeActivation::PreserveVerifiedLive;
    }
    match mode {
        ManagedAttachMode::StandaloneRestoreAfterTcAttach => {
            ManagedRuntimeActivation::RestoreStandalone {
                conntrack: desired_conntrack,
                acl: desired_acl,
            }
        }
        ManagedAttachMode::NeutronResyncRequired { acl_managed } => {
            ManagedRuntimeActivation::AwaitNeutronResync {
                require_tc_acl_links: acl_managed,
            }
        }
    }
}
```

For fresh/rebuilt runtime, replay the desired maps, then immediately publish the quiesced gate:

```rust
aria_core::ebpf_ops::update_acl_runtime_gate(
    TapMapRuntime::new(&pin_path, tap_id),
    false,
    false,
    aria_core::common::ACL_INGRESS_HOOK_TC,
)?;
```

Store the activation action in `PreparedManagedInstance`. For exact preexisting live runtime with desired ACL/CT, require both TC links during validation and use `PreserveVerifiedLive`. For fresh standalone use `RestoreStandalone`; for fresh Neutron use `AwaitNeutronResync { require_tc_acl_links: acl_managed }`. Attach-only Neutron ports do not acquire an ACL dependency.

Expose these exact prepared-state helpers so `TapRegistry` does not inspect
private fields:

```rust
impl PreparedManagedInstance {
    pub fn requires_tc_acl_links(&self) -> bool {
        match self.activation {
            ManagedRuntimeActivation::PreserveVerifiedLive => {
                self.state.conntrack_enabled || self.state.acl_enabled
            }
            ManagedRuntimeActivation::RestoreStandalone { conntrack, acl } => {
                conntrack || acl
            }
            ManagedRuntimeActivation::AwaitNeutronResync {
                require_tc_acl_links,
            } => require_tc_acl_links,
        }
    }
}

pub async fn activate_managed_registration(
    &self,
    prepared: &PreparedManagedInstance,
) -> Result<(), String> {
    let runtime = TapMapRuntime::new(&prepared.pin_path, prepared.tap_id);
    match prepared.activation {
        ManagedRuntimeActivation::PreserveVerifiedLive => Ok(()),
        ManagedRuntimeActivation::RestoreStandalone { conntrack, acl } => {
            aria_core::ebpf_ops::update_acl_runtime_gate(
                runtime,
                conntrack,
                acl,
                aria_core::common::ACL_INGRESS_HOOK_TC,
            )
        }
        ManagedRuntimeActivation::AwaitNeutronResync { .. } => {
            aria_core::ebpf_ops::update_acl_runtime_gate(
                runtime,
                false,
                false,
                aria_core::common::ACL_INGRESS_HOOK_TC,
            )
        }
    }
}
```

- [ ] **Step 5: Attach TC as the required ACL foundation and make XDP best-effort**

In `attach_links_from_pinned_runtime`, claim or attach TC ingress and egress, then return an error from the caller when the prepared desired state requires ACL/CT and `health.acl_ready()` is false.

Attempt XDP independently:

```rust
if let Err(error) = self.attach_xdp_from_pin(&xdp_prog_pin, &xdp_link_pin) {
    warn!(instance = %self.iface, error = %error, "XDP DDoS hook unavailable; TC ACL remains independent");
} else {
    attached.xdp = LinkOwnership::AttachedNow;
}
```

Do not roll back healthy TC links solely because XDP attach failed. Continue to roll back links created by the transaction when required TC readiness or activation publication fails.

After link validation, add `ControlPlane::activate_managed_registration(&prepared)`:

- `PreserveVerifiedLive`: no gate write;
- `RestoreStandalone`: write the stored desired ACL/CT flags with hook TC;
- `AwaitNeutronResync`: verify the gate remains false/false; require dual TC only when `acl_managed=true`.

Only then publish the instance into both registries.

- [ ] **Step 6: Route every Neutron attach through Neutron mode**

Replace the calls in:

- `recover_intent_port`;
- the new-port attach loop in `apply_neutron_snapshot`;
- `TapRegistry::reconcile_neutron_runtime`.

Each must call `attach_neutron` with whether the recovery/snapshot port manages ACL; local netlink auto-attach continues to call standalone `attach`. Change `reconcile_neutron_runtime` input from bare interface names to `(ifname, acl_managed)` pairs derived from committed port domains.

Remove XDP-map readiness from `update_neutron_acl_runtime_gate`. When either requested ACL or CT flag is true, call `require_tc_acl_ready` immediately before the map write. Disable/quiesce writes remain allowed even if one link is already missing.

- [ ] **Step 7: Run allowed local checks**

```bash
python3 ci/check_neutron_stage1.py
python3 ci/check_tc_acl_datapath.py --self-test
python3 ci/check_blocked_terms.py
git diff --check
```

Expected: all pass locally with Rust execution skipped.

- [ ] **Step 8: Commit and prove GREEN in GitHub Actions**

```bash
git add agent/src/instance.rs agent/src/tap_registry.rs agent/src/control_plane.rs \
  agent/src/neutron_api.rs ci/check_neutron_stage1.py .github/workflows/build.yml
git commit -m "fix: gate managed ACL on dual-TC readiness"
```

Run the shared GitHub protocol. Expected: complete Build passes, including managed activation tests and existing Neutron transaction tests.

---

### Task 4: Migrate System Standalone And Local Enablement To The Same TC Boundary

**Files:**

- Modify: `agent/src/system_manager.rs`
- Modify: `agent/src/control_plane.rs`
- Modify: `agent/src/instance.rs`
- Modify: `ci/check_neutron_stage1.py`
- Modify: `.github/workflows/build.yml`

**Interfaces:**

- Consumes: Task 3 `TcAclLinkHealth` and strict runtime gates.
- Produces: quiesced system startup; best-effort XDP; conditional dual-TC hard failure; shared `require_tc_acl_ready_locked`; local ACL/CT enable guard.

- [ ] **Step 1: Add RED system startup and local-enable transition tests**

Extract and test a pure decision:

```rust
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
enum SystemAclActivation {
    Restore { conntrack: bool, acl: bool },
    StayDisabled,
}

fn system_acl_activation(
    desired_conntrack: bool,
    desired_acl: bool,
    health: TcAclLinkHealth,
) -> Result<SystemAclActivation, String> {
    if !desired_conntrack && !desired_acl {
        return Ok(SystemAclActivation::StayDisabled);
    }
    if !health.acl_ready() {
        return Err(format!(
            "standalone ACL/CT requires pinned TC links: {}",
            health.missing_tc().join(", ")
        ));
    }
    Ok(SystemAclActivation::Restore {
        conntrack: desired_conntrack,
        acl: desired_acl,
    })
}

#[test]
fn standalone_acl_activation_requires_both_tc_links() {
    assert_eq!(
        system_acl_activation(true, true, TcAclLinkHealth::new(true, true, false)).unwrap(),
        SystemAclActivation::Restore { conntrack: true, acl: true }
    );
    assert!(system_acl_activation(true, false, TcAclLinkHealth::new(true, false, true)).is_err());
    assert!(system_acl_activation(false, true, TcAclLinkHealth::new(false, true, true)).is_err());
    assert_eq!(
        system_acl_activation(false, false, TcAclLinkHealth::new(false, false, false)).unwrap(),
        SystemAclActivation::StayDisabled
    );
}
```

Add a `ControlPlane` pure guard test:

```rust
#[test]
fn local_config_enable_requires_dual_tc_but_disable_does_not() {
    assert!(config_update_requires_tc(Some(true), None));
    assert!(config_update_requires_tc(None, Some(true)));
    assert!(!config_update_requires_tc(Some(false), Some(false)));
    assert!(!config_update_requires_tc(None, None));
}

fn config_update_requires_tc(conntrack: Option<bool>, acl: Option<bool>) -> bool {
    conntrack == Some(true) || acl == Some(true)
}
```

Add the workflow filter:

```yaml
cargo +stable test --locked -p aria-agent standalone_acl_activation_
```

- [ ] **Step 2: Commit RED and prove the standalone gap**

```bash
git add agent/src/system_manager.rs agent/src/control_plane.rs \
  .github/workflows/build.yml
git commit -m "test: require standalone dual-TC activation"
```

Push and run GitHub Build. Expected: new tests fail because TC attach failures are still warnings and local enablement checks only pinned maps.

- [ ] **Step 3: Quiesce system standalone before attaching programs**

Load the persisted desired state once before replay:

```rust
let desired = aria_core::wal::load_with_wal(state_path);
let desired_conntrack = desired.conntrack_enabled;
let desired_acl = desired.acl_enabled;
```

After `replay_state` and before any program attach, write only the live global gate off while preserving unrelated flags:

```rust
aria_core::ebpf_ops::update_firewall_config(
    TapMapRuntime::new(pin_path, aria_core::common::TAP_ID_UNASSIGNED),
    Some(false),
    None,
    Some(false),
    None,
    None,
    None,
    None,
)?;
```

This runtime write must not alter the persisted desired `FirewallState` or WAL.

- [ ] **Step 4: Make XDP best-effort and dual-TC conditional-hard**

Change XDP attach handling to warn and continue:

```rust
let xdp_ready = match attach_xdp_program(&mut bpf, iface, pin_path) {
    Ok(()) => true,
    Err(error) => {
        warn!(iface = %iface, error = %error, "XDP DDoS hook unavailable; continuing with TC ACL");
        false
    }
};
```

Capture TC results rather than warning and discarding them. Build `TcAclLinkHealth` from the actual outcomes. If `desired_conntrack || desired_acl`, call `system_acl_activation`; on error, run `cleanup_failed_start` and return the stable error. If both are disabled, retain the existing warnings for unrelated optional TC consumers.

Make system `pin_runtime_programs` require `tc_ingress` and `tc_egress` when ACL/CT is desired, while treating `xdp_firewall` pin failure as the independent XDP degraded state. Do not describe XDP as ACL readiness.

Call `register_system_instance` only after the TC decision succeeds. Its existing runtime config publication restores the persisted desired state after both links are live.

- [ ] **Step 5: Enforce dual-TC readiness on later local enable requests**

Rename `check_xdp_ready` to `check_runtime_maps_ready`; it checks map existence only and must not imply an XDP link dependency.

Add a lock-safe helper that uses `InstanceState` already held by the caller:

```rust
fn require_tc_acl_ready_locked(
    instance: &str,
    state: &InstanceState,
    trace_map_mode: TraceMapMode,
) -> Result<(), ControlPlaneError> {
    let iface = Self::runtime_iface_name(instance, state)?;
    FirewallInstance::new(
        &iface,
        state.pin_path.clone().into(),
        state.state_path.clone().into(),
        instance != "system",
        trace_map_mode,
    )
    .require_tc_acl_links()
    .map_err(ControlPlaneError::InstanceNotReady)
}
```

In `update_config`, before a requested `acl=true` or `conntrack=true` map write, call this helper. Disable operations do not require links. In `replace_owned_acl`, require dual TC immediately before an enforcement-affecting bank publication when the desired ACL or CT state is enabled; rules may still be staged while both are disabled.

- [ ] **Step 6: Run allowed local checks**

```bash
python3 ci/check_neutron_stage1.py
python3 ci/check_blocked_terms.py
git diff --check
```

Expected: pass with Rust tests skipped locally.

- [ ] **Step 7: Commit and prove GREEN in GitHub Actions**

```bash
git add agent/src/system_manager.rs agent/src/control_plane.rs agent/src/instance.rs \
  ci/check_neutron_stage1.py .github/workflows/build.yml
git commit -m "fix: move standalone ACL activation to TC"
```

Run the shared GitHub protocol. Expected: complete Build passes, including system activation and local config guard tests.

---

### Task 5: Add Event-Driven Plus Ten-Second TC Health Detection And Status

**Files:**

- Modify: `agent/src/control_plane.rs`
- Modify: `agent/src/tap_registry.rs`
- Modify: `agent/src/neutron_api.rs`
- Modify: `agent/src/main.rs`
- Modify: `api/src/lib.rs`
- Modify: `agent/src/api_handlers/system.rs`
- Modify: `ci/check_neutron_stage1.py`
- Modify: `.github/workflows/build.yml`

**Interfaces:**

- Consumes: Task 3 link health and Task 4 lock-safe readiness helper.
- Produces: `InstanceRuntimeHealthSnapshot`; `TcAclHealthChange`; `ControlPlane::reconcile_tc_acl_health`; additive API fields; Neutron degraded status transition; default ten-second health task.

- [ ] **Step 1: Add RED health transition and API tests**

Add a pure transition state in `agent/src/control_plane.rs`:

```rust
#[derive(Clone, Debug, Eq, PartialEq)]
struct RuntimeHealthState {
    acl_ready: bool,
    xdp_ready: bool,
    acl_error: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RuntimeHealthTransition {
    next: RuntimeHealthState,
    changed: bool,
    quiesce_acl_ct: bool,
}

fn missing_tc_reason(health: TcAclLinkHealth) -> Option<&'static str> {
    match (health.ingress, health.egress) {
        (false, false) => Some("missing_tc_ingress_and_egress"),
        (false, true) => Some("missing_tc_ingress"),
        (true, false) => Some("missing_tc_egress"),
        (true, true) => None,
    }
}

fn apply_tc_health_observation(
    current: RuntimeHealthState,
    observed: TcAclLinkHealth,
) -> RuntimeHealthTransition {
    let mut next = current.clone();
    next.xdp_ready = observed.xdp_ready();
    let quiesce_acl_ct = if let Some(reason) = missing_tc_reason(observed) {
        next.acl_ready = false;
        next.acl_error = Some(reason.to_string());
        current.acl_ready
    } else if !current.acl_ready {
        next.acl_ready = false;
        next.acl_error = Some("recovery_required".to_string());
        false
    } else {
        next.acl_ready = true;
        next.acl_error = None;
        false
    };
    RuntimeHealthTransition {
        changed: next != current,
        next,
        quiesce_acl_ct,
    }
}

#[test]
fn tc_health_loss_is_deduplicated_and_never_auto_restores_ready() {
    let ready = RuntimeHealthState {
        acl_ready: true,
        xdp_ready: true,
        acl_error: None,
    };
    let lost = apply_tc_health_observation(
        ready,
        TcAclLinkHealth::new(true, false, true),
    );
    assert!(lost.changed);
    assert!(!lost.next.acl_ready);
    assert_eq!(lost.next.acl_error.as_deref(), Some("missing_tc_egress"));

    let repeated = apply_tc_health_observation(lost.next.clone(), TcAclLinkHealth::new(true, false, true));
    assert!(!repeated.changed);

    let links_returned = apply_tc_health_observation(lost.next, TcAclLinkHealth::new(true, true, true));
    assert!(!links_returned.next.acl_ready);
    assert_eq!(links_returned.next.acl_error.as_deref(), Some("recovery_required"));
}
```

In `api/src/lib.rs`, add a serialization test proving additive fields:

```rust
#[test]
fn instance_info_reports_acl_and_xdp_health_independently() {
    let value = serde_json::to_value(InstanceInfo {
        name: "tap0".to_string(),
        active: true,
        acl_ready: true,
        xdp_ready: false,
        readiness_reason: Some("xdp_ddos_hook_unavailable".to_string()),
    }).unwrap();
    assert_eq!(value["acl_ready"], true);
    assert_eq!(value["xdp_ready"], false);
}
```

Add workflow commands:

```yaml
cargo +stable test --locked -p aria-agent tc_health_loss_
cargo +stable test --locked -p aria-api instance_info_reports_
```

- [ ] **Step 2: Add RED source contracts for the exact interval and task lifecycle**

In `ci/check_neutron_stage1.py`, require:

```python
for term in (
    "const TC_ACL_HEALTH_INTERVAL_SECS: u64 = 10;",
    "MissedTickBehavior::Skip",
    "reconcile_tc_acl_health().await",
    "tc_acl_health_task.abort()",
):
    if term not in main_source:
        raise SystemExit("ERROR: TC ACL health loop missing %s" % term)
```

Also require Neutron health projection markers:

```python
for term in (
    "tc_acl_link_lost",
    "runtime_degraded",
    "effective_action",
    "bypass",
):
    if term not in neutron_api_source:
        raise SystemExit("ERROR: Neutron TC health status missing %s" % term)
```

- [ ] **Step 3: Commit RED and prove the health/status gap**

```bash
git add agent/src/control_plane.rs api/src/lib.rs ci/check_neutron_stage1.py \
  .github/workflows/build.yml
git commit -m "test: require TC link health detection"
```

Push and run GitHub Build. Expected: new Rust/source contracts fail because no health state or ten-second task exists.

- [ ] **Step 4: Store runtime health separately from desired state**

Add `runtime_health: RuntimeHealthState` to `InstanceState`. Initialize it during managed/system registration from the actual attached-link outcome. Do not store runtime health in `FirewallState` or WAL as desired configuration.

Expose:

```rust
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InstanceRuntimeHealthSnapshot {
    pub name: String,
    pub active: bool,
    pub acl_ready: bool,
    pub xdp_ready: bool,
    pub readiness_reason: Option<String>,
}

pub async fn list_instance_runtime_health(&self) -> Vec<InstanceRuntimeHealthSnapshot>;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TcAclHealthChange {
    pub instance: String,
    pub acl_ready: bool,
    pub xdp_ready: bool,
    pub reason: Option<String>,
    pub quiesced: bool,
}
```

`active` means the instance remains registered. `acl_ready` is dual-TC readiness plus a successfully published gate when ACL/CT is desired. `xdp_ready` is only XDP link health.

- [ ] **Step 5: Implement the deduplicated detector and quiesce transition**

Implement `ControlPlane::reconcile_tc_acl_health` as follows:

1. Snapshot registered instance handles without holding the global instances lock.
2. Lock one `InstanceState` for write.
3. Skip dual-TC enforcement checks when persisted desired ACL and CT are both false, but still refresh XDP health.
4. Re-read link health while the instance lock is held.
5. On first confirmed missing TC link, write `conntrack=false, acl=false, hook=TC` to `TAP_CONFIG_MAP`, or update the two global `FIREWALL_CONFIG` flags for `system`.
6. Do not mutate `state.state.conntrack_enabled`, `state.state.acl_enabled`, or WAL desired state.
7. Store the stable missing-link reason and return one `TcAclHealthChange`.
8. Suppress repeated identical changes and warnings.
9. When links reappear, set the reason to `recovery_required` but keep `acl_ready=false`; only normal attach/reconcile/full-resync calls `mark_tc_acl_runtime_ready`.
10. XDP loss updates only `xdp_ready` and `readiness_reason`; it never writes ACL/CT gates.

Map-read or gate-write failure returns a health change with `acl_quiesce_failed:<error>` and keeps the instance non-ready.

Define the only ready-restoration entry point as:

```rust
pub async fn mark_tc_acl_runtime_ready(
    &self,
    instance: &str,
    xdp_ready: bool,
) -> Result<(), ControlPlaneError> {
    let inst = self.get_instance(instance).await?;
    let mut state = inst.write().await;
    Self::require_tc_acl_ready_locked(instance, &state, self.trace_map_mode())?;
    state.runtime_health = RuntimeHealthState {
        acl_ready: true,
        xdp_ready,
        acl_error: None,
    };
    Ok(())
}
```

Call it only after standalone activation publication or a successful Neutron
full-resync ACL publication. A poll is never a caller.

- [ ] **Step 6: Add the exact ten-second task and event checks**

In `agent/src/main.rs`:

```rust
const TC_ACL_HEALTH_INTERVAL_SECS: u64 = 10;

let tc_health_cp = control_plane.clone();
let tc_acl_health_task = tokio::spawn(async move {
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(
        TC_ACL_HEALTH_INTERVAL_SECS,
    ));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    interval.tick().await;
    loop {
        interval.tick().await;
        tc_health_cp.reconcile_tc_acl_health().await;
    }
});
```

Abort it during shutdown beside the compact and SSL reconcile tasks.

Keep event-driven validation in managed attach, system start, local enable, Neutron publish, and existing netlink/OVS reconciliation paths. Do not add a second automatic reattach loop.

- [ ] **Step 7: Project health to standalone and Neutron status**

Add these fields to `InstanceInfo` with serde defaults for additive compatibility:

```rust
#[serde(default)]
pub acl_ready: bool,
#[serde(default)]
pub xdp_ready: bool,
#[serde(default)]
pub readiness_reason: Option<String>,
```

Change `/api/v1/instances` to use `list_instance_runtime_health`.

In `NeutronApiState`, add a ten-second status projection task started by `build_router`. It reads the control-plane snapshot for committed ports. Only a new `acl_ready=false` state whose reason starts with `missing_tc_` or `acl_quiesce_failed:` is projected as link loss; `recovery_required` and the existing restart/full-resync-required state are not overwritten. For a confirmed link loss it holds `apply_lock`, marks `attach` or `acl` degraded with reason `tc_acl_link_lost`, sets effective action to `bypass`, changes authority to `runtime_degraded`, and appends a WAL snapshot commit. It does not restore ready when links merely reappear; full resync remains required.

Avoid duplicate WAL writes by comparing the existing domain reason/status before committing.

- [ ] **Step 8: Run allowed local checks**

```bash
python3 ci/check_neutron_stage1.py
python3 ci/check_neutron_stage2_acl.py
python3 ci/check_stage3_readiness.py
python3 ci/check_blocked_terms.py
git diff --check
```

Expected: all pass locally with Rust skipped.

- [ ] **Step 9: Commit and prove GREEN in GitHub Actions**

```bash
git add agent/src/control_plane.rs agent/src/tap_registry.rs agent/src/neutron_api.rs \
  agent/src/main.rs api/src/lib.rs agent/src/api_handlers/system.rs \
  ci/check_neutron_stage1.py .github/workflows/build.yml
git commit -m "feat: detect and report TC ACL link loss"
```

Run the shared GitHub protocol. Expected: complete Build passes, including the ten-second lifecycle source contract and health/API tests.

---

### Task 6: Add Standalone Runtime Evidence, Update Neutron Smoke, And Close Documentation

**Files:**

- Create: `deploy/smoke/aria_standalone_acl_tc_datapath_smoke.sh`
- Create: `ci/check_standalone_tc_acl_smoke.py`
- Modify: `deploy/kolla/smoke/neutron_aria_acl_tc_datapath_smoke.sh`
- Modify: `ci/check_tc_acl_smoke.py`
- Modify: `ci/check_neutron_stage1.py`
- Modify: `.github/workflows/build.yml`
- Modify: `docs/openstack-neutron-aria-details/12-review-bug-backlog.md`
- Modify: `docs/superpowers/specs/2026-07-13-xdp-ddos-only-tc-acl-design.md`
- Modify: `.superpowers/sdd/progress.md`

**Interfaces:**

- Consumes: completed all-mode TC datapath, readiness, and health API.
- Produces: guarded `system` and `tap` standalone evidence; selector-independent Neutron smoke; persistent smoke mutation gates; accurate backlog/evidence state.

- [ ] **Step 1: Write the RED standalone smoke checker first**

Create `ci/check_standalone_tc_acl_smoke.py` with the same brace-aware shell-function extraction and mutation style as `ci/check_tc_acl_smoke.py`. Require these functions and markers:

```python
REQUIRED_FUNCTIONS = (
    "cleanup",
    "write_summary",
    "create_netns_fixture",
    "start_agent",
    "start_system_mode",
    "start_tap_mode",
    "capture_links",
    "capture_acl_counters",
    "run_allowed_flow",
    "run_denied_flow",
    "assert_xdp_neutral",
    "assert_dual_tc_ready",
    "assert_missing_tc_rejected",
    "assert_health_poll_degrades",
)

REQUIRED_MARKERS = (
    'MODE="${MODE:-system}"',
    ': "${ARIA_AGENT_BIN:?ARIA_AGENT_BIN is required}"',
    ': "${EBPF_OBJECT:?EBPF_OBJECT is required}"',
    'TC_HEALTH_WAIT_SECS="${TC_HEALTH_WAIT_SECS:-12}"',
    "ip netns add",
    "tc_ingress_link",
    "tc_egress_link",
    '"acl_ready"',
    '"xdp_ready"',
    "summary.json",
    "trap cleanup EXIT",
)
```

Mutation self-tests must reject removal of:

- either TC link assertion;
- the before/after XDP-neutral counter comparison;
- the missing-TC enable rejection;
- the 12-second health-poll wait and degraded assertion;
- cleanup rollback verification;
- final `summary.json` write.

Invoke the new checker from `ci/check_neutron_stage1.py` and add the script path to its shell syntax list.

Run:

```bash
python3 ci/check_standalone_tc_acl_smoke.py --self-test
```

Expected: FAIL because the smoke script does not exist.

- [ ] **Step 2: Commit RED and prove the missing smoke gate**

```bash
git add ci/check_standalone_tc_acl_smoke.py ci/check_neutron_stage1.py \
  .github/workflows/build.yml
git commit -m "test: require standalone TC ACL runtime evidence"
```

Push and run GitHub Build. Expected: Stage 1 fails at the missing standalone smoke contract.

- [ ] **Step 3: Implement the guarded disposable-netns standalone smoke**

Create `deploy/smoke/aria_standalone_acl_tc_datapath_smoke.sh` with hard guards before the first mutation:

```bash
#!/usr/bin/env bash
set -euo pipefail

MODE="${MODE:-system}"
: "${ARIA_AGENT_BIN:?ARIA_AGENT_BIN is required}"
: "${EBPF_OBJECT:?EBPF_OBJECT is required}"
case "${MODE}" in system|tap) ;; *) echo "ERROR: MODE must be system or tap" >&2; exit 2 ;; esac
[ "${EUID}" -eq 0 ] || { echo "ERROR: root is required" >&2; exit 2; }

RUN_ID="${RUN_ID:-standalone-tc-acl-$(date +%Y%m%d%H%M%S)}"
WORK_DIR="${WORK_DIR:-/tmp/${RUN_ID}}"
NETNS="${NETNS:-aria-tc-${RUN_ID}}"
TC_HEALTH_WAIT_SECS="${TC_HEALTH_WAIT_SECS:-12}"
RESULT="fail"
cleanup_errors=()
trap cleanup EXIT
mkdir -p "${WORK_DIR}"
```

The script must:

1. Create a unique network namespace and veth pair; never use a host production interface.
2. Generate a temporary agent config, pin root, state root, HTTP port, and interface pattern scoped to the fixture.
3. Launch the supplied agent binary with the supplied eBPF artifact.
4. For `MODE=system`, call `/api/v1/system/start`; for `MODE=tap`, use the fixture name that matches auto-attach.
5. Require both pinned TC links and `acl_ready=true` from `/api/v1/instances`.
6. Permit a controlled allowed IPv4 flow and reject a controlled denied flow in both directions.
7. Capture ACL/CT/rule counters before and after and prove XDP contributes zero ACL/CT counter changes.
8. In tap mode, save the eight-byte `TapConfig`, mutate only byte 7 to legacy
   zero with `bpftool`, run another four-packet controlled flow, and require the
   same exact TC-only rule/CT deltas. Then perform a normal config update and
   require userspace to normalize byte 7 back to `1`. This proves old zero does
   not suppress TC or reactivate XDP. System mode has no per-tap selector and
   proves XDP neutrality through the same exact counter deltas.
9. Remove one copied fixture TC link pin only after recording how it will be restored; wait `TC_HEALTH_WAIT_SECS`; require `acl_ready=false`, a stable missing-link reason, and the surviving runtime gate to be ACL/CT off.
10. Attempt local `acl=true` and require HTTP 503/explicit not-ready rather than XDP fallback.
11. Restore only through stop/start or detach/attach, then verify cleanup removed the namespace, processes, temporary pins, and qdiscs.
12. Write `summary.json` only after cleanup verification and include `mode`, `dual_tc_ready`, `xdp_neutral`, `missing_tc_rejected`, `health_poll_degraded`, `cleanup_errors`, and final `result`.

Use these concrete fixture and policy functions rather than host interfaces or
implicit defaults:

```bash
HTTP_ADDR="${HTTP_ADDR:-127.0.0.1:18080}"
HTTP="http://${HTTP_ADDR}"
HOST_IF="ariah-${RUN_ID:0:8}"
PEER_IF="ariap-${RUN_ID:0:8}"
HOST_IP="10.203.0.1"
PEER_IP="10.203.0.2"
PIN_ROOT="${WORK_DIR}/bpffs"
STATE_ROOT="${WORK_DIR}/state"
CONFIG_FILE="${WORK_DIR}/agent.toml"
AGENT_PID=""

create_netns_fixture() {
    ip netns add "${NETNS}"
    ip link add "${HOST_IF}" type veth peer name "${PEER_IF}"
    ip link set "${PEER_IF}" netns "${NETNS}"
    ip addr add "${HOST_IP}/30" dev "${HOST_IF}"
    ip link set "${HOST_IF}" up
    ip netns exec "${NETNS}" ip addr add "${PEER_IP}/30" dev "${PEER_IF}"
    ip netns exec "${NETNS}" ip link set lo up
    ip netns exec "${NETNS}" ip link set "${PEER_IF}" up
}

start_agent() {
    local auto_attach=false
    [ "${MODE}" = tap ] && auto_attach=true
    mkdir -p "${PIN_ROOT}" "${STATE_ROOT}"
    mountpoint -q "${PIN_ROOT}" || mount -t bpf bpf "${PIN_ROOT}"
    cat >"${CONFIG_FILE}" <<EOF
mode = "standalone"
auto_attach = ${auto_attach}
ebpf_path = "${EBPF_OBJECT}"
pin_path = "${PIN_ROOT}"
state_path = "${STATE_ROOT}"
iface_pattern = "^${HOST_IF}$"
listen_addr = "${HTTP_ADDR}"
trace_backend = "legacy-map"
log_file_path = "${WORK_DIR}/agent.log"
EOF
    "${ARIA_AGENT_BIN}" --config "${CONFIG_FILE}" >"${WORK_DIR}/agent.stdout" 2>&1 &
    AGENT_PID=$!
    for _ in $(seq 1 100); do
        curl -fsS "${HTTP}/api/v1/health" >/dev/null && return 0
        kill -0 "${AGENT_PID}" 2>/dev/null || return 1
        sleep 0.1
    done
    return 1
}

start_system_mode() {
    curl --fail-with-body -sS -H 'Content-Type: application/json' \
        -d "{\"iface\":\"${HOST_IF}\",\"max_port_policies\":16384}" \
        "${HTTP}/api/v1/system/start" >"${WORK_DIR}/system-start.json"
    INSTANCE="system"
}

start_tap_mode() {
    INSTANCE="${HOST_IF}"
    for _ in $(seq 1 100); do
        curl -fsS "${HTTP}/api/v1/instances" | \
            python3 -c 'import json,sys; n=sys.argv[1]; p=json.load(sys.stdin); raise SystemExit(0 if any(i["name"]==n for i in p["instances"]) else 1)' \
            "${INSTANCE}" && return 0
        sleep 0.1
    done
    return 1
}

install_fixture_policy() {
    curl --fail-with-body -sS -H 'Content-Type: application/json' \
        -d "{\"name\":\"peer\",\"cidr\":\"${PEER_IP}/32\"}" \
        "${HTTP}/api/v1/${INSTANCE}/groups" >/dev/null
    curl --fail-with-body -sS -H 'Content-Type: application/json' \
        -d "{\"name\":\"host\",\"cidr\":\"${HOST_IP}/32\"}" \
        "${HTTP}/api/v1/${INSTANCE}/groups" >/dev/null
    curl --fail-with-body -sS -H 'Content-Type: application/json' \
        -d '{"src_group":"peer","dst_group":"host","proto":"icmp","action":"allow","direction":"ingress","ports":null}' \
        "${HTTP}/api/v1/${INSTANCE}/policies" >/dev/null
    curl --fail-with-body -sS -H 'Content-Type: application/json' \
        -d '{"src_group":"host","dst_group":"peer","proto":"icmp","action":"allow","direction":"egress","ports":null}' \
        "${HTTP}/api/v1/${INSTANCE}/policies" >/dev/null
    curl --fail-with-body -sS -H 'Content-Type: application/json' -X PUT \
        -d '{"conntrack":true,"monitoring":true,"acl":true,"qos":null,"mirror":null,"tcprt":null,"ssl":null}' \
        "${HTTP}/api/v1/${INSTANCE}/config" >/dev/null
}

assert_dual_tc_ready() {
    local ingress egress
    if [ "${MODE}" = system ]; then
        ingress="${PIN_ROOT}/system/tc_ingress_link"
        egress="${PIN_ROOT}/system/tc_egress_link"
    else
        ingress="${PIN_ROOT}/global-v2/${HOST_IF}_tc_ingress_link"
        egress="${PIN_ROOT}/global-v2/${HOST_IF}_tc_egress_link"
    fi
    [ -e "${ingress}" ] && [ -e "${egress}" ]
    curl -fsS "${HTTP}/api/v1/instances" | python3 -c '
import json,sys
name=sys.argv[1]
item=next(i for i in json.load(sys.stdin)["instances"] if i["name"]==name)
assert item["acl_ready"] is True,item
' "${INSTANCE}"
}

run_allowed_flow() {
    ip netns exec "${NETNS}" ping -c 4 -W 1 "${HOST_IP}" \
        >"${WORK_DIR}/allowed-flow.log"
}

capture_acl_counters() {
    local label="$1"
    curl -fsS "${HTTP}/api/v1/${INSTANCE}/config" \
        >"${WORK_DIR}/${label}-config.json"
    curl -fsS "${HTTP}/api/v1/${INSTANCE}/conntrack" \
        >"${WORK_DIR}/${label}-conntrack.json"
    curl -fsS "${HTTP}/api/v1/${INSTANCE}/stats/rules" \
        >"${WORK_DIR}/${label}-rules.json"
    curl -fsS "${HTTP}/metrics" >"${WORK_DIR}/${label}-metrics.prom"
}

assert_xdp_neutral() {
    local before="$1" after="$2" packets="$3"
    python3 - "${WORK_DIR}/${before}-rules.json" \
        "${WORK_DIR}/${after}-rules.json" "${packets}" <<'PY'
import json,sys
before=json.load(open(sys.argv[1],encoding="utf-8"))["rules"]
after=json.load(open(sys.argv[2],encoding="utf-8"))["rules"]
packets=int(sys.argv[3])
def keyed(rows):
    return {(r["src_group"],r["dst_group"],r["direction"]):int(r["packets"]) for r in rows}
b=keyed(before); a=keyed(after)
ing=("peer","host","ingress")
out=("host","peer","egress")
assert a.get(ing,0)-b.get(ing,0)==packets,(a,b,"ingress")
assert a.get(out,0)-b.get(out,0)==packets,(a,b,"egress")
assert (a.get(ing,0)-b.get(ing,0))+(a.get(out,0)-b.get(out,0))==2*packets
PY
}

exercise_legacy_zero_compatibility() {
    [ "${MODE}" = tap ] || return 0
    local map="${PIN_ROOT}/global-v2/TAP_CONFIG_MAP" ifindex ifindex_key tap_id key value
    ifindex="$(cat "/sys/class/net/${HOST_IF}/ifindex")"
    ifindex_key="$(python3 -c 'import struct,sys; print(" ".join("%02x"%b for b in struct.pack("=I",int(sys.argv[1]))))' "${ifindex}")"
    tap_id="$(bpftool -j map lookup pinned "${PIN_ROOT}/global-v2/IFACE_CTX_MAP" \
        key hex ${ifindex_key} | python3 -c 'import json,struct,sys; v=json.load(sys.stdin)["value"]; print(struct.unpack("=I",bytes(v[:4]))[0])')"
    key="$(python3 -c 'import struct,sys; print(" ".join("%02x"%b for b in struct.pack("=I",int(sys.argv[1]))))' "${tap_id}")"
    value="$(bpftool -j map lookup pinned "${map}" key hex ${key} | \
        python3 -c 'import json,sys; v=json.load(sys.stdin)["value"]; v[7]=0; print(" ".join("%02x"%b for b in v))')"
    bpftool map update pinned "${map}" key hex ${key} value hex ${value}
    capture_acl_counters legacy-zero-before
    run_allowed_flow
    capture_acl_counters legacy-zero-after
    assert_xdp_neutral legacy-zero-before legacy-zero-after 4
    curl --fail-with-body -sS -H 'Content-Type: application/json' -X PUT \
        -d '{"conntrack":true,"monitoring":true,"acl":true,"qos":null,"mirror":null,"tcprt":null,"ssl":null}' \
        "${HTTP}/api/v1/${INSTANCE}/config" >/dev/null
    bpftool -j map lookup pinned "${map}" key hex ${key} | python3 -c '
import json,sys
value=json.load(sys.stdin)["value"]
assert len(value)==8 and value[7]==1,value
'
}

run_denied_flow() {
    ip netns exec "${NETNS}" ip addr del "${PEER_IP}/30" dev "${PEER_IF}"
    ip netns exec "${NETNS}" ip addr add 10.203.0.3/30 dev "${PEER_IF}"
    if ip netns exec "${NETNS}" ping -c 2 -W 1 "${HOST_IP}" \
        >"${WORK_DIR}/denied-flow.log" 2>&1; then
        return 1
    fi
    ip netns exec "${NETNS}" ip addr del 10.203.0.3/30 dev "${PEER_IF}"
    ip netns exec "${NETNS}" ip addr add "${PEER_IP}/30" dev "${PEER_IF}"
}

assert_health_poll_degrades() {
    local lost_link
    if [ "${MODE}" = system ]; then
        lost_link="${PIN_ROOT}/system/tc_egress_link"
    else
        lost_link="${PIN_ROOT}/global-v2/${HOST_IF}_tc_egress_link"
    fi
    rm -f "${lost_link}"
    sleep "${TC_HEALTH_WAIT_SECS}"
    curl -fsS "${HTTP}/api/v1/instances" | python3 -c '
import json,sys
name=sys.argv[1]
item=next(i for i in json.load(sys.stdin)["instances"] if i["name"]==name)
assert item["acl_ready"] is False,item
assert "tc_egress" in (item.get("readiness_reason") or ""),item
' "${INSTANCE}"
}

assert_missing_tc_rejected() {
    local code
    code="$(curl -sS -o "${WORK_DIR}/missing-tc-enable.json" -w '%{http_code}' \
        -H 'Content-Type: application/json' -X PUT \
        -d '{"conntrack":true,"monitoring":null,"acl":true,"qos":null,"mirror":null,"tcprt":null,"ssl":null}' \
        "${HTTP}/api/v1/${INSTANCE}/config")"
    [ "${code}" = 503 ]
}
```

The main body must capture counters, run four allowed packets, call
`assert_xdp_neutral`, then call `exercise_legacy_zero_compatibility`,
`run_denied_flow`, `assert_health_poll_degrades`, and
`assert_missing_tc_rejected` in that order. `cleanup` must stop the system
instance when present, terminate and wait for the agent, unmount the private
bpffs, delete the namespace/veth pair, record every cleanup error, and only then
allow `write_summary` to set `result=pass`.

The normal GitHub Build runs syntax and structure/mutation checks only. Real execution requires a privileged guarded runner with the built artifacts.

- [ ] **Step 4: Remove selector authority from the Neutron smoke**

In `neutron_aria_acl_tc_datapath_smoke.sh`, rename `capture_runtime_mode` to `capture_runtime_compatibility`. Continue requiring byte 7 to equal `1` as migration evidence, but change every message and checker assertion so it is not treated as proof that XDP bypassed ACL.

Keep the real proof based on:

- XDP contributes no ACL/CT/rule counter delta;
- both TC link pins exist;
- TC ingress and egress hit/miss evidence is present;
- exact CT packet/byte accounting is not doubled;
- strict bank flush produces miss then hit;
- stateless and deny paths create no prohibited CT state.

Update `ci/check_tc_acl_smoke.py` mutations to reject reintroduction of `unknown_hook_delta` or hook-dependent XDP proof.

- [ ] **Step 5: Run every allowed local gate**

```bash
bash -n deploy/smoke/aria_standalone_acl_tc_datapath_smoke.sh
bash -n deploy/kolla/smoke/neutron_aria_acl_tc_datapath_smoke.sh
python3 ci/check_smoke_python_blocks.py
python3 ci/check_standalone_tc_acl_smoke.py --self-test
python3 ci/check_tc_acl_smoke.py --self-test
python3 ci/check_tc_acl_datapath.py --self-test
python3 ci/check_neutron_stage1.py
python3 ci/check_neutron_stage2_acl.py
python3 ci/check_stage2_acceptance_evidence.py
python3 ci/check_stage3_readiness.py
python3 ci/check_blocked_terms.py
git diff --check
```

Expected: all pass locally with Rust skipped; no Cargo invocation appears in terminal history.

- [ ] **Step 6: Commit runtime evidence and prove GREEN in GitHub Actions**

```bash
git add deploy/smoke/aria_standalone_acl_tc_datapath_smoke.sh \
  ci/check_standalone_tc_acl_smoke.py \
  deploy/kolla/smoke/neutron_aria_acl_tc_datapath_smoke.sh \
  ci/check_tc_acl_smoke.py ci/check_neutron_stage1.py .github/workflows/build.yml
git commit -m "test: cover standalone TC ACL runtime boundaries"
```

Run the shared GitHub protocol. Expected: complete Build passes, including both smoke mutation checkers and the entire Rust/eBPF pipeline.

- [ ] **Step 7: Update documentation from exact evidence only**

Update `REVIEW-ACL-055`:

- `in-progress` while any new Build is red;
- `likely-fixed` only after the final complete GitHub Build is green;
- `fixed` only after both `MODE=system` and `MODE=tap` standalone summaries plus the managed Neutron summary are preserved and all say `result=pass`.

Record exact commit SHA, GitHub run URL/ID, local checker commands, and whether real privileged smoke was available. Never convert missing runtime evidence into a pass.

Update the design status to `implemented; GitHub Build green; real runtime evidence pending` or `fixed` according to that evidence. Keep `REVIEW-ACL-056` open and separate.

- [ ] **Step 8: Commit the final evidence state**

```bash
git add docs/openstack-neutron-aria-details/12-review-bug-backlog.md \
  docs/superpowers/specs/2026-07-13-xdp-ddos-only-tc-acl-design.md \
  .superpowers/sdd/progress.md
git commit -m "docs: record all-mode TC ACL evidence"
git push origin codex/acl-batch-6-tc-ct-fast-path
```

If this last commit changes docs only, do not claim a new code build unless one was actually run at that SHA. Preserve the most recent code Build SHA and explicitly label later documentation-only commits.

---

## Final Whole-Branch Verification

- [ ] Confirm the branch contains the approved design, this implementation plan, all RED/GREEN task commits, and no unrelated changes.

```bash
git status --short --branch
git log --oneline --decorate aad3a65..HEAD
git diff --check aad3a65..HEAD
git rev-list --left-right --count HEAD...origin/codex/acl-batch-6-tc-ct-fast-path
```

- [ ] Run all allowed local non-Cargo checks from Task 6 once more.

- [ ] Confirm the latest code SHA has a complete green GitHub Build and capture its run URL.

```bash
gh run list --workflow build.yml --branch codex/acl-batch-6-tc-ct-fast-path --limit 10
```

- [ ] Dispatch a fresh whole-branch specification reviewer against `4003a49..HEAD`.

- [ ] Dispatch a separate whole-branch code-quality/reliability reviewer, explicitly asking it to inspect mixed-version pins, startup ordering, map error propagation, TC link loss races, status/WAL deduplication, and XDP independence.

- [ ] Fix every confirmed blocker through a new RED/GREEN cycle and rerun the full GitHub Build.

- [ ] Do not mark `REVIEW-ACL-055` fixed without preserved passing real runtime summaries for system standalone, tap-managed standalone, and Neutron managed-tap modes.
