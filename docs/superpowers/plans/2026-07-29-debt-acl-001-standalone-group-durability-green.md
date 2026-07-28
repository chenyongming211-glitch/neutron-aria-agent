# DEBT-ACL-001 Standalone Group Durability GREEN Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the seven verified standalone-group RED behavior contracts pass and route ordinary unreferenced group add/delete through one strictly durable, exactly compensating transaction.

**Architecture:** Keep final-state planning and concrete execution in `standalone_group.rs`. Add one neutral exact-key owner capture API in `aria-core`, then replace the legacy inline standalone add/delete bodies with thin calls into the concrete transaction. Reuse `InstanceState::wal_append_strict`, existing pinned-map operations, runtime health, and ACL/CT quiesce; add no generic executor or WAL abstraction.

**Tech Stack:** Rust 2021, Tokio, Aya pinned maps, `FirewallState`, `WalClient`, GitHub Actions `rust-behavior` and warning-denied `rust-build`.

## Global Constraints

- Work only on local and remote `v0.9-neutron-agent`; create no branch, PR, or worktree.
- Do not run local Cargo commands. Rust/eBPF evidence comes from exact-head GitHub Actions.
- Do not weaken, remove, rename, or suppress the seven existing RED tests.
- Do not add a Python implementation-shape checker, generic transaction trait, boxed-future framework, or second WAL abstraction.
- Do not rotate the ACL bank, advance fragment epoch, scrub CT, or change public HTTP schemas.
- Preserve referenced-group ACL-057/066 routing and managed local projection behavior.
- Treat privileged field evidence as `deferred/pending`.

---

### Task 1: Add exact general/ACL-bank owner capture

**Files:**
- Modify: `core/src/ebpf_ops/inventory.rs`
- Modify: `core/src/ebpf_ops.rs`

**Interfaces:**
- Produces: `NetworkOwnerPlane::{General, AclBank(u8)}`.
- Produces: `capture_network_owner(TapMapRuntime, &str, &str, NetworkOwnerPlane) -> Result<Option<u32>, String>`.
- Preserves: `capture_general_network_owner` as a delegating compatibility API for standalone ACL publication.

- [x] **Step 1: Introduce the plane and exact-key capture API**

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkOwnerPlane {
    General,
    AclBank(u8),
}

pub fn capture_network_owner(
    runtime: TapMapRuntime<'_>,
    direction: &str,
    cidr: &str,
    plane: NetworkOwnerPlane,
) -> Result<Option<u32>, String>
```

Select general map names and `runtime.tap_id` for `General`; select ACL map names and `acl_banked_tap_id(runtime.tap_id, bank)` for `AclBank`. Parse both the requested CIDR and iterated entries as `CanonicalNetwork`, then compare the complete canonical prefix rather than doing LPM lookup.

- [x] **Step 2: Export the API and retain the existing wrapper**

```rust
pub fn capture_general_network_owner(
    runtime: TapMapRuntime<'_>,
    direction: &str,
    cidr: &str,
) -> Result<Option<u32>, String> {
    capture_network_owner(runtime, direction, cidr, NetworkOwnerPlane::General)
}
```

Export both new symbols from `core/src/ebpf_ops.rs`; do not alter the existing standalone ACL caller.

### Task 2: Turn the seven RED contracts GREEN with concrete planning types

**Files:**
- Modify: `agent/src/control_plane/standalone_group.rs`

**Interfaces:**
- Produces: `StandaloneGroupMutation::{AddCidr, DeleteGroup}`.
- Produces: `StandaloneGroupPlan` containing exact old/final state, stable group ID, semantic-change flag, and deterministic targets.
- Produces: receipt compensation, rollback-order, and persistence classification used by tests and executor.

- [x] **Step 1: Define the concrete model above the existing tests**

```rust
#[derive(Debug, Clone, PartialEq, Eq)]
enum StandaloneGroupMutation {
    AddCidr { name: String, cidr: String },
    DeleteGroup { name: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum StandaloneGroupMapPlane {
    General,
    ActiveAcl { bank: u8 },
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct StandaloneGroupMapTarget {
    plane: StandaloneGroupMapPlane,
    direction: &'static str,
    cidr: String,
    desired_owner: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct StandaloneGroupMapReceipt {
    target: StandaloneGroupMapTarget,
    old_owner: Option<u32>,
}

#[derive(Debug, Clone)]
struct StandaloneGroupPlan {
    mutation: StandaloneGroupMutation,
    old_state: FirewallState,
    final_state: FirewallState,
    group_id: u32,
    semantic_changed: bool,
    map_targets: Vec<StandaloneGroupMapTarget>,
}
```

- [x] **Step 2: Implement pure final-state planning**

`AddCidr` clones old state, detects duplicate membership before `add_group`, preserves an existing ID/allocator, and emits exactly general-src, general-dst, active-ACL-src, active-ACL-dst for only the new CIDR. `DeleteGroup` clones the resolved group, removes it only from the clone, and emits the same four targets with `desired_owner=None` for every CIDR. Duplicate add returns identical old/final serialized state and no targets.

- [x] **Step 3: Implement exact compensation and rollback classification**

```rust
fn standalone_group_compensation(receipt: &StandaloneGroupMapReceipt)
    -> StandaloneGroupMapTarget
{
    StandaloneGroupMapTarget {
        desired_owner: receipt.old_owner,
        ..receipt.target.clone()
    }
}
```

For persistence failure, rollback order is `RestoreMemory`, `RestoreMapsReverse`, `RestoreDurableOldState`. Classification is `CommittedByCompact` after append failure plus compact success, `RolledBack` after clean compensation, and `RecoveryRequired` whenever map or durable-old-state compensation reports an error.

### Task 3: Execute the concrete transaction and route add/delete

**Files:**
- Modify: `agent/src/control_plane/standalone_group.rs`
- Modify: `agent/src/control_plane.rs`

**Interfaces:**
- Produces: `ControlPlane::add_group_standalone_locked(instance, state, name, cidr)`.
- Produces: `ControlPlane::delete_group_standalone_locked(instance, state, name)`.
- Consumes: exact owner capture, existing add/delete map operations, `wal_append_strict`, `compact_and_publish_state`, runtime health, and quiesce.

- [x] **Step 1: Capture all preimages before the first write**

For every plan target, call `capture_network_owner` with `General` or `AclBank(bank)`. Abort with `KernelError` if any capture fails. Do not mutate memory, durable state, or a pinned map before the complete receipt vector exists.

- [x] **Step 2: Apply only ownership-safe mutations**

For add, skip an already-correct owner and otherwise insert the final group ID. For delete, remove a key only when `old_owner == Some(plan.group_id)`; absent or foreign-owned keys are untouched. On a later write failure, compensate every successfully applied receipt in reverse order using its exact `old_owner`.

- [x] **Step 3: Persist at the specified commit point**

After all map writes succeed, assign `plan.final_state` to live memory and call `wal_append_strict` with the matching `AddGroup` or `DeleteGroup`. Append failure with successful compact fallback commits normally. If strict persistence returns an error, restore live memory, reverse-compensate maps, and call `compact_and_publish_state(plan.old_state.clone())` to neutralize a possibly partial final WAL entry.

- [x] **Step 4: Enforce recovery-required failure handling**

If any required map or durable compensation fails, set `acl_ready=false`, set `acl_error=recovery_required`, invoke `quiesce_tc_acl_runtime_locked`, retain every primary/compensation error, and return a 503 `InstanceNotReady`. Clean map rollback returns the original `KernelError`; clean persistence rollback returns `PersistenceError`.

- [x] **Step 5: Replace the legacy inline bodies**

Remove the old mutation-first add/delete implementations from `control_plane.rs`. Pass `instance` into the module methods. Keep add referenced-group routing unchanged, keep ACL/QoS/Mirror delete guards before planning, and clear deleted group statistics only after durable success.

### Task 4: Verify, submit, and record exact-head GREEN

**Files:**
- Modify after CI: `docs/superpowers/specs/2026-07-28-debt-acl-001-standalone-group-durability-design.md`
- Modify after CI: `docs/openstack-neutron-aria-details/12-review-bug-backlog.md`
- Modify: this plan

- [x] **Step 1: Run allowed local checks**

```bash
python3 -m unittest ci.test_ci_lane_contract
python3 ci/check_build_workflow_contract.py
python3 ci/check_neutron_stage1.py --fast-contracts
git diff --check
```

Expected: all commands exit zero. Do not run Cargo locally.

- [ ] **Step 2: Commit and push the GREEN implementation**

```bash
git add agent/src/control_plane.rs agent/src/control_plane/standalone_group.rs \
  core/src/ebpf_ops.rs core/src/ebpf_ops/inventory.rs \
  docs/superpowers/plans/2026-07-29-debt-acl-001-standalone-group-durability-green.md
git -c user.name=netmouser -c user.email=chenyongming211@gmail.com \
  commit -m "fix: make standalone groups strictly durable"
git push origin v0.9-neutron-agent
```

- [ ] **Step 3: Require exact-head hosted GREEN**

The exact implementation SHA must have `fast-contracts`, `rust-behavior`, and `rust-build` success. `rust-behavior` must execute `standalone_group_transaction_`; `rust-build` must retain `RUSTFLAGS=-D warnings` and pass eBPF, userspace, and agent static builds.

- [ ] **Step 4: Record evidence without overstating field readiness**

Record the GREEN commit/run/job evidence in the design and `DEBT-ACL-001` backlog entry. Close only the ordinary unreferenced standalone-group durability debt; keep privileged field evidence pending and do not advance into P2 in this batch.
