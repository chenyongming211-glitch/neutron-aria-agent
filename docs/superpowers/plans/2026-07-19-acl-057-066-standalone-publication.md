# ACL-057/066 Standalone ACL Publication Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace standalone active-bank ACL mutations with one durable final-state shadow-bank publication that invalidates CT and rolls back every preimage on failure.

**Architecture:** Add a focused `control_plane::standalone_acl` module. A pure planner builds one complete final state and an ordered publication/rollback plan; one concrete executor consumes that plan while the lifecycle and instance locks remain held. Single-policy, both-direction, batch, and ACL-referenced group expansion all route through this boundary, while managed-Neutron and unreferenced-group paths remain unchanged.

**Tech Stack:** Rust 2021, Tokio, Aya pinned maps, existing `FirewallState`, `WalClient`, ACL bank helpers, strict CT scrub, GitHub Actions.

**Execution status:** Tasks 1-4 and Task 5 Steps 1-4 completed on 2026-07-19.
RED `212828b` / Build `29682513348` and GREEN `a234bb5` / Build
`29683492746` are recorded in the design and backlog. Task 5 Step 5 now uses one
integration branch containing both the former PR #5 batch and ACL-057/066. The
latest `v0.9-neutron-agent` baseline must be merged here, followed by exact-head
CI and one unified PR; the old PR #5 is then closed as superseded.

## Global Constraints

- Do not run local `cargo build`, `cargo check`, or `cargo test`; Rust compilation and behavior evidence must come from GitHub Actions.
- Do not reuse `replace_owned_acl_and_flush` as the standalone public transaction boundary.
- Do not add another generic closure/future transaction framework.
- Do not add Python source-shape checks or bind CI to private Rust helper names.
- Keep the public HTTP request, response, and status-code schemas unchanged.
- Include `REVIEW-ACL-066` but exclude `REVIEW-ACL-059`, `REVIEW-ACL-056`, and ordinary unreferenced-group durability.
- Preserve current standalone selector projection semantics and current `direction=both` delete behavior.
- A semantic batch publishes at most once; a transaction-wide failure returns no partial success.

---

### Task 1: Land Focused RED Behavior Tests

**Files:**
- Modify: `agent/src/control_plane.rs`
- Create: `agent/src/control_plane/standalone_acl.rs`
- Modify: `ci/check_neutron_stage1.py`

**Interfaces:**
- Consumes: `FirewallState`, `RuleInfo`, `requested_directions`, `acl_next_bank`.
- Produces: the required production names `StandaloneAclMutation`, `StandaloneAclBatchItem`, `StandaloneAclPublicationPlan`, `StandaloneAclPublicationStep`, `StandaloneAclFailurePhase`, `build_standalone_acl_publication_plan`, `build_standalone_acl_batch_publication_plan`, and `standalone_acl_rollback_steps`.

- [x] **Step 1: Register the test-only module before production exists**

Add beside the existing `control_plane` child modules:

```rust
#[cfg(test)]
mod standalone_acl;
```

This keeps normal Rust/eBPF builds unchanged while making the behavior test
target compile the wished-for transaction API.

- [x] **Step 2: Add the RED planner and publication tests**

Create `agent/src/control_plane/standalone_acl.rs` with tests named under the
`standalone_acl_publication_` prefix. The tests import the planned production
symbols from the module root and assert:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use aria_core::common::{acl_next_bank, ACL_BANK_PRIMARY};
    use aria_core::state::FirewallState;

    fn state_with_groups() -> FirewallState {
        let mut state = FirewallState::default();
        state.add_group("client", "10.0.0.0/24").unwrap();
        state.add_group("server", "10.1.0.0/24").unwrap();
        state
    }

    #[test]
    fn standalone_acl_publication_add_deny_rotates_bank_and_strictly_flushes_ct() {
        let old = state_with_groups();
        let plan = build_standalone_acl_publication_plan(
            &old,
            ACL_BANK_PRIMARY,
            &[StandaloneAclMutation::UpsertPolicy {
                src_group: "client".into(),
                dst_group: "server".into(),
                proto: 6,
                action: 1,
                direction: 0,
                ports: None,
            }],
        ).unwrap();

        assert_eq!(plan.old_bank, ACL_BANK_PRIMARY);
        assert_eq!(plan.shadow_bank, acl_next_bank(ACL_BANK_PRIMARY));
        assert_eq!(plan.publication_count, 1);
        assert_eq!(plan.steps.last(), Some(&StandaloneAclPublicationStep::StrictCtScrub));
        assert_eq!(plan.final_state.rules.len(), 1);
    }

    #[test]
    fn standalone_acl_publication_allow_to_deny_is_one_both_direction_epoch() {
        let mut old = state_with_groups();
        let src = old.groups["client"].id;
        let dst = old.groups["server"].id;
        old.apply_add_rule(src, dst, 6, 0, None, 0).unwrap();
        old.apply_add_rule(src, dst, 6, 0, None, 1).unwrap();

        let plan = build_standalone_acl_publication_plan(
            &old,
            ACL_BANK_PRIMARY,
            &[StandaloneAclMutation::UpsertPolicy {
                src_group: "client".into(),
                dst_group: "server".into(),
                proto: 6,
                action: 1,
                direction: 2,
                ports: None,
            }],
        ).unwrap();

        assert_eq!(plan.publication_count, 1);
        assert_eq!(plan.accepted, 1);
        assert!(plan.final_state.rules.iter().all(|rule| rule.action == 1));
    }

    #[test]
    fn standalone_acl_publication_delete_allow_removes_both_directions_once() {
        let mut old = state_with_groups();
        let src = old.groups["client"].id;
        let dst = old.groups["server"].id;
        old.apply_add_rule(src, dst, 6, 0, None, 0).unwrap();
        old.apply_add_rule(src, dst, 6, 0, None, 1).unwrap();

        let plan = build_standalone_acl_publication_plan(
            &old,
            ACL_BANK_PRIMARY,
            &[StandaloneAclMutation::DeletePolicy {
                src_group: "client".into(),
                dst_group: "server".into(),
                proto: 6,
                direction: 2,
            }],
        ).unwrap();

        assert_eq!(plan.publication_count, 1);
        assert!(plan.final_state.rules.is_empty());
    }

    #[test]
    fn standalone_acl_publication_referenced_group_expansion_updates_general_before_switch() {
        let mut old = state_with_groups();
        let src = old.groups["client"].id;
        let dst = old.groups["server"].id;
        old.apply_add_rule(src, dst, 6, 1, None, 0).unwrap();

        let plan = build_standalone_acl_publication_plan(
            &old,
            ACL_BANK_PRIMARY,
            &[StandaloneAclMutation::AddReferencedGroupCidr {
                group_name: "client".into(),
                cidr: "10.0.1.0/24".into(),
            }],
        ).unwrap();

        assert_eq!(plan.publication_count, 1);
        assert_eq!(plan.general_targets.len(), 2);
        let general = plan.steps.iter().position(|step| *step == StandaloneAclPublicationStep::ApplyGeneral).unwrap();
        let switch = plan.steps.iter().position(|step| *step == StandaloneAclPublicationStep::SwitchBank).unwrap();
        assert!(general < switch);
    }

    #[test]
    fn standalone_acl_publication_batch_keeps_item_errors_and_switches_once() {
        let old = state_with_groups();
        let plan = build_standalone_acl_publication_plan(
            &old,
            ACL_BANK_PRIMARY,
            &[
                StandaloneAclMutation::UpsertPolicy {
                    src_group: "client".into(), dst_group: "server".into(),
                    proto: 6, action: 1, direction: 2, ports: None,
                },
                StandaloneAclMutation::UpsertPolicy {
                    src_group: "missing".into(), dst_group: "server".into(),
                    proto: 6, action: 1, direction: 0, ports: None,
                },
            ],
        ).unwrap();

        assert_eq!(plan.accepted, 1);
        assert_eq!(plan.errors.len(), 1);
        assert_eq!(plan.publication_count, 1);
        assert_eq!(plan.steps.iter().filter(|step| **step == StandaloneAclPublicationStep::SwitchBank).count(), 1);
    }

    #[test]
    fn standalone_acl_publication_failures_restore_every_preimage_in_reverse() {
        assert_eq!(
            standalone_acl_rollback_steps(StandaloneAclFailurePhase::StrictCtScrub),
            vec![
                StandaloneAclRollbackStep::RestoreActiveBank,
                StandaloneAclRollbackStep::RestoreGeneralReverse,
                StandaloneAclRollbackStep::ScrubFailedShadow,
                StandaloneAclRollbackStep::CleanupCreatedBitmaps,
                StandaloneAclRollbackStep::RestoreDurableState,
            ],
        );
    }
}
```

The initial CI failure must be unresolved standalone publication symbols, not
a syntax error or an unrelated existing test failure.

- [x] **Step 3: Add only the public Rust behavior discovery filter**

Append this entry to `RUST_TESTS` in `ci/check_neutron_stage1.py`:

```python
    ["test", "--locked", "-p", "aria-agent", "standalone_acl_publication_"],
```

Do not add a Python parser, mutation checker, or private source-shape rule.

- [x] **Step 4: Run allowed non-compiling validation**

Run:

```bash
python3 ci/check_neutron_stage1.py --fast-contracts
git diff --check
```

Expected: fast contracts pass and `git diff --check` is silent. Do not run any
Cargo command.

- [x] **Step 5: Commit and push the RED tests**

```bash
git add agent/src/control_plane.rs agent/src/control_plane/standalone_acl.rs ci/check_neutron_stage1.py
git commit -m "test: define standalone ACL publication transaction"
git push origin codex/review-acl-057-direct-publication
```

- [x] **Step 6: Dispatch and inspect exact-head RED CI**

```bash
gh workflow run Build --ref codex/review-acl-057-direct-publication \
  -f publish_artifacts=false -f run_deep_audit=false
gh run list --branch codex/review-acl-057-direct-publication --limit 1
```

Expected: `fast-contracts` and `rust-build` pass; `rust-behavior` fails only
because the concrete standalone publication types/functions do not yet exist.
Record the run ID and exact RED commit before production edits.

### Task 2: Implement the Final-State Planner

**Files:**
- Modify: `agent/src/control_plane.rs`
- Modify: `agent/src/control_plane/standalone_acl.rs`

**Interfaces:**
- Consumes: the RED names and existing `FirewallState` mutation APIs.
- Produces: one immutable `StandaloneAclPublicationPlan` consumed by the concrete executor.

- [x] **Step 1: Make the module part of normal agent builds**

Replace the test-only declaration with:

```rust
mod standalone_acl;
```

- [x] **Step 2: Define the concrete mutation and plan types**

Implement these domain types in `standalone_acl.rs`:

```rust
#[derive(Clone, Debug)]
pub(crate) enum StandaloneAclMutation {
    UpsertPolicy { src_group: String, dst_group: String, proto: u8, action: u8, direction: u8, ports: Option<String> },
    DeletePolicy { src_group: String, dst_group: String, proto: u8, direction: u8 },
    AddReferencedGroupCidr { group_name: String, cidr: String },
}

#[derive(Clone, Debug)]
pub(crate) enum StandaloneAclBatchItem {
    Parsed { request_index: usize, mutation: StandaloneAclMutation },
    Rejected { request_index: usize, error: String },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum StandaloneAclPublicationStep {
    PersistBitmapGuard,
    StageShadow,
    ApplyGeneral,
    SwitchBank,
    PersistFinalState,
    StrictCtScrub,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum StandaloneAclFailurePhase { StageShadow, ApplyGeneral, SwitchBank, PersistFinalState, StrictCtScrub }

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum StandaloneAclRollbackStep { RestoreActiveBank, RestoreGeneralReverse, RestoreDurableState, CleanupCreatedBitmaps, ScrubFailedShadow }

pub(super) struct StandaloneGeneralTarget { pub direction: &'static str, pub cidr: String, pub group_id: u32 }

pub(super) struct StandaloneAclPublicationPlan {
    pub old_state: FirewallState,
    pub final_state: FirewallState,
    pub old_bank: u8,
    pub shadow_bank: u8,
    pub accepted: usize,
    pub errors: Vec<String>,
    pub semantic_changed: bool,
    pub publication_count: usize,
    pub general_targets: Vec<StandaloneGeneralTarget>,
    pub created_port_sets: Vec<TransactionCreatedPortSet>,
    pub released_port_sets: BTreeMap<u32, String>,
    pub steps: Vec<StandaloneAclPublicationStep>,
}
```

Re-export `StandaloneAclMutation` and `StandaloneAclBatchItem` from
`control_plane.rs` with `pub(crate) use` so handlers depend on the domain
contract, not the child module path.

- [x] **Step 3: Build each item on a temporary state clone**

Implement `build_standalone_acl_publication_plan` so that it:

```rust
pub(super) fn build_standalone_acl_publication_plan(
    old_state: &FirewallState,
    old_bank: u8,
    mutations: &[StandaloneAclMutation],
) -> Result<StandaloneAclPublicationPlan, ControlPlaneError>
```

- resolves group names with ID zero reserved for `any`;
- expands direction through `requested_directions`;
- applies both directions to an item-local clone;
- commits the item-local clone only when the whole item validates;
- preserves ordered batch errors by carrying `request_index` through both
  parsed and rejected batch items and sorting the final error pairs before
  projecting them to `Vec<String>`;
- recognizes referenced-group expansion and creates exactly two general
  targets;
- derives created and released port sets by comparing old and final allocator
  metadata;
- returns zero publication steps for a semantic no-op;
- otherwise returns one ordered publication sequence ending in strict CT scrub.

- [x] **Step 4: Aggregate parsed and rejected batch items without losing order**

Implement:

```rust
pub(super) fn build_standalone_acl_batch_publication_plan(
    old_state: &FirewallState,
    old_bank: u8,
    items: &[StandaloneAclBatchItem],
) -> Result<StandaloneAclPublicationPlan, ControlPlaneError>
```

Walk items by `request_index`. A rejected item contributes its existing error
without changing the working state. A parsed item is applied to an item-local
clone; semantic failure contributes an indexed error, while full success
replaces the working state and increments `accepted`. Produce one final plan
from the accepted working state, then sort indexed errors and project them to
the unchanged public `Vec<String>` response.

- [x] **Step 5: Derive rollback order from the reached failure phase**

Implement `standalone_acl_rollback_steps` with explicit match arms. The strict
flush arm must restore the active bank before any failed-shadow scrub, and the
switch/persist/flush arms must restore every recorded general-map preimage in
reverse application order.

### Task 3: Implement the Concrete Locked Publisher

**Files:**
- Modify: `agent/src/control_plane.rs`
- Modify: `agent/src/control_plane/standalone_acl.rs`
- Modify: `core/src/ebpf_ops.rs`
- Modify: `core/src/ebpf_ops/inventory.rs`

**Interfaces:**
- Consumes: `StandaloneAclPublicationPlan`, `TapMapRuntime`, `InstanceState::compact_and_publish_state`, strict CT scrub.
- Produces: `ControlPlane::apply_standalone_acl_mutations_locked` and exact general-map preimage capture.

- [x] **Step 1: Add a neutral exact general-map capture primitive**

Expose a core helper that captures the exact source/destination canonical key
owner for one tap from the pinned general maps:

```rust
pub fn capture_general_network_owner(
    runtime: TapMapRuntime<'_>,
    direction: &str,
    cidr: &str,
) -> Result<Option<u32>, String>
```

It must compare the complete canonical key, not perform longest-prefix packet
lookup. Export only this behavior from `core/src/ebpf_ops.rs`.

- [x] **Step 2: Stage the complete standalone shadow projection**

Add a concrete staging function that:

- scrubs `shadow_bank` first;
- builds `RuntimeGroupMapEntries` with
  `GroupProjectionMode::StandaloneCompatibility`;
- writes all ACL source/destination entries into `shadow_bank`;
- writes every final policy into `shadow_bank`;
- never writes the active bank.

- [x] **Step 3: Execute the ordered transaction under existing locks**

Implement a concrete executor, not a generic callback framework:

```rust
impl ControlPlane {
    async fn apply_standalone_acl_mutations_locked(
        &self,
        state: &mut InstanceState,
        mutations: &[StandaloneAclMutation],
    ) -> Result<StandaloneAclPublicationPlan, ControlPlaneError>
}
```

The executor must:

1. read `old_bank` and build the plan before kernel mutation;
2. strictly persist created-bitmap quarantine when required;
3. stage the complete shadow bank;
4. capture and apply each general-map mutation, recording `Added` or
   `Replaced` receipts from the actual pinned preimage;
5. switch bank exactly once;
6. compact and publish the complete final state;
7. call `scrub_ct_tables_strict`;
8. on failure, attempt every required compensation and return one compound
   error;
9. avoid scrubbing the new bank if restoring the old active bank failed;
10. mark runtime ACL recovery-required and attempt quiesce if a required
    preimage cannot be restored;
11. after success, scrub the old bank and clear removed statistics;
12. leave retired-bitmap cleanup/reuse semantics unchanged for ACL-059.

- [x] **Step 4: Preserve crash-safe allocator recovery**

Use the existing `TransactionCreatedPortSet`,
`cleanup_transaction_created_port_sets`,
`old_state_with_failed_cleanup_quarantines`, and strict compact helpers. Never
restore a free list that exposes an index whose kernel cleanup failed.

### Task 4: Route Single, Both, Batch, And Referenced Group Mutations

**Files:**
- Modify: `agent/src/control_plane.rs`
- Modify: `agent/src/api_handlers/policies.rs`

**Interfaces:**
- Consumes: `apply_standalone_acl_mutations_locked`.
- Produces: unchanged HTTP contracts with one publication per semantic request/batch.

- [x] **Step 1: Replace direct policy add/update mutation**

Keep admission and lock order in `ControlPlane::add_policy`, but pass one
`UpsertPolicy` mutation to the new locked transaction. Remove direct active
bank writes, best-effort WAL acknowledgement, and handler-side compensation.

- [x] **Step 2: Replace direct policy delete mutation**

Pass one `DeletePolicy` mutation to the same transaction. Preserve the rule
that `direction=both` succeeds when at least one requested direction exists.

- [x] **Step 3: Add one control-plane batch entry point**

Expose:

```rust
pub async fn batch_add_policies(
    &self,
    instance: &str,
    items: Vec<StandaloneAclBatchItem>,
) -> Result<(usize, Vec<String>), ControlPlaneError>
```

It acquires lifecycle/instance locks once and returns planner `accepted` and
ordered errors only after the single publication succeeds.

- [x] **Step 4: Stop handler-side direction and batch loops**

`add_policy` parses one request and calls the control plane once with direction
0, 1, or 2. `batch_add_policies` converts every input position into either
`Parsed { request_index, mutation }` or `Rejected { request_index, error }`,
submits the complete ordered item list once, and returns parse/semantic errors
in the original order without changing `BatchPoliciesResponse`.

- [x] **Step 5: Route only referenced group expansion**

In `add_group`, while holding the instance lock, inspect the old state. Route
an existing ACL-referenced group plus a new CIDR through
`AddReferencedGroupCidr`. Keep new groups, duplicate CIDRs, and unreferenced
groups on their existing path. Keep referenced whole-group deletion rejected.

- [x] **Step 6: Run allowed formatting and non-compiling checks**

Run the approved formatter only on changed Rust files, then:

```bash
python3 ci/check_neutron_stage1.py --fast-contracts
git diff --check
```

Do not run Cargo locally.

- [x] **Step 7: Commit the complete GREEN implementation batch**

```bash
git add agent/src/control_plane.rs agent/src/control_plane/standalone_acl.rs \
  agent/src/api_handlers/policies.rs core/src/ebpf_ops.rs core/src/ebpf_ops/inventory.rs
git commit -m "fix: publish standalone ACL final state atomically"
git push origin codex/review-acl-057-direct-publication
```

### Task 5: Verify GREEN And Close Evidence

**Files:**
- Modify: `docs/openstack-neutron-aria-details/12-review-bug-backlog.md`

**Interfaces:**
- Consumes: exact RED and GREEN commits/runs.
- Produces: independent closure evidence for `REVIEW-ACL-057` and `REVIEW-ACL-066`.

- [x] **Step 1: Dispatch exact-head GREEN CI**

```bash
gh workflow run Build --ref codex/review-acl-057-direct-publication \
  -f publish_artifacts=false -f run_deep_audit=false
gh run list --branch codex/review-acl-057-direct-publication --limit 1
```

Expected: `fast-contracts`, `rust-behavior`, and `rust-build` pass with
`RUSTFLAGS=-D warnings`.

- [x] **Step 2: Inspect all failing or warning output before claiming GREEN**

Use `gh run view <run-id> --log-failed` for any failed job. A green conclusion
without the `standalone_acl_publication_` filter actually executing is not
valid evidence.

- [x] **Step 3: Update backlog with separate stable-ID evidence**

Record:

- RED commit and run ID;
- GREEN implementation commit and run ID;
- add-deny, allow-to-deny, delete-allow, batch/both, rollback, and referenced
  group test names;
- explicit statement that ACL-059, ACL-056, unreferenced-group durability, and
  privileged field evidence remain open.

- [x] **Step 4: Commit and push evidence**

```bash
git add docs/openstack-neutron-aria-details/12-review-bug-backlog.md
git commit -m "docs: record standalone ACL publication evidence"
git push origin codex/review-acl-057-direct-publication
```

- [ ] **Step 5: Preserve delivery topology**

Do not create a stacked or sibling PR. This branch is the sole integration
branch for the former PR #5 batch and ACL-057/066. Merge the latest
`v0.9-neutron-agent` baseline here without rewriting published history, rerun
exact-head CI, create one unified PR, and only then close PR #5 as superseded.
Privileged field evidence remains honestly deferred and gates production
activation rather than this source-integration step.
