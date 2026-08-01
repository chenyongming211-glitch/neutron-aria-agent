# REVIEW-ACL-063 General Group Overlap Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans
> to implement this plan task-by-task. This repository requires direct work on
> `v0.9-neutron-agent`; do not create a branch, worktree, PR, or subagent.

**Goal:** Reject newly introduced exact or nested overlap between different
general-domain group IDs before any runtime or durable effect, while preserving
legacy replay and ACL-only isolation.

**Architecture:** Add a pure transition validator next to the existing managed
group projection compiler. Standalone callers validate all groups; managed
callers validate only the existing projected general-domain classification.
Projection compilation retains its deterministic compatibility behavior for
legacy state.

**Tech Stack:** Rust, `aria-core` projection contracts, `aria-agent`
control-plane transactions, GitHub Actions hosted Rust behavior/build lanes.

## Global Constraints

- Work only on local and remote `v0.9-neutron-agent`.
- Do not create another branch, worktree, or pull request.
- Do not run local `cargo build`, `cargo check`, or `cargo test`.
- Use hosted CI for Rust RED/GREEN and warning-denied compilation.
- Do not change eBPF ABI, source-port, priority, ACL-046 isolation, or
  QoS/Mirror precedence.
- Do not claim privileged field evidence.

---

### Task 1: Add RED overlap behavior contracts

**Files:**

- Modify: `core/tests/acl_projection_contract.rs`
- Modify: `agent/src/control_plane/standalone_group.rs`
- Modify: `agent/src/control_plane/standalone_acl.rs`
- Modify: `agent/src/control_plane.rs`

**Interfaces:**

- Consumes: existing `FirewallState`, `CanonicalNetwork`, projection fixtures,
  standalone final-state planners, and managed projection mutation planner.
- Produces: tests expecting
  `validate_general_group_overlap_transition(old, proposed, scope)` and
  `GeneralGroupScope::{Standalone, Managed}` plus HTTP 409 conflict behavior.

- [ ] **Step 1: Add pure projection RED tests**

Add `acl_projection_general_overlap_*` tests for exact IPv4 overlap, nested
IPv4/IPv6 overlap, same-group nesting, disjoint networks, managed ACL-only
isolation, QoS/Mirror promotion, insertion-order-stable reason, unchanged
legacy overlap, and overlap removal.

- [ ] **Step 2: Add transaction-boundary RED tests**

Add tests under existing hosted filters proving:

```rust
#[test]
fn standalone_group_transaction_rejects_new_general_overlap_before_targets() { /* ... */ }

#[test]
fn standalone_acl_publication_referenced_group_overlap_is_item_error() { /* ... */ }

#[test]
fn managed_local_group_projection_rejects_promoted_general_overlap_before_operations() { /* ... */ }

#[test]
fn managed_local_group_projection_overlap_maps_to_conflict() { /* ... */ }
```

The planner tests must assert that a rejected batch item contributes no final
state, general target, allocator, or publication change.

- [ ] **Step 3: Verify non-Rust structure locally**

Run:

```bash
git diff --check
python3 -m unittest ci.test_ci_lane_contract ci.test_ci001_trusted_gates
```

Expected: Python CI wiring passes; no Cargo command runs locally.

- [ ] **Step 4: Commit and push RED**

```bash
git add core/tests/acl_projection_contract.rs \
  agent/src/control_plane/standalone_group.rs \
  agent/src/control_plane/standalone_acl.rs \
  agent/src/control_plane.rs \
  docs/superpowers/plans/2026-08-01-review-acl-063-general-group-overlap.md
git commit -m "test: expose general group overlap ambiguity"
git push origin v0.9-neutron-agent
```

- [ ] **Step 5: Capture hosted RED**

Wait for the exact-head Build. Expected: `rust-behavior` fails because the new
transition validator/scope or production rejection is absent. Record the run
URL and cancel remaining expensive work only after the intended RED failure is
visible.

---

### Task 2: Implement the pure transition invariant

**Files:**

- Modify: `core/src/ebpf_ops/projection.rs`
- Modify: `core/src/ebpf_ops.rs`

**Interfaces:**

- Produces:

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GeneralGroupScope {
    Standalone,
    Managed,
}

pub fn validate_general_group_overlap_transition(
    committed: &FirewallState,
    proposed: &FirewallState,
    scope: GeneralGroupScope,
) -> Result<(), String>;
```

- [ ] **Step 1: Canonicalize candidates**

Reuse `collect_persisted_groups()`. For `Standalone`, include every non-zero
group ID. For `Managed`, reuse the existing ACL-only/general classification
derived from ACL and QoS/Mirror references.

- [ ] **Step 2: Enumerate stable cross-group conflicts**

Sort canonical candidates deterministically. Treat exact equality and nesting
as overlap only across different group IDs. Permit same-group nesting and
different address families. Return the lexicographically first conflict reason
using canonical CIDR strings and stable persisted group names.

- [ ] **Step 3: Compare committed and proposed conflict sets**

Accept when every proposed conflict already exists in committed state. Reject
the first newly introduced conflict as:

```text
general_group_overlap:<left-name>:<left-cidr>:<right-name>:<right-cidr>
```

Do not call this validator from `compile_managed_group_projection()`, so replay
and inventory retain deterministic legacy compatibility.

- [ ] **Step 4: Export the public contract**

Re-export `GeneralGroupScope` and
`validate_general_group_overlap_transition` from `core/src/ebpf_ops.rs`.

---

### Task 3: Wire every final-state write boundary

**Files:**

- Modify: `agent/src/control_plane/standalone_group.rs`
- Modify: `agent/src/control_plane/standalone_acl.rs`
- Modify: `agent/src/control_plane.rs`

**Interfaces:**

- Consumes: Task 2 transition validator.
- Produces: `ControlPlaneError::GroupConflict(String)` with HTTP 409.

- [ ] **Step 1: Guard standalone group planning**

After constructing `final_state` but before constructing map targets, validate
`old_state -> final_state` with `GeneralGroupScope::Standalone`. Convert the
reason to `ControlPlaneError::GroupConflict` at the control-plane boundary.

- [ ] **Step 2: Preserve standalone ACL batch item semantics**

After each parsed mutation builds `item_state`, validate
`working -> item_state`. On overlap, retain `working`, discard the item's
general targets and allocator changes, and append the stable item error. Other
valid items remain eligible for the one atomic publication.

- [ ] **Step 3: Guard managed final-state projection**

At the start of `managed_general_state_mutations(old_state, final_state)`, run
the validator with `GeneralGroupScope::Managed`. Map a new overlap to
`GroupConflict` before compiling or returning any projection operations. This
covers group, QoS, Mirror, owned ACL, and demotion final states.

- [ ] **Step 4: Add explicit conflict status**

Add `GroupConflict(String)` to `ControlPlaneError`; render it as a group
conflict and map it to HTTP 409. Do not overload `GroupInUse` or return HTTP
400.

- [ ] **Step 5: Re-run local non-Cargo verification**

Run:

```bash
git diff --check
python3 -m unittest ci.test_ci_lane_contract ci.test_ci001_trusted_gates
python3 ci/check_neutron_stage1.py --fast-contracts
```

Expected: full Python/CLI/shell fast contracts pass and no Cargo command runs.

- [ ] **Step 6: Commit and push GREEN**

```bash
git add core/src/ebpf_ops/projection.rs core/src/ebpf_ops.rs \
  agent/src/control_plane/standalone_group.rs \
  agent/src/control_plane/standalone_acl.rs agent/src/control_plane.rs
git commit -m "fix: reject ambiguous general group overlap"
git push origin v0.9-neutron-agent
```

- [ ] **Step 7: Capture exact-head GREEN**

Wait for `fast-contracts`, `neutron-db-contracts`, `rust-behavior`, and
`rust-build`. All required jobs must pass at the exact implementation commit,
including warning-denied userspace, eBPF, and static-agent builds.

---

### Task 4: Close documentation and choose the next risk batch

**Files:**

- Modify: `docs/superpowers/specs/2026-08-01-review-acl-063-general-group-overlap-design.md`
- Modify: `docs/superpowers/plans/2026-08-01-review-acl-063-general-group-overlap.md`
- Modify: `docs/openstack-neutron-aria-details/12-review-bug-backlog.md`

**Interfaces:**

- Consumes: exact RED and GREEN commit IDs and Build URLs.
- Produces: authoritative ACL-063 `fixed` status without field-evidence claim.

- [ ] **Step 1: Record evidence**

Update design status, plan checkboxes, and the REVIEW register with exact RED
failure and exact implementation-head GREEN evidence. State explicitly that no
privileged field evidence applies or is claimed.

- [ ] **Step 2: Verify documentation closure**

Run:

```bash
git diff --check
python3 ci/check_neutron_stage1.py --fast-contracts
```

Expected: all non-Cargo required contracts pass.

- [ ] **Step 3: Commit, push, and verify exact documentation head**

```bash
git add docs/superpowers/specs/2026-08-01-review-acl-063-general-group-overlap-design.md \
  docs/superpowers/plans/2026-08-01-review-acl-063-general-group-overlap.md \
  docs/openstack-neutron-aria-details/12-review-bug-backlog.md
git commit -m "docs: close REVIEW-ACL-063"
git push origin v0.9-neutron-agent
```

Wait for exact-head hosted CI. Then verify clean worktree and local/remote
divergence `0 0`.

- [ ] **Step 4: Reassess next work**

Proceed next to `RISK-SEC-002`, then `RISK-READY-001`. Do not mix either risk
into ACL-063.
