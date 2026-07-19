# ACL-059 Bitmap Cleanup Quarantine Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make retired standalone ACL bitmap indices durably recoverable and impossible to reuse before kernel cleanup is proven, while truthfully reporting post-commit cleanup debt.

**Architecture:** Keep retired bitmap cleanup after the standalone ACL commit point. Store cleanup intent separately from live port-set interning, retry it under the existing lifecycle and instance locks, and release an index only after idempotent kernel deletion plus durable state publication. Return cleanup debt as a committed outcome rather than a transaction failure, and expose it separately from ACL datapath readiness.

**Tech Stack:** Rust, Tokio, Serde JSON state/WAL compaction, Aya pinned maps, Axum, GitHub Actions.

## Global Constraints

- Develop directly on local `v0.9-neutron-agent`; compare and push only against `origin/v0.9-neutron-agent`.
- Do not create another branch or worktree.
- Do not run local `cargo build`, `cargo check`, or `cargo test`; GitHub Actions is the Rust/eBPF verification authority.
- Do not change ACL-056 fragment semantics, ordinary unreferenced-group durability, or later P2 API work.
- Do not add Python source-shape checkers or bind tests to private helper layout.
- A retired bitmap cleanup failure is post-commit: never roll back the active policy and never report it as an ordinary failed transaction.

---

### Task 1: Define RED durable-intent and outcome contracts

**Files:**
- Modify: `core/src/state.rs`
- Modify: `agent/src/control_plane.rs`
- Modify: `api/src/lib.rs`

**Interfaces:**
- Consumes: existing `FirewallState`, `PortSetCleanupReport`, `InstanceInfo`, and standalone publication tests.
- Produces: failing Rust contracts for `BitmapCleanupIntent`, exact cleanup-target recovery, committed cleanup-pending outcomes, and maintenance visibility that does not lower `acl_ready`.

- [x] **Step 1: Add failing core state tests**

Add focused tests named with the existing CI filters:

```rust
#[test]
fn quarantined_bitmap_preserves_cleanup_target_across_restart() {
    let mut state = FirewallState::default();
    state
        .quarantine_bitmap_cleanup(7, "80:1".to_string())
        .unwrap();
    let json = serde_json::to_string(&state).unwrap();
    let restarted: FirewallState = serde_json::from_str(&json).unwrap();
    assert_eq!(
        restarted.pending_bitmap_cleanup_targets(),
        vec![(7, "80:1".to_string())]
    );
}
```

Also prove that a pending cleanup survives allocator restart, successful confirmation releases only that index, and a conflicting cleanup target for the same index is rejected.

- [x] **Step 2: Add failing agent behavior tests**

Add `standalone_review_` tests proving:

```rust
let outcome = standalone_cleanup_outcome(&cleanup_report);
assert!(outcome.committed);
assert_eq!(outcome.cleanup_pending[0].bitmap_idx, 7);
```

The tests must distinguish item-validation errors from post-commit cleanup debt and prove that retry uses the persisted normalized target.

- [x] **Step 3: Add failing API contract test**

Add an `instance_info_reports_` test asserting `acl_ready == true` while `cleanup_pending_count == 1` and `maintenance_reason == "bitmap_cleanup_pending"`.

- [x] **Step 4: Commit and push RED**

```bash
git add core/src/state.rs agent/src/control_plane.rs api/src/lib.rs docs/superpowers/plans/2026-07-19-acl-059-bitmap-cleanup-quarantine.md
git -c user.name=netmouser -c user.email=chenyongming211@gmail.com commit -m "test: define ACL bitmap cleanup recovery"
git push origin v0.9-neutron-agent
```

- [x] **Step 5: Verify RED in GitHub Actions**

Use `gh run list`, `gh run watch`, and `gh run view`. Expected: the Rust behavior job fails only because the new durable cleanup-intent/outcome interfaces are missing. Do not accept unrelated failures as RED evidence.

---

### Task 2: Separate cleanup debt from live port-set interning

**Files:**
- Modify: `core/src/state.rs`
- Modify: `agent/src/control_plane.rs`
- Modify: `agent/src/control_plane/standalone_acl.rs`

**Interfaces:**
- Consumes: RED state contracts from Task 1.
- Produces:

```rust
pub struct BitmapCleanupIntent {
    pub ports_normalized: String,
}

impl FirewallState {
    pub fn quarantine_bitmap_cleanup(
        &mut self,
        bitmap_idx: u32,
        ports_normalized: String,
    ) -> Result<(), String>;
    pub fn pending_bitmap_cleanup_targets(&self) -> Vec<(u32, String)>;
    pub fn pending_bitmap_cleanup_count(&self) -> usize;
}
```

- [x] **Step 1: Add the explicit durable state field**

Add a serde-defaulted, deterministically ordered `BTreeMap<u32, BitmapCleanupIntent>` to `FirewallState`. Keep read compatibility for legacy synthetic quarantine entries, but do not write new cleanup debt into `port_sets`.

- [x] **Step 2: Make allocator admission consult cleanup intent**

Both free-list and fresh-index allocation must skip live port sets, explicit pending cleanup entries, and legacy synthetic quarantine entries.

- [x] **Step 3: Preserve exact targets at every quarantine call site**

Change created-bitmap guards, retired standalone bitmaps, managed publication rollback, and partial-cleanup recovery to pass the exact normalized port set. Extend `PortSetCleanupFailure` with `ports_normalized` so rollback persistence never loses its cleanup target.

- [x] **Step 4: Preserve legacy safety**

Legacy entries without a cleanup target remain unavailable. They may be released only after a successful full tap-scoped scrub proves the bitmap clean; targeted retry must not invent a port set.

- [x] **Step 5: Check formatting without compiling or broad source churn**

Run the already approved `rustfmt --check` binary only on changed Rust files.
Do not invoke Cargo, and do not apply unrelated whole-file formatting drift.

---

### Task 3: Retry cleanup and publish a truthful post-commit result

**Files:**
- Modify: `agent/src/control_plane.rs`
- Modify: `agent/src/control_plane/standalone_acl.rs`
- Modify: `agent/src/api_handlers/policies.rs`
- Modify: `api/src/lib.rs`

**Interfaces:**
- Consumes: `pending_bitmap_cleanup_targets`, `cleanup_port_sets`, `apply_confirmed_port_set_cleanups`, and existing policy endpoints.
- Produces a concrete standalone outcome containing accepted-item errors separately from pending cleanup failures.

- [x] **Step 1: Retry durable cleanup before standalone policy planning**

Under the existing lifecycle and instance write locks, load exact cleanup targets, call idempotent `delete_port_set`, durably release only confirmed indices, and leave failed indices pending. A successful kernel delete followed by persistence failure must leave the durable/in-memory allocator quarantined.

- [x] **Step 2: Report current publication cleanup**

After bank switch, final-state persistence, and strict CT scrub succeed, attempt retired-bitmap cleanup. Return an `Ok` committed outcome even when cleanup remains pending; never convert it into `ControlPlaneError::KernelError` or roll back the active bank.

- [x] **Step 3: Preserve batch semantics**

Keep per-item validation errors in `errors`. Add cleanup debt as a separate response field so a successful atomic batch is not falsely described as partially rejected.

- [x] **Step 4: Expose maintenance state without changing ACL readiness**

Add `cleanup_pending_count` and optional `maintenance_reason` to instance status. Derive them from durable cleanup intents while preserving the existing TC-derived `acl_ready` value.

- [x] **Step 5: Return HTTP 202 for committed cleanup debt**

Single add/update/delete and batch handlers return their normal success status when cleanup is complete. When cleanup remains pending, return `202 Accepted` with `committed: true` and structured cleanup details.

---

### Task 4: Verify GREEN, document closure, and deliver

**Files:**
- Modify: `docs/openstack-neutron-aria-details/12-review-bug-backlog.md`
- Modify: `docs/superpowers/plans/2026-07-19-acl-059-bitmap-cleanup-quarantine.md`

**Interfaces:**
- Consumes: completed implementation and exact-head GitHub Actions evidence.
- Produces: current backlog status and reproducible RED/GREEN evidence.

- [x] **Step 1: Review the complete diff**

Confirm there is no new generic transaction framework, no Python checker, no unrelated API/domain change, and no local Cargo output.

- [x] **Step 2: Commit and push GREEN**

```bash
git add core/src/state.rs agent/src/control_plane.rs agent/src/control_plane/standalone_acl.rs agent/src/api_handlers/policies.rs api/src/lib.rs
git -c user.name=netmouser -c user.email=chenyongming211@gmail.com commit -m "fix: recover standalone ACL bitmap cleanup"
git push origin v0.9-neutron-agent
```

- [x] **Step 3: Verify exact-head GitHub Actions**

Require `fast-contracts`, `rust-behavior`, and warning-denied Rust/eBPF build jobs to pass at the exact GREEN commit. No local build may substitute for hosted evidence.

- [x] **Step 4: Record closure evidence**

Update `REVIEW-ACL-059` only after exact-head CI is green. Record RED commit/run, GREEN commit/run, durable target recovery, no-reuse proof, post-commit response semantics, and the absence of privileged field evidence where applicable.

- [x] **Step 5: Commit and push documentation closure**

```bash
git add docs/openstack-neutron-aria-details/12-review-bug-backlog.md docs/superpowers/plans/2026-07-19-acl-059-bitmap-cleanup-quarantine.md
git -c user.name=netmouser -c user.email=chenyongming211@gmail.com commit -m "docs: record ACL bitmap cleanup evidence"
git push origin v0.9-neutron-agent
```

## Self-Review

- Spec coverage: durable exact target, allocator exclusion, post-commit outcome, retry, persistence failure, restart visibility, batch separation, and legacy safety are assigned to Tasks 1-4.
- Placeholder scan: no deferred implementation placeholder is present; privileged field evidence is not required to prove allocator state transitions and is not claimed.
- Type consistency: `BitmapCleanupIntent`, `pending_bitmap_cleanup_targets`, and the committed cleanup outcome are introduced in RED before production use.

## Delivery Evidence

- RED commit `724527d` and Build
  [29690852147](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/29690852147):
  `fast-contracts` passed and `rust-behavior` failed only on the intentionally
  missing durable cleanup-intent/outcome interfaces; the remaining long build
  was cancelled after the RED boundary was proven.
- GREEN commit `65fedfb` and exact-head Build
  [29691471591](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/29691471591):
  `fast-contracts`, `rust-behavior`, and warning-denied eBPF/userspace/agent
  static builds passed.
- No local Cargo command or privileged field execution was used or claimed.
- `rustfmt --check` was run without mutation. It reported pre-existing
  whole-file drift, including unrelated sections of the large control-plane
  modules; no broad formatting rewrite was applied. `git diff --check` passed.
