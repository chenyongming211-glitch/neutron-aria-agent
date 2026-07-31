# REVIEW-ACL-025 Durable ACL Publication Order Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use
> superpowers:subagent-driven-development (recommended) or
> superpowers:executing-plans to implement this plan task-by-task. Steps use
> checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make both managed and standalone ACL publication durably commit the
complete final state before advancing the fragment epoch or activating the new
ACL bank.

**Architecture:** Keep the two existing concrete publishers and move their
final-state compact step before the combined fragment-epoch/bank publication.
Managed publication gains a concrete post-durable rollback path that restores
the old bank only when publication was attempted, reverses general-map
preimages, preserves a possibly active failed bank, cleans created bitmaps, and
restores the old durable snapshot. Standalone reuses its existing rollback
planner with corrected phase ordering.

**Tech Stack:** Rust stable, Tokio, existing `WalClient`/`FirewallState`,
existing Aya pinned-map operations, GitHub Actions `rust-behavior` and
warning-denied `rust-build`.

## Global Constraints

- Work directly on local and remote `v0.9-neutron-agent`; do not create a
  branch, worktree, stacked PR, or parallel delivery line.
- Do not run local `cargo build`, `cargo check`, or `cargo test`.
- Verify Rust RED and GREEN only through GitHub Actions.
- Cover both `agent/src/control_plane.rs` and
  `agent/src/control_plane/standalone_acl.rs`.
- Keep both publishers concrete; do not add a generic closure/future
  transaction framework.
- Do not change `core/src/wal.rs`, WAL formats, eBPF/ABI code,
  `agent/src/neutron_api.rs`, Python, configuration, or API contracts.
- Do not absorb `REVIEW-ACL-026`, `REVIEW-ACL-044`, or later transaction debt.
- Preserve allocator quarantine, strict CT scrub, fragment-epoch, API
  acknowledgement, and existing ACL product semantics.
- Add Rust behavior tests only; do not add a Python checker tied to private Rust
  function names or source layout.

---

### Task 1: Submit the RED durable-order contract

**Files:**

- Modify: `agent/src/control_plane.rs`
- Modify: `agent/src/control_plane/standalone_acl.rs`

**Interfaces:**

- Consumes:
  - `managed_acl_publication_decision`
  - `managed_acl_publication_steps`
  - `managed_acl_publication_compensations`
  - `publication_steps`
  - `standalone_acl_rollback_steps`
- Produces: behavior-only requirements for the existing private planners; no
  production interface.

- [x] **Step 1: Add a test-only order assertion in each existing Rust test module**

Add this helper independently to the `#[cfg(test)]` module in each file, using
the concrete step type of that module:

```rust
fn assert_durable_before_bank_publication(
    persist: usize,
    epoch: usize,
    switch: usize,
) {
    assert!(
        persist < epoch,
        "final state must be durable before fragment epoch advance"
    );
    assert!(
        epoch < switch,
        "fragment epoch must fence the active-bank switch"
    );
}
```

The helper is test-local. Do not add a production helper solely for this
assertion.

- [x] **Step 2: Add managed RED tests**

Add beside the existing managed publication planner tests:

```rust
#[test]
fn managed_general_delta_persists_before_epoch_and_bank_switch() {
    let decision = managed_acl_publication_decision(ProjectionDrift::Clean, true)
        .expect("a semantic ACL change must publish");
    let steps = managed_acl_publication_steps(&decision, Vec::new());
    let persist = steps
        .iter()
        .position(|step| matches!(step, ManagedAclPublicationStep::Persist))
        .expect("managed publication must persist");
    let epoch = steps
        .iter()
        .position(|step| matches!(step, ManagedAclPublicationStep::AdvanceFragmentEpoch))
        .expect("managed publication must advance the fragment epoch");
    let switch = steps
        .iter()
        .position(|step| matches!(step, ManagedAclPublicationStep::SwitchBank))
        .expect("managed publication must switch bank");

    assert_durable_before_bank_publication(persist, epoch, switch);
}

#[test]
fn managed_general_delta_persistence_failure_does_not_restore_unpublished_bank() {
    let compensations = managed_acl_publication_compensations(
        &[managed_replacement("src")],
        ManagedAclPublicationFailurePhase::Persist,
    );

    assert_eq!(
        compensations,
        vec![managed_expected_general_restore("src")]
    );
}

#[test]
fn managed_general_delta_uncertain_bank_switch_failure_restores_old_bank_first() {
    let compensations = managed_acl_publication_compensations(
        &[managed_replacement("src"), managed_replacement("dst")],
        ManagedAclPublicationFailurePhase::SwitchBank,
    );

    assert_eq!(
        compensations,
        vec![
            ManagedAclPublicationCompensation::RestoreActiveBank,
            managed_expected_general_restore("dst"),
            managed_expected_general_restore("src"),
        ]
    );
}
```

These tests use the existing concrete planner and compensation types. They do
not prescribe function source layout.

- [x] **Step 3: Add standalone RED tests**

Add to `control_plane::standalone_acl::tests`:

```rust
#[test]
fn standalone_acl_publication_persists_before_epoch_and_bank_switch() {
    let steps = publication_steps(true);
    let persist = steps
        .iter()
        .position(|step| *step == StandaloneAclPublicationStep::PersistFinalState)
        .expect("standalone publication must persist");
    let epoch = steps
        .iter()
        .position(|step| *step == StandaloneAclPublicationStep::AdvanceFragmentEpoch)
        .expect("standalone publication must advance the fragment epoch");
    let switch = steps
        .iter()
        .position(|step| *step == StandaloneAclPublicationStep::SwitchBank)
        .expect("standalone publication must switch bank");

    assert_durable_before_bank_publication(persist, epoch, switch);
}

#[test]
fn standalone_acl_final_persistence_failure_never_restores_unpublished_bank() {
    assert_eq!(
        standalone_acl_rollback_steps(StandaloneAclFailurePhase::PersistFinalState),
        vec![
            StandaloneAclRollbackStep::RestoreGeneralReverse,
            StandaloneAclRollbackStep::ScrubFailedShadow,
            StandaloneAclRollbackStep::CleanupCreatedBitmaps,
            StandaloneAclRollbackStep::RestoreDurableState,
        ]
    );
}
```

Do not change the existing strict-CT rollback test; it must continue requiring
old-bank restoration.

- [x] **Step 4: Review the RED diff without running local Cargo**

Run:

```bash
git diff --check
git diff --stat
git diff -- agent/src/control_plane.rs \
  agent/src/control_plane/standalone_acl.rs
```

Confirm:

- changes occur only inside `#[cfg(test)]` modules;
- no production enum, planner, executor, or error mapping changes;
- all five new tests describe public durability/failure behavior;
- no static checker or inline Rust source copy is added.

- [x] **Step 5: Commit and push RED**

Run:

```bash
git add agent/src/control_plane.rs \
  agent/src/control_plane/standalone_acl.rs
git commit -m "test: expose ACL publication durability window"
git push origin v0.9-neutron-agent
```

- [x] **Step 6: Record exact hosted RED evidence**

Run:

```bash
head_sha="$(git rev-parse HEAD)"
run_id="$(gh run list --workflow build.yml \
  --branch v0.9-neutron-agent --limit 10 \
  --json databaseId,headSha \
  --jq "map(select(.headSha == \"${head_sha}\"))[0].databaseId")"
test -n "${run_id}"
gh run watch "${run_id}"
gh run view "${run_id}" --json headSha,status,conclusion,jobs,url
gh run view "${run_id}" --log-failed
```

Expected:

- `changes`: pass and require Rust jobs;
- `fast-contracts`: pass;
- `rust-build`: pass because production code is unchanged;
- `rust-behavior`: fail only on the new ordering/compensation assertions:
  - managed persist currently follows epoch/switch;
  - managed persistence compensation currently restores a bank that was
    already published under the old order;
  - managed switch failure currently lacks explicit old-bank restoration;
  - standalone persist currently follows epoch/switch; and
  - standalone persistence rollback currently restores an already-published
    bank.

Record the exact commit, Build, job URL, and assertion messages in the
execution-evidence section before production changes.

---

### Task 2: Make managed final-state persistence the commit point

**Files:**

- Modify: `agent/src/control_plane.rs`

**Interfaces:**

- Consumes:
  - `InstanceState::compact_and_publish_state`
  - `rollback_owned_acl_prepublication`
  - `restore_durable_old_state_after_failed_persistence`
  - `cleanup_transaction_created_port_sets`
  - `managed_acl_publication_compensations`
- Produces:
  - managed step order `Persist -> AdvanceFragmentEpoch -> SwitchBank`
  - a concrete post-durable rollback path for persistence, epoch, and switch
    failures.

- [x] **Step 1: Reorder the managed planner**

Change only the tail of `managed_acl_publication_steps`:

```rust
steps.push(ManagedAclPublicationStep::StageShadow);
steps.push(ManagedAclPublicationStep::VerifyTc);
steps.push(ManagedAclPublicationStep::Persist);
steps.push(ManagedAclPublicationStep::AdvanceFragmentEpoch);
steps.push(ManagedAclPublicationStep::SwitchBank);
```

Keep `InvalidateProjectionHealth` and every `ApplyGeneral` step in their
existing positions.

- [x] **Step 2: Correct phase-specific bank compensation**

Change `managed_acl_publication_compensations` so only an uncertain bank
publication failure requests active-bank restoration:

```rust
let mut compensations = Vec::new();
if phase == ManagedAclPublicationFailurePhase::SwitchBank {
    compensations.push(ManagedAclPublicationCompensation::RestoreActiveBank);
}
compensations.extend(mutations.iter().rev().map(|mutation| {
    ManagedAclPublicationCompensation::RestoreGeneral(shared_network_compensation(mutation))
}));
```

`Persist` and `AdvanceFragmentEpoch` occur while the old bank remains active,
so neither phase restores the bank.

- [x] **Step 3: Add one concrete post-durable rollback helper**

Add an async helper beside `rollback_owned_acl_prepublication` with this
signature:

```rust
async fn rollback_owned_acl_after_durable_commit(
    original: ControlPlaneError,
    mutations: &[SharedNetworkMutation],
    failure_phase: ManagedAclPublicationFailurePhase,
    created_port_sets: &[TransactionCreatedPortSet],
    runtime: TapMapRuntime<'_>,
    ebpf_path: &str,
    previous_active_bank: u8,
    shadow_bank: u8,
    state: &mut InstanceState,
    old_state: &FirewallState,
) -> ControlPlaneError
```

Its concrete order is:

1. set `managed_projection_health=Unverified`;
2. build phase-specific compensations;
3. attempt every compensation in order while recording whether
   `RestoreActiveBank` failed;
4. scrub `shadow_bank` only when the old bank is known restored or no switch
   was attempted;
5. clean every transaction-created bitmap;
6. call `restore_durable_old_state_after_failed_persistence` unconditionally;
7. return the original error when all recovery succeeds, otherwise return the
   same error class with `owned ACL rollback failed: ...` appended.

Do not implement this as a generic future/closure executor. It is a concrete
managed ACL rollback using the current map and WAL primitives.

- [x] **Step 4: Move managed final-state compact before epoch publication**

In `publish_acl_projection_locked`, retain `durable_final_state` construction
and released-bitmap quarantine exactly as currently implemented.

Execute the `Persist` match arm before
`execute_fragment_epoch_bank_publication`. On compact error, call
`rollback_owned_acl_after_durable_commit` with phase `Persist`; this is
required because `WalWriter::compact` can fail after the atomic snapshot
replacement but before all later bookkeeping is acknowledged.

After persistence succeeds:

- `state.state` is the final durable state;
- epoch failure calls the same helper with `AdvanceFragmentEpoch`;
- bank publication failure calls it with `SwitchBank`; and
- `bank_committed=true` is set only after the combined helper succeeds.

Delete the old inline persistence rollback block after its behavior has moved
to the concrete helper.

- [x] **Step 5: Preserve managed success receipts and strict CT rollback**

Do not change:

- publication receipt shape or order;
- outer `replace_owned_acl_and_flush` lock scope;
- strict CT scrub position after successful bank publication;
- `rollback_owned_acl_after_strict_flush_locked`; or
- post-success bitmap/statistics/old-bank cleanup.

The outer strict CT failure must still restore active bank, reverse general
maps, clean created bitmaps, and restore the old durable state.

---

### Task 3: Reorder the standalone concrete publisher

**Files:**

- Modify: `agent/src/control_plane/standalone_acl.rs`

**Interfaces:**

- Consumes:
  - `StandaloneAclPublicationPlan`
  - `compact_and_publish_state`
  - `execute_fragment_epoch_bank_publication`
  - `rollback_standalone_publication`
- Produces: standalone order
  `PersistFinalState -> AdvanceFragmentEpoch -> SwitchBank -> StrictCtScrub`.

- [x] **Step 1: Reorder the standalone step plan**

Change `publication_steps(true)` to:

```rust
vec![
    StandaloneAclPublicationStep::PersistBitmapGuard,
    StandaloneAclPublicationStep::StageShadow,
    StandaloneAclPublicationStep::ApplyGeneral,
    StandaloneAclPublicationStep::PersistFinalState,
    StandaloneAclPublicationStep::AdvanceFragmentEpoch,
    StandaloneAclPublicationStep::SwitchBank,
    StandaloneAclPublicationStep::StrictCtScrub,
]
```

- [x] **Step 2: Correct final-persistence rollback steps**

Change only the `PersistFinalState` rollback arm:

```rust
PersistFinalState => vec![
    RestoreGeneralReverse,
    ScrubFailedShadow,
    CleanupCreatedBitmaps,
    RestoreDurableState,
],
```

Keep `StrictCtScrub` with `RestoreActiveBank` first. Keep
`AdvanceFragmentEpoch` without a bank restore and `SwitchBank` with a bank
restore.

- [x] **Step 3: Move final snapshot preparation and compact**

In `execute_standalone_publication`, move:

- final-state clone;
- released-bitmap quarantine additions; and
- `compact_and_publish_state`

to immediately after all general-map mutations succeed and before
`execute_fragment_epoch_bank_publication`.

On persistence failure, invoke `rollback_standalone_publication` with
`PersistFinalState`. On epoch or switch failure, use the existing phase mapping;
the existing rollback planner now restores the already-committed old durable
snapshot for both phases.

- [x] **Step 4: Preserve strict CT and cleanup order**

After successful epoch/bank publication:

1. call `scrub_ct_tables_strict`;
2. on failure execute the existing `StrictCtScrub` rollback;
3. on success scrub the old bank;
4. preserve released-bitmap cleanup, statistics cleanup, and response
   accounting.

Do not change batch validation, direction handling, group routing, or API
response shapes.

---

### Task 4: Review, commit GREEN, and verify hosted Rust/eBPF CI

**Files:**

- Modify: `agent/src/control_plane.rs`
- Modify: `agent/src/control_plane/standalone_acl.rs`

**Interfaces:**

- Consumes: Tasks 1-3.
- Produces: one GREEN production commit and exact hosted evidence.

- [x] **Step 1: Review the full RED-to-GREEN diff without local Cargo**

Run:

```bash
git diff --check
git diff --stat
red_commit="$(git log -1 --format=%H \
  --grep='^test: expose ACL publication durability window$')"
test -n "${red_commit}"
git diff "${red_commit}^"..HEAD -- agent/src/control_plane.rs \
  agent/src/control_plane/standalone_acl.rs
```

Confirm:

- managed and standalone both persist before epoch/switch;
- no prefix can switch the bank before final durable compact;
- persistence failure does not restore an unpublished bank;
- uncertain bank-switch failure restores the old bank before shadow scrub;
- post-durable epoch/switch failure restores old durable state;
- every compensation is attempted and all failures remain visible;
- strict CT behavior remains unchanged;
- no excluded file changed; and
- no warning suppression or checker expansion was added.

- [x] **Step 2: Commit and push GREEN**

Run:

```bash
git add agent/src/control_plane.rs \
  agent/src/control_plane/standalone_acl.rs
git commit -m "fix: persist ACL state before bank publication"
git push origin v0.9-neutron-agent
```

- [x] **Step 3: Verify the exact GREEN Build**

Run:

```bash
head_sha="$(git rev-parse HEAD)"
run_id="$(gh run list --workflow build.yml \
  --branch v0.9-neutron-agent --limit 10 \
  --json databaseId,headSha \
  --jq "map(select(.headSha == \"${head_sha}\"))[0].databaseId")"
test -n "${run_id}"
gh run watch "${run_id}" --exit-status
gh run view "${run_id}" --json headSha,status,conclusion,jobs,url
gh run view "${run_id}" --log-failed
```

Required:

- `changes`: pass;
- `fast-contracts`: pass;
- `rust-behavior`: pass with all ACL publication tests and `-D warnings`;
- `rust-build`: warning-denied eBPF, userspace-static, and agent-static builds
  pass.

If CI fails, edit only the two approved Rust files. Any required change to an
excluded area is a design deviation and must be reported before editing.

---

### Task 5: Close design, plan, and authoritative backlog

**Files:**

- Modify:
  `docs/superpowers/specs/2026-07-31-review-acl-025-durable-publication-order-design.md`
- Modify:
  `docs/superpowers/plans/2026-07-31-review-acl-025-durable-publication-order.md`
- Modify:
  `docs/openstack-neutron-aria-details/12-review-bug-backlog.md`

**Interfaces:**

- Consumes: exact RED/GREEN commits, Build IDs, job URLs, and observed test
  results.
- Produces: authoritative `REVIEW-ACL-025=fixed` evidence.

- [x] **Step 1: Correct the historical finding wording in the current row**

Record that synchronous compact failures already had immediate compensation,
while the remaining real defect was the process-crash window shared by managed
and standalone switch-before-durable ordering.

- [x] **Step 2: Record exact RED and GREEN evidence**

Add:

- exact RED commit and expected failed assertions;
- exact RED Build and `rust-behavior` job;
- exact GREEN commit;
- exact GREEN Build, `rust-behavior`, and `rust-build` jobs; and
- confirmation that no privileged field evidence applies to this ordering
  repair.

- [x] **Step 3: Mark only REVIEW-ACL-025 fixed**

Do not change the status of `REVIEW-ACL-026`, `REVIEW-ACL-044`, or any deferred
field-evidence item.

- [x] **Step 4: Commit and push closure**

Run:

```bash
git add \
  docs/superpowers/specs/2026-07-31-review-acl-025-durable-publication-order-design.md \
  docs/superpowers/plans/2026-07-31-review-acl-025-durable-publication-order.md \
  docs/openstack-neutron-aria-details/12-review-bug-backlog.md
git commit -m "docs: close durable ACL publication order"
git push origin v0.9-neutron-agent
```

- [ ] **Step 5: Verify exact-head documentation CI and repository state**

Run:

```bash
head_sha="$(git rev-parse HEAD)"
run_id="$(gh run list --workflow build.yml \
  --branch v0.9-neutron-agent --limit 10 \
  --json databaseId,headSha \
  --jq "map(select(.headSha == \"${head_sha}\"))[0].databaseId")"
test -n "${run_id}"
gh run watch "${run_id}" --exit-status
gh run view "${run_id}" --json headSha,status,conclusion,jobs,url
git status --short
git rev-list --left-right --count \
  v0.9-neutron-agent...origin/v0.9-neutron-agent
```

Expected:

- exact-head docs Build succeeds;
- worktree is clean;
- divergence is `0 0`;
- `REVIEW-ACL-025` is fixed;
- `REVIEW-ACL-026` remains the next transaction-order item; and
- all deferred privileged ACL evidence remains unchanged.

## Execution Evidence

Design commit:

- `6918d13 docs: design durable ACL publication order`
- exact-head Build
  [`30608861680`](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/30608861680)
  passed `fast-contracts` and change detection; Rust jobs correctly skipped for
  the documentation-only change.

RED evidence:

- `7f6ec55 test: expose ACL publication durability window`
- Build
  [`30609104910`](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/30609104910):
  `rust-build` job `91087741325` passed, while `rust-behavior` job
  `91087741336` failed on
  `standalone_acl_publication_persists_before_epoch_and_bank_switch` with
  `final state must be durable before fragment epoch advance`.
- `89762da test: route managed ACL durability RED through CI`
- Build
  [`30609535549`](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/30609535549):
  `rust-build` job `91089058607` passed, while `rust-behavior` job
  `91089058584` failed four managed durability/compensation contracts under
  the permanent `managed_general_delta_` selector. This second RED proves the
  managed tests were executed rather than merely compiled.

GREEN evidence:

- `4dca970 fix: persist ACL state before bank publication`
- Build
  [`30609828584`](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/30609828584)
  passed:
  - `fast-contracts` job `91089938179`;
  - `rust-behavior` job `91089985579`; and
  - `rust-build` job `91089985575`, including Rust/eBPF builds and static
    binary verification.
- Production scope remained two existing Rust files. No checker, generic
  transaction framework, new WAL format, API change, or privileged field
  claim was added.
