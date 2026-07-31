# REVIEW-TXN-024 Background Apply Failure Durability Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use
> superpowers:subagent-driven-development (recommended) or
> superpowers:executing-plans to implement this plan task-by-task. Steps use
> checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the snapshot after-intent background failure durably recoverable
without mutating the still-authoritative old datapath.

**Architecture:** Add one concrete after-intent failure handler that owns the
exact intent and previous applied runtime. It commits the previous baseline
with the failed pending identity and blocked authority before publishing RAM;
if that commit fails, it leaves the original intent pending and publishes only
an explicit live recovery-commit-failed state. Existing before-commit and WAL
commit compensation remain unchanged.

**Tech Stack:** Rust stable, Tokio, existing `NeutronWal` snapshot
intent/commit format, existing recover-pending API, GitHub Actions
`rust-behavior` and warning-denied `rust-build`.

## Global Constraints

- Work directly on local and remote `v0.9-neutron-agent`; do not create a
  branch, worktree, stacked PR, or parallel delivery line.
- Do not run local `cargo build`, `cargo check`, or `cargo test`.
- Use hosted CI for the mandatory RED and GREEN Rust evidence.
- Keep the change inside `agent/src/neutron_api.rs` plus the design, plan, and
  backlog evidence.
- Do not change the WAL schema or Status V1 contract.
- Do not modify `REVIEW-TXN-027` or `REVIEW-ACL-045`.
- Do not add a generic closure/future transaction framework.

---

### Task 1: Submit RED after-intent durability behavior

**Files:**

- Modify: `agent/src/neutron_api.rs`

**Interfaces:**

- Consumes:
  - `test_neutron_state`
  - `committed_runtime`
  - `PendingNeutronIntent`
  - `NeutronRecoverPendingRequest`
- Produces: the required concrete interface
  `handle_snapshot_after_intent_fault`.

- [x] **Step 1: Add the durable restart and recover-pending RED**

Add to the existing `neutron_api.rs` test module:

```rust
#[tokio::test]
async fn neutron_snapshot_after_intent_failure_is_durable_across_restart() {
    let root = temp_root("after-intent-durable");
    let state = test_neutron_state(&root);
    let previous = committed_runtime(40);
    state
        .wal
        .append_snapshot_commit(previous.to_wal_state())
        .unwrap();
    {
        let mut runtime = state.runtime.write().await;
        *runtime = previous.clone();
        runtime.pending_generation = Some(41);
        runtime.desired_hash = Some("hash-41".to_string());
        runtime.authority_state = "applying".to_string();
        runtime.wal_status = "intent_written".to_string();
    }
    let intent = PendingNeutronIntent {
        kind: "snapshot".to_string(),
        generation: 41,
        desired_hash: Some("hash-41".to_string()),
        ..PendingNeutronIntent::default()
    };
    state
        .wal
        .append_snapshot_intent(
            intent.generation,
            intent.desired_hash.clone(),
            intent.port_ids.clone(),
            intent.affected_domains.clone(),
            intent.affected_ports.clone(),
            intent.recovery_cause.clone(),
        )
        .unwrap();

    let error = handle_snapshot_after_intent_fault(
        &state,
        &intent,
        &previous,
        Err("forced after-intent failure".to_string()),
    )
    .await
    .expect_err("after-intent failure must be returned");
    assert_eq!(error.code, "fault_injection");

    let replay = state.wal.replay();
    assert!(replay.pending_intent.is_none());
    assert_eq!(replay.state.applied_generation, 40);
    assert_eq!(replay.state.pending_generation, Some(41));
    assert_eq!(
        replay.state.authority_state,
        "blocked_recovery_required"
    );

    let restarted = test_neutron_state(&root);
    {
        let runtime = restarted.runtime.read().await;
        assert_eq!(runtime.applied_generation, 40);
        assert_eq!(runtime.pending_generation, Some(41));
        assert_eq!(
            runtime.authority_state,
            "blocked_recovery_required"
        );
    }
    let recovered = recover_pending_snapshot(
        restarted.clone(),
        NeutronRecoverPendingRequest {
            expected_pending_generation: 41,
            expected_desired_hash: Some("hash-41".to_string()),
            mode: Some("rollback_to_last_applied".to_string()),
        },
    )
    .await
    .expect("durable blocked failure must be recoverable");
    assert_eq!(recovered.status, "recovered");
    assert_eq!(recovered.applied_generation, 40);

    let runtime = restarted.runtime.read().await;
    assert_eq!(runtime.pending_generation, None);
    assert_eq!(runtime.accepted_generation, 40);
    assert_eq!(runtime.applied_generation, 40);
    let _ = std::fs::remove_dir_all(root);
}
```

- [x] **Step 2: Add the blocked-commit-failure RED**

Use the existing `WalParentReplacement` fixture to make the blocked commit
fail after the original intent has already been written:

```rust
#[tokio::test]
async fn neutron_snapshot_after_intent_blocked_commit_failure_retains_intent() {
    let root = temp_root("after-intent-commit-failed");
    let state = test_neutron_state(&root);
    let previous = committed_runtime(50);
    state
        .wal
        .append_snapshot_commit(previous.to_wal_state())
        .unwrap();
    let intent = PendingNeutronIntent {
        kind: "snapshot".to_string(),
        generation: 51,
        desired_hash: Some("hash-51".to_string()),
        ..PendingNeutronIntent::default()
    };
    state
        .wal
        .append_snapshot_intent(
            intent.generation,
            intent.desired_hash.clone(),
            intent.port_ids.clone(),
            intent.affected_domains.clone(),
            intent.affected_ports.clone(),
            intent.recovery_cause.clone(),
        )
        .unwrap();
    let backup = root.join("after-intent-state-backup");
    let mut replacement =
        WalParentReplacement::install(&state.registry.base_state_path, &backup);

    let error = handle_snapshot_after_intent_fault(
        &state,
        &intent,
        &previous,
        Err("forced after-intent failure".to_string()),
    )
    .await
    .expect_err("primary failure must remain visible");
    replacement.restore();

    assert_eq!(error.code, "fault_injection");
    {
        let runtime = state.runtime.read().await;
        assert_eq!(runtime.pending_generation, Some(51));
        assert_eq!(
            runtime.authority_state,
            "pending_recovery_commit_failed"
        );
        assert_eq!(runtime.wal_status, "commit_failed");
    }
    let replay = state.wal.replay();
    assert_eq!(
        replay.pending_intent.as_ref().map(|pending| pending.generation),
        Some(51)
    );
    assert_eq!(replay.state.applied_generation, 50);
    let _ = std::fs::remove_dir_all(root);
}
```

- [x] **Step 3: Review and submit RED without local Cargo**

Run:

```bash
git diff --check
git diff --stat
git diff -- agent/src/neutron_api.rs
```

Confirm the diff is test-only and references the intentionally missing
`handle_snapshot_after_intent_fault`.

Commit and push:

```bash
git add agent/src/neutron_api.rs
git commit -m "test: expose snapshot background durability gap"
git push origin v0.9-neutron-agent
```

- [x] **Step 4: Record hosted RED**

Find the push Build at the exact RED commit and wait for completion.

Expected:

- `fast-contracts`: success;
- `rust-build`: fails only because the test target cannot find
  `handle_snapshot_after_intent_fault`, or passes if it does not compile tests;
- `rust-behavior`: fails on the missing helper; and
- no unrelated failure.

---

### Task 2: Implement the concrete durable after-intent handler

**Files:**

- Modify: `agent/src/neutron_api.rs`

**Interfaces:**

- Produces:

```rust
async fn handle_snapshot_after_intent_fault(
    state: &NeutronApiState,
    intent: &PendingNeutronIntent,
    previous: &NeutronRuntimeState,
    fault: Result<(), String>,
) -> Result<(), SnapshotApplyError>
```

- Consumes:
  - `build_blocked_snapshot_runtime`
  - `NeutronWal::append_snapshot_commit`
  - `mark_snapshot_background_error` preservation states.

- [x] **Step 1: Add the minimal handler**

Implement:

```rust
async fn handle_snapshot_after_intent_fault(
    state: &NeutronApiState,
    intent: &PendingNeutronIntent,
    previous: &NeutronRuntimeState,
    fault: Result<(), String>,
) -> Result<(), SnapshotApplyError> {
    let Err(details) = fault else {
        return Ok(());
    };

    let wal_status = "background_apply_failed:fault_injection";
    let mut blocked =
        build_blocked_snapshot_runtime(previous, intent, BTreeMap::new(), wal_status);
    if let Err(error) = state.wal.append_snapshot_commit(blocked.to_wal_state()) {
        blocked.authority_state = "pending_recovery_commit_failed".to_string();
        blocked.wal_status = "commit_failed".to_string();
        warn!(
            generation = intent.generation,
            desired_hash = ?intent.desired_hash,
            error = %error,
            "failed to commit preapply snapshot failure state"
        );
    }
    {
        let mut runtime = state.runtime.write().await;
        *runtime = blocked;
    }
    Err(SnapshotApplyError {
        status: StatusCode::INTERNAL_SERVER_ERROR,
        code: "fault_injection",
        details,
    })
}
```

This helper must not call `recover_intent_port`, attach, purge, detach, or any
eBPF operation.

- [x] **Step 2: Route the concrete after-intent check**

Replace the direct early return with:

```rust
handle_snapshot_after_intent_fault(
    &state,
    &intent,
    &runtime_before_apply,
    fault_injection::check("neutron.snapshot.after_intent").await,
)
.await?;
```

Do not change the existing before-commit or snapshot-commit recovery blocks.

- [x] **Step 3: Confirm background preservation**

Keep `mark_snapshot_background_error` preserving:

```text
blocked_recovery_required
wal_recovery_commit_failed
pending_recovery_commit_failed
```

The existing
`neutron_snapshot_background_error_preserves_blocked_recovery` test remains
part of the GREEN contract.

- [x] **Step 4: Review and submit GREEN**

Run:

```bash
git diff --check
python3 ci/check_blocked_terms.py
git diff --stat
git diff -- agent/src/neutron_api.rs
```

Do not run local Cargo.

Commit and push:

```bash
git add agent/src/neutron_api.rs
git commit -m "fix: persist snapshot background failure state"
git push origin v0.9-neutron-agent
```

- [x] **Step 5: Verify hosted GREEN**

At the exact production commit require:

- `fast-contracts`: success;
- `rust-behavior`: success;
- `rust-build`: success;
- both new tests pass; and
- no warning-denied Rust/eBPF compilation warning.

---

### Task 3: Close TXN-024 and hand off TXN-027

**Files:**

- Modify:
  `docs/openstack-neutron-aria-details/12-review-bug-backlog.md`
- Modify:
  `docs/superpowers/specs/2026-07-31-review-txn-024-background-failure-durability-design.md`
- Modify:
  `docs/superpowers/plans/2026-07-31-review-txn-024-background-failure-durability.md`

**Interfaces:**

- Consumes: exact RED and GREEN commit/Build evidence.
- Produces: fixed `REVIEW-TXN-024` and the next design target
  `REVIEW-TXN-027`.

- [x] **Step 1: Record exact evidence**

Record:

- RED commit and Build URL;
- GREEN commit and Build URL;
- exact tests;
- failure prefix covered; and
- the no-datapath-mutation boundary.

- [x] **Step 2: Update the Register**

Mark `REVIEW-TXN-024` fixed only after exact-head GREEN. Keep
`REVIEW-TXN-027` and `REVIEW-ACL-045` open.

- [x] **Step 3: Commit and push documentation closure**

Run documentation validation and commit:

```bash
git add docs/openstack-neutron-aria-details/12-review-bug-backlog.md \
  docs/superpowers/specs/2026-07-31-review-txn-024-background-failure-durability-design.md \
  docs/superpowers/plans/2026-07-31-review-txn-024-background-failure-durability.md
git commit -m "docs: close snapshot background durability finding"
git push origin v0.9-neutron-agent
```

Then begin the independent `REVIEW-TXN-027` design and RED cycle.

## Execution Evidence

- RED commit: `b5661c5`
- RED Build:
  [30611148868](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/30611148868)
  (`fast-contracts` passed, `rust-behavior` failed only on the two intentionally
  missing helper references, independent `rust-build` passed).
- Production commit: `95c440a`
- GREEN Build:
  [30611534447](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/30611534447)
  (`fast-contracts`, `rust-behavior`, and warning-denied `rust-build` passed).
- Privileged field evidence: not applicable; the repaired prefix occurs before
  datapath mutation.
