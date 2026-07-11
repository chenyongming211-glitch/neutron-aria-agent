# ACL Batch 2 WAL Atomicity Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make snapshot intent, ACL runtime mutation, WAL commit, RAM publication, and pending recovery crash-consistent for `REVIEW-TXN-021`, `REVIEW-TXN-022`, and `REVIEW-TXN-025`.

**Architecture:** A new snapshot fsyncs its WAL intent while holding an owned apply lock, then returns `pending` without advancing `accepted_generation`; the same lock and prebuilt transaction move into the background task. Transaction failures before commit restore attach topology and scrub ACL to bypass, while a successful commit is published to RAM before any fallible post-commit hook. Recover-pending replays WAL before rollback, and Python prioritizes blocked recovery over same-hash waiting.

**Tech Stack:** Rust, Tokio, Axum, append-only JSON WAL, Python 2/3-compatible Neutron agent code, `unittest`, GitHub Actions.

## Global Constraints

- Implement only `REVIEW-TXN-021`, `REVIEW-TXN-022`, and `REVIEW-TXN-025`.
- Preserve OVS forwarding; a transaction-level ACL failure produces blocked/bypass.
- Do not add an ACL preimage, new WAL backend, WAL compaction, or delete-path fixes.
- Never run local `cargo build`, `cargo check`, or `cargo test`; GitHub Actions provides Rust evidence.
- Preserve and exclude the user's uncommitted `README.md` change.
- Use red-green-refactor and small commits.

## File Map

| File | Responsibility |
| --- | --- |
| `agent/src/neutron_api.rs` | Durable admission, owned lock handoff, failure recovery, commit publication, anti-regression, Rust tests. |
| `agent/src/neutron_wal.rs` | Read-only reference; existing `replay()` already supplies the durable comparison state. |
| `openstack/neutron_aria/neutron_aria/agent/event_loop.py` | Recover blocked pending state before same-hash waiting. |
| `openstack/neutron_aria/neutron_aria/tests/unit/test_event_loop.py` | Python recovery regression coverage. |
| `docs/openstack-neutron-aria-details/07-transaction-wal.md` | Current durable pending/accepted semantics. |
| `docs/openstack-neutron-agent-mode.md` | Authoritative transaction wording. |
| `docs/openstack-neutron-aria-details/12-review-bug-backlog.md` | Closure evidence and counts after CI. |

---

### Task 1: Durable Intent Before Pending Response

**Files:**
- Modify: `agent/src/neutron_api.rs:836-1190`
- Test: `agent/src/neutron_api.rs` snapshot submission tests

**Interfaces:**
- Produces: `PreparedSnapshotApply` containing `OwnedMutexGuard<()>`, `PendingNeutronIntent`, `SnapshotApplyTransaction`, committed baseline state, and timing metadata.
- Produces: `SnapshotSubmitDecision.prepared: Option<PreparedSnapshotApply>`.
- Consumes: `validate_snapshot_preflight`, `snapshot_early_response_for_scope`, `build_snapshot_apply_transaction`, and `append_snapshot_intent`.

- [ ] **Step 1: Write failing durable-admission tests**

Add assertions for a new generation:

```rust
assert_eq!(decision.response.status, "pending");
assert_eq!(decision.response.accepted_generation, previous_generation);
assert_eq!(decision.response.applied_generation, previous_generation);
assert!(decision.prepared.is_some());

let runtime = state.runtime.read().await;
assert_eq!(runtime.accepted_generation, previous_generation);
assert_eq!(runtime.pending_generation, Some(next_generation));
assert_eq!(runtime.authority_state, "applying");
drop(runtime);

let replay = state.wal.replay();
assert_eq!(replay.state.accepted_generation, previous_generation);
assert_eq!(replay.state.pending_generation, Some(next_generation));
assert_eq!(replay.pending_intent.unwrap().generation, next_generation);
```

Add an invalid/unwritable WAL path test expecting `wal_intent_failed` and unchanged RAM.

- [ ] **Step 2: Obtain red Rust evidence through GitHub Actions**

Commit only tests, push, and dispatch Build:

```bash
git add agent/src/neutron_api.rs
git commit -m "test: require durable snapshot pending handoff"
git push -u origin codex/acl-batch-2-wal-atomicity
gh workflow run Build --ref codex/acl-batch-2-wal-atomicity -f publish_artifacts=false
```

Expected: Rust compile/test failure because the prepared handoff does not exist.

- [ ] **Step 3: Implement the prepared apply boundary**

Define the owned handoff:

```rust
use tokio::sync::{Mutex, OwnedMutexGuard, RwLock};

struct PreparedSnapshotApply {
    _apply_guard: OwnedMutexGuard<()>,
    intent: PendingNeutronIntent,
    transaction: SnapshotApplyTransaction,
    current_ports: BTreeMap<String, ManagedNeutronPort>,
    runtime_before_apply: NeutronRuntimeState,
    lock_wait_ms: u64,
    preflight_ms: u64,
    wal_intent_ms: u64,
}

struct SnapshotSubmitDecision {
    response: NeutronSnapshotResponse,
    prepared: Option<PreparedSnapshotApply>,
}
```

For the new-snapshot path, acquire `state.apply_lock.clone().lock_owned().await`, repeat pending/idempotency checks, build `SnapshotApplyTransaction`, append/fsync intent, then publish only:

```rust
runtime.pending_generation = Some(snapshot.generation);
runtime.desired_hash = requested_hash.clone();
runtime.authority_state = "applying".to_string();
runtime.wal_status = "intent_written".to_string();
```

Do not modify accepted/applied. Return `status="pending"` with their previous values. Move the guard and prepared transaction into the background task; the apply body must not reacquire the lock, rebuild the plan, or append a second intent.

- [ ] **Step 4: Verify and commit Task 1**

Run Stage 1/2 and `git diff --check`, commit production code as:

```bash
git commit -m "fix: persist snapshot intent before pending response"
```

Push and dispatch Build. Expected: Task 1 tests and the complete workflow pass.

---

### Task 2: Scrub ACL And Block On Pre-Commit Failure

**Files:**
- Modify: `agent/src/neutron_api.rs:393-590, 1128-1170`
- Test: `agent/src/neutron_api.rs` recovery and transaction tests

**Interfaces:**
- Consumes: `PendingNeutronIntent`, `affected_ports_for_intent`, `recover_intent_port`, and the committed baseline from `PreparedSnapshotApply`.
- Produces: `recover_failed_snapshot_transaction(...) -> NeutronRuntimeState`.

- [ ] **Step 1: Write failing blocked-recovery tests**

Assert the failure result keeps the committed generations and classifies ACL conservatively:

```rust
assert_eq!(blocked.accepted_generation, previous.accepted_generation);
assert_eq!(blocked.applied_generation, previous.applied_generation);
assert_eq!(blocked.pending_generation, Some(failed_generation));
assert_eq!(blocked.authority_state, "blocked_recovery_required");
assert!(blocked.port_statuses.values().all(|status| {
    status.status == "blocked" && status.domains.iter().any(|domain| {
        domain.domain == "acl"
            && domain.status == "blocked"
            && domain.effective_action.as_deref() == Some("bypass")
    })
}));
```

Cover `before_commit`, commit append failure, and refusal to prepare a second snapshot while recovery remains pending.

- [ ] **Step 2: Obtain red CI evidence**

Commit/push only the tests and dispatch Build. Expected: current code leaves mutated ACL live and only sets `wal_commit_failed` metadata.

- [ ] **Step 3: Implement shared transaction failure recovery**

Add:

```rust
async fn recover_failed_snapshot_transaction(
    state: &NeutronApiState,
    intent: &PendingNeutronIntent,
    previous: &NeutronRuntimeState,
    reason: &str,
) -> NeutronRuntimeState
```

Reuse attach/ACL intent recovery for every affected port. Build the result from `previous.clone()`, retain previous accepted/applied and committed inventory, set failed pending/hash, and classify ACL using:

```rust
domain_status_with_action(
    "acl",
    "blocked",
    Some(reason.to_string()),
    Some("bypass".to_string()),
)
```

Set `authority_state="blocked_recovery_required"`. Attempt to append the blocked classified state; if it fails, publish RAM blocked with `wal_status="recovery_commit_failed"` and retain the original intent for restart.

Route both `neutron.snapshot.before_commit` and `append_snapshot_commit` failures through this helper. Prevent `mark_snapshot_background_error` from overwriting blocked/recovery states with generic degraded status.

- [ ] **Step 4: Verify and commit Task 2**

Run Stage 1/2 and `git diff --check`, then commit:

```bash
git commit -m "fix: scrub acl after snapshot commit failure"
```

Push and dispatch Build. Expected: recovery tests, eBPF, and static agent build pass.

---

### Task 3: Make Durable Commit Final And Guard Recovery

**Files:**
- Modify: `agent/src/neutron_api.rs:664-780, 1148-1185`
- Test: `agent/src/neutron_api.rs` recover-pending tests
- Read: `agent/src/neutron_wal.rs` existing replay contract

**Interfaces:**
- Produces: `wal_state_newer_than_runtime(&NeutronWalState, &NeutronRuntimeState) -> bool`.
- Produces: recovery `status="already_committed"` when WAL proves RAM stale.

- [ ] **Step 1: Write failing finality tests**

After a successful commit and return-error at `after_commit`, assert:

```rust
assert_eq!(runtime.accepted_generation, generation);
assert_eq!(runtime.applied_generation, generation);
assert_eq!(runtime.pending_generation, None);
assert_eq!(runtime.authority_state, "ready");
assert_eq!(state.wal.replay().state.applied_generation, generation);
```

Add a stale-RAM test: RAM is N/pending N+1 while WAL is committed N+1. Recover-pending must return `already_committed`, refresh RAM to N+1, and not append generation N.

- [ ] **Step 2: Obtain red CI evidence**

Commit/push tests and dispatch Build. Expected: current `after_commit` path skips RAM assignment and current recovery appends the old RAM view.

- [ ] **Step 3: Publish RAM before post-commit hooks**

Immediately after commit fsync:

```rust
{
    let mut runtime = state.runtime.write().await;
    *runtime = next_runtime.clone();
}

if let Err(error) = fault_injection::check("neutron.snapshot.after_commit").await {
    warn!(
        generation = snapshot.generation,
        error = %error,
        "post-commit snapshot hook failed after durable commit"
    );
}
```

Do not return an error for a return-error action after commit. Process-exit still terminates and restart replay restores WAL.

- [ ] **Step 4: Replay WAL before pending rollback**

Use:

```rust
fn wal_state_newer_than_runtime(
    wal: &NeutronWalState,
    runtime: &NeutronRuntimeState,
) -> bool {
    wal.applied_generation > runtime.applied_generation
        || wal.accepted_generation > runtime.accepted_generation
}
```

Under the apply lock, replay WAL before `recover_pending_runtime`. When a newer valid commit has no superseding unresolved intent, refresh RAM through `NeutronRuntimeState::from_wal_state`, return `already_committed`, and do not append rollback state.

- [ ] **Step 5: Verify and commit Task 3**

Run Stage checks and commit:

```bash
git commit -m "fix: make snapshot wal commit final"
```

Push and dispatch Build. Expected: Task 3 and full Build pass.

---

### Task 4: Recover Blocked Same-Hash Pending In Python

**Files:**
- Modify: `openstack/neutron_aria/neutron_aria/agent/event_loop.py:120-260, 1000-1150`
- Test: `openstack/neutron_aria/neutron_aria/tests/unit/test_event_loop.py`

**Interfaces:**
- Produces: `_status_requires_pending_recovery(status) -> bool`.
- Extends: `_remote_pending_action` with `action="recover"` before same-hash `wait`.
- Consumes: `_recover_remote_pending_snapshot` and generation-floor preparation.

- [ ] **Step 1: Write failing Python tests**

Use:

```python
blocked_status = {
    "accepted_generation": 10,
    "applied_generation": 10,
    "pending_generation": 11,
    "desired_hash": "hash-11",
    "applied_desired_hash": "hash-10",
    "authority_state": "blocked_recovery_required",
}
```

Assert same-hash `_remote_pending_action` returns `recover`, successful full resync calls `recover_pending_snapshot(11, "hash-11")` and submits above the refreshed generation floor, and failed recovery preserves local pending/degraded state.

- [ ] **Step 2: Run focused test and verify red**

```bash
PYTHONPATH=openstack/neutron_aria \
python3 -m unittest neutron_aria.tests.unit.test_event_loop
```

Expected: FAIL because blocked same-hash currently returns `wait`.

- [ ] **Step 3: Implement blocked recovery priority**

Add:

```python
RECOVERY_REQUIRED_AUTHORITY_STATES = frozenset((
    "blocked_recovery_required",
    "wal_commit_failed",
    "wal_recovery_commit_failed",
    "recovered_pending_full_resync",
))

def _status_requires_pending_recovery(self, status):
    return bool(
        status and
        status.get("pending_generation") and
        status.get("authority_state") in RECOVERY_REQUIRED_AUTHORITY_STATES
    )
```

Check it before hash comparison in `_remote_pending_action`. In `full_resync`, recover exact remote generation/hash, re-read status, recompute the floor, and prepare a fresh snapshot. Never clear local pending when recovery fails.

- [ ] **Step 4: Run focused and full Python tests**

```bash
PYTHONPATH=openstack/neutron_aria \
python3 -m unittest neutron_aria.tests.unit.test_event_loop
PYTHONPATH=openstack/neutron_aria \
python3 -m unittest discover \
  -s openstack/neutron_aria/neutron_aria/tests \
  -p 'test_*.py'
```

Expected: all pass.

- [ ] **Step 5: Commit Task 4**

```bash
git add openstack/neutron_aria/neutron_aria/agent/event_loop.py \
  openstack/neutron_aria/neutron_aria/tests/unit/test_event_loop.py
git commit -m "fix: recover blocked neutron snapshot transactions"
```

---

### Task 5: Documentation, Closure, And Delivery

**Files:**
- Modify: `docs/openstack-neutron-aria-details/07-transaction-wal.md`
- Modify: `docs/openstack-neutron-agent-mode.md`
- Modify: `docs/openstack-neutron-aria-details/12-review-bug-backlog.md`

**Interfaces:**
- Consumes: final implementation and CI evidence.
- Produces: authoritative transaction wording and correct tracking counts.

- [ ] **Step 1: Update transaction documentation**

Document:

```text
validate/plan -> intent fsync -> pending response -> runtime apply
-> commit fsync -> RAM/status publication
```

State that accepted is commit-classified, intent-only is pending, commit failure scrubs ACL to bypass, and post-commit return-error cannot regress a commit.

- [ ] **Step 2: Run all allowed local verification**

```bash
PYTHONPATH=openstack/neutron_aria python3 -m unittest discover \
  -s openstack/neutron_aria/neutron_aria/tests -p 'test_*.py'
PYTHONPATH=openstack/neutron_aria:openstack/neutronclient_aria \
  python3 -m unittest discover \
  -s openstack/neutronclient_aria/neutronclient_aria/tests -p 'test_*.py'
python3 -m compileall -q openstack/neutron_aria/neutron_aria \
  openstack/neutronclient_aria/neutronclient_aria
python3 ci/check_neutron_stage1.py
python3 ci/check_neutron_stage2_acl.py
python3 ci/check_stage3_readiness.py
python3 ci/check_smoke_python_blocks.py
bash -n install.sh
find deploy ci -type f -name '*.sh' -exec bash -n {} +
git diff --check
```

Expected: all exit 0; local Rust execution remains skipped.

- [ ] **Step 3: Close the three backlog IDs after CI passes**

Change `REVIEW-TXN-021`, `REVIEW-TXN-022`, and `REVIEW-TXN-025` to fixed, add closure evidence, and update unique counts from `open 41 / fixed 15` to `open 38 / fixed 18`. Keep REVIEW total 60, RISK 5, DEBT 4, and total tracking items 69.

- [ ] **Step 4: Commit documentation**

```bash
git add docs/openstack-neutron-aria-details/07-transaction-wal.md \
  docs/openstack-neutron-agent-mode.md \
  docs/openstack-neutron-aria-details/12-review-bug-backlog.md
git commit -m "docs: close acl wal atomicity batch"
```

- [ ] **Step 5: Push and run final Build**

```bash
git push
gh workflow run Build --ref codex/acl-batch-2-wal-atomicity \
  -f publish_artifacts=false
run_id="$(gh run list --branch codex/acl-batch-2-wal-atomicity \
  --workflow Build --limit 1 --json databaseId --jq '.[0].databaseId')"
gh run watch "${run_id}" --exit-status
```

Expected: Python stages, Rust tests, eBPF, userspace/agent static builds, and binary verification pass.

- [ ] **Step 6: Audit branch**

Verify remote/local SHA equality, exclude `README.md`, and do not create a PR or merge unless requested.
