# REVIEW-TXN-031/034 Delete Failure Recovery Implementation Plan

**Status:** complete; exact RED/GREEN and documentation-head hosted evidence
captured

> **For agentic workers:** REQUIRED SUB-SKILL: Use
> superpowers:executing-plans to implement this plan task-by-task. Steps use
> checkbox (`- [ ]`) syntax for tracking. Execute inline on the sole
> `v0.9-neutron-agent` branch; do not create a branch, worktree, PR, or
> subagent task.

**Goal:** preserve a truthful blocked delete status and the exact unresolved
`DeleteIntent` across every post-intent failure until a matching durable
`DeleteCommit` closes forward recovery.

**Architecture:** keep the existing WAL schema and single-pending-intent model.
Replay validates commit kind and delete identity; blocked `SnapshotCommit`
records checkpoint status without resolving the delete. One concrete failure
publisher creates phase-aware port evidence, attempts the blocked checkpoint,
publishes RAM even when that checkpoint fails, and leaves successful port
absence exclusively to a matching `DeleteCommit`.

**Tech Stack:** Rust 2021, Tokio, Serde JSON, append-only Neutron WAL, Axum UDS
handler state, existing fault injection, GitHub Actions warning-denied Rust/eBPF
builds.

## Global Constraints

- Follow the approved
  [design](../specs/2026-08-13-review-txn-031-034-delete-failure-recovery-design.md)
  without widening semantics.
- Work directly on `v0.9-neutron-agent`; do not create another branch,
  worktree, or PR.
- Do not run local Cargo build, check, test, clippy, or rustfmt commands.
- Push RED and GREEN separately; hosted GitHub Actions is the Rust compiler and
  behavior authority.
- Do not change the WAL JSON schema, Status V1 vocabulary, UDS API, Python
  behavior, or snapshot rollback contract.
- Do not add a transaction ID, generic closure/future transaction framework, or
  multiple-pending-intent model.
- Do not add Python source checkers for Rust helper names, local variables,
  source order, or private function shape.
- Keep `REVIEW-TXN-032/033/035`, orphan cleanup, and unrelated ACL work out of
  this batch.
- No privileged field PASS is required or claimed for this WAL/status repair.

## File Structure

- Modify `agent/src/neutron_wal.rs`: exact commit-to-intent matching and WAL
  behavior tests.
- Modify `agent/src/neutron_api.rs`: phase-preserving purge error, blocked
  delete state/publisher, direct-delete routing, and runtime behavior tests.
- Create this plan and update the approved design after RED/GREEN evidence.
- Modify `docs/openstack-neutron-aria-details/07-transaction-wal.md`: record the
  durable blocked-checkpoint rule.
- Modify `docs/openstack-neutron-aria-details/12-review-bug-backlog.md`: record
  exact evidence only after GREEN.

---

### Task 1: RED WAL And Status Truth Behaviors

**Files:**

- Modify: `agent/src/neutron_wal.rs` test module
- Modify: `agent/src/neutron_api.rs` test module

**Interfaces:**

- Consumes: existing `NeutronWal`, `NeutronWalState`, `PendingNeutronIntent`,
  `NeutronRuntimeState`, `ManagedNeutronPort`, `NeutronApiState`, and test
  fixtures `committed_runtime`, `ready_status`, `WalParentReplacement`.
- Requires future production interface:

```rust
fn build_blocked_delete_runtime(
    previous: &NeutronRuntimeState,
    port: &ManagedNeutronPort,
    generation: u64,
    wal_status: &str,
    reason: &str,
    acl_effective_action: &'static str,
) -> NeutronRuntimeState;

async fn publish_blocked_delete_failure(
    state: &NeutronApiState,
    previous: &NeutronRuntimeState,
    port: &ManagedNeutronPort,
    generation: u64,
    wal_status: &str,
    reason: String,
    acl_effective_action: &'static str,
) -> String;
```

- [x] **Step 1: Add RED WAL checkpoint-retention behavior**

Add a test which writes a committed state containing `p1`, appends its
`DeleteIntent`, then appends a valid blocked `SnapshotCommit` with:

```rust
pending_generation: Some(generation),
desired_hash: None,
authority_state: "blocked_recovery_required".to_string(),
ports: baseline.ports.clone(),
port_statuses: blocked_statuses,
```

Assert replay returns the blocked port status and the exact pending delete
intent. The old scanner must fail because it clears `pending_intent`.

- [x] **Step 2: Add RED mismatch and exact-close WAL behaviors**

Add two tests:

1. a `DeleteCommit` which still contains `p1` or carries a different accepted
   generation increments replay failures and preserves the pending delete;
2. a matching `DeleteCommit` with the same committed generation/hash baseline,
   no pending identity, and `p1` absent clears the intent and publishes port
   absence.

Also append an invalid-status-hash commit after a delete intent and assert the
intent survives. Do not inspect scanner source text.

- [x] **Step 3: Add RED phase-aware blocked runtime behavior**

Create one committed ACL-managed port with a ready ACL `enforce` status. Call
the future builder twice and assert:

```rust
let before = build_blocked_delete_runtime(
    &previous,
    &port,
    generation,
    "delete_after_intent_failed",
    "forced after-intent failure",
    "unchanged",
);
let after = build_blocked_delete_runtime(
    &previous,
    &port,
    generation,
    "delete_detach_failed",
    "forced detach failure",
    "bypass",
);
```

Both retain the port, set the hashless pending identity, and make the port
non-ready. The ACL domain must be `unchanged` in `before` and `bypass` in
`after`; neither may remain `ready/enforce`.

- [x] **Step 4: Add RED blocked-checkpoint failure behavior**

Append the baseline commit and delete intent, replace the WAL parent with the
existing `WalParentReplacement`, and call
`publish_blocked_delete_failure(..., "bypass")`. Assert:

- the returned error contains both the primary failure and blocked-checkpoint
  failure;
- RAM retains the port with `pending_generation`, blocked authority, and
  non-ready ACL `bypass` evidence;
- replay still returns the original delete intent and committed baseline.

- [x] **Step 5: Run allowed local checks**

Run:

```bash
python3 ci/check_blocked_terms.py
git diff --check
```

Expected: exit 0. Do not run Cargo locally.

- [x] **Step 6: Commit and push RED**

```bash
git add agent/src/neutron_wal.rs agent/src/neutron_api.rs
git commit -m "test: expose delete intent loss"
git push origin v0.9-neutron-agent
```

- [x] **Step 7: Capture exact hosted RED**

RED `db14bfa` / Build
[31697811403](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/31697811403)
failed in `rust-behavior` with `E0061` and `E0425`, exactly exposing the old
builder signature and absent failure publisher. Fast contracts passed; the
remaining long build was cancelled after the RED evidence was durable.

Require `rust-behavior` to fail only because the old scanner clears the delete
intent and the two future blocked-delete interfaces are missing or have the old
signature. `fast-contracts` and unrelated build lanes must remain green. Record
the exact commit, Build URL, failing job, and failure names before editing
production code.

---

### Task 2: GREEN Commit-To-Intent Matching

**Files:**

- Modify: `agent/src/neutron_wal.rs`
- Test: `agent/src/neutron_wal.rs`

**Interfaces:**

- Produces:

```rust
fn blocked_delete_snapshot_commit_valid(
    state: &NeutronWalState,
    intent: &PendingNeutronIntent,
    baseline: &NeutronWalState,
) -> Result<bool, String>;

fn matching_delete_commit_valid(
    state: &NeutronWalState,
    intent: &PendingNeutronIntent,
    baseline: &NeutronWalState,
) -> Result<bool, String>;
```

- [x] **Step 1: Implement blocked snapshot checkpoint validation**

Require the future design fields exactly:

```rust
state.status_hash.is_some()
    && state.status_hash_valid()?
    && state.pending_generation == Some(intent.generation)
    && state.desired_hash.is_none()
    && state.authority_state == "blocked_recovery_required"
    && state.accepted_generation == baseline.accepted_generation
    && state.applied_generation == baseline.applied_generation
    && state.applied_desired_hash == baseline.applied_desired_hash
    && intent.port_ids.iter().all(|id| {
        state.ports.contains_key(id) && state.port_statuses.contains_key(id)
    })
```

Reject non-delete intents at the helper boundary.

- [x] **Step 2: Implement matching delete commit validation**

Require valid hashed state, `accepted_generation == intent.generation`, the
same accepted/applied/applied-hash baseline, no pending generation, restored
`desired_hash == applied_desired_hash`, and absence of every intended port from
both maps.

- [x] **Step 3: Split replay by pending intent kind and commit kind**

Preserve the protected-inventory branch first. Then implement:

- pending delete + valid blocked `SnapshotCommit`: update
  `last_committed_state`, retain intent;
- pending delete + matching `DeleteCommit`: update committed state and clear;
- pending delete + any other commit: increment failures and retain intent;
- pending snapshot + `DeleteCommit`: increment failures and retain intent;
- invalid commit hash: increment failures and retain any pending intent;
- no pending intent: preserve existing valid commit behavior;
- ordinary pending snapshot + valid `SnapshotCommit`: preserve existing
  completion behavior.

- [x] **Step 4: Review checkpoint/legacy compatibility**

Inspect `checkpoint_entries`, protected inventory tests, legacy hashless commit
tests, and existing snapshot intent tests. Do not change record serialization or
checkpoint file format. The blocked checkpoint plus retained intent must remain
representable as the last valid commit followed by one pending intent.

Do not commit yet; Task 3 completes the same GREEN transaction boundary.

---

### Task 3: GREEN Phase-Aware Failure Publication

**Files:**

- Modify: `agent/src/neutron_api.rs`
- Test: `agent/src/neutron_api.rs`

**Interfaces:**

- Consumes: Task 2 replay behavior.
- Produces the exact builder/publisher signatures declared in Task 1.
- Changes `purge_neutron_acl_transactionally` to:

```rust
async fn purge_neutron_acl_transactionally(
    state: &NeutronApiState,
    ifname: &str,
    port_id: &str,
) -> Result<OwnedAclReconcileReport, NeutronAclReconcileError>;
```

- [x] **Step 1: Preserve ACL purge failure phase**

Map runtime-gate update failure with
`acl_reconcile_error(AclReconcileFailurePhase::BeforeQuiesce, ...)` and owned
publication/strict-flush failure with
`acl_reconcile_error(AclReconcileFailurePhase::AfterQuiesce, ...)`.

Update existing non-direct-delete callers to use `error.details` where they
previously formatted the string. Do not change their control flow or absorb
their status semantics into this batch.

- [x] **Step 2: Implement the phase-aware blocked runtime builder**

Clone the previous runtime, retain the port, set the hashless pending fields,
and replace the affected port status. Include `attach` plus normalized managed
domains. Every domain becomes non-ready with the exact stable reason; the ACL
domain uses `domain_status_with_action` and the supplied `unchanged` or
`bypass`. No other port status changes.

- [x] **Step 3: Implement the concrete blocked failure publisher**

Build the blocked runtime and call
`state.wal.append_snapshot_commit(blocked.to_wal_state())` before RAM
publication. On success preserve the requested phase `wal_status`. On failure:

```rust
blocked.wal_status = "delete_blocked_checkpoint_failed".to_string();
```

Publish RAM in both cases. Return the original error text on success or a
combined string such as
`forced detach failure; delete_blocked_checkpoint_failed:forced write failure`
on checkpoint failure. Do not clear the intent or remove the port.

- [x] **Step 4: Route every post-intent direct-delete failure**

Use the publisher at these exact boundaries:

| Boundary | WAL status | ACL action |
| --- | --- | --- |
| `after_intent` | `delete_after_intent_failed` | `unchanged` |
| purge typed error | `delete_acl_purge_failed` | `error.effective_action` |
| `after_acl_purge` | `delete_after_acl_purge_failed` | `bypass` |
| registry detach error | `delete_detach_failed` | `bypass` |
| after-detach fault | `delete_after_detach_failed` | `bypass` |
| delete commit failure | `delete_commit_failed` | `bypass` |

Every response remains HTTP 500, `status=error`, and `detached=false`. The
normal not-found and successful durable delete responses remain unchanged.

- [x] **Step 5: Reuse truthful blocked status in startup recovery failures**

Update `finalize_recovered_delete_intent` to build the same non-ready retained
port evidence from the recovery result. Successful recovery still appends
`DeleteCommit` and removes the port only afterward. A recovery-commit failure
retains the intent and reports ACL `bypass` when recovery was quiesced.

- [x] **Step 6: Run allowed local checks**

Run:

```bash
python3 -m unittest ci.test_ci_lane_contract -v
python3 ci/check_blocked_terms.py
git diff --check
```

Expected: all pass. Do not run Cargo locally.

- [x] **Step 7: Commit and push GREEN**

```bash
git add agent/src/neutron_wal.rs agent/src/neutron_api.rs
git commit -m "fix: preserve failed delete recovery"
git push origin v0.9-neutron-agent
```

- [x] **Step 8: Require exact-head hosted GREEN**

GREEN implementation `477761e` and compatibility follow-up `d8ae123` passed
exact-head Build
[31698764813](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/31698764813):
`fast-contracts`, `rust-behavior`, warning-denied `rust-build`, eBPF stack
budget, database contracts, and clean install were all successful.

Require:

- `fast-contracts`: green;
- `rust-behavior`: all new and existing `neutron_wal`/`neutron_api` behaviors
  green with warnings denied;
- `rust-build`: warning-denied userspace, agent, and eBPF builds green;
- no test filtering reports zero executed tests.

If hosted compilation fails, correct production code within this design. Do
not weaken tests, suppress warnings, or expand into another REVIEW item.

---

### Task 4: Contract And Register Closure

**Files:**

- Modify:
  `docs/superpowers/specs/2026-08-13-review-txn-031-034-delete-failure-recovery-design.md`
- Modify:
  `docs/superpowers/plans/2026-08-13-review-txn-031-034-delete-failure-recovery.md`
- Modify: `docs/openstack-neutron-aria-details/07-transaction-wal.md`
- Modify: `docs/openstack-neutron-aria-details/12-review-bug-backlog.md`
- Modify:
  `docs/superpowers/specs/2026-08-13-bug-hunt-remediation-program-design.md`

**Interfaces:**

- Consumes: exact RED commit/run and GREEN commit/run from Tasks 1 and 3.
- Produces: authoritative fixed status for `REVIEW-TXN-031/034` and next-batch
  handoff to `REVIEW-TXN-032`.

- [x] **Step 1: Update design and transaction contract**

Record the implemented matching matrix and concrete evidence. Add the durable
rule to `07-transaction-wal.md`: a blocked `SnapshotCommit` may checkpoint an
unresolved delete but never resolves it; only a matching `DeleteCommit` does.

- [x] **Step 2: Update the REVIEW rows**

Set both rows to `fixed` only after exact-head GREEN. Record exact RED/GREEN
commits and Build links, the phase-aware status result, intent retention, and
successful forward retry. State explicitly that no WAL schema or privileged
field evidence applies.

- [x] **Step 3: Advance the program index**

Mark this source/CI batch complete in the program narrative and identify
`REVIEW-TXN-032` atomic `state.json` persistence as the next fixed-order batch.
Do not alter severities or pull later work forward.

- [x] **Step 4: Validate documentation closure**

Run:

```bash
python3 ci/check_blocked_terms.py
python3 -m unittest ci.test_public_release_hygiene ci.test_ci_lane_contract -v
git diff --check
```

Expected: all pass.

- [x] **Step 5: Commit and push closure**

```bash
git add docs/superpowers/specs/2026-08-13-review-txn-031-034-delete-failure-recovery-design.md \
  docs/superpowers/plans/2026-08-13-review-txn-031-034-delete-failure-recovery.md \
  docs/openstack-neutron-aria-details/07-transaction-wal.md \
  docs/openstack-neutron-aria-details/12-review-bug-backlog.md \
  docs/superpowers/specs/2026-08-13-bug-hunt-remediation-program-design.md
git commit -m "docs: close delete failure recovery"
git push origin v0.9-neutron-agent
```

- [x] **Step 6: Verify final exact-head state**

Require the documentation HEAD Build to pass its selected fast/static lanes,
then verify a clean worktree and divergence `0 0`. Do not relabel the hosted
run as privileged datapath evidence.

Closure commit `2a7f58a` / Build
[31699371226](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/31699371226)
passed every selected docs/fast/static lane. This is hosted contract evidence,
not privileged datapath evidence.

---

## Plan Self-Review

- Spec coverage: WAL kind/identity matching, invalid/mismatched commit
  retention, phase-aware action, durable blocked checkpoint, RAM fallback,
  restart forward recovery, legacy/checkpoint compatibility, hosted evidence,
  and register closure each have an owning task.
- Scope: the two Rust production files and named documentation files are the
  complete boundary; no WAL schema, Python, generic transaction framework, or
  later REVIEW item is included.
- Type consistency: the blocked builder/publisher and typed purge result have
  one exact signature across RED and GREEN tasks.
- Evidence: local commands are Cargo-free; RED and GREEN use separate commits
  and exact hosted Build evidence.
