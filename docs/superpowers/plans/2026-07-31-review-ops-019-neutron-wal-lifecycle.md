# REVIEW-OPS-019 Neutron WAL Lifecycle Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use
> superpowers:subagent-driven-development (recommended) or
> superpowers:executing-plans to implement this plan task-by-task. Steps use
> checkbox (`- [ ]`) syntax for tracking.

**Goal:** Bound `neutron-snapshot.wal` with crash-safe canonical compaction
while preserving the existing committed-state and unresolved-intent replay
contract.

**Architecture:** Refactor the existing replay loop into one internal scan that
retains the undecorated last commit and at most one pending intent. Before an
append crosses 16 MiB, serialize that canonical scan to a same-directory
temporary file, enforce a 64 MiB post-checkpoint limit, install it with
file-fsync/rename/directory-fsync ordering, and then use the existing durable
append path. Replay uncertainty prevents compaction.

**Tech Stack:** Rust stable, `serde_json`, synchronous `std::fs`, SHA-256
integrity already present in `agent/src/neutron_wal.rs`, GitHub Actions
`rust-behavior` and warning-denied `rust-build`.

## Global Constraints

- Work directly on local and remote `v0.9-neutron-agent`; do not create a
  branch, worktree, stacked PR, or parallel delivery line.
- Do not run local `cargo build`, `cargo check`, or `cargo test`.
- Verify Rust RED and GREEN only through GitHub Actions.
- Keep the production implementation in `agent/src/neutron_wal.rs` unless RED
  proves the existing `neutron_api.rs` error mapping is insufficient.
- Preserve the existing JSON-lines `NeutronWalEntry` format and public
  `NeutronWalReplay` meanings.
- Use fixed production thresholds of 16 MiB soft and 64 MiB hard.
- Do not add a background task, timer, deployment option, rotated segment,
  snapshot sidecar, or automatic corrupt-WAL repair.
- Do not change ACL/CT forwarding behavior or claim privileged field evidence.

---

### Task 1: Submit the RED lifecycle behavior contract

**Files:**

- Modify: `agent/src/neutron_wal.rs`

**Interfaces:**

- Consumes: existing `NeutronWal::new`, append methods, replay behavior,
  `neutron_wal_baseline_state`, and raw JSON fixture helpers.
- Produces for later tasks:
  - `NeutronWalLimits { soft_bytes: u64, hard_bytes: u64 }`
  - `NeutronWal::with_limits(base_state_path, limits)`
  - `NeutronWal::compact_now_for_test()`
  - `NeutronWal::checkpoint_temp_path_for_test()`

- [x] **Step 1: Add test helpers that describe the missing lifecycle interface**

Add inside `#[cfg(test)] mod tests`:

```rust
    fn lifecycle_wal(root: &Path, soft_bytes: u64, hard_bytes: u64) -> NeutronWal {
        NeutronWal::with_limits(
            root,
            NeutronWalLimits {
                soft_bytes,
                hard_bytes,
            },
        )
    }

    fn wal_bytes(root: &Path) -> Vec<u8> {
        fs::read(root.join(WAL_FILE)).expect("WAL bytes should be readable")
    }

    fn append_ready_commit(wal: &NeutronWal, generation: u64) {
        wal.append_snapshot_commit(neutron_wal_baseline_state(generation))
            .expect("ready commit should be durable");
    }
```

- [x] **Step 2: Add RED tests for bounded commits and exact replay**

Add:

```rust
    #[test]
    fn neutron_wal_compaction_bounds_repeated_commits_and_replays_latest_state() {
        let root = temp_state_path();
        let wal = lifecycle_wal(&root, 1, 16 * 1024);

        for generation in 1..=40 {
            append_ready_commit(&wal, generation);
        }

        let raw = wal_bytes(&root);
        let replay = wal.replay();
        assert!(raw.len() <= 16 * 1024);
        assert_eq!(40, replay.state.applied_generation);
        assert_eq!(Some("hash-40".to_string()), replay.state.applied_desired_hash);
        assert_eq!(0, replay.failures);
        assert!(replay.pending_intent.is_none());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn neutron_wal_compaction_preserves_snapshot_pending_baseline() {
        let root = temp_state_path();
        let wal = lifecycle_wal(&root, 1, 16 * 1024);
        append_ready_commit(&wal, 10);
        wal.append_snapshot_intent(
            11,
            Some("hash-11".to_string()),
            vec!["p2".to_string()],
            vec!["attach".to_string(), "acl".to_string()],
            vec![managed("p2", "tap-p2")],
            None,
        )
        .unwrap();
        wal.compact_now_for_test().unwrap();

        let replay = wal.replay();
        assert_eq!(10, replay.state.applied_generation);
        assert_eq!(Some("hash-10".to_string()), replay.state.applied_desired_hash);
        assert_eq!(Some(11), replay.state.pending_generation);
        assert_eq!("wal_intent_without_commit", replay.state.authority_state);
        assert_eq!("snapshot", replay.pending_intent.unwrap().kind);
        let _ = fs::remove_dir_all(root);
    }
```

- [x] **Step 3: Add RED tests for delete and protected pending intents**

Add:

```rust
    #[test]
    fn neutron_wal_compaction_preserves_legacy_delete_intent_without_port() {
        let root = temp_state_path();
        let wal = lifecycle_wal(&root, 1, 16 * 1024);
        append_ready_commit(&wal, 20);
        append_wal_value(
            &root,
            &serde_json::json!({
                "type": "delete_intent",
                "port_id": "p1",
                "generation": 21,
                "affected_domains": ["attach", "acl"]
            }),
        );
        wal.compact_now_for_test().unwrap();

        let replay = wal.replay();
        let intent = replay.pending_intent.unwrap();
        assert_eq!("delete", intent.kind);
        assert_eq!(21, intent.generation);
        assert_eq!(vec!["p1".to_string()], intent.port_ids);
        assert!(intent.affected_ports.is_empty());
        assert_eq!(20, replay.state.applied_generation);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn neutron_wal_compaction_preserves_protected_inventory_intent_and_closure() {
        let root = temp_state_path();
        let wal = lifecycle_wal(&root, 1, 16 * 1024);
        let baseline = neutron_wal_baseline_state(30);
        wal.append_snapshot_commit(baseline.clone()).unwrap();
        append_protected_inventory_intent(&wal, 31);
        wal.compact_now_for_test().unwrap();

        let replay = wal.replay();
        assert_eq!(0, replay.failures);
        assert_eq!("intent_without_commit", replay.status);
        let intent = replay.pending_intent.clone().unwrap();
        assert_eq!(
            Some(INVENTORY_UNAVAILABLE_RECOVERY_CAUSE),
            intent.recovery_cause.as_deref()
        );
        let blocked = protected_inventory_resolver_state(&baseline, 31);
        let resolved = wal
            .append_verified_protected_inventory_commit(&intent, blocked)
            .unwrap();
        assert_eq!(INVENTORY_UNAVAILABLE_RECOVERY_CAUSE, resolved.status);
        assert!(resolved.pending_intent.is_none());
        let _ = fs::remove_dir_all(root);
    }
```

- [x] **Step 4: Add RED tests for corruption, hard capacity, and stale temp**

Add:

```rust
    #[test]
    fn neutron_wal_compaction_refuses_uncertain_replay_and_preserves_prefix() {
        let root = temp_state_path();
        let wal = lifecycle_wal(&root, 1, 64 * 1024);
        append_ready_commit(&wal, 40);
        let path = root.join(WAL_FILE);
        let mut raw = wal_bytes(&root);
        raw.extend_from_slice(b"{not-json}\n");
        fs::write(&path, &raw).unwrap();

        append_ready_commit(&wal, 41);

        let after = wal_bytes(&root);
        assert!(after.starts_with(&raw));
        assert_eq!(1, wal.replay().failures);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn neutron_wal_hard_capacity_rejection_preserves_live_bytes() {
        let root = temp_state_path();
        let seed = NeutronWal::new(&root);
        append_ready_commit(&seed, 50);
        let before = wal_bytes(&root);
        let wal = lifecycle_wal(&root, 1, 1);

        let error = wal
            .append_snapshot_commit(neutron_wal_baseline_state(51))
            .unwrap_err();

        assert!(error.starts_with("neutron WAL hard capacity exceeded"));
        assert_eq!(before, wal_bytes(&root));
        assert_eq!(50, wal.replay().state.applied_generation);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn neutron_wal_ignores_and_replaces_stale_checkpoint_temp_file() {
        let root = temp_state_path();
        let wal = lifecycle_wal(&root, 1, 16 * 1024);
        append_ready_commit(&wal, 60);
        fs::write(
            wal.checkpoint_temp_path_for_test(),
            b"{\"type\":\"snapshot_commit\",\"state\":",
        )
        .unwrap();

        append_ready_commit(&wal, 61);

        assert_eq!(61, wal.replay().state.applied_generation);
        assert!(!wal.checkpoint_temp_path_for_test().exists());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn neutron_wal_pre_rename_compaction_failure_falls_back_below_hard_limit() {
        let root = temp_state_path();
        let wal = lifecycle_wal(&root, 1, 64 * 1024);
        append_ready_commit(&wal, 70);
        let before = wal_bytes(&root);
        fs::create_dir_all(wal.checkpoint_temp_path_for_test()).unwrap();

        append_ready_commit(&wal, 71);

        let after = wal_bytes(&root);
        assert!(after.starts_with(&before));
        assert_eq!(71, wal.replay().state.applied_generation);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn neutron_wal_oversized_legacy_history_compacts_and_accepts_new_commit() {
        let root = temp_state_path();
        let seed = NeutronWal::new(&root);
        for generation in 80..=100 {
            append_ready_commit(&seed, generation);
        }
        let legacy_len = wal_bytes(&root).len();
        let wal = lifecycle_wal(&root, 1, legacy_len as u64);

        append_ready_commit(&wal, 101);

        assert!(wal_bytes(&root).len() < legacy_len);
        assert_eq!(101, wal.replay().state.applied_generation);
        let _ = fs::remove_dir_all(root);
    }
```

- [x] **Step 5: Commit and push RED without production implementation**

Run:

```bash
git add agent/src/neutron_wal.rs
git commit -m "test: define bounded Neutron WAL lifecycle"
git push origin v0.9-neutron-agent
```

Expected hosted result:

- `changes`: pass and mark Rust required;
- `fast-contracts`: pass;
- `rust-behavior`: fail because `NeutronWalLimits`,
  `with_limits`, `compact_now_for_test`, and
  `checkpoint_temp_path_for_test` do not exist;
- no unrelated Python or workflow failure.

- [x] **Step 6: Record exact RED evidence before production code**

Run read-only GitHub inspection:

```bash
gh run list --workflow build.yml --branch v0.9-neutron-agent --limit 5
head_sha="$(git rev-parse HEAD)"
run_id="$(gh run list --workflow build.yml \
  --branch v0.9-neutron-agent --limit 10 \
  --json databaseId,headSha \
  --jq "map(select(.headSha == \"${head_sha}\"))[0].databaseId")"
test -n "${run_id}"
gh run view "${run_id}" --json headSha,status,conclusion,jobs,url
gh run view "${run_id}" --log-failed
```

Record the run ID, head SHA, failing job, and missing-interface error in the
plan progress section before changing production code.

---

### Task 2: Refactor replay into an undecorated canonical scan

**Files:**

- Modify: `agent/src/neutron_wal.rs`

**Interfaces:**

- Consumes: current `NeutronWalEntry`, status-hash validation, protected
  inventory validation, and Task 1 pending-intent tests.
- Produces:
  - private `NeutronWalScan`
  - `NeutronWal::scan()`
  - `NeutronWal::replay_from_scan(scan)`
  - `NeutronWalEntry::from_pending_intent(intent)`
  - `NeutronWal::canonical_checkpoint_bytes()`

- [x] **Step 1: Add the scan result and default committed baseline helper**

Implement:

```rust
#[derive(Clone, Debug)]
struct NeutronWalScan {
    last_committed_state: Option<NeutronWalState>,
    pending_intent: Option<PendingNeutronIntent>,
    replayed: u64,
    failures: u64,
}

fn empty_neutron_wal_state() -> NeutronWalState {
    NeutronWalState {
        authority_state: "idle".to_string(),
        ..NeutronWalState::default()
    }
}
```

- [x] **Step 2: Move the current line loop into `scan()` without changing its rules**

`scan()` must:

- return an empty scan when the WAL file is absent;
- increment failures and stop on a line-read I/O failure;
- continue after JSON parse failures;
- normalize missing snapshot `port_ids` from `affected_ports`;
- keep a protected inventory intent pending after an invalid closing commit;
- clear ordinary pending state after an invalid ordinary commit exactly as the
  current replay does; and
- store a valid commit in `last_committed_state` without adding public
  pending-presentation fields.

- [x] **Step 3: Project the existing public replay from the scan**

Implement public projection equivalent to:

```rust
fn replay_from_scan(scan: NeutronWalScan) -> NeutronWalReplay {
    let mut replay = NeutronWalReplay {
        state: scan
            .last_committed_state
            .unwrap_or_else(empty_neutron_wal_state),
        status: "empty".to_string(),
        replayed: scan.replayed,
        failures: scan.failures,
        pending_intent: None,
    };
    if let Some(intent) = scan.pending_intent {
        replay.state.pending_generation = Some(intent.generation);
        replay.state.desired_hash = intent.desired_hash.clone();
        replay.state.authority_state = "wal_intent_without_commit".to_string();
        replay.status = "intent_without_commit".to_string();
        replay.pending_intent = Some(intent);
    } else if replay.failures > 0 {
        replay.status = "replayed_with_errors".to_string();
    } else if let Some(cause) = replay.state.recovery_cause.as_ref() {
        replay.status = cause.clone();
    } else if replay.replayed > 0 {
        replay.status = "replayed".to_string();
    }
    replay
}
```

- [x] **Step 4: Reconstruct the exact pending entry**

Implement a conversion that:

- returns `SnapshotIntent` with a recomputed hash only for the typed protected
  inventory cause;
- returns ordinary `SnapshotIntent` with no hash/cause;
- returns `DeleteIntent` with `port` from the first affected port or `None`;
- rejects unknown intent kinds, unsupported recovery causes, and delete
  intents containing more than one affected port.

- [x] **Step 5: Build canonical checkpoint bytes only from certain scans**

Implement:

```rust
fn canonical_checkpoint_bytes(&self) -> Result<Vec<u8>, String>
```

It must reject `scan.failures != 0`, then serialize:

- optional `SnapshotCommit { state }`;
- optional reconstructed pending entry;
- one newline after each entry.

It must never serialize the public decorated pending state as a commit.

Do not commit separately yet; Task 3 completes the behavior required to make
the RED suite GREEN.

---

### Task 3: Add fixed limits and atomic capacity-aware append

**Files:**

- Modify: `agent/src/neutron_wal.rs`

**Interfaces:**

- Consumes: Task 2 `canonical_checkpoint_bytes`.
- Produces:
  - production `NeutronWalLimits::default()`
  - private checkpoint replacement phase error
  - capacity-aware `append`
  - test-only constructor and checkpoint hooks required by Task 1

- [x] **Step 1: Add fixed production limits**

Implement:

```rust
const NEUTRON_WAL_SOFT_BYTES: u64 = 16 * 1024 * 1024;
const NEUTRON_WAL_HARD_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Clone, Copy, Debug)]
struct NeutronWalLimits {
    soft_bytes: u64,
    hard_bytes: u64,
}

impl Default for NeutronWalLimits {
    fn default() -> Self {
        Self {
            soft_bytes: NEUTRON_WAL_SOFT_BYTES,
            hard_bytes: NEUTRON_WAL_HARD_BYTES,
        }
    }
}
```

Add `limits` to `NeutronWal`. `new()` uses defaults. A `#[cfg(test)]`
`with_limits()` constructor rejects no values at runtime but tests must use
`soft_bytes <= hard_bytes` except when explicitly proving hard rejection.

- [x] **Step 2: Split serialization from ordinary durable append**

Serialize the entry and newline once. Add:

```rust
fn append_serialized(&self, bytes: &[u8]) -> Result<(), String>
```

This helper retains the existing behavior:

- create parent directory;
- open live WAL in create/append mode;
- write the complete bytes;
- flush;
- file `sync_all`;
- parent-directory `sync_all`.

- [x] **Step 3: Add same-directory atomic checkpoint replacement**

Use a deterministic owned path derived from the live file:

```text
neutron-snapshot.wal.compact.tmp
```

The replacement helper must distinguish:

```rust
enum CheckpointInstallError {
    BeforeRename(String),
    AfterRename(String),
}
```

Before rename it removes only a stale regular file at the owned temp path,
creates a fresh file, writes checkpoint bytes, flushes, and fsyncs. A
non-regular temp path is an error. After successful rename it fsyncs the
directory. It never replays the temp path.

- [x] **Step 4: Enforce the threshold before changing the live file**

`append()` must:

1. serialize the requested line;
2. read live length or zero for `NotFound`;
3. use `checked_add`;
4. directly append when projected bytes are at most `soft_bytes`;
5. otherwise prepare canonical checkpoint bytes;
6. reject before replacement when checkpoint plus entry exceeds
   `hard_bytes`;
7. fall back to ordinary append only when preparation or installation failed
   before rename and original projected bytes remain within `hard_bytes`;
8. return a stable `neutron WAL hard capacity exceeded` error when neither
   path fits;
9. return an after-rename durability error without fallback; and
10. append normally only after confirmed checkpoint installation.

Use `tracing::warn!` for the soft maintenance fallback. Include current,
entry, soft, hard, and error fields.

- [x] **Step 5: Add test-only lifecycle hooks**

Implement under `#[cfg(test)]`:

```rust
fn with_limits(base_state_path: impl AsRef<Path>, limits: NeutronWalLimits) -> Self
fn compact_now_for_test(&self) -> Result<(), String>
fn checkpoint_temp_path_for_test(&self) -> PathBuf
```

`compact_now_for_test()` prepares and installs only the canonical checkpoint;
it does not append a record.

- [x] **Step 6: Review the full diff without running local Cargo**

Run:

```bash
git diff --check
git diff --stat
git diff -- agent/src/neutron_wal.rs
```

Confirm:

- no `neutron_api.rs`, eBPF, ABI, or Python changes;
- no background task;
- no new config;
- no `unwrap()` in production code;
- public replay status strings are unchanged;
- test-only thresholds cannot affect production defaults.

- [x] **Step 7: Commit and push GREEN**

Run:

```bash
git add agent/src/neutron_wal.rs
git commit -m "fix: bound Neutron snapshot WAL growth"
git push origin v0.9-neutron-agent
```

Expected hosted result:

- `changes`: pass and mark Rust required;
- `fast-contracts`: pass;
- `rust-behavior`: all `neutron_wal` tests pass with `-D warnings`;
- `rust-build`: userspace and eBPF warning-denied builds pass.

- [x] **Step 8: Inspect failures and make only in-scope corrections**

Run:

```bash
gh run list --workflow build.yml --branch v0.9-neutron-agent --limit 5
head_sha="$(git rev-parse HEAD)"
run_id="$(gh run list --workflow build.yml \
  --branch v0.9-neutron-agent --limit 10 \
  --json databaseId,headSha \
  --jq "map(select(.headSha == \"${head_sha}\"))[0].databaseId")"
test -n "${run_id}"
gh run view "${run_id}" --json headSha,status,conclusion,jobs,url
gh run view "${run_id}" --log-failed
```

If CI fails, change only the approved WAL implementation or its behavior
tests. Any need to modify `neutron_api.rs`, configuration, status contracts, or
the forwarding path is a design deviation and must be reported before editing.

---

### Task 4: Close hosted evidence and backlog

**Files:**

- Modify:
  `docs/superpowers/specs/2026-07-31-review-ops-019-neutron-wal-lifecycle-design.md`
- Modify:
  `docs/superpowers/plans/2026-07-31-review-ops-019-neutron-wal-lifecycle.md`
- Modify:
  `docs/openstack-neutron-aria-details/12-review-bug-backlog.md`

**Interfaces:**

- Consumes: exact RED and GREEN commit SHAs, run IDs, job URLs, and test
  results.
- Produces: authoritative `REVIEW-OPS-019=fixed` register evidence.

- [x] **Step 1: Update the design status**

Record:

- RED commit and expected hosted failure;
- GREEN production commit;
- exact-head successful Build and job links;
- fixed 16 MiB/64 MiB values;
- no privileged field evidence required.

- [x] **Step 2: Complete the plan checkboxes and evidence section**

Add an evidence section containing the exact observed RED commit and Build,
the exact missing-interface RED error, the exact GREEN commit and Build, and
direct `rust-behavior` and `rust-build` job links. Do not insert labels whose
values are not yet known and do not infer a result from a workflow still
running.

- [x] **Step 3: Update the authoritative backlog row**

Change only `REVIEW-OPS-019` from `open` to `fixed`. Describe canonical
checkpointing, unresolved-intent preservation, corruption refusal, atomic
replacement, fixed thresholds, and hard-cap pre-write rejection. Link exact
RED/GREEN builds.

- [x] **Step 4: Commit and push documentation closure**

Run:

```bash
git add \
  docs/superpowers/specs/2026-07-31-review-ops-019-neutron-wal-lifecycle-design.md \
  docs/superpowers/plans/2026-07-31-review-ops-019-neutron-wal-lifecycle.md \
  docs/openstack-neutron-aria-details/12-review-bug-backlog.md
git commit -m "docs: close bounded Neutron WAL lifecycle"
git push origin v0.9-neutron-agent
```

- [x] **Step 5: Verify exact-head documentation CI and repository state**

Run:

```bash
gh run list --workflow build.yml --branch v0.9-neutron-agent --limit 5
head_sha="$(git rev-parse HEAD)"
run_id="$(gh run list --workflow build.yml \
  --branch v0.9-neutron-agent --limit 10 \
  --json databaseId,headSha \
  --jq "map(select(.headSha == \"${head_sha}\"))[0].databaseId")"
test -n "${run_id}"
gh run view "${run_id}" --json headSha,status,conclusion,jobs,url
git status --short
git rev-list --left-right --count \
  v0.9-neutron-agent...origin/v0.9-neutron-agent
```

Expected:

- exact-head docs Build succeeds;
- worktree is clean;
- divergence is `0 0`;
- `REVIEW-OPS-019` is fixed;
- deferred privileged ACL findings remain unchanged.

## Execution Evidence

RED commit `5c79a28` added only the nine lifecycle behavior tests and their
test helpers. Build
[`30601218345`](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/30601218345)
failed in
[`rust-behavior` job `91064136403`](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/30601218345/job/91064136403)
with the expected missing `NeutronWalLimits`, `with_limits`,
`compact_now_for_test`, and `checkpoint_temp_path_for_test` interfaces.
`changes` and `fast-contracts` passed, and the independent `rust-build` job
passed, proving the RED did not modify or break the production binary path.

GREEN commit `c3d8238` implemented the approved lifecycle only in
`agent/src/neutron_wal.rs`. Exact-head Build
[`30601633217`](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/30601633217)
passed:

- [`rust-behavior` job `91065427370`](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/30601633217/job/91065427370)
  passed all 47 focused `neutron_wal` behaviors, including all nine lifecycle
  tests;
- [`rust-build` job `91065427305`](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/30601633217/job/91065427305)
  passed the warning-denied Rust/eBPF, userspace-static, and agent-static
  builds;
- `changes` and `fast-contracts` also passed.

The production constants are 16 MiB soft and 64 MiB hard. No privileged field
evidence applies to this filesystem-only repair.

Documentation closure commit `c7e45e4` updated the design, this plan, and the
authoritative register. Exact-head Build
[`30601933087`](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/30601933087)
passed `fast-contracts` and change detection; Rust jobs correctly skipped
because the closure changed documentation only.
