# REVIEW-TXN-033 WAL Checkpoint Epoch Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use
> superpowers:executing-plans to implement this plan task-by-task. Steps use
> checkbox (`- [ ]`) syntax for tracking. Execute inline on the sole
> `v0.9-neutron-agent` branch; do not create a branch, worktree, PR, or
> subagent task.

**Goal:** make standalone/local snapshot compaction identify and skip the
exact WAL prefix already reflected by `state.json`, preserving allocator
parity across every snapshot/marker/truncate crash window.

**Architecture:** add a writer-owned, versioned checkpoint cursor to
`FirewallState` and a private checkpoint line to `state.wal`. The existing WAL
actor appends the marker, atomically publishes the cursor-bearing snapshot,
truncates only afterwards, and durably installs the same marker as the new WAL
header before acknowledging later mutations. Replay resets to the checkpoint
snapshot at the matching marker and applies only the tail.

**Tech Stack:** Rust 2021, Serde/JSON-lines, Tokio MPSC actor, existing atomic
state-file primitive, GitHub Actions warning-denied Rust/eBPF builds.

## Global Constraints

- Follow the approved
  [design](../specs/2026-08-14-review-txn-033-wal-checkpoint-epoch-design.md).
- Work directly on `v0.9-neutron-agent`; do not create another branch,
  worktree, PR, or subagent task.
- Do not run local Cargo build, check, test, clippy, or rustfmt commands.
- Push RED and GREEN separately; hosted CI is the Rust behavior and compiler
  authority.
- Preserve the order marker fsync -> atomic snapshot -> WAL truncate -> header
  fsync. Truncate-first is forbidden.
- Keep `WalClient::append(WalEntry)` and all control-plane mutation call sites
  unchanged.
- Do not modify Neutron `neutron-state.wal`, allocator behavior, policy
  semantics, map projection, APIs, or eBPF code.
- Do not add per-mutation LSNs, a sidecar file, a generic persistence framework,
  or a Python source-shape checker.

---

### Task 1: RED Replay-Parity And Crash-State Behaviors

**Files:**

- Modify: `core/src/wal.rs` test module
- Modify: `ci/check_neutron_stage1.py`

**Interfaces:**

- Tests consume the existing public `WalWriter::open`, `WalWriter::append`,
  `WalWriter::compact`, `load_with_wal`, `last_wal_replay_failures`,
  `FirewallState::apply_add_rule`, and JSON files.
- Tests write the future cursor and marker as raw JSON values so RED compiles
  against the old implementation and fails on behavior rather than missing
  private helper names.
- The required hosted filter is:

```python
["test", "--locked", "-p", "aria-core", "wal_checkpoint_"],
```

- [x] **Step 1: Add deterministic checkpoint fixtures**

In the `core/src/wal.rs` test module add helpers that use the existing
`temp_state_path`, ordinary `WalEntry` serialization, and raw version-1 marker
JSON:

```rust
fn wal_checkpoint_record(checkpoint_id: u64, version: u8) -> String {
    serde_json::json!({
        "wal_checkpoint": {
            "version": version,
            "checkpoint_id": checkpoint_id,
        }
    })
    .to_string()
}

fn wal_checkpoint_state_json(state: &FirewallState, checkpoint_id: u64) -> String {
    let mut value = serde_json::to_value(state).unwrap();
    value["wal_replay_cursor"] = serde_json::json!({
        "version": 1,
        "checkpoint_id": checkpoint_id,
    });
    serde_json::to_string_pretty(&value).unwrap()
}

fn wal_checkpoint_rule_update_chain() -> (Vec<WalEntry>, FirewallState) {
    let entries = vec![
        WalEntry::AddRule {
            src_id: 1,
            dst_id: 2,
            proto: 6,
            action: 0,
            ports: Some("80".to_string()),
            direction: 0,
        },
        WalEntry::AddRule {
            src_id: 1,
            dst_id: 2,
            proto: 6,
            action: 0,
            ports: Some("443".to_string()),
            direction: 0,
        },
        WalEntry::AddRule {
            src_id: 1,
            dst_id: 2,
            proto: 6,
            action: 0,
            ports: Some("8443".to_string()),
            direction: 0,
        },
    ];
    let mut checkpoint = FirewallState::default();
    for entry in entries.iter().cloned() {
        assert!(apply_wal_entry(&mut checkpoint, entry));
    }
    (entries, checkpoint)
}
```

Add an allocator comparison helper that asserts exact equality for:

- each rule's key, action, ports and `bitmap_idx`;
- `port_sets` key, `bitmap_idx`, `ports_normalized`, and `ref_count`;
- `free_bitmap_indices` in persisted order;
- `next_bitmap_idx`, `max_port_policies`;
- `pending_bitmap_cleanups` and quarantine-visible count.

- [x] **Step 2: Add the retained-prefix parity RED**

Write the checkpoint state with ID 7. Write the three ordinary mutation lines
followed by `Checkpoint(7)` to `state.wal`, then call `load_with_wal` and assert
allocator parity with the checkpoint. The old implementation must fail because
it skips the unknown marker and reapplies all three mutations.

Name the test:

```rust
fn wal_checkpoint_retained_prefix_preserves_complete_allocator_parity()
```

- [x] **Step 3: Add tail, legacy and failure-counter RED behaviors**

Add separately named `wal_checkpoint_` tests for:

1. a mutation after matching marker 7 is applied once;
2. an unmatched marker 8 beside a legacy snapshot is a no-op and all ordinary
   mutations replay;
3. malformed lines before a matching marker do not remain in
   `last_wal_replay_failures`, while malformed lines after it do;
4. an unsupported cursor/marker version increments replay failures and is not
   treated as version 1;
5. a legacy snapshot and mutation-only WAL preserve current replay behavior.

- [x] **Step 4: Add successful-compact and interrupted-header RED behaviors**

Using only existing `WalWriter` APIs:

- compact a state and assert the WAL contains exactly one version-1 checkpoint
  header while `entry_count()==0`;
- manually write a version-1 snapshot with an empty WAL, reopen `WalWriter`,
  append one ordinary mutation, and assert the matching header precedes the
  mutation. This models restart after truncate but before header publication;
- seed snapshot ID 9 plus an unmatched marker ID 10, compact again, and assert
  the installed header ID is greater than 10;
- seed `u64::MAX` in the snapshot/marker and assert compact returns an overflow
  error without truncating existing bytes.

- [x] **Step 5: Wire the nonzero hosted behavior filter**

Add the exact `wal_checkpoint_` Cargo filter to `RUST_TESTS` in
`ci/check_neutron_stage1.py`. Do not add a test-name parser or source regex.

- [x] **Step 6: Run non-compiling local checks only**

Run:

```bash
python3 -m py_compile ci/check_neutron_stage1.py
python3 -m unittest ci.test_ci001_trusted_gates ci.test_rust_warning_hygiene
git diff --check
```

Do not run Cargo locally.

- [x] **Step 7: Commit and push RED**

```bash
git add core/src/wal.rs ci/check_neutron_stage1.py \
  docs/superpowers/plans/2026-08-14-review-txn-033-wal-checkpoint-epoch.md
git commit -m "test: expose WAL checkpoint replay drift"
git push origin v0.9-neutron-agent
```

Expected hosted result: `rust-behavior` fails at the retained-prefix allocator
parity or header assertion. Stop remaining unrelated compilation after the
precise RED is captured.

---

### Task 2: GREEN Versioned Cursor And Record Parsing

**Files:**

- Modify: `core/src/state.rs`
- Modify: `core/src/wal.rs`

**Interfaces:**

- Produce:

```rust
pub const WAL_REPLAY_CURSOR_VERSION: u8 = 1;

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct WalReplayCursor {
    pub version: u8,
    pub checkpoint_id: u64,
}
```

- Add to `FirewallState`:

```rust
#[serde(default, skip_serializing_if = "WalReplayCursor::is_legacy")]
pub wal_replay_cursor: WalReplayCursor,
```

- Keep `WalEntry` unchanged and add private `WalCheckpointRecord` and
  `PersistedWalRecord` in `core/src/wal.rs`.

- [x] **Step 1: Add the cursor type and legacy semantics**

Implement:

```rust
impl WalReplayCursor {
    pub fn is_legacy(&self) -> bool {
        self.version == 0 && self.checkpoint_id == 0
    }

    pub(crate) fn supported_checkpoint_id(&self) -> Result<Option<u64>, String> {
        if self.is_legacy() {
            return Ok(None);
        }
        if self.version != WAL_REPLAY_CURSOR_VERSION || self.checkpoint_id == 0 {
            return Err(format!(
                "unsupported WAL replay cursor version={} checkpoint_id={}",
                self.version, self.checkpoint_id
            ));
        }
        Ok(Some(self.checkpoint_id))
    }
}
```

Place the cursor field after allocator recovery fields in `FirewallState` and
initialize it with `WalReplayCursor::default()`. Update any complete struct
literals that do not use `..FirewallState::default()`.

- [x] **Step 2: Add private persisted record parsing**

Implement the design's private JSON envelope and helpers:

```rust
fn parse_persisted_wal_record(line: &str) -> Result<PersistedWalRecord, String>;
fn serialize_checkpoint_record(checkpoint_id: u64) -> Result<String, String>;
```

The untagged enum must try the explicit `wal_checkpoint` object before the
legacy `WalEntry`. Version 1 requires nonzero ID. Unknown versions parse as a
checkpoint record and are classified by replay, not silently reinterpreted as
a mutation.

- [x] **Step 3: Make open inventory mutation count and maximum marker ID**

Replace the current `WalEntry`-only count with one scan returning:

```rust
struct WalInventory {
    mutation_count: u64,
    max_checkpoint_id: u64,
    has_matching_checkpoint: bool,
}
```

Read the snapshot cursor first. Count only valid mutation lines. Include every
valid checkpoint ID when calculating the next candidate. Set
`header_required=true` only when the snapshot carries a supported nonzero
cursor and the WAL is empty; a retained WAL containing its matching marker is
already append-safe. Reject an unsupported nonzero snapshot cursor from
`WalWriter::open` before accepting any mutation or compact request.

- [x] **Step 4: Make replay select the authoritative tail**

Retain `checkpoint_state = state.clone()` before reading WAL. On a matching
version-1 checkpoint:

```rust
state = checkpoint_state.clone();
replayed = 0;
failed = 0;
prefix_discarded = true;
```

Unmatched supported markers are no-ops. Unsupported markers or cursor versions
increment failures and never reset state. Apply only `Mutation(entry)` through
`apply_wal_entry`. Preserve the existing read-error stop behavior and malformed
tail handling.

- [x] **Step 5: Commit the parsing/replay GREEN slice only after hosted proof**

Do not commit an intermediate production change before Task 3 completes the
compaction writer; the reader and writer format must land in one GREEN commit.

---

### Task 3: GREEN Snapshot-First Checkpoint Compaction

**File:**

- Modify: `core/src/wal.rs`

**Interfaces:**

- Extend `WalWriter` with:

```rust
next_checkpoint_id: Option<u64>,
current_checkpoint_id: Option<u64>,
header_required: bool,
```

- Keep public signatures unchanged:

```rust
pub fn append(&mut self, entry: &WalEntry) -> Result<(), String>;
pub fn compact(&mut self, state_json: &str) -> Result<(), String>;
```

- [x] **Step 1: Reserve IDs without reuse or wrap**

At open, set the next candidate from the maximum snapshot/marker ID using
`checked_add(1)`. Reserve the candidate before writing its marker; after any
successful marker fsync, advance the next candidate even if snapshot
publication later fails.

- [x] **Step 2: Add checkpoint header repair before append**

Implement:

```rust
fn ensure_checkpoint_header(&mut self) -> Result<(), String>;
```

When `header_required` is false it is a no-op. Otherwise append and sync the
current checkpoint record, then clear the flag. `append_buffered` must call it
before serializing an ordinary mutation. Header failure returns before mutation
bytes are written or `entry_count` changes.

- [x] **Step 3: Implement the exact compact order**

`compact` must:

1. parse the complete supplied snapshot;
2. reserve ID N and inject `WalReplayCursor { version: 1,
   checkpoint_id: N }`;
3. serialize the modified state before filesystem mutation;
4. append and sync marker N to the old WAL;
5. atomically publish the modified snapshot;
6. mark N as current once snapshot publication is confirmed;
7. open `state.wal` with truncate, immediately replace the active writer with
   that file, set `header_required=true`, then fsync the truncated file;
8. call `ensure_checkpoint_header()`;
9. reset mutation count and compact time only after header sync succeeds.

If snapshot publication errors after rename, return without truncating; the
durable old-WAL marker makes either possible snapshot generation replayable.
If truncate fails, retain the old append writer and its matching end marker.
If truncate succeeds but later sync/header fails, keep `header_required=true`
so no subsequent mutation is acknowledged before repair.

- [x] **Step 4: Keep actor counters semantically accurate**

The actor-facing mutation count remains zero only after successful compact.
Checkpoint records never increment it. A failed compact may conservatively
retain the prior atomic count and trigger an earlier retry, but it must never
report zero while a mutation tail remains uncheckpointed.

- [x] **Step 4a: Preserve the approved checkpoint observability**

Emit the existing structured compact/replay log with checkpoint ID/version,
covered mutation count, selected tail count and prefix-discarded state. A
failed required-header repair includes `header_required=true`. Do not add a
metric family or log policy bodies.

- [x] **Step 5: Run non-Cargo local validation**

Run:

```bash
python3 -m py_compile ci/check_neutron_stage1.py
python3 ci/check_blocked_terms.py
git diff --check
```

Inspect all `FirewallState` struct literals and every exhaustive
`PersistedWalRecord`/`WalEntry` match with `rg`; do not run Cargo locally.

- [x] **Step 6: Commit and push GREEN**

```bash
git add core/src/state.rs core/src/wal.rs ci/check_neutron_stage1.py \
  docs/superpowers/plans/2026-08-14-review-txn-033-wal-checkpoint-epoch.md
git commit -m "fix: checkpoint standalone WAL epochs"
git push origin v0.9-neutron-agent
```

- [x] **Step 7: Verify exact-head hosted GREEN**

Require:

- nonzero `wal_checkpoint_` behavior execution;
- `rust-behavior` success;
- warning-denied eBPF, core/userspace and agent builds;
- fast contracts and clean-install/database jobs success.

Inspect logs for test count and warnings. Do not mark the finding fixed on a
cancelled, superseded, or non-exact-head run.

---

### Task 4: Contract And Register Closure

**Files:**

- Modify: `docs/superpowers/specs/2026-08-14-review-txn-033-wal-checkpoint-epoch-design.md`
- Modify: `docs/superpowers/plans/2026-08-14-review-txn-033-wal-checkpoint-epoch.md`
- Modify: `docs/superpowers/specs/2026-08-13-bug-hunt-remediation-program-design.md`
- Modify: `docs/openstack-neutron-aria-details/07-transaction-wal.md`
- Modify: `docs/openstack-neutron-aria-details/12-review-bug-backlog.md`

- [x] **Step 1: Record exact RED/GREEN evidence**

Record commit hashes, Build URLs, the precise RED assertion, nonzero hosted
test count, and all required GREEN jobs. Do not claim allocator collision,
wrong enforcement, or privileged datapath evidence unless the RED actually
demonstrated it.

- [x] **Step 2: Update the transaction contract**

Replace the statement that state/WAL schemas remain unchanged with the
version-1 checkpoint cursor/record contract, snapshot-first ordering, legacy
behavior, and older-binary rollback limitation.

- [x] **Step 3: Close only the proven finding**

Mark `REVIEW-TXN-033` fixed after exact-head GREEN. Preserve P2 severity in the
historical row unless the RED evidence met its documented escalation test.
Advance the remediation program to the next fixed-order batch without changing
the remaining item order.

- [x] **Step 4: Commit, push and verify the documentation HEAD**

```bash
git add docs/openstack-neutron-aria-details/07-transaction-wal.md \
  docs/openstack-neutron-aria-details/12-review-bug-backlog.md \
  docs/superpowers/specs/2026-08-13-bug-hunt-remediation-program-design.md \
  docs/superpowers/specs/2026-08-14-review-txn-033-wal-checkpoint-epoch-design.md \
  docs/superpowers/plans/2026-08-14-review-txn-033-wal-checkpoint-epoch.md
git commit -m "docs: close WAL checkpoint epochs"
git push origin v0.9-neutron-agent
```

Require the exact documentation HEAD Build to pass, then confirm:

```bash
git status --short --branch
git rev-list --left-right --count \
  v0.9-neutron-agent...origin/v0.9-neutron-agent
```

Expected: clean worktree and `0 0` divergence.
