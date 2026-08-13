# REVIEW-TXN-032 Atomic State File Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use
> superpowers:executing-plans to implement this plan task-by-task. Steps use
> checkbox (`- [ ]`) syntax for tracking. Execute inline on the sole
> `v0.9-neutron-agent` branch; do not create a branch, worktree, PR, or
> subagent task.

**Goal:** make every authoritative `state.json` update an atomic durable
replacement so a crash or pre-rename write failure preserves the last complete
state.

**Architecture:** add one filesystem primitive in `core/src/state.rs` that
serializes before I/O, writes a writer-owned sibling temp, fsyncs it, renames it
over the target, and fsyncs the parent. Route both `StateManager::with_state`
and `WalWriter::compact` through it while preserving snapshot-before-WAL-
truncate ordering.

**Tech Stack:** Rust 2021, Serde JSON, POSIX rename/fsync, fslock, existing WAL
replay, GitHub Actions warning-denied Rust/eBPF builds.

## Global Constraints

- Follow the approved
  [design](../specs/2026-08-13-review-txn-032-atomic-state-file-design.md).
- Work directly on `v0.9-neutron-agent`; do not create another branch,
  worktree, or PR.
- Do not run local Cargo build, check, test, clippy, or rustfmt commands.
- Push RED and GREEN separately; hosted CI is the Rust authority.
- Do not change `FirewallState`, WAL serialization, replay semantics, public
  APIs, or datapath behavior.
- Keep `REVIEW-TXN-033`, `REVIEW-OPS-038/040`, and unrelated cleanup outside
  this batch.

---

### Task 1: RED Crash-Window Behaviors

**Files:**

- Modify: `core/src/state.rs` test module
- Modify: `core/src/wal.rs` test module only if the existing compact test lacks
  the required complete-snapshot assertion

**Interfaces:**

- Requires future internal interface:

```rust
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AtomicStateWritePhase {
    AfterFileSync,
    AfterRename,
}

fn persist_state_file_atomically_with_hook<F>(
    state_file: &Path,
    contents: &[u8],
    hook: F,
) -> Result<(), String>
where
    F: FnMut(AtomicStateWritePhase) -> Result<(), String>;
```

- [ ] Add a test seeding a non-empty old `state.json`, inject failure at
  `AfterFileSync`, and assert the target bytes are unchanged and still decode.
- [ ] Add a compacted-empty-WAL test which repeats that failure and asserts
  `load_with_wal` returns the old group/rule state rather than default state.
- [ ] Add success and `AfterRename` tests proving the target always contains a
  complete new JSON document and no invocation-owned temp remains after a
  returned normal error.
- [ ] Run `python3 ci/check_blocked_terms.py` and `git diff --check`.
- [ ] Commit as `test: expose torn state snapshot window`, push, and capture
  the exact hosted RED failure caused by the absent future interface or old
  truncate behavior.

### Task 2: GREEN Shared Atomic Replacement

**Files:**

- Modify: `core/src/state.rs`
- Modify: `core/src/wal.rs`

**Interfaces:**

- Produces `pub(crate) fn persist_state_file_atomically(&Path, &[u8])`.
- Keeps the phase-hook helper private to `state.rs` behavior tests.

- [ ] Generate a same-directory writer-owned temp path using process identity,
  a monotonic counter, and `OpenOptions::create_new(true)`; retry only name
  collisions.
- [ ] Write all bytes and call `sync_all` before the `AfterFileSync` hook.
- [ ] Rename over the target, invoke `AfterRename`, then sync the parent
  directory. Clean up only the owned temp on pre-rename failure.
- [ ] Serialize `FirewallState` before calling the helper from
  `StateManager::with_state`; remove direct target truncation.
- [ ] Replace the fixed `state.json.tmp` block in `WalWriter::compact` with the
  shared helper; keep WAL truncation and fsync after successful replacement.
- [ ] Run the allowed Python/static checks, commit as
  `fix: publish state snapshots atomically`, and push.
- [ ] Require exact-head `rust-behavior`, warning-denied `rust-build`, eBPF,
  fast contracts, and nonzero matching test execution.

### Task 3: Contract And Register Closure

**Files:**

- Modify: `docs/openstack-neutron-aria-details/07-transaction-wal.md`
- Modify: `docs/openstack-neutron-aria-details/12-review-bug-backlog.md`
- Modify:
  `docs/superpowers/specs/2026-08-13-bug-hunt-remediation-program-design.md`
- Modify this plan and its design

- [ ] Record exact RED/GREEN commits, Build URLs, pre/post-rename behavior, and
  the unchanged WAL format.
- [ ] Mark `REVIEW-TXN-032` fixed only after exact-head GREEN.
- [ ] Advance the fixed-order program to `REVIEW-OPS-038/040`.
- [ ] Run public-release, CI-lane, blocked-term, and diff checks.
- [ ] Commit/push the documentation closure and require the selected exact-head
  fast/static Build to pass.

## Plan Self-Review

- Coverage: serialization-before-I/O, unique sibling temp, file fsync, atomic
  rename, directory fsync, pre-rename preservation, post-rename uncertainty,
  compacted-empty-WAL recovery, compactor reuse, CI, and register closure each
  have an owning step.
- Scope: two Rust files and the named transaction documentation only.
- Compatibility: state/WAL schemas and snapshot-before-truncate order remain
  unchanged; `REVIEW-TXN-033` is explicitly excluded.
- Evidence: RED and GREEN are separate hosted commits; no local Cargo command
  appears in the execution steps.
