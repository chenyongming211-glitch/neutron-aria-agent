# REVIEW-TXN-032 Atomic State File Design

**Status:** approved repair direction; implementation pending RED evidence

**Date:** 2026-08-13

**Owning finding:** `REVIEW-TXN-032`

## 1. Decision

Replace every authoritative `state.json` snapshot publication with one shared
same-directory atomic replacement primitive:

```text
serialize complete next state in memory
  -> create one writer-owned sibling temporary file
  -> write all bytes
  -> fsync temporary file
  -> atomic rename over state.json
  -> fsync parent directory
```

`StateManager::with_state` uses this primitive instead of opening
`state.json` with `truncate(true)`. `WalWriter::compact` reuses the same
primitive before truncating `state.wal`, so the two persistence paths cannot
drift in durability behavior.

No state schema, WAL record, replay rule, API, or datapath behavior changes.

## 2. Verified Root Cause

`StateManager::with_state` currently reads the committed file, mutates an
in-memory `FirewallState`, then opens the authoritative path with
`truncate(true)`. The old bytes disappear before the new JSON is fully written
and synced. A crash or write failure in that interval can leave an empty or
partial `state.json`.

`load_with_wal` treats an empty or unparsable snapshot as default state. If the
WAL was already compacted and is empty, restart therefore loses every persisted
group, rule, allocator, QoS, mirror, and runtime configuration value. Policy
evaluation then falls back to the empty-state behavior.

`WalWriter::compact` already uses temporary-write, file-fsync, rename and
directory-fsync. It uses the fixed name `state.json.tmp`, however. Reusing that
same fixed name from `StateManager` would add a collision between writers
because their locks are not shared. The common primitive therefore allocates a
writer-owned sibling temp name with `create_new(true)`.

## 3. Atomicity Contract

### 3.1 Before rename

Serialization completes before any file is opened. Failures while allocating,
writing, flushing or syncing the temporary file:

- return an error;
- remove only that invocation's temporary file when possible;
- do not modify, truncate or unlink the prior `state.json`;
- leave an empty compacted WAL paired with the prior complete snapshot, so
  restart still recovers the prior committed state.

### 3.2 Rename

The temp file is created in the same directory as `state.json`; rename is
therefore a same-filesystem atomic replacement. Readers observe either the old
complete JSON or the new complete JSON, never the temporary contents.

### 3.3 After rename

The parent directory is fsynced to make the name replacement durable. If that
fsync reports an error, the call returns an error and the outcome is treated as
uncertain: the target already contains one complete new JSON document and must
not be truncated or rolled back by this helper.

### 3.4 Temporary files

Each writer owns a unique sibling temporary path. Normal errors clean it up.
A process crash may leave an unreferenced temp file, which replay ignores. This
batch does not add unsafe startup scavenging that could delete another live
writer's temporary file.

## 4. Shared Primitive

The primitive lives with persistent state in `core/src/state.rs` and is
`pub(crate)` for `core/src/wal.rs`:

```rust
pub(crate) fn persist_state_file_atomically(
    state_file: &Path,
    contents: &[u8],
) -> Result<(), String>;
```

An internal phase-hook variant is used only by Rust behavior tests to stop at
the two crash boundaries after temp-file fsync and after rename. Production
callers always use the no-hook wrapper. This is a filesystem behavior seam, not
a parser/checker contract.

## 5. WAL Compaction Ordering

The existing safe order remains unchanged:

```text
atomic state.json replacement succeeds
  -> truncate state.wal
  -> fsync truncated WAL
```

Truncate-first remains forbidden. `REVIEW-TXN-033` separately owns the crash
window after snapshot rename but before WAL truncation and its checkpoint/epoch
or replay-idempotence design.

## 6. RED/GREEN Evidence

RED Rust behaviors cover:

1. failure after temp-file fsync preserves the byte-identical old target;
2. a compacted-empty WAL plus that failure reloads the old non-empty state,
   never `FirewallState::default()`;
3. successful replacement publishes complete new JSON and leaves no live temp;
4. stopping after rename exposes complete new JSON rather than a torn file;
5. `WalWriter::compact` continues to publish a complete snapshot before WAL
   truncation using the shared primitive.

Hosted GREEN requires the exact-head `rust-behavior`, warning-denied
`rust-build`, eBPF build, and fast contracts. No local Cargo command is used.

## 7. Scope

Production changes are limited to:

- `core/src/state.rs`: shared atomic state-file replacement and
  `StateManager::with_state` integration;
- `core/src/wal.rs`: reuse the shared primitive in compaction;
- behavior tests in those two modules;
- transaction contract, plan, program index, and REVIEW register closure.

Explicit exclusions:

- no `load_with_wal` fallback redesign;
- no state schema or WAL format migration;
- no checkpoint/epoch work from `REVIEW-TXN-033`;
- no new cross-process transaction coordinator;
- no privileged datapath evidence claim.

## 8. Acceptance

1. No `StateManager` write opens `state.json` with `truncate(true)`.
2. Every pre-rename failure preserves the previous target bytes.
3. Successful publication uses file fsync, atomic same-directory rename and
   directory fsync.
4. A compacted-empty WAL cannot combine with a failed ordinary state write to
   produce default state on restart.
5. WAL compaction preserves snapshot-before-truncate ordering.
6. Exact-head hosted CI is green with warnings denied before the finding is
   closed.
