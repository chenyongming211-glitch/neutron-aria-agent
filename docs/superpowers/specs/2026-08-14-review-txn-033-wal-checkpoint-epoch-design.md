# REVIEW-TXN-033 WAL Checkpoint Epoch Design

**Status:** approved design; implementation plan ready, production not started

**Date:** 2026-08-14

**Owning finding:** `REVIEW-TXN-033`

## 1. Decision

Add one versioned checkpoint epoch to the existing standalone/local
`state.json` plus `state.wal` persistence pair. Compaction keeps the safe
snapshot-first order and makes the exact WAL prefix covered by that snapshot
explicit:

```text
append + fsync Checkpoint(N) to the old WAL
  -> atomically publish state.json carrying checkpoint N
  -> truncate + fsync state.wal
  -> write + fsync Checkpoint(N) as the new WAL header
  -> acknowledge compaction
```

Replay starts from the complete snapshot. When it sees the checkpoint record
whose ID equals the snapshot cursor, it resets to that snapshot and discards
all replay effects and replay-failure counts from the covered prefix. Only
records after the matching marker are authoritative WAL tail.

This is the long-term persistence model for the current single-writer,
single-snapshot, single-WAL architecture. It is not a truncate-first repair,
does not require every mutation to become commutative, and does not introduce
an LSN envelope for every record.

## 2. Verified Root Cause And Impact

`WalWriter::compact` atomically publishes the complete `state.json`, then
truncates and fsyncs `state.wal`. The order protects against data loss, but a
crash after the snapshot rename and before WAL truncation leaves the new
snapshot beside the complete old WAL prefix. `load_with_wal` cannot tell that
the prefix is already reflected by the snapshot and replays every entry.

`FirewallState::apply_add_rule` is not idempotent for an update chain because
it allocates the new port set before releasing the old one. For one rule key:

```text
K:A -> bitmap 0, next=1, free=[]
K:B -> bitmap 1, next=2, free=[0]
K:C -> bitmap 0, next=2, free=[1]     # checkpoint state
```

Replaying the full `K:A -> K:B -> K:C` prefix on top of that checkpoint ends
with the same logical `K:C` rule but bitmap 1 and `free=[0]`. The persisted
allocator therefore differs from the state actually checkpointed, and startup
re-projects kernel maps from that drifted state.

The proven impact remains allocator/index drift. No incorrect allow/drop,
bitmap collision, or permanent enforcement divergence has been demonstrated,
so the finding remains P2 unless RED evidence proves one of those stronger
consequences.

## 3. Why Strict Replay Idempotence Is Not Selected

An equality guard for the final `K:C` entry cannot neutralize the preceding
`K:A` and `K:B` updates. Making every history prefix harmless would require
per-record versions plus per-object applied versions, which is effectively a
new LSN persistence format rather than a local idempotence fix.

A versioned LSN envelope remains a valid future extension if the product adds
WAL segmentation, cross-process writers, replication, or retained audit
history. None exists in the current architecture. Adding it now would expand
every serialized mutation and its legacy migration without improving the
current checkpoint correctness over an explicit epoch boundary.

## 4. Persistent Format

### 4.1 Snapshot cursor

`FirewallState` gains one additive field:

```rust
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct WalReplayCursor {
    #[serde(default)]
    pub version: u8,
    #[serde(default)]
    pub checkpoint_id: u64,
}

#[serde(default, skip_serializing_if = "WalReplayCursor::is_legacy")]
pub wal_replay_cursor: WalReplayCursor,
```

The only supported non-legacy form is `version=1` with
`checkpoint_id >= 1`. A missing field, `version=0`, or `checkpoint_id=0`
means the legacy boundary: replay every ordinary WAL entry.

The cursor is persistence metadata, not policy state. It is excluded from
allocator, policy, datapath and API decisions. `WalWriter` owns cursor
advancement and overwrites the cursor in the snapshot JSON supplied to
`compact`; callers cannot choose or regress it.

### 4.2 WAL checkpoint record

Keep the public `WalEntry` mutation enum unchanged. Add a private persisted
line envelope in `core/src/wal.rs`:

```rust
#[derive(Serialize, Deserialize)]
struct WalCheckpointRecord {
    version: u8,
    checkpoint_id: u64,
}

#[derive(Serialize, Deserialize)]
#[serde(untagged)]
enum PersistedWalRecord {
    Checkpoint { wal_checkpoint: WalCheckpointRecord },
    Mutation(WalEntry),
}
```

Existing JSON-lines mutations remain byte-format compatible. The new record
is reserved for `WalWriter`; `WalClient::append` continues accepting only a
`WalEntry`, so control-plane call sites cannot manufacture a replay boundary.

The marker is not a mutation:

- it does not increment the public `entry_count`;
- it does not trigger the 1000-mutation compaction threshold;
- `apply_wal_entry` never sees it;
- it is not projected to kernel state.

### 4.3 Checkpoint ID allocation

At `WalWriter::open`, scan the snapshot cursor and every valid checkpoint
record. The next candidate is `max(snapshot_id, marker_ids) + 1` using checked
addition. Marker IDs are reserved monotonically even when a later snapshot
step fails, so a retry in the same process never reuses an unmatched marker.

Exhausting `u64` returns a compaction error; it never wraps to zero or reuses an
old ID.

## 5. Compaction State Machine

All messages remain serialized by the existing `WalActor`. No second lock,
worker, background compactor, sidecar file, or cross-process coordinator is
added.

For `Compact { state_json }`:

1. deserialize `state_json` as `FirewallState` before changing the WAL;
2. reserve the next checkpoint ID;
3. set the version-1 cursor on the snapshot copy and serialize it completely;
4. append and fsync the checkpoint record to the current WAL;
5. publish the cursor-bearing snapshot through
   `persist_state_file_atomically`;
6. after confirmed snapshot publication, truncate and fsync the WAL;
7. write and fsync the same checkpoint record as the new WAL header;
8. reset mutation `entry_count` to zero, update the compact timestamp, and
   acknowledge success.

The actor must not acknowledge or process a following mutation append after a
successful truncate until the new checkpoint header is durable. If truncate
succeeds but header publication fails, the writer records `header_required`;
subsequent appends first retry that exact header and fail without writing a
mutation if it cannot be made durable.

If snapshot publication succeeds but truncation fails, the old WAL remains.
Its matching end marker is already durable, so later mutations may safely be
appended after that marker and replay will select them as tail.

The snapshot cursor stored in an `InstanceState` clone may lag the writer's
cursor because `compact` currently receives pre-serialized JSON. This is safe
only because the cursor is writer-owned metadata: every later compact parses
the supplied state, replaces its cursor with the writer's next ID, and
`StateManager` read-modify-write paths load the persisted cursor before
writing. No caller-provided cursor may influence allocation.

## 6. Replay State Machine

`load_with_wal` retains streaming JSON-lines replay and its current
best-effort handling for malformed mutation lines.

1. Load the complete snapshot and retain an immutable clone as
   `checkpoint_state`.
2. Validate the snapshot cursor. Legacy cursor means ordinary legacy replay.
3. Stream `PersistedWalRecord` lines.
4. An unmatched valid checkpoint marker is a no-op. This covers a marker that
   became durable before a snapshot publication failure.
5. A marker matching the snapshot cursor resets working state to
   `checkpoint_state` and resets the replayed/failed counters accumulated for
   the covered prefix.
6. Apply only mutation records after the most recent matching marker.
7. Report parse, read and mutation failures only for the authoritative tail;
   superseded-prefix failures do not make the current checkpoint degraded.

A successful compact leaves the matching marker as the WAL header. An empty
WAL is accepted only for the crash interval after truncate and before header
publication; the snapshot is already complete in that interval. A non-empty
version-1 WAL created by this writer always starts with or contains the
matching marker before any acknowledged tail mutation.

Unknown nonzero cursor or marker versions are replay failures and are never
treated as version 1. They remain visible through the existing WAL replay
failure metric and health evidence. `WalWriter::open` also rejects an
unsupported nonzero snapshot cursor before accepting mutations, so a future
format cannot be silently overwritten by an older writer.

## 7. Crash And Failure Matrix

| Failure point | Durable files | Replay result |
| --- | --- | --- |
| Before old-WAL marker fsync | old snapshot, old WAL | Full legacy/current WAL replay |
| After marker fsync, before snapshot rename | old snapshot, WAL plus unmatched N | Full WAL replay; marker N is a no-op |
| Snapshot temp write/fsync failure | old snapshot, WAL plus unmatched N | Full WAL replay |
| After snapshot rename, before directory fsync | old or new snapshot after power loss, WAL plus N | Old snapshot replays full WAL; new snapshot skips through N |
| After confirmed snapshot, before truncate | new snapshot N, old WAL plus N | Skip covered prefix through N |
| After truncate, before truncated-file fsync | new snapshot N, empty or old WAL | Either complete snapshot or matching-marker replay |
| After truncate fsync, before header | new snapshot N, empty WAL | Snapshot alone is complete; appends remain blocked on header repair |
| After header fsync | new snapshot N, header N plus tail | Replay tail after header |
| Truncate fails and later append succeeds | new snapshot N, old prefix, marker N, tail | Skip prefix and replay tail |

At no point is the WAL truncated before the replacement snapshot exists.

## 8. Compatibility And Rollback

- Old snapshot plus old WAL: cursor is legacy; replay is unchanged.
- Old snapshot plus a future unmatched marker from a failed first compact:
  marker is a no-op and every mutation is replayed.
- New snapshot plus retained old WAL: matching marker selects the tail.
- New snapshot plus successfully truncated WAL: header selects the tail.
- New binaries can compact a legacy pair without an offline migration.

A binary that predates this format will ignore the additive snapshot cursor
but cannot deserialize the private checkpoint line as a `WalEntry`; its current
best-effort reader skips that line and replays all mutations. Rolling back
after a crash-retained prefix can therefore reintroduce allocator drift, but
does not lose the mutations. Operational rollback should compact successfully
with the new binary before installing an older one. This limitation must be
documented; pretending an old reader understands the new boundary would be
unsafe.

No state file is rewritten solely for migration. The first normal compact
introduces version 1.

## 9. RED/GREEN Behavior Matrix

Hosted Rust behavior tests use a `wal_checkpoint_` filter and compare the
complete allocator-relevant state, not private helper spelling.

Required RED behaviors:

1. `K:A -> K:B -> K:C` checkpoint plus retained prefix reloads with the same
   rule ports/action/bitmap as the checkpoint;
2. `port_sets` keys, bitmap indices, normalized ports and refcounts match;
3. `free_bitmap_indices`, `next_bitmap_idx`, `max_port_policies` and pending
   cleanup/quarantine state match;
4. a mutation appended after the checkpoint marker is applied exactly once;
5. marker durable but snapshot publication failed preserves legacy/full replay;
6. snapshot durable but truncate not executed skips the covered prefix;
7. truncate durable but header publication interrupted recovers from the
   snapshot and blocks acknowledgment of later mutations until header repair;
8. successful compact leaves zero mutation count and one matching header;
9. legacy snapshot and legacy WAL round-trip unchanged;
10. malformed covered-prefix lines do not count as current replay failures,
    while malformed tail lines still do;
11. unsupported cursor/marker versions are observable replay failures;
12. checkpoint ID retry never reuses an ID and overflow never wraps.

If the parity test demonstrates capacity exhaustion, bitmap collision, or a
wrong enforcement projection rather than allocator drift alone, stop and
reclassify severity before implementing broader production behavior.

## 10. Observability

Existing WAL replay failure metrics remain authoritative for the selected
tail. Add structured compact/replay fields to existing logs:

- `checkpoint_id`;
- `checkpoint_version`;
- `covered_mutations`;
- `tail_replayed`;
- `prefix_discarded`;
- `header_required` on repair failures.

Do not log policy bodies or create a new metric family in this batch.

## 11. Scope

Production changes are limited to:

- `core/src/state.rs`: additive replay cursor type and `FirewallState` field;
- `core/src/wal.rs`: private checkpoint record, ID allocation, compact/replay
  state machines and behavior tests;
- `ci/check_neutron_stage1.py`: add one nonzero hosted Rust behavior filter;
- transaction/WAL documentation, implementation plan, program index and REVIEW
  register closure.

Existing `WalClient::append(WalEntry)` and control-plane mutation call sites
remain unchanged.

Explicit exclusions:

- no truncate-first ordering;
- no per-mutation LSN envelope or rule-level version map;
- no Neutron `neutron-state.wal` format change;
- no WAL segmentation, replication, remote writer or retained audit history;
- no allocator algorithm, policy semantics, map projection or API change;
- no generic persistence framework or Python/static source-shape checker;
- no privileged datapath evidence claim.

## 12. Acceptance

1. The snapshot explicitly identifies the WAL prefix it covers.
2. Every compact crash window recovers either the prior state plus full WAL or
   the new state plus tail, never the new state plus duplicate prefix effects.
3. `K:A -> K:B -> K:C` replay parity holds for every allocator field.
4. Old snapshots and ordinary mutation lines remain readable without offline
   migration.
5. No mutation append is acknowledged after truncation until the matching WAL
   header is durable.
6. Checkpoint records do not count toward mutation compaction thresholds.
7. Snapshot publication remains before WAL truncation in source and behavior.
8. The hosted `wal_checkpoint_` filter executes a nonzero test count.
9. Exact-head fast contracts, Rust behavior, warning-denied userspace and eBPF
   builds pass before `REVIEW-TXN-033` is marked fixed.
