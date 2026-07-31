# REVIEW-OPS-019 Neutron WAL Lifecycle Design

Date: 2026-07-31

Status: fixed on 2026-07-31; RED behavior contract, production implementation,
and exact-head hosted Rust/eBPF CI complete

Analyzed target:
`v0.9-neutron-agent@f8baf4aa1557ec9395d34fd1adf5628cd101144d`

Tracked finding:

- `REVIEW-OPS-019`: the Neutron snapshot WAL is append-only and has no
  checkpoint, compaction, or capacity bound.

## 1. Executive Decision

The Neutron WAL will compact synchronously, immediately before an append that
would cross a fixed soft byte threshold. Compaction will run under the existing
Neutron `apply_lock`; it will not add a background task, a second lock, a
second persistent file format, or a deployment setting.

The initial limits are:

- soft compaction threshold: 16 MiB (`16 * 1024 * 1024` bytes);
- hard capacity limit: 64 MiB (`64 * 1024 * 1024` bytes).

A canonical compacted WAL contains only:

1. the last valid committed `NeutronWalState`, if one exists; and
2. the single unresolved snapshot or delete intent after that commit, if one
   exists.

The canonical entries use the existing JSON-lines `NeutronWalEntry` format.
No format version, snapshot sidecar, rotated segment, or compatibility
migration is introduced.

Compaction writes a same-directory temporary file, flushes and fsyncs it,
atomically renames it over `neutron-snapshot.wal`, and fsyncs the parent
directory. A crash therefore leaves either the old replayable WAL or the new
replayable checkpoint. A stale temporary file is not replayed.

If soft-threshold compaction fails before replacement and the ordinary append
still fits below the hard limit, the append remains available and a structured
warning records the maintenance failure. If neither the current WAL nor a
prepared canonical checkpoint can accept the entry below 64 MiB, the append is
rejected before changing the WAL.

This design bounds future WAL growth while preserving all existing
intent/commit recovery semantics. It does not claim to repair an already
tampered WAL: replay uncertainty prevents compaction so evidence is not erased.

## 2. Confirmed Current Behavior And Defect

`agent/src/neutron_wal.rs` currently:

- appends one JSON object and newline for every snapshot intent, snapshot
  commit, delete intent, and delete commit;
- flushes and fsyncs each append and fsyncs the parent directory;
- replays every valid line from the beginning on every restart and on several
  protected recovery paths;
- keeps the last valid commit when a later record is malformed;
- exposes at most one unresolved intent after replay; and
- never checkpoints, rotates, truncates, or rejects based on file size.

Every production append is serialized by `NeutronApiState.apply_lock`.
Startup replay occurs before concurrent mutation. The WAL itself therefore
does not need to become an independently concurrent persistence subsystem.

The Neutron UDS request body is limited to 1 MiB. A commit contains the
normalized managed-port and port-status state rather than an unbounded
datapath dump. The 16 MiB/64 MiB defaults leave room for multiple full-state
records while stopping indefinite growth.

The defect is deterministic: repeated full resync, scoped apply, runtime
reconciliation, link-health projection, pending recovery, and delete
operations append full commit state forever. Restart cost and disk use grow
with historical activity rather than current recoverable state.

## 3. Considered Approaches

### 3.1 Synchronous canonical compaction before append

This is the selected approach.

- It reuses the existing `apply_lock`.
- It preserves one WAL file and the current JSON-lines reader.
- It makes the capacity decision before a new mutation record is written.
- It has deterministic tests without timers or scheduling races.
- It adds no idle background I/O.

### 3.2 Periodic background compaction

Rejected for this repair. A background task would need to coordinate with
foreground intent/commit pairs and process shutdown. It would add another
concurrency boundary but would not improve correctness: an idle WAL is not
growing, and the next append is already a safe point to enforce the limit.

### 3.3 Snapshot plus WAL-tail files

Rejected for this repair. A separate checkpoint format and tail file would
require cross-file generation identity, startup selection rules, upgrade and
rollback compatibility, and two-file crash recovery. Those costs are not
necessary because the current commit record already contains a complete
recoverable state.

### 3.4 File rotation retaining old segments

Rejected. Rotation bounds an individual file but not total disk use or replay
work unless old segments are deleted. Deleting them safely requires the same
canonical-state reasoning as compaction while retaining more operational
surface.

## 4. Canonical Replay Model

Compaction must not build a checkpoint from the public decorated replay state.
When an intent is unresolved, public replay overlays:

- `pending_generation`;
- `desired_hash`; and
- `authority_state = "wal_intent_without_commit"`

onto the last committed state. Persisting that decorated view as the baseline
would manufacture a commit that never occurred.

The implementation will therefore separate internal scanning from public
projection:

```text
NeutronWalScan
  last_committed_state: Option<NeutronWalState>
  pending_intent: Option<PendingNeutronIntent>
  replayed: u64
  failures: u64
```

The internal scan applies the same integrity and protected-inventory rules as
the current replay loop but retains the exact last valid committed state before
pending presentation fields are overlaid.

`NeutronWal::replay()` will project its existing `NeutronWalReplay` from that
scan. Existing callers and status strings remain unchanged.

The compactor consumes the scan:

- zero commits and zero pending intents produce an empty checkpoint;
- one last commit produces one `SnapshotCommit` checkpoint entry;
- a last commit plus pending intent produces the commit followed by the
  reconstructed intent;
- a pending intent with no prior commit produces only that intent.

`SnapshotCommit` is the canonical checkpoint carrier even if the last valid
record was a `DeleteCommit`. Current replay treats ordinary snapshot and delete
commits identically once their status hash is valid, so this does not change
the recovered state.

## 5. Pending Intent Preservation

### 5.1 Ordinary snapshot intent

The canonical entry preserves:

- generation;
- desired hash;
- normalized port IDs;
- affected domains;
- affected ports; and
- absence of a recovery cause.

Legacy snapshot intents that omitted `port_ids` are normalized using
`affected_ports`, matching current replay behavior.

### 5.2 Protected inventory-unavailable snapshot intent

The canonical entry preserves the typed
`inventory_unavailable` recovery cause and recomputes the existing integrity
hash from the canonical fields. Compaction must not resolve, downgrade, or
convert this intent to an ordinary snapshot intent.

The last committed baseline remains separate so the existing
`protected_inventory_snapshot_commit_valid()` closure checks retain the same
meaning after compaction.

### 5.3 Delete intent

The canonical entry preserves:

- port ID;
- generation;
- affected domains; and
- the affected managed-port object when it was present.

Legacy delete intents without a stored port remain representable with
`port: null`. Compaction must not invent a port from the current committed
state.

### 5.4 Invalid or ambiguous input

If scanning reports any malformed line, invalid status hash, invalid protected
intent, invalid protected commit, or I/O failure, compaction is refused.
The original bytes remain available for diagnosis and the existing replay
failure count remains authoritative.

## 6. Threshold And Capacity Algorithm

Before opening the WAL for append:

1. serialize the requested entry and its trailing newline;
2. read the current WAL length, treating a missing file as zero;
3. use checked integer addition for `current_length + entry_length`;
4. if the projected length is at most 16 MiB, use the existing append path;
5. otherwise scan the current WAL and prepare canonical checkpoint bytes in
   memory without changing the live file;
6. use checked addition for
   `checkpoint_length + requested_entry_length`;
7. if the prepared total exceeds 64 MiB, reject the append and leave the live
   WAL byte-for-byte unchanged;
8. if checkpoint preparation fails and the unmodified projected length is at
   most 64 MiB, log the failure and append to the original WAL;
9. if checkpoint preparation fails and the unmodified projected length exceeds
   64 MiB, reject the append and leave the live WAL unchanged;
10. if the checkpoint fits, attempt to install it atomically;
11. if installation fails before rename and the unmodified projected length is
    at most 64 MiB, log the failure and append to the original WAL;
12. if installation fails before rename and the unmodified projected length
    exceeds 64 MiB, reject the append with the original WAL unchanged;
13. if installation reaches rename but later durability confirmation fails,
    return the replacement error without a fallback append; and
14. after a confirmed checkpoint install, append and durably sync the requested
    entry through the existing path.

Compaction may also be attempted when a legacy WAL is already larger than the
hard limit. A valid canonical checkpoint can bring it below the limit before
the requested entry is appended. The hard limit is therefore a bound on the
post-checkpoint active WAL, not a reason to permanently strand a recoverable
legacy file.

If the canonical checkpoint alone exceeds 64 MiB, the append is rejected.
The implementation does not silently discard ports, statuses, or an intent to
force the checkpoint under the limit.

No time threshold is added. Time does not cause the file or replay work to
grow, and a periodic timer would require the rejected background concurrency
model. Every future write is a deterministic opportunity to enforce the byte
bound.

## 7. Atomic Replacement

The checkpoint temporary file lives in the WAL directory and is never selected
by replay.

The ordered operation is:

1. remove a stale owned temporary file left by a prior pre-rename crash;
2. create a new temporary file without append mode;
3. write every canonical JSON line and trailing newline;
4. flush the buffered writer;
5. call `sync_all()` on the temporary file;
6. atomically rename the temporary file over `neutron-snapshot.wal`;
7. call `sync_all()` on the parent directory; and
8. only then report checkpoint success.

Crash outcomes:

| Crash point | Restart-visible state |
| --- | --- |
| Before temporary-file creation | old WAL |
| During temporary-file write | old WAL; temporary file ignored |
| After temporary-file fsync, before rename | old WAL; temporary file ignored |
| After rename | new canonical WAL |
| After directory fsync | new canonical WAL durably named |

If rename has completed but directory fsync reports an error, the function
returns an error and does not blindly append through an assumed old path. This
matches the existing append contract: a late fsync error can be durability
ambiguous and must not be converted into a duplicate record.

## 8. Error Semantics

### 8.1 Soft compaction failure

When the old WAL plus the new entry remains within 64 MiB and checkpoint
replacement has definitely not occurred:

- emit one structured warning containing the current bytes, entry bytes, soft
  threshold, hard limit, and error;
- append and fsync the requested entry normally;
- retry compaction on the next append that remains above the soft threshold.

The ACL authority state is not changed merely because optional maintenance
failed while the requested record remained durably appendable.

### 8.2 Hard-capacity rejection

The returned error has a stable
`neutron WAL hard capacity exceeded` prefix and includes:

- current byte length;
- requested entry byte length;
- candidate checkpoint byte length when available;
- hard limit; and
- checkpoint failure when relevant.

The existing callers already map append failure to
`wal_intent_failed`, `wal_commit_failed`, or the corresponding recovery
failure state. No new HTTP status or response schema is required.

Capacity rejection occurs before opening the live WAL for append and before
installing a candidate that cannot accept the requested entry. The live bytes
therefore remain unchanged on a pure hard-capacity failure.

### 8.3 Replacement ambiguity

An error after rename is not classified as a soft pre-replacement failure.
The caller receives an error and existing WAL recovery determines whether the
checkpoint became durable. The implementation must not fall back to an append
that could duplicate the requested record.

## 9. Compatibility And Operational Behavior

- Existing WAL files replay unchanged.
- A compacted WAL is readable by code that understands the current entry enum.
- Existing `status`, `replayed`, `failures`, `pending_intent`, status hashes,
  and protected inventory rules retain their public meaning.
- File permissions follow the current WAL creation behavior.
- The checkpoint temporary file is internal and does not become a recovery
  candidate.
- No operator action or config migration is required.
- The 16 MiB and 64 MiB values are deliberately not configurable in this
  repair. Configuration can be considered later only with production size and
  replay-latency evidence.
- No privileged host, pinned BPF map, OVS bridge, or Neutron deployment is
  needed to validate this persistence algorithm.

## 10. Test Contract

Rust behavior tests in `agent/src/neutron_wal.rs` will prove:

1. repeated valid commit appends cross the test soft threshold, compact, and
   retain the exact last committed state;
2. file size stays within the injected test hard limit over repeated
   intent/commit cycles;
3. an ordinary snapshot pending intent survives compaction with the prior
   committed baseline unchanged;
4. a delete pending intent, including a legacy absent-port form, survives
   compaction;
5. a protected inventory-unavailable intent survives with a valid recomputed
   intent hash and unchanged recovery closure;
6. a valid commit after a compacted pending intent resolves it normally;
7. a malformed tail or invalid latest commit prevents compaction and preserves
   the original bytes;
8. a pre-rename temporary-write or rename failure below the hard limit falls
   back only when replacement definitely did not occur;
9. a crash fixture with a complete stale temporary file still replays the old
   live WAL;
10. a hard-capacity rejection leaves the live WAL byte-for-byte unchanged;
11. a valid oversized legacy WAL can compact below the hard limit and accept a
    new record;
12. a canonical checkpoint larger than the hard limit is rejected without
    dropping state; and
13. existing tampered-commit and protected-inventory regression tests remain
    unchanged and pass.

Thresholds are injected only through a test constructor or private limits
value. Production callers continue using `NeutronWal::new()` with the fixed
defaults.

The RED phase adds these behavior contracts without production compaction
code. GitHub Actions must show failures caused by the missing lifecycle
interface or behavior, not compilation mistakes or unrelated tests.

## 11. Implementation Boundary

Expected production scope:

- `agent/src/neutron_wal.rs`
  - internal scan result;
  - replay projection refactor;
  - limits;
  - checkpoint preparation;
  - atomic replacement;
  - capacity-aware append;
  - focused Rust behavior tests.

Expected documentation scope:

- this design;
- a separate implementation plan;
- `docs/openstack-neutron-aria-details/12-review-bug-backlog.md` after GREEN
  evidence.

`agent/src/neutron_api.rs` is excluded unless RED proves that the existing
append error mapping cannot preserve the approved semantics. No eBPF, ABI,
map, ACL policy, Python agent, database, API contract, or field-smoke code is
part of this repair.

## 12. Delivery And Evidence

The delivery sequence is:

1. commit this approved design;
2. complete written-spec review;
3. write and commit the implementation plan;
4. add RED Rust behavior tests without production code;
5. push and record the expected hosted `rust-behavior` failure;
6. implement the minimal GREEN lifecycle changes;
7. push and require warning-denied Rust/eBPF/static CI to pass;
8. update the backlog with exact commits and CI evidence.

No local `cargo build`, `cargo check`, or `cargo test` command is permitted.
All Rust compilation and behavior evidence comes from GitHub Actions.

`REVIEW-OPS-019` becomes `fixed` only after exact-head hosted CI proves the
bounded-growth, replay, corruption, and crash-safety contracts. Privileged
field evidence is not applicable to this filesystem-only lifecycle repair.

### Delivered evidence

RED commit `5c79a28` added nine lifecycle behavior tests without production
implementation. Exact-head Build
[`30601218345`](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/30601218345)
failed only in
[`rust-behavior` job `91064136403`](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/30601218345/job/91064136403)
on the intentionally missing `NeutronWalLimits`, `with_limits`,
`compact_now_for_test`, and `checkpoint_temp_path_for_test` interfaces. The
independent `rust-build` job passed.

GREEN commit `c3d8238` implements the approved synchronous lifecycle in
`agent/src/neutron_wal.rs`: canonical checkpointing preserves the last valid
commit and at most one unresolved intent, uncertain replay refuses compaction,
same-directory replacement follows file-fsync/rename/directory-fsync ordering,
and an append that cannot fit below the 64 MiB hard limit is rejected before
the live WAL changes. Production thresholds remain fixed at 16 MiB soft and
64 MiB hard.

Exact-head Build
[`30601633217`](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/30601633217)
passed. The
[`rust-behavior` job `91065427370`](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/30601633217/job/91065427370)
passed all 47 focused `neutron_wal` behaviors, including the nine new lifecycle
cases. The independent
[`rust-build` job `91065427305`](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/30601633217/job/91065427305)
passed the warning-denied Rust/eBPF, userspace-static, and agent-static builds.
No privileged field evidence is required because this repair changes only the
filesystem WAL lifecycle.

## 13. Explicit Exclusions

This repair does not:

- fix `REVIEW-TXN-024`, `REVIEW-TXN-027`, or other recovery-state defects;
- reorder ACL bank publication;
- repair or discard a corrupt WAL automatically;
- add WAL encryption, compression codecs, rotation archives, or remote backup;
- introduce periodic compaction;
- expose WAL limit configuration;
- change UDS request or response schemas;
- alter ACL/CT forwarding behavior; or
- claim any deferred privileged ACL evidence.
