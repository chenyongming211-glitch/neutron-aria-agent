# REVIEW-TXN-031/034 Delete Failure Recovery Design

**Status:** implemented and hosted-CI verified; `REVIEW-TXN-031/034` fixed

**Date:** 2026-08-13

**Owning findings:** `REVIEW-TXN-031`, `REVIEW-TXN-034`

## 1. Decision

Keep the current single-pending-intent WAL schema and repair the two boundaries
which make a failed direct port delete untruthful:

1. every failure after a durable `DeleteIntent` publishes one phase-aware
   blocked delete state instead of retaining the old `ready/enforce` port row;
2. WAL replay matches commits to the pending intent kind and identity, so an
   unrelated `SnapshotCommit`, malformed commit, or mismatched `DeleteCommit`
   cannot clear an unresolved delete intent;
3. only a matching durable `DeleteCommit` removes the authoritative port and
   closes forward recovery.

No WAL record field, public UDS DTO, Python API, recovery mode, or generic
closure/future transaction framework is added. The existing `REVIEW-TXN-027`
delete-forward recovery remains the execution mechanism after restart.

## 2. Verified Current Root Causes

### 2.1 Post-intent failures return without publishing transaction truth

`apply_delete_neutron_port` appends and fsyncs `DeleteIntent` before datapath
mutation. Four failure boundaries then return directly without changing live
runtime state:

- `neutron.delete.after_intent`;
- ACL purge failure;
- `neutron.delete.after_acl_purge`;
- registry detach failure.

The last three can occur after the ACL/CT gate has been quiesced. The retained
runtime still contains the prior port status, commonly `ready` with ACL
`effective_action=enforce`, while the actual datapath is quiesced or delete
convergence is unknown. The top-level runtime also lacks a pending/blocked
delete identity.

### 2.2 Existing blocked-delete construction copies stale port evidence

`build_blocked_delete_runtime` is used only after physical detach or delete
commit failure. It sets `pending_generation`, clears `desired_hash`, and marks
the authority blocked, but clones `port_statuses` unchanged. The global status
is therefore blocked while the affected port may still advertise
`ready/enforce`.

### 2.3 Replay clears pending intent for any commit

The generic replay arm accepts either `SnapshotCommit` or `DeleteCommit`,
validates only the state hash, stores the commit, and unconditionally sets
`pending_intent=None`. Its invalid-hash branches also clear the pending intent.

After a failed delete releases `apply_lock`, a health/status checkpoint can
append a valid `SnapshotCommit`. Restart then sees no delete intent and cannot
execute the existing forward recovery. A corrupt or mismatched commit can cause
the same loss.

### 2.4 ACL purge discards the proven failure phase

`purge_neutron_acl_transactionally` returns `String`. A gate-update failure
happens before quiesce and proves only `effective_action=unchanged`; an owned
projection/strict-flush failure happens after successful quiesce and proves
`effective_action=bypass`. Converting both to text prevents the delete status
path from reporting the action it can actually prove.

## 3. Architecture Contracts

This batch implements the already approved bug-hunt program contracts:

- `STATUS-TRUTH`: `ready/enforce` is published only when runtime evidence proves
  enforcement;
- `TXN-DURABLE`: intent precedes mutation, unresolved intent survives unrelated
  work, and commit is durable before successful publication;
- `TXN-IDEMPOTENT`: retrying forward delete recovery closes exactly the same
  intent without duplicating or regressing state.

The direct delete remains a forward-only transaction after mutation begins. It
must not be converted to the snapshot `rollback_to_last_applied` contract.

## 4. Alternatives Considered

### 4.1 Recommended: kind/identity-aware replay with phase-aware blocked state

Use the existing record kinds, embedded port identity, generation, and status
hash. Persist blocked status through `SnapshotCommit` without treating that
record as completion of a pending delete. Require the matching `DeleteCommit`
to close it.

This fixes both root causes, preserves old WAL compatibility, and reuses the
existing forward-recovery path.

### 4.2 Add a transaction ID or epoch to every WAL record

This becomes appropriate if the architecture later permits multiple concurrent
intents or multiple writers. Today it would require record migration,
checkpoint compatibility, compaction changes, and Python/status coordination
without adding safety beyond the current single-pending-intent model.

### 4.3 Publish blocked state only in RAM

This is insufficient. An unrelated commit could still clear the durable intent,
and restart could lose both the truthful port status and the recovery entry.

## 5. Commit-To-Intent Matching

Replay validates every commit status hash before considering it authoritative.
An invalid commit increments the replay failure count and never clears a pending
intent.

### 5.1 No pending intent

A valid `SnapshotCommit` or `DeleteCommit` remains an ordinary committed state.
Legacy hashless commits retain their existing compatibility rules.

### 5.2 Pending snapshot intent

A valid `SnapshotCommit` retains the existing snapshot completion semantics.
The protected `inventory_unavailable` branch keeps its stricter verified
barrier. A `DeleteCommit` cannot close a snapshot intent. This batch does not
otherwise redesign snapshot-intent identity matching.

### 5.3 Pending delete intent

A `SnapshotCommit` is a status checkpoint, not transaction completion. It may
advance `last_committed_state` only when it preserves the exact blocked delete
identity:

- `pending_generation == Some(intent.generation)`;
- `desired_hash == None`;
- `authority_state == blocked_recovery_required`;
- every intended port remains in both the managed-port and port-status maps;
- accepted/applied generation and applied hash remain on the preceding committed
  baseline.

The pending delete remains attached to the scan after such a checkpoint.

A `DeleteCommit` closes the pending delete only when all of these are true:

- the status hash is valid;
- `accepted_generation == intent.generation`;
- accepted/applied generation and applied hash match the preceding committed
  baseline;
- `pending_generation == None`;
- `desired_hash == applied_desired_hash`;
- every intended port is absent from both managed-port and port-status maps.

A mismatched commit increments replay failures, does not replace the preceding
committed baseline, and preserves the pending delete.

The WAL remains single-intent. Admission of a new intent while another is
pending is unchanged and outside this batch.

## 6. Phase-Aware Blocked Delete State

Introduce one concrete blocked-delete builder which receives the previous
committed runtime, exact port, generation, stable failure reason, WAL status,
and proven ACL action.

Every post-intent failure retains the port in authoritative `managed_ports` and
sets:

```text
pending_generation = delete generation
desired_hash = None
authority_state = blocked_recovery_required
recovery_cause = None
```

The affected port row becomes non-ready. Its attach domain is blocked for
delete convergence. If ACL is managed, its domain is degraded/blocked with the
same reason and one exact action:

| Failure boundary | Proven ACL action |
| --- | --- |
| after-intent fault before gate mutation | `unchanged` |
| ACL gate update fails before quiesce | `unchanged` |
| owned ACL publication/strict flush fails after quiesce | `bypass` |
| after-ACL-purge fault | `bypass` |
| detach fails after successful purge | `bypass` |
| after-detach fault or delete-commit failure | `bypass` |

`purge_neutron_acl_transactionally` returns the existing
`NeutronAclReconcileError` classification instead of erasing the phase into a
plain string. Its other callers retain their existing transaction behavior;
only the direct-delete status path consumes the proven action in this batch.

## 7. Failure Publication Sequence

All failures after successful `DeleteIntent` append use one concrete publisher:

```text
primary delete failure
  -> build retained-port blocked runtime with exact phase/action
  -> append SnapshotCommit(blocked runtime)
     -> replay stores blocked status but retains DeleteIntent
  -> publish blocked runtime to RAM
  -> return error and detached=false
```

If the blocked status checkpoint fails, RAM is still published blocked with a
checkpoint-failure WAL status, the response includes both errors, and the
original durable `DeleteIntent` remains the startup recovery authority.

The successful path is unchanged in principle:

```text
DeleteIntent -> purge -> detach -> matching DeleteCommit -> remove RAM port
```

Port absence and `detached=true` are never published before `DeleteCommit`
fsync succeeds.

## 8. Restart And Retry

Startup replay returns the retained delete intent together with the latest
valid blocked checkpoint. Existing `recover_incomplete_wal_intent` then:

1. reconstructs the exact stored port;
2. performs idempotent attach if needed;
3. purges owned ACL runtime while quiesced;
4. detaches;
5. appends a matching `DeleteCommit`;
6. publishes port absence only after that commit.

Runtime recovery failure or recovery-commit failure uses the same truthful
blocked port evidence and leaves the delete intent pending for the next retry.
No snapshot rollback endpoint is advertised for a hashless delete identity.

## 9. RED And GREEN Evidence Plan

Rust behavior tests must demonstrate the following before production code is
changed:

1. a delete intent followed by a valid blocked `SnapshotCommit` still replays
   the exact delete intent and blocked port state;
2. an invalid or mismatched commit cannot clear or replace that intent;
3. only a matching `DeleteCommit` clears the intent and removes the port;
4. pre-quiesce failure produces non-ready ACL `unchanged` evidence;
5. post-quiesce purge or detach failure produces non-ready ACL `bypass`
   evidence and a blocked/pending delete authority;
6. blocked status checkpoint failure still publishes blocked RAM and preserves
   the original intent;
7. restart recovery observes the blocked checkpoint, retries forward, and
   closes with a matching delete commit.

Tests use callable Rust behavior and existing fault-injection boundaries. No
Python checker may parse Rust helper names, local variables, source order, or
private function shape.

Hosted GREEN requires exact-head `fast-contracts`, `rust-behavior`, and
warning-denied Rust/eBPF `rust-build`. No local Cargo command is allowed.

## 10. Files And Scope

Production and behavior work is limited to:

- `agent/src/neutron_wal.rs`: commit-kind/identity matching and replay tests;
- `agent/src/neutron_api.rs`: phase-aware purge classification, blocked delete
  publication, direct-delete routing, restart/retry tests;
- this design, its implementation plan, the transaction contract, and the
  REVIEW register for evidence/status updates.

Explicitly excluded:

- no WAL schema or checkpoint format change;
- no concurrent or multiple pending-intent model;
- no new UDS endpoint, status enum, recovery cause, or Python behavior;
- no snapshot rollback semantic change;
- no `REVIEW-TXN-032/033/035`, orphan cleanup, or unrelated ACL refactor;
- no privileged datapath or field PASS claim.

## 11. Acceptance

1. No failure after durable `DeleteIntent` leaves the affected port
   `ready/enforce`.
2. The live and durable pending identity is hashless, blocked, retained-port,
   and operator-recoverable until a matching delete commit exists.
3. Snapshot/status checkpoints, invalid commits, and mismatched delete commits
   cannot clear the delete intent.
4. Pre-quiesce and post-quiesce failures publish `unchanged` and `bypass`
   respectively.
5. A matching delete commit is the only record that publishes successful port
   absence.
6. Restart recovery remains forward-only and idempotent.
7. Existing snapshot, protected-inventory, WAL compaction, and legacy commit
   behaviors remain green.
8. Exact-head hosted CI passes with warnings denied before either REVIEW row is
   closed.

## 12. Delivery Evidence

- RED `db14bfa`, Build
  [31697811403](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/31697811403):
  `rust-behavior` failed on the absent phase-aware builder and blocked failure
  publisher (`E0061`, `E0425`), while fast contracts passed.
- GREEN implementation `477761e` introduced exact commit-to-intent matching and
  phase-aware delete failure publication. Its first hosted run exposed one
  pre-existing legacy hashless delete-commit compatibility requirement.
- Compatibility follow-up `d8ae123`, exact-head Build
  [31698764813](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/31698764813):
  `fast-contracts`, `rust-behavior`, `rust-build`, eBPF stack budget, database
  contracts, and clean-agent install all passed with warnings denied.
- No WAL record schema, public UDS/status vocabulary, Python behavior, or
  privileged datapath evidence changed.
