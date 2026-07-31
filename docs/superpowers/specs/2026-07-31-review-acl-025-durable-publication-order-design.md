# REVIEW-ACL-025 Durable ACL Publication Order Design

Date: 2026-07-31

Status: approved design direction; formal written specification awaiting review

Analyzed target:
`v0.9-neutron-agent@afb122748850eb23c21afaa18a33a89e21c15cf1`

Tracked finding:

- `REVIEW-ACL-025`: ACL publication can activate a new pinned ACL bank before
  the matching instance state is durable.

## 1. Executive Decision

Both concrete ACL final-state publishers will adopt one durability invariant:

> A new ACL bank must never become active before the complete final
> `FirewallState` that describes it is durably installed.

The scope covers:

- managed/Neutron-owned publication in
  `ControlPlane::publish_acl_projection_locked`; and
- standalone/direct publication in
  `control_plane::standalone_acl::execute_standalone_publication`.

The implementation remains concrete in those two publishers. It does not add
a generic closure/future transaction framework, a new WAL record, or a new
configuration surface.

The new common order is:

```text
validate and construct final state
  -> persist transaction-created bitmap guard when required
  -> stage the complete inactive ACL bank
  -> apply and journal general-map mutations
  -> verify TC readiness when required
  -> strictly persist the complete final state
  -> advance the fragment publication epoch
  -> switch the active ACL bank
  -> strictly scrub conntrack
  -> scrub the old bank and perform existing cleanup
```

The durable final state is the transaction commit point for crash recovery.
Once it exists, a restart may converge forward to that state. Before it
exists, the new ACL bank cannot be active.

## 2. Current Code And Corrected Root Cause

The authoritative register currently describes
`ControlPlane::replace_owned_acl` switching the active bank and updating
in-memory state before `WalClient::compact`.

The present code has improved since the finding was first recorded:

- `compact_and_publish_state` changes `InstanceState.state` only after the
  compact acknowledgement succeeds;
- a synchronous managed final-state compact error attempts to restore the old
  active bank, reverse all recorded general-map mutations, scrub the failed
  shadow, clean transaction-created bitmaps, and restore the old durable state;
- standalone publication has a comparable immediate rollback path; and
- strict CT scrub failure also restores active-bank and durable preimages.

Therefore a normal compact error does not automatically leave a permanent
bank/disk split.

The remaining defect is the process-crash boundary. Both step planners still
place `AdvanceFragmentEpoch` and `SwitchBank` before final-state persistence:

```text
new bank active
  -> process exits before compact acknowledgement
  -> pinned active bank is new
  -> state.json still describes the old state
  -> in-process compensation never executes
```

This is a real durability-ordering bug even though startup drift detection can
later quiesce or repair some instances. Recovery checks are a safety net, not
an atomic commit protocol, and the old durable state cannot authoritatively
explain the already-published bank.

The same ordering is present in standalone publication. Fixing only the
managed function would knowingly retain the identical crash window in the
other supported public ACL path.

## 3. Considered Approaches

### 3.1 Recommended: durable final state before epoch and bank publication

Persist the complete final state after shadow/general staging and TC
verification, but before the fragment epoch and active-bank switch.

Advantages:

- removes every `new bank + old durable state` crash prefix;
- reuses the existing atomic `state.json.tmp`/rename/directory-fsync compact;
- keeps current JSON state and WAL formats;
- keeps the bank switch as the only datapath ACL publication point;
- retains the existing strict CT and rollback mechanisms; and
- requires changes only in the two concrete publishers and their Rust tests.

Trade-off:

- a crash after durable commit but before bank publication leaves durable new
  state with a live old bank. Restart must converge forward from the durable
  final state. This is intentional: persistence is the commit point, and
  client retry remains idempotent.

### 3.2 Managed-only reorder

Changing only `publish_acl_projection_locked` matches the literal historical
row but leaves standalone with the same defect.

Rejected because durability is a publication invariant, not a caller-specific
feature.

### 3.3 Two-phase instance WAL intent and commit

Write a prepare record, publish the bank, then write a commit record, with
startup resolving an incomplete prepare.

Rejected for this batch because it changes WAL schema and replay semantics,
overlaps `REVIEW-OPS-027` and other recovery debt, and is unnecessary to close
the identified bank/durable ordering defect.

## 4. Transaction And Lock Boundaries

No lock boundary changes.

Managed publication continues to hold:

1. the runtime lifecycle lock;
2. the instance write lock; and
3. the caller's already-quiesced ACL/CT runtime gate.

Standalone publication continues to hold the runtime lifecycle and instance
write locks used by its current final-state transaction.

The locks remain held across:

- final-state construction;
- allocator-guard persistence;
- shadow staging;
- general-map mutation;
- final-state persistence;
- epoch/bank publication;
- strict CT scrub; and
- immediate compensation.

After final-state persistence but before bank switch,
`InstanceState.state` contains the final state while packets still use the old
bank. This state is not exposed to another mutation because the instance write
lock remains held. Managed ACL/CT is quiesced; standalone packets continue to
use the complete old bank until the atomic switch.

## 5. Durable State Construction

The final durable snapshot is constructed before the commit step:

- it contains the complete final groups and policies;
- every released bitmap remains durably quarantined until cleanup succeeds;
- transaction-created bitmap guard semantics remain unchanged; and
- it contains the same ACL/CT configuration fields the current transaction
  would persist after bank switch.

The implementation must serialize and compact this exact snapshot once as the
final-state commit. It must not publish an intermediate state that describes
the new policies without their allocator quarantine metadata.

`compact_and_publish_state` remains the persistence primitive. No direct
`state.state = final_state` assignment is added.

## 6. Managed Publication Order

`managed_acl_publication_steps` changes from:

```text
InvalidateProjectionHealth
ApplyGeneral*
StageShadow
VerifyTc
AdvanceFragmentEpoch
SwitchBank
Persist
```

to:

```text
InvalidateProjectionHealth
ApplyGeneral*
StageShadow
VerifyTc
PersistFinalState
AdvanceFragmentEpoch
SwitchBank
```

The existing `SwitchBank` marker remains an assertion that the combined
fragment-epoch/bank helper completed publication.

On successful bank publication, the managed publisher returns receipts for
the applied general-map mutations and active-bank change exactly as today.
The outer strict CT transaction and post-commit cleanup remain in their
current order.

## 7. Standalone Publication Order

`StandaloneAclPublicationStep` changes from:

```text
PersistBitmapGuard
StageShadow
ApplyGeneral
AdvanceFragmentEpoch
SwitchBank
PersistFinalState
StrictCtScrub
```

to:

```text
PersistBitmapGuard
StageShadow
ApplyGeneral
PersistFinalState
AdvanceFragmentEpoch
SwitchBank
StrictCtScrub
```

The concrete executor moves final snapshot preparation and
`compact_and_publish_state` before
`execute_fragment_epoch_bank_publication`. Strict CT scrub stays after the
bank switch.

## 8. Crash Semantics

| Crash boundary | Durable state | Active bank | Recovery meaning |
| --- | --- | --- | --- |
| Before allocator guard | Old | Old | No transaction state committed |
| After allocator guard, before final compact | Old plus created-index quarantine | Old | Retry or recovery may clean/quarantine staged artifacts; new bank was never active |
| During shadow/general staging | Old or allocator guard | Old | No new-bank publication; existing drift/recovery paths remain authoritative |
| After final compact, before epoch advance | Final | Old | Final state is committed; restart converges forward |
| After epoch advance, before bank switch | Final | Old | Final state is committed; stale fragment context is safely fenced; restart converges forward |
| After bank switch, before CT scrub | Final | New | Bank and durable state agree; restart or retry completes cleanup |
| After CT scrub | Final | New | Normal committed state |

There is no allowed crash prefix with `durable=old` and `active_bank=new`.

This batch does not claim that every shadow/general-map write is itself atomic.
Partial general/CIDR mutation remains the separate `REVIEW-ACL-026` scope.

## 9. Runtime Failure And Compensation Matrix

| Failure phase | Required immediate recovery |
| --- | --- |
| Bitmap guard persistence | Return persistence error; no kernel publication |
| Shadow staging | Restore recorded preimages, scrub shadow, clean created bitmaps, restore allocator state as currently required |
| General-map mutation | Reverse every recorded mutation, scrub shadow, clean created bitmaps, restore allocator state |
| Final-state persistence | Do not call epoch/bank publication; reverse general mutations, scrub shadow, clean created bitmaps, and restore old durable state because compact outcome can be uncertain |
| Fragment epoch readiness/advance after final persistence | Active bank remains old; reverse general mutations, scrub shadow, clean created bitmaps, restore old durable state |
| Active-bank publication after final persistence | Explicitly restore the old bank because the failed update outcome is treated as uncertain; reverse general mutations; scrub the new bank only after old-bank restoration; clean created bitmaps; restore old durable state |
| Strict CT scrub | Restore old bank, reverse general mutations, scrub failed publication bank only after bank restoration, clean created bitmaps, restore old durable state |

Every compensation is attempted even after another compensation fails.
Error text retains the primary failure and appends all recovery failures.

If a required bank, general-map, or durable preimage cannot be restored:

- managed projection health stays `Unverified`;
- standalone runtime health becomes not ready with `recovery_required`;
- ACL/CT remains or is made quiesced; and
- the failed publication bank is not scrubbed when it may still be active.

The fragment epoch is monotonic and is not rolled back. Advancing it without a
bank switch only invalidates old fragment context and is fail-safe.

## 10. Acknowledgement And Retry Semantics

Final-state compact success is the crash-recovery commit point, but the API
does not return success until bank publication and strict CT scrub also
succeed.

If the process crashes after durable commit and before API success, restart
converges forward from the committed final state. A client retry is safe
because both publishers construct a complete final state and treat an equal
state as an idempotent reconcile.

If a live runtime step fails after durable commit, the process attempts to
restore the complete old publication and durable state before returning an
error. Failure to restore is reported as recovery-required, never as success.

## 11. RED Behavior Contract

Rust behavior tests, not Python source-shape checkers, will prove:

1. managed publication orders `PersistFinalState` before
   `AdvanceFragmentEpoch` and `SwitchBank`;
2. standalone publication has the same order;
3. every step prefix that contains `SwitchBank` also contains
   `PersistFinalState`;
4. a final-state persistence failure records no epoch advance or bank switch;
5. managed and standalone epoch failures after durable commit restore the old
   durable snapshot and general-map preimages without claiming a bank switch;
6. an uncertain bank-switch failure attempts old-bank restoration before
   failed-shadow scrub and restores the old durable snapshot;
7. strict CT failure continues to restore bank, general maps, created bitmap
   state, and durable state; and
8. rollback failure leaves the runtime unverified/quiesced or
   recovery-required.

The first RED commit contains tests and test helpers only. No production
ordering or rollback implementation is included.

Because local Cargo commands are prohibited, RED and GREEN compilation and
behavior evidence comes from GitHub Actions:

- `changes`;
- `fast-contracts`;
- `rust-behavior`; and
- warning-denied `rust-build`.

## 12. Files And Implementation Boundary

Expected production files:

- `agent/src/control_plane.rs`;
- `agent/src/control_plane/standalone_acl.rs`.

Expected documentation files:

- this design;
- the matching implementation plan; and
- the authoritative `REVIEW-ACL-025` backlog row after GREEN evidence.

Explicitly excluded unless RED proves the boundary insufficient:

- `agent/src/neutron_api.rs`;
- `core/src/wal.rs`;
- eBPF and ABI crates;
- Python agent, API, database, or deployment configuration;
- a new WAL intent/commit schema;
- background recovery workers;
- generic closure/future transaction frameworks; and
- static checkers that bind private Rust function names or source layout.

Any need to modify an excluded production area is a design deviation and must
be reported before editing.

## 13. Explicit Exclusions

This repair does not:

- fix `REVIEW-ACL-026` partial CIDR/general-map kernel writes;
- fix `REVIEW-ACL-044` or other bank cleanup/recovery debt;
- fix `REVIEW-ACL-023`, `REVIEW-TXN-024`, `REVIEW-TXN-027`, or
  `REVIEW-ACL-045`;
- change ACL rule semantics, default actions, source-port support, priorities,
  or controller conflict rules;
- change fragment lookup or forwarding behavior;
- change bitmap reuse/quarantine semantics delivered by `REVIEW-ACL-059`;
- change strict CT scrub semantics;
- add a field-smoke requirement; or
- claim any deferred privileged ACL evidence.

## 14. Completion Criteria

`REVIEW-ACL-025` can become `fixed` only when:

- both concrete publishers satisfy durable-before-bank ordering;
- all approved failure compensations are covered by Rust behavior tests;
- the original switch-before-durable tests are proven RED on the old
  implementation;
- exact-head `rust-behavior` is GREEN;
- exact-head warning-denied Rust/eBPF/static builds are GREEN;
- no excluded production file was modified without a reviewed design update;
  and
- the authoritative backlog records exact RED/GREEN commits and CI evidence.

No privileged field evidence is required for closing this ordering defect.
Pinned-map field testing may still exercise the behavior later as part of the
broader deferred ACL evidence program.
