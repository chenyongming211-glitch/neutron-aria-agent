# REVIEW-ACL-062 Multi-Direction Publication and Recovery Design

Date: 2026-08-01

Status: fixed in source; exact implementation-head hosted CI complete

Analyzed target:
`v0.9-neutron-agent@d729f432217e380c3e3a1e65bff2c4454e1ea5f3`

Tracked finding: `REVIEW-ACL-062`

Delivery evidence:

- Approved design: `bba7035`.
- RED tests: `fb20546`; Build
  [`30683268154`](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/30683268154)
  failed in `rust-behavior` on the intentionally absent recovery model while
  `fast-contracts`, `neutron-db-contracts`, and the independent warning-denied
  Rust/eBPF build passed.
- GREEN implementation: `44743f5`; exact-head Build
  [`30683913104`](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/30683913104)
  passed `fast-contracts`, `neutron-db-contracts`, all selected ACL-062 Rust
  behaviors, and the warning-denied eBPF/userspace/agent static build.
- No local Cargo command or privileged field run was performed. The repair is
  a userspace transaction, durable-state, and startup-replay contract whose
  closure evidence is fault-injected Rust behavior plus hosted compilation;
  any later pinned-map field run is supplementary and remains unclaimed.

## 1. Executive Decision

`direction=both` will be one final-state publication for every local QoS and
Mirror add, update, and delete. The four legacy standalone loops will stop
changing a direction, mutating RAM, and appending best-effort WAL entries one
at a time.

The implementation will reuse the existing local-domain operation, receipt,
preimage, reverse-compensation, and strict-compaction machinery already used
by managed QoS and Mirror writes. It will not add another generic
closure/future transaction framework. Standalone and
`NeutronAttachOwnedStandaloneAcl` will build the same complete final state and
execute the same domain transaction; managed mode keeps its existing group
ownership and projection routing around that transaction.

If a primary operation fails, every successfully applied receipt is
compensated in reverse order. An update receipt restores the complete prior
rule rather than deleting the replacement. The returned error contains the
primary error and every compensation or durable-restore error.

When compensation or durable restoration cannot prove the old publication was
restored, the old desired state remains the durable authority and gains a
versioned local-projection recovery record for the affected domain. Further
writes to that QoS or Mirror domain fail with recovery-required status.
Independent domain records may coexist. Startup must scrub or validate and
replay the durable preimage before it clears the records and reports those
domains writable again.

The policy portion of the historical finding is already fixed by the
`REVIEW-ACL-057/066` shadow-bank final-state transaction. This batch adds a
regression assertion for that routing but does not replace or modify the ACL
publication transaction.

## 2. Revalidated Current State

### 2.1 Historical description that is no longer true

The Register says policy, QoS, and Mirror handlers discard rollback errors
with `let _ = ...`. That statement no longer matches the complete current
tree:

- standalone policy add, update, delete, `direction=both`, and batch mutations
  route through `apply_standalone_acl_mutations_locked` and one shadow-bank
  publication;
- managed QoS and Mirror mutations route through
  `execute_managed_local_projection_transaction`;
- that transaction captures exact prior rules, attempts receipts in reverse,
  aggregates compensation errors, and strictly compacts one final state; and
- the legacy standalone QoS and Mirror add loops have returned rollback errors
  to the caller since commit `f6b4681`.

The finding therefore remains real, but its production scope is narrower and
its current failure is more severe than the stale title suggests.

### 2.2 Remaining QoS add/update defect

`add_qos_standalone_locked` expands `both` and processes each direction
separately. After a successful direction it immediately:

1. replaces the rule in the pinned QoS map;
2. replaces the rule in `FirewallState.qos_rules`; and
3. appends one best-effort `AddQos` WAL entry.

If the later direction fails, rollback calls `delete_qos_rule` for the earlier
direction. For a create this may remove the newly inserted rule. For an update
it is incorrect: the prior rate, burst, priority, and mode were overwritten,
and deleting the replacement does not restore that prior rule.

A rollback failure is included in the API error, but the process keeps
accepting writes while RAM, durable state, and the pinned map may describe
different publications. A WAL append failure is logged and does not fail the
request.

### 2.3 Remaining Mirror add/update defect

`add_mirror_standalone_locked` has the same per-direction publication shape.
On a later failure it deletes the earlier replacement instead of restoring the
prior target interface and ifindex. RAM and WAL also change after each
direction, and persistence acknowledgement remains best effort.

### 2.4 Remaining delete defect

The standalone QoS and Mirror delete paths defer RAM and WAL mutation until
all requested kernel deletes succeed, which is better than the add paths.
However, a later delete failure calls a helper that returns at its first
restore failure. The caller receives a compound string, but no recovery fence
is recorded and subsequent writes can build on an unverified kernel state.

### 2.5 Existing machinery that should be reused

The managed local-domain transaction already provides the required neutral
mechanics:

- `ManagedLocalDomainOperation` describes QoS/Mirror upserts and deletes plus
  FQ-qdisc preparation;
- `ManagedLocalDomainReceipt` records the applied rule and its complete prior
  rule, if any;
- `managed_local_domain_compensation_operations` turns receipts into exact
  restoration operations;
- `execute_managed_local_projection_compensations` attempts all receipts in
  reverse; and
- `managed_local_projection_persist` strictly compacts one complete state.

Those mechanics are not intrinsically Neutron-specific. The managed path adds
owner-prefix and general-map planning outside the domain operation sequence.
The standalone path can use an empty general-map delta and avoid inheriting
managed ownership semantics.

## 3. Goals

- Treat one `direction=both` QoS or Mirror request as one acknowledged
  final-state publication.
- Restore the complete preimage of an updated rule after a later-direction
  failure.
- Restore deleted rules with all fields intact.
- Attempt every known compensation in reverse order.
- Return the primary failure together with every compensation and durable
  restoration failure.
- Strictly persist once after every direction has applied successfully.
- Never publish final RAM state before strict durable acknowledgement.
- Persist and expose an explicit recovery-required condition when restoration
  is incomplete.
- Repair a recovery-required local projection from its durable preimage during
  startup before clearing the condition.
- Reuse existing production transaction primitives and reduce legacy code.

## 4. Non-Goals

This batch does not:

- change the public QoS, Mirror, or policy request/response schemas;
- add QoS or Mirror shadow banks or change their eBPF map ABI;
- make two map writes simultaneously visible to packets;
- change rate, burst, shaping downgrade, mirror-target, or direction
  semantics;
- change Neutron owner-prefix, retained-group, or general-map projection
  rules;
- modify the standalone ACL bank transaction;
- resolve general-group overlap (`REVIEW-ACL-063`);
- address URI encoding (`REVIEW-CLI-001`) or UDS documentation
  (`REVIEW-DOC-022`); or
- claim privileged field evidence that has not been run.

The transaction provides atomic acknowledgement and exact compensation. QoS
and Mirror maps are not banked, so packets can observe the short interval
between direction-specific writes. Eliminating that visibility interval would
require a separate versioned-map ABI design and is intentionally not hidden
inside this bug fix.

## 5. Considered Approaches

### 5.1 Patch the four legacy loops in place

Rejected. Capturing old rules and aggregating errors would reduce the immediate
bug, but the code would still have two transaction implementations, mutate RAM
per direction, use best-effort WAL, and require every future correctness fix to
be duplicated.

### 5.2 Add QoS and Mirror shadow banks

Rejected for this batch. This is the only approach that can make both
direction writes simultaneously visible to packets, but it changes shared
ABI structs, eBPF lookup keys, replay, pinned-map migration, loader behavior,
and field validation. It is a separate product design, not a proportional
repair for discarded compensation state.

### 5.3 Route old and new paths through the existing final-state transaction

Selected. It restores exact preimages, makes persistence strict, removes the
legacy loops, and keeps the change inside existing userspace publication
semantics. A small durable recovery-record map closes the only boundary the
existing managed helper does not persist explicitly.

## 6. Scope and Entry Points

The HTTP handlers continue to call the control plane once per request. They do
not expand directions.

The affected control-plane entry points are:

- `ControlPlane::add_qos`;
- `ControlPlane::delete_qos`;
- `ControlPlane::add_mirror`; and
- `ControlPlane::delete_mirror`.

All four retain the existing lock order:

1. runtime lifecycle lock;
2. instance write lock; and
3. existing local-write/Neutron-authority admission.

Under that lock, publication mode selects only the surrounding projection
plan:

- `StandaloneCompatibility` and `NeutronAttachOwnedStandaloneAcl` use no
  owner-prefix reconciliation and no general-map delta;
- `ManagedAcl` preserves the current owner-prefix, retained-group, and
  general-map planning; and
- both routes submit one ordered operation list and one final state to the same
  transaction executor.

The four private `*_standalone_locked` direction loops are deleted after all
callers move. Neutral existing helpers may keep their current private names in
this batch to avoid a large mechanical rename; their behavior contract, not
private spelling, is the maintained boundary.

## 7. Final-State Planning

Planning clones the acknowledged `FirewallState`. It performs validation and
direction expansion without modifying pinned maps, RAM, or disk.

### 7.1 QoS upsert

The existing direction plan remains authoritative:

- ingress is direction `0`;
- egress is direction `1`; and
- `both` is ordered ingress then egress.

For shaping mode, ingress retains the current policing downgrade and egress
retains shaping. FQ-qdisc preparation is one operation before the two rule
operations when the final plan needs shaping.

Each rule upsert receipt contains both the applied rule and the complete prior
rule for the same `(group_id, direction)`. Compensation restores the prior rule
when it existed, otherwise it deletes the newly created key.

### 7.2 QoS delete

Planning resolves every matching requested direction from the old state. No
match retains the current not-found response. Each delete receipt contains the
complete deleted rule. Compensation re-adds it with its original rate, burst,
priority, and mode.

FQ-qdisc cleanup remains post-commit housekeeping. A transaction never removes
a preexisting or still-required qdisc during rollback.

### 7.3 Mirror upsert

Target interface resolution occurs once before any domain write. The final
state contains one rule for each requested direction. Each receipt retains the
complete prior global or policy mirror rule, including target name, resolved
ifindex, protocol, group IDs, direction, and global flag.

### 7.4 Mirror delete

Planning selects every matching requested direction from the old state. Each
delete receipt restores the exact prior global or policy entry if a later
operation fails.

### 7.5 Policy routing assertion

Policy `direction=both` remains routed through
`apply_standalone_acl_mutations_locked`. No policy mutation may call the local
QoS/Mirror transaction or reintroduce an API-handler direction loop.

## 8. Publication Order

The required order is:

1. reject a write if its domain already has a recovery record;
2. capture `old_state` and build `final_state` completely in memory;
3. build the ordered operation list;
4. mark the in-memory publication health unverified;
5. apply each operation and journal its receipt;
6. strictly compact the complete `final_state` once;
7. publish `InstanceState.state = final_state`;
8. mark publication health verified; and
9. perform existing non-authoritative stats and unused-qdisc cleanup.

No per-direction `WalEntry::AddQos`, `DeleteQos`, `AddMirror`, or
`DeleteMirror` append occurs on these entry points after migration. The entry
variants remain for backward-compatible replay of old WAL files.

## 9. Failure and Compensation Contract

### 9.1 Operation failure before persistence

The failing operation first uses its own receipt to restore a possible
write-then-error result. Every earlier successful receipt is then compensated
in reverse. Persistence is not attempted for `final_state`.

If all compensation succeeds, RAM and durable state remain `old_state`. The
request returns its original kernel error and the domain remains writable.

### 9.2 Strict persistence failure

All applied receipts are compensated in reverse. The transaction strictly
compacts `old_state` because the failed compact may have crossed its atomic
rename point before returning an error.

If kernel and durable restoration both succeed, RAM remains `old_state` and
the request returns a persistence error.

### 9.3 Incomplete restoration

Any failed current-operation compensation, failed earlier receipt
compensation, or failed durable restore makes recovery required.

The error returned to the API contains, in order:

1. the primary operation or persistence error;
2. current-operation compensation error, if present;
3. every reverse compensation error; and
4. durable restore and recovery-record persistence errors, if present.

Every possible compensation is attempted even after an earlier compensation
fails.

## 10. Durable Recovery State

`FirewallState` gains one backward-compatible map field:

```rust
#[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
pub local_projection_recoveries: BTreeMap<String, LocalProjectionRecovery>
```

The key is the affected domain (`qos` or `mirror`). Each value contains a
version and diagnostic reason. Older snapshots deserialize with an empty map;
older binaries ignore the additional JSON field under Serde's default
unknown-field behavior. No new WAL entry is required because recovery state is
persisted by strict full-state compaction. A second domain failure cannot
overwrite or erase an existing recovery record for the first domain.

On incomplete restoration the control plane strictly compacts an `old_state`
clone carrying the affected-domain record and publishes that clone to RAM. Any
record for the other domain is preserved. The old desired rules, not the
observed partial kernel state, remain authoritative.

If recovery-record compaction also fails, the record is still installed in
current RAM and the complete failure is returned. A restart still loads the
last durable preimage and performs normal scrub/replay, so inability to persist
the record cannot turn the partial kernel state into desired state.

Admission checks the records by domain. A marked QoS domain rejects QoS writes
with HTTP 503 but does not invent a Mirror failure, and vice versa. Read-only
list and statistics requests remain available. Instance status reports a
stable maintenance reason:

```text
local_projection_recovery_required:qos
local_projection_recovery_required:mirror
```

Raw diagnostic text stays in durable state and logs; it is not used as a
stable API reason code.

## 11. Startup Recovery

### 11.1 Standalone system mode

Standalone startup already scrubs tap-local runtime maps and replays one
approved durable snapshot before attaching or re-enabling enforcement. Any
recovery record makes that scrub/replay mandatory even if reusable link pins
exist.

After replay, required FQ-qdisc preparation, link validation, and runtime
configuration all succeed, registration strictly compacts the same state with
the recovery records removed. Failure to clear them aborts readiness; a later
restart repeats the idempotent replay.

### 11.2 Tap-managed compatibility mode

A durable local-projection recovery record disables the preexisting-live
preservation shortcut. Preparation must scrub/replay or strictly validate and
repair the QoS/Mirror maps from the durable old state while the ACL/CT gate
follows its existing mode-specific rules.

The recovery records are cleared only after the prepared runtime matches the
durable state and the cleared snapshot is strictly compacted. A failed replay
or clear keeps the instance unavailable and leaves the records for retry.

### 11.3 Same-process behavior

Each affected domain stays blocked after an incomplete compensation. This
batch does not add an unsafe blind “clear recovery” API. Restart/re-attach is
the recovery executor because those paths already own complete map scrub,
replay, link validation, and readiness publication.

## 12. Error and API Semantics

Public success responses and direction strings remain unchanged.

- Validation and not-found behavior remain HTTP 400/404.
- A primary kernel failure with clean compensation remains HTTP 500.
- A strict persistence failure with clean compensation remains HTTP 503.
- Incomplete compensation returns HTTP 503 with
  `local projection recovery required` plus the complete compound failure.
- A later write to a marked domain returns HTTP 503 before mutation.

An error never reports that `both` partially succeeded. Operators can inspect
the maintenance reason and logs to distinguish a cleanly compensated request
failure from a blocked recovery state.

## 13. RED Behavior Matrix

Rust behavior tests will define the contract without binding CI to private
function text:

1. QoS `both` update, second-direction failure: restore the complete first
   direction preimage, including mode and rate fields.
2. Mirror `both` update, second-direction failure: restore the complete prior
   target and ifindex.
3. QoS `both` delete, second-direction failure: restore the exact deleted
   first-direction rule.
4. Mirror `both` delete, second-direction failure: restore the exact deleted
   first-direction rule.
5. Compensation failure: attempt all receipts in reverse, return primary and
   every compensation error, and classify recovery required.
6. Persistence failure: do not publish final RAM state, compensate every
   receipt, and restore the durable preimage.
7. Recovery-record serialization and WAL snapshot round-trip preserve version,
   domain, and reason while old snapshots default to an empty map.
8. Marked-domain admission rejects only the affected mutation domain.
9. Startup planning cannot preserve a live shortcut while a recovery record
   exists and cannot clear records before successful replay/validation.
10. Policy `direction=both` remains one standalone ACL final-state
    publication.

Focused tests use injected operations and persistence closures. They do not
require local Cargo execution or privileged pinned maps. GitHub Actions will
run the Rust behavior tests and warning-denied Rust/eBPF builds.

## 14. Delivery and Evidence

Delivery stays directly on `v0.9-neutron-agent` under the repository branch
rule:

1. commit this approved design;
2. write and commit the implementation/RED plan;
3. commit RED Rust behavior tests and push;
4. record the exact expected failing Build;
5. implement the production transaction and recovery path;
6. push and require exact-head GREEN hosted CI;
7. update the Register and this document with commits and Build evidence.

No local Cargo command will run. Source-level fault injection and hosted CI are
sufficient for this userspace transaction repair. Privileged field evidence,
if later collected, is supplementary and must remain explicitly pending until
it actually runs.

## 15. Acceptance Criteria

`REVIEW-ACL-062` can be marked fixed only when:

- policy is confirmed to remain on its existing strict bank transaction;
- standalone and compatibility QoS/Mirror no longer use per-direction RAM and
  best-effort WAL publication loops;
- `both` creates one final state and one strict durable acknowledgement;
- update and delete compensation restores exact prior values;
- all compensation errors remain visible and all compensations are attempted;
- incomplete restoration produces durable recovery state and blocks the
  affected domain;
- startup recovery clears that state only after successful replay/validation;
- RED is demonstrated against the old production behavior;
- exact-head hosted CI passes the new behaviors and warning-denied builds; and
- the backlog records current code scope instead of the stale `let _ = ...`
  description.
