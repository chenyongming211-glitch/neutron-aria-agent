# DEBT-ACL-001 Standalone Group Durability Design

Date: 2026-07-28

Status: written specification awaiting review; no RED test or production
implementation has been submitted

Analyzed target: `v0.9-neutron-agent@be40edd`

Tracked debt: `DEBT-ACL-001` remaining ordinary unreferenced-group path

## 1. Executive Decision

Ordinary standalone group add and delete will use one concrete, group-specific
transaction. The transaction will build a final `FirewallState` without
publishing it, capture the exact owner preimage for every affected pinned-map
key, apply the required general and active compatibility-ACL map changes,
strictly persist the final state, and acknowledge the request only after that
persistence succeeds.

If kernel mutation or persistence fails, applied map receipts are compensated
in reverse order and the complete old `FirewallState`, including
`next_group_id`, is restored. A persistence failure also triggers a strict
durable restore of the old state so a partially appended WAL record cannot
become authoritative after restart. Failure of a required map or durable
compensation marks ACL runtime recovery-required and quiesces ACL/CT before
returning an error.

This transaction is deliberately narrower than standalone ACL publication:
an unreferenced group cannot change an ACL decision, so it does not rotate the
ACL bank, advance the fragment epoch, or flush conntrack.

## 2. Confirmed Current Defect

`add_group_standalone_locked` currently mutates `state.state`, writes the
general source/destination maps and the current active compatibility-ACL
source/destination maps, then calls the best-effort `wal_append` wrapper. The
wrapper logs and discards an error after both append and compact fallback fail,
so the API still returns `Ok(id)`.

`delete_group_standalone_locked` has the same durability defect. It removes
the four pinned-map entries and the in-memory group, calls best-effort WAL,
and returns success even when the mutation is not durable.

The resulting acknowledged state can disappear or reverse after restart. The
kernel maps, live memory, `state.json`, and replayed WAL may then describe
different group ownership.

The remaining scope is exact:

- referenced standalone group expansion already uses the ACL-057/066 strict
  shadow-bank publication transaction;
- managed group add/delete already uses the managed local projection
  transaction;
- standalone policy add/update/delete became strictly durable in ACL-057;
- only ordinary standalone group additions and deletions remain on the legacy
  best-effort acknowledgement path.

## 3. Goals

- Never acknowledge an ordinary standalone group mutation unless its final
  state is durable.
- Restore memory, group-ID allocator state, and every applied pinned-map key
  after a failed mutation.
- Restore the exact old owner of an overwritten canonical map key rather than
  assuming the key was previously absent.
- Neutralize a possibly partially written final WAL record by durably
  restoring the old complete state after primary persistence failure.
- Keep duplicate CIDR addition a successful semantic no-op without kernel or
  persistence work.
- Clear deleted group statistics only after the transaction commits.
- Express the contract in Rust behavior tests and CI test selection, without
  adding Python source-shape checkers.
- Keep production changes concrete and bounded to the standalone group path.

## 4. Non-Goals

This batch does not:

- change referenced-group ACL publication;
- change managed-Neutron ownership or managed group transactions;
- add CIDR removal from an existing group;
- permit deletion of a group referenced by ACL, QoS, or Mirror;
- add group-name, CIDR-overlap, address-set, or project validation from
  `REVIEW-ACL-058`;
- add database uniqueness from `REVIEW-ACL-061`;
- compact or rotate the Neutron snapshot WAL from `REVIEW-OPS-019`;
- rotate the ACL bank, advance fragment publication epoch, or scrub CT;
- change HTTP request or response schemas;
- introduce a generic closure/future transaction executor;
- refactor unrelated sections of `control_plane.rs`;
- add or expand implementation-shape static checkers.

## 5. Considered Approaches

### 5.1 Replace `wal_append` with `wal_append_strict` in both functions

Rejected. This propagates the persistence error but leaves already changed
kernel maps and in-memory state visible. It also does not neutralize an append
that wrote bytes before reporting a flush/fsync failure.

### 5.2 Route every group mutation through standalone ACL publication

Rejected. It would rebuild the full ACL projection, switch banks, advance the
fragment epoch, and strictly flush CT for a group that no ACL rule references.
That adds unrelated failure modes and packet churn without improving the
required durability guarantee.

### 5.3 Add a concrete standalone group transaction

Selected. It shares neutral primitives such as strict persistence, exact map
owner capture, reverse compensation, and recovery-required quiesce, while
keeping standalone group semantics independent of managed owner-prefix and
ACL publication rules.

## 6. Scope And Entry Routing

The public entry points remain `ControlPlane::add_group` and
`ControlPlane::delete_group`.

The existing lifecycle lock, instance write lock, Neutron-authority admission,
and publication-mode routing remain unchanged. The new transaction is entered
only when the mode is:

- `StandaloneCompatibility`; or
- `NeutronAttachOwnedStandaloneAcl`.

`add_group` keeps the ACL-057 routing decision:

- adding a new CIDR to an existing ACL-referenced group uses standalone ACL
  publication;
- adding a CIDR to a new or unreferenced group uses this transaction;
- adding a duplicate CIDR returns the existing group ID as a no-op.

`delete_group` performs the existing ACL, QoS, and Mirror reference checks
before planning any mutation. A referenced group remains rejected.

## 7. Concrete Internal Model

Implementation will live in a focused
`agent/src/control_plane/standalone_group.rs` module rather than adding another
large transaction body to `control_plane.rs`.

The contract is equivalent to:

```rust
enum StandaloneGroupMutation {
    AddCidr { name: String, cidr: String },
    DeleteGroup { name: String },
}

enum StandaloneGroupMapPlane {
    General,
    ActiveAcl { bank: u8 },
}

struct StandaloneGroupMapTarget {
    plane: StandaloneGroupMapPlane,
    direction: &'static str,
    cidr: String,
    desired_owner: Option<u32>,
}

struct StandaloneGroupMapReceipt {
    target: StandaloneGroupMapTarget,
    old_owner: Option<u32>,
}

struct StandaloneGroupPlan {
    old_state: FirewallState,
    final_state: FirewallState,
    group_id: u32,
    semantic_changed: bool,
    map_targets: Vec<StandaloneGroupMapTarget>,
}
```

Exact private names may differ, but the concrete data and behavior may not.
No boxed futures, transaction traits, or public generic executor are needed.

The core eBPF operations layer will expose one exact-key owner capture helper
that accepts general or ACL-bank identity. Like the existing
`capture_general_network_owner`, it must scan for the canonical exact key and
must not use longest-prefix packet lookup semantics.

## 8. Plan Construction

Plan construction runs while both existing locks are held and does not change
live state or pinned maps.

### 8.1 Add CIDR

1. Clone the acknowledged old state.
2. Apply `FirewallState::add_group` to the clone.
3. If the CIDR already existed, return `semantic_changed=false` and no map
   targets.
4. Otherwise retain the allocated group ID and generate four deterministic
   targets: general source, general destination, active ACL source, and active
   ACL destination, each with `desired_owner=Some(group_id)`.

Restoring the old state clone restores `next_group_id`; no arithmetic rollback
such as decrementing the live allocator is allowed.

### 8.2 Delete Group

1. Resolve and clone the old group.
2. Re-run the existing ACL, QoS, and Mirror reference checks before any
   mutation.
3. Clone the old state and remove the group from the clone.
4. For every CIDR, generate the four deterministic targets with
   `desired_owner=None`.

Before deleting a key, the executor captures its exact current owner. A delete
is issued only when the captured owner equals the deleted group ID. If the key
is absent or currently owned by another group, it is left unchanged. This
batch does not redefine duplicate-CIDR ownership, but it must not delete a key
that the target group does not currently own.

## 9. Transaction And Commit Order

The transaction holds the lifecycle and instance write locks for every step:

1. validate admission and runtime map readiness;
2. build the complete plan and final state;
3. read the active ACL bank once;
4. capture all exact map preimages before the first write;
5. apply map targets in deterministic order;
6. publish `final_state` in memory only for the strict persistence attempt;
7. call strict WAL append with compact-final-state fallback;
8. after durable success, retain `final_state` and return success;
9. after committed delete, clear group statistics on a best-effort basis.

The durable success point is the commit point. No API success is returned
before it.

Pinned maps are changed before persistence because persisting first would let
a restart recover a group that was never installed in the live kernel. The
temporary map-first window is acceptable only because this transaction is
restricted to groups with no ACL, QoS, or Mirror consumer. It may temporarily
change group-stat attribution, but cannot change an ACL decision. The instance
write lock prevents another control-plane mutation from consuming that group
before commit.

## 10. Persistence And Rollback Contract

The primary persistence path keeps the current durable format:

1. append `AddGroup` or `DeleteGroup` and wait for flush/fsync acknowledgement;
2. if append fails, compact the complete final state;
3. treat compact success as durable success;
4. if both fail, begin rollback and return a persistence error.

Rollback is always reverse order:

1. restore live memory to `old_state`;
2. compensate every applied map receipt in reverse order, restoring
   `old_owner` or deleting a newly introduced key;
3. compact and publish the complete old state to neutralize any partially
   written final WAL entry;
4. report the primary error together with every compensation error.

If map and durable compensation both succeed, the old acknowledged state is
again authoritative and later requests may continue.

If any required map or durable compensation fails:

- set standalone ACL runtime health to `recovery_required`;
- mark ACL not ready;
- quiesce ACL/CT using the existing standalone rollback safety path;
- preserve all primary and compensation errors in the returned 503 error;
- do not clear group statistics or claim rollback success.

The ordinary OVS forwarding path remains outside this transaction and is not
stopped by the Aria feature quiesce.

## 11. Failure Matrix

| Failure point | Visible result | Required compensation |
| --- | --- | --- |
| validation or reference check | no mutation | none |
| active-bank or preimage capture | no mutation | none |
| first map write | no committed mutation | compensate any earlier receipt |
| later map write | no committed mutation | compensate all earlier receipts in reverse |
| WAL append, compact final succeeds | success | none |
| WAL append and compact final fail | error | restore memory, maps, and durable old state |
| durable final succeeds | success | retain final state |
| map rollback fails | 503 recovery required | attempt remaining rollback, quiesce ACL/CT |
| durable old-state restore fails | 503 recovery required | preserve old live memory, quiesce ACL/CT |
| post-commit stats cleanup fails | success with warning | no transaction rollback |

Rollback attempts every independent receipt even after one compensation
fails. One rollback error must not suppress later restoration attempts.

## 12. RED Behavior Contract

The RED commit will add Rust behavior tests before production code. Tests will
exercise public transaction behavior or a concrete executor boundary, not
private source spelling.

Required RED cases:

1. add of a new unreferenced group publishes four map targets and acknowledges
   only after strict persistence;
2. add of a CIDR to an existing unreferenced group preserves its group ID and
   allocator state;
3. duplicate CIDR add is a no-op with zero map and persistence operations;
4. delete of a multi-CIDR unreferenced group removes every owned general and
   active-ACL key, then clears stats only after commit;
5. append failure followed by compact-final success commits normally;
6. append plus compact-final failure restores old memory, `next_group_id`, and
   all exact map owners;
7. a later map-write failure compensates all earlier receipts in reverse;
8. deleting a key currently owned by another group leaves that key untouched;
9. map compensation failure marks recovery required and requests ACL/CT
   quiesce;
10. durable old-state compensation failure marks recovery required and does
    not report success.

The focused test names will be added to the existing `rust-behavior` selection.
The RED build must fail for the missing concrete transaction boundary, not for
syntax, formatting, checker, or unrelated test failures.

## 13. File And Complexity Boundary

Expected implementation scope:

- create `agent/src/control_plane/standalone_group.rs` for the plan, concrete
  executor, rollback classification, and focused unit tests;
- modify `agent/src/control_plane.rs` only for module wiring and the two
  standalone call sites;
- modify `core/src/ebpf_ops/inventory.rs` and its export surface only for exact
  general/ACL-bank owner capture;
- modify `ci/check_neutron_stage1.py` only to select the focused Rust tests;
- update the backlog and evidence after RED/GREEN results.

The implementation must not add a Python checker, a second WAL abstraction,
or a generic transaction framework. Production code should remain within one
small focused module plus narrow call-site and capture-helper changes. If the
implementation cannot stay inside this boundary, work pauses for a design
revision instead of silently expanding scope.

## 14. Delivery And Evidence

All work lands directly on the only delivery branch,
`v0.9-neutron-agent`. No feature branch, stacked PR, or temporary worktree is
created.

Delivery sequence:

1. commit this design specification;
2. write and commit the RED Rust behavior tests and CI selection only;
3. push and record an expected failing `rust-behavior` build;
4. implement the concrete transaction in a later GREEN commit;
5. require `fast-contracts`, `rust-behavior`, and warning-denied `rust-build`
   to pass at the exact production head;
6. update `DEBT-ACL-001` with RED and GREEN commit/build evidence.

No local Cargo command is permitted. GitHub Actions supplies all Rust and eBPF
compile and behavior evidence.

## 15. Acceptance Criteria

`DEBT-ACL-001` may be closed only when:

- ordinary standalone group add/delete never acknowledges an undurable final
  state;
- duplicate additions remain no-op successes;
- kernel/map and memory preimages are restored after failed persistence;
- exact overwritten owners are restored rather than blindly deleted;
- partial WAL ambiguity is countered by durable old-state restoration;
- failed required compensation produces explicit recovery-required quiesce;
- referenced and managed group paths retain their existing transaction
  behavior;
- no bank switch, fragment epoch change, or CT scrub is introduced for
  unreferenced groups;
- focused RED evidence exists, followed by exact-head GREEN hosted CI;
- no local Cargo evidence or field-environment claim is substituted for CI.
