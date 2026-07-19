# ACL-057/066 Standalone ACL Final-State Publication Design

Date: 2026-07-19

Status: written specification approved on 2026-07-19; RED and hosted GREEN
implementation evidence complete; direct `v0.9-neutron-agent` delivery pending

Analyzed target: `codex/review-acl-057-direct-publication@67b70ab`

Tracked findings: `REVIEW-ACL-057`, `REVIEW-ACL-066`

## 1. Executive Decision

Standalone/direct ACL policy mutations will stop editing the active ACL bank.
Policy add, update, delete, `direction=both`, and batch-add will all build one
complete final `FirewallState` and publish it through one shadow-bank
transaction. Adding a CIDR to an existing standalone group that is already
referenced by an ACL rule will use the same transaction.

The transaction is standalone-specific. It will not call the managed-Neutron
owned replacement API, inherit owner-prefix or exclusive-domain semantics, or
introduce another generic closure/future transaction framework.

The publication order is:

1. validate the complete request and build the final state in memory;
2. capture the old state, active bank, general-map preimages, and allocator
   effects;
3. durably reserve any transaction-created bitmap indices before their first
   kernel write;
4. compile and stage the complete standalone ACL projection in the inactive
   bank;
5. apply any referenced-group general-map additions;
6. switch the active bank once;
7. strictly persist the complete final state;
8. strictly scrub IPv4 and IPv6 conntrack;
9. after commit, scrub the old bank and perform existing statistics and bitmap
   cleanup.

Staging, general-map update, bank switch, persistence, or strict CT scrub
failure returns an error and restores the old publication. No failure is
reported as a partial batch success.

## 2. Confirmed Current Defect

The current direct policy path in `agent/src/control_plane.rs` reads the active
bank and calls `add_policy_in_bank` or `delete_policy_in_bank` against that
bank. The HTTP handler expands `direction=both` into two independent calls and
the batch handler repeats that process for every input item.

The current referenced-group path also reads the active bank in
`add_group_standalone_locked` and adds the new CIDR directly to both active ACL
selector maps. It separately changes the general source and destination maps.

TC conntrack freshness is bank-based. These in-place changes preserve the bank
identity stored in an existing CT entry. A flow that previously cached PASS can
therefore continue to use and refresh that stale decision after:

- a new deny is added;
- an allow becomes a deny;
- an allow is deleted; or
- a CIDR is added to an ACL-referenced deny group.

Managed-Neutron replacement is not the target. It already publishes through a
shadow bank and performs strict CT cleanup.

## 3. Goals

- Make every semantic standalone policy change select a new ACL bank epoch.
- Strictly invalidate CT before acknowledging success.
- Publish both directions of one request atomically.
- Publish all valid items in one batch through exactly one bank switch.
- Preserve the existing batch response shape and per-item validation behavior.
- Make referenced-group CIDR expansion atomic with ACL selector publication.
- Make standalone policy acknowledgement strictly durable.
- Restore bank, general maps, memory, durable state, and allocator preimages
  after any pre-commit or strict-flush failure.
- Prove behavior with Rust tests that exercise the transaction contract rather
  than Python source-shape checks.

## 4. Non-Goals

This batch does not:

- change managed-Neutron owner-prefix or exclusive-domain publication;
- fix cleanup-failure reuse of an old bitmap index (`REVIEW-ACL-059`);
- define IPv4/IPv6 fragment and CT semantics (`REVIEW-ACL-056`);
- make ordinary unreferenced group add/delete strictly durable
  (`DEBT-ACL-001`);
- add group deletion while an ACL rule still references the group;
- add a standalone CIDR-removal API;
- change ACL source-port, priority, overlap, or controller-validation
  boundaries;
- close the remaining QoS/Mirror portions of multi-direction compensation
  debt;
- add a generic transaction executor or bind CI to private helper names.

The policy subset of `DEBT-ACL-001` is expected to become strict as a
consequence of this transaction. The backlog item remains open for ordinary
unreferenced-group paths.

## 5. Considered Approaches

### 5.1 Continue active-bank mutation, then quiesce or flush

Rejected. A policy is visible before the CT epoch is changed, so a failure
between mutation and flush creates a mixed state. Quiescing after publication
does not make the earlier window atomic.

### 5.2 Reuse `replace_owned_acl_and_flush`

Rejected as the public transaction boundary. That API is designed around a
Neutron owner prefix, optional exclusive policy ownership, managed projection
health, and managed attach/demotion semantics. Supplying synthetic ownership
parameters would make standalone behavior depend on unrelated managed rules.

Its low-level primitives remain reusable where their semantics are neutral:
inactive-bank staging, active-bank switching, complete-state compaction,
transaction-created bitmap cleanup, and strict CT scrubbing.

### 5.3 Add a concrete standalone final-state transaction

Selected. It matches the direct API's state model, keeps the change local to
the standalone boundary, and gives single, both-direction, batch, and
referenced-group changes one publication contract.

## 6. Public And Internal Entry Points

The HTTP schema and status-code contract remain unchanged.

The handlers in `agent/src/api_handlers/policies.rs` will parse wire strings
into typed mutations and call the control plane once. They will no longer loop
over directions or invoke one control-plane mutation per batch item.

The control plane will use a concrete mutation model equivalent to:

```rust
enum StandaloneAclMutation {
    UpsertPolicy {
        src_group: String,
        dst_group: String,
        proto: u8,
        action: u8,
        direction: u8,
        ports: Option<String>,
    },
    DeletePolicy {
        src_group: String,
        dst_group: String,
        proto: u8,
        direction: u8,
    },
    AddReferencedGroupCidr {
        group_name: String,
        cidr: String,
    },
}

struct StandaloneAclMutationOutcome {
    accepted: usize,
    errors: Vec<String>,
    semantic_changed: bool,
}
```

Exact visibility may remain private to the agent crate. The contract, not the
private spelling, is stable.

`ControlPlane::add_policy` and `ControlPlane::delete_policy` become thin
single-item wrappers over the same locked final-state builder and publisher.
The batch handler uses one batch entry point. `add_group` routes only an
ACL-referenced existing group expansion into the transaction.

No endpoint receives managed ownership parameters, and no public API request
or response field changes.

## 7. Lock Boundary And Admission

The complete transaction holds the existing locks in their established order:

1. `runtime_lifecycle_lock`;
2. the selected instance write lock.

The current local-write/Neutron-authority admission check runs before any
final-state or kernel mutation. The instance write lock stays held through
final-state construction, shadow staging, general-map update, bank switch,
strict persistence, strict CT scrub, and immediate rollback.

This prevents another local policy or group request from observing or changing
the allocator, active bank, or in-memory state between transaction phases. It
also makes the referenced-group routing decision stable: once the old state
shows that a group is referenced, no concurrent policy deletion can move the
operation back to the legacy group path.

The transaction applies only in `StandaloneCompatibility` and
`NeutronAttachOwnedStandaloneAcl`. `ManagedAcl` continues through its existing
admission and owned-publication rules.

## 8. Final-State Construction

Final-state construction happens on a clone of the acknowledged old
`FirewallState`. It does not modify `InstanceState.state` or pinned maps.

### 8.1 Policy add and update

The builder resolves source and destination group IDs from the working state,
validates the port expression, expands the requested direction, and applies
`FirewallState::apply_add_rule` to the clone.

`direction=both` expands to ingress and egress inside one item attempt. Both
directions are accepted into the working state or neither is. A failure while
building the second direction discards that item's temporary clone.

An existing policy key remains an update, preserving the current public
semantics.

### 8.2 Policy delete

The builder resolves group IDs, expands the direction, and removes matching
rules from a temporary clone. To preserve current behavior, `direction=both`
deletes every matching requested direction and returns `PolicyNotFound` only
when neither direction exists.

### 8.3 Batch add

Items are evaluated in input order against a working final state. Each item is
first applied to a temporary clone of that working state:

- parse or semantic validation failure records one error and leaves the
  working state unchanged;
- full item success replaces the working state and increments `accepted`;
- a `direction=both` item counts once, not once per direction.

After every item has been evaluated, all accepted items are published in one
transaction. If no item changes semantics, the request returns its normal
response without switching bank or flushing CT.

Kernel, persistence, or CT failure is transaction-wide. The handler returns
the corresponding error response; it must not return `added > 0` for a final
state that was rolled back.

### 8.4 Referenced-group CIDR expansion

`add_group` examines the old acknowledged state while holding the instance
lock:

- a new group cannot yet be referenced and stays on the legacy path;
- adding a CIDR to an existing group with no ACL reference stays on the legacy
  path and remains tracked by `DEBT-ACL-001`;
- adding a new CIDR to an existing group referenced as an ACL source or
  destination uses `AddReferencedGroupCidr`;
- adding a duplicate CIDR is a semantic no-op;
- whole-group deletion remains rejected while referenced.

The referenced mutation updates the cloned group, stages the complete ACL
projection, and upserts the CIDR in both general maps before the bank switch.
Before either upsert, it captures the exact pinned-map owner for that canonical
key. Rollback restores the previous owner when the key existed and deletes the
new key only when it was previously absent. This preserves the current
standalone rule that group membership is available to general domains as well
as ACL without destroying an overlapping-key preimage.

## 9. Projection And Bitmap Preparation

The transaction compiles the complete standalone-compatible projection from
the final state. It uses the existing standalone replay semantics so this bug
fix does not silently change selector membership or overlap behavior:

- every standalone group remains present in general source/destination maps;
- every standalone group remains present in ACL source/destination bank maps;
- every final rule is staged in the inactive bank;
- the active bank is never edited during preparation.

Policy-only transactions do not change general maps. A referenced-group CIDR
addition has two explicit general-map mutations, source then destination. Each
mutation is classified from the captured pinned preimage as either `Added` or
`Replaced`; its compensation is respectively `Deleted` or a reverse
`Replaced`. Capturing the real pinned value is required because the legacy
standalone projection can contain exact-key overlap whose current owner cannot
be reconstructed safely from unordered persisted groups.

Final-state policy construction may allocate a new port bitmap. Before staging
that bitmap, the transaction strictly persists an allocator guard derived from
the old state that quarantines every transaction-created index. This mirrors
the existing crash-safety invariant: a process restart cannot reuse an index
whose kernel contents were written but whose final policy was not durably
acknowledged.

If preparation later fails, successfully cleaned new indices can be released
when the old state is restored. A cleanup failure remains durably quarantined;
it is never hidden by restoring an allocator free list.

## 10. Publication State Machine

Let `old_bank` be the current active bank and `shadow_bank` be
`acl_next_bank(old_bank)`.

```text
validate and build final_state
  -> persist created-bitmap guard when needed
  -> scrub shadow_bank
  -> stage complete ACL selectors and policies in shadow_bank
  -> apply referenced-group general src/dst additions when present
  -> set active bank = shadow_bank                 [publication point]
  -> compact and publish complete final_state      [durable acknowledgement]
  -> strictly scrub CT v4 and v6                    [freshness barrier]
  -> commit success
  -> scrub old_bank and clean retired artifacts
```

The bank switch is the only datapath publication point. Packets before it use
the complete old projection. Packets after it use the complete new projection.

Strict persistence follows the switch so a persistence failure can restore the
old bank without ever acknowledging an undurable state. Strict CT scrub follows
persistence; its failure restores the bank and durable state rather than
claiming that stale CT is safe.

During the short interval between bank switch and CT scrub, old CT entries have
the old bank and are rejected as stale by the new bank. If CT scrub fails and
the old bank is restored, any new-bank CT entries created in that interval are
stale under the restored old bank. A partially completed scrub can reduce old
cache contents but cannot create an incorrectly current entry.

## 11. Rollback Matrix

| Failure phase | Datapath before failure | Required recovery |
| --- | --- | --- |
| Validation/final-state construction | Old bank, old general maps | Return item or request error; no kernel or durable change |
| Bitmap guard persistence | Old bank, old general maps | Return persistence error; no kernel change |
| Shadow scrub/staging | Old bank, old general maps | Scrub shadow; clean transaction-created bitmaps; restore old durable allocator, quarantining cleanup failures |
| General source update | Old bank; source may be new | Delete applied source entry; scrub shadow; clean created bitmaps; restore old durable state |
| General destination update | Old bank; source and possibly destination may be new | Restore destination then source; scrub shadow; clean created bitmaps; restore old durable state |
| Bank switch | Switch failed or outcome reported failed | Restore old bank explicitly, restore general maps, scrub shadow when it is not active, clean created bitmaps, restore old durable state |
| Final-state persistence | New bank may be active | Restore old bank first, restore general maps, scrub failed shadow only after old-bank restoration, clean created bitmaps, restore old durable state |
| Strict CT scrub | New bank and final state are durable | Restore old bank, restore general maps, scrub the failed shadow only after bank restoration, clean transaction-created bitmaps, then restore old durable state with cleanup failures quarantined; return strict-flush error |

Every compensation is attempted even if an earlier compensation fails. The
returned error contains the primary failure and all compensation failures.

If the old bank, general-map, or durable preimage cannot be restored, the
instance is marked ACL recovery-required/unready and the control plane attempts
to quiesce ACL/CT. The API returns an error and never reports the mutation as
committed.

The publisher must not scrub the failed publication bank when active-bank
restoration itself failed, because that bank may still be serving packets.

## 12. Commit And Post-Commit Cleanup

The transaction commits only after both strict persistence and strict CT scrub
succeed. At that point:

- `InstanceState.state` is the complete final state;
- the final state is durable;
- the new bank is active;
- old-bank CT entries have been removed or proven absent.

The following cleanup is post-commit because it does not determine which
policy is active:

- scrub the inactive old ACL bank;
- clear statistics for removed rules or groups;
- delete no-longer-used port bitmap contents.

Old-bank and statistics cleanup failures remain visible as warnings and do not
roll back a successfully published policy. A later publication scrubs its
inactive bank before staging, but this design does not claim a general retry
contract for every post-commit artifact.

This batch deliberately does not claim that a failed retired-bitmap cleanup
prevents allocator reuse. The current allocator can make such an old index
reusable too early. `REVIEW-ACL-059` must add durable quarantine-until-clean
semantics and its own cleanup-fault evidence immediately after ACL-057/066.

## 13. Rust RED And GREEN Evidence

Tests live with Rust behavior code. No Python checker may require private
function names, parameter order, local-variable names, or source layout.

Recorded evidence:

- RED commit `212828b` failed only on the intended missing standalone
  publication API in GitHub Actions Build
  [`29682513348`](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/29682513348).
- Production commits `10c3c45` and `a234bb5` passed all six focused
  `standalone_acl_publication_` behaviors plus warning-denied Rust/eBPF builds
  in exact-head Build
  [`29683492746`](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/29683492746).
- No local Cargo command was run. `REVIEW-ACL-059`, `REVIEW-ACL-056`, ordinary
  unreferenced-group durability, privileged field evidence, and final delivery
  remain explicitly outside this completed implementation evidence. Because no
  privileged environment exists, that evidence is deferred to the production
  activation gate and is not represented as passed.

### 13.1 Final-state and API aggregation tests

- one add-deny mutation builds a different final state without changing the
  old state;
- allow-to-deny replaces the existing key in both requested directions;
- delete-allow removes the requested directions atomically;
- `direction=both` produces one transaction publication;
- a batch with multiple valid entries produces one publication and preserves
  `added` as the number of input items;
- invalid batch entries retain ordered errors while valid entries share one
  final state;
- a transaction-wide kernel or persistence error does not return partial
  `added` success.

### 13.2 CT freshness behavior tests

Each regression starts with an existing CT entry tagged with `old_bank` and
proves that the mutation publishes `shadow_bank` and performs strict CT scrub:

- old PASS followed by new deny;
- old PASS from allow followed by allow-to-deny;
- old PASS followed by deletion of the matching allow;
- old PASS followed by expansion into an ACL-referenced deny group.

The behavior assertion is bank/flush based and does not depend on a private
helper's spelling.

### 13.3 Failure and rollback tests

Deterministic Rust fault points exercise the same concrete publisher used by
the control-plane entry points:

- shadow staging failure;
- referenced-group general source and destination failure;
- active-bank switch failure;
- complete-state compact failure;
- strict CT scrub failure;
- compensation failure after a primary failure.

For every failure, assertions cover the active bank, general-map preimage,
in-memory state, durable state, allocator state, transaction-created bitmap
cleanup/quarantine, returned error, and publication count.

The Rust test seam may inject phase outcomes under `cfg(test)`, but production
code remains a concrete standalone transaction rather than a reusable generic
closure/future framework.

## 14. CI And Delivery

The repository rule forbids local `cargo build`, `cargo check`, and Rust test
compilation. Development therefore uses this evidence sequence:

1. commit the design;
2. commit Rust RED behavior tests without production implementation;
3. push and record an exact-head GitHub Actions run showing only the intended
   missing-publication failures;
4. implement the concrete transaction;
5. push and require fast contracts, Rust behavior, and Rust/eBPF build jobs to
   pass at the exact implementation head;
6. update the backlog with RED and GREEN commit/run evidence;
7. keep `REVIEW-ACL-057` and `REVIEW-ACL-066` independently identifiable and
   close each only after its own regression passes.

No static source-shape checker is added. Existing checkers may verify public
workflow wiring, but they must not be expanded to recognize the private shape
of this implementation.

## 15. Follow-Up Order

After ACL-057 and ACL-066 are GREEN:

1. `REVIEW-ACL-059`: quarantine released bitmap indices until kernel cleanup
   is proven;
2. `REVIEW-ACL-056`: define and implement fragment-safe ACL/CT semantics;
3. `DEBT-ACL-001`: finish strict durability and rollback for ordinary
   unreferenced group paths;
4. proceed to the recorded P2 transaction and API batches.

This order is mandatory unless a newly proven dependency requires a documented
change.
