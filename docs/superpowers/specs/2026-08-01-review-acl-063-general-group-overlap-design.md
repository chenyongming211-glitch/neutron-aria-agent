# REVIEW-ACL-063 General Group Overlap Design

**Status:** proposed; product direction approved, written implementation boundary
awaiting review. No RED test, production implementation, or field evidence is
claimed.

## Problem

The general source and destination LPM maps store one `group_id` for each CIDR
key, and one packet lookup returns one most-specific value. These maps feed QoS,
Mirror, group statistics, and PASS trace attribution. If two different groups
in the general domain contain exact or nested CIDRs, both memberships cannot be
represented:

- exact CIDRs collapse to one deterministic winner;
- nested CIDRs select only the most-specific group for addresses in the nested
  range;
- QoS, Mirror, statistics, and trace can therefore observe different group
  membership from the persisted control-plane model.

`REVIEW-ACL-046` intentionally keeps ACL-only selectors isolated from general
identities. It does not make two general-domain memberships representable.

## Decision

Reject writes that introduce a new overlap between different general-domain
group IDs. Do not expand the eBPF ABI or add multi-membership maps in this
batch.

This is the smallest safe product behavior because a successful write can then
promise that every general-domain group membership is representable for QoS,
Mirror, statistics, and PASS trace. A future multi-membership ABI remains a
separate product and datapath design.

## Alternatives considered

### 1. Transition-aware write guard — selected

Compare conflicts in the committed state with conflicts in the proposed final
state. Reject only conflicts newly introduced by the write. This prevents new
ambiguous state without making legacy overlap impossible to replay or repair.

### 2. Make projection compilation reject every overlap

This is simpler mechanically, but it would also reject startup replay and
unrelated or corrective writes when an older persisted state already contains
an overlap. It turns a write invariant into an availability regression and is
therefore rejected.

### 3. Add multi-membership to the datapath

This could preserve every overlapping membership, but it changes map ABI,
lookup cost, verifier complexity, statistics attribution, QoS/Mirror conflict
resolution, capacity planning, recovery, and migration. It is deliberately
outside this bug-fix batch.

## Domain classification

The guard operates on canonical IPv4 and IPv6 networks and compares different
group IDs. Exact equality and either nesting direction are overlap. Disjoint
networks and different address families do not overlap.

Multiple exact or nested CIDRs inside one group remain valid because every
matching key resolves to the same membership identity.

### Standalone publication

Every standalone group is a general-domain identity. The standalone group and
standalone final-state ACL transactions write these groups into the general
maps, so their proposed final state is checked across all non-zero group IDs.

### Managed publication

Use the existing projection classification:

- a group referenced only by ACL rules is `ACL-only`;
- an unreferenced group is general-domain because standalone QoS/Mirror/group
  APIs may subsequently reference it;
- a group referenced by QoS or Mirror is general-domain, including a dual-use
  ACL group.

Only different IDs that are both general-domain conflict. An ACL-only selector
may overlap a general identity under the already-delivered ACL-046 isolation
rule. ACL direction-specific overlap validation remains unchanged.

Adding a QoS or Mirror reference can promote an ACL-only group into the general
domain. That final-state transition must run the same overlap guard even when
no group CIDR changed.

## Transition semantics and legacy compatibility

The validator computes a stable set of conflict identities for both committed
and proposed state:

```text
new_conflicts = conflicts(proposed) - conflicts(committed)
```

- empty `new_conflicts`: accept;
- non-empty `new_conflicts`: reject before map, allocator, memory, WAL, or
  statistics mutation;
- unchanged legacy conflicts: retain the current deterministic projection so
  startup and unrelated writes remain compatible;
- a delete or update that removes one or more legacy conflicts is accepted;
- a write that replaces one legacy conflict with a different conflict is
  rejected because the new identity is not in the committed conflict set.

Conflict identity is independent of hash-map iteration order. Groups are
ordered by stable persisted name, then group ID; networks are canonicalized and
ordered by address family, network bytes, and prefix length. The public error
uses one stable reason:

```text
general_group_overlap:<left-name>:<left-cidr>:<right-name>:<right-cidr>
```

The API returns HTTP 409 because both individual groups are valid but their
combined membership cannot be represented. It is not a CIDR syntax error.

## Code boundaries

### Pure projection contract

`core/src/ebpf_ops/projection.rs` owns canonical group classification and
conflict enumeration. It exposes a small public transition validator for
standalone-all-general and managed-projected-general scopes. Existing
`compile_managed_group_projection()` keeps its deterministic legacy winner
logic and does not become a fail-closed replay gate.

### Standalone writes

Validate the proposed final state while building:

- the ordinary standalone group add transaction;
- the standalone ACL final-state transaction, because referenced-group changes
  and policy changes can alter the published general-domain state.

Validation occurs before runtime readiness checks or map-preimage capture where
the call structure permits, and always before any effect.

### Managed writes

`managed_general_state_mutations(old_state, final_state)` validates the
transition before compiling map mutations. This shared boundary covers:

- local group add/update;
- QoS and Mirror add/update/delete, including ACL-only-to-general promotion;
- owned ACL final-state publication and demotion paths that change group domain
  classification.

Delete operations that cannot add a conflict remain accepted; routing them
through the shared validator is harmless and proves the final-state invariant.

### Error surface

Add a specific control-plane group-overlap conflict variant mapped to HTTP 409.
Do not reuse `GroupInUse`, and do not report the conflict as HTTP 400 syntax
validation.

## Transaction and failure behavior

Overlap validation is a preflight. On rejection:

- no LPM map entry changes;
- no ACL bank switch occurs;
- no QoS or Mirror rule is published;
- no group ID or bitmap allocator state changes;
- no WAL append, compact, or recovery fence is written;
- existing runtime and persisted state stay authoritative.

Kernel, persistence, compensation, and recovery behavior for accepted writes is
unchanged.

## RED behavior coverage

Rust behavior tests must prove:

1. standalone exact overlap across different groups is rejected;
2. standalone IPv4 and IPv6 nesting across different groups is rejected;
3. same-group nesting and disjoint groups remain accepted;
4. managed unreferenced/general groups reject exact and nested overlap;
5. ACL-only versus general overlap remains accepted under ACL-046;
6. adding QoS or Mirror use that promotes an ACL-only group rejects a newly
   ambiguous final state;
7. unchanged legacy overlap remains replayable and an overlap-removing change
   is accepted;
8. a newly rejected transition produces no projection operations, allocator
   change, or persistence action;
9. the stable conflict reason and HTTP 409 mapping do not depend on insertion
   order;
10. QoS/Mirror matching and group-stat/PASS-trace attribution keep a unique
    general group ID for every accepted state.

Tests target public or pure behavioral boundaries. No Python source parser,
private-helper spelling guard, or local Cargo invocation is added.

## CI and evidence

- Commit RED Rust behavior tests and use hosted `rust-behavior` to prove they
  fail for the missing transition guard.
- Implement the minimum production boundary and use hosted `rust-behavior` plus
  warning-denied Rust/eBPF builds for GREEN.
- Fast Python/static lanes stay separate from compilation.
- This invariant is fully testable without a privileged field environment. No
  field PASS is claimed or required to close ACL-063.

## Exclusions

- no eBPF map or wire ABI change;
- no multi-membership lookup;
- no priority arbitration;
- no source-port ACL support;
- no QoS/Mirror rule-precedence redesign;
- no change to ACL-046 cross-domain isolation;
- no remediation rewrite of legacy persisted overlap;
- no work on `RISK-SEC-002`, `RISK-READY-001`, `REVIEW-ACL-011`, or
  `REVIEW-OPS-036` in this batch.

## Acceptance

ACL-063 is fixed when every write path that can create or promote a
general-domain identity rejects newly introduced cross-group exact/nested
overlap with stable HTTP 409 behavior before effects, legacy state remains
replayable/remediable, accepted states preserve unique QoS/Mirror/stat/trace
attribution, and exact-head hosted CI passes all required lanes.
