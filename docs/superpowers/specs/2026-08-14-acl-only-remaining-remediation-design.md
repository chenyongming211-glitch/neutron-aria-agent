# Remaining ACL-Only Remediation Design

**Status:** approved scope; Batch 1 fixed; Batch 2 is the active implementation batch

**Scope:** remaining Neutron ACL control-plane, ACL state-convergence, and ACL
fragment/conntrack correctness findings only

## 1. Objective

Finish the remaining defects that directly affect the Neutron ACL product
without pulling QoS, Mirror, TCP-RT, generic trace maintenance, or generic
monitoring work into the same delivery line.

An issue is in scope only when its failure can change one of these outcomes:

- which ports and ACL objects enter a Neutron snapshot;
- whether an ACL event is eventually reflected in the authoritative snapshot;
- whether ACL status publication is issued exactly once;
- how an ACL fragment drop is attributed; or
- whether stateful ACL conntrack access is safe on the supported target kernel.

The historical `REVIEW-ACL-*` prefix is not a product-boundary signal. Items
whose implementation belongs to another feature remain open in the Register
but are not developed by this ACL-only program.

## 2. In-Scope Batches

### 2.1 Neutron ACL event and client completeness

The first implementation batch contains `REVIEW-ACL-085`,
`REVIEW-ACL-090`, and `REVIEW-ACL-091`.

#### Delete failure convergence

When deletion of a known projected port fails, the already drained event batch
must not depend on a future unrelated event. The service must mark the delete
failure, retain the batch and error in its returned observability record, and
immediately call the existing authoritative `safe_full_resync()` path. A
successful resync may restore ready state. A failed resync remains degraded and
uses the existing resync backoff. This applies both to the leading
`deleted_ports` phase and to a foreign-host update whose action is
`delete_local`.

The batch is not re-enqueued. Re-enqueueing stale events would require conflict
rules against newer revisions already accepted by `EventMerger`; one immediate
authoritative resync is smaller and already owns convergence semantics.

#### Pagination authority

`NeutronPortSource.list_ports_for_host()` must reject every page that advertises
a next link but cannot provide a usable last-object ID. Both an empty page and a
last row with a missing or empty `id` raise `PortSourceUnavailable`. Existing
repeated-marker and maximum-page protection remains unchanged. A page without a
next link remains a valid terminal empty page.

#### Exactly-once side-effect invocation

No POST or DELETE may be retried merely because the invoked callable raised
`TypeError`. The adapter determines its callable form before the first side
effect and stores that decision:

- the repository-owned `AriaAclRestClient` uses the production
  python-neutronclient keyword-body call contract;
- `AriaAclPortStatusReporter` selects the explicit payload-style adapter
  contract or the direct context-style API contract during construction; and
- an unsupported or indeterminate callable shape fails before dispatch rather
  than probing through a real write.

A `TypeError` raised during request or response processing therefore propagates
after exactly one call. Python 2.7 compatibility is mandatory; the design must
not depend solely on `inspect.signature`.

### 2.2 ACL fragment attribution

The second implementation batch contains `REVIEW-ACL-098` and
`REVIEW-ACL-099`.

It adds one new trace-result constant without changing existing numeric values
or trace record layout. Resolve-stage fragment drops load safe source and
destination group IDs before recording drop and trace data. The change must not
move normal ACL/CT phase ordering and must retain the linked 448-byte TC stack
budget. This batch requires hosted warning-denied Rust/eBPF compilation; no
local Cargo command is allowed.

### 2.3 Verification gates

`REVIEW-ACL-086` remains an ACL/CT safety verification gate. Source inspection
proves a concurrent raw-pointer hazard, but production repair waits for target
4.18 kernel source or stress evidence that establishes the relevant
eviction/reuse behavior. Missing field evidence is recorded as deferred, never
as PASS.

`REVIEW-ACL-083`, `REVIEW-ACL-084`, and `REVIEW-TXN-035` receive separate
behavior probes. A probe that stays GREEN closes or reclassifies the claim; a
real RED result creates a new narrowly scoped implementation plan. These
conditional items are not bundled into either production batch.

## 3. Explicitly Excluded Open Items

The following findings remain recorded and open, but this ACL-only program does
not modify their tests or production paths:

- `REVIEW-ACL-078`: QoS rate bounds;
- `REVIEW-OPS-039`: generic pinned-map authority, currently demonstrated by
  QoS and generic conntrack query paths;
- `REVIEW-ACL-089`: QoS and Mirror deletion;
- `REVIEW-ACL-093`: generic trace-filter deletion;
- `REVIEW-ACL-094`: trace/drop/monitoring flush accounting;
- `REVIEW-ACL-096` and `REVIEW-ACL-097`: TCP-RT queries; and
- `REVIEW-ACL-088`: defensive general network-map ownership debt whose current
  ACL production callers already retain owner-preimage protection.

`REVIEW-ACL-082` is already fixed and is not remaining work.

## 4. Delivery Order

```text
Batch 1  ACL-085 + ACL-090 + ACL-091  Fixed with exact RED/GREEN CI
Batch 2  ACL-098 + ACL-099            Active: ACL fragment attribution
Gate 3   ACL-086                      target-kernel evidence before code
Gate 4   ACL-083/084 + TXN-035        prove each conditional claim separately
```

Each production batch uses behavior-level RED tests, one or more narrow GREEN
commits, exact-head hosted CI, and one documentation closure. Work continues on
`v0.9-neutron-agent`; no feature branch, worktree, stacked PR, or local Cargo
execution is introduced.

## 5. Acceptance Boundary

The ACL-only program is complete when:

- the five confirmed ACL defects have exact RED/GREEN evidence;
- every conditional item has an honest verified or deferred outcome;
- `REVIEW-ACL-086` is not called fixed without target-kernel evidence;
- excluded non-ACL rows remain open and are not counted as ACL delivery gaps;
- all applicable hosted CI lanes pass at each implementation head; and
- the branch is clean and synchronized with `origin/v0.9-neutron-agent`.
