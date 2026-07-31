# REVIEW-ACL-045 Orphan Managed-Runtime Scrub Design

## Status

Approved repair-order design, ready for RED behavior tests.

## Scope

This design fixes `REVIEW-ACL-045`: startup reconciliation finds a managed tap
runtime that is not present in the committed Neutron WAL set, but removes only
its pinned links and persisted live-iface marker.

The repair covers the existing shared managed runtime only:

- XDP and TC link pins;
- tap-scoped shared maps, including both ACL banks, general network maps,
  bitmap, CT, fragment, QoS, mirror, tcprt, statistics, trace filters, tap
  config, and interface context;
- kernel-drop managed-ifindex registration;
- trace runtime registration;
- in-memory Neutron authority/registry residue;
- persisted live-iface marker.

It does not:

- change orphan classification or `REVIEW-ACL-035` hash-skip behavior;
- delete the per-interface state/WAL directory or release its stable tap id;
- clean standalone `system` runtime;
- absorb `REVIEW-TXN-026` startup-readiness races;
- claim real pinned-map evidence in a non-privileged CI environment.

## Confirmed Current Failure

`TapRegistry::reconcile_neutron_runtime` currently:

1. derives runtime inventory only from `*_xdp_link`,
   `*_tc_ingress_link`, and `*_tc_egress_link` filenames;
2. claims committed interfaces through `attach_neutron`;
3. classifies any remaining pinned-link interface as an orphan;
4. calls `remove_orphaned_managed_link_pins`;
5. removes the persisted live-iface marker.

The orphan path never obtains the stable tap id from the interface state
directory and never calls `scrub_managed_runtime_state`. It also bypasses
kernel-drop, trace, control-plane authority, and registry cleanup.

There is a second retryability defect: the marker is released in the same
helper that removes links. If a later map scrub were simply appended to the
current code and failed, both the link pins and marker could already be gone.
The next startup would have no orphan inventory identity with which to retry.

## Authoritative Orphan Identity

The candidate set must be the union of:

- interface names encoded in managed XDP/TC link pins;
- interface names recorded in the shared-runtime persisted live-iface
  manifest.

Subtract the normalized committed Neutron interface set from that union.

For each candidate, load its existing per-interface state/WAL directory and
read the stable `tap_id`. A missing, unreadable, or unassigned tap id is a
blocked cleanup result, not a successful cleanup.

The persisted live-iface manifest remains a recovery witness until the entire
cleanup succeeds. It is not removed during link-only cleanup.

## Cleanup Transaction

Each orphan is serialized by:

1. the per-interface registry lock;
2. the control-plane runtime lifecycle lock.

The concrete cleanup order is:

1. capture the persisted interface state, stable tap id, and any known
   ifindices;
2. detach by removing all owned XDP/TC link pins;
3. remove kernel-drop registrations associated with the orphan tap id and
   known ifindices;
4. unregister the tap from trace runtime state;
5. call `scrub_managed_runtime_state(TapMapRuntime)` for the stable tap id;
6. clear control-plane Neutron authority and any stale registered instance;
7. release the persisted live-iface marker;
8. remove the per-interface registry lock;
9. report `cleanup_orphan/cleaned` with the removed-entry count.

The shared runtime pin directory is retained unless the existing registry
lifecycle independently proves it has no users. The orphan cleanup must never
remove shared maps that can contain other taps.

## Failure And Retry Contract

Link detachment is fail-closed with respect to the orphan: once its links are
removed, residual map entries cannot process traffic for that interface.

If any later required cleanup step fails:

- report `cleanup_orphan/blocked` with the exact phase and error;
- do not report `runtime_reconciled`;
- retain the persisted live-iface marker;
- retain the per-interface state/WAL directory and stable tap id;
- allow the next startup reconcile to retry the same cleanup idempotently.

Partially removed map entries are acceptable only as a retryable intermediate
state. `scrub_managed_runtime_state` is already key-scoped by tap id and
idempotent, so retry cannot remove another tap's entries.

Optional-map cleanup retains the existing scrub semantics. A failure in a map
that the scrub contract treats as required blocks completion. This batch does
not weaken map error handling.

## Runtime Result Contract

`RuntimeReconcileResult` keeps its public shape:

- success: `action=cleanup_orphan`, `status=cleaned`;
- failure: `action=cleanup_orphan`, `status=blocked`;
- reason includes the cleanup phase and, on success, the tap id and removed
  entry count.

`NeutronApiState::reconcile_committed_runtime` already converts any blocked
result into `runtime_degraded`; no new status vocabulary is required.

## Hosted RED/GREEN Coverage

Unprivileged Rust behavior tests must prove:

1. orphan inventory is the union of link pins and persisted live markers;
2. committed interfaces are never selected;
3. the stable tap id is loaded from the existing per-interface state;
4. link-only cleanup does not release the retry marker;
5. a failure after link removal retains the marker and returns blocked;
6. success releases the marker only after the concrete scrub callback
   succeeds;
7. cleanup is tap-id scoped and never selects a committed sibling.

Tests may use a narrow operation seam for the privileged scrub call, but the
production path must call the real control-plane/core cleanup. Do not add a
Python source-shape checker or a generic transaction framework.

## Privileged Field Evidence

Hosted CI cannot create the production pinned Aya maps and attach real
XDP/TC links. Therefore the source implementation can reach
`implementation and hosted CI complete; privileged field evidence deferred`
after GREEN CI, but `REVIEW-ACL-045` remains open until field evidence proves:

- both ACL banks contain no orphan tap-id entries;
- general CIDR, bitmap, CT, fragment, QoS, mirror, tcprt, stats, trace,
  tap-config, and iface-context maps contain no orphan entries;
- kernel-drop managed-ifindex state contains no orphan binding;
- link pins and the live-iface marker are absent;
- a committed sibling tap remains intact;
- a forced mid-cleanup failure is reported blocked and succeeds on retry.

## Acceptance

Source delivery requires:

- RED tests that fail on the missing full cleanup/retry boundary;
- a concrete production cleanup path;
- exact-head `fast-contracts`, `rust-behavior`, and warning-denied
  `rust-build`;
- backlog status updated without overstating field readiness.

Final `fixed` status additionally requires the privileged field evidence above.
