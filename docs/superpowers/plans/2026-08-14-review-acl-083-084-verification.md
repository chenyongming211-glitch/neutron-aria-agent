# REVIEW-ACL-083/084 Verification And Repair Plan

## Status

- `REVIEW-ACL-083`: reproduced by a production-style missing-session fault
  injection; narrow repair in progress.
- `REVIEW-ACL-084`: transaction-ownership probe added; no production change is
  authorized unless hosted SQLAlchemy evidence reproduces the claimed partial
  commit.
- `REVIEW-ACL-086`: excluded; target 4.18 kernel evidence remains pending.

## ACL-083 Confirmed Boundary

The installed `get_port` and `get_ports` wrappers preserve the Neutron request
context. A normal request therefore reaches `NeutronDbAriaAclRepository` and is
not affected.

The defect is reachable when the production plugin receives a non-null context
whose `session` is absent. Before this repair, both CRUD and port projection
silently selected the process-shared `InMemoryAriaAclRepository`. A write from
one such request could therefore become visible to another request and would be
lost on process restart.

The repair keeps three repository-selection cases explicit:

1. An explicitly injected repository remains authoritative for stdlib tests and
   embedding callers.
2. A non-null context with a session uses the Neutron database repository.
3. A non-null context without a session fails with
   `aria_acl_database_session_required`; the port projection boundary catches
   that infrastructure fault and emits `unknown/projection_unavailable`.

The existing `context=None` fallback is retained only for the established
stdlib-only unit seam. No installed controller or port wrapper drops the
request context to `None`.

All public in-memory repository reads and writes use the same reentrant lock.
This closes the independently verified iteration/delete race without adding a
second lock or changing payload, HTTP, notification, or database semantics.

## ACL-083 RED/GREEN Contract

- A public CRUD call with a non-null sessionless context must fail before any
  in-memory mutation.
- The real legacy port wrapper must preserve the port response but mark the ACL
  projection unavailable for the same context.
- Every public in-memory repository access must enter the repository lock.
- Explicit repository injection and normal session-backed calls remain
  unchanged.

## ACL-084 Ownership Probe

`NeutronDbAriaAclRepository` deliberately joins an already active caller-owned
transaction. The repository rethrows write failures; it must not roll back a
transaction it does not own.

The hosted database probe uses the public plugin boundary inside an outer
SQLAlchemy transaction, injects a failure during a multi-row address-set write,
and requires:

- the exception to escape the plugin;
- the outer transaction manager to roll back the earlier policy write;
- no partial address-set state to remain.

Repository and plugin source contain no catch-and-continue path around these
writes. If the probe remains GREEN, `REVIEW-ACL-084` is closed as an
unreproduced consequence under the documented ownership model. A hosted RED
result would instead require a separate repair design; it must not be hidden by
changing `_write_transaction` in this batch.

## Delivery Steps

1. Preserve the exact hosted RED evidence for the three ACL-083 contracts.
2. Apply only the repository-selection and in-memory serialization changes.
3. Run the complete local stdlib plugin suite; do not run local Cargo.
4. Push the ACL-083 GREEN plus ACL-084 database probe.
5. Require exact-head `fast-contracts`, `neutron-db-contracts`, clean install,
   and the repository's normal hosted build gates.
6. Update the authoritative register only from exact-head results.

## Exclusions

This gate does not change database schema, REST payloads, datapath behavior,
notification ordering, field evidence, or the CT implementation tracked by
`REVIEW-ACL-086`.
