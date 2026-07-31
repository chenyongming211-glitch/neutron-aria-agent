# REVIEW-ACL-036/037/028 Pending And Delete Transaction Design

## Status

Design confirmed against current source; RED tests and production implementation
pending.

## Scope

This design repairs the Python Neutron agent transaction boundary shared by:

- `REVIEW-ACL-036`: a new scoped prepare can overwrite unresolved pending;
- `REVIEW-ACL-037`: a failed scoped apply leaves durable pending while runtime
  continues to advertise ready;
- `REVIEW-ACL-028`: delete commits locally after an unvalidated non-timeout
  response and leaves cached port status stale.

It does not change the Rust publication transaction, the UDS wire schema, or
full-resync classification semantics.

## Confirmed Current Failures

### Pending overwrite

`apply_port_scoped_snapshot` does not call `recover_pending_state` before
building a new scoped transaction. `prepare_scoped_snapshot` then overwrites
all `pending_*` fields even when the existing generation/hash belongs to a
different transaction.

### False ready after scoped failure

After scoped prepare, response validation or terminal status validation may
raise while the pending record is intentionally retained for recovery.
`runtime_status` is not degraded, so the previous ready state remains visible
despite an unresolved transaction.

### Unvalidated delete success

`delete_port` validates only timeout ambiguity. Every other returned body is
treated as success; projection and durable state are committed even if the
body reports `status=error`, the wrong port, or an invalid success shape.
Successful delete also removes the projection but does not remove the deleted
port from `last_port_statuses`.

## One Pending Transaction Invariant

State stores enforce the invariant, not only callers:

- no prepare operation may replace an unresolved pending snapshot with a
  different desired hash;
- the same desired hash may be realigned to the generation required by the
  existing remote recovery protocol;
- a different pending snapshot raises an explicit local transaction conflict
  without writing any state;
- a pending delete and pending snapshot are both resolved through
  `recover_pending_state` before a new mutating event proceeds;
- direct state-store callers receive the same protection as the event loop.

`apply_port_scoped_snapshot` keeps the existing remote pre-submit recovery
ordering. The state-store guard is the final boundary: if that protocol has not
resolved a different local pending hash, scoped prepare is rejected without
overwriting it or issuing the scoped UDS mutation.

Full-host behavior keeps its existing recovery entry and remote barrier
ordering, with the same state-store guard as defense in depth.

## Scoped Failure Contract

Once a scoped prepare is durable, any exception before classification commit
must:

- retain the exact pending record for restart/next-loop recovery;
- retain the prior committed projection and feature-ready history;
- mark runtime degraded with `pending_snapshot_unresolved`;
- include the original failure in `last_error`;
- never advertise the prior ready state as current.

The pending record is cleared only by the existing proven terminal
classification/recovery paths. Transport timeout recovery remains unchanged.

## Delete Response Contract

A direct delete commits only when the response:

- is a mapping;
- identifies the requested `port_id`;
- reports `status=ok`, idempotent `status=not_found`, or the existing
  timeout-recovery `status=deleted`;
- does not contain a non-empty error;
- for a direct `ok` response, reports a successful detach/no-op outcome
  compatible with the existing Rust contract.

An invalid or explicit error response raises `LocalApiError`, retains
`pending_delete`, keeps the committed projection, and marks runtime degraded
with `pending_delete_unresolved`.

After a valid success, the event loop performs the existing projection-first,
durable-commit-last sequence and also removes the deleted port from
`last_port_statuses`, then recomputes domain/degraded summaries. Failure before
durable commit retains the pending delete and prior committed view.

## RED/GREEN Coverage

Python behavior tests must prove:

1. a different existing pending snapshot cannot be overwritten by scoped
   prepare in both durable and in-memory stores;
2. scoped apply recovers a terminal pending transaction before preparing;
3. unresolved pending blocks scoped UDS mutation and remains byte-for-byte
   unchanged;
4. response-error and post-submit status failure retain pending, preserve the
   committed projection, and mark runtime degraded;
5. delete `status=error`, wrong port id, malformed response, and contradictory
   success do not commit;
6. delete failure retains pending/projection and marks runtime degraded;
7. valid direct and timeout-recovered deletes commit;
8. valid delete removes the cached port status and recomputes summaries.

## Acceptance

- targeted RED tests fail on current behavior;
- one concrete state-machine implementation turns them GREEN;
- all Python fast contracts pass;
- backlog rows are updated only after exact-head hosted CI evidence.
