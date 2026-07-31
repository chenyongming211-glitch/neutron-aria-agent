# REVIEW-TXN-027 Delete Forward-Recovery Design

## Status

Approved repair-order design, ready for RED behavior tests.

## Scope

This design fixes only `REVIEW-TXN-027`: a Neutron port delete has already
purged its ACL runtime and detached the interface, but the delete commit is not
durable.

It does not:

- change the WAL record format;
- add a new public recovery mode or status-contract vocabulary;
- change snapshot rollback semantics;
- absorb `REVIEW-ACL-045` orphan cleanup;
- claim privileged pinned-map evidence.

## Confirmed Current Failure

`apply_delete_neutron_port` currently performs:

1. append `DeleteIntent`;
2. purge the port ACL transactionally;
3. detach the interface;
4. optionally fail at `neutron.delete.after_detach_before_commit`;
5. append `DeleteCommit`;
6. publish the new runtime state.

After step 3, both failure paths are incorrect:

- the injected fault returns `detached: true` without publishing any blocked
  state;
- an `append_delete_commit` failure sets only three runtime fields and still
  returns `detached: true`.

The last committed WAL state and live runtime continue to contain the port,
while the datapath has already been purged and detached. The response therefore
overstates durable convergence.

The generic `recover-pending` operation cannot repair this state. Its contract
is `rollback_to_last_applied`; applying that contract to a completed physical
detach would restore the old snapshot identity and could erase the unmatched
delete intent before the delete has converged forward.

## Existing Recovery Foundation

The existing WAL already contains all identity required for forward recovery:

- one exact port id;
- the generation;
- affected managed domains;
- the complete managed-port record.

WAL replay preserves an unmatched `DeleteIntent` as
`PendingNeutronIntent { kind: "delete", ... }`.

Startup recovery already uses the stored port to attach temporarily when
required, scrub ACL runtime, and detach again. Those operations are idempotent
at the delete boundary. The missing contract is how failure is represented
before restart and how successful/failed startup recovery closes or preserves
the delete intent.

## Required Invariants

### Durable success

A delete is converged only after all of the following are true:

- ACL-owned runtime is purged;
- the interface is detached;
- `DeleteCommit` is durable;
- the published runtime no longer contains the port;
- the response reports `detached: true`.

### Failure after physical detach

If either the after-detach fault or `DeleteCommit` append fails:

- return an error with `detached: false`;
- keep the port in the live authoritative `managed_ports` projection;
- keep the unmatched durable `DeleteIntent`;
- set `pending_generation` to the delete generation;
- set `desired_hash` to `None`, matching the delete-intent identity;
- set `authority_state=blocked_recovery_required`;
- classify `wal_status` with the exact delete failure phase;
- do not call or advertise snapshot rollback as executable recovery.

Keeping the port in the authoritative projection is intentional. It prevents
the Python pending-delete logic from treating absence in `managed_ports` as a
durably committed delete. The physical interface may already be detached, but
that fact is not advertised as convergence until the WAL commit exists.

The hashless delete identity deliberately projects through Status V1 as
`blocked/blocked/operator`. It must not satisfy the complete pending-snapshot
identity required by `recover_pending`.

### Startup forward recovery

For an unmatched delete intent, startup recovery must:

1. reconstruct the exact affected port from the intent;
2. run the existing idempotent attach/scrub/detach recovery;
3. if runtime recovery succeeds, build the normal final delete state;
4. append `DeleteCommit`, not `SnapshotCommit`;
5. only after the commit succeeds, publish a runtime without the port and with
   no pending generation;
6. if runtime recovery or commit fails, keep the delete intent unmatched and
   publish only an operator-blocked live state that retains the port.

The successful state restores the last applied snapshot identity
(`desired_hash=applied_desired_hash`) because the direct delete API does not
create a new snapshot generation or hash. This matches the existing normal
delete behavior.

## Concrete Implementation Shape

Use delete-specific concrete helpers rather than a generic transaction
framework:

- build the normal committed delete runtime from the last committed runtime;
- build the blocked delete runtime from the last committed runtime and pending
  delete intent;
- finalize the post-detach boundary by either appending `DeleteCommit` and
  publishing success, or publishing the blocked state and returning a truthful
  error;
- close successful startup delete recovery with `DeleteCommit`;
- preserve the unmatched intent on recovery failure.

The main delete path remains serialized by `apply_lock`. Runtime publication
continues to occur only after WAL commit success.

## Failure Matrix

| Failure point | Datapath | WAL | Live authoritative port | Response/status | Recovery |
| --- | --- | --- | --- | --- | --- |
| delete intent append | unchanged | old commit only | retained | error, `detached:false` | retry delete |
| ACL purge | quiesced/compensated by existing transaction | unmatched delete intent | retained | error, `detached:false` | existing purge recovery |
| detach | purge completed, detach failed | unmatched delete intent | retained | error, `detached:false` | startup forward retry |
| after detach fault | purged and detached | unmatched delete intent | retained, operator-blocked | error, `detached:false` | startup forward recovery |
| delete commit append | purged and detached | unmatched delete intent | retained, operator-blocked | error, `detached:false` | startup forward recovery |
| startup runtime recovery | partial/unknown | unmatched delete intent | retained, operator-blocked | not ready | next startup/operator repair |
| startup delete commit | recovered delete state | unmatched delete intent | retained, operator-blocked | not ready | next startup retries |
| success | purged and detached | matching delete commit | removed | success, `detached:true` | none |

## RED Behavior Coverage

The RED phase must demonstrate:

1. an after-detach injected failure never reports `detached:true`;
2. the failure retains the port in live authority and leaves an exact unmatched
   delete intent for restart;
3. a delete-commit append failure has the same blocked contract;
4. a successful post-detach finalization removes the port only after a durable
   `DeleteCommit`;
5. successful startup delete recovery closes with `DeleteCommit`, clears the
   pending identity, and removes the port;
6. failed startup runtime recovery or recovery commit preserves the unmatched
   delete intent and retained-port blocked state.

Rust behavior tests are the source of truth. No Python source-shape checker is
added.

## Acceptance

`REVIEW-TXN-027` can be marked fixed after:

- the RED tests fail only on the missing delete-specific boundary;
- the production implementation makes them GREEN;
- warning-denied Rust behavior and Rust/eBPF build jobs pass at the exact head;
- backlog and this design record the exact commits and hosted CI evidence.

No privileged field evidence is required for the WAL/state correction itself.
Real pinned-map cleanup remains part of the separate orphan and purge evidence
work.
