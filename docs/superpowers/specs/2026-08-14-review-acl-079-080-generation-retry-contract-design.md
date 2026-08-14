# REVIEW-ACL-079/080 Generation And Same-Generation Retry Contract Design

**Status:** approved; Python RED behavior evidence recorded

**Date:** 2026-08-14

**Owning findings:** `REVIEW-ACL-079`, `REVIEW-ACL-080`

## 1. Decision

Make generation zero a reserved internal baseline and introduce one explicitly
versioned same-generation retry contract for a durably committed partial
snapshot.

The contract has two independent rules:

1. a submitted full-host or port-scoped snapshot must have
   `generation >= 1`; generation zero is never written as an accepted or
   applied snapshot;
2. a snapshot whose per-port result was durably committed as `partial` may be
   retried only with the exact same generation and desired hash. The retry
   starts from the durable partial state, runs under the existing host apply
   barrier, and either commits that same generation as ready or leaves the
   same generation visibly partial.

Status V1 remains immutable. Status V2 adds the typed
`required_action=retry_snapshot` decision for a durable partial generation.
Python learns V2 before Rust emits it, preserves the exact pending request, and
uses one bounded explicit retry rather than inventing a new generation.

This is not a blind replay loop. An in-flight request is still deduplicated,
an unsafe WAL/recovery state is still blocked, and a different generation or
hash can never borrow the pending transaction's identity.

## 2. Verified Root Causes

### 2.1 Generation zero reaches production apply

`validate_snapshot_preflight` validates schema and scoped path/body shape but
does not reject `snapshot.generation == 0`. The request can therefore pass
inventory discovery, append a WAL intent, mutate runtime, append a commit and
publish `authority_state=ready` with `applied_generation=0`.

Status V1 deliberately reserves generation zero for an empty idle baseline or
the narrow typed `inventory_unavailable` recovery exception. A committed
generation-zero snapshot is consequently projected as
`blocked/blocked/operator`. Generic pending recovery also rejects it because
there is no positive applied baseline to restore.

The failure is created at admission. It must be rejected there rather than
relaxing Status V1 or treating a submitted generation zero as a real baseline.

### 2.2 Pending deduplication ignores generation identity

`pending_snapshot_submit_response` currently compares only the requested hash
with `runtime.desired_hash`. For example, a runtime pending generation 110 and
a request for generation 111 with the same hash are returned as a successful
`pending` deduplication. The response echoes generation 111 while the runtime
continues applying generation 110.

That is not idempotency. Idempotency requires the exact transaction identity,
which is the pair:

```text
(generation, desired_hash)
```

Both members must match before a request can be treated as the existing
transaction.

### 2.3 A durable partial commit is never re-entered

After a per-port failure, `build_snapshot_commit_runtime` durably records:

```text
accepted_generation = G
applied_generation   = previous G
pending_generation   = G
desired_hash         = H
authority_state      = partial
```

Successful port mutations and error statuses are contained in that committed
partial state. A later identical PUT is intercepted by the hash-only pending
path and returns `pending` without preparing another apply.

When a positive applied baseline exists, the current Python driver can recover
to that baseline and submit a newer generation. That is safe but discards the
opportunity to converge the already durable partial transaction directly.
When the first generation becomes an ordinary partial, no positive baseline
exists and `recover-pending` cannot restore it. Status V1 must then fail closed
as operator, so the deployment can remain stuck even after a transient port
failure disappears.

## 3. Alternatives Rejected

### 3.1 Document recovery plus a new generation only

This preserves the current code but does not recover an ordinary first-
generation partial. It also leaves the hash-only cross-generation
deduplication defect intact.

### 3.2 Retry in Rust without a typed Python/status decision

Allowing `partial` to fall through the Rust pending shortcut would make a raw
PUT retry work, but the official driver would continue following the V1
`recover_pending` action. The public API and the supported client would have
different retry semantics.

### 3.3 Retry every pending authority state

An `applying` request may still own the apply lock. A WAL intent without a
commit, commit failure, inventory recovery or runtime uncertainty may contain
uncompensated side effects. Re-entering those states as an ordinary partial
would race an active task or conceal a required recovery barrier.

Only a fully written ordinary partial commit is eligible.

## 4. Generation Admission Contract

The shared full-host and single-port preflight order becomes:

1. validate the request schema version;
2. require `generation >= 1`;
3. validate scoped path/body shape;
4. only then perform restore-readiness checks, lock acquisition, OVS discovery,
   WAL append or runtime planning.

Generation zero returns HTTP 400 with the stable error code:

```text
INVALID_SNAPSHOT_GENERATION
```

The error details state that generation zero is reserved and submitted
snapshots must start at one. Schema mismatch retains precedence over the
generation error, and a valid generation with a scoped path/body mismatch
retains `PORT_SCOPE_MISMATCH`.

The rejection must prove all of the following:

- no WAL file or WAL entry is created;
- accepted, applied and pending generations are unchanged;
- no OVS inventory load is started;
- no registry, ACL, CT or pinned-map operation is invoked;
- both snapshot routes return the same generation error.

Generation zero remains valid only as producer-internal state for:

- the empty `idle/unknown/full_resync` baseline;
- the already approved typed `inventory_unavailable` empty-baseline recovery.

It never becomes a submitted, accepted or classified generation.

Adding the error changes the public error vocabulary. V2 therefore uses
`v0.9-neutron-errors-3`; it is not silently added under the old errors hash.

## 5. Exact Pending Identity

Every pending admission decision compares both generation and hash.

| Runtime state | Request identity | Result |
| --- | --- | --- |
| no pending generation | any valid request | continue normal admission |
| pending `G/H`, applying or accepted | exact `G/H` | HTTP 200 `pending`; no second task |
| pending `G/H`, durable partial | exact `G/H` | enter the explicit retry path |
| pending `G/H`, unsafe recovery/unknown state | exact `G/H` | HTTP 409 `snapshot_retry_not_safe`; follow status |
| pending `G/H` | generation differs | HTTP 409 `snapshot_apply_in_progress` |
| pending `G/H` | hash differs | HTTP 409 `snapshot_apply_in_progress` |
| fully applied `G/H`, ready | exact `G/H` and no drift | existing `noop` |
| fully applied `G/H`, ready | same G, different H | existing `generation_hash_conflict` |

The conflict response reports the actual pending generation without echoing a
false accepted identity. Neither a same-hash newer generation nor a same-
generation different hash is allowed to start while `G/H` is pending.

The existing Python desired hash includes the scoped request object for a
port-scoped snapshot. This batch does not redefine hash construction or trust
arbitrary caller-selected hashes as proof of scope. The server continues to
validate the route/body scope independently on every retry.

## 6. Durable Partial Retry Barrier

### 6.1 Eligibility

A request is retryable only when all of these are true:

- `runtime.pending_generation == request.generation`;
- `runtime.desired_hash == request.desired_hash`;
- `runtime.authority_state == "partial"`;
- the runtime has a complete pending identity;
- WAL replay has zero failures;
- WAL replay contains no unresolved intent;
- the latest committed WAL state matches the live runtime's generation, hash,
  authority, managed-port and port-status identity.

The final checks run after acquiring the existing `apply_lock`. A status
projection may advertise the normal durable-partial case as retryable, but the
mutating endpoint always replays and revalidates the WAL barrier immediately
before appending the retry intent.

If the barrier cannot be proven, the endpoint performs no mutation and returns
HTTP 409 `snapshot_retry_not_safe`. It does not downgrade uncertainty into a
partial retry. The new error and `INVALID_SNAPSHOT_GENERATION` are both covered
by `v0.9-neutron-errors-3`.

### 6.2 Retry transaction

The retry reuses the existing concrete snapshot transaction; it does not add a
generic closure/future transaction framework.

Under the retained apply guard:

1. take the durable partial runtime as `runtime_before_apply`;
2. load and revalidate local OVS inventory;
3. rebuild the complete full-host or scoped desired-state plan;
4. append and fsync a new ordinary snapshot intent for the same `G/H`;
5. publish `authority_state=applying` without changing generation identity;
6. reconcile from the partial state's managed ports and statuses;
7. append and fsync the resulting snapshot commit;
8. publish the committed runtime.

Desired-state reconciliation supplies idempotency:

- a successfully detached port is absent and is not detached again;
- a failed detach remains present and is retried;
- a successfully attached/updated port is verified or reconciled without
  allocating a second authority identity;
- a failed attach/update remains absent or retains its prior committed state
  and is retried;
- ACL replacement continues using its existing transactional publication and
  strict CT invalidation contracts.

If every result succeeds, the commit records:

```text
accepted_generation = G
applied_generation   = G
pending_generation   = null
desired_hash         = H
applied_desired_hash = H
authority_state      = ready
```

If any result still fails, the next commit remains the same durable partial
`G/H`. No server-side loop is started and no new generation is invented.

### 6.3 States excluded from retry

The following remain on their existing recovery/operator paths:

- `applying` and `accepted`: deduplicate and poll;
- `blocked_recovery_required`;
- `wal_commit_failed`, `wal_recovery_commit_failed` and
  `pending_recovery_commit_failed`;
- `wal_intent_without_commit`;
- typed `inventory_unavailable` recovery;
- WAL replay failures or live/WAL identity disagreement;
- unknown authority or recovery cause.

## 7. Status V2 Contract

Status V1 and its scenario fixture remain unchanged. Status V2 uses:

```text
status_schema_version_min = 2
status_schema_version_max = 2
status_schema_version     = 2
status_contract_hash      = v0.9-neutron-status-2
```

It adds one required-action token and one allowed triple:

```text
required_action = retry_snapshot
(transaction_state, overall_readiness, required_action)
  = (blocked, blocked, retry_snapshot)
```

This triple is emitted only for a structurally complete ordinary
`authority_state=partial` identity with zero known WAL replay failures. It is
not ready and cannot advance Python's classified or feature-ready tracks.

Status V2 deliberately does not expose pending-generation port rows as
classified evidence. Its public `port_statuses` retain the V1 row rule:
`generation <= applied_generation`, with the applied hash required at the
current applied generation. Internal error rows at pending generation G remain
durable runtime/WAL diagnostics but do not become public readiness evidence.
The typed transaction action plus exact pending G/H authorizes retry; Python
does not infer retry permission from a failed port row. This also keeps the V1
row parser reusable and prevents a pending row from being mistaken for an
applied policy after restart.

Existing decisions are preserved:

| Runtime evidence | V2 action |
| --- | --- |
| active exact pending apply | `pending/unknown/poll` |
| durable ordinary partial | `blocked/blocked/retry_snapshot` |
| recoverable unsafe state with positive baseline | `blocked/blocked/recover_pending` |
| typed inventory-unavailable recovery | `blocked/blocked/recover_pending` |
| recovered baseline | `recovery/degraded/full_resync` |
| inconsistent or unknown state | `blocked/blocked/operator` |

`retry_snapshot` means that an exact replay is the primary automatic action.
The client must first prove that its current authoritative desired hash still
equals the pending hash. If the desired state changed:

- it must not replay stale desired state merely to clear pending;
- with a positive applied baseline, the existing exact-identity
  recover-pending operation remains the permitted fallback before a newer full
  resync;
- with no applied baseline, it must remain blocked for operator resolution.

Status V2 does not weaken the generation-zero inventory exception, add an
automatic rollback to a generic empty baseline, or treat partial as classified
degraded.

The capability/error versions emitted with Status V2 are:

```text
status contract:     v0.9-neutron-status-2
error vocabulary:   v0.9-neutron-errors-3
capability contract: v0.9-neutron-capabilities-4
```

The request schema remains version 1 because the snapshot JSON shape does not
change.

## 8. Python Retry Ownership

### 8.1 Durable request evidence

The Python state store adds optional pending-request fields alongside its
existing generation/hash/scope metadata:

- normalized snapshot request body;
- request scope (`full_host` or `port`);
- scoped path port ID when applicable;
- last same-generation retry timestamp and attempt count.

The stored request is capped by the existing UDS request-body limit and is
written through the already atomic state-file path. Committing or clearing the
matching pending snapshot clears the request and retry metadata atomically.
Old state files without these fields remain readable.

Before a retry, Python proves:

- the persisted pending generation/hash match Status V2;
- the stored request recomputes to the same desired hash;
- its route/body scope is valid;
- a fresh authoritative Neutron projection still has the same desired hash.

The last comparison prevents completion of a stale policy after Neutron has
already changed the desired state.

### 8.2 Driver action

On `retry_snapshot`, Python performs at most one explicit replay in a
convergence attempt and uses the existing scheduler/backoff boundary for later
attempts. It calls the original full-host or port-scoped PUT with the exact
stored `G/H`; it never allocates a new generation while `G/H` remains pending.

After the PUT it reads Status V2 again:

- `classified/ready/none` for `G/H`: commit both local tracks normally;
- terminal classified-degraded evidence: follow the existing classified-only
  rule if the server actually cleared pending;
- `blocked/blocked/retry_snapshot`: retain local pending and back off;
- `recover_pending` or `operator`: stop retrying and follow that typed action;
- unknown/malformed V2: latch the write gate closed.

The driver does not derive retry permission from raw `authority_state` strings.

### 8.3 Changed desired state

If the freshly rebuilt desired hash differs from pending `H`, Python must not
send either body under generation `G`.

With `applied_generation > 0`, it may use the existing exact pending recovery
barrier, verify the recovered baseline, then allocate a generation strictly
above both the applied and pending generation floors for the new desired
state. With `applied_generation == 0`, no generic rollback exists; Python
retains pending and reports an operator-required error.

## 9. Upgrade And Compatibility

Rollout remains Python first, then Rust:

1. new Python accepts the immutable `(min=1,max=1,hash=status-1)` pair and the
   new `(min=2,max=2,hash=status-2)` pair, together with their exact capability
   and error-vocabulary hashes;
2. against old Rust/V1 it preserves the existing poll/recover/full-resync
   behavior;
3. new Rust begins advertising and returning Status V2 only after the V2-aware
   Python package is available;
4. old Python presented with V2 fails its exact contract negotiation and
   blocks writes rather than guessing the new action.

Required mixed-version matrix:

| Python | Rust | Result |
| --- | --- | --- |
| new | V1 | supported legacy behavior; no `retry_snapshot` assumption |
| new | V2 | explicit same-generation retry |
| old | V1 | unchanged |
| old | V2 | contract mismatch; fail closed/no write |

The V1 fixture, hash and decoder remain available for compatibility tests.
V2 receives a separate scenario fixture; no static checker is allowed to bind
the implementation to private helper names or source order.

## 10. Failure Matrix

| Failure or race | Required result |
| --- | --- |
| generation-zero full/scoped request | HTTP 400 before side effects |
| same hash but different generation while pending | HTTP 409; actual pending identity preserved |
| exact request while old task still applying | one `pending` response; no second task |
| exact request after durable partial commit | one guarded same-generation retry |
| WAL replay contains unresolved intent | retry refused; recovery/operator status preserved |
| WAL/live partial identity differs | retry refused; no new intent |
| retry intent append fails | partial committed baseline remains authoritative |
| retry runtime operation fails again | same G/H commits partial; bounded backoff |
| retry commit fails after mutation | existing blocked recovery compensation; no false ready |
| retry succeeds | same G/H becomes applied ready; pending clears |
| Python pending request missing/corrupt | no PUT; write gate remains blocked |
| current Neutron desired hash changed | no stale replay; recover positive baseline or require operator |
| process restarts after partial commit | WAL restores partial G/H; new Python revalidates durable request before retry |

## 11. RED/GREEN Behavior Matrix

### 11.1 Rust behavior

Required RED tests:

1. full-host generation zero is rejected before WAL/runtime mutation;
2. scoped generation zero is rejected with the same stable code before scope
   apply work;
3. pending G with request G+1 and the same hash conflicts rather than
   deduplicating;
4. applying G/H plus exact G/H still deduplicates and launches no task;
5. durable partial G/H plus exact G/H prepares one retry under the apply lock;
6. a transient failed port succeeds on retry and commits ready at G, not G+1;
7. successful ports are not duplicated and failed ports are reconciled;
8. a second transient failure remains partial at G/H;
9. unresolved intent, replay failure and WAL/live mismatch each reject retry;
10. first-generation partial can converge through exact retry without an
    invented generation-zero baseline.

### 11.2 Python and cross-language behavior

Required RED tests:

1. V2 decoding accepts only the new closed vocabulary and exact hash;
2. V1 decoding remains unchanged;
3. a persisted exact full-host partial request is replayed at the same G/H;
4. a persisted scoped request uses the same scoped route and body;
5. restart reloads and revalidates the pending request before retry;
6. successful retry clears pending and records G as classified/feature-ready;
7. repeated partial retains pending and observes bounded backoff;
8. missing/corrupt request evidence performs no mutation;
9. a changed current desired hash is never replayed under old G/H;
10. new-Python/V1-Rust and old-Python/V2-Rust compatibility outcomes match the
    rollout matrix.

The hosted Rust test filter must execute a nonzero count. Existing Python unit
discovery may run the Python behavior tests; they must not be copied into a
second static marker suite.

## 12. Observability

Use structured fields on existing snapshot logs:

- `generation` and `desired_hash`;
- `pending_generation`;
- `retry_disposition` (`deduplicated`, `retryable_partial`, `blocked`);
- `same_generation_retry=true` on the retry transaction;
- `retry_attempt` on Python logs;
- `retry_result` (`ready`, `partial`, `recovery_required`, `operator`).

Do not log snapshot bodies, ACL members or policy contents. Do not add a new
high-cardinality metric family. Existing apply latency/result metrics remain
authoritative; a low-cardinality same-generation retry counter may be added
only if an existing snapshot metric family can carry it.

## 13. Scope

Expected production and behavior-test scope:

- `api/src/lib.rs`: Status V2 action/schema/hash and capability/error versions;
- `agent/src/neutron_api.rs`: generation preflight, exact pending identity,
  durable partial retry barrier, V2 projection and Rust behavior tests;
- `agent/src/neutron_wal.rs`: only a narrow committed-state identity helper if
  fresh partial-retry validation cannot be expressed through existing replay;
- `openstack/neutron_aria/neutron_aria/agent/uds_client.py`: V1/V2 negotiation
  and strict V2 decoding;
- `openstack/neutron_aria/neutron_aria/agent/state.py`: bounded durable pending
  request and retry metadata;
- `openstack/neutron_aria/neutron_aria/agent/event_loop.py`: typed V2 retry
  action, current-hash validation and bounded replay;
- existing Rust/Python unit modules and versioned scenario fixtures;
- UDS contract, transaction/status documentation, remediation-program pointer
  and REVIEW register.

Explicit exclusions:

- no generation-zero submitted snapshot compatibility mode;
- no generic rollback from an ordinary first-generation partial to an empty
  baseline;
- no retry of intent-only, commit-failed, inventory-recovery or unknown states;
- no unbounded server/client retry loop;
- no new generation for an unresolved identical desired state;
- no change to ACL policy semantics, map ABI, TC/eBPF forwarding or CT rules;
- no generic transaction framework or private-source-shape Python checker;
- no privileged datapath evidence claim.

## 14. Acceptance

1. No full-host or scoped generation-zero request can create a WAL, runtime or
   datapath mutation.
2. Pending deduplication never crosses generation or hash identity.
3. Only a fresh-WAL-verified durable ordinary partial commit is re-entered.
4. A transient first-generation partial converges to ready at the same
   generation without inventing an empty applied baseline.
5. Repeated retry never duplicates successful ownership or widens scope.
6. Unsafe recovery states remain blocked and retain their existing recovery
   barriers.
7. Python performs a same-generation retry only from typed Status V2 plus exact
   durable request and current desired-state evidence.
8. Status V1 remains immutable and the mixed-version rollout fails closed.
9. Exact-head fast contracts, Python behavior, Rust behavior, warning-denied
   userspace/eBPF builds and packaging pass before either finding is marked
   fixed.
10. No field or privileged evidence is required because this batch changes
    control-plane transaction admission and retry semantics, not datapath packet
    behavior.
