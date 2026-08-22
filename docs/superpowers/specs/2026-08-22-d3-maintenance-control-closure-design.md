# D3 Maintenance Control Closure Design

## Status

Approved approach: retain the current implementation, split D3 into bounded
acceptance gates, and freeze the protocol before any further production change.

This document is a closure addendum to:

- `2026-08-21-aria-planned-maintenance-upgrade-design.md`;
- `2026-08-21-aria-planned-maintenance-upgrade-v09.md`.

It narrows D3 only. It does not change the planned-maintenance product model or
authorize work from D4 and later gates.

## 1. Decision

D3 remains one delivery gate on `main`, but it is reviewed and accepted as
three independently bounded sub-gates:

| Gate | Responsibility | Closure rule |
| --- | --- | --- |
| D3-A | Shared ACL/conntrack packet gate and live managed authority | Frozen after exact-head packet, authority, build, and 480-byte stack evidence |
| D3-B | Durable maintenance transaction, WAL, replay, CAS, and writer fencing | Accepted only against the state and record matrices in this document |
| D3-C | Root-only admin transport, status contract, and audit | Accepted only against the transport and public-contract matrix in this document |

The existing Git history is not split or rewritten. No feature branch or
worktree is created. The current implementation is retained. A structural
refactor is considered only if the bounded review finds a defect that crosses
two or more sub-gates and cannot be repaired without changing their interface.

## 2. Scope Boundary

### 2.1 D3-A: Packet Gate

D3-A owns only:

- the versioned shared `FIREWALL_CONFIG` maintenance byte;
- one packet-entry sample used by ACL, conntrack, and fragment processing;
- bypass before per-tap ACL state access;
- independence of monitoring, QoS, Mirror, and other non-ACL domains;
- serialized key-0 read-modify-write and full readback;
- live runtime, program, map, and attachment authority;
- ingress and egress linked-artifact stack measurement.

D3-A does not own the maintenance transaction, admin routes, Python buffering,
full-resync construction, shadow generations, or upgrade orchestration.

### 2.2 D3-B: Transaction Kernel

D3-B owns only:

- the Rust-local maintenance state and operation identity;
- Enter, progress, Exit, Abort, and recovery compare-and-swap behavior;
- maintenance WAL records, replay, checkpoint, and bounded compaction;
- startup recovery before ordinary reconciliation;
- shared writer leases and the fixed lock order;
- truthful gate state when write, readback, or recovery is uncertain;
- exact idempotency and conflict-with-zero-mutation behavior.

D3-B does not implement the host coordinator phases from design section 7.
The host ledger owns `preflight`, `quiescing`, container replacement,
`full_resync`, rollback, and final host commit. The Rust-local state below is a
smaller protocol used by that coordinator.

### 2.3 D3-C: Admin And Status Contract

D3-C owns only:

- the separate `/run/aria/aria-admin.sock` listener;
- root UID peer authorization before request routing;
- the four maintenance routes and their bounded typed bodies;
- absence of those routes from Neutron UDS and TCP routers;
- atomic maintenance status, readiness degradation, and Status v4 decoding;
- one attempt and one result audit event for each admin operation.

D3-C does not add Python event buffering, stable double-read inventory,
heartbeat orchestration, Kolla coordination, or rollback execution.

## 3. Rust-Local State Machine

The following matrix is authoritative for D3-B:

| State | Active | Gate truth | Writer rule | Legal next state |
| --- | --- | --- | --- | --- |
| `ready` | No | Enforce | Ordinary writers admitted | `bypass_preparing` |
| `bypass_preparing` | Yes | Not yet proven | All ordinary writers fenced | `maintenance_bypass`, `gate_unknown` |
| `maintenance_bypass` | Yes | Bypass proven | Only matching full-host snapshot admitted | progress in place, `verifying`, `gate_unknown` |
| `verifying` | Yes | Bypass until clear proof; fenced until commit | All writers fenced by the terminal transaction | `committed`, `maintenance_bypass`, `gate_unknown` |
| `gate_unknown` | Yes | Unknown | All writers blocked | `maintenance_bypass` only after fresh live proof |
| `committed` | No | Enforce proven | Ordinary writers admitted | No reuse of the same operation identity |

Additional rules:

1. A durable Enter intent fences writers before the gate mutation is trusted.
2. Startup with an active, dangling, or unknown operation proves or forces
   bypass before schema preparation, runtime replay, or ordinary reconciliation.
3. Gate write success followed by readback or authority failure is unknown, not
   enforce and not bypass.
4. `verifying` never authorizes ordinary writers. After a successful clear
   readback but before terminal commit, failure must restore bypass or persist
   `gate_unknown`; enforcement becomes transactionally complete only after the
   terminal commit succeeds.
5. A conservative Abort may finish in `maintenance_bypass`; it does not imply
   enforcement restoration.
6. A pending Exit supersedes an earlier conservative Abort terminal identity.
   The old Abort request then conflicts without WAL, gate, or RAM mutation.

## 4. Compare-And-Swap And Idempotency

| Operation | Required identity | Exact retry | Conflict behavior |
| --- | --- | --- | --- |
| Enter | operation ID, domain, generation, desired hash, inactive state | Return the existing accepted state only when recovery is clean | HTTP 409 and zero mutation |
| Progress | active operation ID plus monotonic generation/hash identity | Exact composite commit is idempotent | Reject scoped, stale, mismatched, or terminal-pending writer |
| Exit | operation ID, current phase, applied generation/hash, complete convergence | Return the matching terminal result | HTTP 409 and zero mutation |
| Abort | operation ID and the original active expected phase | Return only the matching persisted terminal result | HTTP 409 and zero mutation |
| Recovery | operation ID, current durable state, fresh gate authority | Re-record only an exact proven state | Stay blocked on ambiguity |

No endpoint may derive idempotency from operation ID alone.

## 5. WAL Contract

### 5.1 Version Namespaces

The public maintenance state schema and the internal WAL record schema are
separate version namespaces:

- public maintenance state remains schema v1;
- new internal WAL records are written as v2;
- the reader accepts only WAL v1 and v2;
- WAL v1 compatibility is limited to the historical missing Abort expected
  phase, derived from the immediately preceding durable active phase or the
  conservative terminal Abort state;
- WAL v2 requires the Abort expected phase at decode time;
- unknown versions and ambiguous legacy shapes fail conservatively.

### 5.2 Legal Record Sequences

```text
EnterIntent
  -> gate bypass write and full live readback
  -> EnterCommit

ordinary SnapshotIntent
  -> one SnapshotMaintenanceCommit containing:
       ordinary snapshot commit
       exact maintenance ProgressCommit

ExitIntent
  -> convergence revalidation
  -> gate clear and full live readback
  -> ExitCommit

AbortIntent(expected_phase)
  -> either conservative bypass or the same clear proof required by Exit
  -> AbortCommit

active state
  -> RecoveryCommit(gate_state, phase, bounded cause)
```

The replay rules are:

- a commit without its matching intent is invalid;
- the composite snapshot commit requires the matching ordinary intent;
- the ordinary generation/hash and maintenance generation/hash must match;
- pending terminal transitions reject progress records;
- a checkpoint is first, self-contained, and semantically replayable;
- checkpoint pending action, terminal action, expected phase, gate state,
  phase, and block cause must form one legal matrix row;
- duplicate records are invalid except an explicitly supported exact terminal
  retry;
- malformed, oversized, unknown, or identity-drifting records keep the host
  blocked and never reopen enforcement.

### 5.3 Bounds And Durability

- maximum encoded maintenance record: 64 KiB;
- maximum replay set: 4096 maintenance records;
- line reading is bounded before allocation grows beyond the record limit;
- compaction is triggered before the replay-count or byte limit is exhausted;
- checkpoint rename and directory durability follow the existing Neutron WAL
  fsync contract;
- a crash at every intent, gate, commit, checkpoint, and rename boundary has a
  deterministic conservative replay result.

## 6. Writer Fence And Lock Order

The only legal acquisition order is:

```text
maintenance transaction/read lease
  -> Neutron apply lock
  -> runtime state lock
```

No path may acquire a maintenance lease while holding the apply or runtime
lock. Snapshot publication, background failure marking, delete, recovery,
periodic work, lifecycle work, netlink work, and TCP mutation routes retain the
appropriate maintenance lease through their final runtime mutation.

During active maintenance:

- only a matching full-host snapshot may stage progress;
- port-scoped snapshot and delete are rejected;
- missing or mismatched operation ID is rejected;
- pending Exit or Abort rejects all progress;
- `gate_unknown` rejects all ordinary mutation.

## 7. Admin And Public Status Contract

The admin socket contract is:

- exact path `/run/aria/aria-admin.sock`;
- trusted no-follow parent and final socket validation;
- final socket mode `0600` and root ownership;
- every accepted connection requires peer UID 0 before Axum routing;
- admin routes are absent from the Neutron UDS and TCP routers.

Status v4 is one atomic semantic unit:

- `required_action=complete_or_repair_maintenance` if and only if
  `maintenance_action` has the same value;
- maintenance action requires phase, operation ID, bounded reason, degraded or
  blocked control state, and truthful ACL enforcement;
- ordinary ready/classified status cannot carry maintenance identity or bypass;
- `gate_unknown` is blocked and reports unknown enforcement;
- `/livez` may remain 200, while `/readyz` and Docker health remain unhealthy.

Each admin call produces exactly one bounded attempt event and one bounded
success or failure result. Audit data excludes policy bodies, tokens, secrets,
and unbounded nested input.

## 8. Frozen Acceptance Matrix

### D3-A

1. IPv4 and IPv6, ingress and egress, sample the gate before per-tap ACL state.
2. ACL, conntrack, and fragment state are bypassed together.
3. Unrelated feature domains retain their declared behavior.
4. Shared map mutation is serialized and fully read back under live authority.
5. Program, map, attachment, mode, and pin identities are revalidated.
6. Linked `tc_ingress` and `tc_egress` remain at or below 480 bytes.

### D3-B

1. Exhaustive legal and illegal state-transition table tests.
2. Enter, progress, Exit, Abort, and recovery CAS zero-mutation conflict tests.
3. Crash/replay tests at every intent, gate, commit, checkpoint, and rename cut.
4. WAL v1 legacy fixtures migrate narrowly; malformed v1 and incomplete v2 fail.
5. Composite snapshot identity accepts both commits or neither.
6. All writer classes are covered by production-path lease race tests.
7. Startup proves bypass before ordinary runtime mutation.
8. Gate unknown, restore failure, and lost response preserve truthful state.

### D3-C

1. Real temporary-directory bind tests cover path, mode, owner, symlink, type,
   replacement, and peer UID authorization.
2. Production routers prove admin route isolation and ordinary mutation fencing.
3. Status v4 production decoders accept every legal fixture and reject every
   contradictory action, identity, phase, and enforcement fixture.
4. Idempotent, conflict, and failure paths each produce one attempt/result pair.
5. Response and error vocabularies match the authoritative JSON contract.

### Repository Gate

1. Worktree is clean and `main == origin/main`.
2. Exact-head `fast-contracts`, database, install, Rust behavior, Rust build,
   userspace build, agent build, and linked stack jobs pass.
3. `maintenance_gate_capable` remains `false` until Tasks 3-6 coexist.
4. Real EL 4.18 verifier, dual-stack traffic, restart/kill, restoration, and
   rollback evidence remains `deferred/pending`, never represented as CI PASS.

## 9. Bounded Final Review

The next review is finite and maps every finding to section 8:

- Critical or Important violations of the frozen matrix block D3 closure.
- A blocking fix receives a focused RED, the smallest production repair, exact
  CI, and re-review of the changed invariant only.
- Minor findings are recorded for later work unless they violate a stated
  safety or compatibility rule.
- Adjacent Task 5/6 functionality and general refactoring are out of scope.
- A new defect crossing two or more sub-gates triggers a separate refactor
  decision. It does not trigger another open-ended patch wave.

## 10. Refactor Decision

Do not refactor the current implementation before the bounded review merely to
reduce file size. Retain the implementation if the frozen matrix passes.

If a cross-gate defect is found, split the implementation by responsibility:

```text
neutron_maintenance/model.rs       pure states, identity, and CAS plans
neutron_maintenance/wal.rs         record schema, decode, replay, checkpoint
neutron_maintenance/coordinator.rs I/O ordering, leases, gate, and store
neutron_maintenance/audit.rs       bounded audit types and sink
```

That refactor must be behavior-preserving first. No new maintenance feature may
be combined with the structural move.

## 11. Explicit Non-Goals

- no Git history rewrite, branch split, or alternate worktree;
- no Task 5 Python buffering or stable double-read implementation;
- no Task 6 shadow-generation implementation;
- no Kolla coordinator, container replacement, or rollback execution;
- no new eBPF hot-path behavior;
- no capability flip;
- no production-readiness claim from CI alone.
