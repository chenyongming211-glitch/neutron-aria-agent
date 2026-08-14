# Full-Code Bug-Hunt Remediation Program Design

Status: approved program boundary; implementation in progress

Date: 2026-08-13

Authoritative register: [12-review-bug-backlog.md](../../openstack-neutron-aria-details/12-review-bug-backlog.md)

## 1. Goal

Turn the independently re-verified 2026-08-13 bug-hunt findings into a
bounded, auditable repair program without creating another oversized change.
This document records the relationship between each confirmed root cause and
the current architecture contracts, fixes the execution order, and defines the
evidence required before a register row can close.

This is a program index, not one giant implementation specification. Each
production batch receives its own narrow design and RED/GREEN plan before code
changes begin.

## 2. Source Of Truth And Counting

The REVIEW register remains the only status authority. This program document
does not duplicate closure state or CI run numbers; it links every active item
to a repair boundary.

The corrected batch contains 33 stable IDs:

- 25 independent confirmed open root causes: six P1, eight P2, and eleven P3;
- three conditional findings that require a reproduction before production
  repair;
- three withdrawn findings that express current product contracts rather than
  defects;
- one reclassified defensive API debt item;
- one merged pointer (`REVIEW-ACL-087`) whose root cause is owned by
  `REVIEW-ACL-075`.

`REVIEW-TXN-033` is P2. Its proven effect is persistent allocator drift after
duplicate replay, not incorrect enforcement. It may return to P1 only if the
required replay-parity work demonstrates capacity exhaustion, index conflict,
or wrong allow/drop behavior.

## 3. Architecture Contract Catalogue

The matrix below uses these stable contract labels.

| Contract | Existing authority | Required invariant |
| --- | --- | --- |
| `DP-PARSE` | [ACL fragment tracking design](2026-07-19-acl-056-fragment-tracking-design.md), [semantic/datapath boundaries](2026-07-12-acl-semantic-unification-and-datapath-boundaries-design.md) | TC parser uncertainty must not silently skip ACL/CT/QoS. A valid first fragment has a complete transport header; ambiguous or structurally invalid traffic follows an explicit bounded action. |
| `DP-BOUNDS` | [legacy eBPF stack budget](2026-08-04-ebpf-legacy-stack-budget-design.md) | Parser loops, copy lengths, arithmetic and eBPF stack use remain verifier-safe and bounded on the maintained 4.18 target. |
| `STATUS-TRUTH` | [domain status and heartbeat](../../openstack-neutron-aria-details/05-domain-status-heartbeat.md), [versioned status contract](../../openstack-neutron-aria-details/16-versioned-rust-python-status-contract.md) | `ready/enforce` is published only when runtime evidence proves enforcement. Uncertainty is degraded or blocked and preserves the exact required recovery action. |
| `TXN-DURABLE` | [transaction and WAL contract](../../openstack-neutron-aria-details/07-transaction-wal.md), [scoped apply contract](../../openstack-neutron-aria-details/10-rust-scoped-apply.md) | Intent precedes mutation, commit is durable before publication, unresolved intent survives unrelated work, and a failed mutation cannot become false ready. |
| `TXN-IDEMPOTENT` | [transaction and WAL contract](../../openstack-neutron-aria-details/07-transaction-wal.md) | Same identity replay is idempotent; recovery neither duplicates side effects nor regresses a newer durable state. |
| `STATE-ATOMIC` | [transaction and WAL contract](../../openstack-neutron-aria-details/07-transaction-wal.md), [Neutron WAL lifecycle design](2026-07-31-review-ops-019-neutron-wal-lifecycle-design.md) | A crash cannot expose a partially written authoritative snapshot. Snapshot, checkpoint and WAL replay boundaries preserve one recoverable committed state. |
| `CONFIG-SAFE` | [INI contract](../../openstack-neutron-aria-details/01-ini-contract.md), [agent-mode architecture](../../openstack-neutron-agent-mode.md) | Missing optional configuration may use documented safe defaults; present but invalid safety-critical configuration is a hard error and never broadens interface ownership. |
| `DB-ATOMIC` | [ACL service plugin contract](../../openstack-neutron-aria-details/02-aria-acl-plugin.md) | Repository validation and mutation that protect references execute under one database transaction with concurrency-safe invariants. |
| `COMPAT-PY27` | [agent-mode architecture](../../openstack-neutron-agent-mode.md), [versioned status contract](../../openstack-neutron-aria-details/16-versioned-rust-python-status-contract.md) | The supported legacy Neutron/Python 2.7 runtime preserves the same wire and durable-state meaning as hosted Python. |
| `ERROR-EXACT` | [UDS/security contract](../../openstack-neutron-aria-details/04-uds-contract-security.md), [domain status contract](../../openstack-neutron-aria-details/05-domain-status-heartbeat.md) | Missing, empty, no-op and operational error are distinct outcomes. Kernel, repository and client faults are not silently converted into success. |
| `EVENT-COMPLETE` | [incremental sync contract](../../openstack-neutron-aria-details/09-aria-rpc-incremental-sync.md) | Drained events and paginated inventory are either processed completely or retained/rejected with an explicit convergence action. |
| `CONCURRENCY-SAFE` | implicit eBPF map safety invariant | A map element pointer is not used across an operation that can delete, evict or reuse its backing slot. |
| `OBS-EXACT` | [domain status contract](../../openstack-neutron-aria-details/05-domain-status-heartbeat.md), [logging governance](../../openstack-neutron-aria-details/14-logging-level-governance.md) | Trace, counters, deletion counts and runtime queries identify the actual cause and never report successful or empty evidence after an operational fault. |

Contract relationship has one of three meanings:

- **conflict**: current code contradicts an explicit documented contract;
- **invariant**: the defect violates a necessary implementation safety
  property even when the document does not name the exact helper;
- **gap**: the current architecture lacks enough vocabulary or bounds and the
  batch must update the contract before production behavior.

## 4. Confirmed Root-Cause Matrix

### 4.1 P1

| ID | Relationship | Contract | Repair boundary | Required evidence |
| --- | --- | --- | --- | --- |
| `REVIEW-ACL-075` | conflict | `DP-PARSE`, `DP-BOUNDS` | Separate expected runtime uncertainty from invalid/truncated input. Valid IPv6 extension chains cannot bypass inspection merely by exceeding the current walk bound; invalid L4 and structurally unparseable TC packets use an explicit fail-closed result. `REVIEW-ACL-087` stays merged here. | Raw parser fixtures for both packet shapes, TC action behavior, warning-denied hosted build, legacy-kernel packet evidence deferred until a suitable host exists. |
| `REVIEW-ACL-076` | conflict | `DP-PARSE`, `DP-BOUNDS` | Replace `pull_data(0)` reparsing with a verifier-safe bounded pull sufficient for the parsed IP and transport headers. Do not default to full `ctx.len()` linearization on large GSO skbs. | Non-linear-skb behavior test, target 4.18 helper-semantics check, stack-budget and warning-denied eBPF CI. |
| `REVIEW-ACL-077` | conflict | `COMPAT-PY27`, `STATUS-TRUTH` | Use the repository's `basestring`-compatible predicate when restoring per-domain generation history. Do not change feature-ready history ownership. | Hosted unit test plus real Python 2.7 JSON/durable-state round trip; no privileged network environment required. |
| `REVIEW-TXN-031` | conflict | `STATUS-TRUTH`, `TXN-DURABLE` | A purge or detach failure must publish the proven quiesced/error action and retain a blocked/pending delete authority. No path may retain stale `ready/enforce`. | Fault-injection behavior covering purge success plus detach failure, status projection, restart and successful retry. |
| `REVIEW-TXN-032` | conflict | `STATE-ATOMIC` | Replace in-place truncate/write of authoritative `state.json` with same-directory temporary write, file fsync, atomic rename and directory fsync. Preserve the last committed file on every pre-rename failure. | Torn-write/crash-window tests for empty, partial and rename-boundary states, including compacted-empty WAL recovery. |
| `REVIEW-OPS-038` | conflict | `CONFIG-SAFE` | Distinguish absent configuration from an existing unreadable or unparseable file. Invalid configured input terminates startup before registry creation or auto-attach. | Startup tests for absent file, invalid TOML, unreadable file and valid standalone/Neutron modes; no privileged attach is substituted for the pre-attach assertion. |

### 4.2 P2

| ID | Relationship | Contract | Repair boundary | Required evidence |
| --- | --- | --- | --- | --- |
| `REVIEW-ACL-078` | gap | `DP-BOUNDS`, `ERROR-EXACT` | Define one documented maximum representable QoS rate from the actual refill arithmetic and reject larger/non-finite values at every public parser boundary. Do not repair overflow by saturating silently. | Boundary tests immediately below, at and above the maximum; Rust/Python contract parity where both accept rates. |
| `REVIEW-ACL-079` | conflict | `TXN-DURABLE`, `STATUS-TRUTH` | Reject generation zero before intent or runtime mutation. Generation zero remains the explicit empty baseline/recovery concept, not a submitted committed generation. | Preflight RED/GREEN test proving no WAL, map or RAM mutation and a stable error code. |
| `REVIEW-ACL-080` | gap | `TXN-IDEMPOTENT`, `STATUS-TRUTH` | Freeze one public retry rule: identical partially failed submission either performs an idempotent retry or returns a typed recovery action that the Python driver demonstrably follows. It must not remain an undocumented permanent `pending`. | Rust and Python scenario test for transient failure, identical re-submit, required action and eventual convergence. |
| `REVIEW-ACL-082` | conflict | `DB-ATOMIC` | Put policy/address-set in-use check and delete under one outer write transaction with row locking or database-enforced reference safety. Preserve HTTP conflict semantics. | Real SQLAlchemy/SQLite race test plus in-memory repository behavioral parity where applicable. |
| `REVIEW-ACL-086` | invariant | `CONCURRENCY-SAFE` | Do not retain a raw map value pointer across removal/eviction. Re-lookup or restructure stale-entry deletion so all later writes target a currently owned element. Avoid a broad conntrack rewrite. | Host-side state-machine test, warning-denied eBPF build and target-kernel concurrency stress when available; worst-case cross-flow corruption remains unclaimed until field-proven. |
| `REVIEW-TXN-033` | gap | `STATE-ATOMIC`, `TXN-IDEMPOTENT` | Add a checkpoint/epoch replay boundary or make snapshot-plus-prefix replay strictly idempotent. Truncate-first is forbidden because it creates a data-loss window. | Replay-parity test comparing rules, port sets, refcounts, free list and next index after checkpoint versus checkpoint plus retained WAL. Escalate severity only on demonstrated enforcement/capacity harm. |
| `REVIEW-TXN-034` | conflict | `TXN-DURABLE` | Match commit records to intent kind and identity. Unrelated snapshot/health commits cannot clear an unresolved delete intent; share the blocked delete recovery model with `REVIEW-TXN-031`. | Replay sequence containing failed delete intent, unrelated snapshot commit, restart, retry and final delete commit. |
| `REVIEW-OPS-039` | conflict | `ERROR-EXACT`, `STATUS-TRUTH` | Treat map absence only as absence where the API explicitly allows it. Open, conversion and iteration faults propagate as degraded/error and cannot disable enforcement as if the map were empty. | Fault injection for missing pin versus permission/open/convert/iteration failure, including QoS enable-state preservation. |

### 4.3 P3

| ID | Relationship | Contract | Repair boundary | Required evidence |
| --- | --- | --- | --- | --- |
| `REVIEW-ACL-085` | conflict | `EVENT-COMPLETE` | Preserve the unprocessed suffix of a drained event batch or force an immediate full resync after delete failure. Do not silently rely on an unrelated future event. | Python event-loop test with delete failure followed by port updates and dirty networks. |
| `REVIEW-ACL-089` | conflict | `TXN-IDEMPOTENT`, `ERROR-EXACT` | Make QoS and Mirror deletion of an already absent key an explicit idempotent success while preserving real map faults. | Repeat-delete and injected map-error behavior tests. |
| `REVIEW-ACL-090` | conflict | `EVENT-COMPLETE`, `STATUS-TRUTH` | A pagination next link with no usable marker is incomplete authority and must raise/degrade instead of returning a truncated host inventory. | Multi-page, empty-page-with-next and malformed-marker client tests. |
| `REVIEW-ACL-091` | invariant | `TXN-IDEMPOTENT`, `ERROR-EXACT` | Determine callable shape once before issuing a side effect. A `TypeError` raised after request dispatch cannot trigger a second POST/DELETE. | Client double-issue tests for legacy/new signatures and response-processing `TypeError`. |
| `REVIEW-ACL-093` | conflict | `ERROR-EXACT`, `OBS-EXACT` | `delete_trace_filter` distinguishes key absence from map read failure and propagates the latter. | Missing-key idempotency plus injected read-fault test. |
| `REVIEW-ACL-094` | conflict | `ERROR-EXACT`, `OBS-EXACT` | Batch flush reports the exact removed prefix and aggregates every per-key failure; requested-key count is never returned as deletion count. | Multi-key partial-failure tests across trace, drop, kernel-drop and monitoring helpers. |
| `REVIEW-ACL-096` | conflict | `ERROR-EXACT`, `OBS-EXACT` | TCP-RT stats queries preserve a real empty result but propagate map faults. | Empty-map and open/iteration-fault tests. |
| `REVIEW-ACL-097` | conflict | `ERROR-EXACT`, `OBS-EXACT` | Control-plane TCP-RT routes propagate kernel query faults instead of normalizing them to empty lists. | Route-level success-empty and fault response tests. |
| `REVIEW-ACL-098` | gap | `OBS-EXACT` | Extend the additive trace-result ABI with fragment-drop attribution, or explicitly map every fragment reason. Reusing the existing default-to-ACL mapper is not a fix. | ABI layout/version checks, reason-to-result behavior and warning-denied userspace/eBPF builds. |
| `REVIEW-ACL-099` | gap | `OBS-EXACT` | Define attribution for fragment drops before group IDs are loaded. Prefer loading safe IDs before the drop; if group-zero aggregation is retained, make that an explicit documented metric contract. | Resolve-stage and install-stage fragment attribution tests for IPv4/IPv6. |
| `REVIEW-OPS-040` | conflict | `CONFIG-SAFE` | Reject an invalid interface regex at startup. Never substitute `^tap` for operator input unless a future explicit fallback option is separately designed. | Config/registry startup tests proving zero discovery or attach work after invalid input. |

## 5. Conditional, Merged And Corrected Records

These rows originated outside the initial confirmed production-fix set. Their
later verification outcomes are recorded below.

| ID | Classification | Required next action |
| --- | --- | --- |
| `REVIEW-ACL-083` | fixed after conditional verification | A missing-session production-style context reproduced the shared fallback. The plugin now fails fast for that context, port projection reports unavailable, and all in-memory public access is serialized. |
| `REVIEW-ACL-084` | closed; consequence not reproduced | The public plugin rethrows the injected multi-row write error and the real SQLAlchemy outer owner rolls back all prior writes. Joining an owner transaction without self-rollback remains the correct model. |
| `REVIEW-TXN-035` | closed; original false-ready consequence not reproduced | The exact restart projection test now covers committed-runtime reconstruction, ACL restart invalidation and the public status projection. A partial newer generation remains pending; the applied-generation ACL row becomes `degraded/unchanged`; and readiness remains `blocked/recover_pending`. Preserving the stale error row is neither required nor correct because the row describes the rebuilt applied runtime while transaction fields retain the failed newer generation. |
| `REVIEW-ACL-087` | merged | No independent implementation. Its truncated-first-fragment consequence is accepted only through the `REVIEW-ACL-075` batch. |
| `REVIEW-ACL-081` | withdrawn | XDP/DDoS remains outside the current Neutron-managed domain set. Reopen only with a separately approved product/status contract. |
| `REVIEW-ACL-092` | withdrawn | Feature-ready is contract-defined last-ready history; delete must not rewrite that history. |
| `REVIEW-ACL-095` | withdrawn | SSL is host-global and already flows through the host-global update path. |
| `REVIEW-ACL-088` | defensive API debt | Harden `delete_network` owner validation after active correctness batches. Current production callers retain overlap admission and owner-preimage protection. |

## 6. Fixed Delivery Order

The order is chosen by demonstrated enforcement/durability impact, then by
shared implementation boundary. A later batch may not be pulled forward merely
because its edit is convenient.

1. **TC parser safety:** `REVIEW-ACL-075/076`, including merged
   `REVIEW-ACL-087` evidence.
2. **Delete transaction recovery:** `REVIEW-TXN-031/034`.
3. **Atomic standalone state:** `REVIEW-TXN-032`.
4. **Startup configuration safety:** `REVIEW-OPS-038/040`.
5. **Python 2.7 status compatibility:** `REVIEW-ACL-077`.
6. **WAL replay parity:** `REVIEW-TXN-033`.
7. **Generation and retry contract:** `REVIEW-ACL-079/080`.
8. **Database delete atomicity:** `REVIEW-ACL-082`.
9. **Bounded values and map authority:** `REVIEW-ACL-078`,
   `REVIEW-OPS-039` as independent commits in one review window.
10. **Conntrack concurrent element safety:** `REVIEW-ACL-086`.
11. **Event/client completeness:** `REVIEW-ACL-085/090/091`.
12. **Idempotent operations and exact error propagation:**
    `REVIEW-ACL-089/093/094/096/097`.
13. **Fragment observability ABI:** `REVIEW-ACL-098/099`.
14. **Defensive API debt:** `REVIEW-ACL-088`.
15. **Conditional verification:** `REVIEW-ACL-083` is fixed after its RED
    sessionless-context reproduction. `REVIEW-ACL-084` and `REVIEW-TXN-035`
    are closed by their GREEN ownership and restart projections.

## 7. Batch Workflow And Evidence Rules

Every production batch follows the same gates:

1. Re-read the exact current functions and referenced architecture contract.
2. Write a narrow batch design with explicit included/excluded files and no
   unrelated refactor.
3. Add public behavior or fault-injection RED tests. Tests may not bind private
   helper names, local-variable order or source layout.
4. Push the RED commit and record the expected hosted-CI failure. Local Cargo
   commands remain prohibited.
5. Implement the smallest production boundary that satisfies the written
   contract; do not introduce a generic closure/future transaction framework.
6. Push GREEN, require warning-denied Rust/eBPF builds where Rust changes, and
   record exact-head CI evidence.
7. Update the REVIEW register only after the implementation HEAD is green.
8. If target-kernel or privileged evidence is required but unavailable, mark it
   `deferred/pending`. Do not substitute static inspection or hosted CI and do
   not claim the item fully field-verified.

All work remains directly on `v0.9-neutron-agent`. No new feature branch,
stacked PR or worktree is created for this program.

## 8. Scope And Change-Control Guardrails

- No XDP storm/DDoS implementation is included. Its approved product design is
  independent of this repair program.
- No new Neutron managed domain, public source-port match, datapath priority
  arbitration or multi-writer authority model is introduced.
- No checker may parse Rust private implementation shape. Structural checks are
  limited to real artifact/workflow contracts; behavior belongs in executable
  tests.
- Existing withdrawn rows are contract decisions, not convenient code cleanup.
- A batch may expand files only when required to connect its documented public
  behavior, recovery or ABI boundary. Any semantic departure from this program
  requires a design amendment before code.
- A conditional row cannot be marked fixed from defensive code alone; first
  establish whether the claimed production path exists.

## 9. Program Completion

This program is complete only when:

- all 25 confirmed root causes are fixed or explicitly reclassified with new
  evidence;
- every batch has exact-head hosted CI evidence;
- required but unavailable privileged evidence remains visibly pending rather
  than being counted as passed;
- all conditional rows have either a reproducer and repair or a recorded
  disproval;
- the REVIEW register, architecture contracts and batch documents agree on
  severity, status and product scope.

The `REVIEW-ACL-075/076` TC parser safety source implementation and hosted CI
are complete; its target-kernel evidence remains pending under its independent
[design](2026-08-13-acl-075-076-tc-parser-safety-design.md).
`REVIEW-TXN-031/034` are also complete: RED `db14bfa` exposed the missing
phase-aware failure publication, and implementation `477761e` plus legacy WAL
compatibility follow-up `d8ae123` passed exact-head Build
[31698764813](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/31698764813).
`REVIEW-TXN-032` atomic standalone state persistence is complete: RED
`9309fe9` exposed the torn-write boundary and GREEN `37740d4` passed exact-head
Build
[31717345713](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/31717345713).
`REVIEW-OPS-038/040` startup configuration safety is complete: RED `fb0f948`
exposed both unsafe fallbacks and GREEN `9010f7e` passed eight exact startup
behaviors plus warning-denied builds in exact-head Build
[31763073075](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/31763073075).
`REVIEW-ACL-077` Python 2.7 status compatibility is complete. Its
[design](2026-08-14-review-acl-077-python27-domain-history-design.md) and
[implementation plan](../plans/2026-08-14-review-acl-077-python27-domain-history.md)
used the existing real Python 2.7 clean-install lane for the durable JSON
round-trip evidence; GREEN `a483737` passed exact-head Build
[31764984847](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/31764984847).
`REVIEW-TXN-033` is complete under the versioned checkpoint epoch recorded in
[the formal design](2026-08-14-review-txn-033-wal-checkpoint-epoch-design.md).
RED `e661627` exposed allocator and replay-boundary drift; implementation
`4265ccf` plus observability completion `2cf0d47` passed 10/10 checkpoint
behaviors and every required warning-denied build in exact-head Build
[31767131659](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/31767131659).
Step 7, `REVIEW-ACL-079/080`, is complete. Its delivered long-term boundary is
the versioned explicit retry contract recorded in
[the formal design](2026-08-14-review-acl-079-080-generation-retry-contract-design.md):
reject submitted generation zero before side effects, bind pending identity to
generation plus desired hash, and let only a fresh-WAL-verified durable partial
generation use the typed Status V2 same-generation retry path. Exact-head Build
[31779783002](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/31779783002)
passed the retry behaviors and warning-denied builds. Step 8,
`REVIEW-ACL-082`, is complete under the shared parent-lock protocol recorded
in [the formal design](2026-08-14-review-acl-082-database-delete-atomicity-design.md).
RED `4336892` exposed all six deterministic delete/create races in hosted fast
and database contracts. Implementation `db169c9` passed exact-head Build
[31784634775](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/31784634775),
including fast contracts, real SQLAlchemy database contracts, and clean
install. At that closure, the next fixed-order batch was step 9:
`REVIEW-ACL-078` and `REVIEW-OPS-039` as independent implementation commits in
one review window. Section 8 records the later user-approved narrowing of the
execution scope.

## 8. ACL-Only Continuation Boundary

After `REVIEW-ACL-082`, implementation scope was narrowed to the ACL product
boundary in
[the ACL-only continuation design](2026-08-14-acl-only-remaining-remediation-design.md).
`REVIEW-ACL-085/090/091` and `REVIEW-ACL-098/099` are fixed with exact
RED/GREEN hosted evidence. `REVIEW-ACL-083` is also fixed after its conditional
path produced exact RED evidence. `REVIEW-ACL-084` and `REVIEW-TXN-035` are
closed after their GREEN probes disproved the claimed consequences. No
confirmed ACL production-fix batch remains in this narrowed line;
`REVIEW-ACL-086` alone remains a target-kernel evidence gate.

The former steps containing `REVIEW-ACL-078`, `REVIEW-OPS-039`,
`REVIEW-ACL-089`, `REVIEW-ACL-093/094`, and `REVIEW-ACL-096/097` remain valid
backlog records but are outside this ACL-only execution line because their
product owners are QoS, Mirror, generic trace/drop monitoring, or TCP-RT.
`REVIEW-ACL-088` also remains separate defensive general-map debt. None of
these exclusions changes an item to fixed or verification-complete.
