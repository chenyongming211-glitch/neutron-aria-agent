# New-Findings Remediation Program Design

Status: complete — all five batches closed 2026-08-15

Date: 2026-08-15

Authoritative register: [12-review-bug-backlog.md](../../openstack-neutron-aria-details/12-review-bug-backlog.md)

## 1. Objective

Turn the fourteen findings recorded by the 2026-08-15 record-only review pass
into a bounded, auditable repair program without expanding product scope. The
same-day independent adversarial re-verification produced 11 confirmed,
3 narrowed, 0 withdrawn, and 0 duplicate verdicts; this program develops the
thirteen in-scope rows in five batches and records the fourteenth as excluded
debt with explicit escalation conditions.

This is a program index, not one giant implementation specification. Each
batch receives its own narrow design and RED/GREEN plan before code changes
begin, and each bug closes with `test: expose` → `fix` → `docs: close`
commits, matching the repository's established TDD rhythm.

## 2. Source Of Truth And Counting

The REVIEW register remains the only status authority. This document does not
duplicate closure state; it links each row to a repair boundary.

The corrected portfolio for this program:

| Register ID | Final severity | Verdict | In scope |
| --- | --- | --- | --- |
| `REVIEW-ACL-106` | P2 | confirmed | Batch 1 |
| `REVIEW-ACL-107` | P3 (P2 defensible) | confirmed | Batch 1 |
| `REVIEW-ACL-108` | P3 | confirmed | Batch 2 |
| `REVIEW-ACL-109` | P3 | confirmed | Batch 2 |
| `REVIEW-ACL-110` | P3, conditional | confirmed | Batch 2 |
| `REVIEW-TXN-038` | P3, conditional | confirmed | Batch 2 |
| `REVIEW-ACL-101` | P3 | confirmed | Batch 3 |
| `REVIEW-ACL-102` | P3 | confirmed | Batch 3 |
| `REVIEW-TXN-037` | P3, conditional | narrowed | Batch 3 |
| `REVIEW-ACL-104` | P3 | confirmed | Batch 4 |
| `REVIEW-ACL-105` | P3 | confirmed | Batch 4 |
| `REVIEW-TXN-036` | P3 (narrowed from P2) | narrowed | Batch 5 |
| `REVIEW-ACL-100` | P3 | confirmed | Batch 5 |
| `REVIEW-ACL-103` | P3 | closed-not-supported | excluded |

## 3. Batch Design

### 3.1 Batch 1: user-visible P2 repairs (Python agent)

`REVIEW-ACL-106` and `REVIEW-ACL-107` are the only rows whose failure is
directly user-visible today: a valid ACL silently never enforces, and a
deterministic 404 stops status publication and heartbeat until restart. Both
repairs are under twenty lines, live in the Python agent, and share the
fast-contracts / clean-install / Python 2.7 CI lanes, so they form one batch.

`REVIEW-ACL-106` — ethertype case gap:

- Primary repair in the compile path: compare the stored ethertype
  case-insensitively against `_ip_version()` (`effective_acl.py:628-632`),
  matching the existing `_normalized_direction/_normalized_action/
  _normalized_protocol` family. The compile-side choice is decisive: rules
  already stored with non-canonical casing recover to `ready/enforce` without
  any database migration.
- Defense in depth (second commit in the same batch): canonicalize ethertype
  in `prepare_rule` at write time so new rows never store non-canonical values.
- Acceptance: `ipv4`/`IPV4`/`IpV4` each compile to `ready/enforce`; canonical
  behavior and IPv6 rejection are unchanged; a stored-value compatibility
  test proves no migration is required.

`REVIEW-ACL-107` — port-status delete 404 wedge:

- Treat NotFound/404 as idempotent success in `_delete_one`: discard the
  pending id and count the delete as done; retain only transport errors and
  5xx for retry. `_flush_pending_deletes` gets the same defense.
- Acceptance: after a 404, `report()` still writes status rows and heartbeat;
  transient `RuntimeError` retains the retry semantics; consecutive 404s never
  block the pipeline.

### 3.2 Batch 2: Python robustness (agent + DB)

Four independent Python-side hardening rows, one CI lane family, no
datapath interaction:

- `REVIEW-ACL-108` — `EventMerger.ready()` gets an absolute drain deadline
  (default 5s, configurable) so sustained event streams cannot starve the
  drain; overflow must preserve `_deleted_ports` for `safe_full_resync`
  instead of dropping them. Acceptance: a sustained 0.1s event stream drains
  more than zero times; delete events survive overflow; the existing silence
  window semantics do not regress.
- `REVIEW-ACL-109` — `update_address_set` calls `_replace_members` only when
  the update explicitly supplies `members` (`"members" in values`); an
  explicit empty list keeps its clear semantics. Acceptance: a name-only
  update performs zero member-row changes.
- `REVIEW-ACL-110` — replace the rowcount-based presence decision in
  `upsert_port_status` with an existence check (`SELECT 1`) or an
  insert-first plus savepoint-absorbed IntegrityError flow, so idempotent
  repeat writes cannot surface a pseudo 500. Acceptance: unchanged-value
  double writes return success; concurrent-writer semantics from
  `REVIEW-ACL-040` do not regress. The MySQL same-second trigger remains a
  documented conditional; a real-target verification is recorded deferred
  when no environment is available.
- `REVIEW-TXN-038` — fsync the parent directory after `os.replace` in
  `SnapshotStateStore._write`, mirroring the Rust `REVIEW-TXN-032` pattern.
  Acceptance: a behavior test proves the file-then-directory fsync order; the
  power-loss window itself is documented deferred.

### 3.3 Batch 3: Rust core ERROR-EXACT family

Three rows share one root-cause family (errors silently converted to empty or
success) and one repair style already present in the codebase:

- `REVIEW-ACL-101` — the eight scrub helpers aggregate per-entry iteration
  errors instead of `filter_map(|item| item.ok())`, and the POLICY /
  PORT_BITMAP_POOL / ACL-LPM families gain post-scrub `verify_empty` passes
  mirroring `fragment_sweep_with`; `scrub_acl_bank` and friends propagate
  failures upward. Acceptance: injected iteration faults fail the scrub
  instead of returning a short count; healthy paths are unchanged.
- `REVIEW-ACL-102` — `get_ct_contract_stats` propagates iteration errors
  following `inventory.rs:93-95`; `/metrics` exposes the failure instead of
  silently dropping the series. Acceptance: injected faults return an error
  observable at the endpoint.
- `REVIEW-TXN-037` — `inventory_wal` propagates read errors;
  `WalWriter::open` fails or records them, and `system_start` surfaces the
  count to the health endpoint. The narrowed scope (no replay attribution)
  is the accepted contract. Acceptance: injected read errors produce a
  visible failure count without regressing the `REVIEW-OPS-027` replay
  semantics.

All three close with hosted rust-behavior tests under `-D warnings`; no
privileged field evidence applies.

### 3.4 Batch 4: eBPF fragment drop attribution

The two rows touch the same fragment resolve-drop code and must be changed
together to avoid conflicts; both are subject to the legacy 448-byte TC stack
budget gate:

- `REVIEW-ACL-104` — call the existing `refresh_trace_flag_tc` in the four
  resolve-drop phases with resolved (or documented port-0) ports so
  port-filtered tracing captures fragment-context drops. Acceptance:
  resolve-stage drops appear in TRACE_LOG under a port filter; the linked
  stack budget stays at or under 448 bytes; unfiltered behavior is unchanged.
- `REVIEW-ACL-105` — overwrite `info.proto` with the recoverable
  `fragment_context_l4_proto` before `do_drop`/`do_trace` in the resolve-drop
  path; when unrecoverable, document the on-wire semantics. Acceptance: a
  Frag→HOPOPTS→TCP non-first fragment drop is attributed to proto 6, not
  0/43/60.

Target-kernel trace/statistics observation is recorded deferred when no
environment is available and does not block merge.

### 3.5 Batch 5: Rust agent transaction and status projection integrity

`REVIEW-TXN-036` and `REVIEW-ACL-100` share the same projection gap (the
Status V1 `operator_blocked` wedge) from two trigger surfaces and must be
repaired and verified in one transaction batch, last, on the stable CI
baseline established by Batches 1–4:

- `REVIEW-TXN-036` — guard `apply_delete_neutron_port` against an unresolved
  durable partial: reject the delete with a stable error code (for example
  `delete_blocked_by_unresolved_pending`, consistent with admission pending
  semantics) without writing WAL. The alternative that preserves the pending
  identity inside the delete commit is recorded but not recommended (larger
  state-machine surface). Acceptance: a delete during partial+pending is
  rejected with no WAL write; normal not_found/deleted semantics are
  unchanged; the Python double gate does not regress.
- `REVIEW-ACL-100` — `acl_domain_status_for` returns
  `degraded` + `effective_action=bypass` (stable reason `no_acl_payload`) for
  acl-managed ports without an acl payload, and the Python `302-306` default
  only applies `enforce` when a concrete acl domain payload exists.
  Acceptance: a direct-UDS acl-less managed port projects degraded/bypass and
  no longer wedges whole-machine Status V1; the production Python pipeline
  behavior is unchanged; `REVIEW-ACL-048` semantics do not regress.
- If a new error code is introduced, `NEUTRON_UDS_ERROR_CODES_HASH` and
  `neutron-uds-contract.json` are updated in the same batch and verified by
  the UDS contract drift check.

## 4. Verification Gates

- TDD rhythm: `test: expose` (RED) → `fix` (GREEN) → `docs: close`; the RED
  commit must fail only on the intended missing behavior.
- No local Cargo execution; GitHub Actions is the compilation authority.
  Python suites may run locally as the repository rules permit.
- CI lanes per batch: Batches 1–2 run fast-contracts, clean-install,
  neutron-db-contracts (Batch 2), and the Python 2.7 lane; Batch 3 runs
  rust-behavior with `-D warnings`; Batch 4 runs the nightly eBPF build,
  `check_ebpf_stack_budget --max-path-bytes 448`, and ABI contracts; Batch 5
  runs the `neutron_snapshot_*`/`neutron_wal_*` behavior filters and the UDS
  contract drift check.
- Conditional items (`REVIEW-ACL-110` MySQL semantics, `REVIEW-TXN-038`
  power-loss window, Batch 4 field observation) close with honest verified or
  deferred outcomes; deferred evidence is never written as PASS.

## 5. Delivery Order

```text
Batch 1  ACL-106 + ACL-107   Python agent, user-visible P2 fast wins   DONE
Batch 2  ACL-108 + ACL-109 + ACL-110 + TXN-038   Python robustness    DONE
Batch 3  ACL-101 + ACL-102 + TXN-037             Rust core ERROR-EXACT DONE
Batch 4  ACL-104 + ACL-105                       eBPF fragment attribution DONE
Batch 5  TXN-036 + ACL-100                       transaction/status projection DONE
```

Batch 1 closed 2026-08-15: RED `8b34f26` / Build
[31853208120](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/31853208120)
failed only the five intended behaviors; GREEN `7feda2d` + `774158c` passed
exact-head Build
[31853325569](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/31853325569)
and the local full Python suite (645 tests OK). The compile-side ethertype
repair recovers stored non-canonical rules without a data migration.

Batch 2 closed 2026-08-15: RED `95b8538` / Build
[31853722516](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/31853722516)
failed only the eight intended behaviors; GREEN `9c05dec` + `0ecf0fc` +
`3e0bf92` passed exact-head Build
[31853908451](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/31853908451)
and the local full Python suite (652 tests OK). The MySQL same-second and
power-loss conditionals remain deferred evidence as recorded in the register.

Batch 3 closed 2026-08-15: RED `53b7310` / Build
[31854525474](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/31854525474)
failed rust-behavior only on the four missing-interface errors; GREEN
`9b35904` + `128afa4` + `826110c` + `096a9da` passed exact-head Build
[31856998709](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/31856998709)
with all jobs green. The parallel Phase B line shared the branch during this
batch; the multi-session coordination rules in `AGENTS.md` record the
attribution protocol used to isolate this batch's evidence.

Batch 4 closed 2026-08-15: RED `97b12d6` / Build
[31866487502](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/31866487502)
failed fast-contracts on the missing trace-refresh call site and
rust-behavior on the missing abi helper; GREEN `db5297a` + `e895ef6` +
`edab3e1` passed exact-head Build
[31867137312](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/31867137312)
with all jobs green, including the nightly eBPF build and the 448-byte
stack budget. Target-kernel observation stays deferred.

Batch 5 closed 2026-08-15: RED `04f40af` + `355d8bf` / Build
[31869238668](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/31869238668)
failed only the two intended Rust contracts and the reporter contract;
GREEN `3d0d29d` + `7bb97cd` passed exact-head Build
[31869573028](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/31869573028)
with all jobs green. The thirteen-row program is complete. Product-contract
clarification closes `REVIEW-ACL-103` as `closed-not-supported`: ACL/CT manages
only untagged ordinary VM taps, while physical/provider trunks and Neutron
trunk/subport or guest tagged taps remain outside the supported boundary. The
pass therefore has no ordinary open row.

The order fixes the two user-visible P2 rows first, then completes the
same-language Python hardening, then the core error-propagation family, then
the verifier-constrained eBPF changes, and finally the most regression-prone
state-machine batch on the stable baseline produced by Batches 1–4. Work
continues on `v0.9-neutron-agent` only: no feature branch, worktree, stacked
PR, or local Cargo execution is introduced.

## 6. Cross-Cutting Constraints

- No eBPF map ABI change, no WAL record schema change, and no change to
  existing UDS routes or success semantics; each batch is independently
  revertible.
- The Batch 1 compile-side ethertype repair is chosen deliberately so that
  already-stored non-canonical values recover to enforce without data
  migration; the write-side canonicalization then prevents new non-canonical
  rows.
- `REVIEW-ACL-103` is excluded from all batches and is
  `closed-not-supported`, not deferred implementation debt. Reopen it before
  introducing VLAN-aware policy, Neutron trunk/subport, guest tagged taps, or
  ACL/CT attachment to a physical trunk; that future design must version
  policy, CT, fragment identity, and pinned-map ABI coherently.

## 7. Explicitly Excluded Items

The following rows are not developed by this program, continuing the boundary
set by the 2026-08-14 ACL-only design:

- `REVIEW-ACL-103` (`closed-not-supported` under the untagged-VM-tap product
  contract, with the support-expansion reopen conditions above);
- the pre-existing non-ACL rows `REVIEW-ACL-078`, `REVIEW-OPS-039`,
  `REVIEW-ACL-089`, `REVIEW-ACL-093`, `REVIEW-ACL-094`, `REVIEW-ACL-096`,
  `REVIEW-ACL-097`, and the defensive `REVIEW-ACL-088`; and
- `REVIEW-ACL-086`, which remains the separate target-kernel verification
  gate and is not called fixed without target-kernel evidence.

## 8. Acceptance Boundary

The program is complete when:

- all thirteen in-scope rows have exact RED/GREEN evidence and their register
  rows are marked fixed with Build or field evidence;
- the three conditional items have honest verified or deferred outcomes;
- `REVIEW-ACL-103` remains `closed-not-supported` with its support-expansion
  reopen conditions intact;
- all applicable hosted CI lanes pass at each implementation head, including
  the 448-byte stack budget for Batch 4 and the UDS contract check for
  Batch 5; and
- the branch is clean and synchronized with `origin/v0.9-neutron-agent`.
