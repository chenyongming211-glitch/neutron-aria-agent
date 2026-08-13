# Review Bug Backlog

Status: open review backlog.

Date: 2026-07-03; refreshed 2026-07-10 (deep-dive); re-verified 2026-07-12;
`REVIEW-ACL-055` three-form privileged field acceptance closed 2026-08-11;
ACL transaction Batch 2, restart/CT safety Batch 3, and stateful/CT contract
Batch 4 closed 2026-07-11; priority/overlap Batch 5 closure recorded
2026-07-12; the all-mode TC-unified follow-up was approved 2026-07-13 and its
code/CI implementation passed on 2026-07-14. Batch 6 is now likely-fixed while
privileged standalone system and complete managed-Neutron runtime evidence
remain pending. Fragment-safe ACL/CT implementation, hosted CI, and privileged
legacy-kernel tap evidence are complete; the independent XDP hook-health
source fix and hosted CI are complete while target-kernel evidence remains
pending. A full-code independent re-verification at
`dc5d56106472c205a432c98be369c5c51bfdc0d8` was recorded 2026-07-15; its
merge-gate and truthful-readiness batches closed 2026-07-17.
Standalone bitmap cleanup quarantine and recovery (`REVIEW-ACL-059`) closed
2026-07-19 with exact-head hosted Rust/eBPF evidence.
Bounded Neutron WAL checkpointing and capacity enforcement
(`REVIEW-OPS-019`) closed 2026-07-31 with exact-head hosted Rust/eBPF
evidence; no privileged field evidence applies to that filesystem-only repair.

## 2026-08-11 ACL-055 Field Closure

`REVIEW-ACL-055` is fixed. Exact runtime artifacts from `7ffc5d6` passed
standalone `MODE=system`, standalone `MODE=tap`, and focused Neutron-managed
execution on the target 4.18 kernel. XDP remained ACL/CT-neutral; TC ingress and
egress were the only ACL/CT authorities; stale CT, missing-direction recovery,
restart replay, bank transitions, and cleanup passed. A managed deny policy
also admitted zero packets across a controlled `aria_datapath` restart and
returned directly to `ready/enforce`. An independent OVS
canary received 30,162 replies with no failure markers, and neither
`ovs-vswitchd` nor `neutron_openvswitch_agent` changed identity. See
`docs/evidence/openstack-n05-lite/20260811-acl055-all-mode-tc-authority/summary.md`.

The dated July classification sections below remain unchanged as historical
snapshots. The Register records the current status.

Scope rule:

- Fix bugs and contract gaps discovered during review.
- Do not use this backlog to add new ACL/QoS/Mirror product features.
- Prefer API/config validation and narrowly scoped tests over new behavior.
- Record-only updates are allowed without expanding product scope.

## 2026-07-15 Full-Code Independent Re-Verification (Historical Snapshot)

This section records the verdicts at `dc5d561`. The current register below
supersedes this dated snapshot after later fixes; older dated counts remain
audit history. The reviewed tree was
`codex/rust-ebpf-warning-cleanup` at `dc5d561`. The pass traced Python-to-UDS
state transitions, Rust snapshot commit flow, ACL/CT datapath keys, northbound
validation, and CI gates. No local Cargo command was run.

### Confirmed blockers at the time

| ID | Severity | Re-verification verdict | Root-cause fix boundary |
| --- | --- | --- | --- |
| `REVIEW-TXN-028` | P1 | Post-apply status failure can false-commit. A `pending` submit followed by `LocalApiError` from status reproduced `ready=true`, local pending cleared, and generation committed. A status with matching generation/hash but `runtime_degraded` or ACL `degraded/bypass` is also accepted. Explicit pending/non-converged status is already polled and correctly fails; that branch is not the bug. | Make `_status_after_apply()` return a verified terminal status or raise. Commit projection/state and call `mark_ready()` only after authority and requested domains prove terminal ready. On status failure or exhausted polling, retain pending and mark degraded. |
| `REVIEW-TXN-029` | P1 | OVSDB/`ovs-vsctl` failure becomes a non-authoritative empty inventory; eligible ports become `ignored`, but success checks only look for `error`. The transaction can advance applied generation/hash, clear pending, write WAL commit, and report ready while the old datapath remains. | Preserve the existing no-detach behavior for non-authoritative inventory, but promote `ovsdb_unavailable` to a retriable transaction-level degraded/blocked result. Do not advance applied/hash or clear pending; preserve prior ports and statuses. Keep normal DHCP/SR-IOV/not-applicable ignores legal. |
| `REVIEW-ACL-046` | P1 | **Reopened.** The earlier risk classification lacked a demonstrated enforcement path. Non-`neutron:*` local groups are allowed and are written into active ACL LPM banks; shadow staging also replays every group. Same or more-specific local CIDRs return a local group ID while the Neutron policy key expects its selector ID, so a selector deny can miss and default PASS. This is LPM namespace interference, not allocator ID collision. | Separate ACL selector maps from QoS/Mirror/general group maps. Stage only group IDs referenced by the final ACL rule set. Exact/overlapping selector conflicts must be rejected or canonicalized. Publish the repair with a bank switch or strict CT scrub. |
| `REVIEW-ACL-057` | P1 | Standalone/direct policy add, update, and delete mutate the active ACL bank in place without bank rotation or CT invalidation. The same root cause applies when a CIDR is added to a standalone group already referenced by an ACL policy (`REVIEW-ACL-066`): the selector is written into the active bank. CT freshness only checks the bank, so an established/default-PASS flow can survive either change and refresh its lifetime indefinitely. Managed-Neutron replacement is not affected because it switches bank and strictly scrubs CT. | Route all direct/batch policy mutations and ACL-referenced standalone group membership changes through one complete shadow-bank publish transaction. Stage final state, atomically switch bank, strictly invalidate CT, and restore the old bank/state/durable preimage on failure. Keep ordinary unreferenced-group durability outside this batch under `DEBT-ACL-001`. |
| `REVIEW-ACL-056` | P1 | Reconfirmed. IPv4 parsing ignores fragment offset and interprets non-first-fragment payload bytes as TCP/UDP ports; those values enter ACL evaluation and ordinary CT keys. IPv6 already avoids L4 parsing for non-first fragments. Passing one later fragment does not by itself prove successful reassembly when the first fragment was dropped, but the ACL/CT semantics and cache pollution are still incorrect. | Expose first/non-first fragment metadata for both families, never read L4 bytes from non-first fragments, and keep them out of ordinary five-tuple CT. For port-dependent policy, use an explicit fail-closed interim action or a fragment-decision cache keyed by address/protocol/fragment ID/direction/bank. |
| `REVIEW-CI-002` | P1 | Pull requests targeting `v0.9-neutron-agent` do not trigger Build because `pull_request.branches` contains only `main`. The successful `dc5d561` build was manually dispatched, so it is not a merge gate. | Include the maintained v0.9 target branch (or the intended `v*` branch set) in PR triggers, add a workflow contract check, and require the Build check in branch protection before runtime fixes are merged. |

### Confirmed additional defects and guard gaps

| ID | Severity | Re-verification verdict | Required fix |
| --- | --- | --- | --- |
| `REVIEW-ACL-058` | P2, P1 impact | Write-time validation accepts legacy short IPv4 forms such as `10.1/16`, missing/disabled/empty/invalid address sets, and cross-project address-set references. Runtime strict parsing degrades invalid input to bypass; a valid cross-project set can compile directly to enforce. Current write policy is admin-only, which reduces exposure but not correctness impact. | Use the same strict canonical IPv4 parser at every repository create/update boundary. Resolve address-set references transactionally and require existence, enabled state, valid non-empty IPv4 members, and matching project before mutation. Keep runtime validation as defense in depth. |
| `REVIEW-ACL-059` | P2 | On standalone policy replacement/delete, a bitmap index is released to the reusable pool before kernel bitmap cleanup is proven. Cleanup failure is only logged, so a later policy can reuse an index containing stale port bits. The trigger requires a kernel cleanup fault. | Quarantine the index until `delete_port_set` succeeds; on failure keep it unavailable and return degraded/error. Add fault tests proving no reuse until confirmed cleanup. |
| `REVIEW-OPS-037` | P2 | Snapshot admission holds the global apply mutex while two synchronous `Command::output()` `ovs-vsctl` calls run with no timeout. A hung OVS command blocks the async executor thread and every later apply. | Gather inventory before the mutation lock where safe, or use bounded `spawn_blocking`/async process execution with kill-on-timeout. Revalidate inventory identity after acquiring the lock. |
| `REVIEW-ACL-060` | P2 | Neutron list methods accept `sorts`, `limit`, `marker`, and `page_reverse` but discard them. DB implementations fetch entire tables; SQL address-set listing performs one member query per row. | Push filters, stable sorting, marker, direction, fields, and limit into repositories. Batch-load address-set members. Add forward/reverse pagination and large-list query-count tests. |
| `REVIEW-ACL-061` | P2 | Duplicate enabled rule-priority and binding-target checks read first and insert/update in a later transaction, while migration indexes are non-unique. Concurrent writers can both pass validation and commit a conflicting state. | Enforce the invariant in the database with an appropriate uniqueness strategy for enabled rows, map conflicts to HTTP 409, and retain preflight checks only for friendly errors. Add concurrent writer tests. |
| `REVIEW-ACL-062` | P2 | Fixed. Revalidation narrowed the live gap to standalone and attach-owned QoS/Mirror: policy already used the ACL-057/066 bank transaction, while managed QoS/Mirror already had receipt-based compensation but lacked durable fencing for incomplete restoration. All local QoS/Mirror paths now publish one complete final state through one strict transaction, restore exact update/delete preimages, report every compensation/durable-restore error, and persist a domain-scoped recovery fence until startup replay and validation succeed. | RED `fb20546` / Build [`30683268154`](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/30683268154) proved the missing recovery interface while independent compilation passed. GREEN `44743f5` / exact-head Build [`30683913104`](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/30683913104) passed the named fault-injection/startup behaviors plus warning-denied eBPF/userspace/agent builds. No local Cargo or privileged field run was performed; field execution is supplementary for this userspace transaction repair and remains unclaimed. |
| `REVIEW-CLI-001` | P2 | Fixed. The live defect covered 37 dynamic Rust-client request sites. All instance, group, and chain names now pass through concrete segment-encoding boundaries; numeric query parameters remain separate and literal percent text is encoded exactly once. | RED `9609518` / Build [30693251050](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/30693251050) failed only the three real request-line behaviors while independent checks passed. GREEN `91edc43` / exact-head Build [30693519106](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/30693519106) passed those behaviors plus fast/database contracts and warning-denied eBPF/userspace/agent builds. No local Cargo or privileged field run was performed; field evidence is not required or claimed for this client-only repair. |
| `REVIEW-CI-003` | P2 | Rust-change detection includes Rust source directories but not `.github/workflows/` or `ci/`. A change to toolchains, warning flags, linker installation, or Rust guard scripts can skip the Rust/eBPF build. | Treat workflow and Rust-related CI script changes as Rust-required, or default to Rust builds for all PRs to maintained release branches. Add a table-driven detector self-test. |
| `REVIEW-CI-004` | P3 | The new Pod-layout guard proves explicit field/tail padding but does not require `#[repr(C)]`; removing it from `PolicyKey` still passes the checker. All current Pod structs do have `repr(C)`, so this is a prevention gap, not an observed ABI regression. | Parse or structurally inspect each `aya::Pod` type and require an adjacent `#[repr(C)]`; keep size/alignment assertions in the ABI crate for userspace CI. |
| `REVIEW-DOC-022` | P2 | Fixed. The public UDS contract now documents `POST /api/v1/neutron/snapshot/recover-pending`, including request defaults and identity guards, both success outcomes, every current HTTP/error-code pair, and compatibility behavior. Stage 1 now requires the exact six-route inventory and checks public method/path parity across the JSON artifact, Rust server, and Python client without binding private helper structure. | RED `8d3183e` / Build [30693943116](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/30693943116) failed the missing contract route while database contracts, Rust behavior tests, and warning-denied Rust/eBPF builds passed. GREEN `fb74ba8` / Build [30694029883](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/30694029883) passed fast/database contracts, Rust behavior tests, and warning-denied eBPF/userspace/agent builds. No runtime behavior changed, no local Cargo command was run, and privileged field evidence is not applicable to this contract-only repair. |

Existing items `REVIEW-ACL-036` (scoped prepare overwrites unresolved pending),
`REVIEW-ACL-045` (orphan cleanup does not use the full managed-runtime scrub),
and `REVIEW-OPS-019` (unbounded Neutron WAL) remain open and were not assigned
duplicate IDs. This paragraph records the original review snapshot; the
authoritative Register below now records `REVIEW-OPS-019` and
`REVIEW-ACL-045` fixed. ACL-045 received target-kernel field closure on
2026-08-07 after an additional legacy-TC detach defect was found and repaired.

### Direct evidence and corrected non-findings

The read-only Python/source probes produced these stable observations:

```text
FALSE_READY pending True None 1
SCOPED_OVERWRITE <old-hash> <new-hash> True
WRITE_ACCEPTED 10.1/16 missing-set
RUNTIME_RESULT degraded bypass invalid_acl_ipv4_cidr,...address_set_missing
POD_GUARD_ACCEPTS_MISSING_REPR_C True
RUST_CHANGE .github/workflows/build.yml False
RUST_CHANGE ci/check_rust_warning_hygiene.py False
```

- No semantic or layout regression was found in the `dc5d561` ABI extraction
  itself. Current CI compiled it with zero Rust warning lines; `REVIEW-CI-004`
  records only the missing future guard.
- The local/Neutron group defect is not duplicate numeric allocation; all
  groups share one allocator. It is a selector-map namespace and value-aliasing
  defect.
- A normal explicit pending response whose status remains non-converged is
  polled and fails safely. `REVIEW-TXN-028` is limited to unavailable status or
  a generation/hash match whose authority/domain outcome is not ready.
- `REVIEW-ACL-055` remains likely-fixed pending its three privileged runtime
  summaries; this pass did not reopen the Batch 6 implementation.

## 2026-07-12 Source Re-Verification And Classification

Full re-check of all recorded `REVIEW-*` IDs against the current tree, followed
by ACL contract-guardrail Batch 1, transaction Batch 2, restart/CT safety Batch
3, stateful/CT contract Batch 4, and priority/overlap Batch 5 closure. The
`REVIEW-*` prefix remains a stable historical identifier and no longer implies
that the item is an open implementation bug by itself.

The numerical tables in this dated checkpoint are retained for audit history;
the Register later in this document is authoritative for current status.

| Verdict | Count | IDs |
| --- | ---: | --- |
| Confirmed active defect or contract gap | 35 | Remaining open/in-progress register rows, including the fragment and XDP hook-health defects |
| Likely fixed; operational evidence pending | 1 | `REVIEW-ACL-055`: all-mode TC/XDP-neutral code and full GitHub Build are green; three privileged runtime summaries remain pending |
| Fixed | 24 | `REVIEW-ACL-016`, `REVIEW-ACL-018`, 13 ACL Batch 1 IDs, 3 transaction Batch 2 IDs, 2 Batch 3 IDs, 2 Batch 4 IDs, `REVIEW-ACL-047` in Batch 5, and field-verified `REVIEW-ACL-046` |
| Verification needed | 1 | `REVIEW-ACL-012`: implementation path is present; clean-container evidence is still required |
| Reclassified as risk/design boundary | 1 | `REVIEW-ACL-032` |
| Closed: finding not supported as written | 1 | `REVIEW-ACL-052` |
| **Total `REVIEW-*` IDs** | **63** | Stable IDs retained for audit history |

The 35 active items are grouped by failure surface so that
runtime bugs are not mixed with delivery and documentation gaps:

| Active class | Count | IDs |
| --- | ---: | --- |
| Transaction, datapath, recovery, and runtime consistency | 17 | `ACL-023`, `ACL-025`, `ACL-026`, `ACL-028`, `ACL-033`, `ACL-036`, `ACL-037`, `ACL-044`, `ACL-045`, `ACL-056`; `TXN-024`, `TXN-026`, `TXN-027`; `OPS-019`, `OPS-027`, `OPS-034`, `OPS-036` |
| Northbound API, DB, compile, and status projection correctness | 8 | `ACL-003`, `ACL-004`, `ACL-008`, `ACL-013`, `ACL-038`, `ACL-040`-`ACL-042` |
| Packaging, deployment, validation, documentation, and release gaps | 10 | `ACL-005`, `ACL-007`, `ACL-010`, `ACL-011`, `ACL-014`, `ACL-015`, `ACL-017`; `DOC-020`; `OPS-035`; `CI-001` |
| **Total active defect or contract gap** | **35** | Excludes the separately reported likely-fixed and verification-needed states |

The authoritative Register has since marked `REVIEW-ACL-056` and
`REVIEW-OPS-019` fixed; they are not active P1 defects. `REVIEW-ACL-055`
remains a P1 likely-fixed item until its privileged runtime evidence closes it.

Also spot-checked: `ACL-004` (host=None returns `status[0]`), `ACL-014`
(workflow `contents: write`), `ACL-015` (plugin policy backup only when file
exists), `ACL-017` (CLI installer hard-codes `/etc/kolla/.adminrc`) — all still
present.

Risk tracking now contains six classified items: five existing `RISK-*` IDs
plus reclassified `REVIEW-ACL-032`. Engineering debt now
contains five `DEBT-*` IDs, including the separately recorded legacy local-ACL
persistence debt. The unique tracking-item total is now 73.

| Current tracking portfolio | Count | Included states |
| --- | ---: | --- |
| Active defect or contract gap | 35 | Open or in-progress `REVIEW-*` register rows pending closure evidence |
| Likely fixed; operational evidence pending | 1 | `REVIEW-ACL-055` |
| Risk / design boundary | 6 | Five `RISK-*` IDs plus reclassified `REVIEW-ACL-032` |
| Engineering debt | 5 | `DEBT-*` IDs |
| Verification needed | 1 | `REVIEW-ACL-012` |
| Fixed | 24 | Two earlier fixes plus 13 ACL Batch 1, three transaction Batch 2, two Batch 3, two Batch 4, one Batch 5 fix, and field-verified `REVIEW-ACL-046` |
| Closed / unsupported finding | 1 | `REVIEW-ACL-052` |
| **Total unique tracking items** | **73** | Includes the Batch 6 fast-path, fragment finding, XDP hook-health finding, and local-ACL persistence debt |

### ACL Batch 1 Closure

| IDs | Closure evidence |
| --- | --- |
| `ACL-001`, `ACL-009`, `ACL-043` | Shared strict policy/rule contract, server-side create/update validation, priority-zero handling, and executable legacy CLI parser tests. |
| `ACL-002` | All repository implementations reject duplicate enabled binding targets and duplicate enabled priorities before mutation. |
| `ACL-006` | Plugin repository proxy maps validation to HTTP 400 and not-found to HTTP 404 while preserving unexpected faults. |
| `ACL-029`, `ACL-030` | Effective compiler degrades disabled, empty, invalid, or missing address-set references to bypass. |
| `ACL-031` | Effective-for-port derives eligibility from Neutron owner/vif/vnic fields instead of hard-coding true. |
| `ACL-039`, `ACL-049`, `DOC-021` | Python accepts only `managed_domains=acl`; Rust/JSON capabilities advertise only `attach` and `acl`; Stage 1 enforces exact equality. Direct unsupported domains remain rejected. |
| `ACL-048` | Runtime UDS status/action/reason are authoritative and cannot be overwritten by optimistic snapshot metadata. |
| `ACL-051` | WAL pending-intent recovery blocks all domains outside `attach` and `acl`; legacy `qos`/`mirror` intents can no longer report recovered success without an executor. |

### ACL Transaction Batch 2 Closure

| IDs | Closure evidence |
| --- | --- |
| `TXN-021` | Snapshot admission now holds the owned apply lock, fsyncs the exact WAL intent before returning `pending`, and advances only pending/hash metadata. Accepted/applied remain at the last commit. Rust tests cover durable handoff and intent-write failure. |
| `TXN-022` | Pre-commit and commit-append failures share recovery that restores/retains committed attach topology, scrubs affected ACL, reports `blocked` with `effective_action=bypass`, retains the failed pending generation, and prevents the generic background marker from overwriting recovery state. QoS/Mirror remain unimplemented and rejected. |
| `TXN-025` | A successful WAL commit publishes RAM before the post-commit hook; return-error becomes a committed warning. Recover-pending replays WAL first and returns `already_committed` instead of appending stale RAM. Python prioritizes recoverable authority over same-hash waiting and preserves pending on recovery failure. |

### ACL Restart And CT Safety Batch 3 Closure

| IDs | Closure evidence |
| --- | --- |
| `ACL-035` | Successful restart attach preserves `attach=ready` but invalidates only the ACL domain hash, reports ACL `degraded/unchanged`, and persists `runtime_reconcile_requires_full_resync`. Same-generation and same-hash shortcuts cannot bypass the next ACL reconcile. WAL append failure still publishes invalidated RAM state rather than retaining false-ready skip metadata, while an existing pending recovery authority remains authoritative. |
| `ACL-053` | Every Neutron ACL replacement pre-disables the ACL gate, uses a Neutron-specific strict V4/V6 CT scrub, and enables a non-empty ACL only after CT clear succeeds. Missing/invalid pins, iteration failures, and removal failures now fail ACL apply; post-disable failures report bypass. The general lenient management flush remains unchanged. |

### ACL Stateful And Conntrack Contract Batch 4 Closure

| IDs | Closure evidence |
| --- | --- |
| `ACL-050` | ACL reconcile now atomically quiesces per-tap CT and ACL, strictly clears CT while lookup/create is disabled, and atomically publishes the desired CT mode with the final ACL gate. ACL-selected authority rejects local conntrack mutation as an internal dependency without adding `conntrack` to advertised or accepted managed domains. |
| `ACL-054` | Rust translation carries `NeutronAclSnapshot.stateful` into the ACL apply plan. Stateful enforcement publishes CT on plus ACL on; stateless enforcement publishes CT off plus ACL on, so the existing eBPF per-tap guard skips both CT lookup and CT create. Empty/bypass and missing-payload preservation paths have explicit transition tests. |

### ACL Priority And Overlap Batch 5 Closure

| IDs | Closure evidence |
| --- | --- |
| `ACL-047` | Python effective-ACL preflight and the Rust direct-UDS defense both reject priority-dependent overlaps with stable reasons. Exact canonical CIDR selector sets reuse one Rust group. Rust returns the actual `degraded/bypass` outcome only after the classified empty-ACL transaction succeeds; failed transactions retain the existing proven-action error classification. Numeric priority ordering is not implemented in the current eBPF datapath, and QoS/Mirror remain outside this fix. |

#### Batch 5 Final Review Hardening Verification

`REVIEW-ACL-047` remains fixed and the inventory counts above are unchanged.
The final hardening pass added strict Python/Rust IPv4 CIDR parity, exact
1000-rule and 2048-raw-selector-member runtime bounds, an index-lifetime Python
compile cache, and a snapshot-request-scoped Rust validation-template cache.
Production force-bypass status now flows through `AclApplyPlan` and
`NeutronAclReconcileOutcome::from_plan`; reconcile errors use the same
before-quiesce, after-quiesce, and compensation-failed classifier at tests and
production call sites.

- Python RED: `PYTHONPATH=openstack/neutron_aria python3 -m unittest
  neutron_aria.tests.unit.test_effective_acl` ran 31 tests and produced the
  expected 5 failures plus 2 errors before implementation.
- Python GREEN: the effective-ACL and event-loop suites ran 75 tests with zero
  failures after implementation.
- Rust RED: GitHub Build run `29177709424` failed with the expected 15 missing
  constant/cache/translation/phase-interface compiler errors.
- Rust GREEN: GitHub Build run `29177888031` passed the persistent
  `neutron_acl_` filter, eBPF build, userspace static build, agent static build,
  and binary verification.
- Focused hardening coverage comprises 4 CIDR parity tests, 4 boundary-limit
  tests, 3 cache/defensive-copy tests, and 2 production outcome/failure-phase
  tests across Python and Rust.
- No local Cargo build, check, or test command was run.

### ACL TC-Unified Datapath Batch 6 Evidence State

| IDs | Evidence state |
| --- | --- |
| `ACL-055` | **Likely fixed; privileged runtime evidence pending.** Final hardening commit `89b81e94ac7a6aaaf98295132a9b09d556b99796` keeps XDP ACL/CT-neutral, rejects CT entries that were created before ACL evaluation when ACL becomes active, requires exact dual TCX identity before reusing pinned runtime, propagates global-config read failures, and quiesces every managed/system failure path. The guarded standalone smoke now preserves bpffs across healthy and incomplete restarts instead of proving only a cold rebuild. Complete Build [29297316622](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/29297316622) passed Python stages, targeted Rust contracts, nightly eBPF, static userspace/agent builds, and binary verification. Do not mark fixed until preserved `result=pass` summaries exist for privileged `MODE=system`, `MODE=tap`, and managed Neutron execution. |
| `ACL-056` | **Open P1.** Fragment-safe ACL/CT semantics are intentionally excluded from Batch 6 and require a separate design. |

## 2026-07-08 Full Review Refresh

The 2026-07-08 full-code review confirmed that the highest-risk findings are
already represented by existing backlog IDs. No new ACL/RPC feature work should
be added while closing this list.

Confirmed still open (as of 2026-07-08; see deep-dive refresh below for
superseding notes):

- `REVIEW-ACL-001`: `default_action=deny` is accepted by Neutron API/legacy CLI
  but rejected by the Rust datapath translator.
- `REVIEW-ACL-009`: ACL rule API/CLI still accept fields outside the current MVP
  translator contract, including source-port matching and IPv6 inputs.
- `REVIEW-ACL-012`: the Kolla agent egg installer still copies the egg into
  `site-packages` without a clean setuptools/easy-install path update.
- `REVIEW-ACL-003`: Neutron DB address-set row/member updates are still split
  across transactions.
- `REVIEW-ACL-006`: aria_acl repository errors still lack a legacy-Neutron-safe
  HTTP error mapping layer.
- `REVIEW-ACL-018`: root `install.sh` still fails `bash -n` because of CRLF
  line endings.
- `REVIEW-ACL-010`: DB CRUD smoke still uses `ADMIN_RC_FILE` without defining a
  default value.
- `REVIEW-ACL-014`: GitHub workflow still grants `contents: write` globally.

Review note:

- P3 port-scoped apply was reviewed for false-success commits. Current Python
  and Rust paths check per-port errors plus generation/hash convergence, so no
  new bug ID is recorded for that path in this pass.

## 2026-07-10 Deep-Dive Bug Hunt

A second source-verified pass re-checked Plan 12 IDs and hunted for additional
transaction, ACL compile, and agent-status defects. No code fixes were applied
in this pass; findings are recorded only.

### Backlog status refresh

| ID | Refresh | Note |
| --- | --- | --- |
| `REVIEW-ACL-001` | still open | Confirmed: extension accepts `default_action`; Rust `translate_neutron_acl` rejects non-allow. |
| `REVIEW-ACL-009` | still open | Confirmed: API/CLI lack MVP field validation; Rust rejects IPv6; EffectiveAcl can still mark ready. |
| `REVIEW-OPS-019` | still open | Confirmed: Neutron WAL append-only, no compact/rotate. |
| `REVIEW-ACL-002` | still open | Confirmed: DB accepts duplicate bindings/priorities; compile later degrades. |
| `REVIEW-ACL-003` | still open | Confirmed: `update_address_set` calls `_update` then `_replace_members` in separate transactions. |
| `REVIEW-ACL-006` | still open | Confirmed: repository exceptions lack Neutron HTTP mapping. |
| `REVIEW-ACL-007` | still open | Confirmed: first-install agent egg backup still has no `.none` marker. |
| `REVIEW-ACL-008` | still open | Confirmed: `mark_degraded()` retains stale `last_port_statuses`. |
| `REVIEW-ACL-012` | verification needed | `install_neutron_aria_agent_egg.sh` now calls `refresh_easy_install_pth`; no active source defect is confirmed. Retain until a clean-container smoke proves import/entrypoint without prior path state. First-install rollback remains `REVIEW-ACL-007`. |
| `REVIEW-ACL-018` | fixed | Current tracked `install.sh` is LF-only and `bash -n install.sh` passes. The missing regression gate belongs under CI verification debt rather than keeping this implementation bug open. |

### New confirmed bugs

- `REVIEW-TXN-021`: HTTP snapshot submit advances `accepted_generation` and
  returns `"accepted"` before WAL intent is durable.
- `REVIEW-TXN-022`: runtime ACL apply can succeed and then WAL commit can fail,
  leaving eBPF updated while in-memory/status/WAL stay on the old generation.
- `REVIEW-ACL-023`: snapshot detach / port delete ignore `purge_neutron_acl`
  failures and still report `ok`.
- `REVIEW-TXN-024`: background apply failure only flips in-memory
  `authority_state=degraded`; no WAL record and pending generation can wedge
  later submits.
- `REVIEW-ACL-025`: managed and standalone publishers could switch the active
  ACL bank before final-state compact. Synchronous compact failures had
  immediate compensation, but process exit in the switch-before-durable
  window could leave a new pinned bank with old disk state.
- `REVIEW-ACL-026`: `replace_owned_acl` CIDR add/delete loops can fail mid-flight
  with no kernel rollback.
- `REVIEW-OPS-027`: Neutron WAL replay breaks on I/O read errors and skips later
  valid commits.
- `REVIEW-ACL-028`: Python `delete_port` commits local projection without
  validating the UDS apply outcome or refreshing runtime port statuses.
- `REVIEW-ACL-029`: empty address-set members compile as `ACL_READY` / `enforce`.
- `REVIEW-ACL-030`: disabled address sets are still expanded during effective ACL
  compile.
- `REVIEW-ACL-031`: plugin `get_aria_acl_effective_for_port` hardcodes
  `eligible=True`.
- `REVIEW-ACL-032`: ACL mutation RPC notify failures are swallowed; notifier may
  be a no-op.
- `REVIEW-ACL-033`: `CompositeStatusReporter` can succeed on heartbeat and fail
  on port-status writes, splitting northbound views.
- `REVIEW-OPS-034`: port-scoped `capabilities()` permanently shrinks the shared
  UDS client timeout via `min()`.

## 2026-07-10 Deep-Dive Pass 2 (Round 1 of 3)

Record-only. Focus: Rust recovery / hash-skip / post-commit RAM assign, and
Python pending WAL vs port-scoped apply.

### New confirmed bugs

- `REVIEW-ACL-035`: After datapath restart, committed ACL hashes can skip
  re-apply while kernel ACL maps are empty, leaving status `ready`/`enforce`
  with no enforcement.
- `REVIEW-TXN-025`: WAL commit can succeed while a post-commit fault prevents
  assigning `next_runtime` in memory; status lies and recover-pending can
  regress WAL over a newer commit.
- `REVIEW-TXN-026`: Startup WAL recovery runs unlocked against accept-phase
  writes and can overwrite concurrent `accepted`/`pending` runtime state.
- `REVIEW-ACL-036`: Port-scoped apply does not recover/guard unresolved pending
  and can silently overwrite durable Python pending WAL from a prior full
  resync.
- `REVIEW-ACL-037`: Failed port-scoped apply leaves durable pending while
  `runtime_status` stays `ready` (no degrade / no pending clear).

## 2026-07-10 Deep-Dive Pass 2 (Round 2 of 3)

Record-only. Focus: Python RPC/client/DB/CLI and Rust eBPF scrub / authority /
translator / delete commit.

### New confirmed bugs

- `REVIEW-ACL-038`: Neutron port-list pagination can infinite-loop on repeating
  `next` markers (ACL list path already guards; port path does not).
- `REVIEW-ACL-039`: Config can set `managed_domains` including `qos` while the
  production snapshot builder never supplies a QoS payload.
- `REVIEW-ACL-040`: DB `upsert_port_status` checks existence outside the write
  transaction (TOCTOU insert race on `(port_id, host)`).
- `REVIEW-ACL-041`: Legacy CLI address-set update with `--member` replaces the
  full member list and can wipe prior members.
- `REVIEW-ACL-042`: `delete_address_set` purges members and deletes the parent
  row in separate transactions.
- `REVIEW-ACL-043`: `_require()` treats `priority=0` as missing via falsy check.
- `REVIEW-ACL-044`: Metadata-only ACL reconcile still flips `acl_active_bank`
  then returns without instance WAL/state persist.
- `REVIEW-ACL-045`: Orphan runtime reconcile removes link pins only and skips
  `scrub_managed_runtime_state` / detach.
- `REVIEW-ACL-046`: Local group CIDR writes only block `neutron:*` names, so
  other group names bypass Neutron ACL authority on managed ports.
- `REVIEW-ACL-047`: Neutron rule `priority` is present on the DTO but ignored by
  `translate_neutron_acl` / eBPF match order.
- `REVIEW-TXN-027`: Port delete can return `detached: true` after successful
  detach while WAL delete-commit fails, leaving kernel/WAL split.

## 2026-07-10 Deep-Dive Pass 2 (Round 3 of 3)

Record-only. Focus: deploy/CI/contract advertisement, status projection lies,
managed_domains wedge, conntrack foundation, eBPF CT flush/stateful.

### New confirmed bugs

- `REVIEW-ACL-048`: Port-status projection overwrites UDS `effective_action=bypass`
  with snapshot `enforce` when ACL metadata is enabled.
- `REVIEW-ACL-049`: Any non-`attach|acl` entry in `managed_domains` blocks ACL
  reconcile via `blocked_by_unimplemented_domains` (hard wedge).
- `REVIEW-ACL-050`: Neutron ACL reconcile enables ACL without verifying
  conntrack foundation; loopback can disable CT when not in managed_domains.
- `REVIEW-ACL-051`: WAL intent recovery marks `qos`/`mirror` as recovered/`ok`
  with `*_no_runtime_executor` instead of failing.
- `REVIEW-ACL-052`: Failed domain update leaves the port attached with prior
  mirror/tcprt/local state; no scrub on update-error path.
- `REVIEW-ACL-053`: Neutron ACL `ct_flush` returns success when CT maps fail to
  open, leaving XDP CT fast-path entries after rule changes.
- `REVIEW-ACL-054`: `NeutronAclSnapshot.stateful` is ignored; `stateful=false`
  still uses XDP CT create/fast-path.
- `REVIEW-DOC-021`: Capabilities/UDS contract advertise unimplemented domains
  (`qos`/`mirror`/…) while reconcile only implements `attach`+`acl`.
- `REVIEW-OPS-035`: Transaction-state smoke defaults `MIN_MANAGED_PORTS=0` and
  can pass while skipping delete/migration WAL checks.
- `REVIEW-CI-001`: Stage-2/3 CI gates are largely marker/substring checks and
  omit several high-value unit modules.

## 2026-07-10 Readiness, Security, and Engineering-Debt Audit

Classification rule:

- A deterministic implementation defect, resource leak, or code/document
  contract mismatch receives a `REVIEW-*` bug ID.
- A design that is safe only while an explicit deployment or product boundary
  is preserved receives a `RISK-*` ID. It is not called a runtime bug unless
  that boundary is violated by the shipped deployment.
- Maintainability, CI breadth, release metadata, and repository hygiene gaps
  receive a `DEBT-*` ID unless they already cause a concrete failure.

New confirmed bugs:

- `REVIEW-OPS-019`: the Neutron snapshot WAL is append-only and replays the
  complete history. Snapshot/delete commits include full `NeutronWalState`, but
  the implementation has no checkpoint, compaction, truncation, or rotation
  path. Long-running resync traffic therefore produces deterministic unbounded
  WAL growth and progressively more expensive startup replay.
- `REVIEW-DOC-020`: `05-domain-status-heartbeat.md` still says rich Rust domain
  fields such as `effective_action` are planned, while the Rust status DTO and
  Python heartbeat projection already implement that field. The detail plan
  can mislead implementation and acceptance reviews about the current contract.

Existing bug/risk IDs reused instead of duplicated:

- `REVIEW-ACL-014` already tracks workflow-wide `contents: write` permission.
- `REVIEW-ACL-011` already tracks public-release environment and identity
  scrubbing.

### Tracked Risks and Engineering Debt

| ID | Priority | Class | Status | Finding and classification | Required closure |
| --- | --- | --- | --- | --- | --- |
| RISK-READY-001 | high | readiness boundary | fixed; source, CI, composite baseline, and target negative-state field proof complete | Commit `9060a77` adds UDS-only `GET /readyz` without changing TCP `/api/v1/health` liveness. `/readyz` and `/api/v1/neutron/status` build the same Status V1 response; exact `ready` maps to HTTP 200 and non-ready states map to HTTP 503. The maintained composite smoke additionally requires the matching Neutron agent heartbeat to be alive. Two available test computes passed the ready baseline and heartbeat composition. A target-kernel isolated datapath then proved `pending/unknown/poll`, `blocked/blocked/recover_pending`, and post-rollback `recovery/degraded/full_resync`; every non-ready case returned HTTP 503 with a body identical to Status V1. | RED `7447e4e` / Build [30707303054](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/30707303054) and GREEN `9060a77` / Build [30707571086](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/30707571086) cover strict source behavior and warning-denied builds. Field evidence is recorded in `docs/evidence/openstack-n05-lite/20260810-ready001-composite-readiness/summary.md` and `docs/evidence/openstack-n05-lite/20260811-ready001-negative-states/summary.md`. The isolated run used private socket, state, pin, and container identities; cleanup left no residue, production datapath and OVS process identities were unchanged, and a 202-packet VM canary had zero loss. Probe failure remains observation only and must never restart OVS, OVS-agent, or the datapath. |
| RISK-SEC-001 | high | UDS authentication | fixed for the declared two-compute topology | The generic bootstrap config remains audit-only because numeric identities are site-local. The Kolla-host installer discovers the running Neutron agent UID/GID, renders one exact enforced allow-list, atomically updates the mounted config, tightens `/run/aria` and the socket, validates allowed and denied peers plus audit records, and preserves rollback preimages. Healthy repeat apply is read-only and does not restart the datapath. | TDD and field validation found and fixed a Bash conditional-error propagation defect and a stale-socket restart race. Every admitted compute passed exact config, peer allow/deny, audit, composite readiness, and zero-lag checks. One compute passed apply/rollback/reapply with a 55/55 zero-loss VM canary and unchanged OVS-agent uptime; the other proved idempotent zero-restart apply. Fast contracts passed 584 tests with 8 skips, and the generated bundle includes the installer. A recovered or replacement compute must independently run `apply` plus `check`; numeric identity must never be copied from another host. See `docs/evidence/openstack-n05-lite/20260810-risk-sec-001-peercred-profile/summary.md`. |
| RISK-SEC-002 | high | privileged management API | fixed | `aria-agent` still runs as root and its TCP management router remains unauthenticated, but startup now parses `listen_addr` once as a literal IP socket and defaults to accepting only IPv4/IPv6 loopback. Hostnames, wildcard, private, public, link-local, multicast, and mapped addresses fail closed unless a valid non-loopback socket is paired with the deliberately named `allow_unauthenticated_non_loopback=true` escape hatch. That unsafe state emits an explicit warning, and Tokio binds only the validated `SocketAddr`. Packaged/install configurations keep loopback plus an explicit false override. | RED `4316b62` / Build [30706588907](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/30706588907) failed on the missing field/method. GREEN `ca5cb88` / exact-head Build [30706732514](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/30706732514) executed all five listener tests and passed fast/database/install contracts, selected Rust behavior, and warning-denied eBPF/userspace/static builds. This closes accidental exposure, not HTTP authentication; no privileged field evidence applies or is claimed. |
| RISK-BOUNDARY-001 | high | ACL failure semantics | fixed; source, CI, and two-available-host field proof complete | ACL degraded/not-requested paths intentionally use `effective_action=bypass` so OVS forwarding continues. This is availability-first behavior, not a code bug, but becomes a security defect if operators or northbound consumers interpret Aria ACL as fail-closed enforcement or Security Group replacement. | The read-only `neutron_aria_acl_enforcement_gap_smoke.sh` now joins enabled desired state, current port host ownership, and exact non-stale runtime identity. The stage-two acceptance smoke invokes it; exit `2` emits one actionable alert per expected port that is not `ready/enforce`, while no binding and unbound ports do not page. Runbook and Status V1 detail define the boundary. Two available hosts passed catalog/API baselines; a live test port passed ready, deliberate degraded/bypass alert, recovery, and cleanup with zero packet loss and no service restart. Evidence: `docs/evidence/openstack-n05-lite/20260810-risk-boundary-001-enforcement-gap/summary.md`. |
| RISK-ENV-001 | high | Neutron API/DB view during topology change | fixed for the declared topology; node re-admission gate retained | During the 2026-08-07 low-impact continuation, the clustered API intermittently returned one already-cleaned synthetic policy while a former compute was under recovery. That compute is no longer part of the declared topology or an admitted backend. On 2026-08-12 the active local and virtual endpoints passed five local-create/virtual-read-delete and five virtual-create/local-read-delete transactions, including dual 404 checks after every delete. | The stale result did not reproduce on the active topology; cleanup left no correlated objects and both VM canaries passed. A recovered or replacement backend remains excluded until direct-versus-virtual create/read/delete consistency and database synchronization pass before rotation. See `docs/evidence/openstack-n05-lite/20260812-current-topology-api-db-consistency/summary.md`. |
| REVIEW-ACL-032 | medium | RPC delivery and observability | reclassified-risk | RPC notify failure or notifier initialization fallback can delay ACL convergence until periodic full resync. Periodic full resync is the documented lost-RPC/drift fallback, so this is not a correctness bug while that fallback and its latency objective remain enabled; silent no-op initialization is still an observability risk. | Alert or expose status when the notifier falls back to no-op, test periodic recovery, and define the maximum acceptable convergence delay. Reopen as a bug only if production disables or violates the fallback contract. |
| DEBT-MAINT-001 | medium | source modularity | open | `agent/src/neutron_api.rs` is about 5.4k lines and `agent/src/control_plane.rs` about 3.4k lines. Snapshot transactions, ACL translation, status projection, recovery, and control-plane mutation are concentrated in large modules. This is maintainability and review-risk debt, not a reproduced behavior bug. | Split along existing contract boundaries without changing behavior: snapshot transaction/recovery, ACL translator/executor, status projection, and domain authority. Preserve focused contract tests during extraction. |
| DEBT-CI-001 | medium | verification breadth | open | CI runs Python/stage gates, selected Rust Neutron tests, eBPF and static builds, but has no full Rust workspace test job and no dedicated clippy, rustfmt, Python linter, or shellcheck gate. | Add separate CI jobs for full workspace tests and static analysis; keep the existing targeted gates for fast contract feedback. Follow the repository rule that Rust compilation remains in GitHub Actions rather than local development runs. |
| DEBT-ACL-001 | medium | legacy local ACL durability | open; source implementation and hosted CI complete; privileged field evidence deferred | The policy subset is covered by the strict standalone final-state publication delivered under `REVIEW-ACL-057`. Production commit `2ed4a52` now routes ordinary unreferenced group add/delete through a concrete strict transaction: it builds final state before publication, captures exact preimages for the general and active compatibility-ACL source/destination maps, compensates receipts in reverse, strictly persists, restores memory/durable/allocator/map state on clean failure, and quiesces recovery-required state if compensation fails. Exact-head Build [30378197930](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/30378197930) passed the seven unchanged GREEN behaviors plus warning-denied Rust/eBPF/static builds. | Keep the debt open: no privileged host is available to verify the four-map preimage/compensation path against real pinned maps. Record that evidence as `deferred/pending`, never passed. Do not enter the following P2 batch as part of this closure. |
| RISK-CI-001 | medium | workflow supply chain | open; Node 20 warning removed for checkout/cache | Commit `158d060` replaced all five `actions/checkout@v4` and both `actions/cache@v4` uses with reviewed immutable Node 24 action SHAs. Build [30377280395](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/30377280395) ran the new actions without the prior GitHub Actions Node.js 20 deprecation annotation; its `rust-behavior` failure was the independently expected `DEBT-ACL-001` RED state, while `fast-contracts` and `rust-build` passed. `REVIEW-ACL-014` later closed the independent token-permission defect and pinned the new download plus existing release actions to Node 24 SHAs, but other workflow actions still use mutable tags. | Pin the remaining third-party actions to reviewed immutable SHAs and use automated, reviewed dependency updates. Do not reopen the separately fixed workflow-token boundary unless write permission escapes the tag-only release job. |
| DEBT-RELEASE-001 | medium | release metadata and licensing | fixed | Root `VERSION` is the product release authority, the MIT `LICENSE` and changelog are present, placeholder author metadata is removed, and CI now verifies release manifests, checksums, support bounds, reproducibility, and tag/version agreement. Rust and Python remain separately reported `0.1.0` component compatibility versions by design. | Closed by P6-1 RC delivery governance. Formal tag and registry promotion now depend on the remaining P6 preflight and explicit release authorization, not a retired compute. |
| DEBT-REPO-001 | medium | repository and evidence hygiene | open | The repository tracks generated HTML/ZIP output, a roughly 4.6 MiB latest-build binary archive, and extensive field evidence containing environment hostnames and internal addresses. The current shared Git object store is roughly 211 MiB. This is repository/disclosure debt, not a runtime bug. | Move generated binaries and presentation bundles to CI artifacts/releases, retain only durable evidence summaries where possible, define evidence retention/redaction rules, and reuse `REVIEW-ACL-011` for public identifier scrubbing. |

## 2026-08-13 Full-Code Bug-Hunt Review

Five independent reviewers read every Rust workspace source file (ebpf,
core, agent, api, abi) and the full Python adapter under the no-local-Cargo
policy, then every finding above LOW was re-verified against the exact code
by a second pass before recording. Cross-crate ABI layouts, LPM trie key
projection, CT key construction, bank-switch staging, lock ordering, and
handler panic surfaces were checked and found sound. The confirmed findings
were registered as `REVIEW-ACL-075`..`REVIEW-ACL-099`,
`REVIEW-TXN-031`..`REVIEW-TXN-035`, and `REVIEW-OPS-038`..`REVIEW-OPS-040`
with status `open`.

Claims evaluated and rejected after code verification:

- Standalone bitmap-cleanup retry deleting active-bank port sets after a
  durable-commit/bank-switch crash window: rejected. `system_start` scrubs
  the full standalone runtime and replays the durable snapshot under the
  lifecycle lock before `register_system_instance`, resetting the active
  bank to PRIMARY and rewriting only committed port sets, so the retry runs
  only after the kernel state matches durable state.
- Raw `ValueError` escaping from truncated non-contract 2xx UDS bodies:
  rejected. The read path wraps non-`LocalApiError` exceptions in
  `LocalApiTransportError` inside the enclosing handler.

Claims recorded with reduced scope after verification:

- `REVIEW-ACL-082`: the check/delete split is real for `delete_policy` only;
  `delete_address_set` is already single-transaction (but still unlocked),
  and the orphaned-reference outcome surfaces as `degraded/bypass`, not a
  fully silent pass.
- `REVIEW-ACL-084`: the no-rollback branch is real, but the end-to-end
  409/400-turns-into-500 consequence was not traced beyond the repository
  layer and is recorded as the mechanism only.
- `REVIEW-ACL-085`: the remaining batch updates are dropped, but a degraded
  flag IS surfaced in the heartbeat; convergence relies on the periodic
  resync, so the loss is not silent.

## 2026-08-13 Independent Re-Verification Correction

A second independent pass re-checked every recorded row against the source.
Corrections applied to the register:

- Withdrawn: `REVIEW-ACL-081` (XDP/DDoS is outside the Neutron-managed domain
  set by design), `REVIEW-ACL-092` (feature-ready history is contract-defined
  evidence), `REVIEW-ACL-095` (SSL applies through the host-global path and
  is not dropped).
- Reclassified: `REVIEW-ACL-088` as defensive API debt (production callers
  are preimage-protected).
- Merged: `REVIEW-ACL-087` into `REVIEW-ACL-075` (same root cause, detailed
  consequence).
- Narrowed: `REVIEW-ACL-075` (ext-header overflow = substantive bypass;
  truncated first fragment = asymmetric pass/DoS, not a full-connection
  bypass), `REVIEW-ACL-078`, `REVIEW-ACL-080`, `REVIEW-ACL-086` (UAF
  consequence requires target-kernel verification), `REVIEW-ACL-091`,
  `REVIEW-ACL-098` (recorded fix suggestion was invalid: the fallback mapper
  also defaults fragment reasons to ACL), `REVIEW-TXN-033` (do NOT truncate
  the WAL before the snapshot rename; correct direction is checkpoint/epoch
  or strict replay idempotency).
- Conditional: `REVIEW-ACL-083` (fallback reachability unproven),
  `REVIEW-ACL-084` (transaction-ownership model), `REVIEW-TXN-035` (must
  model the restart ACL invalidation step).
- Corrected the P1 count from eight to seven.

## REVIEW Item Register

This register retains all 118 stable `REVIEW-*` IDs. Use the `Status` column,
not the ID prefix, to decide whether an item is an active defect, fixed,
verification-only, risk-classified, or closed.

| ID | Severity | Area | Status | Finding | Required fix |
| --- | --- | --- | --- | --- | --- |
| REVIEW-ACL-001 | P1 | ACL API/CLI/datapath contract | fixed | Neutron API and legacy CLI allow `default_action=deny`, but the Rust Neutron ACL translator rejects non-allow defaults. A user can create a policy that looks valid and later gets degraded/bypassed during apply. | For MVP, reject `default_action=deny` in server-side validation and CLI help/choices, or mark it explicitly unsupported until datapath default-deny support is implemented. Add API, CLI, and translator contract tests. |
| REVIEW-ACL-002 | P2 | ACL desired-state validation | fixed | Server-side create/update accepts multiple enabled bindings for the same `(target_type, target_id)` and duplicate rule priorities inside a policy/direction. Effective ACL later degrades to bypass. | Reject conflicting enabled binding writes with 409/validation error. Reject duplicate enabled rule priority per `(policy_id, direction)`. Add repository/plugin tests for create and update paths. |
| REVIEW-ACL-003 | P2 | ACL DB transactionality | fixed | Neutron DB address-set create/update now run under one outer write transaction; nested row and member helpers join that transaction, so a member-write failure restores the complete parent/member preimage. Delete is covered separately by `REVIEW-ACL-042`. | The production boundary was delivered incidentally by `bad6731`. Commit `ff6cc1f` adds real SQLAlchemy failure injection for create and update: temporarily removing the outer transactions makes both tests fail with partial state, while exact-head Build [30696458677](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/30696458677) passes all database contracts. No privileged field evidence applies. |
| REVIEW-ACL-004 | P3 | Port runtime status API/CLI | fixed | Every status row now exposes a versioned URL-safe ID derived from `(port_id, host)`. Exact show/update/delete use that pair; legacy single-host show remains compatible, multi-host legacy show returns 409, and legacy delete retains its documented all-host behavior. | Delivered by `9ba57c1`, `f333169`, and `22463ed`. Exact-head Build [30644674860](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/30644674860) passed repository/plugin/CLI identity tests. Target Neutron 9/Python 2 field evidence remains deferred/pending. |
| REVIEW-ACL-005 | P3 | Legacy neutron CLI test coverage | fixed | The fallback parser/client harness now runs unconditionally in fast-contracts and covers request bodies, real list option shape, the python-neutronclient 6.0 `list_ext` signature, and derived status IDs. | Commit `f9da01e`; exact-head Build [30644674860](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/30644674860) passed all 9 CLI contracts. A local compatibility run against python-neutronclient 6.0.0 also passed; target Python 2 smoke remains deferred/pending. |
| REVIEW-ACL-006 | P2 | Neutron REST error semantics | fixed | Repository failures such as `AriaAclValidationError` and `AriaAclNotFound` are plain Python exceptions. The service plugin passes them through directly, so old Neutron controllers can expose invalid requests or missing resources as HTTP 500 instead of 400/404. | Add a legacy-Neutron-compatible exception mapping layer in the plugin or exception classes. Cover missing policy, invalid binding target type, duplicate/unsupported writes, and missing object show/delete with API-level tests. |
| REVIEW-ACL-007 | P2 | Kolla package rollback | fixed | First-time agent installation now records a timestamped `.none` marker behind the same `latest.bak` link used for real backups. Rollback resolves the marker transaction: a `.bak` target restores and smokes the previous egg, while a `.none` target removes the newly installed egg and its `easy-install.pth` entry. | RED commit `f7cd8cd` exercised the public installer against a disposable fake container and failed because the first install created no marker; Build [30697430555](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/30697430555) reproduced that contract failure and was cancelled after the RED evidence was captured. GREEN commit `e86df74` passed the same first-install install/rollback smoke, all fast/database contracts, selected Rust behaviors, and warning-denied eBPF/userspace/agent builds in exact-head Build [30697466610](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/30697466610). That mocked transaction did not by itself close `REVIEW-ACL-012`; the later real Python 2.7 clean-container lane now supplies the missing evidence. |
| REVIEW-ACL-008 | P3 | Port status consistency | fixed | Commit `2bd1726` makes global degradation transform every cached top-level and managed-domain row to `degraded/bypass` with the global reason while preserving identity fields, then recomputes counts and reasons. Stale `ready/enforce` rows can no longer be republished under a degraded heartbeat. | RED `c847761` contributed the intended failures in Build [30615481157](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/30615481157). GREEN Build [30615746741](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/30615746741) passed 176 targeted Python tests and the complete 515-test fast-contract path; combined exact-head Build [30616520693](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/30616520693) remained GREEN. No privileged field evidence applies. |
| REVIEW-ACL-009 | P1 | ACL rule API/datapath contract | fixed | The API/CLI accept rule fields that the Rust translator does not support yet, including source-port matching, IPv6 ethertype/CIDRs, and unvalidated protocol/action values. `EffectiveAclIndex` can mark such rules `ready/enforce`, but datapath apply later fails and the port falls back to degraded/bypass. | Add server-side and CLI validation for the current MVP-supported rule subset, and make `EffectiveAclIndex` return degraded/unsupported before submit for unsupported fields. Cover source-port, IPv6, unknown protocol, unknown action, and bad port range cases. |
| REVIEW-ACL-010 | P3 | Stage-two smoke reliability | fixed | The DB/REST CRUD smoke now resolves one adminrc path: an explicit readable `ADMIN_RC_FILE` wins; otherwise it preserves the existing `/root/adminrc`, then `/etc/kolla/.adminrc` fallback order. The exact resolved file is both sourced on the host and passed to the OpenStack client container, so an unset variable or split credentials path cannot abort or misdirect the token check. | RED commit `97a49cc` and Build [30698677693](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/30698677693) proved that the old public smoke ignored a valid custom adminrc and failed before reaching the token boundary; the run was cancelled after fast-contracts captured RED. GREEN commit `d079ec1` passed the executable source/forward-path contract, all fast/database contracts, selected Rust behaviors, and warning-denied eBPF/userspace/agent builds in exact-head Build [30698743828](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/30698743828). This closes the shell routing defect without claiming a new privileged DB/REST field run. |
| REVIEW-ACL-011 | P3 | Public release hygiene | fixed | Current tracked path names/content and generated payloads now share one encoded, path/archive-aware identifier policy. Deterministic aliases preserve field-evidence semantics and canonical public provenance URLs. | RED `6ed8abc` / Build [30811086605](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/30811086605) proved the old policy gaps. GREEN `af6accb` / exact-head Build [30811728869](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/30811728869) passed fast/database/install contracts, Rust behavior, and warning-denied eBPF/userspace/static builds. Git history was deliberately not rewritten, no privileged field run applies or is claimed, and `DEBT-REPO-001` remains separate. |
| REVIEW-ACL-012 | P1 | Kolla agent package install | fixed | The real clean-container test disproved the earlier “verification only” classification: after copying the egg and creating `easy-install.pth`, Python imports succeeded but the first install exited 127 because no `neutron-aria-agent` console script existed. The installer now creates a deterministic Python entrypoint, records its independent `.bak`/`.none` preimage with the egg transaction, and restores or removes it during rollback. | RED `59d1f7b` / Build [30702727302](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/30702727302) reached `agent_imports=ok` in an empty official Python 2.7 container and then failed the missing entrypoint with exit 127. GREEN `b1015ce` / exact-head Build [30702872608](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/30702872608) passed the independent clean-install lane, first-install and upgrade rollback contracts, fast/database contracts, Rust behavior, and warning-denied Rust/eBPF/static builds. No privileged datapath evidence applies. |
| REVIEW-ACL-013 | P3 | Neutron port extension projection | fixed and field-verified on the declared two-compute topology | Commit `133b52b` installs a batch-aware legacy `get_port`/`get_ports` projection. It computes desired fields from one effective snapshot, queries runtime rows once for the returned port IDs, accepts only the current `(port_id, binding:host_id)` plus current policy/binding identity, maps fresh `ready` to legacy `applied`, and makes stale/missing/mismatched evidence conservative. Projection failure returns a complete unknown summary without failing the native port read. Hosted Builds `30703680367`, `30703735814`, and `30703793706` passed source, CLI, and Python 2.7 contracts. | On 2026-08-12 both admitted computes passed real REST/legacy CLI/`neutron port-show` identity checks, `ready/enforce -> applied`, wrong-host isolation, old-binding conservative projection, `degraded/bypass`, cleanup, traffic, and OVS non-interference. Compute A additionally passed 90-second stale projection and Python-agent recovery without restarting Rust or OVS. See `docs/evidence/openstack-n05-lite/20260812-acl013-two-compute-port-projection/summary.md`. |
| REVIEW-ACL-014 | P3 | GitHub release permissions | fixed | The Build workflow now defaults to `contents: read`. Compilation and Actions artifact upload remain in `rust-build`; a separate job depending on that build is restricted to `push` events for `refs/tags/v*` and is the only location granted `contents: write`. It downloads the already-built artifacts and creates the GitHub Release. Both artifact download and release actions use immutable Node 24 commit SHAs. | RED `2d2ddbd` / Build [30701055296](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/30701055296) failed the new minimum-permission contract on the old workflow and was cancelled after fast-contracts captured the defect. GREEN `2cff9c4` / exact-head Build [30701143632](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/30701143632) passed fast/database contracts, Rust behavior, and warning-denied eBPF/userspace/agent builds; the normal branch run also proved the release job stays skipped. No test tag or GitHub Release was created; artifact handoff will receive its first live execution during the next authorized version-tag release. |
| REVIEW-ACL-015 | P3 | Plugin loader rollback | fixed | Plugin installation now records the exact policy-file preimage: an existing file is retained as a timestamped `.bak`, while a missing file is represented by a timestamped `.none` marker behind the same `policy.json.latest.bak` link. Rollback restores `.bak`, removes the smoke-created policy for `.none`, and rejects an unknown marker instead of guessing. | RED commit `823a275` and Build [30699371375](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/30699371375) reproduced the missing first-install marker after an injected post-policy restart failure; the run was cancelled after fast-contracts captured RED. GREEN commit `1742c9a` passed the executable install/failure/rollback contract, all fast/database contracts, Rust behaviors, and warning-denied eBPF/userspace/agent builds in exact-head Build [30699433259](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/30699433259). This mocked container boundary verifies transaction semantics without claiming a new privileged Kolla-host rollback run. |
| REVIEW-ACL-016 | P2 | Agent config safety | fixed | Boolean config parsing accepted only known true values and treated every other non-empty string as `false`. A typo such as `full_resync_enabled = ture` silently disabled ACL submit and left the agent in heartbeat-only/degraded mode instead of failing fast with a config error. | Fixed in `agent/config.py`: `full_resync_enabled`, `rpc_events_enabled`, and `incremental_rpc_enabled` now use strict boolean parsing and raise `ConfigError` with section/option/value on invalid values. Unit tests cover typo cases. |
| REVIEW-ACL-017 | P3 | Legacy CLI package smoke | fixed | The legacy neutronclient installer now accepts `ADMIN_RC_FILE`, retains `/etc/kolla/.adminrc` as its default, validates that the selected host file is readable before container work, and forwards that exact path to Docker command discovery. A caller-provided credentials path is no longer ignored, and a missing path fails with an actionable error. | RED commit `1224129` and Build [30699715441](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/30699715441) proved that the old public `smoke` entrypoint ignored a valid custom path; the run was cancelled after fast-contracts captured RED. GREEN commit `bffd831` passed custom-path and missing-path contracts, all fast/database contracts, Rust behaviors, and warning-denied eBPF/userspace/agent builds in exact-head Build [30699749054](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/30699749054). This closes the shell routing defect without claiming a new privileged OpenStack-client field run. |
| REVIEW-ACL-018 | P2 | Root install script | fixed | Earlier review found CRLF line endings that broke `bash -n install.sh` on Linux. Current tracked `install.sh` is LF-only and `bash -n install.sh` passes. | Keep the implementation item closed. Track the missing root-installer regression gate under CI verification debt. |
| REVIEW-OPS-019 | P1 | Neutron WAL lifecycle | fixed | RED commit `5c79a28` and Build [`30601218345`](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/30601218345) proved the missing lifecycle interface. GREEN commit `c3d8238` adds synchronous canonical checkpointing at 16 MiB soft, retains the last valid commit plus at most one unresolved intent, refuses uncertain/corrupt replay, installs with file-fsync/rename/directory-fsync ordering, and rejects pre-write when neither current nor compacted state can fit below 64 MiB. Exact-head Build [`30601633217`](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/30601633217) passed 47 focused WAL behaviors and warning-denied Rust/eBPF/static builds. | Fixed. No privileged field evidence is applicable to this filesystem-only lifecycle repair. |
| REVIEW-DOC-020 | P3 | Domain status documentation | fixed | The former detail plan described `effective_action`, `support_disposition`, and the richer Rust domain DTO as future work even though Status V1, strict Python decoding, heartbeat aggregation, and ACL port-status projection were already implemented. Commit `b470f2f` replaces that stale plan with the current versioned contract, distinguishes legacy adaptation and `REVIEW-ACL-013` port-show work, and updates the detail index. | RED `0cf0835` / Build [30702240495](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/30702240495) made `fast-contracts` reject the obsolete planned-contract claims. GREEN `b470f2f` / exact-head Build [30702418132](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/30702418132) passed the complete fast-contract and Neutron DB lanes; Rust jobs correctly skipped for the documentation-only implementation commit. No privileged field evidence applies. |
| REVIEW-TXN-021 | P1 | Snapshot accept before WAL | fixed | Historical finding: snapshot admission returned accepted semantics before durable intent. Admission now fsyncs intent while holding the apply lock, returns `pending`, and leaves accepted/applied on the committed baseline. | Fixed with durable-intent and WAL-intent-failure Rust regression tests plus the permanent `neutron_snapshot*` CI test gate. |
| REVIEW-TXN-022 | P1 | Apply/commit metadata split | fixed | Historical finding: datapath could mutate before a failed commit while RAM/WAL retained the old classification. Commit failure now restores attach where possible, scrubs ACL to bypass, retains the failed pending generation, and enters blocked recovery. | Fixed with blocked-runtime/background-preservation tests and shared pre-commit/commit-failure recovery. |
| REVIEW-ACL-023 | P2 | Detach/delete ignores ACL purge failure | fixed | Historical finding: snapshot detach and direct port delete could continue after owned-ACL purge failure. Commit `49081c6` routes both through the transactional quiesce/purge boundary: snapshot detach records the port error and does not call `registry.detach`, while direct delete returns `detached=false`. Ordered behavior `neutron_acl_purge_failure_aborts_detach_without_partial_owned_state` proves detach is never attempted after the failed atomic purge. | Source behavior passed `fast-contracts`, `rust-behavior`, and `rust-build` in Build [29672271181](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/29672271181) at `ad30cad`; manually dispatched exact-head closure Build [30610771022](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/30610771022) passed at `98034c1`. A target-kernel isolated direct-snapshot fixture then proved purge failure aborts detach, preserves the complete owned projection, and allows a clean retry while an independent OVS canary had zero gaps. See the 2026-08-06 high-risk field summary. |
| REVIEW-TXN-024 | P2 | Background apply error non-durable | fixed | Historical finding narrowed to the uncovered `neutron.snapshot.after_intent` prefix: the intent was durable and live state was applying, but the fault returned before datapath apply and the outer marker changed only RAM. The concrete handler now commits the complete previous applied baseline plus the exact failed pending generation/hash and `blocked_recovery_required` before publishing RAM. Restart reconstructs the blocked identity and `recover-pending` restores the last applied baseline. If the blocked commit fails, RAM reports `pending_recovery_commit_failed` while the original durable intent remains available for startup recovery. No datapath compensation runs before datapath mutation begins. | RED `b5661c5` failed only on the two missing handler references while independent warning-denied Rust/eBPF build passed in Build [30611148868](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/30611148868). Production `95c440a` passed `neutron_snapshot_after_intent_failure_is_durable_across_restart`, `neutron_snapshot_after_intent_blocked_commit_failure_retains_intent`, all selected Rust behaviors, and warning-denied `rust-build` in exact-head Build [30611534447](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/30611534447). No privileged field evidence applies. |
| REVIEW-ACL-025 | P2 | ACL bank switch before final-state compact | fixed | Historical finding: managed and standalone publishers staged the complete shadow/general projection, then advanced the fragment epoch and switched the active bank before compacting the matching final state. Synchronous compact errors already attempted compensation, but process exit in that ordering window could leave `active_bank=new` with `durable_state=old`. Both concrete publishers now compact the complete final state before epoch/bank publication. Persistence and epoch failures never restore an unpublished bank; an uncertain switch failure restores the old bank before shadow scrub; strict CT rollback remains after publication. | Fixed by RED `7f6ec55` / `89762da` and production `4dca970`. Builds [30609104910](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/30609104910) and [30609535549](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/30609535549) proved the standalone and managed contracts RED while independent Rust/eBPF builds passed. GREEN Build [30609828584](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/30609828584) passed `fast-contracts`, `rust-behavior`, and `rust-build`. This is a hosted ordering/compensation repair; no privileged field evidence applies. |
| REVIEW-ACL-026 | P2 | Partial CIDR kernel writes without rollback | fixed | Historical finding: the old `replace_owned_acl` CIDR loops could exit after a partial general-map mutation. Commit `4160f73` replaced that path with a concrete publication executor that records each shared mutation only after success and passes the exact applied prefix into reverse-order prepublication compensation on general, shadow, TC verification, persistence, epoch, or bank publication failure. ACL-specific CIDRs are staged into the inactive bank and failed shadow staging is scrubbed. | Fixed by RED contract `d4ce7e8` and production `4160f73`. Rust behaviors `managed_general_delta_source_only_failure_restores_preimage`, `managed_general_delta_destination_failure_restores_source_preimage`, `managed_general_delta_shadow_failure_restores_both_preimages`, and `managed_general_delta_general_compensation_failure_attempts_every_preimage` cover the partial-write and best-effort compensation boundaries. Manually dispatched exact-head Build [30610771022](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/30610771022) at `98034c1` passed `fast-contracts`, `rust-behavior`, and warning-denied `rust-build`. No privileged evidence applies to this executor-ordering repair. |
| REVIEW-OPS-027 | P3 | WAL replay aborts on read I/O error | fixed | The finding was narrowed to a record-boundary defect: `BufRead::lines()` reported a non-UTF-8 WAL record as an I/O error, and the shared `break` discarded every later valid commit. Commit `fa1e326` reads newline-delimited records as bytes, skips malformed record contents with a counted `replayed_with_errors` result, and continues to the latest valid commit. A genuine `read_until` I/O failure still stops scanning with `failures > 0`, preserving the existing operator-blocked recovery boundary instead of trusting an unread tail. | RED `ffd520d` / Build [30701699907](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/30701699907) proved the middle non-UTF-8 record stopped replay after one valid commit while the independent truncated-tail contract already passed. GREEN Build [30701829923](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/30701829923) passed all 49 selected WAL behaviors plus warning-denied Rust/eBPF/static builds. No privileged field evidence applies to this filesystem-only replay repair. |
| REVIEW-ACL-028 | P2 | delete_port commits without response validation | fixed | Commit `2bd1726` validates delete mappings, requested identity, empty error, and only the accepted `ok` / idempotent `not_found` / timeout-recovered `deleted` outcomes before projection or durable commit. Invalid responses retain pending delete and the committed projection, mark runtime `pending_delete_unresolved`, and successful deletion removes the cached port row and recomputes summaries. | RED `c847761` proved explicit error and wrong-identity miscommit plus stale cached status in Build [30615481157](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/30615481157). GREEN Builds [30615746741](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/30615746741) and [30616520693](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/30616520693) passed the complete fast-contract path. No privileged field evidence applies. |
| REVIEW-ACL-029 | P2 | Empty address-set compiles as ready | fixed | `EffectiveAclIndex._compile_address_match` accepts address sets whose members list is empty (or only empty addresses) and returns no compile error, so rules can be `ACL_READY`/`enforce` with empty CIDR lists. | Treat empty member sets as degraded/unsupported before submit; cover with effective-ACL unit tests. |
| REVIEW-ACL-030 | P2 | Disabled address-set still expanded | fixed | `_compile_address_match` checks missing address-set IDs but never `_enabled(address_set)`. Disabled sets still expand members into effective rules. | Reject or degrade rules that reference disabled address sets; add unit tests. |
| REVIEW-ACL-031 | P2 | Effective-for-port API hardcodes eligible | fixed | `AriaAclPlugin.get_aria_acl_effective_for_port` always calls `effective_for_port(..., {"eligible": True})`, so non-OVS/non-compute ports can appear ready/enforce from the API even when the agent would mark them unsupported/bypass. | Pass real eligibility (or document API as desired-state-only and return an explicit disposition field). Add plugin tests for ineligible ports. |
| REVIEW-ACL-032 | P2 | ACL RPC notify fallback visibility | reclassified-risk | `_notify_acl_change` logs notifier exceptions after DB success, and notifier initialization can fall back to `NoopAriaAclNotifier`. Agents then converge through the documented periodic full-resync lost-RPC fallback. This is a delivery-latency and observability risk, not a correctness bug while that fallback remains enabled and bounded. | Expose/alert no-op notifier state, test periodic convergence, and define a latency objective. Reopen as a bug if production disables or violates the fallback contract. |
| REVIEW-ACL-033 | P2 | Composite status reporter partial success | fixed | Commit `2bd1726` implements an explicit fail-safe visibility boundary instead of pretending RabbitMQ/SQL atomicity: ready publication writes port rows first and heartbeat last; degraded/not-ready publication closes heartbeat readiness first and then writes conservative rows. First-phase failure suppresses the second phase and remains retryable. | RED `c847761` covered both orderings and partial failures in Build [30615481157](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/30615481157). GREEN Builds [30615746741](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/30615746741) and [30616520693](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/30616520693) passed all fast contracts. No privileged field evidence applies. |
| REVIEW-OPS-034 | P3 | UDS client timeout permanently shrinks | fixed | `LocalClient.timeout` now remains the configured default. Capability validation still rejects invalid `timeout_ms`, while a port-scoped mutation computes `min(configured_timeout, capability_timeout)` and passes it only to that PUT connection. The capability GET and every later unrelated request continue to use the configured default; no negotiated timeout is retained in shared client state. | RED commit `517dbad` and Build [30700167616](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/30700167616) proved the old `5.0s -> 2.5s -> 2.5s` leak; GREEN commit `064e6d3` passed the request-local `5.0s -> 2.5s -> 5.0s` contract, all 549 Python tests, DB contracts, and public smoke/config checks in exact-head Build [30700243216](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/30700243216). Rust jobs correctly skipped because no Rust/eBPF source changed. No privileged field evidence applies to this Python connection-construction defect. |
| REVIEW-ACL-035 | P1 | Restart hash-skip leaves ACL unenforced | fixed | Historical finding narrowed during implementation: attach replays or validates kernel state against the tap-local WAL, but that WAL has no shared commit identity with the Neutron ACL desired hash/status. Successful attach therefore could not prove that a same-hash Neutron ACL skip was safe. Restart reconcile now keeps attach ready, invalidates only the ACL domain hash, reports ACL `degraded` with `effective_action=unchanged`, persists `runtime_reconcile_requires_full_resync`, preserves stronger pending-recovery authority, and publishes the invalidated RAM state even if that WAL append fails. | Fixed with restart invalidation tests covering binding/hash preservation, pending-authority preservation, attach-ready plus ACL-degraded status, same-generation no-op rejection, and same-hash domain skip rejection. |
| REVIEW-TXN-025 | P1 | Post-commit RAM assign skipped | fixed | Historical finding: a post-commit error could skip RAM publication and recover-pending could regress the newer WAL commit. Commit now publishes RAM before the hook, return-error is a warning, and recovery refreshes from a newer valid WAL commit. | Fixed with post-commit finality, stale-RAM anti-regression, and blocked same-hash Python recovery tests. |
| REVIEW-TXN-026 | P2 | Startup recovery races accept path | fixed | Startup recovery, committed-runtime reconcile, snapshot admission, and the prepared background apply now share `apply_lock`. Snapshot admission retains an owned guard through apply; OVS discovery occurs outside the lock but the complete admission identity is revalidated after reacquiring it. The pre-lock pending fast path is read-only and can only deduplicate or reject. | The serialization boundary was delivered by `933d1af` and strengthened by `f6e0f9b`. Commit `d7db9ec` adds a real concurrent behavior proving a prepared snapshot holds the shared barrier and startup reconcile cannot overwrite it before release. Exact-head Build [30696668251](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/30696668251) passed Rust behavior and warning-denied Rust/eBPF builds. No privileged field evidence applies. |
| REVIEW-ACL-036 | P2 | Port-scoped prepare overwrites unresolved pending | fixed | Commit `2bd1726` enforces one unresolved transaction at both durable and in-memory state-store boundaries. A different desired hash, snapshot/delete overlap, or different pending delete is rejected without state mutation; same-hash generation realignment remains available to the existing remote recover/barrier protocol rather than preempting it. | RED `c847761` proved pending overwrite in Build [30615481157](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/30615481157). GREEN Builds [30615746741](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/30615746741) and [30616520693](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/30616520693) passed durable/in-memory and event-loop regressions. No privileged field evidence applies. |
| REVIEW-ACL-037 | P2 | Failed scoped apply leaves ready + dirty pending | fixed | Commit `2bd1726` keeps the exact prepared transaction for recovery but marks submission, response, terminal-status, and finalization failures as `pending_snapshot_unresolved`; the prior ready state is no longer advertised while durable pending exists. Existing transport-timeout recovery and committed projection semantics are preserved. | RED `c847761` proved both response and status false-ready cases in Build [30615481157](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/30615481157). GREEN Builds [30615746741](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/30615746741) and [30616520693](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/30616520693) passed the complete fast-contract path. No privileged field evidence applies. |
| REVIEW-ACL-038 | P2 | Port-list pagination can hang | fixed | `NeutronPortSource` now rejects repeated markers and any response that still advertises a next page at the 10,000-page safety bound, raising `PortSourceUnavailable` before another request. Normal legacy marker pagination remains unchanged. | Fixed in `d42b83d`. RED `76fac59` / Build [30696036575](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/30696036575) failed both missing termination behaviors; GREEN Build [30696145624](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/30696145624) passed the complete fast-contract lane. |
| REVIEW-ACL-039 | P1 | managed_domains qos without payload | fixed | Config allows `managed_domains` including `qos`. Production `SnapshotSynchronizer` passes domains into `PortCandidateBuilder` but never builds/passes `qos_index`, so ports advertise managed `qos` with no `qos` snapshot block while local QoS writes are blocked. | Reject unwired domains in config validation, or wire EffectiveQosIndex before advertising `qos`. Add config/unit guard tests. |
| REVIEW-ACL-040 | P2 | Port-status upsert TOCTOU | fixed | Neutron DB status writes now run under one outer transaction, attempt an atomic update first, and insert under a savepoint only when no row matched. A concurrent primary-key winner is absorbed by rolling back only the savepoint and retrying the update; unrelated integrity failures remain errors. | Fixed in `141cdef`. RED Build [30696036575](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/30696036575) lost both coordinated writers; GREEN Build [30696145624](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/30696145624) passed the concurrent convergence contract. |
| REVIEW-ACL-041 | P2 | CLI address-set update wipes members | fixed | Create retains repeatable `--member`; update now rejects that ambiguous option and exposes repeatable `--replace-member` as an explicit complete-membership replacement. Omitting it preserves members, and the product contract documents the destructive boundary. | Fixed in `11bdff7`. The original parser failed the local RED contract by still exposing `--member`; GREEN Build [30696145624](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/30696145624) passed all 10 maintained CLI contracts. |
| REVIEW-ACL-042 | P2 | delete_address_set split transactions | fixed | Neutron DB address-set deletion now has one outer write transaction covering reference validation, member purge, and parent deletion. Nested helpers cannot independently commit, so a parent-delete failure restores both rows and members. | Fixed in `ecfbea9`. RED Build [30696036575](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/30696036575) reproduced the empty-member residue; GREEN Build [30696145624](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/30696145624) passed the injected rollback contract. This does not claim the separate `REVIEW-ACL-003` create/update path. |
| REVIEW-ACL-043 | P3 | priority=0 rejected as missing | fixed | `_require()` uses falsy `not obj.get(field)`, so rule `priority=0` fails validation while effective compile accepts 0. | Use explicit missing checks for numeric fields; add create/update unit tests for priority 0. |
| REVIEW-ACL-044 | P2 | Metadata-only ACL flips bank without WAL | fixed | Historical finding: metadata-only ACL changes could enter publication even when the compiled group/policy projection was unchanged. Commit `4160f73` computes `semantic_changed` from concrete policy, group-CIDR, group-delete, and released-bitmap deltas; a clean projection with no semantic delta returns `ManagedAclPublicationDecision::Noop` before shadow staging, persistence, fragment epoch advance, or bank switch. Metadata revision still invalidates the outer translation/reconcile cache but cannot publish an unchanged bank. | Fixed by RED contract `d4ce7e8` and production `4160f73`. Rust behaviors `managed_projection_repair_clean_equal_reconcile_is_noop` and `neutron_acl_validation_cache_is_content_safe_and_port_specific` cover the inner no-publication and outer metadata-reconcile boundaries. Manually dispatched exact-head Build [30610771022](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/30610771022) at `98034c1` passed `fast-contracts`, `rust-behavior`, and warning-denied `rust-build`. No privileged field evidence applies. |
| REVIEW-ACL-045 | P2 | Orphan reconcile skips map scrub | fixed | Commit `8242c1b` derives orphan identity from link pins and persisted live-iface markers, subtracts committed siblings, serializes cleanup, scrubs both ACL banks and every tap-scoped runtime family, and releases the retry marker last. Target-kernel RED then found that legacy TC filters are kernel-owned and have no link pin. Commit `b18dd3c` runs the full ownership-verified detach path before map scrub, covering legacy TC without deleting shared map state. Any required failure remains blocked and retains stable identity plus the retry marker for startup retry. | Hosted Build `31154605848` passed the maintained Rust, eBPF, package, and static gates. An isolated target-kernel fixture audited 29 available map families: orphan entries changed 13 to 0, all 13 sibling entries remained, an injected map failure retained the retry marker, and retry completed after repair. Orphan ingress/egress legacy TC filters were absent while sibling filters remained. Private taps and a private bridge were used; production OVS and `br-int` were not mutated. Distinct from `REVIEW-ACL-035`. |
| REVIEW-ACL-046 | P1 | Cross-domain ACL selector isolation | fixed; managed Neutron field-verified on two available computes | Reopened 2026-07-15 with a complete enforcement path. The repair derives ACL maps from final direction-specific rule references, uses a conflict-aware general projection, gates ownership/skip on projection health, and repairs legacy pollution through bank publication plus strict CT invalidation while preserving standalone direct publication for `REVIEW-ACL-057`. The transaction implementation is `49081c6`. Pre-field wiring/hardening commits `d1aa523..ad30cad` cover managed detach ordering, purge-failure atomicity, strict-flush rollback, and successful retry detach; independent final review approved the wiring. Exact-head GitHub Actions run [29672271181](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/29672271181) at `ad30cad` passed `fast-contracts`, `rust-behavior`, and `rust-build`. | A privileged legacy-kernel standalone tap fixture passed on 2026-08-06. On 2026-08-11, real Neutron `aria_acl` policy/rule/binding projection passed exact-CIDR isolation, more-specific-CIDR isolation, injected legacy pollution repair, strict CT invalidation, restart recovery, cleanup, and independent OVS safety checks on both available compute nodes. See `docs/evidence/openstack-n05-lite/20260811-acl046-managed-selector-isolation/summary.md`. The unavailable third compute remains a wider P5 environment constraint, not an ACL-046 semantic gap. |
| REVIEW-ACL-047 | P2 | Translator ignores rule priority | fixed | Numeric priority remains northbound metadata and is not added to eBPF `PolicyKey`. Python preflight and Rust direct-UDS validation now reject priority-dependent CIDR/specificity overlaps with stable reasons; canonical-equivalent CIDR groups are reused. A classified direct-UDS rejection reports real `degraded/bypass` only after the empty owned-ACL transaction succeeds. | Fixed with Python and Rust overlap/canonicalization/outcome regression tests, persistent Stage 1/2 static guards, and the documented priority-independent acceptance boundary. QoS/Mirror are unchanged. Distinct from `REVIEW-ACL-009`. |
| REVIEW-TXN-027 | P2 | Delete detach succeeds / WAL commit fails | fixed | Commit `efb113c` makes post-detach publication delete-specific and forward-only. An after-detach fault or `DeleteCommit` failure now reports `detached:false`, retains the last committed port in live authority, exposes a hashless operator-blocked delete identity, and leaves the exact unmatched `DeleteIntent` durable. Startup recovery performs idempotent attach/scrub/detach and removes the port only after a durable `DeleteCommit`; failed runtime recovery or recovery commit preserves the intent for retry instead of clearing it with snapshot rollback. | RED `7bfb88f` / Build [30612312902](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/30612312902) proved the missing boundaries. Exact-head `f8b72b8` / Build [30612826096](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/30612826096) passed the five delete-forward behaviors, `fast-contracts`, and warning-denied Rust/eBPF build. No WAL schema, UDS API, or snapshot rollback contract changed. Distinct from `REVIEW-ACL-023`. |
| REVIEW-ACL-048 | P1 | Status projection overwrites bypass→enforce | fixed | `_port_statuses_from_status` replaces UDS `effective_action` values of `bypass` (and empty) with snapshot metadata defaulting to `enforce` when `acl_enabled` is true. Northbound `aria_acl_port_statuses` can report enforce while datapath bypassed. | Never overwrite a concrete UDS runtime `effective_action`/`status`; treat UDS as runtime truth. Add unit tests for UDS bypass + snapshot enforce. |
| REVIEW-ACL-049 | P1 | Unwired managed_domains wedge ACL | fixed | Config allows `qos`/`mirror` in `managed_domains`. Rust `reconcile_neutron_domains` treats any domain outside `attach|acl` as unimplemented and marks ACL `blocked` for the whole port. Distinct from `REVIEW-ACL-039` (missing qos payload). | Reject unwired domains at config validation, or implement them; never block ACL solely because another domain is unimplemented. |
| REVIEW-ACL-050 | P2 | ACL enforce without conntrack foundation check | fixed | Historical finding: ACL activation did not bind the required CT mode to the same transaction, and ACL-only authority allowed local CT mutation. Reconcile now atomically quiesces `conntrack=false,acl=false`, replaces policy, strictly clears CT while creation is disabled, and atomically publishes the desired CT plus final ACL flags. `managed_domains=acl` also blocks local conntrack mutation as an internal dependency without advertising a `conntrack` Neutron domain. | Fixed with pure transition tests, ACL-dependency authority tests, stable HTTP 409 error text, Stage 1 static guards, and full Rust/eBPF/static-agent CI. |
| REVIEW-ACL-051 | P2 | WAL recovery false-passes qos/mirror | fixed | Pending-intent recovery marks `qos`/`mirror` as `recovered` with `*_no_runtime_executor` and can still return `ok: true` when those domains were in the intent. | Treat unimplemented recovery domains as degraded/failed; do not report recovered success without an executor/scrub. |
| REVIEW-ACL-052 | P2 | Update-error preserves unmanaged state | closed-not-supported | Attach failure purges/detaches, while update failure records an error and preserves the attached port plus state outside the failed Neutron-managed domain. Preserving unmanaged mirror/tcprt/local state is consistent with selected-domain authority and the availability-first OVS enhancement boundary; the original finding does not demonstrate an invariant violation. ACL partial-write/rollback defects remain tracked by `REVIEW-ACL-025` and `REVIEW-ACL-026`. | Keep closed unless a residual-state test proves that a failed update changes or falsely reports a Neutron-managed domain. Do not scrub unrelated domains or detach solely on this finding. |
| REVIEW-ACL-053 | P1 | Lenient ct_flush hides CT clear failure | fixed | Historical Neutron ACL reconcile used `core::ct_ops::ct_flush`, which returned `Ok(0)` when CT pins could not be opened or converted. Neutron now pre-disables ACL before every replacement, calls a dedicated strict control-plane flush backed by `scrub_ct_tables_strict`, propagates V4/V6 open/convert/iterate/remove failures, and enables non-empty ACL only after clear succeeds. Post-disable failures report `error/bypass`; translation or pre-disable failures report `error/unchanged`. | Fixed with gate-order, strict-method contract, proven effective-action, and missing-pin compatibility tests. The general lenient flush API remains unchanged. |
| REVIEW-ACL-054 | P2 | stateful=false still uses XDP CT fast-path | fixed | Rust now carries `NeutronAclSnapshot.stateful` as per-apply CT intent. Non-empty stateful policy publishes `conntrack=true,acl=true`; non-empty stateless policy publishes `conntrack=false,acl=true`. The existing eBPF per-tap CT guards therefore skip lookup and create for stateless ACL. Empty/bypass publishes ACL off with snapshot CT intent, while a missing ACL payload preserves the prior CT mode. | Fixed with translator intent and atomic runtime-transition tests covering stateful, stateless, empty, and missing-payload paths. |
| REVIEW-ACL-055 | P1 | Split ACL/CT hooks and incomplete all-mode TC recovery | fixed; three-form target-kernel field-verified | The all-mode implementation keeps XDP ACL/CT-neutral and makes TC ingress/egress the only ACL/CT authorities. Target-kernel execution additionally found and fixed legacy-TC link conversion, standalone bank publication, `tap_id=0` CT observability, replay-map identity, incomplete-direction recovery, and execution/API map-set divergence. | Exact runtime artifacts from `7ffc5d6` passed standalone `MODE=system`, standalone `MODE=tap`, and focused Neutron-managed execution. The managed run passed all eight ACL/CT authority checks, admitted zero packets across a controlled datapath restart, and restored its baseline with no cleanup errors. A 30,162-reply independent OVS canary had zero failure markers; OVS and ovs-agent identities were unchanged. See `docs/evidence/openstack-n05-lite/20260811-acl055-all-mode-tc-authority/summary.md`. |
| REVIEW-ACL-056 | P1 | Fragment-safe ACL/CT key semantics | fixed; production activation remains change-controlled | IPv4 non-first fragments are no longer parsed as ports and IPv6 uses the same bounded context contract. First fragments publish bounded address/protocol/ID/tap/direction/VLAN/bank/epoch context before CT creation; later fragments recover the authoritative ports or fail closed. Final review also closed replacement-CT deletion (`REVIEW-ACL-067`) and stale per-CPU identity attribution (`REVIEW-ACL-068`). The guarded field orchestration installs direction-specific UDP/53 policy, covers dual-stack/direction/order, VLAN/tap isolation, publication stale, restart scrub, cleanup, and standalone capacity-8 pressure/oldest-identity eviction. | Hosted RED/GREEN evidence is preserved in the fragment design. A privileged legacy-kernel `MODE=tap` run on 2026-08-06 passed IPv4/IPv6, both directions, ordered and reordered delivery, later-before-first fail-closed behavior, tap/VLAN isolation, epoch invalidation, restart scrub, bounded pressure, oldest-key eviction, and cleanup. See `docs/evidence/openstack-n05-lite/20260806-acl-high-risk-field-acceptance/summary.md`. Shipped production configuration remains disabled at capacity 8192; activation requires a separate rollout decision. `update_failed` remains hosted-only because no safe deterministic LRU field trigger exists. |
| REVIEW-TXN-028 | P1 | Post-apply status false commit | fixed | Python now commits full or scoped projection/state only after terminal status exactly matches `accepted_generation`, `applied_generation`, `desired_hash`, and `applied_desired_hash`, reports `authority_state=ready`, and proves every requested domain ready. Validation failure preserves the prior committed identity and leaves the pending snapshot unresolved. The `safe_full_resync()` path publishes degraded; scoped failure can still leave runtime readiness unchanged and remains separately tracked by `REVIEW-ACL-037`. | Fixed through RED `e593a48` and production commit `8e14944` with strict terminal-identity regressions; exact-head Build [29547730124](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/29547730124) passed. |
| REVIEW-TXN-029 | P1 | Non-authoritative OVS inventory false commit | fixed | Rust treats OVS inventory failure as transaction-level missing authority: the protected pending intent carries the typed `inventory_unavailable` cause, the applied baseline is preserved, and no attach/update/detach work runs. Recovery exact-validates the protected intent and live typed state, durably commits and verifies the blocked barrier, then requires a fresh replay with zero failures, no pending intent, the typed inventory status, and an exact barrier-state match immediately before the cause-free rollback append. Corrupt, missing, unreadable, or changed lineage therefore fails closed without changing WAL or RAM. Legitimate authoritative per-port ignores remain legal. | RED `3112a75` produced only the two intended failures in Build [29548531843](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/29548531843). Fresh-replay RED `fc22f45` produced only its intended failure (37/38 passed) in Build [29550329874](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/29550329874). Production commits `6236bbd` and `f74aaf4` passed all 38 focused `neutron_wal` tests, including baseline, generation-0, phase-2 retry, corrupt-tail, and restart coverage, in exact-head Build [29550671826](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/29550671826). |
| REVIEW-TXN-030 | P1 contract / P2 runtime | Strict CT flush managed-publication rollback | fixed | Commit `49081c6` moves strict CT flush inside the lifecycle/instance-locked owned publication transaction and restores bank, general-map, and durable preimages on failure while keeping health unverified when the primary operation or compensation fails. Pre-field wiring/hardening commits `d1aa523..ad30cad` cover managed detach ordering, purge-failure atomicity, strict-flush rollback, and successful retry detach; independent final review approved the wiring. Exact-head GitHub Actions run [29672271181](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/29672271181) at `ad30cad` passed `fast-contracts`, `rust-behavior`, and `rust-build`. | A target-kernel isolated direct-snapshot fixture forced strict CT-flush failure against real pinned state and proved restoration of the old bank, general selectors, durable state, and attached/quiesced boundary before a successful retry. The independent OVS canary had zero gaps. See the 2026-08-06 high-risk field summary. |
| REVIEW-ACL-057 | P1 | Direct ACL publication leaves same-bank CT valid | delivered to `v0.9-neutron-agent`; hosted CI complete | Standalone policy add/update/delete, `direction=both`, and every accepted item in a batch now build one complete final state and publish it once through the inactive shadow bank. The concrete locked transaction captures the old bank, exact general-map preimage, state, allocator, durable state, and transaction-created bitmaps; it stages the full projection, applies required general-map changes, switches bank once, strictly persists, strictly scrubs CT, and compensates in reverse on failure. All-rejected batches retain the prior no-publication response behavior. | RED commit `212828b` failed only on the intended missing transaction API in Build [29682513348](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/29682513348). Production commits `10c3c45` and `a234bb5` passed `standalone_acl_publication_add_deny_rotates_bank_and_strictly_flushes_ct`, `standalone_acl_publication_allow_to_deny_is_one_both_direction_epoch`, `standalone_acl_publication_delete_allow_removes_both_directions_once`, `standalone_acl_publication_batch_keeps_item_errors_and_switches_once`, and `standalone_acl_publication_failures_restore_every_preimage_in_reverse`, plus full warning-denied Rust/eBPF builds, in Build [29683492746](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/29683492746). Direct delivery head `a0861bb` passed exact-head v0.9 push Build [29685324204](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/29685324204). The later `REVIEW-ACL-059` cleanup/reuse fix is recorded below. `REVIEW-ACL-056`, ordinary unreferenced-group durability, and privileged field evidence remain open and are not claimed here. |
| REVIEW-ACL-058 | P2 | Northbound CIDR and address-set reference validation | fixed | Commit `bad6731` routes all three repositories through one strict final-state invariant layer. Direct rule CIDRs and address-set members are canonicalized before persistence; referenced sets must exist, remain enabled/non-empty/valid/in-limit, and match the policy project. Failed updates preserve the complete preimage and immutable identity fields cannot change. Effective ACL defense in depth now delegates to the same parser while preserving the stable runtime degradation reason. | RED `8bc9f49` produced the intended 87 failures with no unittest errors in Build [30597384263](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/30597384263). Exact-head GREEN Build [30598232712](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/30598232712) passed 504 `fast-contracts` tests and `changes`; Rust jobs correctly skipped for the Python-only change. Privileged field evidence is not applicable to this northbound contract fix. |
| REVIEW-ACL-059 | P2 | Standalone bitmap reuse before cleanup proof | delivered to `v0.9-neutron-agent`; hosted CI complete | Retired indices now carry a separate durable cleanup intent containing the exact normalized kernel target. Free-list and fresh allocation skip explicit and legacy quarantines; standalone writes retry pending deletes before planning and release an index only after idempotent kernel deletion plus durable state publication. Post-commit cleanup faults return `202 Accepted` with `committed=true` and structured cleanup debt, remain visible as maintenance state without falsely lowering ACL readiness, and do not roll back an already committed policy. | RED commit `724527d` failed only on the intended missing cleanup-intent/outcome interfaces in Build [29690852147](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/29690852147). Production commit `65fedfb` passed exact-target restart recovery, allocator no-reuse, committed-pending outcome, item-error separation, API status, all selected Rust behaviors, and warning-denied eBPF/userspace/agent builds in exact-head Build [29691471591](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/29691471591). No privileged field execution is claimed or required for this allocator/cleanup-state closure. |
| REVIEW-OPS-037 | P2 | Blocking OVS discovery under apply mutex | fixed | Commit `f6e0f9b` runs both `ovs-vsctl` calls asynchronously outside the apply mutex under one three-second inventory deadline with `kill_on_drop`; partial/failing output becomes the existing non-authoritative `inventory_unavailable` result. Admission reacquires the lock, compares the complete runtime identity, retries a bounded three times, and returns conflict before WAL/runtime mutation on exhaustion. | RED `b127807` failed on the two absent boundaries in Build [30615820795](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/30615820795). Commit `4b02277` put both new behaviors in the maintained hosted filter; exact-head Build [30616520693](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/30616520693) ran them successfully and passed warning-denied Rust/eBPF/static builds. No local Cargo or privileged field evidence applies. |
| REVIEW-ACL-060 | P2 | ACL list pagination and N+1 queries | implementation fixed; deployment activation open | All five list resources share strict typed filters, deterministic identity-tied keyset ordering, forward/reverse markers, field projection, and bounded native SQL/SQLite execution. Address-set members are batch-loaded once per selected page; the agent requests bounded ACL pages independently from port reads. The target legacy Neutron exposes pagination only through its global `allow_pagination` gate; the extension helper has no per-resource override. | Commits `a46c11d`, `0087e7d`, `0dbd476`, `f9da01e`, `5a7845b`, and `3999e49`. Exact-head Build [30644674860](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/30644674860) passed 543 fast contracts, 9 CLI contracts, and 4 warning-as-error DB contracts. Repository/plugin-level target execution passed forward/reverse and custom-marker coverage with bounded SQL budgets. A 2026-08-07 production-configuration check found `allow_pagination=False`: twelve HTTP requests with `limit=2` each returned all five rows with no next link, and malformed markers were ignored for both Aria and built-in resources. Closure therefore also requires a reviewed global Neutron pagination activation, regression across built-in APIs, and a target HTTP rerun; internal repository evidence alone is insufficient. |
| REVIEW-ACL-061 | P2 | Duplicate rule/binding write race | fixed | Commit `bad6731` keeps friendly final-state preflight but makes named database uniqueness authoritative. Enabled rows use nullable guard `1`, disabled rows use `NULL`; SQLite and Neutron schemas enforce the exact rule-priority and binding-target keys. Complete repository transactions preserve preimages, known race losers map to HTTP 409, and unknown storage errors remain unmapped. Migration `f61a2c4e7b90` fails closed with every historical conflict before applying DDL. | RED `8bc9f49` and Build [30597384263](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/30597384263) proved repository parity, update/enable conflicts, notifier suppression, old-schema rejection, and migration gaps. Exact-head GREEN Build [30598232712](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/30598232712) passed all 504 fast contracts; [`fast-contracts` job](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/30598232712/job/91055190719) and [`changes` job](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/30598232712/job/91055190747) both succeeded. |
| REVIEW-ACL-062 | P2 | Multi-direction publication and incomplete recovery | fixed | Revalidation found policy already atomic under ACL-057/066 and managed QoS/Mirror already receipt-based. Commit `44743f5` routes the remaining standalone and attach-owned QoS/Mirror paths through one concrete final-state transaction. Exact update/delete preimages are compensated in reverse; every compensation and durable-restore error remains visible. An unprovable restore strictly persists a versioned, domain-scoped recovery fence, blocks only that domain, and startup clears it only after replay and full runtime validation. | RED `fb20546` failed on the intentionally absent recovery model in Build [`30683268154`](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/30683268154). Exact-head GREEN Build [`30683913104`](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/30683913104) passed `fast-contracts`, `neutron-db-contracts`, all selected Rust behaviors, and warning-denied eBPF/userspace/agent static builds. No privileged field evidence is required for closure; none is claimed. |
| REVIEW-ACL-063 | P2 | General group LPM overlap is single-ID | fixed | A pure final-state transition guard now rejects newly introduced exact or nested overlap between different general-domain group IDs before projection, allocator, runtime, or persistence effects. Standalone checks every group; managed mode uses the existing ACL-only/general classification, including rejection when QoS or Mirror promotes an overlapping ACL-only selector. Same-group nesting and ACL-046 isolation remain valid. Unchanged legacy conflicts remain replayable and removable under the deterministic compatibility compiler. Public group conflicts return HTTP 409; standalone ACL batch conflicts remain per-item errors. | RED `7e94aed` / Build [30705557669](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/30705557669) failed on the missing transition contract. Production `9585ed7` plus corrected IPv6 fixture `1871e55` passed exact-head Build [30705819827](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/30705819827), including selected Rust behavior and warning-denied eBPF/userspace/static builds. No eBPF ABI changed and no privileged field evidence applies or is claimed. |
| REVIEW-ACL-064 | P1 | Detach purge active-policy-miss PASS window | fixed | Commit `49081c6` replaces item-at-a-time detach purge with the ordered transaction: quiesce ACL/CT, publish an empty owned ACL projection, strictly flush CT, then detach; purge or flush failure keeps the interface attached and quiesced. Later lifecycle repairs make already-deleted tap observation and delete recovery idempotent. | A clean Neutron port detach removed the tap and converged runtime state. A separate target-kernel isolated fault fixture then proved purge and strict-flush failures never advance to detach or expose a policy-miss PASS state, and a later retry detaches cleanly. Independent OVS canaries recorded zero gaps. See the 2026-08-06 high-risk field summary. |
| REVIEW-ACL-065 | P1 | Privileged purge partial owned-ACL deletion | fixed | Commit `49081c6` removes privileged item deletion in favor of one quiesced empty-owned-ACL publication with complete rollback; failure aborts detach and preserves the complete prior owned state. This remains the root cause beneath the older ignored-error symptom in `REVIEW-ACL-023`. Later lifecycle repairs make already-deleted tap cleanup and full-resync recovery idempotent. | A target-kernel isolated direct-snapshot fixture forced real pinned-map purge failure and verified the complete owned projection, bank, selectors, WAL identity, and attachment boundary before a successful retry detach. The independent OVS canary had zero gaps. See the 2026-08-06 high-risk field summary. |
| REVIEW-ACL-066 | P1 | Referenced standalone group expansion leaves same-bank CT valid | delivered to `v0.9-neutron-agent`; hosted CI complete | Adding a CIDR to a standalone group referenced by an ACL policy now routes through the same final-state shadow-bank transaction as `REVIEW-ACL-057`: the full referenced selector projection is staged before one bank switch, strict persistence, and strict CT scrub. Whole-group deletion while referenced remains rejected, and unreferenced group mutation deliberately remains on the legacy path. | RED commit `212828b` failed only on the intended missing transaction API in Build [29682513348](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/29682513348). Production commits `10c3c45` and `a234bb5` passed the group-specific `standalone_acl_publication_referenced_group_expansion_updates_general_before_switch` regression and full warning-denied Rust/eBPF builds in Build [29683492746](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/29683492746). Direct delivery head `a0861bb` passed exact-head v0.9 push Build [29685324204](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/29685324204). The later `REVIEW-ACL-059` cross-transaction cleanup/reuse fix is recorded above; ordinary unreferenced-group durability and privileged field evidence remain open and are not claimed here. |
| REVIEW-ACL-067 | P2 | Fragment-context failure can delete a replacement CT entry | fixed | A tracked first fragment formerly created CT before context and could later delete a same-key replacement using stale ownership. The four ingress/egress V4/V6 paths now evaluate policy/QoS, install first-fragment context, and only then attempt `BPF_NOEXIST` CT creation. Context failure drops without any CT delete; unfragmented/atomic/resolved-non-initial ordering is unchanged. | RED `dd35fb2` added create-point, no-delete, and same-key replacement interleaving contracts; Build [29942509813](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/29942509813) failed only on the intended missing interfaces. GREEN `43e0e2a` removed the ownership boolean, rollback helpers, and delete calls; Build [29943612716](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/29943612716) passed behavior and warning-denied Rust/eBPF/static builds. |
| REVIEW-ACL-068 | P2 | Early fragment drops reuse stale per-CPU identity fields | fixed | TC ingress and egress now call one `PipelineCtx::reset_for_tc_packet` immediately after acquiring per-CPU scratch and before fragment resolution. It initializes tap/identity/matched/CT/action/authority fields and every padding byte, so early fragment drops cannot inherit the prior packet's profiling or trace identity. | RED `dd35fb2` poisons every byte then verifies every field for both directions; expected Build [29942509813](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/29942509813) failed on the missing reset. GREEN `43e0e2a` passed the new behavior and full warning-denied Rust/eBPF/static Build [29943612716](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/29943612716). |
| REVIEW-ACL-069 | P1 | Same-generation snapshot noop skips pinned ACL projection repair | fixed | Snapshot admission now performs bounded managed-ACL projection verification before returning an equal-generation/hash noop. A clean verified projection remains a cheap noop; repairable selector drift enters the existing owned publication and strict CT invalidation path, while fatal verification remains fail-safe and observable. Independent non-ACL domains are not republished. | Commit `445dcec` passed hosted Build `31146831997`. A target-kernel field run corrupted the active managed selector, submitted the same generation/hash, observed repair and strict CT invalidation, and then observed the deny counter advance. An independent OVS canary recorded 1,392 contiguous replies with zero gaps. |
| REVIEW-ACL-070 | P1 | Legacy Neutron collection RBAC bypass | fixed | Target Neutron 9 calls collection `index()` with authorization disabled and expects each plugin list query to enforce tenant visibility. The Aria ACL plugin formerly queried all five repositories directly, allowing an authenticated non-admin tenant to list cross-project policy, rule, address-set, binding, and port-status metadata even though create and item policies remained protected. | All five list methods now enforce their existing `get_aria_acl_*` policy before repository access. A denial-first unit regression covers every collection. On 2026-08-07 the updated package was installed through the reversible plugin gate on the target controller: the public smoke observed HTTP 403 for all five member-token collection requests and policy create, the admin API/CLI consistency smoke passed through cleanup, temporary identities left zero residue, and an independent VM canary recorded 5/5 replies. Exact-head Build [31166418193](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/31166418193) passed fast/database/clean-install contracts, selected Rust behavior, the legacy eBPF stack budget, and warning-denied Rust/eBPF builds. |
| REVIEW-ACL-071 | P2 | Composite port-status ID is not path-safe on target Neutron 9 | fixed and field-verified | New responses emit `aria-status-v1_<base64url>`, whose complete alphabet is route-safe for the target legacy controller. The decoder and all repository/plugin identity branches continue accepting the former dotted prefix for direct calls, filters, and pagination markers during rolling upgrades. Marker and filter resolution compare decoded `(port_id, host)` identity, so old and new encodings have identical semantics without a database migration. | TDD covered route-safe emission, the target controller's formatted-route precedence, exact show/delete, old-ID decoding, and old filter/marker compatibility across memory, SQLAlchemy, and SQLite paths. Fast contracts passed 584 tests with 8 environment skips, plus 10 CLI tests. A reversible deployment on the active test controller passed real HTTP creation and exact GET for two host rows on one port; exact DELETE returned 204, the deleted row returned 404, and the peer row remained readable. Cleanup left no synthetic status rows, and the VM connectivity canary remained lossless. OVS, ovs-agent, Python compute agents, and the Rust datapath were not restarted. See `docs/evidence/openstack-n05-lite/20260810-acl071-route-safe-status-id/summary.md`. |
| REVIEW-SEC-003 | P1 | Neutron client authentication tokens are written to agent DEBUG logs | fixed and field-verified | `openvswitch_agent.ini` is the last Neutron runtime config loaded by `neutron-aria-agent`; its `debug=True` made `common_config.setup_logging()` enable third-party HTTP DEBUG output. The agent now fixes the known client logger namespaces at WARNING after Neutron initialization and installs an idempotent handler filter that redacts `Authorization`, `X-Auth-Token`, and `X-Subject-Token` values as defense in depth. | TDD RED reproduced both DEBUG disclosure and unredacted WARNING output. Focused GREEN passed; fast contracts passed 581 tests with 8 environment skips. A reversible Python 2.7 egg rollout on the two available test nodes passed imports, entrypoint smoke, forced redaction, fresh-log inspection, and ready/non-degraded health. Fresh active logs had zero authentication-header, client DEBUG, or error lines; OVS, ovs-agent, and the Rust datapath were not restarted. Pre-fix logs were retained as mode-0640 audit archives. See `docs/evidence/openstack-n05-lite/20260810-sec003-log-redaction/summary.md`. |
| REVIEW-ACL-073 | P3 | Legacy Neutron wrong-shape bodies return framework 500 | inherited framework risk | A syntactically valid JSON object whose resource value is a list, for example `{"aria_acl_policy":[]}`, reaches Neutron 9 `prepare_request_body()`. The framework writes `tenant_id` through a string key and raises `TypeError` before the Aria controller or plugin can validate the body. | Reproduced on 2026-08-07. The same-shaped request against the built-in `networks` resource produced the same 500 and stack location, proving this is not Aria-specific. Normal malformed JSON and unknown attributes returned 400, no object was created, and the API remained healthy. Prefer an API-front validation or upstream-compatible framework guard only if product requirements demand eliminating this inherited 500; do not add resource-specific duplicate validation without a controller boundary that runs before `prepare_request_body()`. |
| REVIEW-ACL-074 | P1 | Cold migration retains the source-host port status | fixed and field-verified | The source compute removed its datapath projection after migration, but the status reporter only upserted rows and never deleted the former `(port_id, host)` row. The API therefore returned two current-looking execution rows for one port. The agent now deletes the route-safe composite status ID for its own host, retries failed deletes, removes status on explicit port delete, and compares the prior and current projected-port sets during full resync. | Commit `02cc2d8` adds client, reporter, event-loop, retry, and regression coverage. A field cold migration first reproduced the duplicate beyond two full-resync intervals. After deployment, the reverse migration recovered traffic in 2 seconds, exposed exactly one status row for the destination host immediately, and still exposed one row after the next periodic full resync. An independent forwarding canary recorded 116 replies with zero failures. See `docs/evidence/openstack-n05-lite/20260813-daytime-validation-02cc2d8/summary.md`. |
| REVIEW-CLI-001 | P2 | Dynamic path segments are not encoded | fixed | All 37 dynamic request sites now use concrete instance/group/chain segment-encoding boundaries. Request-line tests cover `/`, `?`, `#`, literal `%2F`, and query separation without binding CI to private helper spelling. | RED `9609518` / Build [30693251050](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/30693251050); GREEN `91edc43` / exact-head Build [30693519106](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/30693519106). Fast/database contracts and warning-denied eBPF/userspace/agent builds passed. |
| REVIEW-CI-002 | P1 | v0.9 pull requests miss Build workflow | fixed | Build now triggers for pull requests targeting `main` and `v0.9-neutron-agent`; `check_build_workflow_contract.py` enforces the maintained target and detector invocation. GitHub branch protection for `v0.9-neutron-agent` is strict and requires the `build` check. | Fixed in `a7e742c`. PR #3 Builds are automatically triggered by the `pull_request` event; closure Build [29550671826](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/29550671826) passed. |
| REVIEW-CI-003 | P2 | Rust change detector omits workflow and CI inputs | fixed | `rust_build_required.py` treats `.github/workflows/` and `ci/` as Rust-required, evaluates the full PR base-to-head path set with rename detection disabled, and fails closed for empty, malformed, or unknown paths. | Fixed in `a7e742c` and `e44537f` with table-driven detector tests and workflow contract coverage; closure Build [29550671826](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/29550671826) passed. |
| REVIEW-CI-004 | P3 | Pod layout guard does not require repr(C) | fixed | `verify_pod_layouts()` now requires adjacent `#[repr(C)]` for every type in `impl_aya_pod!` while retaining implicit-field and tail-padding checks. | Fixed in `a7e742c` with mutation tests that remove `repr(C)` from `PolicyKey` and the final Pod declaration; warning-hygiene contracts passed in closure Build [29550671826](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/29550671826). |
| REVIEW-DOC-022 | P2 | Recover-pending route absent from UDS contract | fixed | The JSON artifact now carries the complete recovery wire contract, and Stage 1 enforces the exact public route inventory plus server/client method-path parity. The check deliberately ignores private function layout. | Fixed in `fb74ba8`. RED `8d3183e` / Build [30693943116](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/30693943116) exposed the omission; GREEN Build [30694029883](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/30694029883) is the exact implementation-head closure evidence. |
| REVIEW-DOC-021 | P2 | Capabilities advertise unimplemented domains | fixed | `NEUTRON_SUPPORTED_DOMAINS` / `neutron-uds-contract.json` / capabilities response list qos/mirror/config/ct/… while reconcile only implements `attach`+`acl`. Stage-1 CI even requires qos/mirror in supported_domains. | Split advertised vs implemented domains; shrink supported set or mark planned and reject managed_domains that are unimplemented. |
| REVIEW-OPS-035 | P2 | Transaction smoke can pass with zero ports | fixed | The transaction-state smoke now defaults `MIN_MANAGED_PORTS=1`, rejects explicit zero or non-numeric minimums, and requires a concrete `port_id` both before pending-delete recovery and before migration-source cleanup. None of those missing-coverage states can reach the final `passed` result. | RED commit `1c239de` and Build [30698108346](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/30698108346) proved that zero ports and both missing-`port_id` cut points still reported success; the run was cancelled after fast-contracts captured the expected failure. GREEN commit `f19e03f` covers those cases plus an explicit zero override through the public smoke entrypoint. Exact-head Build [30698215982](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/30698215982) passed fast/database contracts, selected Rust behaviors, and warning-denied eBPF/userspace/agent builds. This closes the false-success implementation defect; it does not claim a new privileged transaction field run. |
| REVIEW-OPS-036 | P3 | XDP pinned-path health can false-pass | implementation and hosted CI complete; exact system/XDP field evidence deferred | `FirewallInstance`, standalone startup, and shared-runtime recovery now use one in-process observation of the exact pinned program and link. Readiness and ownership require XDP link type, nonzero link ID and ifindex, the current expected interface ifindex, and the exact pinned program ID. Missing, detached, mismatched, or unverifiable evidence is not-ready; an existing unverified pin is preserved and blocks replacement while independent TC ACL/CT startup continues. | RED `c82e18e` / Build [30872857520](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/30872857520) failed on the deliberately missing identity boundary. GREEN `31dcf49` / exact-head Build [30873163705](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/30873163705) passed all five exact-identity behaviors plus warning-denied eBPF/userspace/agent builds. Field wiring `6548272` / Build [30873611591](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/30873611591) adds the opt-in scenario. Standalone `tap` mode passed on the target host, but the legacy kernel returned Aya `FdLink InvalidLink` for the exact system/XDP pinned-link path. That path remains an activation gate; tap evidence is not substituted for it. Full DDoS readiness still requires attach-mode, domain-generation, and required-map validation. |
| REVIEW-CI-001 | P2 | Stage gates are marker/substring heavy | fixed | The required fast lane now inventories critical behavior through Python `unittest` discovery and still executes the full suite exactly once. Rust filters are accepted only when Cargo reports at least one executed test; the source-regex Rust test parser is removed. Runtime-implemented and advertised domains are equal by Rust behavior, while Python enforces `requested ⊆ Python-supported ⊆ advertised`. Stage 2 no longer reruns six modules or activates private source/test-name guards. Static artifacts report `static_artifact`; committed field summaries report `historical_field_evidence` with `head_bound=false`. | RED `e6c1fe8` / Build [30704754808](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/30704754808) failed the missing required wiring and was cancelled after RED capture. GREEN `5d7fcfc` / exact implementation-head Build [30704906357](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/30704906357) passed fast/database/clean-install contracts, Rust behavior, and warning-denied Rust/eBPF builds. No privileged or target runtime execution is claimed. Full-workspace quality expansion remains `DEBT-CI-001`. |
| REVIEW-ACL-075 | P1 | TC parse-uncertainty fail-open bypass | open | Commit `8bab0b8` deliberately returns `TC_ACT_OK` when `parse_tc_packet` fails (`ebpf/src/lib.rs:118-123`, `314-319`), replacing the former drop path. Two distinct scenarios follow. (1) Substantive bypass: an IPv6 packet carrying more than four extension headers (`parser.rs:345`, `390-392`) is RFC 8200-valid and processed normally by Linux, yet skips ACL/CT/QoS entirely, so an attacker can run a whole connection uninspected. (2) Asymmetric pass + DoS: an IPv4 first fragment whose TCP/UDP header is truncated (`parser.rs:243-246`) passes un-inspected without installing a fragment context, while every successor fragment is dropped for missing context; reassembly cannot complete, so this is not a full-connection bypass. `REVIEW-ACL-087` was merged into this row as the detailed consequence of scenario (2). | Re-review the fail-open decision: distinguish adversarial parse failure from expected runtime uncertainty. Fail closed for invalid-L4 and structurally unparseable packets, and raise the extension-header walk limit within verifier-safe bounds (CI stack-budget gate arbitrates) rather than passing overflow packets; record the decision in the design-decisions ledger. Add parser-contract tests for both shapes. |
| REVIEW-ACL-076 | P1 | pull_data(0) never linearizes non-linear skbs | open | `ebpf/src/lib.rs:546` and `:563` call `pull_data(0)`; `bpf_skb_pull_data` returns success immediately when the requested length is within the linear head, so paged data is never pulled. The intended non-linear-skb repair path (comment at `lib.rs:558-561`) is dead code, and GRO/segmented traffic whose L4 header is paged falls into the fail-open parse path recorded by `REVIEW-ACL-075`. | Pull the required length (`ctx.len()` or the minimum needed to cover the L4 header) before the re-parse; add a non-linear-skb contract test. |
| REVIEW-ACL-077 | P1 | status.py drops unicode domain keys on Python 2.7 | open | `AgentRuntimeStatus._generation_by_domain` (`openstack/neutron_aria/neutron_aria/agent/status.py:284`) filters with a bare `isinstance(domain, str)`; under Python 2.7 JSON-loaded dict keys are `unicode`, so every durable per-domain feature-ready entry is discarded after restart and heartbeats report an empty history. Every other adapter module uses a `basestring`-compatible string check; this file does not. | Use the same `basestring`-compatible string check as the rest of the adapter and add a Python 2.7 key round-trip regression test. |
| REVIEW-ACL-078 | P2 | QoS rate parsing allows values that overflow the token refill | open | `parse_rate` (`core/src/qos_ops.rs:211-246`) has no upper bound and casts `f64` to `u64` with saturation; `compute_refill` (`ebpf/src/qos.rs:20-24`) only preserves precision below roughly 18 GB/s. Rates above that bound produce wrapped refills with undefined policer behavior (over- or under-policing depending on idle time), and no validation rejects them at the API boundary. | Validate a documented maximum rate at the API/config boundary and reject overflow-capable values; add unit tests at the overflow threshold. |
| REVIEW-ACL-079 | P2 | Generation-0 snapshots apply into a permanently Blocked state | open | `validate_snapshot_preflight` (`agent/src/neutron_api.rs:3608-3616`) does not require `generation > 0`; a generation-0 snapshot applies fully with `authority_state=ready`, but Status V1 then classifies the runtime Blocked (`neutron_api.rs:1872`, `1921-1923`, `1964-1976`, `2085-2119`) and recover-pending refuses with `no_applied_snapshot_to_restore`, wedging the deployment until a generation >= 1 resync arrives. | Reject generation-0 snapshots at preflight with an explicit error code; add a contract test. |
| REVIEW-ACL-080 | P2 | Identical partially-failed snapshot re-submit never retries | open | `pending_snapshot_submit_response` (`agent/src/neutron_api.rs:2303-2335`) returns `pending` for the same generation+hash without re-attempting failed ports. The documented contract converges via driver-side recover-pending plus a new generation, so this is a driver-contract asymmetry rather than a dead end; the agent side still offers no idempotent retry path for a transient per-port failure. | Either retry failed per-port operations idempotently on an identical re-submit, or make the pending response state the retry contract explicitly so drivers can rely on it; add a transient-failure re-submit test documenting the chosen behavior. |
| REVIEW-ACL-081 | P2 | Dead XDP link is never projected into per-port Neutron status | withdrawn; outside the Neutron-managed domain set | `NEUTRON_SUPPORTED_DOMAINS` is `["attach", "acl"]` and XDP is pass-only by design. The `xdp_ddos_hook_unavailable` readiness reason is intentionally not projected into ACL port status because DDoS/XDP is not a Neutron-managed domain in this release; the HTTP instances endpoint remains the observation surface. This was recorded as a bug but is the explicit product boundary. | Reopen only if a future release adds a Neutron-managed XDP/DDoS domain with a defined per-port status contract. |
| REVIEW-ACL-082 | P2 | ACL DB delete paths lack row locks and check/delete atomicity | open | `delete_policy` runs its in-use check and delete in separate transactions with no row locks (`db/aria_acl/api.py:718-720`, `1378-1384`, `1232-1237`) and `_define_tables` declares no foreign-key constraints (`:1110-1217`); a concurrent create between check and delete leaves an orphaned rule and the port degrades to `bypass`. `delete_address_set` is transaction-wrapped but still unlocked, and the outcome is surfaced as `degraded/bypass`, not fully silent. | Wrap delete check+delete in one locked write transaction using the existing row-lock helper; add concurrent-writer tests. |
| REVIEW-ACL-083 | P2 | Shared fallback in-memory ACL repository mixes requests and loses state | conditional; production-path reachability unproven | `plugin.py:53-54` creates one `InMemoryAriaAclRepository` per process and `_repo` (`:479-489`) serves it whenever `context.session` is absent. The mixing/loss mechanics are real, but normal Neutron API requests carry a DB session; before treating this as a production bug it must be demonstrated that a production request path can reach the fallback (misconfiguration probe or fault injection), and the unlocked list/delete methods on the repository itself remain a latent hazard either way. | Prove the fallback is reachable on a production-style path first; regardless of that proof, lock the remaining repository methods as defensive hardening. |
| REVIEW-ACL-084 | P3 | DB write errors inside a pre-existing transaction skip rollback | conditional; transaction-ownership model | `_write_transaction` (`db/aria_acl/api.py:1041-1056`) yields without rollback when the session already has a transaction, and `_neutron_write` (`:189-203`) re-raises. Joining the caller's transaction without self-rollback is the normal transaction-ownership model; this is not a bug unless it can be demonstrated that an upper layer catches the error and continues using the failed session. That consequence was not traced end to end. | Keep as a conditional note; reopen as a bug only with a reproduction where a failed inner write leaves the outer request committing a broken session. |
| REVIEW-ACL-085 | P3 | Delete errors drop the remainder of a drained event batch | open | `agent/service.py:262-278` returns after marking `DELETE_PORT_DEGRADED` when `_delete_known_ports` fails, discarding the batch's remaining port_updates/dirty_networks. The degraded flag IS surfaced in the heartbeat, and convergence relies on the next periodic resync, so the loss is not silent. | Preserve the unprocessed updates for the next drain or trigger an immediate resync on delete failure. |
| REVIEW-ACL-086 | P2 | Cross-CPU CT entry use-after-free through get_ptr_mut | open | `ebpf/src/conntrack.rs:143-158` (and the v6/reverse equivalents) take a raw element pointer then `remove(key)` on stale/expired paths while other CPUs hold pointers to the same hash slot; the kernel documents concurrent value access as unsafe. The concurrency hazard and counter-loss race are real, but the worst-case consequence (writing through a freed slot into an unrelated flow) depends on the target 4.18 backport's LRU eviction/reuse behavior and is NOT proven by source review alone. | Re-lookup or re-check the entry under a single guarded sequence, or use per-CPU-safe updates; before asserting cross-flow corruption as fact, obtain kernel-level stress or target-source verification of the 4.18 backport reuse path. |
| REVIEW-ACL-087 | P2 | Truncated first fragment passes while successors are dropped | merged into `REVIEW-ACL-075` | This row was the detailed consequence of the truncated-first-fragment scenario in `REVIEW-ACL-075` and carries no independent root cause. The scenario and fix direction now live in that row. | No separate action; resolve together with `REVIEW-ACL-075`. |
| REVIEW-ACL-088 | P2 | delete_network ignores its id argument | reclassified: defensive API debt, not a live defect | `delete_network` (`core/src/ebpf_ops/network.rs:182-190`) builds the LPM key purely from `(tap_id, ip, prefix)` and never checks the stored owner id. All production callers are currently protected by overlap admission and `capture_network_owner` preimages, so no current entrypoint can delete another group's CIDR; the core API shape remains a silent-corruption footgun for future callers. | Harden the core API (read back the stored id and refuse mismatched deletes) as defensive debt; do not treat this as an active production defect. |
| REVIEW-ACL-089 | P3 | QoS and mirror deletes are non-idempotent | open | Delete paths in `core/src/qos_ops.rs:122-123` and `core/src/mirror_ops.rs:141-142`, `222-223` map a missing key to an error that surfaces as HTTP 500, unlike policy deletes which use `classify_map_delete`. | Use the existing missing-tolerant delete classification; add repeat-delete tests. |
| REVIEW-ACL-090 | P3 | Port list pagination truncates silently | open | `list_ports_for_host` (`agent/neutron_client.py:50-54`) breaks out of paging when a page advertises a next link but yields no port id, returning an incomplete port list that silently omits ports from snapshots; the parallel `AriaAclRestClient._list` raises for the same condition. | Raise or degrade on incomplete pages like the sibling client; add a truncated-page test. |
| REVIEW-ACL-091 | P3 | TypeError-based signature sniffing can double-issue writes | open | `agent/neutron_client.py:133-136` and `agent/status_reporter.py:259-266`, `312-315` retry POST/DELETE with an alternate signature on any `TypeError`, which cannot distinguish a signature mismatch from a `TypeError` raised during response processing. A double-issue therefore only occurs when the underlying client raises `TypeError` after the request was sent; that contingency is unproven for the current client implementations. | Probe callable signatures once at construction instead of retrying on `TypeError`; add a double-issue test with a client that raises `TypeError` during response processing. |
| REVIEW-ACL-092 | P3 | commit_delete leaves deleted ports in feature-ready history | withdrawn; contract-defined history semantics | The status contract (`16-versioned-rust-python-status-contract.md`) makes history ownership deliberately asymmetric: the classified track owns generation floors and scoped/delete events, while the feature-ready track is explicit last-ready history evidence. Pruning deleted ports from the feature-ready track would tamper with the historical projection the contract preserves. | Keep closed per contract; do not prune the feature-ready track on port delete. |
| REVIEW-ACL-093 | P3 | delete_trace_filter treats read errors as not-present | open | `core/src/trace_ops.rs:196-198` returns `Ok(false)` for any `map.get` error, including transient syscall faults, suppressing the removal and reporting success. | Distinguish a missing key from other errors and propagate the latter. |
| REVIEW-ACL-094 | P3 | Batch flush helpers swallow per-key removal failures | open | `core/src/trace_ops.rs:269-287`, `core/src/drop_ops.rs:79-82`, `core/src/kernel_drop_ops.rs:201-204`, and `core/src/monitoring.rs:1020-1071` count keys before removal and discard remove errors, overstating deletion counts. | Aggregate removal failures like `execute_map_delete_batch` and return them. |
| REVIEW-ACL-095 | P3 | Managed-tap config updates silently drop ssl_enabled | withdrawn; SSL applies through the host-global path | `update_config` (`agent/src/control_plane.rs:7917-7931`) applies `ssl_enabled` through `set_ssl_global_config` before the per-tap runtime update and returns early for SSL-only requests; SSL is host-global by design and is not a `TapConfig` field. The value is not silently discarded. | Keep closed per the host-global SSL design. |
| REVIEW-ACL-096 | P3 | TCP-RT stats swallow map errors as empty success | open | `core/src/monitoring.rs:982-983` uses `unwrap_or_default` on both TCP-RT flow queries, so a map fault reports an empty stats list with HTTP success. | Propagate map faults as errors. |
| REVIEW-ACL-097 | P3 | TCP-RT control-plane queries swallow kernel errors | open | `agent/src/control_plane.rs:8156-8176` uses `unwrap_or_default` on the lookup/filter results, conflating map failures with no flows. | Propagate faults; keep empty as a distinct result. |
| REVIEW-ACL-098 | P3 | Fragment drops are always traced as ACL drops | open | `phase_fragment_drop_tc` (`ebpf/src/lib.rs:678-685`) hardcodes `TRACE_RESULT_DROP_ACL` regardless of the fragment `drop_reason`. Calling `trace_result_from_drop_reason` would NOT help: it defaults unknown reasons (all fragment codes 6-19) to `TRACE_RESULT_DROP_ACL` as well. The trace result vocabulary has no fragment-specific code today. | Extend the trace result ABI with a fragment-drop result code (or map fragment reasons explicitly) and use it on this path; keep the ABI change additive. |
| REVIEW-ACL-099 | P3 | Fragment resolve-stage drops record src_id/dst_id 0 | open | Resolve-stage fragment drops run before `load_packet_ids_*`, so `do_drop` (`ebpf/src/lib.rs:664-676`) keys group stats with ids 0; install-failure drops happen after the CT phase and may have ids loaded, so the gap is specific to resolve-stage paths. | Load ids before the resolve drop paths or accept and document the group-0 aggregation. |
| REVIEW-TXN-031 | P1 | Failed port delete keeps stale ready status after ACL purge | open | `apply_delete_neutron_port` purges ACL and quiesces the runtime gate before detach (`agent/src/neutron_api.rs:4478-4498`). If detach then fails (`:4519-4540`) the handler returns 500 without updating `runtime.port_statuses`, so Neutron keeps receiving `status=ready` with `effective_action=enforce` while the datapath no longer enforces ACL. Health projection cannot correct it because the TC links remain attached. | On purge/detach failure, update the port status to error/degraded reflecting the quiesced state, and mark the runtime pending/blocked so the delete intent is recovered; add regression tests. |
| REVIEW-TXN-032 | P1 | state.json non-atomic write can reset the firewall to allow-all | open | `StateManager::with_state` (`core/src/state.rs:688-701`) truncates and rewrites `state.json` in place with no tmp+rename; the WAL compactor uses the correct atomic pattern. A crash in the write window leaves an empty or torn snapshot; `load_with_wal` then starts from `FirewallState::default()` and, once the WAL is compacted, replays nothing, dropping every group/policy/QoS/mirror rule while `evaluate_policy` defaults to pass. | Persist state via tmp+fsync+rename+dir-sync like `WalWriter::compact`; add a torn-write recovery test. |
| REVIEW-TXN-033 | P1 | WAL compact snapshot-before-truncate window corrupts the bitmap allocator | open | `WalWriter::compact` (`core/src/wal.rs:200-236`) renames the new snapshot before truncating the WAL. A crash between the two replays the full WAL prefix on top of the new snapshot; `apply_add_rule` (`core/src/state.rs:462-512`) is not idempotent for updates, so replayed older `AddRule` entries release and re-allocate port sets and can move the surviving rule's `bitmap_idx` (verified for a K:A then K:B then K:C chain). Kernel maps are re-projected at startup, so the persistent harm is allocator drift/phantom free-list entries rather than permanent enforcement divergence. | Do NOT reorder to truncate-first: that opens a data-loss window between truncate and snapshot rename. Correct directions: a checkpoint/epoch boundary so replay skips entries already reflected in the snapshot, or make rule replay strictly idempotent. Add a replay-parity test asserting allocator state after snapshot+full-WAL replay equals the checkpoint state. |
| REVIEW-TXN-034 | P2 | Pending delete intent silently discarded by a later commit | open | The replay scan clears `pending_intent` on any `SnapshotCommit`/`DeleteCommit` with a valid status hash (`agent/src/neutron_wal.rs:427-444`) regardless of intent kind, while the delete failure paths (`neutron_api.rs:4465-4540`) do not mark the runtime pending/blocked. A failed delete whose intent was appended is therefore dropped by the next health-tick commit and never recovered after restart. | Preserve delete intents across unrelated commits or mark the runtime blocked on delete failure; add a replay test combining a failed delete intent and a later snapshot commit. |
| REVIEW-TXN-035 | P2 | Startup reconcile masks per-port error status after partial apply | conditional; needs re-verification against restart ACL invalidation | `reconcile_committed_runtime` (`agent/src/neutron_api.rs:624-756`) rebuilds committed ports as `ready` at `applied_generation` without consulting prior status. Startup then runs `invalidate_restarted_acl_runtime` (`neutron_api.rs:4111`, called at `:723`), which degrades ACL ports to `degraded/unchanged`, and the global pending state survives. Whether the per-port `error` evidence is fully masked therefore depends on the interaction between the reconcile row and the subsequent invalidation, which the original claim did not model. | Re-verify the end-to-end post-restart status with a test that exercises both steps before deciding the fix (skip/preserve error rows during restore, or accept the invalidation as the corrective projection). |
| REVIEW-OPS-038 | P1 | Broken agent config silently starts standalone auto-attach | open | `load_config` (`agent/src/main.rs:486-508`) falls back to `Config::default()` (standalone, auto-attach effective) when the configured TOML fails to parse. In a `neutron_managed` deployment a corrupted config therefore attaches XDP to every `^tap` interface with no snapshot authority and no bound UDS, without failing the service. | Treat an existing-but-unparseable config as fatal (config absent may still default for standalone quick start); add startup tests for the corrupted-config path. |
| REVIEW-OPS-039 | P2 | Map-open failures are conflated with empty state | open | Read paths such as `has_qos_rules` (`core/src/qos_ops.rs:24-39`) and `ct_list` (`core/src/ct_ops.rs:22-50`) treat `from_pin`/convert errors as empty; `sync_qos_enabled` (`qos_ops.rs:127`) then silently disables QoS enforcement on a transient map fault. | Distinguish NotFound from other open/convert faults and surface the latter as degraded/error; add fault-injection tests. |
| REVIEW-OPS-040 | P3 | Invalid iface_pattern silently falls back to ^tap | open | `tap_registry.rs:122-123` substitutes `^tap` for any invalid regex, so a typo'd operator pattern auto-attaches interfaces that were never intended to be managed. | Reject invalid patterns at startup with a clear error (or require an explicit fallback flag); add a startup test. |

## Verification At Time Of Recording

- `python -m unittest discover -s openstack/neutron_aria/neutron_aria/tests/unit -v`: 214 tests passed.
- `python -m unittest discover -s openstack/neutronclient_aria/neutronclient_aria/tests -v`: 4 tests skipped because legacy neutronclient is not installed locally.
- `python ci/check_neutron_stage1.py`: passed; 214 Python tests passed, Rust checks skipped locally because cargo is unavailable.
- `python ci/check_neutron_stage2_acl.py`: passed; after RPC sync-mode hardening, 98 tests passed.
- `python ci/check_stage2_acceptance_evidence.py`: passed.
- `python ci/check_stage3_readiness.py`: passed.
- `python ci/check_stage3_n3_evidence.py`: passed.
- `python ci/check_payload_terms.py dist/kolla/neutron-aria-stage2-acl-kolla-bundle.tgz`: passed.
- `python ci/check_blocked_terms.py`: passed.
- `git diff --check`: passed for this backlog patch; one unrelated pre-existing HTML line-ending warning remains outside this review change.
- `bash -n` over deploy/ci shell scripts using POSIX-style paths: 37 scripts passed.
- Continued targeted review of agent config, RPC event routing, incremental fallback, and CLI package smoke found `REVIEW-ACL-016` and `REVIEW-ACL-017`; `REVIEW-ACL-016` is now fixed by strict boolean parsing and config unit tests.
- `python -m unittest neutron_aria.tests.unit.test_config -v`: 27 tests passed after the strict RPC boolean parsing and sync-mode helper fix.
- `python -m unittest neutron_aria.tests.unit.test_config neutron_aria.tests.unit.test_status_reporter neutron_aria.tests.unit.test_service neutron_aria.tests.unit.test_rpc -v`: 64 tests passed for RPC/config/status/service coverage.
- `python -m compileall -q openstack/neutron_aria/neutron_aria openstack/neutronclient_aria/neutronclient_aria`: passed.
- `python ci/check_smoke_python_blocks.py`: passed, 89 embedded smoke Python blocks accepted.
- `bash -n` over tracked `deploy/` and `ci/` shell scripts: 37 scripts passed.
- `bash -n install.sh`: failed on CRLF line endings, recorded as
  `REVIEW-ACL-018` at that time. This is historical evidence; the current file
  is LF-only and passes the same check.

## Verification Refresh 2026-07-08

- `python ci\check_neutron_stage1.py`: passed; Rust checks skipped locally
  because `cargo` is unavailable.
- `python ci\check_neutron_stage2_acl.py`: passed.
- `python ci\check_blocked_terms.py`: passed.
- `git diff --check`: passed; only line-ending warnings were reported.
- `bash -n install.sh`: failed with CRLF syntax error, confirming
  `REVIEW-ACL-018` at that time. The 2026-07-11 classification supersedes this
  historical state.

## Verification Refresh 2026-07-10

- `agent/src/neutron_wal.rs` was inspected end to end: writes use
  `OpenOptions::append(true)` and replay scans every line; no compact,
  truncate, checkpoint, rotation, or size-bound path exists. This confirms
  `REVIEW-OPS-019` as a deterministic lifecycle bug even though no disk-full
  incident was reproduced locally.
- `agent/src/api_handlers/health.rs` always emits `status=ok` and the standalone
  WAL replay counter. No Kolla/deploy healthcheck currently points at that
  route, so `RISK-READY-001` is recorded as an operational guard gap rather
  than a currently active probe bug.
- `deploy/kolla/config/aria-agent-openstack.toml` explicitly documents
  `neutron_peercred_enforce=false` as an audit-only safe-bundle default pending
  the production hardening gate; recorded as `RISK-SEC-001`, not a hidden bug.
- `agent/src/main.rs` requires root, defaults HTTP to `127.0.0.1:8080`, and has
  no non-loopback validation or HTTP authentication layer; recorded as the
  bounded deployment risk `RISK-SEC-002`.
- At this refresh, Rust and Python already contained `effective_action`
  projection while `05-domain-status-heartbeat.md` still called the rich Rust
  field planned, confirming `REVIEW-DOC-020`; commit `b470f2f` later fixed the
  documentation mismatch.
- No local `cargo build`, `cargo check`, or `cargo test` was run, preserving the
  checkout policy.

## Verification Refresh 2026-07-10 Deep-Dive Pass 2 (3 rounds, record only)

Round 1 (recovery / pending):
- Confirmed restart hash-skip (`REVIEW-ACL-035`), post-commit RAM skip
  (`REVIEW-TXN-025`), startup recovery race (`REVIEW-TXN-026`), Python pending
  overwrite (`REVIEW-ACL-036`), scoped ready+dirty pending (`REVIEW-ACL-037`).

Round 2 (RPC/DB/CLI + eBPF authority):
- Confirmed port pagination hang (`REVIEW-ACL-038`), qos managed without payload
  (`REVIEW-ACL-039`), port-status TOCTOU (`REVIEW-ACL-040`), CLI member wipe
  (`REVIEW-ACL-041`), delete_address_set split txn (`REVIEW-ACL-042`),
  priority=0 falsy require (`REVIEW-ACL-043`), metadata bank flip
  (`REVIEW-ACL-044`), orphan no scrub (`REVIEW-ACL-045`), selected-domain group
  behavior (`REVIEW-ACL-046`, field-verified and fixed on 2026-08-11), ignored
  priority (`REVIEW-ACL-047`), delete detach/commit split
  (`REVIEW-TXN-027`).

Round 3 (contract / status / CT / CI):
- Confirmed bypass→enforce overwrite (`REVIEW-ACL-048`), unwired domains wedge
  ACL (`REVIEW-ACL-049`), ACL without CT foundation check (`REVIEW-ACL-050`),
  WAL recovery false-pass (`REVIEW-ACL-051`), update-error state preservation
  (`REVIEW-ACL-052`, closed as unsupported as written on 2026-07-11), lenient
  ct_flush (`REVIEW-ACL-053`), ignored stateful (`REVIEW-ACL-054`), capabilities
  lie (`REVIEW-DOC-021`), smoke zero-port pass (`REVIEW-OPS-035`), marker-heavy
  CI (`REVIEW-CI-001`).
- No code fixes were applied in any of the three rounds.

Round 4 (TC conntrack fast path):

- Confirmed that the live TC ingress/egress paths do not call the existing TC
  CT lookup, fast-path, or accepted-flow creation helpers
  (`REVIEW-ACL-055`). This is both a per-packet performance gap and a stateful
  behavior inconsistency relative to XDP.

## Verification Refresh 2026-07-11 Classification

- `PYTHONPATH=openstack/neutron_aria python3 -m unittest discover -s
  openstack/neutron_aria/neutron_aria/tests -p 'test_*.py'`: 231 tests passed.
- Legacy `neutronclient_aria` suite: four tests skipped because
  `python-neutronclient` is not installed; this remains `REVIEW-ACL-005`.
- `bash -n install.sh`: passed; `REVIEW-ACL-018` is fixed.
- `python3 -m compileall`, Neutron stage checks, embedded Python smoke checks,
  and tracked deploy/CI shell syntax checks passed.
- No local `cargo build`, `cargo check`, or `cargo test` was run, preserving the
  checkout policy. Rust findings remain source/contract-confirmed rather than
  locally compiled fault-injection reproductions.

## ACL Batch 3 Verification

- Red GitHub Actions run `29156442219` failed only on the intentionally missing
  restart invalidation helper and strict control-plane CT method.
- Intermediate run `29156544341` proved the restart implementation compiled;
  its only remaining error was the intentionally missing strict CT method.
- Green GitHub Actions run `29156695151` passed Stage 1/2/3 contracts, Rust
  Neutron attach-authority tests, eBPF build, static userspace build, static
  agent build, and binary verification.
- `PYTHONPATH=openstack/neutron_aria python3 -m unittest discover -s
  openstack/neutron_aria/neutron_aria/tests/unit -p 'test_*.py'`: 250 tests
  passed locally.
- No local Cargo command was run.

## ACL Batch 4 Verification

- Red GitHub Actions run `29157554289` failed on the intentionally missing
  `AclApplyPlan.conntrack_enabled`, `AclRuntimeFeatureState`, and
  `acl_runtime_transition` contracts.
- Green implementation run `29157662138` passed Stage 1/2/3 contracts, Rust
  Neutron attach-authority tests, eBPF build, static userspace build, static
  agent build, and binary verification.
- Local Stage 1 ran with Cargo deliberately absent from `PATH`: 250 Python
  tests and all static/shell checks passed. Stage 2 passed 120 Python tests.
- No local Cargo command was run.

## ACL Batch 5 Verification

- Formal Python RED run `29174377822` failed on the eight expected missing
  overlap/stable-reason contracts.
- Authorized Rust compiler RED probe `29174454194` failed only on the future
  `AclApplyPlan.force_bypass_reason` and `NeutronAclReconcileOutcome`
  interfaces: six `E0609` errors and one `E0433` error.
- Exact parser-parity RED run `29175746390` executed the persistent
  `neutron_acl_` filter and failed only the three expected whitespace tests:
  15 passed and 3 failed.
- Implementation GREEN run `29175882048` at final implementation commit
  `53e5ddfdd613fb0948b56e273adcdde5b372b061` passed the complete Build
  workflow, including `neutron_acl_`: 18 passed, 0 failed, 83 filtered out.
- Closure workflow run `29176402461` at guard/docs commit
  `2ebc46991334d75de22c0f8cf47e8e36a3c86e12` passed Stage 1/2/3, the
  persistent `neutron_acl_` filter (18 passed, 0 failed, 83 filtered out), eBPF,
  userspace static, agent static, and static-binary verification.
- Local full discovery passed 263 Python tests. Stage 1, with Cargo deliberately
  absent from `PATH`, passed the same 263 Python tests plus its static/shell
  checks. Stage 2 passed 133 Python tests, and Stage 3 checked 18 files.
- `check_blocked_terms.py` and `git diff --check` passed. No local Cargo command
  was run.

## ACL Batch 6 Verification

- RED guard commit `ca4165f082216a18993adfa5f3586baacb9762c7` and Build
  [29202608016](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/29202608016)
  failed at the expected missing real-tap smoke contract.
- GREEN implementation commit `00d47332bdd8076367c5bd9718c90c5156744cb4`
  exposed one ordinary embedded-Python smoke parsing defect in Build
  [29202845773](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/29202845773).
- Final bank-byte correction commit `cc9c6b574558d336b9a0bd894a52bca532293030`
  passed complete Build
  [29204885966](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/29204885966),
  including the exact diagnostic metric-label test, nightly eBPF build,
  static userspace/agent builds, binary verification, all Python stages, and
  the fail-closed smoke structure/mutation checks for the Neutron strict-flush
  bank contract and its exact same-flow CT byte reference.
- Local allowed gates passed: smoke `bash -n`, embedded Python extraction,
  TC datapath static checker, Stage 1/2/3 and evidence gates, and
  `git diff --check`. No local Cargo command was run.
- Real managed-tap execution was not available in this development
  environment. The 2026-07-13 all-mode design also supersedes the legacy
  standalone XDP path and records two final-review blockers. `REVIEW-ACL-055`
  was therefore still `in-progress` at that historical checkpoint;
  `REVIEW-ACL-056` remains open P1.

## ACL All-Mode TC Follow-Up Verification

- Initial RED commit `9c3b3ef2d9e41a721c005be6190c9a0164b529f5`
  and Build [29290357578](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/29290357578)
  failed at the intended missing standalone smoke contract.
- The first complete candidate Build
  [29291211798](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/29291211798)
  passed but is explicitly superseded: quality review found unsafe fixture
  ownership, tautological XDP-neutral evidence, incomplete restart proof, and
  unbounded shutdown.
- Review RED commits `95c8e709d19ae640f09fe80c7424a36610462cd6`,
  `65c340ee1dcae6fbbd2f602f4f996d4acbe349ab`, and
  `059f923a33922de41cd71e343565531f62956222` produced the intended failures in
  Builds [29292055118](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/29292055118),
  [29292895250](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/29292895250),
  and [29293113342](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/29293113342).
  Those gates reject resource collisions/foreign cleanup, missing exact
  `tc_ingress`/`tc_egress` packet-byte evidence, partial recovery proof,
  unbounded/invalid shutdown timeouts, one-way tracing, and denied-source
  routing in the allowed flow.
- The first code-complete checkpoint
  `5800940bcc54b5ec7bcb7cf35ee980492436addf` passed Build
  [29293162332](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/29293162332),
  but whole-branch review then found CT-only cache reuse, incomplete pinned
  runtime, partial global-config read, and cold-only restart evidence gaps.
- Hardening commit `758aae87d1b11d0f37689f4b46eb5b85f1b38da9`
  closed those gaps. Build
  [29296864168](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/29296864168)
  correctly rejected one stale Rust source contract; follow-up commit
  `89b81e94ac7a6aaaf98295132a9b09d556b99796` aligned that contract with the
  approved quiesced replay sequence.
- Final complete Build
  [29297316622](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/29297316622)
  passed Stage 1/2/3, targeted Rust authority/recovery tests, nightly eBPF,
  static userspace/agent builds, and binary verification.
- Final local allowed gates passed: 283 Stage 1 Python tests with Cargo absent
  from `PATH`, 153 Stage 2 tests, Stage 2/3 evidence, both TC smoke mutation
  checkers, the datapath mutation checker, 109 embedded smoke Python blocks,
  shell syntax, blocked terms, and `git diff --check`. No local Cargo command
  was run.
- This development environment did not provide a privileged Linux runner with
  the built artifacts. Standalone `MODE=system`, standalone `MODE=tap`, and
  managed-Neutron smoke scripts were therefore not executed here. Their
  missing summaries are pending evidence, not passes; `REVIEW-ACL-055` is
  `likely-fixed`, not `fixed`.
- Independent review also confirmed `REVIEW-OPS-036`: XDP hook health remains
  path-only and can false-pass for a detached-but-pinned link. It is recorded
  separately because XDP is ACL/CT-neutral and the DDoS domain is not yet
  implemented.

## Delivery Status and Remaining Fix Order After 2026-07-17 Closure

Keep the remaining work in narrow reviewable batches. Implementation batches
start with a failing regression or fault-injection test, change one invariant,
and pass the maintained-branch GitHub Build before the next batch starts. Batch
2C followed that design-first gate and passed its final hosted implementation
verification before the next batch started.

1. **Completed — Restore the merge gate:** `REVIEW-CI-002`,
   `REVIEW-CI-003`, and `REVIEW-CI-004` are fixed. The maintained v0.9 PR
   trigger, required `build` check, fail-closed Rust change detector, and
   `repr(C)` Pod guard are active.
2. **Completed — Make readiness truthful:** `REVIEW-TXN-028` and
   `REVIEW-TXN-029` are fixed. Python requires complete terminal identity and
   domain evidence; Rust preserves non-authoritative inventory failures through
   a verified two-stage WAL recovery sequence with a fresh phase-2 replay gate.
3. **Completed — Versioned Rust-Python status contract (Batch 2C):** the
   approved design in
   `16-versioned-rust-python-status-contract.md` now has one shared 14-scenario
   artifact, typed Rust projection, strict Python V1/Legacy adapters, durable
   classified-versus-feature-ready tracks, action gating, and a Stage 1 drift
   checker. Local Python/static gates and independent review are green. GitHub
   Actions Build
   [`29599301028`](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/29599301028)
   passed Rust authority tests, eBPF compilation, userspace/agent static builds,
   binary verification, and warning gates at exact implementation head
   `3c61187db25f557fcf2bff3fcd765f3d9ea0a5ce`.
4. **Completed - Isolate ACL selector ownership:**
   `REVIEW-ACL-046` implementation and hosted CI are complete. Transaction
   implementation commit `49081c6` is followed by pre-field wiring/hardening
   commits `d1aa523..ad30cad`, covering managed detach ordering, purge-failure
   atomicity, strict-flush rollback, and successful retry detach. Independent
   final review approved the wiring. Exact-head GitHub Actions run
   [`29672271181`](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/29672271181)
   at `ad30cad` passed `fast-contracts`, `rust-behavior`, and `rust-build`.
   Privileged standalone evidence passed on 2026-08-06. Real Neutron-managed
   exact, more-specific, and injected-legacy-pollution scenarios passed on both
   available compute nodes on 2026-08-11, including CT invalidation, restart,
   cleanup, and independent OVS safety checks. The sanitized record is
   `docs/evidence/openstack-n05-lite/20260811-acl046-managed-selector-isolation/summary.md`.
   `REVIEW-ACL-046` is fixed; the unavailable third compute remains a separate
   P5 environment constraint.
5. **Implementation and hosted CI complete — Unify direct ACL publication:**
   `REVIEW-ACL-057` and its referenced-group subfinding `REVIEW-ACL-066` now
   use one strict final-state shadow-bank transaction. RED Build
   [`29682513348`](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/29682513348)
   failed only on the intended missing boundary; exact-head GREEN Build
   [`29683492746`](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/29683492746)
   passed the six focused Rust behaviors and the warning-denied Rust/eBPF
   builds. These commits now share the same direct `v0.9-neutron-agent`
   delivery history as the former PR #5 batch; exact-head CI replaces the
   earlier stacked delivery. `REVIEW-ACL-059` was subsequently completed in
   `65fedfb`; `REVIEW-ACL-056` implementation and hosted CI are also complete.
6. **Source implementation and hosted CI complete; field evidence pending —
   remaining standalone group durability:** production commit `2ed4a52` now
   provides ordinary unreferenced-group strict persistence and exact rollback.
   Exact-head Build
   [`30378197930`](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/30378197930)
   passed the seven focused behaviors and warning-denied Rust/eBPF/static
   builds. Keep `DEBT-ACL-001` open because the four-map transaction has not
   been exercised against real pinned maps; that evidence and ACL-056
   privileged smoke both remain `deferred/pending`. Stop here rather than
   beginning the following P2 batch.
7. **Completed — Reject invalid desired state at write time:**
   `REVIEW-ACL-058` and `REVIEW-ACL-061` are fixed in `bad6731`. One strict
   final-state layer now covers all repositories; named database constraints
   arbitrate concurrent enabled-key conflicts; malformed input returns 400 and
   conflicts return 409. Exact-head Build
   [`30598232712`](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/30598232712)
   passed 504 fast contracts and change detection.
8. **Source complete; privileged ACL-045 evidence deferred — close transaction
   and recovery debt:**
   `REVIEW-OPS-019` is fixed in `c3d8238`, `REVIEW-ACL-025` is fixed in
   `4dca970`, and the stale `REVIEW-ACL-026` / `REVIEW-ACL-044` Register rows
   are now closed against the concrete publication transaction delivered by
   `4160f73`. `REVIEW-ACL-023` source behavior and hosted CI are also complete
   in `49081c6` / `ad30cad`; its privileged purge evidence remains deferred
   with `REVIEW-ACL-065`. `REVIEW-TXN-024` is fixed in `95c440a`, and
   `REVIEW-TXN-027` is fixed in `efb113c` with exact-head GREEN Build
   [`30612826096`](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/30612826096).
   The stale `REVIEW-TXN-026` row is also closed: `933d1af` and `f6e0f9b`
   already serialize startup recovery with snapshot admission/application,
   while `d7db9ec` and exact-head Build
   [30696668251](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/30696668251)
   provide the missing concurrent behavior evidence.
   The initial `REVIEW-ACL-045` source repair is delivered in `8242c1b`.
   Target-kernel field RED later exposed the legacy-TC detach gap; `b18dd3c`
   and hosted Build `31154605848` closed it. The isolated field rerun passed
   complete map scrub, retry-marker, sibling-preservation, and owned legacy-TC
   detach checks. Do not fold the remaining production defects into one
   implementation commit.
9. **Completed — Remove apply-loop stalls and pending corruption:**
   `REVIEW-ACL-036`, `REVIEW-ACL-037`, `REVIEW-ACL-028`,
   `REVIEW-ACL-008`, and `REVIEW-ACL-033` are fixed in Python production
   commit `2bd1726`; GREEN Build
   [`30615746741`](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/30615746741)
   passed 176 targeted tests and all 515 fast contracts. `REVIEW-OPS-037` is
   fixed in Rust production commit `f6e0f9b`; commit `4b02277` ensures both new
   behaviors execute through the maintained hosted filter. Combined exact-head
   Build
   [`30616520693`](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/30616520693)
   passed `fast-contracts`, the named OVS admission behaviors, and
   warning-denied Rust/eBPF/static builds. None of these six fixes requires
   privileged field evidence.
10. **Completed — Finish API/client correctness:** `REVIEW-ACL-060` is fixed
   at `3999e49`, together with `REVIEW-ACL-004/005`; `REVIEW-ACL-062` is fixed
   at `44743f5` with exact-head GREEN Build
   [`30683913104`](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/30683913104).
   `REVIEW-CLI-001` is fixed at `91edc43` with exact-head GREEN Build
   [30693519106](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/30693519106).
   `REVIEW-DOC-022` is fixed at `fb74ba8`; RED Build
   [30693943116](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/30693943116)
   exposed the missing route and GREEN Build
   [30694029883](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/30694029883)
   is the exact implementation-head closure evidence. `REVIEW-ACL-038` and
   `REVIEW-ACL-040`-`REVIEW-ACL-042` are fixed in `d42b83d..ecfbea9`; RED Build
   [30696036575](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/30696036575)
   exposed the four boundaries and exact-head GREEN Build
   [30696145624](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/30696145624)
   passed fast and database contracts. No Rust/eBPF source changed, so the Rust
   jobs correctly skipped. The stale `REVIEW-ACL-003` row is also closed:
   `bad6731` already supplied the complete create/update transaction, and
   `ff6cc1f` plus exact-head Build
   [30696458677](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/30696458677)
   prove rollback of both parent metadata and members under injected member
   write failure. Continue with step 11.
11. **Complete evidence and lower-risk hardening:** `REVIEW-ACL-007` is fixed
    by `e86df74`; the installer now records an explicit first-install `.none`
    preimage and rollback removes both the new egg and its path entry. RED Build
    [30697430555](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/30697430555)
    exposed the missing marker, and exact-head GREEN Build
    [30697466610](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/30697466610)
    passed the package transaction smoke and the full required build path.
    At that point this did not close `REVIEW-ACL-012`, whose clean-container
    import/entrypoint evidence was still pending. RED Build
    [30702727302](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/30702727302)
    later proved imports succeeded but the console script was absent; `b1015ce`
    added transactional entrypoint install/rollback, and exact-head Build
    [30702872608](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/30702872608)
    closed `REVIEW-ACL-012` with the real Python 2.7 clean-container lane and
    the complete required build. `REVIEW-OPS-035` is also fixed:
    `f19e03f` makes non-zero managed-port coverage and both port transaction
    cut points mandatory before the transaction smoke can report success.
    RED Build [30698108346](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/30698108346)
    exposed all three skipped paths, while exact-head GREEN Build
    [30698215982](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/30698215982)
    passed the new executable smoke contract and the complete required build.
    `REVIEW-ACL-010` is fixed by `d079ec1`: the DB/REST CRUD smoke now sources
    and forwards one resolved adminrc path, including a caller-provided path.
    RED Build [30698677693](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/30698677693)
    proved the old split, and GREEN Build
    [30698743828](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/30698743828)
    passed the executable contract plus the complete required build.
    `REVIEW-ACL-015` is fixed by `1742c9a`: first policy installation records a
    `.none` preimage and rollback removes the smoke-created file. RED Build
    [30699371375](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/30699371375)
    exposed the missing marker; GREEN Build
    [30699433259](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/30699433259)
    passed the executable transaction contract and complete required build.
    `REVIEW-ACL-017` is fixed by `bffd831`: the legacy CLI smoke validates and
    forwards one caller-selectable adminrc path. RED Build
    [30699715441](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/30699715441)
    exposed the hard-coded path; GREEN Build
    [30699749054](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/30699749054)
    passed both adminrc behaviors and the complete required build.
    `REVIEW-OPS-034` is fixed by `064e6d3`: capability timeout validation no
    longer mutates the configured UDS client default, and the stricter server
    value is passed only to the coupled port-scoped PUT. RED Build
    [30700167616](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/30700167616)
    captured the leaked timeout; exact-head GREEN Build
    [30700243216](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/30700243216)
    passed all Python, DB, and public contract checks. No privileged evidence
    applies to this client-only repair.
    `REVIEW-ACL-014` is fixed by `2cff9c4`: all validation and build jobs now
    inherit `contents: read`, while the only `contents: write` grant belongs to
    a separate `push` + `refs/tags/v*` release job. RED Build
    [30701055296](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/30701055296)
    exposed the workflow-wide grant; exact-head GREEN Build
    [30701143632](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/30701143632)
    passed the full hosted build and proved the release job stays skipped on a
    normal branch push. No synthetic tag or release was created.
    `REVIEW-OPS-027` is fixed by `fa1e326`: replay now separates recoverable
    malformed record contents from a genuine reader failure, continues to later
    valid commits with `replayed_with_errors`, and retains the fail-closed unread
    tail boundary. RED Build
    [30701699907](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/30701699907)
    exposed the premature stop; exact-head implementation Build
    [30701829923](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/30701829923)
    passed all selected WAL behaviors and warning-denied builds.
    `REVIEW-DOC-020` is fixed by `b470f2f`: the former future-looking detail
    plan is now an implementation-backed Status V1 reference covering typed
    Rust evidence, strict Python/legacy compatibility, heartbeat aggregation,
    and product status projection. RED Build
    [30702240495](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/30702240495)
    rejected the stale claims; exact-head GREEN Build
    [30702418132](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/30702418132)
    passed the fast-contract and Neutron DB lanes. `REVIEW-ACL-013` source
    implementation is now complete in `133b52b`: exact current-host identity,
    conservative stale/mismatch handling, batch projection, and core-read
    fail-soft behavior passed GREEN Build
    [30703680367](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/30703680367).
    Commit `0b32d4b` wires the real legacy `neutron port-show` smoke, but its
    hosted Build
    [30703735814](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/30703735814)
    and Python 2.7 clean-container Build
    [30703793706](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/30703793706)
    do not replace the target smoke; its Neutron 9 execution remains
    `deferred/pending`.
    `REVIEW-CI-001` is fixed by `5d7fcfc`: required Python behavior is tied to
    real `unittest` discovery without a second selected suite; every Cargo
    filter must execute a non-zero test count; the domain contract is checked
    at Rust runtime/advertisement and Python request boundaries; and static or
    committed historical evidence can no longer label itself current runtime
    readiness. RED Build
    [30704754808](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/30704754808)
    captured the old false-green boundary, while exact implementation-head
    Build
    [30704906357](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/30704906357)
    passed every required hosted lane. `RISK-SEC-002` and `RISK-READY-001`
    remain independent high-priority production-hardening batches; they are not
    part of this CI closure.
    Also close
    `REVIEW-ACL-055` only after the three privileged summaries pass. The
    `REVIEW-OPS-036` source fix and hosted CI are complete, but its guarded
    detached-pin target-kernel smoke remains an XDP/DDoS activation gate. Then
    handle package, smoke, projection, documentation, and release-hygiene P3
    items.

Risk follow-up remains separate from active bug fixing:

- `REVIEW-ACL-032`: expose notifier fallback and bound periodic convergence.

12. **Open — 2026-08-13 full-code bug-hunt batch:** 33 findings recorded as
    `REVIEW-ACL-075..099`, `REVIEW-TXN-031..035`, and `REVIEW-OPS-038..040`.
    After an independent re-verification pass the register now holds:
    seven P1 (`REVIEW-ACL-075/076/077`, `REVIEW-TXN-031/032/033`,
    `REVIEW-OPS-038`), with `REVIEW-ACL-087` merged into `REVIEW-ACL-075`,
    `REVIEW-ACL-081/092/095` withdrawn, `REVIEW-ACL-088` reclassified as
    defensive API debt, `REVIEW-ACL-083/084` and `REVIEW-TXN-035` marked
    conditional, and the remaining rows narrowed to verified impact. Batch by
    severity; the P1 set must be reviewed against the RC before production
    activation.

Verification and closure follow-up:

- `REVIEW-ACL-012`: fixed by the clean-container entrypoint transaction and
  exact-head Build 30702872608.
- `REVIEW-ACL-016` and `REVIEW-ACL-018`: fixed.
- `REVIEW-ACL-052`: closed as unsupported as written; reopen only with a
  Neutron-managed invariant violation reproduction.
