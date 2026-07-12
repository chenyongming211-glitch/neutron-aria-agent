# Review Bug Backlog

Status: open review backlog.

Date: 2026-07-03; refreshed 2026-07-10 (deep-dive); re-verified 2026-07-12;
ACL transaction Batch 2, restart/CT safety Batch 3, and stateful/CT contract
Batch 4 closed 2026-07-11; priority/overlap Batch 5 closure recorded
2026-07-12; TC-unified ACL/CT Batch 6 is likely fixed in code pending real-tap
evidence, and its separate fragment defect is recorded open.

Scope rule:

- Fix bugs and contract gaps discovered during review.
- Do not use this backlog to add new ACL/QoS/Mirror product features.
- Prefer API/config validation and narrowly scoped tests over new behavior.
- Record-only updates are allowed without expanding product scope.

## 2026-07-12 Source Re-Verification And Classification

Full re-check of all recorded `REVIEW-*` IDs against the current tree, followed
by ACL contract-guardrail Batch 1, transaction Batch 2, restart/CT safety Batch
3, stateful/CT contract Batch 4, and priority/overlap Batch 5 closure. The
`REVIEW-*` prefix remains a stable historical identifier and no longer implies
that the item is an open implementation bug by itself.

| Verdict | Count | IDs |
| --- | ---: | --- |
| Confirmed active defect or contract gap | 34 | Remaining open register rows, including the new fragment defect |
| Likely fixed; operational evidence pending | 1 | `REVIEW-ACL-055`: code/static gates implemented; real-tap smoke pending |
| Fixed | 23 | `REVIEW-ACL-016`, `REVIEW-ACL-018`, 13 ACL Batch 1 IDs, 3 transaction Batch 2 IDs, 2 Batch 3 IDs, 2 Batch 4 IDs, and `REVIEW-ACL-047` in Batch 5 |
| Verification needed | 1 | `REVIEW-ACL-012`: implementation path is present; clean-container evidence is still required |
| Reclassified as risk/design boundary | 2 | `REVIEW-ACL-032`, `REVIEW-ACL-046` |
| Closed: finding not supported as written | 1 | `REVIEW-ACL-052` |
| **Total `REVIEW-*` IDs** | **62** | Stable IDs retained for audit history |

The 35 active or evidence-pending items are grouped by failure surface so that
runtime bugs are not mixed with delivery and documentation gaps:

| Active class | Count | IDs |
| --- | ---: | --- |
| Transaction, datapath, recovery, and runtime consistency | 17 | `ACL-023`, `ACL-025`, `ACL-026`, `ACL-028`, `ACL-033`, `ACL-036`, `ACL-037`, `ACL-044`, `ACL-045`, `ACL-055`, `ACL-056`; `TXN-024`, `TXN-026`, `TXN-027`; `OPS-019`, `OPS-027`, `OPS-034` |
| Northbound API, DB, compile, and status projection correctness | 8 | `ACL-003`, `ACL-004`, `ACL-008`, `ACL-013`, `ACL-038`, `ACL-040`-`ACL-042` |
| Packaging, deployment, validation, documentation, and release gaps | 10 | `ACL-005`, `ACL-007`, `ACL-010`, `ACL-011`, `ACL-014`, `ACL-015`, `ACL-017`; `DOC-020`; `OPS-035`; `CI-001` |
| **Total active defect, gap, or evidence-pending item** | **35** | Includes `REVIEW-ACL-055` until real-tap evidence closes it |

Remaining active P1 set: `ACL-055`, `ACL-056`, and `OPS-019`.

Also spot-checked: `ACL-004` (host=None returns `status[0]`), `ACL-014`
(workflow `contents: write`), `ACL-015` (plugin policy backup only when file
exists), `ACL-017` (CLI installer hard-codes `/etc/kolla/.adminrc`) — all still
present.

Risk tracking now contains seven classified items: five existing `RISK-*` IDs
plus reclassified `REVIEW-ACL-032` and `REVIEW-ACL-046`. Engineering debt
remains four `DEBT-*` IDs. The unique tracking-item total is now 71.

| Current tracking portfolio | Count | Included states |
| --- | ---: | --- |
| Active defect or contract gap | 35 | Open or likely-fixed `REVIEW-*` register rows pending closure evidence |
| Risk / design boundary | 7 | Five `RISK-*` IDs plus two reclassified `REVIEW-*` IDs |
| Engineering debt | 4 | `DEBT-*` IDs |
| Verification needed | 1 | `REVIEW-ACL-012` |
| Fixed | 23 | Two earlier fixes plus 13 ACL Batch 1, three transaction Batch 2, two Batch 3, two Batch 4, and one Batch 5 fix |
| Closed / unsupported finding | 1 | `REVIEW-ACL-052` |
| **Total unique tracking items** | **71** | Includes the Batch 6 fast-path and fragment findings |

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

### ACL TC-Unified Datapath Batch 6 Evidence State

| IDs | Evidence state |
| --- | --- |
| `ACL-055` | **Likely fixed, not operationally closed.** Neutron-managed ACL/CT now uses bank-aware TC ingress and egress; TC-mode XDP bypasses ACL/CT; routine CT diagnostic events require a matching Trace filter while stale-bank remains unconditional; enforcement publication requires both TC links. GREEN Build [29204885966](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/29204885966) passed the exact Rust metric test, nightly eBPF build, static userspace/agent builds, binary verification, Python stage gates, and fail-closed smoke structure/mutation checks, including strict-flush bank handling and exact same-flow CT byte accounting. `real-tap smoke pending`: a successful managed-tap `summary.json` is still required before changing this item to `fixed`. |
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
- `REVIEW-ACL-025`: `replace_owned_acl` switches the active ACL bank before
  instance WAL compact; compact failure diverges live maps from disk state.
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
| RISK-READY-001 | high | readiness boundary | open | `/api/v1/health` always returns `status=ok` and exposes the standalone WAL replay counter, not Neutron authority, pending/applied generation, or per-domain degraded/blocked state. Current deployment files do not use this route as a readiness probe, and the architecture explicitly separates liveness from readiness, so this is a missing operational guard rather than a currently reproduced deployment bug. | Add a Neutron-aware `/readyz` or a documented probe that evaluates `/api/v1/neutron/status`, per-domain action, heartbeat, and generation convergence. Add a negative probe test for pending, degraded, and blocked states before wiring it into deployment health checks. |
| RISK-SEC-001 | high | UDS authentication | open | The UDS is mode `0660`, but the packaged OpenStack config intentionally keeps `neutron_peercred_enforce=false` with empty allow-lists. The config labels this audit-only behavior as a production-hardening gate, so it is not an accidental implementation bug; production enablement without closing the gate would be unsafe. | Produce a production profile with the discovered Neutron agent UID/GID allow-list, require peer credentials, fail startup on an empty enforced allow-list, and keep reversible hardened-rollout smoke coverage. |
| RISK-SEC-002 | high | privileged management API | open | `aria-agent` requires root and the HTTP management router has no authentication layer. The packaged address is loopback-only, which is the current safety boundary, but `listen_addr` has no validation preventing a non-loopback bind. | Keep the packaged listener on loopback or a protected namespace; reject non-loopback binds unless an explicit unsafe/secured mode is configured, and document the root-process blast radius. |
| RISK-BOUNDARY-001 | high | ACL failure semantics | open | ACL degraded/not-requested paths intentionally use `effective_action=bypass` so OVS forwarding continues. This is availability-first behavior, not a code bug, but becomes a security defect if operators or northbound consumers interpret Aria ACL as fail-closed enforcement or Security Group replacement. | Keep the OVS-enhancement boundary in API/docs/runbooks, alert on degraded+bypass ports, and require acceptance checks to inspect domain status and `effective_action` rather than connectivity alone. |
| REVIEW-ACL-032 | medium | RPC delivery and observability | reclassified-risk | RPC notify failure or notifier initialization fallback can delay ACL convergence until periodic full resync. Periodic full resync is the documented lost-RPC/drift fallback, so this is not a correctness bug while that fallback and its latency objective remain enabled; silent no-op initialization is still an observability risk. | Alert or expose status when the notifier falls back to no-op, test periodic recovery, and define the maximum acceptable convergence delay. Reopen as a bug only if production disables or violates the fallback contract. |
| REVIEW-ACL-046 | medium | domain authority boundary | reclassified-risk | `ensure_local_group_write_allowed` intentionally blocks `neutron:*` group names while allowing non-Neutron groups, and existing authority tests encode that selected-domain behavior. No evidence currently shows a non-Neutron group mutation changing effective Neutron ACL rules. | Document the selected-domain coexistence boundary and add an isolation test proving non-Neutron groups cannot alter Neutron-owned enforcement. Reopen as a bug if cross-domain map interference is reproduced. |
| DEBT-MAINT-001 | medium | source modularity | open | `agent/src/neutron_api.rs` is about 5.4k lines and `agent/src/control_plane.rs` about 3.4k lines. Snapshot transactions, ACL translation, status projection, recovery, and control-plane mutation are concentrated in large modules. This is maintainability and review-risk debt, not a reproduced behavior bug. | Split along existing contract boundaries without changing behavior: snapshot transaction/recovery, ACL translator/executor, status projection, and domain authority. Preserve focused contract tests during extraction. |
| DEBT-CI-001 | medium | verification breadth | open | CI runs Python/stage gates, selected Rust Neutron tests, eBPF and static builds, but has no full Rust workspace test job and no dedicated clippy, rustfmt, Python linter, or shellcheck gate. | Add separate CI jobs for full workspace tests and static analysis; keep the existing targeted gates for fast contract feedback. Follow the repository rule that Rust compilation remains in GitHub Actions rather than local development runs. |
| RISK-CI-001 | medium | workflow supply chain | open | Actions are referenced by version tags such as `actions/checkout@v4` rather than immutable commit SHAs. Workflow-wide write permission is separately tracked by `REVIEW-ACL-014`. | Pin third-party actions to reviewed immutable SHAs and use automated, reviewed dependency updates. Close `REVIEW-ACL-014` independently by reducing default token permissions. |
| DEBT-RELEASE-001 | medium | release metadata and licensing | open | Workspace metadata remains `version=0.1.0` with placeholder author data while the product line is documented as v0.9. The manifest declares MIT, but no root `LICENSE` or `COPYING` file was found. | Define one release-version source, replace placeholder author metadata, add the intended license text, and add a release-hygiene CI check. |
| DEBT-REPO-001 | medium | repository and evidence hygiene | open | The repository tracks generated HTML/ZIP output, a roughly 4.6 MiB latest-build binary archive, and extensive field evidence containing environment hostnames and internal addresses. The current shared Git object store is roughly 211 MiB. This is repository/disclosure debt, not a runtime bug. | Move generated binaries and presentation bundles to CI artifacts/releases, retain only durable evidence summaries where possible, define evidence retention/redaction rules, and reuse `REVIEW-ACL-011` for public identifier scrubbing. |

## REVIEW Item Register

This register retains all 62 stable `REVIEW-*` IDs. Use the `Status` column,
not the ID prefix, to decide whether an item is an active defect, fixed,
verification-only, risk-classified, or closed.

| ID | Severity | Area | Status | Finding | Required fix |
| --- | --- | --- | --- | --- | --- |
| REVIEW-ACL-001 | P1 | ACL API/CLI/datapath contract | fixed | Neutron API and legacy CLI allow `default_action=deny`, but the Rust Neutron ACL translator rejects non-allow defaults. A user can create a policy that looks valid and later gets degraded/bypassed during apply. | For MVP, reject `default_action=deny` in server-side validation and CLI help/choices, or mark it explicitly unsupported until datapath default-deny support is implemented. Add API, CLI, and translator contract tests. |
| REVIEW-ACL-002 | P2 | ACL desired-state validation | fixed | Server-side create/update accepts multiple enabled bindings for the same `(target_type, target_id)` and duplicate rule priorities inside a policy/direction. Effective ACL later degrades to bypass. | Reject conflicting enabled binding writes with 409/validation error. Reject duplicate enabled rule priority per `(policy_id, direction)`. Add repository/plugin tests for create and update paths. |
| REVIEW-ACL-003 | P2 | ACL DB transactionality | open | Neutron DB address-set writes update the main address-set row and members in separate transactions. A mid-operation failure can leave the main row updated while members remain stale. | Wrap address-set create/update/delete plus member replacement/removal in one transaction. Add a failure-injection/unit test that proves no partial member state is committed. |
| REVIEW-ACL-004 | P3 | Port runtime status API/CLI | open | `aria_acl_port_statuses` is keyed by `(port_id, host)`, but `get_aria_acl_port_status(port_id, host=None)` returns the first row, and legacy CLI show has no `--host` selector. Multi-host or detached retained rows can be misleading. | Require host for single-row show when multiple rows exist, or return a clear ambiguity error/list. Add CLI/API tests for multi-host status rows. |
| REVIEW-ACL-005 | P3 | Legacy neutron CLI test coverage | open | Local `neutronclient_aria` unit tests skip when legacy `python-neutronclient` is absent, so CI can miss CLI command regressions outside onsite smoke. | Add a small fake/stub test path that exercises command body construction without a real neutronclient install, or add a legacy container CI job. Keep onsite smoke as integration evidence. |
| REVIEW-ACL-006 | P2 | Neutron REST error semantics | fixed | Repository failures such as `AriaAclValidationError` and `AriaAclNotFound` are plain Python exceptions. The service plugin passes them through directly, so old Neutron controllers can expose invalid requests or missing resources as HTTP 500 instead of 400/404. | Add a legacy-Neutron-compatible exception mapping layer in the plugin or exception classes. Cover missing policy, invalid binding target type, duplicate/unsupported writes, and missing object show/delete with API-level tests. |
| REVIEW-ACL-007 | P2 | Kolla package rollback | open | `install_neutron_aria_agent_egg.sh` only records a rollback backup when an old egg exists. First-time installs leave no "none" marker, so rollback fails instead of removing the newly installed agent egg. The CLI package installer already handles this correctly. | Mirror the CLI installer behavior: write a `.none` marker when no previous agent egg exists, and on rollback remove the agent egg and `easy-install.pth` entry. Add shell/unit smoke coverage for first-install rollback. |
| REVIEW-ACL-008 | P3 | Port status consistency | open | If a host was previously ready and a later full resync becomes globally degraded, `mark_degraded()` keeps old `last_port_statuses`. The port-status reporter can continue writing old per-port rows as `ready/enforce` while the agent heartbeat is degraded. | On global degraded, either mark existing ACL port statuses as degraded with the global reason or suppress per-port status writes until the next successful apply. Add a regression test with ready status followed by local API/ACL-source degraded. |
| REVIEW-ACL-009 | P1 | ACL rule API/datapath contract | fixed | The API/CLI accept rule fields that the Rust translator does not support yet, including source-port matching, IPv6 ethertype/CIDRs, and unvalidated protocol/action values. `EffectiveAclIndex` can mark such rules `ready/enforce`, but datapath apply later fails and the port falls back to degraded/bypass. | Add server-side and CLI validation for the current MVP-supported rule subset, and make `EffectiveAclIndex` return degraded/unsupported before submit for unsupported fields. Cover source-port, IPv6, unknown protocol, unknown action, and bad port range cases. |
| REVIEW-ACL-010 | P3 | Stage-two smoke reliability | open | `neutron_aria_acl_db_crud_smoke.sh` sources an adminrc file but never defines `ADMIN_RC_FILE`; later it runs `docker exec --env-file "${ADMIN_RC_FILE}"` under `set -u`. On a clean host without that variable already exported, the CRUD smoke can fail before testing ACL. | Add the same `ADMIN_RC_FILE="${ADMIN_RC_FILE:-/etc/kolla/.adminrc}"` default used by the CLI/live smokes, or derive it from the sourced adminrc path. Add shellcheck or a smoke syntax check for unset variables. |
| REVIEW-ACL-011 | P3 | Public release hygiene | open | A repository-wide sensitive-term scan did not find the previously blocked product acronym or environment password, but public-facing docs/metadata still contain personal repository/email and environment hostname identifiers. | Scrub or generalize public docs/metadata before public release. Keep the blocked-term CI gate, and extend it to cover agreed public-release identifiers without recording the sensitive strings in this backlog. |
| REVIEW-ACL-012 | P1 | Kolla agent package install | verification-needed | Earlier review found egg copy without path update. Current `install_neutron_aria_agent_egg.sh` calls `refresh_easy_install_pth` after copy, so no active source defect is confirmed. Fresh containers without prior path state still need a clean-container smoke to prove import/entrypoint; first-install rollback remains covered by `REVIEW-ACL-007`. | Run a clean-container package smoke starting with no previous egg and no path entry. Close after evidence succeeds; reopen as a defect only if that smoke fails. |
| REVIEW-ACL-013 | P3 | Neutron port extension projection | open | The extension declares read-only `ports` fields such as `aria_acl_enabled`, `aria_acl_effective_policy_id`, and `aria_acl_runtime_status`, and product docs show them in `port-show`; review found only attribute declaration, not a Neutron port-dict extension hook that fills those values from effective ACL and `aria_acl_port_statuses`. | Either implement the legacy Neutron port extension hook/populator and smoke `neutron port-show`, or narrow the MVP contract to the explicit `aria-acl-port-status*`/effective APIs until port projection is implemented. |
| REVIEW-ACL-014 | P3 | GitHub release permissions | open | `.github/workflows/build.yml` grants `contents: write` at workflow scope, so normal push/PR validation jobs run with broader repository token permissions than they need. Artifact upload does not require repository content write; only tag release creation needs it. | Set default workflow permissions to read-only and grant `contents: write` only to the release job/step that creates GitHub Releases. Keep artifact upload unchanged. |
| REVIEW-ACL-015 | P3 | Plugin loader rollback | open | `neutron_aria_acl_plugin_load_smoke.sh` backs up `policy.json` only when it already exists. If the install creates a new policy file and rollback is requested, rollback restores `neutron.conf` and package state but leaves the newly created policy file in place. | Mirror the package rollback marker pattern: record a "no previous policy file" marker and remove the smoke-created policy file during rollback. Add first-install rollback coverage for the plugin loader. |
| REVIEW-ACL-016 | P2 | Agent config safety | fixed | Boolean config parsing accepted only known true values and treated every other non-empty string as `false`. A typo such as `full_resync_enabled = ture` silently disabled ACL submit and left the agent in heartbeat-only/degraded mode instead of failing fast with a config error. | Fixed in `agent/config.py`: `full_resync_enabled`, `rpc_events_enabled`, and `incremental_rpc_enabled` now use strict boolean parsing and raise `ConfigError` with section/option/value on invalid values. Unit tests cover typo cases. |
| REVIEW-ACL-017 | P3 | Legacy CLI package smoke | open | `install_neutronclient_aria_cli.sh` hard-codes `/etc/kolla/.adminrc` during command-discovery smoke, while other ACL smokes allow `ADMIN_RC_FILE` override. Sites with a different Kolla/adminrc location can install the CLI package but fail the built-in smoke for an avoidable path assumption. | Add `ADMIN_RC_FILE="${ADMIN_RC_FILE:-/etc/kolla/.adminrc}"` to the installer and use it in smoke, with a clear error if the file is missing. Add a shell smoke/syntax check that exercises a custom adminrc path. |
| REVIEW-ACL-018 | P2 | Root install script | fixed | Earlier review found CRLF line endings that broke `bash -n install.sh` on Linux. Current tracked `install.sh` is LF-only and `bash -n install.sh` passes. | Keep the implementation item closed. Track the missing root-installer regression gate under CI verification debt. |
| REVIEW-OPS-019 | P1 | Neutron WAL lifecycle | open | `agent/src/neutron_wal.rs` appends snapshot/delete intent and full-state commit records and replays every valid line, but has no checkpoint, compaction, truncation, size bound, or rotation. Repeated full resync and scoped apply make the WAL grow without bound and increase restart replay cost. | Add atomic checkpoint/compaction with directory fsync, retain enough intent/commit information for crash recovery, define size/time thresholds, and add tests for compacted replay, crash during compaction, tampered latest records, and bounded file growth. |
| REVIEW-DOC-020 | P3 | Domain status documentation | open | `docs/openstack-neutron-aria-details/05-domain-status-heartbeat.md` lists rich Rust fields including `effective_action` as still planned, but `agent/src/neutron_api.rs` already emits `effective_action` and `agent/status.py` projects it into heartbeat summaries. | Refresh the detail document to distinguish implemented fields from remaining status work, and add a lightweight documentation/contract check for the current status DTO fields. |
| REVIEW-TXN-021 | P1 | Snapshot accept before WAL | fixed | Historical finding: snapshot admission returned accepted semantics before durable intent. Admission now fsyncs intent while holding the apply lock, returns `pending`, and leaves accepted/applied on the committed baseline. | Fixed with durable-intent and WAL-intent-failure Rust regression tests plus the permanent `neutron_snapshot*` CI test gate. |
| REVIEW-TXN-022 | P1 | Apply/commit metadata split | fixed | Historical finding: datapath could mutate before a failed commit while RAM/WAL retained the old classification. Commit failure now restores attach where possible, scrubs ACL to bypass, retains the failed pending generation, and enters blocked recovery. | Fixed with blocked-runtime/background-preservation tests and shared pre-commit/commit-failure recovery. |
| REVIEW-ACL-023 | P2 | Detach/delete ignores ACL purge failure | open | Snapshot detach and port-delete paths log `purge_neutron_acl` errors and continue, still returning `status=ok` / detached success. | Fail the detach/delete result (or mark port `degraded` with residual-ACL reason) when purge fails; add regression coverage for residual `neutron:{port_id}:*` objects. |
| REVIEW-TXN-024 | P2 | Background apply error non-durable | open | `mark_snapshot_background_error` only updates in-memory `authority_state`/`wal_status` when pending generation/hash still match. It does not append WAL, clear or converge pending, or roll back datapath. Restart loses the degraded classification; pending can wedge later snapshots with `409 snapshot_apply_in_progress`. | Persist failure/blocked state, define recover-pending behavior after background failure, and add tests for restart and subsequent submit. |
| REVIEW-ACL-025 | P2 | ACL bank switch before instance WAL compact | open | `ControlPlane::replace_owned_acl` calls `set_acl_active_bank` and updates in-memory `state.state` before `wal.compact`. Compact failure returns error after live enforcement already switched. | Reorder to durable compact (or dual-write intent) before activating the new bank, or activate only after compact success with compensating scrub. Add crash/compact-failure tests. |
| REVIEW-ACL-026 | P2 | Partial CIDR kernel writes without rollback | open | In `replace_owned_acl`, `add_network`/`delete_network` loops can return mid-flight via `?` before bank switch and before `state.state` update, leaving kernel maps partially mutated. | Stage CIDR mutations into the shadow bank only, or roll back partial network map writes on failure. Add mid-loop fault tests. |
| REVIEW-OPS-027 | P3 | WAL replay aborts on read I/O error | open | `NeutronWal::replay` breaks the line loop on `BufReader` read errors, skipping any later valid commits. JSON parse errors continue, so behavior is inconsistent. | Prefer continue/skip with `replayed_with_errors` for recoverable line errors, or hard-fail startup with an explicit blocked recovery state; never silently ignore the WAL tail. Add truncated-file and mid-file read-error tests. |
| REVIEW-ACL-028 | P2 | delete_port commits without response validation | open | `SnapshotSynchronizer.delete_port` does not call `_raise_if_response_failed`, always discards projection state, and `commit_delete`s after any non-timeout return. Runtime port statuses are not refreshed, so deleted ports can remain visible as ready/enforce until the next full resync. | Validate UDS delete outcome before local commit; on soft failure keep projection or mark degraded; clear/update `last_port_statuses`. Add unit coverage for failed delete bodies. |
| REVIEW-ACL-029 | P2 | Empty address-set compiles as ready | fixed | `EffectiveAclIndex._compile_address_match` accepts address sets whose members list is empty (or only empty addresses) and returns no compile error, so rules can be `ACL_READY`/`enforce` with empty CIDR lists. | Treat empty member sets as degraded/unsupported before submit; cover with effective-ACL unit tests. |
| REVIEW-ACL-030 | P2 | Disabled address-set still expanded | fixed | `_compile_address_match` checks missing address-set IDs but never `_enabled(address_set)`. Disabled sets still expand members into effective rules. | Reject or degrade rules that reference disabled address sets; add unit tests. |
| REVIEW-ACL-031 | P2 | Effective-for-port API hardcodes eligible | fixed | `AriaAclPlugin.get_aria_acl_effective_for_port` always calls `effective_for_port(..., {"eligible": True})`, so non-OVS/non-compute ports can appear ready/enforce from the API even when the agent would mark them unsupported/bypass. | Pass real eligibility (or document API as desired-state-only and return an explicit disposition field). Add plugin tests for ineligible ports. |
| REVIEW-ACL-032 | P2 | ACL RPC notify fallback visibility | reclassified-risk | `_notify_acl_change` logs notifier exceptions after DB success, and notifier initialization can fall back to `NoopAriaAclNotifier`. Agents then converge through the documented periodic full-resync lost-RPC fallback. This is a delivery-latency and observability risk, not a correctness bug while that fallback remains enabled and bounded. | Expose/alert no-op notifier state, test periodic convergence, and define a latency objective. Reopen as a bug if production disables or violates the fallback contract. |
| REVIEW-ACL-033 | P2 | Composite status reporter partial success | open | `CompositeStatusReporter.report` runs heartbeat then aria_acl port-status reporters sequentially. Heartbeat can succeed while port-status reporting raises, leaving Neutron agent-state and `aria_acl_port_statuses` divergent. | Make dual-channel reporting atomic from the caller's perspective (rollback/compensate, or report a combined failure that suppresses stale port-status reads). Add partial-failure unit tests. |
| REVIEW-OPS-034 | P3 | UDS client timeout permanently shrinks | open | `LocalClient._validate_capabilities` sets `self.timeout = min(self.timeout, timeout_ms/1000)`. Every port-scoped snapshot calls `capabilities()`, so later full-resync submits can run under a shorter timeout than configured. | Apply capability timeout as a per-request ceiling without mutating the configured client default, or reset after the call. Add a unit test that port-scoped traffic does not shrink later full-resync timeout. |
| REVIEW-ACL-035 | P1 | Restart hash-skip leaves ACL unenforced | fixed | Historical finding narrowed during implementation: attach replays or validates kernel state against the tap-local WAL, but that WAL has no shared commit identity with the Neutron ACL desired hash/status. Successful attach therefore could not prove that a same-hash Neutron ACL skip was safe. Restart reconcile now keeps attach ready, invalidates only the ACL domain hash, reports ACL `degraded` with `effective_action=unchanged`, persists `runtime_reconcile_requires_full_resync`, preserves stronger pending-recovery authority, and publishes the invalidated RAM state even if that WAL append fails. | Fixed with restart invalidation tests covering binding/hash preservation, pending-authority preservation, attach-ready plus ACL-degraded status, same-generation no-op rejection, and same-hash domain skip rejection. |
| REVIEW-TXN-025 | P1 | Post-commit RAM assign skipped | fixed | Historical finding: a post-commit error could skip RAM publication and recover-pending could regress the newer WAL commit. Commit now publishes RAM before the hook, return-error is a warning, and recovery refreshes from a newer valid WAL commit. | Fixed with post-commit finality, stale-RAM anti-regression, and blocked same-hash Python recovery tests. |
| REVIEW-TXN-026 | P2 | Startup recovery races accept path | open | `build_router` spawns `recover_incomplete_wal_intent` / `reconcile_committed_runtime` without gating UDS readiness. Recovery takes `apply_lock` and ends with full `*runtime = next_runtime`, while `accept_neutron_snapshot_submit` mutates pending/accepted under `runtime` write lock only (no apply_lock). | Gate snapshot accept until recovery completes, or make accept take the same apply/recovery barrier. Add concurrent accept-during-recovery test. |
| REVIEW-ACL-036 | P2 | Port-scoped prepare overwrites unresolved pending | open | `full_resync` calls `recover_pending_state()` first; `apply_port_scoped_snapshot` does not. Both `prepare_snapshot` / `prepare_scoped_snapshot` overwrite `pending_generation`/`pending_desired_hash` without `clear_pending_snapshot` audit. Unresolved or operator-blocked pending from a prior full resync can be silently replaced. | Require pending recovery/guard before scoped prepare; refuse overwrite when pending is unresolved/operator-blocked; always clear-with-reason before replace. Add unit tests for pending survival across scoped apply. |
| REVIEW-ACL-037 | P2 | Failed scoped apply leaves ready + dirty pending | open | `apply_port_scoped_snapshot` prepares pending before UDS submit. On port-level error it raises via `_raise_if_response_failed` without clearing pending or `mark_degraded`, so heartbeat can remain `ready` with durable dirty pending. Full-resync failure path degrades; scoped path does not. | On scoped failure, clear pending or mark degraded consistently with full-resync; add regression test asserting not `(ready and pending)`. |
| REVIEW-ACL-038 | P2 | Port-list pagination can hang | open | `NeutronPortSource.list_ports_for_host` follows `ports_links[rel=next]` without repeated-marker / page-bound guards. `AriaAclRestClient._list` already detects repeated markers. | Mirror ACL pagination hardening; add unit test with repeating next link. |
| REVIEW-ACL-039 | P1 | managed_domains qos without payload | fixed | Config allows `managed_domains` including `qos`. Production `SnapshotSynchronizer` passes domains into `PortCandidateBuilder` but never builds/passes `qos_index`, so ports advertise managed `qos` with no `qos` snapshot block while local QoS writes are blocked. | Reject unwired domains in config validation, or wire EffectiveQosIndex before advertising `qos`. Add config/unit guard tests. |
| REVIEW-ACL-040 | P2 | Port-status upsert TOCTOU | open | `NeutronDbAriaAclRepository.upsert_port_status` reads existing row outside the write transaction, then insert/update inside. Concurrent upserts for the same `(port_id, host)` can both insert. | Use one transactional upsert/merge; add concurrent or conflict unit coverage. |
| REVIEW-ACL-041 | P2 | CLI address-set update wipes members | open | `aria-acl-address-set-update --member` sends a full `members` replacement list. Repository `_replace_members` replaces all members when the field is present. | Document destructive replace or add merge/remove flags; add CLI test that one `--member` does not drop prior members unless replace is explicit. |
| REVIEW-ACL-042 | P2 | delete_address_set split transactions | open | Member purge and parent-row delete run in separate `session.begin` blocks. Failure after purge leaves an address-set row with zero members. | One transaction for purge + delete; failure-injection test. Distinct from `REVIEW-ACL-003` update path. |
| REVIEW-ACL-043 | P3 | priority=0 rejected as missing | fixed | `_require()` uses falsy `not obj.get(field)`, so rule `priority=0` fails validation while effective compile accepts 0. | Use explicit missing checks for numeric fields; add create/update unit tests for priority 0. |
| REVIEW-ACL-044 | P2 | Metadata-only ACL flips bank without WAL | open | `replace_owned_acl` stages/switches ACL banks even when group/policy diffs are empty, then early-returns without `state.state` update or `wal.compact`. Metadata-only hash changes (revision/name) force reconcile via domain hash. | Skip bank flip on true no-op, or persist bank/state whenever the active bank changes. Add metadata-only reconcile test asserting no unsynced bank flip. |
| REVIEW-ACL-045 | P2 | Orphan reconcile skips map scrub | open | `TapRegistry::reconcile_neutron_runtime` orphan cleanup only removes link pins / live-iface markers. It does not `detach`, `unregister_instance`, or `scrub_managed_runtime_state`. | Scrub orphaned tap-scoped maps (or full detach path) during orphan reconcile; add residual-map assertion test. Distinct from `REVIEW-ACL-035` hash-skip. |
| REVIEW-ACL-046 | P2 | Selected-domain group authority | reclassified-risk | `ensure_local_group_write_allowed` intentionally blocks `neutron:*` names while allowing non-Neutron groups, and the authority unit test explicitly expects that coexistence behavior. No current evidence demonstrates that non-Neutron group writes change effective Neutron ACL enforcement. | Document the authority/isolation boundary and add a cross-domain isolation test. Reopen as a bug only if non-Neutron writes are shown to alter Neutron-owned enforcement. |
| REVIEW-ACL-047 | P2 | Translator ignores rule priority | fixed | Numeric priority remains northbound metadata and is not added to eBPF `PolicyKey`. Python preflight and Rust direct-UDS validation now reject priority-dependent CIDR/specificity overlaps with stable reasons; canonical-equivalent CIDR groups are reused. A classified direct-UDS rejection reports real `degraded/bypass` only after the empty owned-ACL transaction succeeds. | Fixed with Python and Rust overlap/canonicalization/outcome regression tests, persistent Stage 1/2 static guards, and the documented priority-independent acceptance boundary. QoS/Mirror are unchanged. Distinct from `REVIEW-ACL-009`. |
| REVIEW-TXN-027 | P2 | Delete detach succeeds / WAL commit fails | open | `apply_delete_neutron_port` can detach and purge, then fail `append_delete_commit` (or after-detach fault) and return `detached: true` with `status=error` while runtime/WAL still diverge. | Roll back or durable-mark blocked recovery; do not report detached success without durable commit. Add after-detach-before-commit fault tests. Distinct from `REVIEW-ACL-023`. |
| REVIEW-ACL-048 | P1 | Status projection overwrites bypass→enforce | fixed | `_port_statuses_from_status` replaces UDS `effective_action` values of `bypass` (and empty) with snapshot metadata defaulting to `enforce` when `acl_enabled` is true. Northbound `aria_acl_port_statuses` can report enforce while datapath bypassed. | Never overwrite a concrete UDS runtime `effective_action`/`status`; treat UDS as runtime truth. Add unit tests for UDS bypass + snapshot enforce. |
| REVIEW-ACL-049 | P1 | Unwired managed_domains wedge ACL | fixed | Config allows `qos`/`mirror` in `managed_domains`. Rust `reconcile_neutron_domains` treats any domain outside `attach|acl` as unimplemented and marks ACL `blocked` for the whole port. Distinct from `REVIEW-ACL-039` (missing qos payload). | Reject unwired domains at config validation, or implement them; never block ACL solely because another domain is unimplemented. |
| REVIEW-ACL-050 | P2 | ACL enforce without conntrack foundation check | fixed | Historical finding: ACL activation did not bind the required CT mode to the same transaction, and ACL-only authority allowed local CT mutation. Reconcile now atomically quiesces `conntrack=false,acl=false`, replaces policy, strictly clears CT while creation is disabled, and atomically publishes the desired CT plus final ACL flags. `managed_domains=acl` also blocks local conntrack mutation as an internal dependency without advertising a `conntrack` Neutron domain. | Fixed with pure transition tests, ACL-dependency authority tests, stable HTTP 409 error text, Stage 1 static guards, and full Rust/eBPF/static-agent CI. |
| REVIEW-ACL-051 | P2 | WAL recovery false-passes qos/mirror | fixed | Pending-intent recovery marks `qos`/`mirror` as `recovered` with `*_no_runtime_executor` and can still return `ok: true` when those domains were in the intent. | Treat unimplemented recovery domains as degraded/failed; do not report recovered success without an executor/scrub. |
| REVIEW-ACL-052 | P2 | Update-error preserves unmanaged state | closed-not-supported | Attach failure purges/detaches, while update failure records an error and preserves the attached port plus state outside the failed Neutron-managed domain. Preserving unmanaged mirror/tcprt/local state is consistent with selected-domain authority and the availability-first OVS enhancement boundary; the original finding does not demonstrate an invariant violation. ACL partial-write/rollback defects remain tracked by `REVIEW-ACL-025` and `REVIEW-ACL-026`. | Keep closed unless a residual-state test proves that a failed update changes or falsely reports a Neutron-managed domain. Do not scrub unrelated domains or detach solely on this finding. |
| REVIEW-ACL-053 | P1 | Lenient ct_flush hides CT clear failure | fixed | Historical Neutron ACL reconcile used `core::ct_ops::ct_flush`, which returned `Ok(0)` when CT pins could not be opened or converted. Neutron now pre-disables ACL before every replacement, calls a dedicated strict control-plane flush backed by `scrub_ct_tables_strict`, propagates V4/V6 open/convert/iterate/remove failures, and enables non-empty ACL only after clear succeeds. Post-disable failures report `error/bypass`; translation or pre-disable failures report `error/unchanged`. | Fixed with gate-order, strict-method contract, proven effective-action, and missing-pin compatibility tests. The general lenient flush API remains unchanged. |
| REVIEW-ACL-054 | P2 | stateful=false still uses XDP CT fast-path | fixed | Rust now carries `NeutronAclSnapshot.stateful` as per-apply CT intent. Non-empty stateful policy publishes `conntrack=true,acl=true`; non-empty stateless policy publishes `conntrack=false,acl=true`. The existing eBPF per-tap CT guards therefore skip lookup and create for stateless ACL. Empty/bypass publishes ACL off with snapshot CT intent, while a missing ACL payload preserves the prior CT mode. | Fixed with translator intent and atomic runtime-transition tests covering stateful, stateless, empty, and missing-payload paths. |
| REVIEW-ACL-055 | P1 | Neutron ACL/CT hook split and missing TC fast path | likely-fixed | Neutron ingress ACL previously remained authoritative in XDP while TC egress had no complete bank-aware CT fast path, which split enforcement/accounting semantics and made TC-only post-processing incompatible with authoritative CT creation. Batch 6 moves Neutron ACL/CT authority to TC ingress and egress, keeps legacy XDP mode for standalone taps, and makes TC-mode XDP ACL/CT-neutral. | GREEN Build [29204885966](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/29204885966) passed, including fail-closed smoke structure, mutation checks, strict-flush→miss→hit bank evidence, and exact same-flow CT byte accounting. Keep `real-tap smoke pending` until the bounded managed-tap smoke preserves a passing `summary.json`; only then mark fixed. |
| REVIEW-ACL-056 | P1 | Fragment-safe ACL/CT key semantics | open | IPv4 non-first fragments are parsed as if payload bytes were TCP/UDP ports, while IPv6 non-first fragments use zero ports. Port ACL and CT keys can diverge across fragments. | A separate design must define fragment allow/drop/reassembly semantics before implementation. Do not treat Batch 6 TC unification as a parser fix. |
| REVIEW-DOC-021 | P2 | Capabilities advertise unimplemented domains | fixed | `NEUTRON_SUPPORTED_DOMAINS` / `neutron-uds-contract.json` / capabilities response list qos/mirror/config/ct/… while reconcile only implements `attach`+`acl`. Stage-1 CI even requires qos/mirror in supported_domains. | Split advertised vs implemented domains; shrink supported set or mark planned and reject managed_domains that are unimplemented. |
| REVIEW-OPS-035 | P2 | Transaction smoke can pass with zero ports | open | `neutron_aria_transaction_state_smoke.sh` defaults `MIN_MANAGED_PORTS=0` and skips pending-delete / migration-source checks when no managed port exists, still exiting success. | Require `MIN_MANAGED_PORTS>=1` for release gates, or fail when skip paths are taken. |
| REVIEW-CI-001 | P2 | Stage gates are marker/substring heavy | open | `check_stage3_readiness.py` checks file/marker presence; stage-2 production ACL smoke check greps shell strings; several high-value unit modules are omitted from stage-2 test lists. | Run real smoke with non-zero ports where possible; include omitted unit modules; add implemented-domain ⊆ allowed-domain contract check. |

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
- Current code contains Rust and Python `effective_action` projection while
  `05-domain-status-heartbeat.md` still calls the rich Rust field planned,
  confirming `REVIEW-DOC-020`.
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
  behavior (`REVIEW-ACL-046`, reclassified as a design-boundary risk on
  2026-07-11), ignored priority (`REVIEW-ACL-047`), delete detach/commit split
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
  environment. `REVIEW-ACL-055` therefore remains `likely-fixed` with
  `real-tap smoke pending`; `REVIEW-ACL-056` remains open P1.

## Active Fix Order After Batch 6

1. `REVIEW-ACL-055`: run and preserve the guarded real managed-tap smoke; only a passing `summary.json` closes the likely-fixed item.
2. `REVIEW-ACL-056`: define fragment allow/drop/reassembly and ACL/CT key semantics before parser implementation.
3. `REVIEW-OPS-019`: bound Neutron WAL growth and restart replay cost.
4. `REVIEW-ACL-025` / `REVIEW-ACL-026` / `REVIEW-ACL-044`: owned-ACL durable ordering and no-op bank flips.
5. `REVIEW-ACL-023` / `REVIEW-TXN-024` / `REVIEW-TXN-027` / `REVIEW-ACL-045`: detach/delete/orphan convergence.
6. `REVIEW-ACL-036` / `REVIEW-ACL-037` / `REVIEW-ACL-028` / `REVIEW-ACL-008` / `REVIEW-ACL-033` / `REVIEW-ACL-004`: Python pending/status consistency.
7. `REVIEW-TXN-026`: gate accept until startup recovery completes.
8. `REVIEW-ACL-038` / `REVIEW-ACL-040` / `REVIEW-ACL-041` / `REVIEW-ACL-042`: client/DB/CLI correctness.
9. `REVIEW-ACL-007`: first-install package rollback hygiene.
10. `REVIEW-ACL-003`: make address-set parent/member writes transactional.
11. `REVIEW-OPS-027` / `REVIEW-OPS-034` / `REVIEW-OPS-035` / `REVIEW-CI-001`: ops/CI hardening.
12. `REVIEW-ACL-010` / `REVIEW-ACL-013` / `REVIEW-ACL-015` / `REVIEW-ACL-017`: smoke/projection/rollback polish.
13. `REVIEW-DOC-020`: align domain-status detail documentation with current DTOs.
14. `REVIEW-ACL-011` / `REVIEW-ACL-014` / `REVIEW-ACL-005`: release hygiene and coverage.

Risk follow-up is tracked separately from active bug fixing:

- `REVIEW-ACL-032`: expose notifier fallback and bound periodic convergence.
- `REVIEW-ACL-046`: document selected-domain authority and prove cross-domain
  isolation.

Verification and closure follow-up:

- `REVIEW-ACL-012`: run the clean-container package smoke; no active source
  defect is currently confirmed.
- `REVIEW-ACL-016` and `REVIEW-ACL-018`: fixed.
- `REVIEW-ACL-052`: closed as unsupported as written; reopen only with a
  Neutron-managed invariant violation reproduction.
