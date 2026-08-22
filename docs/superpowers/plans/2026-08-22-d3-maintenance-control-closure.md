# D3 Maintenance Control Closure Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close D3 with one finite, evidence-backed review of the frozen packet-gate, transaction/WAL, and root-admin contract boundaries, without reopening adjacent development scope.

**Architecture:** Keep the implementation on `main` and review it as three independent acceptance gates. D3-A is frozen and evidence-only; D3-B and D3-C are checked against `docs/superpowers/specs/2026-08-22-d3-maintenance-control-closure-design.md`. A finding may trigger one focused RED/GREEN repair plan, but the closure review may not expand into Task 5/6 behavior or general refactoring.

**Tech Stack:** Rust, Tokio, Axum, Aya/eBPF TC, JSON WAL records, Python 2.7-compatible Neutron client code, Python 3 contract checks, GitHub Actions.

## Global Constraints

- Work only on `main`; do not create a branch, stacked change, pull request, or worktree.
- Before every mutation, require a clean worktree and `main == origin/main` after `git fetch origin && git pull --ff-only`.
- Do not run local `cargo build`, `cargo check`, `cargo test`, `cargo fmt`, Clippy, or another local Rust compilation command.
- Use GitHub Actions for Rust behavior, eBPF, userspace, static agent, and linked-artifact verification.
- Do not change `abi/src`, `ebpf/src`, or the approved Task 3 live-authority implementation during closure.
- Keep linked `tc_ingress` and `tc_egress` at or below 480 verifier-charged bytes.
- Keep `release/runtime-compatibility.json` field `maintenance_gate_capable` equal to `false`.
- Do not implement Python buffering, stable double-read inventory, shadow generations, Kolla coordination, rollback execution, or another Task 5/6 feature.
- Real EL 4.18 verifier, dual-stack traffic, restart/kill, restoration, and rollback evidence remains `deferred/pending` and cannot be represented as CI PASS.
- Review findings must cite a frozen acceptance-matrix ID from the closure design. Adjacent cleanup is not a closure blocker.

---

## File Responsibility Map

| File | Closure responsibility |
| --- | --- |
| `docs/superpowers/specs/2026-08-22-d3-maintenance-control-closure-design.md` | Frozen D3-A/B/C source of truth |
| `abi/src/lib.rs`, `ebpf/src/lib.rs`, `ebpf/src/runtime.rs` | Frozen packet-entry gate behavior and ABI |
| `core/src/ebpf_ops/runtime.rs`, `agent/src/control_plane.rs`, `agent/src/instance.rs` | Frozen serialized gate mutation and live authority |
| `api/src/lib.rs` | Public maintenance state and Status v4 types |
| `agent/src/neutron_maintenance.rs` | D3-B state, CAS, WAL record/replay, coordinator, audit tests |
| `agent/src/neutron_wal.rs` | Durable framing, composite snapshot commit, bounded read/compaction |
| `agent/src/neutron_api.rs` | Writer leases, production routers, status projection, admin handlers |
| `agent/src/main.rs` | Startup barrier, anchored admin socket, peer authorization |
| `openstack/neutron_aria/neutron_aria/agent/uds_client.py` | Production Status v4 decoder |
| `docs/neutron-uds-contract.json`, `docs/neutron-status-contract-v4-scenarios.json` | Authoritative public contract and fixtures |
| `ci/check_neutron_stage1.py` | Hosted Rust selectors and production decoder execution |
| `.superpowers/sdd/d3-closure-report.md` | Local ignored closure evidence |

---

### Task 1: Establish The Exact Closure Baseline

**Files:**
- Create: `.superpowers/sdd/d3-closure-report.md`
- Read: `docs/superpowers/specs/2026-08-22-d3-maintenance-control-closure-design.md`
- Read: `release/runtime-compatibility.json`

**Interfaces:**
- Consumes: D3-A head `de5686272498f1304234b66547ba5ebb97c2d782`, production head `ad57f6ac382ab09038891d37f94ca0e2163bc301`, closure design head `d5270148a15f2b57959860d0274a99fa184bb36c`.
- Produces: one immutable baseline used by later tasks.

- [ ] **Step 1: Verify branch and ownership preflight**

Run:

```bash
git fetch origin
git pull --ff-only
git status --short --branch
git rev-parse HEAD
git rev-parse origin/main
git log --oneline -5 -- \
  agent/src/neutron_maintenance.rs \
  agent/src/neutron_wal.rs \
  agent/src/neutron_api.rs \
  agent/src/main.rs \
  api/src/lib.rs \
  openstack/neutron_aria/neutron_aria/agent/uds_client.py
```

Expected: clean `main`, equal local/remote SHAs, and no newer unowned change on a closure file.

- [ ] **Step 2: Verify production and design CI baselines**

Run:

```bash
gh run view 32559800618 --json status,conclusion,headSha,jobs
gh run view 32560368741 --json status,conclusion,headSha,jobs
```

Expected:

- run `32559800618` is success at `ad57f6ac382ab09038891d37f94ca0e2163bc301` with `fast-contracts`, `rust-behavior`, and `rust-build` successful;
- run `32560368741` is success at `d5270148a15f2b57959860d0274a99fa184bb36c`;
- only the closure design document differs between those heads.

- [ ] **Step 3: Prove the design commit changed no production path**

Run:

```bash
git diff --name-only \
  ad57f6ac382ab09038891d37f94ca0e2163bc301..d5270148a15f2b57959860d0274a99fa184bb36c
git diff --check \
  ad57f6ac382ab09038891d37f94ca0e2163bc301..d5270148a15f2b57959860d0274a99fa184bb36c
```

Expected: the only path is `docs/superpowers/specs/2026-08-22-d3-maintenance-control-closure-design.md`, and diff-check is silent.

- [ ] **Step 4: Create the closure report baseline**

Create `.superpowers/sdd/d3-closure-report.md` with:

```markdown
# D3 Closure Report

## Baseline

- Branch: `main`
- Production head: `ad57f6ac382ab09038891d37f94ca0e2163bc301`
- Production Actions: `32559800618` (`success`)
- Closure design head: `d5270148a15f2b57959860d0274a99fa184bb36c`
- Closure design Actions: `32560368741` (`success`)
- Capability: `maintenance_gate_capable=false`
- Field evidence: `deferred/pending`

## D3-A Packet Gate

## D3-B Transaction And WAL

## D3-C Admin And Status

## Bounded Review

## Final Verification
```

Expected: no policy body, token, credential, or invented field evidence.

- [ ] **Step 5: Confirm the ignored report does not dirty tracked state**

Run:

```bash
git status --short
```

Expected: tracked worktree remains clean because `.superpowers/sdd/` is ignored.

---

### Task 2: Freeze D3-A Packet-Gate Evidence

**Files:**
- Read: `abi/src/lib.rs`
- Read: `ebpf/src/lib.rs`
- Read: `ebpf/src/runtime.rs`
- Read: `ebpf/src/conntrack.rs`
- Read: `ebpf/src/fragment.rs`
- Read: `core/src/ebpf_ops/runtime.rs`
- Read: `agent/src/control_plane.rs`
- Read: `agent/src/instance.rs`
- Modify: `.superpowers/sdd/d3-closure-report.md`

**Interfaces:**
- Consumes: approved D3-A head `de5686272498f1304234b66547ba5ebb97c2d782` and Actions `32548527312`.
- Produces: a frozen decision for D3-A-1..6; no source edit.

- [ ] **Step 1: Prove D3-A production files stayed frozen**

Run:

```bash
git diff --name-only \
  de5686272498f1304234b66547ba5ebb97c2d782..HEAD -- \
  abi/src ebpf/src \
  core/src/ebpf_ops/runtime.rs \
  core/src/ebpf_ops/inventory.rs \
  core/src/ebpf_ops/replay.rs \
  agent/src/control_plane.rs \
  agent/src/instance.rs \
  .github/workflows/build.yml \
  ci/check_ebpf_stack_budget.py \
  release/runtime-compatibility.json
```

Expected: silent output. If a path appears, stop and classify ownership before reviewing D3-A.

- [ ] **Step 2: Verify approved D3-A Actions evidence**

Run:

```bash
gh run view 32548527312 --json status,conclusion,headSha,jobs
gh run view 32548527312 --log | rg \
  'tc_ingress.*480|tc_egress.*480|maintenance|authority|stream'
```

Expected: success at `de5686272498f1304234b66547ba5ebb97c2d782`, both linked entries at 480 or less, and selected authority/packet behaviors executed.

- [ ] **Step 3: Record the frozen D3-A verdict**

Append under `## D3-A Packet Gate`:

```markdown
| Matrix ID | Evidence | Result |
| --- | --- | --- |
| D3-A-1 | packet-entry sample before per-tap state | PASS |
| D3-A-2 | ACL/CT/fragment common packet flags | PASS |
| D3-A-3 | unrelated domain independence | PASS |
| D3-A-4 | serialized key-0 RMW and readback | PASS |
| D3-A-5 | live program/map/attachment authority | PASS |
| D3-A-6 | Actions 32548527312, ingress/egress <= 480 | PASS |
```

Expected: later tasks do not reopen D3-A.

---

### Task 3: Perform The Bounded D3-B Transaction And WAL Review

**Files:**
- Read: `api/src/lib.rs:49-105`
- Read: `agent/src/neutron_maintenance.rs`
- Read: `agent/src/neutron_wal.rs`
- Read: `agent/src/neutron_api.rs`
- Read: `agent/src/main.rs`
- Modify: `.superpowers/sdd/d3-closure-report.md`

**Interfaces:**
- Consumes: the frozen state, CAS, WAL, lock-order, and D3-B-1..8 matrices.
- Produces: findings where each item names one primary matrix ID; no production mutation.

- [ ] **Step 1: Map D3-B-1 and D3-B-2 to state/CAS seams**

Inspect:

```text
MaintenanceState::is_active
MaintenanceStateMachine::plan_enter
MaintenanceStateMachine::plan_exit
MaintenanceStateMachine::plan_abort
MaintenanceCoordinator::enter_with_transaction
MaintenanceCoordinator::exit_with_transaction
MaintenanceCoordinator::abort_with_transaction
```

Require these tests:

```text
neutron_maintenance_same_enter_is_idempotent_and_conflict_is_side_effect_free
neutron_maintenance_generation_hash_and_phase_cas_mismatch_do_not_mutate_state
neutron_maintenance_exit_requires_exact_complete_convergence_and_is_idempotent
neutron_maintenance_abort_terminal_retry_requires_original_active_phase
neutron_maintenance_exit_intent_supersedes_conservative_abort_identity_atomically
```

Expected: every illegal CAS conflicts without WAL, gate, or RAM mutation.

- [ ] **Step 2: Map D3-B-3 and D3-B-4 to replay and compatibility**

Inspect `decode_maintenance_record`, `replay_maintenance_records`, the Neutron WAL replay, checkpoint installation, and bounded line reader.

Require:

```text
neutron_maintenance_dangling_enter_intent_replays_as_active_bypass
neutron_maintenance_records_are_bounded_typed_and_reject_duplicate_unknown_or_oversized
neutron_maintenance_checkpoint_gate_and_cause_combinations_are_strict_and_bounded
neutron_maintenance_schema_v1_abort_records_restart_and_retry_compatibly
neutron_maintenance_recovery_commit_gate_phase_and_cause_are_bidirectional
neutron_maintenance_wal_unknown_malformed_and_oversized_records_fail_conservatively
neutron_maintenance_wal_compacts_by_record_count_before_replay_limit
neutron_maintenance_wal_rejects_oversized_tail_without_newline
```

Expected: writes use WAL v2; v1 migration is limited to legacy Abort identity; malformed v1 and incomplete v2 fail conservatively.

- [ ] **Step 3: Map D3-B-5 to composite snapshot replay**

Inspect `NeutronWal::append_snapshot_commit_with_maintenance_progress` and its replay branch.

Require:

```text
neutron_maintenance_wal_snapshot_and_progress_commit_are_one_replay_boundary
neutron_maintenance_wal_composite_replay_rejects_orphan_wrong_type_and_identity_drift
```

Expected: matching ordinary intent, ready generation/hash, exact `ProgressCommit`, and active maintenance identity are accepted together; orphan, wrong-type, and drift are rejected together.

- [ ] **Step 4: Map D3-B-6 to every writer class**

Trace the lease through full-host snapshot, port snapshot, delete, periodic,
background, direct, lifecycle, netlink, recovery, and TCP mutation paths.

Require:

```text
neutron_maintenance_writer_fence_allows_only_matching_full_host_snapshot
neutron_maintenance_atomic_writer_lease_serializes_enter_and_mutation
neutron_maintenance_pending_exit_or_abort_fences_matching_snapshot_progress
neutron_maintenance_background_failure_marker_retains_admitted_writer_lease
neutron_maintenance_actual_routers_isolate_admin_routes_and_fence_tcp_mutations
```

Expected: lock order is maintenance lease, apply lock, runtime lock; no final mutation happens after lease release.

- [ ] **Step 5: Map D3-B-7 and D3-B-8 to startup and gate truth**

Require:

```text
neutron_maintenance_startup_barrier_runs_before_and_blocks_mutating_initialization
neutron_maintenance_recovery_failure_blocks_restore_and_same_id_repairs_after_proof
neutron_maintenance_uncertain_gate_clear_and_restore_failure_marks_blocked
neutron_maintenance_double_gate_failure_is_unknown_not_bypass
neutron_maintenance_checkpoint_unknown_requires_live_startup_proof
neutron_maintenance_enter_commit_failure_keeps_verified_bypass_truth
```

Expected: maintenance recovery precedes ordinary initialization; unknown gate truth stays active and blocked until fresh proof.

- [ ] **Step 6: Record D3-B evidence**

Append rows D3-B-1 through D3-B-8 with:

```markdown
| Matrix ID | Production seam | Executed tests | Result | Finding |
| --- | --- | --- | --- | --- |
```

Use only `PASS`, `CRITICAL`, `IMPORTANT`, or `MINOR`. A non-PASS row includes file, exact line, violated rule, and failure mode.

---

### Task 4: Perform The Bounded D3-C Admin And Status Review

**Files:**
- Read: `agent/src/main.rs`
- Read: `agent/src/neutron_api.rs`
- Read: `api/src/lib.rs`
- Read: `openstack/neutron_aria/neutron_aria/agent/uds_client.py`
- Read: `docs/neutron-uds-contract.json`
- Read: `docs/neutron-status-contract-v4-scenarios.json`
- Read: `ci/check_neutron_stage1.py`
- Modify: `.superpowers/sdd/d3-closure-report.md`

**Interfaces:**
- Consumes: D3-C-1..5.
- Produces: one bounded admin/status verdict; no production mutation.

- [ ] **Step 1: Verify D3-C-1 transport and peer authorization**

Inspect directory walk, no-follow checks, bind, ownership/mode verification,
accepted-stream peer credentials, and handoff to Axum.

Require:

```text
neutron_maintenance_admin_binder_anchors_directory_and_enforces_private_socket
neutron_maintenance_admin_binder_rejects_symlink_and_group_world_writable_parent
neutron_maintenance_admin_peercred_rejects_queued_non_root_connection
neutron_maintenance_admin_peercred_authorizes_root_uid_independent_of_gid
```

Expected: UID 0 is required before routing; queued non-root, replaced paths, and unsafe parents fail closed.

- [ ] **Step 2: Verify D3-C-2 route isolation**

Require:

```text
neutron_maintenance_admin_route_inventory_is_separate_and_complete
neutron_maintenance_actual_routers_isolate_admin_routes_and_fence_tcp_mutations
```

Expected: only the root router contains four admin routes; Neutron/TCP routers return 404 for admin paths and fence ordinary mutation.

- [ ] **Step 3: Verify D3-C-3 and D3-C-5 Status v4 authority**

Run allowed contract checks:

```bash
python3 -m unittest -v ci.test_neutron_maintenance_contract
python3 ci/check_neutron_stage1.py --fast-contracts
```

Expected: PASS, including production `_decode_status(..., STATUS_CONTRACT_V4)` for every legal and illegal fixture.

Inspect that required and maintenance actions identify one transaction, ordinary ready state cannot carry maintenance identity/bypass, gate unknown is blocked, and JSON vocabulary matches Rust/Python.

- [ ] **Step 4: Verify D3-C-4 audit cardinality and bounds**

Require:

```text
neutron_maintenance_audit_events_are_bounded_structured_and_redacted
neutron_maintenance_idempotent_results_emit_success_audit
neutron_maintenance_admin_enter_failure_emits_one_result_event
```

Expected: one Attempt plus one Success or Failure per request; no policy/token/secret payload.

- [ ] **Step 5: Record D3-C evidence**

Append rows D3-C-1 through D3-C-5 using the Task 3 result vocabulary and finding format.

---

### Task 5: Run One Independent Bounded Review

**Files:**
- Read: `docs/superpowers/specs/2026-08-22-d3-maintenance-control-closure-design.md`
- Read: `.superpowers/sdd/d3-closure-report.md`
- Modify: `.superpowers/sdd/d3-closure-report.md`

**Interfaces:**
- Consumes: Tasks 1-4 evidence and exact current head.
- Produces: one independent verdict limited to D3-A-1..6, D3-B-1..8, D3-C-1..5.

- [ ] **Step 1: Give the reviewer this finite brief**

```text
Review the exact current head read-only against
docs/superpowers/specs/2026-08-22-d3-maintenance-control-closure-design.md.
Every finding must cite one primary matrix ID from D3-A-1..6, D3-B-1..8,
or D3-C-1..5. Do not modify files, run local Cargo or broad suites, review
Task 5/6 behavior, or recommend general refactoring. Verify exact CI heads and
capability=false. Report Critical, Important, Minor, and Ready.
```

Expected: reviewer accepts the scope before inspection.

- [ ] **Step 2: Apply this closure rule**

```text
Critical or Important: D3 stays open. Stop this plan and write one focused
finding-repair micro-plan containing a RED test, minimal repair, exact CI, and
re-review of only the affected matrix ID.

Minor: record unless it directly violates a frozen safety/compatibility rule.

No Critical/Important: Ready: Yes.

Defect crossing two or more sub-gates: stop and request the separate
behavior-preserving module-refactor decision from closure design section 10.
```

Expected: no open-ended review wave.

- [ ] **Step 3: Record the independent verdict**

Append reviewer identity, exact head, matrix IDs, findings, and `Ready: Yes/No` under `## Bounded Review`.

---

### Task 6: Verify And Close D3

**Files:**
- Modify: `docs/superpowers/plans/2026-08-21-aria-planned-maintenance-upgrade-v09.md`
- Modify: `.superpowers/sdd/progress.md`
- Modify: `.superpowers/sdd/d3-closure-report.md`
- Read: `release/runtime-compatibility.json`

**Interfaces:**
- Consumes: `Ready: Yes` from Task 5 and clean exact-head CI.
- Produces: documentation-only D3 closure; no capability flip and no field PASS claim.

- [ ] **Step 1: Re-run synchronized-main preflight**

Run:

```bash
git fetch origin
git pull --ff-only
git status --short --branch
git rev-parse HEAD
git rev-parse origin/main
```

Expected: clean synchronized `main`.

- [ ] **Step 2: Mark only Task 3 and Task 4 complete**

In `docs/superpowers/plans/2026-08-21-aria-planned-maintenance-upgrade-v09.md`:

- change each Task 3 and Task 4 step checkbox from `[ ]` to `[x]`;
- leave Task 5 and later checkboxes unchanged;
- add accepted code SHA, Actions run, bounded-review verdict, and closure-design link.

Expected: D3 is code-complete while later gates remain open.

- [ ] **Step 3: Update local progress and evidence**

Record in ignored progress/report files:

```text
D3-A: complete
D3-B: complete
D3-C: complete
maintenance_gate_capable: false
EL 4.18 and field evidence: deferred/pending
production readiness: not approved
```

- [ ] **Step 4: Run allowed checks**

Run:

```bash
git diff --check
python3 -m unittest -v \
  ci.test_neutron_maintenance_contract \
  ci.test_release_governance \
  ci.test_aria_upgrade_control
python3 ci/check_neutron_stage1.py --fast-contracts
```

Expected: PASS. Do not run local Cargo.

- [ ] **Step 5: Commit and push closure documentation**

Run:

```bash
git add docs/superpowers/plans/2026-08-21-aria-planned-maintenance-upgrade-v09.md
git commit -m "docs(plan): close D3 maintenance control gate"
git push origin main
```

Expected: push succeeds without rewriting history; ignored evidence remains local.

- [ ] **Step 6: Wait for terminal exact-head Actions**

Run:

```bash
closure_sha=$(git rev-parse HEAD)
closure_run_id=$(gh run list --workflow build.yml --branch main --limit 3 \
  --json databaseId,headSha,status,conclusion,displayTitle \
  | jq -r --arg sha "$closure_sha" \
    '.[] | select(.headSha == $sha) | .databaseId' \
  | head -1)
gh run list --workflow build.yml --branch main --limit 3 \
  --json databaseId,headSha,status,conclusion,displayTitle
gh run view "$closure_run_id" --json status,conclusion,headSha,jobs
```

Expected: terminal success at exact closure head. If docs-only change skips Rust, retain production Rust/build evidence from `32559800618` and report both runs.

- [ ] **Step 7: Deliver final status**

Report D3 code complete; exact production and documentation SHAs/runs; D3-A/B/C verdicts; capability false until Tasks 3-6 coexist; field evidence deferred; production readiness not approved.
