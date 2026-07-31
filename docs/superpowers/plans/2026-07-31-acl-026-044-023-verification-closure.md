# REVIEW-ACL-026/044/023 Verification Closure Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use
> superpowers:subagent-driven-development (recommended) or
> superpowers:executing-plans to implement this plan task-by-task. Steps use
> checkbox (`- [ ]`) syntax for tracking.

**Goal:** Revalidate the three historical ACL transaction findings against the
current `v0.9-neutron-agent` implementation, preserve one exact Rust behavior
contract per finding, and correct stale Register state without duplicating
already-landed production fixes.

**Architecture:** Treat the current concrete managed ACL publisher and
transactional purge path as the implementation under test. Reuse the existing
Rust behavior tests when they already express the required failure boundary;
do not add a second copy of the same contract merely to change a test name.
After source/test mapping is complete, run an exact-head manually dispatched
GitHub Actions build so `rust-behavior` and `rust-build` cannot be skipped by a
documentation-only push.

**Tech Stack:** Rust stable, Tokio, existing managed ACL publication planners,
GitHub Actions `fast-contracts`, `rust-behavior`, and warning-denied
`rust-build`.

## Global Constraints

- Work directly on local and remote `v0.9-neutron-agent`; do not create a
  branch, worktree, stacked PR, or parallel delivery line.
- Do not run local `cargo build`, `cargo check`, or `cargo test`.
- Do not change production Rust unless an exact behavior contract fails on the
  current implementation.
- Do not add Python source-shape checkers or copied inline Rust source.
- Do not absorb `REVIEW-TXN-024`, `REVIEW-TXN-027`, or `REVIEW-ACL-045`.
- Keep privileged pinned-map evidence separate; do not record unexecuted field
  validation as passed.

---

### Task 1: Map each historical finding to current source and behavior tests

**Files:**

- Inspect: `agent/src/control_plane.rs`
- Inspect: `agent/src/neutron_api.rs`
- Modify:
  `docs/openstack-neutron-aria-details/12-review-bug-backlog.md`

**Interfaces:**

- Consumes:
  - `managed_acl_publication_compensations`
  - `managed_acl_publication_decision`
  - `execute_neutron_acl_detach_cleanup`
- Produces: one evidence-backed current Register classification for each of
  `REVIEW-ACL-026`, `REVIEW-ACL-044`, and `REVIEW-ACL-023`.

- [x] **Step 1: Verify `REVIEW-ACL-026` partial-write compensation**

Confirm the executor appends a general-map mutation to
`applied_shared_mutations` only after that mutation succeeds and passes only
that applied prefix to `rollback_owned_acl_prepublication` on a later failure.

Confirm the existing Rust behavior contracts:

```text
managed_general_delta_source_only_failure_restores_preimage
managed_general_delta_destination_failure_restores_source_preimage
managed_general_delta_shadow_failure_restores_both_preimages
managed_general_delta_general_compensation_failure_attempts_every_preimage
```

These tests cover no-write, one-write, all-write, reverse-order, and
compensation-failure behavior. Do not add a duplicate mid-loop planner test.

- [x] **Step 2: Verify `REVIEW-ACL-044` true no-op publication**

Confirm `semantic_changed` is false only when policy, group CIDR, group delete,
and released bitmap changes are all empty. Confirm
`managed_acl_publication_decision(ProjectionDrift::Clean, false)` returns
`Noop`, and `publish_acl_projection_locked` returns before staging,
persistence, fragment epoch advance, or bank switch.

Use the existing Rust behavior contracts:

```text
managed_projection_repair_clean_equal_reconcile_is_noop
neutron_acl_validation_cache_is_content_safe_and_port_specific
```

The first proves the inner publication is empty; the second proves metadata
revision changes can still invalidate outer translation/reconcile caches
without making the resulting ACL projection semantically different.

- [x] **Step 3: Verify `REVIEW-ACL-023` purge failure propagation**

Confirm snapshot detach records an error and continues without calling
`registry.detach`. Confirm direct port delete returns HTTP 500 with
`detached=false`. Use the existing ordered Rust behavior:

```text
neutron_acl_purge_failure_aborts_detach_without_partial_owned_state
```

The observed event list must end after:

```text
quiesce
replace-empty-and-strict-flush
```

and must not contain `detach`.

- [x] **Step 4: Update the authoritative Register**

Update only the authoritative Register rows and the current execution order.
Do not rewrite dated historical discovery snapshots. Record the implementation
commits, exact test names, hosted CI, and any remaining privileged evidence
boundary.

---

### Task 2: Review, commit, and push the closure record

**Files:**

- Modify:
  `docs/openstack-neutron-aria-details/12-review-bug-backlog.md`
- Modify:
  `docs/superpowers/plans/2026-07-31-acl-026-044-023-verification-closure.md`

**Interfaces:**

- Consumes: Task 1 source/test evidence.
- Produces: a durable repository record that removes the three stale ordinary
  open items from the active production-fix queue.

- [x] **Step 1: Perform documentation validation**

Run:

```bash
git diff --check
python3 ci/check_blocked_terms.py
python3 ci/check_neutron_stage1.py --fast-contracts
```

Expected: all commands exit zero. These are documentation/contract checks, not
local Rust compilation.

- [x] **Step 2: Review scope**

Run:

```bash
git diff --stat
git diff -- docs/openstack-neutron-aria-details/12-review-bug-backlog.md \
  docs/superpowers/plans/2026-07-31-acl-026-044-023-verification-closure.md
```

Confirm no Rust, Python, eBPF, workflow, configuration, or API file changed.

- [ ] **Step 3: Commit and push**

Run:

```bash
git add docs/openstack-neutron-aria-details/12-review-bug-backlog.md \
  docs/superpowers/plans/2026-07-31-acl-026-044-023-verification-closure.md
git commit -m "docs: close stale ACL transaction findings"
git push origin v0.9-neutron-agent
```

---

### Task 3: Produce exact-head hosted evidence

**Files:**

- Modify:
  `docs/openstack-neutron-aria-details/12-review-bug-backlog.md`
- Modify:
  `docs/superpowers/plans/2026-07-31-acl-026-044-023-verification-closure.md`

**Interfaces:**

- Consumes: the pushed closure commit.
- Produces: exact-head full GitHub Actions evidence and the handoff to
  `REVIEW-TXN-024`.

- [ ] **Step 1: Dispatch the full build**

Run:

```bash
head_sha="$(git rev-parse HEAD)"
gh workflow run build.yml --ref v0.9-neutron-agent
```

Find the `workflow_dispatch` run whose `headSha` equals `${head_sha}`. The
manual dispatch is required because a documentation-only push intentionally
skips Rust jobs.

- [ ] **Step 2: Verify hosted behavior and compilation**

Run:

```bash
gh run watch "${run_id}"
gh run view "${run_id}" --json headSha,event,status,conclusion,jobs,url
gh run view "${run_id}" --log-failed
```

Expected:

- exact `headSha`;
- event `workflow_dispatch`;
- `fast-contracts`: success;
- `rust-behavior`: success;
- `rust-build`: success; and
- no warning-denied Rust/eBPF compilation failure.

- [ ] **Step 3: Record exact-head evidence**

Add the run URL and exact commit to the three Register rows and this plan.
Commit and push the evidence-only update. The push may skip Rust jobs because
the referenced manually dispatched run already proves the immediately prior
source-identical documentation head.

- [ ] **Step 4: Begin the next independent batch**

Create the formal `REVIEW-TXN-024`/`REVIEW-TXN-027` WAL recovery design. Keep
`REVIEW-TXN-024` first and do not modify `REVIEW-TXN-027` production behavior
until the first transaction has its own RED/GREEN cycle.

## Execution Evidence

- Analyzed baseline:
  `v0.9-neutron-agent@21ab3e4cf3ed6f6a4f96036ba7299ef52cd612a0`
- Baseline full Rust evidence:
  [Build 30609828584](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/30609828584)
  at `4dca970` passed `fast-contracts`, `rust-behavior`, and `rust-build`.
- `REVIEW-ACL-023` transactional purge evidence:
  [Build 29672271181](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/29672271181)
  at `ad30cad` passed `fast-contracts`, `rust-behavior`, and `rust-build`.
- Exact-head closure dispatch: pending.
