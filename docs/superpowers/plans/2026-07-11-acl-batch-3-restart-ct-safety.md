# ACL Batch 3 Restart and Conntrack Safety Implementation Plan

> **Execution:** Follow test-driven development task by task. This checkout
> forbids local Cargo commands, so Rust red/green evidence comes from GitHub
> Actions.

**Goal:** Fix `REVIEW-ACL-035` and `REVIEW-ACL-053` so restart recovery cannot
claim ACL readiness before a confirmed resync, and Neutron ACL updates cannot
claim enforcement unless strict conntrack clearing succeeds.

**Architecture:** Restart reconciliation keeps attach readiness but invalidates
only the ACL domain hash/status and persists a full-resync-required authority
state. Neutron ACL apply disables the ACL gate before replacement, uses the
existing strict CT scrub through a Neutron-specific control-plane method, and
re-enables only after replacement and both CT maps clear successfully.

**Tech Stack:** Rust, Tokio, Axum, Aya pinned maps, append-only JSON WAL,
GitHub Actions, repository Python contract checks.

## Global Constraints

- Implement only `REVIEW-ACL-035` and `REVIEW-ACL-053`.
- Preserve the approved availability-first boundary: ACL uncertainty is
  explicit degraded/error plus `unchanged` or `bypass`, never false enforce.
- Preserve OVS attachment and forwarding.
- Do not add a shared hash/transaction identity to the tap-local WAL.
- Do not change the general lenient `ct_flush` API.
- Never run local `cargo build`, `cargo check`, or `cargo test`.
- Preserve and exclude the user's uncommitted `README.md` change.
- Use separate test and implementation commits so CI records red/green proof.

## File Map

| File | Responsibility |
| --- | --- |
| `agent/src/neutron_api.rs` | Restart invalidation, ACL gate ordering, strict CT call, Rust regression tests. |
| `agent/src/control_plane.rs` | Neutron-specific strict conntrack flush method. |
| `core/src/ct_ops.rs` | Existing strict CT scrub and focused missing-pin coverage. |
| `docs/openstack-neutron-aria-details/07-transaction-wal.md` | Restart recovery and full-resync-required status contract. |
| `docs/openstack-neutron-aria-details/12-review-bug-backlog.md` | Fixed status, closure evidence, counts, and next fix order. |

---

### Task 1: Establish Red Restart and CT Safety Evidence

**Files:**
- Test: `agent/src/neutron_api.rs`
- Test: `core/src/ct_ops.rs`

- [ ] Add a pure restart-state test for an ACL-managed port. It must require:
  attach `ready`, ACL `degraded`, ACL action `unchanged`, reason
  `acl_restart_replay_requires_resync`, removal of only the ACL domain hash,
  and non-ready process authority.
- [ ] Add a mixed-domain test proving non-ACL hashes and binding identity are
  preserved.
- [ ] Add a non-ACL port test proving its existing ready recovery behavior is
  unchanged.
- [ ] Assert the invalidated state rejects both the same-generation early no-op
  and `can_skip_neutron_domain_reconcile` for the same ACL payload.
- [ ] Change the non-empty ACL gate-order test to require
  `DisableBeforeReplace`; current code returns `KeepCurrentUntilEnable`.
- [ ] Add a compile-level test/use of a Neutron-specific
  `flush_conntrack_strict` control-plane method.
- [ ] Add a core strict-scrub missing-pin assertion with a unique nonexistent
  path; it must return an error naming `CT_TABLE_V4`, while lenient `ct_flush`
  remains `Ok(0)`.
- [ ] Commit tests only as:

```bash
git commit -m "test: require restart and conntrack safety"
```

- [ ] Push the branch and dispatch Build with `publish_artifacts=false`.
  Expected red: the restart invalidation helper and strict control-plane method
  do not exist, and non-empty ACL currently keeps the gate enabled.

---

### Task 2: Invalidate ACL Readiness After Restart

**Files:**
- Modify: `agent/src/neutron_api.rs:305-390`
- Test: `agent/src/neutron_api.rs` restart-state tests

- [ ] Add a focused helper that transforms a successful runtime reconcile:

```rust
fn invalidate_restarted_acl_runtime(
    runtime: &mut NeutronRuntimeState,
    ports: &[ManagedNeutronPort],
) -> bool
```

For each port managing ACL, remove only `domain_desired_hashes["acl"]`, keep
attach ready, replace the ACL domain status with degraded/unchanged, set the
overall port status degraded, and return whether any ACL was invalidated.

- [ ] In `reconcile_committed_runtime`, apply invalidation only after a
  successful `claim_committed`. Failed attach remains blocked.
- [ ] When any ACL is invalidated, set
  `authority_state=runtime_reconcile_requires_full_resync` and a stable WAL
  status instead of `ready`.
- [ ] Append the invalidated snapshot to the Neutron WAL before RAM publication.
- [ ] If that append fails, still publish the invalidated ports/status/hashes to
  RAM with `wal_runtime_reconcile_commit_failed` / `commit_failed`; do not
  restore false-ready skip metadata.
- [ ] Run non-Cargo static checks and `git diff --check`.
- [ ] Commit as:

```bash
git commit -m "fix: require acl resync after restart"
```

- [ ] Push and dispatch Build. Expected green for restart tests; CT tests may
  remain red until Task 3 if CI commits are evaluated independently.

---

### Task 3: Make CT Clear a Gate for ACL Enforcement

**Files:**
- Modify: `agent/src/control_plane.rs:2765-2770`
- Modify: `agent/src/neutron_api.rs:208-228, 3420-3610`
- Test: `agent/src/neutron_api.rs`
- Test: `core/src/ct_ops.rs`

- [ ] Add `ControlPlane::flush_conntrack_strict`, delegating to
  `aria_core::ct_ops::scrub_ct_tables_strict` and mapping errors to
  `ControlPlaneError::KernelError`. Keep `flush_conntrack` unchanged.
- [ ] Make every Neutron ACL plan use `DisableBeforeReplace`, including
  non-empty policies.
- [ ] Route `flush_neutron_acl_conntrack` to the strict control-plane method.
- [ ] Make strict V4/V6 scrubbing propagate iterator errors instead of dropping
  them through `filter_map`; removal errors remain fatal.
- [ ] Preserve this sequence for non-empty policies:

```text
disable ACL gate
  -> replace/stage/switch ACL
  -> strict clear CT_TABLE_V4 and CT_TABLE_V6
  -> enable ACL gate
```

- [ ] Preserve empty-policy behavior: gate remains disabled after replacement
  and strict CT clear; success reports bypass/not-requested as appropriate.
- [ ] Ensure replacement or strict-flush error returns before enable. Existing
  ACL domain failure classification must explicitly report
  `status=error,effective_action=bypass` rather than ready/enforce.
- [ ] Run non-Cargo static checks and `git diff --check`.
- [ ] Commit as:

```bash
git commit -m "fix: gate acl enable on strict conntrack clear"
```

- [ ] Push and dispatch Build. Expected: all Task 1 tests and the full workflow
  pass.

---

### Task 4: Close Backlog and Verify the Batch

**Files:**
- Modify: `docs/openstack-neutron-aria-details/07-transaction-wal.md`
- Modify: `docs/openstack-neutron-aria-details/12-review-bug-backlog.md`

- [ ] Document restart status as attach ready plus ACL degraded/unchanged until
  full resync, including WAL-append failure behavior.
- [ ] Mark `REVIEW-ACL-035` fixed with domain-scoped hash invalidation,
  persisted non-ready authority, and regression evidence.
- [ ] Mark `REVIEW-ACL-053` fixed with pre-disable, strict V4/V6 CT clearing,
  enable-after-clear ordering, and missing-pin coverage.
- [ ] Recalculate active/fixed/total counts without changing the 60 REVIEW, 5
  RISK, 4 DEBT inventory totals.
- [ ] Advance Active Fix Order to the next unresolved ACL batch; do not mark
  unrelated findings fixed.
- [ ] Run allowed repository checks, including relevant Python/static CI scripts,
  but no Cargo commands.
- [ ] Inspect `git diff`, `git diff --check`, branch history, and status to prove
  `README.md` remains the only unrelated dirty file.
- [ ] Commit documentation as:

```bash
git commit -m "docs: close acl restart and ct safety batch"
```

- [ ] Push and dispatch final Build. Do not report the batch complete until the
  final GitHub Actions run is green.
