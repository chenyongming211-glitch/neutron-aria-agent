# ACL-062 Multi-Direction Compensation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace standalone QoS/Mirror per-direction publication with one strict final-state transaction that restores exact preimages and durably fences incomplete compensation.

**Architecture:** Reuse the existing managed local-domain operation, receipt, reverse-compensation, and strict-compaction boundary for every publication mode. Add a backward-compatible recovery-record map to `FirewallState`; incomplete compensation keeps the old desired state authoritative, blocks only the affected domain, and is repaired from that preimage during startup before the record is cleared.

**Tech Stack:** Rust 2021, Tokio, Serde JSON, Aya userspace pinned-map APIs, existing `WalClient`, Axum status projection, GitHub Actions warning-denied Rust/eBPF builds.

**Approved Design:** `docs/superpowers/specs/2026-08-01-acl-062-multi-direction-compensation-design.md`

**Starting Head:** `v0.9-neutron-agent@bba7035336708fff35c32077d9b56159054651a3`

## Global Constraints

- Work only on local and remote `v0.9-neutron-agent`; do not create a branch, worktree, stacked PR, or sibling delivery path.
- Before each implementation commit, require a clean worktree and zero divergence from `origin/v0.9-neutron-agent`.
- Do not run local `cargo build`, `cargo check`, `cargo test`, Clippy, or any other Cargo command.
- Submit Rust RED and GREEN evidence through GitHub Actions; record exact commit and run IDs.
- Do not add Python source-shape checkers or bind CI to private helper names.
- Do not add another generic closure/future transaction framework; reuse the existing local-domain transaction machinery.
- Preserve policy publication, Neutron owner-prefix semantics, QoS shaping downgrade, Mirror target resolution, public API schemas, and status codes except the explicit HTTP 503 recovery-required result.
- Keep `REVIEW-ACL-063`, `REVIEW-CLI-001`, `REVIEW-DOC-022`, and any QoS/Mirror shadow-bank ABI design outside this batch.
- Missing privileged execution is recorded as `deferred/pending`, never passed.

---

## File Responsibility Map

**Modify**

- `core/src/state.rs`: versioned `LocalProjectionRecovery`, backward-compatible recovery-record map, domain query/update/clear methods, and serialization behavior tests.
- `agent/src/control_plane.rs`: structured apply/transaction failure, strict recovery-record persistence, domain admission, shared standalone/managed QoS/Mirror final-state execution, exact managed-startup repair planning/execution, status maintenance reason, and Rust behavior tests.
- `agent/src/system_manager.rs`: prove standalone startup replay precedes recovery-record clearing and retain failure for retry.
- `docs/superpowers/specs/2026-08-01-acl-062-multi-direction-compensation-design.md`: approval, RED, GREEN, and final hosted evidence.
- `docs/superpowers/plans/2026-08-01-acl-062-multi-direction-compensation.md`: check off executed steps and record exact evidence.
- `docs/openstack-neutron-aria-details/12-review-bug-backlog.md`: replace the stale all-policy `let _ = ...` description and close ACL-062 only after exact-head GREEN.

No public API crate, eBPF crate, map ABI, migration, workflow, or Python checker file is added.

---

### Task 1: Submit Complete RED Behavior Contracts

**Files:**

- Modify: `core/src/state.rs`
- Modify: `agent/src/control_plane.rs`
- Modify: `agent/src/system_manager.rs`

**Interfaces:**

- Consumes: current `ManagedLocalDomainOperation`, `ManagedLocalDomainReceipt`, `managed_local_domain_compensation_operations`, and `execute_managed_local_projection_transaction` behavior.
- Produces: compile-time RED contracts for `LocalProjectionRecovery`, structured recovery classification, exact both-direction planning, marked-domain admission, managed repair planning, and replay-before-clear startup ordering.

- [x] **Step 1: Add backward-compatible state RED tests**

In `core/src/state.rs`, add tests requiring these exact future interfaces:

```rust
#[test]
fn local_projection_recovery_defaults_empty_and_round_trips_both_domains() {
    let legacy: FirewallState = serde_json::from_str("{}").unwrap();
    assert!(legacy.local_projection_recoveries.is_empty());

    let mut state = FirewallState::default();
    state.mark_local_projection_recovery(
        "qos",
        LocalProjectionRecovery::new("qos compensation failed"),
    );
    state.mark_local_projection_recovery(
        "mirror",
        LocalProjectionRecovery::new("mirror compensation failed"),
    );
    let decoded: FirewallState =
        serde_json::from_str(&serde_json::to_string(&state).unwrap()).unwrap();
    assert_eq!(decoded.local_projection_recoveries.len(), 2);
    assert_eq!(decoded.local_projection_recoveries["qos"].version, 1);
    assert_eq!(
        decoded.local_projection_recoveries["mirror"].reason,
        "mirror compensation failed"
    );
}

#[test]
fn local_projection_recovery_clear_is_domain_scoped() {
    let mut state = FirewallState::default();
    state.mark_local_projection_recovery("qos", LocalProjectionRecovery::new("q"));
    state.mark_local_projection_recovery("mirror", LocalProjectionRecovery::new("m"));
    state.clear_local_projection_recovery("qos");
    assert!(!state.local_projection_recovery_required("qos"));
    assert!(state.local_projection_recovery_required("mirror"));
}
```

- [x] **Step 2: Add transaction failure RED tests**

In the `agent/src/control_plane.rs` test module, extend the existing managed
local transaction tests with a structured apply failure and assert clean vs
incomplete rollback classification:

```rust
#[tokio::test]
async fn local_projection_clean_compensation_restores_verified_health() {
    let health = std::cell::RefCell::new(Vec::new());
    let failure = execute_managed_local_projection_transaction(
        &["ingress", "egress"],
        |next| health.borrow_mut().push(next),
        |direction| {
            if *direction == "egress" {
                std::future::ready(Err(ManagedLocalApplyFailure::clean(
                    "forced egress failure",
                )))
            } else {
                std::future::ready(Ok(*direction))
            }
        },
        || std::future::ready(Ok::<(), String>(())),
        |_receipt| std::future::ready(Ok::<(), String>(())),
        || std::future::ready(Ok::<(), String>(())),
    )
    .await
    .expect_err("later direction must fail");

    assert!(!failure.recovery_required());
    assert!(failure.contains("forced egress failure"));
    assert_eq!(
        health.into_inner(),
        vec![ManagedProjectionHealth::Unverified, ManagedProjectionHealth::Verified]
    );
}

#[tokio::test]
async fn local_projection_compensation_failure_is_attempt_all_and_recovery_required() {
    let attempts = std::cell::RefCell::new(Vec::new());
    let failure = execute_managed_local_projection_transaction(
        &["first", "second", "third"],
        |_health| {},
        |operation| {
            if *operation == "third" {
                std::future::ready(Err(ManagedLocalApplyFailure::recovery_required(
                    "third write failed",
                    "third self-compensation failed",
                )))
            } else {
                std::future::ready(Ok(*operation))
            }
        },
        || std::future::ready(Ok::<(), String>(())),
        |receipt| {
            attempts.borrow_mut().push(*receipt);
            std::future::ready(if *receipt == "second" {
                Err("second compensation failed".to_string())
            } else {
                Ok(())
            })
        },
        || std::future::ready(Ok::<(), String>(())),
    )
    .await
    .expect_err("compensation failure must remain visible");

    assert!(failure.recovery_required());
    assert!(failure.contains("third write failed"));
    assert!(failure.contains("third self-compensation failed"));
    assert!(failure.contains("second compensation failed"));
    assert_eq!(attempts.into_inner(), vec!["second", "first"]);
}
```

- [x] **Step 3: Add both-direction exact-preimage RED tests**

Add four behavior tests using the existing operation/receipt types:

```rust
#[test]
fn standalone_qos_both_plan_is_one_final_state_with_exact_preimages() {
    let old = local_projection_qos_both_fixture();
    let plans = managed_qos_direction_plans(2, 1).unwrap();
    let operations = plan_managed_local_qos_upserts(
        &old, "web", 7, 8_000_000, 256_000, 4, &plans,
    )
    .unwrap();
    let final_state = managed_local_state_after_domain_operations(&old, &operations).unwrap();
    assert_eq!(final_state.qos_rules.len(), old.qos_rules.len());
    assert_qos_rule(&final_state, 7, 0, 8_000_000, 256_000, 4, 0);
    assert_qos_rule(&final_state, 7, 1, 8_000_000, 256_000, 4, 1);
    assert_receipts_restore_complete_qos_preimages(&old, &operations);
}

#[test]
fn standalone_mirror_both_plan_is_one_final_state_with_exact_preimages() {
    let old = local_projection_mirror_both_fixture();
    let operations = plan_managed_local_mirror_upserts(
        &old, "src", 8, "dst", 9, 6, "mirror-new", 84, &[0, 1],
    )
    .unwrap();
    let final_state = managed_local_state_after_domain_operations(&old, &operations).unwrap();
    assert_mirror_targets(&final_state, 8, 9, 6, &[(0, 84), (1, 84)]);
    assert_receipts_restore_complete_mirror_preimages(&old, &operations);
}
```

Add the delete cases explicitly:

```rust
#[test]
fn standalone_qos_both_delete_receipts_restore_exact_rules() {
    let old = local_projection_qos_both_fixture();
    let operations = plan_managed_local_qos_delete(&old, 7, &[0, 1]).unwrap();
    let final_state = managed_local_state_after_domain_operations(&old, &operations).unwrap();
    assert!(!final_state.qos_rules.iter().any(|rule| rule.group_id == 7));
    assert_receipts_restore_complete_qos_preimages(&old, &operations);
}

#[test]
fn standalone_mirror_both_delete_receipts_restore_exact_rules() {
    let old = local_projection_mirror_both_fixture();
    let operations = plan_managed_local_mirror_delete(&old, 8, 9, 6, &[0, 1]).unwrap();
    let final_state = managed_local_state_after_domain_operations(&old, &operations).unwrap();
    assert!(!final_state.mirror_rules.iter().any(|rule| {
        rule.src_group_id == 8 && rule.dst_group_id == 9 && rule.proto == 6
    }));
    assert_receipts_restore_complete_mirror_preimages(&old, &operations);
}
```

The named assertion helpers iterate each operation, call
`build_managed_local_domain_receipt(operation, &old)`, expand
`managed_local_domain_compensation_operations`, and compare every concrete
field against the corresponding rule in `old`.

- [x] **Step 4: Add durable fence and startup RED tests**

Add tests for these pure boundaries:

```rust
#[test]
fn local_projection_recovery_admission_is_domain_scoped() {
    let mut state = FirewallState::default();
    state.mark_local_projection_recovery(
        "qos",
        LocalProjectionRecovery::new("forced rollback failure"),
    );
    assert!(local_projection_recovery_admission(&state, LocalWriteDomain::Qos).is_err());
    assert!(local_projection_recovery_admission(&state, LocalWriteDomain::Mirror).is_ok());
}

#[test]
fn local_projection_recovery_is_the_stable_maintenance_reason() {
    let mut state = FirewallState::default();
    state.mark_local_projection_recovery(
        "mirror",
        LocalProjectionRecovery::new("forced rollback failure"),
    );
    assert_eq!(
        local_projection_maintenance_reason(&state, 3).as_deref(),
        Some("local_projection_recovery_required:mirror")
    );
}

#[test]
fn managed_startup_recovery_plan_repairs_expected_before_deleting_extra() {
    let desired = local_projection_qos_both_fixture();
    let actual = vec![actual_qos(7, 0, 99), actual_qos(100, 1, 1)];
    let operations = plan_local_projection_runtime_repair(&desired, &actual, &[], &[]).unwrap();
    assert!(matches!(operations[0], ManagedLocalDomainOperation::QosUpsert(_)));
    assert!(matches!(operations.last().unwrap(), ManagedLocalDomainOperation::QosDelete { .. }));
}

#[test]
fn standalone_start_clears_recovery_only_after_replay_and_registration() {
    let source = include_str!("system_manager.rs");
    let start = source.split("pub async fn system_start(").nth(1).unwrap();
    let replay = start.find("replay_state_from_snapshot").unwrap();
    let register = start.find("register_system_instance").unwrap();
    assert!(replay < register);
    assert!(!start[..register].contains("clear_local_projection_recoveries"));
}
```

The final test checks a public lifecycle ordering that cannot be expressed by
an unprivileged map fixture; it must not assert private helper spelling beyond
the existing public startup and replay calls.

Keep the existing policy transaction behaviors
`standalone_acl_publication_allow_to_deny_is_one_both_direction_epoch` and
`standalone_acl_publication_delete_allow_removes_both_directions_once` in the
hosted Rust behavior filter. They are the policy regression proof; do not add a
source-shape assertion for the private ACL implementation.

- [x] **Step 5: Commit and push RED**

Run only non-compiling hygiene:

```bash
git diff --check
git status --short
```

Expected: no whitespace errors; only the three Rust test files are modified.

Commit and push:

```bash
git add core/src/state.rs agent/src/control_plane.rs agent/src/system_manager.rs
git commit -m "test: expose ACL multi-direction recovery gaps"
git push origin v0.9-neutron-agent
```

Expected hosted result: `rust-behavior` fails because the recovery model and
structured transaction interfaces do not exist; unrelated `fast-contracts`
remain green. Record the exact run before writing production code.

---

### Task 2: Implement the Durable Recovery Model and Structured Failure

**Files:**

- Modify: `core/src/state.rs`
- Modify: `agent/src/control_plane.rs`

**Interfaces:**

- Consumes: RED state and transaction tests from Task 1.
- Produces: `LocalProjectionRecovery`, `FirewallState.local_projection_recoveries`, `ManagedLocalApplyFailure`, `ManagedLocalProjectionFailure::recovery_required`, strict record persistence, and domain-scoped admission.

- [x] **Step 1: Add the versioned recovery state**

Add to `core/src/state.rs`:

```rust
pub const LOCAL_PROJECTION_RECOVERY_VERSION: u8 = 1;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LocalProjectionRecovery {
    pub version: u8,
    pub reason: String,
}

impl LocalProjectionRecovery {
    pub fn new(reason: impl Into<String>) -> Self {
        Self {
            version: LOCAL_PROJECTION_RECOVERY_VERSION,
            reason: reason.into(),
        }
    }
}
```

Add this field to `FirewallState` and initialize it in `Default`:

```rust
#[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
pub local_projection_recoveries: BTreeMap<String, LocalProjectionRecovery>,
```

Implement exact domain methods that reject an empty domain and preserve other
records:

```rust
pub fn mark_local_projection_recovery(
    &mut self,
    domain: &str,
    recovery: LocalProjectionRecovery,
) {
    self.local_projection_recoveries
        .insert(domain.to_string(), recovery);
}

pub fn local_projection_recovery_required(&self, domain: &str) -> bool {
    self.local_projection_recoveries.contains_key(domain)
}

pub fn clear_local_projection_recovery(&mut self, domain: &str) {
    self.local_projection_recoveries.remove(domain);
}

pub fn clear_local_projection_recoveries(&mut self) {
    self.local_projection_recoveries.clear();
}
```

- [x] **Step 2: Make apply and transaction failure structured**

Replace string-only current-operation failure with:

```rust
#[derive(Debug)]
struct ManagedLocalApplyFailure {
    message: String,
    recovery_required: bool,
}

impl ManagedLocalApplyFailure {
    fn clean(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            recovery_required: false,
        }
    }

    fn recovery_required(
        apply: impl Into<String>,
        compensation: impl Into<String>,
    ) -> Self {
        Self {
            message: format!(
                "{}; current-operation compensation failed: {}",
                apply.into(),
                compensation.into()
            ),
            recovery_required: true,
        }
    }
}
```

Extend `ManagedLocalProjectionFailure` with `recovery_required: bool` and make
`transaction_failure` set it when the apply failure is uncertain, any reverse
compensation fails, or durable restore fails. After clean compensation, call
`set_health(ManagedProjectionHealth::Verified)`; incomplete restoration sets
`RepairRequired`.

Preserve current error kind selection: kernel apply failures remain
`KernelError`; compact failures remain `PersistenceError` unless recovery is
required, in which case the caller returns `InstanceNotReady`.

- [x] **Step 3: Persist and publish recovery records strictly**

Add one `InstanceState` method:

```rust
async fn persist_local_projection_recovery(
    &mut self,
    domain: LocalWriteDomain,
    failure: ManagedLocalProjectionFailure,
) -> ControlPlaneError {
    let mut recovery_state = self.state.clone();
    recovery_state.mark_local_projection_recovery(
        domain.as_str(),
        LocalProjectionRecovery::new(failure.message.clone()),
    );
    let persist_error = self.compact_and_publish_state(recovery_state.clone()).await.err();
    self.state = recovery_state;
    let mut message = failure.message;
    if let Some(error) = persist_error {
        message.push_str("; persist recovery record: ");
        message.push_str(&error);
    }
    ControlPlaneError::InstanceNotReady(format!(
        "local projection recovery required for {}: {}",
        domain.as_str(), message
    ))
}
```

Do not lose the RAM fence if compact fails. Add
`local_projection_recovery_admission(&FirewallState, LocalWriteDomain)` and
call it again under the instance write lock before planning QoS/Mirror writes.
Update `ensure_local_write_allowed` to provide the same early API result.

- [x] **Step 4: Run hosted GREEN for this subset only after complete production compilation**

Do not push an intermediate production commit that cannot compile. Continue
directly to Tasks 3 and 4, then submit one GREEN implementation commit.

---

### Task 3: Route Standalone and Managed QoS/Mirror Through One Transaction

**Files:**

- Modify: `agent/src/control_plane.rs`

**Interfaces:**

- Consumes: Task 2 recovery state and current domain planners/receipts.
- Produces: one concrete locked executor used by all four QoS/Mirror public entry points; no legacy per-direction RAM/WAL loop remains.

- [x] **Step 1: Add one concrete final-state executor**

Add a method that accepts `LocalWriteDomain`, `old_state`, `final_state`, and
the already planned `Vec<ManagedLocalProjectionOperation>`. It must create the
existing runtime closures, call `execute_managed_local_projection_transaction`,
publish final RAM only on success, and call
`persist_local_projection_recovery` only when
`failure.recovery_required()` is true.

Cleanly compensated failures restore the prior projection health and return
their existing kernel/persistence error without a durable record.

- [x] **Step 2: Convert QoS add and delete**

In `add_qos`, resolve the group and direction plan once for every publication
mode. Build `domain_operations` with `plan_managed_local_qos_upserts` and
`final_state` with `managed_local_state_after_domain_operations`.

For standalone/attach-owned compatibility, wrap only the domain operations.
For managed mode, retain current general-map and owner-prefix planning and
merge those operations as before. Submit both to the same executor.

For `delete_qos`, resolve requested directions, call
`plan_managed_local_qos_delete`, construct `final_state`, retain the current
managed retained-group/general-map operations only in `ManagedAcl`, and submit
the merged list through the same executor. Stats and owned-FQ cleanup occur
only after commit. Delete `add_qos_standalone_locked`,
`delete_qos_standalone_locked`, and `rollback_qos_deletes` after all callers
are gone.

- [x] **Step 3: Convert Mirror add and delete**

Resolve target ifindex before any write. Use the current Mirror planners for
both standalone and managed modes, with an empty general delta in standalone.
Clear stats only after commit. Delete `add_mirror_standalone_locked`,
`delete_mirror_standalone_locked`, and `rollback_mirror_deletes` after all
callers are gone.

- [x] **Step 4: Preserve policy publication routing**

Do not change `add_policy`, `delete_policy`, batch policy planning, or
`agent/src/control_plane/standalone_acl.rs`. Ensure the RED policy routing test
continues to pass without production changes.

---

### Task 4: Recover Durable Local Projection Records at Startup

**Files:**

- Modify: `agent/src/control_plane.rs`
- Modify: `agent/src/system_manager.rs`

**Interfaces:**

- Consumes: durable recovery records and the old desired QoS/Mirror state.
- Produces: exact managed in-place repair before preexisting-live validation and strict standalone record clearing after replay/registration.

- [x] **Step 1: Plan exact managed local projection repair**

Add a pure planner that compares desired QoS/Mirror entries with the captured
tap-local entries. Its order is:

1. upsert every missing or changed desired key;
2. delete every extra actual key; and
3. leave identical keys untouched.

Mirror planning covers policy and global maps. Resolve desired target ifindex
from the durable target name before producing operations. Sort operations by
domain and key so fault injection and diagnostics are deterministic.

- [x] **Step 2: Execute repair before preexisting-live preservation**

In `prepare_managed_registration`, when recovery records are non-empty and
live pins exist:

1. capture actual QoS/Mirror entries;
2. execute the exact repair plan with existing raw domain operations;
3. run `validate_pinned_runtime_state_with_mode` through the public managed
   validator against the unchanged durable state;
4. strictly compact the same state with all repaired recovery records removed;
5. only then allow the normal preexisting-live validation/preservation path.

Any capture, operation, validation, or compact failure shuts down the WAL,
returns registration failure, and preserves the records for retry. Do not call
`scrub_managed_runtime_state` while links are live because removing
`TAP_CONFIG_MAP` would create an unguarded interval.

- [x] **Step 3: Clear standalone records only after successful replay**

`system_start` already scrubs and replays the approved durable snapshot before
`register_system_instance`. Keep that order. In registration, after runtime
configuration and readiness prerequisites succeed but before the instance is
published, strictly compact a clone with recovery records cleared. A clear
failure aborts registration and retains the durable records for retry.

- [x] **Step 4: Expose stable maintenance state**

Extend `InstanceRuntimeHealthSnapshot.maintenance_reason` selection:

```rust
let local_recovery = state
    .state
    .local_projection_recoveries
    .keys()
    .next()
    .map(|domain| format!("local_projection_recovery_required:{}", domain));
```

Prefer recovery-required over bitmap-cleanup maintenance. Keep raw diagnostic
reasons in state/logs, not in the stable status reason.

---

### Task 5: Submit GREEN, Review the Diff, and Close the Register

**Files:**

- Modify: implementation files from Tasks 2-4
- Modify: `docs/superpowers/specs/2026-08-01-acl-062-multi-direction-compensation-design.md`
- Modify: `docs/superpowers/plans/2026-08-01-acl-062-multi-direction-compensation.md`
- Modify: `docs/openstack-neutron-aria-details/12-review-bug-backlog.md`

**Interfaces:**

- Consumes: all RED tests and production work.
- Produces: one reviewed GREEN implementation commit, exact-head hosted evidence, and an accurate ACL-062 closure.

- [x] **Step 1: Perform non-compiling local review**

Run:

```bash
git diff --check
git diff --stat
git status --short
rg -n "add_qos_standalone_locked|delete_qos_standalone_locked|add_mirror_standalone_locked|delete_mirror_standalone_locked|rollback_qos_deletes|rollback_mirror_deletes" agent/src/control_plane.rs
```

Expected: no whitespace errors; the legacy symbols have no matches; changes
are limited to the planned Rust and documentation files. Inspect every changed
caller and compensation edge manually. Do not invoke Cargo.

- [x] **Step 2: Commit and push GREEN production**

```bash
git add core/src/state.rs agent/src/control_plane.rs agent/src/system_manager.rs
git commit -m "fix: make ACL multi-direction writes recoverable"
git push origin v0.9-neutron-agent
```

Expected: push starts Build on the exact commit.

- [x] **Step 3: Require exact-head hosted GREEN**

Use GitHub Actions evidence for the pushed commit. Require:

- `fast-contracts`: success;
- `rust-behavior`: success with every ACL-062 named behavior executed;
- `rust-build`: success with warnings denied for userspace and eBPF; and
- any maintained static job: success without a new private-source checker.

If CI fails, inspect the exact job log, make the smallest in-scope correction,
commit, push, and require a new exact-head run. Never hide warnings or remove a
behavior assertion to obtain GREEN.

- [x] **Step 4: Review scope and code volume**

Run:

```bash
git diff --stat bba7035..HEAD
git diff --numstat bba7035..HEAD
git log --oneline --stat bba7035..HEAD
```

Confirm the four old loops and rollback helpers were removed, the net change is
dominated by Rust behavior/recovery code rather than checkers, and no unrelated
backlog item entered the diff.

- [x] **Step 5: Update durable evidence**

Update the design status with RED commit/run, GREEN commit/run, and any field
evidence explicitly `deferred/pending`. Check off this plan with the same IDs.

Replace both ACL-062 summaries in the backlog with the revalidated scope:

```text
Policy was already fixed by ACL-057/066 and managed QoS/Mirror already used
the receipt transaction. The remaining standalone/attach-owned QoS/Mirror
paths now publish one strict final state, restore complete prior rules, return
all compensation failures, and durably fence incomplete recovery.
```

Mark `REVIEW-ACL-062` fixed only after exact-head hosted GREEN. Do not close
ACL-063 or advance the recorded order beyond ACL-062.

- [x] **Step 6: Commit, push, and verify documentation head**

```bash
git add docs/superpowers/specs/2026-08-01-acl-062-multi-direction-compensation-design.md \
  docs/superpowers/plans/2026-08-01-acl-062-multi-direction-compensation.md \
  docs/openstack-neutron-aria-details/12-review-bug-backlog.md
git commit -m "docs: close ACL multi-direction recovery"
git push origin v0.9-neutron-agent
```

Require the documentation head Build to remain GREEN, then confirm:

```bash
git status --short --branch
git rev-list --left-right --count v0.9-neutron-agent...origin/v0.9-neutron-agent
```

Expected: clean worktree and `0 0` divergence.
