# ACL Batch 4 Stateful Conntrack Contract Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix `REVIEW-ACL-050` and `REVIEW-ACL-054` so Neutron ACL stateful intent controls the per-tap CT fast path, ACL-owned CT cannot be changed locally, and ACL/CT activation has no recreate-after-flush race.

**Architecture:** The ACL translation plan carries `Option<bool>` CT intent. Reconcile atomically quiesces CT and ACL in one tap-config write, replaces policy, strictly clears CT, then atomically publishes the desired CT mode and ACL gate. Local conntrack writes are rejected when ACL owns the port, while Neutron capabilities remain `attach + acl` only.

**Tech Stack:** Rust, Tokio, Axum, Aya pinned maps, eBPF per-tap config, GitHub Actions, repository Python/static contract checks.

## Global Constraints

- Implement only `REVIEW-ACL-050` and `REVIEW-ACL-054`.
- Do not implement ACL priority, QoS, Mirror, or WAL compaction.
- Do not add `conntrack` to accepted or advertised Neutron managed domains.
- Preserve OVS forwarding and the availability-first ACL bypass boundary.
- Never run local `cargo build`, `cargo check`, or `cargo test`; GitHub Actions provides Rust red/green evidence.
- Preserve and exclude the user's uncommitted `README.md` change.
- Use separate red-test, implementation, and closure-documentation commits.

## File Map

| File | Responsibility |
| --- | --- |
| `agent/src/neutron_api.rs` | ACL CT intent, pure runtime transition plan, ordered reconcile, compensation, Rust tests. |
| `agent/src/control_plane.rs` | Local-write authority for CT as an ACL dependency and Rust tests. |
| `ci/check_neutron_stage1.py` | Static guard that the dependency-authority regression remains present. |
| `docs/openstack-neutron-aria-details/07-transaction-wal.md` | ACL/CT quiesce, flush, and atomic publication contract. |
| `docs/neutron-managed-domains-contract.md` | ACL-selected authority over its internal CT dependency without a new managed domain. |
| `docs/openstack-neutron-aria-details/12-review-bug-backlog.md` | Fixed status, evidence, counts, and next ACL batch. |

---

### Task 1: Establish Red Stateful And Authority Evidence

**Files:**
- Test: `agent/src/neutron_api.rs`
- Test: `agent/src/control_plane.rs`

**Interfaces:**
- Requires future `AclApplyPlan.conntrack_enabled: Option<bool>`.
- Requires future `acl_runtime_transition(&AclApplyPlan, bool) -> AclRuntimeTransition`.
- Exercises existing `ControlPlane::ensure_local_write_allowed`.

- [ ] **Step 1: Add failing translator tests**

Add a stateful and stateless pair:

```rust
#[test]
fn neutron_acl_translator_carries_conntrack_intent() {
    let stateful = ready_acl(vec![tcp_rule("drop-8080", "drop", 8080)]);
    assert_eq!(
        translate_neutron_acl("port-1", &stateful).unwrap().conntrack_enabled,
        Some(true)
    );

    let mut stateless = stateful;
    stateless.stateful = false;
    assert_eq!(
        translate_neutron_acl("port-1", &stateless).unwrap().conntrack_enabled,
        Some(false)
    );
}
```

Also assert `AclApplyPlan::default().conntrack_enabled == None`, proving a
missing ACL payload preserves the existing CT mode.

- [ ] **Step 2: Add failing transition tests**

Require one pure transition helper:

```rust
let transition = acl_runtime_transition(&plan, true);
assert_eq!(
    transition.quiesce,
    AclRuntimeFeatureState { conntrack_enabled: false, acl_enabled: false }
);
assert_eq!(
    transition.publish,
    AclRuntimeFeatureState { conntrack_enabled: false, acl_enabled: true }
);
```

Cover stateful enforce (`true,true`), stateless enforce (`false,true`), empty
stateful bypass (`true,false`), and missing-payload preservation (`prior,false`).

- [ ] **Step 3: Add failing ACL-dependency authority test**

Mark only `managed_domains=["acl"]`, then require:

```rust
let error = cp
    .ensure_local_write_allowed("tap-vm", LocalWriteDomain::Conntrack)
    .await
    .expect_err("ACL authority must protect its CT dependency");
assert_eq!(error.status_code(), 409);
assert!(error.to_string().contains("dependency of 'acl'"));
```

Retain assertions that unrelated QoS, Trace, and other local domains remain
writable.

- [ ] **Step 4: Commit and obtain red CI evidence**

```bash
git add agent/src/neutron_api.rs agent/src/control_plane.rs
git commit -m "test: require ACL stateful conntrack contract"
git push -u origin codex/acl-batch-4-stateful-contract
gh workflow run Build --ref codex/acl-batch-4-stateful-contract -f publish_artifacts=false
```

Expected: Rust compilation fails because `conntrack_enabled`,
`AclRuntimeFeatureState`, and `acl_runtime_transition` do not exist. The
authority assertion would also fail against the current selected-domain-only
guard.

---

### Task 2: Implement ACL-Owned Conntrack Transitions

**Files:**
- Modify: `agent/src/neutron_api.rs:185-225,3373-3740`
- Modify: `agent/src/control_plane.rs:225-265,760-805`
- Test: the Task 1 Rust tests

**Interfaces:**
- Produces `AclApplyPlan.conntrack_enabled: Option<bool>`.
- Produces `AclRuntimeFeatureState { conntrack_enabled: bool, acl_enabled: bool }`.
- Produces `AclRuntimeTransition { quiesce, publish }`.
- Consumes `ControlPlane::get_config`, `update_config`, `replace_owned_acl`, and `flush_conntrack_strict`.

- [ ] **Step 1: Carry stateful intent through translation**

Extend the plan and early bypass return:

```rust
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct AclApplyPlan {
    groups: Vec<AclGroupPlan>,
    policies: Vec<AclPolicyPlan>,
    conntrack_enabled: Option<bool>,
}

fn bypass_acl_plan(acl: &NeutronAclSnapshot) -> AclApplyPlan {
    AclApplyPlan {
        conntrack_enabled: Some(acl.stateful),
        ..AclApplyPlan::default()
    }
}
```

Every successful translation returns `Some(acl.stateful)`. The no-payload path
continues to use `AclApplyPlan::default()` and therefore preserves CT. Update
the existing test-only `AclApplyPlan` struct literals to include the intended
`conntrack_enabled` value so the new field is explicit at each call site.

- [ ] **Step 2: Add the pure runtime transition model**

```rust
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct AclRuntimeFeatureState {
    conntrack_enabled: bool,
    acl_enabled: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct AclRuntimeTransition {
    quiesce: AclRuntimeFeatureState,
    publish: AclRuntimeFeatureState,
}

fn acl_runtime_transition(
    plan: &AclApplyPlan,
    preserved_conntrack_enabled: bool,
) -> AclRuntimeTransition {
    AclRuntimeTransition {
        quiesce: AclRuntimeFeatureState {
            conntrack_enabled: false,
            acl_enabled: false,
        },
        publish: AclRuntimeFeatureState {
            conntrack_enabled: plan
                .conntrack_enabled
                .unwrap_or(preserved_conntrack_enabled),
            acl_enabled: !plan.policies.is_empty(),
        },
    }
}
```

- [ ] **Step 3: Apply the transition in strict order**

Before mutation, read current config only when
`plan.conntrack_enabled.is_none()`; otherwise the snapshot already supplies the
desired value. Calculate the transition, then replace the existing ACL-only
disable with one atomic call:

```rust
update_config(ifname, Some(false), None, Some(false), None, None, None, None)
```

After policy replacement and strict CT clear, use one final call:

```rust
update_config(
    ifname,
    Some(transition.publish.conntrack_enabled),
    None,
    Some(transition.publish.acl_enabled),
    None,
    None,
    None,
    None,
)
```

The empty-policy path must perform this final restore before returning. The
post-publish compensation call must set both CT and ACL false in one update.
Translation/config-read errors report unchanged; all failures after successful
quiesce report bypass except compensation failure, which reports enforce.

- [ ] **Step 4: Protect local CT writes as an ACL dependency**

Extend `ControlPlaneError::LocalWriteBlocked` with
`dependency_of: Option<String>`. Direct domain blocks use `None`; an ACL-owned
conntrack block uses `Some("acl".to_string())`. Display the latter as:

```text
LOCAL_WRITE_BLOCKED_FOR_NEUTRON_MANAGED_DOMAIN: instance '...' domain 'conntrack' is managed by Neutron as a dependency of 'acl'; update this domain through Neutron
```

In `ensure_local_write_allowed`, block Conntrack when either `conntrack` or
`acl` is selected. Do not mutate the stored `managed_domains` set.

- [ ] **Step 5: Run allowed local checks and commit**

```bash
python3 ci/check_blocked_terms.py
python3 ci/check_neutron_stage1.py
python3 ci/check_neutron_stage2_acl.py
git diff --check
git add agent/src/neutron_api.rs agent/src/control_plane.rs
git commit -m "fix: bind ACL stateful mode to conntrack"
```

- [ ] **Step 6: Push and obtain green CI evidence**

Push and dispatch Build. Expected: Task 1 tests compile and pass, eBPF builds,
and static userspace agent compilation succeeds.

---

### Task 3: Close Backlog And Guard The Contract

**Files:**
- Modify: `ci/check_neutron_stage1.py`
- Modify: `docs/openstack-neutron-aria-details/07-transaction-wal.md`
- Modify: `docs/neutron-managed-domains-contract.md`
- Modify: `docs/openstack-neutron-aria-details/12-review-bug-backlog.md`

**Interfaces:**
- Consumes the implemented Rust test names and stable dependency error text.
- Produces durable documentation and CI text guards for `ACL-050/054` closure.

- [ ] **Step 1: Add the Stage 1 static guard**

Require these exact implementation/test markers in `ci/check_neutron_stage1.py`:

```python
"fn neutron_acl_translator_carries_conntrack_intent(",
"fn neutron_acl_runtime_transition_is_atomic(",
"fn domain_authority_blocks_conntrack_as_acl_dependency(",
"dependency of 'acl'",
```

- [ ] **Step 2: Document the runtime contract**

Document that CT and ACL are quiesced together, strict CT clearing runs while
creation is disabled, and desired CT plus final ACL gate are published by one
tap-config insert. Document that `managed_domains=acl` blocks local CT changes
only as an internal dependency and does not advertise a new Neutron domain.

- [ ] **Step 3: Close only ACL-050 and ACL-054**

Mark both rows fixed with code/test/CI evidence. Recalculate all review-state
counts without changing the inventory totals of 60 REVIEW, 5 RISK, and 4 DEBT.
Move the next ACL work item to `REVIEW-ACL-047`; leave `REVIEW-OPS-019` open and
do not alter QoS/Mirror findings.

- [ ] **Step 4: Run the complete allowed local verification set**

```bash
python3 ci/check_blocked_terms.py
PYTHONPATH=openstack/neutron_aria python3 -m unittest discover \
  -s openstack/neutron_aria/neutron_aria/tests/unit -p 'test_*.py'
python3 ci/check_neutron_stage1.py
python3 ci/check_neutron_stage2_acl.py
python3 ci/check_stage3_readiness.py
git diff --check
```

- [ ] **Step 5: Inspect scope and commit closure docs**

Confirm `README.md` is still the only unrelated dirty file, then commit only
the CI/doc files:

```bash
git commit -m "docs: close ACL stateful conntrack batch"
```

- [ ] **Step 6: Push and obtain final green CI**

Push and dispatch Build with `publish_artifacts=false`. Do not report the batch
complete until the workflow for the closure commit succeeds.
