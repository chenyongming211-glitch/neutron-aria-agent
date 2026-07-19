# ACL Selector Transaction Repair Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the three confirmed ACL-046 transaction defects without changing the approved selector-isolation product boundary: detach must never expose an active-policy-miss PASS window, owned purge must be atomic, and strict CT flush failure must restore the old publication.

**Architecture:** Replace item-at-a-time detach purge with a quiesced empty-owned-ACL reconcile. Move strict CT flush inside the owned publication transaction, before post-commit cleanup, and retain enough focused publication preimage to restore the old bank, general selectors, and durable state. Keep behavior proof in Rust tests and privileged smoke; reduce Python checkers to stable public-contract and CI-wiring checks.

**Tech Stack:** Rust/Tokio control plane, Aya eBPF pinned maps, WAL/state compaction, Python CI contract checks, Bash privileged smoke, GitHub Actions.

## Global Constraints

- Do not run `cargo build`, `cargo check`, or `cargo test` locally; Rust/eBPF compilation and tests run only in GitHub Actions.
- Do not change eBPF map key/value layouts, `PolicyKey`, `TapConfig`, CT ABI, WAL/state schema, UDS/public API fields, or standalone direct-publication semantics.
- Preserve the approved ACL-046 order: quiesce, publish general/shadow/bank/durable state, strict CT flush, then publish the runtime gate.
- Do not replace rollback with an implicit fail-closed roll-forward policy. Any such policy change requires a separate design approval.
- Do not add Python rules that constrain private Rust helper names, parameter names/order, local-variable names, tail-call spelling, or internal delegation shape.
- Keep the PR Draft until exact-head hosted CI and privileged managed/standalone field evidence are recorded.
- Each RED commit contains Rust behavior tests and only the minimal CI test-discovery wiring needed to run them.

---

## File Responsibility Map

- `agent/src/control_plane.rs`: owns publication, strict CT flush, rollback preimages, durable restoration, and managed projection health.
- `agent/src/neutron_api.rs`: owns detach/failure-cleanup orchestration and the rule that purge failure aborts detach.
- `agent/src/tap_registry.rs`: remains the link detach/unregister owner; it must only run after owned ACL cleanup succeeds.
- `core/src/ebpf_ops/projection.rs`: remains the single projection compiler/planner; no new projection implementation is allowed.
- `ci/check_neutron_stage1.py`: discovers behavior tests and checks stable public wiring only.
- `ci/check_tc_acl_smoke.py` and `ci/check_standalone_tc_acl_smoke.py`: validate runnable smoke entrypoints/result schema without embedding a second implementation.
- `deploy/kolla/smoke/neutron_aria_acl_tc_datapath_smoke.sh`: proves managed detach/purge/flush behavior on real pinned maps.
- `deploy/smoke/aria_standalone_acl_tc_datapath_smoke.sh`: preserves standalone compatibility coverage.
- `docs/openstack-neutron-aria-details/12-review-bug-backlog.md`: records the three confirmed findings and closure evidence.
- `docs/openstack-neutron-aria-details/17-acl-selector-ownership-isolation.md`: records the implemented transaction boundary, not a new product design.

---

### Task 1: Record the confirmed defects and land behavior-only RED coverage

**Files:**

- Modify: `docs/openstack-neutron-aria-details/12-review-bug-backlog.md`
- Modify: `agent/src/control_plane.rs`
- Modify: `agent/src/neutron_api.rs`
- Modify: `ci/check_neutron_stage1.py`

**Interfaces:**

- Consumes: current `replace_owned_acl`, `purge_neutron_acl`, `delete_policy_for_neutron_purge`, `delete_group_for_neutron_purge`, and `execute_managed_acl_post_replace_completion` behavior.
- Produces: four named RED behavior contracts used by Tasks 2 and 3.

- [ ] **Step 1: Record three separate findings**

Add backlog entries with these exact scopes:

```text
REVIEW-ACL-064 P1: detach purge mutates the active bank before TC detach and can default PASS.
REVIEW-ACL-065 P1: privileged policy purge and admitted group purge can partially commit and persist.
REVIEW-TXN-030 P1 contract/P2 runtime: strict CT flush occurs after bank/general/durable commit and cannot restore preimages.
```

Cross-reference `REVIEW-ACL-023` as the older ignored-purge-error symptom; do not merge the new root causes into that P2 item.

- [ ] **Step 2: Add RED publication rollback tests**

Add tests named:

```rust
#[tokio::test]
async fn managed_owned_acl_strict_flush_failure_restores_old_publication() { /* ... */ }

#[tokio::test]
async fn managed_owned_acl_strict_flush_rollback_failure_stays_unverified() { /* ... */ }
```

The first test must assert old active bank, old general values, old durable state, and non-published gate after injected strict-flush failure. The second must assert combined primary/compensation diagnostics and `ManagedProjectionHealth::Unverified` when restoration itself fails.

- [ ] **Step 3: Add RED detach/purge orchestration tests**

Add tests named:

```rust
#[tokio::test]
async fn neutron_acl_detach_quiesces_before_owned_projection_removal() { /* ... */ }

#[tokio::test]
async fn neutron_acl_purge_failure_aborts_detach_without_partial_owned_state() { /* ... */ }
```

Record ordered events and require:

```text
quiesce_gate
replace_owned_acl_with_empty_snapshot
strict_ct_flush
detach_links
```

On any purge/publication/flush failure, `detach_links` must be absent and the old owned state must be complete.

- [ ] **Step 4: Register only the test prefixes**

Add these stable prefixes to `RUST_TESTS`/test discovery:

```python
"managed_owned_acl_strict_flush_"
"neutron_acl_detach_"
"neutron_acl_purge_failure_"
```

Do not add source-body parsing or mutation self-tests.

- [ ] **Step 5: Commit and push RED**

```bash
git add agent/src/control_plane.rs agent/src/neutron_api.rs \
  ci/check_neutron_stage1.py \
  docs/openstack-neutron-aria-details/12-review-bug-backlog.md
git -c user.name=netmouser -c user.email=chenyongming211@gmail.com \
  commit -m "test: expose managed ACL transaction gaps"
git push origin codex/review-acl-046-selector-isolation-design
```

Expected GitHub result: the new Rust tests fail for missing rollback/quiesced-purge behavior; pre-existing jobs remain green until the Rust test phase.

---

### Task 2: Put strict CT flush inside the owned publication transaction

**Files:**

- Modify: `agent/src/control_plane.rs`
- Modify: `agent/src/neutron_api.rs`

**Interfaces:**

- Consumes: `publish_acl_projection_locked`, existing general-mutation compensation, bank restoration, created-port-set quarantine, and durable old-state restoration.
- Produces: one Neutron-owned reconcile entrypoint whose success means bank/general/durable state and strict CT flush all succeeded.

- [ ] **Step 1: Reuse the existing publication receipt**

Rename the existing demotion-specific receipt to the shared concrete name
`ManagedAclPublicationReceipt` and reuse its existing general/pre-bank
compensation behavior. Do not introduce a parallel receipt enum. Add only the
owned transaction context that the existing demotion path does not need:

```rust
struct ManagedOwnedAclRollbackContext {
    receipts: Vec<ManagedAclPublicationReceipt>,
    old_state: FirewallState,
    created_port_sets: Vec<TransactionCreatedPortSet>,
}
```

`publish_acl_projection_locked` populates the shared receipts only when it
actually publishes. A clean no-op returns no rollback context. Existing
demotion tests must continue to exercise the same receipt compensation path.

- [ ] **Step 2: Split lock ownership from publication mechanics**

Refactor to a locked helper with one public transaction entrypoint:

```rust
async fn replace_owned_acl_locked(
    &self,
    instance: &str,
    state: &mut InstanceState,
    owner_prefix: &str,
    exclusive_policy_domain: bool,
    groups: &[OwnedAclGroupSpec],
    policies: &[OwnedAclPolicySpec],
    require_tc_acl_links: bool,
) -> Result<(OwnedAclReconcileReport, Option<ManagedOwnedAclRollbackContext>), ControlPlaneError>;

pub async fn replace_owned_acl_and_flush(
    &self,
    instance: &str,
    owner_prefix: &str,
    exclusive_policy_domain: bool,
    groups: &[OwnedAclGroupSpec],
    policies: &[OwnedAclPolicySpec],
    require_tc_acl_links: bool,
) -> Result<OwnedAclReconcileReport, ControlPlaneError>;
```

The public method acquires `runtime_lifecycle_lock` and the instance write lock once and holds both through strict CT flush and any rollback.

- [ ] **Step 3: Flush before irreversible cleanup**

Inside `replace_owned_acl_and_flush` use this exact order:

```text
build final state
apply general delta
stage inactive bank
verify TC
switch bank
persist final state
strict scrub IPv4/IPv6 CT tables
post-commit bitmap/stat cleanup
return success
```

Do not clear released port sets or stats before strict flush succeeds.

- [ ] **Step 4: Restore the old publication on flush failure**

On strict-flush failure, while locks are still held:

```text
set health Unverified
restore previous active bank
apply inverse general mutations in reverse order
restore durable old_state
scrub the failed published bank only after old-bank restoration succeeds
clean transaction-created port sets; quarantine cleanup failures durably
return the flush error plus every compensation error
```

Reuse the existing compensation/preimage helpers. Do not add a second general-map rollback implementation.

- [ ] **Step 5: Remove the outer strict flush**

Change `reconcile_neutron_acl` to call `replace_owned_acl_and_flush`. Remove the separate `flush_neutron_acl_conntrack` step from `execute_managed_acl_post_replace_completion`; that helper should now perform only gate publication, precommit fault handling, verification, and re-quiesce on later failure.

- [ ] **Step 6: Push GREEN and verify exact-head CI**

```bash
git add agent/src/control_plane.rs agent/src/neutron_api.rs
git -c user.name=netmouser -c user.email=chenyongming211@gmail.com \
  commit -m "fix: roll back managed ACL publication on CT flush failure"
git push origin codex/review-acl-046-selector-isolation-design
gh run watch --exit-status
```

Expected GitHub result: strict-flush RED tests pass; all existing publication, restart, demotion, and warning-as-error jobs pass.

---

### Task 3: Replace item-at-a-time purge with a quiesced empty-owned transaction

**Files:**

- Modify: `agent/src/neutron_api.rs`
- Modify: `agent/src/control_plane.rs`
- Modify: `agent/src/tap_registry.rs` only if a result type must carry the detach-aborted reason

**Interfaces:**

- Consumes: `replace_owned_acl_and_flush` from Task 2 and the existing serialized runtime-gate update.
- Produces: `purge_neutron_acl_transactionally`, whose success is required before detach.

- [ ] **Step 1: Replace the purge body**

Use this focused orchestration:

```rust
async fn purge_neutron_acl_transactionally(
    state: &NeutronApiState,
    ifname: &str,
    port_id: &str,
) -> Result<OwnedAclReconcileReport, String> {
    state.registry.update_neutron_acl_runtime_gate(
        ifname,
        false,
        false,
        false,
    ).await.map_err(|error| error.to_string())?;

    state.control_plane.replace_owned_acl_and_flush(
        ifname,
        &neutron_acl_prefix(port_id),
        true,
        &[],
        &[],
        false,
    ).await.map_err(|error| error.to_string())
}
```

Do not enumerate and delete policies/groups individually.

- [ ] **Step 2: Abort detach on purge failure**

For snapshot detach and attach/domain-failure cleanup:

```text
purge success -> detach -> unregister/compact
purge failure -> keep interface attached and quiesced -> status error/degraded
```

Do not log-and-continue. Do not report `detached` or remove the port from committed runtime state when purge fails.

- [ ] **Step 3: Remove obsolete privileged item-delete entrypoints**

After all production callers move to the transactional purge, remove:

```rust
delete_policy_for_neutron_purge
delete_group_for_neutron_purge
```

Keep shared private locked helpers only when still used by public standalone/local operations. Remove tests and checker rules that exist solely to prescribe the obsolete delegation shape.

- [ ] **Step 4: Push GREEN and verify exact-head CI**

```bash
git add agent/src/control_plane.rs agent/src/neutron_api.rs agent/src/tap_registry.rs
git -c user.name=netmouser -c user.email=chenyongming211@gmail.com \
  commit -m "fix: purge managed ACL state before detach atomically"
git push origin codex/review-acl-046-selector-isolation-design
gh run watch --exit-status
```

Expected GitHub result: detach ordering and partial-purge RED tests pass; no dead-code or warning-as-error regression.

---

### Task 4: Remove checker shape coupling and duplicate execution

**Files:**

- Modify: `ci/check_neutron_stage1.py`
- Modify: `ci/check_tc_acl_smoke.py`
- Modify: `ci/check_standalone_tc_acl_smoke.py`
- Modify: `.github/workflows/build.yml`

**Interfaces:**

- Consumes: Rust behavior-test prefixes and real smoke scripts.
- Produces: one lightweight static/wiring phase, one Rust behavior phase, and independently executable field smoke.

- [ ] **Step 1: Delete private Rust shape contracts**

Delete checks and mutants that constrain private helper visibility, exact parameter order/names, tail delegation, local shadowing, or exact internal call spelling. In particular remove the `delete_group -> delete_group_locked` structure contract added by `32bba52`.

- [ ] **Step 2: Delete synthetic green implementations**

Remove embedded full Rust/shell green sources and checker mutation suites that reimplement the production contract. Preserve only:

```text
test discovery
file/entrypoint existence
Python/shell syntax
required CLI modes
structured result/evidence schema
public ABI/map/schema guardrails
```

- [ ] **Step 3: Consolidate smoke parsing**

Prefer direct `bash -n` plus small structured-output validation. If shared parsing is still necessary, keep one small shared helper; do not maintain separate managed and standalone heredoc/function parsers.

- [ ] **Step 4: De-duplicate GitHub Actions**

Run lightweight Stage 1 static checks once. When Rust changes, run Rust behavior tests without rerunning the complete Python/meta checker tree. Keep privileged smoke as a separate evidence-producing job/environment.

- [ ] **Step 5: Commit checker reduction separately**

```bash
git add ci/check_neutron_stage1.py ci/check_tc_acl_smoke.py \
  ci/check_standalone_tc_acl_smoke.py .github/workflows/build.yml
git -c user.name=netmouser -c user.email=chenyongming211@gmail.com \
  commit -m "test: replace ACL source-shape checks with behavior gates"
git push origin codex/review-acl-046-selector-isolation-design
gh run watch --exit-status
```

Acceptance target: remove or consolidate at least the previously identified 8.9k lines of second-order mutation/synthetic scaffolding; do not add replacement checker code of comparable size.

---

### Task 5: Run field evidence and close documentation truthfully

**Files:**

- Modify: `deploy/kolla/smoke/neutron_aria_acl_tc_datapath_smoke.sh` only if the new detach scenario needs wiring
- Modify: `docs/openstack-neutron-aria-details/17-acl-selector-ownership-isolation.md`
- Modify: `docs/openstack-neutron-aria-details/12-review-bug-backlog.md`
- Modify: PR description

**Interfaces:**

- Consumes: exact-head binaries and the transactional purge/flush behavior from Tasks 2 and 3.
- Produces: merge evidence for `REVIEW-ACL-046`, `REVIEW-ACL-064`, `REVIEW-ACL-065`, and `REVIEW-TXN-030`.

- [ ] **Step 1: Extend the managed field scenario**

Prove on real pinned maps:

```text
gate is quiesced before owned policy removal
no packet is accepted through policy-miss during detach preparation
injected purge failure leaves the interface attached/quiesced with complete old owned state
injected strict-flush failure restores old bank and general selectors
successful retry purges, flushes, then detaches
```

- [ ] **Step 2: Re-run standalone compatibility evidence**

Run both supported standalone modes and prove no direct-publication behavior changed.

- [ ] **Step 3: Update design/backlog/PR evidence**

Record exact commit SHA, GitHub Build URL, field environment, commands, timestamps, and artifact/log paths. Mark findings fixed only when both hosted and field evidence are present.

- [ ] **Step 4: Final review gate**

Require:

```text
no P1/P2 correctness finding in the changed transaction paths
no ABI/schema/public API change
no local Cargo evidence substituted for GitHub CI
PR description matches the exact HEAD and commit sequence
Draft converts to Ready only after field evidence is attached
```

---

## Self-Review Result

- Spec coverage: all three confirmed defects, checker coupling, CI duplication, field evidence, and documentation closure have an owning task.
- Scope: no source-port, priority arbitration, standalone direct-publication redesign, general multi-membership, ABI, schema, or public API work is included.
- Transaction consistency: strict flush is inside the same lifecycle/instance lock and has explicit preimage restoration; detach consumes only a completed purge transaction.
- Test independence: Rust behavior tests and real field smoke are the authorities; Python no longer duplicates private implementation semantics.
- Placeholder scan: no implementation step is left as `TBD`/`TODO`.
