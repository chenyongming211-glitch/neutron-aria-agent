# ACL Selector Ownership Isolation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `executing-plans` to implement
> this plan task by task, `test-driven-development` for every behavior change,
> and `verification-before-completion` before claiming a task or the batch done.

**Goal:** Close `REVIEW-ACL-046` by making managed ACL selector publication
rule-derived, making general-group publication conflict-aware, and repairing
explainable legacy map pollution without changing the eBPF ABI or the public
product API.

**Architecture:** Add one pure `aria-core` projection/planner module that turns
`FirewallState` into deterministic ACL and general projections and classifies
captured runtime against committed state. Existing standalone wrappers retain
all-group compatibility. Managed control-plane paths consume the new
projection, track in-memory ownership/health, publish general deltas with full
preimages, and admit only explainable legacy drift for one full-resync repair.

**Tech Stack:** Rust 2021, Aya pinned maps, Tokio control plane, Python static
contract checkers, shell field smokes, GitHub Actions.

## Global Constraints

- The normative design is
  `docs/openstack-neutron-aria-details/17-acl-selector-ownership-isolation.md`.
  Stop before production expansion if implementation requires a new map, map
  layout, `PolicyKey`, `TapConfig`, CT ABI, WAL/state schema field, or public
  northbound/UDS product API. Workspace-internal Rust crate interfaces may be
  added where the projection contract must cross `aria-core`/agent boundaries.
- Do not absorb `REVIEW-ACL-044`, `REVIEW-ACL-057`, `REVIEW-ACL-059`,
  `REVIEW-ACL-056`, or `REVIEW-ACL-058`.
- Do not run `cargo build`, `cargo check`, or `cargo test` locally. Rust/eBPF
  compilation and tests run only in GitHub Actions.
- Every production task begins with a tests-only RED commit. Push it, record
  the expected GitHub Build failure, then add production code in a separate
  GREEN commit.
- Local checks are limited to Python/static/shell syntax checks and
  `git diff --check`. Never weaken warning gates or hide warnings.
- Use the existing branch
  `codex/review-acl-046-selector-isolation-design` and a Draft PR targeting
  `v0.9-neutron-agent`. Keep the PR Draft until all hosted and field gates in
  Task 8 are satisfied.
- After every push, locate the exact-head Build with `gh run list`, inspect it
  with `gh run view`, and use `gh run watch --exit-status` for GREEN commits.

---

## Task 0: Publish the reviewed design baseline and open the Draft PR

**Files:**

- Add: `docs/openstack-neutron-aria-details/17-acl-selector-ownership-isolation.md`
- Add: `docs/superpowers/plans/2026-07-17-acl-selector-ownership-isolation.md`
- Modify: `docs/openstack-neutron-aria-details/12-review-bug-backlog.md`
- Modify: `docs/openstack-neutron-aria-details/README.md`

### Step 1: Verify and commit the docs-only baseline

```bash
python3 ci/check_blocked_terms.py
git diff --check
git add docs/openstack-neutron-aria-details/17-acl-selector-ownership-isolation.md \
  docs/superpowers/plans/2026-07-17-acl-selector-ownership-isolation.md \
  docs/openstack-neutron-aria-details/12-review-bug-backlog.md \
  docs/openstack-neutron-aria-details/README.md
git -c user.name=netmouser -c user.email=chenyongming211@gmail.com \
  commit -m "docs: design ACL selector ownership isolation"
git push -u origin codex/review-acl-046-selector-isolation-design
```

Expected: the branch is published with only the independently reviewed design,
plan, index, and backlog changes.

### Step 2: Open the Draft PR before the first RED push

Create a Draft PR targeting `v0.9-neutron-agent`. Its description must state
that design review is complete, production remains pending, local Cargo is
prohibited, and implementation will follow the recorded tests-only RED then
GREEN sequence.

```bash
gh pr create --draft --base v0.9-neutron-agent \
  --head codex/review-acl-046-selector-isolation-design \
  --title "Fix ACL selector ownership isolation"
```

Expected: the `pull_request` workflow produces a Build for the docs-only head.
Record its URL and require it to pass before Task 1 so every later RED/GREEN
push has an exact-head PR Build.

---

## Task 1: Freeze the pure projection and drift-planner contract

**Files:**

- Create: `core/tests/acl_projection_contract.rs`
- Create: `core/src/ebpf_ops/projection.rs`
- Modify: `core/src/ebpf_ops.rs`
- Modify: `core/src/ebpf_ops/network.rs`
- Modify: `ci/check_neutron_stage1.py`

### Step 1: Add the RED integration contract

Create integration tests importing the projection contract re-exported by
`aria_core::ebpf_ops` and cover the design's complete pure matrix:

- direction-specific ACL references and group `0` omission;
- missing/duplicate group IDs and invalid CIDRs;
- IPv4/IPv6 host-bit canonicalization;
- same-group nesting versus cross-ID exact/nested rejection;
- exact, ACL-more-specific, and general-more-specific precedence;
- non-conflicting ACL-only observability;
- QoS/Mirror dual-use classification;
- deterministic highest-ID exact compatibility winner and insertion-order
  independence;
- `Clean`, `RepairRequired`, and `Fatal` drift relative to committed state;
- repair-to-proposed planning when the first full snapshot also changes ACL.

Name tests with the `acl_projection_` prefix. Add
`cargo +stable test --locked -p aria-core acl_projection_` to the hosted Rust
command inventory in `ci/check_neutron_stage1.py`.

### Step 2: Commit and prove RED in GitHub Actions

```bash
git add core/tests/acl_projection_contract.rs ci/check_neutron_stage1.py
git -c user.name=netmouser -c user.email=chenyongming211@gmail.com \
  commit -m "test: define ACL selector projection contract"
git push origin codex/review-acl-046-selector-isolation-design
```

Expected hosted failure: unresolved projection imports from
`aria_core::ebpf_ops` (or the equivalent missing public contract), with all
pre-existing Python/static gates still green.

### Step 3: Implement the pure GREEN module

In `core/src/ebpf_ops/projection.rs`, add public internal-domain types
equivalent to:

```rust
pub enum ProjectionDirection { Src, Dst }
pub enum ProjectionFamily { V4, V6 }
pub struct ProjectionEntry { /* canonical network, prefix, group identity */ }
pub struct ManagedGroupProjection { pub acl_src: Vec<ProjectionEntry>, /* ... */ }
pub enum ProjectionDrift { Clean, RepairRequired(ProjectionRepairPlan), Fatal(String) }

pub fn compile_managed_group_projection(
    state: &FirewallState,
) -> Result<ManagedGroupProjection, String>;

pub fn plan_projection_drift(
    captured: &CapturedProjection,
    committed: &ManagedGroupProjection,
    proposed: &ManagedGroupProjection,
) -> ProjectionDrift;
```

The exact Rust names may differ, but callers must receive sorted canonical
entries, complete legacy candidates/exclusion reasons, and a runtime-to-
proposed general mutation plan. Add structured canonical-network helpers in
`core/src/ebpf_ops/network.rs`; projection paths must mask host bits before
comparison or insertion, while old standalone string APIs remain compatible.
Keep parsing and overlap logic pure; do not open maps in the projection module.
Re-export the contract from `core/src/ebpf_ops.rs`.

### Step 4: Push GREEN and require the exact-head Build

```bash
git add core/src/ebpf_ops/projection.rs core/src/ebpf_ops.rs \
  core/src/ebpf_ops/network.rs
git -c user.name=netmouser -c user.email=chenyongming211@gmail.com \
  commit -m "feat: compile managed ACL group projections"
git push origin codex/review-acl-046-selector-isolation-design
```

Expected hosted result: every `acl_projection_` test passes under
`RUSTFLAGS=-D warnings`; userspace, agent, and eBPF builds remain green.

---

## Task 2: Make replay and inventory projection-aware without changing standalone

**Files:**

- Modify: `core/tests/acl_projection_contract.rs`
- Modify: `core/src/ebpf_ops/replay.rs`
- Modify: `core/src/ebpf_ops/inventory.rs`
- Modify: `core/src/ebpf_ops.rs`
- Modify: `agent/src/system_manager.rs`
- Modify: `agent/src/control_plane.rs`
- Modify: `ci/check_neutron_stage1.py`

### Step 1: Add RED mode-parity tests

Add tests proving:

- standalone fresh and pinned replay still expect all groups in both general
  and ACL directions;
- managed replay expects conflict-aware general entries and direction-specific
  ACL entries;
- managed inventory compares those sets separately;
- a known legacy exact/more-specific/missing candidate produces repair-required
  inventory, while unknown key/value and unrelated policy/link/config drift are
  fatal;
- a second inventory pass over the repaired projection is clean.

The tests should exercise pure expected-entry builders, not require bpffs.
Use the prefixes `managed_projection_replay_` and
`managed_projection_inventory_` and add both to the hosted command inventory.

### Step 2: Push and record RED

Commit only tests/checker changes as
`test: define managed projection replay and inventory` and push. Expected
failure: missing mode-aware replay/inventory helpers; pre-existing standalone
tests remain green.

### Step 3: Implement mode-aware wrappers

Add an internal mode such as:

```rust
pub enum GroupProjectionMode {
    StandaloneCompatibility,
    Managed,
}
```

Keep existing public functions as standalone-compatible wrappers. Add managed
entry points used only by `ControlPlane::prepare_managed_registration` and
`ControlPlane::validate_preexisting_live_runtime`. Both fresh-object replay and
pinned replay must use the same projection builders as inventory. Do not change
`agent/src/system_manager.rs` standalone behavior.

Inventory must return structured clean/repair-required/fatal information to the
control plane instead of encoding repairable drift as an ordinary fatal string.
Policy, port bitmap, QoS, Mirror, link, iface, and tap-config validation stays
fail-closed.

### Step 4: Push GREEN and require hosted verification

Commit as `feat: make managed replay inventory projection aware`. Expected
hosted result: both new test prefixes and all `standalone_review_` tests pass;
no warning or eBPF build regressions.

---

## Task 3: Add managed ownership and projection-health lifecycle

**Files:**

- Modify: `agent/src/control_plane.rs`
- Modify: `agent/src/tap_registry.rs`
- Modify: `agent/src/neutron_api.rs`
- Modify: `ci/check_neutron_stage1.py`

### Step 1: Add RED lifecycle tests

Add private-module tests with these prefixes:

- `managed_projection_health_`: fresh replay and promotion start unverified;
  preexisting-live exact inventory may initialize verified; repairable
  inventory initializes repair-required;
- `managed_acl_ownership_`: idempotent attach cannot swallow standalone-to-
  managed promotion; detach clears both attach and ACL ownership;

Also extend `can_skip_neutron_domain_reconcile` tests so managed ACL skip
requires verified projection health. Full resync remains non-skippable.

### Step 2: Push and record RED

Commit tests/checker inventory as
`test: define managed ACL ownership lifecycle`. Expected failure: missing
ownership/health types and unchanged idempotent attach behavior.

### Step 3: Implement the lifecycle

Add internal in-memory enums equivalent to:

```rust
enum ManagedAclPublicationMode {
    StandaloneCompatibility,
    NeutronAttachOwnedStandaloneAcl,
    ManagedAcl,
}
enum ManagedProjectionHealth { Unverified, RepairRequired, Verified }
```

Store them in `InstanceState`, separate from `RuntimeHealthState` and
`NeutronPortAuthority`, under the same runtime-lifecycle/iface serialization;
do not persist them. Fresh replay and promotion begin unverified; an exact
preexisting-live inventory match may initialize verified, while explainable
legacy drift initializes repair-required. Promotion must quiesce ACL/CT before
reconcile and before skip evaluation.

Freeze the lock order as follows:

- registry transitions: iface lock, then runtime-lifecycle lock, then
  `InstanceState` lock;
- direct control-plane writers: runtime-lifecycle lock, then `InstanceState`
  lock;
- the first idempotent registry check may only decide to fall through into the
  locked transition path; it must not mutate ownership outside the locks;
- any helper called with lifecycle already held must be a private
  `_serialized`/locked helper and must not reacquire that lock.

Update `TapRegistry::attach_with_mode` so the first fast idempotent check only
detects an existing instance and falls through into locking. After acquiring
the iface and lifecycle locks, the second existing-instance branch calls the
`_serialized` managed promotion instead of returning early. Define the
attach-owned standalone-compatible mode now, but defer its demotion transaction
until the shared publication helper exists in Tasks 4-6.

Thread projection health into `can_skip_neutron_domain_reconcile` and every
call site. Expose only internal snapshots needed by tests/status planning; do
not add UDS fields. Task 3 establishes state, initialization, promotion, and
skip consumption only; Task 4 supplies the transaction engine, Task 5 adds
writer invalidation/gates, and Task 6 wires demotion and post-flush
verification.

### Step 4: Push GREEN and require hosted verification

Commit as `feat: track managed ACL projection health`. Expected hosted result:
all lifecycle/skip tests pass and existing attach authority/status-contract
tests remain green.

---

## Task 4: Publish owned ACL and general deltas transactionally

**Files:**

- Modify: `agent/src/control_plane.rs`
- Modify: `agent/src/neutron_api.rs`
- Modify: `core/src/ebpf_ops/network.rs`
- Modify: `core/src/ebpf_ops/inventory.rs`
- Modify: `ci/check_neutron_stage1.py`

### Step 1: Add RED transaction and no-op repair tests

Add tests covering:

- `stage_acl_shadow_bank` consumes only `acl_src`/`acl_dst` projection entries;
- exact and more-specific local groups never enter the staged ACL bank;
- `SharedNetworkMutation::Replaced` restores the old value after source-only,
  destination, shadow, persistence, and compensation failures;
- `rollback_group_deletes` in managed mode restores general entries only;
- verified health becomes unverified before the first map mutation;
- clean equal reconcile no-ops, repairable equal reconcile switches exactly
  once, and repair plus a real proposed ACL change completes in one transaction;
- unknown captured drift fails before publication and leaves the gate quiesced.

Use prefixes `managed_acl_shadow_`, `managed_general_delta_`, and
`managed_projection_repair_`; register them in the hosted checker.

### Step 2: Push and record RED

Commit as `test: define managed selector publication transaction`. Expected
failure: all-group shadow iteration and missing replacement preimage/repair
planner integration.

### Step 3: Implement transactional publication

Refactor `ControlPlane::replace_owned_acl` in this order:

1. Build committed and proposed projections before any mutation.
2. Capture current ACL/general network entries and run the committed-state
   drift planner before the semantic no-op.
3. Reject fatal drift; mark repair-required/unverified before mutation.
4. Generate general runtime-to-proposed mutations with full preimages.
5. Apply general upserts/deletes without an exact-key empty window.
6. Scrub/stage the inactive ACL bank from direction-specific ACL entries.
7. Verify/switch/persist/strictly compensate using existing bank rollback plus the
   complete general preimage.

Put those steps in one private locked publication helper so owned replace and
Task 6 demotion share failure ordering without lifecycle-lock reentry.

Add `SharedNetworkMutation::Replaced { direction, cidr, old_group_id,
new_group_id }` (or an equivalent full preimage). Do not use `Added`/delete
compensation for replacements.

`replace_owned_acl` may report `selector_repair_performed` internally. Strict
CT flush remains in `agent/src/neutron_api.rs`; projection health becomes
verified only through the successful post-flush runtime-gate publication.

### Step 4: Push GREEN and require hosted verification

Commit as `fix: isolate managed ACL selector publication`. Expected hosted
result: new transaction/repair tests, existing bitmap quarantine tests, all
Neutron ACL tests, static builds, eBPF build, and warning gates pass.

---

## Task 5: Make local group and QoS/Mirror mutations projection-safe

**Files:**

- Modify: `agent/src/control_plane.rs`
- Modify: `agent/src/api_handlers/groups.rs`
- Modify: `agent/src/api_handlers/qos.rs`
- Modify: `agent/src/api_handlers/mirror.rs`
- Modify: `ci/check_neutron_stage1.py`

### Step 1: Add RED mutation tests

Add tests proving:

- an ACL-referenced group ID cannot be locally mutated regardless of name;
- an allowed ACL-unreferenced group add/delete changes only persisted/general
  projection and never calls an ACL network writer;
- exact local winner add/delete uses `Replaced` preimages and restores retained
  non-conflicting ACL-selector observability after cleanup;
- QoS/Mirror `0→1→2→1→0` reference transitions change general-domain
  classification only on the first/last reference;
- removing an owned ACL selector retains its last committed group/CIDRs while
  QoS/Mirror still references it, and final reference removal garbage-collects
  it;
- ACL CIDR update while dual-used updates the shared general identity;
- unverified/repair-required mutation attempts are rejected before kernel,
  state, or WAL writes.
- every mutation/failure invalidates verified health before the first kernel
  write and cannot restore it after mutation, compensation, persistence, or
  compensation-rollback failure.

Use prefixes `managed_local_group_projection_` and
`managed_dual_use_group_`.

### Step 2: Push and record RED

Commit as `test: define managed cross-domain group mutations`. Expected
failure: current group add/delete writes the active ACL bank and current owned
replace drops all removed owned groups.

### Step 3: Implement projection-safe mutations

Route managed group and QoS/Mirror first/last-reference changes through the
same before/after general projection delta used by owned replace. Keep
standalone add/delete behavior unchanged for `REVIEW-ACL-057`.

Make every managed rollback ownership-aware. Preserve last committed
retained-owned group data only while an explicit QoS/Mirror reference exists;
garbage-collect it after the final reference disappears. Handler error mapping
may reuse existing not-ready/local-write-blocked responses; do not add a public
status vocabulary.

### Step 4: Push GREEN and require hosted verification

Commit as `fix: isolate managed cross-domain group writes`. Expected hosted
result: the new group/dual-use tests pass with existing QoS, Mirror, group,
WAL, and standalone tests unchanged.

---

## Task 6: Close restart, attach migration, demotion, and outer-skip repair

**Files:**

- Modify: `agent/src/control_plane.rs`
- Modify: `agent/src/tap_registry.rs`
- Modify: `agent/src/neutron_api.rs`
- Modify: `ci/check_neutron_stage1.py`

### Step 1: Add RED end-to-end state-machine tests

Add non-privileged fault-injection tests proving:

- explainable ACL alias, missing selector, exact general alias, and general-only
  `local=/24 + ACL-only=/32` drift are admitted quiesced as
  `AwaitNeutronResync`/repair-required;
- Neutron attach authority survives successful managed-to-standalone-compatible
  ACL demotion, while pre/post-switch failure keeps the prior logical mode
  quiesced and restores bank/general preimages as applicable;
- unknown key/value, unrelated general/policy drift, unreadable maps, and
  link/config mismatch abort attach;
- an outer scoped equal update cannot skip while unverified or
  repair-required;
- full resync repairs, strict flush verifies, the next equal update no-ops,
  and a second restart validates clean inventory, initializes verified, and
  requires neither repair nor another full resync;
- strict-flush or gate-publication failure never leaves verified health.

Use prefixes `managed_projection_attach_repair_` and
`managed_projection_outer_skip_`.

### Step 2: Push and record RED

Commit as `test: define managed selector restart repair`. Expected failure:
current preexisting inventory treats explainable projection drift as fatal and
outer scoped skip has no health input.

### Step 3: Implement one classifier and one repair path

Make attach reuse `plan_projection_drift` with the complete committed-state
legacy candidate set. Do not create a second, narrower drift classifier.
Repairable attach always quiesces and completes registration awaiting full
Neutron resync. Fatal remains fail-closed.

Implement demotion by reusing the locked projection-publication transaction:
quiesce, purge owned ACL state in the proposed snapshot, apply the recorded
general delta, stage and verify the all-group standalone-compatible ACL shadow,
switch, persist, and strictly flush CT before changing logical mode. Do not call
the item-at-a-time `purge_neutron_acl`, do not detach, and do not clear Neutron
attach/WAL authority.

Ensure the existing-port update path synchronizes desired ownership/health
before `can_skip_neutron_domain_reconcile`. After successful replace, strict CT
flush, and gate publication, set verified; any later in-process mutation
invalidates it before touching maps.

### Step 4: Push GREEN and require hosted verification

Commit as `fix: repair managed selector drift on restart`. Expected hosted
result: both restart/skip prefixes and all existing snapshot, WAL recovery,
attach, and status-contract tests pass.

---

## Task 7: Add static and privileged-smoke contract gates

**Files:**

- Modify: `ci/check_neutron_stage1.py`
- Modify: `ci/check_tc_acl_smoke.py`
- Modify: `ci/check_standalone_tc_acl_smoke.py`
- Modify: `deploy/kolla/smoke/neutron_aria_acl_tc_datapath_smoke.sh`
- Modify: `deploy/smoke/aria_standalone_acl_tc_datapath_smoke.sh`

### Step 1: Add RED checker mutation tests first

Extend checker self-tests so they fail if any managed path regresses to raw
`state.groups` iteration or omits:

- shadow stage, fresh replay, pinned replay, inventory;
- managed group add/delete and QoS/Mirror reference transition;
- projection-health invalidation/verification;
- `Replaced` compensation;
- three independent exact, more-specific, and legacy-repair field fixtures.

Extend `check_standalone_tc_acl_smoke.py --self-test` in the same tests-only RED
commit. Its mutation matrix must fail when it removes the referenced group, the
unreferenced group, restart/replay verification, or either `MODE=system` /
`MODE=tap` branch. Only after that RED is recorded may the standalone shell be
changed.

The checker tests must mutate both direct calls and aliased wrapper calls.
Commit as `test: define ACL selector isolation smoke gates`, push, and record
the expected static failure before altering smoke production code.

### Step 2: Implement the field fixtures

Add three isolated fixtures exactly as specified by the normative design:

1. Exact local API mutation leaves the active ACL selector ID/deny intact,
   changes general state, keeps controlled-flow CT empty, and restores general
   observability on cleanup.
2. More-specific local `/32` plus a real owned ACL semantic delta proves the
   new shadow bank excludes `/32` while deny still works.
3. Legacy active-bank pollution is followed by fixed-binary restart/re-attach,
   equal full resync, exactly one repair switch and strict CT cleanup; the next
   equal snapshot and another restart are clean/no-repair.

Capture return codes, map dumps, bank, counters, CT, and cleanup evidence before
asserting. Keep damaged fixtures isolated. Extend standalone smoke in both
system and tap modes for referenced and unreferenced groups without changing
its all-group compatibility expectation.

### Step 3: Run permitted local static checks

```bash
python3 ci/check_tc_acl_smoke.py --self-test
python3 ci/check_standalone_tc_acl_smoke.py --self-test
python3 -m py_compile ci/check_neutron_stage1.py ci/check_tc_acl_smoke.py \
  ci/check_standalone_tc_acl_smoke.py
bash -n deploy/kolla/smoke/neutron_aria_acl_tc_datapath_smoke.sh
bash -n deploy/smoke/aria_standalone_acl_tc_datapath_smoke.sh
git diff --check
```

Expected: all commands exit 0. Do not run the Rust stages locally.

### Step 4: Push GREEN and require hosted verification

Commit as `test: gate managed ACL selector isolation`. Expected hosted result:
all Python/static self-tests and the full Rust/eBPF/static-binary Build pass.

---

## Task 8: Closure evidence, review, and merge readiness

**Files:**

- Modify: `docs/openstack-neutron-aria-details/17-acl-selector-ownership-isolation.md`
- Modify: `docs/openstack-neutron-aria-details/12-review-bug-backlog.md`
- Modify: Draft PR description

### Step 1: Run final local non-Cargo verification

```bash
python3 ci/check_tc_acl_smoke.py --self-test
python3 ci/check_standalone_tc_acl_smoke.py --self-test
python3 -m unittest ci.test_rust_build_required ci.test_rust_warning_hygiene
git diff --check
git status --short
```

Expected: zero failures and only intended files before the closure commit.

### Step 2: Require exact-head hosted evidence

The exact implementation head must pass the Build job, including:

- Stage 1 and Stage 2 checkers;
- every target Rust test prefix added above;
- `RUSTFLAGS=-D warnings`;
- nightly eBPF build;
- static userspace and agent builds;
- static binary verification.

Record the run URL and exact SHA in both design/backlog closure entries.

### Step 3: Obtain independent code and scope review

Run two read-only reviews against base `v0.9-neutron-agent`:

- correctness/failure-order review of projection, publication, repair, and CT
  verification;
- scope review proving no ABI/schema/API expansion and no absorption of the
  excluded review IDs.

Resolve every real P0/P1/P2 within this design. If a fix needs a guardrail
boundary change, stop and ask the user before editing production code.

### Step 4: Record field evidence and close the backlog item

Run the privileged OpenStack exact, more-specific, and legacy-repair fixtures.
Store or link evidence using the repository's existing evidence convention.
Also run and retain privileged standalone restart/replay evidence for both
modes; each must prove referenced enforcement and unreferenced all-group
representation survive replay:

```bash
sudo env MODE=system ARIA_AGENT_BIN=<aria-agent> \
  EBPF_OBJECT=<libebpf_firewall.so> \
  bash deploy/smoke/aria_standalone_acl_tc_datapath_smoke.sh
sudo env MODE=tap ARIA_AGENT_BIN=<aria-agent> \
  EBPF_OBJECT=<libebpf_firewall.so> \
  bash deploy/smoke/aria_standalone_acl_tc_datapath_smoke.sh
```

Only after all three managed fixtures and both standalone modes pass:

- change the design status to implemented/verified;
- mark `REVIEW-ACL-046` fixed with commit SHA and Build/evidence links;
- update the remaining order so `REVIEW-ACL-057` is next;
- update the PR description with RED/GREEN history and exact verification.

Commit as `docs: close ACL selector ownership isolation`, push, require one
final exact-head Build, then convert the Draft PR to Ready. Merge only after
required review/checks pass.
