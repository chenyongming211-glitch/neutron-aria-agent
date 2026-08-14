# REVIEW-ACL-079/080 Generation And Same-Generation Retry Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use
> superpowers:executing-plans to implement this plan task-by-task. Steps use
> checkbox (`- [ ]`) syntax for tracking. Execute inline on the sole
> `v0.9-neutron-agent` branch; do not create a branch, worktree, PR, or
> subagent task.

**Goal:** reject submitted generation zero before side effects and let the
official Python/Rust pair safely converge a fresh-WAL-verified durable partial
snapshot through an exact same-generation retry.

**Architecture:** ship the reader first. Python accepts immutable Status V1
and new Status V2, durably retains the bounded pending request, and follows the
typed `retry_snapshot` action only when fresh Neutron desired state still
matches. Rust then emits V2, binds pending identity to generation plus hash,
and re-enters only an ordinary durable partial commit after fresh WAL/live
identity validation under the existing host apply lock.

**Tech Stack:** Rust 2021, Axum/Tokio, Serde JSON-lines Neutron WAL, Python
2.7/3 compatible Neutron agent, unittest, GitHub Actions warning-denied Rust
and eBPF builds.

## Global Constraints

- Follow the approved
  [design](../specs/2026-08-14-review-acl-079-080-generation-retry-contract-design.md).
- Work directly on `v0.9-neutron-agent`; do not create another branch,
  worktree, PR, or subagent task.
- Do not run local Cargo build, check, test, clippy, or rustfmt commands.
- Push each RED and GREEN boundary separately; hosted CI is the Rust compiler
  and behavior authority.
- Keep Status V1 hash, fixture and behavior immutable.
- Deploy compatibility in source order: dual V1/V2 Python consumer first,
  Status V2 Rust producer second.
- Do not add a generic transaction framework, unbounded retry worker, private
  Rust source parser, or duplicate Python test lane.
- Do not change ACL policy, CT, TC/eBPF, map ABI or packet behavior.
- Do not mark either finding fixed before exact-head GREEN evidence exists.

---

### Task 1: RED Dual-Contract Python Consumer And Durable Request

**Files:**

- Create: `docs/neutron-status-contract-v2-scenarios.json`
- Modify: `openstack/neutron_aria/neutron_aria/tests/unit/test_uds_client.py`
- Modify: `openstack/neutron_aria/neutron_aria/tests/unit/test_state.py`
- Modify: `openstack/neutron_aria/neutron_aria/tests/unit/test_event_loop.py`
- Modify: this plan

**Interfaces:**

- V1 remains the exact pair `1/1/v0.9-neutron-status-1`.
- V2 is the exact pair `2/2/v0.9-neutron-status-2`.
- V2 adds only the public action token `retry_snapshot`; public port rows retain
  `generation <= applied_generation` and never grant pending-generation
  readiness.
- Pending request evidence contains body, route scope, optional scoped port ID,
  retry count and retry timestamp.

- [x] **Step 1: Add a minimal V2 behavior fixture**

Create a separate fixture rather than editing the immutable V1 file. Include
at least:

1. first generation durable partial:
   `blocked/blocked/retry_snapshot`, accepted/pending 1, applied 0, exact hash,
   empty applied-baseline status rows;
2. positive-baseline durable partial with applied rows only;
3. applying state remains `pending/unknown/poll`;
4. unsafe blocked state remains `blocked/blocked/recover_pending` or operator;
5. retry success becomes `classified/ready/none` at the same generation.

Fixture expectations must say that retry does not classify or mark ready until
pending clears.

- [x] **Step 2: Add strict V1/V2 negotiation RED tests**

Using public capability/status dictionaries, prove:

- new Python accepts exact V1 and exact V2 pairs;
- V2 accepts `retry_snapshot` only in the new blocked triple;
- V1 rejects the new token and remains unchanged;
- crossed schema/hash pairs, unknown actions and partial declarations latch
  writes closed;
- old V1 fixture decoding still produces the same normalized object.

Tests must call public `LocalClient.capabilities()` and `status()` or the public
decoder boundary. They must not inspect constant source text.

- [x] **Step 3: Add durable pending-request RED tests**

Exercise `SnapshotStateStore` through its public prepare/load/commit methods:

- full-host body is stored with assigned generation/hash;
- scoped body retains `scope.type=port` and the path port ID;
- reopening the state store returns the exact request;
- recomputed desired hash must equal durable pending hash;
- request JSON over the existing body limit is rejected before replacing a
  valid pending record;
- commit/clear deletes request and retry metadata atomically;
- legacy state without request fields remains readable but cannot authorize a
  retry.

- [x] **Step 4: Add Python V2 retry orchestration RED tests**

Use fake public clients/status payloads to prove:

- first-generation partial replays exact G/H through full-host PUT and reaches
  ready without allocating G+1;
- scoped partial reuses the scoped route and exact body;
- process restart reloads the request before retry;
- current Neutron desired hash mismatch performs no stale PUT;
- a mismatch with positive applied baseline uses exact recover-pending before
  a newer full resync;
- a mismatch without a baseline retains pending and reports operator-required;
- repeated partial performs one retry in the current convergence attempt and
  retains pending for scheduler backoff;
- V1 recovery behavior is unchanged.

- [x] **Step 5: Run focused Python RED locally**

Run only non-Rust commands:

```bash
python3 -m unittest \
  openstack.neutron_aria.neutron_aria.tests.unit.test_uds_client \
  openstack.neutron_aria.neutron_aria.tests.unit.test_state \
  openstack.neutron_aria.neutron_aria.tests.unit.test_event_loop
git diff --check
```

Record the exact failing assertions. The expected failures are unsupported V2,
missing durable request evidence and absent retry orchestration—not import or
fixture syntax errors.

RED evidence on 2026-08-14 (with
`PYTHONPATH=openstack/neutron_aria`): 228 tests ran; the 12 intended failures
were unsupported V2 profile hashes/decoding, absent pending request and retry
metadata, oversize validation occurring after pending conflict, and the event
loop treating `retry_snapshot` as blocked. There were no fixture syntax or
module import failures after using the repository package path.

- [x] **Step 6: Commit and push Python RED**

```bash
git add docs/neutron-status-contract-v2-scenarios.json \
  openstack/neutron_aria/neutron_aria/tests/unit/test_uds_client.py \
  openstack/neutron_aria/neutron_aria/tests/unit/test_state.py \
  openstack/neutron_aria/neutron_aria/tests/unit/test_event_loop.py \
  docs/superpowers/plans/2026-08-14-review-acl-079-080-generation-retry-contract.md \
  docs/superpowers/specs/2026-08-14-review-acl-079-080-generation-retry-contract-design.md
git commit -m "test: expose snapshot retry contract gaps"
git push origin v0.9-neutron-agent
```

Hosted `fast-contracts` must fail on the intended Python behaviors. Do not add
Rust RED until this failure is captured.

Hosted RED: commit `93f77ac`, Build `31777521743`, job `fast-contracts`
`94695986527`. The job ran 614 tests and failed only on the 12 intended new
V2/request/retry behaviors; Rust jobs were skipped behind this RED boundary.

---

### Task 2: GREEN Python-First V1/V2 Consumer

**Files:**

- Modify: `openstack/neutron_aria/neutron_aria/agent/uds_client.py`
- Modify: `openstack/neutron_aria/neutron_aria/agent/state.py`
- Modify: `openstack/neutron_aria/neutron_aria/agent/event_loop.py`
- Modify: `docs/neutron-status-contract-v2-scenarios.json`
- Modify: relevant Python tests from Task 1

**Interfaces:**

Introduce exact supported contract tuples rather than replacing one global
string with loose ranges:

```python
STATUS_CONTRACT_V1 = "v1"
STATUS_CONTRACT_V2 = "v2"

_STATUS_CONTRACTS = {
    (1, 1, "v0.9-neutron-status-1"): STATUS_CONTRACT_V1,
    (2, 2, "v0.9-neutron-status-2"): STATUS_CONTRACT_V2,
}
```

Capability and error hashes must be accepted only in matching known contract
profiles, not as independent mix-and-match sets.

- [x] **Step 1: Implement strict dual negotiation and V2 decoding**

- Preserve the V1 decoder and closed triples unchanged.
- Add the V2 blocked/retry triple and exact hash/profile.
- Reuse V1 managed/applied-row structural validation; do not accept future
  pending-generation rows as readiness evidence.
- Return the negotiated mode so event-loop logic never infers V2 from an
  `authority_state` string.
- Reject crossed profile fields and latch the write gate exactly as today.

- [x] **Step 2: Persist bounded pending request evidence**

- Store a deep-copied request after assigning its generation and desired hash.
- Normalize scope to full host or exact scoped path ID.
- Enforce the existing request-body byte limit before state replacement.
- Validate request generation/hash/scope during load and before exposure.
- Add retry count/timestamp methods without adding a retry thread.
- Clear all request/retry fields only with the matching pending commit/clear.
- Preserve Python 2.7 compatible JSON and atomic fsync/replace behavior.

- [x] **Step 3: Implement typed bounded retry orchestration**

- Teach `_remote_pending_action` to return `retry_snapshot` only from decoded
  V2 control.
- Rebuild fresh authoritative desired state and compare its hash to pending H.
- If equal, replay the stored full/scoped request at exact G/H once.
- Read status after the replay and use existing finalization only after pending
  clears with exact classified identity.
- If different, never replay the stale body. Recover a positive baseline or
  retain operator-required state at generation zero as specified.
- Reuse existing scheduler/backoff; no immediate retry loop.

- [x] **Step 4: Run focused and broad Python GREEN locally**

Run:

```bash
python3 -m unittest \
  openstack.neutron_aria.neutron_aria.tests.unit.test_uds_client \
  openstack.neutron_aria.neutron_aria.tests.unit.test_state \
  openstack.neutron_aria.neutron_aria.tests.unit.test_event_loop
python3 ci/check_neutron_stage1.py
git diff --check
```

Do not run Cargo locally.

- [ ] **Step 5: Commit, push and require Python-first GREEN**

```bash
git add openstack/neutron_aria/neutron_aria/agent/uds_client.py \
  openstack/neutron_aria/neutron_aria/agent/state.py \
  openstack/neutron_aria/neutron_aria/agent/event_loop.py \
  docs/neutron-status-contract-v2-scenarios.json \
  openstack/neutron_aria/neutron_aria/tests/unit/test_uds_client.py \
  openstack/neutron_aria/neutron_aria/tests/unit/test_state.py \
  openstack/neutron_aria/neutron_aria/tests/unit/test_event_loop.py \
  docs/superpowers/plans/2026-08-14-review-acl-079-080-generation-retry-contract.md
git commit -m "feat: accept versioned snapshot retries"
git push origin v0.9-neutron-agent
```

Require exact-head `fast-contracts` and clean-install success while Rust still
emits V1. This is the rollout compatibility barrier before producer changes.

---

### Task 3: RED Rust Generation And Retry Behaviors

**Files:**

- Modify: `api/src/lib.rs` test module
- Modify: `agent/src/neutron_api.rs` test module
- Modify: `ci/check_neutron_stage1.py`
- Modify: this plan

**Interfaces:**

- Add Rust tests with the shared prefix `snapshot_generation_retry_`.
- Tests use public serialized capabilities/status values and existing snapshot
  admission/apply functions. They must not require future private helper names.
- Add one hosted Cargo filter:

```python
["test", "--locked", "-p", "aria-agent", "snapshot_generation_retry_"],
```

- [ ] **Step 1: Add generation-zero preflight RED tests**

Prove full-host and scoped routes return HTTP 400
`INVALID_SNAPSHOT_GENERATION`. Snapshot the runtime and WAL path before the
call and assert they remain unchanged/absent. Use an inventory hook or test
state that would fail if admission reaches OVS discovery; do not infer this
only from source ordering.

- [ ] **Step 2: Add exact pending-identity RED tests**

- pending 110/hash-X plus request 111/hash-X must return 409;
- pending 110/hash-X plus request 110/hash-Y must return 409;
- applying 110/hash-X plus exact request remains one deduplicated pending
  response and prepares no task;
- conflict responses preserve runtime/WAL identity and report actual pending
  generation.

Replace the current test that positively expects cross-generation hash-only
deduplication.

- [ ] **Step 3: Add durable-partial barrier RED tests**

Construct a valid partial commit through the ordinary WAL APIs, publish the
matching runtime and resubmit exact G/H. Assert one prepared apply retains the
apply lock. Add negative cases for:

- unresolved WAL intent;
- replay failures;
- WAL/live generation/hash/ports/status mismatch;
- non-partial blocked authority.

Every negative case returns `snapshot_retry_not_safe`, appends no intent and
changes no runtime.

- [ ] **Step 4: Add same-generation convergence RED tests**

Use an existing deterministic registry/control-plane failure boundary or one
narrow one-shot fault point to prove:

- generation 1 first attempt commits partial;
- the exact retry begins from that partial state;
- already successful ownership is not duplicated;
- the failed operation succeeds after the fault clears;
- the final commit is ready at generation 1 with pending cleared;
- a repeated failure remains partial at generation 1.

Do not add a broad mock transaction framework.

- [ ] **Step 5: Add Status V2 producer RED tests**

Serialize public capabilities and status responses and assert:

- schema min/max 2, status-2, errors-3 and capabilities-4;
- durable ordinary partial projects `blocked/blocked/retry_snapshot`;
- active, recoverable unsafe, inventory and operator cases preserve their
  existing decisions;
- public port rows remain applied-baseline-only;
- generation 1 partial with applied 0 is retryable, not operator.

- [ ] **Step 6: Run non-Cargo RED checks**

Run:

```bash
python3 -m py_compile ci/check_neutron_stage1.py
python3 -m unittest ci.test_ci001_trusted_gates ci.test_rust_warning_hygiene
git diff --check
```

Do not run Cargo locally.

- [ ] **Step 7: Commit and push Rust RED**

```bash
git add api/src/lib.rs agent/src/neutron_api.rs ci/check_neutron_stage1.py \
  docs/superpowers/plans/2026-08-14-review-acl-079-080-generation-retry-contract.md
git commit -m "test: expose generation retry drift"
git push origin v0.9-neutron-agent
```

Require hosted `rust-behavior` to compile the tests and fail on the intended
old generation/retry/status behavior. Stop superseded unrelated jobs after the
precise RED is recorded.

---

### Task 4: GREEN Rust Status V2 And Durable Partial Retry

**Files:**

- Modify: `api/src/lib.rs`
- Modify: `agent/src/neutron_api.rs`
- Modify: `agent/src/neutron_wal.rs` only if a narrow identity helper is needed
- Modify: `ci/check_neutron_stage1.py`
- Modify: Rust tests from Task 3

- [ ] **Step 1: Version the public producer contract**

- Set Status schema min/max/current to 2 and status hash to status-2.
- Add `RetrySnapshot` to `NeutronStatusRequiredAction`.
- Set errors-3 and capabilities-4.
- Keep request schema version 1 and V1 fixture/constants unchanged in docs and
  Python compatibility code.

- [ ] **Step 2: Reject generation zero in shared preflight**

Make shared validation run before restore readiness and any admission side
effect in the exact order schema -> positive generation -> scope. Return the
stable 400 error without touching WAL, inventory, runtime or datapath.

- [ ] **Step 3: Replace hash-only pending admission with a typed decision**

Represent at least:

```text
no pending
deduplicated active exact identity
retryable durable partial exact identity
pending identity conflict
unsafe pending retry
```

Compare generation before hash. Active exact identity returns current pending
generation in the response. Different generation/hash returns
`snapshot_apply_in_progress`. Unsafe exact identity returns
`snapshot_retry_not_safe`.

- [ ] **Step 4: Revalidate durable partial under the apply lock**

Freshly replay WAL and require zero failures, no pending intent and exact
committed/live equality after normalizing only `status_hash`. Compare the full
generation/hash/authority/ports/status/recovery identity. Recheck after OVS
discovery through the existing admission identity loop. Any drift fails before
a retry intent append.

- [ ] **Step 5: Reuse the concrete apply transaction for exact G/H**

Let the eligible partial continue through existing planning, intent fsync,
runtime apply and commit publication with the same generation. Preserve
idempotent desired-state behavior and existing compensation. Add structured
retry disposition/result fields to existing logs without logging request
bodies or adding a metric family.

- [ ] **Step 6: Emit the V2 retry action without widening row authority**

Project `RetrySnapshot` only for complete ordinary partial identity with no
known WAL replay failure. Keep pending-generation internal error rows out of
public applied rows. Preserve all current inventory, recovery, poll,
full-resync and operator branches.

- [ ] **Step 7: Run non-Cargo validation**

Run:

```bash
python3 -m py_compile ci/check_neutron_stage1.py
python3 ci/check_blocked_terms.py
python3 -m unittest \
  openstack.neutron_aria.neutron_aria.tests.unit.test_uds_client \
  openstack.neutron_aria.neutron_aria.tests.unit.test_state \
  openstack.neutron_aria.neutron_aria.tests.unit.test_event_loop
git diff --check
```

Inspect exhaustive enum matches and complete response literals with `rg`; do
not run Cargo locally.

- [ ] **Step 8: Commit and push Rust GREEN**

```bash
git add api/src/lib.rs agent/src/neutron_api.rs agent/src/neutron_wal.rs \
  ci/check_neutron_stage1.py \
  docs/superpowers/plans/2026-08-14-review-acl-079-080-generation-retry-contract.md
git commit -m "fix: retry durable snapshot generations"
git push origin v0.9-neutron-agent
```

- [ ] **Step 9: Verify exact-head hosted GREEN**

Require:

- nonzero `snapshot_generation_retry_` behavior count;
- `rust-behavior` success;
- Python fast contracts and clean install success;
- warning-denied userspace, agent and eBPF builds;
- packaging/database jobs success;
- no compiler warning or superseded/cancelled evidence substituted for exact
  head.

---

### Task 5: Public Contract And Register Closure

**Files:**

- Modify: `docs/neutron-uds-contract.json`
- Modify: `docs/neutron-status-contract-v2-scenarios.json`
- Modify: `docs/openstack-neutron-aria-details/07-transaction-wal.md`
- Modify: `docs/openstack-neutron-aria-details/10-rust-scoped-apply.md`
- Modify: `docs/openstack-neutron-aria-details/12-review-bug-backlog.md`
- Modify: `docs/openstack-neutron-aria-details/16-versioned-rust-python-status-contract.md`
- Modify: `docs/superpowers/specs/2026-08-13-bug-hunt-remediation-program-design.md`
- Modify: approved design and this plan
- Modify: `ci/check_neutron_stage1.py`

- [ ] **Step 1: Make V2 the active public artifact contract**

Update schema/status/error/capability hashes, the new stable errors, action
vocabulary, routes and V2 scenario path. Retain and validate the immutable V1
fixture as a compatibility artifact. Static checks may validate public JSON,
enum and workflow structure; they must not parse private Rust helper shape.

- [ ] **Step 2: Update transaction and scoped-apply documentation**

Document positive submitted generations, exact G/H pending identity, active
deduplication, durable partial retry, changed-desired fallback and unsafe-state
exclusions. Remove the obsolete claim that same hash alone identifies pending
work.

- [ ] **Step 3: Record RED/GREEN evidence**

Record commit hashes, Build URLs, exact failing RED assertions, nonzero Rust
test count, Python-first GREEN and final producer GREEN. Do not claim field or
privileged datapath evidence.

- [ ] **Step 4: Close only ACL-079/080 after exact-head GREEN**

Mark both fixed only when the generation-zero side-effect test, exact pending
identity, first-generation partial convergence and mixed V1/V2 matrix all
pass. Advance the remediation program to the next fixed-order batch without
pulling it into this implementation.

- [ ] **Step 5: Commit, push and verify documentation head**

```bash
git add docs ci/check_neutron_stage1.py
git commit -m "docs: close versioned snapshot retries"
git push origin v0.9-neutron-agent
```

Require exact-head fast/static documentation contracts. If the final docs-only
head correctly skips Rust, cite the immediately preceding exact implementation
Build for Rust/eBPF evidence and the docs-head Build for contract closure.
