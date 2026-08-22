# Aria Planned Maintenance Upgrade v0.9 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build one auditable, restart-safe Kolla workflow that upgrades `aria_datapath` and `neutron_aria_agent` without touching OVS, keeps ACL in explicit maintenance bypass during incompatible changes, and restores enforcement only after a complete authoritative host snapshot converges.

**Architecture:** A Python 3 host coordinator classifies release manifests, owns a durable operation ledger, and drives a root-only Rust maintenance API over a separate admin UDS socket. The eBPF shared runtime exposes one host ACL/conntrack maintenance bit; the Python 2 agent is fenced by operation identity and produces a revisionless stable double-read snapshot before the Rust datapath atomically activates the complete host generation.

**Tech Stack:** Bash, Python 3 standard library for host orchestration, Python 2.7-compatible `neutron_aria`, Rust/Axum/Aya, eBPF TC, Kolla/Docker, JSON release manifests, WAL-backed runtime state, GitHub Actions.

**Spec:** `docs/superpowers/specs/2026-08-21-aria-planned-maintenance-upgrade-design.md`

## Global Constraints

- Never stop, restart, recreate, or reconfigure `ovs-vswitchd` or `neutron-openvswitch-agent`.
- Never mutate `br-int`, Neutron ports, ofports, `binding:vif_type`, or unowned TC/XDP/BPF objects.
- A maintenance failure leaves ACL and conntrack in explicit bypass while OVS forwarding remains available.
- Docker health remains strict: `degraded`, `blocked`, and `bypass` are `unhealthy`; `/livez` is diagnostic only.
- v0.9 activation is host-wide. No port leaves bypass before the complete host generation is verified.
- Legacy Neutron correctness must not depend on `revision_number`.
- Python code under `openstack/neutron_aria` remains Python 2.7 compatible.
- Host coordinator code uses only the Python 3 standard library and Docker CLI.
- Rust/eBPF artifacts are compiled only by GitHub Actions and must come from one source commit and manifest.
- QoS, Mirror, blue-green datapaths, per-port early activation, and cross-container event-buffer transfer are outside this plan.
- Use one repository, one working tree, one `main` branch, and one `origin` remote.

---

## File And Interface Map

| Responsibility | Files |
| --- | --- |
| Compatibility authority | `release/runtime-compatibility.json`, `ci/create_release_manifest.py`, `deploy/kolla/package/aria_upgrade_control.py` |
| Host operation ledger and state machine | `deploy/kolla/package/aria_upgrade_control.py`, `deploy/kolla/package/install_aria_joint_rc.sh` |
| Shared packet-path maintenance gate | `abi/src/lib.rs`, `ebpf/src/runtime.rs`, `core/src/ebpf_ops/runtime.rs`, `core/src/ebpf_ops/replay.rs` |
| Durable datapath maintenance state | `agent/src/neutron_maintenance.rs`, `agent/src/neutron_wal.rs`, `agent/src/neutron_api.rs` |
| Root-only maintenance API | `api/src/lib.rs`, `agent/src/main.rs`, `agent/src/neutron_maintenance.rs` |
| Revisionless stable snapshot | `openstack/neutron_aria/neutron_aria/agent/event_loop.py`, `service.py`, `uds_client.py`, `state.py` |
| Strict health plus diagnostic liveness | `agent/src/api_routes.rs`, `agent/src/api_handlers/health.rs`, both Kolla healthcheck scripts |
| Packaging and rollback | `deploy/kolla/package/build_stage2_acl_bundle.sh`, both current RC installers, joint installer |
| Automated evidence | `ci/test_aria_upgrade_control.py`, `ci/test_kolla_joint_upgrade.py`, Rust and Python unit suites, new Kolla smoke |

## Delivery Gates

```text
D0 contract freeze
  -> D1 manifest classifier and dry-run
  -> D2 durable coordinator ledger
  -> D3 gate-capable datapath and admin API
  -> D4 stable authoritative rebuild
  -> D5 joint upgrade and rollback
  -> D6 CI, 4.18 canary, rolling field acceptance
```

Each gate is independently reviewable. Do not start D5 field mutation before D1-D4 tests are green and one CI-produced gate-capable artifact exists.

### Task 0: Freeze The v0.9 Contract

**Files:**
- Modify: `docs/superpowers/specs/2026-08-21-aria-planned-maintenance-upgrade-design.md`
- Test: `ci/test_kolla_container_healthchecks.py`

**Interfaces:**
- Consumes: Existing strict health contract and current hash-aware installers.
- Produces: Normative choices for health, host activation, revisionless convergence, and first-adoption bootstrap.

- [x] **Step 1: Record strict health and host-wide activation**

The spec must state that `/livez` may be healthy while `/readyz` and Docker health are unhealthy, and that one failed port keeps the host ACL gate in bypass.

- [x] **Step 2: Record revisionless stable double-read**

The legacy profile requires two canonical host snapshots with equal desired hashes and no RPC buffer overflow.

- [x] **Step 3: Record the one-time bootstrap exception**

The current exact-owner detach installer introduces the first gate-capable ABI; every later incompatible upgrade uses the joint transaction.

- [x] **Step 4: Run the existing health contract**

Run: `python3 -m unittest ci.test_kolla_container_healthchecks`

Expected: PASS and continued assertions that degraded/bypass are Docker unhealthy.

### Task 1: Extend The Release Manifest And Add A Pure Classifier

**Files:**
- Create: `release/runtime-compatibility.json`
- Create: `deploy/kolla/package/aria_upgrade_control.py`
- Modify: `ci/create_release_manifest.py`
- Modify: `deploy/kolla/package/build_stage2_acl_bundle.sh`
- Test: `ci/test_release_governance.py`
- Test: `ci/test_aria_upgrade_control.py`

**Interfaces:**
- Produces: `load_manifest(path) -> dict`, `classify_upgrade(current, candidate, force_maintenance=False) -> UpgradeClassification`.
- `UpgradeClassification.path` is exactly `hot_agent`, `hot_datapath`, or `planned_maintenance`.
- `UpgradeClassification.reasons` is a sorted tuple of stable reason codes.
- The stage-two bundle requires verified `AGENT_IMAGE_IDENTITY` and
  `DATAPATH_IMAGE_IDENTITY` values in named immutable `@sha256:` form; the
  publishing workflow obtains both from the freshly built image IDs before
  constructing the bundle manifest.

- [x] **Step 1: Write failing manifest-field tests**

Assert that generated manifests contain these values from `runtime-compatibility.json`:

```json
{
  "schema_version": 1,
  "uds_schema_min": 1,
  "uds_schema_max": 1,
  "snapshot_schema_version": 1,
  "ebpf_abi_version": 1,
  "map_schema_version": 1,
  "wal_schema_version": 1,
  "runtime_state_schema_version": 1,
  "minimum_kernel_profile": "rhel8-4.18",
  "managed_domain_contract_version": "2026-06-v0.9",
  "maintenance_gate_capable": false
}
```

The generator also emits `release_version`, `ebpf_abi_hash`, and
`map_schema_hash`. Compute `ebpf_abi_hash` from the bytes of `abi/src/lib.rs`
and `map_schema_hash` from length-delimited bytes of `abi/src/lib.rs` plus
`ebpf/src/maps.rs`; do not accept caller-supplied hash strings.

- [x] **Step 2: Run the focused tests and observe failure**

Run: `python3 -m unittest ci.test_release_governance ci.test_aria_upgrade_control`

Expected: FAIL because compatibility data and classifier are absent.

- [x] **Step 3: Extend `build_manifest()` without deriving ABI from filenames**

Read and validate the compatibility JSON, copy it under `runtime_compatibility`, and include its SHA-256 under `contracts`. Missing, boolean-as-integer, negative, or unknown required fields must fail manifest generation.

- [x] **Step 4: Implement deterministic classification**

Use this decision order:

```python
DATAPATH_KEYS = (
    "snapshot_schema_version", "ebpf_abi_version", "map_schema_version",
    "ebpf_abi_hash", "map_schema_hash",
    "wal_schema_version", "runtime_state_schema_version",
    "minimum_kernel_profile", "managed_domain_contract_version",
)

if force_maintenance:
    return UpgradeClassification("planned_maintenance", ("operator_forced",))
if agent_changed and datapath_changed:
    return UpgradeClassification("planned_maintenance", ("joint_agent_datapath_change",))
if uds_ranges_are_disjoint(current, candidate):
    return UpgradeClassification("planned_maintenance", ("uds_schema_incompatible",))
if current["maintenance_gate_capable"] != candidate["maintenance_gate_capable"]:
    return UpgradeClassification("planned_maintenance", ("maintenance_gate_capability_changed",))
if any(current[key] != candidate[key] for key in DATAPATH_KEYS):
    return UpgradeClassification("planned_maintenance", tuple(sorted(changed_keys)))
if agent_changed and not datapath_changed:
    return UpgradeClassification("hot_agent", ("agent_only",))
if datapath_changed:
    return UpgradeClassification("hot_datapath", ("compatible_datapath",))
return UpgradeClassification("hot_agent", ("no_runtime_change",))
```

Unknown or malformed compatibility data must classify as `planned_maintenance`, never hot replacement.
`agent_changed` and `datapath_changed` are computed from the named immutable
image identities in the two manifests; missing required image identities are
unknown compatibility and therefore select planned maintenance.

The approved design governs this task summary: all joint agent and datapath
releases use planned maintenance, regardless of otherwise compatible datapath
ABI. UDS ranges must overlap, and maintenance-gate capability transitions are
planned maintenance.

- [x] **Step 5: Add a read-only dry-run command**

Run interface:

```text
python3 aria_upgrade_control.py classify \
  --current /var/lib/aria-release/current-manifest.json \
  --candidate ./release-manifest.json
```

It prints one bounded JSON object and never calls Docker.

- [x] **Step 6: Run governance and classifier tests**

Run: `python3 -m unittest ci.test_release_governance ci.test_aria_upgrade_control`

Expected: PASS for compatible agent-only, incompatible map ABI, unknown manifest, and forced-maintenance cases.

- [x] **Step 7: Commit the D1 gate**

```bash
git add release/runtime-compatibility.json ci/create_release_manifest.py \
  ci/test_release_governance.py ci/test_aria_upgrade_control.py \
  deploy/kolla/package/aria_upgrade_control.py \
  deploy/kolla/package/build_stage2_acl_bundle.sh
git commit -m "feat(kolla): classify Aria runtime upgrades"
```

### Task 2: Implement The Durable Host Ledger And Lock

**Files:**
- Modify: `deploy/kolla/package/aria_upgrade_control.py`
- Test: `ci/test_aria_upgrade_control.py`

**Interfaces:**
- Produces: `UpgradeLedger.begin()`, `transition()`, `fail()`, `commit()`, and `recover()`.
- Ledger path: `/var/lib/aria-release/operations/<operation_id>.json`, root-owned mode `0600`.
- Lock path: `/run/lock/aria-release.lock` acquired with `fcntl.flock(LOCK_EX | LOCK_NB)`.

- [x] **Step 1: Write crash-boundary and idempotency tests**

Cover duplicate operation ID, conflicting operation ID, invalid transition, stale ledger recovery, write-before-rename failure, and directory-fsync failure. Verify the previous valid ledger remains parseable.

- [x] **Step 2: Run the focused tests and observe failure**

Run: `python3 -m unittest ci.test_aria_upgrade_control.UpgradeLedgerTest`

Expected: FAIL because ledger classes do not exist.

- [x] **Step 3: Implement strict phase transitions**

The allowed edge table is a constant. `transition(expected_phase, next_phase, evidence)` uses compare-and-swap semantics and rejects skipped or backward phases except the explicit `rollback` edge.

```python
ALLOWED = {
    "preflight": ("quiescing", "failed_before_mutation"),
    "quiescing": ("bypass_preparing",),
    "bypass_preparing": ("bypass_confirmed",),
    "bypass_confirmed": ("datapath_upgrading", "maintenance_bypass"),
    "datapath_upgrading": ("datapath_live", "maintenance_bypass"),
    "datapath_live": ("agent_upgrading", "maintenance_bypass"),
    "agent_upgrading": ("agent_buffering", "maintenance_bypass"),
    "agent_buffering": ("full_resync", "maintenance_bypass"),
    "full_resync": ("shadow_apply", "maintenance_bypass"),
    "shadow_apply": ("activating", "maintenance_bypass"),
    "activating": ("verifying", "maintenance_bypass"),
    "verifying": ("committed", "maintenance_bypass"),
    "maintenance_bypass": ("full_resync", "rollback"),
    "rollback": ("full_resync", "maintenance_bypass"),
}
```

- [x] **Step 4: Implement atomic persistence**

Write canonical JSON to a same-directory temp file, `flush`, `os.fsync`, `os.rename`, then `fsync` the directory. Reject symlinks and non-root-owned existing state.

- [x] **Step 5: Add bounded audit output**

Each transition logs operation ID, host, old phase, new phase, elapsed milliseconds, generation, desired hash, image IDs, and result. It never logs environment variables, auth tokens, or snapshot bodies.

- [x] **Step 6: Run ledger tests**

Run: `python3 -m unittest ci.test_aria_upgrade_control.UpgradeLedgerTest`

Expected: PASS including simulated crashes.

- [x] **Step 7: Commit the D2 gate**

```bash
git add deploy/kolla/package/aria_upgrade_control.py ci/test_aria_upgrade_control.py
git commit -m "feat(kolla): persist Aria upgrade transactions"
```

### Task 3: Add The Shared ACL Maintenance Gate To The Packet Path

**Files:**
- Modify: `abi/src/lib.rs`
- Modify: `ebpf/src/runtime.rs`
- Modify: `core/src/ebpf_ops/runtime.rs`
- Modify: `core/src/ebpf_ops/replay.rs`
- Modify: `agent/src/control_plane.rs`
- Test: `core/tests/acl_projection_contract.rs`
- Test: Rust unit tests colocated in the modified modules

**Interfaces:**
- Produces: `set_acl_maintenance_bypass(runtime: TapMapRuntime, enabled: bool) -> Result<(), String>`.
- `FirewallConfig.acl_maintenance_bypass` is a new ABI byte and requires incrementing `ebpf_abi_version` and `map_schema_version`.

- [x] **Step 1: Write failing ABI and packet-gate tests**

Assert that maintenance bypass disables both `acl_enabled(tap_id)` and `conntrack_enabled(tap_id)` before `TAP_CONFIG_MAP` is consulted, while monitoring, QoS, Mirror, and TCP-RT retain their values.

- [x] **Step 2: Run behavior tests and observe failure**

Run: `cargo test -p aria-ebpf --lib runtime -- --nocapture && cargo test -p aria-core acl_maintenance -- --nocapture`

Expected: FAIL because the field and helper are absent.

- [x] **Step 3: Extend the shared ABI explicitly**

Add `acl_maintenance_bypass: u8` to `FirewallConfig`, update every constructor, and increment both compatibility versions. Do not reuse `acl_active_bank` or any feature byte.

- [x] **Step 4: Check the host gate before per-tap state**

```rust
#[inline(always)]
fn acl_maintenance_bypass() -> bool {
    read_global_config()
        .map(|cfg| cfg.acl_maintenance_bypass != 0)
        .unwrap_or(false)
}

pub fn acl_enabled(tap_id: u32) -> bool {
    if acl_maintenance_bypass() { return false; }
    // existing per-tap/global lookup
}

pub fn conntrack_enabled(tap_id: u32) -> bool {
    if acl_maintenance_bypass() { return false; }
    // existing per-tap/global lookup
}
```

Missing gate state defaults to enforcement-capable behavior for legacy runtime adoption; an active durable maintenance ledger forces the value to `1` before reconciliation.

- [x] **Step 5: Implement userspace read/write and strict verification**

The setter opens only the proven managed shared `FIREWALL_CONFIG`, updates key `0`, reads it back, and fails if the observed value differs. No TC link, qdisc, or OVS operation belongs in this helper.

- [x] **Step 6: Run Rust behavior tests**

Run: `cargo test -p aria-ebpf --lib runtime -- --nocapture && cargo test -p aria-core --all-targets && cargo test -p aria-agent acl_maintenance -- --nocapture`

Expected: PASS. eBPF compilation and 4.18 verifier acceptance remain CI/field gates, not local claims.

- [x] **Step 7: Commit the packet gate**

```bash
git add abi/src/lib.rs ebpf/src/runtime.rs core/src/ebpf_ops/runtime.rs \
  core/src/ebpf_ops/replay.rs agent/src/control_plane.rs \
  core/tests/acl_projection_contract.rs release/runtime-compatibility.json
git commit -m "feat(datapath): add host ACL maintenance gate"
```

### Task 4: Add Durable Maintenance State And A Root-Only Admin Socket

**Files:**
- Create: `agent/src/neutron_maintenance.rs`
- Modify: `agent/src/neutron_wal.rs`
- Modify: `agent/src/neutron_api.rs`
- Modify: `agent/src/main.rs`
- Modify: `api/src/lib.rs`
- Modify: `docs/neutron-uds-contract.json`
- Test: Rust unit tests in `agent/src/neutron_maintenance.rs` and `agent/src/neutron_api.rs`

**Interfaces:**
- Admin socket: `/run/aria/aria-admin.sock`, owner `root:root`, mode `0600`.
- Routes: `POST /api/v1/admin/maintenance/enter`, `GET /api/v1/admin/maintenance`, `POST /api/v1/admin/maintenance/exit`, `POST /api/v1/admin/maintenance/abort`.
- Snapshot requests add optional `maintenance_operation_id`; when maintenance is active, only matching full-host snapshots are accepted.

- [x] **Step 1: Write failing state-machine, authorization, and restart tests**

Cover same-ID idempotency, conflicting-ID HTTP 409, generation/hash CAS mismatch, normal Neutron write rejection during maintenance, port-scoped rejection, startup replay forcing bypass, and admin socket mode/owner.

- [x] **Step 2: Run focused Rust tests and observe failure**

Run: `cargo test -p aria-agent neutron_maintenance -- --nocapture`

Expected: FAIL because maintenance state and routes are absent.

- [x] **Step 3: Define typed contract objects**

`MaintenanceState` contains only schema version, operation ID, phase, active domains, expected/applied generation and hash, bypass start time, last progress time, and last error. Snapshot policy remains absent.

- [x] **Step 4: Persist maintenance intent and commit in the Neutron WAL**

Entering maintenance writes intent, flips and verifies the shared gate, then writes commit. Startup with committed active maintenance forces the gate to bypass before normal runtime reconciliation. A dangling enter intent is recovered conservatively as active bypass.

- [x] **Step 5: Bind a separate root-only listener**

Do not route admin calls through the neutron-owned `0660` socket. `main.rs` binds the separate `0600` socket and serves only the maintenance router on it. Normal snapshot routes remain on `/run/aria/aria-agent.sock`.

- [x] **Step 6: Fence normal writers by operation identity**

While active:

```text
matching full-host snapshot + operation ID -> stage allowed
missing/wrong operation ID               -> 409 maintenance_operation_mismatch
port-scoped snapshot                      -> 409 maintenance_requires_full_host
delete route                              -> 409 maintenance_requires_full_host
```

Exit succeeds only when the operation ID, applied generation, applied desired hash, zero pending generation, and complete ready/enforce port set all match.

- [x] **Step 7: Run API, WAL, and contract tests**

Run: `cargo test -p aria-agent neutron_maintenance -- --nocapture && cargo test -p aria-agent neutron_api -- --nocapture && cargo test -p aria-api`

Expected: PASS for enter, replay, stage, exit, abort, and conflict paths.

- [x] **Step 8: Commit the D3 control gate**

```bash
git add agent/src/neutron_maintenance.rs agent/src/neutron_wal.rs \
  agent/src/neutron_api.rs agent/src/main.rs api/src/lib.rs \
  docs/neutron-uds-contract.json
git commit -m "feat(agent): add durable ACL maintenance API"
```

**D3 closure evidence (2026-08-22):** accepted code SHA
`1f9fe513899f08a72f7c5b55649a4215fe719814`; exact-head GitHub Actions run
`32565203326` passed the 60-test maintenance batch, static Rust agent build,
and linked `tc_ingress=480` / `tc_egress=480` stack gates. The independent
bounded review found no remaining Critical or Important issue and recorded
`Ready: Yes`; the governing closure plan is
`docs/superpowers/plans/2026-08-22-d3-maintenance-control-closure.md`.
`maintenance_gate_capable` remains `false`. Real EL 4.18 verifier/load/attach,
dual-stack traffic, restart/rollback, and root-socket field evidence remain
`deferred/pending`; this is not production-readiness approval.

### Task 5: Implement Revisionless Stable Full Resync In The Python Agent

**Files:**
- Modify: `openstack/neutron_aria/neutron_aria/agent/event_loop.py`
- Modify: `openstack/neutron_aria/neutron_aria/agent/service.py`
- Modify: `openstack/neutron_aria/neutron_aria/agent/uds_client.py`
- Modify: `openstack/neutron_aria/neutron_aria/agent/state.py`
- Test: `openstack/neutron_aria/neutron_aria/tests/unit/test_event_loop.py`
- Test: `openstack/neutron_aria/neutron_aria/tests/unit/test_service.py`
- Test: `openstack/neutron_aria/neutron_aria/tests/unit/test_uds_client.py`

**Interfaces:**
- Produces: `SnapshotSynchronizer.safe_stable_full_resync(operation_id, max_attempts=5)`.
- Produces: `LocalClient.maintenance_status()` and typed `maintenance_operation_id` submission.
- Produces bounded status fields: `maintenance_phase`, `maintenance_operation_id`, `stable_read_attempts`, `stable_desired_hash`, `last_progress_at`.

- [ ] **Step 1: Write failing double-read tests**

Cover equal hash, changed hash, event arriving between reads, queue overflow, Neutron timeout, foreign-host ambiguity, and five-attempt exhaustion. Assert that no snapshot is submitted before two equal reads.

- [ ] **Step 2: Run Python 2-compatible unit tests and observe failure**

Run: `python -m unittest neutron_aria.tests.unit.test_event_loop neutron_aria.tests.unit.test_service neutron_aria.tests.unit.test_uds_client`

Expected: FAIL because stable resync is absent.

- [ ] **Step 3: Extract snapshot construction from submission**

Create `_build_host_snapshot_candidate()` from the existing read/build portion of `full_resync()`. It returns a canonical snapshot and desired hash but does not mutate the local state store or call UDS.

- [ ] **Step 4: Implement the bounded stability loop**

```python
for attempt in range(1, max_attempts + 1):
    first = self._build_host_snapshot_candidate()
    self._settle_maintenance_events()
    second = self._build_host_snapshot_candidate()
    if self._maintenance_candidate_stable(first, second):
        return self._submit_stable_candidate(second, operation_id, attempt)
raise LocalApiTimeoutError("maintenance_snapshot_not_stable")
```

Stability requires equal desired hashes, equal projected port IDs, no overflow, no unclassified foreign-host decision, and no pending merged event at the decision point.

- [ ] **Step 5: Make maintenance startup full-host only**

The agent subscribes to RPC before its initial read. If datapath status reports active maintenance, `AgentService.initialize()` invokes stable full resync, suppresses port-scoped apply/delete, and includes the matching operation ID in the request.

- [ ] **Step 6: Persist only progress identity**

Store operation ID, attempt count, desired hash, and timestamp. Do not persist Neutron policy as a second authority and do not transfer the old process event buffer.

- [ ] **Step 7: Run Python unit suites in Python 2.7 and Python 3**

Run in the clean legacy container: `python -m unittest discover -s neutron_aria/tests/unit -p 'test_*.py'`.

Run on CI Python 3: `python3 -m unittest discover -s openstack/neutron_aria/neutron_aria/tests/unit -p 'test_*.py'`.

Expected: PASS on both runtimes.

- [ ] **Step 8: Commit the D4 source barrier**

```bash
git add openstack/neutron_aria/neutron_aria/agent/event_loop.py \
  openstack/neutron_aria/neutron_aria/agent/service.py \
  openstack/neutron_aria/neutron_aria/agent/uds_client.py \
  openstack/neutron_aria/neutron_aria/agent/state.py \
  openstack/neutron_aria/neutron_aria/tests/unit
git commit -m "feat(neutron): add maintenance stable full resync"
```

### Task 6: Add Diagnostic Liveness Without Weakening Docker Health

**Files:**
- Modify: `agent/src/api_routes.rs`
- Modify: `agent/src/api_handlers/health.rs`
- Modify: `agent/src/neutron_api.rs`
- Create: `openstack/neutron_aria/neutron_aria/agent/liveness.py`
- Modify: `openstack/neutron_aria/neutron_aria/agent/service.py`
- Modify: `openstack/neutron_aria/neutron_aria/agent/main.py`
- Modify: `deploy/kolla/aria-datapath/healthcheck-aria-datapath.sh`
- Modify: `deploy/kolla/neutron-aria-agent/healthcheck-neutron-aria-agent.sh`
- Test: `ci/test_kolla_container_healthchecks.py`
- Test: `openstack/neutron_aria/neutron_aria/tests/unit/test_liveness.py`

**Interfaces:**
- TCP diagnostic route: `GET /api/v1/livez`.
- UDS diagnostic route: `GET /livez`.
- Python service-loop evidence: `/var/lib/neutron-aria-agent/state/service-liveness.json`.
- Docker health authority remains `/readyz`.

- [ ] **Step 1: Write failing liveness/readiness matrix tests**

Assert:

```text
ready/enforce              live=200 ready=200 docker=healthy
planned maintenance bypass live=200 ready=503 docker=unhealthy
blocked recovery            live=200 ready=503 docker=unhealthy
dead loop/socket             live=failed ready=failed docker=unhealthy
```

- [ ] **Step 2: Run health contract tests and observe failure**

Run: `python3 -m unittest ci.test_kolla_container_healthchecks`

Expected: FAIL because `/livez` is absent.

- [ ] **Step 3: Add bounded liveness responses**

Liveness checks process loop and API responsiveness only. It must not inspect ACL generation, ports, or OVS.

- [ ] **Step 4: Publish Python service-loop evidence atomically**

At initialization and after every `run_once()`, write schema version, PID, host,
and `updated_at` using temp-file, `fsync`, rename, and directory `fsync`. The
Python health script rejects a missing record, PID mismatch, malformed JSON, or
age greater than 120 seconds.

- [ ] **Step 5: Keep both Docker scripts strict**

The scripts may probe `/livez` for diagnostics, but their exit code still requires `/readyz`. Add comments and tests preventing a future switch to liveness-only Docker health.

- [ ] **Step 6: Run health tests**

Run: `python3 -m unittest ci.test_kolla_container_healthchecks && (cd openstack/neutron_aria && python -m unittest neutron_aria.tests.unit.test_liveness) && bash -n deploy/kolla/aria-datapath/healthcheck-aria-datapath.sh && bash -n deploy/kolla/neutron-aria-agent/healthcheck-neutron-aria-agent.sh`

Expected: PASS.

- [ ] **Step 7: Commit the health split**

```bash
git add agent/src/api_routes.rs agent/src/api_handlers/health.rs \
  agent/src/neutron_api.rs openstack/neutron_aria/neutron_aria/agent/liveness.py \
  openstack/neutron_aria/neutron_aria/agent/service.py \
  openstack/neutron_aria/neutron_aria/agent/main.py \
  openstack/neutron_aria/neutron_aria/tests/unit/test_liveness.py \
  deploy/kolla/aria-datapath/healthcheck-aria-datapath.sh \
  deploy/kolla/neutron-aria-agent/healthcheck-neutron-aria-agent.sh \
  ci/test_kolla_container_healthchecks.py
git commit -m "feat(health): expose Aria liveness diagnostics"
```

### Task 7: Build The Joint Kolla Coordinator

**Files:**
- Create: `deploy/kolla/package/install_aria_joint_rc.sh`
- Modify: `deploy/kolla/package/aria_upgrade_control.py`
- Modify: `deploy/kolla/package/install_aria_datapath_rc_image.sh`
- Modify: `deploy/kolla/package/install_neutron_aria_agent_rc_image.sh`
- Test: `ci/test_kolla_joint_upgrade.py`

**Interfaces:**
- Operator entry point: `install_aria_joint_rc.sh dry-run|install|status|resume|rollback|check`.
- Existing component installers expose internal `prepare`, `replace`, `verify`, and `restore` actions; they do not own the joint ledger.

- [ ] **Step 1: Write a fake-Docker state-machine harness**

Record every Docker and curl invocation. Cover failure before mutation, after bypass, after datapath replacement, after agent replacement, during resync, during activation, and during rollback.

- [ ] **Step 2: Run coordinator tests and observe failure**

Run: `python3 -m unittest ci.test_kolla_joint_upgrade`

Expected: FAIL because the joint installer is absent.

- [ ] **Step 3: Implement preflight and immutable evidence**

Before mutation verify candidate image IDs/hashes, both manifests, admin and Neutron socket ownership, disk space, rollback images/config, OVS PID, OVS-agent ID/start time, `br-int` UUID, managed port inventory, and current generation/hash.

- [ ] **Step 4: Implement planned-maintenance ordering**

```text
lock + ledger begin
  -> enter maintenance on old datapath
  -> verify ACL/CT bypass and OVS canary
  -> stop/preserve old Python agent
  -> replace datapath
  -> verify /livez + matching maintenance ID
  -> replace/start Python agent
  -> stable full-resync with operation ID
  -> verify complete generation/hash
  -> exit maintenance atomically
  -> verify /readyz + Docker health + OVS identity
  -> commit ledger
```

The coordinator never invokes `docker restart` on OVS/ovs-agent and never runs `ovs-vsctl` mutations.

- [ ] **Step 5: Implement compatible agent-only ordering**

Preserve the current datapath and last-known-good ACL, replace only the Python container, require one authoritative full resync, and verify generation convergence. If compatibility is unknown, select planned maintenance.

- [ ] **Step 6: Implement restart-safe resume**

Every mutating command first reads the ledger and observed container/admin state. Repeating the same phase is idempotent. A phase mismatch moves to `maintenance_bypass` and requires `resume` or `rollback`; it never guesses that enforcement is safe.

- [ ] **Step 7: Run state-machine and static non-interference tests**

Run: `python3 -m unittest ci.test_kolla_joint_upgrade ci.test_aria_upgrade_control ci.test_kolla_datapath_runtime_upgrade`

Expected: PASS with zero OVS lifecycle calls in every trace.

- [ ] **Step 8: Commit the D5 coordinator**

```bash
git add deploy/kolla/package/install_aria_joint_rc.sh \
  deploy/kolla/package/aria_upgrade_control.py \
  deploy/kolla/package/install_aria_datapath_rc_image.sh \
  deploy/kolla/package/install_neutron_aria_agent_rc_image.sh \
  ci/test_kolla_joint_upgrade.py
git commit -m "feat(kolla): coordinate joint Aria upgrades"
```

### Task 8: Implement Maintenance-Safe Rollback And Retention

**Files:**
- Modify: `deploy/kolla/package/install_aria_joint_rc.sh`
- Modify: `deploy/kolla/package/aria_upgrade_control.py`
- Test: `ci/test_kolla_joint_upgrade.py`

**Interfaces:**
- `rollback --operation-id <uuid>` restores binaries/config but rebuilds policy from current Neutron state.
- Completed ledgers are immutable; retention defaults to the latest three completed operations plus every unresolved operation.

- [ ] **Step 1: Write rollback failure-point tests**

Cover candidate failure, old datapath restore failure, old agent restore failure, Neutron unavailable, stable-hash timeout, activation failure, coordinator kill, and second rollback invocation.

- [ ] **Step 2: Implement rollback as a new maintenance transaction**

Never reactivate old maps merely because they exist. Restore old binaries in maintenance mode, start the old compatible agent, perform stable full resync from current Neutron, then activate only the complete current generation.

- [ ] **Step 3: Implement bounded retention**

Delete only completed operation records and retired backup containers proven to belong to those records. Preserve unresolved ledgers, current rollback images, current manifests, and every unknown object.

- [ ] **Step 4: Run rollback tests**

Run: `python3 -m unittest ci.test_kolla_joint_upgrade.JointRollbackTest`

Expected: PASS and every post-bypass failure terminates in explicit maintenance bypass.

- [ ] **Step 5: Commit rollback support**

```bash
git add deploy/kolla/package/install_aria_joint_rc.sh \
  deploy/kolla/package/aria_upgrade_control.py ci/test_kolla_joint_upgrade.py
git commit -m "feat(kolla): add maintenance-safe Aria rollback"
```

### Task 9: Package The Coordinator And Bootstrap Profile

**Files:**
- Modify: `deploy/kolla/package/build_stage2_acl_bundle.sh`
- Modify: `deploy/kolla/package/README.md`
- Modify: `docs/openstack-deployment-runbook.md`
- Modify: `.github/workflows/build.yml`
- Test: `ci/check_neutron_stage2_acl.py`
- Test: `ci/check_release_reproducibility.sh`

**Interfaces:**
- Bundle includes coordinator, classifier, compatibility file, both installers, manifest, checksums, and bootstrap instructions.
- Manifest flag `maintenance_gate_capable` becomes `true` only after Tasks 3-6 are present in the same source commit.

- [ ] **Step 1: Write failing bundle-content tests**

Assert exact paths, executable modes, deterministic tar ordering, checksums, compatibility hash, and no undeclared host dependency.

- [ ] **Step 2: Add one-time bootstrap documentation**

Bootstrap uses the current exact-owner detach path once, records gate capability, then disables bootstrap mode. Normal instructions expose only the joint coordinator.

- [ ] **Step 3: Publish all assets from one GitHub workflow run**

Rust agent, both eBPF objects, Python egg, Kolla images, bundle, manifest, checksums, and stack-budget report must share one source commit.

- [ ] **Step 4: Run packaging gates**

Run: `python3 ci/check_neutron_stage2_acl.py && python3 -m unittest ci.test_release_governance && bash ci/check_release_reproducibility.sh`

Expected: PASS and identical bundle SHA-256 across two builds.

- [ ] **Step 5: Commit packaging changes**

```bash
git add deploy/kolla/package/build_stage2_acl_bundle.sh \
  deploy/kolla/package/README.md docs/openstack-deployment-runbook.md \
  .github/workflows/build.yml ci/check_neutron_stage2_acl.py \
  ci/check_release_reproducibility.sh
git commit -m "build(release): package joint Aria upgrade workflow"
```

### Task 10: CI And Target-Kernel Acceptance

**Files:**
- Create: `deploy/kolla/smoke/neutron_aria_joint_upgrade_smoke.sh`
- Create: `docs/evidence/openstack-n05-lite/20260821-planned-maintenance-upgrade/summary.md` during field execution
- Modify: `.github/workflows/build.yml`
- Test: all gates below

**Interfaces:**
- Smoke modes: `bootstrap`, `upgrade`, `kill-phase`, `rollback`, `cleanup`.
- Evidence binds source commit, workflow run, image IDs, binary hashes, manifest hash, host, kernel, operation ID, and ledger.

- [ ] **Step 1: Run repository gates before CI**

Run:

```bash
python3 ci/check_blocked_terms.py
python3 -m unittest ci.test_release_governance ci.test_aria_upgrade_control \
  ci.test_kolla_joint_upgrade ci.test_kolla_container_healthchecks
git diff --check
```

Expected: PASS.

- [ ] **Step 2: Push one candidate commit and run GitHub Actions**

Require Rust workspace tests, clippy/warnings, Python 2.7 clean-container tests, shell syntax/static gates, eBPF build, stack budget, bundle reproducibility, and artifact upload.

- [ ] **Step 3: Run isolated 4.18 veth/netns canary**

Load the exact CI eBPF artifacts on one test node. Verify TC ingress/egress, maintenance bit behavior, allow/drop, detach, no residual pin/link/qdisc, and no verifier stack/bounds errors. Do not use a business VM tap.

- [ ] **Step 4: Execute first-adoption bootstrap on one node**

Use the current proven installer once, maintain an independent OVS canary, install the gate-capable pair, perform full resync, mark gate capability, then execute and verify one real rollback.

- [ ] **Step 5: Execute a normal joint upgrade on the same node**

Change an eBPF/map compatibility version, require automatic planned-maintenance classification, verify strict unhealthy status during bypass, mutate one ACL during the window, and prove the post-upgrade hash includes that mutation.

- [ ] **Step 6: Inject process death at every persisted phase**

Kill the coordinator after each phase boundary and restart with `resume`; kill candidate agent/datapath during full resync and shadow apply; verify no automatic stale enforcement and continuous OVS canary success.

- [ ] **Step 7: Roll through the remaining available nodes one at a time**

Require per-node ICMP/TCP/UDP IPv4+IPv6 ACL smoke, API/CLI/status consistency, generation lag zero, exact cleanup, and unchanged OVS/ovs-agent identities before advancing.

- [ ] **Step 8: Run post-upgrade regression and soak**

Run the existing RC product plan, control-plane fault suite, lifecycle suite, active ACL matrix, and a 12-hour three-node soak only after every node uses the same manifest. This validates the new deployment path without replacing the already established ACL functional baseline.

- [ ] **Step 9: Record the release decision**

The result is `pass`, `deferred`, or `failed` per gate. Static CI evidence must not be labeled as 4.18 field PASS. Any unresolved maintenance ledger blocks release tagging.

## Definition Of Done

The deployment optimization is complete only when:

1. One manifest classifies every supported upgrade path conservatively.
2. One host lock and ledger survive coordinator/container restarts.
3. The root-only maintenance API persists and replays the ACL/CT bypass gate.
4. Old or mismatched Python writers cannot mutate runtime during maintenance.
5. Two stable revisionless inventory reads precede activation.
6. Host activation is atomic for one complete generation and desired hash.
7. Docker reports unhealthy throughout bypass while `/livez` remains diagnostic.
8. Rollback rebuilds current Neutron truth before enforcement.
9. OVS/ovs-agent identities and forwarding remain unchanged in all Aria tests.
10. The exact CI artifact passes 4.18 canary, rolling deployment, rollback, regression, and soak.

## Deferred Optimizations

Do not open implementation tasks for these until field evidence justifies them:

- per-port early activation under a host maintenance transaction;
- cross-container event-buffer transfer;
- transactional Neutron host snapshot endpoint with revision watermark;
- rule-level apply progress and unbounded per-port heartbeat detail;
- blue-green duplicate eBPF datapaths;
- concurrent maintenance on multiple compute nodes;
- QoS or Mirror integration with the coordinator.
