# REVIEW-CI-001 Trusted Automated Gates Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make required CI distinguish executable behavior, static artifacts, historical field evidence, and target runtime evidence without duplicating existing suites or parsing private Rust source.

**Architecture:** Keep full Python discovery as the single required Python execution path, add a loader-backed inventory for critical behavior IDs, use Cargo test-harness execution counts for Rust filters, and make every Stage 2/3 checker report its evidence class explicitly.  Prove Rust-advertised and Python-requested domain relationships at their native behavior boundaries.

**Tech Stack:** Python 3 `unittest`, Rust unit tests, Cargo test harness, GitHub Actions YAML, Markdown evidence records.

**Status:** Tasks 1-5 complete. RED `e6c1fe8` / Build
[30704754808](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/30704754808)
failed the required fast-contract wiring and was cancelled after the RED evidence
was captured. GREEN `5d7fcfc` / Build
[30704906357](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/30704906357)
passed fast contracts, database contracts, clean-container install, Rust
behavior, and warning-denied Rust/eBPF builds.

## Global Constraints

- Work only on `v0.9-neutron-agent`; do not create a branch or worktree.
- Do not run local Cargo build, check, or test commands.
- Preserve separate fast-contract, Rust behavior, and Rust/eBPF build jobs.
- Do not represent historical or missing field execution as current runtime PASS.
- Do not add a Rust source parser or bind checks to private helper layout.

---

### Task 1: Establish RED contracts

**Files:**
- Create: `ci/test_ci001_trusted_gates.py`
- Modify: `ci/test_ci_lane_contract.py`
- Modify: `agent/src/neutron_api.rs`

**Interfaces:**
- Consumes: existing Build `fast-contracts` and `rust-behavior` lanes.
- Produces: failing contracts for required Python inventory, evidence labels,
  domain parity, Cargo zero-test rejection, and required workflow wiring.

- [x] Add Python tests that require the new public CI helpers and scoped output.
- [x] Add a workflow contract requiring the focused CI-001 test module.
- [x] Add a Rust test named with the existing `domain_authority` filter that
  compares runtime implemented domains with advertised domains.
- [x] Run only the Python RED tests locally and verify failures are caused by
  the missing interfaces and old labels.
- [x] Commit and push the RED tests; record the failing Build.

### Task 2: Make behavior discovery authoritative

**Files:**
- Modify: `ci/check_neutron_stage1.py`
- Modify: `openstack/neutron_aria/neutron_aria/tests/unit/test_config.py`
- Modify: `agent/src/neutron_api.rs`

**Interfaces:**
- Consumes: Python `unittest` discovery, `docs/neutron-uds-contract.json`,
  `SUPPORTED_MANAGED_DOMAINS`, packaged configuration, and
  `NEUTRON_SUPPORTED_DOMAINS`.
- Produces: `discovered_python_test_ids()`,
  `check_required_python_behaviors()`,
  `validate_python_managed_domain_contract(...)`, and
  `implemented_neutron_domains()`.

- [x] Implement loader-backed Python test-ID discovery and the focused required
  behavior inventory.
- [x] Invoke the inventory before the existing one-time full Python discovery.
- [x] Validate `requested ⊆ Python supported ⊆ advertised` from imported
  values rather than source strings.
- [x] Make runtime unsupported-domain admission consume one explicit Rust
  implementation inventory and satisfy the advertised/runtime equality test.
- [x] Run focused Python tests; leave Rust verification to hosted CI.

### Task 3: Remove false readiness and duplicate execution

**Files:**
- Modify: `ci/check_neutron_stage2_acl.py`
- Modify: `ci/check_stage2_acceptance_evidence.py`
- Modify: `ci/check_stage3_readiness.py`
- Modify: `ci/check_stage3_n3_evidence.py`
- Modify: `ci/check_n05_discovery_evidence.py`
- Modify: `ci/check_uds_hardening_evidence.py`

**Interfaces:**
- Consumes: committed scripts, package files, workflow files, and historical
  evidence directories.
- Produces: explicit `evidence_class`, `head_bound`, and runtime-evaluation
  output fields.

- [x] Stop Stage 2 from rerunning its six Python modules.
- [x] Remove active source/test-name guards already covered by required behavior
  tests; retain genuine artifact contracts.
- [x] Label structural results `static_artifact`.
- [x] Label committed evidence `historical_field_evidence` and
  `head_bound=false`.
- [x] Run focused Python tests and the individual non-privileged checkers.

### Task 4: Use Cargo execution instead of a Rust source parser

**Files:**
- Modify: `ci/check_neutron_stage1.py`
- Test: `ci/test_ci001_trusted_gates.py`

**Interfaces:**
- Consumes: output from each existing configured Cargo test command.
- Produces: `run_rust_behavior_command(command)` that rejects a successful
  command when its test-harness execution count is zero.

- [x] Remove regex-based Rust source test discovery.
- [x] Execute each configured command once, preserve its output, propagate
  non-zero exits, and reject an aggregate zero-test result.
- [x] Verify the runner with mocked Cargo outputs in Python; do not run Cargo
  locally.

### Task 5: Wire required CI and close documentation

**Files:**
- Modify: `.github/workflows/build.yml`
- Modify: `ci/check_build_workflow_contract.py`
- Modify: `docs/openstack-neutron-aria-details/12-review-bug-backlog.md`
- Modify: this plan and the design status.

**Interfaces:**
- Consumes: all GREEN contracts from Tasks 2-4.
- Produces: an every-Build trusted-gate contract and exact-head CI evidence.

- [x] Run `ci.test_ci001_trusted_gates` in `fast-contracts` without Cargo.
- [x] Rename deep-audit steps so static and historical evidence are not called
  runtime readiness.
- [x] Run all non-Cargo focused checks locally.
- [x] Commit and push production GREEN.
- [x] Wait for `fast-contracts`, `rust-behavior`, and `rust-build` to pass.
- [x] Update the REVIEW Register and plan with exact commit and Build evidence,
  then push the documentation closure.

## Self-review

- The plan covers every accepted review correction and does not duplicate full
  Python discovery.
- The two production risks remain ordered follow-ups, not CI-001 scope.
- No step requires a local Cargo invocation or privileged environment.
- No placeholder implementation or private-source parser is introduced.
