# Aria Kolla Container Healthchecks Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Make `docker ps` report `aria_datapath` and `neutron_aria_agent` as healthy only when the strict Aria ACL path is ready.

**Architecture:** Put one small, side-effect-free probe in each image. The datapath probe checks TCP liveness plus UDS strict readiness using the real `neutron` peer identity; the Python-agent probe checks the shared UDS strict readiness. Image metadata owns the timing policy, while RC installers require Docker health without changing rollback compatibility or touching OVS.

**Tech Stack:** POSIX shell, Docker/Kolla image metadata, existing Rust HTTP/UDS endpoints, Bash RC installers and smoke tests, Python contract tests.

---

### Task 1: Add the strict probe contract and RED tests

**Files:**
- Create: `ci/test_kolla_container_healthchecks.py`
- Create: `deploy/kolla/aria-datapath/healthcheck-aria-datapath.sh`
- Create: `deploy/kolla/neutron-aria-agent/healthcheck-neutron-aria-agent.sh`

- [x] Add tests that require both scripts, shell syntax validity, strict endpoint usage, the `neutron` datapath peer identity, and the exact Docker timing policy.
- [x] Run the test and record the expected failure before production files are complete.
- [x] Implement minimal side-effect-free probes with bounded `curl` calls and exact HTTP success semantics.
- [x] Run the contract test and shell syntax checks to green.

### Task 2: Carry healthchecks through every image build and smoke path

**Files:**
- Modify: `deploy/kolla/aria-datapath/Dockerfile`
- Modify: `deploy/kolla/neutron-aria-agent/Dockerfile`
- Modify: `deploy/kolla/package/build_aria_datapath_image.sh`
- Modify: `deploy/kolla/smoke/aria_datapath_container_smoke.sh`
- Modify: `deploy/kolla/smoke/neutron_aria_container_smoke.sh`

- [x] Copy each probe into its image with mode `0755` and declare `30s/5s/60s/3` Docker health policy.
- [x] Update the generated datapath Dockerfiles so packaged and smoke images keep the same contract.
- [x] Make container smoke wait for Docker `healthy`, and emit health diagnostics on timeout.
- [x] Verify all changed shell scripts with `bash -n` and the contract test.

### Task 3: Enforce health in RC install/check and document operator semantics

**Files:**
- Modify: `deploy/kolla/package/install_aria_datapath_rc_image.sh`
- Modify: `deploy/kolla/package/install_neutron_aria_agent_rc_image.sh`
- Modify: `deploy/kolla/aria-datapath/README.md`
- Modify: `deploy/kolla/neutron-aria-agent/README.md`
- Modify: `.github/workflows/build.yml`

- [x] Reject candidate images that do not declare a Docker healthcheck.
- [x] Require the running candidate to reach Docker `healthy` during install and `check`.
- [x] Keep rollback compatible with older images that may not contain health metadata.
- [x] Document that `degraded`, `bypass`, recovery, and blocked states are unhealthy but do not imply OVS failure or trigger remediation.
- [x] Add the health contract test to GitHub Actions and run the available local Python/shell gates.
- [x] Review the scoped diff, commit only healthcheck files, and leave unrelated working-tree changes untouched.
