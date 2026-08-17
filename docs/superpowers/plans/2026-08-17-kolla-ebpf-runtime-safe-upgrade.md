# Kolla eBPF Runtime Safe Upgrade Implementation Plan

> **For Codex:** Execute with test-driven development. Keep unrelated working
> tree changes untouched and commit each completed task independently.

**Goal:** Make the existing Kolla datapath RC installer safely upgrade and
roll back when the eBPF hash/runtime schema changes, without touching OVS or
the Neutron OVS agent.

**Architecture:** Extend the existing shell installer with a hash-aware
lifecycle and an injectable library mode for executable orchestration tests.
Use the running Python agent image as a one-shot, same-UID UDS client after the
long-running writer is stopped. Preserve the existing fast path for identical
eBPF hashes.

**Tech Stack:** Bash, Docker/Kolla, Python 2.7 `LocalClient`, Python unittest.

---

### Task 1: Lock The Upgrade And Rollback Ordering With RED Tests

**Files:**
- Create: `ci/test_kolla_datapath_runtime_upgrade.py`
- Modify: `ci/test_release_governance.py`

1. Add a fake-command executable harness for the installer library mode.
2. Assert same-hash install skips writer quiesce and detach.
3. Assert changed-hash install orders writer stop, exact detach, zero barrier,
   datapath switch, writer start, full-resync convergence, and verification.
4. Assert detach failure prevents candidate start.
5. Assert candidate failure invokes hash-aware rollback.
6. Assert rollback failure retains pending state and leaves the writer stopped.
7. Assert neither install nor rollback contains an OVS/ovs-agent mutation.
8. Run the selected tests and record the expected RED failure.

### Task 2: Implement Hash-Aware Install And Recovery

**Files:**
- Modify: `deploy/kolla/package/install_aria_datapath_rc_image.sh`

1. Add library mode and small injectable lifecycle functions without changing
   the public `install|check|rollback` command set.
2. Capture active eBPF hash, Python image/UID/GID, and preflight identities.
3. Detect runtime migration from active versus candidate eBPF hash, with an
   explicit test-only/operator force switch.
4. Stop the Python writer and run a short-lived same-image/same-UID UDS helper
   that handshakes, deletes exact managed ports, retries boundedly, and requires
   zero managed ports.
5. Persist lifecycle phase and migration identity in the root-owned pending
   release state before every mutation boundary.
6. Start the candidate, resume the Python agent, and require readiness,
   generation convergence, Docker health, exact file hashes, and unchanged OVS
   identities.
7. On failure, perform the reverse hash-aware detach and restore. If recovery
   cannot converge, stop the Python writer and retain pending state.
8. Make `rollback` consume either committed or interrupted pending release
   state and use the same safety boundary.
9. Run shell syntax and the selected tests until GREEN.

### Task 3: Document Operator Behavior And Bundle Contract

**Files:**
- Modify: `docs/stage2-acl-release-governance.md`
- Modify: `deploy/kolla/aria-datapath/README.md`
- Modify: `ci/test_release_governance.py`

1. Document automatic same-hash fast path and changed-hash safe migration.
2. Document automatic rollback, retained pending state, and manual recovery
   boundary.
3. State explicitly that Python/datapath may restart but OVS/ovs-agent never
   do.
4. Keep the installer in the deterministic Kolla bundle.
5. Run release-governance and bundle tests.

### Task 4: Full Verification And Delivery

1. Run `bash -n` on changed shell files.
2. Run the new executable upgrade tests.
3. Run `python -m unittest ci.test_release_governance`.
4. Run the repository fast contract subset that does not compile Rust/eBPF.
5. Inspect the diff and public/sensitive-term checks.
6. Commit scoped changes and push `main`.
7. Build/deploy a new Kolla RC only after source tests are green. Rust/eBPF
   compilation remains GitHub CI-only if a new binary artifact is required.

