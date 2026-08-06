# ACL Bulk Event Coalescing Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Collapse bulk ACL writes and sustained RPC bursts into one committed notification and one quiet-window full-resync.

**Architecture:** The Neutron service plugin owns transaction-level bulk notification. The existing thread-safe `EventMerger` owns trailing-edge debounce, while the synchronous agent loop continues to enforce one full-resync at a time.

**Tech Stack:** Python 2-compatible service plugin code, SQLAlchemy session transactions, oslo messaging, unittest.

## Global Constraints

- Preserve the pre-`neutron-lib` plugin contract.
- Keep `incremental_rpc_enabled` behavior unchanged.
- Do not modify or restart OVS, the OVS agent, or the Rust datapath.
- Use GitHub CI for any repository build gate; no local Rust build is required.
- Keep the implementation limited to transaction notification and event coalescing.

---

### Task 1: Trailing-Edge Event Merge

**Files:**
- Modify: `openstack/neutron_aria/neutron_aria/agent/event_merge.py`
- Modify: `openstack/neutron_aria/neutron_aria/agent/service.py`
- Test: `openstack/neutron_aria/neutron_aria/tests/unit/test_event_merge.py`
- Test: `openstack/neutron_aria/neutron_aria/tests/unit/test_service.py`

**Interfaces:**
- Consumes: `EventMerger.record_*()`, `EventMerger.ready(interval)`.
- Produces: `EventMerger.last_pending_at()` and a deadline based on the latest event.

- [ ] Add a failing unit test showing that a second event postpones readiness.
- [ ] Run the focused test and verify it fails because readiness still uses the first event.
- [ ] Track and reset `_last_pending_at`, update it for every accepted event, and use it for readiness and service deadlines.
- [ ] Run event merger and service unit tests and verify the burst drains once after the quiet window.

### Task 2: Transaction-Level Native Bulk Notification

**Files:**
- Modify: `openstack/neutron_aria/neutron_aria/services/aria_acl/plugin.py`
- Test: `openstack/neutron_aria/neutron_aria/tests/unit/test_aria_acl_plugin.py`

**Interfaces:**
- Consumes: old Neutron `create_<resource>_bulk(context, <collection>=body)` dispatch and repository singular create methods.
- Produces: native bulk entry points and one `bulk_create` ACL event with `resource_count`.

- [ ] Add failing tests for native bulk capability, one notification on success, and no notification on rollback.
- [ ] Run the focused tests and verify failures are caused by missing native bulk methods.
- [ ] Add Python 2-compatible bulk entry points, one outer DB transaction, singular notification suppression, and one post-commit notification.
- [ ] Run plugin and DB contract tests and preserve existing singular notifications.

### Task 3: CI And Field Verification

**Files:**
- Update after measurement: `docs/openstack-neutron-aria-details/13-acl-delivery-performance-optimization.md`
- Update after measurement: `.artifacts/acl-scale-20260806/REPORT.md`

**Interfaces:**
- Consumes: packaged `neutron_aria` server and agent artifacts.
- Produces: before/after benchmark evidence using the existing workload.

- [ ] Run all relevant Python unit and contract tests plus sensitive-term checks.
- [ ] Commit and push the change, then require GitHub CI to pass.
- [ ] Package and deploy the updated Neutron server and agent components to all three test nodes without restarting OVS components.
- [ ] Repeat 100/500/1000-rule tests and record API time, event batches, full-resyncs, convergence, traffic, resources, and cleanup.
- [ ] Restore the test port to bypass state and verify service health.
- [ ] Add measured results to the performance record and commit the evidence summary.

