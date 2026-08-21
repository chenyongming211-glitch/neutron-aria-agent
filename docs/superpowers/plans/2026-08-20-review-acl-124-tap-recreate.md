# REVIEW-ACL-124 Tap Recreate Recovery Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Eliminate false `ready/enforce` during tap recreation and promptly reapply the exact last successful port snapshot to a replacement ifindex.

**Architecture:** TapRegistry publishes ordered link lifecycle events and preserves Neutron authority across physical link loss. NeutronApiState invalidates status on deletion and conditionally replays an in-memory last-applied port snapshot through the existing SinglePort transaction pipeline on replacement.

**Tech Stack:** Rust, Tokio broadcast channels, Axum Neutron UDS state, existing Neutron WAL and scoped snapshot transaction pipeline.

## Global Constraints

- Never restart, stop, or modify OVS or `neutron-openvswitch-agent`.
- During an unverified replacement window report `degraded/bypass`, never `ready/enforce`.
- The replay cache is process-local and non-persistent.
- Do not add a UDS schema, configuration switch, or persisted authority.
- Do not enable `incremental_rpc_enabled`.
- Rust/eBPF compilation and tests run through GitHub Actions only.

---

### Task 1: Ordered Tap Lifecycle Events

**Files:**
- Modify: `agent/src/tap_registry.rs`
- Modify: `agent/src/netlink.rs`
- Modify: `agent/src/control_plane.rs`

**Interfaces:**
- Produces: `TapLifecycleEvent::{Deleted, Ready}` and `TapRegistry::subscribe_lifecycle()`.
- Produces: authority-preserving link-loss detach distinct from explicit Neutron detach.

- [x] **Step 1: Write failing unit tests** for event ordering, old/new ifindex payloads, preserved Neutron authority, and standalone behavior without authority.
- [x] **Step 2: Commit the RED tests** and trigger GitHub Actions; expect compile/test failure because lifecycle interfaces do not exist.
- [x] **Step 3: Add the bounded broadcast channel and lifecycle event types.**
- [x] **Step 4: Split physical link loss from explicit detach** so only explicit detach clears Neutron authority.
- [x] **Step 5: Make replacement attach authority-aware** and publish `Ready` only after quiesced attach succeeds.
- [x] **Step 6: Route netlink handlers through the lifecycle methods** and retain the 60-second scan as a loss-recovery safety net.
- [x] **Step 7: Run GitHub Actions** and require all TapRegistry/netlink tests to pass.

### Task 2: Immediate Neutron Status Invalidation

**Files:**
- Modify: `agent/src/neutron_api.rs`

**Interfaces:**
- Consumes: `TapLifecycleEvent::Deleted { ifname, ifindex }`.
- Produces: `project_tap_attachment_identity_loss(...) -> bool`.

- [x] **Step 1: Write failing pure tests** proving a matching delete changes only the target port to `degraded/bypass`, removes its ACL domain hash, retains its old ifindex, and sets `runtime_reconcile_requires_full_resync`.
- [x] **Step 2: Add tests** for stale old-ifindex events, unrelated ports, pending generation, and stronger recovery states.
- [x] **Step 3: Commit the RED tests** and trigger GitHub Actions.
- [x] **Step 4: Implement the pure projection** with reason `tap_attachment_identity_lost`.
- [x] **Step 5: Add the lifecycle consumer task** under the existing apply lock and append a snapshot commit to the Neutron WAL.
- [x] **Step 6: Publish invalidated RAM state even when WAL append fails**, while recording the durability failure authority.
- [x] **Step 7: Run GitHub Actions** and require status/transaction tests to pass.

### Task 3: Safe In-Process Scoped Replay

**Files:**
- Modify: `agent/src/neutron_api.rs`

**Interfaces:**
- Consumes: `TapLifecycleEvent::Ready { ifname, ifindex }`.
- Produces: process-local applied port snapshot cache and `replay_recreated_port(...)`.

- [x] **Step 1: Write failing tests** for full-host cache replacement, scoped cache update, and delete eviction.
- [x] **Step 2: Write failing replay tests** for exact generation/hash success and rejection on cache miss, pending generation, identity mismatch, stale event, or unchanged ifindex.
- [x] **Step 3: Commit the RED tests** and trigger GitHub Actions.
- [x] **Step 4: Add the non-persistent cache** to `NeutronApiState` and update it only after a successful durable snapshot commit.
- [x] **Step 5: Build a one-port snapshot from the exact cache entry**, replace only its ifindex, and pass it through existing SinglePort admission/apply/commit code.
- [x] **Step 6: Keep all unsafe cases degraded** and log a bounded fallback reason without retry loops.
- [x] **Step 7: Run GitHub Actions** and require scoped planner, transaction, WAL, and behavior tests to pass.

### Task 4: Regression Evidence and Documentation

**Files:**
- Modify: `docs/openstack-neutron-aria-details/12-review-bug-backlog.md`
- Create: `deploy/kolla/smoke/neutron_aria_tap_recreate_identity_smoke.sh`
- Create: `docs/evidence/openstack-n05-lite/<date>-review-acl-124/summary.md`

**Interfaces:**
- Consumes: the exact GitHub Actions `aria-agent` and eBPF artifact hashes.
- Produces: deterministic field evidence bound to the candidate commit and artifact hashes.

- [x] **Step 1: Add a static smoke contract check** requiring old/new ifindex, status timeline, TC ingress/egress identities, ACL probe, generation/hash, and OVS canary evidence.
- [x] **Step 2: Implement the smoke script** with cleanup traps and no OVS mutation commands.
- [x] **Step 3: Build the exact candidate in GitHub Actions** and record workflow, commit, and SHA-256 values.
- [x] **Step 4: Deploy only Aria candidate artifacts** to the test compute nodes; do not restart OVS/ovs-agent.
- [x] **Step 5: Run at least three tap recreation cycles** and require no false-ready sample plus zero OVS canary loss.
- [x] **Step 6: Record evidence and close REVIEW-ACL-124** only after the field gate passes.
