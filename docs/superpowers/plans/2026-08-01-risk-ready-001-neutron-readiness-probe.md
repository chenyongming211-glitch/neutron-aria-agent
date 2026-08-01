# RISK-READY-001 Neutron Readiness Probe Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use
> superpowers:executing-plans to implement this plan task-by-task. Steps use
> checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a strict Neutron datapath readiness probe without changing TCP
liveness or duplicating the Status V1 state machine.

**Architecture:** The existing Neutron UDS router gains `GET /readyz`. Both
`/readyz` and `/api/v1/neutron/status` build the same full
`NeutronStatusV1Response` from the same `NeutronApiState`. Status inspection
always returns HTTP 200; readiness returns HTTP 200 only for exact `ready` and
HTTP 503 for `unknown`, `degraded`, or `blocked`.

**Tech Stack:** Rust, Axum, Tokio, shared `aria-api` Status V1 DTOs, Python CI
lane inventory, Markdown.

## Global Constraints

- Work only on local and remote `v0.9-neutron-agent`; do not create a branch,
  PR, or worktree.
- Do not run Cargo locally. GitHub Actions supplies all Rust RED/GREEN and
  warning-denied build evidence.
- Preserve `GET /api/v1/health` as TCP liveness and preserve the existing HTTP
  200 behavior of `GET /api/v1/neutron/status`.
- Keep `/readyz` UDS-only; do not expose Neutron status or mutation routes over
  the unauthenticated TCP management listener.
- Do not introduce a readiness flag, persisted field, WAL record, background
  task, new Status V1 schema, or Python parser for Rust source.
- Do not wire Kolla/systemd/Docker health checks or claim Neutron RPC heartbeat
  and privileged field evidence in this batch.

---

### Task 1: Establish the RED readiness behavior

**Files:**
- Modify: `agent/src/neutron_api.rs`
- Modify: `ci/check_neutron_stage1.py`

**Interfaces:**
- Consumes: existing `NeutronRuntimeState`, shared scenario fixtures, and
  `NeutronStatusV1Response`.
- Produces: intentionally missing `get_neutron_readiness` handler and hosted
  test prefix `neutron_readiness_`.

- [ ] **Step 1: Add a response helper for test assertions**

Reuse the existing `test_neutron_state`, runtime seeds, and response-body
decoder. Do not create pinned maps or require privileges.

- [ ] **Step 2: Add strict readiness tests**

Add tests with the stable `neutron_readiness_` prefix that prove:

1. the `full-classified-ready` Status V1 fixture returns HTTP 200;
2. cold-start/idle `unknown` returns HTTP 503;
3. `pending-poll` returns HTTP 503;
4. `classified-degraded-terminal` returns HTTP 503;
5. `blocked-operator` and recoverable blocked states return HTTP 503;
6. the readiness and status handlers return equal Status V1 JSON bodies for
   the same runtime while the status handler remains HTTP 200;
7. only the Neutron UDS router registers `/readyz`.

The RED tests may call the intended handler directly. They must fail to compile
or fail behaviorally only because the readiness handler/route is absent.

- [ ] **Step 3: Add one hosted Rust behavior filter**

Add this Cargo-discovered filter to `ci/check_neutron_stage1.py::RUST_TESTS`:

```python
["test", "--locked", "-p", "aria-agent", "neutron_readiness_"],
```

Keep the existing zero-test guard. Add `("GET", "/readyz", ...)` to the UDS
route inventory only after the production route exists in GREEN, so the RED
failure remains the missing behavior rather than a static source marker.

- [ ] **Step 4: Run local non-Cargo verification**

```bash
git diff --check
python3 -m unittest ci.test_ci_lane_contract ci.test_ci001_trusted_gates
python3 ci/check_neutron_stage1.py --fast-contracts
```

- [ ] **Step 5: Commit, push, and capture exact RED**

Commit only the Rust tests and hosted filter. The exact-head `rust-behavior`
lane must fail on the intentionally absent readiness boundary while fast
contracts remain green. Cancel remaining expensive jobs only after the RED
cause is captured.

---

### Task 2: Implement the same-source UDS readiness route

**Files:**
- Modify: `agent/src/neutron_api.rs`
- Modify: `ci/check_neutron_stage1.py`

**Interfaces:**
- Consumes: `project_neutron_status_v1`, `NeutronApiState`, and
  `NeutronStatusV1Response`.
- Produces: shared status response construction and UDS `GET /readyz`.

- [ ] **Step 1: Extract shared Status V1 response construction**

Move the current `get_neutron_status` body into one asynchronous read-only
function receiving `&NeutronApiState` and returning
`NeutronStatusV1Response`. Preserve field values, lock lifetime, registry
lookup, schema version, and contract hash exactly.

- [ ] **Step 2: Keep status inspection behavior unchanged**

`get_neutron_status` calls the shared constructor and returns `Json(response)`.
Non-ready states must continue to return HTTP 200.

- [ ] **Step 3: Add the readiness handler**

`get_neutron_readiness` calls the same constructor. It selects:

```rust
let status = if response.overall_readiness
    == NeutronStatusOverallReadiness::Ready
{
    StatusCode::OK
} else {
    StatusCode::SERVICE_UNAVAILABLE
};
```

Return `(status, Json(response))`. Do not add another classification rule.

- [ ] **Step 4: Register only the UDS route**

Add `.route("/readyz", get(get_neutron_readiness))` to
`neutron_api::build_router`. Add the structural route to `PUBLIC_UDS_ROUTES`.
Do not modify `api_routes.rs` or TCP OpenAPI paths.

- [ ] **Step 5: Run local non-Cargo verification**

Run `git diff --check` and the fast Python contracts. Do not invoke Cargo.

- [ ] **Step 6: Commit, push, and require exact-head GREEN**

The implementation-head Build must execute all `neutron_readiness_` tests and
pass selected Rust behavior plus warning-denied userspace/eBPF/static builds.
If CI fails for an independent reason, diagnose it separately rather than
weakening the readiness contract.

---

### Task 3: Document the operational boundary and evidence

**Files:**
- Modify: `docs/openstack-neutron-agent-mode.md`
- Modify: `docs/openstack-deployment-runbook.md`
- Modify:
  `docs/superpowers/specs/2026-08-01-risk-ready-001-neutron-readiness-probe-design.md`
- Modify:
  `docs/superpowers/plans/2026-08-01-risk-ready-001-neutron-readiness-probe.md`
- Modify:
  `docs/openstack-neutron-aria-details/12-review-bug-backlog.md`

- [ ] **Step 1: Add maintained operator documentation**

Document the three distinct surfaces and a UDS `curl --fail` example:

- TCP `/api/v1/health`: liveness;
- UDS `/api/v1/neutron/status`: status inspection, HTTP 200 when readable;
- UDS `/readyz`: exact-ready probe, otherwise HTTP 503.

State that 503 means Aria enhancement is not ready, not that OVS forwarding is
down.

- [ ] **Step 2: Record exact RED/GREEN evidence**

Add commit SHAs, Build URLs, executed test count, and warning-denied build
results to the design and plan.

- [ ] **Step 3: Preserve the deferred boundary in the backlog**

Update `RISK-READY-001` to:

```text
source implementation and hosted CI complete; deployment/field wiring deferred
```

Do not mark it fixed. Explicitly retain pending Neutron heartbeat composition,
target-environment probe wiring, recovery timing, and rollback evidence.

- [ ] **Step 4: Run final non-Cargo checks, commit, push, and verify docs CI**

Require a clean worktree, local/remote divergence `0 0`, remote SHA equality,
and a successful exact-head docs Build before reporting completion of the
source/hosted phase.
