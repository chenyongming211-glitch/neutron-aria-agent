# RISK-READY-001 Neutron Readiness Probe Design

**Status:** source implementation and hosted CI complete at `9060a77` / Build
[30707571086](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/30707571086).
Deployment health-check wiring, Neutron RPC heartbeat composition, and
privileged field evidence remain deferred until a target OpenStack environment
is available. The risk therefore remains open rather than fixed.

## Problem

The TCP management endpoint `GET /api/v1/health` is a liveness endpoint. It
always returns HTTP 200 with `status=ok` while the process can answer requests.
Its WAL counter belongs to the standalone control plane; it does not describe
Neutron snapshot authority, generation convergence, recovery state, or
per-domain ACL readiness.

The Neutron UDS endpoint `GET /api/v1/neutron/status` already owns the complete
versioned status contract. Its projection classifies the runtime as `ready`,
`unknown`, `degraded`, or `blocked` from the same state used by snapshot apply,
WAL recovery, generation tracking, and periodic TC/ACL health projection.
However, every valid status response currently returns HTTP 200. A generic
process or container health check can therefore confuse "status was readable"
with "the Neutron-managed datapath is ready".

This is an operational guard gap, not evidence that the current deployment is
already using the wrong probe. No maintained deployment file wires
`/api/v1/health` as Neutron readiness today.

## Decision

Keep `/api/v1/health` unchanged as TCP liveness. Add one strict, read-only
`GET /readyz` route to the existing Neutron UDS router.

`/readyz` uses the exact same `NeutronApiState`, Status V1 projection, and full
`NeutronStatusV1Response` body as `GET /api/v1/neutron/status`:

- `overall_readiness=ready` returns HTTP 200;
- `overall_readiness=unknown`, `degraded`, or `blocked` returns HTTP 503;
- the body remains the complete Status V1 document in both cases so an
  operator can see transaction state, required action, generations, recovery
  cause, WAL state, and per-port/per-domain evidence.

Only exact `ready` is probe success. In particular, availability-first
`degraded + effective_action=bypass` remains live but is not Aria-ready.

The new route is UDS-only. It is not added to the unauthenticated TCP router or
TCP OpenAPI document, and it does not expose any Neutron mutation endpoint.

## Alternatives Considered

### Change `/api/v1/health` to return failure

Rejected. It would collapse process liveness and Neutron feature readiness,
break standalone semantics, and could restart a healthy process during a
recoverable Neutron convergence or control-plane outage.

### Maintain a second readiness flag in the TCP router

Rejected. Snapshot, delete, recovery, WAL replay, and periodic TC health paths
would all need to update the duplicate flag. Missing one transition could
report stale success. Sharing the Status V1 state is smaller and preserves one
source of truth.

### Add a packaged Python probe that reinterprets Status V1

This remains a possible deployment wrapper, but it must not redefine the
state/readiness/action matrix. The server-side UDS status code supplies a
language-neutral primitive that shell, Kolla, systemd, or a future Python
wrapper can consume without duplicating product semantics.

## Authoritative State and Projection

Extract the current status response construction from
`get_neutron_status()` into one internal read-only operation that:

1. acquires `NeutronApiState.runtime` for reading;
2. calls the existing `project_neutron_status_v1()` exactly once;
3. copies the current accepted/applied/pending generations, hashes, authority,
   WAL state, managed ports, and projected per-port evidence;
4. releases the runtime read guard;
5. obtains active instance names from the registry;
6. returns one `NeutronStatusV1Response`.

Both `/api/v1/neutron/status` and `/readyz` call this operation. The readiness
handler derives only the HTTP status from `response.overall_readiness`; it does
not independently inspect private fields or reconstruct the Status V1 matrix.

No new persisted state, background task, atomic flag, ABI field, or WAL record
is introduced.

## Readiness Semantics

The existing Status V1 projector remains authoritative:

- cold start before the first classified snapshot is `unknown/full_resync` and
  therefore HTTP 503;
- an in-flight accepted generation is `unknown/poll` and HTTP 503;
- an incomplete or recovery-required transaction is `blocked` and HTTP 503;
- a terminal unsupported/degraded enhancement is `degraded`, even when OVS
  forwarding continues through `bypass`, and is HTTP 503;
- a fully classified generation with complete ready evidence is `ready/none`
  and HTTP 200;
- loss detected by periodic TC/ACL health projection lowers Status V1 before
  the next probe and therefore changes the probe to HTTP 503.

Generation convergence, domain state, `effective_action`, support disposition,
and recovery classification are not redefined in this batch. Their single
source of truth remains the Status V1 projection and scenario matrix.

The UDS request itself proves only that `aria-agent` can currently serve the
local probe. It does not prove that the separate Python `neutron-aria-agent`
has successfully reported its last RPC heartbeat to Neutron server. That
end-to-end heartbeat is an independent deployment signal and must be combined
by the eventual target-environment health policy rather than guessed inside
the Rust process.

## Route and Compatibility Boundary

Add `GET /readyz` only to `agent/src/neutron_api.rs::build_router`. Keep:

- `GET /api/v1/health` unchanged and always usable for liveness;
- `GET /api/v1/neutron/status` unchanged at HTTP 200 for status inspection;
- all Neutron write routes UDS-only;
- the standalone mode unchanged: when the Neutron UDS is disabled, no Neutron
  readiness route is served;
- the Status V1 schema version and contract hash unchanged because the response
  body is not changed.

The route inventory contract in `ci/check_neutron_stage1.py` is updated to
include `GET /readyz` as a public UDS route. It must not appear in TCP OpenAPI
paths.

## Deployment Boundary

This batch documents a stable manual/exec probe:

```bash
curl --fail --silent --show-error \
  --unix-socket /run/aria/aria-neutron.sock \
  http://localhost/readyz
```

It does not wire Kolla, systemd, Docker, or another orchestrator to restart,
remove, or re-admit the process. That policy needs target-environment evidence
for startup timing, recovery duration, heartbeat ownership, and the desired
relationship between Aria enhancement readiness and OVS traffic availability.

Until that evidence exists:

- manual and CI tests may consume `/readyz`;
- deployment wiring remains `deferred/pending`, never `PASS`;
- `/health` remains the process liveness check;
- a 503 from `/readyz` must not be described as OVS forwarding failure.

## RED Behavior Coverage

Rust behavior tests target the router/handler boundary and the existing public
Status V1 vocabulary:

1. a fully classified ready runtime returns HTTP 200;
2. idle/cold-start `unknown` returns HTTP 503;
3. an accepted pending generation returns HTTP 503;
4. terminal degraded domain evidence returns HTTP 503;
5. blocked recovery/operator state returns HTTP 503;
6. the readiness body is a valid full Status V1 response and exposes the same
   classification and generations as `/api/v1/neutron/status`;
7. `/api/v1/neutron/status` continues to return HTTP 200 for non-ready states;
8. the TCP router keeps `/api/v1/health` and does not gain `/readyz` or any
   Neutron route.

Use a stable Cargo-discovered prefix such as `neutron_readiness_` in the
existing hosted `rust-behavior` lane. Do not add a Python Rust parser or check
private helper names/source order.

Local verification remains non-Cargo only. GitHub Actions supplies RED/GREEN
Rust behavior evidence and warning-denied userspace/eBPF/static builds.

## Documentation and Status Closure

After GREEN, update the maintained Neutron agent-mode/runbook documentation to
distinguish:

- TCP `/api/v1/health`: process liveness;
- UDS `/api/v1/neutron/status`: inspectable Status V1 state, always HTTP 200
  when readable;
- UDS `/readyz`: strict Aria Neutron datapath readiness, HTTP 200 only for
  exact `ready`.

`RISK-READY-001` must not be marked fully fixed merely because hosted tests are
green. Before deployment health-check wiring and production closure, a target
environment must prove the composite policy, including the separate Neutron
agent heartbeat signal and the intended behavior during pending, degraded,
blocked, and recovery states. Until then the accurate state is:

```text
source implementation and hosted CI complete; deployment/field wiring deferred
```

## Execution Evidence

- RED `7447e4e` added two Rust behavior tests using the existing Status V1
  scenario fixtures. Build
  [30707303054](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/30707303054)
  failed at the intentionally absent `get_neutron_readiness` handler; fast,
  database, and clean-install contracts passed. Remaining expensive build work
  was cancelled after the exact RED cause was captured.
- GREEN `9060a77` extracted one shared response constructor, registered the
  UDS-only route, derived only the HTTP status from `overall_readiness`, and
  synchronized the public UDS contract plus thin Python client method. Exact
  Build
  [30707571086](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/30707571086)
  ran both `neutron_readiness_` tests successfully. The full selected Rust
  behavior lane passed in 2m56s and the warning-denied eBPF/userspace/static
  build passed in 5m20s.
- Local non-Cargo verification passed 557 Python tests with 8 skips, 10 CLI
  tests, shell syntax, installer, route-contract, and CI lane checks.
- No Kolla/systemd/Docker readiness wiring, Neutron server heartbeat result,
  recovery timing, OVS availability decision, or privileged field PASS is
  inferred from hosted evidence.

## Closure Criteria

The source/hosted phase is complete when:

- `/health` liveness semantics are unchanged;
- UDS `/readyz` and status inspection share one response projection;
- only exact `ready` returns HTTP 200;
- negative pending/degraded/blocked behavior is proven by Rust tests;
- UDS/TCP route separation is covered;
- exact-head hosted behavior and warning-denied builds pass;
- documentation and backlog retain the deferred deployment/heartbeat boundary.

Full risk closure additionally requires target-environment probe wiring,
Neutron heartbeat composition, recovery timing evidence, and rollback
instructions. The later field-validation result is recorded below.

## Target-Environment Validation

On 2026-08-10 the maintained composite smoke was deployed read-only to the two
available test computes. Both hosts proved that `/readyz` returned HTTP 200,
its body exactly matched `/api/v1/neutron/status`, accepted and applied
generations matched, the heartbeat row was alive, and the combined result was
ready.

A controlled test on one compute then stopped only `neutron_aria_agent` while
probing the UDS socket independently from the running datapath container. The
datapath remained exact-ready, Neutron marked the heartbeat down after its
configured timeout window, and the composite smoke correctly changed from
ready to not-ready. Restarting the Python agent restored the combined result
in approximately five seconds. A continuous test-VM canary delivered all 267
packets with zero loss.

A second controlled test stopped the Python agent and restarted only
`aria_datapath`. Persisted transaction state restored exact readiness by the
first readable probe, approximately four seconds after restart. Restarting the
Python agent restored the strict composite result in approximately four more
seconds. The accompanying canary delivered all 43 packets with zero loss.
Neither test restarted or modified OVS or `neutron-openvswitch-agent`.

These results close target wiring, heartbeat composition, normal recovery,
and rollback evidence. Deliberate target-environment injection of
`pending/degraded/blocked` remains deferred because it would mutate the active
ACL transaction state; the HTTP 503 mapping for those states remains covered
by the exact-head Rust behavior tests.
