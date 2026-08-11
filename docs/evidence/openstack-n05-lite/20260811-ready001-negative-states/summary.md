# RISK-READY-001 Negative-State Field Evidence

Date: 2026-08-11

Status: passed. Together with the two-available-compute composite baseline,
this closes `RISK-READY-001`.

## Scope And Safety

- Exercised the maintained target kernel on one available test compute.
- Used a disposable datapath container with private UDS, state, pin, log, and
  listener identities; no production managed port entered a fault state.
- Kept the production peercred-enforced socket and configuration unchanged.
- Did not restart or modify OVS, the OVS agent, Nova, Neutron server, the
  production Python agent, or the production datapath.
- Removed the disposable containers, UDS directory, state directory, and pin
  namespace after each run.

## Endpoint Contract

The public read-only probe checks both `GET /api/v1/neutron/status` and
`GET /readyz`. It requires an exact transaction state, overall readiness, and
required action; Status V1 must return HTTP 200, `/readyz` must return HTTP 200
only for exact ready and HTTP 503 otherwise, and both response bodies must be
identical.

| Scenario | Observed Status V1 | HTTP result | Result |
| --- | --- | --- | --- |
| Committed baseline | `classified / ready / none` | status 200, readyz 200, equal bodies | pass |
| WAL intent applying | `pending / unknown / poll` | status 200, readyz 503, equal bodies | pass |
| Commit fault retained for recovery | `blocked / blocked / recover_pending` | status 200, readyz 503, equal bodies | pass |
| Rollback to last applied | `recovery / degraded / full_resync` | status 200, readyz 503, equal bodies | pass |

The pending case retained accepted/applied generation 1 with pending generation
2, then converged to accepted/applied generation 2. The blocked case retained
the committed generation 1 and pending generation 2. The official
`recover-pending` rollback cleared the pending generation and deliberately
projected recovery/degraded until a later full resync.

## Forwarding And Cleanup

- A continuous VM ICMP canary transmitted 202 packets and received all 202.
- Production datapath container/process identity was unchanged before and
  after the isolated run.
- OVS process identity was unchanged.
- No disposable container, UDS directory, state directory, or pin namespace
  remained after cleanup.
- The final production probe remained `classified / ready / none`, with status
  HTTP 200, readyz HTTP 200, equal response bodies, and zero generation lag.

## Acceptance Decision

`RISK-READY-001` is fixed for the v0.9 readiness contract. Readiness remains an
observation and admission signal only. A non-ready result must not trigger an
automatic OVS, OVS-agent, or datapath restart.
