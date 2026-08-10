# RISK-READY-001 Composite Readiness Field Validation

Date: 2026-08-10

Status: target wiring, heartbeat composition, normal recovery, and rollback
evidence complete on the two available test computes. Negative
`pending/degraded/blocked` field injection remains deferred.

## Scope And Safety

- Used only the two available test computes; the unavailable compute was not
  accessed.
- Installed a read-only composite smoke script on both available hosts.
- Restarted only `neutron_aria_agent` and, in a separate recovery test,
  `aria_datapath` on one test compute.
- Did not restart or modify OVS or `neutron-openvswitch-agent`.
- Kept a continuous VM ICMP canary running from the other available compute.
- Did not compile Rust or eBPF locally and did not change datapath code.

## Composite Contract

The operational result is ready only when:

1. UDS Status V1 reports exact `overall_readiness=ready`, `/readyz` returns
   HTTP 200, and its response body equals `/api/v1/neutron/status`; and
2. Neutron reports the matching `Aria ACL agent` heartbeat alive under the
   configured `agent_down_time` policy.

The smoke is an observation/admission gate. It does not restart services and
must not be used to restart OVS, `neutron-openvswitch-agent`, or the datapath.

## Evidence

| Check | Result |
| --- | --- |
| Available-node baseline | Both nodes returned status HTTP 200 and readiness HTTP 200 with equal Status V1 bodies, zero generation lag, live heartbeat rows, and `composite_ready=true`. |
| Heartbeat timeout policy | Neutron server configuration uses `agent_down_time = 75`. The observed dead transition occurred within that policy window relative to the last heartbeat. |
| Python-agent outage | With `neutron_aria_agent` stopped, the independent datapath UDS probe stayed exact-ready. After Neutron marked the heartbeat down, the smoke returned nonzero with `heartbeat_alive=false`, `uds_overall_readiness=ready`, and `composite_ready=false`. |
| Python-agent recovery | Restarting `neutron_aria_agent` restored strict composite readiness in approximately five seconds. |
| Datapath cold restart | With the Python agent stopped, restarting only `aria_datapath` restored persisted generation state by the first readable probe, approximately four seconds after restart. |
| Full recovery | Restarting the Python agent after the datapath test restored strict composite readiness in approximately four seconds. |
| Forwarding canary, heartbeat test | 267 packets transmitted, 267 received, zero packet loss. |
| Forwarding canary, datapath test | 43 packets transmitted, 43 received, zero packet loss. |
| Local contracts | `python ci/check_neutron_stage1.py --fast-contracts` passed 584 Python tests with 8 environment-dependent skips, 10 CLI tests, package/install contracts, and syntax checks for every public smoke entrypoint including the new composite probe. |

## Remaining Boundary

The exact-head Rust behavior suite proves that cold-start/pending `unknown`,
terminal `degraded`, and recovery/operator `blocked` return HTTP 503 while the
inspection endpoint remains HTTP 200 with the same Status V1 body. Deliberate
field injection of those states was not performed because it would mutate the
active ACL transaction state without adding a new source-contract result.
