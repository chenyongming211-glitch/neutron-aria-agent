# Heartbeat V2 Control-Plane Fault Acceptance

## Scope

This acceptance uses the three-compute Heartbeat V2 Kolla candidate. It tests
control-plane availability and datapath continuity without restarting OVS, the
Neutron OVS agent, or the Aria datapath.

## Neutron Server Single-Node Fault

A Neutron Server container on one of the two active API/controller nodes was
stopped and then restored through a rollback-protected test harness.

| Check | Result |
| --- | --- |
| Neutron API calls while one server was stopped | pass, 8/8 |
| Existing VM forwarding canary | pass, 74/74 |
| Aria readiness during the fault | `ready` |
| Accepted versus applied generation | equal |
| Pending generation | none |
| Neutron Server recovery | pass, healthy after 28 seconds |
| OVS agent or Aria datapath restart | none |

An initial harness run was discarded because GNU `timeout` was incorrectly
asked to invoke a shell function, so no API request was made. The corrected
run invoked the client directly and produced the results above.

## RabbitMQ Preflight

The RabbitMQ application on one compute/controller node is currently not
running even though the two reachable cluster views still list the member.
The other two RabbitMQ nodes report no alarm or network partition.

Active RabbitMQ interruption is therefore deferred. Deliberately stopping one
of the remaining message nodes would reduce the test environment to a single
working broker and is not required to validate Heartbeat V2. Repair or
explicitly remove the inactive member before running the controlled RabbitMQ
outage test.

## Disposition

- Neutron Server single-node failure and recovery: `pass`.
- Existing ACL/OVS forwarding during that fault: `pass`.
- RabbitMQ active fault injection: `deferred_environment_precondition`.
