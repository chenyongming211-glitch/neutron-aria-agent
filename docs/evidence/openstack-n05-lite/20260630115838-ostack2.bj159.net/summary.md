# Rollback Connectivity Smoke Evidence

Host: `ostack2.bj159.net`

VM IP: `10.58.159.26`

Port: `86b83885-671f-474c-9556-8af98cf1cdc8` / `tap86b83885-67`

Generated at: `2026-06-30T03:59:02Z`

This smoke verifies rollback connectivity only. It does not enable
QoS, Mirror, or RabbitMQ event consumption.

| Fact | Expected | Command | Actual | Evidence | Disposition |
| --- | --- | --- | --- | --- | --- |
| Baseline VM connectivity | VM is reachable before rollback smoke | `ping_vm` | exit=0 | `baseline-ping.txt` | pass |
| Initial datapath status | UDS status is readable and has no managed ports before rollback drill | `status_no_managed_ports` | exit=0 | `initial-status.txt` | pass |
| ACL rollback drill | ACL blocks test traffic, UDS rollback deletes managed port, and ping recovers | `acl_rollback_drill` | exit=0 | `acl-rollback-drill.log` | pass |
| Post-rollback datapath status | UDS status has no managed ports after rollback drill | `status_no_managed_ports` | exit=0 | `post-rollback-status.txt` | pass |
| Post-rollback VM connectivity | VM remains reachable after rollback drill | `ping_vm` | exit=0 | `post-rollback-ping.txt` | pass |
| neutron-aria-agent stop connectivity | Stopping neutron-aria-agent does not break baseline OVS connectivity, and restart recovers the service | `agent_stop_connectivity` | exit=0 | `agent-stop-connectivity.log` | pass |
| aria-datapath stop connectivity | Stopping aria-datapath does not break baseline OVS connectivity, and restart recovers UDS/status | `datapath_stop_connectivity` | exit=0 | `datapath-stop-connectivity.log` | pass |

## Result

- pass: 7
- fail: 0
