# Rollback Connectivity Smoke Evidence

Host: `compute-1.example.test`

VM IP: `192.0.2.26`

Port: `86b83885-671f-474c-9556-8af98cf1cdc8` / `tap86b83885-67`

Generated at: `2026-06-30T04:10:37Z`

This smoke verifies rollback connectivity only. It does not enable
QoS, Mirror, or RabbitMQ event consumption.

| Fact | Expected | Command | Actual | Evidence | Disposition |
| --- | --- | --- | --- | --- | --- |
| Baseline VM connectivity | VM is reachable before rollback smoke | `ping_vm` | exit=0 | `baseline-ping.txt` | pass |
| Initial datapath status | UDS status is readable and has no managed ports before rollback drill | `status_no_managed_ports` | exit=0 | `initial-status.txt` | pass |
| ACL rollback drill | ACL blocks test traffic, UDS rollback deletes managed port, and ping recovers | `acl_rollback_drill` | exit=1 | `acl-rollback-drill.log` | fail |
| Post-rollback datapath status | UDS status has no managed ports after rollback drill | `status_no_managed_ports` | exit=0 | `post-rollback-status.txt` | pass |
| Post-rollback VM connectivity | VM remains reachable after rollback drill | `ping_vm` | exit=0 | `post-rollback-ping.txt` | pass |

## Result

- pass: 4
- fail: 1
