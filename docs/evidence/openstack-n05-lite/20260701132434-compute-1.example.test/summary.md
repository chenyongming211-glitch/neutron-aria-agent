# UDS Hardening Evidence

Host: `compute-1.example.test`

Generated at: `2026-07-01T05:24:35Z`

This smoke records the UDS hardening gate for stage-two ACL MVP.
It does not enable QoS, Mirror, RabbitMQ event consumption, or tenant features.

| Fact | Expected | Command | Actual | Evidence | Disposition |
| --- | --- | --- | --- | --- | --- |
| Container peer identities | Record uid/gid/group inputs for peercred allow-list | `collect_identity` | exit=0 | `peer-identities.txt` | pass |
| UDS directory and socket permissions | Record host and container view of /run/aria and socket permissions | `collect_permissions` | exit=0 | `socket-permissions.txt` | pass |
| World-writable socket check | Socket and parent directory have no other-user permission bits | `check_socket_not_world_writable` | exit=0 | `world-writable-check.txt` | pass |
| Peercred allow-list candidates | Record candidate uid/gid values before enabling enforcement | `collect_peercred_allow_list` | exit=0 | `peercred-allow-list.txt` | pass |
| Audit log path | Audit log path is known; required only when hardened mode is enforced | `collect_audit_log_path` | exit=0 | `audit-log.txt` | pass |
| Hardened enforcement gate | When REQUIRE_HARDENED=true, socket and audit requirements must pass | `check_hardened_required` | exit=0 | `hardened-required.txt` | pass |

## Result

- pass: 6
- non-pass: 0
- fail: 0
- require_hardened: true
