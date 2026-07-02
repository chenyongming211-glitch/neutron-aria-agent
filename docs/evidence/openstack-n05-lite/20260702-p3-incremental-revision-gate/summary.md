# P3 Incremental RPC Revision Gate

Date: 2026-07-02

Scope: controlled ostack2 test of P3 runtime incremental RPC after the Python
submitter and Rust port-scoped UDS route were implemented behind
`incremental_rpc_enabled=true`.

## What Passed

| Check | Result | Evidence |
| --- | --- | --- |
| Rust datapath capability | pass | `capability_hash=v0.9-neutron-capabilities-2`, `supports_port_scoped_snapshot=True` from the agent container. |
| Python package smoke | pass | Updated `neutron_aria_rpc_event_smoke.sh` passed in `neutron_aria_agent`. |
| Real RabbitMQ fanout | pass | Temporary enabled agent logged `event_batch_drained ... port_updates=1`. |
| Neutron port read | pass | Temporary agent listed 8 ports bound to `ostack2.bj159.net`. |
| Full-resync apply | pass | Temporary agents submitted generations 167 and 168 with `snapshot_ports=8`, `managed_ports=5`. |
| Rollback cleanup | pass | UDS delete cleanup returned `rollback_remaining_managed_ports=0` after each case. |

## Gate Not Accepted

P3 port-scoped runtime apply was not accepted on this environment because the
target Neutron returned no port revision:

```text
target_port_revision_enabled=none
ERROR: incremental enabled case cannot validate port-scoped apply:
target port has no revision_number
```

The agent correctly processed the RPC event and fell back to full-resync
instead of submitting a port-scoped snapshot without a trustworthy revision
comparison.

## Deployment Finding

Persistently enabling `[acl] source=neutron` in the running Kolla
`neutron_aria_agent` container also requires Neutron API credentials to be
injected into that long-running process. The temporary smoke sourced `adminrc`
and passed credentials into `docker exec`, but the persistent container did not
have `OS_AUTH_URL`, `OS_USERNAME`, `OS_PASSWORD`, or project/tenant variables.

Until that deployment path is added, keep the persistent agent on the packaged
safe default or P2-only canary mode.

## Final State

- `aria_datapath` on ostack2 was left running with the v2 port-scoped capable
  binary and existing peercred hardening.
- `neutron_aria_agent` was restored to heartbeat-only safe defaults:
  `full_resync_enabled=false`, `rpc_events_enabled=false`,
  `incremental_rpc_enabled=false`, `port_source=disabled`, `acl.source=disabled`.
- Managed ports were cleaned up through UDS delete; final managed count was 0.

## Decision

Do not enable `incremental_rpc_enabled=true` as a persistent runtime mode for
this old Neutron environment yet. Continue with P2 RPC-triggered full-resync, or
add a separate design for revisionless stale-event protection before allowing
port-scoped apply.
