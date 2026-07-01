# 2026-07-01 RPC Source-Cleanup Smoke

Status: pass.

Scope: validate the P2 lifecycle case where a port already projected on the
current host receives a real RabbitMQ `port.update` fanout whose
`binding:host_id` points to another host. This simulates the old/source host
side of migration or rebinding cleanup without changing Neutron DB state.

Smoke script:

```text
deploy/kolla/smoke/neutron_aria_rpc_source_cleanup_smoke.sh
```

## Result

| Host | Simulated new binding host | Result | Evidence work directory |
| --- | --- | --- | --- |
| `ostack2.bj159.net` | `ostack3.bj159.net` | pass | `/tmp/neutron-aria-rpc-source-cleanup-20260701174920` |

## Observed Signals

- Temporary agent used `rpc_events_enabled=true`, `full_resync_enabled=true`,
  and `port_source=neutronclient`.
- Startup full-resync projected 5 local managed ports on `ostack2.bj159.net`.
- The smoke selected local projected port
  `39adf570-1acb-4e81-9215-96744a6bf627`.
- A real Neutron ML2 `AgentNotifierApi.port_update()` fanout was sent for that
  port with `binding:host_id=ostack3.bj159.net`.
- The agent logged:

```text
event_batch_drained ... port_updates=1
delete_port_complete ... reason=migration_source_cleanup projected_ports=4
service_result action=event_batch ... event_port_updates=1
```

- `full_resync_complete_count=1`, meaning only the startup full-resync ran.
  The source-cleanup event did not trigger an unexpected second full-resync.
- The selected port was absent from local UDS `managed_ports` after the event.
- Managed-port count changed from 5 to 4 before rollback, matching exactly one
  source cleanup delete.
- Rollback removed the remaining four temporary managed ports and ended with
  `rollback_remaining_managed_ports=0`.

Post-check:

- No temporary source-cleanup process remained.
- No temporary test agent remained.
- UDS status reported `managed_ports=0` and `generation=164`.

## Boundary

This validates the old/source host cleanup branch in P2 full-resync mode. It
does not claim live Nova migration support, P3 port-scoped incremental apply,
or automatic destination-host attach beyond the existing full-resync path.
