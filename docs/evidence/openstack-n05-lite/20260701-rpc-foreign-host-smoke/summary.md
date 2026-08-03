# 2026-07-01 RPC Foreign-Host Fanout Smoke

Status: pass.

Scope: validate P2 real RabbitMQ fanout locality filtering across the
10.58.159 test hosts. The smoke starts only a temporary `neutron-aria-agent`
process per host; it does not restart OVS, OVS agent, Neutron server, or
aria-datapath.

Smoke script:

```text
deploy/kolla/smoke/neutron_aria_rpc_foreign_host_smoke.sh
```

## Result

| Listener host | Foreign event | Result | Evidence work directory |
| --- | --- | --- | --- |
| `compute-1.example.test` | `compute-2.example.test` port `3485b315-e152-42b8-aa55-75dff9d4266c` | pass | `/tmp/neutron-aria-rpc-foreign-host-20260701173603` |
| `compute-2.example.test` | `compute-1.example.test` port `86b83885-671f-474c-9556-8af98cf1cdc8` | pass | `/tmp/neutron-aria-rpc-foreign-host-20260701173700` |
| `compute-3.example.test` | `compute-1.example.test` port `86b83885-671f-474c-9556-8af98cf1cdc8` | pass | `/tmp/neutron-aria-rpc-foreign-host-20260701173757` |

## Observed Signals

For each listener host:

- `rpc_events_enabled=true`, `full_resync_enabled=true`, and
  `port_source=neutronclient` were used.
- The temporary agent consumed the real fanout and logged
  `event_batch_drained ... port_updates=1`.
- The service loop logged `service_result action=event_batch`.
- `full_resync_complete_count=1`, meaning only the startup full-resync ran.
  The foreign-host event did not trigger an unexpected local full-resync.
- The foreign port id was not present in local UDS `managed_ports`.
- Local managed-port count before rollback matched the count after processing
  the foreign event.
- Rollback ended with `rollback_remaining_managed_ports=0`.

Post-check after all three runs:

| Host | Temporary process | Temporary test agent | UDS managed ports |
| --- | --- | --- | --- |
| `compute-1.example.test` | absent | absent | `0` |
| `compute-2.example.test` | absent | absent | `0` |
| `compute-3.example.test` | absent | absent | `0` |

## Boundary

This proves that real RabbitMQ fanout can be received on multiple target hosts
and that foreign-host `port.update` events do not cause local mis-management in
P2 full-resync mode. It does not claim P3 port-scoped incremental apply or VM
migration source cleanup for a previously projected local port; those remain
separate targeted tests.
