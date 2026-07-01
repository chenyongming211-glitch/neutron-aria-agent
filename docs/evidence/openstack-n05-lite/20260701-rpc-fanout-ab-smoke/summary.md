# 2026-07-01 RPC Fanout A/B Smoke

Status: pass.

Scope: validate the P2 real RabbitMQ fanout path on one 10.58.159 test host
without restarting OVS, OVS agent, Neutron server, or aria-datapath.

## Result

| Host | Result | Notes |
| --- | --- | --- |
| `ostack2.bj159.net` | pass | `rpc_events_enabled=false` ignored a real fanout cast; `rpc_events_enabled=true` consumed the fanout and drained one port update event. |

Smoke script:

```text
deploy/kolla/smoke/neutron_aria_rpc_fanout_smoke.sh
```

Remote evidence work directory:

```text
/tmp/neutron-aria-rpc-fanout-agent-20260701153052
```

## Observed Signals

Disabled side:

- Temporary agent used `full_resync_enabled=true`,
  `port_source=neutronclient`, and `rpc_events_enabled=false`.
- Initial full resync converged with `generation=161` and `managed_ports=5`.
- A real Neutron ML2 `AgentNotifierApi.port_update()` fanout was sent for
  port `86b83885-671f-474c-9556-8af98cf1cdc8`.
- No `event_batch_drained` line was present, as expected.

Enabled side:

- Temporary agent used `full_resync_enabled=true`,
  `port_source=neutronclient`, and `rpc_events_enabled=true`.
- Runtime package exposed `AriaAgentRpcCallback.target.version=1.4`.
- Event loop idle sleep was capped at `1.0s` while RPC event merging was
  enabled, so incoming fanout events can wake the resync path promptly.
- Initial full resync converged with `generation=162` and `managed_ports=5`.
- The same real fanout produced:

```text
event_batch_drained ... port_updates=1 deleted_ports=0 dirty_networks=0
service_result action=event_batch ... event_port_updates=1
```

Cleanup:

- `rollback_remaining_managed_ports=0` after both A and B sides.
- Post-check reported no temporary fanout process and no temporary test agent.
- UDS status after cleanup reported `managed_ports=0` and `generation=162`.

## Findings

- The old ML2 plugin does not notify L2 agents for a name-only port update.
  The smoke therefore uses `AgentNotifierApi.port_update()` directly to test
  the real RabbitMQ/oslo.messaging fanout path without changing VM-facing
  Neutron resource fields.
- Legacy Neutron RPC consumers require eventlet before starting the consumer
  server; the agent package now enables eventlet when
  `rpc_events_enabled=true`.
- The callback endpoint must expose an oslo.messaging target compatible with
  the old OVS agent shape. The package now declares target version `1.4`.
- `AgentService.run_forever()` must poll while RPC event merging is enabled;
  otherwise a long heartbeat/resync sleep can delay event processing until the
  next scheduled full resync.

## Boundary

This proves P2 real fanout-triggered full-resync on one host. It does not claim
P3 port-scoped incremental apply, cross-host fanout filtering, or multi-host
RabbitMQ rollout readiness.
