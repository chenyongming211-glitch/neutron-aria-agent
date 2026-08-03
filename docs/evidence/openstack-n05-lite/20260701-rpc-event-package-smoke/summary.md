# 2026-07-01 RPC Event Package Smoke

Status: pass.

Scope: validate the P2 RPC-event package path on the 10.58.159 test
environment before any real RabbitMQ fanout or incremental RPC work.

## Result

The package-level smoke passed on all three target hosts:

| Host | Result | Notes |
| --- | --- | --- |
| `compute-1.example.test` | pass | Updated the `neutron_aria_agent` container egg, confirmed `validate_config`, and passed `rpc_event_package_smoke=pass`. |
| `compute-2.example.test` | pass | Updated the `neutron_aria_agent` container egg, confirmed `validate_config`, and passed `rpc_event_package_smoke=pass`. |
| `compute-3.example.test` | pass | Updated the `neutron_aria_agent` container egg, confirmed `validate_config`, and passed `rpc_event_package_smoke=pass`. |

Backups of the previous container egg were written under:

```text
/var/tmp/neutron-aria-agent-package/
```

Observed backup files:

```text
compute-1.example.test: neutron_aria-0.1.0-py2.7.egg.20260701142902.bak
compute-2.example.test: neutron_aria-0.1.0-py2.7.egg.20260701142931.bak
compute-3.example.test: neutron_aria-0.1.0-py2.7.egg.20260701142932.bak
```

## What The Smoke Proved

- `rpc_events_enabled=true` is rejected unless full resync is enabled and
  `port_source=neutronclient`.
- Local `port.update` events drive one safe full-resync after the merge window.
- `network.update` events drive one safe full-resync after the merge window.
- Foreign-host unknown port updates do not resync and do not delete local
  state.
- Foreign-host updates for known projected ports trigger local cleanup with
  `migration_source_cleanup`.
- Known `port.delete` events use the idempotent UDS delete path with
  `port_delete_event` instead of pretending to be port-scoped incremental
  apply.

## Boundary

This is a package-level P2 preflight only:

- It does not subscribe to RabbitMQ.
- It does not modify tap datapath state.
- It does not restart OVS, OVS agent, Neutron server, or the datapath service.
- It does not claim P3 incremental RPC readiness.

The next P2 validation step is a controlled real RabbitMQ fanout A/B smoke on
one test host, still using full-resync as the only production apply model.
