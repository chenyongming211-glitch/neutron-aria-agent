# 2026-07-02 P3 Revisionless Experimental Fanout Smoke

Scope: controlled compute-1 test of P3 port-scoped apply in an old Neutron
environment that returns no trustworthy port `revision_number`.

This is legacy-environment evidence only. It does not replace the production
P3 requirement for revision-aware events or targeted reads.

## Build And Package

- Code revision: `d866aec`
- Agent package installed into `neutron_aria_agent`:
  `neutron_aria-0.1.0-py2.7.egg`
- The `neutron_aria_agent` container was restarted to load the new Python egg.
- OVS, OVS agent, Neutron server, and datapath were not restarted for this
  test.

Package preflight:

```text
rpc_event_package_smoke=pass
neutron-aria-agent RPC event package smoke passed
```

## Runtime Mode

The fanout smoke used temporary config files under `/tmp`; the persistent
agent config was not changed.

```text
INCREMENTAL_RPC_ENABLED=true
REVISIONLESS_INCREMENTAL_MODE=experimental
STARTUP_WAIT=10
AGENT_TIMEOUT=45
```

The smoke was updated to choose a currently projected local managed port for
P3 incremental testing. A generic bound Neutron port may be ineligible or not
projected, in which case the correct behavior is full-resync fallback.

## Result

Disabled A/B leg:

- `rpc_events_enabled=false`
- Full-resync initialized and projected local managed ports.
- The injected RabbitMQ `port.update` did not process an event batch.
- Rollback removed all test-managed ports.

Enabled experimental leg:

```text
rpc_events_enabled=true
incremental_rpc_enabled=true
revisionless_incremental_mode=experimental
target_port_revision_enabled=none
event_batch_drained ... port_updates=1
port_scoped_snapshot_complete ... generation=173 managed_ports=5 projected_ports=5
rpc_fanout_agent_ab=pass incremental_rpc_enabled=true revisionless_incremental_mode=experimental
```

Cleanup:

```text
rollback_remaining_managed_ports=0
final_ready=None final_degraded=None managed_ports=0
```

## Disposition

Pass for controlled legacy-environment P3 experiment:

- The old Neutron target still has no port `revision_number`.
- With default `revisionless_incremental_mode=disabled`, this environment must
  stay on P2 full-resync fallback.
- With explicit `revisionless_incremental_mode=experimental`, a single local
  projected `port.update` can submit the Rust port-scoped UDS route.

Production P3 remains gated on revision-aware event/read semantics and
rollback readiness.
