# P3-5 Incremental On/Off Smoke Evidence

Date: 2026-07-02

Host: `compute-1.example.test`

Scope:

- Validate the package-level RPC event path after the P3-4 failure fallback
  changes.
- Validate RPC on/off behavior with `incremental_rpc_enabled=false`.
- Validate controlled test-host port-scoped apply with
  `incremental_rpc_enabled=true` and
  `revisionless_incremental_mode=experimental`.
- Validate old Neutron default behavior when no `revision_number` is available:
  stay on full-resync fallback unless experimental mode is explicitly enabled.
- Validate rollback leaves no managed ports.

Commands were run from temporary host directory:

```text
/tmp/neutron-aria-p3-5-20260702170952
```

## Package Smoke

`neutron_aria_rpc_event_smoke.sh` passed inside the `neutron_aria_agent`
container after installing the rebuilt `neutron_aria-0.1.0-py2.7.egg`.

Observed marker:

```text
rpc_event_package_smoke=pass
```

## P2 RPC Full-Resync A/B

Work directory:

```text
/tmp/neutron-aria-p3-5-fanout-p2-20260702171042
```

Configuration:

```text
INCREMENTAL_RPC_ENABLED=false
REVISIONLESS_INCREMENTAL_MODE=disabled
```

Result:

- Disabled case: no event batch processed.
- Enabled case: one port update event was processed.
- Because incremental mode was disabled, the event path used full-resync.
- Target Neutron returned `revision_number=None`.
- Rollback deleted all managed ports.

Observed markers:

```text
event_batch_drained ... port_updates=1
full_resync_complete ... managed_ports=5
rollback_remaining_managed_ports=0
rpc_fanout_agent_ab=pass incremental_rpc_enabled=false revisionless_incremental_mode=disabled
```

## P3 Experimental Port-Scoped Apply

Work directory:

```text
/tmp/neutron-aria-p3-5-fanout-incr-20260702171228
```

Configuration:

```text
INCREMENTAL_RPC_ENABLED=true
REVISIONLESS_INCREMENTAL_MODE=experimental
```

Result:

- Disabled case: no event batch processed.
- Enabled case: one local port update event was processed.
- The test host accepted revisionless experimental mode.
- Port-scoped UDS apply completed for the target port.
- No scoped fallback was observed.
- Rollback deleted all managed ports.

Observed markers:

```text
event_batch_drained ... port_updates=1
port_scoped_snapshot_complete ... generation=178 managed_ports=5 projected_ports=5
rollback_remaining_managed_ports=0
rpc_fanout_agent_ab=pass incremental_rpc_enabled=true revisionless_incremental_mode=experimental
```

## Revisionless Default Fallback

Work directory:

```text
/tmp/neutron-aria-p3-5-revisionless-fallback-20260702171655
```

Configuration:

```text
INCREMENTAL_RPC_ENABLED=true
REVISIONLESS_INCREMENTAL_MODE=disabled
ALLOW_REVISIONLESS_INCREMENTAL_FALLBACK=true
```

Result:

- Target Neutron returned `revision_number=None`.
- With experimental mode disabled, no `port_scoped_snapshot_complete` marker
  was emitted.
- The event path stayed on full-resync fallback.
- Rollback deleted all managed ports.

Observed markers:

```text
event_batch_drained ... port_updates=1
full_resync_complete ... managed_ports=5
target_port_revision_enabled=none
rollback_remaining_managed_ports=0
rpc_fanout_agent_ab=pass incremental_rpc_enabled=true revisionless_incremental_mode=disabled
```

## Final State

After all P3-5 smokes:

```text
neutron_aria_agent Up
uds_generation=182
managed_ports=0
pending_generation=None
```

## Disposition

P3-5 is accepted for the current old Neutron test environment:

- P2 RPC-triggered full-resync remains the safe default.
- P3 port-scoped apply is proven on the controlled test host only with
  `revisionless_incremental_mode=experimental`.
- Production P3 remains revision-aware. Old Neutron without trustworthy
  `revision_number` must not enable revisionless incremental mode by default.

No QoS/Mirror scope was added.
