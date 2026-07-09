# P2.5 RPC-Triggered Full-Resync 3-Node Smoke

Date: 2026-07-09

## Scope

Validated the P2.5 mode where `aria_acl` Neutron API changes emit
`aria_acl_update` RPC events, and each `neutron-aria-agent` consumes the event
as a full-host resync while `incremental_rpc_enabled=false`.

This smoke does not enable P3 port-scoped apply.

## Runtime Mode

- `full_resync_enabled=true`
- `rpc_events_enabled=true`
- `incremental_rpc_enabled=false`
- `event_merge_interval=0.2`

The same CI-built datapath artifact was deployed to all three compute nodes
before the live smoke. Artifact identity was verified during deployment; the
environment-specific digests are intentionally omitted from public evidence.

Only `aria_datapath` was restarted during the datapath rollout. OVS and
`neutron-openvswitch-agent` were not restarted.

## Live Targets

| Node | Port | IP | Result |
| --- | --- | --- | --- |
| `compute-a` | `test-port-a` | `test-vm-a` | pass |
| `compute-b` | `test-port-b` | `test-vm-b` | pass |
| `compute-c` | `test-port-c` | `test-vm-c` | pass |

## Measured Convergence

| Node | Binding create -> ICMP drop | Rule disable -> ICMP allow | Rule enable -> ICMP drop | Binding disable -> ICMP allow | Policy disable -> ICMP allow |
| --- | ---: | ---: | ---: | ---: | ---: |
| `compute-a` | 2785 ms | 2174 ms | 3190 ms | 2180 ms | 2791 ms |
| `compute-b` | 2838 ms | 2168 ms | 2659 ms | 2160 ms | 1268 ms |
| `compute-c` | 3345 ms | 2170 ms | 2693 ms | 2154 ms | 2813 ms |

All operations converged in a few seconds through event-triggered full-resync,
not the 60-second periodic resync interval.

## Evidence Signals

Each target agent reported event-driven full resync:

- `event_batch_drained ... full_resync=True`
- `reasons=aria_domain_update:acl:*`
- `service_result action=event_batch ... event_full_resync=True`
- `full_resync_complete ... heartbeat_ok=True`

The temporary ACL objects were deleted at the end of each node test, and
baseline ping recovered on all three targets.

## Follow-Up

The smoke has been captured as:

`deploy/kolla/smoke/neutron_aria_acl_rpc_full_resync_smoke.sh`

Run it per target port with:

```bash
TARGET_PORT_ID=<port-id> \
TARGET_VM_IP=<vm-ip> \
TARGET_LABEL=<node-or-case-label> \
deploy/kolla/smoke/neutron_aria_acl_rpc_full_resync_smoke.sh
```
