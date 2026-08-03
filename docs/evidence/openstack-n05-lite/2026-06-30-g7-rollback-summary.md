# 2026-06-30 G7 Rollback Connectivity Summary

Status: first target-environment rollback/connectivity evidence.

Evidence directory:

| Host | Evidence Path | Result |
| --- | --- | --- |
| `compute-1.example.test` | `docs/evidence/openstack-n05-lite/20260630115838-compute-1.example.test/` | 7 pass, 0 fail |

## Confirmed Facts

| Area | Result |
| --- | --- |
| Baseline connectivity | `192.0.2.26` was reachable from `compute-1.example.test` before the smoke. |
| ACL active traffic | Full-resync generation `81` managed five local compute tap ports. ICMP from `192.0.2.2/32` to VM port `86b83885-671f-474c-9556-8af98cf1cdc8` / `tap86b83885-67` was blocked by the smoke ACL. |
| UDS rollback | `DELETE /api/v1/neutron/ports/{port_id}` removed all five managed ports and returned `rollback_remaining_managed_ports=0`. |
| Post-rollback connectivity | `192.0.2.26` was reachable again after rollback. |
| Post-rollback status | UDS status reported `managed_ports=[]`, `active_instances=[]`, `pending_generation=null`, and `wal_replay_failures=0`. |
| Python agent stop | Stopping `neutron_aria_agent` did not interrupt VM connectivity; ping stayed at 0% packet loss while the container was stopped and after restart. |
| Datapath stop | Stopping `aria_datapath` after rollback did not interrupt VM connectivity; ping stayed at 0% packet loss while the container was stopped and after restart. |
| Datapath restart status | After `aria_datapath` restart, UDS status was readable and reported `managed_ports=[]`, `active_instances=[]`, `pending_generation=null`, `wal_replay_failures=0`, and `wal_status=replayed`. |
| Scope boundary | The smoke did not enable QoS, Mirror, or RabbitMQ event consumption. |

## Later Evidence And Remaining Gate Items

- VM -> external active direction evidence is covered by the later temporary
  CirrOS guest-originated ICMP proof in
  `docs/evidence/openstack-n05-lite/20260630145200-compute-1.example.test-cirros-vm-egress-final/`.
  The `20260630121023-compute-1.example.test` probe remains recorded as a rejected
  proof shape because host-initiated ping echo-reply is reverse traffic under
  stateful ACL, not a VM-initiated flow.
- DHCP/metadata/IPv6 disposition is covered by
  `docs/evidence/openstack-n05-lite/20260630155334-compute-1.example.test-guest-bypass-probe/`:
  DHCP initial lease passed, metadata reached the namespace proxy but target
  metadata backend returned HTTP 500/`ENOENT`, and IPv6 ND is `not_applicable`.
- UDS peer credential/audit has accepted three-node reversible hardening
  evidence in
  `docs/evidence/openstack-n05-lite/2026-06-30-uds-hardening-summary.md`.
  Persistent hardened rollout is still a release/operations gate.
