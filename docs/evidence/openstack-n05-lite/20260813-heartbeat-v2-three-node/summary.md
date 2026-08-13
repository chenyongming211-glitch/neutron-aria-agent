# Heartbeat V2 Three-Node Acceptance

## Candidate

- Source commit: `c0b9e726e7e732a1ba38ed6601d61ec751687f70`
- GitHub Actions run: `31658816824`
- Stage2 bundle SHA-256: `c1ba51eaa22fd54fe15e449ca2a8cb9a605e9dac48a5afc01acb492cabd53f77`
- Python agent egg SHA-256: `fe3350624cc9ff360ced4593b91649684e94f882b92360369598cb1d31d4737e`
- Deployment order: compute node 2, compute node 3, compute node 4
- Restart boundary: `neutron_aria_agent` only

## Deployment Result

All three compute nodes loaded the same Python agent egg and the Kolla host
configuration contains:

```ini
[agent]
heartbeat_detail_mode = summary_only
```

The runtime import gate returned `heartbeat_schema_version=2` and
`heartbeat_detail_mode=summary_only` on every node.

## Acceptance Result

| Gate | Result |
| --- | --- |
| Three Aria agents alive in Neutron | PASS |
| Heartbeat schema V2 on all nodes | PASS |
| Summary-only detail mode on all nodes | PASS |
| Legacy per-item heartbeat samples absent | PASS |
| Summary and P3 projection fields present | PASS |
| Dedicated ACL port-status API | PASS |
| V2 rollback to the previous contract | PASS |
| Reapply the exact V2 candidate after rollback | PASS |
| Aria datapath not restarted | PASS |
| Neutron OVS agent not restarted | PASS |

Observed serialized `neutron agent-show` payload sizes were approximately
2.3 KiB, 2.5 KiB, and 2.3 KiB. All were below the 16 KiB acceptance limit.

The port-status gate used a real `ready/enforce` port projection and verified
the dedicated API fields `port_id`, `status`, `runtime_status`, and
`effective_action`.

## Rollback Evidence

Compute node 2 was rolled back after the first V2 deployment:

1. The previous agent egg was restored.
2. The V2-only INI key was removed by restoring the Kolla host config backup.
3. The runtime schema returned to the previous contract.
4. The Neutron agent remained alive.
5. The exact V2 egg was installed again and the three-node V2 gate passed.

## Non-Interference

The Aria datapath and Neutron OVS agent container identities, start times, and
restart counts were unchanged across the rollout. No OVS, OVS agent,
neutron-server, or Rust/eBPF restart was performed.
