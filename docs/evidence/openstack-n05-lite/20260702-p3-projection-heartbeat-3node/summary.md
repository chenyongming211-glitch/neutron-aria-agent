# 2026-07-02 P3-1 Projection Heartbeat Three-Node Smoke

Status: pass.

Scope: extend the P3-1 read-only projection heartbeat gate from one host to all
three 10.58.159 target hosts. This validates observability for
`ProjectedStateIndex` and RPC decision summaries only; it does not enable
port-scoped incremental apply.

## Result

| Host | Package refresh | Package smoke | Heartbeat projection fields |
| --- | --- | --- | --- |
| `compute-1.example.test` | pass | pass | pass |
| `compute-2.example.test` | pass | pass | pass |
| `compute-3.example.test` | pass | pass | pass |

## Observed Signals

- Rebuilt the current stage-two Kolla bundle from the branch head.
- Installed the current `neutron_aria` egg into each running
  `neutron_aria_agent` container.
- Restarted only `neutron_aria_agent` on each host so the Python heartbeat code
  was loaded.
- `deploy/kolla/smoke/neutron_aria_rpc_event_smoke.sh` passed on all three
  hosts with `rpc_event_package_smoke=pass`.
- `deploy/kolla/smoke/neutron_aria_heartbeat_smoke.sh` passed from the control
  path with:
  - `EXPECTED_HOSTS="compute-1.example.test compute-2.example.test compute-3.example.test"`
  - `REQUIRE_HEARTBEAT_SUMMARY_FIELDS=true`
  - `REQUIRE_P3_PROJECTION_FIELDS=true`

The heartbeat gate confirmed all three hosts reported:

```text
heartbeat_summary_fields=ok
p3_projection_fields=ok
```

## Boundary

- `incremental_rpc_enabled` remains `false`.
- No port-scoped snapshot was submitted.
- No Rust datapath incremental apply path was touched.
- OVS, OVS agent, Neutron server, and `aria-datapath` were not restarted.
- This completes the P3-1 observability field gate, not the full P3 entry gate.
