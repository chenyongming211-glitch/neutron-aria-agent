# 2026-07-01 P3-1 Projection Heartbeat Smoke

Status: pass.

Scope: validate that the P3-1 read-only `ProjectedStateIndex` and RPC decision
debug summary are visible through the real Neutron agent heartbeat, without
enabling port-scoped incremental apply.

## Result

| Host | Result | Notes |
| --- | --- | --- |
| `ostack2.bj159.net` | pass | Installed the current `neutron_aria` egg into the running `neutron_aria_agent` container, restarted only that container, passed the package RPC-event smoke, and confirmed the new heartbeat fields through `neutron agent-show`. |

## Observed Signals

- `deploy/kolla/package/install_neutron_aria_agent_egg.sh install` completed
  and backed up the previous egg under `/var/tmp/neutron-aria-agent-package/`.
- `deploy/kolla/smoke/neutron_aria_rpc_event_smoke.sh` passed with
  `rpc_event_package_smoke=pass`.
- `deploy/kolla/smoke/neutron_aria_heartbeat_smoke.sh` passed with:
  - `REQUIRE_HEARTBEAT_SUMMARY_FIELDS=true`
  - `REQUIRE_P3_PROJECTION_FIELDS=true`
- The heartbeat smoke confirmed:
  - `heartbeat_summary_fields=ok host=ostack2.bj159.net`
  - `p3_projection_fields=ok host=ostack2.bj159.net`

## Boundary

- This validates heartbeat/debug observability only.
- `incremental_rpc_enabled` remains `false`.
- No port-scoped snapshot or Rust datapath incremental apply was enabled.
- OVS, OVS agent, Neutron server, and `aria-datapath` were not restarted.
