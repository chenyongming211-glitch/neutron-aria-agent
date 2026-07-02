# P3 Acceptance Summary

Date: 2026-07-02

Status: accepted for controlled test-host use; production defaults remain
disabled.

## Scope

This summary closes the P3 incremental RPC work package after P3-1 through P3-6.
It does not expand ACL/RPC beyond the config-gated port-scoped path already
implemented, and it does not open QoS or Mirror.

## Accepted Evidence

| Area | Evidence | Disposition |
| --- | --- | --- |
| P3-1 projection observability | `docs/evidence/openstack-n05-lite/20260702-p3-projection-heartbeat-3node/summary.md` | pass on `ostack2/3/4`; read-only projection and decision heartbeat fields accepted. |
| P3-2 Python builder and dry-run | Unit tests covered by stage checks and CI | pass; no production behavior change outside config gates. |
| P3-3 Rust port-scoped UDS route | `docs/evidence/openstack-n05-lite/20260702-p3-port-scoped-uds-route-smoke/summary.md` | pass; route/capability and mismatch guard accepted while runtime remained gated. |
| P3-4 failure semantics | Commit `9901c1f`; CI run `28577963141` | pass; scoped errors or unsafe candidates fall back to full-resync, invalid ACL remains degraded/bypass. |
| P3-5 incremental on/off smoke | `docs/evidence/openstack-n05-lite/20260702-p3-5-incremental-smoke/summary.md` | pass; P2 full-resync A/B, revisionless experimental scoped apply, default revisionless fallback, and rollback accepted. |
| P3-6 default-off runbook | Commit `0de826f`; CI run `28580471728` | pass; runbook and INI contract define default-off behavior, test enablement, and rollback levels. |

## Final Behavior Contract

- Packaged defaults keep:

  ```ini
  rpc_events_enabled = false
  incremental_rpc_enabled = false
  revisionless_incremental_mode = disabled
  ```

- P2 may be enabled per host as RPC-triggered full-resync:

  ```ini
  rpc_events_enabled = true
  incremental_rpc_enabled = false
  revisionless_incremental_mode = disabled
  ```

- P3 may be tested explicitly on a controlled host:

  ```ini
  rpc_events_enabled = true
  incremental_rpc_enabled = true
  revisionless_incremental_mode = disabled
  ```

- Old Neutron without trustworthy `revision_number` may use
  `revisionless_incremental_mode=experimental` only as a lab valve.
- Any unsafe event, capability drift, stale/missing revision, scoped UDS error,
  or invalid scoped candidate falls back to full-resync.
- Rollback from P3 to P2 changes only `incremental_rpc_enabled=false` and
  `revisionless_incremental_mode=disabled`, then restarts only
  `neutron_aria_agent`.
- Rollback from P2 to polling-only changes `rpc_events_enabled=false`, then
  restarts only `neutron_aria_agent`.

## Field Result

The final P3-5 smoke on `ostack2.bj159.net` showed:

- package RPC event smoke passed;
- P2 RPC full-resync A/B passed;
- controlled revisionless experimental port-scoped apply reached
  `port_scoped_snapshot_complete`;
- default revisionless mode stayed on full-resync fallback;
- final UDS state had `managed_ports=0` and `pending_generation=None`.

## Boundaries

- Do not enable P3 in packaged defaults.
- Do not treat revisionless experimental mode as production acceptance.
- Do not remove periodic/full-resync recovery.
- Do not restart OVS, OVS agent, neutron-server, or datapath to change P2/P3
  flags.
- Do not expand QoS/Mirror as part of P3 closure.

## Next Phase

The next reasonable planning target is QoS entry assessment. Current discovery
evidence says the target Neutron does not expose QoS extension and the hosts
lack `tc`, so QoS must start with capability discovery and degraded/unsupported
semantics rather than shaping implementation.
