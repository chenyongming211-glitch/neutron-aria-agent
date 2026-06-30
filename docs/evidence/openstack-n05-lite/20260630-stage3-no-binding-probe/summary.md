# Stage-Three N3 No-Binding Probe

Date: 2026-06-30
Target: ostack2.bj159.net

## Purpose

Validate the ACL no-binding path in production mode without expanding QoS or
Mirror scope.

## Preconditions

- `aria_acl` API was reachable from `neutron_aria_agent`.
- `aria_acl` object counts before the probe:
  - policies: 0
  - rules: 0
  - address_sets: 0
  - bindings: 0
- UDS before the probe:
  - generation: 89
  - managed_count: 0
  - active_count: 0

## Initial Probe Result

- One-shot `neutron-aria-agent --once --enable-full-resync` returned `agent_rc=1`.
- Datapath nevertheless converged to:
  - generation: 91
  - accepted_generation: 91
  - applied_generation: 91
  - authority_state: ready
  - wal_status: commit_written
  - wal_replay_failures: 0
  - managed_count: 5
  - active_count: 5
  - port_status_count: 5
- Sample port statuses from the deployed binary reported ACL domain `ready`
  instead of `not_requested` / `bypass`.

## Fix And Rerun

After deploying the CI datapath artifact built from commit
`e476b2d1463988a84dc525f58bf01e46d0121146` and applying the Python
timeout/reportback fix to the test `neutron_aria_agent` package on
`ostack2.bj159.net`, the parameterized no-binding smoke passed:

- UDS hardened path was active:
  - `/run/aria/aria-agent.sock`: `root:42435 0660`
  - `neutron_peercred_enforce=true`
  - peer UID/GID allow-list: `42435`
- One-shot `neutron-aria-agent --once --enable-full-resync` returned
  `agent_rc=0` and printed `snapshot generation 107 submitted`.
- `aria_acl` input remained empty:
  - policies: 0
  - rules: 0
  - bindings: 0
- Datapath status after apply:
  - generation: 107
  - accepted_generation: 107
  - applied_generation: 107
  - wal_status: commit_written
  - managed_count: 5
  - active_count: 5
  - port_status_count: 5
- Each managed port reported ACL domain:
  - status: `not_requested`
  - runtime_status in Neutron API: `not_requested`
  - effective_action: `bypass`
  - reason: `no_enabled_binding`
  - stale: `False`
- Neutron `aria_acl_port_statuses` reportback refreshed the five managed port
  rows to generation 107.

The datapath status still carried `wal_replay_failures=219` from the earlier
restart/replay window, while the current transaction state was
`wal_status=commit_written`. This is recorded as follow-up WAL hygiene rather
than a no-binding semantic failure.

## Cleanup

All five managed ports were deleted through the UDS port-delete path. Final
state:

- generation: 107
- authority_state: ready
- managed_count: 0
- active_count: 0
- post-cleanup ping to the test VM address: pass

## Disposition

`pass`.

The Neutron-managed ACL domain may legitimately claim local VM ports even when
no ACL binding exists, because local ACL writes must remain blocked while the
ACL domain is Neutron-managed. The effective ACL behavior is bypass:
`not_requested` with `effective_action=bypass` for ports without an enabled
binding. The one-shot agent now exits successfully after recognizing the
committed snapshot transaction by generation and desired hash, and it reports
the no-binding port statuses back to Neutron.
