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

## Probe Result

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

## Cleanup

All five managed ports were deleted through the UDS port-delete path. Final
state:

- generation: 91
- authority_state: ready
- wal_replay_failures: 0
- managed_count: 0
- active_count: 0
- post-cleanup ping to the test VM address: pass

## Disposition

`degraded`.

The Neutron-managed ACL domain may legitimately claim local VM ports even when
no ACL binding exists, because local ACL writes must remain blocked while the
ACL domain is Neutron-managed. The implementation gap is status fidelity: the
ACL domain should report `not_requested` with `effective_action=bypass` for
ports without an enabled binding, rather than plain `ready`. The one-shot
agent returning non-zero while the datapath converged is also tracked by the
N3 timeout/recovery work.
