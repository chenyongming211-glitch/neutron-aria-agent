# Stage-Three N3 Missing-Policy Probe

Date: 2026-06-30
Target: ostack2.bj159.net

## Purpose

Validate the ACL fault path where an `aria_acl` binding references a policy
that no longer exists or is not readable by the agent. This is not a normal
operator/API workflow: public `aria_acl` CRUD rejects missing-policy bindings.
The probe used direct DB fault injection and removed the injected rows during
cleanup.

## Preconditions

- Hardened UDS path was active on the test host.
- Datapath status before the probe:
  - generation: 108
  - managed_count: 0
  - active_count: 0
  - port_status_count: 0
  - wal_status: commit_written
- Five ACTIVE compute ports were selected for port-level fault bindings.

## Fault Injection

The probe inserted five temporary `aria_acl_bindings` rows, one per selected
ACTIVE compute port. Each binding referenced the same non-existent policy ID.
No policy or rule rows were inserted.

The production `aria_acl` source then read:

- policies: 0
- rules: 0
- bindings: 5

## Probe Result

- One-shot full-resync returned success and printed
  `snapshot generation 109 submitted`.
- Datapath status after apply:
  - generation: 109
  - accepted_generation: 109
  - applied_generation: 109
  - wal_status: commit_written
  - managed_count: 5
  - active_count: 5
  - port_status_count: 5
- Every managed ACL domain reported:
  - status: `degraded`
  - effective_action: `bypass`
  - reason: `policy_missing_or_disabled`
- Neutron `aria_acl_port_statuses` reportback refreshed the five managed port
  rows to generation 109:
  - status: `degraded`
  - runtime_status: `degraded`
  - effective_action: `bypass`
  - reason: `policy_missing_or_disabled`
  - stale: `False`
- Forwarding stayed available while ACL was degraded/bypass:
  - probe target: `10.58.159.28`
  - ping: 2 transmitted, 2 received, 0% packet loss

The datapath status still carried `wal_replay_failures=219` from the earlier
restart/replay window. The current transaction state for this probe was
`wal_status=commit_written`.

## Cleanup

Cleanup deleted all five injected DB binding rows by their missing policy ID,
then deleted all five managed ports through the UDS port-delete path.

Final state:

- generation: 109
- wal_status: commit_written
- managed_count: 0
- wal_replay_failures: 219

## Disposition

`pass`.

The missing-policy condition does not falsely report ready and does not enforce
a partial or stale ACL. It degrades the ACL domain to bypass, preserves baseline
forwarding, reports the degraded state back through Neutron, and leaves no
temporary DB or datapath state after cleanup.
