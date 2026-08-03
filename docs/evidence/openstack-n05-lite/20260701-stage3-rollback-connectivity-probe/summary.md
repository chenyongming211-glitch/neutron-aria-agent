# Stage-Three N3 Rollback Connectivity Probe

Date: 2026-07-01
Target: compute-1.example.test

## Purpose

Validate the stage-three rollback-connectivity lifecycle gate after the N3
fault probes. This probe confirms that ACL rollback removes managed datapath
state, restores baseline VM reachability, and that stopping either the
Python agent or Rust datapath container does not break baseline OVS
connectivity.

This probe does not expand the product scope to QoS, Mirror, or RabbitMQ event
consumption.

## Inputs

- Script: `deploy/kolla/smoke/neutron_aria_rollback_connectivity_smoke.sh`
- Remote evidence root:
  `/tmp/aria-stage3-rollback-connectivity-20260701094955/evidence/20260701094952-compute-1.example.test`
- VM IP: `192.0.2.28`
- Port: `39adf570-1acb-4e81-9215-96744a6bf627`
- Tap: `tap39adf570-1a`
- `CHECK_AGENT_STOP=true`
- `CHECK_DATAPATH_STOP=true`
- `WAL_REPLAY_FAILURE_MAX_DELTA=0`

## Preconditions

- Baseline VM ping passed.
- Initial UDS status was readable.
- Initial datapath status:
  - generation: 135
  - accepted_generation: 135
  - applied_generation: 135
  - authority_state: `ready`
  - pending_generation: null
  - managed_count: 0
  - wal_status: `commit_written`
  - wal_replay_failures: 219

The pre-existing `wal_replay_failures=219` is historical residue from earlier
restart/replay testing. The probe treated it as the baseline and required no
increase during this run.

## Observed Flow

- The rollback smoke captured the WAL replay failure baseline:
  - baseline: 219
  - max_delta: 0
- ACL full-resync submitted snapshot generation 136.
- The target port reported:
  - domain: `acl`
  - status: `ready`
  - effective_action: `enforce`
- Other attached ports remained `not_requested` with
  `effective_action=bypass`.
- Rollback deleted five managed ACL ports:
  - `39adf570-1acb-4e81-9215-96744a6bf627`
  - `86b83885-671f-474c-9556-8af98cf1cdc8`
  - `aa4ddb4a-5b73-4e94-bb21-e9a4f9614045`
  - `d53ce06c-c90e-4371-b8e4-4912f90a91d3`
  - `e607e86b-9e5f-4c63-a5df-3dc8986a1b0f`
- `rollback_remaining_managed_ports=0`.
- Post-rollback VM ping passed.
- Stopping `neutron-aria-agent` did not break baseline VM ping, and the
  service restarted.
- Stopping `aria-datapath` did not break baseline VM ping, and the datapath
  restarted with UDS status readable.

## Post-rollback Status

Dedicated post-rollback status, before the stop/restart subchecks:

- generation: 136
- accepted_generation: 136
- applied_generation: 136
- authority_state: `ready`
- pending_generation: null
- managed_count: 0
- wal_status: `commit_written`
- wal_replay_failures: 219

The datapath stop/restart subcheck also returned readable UDS status with no
managed ports and unchanged `wal_replay_failures=219`. Because the target
environment already had historical WAL replay failures, the status after that
restart reported `wal_status=replayed_with_errors`; this is not a new failure
for this probe because the counter did not increase.

## Result

- pass: 8
- fail: 0

## Disposition

`pass`.

Rollback connectivity is verified for this test VM and host. The probe removed
all managed ACL datapath state, preserved/recovered baseline VM reachability
across rollback, agent stop, and datapath stop, and did not increase the
historical WAL replay failure counter.
