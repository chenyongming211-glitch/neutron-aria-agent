# Stage-Three N3 UDS Timeout / Crash Probe

Date: 2026-07-01
Target: compute-1.example.test

## Purpose

Validate the stage-three UDS timeout and crash-recovery path without expanding
the product scope. This probe used the existing crash and transaction smoke
scripts to verify that local snapshot/delete transaction state can recover
after agent restart, datapath restart, and replay/status reconciliation.

## Preconditions

- Hardened UDS config was active:
  - socket mode: `0660`
  - peercred enforcement: enabled
  - allowed uid/gid: `42435`
- Datapath status before the probe:
  - generation: 120
  - accepted_generation: 120
  - applied_generation: 120
  - authority_state: `ready`
  - managed_count: 0
  - pending_generation: null
  - wal_status: `replayed_with_errors`
  - wal_replay_failures: 219
- The test VM was reachable before the probe.

The pre-existing `wal_replay_failures=219` is historical residue from earlier
restart/replay testing. The probe treated it as the baseline and required no
increase.

## Crash Injection Smoke

Script:

- `deploy/kolla/smoke/neutron_aria_crash_injection_smoke.sh`

Inputs:

- `MIN_MANAGED_PORTS=1`
- `RESTART_DATAPATH=true`
- `ROLLBACK=true`
- `REQUEST_TIMEOUT_OVERRIDE=3.0`

Observed flow:

- Baseline full-resync submitted snapshot generation 121.
- Baseline managed ports: 5.
- Agent crash after local snapshot prepare recovered through a subsequent
  full-resync to generation 123.
- Agent crash after datapath delete and before local delete commit recovered
  through a subsequent full-resync to generation 125.
- Datapath container restart verified replay/status recovery:
  - accepted_generation: 125
  - applied_generation: 125
  - authority_state: `ready`
  - pending_generation: null
  - managed_count: 5
  - wal_replay_failures: 219
- Final full-resync submitted generation 127.
- Rollback deleted all five managed ports.

Post-crash-smoke status:

- generation: 127
- accepted_generation: 127
- applied_generation: 127
- authority_state: `ready`
- pending_generation: null
- managed_count: 0
- wal_status: `commit_written`
- wal_replay_failures: 219

## Transaction State Smoke

Script:

- `deploy/kolla/smoke/neutron_aria_transaction_state_smoke.sh`

Inputs:

- `MIN_MANAGED_PORTS=1`
- `ROLLBACK=true`
- `REQUEST_TIMEOUT_OVERRIDE=3.0`

Observed flow:

- Baseline full-resync submitted snapshot generation 129.
- Baseline managed ports: 5.
- Injected pending snapshot state for generation 129.
- Agent restart plus full-resync recovered and cleared pending snapshot state
  at generation 131.
- Injected pending delete state for port
  `39adf570-1acb-4e81-9215-96744a6bf627`.
- Agent restart plus full-resync recovered and cleared pending delete state at
  generation 133.
- Migration-source cleanup delete recorded `last_deleted_port_id` and left no
  pending delete state.
- Final full-resync submitted generation 135.
- Rollback deleted all five managed ports.

Final status after transaction smoke:

- generation: 135
- accepted_generation: 135
- applied_generation: 135
- authority_state: `ready`
- pending_generation: null
- managed_count: 0
- wal_status: `commit_written`
- wal_replay_failures: 219

The test VM remained reachable after the smoke run.

## Disposition

`pass`.

The UDS timeout / crash path recovered pending snapshot state, pending delete
state, datapath restart/replay state, and migration-source cleanup state. It did
not leave managed datapath ports behind, did not leave local transaction
pending fields set, and did not increase the historical WAL replay failure
counter.
