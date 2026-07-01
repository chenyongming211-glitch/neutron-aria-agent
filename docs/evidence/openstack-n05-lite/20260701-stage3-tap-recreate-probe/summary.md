# Stage-Three N3 Tap Recreate Probe

Date: 2026-07-01
Target: ostack2.bj159.net

## Purpose

Validate the stage-three tap lifecycle gate on a controlled test VM. This probe
verifies that a Neutron-managed tap can be recreated by VM reboot, then repaired
by the existing full-resync path without introducing a new feature path or
expanding scope to QoS or Mirror.

## Inputs

- Script: `deploy/kolla/smoke/neutron_aria_tap_recreate_smoke.sh`
- Remote log:
  `/tmp/aria-stage3-tap-recreate-20260701100003/tap-recreate.log`
- VM IP: `10.58.159.28`
- Port: `39adf570-1acb-4e81-9215-96744a6bf627`
- Tap: `tap39adf570-1a`
- `ALLOW_VM_REBOOT=true`
- `REBOOT_TYPE=hard`
- `ROLLBACK=true`
- `WAL_REPLAY_FAILURE_MAX_DELTA=0`

## Preconditions

- The target port was bound to `ostack2.bj159.net`.
- The UDS status path was read through the authorized agent container user,
  matching the hardened peercred/socket-permission model.
- The probe captured the pre-existing WAL replay failure baseline:
  - wal_replay_failures: 219
  - max_delta: 0

The pre-existing `wal_replay_failures=219` is historical residue from earlier
restart/replay testing. This probe required no increase.

## Observed Flow

- Existing managed ports were cleaned before the lifecycle run:
  - `rollback_remaining_managed_ports=0`
- Baseline full-resync submitted snapshot generation 137.
- Target port was managed before reboot:
  - port: `39adf570-1acb-4e81-9215-96744a6bf627`
  - ifname: `tap39adf570-1a`
  - ifindex: 48
- The test VM was hard rebooted through Nova.
- The tap was recreated:
  - before ifindex: 48
  - after ifindex: 69
- Full-resync after the lifecycle event submitted snapshot generation 139.
- Target port was managed again after the tap recreate:
  - port: `39adf570-1acb-4e81-9215-96744a6bf627`
  - ifname: `tap39adf570-1a`
  - ifindex: 69
- Rollback deleted five managed ACL ports and left:
  - `rollback_remaining_managed_ports=0`

## Final State

- generation: 139
- accepted_generation: 139
- applied_generation: 139
- authority_state: `ready`
- pending_generation: null
- managed_count: 0
- wal_status: `commit_written`
- wal_replay_failures: 219
- final tap ifindex: 69
- final VM ping: 2 packets transmitted, 2 received, 0% packet loss

## Disposition

`pass`.

The tap recreate lifecycle path is verified for the controlled test VM. The tap
ifindex changed after reboot, full-resync re-associated the target port with the
new ifindex, rollback removed all managed datapath ports, final VM connectivity
was healthy, and the historical WAL replay failure counter did not increase.
