# Stage-Three N3 VM Migration Probe

Date: 2026-07-01
Targets: ostack2.bj159.net, ostack3.bj159.net

## Purpose

Validate the stage-three VM migration lifecycle gate on a controlled test VM.
This probe verifies that the source host removes local ACL datapath state after
the Neutron binding moves away, and that the destination host can apply the
same port after full-resync sees the new binding host.

The probe used the existing full-resync path only. It did not enable QoS,
Mirror, or RabbitMQ event consumption.

## Inputs

- Script: `deploy/kolla/smoke/neutron_aria_vm_migration_smoke.sh`
- Remote evidence root:
  `/tmp/aria-stage3-vm-migration-20260701102811`
- VM IP: `10.58.159.28`
- Server: `68fa335c-8c4d-451c-9685-ca9f21de79cc`
- Port: `39adf570-1acb-4e81-9215-96744a6bf627`
- Tap: `tap39adf570-1a`
- Source/destination sequence:
  - `ostack2.bj159.net -> ostack3.bj159.net`
  - `ostack3.bj159.net -> ostack2.bj159.net`
- `ALLOW_VM_MIGRATE=true`
- `ROLLBACK=true`
- `WAL_REPLAY_FAILURE_MAX_DELTA=0`

## Capability Probe

- `nova live-migration` command was available.
- Nova compute services were `enabled/up` on:
  - `ostack2.bj159.net`
  - `ostack3.bj159.net`
  - `ostack4.bj159.net`
- Nova hypervisors were `enabled/up` on the same three hosts.
- The server was initially `ACTIVE` on `ostack2.bj159.net`.
- The target Neutron port was initially bound to `ostack2.bj159.net`.

## Observed Flow

### Source: ostack2 -> ostack3

- WAL replay failure baseline: 219
- Cleaned existing managed ports:
  - `rollback_remaining_managed_ports=0`
- Baseline source full-resync submitted generation 141.
- Target port was managed on source:
  - ifname: `tap39adf570-1a`
  - ifindex: 69
- Nova live migration to `ostack3.bj159.net` was accepted.
- Source cleanup full-resync submitted generation 142.
- Source status confirmed the target port was no longer managed.
- Source rollback left:
  - `rollback_remaining_managed_ports=0`

### Destination: ostack3

- WAL replay failure baseline: 0
- Destination full-resync submitted generation 16.
- Target port was managed on destination:
  - ifname: `tap39adf570-1a`
  - ifindex: 27
- Destination rollback removed managed ACL ports and left:
  - `rollback_remaining_managed_ports=0`

### Source: ostack3 -> ostack2

- WAL replay failure baseline: 0
- Baseline source full-resync submitted generation 18.
- Target port was managed on source:
  - ifname: `tap39adf570-1a`
  - ifindex: 27
- Nova live migration back to `ostack2.bj159.net` was accepted.
- Source cleanup full-resync submitted generation 19.
- Source status confirmed the target port was no longer managed.
- Source rollback left:
  - `rollback_remaining_managed_ports=0`

### Destination: ostack2

- WAL replay failure baseline: 219
- Destination full-resync submitted generation 143.
- Target port was managed on destination:
  - ifname: `tap39adf570-1a`
  - ifindex: 71
- Destination rollback removed managed ACL ports and left:
  - `rollback_remaining_managed_ports=0`

Each phase included VM reachability checks through the smoke script.

## Final State

Final status on `ostack2.bj159.net`:

- generation: 143
- accepted_generation: 143
- applied_generation: 143
- authority_state: `ready`
- pending_generation: null
- managed_count: 0
- wal_status: `commit_written`
- wal_replay_failures: 219
- target tap exists with ifindex 71

Final status on `ostack3.bj159.net`:

- generation: 19
- accepted_generation: 19
- applied_generation: 19
- authority_state: `ready`
- pending_generation: null
- managed_count: 0
- wal_status: `commit_written`
- wal_replay_failures: 0
- target tap absent after migration back
- target port status retained as `detached`

## Disposition

`pass`.

The bidirectional migration path is verified for this controlled test VM. The
old host cleaned local managed state after the binding moved away, the new host
applied the port only after it became the authoritative binding host, rollback
removed all managed datapath ports, and neither host increased its WAL replay
failure counter.
