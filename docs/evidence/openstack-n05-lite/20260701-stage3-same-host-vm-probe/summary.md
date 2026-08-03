# Stage-Three N3 Same-Host VM Probe

Date: 2026-07-01
Target: compute-1.example.test

## Purpose

Validate the stage-three same-host VM lifecycle gate with guest-originated
traffic. This probe verifies that ACL enforcement works for two VMs placed on
the same compute host and that rollback restores traffic without expanding
scope to QoS, Mirror, or event-driven incremental sync.

## Inputs

- Remote evidence root:
  `/tmp/aria-stage3-same-host-vm-20260701110327/evidence`
- Temporary guest IP: `192.0.2.43`
- Target guest IP: `192.0.2.28`
- Temporary port: `ae8cc2b6-cc0c-431f-92bb-83d158c8c9e6`
- Temporary tap: `tapae8cc2b6-cc`
- ACL fixture:
  - src CIDR: `192.0.2.43/32`
  - dst CIDR: `192.0.2.28/32`
  - protocol: `icmp`
- `ROLLBACK=true`
- `WAL_REPLAY_FAILURE_MAX_DELTA=0`

## Preconditions

- The target VM was active on `compute-1.example.test`.
- A temporary CirrOS VM was created on the same host for guest-originated
  traffic.
- The temporary guest was reachable through SSH for the traffic checks.
- The UDS status path was read through the authorized agent container user,
  matching the hardened peercred/socket-permission model.

The target host carried a historical WAL replay failure baseline:

- wal_replay_failures: 219
- max_delta: 0

This probe required no increase.

## Observed Flow

- Baseline guest-originated ping from `192.0.2.43` to `192.0.2.28`
  succeeded before ACL was applied.
- ACL full-resync submitted snapshot generation 144.
- The temporary port was managed by the datapath:
  - port: `ae8cc2b6-cc0c-431f-92bb-83d158c8c9e6`
  - ifname: `tapae8cc2b6-cc`
  - ifindex: 75
  - managed_domains: `acl`
- Runtime port status reported the temporary port as:
  - status: `ready`
  - effective_action: `enforce`
- Datapath ACL state contained ICMP drop policy state for the temporary and
  target guest CIDRs.
- Guest-originated ping from the temporary VM to the target VM was blocked
  while ACL was active.
- Rollback deleted all six managed ACL ports and left:
  - `rollback_remaining_managed_ports=0`
- Post-rollback guest-originated ping from the temporary VM to the target VM
  succeeded.
- Temporary VM, image, keypair, and managed datapath state were cleaned up.

## Final State

- generation: 144
- accepted_generation: 144
- applied_generation: 144
- authority_state: `ready`
- pending_generation: null
- managed_count: 0
- port_statuses: empty
- wal_status: `commit_written`
- wal_replay_failures: 219

## Disposition

`pass`.

The same-host VM path is verified with real guest-originated traffic. ACL
full-resync enforced ICMP drop for the temporary guest, rollback removed all
managed datapath ports, post-rollback traffic recovered, and no new WAL replay
failure was introduced.
