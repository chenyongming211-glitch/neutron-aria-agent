# Stage-Three N3 OVS Restart Probe

Date: 2026-07-01
Target: compute-1.example.test

## Purpose

Validate the stage-three OVS restart lifecycle gate under ACL managed state.
This probe intentionally uses the existing full-resync path only. It does not
enable QoS, Mirror, RabbitMQ event consumption, or a new recovery feature.

## Inputs

- Remote evidence root:
  `/tmp/aria-stage3-ovs-restart-20260701110556/evidence`
- Target VM IP: `192.0.2.28`
- Target port: `39adf570-1acb-4e81-9215-96744a6bf627`
- Target tap: `tap39adf570-1a`
- OVS action: restart `ovs-vswitchd.service`
- ACL fixture:
  - src CIDR: `198.51.100.1/32`
  - dst CIDR: `198.51.100.2/32`
  - protocol: `icmp`
- `ROLLBACK=true`
- `WAL_REPLAY_FAILURE_MAX_DELTA=0`

The ACL fixture used non-matching documentation CIDRs, so the target VM ping was
not expected to be intentionally blocked by ACL policy.

## Preconditions

- `aria_datapath`, `neutron_aria_agent`, and `neutron_openvswitch_agent` were
  running before the restart probe.
- `openvswitch.service`, `ovs-vswitchd.service`, and `ovsdb-server.service`
  were active before the restart probe.
- The target VM ping succeeded before ACL state was applied.
- The target host carried a historical WAL replay failure baseline:
  - wal_replay_failures: 219
  - max_delta: 0

## Observed Flow

- Pre-probe UDS status was clean:
  - generation: 144
  - authority_state: `ready`
  - managed_count: 0
  - pending_generation: null
  - wal_replay_failures: 219
- ACL full-resync submitted snapshot generation 145.
- Five local compute ports became managed by ACL.
- Target port was managed before restart:
  - port: `39adf570-1acb-4e81-9215-96744a6bf627`
  - ifname: `tap39adf570-1a`
  - ifindex: 71
  - managed_domains: `acl`
- Target VM ping succeeded while ACL managed state was active before the OVS
  restart.
- After `ovs-vswitchd.service` restart:
  - `br-int` still existed.
  - `tap39adf570-1a` still existed with ifindex 71.
  - XDP was still attached to the tap.
  - The immediate target VM ping failed with 100% packet loss.
- The smoke script exited non-zero and ran cleanup.
- Cleanup deleted all five managed ACL ports and left:
  - `cleanup_remaining_managed_ports=0`
- Post-cleanup recovery check showed:
  - VM ping succeeded again.
  - OVS services were active.
  - `neutron_openvswitch_agent` was running.
  - UDS status was `ready` with zero managed ports.

## Final State

- generation: 145
- accepted_generation: 145
- applied_generation: 145
- authority_state: `ready`
- pending_generation: null
- managed_count: 0
- port_statuses: empty
- wal_status: `commit_written`
- wal_replay_failures: 219
- post-cleanup VM ping: 3 packets transmitted, 3 received, 0% packet loss

## Disposition

`degraded`.

This evidence is degraded for the current N3 matrix because the temporary probe
used immediate VM ping as the decisive check. After the follow-up design review,
the target contract is more precise: Aria owns ACL attach health, not OVS
forwarding health. In this run, the tap and XDP attachment remained present
after `ovs-vswitchd` restart, while VM connectivity dropped during the OVS
restart window. Cleanup restored zero managed state and VM connectivity.

The next probe must split the result into two channels:

- ACL attach: tap identity, XDP attachment, ACL maps/policy, generation, WAL,
  and rollback.
- OVS forwarding: VM ping/traffic recovery during OVS maintenance.

This row should remain `degraded` until an ACL-focused `ovs-restart` smoke
proves attach health and rollback independently from immediate OVS forwarding.
