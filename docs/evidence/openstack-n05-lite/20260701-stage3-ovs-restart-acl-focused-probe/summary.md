# Stage-Three N3 OVS Restart ACL-Focused Probe

Date: 2026-07-01
Target: ostack2.bj159.net

## Purpose

Validate the stage-three OVS restart lifecycle gate using the corrected Aria
boundary: Aria owns ACL attach health, not OVS forwarding health. The smoke
therefore decides pass/fail from tap identity, XDP attachment, ACL map/policy
state, UDS generation, WAL stability, and rollback cleanup. VM ping is recorded
as OVS forwarding observation only.

This test was run in the controlled test environment. Production Aria runtime
must not trigger OVS or OVS agent restart.

## Inputs

- Script: `deploy/kolla/smoke/neutron_aria_ovs_restart_smoke.sh`
- Remote evidence root:
  `/tmp/aria-stage3-ovs-restart-acl-focused-20260701130722`
- Target VM IP: `10.58.159.28`
- Target port: `39adf570-1acb-4e81-9215-96744a6bf627`
- Target tap: `tap39adf570-1a`
- Test action: `TEST_TRIGGER_OVS_RESTART=true`
- OVS service: `ovs-vswitchd.service`
- ACL fixture:
  - src CIDR: `198.51.100.1/32`
  - dst CIDR: `198.51.100.2/32`
  - protocol: `icmp`
- `ROLLBACK=true`
- `WAL_REPLAY_FAILURE_MAX_DELTA=0`

The ACL fixture used non-matching documentation CIDRs, so VM ping was not
expected to be intentionally blocked by ACL policy.

## Preconditions

- Baseline VM forwarding passed before ACL managed state was applied.
- Existing managed ports were cleaned before the run:
  - `rollback_remaining_managed_ports=0`
- The target host carried a historical WAL replay failure baseline:
  - wal_replay_failures: 219
  - max_delta: 0

## Observed Flow

- ACL full-resync submitted snapshot generation 148.
- Five local compute ports became managed by ACL.
- Target port was managed before OVS restart:
  - port: `39adf570-1acb-4e81-9215-96744a6bf627`
  - ifname: `tap39adf570-1a`
  - ifindex: 71
  - managed_domains: `acl`
- Target ACL domain was reported:
  - status: `ready`
  - effective_action: `enforce`
- Datapath ACL state contained drop policy/map state for the target tap.
- The test harness explicitly restarted `ovs-vswitchd.service`.
- After OVS restart, the ACL attach case was:
  - `tap_exists_same_ifindex_xdp_attached`
- Target ACL attach remained healthy after restart:
  - port: `39adf570-1acb-4e81-9215-96744a6bf627`
  - ifname: `tap39adf570-1a`
  - ifindex: 71
  - generation: 148
  - status: `ready`
  - effective_action: `enforce`
- Datapath ACL policy/map state remained visible after restart.
- OVS forwarding observation:
  - before restart: pass
  - after restart: pass after 8 seconds
  - final: pass after 1 second
- Rollback deleted all five managed ACL ports and left:
  - `rollback_remaining_managed_ports=0`

## Final State

- generation: 148
- accepted_generation: 148
- applied_generation: 148
- authority_state: `ready`
- pending_generation: null
- managed_count: 0
- port_statuses: empty
- wal_status: `commit_written`
- wal_replay_failures: 219
- post-smoke VM ping: 3 packets transmitted, 3 received, 0% packet loss
- containers remained running:
  - `aria_datapath`
  - `neutron_aria_agent`
  - `neutron_openvswitch_agent`
  - `openstack_client`

## Disposition

`pass`.

The corrected ACL-focused OVS restart lifecycle gate passed. OVS restart did
not require Aria to inspect OVS forwarding internals. The target tap remained
present with the same ifindex and XDP attachment, ACL status stayed
ready/enforce, ACL maps remained present, rollback removed all managed datapath
ports, and the WAL replay failure counter did not increase.
