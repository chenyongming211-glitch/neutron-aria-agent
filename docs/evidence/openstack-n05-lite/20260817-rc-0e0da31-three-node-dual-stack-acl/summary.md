# RC 0e0da31 Three-Compute IPv4/IPv6 ACL Acceptance

Date: 2026-08-17

## Scope

This acceptance validates the deployed `rc-0e0da31` Kolla candidate on the
three test computes. It covers real Neutron `aria_acl` objects and real VM
traffic. It does not claim the separate fragment, host-reboot, scale, or soak
gates.

IPv4 and IPv6 were exercised through separate Neutron ports on paired test
VMs. This evidence does not claim the separate same-port dual-stack case.

Aria did not restart or modify OVS or the Neutron OVS agent during this run.

## Candidate

- Source and image tag: `0e0da31`, `rc-0e0da31`.
- Kernel on all computes: `4.18.0-553.5.1.el8_10.x86_64`.
- `aria-agent` SHA-256:
  `9e446efaab37b733852d978f2e5a45d409c7682eb8a5ff316a239c5b86966e4b`.
- eBPF SHA-256:
  `b70f5f1e57f005c17aa262d3cde757764577df9a0c187aac0f5f682f7bee3e63`.
- Both Aria containers declared Docker healthchecks and finished healthy on
  every compute.

## IPv4 Result

Each compute used one source and one destination CirrOS VM. The destination
port received a temporary policy with IPv4 ingress drops for ICMP, TCP/8080,
and UDP/1080.

All three computes passed:

1. baseline ICMP/TCP/UDP connectivity;
2. policy/rule/binding creation and `ready/enforce` identity projection;
3. simultaneous ICMP, TCP/8080, and UDP/1080 blocking;
4. disabling only the TCP rule restored TCP while ICMP and UDP stayed blocked;
5. restoring the rule blocked TCP again;
6. disabling the policy produced `degraded/bypass` and restored traffic;
7. re-enabling the policy returned to `ready/enforce`;
8. disabling the binding produced `not_requested/bypass` and restored all
   traffic;
9. deleting the binding, rules, and policy left no temporary object.

Observed IPv4 update convergence was approximately 2.7 to 5.3 seconds.

## IPv6 Result

The existing test VLAN contains one IPv6 source/destination VM pair on each
compute. Same-compute and cross-compute TCP/8080 and UDP/1080 baselines passed.

All three computes passed:

1. IPv6 policy/rule/binding creation and exact `ready/enforce` projection;
2. ICMPv6, TCP/8080, and UDP/1080 ingress blocking;
3. binding-disable rollback to `not_requested/bypass` with all traffic restored;
4. stateful TCP/UDP replies with explicit egress drops;
5. `stateful=false` blocking those replies;
6. restoring `stateful=true` restoring replies;
7. explicit ICMPv6 allow after neighbor-cache flush, proving NS/NA completion;
8. IPv6 ingress deny-any after neighbor-cache flush, producing a failed
   neighbor entry and no echo reply;
9. detach rollback restoring neighbor discovery and ICMPv6 immediately.

Observed IPv6 enforce convergence was approximately 1.9 to 2.4 seconds and
binding-disable convergence was approximately 2.5 to 3.3 seconds.

The ND result matches the product contract: there is no hidden ND/RA/MLD ACL
bypass. Explicit allow permits ND; deny-any may block it.

## Health And OVS Safety

One controlled enabled-binding/disabled-policy case produced
`degraded/bypass`. Docker health changed as follows:

- both containers started `healthy`;
- the datapath became `unhealthy`, followed by the Python agent;
- both were `unhealthy` by health poll 17 (five-second observation polls);
- after policy recovery, both returned to `healthy` by poll 6.

During the full negative-health interval, the independent OVS canary received
596 of 596 replies with zero loss. The `ovs-vswitchd` PID and Neutron OVS agent
start identity were unchanged.

## Final State

- All three Aria heartbeats are alive, `ready=true`, `degraded=false`, and
  `generation_lag=0`.
- Final accepted/applied generations are equal on every compute.
- All six target IPv4/IPv6 ports are `not_requested/bypass` with reason
  `no_enabled_binding`.
- No temporary policy or binding prefix from this run remains.
- Final IPv6 TCP/UDP same-compute and cross-compute probes pass.
- Both Aria containers are healthy on all three computes.
- No new Aria ERROR, CRITICAL, panic, or fatal-runtime entry was found in the
  test window.
- OVS and the Neutron OVS agent retained their long-running identities.

## Result

Result: **PASS** for the stated three-compute IPv4/IPv6 ACL RC matrix.
