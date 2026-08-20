# IPv6 Egress, Fragment, And Dual-Stack Acceptance

Date: 2026-08-20

## Scope

This gate validates the remaining planned IPv6 functional paths for the exact
`rc-6144bf36` Rust/eBPF candidate: IPv6 egress direction, valid IPv6 extension
headers, fragmented IPv6 UDP, and IPv4/IPv6 isolation on one Neutron port.
The environment provides VLAN L2 east-west networking only. L3 agent, DNS,
floating IP, and north-south cases are not applicable here.

Aria did not restart or modify OVS or the Neutron OVS agent during this run.

## Candidate Identity

- Source commit: `6144bf36`.
- GitHub Actions run: `32334693695`, result `success`.
- Datapath image ID on all three computes:
  `sha256:3c6f96376ffdfca8788b48ab5aa0e5fc8bf6b94e9d2b4e87f408481f4cf69a1a`.
- `aria-agent` SHA-256:
  `a6e069fcaa06c6fc80d0cdf8e03ce86780f53d5d5473801121784923e8d4347f`.
- eBPF ingress/egress object SHA-256:
  `b70f5f1e57f005c17aa262d3cde757764577df9a0c187aac0f5f682f7bee3e63`.

## IPv6 Egress Result

Three real source/destination VM pairs were exercised on the IPv6 VLAN. Both
same-compute and cross-compute ring paths passed. Each path set verified:

1. ICMPv6, TCP/8080, and UDP/1080 baseline allow;
2. egress TCP and UDP rules bound to the source Neutron port;
3. exact `ready/enforce` policy, binding, port, and source-host identity;
4. TCP rule disable restored only TCP while UDP remained blocked;
5. TCP rule re-enable restored enforcement;
6. egress ICMPv6 deny blocked echo and neighbor resolution after cache flush;
7. ICMPv6 rule disable restored ND while TCP/UDP remained blocked;
8. policy disable/enable and binding disable lifecycle;
9. final `not_requested/bypass` and object cleanup.

The same-compute and cross-compute runs each produced 88 expected-result
markers, for 176 passing markers in total.

## Extension Header And Fragment Result

A real source VM emitted raw IPv6 UDP frames using:

- Hop-by-Hop Options;
- Destination Options;
- a Hop-by-Hop plus Destination Options chain.

All three forms completed a 32-byte UDP echo at baseline, were blocked by the
IPv6 ingress UDP rule, and completed again after rollback.

A separate 4,096-byte UDP echo was captured as three IPv6 fragments in each
direction: the initial fragment and two non-initial fragments. The datagram
completed at baseline, timed out while the UDP ACL was enforced, and completed
again after rollback. The capture recorded six fragments with zero kernel
capture drops.

This is current-candidate functional evidence for valid extension headers and
real fragmented delivery. It does not replace the deeper malformed-chain,
different-tap/VLAN isolation, out-of-order, overlap, pressure, and stale-cache
fragment gates.

## Same-Port Dual-Stack Result

One existing IPv6 VLAN source/destination port pair temporarily received an
additional IPv4 fixed address from a no-gateway, DHCP-disabled test subnet.
The guests configured the same interface with both addresses. One policy then
used two rules with the same numeric priority:

- IPv4 ingress TCP drop on the IPv4 echo port;
- IPv6 ingress UDP drop on the IPv6 echo port.

The IPv4 rule blocked only IPv4 TCP. IPv4 UDP, IPv4 ICMP, IPv6 TCP, and ICMPv6
remained available. The IPv6 rule blocked only IPv6 UDP. Disabling and
re-enabling either rule did not change the other family's verdict. Rollback
restored all six protocol/family probes.

The accepted rerun produced 27 passing expected-result markers. An initial
pre-ACL attempt used an IPv6-only echo listener for the temporary IPv4 address
and failed at the IPv4 TCP baseline. It never created an ACL policy, rule, or
binding, cleanup completed, and it is retained only as test-harness evidence.

## Safety And Final State

Independent OVS forwarding canaries recorded:

| Compute | Samples | Missing sequence | Error lines |
| --- | ---: | ---: | ---: |
| node-a | 6,769 | 0 | 0 |
| node-b | 6,768 | 0 | 0 |
| node-c | 6,768 | 0 | 0 |
| Total | 20,305 | 0 | 0 |

At cleanup:

- all six source/destination ports were `not_requested/bypass` with zero test
  bindings;
- all temporary policies, rules, bindings, IPv4 fixed addresses, the temporary
  IPv4 subnet, and dedicated IPv4 echo listeners were removed;
- all three Aria agents reported `ready=true`, `degraded=false`, and
  `generation_lag=0`;
- both Aria containers were healthy with zero restart count on every compute;
- the observed `ovs-vswitchd` start times predated the test and no OVS restart
  was performed.

## Private Raw Evidence

Raw evidence is retained outside the public repository because it contains
environment-specific host, address, port, and object identities:

- node-a archive:
  `da71ded327ab3192b8952897b1a82fa5bbdbb5ec1157d7264d32646d29b9af01`;
- node-b archive:
  `9f392081d9445d9795a87e9ef0f35ec49ed7f5ea4cdcffe9e8b33ae39e916d6e`;
- node-c archive:
  `bd2bf090be09753db7a438d5f88ad933e4576e97e28efe77855ef288fe74dffa`.

## Result And Remaining Boundary

Result: **PASS** for current-candidate IPv6 egress direction, valid extension
headers, fragmented UDP delivery and rollback, and same-port IPv4/IPv6 family
isolation.

The broader ACL6-005/006 deep gates still include established-connection
revision invalidation, malformed extension chains, fragment ordering/overlap,
different-tap/VLAN isolation, and pressure behavior. They are not claimed by
this functional acceptance.
