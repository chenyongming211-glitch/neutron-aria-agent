# IPv6 Transport And ND Joint Acceptance

Date: 2026-08-20

## Scope

This gate validates real IPv6 TCP, UDP, and Neighbor Discovery traffic for the
exact `rc-6144bf36` Rust/eBPF candidate on all three admitted test computes.
It covers both same-compute and cross-compute VLAN east-west paths. It does not
claim L3 routing, DNS, floating IP, or north-south behavior because those
capabilities are not present in this test environment.

The environment uses VLAN networks, DHCP-based VM address allocation, and an
external switch gateway. Aria did not restart or modify OVS or the Neutron OVS
agent during this run.

## Candidate Identity

- Source commit: `6144bf36`.
- GitHub Actions run: `32334693695`, result `success`.
- Datapath image ID on all three computes:
  `sha256:3c6f96376ffdfca8788b48ab5aa0e5fc8bf6b94e9d2b4e87f408481f4cf69a1a`.
- `aria-agent` SHA-256:
  `a6e069fcaa06c6fc80d0cdf8e03ce86780f53d5d5473801121784923e8d4347f`.
- eBPF ingress/egress object SHA-256:
  `b70f5f1e57f005c17aa262d3cde757764577df9a0c187aac0f5f682f7bee3e63`.

## Traffic Matrix

Three source/destination VM pairs ran on the real IPv6 VLAN. Each destination
provided IPv6 TCP echo on port 8080 and IPv6 UDP echo on port 1080.

| Path set | Paths | Result |
| --- | --- | --- |
| Same compute | node-a to node-a, node-b to node-b, node-c to node-c | pass |
| Cross compute | node-a to node-b, node-b to node-c, node-c to node-a | pass |

Each path set verified:

1. ICMPv6, TCP, and UDP baseline allow;
2. stateful ingress TCP/8080 and UDP/1080 drop with exact
   `ready/enforce` policy and binding identity;
3. TCP rule disable restored only TCP while UDP remained blocked;
4. TCP rule re-enable restored enforcement;
5. an ingress deny-any ICMPv6 rule blocked echo and ND;
6. ICMPv6 rule disable restored ND and echo while TCP/UDP remained blocked;
7. policy disable restored all three protocols and reported bypass;
8. policy re-enable restored enforcement;
9. binding disable restored all traffic and reported
   `not_requested/bypass`;
10. policy, rules, and bindings were deleted without residue.

The two path sets produced 176 expected-result markers in total. All markers
passed, including expected drop observations.

## Neighbor Discovery

The source VM neighbor entry was flushed before every ND verdict check. With
the broad ICMPv6 drop active, all six same-compute/cross-compute paths failed
to resolve the destination and reached a failed neighbor state. After the rule
was disabled, every path resolved the neighbor again and completed ICMPv6
echo. This confirms the current product contract has no hidden ND bypass.

## Safety And Final State

Independent OVS forwarding canaries used ports separate from the IPv6 ACL
targets and recorded:

| Compute | Samples | Missing sequence | Error lines |
| --- | ---: | ---: | ---: |
| node-a | 3,791 | 0 | 0 |
| node-b | 3,789 | 0 | 0 |
| node-c | 3,789 | 0 | 0 |
| Total | 11,369 | 0 | 0 |

At cleanup:

- all three target ports were `not_requested/bypass/no_enabled_binding`;
- each target had zero ACL bindings;
- neither test policy remained;
- all three Aria agents reported `ready=true`, `degraded=false`, and
  `generation_lag=0`;
- both Aria containers were healthy with zero restart count on every compute;
- the observed `ovs-vswitchd` start times predated the test and no OVS restart
  was performed.

## Private Raw Evidence

Raw evidence is retained outside the public repository because it contains
environment-specific host, address, port, and object identities:

- node-a archive:
  `45bc3161ae50c311bf2372b78e3bf31f8b09f59654434cf481546de652be1d04`;
- node-b archive:
  `cb54e781448281f271a9ce977ecf9b12e9959bec753f5b2fdcc309426f5aba76`;
- node-c archive:
  `4c74caae1d76a4f158274e1b7291b677a0f8ff41c70157cd530d6c4446823ebc`.

## Result And Boundary

Result: **PASS** for current-candidate IPv6 TCP/UDP ingress enforcement,
stateful echo return traffic, explicit ND behavior, rule/policy/binding
lifecycle, cleanup, and same-compute/cross-compute VLAN east-west paths.

IPv6 egress-rule direction, valid extension headers, fragmented UDP, and
same-port dual-stack behavior for this exact candidate are recorded separately
in `../20260820-rc-6144bf36-ipv6-egress-fragment-dual-stack/summary.md`. L3
agent, DNS, floating IP, and north-south cases are `N/A` for this environment
rather than product failures.
