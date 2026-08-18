# IPv4 and IPv6 Joint ACL Acceptance Summary

Date: 2026-08-18

This acceptance used three Kolla compute nodes on the target legacy 4.18
kernel. Environment-specific host names, addresses, VM identifiers, port
identifiers, project identifiers, and credentials are intentionally omitted.

The deployed Rust/eBPF candidate remained `aria-datapath:rc-0e0da31` and the
Python candidate remained `neutron-aria-agent:rc-0e0da31`. All nodes used the
same candidate images. The tested `aria-agent` SHA-256 was
`9e446efaab37b733852d978f2e5a45d409c7682eb8a5ff316a239c5b86966e4b`; the
tested eBPF object SHA-256 was
`b70f5f1e57f005c17aa262d3cde757764577df9a0c187aac0f5f682f7bee3e63`.

## Results

| Scenario | Result | Evidence boundary |
| --- | --- | --- |
| Same-port dual stack | pass | One real VM port carried temporary IPv4 and existing IPv6 fixed addresses. IPv4 ICMP/TCP/UDP and IPv6 ICMPv6/TCP/UDP were independently blocked and restored. IPv4-only rules did not block IPv6, and IPv6-only rules did not block IPv4. |
| Three-node fanout | pass | Two policies and six bindings covered an IPv4 port and an IPv6 port on each compute node. All six ports reached `ready/enforce`, blocked the selected traffic, then reached `not_requested/bypass` and restored traffic after binding disable. |
| Policy and binding lifecycle | pass | Policy disable restored both families and reported bypass. Policy enable restored enforcement. Binding disable restored both families and reported `no_enabled_binding`. |
| Address sets | pass | IPv4 and IPv6 address sets matched exact source members. Replacing members with nonmatching addresses restored traffic. A mixed-family address set was rejected by the API. |
| CIDR and priority behavior | pass | Exact `/32` and `/128` allow rules won over broader `/24` and `/64` drop rules at the selected priority. Disabling exact rules exposed the broader drops. |
| Port boundaries | pass with one probe limitation | TCP ports 1 and 65535 were blocked for IPv4 and IPv6. UDP ports 1 and 65535 were blocked for IPv4. Ranges ending at 65535 were enforced and traffic outside the range remained available. IPv6 UDP ports 1 and 65535 are not claimed because the temporary guest listener did not provide a reliable IPv6 UDP boundary echo. |
| IPv6 extension headers | pass | UDP traffic with Hop-by-Hop, Destination Options, and a Hop-by-Hop plus Destination Options chain passed without ACL, was blocked by the IPv6 UDP rule, and passed after rollback. |
| IPv6 fragmented UDP | pass | A 4096-byte UDP probe produced first-fragment, non-initial, context-insert, and context-hit counter deltas. The port rule blocked the fragmented datagram and rule deletion restored it. |
| IPv4 fragmentation | pass | A 4000-byte ICMP probe passed without the rule, was blocked by the IPv4 ICMP rule, and passed after rollback. |
| Python agent restart | pass | IPv4 and IPv6 ACL remained enforced during restart. An independent OVS canary completed 300 of 300 probes with zero loss; the OVS datapath process identity did not change. |
| Rust datapath restart | pass | Protected IPv4 and IPv6 probes each sent 600 packets and observed zero unintended replies. The independent OVS canary completed 700 of 700 probes with zero loss. ACL status recovered to `ready/enforce`; OVS process identity did not change. |
| VM soft reboot and tap recreation | pass | The real tap ifindex changed from the pre-reboot value to a new value. After guest test-address restoration, all six IPv4/IPv6 protocol probes remained blocked. An independent OVS canary completed 900 of 900 probes with zero loss. |
| RPC-triggered full resync | pass | Policy updates produced `aria_domain_update` event batches and full-host resync, rather than waiting for the periodic interval. CLI-observed disable and enable convergence were approximately 6.3 and 5.0 seconds. Agent logs showed event merge, UDS submit, generation convergence, and heartbeat completion. |
| Multi-port sustained updates | pass | Ten cycles simultaneously enabled and disabled six bindings across three nodes. Enable convergence was 2.774-7.058 seconds with a 4.037-second median. Disable convergence was 3.177-7.630 seconds with a 3.603-second median. |
| OVS isolation during sustained updates | pass | Three independent canaries each completed 951 of 951 probes, for 2,853 successful probes and zero loss. Aria did not restart or modify OVS or the OVS agent. |
| Cleanup | pass | All acceptance policies, rules, bindings, address sets, temporary IPv4 fixed addresses, and the temporary IPv4 subnet were removed. The target port returned to `not_requested/bypass/no_enabled_binding`. |

## Final Runtime State

All three Aria agents reported:

- `ready=true`;
- `degraded=false`;
- `generation_lag=0`;
- accepted, applied, submitted, and reported generations aligned;
- RPC full-resync enabled and incremental RPC disabled;
- Heartbeat schema version 2.

Both Aria containers were healthy on every node. The recorded OVS process
identities were unchanged by the acceptance run.

## Findings and Boundaries

The `openstack_client` container initially contained an older CLI package whose
argument parser exposed only IPv4. The current client package passed its unit
suite and was installed into the test container without a restart; IPv6 CLI
creation then worked. This is deployment drift, not a Neutron API or datapath
IPv6 failure, and the release package must carry the current client extension.

Combining an earlier wildcard-selector port-boundary rule with a later
specific-selector rule caused the documented
`unsupported_acl_priority_overlap` pre-degradation. The port correctly reported
`degraded/bypass` instead of partially programming an ambiguous rule set. The
test continued after the earlier rule group was disabled. This behavior is a
known product contract boundary, not recorded as successful priority
composition.

This run did not repeat a binary downgrade and upgrade. The Kolla runtime-safe
upgrade and rollback result for this candidate lineage is recorded separately
in `../20260817-kolla-ebpf-runtime-safe-upgrade/summary.md`.

## Safety Conclusion

The current release candidate passed the combined IPv4/IPv6 ACL functional,
fragment, extension-header, RPC, restart, tap-recreation, and sustained-update
acceptance covered here. No observed Aria failure or lifecycle action disrupted
the independent OVS forwarding canaries.
