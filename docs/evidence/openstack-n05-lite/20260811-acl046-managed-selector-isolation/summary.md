# Managed ACL Selector Isolation Field Evidence

Date: 2026-08-11

Environment: a Kolla-based test cloud with a legacy 4.18 kernel and legacy TC
attachment. The two available compute nodes are identified only as Compute A
and Compute B. Host, port, VM, address, policy, binding, group, credential, and
tenant identifiers are intentionally omitted or replaced with aliases.

This record closes `REVIEW-ACL-046`. It does not enable QoS, Mirror, or a new
production feature gate. The unavailable third compute is tracked separately
by the wider P5 rollout gate.

## Result

| Scenario | Compute A | Compute B | Acceptance evidence |
| --- | --- | --- | --- |
| Baseline without ACL binding | pass | pass | Target VM traffic was reachable and the port reported `not_requested/bypass`. |
| Exact-CIDR local group versus managed selector | pass | pass | Real Neutron `aria_acl` policy/rule/binding projection kept the managed selector authoritative; the deny verdict was observed and conntrack remained empty. |
| More-specific local CIDR versus managed selector | pass | pass | The local group remained outside the managed ACL bank and could not widen the managed policy. |
| Injected legacy selector pollution | pass | pass | The polluted active bank initially exposed the local identity. Managed publication repaired it to the selector identity, restored the deny verdict, and strictly cleared conntrack. |
| Datapath restart after repair | pass | pass | The active selector content remained correct, the legacy local identity was absent from general and both ACL banks, inventory returned ready, and no second repair was required. |
| Cleanup and forwarding safety | pass | pass | Test policy/rule/binding objects were removed, each port returned to `not_requested/bypass`, VM traffic recovered, and OVS plus the OVS agent retained their pre-test process identity. |

All required core datapath checks passed on both computes:

- managed ACL bank revalidation;
- deny verdict with zero conntrack state;
- TC ingress and egress execution;
- no ingress double counting;
- stateless path with zero conntrack state;
- required TC link presence;
- XDP remained neutral for ACL and conntrack.

## Harness Corrections

The field run exposed test-harness assumptions rather than product defects:

- the legacy target `curl` does not support `--fail-with-body`, so the managed
  smoke uses portable `--fail`;
- enforced UDS peer credentials correctly reject a host-root probe, so status
  is read from the authorized Neutron container identity;
- background RPC or periodic resync can overlap an explicit smoke resync, so
  the harness waits for stable accepted/applied generation convergence first;
- a managed background reconcile may repair injected pollution before the
  explicit request. Both observed-background and explicit repair modes require
  the same final selector, deny, and conntrack-zero evidence;
- the active ACL bank number is a process-local double-buffer slot and may be
  reinitialized after restart. Selector content, absence of the legacy group,
  readiness, and traffic verdict are the persistent acceptance invariants.

The target hosts did not provide host-installed `tc` and `bpftool`; the field
fixture used isolated, previously staged diagnostic binaries only for evidence
collection. No product image package was changed by this setup.

## Safety Conclusion

The smoke restarted only the Aria datapath where restart recovery was part of
the scenario. It did not restart or modify OVS, the OVS agent, Nova, or
Neutron server. Final residual-object checks were empty on both computes, and
the original OVS forwarding path remained available after cleanup.
