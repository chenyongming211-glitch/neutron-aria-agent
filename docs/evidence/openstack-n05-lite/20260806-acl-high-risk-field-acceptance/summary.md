# ACL High-Risk Field Acceptance Summary

Date: 2026-08-06

Environment: a Kolla-based test cloud with a legacy 4.18 kernel and legacy TC
attachment. Host, port, VM, address, credential, and tenant identifiers are
intentionally replaced with aliases.

This record covers ACL risk closure only. It does not enable QoS, Mirror, or a
new production feature gate.

## Results

| Scenario | Result | Evidence boundary |
| --- | --- | --- |
| IPv4 and IPv6 fragments with ACL/conntrack | pass | Both TC directions passed ordered fragments, post-first reordering, later-before-first fail-closed behavior, VLAN isolation, tap isolation, publication-epoch invalidation, restart scrub, bounded LRU pressure, oldest-key eviction, and cleanup. |
| ACL selector and local group isolation | pass | A privileged standalone tap fixture proved that ACL selector ownership is isolated from general local groups and that conflicting projection cannot silently widen policy. |
| Continuous traffic during create, update, delete, and rollback | pass | Existing traffic was observed before policy, blocked after enforcement, and restored after cleanup without OVS mutation. |
| Python control-plane agent restart | pass | ACL enforcement did not open during restart. The independent OVS canary recorded 81 successful probes and zero failures. |
| Rust datapath restart | pass with availability-first recovery | The datapath recovered ACL state through reconciliation in about 58 seconds. The independent OVS canary recorded 291 successful probes and zero failures. ACL may temporarily bypass while authority is rebuilding; OVS forwarding remained available. |
| Tap recreation | pass with documented enforcement gap | The tap ifindex changed and ACL enforcement recovered in about 60 seconds. The independent OVS canary recorded 350 successful probes and zero failures. Zero-window enforcement is not guaranteed during tap absence/recreation. |
| Explicit port detach and cleanup | pass | The real Neutron detach path removed the tap, converged runtime and generation state, cleared ACL ownership, and preserved the explicitly created detached port. The independent OVS canary recorded 291 successful probes and zero failures. |
| Detach transaction fault injection | pass | An isolated direct-snapshot fixture on the target kernel verified detach ordering, ACL purge-failure atomicity, strict CT-flush rollback, and successful retry detach against real pinned maps. The independent OVS canary recorded 223 contiguous replies and zero gaps. |
| Three-node UDS peer authorization | pass | The current Rust datapath build accepted the authorized Neutron peer on all three compute nodes, rejected and audited an unauthorized host-root client, preserved the hardened socket boundary, and produced zero independent OVS canary gaps. |

## 2026-08-07 Completion Pass

| Scenario | Result | Evidence boundary |
| --- | --- | --- |
| Same-generation managed ACL projection repair | pass | Commit `445dcec` and hosted Build `31146831997` passed the maintained Rust and package gates. A controlled active-selector drift was detected and repaired without changing the snapshot generation; strict conntrack invalidation made the deny rule effective, and an independent OVS canary recorded 1,392 contiguous replies with zero gaps. |
| RPC P2 convergence soak | pass | A five-minute run collected 29 aligned samples across the three compute nodes. ACL notifications converged in approximately one second, with no pending generation, restart, or disallowed startup-log condition. Independent OVS canaries recorded zero gaps. |
| Legacy Neutron ACL pagination and query bounds | pass | The target Python 2, Neutron 9, and SQLAlchemy 1.0 runtime completed forward/reverse and custom-marker list coverage without N+1 behavior. Observed SQL query budgets were 1 for a normal page, 2 for a custom-marker page, 1 for address sets without members, and 2 with members. |
| Orphan full runtime scrub, retry, and sibling protection | pass | Commit `b18dd3c` and hosted Build `31154605848` passed the maintained Rust, eBPF, package, and static gates. An isolated target-kernel fixture audited 29 available tap-scoped map families, reduced the orphan identity from 13 entries to zero, preserved all 13 sibling entries, retained the retry marker after an injected scrub failure, and completed cleanup after repair. Orphan legacy TC ingress and egress filters were detached while sibling filters remained attached. The fixture used private taps, pins, state, and bridge resources and did not mutate `br-int`, OVS, or the OVS agent. |
| Final three-node runtime health | pass with one pre-existing port degradation | All required Aria, Neutron-Aria, and OVS-agent containers were running with zero restarts. Accepted and applied generations were aligned, no transaction was pending, and authority was ready on all nodes. Two nodes reported overall ready; one node reported degraded only because an existing port referenced a missing or disabled policy. |
| Standalone tap and system XDP coverage | partial | Standalone `tap` mode passed. The legacy target kernel did not provide valid Aya pinned-link evidence for the standalone system/XDP path and returned `FdLink InvalidLink`; that exact XDP activation proof remains gated rather than being recorded as pass. |

## Field Defects Closed

The acceptance run exposed and verified three bounded lifecycle repairs:

- missing-interface legacy TC observation is idempotent instead of treating a
  deleted tap as a permanent cleanup error;
- delete recovery skips an impossible ACL purge only when the interface is
  already absent, while retaining strict purge behavior for an existing tap;
- the Python synchronizer accepts the exact normalized
  `classified/degraded/full_resync` recovery state when the deleted port is
  absent, allowing the required full resync to finish the transaction.

Hosted builds for the repair commits passed Rust behavior, warning-denied
Rust/eBPF builds, and the Neutron package gates before the clean field rerun.

The completion pass also closed a legacy-TC orphan gap found by the field RED:
old-kernel TC filters are kernel-owned and have no link pin, so orphan cleanup
must run the full owned detach path before map scrub. The repaired path verifies
program ownership before detaching those filters and keeps the retry marker
until every required cleanup step succeeds.

## Safety Conclusion

Aria did not restart or mutate OVS or the OVS agent in this acceptance pass.
Failures and restart recovery followed the availability-first contract:
unknown or rebuilding ACL authority may report degraded/bypass, but it must not
block the original OVS forwarding path. The independent canary had zero packet
loss in every restart, recreation, and detach observation above.

## Residual Boundaries

- Fragment tracking is field-verified, but the shipped production gate remains
  disabled until a separate change-controlled rollout enables it.
- Tap recreation and datapath restart do not provide zero-window ACL
  enforcement. Current recovery time is bounded by reconciliation/polling and
  was approximately one minute in this environment.
- Successful detach cleanup and isolated real-pinned-map purge/flush failure
  behavior are field-verified. The fault fixture used private state, pins, and
  a synthetic tap; it did not mutate a production VM port.
- A classified/degraded overall summary may include unrelated ineligible ports.
  Lifecycle acceptance requires no pending generation, no required action, and
  convergence of the target port transaction rather than a globally perfect
  classification count.
- Exact standalone system/XDP pinned-link recovery remains an activation gate on
  the legacy target kernel. Standalone tap coverage does not substitute for that
  evidence.
