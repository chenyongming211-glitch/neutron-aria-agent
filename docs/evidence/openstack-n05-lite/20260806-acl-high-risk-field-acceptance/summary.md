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
- Successful detach cleanup is field-verified. Injected purge/flush failure
  while the tap still exists remains a separate privileged fault-path gate.
- A classified/degraded overall summary may include unrelated ineligible ports.
  Lifecycle acceptance requires no pending generation, no required action, and
  convergence of the target port transaction rather than a globally perfect
  classification count.
