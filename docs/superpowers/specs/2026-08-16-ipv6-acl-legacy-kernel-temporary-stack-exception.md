# IPv6 ACL Legacy-Kernel Temporary Stack Exception

**Date:** 2026-08-16

**Status:** approved product constraint; source implementation and exact-head
hosted verification complete; target-kernel evidence pending

## 1. Decision

The current product generation prioritizes complete IPv4/IPv6 ACL support on
the maintained low-version enterprise kernel. It keeps the existing bounded
monolithic TC datapath and accepts a 480-byte linked call-path ceiling for this
ACL-only generation.

The tail-call architecture remains the required redesign boundary for a later
product generation that adds new datapath capabilities. It is not a dependency
of the current IPv6 ACL delivery. That later generation must first establish a
new minimum kernel contract and re-review the tail-call design against it.

## 2. Evidence And Root Cause

The previously accepted IPv4 artifact consumed the entire 448-byte project
budget while retaining 64 bytes below the kernel's 512-byte combined-stack
limit. Family-qualified IPv6 policy, conntrack, drop, and counter identities
made the IPv6 ingress fast path the new worst path:

```text
tc_ingress                         verifier 32
  -> try_tc_ingress                verifier 32
  -> try_tc_ingress_v6             verifier 192
  -> phase_ct_fastpath_ingress_v6  verifier 192
  -> memset                        verifier 32
                                      total 480
```

Exact-head Build run `31939447667` compiled the eBPF object and passed selected
Rust behavior, Python, database, and clean-install jobs. Its linked-artifact
gate failed only because 480 exceeded the former 448-byte project ceiling.
Repeated isolated stack-shape changes did not lower the 480-byte result. This
shows that the remaining issue is exhausted engineering headroom in the
monolithic call graph, not a missing IPv6 behavior implementation.

The 480-byte ceiling remains below the 512-byte kernel hard limit, but it leaves
only 32 bytes of static margin. It is therefore a frozen product exception, not
general capacity for future features.

## 3. Scope

Allowed in this product generation:

- complete IPv4/IPv6 ACL family isolation;
- ACL conntrack, fragment, counters, persistence, capability and API fixes;
- verifier/load compatibility fixes that do not expand product behavior;
- tests, packaging, rollback and real-environment evidence.

Not allowed in the monolithic TC artifact:

- new or expanded Mirror behavior;
- new or expanded QoS behavior;
- load balancing or NAT service processing;
- DDoS or broadcast-storm processing;
- any other non-ACL datapath feature;
- raising the ceiling above 480 bytes.

Existing code is not removed merely because a capability is outside this
generation's expansion scope. The constraint governs new datapath growth and
enablement.

## 4. Release Gates

The current generation is accepted only when all of the following hold:

1. The release eBPF object builds with warnings denied.
2. The linked call graph reports no TC entry path above 480 bytes.
3. Any future path increase to 512 bytes is rejected.
4. IPv4 and IPv6 family-isolation behavior tests pass.
5. The exact maintained kernel
   `4.18.0-553.5.1.el8_10.x86_64` loads and attaches both TC directions.
6. Real IPv4/IPv6 allow and deny cases pass without cross-family verdict bleed.
7. Scratch/load failure preserves fail-open OVS forwarding.
8. Rollback restores the previous accepted artifact and normal port traffic.

Items 5 through 8 remain `deferred/pending` until executed in the user's test
environment. Hosted CI must not report them as field PASS.

Exact-head commit `0eafc85c14e7cdad2ad1f3e7a2ba4752a3c2f7af` passed Build
[`31940674926`](https://github.com/chenyongming211-glitch/neutron-aria-agent/actions/runs/31940674926):

- `rust-build` job `95149272171` passed warning-denied eBPF, userspace and
  agent builds, the 480-byte linked stack gate, static verification and release
  packaging;
- `rust-behavior` job `95149272257` passed the selected IPv6/family behavior
  tests;
- fast contracts, Neutron database contracts and clean-package installation
  all passed.

This is source and hosted-artifact evidence only. It does not close the exact
4.18 verifier/load or OpenStack traffic rows.

## 5. Later Product Generation

Requesting Mirror, QoS, load balancing, DDoS, broadcast-storm suppression, or
another datapath feature triggers a new architecture review. Before coding:

1. set and document a higher minimum kernel version;
2. run exact-kernel tail-call/subprogram capability canaries;
3. revise the deferred tail-call design for that kernel;
4. migrate as one architecture rather than retaining two production runtimes;
5. restore per-stage stack and performance margins suitable for future growth.

The deferred design is recorded in
`2026-08-16-tail-call-datapath-architecture-design.md`. Its existence does not
authorize tail-call implementation in the current ACL-only generation.
