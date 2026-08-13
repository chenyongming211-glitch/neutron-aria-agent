# ACL Active Matrix Soak Design

## Objective

Add a three-compute, bidirectional ACL acceptance soak that repeatedly proves
real Neutron ACL enforcement and rollback without changing the meaning or
evidence of the runtime, fixed-policy, or control-plane churn soaks already in
progress.

This is a pre-release acceptance gate. It is not a new tenant feature and does
not change ACL product behavior.

## Non-Negotiable Constraints

- Use one dedicated CirrOS test VM on each of `compute-a`, `compute-b`, and
  `compute-c`.
- Do not reuse the ports owned by the fixed-policy soak.
- Do not restart or modify OVS, the Neutron OVS agent, or the Rust datapath.
- Do not compile Rust or eBPF locally. This test requires no Rust build.
- Do not run overlapping active-matrix cycles.
- Do not treat unsupported product contracts as positive test cases. In
  particular, a non-`allow` policy default remains a rejection test.
- Any failed cycle stops the active matrix, cleans its current objects on a
  best-effort basis, and preserves evidence. Other soaks keep running.
- Temporary VMs, listeners, policies, rules, bindings, and status rows must be
  removed after the gate.

## Why A Dedicated Topology Is Required

The fixed-policy soak already owns one enabled binding per compute. A second
enabled binding on those ports would make the policy authority ambiguous and
would contaminate the long-duration stability evidence.

Dedicated test VMs provide independent ports for active policy replacement,
bidirectional traffic, connection-state checks, and cleanup verification. A
veth or network-namespace fixture is not a substitute because it does not
exercise the Neutron API, database, RPC notifications, Python agent, UDS
contract, real VM tap, and OVS forwarding path together.

## Test Topology

Each compute hosts one dedicated CirrOS VM with a normal OVS-backed Neutron
port. Every guest provides:

- an ingress TCP echo listener;
- an ingress UDP echo listener;
- SSH-based command execution for guest-originated traffic;
- ICMP reachability in both directions.

Each compute host provides independent TCP and UDP egress targets for its local
guest. Test ports and host-side listener ports are allocated only to this gate
and must not overlap fixed-soak ports.

Traffic verdicts use application-level responses rather than socket-tool exit
codes alone. TCP and UDP probes carry a per-attempt nonce and pass only when
the expected endpoint returns that nonce. UDP is never declared reachable from
`nc -uvz`. ICMP uses bounded echo requests with packet-loss accounting. Before
each policy transition, the harness confirms that every endpoint used as an
allow/drop oracle is listening and answers on the control path.

An independent OVS forwarding canary uses traffic that is outside the active
ACL selectors. It must remain continuously reachable throughout every cycle.

## Concurrent Test Layers

| Layer | Purpose | Policy behavior |
| --- | --- | --- |
| Runtime soak | Detect resource, WAL, pin, process, and readiness drift | Read-only |
| Fixed-policy soak | Prove one policy remains enforced for the full observation window | Stable enabled binding |
| Control-plane churn | Stress API, DB, RPC, generation, and cleanup | Disabled temporary bindings |
| Active matrix soak | Prove repeated real bidirectional enforcement and rollback | Dedicated enabled bindings |

The active matrix does not replace any other layer. Results are reported
separately and correlated only by candidate commit, image digest, and time.

## Active Matrix

Cycles are serialized and begin only after the previous cycle has completed
and cleanup has been verified. A target cadence is recorded, but correctness
takes precedence over a fixed rate.

Across successive cycles, each dedicated VM rotates through these cases:

| Dimension | Required values |
| --- | --- |
| Direction | ingress, egress |
| Protocol | ICMP, TCP, UDP |
| Action | matching traffic dropped; non-matching traffic allowed |
| State mode | stateful, stateless |
| Port selector | single port, bounded range, ports 1 and 65535 |
| Mutation | create, rule update, rule disable/enable, binding disable/enable, policy disable/enable, delete |

Every enabled policy uses `default_action=allow`. Negative contract tests
separately verify that unsupported defaults, protocols, address families, and
source-port selectors are rejected by both API and CLI.

## Cycle Flow

1. Confirm all three dedicated VM ports have no pre-existing Aria ACL binding.
2. Confirm ingress and egress ICMP, TCP, and UDP baselines pass.
3. Create one policy and the cycle's ingress and egress rules.
4. Create an enabled port binding and wait for `ready/enforce` status with the
   exact policy ID, binding ID, port ID, and compute host.
5. Verify each matching direction/protocol is dropped.
6. Verify at least one non-matching protocol and one non-matching port remain
   allowed in each direction.
7. For TCP stateful cycles, establish traffic before a policy mutation and
   verify the publication epoch invalidates stale connection state as required
   by the current lightweight five-tuple contract.
8. Update the selected protocol or port and verify the old selector recovers
   while the new selector is enforced.
9. Disable and re-enable the rule, binding, and policy one boundary at a time,
   verifying traffic and status after each transition.
10. Delete binding, rules, and policy in dependency order.
11. Verify all six direction/protocol baselines recover.
12. Verify no temporary API object, stale host status, or active datapath
    projection remains.
13. Verify all three agent heartbeats report `ready=true`, `degraded=false`,
    and `generation_lag=0`.
14. Verify the independent OVS canary recorded no forwarding gap.

## Stateful Semantics

The product implements lightweight state tracking based on five-tuple,
reply-seen state, and timeout. The soak must not describe this as a strict TCP
SYN/SYN-ACK/ACK state machine.

Stateful cases cover new flows, reverse replies, policy epoch changes, and
stale-state invalidation. Stateless cases prove matching traffic is evaluated
without reusing connection state. Detailed malformed-packet, fragment, and map
pressure tests remain separate privileged gates and are not duplicated here.

Port 1 and port 65535 are exercised with real listeners: the compute-side
egress target may bind privileged port 1 as root, while the guest-side ingress
target uses port 65535. This prevents a closed endpoint from being mistaken for
an ACL drop.

## Timing And Load

- Active cycles run one at a time across all three computes.
- The scheduler ticks once per minute. If a cycle is still running, that tick
  is recorded as skipped; a second cycle is never started concurrently.
- After cleanup, the next cycle begins on the next one-minute scheduler tick.
- A cycle timeout stops this gate; it does not start another cycle in parallel.
- The existing one-minute control-plane churn may continue because its
  bindings are disabled and its namespace is distinct.
- API latency, enforcement convergence, rollback convergence, and total cycle
  time are recorded independently.

## Evidence

The gate writes a manifest and append-only per-cycle evidence containing:

- candidate commit and immutable agent image digest;
- VM, port, and host aliases without credentials;
- case dimensions and generated object IDs;
- create, update, disable, enable, and delete latency;
- observed ingress and egress traffic verdicts;
- effective policy/binding identity and generation;
- heartbeat readiness and generation lag;
- cleanup and OVS-canary result;
- final exit code and completion marker.

Credentials, tokens, passwords, internal endpoint URLs, and raw environment
configuration are never written to repository evidence.

## Failure And Cleanup

The current cycle owns an explicit list of every object it creates. Signal and
error traps delete bindings first, then rules, policies, VMs, and temporary
images/listeners. Cleanup failure is itself a failed gate and is preserved in
the evidence.

The gate never disables a fixed-soak binding, never falls back to local Aria
writes, and never restarts OVS. If guest execution, Neutron API, RPC, UDS, or
datapath status becomes unavailable, the gate records the failing boundary and
stops instead of guessing.

## Exit Criteria

The active matrix passes only when:

- all planned cases completed on all three computes;
- every expected drop and allow verdict matched;
- all policy transitions converged within the configured bound;
- every status identity matched the current port, policy, binding, and host;
- heartbeats remained ready and non-degraded;
- the OVS canary had no forwarding gap;
- every temporary ACL and VM resource was removed;
- no stale status or datapath projection remained.

This pass contributes the bidirectional active-policy portion of release
acceptance. Control-plane fault injection, OpenStack lifecycle, base-network
services, scale limits, rolling upgrade, and rollback remain separate release
gates and must also pass before production release.
