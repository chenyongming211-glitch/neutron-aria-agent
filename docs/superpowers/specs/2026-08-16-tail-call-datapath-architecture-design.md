# Aria Tail-Call Datapath Architecture Design

**Date:** 2026-08-16

**Status:** deferred design reserve. It is not implemented for the current
ACL-only low-kernel product generation. Reopen only when a new datapath feature
also raises and revalidates the minimum kernel contract.

**Supersedes:** the bounded monolithic TC pipeline as the long-term architecture
in `2026-08-04-ebpf-legacy-stack-budget-design.md`

## 1. Deferred Decision Boundary

The current delivery decision is defined by
`2026-08-16-ipv6-acl-legacy-kernel-temporary-stack-exception.md`. IPv6 ACL is
completed on the bounded monolithic TC artifact with a frozen 480-byte ceiling.
Nothing in this document authorizes tail-call implementation in that product
generation.

When a later product generation adds Mirror, QoS, load balancing, DDoS,
broadcast-storm suppression, or another datapath feature, Aria will reconsider
one fixed, versioned tail-call pipeline after setting a higher minimum kernel
and completing exact-kernel capability canaries. The product will not retain a
monolithic/tail-call dual runtime after that migration.

The implementation may use two program banks for atomic upgrade and rollback.
Those banks contain two generations of the same tail-call architecture; they
are not separate product modes.

Deployment rollback restores the previous accepted eBPF artifact or switches
back to the retained program bank. It never requires a second monolithic code
path in the current product.

This decision applies to future datapath work, including IPv4/IPv6 ACL, QoS,
Mirror, service processing such as load balancing, physical-ingress DDoS, and
broadcast-storm suppression.

## 2. Why the Architecture Changes Now

The maintained kernel hard limit is 512 verifier-charged bytes for a combined
BPF-to-BPF call path. Aria keeps a stricter 448-byte release limit to reserve
64 bytes for compiler and maintained-kernel compatibility.

The last accepted monolithic TC artifact already consumed the full 448-byte
budget. The IPv6 ACL datapath work added family-qualified policy, conntrack,
drop, and counter identities. One hot phase grew from 160 raw bytes to 168 raw
bytes. The maintained verifier rounds every frame to 32-byte units, so that
small spill changed the charged frame from 160 to 192 bytes and the combined
path from 448 to 480 bytes.

Repeated local changes moved the reported maximum among IPv4 miss, IPv6 miss,
drop, and IPv6 conntrack-fast-path branches without removing the common
capacity constraint. The problem is therefore the shared monolithic call
stack, not the existence of IPv6 logic or one specific helper.

The escalation condition recorded in the legacy stack design has now been
met: scratch-backed bounded calls no longer preserve the 448-byte limit, and
planned capabilities would continue to compete for the same stack.

## 3. Goals

The new architecture must:

- isolate feature stack use so adding one stage does not enlarge another;
- preserve the exact maintained Rocky Linux 8 kernel contract
  `4.18.0-553.5.1.el8_10.x86_64`;
- keep ACL or pipeline infrastructure failure fail-open so original OVS port
  forwarding remains available;
- preserve family and direction isolation without carrying avoidable runtime
  discriminators through stack-constrained hot helpers;
- give every feature an explicit position, ordering contract, failure mode,
  ABI, observability, upgrade, and rollback contract;
- support atomic generation changes without maintaining two implementations;
- make architectural violations fail CI rather than depend on reviewer memory;
- provide stable extension points for QoS, Mirror, and separately designed
  service transformations such as load balancing.

## 4. Non-Goals

This architecture change does not itself:

- define a load-balancing product, NAT semantics, or service-chain policy;
- add new DDoS or broadcast-storm enforcement behavior;
- change the public Neutron ACL model;
- change the existing intentional malformed-packet policy;
- raise the 448-byte release limit or weaken exact-kernel acceptance;
- restart, configure, or take ownership of OVS or
  `neutron-openvswitch-agent`;
- treat hosted compilation as target-kernel field evidence.

Each new product capability still requires its own design. It must fit a
declared pipeline stage or explicitly version the pipeline contract.

## 5. Datapath Planes

Aria has two independent extensibility planes.

### 5.1 Tap TC plane

TC ingress and egress own VM/tap ACL, conntrack, QoS, Mirror, service
processing, trace, and flow accounting. This design replaces the current
monolithic TC call graph.

### 5.2 Physical-ingress XDP plane

Physical-ingress XDP owns the first-stage DDoS and broadcast-storm pipeline.
It uses a separate program array and lifecycle from TC. XDP remains ingress
only. TC and XDP may share stable ABI types and userspace lifecycle helpers,
but they do not share a tail-call program array or silently change each
other's readiness.

The initial implementation plan covers the TC foundation required to unblock
IPv6 ACL. The XDP pipeline adopts the same governance rules when its first
multi-stage capability is implemented.

## 6. TC Pipeline

### 6.1 Attached entry programs

Only `tc_ingress` and `tc_egress` are attached to interfaces. They may:

- read packet bounds and classify IP family;
- perform the minimum parse needed to establish trusted packet context;
- resolve authoritative tap identity and direction;
- reset and initialize the complete per-CPU packet context;
- snapshot active program bank, generation, and pipeline ABI version;
- dispatch to the first family- and direction-specific stage;
- handle the existing non-IP/raw mirror route through a declared raw stage;
- return `TC_ACT_OK` on scratch, dispatch, or tail-call infrastructure failure.

They must not implement ACL lookup, conntrack policy, QoS decisions, Mirror
policy, load balancing, counters, or feature-specific packet mutation.

### 6.2 Fixed stage sequence

The initial IP pipeline is:

```text
ENTRY
  -> SECURITY
  -> SERVICE
  -> TRAFFIC
  -> FINALIZE
```

The contracts are:

| Stage | Initial responsibility | Extension rule |
| --- | --- | --- |
| `ENTRY` | parse, tap authority, context reset, typed dispatch | no product feature logic |
| `SECURITY` | fragment resolution/install decision, CT lookup, ACL evaluation, pending security verdict | security identity and verdict only |
| `SERVICE` | initially a no-op pass-through | load balancing/NAT requires a separate approved ordering and mutation design |
| `TRAFFIC` | ingress policing or egress EDT/priority, pending QoS verdict | traffic control only |
| `FINALIZE` | CT create/update, flow/rule/drop statistics, Mirror, Trace, TCP-RT, apply final action | only stage that normally commits a pending drop |

Non-IP traffic dispatches to a declared `RAW_FINALIZE` stage so global L2
Mirror behavior does not grow `ENTRY`.

The `SERVICE` slot is a stable extension point, not approval to insert an
unspecified load balancer. A future service feature must declare whether ACL
sees the original or transformed tuple, how reverse traffic is restored, and
how partial packet mutation is rolled back before it can replace the no-op.

### 6.3 Family and direction specialization

IP stages are separate compiled programs for each direction and family:

```text
security_ingress_v4    security_ingress_v6
security_egress_v4     security_egress_v6
service_ingress_v4     service_ingress_v6
service_egress_v4      service_egress_v6
traffic_ingress_v4     traffic_ingress_v6
traffic_egress_v4      traffic_egress_v6
finalize_ingress_v4    finalize_ingress_v6
finalize_egress_v4     finalize_egress_v6
```

Shared source may be generated by macros. The compiled program identity must
still make family and direction structural constants.

`PipelineCtx` records family and direction for cross-stage validation and
observability. Stack-constrained policy, conntrack, drop, and counter key
construction must use the typed program's constants rather than propagate a
runtime `ip_family` or `direction` through nested helper structures.

Persistent keys remain family-qualified. `PolicyKey.ip_family`,
`CtValue.matched_family`, and `DropKey.ip_family` are not removed.

### 6.4 Program-array slot identity

Slot numbers are declared once in the shared ABI crate. Code must not contain
feature-local numeric slot literals.

A slot identity is derived from:

```text
(program_bank, hook, family, stage)
```

Program bank `A/B` is an executable-generation mechanism. It is independent
from the existing ACL policy bank `0/1`, which atomically publishes rule and
selector state. Code, status, and documentation must use the full terms
`program_bank` and `acl_policy_bank`; the unqualified word `bank` is not a
valid public or internal contract where both can be in scope.

The initial implementation reserves at most eight tail calls per packet and
uses fewer than that limit. Increasing the depth requires a new architecture
review even if the kernel maximum would permit it.

Every enabled bank has every required slot populated. A disabled capability
uses a real no-op pass-through program which tail-calls the next stage. An
empty slot never means "disabled".

## 7. Cross-Stage Packet Context

The existing per-CPU map-backed packet context becomes a versioned pipeline
contract. It contains at least:

- `pipeline_abi_version`;
- `program_bank` and `generation` snapshot;
- current and expected stage;
- hook, family, and direction;
- tap identity and packet length;
- parsed tuple and selector identities;
- fragment and conntrack state;
- matched policy identity;
- pending verdict and stable reason;
- feature and observability flags.

The entry program initializes every field used by any reachable stage. A
stage validates ABI version, bank/generation, expected predecessor, hook,
family, and direction before acting. Invalid or stale context is a pipeline
failure and returns pass.

After taking the bank/generation snapshot and before the first tail call, entry
increments a per-CPU in-flight counter for that bank. `FINALIZE`,
`RAW_FINALIZE`, and every tail-call failure path decrement it exactly once.
The counter may be greater than one because nested TC execution is possible;
it is not a boolean. Underflow, a counter that does not drain, or an unknown
bank value makes the pipeline not ready.

Large packet-lifetime values remain in per-CPU scratch. No stage returns a
large structure by value or carries map-key structures through unrelated
stages. The per-CPU context is reset for every packet; no stage may depend on
unreset data from a previous packet.

## 8. Verdict and Failure Contract

### 8.1 Deferred commit

Intermediate stages record a pending verdict. `FINALIZE` normally applies the
final `TC_ACT_OK` or `TC_ACT_SHOT` action after required statistics and trace
work.

An ACL or QoS decision does not directly drop before the required final stage
is known to be reachable. If the next tail call fails, the current program
returns `TC_ACT_OK`; Aria loses the feature for that packet rather than
blocking normal OVS forwarding.

The existing intentional malformed-packet envelope is a separate parser
contract and is not silently changed by this architecture work.

### 8.2 Tail-call failure

An unexpected tail-call miss or invalid stage context must:

- return pass for the packet;
- never apply a pending drop;
- increment a bounded
  `tail_call_miss{hook,family,stage,generation}`-equivalent metric when safe;
- mark the affected datapath `degraded/bypass` in agent status;
- make readiness false until the complete bank is verified again;
- leave OVS and `neutron-openvswitch-agent` untouched.

Failure observability is subordinate to pass. If the counter cannot be
updated, the packet still passes.

### 8.3 Packet mutation

A future stage that modifies packet bytes or metadata must provide one of:

- a design proving all required later stages are available before mutation
  and that the stage can safely terminate itself; or
- a bounded preimage and an explicit rollback path executed when the next
  tail call fails.

Forwarding a partially transformed packet after a pipeline failure is
forbidden. A service feature cannot use `SERVICE` until this contract is
tested for both directions and both families.

## 9. Atomic Upgrade and Rollback

### 9.1 Two banks, one architecture

The loader maintains program banks `A` and `B` plus a small pipeline-control
map containing active bank, generation, and ABI version.

Upgrade is transactional:

1. keep the active bank serving traffic;
2. load every new stage program;
3. populate every slot in the inactive bank, including no-op stages;
4. verify program identity, expected next-stage identity, ABI version, and
   map compatibility;
5. load-probe the complete bank on the maintained kernel;
6. atomically publish the new active bank and generation;
7. retain the previous bank and previous accepted artifact for rollback;
8. after publication, prevent new entries from selecting the old bank and wait
   until every per-CPU in-flight counter for that bank is zero;
9. reuse the old bank only after the zero-reference observation is repeated
   across a bounded verification interval with the active bank unchanged.

Every packet snapshots the active bank and generation at entry and follows
that bank for its complete lifetime.

The loader allows five seconds for the old bank to drain and requires two zero
observations separated by 100 milliseconds while the active bank remains
unchanged. If it does not drain, traffic continues on the active bank,
readiness reports the blocked upgrade state, and the old bank is not
overwritten. A timeout is not permission to guess that no packet remains.
These are versioned product constants covered by behavior and target-kernel
tests, not operator-provided arbitrary values.

### 9.2 Rollback

If the entry and shared ABI remain compatible, rollback flips to the retained
complete prior bank. If the entry or shared ABI changed, rollback restores the
previous accepted complete artifact using the existing exact-name TC
ownership procedure.

Rollback never restarts OVS or `neutron-openvswitch-agent` and never assembles
a generation from individually guessed stage versions.

## 10. Loader and Readiness Contract

The agent must not attach or advertise a bank until all required stages have
been loaded and verified. Readiness requires:

- both TC directions attached with exact expected identity;
- active bank and generation readable;
- every required slot populated by the expected program;
- stage ABI and shared map ABI compatible;
- no unresolved loader transaction;
- no observed tail-call miss or stage-contract failure since the accepted
  readiness epoch;
- exact maintained-kernel load evidence for the candidate before production
  enablement.

An in-memory boolean, pinned map existence, or source marker alone is not
sufficient evidence.

## 11. Stack, Complexity, and Performance Budgets

Every attached or tail-called program entry is checked independently from the
linked artifact.

| Constraint | Rule |
| --- | --- |
| hard verifier-charged stack budget | no stage above 448 bytes |
| architecture review threshold | any stage above 416 bytes |
| reserved hard-limit margin | at least 64 bytes below 512 |
| tail-call depth | at most 8 per packet without a new design |
| report coverage | every stage, not only the globally longest path |

The CI report records raw frame bytes, verifier-charged bytes, child call path,
program identity, hook, family, stage, and comparison with the previous
accepted artifact.

Tail calls also add per-packet cost. The implementation must benchmark disabled
no-op stages and the fully enabled ACL/QoS/Mirror path. A stage split is not
accepted merely because it passes the stack checker; material throughput or
latency regression requires review against an explicit baseline.

The 448-byte gate is never increased to admit a feature.

## 12. Mandatory Development Rules

Every future datapath change must declare:

1. XDP or TC ownership;
2. hook and pipeline stage;
3. ordering relative to ACL, CT, QoS, Mirror, and packet mutation;
4. IPv4, IPv6, and non-IP behavior;
5. ingress and egress behavior;
6. disabled/no-op behavior;
7. scratch, map, program-slot, and tail-call failure behavior;
8. pending and committed verdict semantics;
9. packet mutation preimage/rollback, when applicable;
10. map and pipeline ABI changes;
11. stack, tail-depth, and performance evidence;
12. upgrade, rollback, readiness, and observability behavior;
13. hosted CI evidence and exact-kernel evidence status;
14. default enablement state.

A feature that cannot answer these questions remains a design proposal and
does not enter implementation.

The following are prohibited:

- adding product behavior directly to an attached entry program;
- bypassing a stage boundary through a cross-feature BPF-to-BPF call;
- using empty program-array slots as normal feature-disable semantics;
- increasing the stack gate or hiding a stage from artifact analysis;
- using runtime family/direction in a typed hot key when a structural constant
  is available;
- using `inline` annotations as an unmeasured architecture fix;
- reporting a skipped target-kernel probe as PASS;
- enabling a new datapath capability by default before required field proof;
- allowing static source-string checks to substitute for behavior or artifact
  verification.

These rules are duplicated in concise form in repository `AGENTS.md` so future
agent sessions receive them before editing. CI remains the authoritative
machine enforcement.

## 13. CI and Test Gates

The implementation must add artifact- and behavior-backed gates for:

- all attached and tail-called program identities;
- all required slot combinations for bank, hook, family, and stage;
- pass-through behavior of every disabled no-op stage;
- tail-call miss at each boundary returning pass and degrading readiness;
- pending ACL/QoS drop not being committed when `FINALIZE` is unavailable;
- IPv4 rules never affecting IPv6 and the reverse;
- CT hit, CT miss, stale bank, fragments, ingress, and egress;
- program-bank publication only after complete population;
- generation-consistent packet traversal;
- failed publication preserving the old active bank;
- rollback restoring one complete accepted generation;
- ABI mismatch refusing readiness and preserving forwarding;
- per-stage stack and tail-depth budgets;
- target-kernel load, allow/drop, missing-stage, and rollback canaries.

Tests that require the real 4.18 environment remain `deferred/pending` until
executed there. Hosted CI cannot convert them to PASS.

## 14. Direct Migration Strategy

There is no runtime dual-mode period.

The implementation plan will:

1. preserve Tasks 1-3 of the IPv6 restoration work;
2. revert the incomplete Task 4 datapath implementation and stack-shaping
   commits with ordinary revert commits, without rewriting published history;
3. retain the IPv6 family-qualified ABI, persistence, WAL migration, control
   plane, and behavior requirements;
4. introduce the single tail-call loader, program arrays, pipeline context,
   no-op stages, status, and CI gates;
5. migrate existing IPv4 behavior stage by stage without adding product
   behavior;
6. restore IPv6 ACL with structural family-specific stages;
7. migrate existing QoS, Mirror, Trace, TCP-RT, and statistics while preserving
   their current ordering and product semantics;
8. prove exact 4.18 loading and failure behavior in the user's test
   environment;
9. use the previous accepted monolithic artifact only as deployment rollback,
   not as a selectable mode in the new code.

The implementation plan must identify the exact commit range to revert and
prove that no completed Tasks 1-3 state, WAL, or control-plane work is lost.

## 15. Acceptance

The architecture is complete only when:

- the repository contains one TC runtime architecture;
- all stages and no-op stages are loaded from one reviewed candidate artifact;
- every stage is at or below 448 bytes and all stages above 416 bytes have an
  explicit review record;
- ingress and egress, IPv4 and IPv6, CT hit and miss, fragments, ACL allow and
  deny, QoS, Mirror, and non-IP paths pass hosted behavior tests;
- missing-stage and ABI-mismatch tests prove pass plus degraded/not-ready;
- bank switch and rollback tests prove complete-generation behavior;
- the exact maintained 4.18 kernel loads the artifact and passes the canary
  matrix;
- normal OVS port forwarding survives pipeline load, stage, scratch, and
  rollback failures;
- documentation, `AGENTS.md`, CI, release gates, and operator status expose
  the same contract.
