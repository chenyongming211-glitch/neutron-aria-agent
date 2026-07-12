# ACL Semantic Unification And Datapath Boundaries Design

Date: 2026-07-12

Status: approved in conversation

## Goal

Unify the ACL meaning shared by the Neutron API, Python adapter, Rust control
plane, and eBPF datapath without turning the datapath into a generic ordered
five-tuple rule engine.

The product keeps a service-oriented ACL model:

```text
direction
source IP selector
destination IP selector
protocol
destination port selector
action
```

The packet parser, conntrack, trace, and flow observability remain aware of the
complete five tuple. Source port is deliberately not exposed as an ACL match
dimension because it is normally ephemeral, may be rewritten by NAT, and is
not a stable service identity.

## Confirmed Product Boundaries

1. The ACL datapath is priority-independent.
2. Numeric priority is control-plane metadata used for stable ordering,
   uniqueness, and diagnostics. It does not arbitrate packet actions.
3. A normal Neutron create/update request whose result would depend on
   priority must be rejected by the controller with an actionable conflict.
4. Runtime degraded/bypass overlap handling is defense in depth for legacy
   persisted data, upgrade drift, and direct UDS input. It is not the normal
   user-facing validation path.
5. Source-port matching is unsupported by the ACL product contract.
6. The complete five tuple remains an internal runtime primitive for
   conntrack, trace, TCP-RT, statistics, and diagnostics.
7. IP selectors and port selectors do not need the same eBPF map type. Their
   semantics must be consistent even though their optimal storage differs.

## Non-Goals

- Do not add source-port ACL matching.
- Do not add numeric priority to `PolicyKey`, `PolicyValue`, CT state, or eBPF
  map keys.
- Do not implement an ordered per-packet scan of Neutron ACL rules.
- Do not partition overlapping CIDR space into priority-resolved cells in this
  workstream.
- Do not add IPv6, default-deny, QoS, or Mirror behavior.
- Do not replace the existing LPM plus hash-map datapath with one large generic
  five-tuple map.
- Do not expand source-port and destination-port ranges into a Cartesian
  product.

## Architecture

The design has three layers.

```text
Neutron ACL objects
  -> canonical ACL compiler contract
  -> side-aware, priority-independent effective plan
  -> map-specific eBPF publication and packet lookup
```

### Layer 1: Product Rule Contract

The public rule remains service-oriented:

```text
AclRuleContract
  rule_id
  direction
  priority_metadata
  src_ip_selector
  dst_ip_selector
  protocol
  dst_port_selector
  action
```

`priority_metadata` is retained because Neutron objects need stable ordering,
duplicate detection, deterministic output, and useful conflict messages. A
valid policy cannot depend on that number to choose an action.

The controller validates the complete effective policy during create/update:

- duplicate priority within one policy and direction is rejected;
- non-identical intersecting source or destination selectors are rejected when
  the current single-membership datapath cannot represent them;
- wildcard/specificity overlap with different actions or port behavior is
  rejected;
- exact equivalent selectors may be canonicalized and reused;
- source-port fields are rejected as unsupported;
- destination ports require TCP or UDP and a valid range.

The normal API must return a stable 4xx conflict containing the affected rule
IDs and match dimensions. It must not accept the desired state and wait for a
later agent resync to discover the conflict.

### Layer 2: Canonical ACL IR

Python and Rust use the same normalized meaning:

```text
CanonicalAclRule
  rule_id: string
  direction: ingress | egress
  priority_metadata: non-negative integer
  datapath_directions: set<ingress | egress>
  protocol: u8, zero means any
  src_selector: canonical ordered IPv4 CIDR set, empty means any
  dst_selector: canonical ordered IPv4 CIDR set, empty means any
  dst_ports: canonical non-overlapping ranges, empty means any
  action: allow | deny
```

The IR separates packet tuple meaning from hook placement:

- source always means the packet source;
- destination always means the packet destination;
- Neutron ingress mapping to host-side TC egress changes only the hook and
  datapath direction;
- it never swaps source/destination IPs or ports.

The compiler produces a side-aware plan:

```text
AclSelectorPlan
  side: source | destination
  selector_id
  canonical_cidrs

AclPolicyPlan
  src_selector_id
  dst_selector_id
  protocol
  datapath_direction
  dst_port_set_id | none
  action
```

The IR is a semantic boundary, not a requirement to share a language runtime.
Python and Rust keep independent implementations with shared fixtures,
canonical serialization, stable error reasons, and contract tests.

### Layer 3: Datapath-Specific Structures

The current map specialization remains appropriate:

```text
source IP       -> source ACL LPM trie       -> src_group_id
destination IP  -> destination ACL LPM trie  -> dst_group_id

(tap, src_group_id, dst_group_id, protocol, direction, bank)
                -> POLICY_TABLE              -> PolicyValue

(tap, destination_port_set_id, destination_port)
                -> PORT_BITMAP_POOL          -> port action/membership
```

The packet path remains bounded:

```text
two IP LPM lookups
  + at most eight PolicyKey hash fallbacks
  + zero or one destination-port-set hash lookup
```

No source-port map is added. Supporting source-port ACL matching later would be
a separate product decision and design, not a hidden extension of this IR.

## Why One Large Five-Tuple Map Is Not Used

A generic exact five-tuple hash does not naturally represent CIDR and port
ranges. Pre-expanding those ranges would multiply entries and make control-plane
publication and map capacity depend on the Cartesian product of address and
port ranges.

An ordered eBPF rule scan would preserve northbound priority directly, but its
per-packet cost would grow with the number of rules and conflict with the
existing 1000-rule-per-port target.

The selected design resolves unsupported ambiguity at the controller and keeps
the packet path independent of total rule count.

## Side-Aware Selector Publication

The current translator creates source and destination selector identities, but
the shadow-bank staging path writes every group CIDR into both source and
destination ACL LPM maps. This duplicates map entries and hides selector
ownership.

The target publication plan retains `side` through translation and staging:

```text
source selector      -> source LPM only
destination selector -> destination LPM only
```

An identical CIDR set used on both sides has two explicit side-scoped selector
records. It may share canonical parsing data in userspace, but its map
publication remains side-specific.

This change reduces avoidable LPM writes and makes map capacity accounting
match the actual rule contract.

## Compiler Caching

At the current `f5d59b1` baseline, both cache layers below are implemented.
They are recorded here as required architecture that later side-aware and TC
work must preserve, not as unimplemented feature requests.

### Python Policy Compile Cache

`EffectiveAclIndex` is immutable for one loaded ACL source payload. Compile
each effective policy once and cache both successful and degraded results.

The cache contains:

- normalized rules;
- canonical selectors and destination-port ranges;
- overlap/representability disposition;
- stable conflict reason;
- the port-independent effective ACL template.

Every bound port receives a defensive copy plus port-specific metadata. A
network-bound policy applied to 100 ports must not run pairwise rule validation
100 times.

### Rust Request-Scoped Validation Cache

Rust validates each unique ACL payload once per full or port-scoped snapshot
request. The key contains:

```text
policy_id + revision + deterministic digest of every translated field
```

The cached template contains no port-specific group names. On a cache hit,
Rust only renders the current port ownership prefix and selector IDs.

No cross-request cache is introduced, so there is no persistent invalidation
or eviction contract.

## Shadow-Bank Publication And Measurement

Atomic bank switching remains the correct visibility model: packets see the
old committed ACL or the new committed ACL, not a partially rewritten table.

However, the current shadow staging walks the complete group/rule state even
when the logical change is one rule. Delta counters alone therefore do not
describe actual publication work.

Add explicit shadow metrics:

```text
shadow_scrub_ms
shadow_src_lpm_entries_written
shadow_dst_lpm_entries_written
shadow_policy_entries_written
shadow_port_entries_written
shadow_stage_ms
bank_switch_ms
old_bank_scrub_ms
total_publish_ms
```

Performance claims must use these physical-write counts rather than only
logical `group_add_count` and `policy_add_count`.

## Conntrack And TC Fast Path

The complete five tuple remains necessary inside conntrack:

```text
PacketTuple
  src_ip
  dst_ip
  protocol
  src_port
  dst_port
```

This does not imply source-port ACL matching. Conntrack uses the tuple to
identify forward and reverse flows; the ACL compiler still exposes only the
service-oriented match dimensions.

`REVIEW-ACL-055` is a prerequisite datapath fix. The live TC ingress/egress
paths must call the CT lookup, established-flow fast path, and accepted-flow CT
creation logic that currently exists but is not connected to those paths.

Required semantics:

- stateful ACL: XDP and TC use consistent forward/reply CT behavior;
- stateless ACL: Batch 4 `stateful=false => CT off` remains authoritative;
- an established CT hit does not repeat the full ACL lookup;
- CT state cannot reuse an obsolete ACL bank decision;
- TC CT failure cannot silently become a successful stateful fast path.

The TC CT change is independent from source-port ACL support.

## Failure And Status Semantics

| Failure | Normal handling |
| --- | --- |
| User creates priority-dependent overlap | Controller rejects create/update with rule conflict |
| Legacy DB contains unsupported overlap | Python effective compile reports degraded/bypass |
| Direct UDS contains unsupported overlap | Rust defensive empty-ACL transaction, then degraded/bypass |
| Canonical parsing fails before mutation | Error/unchanged |
| Shadow publication fails after quiesce | Error/bypass or blocked recovery according to transaction phase |
| TC CT fast path cannot be initialized for stateful ACL | ACL must not report ready/enforce |

Readiness and effective action continue to describe the applied runtime, not
only whether the controller accepted the desired object.

## Performance Validation

The existing 1000-rule evidence used ICMP rules and did not exercise the
destination-port bitmap. It also predates the final shadow-bank implementation.
It is useful historical evidence but is not sufficient for the current design.

Required current-HEAD gates:

1. 1000 TCP rules with destination-port matching.
2. Exact PolicyKey hit and eighth fallback hit/miss.
3. XDP CT hit and CT miss.
4. TC ingress/egress CT hit and CT miss after `REVIEW-ACL-055`.
5. One network policy shared by 1, 10, and 100 local ports.
6. Narrow and wide destination-port ranges, including map-entry accounting.
7. Address sets at 1, 256, and 2048 members per selector side.
8. Initial shadow publication, one-rule change, deletion, and cleanup.
9. Continuous allowed and denied traffic during bank publication.
10. Physical map writes, control-plane CPU, memory, and end-to-end convergence.

No source-port ACL benchmark is required because source-port matching is not a
supported product feature. Source port remains covered by conntrack and trace
correctness tests.

## Delivery Sequence

This is the approved dependency order, not an implementation plan:

1. Keep the public source-port and priority-independent constraints explicit.
2. Introduce shared canonical fixtures and the side-aware ACL IR.
3. Preserve the implemented Python and Rust validation caches and their
   1000-rule/2048-member bounds.
4. Preserve selector side through shadow-bank map publication.
5. Add physical shadow-stage metrics and rerun the current-HEAD 1000-rule gate.
6. Fix and validate the TC conntrack fast path under `REVIEW-ACL-055`.
7. Reassess capacity only from current physical-write and packet-path evidence.

## Future Research, Not Current Commitment

Two topics remain outside the product contract:

- source-port ACL matching or arbitrary source/destination port combinations;
- true ordered priority resolution with overlapping CIDRs.

Either topic requires a new approved design and evidence-backed use case. A
future implementation must not be inferred from the presence of source port in
the internal packet tuple or priority in the Neutron database schema.

## Acceptance Criteria

1. Product documentation does not advertise source-port ACL support.
2. Normal Neutron overlap conflicts are rejected at create/update, not first
   discovered during runtime resync.
3. Numeric priority never changes a datapath result.
4. Python and Rust produce identical canonical selectors, directions,
   protocols, destination-port ranges, and stable conflict reasons.
5. A shared network policy is normalized and validated once per loaded payload
   or request, not once per bound port.
6. Source-only selectors write only source ACL LPM maps; destination-only
   selectors write only destination ACL LPM maps.
7. Shadow-stage logs expose physical writes and stage/scrub duration.
8. Stateful TC traffic uses a proven CT fast path; stateless TC traffic does
   not use CT.
9. Current-HEAD 1000-rule destination-port and continuous-traffic gates pass
   without false ready/enforce status.
