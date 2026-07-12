# ACL Batch 5 Priority And Overlap Guardrails Design

Date: 2026-07-12

Status: approved in conversation; pending written-spec review

## Goal

Close `REVIEW-ACL-047` without claiming full Neutron rule-priority support.
Policies that the current single-key/specificity-first datapath can represent
remain accepted. Policies whose result or selector ownership would depend on
Neutron priority are rejected before enforcement and converge to explicit ACL
`degraded/bypass`.

## Scope

- Validate priority and overlap in the production Python effective-ACL
  compiler so unsupported desired state is degraded before submission.
- Repeat the validation in Rust for direct UDS callers that bypass Python.
- Canonicalize identical IPv4 CIDR selector sets and reuse one Rust ACL group.
- Reject non-identical intersecting CIDR selector sets because the LPM map can
  return only one group ID for an IP.
- Reject specificity/fallback overlaps whose effective action or port behavior
  differs and would therefore require priority ordering.
- Preserve current safe same-key, same-action port-range merging.

## Non-Goals

- Do not add priority to `PolicyKey`, `PolicyValue`, CT state, WAL state, or
  eBPF maps.
- Do not implement an ordered rule-list scan in eBPF.
- Do not reinterpret numeric priority as CIDR/protocol specificity.
- Do not expand IPv6, source-port, default-deny, QoS, or Mirror support.
- Do not change the current Python rule-priority rule that lower numeric values
  sort before higher values.
- Do not run local Cargo build, check, or test commands; GitHub Actions remains
  the Rust/eBPF compilation authority for this checkout.

## Confirmed Root Causes

### Priority Is Lost At The Rust Boundary

The Python compiler sorts rules by `(direction, priority)` and carries
`priority` in every `NeutronAclRuleSnapshot`. Rust never reads that field.
`AclEffectivePolicyKey` and the eBPF `PolicyKey` contain source group,
destination group, protocol, direction, and bank, but no priority.

The eBPF lookup tries eight hard-coded keys from most specific to least
specific. This is deterministic specificity ordering, not Neutron ordering.
When a wildcard and a specific rule both match, the specific key always wins
regardless of their numeric priorities.

### The Address Maps Store One Group Identity Per IP

Each translated non-`any` rule currently creates a rule-ID-scoped source and
destination group. The LPM maps return one group ID for a source IP and one for
a destination IP. They cannot express membership in both `10.0.0.0/8` and
`10.1.0.0/16` at the same time.

Consequently, non-identical overlapping CIDRs can hide the broader group's
policy even when the two rules use different protocols or ports. This is not
fixed by checking action conflicts alone. The translator must either use a
multi-membership datapath or reject that selector shape. Batch 5 uses the
approved rejection boundary.

### Port-Filtered Policies Terminate Fallback Lookup

One policy key owns one port bitmap and one outside-the-bitmap action. Once a
specific policy key is found, eBPF does not continue to a less-specific rule
for ports outside that bitmap. Therefore two specificity levels with different
port behavior are not safe merely because their explicit port ranges are
disjoint.

## Approved Contract

### 1. Normalize Rules Before Building Groups

Both Python and Rust build a validation-only normalized view containing:

- stable rule ID and numeric priority;
- expanded datapath directions;
- protocol number, with `0` representing `any`;
- action;
- canonical source and destination IPv4 CIDR sets;
- normalized destination-port ranges, with an empty selector representing all
  ports.

IPv4 CIDRs are normalized to network-address/prefix form, sorted, and
deduplicated. For example, `10.1.2.3/24` and `10.1.2.0/24` represent the same
selector. Python uses a Python-2/3-compatible integer IPv4 helper and adds no
new runtime dependency. Rust uses standard IPv4 address parsing and integer
mask comparison.

Negative priority and duplicate priority within the same Neutron direction are
invalid and produce the same unsupported/bypass disposition for direct UDS
input. The existing server-side validation remains the first line of defense.

### 2. CIDR Selector Rules

For each source side and destination side independently:

- empty CIDRs mean `any` and use group ID zero;
- identical non-empty canonical CIDR sets reuse one translated group;
- disjoint non-empty sets may use separate groups;
- non-identical sets with any intersecting or nested network are rejected,
  regardless of action, protocol, priority, or port range.

The last rule is intentionally conservative. Allowing a pair because its
current actions happen to match would not prove safety when either group also
participates in another policy key.

Group reuse is deterministic and remains under the existing
`neutron:<port-id>:` ownership prefix, so purge and exclusive replacement keep
their current ownership behavior.

### 3. Priority-Dependent Fallback Rules

After the CIDR ownership check, compare rule pairs that share at least one
datapath direction and whose protocol/address spaces can reach the same
specificity fallback chain.

The pair is safe only when one of these conditions holds:

1. a concrete dimension makes the pair disjoint, such as TCP versus UDP or
   disjoint source/destination CIDR sets; or
2. both rules have identical effective behavior at the competing specificity
   levels: same action and the same normalized port behavior; or
3. the rules collapse to the exact same source group, destination group,
   protocol, and direction with the same action, in which case the existing
   port-range union produces one policy.

Otherwise reject the pair. This includes:

- `any` protocol versus a concrete protocol with different behavior;
- `any` source/destination versus a specific selector with different behavior;
- equal action but different port behavior across specificity levels;
- different actions for a match space that either rule can own;
- equal selector keys with conflicting actions, even when explicit port ranges
  are disjoint.

Numeric priority is included in the diagnostic but is never mapped to
specificity. Non-overlapping rules remain accepted even though their priority
does not affect the datapath.

### 4. Stable Rejection Reasons

Use stable machine-readable prefixes with both rule IDs and priorities:

```text
unsupported_acl_cidr_overlap:<side>:<rule-a>:<priority-a>:<rule-b>:<priority-b>
unsupported_acl_priority_overlap:<rule-a>:<priority-a>:<rule-b>:<priority-b>
invalid_acl_priority:<rule-id>:<priority>
duplicate_acl_priority:<direction>:<priority>:<rule-a>:<rule-b>
```

User-facing details may append selector information, but tests and status
projection rely only on these stable prefixes and identifiers.

### 5. Production Python Degrades Before Submit

`EffectiveAclIndex._compile_rules` runs overlap validation after individual
rules compile successfully. Any rejection reason is added to the existing
compiler reasons, which produces:

```text
enabled=false
status=degraded
effective_action=bypass
reason=<stable rejection reason>
```

The snapshot remains observable and auditable, but it is not advertised as a
ready ACL. The normal Rust empty/bypass reconcile disables the ACL gate,
replaces Neutron-owned policy with an empty plan, strictly clears CT, and
preserves the Batch 4 stateful CT contract.

### 6. Rust Direct-UDS Defense Also Produces Real Bypass

Rust repeats normalization and validation before group creation. An overlap
rejection is not returned as an ordinary pre-mutation translation error,
because that would retain the previous ACL and report `unchanged`.

Instead, the translator returns a classified force-bypass plan containing the
stable reason and the snapshot's stateful CT intent. Reconcile applies it as an
empty owned ACL replacement using the existing sequence:

```text
CT=false + ACL=false
  -> replace owned ACL with empty plan
  -> strict CT clear
  -> publish desired CT mode + ACL=false
```

The reconcile outcome overrides optimistic input metadata with ACL
`degraded/bypass` and the stable reason. If quiesce, replacement, CT clear, or
publication fails, the existing proven-action error classification applies;
the system never reports bypass unless the ACL gate is actually off.

Ordinary unsupported translator errors outside this batch retain their current
pre-mutation `error/unchanged` behavior.

## Data And Control Flow

```text
Neutron DB rules
  -> Python individual rule validation/normalization
  -> Python priority/overlap guard
     -> unsupported: degraded/bypass snapshot
     -> supported: ready/enforce snapshot
  -> Rust defensive normalization/overlap guard
     -> unsupported direct UDS: classified force-bypass plan
     -> supported: canonical groups + policy plan
  -> existing Batch 4 CT/ACL transaction
  -> runtime domain status from actual reconcile outcome
```

## Failure Semantics

| Condition | Datapath action | Reported ACL state |
| --- | --- | --- |
| Python detects unsupported overlap and Rust bypass succeeds | ACL off | degraded/bypass |
| Direct UDS overlap and Rust force-bypass succeeds | ACL off | degraded/bypass |
| Force-bypass quiesce fails before mutation | unchanged | error/unchanged |
| Force-bypass mutation fails after quiesce | ACL remains off | error/bypass |
| Unrelated translation error before mutation | unchanged | error/unchanged |
| Supported non-overlapping policy succeeds | requested ACL active | ready/enforce |

## Invariants

1. No accepted ACL policy depends on numeric priority for its datapath result.
2. No accepted policy requires simultaneous membership in two non-identical
   overlapping source or destination CIDR groups.
3. Identical CIDR selector sets map to one group identity.
4. Specificity fallback is accepted only when competing rules have identical
   effective behavior.
5. Unsupported priority/overlap state never reports ready/enforce.
6. Reported bypass requires the ACL gate to be disabled in the applied runtime.
7. `PolicyKey`, CT schemas, eBPF lookup order, and advertised capabilities do
   not change in Batch 5.

## Verification

Python regression coverage must prove:

- nested and partially intersecting CIDRs degrade with stable reasons;
- canonical-equivalent CIDRs are treated as identical;
- wildcard/specific action and port-behavior conflicts degrade;
- exact safe selectors and concrete disjoint protocols remain ready;
- negative and duplicate priority cannot reach ready status.

Rust regression coverage must prove:

- identical CIDR sets reuse one group;
- non-identical intersecting CIDRs produce a classified force-bypass plan;
- wildcard/specific differing behavior produces force-bypass;
- safe same-key/same-action port ranges still merge;
- disjoint rules still translate;
- direct UDS force-bypass returns degraded/bypass only after the empty ACL
  transaction succeeds;
- unrelated translation failures remain error/unchanged.

CI static guards must require the Python and Rust overlap tests, stable reason
prefixes, classified force-bypass outcome, and unchanged eBPF `PolicyKey`
layout. Backlog closure occurs only after the final GitHub Actions workflow is
green.
