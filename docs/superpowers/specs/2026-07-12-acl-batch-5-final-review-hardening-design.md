# ACL Batch 5 Final Review Hardening Design

Date: 2026-07-12

Status: approved in conversation; pending written-spec review

## Goal

Resolve the three Important findings from the Batch 5 whole-branch review
without changing the approved priority-independent datapath boundary:

1. make Python and Rust IPv4 CIDR normalization strict and consistent;
2. preserve the documented 1000-rule product target without repeating
   quadratic validation for every bound port; and
3. prove the production force-bypass outcome and reconcile failure
   classifications rather than testing a test-only constructor.

## Scope

- Canonicalize IPv4 CIDRs before Python emits the effective ACL snapshot.
- Reject abbreviated, leading-zero, malformed, and invalid-prefix IPv4 CIDRs
  without crashing the Python snapshot builder.
- Cache one Python compiled-policy result per policy for the lifetime of an
  immutable `EffectiveAclIndex`.
- Cache one Rust normalized/validated ACL template per unique ACL payload
  within a full or port-scoped snapshot request.
- Add explicit runtime limits of 1000 effective rules per policy and 2048 raw
  members per rule-side selector in both Python and Rust.
- Memoize canonical selector relations so repeated rule pairs do not repeat
  nested CIDR member comparisons.
- Connect Rust status tests to the production
  `translate_neutron_acl -> AclApplyPlan -> NeutronAclReconcileOutcome::from_plan`
  path.
- Test the production reconcile failure-phase classification used at actual
  call sites.
- Tighten the two non-blocking static guard findings while the relevant CI
  files are already in scope.

## Non-Goals

- Do not implement numeric priority ordering or an eBPF ordered rule scan.
- Do not change `PolicyKey`, `PolicyValue`, CT, WAL, or eBPF map layouts.
- Do not add IPv6, source-port, default-deny, QoS, or Mirror behavior.
- Do not add or change Neutron API create/update quotas in this batch.
- Do not lower the existing 1000-rule-per-port product target to the older
  conservative 100-rule profile.
- Do not introduce a persistent cross-request Rust cache or cache eviction
  policy.
- Do not run local Cargo build, check, or test commands.

## Confirmed Problems

### CIDR Validation And Canonicalization Drift

The existing ACL contract trims CIDR text for validation, but the Batch 5
Python canonicalizer passes the untrimmed address to `socket.inet_aton`.
Surrounding whitespace can therefore crash effective ACL construction even
though the rule passed contract validation.

`inet_aton` also accepts abbreviated IPv4 forms and platform-dependent
leading-zero forms that Rust's `Ipv4Addr` parser rejects. Python can publish a
ready snapshot that Rust rejects as an ordinary translation error. This is a
control-plane parity defect, not a request to expand supported address syntax.

### Repeated Unbounded Pair Validation

Priority/overlap validation compares rule pairs. Selector intersection can
also compare CIDR members pairwise. The Python inventory path calls
`effective_for_port` for every bound port, so a network-bound policy can be
compiled and validated repeatedly during one full resync.

The repository's accepted product target is 1000 effective rules per port,
with a planned 2048-member address-set profile. The solution must preserve
that target while bounding work and eliminating avoidable repetition.

### Outcome Test Is Disconnected From Production

The existing force-bypass outcome test constructs
`NeutronAclReconcileOutcome` through a test-only `force_bypass` constructor.
Production constructs it with `from_plan`. A regression that drops the reason
inside `from_plan` would therefore leave all existing tests green while a
successful empty transaction could report optimistic ready/enforce metadata.

The existing error-action constructor test also does not prove that actual
reconcile call sites classify failures by whether quiesce succeeded.

## Approved Architecture

### 1. Strict Canonical IPv4 Parser

Python and Rust use the same accepted grammar:

- trim surrounding ASCII whitespace;
- require exactly four decimal octets;
- require every octet to contain ASCII digits only and have value `0..255`;
- reject leading zeroes when an octet contains more than one character;
- require one decimal prefix with value `0..32`;
- canonicalize host bits to the network address;
- render the result as `a.b.c.d/prefix`.

Examples:

| Input | Result |
| --- | --- |
| ` 10.1.2.3/24 ` | `10.1.2.0/24` |
| `0.0.0.0/0` | `0.0.0.0/0` |
| `10.1/16` | rejected |
| `010.1.2.3/24` | rejected |
| `10.1.2.3/33` | rejected |

Python uses one parser for direct CIDRs and expanded address-set members. It
stores canonical strings in the compiled rule DTO, so Rust receives the same
representation Python validated. Parser failures become normal compiler
reasons and produce `enabled=false`, `status=degraded`, and
`effective_action=bypass`; they never escape as `OSError` or `ValueError`.

Rust uses the same strict grammar before building `AclIpv4Cidr`. A direct UDS
payload with invalid CIDR syntax remains an ordinary pre-mutation translation
error and therefore reports `error/unchanged`. This preserves the approved
boundary for unrelated malformed direct input while eliminating the former
Python-ready/Rust-error case.

### 2. Runtime Limits

Use these fixed limits:

```text
MAX_ACL_RULES_PER_POLICY = 1000
MAX_ACL_SELECTOR_MEMBERS = 2048
```

The rule limit counts enabled effective rules because disabled rules are not
serialized into the Rust ACL snapshot. The selector limit is checked against
the raw source or destination member vector before canonicalization and
deduplication, so duplicate-heavy input cannot evade the work bound.

Each rule side is checked independently. A direct CIDR has one member; an
expanded address set may contain up to 2048 raw members.

Stable limit reasons are identical in Python and Rust:

```text
acl_rule_limit_exceeded:<actual>:1000
acl_selector_member_limit_exceeded:<side>:<rule-id>:<actual>:2048
```

Python adds the reason to the compiled-policy result and projects
`degraded/bypass`. Rust classifies either reason as a force-bypass plan with
the snapshot's stateful CT intent, then applies the existing empty ACL
transaction. This batch does not reject Neutron API create/update operations;
the runtime layers remain defensive against existing, legacy, or direct UDS
state.

Limits are checked before pairwise overlap validation.

### 3. Python Policy Compile Cache

`EffectiveAclIndex` is immutable after construction: policies, rules, address
sets, and bindings are indexed in `__init__` and are not mutated during
inventory projection. Add a private cache keyed by policy ID.

The cached value contains the complete `_compile_rules` result, including
ready or degraded status, stable reason, and canonical compiled rules. Cache
both successful and degraded results so invalid network-bound policies are not
revalidated for every port.

`effective_for_port` receives a defensive copy of the cached result so a
caller cannot mutate shared cached rule dictionaries. Revision calculation
remains per effective result and is not part of the compile cache.

The cache lifetime is exactly one `EffectiveAclIndex`, which already
corresponds to one loaded ACL payload. A refreshed payload creates a new index
and therefore cannot reuse stale compiled state.

### 4. Rust Snapshot-Scoped Validation Cache

Rust separates port-independent validation from port-specific plan rendering.

The port-independent template contains:

- normalized rules and canonical selector sets;
- a safe validation disposition or stable force-bypass reason;
- the ordinary translation error, when normalization fails;
- no port-specific group names.

The cache key contains:

```text
policy_id + revision + deterministic digest of every rule field used by translation
```

The digest prevents stale reuse when a caller repeats a policy ID/revision with
different rule content. Missing policy IDs are allowed because the content
digest remains authoritative.

A cache lives only for one full or port-scoped snapshot request. Full snapshot
processing passes the cache through every port reconcile; a port-scoped request
creates a fresh one-entry-capable cache. No cache is stored in
`NeutronApiState`, so there is no cross-request invalidation or eviction
contract.

On a cache hit, Rust reuses normalization and validation, then renders
deterministic source/destination group names under the current port's
`neutron:<port-id>:` ownership prefix. Stateful intent remains per snapshot,
not part of the reusable validation result.

### 5. Selector Relation Memoization

Within one validation, use canonical selector sets as keys and memoize their
relationship independently for source and destination sides:

```text
identical | disjoint | intersecting
```

CIDR ownership rejection consumes this relation. Priority fallback validation
reuses it rather than re-running member-by-member intersection for every rule
pair. Empty selectors retain `any` semantics and are handled without CIDR
member comparison.

This retains the approved conservative pair semantics. It does not introduce
a different priority algorithm. With explicit `1000/2048` limits, one
validation per unique policy payload per request, and selector-relation reuse,
the existing 1000-rule target remains the required acceptance profile.

## Data Flow

```text
Neutron ACL payload
  -> Python strict CIDR parse and raw-size guards
  -> Python policy compile cache
     -> ready canonical DTO
     -> or degraded/bypass reason
  -> Rust request-scoped template cache
     -> strict normalization and raw-size guards on cache miss
     -> memoized selector relations and priority-independent validation
     -> cached safe template / force reason / ordinary error
  -> port-specific canonical group and policy rendering
  -> Batch 4 CT/ACL transaction
  -> production reconcile outcome after successful publish
```

## Reconcile Outcome And Failure Proof

Delete the test-only `NeutronAclReconcileOutcome::force_bypass` constructor.
The regression path must start with a real ACL snapshot:

```text
translate_neutron_acl
  -> AclApplyPlan.force_bypass_reason
  -> NeutronAclReconcileOutcome::from_plan
  -> domain_status
```

The test proves optimistic ready/enforce metadata is overridden by the stable
reason and `degraded/bypass` action.

Extract a small production-used reconcile phase classifier. Actual
`map_err` call sites use it rather than duplicating action selection:

| Failure phase | Proven action |
| --- | --- |
| normalization, config read, or quiesce update fails | `unchanged` |
| replacement, strict CT clear, or publication fails after quiesce | `bypass` |
| post-enable compensation cannot disable ACL | `enforce` |

Unit tests call the same classifier used by production and prove no error
variant can produce a successful `NeutronAclReconcileOutcome`. A successful
force-bypass outcome remains constructed and returned only after empty policy
replacement, strict CT clear, and final publication complete.

## Static Guard Tightening

While the CI files are already being updated:

- Stage 1 locates an active, non-comment workflow `run` command for
  `cargo +stable test --locked -p aria-agent neutron_acl_` rather than accepting
  the string anywhere in the YAML text.
- Stage 2 checks production helpers/reason prefixes only in
  `effective_acl.py`, and regression test names only in
  `test_effective_acl.py`.

These changes close the two final-review Minor findings without changing the
runtime design.

## Verification

Python red/green coverage must prove:

- direct CIDR surrounding whitespace canonicalizes without exception;
- address-set member whitespace canonicalizes through the same parser;
- abbreviated and leading-zero IPv4 forms degrade without crashing;
- canonical DTO rules contain network-address/prefix strings;
- 1000 rules are accepted and 1001 degrade with the stable limit reason;
- 2048 selector members are accepted and 2049 degrade with the stable reason;
- repeated ports bound to one policy invoke policy compilation once;
- cached degraded results are also reused safely.

Rust red/green coverage must prove:

- strict CIDR behavior matches Python for whitespace, abbreviated, and
  leading-zero forms;
- 1000/1001 rule and 2048/2049 selector-member boundaries;
- identical policy/revision/rules content hits the snapshot cache;
- changed revision or rule digest cannot reuse a stale template;
- group names remain port-specific on cache hits;
- force-bypass status flows through `from_plan`;
- the production failure-phase classifier returns unchanged, bypass, and
  enforce exactly at the approved boundaries.

Allowed local verification remains Python/static only. GitHub Actions must
execute the persistent `neutron_acl_` Rust filter, eBPF build, userspace static
build, agent static build, and binary verification. The Batch 5 backlog and
design evidence must be refreshed only after the final hardening workflow is
green.

## Completion Criteria

1. All three final-review Important findings have regression tests and fixes.
2. Both final-review Minor CI guard findings are closed.
3. The 1000-rule target is retained with explicit runtime bounds and cache
   evidence.
4. Python and Rust no longer disagree on accepted IPv4 CIDR syntax.
5. Force-bypass status evidence uses the production construction path.
6. No local Cargo command is run.
7. Final GitHub Actions is green at the implementation head.
8. The user's uncommitted `README.md` change remains untouched.
