# ACL Batch 5 Final Review Hardening Design

Date: 2026-07-12

Status: initial hardening and selector-resource addendum implemented, reviewed,
and verified

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
- Intern canonical selectors and validate cross-selector ownership with one
  interval sweep so rule pairs never own or rescan complete CIDR vectors.
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

### 5. Selector Interning And Global Interval Sweep

The first implementation used complete canonical CIDR vectors as owning
relation-cache keys. At the permitted `1000 rules x 2048 members` boundary,
unique rule pairs could copy the vectors hundreds of thousands of times. This
is not an acceptable bounded-validation profile.

Both Python and Rust intern canonical selectors independently for source and
destination. Selector ID `0` means `any`; every unique non-empty canonical
selector receives one deterministic positive integer ID. A validation rule
stores only its source and destination selector IDs. Rust stores each CIDR
vector once in the validated template; Python keeps one tuple per interned
selector in the policy validation view.

CIDR ownership is validated once per side with an interval sweep:

1. derive every non-zero selector ID's first rule index from the already
   direction/priority/ID-ordered rules;
2. merge overlapping or nested intervals inside each interned selector;
3. flatten every merged CIDR into
   `(network_start, network_end, selector_id)`;
4. sort intervals by start, end, and selector ID;
5. maintain active interval expirations/counts plus active selector ordering
   keyed by `(first_rule_index, selector_id)`;
6. before inserting the next interval, expire intervals whose end is before
   its start;
7. compare the current selector only with the first different active selector,
   rank that candidate as `(min(first[a], first[b]), max(first[a], first[b]))`,
   and retain only the globally best candidate for that side.

Because members inside each selector are merged first, an active selector
appears once in the ordering. Its smallest different key is sufficient: any
other active selector can only produce an equal or later rule-pair rank. No
conflict-pair set, matrix, or bitset is materialized.

Source and destination each yield at most one rule-index pair. The lower pair
rank wins across sides; source wins only when both sides name the same pair.
The combined bounded candidate is retained as
`(left_rule_index, right_rule_index, side)` while the existing ordered,
ID-only rule-pair scan runs. When the scan reaches that exact pair, it returns
`unsupported_acl_cidr_overlap` before ordinary priority checks for the same
pair. Any ordinary priority overlap on an earlier pair therefore remains the
stable first reason. This preserves pair and side ordering even when address
order discovers a later conflict first. The wire reason format does not
change.

After a side passes the sweep, selector relation is constant-time:

```text
same ID                 -> identical
either ID is 0          -> intersecting through any
different non-zero IDs  -> disjoint
```

Priority fallback retains the existing rule-pair scan, but the scan compares
small IDs and behavior fields only. It owns no CIDR vectors and performs no
member-by-member intersection. The `O(R^2)` portion is therefore bounded to
at most 499,500 cheap comparisons for 1000 rules. For `T` merged input
intervals and `U` active selectors, the overlap pass is
`O(T log T + T log U)`, equivalently `O(T log T)`, and uses `O(T + U)` memory
beyond the existing rule and selector tables. It retains only one best
rule-index pair per side.

This is a representation and validation optimization, not a different
priority algorithm. It preserves exact-selector reuse, conservative overlap
rejection, `any` fallback semantics, deterministic group rendering, and the
approved `1000/2048` runtime limits.

## Data Flow

```text
Neutron ACL payload
  -> Python strict CIDR parse and raw-size guards
  -> Python policy compile cache
     -> ready canonical DTO
     -> or degraded/bypass reason
  -> Rust request-scoped template cache
     -> strict normalization and raw-size guards on cache miss
     -> per-side selector interning and global interval sweep
     -> ID-only priority-independent rule-pair validation
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

Selector-resource red/green coverage must additionally prove in both Python
and Rust:

- identical 2048-member selectors are stored once and referenced by ID;
- 1000 rules sharing one large selector do not create rule-pair CIDR copies;
- 1000 disjoint selectors pass the ownership sweep;
- nested or intersecting CIDRs across different selector IDs are rejected;
- nested CIDRs inside one selector remain one valid selector;
- the stable overlap reason still names the expected rule IDs and priorities;
- source and destination selector ID spaces remain independent;
- port-specific group names are rendered after cached template lookup.

Allowed local verification remains Python/static only. GitHub Actions must
execute the persistent `neutron_acl_` Rust filter, eBPF build, userspace static
build, agent static build, and binary verification. The Batch 5 backlog and
design evidence must be refreshed only after the final hardening workflow is
green.

Implementation evidence:

- Python RED ran 31 focused effective-ACL tests with the expected 5 failures
  and 2 errors; Python GREEN ran the effective-ACL and event-loop suites with
  75/75 passing.
- GitHub Build `29177709424` is the Rust RED evidence: 15 expected missing
  constant/cache/translation/phase-interface compiler errors.
- GitHub Build `29177888031` is the implementation GREEN evidence: the
  persistent `neutron_acl_` filter, eBPF build, userspace static build, agent
  static build, and binary verification all passed.
- GitHub Build `29178194781` is the initial hardening closure GREEN evidence:
  Python 270/270, Stage 2 140/140, persistent Rust ACL tests 22/22, eBPF,
  userspace static, agent static, and binary verification passed.
- No local Cargo command was run, and the pre-existing `README.md` worktree
  modification was not staged or committed.

Selector-resource closure evidence:

- Python RED commit `5f4df94` added the selector-table/ID/sweep contracts.
  The focused module ran 37 tests with the expected five errors because
  `_acl_validation_view` did not exist; the existing public DTO defensive-copy
  contract continued to pass.
- Python GREEN commit `dbff51d` added independent source/destination selector
  tables, ID-only validation rules, and the per-side heap sweep. The focused
  module passed 37/37, the full Python suite passed 276/276, Stage 1 passed
  276/276, Stage 2 passed 146/146, and `git diff --check` passed.
- Rust RED commit `d96c8b4` added the ID-only normalized-rule, retained-table,
  sweep, nesting, independent-ID-space, and cached group-rendering contracts.
  GitHub Build
  [`29180675411`](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/29180675411)
  failed with the expected 21 compiler errors for the absent
  `AclSelectorId`, selector-ID fields, retained selector tables, and
  three-argument overlap validator. The Python adapter remained green; the
  workflow stopped when Stage 1 invoked its persistent Rust tests.
- Rust GREEN commit `0d89b6f` implemented the retained interned tables and
  interval sweep. GitHub Build
  [`29180820079`](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/29180820079)
  passed Python 276/276, Stage 2 146/146, the persistent `neutron_acl_` filter
  28/28, eBPF build and artifact discovery, static userspace and agent builds,
  and static binary verification.

The closed representation has no selector vectors in retained normalized
rules and no selector-pair relation cache. Source and destination tables own
each unique canonical selector once, with ID `0` reserved for `any`. CIDR work
uses deterministic interval sorting and an active-selector order per side;
storage is `O(T + U)` and retains at most one best rule-index pair per side.
There is no conflict-pair set, matrix, bitset, selector vector per rule, or
pair-by-member work. The remaining worst-case 499,500 priority-overlap rule
pairs compare selector IDs and behavior fields only.

Stable-order review closure evidence:

- Python RED commit `c511715` added regressions in which address-order
  discovery points to a later rule pair and in which a later source conflict
  competes with an earlier destination conflict. The focused module ran 39
  tests with the expected two failures: both diagnostics named the later
  source pair instead of the priority/ID-first pair.
- Rust RED commit `2d56149` added the equivalent contracts. The combined run
  [`29181315421`](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/29181315421)
  stopped at the intentionally failing Python tests. Test-only commit
  `596bca4` temporarily isolated the Rust RED, and Build
  [`29181345551`](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/29181345551)
  reached the persistent Rust filter with 28 passing and the expected two
  ordering failures. Commit `d38e638` restored the Python regressions before
  implementation.
- GREEN commit `9de7368` changed both validators to collect selector-ID
  conflict pairs as an intermediate ordering correction and made the
  priority/ID-ordered rule scan authoritative. Locally, the focused
  Python module passed 39/39, the full Python suite and Stage 1 passed 278/278,
  Stage 2 passed 148/148, and `git diff --check` passed.
- Build
  [`29181524962`](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/29181524962)
  passed Python 278/278, Stage 2 148/148, the persistent Rust ACL filter 30/30,
  eBPF build and artifact discovery, static userspace and agent builds, and
  static binary verification. No local Cargo command was run.

Bounded-candidate review closure evidence:

- Python RED commit `ec0b8b3` added the single-best helper contract and a
  1000-selector repeated-overlap regression that would otherwise generate
  499,500 conflict pairs. The focused module ran 41 tests with the expected
  two `AttributeError` errors because `_selector_best_overlap` did not exist;
  the previous 39 tests remained green.
- Rust RED commit `7b4fecb` added the equivalent `neutron_acl_` contracts.
  Test-only commit `5ed0ae6` temporarily isolated the Rust RED, and Build
  [`29186222249`](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/29186222249)
  reached Rust with exactly two `E0425` errors for the missing
  `acl_selector_best_overlap`. Commit `e1d664b` restored the Python RED tests
  before implementation.
- GREEN commit `bb1fcd4` implemented the first-rule-index active ordering and
  retained only one best candidate per side. Locally, the focused Python
  module passed 41/41, the full suite and Stage 1 passed 280/280, Stage 2
  passed 150/150, and `git diff --check` passed.
- Build
  [`29186328080`](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/29186328080)
  passed Python 280/280, Stage 2 150/150, the persistent Rust ACL filter 32/32,
  eBPF build and artifact discovery, static userspace and agent builds, and
  static binary verification. No local Cargo command was run.

Final reason-interleaving review closure evidence:

- Python RED commit `d330a28` added the reviewer scenario, a same-pair
  source/destination CIDR tie, and multi-gap expiration/reactivation coverage.
  The focused module ran 44 tests with exactly one failure: the implementation
  returned `unsupported_acl_cidr_overlap:src:first:10:third:30` instead of the
  earlier `unsupported_acl_priority_overlap:first:10:second:20`. The tie and
  multi-gap synchronization tests passed.
- Rust RED commit `5f9ffe6` added the equivalent `neutron_acl_` contracts.
  Test-only commit `de02f21` isolated the Rust RED, and Build
  [`29186984104`](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/29186984104)
  ran 35 persistent Rust ACL tests with 34 passing and the same single reason
  mismatch. Commit `723b5ce` restored the Python regressions before
  implementation.
- GREEN commit `204c056` retained the one bounded `(left, right, side)`
  candidate and moved only its return point into the existing ordered ID-only
  rule-pair scan. Locally, the focused Python module passed 44/44, the full
  suite and Stage 1 passed 283/283, Stage 2 passed 153/153, and
  `git diff --check` passed.
- Build
  [`29187140448`](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/29187140448)
  passed Python 283/283, Stage 2 153/153, the persistent Rust ACL filter 35/35,
  eBPF build and artifact discovery, static userspace and agent builds, and
  static binary verification. No local Cargo command was run.

This closure is runtime-only. It changes Python policy validation and Rust
request-scoped validated-template representation, but not Neutron API quotas,
the UDS/public effective-ACL DTO, datapath maps, policy ordering semantics,
limits, stable reasons, group-name format, cache lifetime, force-bypass
classification, or readiness boundaries.

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
9. Selector-relation state owns only interned selector tables, sweep state,
   and one best rule-index pair per side; it never owns a conflict-pair set or
   one CIDR vector per rule pair.
