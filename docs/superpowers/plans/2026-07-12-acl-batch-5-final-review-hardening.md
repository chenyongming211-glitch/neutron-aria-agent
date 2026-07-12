# ACL Batch 5 Final Review Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close all three Important and both Minor findings from the Batch 5 whole-branch review while preserving the documented 1000-rule ACL target and the approved priority-independent datapath boundary.

**Architecture:** Python strictly canonicalizes CIDRs, enforces `1000/2048` runtime limits, memoizes selector relations, and caches each immutable policy compilation once. Rust separates port-independent ACL validation from port-specific rendering, reuses validated templates within one snapshot request, and routes force-bypass status and failure classification through production-used interfaces. CI executes the Rust ACL filter and guards exact source/test ownership before closure evidence is refreshed.

**Tech Stack:** Python 2/3-compatible OpenStack adapter code, Rust, Tokio, SHA-256/serde JSON cache keys, Aya/eBPF policy maps, GitHub Actions.

## Global Constraints

- Implement only the Batch 5 final-review hardening for `REVIEW-ACL-047`.
- Preserve the approved priority-independent selector semantics.
- Do not add priority to `PolicyKey`, `PolicyValue`, CT, WAL, or eBPF maps.
- Do not implement numeric priority scanning, IPv6, source-port, default-deny, QoS, or Mirror.
- Do not modify Neutron API create/update quota behavior.
- Use `MAX_ACL_RULES_PER_POLICY = 1000` and `MAX_ACL_SELECTOR_MEMBERS = 2048` in both Python and Rust.
- Python limit failures produce `degraded/bypass`; Rust direct UDS limit failures use the existing real empty force-bypass transaction.
- Accept surrounding CIDR whitespace, but reject abbreviated IPv4 and multi-character octets with leading zeroes.
- Cache Python compilation only for one immutable `EffectiveAclIndex` and Rust validation only for one snapshot request.
- Keep source and destination selector registries independent and group names under `neutron:<port-id>:`.
- Ordinary malformed direct-UDS CIDR translation remains pre-mutation `error/unchanged`.
- Never run local `cargo build`, `cargo check`, or `cargo test`; GitHub Actions is the Rust/eBPF authority.
- Preserve and exclude the user's uncommitted `README.md` change.
- One final-review fix agent executes this complete task and creates separate RED, GREEN, and closure commits.

## File Map

| File | Responsibility |
| --- | --- |
| `openstack/neutron_aria/neutron_aria/agent/effective_acl.py` | Strict CIDR grammar/canonical DTOs, runtime limits, selector relation memoization, immutable policy compile cache. |
| `openstack/neutron_aria/neutron_aria/tests/unit/test_effective_acl.py` | Python CIDR parity, limit boundaries, cache reuse, and defensive-copy regression coverage. |
| `agent/src/neutron_api.rs` | Strict Rust CIDR parser, limits, selector relation memoization, snapshot-scoped validation template cache, production outcome/failure classifier, Rust tests. |
| `.github/workflows/build.yml` | Persistent execution of the `neutron_acl_` Rust test family; command remains unchanged but is guarded more precisely. |
| `ci/check_neutron_stage1.py` | Active workflow-command guard and Rust hardening marker checks. |
| `ci/check_neutron_stage2_acl.py` | Separate production-source and regression-test marker checks. |
| `docs/openstack-neutron-aria-details/02-aria-acl-plugin.md` | Exact runtime limits, cache scope, and strict IPv4 syntax boundary. |
| `docs/openstack-neutron-aria-details/12-review-bug-backlog.md` | Final hardening evidence while keeping only `ACL-047` closed. |
| `docs/superpowers/specs/2026-07-12-acl-batch-5-priority-overlap-guardrails-design.md` | Original Batch 5 verification refreshed with hardening evidence. |
| `docs/superpowers/specs/2026-07-12-acl-batch-5-final-review-hardening-design.md` | Hardening status and final RED/GREEN evidence. |

---

### Task 1: Resolve All Batch 5 Whole-Branch Review Findings

**Files:**
- Modify: `openstack/neutron_aria/neutron_aria/agent/effective_acl.py:1-503`
- Test: `openstack/neutron_aria/neutron_aria/tests/unit/test_effective_acl.py`
- Modify: `agent/src/neutron_api.rs:170-330,1598-1930,2548-2605,3502-4097,6488-6895`
- Modify: `ci/check_neutron_stage1.py:540-566`
- Modify: `ci/check_neutron_stage2_acl.py:114-135`
- Modify: `docs/openstack-neutron-aria-details/02-aria-acl-plugin.md:117-145`
- Modify: `docs/openstack-neutron-aria-details/12-review-bug-backlog.md`
- Modify: `docs/superpowers/specs/2026-07-12-acl-batch-5-priority-overlap-guardrails-design.md`
- Modify: `docs/superpowers/specs/2026-07-12-acl-batch-5-final-review-hardening-design.md`

**Interfaces:**
- Produces Python `_strict_ipv4_cidr(value) -> (network_u32, prefix, canonical_text)`.
- Produces Python `_compile_rules_uncached(policy) -> compiled_result` behind cached `_compile_rules(policy)`.
- Produces Python `_selector_relation(left, right, cache) -> identical|disjoint|intersecting`.
- Produces Rust `AclValidatedTemplate`, `AclValidationCacheKey`, and `AclValidationCache`.
- Produces Rust `translate_neutron_acl_with_cache(port_id, acl, cache) -> Result<AclApplyPlan, String>` while retaining the one-shot `translate_neutron_acl` test/helper wrapper.
- Produces Rust `AclReconcileFailurePhase` and `acl_reconcile_error(phase, details)` used by production call sites.
- Stable limit reasons are exactly `acl_rule_limit_exceeded:<actual>:1000` and `acl_selector_member_limit_exceeded:<side>:<rule-id>:<actual>:2048`.

- [ ] **Step 1: Add Python RED fixtures for strict CIDR behavior**

Add focused tests using the public `effective_for_port` path:

```python
def test_cidr_whitespace_is_canonicalized_in_snapshot(self):
    result = effective_acl([acl_rule("spaced", 10, src_cidr=" 10.1.2.3/24 ")])
    self.assertEqual(ACL_READY, result["status"])
    self.assertEqual(["10.1.2.0/24"], result["rules"][0]["src_cidrs"])

def test_address_set_member_whitespace_uses_same_canonicalizer(self):
    index = EffectiveAclIndex(
        policies=[{"id": "policy-1", "default_action": "allow"}],
        address_sets=[{"id": "aset-1", "members": [" 10.2.3.4/24 "]}],
        rules=[acl_rule("aset", 10, src_address_set_id="aset-1")],
        bindings=[{
            "id": "binding-1", "policy_id": "policy-1",
            "target_type": "port", "target_id": PORT_ID,
        }],
    )
    result = index.effective_for_port(port(), snapshot())
    self.assertEqual(ACL_READY, result["status"])
    self.assertEqual(["10.2.3.0/24"], result["rules"][0]["src_cidrs"])

def test_noncanonical_ipv4_forms_degrade_without_exception(self):
    for rule_id, cidr in (("short", "10.1/16"), ("leading-zero", "010.1.2.3/24")):
        result = effective_acl([acl_rule(rule_id, 10, src_cidr=cidr)])
        self.assertEqual(ACL_DEGRADED, result["status"])
        self.assertEqual("bypass", result["effective_action"])
        self.assertIn("invalid_acl_ipv4_cidr:src:%s:" % rule_id, result["reason"])
```

- [ ] **Step 2: Add Python RED limit tests**

Generate valid boundary rules with unique priority and identical behavior:

```python
def acl_rules(count):
    return [acl_rule("rule-%s" % index, index) for index in range(count)]

def selector_members(count):
    return ["10.%s.%s.%s/32" % (
        (index >> 16) & 0xff,
        (index >> 8) & 0xff,
        index & 0xff,
    ) for index in range(count)]


def effective_acl_with_address_set(members):
    return EffectiveAclIndex(
        policies=[{"id": "policy-1", "default_action": "allow"}],
        address_sets=[{"id": "aset-1", "members": members}],
        rules=[acl_rule("aset-rule", 10, src_address_set_id="aset-1")],
        bindings=[{
            "id": "binding-1", "policy_id": "policy-1",
            "target_type": "port", "target_id": PORT_ID,
        }],
    ).effective_for_port(port(), snapshot())


def test_rule_runtime_limit_accepts_1000_and_bypasses_1001(self):
    accepted = effective_acl(acl_rules(1000))
    rejected = effective_acl(acl_rules(1001))
    self.assertEqual(ACL_READY, accepted["status"])
    self.assertEqual(ACL_DEGRADED, rejected["status"])
    self.assertEqual("acl_rule_limit_exceeded:1001:1000", rejected["reason"])

def test_selector_runtime_limit_accepts_2048_and_bypasses_2049(self):
    accepted = effective_acl_with_address_set(selector_members(2048))
    rejected = effective_acl_with_address_set(selector_members(2049))
    self.assertEqual(ACL_READY, accepted["status"])
    self.assertEqual(ACL_DEGRADED, rejected["status"])
    self.assertEqual(
        "acl_selector_member_limit_exceeded:src:aset-rule:2049:2048",
        rejected["reason"],
    )
```

- [ ] **Step 3: Add Python RED cache and defensive-copy tests**

Define a counting subclass around the required uncached boundary:

```python
class CountingEffectiveAclIndex(EffectiveAclIndex):
    def __init__(self, *args, **kwargs):
        self.compile_count = 0
        super(CountingEffectiveAclIndex, self).__init__(*args, **kwargs)

    def _compile_rules_uncached(self, policy):
        self.compile_count += 1
        return super(CountingEffectiveAclIndex, self)._compile_rules_uncached(policy)
```

Then require one compile for two ports and safe result copies:

```python
first = index.effective_for_port(port("port-1", "net-1"), snapshot())
first["rules"][0]["src_cidrs"].append("192.0.2.0/24")
second = index.effective_for_port(port("port-2", "net-1"), snapshot())
self.assertEqual(1, index.compile_count)
self.assertEqual(["10.1.2.0/24"], second["rules"][0]["src_cidrs"])
```

Repeat with an invalid policy and assert its degraded result is also compiled
once and returned as independent dictionaries.

- [ ] **Step 4: Run and commit Python RED evidence**

```bash
PYTHONPATH=openstack/neutron_aria python3 -m unittest \
  neutron_aria.tests.unit.test_effective_acl
```

Expected: the whitespace case errors in the current canonicalizer; canonical
DTO, limits, and cache tests fail because the behavior/interfaces are absent.
Fix test syntax or fixture mistakes until failures are only the missing
hardening behavior, then commit tests only:

```bash
git add openstack/neutron_aria/neutron_aria/tests/unit/test_effective_acl.py
git commit -m "test: require ACL CIDR limits and compile cache"
```

- [ ] **Step 5: Implement the strict Python IPv4 parser**

Add constants and replace `inet_aton` acceptance with explicit grammar:

```python
MAX_ACL_RULES_PER_POLICY = 1000
MAX_ACL_SELECTOR_MEMBERS = 2048


def _strict_ipv4_cidr(value):
    text = str(value).strip()
    pieces = text.split("/")
    if len(pieces) != 2:
        raise ValueError("invalid IPv4 CIDR")
    address, prefix_text = pieces
    octets = address.split(".")
    if len(octets) != 4:
        raise ValueError("invalid IPv4 address")
    values = []
    for octet in octets:
        if (not octet or not all(character in "0123456789" for character in octet) or
                (len(octet) > 1 and octet.startswith("0"))):
            raise ValueError("invalid IPv4 octet")
        number = int(octet, 10)
        if number > 255:
            raise ValueError("invalid IPv4 octet")
        values.append(number)
    if not prefix_text or not all(character in "0123456789" for character in prefix_text):
        raise ValueError("invalid IPv4 prefix")
    prefix = int(prefix_text, 10)
    if prefix > 32:
        raise ValueError("invalid IPv4 prefix")
    value = ((values[0] << 24) | (values[1] << 16) |
             (values[2] << 8) | values[3])
    mask = 0 if prefix == 0 else ((0xffffffff << (32 - prefix)) & 0xffffffff)
    network = value & mask
    canonical = "%s.%s.%s.%s/%s" % (
        (network >> 24) & 0xff, (network >> 16) & 0xff,
        (network >> 8) & 0xff, network & 0xff, prefix,
    )
    return network, prefix, canonical
```

`_canonical_ipv4_cidrs` returns ordered `(network, prefix)` keys for relation
checks. Add `_canonical_ipv4_strings` to return canonical rendered DTO values
from the same parser. Catch `TypeError` and `ValueError` inside `_compile_rule`
and return:

```text
invalid_acl_ipv4_cidr:<side>:<rule-id>:<raw-value>
```

Canonicalize direct and address-set selectors before storing them in the
compiled rule dictionary.

- [ ] **Step 6: Implement Python limits before pair validation**

At the top of `_compile_rules_uncached`, count enabled rules and return without
compiling when the limit is exceeded:

```python
if len(rules) > MAX_ACL_RULES_PER_POLICY:
    return {
        "status": ACL_DEGRADED,
        "reason": "acl_rule_limit_exceeded:%s:%s" % (
            len(rules), MAX_ACL_RULES_PER_POLICY,
        ),
        "rules": [],
    }
```

In `_compile_address_match`, inspect the raw member vector before contract
validation/canonicalization:

```python
if len(members) > MAX_ACL_SELECTOR_MEMBERS:
    return [], "acl_selector_member_limit_exceeded:%s:%s:%s:%s" % (
        prefix, rule.get("id"), len(members), MAX_ACL_SELECTOR_MEMBERS,
    )
```

- [ ] **Step 7: Implement Python selector relation memoization**

Use one relation cache for a policy validation:

```python
SELECTOR_IDENTICAL = "identical"
SELECTOR_DISJOINT = "disjoint"
SELECTOR_INTERSECTING = "intersecting"


def _selector_relation(left, right, cache):
    key = (left, right) if left <= right else (right, left)
    if key not in cache:
        if left == right:
            relation = SELECTOR_IDENTICAL
        elif not left or not right:
            relation = SELECTOR_INTERSECTING
        elif _ipv4_cidrs_intersect(left, right):
            relation = SELECTOR_INTERSECTING
        else:
            relation = SELECTOR_DISJOINT
        cache[key] = relation
    return cache[key]
```

`_acl_overlap_reason` calls this helper for source and destination. CIDR
ownership rejects `INTERSECTING` only when both selectors are non-empty and
not identical. Fallback skips a pair when either concrete dimension is
`DISJOINT`.

- [ ] **Step 8: Implement the immutable Python policy compile cache**

Import `copy`, initialize `self._compiled_rules_by_policy = {}` in `__init__`,
and split compilation:

```python
def _compile_rules(self, policy):
    policy_id = policy.get("id")
    if policy_id not in self._compiled_rules_by_policy:
        self._compiled_rules_by_policy[policy_id] = self._compile_rules_uncached(policy)
    return copy.deepcopy(self._compiled_rules_by_policy[policy_id])
```

Rename the current `_compile_rules` implementation to
`_compile_rules_uncached`; Steps 6 and 7 provide its limit and overlap changes.

The cache stores ready and degraded results. Do not cache revision or binding
metadata because `effective_for_port` computes those separately.

- [ ] **Step 9: Run Python GREEN and commit**

```bash
PYTHONPATH=openstack/neutron_aria python3 -m unittest \
  neutron_aria.tests.unit.test_effective_acl \
  neutron_aria.tests.unit.test_event_loop
python3 ci/check_neutron_stage2_acl.py
git diff --check
git add \
  openstack/neutron_aria/neutron_aria/agent/effective_acl.py \
  openstack/neutron_aria/neutron_aria/tests/unit/test_effective_acl.py
git commit -m "fix: canonicalize and bound Python ACL validation"
```

Expected: targeted Python and Stage 2 suites pass with no exception or warning.

- [ ] **Step 10: Add Rust RED tests for strict CIDRs and runtime limits**

Add tests under the existing `neutron_acl_` naming filter:

```rust
fn numbered_acl_rules(count: usize) -> Vec<NeutronAclRuleSnapshot> {
    (0..count)
        .map(|index| acl_rule_with(
            &format!("rule-{}", index),
            index as i64,
            "tcp",
            "drop",
            &[],
            &[],
            None,
        ))
        .collect()
}

fn numbered_acl_members(count: usize) -> Vec<String> {
    (0..count)
        .map(|index| format!(
            "10.{}.{}.{}/32",
            (index >> 16) & 0xff,
            (index >> 8) & 0xff,
            index & 0xff,
        ))
        .collect()
}

#[test]
fn neutron_acl_cidrs_match_python_strict_grammar() {
    assert_eq!(AclIpv4Cidr::parse(" 10.1.2.3/24 ").unwrap().canonical(), "10.1.2.0/24");
    assert!(AclIpv4Cidr::parse("10.1/16").is_err());
    assert!(AclIpv4Cidr::parse("010.1.2.3/24").is_err());
}

#[test]
fn neutron_acl_runtime_limits_accept_boundary_and_force_bypass_overflow() {
    let accepted = ready_acl(numbered_acl_rules(MAX_ACL_RULES_PER_POLICY));
    assert_eq!(translate_neutron_acl("port-1", &accepted).unwrap().force_bypass_reason, None);
    let rejected = ready_acl(numbered_acl_rules(MAX_ACL_RULES_PER_POLICY + 1));
    assert_eq!(
        translate_neutron_acl("port-1", &rejected).unwrap().force_bypass_reason.as_deref(),
        Some("acl_rule_limit_exceeded:1001:1000")
    );
}

#[test]
fn neutron_acl_selector_limit_accepts_2048_and_force_bypasses_2049() {
    let mut accepted_rule = acl_rule_with(
        "accepted-members", 10, "tcp", "drop", &[], &[], None,
    );
    accepted_rule.src_cidrs = numbered_acl_members(MAX_ACL_SELECTOR_MEMBERS);
    let accepted = ready_acl(vec![accepted_rule]);
    assert_eq!(
        translate_neutron_acl("port-1", &accepted)
            .unwrap()
            .force_bypass_reason,
        None,
    );

    let mut rejected_rule = acl_rule_with(
        "rejected-members", 10, "tcp", "drop", &[], &[], None,
    );
    rejected_rule.src_cidrs = numbered_acl_members(MAX_ACL_SELECTOR_MEMBERS + 1);
    let rejected = ready_acl(vec![rejected_rule]);
    assert_eq!(
        translate_neutron_acl("port-1", &rejected)
            .unwrap()
            .force_bypass_reason
            .as_deref(),
        Some("acl_selector_member_limit_exceeded:src:rejected-members:2049:2048"),
    );
}
```

- [ ] **Step 11: Add Rust RED validation-cache tests**

Require these interfaces and behaviors:

```rust
let acl = ready_acl(vec![acl_rule_with(
    "cached", 10, "tcp", "drop", &["10.1.2.3/24"], &[], None,
)]);
let mut cache = AclValidationCache::default();
let first = translate_neutron_acl_with_cache("port-1", &acl, &mut cache).unwrap();
let second = translate_neutron_acl_with_cache("port-2", &acl, &mut cache).unwrap();
assert_eq!(cache.misses, 1);
assert_eq!(cache.hits, 1);
assert!(first.groups.iter().all(|group| group.name.starts_with("neutron:port-1:")));
assert!(second.groups.iter().all(|group| group.name.starts_with("neutron:port-2:")));

let mut changed_revision = acl.clone();
changed_revision.revision += 1;
translate_neutron_acl_with_cache("port-3", &changed_revision, &mut cache).unwrap();
assert_eq!(cache.misses, 2);

let mut changed_rules = acl;
changed_rules.rules[0].action = Some("allow".to_string());
translate_neutron_acl_with_cache("port-4", &changed_rules, &mut cache).unwrap();
assert_eq!(cache.misses, 3);
```

- [ ] **Step 12: Add Rust RED production outcome and phase-classifier tests**

Replace the test-only constructor path:

```rust
let acl = ready_acl(vec![
    acl_rule_with("wildcard", 10, "any", "allow", &[], &[], None),
    acl_rule_with("tcp-drop", 20, "tcp", "drop", &[], &[], None),
]);
let plan = translate_neutron_acl("port-1", &acl).unwrap();
let outcome = NeutronAclReconcileOutcome::from_plan(&plan);
let mut snapshot = port("port-1", "tap-port-1", true);
snapshot.managed_domains = vec!["acl".to_string()];
snapshot.acl = Some(acl);
let status = outcome.domain_status(&snapshot);
assert_eq!(status.status, "degraded");
assert_eq!(status.effective_action.as_deref(), Some("bypass"));
```

Delete `NeutronAclReconcileOutcome::force_bypass`. Add tests for the future
production classifier:

```rust
assert_eq!(acl_reconcile_error(AclReconcileFailurePhase::BeforeQuiesce, "x").effective_action, "unchanged");
assert_eq!(acl_reconcile_error(AclReconcileFailurePhase::AfterQuiesce, "x").effective_action, "bypass");
assert_eq!(acl_reconcile_error(AclReconcileFailurePhase::CompensationFailed, "x").effective_action, "enforce");
```

- [ ] **Step 13: Commit and obtain Rust RED from GitHub Actions**

```bash
git add agent/src/neutron_api.rs
git commit -m "test: require cached bounded Rust ACL validation"
git push origin codex/acl-batch-5-priority-guardrails
gh workflow run Build --ref codex/acl-batch-5-priority-guardrails -f publish_artifacts=false
```

Expected: Python stages pass; `cargo +stable test --locked -p aria-agent
neutron_acl_` fails to compile on missing cache/phase interfaces or fails the
strict/limit assertions. Record the run ID and exact expected failures before
writing Rust production code.

- [ ] **Step 14: Implement strict Rust CIDRs and pre-validation limits**

Add the same constants as Python. `AclIpv4Cidr::parse` trims the full input,
splits exactly once, verifies exactly four ASCII-decimal octets, rejects
multi-character leading zeroes, validates `0..255` and prefix `0..32`, then
canonicalizes host bits.

Before normalization, use:

```rust
fn acl_runtime_limit_reason(acl: &NeutronAclSnapshot) -> Option<String> {
    if acl.rules.len() > MAX_ACL_RULES_PER_POLICY {
        return Some(format!(
            "acl_rule_limit_exceeded:{}:{}",
            acl.rules.len(), MAX_ACL_RULES_PER_POLICY,
        ));
    }
    for (index, rule) in acl.rules.iter().enumerate() {
        let rule_id = acl_rule_id(rule, index);
        for (side, members) in [("src", &rule.src_cidrs), ("dst", &rule.dst_cidrs)] {
            if members.len() > MAX_ACL_SELECTOR_MEMBERS {
                return Some(format!(
                    "acl_selector_member_limit_exceeded:{}:{}:{}:{}",
                    side, rule_id, members.len(), MAX_ACL_SELECTOR_MEMBERS,
                ));
            }
        }
    }
    None
}
```

Return `force_bypass_acl_plan` for a limit reason before normalizing rules.

- [ ] **Step 15: Implement Rust selector relation memoization**

Define:

```rust
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AclSelectorRelation { Identical, Disjoint, Intersecting }
```

Use a canonical ordered key of two selector vectors in a `BTreeMap`. Replace
direct repeated calls to `acl_cidr_selectors_intersect` inside
`acl_priority_overlap_reason` with a cached relation lookup. Keep empty
selectors as `Intersecting` for fallback semantics, while CIDR ownership still
requires both sides non-empty and non-identical.

- [ ] **Step 16: Implement the snapshot-scoped Rust validation template cache**

Define:

```rust
#[derive(Clone, Debug, PartialEq, Eq)]
enum AclValidatedTemplate {
    Ready(Vec<NormalizedAclRule>),
    ForceBypass(String),
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct AclValidationCacheKey {
    policy_id: Option<String>,
    revision: u64,
    content_hash: String,
}

#[derive(Serialize)]
struct AclValidationHashPayload<'a> {
    default_action: &'a str,
    rules: &'a [NeutronAclRuleSnapshot],
}

#[derive(Default)]
struct AclValidationCache {
    entries: BTreeMap<AclValidationCacheKey, Result<AclValidatedTemplate, String>>,
    hits: usize,
    misses: usize,
}
```

Build `content_hash` with the existing `stable_json_hash` over a serializable
payload containing `default_action` and `rules`. `validate_neutron_acl_template`
performs default-action validation, limits, normalization, and overlap guard.
Cache both ordinary `Err`, `Ready`, and `ForceBypass` results.

`translate_neutron_acl_with_cache` handles non-ready input directly, obtains a
template for ready input, then renders groups/policies for the current
`port_id`. The existing `translate_neutron_acl` creates a fresh local cache and
delegates, preserving simple unit-test callers.

- [ ] **Step 17: Wire one Rust cache through a snapshot request**

In `apply_snapshot_runtime_transaction`, create:

```rust
let mut acl_validation_cache = AclValidationCache::default();
```

Pass `&mut acl_validation_cache` through both update and attach calls to
`reconcile_neutron_domains`, then to `reconcile_neutron_acl`, and finally to
`translate_neutron_acl_with_cache`. Detach and no-op skipped ports do not use
the cache. A full snapshot shares one cache across all update/attach ports; a
port-scoped request gets a fresh cache because it enters a new runtime
transaction.

- [ ] **Step 18: Implement production reconcile failure classification**

Define:

```rust
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AclReconcileFailurePhase {
    BeforeQuiesce,
    AfterQuiesce,
    CompensationFailed,
}

fn acl_reconcile_error(
    phase: AclReconcileFailurePhase,
    details: impl Into<String>,
) -> NeutronAclReconcileError {
    match phase {
        AclReconcileFailurePhase::BeforeQuiesce => NeutronAclReconcileError::unchanged(details),
        AclReconcileFailurePhase::AfterQuiesce => NeutronAclReconcileError::bypass(details),
        AclReconcileFailurePhase::CompensationFailed => NeutronAclReconcileError::enforce(details),
    }
}
```

Use this helper at real `map_err` and compensation call sites. Translation,
config read, and failed quiesce use `BeforeQuiesce`; all failures after a
successful quiesce use `AfterQuiesce`; failed post-enable disable compensation
uses `CompensationFailed`. Delete the test-only outcome constructor.

- [ ] **Step 19: Push Rust GREEN and wait for full Build**

Run allowed local checks only:

```bash
python3 ci/check_blocked_terms.py
PYTHON_BIN="$(command -v python3)"
PATH=/usr/bin:/bin:/usr/sbin:/sbin "$PYTHON_BIN" ci/check_neutron_stage1.py
python3 ci/check_neutron_stage2_acl.py
git diff --check
git add agent/src/neutron_api.rs
git commit -m "fix: cache and bound Rust ACL validation"
git push origin codex/acl-batch-5-priority-guardrails
gh workflow run Build --ref codex/acl-batch-5-priority-guardrails -f publish_artifacts=false
```

Expected: `neutron_acl_` tests pass, followed by eBPF, userspace static, agent
static, and binary verification. Fix only evidence-backed failures and rerun
until green.

- [ ] **Step 20: Tighten the two static CI guards**

In Stage 1, replace the workflow substring with an active-line regex:

```python
acl_test_command = "cargo +stable test --locked -p aria-agent neutron_acl_"
acl_test_pattern = r"(?m)^[ \t]+%s[ \t]*$" % re.escape(acl_test_command)
if not re.search(acl_test_pattern, build_workflow_source):
    raise SystemExit("ERROR: Build workflow missing active %s" % acl_test_command)
```

Extend Rust required terms with the limit constants, cache types, production
`from_plan` test, and phase-classifier test.

In Stage 2, use separate lists:

```python
required_source_terms = (
    "MAX_ACL_RULES_PER_POLICY = 1000",
    "MAX_ACL_SELECTOR_MEMBERS = 2048",
    "def _strict_ipv4_cidr(",
    "def _selector_relation(",
    "def _compile_rules_uncached(",
    "acl_rule_limit_exceeded:",
    "acl_selector_member_limit_exceeded:",
)
required_test_terms = (
    "test_cidr_whitespace_is_canonicalized_in_snapshot",
    "test_rule_runtime_limit_accepts_1000_and_bypasses_1001",
    "test_selector_runtime_limit_accepts_2048_and_bypasses_2049",
    "test_policy_compile_cache_reuses_ready_result",
)
```

Check each tuple only against its owning file.

- [ ] **Step 21: Refresh documentation after implementation GREEN**

Document the exact `1000/2048` runtime limits, strict IPv4 grammar, Python
index-lifetime cache, and Rust request-scoped cache in `02-aria-acl-plugin.md`.

Keep `REVIEW-ACL-047` fixed and all inventory counts unchanged. Add a final
hardening verification subsection to the backlog with:

- Python RED and GREEN evidence;
- Rust RED and GREEN run IDs;
- final rule/member/cache/outcome test evidence;
- statement that no local Cargo command ran.

Mark the hardening design `implemented and verified` only after the Rust GREEN
workflow. Add the hardening run to the original Batch 5 design so its closure
evidence points to the final implementation head.

- [ ] **Step 22: Run final local verification and commit closure**

```bash
python3 ci/check_blocked_terms.py
PYTHONPATH=openstack/neutron_aria python3 -m unittest discover \
  -s openstack/neutron_aria/neutron_aria/tests/unit -p 'test_*.py'
PYTHON_BIN="$(command -v python3)"
PATH=/usr/bin:/bin:/usr/sbin:/sbin "$PYTHON_BIN" ci/check_neutron_stage1.py
python3 ci/check_neutron_stage2_acl.py
python3 ci/check_stage3_readiness.py
git diff --check
git status --short
```

Expected: all checks pass; only the user's pre-existing `README.md` is dirty.
Commit CI/docs files separately:

```bash
git add \
  ci/check_neutron_stage1.py \
  ci/check_neutron_stage2_acl.py \
  docs/openstack-neutron-aria-details/02-aria-acl-plugin.md \
  docs/openstack-neutron-aria-details/12-review-bug-backlog.md \
  docs/superpowers/specs/2026-07-12-acl-batch-5-priority-overlap-guardrails-design.md \
  docs/superpowers/specs/2026-07-12-acl-batch-5-final-review-hardening-design.md
git commit -m "docs: close ACL final review hardening"
git push origin codex/acl-batch-5-priority-guardrails
gh workflow run Build --ref codex/acl-batch-5-priority-guardrails -f publish_artifacts=false
```

Do not declare complete until this closure workflow is green. Record the final
run ID in the backlog and both design documents with one documentation-only
evidence commit, push it, and verify local/upstream divergence is `0 0`.
