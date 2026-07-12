# ACL Batch 5 Priority And Overlap Guardrails Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix `REVIEW-ACL-047` by accepting only ACL rule sets whose result is independent of Neutron priority, while unsupported overlaps converge to a real runtime `degraded/bypass` state.

**Architecture:** Python validates the compiled effective rule set before submission and marks unsupported priority/overlap shapes degraded. Rust repeats the same guard for direct UDS callers, canonicalizes identical IPv4 selector sets into shared groups, and classifies unsupported shapes as an empty force-bypass plan. Reconcile applies that empty plan through the existing Batch 4 CT/ACL transaction and returns a runtime-derived ACL status override only after the bypass transaction succeeds.

**Tech Stack:** Python 2/3-compatible OpenStack adapter code, Rust, Tokio, Aya/eBPF policy maps, repository Python/static checks, GitHub Actions.

## Global Constraints

- Implement only `REVIEW-ACL-047`.
- Do not add priority to `PolicyKey`, `PolicyValue`, CT state, WAL state, or eBPF maps.
- Do not implement ordered eBPF rule scanning, IPv6, source-port support, default-deny, QoS, or Mirror.
- Empty CIDRs mean `any`; identical canonical IPv4 selector sets reuse one group; non-identical intersecting CIDR sets are rejected.
- Wildcard/specific fallback is accepted only when behavior is identical, or when the pair is concretely disjoint.
- Preserve safe same-key, same-action destination-port union.
- Unsupported priority/overlap input must disable ACL and report `degraded/bypass`; it must not leave old ACL active under `error/unchanged`.
- Ordinary translation errors outside this batch retain `error/unchanged` before mutation.
- Never run local `cargo build`, `cargo check`, or `cargo test`; GitHub Actions provides Rust/eBPF red and green evidence.
- Preserve and exclude the user's uncommitted `README.md` change.
- Use separate red-test, implementation, and closure-documentation commits.

## File Map

| File | Responsibility |
| --- | --- |
| `openstack/neutron_aria/neutron_aria/agent/effective_acl.py` | Python IPv4 normalization, CIDR ownership guard, fallback-overlap guard, and stable degradation reasons. |
| `openstack/neutron_aria/neutron_aria/tests/unit/test_effective_acl.py` | Python unit coverage for canonical selectors, overlap rejection, disjoint rules, and stable reasons. |
| `openstack/neutron_aria/neutron_aria/tests/unit/test_event_loop.py` | End-to-end Python projection of the new stable invalid-priority reason into UDS/status payloads. |
| `agent/src/neutron_api.rs` | Rust normalized rule model, defensive guard, canonical group reuse, classified force-bypass plan, reconcile outcome, and Rust tests. |
| `ci/check_neutron_stage1.py` | Static Rust contract guard for force-bypass status, canonical reuse, and unchanged eBPF key boundary. |
| `ci/check_neutron_stage2_acl.py` | Static Python contract guard for the priority/overlap test surface and stable reason prefixes. |
| `docs/openstack-neutron-aria-details/02-aria-acl-plugin.md` | Operational statement that numeric priority is stored but priority-dependent overlap is rejected in this datapath version. |
| `docs/openstack-neutron-aria-details/12-review-bug-backlog.md` | Batch 5 evidence, fixed status for `ACL-047`, counts, and next fix order. |
| `docs/superpowers/specs/2026-07-12-acl-batch-5-priority-overlap-guardrails-design.md` | Final implementation/verification status for the approved design. |

---

### Task 1: Establish Red Priority And Bypass Contracts

**Files:**
- Test: `openstack/neutron_aria/neutron_aria/tests/unit/test_effective_acl.py`
- Test: `openstack/neutron_aria/neutron_aria/tests/unit/test_event_loop.py`
- Test: `agent/src/neutron_api.rs`

**Interfaces:**
- Requires future Python stable reasons `unsupported_acl_cidr_overlap`, `unsupported_acl_priority_overlap`, `invalid_acl_priority`, and `duplicate_acl_priority`.
- Requires future Rust `AclApplyPlan.force_bypass_reason: Option<String>`.
- Requires future Rust `NeutronAclReconcileOutcome::domain_status(&NeutronPortSnapshot)`.
- Preserves `translate_neutron_acl(&str, &NeutronAclSnapshot) -> Result<AclApplyPlan, String>` so unrelated translation failures remain distinguishable.

- [ ] **Step 1: Add a compact Python rule fixture**

Add this fixture above `EffectiveAclTestCase`:

```python
def acl_rule(rule_id, priority, **overrides):
    rule = {
        "id": rule_id,
        "policy_id": "policy-1",
        "direction": "egress",
        "priority": priority,
        "action": "deny",
        "ethertype": "IPv4",
        "protocol": "tcp",
    }
    rule.update(overrides)
    return rule


def effective_acl(rules):
    return EffectiveAclIndex(
        policies=[{"id": "policy-1", "default_action": "allow"}],
        rules=rules,
        bindings=[{
            "id": "binding-1",
            "policy_id": "policy-1",
            "target_type": "port",
            "target_id": PORT_ID,
        }],
    ).effective_for_port(port(), snapshot())
```

- [ ] **Step 2: Add failing Python ownership and fallback tests**

Add tests that require the approved boundary:

```python
def test_nested_cidrs_degrade_with_stable_overlap_reason(self):
    result = effective_acl([
        acl_rule("broad", 10, src_cidr="10.0.0.0/8"),
        acl_rule("narrow", 20, src_cidr="10.1.0.0/16", protocol="udp"),
    ])
    self.assertEqual(ACL_DEGRADED, result["status"])
    self.assertEqual("bypass", result["effective_action"])
    self.assertIn(
        "unsupported_acl_cidr_overlap:src:broad:10:narrow:20",
        result["reason"],
    )

def test_partial_cidr_intersection_degrades(self):
    result = effective_acl([
        acl_rule("left", 10, dst_cidr="10.0.0.0/23"),
        acl_rule("right", 20, dst_cidr="10.0.1.0/24", protocol="udp"),
    ])
    self.assertIn("unsupported_acl_cidr_overlap:dst:left:10:right:20", result["reason"])

def test_wildcard_specific_behavior_conflict_degrades(self):
    result = effective_acl([
        acl_rule("wildcard", 10, protocol=None, action="allow"),
        acl_rule("tcp-drop", 20, protocol="tcp", action="deny"),
    ])
    self.assertIn(
        "unsupported_acl_priority_overlap:wildcard:10:tcp-drop:20",
        result["reason"],
    )

def test_specificity_port_behavior_conflict_degrades(self):
    result = effective_acl([
        acl_rule("any-src", 10, dst_port_min=80, dst_port_max=80),
        acl_rule(
            "specific-src", 20, src_cidr="10.1.0.0/16",
            dst_port_min=443, dst_port_max=443,
        ),
    ])
    self.assertIn(
        "unsupported_acl_priority_overlap:any-src:10:specific-src:20",
        result["reason"],
    )
```

- [ ] **Step 3: Add failing Python safe-shape and priority tests**

Require canonical equivalence, concrete disjointness, and the new stable priority reasons:

```python
def test_canonical_equivalent_cidrs_are_one_safe_selector(self):
    result = effective_acl([
        acl_rule("tcp", 10, src_cidr="10.1.2.3/24", dst_port_min=80),
        acl_rule("udp", 20, src_cidr="10.1.2.0/24", protocol="udp", dst_port_min=53),
    ])
    self.assertEqual(ACL_READY, result["status"])
    self.assertEqual("enforce", result["effective_action"])

def test_disjoint_protocols_and_cidrs_remain_ready(self):
    result = effective_acl([
        acl_rule("tcp-left", 10, src_cidr="10.1.0.0/16"),
        acl_rule("udp-right", 20, src_cidr="10.2.0.0/16", protocol="udp"),
    ])
    self.assertEqual(ACL_READY, result["status"])

def test_negative_priority_uses_stable_reason(self):
    result = effective_acl([acl_rule("negative", -1)])
    self.assertIn("invalid_acl_priority:negative:-1", result["reason"])

def test_duplicate_priority_uses_stable_reason(self):
    result = effective_acl([
        acl_rule("first", 10),
        acl_rule("second", 10, protocol="udp"),
    ])
    self.assertIn(
        "duplicate_acl_priority:egress:10:first:second",
        result["reason"],
    )
```

Update the existing invalid-priority assertions in `test_effective_acl.py` and
`test_event_loop.py` from `invalid_rule_priority:<id>` to
`invalid_acl_priority:<id>:<raw-value>`.

- [ ] **Step 4: Add failing Rust translator tests**

Add a helper that changes a complete DTO without duplicating all fields:

```rust
fn acl_rule_with(
    id: &str,
    priority: i64,
    protocol: &str,
    action: &str,
    src_cidrs: &[&str],
    dst_cidrs: &[&str],
    dst_port: Option<u16>,
) -> NeutronAclRuleSnapshot {
    NeutronAclRuleSnapshot {
        id: Some(id.to_string()),
        direction: Some("egress".to_string()),
        priority,
        action: Some(action.to_string()),
        ethertype: Some("IPv4".to_string()),
        protocol: Some(protocol.to_string()),
        src_cidrs: src_cidrs.iter().map(|value| value.to_string()).collect(),
        dst_cidrs: dst_cidrs.iter().map(|value| value.to_string()).collect(),
        src_port_min: None,
        src_port_max: None,
        dst_port_min: dst_port,
        dst_port_max: dst_port,
    }
}
```

Then add these red contracts:

```rust
#[test]
fn neutron_acl_translator_force_bypasses_nested_cidrs() {
    let acl = ready_acl(vec![
        acl_rule_with("broad", 10, "tcp", "allow", &["10.0.0.0/8"], &[], None),
        acl_rule_with("narrow", 20, "udp", "allow", &["10.1.0.0/16"], &[], None),
    ]);
    let plan = translate_neutron_acl("port-1", &acl).unwrap();
    assert!(plan.groups.is_empty());
    assert!(plan.policies.is_empty());
    assert_eq!(
        plan.force_bypass_reason.as_deref(),
        Some("unsupported_acl_cidr_overlap:src:broad:10:narrow:20")
    );
}

#[test]
fn neutron_acl_translator_reuses_canonical_cidr_groups() {
    let acl = ready_acl(vec![
        acl_rule_with("tcp", 10, "tcp", "drop", &["10.1.2.3/24"], &[], Some(80)),
        acl_rule_with("udp", 20, "udp", "drop", &["10.1.2.0/24"], &[], Some(53)),
    ]);
    let plan = translate_neutron_acl("port-1", &acl).unwrap();
    assert_eq!(plan.groups.len(), 1);
    assert_eq!(plan.groups[0].cidrs, vec!["10.1.2.0/24"]);
    assert_eq!(plan.policies[0].src_group, plan.policies[1].src_group);
    assert_eq!(plan.force_bypass_reason, None);
}

#[test]
fn neutron_acl_translator_force_bypasses_priority_fallback_conflict() {
    let acl = ready_acl(vec![
        acl_rule_with("wildcard", 10, "any", "allow", &[], &[], None),
        acl_rule_with("tcp-drop", 20, "tcp", "drop", &[], &[], None),
    ]);
    let plan = translate_neutron_acl("port-1", &acl).unwrap();
    assert_eq!(
        plan.force_bypass_reason.as_deref(),
        Some("unsupported_acl_priority_overlap:wildcard:10:tcp-drop:20")
    );
}

#[test]
fn neutron_acl_translator_force_bypasses_invalid_and_duplicate_priority() {
    let negative = ready_acl(vec![acl_rule_with(
        "negative", -1, "tcp", "drop", &[], &[], None,
    )]);
    assert_eq!(
        translate_neutron_acl("port-1", &negative)
            .unwrap()
            .force_bypass_reason
            .as_deref(),
        Some("invalid_acl_priority:negative:-1")
    );

    let duplicate = ready_acl(vec![
        acl_rule_with("first", 10, "tcp", "drop", &[], &[], None),
        acl_rule_with("second", 10, "udp", "drop", &[], &[], None),
    ]);
    assert_eq!(
        translate_neutron_acl("port-1", &duplicate)
            .unwrap()
            .force_bypass_reason
            .as_deref(),
        Some("duplicate_acl_priority:egress:10:first:second")
    );
}
```

Retain the existing same-key/same-action port-union test and add a disjoint CIDR
test that asserts two groups, two policies, and `force_bypass_reason == None`.

- [ ] **Step 5: Add the failing Rust status-override contract**

Require a reconcile outcome that cannot be reported until reconcile returns:

```rust
#[test]
fn neutron_acl_force_bypass_outcome_overrides_optimistic_snapshot() {
    let mut snapshot = port("vm-port", "tap-vm", true);
    snapshot.managed_domains = vec!["acl".to_string()];
    snapshot.acl = Some(ready_acl(Vec::new()));
    let outcome = NeutronAclReconcileOutcome::force_bypass(
        "unsupported_acl_priority_overlap:first:10:second:20".to_string(),
    );

    let status = outcome.domain_status(&snapshot);
    assert_eq!(status.status, "degraded");
    assert_eq!(status.effective_action.as_deref(), Some("bypass"));
    assert_eq!(
        status.reason.as_deref(),
        Some("unsupported_acl_priority_overlap:first:10:second:20")
    );
}
```

- [ ] **Step 6: Record local Python red and GitHub Actions Rust red**

Run only the allowed Python target first:

```bash
PYTHONPATH=openstack/neutron_aria python3 -m unittest \
  neutron_aria.tests.unit.test_effective_acl \
  neutron_aria.tests.unit.test_event_loop
```

Expected: failures identify missing Python overlap guards and old stable reason
names. Then commit only the red tests:

```bash
git add \
  openstack/neutron_aria/neutron_aria/tests/unit/test_effective_acl.py \
  openstack/neutron_aria/neutron_aria/tests/unit/test_event_loop.py \
  agent/src/neutron_api.rs
git commit -m "test: require ACL priority overlap guardrails"
git push -u origin codex/acl-batch-5-priority-guardrails
gh workflow run Build --ref codex/acl-batch-5-priority-guardrails -f publish_artifacts=false
```

Expected GitHub Actions result: Rust compilation fails only because
`force_bypass_reason` and `NeutronAclReconcileOutcome` do not yet exist, while
the new Python tests also demonstrate the missing behavior.

---

### Task 2: Implement Python Pre-Submission Guardrails

**Files:**
- Modify: `openstack/neutron_aria/neutron_aria/agent/effective_acl.py:1-345`
- Test: `openstack/neutron_aria/neutron_aria/tests/unit/test_effective_acl.py`
- Test: `openstack/neutron_aria/neutron_aria/tests/unit/test_event_loop.py`

**Interfaces:**
- Produces `_canonical_ipv4_cidrs(cidrs) -> tuple[(network_int, prefix)]`.
- Produces `_acl_overlap_reason(compiled_rules) -> str | None`.
- `_compile_rules` appends the stable reason after all individually valid rules compile.
- Leaves the serialized rule DTO shape unchanged.

- [ ] **Step 1: Add Python-2/3-compatible IPv4 canonicalization**

Import `socket` and `struct`, then add:

```python
def _ipv4_network(cidr):
    address, prefix = str(cidr).split("/", 1)
    prefix = int(prefix)
    if prefix < 0 or prefix > 32:
        raise ValueError("invalid IPv4 prefix")
    value = struct.unpack("!I", socket.inet_aton(address))[0]
    mask = 0 if prefix == 0 else ((0xffffffff << (32 - prefix)) & 0xffffffff)
    return value & mask, prefix


def _canonical_ipv4_cidrs(cidrs):
    return tuple(sorted(set(_ipv4_network(cidr) for cidr in cidrs or [])))


def _ipv4_cidrs_intersect(left, right):
    for left_network, left_prefix in left:
        for right_network, right_prefix in right:
            prefix = min(left_prefix, right_prefix)
            mask = 0 if prefix == 0 else ((0xffffffff << (32 - prefix)) & 0xffffffff)
            if (left_network & mask) == (right_network & mask):
                return True
    return False
```

The existing contract validator remains responsible for user-facing malformed
CIDR errors; these helpers receive already compiled IPv4 rules.

- [ ] **Step 2: Add normalized behavior helpers**

Add deterministic helpers used only by the overlap validator:

```python
def _normalized_protocol(protocol):
    value = str(protocol or "any").lower()
    known = {"any": 0, "tcp": 6, "udp": 17, "icmp": 1}
    if value in known:
        return known[value]
    return int(value)


def _normalized_action(action):
    value = str(action or "allow").lower()
    if value in ("allow", "accept", "pass"):
        return "allow"
    if value in ("deny", "drop"):
        return "deny"
    return value


def _normalized_ports(rule):
    minimum = rule.get("dst_port_min")
    maximum = rule.get("dst_port_max")
    if minimum is None and maximum is None:
        return ()
    minimum = int(minimum if minimum is not None else maximum)
    maximum = int(maximum if maximum is not None else minimum)
    return ((minimum, maximum),)


def _datapath_directions(direction):
    value = str(direction or "ingress").lower()
    if value == "both":
        return frozenset((0, 1))
    return frozenset((1,)) if value == "ingress" else frozenset((0,))
```

Build normalized dictionaries with ID, priority, normalized action, protocol, directions,
canonical source/destination selectors, and ports. Sort them by
`(direction, priority, id)` before pair validation so every stable reason uses
the same `rule-a/rule-b` ordering.

- [ ] **Step 3: Implement CIDR ownership rejection**

For each rule pair and each side, reject only non-empty, non-identical selector
sets that intersect:

```python
for side in ("src", "dst"):
    left_cidrs = left[side + "_cidrs"]
    right_cidrs = right[side + "_cidrs"]
    if (left_cidrs and right_cidrs and left_cidrs != right_cidrs and
            _ipv4_cidrs_intersect(left_cidrs, right_cidrs)):
        return "unsupported_acl_cidr_overlap:%s:%s:%s:%s:%s" % (
            side, left["id"], left["priority"],
            right["id"], right["priority"],
        )
```

Perform this check regardless of protocol, action, or port because the LPM map
can return only one group ID.

- [ ] **Step 4: Implement priority-independent fallback validation**

Use these exact safety rules in pair order:

```python
if not (left["directions"] & right["directions"]):
    continue
if left["protocol"] and right["protocol"] and left["protocol"] != right["protocol"]:
    continue
if _selector_dimension_is_disjoint(left["src_cidrs"], right["src_cidrs"]):
    continue
if _selector_dimension_is_disjoint(left["dst_cidrs"], right["dst_cidrs"]):
    continue

same_key = (
    left["protocol"] == right["protocol"] and
    left["src_cidrs"] == right["src_cidrs"] and
    left["dst_cidrs"] == right["dst_cidrs"]
)
same_behavior = (
    left["action"] == right["action"] and
    left["ports"] == right["ports"]
)
if same_behavior or (same_key and left["action"] == right["action"]):
    continue
return "unsupported_acl_priority_overlap:%s:%s:%s:%s" % (
    left["id"], left["priority"], right["id"], right["priority"],
)
```

`_selector_dimension_is_disjoint` returns true only when both selector sets are
non-empty and have no intersection; an empty selector means `any`.

- [ ] **Step 5: Replace old priority diagnostics and invoke the guard**

Reject a non-integer or negative value with:

```python
"invalid_acl_priority:%s:%s" % (rule.get("id"), rule.get("priority"))
```

Track `(direction, priority) -> first_rule_id`; emit:

```python
"duplicate_acl_priority:%s:%s:%s:%s" % (
    direction, priority, first_rule_id, rule.get("id"),
)
```

After individual compilation, call `_acl_overlap_reason(compiled)`. Append its
single deterministic reason when present. Existing `effective_for_port`
automatically projects any reason to `enabled=false`, `status=degraded`, and
`effective_action=bypass`.

- [ ] **Step 6: Run Python checks and commit**

```bash
PYTHONPATH=openstack/neutron_aria python3 -m unittest \
  neutron_aria.tests.unit.test_effective_acl \
  neutron_aria.tests.unit.test_event_loop
python3 ci/check_neutron_stage2_acl.py
git diff --check
git add \
  openstack/neutron_aria/neutron_aria/agent/effective_acl.py \
  openstack/neutron_aria/neutron_aria/tests/unit/test_effective_acl.py \
  openstack/neutron_aria/neutron_aria/tests/unit/test_event_loop.py
git commit -m "fix: reject priority-dependent ACL rules in Python"
```

Expected: targeted tests and all Stage 2 tests pass locally. Rust red tests
remain intentionally uncompilable until Task 3.

---

### Task 3: Implement Rust Defensive Guard And Real Force-Bypass Outcome

**Files:**
- Modify: `agent/src/neutron_api.rs:170-285,2320-2344,2453-2520,3195-3489,3580-3812,4137-4169,6177-6414`
- Test: `agent/src/neutron_api.rs`

**Interfaces:**
- Adds `AclIpv4Cidr { network: u32, prefix: u8 }`.
- Adds `NormalizedAclRule` carrying canonical selectors and datapath directions.
- Adds `AclApplyPlan.force_bypass_reason: Option<String>`.
- Adds `NeutronAclReconcileOutcome::domain_status(&NeutronPortSnapshot)`.
- Keeps `AclEffectivePolicyKey` and the eBPF `PolicyKey` layout unchanged.

- [ ] **Step 1: Add canonical Rust IPv4 and normalized-rule types**

Define an ordered CIDR value and explicit renderer:

```rust
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct AclIpv4Cidr {
    network: u32,
    prefix: u8,
}

impl AclIpv4Cidr {
    fn parse(value: &str) -> Result<Self, String> {
        let (address, prefix) = value
            .split_once('/')
            .ok_or_else(|| format!("invalid IPv4 CIDR {}", value))?;
        let address = address
            .parse::<std::net::Ipv4Addr>()
            .map_err(|_| format!("invalid IPv4 CIDR {}", value))?;
        let prefix = prefix
            .parse::<u8>()
            .map_err(|_| format!("invalid IPv4 CIDR {}", value))?;
        if prefix > 32 {
            return Err(format!("invalid IPv4 CIDR {}", value));
        }
        let mask = if prefix == 0 { 0 } else { u32::MAX << (32 - prefix) };
        Ok(Self { network: u32::from(address) & mask, prefix })
    }

    fn intersects(self, other: Self) -> bool {
        let prefix = self.prefix.min(other.prefix);
        let mask = if prefix == 0 { 0 } else { u32::MAX << (32 - prefix) };
        (self.network & mask) == (other.network & mask)
    }

    fn canonical(self) -> String {
        format!("{}/{}", std::net::Ipv4Addr::from(self.network), self.prefix)
    }
}
```

`NormalizedAclRule` contains `id`, `priority`, `directions`, `proto`, `action`,
`src_cidrs`, `dst_cidrs`, and normalized destination-port ranges. Parse all
ordinary rule fields first; malformed CIDRs, unsupported source ports, and
unsupported protocol/action remain ordinary `Err(String)` translation errors.

- [ ] **Step 2: Detect stable Rust priority and overlap reasons**

Before group creation:

1. Reject `priority < 0` as `invalid_acl_priority:<id>:<priority>`.
2. Track `(normalized Neutron direction, priority)` and reject the second rule
   as `duplicate_acl_priority:<direction>:<priority>:<first-id>:<second-id>`.
3. Sort normalized rules by `(direction text, priority, id)` for deterministic
   pair diagnostics.
4. Apply the same CIDR ownership and fallback pair algorithm as Task 2.

Return `Option<String>` from `acl_priority_overlap_reason`; `None` means the
rules are priority-independent. Stable overlap strings are created only in one
function so Python/Rust prefixes cannot drift.

- [ ] **Step 3: Add the classified force-bypass plan**

Extend the plan:

```rust
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct AclApplyPlan {
    groups: Vec<AclGroupPlan>,
    policies: Vec<AclPolicyPlan>,
    conntrack_enabled: Option<bool>,
    force_bypass_reason: Option<String>,
}

fn force_bypass_acl_plan(acl: &NeutronAclSnapshot, reason: String) -> AclApplyPlan {
    AclApplyPlan {
        conntrack_enabled: Some(acl.stateful),
        force_bypass_reason: Some(reason),
        ..AclApplyPlan::default()
    }
}
```

In `translate_neutron_acl`, ordinary parsing errors still use `Err`. A stable
priority/overlap reason returns `Ok(force_bypass_acl_plan(acl, reason))` before
any groups or policies are built.

- [ ] **Step 4: Reuse canonical selector groups deterministically**

Build source and destination selector registries independently from a sorted
`BTreeSet<Vec<AclIpv4Cidr>>`. Assign stable per-snapshot names in canonical
selector order:

```rust
neutron:<port-id>:src:selector:<ordinal>
neutron:<port-id>:dst:selector:<ordinal>
```

Each registry produces one `AclGroupPlan` per unique non-empty selector and a
lookup from canonical selector to group name. Render only canonical CIDRs into
the group. `any` continues to map to the literal group name `any`. The same
canonical selector used by multiple rules on the same side must resolve to the
same group name, while source and destination registries remain independent.

- [ ] **Step 5: Return a runtime status only after reconcile succeeds**

Add:

```rust
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct NeutronAclReconcileOutcome {
    force_bypass_reason: Option<String>,
}

impl NeutronAclReconcileOutcome {
    fn from_plan(plan: &AclApplyPlan) -> Self {
        Self { force_bypass_reason: plan.force_bypass_reason.clone() }
    }

    fn force_bypass(reason: String) -> Self {
        Self { force_bypass_reason: Some(reason) }
    }

    fn domain_status(&self, port: &NeutronPortSnapshot) -> NeutronDomainStatus {
        match &self.force_bypass_reason {
            Some(reason) => domain_status_with_action(
                "acl", "degraded", Some(reason.clone()), Some("bypass".to_string()),
            ),
            None => acl_domain_status_for(port),
        }
    }
}
```

Change `reconcile_neutron_acl` to return
`Result<NeutronAclReconcileOutcome, NeutronAclReconcileError>`. Capture the
outcome from the translated plan, run the existing Batch 4 sequence unchanged,
and return `Ok(outcome)` only after the empty or non-empty publish succeeds.
Change the domain loop to:

```rust
"acl" => match reconcile_neutron_acl(state, port).await {
    Ok(outcome) => statuses.push(outcome.domain_status(port)),
    Err(error) => {
        let reason = format!("acl_apply_failed:{}", error.details);
        statuses.push(domain_status_with_action(
            &domain,
            "error",
            Some(reason.clone()),
            Some(error.effective_action.to_string()),
        ));
        errors.push(reason);
    }
},
```

This preserves `error/unchanged` when quiesce fails. Any failure after quiesce
continues to use the existing proven `bypass`/`enforce` error classification;
no failed transaction returns the optimistic `degraded/bypass` override.

- [ ] **Step 6: Preserve same-key merging and update existing literals**

Keep `merge_acl_ports` unchanged. Because canonical group names now replace
rule-ID-scoped names, update existing translator assertions to use the new
selector names and add `force_bypass_reason: None` to explicit
`AclApplyPlan` literals. Confirm the existing same-key/same-action test still
serializes `8080,18081`.

- [ ] **Step 7: Run allowed static checks, commit, and obtain green CI**

```bash
python3 ci/check_blocked_terms.py
PYTHON_BIN="$(command -v python3)"
PATH=/usr/bin:/bin:/usr/sbin:/sbin "$PYTHON_BIN" ci/check_neutron_stage1.py
python3 ci/check_neutron_stage2_acl.py
git diff --check
git add agent/src/neutron_api.rs
git commit -m "fix: force bypass unsupported ACL overlaps"
git push origin codex/acl-batch-5-priority-guardrails
gh workflow run Build --ref codex/acl-batch-5-priority-guardrails -f publish_artifacts=false
```

Expected GitHub Actions result: all new Rust tests compile and pass, eBPF key
layout remains unchanged, and static userspace/agent builds succeed. If CI
finds a Rust error, fix only that evidence-backed defect and rerun the same
workflow; do not run Cargo locally.

---

### Task 4: Guard And Close Batch 5

**Files:**
- Modify: `ci/check_neutron_stage1.py`
- Modify: `ci/check_neutron_stage2_acl.py`
- Modify: `docs/openstack-neutron-aria-details/02-aria-acl-plugin.md`
- Modify: `docs/openstack-neutron-aria-details/12-review-bug-backlog.md`
- Modify: `docs/superpowers/specs/2026-07-12-acl-batch-5-priority-overlap-guardrails-design.md`

**Interfaces:**
- Consumes the exact Python/Rust test names and stable prefixes added in Tasks 1-3.
- Produces durable CI guards and audit evidence for `REVIEW-ACL-047` closure.

- [ ] **Step 1: Add Stage 1 Rust static guards**

Extend `required_acl_conntrack_terms` or add a neighboring
`required_acl_priority_terms` list containing:

```python
required_acl_priority_terms = [
    "struct AclIpv4Cidr {",
    "force_bypass_reason: Option<String>",
    "fn neutron_acl_translator_force_bypasses_nested_cidrs(",
    "fn neutron_acl_translator_reuses_canonical_cidr_groups(",
    "fn neutron_acl_translator_force_bypasses_priority_fallback_conflict(",
    "fn neutron_acl_force_bypass_outcome_overrides_optimistic_snapshot(",
    "unsupported_acl_cidr_overlap:",
    "unsupported_acl_priority_overlap:",
]
```

Also read `ebpf/src/common.rs` and assert that its `PolicyKey` source still lacks a
`priority` field. The guard must identify the `struct PolicyKey` block before
checking so unrelated priority fields elsewhere do not produce false results.

- [ ] **Step 2: Add Stage 2 Python static guards**

Read `effective_acl.py` and `test_effective_acl.py`, then require:

```python
for term in (
    "def _canonical_ipv4_cidrs(",
    "def _acl_overlap_reason(",
    "unsupported_acl_cidr_overlap:",
    "unsupported_acl_priority_overlap:",
    "invalid_acl_priority:",
    "duplicate_acl_priority:",
    "test_nested_cidrs_degrade_with_stable_overlap_reason",
    "test_canonical_equivalent_cidrs_are_one_safe_selector",
    "test_specificity_port_behavior_conflict_degrades",
):
    if term not in effective_source + effective_tests:
        raise SystemExit("ERROR: ACL priority guard missing %s" % term)
```

- [ ] **Step 3: Document the supported priority boundary**

In `02-aria-acl-plugin.md`, state:

- lower numeric priority remains the northbound ordering convention;
- the current eBPF datapath does not implement numeric priority ordering;
- exact canonical CIDR sets and concretely disjoint rules are accepted;
- non-identical intersecting CIDRs and behavior-changing wildcard/specific
  fallbacks are rejected as `degraded/bypass`;
- QoS and Mirror remain outside this fix.

- [ ] **Step 4: Close only `REVIEW-ACL-047` and update counts**

Change the row to `fixed` with evidence that Python preflight and Rust direct
UDS defense both reject priority-dependent overlaps, canonical group reuse is
covered, and actual runtime bypass status is returned only after the empty ACL
transaction succeeds.

Update the top-level counts from Batch 4 to Batch 5:

- confirmed active defect/contract gap: `34 -> 33`;
- fixed: `22 -> 23`;
- transaction/datapath/recovery/runtime class: `16 -> 15` and remove `ACL-047`;
- total `REVIEW-*`: remain `60`;
- risk/debt and total tracking items: unchanged.

Append a Batch 5 verification section with the red and green GitHub Actions run
IDs, local Python/static counts, and the statement that no local Cargo command
was run. Move the active fix order past `ACL-047` without changing unrelated
QoS/Mirror records.

- [ ] **Step 5: Mark the approved design implemented**

Change the design status to `implemented and verified` only after green GitHub
Actions, and add the final commit and workflow run IDs under Verification.

- [ ] **Step 6: Run final allowed verification and commit closure**

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

Expected: all Python/static/shell checks pass and only the user's pre-existing
`README.md` remains outside the Batch 5 diff. Then commit and push:

```bash
git add \
  ci/check_neutron_stage1.py \
  ci/check_neutron_stage2_acl.py \
  docs/openstack-neutron-aria-details/02-aria-acl-plugin.md \
  docs/openstack-neutron-aria-details/12-review-bug-backlog.md \
  docs/superpowers/specs/2026-07-12-acl-batch-5-priority-overlap-guardrails-design.md
git commit -m "docs: close ACL priority overlap bug"
git push origin codex/acl-batch-5-priority-guardrails
gh workflow run Build --ref codex/acl-batch-5-priority-guardrails -f publish_artifacts=false
```

Do not report Batch 5 complete until the final workflow is green. If the final
run succeeds, record its run ID in the design and backlog with a final
documentation-only evidence commit, push once more, and verify that the branch
and remote point to the same commit.
