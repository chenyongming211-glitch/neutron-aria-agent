# ACL Batch 1 Contract Guardrails Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the 12 Batch 1 ACL findings by enforcing one strict current-MVP contract from Neutron API through Python compilation, agent configuration, UDS capabilities, and status projection.

**Architecture:** A stdlib-only shared Python module validates northbound writes and defensively validates existing records during effective-ACL compilation. The Python agent admits only ACL, Rust advertises only `attach` and `acl`, and concrete UDS runtime status always overrides desired-state metadata.

**Tech Stack:** Python 2/3 compatible stdlib, legacy Neutron service plugin, unittest, Rust capability constants/tests, JSON UDS contract, GitHub Actions.

## Global Constraints

- Do not implement QoS or Mirror; reject them as managed runtime domains.
- Invalid ACL enhancement input is rejected northbound or classified `degraded` with `effective_action=bypass` for existing records.
- Keep OVS connectivity readiness independent from Aria ACL readiness.
- Do not run local `cargo build`, `cargo check`, or `cargo test`.
- Use red-green-refactor for every locally executable behavior change.
- Preserve unrelated dirty files in the original checkout.

---

### Task 1: Shared ACL Contract Validator

**Files:**
- Create: `openstack/neutron_aria/neutron_aria/acl_contract.py`
- Create: `openstack/neutron_aria/neutron_aria/tests/unit/test_acl_contract.py`

**Interfaces:**
- Produces: `AclContractError`, `validate_policy`, `validate_rule`, `validate_address_set_reference`, `port_contract_eligibility`.

- [ ] **Step 1: Write failing tests**

```python
class AclContractTestCase(unittest.TestCase):
    def test_policy_rejects_default_deny(self):
        with self.assertRaises(AclContractError):
            validate_policy({"default_action": "deny"})

    def test_rule_accepts_priority_zero(self):
        validate_rule({"direction": "ingress", "priority": 0, "action": "allow"})

    def test_rule_rejects_ipv6_and_source_ports(self):
        invalid = [
            {"direction": "ingress", "priority": 1, "action": "allow", "ethertype": "IPv6"},
            {"direction": "ingress", "priority": 1, "action": "allow", "src_port_min": 80},
        ]
        for values in invalid:
            with self.assertRaises(AclContractError):
                validate_rule(values)

    def test_address_set_reference_requires_enabled_members(self):
        for values in ({"enabled": False, "members": ["10.0.0.1/32"]}, {"enabled": True, "members": []}):
            with self.assertRaises(AclContractError):
                validate_address_set_reference(values)
```

- [ ] **Step 2: Verify RED**

Run: `PYTHONPATH=openstack/neutron_aria python3 -m unittest -v neutron_aria.tests.unit.test_acl_contract`

Expected: import failure because `neutron_aria.acl_contract` does not exist.

- [ ] **Step 3: Implement the minimal pure validator**

```python
class AclContractError(ValueError):
    pass

def validate_policy(values):
    if str(values.get("default_action") or "allow").strip().lower() != "allow":
        raise AclContractError("default_action must be allow")

def validate_rule(values):
    if str(values.get("direction") or "").strip().lower() not in ("ingress", "egress"):
        raise AclContractError("direction must be ingress or egress")
    if values.get("priority") is None or int(values["priority"]) < 0:
        raise AclContractError("priority must be a non-negative integer")
    if str(values.get("action") or "").strip().lower() not in ("allow", "deny", "drop"):
        raise AclContractError("action must be allow, deny, or drop")
    if str(values.get("ethertype") or "IPv4").strip().lower() != "ipv4":
        raise AclContractError("only IPv4 is supported")
    if values.get("src_port_min") is not None or values.get("src_port_max") is not None:
        raise AclContractError("source port matching is unsupported")
    protocol = _protocol_number(values.get("protocol"))
    for key in ("src_cidr", "dst_cidr"):
        if values.get(key):
            _validate_ipv4_cidr(values[key])
    low = values.get("dst_port_min")
    high = values.get("dst_port_max")
    if low is not None or high is not None:
        low = int(low if low is not None else high)
        high = int(high if high is not None else low)
        if protocol not in (6, 17) or low < 0 or high > 65535 or low > high:
            raise AclContractError("destination ports require valid tcp/udp range")

def validate_address_set_reference(values):
    if values.get("enabled") is False:
        raise AclContractError("address set is disabled")
    members = [value for value in values.get("members") or [] if str(value).strip()]
    if not members:
        raise AclContractError("address set has no members")
    for member in members:
        _validate_ipv4_cidr(member)

def _protocol_number(value):
    normalized = str(value if value is not None else "any").strip().lower()
    aliases = {"any": 0, "tcp": 6, "udp": 17, "icmp": 1}
    if normalized in aliases:
        return aliases[normalized]
    number = int(normalized)
    if number < 0 or number > 255:
        raise AclContractError("protocol must be in 0..255")
    return number

def _validate_ipv4_cidr(value):
    import socket
    parts = str(value).split("/")
    if len(parts) != 2 or ":" in parts[0]:
        raise AclContractError("only IPv4 CIDR is supported")
    socket.inet_aton(parts[0])
    prefix = int(parts[1])
    if prefix < 0 or prefix > 32:
        raise AclContractError("invalid IPv4 prefix")

def port_contract_eligibility(port):
    owner = port.get("device_owner") or ""
    vif = port.get("binding:vif_type")
    vnic = port.get("binding:vnic_type")
    if owner and not owner.startswith("compute:"):
        return False, "not_applicable_device_owner:%s" % owner
    if vif not in (None, "", "ovs"):
        return False, "unsupported_vif_type:%s" % vif
    if vnic not in (None, "", "normal"):
        return False, "unsupported_vnic_type:%s" % vnic
    return True, "pending_local_validation"
```

- [ ] **Step 4: Verify GREEN**

Run the command from Step 2. Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add openstack/neutron_aria/neutron_aria/acl_contract.py openstack/neutron_aria/neutron_aria/tests/unit/test_acl_contract.py
git commit -m "fix: define strict neutron acl contract"
```

### Task 2: Repository Validation And Conflict Rules

**Files:**
- Modify: `openstack/neutron_aria/neutron_aria/db/aria_acl/api.py`
- Modify: `openstack/neutron_aria/neutron_aria/tests/unit/test_aria_acl_plugin.py`

**Interfaces:**
- Consumes: Task 1 validators.
- Produces: create/update rejection for unsupported fields, duplicate enabled priorities, and duplicate enabled bindings.

- [ ] **Step 1: Add failing tests for default deny, priority zero, duplicate priority, and duplicate binding**

```python
def test_policy_rejects_default_deny(self):
    with self.assertRaises(AriaAclValidationError):
        self.plugin.create_aria_acl_policy(None, {"aria_acl_policy": {"project_id": "p1", "default_action": "deny"}})

def test_priority_zero_is_valid_but_duplicate_is_rejected(self):
    policy = self._create_policy("p1")
    self._create_rule(policy["id"], priority=0, direction="ingress")
    with self.assertRaises(AriaAclValidationError):
        self._create_rule(policy["id"], priority=0, direction="ingress")

def test_duplicate_enabled_binding_is_rejected(self):
    first = self._create_policy("p1")
    second = self._create_policy("p1")
    self._create_binding(first["id"], "port", "port-1")
    with self.assertRaises(AriaAclValidationError):
        self._create_binding(second["id"], "port", "port-1")
```

- [ ] **Step 2: Verify RED**

Run: `PYTHONPATH=openstack/neutron_aria python3 -m unittest -v neutron_aria.tests.unit.test_aria_acl_plugin`

Expected: unsupported and duplicate writes succeed, while priority zero fails as missing.

- [ ] **Step 3: Implement explicit missing checks and pre-write conflict validation**

```python
def _require(obj, fields, object_type):
    missing = [field for field in fields if field not in obj or obj.get(field) is None]
    if missing:
        raise AriaAclValidationError(
            "%s missing required field(s): %s" % (object_type, ",".join(missing))
        )
```

Validate the complete merged update object. Query conflicts while excluding the
object being updated, and raise before any mutation in both repository types.

- [ ] **Step 4: Verify GREEN and commit**

```bash
PYTHONPATH=openstack/neutron_aria python3 -m unittest -v neutron_aria.tests.unit.test_aria_acl_plugin
git add openstack/neutron_aria/neutron_aria/db/aria_acl/api.py openstack/neutron_aria/neutron_aria/tests/unit/test_aria_acl_plugin.py
git commit -m "fix: reject invalid neutron acl writes"
```

### Task 3: Legacy Neutron HTTP Error Mapping

**Files:**
- Create: `openstack/neutron_aria/neutron_aria/services/aria_acl/exceptions.py`
- Modify: `openstack/neutron_aria/neutron_aria/services/aria_acl/plugin.py`
- Modify: `openstack/neutron_aria/neutron_aria/tests/unit/test_aria_acl_plugin.py`

**Interfaces:**
- Produces: `map_repository_error(exc)` and plugin `_repository_call`.

- [ ] **Step 1: Add failing tests that validation maps to 400, not-found to 404, and unexpected errors remain unchanged**
- [ ] **Step 2: Run the plugin suite and verify the new module import fails**
- [ ] **Step 3: Implement optional legacy-Neutron exception imports with stdlib test fallbacks**
- [ ] **Step 4: Wrap every plugin CRUD repository call and re-raise unexpected failures unchanged**
- [ ] **Step 5: Run the plugin suite and commit**

```bash
PYTHONPATH=openstack/neutron_aria python3 -m unittest -v neutron_aria.tests.unit.test_aria_acl_plugin
git add openstack/neutron_aria/neutron_aria/services/aria_acl/exceptions.py openstack/neutron_aria/neutron_aria/services/aria_acl/plugin.py openstack/neutron_aria/neutron_aria/tests/unit/test_aria_acl_plugin.py
git commit -m "fix: map acl repository errors to neutron responses"
```

### Task 4: Defensive Effective ACL And Real Port Eligibility

**Files:**
- Modify: `openstack/neutron_aria/neutron_aria/agent/effective_acl.py`
- Modify: `openstack/neutron_aria/neutron_aria/services/aria_acl/plugin.py`
- Modify: `openstack/neutron_aria/neutron_aria/tests/unit/test_effective_acl.py`
- Modify: `openstack/neutron_aria/neutron_aria/tests/unit/test_aria_acl_plugin.py`

- [ ] **Step 1: Add failing tests**

```python
def test_disabled_or_empty_address_set_degrades(self):
    for address_set in ({"id": "as1", "enabled": False, "members": ["10.0.0.1/32"]}, {"id": "as1", "enabled": True, "members": []}):
        result = self._index_with_address_set(address_set).effective_for_port(self._port(), {"eligible": True})
        self.assertEqual("degraded", result["status"])
        self.assertEqual("bypass", result["effective_action"])

def test_plugin_effective_api_marks_failed_vif_unsupported(self):
    result = self.plugin.get_aria_acl_effective_for_port(None, {
        "id": "p1", "device_owner": "compute:nova",
        "binding:vif_type": "binding_failed", "binding:vnic_type": "normal",
    })
    self.assertEqual("unsupported", result["status"])
```

- [ ] **Step 2: Verify RED using the effective ACL and plugin suites**
- [ ] **Step 3: Reuse Task 1 validators for existing records and pass computed eligibility instead of `eligible=True`**
- [ ] **Step 4: Verify GREEN and commit**

```bash
PYTHONPATH=openstack/neutron_aria python3 -m unittest -v neutron_aria.tests.unit.test_effective_acl neutron_aria.tests.unit.test_aria_acl_plugin
git add openstack/neutron_aria/neutron_aria/agent/effective_acl.py openstack/neutron_aria/neutron_aria/services/aria_acl/plugin.py openstack/neutron_aria/neutron_aria/tests/unit/test_effective_acl.py openstack/neutron_aria/neutron_aria/tests/unit/test_aria_acl_plugin.py
git commit -m "fix: degrade unsupported effective acl input"
```

### Task 5: Exact Managed Domains And Capabilities

**Files:**
- Modify: `openstack/neutron_aria/neutron_aria/agent/config.py`
- Modify: `openstack/neutron_aria/neutron_aria/tests/unit/test_config.py`
- Modify: `api/src/lib.rs`
- Modify: `docs/neutron-uds-contract.json`
- Modify: `ci/check_neutron_stage1.py`

- [ ] **Step 1: Add a failing config test that rejects `acl,qos` and `acl,mirror`**

```python
def test_rejects_unimplemented_managed_domains(self):
    for domain in ("qos", "mirror"):
        with self.assertRaises(ConfigError):
            validate_config(AgentConfig(managed_domains=["acl", domain]))
```

- [ ] **Step 2: Change the stage check expectation to exact `["attach", "acl"]` and verify RED before production changes**
- [ ] **Step 3: Set Python `SUPPORTED_MANAGED_DOMAINS=("acl",)`, Rust `NEUTRON_SUPPORTED_DOMAINS=&["attach", "acl"]`, and align JSON/embedded contract examples**
- [ ] **Step 4: Verify Python config and stage checks GREEN; do not run local Cargo**
- [ ] **Step 5: Commit**

```bash
PYTHONPATH=openstack/neutron_aria python3 -m unittest -v neutron_aria.tests.unit.test_config
python3 ci/check_neutron_stage1.py
git add openstack/neutron_aria/neutron_aria/agent/config.py openstack/neutron_aria/neutron_aria/tests/unit/test_config.py api/src/lib.rs docs/neutron-uds-contract.json ci/check_neutron_stage1.py
git commit -m "fix: advertise only implemented neutron domains"
```

### Task 6: Runtime-First Status Projection

**Files:**
- Modify: `openstack/neutron_aria/neutron_aria/agent/event_loop.py`
- Modify: `openstack/neutron_aria/neutron_aria/tests/unit/test_event_loop.py`

- [ ] **Step 1: Add a failing test with UDS `degraded/bypass` and snapshot `ready/enforce`**
- [ ] **Step 2: Verify RED: projected action incorrectly becomes `enforce`**
- [ ] **Step 3: Fill status/action/reason only when absent; never treat `bypass`, `not_requested`, `degraded`, or `blocked` as empty**
- [ ] **Step 4: Verify GREEN and commit**

```bash
PYTHONPATH=openstack/neutron_aria python3 -m unittest -v neutron_aria.tests.unit.test_event_loop
git add openstack/neutron_aria/neutron_aria/agent/event_loop.py openstack/neutron_aria/neutron_aria/tests/unit/test_event_loop.py
git commit -m "fix: preserve acl runtime status projection"
```

### Task 7: CLI, Documentation, Full Verification, And GitHub Delivery

**Files:**
- Modify: `openstack/neutronclient_aria/neutronclient_aria/v2_0/aria_acl.py`
- Modify: `openstack/neutronclient_aria/neutronclient_aria/tests/test_aria_acl_cli.py`
- Modify: `docs/openstack-neutron-agent-mode.md`
- Modify: `docs/openstack-neutron-aria-details/12-review-bug-backlog.md`

- [ ] **Step 1: Add executable CLI tests for rejecting default deny, IPv6, and source ports while accepting priority zero and valid IPv4 destination ports**
- [ ] **Step 2: Verify the new assertions fail rather than skip without legacy neutronclient**
- [ ] **Step 3: Restrict CLI choices to the approved contract and update current capability wording**
- [ ] **Step 4: Mark each Batch 1 ID fixed only when its focused evidence passes**
- [ ] **Step 5: Run the complete allowed verification set**

```bash
PYTHONPATH=openstack/neutron_aria python3 -m unittest discover -s openstack/neutron_aria/neutron_aria/tests -p 'test_*.py'
PYTHONPATH=openstack/neutron_aria:openstack/neutronclient_aria python3 -m unittest discover -s openstack/neutronclient_aria/neutronclient_aria/tests -p 'test_*.py'
python3 -m compileall -q openstack/neutron_aria/neutron_aria openstack/neutronclient_aria/neutronclient_aria
python3 ci/check_neutron_stage1.py
python3 ci/check_neutron_stage2_acl.py
python3 ci/check_stage3_readiness.py
python3 ci/check_smoke_python_blocks.py
bash -n install.sh
find deploy ci -type f -name '*.sh' -exec bash -n {} \;
git diff --check
```

- [ ] **Step 6: Commit, push, and use GitHub Actions as Rust authority**

```bash
git add openstack/neutronclient_aria/neutronclient_aria/v2_0/aria_acl.py openstack/neutronclient_aria/neutronclient_aria/tests/test_aria_acl_cli.py docs/openstack-neutron-agent-mode.md docs/openstack-neutron-aria-details/12-review-bug-backlog.md
git commit -m "docs: close acl contract guardrail batch"
git push -u origin codex/acl-batch-1-contract-guardrails
```

If CI fails, fix only failures caused by this batch, rerun the allowed local
checks, and push the smallest follow-up commit until GitHub Actions passes.
