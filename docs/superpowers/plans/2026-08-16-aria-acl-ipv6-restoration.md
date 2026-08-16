# Aria ACL IPv6 Restoration Implementation Plan

> **Execution status (2026-08-16):** Tasks 1-3 are retained. Task 4 and all
> later datapath-dependent steps in this plan are stopped and must not be
> executed against the monolithic TC pipeline. They will be replaced by a new
> implementation plan after user review of
> `docs/superpowers/specs/2026-08-16-tail-call-datapath-architecture-design.md`.

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Restore complete, family-isolated IPv6 ACL support for Neutron-managed and standalone ports without changing the existing ACL product boundaries or enabling the feature in production before field proof.

**Architecture:** Keep the shared banked policy map and existing IPv4/IPv6 selector tries, but make `ip_family` part of every policy, conntrack, selector, persistence, capability, and counter identity. Publish IPv4 and IPv6 as one atomic generation, rebuild incompatible pinned state under an explicit runtime schema, and use an expand-contract Python/Rust rollout with `[acl] ipv6_acl_enabled=false` by default.

**Tech Stack:** Rust stable plus nightly eBPF through GitHub Actions, `aya`, `serde`, Python 2.7-compatible Neutron plugin/agent code, `netaddr>=0.7.19,<1.0.0`, SQLAlchemy/Alembic, python-neutronclient extension commands, shell-based OpenStack smoke tests.

## Global Constraints

- Work only on `main`; before each task run `git fetch origin`, verify `main...origin/main` is `0 0`, and require a clean worktree.
- Do not create a feature branch, worktree, stacked PR, or force-push. Preserve unrelated changes from other sessions.
- Do not run local `cargo build`, `cargo check`, `cargo test`, Clippy, or any other local Rust compilation. Rust RED/GREEN evidence comes from GitHub Actions.
- Python code must remain Python 2.7 compatible: no f-strings, dataclasses, type annotations, `pathlib`, or reliance on `inspect.signature`.
- Pin the Python network dependency exactly as `netaddr>=0.7.19,<1.0.0` in both requirements and package metadata.
- Public rules use one family each: `ethertype=IPv4|IPv6`; omission means `IPv4`; dual stack uses two rules.
- Kernel policy and matched-conntrack family values are only `4` or `6`; `DropKey.ip_family` additionally accepts `0` for non-IP/unknown.
- Selector names are exactly `__neutron_acl:<port-id>:<src|dst>:selector:<ipv4|ipv6>:<ordinal>`; selector ordinals are independent per side and family.
- Source-port matching stays unsupported; priority remains metadata; overlap with different actions stays a controller validation error.
- No hidden ND/RA/MLD bypass and no ICMPv6 type/code matching are added.
- Existing limits remain 1,000 effective rules per port and 2,048 address-set members.
- Preserve the 448-byte linked TC stack gate and warning-denied hosted builds.
- `ipv6_acl_enabled` and Phase B counters remain default `false`; field evidence stays `deferred/pending` until actually executed on the real OpenStack/4.18 environment.
- Reference design: `docs/superpowers/specs/2026-08-16-aria-acl-ipv6-restoration-design.md`.

## Dependency Order and File Ownership

| Task | Produces | Required by |
| --- | --- | --- |
| 1 | Python family/CIDR/protocol contract and default-off gate | 7, 8, 9, 10 |
| 2 | Shared ABI family constants and layouts | 3, 4, 5, 6, 9, 10 |
| 3 | Family-aware persisted `RuleInfo` and local WAL | 4, 5, 6 |
| 4 | Family-isolated core/eBPF lookup, CT, drop, stats | 5, 6, 10 |
| 5 | Dual-stack Rust compiler and selector namespace | 6, 9 |
| 6 | Atomic apply, Neutron WAL normalization, runtime schema rebuild | 9, 10, 11, 12 |
| 7 | Neutron write invariants, projection, and address-set family | 8, 9, 10, 11 |
| 8 | REST/CLI dual-stack product surface | 11, 12 |
| 9 | Python expand-contract compatibility and host enablement | 10, 11, 12 |
| 10 | Counters v2 plus atomic Rust capability publication | 11, 12 |
| 11 | Integrated gates, documentation, packaging, smoke driver | 12 |
| 12 | Real-environment rollout, rollback, and acceptance evidence | production decision |

Tasks 2 through 10 change shared ABI or contract files. Execute them serially and wait for the exact-head CI result before beginning the next shared-file task.

---

### Task 1: Establish the Python Family Contract, Dependency, and Default-Off Gate

**Files:**
- Modify: `openstack/neutron_aria/requirements.txt`
- Modify: `openstack/neutron_aria/setup.py`
- Modify: `openstack/neutron_aria/neutron_aria/acl_contract.py`
- Modify: `openstack/neutron_aria/neutron_aria/agent/config.py`
- Modify: `openstack/neutron_aria/neutron_aria/tests/unit/test_acl_contract.py`
- Modify: `openstack/neutron_aria/neutron_aria/tests/unit/test_config.py`
- Modify: `deploy/kolla/config/neutron-aria-agent.ini`
- Modify: `ci/check_neutron_stage1.py`
- Modify: `docs/openstack-neutron-aria-details/01-ini-contract.md`
- Modify: `docs/openstack-neutron-agent-mode.md`

**Interfaces:**
- Consumes: the approved `IPv4|IPv6`, ICMP, CIDR, address-set, and default-off contracts.
- Produces: `normalize_ethertype(value) -> "IPv4"|"IPv6"`, `normalize_cidr(value, ethertype) -> canonical CIDR`, `protocol_number(value, ethertype) -> int`, `address_set_ethertype(members) -> "IPv4"|"IPv6"|None`, and `AgentConfig.ipv6_acl_enabled: bool`.

- [ ] **Step 1: Add RED contract tests for strict dual-stack normalization**

Add tests with these exact assertions:

```python
def test_rule_accepts_ipv6_and_resolves_icmp_by_family(self):
    validate_rule({
        "direction": "ingress", "priority": 1, "action": "allow",
        "ethertype": "IPv6", "protocol": "icmp",
        "src_cidr": "2001:db8::7/64",
    })
    self.assertEqual(
        "2001:db8::/64",
        acl_contract.normalize_cidr(" 2001:db8::7/64 ", "IPv6"),
    )
    self.assertEqual(1, acl_contract.protocol_number("icmp", "IPv4"))
    self.assertEqual(58, acl_contract.protocol_number("icmp", "IPv6"))
    self.assertEqual(58, acl_contract.protocol_number("icmpv6", "IPv6"))

def test_rule_rejects_cross_family_and_mapped_ipv6(self):
    for ethertype, cidr in (
        ("IPv4", "2001:db8::/64"),
        ("IPv6", "192.0.2.0/24"),
        ("IPv6", "::ffff:192.0.2.1/128"),
        ("IPv6", "fe80::1%eth0/128"),
    ):
        with self.assertRaises(AclContractError):
            acl_contract.normalize_cidr(cidr, ethertype)

def test_address_set_family_is_single_and_computed(self):
    self.assertEqual("IPv4", acl_contract.address_set_ethertype(["10.0.0.1/24"]))
    self.assertEqual("IPv6", acl_contract.address_set_ethertype(["2001:db8::1/64"]))
    self.assertIsNone(acl_contract.address_set_ethertype([]))
    with self.assertRaises(AclContractError):
        acl_contract.address_set_ethertype(["10.0.0.0/24", "2001:db8::/64"])
```

Add config tests:

```python
def test_ipv6_acl_enabled_defaults_false(self):
    self.assertFalse(AgentConfig().ipv6_acl_enabled)

def test_loads_ipv6_acl_enabled(self):
    path = self._write_config("[acl]\nipv6_acl_enabled = true\n")
    try:
        self.assertTrue(load_config(path).ipv6_acl_enabled)
    finally:
        os.unlink(path)
```

- [ ] **Step 2: Run the Python RED tests**

Run:

```bash
PYTHONPATH=openstack/neutron_aria python3 -m unittest \
  neutron_aria.tests.unit.test_acl_contract \
  neutron_aria.tests.unit.test_config
```

Expected: FAIL because `normalize_cidr`, `protocol_number`, `address_set_ethertype`, and `ipv6_acl_enabled` do not exist and IPv6 is still rejected.

- [ ] **Step 3: Implement the shared Python family primitives**

Replace the IPv4-only helpers with this public shape:

```python
import netaddr

def normalize_ethertype(value):
    token = _text(value or "IPv4")
    if token == "ipv4":
        return "IPv4"
    if token == "ipv6":
        return "IPv6"
    raise AclContractError("ethertype must be IPv4 or IPv6")

def normalize_cidr(value, ethertype):
    text = str(value).strip()
    if not text or "%" in text or any(char.isspace() for char in text):
        raise AclContractError("invalid %s CIDR: %s" % (ethertype, value))
    try:
        network = netaddr.IPNetwork(text)
    except (netaddr.AddrFormatError, ValueError):
        raise AclContractError("invalid %s CIDR: %s" % (ethertype, value))
    expected = 4 if normalize_ethertype(ethertype) == "IPv4" else 6
    if network.version != expected:
        raise AclContractError("ethertype and CIDR family must match")
    original_ip = netaddr.IPAddress(text.split("/", 1)[0])
    if network.version == 6 and (int(original_ip) >> 32) == 0xffff:
        raise AclContractError("IPv4-mapped IPv6 CIDR is unsupported")
    return str(network.cidr)

def protocol_number(value, ethertype):
    family = normalize_ethertype(ethertype)
    token = _text(value if value is not None else "any")
    aliases = {"any": 0, "tcp": 6, "udp": 17}
    if token in aliases:
        return aliases[token]
    if token == "icmp":
        return 1 if family == "IPv4" else 58
    if token in ("icmpv6", "ipv6-icmp"):
        if family != "IPv6":
            raise AclContractError("ICMPv6 requires IPv6 ethertype")
        return 58
    number = _integer(token, "protocol")
    if number not in range(0, 256):
        raise AclContractError("protocol must be in 0..255")
    if (family == "IPv4" and number == 58) or (family == "IPv6" and number == 1):
        raise AclContractError("ICMP protocol number does not match ethertype")
    return number

def address_set_ethertype(members):
    families = set()
    for member in members or []:
        value = member.get("address") if isinstance(member, dict) else member
        text = str(value).strip()
        if not text:
            continue
        family = "IPv6" if ":" in text else "IPv4"
        normalize_cidr(text, family)
        families.add(family)
    if len(families) > 1:
        raise AclContractError("address set must contain one IP family")
    return next(iter(families), None)
```

Keep `normalize_ipv4_cidr(value)` as a compatibility wrapper around `normalize_cidr(value, "IPv4")`. Update `validate_rule` and `validate_address_set_reference` to call these public primitives.

Add `DEFAULT_IPV6_ACL_ENABLED = False`, an `ipv6_acl_enabled` constructor field, `[acl]` parsing, and packaged `ipv6_acl_enabled = false`. Extend `check_packaged_ini_contract`, `check_documented_ini_contract`, and `REQUIRED_PYTHON_BEHAVIORS` with the exact new default test.

Document the new default-off option in the two authoritative configuration-contract documents in this task, so the documented-INI gate remains truthful from the first implementation commit. Task 11 later expands the operator and rollout guidance; it does not defer this contract declaration.

Declare the dependency as:

```text
netaddr>=0.7.19,<1.0.0
```

and add `install_requires=["netaddr>=0.7.19,<1.0.0"]` to `setup.py`.

- [ ] **Step 4: Run the GREEN Python and fast-contract checks**

Run:

```bash
PYTHONPATH=openstack/neutron_aria python3 -m unittest \
  neutron_aria.tests.unit.test_acl_contract \
  neutron_aria.tests.unit.test_config
python3 ci/check_neutron_stage1.py --fast-contracts
git diff --check
```

Expected locally: all selected unit tests pass and `git diff --check` prints nothing. The full fast-contract command may reach the repository's macOS-incompatible peer-credential shell fixture; if so, record that pre-existing environment-specific failure exactly and do not claim the full gate passed. The authoritative full fast-contract result is the exact-head hosted CI job in Step 5.

- [ ] **Step 5: Commit and push Task 1**

```bash
git add openstack/neutron_aria deploy/kolla/config/neutron-aria-agent.ini ci/check_neutron_stage1.py docs/openstack-neutron-aria-details/01-ini-contract.md docs/openstack-neutron-agent-mode.md
git commit -m "feat(acl): define dual-stack Python family contract"
git push origin main
```

Wait for the exact commit's `fast-contracts` and `neutron-agent-clean-install` jobs to pass before Task 2.

---

### Task 2: Add Address Family to the Shared eBPF ABI

**Files:**
- Modify: `abi/src/lib.rs`
- Create: `abi/tests/acl_family_contract.rs`
- Modify: `ci/check_neutron_stage1.py`
- Modify as required for this ABI transition: every existing Rust `PolicyKey`, `CtValue`, `DropKey`, and `PipelineCtx` initializer and every `ct_acl_cache_is_current` caller found by `rg`; do not defer compilation repairs to Task 4.

**Interfaces:**
- Consumes: Task 1's numeric family contract.
- Produces: `IP_FAMILY_UNSPECIFIED`, `IP_FAMILY_V4`, `IP_FAMILY_V6`, `PolicyKey.ip_family`, `CtValue.matched_family`, `DropKey.ip_family`, `PipelineCtx.ip_family`, and family-aware CT validity helpers with unchanged C layout sizes.

- [ ] **Step 1: Add the ABI RED test**

Create a test that asserts constants, sizes, and family-aware cache behavior:

```rust
use aria_ebpf_abi::*;

#[test]
fn acl_family_layout_and_cache_contract() {
    assert_eq!(IP_FAMILY_UNSPECIFIED, 0);
    assert_eq!(IP_FAMILY_V4, 4);
    assert_eq!(IP_FAMILY_V6, 6);
    assert_eq!(core::mem::size_of::<PolicyKey>(), 16);
    assert_eq!(core::mem::size_of::<CtValue>(), 40);
    assert_eq!(core::mem::size_of::<DropKey>(), 16);
    assert!(policy_family_is_valid(IP_FAMILY_V4));
    assert!(policy_family_is_valid(IP_FAMILY_V6));
    assert!(!policy_family_is_valid(IP_FAMILY_UNSPECIFIED));
    assert!(drop_family_is_valid(IP_FAMILY_UNSPECIFIED));
    assert!(!ct_acl_family_is_current(0, IP_FAMILY_V6));
    assert!(!ct_acl_family_is_current(IP_FAMILY_V4, IP_FAMILY_V6));
    assert!(ct_acl_family_is_current(IP_FAMILY_V6, IP_FAMILY_V6));
}
```

Add `acl_family_` to the hosted Rust test inventory.

- [ ] **Step 2: Commit and push the RED test without running Cargo locally**

```bash
git add abi/tests/acl_family_contract.rs ci/check_neutron_stage1.py
git commit -m "test(acl): require family-aware eBPF ABI"
git push origin main
```

Run:

```bash
ARIA_IPV6_HEAD_SHA="$(git rev-parse HEAD)"
ARIA_IPV6_RED_RUN_ID="$(gh run list --commit "$ARIA_IPV6_HEAD_SHA" --workflow build.yml --limit 1 --json databaseId --jq '.[0].databaseId')"
gh run view "$ARIA_IPV6_RED_RUN_ID" --log-failed
```

Expected: `rust-behavior` fails in `acl_family_layout_and_cache_contract` because the new symbols and fields are absent. Record the run ID and commit hash in the task evidence note.

- [ ] **Step 3: Implement the ABI without changing structure sizes**

Use these definitions:

```rust
pub const IP_FAMILY_UNSPECIFIED: u8 = 0;
pub const IP_FAMILY_V4: u8 = 4;
pub const IP_FAMILY_V6: u8 = 6;

#[inline(always)]
pub const fn policy_family_is_valid(family: u8) -> bool {
    family == IP_FAMILY_V4 || family == IP_FAMILY_V6
}

#[inline(always)]
pub const fn drop_family_is_valid(family: u8) -> bool {
    family == IP_FAMILY_UNSPECIFIED || policy_family_is_valid(family)
}
```

Change the layout fields exactly:

```rust
pub struct PolicyKey {
    pub tap_id: u32,
    pub src_id: u32,
    pub dst_id: u32,
    pub proto: u8,
    pub direction: u8,
    pub bank: u8,
    pub ip_family: u8,
}

pub struct CtValue {
    pub state: u8,
    pub flags: u8,
    pub direction: u8,
    pub matched_proto: u8,
    pub matched_src_id: u32,
    pub matched_dst_id: u32,
    pub matched_bank: u8,
    pub matched_family: u8,
    pub _pad: [u8; 2],
    pub last_seen: u64,
    pub pkt_count: u64,
    pub byte_count: u64,
}

pub struct DropKey {
    pub tap_id: u32,
    pub reason: u8,
    pub direction: u8,
    pub proto: u8,
    pub ip_family: u8,
    pub src_id: u32,
    pub dst_id: u32,
}

pub struct PipelineCtx {
    pub tap_id: u32,
    pub src_id: u32,
    pub dst_id: u32,
    pub pkt_len: u32,
    pub now: u64,
    pub proto: u8,
    pub direction: u8,
    pub flags: u16,
    pub ct_state: u8,
    pub drop_reason: u8,
    pub _pad: [u8; 2],
    pub action: u32,
    pub matched_src_id: u32,
    pub matched_dst_id: u32,
    pub matched_proto: u8,
    pub matched_direction: u8,
    pub matched_bank: u8,
    pub ip_family: u8,
    pub fragment_epoch_snapshot: u64,
    pub acl_bank_snapshot: u8,
    pub fragment_epoch_present: u8,
    pub _pad3: [u8; 6],
}
```

Add:

```rust
#[inline(always)]
pub fn ct_acl_family_is_current(matched_family: u8, expected_family: u8) -> bool {
    policy_family_is_valid(expected_family) && matched_family == expected_family
}
```

Extend `ct_acl_cache_is_current` and `ct_snapshot_is_stable` to include `matched_family`; do not compare the retired padding byte as policy state.

Keep this exact-head ABI commit buildable without claiming the Task 4 datapath work is complete. At existing production call sites, initialize the current IPv4-only ACL compatibility path with `IP_FAMILY_V4` for policy keys, matched CT state, pipeline context, and cache expectations. Initialize drop keys with `IP_FAMILY_UNSPECIFIED` until Task 4 supplies the parsed packet family. Update ABI/unit fixtures mechanically. Task 4 must replace these compatibility initializers with the real IPv4/IPv6 parser-derived family; Task 2 alone is not IPv6 enforcement evidence.

- [ ] **Step 4: Commit and push the GREEN ABI implementation**

```bash
git add abi/src/lib.rs core ebpf agent
git commit -m "feat(acl): add address family to shared ABI"
git push origin main
```

Expected hosted evidence: `rust-behavior`, `rust-build`, ABI `repr(C)` checks, warning-denied builds, and the 448-byte stack gate pass at the GREEN commit.

---

### Task 3: Migrate Persisted Rules and the Local WAL to Concrete Families

**Files:**
- Modify: `core/src/state.rs`
- Modify: `core/src/wal.rs`
- Modify: `core/src/ebpf_ops/replay.rs`
- Modify: `core/tests/acl_projection_contract.rs`
- Modify: `agent/src/control_plane.rs`
- Modify: `agent/src/control_plane/standalone_acl.rs`
- Modify: all `RuleInfo` constructors found by `rg -n "RuleInfo \\{" core agent`

**Interfaces:**
- Consumes: Task 2 family constants.
- Produces: `RuleInfo.ip_family`, family-aware `apply_add_rule`/`apply_remove_rule`, family-bearing `WalEntry::AddRule`/`RemoveRule`, and `migrate_legacy_rule_families` for idempotent historical replay.

- [ ] **Step 1: Add RED persistence tests**

Add these cases to the existing state/WAL table-driven test harness. Each row
must assert the complete identity `(src_id,dst_id,proto,direction,ip_family)`:

| Test name | Stored input | Expected replay |
| --- | --- | --- |
| `wal_inventory_ipv6_rule_round_trips_family` | `AddRule` with ids `10/20`, proto `6`, direction `0`, family `6` | one identical `RuleInfo`, family `6` |
| `local_projection_legacy_ipv4_rule_infers_family` | family `0`, src group `10.0.0.0/24`, dst any | one family `4` rule |
| `local_projection_legacy_any_rule_expands_both_families` | family `0`, src/dst group `0` | two otherwise identical rules with families `[4,6]` |
| `local_projection_legacy_mixed_selector_families_fail_closed_before_replay` | family `0`, IPv4 src group, IPv6 dst group | error `legacy_acl_rule_mixed_family` and no replayed rule |

- [ ] **Step 2: Push the RED tests and capture hosted failure**

Commit `test(acl): require family-aware state and WAL replay`, push, and inspect the exact `rust-behavior` run. Expected failure: missing `RuleInfo.ip_family`, missing WAL field, or wrong legacy expansion.

- [ ] **Step 3: Implement the persisted family contract**

Change the stored rule and state methods:

```rust
pub struct RuleInfo {
    pub name: Option<String>,
    pub src_group_id: u32,
    pub dst_group_id: u32,
    pub proto: u8,
    pub action: u8,
    pub ports: Option<String>,
    pub bitmap_idx: Option<u32>,
    #[serde(default)]
    pub direction: u8,
    #[serde(default)]
    pub ip_family: u8,
}

pub fn apply_add_rule(
    &mut self,
    src_group_id: u32,
    dst_group_id: u32,
    proto: u8,
    action: u8,
    ports: Option<&str>,
    direction: u8,
    ip_family: u8,
) -> Result<AddRuleResult, String>

pub fn apply_remove_rule(
    &mut self,
    src_group_id: u32,
    dst_group_id: u32,
    proto: u8,
    direction: u8,
    ip_family: u8,
) -> Result<RemoveRuleResult, String>
```

Duplicate/update/remove identity includes `ip_family`. Add `#[serde(default)] ip_family: u8` to both WAL variants. New writes reject values other than `4` or `6`.

Implement legacy normalization with this signature:

```rust
pub fn migrate_legacy_rule_families(
    rule: &RuleInfo,
    groups: &std::collections::HashMap<String, GroupInfo>,
) -> Result<Vec<RuleInfo>, String>
```

Rules already carrying `4` or `6` return one clone. Family-zero rules infer
from all concrete src/dst group CIDRs; both groups `0` expand to two clones;
conflicting or mixed group membership returns an explicit error. Apply
normalization before any pinned-map replay and write the migrated state
atomically through the existing checkpoint path. A complete WAL scan with any
selected-tail failure blocks family migration with typed reason
`legacy_acl_family_checkpoint_blocked_by_wal_failure` before runtime or state
writers and before compaction, preserving both durable files byte-for-byte;
concrete-family snapshots keep the prior best-effort malformed-WAL behavior.
The atomic cursor-bearing snapshot publication is the migration commit point.
A failure before marker append preserves both files. A failure after the marker
is appended and synced but before snapshot publication is fatal with the old
snapshot bytes/cursor authoritative; the unmatched marker may remain in the
WAL and must be ignored on restart rather than truncated or rolled back. The
retry must reconstruct the same prior effective `FirewallState`, allocate a
later checkpoint ID, and converge without stale or duplicate family-qualified
policy identities. Post-publication WAL truncate/fsync/header failure is a
recoverable committed outcome, returns the normalized cursor-bearing state,
and relies on cursor replay for restart convergence rather than durable byte
rollback.

- [ ] **Step 4: Update every state/control-plane constructor and preimage identity**

Every `RuleInfo` literal must set `ip_family`. Extend `OwnedAclPolicySpec`, `OwnedAclPolicyKey`, `ExistingOwnedAclPolicy`, runtime-add records, equality, BTreeMap keys, and standalone transaction preimages to include family. Preserve the compensation sequence; only the identity changes to `(plane,direction,family,canonical CIDR)`.

- [ ] **Step 5: Push GREEN and verify hosted behavior**

Commit `feat(acl): persist family-qualified ACL rules`, push, and require `rust-behavior`, `rust-build`, `fast-contracts`, and full workspace tests to pass at the exact commit.

---

### Task 4: Isolate Core and eBPF Policy, Conntrack, Drop, and Statistics Paths

**Files:**
- Modify: `ebpf/src/lib.rs`
- Modify: `ebpf/src/policy.rs`
- Modify: `ebpf/src/conntrack.rs`
- Modify: `ebpf/src/drops.rs`
- Modify: `ebpf/src/fragment.rs`
- Modify: `core/src/ebpf_ops/policy.rs`
- Modify: `core/src/ebpf_ops/replay.rs`
- Modify: `core/src/ebpf_ops/scrub.rs`
- Modify: `core/src/ebpf_ops/inventory.rs`
- Modify: `core/src/monitoring.rs`
- Modify: `core/src/port_counters.rs`
- Modify: `core/src/drop_ops.rs`
- Create: `core/tests/acl_ipv6_datapath_contract.rs`
- Modify: `ci/check_neutron_stage1.py`

**Interfaces:**
- Consumes: Tasks 2 and 3 ABI/state fields.
- Produces: family-qualified policy map construction and lookup, family-aware CT cache validity, honest `DropKey` family, and separated rule-stat buckets.

- [ ] **Step 1: Add RED core behavior tests**

Create tests under the `acl_ipv6_` filter that prove:

```rust
#[test]
fn acl_ipv6_wildcard_policy_keys_do_not_alias_ipv4() {
    let v4 = policy_key_for_test(7, 0, 0, 0, 0, 1, IP_FAMILY_V4);
    let v6 = policy_key_for_test(7, 0, 0, 0, 0, 1, IP_FAMILY_V6);
    assert_ne!(policy_key_bytes(v4), policy_key_bytes(v6));
}

#[test]
fn acl_ipv6_ct_family_zero_and_mismatch_are_stale() {
    assert!(!ct_acl_family_is_current(0, IP_FAMILY_V6));
    assert!(!ct_acl_family_is_current(IP_FAMILY_V4, IP_FAMILY_V6));
    assert!(ct_acl_family_is_current(IP_FAMILY_V6, IP_FAMILY_V6));
}

#[test]
fn acl_ipv6_drop_family_zero_is_valid_only_for_drop_accounting() {
    assert!(drop_family_is_valid(0));
    assert!(!policy_family_is_valid(0));
}

#[test]
fn acl_ipv6_counter_bucket_identity_contains_family() {
    let rows = rule_rows_with_identical_selectors_for_families(4, 6);
    let summary = aggregate_port_counters(&rows, &[], 7);
    assert_eq!(summary.buckets.len(), 2);
    assert_eq!(
        summary.buckets.iter().map(|row| row.ip_family).collect::<Vec<_>>(),
        vec![4, 6],
    );
}

#[test]
fn acl_ipv6_drop_reason_identity_contains_family() {
    let rows = drop_rows_with_identical_reason_for_families(4, 6);
    let summary = aggregate_port_counters(&[], &rows, 7);
    assert_eq!(summary.reasons.len(), 2);
    assert_eq!(
        summary.reasons.iter().map(|row| row.ip_family).collect::<Vec<_>>(),
        vec![4, 6],
    );
}
```

The first three ABI/key regressions may already pass after Tasks 2 and 3. The RED proof for Task 4 must come from the real counter/drop aggregation tests: they must fail because `PortCounterBucket`, `PortCounterReason`, and `DropStatsEntry` do not yet carry family and reason aggregation still aliases v4/v6. Do not count a synthetic tuple-only set as Task 4 RED evidence.

Add `aria-core acl_ipv6_` to `RUST_TESTS`.

- [ ] **Step 2: Push RED and record the exact hosted failure**

Commit `test(acl): prove IPv4 and IPv6 datapath isolation`, push, and record the failing `rust-behavior` job. Do not run Cargo locally.

- [ ] **Step 3: Thread family through packet and policy evaluation**

Set `PipelineCtx.ip_family=4` immediately after successful IPv4 parsing and `6` after successful IPv6 parsing. Construct every policy candidate as:

```rust
PolicyKey {
    tap_id: ctx.tap_id,
    src_id,
    dst_id,
    proto,
    direction: ctx.direction,
    bank,
    ip_family: ctx.ip_family,
}
```

Reject an invalid packet family as no valid ACL decision; never look up family `0`. Update userspace add/delete/replay/scrub/inventory constructors to include the stored rule family.

- [ ] **Step 4: Thread family through CT and drops**

`MatchedPolicy` carries `ip_family`; CT inserts store it; CT fast-path acceptance calls the family-aware cache helper with the parsed packet family. Mark mismatch and zero as stale and re-evaluate.

Every drop record constructs:

```rust
DropKey {
    tap_id,
    reason,
    direction,
    proto,
    ip_family: parsed_family_or_zero,
    src_id,
    dst_id,
}
```

ACL, known IPv4/IPv6 fragment, and post-family parse drops use `4/6`; non-IP and pre-family failures use `0`.

- [ ] **Step 5: Update statistics collection and stack checks**

Carry `PolicyKey.ip_family` into `RuleStatsEntry`/`PortPolicyCounter` identities and `DropKey.ip_family` into reason rows. Update all fixed key literals in tests. Do not add a stack-local copy of `PipelineCtx`, `PolicyKey`, or `CtValue`.

- [ ] **Step 6: Push GREEN and require all Rust/eBPF gates**

Commit `feat(acl): isolate IPv4 and IPv6 datapath state`, push, then require exact-head `rust-behavior`, warning-denied `rust-build`, full workspace tests, ABI layout, legacy packet bounds, and 448-byte stack-budget jobs to pass.

---

### Task 5: Implement the Dual-Stack Rust Compiler and Family-Qualified Selectors

**Files:**
- Create: `agent/src/neutron_acl_ip.rs`
- Modify: `agent/src/main.rs`
- Modify: `agent/src/neutron_api.rs`
- Modify: `agent/src/control_plane.rs`
- Modify: `ci/check_neutron_stage1.py`

**Interfaces:**
- Consumes: Tasks 2–4 family ABI, persisted state, and datapath APIs.
- Produces: `IpFamily`, `AclCidr`, family-aware rule normalization/overlap/protocol logic, `AclSelectorId { family, ordinal }`, and family-bearing `AclApplyPlan`/`OwnedAclPolicySpec`.

- [ ] **Step 1: Add RED compiler and namespace tests**

Add `neutron_acl_ipv6_` cases to the existing `ready_acl` compiler harness:

| Test name | Input | Exact assertion |
| --- | --- | --- |
| `neutron_acl_ipv6_v4_wildcard_deny_never_compiles_as_v6` | IPv4 any/any deny plus IPv6 any/any allow | two policies with families `4` and `6`, actions deny and allow respectively |
| `neutron_acl_ipv6_selector_names_are_family_qualified` | IPv4 `10.0.0.0/24` and IPv6 `2001:db8::/64` src selectors | names `__neutron_acl:port-1:src:selector:ipv4:0` and `__neutron_acl:port-1:src:selector:ipv6:0`, distinct IDs |
| `neutron_acl_ipv6_group_info_never_mixes_families` | both selectors above | every planned group contains CIDRs of exactly its encoded family |
| `neutron_acl_ipv6_protocol_aliases_are_family_aware` | IPv4 `icmp`, IPv6 `icmp`, IPv6 `icmpv6`, wrong numeric `1/58` cases | protocols `1`, `58`, `58`; wrong-family numeric inputs reject |
| `neutron_acl_ipv6_opposite_actions_coexist` | same direction/protocol, IPv4 allow and IPv6 deny | translation succeeds with two family-qualified effective keys |

Add the filter to hosted Rust behavior tests and capture RED.

- [ ] **Step 2: Implement `neutron_acl_ip.rs`**

Define the focused types:

```rust
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) enum IpFamily { Ipv4, Ipv6 }

impl IpFamily {
    pub(crate) fn as_u8(self) -> u8 { match self { Self::Ipv4 => 4, Self::Ipv6 => 6 } }
    pub(crate) fn label(self) -> &'static str { match self { Self::Ipv4 => "ipv4", Self::Ipv6 => "ipv6" } }
    pub(crate) fn parse_ethertype(value: Option<&str>) -> Result<Self, String> {
        match value.unwrap_or("IPv4").trim().to_ascii_lowercase().as_str() {
            "ipv4" => Ok(Self::Ipv4),
            "ipv6" => Ok(Self::Ipv6),
            other => Err(format!("unsupported ACL ethertype {other}")),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) enum AclCidr {
    V4 { network: u32, prefix: u8 },
    V6 { network: u128, prefix: u8 },
}

impl AclCidr {
    pub(crate) fn parse(value: &str, family: IpFamily) -> Result<Self, String>;
    pub(crate) fn family(self) -> IpFamily;
    pub(crate) fn canonical(self) -> String;
    pub(crate) fn overlaps(self, other: Self) -> bool;
}

pub(crate) fn acl_protocol(value: Option<&str>, family: IpFamily) -> Result<u8, String>;
```

Use standard-library address parsing; reject `%` zone identifiers and IPv4-mapped IPv6. Keep all overlap operations family-local.

- [ ] **Step 3: Replace IPv4-only compiler structures**

Remove `AclIpv4Cidr` and `ensure_ipv4_cidrs`. Add `family: IpFamily` to `CanonicalAclRule`, `NormalizedAclRule`, `AclEffectivePolicyKey`, `AclPolicyPlan`, validation-cache keys, and `OwnedAclPolicySpec`.

Define selector identity as:

```rust
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct AclSelectorId { family: IpFamily, ordinal: Option<usize> }

impl AclSelectorId {
    fn any(family: IpFamily) -> Self { Self { family, ordinal: None } }
    fn concrete(family: IpFamily, ordinal: usize) -> Self {
        Self { family, ordinal: Some(ordinal) }
    }
    fn is_any(self) -> bool { self.ordinal.is_none() }
    fn group_ordinal(self) -> usize {
        self.ordinal.expect("concrete ACL selector requires an ordinal")
    }
}
```

Build independent src/dst selector tables per family. `acl_group_for_selector` returns `"any"` for ordinal zero and otherwise formats the exact family-qualified namespace. Validate that every non-any group's CIDRs match its encoded family before producing `AclApplyPlan`.

- [ ] **Step 4: Preserve atomic policy conflict semantics**

Include family in `AclEffectivePolicyKey`, so conflicting actions are compared only inside the same family. Keep priority out of the key and retain controller overlap validation. Convert each planned policy to `OwnedAclPolicySpec { ..., ip_family: family.as_u8() }`.

- [ ] **Step 5: Push GREEN and verify Rust behavior**

Commit `feat(acl): compile family-qualified IPv6 policies`, push, and require the new `neutron_acl_ipv6_` tests plus all existing `neutron_acl_`, shadow-bank, ownership, and transaction tests to pass.

---

### Task 6: Normalize Neutron WAL State and Rebuild Incompatible Runtime Schema Atomically

**Files:**
- Create: `agent/src/acl_runtime_schema.rs`
- Modify: `agent/src/main.rs`
- Modify: `agent/src/neutron_wal.rs`
- Modify: `agent/src/neutron_api.rs`
- Modify: `agent/src/tap_registry.rs`
- Modify: `agent/src/control_plane.rs`
- Modify: `core/src/ebpf_ops/inventory.rs`
- Modify: `core/src/ebpf_ops/scrub.rs`
- Modify: `ci/check_neutron_stage1.py`

**Interfaces:**
- Consumes: Tasks 2–5 complete family-aware runtime plan.
- Produces: ACL runtime metadata schema `3`, policy-key schema `2`, idempotent Neutron committed/pending intent normalization, safe dormant-pin rebuild, and `acl_runtime_schema_mismatch_live` refusal.

- [ ] **Step 1: Add RED migration and runtime adoption tests**

Add these exact cases under existing `neutron_wal`,
`managed_startup_recovery_`, and new `acl_runtime_schema_` filters:

| Test name | Setup | Expected result |
| --- | --- | --- |
| `neutron_wal_legacy_missing_ethertype_normalizes_committed_and_pending_to_ipv4` | committed port and pending snapshot each contain a rule with missing ethertype | both normalize to explicit `IPv4` before returned replay |
| `neutron_wal_ipv6_intent_round_trips_explicit_family` | pending snapshot carries explicit `IPv6` | replay retains `IPv6` and passes recomputed intent hash |
| `acl_runtime_schema_dormant_old_pins_require_rebuild` | metadata `2/1`, live link count `0` | `RebuildDormant` |
| `acl_runtime_schema_live_old_links_refuse_cleanup` | metadata `2/1`, live link count `1` | `RefuseLive` with `acl_runtime_schema_mismatch_live` |
| `acl_runtime_schema_migration_is_idempotent_after_crash_restart` | run normalization twice around an injected checkpoint boundary | byte-identical normalized state and no family-zero materialization |

Push RED and retain the failing run evidence.

- [ ] **Step 2: Implement explicit runtime metadata**

Create:

```rust
pub(crate) const ACL_RUNTIME_SCHEMA_VERSION: u32 = 3;
pub(crate) const ACL_POLICY_KEY_SCHEMA_VERSION: u32 = 2;

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, Eq, PartialEq)]
pub(crate) struct AclRuntimeMetadata {
    pub runtime_schema: u32,
    pub acl_policy_key_schema: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum AclRuntimeSchemaDisposition {
    Adopt,
    RebuildDormant,
    RefuseLive { reason: String },
}
```

Store metadata atomically at
`registry.base_state_path.join("acl-runtime-schema.json")` using the existing
atomic state-file pattern. `classify_acl_runtime_schema(metadata,
live_link_count)` returns
`Adopt` only for `3/2`, `RebuildDormant` only when no live links exist, and
otherwise `RefuseLive { reason: "acl_runtime_schema_mismatch_live" }`.

- [ ] **Step 3: Normalize committed and pending Neutron WAL before materialization**

Add:

```rust
pub(crate) fn normalize_neutron_wal_acl_families(
    replay: NeutronWalReplay,
) -> Result<NeutronWalReplay, String>
```

Walk `state.ports[*].acl.rules` and `pending_intent.affected_ports[*].acl.rules`. Missing/empty historical `ethertype` becomes `IPv4`; explicit `IPv4`/`IPv6` is canonicalized; every other value fails. Recompute the existing status/intent integrity hashes and atomically checkpoint the normalized state before any call that attaches or writes maps.

- [ ] **Step 4: Integrate safe upgrade ordering**

At managed startup enforce:

```text
block transactions -> gate off -> verify quiesced -> detach links
-> normalize core state/local WAL -> normalize Neutron WAL/pending intent
-> classify pins -> remove only dormant resolved Aria pin directory
-> load fresh maps -> request full snapshot -> verify both banks
-> attach -> gate on -> resume transactions
```

If live old links exist, keep pins untouched, do not attach the new program, and publish blocked/operator status with reason `acl_runtime_schema_mismatch_live`. Legacy family-less owned selector groups are removed only as part of the authoritative full replacement.

- [ ] **Step 5: Verify atomic generation behavior**

Add/extend transaction tests proving a failure after IPv4 staging but before IPv6 verification does not switch the bank or report ready, and a failure during metadata/state migration leaves the gate off. Preserve existing `BeforeQuiesce`, `AfterQuiesce`, and `CompensationFailed` distinctions.

- [ ] **Step 6: Push GREEN and require recovery suites**

Commit `feat(acl): migrate family-aware runtime state safely`, push, and require WAL, startup recovery, pinned inventory, detach/attach, snapshot transaction, shadow bank, and warning-denied build jobs to pass.

---

### Task 7: Enforce Dual-Stack Neutron Write Invariants and Effective Projection

**Files:**
- Modify: `openstack/neutron_aria/neutron_aria/db/aria_acl/write_invariants.py`
- Modify: `openstack/neutron_aria/neutron_aria/agent/effective_acl.py`
- Modify: `openstack/neutron_aria/neutron_aria/agent/acl_source.py`
- Modify: `openstack/neutron_aria/neutron_aria/agent/inventory.py`
- Modify: `openstack/neutron_aria/neutron_aria/agent/main.py`
- Modify: `openstack/neutron_aria/neutron_aria/agent/event_loop.py`
- Modify: `openstack/neutron_aria/neutron_aria/services/aria_acl/plugin.py`
- Modify: `openstack/neutron_aria/neutron_aria/extensions/aria_acl.py`
- Modify: `openstack/neutron_aria/neutron_aria/tests/unit/test_aria_acl_write_invariants.py`
- Modify: `openstack/neutron_aria/neutron_aria/tests/unit/test_effective_acl.py`
- Modify: `openstack/neutron_aria/neutron_aria/tests/unit/test_aria_acl_plugin.py`

**Interfaces:**
- Consumes: Task 1 Python helpers and gate.
- Produces: family-canonical rule/address-set writes, reverse-reference protection, explicit-family snapshots, computed address-set `ethertype`, and honest gate-disabled projection.

- [ ] **Step 1: Add RED write and projection tests**

Add these cases to the existing repository and `EffectiveAclIndex` harnesses:

| Test name | Input | Exact assertion |
| --- | --- | --- |
| `test_ipv6_rule_is_canonicalized_and_persisted` | enabled IPv6 rule with `2001:db8::7/64` | stored CIDR `2001:db8::/64`, stored ethertype `IPv6` |
| `test_address_set_update_cannot_cross_enabled_rule_family` | enabled IPv4 rule referencing a set, update members to `2001:db8::/64` | `AriaAclValidationError`; old set remains unchanged |
| `test_empty_address_set_cannot_be_referenced_by_enabled_rule` | create empty set, then enabled rule reference | set creation succeeds; rule creation raises `AriaAclValidationError` |
| `test_dual_stack_effective_snapshot_keeps_two_explicit_rules` | one IPv4 and one IPv6 rule on the same policy | output contains exactly two rules with families `IPv4` and `IPv6` |
| `test_ipv6_gate_disabled_never_emits_enforcing_ipv6_snapshot` | selected enabled IPv6 rule and gate false | `enabled=False`, `status=degraded`, `effective_action=bypass`, reason `ipv6_acl_disabled` |

Run the selected Python modules and capture RED.

- [ ] **Step 2: Make writes family-canonical and reverse-safe**

`prepare_rule` first merges existing+patch, canonicalizes `ethertype`, canonicalizes direct CIDRs with that family, resolves every referenced address set's computed family, and rejects mismatch before the repository write.

`prepare_address_set` canonicalizes each member according to its parsed family, rejects mixed membership, then scans enabled referencing rules. It rejects disabled/empty replacement and any family change that differs from a referencing rule. The mutation remains inside the existing outer transaction.

- [ ] **Step 3: Emit computed address-set family without adding a writable field**

Add an extension-visible, read-only `ethertype` field for address sets:

```python
"ethertype": {
    "allow_post": False,
    "allow_put": False,
    "is_visible": True,
    "default": None,
}
```

Plugin create/get/list/update responses set it from `address_set_ethertype(members)`. Do not persist a new address-set column.

- [ ] **Step 4: Make effective snapshots family-explicit and gate-aware**

`EffectiveAclIndex` receives `ipv6_acl_enabled=False`. `_compile_rule` normalizes omitted family to `IPv4`, calls `normalize_cidr` for direct and address-set CIDRs, and emits explicit `ethertype`. If an enabled IPv6 rule is selected while the host gate is false, return `enabled=False`, `status=degraded`, `effective_action=bypass`, reason `ipv6_acl_disabled`; never silently drop the IPv6 rule from an otherwise ready policy.

Pass the config field through `build_acl_index`, agent startup, full-resync, and incremental event paths.

- [ ] **Step 5: Run GREEN Python suites and commit**

Run:

```bash
PYTHONPATH=openstack/neutron_aria python3 -m unittest \
  neutron_aria.tests.unit.test_aria_acl_write_invariants \
  neutron_aria.tests.unit.test_effective_acl \
  neutron_aria.tests.unit.test_aria_acl_plugin \
  neutron_aria.tests.unit.test_event_loop
python3 ci/check_neutron_stage1.py --fast-contracts
```

Expected: all pass. Commit `feat(neutron): enforce IPv6 ACL write invariants`, push, and wait for fast, DB, and clean-install jobs.

---

### Task 8: Expose IPv6 Rule and Address-Set Family Through the Neutron CLI

**Files:**
- Modify: `openstack/neutronclient_aria/neutronclient_aria/v2_0/aria_acl.py`
- Modify: `openstack/neutronclient_aria/neutronclient_aria/tests/test_aria_acl_cli.py`
- Modify: `ci/test_neutronclient_aria_cli_adminrc.sh`

**Interfaces:**
- Consumes: Task 7 REST fields.
- Produces: `--ethertype IPv4|IPv6` create/update input and explicit `ethertype` display for rules and address sets.

- [ ] **Step 1: Add RED CLI parser/rendering tests**

```python
def test_rule_create_accepts_ipv6_ethertype(self):
    command = aria_acl.AriaAclRuleCreate(FakeApp(None), None)
    args = command.get_parser("aria-acl-rule-create").parse_args([
        "--policy-id", "policy-1", "--direction", "ingress",
        "--priority", "100", "--action", "allow",
        "--ethertype", "IPv6", "--protocol", "icmpv6",
        "--src-cidr", "2001:db8::/64",
    ])
    self.assertEqual("IPv6", command.args2body(args)["aria_acl_rule"]["ethertype"])

def test_address_set_show_displays_computed_ethertype(self):
    class FakeClient(object):
        def show_ext(self, path, resource_id):
            return {"aria_acl_address_set": {
                "id": resource_id,
                "members": ["2001:db8::/64"],
                "ethertype": "IPv6",
            }}
    command = aria_acl.AriaAclAddressSetShow(FakeApp(FakeClient()), None)
    args = command.get_parser("aria-acl-address-set-show").parse_args(["set-1"])
    rows = self._show_result(command.execute(args))
    self.assertEqual("IPv6", rows["ethertype"])
```

Run `PYTHONPATH=openstack/neutronclient_aria python3 -m unittest neutronclient_aria.tests.test_aria_acl_cli` and expect the IPv6 parser case to fail.

- [ ] **Step 2: Expand choices and stabilize output**

Change both rule create/update parsers to `choices=["IPv4", "IPv6"]`. Ensure rule list/show column selection includes `ethertype` even when it was defaulted server-side. Add computed address-set `ethertype` to list/show fields. Do not add source-port flags or ICMPv6 type/code flags.

- [ ] **Step 3: Extend the packaged CLI smoke contract**

Add a dry parser/import assertion that both families are accepted and the command entry points remain discoverable. The smoke must not require a live Neutron server.

- [ ] **Step 4: Run GREEN and commit**

Run the CLI unit module and `bash ci/test_neutronclient_aria_cli_adminrc.sh`; commit `feat(cli): expose IPv6 ACL ethertype`, push, and require fast/clean-install CI.

---

### Task 9: Deploy Python Expand-Contract Compatibility and Enforce Host Enablement

**Files:**
- Modify: `openstack/neutron_aria/neutron_aria/agent/uds_client.py`
- Modify: `openstack/neutron_aria/neutron_aria/tests/unit/test_uds_client.py`
- Modify: `ci/check_neutron_stage1.py`
- Modify: `ci/test_ci001_trusted_gates.py`

**Interfaces:**
- Consumes: Tasks 5–8 working family compiler, projection, and config gate.
- Produces: Python acceptance for the current hash `v0.9-neutron-capabilities-5` and future hash `v0.9-neutron-capabilities-6`, strict validation of future `acl_ipv6_v1`/`counters_v2` fields, and explicit refusal to send IPv6 while the capability or host gate is absent. This task does not change the Rust producer or advertise the future capability.

- [ ] **Step 1: Add RED Python compatibility and gate tests**

Python tests must accept current hash `-5` with implicit
`acl_ipv6_v1=False,counters_v2=False`, accept a synthetic future `-6` payload
only when both fields are present and true, require `acl_ipv6_v1` before
sending an enabled IPv6 snapshot, and reject any unknown hash. The future
payload lives in the Python unit fixture in this task; public producer fixtures
change only in Task 10.

- [ ] **Step 2: Implement Python expand-contract acceptance**

Replace single-value comparison with an explicit allowlist:

```python
SUPPORTED_CAPABILITY_HASHES = frozenset((
    "v0.9-neutron-capabilities-5",
    "v0.9-neutron-capabilities-6",
))
```

Old hash means `acl_ipv6_v1=False,counters_v2=False`; future hash requires both
fields true. A selected IPv6 snapshot with missing capability returns a typed
local contract error before mutation. IPv4 snapshots continue during the
rolling window. Do not alter `api/src/lib.rs` or the Rust capability response
in this task.

- [ ] **Step 3: Update behavioral CI contracts, not source markers**

Add the exact compatibility and gate test IDs to fixed Python discovery.
`check_packaged_ini_contract` must assert `ipv6_acl_enabled is False`, and
`check_documented_ini_contract` must require the documented option. Public
Rust-produced fixtures still assert hash `-5` until Task 10. Do not bind checks
to private helper names.

- [ ] **Step 4: Verify and commit the Python-first expansion**

Run Python UDS tests and fast contracts locally. Commit
`feat(neutron): accept future IPv6 ACL capability safely`, push, and require
fast contracts and clean-install to pass before Task 10. The branch still
advertises hash `-5` and cannot enable IPv6 at this point.

---

### Task 10: Upgrade Counters v2 and Publish the New Rust Capability Atomically

**Files:**
- Modify: `api/src/lib.rs`
- Modify: `agent/src/neutron_api.rs`
- Modify: `core/src/port_counters.rs`
- Modify: `core/src/drop_ops.rs`
- Modify: `openstack/neutron_aria/neutron_aria/agent/uds_client.py`
- Modify: `openstack/neutron_aria/neutron_aria/agent/counter_sampler.py`
- Modify: `openstack/neutron_aria/neutron_aria/agent/status_reporter.py`
- Modify: `openstack/neutron_aria/neutron_aria/db/migration/aria_acl_counters.py`
- Create: `openstack/neutron_aria/neutron_aria/db/aria_acl/migration/versions/c7d4e9a1b260_add_acl_counter_family.py`
- Modify: `openstack/neutron_aria/neutron_aria/db/aria_acl/api.py`
- Modify: `openstack/neutron_aria/neutron_aria/db/aria_acl/sql_query.py`
- Modify: `openstack/neutron_aria/neutron_aria/extensions/aria_acl.py`
- Modify: `openstack/neutron_aria/neutron_aria/services/aria_acl/plugin.py`
- Modify: `openstack/neutron_aria/neutron_aria/tests/unit/test_uds_client.py`
- Modify: `openstack/neutron_aria/neutron_aria/tests/unit/test_counter_sampler.py`
- Modify: `openstack/neutron_aria/neutron_aria/tests/unit/test_status_reporter.py`
- Modify: `openstack/neutron_aria/neutron_aria/tests/unit/test_aria_acl_counter_migration.py`
- Modify: `openstack/neutron_aria/neutron_aria/tests/unit/test_aria_acl_plugin.py`
- Modify: `openstack/neutronclient_aria/neutronclient_aria/v2_0/aria_acl.py`
- Modify: `openstack/neutronclient_aria/neutronclient_aria/tests/test_aria_acl_cli.py`
- Modify: `docs/neutron-uds-contract.json`
- Modify: `docs/neutron-status-contract-v3-scenarios.json`
- Modify: `ci/check_neutron_stage1.py`
- Modify: `ci/test_ci001_trusted_gates.py`

**Interfaces:**
- Consumes: Task 4 family-bearing counters and Task 9 Python compatibility.
- Produces: counters schema v2 bucket/reason `ip_family`, v1/v2 strict decoder dispatch, nullable DB migration, family-qualified row identity, CLI rendering, and the first Rust producer that atomically advertises capability hash `v0.9-neutron-capabilities-6`, `acl_ipv6_v1=true`, and `counters_v2=true`.

- [ ] **Step 1: Add RED transport, decoder, DB, and CLI tests**

Add these exact cases to the existing counter payload and repository harnesses:

| Test name | Input | Exact assertion |
| --- | --- | --- |
| `test_counters_v2_bucket_requires_ipv4_or_ipv6_family` | otherwise-valid v2 bucket with family `4`, `6`, then `0` | first two decode; family zero produces `invalid_counters_v2` |
| `test_counters_v2_reason_accepts_non_ip_family_zero` | v2 reason row family `0` | decode succeeds and CLI renders `non-ip/unknown` |
| `test_counters_v1_remains_accepted_with_unknown_family` | existing v1 fixture | decoded rows carry `ip_family=None` |
| `test_counter_migration_adds_nullable_family_and_rebuilds_unique_index` | pre-v2 schema with one existing row | row preserved, nullable column exists, index includes family, second upgrade returns unchanged |
| `test_counter_replace_keeps_same_selector_ids_in_two_families` | v2 IPv4 and IPv6 buckets with same ids/proto/direction | two persisted rows remain after replace-all |

Add Rust tests asserting two policy keys differing only by family produce two v2 bucket rows.
Also add a producer capability RED assertion requiring hash
`v0.9-neutron-capabilities-6`, `acl_ipv6_v1=true`, and `counters_v2=true`.

Commit the RED tests as `test(acl): require counters v2 capability`, push, and
capture the exact failing `rust-behavior`, `fast-contracts`, or DB contract job
with the Task 2 `gh run list --commit` procedure. The expected failure is
missing v2 wire fields, missing DB family identity, or current capability still
being hash `-5`.

- [ ] **Step 2: Define v2 wire structs while retaining v1 decoding**

Add explicit v2 types rather than silently changing v1:

```rust
pub struct NeutronCounterBucketV2 {
    pub ip_family: u8,
    pub src_id: u32,
    pub dst_id: u32,
    pub proto: u8,
    pub direction: u8,
    pub packets: u64,
    pub bytes: u64,
    pub dropped_packets: u64,
    pub dropped_bytes: u64,
}

pub struct NeutronCounterReasonV2 {
    pub ip_family: u8,
    pub reason: u8,
    pub direction: u8,
    pub proto: u8,
    pub packets: u64,
    pub bytes: u64,
}

pub struct NeutronPortCountersV2 {
    pub port_id: String,
    pub tap_id: u32,
    pub policy_packets: u64,
    pub policy_bytes: u64,
    pub policy_allow_packets: u64,
    pub policy_dropped_packets: u64,
    pub policy_dropped_bytes: u64,
    pub drop_packets: u64,
    pub drop_bytes: u64,
    pub truncated: bool,
    pub buckets: Vec<NeutronCounterBucketV2>,
    pub reasons: Vec<NeutronCounterReasonV2>,
    pub groups: Vec<NeutronCounterGroupV1>,
}

pub struct NeutronStatusCountersV2 {
    pub counters_schema_version: u32,
    pub sampled_at_ms: u64,
    pub counters_error: Option<String>,
    pub ports: Vec<NeutronPortCountersV2>,
}
```

Bucket family must pass `policy_family_is_valid`; reason family must pass
`drop_family_is_valid`. Keep the producer on counters v1 until the capability
publication step below, so no pushed intermediate commit advertises or emits
an unsupported contract.

- [ ] **Step 3: Dispatch Python v1/v2 through shared strict validation**

Create `_decode_counters_v1` and `_decode_counters_v2` wrappers around shared timestamp, size, row, and reset validation. v1 rows receive `ip_family=None`; v2 buckets require `4/6`; v2 reasons accept `0/4/6`. Contain malformed sections as `invalid_counters_v1` or `invalid_counters_v2` without suppressing ordinary heartbeat/status.

- [ ] **Step 4: Add the database migration**

The new Alembic revision uses `revision="c7d4e9a1b260"`, `down_revision="a4e7c2d9b610"`. It adds nullable `ip_family` to `aria_acl_port_counters`, drops `uq_aria_acl_port_counters_natural`, and recreates it over:

```text
port_id, host, kind, ip_family, src_id, dst_id, proto, direction, reason
```

The runtime bridge performs the same operations idempotently. Preserve v1 NULL rows. v2 replace-all writes non-null bucket family and `0/4/6` reason family.

- [ ] **Step 5: Update server and CLI identity/rendering**

Repository sort/natural-key tuples include `ip_family`. Extension/API rows expose it. CLI renders `4 -> IPv4`, `6 -> IPv6`, `0 -> non-ip/unknown`, and `None -> unknown`. Phase B `counters_report_enabled` remains false.

- [ ] **Step 6: Publish capability v6 in the same GREEN commit**

Add defaulted fields to `NeutronCapabilitiesResponse`:

```rust
#[serde(default)] pub acl_ipv6_v1: bool,
#[serde(default)] pub counters_v2: bool,
```

Set both true in `current()`, set the counters producer version to `2`, and
bump the capability hash to `v0.9-neutron-capabilities-6`. Update UDS/status
fixtures and `check_status_v1_contract` to validate current `-6` plus retained
rolling compatibility with `-5`. Status schema remains v3.

- [ ] **Step 7: Verify and commit**

Run all counter unit modules, DB contract modules with `ci/requirements-neutron-db-contracts.txt`, CLI tests, and fast contracts. Push and require Rust behavior/build plus `neutron-db-contracts`. Commit `feat(acl): qualify counter schema by IP family`.

---

### Task 11: Close Integrated CI, Packaging, Documentation, and Smoke Coverage

**Files:**
- Modify: `.github/workflows/build.yml` only if new behavior filters are not already reached by `check_neutron_stage1.py`
- Modify: `ci/check_neutron_stage1.py`
- Modify: `ci/check_tc_acl_datapath.py`
- Modify: `ci/check_standalone_tc_acl_smoke.py`
- Modify: `deploy/kolla/smoke/neutron_aria_acl_tc_datapath_smoke.sh`
- Modify: `deploy/smoke/aria_standalone_acl_tc_datapath_smoke.sh`
- Modify: `docs/aria-acl-neutron-extension-product-design.md`
- Modify: `docs/openstack-neutron-agent-mode.md`
- Modify: `docs/openstack-deployment-runbook.md`
- Modify: `docs/neutron-managed-domains-contract.md`
- Modify: `docs/acl-drop-reason-dictionary.md`
- Modify: `docs/openstack-ebpf-platform-roadmap.md`
- Modify: `docs/superpowers/specs/2026-08-16-aria-acl-ipv6-restoration-design.md`

**Interfaces:**
- Consumes: Tasks 1–10 complete implementation and test names.
- Produces: one trustworthy exact-head CI gate, packaged defaults, operator upgrade/rollback procedure, dual-stack smoke entrypoints, and an honest implementation status.

- [ ] **Step 1: Add behavior tests to fixed CI discovery**

Ensure `RUST_TESTS` contains non-zero filters for `acl_family_`, `acl_ipv6_`, `neutron_acl_ipv6_`, and `acl_runtime_schema_`. Add high-value Python test IDs to `REQUIRED_PYTHON_BEHAVIORS`. Keep `run_rust_behavior_command`'s zero-test rejection.

- [ ] **Step 2: Extend static smoke validators only for entrypoint structure**

Require the smoke scripts to expose IPv4-only, IPv6-only, dual-stack, wildcard-isolation, fragment, stateful-reply, upgrade, and rollback case names. Do not make a static checker report those cases PASS; scripts return SKIP/deferred when prerequisites or managed ports are absent.

- [ ] **Step 3: Add concrete smoke operations**

The managed smoke creates separate IPv4 and IPv6 rules and verifies both directions with namespace/VM traffic. The standalone smoke covers `ethertype=any` expansion. Every case records command, expected verdict, observed verdict, interface, ifindex, kernel, agent/datapath version, and status/counter snapshot. Zero managed ports is failure, not PASS.

- [ ] **Step 4: Document product and operational contracts**

Update all listed docs to state:

- one-rule/one-family and omitted=`IPv4`;
- ICMP family mapping and no hidden ND bypass;
- address-set single-family behavior;
- family-qualified runtime and counter identity;
- runtime schema 3/policy-key schema 2 rebuild and symmetric rollback;
- Python-first expand-contract rollout;
- `ipv6_acl_enabled=false` and counters default-off; and
- field status `deferred/pending` until Task 12.

Change the design status to `implementation complete; hosted CI linked; field
evidence pending` only after the exact-head run passes, and append the URL
printed by `gh run view "$ARIA_IPV6_GREEN_RUN_ID" --json url --jq .url`.

- [ ] **Step 5: Run all allowed local non-Rust checks**

```bash
python3 ci/check_neutron_stage1.py --fast-contracts
python3 -m unittest ci.test_ci001_trusted_gates
python3 -m unittest ci.test_ci_lane_contract
python3 -m unittest ci.test_ebpf_stack_budget
python3 ci/check_tc_acl_datapath.py
python3 ci/check_standalone_tc_acl_smoke.py
bash -n deploy/kolla/smoke/neutron_aria_acl_tc_datapath_smoke.sh
bash -n deploy/smoke/aria_standalone_acl_tc_datapath_smoke.sh
git diff --check
```

Expected: all commands exit `0`; no command claims privileged traffic passed.

- [ ] **Step 6: Commit, push, and require exact-head full CI**

Commit `test(acl): gate complete dual-stack IPv6 delivery`, push, and wait for `fast-contracts`, clean install, DB contracts, `rust-behavior`, warning-denied `rust-build`, full workspace tests, stack budget, and release packaging. Record the exact run URL in the design and implementation status docs in a final documentation-only commit.

---

### Task 12: Execute Real OpenStack/4.18 Field Validation and Decide Enablement

**Files:**
- Create under the validated `ARIA_IPV6_EVIDENCE_DIR`: `commands.log`
- Create under the validated `ARIA_IPV6_EVIDENCE_DIR`: `facts.tsv`
- Create under the validated `ARIA_IPV6_EVIDENCE_DIR`: `results.tsv`
- Create under the validated `ARIA_IPV6_EVIDENCE_DIR`: `status-before.json`
- Create under the validated `ARIA_IPV6_EVIDENCE_DIR`: `status-after.json`
- Create under the validated `ARIA_IPV6_EVIDENCE_DIR`: `summary.md`
- Modify: `docs/superpowers/specs/2026-08-16-aria-acl-ipv6-restoration-design.md`
- Modify: `docs/openstack-deployment-runbook.md`

**Interfaces:**
- Consumes: Task 11 exact-head artifacts and smoke drivers.
- Produces: host/kernel-bound evidence for IPv4-only, IPv6-only, dual-stack, update/restart/rollback, and an explicit production-gate decision.

- [ ] **Step 1: Freeze the tested artifact identity**

Record Git commit, GitHub Actions run URL, image digests, RPM/container package versions, each compute hostname, kernel release, NIC/tap names, ifindex, OVS version, Neutron version, and current capability payload. Reject mixed artifacts not described by the expand-contract sequence.

Create the evidence directory once and reuse it for the whole run:

```bash
ARIA_IPV6_EVIDENCE_ID="$(date -u +%Y%m%d%H%M%S)-$(hostname -s | tr -cd 'A-Za-z0-9._-')"
ARIA_IPV6_EVIDENCE_DIR="docs/evidence/openstack-ipv6-acl/${ARIA_IPV6_EVIDENCE_ID}"
install -d -m 0755 "$ARIA_IPV6_EVIDENCE_DIR"
```

- [ ] **Step 2: Deploy in expand-contract order with gates off**

Deploy compatible Python first, verify IPv4 ACL remains operational, deploy Rust/eBPF and complete runtime schema rebuild, verify `acl_ipv6_v1=true`, then enable `ipv6_acl_enabled=true` only on the selected test compute. Leave production/default config false.

- [ ] **Step 3: Run the mandatory traffic matrix**

Execute IPv4-only, IPv6-only, and dual-stack ports across ingress/egress allow/deny, wildcard isolation, direct CIDR, address set, TCP, UDP, ICMP/ICMPv6, ND under explicit allow and deny-any, first/non-first fragments, and stateful replies. Each row records expected and observed verdict plus the effective ACL status.

- [ ] **Step 4: Run lifecycle and rollback cases**

Exercise bank update, agent restart, datapath restart, host reboot, detach/reattach, schema-mismatch refusal, and symmetric rollback. Prove old/new pinned maps are never reused across policy-key schemas and ordinary IPv4 forwarding follows the documented failure outcome.

- [ ] **Step 5: Optionally enable the separate counters test gate**

Set `counters_report_enabled=true` only for the counters sub-matrix. Verify same selector IDs in IPv4 and IPv6 produce separate rows and non-IP drop reasons render family zero honestly. Restore the counter gate to false afterward.

- [ ] **Step 6: Classify evidence and commit it**

Every executed row is `PASS` or `FAIL`; every unexecuted row is `deferred/pending`, never PASS. A failure blocks production enablement but does not authorize unrelated changes. Commit evidence as `test(acl): record IPv6 field validation` and push.

- [ ] **Step 7: Make the production enablement decision**

Enablement is approved only if the full mandatory matrix passes, exact tested artifacts are reproducible, rollback succeeds, and no port reports ready after partial-family publication. Update the design/runbook with the decision. The packaged default remains false even after approval; production hosts opt in through controlled rollout.

## Final Verification Checklist

- [ ] `git status --short --branch` is clean and `git rev-list --left-right --count main...origin/main` is `0 0`.
- [ ] No `PolicyKey`, `CtValue`, `RuleInfo`, owned-policy key, selector ID, or v2 counter bucket can lose family.
- [ ] `DropKey` alone accepts family zero, and display renders it as `non-ip/unknown`.
- [ ] IPv4 wildcard deny does not affect IPv6 and IPv6 wildcard deny does not affect IPv4.
- [ ] Legacy core state, local WAL, committed Neutron WAL, and pending intents normalize before runtime materialization.
- [ ] Live old-schema links stop automatic cleanup with `acl_runtime_schema_mismatch_live`.
- [ ] IPv4/IPv6 selector groups have separate names, IDs, lifetime, persistence, and display mapping.
- [ ] Python accepts old/new capability hashes only during the documented rollout window.
- [ ] `ipv6_acl_enabled=false` and `counters_report_enabled=false` are packaged and CI-enforced defaults.
- [ ] All exact-head hosted Rust/eBPF, Python, DB, packaging, and stack gates pass.
- [ ] Real OpenStack/4.18 evidence is either actual PASS/FAIL or honestly `deferred/pending`.
