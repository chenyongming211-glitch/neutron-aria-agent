# 02. aria_acl Plugin Detail Plan

Status: partial implementation package. A stdlib-only repository/plugin
contract, API extension descriptor, entry points, minimal persistent DB
repository, minimal Alembic table creation, CRUD/revision behavior, and RBAC
contract exist for unit testing and agent integration; `neutron-db-manage`
execution and neutron-server startup validation remain target-environment gates.

Detailed CRUD, DB schema, RBAC, legacy client, and product API behavior belong
to `../aria-acl-neutron-extension-product-design.md`. This file defines only the
v0.9 minimum gate and implementation slice.

## Goal

Provide the production ACL input source for v0.9 through a Neutron service
plugin/API/DB extension named `aria_acl`.

## Minimum Product Objects

| Object | Purpose |
| --- | --- |
| `aria_acl_policy` | Named ACL policy owned by a project or admin. |
| `aria_acl_rule` | Match/action rule inside a policy. |
| `aria_acl_address_set` | Explicit CIDR/address set referenced by rules. |
| `aria_acl_binding` | Binding from policy to port or network. |
| `aria_acl_port_status` | Runtime status reported by agent/datapath. |

## First-Stage Semantics

- Admin/operator controlled first version is acceptable.
- No Neutron Security Group projection.
- No remote group expansion.
- No anti-spoof or port security enforcement.
- Binding missing means ACL domain `not_requested` and `effective_action=bypass`.
- Binding invalid or policy inaccessible means ACL domain `degraded` and
  `effective_action=bypass`.

## API Requirements

Minimum CRUD/read path:

- policy create/list/show/update/delete;
- rule create/list/show/update/delete;
- address-set create/list/show/update/delete/member update;
- binding create/list/show/delete;
- effective ACL show for a port;
- runtime status show for a port.

## Compatibility Constraints

- Must be compatible with the target product Neutron Python2 environment.
- Do not assume modern Python3-only `neutron-lib` patterns unless verified.
- Registration path must be validated in the product neutron-server image.

## Output To Agent

The plugin must allow `neutron-aria-agent` to derive:

- policy id/name/revision;
- binding id/source;
- rule list;
- address-set membership;
- project ownership;
- effective source: `port`, `network`, or `none`.

## Implementation Design Package

This package is detailed to file/object/API/flow/test level. CRUD field details,
DB migrations, and RBAC defaults stay in
`../aria-acl-neutron-extension-product-design.md` as the product reference.
Do not expand to function-call level until the `aria_acl` server plugin PR is
opened.

### Target Files

| File | Role |
| --- | --- |
| `openstack/neutron_aria/neutron_aria/extensions/aria_acl.py` | Neutron API extension descriptor, resources, attributes, aliases. |
| `openstack/neutron_aria/neutron_aria/services/aria_acl/plugin.py` | Service plugin entry point and API operations. |
| `openstack/neutron_aria/neutron_aria/db/aria_acl/api.py` | DB API/repository for policies, rules, address sets, bindings, and statuses; keep aligned with the implementation plan. |
| `openstack/neutron_aria/neutron_aria/db/migration/` and `db/aria_acl/migration/versions/` | Alembic migration contract and product version file for `aria_acl` tables. |
| `openstack/neutron_aria/neutron_aria/policies/aria_acl.py` | RBAC rules for admin/operator first-stage access. |
| `openstack/neutron_aria/neutron_aria/cmd/` or client extension path | Legacy `neutron aria-acl-*` command registration if required by product packaging. |
| `openstack/neutron_aria/neutron_aria/tests/unit/services/aria_acl/` | Unit tests for CRUD, validation, RBAC, and effective ACL read path. |
| `openstack/neutron_aria/neutron_aria/tests/functional/` | Neutron-server startup and extension visibility tests where available. |

### Object Model

| Object | Required Keys | Notes |
| --- | --- | --- |
| policy | `id`, `project_id`, `name`, `revision_number`, timestamps | Named desired ACL policy. |
| rule | `id`, `policy_id`, match fields, action, priority | Explicit Aria ACL rule; no SG semantic projection. |
| address set | `id`, `project_id`, `name`, members, revision | Explicit CIDR/member set referenced by rules. |
| binding | `id`, `project_id`, `policy_id`, target type/id, revision | Target type is `port` or `network` in v0.9. |
| port status | `port_id`, `host`, `policy_id`, domain status, generation | Runtime summary written/read by agent path. |

Runtime status ownership:

- Writer: `neutron-aria-agent` reports per-port runtime summaries through the
  `aria_acl` Neutron API after reading datapath status.
- Reader: the `aria_acl` plugin/API serves `neutron port-show` summaries,
  `aria-acl-port-status-show`, and product troubleshooting reads.
- Server-side plugin code owns storage, stale detection, and read projection; it
  must not infer desired ACL state from runtime status rows.

### API Surface

| API Group | Minimum Operations |
| --- | --- |
| policies | create/list/show/update/delete |
| rules | create/list/show/update/delete |
| address sets | create/list/show/update/delete/member update |
| bindings | create/list/show/delete |
| effective ACL | show by port id |
| port status | show by port id and optional host |

### Validation Rules

- Policy, rule, address set, and binding project ownership must match unless an
  admin override is explicitly allowed.
- Binding target must exist or be classified as invalid during effective read;
  do not silently apply to a wrong target.
- Port binding has precedence over network binding.
- Conflicting bindings at the same precedence level must return degraded input
  for the agent rather than picking one implicitly.
- Rule action vocabulary must map to Aria datapath action vocabulary; unknown
  values are API validation errors.
- Effective runtime compilation accepts at most 1000 enabled rules per policy
  and at most 2048 raw members on each rule-side selector. The selector bound is
  checked before canonicalization or deduplication. Overflow projects the ACL as
  `degraded/bypass` with stable `acl_rule_limit_exceeded:*` or
  `acl_selector_member_limit_exceeded:*` reasons; it does not add a Neutron API
  create/update quota.
- IPv4 selectors use one strict grammar in Python and Rust: surrounding
  whitespace is trimmed, exactly four decimal octets and a `0..32` prefix are
  required, multi-character leading-zero octets are rejected, and host bits are
  rendered as the canonical network address.

### Rule Priority Support Boundary

- The northbound rule model stores `priority`, and lower numeric values remain
  the northbound ordering convention.
- The current eBPF datapath does not implement numeric priority ordering:
  `PolicyKey` has no priority field and lookup remains specificity-based.
- Only priority-independent selector shapes are accepted. Exact canonical CIDR
  sets may share one selector group, and concretely disjoint rules remain safe.
- Non-identical intersecting CIDRs, plus wildcard/specific fallbacks whose
  action or port behavior changes, are rejected before enforcement and converge
  to ACL `degraded` with `effective_action=bypass`.
- This boundary does not add or change QoS or Mirror behavior; both remain
  outside the Batch 5 ACL fix.

### Effective ACL Validation Cache Boundary

- One immutable Python `EffectiveAclIndex` compiles each policy once and caches
  both ready and degraded results. Each port projection receives a defensive
  copy, while revision and binding metadata remain port-specific.
- Rust caches normalized/validated ACL templates only within one full or
  port-scoped snapshot request. The key contains policy id, revision, and a
  deterministic digest of every translated rule field; there is no persistent
  cross-request cache.
- Cache hits still render selector-group names under the current port ownership
  prefix, so validation reuse cannot leak another port's group identity.

### Effective ACL Read Flow

1. Receive port id and resolve port/project/network.
2. Read port-level binding.
3. If none, read network-level binding.
4. Load policy, rules, and address sets for the selected binding.
5. Validate ownership and schema consistency.
6. Return effective source `port`, `network`, or `none`.
7. Return degraded reason instead of desired rules when validation fails.

### RBAC And Audit

First-stage product mode is admin/operator controlled:

- tenant self-service is disabled unless separately approved;
- every write records request id, project id, user context, and object id;
- runtime status writes are restricted to the agent service identity or admin;
- read paths needed by `neutron-aria-agent` must work in the target
  Python2/Neutron environment.

### Test Matrix

| Test | Expected Result |
| --- | --- |
| neutron-server starts with plugin enabled | Extension visible and service loads. |
| Policy/rule/address-set/binding CRUD | Objects persist with revisions and request ids. |
| Port binding overrides network binding | Effective ACL source is `port`. |
| No binding | Effective ACL source is `none`; agent sees bypass/not requested. |
| Missing policy in binding | Effective read returns degraded reason. |
| Cross-project reference | Rejected or degraded; no silent merge. |
| Tenant write in admin-only mode | Rejected by RBAC. |
| Agent status write | Allowed only for agent/admin identity. |

### Anti-Overengineering Guardrails

- Do not implement Neutron Security Group compatibility in this plugin.
- Do not add remote group expansion.
- Do not build tenant self-service until product policy approves it.
- Do not add QoS objects under `aria_acl`.
- Do not optimize incremental read paths before full effective read is stable.

## Acceptance

- neutron-server starts with `aria_acl` enabled.
- extension is visible through the target network extension command.
- CRUD works with request ids and audit logs.
- port effective ACL can be read by the agent.
- `neutron port-show` or equivalent can expose read-only `aria_acl_*` summary.

## Non-Goals

- Do not modify Neutron Security Group.
- Do not implement tenant self-service policy unless separately approved.
- Do not make QoS part of `aria_acl`; QoS uses Neutron QoS model.

## Legacy CLI Note

Legacy `neutron aria-acl-*` commands are delivered with the `aria_acl` product
extension. They do not need a separate detail plan unless CLI scope grows beyond
the plugin/API/DB delivery.
