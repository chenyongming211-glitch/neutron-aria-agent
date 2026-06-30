# 03. NeutronAclSource Detail Plan

Status: partial implementation package. `NeutronAclSource` can consume the
`aria_acl` effective payload/list contract and build `EffectiveAclIndex`.
Injected clients, legacy list methods, and a thin aria_acl REST adapter for
python-neutronclient are covered by unit tests; production auth/session
execution against the target neutron-server image remains.

## Goal

Replace the current fail-fast `NeutronAclSource` placeholder with a production
reader that consumes `aria_acl` data and produces the effective ACL index used by
`neutron-aria-agent`.

## Input Sources

| Source | Role |
| --- | --- |
| Neutron ports for local host | Determine candidate ports and binding host. |
| `aria_acl` bindings | Determine whether ACL is requested for port/network. |
| `aria_acl` policies/rules/address-sets | Build explicit ACL enhancement payload. |
| `aria_acl` runtime status | Optional read path for reconciliation and stale status decisions. |

## Effective ACL Rules

Precedence:

1. Port-level binding.
2. Network-level binding.
3. No binding means `not_requested` / `bypass`.

If multiple bindings conflict, return degraded input status rather than silently
guessing.

## Snapshot Output

For each eligible port:

- include `managed_domains` based on config, usually `["acl"]`;
- include ACL payload only when effective ACL exists or degraded reason must be
  reported;
- use `effective_action=enforce` only when ACL is ready to apply;
- use `effective_action=bypass` for missing, invalid, degraded, or unsupported
  inputs.

## Revision And Resync

- Full resync is the first production path.
- Incremental event handling may trigger full resync until a safe port-scoped
  cache exists.
- Keep revision fields in the effective ACL index so future incremental logic can
  detect stale updates.

## Failure Handling

| Failure | Required Behavior |
| --- | --- |
| Neutron ACL API unavailable | agent degraded; keep previous classified state until resync. |
| Binding points to missing policy | ACL degraded, bypass. |
| Rule schema invalid | ACL degraded, bypass. |
| Address set missing member data | ACL degraded, bypass. |
| Project ownership conflict | ACL degraded or API validation error; never merge across projects silently. |

## Implementation Design Package

This package is detailed to file/source/merge/flow/test level. Do not expand to
function-call level until the `NeutronAclSource` PR is opened.

### Target Files

| File | Role |
| --- | --- |
| `openstack/neutron_aria/neutron_aria/agent/acl_source.py` | ACL source interface plus `DisabledAclSource`, `FixtureAclSource`, and `NeutronAclSource`. |
| `openstack/neutron_aria/neutron_aria/agent/event_loop.py` | Full resync orchestration and snapshot construction. |
| `openstack/neutron_aria/neutron_aria/agent/state.py` | Effective ACL index, pending transaction state, and degraded input tracking. |
| `openstack/neutron_aria/neutron_aria/agent/config.py` | `[acl].source=neutron` selection and validation. |
| `openstack/neutron_aria/neutron_aria/agent/neutron_client.py` or equivalent | Neutron API wrapper for ports and `aria_acl` effective read. |
| `openstack/neutron_aria/neutron_aria/tests/unit/test_acl_source.py` | Unit tests for precedence, degraded input, and project isolation. |
| `deploy/kolla/smoke/` | Production ACL smoke after plugin exists. |

### Source Interface

All ACL sources should return one bounded effective index:

| Field | Meaning |
| --- | --- |
| `port_id` | Neutron port id. |
| `project_id` | Project owner for validation and status. |
| `effective_source` | `port`, `network`, or `none`. |
| `policy_id` / `policy_revision` | Selected policy identity and revision. |
| `rules` | Ordered Aria ACL rules ready for snapshot conversion. |
| `address_sets` | Resolved address-set members referenced by rules. |
| `input_status` | `ready`, `not_requested`, or `degraded`. |
| `reason` | Stable degraded reason, if any. |

### Full Resync Flow

1. Read local Neutron ports for the configured host.
2. Filter eligible VM/tap ports according to the main OpenStack design.
3. For each eligible port, read effective ACL through `aria_acl`.
4. Apply precedence: port binding, then network binding, then no binding.
5. Validate policy/rule/address-set ownership and schema.
6. Build effective ACL index with revision metadata.
7. Convert the index into snapshot ACL payloads.
8. Submit snapshot through the transaction path in `07-transaction-wal.md`.

### Snapshot Conversion Rules

| Input Status | Snapshot Result |
| --- | --- |
| `ready` | Include ACL payload with `effective_action=enforce`. |
| `not_requested` | Include domain status or omit payload according to DTO contract; effective action is `bypass`. |
| `degraded` | Include stable reason; effective action is `bypass`. |
| unsupported target port | Exclude from ACL apply and report support disposition when available. |

### Cache And Revision Rules

- Full resync is authoritative in v0.9.
- Cache may hold the last effective index only to compare revisions and build
  stable generation hashes.
- Incremental events may trigger full resync; they must not apply partial ACL
  deltas until explicitly designed.
- Display names are never cache keys; use ids and revisions.

### Error Semantics

| Condition | Required Status |
| --- | --- |
| `aria_acl` API unavailable | Agent degraded; keep previous classified datapath state until resync. |
| Effective ACL read returns 404 for binding target | Input degraded, bypass. |
| Missing policy/rule/address-set | Input degraded, bypass. |
| Rule action unknown to datapath | Input degraded, bypass. |
| Project mismatch | Input degraded or server-side validation error. |
| Neutron auth/session failure | Agent degraded; no local authority release. |

### Test Matrix

| Test | Expected Result |
| --- | --- |
| `acl.source=neutron` with plugin available | Source builds effective index. |
| Port-level binding exists | Port binding wins over network binding. |
| Only network binding exists | Network binding selected. |
| No binding exists | ACL not requested and bypass. |
| Missing referenced policy | Degraded input and bypass. |
| Same display name in two projects | No collision because ids/project ids are used. |
| Incremental event received | Triggers full resync, not partial delta apply. |
| Neutron API unavailable | Agent degraded and previous datapath state remains classified. |

### Anti-Overengineering Guardrails

- Do not reintroduce tag/mapping as production input.
- Do not consume Neutron Security Group.
- Do not implement partial/incremental ACL apply before full resync is proven.
- Do not build a second ACL product model inside the agent.
- Do not treat Neutron read failure as permission to accept local writes for
  managed domains.

## Acceptance

- `acl.source=neutron` no longer raises placeholder error after plugin exists.
- Port-level and network-level binding precedence is tested.
- Missing/invalid ACL input results in bypass, not OVS disruption.
- Two projects with same display names do not collide.

## Non-Goals

- Do not consume Security Group.
- Do not implement port-scoped incremental snapshots before full resync path is
  stable.
- Do not add local file mapping to the production read path.
