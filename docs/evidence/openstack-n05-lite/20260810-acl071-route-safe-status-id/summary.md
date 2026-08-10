# Route-Safe Composite Port-Status Identity

Date: 2026-08-10

Status: fixed and field-verified on the active test controller.

## Root Cause

The original derived identity used `aria-status-v1.<base64url>`. The target
Neutron 9 controller registers the formatted member route `/{id}.:{format}`
before the plain `/{id}` route. A request containing the derived ID therefore
reached the plugin with only `aria-status-v1` as its ID.

The stored identity was already correct: port-status rows use the composite
key `(port_id, host)`. The defect was limited to the public path encoding.

## Repair

- New API projections emit `aria-status-v1_<base64url>`.
- The complete emitted value uses only `[A-Za-z0-9_-]`.
- The decoder accepts both the new prefix and the former dotted prefix.
- Plugin and repository dispatch use one shared derived-ID predicate.
- In-memory filters and pagination resolve old and new identities by decoded
  composite key, matching the SQLAlchemy and SQLite repositories.
- No database column or migration was added.

## Verification

| Check | Result |
| --- | --- |
| TDD RED | New-prefix emission and shared identity recognition failed before implementation; old marker lookup also reproduced a repository parity error. |
| Focused tests | 90 Neutron query/plugin/source tests and 10 legacy CLI tests passed. |
| Fast contracts | 584 tests passed, 8 environment-dependent tests skipped; CLI, configuration, package, and smoke contracts passed. |
| Controller contract | The regression models the target route order and proves the emitted ID cannot match the formatted member route. |
| Reversible install | The active controller backed up its Neutron config, policy, and plugin package before installation; the extension returned after the controlled neutron-server restart. |
| Real HTTP exact access | Two status rows sharing one port and using different hosts returned distinct route-safe IDs. Exact GET resolved both rows. Exact DELETE returned 204, the deleted row returned 404, and the peer row remained readable. |
| Cleanup | The smoke removed all synthetic policy, rule, binding, and status rows. |
| Data-plane boundary | A VM connectivity canary passed before and after. OVS, ovs-agent, compute-side Python agents, and the Rust datapath were not restarted. |

## Compatibility

The old dotted form is accepted for direct plugin calls and query markers so a
rolling upgrade does not invalidate in-flight pagination state. It remains
unsuitable as a target Neutron HTTP path and is never emitted by the corrected
server. Existing database rows require no conversion because the derived ID is
computed from `port_id` and `host` on read.
