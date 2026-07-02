# 01. INI Contract Detail Plan

Status: stage-one implementation package; config validation and packaged safe
defaults are partially implemented.

## Goal

Freeze one target configuration layout for `neutron-aria-agent.ini` and keep
`integration_mode=coexist` out of ini files. `integration_mode` is a snapshot
field written by `neutron-aria-agent` when it submits
`PUT /api/v1/neutron/snapshot`.

## Target `neutron-aria-agent.ini`

```ini
[agent]
host = compute-01
agent_type = Aria ACL agent
report_interval = 30
resync_interval = 300
full_resync_enabled = false
managed_domains = acl

[ovs]
integration_bridge = br-int

[aria]
socket_path = /run/aria/aria-agent.sock
request_timeout = 3.0

[neutron]
port_source = disabled
rpc_events_enabled = false
incremental_rpc_enabled = false

[acl]
source = disabled
# fixture_path is CI/smoke only.
# fixture_path = /etc/neutron-aria-agent/acl-fixture.json
```

## Ownership Rules

| Setting | Owner | Notes |
| --- | --- | --- |
| `managed_domains` | `neutron-aria-agent` | Default `acl`; later may include `qos`, `mirror` only by explicit scope decision. |
| `full_resync_enabled` | `[agent]` | Safe default `false`; production enablement requires gates. |
| `port_source` | `[neutron]` | Safe default `disabled`; use `neutronclient` after auth and N0.5 gates. |
| `socket_path` | `[aria]` | UDS path to local datapath. |
| `integration_bridge` | `[ovs]` | Used for inventory/classification or delegated validation. |
| `acl.source` | `[acl]` | `disabled`, `fixture`, or `neutron`; production is `neutron`. |
| `integration_mode` | snapshot body | Must not appear in ini examples. |

## Local Datapath Config

The local datapath side may use:

```toml
agent_mode = "openstack"
listen_unix_socket = "/run/aria/aria-agent.sock"
```

or, for container packaging that uses different naming:

```toml
mode = "neutron_managed"
```

The naming must be documented per deployment target, but it must not be confused
with snapshot `integration_mode`.

## Required Documentation Follow-Up

- Align `../openstack-deployment-runbook.md` safe defaults.
- Align `../openstack-neutron-agent-mode.md` section 10 examples.
- Align `../aria-acl-neutron-extension-product-design.md` deployment examples.
- Mark deploy/kolla temporary differences as implementation evidence, not a
  second normative contract.

## Implementation Design Package

This package is detailed to file/field/flow/test level. Do not expand it into a
function-by-function design until the config PR is opened.

### Target Files

| File | Role |
| --- | --- |
| `openstack/neutron_aria/neutron_aria/agent/config.py` | Python config model, defaults, validation, and section ownership. |
| `openstack/neutron_aria/neutron_aria/tests/unit/test_config.py` | Unit tests for parser defaults, target layout, and invalid values. |
| `deploy/kolla/config/neutron-aria-agent.ini` | Packaged sample ini; must follow this target layout or be clearly marked transitional. |
| `deploy/kolla/neutron-aria-agent/README.md` | Deployment packaging notes and operator-facing config mapping. |
| `docs/openstack-deployment-runbook.md` | Safe defaults, enablement gates, and rollback instructions. |
| `docs/openstack-neutron-agent-mode.md` | Main normative architecture examples. |
| `docs/aria-acl-neutron-extension-product-design.md` | ACL product deployment examples and source selection. |

### Config Model

| Section | Field | Target Meaning |
| --- | --- | --- |
| `[agent]` | `host` | Local compute host identity reported to Neutron and datapath. |
| `[agent]` | `agent_type` | Neutron agent type string. |
| `[agent]` | `report_interval` | Heartbeat interval. |
| `[agent]` | `resync_interval` | Periodic resync cadence when enabled. Current Python code uses this key. |
| `[agent]` | `full_resync_enabled` | Safe default `false`; production enablement requires gates. |
| `[agent]` | `managed_domains` | Domain authority list, default `acl`. |
| `[ovs]` | `integration_bridge` | Local bridge inventory/classification input. |
| `[aria]` | `socket_path` | Local UDS path for `aria-datapath`. |
| `[aria]` | `request_timeout` | Client timeout; timeout recovery is defined in `07-transaction-wal.md`. |
| `[neutron]` | `port_source` | `disabled` by default; production target `neutronclient` after N0.5 gates. |
| `[neutron]` | `rpc_events_enabled` | Event path gate; safe default `false`. |
| `[neutron]` | `incremental_rpc_enabled` | P3 port-scoped apply gate; safe default `false`. When set to `true`, config validation requires RPC events, full resync, and `port_source=neutronclient`. |
| `[acl]` | `source` | `disabled`, `fixture`, or `neutron`; production target `neutron`. |
| `[acl]` | `fixture_path` | CI/smoke only. |

`integration_mode` is intentionally absent from the config model. The Python
agent writes `integration_mode=coexist` into snapshot bodies only.

### Load And Validation Flow

1. Load file and apply safe defaults.
2. Normalize `managed_domains` to a non-empty, lower-case, de-duplicated list.
3. Validate domains against the known domain set for v0.9.
4. Validate `acl.source` and require `fixture_path` only when source is
   `fixture`.
5. Validate `port_source`; do not construct a Neutron port reader when it is
   `disabled`.
6. Validate `incremental_rpc_enabled=true` only when `rpc_events_enabled=true`,
   `full_resync_enabled=true`, and `port_source=neutronclient`.
7. Build the UDS client from `[aria]`.
8. Build ACL source selection from `[acl]`.
9. Log an effective config summary without secrets or Keystone credentials.

### Migration Rules

- Use `resync_interval` as the target ini key for v0.9 because that is the
  current code path. If a later implementation renames it to
  `full_resync_interval`, that PR must provide an explicit compatibility alias
  and update this contract.
- Existing examples that place `full_resync_enabled` in `[neutron]` must be
  migrated to `[agent]`.
- Existing examples that place `acl_source` under `[aria]` must be migrated to
  `[acl].source`.
- Existing examples that include `integration_mode = coexist` must remove it.
- Runtime code may accept transitional aliases for one release only if needed,
  but docs must present a single target layout.

### Error And Warning Semantics

| Condition | Required Handling |
| --- | --- |
| Unknown section | Warn only unless it shadows a target setting. |
| Unknown domain in `managed_domains` | Hard config error. |
| Empty `managed_domains` | Hard config error. |
| `incremental_rpc_enabled=true` without RPC/full-resync/neutronclient dependencies | Hard config error; keep P2 on RPC-triggered full-resync only. |
| `acl.source=fixture` without `fixture_path` | Hard config error for CI/smoke mode. |
| `integration_mode` appears in ini | Warn or hard-fail during convergence; docs must not show it. |
| `full_resync_enabled=true` while `port_source=disabled` | Hard config error or explicit degraded startup; do not silently claim production resync. |

### Test Matrix

| Test | Expected Result |
| --- | --- |
| Target ini parses with safe defaults | Config object matches target values. |
| Missing optional sections | Safe defaults are applied. |
| `managed_domains = acl,qos` | Normalized to `["acl", "qos"]`. |
| Unknown managed domain | Config load fails. |
| `acl.source=fixture` without path | Config load fails. |
| `integration_mode` in ini | Test documents warning/failure behavior and no docs examples include it. |
| `full_resync_enabled=true` + `port_source=disabled` | Startup is rejected or explicitly degraded. |

## Acceptance

- No ini example contains `integration_mode = coexist`.
- All `neutron-aria-agent.ini` examples use the same sections.
- Runbook enablement steps mention when to switch `port_source` and
  `full_resync_enabled`.
- CI/smoke fixture examples remain clearly non-production.

## Non-Goals

- Do not change runtime code in this pass.
- Do not invent new config fields unless they already map to code or an approved
  gate.
