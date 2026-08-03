# Aria ACL / Aria QoS / Aria Mirror Neutron Productization Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a productized OpenStack Neutron integration where Aria ACL is an independent Neutron extension, Aria QoS is the product-facing facade over Neutron native QoS policy/rule models, Aria Mirror is a second-phase independent extension, and Aria enforces ACL/QoS/Mirror only on eligible VM OVS tap ports or explicitly configured host capture interfaces.

**Architecture:** Neutron Server is the source of truth for ACL/QoS/Mirror API, DB, RBAC, port binding, and runtime status. `neutron-aria-agent` runs on compute nodes, consumes Neutron state, discovers local OVS tap interfaces through `external_ids:iface-id`, computes per-port effective ACL/QoS/Mirror snapshots, and sends those snapshots to local `aria-agent` over `/run/aria/aria-agent.sock`. `aria-agent` does not access Neutron; it only validates snapshots, updates eBPF maps, preserves WAL/runtime state, and reports per-domain status.

**Tech Stack:** OpenStack Neutron Python 2.7, Legacy `python-neutronclient` 2016.9.9, ML2/Open vSwitch, Kolla-style containers, RabbitMQ/oslo.messaging, MySQL/Alembic `neutron-db-manage`, Rust 2021, Axum/UDS API, Aya/eBPF.

---

## 0. Scope And Delivery Rules

### 0.1 First-Stage Support Matrix

| Port type | First-stage action | Reason |
| --- | --- | --- |
| VM OVS tap, `device_owner=compute:*`, `binding:vif_type=ovs`, `binding:vnic_type=normal` | Supported | Current product environment has direct tap-to-`br-int` mapping with OVS `external_ids:iface-id=$PORT_ID` |
| Empty `device_owner` pre-created normal port after Nova bind | Supported after it becomes compute-owned | Before binding there is no local VM tap to enforce |
| `network:dhcp`, `network:router_*`, metadata/service ports | `not_applicable` | These can be OVS normal tap ports, but must not be ACL-enforced as VM ports |
| SR-IOV `direct` / `direct-physical` | `unsupported` | Traffic bypasses VM tap/`br-int`; needs future representor/hardware backend |
| LinuxBridge port | `unsupported` | Current Aria backend is OVS tap/eBPF only |
| Port without OVS `iface-id` mapping | `unknown` or `not_applicable` | Runtime attachment cannot be proven |

### 0.2 Implementation Order

1. ACL control plane visible in Neutron.
2. Legacy CLI and `port-show` observability.
3. `neutron-aria-agent` inventory/effective-policy/status loop.
4. `aria-agent` UDS snapshot/status/delete API.
5. ACL datapath enforcement.
6. Aria QoS facade, native Neutron QoS enablement, and Aria execution.
7. Aria Mirror second-phase productization.
8. Kolla packaging, smoke, rollout, rollback.

### 0.3 Commit Discipline

- Commit after each task group that passes tests.
- Keep ACL, Aria QoS facade, native QoS enablement, and Aria Mirror commits separate.
- Keep server-side Neutron plugin, Legacy CLI, Python agent, Rust UDS API, datapath, and deployment packaging separable.

---

## 1. File And Package Layout

### 1.1 New OpenStack Python Package

Create a product package under the repository so it can later be copied into the `neutron-server` and `neutron-aria-agent` images.

```text
openstack/neutron_aria/
  setup.py
  requirements.txt
  neutron_aria/
    __init__.py
    extensions/
      __init__.py
      aria_acl.py
      aria_qos.py
    services/
      __init__.py
      aria_acl/
        __init__.py
        constants.py
        exceptions.py
        validators.py
        plugin.py
      aria_qos/
        __init__.py
        constants.py
        exceptions.py
        validators.py
        plugin.py
    db/
      __init__.py
      aria_acl/
        __init__.py
        models.py
        api.py
        migration/
          __init__.py
          versions/
            8b9c2d1e4f60_add_aria_acl_tables.py
      aria_qos/
        __init__.py
        models.py
        api.py
        migration/
          __init__.py
          versions/
            <rev>_add_aria_qos_status_tables.py
    rpc/
      __init__.py
      aria_acl.py
    agent/
      __init__.py
      config.py
      main.py
      ovsdb.py
      neutron_client.py
      inventory.py
      effective_acl.py
      effective_qos.py
      uds_client.py
      status_reporter.py
      event_loop.py
    tests/
      unit/
        test_aria_acl_plugin.py
        test_aria_acl_validators.py
        test_aria_qos_facade.py
        test_aria_qos_status.py
        test_port_extension_fields.py
        test_agent_inventory.py
        test_effective_acl.py
        test_effective_qos.py
```

### 1.2 New Legacy Neutronclient Extension Package

Create a client extension package that can be installed into the `openstack_client` / toolbox environment.

```text
openstack/neutronclient_aria/
  setup.py
  neutronclient_aria/
    __init__.py
    v2_0/
      __init__.py
      aria_acl_policy.py
      aria_acl_rule.py
      aria_acl_address_set.py
      aria_acl_binding.py
      aria_acl_status.py
      aria_qos_policy.py
      aria_qos_rule.py
      aria_qos_binding.py
      aria_qos_status.py
    tests/
      test_policy_cli.py
      test_rule_cli.py
      test_binding_cli.py
      test_status_cli.py
      test_aria_qos_cli.py
```

### 1.3 Rust API And Agent Additions

Modify existing Rust packages without renaming the `aria-agent` binary.

```text
api/src/lib.rs
api/src/neutron.rs

agent/src/api_handlers/mod.rs
agent/src/api_handlers/neutron.rs
agent/src/api_routes.rs
agent/src/main.rs
agent/src/neutron_socket.rs

core/src/lib.rs
core/src/neutron_snapshot.rs
core/src/neutron_apply.rs
core/src/neutron_status.rs
core/src/state.rs
core/src/wal.rs
core/src/qos_ops.rs

config/aria-agent.toml
```

### 1.4 Deployment And Smoke Assets

```text
deploy/kolla/neutron-server/Dockerfile
deploy/kolla/neutron-aria-agent/Dockerfile
deploy/kolla/aria-agent/Dockerfile
deploy/kolla/config/neutron-aria-agent.ini
deploy/kolla/config/aria-agent-openstack.toml
deploy/kolla/smoke/acl_control_plane_smoke.sh
deploy/kolla/smoke/acl_datapath_smoke.sh
deploy/kolla/smoke/qos_smoke.sh
deploy/kolla/smoke/rollback_smoke.sh
```

---

## 2. Chapter One: Neutron Server ACL Control Plane

### 2.1 Extension Descriptor

**Files:**
- Create: `openstack/neutron_aria/neutron_aria/extensions/aria_acl.py`
- Test: `openstack/neutron_aria/neutron_aria/tests/unit/test_aria_acl_plugin.py`

- [ ] Define extension alias `aria-acl`, name `Aria ACL`, and description `Aria ACL enhancement extension`.
- [ ] Define API resources:
  - `/v2.0/aria-acl-policies`
  - `/v2.0/aria-acl-rules`
  - `/v2.0/aria-acl-address-sets`
  - `/v2.0/aria-acl-bindings`
- [ ] Define extended port attributes:
  - `aria_acl_enabled`
  - `aria_acl_effective_policy_id`
  - `aria_acl_effective_policy_name`
  - `aria_acl_effective_source`
  - `aria_acl_binding_id`
  - `aria_acl_effective_revision`
  - `aria_acl_runtime_status`
  - `aria_acl_runtime_host`
  - `aria_acl_runtime_reason`
- [ ] Set all `aria_acl_*` port attributes to `allow_post=False`, `allow_put=False`, `is_visible=True`.
- [ ] Use the style of onsite `/usr/lib/python2.7/site-packages/neutron/extensions/qos.py`, not modern Python 3-only neutron-lib patterns.

**Expected visible result:**

```bash
neutron ext-show aria-acl
```

Expected: extension exists with alias `aria-acl`.

### 2.2 DB Models And Migration

**Files:**
- Create: `openstack/neutron_aria/neutron_aria/db/aria_acl/models.py`
- Create: `openstack/neutron_aria/neutron_aria/db/aria_acl/api.py`
- Create: `openstack/neutron_aria/neutron_aria/db/aria_acl/migration/versions/8b9c2d1e4f60_add_aria_acl_tables.py`
- Test: `openstack/neutron_aria/neutron_aria/tests/unit/test_aria_acl_plugin.py`

- [ ] Add `aria_acl_policies`.
- [ ] Add `aria_acl_rules`.
- [ ] Add `aria_acl_address_sets`.
- [ ] Add `aria_acl_address_set_members`.
- [ ] Add `aria_acl_bindings`.
- [ ] Add `aria_acl_rbac`.
- [ ] Add `aria_acl_port_statuses`.
- [ ] Add indexes for `project_id`, `policy_id`, `target_type/target_id`, `host`, `network_id`, `runtime_status`.
- [ ] Enforce one enabled binding per target in plugin logic if MySQL/alembic branch cannot support partial unique index.
- [ ] Ensure migration works with current two heads observed onsite: `4af11ca47297` and `2948f8b16a0c`.

**Verification command:**

```bash
docker exec neutron_server neutron-db-manage upgrade heads
docker exec neutron_server neutron-db-manage current
```

Expected: migration succeeds and current heads are still valid.

### 2.3 Service Plugin CRUD

**Files:**
- Create: `openstack/neutron_aria/neutron_aria/services/aria_acl/plugin.py`
- Create: `openstack/neutron_aria/neutron_aria/services/aria_acl/validators.py`
- Create: `openstack/neutron_aria/neutron_aria/services/aria_acl/exceptions.py`
- Test: `openstack/neutron_aria/neutron_aria/tests/unit/test_aria_acl_plugin.py`

- [ ] Implement `create_aria_acl_policy`, `get_aria_acl_policy`, `get_aria_acl_policies`, `update_aria_acl_policy`, `delete_aria_acl_policy`.
- [ ] Implement `create_aria_acl_rule`, `get_aria_acl_rule`, `get_aria_acl_rules`, `update_aria_acl_rule`, `delete_aria_acl_rule`.
- [ ] Implement `create_aria_acl_address_set`, member add/remove, show/list/delete.
- [ ] Implement `create_aria_acl_binding`, `get_aria_acl_binding`, `get_aria_acl_bindings`, `update_aria_acl_binding`, `delete_aria_acl_binding`.
- [ ] Reject binding to nonexistent Neutron port/network.
- [ ] Reject enabled binding conflict for the same `(target_type, target_id)`.
- [ ] Reject rule priority collision within `(policy_id, direction)`.
- [ ] Reject invalid CIDR/IP version combinations.
- [ ] Reject port-range rules without TCP/UDP protocol.
- [ ] Keep `tenant_id` compatibility while normalizing internal names to `project_id`.

**Expected visible result:**

```bash
neutron aria-acl-policy-create --name web-db-acl --default-action allow
neutron aria-acl-rule-create --policy web-db-acl --direction egress --priority 100 --action deny --protocol tcp --dst-port 3306
neutron aria-acl-binding-create --policy web-db-acl --port $PORT_ID
```

Expected: all commands create Neutron DB objects without touching Security Group tables.

### 2.4 Port Response Extension

**Files:**
- Modify: `openstack/neutron_aria/neutron_aria/services/aria_acl/plugin.py`
- Modify: `openstack/neutron_aria/neutron_aria/db/aria_acl/api.py`
- Test: `openstack/neutron_aria/neutron_aria/tests/unit/test_port_extension_fields.py`

- [ ] Fill `aria_acl_enabled` based on port-level or network-level enabled binding.
- [ ] Fill `aria_acl_effective_policy_id`, `aria_acl_effective_policy_name`, `aria_acl_effective_source`, and `aria_acl_binding_id`.
- [ ] Fill `aria_acl_runtime_status`, `aria_acl_runtime_host`, and `aria_acl_runtime_reason` from `aria_acl_port_statuses`.
- [ ] For `get_ports`, batch-load bindings/status rows to avoid N+1 queries.
- [ ] If runtime status `updated_at` is stale compared with agent heartbeat, return `unknown` or `stale` behavior defined by the plugin.
- [ ] Ensure `port-create` and `port-update` reject attempts to set `aria_acl_*` fields.

**Expected visible result:**

```bash
neutron port-show $PORT_ID
```

Expected output includes:

```text
aria_acl_enabled
aria_acl_effective_policy_id
aria_acl_effective_source
aria_acl_runtime_status
aria_acl_runtime_reason
```

### 2.5 RPC / Notification

**Files:**
- Create: `openstack/neutron_aria/neutron_aria/rpc/aria_acl.py`
- Modify: `openstack/neutron_aria/neutron_aria/services/aria_acl/plugin.py`
- Test: `openstack/neutron_aria/neutron_aria/tests/unit/test_aria_acl_plugin.py`

- [ ] Emit notifications for policy create/update/delete.
- [ ] Emit notifications for rule create/update/delete.
- [ ] Emit notifications for address set create/update/delete.
- [ ] Emit notifications for binding create/update/delete.
- [ ] Include `event_type`, `resource_id`, `policy_id`, `project_id`, `revision_number`, and affected targets.
- [ ] Ensure agents can ignore stale revisions.
- [ ] Provide a full-resync query path for agents to recover from missing events.

**Expected visible result:**

Agent logs show coalesced dirty policy/target events, followed by per-port recompute.

### 2.6 RBAC And Policy Rules

**Files:**
- Create: `openstack/neutron_aria/neutron_aria/policies/aria_acl.py`
- Modify: `deploy/kolla/config/policy.yaml`

- [ ] First release is admin-only for create/update/delete.
- [ ] Optional read-only project user access can be added later, but do not enable tenant writes in first release.
- [ ] Add explicit policy rule names:
  - `create_aria_acl_policy`
  - `update_aria_acl_policy`
  - `delete_aria_acl_policy`
  - `get_aria_acl_policy`
  - `create_aria_acl_rule`
  - `create_aria_acl_binding`
  - `delete_aria_acl_binding`

**Expected visible result:**

Non-admin request to create ACL object fails with a Neutron authorization error; admin request succeeds.

---

## 3. Chapter Two: Legacy `neutron` CLI

### 3.1 CLI Resource Commands

**Files:**
- Create: `openstack/neutronclient_aria/neutronclient_aria/v2_0/aria_acl_policy.py`
- Create: `openstack/neutronclient_aria/neutronclient_aria/v2_0/aria_acl_rule.py`
- Create: `openstack/neutronclient_aria/neutronclient_aria/v2_0/aria_acl_address_set.py`
- Create: `openstack/neutronclient_aria/neutronclient_aria/v2_0/aria_acl_binding.py`
- Create: `openstack/neutronclient_aria/neutronclient_aria/v2_0/aria_acl_status.py`

- [ ] Implement `neutron aria-acl-policy-list/show/create/update/delete`.
- [ ] Implement `neutron aria-acl-rule-list/show/create/update/delete`.
- [ ] Implement `neutron aria-acl-address-set-list/show/create/member-add/member-remove/delete`.
- [ ] Implement `neutron aria-acl-binding-list/show/create/update/delete`.
- [ ] Implement `neutron aria-acl-effective-show --port $PORT_ID`.
- [ ] Implement `neutron aria-acl-port-status-show $PORT_ID`.
- [ ] Support UUID input for all commands.
- [ ] Support name resolution for policy/address-set as convenience, while never requiring names to be unique across projects without project scope.
- [ ] Support `--tenant-id` and `--project-id`; normalize to `project_id`.

**Expected visible result:**

```bash
neutron aria-acl-policy-list
neutron aria-acl-binding-list --port $PORT_ID
neutron aria-acl-port-status-show $PORT_ID
```

### 3.2 CLI Packaging

**Files:**
- Create: `openstack/neutronclient_aria/setup.py`
- Create: `openstack/neutronclient_aria/neutronclient_aria/__init__.py`

- [ ] Register commands through the legacy neutronclient entrypoint style supported by onsite `neutronclient 2016.9.9`.
- [ ] Test inside a Python 2 environment.
- [ ] Package into the product `openstack_client` image or toolbox image.

**Verification command:**

```bash
docker exec openstack_client neutron help | grep aria-acl
```

Expected: all `aria-acl-*` command families are listed.

---

## 4. Chapter Three: `neutron-aria-agent`

### 4.1 Agent Skeleton And Config

**Files:**
- Create: `openstack/neutron_aria/setup.py`
- Create: `openstack/neutron_aria/neutron_aria/agent/main.py`
- Create: `openstack/neutron_aria/neutron_aria/agent/config.py`
- Create: `deploy/kolla/config/neutron-aria-agent.ini`

- [x] Add Python package skeleton for `neutron_aria`.
- [x] Add stdlib-only config loader and Kolla-style sample config.
- [ ] Add oslo config wiring compatible with current Python 2 Neutron environment.
- [x] Read `host`, OVS bridge name, UDS socket path, managed domains, timeout, and resync interval from the stdlib config skeleton.
- [ ] Read RabbitMQ credentials and Neutron service credentials from the product OpenStack config.
- [ ] Register as Neutron agent type `Aria ACL agent`.
- [ ] Heartbeat to Neutron agent table.
- [x] Provide process logs with host, generation, dirty target count, and status update count.

**Expected visible result:**

```bash
neutron agent-list | grep aria
```

Expected: `neutron-aria-agent` shows alive on each enabled compute.

### 4.2 Inventory And Port Filtering

**Files:**
- Create: `openstack/neutron_aria/neutron_aria/agent/inventory.py`
- Create: `openstack/neutron_aria/neutron_aria/agent/ovsdb.py`
- Create: `openstack/neutron_aria/neutron_aria/agent/neutron_client.py`
- Test: `openstack/neutron_aria/neutron_aria/tests/unit/test_agent_inventory.py`

- [x] Add Neutron client wrapper for full-resync port pull where `binding:host_id == local_host`.
- [x] Support legacy Neutron pagination through `ports_links rel=next` and marker.
- [x] Query OVSDB interfaces through `ovs-vsctl --format=json`.
- [x] Query target bridge membership through `ovs-vsctl list-ports br-int`.
- [x] Build `port_id -> tap_name -> ifindex` by matching OVS `external_ids:iface-id`.
- [x] Mark eligible VM ports only when:
  - `binding:vif_type == ovs`
  - `binding:vnic_type in ["normal", "", None]`
  - `device_owner` is empty or starts with `compute:`
  - local tap exists
  - local tap is a member of the configured OVS bridge, default `br-int`
- [x] Mark `network:dhcp`, SR-IOV/direct, missing tap, and non-OVS types as ineligible with explicit reason.
- [x] Add OVS bridge membership validation for direct `br-int` tap ports.
- [ ] Add router, metadata, LinuxBridge, and unknown-port regression fixtures from the target environment.

**Expected visible result:**

`neutron aria-acl-port-status-show $DHCP_PORT_ID` returns `not_applicable`.

### 4.3 Effective ACL Computation

**Files:**
- Create: `openstack/neutron_aria/neutron_aria/agent/effective_acl.py`
- Test: `openstack/neutron_aria/neutron_aria/tests/unit/test_effective_acl.py`

- [x] Resolve port-level binding first.
- [x] Resolve network-level binding second.
- [x] Return no ACL for unsupported/not_applicable ports.
- [x] Expand address-set members into snapshot-ready structures.
- [x] Sort rules by direction and ascending priority.
- [x] Compute `effective_revision` from policy/rules/address-sets/binding revisions.
- [x] Emit `not_requested + bypass` when no binding exists.

**Expected visible result:**

```bash
neutron aria-acl-effective-show --port $PORT_ID
```

Expected: shows source `port`, `network`, or `none`.

### 4.4 UDS Client And Snapshot Submission

**Files:**
- Create: `openstack/neutron_aria/neutron_aria/agent/uds_client.py`
- Create: `openstack/neutron_aria/neutron_aria/agent/event_loop.py`

- [x] Call `GET /api/v1/neutron/capabilities`.
- [x] Validate schema version, attach authority, full snapshot support, port delete support, response body size, timeout, and required domains.
- [x] Submit `PUT /api/v1/neutron/snapshot`.
- [x] Delete local runtime with `DELETE /api/v1/neutron/ports/{port_id}` when a port migrates away or is deleted.
- [x] Add a `SnapshotSynchronizer.full_resync()` skeleton that performs capabilities -> inventory -> snapshot -> UDS submit.
- [x] Add `safe_full_resync()` and an `AgentRuntimeStatus` model that turns UDS/local API failures into `local_api_degraded` instead of crashing the loop.
- [x] Wire `AgentRuntimeStatus.heartbeat_payload()` into the real Neutron agent heartbeat path.
- [x] Add a long-running service launcher with periodic Neutron heartbeat.
- [x] Add retry/backoff before full-resync service mode is enabled.
- [ ] Add event merge and real RPC event wiring before full-resync service mode is enabled by default.

**Expected visible result:**

Agent logs show snapshot accepted with generation number.

**Implementation checkpoint, 2026-06-24:**

The first Python-side stdlib skeleton is implemented and covered by unit tests. It does not yet register a Neutron agent heartbeat or consume Neutron RPC notifications. It is sufficient to validate the local contract boundary: legacy Neutron port dictionaries plus OVS `external_ids:iface-id` are translated into the Rust `NeutronSnapshotRequest` shape and submitted over `/run/aria/aria-agent.sock`.

**Implementation checkpoint, 2026-06-24 update:**

The Python-side product boundary no longer relies on the smoke CLI path. `neutron_client.NeutronPortSource` models the full-resync input as an injected legacy `python-neutronclient` object and supports paginated `list_ports(binding:host_id=...)` calls. `ovsdb.OvsdbInterfaceReader` now validates target bridge membership through `ovs-vsctl list-ports br-int`, and `inventory.PortInventoryBuilder` only marks a port eligible when the tap is both matched by `external_ids:iface-id` and present on the configured bridge. UDS failures now produce a degraded status dictionary through `safe_full_resync()`; the remaining product task is to publish that payload through the real Neutron agent heartbeat/status channel.

**Implementation checkpoint, 2026-06-24 heartbeat update:**

`AgentRuntimeStatus.heartbeat_payload()` is now connected to the Python-side Neutron report-state boundary through `neutron_aria.agent.status_reporter.NeutronStatusReporter`. The reporter converts Aria runtime status into the legacy Neutron agent-state shape:

```python
{
    "binary": "neutron-aria-agent",
    "host": "<compute-host>",
    "topic": "N/A",
    "agent_type": "Aria ACL agent",
    "configurations": {
        "ready": true,
        "degraded": false,
        "reason": "ready",
        "last_generation": 12,
        "last_snapshot_ports": 5,
        "last_managed_ports": 2,
        "managed_domains": ["acl"],
        "ovs_bridge": "br-int",
        "socket_path": "/run/aria/aria-agent.sock"
    },
    "start_flag": true
}
```

`SnapshotSynchronizer` now reports heartbeat after successful full resync and after degraded safe resync. This means a live `neutron-aria-agent` can publish `ready` or `local_api_degraded` into Neutron's normal agent heartbeat path, while `neutron agent-list` derives `alive` from the standard heartbeat timestamp. Heartbeat/RabbitMQ failure is reported as a bounded heartbeat error and does not hide the snapshot result.

This is a `neutron-aria-agent` Python change. It does not require modifying Neutron Server or Rust `aria-agent`. The remaining work before full-resync daemon delivery is retry/backoff, event merge, and real oslo/neutron RPC event wiring.

**Implementation checkpoint, 2026-06-24 service launcher update:**

`neutron_aria.agent.service.AgentService` now provides a long-running loop with two independent intervals:

- `report_interval`: periodically publishes Neutron heartbeat through `PluginReportStateAPI.report_state()`.
- `resync_interval`: periodically runs `SnapshotSynchronizer.safe_full_resync()` when full resync is explicitly enabled.

The default product-safe startup mode is heartbeat-only:

```ini
[agent]
host = compute-1.example.test
managed_domains = acl
report_interval = 30
resync_interval = 60
full_resync_enabled = false
```

In heartbeat-only mode the agent reports:

```text
agent_type = Aria ACL agent
binary = neutron-aria-agent
alive = derived by Neutron heartbeat timestamp
configurations.reason = full_resync_disabled
configurations.degraded = true
```

This lets `neutron agent-list` show the Aria agent as alive without submitting an empty snapshot or touching any tap datapath. Full snapshot submission remains gated behind `full_resync_enabled=true` or CLI `--enable-full-resync`, and must not be enabled in production until the real Neutron port source/RPC event path and retry/backoff are complete.

The Python agent now emits process logs through stdlib `logging`, which the Kolla launcher writes to `/var/log/kolla/neutron/neutron-aria-agent.log`. The log includes:

- `agent_start` with host, managed domains, full-resync flag, RPC event flag, port source, OVS bridge, and UDS socket path.
- `heartbeat_reported` with ready/degraded status, reason, generation, snapshot port count, and managed port count.
- `full_resync_complete` and `full_resync_degraded` with generation or degraded reason.
- `event_batch_drained` and `service_result` with merged port update/delete/network counts, full-resync flag, overflow flag, and heartbeat result.
- `delete_port_complete` with the local projected-port count after cleanup.

CLI entry point:

```bash
neutron-aria-agent \
  --config-file /etc/neutron-aria-agent/neutron-aria-agent.ini \
  --neutron-config-file /etc/neutron/neutron.conf \
  --heartbeat-only
```

The host value must match the existing Neutron agent host convention, for example `compute-1.example.test`, not merely `compute-1`.

**Real environment heartbeat-only service smoke, 2026-06-24:**

- Git commit: `b0476f1`.
- GitHub Actions run: `28085654256`, result `success`.
- Deployment shape used for smoke:
  - Source copied temporarily into each host's `neutron_openvswitch_agent` container under `/tmp/neutron_aria_agent_src`.
  - Process launched with container Python 2.7 and `PYTHONPATH=/tmp/neutron_aria_agent_src`.
  - Neutron runtime initialized with:
    - `/etc/neutron/neutron.conf`
    - `/etc/neutron/plugins/ml2/openvswitch_agent.ini`
  - `--heartbeat-only` used, so no snapshot was submitted and no tap datapath was touched.
- Host values:
  - `compute-1.example.test`
  - `compute-2.example.test`
  - `compute-3.example.test`
- Observed `neutron agent-list` result:

```text
Aria ACL agent | compute-1.example.test | :-) | True | neutron-aria-agent
Aria ACL agent | compute-2.example.test | :-) | True | neutron-aria-agent
Aria ACL agent | compute-3.example.test | :-) | True | neutron-aria-agent
```

- Observed `neutron agent-show` configuration on `compute-1.example.test`:

```json
{
  "ready": false,
  "degraded": true,
  "reason": "full_resync_disabled",
  "last_error": "full resync is disabled; heartbeat-only service mode",
  "last_generation": 0,
  "last_snapshot_ports": 0,
  "last_managed_ports": 0,
  "managed_domains": ["acl"],
  "ovs_bridge": "br-int",
  "socket_path": "/run/aria/aria-agent.sock"
}
```

This proves the `neutron-aria-agent` heartbeat path is compatible with the onsite legacy Neutron RPC stack. The smoke deployment is temporary and container-local; it is not persistent across container rebuild/restart. Product delivery still needs a Kolla service definition or image layer.

**Implementation checkpoint, 2026-06-24 Kolla/full-resync safety update:**

The `neutron-aria-agent` now has a product packaging skeleton and safer full-resync gate:

- `deploy/kolla/neutron-aria-agent/Dockerfile` builds an image from the existing Neutron agent base image and installs the Python 2 compatible `neutron_aria` package.
- `deploy/kolla/neutron-aria-agent/config.json` follows the onsite Kolla config-file pattern observed in `neutron_openvswitch_agent`.
- `deploy/kolla/neutron-aria-agent/start-neutron-aria-agent.sh` is the product launcher and writes stdout/stderr to `/var/log/kolla/neutron/neutron-aria-agent.log`.
- `deploy/kolla/config/neutron-aria-agent.ini` now defaults to heartbeat-only:
  - `full_resync_enabled = false`
  - `[neutron] port_source = disabled`
- `deploy/kolla/smoke/neutron_aria_heartbeat_smoke.sh` validates that all expected hosts show an alive `Aria ACL agent`.
- `deploy/kolla/smoke/neutron_aria_container_smoke.sh` builds and starts an independent `neutron_aria_agent` container from the onsite OVS agent image family for heartbeat-only service smoke.
- `deploy/kolla/smoke/neutron_aria_full_resync_smoke.sh` validates `/run/aria`, UDS capabilities, OVSDB access, neutronclient credentials, one full snapshot, and UDS rollback.
- Full resync no longer falls back to an empty static port list. If full resync is enabled without `[neutron] port_source = neutronclient` and OS_* credentials, the agent reports degraded and does not submit an empty snapshot.
- `AgentService` uses exponential backoff for degraded full-resync attempts:
  - `resync_backoff_initial`
  - `resync_backoff_max`
  - success resets backoff to the normal `resync_interval`.

**Implementation checkpoint, 2026-06-24 independent Kolla container smoke:**

- Built `neutron-aria-agent:smoke-e68e1aa` from the onsite OVS agent image family on the target compute hosts.
- Started an independent `neutron_aria_agent` container on `compute-1.example.test`, `compute-2.example.test`, and `compute-3.example.test`.
- Stopped the previous temporary embedded `neutron-aria-agent` process inside `neutron_openvswitch_agent` on all three hosts.
- Verified `/var/log/kolla/neutron/neutron-aria-agent.log` contains `agent_start`, `service_initialize`, `heartbeat_reported`, and `service_result`.
- Verified `neutron agent-list` shows alive `Aria ACL agent` entries for all three hosts.
- Kept the smoke in heartbeat-only mode:
  - `full_resync_enabled = false`
  - `port_source = disabled`
  - `rpc_events_enabled = false`
- Full resync, RPC event consumption, UDS snapshot submission, and tap datapath writes are still intentionally disabled.

**Implementation checkpoint, 2026-06-24 full-resync smoke gate:**

- Host: `compute-1.example.test`.
- Started temporary Rust `aria-agent` in `neutron_managed` mode with `auto_attach=false` and UDS at `/run/aria/aria-agent.sock`.
- Restarted `neutron_aria_agent` with `/run/aria` mounted.
- Rebuilt the smoke image so the container process runs as root. This was required because the target OVSDB socket is `root:root 0750`; the `neutron` user cannot run `ovs-vsctl br-exists br-int`.
- UDS capabilities passed for `api_version=v1`, `attach_authority=neutron_snapshot`, `supports_full_snapshot=true`, `supports_port_delete=true`, and `acl` domain support.
- Legacy neutronclient listed 5 local ports for `compute-1.example.test`, including 2 compute ports.
- One `neutron-aria-agent --once --enable-full-resync` submitted a snapshot and UDS status showed 2 managed ACL ports:
  - `86b83885-671f-474c-9556-8af98cf1cdc8` -> `tap86b83885-67`, ifindex `26`.
  - `e607e86b-9e5f-4c63-a5df-3dc8986a1b0f` -> `tape607e86b-9e`, ifindex `27`.
- Rollback deleted both ports through `DELETE /api/v1/neutron/ports/{port_id}`.
- Final UDS status returned `active_instances=[]` and `managed_ports=[]`; `ip -d link show` showed no XDP attachment left on the two tap ports.
- Long-running `neutron_aria_agent` remains heartbeat-only by default. RPC event consumption remains disabled.

**Product deployment boundary correction, 2026-06-24:**

The full-resync smoke above intentionally used a temporary root/OVSDB path to
prove the old snapshot mechanics. That is not the final product shape.

Final product container boundary:

- `aria-datapath`: independent Kolla container, privileged or granted the
  required datapath capabilities. It owns eBPF load/attach, map writes, tap
  access, OVS/tap identity validation, `/sys/fs/bpf`, `/run/openvswitch`,
  `/var/lib/aria-agent`, and `/run/aria/aria-agent.sock`.
- `neutron-aria-agent`: independent Kolla container, non-privileged, runs as
  the image's `neutron` user, does not mount `/run/openvswitch`, `/sys/fs/bpf`,
  or `/lib/modules`, and only talks to `aria-datapath` through
  `/run/aria/aria-agent.sock`.

Required follow-up before production full-resync:

- [x] Change the Python snapshot builder from authoritative OVSDB inventory to
  Neutron logical candidate projection.
- [x] Extend the Rust UDS snapshot contract so `aria-datapath` validates
  `br-int` membership, OVS `external_ids:iface-id`, tap existence, ifindex,
  and supported/unsupported reasons locally.
- [x] Move current `OvsdbInterfaceReader` usage out of the product path. Keep it
  only in legacy smoke/tests until the new UDS contract is verified.
- [x] Add a non-privileged container smoke asserting `neutron_aria_agent` is not
  privileged, runs as `neutron`, has `/run/aria` mounted, and has no
  `/run/openvswitch` mount.
- [x] Add an `aria-datapath` Kolla container smoke that proves UDS readiness,
  container boundary, `auto_attach=false` baseline, and local OVS/tap
  validation with a non-existent compute OVS port candidate.
- [ ] Extend the `aria-datapath` smoke with real eligible VM tap attach and
  cleanup once a dedicated test VM port is assigned.

The implemented full-resync source is legacy `python-neutronclient` with OS_* credentials. This is adequate for the first Kolla service smoke and controlled lab testing. The RPC event path is intentionally not hard-coded yet; it must be matched against the onsite Neutron source or `/usr/lib/python2.7/site-packages/neutron` callback/topic implementation before enabling event merge in production.

**Real environment smoke, 2026-06-24:**

- Host: `compute-1.example.test`.
- Git commit: `f9e90ab`.
- GitHub Actions run: `28072633145`.
- Artifact: `firewall-binaries-f9e90abbe1a95b91190cb328b496b2e4fe170de8`.
- Evidence retained on the host: `/tmp/aria-smoke-f9e90ab/python-snapshot-uds-smoke.txt`.
- Discovery:
  - Neutron ports visible through `adminrc`: 8.
  - Ports bound to `compute-1` and included in snapshot: 5.
  - Eligible compute OVS tap ports: 2.
    - `86b83885-671f-474c-9556-8af98cf1cdc8` -> `tap86b83885-67`, ifindex `26`.
    - `e607e86b-9e5f-4c63-a5df-3dc8986a1b0f` -> `tape607e86b-9e`, ifindex `27`.
  - Ineligible local DHCP ports: 3, all returned `not_applicable_device_owner:network:dhcp`.
  - Remote-host ports ignored before snapshot: 3.
- UDS result:
  - `GET /api/v1/neutron/capabilities` returned `api_version=v1`, `attach_authority=neutron_snapshot`, `supports_full_snapshot=true`, and `supports_port_delete=true`.
  - `GET /api/v1/neutron/status` before snapshot returned `generation=0`, `managed_ports=[]`, and `active_instances=[]`.
  - `PUT /api/v1/neutron/snapshot` generation `2026062401` returned 3 ignored DHCP ports and 2 `attach ok` compute ports.
  - Status after snapshot returned 2 managed ports with `managed_domains=["acl"]`.
  - XDP was present on `tap86b83885-67` and `tape607e86b-9e` after attach.
  - `DELETE /api/v1/neutron/ports/{port_id}` detached both ports successfully.
  - Final cleanup left no `aria-agent` process, no smoke UDS socket, no XDP on the two tap ports, and no `/sys/fs/bpf/aria-smoke-f9e90ab` pins.
- Environment note:
  - In this product environment, `neutron` CLI is a shell function from `/root/adminrc` wrapping `docker exec openstack_client neutron`.
  - Product `neutron-aria-agent` must use Neutron client/RPC wiring, not this shell function; CLI was only used for smoke data extraction.

**RPC skeleton deployment and ACL/QoS translator checkpoint, 2026-06-24:**

- Commit `c4dbef0` was built by GitHub Actions run `28090615180` with result `success`.
- The same `neutron-aria-agent` Python code, including RPC event merge skeleton files and ACL/QoS translator modules, was temporarily deployed into the three onsite `neutron_openvswitch_agent` containers under `/tmp/neutron_aria_agent_src`.
- Runtime mode remained heartbeat-only:
  - `full_resync_enabled = false`
  - `port_source = disabled`
  - `rpc_events_enabled = false`
- Observed result: all three containers can import `neutron_aria.agent.effective_acl` and `neutron_aria.agent.effective_qos`.
- Observed result: all three hosts run `python -m neutron_aria.agent.main ... --heartbeat-only` as a temporary test process.
- Observed result: temporary test process stdout/stderr is written to `/var/log/kolla/neutron/neutron-aria-agent.log`.
- Observed result: `neutron agent-list` shows alive `Aria ACL agent` entries for `compute-1.example.test`, `compute-2.example.test`, and `compute-3.example.test`.
- Boundary: this proves package layout and heartbeat compatibility with the target legacy Neutron runtime. It does not enable RPC event consumption, full-resync, snapshot submission, or datapath apply.
- `effective_acl.py` now computes per-port effective Aria ACL from product ACL policies, rules, address sets, and port/network bindings.
- `effective_qos.py` now computes per-port Aria QoS from native Neutron QoS policy semantics, with port policy taking precedence over network policy.
- `inventory.PortInventoryBuilder` can embed optional `acl` and `qos` extension payloads into each snapshot port when the corresponding indexes are provided.
- Remaining boundary: Neutron Server API/DB/CLI for `aria-acl` and the product `aria-qos` facade still require the target legacy Neutron source tree. Rust `aria-agent` also still needs the ACL/QoS snapshot DTO and apply path before these translator results can affect eBPF maps.

### 4.5 Runtime Status Reporting

**Files:**
- Create: `openstack/neutron_aria/neutron_aria/agent/status_reporter.py`
- Modify: `openstack/neutron_aria/neutron_aria/services/aria_acl/plugin.py`

- [ ] Report per-port `runtime_status`.
- [ ] Report `support_disposition`.
- [ ] Report `effective_action`.
- [ ] Report `runtime_host`, `tap_name`, `ifindex`, `reason`, and `last_applied_at`.
- [ ] Write to `aria_acl_port_statuses`.
- [ ] Ensure stale status becomes visible as `unknown` or `stale`.

**Expected visible result:**

```bash
neutron port-show $PORT_ID | grep aria_acl_runtime_status
```

---

## 5. Chapter Four: `aria-agent` UDS Snapshot Runtime

### 5.0 Startup Modes And Auto-Attach Boundary

**Files:**
- Modify: `agent/src/main.rs`
- Modify: `agent/src/netlink.rs`
- Modify: `agent/src/tap_registry.rs`
- Modify: `deploy/kolla/config/aria-agent.toml`
- Test: `agent` startup/config unit tests

- [ ] Add explicit startup mode:
  - `standalone`
  - `neutron_managed`
- [ ] Keep existing `iface_pattern` auto-discovery behavior only for `standalone` mode.
- [ ] In `neutron_managed` mode, default `auto_attach=false`.
- [ ] In product Kolla config, run aria-agent in `neutron_managed` mode.
- [ ] In `neutron_managed` mode, do not scan and attach existing interfaces from `iface_pattern`.
- [ ] In `neutron_managed` mode, do not attach new netlink-discovered interfaces from `iface_pattern`.
- [ ] In `neutron_managed` mode, attach only ports present in the latest accepted Neutron snapshot.
- [ ] In `neutron_managed` mode, validate snapshot tap identity before attach:
  - Neutron `port_id`.
  - local ifname.
  - current ifindex.
  - OVS `external_ids:iface-id`.
  - supported port disposition.
- [ ] In `neutron_managed` mode, snapshot deletion or empty snapshot must detach runtime for removed ports.
- [ ] Allow an explicit lab-only override such as `auto_attach=true` only outside the product default; it must be visible in logs and status.

**Verification command:**

```bash
cargo test -p aria-agent startup_mode
```

**Expected visible result:**

Starting product-mode `aria-agent` on a host with existing `tap*` interfaces but no Neutron snapshot leaves all tap interfaces unattached. After `neutron-aria-agent` submits a snapshot for one eligible OVS VM tap, only that tap gets Aria runtime; DHCP/service/SR-IOV/LinuxBridge/unknown ports remain untouched and are reported through status instead of auto-attached.

**Implementation checkpoint, 2026-06-24:**

The Rust-side startup boundary and Neutron attach authority are implemented and smoke tested on `compute-1.example.test` with CI artifact `7d9e38d`. In `neutron_managed` mode, `aria-agent` no longer auto-attaches every `tap*`; attach/detach authority is driven by the Neutron UDS snapshot. This checkpoint intentionally does not mean ACL/QoS/Mirror northbound business APIs are complete.

### 5.1 Snapshot DTO

**Files:**
- Modify: `api/src/lib.rs`
- Modify: `agent/src/neutron_api.rs`

- [x] Define stable base UDS constants:
  - `NEUTRON_UDS_API_VERSION = v1`.
  - `NEUTRON_ATTACH_AUTHORITY = neutron_snapshot`.
  - `NEUTRON_SUPPORTED_DOMAINS = attach, acl, qos, mirror, config, conntrack, tcprt, trace, drops, ssl`.
- [x] Define `NeutronSnapshotRequest`.
- [x] Define `NeutronPortSnapshot`.
- [x] Define `ManagedNeutronPort`.
- [x] Define `NeutronCapabilitiesResponse`.
- [x] Define `NeutronStatusResponse`.
- [x] Define `NeutronSnapshotResponse`.
- [x] Define `NeutronDeleteResponse`.
- [x] Define `NeutronPortApplyResult`.
- [x] Derive `Serialize`, `Deserialize`, and `utoipa::ToSchema` for the UDS contract DTOs.
- [x] Move agent UDS handler code to reuse `aria-api` DTOs instead of keeping private duplicate structs.
- [x] Add serde contract tests for:
  - capabilities version, attach authority, and supported domain list.
  - snapshot round-trip with `managed_domains`.
  - backward-compatible default values for minimal snapshot JSON.
- [ ] Define `NeutronAclPolicySnapshot`.
- [ ] Define `NeutronQosPolicySnapshot`.
- [ ] Define `NeutronMirrorSnapshot`.
- [ ] Define `NeutronDomainStatus`.
- [ ] Define enums for `RuntimeStatus`, `SupportDisposition`, and `EffectiveAction`.

**Verification command:**

```bash
cargo test -p aria-api neutron_contract
```

Expected: base UDS DTO serde tests pass. This verifies the Rust UDS contract shape before any full ACL/QoS/Mirror business snapshot is implemented.

### 5.2 Unix Socket Router

**Files:**
- Modify: `agent/src/neutron_api.rs`
- Modify: `agent/src/main.rs`
- Later split target: `agent/src/api_handlers/neutron.rs`
- Later split target: `agent/src/neutron_socket.rs`

- [x] Bind Neutron API only to Unix socket path from config, default `/run/aria/aria-agent.sock`.
- [x] Do not expose Neutron snapshot routes on TCP REST/OpenAPI listener.
- [x] Add base routes:
  - `GET /api/v1/neutron/capabilities`
  - `GET /api/v1/neutron/status`
  - `PUT /api/v1/neutron/snapshot`
  - `DELETE /api/v1/neutron/ports/{port_id}`
- [ ] Enforce socket file mode/group in startup or deployment scripts.
- [ ] Reject requests that exceed configured body size.
- [x] Add OpenAPI guard test proving Neutron UDS paths are not published by the TCP API document.

**Verification command:**

```bash
cargo test -p aria-agent neutron_snapshot_plan
cargo test -p aria-agent openapi_does_not_expose_neutron_uds_paths
```

Expected: UDS routes exist; TCP route table does not include `/api/v1/neutron/snapshot`.

### 5.3 Snapshot Apply Engine

**Files:**
- Create: `core/src/neutron_snapshot.rs`
- Create: `core/src/neutron_apply.rs`
- Create: `core/src/neutron_status.rs`
- Modify: `core/src/lib.rs`
- Modify: `core/src/wal.rs`
- Modify: `core/src/state.rs`

- [ ] Validate host and schema.
- [ ] Validate each port has current ifindex or return `PORT_IFACE_NOT_FOUND`.
- [ ] Write WAL intent before changing runtime state.
- [ ] Apply groups/address-sets.
- [ ] Apply ACL maps.
- [ ] Apply QoS maps when QoS phase is enabled.
- [ ] Commit WAL only after durable state is consistent.
- [ ] Return per-port status, never a vague global success only.
- [ ] Maintain last good generation.

**Expected visible result:**

`GET /api/v1/neutron/status` returns generation, domain statuses, and per-port status.

### 5.4 Neutron-Managed Local Write Gate

**Files:**
- Modify: `agent/src/control_plane.rs`
- Modify: `agent/src/neutron_api.rs`
- Modify: `agent/src/api_handlers/groups.rs`
- Modify: `agent/src/api_handlers/policies.rs`
- Modify: `agent/src/api_handlers/qos.rs`
- Modify: `agent/src/api_handlers/mirror.rs`
- Modify: `agent/src/api_handlers/config.rs`
- Modify: `agent/src/api_handlers/conntrack.rs`
- Modify: `agent/src/api_handlers/tcprt.rs`
- Modify: `agent/src/api_handlers/drops.rs`
- Modify: `agent/src/api_handlers/trace.rs`
- Modify: `agent/src/api_handlers/ssl.rs`
- Test: `agent` authority/gate unit tests

- [ ] Mark Neutron snapshot-attached ports with `attach_authority=neutron`.
- [ ] Add per-port `managed_domains`, supplied by `NeutronPortSnapshot.managed_domains`.
- [ ] Keep `neutron_managed` and `managed_domains` separate:
  - `neutron_managed` controls who is allowed to attach/detach VM tap runtime.
  - `managed_domains` controls which feature writes are owned by Neutron for that already-attached port.
- [ ] Do not hard-code ACL/QoS/Mirror as always Neutron-owned.
- [ ] Treat each domain independently, so product can start with only `managed_domains=["acl"]` and later add `qos` or `mirror` without changing attach semantics.
- [ ] Gate local API writes by action domain:
  - `acl`: policy add/delete/batch and ACL-owned group mutations.
  - `qos`: QoS add/delete.
  - `mirror`: mirror add/delete.
  - `config`: reject config updates that toggle a Neutron-managed domain.
  - `conntrack`, `tcprt`, `trace`, `drops`, `ssl`: default to local/admin domains unless explicitly added to `managed_domains`.
- [ ] Allow local writes for domains not listed in `managed_domains`.
- [ ] Allow read-only list/stats/health/metrics operations for Neutron-attached ports.
- [ ] For shared groups/address-sets, do not globally block all group writes when only ACL is Neutron-managed:
  - Reserve Neutron-generated object names with a stable prefix such as `neutron:`.
  - Local `ariactl` may create/update local groups for local QoS/Mirror.
  - Local `ariactl` must not delete or mutate Neutron-reserved groups, or groups referenced by Neutron-managed ACL rules.
- [ ] Reject blocked local writes with stable error code `LOCAL_WRITE_BLOCKED_FOR_NEUTRON_MANAGED_DOMAIN`.
- [ ] Include the blocked `domain` and instance in the error message.
- [ ] Add explicit break-glass mode only if product owner approves; default plan does not enable it.

**Expected visible result:**

If `managed_domains=["acl"]`, local `ariactl policy add/delete` is rejected while local `ariactl qos add/delete`, `ariactl mirror add/delete`, `ariactl tcprt`, `ariactl trace`, and drop/SSL observability operations remain allowed. If `managed_domains=["acl","qos","mirror"]`, local writes for all three product domains are rejected. Read-only stats and observability queries remain available.

**Real environment smoke, 2026-06-24:**

- Host: `compute-1.example.test`.
- Test interface: `tape607e86b-9e`.
- Neutron port: `e607e86b-9e5f-4c63-a5df-3dc8986a1b0f`.
- Artifact commit: `7d9e38d`.
- Snapshot: `managed_domains=["acl"]`.
- Result:
  - Neutron snapshot attached the target tap and status reported the port under Neutron authority.
  - Local ACL writes were rejected with `LOCAL_WRITE_BLOCKED_FOR_NEUTRON_MANAGED_DOMAIN`.
  - Local QoS writes still succeeded.
  - Local Mirror writes still succeeded.
  - Local Trace start/stop still succeeded.
  - `DELETE /api/v1/neutron/ports/{port_id}` detached runtime and cleanup left no process, UDS listener, XDP program, or bpffs pin.
- Evidence retained on the host: `/tmp/aria-domain-7d9e38d/domain-authority-smoke-2.log`.

---

## 6. Chapter Five: ACL Datapath Enforcement

### 6.1 ACL Snapshot Compiler

**Files:**
- Create: `core/src/neutron_acl.rs`
- Modify: `core/src/ebpf_ops/policy.rs`
- Modify: `core/src/ebpf_ops/runtime.rs`
- Test: Rust unit tests under corresponding modules

- [ ] Convert snapshot rules into existing policy/map structures.
- [ ] Preserve rule priority and direction.
- [ ] Support IPv4 first; IPv6 rules return unsupported until datapath support is verified.
- [ ] Support TCP/UDP port range.
- [ ] Support ICMP if existing eBPF parser supports it; otherwise mark unsupported.
- [ ] Use `default_action` only for bound policies.
- [ ] Unbound port remains `not_requested + bypass`.

### 6.2 Tap Attach And Re-Attach

**Files:**
- Modify: `core/src/ebpf_ops/attach.rs`
- Modify: `agent/src/netlink.rs`
- Modify: `agent/src/tap_registry.rs`

- [ ] Attach only when tap name and ifindex match the latest snapshot.
- [ ] Never attach from `iface_pattern` alone while in `neutron_managed` mode.
- [ ] Detect ifindex changes and require reattach.
- [ ] On VM reboot/tap recreate, keep desired state but rebuild runtime.
- [ ] On port migration away, detach and delete local port runtime.
- [ ] On agent restart, recover only snapshot-owned Neutron-managed ports, not arbitrary existing `tap*` interfaces.

**Expected visible result:**

VM hard reboot causes temporary `pending`/`unknown`, then returns to `applied` without manual intervention.

### 6.3 ACL Smoke Tests

**Files:**
- Create: `deploy/kolla/smoke/acl_datapath_smoke.sh`

- [ ] Boot two VMs on supported OVS tap ports.
- [ ] Create allow policy and prove traffic passes.
- [ ] Create deny TCP destination port rule and prove targeted traffic is blocked.
- [ ] Delete binding and prove traffic returns to baseline.
- [ ] Restart `neutron-aria-agent` and prove full resync restores status.
- [ ] Restart `aria-agent` and prove WAL/status recovery.
- [ ] Start product-mode `aria-agent` with existing non-snapshot `tap*` interfaces and prove it does not attach them.
- [ ] Submit a snapshot for exactly one eligible VM OVS tap and prove only that tap is attached.
- [ ] Reboot VM and prove tap recreate recovery.
- [ ] Verify DHCP/metadata path is not affected when no explicit VM ACL blocks it.

---

## 7. Chapter Six: Aria QoS Facade Over Neutron Native Model

Aria QoS uses a product-facing `aria-qos` name while preserving Neutron native QoS as the underlying semantic model. Do not use the onsite `qhqos` / `qcloud qos` code as the Aria QoS base: it is Floating IP / router gateway oriented and does not match ordinary VM OVS tap QoS.

### 7.1 Neutron Native QoS And Aria QoS Enablement

**Files:**
- Modify: Kolla `neutron.conf` template
- Modify: Kolla `ml2_conf.ini` template
- Create: `openstack/neutron_aria/neutron_aria/extensions/aria_qos.py`
- Create: `openstack/neutron_aria/neutron_aria/services/aria_qos/plugin.py`
- Create: `openstack/neutron_aria/neutron_aria/db/aria_qos/models.py`
- Create: `openstack/neutron_aria/neutron_aria/db/aria_qos/api.py`
- Create: `openstack/neutron_aria/neutron_aria/db/aria_qos/migration/versions/<rev>_add_aria_qos_status_tables.py`

- [ ] Add `qos` to `service_plugins` only in QoS rollout phase.
- [ ] Add `aria_qos` to `service_plugins` only after native `qos` is enabled.
- [ ] Add `qos` to `[ml2] extension_drivers`.
- [ ] Do not add `qos` to OVS agent `extensions`; keep onsite `extensions = mirror`.
- [ ] Add `aria-qos` extension alias for product-facing capability/status.
- [ ] Add `aria_qos_port_statuses`; do not add `aria_qos_policies` or `aria_qos_rules`.
- [ ] Make `aria_qos` startup fail or report disabled when native `qos` is missing.
- [ ] Keep onsite `qhqos` disabled and out of the Aria QoS path.
- [ ] Verify:

```bash
openstack extension list --network | grep qos
neutron ext-list | grep qos
neutron ext-show aria-qos
```

Expected: native `qos` and product-facing `aria-qos` are visible only after QoS phase configuration.

### 7.2 Legacy `neutron aria-qos-*` Product CLI

**Files:**
- Create: `openstack/neutronclient_aria/neutronclient_aria/v2_0/aria_qos_policy.py`
- Create: `openstack/neutronclient_aria/neutronclient_aria/v2_0/aria_qos_rule.py`
- Create: `openstack/neutronclient_aria/neutronclient_aria/v2_0/aria_qos_binding.py`
- Create: `openstack/neutronclient_aria/neutronclient_aria/v2_0/aria_qos_status.py`

- [ ] Add `neutron aria-qos-policy-create/list/show/update/delete`.
- [ ] Add `neutron aria-qos-bandwidth-limit-rule-create/list/show/update/delete`.
- [ ] Add `neutron aria-qos-port-bind --port $PORT_ID --policy $POLICY`.
- [ ] Add `neutron aria-qos-network-bind --network $NETWORK_ID --policy $POLICY`.
- [ ] Add `neutron aria-qos-status-show --port $PORT_ID`.
- [ ] Implement `aria-qos-policy-*` as a facade over native `/qos/policies`.
- [ ] Implement `aria-qos-bandwidth-limit-rule-*` as a facade over native `/qos/policies/{policy}/bandwidth_limit_rules`.
- [ ] Implement bind commands by updating native `qos_policy_id` on port/network.
- [ ] Document native `qos-*` commands as compatibility/debug entrypoints, not the product-facing path.

Expected product commands:

```bash
neutron aria-qos-policy-create web-limit
neutron aria-qos-bandwidth-limit-rule-create web-limit --max-kbps 100000
neutron aria-qos-port-bind --port $PORT_ID --policy web-limit
neutron aria-qos-status-show --port $PORT_ID
```

### 7.3 Aria QoS Translator

**Files:**
- Create: `openstack/neutron_aria/neutron_aria/agent/effective_qos.py`
- Modify: `openstack/neutron_aria/neutron_aria/agent/event_loop.py`
- Modify: `api/src/neutron.rs`
- Modify: `core/src/qos_ops.rs`

- [ ] Pull QoS policy bound to port.
- [ ] Pull QoS policy inherited from network.
- [x] Apply precedence: port-level > network-level > none.
- [x] Support bandwidth limit rule fields:
  - `max_kbps`
  - `max_burst_kbps`
  - direction when available
- [x] Mark unsupported rules as QoS domain degraded, not silently ignored.
- [x] Translate into Aria snapshot.
- [ ] Write `aria_qos_port_statuses` with runtime state, unsupported reason, effective policy, and applied generation.

### 7.4 QoS Smoke Tests

**Files:**
- Create: `deploy/kolla/smoke/qos_smoke.sh`

- [ ] Confirm `qhqos-policy-list` is not part of the Aria QoS smoke path.
- [ ] Create policy through `neutron aria-qos-policy-create`.
- [ ] Create bandwidth limit rule through `neutron aria-qos-bandwidth-limit-rule-create`.
- [ ] Bind to a VM port through `neutron aria-qos-port-bind`.
- [ ] Verify the underlying native `qos_policy_id` is set on the port.
- [ ] Verify `neutron-aria-agent` computes effective QoS.
- [ ] Verify Aria runtime status shows QoS applied.
- [ ] Verify `neutron aria-qos-status-show --port $PORT_ID`.
- [ ] Verify bandwidth limit is observable.
- [ ] Remove QoS policy and verify token bucket/map state is cleaned.
- [ ] Verify QoS failure does not change ACL status.

---

## 8. Chapter Seven: Kolla Packaging And Deployment

### 8.1 Neutron Server Image

**Files:**
- Create: `deploy/kolla/neutron-server/Dockerfile`
- Create: `deploy/kolla/config/policy.yaml`

- [ ] Install `neutron_aria` Python 2 package.
- [ ] Install DB migration files where `neutron-db-manage` can discover them.
- [ ] Add `aria_acl` service plugin registration path.
- [ ] Add `aria_qos` service plugin registration path, but enable it only in the QoS rollout phase.
- [ ] Start with ACL-only config:

```ini
[DEFAULT]
service_plugins = router,network_ip_availability,mirror,aria_acl
```

- [ ] Validate existing `router`, `network_ip_availability`, and `mirror` APIs still work.

### 8.2 Neutron-Aria-Agent Image

**Files:**
- Create: `deploy/kolla/neutron-aria-agent/Dockerfile`
- Create: `deploy/kolla/neutron-aria-agent/config.json`
- Create: `deploy/kolla/neutron-aria-agent/README.md`
- Create: `deploy/kolla/config/neutron-aria-agent.ini`
- Create: `deploy/kolla/smoke/neutron_aria_heartbeat_smoke.sh`
- Create: `deploy/kolla/smoke/neutron_aria_full_resync_smoke.sh`
- Create: `deploy/kolla/smoke/neutron_aria_boundary_smoke.sh`

- [x] Install Python 2 compatible package.
- [x] Mount Neutron config and messaging credentials.
- [x] Mount `/run/aria` for full-resync smoke.
- [x] Remove OVSDB access from the `neutron-aria-agent` product path. Current root/OVSDB access is legacy smoke only.
- [x] Move OVS/tap identity validation into `aria-datapath` UDS handling.
- [x] Ensure it does not mount `/sys/fs/bpf` and does not require eBPF privileges.
- [x] Default to heartbeat-only service mode until full-resync dependencies are present.
- [x] Provide heartbeat smoke for `neutron agent-list` and `agent-show`.
- [x] Write product logs to `/var/log/kolla/neutron/neutron-aria-agent.log`.
- [x] Run independent `neutron_aria_agent` Kolla container smoke on each compute host.
- [x] Run one-host full-resync gate smoke with UDS rollback on `compute-1.example.test`.

### 8.3 Aria-Agent Image

**Files:**
- Create: `deploy/kolla/aria-agent/Dockerfile`
- Create: `deploy/kolla/config/aria-agent-openstack.toml`
- Create: `deploy/kolla/aria-datapath/Dockerfile`
- Create: `deploy/kolla/aria-datapath/config.json`
- Create: `deploy/kolla/aria-datapath/start-aria-datapath.sh`
- Create: `deploy/kolla/aria-datapath/README.md`

- [x] Add Kolla packaging skeleton for the `aria-datapath` service.
- [x] Add non-destructive `aria-datapath` container smoke for UDS readiness,
  required mounts, and local OVS validation.
- [ ] Include existing `aria-agent` binary.
- [ ] Include eBPF artifacts.
- [ ] Mount `/sys/fs/bpf`.
- [ ] Mount `/sys/kernel/btf/vmlinux` read-only when needed.
- [ ] Mount `/run/aria`.
- [ ] Mount `/var/lib/aria-agent`.
- [ ] Mount `/run/openvswitch` or provide equivalent OVSDB access for local tap validation.
- [ ] Run as privileged initially; later narrow to CAP_NET_ADMIN, BPF, PERFMON, SYS_RESOURCE and required host namespace access where the target kernel/runtime supports it.
- [ ] Set `mode = "neutron_managed"` and `auto_attach = false`.
- [ ] Provide log path and metrics endpoint according to product standards.

### 8.4 Rollout And Rollback

**Files:**
- Create: `deploy/kolla/smoke/rollback_smoke.sh`

- [ ] Rollout step 1: deploy Neutron Server extension with `enforcement_enabled=false`.
- [ ] Rollout step 2: deploy `neutron-aria-agent` and observe full resync/status only.
- [ ] Rollout step 3: deploy `aria-agent` UDS snapshot API.
- [ ] Rollout step 4: enable ACL enforcement for selected test ports.
- [ ] Rollout step 5: enable broader ACL enforcement.
- [ ] Rollout step 6: enable native `qos` and product-facing `aria_qos` only after ACL stable.
- [ ] Rollout step 7: keep `qhqos` disabled unless a separate Floating IP / router QoS product decision requires it.
- [ ] Rollback closes `enforcement_enabled`, sends cleanup snapshots, stops `neutron-aria-agent`, removes service plugin from config, and preserves DB tables.

---

## 9. Chapter Eight: Aria Mirror Phase Two

Aria Mirror is a second-phase feature. Phase one delivers independent `aria_acl` plus Aria execution for native Neutron QoS. Phase two adds an explicit `aria_mirror` extension instead of overloading the existing `networking_mirror` API.

The reason is semantic: the current `networking_mirror` code treats `port_id` as the destination analyzer VM port and receives source traffic from `[mirror] interface` through `br-mirror`; Aria-agent mirror treats the managed source interface/tap as the clone point and sends a copy to a target ifindex. Reusing the same API would make `port_id` ambiguous.

### 9.0 2026-06-23 compute-1 Mirror Validation Baseline

This baseline was captured on the deployed product environment `compute-1.example.test` before productizing the Neutron API layer. It validates that the current Aria-agent/eBPF mirror datapath can support the second-phase `aria_mirror` semantics.

Environment facts:

- Compute host: `compute-1.example.test`, kernel `4.18.0-553.5.1.el8_10.x86_64`.
- ML2 agents include Open vSwitch, LinuxBridge, SR-IOV NIC, DHCP, and metadata agents.
- The VM ports used for live validation were normal OVS ports:
  - `wp-test`: Neutron port `86b83885-671f-474c-9556-8af98cf1cdc8`, tap `tap86b83885-67`, fixed IP `192.0.2.26`.
  - `test1111`: Neutron port `e607e86b-9e5f-4c63-a5df-3dc8986a1b0f`, tap `tape607e86b-9e`, fixed IP `192.0.2.27`.
- Both VM ports reported `binding:vif_type=ovs`, `binding:vnic_type=normal`, `binding:vif_details.port_filter=false`, and `binding:vif_details.ovs_hybrid_plug=false`.
- The live VM tap validation used `test1111` / `tape607e86b-9e` and a temporary local veth target. The temporary agent process, veth pair, BPF pins, and `/tmp/aria-verify` payload were removed after validation.

Validated datapath behavior:

- Isolated veth validation proved that `aria-mirror global` clones IPv4 ICMP/TCP/UDP, ARP, DHCP-like broadcast, IPv6 ND/ICMPv6, LLDP, unknown EtherType, and VLAN `0x8100` frames.
- Isolated `global + policy` validation proved the intended coexistence semantics:
  - global-only: all source traffic is cloned to the global target.
  - global plus policy, different targets: IP traffic matching the policy is cloned to both the global target and the policy target.
  - global plus policy, same target: the packet is cloned once, while both global and policy counters are updated.
  - non-IP frames such as ARP, LLDP, unknown EtherType, and VLAN frames are covered by global mirror and do not match policy mirror rules.
- Live OVS tap validation on `tape607e86b-9e` proved that Aria-agent can attach to a real VM OVS tap, create a global mirror to a local target interface, clone ICMP/ARP packets, keep original VM traffic passing, and remove the XDP attachment after shutdown.
- Live validation counters showed non-zero ingress/egress mirrored packets and bytes with `errors=0`.

Product implications:

- `aria-mirror global` must be documented and implemented as `global_l2` / SPAN-like mirror: clone all L2 frames seen on the source tap/source interface for the selected direction.
- `aria-mirror policy` should be named as a selective mirror rule in user-facing documents where possible. It is IP-selective mirror based on source/destination address group or prefix, protocol, direction, priority, and target.
- The second-phase implementation can commit to `global + selective rule` coexistence. It must not use the older "policy hit first, global fallback only" semantics.
- QoS was not part of this mirror validation. `edt_available=false` on the live tap is still consistent with treating QoS execution as a separate second-stage readiness item.

### 9.1 Existing `networking_mirror` Compatibility Freeze

**Files:**
- Document: `docs/aria-acl-neutron-extension-product-design.md`
- Existing package: `networking_mirror`

- [ ] Keep the existing `mirror` extension alias for the current OpenFlow based implementation.
- [ ] Do not change the meaning of existing `mirror.port_id`.
- [ ] Document that existing `mirror.port_id` is the destination analyzer VM port.
- [ ] Document that source traffic is provided by `[mirror] interface` and `br-mirror`.
- [ ] Document table usage:
  - table `100`: ICG distribution.
  - table `101`: DLP distribution.
  - table `102`: NDS distribution when present in the deployed package.
- [ ] Add operational checks:

```bash
ovs-ofctl -O OpenFlow11 dump-groups br-int
ovs-ofctl -O OpenFlow11 dump-flows br-int table=100
ovs-ofctl -O OpenFlow11 dump-flows br-int table=101
ovs-ofctl -O OpenFlow11 dump-flows br-int table=102
ovs-vsctl list-br
ovs-vsctl show
```

**Expected visible result:**

Existing `mirror` behavior remains unchanged, and operators can distinguish `networking_mirror` from `aria_mirror` during troubleshooting.

### 9.2 Neutron Server `aria_mirror` API And DB

**Files:**
- Create: `openstack/neutron_aria/neutron_aria/extensions/aria_mirror.py`
- Create: `openstack/neutron_aria/neutron_aria/services/aria_mirror/plugin.py`
- Create: `openstack/neutron_aria/neutron_aria/db/aria_mirror_db.py`
- Create: `openstack/neutron_aria/neutron_aria/db/migration/alembic_migrations/versions/<rev>_aria_mirror.py`
- Modify: package entrypoint / built-in plugin registration
- Modify: `deploy/kolla/config/policy.yaml`

- [ ] Register extension alias `aria-mirror`.
- [ ] Register service plugin alias `aria_mirror`.
- [ ] Add `aria_mirror_sessions`.
- [ ] Add `aria_mirror_rules`.
- [ ] Add `aria_mirror_bindings` if product UX requires ACL-like bind/unbind operations.
- [ ] Add `aria_mirror_port_statuses`.
- [ ] Add runtime status fields for cumulative mirror counters:
  - `mirrored_packets`
  - `mirrored_bytes`
  - `errors`
- [ ] Add runtime status fields for sampled mirror rates:
  - `mirrored_pps`
  - `mirrored_bps`
  - `stats_window_seconds`
  - `last_sampled_at`
- [ ] Treat counters and rates as agent-reported runtime fields, not user-editable configuration.
- [ ] Implement session CRUD.
- [ ] Implement rule CRUD.
- [ ] Add session-level `mirror_mode`:
  - `global`
  - `policy`
- [ ] Add rule-level optional target override:
  - `target_type`
  - `target_port_id`
  - `target_host`
  - `target_interface`
- [ ] Support prefix/address-set based distribution to different target VM ports.
- [ ] Validate prefix/address-set overlap with explicit `priority`.
- [ ] Reject overlapping rules with the same priority for the same source and direction.
- [ ] Implement status show/list.
- [ ] Validate `source_type`:
  - `port`
  - `network`
  - `host_interface`
- [ ] Validate `target_type`:
  - `port`
  - `local_interface`
- [ ] Make `host_interface` source admin-only.
- [ ] Reject raw writes to runtime fields such as `source_ifindex`, `target_ifindex`, packet counters, and error counters.
- [ ] Emit RPC/notification events for session/rule/binding changes.

**Expected visible result:**

```bash
neutron ext-show aria-mirror
neutron aria-mirror-session-list
neutron aria-mirror-session-show $SESSION_ID
```

### 9.3 Legacy `neutron` CLI For `aria_mirror`

**Files:**
- Create: `openstack/neutron_aria/neutron_aria/client/commands/aria_mirror.py`
- Modify: legacy client registration path used by the product image

- [ ] Add `neutron aria-mirror-session-create`.
- [ ] Add `neutron aria-mirror-session-update`.
- [ ] Add `neutron aria-mirror-session-delete`.
- [ ] Add `neutron aria-mirror-session-show`.
- [ ] Add `neutron aria-mirror-session-list`.
- [ ] Add `neutron aria-mirror-rule-create`.
- [ ] Add `neutron aria-mirror-rule-delete`.
- [ ] Add `neutron aria-mirror-rule-list`.
- [ ] Add `neutron aria-mirror-status-show`.
- [ ] Support VM tap source:

```bash
neutron aria-mirror-session-create \
  --name vm-to-analyzer \
  --source-port $SRC_PORT_ID \
  --target-port $TARGET_PORT_ID \
  --direction both
```

- [ ] Support global mirror using Aria-agent's existing global mirror capability:

```bash
neutron aria-mirror-session-create \
  --name vm-global-mirror \
  --source-port $SRC_PORT_ID \
  --target-port $ANALYZER_PORT_ID \
  --direction both \
  --mirror-mode global
```

- [ ] Support IP-prefix distribution to different analyzer VM ports:

```bash
neutron aria-mirror-session-create \
  --name span-by-prefix \
  --source-host compute-1 \
  --source-interface ensXfY \
  --direction ingress \
  --mirror-mode policy

neutron aria-mirror-rule-create $SESSION_ID \
  --priority 10 \
  --dst-ip-prefix 10.10.0.0/16 \
  --target-port $ANALYZER_VM_A_PORT_ID

neutron aria-mirror-rule-create $SESSION_ID \
  --priority 20 \
  --dst-ip-prefix 10.20.0.0/16 \
  --target-port $ANALYZER_VM_B_PORT_ID
```

- [ ] Support physical capture NIC source, admin-only:

```bash
neutron aria-mirror-session-create \
  --name span-uplink-to-analyzer \
  --source-host compute-1 \
  --source-interface ensXfY \
  --target-port $ANALYZER_PORT_ID \
  --direction ingress
```

**Expected visible result:**

Operators can create a mirror session without touching OVS commands or Aria local CLI directly.

### 9.4 `neutron-aria-agent` Mirror Translator

**Files:**
- Create: `openstack/neutron_aria/neutron_aria/agent/effective_mirror.py`
- Modify: `openstack/neutron_aria/neutron_aria/agent/event_loop.py`
- Modify: `openstack/neutron_aria/neutron_aria/agent/ovs_discovery.py`
- Modify: `openstack/neutron_aria/neutron_aria/agent/status_reporter.py`

- [ ] Full resync all `aria_mirror` sessions.
- [ ] Subscribe to session/rule/binding changes.
- [ ] Subscribe to port binding and port delete changes.
- [ ] Resolve `source_port_id` to local OVS tap by `external_ids:iface-id`.
- [ ] Resolve `source_network_id` to all eligible local VM OVS tap ports on that network.
- [ ] Resolve `source_host_interface` only when `source_host` equals the local host.
- [ ] Resolve `target_port_id` to local target OVS tap and ifindex.
- [ ] Resolve rule-level `target_port_id` when a rule overrides the session target.
- [ ] Resolve `target_interface` to local ifindex.
- [ ] Reject first-version cross-host source/target with `CROSS_HOST_UNSUPPORTED`.
- [ ] Reject SR-IOV/LinuxBridge/service ports with `UNSUPPORTED` or `NOT_APPLICABLE`.
- [ ] Generate per-source mirror snapshot:
  - source tap identity.
  - direction.
  - protocol.
  - source group/address set.
  - destination group/address set.
  - target ifindex.
  - mirror mode.
  - priority.
  - revision.
- [ ] Translate `mirror_mode=global` to Aria-agent `MIRROR_GLOBAL`.
- [ ] Translate `mirror_mode=policy` rules to Aria-agent `MIRROR_POLICY`.
- [ ] Compile `src_ip_prefix` / `dst_ip_prefix` into Aria address groups when needed.
- [ ] Define global mirror as `global_l2` / SPAN-like mirror:
  - clone all L2 frames on the source tap/source interface for the selected direction.
  - include IPv4, IPv6, ARP, broadcast, multicast, LLDP, unknown EtherType, and VLAN frames.
- [ ] Define policy mirror as IP-selective mirror:
  - match parsed IP packets by source group/prefix, destination group/prefix, protocol, direction, and priority.
  - do not match ARP, LLDP, unknown EtherType, or other non-IP frames.
- [ ] Define `global + policy` coexistence:
  - global mirror is applied first and remains active for all traffic.
  - policy mirror can clone matching IP packets to an additional target.
  - if global and policy targets are different, one matched packet is cloned to both targets.
  - if global and policy targets are the same, clone once and update both global and policy stats.
  - non-IP frames are cloned only by global mirror.
- [ ] Translate `global + policy` snapshots without collapsing policy rules into global fallback.
- [ ] Report status and counters back to `aria_mirror_port_statuses`.
- [ ] Report sampled rates back to `aria_mirror_port_statuses`:
  - `mirrored_pps`
  - `mirrored_bps`
  - `stats_window_seconds`
  - `last_sampled_at`

**Expected visible result:**

`neutron aria-mirror-status-show --port $SRC_PORT_ID` displays local host, source ifname/ifindex, target ifname/ifindex, revision, status, mirrored packets, mirrored bytes, mirrored pps, mirrored bps, stats window, last sampled time, and errors.

### 9.5 `aria-agent` Mirror UDS Contract

**Files:**
- Modify: `api/src/neutron.rs`
- Modify: `agent/src/api_routes.rs`
- Modify: `agent/src/control_plane.rs`
- Modify: `core/src/mirror_ops.rs`
- Modify: `ebpf/src/mirror.rs` only if OpenStack-specific semantics require map/schema changes

- [ ] Add mirror domain to the OpenStack snapshot DTO.
- [ ] Map Neutron direction values to Aria values:
  - `ingress`
  - `egress`
  - `both`
- [ ] Map Neutron protocol values to Aria protocol numbers.
- [ ] Map address sets/prefixes to Aria group IDs.
- [ ] Preserve existing Aria global mirror behavior for `mirror_mode=global`.
- [ ] Support rule-specific target ifindex for prefix/address-set distribution.
- [ ] Apply mirror entries without changing ACL/QoS domains.
- [ ] Delete stale mirror entries by session/revision.
- [ ] Expose mirror stats to `neutron-aria-agent`.
- [ ] Expose cumulative mirror counters per global session and selective rule:
  - `mirrored_packets`
  - `mirrored_bytes`
  - `errors`
- [ ] Add an aria-agent mirror stats sampler in the local control plane:
  - keep eBPF datapath limited to fast cumulative counters only.
  - periodically read `MIRROR_GLOBAL_STATS` and `MIRROR_STATS`.
  - aggregate per-CPU values before calculating rates.
  - keep the previous sample in memory keyed by tap/session/rule/direction.
  - compute `mirrored_pps = delta_packets / interval_seconds`.
  - compute `mirrored_bps = delta_bytes * 8 / interval_seconds`.
  - return `0` or `null` rates for the first sample before a delta exists.
  - detect counter reset or map reattach when the current counter is lower than the previous counter and restart the rate window.
  - expose `stats_window_seconds` and `last_sampled_at` with every rate snapshot.
- [ ] Default sampler interval:
  - prefer `1s` for local aria-agent CLI/API display.
  - allow product config to raise it to `5s` in large deployments to reduce polling load.
- [ ] Keep Neutron Server out of high-frequency rate calculation:
  - Neutron DB stores the latest reported counters/rates/status.
  - `neutron-aria-agent` polls or receives local aria-agent snapshots and reports bounded status updates.
  - Neutron Server should not poll eBPF maps directly.
- [ ] Preserve original traffic when mirror apply fails.

**Expected visible result:**

Aria-agent applies mirror entries using existing TC/eBPF clone behavior and reports packet/byte/error counters plus sampled pps/bps rates. eBPF remains responsible for counters only; rate math lives in the aria-agent control plane.

### 9.6 Mirror Datapath Smoke Tests

**Files:**
- Create: `deploy/kolla/smoke/aria_mirror_smoke.sh`

- [ ] Boot source VM and analyzer VM on the same host.
- [ ] Create `aria_mirror` session from source VM port to analyzer VM port.
- [ ] Verify ingress clone.
- [ ] Verify egress clone.
- [ ] Verify `both` creates both directions.
- [ ] Create global mirror session and verify all source traffic is cloned to the target VM port or local analyzer interface.
- [ ] Verify global L2 coverage:
  - IPv4 ICMP/TCP/UDP.
  - ARP.
  - DHCP broadcast.
  - IPv6 ND/ICMPv6.
  - LLDP.
  - unknown EtherType.
  - VLAN `0x8100`.
- [ ] Create protocol-specific mirror rule.
- [ ] Create address-set or prefix-specific mirror rule.
- [ ] Create two prefix rules under one source and verify different prefixes go to different analyzer VM ports.
- [ ] Create `global + policy` with different targets and verify matching IP traffic reaches both targets.
- [ ] Create `global + policy` with the same target and verify one packet copy is observed while both stats entries increase.
- [ ] Verify non-IP traffic only matches global and does not increment policy stats.
- [ ] Create overlapping prefixes with the same priority and verify server-side rejection.
- [ ] Create overlapping prefixes with different priority and verify higher priority wins.
- [ ] Verify cumulative stats:
  - `mirrored_packets`.
  - `mirrored_bytes`.
  - `errors`.
- [ ] Verify sampled rates:
  - `mirrored_pps`.
  - `mirrored_bps`.
  - `stats_window_seconds`.
  - reset behavior after session delete/recreate or agent restart.
- [ ] Delete the session and verify clone stops.
- [ ] Reboot analyzer VM and verify target ifindex recovery.
- [ ] Migrate source VM and verify source host cleanup plus destination host reapply.
- [ ] Create a cross-host target and verify `CROSS_HOST_UNSUPPORTED`.
- [ ] Try SR-IOV/LinuxBridge ports and verify explicit unsupported status.
- [ ] Configure a physical capture NIC source in a lab and verify SPAN traffic can be cloned to a local analyzer VM.
- [ ] Repeat the 2026-06-23 compute-1 live OVS tap scenario in product smoke:
  - source VM `test1111`-like normal OVS tap.
  - temporary local analyzer interface or analyzer VM port.
  - global mirror to target.
  - ping source traffic remains `0% packet loss`.
  - ICMP and ARP are visible on target.
  - cleanup removes XDP/TC attachments, temporary interfaces, BPF pins, and temporary state.

**Expected visible result:**

Mirror failures are visible in `aria_mirror` status and do not block original VM traffic.

### 9.7 Mirror Kolla Packaging

**Files:**
- Modify: `deploy/kolla/neutron-server/Dockerfile`
- Modify: `deploy/kolla/config/neutron.conf`
- Modify: `deploy/kolla/config/neutron-aria-agent.ini`
- Modify: `deploy/kolla/config/policy.yaml`

- [ ] Package `aria_mirror` Neutron Server code into the product neutron-server image.
- [ ] Add `aria_mirror` only in second-phase configuration:

```ini
[DEFAULT]
service_plugins = router,network_ip_availability,mirror,qos,aria_acl,aria_qos,aria_mirror
```

- [ ] Add mirror-specific agent config:

```ini
[mirror]
enabled = true
enforcement_driver = aria
allow_host_interface_source = true
allow_cross_host_target = false
```

- [ ] Keep existing `mirror` plugin enabled unless product decides to retire it separately.
- [ ] Do not require tenants to run OVS commands.

---

## 9.8 Pre-Neutron-Server Work Boundary

**Implementation checkpoint, 2026-06-25:**

The work that does not require the product Neutron Server source continues in
the `neutron-aria-agent` and smoke layers:

- `neutron-aria-agent` now uses an ACL source abstraction instead of reading the
  fixture JSON directly in `main.py`.
- `AclSource` currently supports:
  - `disabled`: no ACL enhancement input.
  - `fixture`: lab and smoke JSON payloads.
  - `neutron`: explicit placeholder that fails fast until the `aria-acl`
    Neutron API/DB extension exists.
- Existing fixture smoke remains compatible: if `[acl] fixture_path` is set and
  `[acl] source` is omitted, the agent selects `fixture` automatically.
- `neutron_aria_full_resync_smoke.sh` accepts `REQUEST_TIMEOUT_OVERRIDE` so UDS
  timeout convergence can be regression-tested without editing the running
  container by hand.

This checkpoint deliberately does not implement the real product northbound
objects. `aria-acl` policy/rule/address-set/binding CRUD, DB migrations,
extension alias, service plugin, and legacy CLI commands still require the
matching Neutron Server source tree.

---

## 9.9 Pause Checkpoint And Transaction-First Optimization

**Pause checkpoint, 2026-06-25:**

Current implemented and validated state:

- Previous checkpoint commit: `aa19d73 neutron: abstract ACL source for agent`.
- CI status at that checkpoint: green; Python adapter tests pass and Rust/eBPF
  build is skipped when no Rust files changed.
- `aria-datapath` has the base Neutron UDS routes:
  - `GET /api/v1/neutron/capabilities`.
  - `GET /api/v1/neutron/status`.
  - `PUT /api/v1/neutron/snapshot`.
  - `DELETE /api/v1/neutron/ports/{port_id}`.
- Mutating UDS handlers are cancel-safe at the HTTP handler boundary: client
  timeout or disconnect no longer cancels an apply task that has already
  started.
- `neutron-aria-agent` can run as an independent Kolla-style container, report
  heartbeat, read Neutron ports through legacy `python-neutronclient`, build a
  per-host snapshot, and submit it to local UDS.
- UDS timeout convergence is implemented in Python for snapshot and port delete:
  a timed-out mutation is treated as successful only after `GET /status` proves
  the desired state converged.
- ACL fixture smoke on `compute-1.example.test` proved:
  - full resync discovers the real OVS VM tap.
  - ACL fixture translates into datapath groups/policies.
  - ICMP can be blocked and rollback restores traffic.
  - a low request timeout can still converge through status polling.
- ACL source abstraction is in place:
  - `disabled` for product-safe default.
  - `fixture` for lab and smoke payloads.
  - `neutron` placeholder that intentionally fails until the Neutron Server
    `aria-acl` API/DB extension exists.

Transaction completion status after the first transaction-first implementation
pass:

| Component | Transaction status | Already done | Not done yet |
| --- | --- | --- | --- |
| Neutron Server | Not started in this repository | Product design only | API/DB transaction, revision checks, RPC event emission, status DB update |
| `neutron-aria-agent` | Partial | full resync, heartbeat, ACL source abstraction, UDS timeout convergence, degraded reporting, durable local generation/desired-hash state, same desired-state generation reuse, pending generation restart reuse, response error classification | event revision ordering, full desired-state journal with source revisions, bounded unresolved-generation policy, production restart smoke |
| Rust `aria-agent` / `aria-datapath` | Partial | neutron-managed attach boundary, UDS routes, cancel-safe mutation task, ACL fixture apply, delete cleanup, `desired_hash` UDS field, accepted/applied/pending generation status, same-generation replay/no-op, same-generation hash conflict, stale generation classification, per-port/domain status surface, QoS/Mirror payload fields in the UDS snapshot contract, domain-aware apply classification, host-level Neutron WAL intent/commit/replay, affected ports/domains in WAL intent records, startup recovery classification and best-effort ACL scrub for intent-without-commit, startup pinned runtime reconciliation for committed ports, orphan managed link-pin cleanup, runtime degraded status on reconcile failure, fsync-backed WAL append, committed-state replay, WAL status reporting | real QoS apply backend, real Mirror apply backend, crash injection tests, deep pinned map/content scrub for pinned/runtime mismatch, WAL compaction, durable status snapshot separate from WAL |

So the answer is: the full transaction model is **not complete yet**. The
current code proves the basic control path and several safety foundations, but
it must not be described as fully atomic or fully durable until the remaining
items in this section are implemented and tested.

Development is paused at this checkpoint before adding more northbound feature
surface. The next implementation pass must prioritize transaction semantics,
atomicity, idempotency, and crash recovery before adding more ACL/QoS/Mirror
business APIs.

### 9.9.1 Transaction Boundary Definitions

The project uses different transaction boundaries at each layer. They must not
be blurred:

| Layer | Transaction boundary | Source of truth | Commit point |
| --- | --- | --- | --- |
| Neutron Server | One API/DB write transaction for policy/rule/address-set/binding/status update | Neutron DB | DB commit succeeds and revision is advanced |
| `neutron-aria-agent` | One host-local desired-state generation produced from a full resync or merged event batch | Neutron DB/API view plus local generation state | Snapshot is submitted and status convergence is classified |
| `aria-datapath` | One UDS snapshot generation for one host | Latest accepted Neutron snapshot and local WAL/state | WAL commit and runtime status are durable/consistent |

Atomicity is not allowed to mean "silently half-ready". If an enhancement
domain cannot be applied, the system must choose an explicit classified state:

- `ready`: desired state is applied and status is durable.
- `degraded`: original OVS forwarding is preserved, enhancement may be bypassed
  or partially unavailable, and the reason is visible.
- `blocked`: consistency cannot be proven; generation must not be advanced as
  accepted.
- `not_requested` / `unsupported` / `not_applicable`: no hidden failure.

For ACL/QoS product behavior, original VM forwarding must stay safe on
degraded enhancement paths. A domain may degrade to bypass, but it must never be
reported as ready before its runtime state, status, and durable metadata agree.
This is not ACL-only: if `managed_domains` contains `qos` or `mirror`, those
domains must be included in the same generation, desired hash, WAL record, and
per-domain status model. Until the QoS or Mirror executor is implemented, the
domain must be reported as `error` or `blocked`; it must not be silently treated
as ready just because attach or ACL succeeded.

### 9.9.2 Mandatory Idempotency Rules

These rules are mandatory before promoting more feature work:

- Replaying the same `local_generation` must be idempotent and return current
  status without duplicating groups, policies, qdisc, maps, refs, or authority
  markers.
- Receiving an older generation must be rejected or treated as no-op without
  deleting newer runtime state.
- Repeating `DELETE /api/v1/neutron/ports/{port_id}` for a missing or already
  detached port must be a successful no-op.
- Python UDS retry must resend the same desired generation, not synthesize a new
  generation for the same desired state while recovery is unknown.
- Neutron RPC events are hints only. Lost, duplicated, or reordered events must
  converge through full resync.
- Datapath apply must be desired-state reconciliation, not unbounded append-only
  mutation.
- Runtime object keys must be scoped by authority, domain, project/object when
  that metadata exists, port id, and generation where needed; human-readable
  names are not sufficient uniqueness keys.
- Local admin and Neutron-managed persistent state must use separate authority
  namespaces and separate WAL entries.
- Temporary troubleshooting features, such as trace-only sessions, must not
  modify Neutron generation or Neutron WAL state.

### 9.9.3 Atomic Apply Sequence

The optimized implementation order for `aria-datapath` snapshot apply is:

1. Parse request and enforce body size, schema version, peer authority, host,
   mode, and supported domains.
2. Acquire one host-local apply lock; no concurrent snapshot/delete writes.
3. Load current runtime state, pinned state, and WAL summary.
4. Preflight all affected ports and domains without changing datapath:
   - tap exists.
   - ifindex matches current interface.
   - OVS `iface-id` matches port id.
   - managed domain ownership is compatible.
   - unsupported ports are classified.
5. Build a deterministic desired state and a deterministic diff.
6. Write WAL intent with generation, affected ports, domains, object revisions,
   and the planned diff hash.
7. Apply runtime changes with compensating cleanup for partial failures:
   - attach/detach runtime.
   - group/address-set reconciliation.
   - ACL policy reconciliation.
   - QoS reconciliation when enabled.
   - mirror reconciliation only in second phase.
   Domain preflight must reject or block the whole affected port before any
   mutating domain apply when the requested domain set contains an unimplemented
   transactional domain. For example, `managed_domains=["acl","qos"]` must not
   write ACL state and then report the port as partially failed simply because
   QoS is not implemented yet.
8. Collect per-port and per-domain status, including degraded/bypass reasons.
9. Write WAL commit only if the runtime and status can be explained.
10. Advance accepted/classified generation only after WAL commit.
11. Publish status atomically from committed state.

If any step before WAL commit fails, the implementation must keep the previous
accepted/classified generation visible. The failed attempt can be exposed as
degraded/blocked diagnostics, but it cannot be mistaken for a committed ready
state.

### 9.9.4 Recovery And Replay Rules

Restart recovery must handle the following cases:

- No intent and no commit: load committed state and continue.
- Intent without commit: treat previous apply as incomplete, scrub or reconcile
  affected objects, do not advance accepted generation, and require full resync.
- Partial runtime apply without commit: status must be degraded or blocked until
  reconciliation proves state is safe.
- Commit without status write: rebuild status from committed WAL/state and only
  then expose the committed generation.
- Pinned map/link mismatch: classify as degraded/blocked and force reconcile;
  do not silently assume maps are correct.
- Python timeout with later datapath success: status convergence may recover the
  operation.
- Python timeout without status convergence: mark local API degraded and retry
  through backoff/full resync.

### 9.9.5 Optimized Development Order

The next development order is changed to transaction-first:

1. Freeze the UDS status contract for generation, per-port status, per-domain
   status, WAL status, and authority state.
2. Implement idempotent Rust snapshot/delete reconciliation with explicit
   generation comparison and repeated-request tests.
3. Implement WAL intent/commit/replay and startup recovery tests.
4. Make Python `neutron-aria-agent` persist and reuse host-local generation
   state, including retry and restart behavior. **First pass complete for
   desired-hash generation reuse and pending-generation restart reuse.**
5. Add contract tests for timeout convergence, duplicate snapshot replay,
   duplicate delete, older generation, crash/restart, and partial apply.
6. Only after those gates pass, continue to Neutron Server `aria-acl` API/DB/CLI
   work when the matching source tree is available.
7. QoS and Mirror remain behind their phase gates until the same transaction
   rules are proven for ACL.

### 9.9.6 `neutron-aria-agent` Transaction Development Plan

`neutron-aria-agent` does not write datapath maps directly, but it still needs a
transaction model because it converts Neutron's control-plane state into a
host-local desired snapshot. Its correctness target is: one input view produces
one deterministic local generation, and retries/restarts do not invent a
different desired state while the previous state is unresolved.

**Current status:** partial. Timeout convergence and host-local
generation/desired-hash persistence now exist. Event revision ordering,
full source-revision journaling, and production restart smoke are not complete.

**Files to create or modify:**

- Create: `openstack/neutron_aria/neutron_aria/agent/state.py` **done**
- Create: `openstack/neutron_aria/neutron_aria/agent/generation.py` **not
  required in the first pass; folded into `state.py`**
- Modify: `openstack/neutron_aria/neutron_aria/agent/event_loop.py`
- Modify: `openstack/neutron_aria/neutron_aria/agent/service.py`
- Modify: `openstack/neutron_aria/neutron_aria/agent/event_merge.py`
- Modify: `openstack/neutron_aria/neutron_aria/agent/config.py`
- Modify: `deploy/kolla/config/neutron-aria-agent.ini`
- Test: `openstack/neutron_aria/neutron_aria/tests/unit/test_state.py`
- Test: `openstack/neutron_aria/neutron_aria/tests/unit/test_generation.py`
- Test: `openstack/neutron_aria/neutron_aria/tests/unit/test_event_loop.py`

**Required implementation tasks:**

- [x] Add local state directory, default
  `/var/lib/neutron-aria-agent/state`.
- [x] Persist host-local generation state.
- [x] Persist pending generation, desired-state hash, and submit timestamp
  before sending UDS snapshot.
- [x] Use a deterministic desired-state hash covering:
  - host.
  - port ids.
  - managed domains.
  - ACL/QoS/Mirror effective payloads when enabled.
  - source revision numbers where available once Neutron Server source exists.
- [x] If the same desired-state hash is retried, reuse the same generation.
- [ ] Generate a new generation only when the desired-state hash changes or the
  previous generation is classified as failed and a full resync recomputes the
  state.
- [x] Persist the committed generation only after UDS response/status proves
  convergence.
- [x] On process restart, load pending state and check UDS status before
  submitting a new generation.
- [x] If status already converged, mark ready without resubmitting.
- [x] If status did not converge, resubmit the same generation before creating a
  new one.
- [ ] Treat RPC events as dirty hints; never apply an event payload directly as
  authoritative state.
- [ ] Merge duplicated events by port/network id.
- [ ] Drop stale RPC events when object `revision_number` is older than the
  latest seen revision.
- [ ] Escalate to full resync when event ordering cannot be proven.
- [ ] Keep delete handling idempotent:
  - if the port is known local, call UDS delete.
  - if delete times out, status-check that port disappeared.
  - if the port is already absent, treat as success.
- [x] Report current desired hash through heartbeat configurations.
- [ ] Report full transaction fields through heartbeat configurations:
  - `last_submitted_generation`.
  - `last_converged_generation`.
  - `pending_generation`.
  - `last_convergence_error`.
- [ ] Add bounded backoff for repeated unresolved generations.
- [ ] Add production startup smoke proving restart does not create duplicate
  generations.

**Required tests:**

- [ ] Same desired state after timeout resubmits the same generation.
- [ ] Different desired state increments generation.
- [ ] Restart with pending generation checks status before submit.
- [ ] Restart with converged generation reports ready.
- [ ] Duplicate RPC events produce one full resync.
- [ ] Older revision event does not overwrite newer dirty state.
- [ ] Lost event triggers full resync.
- [ ] Delete timeout converged by status is success.
- [ ] Delete timeout not converged is degraded and retried.

**Visible result after completion:**

```text
neutron-aria-agent logs show one stable generation for one desired state.
Restarting neutron-aria-agent does not create duplicate datapath writes.
Heartbeat exposes submitted/converged/pending generation fields.
```

### 9.9.7 Rust `aria-agent` / `aria-datapath` Transaction Development Plan

The privileged Rust side is the most important transaction boundary. It owns
local runtime, eBPF maps, pinned links/maps, WAL, and per-port/domain status.
Its correctness target is: a snapshot is either classified and recoverable, or
kept out of accepted generation. It must never report ready for a state that
cannot be reconstructed after restart.

**Current status:** partial. UDS routes, neutron-managed attach boundary,
cancel-safe mutation tasks, ACL fixture apply, cleanup smoke, `desired_hash`
contract field, accepted/applied/pending generation status, same-generation
no-op, hash-conflict rejection, stale generation classification,
per-port/per-domain status surface, host-level Neutron WAL intent/commit/replay,
fsync-backed WAL append, affected ports/domains in WAL intent records,
intent-without-commit startup recovery classification, best-effort ACL scrub,
startup pinned runtime reconciliation for committed ports, orphan managed
link-pin cleanup, QoS/Mirror snapshot payload fields, and domain-aware apply
classification exist. QoS/Mirror are not yet runtime executors: a snapshot that
requests those domains is classified as blocked/error rather than falsely ready.
Crash injection tests, deep pinned map/content scrub, WAL compaction, and
startup scrub/reconcile for deep pinned/runtime mismatch cases are not complete.

**Files to create or modify:**

- Modify: `api/src/lib.rs`
- Modify: `agent/src/neutron_api.rs`
- Modify: `agent/src/control_plane.rs`
- Modify: `agent/src/tap_registry.rs`
- Modify: `agent/src/system_manager.rs`
- Modify: `agent/src/main.rs`
- Create or extend: `core/src/neutron_state.rs`
- Create or extend: `core/src/neutron_wal.rs`
- Create or extend: `core/src/neutron_reconcile.rs`
- Create or extend: `core/src/neutron_status.rs`
- Test: `agent` neutron snapshot/delete/status tests.
- Test: `core` WAL replay and recovery tests.

**Required UDS contract changes:**

- [x] Extend snapshot request with stable identifiers:
  - `schema_version`.
  - `generation` as the host-local generation.
  - `desired_hash`.
- [x] Extend per-port snapshot payload with domain-specific effective payload
  slots:
  - `acl` for Aria ACL effective policy.
  - `qos` for Aria QoS effective policy when the QoS phase is enabled.
  - `mirror` for Aria Mirror effective session/rule projection in phase two.
- [ ] Extend snapshot request with optional future identifiers:
  - optional `source_revision`.
  - `integration_mode`.
- [x] Extend status response with:
  - `accepted_generation`.
  - `applied_generation`.
  - `pending_generation`.
  - `wal_status`.
  - `wal_replay_failures`.
  - `authority_state`.
  - per-port status list.
  - per-domain status list.
- [ ] Extend status response with future durable classification fields:
  - `last_classified_generation`.
  - `last_feature_ready_generation_by_domain`.
- [ ] Add stable error codes for:
  - old generation. **First pass returns stale classification.**
  - duplicate generation hash mismatch. **First pass returns conflict.**
  - WAL append failure.
  - WAL commit failure.
  - preflight failed.
  - partial apply.
  - pinned runtime mismatch.
  - unsupported domain.
- [ ] Add response body size and contract version metadata to capabilities.

**Required apply engine tasks:**

- [x] Compare incoming generation with current accepted/applied generation.
- [x] Same generation and same desired hash: return current status without
  rewriting runtime.
- [x] Same generation but different desired hash: reject as conflict.
- [x] Older generation: reject or no-op without deleting newer state.
- [x] Newer generation: proceed through the current in-memory apply sequence.
- [x] Acquire a single writer lock across snapshot and delete.
- [ ] Preflight every affected port before mutating runtime.
- [x] Preflight requested Neutron-managed domains before mutating ACL/QoS/Mirror
  state. **Current code allows attach and ACL; QoS/Mirror are classified as
  unimplemented transactional domains until their executors exist.**
- [ ] Build deterministic diff:
  - ports to attach.
  - ports to update.
  - ports to detach.
  - ACL groups/policies to add/update/delete.
  - QoS entries when phase is enabled.
  - mirror entries only in second phase.
- [x] Write WAL intent before runtime mutation.
- [x] Apply runtime diff with cleanup hooks.
- [x] ACL apply uses gate-first semantics: disable ACL/bypass before purging or
  writing Neutron-owned ACL maps, then enable ACL only after all groups,
  policies, and conntrack cleanup succeed.
- [x] Add deterministic Rust fault-injection hooks for transaction cut points:
  snapshot after intent, port after attach, ACL after disable/purge/group
  write/policy write/before enable/after enable, snapshot before/after commit,
  and delete after intent/ACL purge/detach-before-commit.
- [x] Add one-shot fault marker support so `sigkill`/abort smoke can trigger a
  datapath crash once and then allow restart replay/full-resync to complete.
- [x] Track per-port/per-domain result for applied ready/error ports.
- [x] Block ACL mutation when the same port snapshot also requests an
  unimplemented QoS/Mirror transaction domain.
- [ ] Track per-port/per-domain result for every requested port, including
  ignored/unsupported/not-applicable ports, in the durable status model.
- [x] Write WAL commit with final classified runtime/status state.
- [x] Add final status hash to WAL commit records.
- [x] Advance applied generation only after the in-memory apply reports no
  per-port errors.
- [x] Update in-memory status from the current classified state.
- [x] Advance durable accepted/classified generation only after WAL commit.

**Required delete semantics:**

- [x] Delete of unknown port returns success `not_found` and does not change
  generation.
- [x] Delete of known port writes WAL intent before detach.
- [x] Detach runtime and remove managed authority for that port.
- [ ] Clean ACL/QoS/Mirror scoped runtime entries owned by that port/domain.
  **Current code purges ACL-owned state. QoS/Mirror cleanup remains tied to the
  future QoS/Mirror executors.**
- [x] Write WAL commit after cleanup is classified.
- [x] Repeating the same delete is a success no-op.
- [x] Delete must not remove local/admin state outside Neutron authority.

**Required WAL and recovery tasks:**

- [x] Store WAL under product state path, not `/tmp`.
- [x] Use separate WAL namespace/file for Neutron-managed state and local
  override state. **Neutron-managed state now uses a separate host-level WAL
  file under the product state path. Local override WAL is already separate per
  instance.**
- [x] WAL intent records:
  - generation.
  - desired hash.
  - affected ports.
- [x] Extend WAL intent with affected ports and domains.
  - planned diff hash.
  - authority.
  - source revisions when available.
- [x] WAL commit records:
  - accepted/applied/classified generation.
  - per-domain status summary.
  - per-port status summary.
- [x] Extend WAL commit with final status hash.
- [x] On startup, replay WAL before opening UDS write paths.
- [x] Intent without commit triggers startup recovery classification,
  best-effort attach/ACL scrub/detach where enough port information exists, and
  durable recovered/blocked status without advancing applied generation.
- [x] Commit without status rebuilds status from committed state.
- [x] Startup pinned runtime reconciliation claims/rebuilds committed ports
  through the normal attach path and writes degraded/blocked status on failure.
- [x] Startup orphan managed link-pin cleanup removes pinned links that do not
  belong to the committed Neutron WAL port set.
- [ ] Deep pinned map/content mismatch scrub beyond attach-path validation.
- [ ] WAL compact keeps a durable snapshot plus enough audit trail for recovery.

**Required Python agent local transaction tasks:**

- [x] `neutron-aria-agent` writes local durable `prepare_snapshot` before
  submitting a UDS snapshot.
- [x] `neutron-aria-agent` writes local durable `commit_snapshot` only after
  UDS convergence or a successful UDS response.
- [x] Pending snapshot state records `generation`, `desired_hash`,
  `snapshot_ports`, and projected Neutron port IDs.
- [x] Agent restart checks pending snapshot against UDS status before
  resubmitting.
- [x] If pending snapshot already converged, local state is committed and the
  same desired generation is reused.
- [x] If pending snapshot hash conflicts with UDS status, resync is blocked and
  the agent reports degraded instead of overwriting runtime state.
- [x] Delete and migration-source cleanup write local durable pending delete
  state before calling UDS delete.
- [x] Delete pending state is committed only after UDS delete succeeds or UDS
  status proves the port is no longer managed.
- [x] Agent restart can recover a pending delete when UDS status no longer
  contains the port.
- [x] Agent heartbeat/configurations carry latest managed port details and
  per-port/per-domain runtime statuses from UDS status.
- [ ] Neutron Server plugin consumes the reported per-port/per-domain statuses
  and writes `aria_acl_port_statuses`.
- [ ] Delete/migration pending state is also reflected in future
  `aria_acl_port_statuses` as `pending` or `degraded` when unresolved.

**Required Neutron Server transaction tasks:**

- [ ] `aria_acl_policy`, `aria_acl_rule`, `aria_acl_address_set`, and
  `aria_acl_binding` CRUD update object data and `revision_number` inside the
  same DB transaction.
- [ ] RPC/notification is emitted only after DB commit.
- [ ] If notification delivery fails, periodic full resync remains the durable
  recovery path; no committed DB state may depend only on an in-memory event.
- [ ] Agent-side revision cache is extended from port-only revision handling to
  ACL policy/rule/address-set/binding revisions once the server objects exist.
- [ ] Revision gap, missing object, stale object, or event queue overflow marks
  agent degraded and schedules full resync.
- [ ] Full resync success clears the degraded reason and updates the latest
  revision watermark.

**Required tests:**

- [ ] Same generation replay does not duplicate groups/policies/maps. **Code
  path implemented; CI compile/runtime test still required.**
- [ ] Same generation with different hash is rejected. **Code path implemented;
  CI compile/runtime test still required.**
- [ ] Older generation does not delete newer state. **Code path implemented; CI
  compile/runtime test still required.**
- [ ] Duplicate delete returns success. **Existing behavior preserved; CI
  compile/runtime test still required.**
- [ ] Snapshot crash after intent but before apply recovers as degraded/blocked.
- [ ] Snapshot crash after partial apply but before commit recovers by scrub or
  full resync.
- [x] ACL fault-injection smoke proves `after_purge`,
  `after_group_write`, `after_policy_write`, and `before_enable` leave the port
  in bypass rather than enforcing partial ACL state.
- [x] Python agent restart recovers a converged pending snapshot before
  resubmit.
- [x] Python agent restart blocks a pending snapshot hash mismatch.
- [x] Python agent records and commits local pending delete state.
- [x] Python agent preserves pending delete state when UDS delete timeout does
  not converge.
- [x] Python agent restart recovers pending delete when UDS status no longer
  contains the port.
- [x] Python agent carries UDS per-port/per-domain status in heartbeat payload.
- [ ] Commit without status rebuilds status.
- [x] Pinned runtime attach/reclaim failure is visible in status.
- [ ] Deep pinned map/content mismatch is visible in status.
- [ ] WAL append failure does not advance accepted generation.
- [ ] WAL commit failure does not report ready.
- [ ] Restart after successful snapshot preserves committed managed ports.
- [ ] Process-level crash injection: kill `aria-datapath` after WAL intent,
  after attach, after partial ACL map write, and before WAL commit.
  `sigkill` cut points must use a one-shot marker under `/run/aria` so the
  restarted container can recover instead of re-triggering the same fault.
- [x] Delete detach process-level crash injection: kill `aria-datapath` after
  port detach and before WAL commit, then prove retry/full-resync cleanup
  converges without breaking baseline VM connectivity.
- [x] VM migration smoke: old host cleanup and new host full-resync both
  converge without stale managed pins.
- [x] Tap recreate smoke: deleted/recreated tap with the same Neutron port ID is
  reclaimed or reattached by full resync.

**Live smoke record, 2026-06-25:**

- Deployed `aria-datapath:5613d26` to `compute-1`, `compute-2`, and `compute-3`.
  All three nodes reported `authority_state=ready`, `wal_status=commit_written`,
  `pending_generation=null`, `wal_replay_failures=0`, and no managed ports after
  smoke rollback.
- `neutron agent-list` showed all three `Aria ACL agent` entries alive.
- Baseline ACL full-resync on `compute-1` used VM port
  `e607e86b-9e5f-4c63-a5df-3dc8986a1b0f` / `tape607e86b-9e` and VM IP
  `192.0.2.27`. The test attached 4 local OVS tap ports, wrote an ICMP drop
  ACL for source `192.0.2.2/32`, confirmed ping was blocked, then rollback
  detached all managed ports and ping recovered.
- Process-level datapath fault injection was run with:
  `ARIA_FAULT_POINT=neutron.acl.after_policy_write`,
  `ARIA_FAULT_ACTION=sigkill`, and
  `ARIA_FAULT_ONCE_FILE=/run/aria/fault-after-policy.once`.
  The first run killed `aria-datapath` after ACL policy write and before WAL
  commit. The Neutron agent saw a UDS transport error; the restarted datapath
  reported `wal_status=intent_without_commit`,
  `authority_state=wal_intent_without_commit`, `pending_generation=21`, no
  managed ports, and active instance `tape607e86b-9e`.
- The second full-resync reused generation 21, skipped the one-shot fault via
  the marker, converged to `authority_state=ready`,
  `wal_status=commit_written`, applied the ACL, verified ping block, and
  rollback returned the node to no managed ports.
- Added and ran `neutron_aria_acl_fault_injection_smoke.sh` on `compute-1`.
  The automated smoke loop covered `neutron.acl.after_purge`,
  `neutron.acl.after_group_write`, `neutron.acl.after_policy_write`, and
  `neutron.acl.before_enable`. For each point, the first run failed with the
  expected UDS transport error and left `wal_status=intent_without_commit`,
  `authority_state=wal_intent_without_commit`, no managed ports, and reachable
  VM traffic; the second run recovered, verified ACL block, and rollback
  returned `managed_ports=[]`.
- Added and ran `neutron_aria_delete_fault_injection_smoke.sh` on `compute-1`.
  The automated smoke uses the real VM port
  `e607e86b-9e5f-4c63-a5df-3dc8986a1b0f` / `tape607e86b-9e`, applies an ACL
  snapshot without rollback, triggers
  `neutron.delete.after_detach_before_commit` with one-shot `sigkill`, verifies
  the fault marker, and requires the VM to remain reachable after the
  interrupted delete.
- The delete fault gate accepts two valid recovery branches:
  `wal_status=intent_without_commit` with
  `authority_state=wal_intent_without_commit`, or `wal_status=intent_recovered`
  with `authority_state=recovered_pending_full_resync` and a recovered target
  port status. In both cases, retrying delete must be idempotent and remove the
  target port from the managed set.
- Final cleanup restarts `aria-datapath` without fault injection and requires
  `authority_state=ready`, `pending_generation=null`,
  `wal_replay_failures=0`, and `managed_ports=[]`.

**Live smoke record, 2026-06-26:**

- Added and ran `neutron_aria_tap_recreate_smoke.sh` with test VM
  `de981869-29c2-4465-8804-e293fed53184`, port
  `e607e86b-9e5f-4c63-a5df-3dc8986a1b0f`, tap `tape607e86b-9e`, and VM IP
  `192.0.2.27`.
- The first tap recreate run exposed a Python control-plane transaction gap:
  same `generation` / `desired_hash` full-resync was incorrectly treated as
  already converged and skipped the UDS PUT. This prevented the datapath from
  revalidating a recreated tap. The fix limits the
  `recovered_before_submit` short-circuit to genuinely reused pending
  snapshots; normal full-resync always submits to datapath for authoritative
  runtime validation.
- The second tap recreate run exposed a Rust datapath plan gap: same ifname with
  changed ifindex was treated as an `update`, so status moved to the new ifindex
  but XDP was not reattached. The fix treats same-port/same-ifname/different
  ifindex as binding drift and plans `detach + attach`.
- Final tap recreate smoke passed on `compute-1.example.test`: baseline attach used
  ifindex `53`, hard reboot recreated the tap as ifindex `54`, full-resync
  reused generation `53`, reattached the port, confirmed XDP, kept VM
  connectivity, and rollback returned `managed_ports=[]`.
- Added and ran `neutron_aria_vm_migration_smoke.sh` in both directions:
  `compute-1.example.test -> compute-2.example.test` and
  `compute-2.example.test -> compute-1.example.test`.
- Migration source phase attaches the source tap, triggers Nova live migration,
  waits for server and Neutron port binding to move, waits for source tap
  absence, then full-resyncs the old host and requires the target port to be
  absent from `managed_ports`.
- Migration destination phase full-resyncs the new host, requires the target
  port to become managed with the local ifindex, verifies XDP attachment and VM
  reachability, then rolls back.
- Final state after the bidirectional migration smoke: VM and Neutron port are
  back on `compute-1.example.test`; `compute-1` and `compute-2` both report
  `authority_state=ready`, `pending_generation=null`, `wal_replay_failures=0`,
  and `managed_ports=[]`.

**Visible result after completion:**

```text
GET /api/v1/neutron/status shows accepted/applied/classified generation,
per-port status, per-domain status, WAL status, and authority state.
Replaying the same snapshot is safe.
Restarting aria-datapath keeps or reconciles committed state.
No half-applied ACL/QoS/Mirror state is reported as ready.
No requested QoS/Mirror domain is reported as ready before the corresponding
executor and cleanup path exist.
```

---

## 10. Chapter Nine: Test Matrix And Acceptance

### 10.1 Unit Tests

- [ ] Neutron extension attributes.
- [ ] DB CRUD and validators.
- [ ] Binding conflict.
- [ ] Port extension fields.
- [x] Agent base port filtering.
- [x] OVS `external_ids:iface-id` parser.
- [x] OVS `br-int` membership validation.
- [x] Neutron client full-resync pagination.
- [x] Python UDS client base contract.
- [x] Python full-resync skeleton.
- [x] Python local API degraded status model.
- [x] Python ACL source abstraction.
- [x] Python desired-state hash and local generation state.
- [x] Python same desired-state generation reuse.
- [x] Python pending generation restart reuse.
- [x] Python snapshot response errors keep pending state and degrade.
- [x] Python pending snapshot restart convergence and hash-mismatch blocking.
- [x] Python durable pending delete for port delete and migration-source cleanup.
- [x] Python per-port/per-domain status propagation from UDS status to heartbeat.
- [x] Effective ACL computation.
- [x] Effective QoS computation.
- [x] Base Rust UDS schema serde.
- [x] TCP OpenAPI does not expose Neutron UDS paths.
- [ ] Snapshot apply status.
- [ ] Same generation snapshot replay is idempotent.
- [ ] Older generation snapshot is reject/no-op without deleting newer state.
- [ ] Duplicate port delete is idempotent.
- [x] WAL intent without commit recovery classification.
- [x] WAL intent without commit is replayed as `wal_intent_without_commit`.
- [x] WAL commit without separate status file rebuilds status from committed WAL state.
- [x] WAL intent without commit best-effort ACL scrub when affected port details exist.
- [ ] WAL intent without commit deep pinned/runtime scrub.
- [ ] Partial runtime apply without commit recovery.
- [ ] Local write gate.
- [ ] Aria Mirror session/rule validators.
- [ ] Aria Mirror source/target host validation.
- [ ] Aria Mirror unsupported-port classification.

### 10.2 Integration Tests

- [ ] `neutron ext-show aria-acl`.
- [ ] `neutron ext-show aria-qos` after QoS phase.
- [ ] ACL policy/rule/address-set/binding CRUD.
- [ ] `neutron port-show` shows `aria_acl_*`.
- [x] `neutron agent-list` shows Aria agent alive.
- [ ] Full resync after agent restart.
- [x] Port migration source cleanup and destination apply.
- [x] VM reboot/tap recreate recovery.
- [ ] Datapath restart after snapshot preserves or reconciles committed state.
- [ ] Python agent restart reuses generation state and converges by full resync.
- [ ] Second phase: `neutron ext-show aria-mirror`.
- [ ] Second phase: `neutron aria-mirror-session-*` CRUD.
- [ ] Second phase: `neutron aria-mirror-status-show`.

### 10.3 Production Smoke

- [ ] Three-node OVSDB/interface discovery consistency.
- [ ] bpffs/BTF availability.
- [ ] UDS socket permissions.
- [ ] ACL allow/deny behavior.
- [ ] Unsupported SR-IOV behavior.
- [ ] Not-applicable DHCP/router/metadata behavior.
- [ ] QoS bandwidth limit behavior.
- [ ] Rollback behavior.
- [x] One-host ACL allow/deny smoke through fixture source.
- [x] UDS mutation timeout recovery smoke with low request timeout.
- [x] Delete detach crash recovery smoke with one-shot datapath `sigkill`.
- [x] VM reboot/tap recreate recovery smoke.
- [x] VM migration source cleanup and destination apply smoke.
- [ ] Second phase: same-host VM tap mirror behavior.
- [ ] Second phase: physical capture NIC to local analyzer VM in a lab.

### 10.4 Final Acceptance Criteria

The release is accepted when all of the following are true:

```text
neutron ext-show aria-acl succeeds
neutron aria-acl-* commands work in the Legacy CLI environment
neutron port-show shows aria_acl_* fields
neutron agent-list shows neutron-aria-agent alive
VM OVS tap ACL allow/deny works
Rule update takes effect without VM rebuild
VM reboot/tap recreate recovers automatically
Unsupported SR-IOV ports show unsupported
Neutron service ports show not_applicable
Unbound VM ports remain bypass
QoS extension is visible only in QoS phase
aria-qos extension is visible only in QoS phase
neutron aria-qos-* commands work as the product-facing QoS entrypoint
QoS policy binding is executed by Aria, not OVS agent qos extension
qhqos remains outside the Aria QoS path
Rollback keeps original OVS connectivity
```

Second-phase `aria_mirror` acceptance is separate:

```text
neutron ext-show aria-mirror succeeds
neutron aria-mirror-session-* commands work in the Legacy CLI environment
neutron aria-mirror-status-show shows source/target ifindex and counters
Same-host VM tap mirror works for ingress, egress, and both
Global mirror clones all traffic on the selected source/direction to the configured target
Policy mirror can send different IP prefixes/address sets to different analyzer VM ports
Physical capture NIC to local analyzer VM works in a controlled lab
Cross-host target returns CROSS_HOST_UNSUPPORTED
SR-IOV/LinuxBridge/service ports return explicit unsupported/not_applicable status
Deleting the session removes mirror map entries and does not affect original VM traffic
Existing networking_mirror behavior remains unchanged
```

---

## 11. Recommended Work Breakdown

### Milestone A: ACL Control Plane Visible

- Task A1: Python package skeleton.
- Task A2: Extension descriptor.
- Task A3: DB migration.
- Task A4: CRUD plugin.
- Task A5: port-show readonly fields.
- Task A6: Legacy CLI commands.

### Milestone B: Agent Observable

- Task B1: agent skeleton and heartbeat.
- Task B2: full resync.
- Task B3: OVSDB tap discovery.
- Task B4: port eligibility filter.
- Task B5: effective ACL calculator.
- Task B6: status reporter.

### Milestone C: ACL Enforcement

- Task C1: Rust DTO.
- Task C2: UDS router.
- Task C3: snapshot apply skeleton.
- Task C4: ACL map compiler.
- Task C5: attach/re-attach.
- Task C6: allow/deny smoke.

### Milestone D: QoS

- Task D1: enable Neutron QoS API/DB.
- Task D2: add `aria_qos` product facade extension and status table.
- Task D3: add Legacy `neutron aria-qos-*` commands.
- Task D4: effective QoS calculator.
- Task D5: Aria QoS snapshot DTO.
- Task D6: eBPF QoS apply.
- Task D7: QoS smoke through `aria-qos-*` commands.

### Milestone E: Productization

- Task E1: Kolla images.
- Task E2: config templates.
- Task E3: deployment smoke.
- Task E4: metrics/logging.
- Task E5: rollback drill.
- Task E6: runbook and release notes.

### Milestone F: Aria Mirror Phase Two

- Task F1: freeze and document existing `networking_mirror` semantics.
- Task F2: `aria_mirror` extension descriptor and DB migration.
- Task F3: `aria_mirror` service plugin CRUD and RBAC.
- Task F4: Legacy CLI commands.
- Task F5: `neutron-aria-agent` mirror translator.
- Task F6: Aria-agent OpenStack mirror DTO/status integration.
- Task F7: Aria-agent mirror stats sampler and pps/bps rate reporting.
- Task F8: `global_l2 + selective rule` coexistence smoke.
- Task F9: VM tap mirror smoke.
- Task F10: physical capture NIC mirror lab smoke.
- Task F11: second-phase Kolla config and rollout/rollback.

---

## 12. Self-Review

### 12.1 Spec Coverage

- ACL independent API/DB/CLI: covered in Chapters 2 and 3.
- `port-show` readonly expression: covered in 2.4.
- Neutron Server as northbound source of truth: covered across Chapters 2 and 4.
- OVS tap only, service ports excluded: covered in 0.1 and 4.2.
- SR-IOV first-stage unsupported: covered in 0.1, 4.2, and 10.3.
- QoS native model reuse: covered in Chapter 7.
- Aria QoS product facade: covered in 7.1 and 7.2.
- No OVS agent QoS execution: covered in 7.1 and 10.4.
- Aria Mirror second-phase plan: covered in Chapter 9.
- Aria Mirror `global_l2 + selective rule` verified semantics: covered in 9.0, 9.4, and 9.6.
- Aria Mirror stats and pps/bps rate calculation: covered in 9.2, 9.4, 9.5, and 9.6.
- Kolla productization: covered in section 8.
- Smoke and rollback: covered in Chapters 8, 9, and 10.

### 12.2 Placeholder Scan

This plan contains no unfinished steps. Commands use shell variables such as `$PORT_ID` and `$DHCP_PORT_ID` for environment-specific Neutron object IDs captured during smoke setup; product image names are selected by the release pipeline, while required files and validation behavior are specified above.

### 12.3 Type And Naming Consistency

The plan consistently uses:

```text
aria-acl             Neutron extension alias
aria_acl_*           DB table and Python symbol prefix
aria-qos            Product-facing QoS extension/CLI facade
aria_qos_*          Status/capability table and Python symbol prefix; no policy/rule DB duplication
neutron-aria-agent   compute-side Python agent
aria-agent           existing Rust binary
aria_acl_*           port response readonly fields
aria-mirror          Neutron extension alias for second-phase mirror
aria_mirror_*        DB table and Python symbol prefix for second-phase mirror
```
