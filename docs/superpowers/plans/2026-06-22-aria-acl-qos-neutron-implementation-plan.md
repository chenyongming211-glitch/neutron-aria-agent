# Aria ACL/QoS Neutron Productization Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a productized OpenStack Neutron integration where Aria ACL is an independent Neutron extension, QoS reuses Neutron native QoS policy/rule models, and Aria enforces ACL/QoS only on eligible VM OVS tap ports.

**Architecture:** Neutron Server is the source of truth for ACL/QoS API, DB, RBAC, port binding, and runtime status. `neutron-aria-agent` runs on compute nodes, consumes Neutron state, discovers local OVS tap interfaces through `external_ids:iface-id`, computes per-port effective ACL/QoS snapshots, and sends those snapshots to local `aria-agent` over `/run/aria/aria-agent.sock`. `aria-agent` does not access Neutron; it only validates snapshots, updates eBPF maps, preserves WAL/runtime state, and reports per-domain status.

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
6. QoS native Neutron enablement and Aria execution.
7. Kolla packaging, smoke, rollout, rollback.

### 0.3 Commit Discipline

- Commit after each task group that passes tests.
- Keep ACL and QoS commits separate.
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
    services/
      __init__.py
      aria_acl/
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
    tests/
      test_policy_cli.py
      test_rule_cli.py
      test_binding_cli.py
      test_status_cli.py
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
- Create: `openstack/neutron_aria/neutron_aria/agent/main.py`
- Create: `openstack/neutron_aria/neutron_aria/agent/config.py`
- Create: `deploy/kolla/config/neutron-aria-agent.ini`

- [ ] Load oslo config compatible with current Python 2 Neutron environment.
- [ ] Read `host`, RabbitMQ credentials, Neutron config, OVS bridge name, OVSDB connection, and UDS socket path.
- [ ] Register as Neutron agent type `Aria ACL agent`.
- [ ] Heartbeat to Neutron agent table.
- [ ] Provide process logs with host, generation, dirty target count, and status update count.

**Expected visible result:**

```bash
neutron agent-list | grep aria
```

Expected: `neutron-aria-agent` shows alive on each enabled compute.

### 4.2 Inventory And Port Filtering

**Files:**
- Create: `openstack/neutron_aria/neutron_aria/agent/inventory.py`
- Create: `openstack/neutron_aria/neutron_aria/agent/ovsdb.py`
- Test: `openstack/neutron_aria/neutron_aria/tests/unit/test_agent_inventory.py`

- [ ] Pull ports where `binding:host_id == local_host`.
- [ ] Query OVSDB interfaces on `br-int`.
- [ ] Build `port_id -> tap_name -> ifindex` by matching OVS `external_ids:iface-id`.
- [ ] Mark eligible VM ports only when:
  - `binding:vif_type == ovs`
  - `binding:vnic_type in ["normal", "", None]`
  - `device_owner` is empty or starts with `compute:`
  - local tap exists
- [ ] Mark `network:dhcp`, router, metadata, LinuxBridge, SR-IOV, missing tap, and unknown types as `not_applicable`, `unsupported`, or `unknown` with explicit reason.

**Expected visible result:**

`neutron aria-acl-port-status-show $DHCP_PORT_ID` returns `not_applicable`.

### 4.3 Effective ACL Computation

**Files:**
- Create: `openstack/neutron_aria/neutron_aria/agent/effective_acl.py`
- Test: `openstack/neutron_aria/neutron_aria/tests/unit/test_effective_acl.py`

- [ ] Resolve port-level binding first.
- [ ] Resolve network-level binding second.
- [ ] Return no ACL for unsupported/not_applicable ports.
- [ ] Expand address-set members into snapshot-ready structures.
- [ ] Sort rules by direction and ascending priority.
- [ ] Compute `effective_revision` from policy/rules/address-sets/binding revisions.
- [ ] Emit `not_requested + bypass` when no binding exists.

**Expected visible result:**

```bash
neutron aria-acl-effective-show --port $PORT_ID
```

Expected: shows source `port`, `network`, or `none`.

### 4.4 UDS Client And Snapshot Submission

**Files:**
- Create: `openstack/neutron_aria/neutron_aria/agent/uds_client.py`
- Create: `openstack/neutron_aria/neutron_aria/agent/event_loop.py`

- [ ] Call `GET /api/v1/neutron/capabilities`.
- [ ] Validate schema version, body size, timeout, and required domains.
- [ ] Submit `PUT /api/v1/neutron/snapshot`.
- [ ] Delete local runtime with `DELETE /api/v1/neutron/ports/{port_id}` when a port migrates away or is deleted.
- [ ] Treat UDS failures as Aria runtime degraded, not as OVS connectivity failure.

**Expected visible result:**

Agent logs show snapshot accepted with generation number.

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

### 5.1 Snapshot DTO

**Files:**
- Create: `api/src/neutron.rs`
- Modify: `api/src/lib.rs`

- [ ] Define `NeutronSnapshotRequest`.
- [ ] Define `NeutronPortSnapshot`.
- [ ] Define `NeutronAclPolicySnapshot`.
- [ ] Define `NeutronQosPolicySnapshot`.
- [ ] Define `NeutronDomainStatus`.
- [ ] Define enums for `RuntimeStatus`, `SupportDisposition`, and `EffectiveAction`.
- [ ] Derive `Serialize`, `Deserialize`, and `utoipa::ToSchema` where supported by current crate setup.

**Verification command:**

```bash
cargo test -p aria-api neutron --all-features
```

Expected: DTO serde tests pass.

### 5.2 Unix Socket Router

**Files:**
- Create: `agent/src/api_handlers/neutron.rs`
- Create: `agent/src/neutron_socket.rs`
- Modify: `agent/src/api_handlers/mod.rs`
- Modify: `agent/src/api_routes.rs`
- Modify: `agent/src/main.rs`

- [ ] Bind Neutron API only to Unix socket path from config, default `/run/aria/aria-agent.sock`.
- [ ] Do not expose Neutron snapshot routes on TCP REST/OpenAPI listener.
- [ ] Add routes:
  - `GET /api/v1/neutron/capabilities`
  - `GET /api/v1/neutron/status`
  - `PUT /api/v1/neutron/snapshot`
  - `DELETE /api/v1/neutron/ports/{port_id}`
- [ ] Enforce socket file mode/group in startup or deployment scripts.
- [ ] Reject requests that exceed configured body size.

**Verification command:**

```bash
cargo test -p aria-agent neutron_socket
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
- Modify: `agent/src/api_handlers/groups.rs`
- Modify: `agent/src/api_handlers/policies.rs`
- Modify: `agent/src/api_handlers/qos.rs`
- Modify: `core/src/state.rs`

- [ ] Mark Neutron-managed ports in runtime state.
- [ ] Reject local `ariactl` writes that would modify group/ACL/QoS for a Neutron-managed port.
- [ ] Allow read-only stats/trace operations.
- [ ] Add explicit break-glass mode only if product owner approves; default plan does not enable it.

**Expected visible result:**

Local `ariactl` write against Neutron-managed port returns a clear error instead of silently overriding Neutron state.

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
- [ ] Detect ifindex changes and require reattach.
- [ ] On VM reboot/tap recreate, keep desired state but rebuild runtime.
- [ ] On port migration away, detach and delete local port runtime.

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
- [ ] Reboot VM and prove tap recreate recovery.
- [ ] Verify DHCP/metadata path is not affected when no explicit VM ACL blocks it.

---

## 7. Chapter Six: QoS Reuse Of Neutron Native Model

### 7.1 Neutron QoS Enablement

**Files:**
- Modify: Kolla `neutron.conf` template
- Modify: Kolla `ml2_conf.ini` template

- [ ] Add `qos` to `service_plugins` only in QoS rollout phase.
- [ ] Add `qos` to `[ml2] extension_drivers`.
- [ ] Do not add `qos` to OVS agent `extensions`; keep onsite `extensions = mirror`.
- [ ] Verify:

```bash
openstack extension list --network | grep qos
neutron ext-list | grep qos
```

Expected: `qos` visible only after QoS phase configuration.

### 7.2 Aria QoS Translator

**Files:**
- Create: `openstack/neutron_aria/neutron_aria/agent/effective_qos.py`
- Modify: `openstack/neutron_aria/neutron_aria/agent/event_loop.py`
- Modify: `api/src/neutron.rs`
- Modify: `core/src/qos_ops.rs`

- [ ] Pull QoS policy bound to port.
- [ ] Pull QoS policy inherited from network.
- [ ] Apply precedence: port-level > network-level > none.
- [ ] Support bandwidth limit rule fields:
  - `max_kbps`
  - `max_burst_kbps`
  - direction when available
- [ ] Mark unsupported rules as QoS domain degraded, not silently ignored.
- [ ] Translate into Aria snapshot.

### 7.3 QoS Smoke Tests

**Files:**
- Create: `deploy/kolla/smoke/qos_smoke.sh`

- [ ] Create Neutron QoS policy.
- [ ] Create bandwidth limit rule.
- [ ] Bind to a VM port.
- [ ] Verify `neutron-aria-agent` computes effective QoS.
- [ ] Verify Aria runtime status shows QoS applied.
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
- [ ] Start with ACL-only config:

```ini
[DEFAULT]
service_plugins = router,network_ip_availability,mirror,aria_acl
```

- [ ] Validate existing `router`, `network_ip_availability`, and `mirror` APIs still work.

### 8.2 Neutron-Aria-Agent Image

**Files:**
- Create: `deploy/kolla/neutron-aria-agent/Dockerfile`
- Create: `deploy/kolla/config/neutron-aria-agent.ini`

- [ ] Install Python 2 compatible package.
- [ ] Mount Neutron config and messaging credentials.
- [ ] Mount `/run/aria`.
- [ ] Read OVSDB with the least privilege available in the target product.
- [ ] Ensure it does not mount `/sys/fs/bpf` and does not require eBPF privileges.

### 8.3 Aria-Agent Image

**Files:**
- Create: `deploy/kolla/aria-agent/Dockerfile`
- Create: `deploy/kolla/config/aria-agent-openstack.toml`

- [ ] Include existing `aria-agent` binary.
- [ ] Include eBPF artifacts.
- [ ] Mount `/sys/fs/bpf`.
- [ ] Mount `/sys/kernel/btf/vmlinux` read-only when needed.
- [ ] Mount `/run/aria`.
- [ ] Mount `/var/lib/aria-agent`.
- [ ] Provide log path and metrics endpoint according to product standards.

### 8.4 Rollout And Rollback

**Files:**
- Create: `deploy/kolla/smoke/rollback_smoke.sh`

- [ ] Rollout step 1: deploy Neutron Server extension with `enforcement_enabled=false`.
- [ ] Rollout step 2: deploy `neutron-aria-agent` and observe full resync/status only.
- [ ] Rollout step 3: deploy `aria-agent` UDS snapshot API.
- [ ] Rollout step 4: enable ACL enforcement for selected test ports.
- [ ] Rollout step 5: enable broader ACL enforcement.
- [ ] Rollout step 6: enable QoS only after ACL stable.
- [ ] Rollback closes `enforcement_enabled`, sends cleanup snapshots, stops `neutron-aria-agent`, removes service plugin from config, and preserves DB tables.

---

## 9. Chapter Eight: Test Matrix And Acceptance

### 9.1 Unit Tests

- [ ] Neutron extension attributes.
- [ ] DB CRUD and validators.
- [ ] Binding conflict.
- [ ] Port extension fields.
- [ ] Agent port filtering.
- [ ] Effective ACL computation.
- [ ] Effective QoS computation.
- [ ] UDS schema serde.
- [ ] Snapshot apply status.
- [ ] Local write gate.

### 9.2 Integration Tests

- [ ] `neutron ext-show aria-acl`.
- [ ] ACL policy/rule/address-set/binding CRUD.
- [ ] `neutron port-show` shows `aria_acl_*`.
- [ ] `neutron agent-list` shows Aria agent alive.
- [ ] Full resync after agent restart.
- [ ] Port migration source cleanup and destination apply.
- [ ] VM reboot/tap recreate recovery.

### 9.3 Production Smoke

- [ ] Three-node OVSDB/interface discovery consistency.
- [ ] bpffs/BTF availability.
- [ ] UDS socket permissions.
- [ ] ACL allow/deny behavior.
- [ ] Unsupported SR-IOV behavior.
- [ ] Not-applicable DHCP/router/metadata behavior.
- [ ] QoS bandwidth limit behavior.
- [ ] Rollback behavior.

### 9.4 Final Acceptance Criteria

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
QoS policy binding is executed by Aria, not OVS agent qos extension
Rollback keeps original OVS connectivity
```

---

## 10. Recommended Work Breakdown

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
- Task D2: effective QoS calculator.
- Task D3: Aria QoS snapshot DTO.
- Task D4: eBPF QoS apply.
- Task D5: QoS smoke.

### Milestone E: Productization

- Task E1: Kolla images.
- Task E2: config templates.
- Task E3: deployment smoke.
- Task E4: metrics/logging.
- Task E5: rollback drill.
- Task E6: runbook and release notes.

---

## 11. Self-Review

### 11.1 Spec Coverage

- ACL independent API/DB/CLI: covered in Chapters 2 and 3.
- `port-show` readonly expression: covered in 2.4.
- Neutron Server as northbound source of truth: covered across Chapters 2 and 4.
- OVS tap only, service ports excluded: covered in 0.1 and 4.2.
- SR-IOV first-stage unsupported: covered in 0.1, 4.2, and 9.3.
- QoS native model reuse: covered in Chapter 7.
- No OVS agent QoS execution: covered in 7.1 and 9.4.
- Kolla productization: covered in Chapter 8.
- Smoke and rollback: covered in Chapters 8 and 9.

### 11.2 Placeholder Scan

This plan contains no unfinished steps. Commands use shell variables such as `$PORT_ID` and `$DHCP_PORT_ID` for environment-specific Neutron object IDs captured during smoke setup; product image names are selected by the release pipeline, while required files and validation behavior are specified above.

### 11.3 Type And Naming Consistency

The plan consistently uses:

```text
aria-acl             Neutron extension alias
aria_acl_*           DB table and Python symbol prefix
neutron-aria-agent   compute-side Python agent
aria-agent           existing Rust binary
aria_acl_*           port response readonly fields
```
