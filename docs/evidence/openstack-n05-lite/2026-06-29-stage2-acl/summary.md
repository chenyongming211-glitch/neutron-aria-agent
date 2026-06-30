# 2026-06-29 Stage-Two ACL MVP Evidence

Status: field smoke evidence for the production ACL input/full-resync gate.
Later 2026-06-30 records complete the stage-two G4/G7/UDS acceptance evidence
around this original ACL delivery gate.

Target environment:

| Item | Value |
| --- | --- |
| Neutron server nodes exercised | `ostack2.bj159.net` (`10.58.159.2`), `ostack3.bj159.net` (`10.58.159.3`) |
| Agent hosts visible in Neutron | `ostack2.bj159.net`, `ostack3.bj159.net`, `ostack4.bj159.net` |
| Neutron runtime constraint | legacy Python 2 Neutron; no `neutron_lib`; plugin path must use old Neutron service-plugin style |
| Delivery artifact | `dist/kolla/neutron-aria-stage2-acl-kolla-bundle.tgz` |
| Gate script | `deploy/kolla/smoke/neutron_aria_acl_stage2_gate_smoke.sh install` |

## Commands

Local package and checks:

```bash
bash deploy/kolla/package/build_stage2_acl_bundle.sh
python ci/check_neutron_stage2_acl.py
python ci/check_neutron_stage1.py
```

Field install gate on each neutron-server node:

```bash
scp dist/kolla/neutron-aria-stage2-acl-kolla-bundle.tgz root@<host>:/tmp/
ssh root@<host> '
  set -euo pipefail
  work=/tmp/neutron_aria_stage2_05_hb2_$(date +%Y%m%d%H%M%S)
  mkdir -p "$work"
  tar -xzf /tmp/neutron-aria-stage2-acl-kolla-bundle.tgz -C "$work"
  cd "$work"
  REPO_ROOT="$work" bash deploy/kolla/smoke/neutron_aria_acl_stage2_gate_smoke.sh install
'
```

## Local Results

| Check | Result |
| --- | --- |
| `ci/check_neutron_stage2_acl.py` | `Ran 82 tests ... OK` |
| `ci/check_neutron_stage1.py` | `Ran 159 tests ... OK`; Rust checks skipped because local `cargo` was unavailable |
| bundle build | Built `dist/kolla/neutron-aria-stage2-acl-kolla-bundle.tgz` |

## Field Results

`ostack2.bj159.net`:

| Gate | Observed result |
| --- | --- |
| `aria-acl` extension | visible in `neutron extension-list` |
| DB migration | `found=aria_acl_address_set_members,aria_acl_address_sets,aria_acl_bindings,aria_acl_policies,aria_acl_port_statuses,aria_acl_rbac,aria_acl_rules` |
| REST CRUD | `rest_acl_crud=ok` |
| NeutronAclSource | `aria_acl_source policies=1 rules=1 bindings=1` |
| Full resync | snapshot generation `78` submitted and accepted/applied |
| Managed ports | `MANAGED_COUNT=5` |
| Port-status reportback | `aria_acl_port_statuses host=ostack2.bj159.net managed=5 reported=6 generation=78` |
| Rollback | all five managed ports deleted through UDS; `rollback_remaining_managed_ports=0` |
| Heartbeat summary | `heartbeat_summary_fields=ok host=ostack2.bj159.net` |
| Final gate | `stage-two ACL gate ok` |

`ostack3.bj159.net`:

| Gate | Observed result |
| --- | --- |
| `aria-acl` extension | visible in `neutron extension-list` |
| DB migration | same seven `aria_acl` tables found |
| REST CRUD | `rest_acl_crud=ok` |
| NeutronAclSource | `aria_acl_source policies=1 rules=1 bindings=1` |
| Full resync | snapshot generation `15` submitted and accepted/applied |
| Managed ports | `MANAGED_COUNT=0` |
| Port-status reportback | `aria_acl_port_statuses host=ostack3.bj159.net managed=0 reported=0 generation=15` |
| Rollback | `rollback_remaining_managed_ports=0` |
| Heartbeat summary | `heartbeat_summary_fields=ok host=ostack3.bj159.net` |
| Final gate | `stage-two ACL gate ok` |

## Delivery Constraints Confirmed

- The `aria_acl` plugin, extension map, policy rules, and package files must be installed on every active `neutron_server` node behind the Neutron API endpoint. Updating only one node can return mixed API fields depending on which server handles the request.
- The install gate backs up `neutron.conf`, merges `aria_acl` policy rules into `/etc/neutron/policy.json`, runs DB upgrade/check, installs the `neutron_aria` egg into `neutron_aria_agent`, restarts the agent container, and then runs CRUD/source/full-resync/heartbeat smokes.
- Agent restart after egg install is required for long-running heartbeat payloads to include the new generation/domain summary fields.
- Normal rollback does not drop `aria_acl` DB tables. DB downgrade remains explicit test-only behavior through `ROLLBACK_DB_ON_ROLLBACK=true`.

## Scope Boundaries

- This evidence proves the stage-two ACL MVP delivery gate on the exercised neutron-server nodes.
- G4/N0.5 discovery, hook direction, rollback connectivity, DHCP/metadata/IPv6
  disposition, and UDS hardening evidence are recorded in the later
  2026-06-30 summaries under `docs/evidence/openstack-n05-lite/`.
- It does not enable QoS/Mirror or RabbitMQ event consumption.
- It does not replace a future product image/registry release flow.
