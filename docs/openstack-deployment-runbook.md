# OpenStack Deployment Runbook

Status: operational checklist for the v0.9 Neutron agent mode.

This runbook describes how to enable the integration safely. It does not replace
the design documents:

- `neutron-managed-domains-contract.md`: short control-plane contract.
- `openstack-neutron-agent-mode.md`: full architecture and gates.
- `aria-acl-neutron-extension-product-design.md`: `aria_acl` product extension.
- `openstack-target-env-discovery.md`: target environment evidence.

## Runtime Shape

Recommended production shape:

| Component | Shape | Responsibility |
| --- | --- | --- |
| `neutron-aria-agent` | OpenStack compute-side Python agent/container | Reads Neutron state, builds snapshots, reports heartbeat/status. |
| `aria-datapath` / `aria-agent` | Separate privileged datapath container or host service | Loads eBPF, owns WAL/state, exposes local UDS, applies snapshots. |
| `ariactl` | Datapath image and operator toolbox | Local read/status/debug; local writes are gated by `managed_domains`. |

Do not bind-mount `aria-agent` into the OVS agent as the long-term production
shape. Keep datapath privilege and lifecycle separate from Neutron's OVS agent.

## Required Mounts And Permissions

Minimum host resources for `aria-datapath`:

| Path / Capability | Purpose |
| --- | --- |
| `/sys/fs/bpf` | Pinned maps and links. |
| `/run/aria` | Unix socket directory shared with `neutron-aria-agent`. |
| `/var/lib/aria-agent` | WAL and runtime state. |
| `/run/openvswitch` or equivalent OVSDB access | Validate tap and `external_ids:iface-id`. |
| `CAP_NET_ADMIN`, BPF capability set, netlink access | eBPF attach and qdisc/map operations. |

Target permissions:

```text
/run/aria                 root:neutron-aria 0770
/run/aria/aria-agent.sock aria-datapath:neutron-aria 0660
```

Production hardening uses Unix peer credential validation and audit logging;
filesystem permissions are only the first layer. The safe default bundle keeps
peer credential enforcement disabled until N0.5 records the final container
uid/gid allow-list, but it must keep the socket non-world-writable.

## Safe Defaults

Before the target environment is fully verified:

```ini
[agent]
managed_domains = acl
full_resync_enabled = false

[neutron]
port_source = disabled

[aria]
socket_path = /run/aria/aria-agent.sock

[acl]
source = disabled
```

`integration_mode=coexist` is written by `neutron-aria-agent` into snapshot
bodies only; it must not appear in `neutron-aria-agent.ini`.

Use fixture input only for CI/smoke:

```ini
[acl]
source = fixture
fixture_path = /etc/neutron-aria-agent/acl-fixture.json
```

Production ACL input requires:

```ini
[acl]
source = neutron
```

and a working `aria_acl` Neutron service plugin/API/DB.

## Enablement Gates

Enable in this order:

1. **N0.5-lite discovery**

   Verify OS/kernel, BTF, bpffs, OVS bridge, tap naming, UDS directory, and
   container mounts. Record command, expected result, actual result, and evidence
   in `openstack-target-env-discovery.md`.

   Use the read-only discovery smoke on each target host:

   ```bash
   sudo EVIDENCE_ROOT=/var/tmp/neutron-aria-n05-discovery \
     REPO_ROOT=$(pwd) \
     deploy/kolla/smoke/neutron_aria_n05_discovery_smoke.sh
   ```

   Copy the generated evidence directory back under
   `docs/evidence/openstack-n05-lite/` and update
   `openstack-target-env-discovery.md`. Non-pass dispositions must remain
   visible as `degraded`, `unsupported`, `not_applicable`, or `fail`; do not
   hide them behind a green stage label.

   Validate the copied evidence before marking G4 discovery accepted:

   ```bash
   python ci/check_n05_discovery_evidence.py
   ```

   Current 2026-06-30 evidence is summarized in:

   ```text
   docs/evidence/openstack-n05-lite/2026-06-30-discovery-summary.md
   ```

   The 2026-06-30 G4 discovery evidence is accepted with zero `fail` across
   `ostack2/3/4`. QoS, Trunk, and `tc` are explicitly `unsupported` in the
   target environment. UDS peercred enforcement/audit is a config-gated
   hardening check in `ci/check_neutron_stage1.py`; production enablement must
   set `neutron_peercred_enforce=true` and a recorded uid/gid allow-list before
   declaring peer auth enforced on site.

   Current 2026-06-30 UDS hardening evidence is summarized in:

   ```text
   docs/evidence/openstack-n05-lite/2026-06-30-uds-hardening-summary.md
   ```

   Validate the copied evidence:

   ```bash
   python ci/check_uds_hardening_evidence.py
   ```

   The evidence records `neutron_aria_agent` UID/GID `42435` and groups
   `42435 42400` on all three hosts. It also includes reversible hardened
   rollout proofs on `ostack2.bj159.net`, `ostack3.bj159.net`, and
   `ostack4.bj159.net`: the peercred-enabled datapath image tightened the
   socket to `root:42435 0660`, accepted a UDS probe from the `neutron` user,
   wrote an allow audit record, and restored the original container/config.
   Persistent hardened rollout across all target hosts remains a separate
   production change.

2. **Datapath inert/bypass smoke**

   Start `aria-datapath` with the UDS socket available. Confirm health/status and
   that degraded Aria state does not affect existing OVS forwarding.

3. **UDS contract smoke**

   Confirm:

   ```text
   GET /api/v1/neutron/capabilities
   GET /api/v1/neutron/status
   PUT /api/v1/neutron/snapshot
   DELETE /api/v1/neutron/ports/{port_id}
   ```

   Snapshot timeout must be recovered through status/full resync, not by assuming
   the request failed.

4. **Domain authority smoke**

   Apply a snapshot with:

   ```json
   {"managed_domains": ["acl"]}
   ```

   Required result:

   - local ACL writes are rejected with
     `LOCAL_WRITE_BLOCKED_FOR_NEUTRON_MANAGED_DOMAIN`;
   - local QoS/Mirror writes remain allowed;
   - read/status/stats/trace remain allowed.

5. **Full resync read-only preview**

   Set `port_source=neutronclient` while keeping feature input disabled or
   fixture-only. Confirm eligible VM OVS taps and ignored service ports are
   classified correctly.

6. **Production ACL source**

   Enable `acl.source=neutron` only after the `aria_acl` plugin/API/DB and
   `NeutronAclSource` are implemented and tested. Run
   `deploy/kolla/smoke/neutron_aria_acl_neutron_source_smoke.sh` to verify that
   the `aria_acl` extension is visible and the agent can read ACL input through
   Neutron before enabling broad production resync.

7. **Full resync production enablement**

   Enable:

   ```ini
   full_resync_enabled = true
   ```

   only after UDS, N0.5, domain authority smoke, and ACL input source gates pass.

8. **Rollback connectivity smoke**

   Run the rollback connectivity smoke on a known reachable VM tap:

   ```bash
   sudo EVIDENCE_ROOT=/var/tmp/neutron-aria-rollback-connectivity \
     REPO_ROOT=$(pwd) \
     VM_IP=<reachable-vm-ip> \
     EXPECTED_PORT_ID=<neutron-port-id> \
     EXPECTED_IFNAME=<tap-ifname> \
     CHECK_AGENT_STOP=true \
     CHECK_DATAPATH_STOP=true \
     deploy/kolla/smoke/neutron_aria_rollback_connectivity_smoke.sh
   ```

   The smoke must prove baseline ping, ACL-induced traffic block, UDS rollback
   to zero managed ports, post-rollback ping recovery, and that stopping
   `neutron-aria-agent` or `aria-datapath` does not break OVS baseline
   forwarding.

   Current 2026-06-30 evidence is summarized in:

   ```text
   docs/evidence/openstack-n05-lite/2026-06-30-g7-rollback-summary.md
   ```

   This closes the first external-to-VM rollback evidence on `ostack2`,
   including `neutron-aria-agent` and `aria-datapath` stop/restart connectivity;
   full N0.5 still requires VM-to-external direction, DHCP/metadata/IPv6 ND
   bypass evidence.

   Do not count host-initiated ping echo-reply as VM-to-external proof. Under
   the current stateful ACL model it is reverse traffic for an inbound flow.
   VM-to-external acceptance needs guest-originated traffic through SSH, QEMU
   guest agent, or a short-lived test VM with known credentials.

   When a guest execution path exists, pass the guest-originated probe through
   `TRAFFIC_CHECK_CMD`, for example an SSH command that runs
   `ping -c 2 -W 1 <host-or-external-ip>` inside the VM while
   `ACL_DIRECTION=egress`.

## Stage-Two ACL MVP Delivery Gate

For the stage-two ACL MVP, do not hand-edit one live container and call it
done. Use the packaged gate and run it on every active `neutron_server` node
behind the Neutron API endpoint.

Build and check the bundle from the repo:

```bash
bash deploy/kolla/package/build_stage2_acl_bundle.sh
python ci/check_neutron_stage2_acl.py
python ci/check_neutron_stage1.py
```

Copy the bundle to each target node and run:

```bash
sudo REPO_ROOT=$(pwd) deploy/kolla/smoke/neutron_aria_acl_stage2_gate_smoke.sh install
```

The gate performs the minimum repeatable delivery sequence:

| Step | Behavior |
| --- | --- |
| neutron-server plugin install | Backs up `neutron.conf`, copies the `neutron_aria` package, enables `aria_acl`, merges policy rules into `/etc/neutron/policy.json`, and restarts `neutron_server`. |
| DB migration | Runs `aria_acl` upgrade and schema check for the seven stage-two tables. |
| agent package install | Backs up the current egg, installs the new `neutron_aria` egg, and restarts `neutron_aria_agent` so heartbeat code is loaded. |
| CRUD smoke | Verifies plugin-level DB CRUD and REST CRUD through local neutron-server. |
| production ACL source smoke | Verifies `aria_acl` read path, `NeutronAclSource`, full-resync snapshot, UDS rollback, and `aria_acl_port_statuses` reportback. |
| heartbeat smoke | Verifies Neutron agent heartbeat summary fields: generation lag, accepted/applied generation, domain counts, and degraded reasons. |
| rollback connectivity smoke | Verifies ACL rollback restores VM connectivity and stopping `neutron-aria-agent` / `aria-datapath` does not break OVS forwarding. |

Multi-node rule:

- Install the same bundle on all active `neutron_server` nodes before declaring
  the API gate stable. A mixed deployment can randomly return old API fields
  depending on which neutron-server handles the request.
- Compute-only hosts still need their `neutron_aria_agent` package/container
  flow, but they do not receive the neutron-server plugin.

Field evidence from 2026-06-29 is recorded in
`docs/evidence/openstack-n05-lite/2026-06-29-stage2-acl/summary.md`.

This evidence advances the stage-two ACL MVP gate only. It does not complete
full N0.5, does not enable QoS/Mirror, and does not open RabbitMQ event
consumption. UDS peercred hooks are present as a stage-one hardening gate, and
`ostack2.bj159.net`, `ostack3.bj159.net`, and `ostack4.bj159.net` have
reversible `REQUIRE_HARDENED=true` proofs. Persistent site-level enforcement
remains closed until the peercred-enabled datapath image and hardened socket
config are rolled out across the target hosts.

## Smoke Checklist

Minimum production smoke:

| Check | Expected Result |
| --- | --- |
| VM tap on local host appears in full snapshot | Eligible VM port has `managed_domains=["acl"]` or configured domains. |
| DHCP/router/metadata/service ports | Not managed or marked unsupported/not applicable. |
| ACL absent | ACL domain `not_requested`, `effective_action=bypass`. |
| ACL policy valid | ACL domain `ready`, `effective_action=enforce`. |
| ACL policy missing/invalid | ACL domain `degraded`, `effective_action=bypass`; OVS forwarding unaffected. |
| Local `ariactl policy add` on ACL-managed instance | Rejected with `LOCAL_WRITE_BLOCKED_FOR_NEUTRON_MANAGED_DOMAIN`. |
| Local `ariactl qos add` when only ACL is managed | Allowed. |
| Datapath restart | WAL/status recovers or full resync repairs; no unmanaged tap takeover. |
| UDS hardening evidence-only smoke | `neutron_aria_uds_hardening_smoke.sh` records uid/gid allow-list candidates and current socket/audit disposition without mutating the host. |
| UDS hardened enforcement smoke | With `REQUIRE_HARDENED=true`, socket has no other-user bits, audit log exists, and peercred enforcement uses the recorded uid/gid allow-list. |

## Rollback

Safe rollback order:

1. Set `full_resync_enabled=false` in `neutron-aria-agent`.
2. Set `[acl] source=disabled` or remove ACL bindings in Neutron.
3. Allow one full resync/delete cycle to clear Neutron-managed datapath state.
4. Stop `neutron-aria-agent`.
5. Keep OVS agent and OVS forwarding untouched.
6. Stop or restart `aria-datapath` only after confirming OVS connectivity remains healthy.

Never use socket deletion as the primary rollback method. A missing socket should
produce degraded status and trigger recovery/full resync, not silently switch to
local writes for managed domains.

## Break-Glass

Break-glass is not a default product path. If implemented:

- it must be explicit;
- it must write a local override WAL, not Neutron WAL;
- rejoin must default to Neutron wins;
- local overrides must be archived or discarded before full resync resumes.
