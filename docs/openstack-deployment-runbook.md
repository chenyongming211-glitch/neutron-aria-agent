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
rpc_events_enabled = false
incremental_rpc_enabled = false
revisionless_incremental_mode = disabled

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
| RPC P2 package smoke | `neutron_aria_rpc_event_smoke.sh` passes before any live RabbitMQ canary. |
| RPC P2 live fanout smokes | A/B, foreign-host filtering, and source-host cleanup pass before production enablement. |
| P3-1 projection heartbeat smoke | `neutron_aria_heartbeat_smoke.sh` passes with `REQUIRE_P3_PROJECTION_FIELDS=true` on all target hosts; `incremental_rpc_enabled` remains `false`. |
| P3 runtime prerequisites | Long-running `neutron_aria_agent` has Neutron API credentials for `port_source=neutronclient` / `acl.source=neutron`, and target Neutron returns a trustworthy port `revision_number`; otherwise stay on P2 full-resync fallback unless a controlled test explicitly sets `revisionless_incremental_mode=experimental`. |
| Datapath restart | WAL/status recovers or full resync repairs; no unmanaged tap takeover. |
| UDS hardening evidence-only smoke | `neutron_aria_uds_hardening_smoke.sh` records uid/gid allow-list candidates and current socket/audit disposition without mutating the host. |
| UDS hardened enforcement smoke | With `REQUIRE_HARDENED=true`, socket has no other-user bits, audit log exists, and peercred enforcement uses the recorded uid/gid allow-list. |

## RPC P2 Canary Enablement

`rpc_events_enabled=true` is allowed only after production ACL source,
full-resync, rollback, and N3 fault/lifecycle gates have passed or have an
explicit written waiver. It is a latency switch over the existing P1
full-resync path, not an incremental apply feature.

Keep the packaged default as polling-only:

```ini
[agent]
full_resync_enabled = true

[neutron]
port_source = neutronclient
rpc_events_enabled = false
incremental_rpc_enabled = false
revisionless_incremental_mode = disabled

[acl]
source = neutron
```

Revisionless legacy Neutron note:

- Production P3 still requires trustworthy port revision data.
- On a controlled test host only, `incremental_rpc_enabled=true` plus
  `revisionless_incremental_mode=experimental` may be used to validate the
  port-scoped runtime path when old Neutron returns no `revision_number`.
- This test mode must not be rolled out as a default. If it fails or any
  locality/capability check is ambiguous, revert to polling or P2 full-resync.

Before enabling RPC events on a production host, require all of the following:

| Gate | Required proof |
| --- | --- |
| package preflight | `deploy/kolla/smoke/neutron_aria_rpc_event_smoke.sh` passes on the installed package. |
| live fanout A/B | `rpc_events_enabled=false` ignores the test fanout and `true` consumes it. |
| multi-host locality | Foreign-host fanout on `ostack2/3/4` does not mutate local managed ports. |
| source cleanup | A previously projected local port moved to another host is deleted locally with `migration_source_cleanup`. |
| recovery baseline | Polling full-resync, UDS status, and rollback/delete cleanup are already passing. |

Enable one host first:

```bash
sudo cp /etc/kolla/neutron-aria-agent/neutron-aria-agent.ini \
  /etc/kolla/neutron-aria-agent/neutron-aria-agent.ini.pre-rpc-p2

sudo sed -i 's/^rpc_events_enabled *=.*/rpc_events_enabled = true/' \
  /etc/kolla/neutron-aria-agent/neutron-aria-agent.ini

sudo docker restart neutron_aria_agent
```

If the container name differs, restart only the `neutron-aria-agent`
service/container used on that host. Do not restart OVS, OVS agent,
neutron-server, or `aria-datapath` for this switch.

Post-enable checks:

- `neutron-aria-agent` starts cleanly with RPC event mode enabled.
- Heartbeat remains active and no unexpected degraded reason appears.
- A bounded test fanout reaches `event_batch_drained`.
- `managed_ports` does not grow for foreign-host events.
- Periodic or manual full-resync remains available as the recovery path.

Rollback to polling-only:

```bash
sudo sed -i 's/^rpc_events_enabled *=.*/rpc_events_enabled = false/' \
  /etc/kolla/neutron-aria-agent/neutron-aria-agent.ini

sudo docker restart neutron_aria_agent
```

After rollback, verify the agent starts with RPC events disabled, no new event
batches are drained, and a normal full-resync/UDS rollback smoke can still
clear any test-managed ports.

Keep P2 closed on additional hosts if any live fanout causes cross-host local
mutation, stale managed ports after source cleanup, repeated full-resync loops,
or RabbitMQ consumer startup failure. The safe fallback is polling-only P1, not
disabling ACL or touching OVS.

## P3 Controlled Incremental Test

P3 port-scoped apply is implemented but remains default-off. Treat it as a
controlled test mode until a separate production rollout decision accepts a
revision-aware environment.

Do not change packaged defaults:

```ini
[neutron]
rpc_events_enabled = false
incremental_rpc_enabled = false
revisionless_incremental_mode = disabled
```

Prerequisites before enabling P3 on a test host:

| Gate | Required proof |
| --- | --- |
| P1 ACL full-resync | `port_source=neutronclient`, `acl.source=neutron`, and `full_resync_enabled=true` already pass on the host. |
| P2 RPC canary | RPC package smoke and live fanout A/B pass with `incremental_rpc_enabled=false`. |
| P3 failure semantics | Scoped UDS failure and unsafe candidate paths fall back to full-resync; invalid ACL remains degraded/bypass. |
| P3 smoke evidence | `docs/evidence/openstack-n05-lite/20260702-p3-5-incremental-smoke/summary.md` or newer evidence exists. |
| Revision policy | Production test requires trustworthy port `revision_number`; old Neutron may use `revisionless_incremental_mode=experimental` only as a lab valve. |

Enable a revision-aware P3 test host:

```bash
sudo cp /etc/kolla/neutron-aria-agent/neutron-aria-agent.ini \
  /etc/kolla/neutron-aria-agent/neutron-aria-agent.ini.pre-p3

sudo sed -i 's/^rpc_events_enabled *=.*/rpc_events_enabled = true/' \
  /etc/kolla/neutron-aria-agent/neutron-aria-agent.ini
sudo sed -i 's/^incremental_rpc_enabled *=.*/incremental_rpc_enabled = true/' \
  /etc/kolla/neutron-aria-agent/neutron-aria-agent.ini
sudo sed -i 's/^revisionless_incremental_mode *=.*/revisionless_incremental_mode = disabled/' \
  /etc/kolla/neutron-aria-agent/neutron-aria-agent.ini

sudo docker restart neutron_aria_agent
```

For the current old Neutron lab only, when the target port has no
`revision_number`, replace the last setting with:

```bash
sudo sed -i 's/^revisionless_incremental_mode *=.*/revisionless_incremental_mode = experimental/' \
  /etc/kolla/neutron-aria-agent/neutron-aria-agent.ini
```

This is a test-only switch. It proves the implementation path can run in that
lab; it does not replace revision-aware production acceptance.

Recommended P3 smoke:

```bash
sudo REPO_ROOT=$(pwd) \
  INCREMENTAL_RPC_ENABLED=true \
  REVISIONLESS_INCREMENTAL_MODE=disabled \
  deploy/kolla/smoke/neutron_aria_rpc_fanout_smoke.sh
```

For the old Neutron lab valve only:

```bash
sudo REPO_ROOT=$(pwd) \
  INCREMENTAL_RPC_ENABLED=true \
  REVISIONLESS_INCREMENTAL_MODE=experimental \
  deploy/kolla/smoke/neutron_aria_rpc_fanout_smoke.sh
```

Expected P3 test result:

- disabled case ignores the test fanout;
- enabled case processes exactly one local port update;
- revision-aware or explicit experimental test emits
  `port_scoped_snapshot_complete`;
- default revisionless mode emits no scoped completion and falls back to
  full-resync;
- rollback leaves `managed_ports=0` and no pending generation.

P3 rollback to P2:

```bash
sudo sed -i 's/^incremental_rpc_enabled *=.*/incremental_rpc_enabled = false/' \
  /etc/kolla/neutron-aria-agent/neutron-aria-agent.ini
sudo sed -i 's/^revisionless_incremental_mode *=.*/revisionless_incremental_mode = disabled/' \
  /etc/kolla/neutron-aria-agent/neutron-aria-agent.ini

sudo docker restart neutron_aria_agent
```

P3 rollback to polling-only:

```bash
sudo sed -i 's/^incremental_rpc_enabled *=.*/incremental_rpc_enabled = false/' \
  /etc/kolla/neutron-aria-agent/neutron-aria-agent.ini
sudo sed -i 's/^revisionless_incremental_mode *=.*/revisionless_incremental_mode = disabled/' \
  /etc/kolla/neutron-aria-agent/neutron-aria-agent.ini
sudo sed -i 's/^rpc_events_enabled *=.*/rpc_events_enabled = false/' \
  /etc/kolla/neutron-aria-agent/neutron-aria-agent.ini

sudo docker restart neutron_aria_agent
```

Do not restart OVS, OVS agent, neutron-server, or `aria-datapath` for P3 flag
rollback. Escalate to the broader ACL rollback flow only when datapath managed
state itself must be cleared.

## OVS Restart Handling

Aria does not own OVS data-plane health. During planned OVS maintenance, do not
judge ACL readiness only from immediate VM ping results. Split the check into
two channels:

| Channel | Required Evidence |
| --- | --- |
| Aria ACL attach | tap exists or is correctly reported missing; ifindex is not stale; XDP is attached or reattached; ACL maps/policy are still consistent; UDS generation is applied; rollback leaves `managed_ports=[]`. |
| OVS forwarding | VM ping or service traffic recovers according to the OVS maintenance procedure. This is operational evidence, not proof that ACL attach failed. |

For `ovs-vswitchd` restart:

1. Before restart, record UDS status, target tap details, XDP attachment, and
   baseline VM reachability.
2. Apply ACL managed state through full-resync and verify the target port is
   `ready/effective_action=enforce` when a policy is expected to enforce.
3. Restart `ovs-vswitchd.service`.
4. If the tap still exists with the same ifindex and XDP attachment, keep Aria
   ACL state as attach-healthy. Record VM ping separately as OVS forwarding
   evidence.
5. If the tap exists but XDP is missing, run idempotent reattach/full-resync and
   require ACL status to return to ready.
6. If the tap is missing or ifindex changed, treat the event as tap recreate:
   do not report stale ready; wait for full-resync to bind the current tap.
7. Always run rollback/delete cleanup and verify `managed_ports=[]`,
   `pending_generation=null`, and no WAL replay failure increase beyond the
   recorded baseline.

Do not add OpenFlow/ofport inspection to Aria runtime as a product dependency.
Those checks can remain smoke/runbook diagnostics for OVS recovery only.
Aria runtime and Aria smoke scripts must not restart OVS or OVS agent. OVS
restart is an operator maintenance action outside Aria's authority.

Use the ACL-focused OVS restart smoke for N3 evidence in one of two modes:

```bash
sudo REPO_ROOT=$(pwd) \
  WAIT_FOR_EXTERNAL_OVS_RESTART=true \
  VM_IP=<reachable-vm-ip> \
  EXPECTED_PORT_ID=<neutron-port-id> \
  EXPECTED_IFNAME=<tap-ifname> \
  deploy/kolla/smoke/neutron_aria_ovs_restart_smoke.sh
```

Start this smoke before a planned external OVS maintenance action. The smoke
waits for the externally triggered restart marker to change, then passes or
fails on the Aria ACL attach channel.

In an isolated test environment only, the same smoke can trigger the service
restart itself:

```bash
sudo REPO_ROOT=$(pwd) \
  TEST_TRIGGER_OVS_RESTART=true \
  VM_IP=<reachable-vm-ip> \
  EXPECTED_PORT_ID=<neutron-port-id> \
  EXPECTED_IFNAME=<tap-ifname> \
  deploy/kolla/smoke/neutron_aria_ovs_restart_smoke.sh
```

`TEST_TRIGGER_OVS_RESTART=true` is a test harness action, not product behavior.
Production Aria runtime must never trigger OVS or OVS agent restart. The smoke
records VM ping as OVS forwarding observation and does not treat immediate OVS
restart packet loss as ACL failure. Running it with neither
`WAIT_FOR_EXTERNAL_OVS_RESTART=true` nor `TEST_TRIGGER_OVS_RESTART=true`
performs only a non-restart ACL attach observation and is not enough to close
the N3 `ovs-restart` gate.

## Rollback

Safe rollback order:

1. If P3 is enabled, set `[neutron] incremental_rpc_enabled=false` and
   `revisionless_incremental_mode=disabled`, then restart only
   `neutron-aria-agent` to return to P2 full-resync behavior.
2. If RPC P2 is enabled, set `[neutron] rpc_events_enabled=false` and restart
   only `neutron-aria-agent` to return to polling-only.
3. Set `full_resync_enabled=false` in `neutron-aria-agent` when rolling back
   production snapshot submission.
4. Set `[acl] source=disabled` or remove ACL bindings in Neutron.
5. Allow one full resync/delete cycle to clear Neutron-managed datapath state.
6. Stop `neutron-aria-agent`.
7. Keep OVS agent and OVS forwarding untouched.
8. Stop or restart `aria-datapath` only after confirming OVS connectivity remains healthy.

Never use socket deletion as the primary rollback method. A missing socket should
produce degraded status and trigger recovery/full resync, not silently switch to
local writes for managed domains.

## Break-Glass

Break-glass is not a default product path. If implemented:

- it must be explicit;
- it must write a local override WAL, not Neutron WAL;
- rejoin must default to Neutron wins;
- local overrides must be archived or discarded before full resync resumes.
