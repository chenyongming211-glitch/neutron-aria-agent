# 06. Deployment, N0.5, And Runbook Detail Plan

Status: planned deployment refinement.

`../openstack-deployment-runbook.md` is the operator-facing runbook. This file
is the design-side supplement for N0.5 evidence, gate ordering, smoke grouping,
and rollback acceptance. If the two drift, update the runbook after the target
INI contract is finalized.

## Goal

Turn the design into a safe field enablement sequence without overclaiming
features before the target OpenStack environment is verified.

## Required Evidence

Record every target-environment fact in `../openstack-target-env-discovery.md`
with command, expected result, actual result, and evidence path.

Minimum facts:

- OS and kernel version.
- BTF and bpffs availability.
- OVS bridge and tap naming.
- OVSDB `external_ids:iface-id` availability.
- UDS directory ownership/mode.
- socket ownership/mode.
- container host mounts.
- `tc` availability or QoS shaping degradation.
- eligible VM tap, service ports, unsupported ports.

## Safe Enablement Order

1. Start `aria-datapath` in inert/bypass mode.
2. Verify UDS capabilities/status.
3. Apply a controlled snapshot with `managed_domains=["acl"]`.
4. Verify local ACL writes are blocked and local QoS/Mirror writes remain allowed.
5. Enable `port_source=neutronclient` for read-only full-resync preview.
6. Enable `acl.source=neutron` only after `aria_acl` and `NeutronAclSource` exist.
7. Enable `full_resync_enabled=true` only after N0.5 and domain-authority smoke pass.
8. Enable `rpc_events_enabled=true` only as a per-host P2 canary after P1
   polling full-resync, rollback, and N3 lifecycle gates are accepted.
9. Enable `incremental_rpc_enabled=true` only as a controlled P3 test after P2
   evidence, P3 failure semantics, and P3 smoke evidence are accepted. Keep
   packaged defaults disabled.

## Smoke Groups

| Smoke | Purpose |
| --- | --- |
| container smoke | Validate image, config mounts, socket path, health. |
| UDS contract smoke | Validate capabilities/status/snapshot/delete. |
| domain authority smoke | Validate `managed_domains` local write gate. |
| ACL fixture smoke | Validate datapath ACL path before Neutron server plugin exists. |
| production ACL smoke | Validate `aria_acl` plugin -> agent -> datapath. |
| ACL active traffic smoke | Validate a real VM traffic stream is already running, ACL is created through Neutron `aria_acl`, datapath blocks the stream, rollback clears policy, and traffic recovers. |
| RPC P2 smoke | Validate package preflight, strict mode reporting, real fanout A/B, foreign-host filtering, and source-host cleanup before enabling events beyond a canary. |
| RPC P3 smoke | Validate explicit incremental on/off, revisionless default fallback, controlled revisionless lab mode, and rollback to zero managed ports. |
| crash/restart smoke | Validate WAL and timeout recovery. |
| rollback smoke | Validate disabling agent/ACL does not break OVS forwarding. |

## Rollback Principles

- Prefer disabling `full_resync_enabled` and ACL source before stopping datapath.
- Do not delete the socket as the primary rollback mechanism.
- OVS forwarding remains the safety baseline.
- Break-glass must be explicit and must not silently merge local override with
  Neutron state.

## Implementation Design Package

This package is detailed to file/runbook/evidence/smoke/test level. Do not
expand to command-by-command field procedures until the deployment PR or field
runbook review is opened.

### Target Files

| File | Role |
| --- | --- |
| `docs/openstack-deployment-runbook.md` | Operator-facing enablement, rollback, and break-glass entry point. |
| `docs/openstack-target-env-discovery.md` | N0.5 evidence table and target environment facts. |
| `deploy/kolla/config/neutron-aria-agent.ini` | Packaged safe defaults and enablement toggles. |
| `deploy/kolla/neutron-aria-agent/` | Container image/build/deploy packaging notes. |
| `deploy/kolla/smoke/` | Smoke scripts for config, UDS, authority, ACL fixture, production ACL, restart, rollback. |
| `ci/check_n05_discovery_evidence.py` | Offline G4 evidence acceptance check. |
| `docs/openstack-neutron-aria-details/01-ini-contract.md` | Config layout source for runbook examples. |
| `docs/openstack-neutron-aria-details/04-uds-contract-security.md` | UDS security and contract source for smoke gates. |
| `docs/openstack-neutron-aria-details/07-transaction-wal.md` | Restart/recovery smoke source. |

### Enablement Gates

| Gate | Required Evidence | Exit Criteria |
| --- | --- | --- |
| G0 image/config packaged | container build, mounted config, safe defaults | Services start with no production mutation. |
| G1 datapath inert | UDS status/capabilities reachable | OVS forwarding unaffected. |
| G2 authority gate | `managed_domains=["acl"]` snapshot | Local ACL blocked; local QoS/Mirror allowed. |
| G3 fixture ACL | fixture source smoke | ACL datapath path works without Neutron plugin. |
| G4 environment discovery | `neutron_aria_n05_discovery_smoke.sh` evidence plus N0.5 table update | Ports, BTF/bpffs, OVSDB, socket, QoS capability known with explicit dispositions. |
| G5 production ACL source | `aria_acl` + `NeutronAclSource` available | Effective ACL read builds snapshot. |
| G6 full resync | `port_source=neutronclient`, `full_resync_enabled=true` | Resync and heartbeat stable. |
| G7 rollback / active traffic | rollback smoke plus optional active traffic gate | OVS connectivity preserved; when a test VM is provided, live traffic is blocked by ACL and recovers after rollback. |
| P2 RPC events | P2 package + live fanout smokes | Per-host `rpc_events_enabled=true` reports `sync_mode=rpc_full_resync`, can be enabled, and can be rolled back to `sync_mode=polling_full_resync` without OVS/datapath restart. |
| P3 incremental events | P3-5 smoke + P3-6 runbook contract | Per-host `incremental_rpc_enabled=true` can be tested and rolled back to P2 or polling-only without OVS/datapath restart; packaged defaults remain disabled. |

UDS peer-auth gates follow the Phase A-D sequence in
`04-uds-contract-security.md`. Production mutating routes must not be declared
ready beyond the peer-auth phase that is actually packaged and verified in the
target environment.

### 2026-06-29 Stage-Two ACL MVP Gate Evidence

Evidence path:
`docs/evidence/openstack-n05-lite/2026-06-29-stage2-acl/summary.md`.

Final acceptance audit:
`docs/evidence/openstack-n05-lite/2026-06-30-stage2-acceptance-summary.md`.

Current gate disposition:

| Gate | Status | Evidence / Boundary |
| --- | --- | --- |
| G0 image/config packaged | pass for MVP | Stage-two bundle builds and installs as an egg/bundle gate; registry image release remains a later release-governance item, not a stage-two MVP blocker. |
| G5 production ACL source | pass for MVP | `aria_acl` extension/API/DB, REST CRUD, and `NeutronAclSource` full-resync input passed on `ostack2.bj159.net` and `ostack3.bj159.net`. |
| G6 full resync | pass for ACL MVP | `ostack2` applied five ACL-managed ports and rolled them back; `ostack3` handled the zero-compute-port case cleanly. |
| heartbeat summary | pass for MVP | Neutron agent heartbeat includes generation lag, accepted/applied generation, domain counts, and degraded reason summary after the agent egg is installed and the container is restarted. |
| G4 environment discovery | pass for discovery + reversible hardened proof + bounded guest disposition | `neutron_aria_n05_discovery_smoke.sh` collected OS/kernel, OVS/tap, BTF/bpffs, `tc`, UDS, container, Neutron extension, trunk extension, port-source, port-class, and `aria_acl` API evidence on `ostack2/3/4`; `ci/check_n05_discovery_evidence.py` accepts the evidence with zero `fail`. `neutron_aria_uds_hardening_smoke.sh` also produced three-host `REQUIRE_HARDENED=true` evidence with socket `root:42435 0660`, allowed peercred audit, and clean restore. Persistent hardened rollout is still a release/operations gate, not a reason to expand product features. DHCP initial lease passed in a bounded CirrOS guest; explicit renew is `not_applicable` because that image lacks executable `udhcpc`; metadata reached the namespace proxy but target backend socket `ENOENT` returned HTTP 500; IPv6 ND is `not_applicable` because no IPv6 subnet exists. |
| G7 rollback | pass for active ACL rollback evidence | `neutron_aria_rollback_connectivity_smoke.sh` on `ostack2` proved baseline ping, ACL-induced ICMP block, UDS rollback to `managed_ports=[]`, ping recovery, and both `neutron_aria_agent` and `aria_datapath` stop/restart without OVS connectivity loss. A host-initiated `ACL_DIRECTION=egress` probe was rejected because echo-reply is reverse traffic under stateful ACL, then a temporary CirrOS guest proved VM-originated ICMP before ACL, 0 matching packets after generation `85` reached UDS `ready`, and packet recovery after UDS rollback. |
| ACL active traffic | pass for live test VM stream | `neutron_aria_acl_active_traffic_smoke.sh` on `ostack2` kept a continuous ping stream to `wp-test` running, applied a temporary Neutron `aria_acl` ingress drop policy to port `86b83885-671f-474c-9556-8af98cf1cdc8`, observed `success_delta=0` and `failure_delta=4` while active, then deleted the temporary ACL objects, full-resynced, cleared datapath policy, and observed traffic recovery. Evidence: `docs/evidence/openstack-n05-lite/20260706-acl-active-traffic-smoke/summary.md`. |
| QoS/Mirror | not in scope | No QoS/Mirror gate is opened by this evidence. |

Operational constraint discovered:

- The `aria_acl` plugin, extension map, policy rules, and package files must be
  installed on every active `neutron_server` node behind the Neutron API
  endpoint. Updating only one node can return mixed old/new response fields
  depending on which server handles a request.
- Installing the agent egg is not enough for heartbeat verification. The
  long-running `neutron_aria_agent` container must restart so the new heartbeat
  payload code is actually loaded.
- Compute-only hosts still need the same stage-two agent egg. `ostack4` initially
  had an older egg and was corrected by the package installer before final N0.5
  discovery evidence was recorded.
- These constraints belong in the delivery package and runbook; they must not
  be treated as ad hoc operator memory.

### Evidence Record Shape

Each N0.5 entry should record:

| Field | Meaning |
| --- | --- |
| fact | Environment fact being verified. |
| command | Exact command or script used. |
| expected | Expected result before running. |
| actual | Captured result or summary. |
| evidence_path | Log/file path, screenshot path, or copied command output location. |
| disposition | `pass`, `fail`, `degraded`, `unsupported`, or `not_applicable`. |
| follow_up | Required action when not pass. |

### Smoke Script Groups

| Script Group | Existing Script(s) | Minimum Checks |
| --- | --- | --- |
| N0.5 discovery smoke | `neutron_aria_n05_discovery_smoke.sh` | Read-only OS/kernel, OVS/tap, BTF/bpffs, `tc`, socket, container, Neutron extension, trunk extension, ACL API, port-source, and port-class evidence with dispositions. |
| N0.5 evidence checker | `ci/check_n05_discovery_evidence.py` | Latest host evidence has required facts, zero `fail`, allowed non-pass dispositions, and at least one host with compute tap plus OVS `iface-id` evidence. |
| stage-two acceptance evidence checker | `ci/check_stage2_acceptance_evidence.py` | Cross-checks G0/G4/G5/G6/G7 evidence summaries, DHCP/metadata/IPv6 guest disposition, QoS/Mirror boundary, and absence of stale partial guest evidence. |
| UDS peercred config gate | `ci/check_neutron_stage1.py` | Packaged datapath config has non-world-writable UDS mode, audit-only safe defaults, source-level `SO_PEERCRED` support, and peercred unit-test hooks. |
| UDS peercred field evidence | `neutron_aria_uds_hardening_smoke.sh` | Records container uid/gid allow-list candidates, current socket mode, and audit-log disposition without mutating the target. |
| UDS peercred evidence checker | `ci/check_uds_hardening_evidence.py` | Latest host evidence has required UDS hardening facts, zero `fail`, and explicit degraded/not-applicable dispositions. |
| UDS peercred hardened enforcement | `REQUIRE_HARDENED=true neutron_aria_uds_hardening_smoke.sh` | Fails unless socket permissions have no other-user bits and the audit/enforcement path is present. |
| config smoke | `neutron_aria_container_smoke.sh` | Target ini parses; no `integration_mode`; safe defaults active. |
| container smoke | `aria_datapath_container_smoke.sh`, `neutron_aria_container_smoke.sh` | Process starts; mounts and socket path exist; logs have no fatal errors. |
| UDS smoke | `neutron_aria_boundary_smoke.sh` | capabilities/status/snapshot/delete routes work over UDS only. |
| authority smoke | `neutron_aria_boundary_smoke.sh` | Managed ACL blocks local ACL writes; unmanaged QoS/Mirror remains allowed. |
| fixture ACL smoke | `neutron_aria_acl_full_resync_smoke.sh`, `neutron_aria_acl_fault_injection_smoke.sh` | Fixture snapshot can enforce/bypass ACL without Neutron plugin. |
| production ACL smoke | `neutron_aria_acl_neutron_source_smoke.sh` | `aria_acl` extension visible, `NeutronAclSource` reads ACL input, then snapshot reaches datapath status. |
| active traffic ACL smoke | `neutron_aria_acl_active_traffic_smoke.sh` | A continuous host-to-VM ping stream is running before ACL apply; Neutron `aria_acl` creates a temporary ingress drop policy; datapath, port-status, blocked samples, cleanup, and post-rollback recovery all pass. |
| heartbeat smoke | `neutron_aria_heartbeat_smoke.sh` | Heartbeat and per-port status summaries are visible. |
| recovery smoke | `neutron_aria_transaction_state_smoke.sh`, `neutron_aria_crash_injection_smoke.sh`, `neutron_aria_delete_fault_injection_smoke.sh` | Restart with pending WAL intent and UDS timeout recovery. |
| tap lifecycle smoke | `neutron_aria_tap_recreate_smoke.sh`, `neutron_aria_vm_migration_smoke.sh` | Tap recreation/migration does not widen permissions. |
| rollback smoke | `neutron_aria_rollback_connectivity_smoke.sh` | Baseline ping, ACL block, UDS rollback, post-rollback ping, optional `neutron_aria_agent` and `aria_datapath` stop/restart connectivity. |
| RPC P2 package smoke | `neutron_aria_rpc_event_smoke.sh` | Installed package validates config gate, `sync_mode` mapping, event merge behavior, foreign-host filtering, and known-port delete cleanup without RabbitMQ mutation. |
| RPC P2 live fanout A/B | `neutron_aria_rpc_fanout_smoke.sh` | Disabled path ignores test fanout; enabled path consumes fanout and triggers the P2 full-resync path. |
| RPC P2 foreign-host filtering | `neutron_aria_rpc_foreign_host_smoke.sh` | Cross-host fanout is consumed but does not mutate local managed ports. |
| RPC P2 source cleanup | `neutron_aria_rpc_source_cleanup_smoke.sh` | Projected local port moved to a foreign host is locally deleted with `migration_source_cleanup`. |
| RPC P3 incremental on/off | `neutron_aria_rpc_fanout_smoke.sh` | With explicit incremental test settings, a safe local port update reaches port-scoped apply; with default revisionless mode, old Neutron falls back to full-resync; rollback leaves zero managed ports. |

For VM->external direction, do not use host-initiated ping echo-reply as the
proof. The guest must initiate traffic through SSH, QEMU guest agent, or a
dedicated temporary test VM with known credentials. The rollback smoke accepts
`TRAFFIC_CHECK_CMD` so the same harness can verify guest-originated egress when
that access is available. The 2026-06-30 CirrOS probe is the accepted current
evidence for this direction.

### Rollback Flow

1. Set `full_resync_enabled=false`.
2. Set `acl.source=disabled` or return to fixture-only smoke mode if needed.
3. Confirm Python agent no longer submits production snapshots.
4. Confirm datapath reports bypass/degraded rather than half-enforced unknown.
5. Stop or restart datapath only after UDS/status evidence is captured.
6. Use break-glass only with explicit operator action and recorded reason.

RPC P2 rollback is narrower than product rollback: set
`rpc_events_enabled=false`, restart only `neutron-aria-agent`, and keep
polling/full-resync enabled. Do not disable ACL, stop datapath, or touch OVS
for an RPC event-path rollback unless a separate ACL/datapath failure requires
the broader rollback flow above. Before the canary, heartbeat should report
`sync_mode=polling_full_resync`; after enabling P2 it should report
`sync_mode=rpc_full_resync`; after rollback it must return to
`sync_mode=polling_full_resync`.

RPC P3 rollback is narrower than P2 rollback: set
`incremental_rpc_enabled=false` and
`revisionless_incremental_mode=disabled`, restart only
`neutron-aria-agent`, and keep P2 full-resync recovery available. Set
`rpc_events_enabled=false` only when rolling back all RPC event consumption.

### Error And Disposition Semantics

| Condition | Required Disposition |
| --- | --- |
| `tc` unavailable | QoS shaping is `unsupported` or degraded to policing if available. |
| BTF/bpffs unavailable | XDP/eBPF capability degraded according to runtime support. |
| UDS peer auth not enforceable | Keep packaged safe defaults audit-only or block production mutation until `neutron_peercred_enforce=true` has a recorded uid/gid allow-list and hardened socket evidence. |
| N0.5 evidence missing | Feature gate cannot advance. |
| Smoke failure | Gate remains closed; do not skip to later gate. |

### Test Matrix

| Test | Expected Result |
| --- | --- |
| N0.5 discovery smoke | Evidence directory contains `summary.md`, `commands.log`, raw command outputs, and explicit non-pass dispositions. |
| UDS peercred config gate | Stage-one check accepts socket mode, peercred/audit config fields, source hooks, and contract artifact phase status. |
| UDS hardening evidence smoke | Evidence directory contains UID/GID allow-list candidates and current socket/audit disposition for every target host. |
| UDS hardening evidence checker | Evidence-only mode accepts zero-fail records and leaves the current `0666` socket as degraded. |
| UDS hardened enforcement smoke | With `REQUIRE_HARDENED=true`, non-world-writable socket and audit/enforcement evidence pass. |
| Safe defaults deployment | No production full resync or ACL source mutation. |
| Config smoke | Target ini layout passes and no `integration_mode` appears. |
| UDS-only route check | Neutron routes reachable on UDS and not TCP. |
| Authority smoke | ACL local write blocked only when `acl` managed. |
| Fixture ACL smoke | ACL datapath path works before server plugin exists. |
| Production ACL smoke | Effective ACL reaches datapath and reports status. |
| ACL active traffic smoke | Existing VM traffic is observed before ACL apply, blocked while ACL is active, and restored after temporary ACL rollback. |
| RPC P2 enablement smoke | Package, A/B, foreign-host, and source-cleanup smokes pass before production canary; startup log and heartbeat expose `sync_mode=rpc_full_resync` after enablement. |
| RPC P2 rollback | Disabling `rpc_events_enabled` returns the host to `sync_mode=polling_full_resync` without changing ACL semantics. |
| RPC P3 controlled smoke | Explicit incremental test reaches scoped apply only for safe local events; default revisionless mode falls back to full-resync. |
| RPC P3 rollback | Disabling `incremental_rpc_enabled` and resetting `revisionless_incremental_mode=disabled` returns the host to P2 without changing ACL semantics. |
| Recovery smoke | WAL/timeout recovery does not widen permissions. |
| Rollback smoke | OVS forwarding continues after UDS rollback and after stopping/restarting `neutron_aria_agent`. |

### Anti-Overengineering Guardrails

- Do not require root SSH probes as normal runtime behavior.
- Do not mix N0.5 discovery scripts into always-on services.
- Do not promise QoS shaping without target capability evidence.
- Do not make every smoke a blocking gate for earlier local development modes.
- Do not hide unsupported/degraded dispositions behind a green deployment label.

## Acceptance

- Runbook says when to change `port_source`, `acl.source`, and
  `full_resync_enabled`.
- N0.5 table has evidence for required facts before feature gate.
- Production ACL smoke is separate from fixture smoke.
- Rollback preserves OVS connectivity.

## Non-Goals

- Do not make root SSH probes part of the production runtime shape.
- Do not require tenants or support staff to run OVS commands for normal use.
- Do not treat QoS shaping as available until `tc` or equivalent capability is
  verified.
