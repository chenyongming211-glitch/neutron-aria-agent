# Neutron Managed Domains Contract

Status: normative short contract for the v0.9 OpenStack integration.

This file is the day-to-day entry point for developers. The full rationale stays
in `openstack-neutron-agent-mode.md`; the `aria_acl` API/DB details stay in
`aria-acl-neutron-extension-product-design.md`.

If this short contract and `openstack-neutron-agent-mode.md` disagree, the
normative constraints in `openstack-neutron-agent-mode.md` section 1.5 win. This
file must then be updated to match the main design.

Large design decisions and known documentation debt are tracked in
`openstack-neutron-aria-design-decisions.md`.

One fixed product principle: do not overengineer v0.9. Every new feature, field,
abstraction, or workflow must map to a first-stage gate, smoke, production risk,
or explicitly approved later-stage plan.

## Current Implementation Status

| Area | Status | Notes |
| --- | --- | --- |
| Stage-one contract | closed | Closure evidence is `docs/evidence/openstack-n05-lite/20260701-stage1-closure-summary.md`. |
| Rust Neutron UDS snapshot/status/delete routes | implemented for stage one | Snapshot apply, WAL, generation, desired hash, delete, capabilities/status, and local write gate exist for the stage-one contract. |
| `managed_domains` local write gate | implemented | Uses `NeutronPortSnapshot.managed_domains`, `mark_neutron_port_authority()`, and `ensure_local_write_allowed()`. |
| Python `neutron-aria-agent` full resync skeleton | partial | Can build local snapshots and submit them over UDS. |
| ACL fixture source | implemented | CI/smoke only. |
| ACL Neutron source | partial | `NeutronAclSource` can consume an `aria_acl` effective payload, legacy list methods, or the aria_acl REST adapter; production auth/session execution against target Neutron remains. |
| `aria_acl` Neutron service plugin/API/DB | partial | Minimal stdlib-only repository/plugin contract, API extension descriptor, persistent DB contract, Alembic table creation, CRUD/revision behavior, and RBAC contract exist; `neutron-db-manage` and server startup validation remain target-environment gates. |
| Rich domain status | planned | Current `NeutronDomainStatus` is still `domain/status/reason`; target also includes `effective_action` and `support_disposition`. |
| UDS contract JSON | implemented | `docs/neutron-uds-contract.json` is checked by `ci/check_neutron_stage1.py`. |
| UDS peer credential enforcement/audit | implemented and rolled out | Socket mode validation, socket group alignment, and connection-level `SO_PEERCRED` audit/enforcement hooks exist. `compute-1.example.test`, `compute-2.example.test`, and `compute-3.example.test` have persistent hardened rollout evidence with `REQUIRE_HARDENED=true`. |
| Unified `neutron-aria-agent.ini` target layout | partial | Target layout, packaged safe defaults, config validation, and documentation checks exist; production enablement still depends on N0.5/runbook gates. |

## INI Contract Convergence

Status: stage-one contract recorded, enforced by config validation, packaged
safe defaults, and `ci/check_neutron_stage1.py`; closure evidence is
`docs/evidence/openstack-n05-lite/20260701-stage1-closure-summary.md`.

The design already separates local process mode from snapshot integration mode:

| Concept | Owner | Where It Belongs |
| --- | --- | --- |
| `agent_mode` / `mode = neutron_managed` | local `aria-agent` / `aria-datapath` config | local datapath config only |
| `integration_mode = coexist` | `neutron-aria-agent` snapshot writer | `PUT /api/v1/neutron/snapshot` body only |
| `managed_domains` | `neutron-aria-agent` config and snapshot ports | agent config plus per-port snapshot field |

Therefore, `integration_mode = coexist` must be removed from
`neutron-aria-agent.ini` and local `aria-agent` config examples. If a local
equivalent is needed, the local datapath side uses `agent_mode = "openstack"` or
`mode = "neutron_managed"` as documented by the deployment target.

The target `neutron-aria-agent.ini` documentation should converge to one layout:

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
revisionless_incremental_mode = disabled

[acl]
source = disabled
# fixture_path is CI/smoke only.
# fixture_path = /etc/neutron-aria-agent/acl-fixture.json
```

Maintained documentation tasks:

- Keep `resync_interval` as the target ini key unless a later code PR renames it
  with an explicit compatibility alias.
- Keep deploy/kolla examples as implementation evidence, but document any
  temporary mismatch as transitional rather than a second normative contract.

Revisionless P3 rule:

- Production P3 port-scoped apply remains revision-aware.
- Old Neutron environments that return no trustworthy port `revision_number`
  stay on P2 RPC-triggered full-resync by default.
- `revisionless_incremental_mode=experimental` may be used only on controlled
  test hosts, with `incremental_rpc_enabled=true`, to validate the datapath
  scoped route in legacy environments. It must not be packaged or rolled out as
  a production default.

## ACL Input Source

Production ACL input source:

```text
aria_acl Neutron service plugin/API/DB
  -> neutron-aria-agent NeutronAclSource
  -> effective ACL index
  -> Neutron snapshot
  -> aria-datapath
```

Non-production sources:

| Source | Allowed Use |
| --- | --- |
| `fixture` | CI, local smoke, pre-Neutron-server datapath validation. |
| tag + local mapping | Legacy lab/bootstrap/migration helper only; not a production control-plane contract. |

The product path does not consume Neutron Security Group, remote group, port
security, or allowed address pairs.

## Authority Model

Attach authority and feature/domain authority are separate:

| Concept | Field / Mechanism | Meaning |
| --- | --- | --- |
| Tap attach authority | `neutron_managed` / Neutron snapshot | Which control plane may attach or detach VM tap runtime. |
| Feature write authority | `ports[].managed_domains` | Which feature domains are owned by Neutron for that port/instance. |

Current code path:

```text
NeutronPortSnapshot.managed_domains
  -> mark_neutron_port_authority()
  -> ensure_local_write_allowed()
  -> LOCAL_WRITE_BLOCKED_FOR_NEUTRON_MANAGED_DOMAIN
```

Rules:

| Scenario | Required Behavior |
| --- | --- |
| `managed_domains=["acl"]` | Local ACL writes are rejected. Local conntrack mutation/flush is also rejected because CT is an internal ACL lifecycle dependency; local QoS/Mirror writes remain allowed. |
| `managed_domains=["acl","qos"]` | Local ACL and QoS writes are rejected. |
| `managed_domains=["acl","qos","mirror"]` | Local ACL, QoS, and Mirror writes are rejected. |
| Domain not listed in `managed_domains` | Local `ariactl` writes remain allowed, subject to normal local validation, except an internal dependency explicitly owned by a selected domain. |
| Read-only/status/stats/diagnose | Allowed for Neutron-attached ports. |
| Trace/drops/tcprt troubleshooting | Allowed unless the domain is explicitly added to `managed_domains` later. |

Rejected local writes must return HTTP 409 or an equivalent local API response
with:

```text
LOCAL_WRITE_BLOCKED_FOR_NEUTRON_MANAGED_DOMAIN
```

Conntrack remains a runtime foundation rather than an advertised Neutron
managed domain. The Python agent still accepts only `managed_domains=acl`, and
Rust capabilities still publish only `attach` and `acl`. ACL authority blocks
local CT mutation so a local operator cannot invalidate `stateful=true` or
silently re-enable the CT fast path for `stateful=false`; internal Neutron ACL
reconcile controls both flags in the same per-tap config transaction.

## Status Contract

Target domain status fields:

| Field | Meaning |
| --- | --- |
| `DomainStatus` | `ready`, `degraded`, `blocked`, or `not_requested`. |
| `effective_action` | `enforce`, `bypass`, `unchanged`, `cleanup`, or `no_op`. |
| `support_disposition` | `supported`, `unsupported`, `unknown`, or `not_applicable`. |

Important rules:

- `bypass` is an `effective_action`, not a `DomainStatus`.
- ACL not ready must use `effective_action=bypass` and must not block OVS L2 forwarding.
- ACL ready must use `effective_action=enforce`.
- `accepted_generation` means the snapshot passed schema/authority/WAL checks; it does not by itself mean every feature domain is ready.

### OVS forwarding invariant

Aria is an enhancement of the existing OVS datapath. Failure of an Aria
control-plane or ACL runtime operation must never be translated into an OVS
restart, OVS-agent restart, bridge/port removal, or an unowned hook cleanup.

The required failure order is:

1. Keep a complete last-known-good ACL generation when its link, map, tap, and
   runtime identity remain provably valid.
2. If that identity or a complete rollback cannot be proven, disable the Aria
   ACL gate and publish `degraded` or `blocked` with
   `effective_action=bypass`.
3. In bypass, packet processing continues to OVS; health may be non-ready, but
   recovery must not stop OVS or `neutron-openvswitch-agent`.
4. A two-direction apply is one policy result. A partial ingress/egress result
   must roll back to a complete old generation or bypass both directions.
5. Detach and cleanup may remove only objects whose exact Aria ownership is
   proven. Shared `clsact`, foreign filters, and foreign XDP/TC programs are
   outside Aria cleanup authority.

This invariant does not turn an explicit ACL deny into pass. It also does not
weaken fail-closed handling for malformed, overlapping, or authority-less IP
fragments. Those are packet-policy/security outcomes rather than an Aria
component outage. OVS, host, physical-link, and external-network failures are
outside this guarantee.

Planned agent/datapath upgrades use the maintenance transaction defined in
[`2026-08-21-aria-planned-maintenance-upgrade-design.md`](superpowers/specs/2026-08-21-aria-planned-maintenance-upgrade-design.md).
The maintenance gate is domain-scoped: an ACL upgrade may bypass ACL without
silently disabling unrelated QoS, Mirror, trace, or observability ownership.
Container liveness, ACL readiness, and effective action are separate states;
a recognized maintenance operation may be live while ACL is non-ready/bypass.

## UDS Minimum Contract

The Neutron UDS API is local only:

```text
GET    /api/v1/neutron/capabilities
GET    /api/v1/neutron/status
PUT    /api/v1/neutron/snapshot
DELETE /api/v1/neutron/ports/{port_id}
```

Production hardening requires:

- generated `neutron-uds-contract.json`;
- contract version and schema version range;
- body size limit;
- stable error code hash;
- peer auth policy;
- Unix socket permissions and peer credential audit.

Stage-one contract artifact:

```text
docs/neutron-uds-contract.json
```

## Gate Scenarios

Minimum tests:

| Test | Expected Result |
| --- | --- |
| Snapshot with `managed_domains=["acl"]`, then local `policy add` | Rejected with `LOCAL_WRITE_BLOCKED_FOR_NEUTRON_MANAGED_DOMAIN`. |
| Snapshot with `managed_domains=["acl"]`, then local `qos add` | Allowed. |
| Snapshot with `managed_domains=["acl","qos"]`, then local `qos add` | Rejected with `LOCAL_WRITE_BLOCKED_FOR_NEUTRON_MANAGED_DOMAIN`. |
| Snapshot with ACL apply failure | ACL domain degraded, `effective_action=bypass`, OVS forwarding unaffected. |
| Neutron communication failure after accepted snapshot | Remains Neutron-managed/degraded; local writes for managed domains stay blocked. |
| Break-glass, if enabled | Explicit only; writes local override WAL; rejoin defaults to Neutron wins. |
| Python agent exits while committed kernel ACL identity remains valid | Last-known-good ACL remains active; OVS forwarding and topology are unchanged. |
| Datapath apply or rollback cannot prove a complete generation | ACL gate is disabled, status is non-ready/bypass, and OVS continues forwarding. |
| One TC direction applies and the other fails | Restore the complete old generation or bypass both directions; never report a half policy as applied. |
| Aria detach encounters a foreign filter or shared qdisc | Preserve the foreign/shared object, report conflict/degraded, and leave OVS forwarding unchanged. |

## Dual-stack ACL identity

Managed ACL compilation produces one rule per family: omitted `ethertype` is
`IPv4`, and `any` is explicit IPv4 plus IPv6 expansion. `icmp` is mapped by
the selected family and there is no hidden Neighbor Discovery bypass. Every
address set is single-family; policy runtime and counter rows carry the family
so equal selector IDs cannot alias. Packaged IPv6 ACL and counters remain
default-off, and field execution is `deferred/pending` until Task 12.
