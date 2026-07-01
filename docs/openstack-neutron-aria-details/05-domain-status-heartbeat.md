# 05. Domain Status And Heartbeat Detail Plan

Status: partial implementation; richer Rust/domain DTO remains planned.

## Goal

Make runtime status explicit enough for Neutron heartbeat, product UI, and
operations without overloading one string field.

## Target Domain Status

| Field | Values | Meaning |
| --- | --- | --- |
| `domain` | `attach`, `acl`, `qos`, later explicit domains | Feature/runtime domain. |
| `status` | `ready`, `degraded`, `blocked`, `not_requested`, `detached` | Domain execution result. |
| `effective_action` | `enforce`, `bypass`, `unchanged`, `cleanup`, `no_op` | Datapath action. |
| `support_disposition` | `supported`, `unsupported`, `unknown`, `not_applicable` | Capability/support classification. |
| `reason` | stable error code or null | Why status is not ready. |
| `details` | optional bounded object | Debug details, not required for normal UI. |

## Rules

- `bypass` is never a `DomainStatus`.
- `alive` is agent health, not feature readiness.
- ACL ready uses `effective_action=enforce`.
- ACL missing input uses `status=not_requested,effective_action=bypass`.
- ACL invalid/apply failed uses `status=degraded,effective_action=bypass`.
- Missing local attach target uses `status=detached` or
  `status=degraded,reason=interface_missing`; it must not be reported as ACL
  ready.
- WAL/schema/capability uncertainty may use `blocked`.

## Heartbeat Projection

`neutron-aria-agent` heartbeat/configurations should include:

- `managed_domains`;
- `managed_ports`;
- per-domain counts;
- last submitted generation;
- accepted/applied generation observed from datapath;
- degraded reasons summarized by stable error code.
- P3-1 projection observability: compact projected-port/network index counts
  and the last RPC decision summary. These fields are debug/operations signals,
  not proof that port-scoped incremental apply is enabled.

Product `aria_acl_port_statuses` should store per-port runtime summary, not user
desired state.

Generation terminology is normative in `07-transaction-wal.md`. This document
only projects those generation values into heartbeat and product status.

## Current Gap

Current Rust `NeutronDomainStatus` is still mostly:

```text
domain/status/reason
```

The richer fields are target contract fields and should be introduced with
backward-compatible decoding/defaults.

## Implementation Design Package

This package is detailed to file/field/projection/test level. Do not expand to
function-call level until the status/heartbeat PR is opened.

### Target Files

| File | Role |
| --- | --- |
| `api/src/lib.rs` | Rust DTOs for domain status, generation, effective action, support disposition. |
| `agent/src/neutron_api.rs` | UDS status route response construction. |
| `agent/src/control_plane.rs` and `core/src/state.rs` | Current Rust control-plane/runtime state paths related to datapath state. |
| `openstack/neutron_aria/neutron_aria/agent/uds_client.py` | Python decoding with backward-compatible defaults. |
| `openstack/neutron_aria/neutron_aria/agent/status.py` | Agent-side generation lag, degraded summary, and heartbeat state. |
| `openstack/neutron_aria/neutron_aria/agent/event_loop.py` | Heartbeat/configurations update cadence and resync status projection. |
| `openstack/neutron_aria/neutron_aria/db/aria_acl/api.py` and `services/aria_acl/` | Product `aria_acl_port_status` persistence and API projection after plugin exists. |
| `openstack/neutron_aria/neutron_aria/tests/unit/` | Unit tests for decoding, projection, and degraded summaries. |

### 2026-06-29 MVP Implementation Evidence

Evidence path:
`docs/evidence/openstack-n05-lite/2026-06-29-stage2-acl/summary.md`.

Implemented for stage-two ACL MVP:

- Python heartbeat configurations now include `last_submitted_generation`,
  `accepted_generation`, `applied_generation`, `generation_lag`,
  `domain_counts`, and `degraded_reasons`.
- `aria_acl_port_statuses` read APIs project `last_reported_at`, `stale`, and
  `runtime_status` without adding DB columns.
- `neutron-aria-agent` writes runtime summaries after reading UDS status;
  `aria_acl` stores and serves those summaries.
- Stage-two gate validates the fields through live Neutron on `ostack2` and
  `ostack3`.

Still planned:

- Rich Rust per-domain DTO fields such as `effective_action` and
  `support_disposition` at the datapath API boundary.
- Product UI wording and full port-show effective field integration.

### Status DTO

Minimum target shape:

```json
{
  "port_id": "uuid",
  "generation": 12,
  "desired_hash": "sha256:...",
  "domains": [
    {
      "domain": "acl",
      "status": "ready",
      "effective_action": "enforce",
      "support_disposition": "supported",
      "reason": null,
      "details": {}
    }
  ]
}
```

`details` must remain bounded and optional. Product UI and heartbeat must not
depend on unbounded debug payloads.

### Projection Flow

1. Rust classifies per-port/per-domain status after snapshot/delete/recovery.
2. Rust exposes the current status through `GET /api/v1/neutron/status`.
3. Python decodes status with backward-compatible defaults for older datapath
   fields.
4. Python computes heartbeat summaries: counts, generation lag, and top degraded
   reasons.
5. Python reports Neutron agent health separately from domain readiness.
6. After `aria_acl` exists, Python or the plugin path persists per-port ACL
   runtime summary for product read APIs.

Runtime status write/read responsibility:

- `neutron-aria-agent` writes runtime summaries after reading UDS status.
- `aria_acl` plugin/API stores and serves those summaries.
- Desired ACL state remains owned by policy/rule/binding tables, not status
  rows.

### Heartbeat Fields

| Field | Meaning |
| --- | --- |
| `alive` | Agent process/control health only. |
| `managed_domains` | Current authority domains from config/snapshot. |
| `managed_ports` | Number of ports under Neutron attach authority. |
| `last_submitted_generation` | Latest generation Python attempted. |
| `accepted_generation` | Latest generation datapath accepted/classified. |
| `applied_generation` | Latest generation datapath reports as applied/classified. |
| `domain_counts` | Count by domain/status/effective action. |
| `degraded_reasons` | Bounded stable reason counts. |
| `projection_index` | Bounded P3-1 debug summary: projected port count, indexed network count, ports with network metadata, and ports with revision metadata. |
| `last_event_decision_counts` | Bounded count by RPC decision action/reason for the last processed event batch. |
| `last_event_decisions` | Bounded debug sample of the last processed event decisions. It is not a durable audit log. |

### Compatibility Rules

- Missing `effective_action` defaults to conservative interpretation:
  `enforce` only if status is clearly ready and domain semantics allow it;
  otherwise `bypass` or `unknown`.
- Missing `support_disposition` defaults to `unknown`.
- Unknown domains are preserved in details but do not become required product
  gates.
- Unknown enum values are treated as degraded/unknown, not ready.

### Error And Status Semantics

| Condition | Status Projection |
| --- | --- |
| ACL ready | `status=ready,effective_action=enforce,support_disposition=supported`. |
| ACL not bound | `status=not_requested,effective_action=bypass`. |
| ACL invalid input | `status=degraded,effective_action=bypass,reason=<stable code>`. |
| Tap missing for a Neutron-managed local port | `status=detached` or `status=degraded,reason=interface_missing`; no ACL ready. |
| OVS forwarding interrupted while tap/XDP/map state is healthy | ACL status remains based on attach health; do not mark ACL degraded solely from VM ping failure during OVS restart. |
| Capability unsupported | `status=degraded` or `blocked`, `support_disposition=unsupported`. |
| WAL/recovery uncertainty | `status=blocked` or `degraded`, never ready. |
| Agent cannot reach UDS | Agent alive may be true, domain readiness degraded/unknown. |

### Test Matrix

| Test | Expected Result |
| --- | --- |
| Ready ACL status from Rust | Heartbeat counts ready/enforce ACL. |
| ACL invalid input | Heartbeat reports degraded/bypass reason. |
| Older datapath status without rich fields | Python decodes safely with defaults. |
| Unknown enum value | Classified as degraded/unknown, not ready. |
| Generation lag | Heartbeat exposes submitted vs accepted/applied gap. |
| P3-1 event decision observability | Heartbeat exposes projection index summary and last event decision counts without enabling incremental apply. |
| UDS unavailable | Agent health and domain readiness are reported separately. |
| Product port status read | Runtime summary does not mutate desired ACL state. |

### Anti-Overengineering Guardrails

- Do not expose internal WAL records as required product API fields.
- Do not build UI-specific wording into the datapath DTO.
- Do not mark a whole agent unhealthy only because one domain is degraded.
- Do not invent per-rule runtime status unless a product gate requires it.
- Do not turn decision observability into a durable event journal.

## Acceptance

- Status responses include per-domain status for requested managed domains.
- ACL degraded with bypass is visible without implying OVS connectivity failure.
- Heartbeat reports enough information to alert on generation lag and degraded
  ACL ports.
- Unknown optional fields are ignored safely.

## Non-Goals

- Do not build a UI-only status vocabulary.
- Do not expose internal WAL implementation details as required product fields.
- Do not mark all domains ready just because snapshot was accepted.
