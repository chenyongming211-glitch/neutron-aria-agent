# 05. Domain Status And Heartbeat Contract

Status: implemented for the v0.9 Status V1 and Neutron heartbeat projection.
Legacy Neutron port-field projection and product UI wording remain separate work.

## Purpose

Runtime status must distinguish agent health, transaction progress, and feature
readiness. A healthy `neutron-aria-agent` process does not prove that ACL is
enforcing, and an accepted snapshot does not prove that its generation reached
the datapath.

This document describes the implemented Rust-to-Python status contract and its
bounded projection into Neutron heartbeat and `aria_acl_port_statuses`.
Generation and WAL semantics remain normative in `07-transaction-wal.md`.

## Canonical Sources

| Source | Authority |
| --- | --- |
| `api/src/lib.rs` | Public Rust Status V1 DTOs and typed vocabularies. |
| `agent/src/neutron_api.rs` | Runtime-to-Status V1 projection and fail-closed classification. |
| `docs/neutron-status-contract-v1-scenarios.json` | Shared Rust-Python scenario and vocabulary source. |
| `docs/neutron-uds-contract.json` | Negotiated schema range and `status_contract_hash`. |
| `openstack/neutron_aria/neutron_aria/agent/uds_client.py` | Strict Status V1 decoder and conservative legacy adapter. |
| `openstack/neutron_aria/neutron_aria/agent/status.py` | Generation lag, domain counts, and degraded-reason aggregation. |
| `openstack/neutron_aria/neutron_aria/agent/status_reporter.py` | Neutron heartbeat and per-port product projection. |

The shared scenario file is the executable contract. This document explains
that contract but does not replace it.

## Implemented Status V1 Contract

`GET /api/v1/neutron/status` returns `NeutronStatusV1Response` after successful
Status V1 negotiation. The response carries three independent kinds of truth:

1. transaction control: `transaction_state`, `required_action`, and optional
   `recovery_cause`;
2. aggregate readiness: `overall_readiness`;
3. concrete runtime evidence: generation identity, WAL diagnostics, managed
   ports, and per-domain port status.

### Top-Level Control Vocabulary

| Field | Implemented values | Meaning |
| --- | --- | --- |
| `status_schema_version` | `1` | Status response schema, independent from snapshot schema. |
| `status_contract_hash` | `v0.9-neutron-status-1` | Exact shared vocabulary/scenario identity. |
| `transaction_state` | `idle`, `pending`, `classified`, `blocked`, `recovery` | Durable transaction state. |
| `overall_readiness` | `ready`, `degraded`, `blocked`, `unknown` | Aggregate feature-readiness result. |
| `required_action` | `none`, `poll`, `recover_pending`, `full_resync`, `operator` | The only action Python may take from this response. |
| `recovery_cause` | null or `inventory_unavailable` | Typed cause for the supported recovery exception. |
| `last_classified_generation` | unsigned generation | Latest generation with terminal classification. |

The response also contains `generation`, `accepted_generation`,
`applied_generation`, `pending_generation`, `desired_hash`,
`applied_desired_hash`, `wal_status`, `wal_replay_failures`, `authority_state`,
`managed_ports`, `port_statuses`, and `active_instances`.

`generation` is an alias of `applied_generation` in Status V1. Python rejects a
response if those values differ. Pending and classified states must carry a
complete, internally consistent generation/hash identity before Python may poll,
recover, or finalize them.

### Per-Domain Evidence

Each Status V1 port row contains `NeutronStatusDomainEvidence` entries:

| Field | Implemented contract |
| --- | --- |
| `domain` | Normalized managed-domain name, currently including `attach` and `acl` where requested. |
| `status` | `ready`, `not_requested`, `degraded`, or `blocked`. |
| `reason` | Optional stable reason code. |
| `effective_action` | Optional `enforce`, `bypass`, `unchanged`, `cleanup`, or `no_op`. |
| `support_disposition` | Required `supported`, `unsupported`, `unknown`, or `not_applicable`. |

`effective_action` is optional because not every domain directly selects a
datapath action. For example, a ready `attach` domain carries no ACL action.
`support_disposition` is required in V1 so unsupported and not-applicable input
cannot be mistaken for feature readiness.

The legacy `NeutronDomainStatus` DTO still represents internal and legacy wire
rows with `domain`, `status`, `reason`, and optional `effective_action`. Status
V1 does not expose that legacy row directly: Rust normalizes it into
`NeutronStatusDomainEvidence` and adds the typed support disposition.

Status V1 has no unbounded `details` object. Adding new required evidence or
changing enum meaning requires a new status schema/hash and shared scenarios.

### Domain Rules

- `bypass` is an effective action, never a domain status.
- ACL ready requires `status=ready`, `effective_action=enforce`, and
  `support_disposition=supported`.
- ACL without an enabled binding uses `status=not_requested`,
  `effective_action=bypass` or `no_op`, and
  `support_disposition=not_applicable`.
- A terminal ACL input/application failure may be classified degraded only when
  the proven action is `bypass` or `unchanged`.
- Attach ready requires `support_disposition=supported` and no ACL action.
- Internal legacy states such as `error`, `unsupported`, `detached`, and
  `recovered` are normalized to the bounded V1 status vocabulary. They are not
  additional V1 enum values.
- WAL corruption, incomplete identity, unknown enum values, or contradictory
  port/domain evidence becomes `blocked/operator`; it never becomes ready.
- `alive` remains Neutron agent process/control health, not domain readiness.

## Rust-Python Compatibility Boundary

Capabilities advertise `status_schema_version_min`,
`status_schema_version_max`, and `status_contract_hash`. Python selects one of
two explicit adapters:

- Status V1 requires the exact schema/hash and all required typed fields. It
  rejects unknown control triples, enum values, incomplete generations, future
  port generations, duplicate identities, and managed-domain mismatches.
- Legacy V0 is accepted only when V1 metadata is absent. Python derives a
  conservative transaction/readiness/action triple from the legacy authority
  and generation identity. Ambiguous legacy state becomes `blocked/operator`.

A response cannot mix legacy and V1 metadata, and an unknown V1 contract is not
downgraded to legacy. This prevents a rolling-upgrade mismatch from being
interpreted as ready.

## Projection Flow

```text
Rust runtime/WAL state
  -> Status V1 typed control and per-domain evidence
  -> Python strict decoder or conservative legacy adapter
  -> snapshot decision and durable classified/feature-ready history
  -> bounded Neutron heartbeat summaries
  -> ACL-only per-port rows in aria_acl_port_statuses
```

Rust classifies the response after snapshot, port-scoped apply, delete, startup,
and recovery paths. Python uses the normalized control fields to decide whether
to finalize, poll, recover, request a full resync, or require an operator.
Heartbeat reporting is downstream visibility; it does not authorize a state
transition.

## Implemented Heartbeat Projection

`AgentRuntimeStatus` and `NeutronStatusReporter` publish these configuration
fields through Neutron `report_state`:

| Field | Meaning |
| --- | --- |
| `ready`, `degraded`, `reason`, `last_error` | Agent-level runtime summary, separate from process liveness. |
| `last_generation` | Latest generation that reached the feature-ready history. |
| `last_classified_generation` | Latest terminally classified generation, including terminal degradation. |
| `last_feature_ready_generation_by_domain` | Per-domain feature-ready history. |
| `last_submitted_generation` | Latest generation Python attempted. |
| `accepted_generation` | Latest generation accepted/classified by the local runtime. |
| `applied_generation` | Latest generation reported as applied/classified. |
| `generation_lag` | `max(0, last_submitted_generation - applied_generation)`. |
| `last_snapshot_ports`, `last_managed_ports` | Snapshot and managed-port counts. |
| `domain_counts` | Count grouped by domain, status, and effective action. |
| `status_reason_counts` | Count grouped by every non-ready reason, including normal `not_requested` states such as `no_enabled_binding`. |
| `degraded_reasons` | Count grouped only from `blocked`, `degraded`, or `error` port/domain rows. If the agent is degraded before any port row exists, preserve one agent-level fallback reason. |
| `projection_index` | Bounded projected-port/network/revision debug counts. |
| `last_event_decision_counts` | Count by the last event batch's action and reason. |

Heartbeat schema V2 defaults to `heartbeat_detail_mode=summary_only`. It does
not publish managed-port, port-status, or event-decision rows, so the Neutron
`agent-show` payload remains bounded as the host grows from tens to thousands
of ports. `heartbeat_schema_version=2` and `heartbeat_detail_mode` make this
contract explicit.

`legacy_sample` is a temporary rolling-upgrade mode. It restores the historical
three-row samples and truncation flags, but hashes, interface internals, and
full domain evidence remain omitted. Product deployments must converge back to
`summary_only` after compatibility validation.

The status surfaces have separate responsibilities:

| Surface | Responsibility |
| --- | --- |
| `neutron agent-show` | Process/node health, convergence generations, port counts, domain/reason aggregates, and RPC decision counts. |
| `neutron port-show <port-id>` | Product-level ACL summary for one Neutron port. |
| `neutron aria-acl-port-status-show <port-id>` | Full runtime ACL status for one port from `aria_acl_port_statuses`. |
| Agent logs and metrics | Per-event decisions, history, profiling, and failure evidence. |

Heartbeat is therefore not a per-port database, event audit log, or debugging
dump. Removing samples from `report_state` does not remove the complete local
runtime rows or the dedicated ACL port-status publication path.

`domain_counts` preserves an explicit `effective_action` when present. For
legacy rows without one, the compatibility fallback is `ready -> enforce`,
non-ready control states -> `bypass`, and otherwise `unknown`.
`support_disposition` remains available in Status V1 evidence but is not copied
into the compact heartbeat summary.

## Product Port Status Projection

When `acl_source=neutron`, `AriaAclPortStatusReporter` writes ACL runtime summary
rows containing only:

```text
port_id, host, effective_policy_id, binding_id,
status, reason, effective_action, generation
```

The reporter extracts the ACL domain, defaults a clearly ready ACL row to
`effective_action=enforce` for legacy compatibility, and never writes desired
policy/rule state through the status path. Ready publication writes port rows
before the ready heartbeat; degraded publication closes heartbeat readiness
before publishing conservative rows.

Product read APIs derive `last_reported_at`, `stale`, and `runtime_status` from
these rows. Those read-only projections do not transfer desired-state ownership
away from policy, rule, binding, and address-set tables.

## Error And Status Semantics

| Condition | Implemented projection |
| --- | --- |
| ACL ready | `classified/ready/none` with ACL `ready/enforce/supported`. |
| ACL not bound | Terminal classification with ACL `not_requested/bypass/not_applicable`. |
| ACL invalid or unsupported | Degraded or blocked according to the proven action and support disposition. |
| Full-resync-required ACL state | `classified/degraded/full_resync`. |
| Snapshot still applying | `pending/unknown/poll` with complete pending identity. |
| Supported pending recovery | `blocked/blocked/recover_pending`; inventory-unavailable carries the typed cause. |
| WAL/identity/contract uncertainty | `blocked/blocked/operator`. |
| Agent cannot reach UDS | Agent runtime status becomes degraded; cached ACL rows are rewritten to bypass. |

OVS forwarding interruption alone does not redefine ACL domain evidence when
the attach/TC runtime remains healthy. Connectivity smoke and feature status are
separate signals.

## Verification Evidence

- `docs/neutron-status-contract-v1-scenarios.json` defines 14 shared positive,
  legacy, recovery, and invalid-evidence scenarios.
- Rust API serialization and runtime projection tests consume the same scenario
  inventory.
- Python UDS decoder and event-loop tests consume that inventory and exercise
  strict V1, conservative legacy, and contract-error behavior.
- `test_status_reporter.py` verifies generation lag, domain/action counts,
  degraded reasons, bounded heartbeat samples, and ACL port-status projection.
- `ci/check_neutron_stage1.py` checks the public enums, shared scenario inventory,
  Rust producer inventory, and this document's implemented-contract declaration.
- Stage-two live evidence remains at
  `docs/evidence/openstack-n05-lite/2026-06-29-stage2-acl/summary.md`.

## Remaining Work

- `REVIEW-ACL-013` source implementation and hosted tests now populate the
  separate legacy Neutron `port-show` fields through a batch-aware read
  projection. The target Neutron 9/Python 2 CLI smoke is wired but remains
  `deferred/pending`; Status V1 and `aria-acl-port-status*` APIs remain the
  authoritative detailed runtime-status surfaces.
- Product UI wording and presentation remain product-layer work; they must use
  the typed status vocabulary without inventing new datapath states.
- Adding a domain to the status vocabulary does not advertise that feature as
  implemented. Capabilities and deployment configuration remain authoritative.
- A future bounded per-domain debug object would require an explicit versioned
  contract change; it is not part of Status V1.

## Acceptance

- Status V1 responses expose complete typed transaction, readiness, action,
  support, generation, and WAL evidence.
- Python rejects incomplete or contradictory V1 state and handles legacy status
  through a separate conservative adapter.
- ACL degraded/bypass is visible without implying that the agent process or OVS
  connectivity is down.
- Heartbeat exposes generation lag plus aggregated domain/action and
  degraded-reason counts. Only row samples are explicitly bounded, so the
  heartbeat does not carry full per-port runtime evidence.
- Product status writes never mutate desired ACL state.

### Enforcement-Gap Monitoring Boundary

Heartbeat is an aggregate and its per-port sample is bounded, so it is not the
complete security alert source. The maintained read-only check
`deploy/kolla/smoke/neutron_aria_acl_enforcement_gap_smoke.sh` joins desired
policy/binding state, current Neutron port host ownership, and complete runtime
status rows.

For a currently bound port selected by an enabled binding, only an exact,
non-stale `ready/enforce` row with matching policy and binding identity is
accepted. Missing, stale, degraded, bypass, or identity-mismatched evidence is
an enforcement gap. A port with no enabled binding remains the normal
`not_requested/bypass` case and is not alerted. The check is read-only and must
never restart OVS, OVS-agent, datapath, or mutate desired ACL state.

## Non-Goals

- Do not expose internal WAL records as public status fields.
- Do not make heartbeat delivery a transaction commit point.
- Do not treat an accepted snapshot as feature-ready.
- Do not build UI-specific wording into Rust or Python status DTOs.
- Do not add per-rule runtime status without a separately approved product gate.
