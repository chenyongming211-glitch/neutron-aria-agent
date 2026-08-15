# ACL Explainability Counter Pipeline Design

**Status:** implementation and hosted CI complete 2026-08-15; privileged field
evidence deferred/pending; production gate remains default-off

**Scope:** Phase B of `docs/openstack-ebpf-platform-roadmap.md` — per-rule hit/drop
counters, drop-reason vocabulary, and per-port metrics for the Neutron-managed
ACL product path, delivered to operators only.

## 1. Objective

Give operators a minute-fresh, Neutron-visible answer to "why is this VM's
traffic being dropped or bypassed" without touching the eBPF data plane, the
ACL enforcement semantics, or the OVS forwarding path.

The pipeline reuses the existing heartbeat/status transport end to end. No new
real-time query channel is introduced in this phase.

## 2. Design Inputs (already decided)

| Decision | Choice |
| --- | --- |
| Consumer | operators/admin only; no tenant-visible surface |
| Freshness | minute-level snapshot carried on the existing agent→server heartbeat |
| Granularity | per-port aggregates + per-policy-bucket detail; no eBPF data-plane change; buckets shared by multiple Neutron rules are honestly reported as merged counts |
| Rates | agent computes pps/bps by differencing consecutive snapshots |
| Acceptance | CI/test evidence; field evidence deferred/pending per repo rules |

## 3. Non-Goals (v1)

- No real-time on-demand counter query channel.
- No `rule_id`-exact attribution in eBPF (bucket keys remain the accounting
  unit; the snapshot model has no rule_id today).
- No counter history or trend storage in Neutron DB (latest snapshot only).
- No flow top-N, no kernel-drop integration, no Prometheus/OTel exporter, no
  generic observability API. These remain Phase E items.
- No change to ACL verdict semantics, conntrack behavior, or OVS forwarding.

## 4. Architecture and Data Flow

```text
eBPF maps (unchanged)
  RULE_STATS         per PolicyKey: packets/bytes/dropped_packets/dropped_bytes
  DROP_REASON_STATS  per DropKey:   packets/bytes/last_seen
        │ read-only
aria-datapath (core/src/monitoring.rs + drop_ops.rs already read these maps)
        │ an explicit UDS status query gains an optional read-only `counters`
        │ section (same route and peercred policy; ordinary status/readiness
        │ responses never scan or serialize counters)
neutron-aria-agent
  when counters_report_enabled=true: explicitly fetch status+counters during
  each heartbeat cycle -> difference vs previous cycle
  -> compute pps/bps -> carry the datapath-provided group id -> CIDR map
  -> attach counters payload to the per-port status report
  (report_aria_acl_port_status, emitted within the same heartbeat cycle)
        │
neutron-server `aria_acl` plugin
  aria_acl_port_statuses  += summary columns + group map (latest snapshot)
  aria_acl_port_counters  new table (bucket + reason rows, latest snapshot only)
        │
neutron aria-acl-port-status-show <port> [--counters]
```

Note: the agent↔server transport in this repo is the per-port status report
(`report_aria_acl_port_status`), not the `report_state` heartbeat
`configurations` blob; both are emitted from the same heartbeat cycle.

Principles:

- Data plane untouched; the only new code paths are read-only aggregations and
  payload plumbing.
- Payload is bounded twice: per-port bucket rows are capped at 512 plus the
  fixed reason enumeration, and the complete optional counters section is
  limited by the remaining 1 MiB UDS response budget with 64 KiB reserved for
  encoding headroom. If the section cannot fit, it is replaced by an empty
  `counters_response_budget_exceeded` error section. The ordinary status and
  readiness responses remain counter-free.
- Counters are best-effort and can never degrade ACL apply or status.
- With `counters_report_enabled=false`, the Python agent never requests the
  counters view and the Rust status/readiness path performs no counter map
  scan. A failure of the explicit counters read is logged and retains the last
  good counter snapshot; it does not latch ACL writes closed.

## 5. Counting Semantics (normative)

The two eBPF views are independent and **must never be summed into one
"total"**.

| View | Source | Semantics |
| --- | --- | --- |
| policy view | `RULE_STATS` | per-bucket packets/bytes and dropped_* for traffic that hit an ACL policy bucket |
| drop view | `DROP_REASON_STATS` | authoritative per-port drop accounting keyed by reason, including non-ACL drops (fragment, QoS, parse) |

Overlap rule: a packet dropped by an ACL policy verdict is recorded in **both**
views (RULE_STATS.dropped_* and a DROP_REASON_STATS row with an ACL reason).
This is by design; the views answer different questions.

Pipeline-order caveat (verified in `ebpf/src/lib.rs`): a packet on the CT
fast-path may be counted as policy-allow in `RULE_STATS` and then dropped by a
later phase (e.g. QoS ingress) recorded in `DROP_REASON_STATS`. Therefore
`policy_allow + drop_total` double-counts such packets and is not a valid
derived metric. Derived metrics must stay inside a single view:

- `policy_allow = policy_packets − policy_dropped` (per bucket and per port)
- `drop_total = Σ drop view per port`
- `drop_pps` from drop view deltas only
- `pps`/`bps` are reported per view (`policy_pps`, `drop_pps`); no blended rate

Every counter row carries `sampled_at` (datapath wall clock) so readers can
judge staleness themselves.

## 6. Data Model

### 6.1 `aria_acl_port_statuses` new columns (all nullable, atomically replaced per report)

```text
counters_sampled_at    DateTime
counters_policy_packets        BigInteger
counters_policy_bytes          BigInteger
counters_policy_allow_packets  BigInteger
counters_policy_dropped_packets BigInteger
counters_policy_dropped_bytes  BigInteger
counters_policy_pps            Float
counters_drop_packets          BigInteger
counters_drop_bytes            BigInteger
counters_drop_pps              Float
counters_truncated             Boolean
counters_reset_detected        Boolean
```

### 6.2 New table `aria_acl_port_counters` (generic kind-row model)

```text
port_id      UUID   not null   FK, cascade delete on port removal
host         String not null
kind         Enum   bucket|reason  not null
src_id       Integer  (bucket rows; nullable)
dst_id       Integer  (bucket rows; nullable)
proto        Integer  (bucket rows; nullable)
direction    Enum    ingress|egress (bucket rows; nullable)
reason       Integer  (reason rows; nullable)
packets      BigInteger
bytes        BigInteger
dropped_packets BigInteger  (bucket rows only)
dropped_bytes   BigInteger  (bucket rows only)
pps          Float    nullable
bps          Float    nullable
sampled_at   DateTime not null

primary key (port_id, kind, src_id, dst_id, proto, direction, reason)
```

(If a backend cannot host nullable primary-key columns, use a surrogate
`id` primary key plus a unique index over the same column set. Note the
constraint is then approximate: most backends treat NULLs as distinct, so
duplicate rows whose key columns are NULL are not fully excluded. v1 relies
on the single-writer atomic replace-all upsert for row identity; a strict
natural key with non-NULL sentinel columns is a deferred hardening item.)

Upsert policy: each report replaces all rows for the port in one transaction
(latest snapshot only, no history). The generic `kind` column is the future
extension point: QoS/Mirror/flow counters become new `kind` values without a
schema change.

Existing deployments are upgraded by Alembic revision `a4e7c2d9b610`, whose
parent is the write-invariant revision `f61a2c4e7b90`. It adds the nullable
status columns, creates `aria_acl_port_counters`, preserves existing status
rows, and is idempotent when invoked through the runtime migration bridge. The
historical initial migration is intentionally unchanged so an already-created
database cannot be mistaken for an upgraded one.

The DB stores numeric ids only. Display-layer translation is carried
alongside the counters: the datapath reads its per-tap group registry
(`StateManager::list_groups`) and ships the id -> CIDR map in the counters
section; the server persists it on the status row (`counters_group_map`) and
the CLI renders bucket rows with CIDRs (numeric fallback when absent). A
dedicated group-name table remains out of scope.

## 7. Rate and Reset Semantics

- Agent keeps `(previous_sampled_at, previous_counters)` per port.
- `rate = (current − previous) / (current_sampled_at − previous_sampled_at)`
  computed with monotonic elapsed time; first snapshot reports `null` rates.
- Any negative delta (rule rebuild, ACL bank switch, WAL replay, port recreate,
  map clear) is treated as a reset: rates are reported `null`,
  `counters_reset_detected=true`, cumulative values are reported as-is. The
  agent must never fabricate monotonicity.
- `sampled_at` comes from the datapath (single clock source), not the agent
  clock, to keep the diff denominator consistent.

## 8. Contract and Compatibility

- UDS status schema becomes v3 with an **optional** `counters` section carrying
  `counters_schema_version=1` and `sampled_at`.
- Capability payload adds `counters_v1`; capability hash bumps per the existing
  contract discipline (`docs/neutron-status-contract-*.json` fixtures).
- Backward compatibility: an older datapath without the counters section makes
  the agent emit a counter-less status (existing v2 shape); the status pipeline
  must never be degraded by missing counters.
- Agent/server are upgraded together in the repo (existing convention); no
  cross-version counters negotiation beyond the optional-section check.

## 9. API / CLI and Permissions

- `neutron aria-acl-port-status-show <port>` renders the summary columns by
  default; `--counters` adds bucket rows and reason rows.
- Reasons render as names, never bare numbers; a `drop_reason_name` mapping
  already exists in `core/src/trace_ops.rs` and is extended to the complete
  enumeration in `abi/src/lib.rs` (ACL 1–3, QoS 4–5, fragment 6–19, plus the TC
  parse family).
- A companion operations dictionary doc (`docs/acl-drop-reason-dictionary.md`)
  records per reason: name, meaning, trigger conditions, and recommended
  troubleshooting action. v1 covers the ACL + fragment + parse families; QoS
  reasons are included in the vocabulary but are expected zero on
  Neutron-managed ports until QoS is product-enabled.
- Permissions remain `aria_acl` admin-only; no tenant-visible surface is added.

## 10. Failure Semantics

- Map read, aggregation, or explicit counters-response failure: the ordinary
  status contract remains readable, ACL writes remain governed only by that
  ordinary contract, and the agent keeps the last good counter snapshot. A
  successfully encoded counter error is carried in `counters_error`; an
  oversized section is reduced to
  `counters_response_budget_exceeded` with no port rows.
- Counter truncation, resets, or absence never change `runtime_status`,
  `effective_action`, or OVS forwarding.
- No new blocking paths: any counters bug is containable to the counters fields.

## 11. Enablement Gate

- New agent config `counters_report_enabled`, **default false**, shipped
  disabled until field RED/GREEN evidence exists (AGENTS.md deferred/pending
  rule; no fabricated field evidence).
- CI gates run the full counter pipeline with synthetic traffic regardless of
  the default.
- Group translation ships from the datapath group registry (id -> CIDR) as
  described in §6.2; a dedicated group-names table is explicitly out of v1
  scope and may be added when operator feedback demands it.

## 12. Testing and Acceptance

CI (must pass before merge):

- per-CPU aggregation correctness for RULE_STATS and DROP_REASON_STATS sums.
- counting-semantics unit tests: policy drop appears in both views; QoS-after-
  allow does not produce a blended total; reset detection on negative delta.
- truncation behavior at the 512-row cap and `truncated=true`.
- UDS v3 contract fixture: optional counters section, capability hash,
  counter-less datapath fallback.
- agent diff/rate math with synthetic clock data, including first-snapshot nulls.
- server DB upsert-replace atomicity and cascade cleanup on port delete.
- upgrade from the pre-counter write-invariant schema, including existing row
  preservation and repeated-upgrade idempotency.
- ordinary status/readiness omission of counters and explicit counters-query
  enforcement of the complete 1 MiB response budget.
- CLI rendering: reason names, group names, `--counters` expansion.

Field acceptance: recorded as deferred/pending until a real three-compute
environment is available; production enablement requires `counters_report_enabled`
plus observed RED/GREEN evidence, per AGENTS.md.

## 13. Documentation Alignment

- `docs/openstack-ebpf-platform-roadmap.md` Phase B checklist: mark per-rule hit,
  per-rule drop, per-port allow/drop, drop-reason vocabulary, and the
  explainability CLI view as delivered once CI gates pass; keep Phase E items
  untouched.
- `docs/aria-acl-neutron-extension-product-design.md` §6.8: add the new
  `aria_acl_port_statuses` columns and the `aria_acl_port_counters` table to the
  schema section.
- `docs/openstack-deployment-runbook.md`: document `counters_report_enabled`
  (default off) and the enable-after-evidence procedure.

## 14. Future Directions (explicitly deferred)

Real-time query channel; rule_id-exact attribution; counter history/trends;
flow top-N; kernel-drop integration; Prometheus/OpenTelemetry exporters;
generic observability API; strict natural key (non-NULL sentinel columns) for
`aria_acl_port_counters`. The `kind` column and `counters_schema_version` are
the two extension points reserved for those phases.
