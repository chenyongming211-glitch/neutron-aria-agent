# 04. UDS Contract And Security Detail Plan

Status: stage-one implementation package; capabilities metadata, contract
artifact, Python validation, body-size bounds, socket mode validation,
connection-level peer credential audit/enforcement hooks, and a persistent
Kolla production-profile installer are implemented.

## Goal

Make the local Unix socket API between `neutron-aria-agent` and `aria-datapath`
stable, versioned, size-bounded, and auditable.

## UDS Routes

```text
GET    /api/v1/neutron/capabilities
GET    /api/v1/neutron/status
PUT    /api/v1/neutron/snapshot
DELETE /api/v1/neutron/ports/{port_id}
```

These routes must not be exposed through the TCP OpenAPI router.

P3 port-scoped snapshot is documented in `docs/neutron-uds-contract.json` as an
implemented, config-gated contract:

```text
PUT /api/v1/neutron/ports/{port_id}/snapshot
```

It is listed in the implemented UDS `routes` and advertised through
`supports_port_scoped_snapshot=true`, but Python only uses it when
`incremental_rpc_enabled=true` is explicitly configured. The contract uses the
current 1 MiB request body cap and 3000 ms UDS timeout until measurement proves
a different limit is needed. Unsafe revision, contract, body-size,
multi-port/network batch, or local-interface conditions must fall back to full
resync rather than trying a best-effort scoped apply.

The Rust-side minimum implementation and test boundary for this planned route
is recorded in `10-rust-scoped-apply.md`. Until that boundary is implemented
and tested, the route must remain absent from current runtime `routes`.

## Capabilities Contract

Target fields:

| Field | Purpose |
| --- | --- |
| `api_version` | Local UDS API version. |
| `contract_version` | Generated contract artifact version. |
| `schema_version_min/max` | Snapshot schema compatibility. |
| `attach_authority` | Must be `neutron_snapshot`. |
| `supported_domains` | Accepted managed domains. |
| `mandatory_domains` | Domains required for this deployment profile. |
| `body_max_bytes` | Request body upper bound. |
| `timeout_ms` | Recommended client timeout. |
| `error_codes_hash` | Drift detection for stable errors. |
| `peer_auth_policy` | Expected Unix peer credential policy. |
| `capability_hash` | Overall capability drift detection. |

## Contract Artifact

The stage-one contract artifact is:

```text
docs/neutron-uds-contract.json
```

`ci/check_neutron_stage1.py` validates this artifact against the Python UDS
client constants. Rust-side drift is covered by the Rust `neutron_contract`
tests when `cargo` is available. Peer credential enforcement is config-gated:
the safe default package runs in audit-only mode, while production hardening
sets `neutron_peercred_enforce=true` plus an explicit uid/gid allow-list after
N0.5 records the final container identity.

The safe default file is intentionally not a production profile. Production
deployment uses
`deploy/kolla/package/install_aria_uds_peercred_profile.sh`, which discovers
the final numeric identity from the running Neutron agent container, renders
one exact allow-list, atomically replaces the host-mounted Kolla config, and
keeps a rollback preimage. Re-running `apply` on a valid profile performs a
read-only verification and does not restart the datapath.

## Peer Authentication

Target behavior:

- socket directory: `root:neutron-aria 0770`;
- socket file: `aria-datapath:neutron-aria 0660`;
- server verifies Unix peer uid/gid through `SO_PEERCRED` on Linux when
  `neutron_peercred_enforce=true`;
- unauthorized peer connections are closed before request parsing and recorded
  with reason `UDS_PEER_UNAUTHORIZED`;
- inability to read peer credentials closes the connection with reason
  `UDS_PEERCRED_UNAVAILABLE` when enforcement is enabled;
- when enforcement is disabled, peer credentials are still audited when
  available and the deployment remains in audit-only mode.

## Audit

The implemented v0.9 gate audits each UDS connection:

- peer uid/gid/pid when available;
- allow/deny result;
- reason code;
- credential read error when present.

Later route-level audit may add:

- route and method;
- generation;
- body size;
- result code;
- error code.

## Timeout Semantics

Client timeout does not mean apply did not happen. Python must reconcile through
status/full resync before deciding whether to retry or bump generation.

## Implementation Design Package

This package is detailed to file/schema/flow/test level. Do not expand to
function-call level until the UDS contract PR is opened.

### Target Files

| File | Role |
| --- | --- |
| `api/src/lib.rs` | Rust DTO definitions shared by the local UDS API. |
| `agent/src/neutron_api.rs` | UDS route handlers, validation, status responses, and error mapping. |
| `agent/src/neutron_wal.rs` | WAL-visible error/status interaction for mutating routes. |
| `agent/src/main.rs` and `config/aria-agent.toml` | Current Rust agent entry/config path for socket, body limit, and peer auth policy settings until a dedicated config module exists. |
| `openstack/neutron_aria/neutron_aria/agent/uds_client.py` | Python client handshake, capability validation, timeout behavior. |
| `openstack/neutron_aria/neutron_aria/tests/unit/` | Python tests for capability mismatch, timeout, and body limit handling. |
| `docs/neutron-uds-contract.json` | Stage-one UDS contract artifact checked by `ci/check_neutron_stage1.py`. |
| `docs/neutron-managed-domains-contract.md` | Human-readable short contract that links the generated artifact. |
| `deploy/kolla/package/install_aria_uds_peercred_profile.sh` | Persistent Kolla-host production profile apply/check/rollback boundary. |
| `ci/test_aria_uds_peercred_profile.sh` | Deterministic render, exact-key, idempotency, and invalid-identity contract. |

### Contract Schema Levels

| Level | Fields | Purpose |
| --- | --- | --- |
| Minimum current contract | `api_version`, `attach_authority`, `supports_full_snapshot`, `supports_port_delete`, `supported_domains` | Existing handshake needed before Python sends production snapshots. |
| v0.9 target contract | Current fields plus `contract_version`, `schema_version_min/max`, `body_max_bytes`, `timeout_ms`, `error_codes_hash`, `peer_auth_policy`, `capability_hash` | Drift detection, bounded requests, and security posture. |
| P3 port-scoped contract | `p3_port_scoped_snapshot` route, body/timeout limits, error list, advertised capability, and config-gated runtime guardrails | Entry-gate documentation for incremental RPC with packaged runtime disabled by default. |
| Later extension | Optional route-level capability detail | Only add if domain-level capability proves insufficient. |

### Capability Handshake Flow

1. Python starts and loads `[aria]` UDS settings.
2. Python calls `GET /api/v1/neutron/capabilities` before enabling production
   snapshot submission.
3. Python validates `attach_authority == neutron_snapshot`.
4. Python validates full snapshot and port delete support for enabled flows.
5. Python validates every configured `managed_domains` item is supported.
6. Python validates schema/contract/body-limit fields when present.
7. If validation fails, Python remains degraded and must not submit mutating
   production snapshots.

### Request Boundaries

| Boundary | Required Behavior |
| --- | --- |
| Body size | Rust rejects oversized requests before apply and returns `UDS_BODY_TOO_LARGE`. |
| Schema version | Rust rejects unsupported schema with `UDS_SCHEMA_MISMATCH`. |
| Unsupported domain | Rust rejects or degrades before mutation; Python should catch this at handshake. |
| Timeout | Python uses status reconciliation from `07-transaction-wal.md`. |
| TCP exposure | Neutron routes stay UDS-only. |

### Peer Auth Rollout

Implement in phases to avoid overengineering:

1. Phase A: package socket directory/file ownership and permissions in deploy
   docs and containers.
2. Phase B: expose `peer_auth_policy` in capabilities and contract artifact.
3. Phase C: enforce peer uid/gid at connection accept time when platform support
   is available and `neutron_peercred_enforce=true`.
4. Phase D: add connection audit fields for uid/gid/pid when available.
5. Optional later phase: add route/generation/body-size fields to audit lines
   if operations need that detail.

Persistent production rollout uses the implemented phase A-D settings in one
serial per-host transaction. A failed apply restores the saved config and
runtime-directory preimage. It may restart only `aria_datapath`; it must never
restart OVS or `neutron-openvswitch-agent`.

If peer credentials are unavailable on the target platform, the deployment must
either fail closed for production mutating routes or explicitly run in a
documented degraded mode.

Deployment gates in `06-deployment-n05-runbook.md` must reference this Phase
A-D sequence. Production mutating routes must not advance beyond the accepted
security phase for the target environment.

### Error Semantics

| Condition | Stable Error |
| --- | --- |
| Body too large | `UDS_BODY_TOO_LARGE` |
| Schema mismatch | `UDS_SCHEMA_MISMATCH` |
| Missing required capability | `UDS_CAPABILITY_MISMATCH` |
| Unsupported domain | `UDS_UNSUPPORTED_DOMAIN` |
| Unauthorized peer | `UDS_PEER_UNAUTHORIZED` |
| Peer credentials unavailable | `UDS_PEERCRED_UNAVAILABLE` |
| Route exposed outside UDS | packaging/configuration failure; not a runtime fallback |

### Test Matrix

| Test | Expected Result |
| --- | --- |
| Python starts with matching capabilities | Mutating snapshot path may be enabled according to config gates. |
| Missing required domain | Python remains degraded and does not submit production snapshot. |
| Unsupported schema | Rust returns `UDS_SCHEMA_MISMATCH`; Python records degraded. |
| Oversized body | Rust returns `UDS_BODY_TOO_LARGE` before mutation. |
| Timeout on mutating request | Python reconciles through status and transaction logic. |
| Unauthorized peer | With peercred enforcement enabled, Rust closes the UDS connection before request parsing and audits `UDS_PEER_UNAUTHORIZED`. |
| Contract artifact drift | Test fails until artifact is updated intentionally. |
| TCP router scan | Neutron routes are not reachable through TCP API. |

### Anti-Overengineering Guardrails

- Do not add TCP fallback for Neutron control.
- Do not add mTLS, OAuth, or remote auth for this local channel.
- Do not make every field optional once it is part of the v0.9 contract.
- Do not block CI fixture smoke on peercred enforcement; packaged safe defaults
  stay audit-only until N0.5 records the production uid/gid allow-list.

## Acceptance

- Contract drift test exists.
- Body too large returns `UDS_BODY_TOO_LARGE`.
- Unsupported schema returns `UDS_SCHEMA_MISMATCH`.
- Socket permission Phase A is enforced with a non-world-writable OpenStack sample config.
- Peercred enforcement/audit hooks are implemented and config-gated; the safe
  default package is audit-only, and production enablement must set the final
  uid/gid allow-list from N0.5 evidence.
- The Kolla production-profile installer renders exactly one hardened key set,
  rejects invalid identity input, preserves unrelated config, verifies allowed
  and denied peers, and supports rollback.
- Timeout recovery is covered by smoke or unit tests.

## Non-Goals

- Do not add TCP fallback.
- Do not rely only on filesystem permissions for production security.
- Do not make best-effort apply on contract mismatch.
