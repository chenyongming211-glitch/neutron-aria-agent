# RISK-SEC-001 UDS Peercred Production Profile

Date: 2026-08-10

Status: production installer and two-available-node field validation complete;
the unavailable compute remains pending.

## Scope And Safety

- Added a Kolla-host `render/apply/check/rollback` installer for the existing
  Rust peer-credential enforcement capability.
- Kept the generic bootstrap config audit-only because numeric container
  identities are site-local; production values are discovered at install time.
- Used only the two available test computes. The unavailable compute was not
  accessed.
- Restarted only `aria_datapath` during the controlled apply/rollback test.
- Did not restart or modify OVS or `neutron-openvswitch-agent`.
- Did not change or locally compile Rust/eBPF code.

## Production Contract

The installer discovers the numeric `neutron` UID/GID from the running Python
agent container and renders exactly one hardened key set:

- socket mode `0660`;
- peercred enforcement enabled;
- explicit UID and GID allow-lists;
- persistent UDS audit path.

It atomically replaces the host-mounted Kolla config, changes `/run/aria` to
the discovered group with mode `0770`, restarts only the datapath when a change
is required, and stores config plus directory metadata for rollback. An
already-correct profile is verified without restarting.

## Defects Found During Field Validation

1. Bash `set -e` did not stop a configuration-check function when that
   function was called from an `if` condition. A mismatched middle field could
   therefore be ignored if the final field matched. Every check now propagates
   failure explicitly, and an automated conditional-call regression covers it.
2. A stale Unix socket pathname survived datapath restart briefly. Waiting
   only for the socket file and permissions allowed an early probe to receive
   connection refused. Restart readiness now also requires a successful
   authorized UDS Status V1 request.

Both failed attempts restored the known hardened profile through their
fail-safe path. Their VM canaries recorded 15/15 and 20/20 replies with zero
loss.

## Verification

| Check | Result |
| --- | --- |
| Render contract | Replaces duplicate/legacy peercred keys, preserves unrelated config, rejects invalid identity input, rejects source/output aliasing, and is deterministic across repeated renders. |
| Conditional regression | A middle-field mismatch fails even when `check_config` is called from an `if` condition. |
| Available-node `check` | Both nodes verified exact config, directory/socket permissions, authorized Python-agent access, denied root peer access, and allow/deny audit records. |
| Controlled apply | One node migrated from a still-secure UID-only preimage to the complete UID/GID profile and passed runtime verification. |
| Controlled rollback | Rollback restored the exact UID-only secure preimage and restarted only the datapath. |
| Controlled reapply | Reapply restored the complete production profile and composite readiness. |
| Idempotent apply | The other available node retained the identical datapath `StartedAt` value; no restart occurred. |
| Forwarding canary | Final apply/rollback/reapply run transmitted and received 55/55 packets with zero loss. |
| OVS isolation | `neutron_openvswitch_agent` retained the identical start timestamp across the controlled rollout. |
| Composite readiness | Both available nodes finished with heartbeat alive, Status V1 and `/readyz` equal, HTTP 200, zero generation lag, and `composite_ready=true`. |
| Fast contracts | 584 Python tests passed with 8 environment-dependent skips; 10 CLI tests and all package/install contracts passed. |
| Bundle | Generated Kolla bundle contains the executable installer and its manifest entry. |

## Remaining Boundary

Run the same `apply` and `check` operations on the unavailable compute after it
is restored and its final container identity is rediscovered. Do not copy the
numeric allow-list from another host without checking the local identity.
