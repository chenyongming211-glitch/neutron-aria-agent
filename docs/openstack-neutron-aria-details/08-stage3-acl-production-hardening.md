# 08. Stage-Three ACL Production Hardening

Status: active stage-three entry plan.

This document is the active stage-three entry plan. It starts after stage two
acceptance. It turns the working ACL production input loop into a
production-ready, auditable, release-gated path.

Post-stage-three incremental RPC design is recorded separately in
`09-aria-rpc-incremental-sync.md`. Stage three intentionally stops at
RPC-triggered full-resync and does not implement port-scoped delta apply.

## Goal

Make ACL production mode safe to ship and keep running:

- Release/CI gate covers stage-two acceptance evidence and Rust checks.
- Persistent UDS hardening rollout has a controlled path.
- ACL N3 fault and lifecycle gates are explicit.
- Full-resync first remains the production update model.

## Non-Goals

- Do not expand QoS/Mirror.
- Do not implement port-scoped delta apply before full-resync reliability is
  proven under N3 lifecycle tests.
- Do not turn temporary root SSH probes into production runtime behavior.
- Do not fix target metadata service HTTP 500 inside Aria; record it as target
  environment degraded until the metadata backend socket is repaired.

## Entry Criteria

Stage two must be accepted by:

```text
python ci/check_stage2_acceptance_evidence.py
python ci/check_neutron_stage2_acl.py
python ci/check_neutron_stage1.py
```

The 2026-06-30 stage-two acceptance summary is the current evidence root:

```text
docs/evidence/openstack-n05-lite/2026-06-30-stage2-acceptance-summary.md
```

## Work Packages

| Work Package | Scope | Exit Criteria |
| --- | --- | --- |
| S3-1 Release/CI gate | Wire stage-two evidence, N0.5, UDS hardening, and Rust-required checks into GitHub Actions. | CI runs stage-two evidence checks and `check_neutron_stage1.py --require-rust --rust-toolchain stable` when Rust build is required or workflow is manually dispatched. |
| S3-2 Persistent UDS hardening rollout | Turn reversible proof into a release/ops rollout path. | `REQUIRE_HARDENED=true` smoke passes after deploying peercred-enabled datapath image and non-world-writable socket on each target host. |
| S3-3 ACL N3 fault gates | Exercise missing binding, missing policy, ACL apply failure, and rollback. | Every failure reports degraded/bypass or unsupported without disrupting OVS forwarding or falsely reporting ready. |
| S3-4 ACL lifecycle gates | Exercise OVS restart, tap recreate, VM migration, and same-host VM visibility where the target environment exposes the needed resources. | Lifecycle smoke either passes or records explicit `not_applicable` / `unsupported` disposition. |
| S3-5 Event skeleton | Keep RabbitMQ events disabled by default; when enabled, event receipt triggers full-resync. | Event consumer does not perform unsafe partial delta apply; delete/update filtering respects local projected state and `binding:host_id`. |

## Required Scripts And Evidence

Existing scripts are the stage-three starting point:

| Gate | Script |
| --- | --- |
| Release bundle | `deploy/kolla/package/build_stage2_acl_bundle.sh` |
| Stage-two install gate | `deploy/kolla/smoke/neutron_aria_acl_stage2_gate_smoke.sh` |
| UDS hardening | `deploy/kolla/smoke/neutron_aria_uds_hardening_smoke.sh` |
| Reversible UDS rollout | `deploy/kolla/smoke/neutron_aria_uds_hardened_rollout_smoke.sh` |
| ACL fault injection | `deploy/kolla/smoke/neutron_aria_acl_fault_injection_smoke.sh` |
| Crash recovery | `deploy/kolla/smoke/neutron_aria_crash_injection_smoke.sh` |
| Delete recovery | `deploy/kolla/smoke/neutron_aria_delete_fault_injection_smoke.sh` |
| OVS restart | `deploy/kolla/smoke/neutron_aria_ovs_restart_smoke.sh` |
| Tap recreate | `deploy/kolla/smoke/neutron_aria_tap_recreate_smoke.sh` |
| VM migration | `deploy/kolla/smoke/neutron_aria_vm_migration_smoke.sh` |
| Rollback/connectivity | `deploy/kolla/smoke/neutron_aria_rollback_connectivity_smoke.sh` |

The active N3 evidence summary is:

```text
docs/evidence/openstack-n05-lite/2026-06-30-stage3-n3-summary.md
```

`python ci/check_stage3_n3_evidence.py` validates the evidence schema during
normal CI. Stage-three closure must additionally pass
`python ci/check_stage3_n3_evidence.py --require-complete`, which rejects any
remaining `pending` gate.

## N3 Fault Gate Semantics

| Scenario | Required Result |
| --- | --- |
| No `aria_acl` binding | When the ACL domain is Neutron-managed, the port may remain locally claimed for `acl` write arbitration, but the effective ACL status must be `not_requested` with `effective_action=bypass`; OVS forwarding remains baseline. |
| Binding references missing policy | Domain status is degraded/bypass; OVS forwarding remains baseline. |
| ACL compile/apply failure | Domain status is degraded/bypass; no false ready. |
| UDS timeout | Python remains pending/degraded and reconciles through status/full-resync. |
| Rollback | UDS delete removes managed ports and OVS connectivity recovers. |

## Lifecycle Gate Semantics

| Scenario | Required Result |
| --- | --- |
| OVS agent / ovs-vswitchd / ovsdb-server restart | Aria does not own OVS forwarding health. If the tap still exists, Aria validates tap identity, XDP attachment, ACL maps, generation, and rollback. If the tap is missing or recreated, Aria follows the tap lifecycle rules below. |
| Tap recreate | Old ifindex is not trusted after recreate; full-resync or status recovery repairs projection. |
| VM migration / rebind | Old host removes local managed state; new host applies only after authoritative binding matches. |
| Same-host VM traffic | If target environment exposes two local VMs, visibility and direction are recorded; otherwise mark `not_applicable`. |

### OVS Restart Boundary

OVS restart handling is deliberately scoped to Aria's attachment boundary. Aria
must not become an OVS data-plane health checker and must not mark ACL degraded
only because end-to-end VM ping fails while OVS is restarting.

| Condition after OVS restart | Aria behavior | Status expectation | Smoke evidence |
| --- | --- | --- | --- |
| tap exists, same ifindex, XDP still attached | Keep ACL runtime state, verify maps/generation, allow rollback/delete. | ACL may remain `ready/effective_action=enforce` if policy state is valid. | `ip -d link`, UDS status, ACL policy/map evidence, rollback evidence. |
| tap exists, same ifindex, XDP missing | Idempotently reattach XDP and recheck maps. | `degraded` only until reattach succeeds, then `ready`. | attach/retry log, UDS status before/after. |
| tap exists, ifindex changed | Treat as tap recreate; do not trust stale runtime state. | `degraded` or detached until full-resync rebinds new ifindex. | old/new ifindex, full-resync generation, reattach evidence. |
| tap missing | There is no local attach target; clear stale runtime projection and preserve desired snapshot intent for the next resync. | `detached` or `degraded` with reason such as `interface_missing`; do not report ACL ready. | missing link evidence, zero stale XDP state, recovery after tap returns. |
| OVS forwarding temporarily fails but tap/XDP remain healthy | Do not reinterpret this as ACL failure. | ACL attach status remains based on tap/XDP/map health. | Record VM ping separately as OVS forwarding evidence, not ACL disposition. |

An `ovs-restart` smoke should therefore have two result channels:

- ACL attach result: tap identity, XDP attachment, ACL maps, generation, WAL, and
  rollback.
- OVS forwarding observation: VM ping or flow recovery during the OVS
  maintenance window.

Only the first channel decides whether Aria ACL lifecycle passed. The second
channel is operational evidence for OVS recovery and should not force Aria to
inspect OpenFlow/ofport state. Aria runtime and smoke scripts must not restart
OVS or OVS agent; the `ovs-restart` smoke may only observe an externally
scheduled maintenance action. In an isolated test environment, the smoke may
trigger `ovs-vswitchd` restart only through an explicit test harness flag; this
must not be implemented in Aria runtime or production automation.

## CI Contract

GitHub Actions must run:

```text
python3 ci/check_neutron_stage1.py
python3 ci/check_neutron_stage2_acl.py
python3 ci/check_n05_discovery_evidence.py
python3 ci/check_uds_hardening_evidence.py --require-hardened ...
python3 ci/check_stage2_acceptance_evidence.py
python3 ci/check_stage3_readiness.py
python3 ci/check_stage3_n3_evidence.py
python3 ci/check_smoke_python_blocks.py
bash deploy/kolla/package/build_stage2_acl_bundle.sh
```

When Rust/eBPF files change, on tag builds, or on manual workflow dispatch, CI
must run the Rust-required path:

```text
python3 ci/check_neutron_stage1.py --require-rust --rust-toolchain stable
cargo +stable test -p aria-agent startup_mode
cargo +stable test -p aria-agent domain_authority
cargo +nightly build --release --target bpfel-unknown-none -Z build-std=core
```

## Acceptance

Stage three is ready to close only when:

- CI/release gates include the stage-two evidence check and stage-three
  readiness check.
- Rust-required CI has run successfully in GitHub Actions or another
  Rust-enabled CI environment.
- Persistent UDS hardening has a passed rollout record, or the release is
  explicitly marked audit-only for UDS peer auth.
- ACL N3 fault and lifecycle gates have pass/degraded/unsupported evidence.
- `python ci/check_stage3_n3_evidence.py --require-complete` passes.
- QoS/Mirror remain out of this stage unless a separate approved goal opens
  them.
