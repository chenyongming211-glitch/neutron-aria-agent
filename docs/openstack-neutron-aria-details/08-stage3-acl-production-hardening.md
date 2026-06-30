# 08. Stage-Three ACL Production Hardening

Status: active stage-three entry plan.

This plan starts after stage two acceptance. It turns the working ACL
production input loop into a production-ready, auditable, release-gated path.

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
| Tap recreate | `deploy/kolla/smoke/neutron_aria_tap_recreate_smoke.sh` |
| VM migration | `deploy/kolla/smoke/neutron_aria_vm_migration_smoke.sh` |
| Rollback/connectivity | `deploy/kolla/smoke/neutron_aria_rollback_connectivity_smoke.sh` |

## N3 Fault Gate Semantics

| Scenario | Required Result |
| --- | --- |
| No `aria_acl` binding | Port remains bypass/not_requested; no local ACL authority is claimed. |
| Binding references missing policy | Domain status is degraded/bypass; OVS forwarding remains baseline. |
| ACL compile/apply failure | Domain status is degraded/bypass; no false ready. |
| UDS timeout | Python remains pending/degraded and reconciles through status/full-resync. |
| Rollback | UDS delete removes managed ports and OVS connectivity recovers. |

## Lifecycle Gate Semantics

| Scenario | Required Result |
| --- | --- |
| OVS agent / ovs-vswitchd / ovsdb-server restart | Aria reports degraded or recovers; no silent ready with stale tap identity. |
| Tap recreate | Old ifindex is not trusted after recreate; full-resync or status recovery repairs projection. |
| VM migration / rebind | Old host removes local managed state; new host applies only after authoritative binding matches. |
| Same-host VM traffic | If target environment exposes two local VMs, visibility and direction are recorded; otherwise mark `not_applicable`. |

## CI Contract

GitHub Actions must run:

```text
python3 ci/check_neutron_stage1.py
python3 ci/check_neutron_stage2_acl.py
python3 ci/check_n05_discovery_evidence.py
python3 ci/check_uds_hardening_evidence.py --require-hardened ...
python3 ci/check_stage2_acceptance_evidence.py
python3 ci/check_stage3_readiness.py
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
- QoS/Mirror remain out of this stage unless a separate approved goal opens
  them.
