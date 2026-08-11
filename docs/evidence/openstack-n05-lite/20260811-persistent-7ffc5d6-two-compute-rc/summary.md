# Persistent Two-Compute Kolla RC Evidence

Date: 2026-08-11

Status: partial pass. The two available computes run the same persistent Kolla
release-candidate image built from the exact `7ffc5d6` Rust/eBPF artifacts.
Both computes passed old-version rollback, fresh container recreation, runtime
identity, readiness, real ACL traffic, cleanup, and independent OVS safety
checks. The unavailable third compute still prevents the three-compute P5 gate
from closing.

## Candidate Identity

| Item | Identity |
| --- | --- |
| Runtime source commit | `7ffc5d65d9b30d0a1f9e706ec779cc8213200458` |
| Exact-artifact workflow | `31477810061` |
| Rust `aria-agent` SHA-256 | `687af9d6a319eb1858004e5cff8bfe061e3693217c401e0a9b033a92e86d3079` |
| eBPF object SHA-256 | `6488da9614a7ce81d0d2ae6271ffd0108d084a2115c2d37da02f6dcda13ab50f` |
| eBPF perf object SHA-256 | `6488da9614a7ce81d0d2ae6271ffd0108d084a2115c2d37da02f6dcda13ab50f` |
| Stack budget | TC ingress `448` bytes; TC egress `448` bytes |
| Local RC image tag | `aria-datapath:rc-7ffc5d6` |
| Image ID | `sha256:91377e742a2b455729bab83f50c3c21292e4b72f060210461781f00336e5f319` |
| Image archive SHA-256 | `df32ff1b7a59dc37707a534555e23e19461dbfcd8157363b2be8ad69932a9efe` |

The image was built once from the CI artifacts and the existing Kolla package
path, exported once, and loaded on both computes. The three runtime files in
both final containers match the table above.

## Rollout Results

| Check | Compute A | Compute C |
| --- | --- | --- |
| Load the same image ID | passed | passed |
| Start from the Kolla image | passed | passed |
| UDS `/readyz` | `ready` | `ready` |
| Accepted/applied generation convergence | passed | passed |
| WAL state | `commit_written` | `commit_written` |
| Actual old-version rollback | passed | passed |
| Fresh RC container recreation | passed | passed |
| Runtime hashes after recreation | passed | passed |
| Real ACL enforce and traffic block | passed | passed |
| ACL disable/delete and traffic restore | passed | passed |
| Temporary ACL object cleanup | not applicable; existing disabled test objects retained | passed; zero residue |
| Independent OVS canary | 2,994 replies, zero failure markers | 1,330 replies, zero failure markers |
| OVS and OVS-agent identity unchanged | passed | passed |

Aria did not restart or modify OVS or the Neutron OVS agent. The final runtime
on each compute is the freshly recreated RC container, not the container that
received the initial rollout. Stopped pre-RC containers remain available as
bounded local rollback points.

## Runtime Semantics

The TCP health endpoint returned `status=ok` and zero WAL replay failures on
both computes. The Neutron-authenticated UDS readiness endpoint returned
`overall_readiness=ready`, equal accepted and applied generations, no pending
generation, and `wal_status=commit_written`.

Kernel-drop observability remained explicitly disabled in this deployment and
reported its optional map as unavailable. This did not change ACL readiness,
TC enforcement, rollback, or OVS forwarding and is not treated as a hidden
pass for that separate observability capability.

## Persistence Boundary

This closes the manual-file-overlay gap recorded by the all-mode ACL evidence:
the candidate now exists as a reusable Kolla-compatible image, and deleting
and recreating the service container preserves the exact candidate files.

The image and its archive are currently stored on the target computes. They
have not been pushed to a production registry, and a future site-wide Kolla
redeploy must reference the RC or a promoted release tag explicitly. Registry
publication and site-wide image governance remain P6 work.

## Remaining Gate

P5 remains partial until the unavailable compute can load this exact image and
pass the same rollout, rollback, readiness, ACL lifecycle, OVS safety, RPC,
and no-orphan checks. This evidence must not be described as three-compute
acceptance or as a formal release.
