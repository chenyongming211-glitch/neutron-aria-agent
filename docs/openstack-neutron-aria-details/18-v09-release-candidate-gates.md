# v0.9 Release Candidate Gates

Status: normative release sequence; P0-P4 complete. The current persistent
Rust/eBPF runtime candidate is
`7ffc5d65d9b30d0a1f9e706ec779cc8213200458`; it is deployed as the same local
Kolla RC image on both available computes. P5 remains partial because one
compute is unavailable. P6-P7 remain pending or deferred as recorded below.

## Purpose

This document turns the existing implementation history into a status-aware
release path. It does not reopen completed architecture work and does not add
tenant features.

The order is:

```text
P0 trusted source baseline
  -> P1 legacy-kernel stack architecture
  -> P2 exact-candidate CI artifacts
  -> P3 exact-artifact 4.18 isolated canary
  -> P4 single-node release candidate
  -> P5 three-node final acceptance
  -> P6 release governance
  -> P7 QoS, then Mirror
```

RPC P2 and config-gated P3 are regression scope in P5, not an independent
feature-development stream. Storm/DDoS remains design-only and is outside the
ACL release path.

## Gate Status

| Gate | Status | Exit evidence |
| --- | --- | --- |
| P0 trusted source baseline | complete | Shared ACL error contract locked; Windows and Linux fast contracts and public-term scan green; generated outputs excluded; source/history boundary recorded. |
| P1 legacy-kernel stack architecture | complete for current runtime candidate | Two-slot CT key scratch and the 448-byte budget gate are present. The `7ffc5d6` artifact reports 448 bytes for both TC ingress and egress; no tail-call expansion is planned. |
| P2 exact-candidate CI artifacts | complete for candidate `7ffc5d65d9b30d0a1f9e706ec779cc8213200458` | Exact-artifact workflow `31477810061` produced the Rust/eBPF files used by the persistent RC image. Runtime hashes and the stack budget are recorded in the persistent two-compute evidence. |
| P3 4.18 isolated canary | complete for current runtime candidate | Exact `7ffc5d6` artifacts passed the target-kernel standalone system, standalone tap, and focused Neutron-managed TC authority suites. XDP remained ACL/CT-neutral, restart recovery admitted zero packets, and OVS identities were unchanged. |
| P4 single-node release candidate | complete for persistent image | Compute A passed exact-image deployment, readiness, real ACL traffic, actual old-version rollback, fresh container recreation, and a 2,994-reply zero-failure OVS canary without restarting OVS or OVS-agent. |
| P5 three-node final acceptance | partial pass; blocked on one unavailable compute | Both available computes now run the same persistent `7ffc5d6` image and passed rollback, recreation, readiness, ACL lifecycle, cleanup, and OVS non-interference. Earlier production-agent RPC fanout, foreign-host filtering, migration-source cleanup, and event-driven restore evidence remains valid. The same suite remains required on the unavailable compute before P5 can close. |
| P6 release governance | pending | Version, license, manifest, checksums, support matrix, change log, upgrade, and rollback rules are frozen. |
| P7 QoS then Mirror | deferred | Starts only after P6; no ACL release work is displaced by new feature scope. |

## P0 Trusted Source Baseline

### Source and history boundary

- P0 input HEAD was `492799dc76c307a730c4d7ee5e077ef372513ed6` on
  `codex/ebpf-legacy-stack-budget`.
- The candidate SHA is not frozen until P0 changes are committed and P2 builds
  that exact clean tree.
- `stash@{0}` is a historical pre-pull backup. It contains older specialized
  ACL error reasons and unrelated field tooling; it is not candidate source
  and must not be applied wholesale.
- Committed `docs/evidence/` files are historical field evidence unless they
  explicitly bind themselves to the P2 candidate SHA and artifact hashes.
- `.artifacts/` and Python `build/`, `dist/`, and `*.egg-info/` directories are
  generated outputs. They are not candidate source and remain excluded from
  version control.

### ACL error contract

The authoritative validation details come from the shared ACL contract:

```text
default_action must be allow
source port matching is unsupported
```

Runtime projection wraps those details with stable category and identity:

```text
unsupported_policy:<detail>
unsupported_rule:<rule-id>:<detail>
```

The older `unsupported_default_action` and `unsupported_src_port_match`
spellings in the historical stash are not the current contract. Tests must not
restore them merely to match old expectations.

### Platform boundary

The production compatibility authority is the target Linux/Python 2 Kolla
environment. Linux atomic rename-over-existing behavior is part of that target
contract. P0 runs the full source lane on Linux/Python 3; the independent
Python 2.7 clean-container package lane is an exact-candidate P2 gate. Windows
development runs may expose different `os.rename()`
overwrite behavior; such a result is recorded as a platform-specific developer
compatibility issue unless the same behavior reproduces in the target
container. It is not evidence of a Linux product defect by itself.

Cross-platform source tests still run where practical. Platform classification
must never be used to waive a failure that reproduces on target Linux.

### Historical verifier baseline

The pre-remediation maintained-kernel verifier rejected both TC entry paths
with a worst combined call-path stack of 544 bytes against the 512-byte kernel
limit. This is the immutable RED baseline. P1 moved primary and TCP-RT-derived
keys into two-slot per-CPU scratch and added a 448-byte release budget. P2 must
measure the final linked candidate artifact; source shape alone is not release
evidence.

### P0 exit checks

P0 is complete only when all of the following hold:

1. Fast Python and legacy CLI contracts pass from the active source tree on
   Windows and Linux.
2. The two shared runtime error wrappers above have explicit regression tests.
3. Public blocked-term scanning and `git diff --check` pass.
4. Tracked candidate changes are intentional; generated outputs remain
   untracked and ignored.
5. No Rust/eBPF binary is built locally and no field service is modified.

## Guardrails

- Aria never restarts OVS or `neutron-openvswitch-agent` as recovery behavior.
- Managed ACL/CT authority is TC ingress and egress. XDP remains ACL/CT-neutral
  unless a separately declared product mode says otherwise.
- Scratch or attach uncertainty preserves original OVS forwarding and must be
  surfaced as degraded/bypass rather than silently treated as enforcement.
- Deployment components are selected from the candidate change manifest; do
  not restart an unchanged service merely because an earlier rollout did.
- Do not start QoS, Mirror, Storm/DDoS, or tail-call architecture work inside
  P0-P6 unless a recorded release blocker requires it.

## Current Candidate Evidence

- P0 source baseline:
  `docs/evidence/openstack-n05-lite/20260810-p0-trusted-source-baseline/summary.md`
- P2 exact-candidate CI artifacts:
  `docs/evidence/openstack-n05-lite/20260810-p2-exact-candidate-artifacts/summary.md`
- P3 maintained-kernel isolated canary:
  `docs/evidence/openstack-n05-lite/20260810-p3-legacy-kernel-canary/summary.md`
- P4 single-node release candidate:
  `docs/evidence/openstack-n05-lite/20260810-p4-single-node-release-candidate/summary.md`
- P5 two-node current-candidate partial evidence:
  `docs/evidence/openstack-n05-lite/20260811-p5-two-node-current-candidate/summary.md`
- Persistent `7ffc5d6` two-compute Kolla RC:
  `docs/evidence/openstack-n05-lite/20260811-persistent-7ffc5d6-two-compute-rc/summary.md`
