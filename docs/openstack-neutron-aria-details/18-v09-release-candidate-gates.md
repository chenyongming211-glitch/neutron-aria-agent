# v0.9 Release Candidate Gates

Status: normative release sequence; P0 source baseline complete, P1
implemented, P2-P7 pending or deferred as recorded below.

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
| P1 legacy-kernel stack architecture | implemented, verify-only | Two-slot CT key scratch and 448-byte budget gate exist. No tail-call expansion is planned. |
| P2 exact-candidate CI artifacts | pending | One clean candidate SHA produces `aria-agent`, `libebpf_firewall.so`, and `stack-budget.json` in one workflow run, with recorded hashes. |
| P3 4.18 isolated canary | pending revalidation | P2 artifacts pass both TC directions on the exact maintained kernel and leave no fixture residue. |
| P4 single-node release candidate | pending | One compute passes readiness, peercred, managed ACL, recovery, detach/purge, and real rollback without restarting OVS or OVS-agent. |
| P5 three-node final acceptance | blocked on unavailable compute | Current-hash evidence covers rolling deployment, traffic, lifecycle, RPC regression, cleanup, and rollback on all target computes. |
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
