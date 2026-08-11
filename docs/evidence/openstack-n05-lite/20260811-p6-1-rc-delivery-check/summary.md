# P6-1 RC Delivery Check

Date: 2026-08-11

## Scope

This evidence closes the P6-1 delivery-entrypoint check on the two currently
available computes. It is read-only runtime verification, not a new datapath
deployment and not formal release promotion.

## Source And CI

| Item | Value |
| --- | --- |
| P6-1 source commit | `9848779a607a0810f93fa7d0ffe26e9341d0b903` |
| GitHub Actions run | `31492061846` |
| CI result | pass |
| Product version | `0.9.0-rc.1` |

The successful workflow covered fast contracts, the Python 2 clean-install
lane, Neutron DB contracts, Rust behavior tests, Rust/eBPF builds, and the
legacy-kernel eBPF stack-budget gate. Deep audit is intentionally tag,
scheduled, or manually triggered and was not run by this branch push.

## Runtime Identity

| Item | Value |
| --- | --- |
| Runtime source candidate | `7ffc5d65d9b30d0a1f9e706ec779cc8213200458` |
| Local RC image | `aria-datapath:rc-7ffc5d6` |
| Image ID | `sha256:91377e742a2b455729bab83f50c3c21292e4b72f060210461781f00336e5f319` |
| `aria-agent` SHA-256 | `687af9d6a319eb1858004e5cff8bfe061e3693217c401e0a9b033a92e86d3079` |
| eBPF object SHA-256 | `6488da9614a7ce81d0d2ae6271ffd0108d084a2115c2d37da02f6dcda13ab50f` |
| eBPF perf object SHA-256 | `6488da9614a7ce81d0d2ae6271ffd0108d084a2115c2d37da02f6dcda13ab50f` |

## Results

| Check | Compute A | Compute B |
| --- | --- | --- |
| Active image identity | pass | pass |
| Runtime binary hashes | pass | pass |
| HTTP health | pass | pass |
| Authenticated UDS readiness | pass | pass |
| OVS identity unchanged during check | pass | pass |
| Neutron OVS-agent identity unchanged during check | pass | pass |

The command returned `Candidate check passed` on both available computes. It
did not replace or restart a container, change configuration, or touch OVS.

## Remaining Boundary

One compute remains unavailable, so P5 is still partial and formal P6 remains
blocked. No release tag or registry promotion was performed. The same current
candidate and P6 delivery gate must be rerun there after recovery.
