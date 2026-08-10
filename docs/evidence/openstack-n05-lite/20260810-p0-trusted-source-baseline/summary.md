# P0 Trusted Source Baseline Evidence

Date: 2026-08-10

Status: source baseline passed; exact candidate artifact and field validation
remain P2-P5 work.

## Provenance

- Branch: `codex/ebpf-legacy-stack-budget`
- P0 input HEAD: `492799dc76c307a730c4d7ee5e077ef372513ed6`
- Historical stash: `stash@{0}` from the pre-pull 2026-07-31 workspace
- Historical verifier RED baseline: ingress/egress worst path `544` bytes
- Current static release budget: `448` bytes
- Target maintained kernel: `4.18.0-553.5.1.el8_10.x86_64`

The P2 candidate commit is deliberately not claimed here. P2 records the exact
post-P0 commit, workflow run, and hashes from one clean GitHub Actions build.

## Contract Decision

The active source uses the shared ACL contract and the runtime wrappers
`unsupported_policy:<detail>` and
`unsupported_rule:<rule-id>:<detail>`. The specialized
`unsupported_default_action` and `unsupported_src_port_match` strings exist
only in the historical stash and are not restored.

## Verification

| Check | Result |
| --- | --- |
| Windows `python ci/check_neutron_stage1.py --fast-contracts` before P0 edits | passed: 584 Python tests with 8 skips, plus 10 legacy CLI tests |
| WSL Ubuntu/Python 3.12 fast contracts after P0 edits | passed: 586 Python tests with 8 skips, plus 10 legacy CLI tests and shell/package source contracts |
| Shared error wrapper regressions | passed as part of the 586-test Linux run |
| `python ci/check_blocked_terms.py` | passed |
| `git diff --check` | passed before P0 edits; final P0 verification reruns it |
| Rust/eBPF local build | not run, by policy |
| Test environment mutation | none |

The P0 Linux run is a source-contract gate, not a Python 2.7 package claim.
The independent `python:2.7.18-slim-buster` clean-container install remains a
P2 exact-candidate GitHub Actions requirement.

## Source Boundary

The RISK-BOUNDARY-001 enforcement-gap work was verified and committed
separately as `492799dc76c307a730c4d7ee5e077ef372513ed6` before P0 documentation
and contract locking began. Local CI downloads and Python packaging outputs are
generated material, not release source. Historical field evidence remains
non-current unless a later gate explicitly binds it to the P2 commit and
artifact hashes.
