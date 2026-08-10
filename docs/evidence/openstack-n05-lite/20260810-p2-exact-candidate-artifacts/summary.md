# P2 Exact-Candidate Artifact Evidence

Date: 2026-08-10

Status: passed. This evidence locks one candidate source commit to one complete
GitHub Actions run and its uploaded artifacts. It does not claim target-kernel
load acceptance; that is P3.

## Candidate Identity

- Commit: `1051b677063ebe337e977c52a253b907027e6fad`
- Branch at dispatch: `codex/ebpf-legacy-stack-budget`
- Workflow: `Build`
- Event: `workflow_dispatch`
- Run: `31373688900`
- Run URL:
  `https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/31373688900`
- Started: `2026-08-10T09:14:49Z`
- Completed: `2026-08-10T09:20:45Z`
- Conclusion: `success`

The run metadata reported the exact candidate commit above. Artifacts were
downloaded from that run only; no local Rust or eBPF compilation was performed.

## Required Jobs

| Job | Result |
| --- | --- |
| `fast-contracts` | passed |
| `neutron-agent-clean-install` | passed using the maintained Python 2.7 clean-container lane |
| `neutron-db-contracts` | passed |
| `rust-behavior` | passed with warnings denied |
| `rust-build` | passed for eBPF, static `ariactl`, and static `aria-agent` |

`deep-audit` was deliberately disabled for this exact-candidate artifact run.
The tag-only release job and optional image-tar jobs were not release
requirements and were skipped.

## Uploaded Artifacts

| Artifact | Size | SHA-256 |
| --- | ---: | --- |
| `firewall-binaries-x86_64.zip` | 9,381,075 | `d57e2a188f1b035331cb25ba45a42529b6d003e20df91bd00dbf4d41baec3c2b` |
| `release/aria-agent` | 23,264,600 | `ba9cdb3f5b01390533c1f7868027b1a8dd994df930e584598e9145e067202c15` |
| `release/ariactl` | 4,524,680 | `a71c7887bfe20afcf8586b912b74e06eba2cb3b6a8c689dee9641675292cf6c0` |
| `release/libebpf_firewall.so` | 241,896 | `140ec66ae9d8f40db2804b3f17538a1ee967e54b9ce70839faf0aa116d2ea1cd` |
| `release/libebpf_firewall_perf.so` | 241,896 | `140ec66ae9d8f40db2804b3f17538a1ee967e54b9ce70839faf0aa116d2ea1cd` |
| `release/stack-budget.json` | 1,665 | `98cdc4de5199cee498c752b49f7a5fad5c2756e86a62e75755772e92c98e0503` |
| `neutron-aria-stage2-acl-kolla-bundle.tgz` | 511,368 | `33f4eea2ce53b400ffaaaeb850dec4070fdd043120face934b067e51420d0766` |

The separately uploaded eBPF diagnostics object has the same eBPF and stack
report hashes as the release directory. This proves the diagnostics and
deployable binary payload came from the same run output.

## Stack Budget

| TC entry | Worst analyzed path | Gate |
| --- | ---: | ---: |
| `tc_ingress` | 448 bytes | 448 bytes maximum |
| `tc_egress` | 448 bytes | 448 bytes maximum |

Both entries retain the required 64-byte margin below the 512-byte kernel
limit. The exact maintained 4.18 verifier remains authoritative and is the P3
gate.

## Bundle Boundary

The Kolla bundle contains the Python 2.7 egg, migration/install/rollback tools,
the legacy CLI installer, UDS peercred profile tooling, stage-two smoke, and the
read-only ACL enforcement-gap check. Payload policy validation passed in CI.

The manifest still derives a development `release_version` from the branch
name. No optional image tar was built, and this development value is not a
final image tag. P6 must replace it with the frozen product version/tag policy
before a formal image release; it does not block P3 binary canary execution.

## P2 Exit Decision

P2 is complete for the immutable candidate commit and hashes above. P3 must use
the exact `aria-agent` and `libebpf_firewall.so` hashes from this record. Any
Rust/eBPF source change creates a new candidate and requires a new P2 run.
