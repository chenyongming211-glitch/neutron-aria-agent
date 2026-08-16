# Task 11 — CI, smoke, packaging, and documentation closure report

## Status

**DONE_WITH_CONCERNS.** The Task 11 implementation and the recovered public
standalone family contract are committed on `main`; exact-head hosted Build
[`31956696938`](https://github.com/chenyongming211-glitch/neutron-aria-agent/actions/runs/31956696938)
is green. OpenStack and EL 4.18 field validation was not available and remains
strictly `deferred/pending`; this report makes no field PASS claim.

## Commits

- `8f70ab8` — RED CI-discovery and smoke contracts.
- `6ba38c1` — initial Task 11 CI/smoke/docs green implementation.
- `f419b34` — smoke-evidence and datapath-checker hardening.
- `47d32a1` — hosted RED for standalone `ethertype=any` expansion.
- `421aa02101727118e83448717b9d3d0bc9f17ebe` — public standalone IPv4/IPv6/any
  family contract, atomic expansion/deletion, explicit output, and CLI option.
- This documentation-only closure commit — links the exact-head CI and records
  this report.

## RED evidence

The RED commit was pushed and then dispatched with:

```bash
gh workflow run build.yml --ref main
```

Exact RED run
[`31955989649`](https://github.com/chenyongming211-glitch/neutron-aria-agent/actions/runs/31955989649),
Rust behavior job
[`95186629748`](https://github.com/chenyongming211-glitch/neutron-aria-agent/actions/runs/31955989649/job/95186629748),
failed as expected with two `E0559` errors: `StandaloneAclMutation::UpsertPolicy`
and `DeletePolicy` did not contain `ip_families`. The run's fast contracts,
Rust build, DB contracts, and clean install jobs were green. This isolated the
missing behavior before the GREEN implementation.

## GREEN local checks

No standalone `cargo build`, `cargo check`, or `cargo test` was intentionally
run. The following permitted static checks completed successfully:

```text
python3 ci/check_neutron_stage1.py --fast-contracts                 PASS (723 passed, 19 skipped)
python3 -m unittest ci.test_ci001_trusted_gates                    PASS (10 tests)
python3 -m unittest ci.test_ebpf_stack_budget                       PASS (11 tests)
python3 ci/check_tc_acl_datapath.py                                 PASS
python3 ci/check_standalone_tc_acl_smoke.py                         PASS
bash -n deploy/kolla/smoke/neutron_aria_acl_tc_datapath_smoke.sh    PASS
bash -n deploy/smoke/aria_standalone_acl_tc_datapath_smoke.sh       PASS
git diff --check                                                    PASS
```

Concern: Task 11's brief also lists `python3 -m unittest
ci.test_ci_lane_contract`. When invoked, that wrapper internally executed
`cargo test` (0 and 2 tests passed). That was an accidental breach of the
repository's no-local-Cargo rule; it was stopped immediately, not repeated,
and is not used as Rust verification evidence. Hosted CI is the verification
source for Rust/build/package work.

## Exact-head hosted CI

`421aa02101727118e83448717b9d3d0bc9f17ebe` was verified by the exact-head
workflow-dispatch run
[`31956696938`](https://github.com/chenyongming211-glitch/neutron-aria-agent/actions/runs/31956696938):

- [fast-contracts](https://github.com/chenyongming211-glitch/neutron-aria-agent/actions/runs/31956696938/job/95188308650): success.
- [neutron-agent-clean-install](https://github.com/chenyongming211-glitch/neutron-aria-agent/actions/runs/31956696938/job/95188308654): success.
- [neutron-db-contracts](https://github.com/chenyongming211-glitch/neutron-aria-agent/actions/runs/31956696938/job/95188308672): success.
- [rust-behavior](https://github.com/chenyongming211-glitch/neutron-aria-agent/actions/runs/31956696938/job/95188333131): success.
- [rust-build](https://github.com/chenyongming211-glitch/neutron-aria-agent/actions/runs/31956696938/job/95188333164): success with `RUSTFLAGS=-D warnings`; its log shows the eBPF/userspace builds, stack-budget report, Kolla Stage 2 bundle, release archive, manifest, and checksums.

The separate `release` job was skipped because artifact publishing was disabled
for this non-tag dispatch; packaging itself ran in `rust-build`. The same SHA's
push-triggered run `31956689529` is also green, but the dispatch run above is
the designated exact-head evidence.

## Requirement mapping and self-audit

| Brief requirement | Delivered evidence |
| --- | --- |
| Fixed CI discovery | Non-zero `acl_family_`, `acl_ipv6_`, `neutron_acl_ipv6_`, `acl_runtime_schema_`, `standalone_acl_any_`, plus high-value Python behavior IDs are enforced by `check_neutron_stage1.py` and trusted-gate tests. |
| Static smoke structure | Both entrypoints expose the eight required case names and the required evidence schema; their checker does not claim traffic PASS. |
| Managed dual-stack smoke | The managed smoke makes separate IPv4/IPv6 ingress/egress rules, tests both directions when prerequisites exist, fails on zero managed ports, and records command/verdict/interface/ifindex/kernel/version/status/counter evidence. |
| Standalone `any` | The smoke itself uses the product REST API and GETs two explicit family entries; public Add/Delete/Batch accept omitted IPv4, IPv4, IPv6, and `any`; List/WithStats explicitly emit `ethertype`; CLI exposes optional `--ethertype`. |
| Atomicity and identity | `any` creates/deletes IPv4 and IPv6 keys as one mutation. Delete prevalidates every requested direction/family, and rejected mutations remain in the unpublished clone. Family is in rule identity and stats lookup. |
| Packaging/docs/defaults | Exact-head rust-build assembles the package; documentation retains schema/rebuild/rollback/default-off contracts and links hosted CI. |

The datapath checker remains a real source-contract gate: its fragment-aware
wrapper and three mutation tests reject an unsafe CT-hit guard, context-install,
and miss-branch mutations. It is not represented as a traffic test. No eBPF hot
path was changed for Task 11.

## Field-evidence boundary

All real OpenStack/OVS/VM traffic, target EL 4.18 verifier load/attach, packet
allow/drop, counters, upgrade, and rollback cases remain `deferred/pending`.
Every smoke PASS path requires actual interface, ifindex, agent/datapath
versions, status snapshot, and counter snapshot; placeholder `unknown` or
`pending capture` cannot produce PASS. `ipv6_acl_enabled=false` and counters
default-off remain unchanged. Task 12 alone may convert field rows to PASS.
