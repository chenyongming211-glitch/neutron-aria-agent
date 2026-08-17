# Task 11 — CI, smoke, packaging, and documentation closure report

## Status

**DONE_WITH_CONCERNS.** The Task 11 implementation head is
`87965bd170118ea879d3c47bacb241c38e7a2db3`; its exact-head hosted Build
workflow-dispatch `31959923011` and push `31959913784` are green. Retrieve
authenticated URLs with `gh run view <run-id> --json url --jq .url`. OpenStack
and EL 4.18 field validation was not available and remains
strictly `deferred/pending`; this report makes no field PASS claim.

**Superseded review boundary (2026-08-17):** the exact-head delivery evidence
below remains valid, but the statement that no Critical, Important, or Minor
findings remained is no longer the current source-review verdict. The later
audit is recorded under `REVIEW-ACL-116..123` and `REVIEW-TXN-039` in
`docs/openstack-neutron-aria-details/12-review-bug-backlog.md`. It also records
the standalone family gap as fixed and keeps product decisions, defensive debt,
and field evidence separate from open implementation defects.

## Commits

- `8f70ab8` — RED CI-discovery and smoke contracts.
- `6ba38c1` — initial Task 11 CI/smoke/docs green implementation.
- `f419b34` — smoke-evidence and datapath-checker hardening.
- `47d32a1` — hosted RED for standalone `ethertype=any` expansion.
- `421aa02101727118e83448717b9d3d0bc9f17ebe` — public standalone IPv4/IPv6/any
  family contract, atomic expansion/deletion, explicit output, and CLI option.
- `802c95403efc0f425c3fd3cbfd63c0a700238062` — review RED contracts.
- `4532e696866d80acef9570fa4d0a8b2c2f87ca31` — first review GREEN.
- `45dd1ab27faa12d9d29eb9e505ae71d25eab6c1e` — standalone field-record RED.
- `2dcd36a5bb526bef191ff8858fdb4b0028033bce` — field-record and ICMP GREEN.
- `2a48685820e4678237377109d1325ee11ea93106` — obsolete path removal GREEN.
- `cf31ea9c38c5d309d95127f786de994c24d9c7c7` — fragment/config RED.
- `a0101d3422085cd6439d051d0c10ced2536bcae3` — reviewed family/fragment/config GREEN.
- `7ea075f9ee3f1802703f9427c9fee820fcbf6798` — managed dual-stack transition RED.
- `87965bd170118ea879d3c47bacb241c38e7a2db3` — final reviewer-approved GREEN.

## RED evidence

The RED commit was pushed and then dispatched with:

```bash
gh workflow run build.yml --ref main
```

Exact RED run `31955989649`, Rust behavior job `95186629748` (retrieve the
run URL with `gh run view 31955989649 --json url --jq .url`), failed as expected
with two `E0559` errors: `StandaloneAclMutation::UpsertPolicy`
and `DeletePolicy` did not contain `ip_families`. The run's fast contracts,
Rust build, DB contracts, and clean install jobs were green. This isolated the
missing behavior before the GREEN implementation.

Review RED `802c954` used workflow-dispatch `31957581408`: trusted-gate fast
job `95190458851` rejected the fragment early-return, and Rust behavior job
`95190484772` failed only because `standalone_policy_family_protocols` was
missing. The focused local RED for `45dd1ab` failed as expected because the
standalone API expansion function wrote two conflicting `dual-stack` field
rows. The focused local RED for `cf31ea9` failed as expected because fragment
IPv6 policy JSON lacked `ethertype` and `counters_report_enabled` was absent
from `[agent]` when parsed with `ConfigParser`.
The focused local RED for `7ea075f` failed as expected because the managed
dual-stack transition did not clear owned prior rules or assign unique family
priorities before resync.

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

Final reviewed local static results (no local Cargo) were:

```text
python3 -m unittest ci.test_ci001_trusted_gates.TrustedGateContractTests.test_standalone_fragment_fixture_and_recovery_are_family_qualified ci.test_ci001_trusted_gates.TrustedGateContractTests.test_packaged_counter_default_is_parsed_from_agent_section PASS (2 tests)
bash -n deploy/smoke/aria_standalone_acl_tc_datapath_smoke.sh        PASS
python3 ci/check_tc_acl_datapath.py --self-test                      PASS (16 rejection, 4 acceptance)
python3 ci/check_standalone_tc_acl_smoke.py --self-test              PASS
git diff --check                                                     PASS
```

The final managed-transition GREEN for `87965bd` also completed, without local
Cargo:

```text
python3 -m unittest ci.test_ci001_trusted_gates.TrustedGateContractTests.test_managed_dual_stack_field_rules_clear_transitions_and_use_unique_priorities PASS (1 test)
bash -n deploy/kolla/smoke/neutron_aria_acl_tc_datapath_smoke.sh    PASS
python3 ci/check_tc_acl_datapath.py --self-test                      PASS (16 rejection, 4 acceptance)
python3 ci/check_standalone_tc_acl_smoke.py --self-test              PASS
git diff --check                                                     PASS
```

## Exact-head hosted CI

`87965bd170118ea879d3c47bacb241c38e7a2db3` was verified by exact-head
workflow-dispatch run `31959923011` (retrieve its authenticated URL with
`gh run view 31959923011 --json url --jq .url`):

- fast-contracts job `95196234789`: success.
- neutron-agent-clean-install job `95196234756`: success.
- neutron-db-contracts job `95196234714`: success.
- rust-behavior job `95196262681`: success.
- rust-build job `95196262688`: success with `RUSTFLAGS=-D warnings`; its log shows the eBPF/userspace builds, stack-budget report, Kolla Stage 2 bundle, release archive, manifest, and checksums.

The separate `release` job was skipped because artifact publishing was disabled
for this non-tag dispatch; packaging itself ran in `rust-build`. The same SHA's
push-triggered run `31959913784` is also green (fast `95196210532`, install
`95196210565`, DB `95196210506`, Rust behavior `95196233036`, Rust build
`95196232995`), but the dispatch run above is
the designated exact-head evidence.

## Requirement mapping and self-audit

| Brief requirement | Delivered evidence |
| --- | --- |
| Fixed CI discovery | Non-zero `acl_family_`, `acl_ipv6_`, `neutron_acl_ipv6_`, `acl_runtime_schema_`, `standalone_acl_any_`, plus high-value Python behavior IDs are enforced by `check_neutron_stage1.py` and trusted-gate tests. |
| Static smoke structure | Both entrypoints expose the eight required case names and the required evidence schema; their checker does not claim traffic PASS. |
| Managed dual-stack smoke | The managed smoke deletes its owned transition rules exactly once before the field matrix, then makes separate IPv4/IPv6 ingress/egress rules with per-direction v4=90/v6=91 priorities, full-resyncs, tests both directions when prerequisites exist, fails on zero managed ports, and records command/verdict/interface/ifindex/kernel/version/status/counter evidence. |
| Standalone `any` | The smoke itself uses the product REST API, filters only its exact created entries, verifies one IPv4 plus one IPv6, explicitly deletes each family, and leaves the eight traffic cases deferred; Add/Delete/Batch accept omitted IPv4, IPv4, IPv6, and `any`; List/WithStats explicitly emit `ethertype`; CLI exposes optional `--ethertype`. |
| Atomicity and identity | Family-aware protocol expansion maps ICMP correctly (v4=1, v6=58), rejects conflicting family/protocol pairs, and prevalidates all `any` keys. A rejected delete preserves the serialized durable preimage; shared port bitmap refcount is tested 2→1→release. |
| Checker/smoke review closure | The fragment-aware datapath wrapper runs its three added mutations plus the preserved 13 legacy mutations. Fragment fixture POST and recovery assertions use explicit IPv4/IPv6 ethertype five-tuples. Managed PASS requires family-qualified ingress and egress counter deltas. |
| Packaging/docs/defaults | Exact-head rust-build assembles the package; `counters_report_enabled=false` is parsed from `[agent]`; documentation retains schema/rebuild/rollback/default-off contracts and links hosted CI. |

The datapath checker remains a real source-contract gate: its fragment-aware
wrapper and three mutation tests reject an unsafe CT-hit guard, context-install,
and miss-branch mutations. It is not represented as a traffic test. No eBPF hot
path was changed for Task 11.

The Task 11 broad review was **APPROVED** at `87965bd` for the planned delivery
matrix. A later 2026-08-17 audit supersedes its former claim that no findings
remained; see the backlog rows linked in the Status correction above. The final
transition contract still verifies cleanup precedes all four family rules, the
two family priorities are distinct per direction, and full resync follows
creation.

## Field-evidence boundary

All real OpenStack/OVS/VM traffic, target EL 4.18 verifier load/attach, packet
allow/drop, counters, upgrade, and rollback cases remain `deferred/pending`.
Every smoke PASS path requires actual interface, ifindex, agent/datapath
versions, status snapshot, and counter snapshot; placeholder `unknown` or
`pending capture` cannot produce PASS. `ipv6_acl_enabled=false` and counters
default-off remain unchanged. Task 12 alone may convert field rows to PASS.
