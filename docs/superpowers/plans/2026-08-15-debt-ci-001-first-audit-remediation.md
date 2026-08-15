# DEBT-CI-001 First Hosted Audit Remediation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Resolve every finding from the first opt-in hosted quality audit without shrinking its Rust workspace, tracked shell inventory, lint rules, or failure policy.

**Architecture:** Treat the two Rust failures as independent fixture/test-contract defects and preserve production behavior. Treat ShellCheck as a full-inventory baseline: correct actual shell semantics, rewrite ambiguous constructs where small, and use only line-local annotations whose adjacent comment explains an intentional construct. Re-run the unchanged hosted jobs until both are green, then collect the three-run evidence required by `DEBT-CI-001`.

**Evidence baseline:** Exact head `bb56310f0dee88a8669fd57eee61599060b6e29a`, Build [31890013101](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/31890013101). The Rust job ran 487 tests: 485 passed and 2 failed. The scripts job passed Ruff and reported 85 ShellCheck diagnostics at 82 locations in 26 files. After the two Rust tests were corrected, Build [31890412178](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/31890412178) passed all 487 tests and exposed `DEBT-CI-005` in the first strict Clippy step.

## Global constraints

- Work only on `v0.9-neutron-agent`; no new branch, worktree, PR, or workflow.
- Do not run Cargo, Ruff, or ShellCheck locally. Hosted jobs are authoritative.
- Do not change production Rust behavior to accommodate an invalid test fixture.
- Do not add global ShellCheck excludes, reduce the file inventory, lower severity, add `continue-on-error`, or ignore job exit status.
- Prefer semantic shell fixes. A disable is allowed only on the immediately affected line with an adjacent reason.
- Keep unrelated QoS, Mirror, TCP-RT, product, and field-validation work out of this plan.

## Task 1: Close DEBT-CI-002 counter-order test defect

**Files:**
- Modify: `agent/src/neutron_api.rs`

- [ ] Rename the allocation variables so creation order is unambiguous.
- [ ] Assert the first allocation has the smaller id.
- [ ] Keep the production `counters_groups` numeric sort and expected CIDR ordering unchanged.
- [ ] Commit and push the test-only repair.

## Task 2: Close DEBT-CI-003 orphan fixture defect

**Files:**
- Modify: `agent/src/tap_registry.rs`

- [ ] Preserve the disappeared-interface test identity.
- [ ] Seed `PersistedLiveIfaces` directly with the orphan ifname, a historical nonzero ifindex, and an inactive marker.
- [ ] Do not call the live-interface reservation path for the disappeared interface.
- [ ] Keep the assertion that link-only cleanup does not consume the retry marker.
- [ ] Commit and push the test-only repair.

## Task 3: Close DEBT-CI-004 shell correctness baseline

**Files:**
- Modify only the 24 scripts named by Build 31890013101.

- [ ] Correct SC2097/SC2098 environment assignment order so the invoked process receives the intended values and expansions see the intended preimage.
- [ ] Correct SC1010, SC2155, SC2295, SC2196, and SC2029 with explicit syntax, status-preserving assignment, quoted parameter operations, `grep -E`, and deliberate local/remote expansion.
- [ ] Quote SC2086 sites unless intentional argument splitting is part of the command contract; document and annotate only those intentional sites.
- [ ] Replace ambiguous SC2015 chains with explicit `if`/`else` where failure behavior matters; annotate only literal boolean projections proven safe.
- [ ] Preserve literal embedded shell/AWK/Python expressions at SC2016 sites with line-local explanations rather than changing their runtime expansion layer.
- [ ] Rename intentionally unused retry counters/loop variables or annotate the narrow line; remove genuinely dead assignments.
- [ ] Run `bash -n` over every modified shell script and the existing Cargo-free CI contract tests locally.
- [ ] Commit and push the shell remediation.

## Task 4: Obtain hosted GREEN and close the four findings

Before the GREEN run, close `DEBT-CI-005` without a lint suppression:

- [ ] Add a public, copyable `FragmentResolveInput` in `abi/src/fragment.rs` containing `tap_id`, `is_ipv6`, `active_bank`, `now_ns`, and `fragment_offset`.
- [ ] Change `fragment_resolve_decision` to accept that input plus the existing config, epoch, and context references.
- [ ] Update all eBPF and ABI-test callers without changing decision values, ABI map layouts, or datapath ordering.
- [ ] Commit and push the API-structure remediation.

- [ ] Dispatch `run_quality_audit=true` on the exact remediation head.
- [ ] If new diagnostics appear, preserve the command/rules and repair them under this plan.
- [ ] Require the full host-workspace test, clippy, rustfmt, Ruff, and ShellCheck steps all green.
- [ ] Update `DEBT-CI-002` through `DEBT-CI-005` to fixed with exact commit/run evidence.
- [ ] Do not close `DEBT-CI-001` until two more runs of the same unchanged head also pass.

## Task 5: Complete DEBT-CI-001 reproducibility evidence

- [ ] Dispatch the same unchanged green head two additional times.
- [ ] Record all three run URLs, both job durations, and overlapping execution evidence.
- [ ] Update the design status, parent implementation plan, and backlog without promoting the jobs into ordinary push/release gates.
- [ ] Commit, push, require final documentation-head Build green, divergence `0 0`, and a clean worktree.
