# DEBT-CI-001 Hosted Quality Audit Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add strict, parallel, opt-in hosted quality audits for the full host Rust workspace and tracked Python/shell sources without lengthening ordinary push, pull-request, or release gates.

**Architecture:** Extend the already registered Build workflow with one default-off dispatch input and two independent conditional jobs. Cargo-free contract tests define the trigger, exclusion, strictness, and command boundaries. The first manual exact-head run becomes measured discovery evidence; unknown findings are never hidden or repaired by weakening the audit.

**Tech Stack:** GitHub Actions YAML, Rust/Cargo, Ruff 0.16.0, ShellCheck, Python 3 `unittest`, GitHub CLI, Markdown.

## Global Constraints

- Begin only after `RISK-CI-001` is GREEN and all external action references are immutable.
- Work only on local and remote `v0.9-neutron-agent`; do not create a branch, PR, worktree, or second workflow file.
- Do not run Cargo, Ruff, or ShellCheck locally. The hosted audit is the source of broad quality evidence.
- Ordinary push and pull-request events must skip both quality jobs. Release must not depend on them.
- `quality-rust` and `quality-scripts` must be independent jobs with no dependency on each other.
- Do not use `continue-on-error`, `|| true`, ignored exit codes, or success summaries after failed commands.
- Do not expand Ruff into a formatting/style rewrite. Use only `E9,F63,F7,F82` in the initial audit.
- Do not run host test/clippy against the `ebpf-firewall` cdylib. Existing warning-denied BPF build and stack-budget lanes remain authoritative for eBPF.
- Do not describe a skipped job as passed or claim scheduled execution while the updated workflow is absent from the default branch.
- Every logical RED, workflow GREEN, discovery, remediation, and closure change is committed and pushed immediately.

## Trigger Contract

Both quality jobs use exactly this condition:

```yaml
if: github.event_name == 'schedule' || (github.event_name == 'workflow_dispatch' && inputs.run_quality_audit == true)
```

The immediately supported invocation is:

```bash
gh workflow run build.yml \
  --ref v0.9-neutron-agent \
  -f publish_artifacts=false \
  -f run_deep_audit=false \
  -f run_quality_audit=true
```

---

### Task 1: Establish the RED quality-lane contract

**Files:**
- Modify: `ci/test_ci_lane_contract.py`

**Interfaces:**
- Consumes: public workflow input/job/command definitions.
- Produces: contract tests for `run_quality_audit`, `quality-rust`, and `quality-scripts`.

- [x] **Step 1: Add exact command constants**

Add these constants below the existing action identities:

```python
QUALITY_CONDITION = (
    "github.event_name == 'schedule' || "
    "(github.event_name == 'workflow_dispatch' && "
    "inputs.run_quality_audit == true)"
)
RUST_WORKSPACE_TEST = (
    "cargo +stable test --workspace --exclude ebpf-firewall "
    "--all-targets --locked"
)
RUST_WORKSPACE_CLIPPY = (
    "cargo +stable clippy --workspace --exclude ebpf-firewall "
    "--all-targets --locked -- -D warnings"
)
RUST_WORKSPACE_FMT = "cargo +stable fmt --all -- --check"
RUFF_COMMAND = "ruff check --select E9,F63,F7,F82 ci openstack"
SHELLCHECK_COMMAND = (
    "git ls-files -z '*.sh' | "
    "xargs -0 --no-run-if-empty shellcheck"
)
```

- [x] **Step 2: Add opt-in and parallelism tests**

Add tests that require the input and both independent jobs:

```python
def test_quality_audit_input_is_explicitly_opt_in(self):
    self.assertRegex(
        self.source,
        r"(?ms)^      run_quality_audit:\n"
        r"        description: .+\n"
        r"        required: false\n"
        r"        default: false\n"
        r"        type: boolean$",
    )

def test_quality_jobs_are_independent_and_share_the_exact_trigger(self):
    for name in ["quality-rust", "quality-scripts"]:
        block = job_block(self.source, name)
        self.assertIn("if: " + QUALITY_CONDITION, block)
        self.assertNotRegex(block, r"(?m)^    needs:")

    release = job_block(self.source, "release")
    self.assertNotIn("quality-rust", release)
    self.assertNotIn("quality-scripts", release)
```

- [x] **Step 3: Add command and strictness tests**

Add:

```python
def test_quality_rust_has_the_broad_host_commands(self):
    block = job_block(self.source, "quality-rust")
    for command in [RUST_WORKSPACE_TEST, RUST_WORKSPACE_CLIPPY, RUST_WORKSPACE_FMT]:
        self.assertIn(command, block)
    self.assertNotIn("--exclude aria-", block)
    self.assertNotIn("continue-on-error", block)
    self.assertNotIn("|| true", block)

def test_quality_scripts_is_cargo_free_and_uses_pinned_correctness_tools(self):
    block = job_block(self.source, "quality-scripts")
    self.assertIn("ruff==0.16.0", block)
    self.assertIn("ruff --version", block)
    self.assertIn("shellcheck --version", block)
    self.assertIn(RUFF_COMMAND, block)
    self.assertIn(SHELLCHECK_COMMAND, block)
    self.assertNotRegex(block, r"\bcargo\b")
    self.assertNotIn("continue-on-error", block)
    self.assertNotIn("|| true", block)
```

- [x] **Step 4: Run local Cargo-free RED verification**

Run:

```bash
git diff --check
python3 -m unittest ci.test_ci_lane_contract -v
```

Expected: existing tests pass and the new tests fail because the input and both
jobs do not exist.

- [x] **Step 5: Commit and push RED**

```bash
git add ci/test_ci_lane_contract.py
git commit -m "test(ci): require opt-in quality audit lanes"
git push origin v0.9-neutron-agent
```

- [x] **Step 6: Capture hosted RED**

Require exact-head `fast-contracts` to fail on the missing public workflow
contract. Record its commit, run URL, and failing test names; do not expect or
claim quality-job execution yet.

---

### Task 2: Add strict parallel quality jobs to the registered Build workflow

**Files:**
- Modify: `.github/workflows/build.yml:on.workflow_dispatch.inputs`
- Modify: `.github/workflows/build.yml:jobs`
- Modify: `ci/test_ci_lane_contract.py:test_javascript_actions_use_pinned_node24_releases`

**Interfaces:**
- Consumes: immutable action SHAs established by `RISK-CI-001`.
- Produces: opt-in `quality-rust` and `quality-scripts` hosted jobs.

- [x] **Step 1: Add the default-off dispatch input**

After `run_deep_audit`, add:

```yaml
run_quality_audit:
  description: Run full host Rust tests and source quality audits.
  required: false
  default: false
  type: boolean
```

- [x] **Step 2: Add `quality-rust` before the release job**

Use the pinned checkout, stable toolchain, and Cargo cache identities already
accepted by the immutable-reference contract:

```yaml
quality-rust:
  if: github.event_name == 'schedule' || (github.event_name == 'workflow_dispatch' && inputs.run_quality_audit == true)
  runs-on: ubuntu-22.04
  steps:
    - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1

    - name: Install Rust stable quality components
      uses: dtolnay/rust-toolchain@4360b52568e2003a75bf9bc1d59f33a8e3fc893c # stable 2026-08-05
      with:
        toolchain: stable
        components: clippy, rustfmt

    - name: Cache cargo
      uses: actions/cache@55cc8345863c7cc4c66a329aec7e433d2d1c52a9 # v6.1.0
      with:
        path: |
          ~/.cargo/registry
          ~/.cargo/git
        key: ${{ runner.os }}-cargo-${{ hashFiles('Cargo.lock', '**/Cargo.toml') }}
        restore-keys: |
          ${{ runner.os }}-cargo-

    - name: Test full host workspace
      run: cargo +stable test --workspace --exclude ebpf-firewall --all-targets --locked

    - name: Lint full host workspace
      run: cargo +stable clippy --workspace --exclude ebpf-firewall --all-targets --locked -- -D warnings

    - name: Check Rust formatting
      run: cargo +stable fmt --all -- --check
```

- [x] **Step 3: Add `quality-scripts` as a separate job**

```yaml
quality-scripts:
  if: github.event_name == 'schedule' || (github.event_name == 'workflow_dispatch' && inputs.run_quality_audit == true)
  runs-on: ubuntu-22.04
  steps:
    - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1

    - name: Install pinned source quality tools
      run: |
        python3 -m pip install --disable-pip-version-check ruff==0.16.0
        sudo apt-get update
        sudo apt-get install -y shellcheck
        ruff --version
        shellcheck --version

    - name: Check Python correctness
      run: ruff check --select E9,F63,F7,F82 ci openstack

    - name: Check tracked shell scripts
      run: git ls-files -z '*.sh' | xargs -0 --no-run-if-empty shellcheck
```

- [x] **Step 4: Update existing immutable JavaScript action counts**

The two new jobs add two checkout executions and `quality-rust` adds one cache
execution. Update only these expected counts:

```python
self.assertEqual(self.source.count(CHECKOUT_NODE24), 9)
self.assertEqual(self.source.count(CACHE_NODE24), 3)
```

- [x] **Step 5: Run local Cargo-free GREEN verification**

Run:

```bash
git diff --check
python3 -m unittest ci.test_ci_lane_contract -v
python3 -m unittest ci.test_workflow_action_pins -v
python3 ci/check_build_workflow_contract.py
```

Expected: all public workflow contracts pass. No local Cargo, Ruff, or
ShellCheck command runs.

- [x] **Step 6: Commit and push the workflow implementation**

```bash
git add .github/workflows/build.yml ci/test_ci_lane_contract.py
git commit -m "ci: add opt-in hosted quality audit lanes"
git push origin v0.9-neutron-agent
```

- [x] **Step 7: Verify ordinary push behavior**

For the implementation commit's automatic Build, require existing applicable
jobs green and confirm both quality jobs are `skipped`. This proves the default
push path did not acquire the audit cost.

---

### Task 3: Execute and classify the first exact-head hosted audit

**Files:**
- Modify: `docs/openstack-neutron-aria-details/12-review-bug-backlog.md:DEBT-CI-001`
- Modify: `docs/superpowers/plans/2026-08-15-debt-ci-001-quality-audit.md`

- [x] **Step 1: Dispatch the exact implementation head**

Run:

```bash
gh workflow run build.yml \
  --ref v0.9-neutron-agent \
  -f publish_artifacts=false \
  -f run_deep_audit=false \
  -f run_quality_audit=true
```

Resolve the new run ID with `gh run list`, verify its head SHA equals the
implementation head, then wait for completion.

- [x] **Step 2: Record job execution and duration**

Require both `quality-rust` and `quality-scripts` to be present and not skipped.
Record each job conclusion and duration. Verify their timestamps overlap; they
must not be serialized through `needs`.

- [x] **Step 3: Classify the first-run result without weakening checks**

If both jobs pass, record zero findings and continue to Task 4. If either job
fails:

1. assign the resolved numeric run identifier to `run_id`, then use
   `gh run view "${run_id}" --log-failed` to collect the exact tool, file,
   line, diagnostic, and count;
2. add each independent root cause as an explicit open backlog finding;
3. retain `DEBT-CI-001` as implementation complete but audit RED;
4. create a finding-specific RED/GREEN plan before editing affected source;
5. do not reduce the workspace, path set, lint rules, warning policy, or shell
   inventory to manufacture GREEN.

This is an intentional decision point based on evidence that does not exist
until hosted tools run. No unknown source remediation is authorized by this
plan.

- [x] **Step 4: Commit the measured baseline**

Record the exact head, run URL, job conclusions, durations, and either zero
findings or the newly registered finding IDs in the backlog and this plan.

```bash
git add \
  docs/superpowers/plans/2026-08-15-debt-ci-001-quality-audit.md \
  docs/openstack-neutron-aria-details/12-review-bug-backlog.md
git commit -m "docs(ci): record first hosted quality audit"
git push origin v0.9-neutron-agent
```

Measured baseline: exact implementation head `bb56310f0dee88a8669fd57eee61599060b6e29a`,
Build [31890013101](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/31890013101).
`quality-scripts` and `quality-rust` started at 14:28:44Z/14:28:45Z and failed
after 26/107 seconds respectively. Ruff passed; the Rust workspace exposed two
dormant test defects and ShellCheck reported 85 diagnostics at 82 locations in
26 scripts. Findings are `DEBT-CI-002` through `DEBT-CI-004`; their exact
remediation is defined in
`docs/superpowers/plans/2026-08-15-debt-ci-001-first-audit-remediation.md`.
After both Rust tests were corrected, exact-head Build
[31890412178](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/31890412178)
passed all 487 workspace tests and exposed `DEBT-CI-005` at the first strict
Clippy step. Commit `0157110` fixed that API-structure finding without a lint
suppression; ordinary exact-head Build
[31890852231](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/31890852231)
then passed the warning-denied Rust/eBPF build and stack-budget gates. The next
hosted Clippy pass in Build
[31890857284](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/31890857284)
reached `aria-core` and exposed `DEBT-CI-006`: 107 historical diagnostics in
17 files, including deliberately deferred QoS, Mirror, TCP-RT, and SSL code.
Several iterator suggestions would retain existing swallowed-error behavior,
so this is not a safe mechanical rewrite. Exact-head Build
[31891297201](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/31891297201)
independently passed the unchanged full Ruff/ShellCheck job in 21 seconds; the
overall run was cancelled after that job completed because Clippy's separate
scope decision remained open. Rustfmt has not yet run because the quality-rust
job stops at Clippy.

The recommended boundary adjustment is explicit rather than silent: existing
Rust/eBPF jobs retain compiler warnings as errors, while the broad Clippy lane
denies `correctness`, `suspicious`, and `perf`. Style and complexity findings
remain visible but non-fatal and stay registered under `DEBT-CI-006`. The
alternative is a separately authorized multi-module refactor of all 107
diagnostics. This plan must not choose between those scopes without approval.

---

### Task 4: Close initial delivery only after reproducible GREEN evidence

**Files:**
- Modify: `docs/superpowers/specs/2026-08-15-debt-ci-001-quality-audit-design.md`
- Modify: `docs/openstack-neutron-aria-details/12-review-bug-backlog.md:DEBT-CI-001`
- Modify: `docs/superpowers/plans/2026-08-15-debt-ci-001-quality-audit.md`

- [ ] **Step 1: Require a green source head**

Do not enter closure while any first-run finding is unresolved. After all
finding-specific plans are GREEN, dispatch the exact resulting source head
with `run_quality_audit=true` and require both quality jobs to pass.

- [ ] **Step 2: Repeat the exact green head twice**

Dispatch the same unchanged commit two additional times. Record all three run
URLs and both job durations for every run. Any flaky failure reopens the
relevant finding and resets the three-run evidence sequence.

- [ ] **Step 3: Close implementation without promoting the lanes**

Change the design status to `implemented; three hosted audit runs green` and
mark `DEBT-CI-001` fixed for initial audit coverage. Explicitly retain:

- both jobs as manual opt-in on ordinary pushes and releases;
- scheduled activation as pending default-branch governance;
- privileged and target-kernel testing as out of scope; and
- promotion of lightweight checks as a later measured decision.

- [ ] **Step 4: Commit and push closure**

```bash
git add \
  docs/superpowers/specs/2026-08-15-debt-ci-001-quality-audit-design.md \
  docs/superpowers/plans/2026-08-15-debt-ci-001-quality-audit.md \
  docs/openstack-neutron-aria-details/12-review-bug-backlog.md
git commit -m "docs(ci): close hosted quality audit delivery"
git push origin v0.9-neutron-agent
```

- [ ] **Step 5: Verify final repository state**

Require the final documentation-head Build green, local and remote branch
divergence `0 0`, and a clean worktree. Do not claim that the audit replaces
field evidence or target-kernel validation.
