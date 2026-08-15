# DEBT-CI-001 Hosted Quality Audit Design

**Status:** approved design; implementation plan pending

**Scope:** non-privileged full host-workspace tests and source-quality checks

## 1. Objective

Add trustworthy broad verification without returning to a long serial push
gate. Existing fast contracts, selected Rust behavior, warning-denied builds,
database contracts, clean install, and deep audit remain unchanged.

The first delivery is an opt-in hosted audit. It records real failures and
duration before any check becomes required on ordinary pushes or releases.

## 2. Workflow Placement and Trigger Boundary

The audit is implemented as two independent jobs inside the existing
`.github/workflows/build.yml`, controlled by a new boolean
`workflow_dispatch` input named `run_quality_audit`, default `false`.

This placement is required by the branch contract. GitHub registers manual and
scheduled workflows from the default branch. `build.yml` already exists on
default branch `main`, so this command can execute the workflow content from
the maintained delivery branch immediately:

```bash
gh workflow run build.yml \
  --ref v0.9-neutron-agent \
  -f run_quality_audit=true
```

A newly created quality workflow that existed only on
`v0.9-neutron-agent` would not be registered and is therefore rejected.

The two jobs use this condition:

```text
github.event_name == 'schedule' ||
(github.event_name == 'workflow_dispatch' && inputs.run_quality_audit == true)
```

On the maintained branch, manual dispatch is the immediately valid trigger.
The schedule arm becomes effective only after the same workflow definition is
present on the default branch; until then, no nightly execution is claimed.
Neither job is added to release `needs`, and both remain skipped on ordinary
push and pull-request events.

## 3. Parallel Job Boundaries

### 3.1 `quality-rust`

This job uses the same immutable checkout and Rust action identities required
by `RISK-CI-001`, then runs three independent commands:

```bash
cargo +stable test --workspace --exclude ebpf-firewall --all-targets --locked
cargo +stable clippy --workspace --exclude ebpf-firewall --all-targets --locked -- -D warnings
cargo +stable fmt --all -- --check
```

`ebpf-firewall` is excluded only from host test and host clippy because it is a
`no_std`/`no_main` BPF cdylib, not a host test target. It remains covered by the
existing warning-denied nightly BPF build and 448-byte linked stack gate.
`cargo fmt --all` still covers its Rust sources.

The job does not rerun release packaging, clean-container installation, Python
tests, or the selected behavior filters.

### 3.2 `quality-scripts`

This job has no Cargo command. It installs exact `ruff==0.16.0`, installs the
Ubuntu 22.04 `shellcheck` package, prints both tool versions, and runs:

```bash
ruff check --select E9,F63,F7,F82 ci openstack
git ls-files -z '*.sh' | xargs -0 --no-run-if-empty shellcheck
```

The Ruff rules are a correctness baseline, not a repository-wide style
rewrite. They cover syntax errors, invalid constructs and undefined-name class
faults while preserving the Python 2.7-compatible OpenStack formatting
contract. Shellcheck covers every tracked shell script rather than a manually
maintained path list. Any required suppression must be local, narrow and
explain the intentional shell behavior.

The two jobs have no dependency on one another, so wall time is their maximum,
not their sum.

## 4. Failure and Reporting Semantics

An invoked audit is strict: any command failure fails its job. The workflow
must not use `continue-on-error`, `|| true`, ignored exit codes, or a success
summary after a failed command.

An audit that was not requested is `skipped`, never `passed`. Historical audit
results are evidence for their exact head only and do not become field or
runtime readiness evidence.

The implementation records each exact-head run, per-job duration, failing
command, and baseline issue count in the backlog. Existing findings uncovered
by the first run are fixed in separate, reviewable commits; the workflow is not
weakened to obtain green status.

## 5. Contract Tests

Cargo-free workflow tests must verify:

- `run_quality_audit` exists and defaults to `false`;
- both jobs have the exact manual/schedule condition;
- neither job runs on ordinary push or pull request;
- neither job is a release dependency;
- `quality-scripts` contains no Cargo command;
- Rust host tests/clippy exclude only `ebpf-firewall`;
- Rust formatting still uses `--all`;
- Ruff uses the exact version and selected correctness rules;
- Shellcheck consumes all tracked shell scripts; and
- neither job contains an error-suppression mechanism.

Tests describe these public lane boundaries and commands. They must not parse
private Rust/Python helpers or bind to unrelated workflow step ordering.

## 6. Promotion Policy

The audit remains manual until three exact-head runs are green and their
durations are recorded. After that evidence:

- `rustfmt`, Ruff correctness lint and shellcheck may be proposed as short
  required push checks if their measured cost is acceptable;
- full host-workspace tests and clippy remain in the independent audit unless
  measured evidence proves they fit the agreed push budget; and
- scheduled execution is activated only through an explicit default-branch
  governance change.

Promotion is a later decision, not part of `DEBT-CI-001` initial delivery.

## 7. Acceptance and Exclusions

Initial delivery is accepted when the manual exact-head audit is callable on
`v0.9-neutron-agent`, both jobs execute strictly and in parallel, the workflow
contract tests pass, and all first-run findings are either fixed or retained as
precise open findings with failing evidence.

This design does not:

- run privileged or target-kernel tests;
- modify ACL, QoS, Mirror, TCP-RT or datapath behavior;
- add quality jobs to ordinary push, pull request or release dependencies;
- claim a working nightly schedule on the non-default branch;
- introduce a second development branch or worktree; or
- run local Cargo commands.
