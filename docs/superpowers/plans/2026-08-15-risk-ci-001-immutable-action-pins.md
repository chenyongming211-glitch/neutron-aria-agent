# RISK-CI-001 Immutable Action Pins Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make every external GitHub Action execution immutable and prevent mutable action references from re-entering any repository workflow.

**Architecture:** Add one Cargo-free public workflow contract test that classifies `uses:` values and accepts only repository-local actions or external actions pinned to a lowercase 40-character commit SHA. Capture RED against the eight current mutable references, then replace only those references with reviewed upstream SHAs while preserving all toolchain, artifact, trigger, permission, and release behavior.

**Tech Stack:** GitHub Actions YAML, Python 3 `unittest`, GitHub CLI/API, Markdown.

## Global Constraints

- Work only on local and remote `v0.9-neutron-agent`; do not create a branch, PR, or worktree.
- Before each edit, fetch and fast-forward from `origin`, require a clean worktree, and inspect recent history for every touched file.
- Do not run Cargo locally. Hosted GitHub Actions supplies Rust/eBPF build evidence.
- Do not change workflow permissions, triggers, job conditions, artifact names, paths, retention periods, release dependencies, or publication policy.
- Do not add Dependabot configuration on this non-default delivery branch or claim that automated action refresh is active.
- The validator may inspect public workflow `uses:` references only. It must not parse Rust/Python implementation details or depend on job/step ordering.
- Every logical RED, GREEN, and documentation closure change is committed and pushed immediately.

## Reviewed Upstream Identities

Use exactly these reviewed identities:

```text
dtolnay/rust-toolchain stable
4360b52568e2003a75bf9bc1d59f33a8e3fc893c

dtolnay/rust-toolchain master
6c977a6ca4077a0ceb28ffbe03f59d46e9ac8772

actions/upload-artifact v4.6.2
ea165f8d65b6e75b540449e92b4886f43607fa02
```

The stable and master commits were resolved independently on 2026-08-15. The
upload commit is the target of both upstream `v4` and `v4.6.2` at resolution
time.

---

### Task 1: Establish the RED immutable-reference contract

**Files:**
- Create: `ci/test_workflow_action_pins.py`
- Modify: `.github/workflows/build.yml:fast-contracts`

**Interfaces:**
- Consumes: tracked `.github/workflows/*.yml` files.
- Produces: `external_action_pin_errors(source, source_name)` and a mutation-tested repository contract.

- [ ] **Step 1: Add the public validator and mutation tests**

Create `ci/test_workflow_action_pins.py` with this behavior:

```python
#!/usr/bin/env python3
"""Require immutable identities for every external GitHub Action execution."""

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW_DIR = ROOT / ".github" / "workflows"
USES_LINE = re.compile(r"^\s*(?:-\s*)?uses:\s*(?P<value>.+?)\s*$")
FULL_SHA = re.compile(r"^[0-9a-f]{40}$")


def external_action_pin_errors(source, source_name="<memory>"):
    errors = []
    for line_number, line in enumerate(source.splitlines(), start=1):
        match = USES_LINE.match(line)
        if match is None:
            continue

        value = match.group("value").split(" #", 1)[0].strip().strip("'\"")
        if value.startswith("./"):
            continue
        if value.startswith("docker://"):
            errors.append(
                "{}:{}: unsupported external action identity {!r}; "
                "add digest-aware validation before using docker actions".format(
                    source_name, line_number, value
                )
            )
            continue

        action, separator, revision = value.rpartition("@")
        if not separator or not action or FULL_SHA.fullmatch(revision) is None:
            errors.append(
                "{}:{}: external action {!r} must use a full lowercase "
                "40-character commit SHA".format(source_name, line_number, value)
            )
    return errors


class WorkflowActionPinTests(unittest.TestCase):
    def test_accepts_local_action_and_full_lowercase_sha(self):
        source = "\n".join(
            [
                "      - uses: ./ci/local-action",
                "      - uses: actions/example@{} # v1.2.3".format("a" * 40),
            ]
        )
        self.assertEqual(external_action_pin_errors(source), [])

    def test_rejects_every_mutable_or_unsupported_identity_shape(self):
        invalid = [
            "actions/example@v4",
            "dtolnay/rust-toolchain@stable",
            "dtolnay/rust-toolchain@master",
            "actions/example@1234abcd",
            "actions/example@{}".format("A" * 40),
            "actions/example",
            "docker://example/action:latest",
        ]
        for value in invalid:
            with self.subTest(value=value):
                self.assertEqual(
                    len(external_action_pin_errors("      - uses: {}".format(value))),
                    1,
                )

    def test_repository_workflows_use_only_immutable_external_actions(self):
        errors = []
        for workflow in sorted(WORKFLOW_DIR.glob("*.yml")):
            errors.extend(
                external_action_pin_errors(
                    workflow.read_text(encoding="utf-8"),
                    str(workflow.relative_to(ROOT)),
                )
            )
        self.assertEqual(errors, [], "\n" + "\n".join(errors))


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Wire the contract into the existing Cargo-free fast lane**

In the `fast-contracts` workflow command list, immediately after
`ci.test_ci_lane_contract`, add:

```yaml
python3 -m unittest ci.test_workflow_action_pins
```

- [ ] **Step 3: Run local non-Cargo RED verification**

Run:

```bash
git diff --check
python3 -m unittest ci.test_workflow_action_pins -v
```

Expected: the mutation tests pass and the repository assertion fails with
exactly eight actionable errors: two `@stable`, one `@master`, and five `@v4`.

- [ ] **Step 4: Commit and push RED**

```bash
git add ci/test_workflow_action_pins.py .github/workflows/build.yml
git commit -m "test(ci): reject mutable workflow action refs"
git push origin v0.9-neutron-agent
```

- [ ] **Step 5: Capture hosted RED**

Use `gh run list` and `gh run view` to verify the exact-head `fast-contracts`
job fails only on the eight immutable-reference violations. Record the commit,
run URL, failed job, and count before changing the references. Cancel remaining
expensive jobs only after the intended RED evidence is visible.

---

### Task 2: Replace the eight mutable executions without semantic drift

**Files:**
- Modify: `.github/workflows/build.yml:rust-behavior`
- Modify: `.github/workflows/build.yml:rust-build`

**Interfaces:**
- Consumes: the reviewed upstream identities above.
- Produces: immutable stable/nightly toolchain installation and immutable v4.6.2 artifact upload.

- [ ] **Step 1: Pin stable Rust in `rust-behavior` and make selection explicit**

Replace the mutable use with:

```yaml
- name: Install Rust stable
  uses: dtolnay/rust-toolchain@4360b52568e2003a75bf9bc1d59f33a8e3fc893c # stable 2026-08-05
  with:
    toolchain: stable
```

- [ ] **Step 2: Pin both Rust installations in `rust-build`**

Keep nightly inputs unchanged and replace only the identity:

```yaml
- name: Install Rust nightly (eBPF)
  uses: dtolnay/rust-toolchain@6c977a6ca4077a0ceb28ffbe03f59d46e9ac8772 # master 2026-08-05
  with:
    toolchain: nightly-2026-07-14
    components: rust-src
```

Make stable explicit while retaining the musl target:

```yaml
- name: Install Rust stable (userspace)
  uses: dtolnay/rust-toolchain@4360b52568e2003a75bf9bc1d59f33a8e3fc893c # stable 2026-08-05
  with:
    toolchain: stable
    targets: x86_64-unknown-linux-musl
```

- [ ] **Step 3: Pin all five artifact upload steps**

Replace each `actions/upload-artifact@v4` with:

```yaml
uses: actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02 # v4.6.2
```

Do not change any adjacent `if`, `name`, `path`, or `retention-days` value.

- [ ] **Step 4: Run local non-Cargo GREEN verification**

Run:

```bash
git diff --check
python3 -m unittest ci.test_workflow_action_pins -v
python3 -m unittest ci.test_ci_lane_contract -v
python3 ci/check_build_workflow_contract.py
```

Expected: all commands pass; the generic workflow scan reports no mutable
external reference.

- [ ] **Step 5: Audit the semantic diff**

Run:

```bash
git diff --word-diff=plain -- .github/workflows/build.yml
git grep -nE 'uses: [^./][^ ]*@(v[0-9]|stable|master)([[:space:]]|$)' -- .github/workflows || true
```

Expected: the first diff contains only three Rust identity changes, two
explicit `toolchain: stable` inputs, and five upload identity changes. The
second command prints nothing.

- [ ] **Step 6: Commit and push GREEN**

```bash
git add .github/workflows/build.yml
git commit -m "fix(ci): pin every external workflow action"
git push origin v0.9-neutron-agent
```

- [ ] **Step 7: Capture exact-head hosted GREEN**

Wait for the Build attached to the GREEN commit. Require successful
`fast-contracts`, selected Rust behavior, warning-denied userspace/agent/eBPF
builds, and the 448-byte stack gate. Confirm skipped artifact steps still have
their original conditions. Do not infer Dependabot or field evidence.

---

### Task 3: Close the immutable-execution risk with exact evidence

**Files:**
- Modify: `docs/superpowers/specs/2026-08-15-risk-ci-001-immutable-action-pins-design.md`
- Modify: `docs/openstack-neutron-aria-details/12-review-bug-backlog.md:RISK-CI-001`
- Modify: `docs/superpowers/plans/2026-08-15-risk-ci-001-immutable-action-pins.md`

- [ ] **Step 1: Record RED and GREEN evidence**

Change the design status to `implemented; hosted CI complete`. Add the exact
RED/GREEN commit IDs and Build URLs. Mark `RISK-CI-001` fixed for immutable
execution and state separately that automatic refresh remains a default-branch
governance follow-up.

- [ ] **Step 2: Mark completed plan checkboxes**

Mark only steps with observed evidence as complete. Leave no checkmark on an
uncaptured CI claim.

- [ ] **Step 3: Commit and push documentation closure**

```bash
git add \
  docs/superpowers/specs/2026-08-15-risk-ci-001-immutable-action-pins-design.md \
  docs/superpowers/plans/2026-08-15-risk-ci-001-immutable-action-pins.md \
  docs/openstack-neutron-aria-details/12-review-bug-backlog.md
git commit -m "docs(ci): close immutable action execution risk"
git push origin v0.9-neutron-agent
```

- [ ] **Step 4: Verify the exact documentation head**

Wait for the documentation-head Build and require all applicable lanes green.
If Rust jobs are skipped because only documentation changed, run:

```bash
gh workflow run build.yml \
  --ref v0.9-neutron-agent \
  -f publish_artifacts=false \
  -f run_deep_audit=false
```

Require that exact dispatched head to pass before final closure.
