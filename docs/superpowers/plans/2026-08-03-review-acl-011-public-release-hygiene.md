# REVIEW-ACL-011 Public Release Hygiene Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Remove agreed personal, workstation, and target-environment identifiers from the current public tree and future release payloads, while preserving evidence semantics and Git history.

**Architecture:** One small Python policy module owns encoded rules, the narrow canonical-GitHub provenance exception, path scanning, binary-string handling, and bounded recursive ZIP/TAR scanning. The repository and generated-payload entry points consume that module; a deterministic migration script rewrites current tracked content and path names using standards-reserved aliases, then a focused fast-contract test prevents regression.

**Tech Stack:** Python 3 standard library (`unittest`, `subprocess`, `zipfile`, `tarfile`, `io`, `pathlib`), Git, GitHub Actions, existing shell/static contracts.

## Global Constraints

- Work only on local and remote `v0.9-neutron-agent`; do not create another branch, worktree, or PR.
- Do not run local `cargo build`, `cargo check`, `cargo test`, or any other local Cargo command.
- Do not rewrite Git history, force-push, rewrite tags, or delete hosted CI evidence.
- Keep canonical HTTPS repository and Actions-run provenance URLs; reject the same owner identity outside a complete allowed URL.
- Do not delete field evidence or generated output; `DEBT-REPO-001` remains separate.
- Preserve pass/fail results, timestamps, counters, UUIDs, generations, policy relationships, prefix relationships, and evidence chronology.
- Store prohibited values and migration source tokens encoded; diagnostics report only path/member and rule number.
- Missing privileged field execution remains `deferred/pending`; ACL-011 itself requires no field PASS.
- Each pushed implementation commit must receive hosted CI evidence before the next semantic phase is declared complete.

---

## File structure and responsibilities

- Create `ci/public_release_policy.py`: encoded rule inventory, provenance masking, path/content scanning, binary-string handling, and bounded recursive archive scanning.
- Create `ci/test_public_release_hygiene.py`: executable behavior contracts for content, paths, provenance, ZIP/TAR nesting, diagnostics, and migration idempotence.
- Create `ci/anonymize_public_tree.py`: deterministic, idempotent one-shot/current-tree migration using encoded source values and explicit public aliases.
- Modify `ci/check_blocked_terms.py`: scan every tracked path and its regular/archive content through the shared policy.
- Modify `ci/check_payload_terms.py`: scan directory-relative names, regular content, archive names/content, and nested archives through the same policy.
- Modify `.github/workflows/build.yml`: execute the focused hygiene tests in `fast-contracts` before the live tracked-tree policy.
- Modify `ci/test_ci_lane_contract.py`: require the new focused test invocation and keep Cargo out of `fast-contracts`.
- Mechanically modify/rename matched tracked content under `AGENTS.md`, `CLAUDE.md`, `README.md`, `aria-firewall.spec`, `.github/**`, `api/**`, `ci/**`, `deploy/**`, `docs/**`, `openstack/**`, and `outputs/**` according to the deterministic mapping.
- Modify `docs/superpowers/specs/2026-08-03-review-acl-011-public-release-hygiene-design.md`: record implementation/CI status only after GREEN.
- Modify `docs/openstack-neutron-aria-details/12-review-bug-backlog.md`: close ACL-011 with exact RED/GREEN commits, CI runs, and the no-history-rewrite boundary.

---

### Task 1: RED public-release policy contracts

**Files:**
- Create: `ci/test_public_release_hygiene.py`
- Modify: `.github/workflows/build.yml`
- Modify: `ci/test_ci_lane_contract.py`

**Interfaces:**
- Consumes: current `ci/check_blocked_terms.py` and `ci/check_payload_terms.py` CLI behavior.
- Produces: required public interfaces `public_release_policy.find_rule_ids(data, allow_provenance=True)`, `public_release_policy.scan_path(label)`, `public_release_policy.scan_payload(label, data, depth=0)`, `check_blocked_terms.collect_blocked(paths)`, and `check_payload_terms.collect_payload_hits(args)`.

- [x] **Step 1: Add the failing unit-test module**

Create `ci/test_public_release_hygiene.py` with fixtures built from hex rather than plain prohibited values:

```python
import io
import os
import subprocess
import tarfile
import tempfile
import unittest
import zipfile
from contextlib import redirect_stderr
from pathlib import Path

from ci import check_blocked_terms
from ci import check_payload_terms
from ci import public_release_policy


NEW_RULE_HEX = (
    "6368656e796f6e676d696e673231312d676c69746368",
    "6368656e796f6e676d696e6732313140676d61696c2e636f6d",
    "6e65746d6f75736572",
    "2f55736572732f6368656e",
    "626a3135392e6e6574",
    "6f737461636b32",
    "6f737461636b33",
    "6f737461636b34",
    "31302e35382e3135392e",
)
REPOSITORY_URL = bytes.fromhex(
    "68747470733a2f2f6769746875622e636f6d2f"
    "6368656e796f6e676d696e673231312d676c697463682f"
    "617269612d6669726577616c6c"
)


class PublicReleasePolicyTest(unittest.TestCase):
    def test_new_identifier_classes_are_blocked_without_plaintext_fixtures(self):
        for encoded in NEW_RULE_HEX:
            with self.subTest(encoded=encoded):
                self.assertTrue(public_release_policy.find_rule_ids(bytes.fromhex(encoded)))

    def test_ascii_rules_are_case_insensitive(self):
        value = bytes.fromhex(NEW_RULE_HEX[4]).upper()
        self.assertTrue(public_release_policy.find_rule_ids(value))

    def test_canonical_repository_and_actions_urls_are_the_only_owner_allowance(self):
        self.assertEqual([], public_release_policy.find_rule_ids(REPOSITORY_URL))
        self.assertEqual(
            [],
            public_release_policy.find_rule_ids(
                REPOSITORY_URL + bytes.fromhex("2f616374696f6e732f72756e732f313233")
            ),
        )
        owner = bytes.fromhex(NEW_RULE_HEX[0])
        self.assertTrue(public_release_policy.find_rule_ids(b"owner=" + owner))
        self.assertTrue(public_release_policy.find_rule_ids(REPOSITORY_URL + b"-copy"))

    def test_path_names_are_scanned(self):
        label = os.fsdecode(bytes.fromhex(NEW_RULE_HEX[5])) + "/summary.md"
        self.assertTrue(public_release_policy.scan_path(label))

    def test_zip_member_name_and_nested_content_are_scanned(self):
        outer = io.BytesIO()
        inner = io.BytesIO()
        with zipfile.ZipFile(inner, "w") as archive:
            archive.writestr("safe.txt", bytes.fromhex(NEW_RULE_HEX[4]))
        with zipfile.ZipFile(outer, "w") as archive:
            archive.writestr("nested.zip", inner.getvalue())
            archive.writestr(os.fsdecode(bytes.fromhex(NEW_RULE_HEX[5])) + "/x", b"safe")
        hits = public_release_policy.scan_payload("fixture.zip", outer.getvalue())
        self.assertGreaterEqual(len(hits), 2)

    def test_tar_member_name_and_content_are_scanned(self):
        payload = bytes.fromhex(NEW_RULE_HEX[8])
        outer = io.BytesIO()
        with tarfile.open(fileobj=outer, mode="w") as archive:
            info = tarfile.TarInfo("safe.txt")
            info.size = len(payload)
            archive.addfile(info, io.BytesIO(payload))
        self.assertTrue(public_release_policy.scan_payload("fixture.tar", outer.getvalue()))

    def test_diagnostics_do_not_echo_decoded_values(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir, "fixture.txt")
            prohibited = bytes.fromhex(NEW_RULE_HEX[1])
            path.write_bytes(prohibited)
            stderr = io.StringIO()
            with redirect_stderr(stderr):
                hits = check_blocked_terms.collect_blocked([str(path)])
                check_blocked_terms.report_blocked(hits)
            self.assertTrue(hits)
            self.assertNotIn(prohibited.decode("ascii"), stderr.getvalue())

    def test_migration_is_idempotent_on_a_temporary_tree(self):
        from ci import anonymize_public_tree

        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source = bytes.fromhex(NEW_RULE_HEX[5]).decode("ascii")
            path = root / (source + "-summary.md")
            path.write_text(source, encoding="utf-8")
            anonymize_public_tree.migrate_paths([path], root=root)
            first = sorted(str(item.relative_to(root)) for item in root.rglob("*"))
            anonymize_public_tree.migrate_paths(list(root.rglob("*")), root=root)
            second = sorted(str(item.relative_to(root)) for item in root.rglob("*"))
            self.assertEqual(first, second)
            self.assertFalse(any(public_release_policy.scan_path(item) for item in second))


if __name__ == "__main__":
    unittest.main()
```

- [x] **Step 2: Wire the new behavior into the required fast lane**

Add this command immediately after `python3 ci/check_blocked_terms.py` in `.github/workflows/build.yml`:

```yaml
          python3 -m unittest ci.test_public_release_hygiene
```

Add an exact required-command assertion to `CiLaneContractTest.test_fast_contracts_keep_python_and_rust_separate` in `ci/test_ci_lane_contract.py`:

```python
self.assertIn(
    "python3 -m unittest ci.test_public_release_hygiene",
    fast_contracts,
)
```

- [x] **Step 3: Run the focused test and verify RED**

Run:

```bash
python3 -m unittest ci.test_public_release_hygiene -v
```

Expected: FAIL during import because `ci.public_release_policy` and `ci.anonymize_public_tree` do not exist.

Run:

```bash
python3 -m unittest ci.test_ci_lane_contract -v
git diff --check
```

Expected: lane contract PASS; diff check PASS.

- [x] **Step 4: Commit and push RED**

```bash
git add ci/test_public_release_hygiene.py ci/test_ci_lane_contract.py .github/workflows/build.yml
git commit -m "test: expose public release identifier leaks"
git push origin v0.9-neutron-agent
```

- [x] **Step 5: Capture hosted RED evidence**

Run:

```bash
red_sha="$(git rev-parse HEAD)"
red_run_id="$(gh run list --commit "$red_sha" --workflow Build --limit 1 \
  --json databaseId --jq '.[0].databaseId')"
test -n "$red_run_id"
gh run view "$red_run_id" --log-failed
```

Expected: `fast-contracts` fails on the missing public policy/migration interfaces; unrelated required lanes either pass or are still running. Record the run URL, then cancel remaining expensive jobs only after the intended RED is visible.

---

### Task 2: GREEN shared policy and deterministic current-tree migration

**Files:**
- Create: `ci/public_release_policy.py`
- Create: `ci/anonymize_public_tree.py`
- Modify: `ci/check_blocked_terms.py`
- Modify: `ci/check_payload_terms.py`
- Modify/rename: every matched tracked file/path selected by `git ls-files`, especially `AGENTS.md`, `CLAUDE.md`, `README.md`, `aria-firewall.spec`, `.github/**`, `api/**`, `ci/**`, `deploy/**`, `docs/**`, `openstack/**`, and `outputs/**`

**Interfaces:**
- Consumes: encoded rule values and current tracked paths.
- Produces:
  - `find_rule_ids(data: bytes, allow_provenance: bool = True) -> list[int]`
  - `scan_path(label: str) -> list[tuple[str, int]]`
  - `scan_payload(label: str, data: bytes, depth: int = 0) -> list[tuple[str, int]]`
  - `collect_blocked(paths: Iterable[str]) -> list[tuple[str, int]]`
  - `report_blocked(hits: Iterable[tuple[str, int]]) -> None`
  - `collect_payload_hits(args: Iterable[str]) -> tuple[int, list[tuple[str, int]]]`
  - `migrate_paths(paths: Iterable[Path], root: Path) -> None`

- [x] **Step 1: Implement the shared encoded policy**

Create `ci/public_release_policy.py`. Keep the existing four hex rules first so their numeric diagnostics remain stable, append the nine new encoded rules from Task 1, and implement these exact behaviors:

```python
#!/usr/bin/env python3
from __future__ import print_function

import io
import os
import re
import tarfile
import zipfile


_BINARY_STRING_MIN_LEN = 6
_MAX_ARCHIVE_DEPTH = 3

RULES = (
    (bytes.fromhex("716178"), True),
    (bytes.fromhex("7169616e78696e"), True),
    (bytes.fromhex("e9bd90e5ae89e4bfa1"), False),
    (bytes.fromhex("63736d70"), True),
    (bytes.fromhex("6368656e796f6e676d696e673231312d676c69746368"), True),
    (bytes.fromhex("6368656e796f6e676d696e6732313140676d61696c2e636f6d"), True),
    (bytes.fromhex("6e65746d6f75736572"), True),
    (bytes.fromhex("2f55736572732f6368656e"), True),
    (bytes.fromhex("626a3135392e6e6574"), True),
    (bytes.fromhex("6f737461636b32"), True),
    (bytes.fromhex("6f737461636b33"), True),
    (bytes.fromhex("6f737461636b34"), True),
    (bytes.fromhex("31302e35382e3135392e"), True),
)

_OWNER = RULES[4][0]
_REPOSITORY = bytes.fromhex("617269612d6669726577616c6c")
_PUBLIC_URL = re.compile(
    rb"https://github[.]com/" + re.escape(_OWNER) + rb"/" + _REPOSITORY
    + rb"(?=$|[/#? )\\]>'\\\"])"
)


def _mask_allowed_provenance(data):
    return _PUBLIC_URL.sub(b"https://github.com/public/aria-firewall", data)


def find_rule_ids(data, allow_provenance=True):
    candidate = _mask_allowed_provenance(data) if allow_provenance else data
    lowered = candidate.lower()
    return [
        index
        for index, (needle, ascii_fold) in enumerate(RULES, 1)
        if needle in (lowered if ascii_fold else candidate)
    ]


def scan_path(label):
    return [(label, item) for item in find_rule_ids(os.fsencode(label), False)]
```

Add the existing ELF/text/binary-string discrimination from `check_payload_terms.py`, then implement recursive ZIP/TAR scanning over `io.BytesIO`. Every archive member runs `scan_path(member_label)` and `scan_payload(member_label, member_data, depth + 1)`. At depth greater than `_MAX_ARCHIVE_DEPTH`, fall back to the normal text/binary-string scan rather than silently accepting content.

- [x] **Step 2: Refactor both entry points onto the shared policy**

In `ci/check_blocked_terms.py`:

```python
from public_release_policy import scan_path, scan_payload


def collect_blocked(paths):
    blocked = []
    for path in paths:
        blocked.extend(scan_path(path))
        with open(path, "rb") as handle:
            blocked.extend(scan_payload(path, handle.read()))
    return blocked


def report_blocked(blocked):
    if not blocked:
        return
    print("Blocked token found in tracked files:", file=sys.stderr)
    for path, rule_index in blocked:
        print("  %s (rule %s)" % (path, rule_index), file=sys.stderr)
```

`main()` calls `collect_blocked(tracked_files())`, reports, and returns one only when hits exist. Delete the duplicate local rule/content scan.

In `ci/check_payload_terms.py`, retain glob/directory enumeration but yield a root-relative display label for each file. Implement:

```python
from public_release_policy import scan_path, scan_payload


def collect_payload_hits(args):
    blocked = []
    checked = 0
    for path, label in _iter_paths(args):
        checked += 1
        blocked.extend(scan_path(label))
        with open(path, "rb") as handle:
            blocked.extend(scan_payload(label, handle.read()))
    return checked, blocked
```

The CLI retains the existing missing-path error and accepted-output text. Delete duplicate archive and binary scanning code.

- [x] **Step 3: Implement the deterministic migration script**

Create `ci/anonymize_public_tree.py` with ordered encoded byte mappings. Apply complete FQDN before short host, and the address prefix as one mapping so every host octet and prefix length is preserved:

```python
REPLACEMENTS = (
    (bytes.fromhex("6f737461636b322e626a3135392e6e6574"), b"compute-1.example.test"),
    (bytes.fromhex("6f737461636b332e626a3135392e6e6574"), b"compute-2.example.test"),
    (bytes.fromhex("6f737461636b342e626a3135392e6e6574"), b"compute-3.example.test"),
    (bytes.fromhex("6f737461636b32"), b"compute-1"),
    (bytes.fromhex("6f737461636b33"), b"compute-2"),
    (bytes.fromhex("6f737461636b34"), b"compute-3"),
    (bytes.fromhex("31302e35382e3135392e"), b"192.0.2."),
    (bytes.fromhex("6368656e796f6e676d696e6732313140676d61696c2e636f6d"), b"maintainers@example.invalid"),
    (bytes.fromhex("6e65746d6f75736572"), b"repository-maintainer"),
    (bytes.fromhex("2f55736572732f6368656e"), b"/home/developer"),
)
```

Handle the public repository owner separately: mask complete canonical HTTPS repository URLs before replacing the encoded owner with `example-org`, then restore the canonical URLs. `migrate_paths()` rewrites regular non-archive files atomically through a sibling temporary file while preserving mode, renames paths deepest-first, refuses destination collisions, and is idempotent.

The CLI obtains the tracked set from `git ls-files -z`, migrates file content, then renames matched paths deepest-first. It prints counts only, never decoded source values.

- [x] **Step 4: Run the migration and rebuild tracked generated archives**

Run:

```bash
python3 ci/anonymize_public_tree.py
cd outputs/html-ppt/aria-neutron-agent-report
zip -FSr ../aria-neutron-agent-report.zip .
cd ../../..
```

Expected: tracked content and evidence paths use deterministic aliases; the tracked report archive contains only anonymized source files.

- [x] **Step 5: Repair semantic prose and public metadata after mechanical replacement**

Review and use `apply_patch` for these exact files:

- `AGENTS.md`, `CLAUDE.md`: replace the now-placeholder remote/user/email list with “use configured origin and repository-local Git identity”; retain the single-branch and no-local-Cargo rules.
- `README.md`: replace machine-specific working-directory prose with “repository root”.
- `aria-firewall.spec`: retain the canonical HTTPS project URL and use `Aria Firewall Maintainers <maintainers@example.invalid>` in `%changelog`.
- `docs/openstack-neutron-agent-mode.md`: replace fixed local path/identity statements with repository-root/local-config wording.
- `docs/user-manual.md`: convert local absolute source links to repository-relative links while retaining line references only if still correct.
- `deploy/kolla/config/neutron-aria-agent.ini`: use `compute-1.example.test` only as an RFC-style example, not a target default.

Expected: no fake operational instruction remains after mechanical replacement, and canonical repository/Actions links still navigate correctly.

- [x] **Step 6: Run focused GREEN verification**

Run:

```bash
python3 -m unittest ci.test_public_release_hygiene -v
python3 ci/check_blocked_terms.py
python3 -m unittest ci.test_ci_lane_contract -v
python3 -m unittest ci.test_ci001_trusted_gates -v
python3 -m unittest ci.test_rust_build_required -v
python3 ci/check_smoke_python_blocks.py
find deploy ci -type f -name '*.sh' -print0 | xargs -0 -n1 bash -n
python3 ci/check_payload_terms.py outputs/html-ppt/aria-neutron-agent-report.zip
git diff --check
```

Expected: all commands PASS; no command invokes Cargo.

Run a second idempotence check:

```bash
before="$(git status --porcelain=v1)"
python3 ci/anonymize_public_tree.py
after="$(git status --porcelain=v1)"
test "$before" = "$after"
```

Expected: PASS with no additional changes.

Execution note: `ci/check_smoke_python_blocks.py` reports three pre-existing
heredoc-continuation false positives. The same failures were reproduced against
the unmodified pre-migration `HEAD`; both affected shell files have no ACL-011
diff and pass `bash -n`. This independent checker defect was not modified in
this batch. All other commands above, the 557-test Python discovery, Stage 2/3
contracts, N0.5 evidence, and three-host UDS evidence passed.

- [x] **Step 7: Review the mechanical scope before commit**

Run:

```bash
git diff --stat
git diff --numstat
git diff --name-status
git diff -- ci/public_release_policy.py ci/check_blocked_terms.py ci/check_payload_terms.py ci/anonymize_public_tree.py ci/test_public_release_hygiene.py .github/workflows/build.yml ci/test_ci_lane_contract.py
```

Expected: policy code is reviewable separately; the remaining large diff is deterministic replacement/rename output with no ACL/runtime behavior change.

- [x] **Step 8: Commit and push GREEN**

```bash
git add -A
git commit -m "fix: anonymize public release identifiers"
git push origin v0.9-neutron-agent
```

- [x] **Step 9: Require exact-head hosted GREEN**

Run:

```bash
head_sha="$(git rev-parse HEAD)"
green_run_id="$(gh run list --commit "$head_sha" --workflow Build --limit 1 \
  --json databaseId --jq '.[0].databaseId')"
test -n "$green_run_id"
gh run watch "$green_run_id" --exit-status
test "$(gh run view "$green_run_id" --json headSha --jq .headSha)" = "$head_sha"
```

Expected: exact-head Build passes `fast-contracts`, database/clean-install lanes, selected Rust behavior, and warning-denied eBPF/userspace/static-agent builds. No field PASS is claimed.

Execution evidence: implementation commit `af6accb` passed exact-head Build
[`30811728869`](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/30811728869).

---

### Task 3: Delivery record and final exact-head closure

**Files:**
- Modify: `docs/superpowers/specs/2026-08-03-review-acl-011-public-release-hygiene-design.md`
- Modify: `docs/superpowers/plans/2026-08-03-review-acl-011-public-release-hygiene.md`
- Modify: `docs/openstack-neutron-aria-details/12-review-bug-backlog.md`

**Interfaces:**
- Consumes: RED commit/run and GREEN commit/run from Tasks 1–2.
- Produces: authoritative fixed status with current-tree/future-payload scope and explicit historical-object exclusion.

- [x] **Step 1: Update design status and acceptance evidence**

Collect the concrete evidence first:

```bash
red_sha="$(git log --grep='test: expose public release identifier leaks' -1 --format=%H)"
green_sha="$(git log --grep='fix: anonymize public release identifiers' -1 --format=%H)"
red_run_url="$(gh run list --commit "$red_sha" --workflow Build --limit 1 --json url --jq '.[0].url')"
green_run_json="$(gh run list --commit "$green_sha" --workflow Build --limit 1 --json databaseId,url --jq '.[0]')"
green_run_id="$(printf '%s' "$green_run_json" | python3 -c 'import json,sys; print(json.load(sys.stdin)["databaseId"])')"
green_run_url="$(printf '%s' "$green_run_json" | python3 -c 'import json,sys; print(json.load(sys.stdin)["url"])')"
test -n "$red_sha" && test -n "$green_sha" && test -n "$red_run_url" && test -n "$green_run_id" && test -n "$green_run_url"
```

Replace the design status using those concrete values; the resulting text must
have this exact shape with the variables resolved, not copied literally:

```markdown
**Status:** implemented in `${green_sha}`. Exact implementation-head Build
[`${green_run_id}`](${green_run_url}) passed every required hosted lane. Current
tracked paths/content and future payloads are covered; historical Git objects
were deliberately not rewritten.
```

Append RED and GREEN evidence under acceptance without claiming field execution.

- [x] **Step 2: Update the authoritative backlog row**

Set `REVIEW-ACL-011` to `fixed` and record:

```text
Current tracked path names/content and generated payloads now share an encoded,
path/archive-aware identifier policy. Deterministic aliases preserve field
evidence semantics and canonical public provenance URLs. The concrete RED
commit and run proved the old checker gaps; the concrete GREEN commit and run
passed exact-head hosted CI. Git history was not rewritten, no privileged field
run applies, and DEBT-REPO-001 remains separate.
```

Do not place decoded prohibited values in the backlog.

- [x] **Step 3: Mark every completed plan checkbox and run documentation checks**

Run:

```bash
python3 ci/check_blocked_terms.py
python3 -m unittest ci.test_public_release_hygiene ci.test_ci_lane_contract -v
git diff --check
```

Expected: PASS.

- [x] **Step 4: Commit and push delivery documentation**

```bash
git add docs/superpowers/specs/2026-08-03-review-acl-011-public-release-hygiene-design.md \
  docs/superpowers/plans/2026-08-03-review-acl-011-public-release-hygiene.md \
  docs/openstack-neutron-aria-details/12-review-bug-backlog.md
git commit -m "docs: close public release hygiene review"
git push origin v0.9-neutron-agent
```

- [x] **Step 5: Verify final branch and exact-head CI**

Run:

```bash
git status --short --branch
git rev-list --left-right --count v0.9-neutron-agent...origin/v0.9-neutron-agent
gh run list --branch v0.9-neutron-agent --workflow Build --limit 5 \
  --json databaseId,headSha,status,conclusion,url
```

Expected: clean worktree, divergence `0 0`, and the documentation HEAD has a successful exact-head Build. If docs-only HEAD triggers all required lanes under the existing change detector, wait for them; never cite the prior implementation run as exact-head for the documentation commit.

---

## Plan self-review

- Spec coverage: current tree, tracked path names, nested archives, generated payloads, provenance exception, deterministic evidence aliases, history exclusion, CI evidence, and backlog closure each have an owning task.
- Placeholder scan: angle-bracket values appear only where execution must substitute the actual commit/run produced by earlier steps; no implementation behavior is left unspecified.
- Type consistency: the shared policy, repository checker, payload checker, migration script, and tests use the same function names and return shapes throughout.
- Scope control: no product behavior, evidence deletion, branch creation, field claim, local Cargo work, or history rewrite is included.
