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
