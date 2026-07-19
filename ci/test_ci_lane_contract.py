#!/usr/bin/env python3
"""Public contract tests for the independent Build workflow lanes."""

import re
import unittest
from pathlib import Path


WORKFLOW = Path(__file__).resolve().parents[1] / ".github" / "workflows" / "build.yml"
STAGE_ONE = Path(__file__).with_name("check_neutron_stage1.py")


def job_block(source: str, job: str) -> str:
    match = re.search(
        rf"(?ms)^  {re.escape(job)}:\n(?P<body>.*?)(?=^  [A-Za-z][A-Za-z0-9_-]*:|\Z)",
        source,
    )
    if match is None:
        raise AssertionError(f"Build workflow must define the {job!r} job")
    return match.group("body")


class CiLaneContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = WORKFLOW.read_text(encoding="utf-8")

    def test_changes_publishes_single_shared_rust_required_output(self):
        changes = job_block(self.source, "changes")
        self.assertRegex(
            changes,
            r"(?m)^      rust_required: \$\{\{ steps\.rust_changes\.outputs\.rust_required \}\}$",
        )
        self.assertEqual(
            len(re.findall(r"(?m)^      rust_required:", changes)),
            1,
            "changes must publish rust_required exactly once",
        )

    def test_fast_contracts_has_no_cargo_commands(self):
        self.assertNotRegex(job_block(self.source, "fast-contracts"), r"\bcargo\b")

    def test_rust_behavior_runs_only_rust_tests(self):
        behavior = job_block(self.source, "rust-behavior")
        self.assertIn(
            "python3 ci/check_neutron_stage1.py --rust-tests-only --rust-toolchain stable",
            behavior,
        )
        stage_one = STAGE_ONE.read_text(encoding="utf-8")
        self.assertIn("for cmd in RUST_TESTS:", stage_one)
        self.assertIn("run(prefix + cmd)", stage_one)
        self.assertNotRegex(behavior, r"\bcargo\s+\+[^\n]*\bbuild\b")

    def test_rust_build_does_not_run_rust_tests(self):
        build = job_block(self.source, "rust-build")
        self.assertRegex(build, r"\bcargo\s+\+[^\n]*\bbuild\b")
        self.assertNotRegex(build, r"\bcargo\s+\+[^\n]*\btest\b")


if __name__ == "__main__":
    unittest.main()
