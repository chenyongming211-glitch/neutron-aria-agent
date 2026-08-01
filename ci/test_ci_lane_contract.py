#!/usr/bin/env python3
"""Public contract tests for the independent Build workflow lanes."""

import re
import unittest
from pathlib import Path


WORKFLOW = Path(__file__).resolve().parents[1] / ".github" / "workflows" / "build.yml"
STAGE_ONE = Path(__file__).with_name("check_neutron_stage1.py")
CHECKOUT_NODE24 = "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1"
CACHE_NODE24 = "actions/cache@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"


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
        fast_contracts = job_block(self.source, "fast-contracts")
        self.assertNotRegex(fast_contracts, r"\bcargo\b")
        self.assertIn(
            "python3 -m unittest ci.test_ci001_trusted_gates",
            fast_contracts,
        )

    def test_javascript_actions_use_pinned_node24_releases(self):
        self.assertEqual(self.source.count(CHECKOUT_NODE24), 7)
        self.assertEqual(self.source.count(CACHE_NODE24), 2)
        self.assertNotIn("actions/checkout@v4", self.source)
        self.assertNotIn("actions/cache@v4", self.source)

    def test_clean_agent_install_is_an_independent_cargo_free_container_lane(self):
        clean_install = job_block(self.source, "neutron-agent-clean-install")
        self.assertIn("ci/test_neutron_agent_clean_install.sh", clean_install)
        self.assertIn("sudo env", clean_install)
        self.assertNotRegex(clean_install, r"\bcargo\b")
        self.assertNotIn("needs: rust-build", clean_install)

    def test_neutron_db_contracts_are_independent_and_cargo_free(self):
        db_contracts = job_block(self.source, "neutron-db-contracts")
        self.assertIn("ci/requirements-neutron-db-contracts.txt", db_contracts)
        self.assertIn("test_aria_acl_sql_query", db_contracts)
        self.assertIn("PYTHONWARNINGS: error", db_contracts)
        self.assertIn('SQLALCHEMY_WARN_20: "1"', db_contracts)
        self.assertNotRegex(db_contracts, r"\bcargo\b")
        self.assertNotIn("needs: rust-build", db_contracts)

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
