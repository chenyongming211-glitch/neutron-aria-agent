#!/usr/bin/env python3
"""Public contract tests for the independent Build workflow lanes."""

import re
import unittest
from pathlib import Path


WORKFLOW = Path(__file__).resolve().parents[1] / ".github" / "workflows" / "build.yml"
STAGE_ONE = Path(__file__).with_name("check_neutron_stage1.py")
CHECKOUT_NODE24 = "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1"
CACHE_NODE24 = "actions/cache@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"
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
        self.assertIn(
            "python3 -m unittest ci.test_public_release_hygiene",
            fast_contracts,
        )

    def test_javascript_actions_use_pinned_node24_releases(self):
        self.assertEqual(self.source.count(CHECKOUT_NODE24), 9)
        self.assertEqual(self.source.count(CACHE_NODE24), 3)
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
        self.assertIn("test_aria_acl_counter_migration", db_contracts)
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
        self.assertIn("run_rust_behavior_command(prefix + cmd)", stage_one)
        self.assertNotIn("discovered_rust_test_names", stage_one)
        self.assertNotRegex(behavior, r"\bcargo\s+\+[^\n]*\bbuild\b")

    def test_rust_build_does_not_run_rust_tests(self):
        build = job_block(self.source, "rust-build")
        self.assertRegex(build, r"\bcargo\s+\+[^\n]*\bbuild\b")
        self.assertNotRegex(build, r"\bcargo\s+\+[^\n]*\btest\b")

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

    def test_quality_rust_has_the_broad_host_commands(self):
        block = job_block(self.source, "quality-rust")
        for command in [
            RUST_WORKSPACE_TEST,
            RUST_WORKSPACE_CLIPPY,
            RUST_WORKSPACE_FMT,
        ]:
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


if __name__ == "__main__":
    unittest.main()
