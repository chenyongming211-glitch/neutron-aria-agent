#!/usr/bin/env python3
"""Behavior contracts for REVIEW-CI-001 trusted automated gates."""

import contextlib
import io
import subprocess
import unittest
from unittest import mock

from ci import check_neutron_stage1
from ci import check_neutron_stage2_acl
from ci import check_stage2_acceptance_evidence
from ci import check_stage3_n3_evidence
from ci import check_stage3_readiness


class TrustedGateContractTests(unittest.TestCase):
    def test_required_python_behaviors_are_in_full_discovery(self):
        discovered = check_neutron_stage1.discovered_python_test_ids()
        required = set(check_neutron_stage1.REQUIRED_PYTHON_BEHAVIORS)
        self.assertTrue(required)
        self.assertEqual(required - discovered, set())

    def test_python_requested_domains_are_bounded_by_advertised_domains(self):
        check_neutron_stage1.validate_python_managed_domain_contract(
            advertised=("attach", "acl"),
            python_supported=("acl",),
            requested=("acl",),
        )
        with self.assertRaises(SystemExit):
            check_neutron_stage1.validate_python_managed_domain_contract(
                advertised=("attach", "acl"),
                python_supported=("acl", "qos"),
                requested=("acl",),
            )
        with self.assertRaises(SystemExit):
            check_neutron_stage1.validate_python_managed_domain_contract(
                advertised=("attach", "acl"),
                python_supported=("acl",),
                requested=("acl", "mirror"),
            )

    def test_stage2_static_audit_does_not_duplicate_python_execution(self):
        output = io.StringIO()
        with mock.patch("subprocess.check_call") as run:
            with contextlib.redirect_stdout(output):
                self.assertEqual(check_neutron_stage2_acl.main(), 0)
        run.assert_not_called()
        self.assertIn("evidence_class=static_artifact", output.getvalue())
        self.assertIn("runtime_evidence=not_evaluated", output.getvalue())

    def test_stage3_plan_checker_reports_static_scope(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            check_stage3_readiness.main()
        self.assertIn("stage-three static/artifact contract passed", output.getvalue())
        self.assertIn("evidence_class=static_artifact", output.getvalue())
        self.assertIn("runtime_evidence=not_evaluated", output.getvalue())
        self.assertNotIn("readiness plan accepted", output.getvalue())

    def test_committed_field_summaries_are_not_head_bound_runtime_evidence(self):
        stage2 = io.StringIO()
        with contextlib.redirect_stdout(stage2):
            check_stage2_acceptance_evidence.main()
        self.assertIn("evidence_class=historical_field_evidence", stage2.getvalue())
        self.assertIn("head_bound=false", stage2.getvalue())

        stage3 = io.StringIO()
        with contextlib.redirect_stdout(stage3):
            self.assertEqual(
                check_stage3_n3_evidence.main(["--require-complete"]),
                0,
            )
        self.assertIn("evidence_class=historical_field_evidence", stage3.getvalue())
        self.assertIn("head_bound=false", stage3.getvalue())

    def test_cargo_success_with_zero_executed_tests_is_rejected(self):
        completed = subprocess.CompletedProcess(
            args=["cargo", "test"],
            returncode=0,
            stdout="running 0 tests\n\ntest result: ok. 0 passed; 0 failed\n",
        )
        with mock.patch.object(check_neutron_stage1.subprocess, "run", return_value=completed):
            with self.assertRaises(SystemExit):
                check_neutron_stage1.run_rust_behavior_command(["cargo", "test"])

    def test_cargo_execution_count_accepts_a_real_matching_test(self):
        completed = subprocess.CompletedProcess(
            args=["cargo", "test"],
            returncode=0,
            stdout=(
                "running 0 tests\n"
                "test result: ok. 0 passed; 0 failed\n"
                "running 2 tests\n"
                "test result: ok. 2 passed; 0 failed\n"
            ),
        )
        with mock.patch.object(check_neutron_stage1.subprocess, "run", return_value=completed):
            self.assertEqual(
                check_neutron_stage1.run_rust_behavior_command(["cargo", "test"]),
                2,
            )


if __name__ == "__main__":
    unittest.main()
