#!/usr/bin/env python3
"""Behavior contracts for REVIEW-CI-001 trusted automated gates."""

import contextlib
import configparser
import io
import os
import subprocess
import unittest
from unittest import mock

from ci import check_neutron_stage1
from ci import check_neutron_stage2_acl
from ci import check_tc_acl_datapath
from ci import check_stage2_acceptance_evidence
from ci import check_stage3_n3_evidence
from ci import check_stage3_readiness


class TrustedGateContractTests(unittest.TestCase):
    def test_ipv6_behavior_filters_and_python_contracts_are_fixed(self):
        filters = {
            check_neutron_stage1.rust_test_filter(command)
            for command in check_neutron_stage1.RUST_TESTS
        }
        self.assertTrue(
            set(check_neutron_stage1.IPV6_REQUIRED_RUST_FILTERS).issubset(filters)
        )
        self.assertFalse(
            set(check_neutron_stage1.IPV6_REQUIRED_RUST_FILTERS) - filters
        )
        self.assertTrue(
            set(check_neutron_stage1.IPV6_REQUIRED_PYTHON_BEHAVIORS).issubset(
                set(check_neutron_stage1.REQUIRED_PYTHON_BEHAVIORS)
            )
        )

    def test_dual_stack_smoke_contract_names_evidence_and_deferred_boundary(self):
        self.assertEqual(
            set(check_neutron_stage1.DUAL_STACK_SMOKE_CASES),
            {
                "ipv4-only", "ipv6-only", "dual-stack", "wildcard-isolation",
                "fragment", "stateful-reply", "upgrade", "rollback",
            },
        )
        self.assertEqual(
            set(check_neutron_stage1.SMOKE_EVIDENCE_FIELDS),
            {
                "command", "expected_verdict", "observed_verdict", "interface",
                "ifindex", "kernel", "agent_version", "datapath_version",
                "status_snapshot", "counter_snapshot", "status",
            },
        )
        self.assertEqual(check_neutron_stage1.FIELD_EVIDENCE_STATUS, "deferred/pending")

    def test_fragment_aware_wrapper_rejects_a_non_ct_hit_guard(self):
        with open(check_tc_acl_datapath.EBPF_LIB, encoding="utf-8") as handle:
            source = handle.read()
        mutant = source.replace(
            "let create_point = fragment_ct_create_point(info.fragment_kind);\n    if ct_hit {",
            "let create_point = fragment_ct_create_point(info.fragment_kind);\n    if true {",
            1,
        )
        errors = check_tc_acl_datapath.check_source(mutant)
        self.assertTrue(
            any("fragment-aware CT hit/miss branch" in error for error in errors),
            errors,
        )

    def test_review_contracts_retain_all_datapath_mutations_and_reject_field_forgery(self):
        with open(check_tc_acl_datapath.__file__, encoding="utf-8") as handle:
            checker = handle.read()
        self.assertNotIn(
            'if "fragment::resolve_v4" in source:\n        specs = (', checker,
            "fragment-aware source must run legacy and new mutations together",
        )
        for label in (
            "egress v4 hit QoS drop without return",
            "ingress v4 miss ACL drop without return",
            "ingress v4 miss QoS drop without return",
            "egress v4 miss CT create without runtime guard",
            "fragment-aware CT hit guard",
            "fragment context install",
            "fragment-aware miss branch",
        ):
            self.assertIn(label, checker)

        managed_path = os.path.join(
            check_neutron_stage1.ROOT,
            check_neutron_stage1.TC_ACL_DATAPATH_SMOKE_PATH,
        )
        standalone_path = os.path.join(
            check_neutron_stage1.ROOT,
            check_neutron_stage1.STANDALONE_TC_ACL_SMOKE_PATH,
        )
        with open(managed_path, encoding="utf-8") as handle:
            managed = handle.read()
        with open(standalone_path, encoding="utf-8") as handle:
            standalone = handle.read()
        for smoke in (managed, standalone):
            self.assertIn('FIELD_EVIDENCE_STATUS="deferred/pending"', smoke)
            self.assertNotIn('FIELD_EVIDENCE_STATUS="${FIELD_EVIDENCE_STATUS:-', smoke)
            self.assertIn("observed_verdict != \"not run\"", smoke)
            self.assertIn("prerequisite", smoke)
        self.assertIn('payload["policies"]', standalone)
        self.assertIn('for ethertype in IPv4 IPv6', standalone)
        self.assertIn('DELETE', standalone)
        config_path = os.path.join(
            check_neutron_stage1.ROOT,
            "deploy", "kolla", "config", "neutron-aria-agent.ini",
        )
        with open(config_path, encoding="utf-8") as handle:
            self.assertIn("counters_report_enabled = false", handle.read())

    def test_standalone_api_expansion_never_records_a_field_traffic_pass(self):
        standalone_path = os.path.join(
            check_neutron_stage1.ROOT,
            check_neutron_stage1.STANDALONE_TC_ACL_SMOKE_PATH,
        )
        with open(standalone_path, encoding="utf-8") as handle:
            source = handle.read()
        start = source.index("run_ethertype_any_expansion_smoke() {")
        end = source.index("\ndie() {", start)
        expansion = source[start:end]
        self.assertNotIn("record_field_case", expansion)
        self.assertIn("record_deferred_field_cases", expansion)
        self.assertIn("ethertype-any-expansion.json", expansion)

    def test_standalone_fragment_fixture_and_recovery_are_family_qualified(self):
        standalone_path = os.path.join(
            check_neutron_stage1.ROOT,
            check_neutron_stage1.STANDALONE_TC_ACL_SMOKE_PATH,
        )
        with open(standalone_path, encoding="utf-8") as handle:
            source = handle.read()
        fixture = source[
            source.index("install_fixture_policy() {") : source.index("\ncapture_links() {")
        ]
        for source_group, destination_group, direction in (
            ("fragment-peer-v4", "fragment-host-v4", "ingress"),
            ("fragment-host-v4", "fragment-peer-v4", "egress"),
            ("fragment-peer-v6", "fragment-host-v6", "ingress"),
            ("fragment-host-v6", "fragment-peer-v6", "egress"),
        ):
            ethertype = "IPv6" if source_group.endswith("v6") else "IPv4"
            self.assertIn(
                '"src_group":"%s","dst_group":"%s","proto":"udp","action":"allow","direction":"%s","ports":"53","ethertype":"%s"'
                % (source_group, destination_group, direction, ethertype),
                fixture,
            )
        recovery = source[
            source.index("assert_recovery_verified() {") : source.index("\nwrite_summary() {")
        ]
        self.assertIn('row["ethertype"]', recovery)
        self.assertIn('"IPv6"', recovery)

    def test_packaged_counter_default_is_parsed_from_agent_section(self):
        config_path = os.path.join(
            check_neutron_stage1.ROOT,
            "deploy", "kolla", "config", "neutron-aria-agent.ini",
        )
        parser = configparser.ConfigParser()
        parser.read(config_path)
        self.assertFalse(parser.getboolean("agent", "counters_report_enabled"))
        from neutron_aria.agent.config import load_config
        self.assertFalse(load_config(config_path).counters_report_enabled)

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
