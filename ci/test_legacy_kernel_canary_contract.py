#!/usr/bin/env python3

from __future__ import print_function

import os
import unittest


ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir))
CANARY = os.path.join(
    ROOT,
    "deploy",
    "kolla",
    "smoke",
    "neutron_aria_legacy_kernel_loader_canary.sh",
)
STANDALONE = os.path.join(
    ROOT,
    "deploy",
    "smoke",
    "aria_standalone_acl_tc_datapath_smoke.sh",
)


class LegacyKernelCanaryContractTest(unittest.TestCase):
    def setUp(self):
        with open(CANARY, "r", encoding="utf-8") as handle:
            self.source = handle.read()
        with open(STANDALONE, "r", encoding="utf-8") as handle:
            self.standalone_source = handle.read()

    def test_requires_exact_kernel_and_artifact_hashes(self):
        self.assertIn("4.18.0-553.5.1.el8_10.x86_64", self.source)
        self.assertIn(': "${ARIA_AGENT_SHA256:?', self.source)
        self.assertIn(': "${EBPF_SHA256:?', self.source)
        self.assertIn("sha256sum", self.source)

    def test_reuses_isolated_tap_smoke_and_removes_state(self):
        self.assertIn("aria_standalone_acl_tc_datapath_smoke.sh", self.source)
        self.assertIn("MODE=tap", self.source)
        self.assertIn('rm -rf -- "${WORK_DIR}"', self.source)
        self.assertIn("ip netns", self.source)
        self.assertIn("tc qdisc", self.source)
        self.assertIn('for diagnostic in agent.stdout agent.log', self.source)

    def test_does_not_manage_ovs_lifecycle(self):
        lowered = self.source.lower()
        for command in (
            "systemctl restart",
            "docker restart",
            "podman restart",
            "ovs-vsctl",
            "neutron-openvswitch-agent",
        ):
            self.assertNotIn(command, lowered)

    def test_dual_tc_readiness_accepts_exact_legacy_filters_without_link_pins(self):
        self.assertIn('TC_ATTACH_MODE="legacy"', self.standalone_source)
        self.assertIn('"tc_ingress"', self.standalone_source)
        self.assertIn('"tc_egress"', self.standalone_source)
        self.assertIn("assert_exact_legacy_tc_filter", self.standalone_source)


if __name__ == "__main__":
    unittest.main()
