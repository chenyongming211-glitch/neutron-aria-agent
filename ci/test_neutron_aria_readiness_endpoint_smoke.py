from __future__ import print_function

import os
import unittest


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SMOKE = os.path.join(
    ROOT,
    "deploy",
    "kolla",
    "smoke",
    "neutron_aria_readiness_endpoint_smoke.sh",
)


class ReadinessEndpointSmokeContractTest(unittest.TestCase):
    def test_public_probe_enforces_negative_status_contract(self):
        with open(SMOKE, "r") as stream:
            source = stream.read()

        required = (
            "EXPECTED_TRANSACTION_STATE",
            "EXPECTED_OVERALL_READINESS",
            "EXPECTED_REQUIRED_ACTION",
            "/api/v1/neutron/status",
            "/readyz",
            "status_body != ready_body",
            "ready_code != expected_ready_code",
            "docker exec",
        )
        for term in required:
            self.assertIn(term, source)

    def test_probe_is_observation_only(self):
        with open(SMOKE, "r") as stream:
            source = stream.read()

        forbidden = (
            "docker restart",
            "docker stop",
            "systemctl",
            "ovs-vsctl",
            "tc filter del",
            "bpftool link detach",
            "-X PUT",
            "-X POST",
            "-X DELETE",
        )
        for term in forbidden:
            self.assertNotIn(term, source)


if __name__ == "__main__":
    unittest.main()
