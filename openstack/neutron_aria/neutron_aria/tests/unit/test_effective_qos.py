from __future__ import absolute_import

import unittest

from neutron_aria.agent.effective_qos import EffectiveQosIndex
from neutron_aria.agent.effective_qos import QOS_DEGRADED
from neutron_aria.agent.effective_qos import QOS_NOT_REQUESTED
from neutron_aria.agent.effective_qos import QOS_READY


PORT_ID = "port-1"
NETWORK_ID = "net-1"


def port(qos_policy_id=None, network_id=NETWORK_ID):
    return {
        "id": PORT_ID,
        "network_id": network_id,
        "qos_policy_id": qos_policy_id,
    }


def snapshot(eligible=True, disposition="eligible_ovs_tap"):
    return {
        "eligible": eligible,
        "disposition": disposition,
    }


class EffectiveQosTestCase(unittest.TestCase):
    def test_no_policy_is_not_requested(self):
        index = EffectiveQosIndex()

        result = index.effective_for_port(port(), snapshot())

        self.assertFalse(result["enabled"])
        self.assertEqual(QOS_NOT_REQUESTED, result["status"])

    def test_port_policy_overrides_network_policy(self):
        index = EffectiveQosIndex(
            policies=[
                {
                    "id": "policy-port",
                    "name": "port",
                    "rules": [{"id": "rule-port", "max_kbps": 100000}],
                },
                {
                    "id": "policy-net",
                    "name": "net",
                    "rules": [{"id": "rule-net", "max_kbps": 200000}],
                },
            ],
            networks=[
                {"id": NETWORK_ID, "qos_policy_id": "policy-net"},
            ],
        )

        result = index.effective_for_port(port(qos_policy_id="policy-port"), snapshot())

        self.assertTrue(result["enabled"])
        self.assertEqual(QOS_READY, result["status"])
        self.assertEqual("policy-port", result["policy_id"])
        self.assertEqual("port", result["source"])
        self.assertEqual(100000, result["rules"][0]["max_kbps"])

    def test_network_policy_is_inherited(self):
        index = EffectiveQosIndex(
            policies=[
                {
                    "id": "policy-net",
                    "rules": [{"id": "rule-net", "max_kbps": "200000", "direction": "ingress"}],
                },
            ],
            networks=[
                {"id": NETWORK_ID, "qos_policy_id": "policy-net"},
            ],
        )

        result = index.effective_for_port(port(), snapshot())

        self.assertEqual(QOS_READY, result["status"])
        self.assertEqual("network", result["source"])
        self.assertEqual(200000, result["rules"][0]["max_kbps"])
        self.assertEqual("ingress", result["rules"][0]["direction"])

    def test_missing_policy_degrades(self):
        index = EffectiveQosIndex()

        result = index.effective_for_port(port(qos_policy_id="missing"), snapshot())

        self.assertFalse(result["enabled"])
        self.assertEqual(QOS_DEGRADED, result["status"])
        self.assertEqual("qos_policy_missing", result["reason"])

    def test_unsupported_rule_degrades(self):
        index = EffectiveQosIndex(
            policies=[
                {
                    "id": "policy-1",
                    "rules": [{"id": "rule-1", "type": "dscp_marking", "dscp_mark": 16}],
                },
            ],
        )

        result = index.effective_for_port(port(qos_policy_id="policy-1"), snapshot())

        self.assertFalse(result["enabled"])
        self.assertEqual(QOS_DEGRADED, result["status"])
        self.assertIn("unsupported_qos_rule:dscp_marking", result["reason"])

    def test_ineligible_port_degrades(self):
        index = EffectiveQosIndex(
            policies=[{"id": "policy-1", "rules": [{"id": "rule-1", "max_kbps": 1}]}],
        )

        result = index.effective_for_port(
            port(qos_policy_id="policy-1"),
            snapshot(False, "unsupported_vnic_type:direct"),
        )

        self.assertFalse(result["enabled"])
        self.assertEqual(QOS_DEGRADED, result["status"])
        self.assertEqual("unsupported_vnic_type:direct", result["reason"])


if __name__ == "__main__":
    unittest.main()
