from __future__ import absolute_import

import unittest

from neutron_aria.agent.effective_acl import ACL_DEGRADED
from neutron_aria.agent.effective_acl import ACL_NOT_REQUESTED
from neutron_aria.agent.effective_acl import ACL_READY
from neutron_aria.agent.effective_acl import ACL_UNSUPPORTED
from neutron_aria.agent.effective_acl import EffectiveAclIndex


PORT_ID = "port-1"
NETWORK_ID = "net-1"


def port(port_id=PORT_ID, network_id=NETWORK_ID):
    return {
        "id": port_id,
        "network_id": network_id,
    }


def snapshot(eligible=True, disposition="eligible_ovs_tap"):
    return {
        "eligible": eligible,
        "disposition": disposition,
    }


class EffectiveAclTestCase(unittest.TestCase):
    def test_no_binding_is_not_requested(self):
        index = EffectiveAclIndex()

        result = index.effective_for_port(port(), snapshot())

        self.assertFalse(result["enabled"])
        self.assertEqual(ACL_NOT_REQUESTED, result["status"])
        self.assertEqual("bypass", result["effective_action"])

    def test_port_binding_overrides_network_binding(self):
        index = EffectiveAclIndex(
            policies=[
                {"id": "policy-port", "name": "port", "default_action": "allow"},
                {"id": "policy-net", "name": "net", "default_action": "deny"},
            ],
            bindings=[
                {
                    "id": "binding-net",
                    "policy_id": "policy-net",
                    "target_type": "network",
                    "target_id": NETWORK_ID,
                },
                {
                    "id": "binding-port",
                    "policy_id": "policy-port",
                    "target_type": "port",
                    "target_id": PORT_ID,
                },
            ],
        )

        result = index.effective_for_port(port(), snapshot())

        self.assertTrue(result["enabled"])
        self.assertEqual(ACL_READY, result["status"])
        self.assertEqual("enforce", result["effective_action"])
        self.assertEqual("policy-port", result["policy_id"])
        self.assertEqual("port", result["source"])

    def test_rule_expands_address_set_members(self):
        index = EffectiveAclIndex(
            policies=[{"id": "policy-1", "default_action": "allow", "revision_number": 2}],
            address_sets=[
                {
                    "id": "aset-1",
                    "revision_number": 7,
                    "members": [{"address": "10.10.20.0/24"}, "10.10.21.15/32"],
                }
            ],
            rules=[
                {
                    "id": "rule-1",
                    "policy_id": "policy-1",
                    "direction": "egress",
                    "priority": 100,
                    "action": "deny",
                    "ethertype": "IPv4",
                    "protocol": "tcp",
                    "dst_address_set_id": "aset-1",
                    "dst_port_min": 3306,
                    "dst_port_max": 3306,
                }
            ],
            bindings=[
                {
                    "id": "binding-1",
                    "policy_id": "policy-1",
                    "target_type": "port",
                    "target_id": PORT_ID,
                }
            ],
        )

        result = index.effective_for_port(port(), snapshot())

        self.assertEqual(ACL_READY, result["status"])
        self.assertEqual(["10.10.20.0/24", "10.10.21.15/32"], result["rules"][0]["dst_cidrs"])
        self.assertEqual(3306, result["rules"][0]["dst_port_min"])
        self.assertEqual(7, result["revision"])

    def test_invalid_priority_degrades_policy_without_crashing(self):
        index = EffectiveAclIndex(
            policies=[{"id": "policy-1"}],
            rules=[
                {
                    "id": "rule-1",
                    "policy_id": "policy-1",
                    "direction": "egress",
                    "priority": "bad",
                    "action": "deny",
                }
            ],
            bindings=[
                {"id": "b1", "policy_id": "policy-1", "target_type": "port", "target_id": PORT_ID},
            ],
        )

        result = index.effective_for_port(port(), snapshot())

        self.assertEqual(ACL_DEGRADED, result["status"])
        self.assertFalse(result["enabled"])
        self.assertIn("invalid_rule_priority:rule-1", result["reason"])
        self.assertEqual("bypass", result["effective_action"])

    def test_duplicate_enabled_bindings_degrade(self):
        index = EffectiveAclIndex(
            policies=[{"id": "policy-1"}, {"id": "policy-2"}],
            bindings=[
                {"id": "b1", "policy_id": "policy-1", "target_type": "port", "target_id": PORT_ID},
                {"id": "b2", "policy_id": "policy-2", "target_type": "port", "target_id": PORT_ID},
            ],
        )

        result = index.effective_for_port(port(), snapshot())

        self.assertFalse(result["enabled"])
        self.assertEqual(ACL_DEGRADED, result["status"])
        self.assertEqual("multiple_enabled_port_bindings", result["reason"])
        self.assertEqual("bypass", result["effective_action"])

    def test_l4_ports_without_tcp_udp_degrade_policy(self):
        index = EffectiveAclIndex(
            policies=[{"id": "policy-1"}],
            rules=[
                {
                    "id": "rule-1",
                    "policy_id": "policy-1",
                    "direction": "egress",
                    "priority": 100,
                    "action": "deny",
                    "protocol": "icmp",
                    "dst_port_min": 80,
                }
            ],
            bindings=[
                {"id": "b1", "policy_id": "policy-1", "target_type": "port", "target_id": PORT_ID},
            ],
        )

        result = index.effective_for_port(port(), snapshot())

        self.assertEqual(ACL_DEGRADED, result["status"])
        self.assertFalse(result["enabled"])
        self.assertIn("l4_ports_require_tcp_or_udp", result["reason"])
        self.assertEqual("bypass", result["effective_action"])

    def test_ineligible_port_is_unsupported(self):
        index = EffectiveAclIndex(
            policies=[{"id": "policy-1"}],
            bindings=[
                {"id": "b1", "policy_id": "policy-1", "target_type": "port", "target_id": PORT_ID},
            ],
        )

        result = index.effective_for_port(port(), snapshot(False, "unsupported_vif_type:hw_veb"))

        self.assertFalse(result["enabled"])
        self.assertEqual(ACL_UNSUPPORTED, result["status"])
        self.assertEqual("unsupported_vif_type:hw_veb", result["reason"])
        self.assertEqual("bypass", result["effective_action"])


if __name__ == "__main__":
    unittest.main()
