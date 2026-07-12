from __future__ import absolute_import

import unittest

from neutron_aria.agent.effective_acl import ACL_DEGRADED
from neutron_aria.agent.effective_acl import ACL_NOT_REQUESTED
from neutron_aria.agent.effective_acl import ACL_READY
from neutron_aria.agent.effective_acl import ACL_UNSUPPORTED
from neutron_aria.agent.effective_acl import EffectiveAclIndex
from neutron_aria.agent.effective_acl import REVISION_NEWER
from neutron_aria.agent.effective_acl import REVISION_OLDER
from neutron_aria.agent.effective_acl import REVISION_SAME
from neutron_aria.agent.effective_acl import REVISION_UNKNOWN


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


def acl_rule(rule_id, priority, **overrides):
    rule = {
        "id": rule_id,
        "policy_id": "policy-1",
        "direction": "egress",
        "priority": priority,
        "action": "deny",
        "ethertype": "IPv4",
        "protocol": "tcp",
    }
    rule.update(overrides)
    return rule


def effective_acl(rules):
    return EffectiveAclIndex(
        policies=[{"id": "policy-1", "default_action": "allow"}],
        rules=rules,
        bindings=[{
            "id": "binding-1",
            "policy_id": "policy-1",
            "target_type": "port",
            "target_id": PORT_ID,
        }],
    ).effective_for_port(port(), snapshot())


class EffectiveAclTestCase(unittest.TestCase):
    def test_nested_cidrs_degrade_with_stable_overlap_reason(self):
        result = effective_acl([
            acl_rule("broad", 10, src_cidr="10.0.0.0/8"),
            acl_rule("narrow", 20, src_cidr="10.1.0.0/16", protocol="udp"),
        ])
        self.assertEqual(ACL_DEGRADED, result["status"])
        self.assertEqual("bypass", result["effective_action"])
        self.assertIn(
            "unsupported_acl_cidr_overlap:src:broad:10:narrow:20",
            result["reason"],
        )

    def test_partial_cidr_intersection_degrades(self):
        result = effective_acl([
            acl_rule("left", 10, dst_cidr="10.0.0.0/23"),
            acl_rule("right", 20, dst_cidr="10.0.1.0/24", protocol="udp"),
        ])
        self.assertIn("unsupported_acl_cidr_overlap:dst:left:10:right:20", result["reason"])

    def test_wildcard_specific_behavior_conflict_degrades(self):
        result = effective_acl([
            acl_rule("wildcard", 10, protocol=None, action="allow"),
            acl_rule("tcp-drop", 20, protocol="tcp", action="deny"),
        ])
        self.assertIn(
            "unsupported_acl_priority_overlap:wildcard:10:tcp-drop:20",
            result["reason"],
        )

    def test_specificity_port_behavior_conflict_degrades(self):
        result = effective_acl([
            acl_rule("any-src", 10, dst_port_min=80, dst_port_max=80),
            acl_rule(
                "specific-src", 20, src_cidr="10.1.0.0/16",
                dst_port_min=443, dst_port_max=443,
            ),
        ])
        self.assertIn(
            "unsupported_acl_priority_overlap:any-src:10:specific-src:20",
            result["reason"],
        )

    def test_canonical_equivalent_cidrs_are_one_safe_selector(self):
        result = effective_acl([
            acl_rule("tcp", 10, src_cidr="10.1.2.3/24", dst_port_min=80),
            acl_rule("udp", 20, src_cidr="10.1.2.0/24", protocol="udp", dst_port_min=53),
        ])
        self.assertEqual(ACL_READY, result["status"])
        self.assertEqual("enforce", result["effective_action"])

    def test_disjoint_protocols_and_cidrs_remain_ready(self):
        result = effective_acl([
            acl_rule("tcp-left", 10, src_cidr="10.1.0.0/16"),
            acl_rule("udp-right", 20, src_cidr="10.2.0.0/16", protocol="udp"),
        ])
        self.assertEqual(ACL_READY, result["status"])

    def test_negative_priority_uses_stable_reason(self):
        result = effective_acl([acl_rule("negative", -1)])
        self.assertIn("invalid_acl_priority:negative:-1", result["reason"])

    def test_duplicate_priority_uses_stable_reason(self):
        result = effective_acl([
            acl_rule("first", 10),
            acl_rule("second", 10, protocol="udp"),
        ])
        self.assertIn(
            "duplicate_acl_priority:egress:10:first:second",
            result["reason"],
        )

    def test_duplicate_priority_normalizes_direction_and_reason(self):
        result = effective_acl([
            acl_rule("first", 10, direction=" EGRESS "),
            acl_rule("second", 10, direction="egress", protocol="udp"),
        ])
        self.assertIn(
            "duplicate_acl_priority:egress:10:first:second",
            result["reason"],
        )

    def test_overlap_normalization_strips_protocol_and_action(self):
        result = effective_acl([
            acl_rule("spaced", 10, protocol=" TCP ", action=" DENY "),
            acl_rule("canonical", 20, protocol="tcp", action="drop"),
        ])
        self.assertEqual(ACL_READY, result["status"])

    def test_overlap_normalization_strips_direction(self):
        result = effective_acl([
            acl_rule("spaced", 10, direction=" INGRESS ", action="allow"),
            acl_rule("canonical", 20, direction="ingress", action="deny"),
        ])
        self.assertIn(
            "unsupported_acl_priority_overlap:spaced:10:canonical:20",
            result["reason"],
        )

    def test_non_integer_priorities_use_stable_reason(self):
        for rule_id, priority in (
                ("boolean", True), ("float", 1.5), ("text", "1.5")):
            result = effective_acl([acl_rule(rule_id, priority)])
            self.assertIn(
                "invalid_acl_priority:%s:%s" % (rule_id, priority),
                result["reason"],
            )

    def test_integer_string_priority_remains_valid(self):
        result = effective_acl([acl_rule("string", "10")])
        self.assertEqual(ACL_READY, result["status"])

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

    def test_disabled_or_empty_address_set_degrades(self):
        for address_set in (
            {
                "id": "aset-1",
                "enabled": False,
                "members": ["10.10.20.0/24"],
            },
            {"id": "aset-1", "enabled": True, "members": []},
        ):
            index = EffectiveAclIndex(
                policies=[{"id": "policy-1", "default_action": "allow"}],
                address_sets=[address_set],
                rules=[{
                    "id": "rule-1",
                    "policy_id": "policy-1",
                    "direction": "ingress",
                    "priority": 10,
                    "action": "allow",
                    "src_address_set_id": "aset-1",
                }],
                bindings=[{
                    "id": "binding-1",
                    "policy_id": "policy-1",
                    "target_type": "port",
                    "target_id": PORT_ID,
                }],
            )

            result = index.effective_for_port(port(), snapshot())

            self.assertFalse(result["enabled"])
            self.assertEqual(ACL_DEGRADED, result["status"])
            self.assertEqual("bypass", result["effective_action"])
            self.assertIn("address_set", result["reason"])

    def test_revision_compare_uses_effective_acl_revision(self):
        index = EffectiveAclIndex(
            policies=[{"id": "policy-1", "revision_number": 2}],
            address_sets=[{
                "id": "aset-1",
                "revision_number": 7,
                "members": ["10.10.20.0/24"],
            }],
            rules=[{
                "id": "rule-1",
                "policy_id": "policy-1",
                "direction": "egress",
                "priority": 100,
                "action": "deny",
                "dst_address_set_id": "aset-1",
                "revision_number": 5,
            }],
            bindings=[{
                "id": "binding-1",
                "policy_id": "policy-1",
                "target_type": "port",
                "target_id": PORT_ID,
                "revision_number": 4,
            }],
        )

        newer = index.compare_revision_for_port(port(), 6, snapshot())
        same = index.compare_revision_for_port(port(), 7, snapshot())
        older = index.compare_revision_for_port(port(), 8, snapshot())

        self.assertEqual(REVISION_NEWER, newer["status"])
        self.assertEqual(7, newer["current_revision"])
        self.assertEqual(6, newer["projected_revision"])
        self.assertEqual(REVISION_SAME, same["status"])
        self.assertEqual(REVISION_OLDER, older["status"])

    def test_revision_compare_is_unknown_when_no_effective_revision_exists(self):
        index = EffectiveAclIndex()

        result = index.compare_revision_for_port(port(), 1, snapshot())

        self.assertEqual(REVISION_UNKNOWN, result["status"])
        self.assertEqual(None, result["current_revision"])
        self.assertEqual(1, result["projected_revision"])

    def test_revision_compare_is_unknown_when_projected_revision_is_invalid(self):
        index = EffectiveAclIndex(
            policies=[{"id": "policy-1", "revision_number": 2}],
            bindings=[{
                "id": "binding-1",
                "policy_id": "policy-1",
                "target_type": "port",
                "target_id": PORT_ID,
                "revision_number": 4,
            }],
        )

        result = index.compare_revision_for_port(port(), "bad", snapshot())

        self.assertEqual(REVISION_UNKNOWN, result["status"])
        self.assertEqual(4, result["current_revision"])
        self.assertEqual(None, result["projected_revision"])

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
        self.assertIn("invalid_acl_priority:rule-1:bad", result["reason"])
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
        self.assertIn("destination ports require tcp or udp", result["reason"])
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
