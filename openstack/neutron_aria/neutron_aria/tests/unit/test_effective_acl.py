from __future__ import absolute_import

import unittest

from neutron_aria.agent import effective_acl as effective_acl_module
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


def acl_rules(count):
    return [acl_rule("rule-%s" % index, index) for index in range(count)]


def selector_members(count):
    return ["10.%s.%s.%s/32" % (
        (index >> 16) & 0xff,
        (index >> 8) & 0xff,
        index & 0xff,
    ) for index in range(count)]


def compiled_acl_rule(rule_id, priority, **overrides):
    rule = {
        "id": rule_id,
        "direction": "egress",
        "priority": priority,
        "action": "deny",
        "protocol": "tcp",
        "src_cidrs": [],
        "dst_cidrs": [],
        "dst_port_min": None,
        "dst_port_max": None,
    }
    rule.update(overrides)
    return rule


def effective_acl_with_address_set(members):
    return EffectiveAclIndex(
        policies=[{"id": "policy-1", "default_action": "allow"}],
        address_sets=[{"id": "aset-1", "members": members}],
        rules=[acl_rule("aset-rule", 10, src_address_set_id="aset-1")],
        bindings=[{
            "id": "binding-1",
            "policy_id": "policy-1",
            "target_type": "port",
            "target_id": PORT_ID,
        }],
    ).effective_for_port(port(), snapshot())


class CountingEffectiveAclIndex(EffectiveAclIndex):
    def __init__(self, *args, **kwargs):
        self.compile_count = 0
        super(CountingEffectiveAclIndex, self).__init__(*args, **kwargs)

    def _compile_rules_uncached(self, policy):
        self.compile_count += 1
        return super(CountingEffectiveAclIndex, self)._compile_rules_uncached(policy)


class EffectiveAclTestCase(unittest.TestCase):
    def test_unsupported_policy_uses_shared_contract_reason(self):
        index = EffectiveAclIndex(
            policies=[{"id": "policy-1", "default_action": "deny"}],
            bindings=[{
                "id": "binding-1",
                "policy_id": "policy-1",
                "target_type": "port",
                "target_id": PORT_ID,
            }],
        )

        result = index.effective_for_port(port(), snapshot())

        self.assertEqual(ACL_DEGRADED, result["status"])
        self.assertEqual("bypass", result["effective_action"])
        self.assertEqual(
            "unsupported_policy:default_action must be allow",
            result["reason"],
        )

    def test_unsupported_source_port_uses_shared_rule_reason(self):
        result = effective_acl([
            acl_rule("src-port", 10, src_port_min=80, src_port_max=80),
        ])

        self.assertEqual(ACL_DEGRADED, result["status"])
        self.assertEqual("bypass", result["effective_action"])
        self.assertEqual(
            "unsupported_rule:src-port:source port matching is unsupported",
            result["reason"],
        )

    def test_shared_large_selector_is_interned_once_for_1000_rules(self):
        shared = tuple(selector_members(2048))
        rules = [compiled_acl_rule(
            "shared-%s" % index,
            index,
            protocol="tcp" if index % 2 else "udp",
            src_cidrs=shared,
        ) for index in range(1000)]

        validation = effective_acl_module._acl_validation_view(rules)

        self.assertEqual(2, len(validation["src_selectors"]))
        self.assertEqual((), validation["src_selectors"][0])
        self.assertEqual(tuple(shared), validation["src_selectors"][1])
        self.assertEqual(
            {1},
            set(rule["src_selector_id"] for rule in validation["rules"]),
        )
        self.assertTrue(all(
            "src_cidrs" not in rule and "dst_cidrs" not in rule
            for rule in validation["rules"]
        ))

    def test_1000_disjoint_selectors_pass_without_pair_relation_cache(self):
        rules = [compiled_acl_rule(
            "disjoint-%s" % index,
            index,
            protocol="tcp" if index % 2 else "udp",
            src_cidrs=["10.%s.%s.%s/32" % (
                (index >> 16) & 0xff,
                (index >> 8) & 0xff,
                index & 0xff,
            )],
        ) for index in range(1000)]

        validation = effective_acl_module._acl_validation_view(rules)

        self.assertEqual(1001, len(validation["src_selectors"]))
        self.assertEqual(None, effective_acl_module._acl_overlap_reason(validation))
        self.assertEqual(
            {"rules", "src_selectors", "dst_selectors"},
            set(validation),
        )

    def test_cross_selector_nesting_keeps_stable_overlap_reason(self):
        validation = effective_acl_module._acl_validation_view([
            compiled_acl_rule("broad", 10, src_cidrs=["10.0.0.0/8"]),
            compiled_acl_rule(
                "narrow", 20, protocol="udp",
                src_cidrs=["10.1.0.0/16"],
            ),
        ])

        self.assertEqual(
            "unsupported_acl_cidr_overlap:src:broad:10:narrow:20",
            effective_acl_module._acl_overlap_reason(validation),
        )

    def test_overlap_reason_uses_earliest_rule_pair_not_cidr_address_order(self):
        validation = effective_acl_module._acl_validation_view([
            compiled_acl_rule(
                "first", 10,
                src_cidrs=["10.0.0.0/8", "192.0.2.0/24"],
            ),
            compiled_acl_rule(
                "second", 20, protocol="udp",
                src_cidrs=["192.0.2.128/25"],
            ),
            compiled_acl_rule(
                "third", 30, protocol="icmp",
                src_cidrs=["10.1.0.0/16"],
            ),
        ])

        self.assertEqual(
            "unsupported_acl_cidr_overlap:src:first:10:second:20",
            effective_acl_module._acl_overlap_reason(validation),
        )

    def test_earlier_rule_pair_destination_overlap_beats_later_source(self):
        validation = effective_acl_module._acl_validation_view([
            compiled_acl_rule(
                "first", 10,
                src_cidrs=["10.0.0.0/8"],
                dst_cidrs=["192.0.2.0/24"],
            ),
            compiled_acl_rule(
                "second", 20, protocol="udp",
                dst_cidrs=["192.0.2.128/25"],
            ),
            compiled_acl_rule(
                "third", 30, protocol="icmp",
                src_cidrs=["10.1.0.0/16"],
            ),
        ])

        self.assertEqual(
            "unsupported_acl_cidr_overlap:dst:first:10:second:20",
            effective_acl_module._acl_overlap_reason(validation),
        )

    def test_earlier_priority_pair_beats_later_cidr_pair(self):
        validation = effective_acl_module._acl_validation_view([
            compiled_acl_rule(
                "first", 10, protocol="udp", action="allow",
                src_cidrs=["10.0.0.0/32"],
            ),
            compiled_acl_rule(
                "second", 20, protocol=None, action="deny",
                dst_cidrs=["192.0.2.0/24"],
            ),
            compiled_acl_rule(
                "third", 30, protocol="tcp", action="allow",
                src_cidrs=["10.0.0.0/31"],
            ),
        ])

        self.assertEqual(
            "unsupported_acl_priority_overlap:first:10:second:20",
            effective_acl_module._acl_overlap_reason(validation),
        )

    def test_same_rule_pair_source_cidr_overlap_beats_destination(self):
        validation = effective_acl_module._acl_validation_view([
            compiled_acl_rule(
                "first", 10,
                src_cidrs=["10.0.0.0/24"],
                dst_cidrs=["192.0.2.0/24"],
            ),
            compiled_acl_rule(
                "second", 20, protocol="udp",
                src_cidrs=["10.0.0.128/25"],
                dst_cidrs=["192.0.2.128/25"],
            ),
        ])

        self.assertEqual(
            "unsupported_acl_cidr_overlap:src:first:10:second:20",
            effective_acl_module._acl_overlap_reason(validation),
        )

    def test_selector_sweep_reactivates_multi_gap_selectors_stably(self):
        selectors = (
            (),
            ("0.0.0.0/32", "0.0.0.4/32"),
            ("0.0.0.0/31", "0.0.0.4/31"),
        )

        self.assertEqual(
            (0, 1),
            effective_acl_module._selector_best_overlap(
                selectors, (None, 1, 0),
            ),
        )

    def test_selector_sweep_returns_only_best_rule_pair_rank(self):
        selectors = (
            (),
            ("10.0.0.0/8", "192.0.2.0/24"),
            ("192.0.2.128/25",),
            ("10.1.0.0/16",),
        )

        self.assertEqual(
            (0, 1),
            effective_acl_module._selector_best_overlap(
                selectors, (None, 0, 1, 2),
            ),
        )

    def test_selector_sweep_repeated_overlap_keeps_one_best_candidate(self):
        selectors = [()]
        for index in range(1000):
            selectors.append((
                "10.0.0.0/8",
                "10.%s.%s.%s/32" % (
                    (index >> 16) & 0xff,
                    (index >> 8) & 0xff,
                    index & 0xff,
                ),
            ))

        self.assertEqual(
            (0, 1),
            effective_acl_module._selector_best_overlap(
                tuple(selectors), tuple([None] + list(range(1000))),
            ),
        )

    def test_nested_members_inside_shared_selector_remain_valid(self):
        shared = ["10.0.0.0/8", "10.1.0.0/16"]
        validation = effective_acl_module._acl_validation_view([
            compiled_acl_rule("tcp", 10, src_cidrs=shared),
            compiled_acl_rule("udp", 20, protocol="udp", src_cidrs=shared),
        ])

        self.assertEqual(2, len(validation["src_selectors"]))
        self.assertEqual(
            [1, 1],
            [rule["src_selector_id"] for rule in validation["rules"]],
        )
        self.assertEqual(None, effective_acl_module._acl_overlap_reason(validation))

    def test_source_and_destination_selector_id_spaces_are_independent(self):
        shared_text = ["192.0.2.0/24"]
        validation = effective_acl_module._acl_validation_view([
            compiled_acl_rule("source", 10, src_cidrs=shared_text),
            compiled_acl_rule(
                "destination", 20, protocol="udp", dst_cidrs=shared_text,
            ),
        ])

        self.assertEqual(validation["src_selectors"], validation["dst_selectors"])
        self.assertIsNot(validation["src_selectors"], validation["dst_selectors"])
        self.assertEqual(1, validation["rules"][0]["src_selector_id"])
        self.assertEqual(0, validation["rules"][0]["dst_selector_id"])
        self.assertEqual(0, validation["rules"][1]["src_selector_id"])
        self.assertEqual(1, validation["rules"][1]["dst_selector_id"])

    def test_public_dto_stays_id_free_and_defensively_copied(self):
        index = EffectiveAclIndex(
            policies=[{"id": "policy-1", "default_action": "allow"}],
            address_sets=[{"id": "aset-1", "members": ["10.1.2.3/24"]}],
            rules=[acl_rule("cached", 10, src_address_set_id="aset-1")],
            bindings=[{
                "id": "binding-1",
                "policy_id": "policy-1",
                "target_type": "network",
                "target_id": NETWORK_ID,
            }],
        )

        first = index.effective_for_port(port("port-1", NETWORK_ID), snapshot())
        first["rules"][0]["src_cidrs"].append("192.0.2.0/24")
        second = index.effective_for_port(port("port-2", NETWORK_ID), snapshot())

        self.assertNotIn("src_selectors", second)
        self.assertNotIn("dst_selectors", second)
        self.assertNotIn("src_selector_id", second["rules"][0])
        self.assertNotIn("dst_selector_id", second["rules"][0])
        self.assertEqual(["10.1.2.0/24"], second["rules"][0]["src_cidrs"])

    def test_cidr_whitespace_is_canonicalized_in_snapshot(self):
        result = effective_acl([
            acl_rule("spaced", 10, src_cidr=" 10.1.2.3/24 "),
        ])

        self.assertEqual(ACL_READY, result["status"])
        self.assertEqual(["10.1.2.0/24"], result["rules"][0]["src_cidrs"])

    def test_address_set_member_whitespace_uses_same_canonicalizer(self):
        index = EffectiveAclIndex(
            policies=[{"id": "policy-1", "default_action": "allow"}],
            address_sets=[{"id": "aset-1", "members": [" 10.2.3.4/24 "]}],
            rules=[acl_rule("aset", 10, src_address_set_id="aset-1")],
            bindings=[{
                "id": "binding-1",
                "policy_id": "policy-1",
                "target_type": "port",
                "target_id": PORT_ID,
            }],
        )

        result = index.effective_for_port(port(), snapshot())

        self.assertEqual(ACL_READY, result["status"])
        self.assertEqual(["10.2.3.0/24"], result["rules"][0]["src_cidrs"])

    def test_noncanonical_ipv4_forms_degrade_without_exception(self):
        for rule_id, cidr in (
                ("short", "10.1/16"),
                ("leading-zero", "010.1.2.3/24")):
            result = effective_acl([acl_rule(rule_id, 10, src_cidr=cidr)])
            self.assertEqual(ACL_DEGRADED, result["status"])
            self.assertEqual("bypass", result["effective_action"])
            self.assertIn(
                "invalid_acl_ipv4_cidr:src:%s:" % rule_id,
                result["reason"],
            )

    def test_rule_runtime_limit_accepts_1000_and_bypasses_1001(self):
        accepted = effective_acl(acl_rules(1000))
        rejected = effective_acl(acl_rules(1001))

        self.assertEqual(ACL_READY, accepted["status"])
        self.assertEqual(ACL_DEGRADED, rejected["status"])
        self.assertEqual("acl_rule_limit_exceeded:1001:1000", rejected["reason"])

    def test_selector_runtime_limit_accepts_2048_and_bypasses_2049(self):
        accepted = effective_acl_with_address_set(selector_members(2048))
        rejected = effective_acl_with_address_set(selector_members(2049))

        self.assertEqual(ACL_READY, accepted["status"])
        self.assertEqual(ACL_DEGRADED, rejected["status"])
        self.assertEqual(
            "acl_selector_member_limit_exceeded:src:aset-rule:2049:2048",
            rejected["reason"],
        )

    def test_policy_compile_cache_reuses_ready_result(self):
        index = CountingEffectiveAclIndex(
            policies=[{"id": "policy-1", "default_action": "allow"}],
            rules=[acl_rule("cached", 10, src_cidr="10.1.2.3/24")],
            bindings=[{
                "id": "binding-1",
                "policy_id": "policy-1",
                "target_type": "network",
                "target_id": NETWORK_ID,
            }],
        )

        first = index.effective_for_port(port("port-1", NETWORK_ID), snapshot())
        first["rules"][0]["src_cidrs"].append("192.0.2.0/24")
        second = index.effective_for_port(port("port-2", NETWORK_ID), snapshot())

        self.assertEqual(1, index.compile_count)
        self.assertEqual(["10.1.2.0/24"], second["rules"][0]["src_cidrs"])

    def test_policy_compile_cache_reuses_degraded_result(self):
        index = CountingEffectiveAclIndex(
            policies=[{"id": "policy-1", "default_action": "allow"}],
            rules=[acl_rule("invalid", "not-an-integer")],
            bindings=[{
                "id": "binding-1",
                "policy_id": "policy-1",
                "target_type": "network",
                "target_id": NETWORK_ID,
            }],
        )

        first = index.effective_for_port(port("port-1", NETWORK_ID), snapshot())
        first["reason"] = "mutated"
        first["rules"].append({"id": "mutated"})
        second = index.effective_for_port(port("port-2", NETWORK_ID), snapshot())

        self.assertEqual(1, index.compile_count)
        self.assertEqual(ACL_DEGRADED, second["status"])
        self.assertIn("invalid_acl_priority:invalid:not-an-integer", second["reason"])
        self.assertEqual([], second["rules"])

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

    def test_default_deny_degrades_before_datapath_submit(self):
        index = EffectiveAclIndex(
            policies=[{"id": "policy-1", "default_action": "deny"}],
            bindings=[
                {"id": "b1", "policy_id": "policy-1", "target_type": "port", "target_id": PORT_ID},
            ],
        )

        result = index.effective_for_port(port(), snapshot())

        self.assertEqual(ACL_DEGRADED, result["status"])
        self.assertFalse(result["enabled"])
        self.assertIn(
            "unsupported_policy:default_action must be allow",
            result["reason"],
        )
        self.assertEqual("bypass", result["effective_action"])

    def test_unsupported_rule_fields_degrade_before_datapath_submit(self):
        index = EffectiveAclIndex(
            policies=[{"id": "policy-1", "default_action": "allow"}],
            rules=[
                {
                    "id": "src-port",
                    "policy_id": "policy-1",
                    "direction": "ingress",
                    "priority": 100,
                    "action": "drop",
                    "protocol": "tcp",
                    "src_port_min": 1024,
                },
                {
                    "id": "ipv6-cidr",
                    "policy_id": "policy-1",
                    "direction": "ingress",
                    "priority": 101,
                    "action": "drop",
                    "protocol": "tcp",
                    "src_cidr": "2001:db8::/64",
                },
                {
                    "id": "bad-protocol",
                    "policy_id": "policy-1",
                    "direction": "ingress",
                    "priority": 102,
                    "action": "drop",
                    "protocol": "gre",
                },
            ],
            bindings=[
                {"id": "b1", "policy_id": "policy-1", "target_type": "port", "target_id": PORT_ID},
            ],
        )

        result = index.effective_for_port(port(), snapshot())

        self.assertEqual(ACL_DEGRADED, result["status"])
        self.assertFalse(result["enabled"])
        self.assertIn("unsupported_rule:src-port", result["reason"])
        self.assertIn("invalid_acl_ipv4_cidr:src:ipv6-cidr", result["reason"])
        self.assertIn("unsupported_rule:bad-protocol", result["reason"])
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
