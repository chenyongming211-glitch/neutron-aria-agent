from __future__ import absolute_import

import unittest

from neutron_aria import acl_contract
from neutron_aria.acl_contract import AclContractError
from neutron_aria.acl_contract import port_contract_eligibility
from neutron_aria.acl_contract import validate_address_set_reference
from neutron_aria.acl_contract import validate_policy
from neutron_aria.acl_contract import validate_rule


class AclContractTestCase(unittest.TestCase):
    def test_policy_rejects_default_deny(self):
        with self.assertRaises(AclContractError):
            validate_policy({"default_action": "deny"})

    def test_rule_accepts_priority_zero(self):
        validate_rule({
            "direction": "ingress",
            "priority": 0,
            "action": "allow",
        })

    def test_rule_rejects_source_ports(self):
        with self.assertRaises(AclContractError):
            validate_rule({
                "direction": "ingress",
                "priority": 1,
                "action": "allow",
                "src_port_min": 80,
            })

    def test_rule_accepts_ipv6_and_resolves_icmp_by_family(self):
        validate_rule({
            "direction": "ingress", "priority": 1, "action": "allow",
            "ethertype": "IPv6", "protocol": "icmp",
            "src_cidr": "2001:db8::7/64",
        })
        self.assertEqual(
            "2001:db8::/64",
            acl_contract.normalize_cidr(" 2001:db8::7/64 ", "IPv6"),
        )
        self.assertEqual(1, acl_contract.protocol_number("icmp", "IPv4"))
        self.assertEqual(58, acl_contract.protocol_number("icmp", "IPv6"))
        self.assertEqual(58, acl_contract.protocol_number("icmpv6", "IPv6"))

    def test_rule_rejects_cross_family_and_mapped_ipv6(self):
        for ethertype, cidr in (
            ("IPv4", "2001:db8::/64"),
            ("IPv6", "192.0.2.0/24"),
            ("IPv6", "::ffff:192.0.2.1/128"),
            ("IPv6", "fe80::1%eth0/128"),
        ):
            with self.assertRaises(AclContractError):
                acl_contract.normalize_cidr(cidr, ethertype)

    def test_address_set_family_is_single_and_computed(self):
        self.assertEqual("IPv4", acl_contract.address_set_ethertype(["10.0.0.1/24"]))
        self.assertEqual("IPv6", acl_contract.address_set_ethertype(["2001:db8::1/64"]))
        self.assertIsNone(acl_contract.address_set_ethertype([]))
        with self.assertRaises(AclContractError):
            acl_contract.address_set_ethertype(["10.0.0.0/24", "2001:db8::/64"])

    def test_rule_validates_destination_port_contract(self):
        validate_rule({
            "direction": "egress",
            "priority": 1,
            "action": "deny",
            "protocol": "tcp",
            "dst_port_min": 80,
            "dst_port_max": 443,
        })
        for values in (
            {
                "direction": "egress",
                "priority": 1,
                "action": "deny",
                "protocol": "icmp",
                "dst_port_min": 80,
            },
            {
                "direction": "egress",
                "priority": 1,
                "action": "deny",
                "protocol": "tcp",
                "dst_port_min": 443,
                "dst_port_max": 80,
            },
        ):
            with self.assertRaises(AclContractError):
                validate_rule(values)

    def test_rule_validates_protocol_and_ipv4_cidrs(self):
        validate_rule({
            "direction": "ingress",
            "priority": 1,
            "action": "allow",
            "protocol": "17",
            "src_cidr": "10.0.0.0/24",
        })
        for values in (
            {
                "direction": "ingress",
                "priority": 1,
                "action": "allow",
                "protocol": "bogus",
            },
            {
                "direction": "ingress",
                "priority": 1,
                "action": "allow",
                "src_cidr": "2001:db8::/64",
            },
        ):
            with self.assertRaises(AclContractError):
                validate_rule(values)

    def test_rule_rejects_non_strict_ipv4_cidr_spellings(self):
        for field in ("src_cidr", "dst_cidr"):
            for cidr in (
                "10.1/16",
                "010.1.2.0/24",
                "10.1.2.0 /24",
                "10.1.2.0/ 24",
                "10.1.2.0/33",
                "2001:db8::/64",
            ):
                values = {
                    "direction": "ingress",
                    "priority": 1,
                    "action": "allow",
                    field: cidr,
                }
                with self.assertRaises(AclContractError):
                    validate_rule(values)

    def test_ipv4_cidr_normalization_trims_outer_space_and_networks_host_bits(self):
        self.assertTrue(
            hasattr(acl_contract, "normalize_ipv4_cidr"),
            "strict canonical CIDR API is missing",
        )
        self.assertEqual(
            "10.1.2.0/24",
            acl_contract.normalize_ipv4_cidr(" 10.1.2.3/24 "),
        )
        self.assertEqual(
            "0.0.0.0/0",
            acl_contract.normalize_ipv4_cidr("255.255.255.255/0"),
        )

    def test_address_set_reference_requires_enabled_single_family_members(self):
        validate_address_set_reference({
            "enabled": True,
            "members": ["10.0.0.1/32"],
        })
        for values in (
            {"enabled": False, "members": ["10.0.0.1/32"]},
            {"enabled": True, "members": []},
            {
                "enabled": True,
                "members": ["10.0.0.1/32", "2001:db8::1/128"],
            },
        ):
            with self.assertRaises(AclContractError):
                validate_address_set_reference(values)

    def test_port_contract_eligibility_matches_neutron_port_fields(self):
        self.assertEqual(
            (True, "pending_local_validation"),
            port_contract_eligibility({
                "device_owner": "compute:nova",
                "binding:vif_type": "ovs",
                "binding:vnic_type": "normal",
            }),
        )
        eligible, reason = port_contract_eligibility({
            "device_owner": "network:dhcp",
            "binding:vif_type": "ovs",
            "binding:vnic_type": "normal",
        })
        self.assertFalse(eligible)
        self.assertIn("not_applicable_device_owner", reason)


if __name__ == "__main__":
    unittest.main()
