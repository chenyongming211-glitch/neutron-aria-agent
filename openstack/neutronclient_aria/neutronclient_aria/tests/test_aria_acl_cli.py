import argparse
import sys
import types
import unittest

try:
    from neutronclient_aria.v2_0 import aria_acl
except ImportError:
    neutronclient = types.ModuleType("neutronclient")
    common = types.ModuleType("neutronclient.common")
    extension = types.ModuleType("neutronclient.common.extension")

    class StubCommand(object):
        def __init__(self, *args, **kwargs):
            self.app = args[0] if args else None

    extension.ClientExtensionList = StubCommand
    extension.ClientExtensionShow = StubCommand
    extension.ClientExtensionDelete = StubCommand
    extension.ClientExtensionCreate = StubCommand
    extension.ClientExtensionUpdate = StubCommand
    common.extension = extension
    neutronclient.common = common
    sys.modules["neutronclient"] = neutronclient
    sys.modules["neutronclient.common"] = common
    sys.modules["neutronclient.common.extension"] = extension
    from neutronclient_aria.v2_0 import aria_acl


class FakeParsedArgs(object):
    request_format = "json"
    tenant_id = None
    project_id = None
    enabled = None


class AriaAclCliTest(unittest.TestCase):
    def test_policy_parser_rejects_default_deny(self):
        parser = argparse.ArgumentParser()
        aria_acl.AriaAclPolicyCreate(None, None).add_known_arguments(parser)
        with self.assertRaises(SystemExit):
            parser.parse_args(["--default-action", "deny"])

    def test_rule_parser_rejects_ipv6_source_ports_and_unknown_protocol(self):
        command = aria_acl.AriaAclRuleCreate(None, None)
        for args in (
            ["--policy-id", "p1", "--direction", "ingress", "--priority", "1", "--action", "allow", "--ethertype", "IPv6"],
            ["--policy-id", "p1", "--direction", "ingress", "--priority", "1", "--action", "allow", "--src-port-min", "80"],
            ["--policy-id", "p1", "--direction", "ingress", "--priority", "1", "--action", "allow", "--protocol", "bogus"],
        ):
            parser = argparse.ArgumentParser()
            command.add_known_arguments(parser)
            with self.assertRaises(SystemExit):
                parser.parse_args(args)

    def test_rule_parser_accepts_priority_zero_and_ipv4_destination_port(self):
        parser = argparse.ArgumentParser()
        aria_acl.AriaAclRuleCreate(None, None).add_known_arguments(parser)
        args = parser.parse_args([
            "--policy-id", "p1",
            "--direction", "ingress",
            "--priority", "0",
            "--action", "allow",
            "--protocol", "tcp",
            "--ethertype", "IPv4",
            "--dst-port", "443",
        ])
        body = aria_acl.AriaAclRuleCreate(None, None).args2body(args)["aria_acl_rule"]
        self.assertEqual(0, body["priority"])
        self.assertEqual(443, body["dst_port_min"])
        self.assertEqual(443, body["dst_port_max"])

    def test_policy_create_body(self):
        args = FakeParsedArgs()
        args.name = "web"
        args.default_action = "allow"
        args.stateful = "true"
        command = aria_acl.AriaAclPolicyCreate(None, None)

        self.assertEqual(
            {
                "aria_acl_policy": {
                    "name": "web",
                    "default_action": "allow",
                    "stateful": True,
                },
            },
            command.args2body(args),
        )

    def test_rule_create_dst_port_expansion(self):
        args = FakeParsedArgs()
        args.policy_id = "policy-1"
        args.direction = "egress"
        args.priority = 100
        args.action = "drop"
        args.protocol = "tcp"
        args.src_cidr = None
        args.dst_cidr = "10.0.0.1/32"
        args.src_address_set_id = None
        args.dst_address_set_id = None
        args.src_port_min = None
        args.src_port_max = None
        args.dst_port_min = None
        args.dst_port_max = None
        args.dst_port = 3306
        args.ethertype = None
        command = aria_acl.AriaAclRuleCreate(None, None)

        body = command.args2body(args)["aria_acl_rule"]

        self.assertEqual(3306, body["dst_port_min"])
        self.assertEqual(3306, body["dst_port_max"])
        self.assertEqual("policy-1", body["policy_id"])

    def test_binding_create_port_body(self):
        args = FakeParsedArgs()
        args.policy_id = "policy-1"
        args.port = "port-1"
        args.network = None
        command = aria_acl.AriaAclBindingCreate(None, None)

        self.assertEqual(
            {
                "aria_acl_binding": {
                    "policy_id": "policy-1",
                    "target_type": "port",
                    "target_id": "port-1",
                },
            },
            command.args2body(args),
        )

    def test_address_set_create_body(self):
        args = FakeParsedArgs()
        args.name = "db"
        args.members = ["10.0.0.0/24", "10.0.1.1/32"]
        command = aria_acl.AriaAclAddressSetCreate(None, None)

        self.assertEqual(
            {
                "aria_acl_address_set": {
                    "name": "db",
                    "members": ["10.0.0.0/24", "10.0.1.1/32"],
                },
            },
            command.args2body(args),
        )


if __name__ == "__main__":
    unittest.main()
