import argparse
import io
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

        def get_client(self):
            return self.app.client_manager.neutron

        def format_output_data(self, data):
            return data

    class StubListCommand(StubCommand):
        def get_parser(self, prog_name):
            parser = argparse.ArgumentParser(prog=prog_name)
            parser.add_argument("--request-format", default="json")
            if self.pagination_support:
                parser.add_argument("--page-size", type=int)
            if self.sorting_support:
                parser.add_argument("--sort-key", action="append", default=[])
                parser.add_argument("--sort-dir", action="append", default=[])
            self.add_known_arguments(parser)
            return parser

        def add_known_arguments(self, parser):
            return None

    class StubShowCommand(StubCommand):
        def get_parser(self, prog_name):
            parser = argparse.ArgumentParser(prog=prog_name)
            parser.add_argument("--request-format", default="json")
            parser.add_argument("id")
            return parser

    extension.ClientExtensionList = StubListCommand
    extension.ClientExtensionShow = StubShowCommand
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


class FakeClientManager(object):
    def __init__(self, neutron):
        self.neutron = neutron


class FakeApp(object):
    def __init__(self, neutron):
        self.client_manager = FakeClientManager(neutron)
        self.stdout = io.StringIO()


class AriaAclCliTest(unittest.TestCase):
    def test_list_parser_forwards_native_page_and_sort_options(self):
        class FakeClient(object):
            def __init__(self):
                self.calls = []

            def list_ext(self, collection, path, retrieve_all, **kwargs):
                self.calls.append((collection, path, retrieve_all, kwargs))
                return {"aria_acl_policies": []}

        client = FakeClient()
        app = FakeApp(client)
        command = aria_acl.AriaAclPolicyList(app, None)
        parser = command.get_parser("aria-acl-policy-list")
        parsed_args = parser.parse_args([
            "--page-size", "25",
            "--sort-key", "name",
            "--sort-dir", "desc",
        ])

        command.retrieve_list(parsed_args)

        self.assertTrue(command.pagination_support)
        self.assertTrue(command.sorting_support)
        self.assertEqual(
            ("aria_acl_policies", "/aria-acl-policies", True, {
                "limit": 25,
                "sort_key": ["name"],
                "sort_dir": ["desc"],
            }),
            client.calls[0],
        )

    def test_status_show_forwards_derived_id_unchanged(self):
        derived_id = "aria-status-v1.cG9ydC0xAG9zdGFjazI"

        class FakeClient(object):
            def __init__(self):
                self.calls = []

            def show_ext(self, path, resource_id):
                self.calls.append((path, resource_id))
                return {"aria_acl_port_status": {"id": resource_id}}

        client = FakeClient()
        app = FakeApp(client)
        command = aria_acl.AriaAclPortStatusShow(app, None)
        parsed_args = command.get_parser("aria-acl-port-status-show").parse_args([
            derived_id,
        ])

        command.execute(parsed_args)

        self.assertEqual(
            ("/aria-acl-port-statuses/%s", derived_id),
            client.calls[0],
        )

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

    def test_address_set_update_requires_explicit_member_replacement(self):
        command = aria_acl.AriaAclAddressSetUpdate(None, None)
        parser = argparse.ArgumentParser()
        command.add_known_arguments(parser)
        option_strings = set(
            option
            for action in parser._actions
            for option in action.option_strings
        )
        self.assertNotIn("--member", option_strings)
        self.assertIn("--replace-member", option_strings)

        args = parser.parse_args([
            "--replace-member", "10.0.0.0/24",
            "--replace-member", "10.0.1.1/32",
        ])
        body = command.args2body(args)["aria_acl_address_set"]
        self.assertEqual(
            ["10.0.0.0/24", "10.0.1.1/32"],
            body["members"],
        )


if __name__ == "__main__":
    unittest.main()
