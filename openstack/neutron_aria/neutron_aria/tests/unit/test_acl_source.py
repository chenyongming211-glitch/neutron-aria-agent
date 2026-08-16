from __future__ import absolute_import

import json
import os
import tempfile
import unittest

from neutron_aria.agent.acl_source import AclSourceError
from neutron_aria.agent.acl_source import DisabledAclSource
from neutron_aria.agent.acl_source import FixtureAclSource
from neutron_aria.agent.acl_source import NeutronAclSource
from neutron_aria.agent.acl_source import build_acl_index
from neutron_aria.agent.acl_source import build_acl_source
from neutron_aria.agent.config import AgentConfig
from neutron_aria.agent.neutron_client import AriaAclRestClient
from neutron_aria.agent.neutron_client import NeutronClientFactoryError
from neutron_aria.agent.neutron_client import build_port_source
from neutron_aria.db.aria_acl.query import encode_port_status_id


class AclSourceTestCase(unittest.TestCase):
    def test_neutron_acl_factory_receives_acl_page_size_only(self):
        from neutron_aria.agent import neutron_client as neutron_client_module

        calls = []
        original_acl_factory = neutron_client_module.build_aria_acl_client_from_env
        original_neutron_factory = neutron_client_module.build_neutronclient_from_env

        class FakeAclClient(object):
            pass

        class FakeNeutronClient(object):
            pass

        def fake_acl_factory(env=None, page_size=None):
            calls.append(("acl", page_size))
            return FakeAclClient()

        def fake_neutron_factory(env=None):
            calls.append(("port", None))
            return FakeNeutronClient()

        neutron_client_module.build_aria_acl_client_from_env = fake_acl_factory
        neutron_client_module.build_neutronclient_from_env = fake_neutron_factory
        try:
            config = AgentConfig(
                acl_source="neutron",
                acl_page_size=25,
                port_source="neutronclient",
                port_page_size=50,
            )
            acl_source = build_acl_source(config)
            port_source = build_port_source(config, "compute-1")
        finally:
            neutron_client_module.build_aria_acl_client_from_env = original_acl_factory
            neutron_client_module.build_neutronclient_from_env = original_neutron_factory

        self.assertIsInstance(acl_source.neutron_client, FakeAclClient)
        self.assertEqual(25, calls[0][1])
        self.assertEqual(50, port_source.page_size)

    def test_disabled_source_returns_no_index(self):
        source = build_acl_source(AgentConfig(acl_source="disabled"))

        self.assertIsInstance(source, DisabledAclSource)
        self.assertEqual(None, source.load_index())

    def test_fixture_source_loads_effective_index(self):
        fd, path = tempfile.mkstemp()
        try:
            payload = {
                "policies": [{"id": "policy-1", "default_action": "allow"}],
                "rules": [{
                    "id": "rule-1",
                    "policy_id": "policy-1",
                    "direction": "ingress",
                    "priority": 100,
                    "action": "drop",
                    "protocol": "icmp",
                    "src_cidr": "192.0.2.2/32",
                }],
                "bindings": [{
                    "id": "binding-1",
                    "policy_id": "policy-1",
                    "target_type": "port",
                    "target_id": "port-1",
                }],
            }
            os.write(fd, json.dumps(payload).encode("utf-8"))
            os.close(fd)
            fd = None

            source = build_acl_source(AgentConfig(acl_fixture_path=path))
            index = source.load_index()
            result = index.effective_for_port({"id": "port-1"}, {"eligible": True})

            self.assertIsInstance(source, FixtureAclSource)
            self.assertTrue(result["enabled"])
            self.assertEqual("policy-1", result["policy_id"])
            self.assertEqual("rule-1", result["rules"][0]["id"])
        finally:
            if fd is not None:
                os.close(fd)
            os.unlink(path)

    def test_fixture_source_passes_ipv6_gate_to_effective_index(self):
        fd, path = tempfile.mkstemp()
        try:
            payload = {
                "policies": [{"id": "policy-1", "default_action": "allow"}],
                "rules": [{
                    "id": "ipv6-rule",
                    "policy_id": "policy-1",
                    "direction": "ingress",
                    "priority": 100,
                    "action": "drop",
                    "ethertype": "IPv6",
                    "protocol": "icmp",
                    "src_cidr": "2001:db8::7/64",
                }],
                "bindings": [{
                    "id": "binding-1",
                    "policy_id": "policy-1",
                    "target_type": "port",
                    "target_id": "port-1",
                }],
            }
            os.write(fd, json.dumps(payload).encode("utf-8"))
            os.close(fd)
            fd = None

            result = build_acl_source(AgentConfig(
                acl_fixture_path=path,
                ipv6_acl_enabled=True,
            )).load_index().effective_for_port({"id": "port-1"}, {"eligible": True})

            self.assertFalse(result["enabled"])
            self.assertEqual("ipv6_acl_not_implemented", result["reason"])
            self.assertEqual([], result["rules"])
        finally:
            if fd is not None:
                os.close(fd)
            os.unlink(path)

    def test_build_acl_index_keeps_fixture_compatibility(self):
        fd, path = tempfile.mkstemp()
        try:
            os.write(fd, b'{"policies": [], "rules": [], "bindings": []}')
            os.close(fd)
            fd = None

            self.assertIsNotNone(build_acl_index(AgentConfig(acl_fixture_path=path)))
        finally:
            if fd is not None:
                os.close(fd)
            os.unlink(path)

    def test_fixture_source_rejects_invalid_collection_shape(self):
        fd, path = tempfile.mkstemp()
        try:
            os.write(fd, b'{"policies": {"id": "policy-1"}}')
            os.close(fd)
            fd = None

            self.assertRaises(
                AclSourceError,
                build_acl_index,
                AgentConfig(acl_fixture_path=path),
            )
        finally:
            if fd is not None:
                os.close(fd)
            os.unlink(path)

    def test_neutron_source_requires_aria_acl_capable_client(self):
        self.assertRaises(
            AclSourceError,
            build_acl_source,
            AgentConfig(acl_source="neutron"),
        )

    def test_neutron_source_loads_effective_payload(self):
        class FakeAriaAclClient(object):
            def get_aria_acl_effective_payload(self):
                return {
                    "policies": [{"id": "policy-1", "default_action": "allow"}],
                    "rules": [{
                        "id": "rule-1",
                        "policy_id": "policy-1",
                        "direction": "ingress",
                        "priority": 100,
                        "action": "drop",
                        "protocol": "icmp",
                        "src_cidr": "192.0.2.2/32",
                    }],
                    "bindings": [{
                        "id": "binding-1",
                        "policy_id": "policy-1",
                        "target_type": "port",
                        "target_id": "port-1",
                    }],
                }

        source = build_acl_source(
            AgentConfig(acl_source="neutron"),
            neutron_client=FakeAriaAclClient(),
        )
        index = source.load_index()
        result = index.effective_for_port({"id": "port-1"}, {"eligible": True})

        self.assertTrue(result["enabled"])
        self.assertEqual("policy-1", result["policy_id"])
        self.assertEqual("rule-1", result["rules"][0]["id"])

    def test_neutron_source_rejects_invalid_effective_payload_shape(self):
        class FakeAriaAclClient(object):
            def get_aria_acl_effective_payload(self):
                return {"policies": [{"id": "policy-1"}], "rules": ["bad-rule"]}

        source = build_acl_source(
            AgentConfig(acl_source="neutron"),
            neutron_client=FakeAriaAclClient(),
        )

        self.assertRaises(AclSourceError, source.load_index)

    def test_neutron_source_wraps_effective_payload_client_errors(self):
        class FakeAriaAclClient(object):
            def get_aria_acl_effective_payload(self):
                raise RuntimeError("neutron api unavailable")

        source = build_acl_source(
            AgentConfig(acl_source="neutron"),
            neutron_client=FakeAriaAclClient(),
        )

        with self.assertRaises(AclSourceError) as raised:
            source.load_index()
        self.assertIn("neutron acl source failed", str(raised.exception))
        self.assertIn("neutron api unavailable", str(raised.exception))

    def test_neutron_source_supports_legacy_list_methods(self):
        class FakeNeutronClient(object):
            def list_aria_acl_policies(self):
                return {"aria_acl_policies": [{"id": "policy-1"}]}

            def list_aria_acl_rules(self):
                return {"aria_acl_rules": []}

            def list_aria_acl_address_sets(self):
                return {"aria_acl_address_sets": []}

            def list_aria_acl_bindings(self):
                return {
                    "aria_acl_bindings": [{
                        "id": "binding-1",
                        "policy_id": "policy-1",
                        "target_type": "network",
                        "target_id": "net-1",
                    }]
                }

        source = build_acl_source(
            AgentConfig(acl_source="neutron"),
            neutron_client=FakeNeutronClient(),
        )
        result = source.load_index().effective_for_port(
            {"id": "port-1", "network_id": "net-1"},
            {"eligible": True},
        )

        self.assertTrue(result["enabled"])
        self.assertEqual("network", result["source"])

    def test_neutron_source_rejects_invalid_list_method_shape(self):
        class FakeNeutronClient(object):
            def list_aria_acl_policies(self):
                return {"aria_acl_policies": {"id": "policy-1"}}

            def list_aria_acl_rules(self):
                return {"aria_acl_rules": []}

            def list_aria_acl_address_sets(self):
                return {"aria_acl_address_sets": []}

            def list_aria_acl_bindings(self):
                return {"aria_acl_bindings": []}

        source = build_acl_source(
            AgentConfig(acl_source="neutron"),
            neutron_client=FakeNeutronClient(),
        )

        self.assertRaises(AclSourceError, source.load_index)

    def test_neutron_source_wraps_list_method_client_errors(self):
        class FakeNeutronClient(object):
            def list_aria_acl_policies(self):
                raise RuntimeError("aria_acl API timeout")

        source = build_acl_source(
            AgentConfig(acl_source="neutron"),
            neutron_client=FakeNeutronClient(),
        )

        with self.assertRaises(AclSourceError) as raised:
            source.load_index()
        self.assertIn("neutron acl source failed", str(raised.exception))
        self.assertIn("aria_acl API timeout", str(raised.exception))

    def test_neutron_source_rejects_missing_list_collection_key(self):
        class FakeNeutronClient(object):
            def list_aria_acl_policies(self):
                return {"policies": [{"id": "policy-1"}]}

            def list_aria_acl_rules(self):
                return {"aria_acl_rules": []}

            def list_aria_acl_address_sets(self):
                return {"aria_acl_address_sets": []}

            def list_aria_acl_bindings(self):
                return {"aria_acl_bindings": []}

        source = build_acl_source(
            AgentConfig(acl_source="neutron"),
            neutron_client=FakeNeutronClient(),
        )

        self.assertRaises(AclSourceError, source.load_index)

    def test_aria_acl_rest_client_uses_extension_paths(self):
        class FakeNeutronClient(object):
            def __init__(self):
                self.paths = []

            def get(self, path):
                self.paths.append(path)
                payloads = {
                    "/aria-acl-policies": {"aria_acl_policies": [{"id": "policy-1"}]},
                    "/aria-acl-rules": {"aria_acl_rules": []},
                    "/aria-acl-address-sets": {"aria_acl_address_sets": []},
                    "/aria-acl-bindings": {
                        "aria_acl_bindings": [{
                            "id": "binding-1",
                            "policy_id": "policy-1",
                            "target_type": "network",
                            "target_id": "net-1",
                        }]
                    },
                }
                return payloads[path]

        client = FakeNeutronClient()
        source = NeutronAclSource(AriaAclRestClient(client))
        result = source.load_index().effective_for_port(
            {"id": "port-1", "network_id": "net-1"},
            {"eligible": True},
        )

        self.assertEqual([
            "/aria-acl-policies",
            "/aria-acl-rules",
            "/aria-acl-address-sets",
            "/aria-acl-bindings",
        ], client.paths)
        self.assertTrue(result["enabled"])
        self.assertEqual("network", result["source"])

    def test_aria_acl_rest_client_follows_paginated_extension_lists(self):
        class FakeNeutronClient(object):
            def __init__(self):
                self.calls = []

            def get(self, path, params=None):
                params = dict(params or {})
                self.calls.append((path, params))
                if path == "/aria-acl-policies" and not params.get("marker"):
                    return {
                        "aria_acl_policies": [{"id": "policy-1"}],
                        "aria_acl_policies_links": [{"rel": "next"}],
                    }
                if path == "/aria-acl-policies" and params.get("marker") == "policy-1":
                    return {
                        "aria_acl_policies": [{"id": "policy-2"}],
                        "aria_acl_policies_links": [],
                    }
                return {"aria_acl_policies": []}

        client = FakeNeutronClient()
        result = AriaAclRestClient(client, page_size=1).list_aria_acl_policies()

        self.assertEqual(
            {"aria_acl_policies": [{"id": "policy-1"}, {"id": "policy-2"}]},
            result,
        )
        self.assertEqual(2, len(client.calls))
        self.assertEqual({"limit": 1}, client.calls[0][1])
        self.assertEqual({"limit": 1, "marker": "policy-1"}, client.calls[1][1])

    def test_aria_acl_rest_client_pages_status_rows_by_derived_id(self):
        first_id = "aria-status-v1_cG9ydC0xAG9zdGFjazI"
        second_id = "aria-status-v1_cG9ydC0yAG9zdGFjazI"

        class FakeNeutronClient(object):
            def __init__(self):
                self.calls = []

            def get(self, path, params=None):
                params = dict(params or {})
                self.calls.append((path, params))
                if not params.get("marker"):
                    return {
                        "aria_acl_port_statuses": [{
                            "id": first_id,
                            "port_id": "port-1",
                            "host": "compute-1",
                        }],
                        "aria_acl_port_statuses_links": [{"rel": "next"}],
                    }
                return {
                    "aria_acl_port_statuses": [{
                        "id": second_id,
                        "port_id": "port-2",
                        "host": "compute-1",
                    }],
                    "aria_acl_port_statuses_links": [],
                }

        client = FakeNeutronClient()
        result = AriaAclRestClient(
            client, page_size=1
        ).list_aria_acl_port_statuses()

        self.assertEqual(2, len(result["aria_acl_port_statuses"]))
        self.assertEqual(first_id, result["aria_acl_port_statuses"][0]["id"])
        self.assertEqual(
            {"limit": 1, "marker": first_id}, client.calls[1][1]
        )

    def test_neutron_source_does_not_return_partial_index_on_page_failure(self):
        class FakeNeutronClient(object):
            def __init__(self):
                self.policy_pages = 0

            def get(self, path, params=None):
                params = dict(params or {})
                if path != "/aria-acl-policies":
                    collection = dict(
                        (value, key)
                        for key, value in AriaAclRestClient.COLLECTIONS.items()
                    )[path]
                    return {collection: []}
                self.policy_pages += 1
                if self.policy_pages == 3:
                    raise RuntimeError("page 3 unavailable")
                policy_id = "policy-%s" % self.policy_pages
                return {
                    "aria_acl_policies": [{"id": policy_id}],
                    "aria_acl_policies_links": [{"rel": "next"}],
                }

        client = FakeNeutronClient()
        source = NeutronAclSource(AriaAclRestClient(client, page_size=1))
        published = []

        with self.assertRaises(AclSourceError):
            published.append(source.load_index())

        self.assertEqual([], published)
        self.assertEqual(3, client.policy_pages)

    def test_aria_acl_rest_client_rejects_missing_collection_key(self):
        class FakeNeutronClient(object):
            def get(self, path):
                return {"policies": [{"id": "policy-1"}]}

        self.assertRaises(
            NeutronClientFactoryError,
            AriaAclRestClient(FakeNeutronClient()).list_aria_acl_policies,
        )

    def test_aria_acl_rest_client_rejects_repeated_pagination_marker(self):
        class FakeNeutronClient(object):
            def get(self, path, params=None):
                return {
                    "aria_acl_policies": [{"id": "policy-1"}],
                    "aria_acl_policies_links": [{"rel": "next"}],
                }

        self.assertRaises(
            NeutronClientFactoryError,
            AriaAclRestClient(FakeNeutronClient(), page_size=1).list_aria_acl_policies,
        )

    def test_aria_acl_rest_client_rejects_missing_pagination_marker(self):
        class FakeNeutronClient(object):
            def get(self, path, params=None):
                return {
                    "aria_acl_policies": [{"name": "missing-id"}],
                    "aria_acl_policies_links": [{"rel": "next"}],
                }

        self.assertRaises(
            NeutronClientFactoryError,
            AriaAclRestClient(FakeNeutronClient(), page_size=1).list_aria_acl_policies,
        )

    def test_aria_acl_rest_client_requires_params_support_for_pagination(self):
        class FakeNeutronClient(object):
            def get(self, path):
                return {"aria_acl_policies": []}

        self.assertRaises(
            NeutronClientFactoryError,
            AriaAclRestClient(FakeNeutronClient(), page_size=1).list_aria_acl_policies,
        )

    def test_aria_acl_rest_client_reports_port_status(self):
        class FakeNeutronClient(object):
            def __init__(self):
                self.posts = []

            def post(self, path, body=None):
                self.posts.append((path, body))
                return {"ok": True}

        client = FakeNeutronClient()
        result = AriaAclRestClient(client).report_aria_acl_port_status({
            "port_id": "port-1",
            "host": "compute-1",
            "status": "ready",
        })

        self.assertTrue(result["ok"])
        self.assertEqual("/aria-acl-port-statuses", client.posts[0][0])
        self.assertEqual(
            "port-1",
            client.posts[0][1]["aria_acl_port_status"]["port_id"],
        )

    def test_aria_acl_rest_client_does_not_retry_post_processing_type_error(self):
        class FakeNeutronClient(object):
            def __init__(self):
                self.post_count = 0

            def post(self, path, body=None):
                self.post_count += 1
                raise TypeError("response decode failed")

        client = FakeNeutronClient()

        with self.assertRaises(TypeError) as context:
            AriaAclRestClient(client).report_aria_acl_port_status({
                "port_id": "port-1",
                "host": "compute-1",
                "status": "ready",
            })

        self.assertEqual("response decode failed", str(context.exception))
        self.assertEqual(1, client.post_count)

    def test_aria_acl_rest_client_lists_port_statuses(self):
        class FakeNeutronClient(object):
            def __init__(self):
                self.paths = []

            def get(self, path):
                self.paths.append(path)
                return {
                    "aria_acl_port_statuses": [{
                        "port_id": "port-1",
                        "host": "compute-1",
                        "status": "ready",
                    }]
                }

        client = FakeNeutronClient()
        result = AriaAclRestClient(client).list_aria_acl_port_statuses()

        self.assertEqual(["/aria-acl-port-statuses"], client.paths)
        self.assertEqual(
            "port-1",
            result["aria_acl_port_statuses"][0]["port_id"],
        )

    def test_aria_acl_rest_client_deletes_exact_host_port_status(self):
        class FakeNeutronClient(object):
            def __init__(self):
                self.paths = []

            def delete(self, path):
                self.paths.append(path)
                return {"ok": True}

        client = FakeNeutronClient()
        result = AriaAclRestClient(client).delete_aria_acl_port_status(
            "port-1",
            host="compute-1",
        )

        self.assertTrue(result["ok"])
        self.assertEqual(
            "/aria-acl-port-statuses/%s" % encode_port_status_id(
                "port-1",
                "compute-1",
            ),
            client.paths[0],
        )

    def test_unknown_source_fails_fast(self):
        self.assertRaises(
            AclSourceError,
            build_acl_source,
            AgentConfig(acl_source="unknown"),
        )


if __name__ == "__main__":
    unittest.main()
