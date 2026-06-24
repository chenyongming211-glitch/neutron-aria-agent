from __future__ import absolute_import

import unittest

from neutron_aria.agent.neutron_client import NeutronFullResyncClient
from neutron_aria.agent.neutron_client import NeutronClientFactoryError
from neutron_aria.agent.neutron_client import NeutronPortSource
from neutron_aria.agent.neutron_client import PortSourceUnavailable
from neutron_aria.agent.neutron_client import build_port_source
from neutron_aria.agent.neutron_client import normalize_endpoint_type
from neutron_aria.agent.neutron_client import neutron_client_kwargs_from_env


class FakeNeutronClient(object):
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def list_ports(self, **kwargs):
        self.calls.append(kwargs)
        return self.responses.pop(0)


class NeutronClientTestCase(unittest.TestCase):
    def test_port_source_filters_by_host(self):
        client = FakeNeutronClient([{"ports": [{"id": "p1"}], "ports_links": []}])
        source = NeutronPortSource(client, "ostack2")

        ports = source.list_ports_for_host()

        self.assertEqual([{"id": "p1"}], ports)
        self.assertEqual("ostack2", client.calls[0]["binding:host_id"])

    def test_port_source_follows_legacy_pagination(self):
        client = FakeNeutronClient([
            {
                "ports": [{"id": "p1"}],
                "ports_links": [{"rel": "next", "href": "http://neutron/v2.0/ports?marker=p1"}],
            },
            {"ports": [{"id": "p2"}], "ports_links": []},
        ])
        source = NeutronPortSource(client, "ostack2", page_size=1)

        ports = source.list_ports_for_host()

        self.assertEqual([{"id": "p1"}, {"id": "p2"}], ports)
        self.assertEqual(1, client.calls[0]["limit"])
        self.assertEqual("p1", client.calls[1]["marker"])

    def test_full_resync_client_delegates_to_port_source(self):
        source = NeutronPortSource(
            FakeNeutronClient([{"ports": [{"id": "p1"}], "ports_links": []}]),
            "ostack2",
        )
        full_resync = NeutronFullResyncClient(source)

        self.assertEqual([{"id": "p1"}], full_resync.get_ports())

    def test_auth_kwargs_are_loaded_from_legacy_openrc_env(self):
        kwargs = neutron_client_kwargs_from_env({
            "OS_AUTH_URL": "http://keystone:5000/v2.0",
            "OS_USERNAME": "admin",
            "OS_PASSWORD": "secret",
            "OS_TENANT_NAME": "admin",
            "OS_REGION_NAME": "RegionOne",
            "OS_INTERFACE": "internal",
            "OS_INSECURE": "true",
        })

        self.assertEqual("http://keystone:5000/v2.0", kwargs["auth_url"])
        self.assertEqual("admin", kwargs["username"])
        self.assertEqual("secret", kwargs["password"])
        self.assertEqual("admin", kwargs["tenant_name"])
        self.assertEqual("RegionOne", kwargs["region_name"])
        self.assertEqual("internalURL", kwargs["endpoint_type"])
        self.assertTrue(kwargs["insecure"])

    def test_endpoint_type_normalizes_modern_interface_names(self):
        self.assertEqual("publicURL", normalize_endpoint_type("public"))
        self.assertEqual("internalURL", normalize_endpoint_type("internal"))
        self.assertEqual("adminURL", normalize_endpoint_type("admin"))
        self.assertEqual("internalURL", normalize_endpoint_type("internalURL"))

    def test_auth_kwargs_require_neutron_credentials(self):
        with self.assertRaises(NeutronClientFactoryError):
            neutron_client_kwargs_from_env({})

    def test_disabled_port_source_fails_before_empty_snapshot(self):
        class Config(object):
            port_source = "disabled"
            port_page_size = None

        source = build_port_source(Config(), "ostack2")

        with self.assertRaises(PortSourceUnavailable):
            source.list_ports_for_host()


if __name__ == "__main__":
    unittest.main()
