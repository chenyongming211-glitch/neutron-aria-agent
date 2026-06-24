from __future__ import absolute_import

import unittest

from neutron_aria.agent.neutron_client import NeutronFullResyncClient
from neutron_aria.agent.neutron_client import NeutronPortSource


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


if __name__ == "__main__":
    unittest.main()
