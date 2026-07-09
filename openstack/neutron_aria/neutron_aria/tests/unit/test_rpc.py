from __future__ import absolute_import

import unittest

from neutron_aria.agent.event_merge import EventMerger
from neutron_aria.agent.rpc import AriaAgentRpcCallback
from neutron_aria.agent.rpc import rpc_topic_details


class FakeTopics(object):
    AGENT = "q-agent-notifier"
    PORT = "port"
    UPDATE = "update"
    DELETE = "delete"
    NETWORK = "network"


class RpcCallbackTestCase(unittest.TestCase):
    def test_rpc_topics_match_old_neutron_agent_shape(self):
        self.assertEqual(
            [
                ["port", "update"],
                ["port", "delete"],
                ["network", "update"],
                ["aria_acl", "update"],
            ],
            rpc_topic_details(FakeTopics),
        )

    def test_rpc_callback_declares_legacy_endpoint_target_when_available(self):
        target = getattr(AriaAgentRpcCallback, "target", None)
        if target is not None:
            self.assertEqual("1.4", target.version)

    def test_port_update_records_binding_host_and_revision(self):
        merger = EventMerger()
        callback = AriaAgentRpcCallback(merger, local_host="ostack2.bj159.net")

        callback.port_update(
            None,
            port={
                "id": "p1",
                "binding:host_id": "ostack2.bj159.net",
                "revision_number": 9,
            },
        )

        batch = merger.drain()

        self.assertEqual("ostack2.bj159.net", batch.port_updates["p1"]["binding_host"])
        self.assertEqual(9, batch.port_updates["p1"]["revision_number"])

    def test_port_delete_uses_legacy_port_id_kwarg(self):
        merger = EventMerger()
        callback = AriaAgentRpcCallback(merger)

        callback.port_delete(None, port_id="p1")

        self.assertEqual(["p1"], merger.drain().deleted_ports)

    def test_network_update_records_network_id(self):
        merger = EventMerger()
        callback = AriaAgentRpcCallback(merger)

        callback.network_update(None, network={"id": "net1"})

        batch = merger.drain()

        self.assertEqual(["net1"], batch.dirty_networks)
        self.assertIn("network_update:net1", batch.reasons)

    def test_aria_acl_update_records_domain_full_resync(self):
        merger = EventMerger()
        callback = AriaAgentRpcCallback(merger)

        callback.aria_acl_update(
            None,
            resource="binding",
            operation="update",
            resource_id="binding-1",
            target_type="port",
            target_id="port-1",
            revision_number=7,
        )

        batch = merger.drain()

        self.assertTrue(batch.full_resync)
        self.assertIn(
            "aria_domain_update:acl:binding:update:binding-1",
            batch.reasons,
        )


if __name__ == "__main__":
    unittest.main()
