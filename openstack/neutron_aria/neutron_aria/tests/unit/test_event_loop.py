from __future__ import absolute_import

import unittest

from neutron_aria.agent.event_loop import SnapshotSynchronizer
from neutron_aria.agent.neutron_client import StaticPortSource
from neutron_aria.agent.ovsdb import OvsInterface
from neutron_aria.agent.uds_client import LocalApiTransportError


class FakeOvsReader(object):
    def list_interfaces(self):
        return [
            OvsInterface(
                "tapaaaaaaaa-aa",
                external_ids={"iface-id": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"},
                ifindex=31,
                bridge="br-int",
            )
        ]


class FakeLocalClient(object):
    def __init__(self):
        self.capability_calls = []
        self.snapshots = []
        self.deleted_ports = []

    def capabilities(self, required_domains=None):
        self.capability_calls.append(list(required_domains or []))
        return {"api_version": "v1"}

    def put_snapshot(self, snapshot):
        self.snapshots.append(snapshot)
        return {"generation": snapshot["generation"], "results": []}

    def delete_port(self, port_id):
        self.deleted_ports.append(port_id)
        return {"port_id": port_id, "status": "ok"}


class FailingLocalClient(FakeLocalClient):
    def capabilities(self, required_domains=None):
        raise LocalApiTransportError("socket unavailable")


class EventLoopTestCase(unittest.TestCase):
    def test_full_resync_builds_and_submits_snapshot(self):
        port_source = StaticPortSource([{
            "id": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
            "device_owner": "compute:nova",
            "binding:host_id": "ostack2",
            "binding:vif_type": "ovs",
            "binding:vnic_type": "normal",
        }])
        local_client = FakeLocalClient()
        sync = SnapshotSynchronizer(
            "ostack2",
            port_source,
            FakeOvsReader(),
            local_client,
            managed_domains=["acl"],
        )

        result = sync.full_resync()

        self.assertEqual([["acl"]], local_client.capability_calls)
        self.assertEqual(1, result["snapshot"]["generation"])
        self.assertTrue(result["status"]["ready"])
        self.assertFalse(result["status"]["degraded"])
        self.assertEqual(1, len(local_client.snapshots))
        port = local_client.snapshots[0]["ports"][0]
        self.assertTrue(port["eligible"])
        self.assertEqual("tapaaaaaaaa-aa", port["ifname"])

    def test_safe_full_resync_marks_local_api_degraded(self):
        sync = SnapshotSynchronizer(
            "ostack2",
            StaticPortSource([]),
            FakeOvsReader(),
            FailingLocalClient(),
            managed_domains=["acl"],
        )

        result = sync.safe_full_resync()

        self.assertEqual(None, result["snapshot"])
        self.assertEqual(None, result["response"])
        self.assertFalse(result["status"]["ready"])
        self.assertTrue(result["status"]["degraded"])
        self.assertEqual("local_api_degraded", result["status"]["reason"])
        self.assertIn("socket unavailable", result["status"]["last_error"])

    def test_delete_port_delegates_to_local_client(self):
        local_client = FakeLocalClient()
        sync = SnapshotSynchronizer(
            "ostack2",
            StaticPortSource([]),
            FakeOvsReader(),
            local_client,
        )

        sync.delete_port("port-1")

        self.assertEqual(["port-1"], local_client.deleted_ports)


if __name__ == "__main__":
    unittest.main()
