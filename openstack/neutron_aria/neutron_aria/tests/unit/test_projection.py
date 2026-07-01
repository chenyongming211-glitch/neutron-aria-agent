from __future__ import absolute_import

import unittest

from neutron_aria.agent.projection import ACTION_DELETE_LOCAL
from neutron_aria.agent.projection import ACTION_FULL_RESYNC
from neutron_aria.agent.projection import ACTION_IGNORE
from neutron_aria.agent.projection import ProjectedStateIndex


class ProjectedStateIndexTestCase(unittest.TestCase):
    def _index(self):
        index = ProjectedStateIndex()
        neutron_ports = [{
            "id": "p1",
            "network_id": "net-a",
            "binding:host_id": "ostack2",
            "revision_number": 7,
        }, {
            "id": "p2",
            "network_id": "net-b",
            "binding:host_id": "ostack2",
            "revision_number": 3,
        }, {
            "id": "p3",
            "network_id": "net-a",
            "binding:host_id": "ostack3",
            "revision_number": 9,
        }]
        snapshot = {
            "generation": 11,
            "ports": [{
                "port_id": "p1",
                "eligible": True,
                "managed_domains": ["acl"],
            }, {
                "port_id": "p2",
                "eligible": True,
                "managed_domains": ["acl"],
            }, {
                "port_id": "p3",
                "eligible": False,
                "managed_domains": [],
            }],
        }
        index.replace_from_resync(neutron_ports, snapshot)
        return index

    def test_rebuilds_port_and_network_indexes_from_full_resync(self):
        index = self._index()

        self.assertEqual(["p1", "p2"], index.port_ids())
        self.assertEqual(["p1"], index.ports_for_network("net-a"))
        self.assertEqual(["p2"], index.ports_for_network("net-b"))
        self.assertEqual([], index.ports_for_network("net-c"))
        self.assertEqual(7, index.port("p1").revision_number)
        self.assertEqual(11, index.port("p1").generation)

    def test_local_port_update_records_revision_relation_but_uses_full_resync(self):
        index = self._index()

        newer = index.decide_port_update(
            "p1",
            "ostack2",
            binding_host="ostack2",
            revision_number=8,
        ).to_dict()
        same = index.decide_port_update(
            "p1",
            "ostack2",
            binding_host="ostack2",
            revision_number=7,
        ).to_dict()
        older = index.decide_port_update(
            "p1",
            "ostack2",
            binding_host="ostack2",
            revision_number=6,
        ).to_dict()

        self.assertEqual(ACTION_FULL_RESYNC, newer["action"])
        self.assertEqual("newer", newer["revision_status"])
        self.assertEqual("same", same["revision_status"])
        self.assertEqual("older", older["revision_status"])

    def test_foreign_host_update_deletes_only_when_port_was_projected(self):
        index = self._index()

        projected = index.decide_port_update(
            "p1",
            "ostack2",
            binding_host="ostack3",
            revision_number=8,
        ).to_dict()
        unknown = index.decide_port_update(
            "p9",
            "ostack2",
            binding_host="ostack3",
            revision_number=1,
        ).to_dict()

        self.assertEqual(ACTION_DELETE_LOCAL, projected["action"])
        self.assertEqual("migration_source_cleanup", projected["delete_reason"])
        self.assertEqual(ACTION_IGNORE, unknown["action"])

    def test_delete_and_network_update_decisions_are_locality_aware(self):
        index = self._index()

        delete_known = index.decide_port_delete("p1").to_dict()
        delete_unknown = index.decide_port_delete("p9").to_dict()
        network_local = index.decide_network_update("net-a").to_dict()
        network_empty = index.decide_network_update(
            "net-c",
            conservative=False,
        ).to_dict()

        self.assertEqual(ACTION_DELETE_LOCAL, delete_known["action"])
        self.assertEqual(ACTION_IGNORE, delete_unknown["action"])
        self.assertEqual(ACTION_FULL_RESYNC, network_local["action"])
        self.assertEqual(["p1"], network_local["affected_ports"])
        self.assertEqual(ACTION_IGNORE, network_empty["action"])


if __name__ == "__main__":
    unittest.main()
