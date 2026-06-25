from __future__ import absolute_import

import os
import shutil
import tempfile
import unittest

from neutron_aria.agent.state import SnapshotStateStore
from neutron_aria.agent.state import desired_snapshot_hash


class SnapshotStateStoreTestCase(unittest.TestCase):
    def setUp(self):
        self.state_dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.state_dir)

    def _snapshot(self, port_id="p1"):
        return {
            "generation": 999,
            "host": "ostack2",
            "ports": [{
                "port_id": port_id,
                "ifname": "tap%s" % port_id,
                "eligible": True,
                "managed_domains": ["acl"],
            }],
        }

    def test_desired_hash_ignores_generation_and_sorts_ports(self):
        left = self._snapshot("p1")
        right = self._snapshot("p1")
        right["generation"] = 1000
        right["desired_hash"] = "ignored"

        self.assertEqual(desired_snapshot_hash(left), desired_snapshot_hash(right))

    def test_prepare_commit_and_reuse_same_desired_generation(self):
        store = SnapshotStateStore(self.state_dir)
        snapshot = self._snapshot("p1")

        first = store.prepare_snapshot(snapshot)
        store.commit_snapshot(first["generation"], first["desired_hash"])
        second = store.prepare_snapshot(self._snapshot("p1"))

        self.assertEqual(1, first["generation"])
        self.assertEqual(1, second["generation"])

    def test_pending_generation_survives_restart(self):
        store = SnapshotStateStore(self.state_dir)
        first = store.prepare_snapshot(self._snapshot("p1"))

        restarted = SnapshotStateStore(self.state_dir)
        second = restarted.prepare_snapshot(self._snapshot("p1"))

        self.assertEqual(1, first["generation"])
        self.assertEqual(1, second["generation"])

    def test_new_desired_state_advances_after_pending_generation(self):
        store = SnapshotStateStore(self.state_dir)
        first = store.prepare_snapshot(self._snapshot("p1"))
        second = store.prepare_snapshot(self._snapshot("p2"))

        self.assertEqual(1, first["generation"])
        self.assertEqual(2, second["generation"])
        self.assertTrue(os.path.exists(os.path.join(
            self.state_dir,
            "snapshot-state.json",
        )))


if __name__ == "__main__":
    unittest.main()
