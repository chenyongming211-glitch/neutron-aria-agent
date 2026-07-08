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

    def test_pending_snapshot_records_projected_ports_and_commit_clears_pending(self):
        store = SnapshotStateStore(self.state_dir)
        prepared = store.prepare_snapshot(self._snapshot("p1"))

        pending = SnapshotStateStore(self.state_dir).pending_snapshot()
        self.assertEqual(prepared["generation"], pending["generation"])
        self.assertEqual(["p1"], pending["projected_port_ids"])
        self.assertEqual(1, pending["snapshot_ports"])

        store.commit_snapshot(prepared["generation"], prepared["desired_hash"])
        committed = SnapshotStateStore(self.state_dir)

        self.assertEqual(None, committed.pending_snapshot())
        self.assertEqual(["p1"], committed.last_projected_port_ids())

    def test_scoped_snapshot_preserves_existing_projected_ports(self):
        store = SnapshotStateStore(self.state_dir)
        prepared = store.prepare_snapshot({
            "generation": 1,
            "host": "ostack2",
            "ports": [
                self._snapshot("p1")["ports"][0],
                self._snapshot("p2")["ports"][0],
            ],
        })
        store.commit_snapshot(prepared["generation"], prepared["desired_hash"])

        scoped = store.prepare_scoped_snapshot(self._snapshot("p1"))
        pending = SnapshotStateStore(self.state_dir).pending_snapshot()

        self.assertEqual(["p1", "p2"], pending["projected_port_ids"])
        store.commit_scoped_snapshot(scoped["generation"], scoped["desired_hash"])
        committed = SnapshotStateStore(self.state_dir)

        self.assertEqual(None, committed.pending_snapshot())
        self.assertEqual(["p1", "p2"], committed.last_projected_port_ids())
        self.assertEqual(scoped["generation"], committed.to_dict()["last_generation"])

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

    def test_prepare_advances_beyond_remote_generation_floor(self):
        store = SnapshotStateStore(self.state_dir)
        first = store.prepare_snapshot(self._snapshot("p1"))
        second = store.prepare_snapshot(
            self._snapshot("p1"),
            minimum_generation=3,
        )

        self.assertEqual(1, first["generation"])
        self.assertEqual(4, second["generation"])
        self.assertFalse(second["reused_pending"])

    def test_prepare_snapshot_at_generation_tracks_remote_pending(self):
        store = SnapshotStateStore(self.state_dir)
        snapshot = self._snapshot("p1")
        desired_hash = desired_snapshot_hash(snapshot)

        prepared = store.prepare_snapshot_at_generation(
            snapshot,
            7,
            desired_hash=desired_hash,
        )
        pending = SnapshotStateStore(self.state_dir).pending_snapshot()

        self.assertEqual(7, prepared["generation"])
        self.assertEqual(desired_hash, prepared["desired_hash"])
        self.assertEqual(7, pending["generation"])
        self.assertEqual(["p1"], pending["projected_port_ids"])

    def test_prepare_reuses_committed_generation_equal_to_remote_floor(self):
        store = SnapshotStateStore(self.state_dir)
        first = store.prepare_snapshot(self._snapshot("p1"))
        store.commit_snapshot(first["generation"], first["desired_hash"])

        second = store.prepare_snapshot(
            self._snapshot("p1"),
            minimum_generation=first["generation"],
        )

        self.assertEqual(first["generation"], second["generation"])

    def test_prepare_and_commit_delete_are_durable(self):
        store = SnapshotStateStore(self.state_dir)
        prepared = store.prepare_snapshot(self._snapshot("p1"))
        store.commit_snapshot(prepared["generation"], prepared["desired_hash"])

        store.prepare_delete("p1", reason="migration_source_cleanup")
        restarted = SnapshotStateStore(self.state_dir)
        pending = restarted.pending_delete()

        self.assertEqual("p1", pending["port_id"])
        self.assertEqual("migration_source_cleanup", pending["reason"])

        restarted.commit_delete("p1")
        committed = SnapshotStateStore(self.state_dir)

        self.assertEqual(None, committed.pending_delete())
        self.assertEqual([], committed.last_projected_port_ids())
        self.assertEqual("p1", committed.to_dict()["last_deleted_port_id"])

    def test_commit_delete_for_different_port_preserves_pending_delete(self):
        store = SnapshotStateStore(self.state_dir)
        prepared = store.prepare_snapshot(self._snapshot("p1"))
        store.commit_snapshot(prepared["generation"], prepared["desired_hash"])
        store.prepare_delete("p1", reason="port_delete_event")

        store.commit_delete("p2")
        reloaded = SnapshotStateStore(self.state_dir)

        self.assertEqual("p1", reloaded.pending_delete()["port_id"])
        self.assertEqual(["p1"], reloaded.last_projected_port_ids())
        self.assertEqual("p2", reloaded.to_dict()["last_deleted_port_id"])

    def test_clear_pending_snapshot_records_reason(self):
        store = SnapshotStateStore(self.state_dir)
        prepared = store.prepare_snapshot(self._snapshot("p1"))

        cleared = store.clear_pending_snapshot(reason="remote_generation_advanced")
        reloaded = SnapshotStateStore(self.state_dir)
        state = reloaded.to_dict()

        self.assertEqual(prepared["generation"], cleared["generation"])
        self.assertEqual(None, reloaded.pending_snapshot())
        self.assertEqual(prepared["generation"], state["last_cleared_pending_generation"])
        self.assertEqual(
            prepared["desired_hash"],
            state["last_cleared_pending_desired_hash"],
        )
        self.assertEqual(
            "remote_generation_advanced",
            state["last_cleared_pending_reason"],
        )


if __name__ == "__main__":
    unittest.main()
