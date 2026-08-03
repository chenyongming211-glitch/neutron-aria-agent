from __future__ import absolute_import

import copy
import json
import os
import shutil
import tempfile
import unittest

from neutron_aria.agent.state import SnapshotStateStore
from neutron_aria.agent.state import desired_snapshot_hash
from neutron_aria.tests.unit.status_contract_scenarios import status_scenario


class SnapshotStateStoreTestCase(unittest.TestCase):
    def setUp(self):
        self.state_dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.state_dir)

    def _snapshot(self, port_id="p1"):
        return {
            "generation": 999,
            "host": "compute-1",
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
            "host": "compute-1",
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

    def test_pending_snapshot_records_restart_scope_and_affected_ports(self):
        store = SnapshotStateStore(self.state_dir)
        full_snapshot = {
            "host": "compute-1",
            "ports": [
                self._snapshot("p1")["ports"][0],
                self._snapshot("p2")["ports"][0],
            ],
        }
        prepared = store.prepare_snapshot(full_snapshot)

        full_pending = SnapshotStateStore(self.state_dir).pending_snapshot()
        self.assertEqual("full_host", full_pending.get("scope"))
        self.assertEqual(
            ["p1", "p2"],
            full_pending.get("affected_port_ids"),
        )

        store.commit_snapshot(
            prepared["generation"],
            prepared["desired_hash"],
        )
        store.prepare_scoped_snapshot(self._snapshot("p1"))

        scoped_pending = SnapshotStateStore(self.state_dir).pending_snapshot()
        self.assertEqual("port", scoped_pending.get("scope"))
        self.assertEqual(["p1"], scoped_pending.get("affected_port_ids"))
        self.assertEqual(["p1", "p2"], scoped_pending["projected_port_ids"])

    def test_new_desired_state_cannot_replace_pending_generation(self):
        store = SnapshotStateStore(self.state_dir)
        first = store.prepare_snapshot(self._snapshot("p1"))
        pending_before = copy.deepcopy(store.pending_snapshot())
        state_before = copy.deepcopy(store.to_dict())

        self.assertEqual(1, first["generation"])
        with self.assertRaises(RuntimeError):
            store.prepare_snapshot(self._snapshot("p2"))
        self.assertEqual(pending_before, store.pending_snapshot())
        self.assertEqual(state_before, store.to_dict())
        self.assertTrue(os.path.exists(os.path.join(
            self.state_dir,
            "snapshot-state.json",
        )))

    def test_scoped_desired_state_cannot_replace_full_pending_generation(self):
        store = SnapshotStateStore(self.state_dir)
        store.prepare_snapshot(self._snapshot("p1"))
        pending_before = copy.deepcopy(store.pending_snapshot())
        state_before = copy.deepcopy(store.to_dict())

        with self.assertRaises(RuntimeError):
            store.prepare_scoped_snapshot(self._snapshot("p2"))

        self.assertEqual(pending_before, store.pending_snapshot())
        self.assertEqual(state_before, store.to_dict())

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

    def test_delete_prepare_cannot_replace_different_pending_delete(self):
        store = SnapshotStateStore(self.state_dir)
        store.prepare_delete("p1", reason="first-delete")
        pending_before = copy.deepcopy(store.pending_delete())
        state_before = copy.deepcopy(store.to_dict())

        with self.assertRaises(RuntimeError):
            store.prepare_delete("p2", reason="second-delete")

        self.assertEqual(pending_before, store.pending_delete())
        self.assertEqual(state_before, store.to_dict())

    def test_delete_prepare_cannot_overlap_pending_snapshot(self):
        store = SnapshotStateStore(self.state_dir)
        store.prepare_snapshot(self._snapshot("p1"))
        pending_before = copy.deepcopy(store.pending_snapshot())
        state_before = copy.deepcopy(store.to_dict())

        with self.assertRaises(RuntimeError):
            store.prepare_delete("p1", reason="overlap-snapshot")

        self.assertEqual(pending_before, store.pending_snapshot())
        self.assertEqual(state_before, store.to_dict())

    def test_snapshot_prepare_cannot_overlap_pending_delete(self):
        store = SnapshotStateStore(self.state_dir)
        store.prepare_delete("p1", reason="overlap-delete")
        pending_before = copy.deepcopy(store.pending_delete())
        state_before = copy.deepcopy(store.to_dict())

        with self.assertRaises(RuntimeError):
            store.prepare_snapshot(self._snapshot("p1"))

        self.assertEqual(pending_before, store.pending_delete())
        self.assertEqual(state_before, store.to_dict())

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


class StatusContractStateRedTestCase(unittest.TestCase):
    def setUp(self):
        self.state_dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.state_dir)

    def _state_path(self):
        return os.path.join(self.state_dir, "snapshot-state.json")

    def _write_state(self, payload):
        with open(self._state_path(), "w") as stream:
            json.dump(payload, stream, sort_keys=True)
            stream.write("\n")

    def _snapshot(self, port_ids):
        return {
            "host": "compute-1",
            "ports": [
                {
                    "port_id": port_id,
                    "ifname": "tap-%s" % port_id,
                    "eligible": True,
                    "managed_domains": ["acl"],
                }
                for port_id in port_ids
            ],
        }

    def _required_method(self, target, method_name):
        method = getattr(target, method_name, None)
        self.assertTrue(
            callable(method),
            "missing Status V1 state method %s" % method_name,
        )
        return method

    def _commit_feature_ready(self, store, prepared, domains=None):
        try:
            store.commit_snapshot(
                prepared["generation"],
                prepared["desired_hash"],
                snapshot_ports=prepared.get("snapshot_ports", 0),
                managed_ports=prepared.get("managed_ports", 0),
                feature_ready_domains=list(domains or []),
            )
        except TypeError as exc:
            self.fail(
                "commit_snapshot lacks feature_ready_domains: %s" % exc
            )

    def test_legacy_state_migrates_old_fields_into_both_tracks(self):
        scenario = status_scenario("restart-classified-routing")
        source = scenario["durable_state"]
        legacy = {
            "schema_version": source["schema_version"],
            "last_generation": source["last_feature_ready_generation"],
            "last_desired_hash": source["last_feature_ready_desired_hash"],
            "last_projected_port_ids": list(
                source["last_feature_ready_projected_port_ids"]
            ),
        }
        self._write_state(legacy)

        migrated = SnapshotStateStore(self.state_dir).to_dict()

        self.assertEqual(
            legacy["last_generation"],
            migrated.get("last_classified_generation"),
        )
        self.assertEqual(
            legacy["last_desired_hash"],
            migrated.get("last_classified_desired_hash"),
        )
        self.assertEqual(
            legacy["last_projected_port_ids"],
            migrated.get("last_classified_projected_port_ids"),
        )
        self.assertEqual(
            legacy["last_generation"],
            migrated.get("last_feature_ready_generation"),
        )
        self.assertEqual(
            legacy["last_desired_hash"],
            migrated.get("last_feature_ready_desired_hash"),
        )
        self.assertEqual(
            legacy["last_projected_port_ids"],
            migrated.get("last_feature_ready_projected_port_ids"),
        )
        self.assertEqual(
            {},
            migrated.get("last_feature_ready_generation_by_domain"),
        )

    def test_ready_commit_advances_both_tracks_and_domain_history(self):
        scenario = status_scenario("full-classified-ready")
        store = SnapshotStateStore(self.state_dir)
        prepared = store.prepare_snapshot_at_generation(
            self._snapshot(scenario["request_context"]["projected_port_ids"]),
            scenario["request_context"]["expected_generation"],
            desired_hash=scenario["request_context"]["expected_desired_hash"],
        )
        prepared.update({"snapshot_ports": 1, "managed_ports": 1})

        self._commit_feature_ready(store, prepared, domains=["acl"])
        state = SnapshotStateStore(self.state_dir).to_dict()

        self.assertEqual("feature_ready", scenario["expected_python"]["decision"])
        self.assertTrue(scenario["expected_python"]["record_classified"])
        self.assertTrue(scenario["expected_python"]["record_feature_ready"])
        for prefix in ("last_classified", "last_feature_ready"):
            self.assertEqual(
                prepared["generation"],
                state.get("%s_generation" % prefix),
            )
            self.assertEqual(
                prepared["desired_hash"],
                state.get("%s_desired_hash" % prefix),
            )
            self.assertEqual(
                ["port-a"],
                state.get("%s_projected_port_ids" % prefix),
            )
        self.assertEqual(
            {"acl": prepared["generation"]},
            state.get("last_feature_ready_generation_by_domain"),
        )

    def test_scoped_ready_commit_advances_both_tracks_and_preserves_unaffected_id(self):
        scenario = status_scenario("scoped-classified-ready")
        store = SnapshotStateStore(self.state_dir)
        baseline = store.prepare_snapshot_at_generation(
            self._snapshot(["port-a", "port-b"]),
            42,
            desired_hash="hash-ready-42",
        )
        baseline.update({"snapshot_ports": 2, "managed_ports": 2})
        self._commit_feature_ready(store, baseline, domains=["acl"])
        scoped = store.prepare_scoped_snapshot(self._snapshot(["port-a"]))
        try:
            store.commit_scoped_snapshot(
                scoped["generation"],
                scoped["desired_hash"],
                managed_ports=2,
                feature_ready_domains=["acl"],
            )
        except TypeError as exc:
            self.fail(
                "commit_scoped_snapshot lacks feature_ready_domains: %s" % exc
            )
        state = SnapshotStateStore(self.state_dir).to_dict()

        self.assertEqual("feature_ready", scenario["expected_python"]["decision"])
        self.assertEqual(
            scenario["request_context"]["projected_port_ids"],
            state["last_classified_projected_port_ids"],
        )
        self.assertEqual(
            scenario["request_context"]["projected_port_ids"],
            state["last_feature_ready_projected_port_ids"],
        )
        self.assertEqual(scoped["generation"], state["last_classified_generation"])
        self.assertEqual(scoped["generation"], state["last_feature_ready_generation"])
        self.assertEqual(
            {"acl": scoped["generation"]},
            state["last_feature_ready_generation_by_domain"],
        )

    def test_classified_degraded_commit_advances_only_classified_track(self):
        scenario = status_scenario("classified-degraded-terminal")
        store = SnapshotStateStore(self.state_dir)
        baseline = store.prepare_snapshot_at_generation(
            self._snapshot(["port-old"]),
            scenario["request_context"]["feature_ready_generation_before"],
            desired_hash="ready-hash-43",
        )
        baseline.update({"snapshot_ports": 1, "managed_ports": 1})
        self._commit_feature_ready(store, baseline, domains=["acl"])
        prepared = store.prepare_snapshot_at_generation(
            self._snapshot(scenario["request_context"]["projected_port_ids"]),
            scenario["request_context"]["expected_generation"],
            desired_hash=scenario["request_context"]["expected_desired_hash"],
        )
        commit_classified = self._required_method(
            store,
            "commit_classified_snapshot",
        )

        commit_classified(
            prepared["generation"],
            prepared["desired_hash"],
            snapshot_ports=1,
            managed_ports=1,
        )
        state = SnapshotStateStore(self.state_dir).to_dict()

        self.assertEqual(
            scenario["status"]["last_classified_generation"],
            state["last_classified_generation"],
        )
        self.assertEqual(
            scenario["request_context"]["projected_port_ids"],
            state["last_classified_projected_port_ids"],
        )
        self.assertEqual(
            scenario["request_context"]["feature_ready_generation_before"],
            state["last_feature_ready_generation"],
        )
        self.assertEqual(
            scenario["request_context"]["feature_ready_projected_port_ids_before"],
            state["last_feature_ready_projected_port_ids"],
        )
        self.assertEqual(
            {"acl": scenario["request_context"]["feature_ready_generation_before"]},
            state["last_feature_ready_generation_by_domain"],
        )
        self.assertEqual(None, SnapshotStateStore(self.state_dir).pending_snapshot())

    def test_scoped_classification_preserves_unaffected_ids_and_ready_track(self):
        store = SnapshotStateStore(self.state_dir)
        baseline = store.prepare_snapshot(self._snapshot(["port-a", "port-b"]))
        baseline.update({"snapshot_ports": 2, "managed_ports": 2})
        self._commit_feature_ready(store, baseline, domains=["acl"])
        scoped = store.prepare_scoped_snapshot(self._snapshot(["port-c"]))
        commit_classified = self._required_method(
            store,
            "commit_classified_scoped_snapshot",
        )

        commit_classified(
            scoped["generation"],
            scoped["desired_hash"],
            managed_ports=3,
        )
        state = SnapshotStateStore(self.state_dir).to_dict()

        self.assertEqual(
            ["port-a", "port-b", "port-c"],
            state["last_classified_projected_port_ids"],
        )
        self.assertEqual(
            ["port-a", "port-b"],
            state["last_feature_ready_projected_port_ids"],
        )
        self.assertEqual(
            baseline["generation"],
            state["last_feature_ready_generation"],
        )

    def test_generation_floor_uses_latest_classified_generation(self):
        scenario = status_scenario("restart-classified-routing")
        self._write_state(scenario["durable_state"])
        store = SnapshotStateStore(self.state_dir)

        prepared = store.prepare_snapshot(self._snapshot(["port-d"]))

        self.assertEqual(
            scenario["durable_state"]["last_classified_generation"] + 1,
            prepared["generation"],
        )

    def test_classified_degraded_full_resync_forces_newer_generation(self):
        scenario = status_scenario("classified-degraded-full-resync")
        store = SnapshotStateStore(self.state_dir)
        snapshot = self._snapshot(
            scenario["request_context"]["projected_port_ids"]
        )
        baseline = store.prepare_snapshot(snapshot)
        baseline.update({"snapshot_ports": 1, "managed_ports": 1})
        self._commit_feature_ready(store, baseline, domains=["acl"])

        try:
            prepared = store.prepare_snapshot(
                snapshot,
                minimum_generation=baseline["generation"],
                force_new_generation=True,
            )
        except TypeError as exc:
            self.fail(
                "prepare_snapshot lacks force_new_generation: %s" % exc
            )
        state = SnapshotStateStore(self.state_dir).to_dict()

        self.assertEqual("full_resync", scenario["expected_python"]["decision"])
        self.assertGreater(prepared["generation"], baseline["generation"])
        self.assertFalse(prepared.get("reused_pending", False))
        self.assertEqual(
            baseline["generation"],
            state["last_feature_ready_generation"],
        )
        self.assertEqual(
            baseline["generation"],
            state["last_classified_generation"],
        )

    def test_recovery_realigns_classified_baseline_and_clears_only_exact_pending(self):
        scenario = status_scenario("recovery-full-resync")
        context = scenario["request_context"]
        store = SnapshotStateStore(self.state_dir)
        baseline = store.prepare_snapshot_at_generation(
            self._snapshot(["port-a"]),
            context["restored_generation"],
            desired_hash=context["restored_desired_hash"],
        )
        baseline.update({"snapshot_ports": 1, "managed_ports": 1})
        self._commit_feature_ready(store, baseline, domains=["acl"])
        pending = store.prepare_snapshot_at_generation(
            self._snapshot(["port-a", "port-pending"]),
            context["restored_generation"] + 1,
            desired_hash="hash-pending-43",
        )
        realign = self._required_method(store, "realign_classified_snapshot")
        feature_ready_history = self._required_method(
            store,
            "feature_ready_history",
        )
        original_pending = copy.deepcopy(store.pending_snapshot())
        original_feature_ready = copy.deepcopy(feature_ready_history())

        realign(
            context["restored_generation"],
            context["restored_desired_hash"],
            ["port-a"],
            recovered_pending_generation=pending["generation"] + 1,
            recovered_pending_desired_hash=pending["desired_hash"],
        )
        self.assertEqual(original_pending, store.pending_snapshot())
        self.assertEqual(original_feature_ready, feature_ready_history())

        realign(
            context["restored_generation"],
            context["restored_desired_hash"],
            ["port-a"],
            recovered_pending_generation=pending["generation"],
            recovered_pending_desired_hash="hash-pending-mismatch",
        )
        self.assertEqual(original_pending, store.pending_snapshot())
        self.assertEqual(original_feature_ready, feature_ready_history())

        realign(
            context["restored_generation"],
            context["restored_desired_hash"],
            ["port-a"],
            recovered_pending_generation=pending["generation"],
            recovered_pending_desired_hash=pending["desired_hash"],
        )
        cleared_pending = SnapshotStateStore(self.state_dir).pending_snapshot()
        self.assertEqual(original_feature_ready, feature_ready_history())
        try:
            rebuilt = store.prepare_snapshot(
                self._snapshot(["port-a"]),
                minimum_generation=context["restored_generation"],
                force_new_generation=True,
            )
        except TypeError as exc:
            self.fail(
                "prepare_snapshot lacks force_new_generation: %s" % exc
            )
        state = SnapshotStateStore(self.state_dir).to_dict()

        self.assertEqual(
            "recovered_full_resync",
            scenario["expected_python"]["decision"],
        )
        self.assertEqual(
            context["restored_generation"],
            state["last_classified_generation"],
        )
        self.assertEqual(
            context["restored_desired_hash"],
            state["last_classified_desired_hash"],
        )
        self.assertEqual(["port-a"], state["last_classified_projected_port_ids"])
        self.assertEqual(
            context["restored_generation"],
            state["last_feature_ready_generation"],
        )
        self.assertEqual(None, cleared_pending)
        self.assertEqual(original_feature_ready, feature_ready_history())
        self.assertGreater(
            rebuilt["generation"],
            context["restored_generation"],
        )
        self.assertEqual(
            ["put_full_snapshot"],
            scenario["expected_python"]["mutating_calls"],
        )
        self.assertEqual(
            rebuilt["generation"],
            SnapshotStateStore(self.state_dir).pending_snapshot()["generation"],
        )


if __name__ == "__main__":
    unittest.main()
