from __future__ import absolute_import

import unittest

from neutron_aria.agent.service import AgentService
from neutron_aria.agent.service import HEARTBEAT_ONLY_REASON
from neutron_aria.agent.service import EVENTS_WITHOUT_RESYNC_REASON
from neutron_aria.agent.service import EVENT_IDLE_POLL_INTERVAL
from neutron_aria.agent.event_merge import EventMerger
from neutron_aria.agent.status import AgentRuntimeStatus
from neutron_aria.agent.uds_client import LocalApiContractError
from neutron_aria.tests.unit.status_contract_scenarios import status_scenario


class FakeClock(object):
    def __init__(self, value=0):
        self.value = value

    def __call__(self):
        return self.value

    def advance(self, seconds):
        self.value += seconds


class FakeSynchronizer(object):
    def __init__(self):
        self.runtime_status = AgentRuntimeStatus("compute-1.example.test")
        self.resync_calls = 0
        self.heartbeat_calls = 0
        self.projected_port_ids = set()
        self.delete_calls = []
        self.delete_reasons = []
        self.scoped_calls = []
        self.host = "compute-1.example.test"
        self.forced_revision_status = None
        self.scoped_exception = None
        self.scoped_result = None

    def safe_full_resync(self):
        self.resync_calls += 1
        self.runtime_status.mark_ready(
            generation=self.resync_calls,
            snapshot_ports=2,
            managed_ports=2,
        )
        heartbeat = self.report_status()
        return {
            "snapshot": {"generation": self.resync_calls},
            "response": {},
            "status": self.runtime_status.to_dict(),
            "heartbeat": heartbeat,
        }

    def report_status(self):
        self.heartbeat_calls += 1
        return {
            "ok": True,
            "status": self.runtime_status.to_dict(),
        }

    def has_projected_port(self, port_id):
        return port_id in self.projected_port_ids

    def decide_port_update(self, port_id, binding_host=None, revision_number=None):
        if binding_host and binding_host != self.host:
            if self.has_projected_port(port_id):
                return {
                    "action": "delete_local",
                    "reason": "foreign_host_update_for_projected_port",
                    "port_id": port_id,
                    "delete_reason": "migration_source_cleanup",
                }
            return {
                "action": "ignore",
                "reason": "foreign_host_update_for_unknown_port",
                "port_id": port_id,
            }
        revision_status = self.forced_revision_status
        if revision_status is None:
            revision_status = "newer" if revision_number is not None else "unknown"
        return {
            "action": "full_resync",
            "reason": "local_port_update",
            "port_id": port_id,
            "revision_status": revision_status,
        }

    def delete_port(self, port_id, reason=None):
        self.delete_calls.append(port_id)
        self.delete_reasons.append(reason)
        self.projected_port_ids.discard(port_id)
        return {"deleted": port_id}

    def apply_port_scoped_snapshot(
        self,
        port_id,
        binding_host=None,
        revision_number=None,
        allow_revisionless=False,
    ):
        self.scoped_calls.append({
            "port_id": port_id,
            "binding_host": binding_host,
            "revision_number": revision_number,
            "allow_revisionless": allow_revisionless,
        })
        if self.scoped_exception is not None:
            raise self.scoped_exception
        if self.scoped_result is not None:
            return self.scoped_result
        generation = self.resync_calls + len(self.scoped_calls)
        self.runtime_status.mark_ready(
            generation=generation,
            snapshot_ports=2,
            managed_ports=2,
        )
        heartbeat = self.report_status()
        return {
            "submitted": True,
            "snapshot": {"generation": generation, "ports": [{"port_id": port_id}]},
            "response": {},
            "status": self.runtime_status.to_dict(),
            "heartbeat": heartbeat,
        }


class DegradedSynchronizer(FakeSynchronizer):
    def safe_full_resync(self):
        self.resync_calls += 1
        self.runtime_status.mark_degraded("resync_degraded", "port source unavailable")
        heartbeat = self.report_status()
        return {
            "snapshot": None,
            "response": None,
            "status": self.runtime_status.to_dict(),
            "heartbeat": heartbeat,
        }


class AgentServiceTestCase(unittest.TestCase):
    def test_heartbeat_only_initialize_reports_degraded_without_resync(self):
        clock = FakeClock()
        sync = FakeSynchronizer()
        service = AgentService(
            sync,
            full_resync_enabled=False,
            report_interval=5,
            resync_interval=60,
            clock=clock,
        )

        result = service.initialize()

        self.assertEqual(0, sync.resync_calls)
        self.assertEqual(1, sync.heartbeat_calls)
        self.assertTrue(result["status"]["degraded"])
        self.assertEqual(HEARTBEAT_ONLY_REASON, result["status"]["reason"])
        self.assertEqual(5, service.next_report_at)

    def test_heartbeat_only_run_once_reports_on_interval(self):
        clock = FakeClock()
        sync = FakeSynchronizer()
        service = AgentService(
            sync,
            full_resync_enabled=False,
            report_interval=5,
            resync_interval=60,
            clock=clock,
        )
        service.initialize()

        self.assertEqual(None, service.run_once())
        clock.advance(5)
        result = service.run_once()

        self.assertEqual(2, sync.heartbeat_calls)
        self.assertEqual(None, result["snapshot"])
        self.assertEqual(10, service.next_report_at)

    def test_full_resync_initialize_runs_safe_resync(self):
        clock = FakeClock()
        sync = FakeSynchronizer()
        service = AgentService(
            sync,
            full_resync_enabled=True,
            report_interval=5,
            resync_interval=30,
            resync_backoff_initial=3,
            resync_backoff_max=12,
            clock=clock,
        )

        result = service.initialize()

        self.assertEqual(1, sync.resync_calls)
        self.assertEqual(1, sync.heartbeat_calls)
        self.assertTrue(result["status"]["ready"])
        self.assertEqual(5, service.next_report_at)
        self.assertEqual(30, service.next_resync_at)
        self.assertEqual(0, service.current_resync_backoff)

    def test_full_resync_run_once_prefers_resync_deadline(self):
        clock = FakeClock()
        sync = FakeSynchronizer()
        service = AgentService(
            sync,
            full_resync_enabled=True,
            report_interval=5,
            resync_interval=10,
            clock=clock,
        )
        service.initialize()
        clock.advance(10)

        result = service.run_once()

        self.assertEqual(2, sync.resync_calls)
        self.assertEqual(2, sync.heartbeat_calls)
        self.assertEqual(2, result["snapshot"]["generation"])
        self.assertEqual(15, service.next_report_at)
        self.assertEqual(20, service.next_resync_at)

    def test_full_resync_degraded_uses_exponential_backoff(self):
        clock = FakeClock()
        sync = DegradedSynchronizer()
        service = AgentService(
            sync,
            full_resync_enabled=True,
            report_interval=5,
            resync_interval=60,
            resync_backoff_initial=3,
            resync_backoff_max=10,
            clock=clock,
        )

        first = service.initialize()
        self.assertTrue(first["status"]["degraded"])
        self.assertEqual(3, service.current_resync_backoff)
        self.assertEqual(3, service.next_resync_at)

        clock.advance(3)
        service.run_once()
        self.assertEqual(6, service.current_resync_backoff)
        self.assertEqual(9, service.next_resync_at)

        clock.advance(6)
        service.run_once()
        self.assertEqual(10, service.current_resync_backoff)
        self.assertEqual(19, service.next_resync_at)

    def test_heartbeat_only_rpc_events_do_not_write_locally(self):
        clock = FakeClock()
        sync = FakeSynchronizer()
        merger = EventMerger(clock=clock)
        service = AgentService(
            sync,
            full_resync_enabled=False,
            report_interval=5,
            resync_interval=60,
            event_merger=merger,
            event_merge_interval=0.2,
            clock=clock,
        )
        service.initialize()

        merger.record_port_update("p1", binding_host="compute-1.example.test")
        clock.advance(0.2)
        result = service.run_once()

        self.assertEqual(0, sync.resync_calls)
        self.assertEqual([], sync.delete_calls)
        self.assertEqual(EVENTS_WITHOUT_RESYNC_REASON, result["status"]["reason"])

    def test_local_port_update_event_triggers_one_full_resync_after_window(self):
        clock = FakeClock()
        sync = FakeSynchronizer()
        merger = EventMerger(clock=clock)
        service = AgentService(
            sync,
            full_resync_enabled=True,
            report_interval=5,
            resync_interval=60,
            event_merger=merger,
            event_merge_interval=0.2,
            clock=clock,
        )
        service.initialize()

        merger.record_port_update("p1", binding_host="compute-1.example.test")
        merger.record_port_update("p2", binding_host="compute-1.example.test")
        self.assertEqual(None, service.run_once())
        clock.advance(0.2)
        result = service.run_once()

        self.assertEqual(2, sync.resync_calls)
        self.assertEqual(2, result["snapshot"]["generation"])
        self.assertEqual(["p1", "p2"], result["events"]["port_updates"])
        self.assertEqual(
            ["full_resync", "full_resync"],
            [decision["action"] for decision in result["events"]["decisions"]],
        )
        self.assertEqual(
            [{"action": "full_resync", "reason": "local_port_update", "count": 2}],
            result["status"]["last_event_decision_counts"],
        )

    def test_incremental_rpc_single_local_port_update_uses_port_scoped_apply(self):
        clock = FakeClock()
        sync = FakeSynchronizer()
        merger = EventMerger(clock=clock)
        service = AgentService(
            sync,
            full_resync_enabled=True,
            report_interval=5,
            resync_interval=60,
            event_merger=merger,
            event_merge_interval=0.2,
            incremental_rpc_enabled=True,
            clock=clock,
        )
        service.initialize()

        merger.record_port_update(
            "p1",
            binding_host="compute-1.example.test",
            revision_number=8,
        )
        clock.advance(0.2)
        result = service.run_once()

        self.assertEqual(1, sync.resync_calls)
        self.assertEqual(1, len(sync.scoped_calls))
        self.assertFalse(sync.scoped_calls[0]["allow_revisionless"])
        self.assertEqual("p1", sync.scoped_calls[0]["port_id"])
        self.assertTrue(result["events"]["incremental_submitted"])
        self.assertEqual(
            "port_scoped_apply",
            result["events"]["decisions"][0]["action"],
        )
        self.assertEqual(2, result["snapshot"]["generation"])
        self.assertEqual(
            [{"action": "port_scoped_apply", "reason": "local_port_update", "count": 1}],
            result["status"]["last_event_decision_counts"],
        )
        self.assertEqual(
            "port_scoped_apply",
            result["heartbeat"]["status"]["last_event_decisions"][0]["action"],
        )

    def test_incremental_rpc_unknown_revision_falls_back_by_default(self):
        clock = FakeClock()
        sync = FakeSynchronizer()
        merger = EventMerger(clock=clock)
        service = AgentService(
            sync,
            full_resync_enabled=True,
            report_interval=5,
            resync_interval=60,
            event_merger=merger,
            event_merge_interval=0.2,
            incremental_rpc_enabled=True,
            clock=clock,
        )
        service.initialize()

        merger.record_port_update("p1", binding_host="compute-1.example.test")
        clock.advance(0.2)
        result = service.run_once()

        decision = result["events"]["decisions"][0]
        self.assertEqual([], sync.scoped_calls)
        self.assertEqual(2, sync.resync_calls)
        self.assertEqual("fallback_full_resync", decision["incremental_action"])
        self.assertEqual("revision_unknown", decision["incremental_reason"])

    def test_incremental_rpc_unknown_revision_experimental_uses_port_scoped_apply(self):
        clock = FakeClock()
        sync = FakeSynchronizer()
        merger = EventMerger(clock=clock)
        service = AgentService(
            sync,
            full_resync_enabled=True,
            report_interval=5,
            resync_interval=60,
            event_merger=merger,
            event_merge_interval=0.2,
            incremental_rpc_enabled=True,
            revisionless_incremental_mode="experimental",
            clock=clock,
        )
        service.initialize()

        merger.record_port_update("p1", binding_host="compute-1.example.test")
        clock.advance(0.2)
        result = service.run_once()

        decision = result["events"]["decisions"][0]
        self.assertEqual(1, sync.resync_calls)
        self.assertEqual(1, len(sync.scoped_calls))
        self.assertTrue(sync.scoped_calls[0]["allow_revisionless"])
        self.assertEqual("port_scoped_apply", decision["action"])
        self.assertEqual("experimental", decision["incremental_revisionless_mode"])

    def test_incremental_rpc_same_revision_falls_back_even_when_experimental(self):
        clock = FakeClock()
        sync = FakeSynchronizer()
        sync.forced_revision_status = "same"
        merger = EventMerger(clock=clock)
        service = AgentService(
            sync,
            full_resync_enabled=True,
            report_interval=5,
            resync_interval=60,
            event_merger=merger,
            event_merge_interval=0.2,
            incremental_rpc_enabled=True,
            revisionless_incremental_mode="experimental",
            clock=clock,
        )
        service.initialize()

        merger.record_port_update(
            "p1",
            binding_host="compute-1.example.test",
            revision_number=8,
        )
        clock.advance(0.2)
        result = service.run_once()

        decision = result["events"]["decisions"][0]
        self.assertEqual([], sync.scoped_calls)
        self.assertEqual(2, sync.resync_calls)
        self.assertEqual("fallback_full_resync", decision["incremental_action"])
        self.assertEqual("revision_not_newer", decision["incremental_reason"])

    def test_incremental_rpc_scoped_apply_exception_falls_back_to_full_resync(self):
        clock = FakeClock()
        sync = FakeSynchronizer()
        sync.scoped_exception = RuntimeError("uds boom")
        merger = EventMerger(clock=clock)
        service = AgentService(
            sync,
            full_resync_enabled=True,
            report_interval=5,
            resync_interval=60,
            event_merger=merger,
            event_merge_interval=0.2,
            incremental_rpc_enabled=True,
            clock=clock,
        )
        service.initialize()

        merger.record_port_update(
            "p1",
            binding_host="compute-1.example.test",
            revision_number=8,
        )
        clock.advance(0.2)
        result = service.run_once()

        decision = result["events"]["decisions"][0]
        self.assertEqual(1, len(sync.scoped_calls))
        self.assertEqual(2, sync.resync_calls)
        self.assertTrue(result["resync_attempted"])
        self.assertEqual("fallback_full_resync", decision["incremental_action"])
        self.assertEqual("port_scoped_apply_error", decision["incremental_reason"])
        self.assertIn("uds boom", decision["incremental_error"])

    def test_incremental_rpc_scoped_apply_skip_falls_back_to_full_resync(self):
        clock = FakeClock()
        sync = FakeSynchronizer()
        sync.scoped_result = {
            "submitted": False,
            "skipped_reason": "port_not_available_for_host",
            "snapshot": None,
        }
        merger = EventMerger(clock=clock)
        service = AgentService(
            sync,
            full_resync_enabled=True,
            report_interval=5,
            resync_interval=60,
            event_merger=merger,
            event_merge_interval=0.2,
            incremental_rpc_enabled=True,
            clock=clock,
        )
        service.initialize()

        merger.record_port_update(
            "p1",
            binding_host="compute-1.example.test",
            revision_number=8,
        )
        clock.advance(0.2)
        result = service.run_once()

        decision = result["events"]["decisions"][0]
        self.assertEqual(1, len(sync.scoped_calls))
        self.assertEqual(2, sync.resync_calls)
        self.assertTrue(result["resync_attempted"])
        self.assertEqual("fallback_full_resync", decision["incremental_action"])
        self.assertEqual("port_not_available_for_host", decision["incremental_reason"])

    def test_incremental_rpc_multi_port_update_falls_back_to_full_resync(self):
        clock = FakeClock()
        sync = FakeSynchronizer()
        merger = EventMerger(clock=clock)
        service = AgentService(
            sync,
            full_resync_enabled=True,
            report_interval=5,
            resync_interval=60,
            event_merger=merger,
            event_merge_interval=0.2,
            incremental_rpc_enabled=True,
            clock=clock,
        )
        service.initialize()

        merger.record_port_update("p1", binding_host="compute-1.example.test")
        merger.record_port_update("p2", binding_host="compute-1.example.test")
        clock.advance(0.2)
        result = service.run_once()

        self.assertEqual([], sync.scoped_calls)
        self.assertEqual(2, sync.resync_calls)
        self.assertEqual(2, result["snapshot"]["generation"])

    def test_incremental_rpc_update_with_delete_falls_back_to_full_resync(self):
        clock = FakeClock()
        sync = FakeSynchronizer()
        merger = EventMerger(clock=clock)
        service = AgentService(
            sync,
            full_resync_enabled=True,
            report_interval=5,
            resync_interval=60,
            event_merger=merger,
            event_merge_interval=0.2,
            incremental_rpc_enabled=True,
            clock=clock,
        )
        service.initialize()

        merger.record_port_update("p1", binding_host="compute-1.example.test")
        merger.record_port_delete("p2")
        clock.advance(0.2)
        result = service.run_once()

        self.assertEqual([], sync.scoped_calls)
        self.assertEqual(2, sync.resync_calls)
        self.assertEqual(2, result["snapshot"]["generation"])

    def test_remote_port_update_for_unknown_port_is_ignored_after_merge(self):
        clock = FakeClock()
        sync = FakeSynchronizer()
        merger = EventMerger(clock=clock)
        service = AgentService(
            sync,
            full_resync_enabled=True,
            report_interval=5,
            resync_interval=60,
            event_merger=merger,
            event_merge_interval=0.2,
            clock=clock,
        )
        service.initialize()

        merger.record_port_update("p1", binding_host="compute-2.example.test")
        clock.advance(0.2)
        result = service.run_once()

        self.assertEqual(1, sync.resync_calls)
        self.assertEqual([], sync.delete_calls)
        self.assertEqual(None, result["snapshot"])
        self.assertEqual("ignore", result["events"]["decisions"][0]["action"])
        self.assertEqual(
            "foreign_host_update_for_unknown_port",
            result["status"]["last_event_decisions"][0]["reason"],
        )

    def test_remote_port_update_for_known_port_deletes_local_state(self):
        clock = FakeClock()
        sync = FakeSynchronizer()
        merger = EventMerger(clock=clock)
        service = AgentService(
            sync,
            full_resync_enabled=True,
            report_interval=5,
            resync_interval=60,
            event_merger=merger,
            event_merge_interval=0.2,
            clock=clock,
        )
        service.initialize()
        sync.projected_port_ids.add("p1")

        merger.record_port_update("p1", binding_host="compute-2.example.test")
        clock.advance(0.2)
        result = service.run_once()

        self.assertEqual(1, sync.resync_calls)
        self.assertEqual(["p1"], sync.delete_calls)
        self.assertEqual(["migration_source_cleanup"], sync.delete_reasons)
        self.assertEqual(None, result["snapshot"])
        self.assertEqual("delete_local", result["events"]["decisions"][0]["action"])
        self.assertEqual(
            [{"action": "delete_local", "reason": "foreign_host_update_for_projected_port", "count": 1}],
            result["status"]["last_event_decision_counts"],
        )

    def test_port_delete_deletes_only_known_local_port(self):
        clock = FakeClock()
        sync = FakeSynchronizer()
        merger = EventMerger(clock=clock)
        service = AgentService(
            sync,
            full_resync_enabled=True,
            report_interval=5,
            resync_interval=60,
            event_merger=merger,
            event_merge_interval=0.2,
            clock=clock,
        )
        service.initialize()
        sync.projected_port_ids.add("p1")

        merger.record_port_delete("p1")
        merger.record_port_delete("p2")
        clock.advance(0.2)
        result = service.run_once()

        self.assertEqual(["p1"], sync.delete_calls)
        self.assertEqual(["port_delete_event"], sync.delete_reasons)
        self.assertEqual(None, result["snapshot"])
        self.assertEqual(
            ["delete_local", "ignore"],
            [decision["action"] for decision in result["events"]["decisions"]],
        )
        self.assertEqual(2, len(result["status"]["last_event_decision_counts"]))

    def test_network_update_triggers_full_resync(self):
        clock = FakeClock()
        sync = FakeSynchronizer()
        merger = EventMerger(clock=clock)
        service = AgentService(
            sync,
            full_resync_enabled=True,
            report_interval=5,
            resync_interval=60,
            event_merger=merger,
            event_merge_interval=0.2,
            clock=clock,
        )
        service.initialize()

        merger.record_network_update("net1")
        clock.advance(0.2)
        result = service.run_once()

        self.assertEqual(2, sync.resync_calls)
        self.assertEqual(["net1"], result["events"]["dirty_networks"])
        self.assertEqual("full_resync", result["events"]["decisions"][0]["action"])

    def test_aria_acl_domain_event_triggers_one_full_resync_after_window(self):
        clock = FakeClock()
        sync = FakeSynchronizer()
        merger = EventMerger(clock=clock)
        service = AgentService(
            sync,
            full_resync_enabled=True,
            report_interval=5,
            resync_interval=60,
            event_merger=merger,
            event_merge_interval=0.2,
            clock=clock,
        )
        service.initialize()

        merger.record_domain_update(
            domain="acl",
            resource="policy",
            operation="update",
            resource_id="policy-1",
            revision_number=3,
        )
        merger.record_domain_update(
            domain="acl",
            resource="rule",
            operation="create",
            resource_id="rule-1",
            revision_number=1,
        )
        clock.advance(0.2)
        result = service.run_once()

        self.assertEqual(2, sync.resync_calls)
        self.assertEqual(2, result["snapshot"]["generation"])
        self.assertTrue(result["events"]["full_resync"])
        self.assertIn(
            "aria_domain_update:acl:policy:update:policy-1",
            result["events"]["reasons"],
        )
        self.assertIn(
            "aria_domain_update:acl:rule:create:rule-1",
            result["events"]["reasons"],
        )
        self.assertEqual([], result["events"]["port_updates"])
        self.assertEqual([], result["events"]["dirty_networks"])

    def test_rpc_event_loop_caps_idle_sleep_to_poll_for_new_events(self):
        clock = FakeClock()
        sync = FakeSynchronizer()
        merger = EventMerger(clock=clock)
        service = AgentService(
            sync,
            full_resync_enabled=True,
            report_interval=3600,
            resync_interval=3600,
            event_merger=merger,
            event_merge_interval=0.2,
            clock=clock,
        )
        service.initialize()

        self.assertEqual(EVENT_IDLE_POLL_INTERVAL, service.sleep_interval())


class StatusContractServiceRedTestCase(unittest.TestCase):
    def test_scoped_contract_error_never_falls_back_to_full_resync(self):
        scenario = status_scenario("unknown-v1-contract")
        clock = FakeClock()
        sync = FakeSynchronizer()
        sync.scoped_exception = LocalApiContractError(
            "unsupported status contract scenario %s" % scenario["id"]
        )
        merger = EventMerger(clock=clock)
        service = AgentService(
            sync,
            full_resync_enabled=True,
            report_interval=5,
            resync_interval=60,
            event_merger=merger,
            event_merge_interval=0.2,
            incremental_rpc_enabled=True,
            clock=clock,
        )
        service.initialize()
        initial_resync_calls = sync.resync_calls
        initial_heartbeat_calls = sync.heartbeat_calls
        initial_delete_calls = list(sync.delete_calls)
        merger.record_port_update(
            "p1",
            binding_host="compute-1.example.test",
            revision_number=8,
        )
        clock.advance(0.2)

        result = service.run_once()
        decisions = result["events"]["decisions"]

        self.assertEqual(1, len(sync.scoped_calls))
        self.assertEqual(initial_resync_calls, sync.resync_calls)
        self.assertEqual(initial_delete_calls, sync.delete_calls)
        self.assertEqual(initial_heartbeat_calls + 1, sync.heartbeat_calls)
        self.assertEqual(None, result["snapshot"])
        self.assertEqual(None, result["response"])
        self.assertTrue(result["status"]["degraded"])
        self.assertFalse(result["status"]["ready"])
        self.assertEqual(
            "blocked",
            scenario["expected_python"]["publish_readiness"],
        )
        self.assertEqual("local_api_contract_error", result["status"]["reason"])
        self.assertIn(scenario["id"], result["status"]["last_error"])
        self.assertTrue(result["heartbeat"]["ok"])
        self.assertTrue(result["heartbeat"]["status"]["degraded"])
        self.assertEqual(1, len(decisions))
        self.assertEqual(
            "blocked_contract_error",
            decisions[0]["incremental_action"],
        )
        self.assertEqual(
            "local_api_contract_error",
            decisions[0]["incremental_reason"],
        )
        self.assertIn(scenario["id"], decisions[0]["incremental_error"])
        self.assertFalse(result.get("resync_attempted", False))


if __name__ == "__main__":
    unittest.main()
