from __future__ import absolute_import

import unittest

from neutron_aria.agent.service import AgentService
from neutron_aria.agent.service import HEARTBEAT_ONLY_REASON
from neutron_aria.agent.service import EVENTS_WITHOUT_RESYNC_REASON
from neutron_aria.agent.service import EVENT_IDLE_POLL_INTERVAL
from neutron_aria.agent.event_merge import EventMerger
from neutron_aria.agent.status import AgentRuntimeStatus


class FakeClock(object):
    def __init__(self, value=0):
        self.value = value

    def __call__(self):
        return self.value

    def advance(self, seconds):
        self.value += seconds


class FakeSynchronizer(object):
    def __init__(self):
        self.runtime_status = AgentRuntimeStatus("ostack2.bj159.net")
        self.resync_calls = 0
        self.heartbeat_calls = 0
        self.projected_port_ids = set()
        self.delete_calls = []
        self.delete_reasons = []
        self.host = "ostack2.bj159.net"

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

    def delete_port(self, port_id, reason=None):
        self.delete_calls.append(port_id)
        self.delete_reasons.append(reason)
        self.projected_port_ids.discard(port_id)
        return {"deleted": port_id}


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

        merger.record_port_update("p1", binding_host="ostack2.bj159.net")
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

        merger.record_port_update("p1", binding_host="ostack2.bj159.net")
        merger.record_port_update("p2", binding_host="ostack2.bj159.net")
        self.assertEqual(None, service.run_once())
        clock.advance(0.2)
        result = service.run_once()

        self.assertEqual(2, sync.resync_calls)
        self.assertEqual(2, result["snapshot"]["generation"])
        self.assertEqual(["p1", "p2"], result["events"]["port_updates"])

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

        merger.record_port_update("p1", binding_host="ostack3.bj159.net")
        clock.advance(0.2)
        result = service.run_once()

        self.assertEqual(1, sync.resync_calls)
        self.assertEqual([], sync.delete_calls)
        self.assertEqual(None, result["snapshot"])

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

        merger.record_port_update("p1", binding_host="ostack3.bj159.net")
        clock.advance(0.2)
        result = service.run_once()

        self.assertEqual(1, sync.resync_calls)
        self.assertEqual(["p1"], sync.delete_calls)
        self.assertEqual(["migration_source_cleanup"], sync.delete_reasons)
        self.assertEqual(None, result["snapshot"])

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


if __name__ == "__main__":
    unittest.main()
