from __future__ import absolute_import

import unittest

from neutron_aria.agent.service import AgentService
from neutron_aria.agent.service import HEARTBEAT_ONLY_REASON
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
            clock=clock,
        )

        result = service.initialize()

        self.assertEqual(1, sync.resync_calls)
        self.assertEqual(1, sync.heartbeat_calls)
        self.assertTrue(result["status"]["ready"])
        self.assertEqual(5, service.next_report_at)
        self.assertEqual(30, service.next_resync_at)

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


if __name__ == "__main__":
    unittest.main()
