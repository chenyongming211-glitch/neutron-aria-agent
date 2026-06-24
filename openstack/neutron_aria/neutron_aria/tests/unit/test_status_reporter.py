from __future__ import absolute_import

import unittest

from neutron_aria.agent.status import AgentRuntimeStatus
from neutron_aria.agent.status import ARIA_AGENT_TYPE
from neutron_aria.agent.status_reporter import NeutronStatusReporter
from neutron_aria.agent.status_reporter import StatusReportError
from neutron_aria.agent.status_reporter import report_state_topic


class FakeReportStateApi(object):
    def __init__(self):
        self.calls = []

    def report_state(self, context, agent_state, use_call=False):
        self.calls.append((context, agent_state, use_call))


class FailingReportStateApi(object):
    def report_state(self, context, agent_state, use_call=False):
        raise RuntimeError("message bus unavailable")


class StatusReporterTestCase(unittest.TestCase):
    def test_report_state_topic_prefers_reports_and_falls_back_to_plugin(self):
        class ModernTopics(object):
            REPORTS = "q-reports"
            PLUGIN = "q-plugin"

        class LegacyTopics(object):
            PLUGIN = "q-plugin"

        class MinimalTopics(object):
            pass

        self.assertEqual("q-reports", report_state_topic(ModernTopics))
        self.assertEqual("q-plugin", report_state_topic(LegacyTopics))
        self.assertEqual("q-plugin", report_state_topic(MinimalTopics))

    def test_report_builds_neutron_agent_state(self):
        api = FakeReportStateApi()
        runtime_status = AgentRuntimeStatus("ostack2")
        runtime_status.mark_ready(generation=12, snapshot_ports=5, managed_ports=2)
        reporter = NeutronStatusReporter(
            api,
            context="ctx",
            host="ostack2",
            configurations={
                "managed_domains": ["acl"],
                "ovs_bridge": "br-int",
                "socket_path": "/run/aria/aria-agent.sock",
            },
        )

        agent_state = reporter.report(runtime_status)

        self.assertEqual(1, len(api.calls))
        self.assertEqual("ctx", api.calls[0][0])
        self.assertEqual(agent_state, api.calls[0][1])
        self.assertFalse(api.calls[0][2])
        self.assertEqual("neutron-aria-agent", agent_state["binary"])
        self.assertEqual("ostack2", agent_state["host"])
        self.assertEqual("N/A", agent_state["topic"])
        self.assertEqual(ARIA_AGENT_TYPE, agent_state["agent_type"])
        self.assertTrue(agent_state["start_flag"])
        self.assertTrue(agent_state["configurations"]["ready"])
        self.assertFalse(agent_state["configurations"]["degraded"])
        self.assertEqual("ready", agent_state["configurations"]["reason"])
        self.assertEqual(12, agent_state["configurations"]["last_generation"])
        self.assertEqual(5, agent_state["configurations"]["last_snapshot_ports"])
        self.assertEqual(2, agent_state["configurations"]["last_managed_ports"])
        self.assertEqual(["acl"], agent_state["configurations"]["managed_domains"])
        self.assertEqual("br-int", agent_state["configurations"]["ovs_bridge"])

    def test_second_report_clears_start_flag(self):
        api = FakeReportStateApi()
        runtime_status = AgentRuntimeStatus("ostack2")
        runtime_status.mark_ready(generation=1, snapshot_ports=0, managed_ports=0)
        reporter = NeutronStatusReporter(api, context="ctx", host="ostack2")

        first = reporter.report(runtime_status)
        second = reporter.report(runtime_status)

        self.assertTrue(first["start_flag"])
        self.assertFalse(second["start_flag"])
        self.assertEqual(2, len(api.calls))

    def test_report_includes_degraded_status(self):
        api = FakeReportStateApi()
        runtime_status = AgentRuntimeStatus("ostack2")
        runtime_status.mark_degraded("local_api_degraded", "socket unavailable")
        reporter = NeutronStatusReporter(api, context="ctx", host="ostack2")

        agent_state = reporter.report(runtime_status)

        self.assertFalse(agent_state["configurations"]["ready"])
        self.assertTrue(agent_state["configurations"]["degraded"])
        self.assertEqual("local_api_degraded", agent_state["configurations"]["reason"])
        self.assertIn("socket unavailable", agent_state["configurations"]["last_error"])

    def test_report_failure_is_explicit(self):
        runtime_status = AgentRuntimeStatus("ostack2")
        reporter = NeutronStatusReporter(
            FailingReportStateApi(),
            context="ctx",
            host="ostack2",
        )

        with self.assertRaises(StatusReportError):
            reporter.report(runtime_status)


if __name__ == "__main__":
    unittest.main()
