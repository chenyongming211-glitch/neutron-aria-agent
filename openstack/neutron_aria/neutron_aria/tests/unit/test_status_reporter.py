from __future__ import absolute_import

import unittest

from neutron_aria.agent.status import AgentRuntimeStatus
from neutron_aria.agent.status import ARIA_AGENT_TYPE
from neutron_aria.agent.config import AgentConfig
from neutron_aria.agent.status_reporter import AriaAclPortStatusReporter
from neutron_aria.agent.status_reporter import CompositeStatusReporter
from neutron_aria.agent.status_reporter import NeutronStatusReporter
from neutron_aria.agent.status_reporter import StatusReportError
from neutron_aria.agent.status_reporter import build_neutron_status_reporter
from neutron_aria.agent.status_reporter import report_state_topic


class FakeReportStateApi(object):
    def __init__(self):
        self.calls = []

    def report_state(self, context, agent_state, use_call=False):
        self.calls.append((context, agent_state, use_call))


class FailingReportStateApi(object):
    def report_state(self, context, agent_state, use_call=False):
        raise RuntimeError("message bus unavailable")


class FakeAriaAclApi(object):
    def __init__(self):
        self.statuses = []

    def report_aria_acl_port_status(self, context, body):
        self.statuses.append((context, body))
        return body


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
        self.assertEqual(12, agent_state["configurations"]["last_submitted_generation"])
        self.assertEqual(12, agent_state["configurations"]["accepted_generation"])
        self.assertEqual(12, agent_state["configurations"]["applied_generation"])
        self.assertEqual(0, agent_state["configurations"]["generation_lag"])
        self.assertEqual(5, agent_state["configurations"]["last_snapshot_ports"])
        self.assertEqual(2, agent_state["configurations"]["last_managed_ports"])
        self.assertEqual(["acl"], agent_state["configurations"]["managed_domains"])
        self.assertEqual("br-int", agent_state["configurations"]["ovs_bridge"])

    def test_report_projects_domain_counts_and_degraded_reasons(self):
        api = FakeReportStateApi()
        runtime_status = AgentRuntimeStatus("ostack2")
        runtime_status.mark_ready(
            generation=12,
            snapshot_ports=2,
            managed_ports=2,
            port_statuses=[{
                "port_id": "port-1",
                "status": "ready",
                "domains": [{"domain": "acl", "status": "ready"}],
            }, {
                "port_id": "port-2",
                "status": "degraded",
                "reason": "acl_apply_failed",
                "domains": [{
                    "domain": "acl",
                    "status": "degraded",
                    "reason": "acl_apply_failed",
                }],
            }],
            accepted_generation=12,
            applied_generation=11,
        )
        reporter = NeutronStatusReporter(api, context="ctx", host="ostack2")

        agent_state = reporter.report(runtime_status)
        configurations = agent_state["configurations"]

        self.assertEqual(1, configurations["generation_lag"])
        self.assertIn(
            {
                "domain": "acl",
                "status": "ready",
                "effective_action": "enforce",
                "count": 1,
            },
            configurations["domain_counts"],
        )
        self.assertIn(
            {
                "domain": "acl",
                "status": "degraded",
                "effective_action": "bypass",
                "count": 1,
            },
            configurations["domain_counts"],
        )
        self.assertEqual(
            [{"reason": "acl_apply_failed", "count": 1}],
            configurations["degraded_reasons"],
        )

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

    def test_port_status_reporter_writes_aria_acl_status_rows(self):
        runtime_status = AgentRuntimeStatus("ostack2")
        runtime_status.mark_ready(
            generation=12,
            snapshot_ports=1,
            managed_ports=1,
            port_statuses=[{
                "port_id": "port-1",
                "policy_id": "policy-1",
                "binding_id": "binding-1",
                "status": "ready",
                "domains": [{
                    "domain": "acl",
                    "status": "ready",
                    "effective_action": "enforce",
                    "reason": "ready",
                }],
            }],
        )
        api = FakeAriaAclApi()
        reporter = AriaAclPortStatusReporter(api, context="ctx", host="ostack2")

        result = reporter.report(runtime_status)

        self.assertEqual(1, result["reported_port_statuses"])
        self.assertEqual("ctx", api.statuses[0][0])
        payload = api.statuses[0][1]["aria_acl_port_status"]
        self.assertEqual("port-1", payload["port_id"])
        self.assertEqual("ostack2", payload["host"])
        self.assertEqual(12, payload["generation"])
        self.assertEqual("ready", payload["status"])
        self.assertEqual("policy-1", payload["effective_policy_id"])
        self.assertNotIn("policy_id", payload)
        self.assertEqual("binding-1", payload["binding_id"])
        self.assertEqual("enforce", payload["effective_action"])
        self.assertEqual("ready", payload["reason"])
        self.assertNotIn("domains", payload)
        self.assertNotIn("desired_hash", payload)
        self.assertNotIn("ifname", payload)
        self.assertNotIn("managed_domains", payload)

    def test_port_status_reporter_projects_ready_acl_to_enforce(self):
        runtime_status = AgentRuntimeStatus("ostack2")
        runtime_status.mark_ready(
            generation=12,
            snapshot_ports=1,
            managed_ports=1,
            port_statuses=[{
                "port_id": "port-1",
                "ifname": "tap-port-1",
                "desired_hash": "sha256:abc",
                "managed_domains": ["acl"],
                "domains": [{
                    "domain": "acl",
                    "status": "ready",
                    "reason": None,
                }],
            }],
        )
        api = FakeAriaAclApi()
        reporter = AriaAclPortStatusReporter(api, context="ctx", host="ostack2")

        reporter.report(runtime_status)

        payload = api.statuses[0][1]["aria_acl_port_status"]
        self.assertEqual("ready", payload["status"])
        self.assertEqual("enforce", payload["effective_action"])
        self.assertEqual("port-1", payload["port_id"])
        self.assertNotIn("ifname", payload)
        self.assertNotIn("desired_hash", payload)
        self.assertNotIn("managed_domains", payload)
        self.assertNotIn("domains", payload)

    def test_composite_reporter_preserves_heartbeat_and_port_status(self):
        runtime_status = AgentRuntimeStatus("ostack2")
        runtime_status.mark_ready(
            generation=3,
            snapshot_ports=1,
            managed_ports=1,
            port_statuses=[{"port_id": "port-1", "status": "ready"}],
        )
        report_state = FakeReportStateApi()
        aria_acl_api = FakeAriaAclApi()
        reporter = CompositeStatusReporter(
            NeutronStatusReporter(report_state, context="ctx", host="ostack2"),
            AriaAclPortStatusReporter(aria_acl_api, context="ctx", host="ostack2"),
        )

        result = reporter.report(runtime_status)

        self.assertEqual(2, len(result["results"]))
        self.assertEqual(1, len(report_state.calls))
        self.assertEqual(1, len(aria_acl_api.statuses))

    def test_build_reporter_adds_port_status_reporter_for_neutron_acl_source(self):
        report_state = FakeReportStateApi()
        aria_acl_api = FakeAriaAclApi()
        reporter = build_neutron_status_reporter(
            "ostack2",
            AgentConfig(acl_source="neutron"),
            report_state_api=report_state,
            context="ctx",
            aria_acl_api=aria_acl_api,
        )
        runtime_status = AgentRuntimeStatus("ostack2")
        runtime_status.mark_ready(
            generation=4,
            snapshot_ports=1,
            managed_ports=1,
            port_statuses=[{"port_id": "port-1", "status": "ready"}],
        )

        reporter.report(runtime_status)

        self.assertEqual(1, len(report_state.calls))
        self.assertEqual(1, len(aria_acl_api.statuses))


if __name__ == "__main__":
    unittest.main()
