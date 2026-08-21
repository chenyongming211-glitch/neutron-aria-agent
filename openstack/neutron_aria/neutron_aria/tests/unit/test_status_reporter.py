from __future__ import absolute_import

import json
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
from neutron_aria.tests.unit.status_contract_scenarios import status_scenario


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
        self.deleted_statuses = []

    def report_aria_acl_port_status(self, context, body):
        self.statuses.append((context, body))
        return body

    def delete_aria_acl_port_status(self, context, port_id, host=None):
        self.deleted_statuses.append((context, port_id, host))
        return {}


class StatusReporterTestCase(unittest.TestCase):
    def test_durable_domain_history_preserves_json_text_keys(self):
        history = json.loads(
            '{"last_feature_ready_generation_by_domain":'
            '{"acl":"42","qos":7}}'
        )
        runtime_status = AgentRuntimeStatus("compute-1")

        runtime_status.hydrate_durable_history(history)

        self.assertEqual(
            {"acl": 42, "qos": 7},
            runtime_status.last_feature_ready_generation_by_domain,
        )

    def test_durable_domain_history_ignores_empty_and_non_text_keys(self):
        runtime_status = AgentRuntimeStatus("compute-1")

        runtime_status.hydrate_durable_history({
            "last_feature_ready_generation_by_domain": {
                "acl": "42",
                "": 43,
                None: 44,
                45: 46,
            },
        })

        self.assertEqual(
            {"acl": 42},
            runtime_status.last_feature_ready_generation_by_domain,
        )

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
        runtime_status = AgentRuntimeStatus("compute-1")
        runtime_status.mark_ready(generation=12, snapshot_ports=5, managed_ports=2)
        runtime_status.update_projection_summary({
            "projected_ports": 2,
            "indexed_networks": 1,
            "ports_with_network": 2,
            "ports_with_revision": 1,
        })
        runtime_status.record_event_decisions([{
            "action": "full_resync",
            "reason": "local_port_update",
            "port_id": "p1",
        }])
        reporter = NeutronStatusReporter(
            api,
            context="ctx",
            host="compute-1",
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
        self.assertEqual("compute-1", agent_state["host"])
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
        self.assertEqual(
            {
                "projected_ports": 2,
                "indexed_networks": 1,
                "ports_with_network": 2,
                "ports_with_revision": 1,
            },
            agent_state["configurations"]["projection_index"],
        )
        self.assertEqual(
            [{"action": "full_resync", "reason": "local_port_update", "count": 1}],
            agent_state["configurations"]["last_event_decision_counts"],
        )
        self.assertEqual(["acl"], agent_state["configurations"]["managed_domains"])
        self.assertEqual("br-int", agent_state["configurations"]["ovs_bridge"])

    def test_build_reporter_includes_rpc_sync_mode_configuration(self):
        api = FakeReportStateApi()
        runtime_status = AgentRuntimeStatus("compute-1")
        runtime_status.mark_ready(generation=1, snapshot_ports=0, managed_ports=0)
        config = AgentConfig(
            full_resync_enabled=True,
            port_source="neutronclient",
            rpc_events_enabled=True,
            incremental_rpc_enabled=True,
            revisionless_incremental_mode="disabled",
            event_merge_interval=0.4,
            heartbeat_detail_mode="legacy_sample",
        )
        reporter = build_neutron_status_reporter(
            "compute-1",
            config,
            report_state_api=api,
            context="ctx",
        )

        agent_state = reporter.report(runtime_status)
        configurations = agent_state["configurations"]

        self.assertEqual("rpc_port_scoped", configurations["sync_mode"])
        self.assertTrue(configurations["full_resync_enabled"])
        self.assertTrue(configurations["rpc_events_enabled"])
        self.assertTrue(configurations["incremental_rpc_enabled"])
        self.assertEqual("disabled", configurations["revisionless_incremental_mode"])
        self.assertEqual(0.4, configurations["event_merge_interval"])
        self.assertEqual("legacy_sample", configurations["heartbeat_detail_mode"])

    def test_report_projects_domain_counts_and_degraded_reasons(self):
        api = FakeReportStateApi()
        runtime_status = AgentRuntimeStatus("compute-1")
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
        reporter = NeutronStatusReporter(api, context="ctx", host="compute-1")

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

    def test_report_preserves_agent_degraded_reason_without_port_rows(self):
        api = FakeReportStateApi()
        runtime_status = AgentRuntimeStatus("compute-1")
        runtime_status.mark_degraded(
            "resync_degraded",
            RuntimeError("neutron API timeout"),
        )
        reporter = NeutronStatusReporter(api, context="ctx", host="compute-1")

        configurations = reporter.report(runtime_status)["configurations"]

        self.assertFalse(configurations["ready"])
        self.assertTrue(configurations["degraded"])
        self.assertEqual("resync_degraded", configurations["reason"])
        self.assertEqual(
            [{"reason": "resync_degraded", "count": 1}],
            configurations["degraded_reasons"],
        )

    def test_report_uses_summary_only_heartbeat_by_default(self):
        api = FakeReportStateApi()
        runtime_status = AgentRuntimeStatus("compute-1")
        managed_ports = []
        port_statuses = []
        for i in range(1000):
            port_id = "port-%02d-00000000-0000-0000-0000-000000000000" % i
            managed_ports.append({
                "port_id": port_id,
                "ifname": "tap%02d" % i,
                "managed_domains": ["acl"],
                "ifindex": i,
            })
            port_statuses.append({
                "port_id": port_id,
                "ifname": "tap%02d" % i,
                "desired_hash": "x" * 64,
                "managed_domains": ["acl"],
                "status": "not_requested",
                "reason": "no_enabled_binding",
                "domains": [{
                    "domain": "acl",
                    "status": "not_requested",
                    "effective_action": "bypass",
                    "reason": "no_enabled_binding",
                }],
            })
        runtime_status.mark_ready(
            generation=12,
            snapshot_ports=1000,
            managed_ports=1000,
            managed_ports_detail=managed_ports,
            port_statuses=port_statuses,
        )
        reporter = NeutronStatusReporter(api, context="ctx", host="compute-1")

        agent_state = reporter.report(runtime_status)
        configurations = agent_state["configurations"]

        self.assertEqual(2, configurations["heartbeat_schema_version"])
        self.assertEqual("summary_only", configurations["heartbeat_detail_mode"])
        self.assertNotIn("last_managed_ports_detail", configurations)
        self.assertNotIn("last_managed_ports_detail_truncated", configurations)
        self.assertNotIn("last_port_statuses", configurations)
        self.assertNotIn("last_port_statuses_truncated", configurations)
        self.assertNotIn("last_event_decisions", configurations)
        self.assertNotIn("last_event_decisions_truncated", configurations)
        self.assertEqual(
            [{"reason": "no_enabled_binding", "count": 1000}],
            configurations["status_reason_counts"],
        )
        self.assertEqual([], configurations["degraded_reasons"])
        self.assertLess(len(json.dumps(configurations, sort_keys=True)), 2500)

    def test_report_can_publish_legacy_bounded_samples_during_upgrade(self):
        api = FakeReportStateApi()
        runtime_status = AgentRuntimeStatus("compute-1")
        managed_ports = []
        port_statuses = []
        event_decisions = []
        for i in range(5):
            port_id = "port-%s" % i
            managed_ports.append({
                "port_id": port_id,
                "ifname": "tap%s" % i,
                "managed_domains": ["acl"],
            })
            port_statuses.append({
                "port_id": port_id,
                "status": "ready",
                "domains": [{"domain": "acl", "status": "ready"}],
            })
            event_decisions.append({
                "port_id": port_id,
                "action": "port_scoped",
                "reason": "local_port_update",
            })
        runtime_status.mark_ready(
            generation=12,
            snapshot_ports=5,
            managed_ports=5,
            managed_ports_detail=managed_ports,
            port_statuses=port_statuses,
        )
        runtime_status.record_event_decisions(event_decisions)
        reporter = NeutronStatusReporter(
            api,
            context="ctx",
            host="compute-1",
            heartbeat_detail_mode="legacy_sample",
        )

        configurations = reporter.report(runtime_status)["configurations"]

        self.assertEqual(2, configurations["heartbeat_schema_version"])
        self.assertEqual("legacy_sample", configurations["heartbeat_detail_mode"])
        self.assertEqual(3, len(configurations["last_managed_ports_detail"]))
        self.assertTrue(configurations["last_managed_ports_detail_truncated"])
        self.assertEqual(3, len(configurations["last_port_statuses"]))
        self.assertTrue(configurations["last_port_statuses_truncated"])
        self.assertEqual(3, len(configurations["last_event_decisions"]))
        self.assertTrue(configurations["last_event_decisions_truncated"])

    def test_second_report_clears_start_flag(self):
        api = FakeReportStateApi()
        runtime_status = AgentRuntimeStatus("compute-1")
        runtime_status.mark_ready(generation=1, snapshot_ports=0, managed_ports=0)
        reporter = NeutronStatusReporter(api, context="ctx", host="compute-1")

        first = reporter.report(runtime_status)
        second = reporter.report(runtime_status)

        self.assertTrue(first["start_flag"])
        self.assertFalse(second["start_flag"])
        self.assertEqual(2, len(api.calls))

    def test_report_includes_degraded_status(self):
        api = FakeReportStateApi()
        runtime_status = AgentRuntimeStatus("compute-1")
        runtime_status.mark_degraded("local_api_degraded", "socket unavailable")
        reporter = NeutronStatusReporter(api, context="ctx", host="compute-1")

        agent_state = reporter.report(runtime_status)

        self.assertFalse(agent_state["configurations"]["ready"])
        self.assertTrue(agent_state["configurations"]["degraded"])
        self.assertEqual("local_api_degraded", agent_state["configurations"]["reason"])
        self.assertIn("socket unavailable", agent_state["configurations"]["last_error"])

    def test_global_degraded_rewrites_cached_acl_rows_to_bypass(self):
        runtime_status = AgentRuntimeStatus("compute-1")
        runtime_status.mark_ready(
            generation=12,
            snapshot_ports=1,
            managed_ports=1,
            port_statuses=[{
                "port_id": "port-1",
                "policy_id": "policy-1",
                "binding_id": "binding-1",
                "status": "ready",
                "effective_action": "enforce",
                "domains": [{
                    "domain": "acl",
                    "status": "ready",
                    "effective_action": "enforce",
                    "reason": "ready",
                }],
            }],
        )

        runtime_status.mark_degraded(
            "local_api_degraded",
            "socket unavailable",
        )

        row = runtime_status.last_port_statuses[0]
        self.assertEqual("port-1", row["port_id"])
        self.assertEqual("policy-1", row["policy_id"])
        self.assertEqual("binding-1", row["binding_id"])
        self.assertEqual("degraded", row["status"])
        self.assertEqual("bypass", row["effective_action"])
        self.assertEqual("local_api_degraded", row["reason"])
        self.assertEqual("degraded", row["domains"][0]["status"])
        self.assertEqual("bypass", row["domains"][0]["effective_action"])
        self.assertEqual("local_api_degraded", row["domains"][0]["reason"])
        self.assertIn(
            {
                "domain": "acl",
                "status": "degraded",
                "effective_action": "bypass",
                "count": 1,
            },
            runtime_status.domain_counts,
        )

    def test_report_failure_is_explicit(self):
        runtime_status = AgentRuntimeStatus("compute-1")
        reporter = NeutronStatusReporter(
            FailingReportStateApi(),
            context="ctx",
            host="compute-1",
        )

        with self.assertRaises(StatusReportError):
            reporter.report(runtime_status)

    def test_port_status_reporter_writes_aria_acl_status_rows(self):
        runtime_status = AgentRuntimeStatus("compute-1")
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
        reporter = AriaAclPortStatusReporter(api, context="ctx", host="compute-1")

        result = reporter.report(runtime_status)

        self.assertEqual(1, result["reported_port_statuses"])
        self.assertEqual("ctx", api.statuses[0][0])
        payload = api.statuses[0][1]["aria_acl_port_status"]
        self.assertEqual("port-1", payload["port_id"])
        self.assertEqual("compute-1", payload["host"])
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
        runtime_status = AgentRuntimeStatus("compute-1")
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
        reporter = AriaAclPortStatusReporter(api, context="ctx", host="compute-1")

        reporter.report(runtime_status)

        payload = api.statuses[0][1]["aria_acl_port_status"]
        self.assertEqual("ready", payload["status"])
        self.assertEqual("enforce", payload["effective_action"])
        self.assertEqual("port-1", payload["port_id"])
        self.assertNotIn("ifname", payload)
        self.assertNotIn("desired_hash", payload)
        self.assertNotIn("managed_domains", payload)
        self.assertNotIn("domains", payload)

    def test_port_status_reporter_does_not_default_enforce_without_acl_domain(self):
        runtime_status = AgentRuntimeStatus("compute-1")
        runtime_status.mark_ready(
            generation=12,
            snapshot_ports=1,
            managed_ports=1,
            port_statuses=[{
                "port_id": "port-1",
                "ifname": "tap-port-1",
                "desired_hash": "sha256:abc",
                "managed_domains": ["acl"],
                "domains": [],
            }],
        )
        api = FakeAriaAclApi()
        reporter = AriaAclPortStatusReporter(api, context="ctx", host="compute-1")

        reporter.report(runtime_status)

        payload = api.statuses[0][1]["aria_acl_port_status"]
        self.assertEqual("ready", payload["status"])
        self.assertNotIn("effective_action", payload)

    def test_port_status_reporter_retries_exact_host_delete(self):
        class FailOnceAriaAclApi(FakeAriaAclApi):
            def __init__(self):
                FakeAriaAclApi.__init__(self)
                self.attempts = 0

            def delete_aria_acl_port_status(self, context, port_id, host=None):
                self.attempts += 1
                if self.attempts == 1:
                    raise RuntimeError("status database unavailable")
                return FakeAriaAclApi.delete_aria_acl_port_status(
                    self,
                    context,
                    port_id,
                    host=host,
                )

        api = FailOnceAriaAclApi()
        reporter = AriaAclPortStatusReporter(
            api,
            context="ctx",
            host="compute-1",
        )

        with self.assertRaises(RuntimeError):
            reporter.remove_port_status("port-1")
        result = reporter.report(AgentRuntimeStatus("compute-1"))

        self.assertEqual(2, api.attempts)
        self.assertEqual(
            [("ctx", "port-1", "compute-1")],
            api.deleted_statuses,
        )
        self.assertEqual(1, result["deleted_port_statuses"])

    def test_port_status_reporter_treats_not_found_delete_as_idempotent(self):
        class NotFoundError(Exception):
            status_code = 404

        class NotFoundApi(FakeAriaAclApi):
            def delete_aria_acl_port_status(self, context, port_id, host=None):
                raise NotFoundError("aria_acl_port_status not found")

        api = NotFoundApi()
        reporter = AriaAclPortStatusReporter(
            api,
            context="ctx",
            host="compute-1",
        )

        error = None
        try:
            reporter.remove_port_status("port-1")
        except Exception as exc:
            error = exc
        self.assertIsNone(error)
        self.assertEqual([], sorted(reporter.pending_deleted_port_ids))

        runtime_status = AgentRuntimeStatus("compute-1")
        runtime_status.mark_ready(
            generation=3,
            snapshot_ports=1,
            managed_ports=1,
            port_statuses=[{"port_id": "port-1", "status": "ready"}],
        )
        result = reporter.report(runtime_status)

        self.assertEqual(0, result["deleted_port_statuses"])
        self.assertEqual(1, len(api.statuses))

    def test_port_status_reporter_flush_treats_not_found_as_idempotent(self):
        class NotFoundError(Exception):
            status_code = 404

        class FailThenNotFoundApi(FakeAriaAclApi):
            def __init__(self):
                FakeAriaAclApi.__init__(self)
                self.attempts = 0

            def delete_aria_acl_port_status(self, context, port_id, host=None):
                self.attempts += 1
                if self.attempts == 1:
                    raise RuntimeError("status database unavailable")
                raise NotFoundError("aria_acl_port_status not found")

        api = FailThenNotFoundApi()
        reporter = AriaAclPortStatusReporter(
            api,
            context="ctx",
            host="compute-1",
        )

        with self.assertRaises(RuntimeError):
            reporter.remove_port_status("port-1")

        runtime_status = AgentRuntimeStatus("compute-1")
        runtime_status.mark_ready(
            generation=3,
            snapshot_ports=1,
            managed_ports=1,
            port_statuses=[{"port_id": "port-1", "status": "ready"}],
        )
        result = reporter.report(runtime_status)

        self.assertEqual(1, result["deleted_port_statuses"])
        self.assertEqual([], sorted(reporter.pending_deleted_port_ids))
        self.assertEqual(1, len(api.statuses))

    def test_port_status_reporter_does_not_retry_report_type_error(self):
        class TypeErrorApi(object):
            def __init__(self):
                self.calls = 0

            def report_aria_acl_port_status(self, *args, **kwargs):
                self.calls += 1
                raise TypeError("response processing failed")

        api = TypeErrorApi()
        reporter = AriaAclPortStatusReporter(api, context="ctx", host="compute-1")
        runtime_status = AgentRuntimeStatus("compute-1")
        runtime_status.mark_ready(
            generation=3,
            snapshot_ports=1,
            managed_ports=1,
            port_statuses=[{"port_id": "port-1", "status": "ready"}],
        )

        with self.assertRaises(TypeError) as context:
            reporter.report(runtime_status)

        self.assertEqual("response processing failed", str(context.exception))
        self.assertEqual(1, api.calls)

    def test_port_status_reporter_does_not_retry_delete_type_error(self):
        class TypeErrorApi(object):
            def __init__(self):
                self.calls = 0

            def delete_aria_acl_port_status(self, *args, **kwargs):
                self.calls += 1
                raise TypeError("response processing failed")

        api = TypeErrorApi()
        reporter = AriaAclPortStatusReporter(api, context="ctx", host="compute-1")

        with self.assertRaises(TypeError) as context:
            reporter.remove_port_status("port-1")

        self.assertEqual("response processing failed", str(context.exception))
        self.assertEqual(1, api.calls)

    def test_port_status_reporter_uses_explicit_payload_adapter_style(self):
        class PayloadApi(object):
            ARIA_ACL_STATUS_CALL_STYLE = "payload"

            def __init__(self):
                self.reports = []
                self.deletes = []

            def report_aria_acl_port_status(self, payload):
                self.reports.append(payload)
                return payload

            def delete_aria_acl_port_status(self, port_id, host):
                self.deletes.append((port_id, host))
                return {}

        api = PayloadApi()
        reporter = AriaAclPortStatusReporter(api, context="ctx", host="compute-1")
        runtime_status = AgentRuntimeStatus("compute-1")
        runtime_status.mark_ready(
            generation=3,
            snapshot_ports=1,
            managed_ports=1,
            port_statuses=[{"port_id": "port-1", "status": "ready"}],
        )

        reporter.report(runtime_status)
        reporter.remove_port_status("port-1")

        self.assertEqual("port-1", api.reports[0]["port_id"])
        self.assertEqual([("port-1", "compute-1")], api.deletes)

    def test_port_status_reporter_rejects_unknown_adapter_style_before_write(self):
        class InvalidApi(object):
            ARIA_ACL_STATUS_CALL_STYLE = "guess"

        with self.assertRaises(StatusReportError):
            AriaAclPortStatusReporter(
                InvalidApi(),
                context="ctx",
                host="compute-1",
            )

    def test_composite_reporter_preserves_heartbeat_and_port_status(self):
        runtime_status = AgentRuntimeStatus("compute-1")
        runtime_status.mark_ready(
            generation=3,
            snapshot_ports=1,
            managed_ports=1,
            port_statuses=[{"port_id": "port-1", "status": "ready"}],
        )
        report_state = FakeReportStateApi()
        aria_acl_api = FakeAriaAclApi()
        reporter = CompositeStatusReporter(
            NeutronStatusReporter(report_state, context="ctx", host="compute-1"),
            AriaAclPortStatusReporter(aria_acl_api, context="ctx", host="compute-1"),
        )

        result = reporter.report(runtime_status)

        self.assertEqual(2, len(result["results"]))
        self.assertEqual(1, len(report_state.calls))
        self.assertEqual(1, len(aria_acl_api.statuses))

    def test_ready_composite_publishes_port_rows_before_heartbeat(self):
        order = []

        class OrderedReportStateApi(FakeReportStateApi):
            def report_state(self, context, agent_state, use_call=False):
                order.append("heartbeat")
                return FakeReportStateApi.report_state(
                    self,
                    context,
                    agent_state,
                    use_call,
                )

        class OrderedAriaAclApi(FakeAriaAclApi):
            def report_aria_acl_port_status(self, context, body):
                order.append("port")
                return FakeAriaAclApi.report_aria_acl_port_status(
                    self,
                    context,
                    body,
                )

        runtime_status = AgentRuntimeStatus("compute-1")
        runtime_status.mark_ready(
            generation=3,
            snapshot_ports=1,
            managed_ports=1,
            port_statuses=[{"port_id": "port-1", "status": "ready"}],
        )
        reporter = CompositeStatusReporter(
            NeutronStatusReporter(
                OrderedReportStateApi(),
                context="ctx",
                host="compute-1",
            ),
            AriaAclPortStatusReporter(
                OrderedAriaAclApi(),
                context="ctx",
                host="compute-1",
            ),
        )

        reporter.report(runtime_status)

        self.assertEqual(["port", "heartbeat"], order)

    def test_ready_port_failure_suppresses_new_heartbeat(self):
        report_state = FakeReportStateApi()

        class FailingAriaAclApi(object):
            def report_aria_acl_port_status(self, context, body):
                raise RuntimeError("status database unavailable")

        runtime_status = AgentRuntimeStatus("compute-1")
        runtime_status.mark_ready(
            generation=3,
            snapshot_ports=1,
            managed_ports=1,
            port_statuses=[{"port_id": "port-1", "status": "ready"}],
        )
        reporter = CompositeStatusReporter(
            NeutronStatusReporter(
                report_state,
                context="ctx",
                host="compute-1",
            ),
            AriaAclPortStatusReporter(
                FailingAriaAclApi(),
                context="ctx",
                host="compute-1",
            ),
        )

        with self.assertRaises(RuntimeError):
            reporter.report(runtime_status)

        self.assertEqual([], report_state.calls)

    def test_degraded_composite_publishes_heartbeat_before_port_rows(self):
        order = []

        class OrderedReportStateApi(FakeReportStateApi):
            def report_state(self, context, agent_state, use_call=False):
                order.append("heartbeat")
                return FakeReportStateApi.report_state(
                    self,
                    context,
                    agent_state,
                    use_call,
                )

        class OrderedAriaAclApi(FakeAriaAclApi):
            def report_aria_acl_port_status(self, context, body):
                order.append("port")
                return FakeAriaAclApi.report_aria_acl_port_status(
                    self,
                    context,
                    body,
                )

        runtime_status = AgentRuntimeStatus("compute-1")
        runtime_status.mark_ready(
            generation=3,
            snapshot_ports=1,
            managed_ports=1,
            port_statuses=[{"port_id": "port-1", "status": "ready"}],
        )
        runtime_status.mark_degraded("local_api_degraded", "socket unavailable")
        reporter = CompositeStatusReporter(
            NeutronStatusReporter(
                OrderedReportStateApi(),
                context="ctx",
                host="compute-1",
            ),
            AriaAclPortStatusReporter(
                OrderedAriaAclApi(),
                context="ctx",
                host="compute-1",
            ),
        )

        reporter.report(runtime_status)

        self.assertEqual(["heartbeat", "port"], order)

    def test_build_reporter_adds_port_status_reporter_for_neutron_acl_source(self):
        report_state = FakeReportStateApi()
        aria_acl_api = FakeAriaAclApi()
        reporter = build_neutron_status_reporter(
            "compute-1",
            AgentConfig(acl_source="neutron"),
            report_state_api=report_state,
            context="ctx",
            aria_acl_api=aria_acl_api,
        )
        runtime_status = AgentRuntimeStatus("compute-1")
        runtime_status.mark_ready(
            generation=4,
            snapshot_ports=1,
            managed_ports=1,
            port_statuses=[{"port_id": "port-1", "status": "ready"}],
        )

        reporter.report(runtime_status)

        self.assertEqual(1, len(report_state.calls))
        self.assertEqual(1, len(aria_acl_api.statuses))

    def test_build_reporter_passes_neutron_api_timeout_to_acl_client(self):
        from neutron_aria.agent import neutron_client as neutron_client_module

        calls = []
        original_factory = neutron_client_module.build_aria_acl_client_from_env

        def fake_factory(env=None, page_size=None, timeout=None):
            calls.append(timeout)
            return FakeAriaAclApi()

        neutron_client_module.build_aria_acl_client_from_env = fake_factory
        try:
            build_neutron_status_reporter(
                "compute-1",
                AgentConfig(acl_source="neutron", neutron_api_timeout=7.5),
                report_state_api=FakeReportStateApi(),
                context="ctx",
            )
        finally:
            neutron_client_module.build_aria_acl_client_from_env = original_factory

        self.assertEqual([7.5], calls)


class StatusContractStatusReporterRedTestCase(unittest.TestCase):
    def test_classified_degraded_heartbeat_preserves_feature_ready_domain_history(self):
        scenario = status_scenario("restart-classified-routing")
        history = scenario["durable_state"][
            "last_feature_ready_generation_by_domain"
        ]
        api = FakeReportStateApi()
        runtime_status = AgentRuntimeStatus("compute-1")
        try:
            runtime_status.mark_ready(
                generation=scenario["durable_state"]["last_feature_ready_generation"],
                snapshot_ports=2,
                managed_ports=2,
                desired_hash=scenario["durable_state"][
                    "last_feature_ready_desired_hash"
                ],
                feature_ready_generation_by_domain=history,
            )
        except TypeError as exc:
            self.fail(
                "mark_ready lacks feature-ready domain history: %s" % exc
            )
        runtime_status.mark_degraded(
            "classified_degraded",
            "acl_not_supported",
        )
        reporter = NeutronStatusReporter(api, context="ctx", host="compute-1")

        agent_state = reporter.report(runtime_status)
        configurations = agent_state["configurations"]

        self.assertFalse(configurations["ready"])
        self.assertTrue(configurations["degraded"])
        self.assertEqual(
            scenario["durable_state"]["last_feature_ready_generation"],
            configurations["last_generation"],
        )
        self.assertEqual(
            history,
            configurations["last_feature_ready_generation_by_domain"],
        )


class CountersReportTestCase(unittest.TestCase):
    def _runtime(self, with_counters=True):
        runtime = AgentRuntimeStatus(host="h")
        runtime.mark_ready(1, 1, 1)
        if with_counters:
            runtime.last_counters = {
                "counters_schema_version": 1,
                "sampled_at_ms": 2000,
                "ports": [{
                    "port_id": "p1", "tap_id": 7,
                    "policy_packets": 200, "policy_bytes": 2000,
                    "policy_allow_packets": 180,
                    "policy_dropped_packets": 20,
                    "policy_dropped_bytes": 200,
                    "drop_packets": 20, "drop_bytes": 200,
                    "truncated": False,
                    "buckets": [],
                    "reasons": [],
                }],
            }
        else:
            runtime.last_counters = None
        return runtime

    def test_port_counters_blob_builds_rows_when_present(self):
        from neutron_aria.agent.status_reporter import _PREVIOUS_COUNTERS
        from neutron_aria.agent.status_reporter import port_counters_blob
        _PREVIOUS_COUNTERS.pop("p1", None)
        blob = port_counters_blob(
            self._runtime(with_counters=True), "p1"
        )
        self.assertEqual(blob["counters_sampled_at_ms"], 2000)
        self.assertEqual(len(blob["counters_rows"]), 1)
        row = blob["counters_rows"][0]
        self.assertEqual(row["port_id"], "p1")
        self.assertFalse(row["reset_detected"])
        self.assertIsNone(row["drop_pps"])
        self.assertEqual(row["summary"]["policy_packets"], 200)
        self.assertEqual(row["summary"]["drop_packets"], 20)
        port_row = [r for r in row["rows"] if r["kind"] == "port"][0]
        self.assertEqual(port_row["packets"], 200)
        self.assertIsNone(port_row["pps"])

    def test_port_counters_blob_preserves_v2_family_identity(self):
        from neutron_aria.agent.status_reporter import _PREVIOUS_COUNTERS
        from neutron_aria.agent.status_reporter import port_counters_blob
        _PREVIOUS_COUNTERS.pop("p1", None)
        runtime = self._runtime(with_counters=True)
        runtime.last_counters["counters_schema_version"] = 2
        port = runtime.last_counters["ports"][0]
        port["buckets"] = [{
            "ip_family": 6, "src_id": 1, "dst_id": 2, "proto": 6,
            "direction": 0, "packets": 10, "bytes": 100,
            "dropped_packets": 1, "dropped_bytes": 10,
        }]
        port["reasons"] = [{
            "ip_family": 0, "reason": 18, "direction": 0, "proto": 0,
            "packets": 1, "bytes": 10,
        }]

        blob = port_counters_blob(runtime, "p1")
        rows = blob["counters_rows"][0]["rows"]

        bucket = [row for row in rows if row["kind"] == "bucket"][0]
        reason = [row for row in rows if row["kind"] == "reason"][0]
        self.assertEqual(bucket["key"]["ip_family"], 6)
        self.assertEqual(reason["key"]["ip_family"], 0)

    def test_port_counters_blob_is_none_without_counters(self):
        from neutron_aria.agent.status_reporter import port_counters_blob
        blob = port_counters_blob(
            self._runtime(with_counters=False), "p1"
        )
        self.assertIsNone(blob)

    def test_port_counters_blob_reports_datapath_error_marker(self):
        from neutron_aria.agent.status_reporter import port_counters_blob
        runtime = self._runtime(with_counters=True)
        runtime.last_counters = {
            "counters_schema_version": 1,
            "sampled_at_ms": 2000,
            "counters_error": "map read failed",
            "ports": [],
        }
        blob = port_counters_blob(runtime, "p1")
        self.assertEqual(blob, {"counters_error": "map read failed"})

    def test_port_counters_blob_reports_port_not_sampled(self):
        from neutron_aria.agent.status_reporter import port_counters_blob
        runtime = self._runtime(with_counters=True)
        blob = port_counters_blob(runtime, "missing-port")
        self.assertEqual(blob, {"counters_error": "port_not_sampled"})

    def test_malformed_counters_do_not_suppress_ordinary_heartbeat(self):
        runtime = self._runtime(with_counters=True)
        runtime.last_counters = {
            "counters_schema_version": 1,
            "sampled_at_ms": 2000,
            "ports": ["malformed-port-row"],
        }
        runtime.last_port_statuses = [{
            "port_id": "p1",
            "status": "ready",
            "domains": [{
                "domain": "acl",
                "status": "ready",
                "effective_action": "enforce",
            }],
        }]
        report_state = FakeReportStateApi()
        aria_acl_api = FakeAriaAclApi()
        reporter = CompositeStatusReporter(
            NeutronStatusReporter(report_state, context="ctx", host="h"),
            AriaAclPortStatusReporter(
                aria_acl_api,
                context="ctx",
                host="h",
                counters_report_enabled=True,
            ),
        )

        reporter.report(runtime)

        self.assertEqual(len(report_state.calls), 1)
        self.assertEqual(len(aria_acl_api.statuses), 1)
        payload = aria_acl_api.statuses[0][1]["aria_acl_port_status"]
        self.assertIn("invalid_counters_v1", payload["counters_error"])

    def test_port_counters_blob_diffs_drop_pps_from_summary(self):
        from neutron_aria.agent.status_reporter import _PREVIOUS_COUNTERS
        from neutron_aria.agent.status_reporter import port_counters_blob
        _PREVIOUS_COUNTERS["p1"] = {
            "sampled_at_ms": 1000,
            "drop_packets": 10,
        }
        blob = port_counters_blob(
            self._runtime(with_counters=True), "p1"
        )
        row = blob["counters_rows"][0]
        self.assertAlmostEqual(row["drop_pps"], 10.0, places=3)

    def test_rest_reporter_attaches_counters_only_when_enabled(self):
        api = FakeAriaAclApi()
        runtime = self._runtime(with_counters=True)
        runtime.last_port_statuses = [{
            "port_id": "p1",
            "status": "ready",
            "domains": [{
                "domain": "acl",
                "status": "ready",
                "effective_action": "enforce",
            }],
        }]
        disabled = AriaAclPortStatusReporter(api, context="ctx", host="h")
        disabled.report(runtime)
        self.assertNotIn(
            "counters_rows", api.statuses[0][1]["aria_acl_port_status"]
        )
        enabled = AriaAclPortStatusReporter(
            api,
            context="ctx",
            host="h",
            counters_report_enabled=True,
        )
        enabled.report(runtime)
        self.assertIn(
            "counters_rows", api.statuses[-1][1]["aria_acl_port_status"]
        )

    def test_remove_port_status_evicts_previous_counters(self):
        from neutron_aria.agent.status_reporter import _PREVIOUS_COUNTERS
        _PREVIOUS_COUNTERS["p1"] = {"sampled_at_ms": 1000}
        reporter = AriaAclPortStatusReporter(
            FakeAriaAclApi(), context="ctx", host="h"
        )
        reporter.remove_port_status("p1")
        self.assertNotIn("p1", _PREVIOUS_COUNTERS)


if __name__ == "__main__":
    unittest.main()
