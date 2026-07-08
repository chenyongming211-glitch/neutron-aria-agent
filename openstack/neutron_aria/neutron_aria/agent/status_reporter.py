from __future__ import absolute_import

from neutron_aria.agent.config import sync_mode
from neutron_aria.agent.status import ARIA_AGENT_TYPE


ARIA_AGENT_BINARY = "neutron-aria-agent"
ARIA_AGENT_TOPIC = "N/A"
HEARTBEAT_SAMPLE_LIMIT = 3
ARIA_ACL_PORT_STATUS_FIELDS = set([
    "port_id",
    "host",
    "effective_policy_id",
    "binding_id",
    "status",
    "reason",
    "effective_action",
    "generation",
])


class StatusReportError(Exception):
    pass


class NeutronStatusReporter(object):
    """Adapter from local Aria runtime status to Neutron report_state()."""

    def __init__(
        self,
        report_state_api,
        context,
        host,
        agent_type=ARIA_AGENT_TYPE,
        binary=ARIA_AGENT_BINARY,
        topic=ARIA_AGENT_TOPIC,
        use_call=False,
        configurations=None,
    ):
        self.report_state_api = report_state_api
        self.context = context
        self.host = host
        self.agent_type = agent_type
        self.binary = binary
        self.topic = topic
        self.use_call = use_call
        self.configurations = dict(configurations or {})
        self.start_flag = True

    def report(self, runtime_status):
        agent_state = self.build_agent_state(runtime_status)
        try:
            self.report_state_api.report_state(
                self.context,
                agent_state,
                self.use_call,
            )
        except Exception as exc:
            raise StatusReportError(str(exc))

        self.start_flag = False
        return agent_state

    def build_agent_state(self, runtime_status):
        payload = runtime_status.heartbeat_payload()
        managed_port_sample = self._compact_managed_ports(
            payload.get("last_managed_ports_detail") or [],
        )
        port_status_sample = self._compact_port_statuses(
            payload.get("last_port_statuses") or [],
        )
        event_decision_sample = self._compact_event_decisions(
            payload.get("last_event_decisions") or [],
        )
        configurations = dict(self.configurations)
        configurations.update({
            "ready": payload.get("ready"),
            "degraded": payload.get("degraded"),
            "reason": payload.get("reason"),
            "last_error": payload.get("last_error"),
            "last_generation": payload.get("last_generation"),
            "last_submitted_generation": payload.get("last_submitted_generation"),
            "accepted_generation": payload.get("accepted_generation"),
            "applied_generation": payload.get("applied_generation"),
            "generation_lag": payload.get("generation_lag"),
            "last_snapshot_ports": payload.get("last_snapshot_ports"),
            "last_managed_ports": payload.get("last_managed_ports"),
            "last_managed_ports_detail": managed_port_sample,
            "last_managed_ports_detail_truncated": (
                len(payload.get("last_managed_ports_detail") or []) >
                len(managed_port_sample)
            ),
            "last_port_statuses": port_status_sample,
            "last_port_statuses_truncated": (
                len(payload.get("last_port_statuses") or []) >
                len(port_status_sample)
            ),
            "domain_counts": payload.get("domain_counts") or [],
            "degraded_reasons": payload.get("degraded_reasons") or [],
            "projection_index": payload.get("projection_index") or {},
            "last_event_decision_counts": payload.get("last_event_decision_counts") or [],
            "last_event_decisions": event_decision_sample,
            "last_event_decisions_truncated": (
                len(payload.get("last_event_decisions") or []) >
                len(event_decision_sample)
            ),
            "last_event_decision_updated_at": payload.get("last_event_decision_updated_at"),
            "updated_at": payload.get("updated_at"),
        })

        return {
            "binary": self.binary,
            "host": self.host,
            "topic": self.topic,
            "agent_type": self.agent_type,
            "configurations": configurations,
            "start_flag": self.start_flag,
        }

    def _compact_managed_ports(self, ports):
        sample = []
        for port in list(ports or [])[:HEARTBEAT_SAMPLE_LIMIT]:
            sample.append({
                "port_id": port.get("port_id"),
                "ifname": port.get("ifname"),
                "managed_domains": port.get("managed_domains") or [],
            })
        return sample

    def _compact_port_statuses(self, statuses):
        sample = []
        for status in list(statuses or [])[:HEARTBEAT_SAMPLE_LIMIT]:
            domains = []
            for domain_status in status.get("domains") or []:
                domains.append({
                    "domain": domain_status.get("domain"),
                    "status": domain_status.get("status"),
                    "effective_action": domain_status.get("effective_action"),
                    "reason": domain_status.get("reason"),
                })
            sample.append({
                "port_id": status.get("port_id"),
                "status": status.get("status"),
                "effective_action": status.get("effective_action"),
                "reason": status.get("reason"),
                "domains": domains,
            })
        return sample

    def _compact_event_decisions(self, decisions):
        sample = []
        for decision in list(decisions or [])[:HEARTBEAT_SAMPLE_LIMIT]:
            sample.append({
                "port_id": decision.get("port_id"),
                "action": decision.get("action"),
                "reason": decision.get("reason"),
                "revision_status": decision.get("revision_status"),
            })
        return sample


class AriaAclPortStatusReporter(object):
    """Write per-port runtime status to the aria_acl service plugin/API."""

    def __init__(self, aria_acl_api, context=None, host=None):
        self.aria_acl_api = aria_acl_api
        self.context = context
        self.host = host

    def report(self, runtime_status):
        reported = []
        for status in runtime_status.last_port_statuses:
            payload = self._port_status_payload(runtime_status, status)
            self._report_one(payload)
            reported.append(payload)
        return {"reported_port_statuses": len(reported), "port_statuses": reported}

    def _port_status_payload(self, runtime_status, status):
        source = dict(status)
        payload = {}
        for key in ARIA_ACL_PORT_STATUS_FIELDS:
            if key in source:
                payload[key] = source[key]
        if "effective_policy_id" not in payload and source.get("policy_id"):
            payload["effective_policy_id"] = source.get("policy_id")
        payload.setdefault("host", self.host or runtime_status.host)
        payload.setdefault("generation", runtime_status.last_generation)
        acl_domain = self._acl_domain_status(source)
        if acl_domain:
            self._setdefault_present(payload, "status", acl_domain.get("status"))
            self._setdefault_present(
                payload,
                "effective_action",
                acl_domain.get("effective_action"),
            )
            self._setdefault_present(payload, "reason", acl_domain.get("reason"))
        payload.setdefault("status", runtime_status.reason)
        if (
            payload.get("status") == "ready" and
            not payload.get("effective_action")
        ):
            payload["effective_action"] = "enforce"
        if runtime_status.last_error and not payload.get("reason"):
            payload["reason"] = runtime_status.last_error
        return payload

    def _acl_domain_status(self, payload):
        for domain_status in payload.get("domains") or []:
            if domain_status.get("domain") == "acl":
                return domain_status
        return None

    def _setdefault_present(self, payload, key, value):
        if value is not None and key not in payload:
            payload[key] = value

    def _report_one(self, payload):
        body = {"aria_acl_port_status": payload}
        method = getattr(self.aria_acl_api, "report_aria_acl_port_status", None)
        if method is None:
            raise StatusReportError("aria_acl API does not expose report_aria_acl_port_status")
        try:
            return method(self.context, body)
        except TypeError:
            return method(payload)


class CompositeStatusReporter(object):
    def __init__(self, *reporters):
        self.reporters = [reporter for reporter in reporters if reporter is not None]

    def report(self, runtime_status):
        results = []
        for reporter in self.reporters:
            results.append(reporter.report(runtime_status))
        if len(results) == 1:
            return results[0]
        return {"results": results}


def report_state_topic(topics):
    return getattr(topics, "REPORTS", getattr(topics, "PLUGIN", "q-plugin"))


def build_neutron_status_reporter(
    host,
    config,
    report_state_api=None,
    context=None,
    aria_acl_api=None,
):
    """Build a real Neutron report_state reporter inside a Neutron runtime.

    Unit tests and smoke scripts can inject report_state_api/context directly.
    In a deployed OpenStack process, this factory imports the legacy Neutron
    runtime lazily so the package stays importable without Neutron installed.
    """
    if report_state_api is None:
        try:
            from neutron.agent import rpc as agent_rpc
            from neutron.common import topics
        except Exception as exc:
            raise StatusReportError("Neutron report_state API unavailable: %s" % exc)
        report_state_api = agent_rpc.PluginReportStateAPI(report_state_topic(topics))

    if context is None:
        try:
            from neutron import context as neutron_context
        except Exception as exc:
            raise StatusReportError("Neutron admin context unavailable: %s" % exc)
        if hasattr(neutron_context, "get_admin_context_without_session"):
            context = neutron_context.get_admin_context_without_session()
        else:
            context = neutron_context.get_admin_context()

    configurations = {
        "managed_domains": list(config.managed_domains),
        "ovs_bridge": config.ovs_bridge,
        "socket_path": config.socket_path,
        "sync_mode": sync_mode(config),
        "full_resync_enabled": bool(config.full_resync_enabled),
        "rpc_events_enabled": bool(config.rpc_events_enabled),
        "incremental_rpc_enabled": bool(config.incremental_rpc_enabled),
        "revisionless_incremental_mode": config.revisionless_incremental_mode,
        "event_merge_interval": config.event_merge_interval,
    }
    heartbeat_reporter = NeutronStatusReporter(
        report_state_api=report_state_api,
        context=context,
        host=host,
        configurations=configurations,
    )
    if getattr(config, "acl_source", None) != "neutron":
        return heartbeat_reporter

    if aria_acl_api is None:
        try:
            from neutron_aria.agent.neutron_client import build_aria_acl_client_from_env
            aria_acl_api = build_aria_acl_client_from_env()
        except Exception as exc:
            raise StatusReportError("aria_acl port-status API unavailable: %s" % exc)

    return CompositeStatusReporter(
        heartbeat_reporter,
        AriaAclPortStatusReporter(aria_acl_api, context=context, host=host),
    )
