from __future__ import absolute_import

from neutron_aria.agent.status import ARIA_AGENT_TYPE


ARIA_AGENT_BINARY = "neutron-aria-agent"
ARIA_AGENT_TOPIC = "N/A"


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
        configurations = dict(self.configurations)
        configurations.update({
            "ready": payload.get("ready"),
            "degraded": payload.get("degraded"),
            "reason": payload.get("reason"),
            "last_error": payload.get("last_error"),
            "last_generation": payload.get("last_generation"),
            "last_snapshot_ports": payload.get("last_snapshot_ports"),
            "last_managed_ports": payload.get("last_managed_ports"),
            "last_managed_ports_detail": payload.get("last_managed_ports_detail") or [],
            "last_port_statuses": payload.get("last_port_statuses") or [],
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


def report_state_topic(topics):
    return getattr(topics, "REPORTS", getattr(topics, "PLUGIN", "q-plugin"))


def build_neutron_status_reporter(host, config, report_state_api=None, context=None):
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
    }
    return NeutronStatusReporter(
        report_state_api=report_state_api,
        context=context,
        host=host,
        configurations=configurations,
    )
