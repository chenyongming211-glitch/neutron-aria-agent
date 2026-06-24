from __future__ import absolute_import

import logging

from neutron_aria.agent.inventory import PortCandidateBuilder
from neutron_aria.agent.status import AgentRuntimeStatus
from neutron_aria.agent.uds_client import LocalApiError


LOG = logging.getLogger(__name__)


class GenerationStore(object):
    def __init__(self, initial=0):
        self.value = int(initial)

    def next(self):
        self.value += 1
        return self.value


class SnapshotSynchronizer(object):
    def __init__(
        self,
        host,
        port_source,
        ovs_reader,
        local_client,
        managed_domains=None,
        generation_store=None,
        ovs_bridge="br-int",
        runtime_status=None,
        status_reporter=None,
        acl_index=None,
    ):
        self.host = host
        self.port_source = port_source
        self.ovs_reader = ovs_reader
        self.local_client = local_client
        self.managed_domains = list(managed_domains or ["acl"])
        self.generation_store = generation_store or GenerationStore()
        self.ovs_bridge = ovs_bridge
        self.runtime_status = runtime_status or AgentRuntimeStatus(host)
        self.status_reporter = status_reporter
        self.projected_port_ids = set()
        self.acl_index = acl_index

    def check_capabilities(self):
        return self.local_client.capabilities(required_domains=self.managed_domains)

    def full_resync(self):
        self.check_capabilities()
        ports = self._list_ports()
        builder = PortCandidateBuilder(
            self.host,
            managed_domains=self.managed_domains,
            acl_index=self.acl_index,
        )
        snapshot = builder.build_snapshot(
            ports,
            generation=self.generation_store.next(),
        )
        response = self.local_client.put_snapshot(snapshot)
        self.projected_port_ids = set(
            port.get("port_id") for port in snapshot["ports"]
            if port.get("port_id") and (port.get("eligible") or port.get("managed_domains"))
        )
        managed_ports = response.get("active_instances") or []
        self.runtime_status.mark_ready(
            snapshot["generation"],
            len(snapshot["ports"]),
            len(managed_ports),
        )
        heartbeat = self.report_status()
        LOG.info(
            "full_resync_complete host=%s generation=%s snapshot_ports=%s "
            "managed_ports=%s projected_ports=%s heartbeat_ok=%s",
            self.host,
            snapshot["generation"],
            len(snapshot["ports"]),
            len(managed_ports),
            len(self.projected_port_ids),
            heartbeat is None or heartbeat.get("ok", False),
        )
        return {
            "snapshot": snapshot,
            "response": response,
            "status": self.runtime_status.to_dict(),
            "heartbeat": heartbeat,
        }

    def safe_full_resync(self):
        try:
            return self.full_resync()
        except LocalApiError as exc:
            self.runtime_status.mark_degraded("local_api_degraded", exc)
            heartbeat = self.report_status()
            LOG.warning(
                "full_resync_degraded host=%s reason=%s error=%s heartbeat_ok=%s",
                self.host,
                self.runtime_status.reason,
                self.runtime_status.last_error,
                heartbeat is None or heartbeat.get("ok", False),
            )
            return {
                "snapshot": None,
                "response": None,
                "status": self.runtime_status.to_dict(),
                "heartbeat": heartbeat,
            }
        except Exception as exc:
            self.runtime_status.mark_degraded("resync_degraded", exc)
            heartbeat = self.report_status()
            LOG.warning(
                "full_resync_degraded host=%s reason=%s error=%s heartbeat_ok=%s",
                self.host,
                self.runtime_status.reason,
                self.runtime_status.last_error,
                heartbeat is None or heartbeat.get("ok", False),
            )
            return {
                "snapshot": None,
                "response": None,
                "status": self.runtime_status.to_dict(),
                "heartbeat": heartbeat,
            }

    def delete_port(self, port_id):
        response = self.local_client.delete_port(port_id)
        self.projected_port_ids.discard(port_id)
        LOG.info(
            "delete_port_complete host=%s port_id=%s projected_ports=%s",
            self.host,
            port_id,
            len(self.projected_port_ids),
        )
        return response

    def has_projected_port(self, port_id):
        return port_id in self.projected_port_ids

    def _list_ports(self):
        if hasattr(self.port_source, "list_ports_for_host"):
            return self.port_source.list_ports_for_host()
        return self.port_source.get_ports()

    def report_status(self):
        if self.status_reporter is None:
            return None
        try:
            agent_state = self.status_reporter.report(self.runtime_status)
            LOG.info(
                "heartbeat_reported host=%s ready=%s degraded=%s reason=%s "
                "generation=%s snapshot_ports=%s managed_ports=%s",
                self.host,
                self.runtime_status.ready,
                self.runtime_status.degraded,
                self.runtime_status.reason,
                self.runtime_status.last_generation,
                self.runtime_status.last_snapshot_ports,
                self.runtime_status.last_managed_ports,
            )
            return {"ok": True, "agent_state": agent_state}
        except Exception as exc:
            LOG.warning(
                "heartbeat_report_failed host=%s reason=%s error=%s",
                self.host,
                self.runtime_status.reason,
                exc,
            )
            return {"ok": False, "error": str(exc)}
