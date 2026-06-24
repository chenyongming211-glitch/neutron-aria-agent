from __future__ import absolute_import

from neutron_aria.agent.inventory import PortInventoryBuilder
from neutron_aria.agent.status import AgentRuntimeStatus
from neutron_aria.agent.uds_client import LocalApiError


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

    def check_capabilities(self):
        return self.local_client.capabilities(required_domains=self.managed_domains)

    def full_resync(self):
        self.check_capabilities()
        ports = self._list_ports()
        interfaces = self.ovs_reader.list_interfaces()
        builder = PortInventoryBuilder(
            self.host,
            managed_domains=self.managed_domains,
            ovs_bridge=self.ovs_bridge,
        )
        snapshot = builder.build_snapshot(
            ports,
            interfaces,
            generation=self.generation_store.next(),
        )
        response = self.local_client.put_snapshot(snapshot)
        managed_ports = response.get("active_instances") or []
        self.runtime_status.mark_ready(
            snapshot["generation"],
            len(snapshot["ports"]),
            len(managed_ports),
        )
        heartbeat = self.report_status()
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
            return {
                "snapshot": None,
                "response": None,
                "status": self.runtime_status.to_dict(),
                "heartbeat": heartbeat,
            }
        except Exception as exc:
            self.runtime_status.mark_degraded("resync_degraded", exc)
            heartbeat = self.report_status()
            return {
                "snapshot": None,
                "response": None,
                "status": self.runtime_status.to_dict(),
                "heartbeat": heartbeat,
            }

    def delete_port(self, port_id):
        return self.local_client.delete_port(port_id)

    def _list_ports(self):
        if hasattr(self.port_source, "list_ports_for_host"):
            return self.port_source.list_ports_for_host()
        return self.port_source.get_ports()

    def report_status(self):
        if self.status_reporter is None:
            return None
        try:
            agent_state = self.status_reporter.report(self.runtime_status)
            return {"ok": True, "agent_state": agent_state}
        except Exception as exc:
            return {"ok": False, "error": str(exc)}
