from __future__ import absolute_import

import time


ARIA_AGENT_TYPE = "Aria ACL agent"


class AgentRuntimeStatus(object):
    def __init__(self, host, agent_type=ARIA_AGENT_TYPE):
        self.host = host
        self.agent_type = agent_type
        self.ready = False
        self.degraded = False
        self.reason = "not_synced"
        self.last_error = None
        self.last_generation = 0
        self.last_desired_hash = None
        self.last_snapshot_ports = 0
        self.last_managed_ports = 0
        self.last_managed_ports_detail = []
        self.last_port_statuses = []
        self.updated_at = None

    def mark_ready(
        self,
        generation,
        snapshot_ports,
        managed_ports,
        desired_hash=None,
        managed_ports_detail=None,
        port_statuses=None,
    ):
        self.ready = True
        self.degraded = False
        self.reason = "ready"
        self.last_error = None
        self.last_generation = generation
        self.last_desired_hash = desired_hash
        self.last_snapshot_ports = snapshot_ports
        self.last_managed_ports = managed_ports
        self.last_managed_ports_detail = list(managed_ports_detail or [])
        self.last_port_statuses = list(port_statuses or [])
        self.updated_at = time.time()

    def mark_degraded(self, reason, error):
        self.ready = False
        self.degraded = True
        self.reason = reason
        self.last_error = str(error)
        self.updated_at = time.time()

    def to_dict(self):
        return {
            "agent_type": self.agent_type,
            "host": self.host,
            "ready": self.ready,
            "degraded": self.degraded,
            "reason": self.reason,
            "last_error": self.last_error,
            "last_generation": self.last_generation,
            "last_desired_hash": self.last_desired_hash,
            "last_snapshot_ports": self.last_snapshot_ports,
            "last_managed_ports": self.last_managed_ports,
            "last_managed_ports_detail": list(self.last_managed_ports_detail),
            "last_port_statuses": list(self.last_port_statuses),
            "updated_at": self.updated_at,
        }

    def heartbeat_payload(self):
        payload = self.to_dict()
        payload["binary"] = "neutron-aria-agent"
        payload["topic"] = "N/A"
        return payload
