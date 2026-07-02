from __future__ import absolute_import

from neutron_aria.agent.inventory import port_get


ACTION_FULL_RESYNC = "full_resync"
ACTION_PORT_SCOPED_APPLY = "port_scoped_apply"
ACTION_DELETE_LOCAL = "delete_local"
ACTION_IGNORE = "ignore"

REASON_LOCAL_PORT_UPDATE = "local_port_update"
REASON_UNKNOWN_LOCAL_PORT = "unknown_local_or_unbound_port_update"
REASON_FOREIGN_PROJECTED_PORT = "foreign_host_update_for_projected_port"
REASON_FOREIGN_UNKNOWN_PORT = "foreign_host_update_for_unknown_port"
REASON_LOCAL_PORT_DELETE = "local_port_delete"
REASON_UNKNOWN_PORT_DELETE = "unknown_port_delete"
REASON_NETWORK_LOCAL_PORTS = "network_update_affects_local_ports"
REASON_NETWORK_NO_LOCAL_PORTS = "network_update_no_local_ports"
REASON_NETWORK_MISSING_ID = "network_update_missing_network_id"


def _coerce_revision(value):
    if value in (None, ""):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _port_id(port):
    return port.get("id") or port.get("port_id")


def _network_id(port):
    return port.get("network_id") or port.get("network")


def _binding_host(port):
    return port_get(port, "binding:host_id")


def _revision(port):
    return _coerce_revision(port.get("revision_number"))


class ProjectedPort(object):
    """Last known local projection metadata for one Neutron port."""

    def __init__(
        self,
        port_id,
        network_id=None,
        binding_host=None,
        revision_number=None,
        generation=None,
        managed_domains=None,
    ):
        self.port_id = port_id
        self.network_id = network_id
        self.binding_host = binding_host
        self.revision_number = _coerce_revision(revision_number)
        self.generation = _coerce_revision(generation)
        self.managed_domains = list(managed_domains or [])

    def to_dict(self):
        return {
            "port_id": self.port_id,
            "network_id": self.network_id,
            "binding_host": self.binding_host,
            "revision_number": self.revision_number,
            "generation": self.generation,
            "managed_domains": list(self.managed_domains),
        }


class ProjectionDecision(object):
    """Read-only event decision. P2 maps full-resync decisions to safe resync."""

    def __init__(
        self,
        action,
        reason,
        port_id=None,
        network_id=None,
        affected_ports=None,
        revision_status=None,
        delete_reason=None,
    ):
        self.action = action
        self.reason = reason
        self.port_id = port_id
        self.network_id = network_id
        self.affected_ports = sorted(affected_ports or [])
        self.revision_status = revision_status
        self.delete_reason = delete_reason

    def to_dict(self):
        payload = {
            "action": self.action,
            "reason": self.reason,
        }
        if self.port_id:
            payload["port_id"] = self.port_id
        if self.network_id:
            payload["network_id"] = self.network_id
        if self.affected_ports:
            payload["affected_ports"] = list(self.affected_ports)
        if self.revision_status:
            payload["revision_status"] = self.revision_status
        if self.delete_reason:
            payload["delete_reason"] = self.delete_reason
        return payload


class ProjectedStateIndex(object):
    """In-memory local projection index for P3 decisions.

    This is intentionally not a WAL. The durable transaction source remains
    SnapshotStateStore; this index is rebuilt from the last accepted full
    resync and is safe to lose.
    """

    def __init__(self):
        self._ports = {}
        self._network_ports = {}

    def replace_from_resync(self, neutron_ports, snapshot, generation=None):
        snapshot_ports = snapshot.get("ports") or []
        projected_snapshot_ports = {}
        for port in snapshot_ports:
            port_id = port.get("port_id")
            if not port_id:
                continue
            if port.get("eligible") or port.get("managed_domains"):
                projected_snapshot_ports[port_id] = port

        raw_by_id = {}
        for port in neutron_ports or []:
            port_id = _port_id(port)
            if port_id:
                raw_by_id[port_id] = port

        records = {}
        for port_id, snapshot_port in projected_snapshot_ports.items():
            raw = raw_by_id.get(port_id, {})
            records[port_id] = ProjectedPort(
                port_id=port_id,
                network_id=_network_id(raw),
                binding_host=_binding_host(raw),
                revision_number=_revision(raw),
                generation=generation or snapshot.get("generation"),
                managed_domains=snapshot_port.get("managed_domains") or [],
            )
        self._replace_records(records)

    def update_from_scoped_port(self, neutron_port, snapshot_port, generation=None):
        port_id = (
            (snapshot_port or {}).get("port_id") or
            _port_id(neutron_port or {})
        )
        if not port_id:
            return
        if (snapshot_port or {}).get("eligible") or (snapshot_port or {}).get("managed_domains"):
            self._ports[port_id] = ProjectedPort(
                port_id=port_id,
                network_id=_network_id(neutron_port or {}),
                binding_host=_binding_host(neutron_port or {}),
                revision_number=_revision(neutron_port or {}),
                generation=generation,
                managed_domains=(snapshot_port or {}).get("managed_domains") or [],
            )
        else:
            self._ports.pop(port_id, None)
        self._rebuild_network_index()

    def replace_projected_ids(self, port_ids, generation=None):
        records = {}
        for port_id in port_ids or []:
            records[port_id] = ProjectedPort(
                port_id=port_id,
                generation=generation,
            )
        self._replace_records(records)

    def remove(self, port_id):
        if port_id in self._ports:
            del self._ports[port_id]
            self._rebuild_network_index()

    def has_port(self, port_id):
        return port_id in self._ports

    def port(self, port_id):
        return self._ports.get(port_id)

    def port_ids(self):
        return sorted(self._ports.keys())

    def ports_for_network(self, network_id):
        return sorted(self._network_ports.get(network_id) or [])

    def decide_port_update(self, port_id, local_host, binding_host=None, revision_number=None):
        if binding_host and binding_host != local_host:
            if self.has_port(port_id):
                return ProjectionDecision(
                    ACTION_DELETE_LOCAL,
                    REASON_FOREIGN_PROJECTED_PORT,
                    port_id=port_id,
                    delete_reason="migration_source_cleanup",
                )
            return ProjectionDecision(
                ACTION_IGNORE,
                REASON_FOREIGN_UNKNOWN_PORT,
                port_id=port_id,
            )

        projected = self.port(port_id)
        if projected is None:
            return ProjectionDecision(
                ACTION_FULL_RESYNC,
                REASON_UNKNOWN_LOCAL_PORT,
                port_id=port_id,
                revision_status="unknown_projected_revision",
            )

        return ProjectionDecision(
            ACTION_FULL_RESYNC,
            REASON_LOCAL_PORT_UPDATE,
            port_id=port_id,
            revision_status=self._revision_status(projected, revision_number),
        )

    def decide_port_delete(self, port_id):
        if self.has_port(port_id):
            return ProjectionDecision(
                ACTION_DELETE_LOCAL,
                REASON_LOCAL_PORT_DELETE,
                port_id=port_id,
                delete_reason="port_delete_event",
            )
        return ProjectionDecision(
            ACTION_IGNORE,
            REASON_UNKNOWN_PORT_DELETE,
            port_id=port_id,
        )

    def decide_network_update(self, network_id, conservative=True):
        if not network_id:
            return ProjectionDecision(
                ACTION_FULL_RESYNC,
                REASON_NETWORK_MISSING_ID,
            )
        affected = self.ports_for_network(network_id)
        if affected:
            return ProjectionDecision(
                ACTION_FULL_RESYNC,
                REASON_NETWORK_LOCAL_PORTS,
                network_id=network_id,
                affected_ports=affected,
            )
        if conservative:
            return ProjectionDecision(
                ACTION_FULL_RESYNC,
                REASON_NETWORK_NO_LOCAL_PORTS,
                network_id=network_id,
            )
        return ProjectionDecision(
            ACTION_IGNORE,
            REASON_NETWORK_NO_LOCAL_PORTS,
            network_id=network_id,
        )

    def to_dict(self):
        return {
            "ports": [
                self._ports[port_id].to_dict()
                for port_id in self.port_ids()
            ],
            "networks": {
                network_id: self.ports_for_network(network_id)
                for network_id in sorted(self._network_ports.keys())
            },
        }

    def summary(self):
        ports_with_revision = 0
        ports_with_network = 0
        for record in self._ports.values():
            if record.revision_number is not None:
                ports_with_revision += 1
            if record.network_id:
                ports_with_network += 1
        return {
            "projected_ports": len(self._ports),
            "indexed_networks": len(self._network_ports),
            "ports_with_network": ports_with_network,
            "ports_with_revision": ports_with_revision,
        }

    def _replace_records(self, records):
        self._ports = dict(records)
        self._rebuild_network_index()

    def _rebuild_network_index(self):
        self._network_ports = {}
        for port_id, record in self._ports.items():
            if not record.network_id:
                continue
            self._network_ports.setdefault(record.network_id, set()).add(port_id)

    def _revision_status(self, projected, event_revision):
        event_revision = _coerce_revision(event_revision)
        if event_revision is None or projected.revision_number is None:
            return "unknown"
        if event_revision > projected.revision_number:
            return "newer"
        if event_revision == projected.revision_number:
            return "same"
        return "older"
