from __future__ import absolute_import

import threading
import time


EVENT_QUEUE_OVERFLOW = "event_queue_overflow"


def _coerce_revision(value):
    if value in (None, ""):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


class MergedEventBatch(object):
    def __init__(
        self,
        port_updates=None,
        deleted_ports=None,
        dirty_networks=None,
        full_resync=False,
        reasons=None,
        overflowed=False,
    ):
        self.port_updates = port_updates or {}
        self.deleted_ports = list(deleted_ports or [])
        self.dirty_networks = list(dirty_networks or [])
        self.full_resync = bool(full_resync)
        self.reasons = list(reasons or [])
        self.overflowed = bool(overflowed)

    def has_changes(self):
        return bool(
            self.full_resync or
            self.port_updates or
            self.deleted_ports or
            self.dirty_networks
        )

    def needs_full_resync(self):
        return bool(self.full_resync or self.port_updates or self.dirty_networks)

    def to_dict(self):
        return {
            "port_updates": sorted(self.port_updates.keys()),
            "deleted_ports": list(self.deleted_ports),
            "dirty_networks": list(self.dirty_networks),
            "full_resync": self.full_resync,
            "reasons": list(self.reasons),
            "overflowed": self.overflowed,
        }


class EventMerger(object):
    """Merge Neutron RPC bursts before they drive snapshot submission."""

    def __init__(
        self,
        max_pending_ports=10000,
        max_pending_networks=1000,
        clock=None,
    ):
        self.max_pending_ports = max(1, int(max_pending_ports))
        self.max_pending_networks = max(1, int(max_pending_networks))
        self.clock = clock or time.time
        self._lock = threading.Lock()
        self._port_updates = {}
        self._deleted_ports = set()
        self._dirty_networks = set()
        self._full_resync = False
        self._reasons = []
        self._overflowed = False
        self._first_pending_at = None
        self._last_pending_at = None

    def record_port_update(self, port_id, binding_host=None, revision_number=None):
        if not port_id:
            self.request_full_resync("port_update_missing_port_id")
            return
        with self._lock:
            revision = _coerce_revision(revision_number)
            existing = self._port_updates.get(port_id)
            if existing is not None:
                old_revision = _coerce_revision(existing.get("revision_number"))
                if old_revision is not None and revision is not None:
                    if revision < old_revision:
                        return
            self._mark_pending_locked()
            self._deleted_ports.discard(port_id)
            self._port_updates[port_id] = {
                "port_id": port_id,
                "binding_host": binding_host,
                "revision_number": revision,
            }
            self._check_overflow_locked()

    def record_port_delete(self, port_id):
        if not port_id:
            self.request_full_resync("port_delete_missing_port_id")
            return
        with self._lock:
            self._mark_pending_locked()
            self._port_updates.pop(port_id, None)
            self._deleted_ports.add(port_id)
            self._check_overflow_locked()

    def record_network_update(self, network_id):
        with self._lock:
            self._mark_pending_locked()
            if network_id:
                self._dirty_networks.add(network_id)
                self._reasons.append("network_update:%s" % network_id)
            else:
                self._full_resync = True
                self._reasons.append("network_update_missing_network_id")
            self._check_overflow_locked()

    def record_domain_update(
        self,
        domain,
        resource=None,
        operation=None,
        resource_id=None,
        target_type=None,
        target_id=None,
        revision_number=None,
    ):
        domain = _normalize_reason_part(domain)
        if not domain:
            self.request_full_resync("aria_domain_update_missing_domain")
            return
        resource = _normalize_reason_part(resource) or "unknown"
        operation = _normalize_reason_part(operation) or "update"
        reason_id = resource_id or target_id or "unknown"
        self.request_full_resync(
            "aria_domain_update:%s:%s:%s:%s" % (
                domain,
                resource,
                operation,
                reason_id,
            )
        )

    def request_full_resync(self, reason):
        with self._lock:
            self._mark_pending_locked()
            self._full_resync = True
            if reason:
                self._reasons.append(str(reason))

    def has_pending(self):
        with self._lock:
            return self._has_pending_locked()

    def first_pending_at(self):
        with self._lock:
            return self._first_pending_at

    def last_pending_at(self):
        with self._lock:
            return self._last_pending_at

    def ready(self, merge_interval, max_merge_delay=None):
        with self._lock:
            if not self._has_pending_locked():
                return False
            now = self.clock()
            if now >= self._last_pending_at + float(merge_interval):
                return True
            if (
                max_merge_delay is not None and
                self._first_pending_at is not None and
                now >= self._first_pending_at + float(max_merge_delay)
            ):
                return True
            return False

    def drain(self):
        with self._lock:
            batch = MergedEventBatch(
                port_updates=dict(self._port_updates),
                deleted_ports=sorted(self._deleted_ports),
                dirty_networks=sorted(self._dirty_networks),
                full_resync=self._full_resync,
                reasons=list(self._reasons),
                overflowed=self._overflowed,
            )
            self._port_updates = {}
            self._deleted_ports = set()
            self._dirty_networks = set()
            self._full_resync = False
            self._reasons = []
            self._overflowed = False
            self._first_pending_at = None
            self._last_pending_at = None
            return batch

    def _mark_pending_locked(self):
        now = self.clock()
        if self._first_pending_at is None:
            self._first_pending_at = now
        self._last_pending_at = now

    def _has_pending_locked(self):
        return bool(
            self._full_resync or
            self._port_updates or
            self._deleted_ports or
            self._dirty_networks
        )

    def _check_overflow_locked(self):
        if (
            len(self._port_updates) + len(self._deleted_ports) > self.max_pending_ports or
            len(self._dirty_networks) > self.max_pending_networks
        ):
            self._port_updates = {}
            # Deleted ports are preserved: they represent deletions that must
            # still reach the datapath, and the drain deadline bounds the set
            # size even under sustained events.
            self._dirty_networks = set()
            self._full_resync = True
            self._overflowed = True
            self._reasons.append(EVENT_QUEUE_OVERFLOW)


def _normalize_reason_part(value):
    if value in (None, ""):
        return None
    return str(value).strip().lower()
