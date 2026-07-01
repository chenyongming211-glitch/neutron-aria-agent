from __future__ import absolute_import

import logging
import time


LOG = logging.getLogger(__name__)


HEARTBEAT_ONLY_REASON = "full_resync_disabled"
HEARTBEAT_ONLY_ERROR = "full resync is disabled; heartbeat-only service mode"
EVENTS_WITHOUT_RESYNC_REASON = "rpc_events_full_resync_disabled"
EVENTS_WITHOUT_RESYNC_ERROR = (
    "received Neutron RPC events but full resync is disabled; no local writes submitted"
)
DELETE_PORT_DEGRADED_REASON = "delete_port_degraded"
EVENT_IDLE_POLL_INTERVAL = 1.0


class AgentService(object):
    """Long-running neutron-aria-agent service loop."""

    def __init__(
        self,
        synchronizer,
        full_resync_enabled=False,
        report_interval=30,
        resync_interval=60,
        resync_backoff_initial=5,
        resync_backoff_max=300,
        event_merger=None,
        event_merge_interval=0.2,
        clock=None,
        sleeper=None,
    ):
        self.synchronizer = synchronizer
        self.full_resync_enabled = bool(full_resync_enabled)
        self.report_interval = max(1, int(report_interval))
        self.resync_interval = max(1, int(resync_interval))
        self.resync_backoff_initial = max(1, int(resync_backoff_initial))
        self.resync_backoff_max = max(
            self.resync_backoff_initial,
            int(resync_backoff_max),
        )
        self.current_resync_backoff = 0
        self.event_merger = event_merger
        self.event_merge_interval = float(event_merge_interval)
        self.clock = clock or time.time
        self.sleeper = sleeper or time.sleep
        self.initialized = False
        self.next_report_at = 0
        self.next_resync_at = 0

    def initialize(self):
        now = self.clock()
        self.initialized = True
        LOG.info(
            "service_initialize host=%s full_resync_enabled=%s report_interval=%s "
            "resync_interval=%s event_merge_enabled=%s",
            getattr(self.synchronizer, "host", ""),
            self.full_resync_enabled,
            self.report_interval,
            self.resync_interval,
            self.event_merger is not None,
        )
        if self.full_resync_enabled:
            result = self.synchronizer.safe_full_resync()
            self.next_resync_at = now + self._next_resync_delay(result)
            self.next_report_at = now + self.report_interval
            self._log_result("initialize_full_resync", result)
            return result

        self.synchronizer.runtime_status.mark_degraded(
            HEARTBEAT_ONLY_REASON,
            HEARTBEAT_ONLY_ERROR,
        )
        heartbeat = self.synchronizer.report_status()
        self.next_report_at = now + self.report_interval
        result = {
            "snapshot": None,
            "response": None,
            "status": self.synchronizer.runtime_status.to_dict(),
            "heartbeat": heartbeat,
        }
        self._log_result("initialize_heartbeat_only", result)
        return result

    def run_once(self):
        if not self.initialized:
            return self.initialize()

        now = self.clock()
        if self._events_ready():
            result = self._process_event_batch()
            if result is None:
                return None
            if self.full_resync_enabled and result.get("resync_attempted"):
                self.next_resync_at = now + self._next_resync_delay(result)
            self.next_report_at = now + self.report_interval
            self._log_result("event_batch", result)
            return result

        if self.full_resync_enabled and now >= self.next_resync_at:
            result = self.synchronizer.safe_full_resync()
            self.next_resync_at = now + self._next_resync_delay(result)
            self.next_report_at = now + self.report_interval
            self._log_result("periodic_full_resync", result)
            return result

        if now >= self.next_report_at:
            heartbeat = self.synchronizer.report_status()
            self.next_report_at = now + self.report_interval
            result = {
                "snapshot": None,
                "response": None,
                "status": self.synchronizer.runtime_status.to_dict(),
                "heartbeat": heartbeat,
            }
            self._log_result("periodic_heartbeat", result)
            return result

        return None

    def sleep_interval(self):
        now = self.clock()
        deadlines = [self.next_report_at]
        if self.full_resync_enabled:
            deadlines.append(self.next_resync_at)
        event_deadline = self._event_deadline()
        if event_deadline is not None:
            deadlines.append(event_deadline)
        next_deadline = min([deadline for deadline in deadlines if deadline > 0])
        delay = next_deadline - now
        if delay <= 0:
            return 0
        if self.event_merger is not None and event_deadline is None:
            delay = min(delay, EVENT_IDLE_POLL_INTERVAL)
        return max(0.1, delay)

    def run_forever(self):
        self.initialize()
        while True:
            self.run_once()
            self.sleeper(self.sleep_interval())

    def _log_result(self, action, result):
        if result is None:
            return
        status = result.get("status") or {}
        heartbeat = result.get("heartbeat")
        events = result.get("events") or {}
        heartbeat_ok = heartbeat is None or heartbeat.get("ok", False)
        LOG.info(
            "service_result action=%s host=%s ready=%s degraded=%s reason=%s "
            "generation=%s snapshot_ports=%s managed_ports=%s heartbeat_ok=%s "
            "event_port_updates=%s event_deleted_ports=%s event_dirty_networks=%s "
            "event_full_resync=%s event_overflowed=%s",
            action,
            status.get("host") or getattr(self.synchronizer, "host", ""),
            status.get("ready"),
            status.get("degraded"),
            status.get("reason"),
            status.get("last_generation"),
            status.get("last_snapshot_ports"),
            status.get("last_managed_ports"),
            heartbeat_ok,
            len(events.get("port_updates") or []),
            len(events.get("deleted_ports") or []),
            len(events.get("dirty_networks") or []),
            events.get("full_resync", False),
            events.get("overflowed", False),
        )

    def _next_resync_delay(self, result):
        status = result.get("status") or {}
        heartbeat = result.get("heartbeat")
        heartbeat_failed = heartbeat is not None and not heartbeat.get("ok", False)
        if status.get("degraded") or heartbeat_failed:
            if self.current_resync_backoff:
                self.current_resync_backoff = min(
                    self.current_resync_backoff * 2,
                    self.resync_backoff_max,
                )
            else:
                self.current_resync_backoff = self.resync_backoff_initial
            return self.current_resync_backoff

        self.current_resync_backoff = 0
        return self.resync_interval

    def _events_ready(self):
        return (
            self.event_merger is not None and
            self.event_merger.ready(self.event_merge_interval)
        )

    def _event_deadline(self):
        if self.event_merger is None or not self.event_merger.has_pending():
            return None
        first_pending_at = self.event_merger.first_pending_at()
        if first_pending_at is None:
            return None
        return first_pending_at + self.event_merge_interval

    def _process_event_batch(self):
        batch = self.event_merger.drain()
        if not batch.has_changes():
            return None
        batch_dict = batch.to_dict()
        LOG.info(
            "event_batch_drained host=%s port_updates=%s deleted_ports=%s "
            "dirty_networks=%s full_resync=%s overflowed=%s reasons=%s",
            getattr(self.synchronizer, "host", ""),
            len(batch_dict["port_updates"]),
            len(batch_dict["deleted_ports"]),
            len(batch_dict["dirty_networks"]),
            batch_dict["full_resync"],
            batch_dict["overflowed"],
            ",".join(batch_dict["reasons"]),
        )

        if not self.full_resync_enabled:
            self.synchronizer.runtime_status.mark_degraded(
                EVENTS_WITHOUT_RESYNC_REASON,
                EVENTS_WITHOUT_RESYNC_ERROR,
            )
            heartbeat = self.synchronizer.report_status()
            return {
                "snapshot": None,
                "response": None,
                "status": self.synchronizer.runtime_status.to_dict(),
                "heartbeat": heartbeat,
                "events": batch_dict,
            }

        delete_errors = self._delete_known_ports(batch.deleted_ports)
        if delete_errors:
            self.synchronizer.runtime_status.mark_degraded(
                DELETE_PORT_DEGRADED_REASON,
                "; ".join(delete_errors),
            )
            heartbeat = self.synchronizer.report_status()
            return {
                "snapshot": None,
                "response": None,
                "status": self.synchronizer.runtime_status.to_dict(),
                "heartbeat": heartbeat,
                "events": batch_dict,
            }

        port_updates_requiring_resync = {}
        for port_id, event in batch.port_updates.items():
            binding_host = event.get("binding_host")
            if binding_host and binding_host != self.synchronizer.host:
                if self.synchronizer.has_projected_port(port_id):
                    try:
                        self.synchronizer.delete_port(
                            port_id,
                            reason="migration_source_cleanup",
                        )
                    except Exception as exc:
                        self.synchronizer.runtime_status.mark_degraded(
                            DELETE_PORT_DEGRADED_REASON,
                            "%s:%s" % (port_id, exc),
                        )
                        heartbeat = self.synchronizer.report_status()
                        return {
                            "snapshot": None,
                            "response": None,
                            "status": self.synchronizer.runtime_status.to_dict(),
                            "heartbeat": heartbeat,
                            "events": batch_dict,
                        }
                continue
            port_updates_requiring_resync[port_id] = event

        if batch.full_resync or batch.dirty_networks or port_updates_requiring_resync:
            result = self.synchronizer.safe_full_resync()
            result["events"] = batch_dict
            result["resync_attempted"] = True
            return result

        heartbeat = self.synchronizer.report_status()
        return {
            "snapshot": None,
            "response": None,
            "status": self.synchronizer.runtime_status.to_dict(),
            "heartbeat": heartbeat,
            "events": batch_dict,
        }

    def _delete_known_ports(self, port_ids):
        errors = []
        for port_id in port_ids:
            if not self.synchronizer.has_projected_port(port_id):
                continue
            try:
                self.synchronizer.delete_port(port_id, reason="port_delete_event")
            except Exception as exc:
                errors.append("%s:%s" % (port_id, exc))
        return errors
