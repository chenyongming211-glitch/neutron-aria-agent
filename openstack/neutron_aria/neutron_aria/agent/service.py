from __future__ import absolute_import

import logging
import time

from neutron_aria.agent.effective_acl import REVISION_NEWER
from neutron_aria.agent.effective_acl import REVISION_UNKNOWN
from neutron_aria.agent.projection import ACTION_PORT_SCOPED_APPLY
from neutron_aria.agent.projection import ACTION_DELETE_LOCAL
from neutron_aria.agent.projection import ACTION_FULL_RESYNC
from neutron_aria.agent.projection import ACTION_IGNORE
from neutron_aria.agent.projection import REASON_LOCAL_PORT_UPDATE
from neutron_aria.agent.uds_client import LocalApiContractError


LOG = logging.getLogger(__name__)


HEARTBEAT_ONLY_REASON = "full_resync_disabled"
HEARTBEAT_ONLY_ERROR = "full resync is disabled; heartbeat-only service mode"
EVENTS_WITHOUT_RESYNC_REASON = "rpc_events_full_resync_disabled"
EVENTS_WITHOUT_RESYNC_ERROR = (
    "received Neutron RPC events but full resync is disabled; no local writes submitted"
)
DELETE_PORT_DEGRADED_REASON = "delete_port_degraded"
EVENT_IDLE_POLL_INTERVAL = 1.0
REVISIONLESS_INCREMENTAL_DISABLED = "disabled"
REVISIONLESS_INCREMENTAL_EXPERIMENTAL = "experimental"


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
        incremental_rpc_enabled=False,
        revisionless_incremental_mode=REVISIONLESS_INCREMENTAL_DISABLED,
        clock=None,
        sleeper=None,
    ):
        self.synchronizer = synchronizer
        self.full_resync_enabled = bool(full_resync_enabled)
        self.incremental_rpc_enabled = bool(incremental_rpc_enabled)
        self.revisionless_incremental_mode = (
            revisionless_incremental_mode or REVISIONLESS_INCREMENTAL_DISABLED
        ).strip().lower()
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
            "resync_interval=%s event_merge_enabled=%s incremental_rpc_enabled=%s "
            "revisionless_incremental_mode=%s",
            getattr(self.synchronizer, "host", ""),
            self.full_resync_enabled,
            self.report_interval,
            self.resync_interval,
            self.event_merger is not None,
            self.incremental_rpc_enabled,
            self.revisionless_incremental_mode,
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
        resync_completed = bool(
            result.get("snapshot") is not None and
            result.get("response") is not None
        )
        if (status.get("degraded") and not resync_completed) or heartbeat_failed:
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
        last_pending_at = self.event_merger.last_pending_at()
        if last_pending_at is None:
            return None
        return last_pending_at + self.event_merge_interval

    def _process_event_batch(self):
        batch = self.event_merger.drain()
        if not batch.has_changes():
            return None
        batch_dict = batch.to_dict()
        batch_dict["decisions"] = []
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
            self._record_event_observability(batch_dict["decisions"])
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

        delete_errors = self._delete_known_ports(
            batch.deleted_ports,
            decisions=batch_dict["decisions"],
        )
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
        single_port_incremental_allowed = self._single_port_incremental_allowed(batch)
        for port_id, event in batch.port_updates.items():
            decision = self._decide_port_update(port_id, event)
            batch_dict["decisions"].append(decision)
            if decision.get("action") == ACTION_DELETE_LOCAL:
                try:
                    self.synchronizer.delete_port(
                        port_id,
                        reason=decision.get("delete_reason") or "migration_source_cleanup",
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
            if decision.get("action") == ACTION_IGNORE:
                continue
            if self._can_incremental_port_update(decision, single_port_incremental_allowed):
                result = self._apply_incremental_port_update(
                    port_id,
                    event,
                    decision,
                    batch_dict,
                )
                if result is not None:
                    return self._finalize_incremental_result(
                        result,
                        batch_dict,
                    )
            port_updates_requiring_resync[port_id] = event

        network_updates_requiring_resync = []
        for network_id in batch.dirty_networks:
            decision = self._decide_network_update(network_id)
            batch_dict["decisions"].append(decision)
            if decision.get("action") == ACTION_FULL_RESYNC:
                network_updates_requiring_resync.append(network_id)

        self._record_event_observability(batch_dict["decisions"])

        if batch.full_resync or network_updates_requiring_resync or port_updates_requiring_resync:
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

    def _single_port_incremental_allowed(self, batch):
        return bool(
            self.incremental_rpc_enabled and
            not batch.full_resync and
            not batch.overflowed and
            len(batch.port_updates) == 1 and
            not batch.deleted_ports and
            not batch.dirty_networks
        )

    def _can_incremental_port_update(self, decision, single_port_incremental_allowed):
        return bool(
            single_port_incremental_allowed and
            decision.get("action") == ACTION_FULL_RESYNC and
            decision.get("reason") == REASON_LOCAL_PORT_UPDATE and
            hasattr(self.synchronizer, "apply_port_scoped_snapshot")
        )

    def _apply_incremental_port_update(self, port_id, event, decision, batch_dict):
        if not self._revision_allows_incremental(decision):
            decision["incremental_action"] = "fallback_full_resync"
            return None
        allow_revisionless = (
            decision.get("incremental_revisionless_mode") ==
            REVISIONLESS_INCREMENTAL_EXPERIMENTAL
        )
        try:
            result = self.synchronizer.apply_port_scoped_snapshot(
                port_id,
                binding_host=event.get("binding_host"),
                revision_number=event.get("revision_number"),
                allow_revisionless=allow_revisionless,
            )
        except LocalApiContractError as exc:
            LOG.warning(
                "port_scoped_apply_contract_error host=%s port_id=%s error=%s",
                getattr(self.synchronizer, "host", ""),
                port_id,
                exc,
            )
            self.synchronizer.runtime_status.mark_degraded(
                "local_api_contract_error",
                exc,
            )
            decision["incremental_action"] = "blocked_contract_error"
            decision["incremental_reason"] = "local_api_contract_error"
            decision["incremental_error"] = str(exc)
            return {
                "snapshot": None,
                "response": None,
            }
        except Exception as exc:
            LOG.warning(
                "port_scoped_apply_fallback host=%s port_id=%s error=%s",
                getattr(self.synchronizer, "host", ""),
                port_id,
                exc,
            )
            decision["incremental_action"] = "fallback_full_resync"
            decision["incremental_reason"] = "port_scoped_apply_error"
            decision["incremental_error"] = str(exc)
            return None

        if result.get("submitted"):
            decision["action"] = ACTION_PORT_SCOPED_APPLY
            decision["incremental_action"] = ACTION_PORT_SCOPED_APPLY
            decision["generation"] = (result.get("snapshot") or {}).get("generation")
            batch_dict["incremental_submitted"] = True
            return result

        decision["incremental_action"] = "fallback_full_resync"
        decision["incremental_reason"] = (
            result.get("skipped_reason") or "port_scoped_not_submitted"
        )
        return None

    def _revision_allows_incremental(self, decision):
        revision_status = decision.get("revision_status")
        if revision_status == REVISION_NEWER:
            return True
        if (
            revision_status == REVISION_UNKNOWN and
            self.revisionless_incremental_mode == REVISIONLESS_INCREMENTAL_EXPERIMENTAL
        ):
            decision["incremental_revisionless_mode"] = (
                REVISIONLESS_INCREMENTAL_EXPERIMENTAL
            )
            return True
        if revision_status == REVISION_UNKNOWN:
            decision["incremental_reason"] = "revision_unknown"
        elif revision_status:
            decision["incremental_reason"] = "revision_not_newer"
        else:
            decision["incremental_reason"] = "revision_missing"
        return False

    def _finalize_incremental_result(self, result, batch_dict):
        self._record_event_observability(batch_dict["decisions"])
        result["events"] = batch_dict
        result["incremental_attempted"] = True
        result["status"] = self.synchronizer.runtime_status.to_dict()
        result["heartbeat"] = self.synchronizer.report_status()
        return result

    def _delete_known_ports(self, port_ids, decisions=None):
        errors = []
        for port_id in port_ids:
            decision = self._decide_port_delete(port_id)
            if decisions is not None:
                decisions.append(decision)
            if decision.get("action") == ACTION_IGNORE:
                continue
            try:
                self.synchronizer.delete_port(
                    port_id,
                    reason=decision.get("delete_reason") or "port_delete_event",
                )
            except Exception as exc:
                errors.append("%s:%s" % (port_id, exc))
        return errors

    def _decide_port_update(self, port_id, event):
        if hasattr(self.synchronizer, "decide_port_update"):
            return self._decision_to_dict(self.synchronizer.decide_port_update(
                port_id,
                binding_host=event.get("binding_host"),
                revision_number=event.get("revision_number"),
            ))
        binding_host = event.get("binding_host")
        if binding_host and binding_host != self.synchronizer.host:
            if self.synchronizer.has_projected_port(port_id):
                return {
                    "action": ACTION_DELETE_LOCAL,
                    "reason": "foreign_host_update_for_projected_port",
                    "port_id": port_id,
                    "delete_reason": "migration_source_cleanup",
                }
            return {
                "action": ACTION_IGNORE,
                "reason": "foreign_host_update_for_unknown_port",
                "port_id": port_id,
            }
        return {
            "action": ACTION_FULL_RESYNC,
            "reason": "local_port_update",
            "port_id": port_id,
            "revision_status": "unknown_projected_revision",
        }

    def _decide_port_delete(self, port_id):
        if hasattr(self.synchronizer, "decide_port_delete"):
            return self._decision_to_dict(self.synchronizer.decide_port_delete(port_id))
        if self.synchronizer.has_projected_port(port_id):
            return {
                "action": ACTION_DELETE_LOCAL,
                "reason": "local_port_delete",
                "port_id": port_id,
                "delete_reason": "port_delete_event",
            }
        return {
            "action": ACTION_IGNORE,
            "reason": "unknown_port_delete",
            "port_id": port_id,
        }

    def _decide_network_update(self, network_id):
        if hasattr(self.synchronizer, "decide_network_update"):
            return self._decision_to_dict(self.synchronizer.decide_network_update(network_id))
        return {
            "action": ACTION_FULL_RESYNC,
            "reason": "network_update",
            "network_id": network_id,
        }

    def _decision_to_dict(self, decision):
        if hasattr(decision, "to_dict"):
            return decision.to_dict()
        return dict(decision or {})

    def _record_event_observability(self, decisions):
        runtime_status = getattr(self.synchronizer, "runtime_status", None)
        if runtime_status is None:
            return
        projection_summary = getattr(self.synchronizer, "projection_summary", None)
        if projection_summary is not None:
            runtime_status.update_projection_summary(projection_summary())
        if hasattr(runtime_status, "record_event_decisions"):
            runtime_status.record_event_decisions(decisions)
