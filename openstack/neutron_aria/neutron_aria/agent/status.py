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
        self.last_classified_generation = 0
        self.last_feature_ready_generation_by_domain = {}
        self.last_submitted_generation = 0
        self.accepted_generation = 0
        self.applied_generation = 0
        self.generation_lag = 0
        self.last_desired_hash = None
        self.last_snapshot_ports = 0
        self.last_managed_ports = 0
        self.last_managed_ports_detail = []
        self.last_port_statuses = []
        self.domain_counts = []
        self.degraded_reasons = []
        self.projection_index = {
            "projected_ports": 0,
            "indexed_networks": 0,
            "ports_with_network": 0,
            "ports_with_revision": 0,
        }
        self.last_event_decision_counts = []
        self.last_event_decisions = []
        self.last_event_decision_updated_at = None
        self.updated_at = None

    def mark_ready(
        self,
        generation,
        snapshot_ports,
        managed_ports,
        desired_hash=None,
        managed_ports_detail=None,
        port_statuses=None,
        accepted_generation=None,
        applied_generation=None,
        feature_ready_generation_by_domain=None,
    ):
        self.ready = True
        self.degraded = False
        self.reason = "ready"
        self.last_error = None
        self.last_generation = generation
        self.last_classified_generation = generation
        if feature_ready_generation_by_domain is not None:
            self.last_feature_ready_generation_by_domain = (
                self._generation_by_domain(feature_ready_generation_by_domain)
            )
        self.last_submitted_generation = generation
        self.accepted_generation = self._int_or_default(accepted_generation, generation)
        self.applied_generation = self._int_or_default(applied_generation, generation)
        self.generation_lag = max(0, int(generation) - int(self.applied_generation))
        self.last_desired_hash = desired_hash
        self.last_snapshot_ports = snapshot_ports
        self.last_managed_ports = managed_ports
        self.last_managed_ports_detail = list(managed_ports_detail or [])
        self.last_port_statuses = list(port_statuses or [])
        self.domain_counts = self._domain_counts(self.last_port_statuses)
        self.degraded_reasons = self._degraded_reasons(self.last_port_statuses)
        self.updated_at = time.time()

    def mark_classified_degraded(
        self,
        generation,
        snapshot_ports,
        managed_ports,
        desired_hash=None,
        managed_ports_detail=None,
        port_statuses=None,
        accepted_generation=None,
        applied_generation=None,
        reason="classified_degraded",
        error=None,
    ):
        self.ready = False
        self.degraded = True
        self.reason = reason
        self.last_error = None if error is None else str(error)
        self.last_classified_generation = generation
        self.last_submitted_generation = generation
        self.accepted_generation = self._int_or_default(accepted_generation, generation)
        self.applied_generation = self._int_or_default(applied_generation, generation)
        self.generation_lag = max(0, int(generation) - int(self.applied_generation))
        self.last_snapshot_ports = snapshot_ports
        self.last_managed_ports = managed_ports
        self.last_managed_ports_detail = list(managed_ports_detail or [])
        self.last_port_statuses = list(port_statuses or [])
        self.domain_counts = self._domain_counts(self.last_port_statuses)
        self.degraded_reasons = self._degraded_reasons(self.last_port_statuses)
        self.updated_at = time.time()

    def hydrate_durable_history(
        self,
        history=None,
        last_classified_generation=None,
    ):
        payload = dict(history or {})
        if last_classified_generation is None:
            last_classified_generation = payload.get(
                "last_classified_generation",
                self.last_classified_generation,
            )
        self.last_classified_generation = self._int_or_default(
            last_classified_generation,
            self.last_classified_generation,
        )

        feature_ready_generation = payload.get(
            "last_feature_ready_generation",
            payload.get("generation", self.last_generation),
        )
        self.last_generation = self._int_or_default(
            feature_ready_generation,
            self.last_generation,
        )
        self.last_desired_hash = payload.get(
            "last_feature_ready_desired_hash",
            payload.get("desired_hash", self.last_desired_hash),
        )
        generation_by_domain = payload.get(
            "last_feature_ready_generation_by_domain",
            payload.get("generation_by_domain"),
        )
        if generation_by_domain is not None:
            self.last_feature_ready_generation_by_domain = (
                self._generation_by_domain(generation_by_domain)
            )
        self.updated_at = time.time()

    def mark_degraded(self, reason, error):
        self.ready = False
        self.degraded = True
        self.reason = reason
        self.last_error = str(error)
        self.generation_lag = max(
            0,
            int(self.last_submitted_generation or self.last_generation or 0) -
            int(self.applied_generation or 0),
        )
        self.last_port_statuses = [
            self._degraded_port_status(status, reason)
            for status in self.last_port_statuses
        ]
        self.domain_counts = self._domain_counts(self.last_port_statuses)
        self.degraded_reasons = (
            self._degraded_reasons(self.last_port_statuses) or
            [{"reason": reason, "count": 1}]
        )
        self.updated_at = time.time()

    def remove_port_status(self, port_id):
        removed = sum(
            1 for status in self.last_port_statuses
            if status.get("port_id") == port_id
        )
        self.last_port_statuses = [
            status for status in self.last_port_statuses
            if status.get("port_id") != port_id
        ]
        self.last_managed_ports_detail = [
            port for port in self.last_managed_ports_detail
            if port.get("port_id") != port_id
        ]
        self.last_managed_ports = max(
            0,
            int(self.last_managed_ports or 0) - removed,
        )
        self.domain_counts = self._domain_counts(self.last_port_statuses)
        self.degraded_reasons = self._degraded_reasons(
            self.last_port_statuses
        )
        self.updated_at = time.time()

    def _degraded_port_status(self, status, reason):
        degraded = dict(status or {})
        degraded["status"] = "degraded"
        degraded["effective_action"] = "bypass"
        degraded["reason"] = reason
        degraded["domains"] = [
            dict(
                domain_status,
                status="degraded",
                effective_action="bypass",
                reason=reason,
            )
            for domain_status in degraded.get("domains") or []
        ]
        return degraded

    def update_projection_summary(self, summary):
        payload = dict(summary or {})
        self.projection_index = {
            "projected_ports": self._int_or_default(payload.get("projected_ports"), 0),
            "indexed_networks": self._int_or_default(payload.get("indexed_networks"), 0),
            "ports_with_network": self._int_or_default(payload.get("ports_with_network"), 0),
            "ports_with_revision": self._int_or_default(payload.get("ports_with_revision"), 0),
        }
        self.updated_at = time.time()

    def record_event_decisions(self, decisions, limit=16):
        counts = {}
        sample = []
        for decision in decisions or []:
            payload = dict(decision or {})
            action = payload.get("action") or "unknown"
            reason = payload.get("reason") or "unknown"
            key = (action, reason)
            counts[key] = counts.get(key, 0) + 1
            if len(sample) < int(limit or 0):
                sample.append(payload)
        self.last_event_decision_counts = [
            {
                "action": action,
                "reason": reason,
                "count": counts[(action, reason)],
            }
            for action, reason in sorted(counts)
        ]
        self.last_event_decisions = sample
        self.last_event_decision_updated_at = time.time() if decisions else None
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
            "last_classified_generation": self.last_classified_generation,
            "last_feature_ready_generation_by_domain": dict(
                self.last_feature_ready_generation_by_domain
            ),
            "last_submitted_generation": self.last_submitted_generation,
            "accepted_generation": self.accepted_generation,
            "applied_generation": self.applied_generation,
            "generation_lag": self.generation_lag,
            "last_desired_hash": self.last_desired_hash,
            "last_snapshot_ports": self.last_snapshot_ports,
            "last_managed_ports": self.last_managed_ports,
            "last_managed_ports_detail": list(self.last_managed_ports_detail),
            "last_port_statuses": list(self.last_port_statuses),
            "domain_counts": list(self.domain_counts),
            "degraded_reasons": list(self.degraded_reasons),
            "projection_index": dict(self.projection_index),
            "last_event_decision_counts": list(self.last_event_decision_counts),
            "last_event_decisions": list(self.last_event_decisions),
            "last_event_decision_updated_at": self.last_event_decision_updated_at,
            "updated_at": self.updated_at,
        }

    def heartbeat_payload(self):
        payload = self.to_dict()
        payload["binary"] = "neutron-aria-agent"
        payload["topic"] = "N/A"
        return payload

    def _int_or_default(self, value, default):
        try:
            return int(value)
        except (TypeError, ValueError):
            return int(default or 0)

    def _generation_by_domain(self, generations):
        result = {}
        for domain, generation in dict(generations or {}).items():
            if not isinstance(domain, str) or not domain:
                continue
            result[domain] = self._int_or_default(generation, 0)
        return result

    def _domain_counts(self, port_statuses):
        counts = {}
        for port_status in port_statuses or []:
            domains = port_status.get("domains") or [{
                "domain": "acl",
                "status": port_status.get("status") or "unknown",
                "effective_action": port_status.get("effective_action"),
            }]
            for domain_status in domains:
                domain = domain_status.get("domain") or "unknown"
                status = domain_status.get("status") or port_status.get("status") or "unknown"
                effective_action = (
                    domain_status.get("effective_action") or
                    port_status.get("effective_action") or
                    self._default_effective_action(status)
                )
                key = (domain, status, effective_action)
                counts[key] = counts.get(key, 0) + 1
        result = []
        for domain, status, effective_action in sorted(counts):
            result.append({
                "domain": domain,
                "status": status,
                "effective_action": effective_action,
                "count": counts[(domain, status, effective_action)],
            })
        return result

    def _degraded_reasons(self, port_statuses):
        counts = {}
        for port_status in port_statuses or []:
            domains = port_status.get("domains") or []
            if not domains:
                status = port_status.get("status")
                reason = port_status.get("reason")
                if status and status != "ready" and reason:
                    counts[reason] = counts.get(reason, 0) + 1
                continue
            for domain_status in domains:
                status = domain_status.get("status") or port_status.get("status")
                reason = domain_status.get("reason") or port_status.get("reason")
                if status and status != "ready" and reason:
                    counts[reason] = counts.get(reason, 0) + 1
        return [
            {"reason": reason, "count": counts[reason]}
            for reason in sorted(counts)
        ]

    def _default_effective_action(self, status):
        if status == "ready":
            return "enforce"
        if status in ("blocked", "degraded", "error", "not_requested"):
            return "bypass"
        return "unknown"
