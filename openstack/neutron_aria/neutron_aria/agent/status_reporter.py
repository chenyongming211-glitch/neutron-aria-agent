from __future__ import absolute_import

from neutron_aria.agent.config import sync_mode
from neutron_aria.agent.counter_sampler import diff_port_counters
from neutron_aria.agent.status import ARIA_AGENT_TYPE
from neutron_aria.agent.uds_client import LocalApiContractError
from neutron_aria.agent.uds_client import _counter_decoder


ARIA_AGENT_BINARY = "neutron-aria-agent"
ARIA_AGENT_TOPIC = "N/A"
ARIA_ACL_STATUS_CALL_CONTEXT = "context"
ARIA_ACL_STATUS_CALL_PAYLOAD = "payload"
HEARTBEAT_SCHEMA_VERSION = 2
HEARTBEAT_SAMPLE_LIMIT = 3
HEARTBEAT_DETAIL_SUMMARY_ONLY = "summary_only"
HEARTBEAT_DETAIL_LEGACY_SAMPLE = "legacy_sample"
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

# Latest per-port counter snapshot per process; counter rates are diffed
# against this. Persistence across restarts is out of v1 scope.
_PREVIOUS_COUNTERS = {}


def _rate_delta(prev, curr, elapsed_seconds):
    if prev is None or curr is None or elapsed_seconds <= 0:
        return None
    return float(curr - prev) / elapsed_seconds


def port_counters_blob(runtime_status, port_id):
    """Build the counters blob for one port status payload.

    Returns None when the runtime status carries no counters section (older
    datapath or feature disabled). Returns an error blob (``counters_error``
    only) when the datapath reported a read failure or this port was not
    sampled; the server then keeps the last good snapshot per spec section 10.
    Otherwise returns the diffed rows, the cumulative summary, the exact drop
    pps diffed from the summary drop totals, and the reset/truncated flags.
    Rates are None on the first snapshot and on any negative-delta reset.
    """
    counters = getattr(runtime_status, "last_counters", None)
    if counters is None:
        return None
    try:
        decoder, error_code, _schema_version = _counter_decoder(counters)
        counters = decoder(counters)
    except (LocalApiContractError, AttributeError, TypeError) as exc:
        return {"counters_error": "%s: %s" % (error_code, exc)}
    if counters.get("counters_error"):
        return {"counters_error": counters["counters_error"]}
    sampled_at_ms = counters.get("sampled_at_ms")
    port = None
    for candidate in counters.get("ports") or []:
        if candidate.get("port_id") == port_id:
            port = candidate
            break
    if port is None:
        return {"counters_error": "port_not_sampled"}
    port_copy = dict(port)
    port_copy.setdefault("sampled_at_ms", sampled_at_ms)
    previous = _PREVIOUS_COUNTERS.get(port_id)
    rows, reset = diff_port_counters(previous, port_copy)
    _PREVIOUS_COUNTERS[port_id] = port_copy

    elapsed = 0.0
    if previous is not None:
        prev_sampled = float(previous.get("sampled_at_ms") or 0)
        elapsed = max(0.0, (float(sampled_at_ms or 0) - prev_sampled) / 1000.0)
    drop_pps = None
    if previous is not None and not reset:
        drop_pps = _rate_delta(
            previous.get("drop_packets"),
            port_copy.get("drop_packets"),
            elapsed,
        )
    return {
        "counters_sampled_at_ms": sampled_at_ms,
        "counters_rows": [{
            "port_id": port["port_id"],
            "tap_id": port.get("tap_id"),
            "truncated": port.get("truncated", False),
            "reset_detected": reset,
            "drop_pps": drop_pps,
            "groups": port.get("groups") or [],
            "summary": {
                "policy_packets": port_copy.get("policy_packets"),
                "policy_bytes": port_copy.get("policy_bytes"),
                "policy_allow_packets": port_copy.get(
                    "policy_allow_packets"
                ),
                "policy_dropped_packets": port_copy.get(
                    "policy_dropped_packets"
                ),
                "policy_dropped_bytes": port_copy.get(
                    "policy_dropped_bytes"
                ),
                "drop_packets": port_copy.get("drop_packets"),
                "drop_bytes": port_copy.get("drop_bytes"),
            },
            "rows": rows,
        }],
    }


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
        heartbeat_detail_mode=HEARTBEAT_DETAIL_SUMMARY_ONLY,
    ):
        self.report_state_api = report_state_api
        self.context = context
        self.host = host
        self.agent_type = agent_type
        self.binary = binary
        self.topic = topic
        self.use_call = use_call
        self.configurations = dict(configurations or {})
        self.heartbeat_detail_mode = heartbeat_detail_mode
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
        feature_ready_generation_by_domain = dict(
            payload.get("last_feature_ready_generation_by_domain") or {}
        )
        degraded_reasons = self._degraded_reason_counts(
            payload.get("last_port_statuses") or [],
        )
        if payload.get("degraded") and not degraded_reasons:
            degraded_reasons = list(payload.get("degraded_reasons") or [])
        configured_domains = configurations.get("managed_domains")
        if configured_domains is not None:
            configured_domains = set(configured_domains)
            feature_ready_generation_by_domain = {
                domain: generation
                for domain, generation in feature_ready_generation_by_domain.items()
                if domain in configured_domains
            }
        configurations.update({
            "heartbeat_schema_version": HEARTBEAT_SCHEMA_VERSION,
            "heartbeat_detail_mode": self.heartbeat_detail_mode,
            "ready": payload.get("ready"),
            "degraded": payload.get("degraded"),
            "reason": payload.get("reason"),
            "last_error": payload.get("last_error"),
            "last_generation": payload.get("last_generation"),
            "last_classified_generation": payload.get(
                "last_classified_generation"
            ),
            "last_feature_ready_generation_by_domain": (
                feature_ready_generation_by_domain
            ),
            "last_submitted_generation": payload.get("last_submitted_generation"),
            "accepted_generation": payload.get("accepted_generation"),
            "applied_generation": payload.get("applied_generation"),
            "generation_lag": payload.get("generation_lag"),
            "last_snapshot_ports": payload.get("last_snapshot_ports"),
            "last_managed_ports": payload.get("last_managed_ports"),
            "domain_counts": payload.get("domain_counts") or [],
            "status_reason_counts": payload.get("degraded_reasons") or [],
            "degraded_reasons": degraded_reasons,
            "projection_index": payload.get("projection_index") or {},
            "last_event_decision_counts": payload.get("last_event_decision_counts") or [],
            "last_event_decision_updated_at": payload.get("last_event_decision_updated_at"),
            "updated_at": payload.get("updated_at"),
        })
        if self.heartbeat_detail_mode == HEARTBEAT_DETAIL_LEGACY_SAMPLE:
            self._add_legacy_samples(configurations, payload)

        return {
            "binary": self.binary,
            "host": self.host,
            "topic": self.topic,
            "agent_type": self.agent_type,
            "configurations": configurations,
            "start_flag": self.start_flag,
        }

    def _add_legacy_samples(self, configurations, payload):
        managed_port_sample = self._compact_managed_ports(
            payload.get("last_managed_ports_detail") or [],
        )
        port_status_sample = self._compact_port_statuses(
            payload.get("last_port_statuses") or [],
        )
        event_decision_sample = self._compact_event_decisions(
            payload.get("last_event_decisions") or [],
        )
        configurations.update({
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
            "last_event_decisions": event_decision_sample,
            "last_event_decisions_truncated": (
                len(payload.get("last_event_decisions") or []) >
                len(event_decision_sample)
            ),
        })

    def _degraded_reason_counts(self, statuses):
        counts = {}
        degraded_states = set(["blocked", "degraded", "error"])
        for port_status in statuses or []:
            domains = port_status.get("domains") or []
            rows = domains or [port_status]
            for row in rows:
                status = row.get("status") or port_status.get("status")
                reason = row.get("reason") or port_status.get("reason")
                if status in degraded_states and reason:
                    counts[reason] = counts.get(reason, 0) + 1
        return [
            {"reason": reason, "count": counts[reason]}
            for reason in sorted(counts)
        ]

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

    def __init__(
        self,
        aria_acl_api,
        context=None,
        host=None,
        counters_report_enabled=False,
    ):
        self.aria_acl_api = aria_acl_api
        self.context = context
        self.host = host
        self.counters_report_enabled = bool(counters_report_enabled)
        self.api_call_style = getattr(
            aria_acl_api,
            "ARIA_ACL_STATUS_CALL_STYLE",
            ARIA_ACL_STATUS_CALL_CONTEXT,
        )
        if self.api_call_style not in (
            ARIA_ACL_STATUS_CALL_CONTEXT,
            ARIA_ACL_STATUS_CALL_PAYLOAD,
        ):
            raise StatusReportError(
                "unsupported aria_acl status call style %s"
                % self.api_call_style
            )
        self.pending_deleted_port_ids = set()

    def report(self, runtime_status):
        deleted = self._flush_pending_deletes()
        reported = []
        for status in runtime_status.last_port_statuses:
            payload = self._port_status_payload(runtime_status, status)
            self._report_one(payload)
            reported.append(payload)
        return {
            "reported_port_statuses": len(reported),
            "deleted_port_statuses": deleted,
            "port_statuses": reported,
        }

    def remove_port_status(self, port_id):
        _PREVIOUS_COUNTERS.pop(port_id, None)
        self.pending_deleted_port_ids.add(port_id)
        self._delete_one(port_id)
        self.pending_deleted_port_ids.discard(port_id)

    def _flush_pending_deletes(self):
        deleted = 0
        for port_id in sorted(self.pending_deleted_port_ids):
            self._delete_one(port_id)
            self.pending_deleted_port_ids.discard(port_id)
            deleted += 1
        return deleted

    def _delete_one(self, port_id):
        method = getattr(
            self.aria_acl_api,
            "delete_aria_acl_port_status",
            None,
        )
        if method is None:
            raise StatusReportError(
                "aria_acl API does not expose delete_aria_acl_port_status"
            )
        try:
            if self.api_call_style == ARIA_ACL_STATUS_CALL_PAYLOAD:
                return method(port_id, self.host)
            return method(
                self.context,
                port_id,
                host=self.host,
            )
        except Exception as exc:
            if getattr(exc, "status_code", None) == 404:
                return None
            raise

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
            not payload.get("effective_action") and
            acl_domain is not None and
            acl_domain.get("status") == "ready"
        ):
            payload["effective_action"] = "enforce"
        if runtime_status.last_error and not payload.get("reason"):
            payload["reason"] = runtime_status.last_error
        if self.counters_report_enabled:
            blob = port_counters_blob(
                runtime_status, payload.get("port_id")
            )
            if blob is not None:
                payload.update(blob)
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
        if self.api_call_style == ARIA_ACL_STATUS_CALL_PAYLOAD:
            return method(payload)
        return method(self.context, body)


class CompositeStatusReporter(object):
    def __init__(self, *reporters):
        self.reporters = [reporter for reporter in reporters if reporter is not None]

    def report(self, runtime_status):
        reporters = list(self.reporters)
        if runtime_status.ready and not runtime_status.degraded:
            port_reporters = [
                reporter for reporter in reporters
                if isinstance(reporter, AriaAclPortStatusReporter)
            ]
            heartbeat_reporters = [
                reporter for reporter in reporters
                if isinstance(reporter, NeutronStatusReporter)
            ]
            other_reporters = [
                reporter for reporter in reporters
                if (
                    not isinstance(reporter, AriaAclPortStatusReporter) and
                    not isinstance(reporter, NeutronStatusReporter)
                )
            ]
            if port_reporters and heartbeat_reporters:
                reporters = (
                    port_reporters +
                    other_reporters +
                    heartbeat_reporters
                )
        results = []
        for reporter in reporters:
            results.append(reporter.report(runtime_status))
        if len(results) == 1:
            return results[0]
        return {"results": results}

    def remove_port_status(self, port_id):
        results = []
        for reporter in self.reporters:
            method = getattr(reporter, "remove_port_status", None)
            if method is not None:
                results.append(method(port_id))
        return results


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
        "neutron_api_timeout": config.neutron_api_timeout,
    }
    heartbeat_reporter = NeutronStatusReporter(
        report_state_api=report_state_api,
        context=context,
        host=host,
        configurations=configurations,
        heartbeat_detail_mode=config.heartbeat_detail_mode,
    )
    if getattr(config, "acl_source", None) != "neutron":
        return heartbeat_reporter

    if aria_acl_api is None:
        try:
            from neutron_aria.agent.neutron_client import build_aria_acl_client_from_env
            aria_acl_api = build_aria_acl_client_from_env(
                timeout=config.neutron_api_timeout
            )
        except Exception as exc:
            raise StatusReportError("aria_acl port-status API unavailable: %s" % exc)

    return CompositeStatusReporter(
        heartbeat_reporter,
        AriaAclPortStatusReporter(
            aria_acl_api,
            context=context,
            host=host,
            counters_report_enabled=getattr(
                config, "counters_report_enabled", False
            ),
        ),
    )
