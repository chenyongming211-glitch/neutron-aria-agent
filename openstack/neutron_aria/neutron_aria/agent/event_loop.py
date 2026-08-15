from __future__ import absolute_import

import copy
import logging
import time

from neutron_aria.agent.effective_acl import EffectiveAclIndex
from neutron_aria.agent.effective_acl import REVISION_NEWER
from neutron_aria.agent.effective_acl import REVISION_UNKNOWN
from neutron_aria.agent.inventory import PortCandidateBuilder
from neutron_aria.agent.inventory import PortScopedSnapshotBuilder
from neutron_aria.agent.projection import ACTION_FULL_RESYNC
from neutron_aria.agent.projection import ProjectedStateIndex
from neutron_aria.agent.projection import REASON_LOCAL_PORT_UPDATE
from neutron_aria.agent.state import InMemorySnapshotStateStore
from neutron_aria.agent.state import desired_snapshot_hash
from neutron_aria.agent.status import AgentRuntimeStatus
from neutron_aria.agent.uds_client import LocalApiContractError
from neutron_aria.agent.uds_client import LocalApiError
from neutron_aria.agent.uds_client import LocalApiResponseError
from neutron_aria.agent.uds_client import LocalApiTimeoutError


LOG = logging.getLogger(__name__)

RECOVERY_REQUIRED_AUTHORITY_STATES = frozenset((
    "blocked_recovery_required",
    "wal_commit_failed",
    "wal_recovery_commit_failed",
    "wal_runtime_reconcile_commit_failed",
    "pending_recovery_commit_failed",
    "recovered_pending_full_resync",
    "partial",
    "degraded",
    "runtime_degraded",
    "wal_intent_without_commit",
))
TERMINAL_FAILURE_AUTHORITY_STATES = RECOVERY_REQUIRED_AUTHORITY_STATES.union((
    "runtime_degraded",
    "degraded",
    "blocked",
    "error",
    "unsupported",
    "detached",
))


try:
    _INTEGER_TYPES = (int, long)
    _STRING_TYPES = (basestring,)
except NameError:
    _INTEGER_TYPES = (int,)
    _STRING_TYPES = (str,)


def _elapsed_ms(started_at):
    return int((time.time() - started_at) * 1000)


def _status_token(value):
    return str(value or "").strip().lower()


def _strict_scalar(value, scalar_type, allow_none=False):
    if value is None and allow_none:
        return None
    if scalar_type == "integer":
        if (
            isinstance(value, bool) or
            not isinstance(value, _INTEGER_TYPES) or
            value < 0
        ):
            raise ValueError("expected a non-negative integer")
        return value
    if scalar_type == "string":
        if not isinstance(value, _STRING_TYPES) or not value:
            raise ValueError("expected a non-empty string")
        return value
    raise ValueError("unsupported scalar type")


def _unique_row_index(rows, identity_key, collection_name, normalize=None):
    if not isinstance(rows, list):
        return None, "%s must be a list" % collection_name
    index = {}
    for row in rows:
        if not isinstance(row, dict):
            return None, "%s contains a non-object row" % collection_name
        try:
            identity = _strict_scalar(row.get(identity_key), "string")
        except ValueError:
            return (
                None,
                "%s contains an invalid %s" % (
                    collection_name,
                    identity_key,
                ),
            )
        if normalize is not None:
            identity = normalize(identity)
        if identity in index:
            return (
                None,
                "duplicate %s row for %s" % (collection_name, identity),
            )
        index[identity] = row
    return index, None


def _acl_index_profile(acl_index):
    if acl_index is None:
        return {
            "acl_source_policies": 0,
            "acl_source_rules": 0,
            "acl_source_address_sets": 0,
            "acl_source_enabled_bindings": 0,
        }
    rules_by_policy = getattr(acl_index, "rules_by_policy", {}) or {}
    bindings_by_target = getattr(acl_index, "bindings_by_target", {}) or {}
    return {
        "acl_source_policies": len(getattr(acl_index, "policies", {}) or {}),
        "acl_source_rules": sum(len(rules) for rules in rules_by_policy.values()),
        "acl_source_address_sets": len(getattr(acl_index, "address_sets", {}) or {}),
        "acl_source_enabled_bindings": sum(
            len(bindings) for bindings in bindings_by_target.values()
        ),
    }


def _snapshot_acl_profile(snapshot):
    result = {
        "acl_bound_ports": 0,
        "acl_enabled_ports": 0,
        "acl_effective_rules": 0,
        "acl_src_cidrs": 0,
        "acl_dst_cidrs": 0,
    }
    for port in (snapshot or {}).get("ports") or []:
        acl = port.get("acl") or {}
        if acl.get("policy_id") or acl.get("binding_id"):
            result["acl_bound_ports"] += 1
        if acl.get("enabled"):
            result["acl_enabled_ports"] += 1
        rules = acl.get("rules") or []
        result["acl_effective_rules"] += len(rules)
        for rule in rules:
            result["acl_src_cidrs"] += len(rule.get("src_cidrs") or [])
            result["acl_dst_cidrs"] += len(rule.get("dst_cidrs") or [])
    return result


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
        state_store=None,
        ovs_bridge="br-int",
        runtime_status=None,
        status_reporter=None,
        acl_index=None,
        acl_source=None,
        projection_index=None,
        timeout_convergence_attempts=5,
        timeout_convergence_interval=1.0,
        sleeper=None,
    ):
        self.host = host
        self.port_source = port_source
        self.ovs_reader = ovs_reader
        self.local_client = local_client
        self.managed_domains = list(managed_domains or ["acl"])
        self.generation_store = generation_store or GenerationStore()
        self.state_store = state_store or InMemorySnapshotStateStore()
        self.ovs_bridge = ovs_bridge
        self.runtime_status = runtime_status or AgentRuntimeStatus(host)
        self.status_reporter = status_reporter
        if (
            hasattr(self.runtime_status, "hydrate_durable_history") and
            hasattr(self.state_store, "feature_ready_history")
        ):
            self.runtime_status.hydrate_durable_history(
                self.state_store.feature_ready_history()
            )
        self.projected_port_ids = set(self.state_store.last_projected_port_ids())
        self.projection_index = projection_index or ProjectedStateIndex()
        self.projection_index.replace_projected_ids(self.projected_port_ids)
        self.runtime_status.update_projection_summary(self.projection_summary())
        self.acl_index = acl_index
        self.acl_source = acl_source
        self.timeout_convergence_attempts = max(1, int(timeout_convergence_attempts))
        self.timeout_convergence_interval = max(0.0, float(timeout_convergence_interval))
        self.sleeper = sleeper or time.sleep

    def check_capabilities(self):
        return self.local_client.capabilities(required_domains=self.managed_domains)

    def full_resync(self):
        profile_started = time.time()
        phase_started = time.time()
        self.check_capabilities()
        capabilities_ms = _elapsed_ms(phase_started)

        phase_started = time.time()
        self.recover_pending_state()
        pending_recovery_ms = _elapsed_ms(phase_started)
        previously_projected_port_ids = set(self.projected_port_ids)

        phase_started = time.time()
        ports = self._list_ports()
        neutron_read_ms = _elapsed_ms(phase_started)

        phase_started = time.time()
        acl_index = self._load_acl_index()
        acl_source_ms = _elapsed_ms(phase_started)
        acl_source_profile = _acl_index_profile(acl_index)

        phase_started = time.time()
        builder = PortCandidateBuilder(
            self.host,
            managed_domains=self.managed_domains,
            acl_index=acl_index,
        )
        snapshot = builder.build_snapshot(
            ports,
            generation=0,
        )
        snapshot_build_ms = _elapsed_ms(phase_started)
        snapshot_acl_profile = _snapshot_acl_profile(snapshot)

        phase_started = time.time()
        remote_status = self._pre_submit_remote_status("full-host snapshot")
        remote_status_ms = _elapsed_ms(phase_started)
        generation_floor = self._generation_floor_from_status(remote_status)

        phase_started = time.time()
        pending_action = self._remote_pending_action(
            snapshot,
            remote_status,
            desired_snapshot_hash(snapshot),
        )
        if pending_action.get("action") == "retry_snapshot":
            snapshot = self._retry_snapshot_body(
                pending_action,
                expected_scope="full_host",
            )
        if pending_action.get("action") == "wait":
            prepared = self.state_store.prepare_snapshot_at_generation(
                snapshot,
                pending_action["generation"],
                desired_hash=pending_action["desired_hash"],
            )
        elif pending_action.get("action") in ("block", "recover"):
            if (
                pending_action.get("action") == "block" and
                pending_action.get("normalized_control")
            ):
                LOG.warning(
                    "remote_snapshot_status_blocks_submit host=%s "
                    "remote_pending_generation=%s remote_desired_hash=%s",
                    self.host,
                    pending_action.get("generation"),
                    pending_action.get("remote_desired_hash"),
                )
                raise LocalApiTimeoutError(
                    "remote snapshot generation %s requires operator action" %
                    pending_action.get("generation")
                )
            recovery = self._recover_remote_pending_snapshot(pending_action)
            if recovery is None:
                LOG.warning(
                    "remote_snapshot_pending_blocks_submit host=%s "
                    "remote_pending_generation=%s remote_desired_hash=%s "
                    "local_desired_hash=%s",
                    self.host,
                    pending_action.get("generation"),
                    pending_action.get("remote_desired_hash"),
                    pending_action.get("desired_hash"),
                )
                raise LocalApiTimeoutError(
                    "remote snapshot generation %s is still pending" %
                    pending_action.get("generation")
                )
            remote_status = self._pre_submit_remote_status(
                "post-recovery full-host snapshot"
            )
            if pending_action.get("normalized_control"):
                self._realign_after_pending_recovery(
                    pending_action,
                    remote_status,
                )
                generation_floor = max(
                    self._generation_floor_from_status(remote_status),
                    int(pending_action.get("generation") or 0),
                )
                pending_action = {"action": "force_full_resync"}
                prepared = self.state_store.prepare_snapshot(
                    snapshot,
                    minimum_generation=generation_floor,
                    force_new_generation=True,
                )
            else:
                generation_floor = self._generation_floor_from_status(
                    remote_status
                )
                pending_action = {}
                prepared = self.state_store.prepare_snapshot(
                    snapshot,
                    minimum_generation=generation_floor,
                )
        elif pending_action.get("action") == "force_full_resync":
            generation_floor = max(
                generation_floor,
                int(pending_action.get("generation") or 0),
            )
            prepared = self.state_store.prepare_snapshot(
                snapshot,
                minimum_generation=generation_floor,
                force_new_generation=True,
            )
        else:
            prepared = self.state_store.prepare_snapshot(
                snapshot,
                minimum_generation=generation_floor,
            )
        snapshot["generation"] = prepared["generation"]
        snapshot["desired_hash"] = prepared["desired_hash"]
        projected_port_ids = self._projected_port_ids(snapshot)
        requires_live_acl_verification = self._requires_live_acl_verification(
            snapshot,
            remote_status,
        )
        existing_terminal_status = None
        if (
            not pending_action.get("action") and
            self._is_v1_status(remote_status)
        ):
            existing_verdict, _ = self._snapshot_status_verdict(
                snapshot,
                projected_port_ids,
                remote_status,
            )
            if (
                existing_verdict in ("ready", "classified_degraded") and
                not requires_live_acl_verification
            ):
                existing_terminal_status = remote_status
        if (
            existing_terminal_status is None and
            not pending_action.get("action") and
            remote_status is not None and
            snapshot["generation"] <= generation_floor and
            not self._status_converged(snapshot, projected_port_ids, remote_status)
        ):
            prepared = self.state_store.prepare_snapshot(
                snapshot,
                minimum_generation=generation_floor + 1,
            )
            snapshot["generation"] = prepared["generation"]
            snapshot["desired_hash"] = prepared["desired_hash"]
            LOG.warning(
                "snapshot_generation_bumped_for_non_converged_remote "
                "host=%s generation=%s generation_floor=%s projected_ports=%s "
                "remote_managed_ports=%s",
                self.host,
                snapshot["generation"],
                generation_floor,
                len(projected_port_ids),
                len(remote_status.get("managed_ports") or []),
            )
        prepare_ms = _elapsed_ms(phase_started)

        uds_submit_ms = 0
        timeout_recovery_ms = 0
        submit_mode = "new_snapshot"
        try:
            response = None
            if existing_terminal_status is not None:
                submit_mode = "already_classified"
                response = {
                    "status": "classified",
                    "generation": snapshot["generation"],
                    "desired_hash": snapshot.get("desired_hash"),
                    "results": [],
                    "active_instances": existing_terminal_status.get(
                        "active_instances"
                    ) or [],
                    "managed_ports": existing_terminal_status.get(
                        "managed_ports"
                    ) or [],
                    "port_statuses": existing_terminal_status.get(
                        "port_statuses"
                    ) or [],
                    "already_classified": True,
                }
            elif pending_action.get("action") == "wait":
                submit_mode = "remote_pending_same_hash"
                response = self._wait_for_snapshot_convergence(
                    snapshot,
                    projected_port_ids,
                    response_flag="recovered_remote_pending",
                    success_phase="remote_pending_converged",
                    failure_phase="remote_pending_not_converged",
                    attempts=self._accepted_convergence_attempts(),
                )
            elif pending_action.get("action") == "retry_snapshot":
                self.state_store.record_snapshot_retry(
                    snapshot["generation"],
                    snapshot["desired_hash"],
                )
                submit_mode = "retry_snapshot"
            elif prepared.get("reused_pending"):
                response = self._maybe_recover_pending_before_submit(
                    snapshot,
                    projected_port_ids,
                )
                if response is not None:
                    submit_mode = "pending_recovered_before_submit"
            if response is None:
                if submit_mode != "retry_snapshot":
                    submit_mode = "put_snapshot"
                phase_started = time.time()
                response = self.local_client.put_snapshot(snapshot)
                uds_submit_ms = _elapsed_ms(phase_started)
        except LocalApiTimeoutError as exc:
            uds_submit_ms = _elapsed_ms(phase_started)
            phase_started = time.time()
            response = self._recover_snapshot_timeout(snapshot, projected_port_ids, exc)
            timeout_recovery_ms = _elapsed_ms(phase_started)
            submit_mode = "timeout_recovered"
        except LocalApiResponseError as exc:
            if not self._is_restore_in_progress_error(exc):
                raise
            uds_submit_ms = _elapsed_ms(phase_started)
            phase_started = time.time()
            response = self._recover_snapshot_timeout(snapshot, projected_port_ids, exc)
            timeout_recovery_ms = _elapsed_ms(phase_started)
            submit_mode = "startup_restore_retried"
        self._raise_if_response_failed(response)

        phase_started = time.time()
        if existing_terminal_status is not None:
            apply_status = existing_terminal_status
        else:
            apply_status = self._status_after_apply(
                snapshot,
                projected_port_ids,
                response,
            )
        post_apply_status_ms = _elapsed_ms(phase_started)
        managed_ports = self._finalize_snapshot_classification(
            snapshot,
            projected_port_ids,
            apply_status,
            response,
            scope="full_host",
            ports=ports,
        )
        for removed_port_id in sorted(
            previously_projected_port_ids - self.projected_port_ids
        ):
            self._remove_reported_port_status(removed_port_id)

        phase_started = time.time()
        heartbeat = self.report_status()
        heartbeat_ms = _elapsed_ms(phase_started)
        LOG.info(
            "full_resync_complete host=%s generation=%s snapshot_ports=%s "
            "managed_ports=%s projected_ports=%s heartbeat_ok=%s",
            self.host,
            snapshot["generation"],
            len(snapshot["ports"]),
            managed_ports,
            len(self.projected_port_ids),
            heartbeat is None or heartbeat.get("ok", False),
        )
        self._log_acl_delivery_profile(
            phase="full_resync_done",
            scope="full_host",
            generation=snapshot["generation"],
            desired_hash=snapshot.get("desired_hash"),
            generation_floor=generation_floor,
            submit_mode=submit_mode,
            neutron_ports=len(ports or []),
            snapshot_ports=len(snapshot["ports"]),
            projected_ports=len(self.projected_port_ids),
            managed_ports=managed_ports,
            capabilities_ms=capabilities_ms,
            pending_recovery_ms=pending_recovery_ms,
            neutron_read_ms=neutron_read_ms,
            acl_source_ms=acl_source_ms,
            snapshot_build_ms=snapshot_build_ms,
            remote_status_ms=remote_status_ms,
            prepare_ms=prepare_ms,
            uds_submit_ms=uds_submit_ms,
            timeout_recovery_ms=timeout_recovery_ms,
            post_apply_status_ms=post_apply_status_ms,
            heartbeat_ms=heartbeat_ms,
            total_ms=_elapsed_ms(profile_started),
            **dict(acl_source_profile, **snapshot_acl_profile)
        )
        return {
            "snapshot": snapshot,
            "response": response,
            "status": self.runtime_status.to_dict(),
            "heartbeat": heartbeat,
        }

    def _requires_live_acl_verification(self, snapshot, remote_status):
        runtime_by_port = dict(
            (row.get("port_id"), row)
            for row in (remote_status or {}).get("port_statuses") or []
            if row.get("port_id")
        )
        for port in snapshot.get("ports") or []:
            if "acl" not in (port.get("managed_domains") or []):
                continue
            runtime_port = runtime_by_port.get(port.get("port_id")) or {}
            runtime_acl = next((
                domain for domain in runtime_port.get("domains") or []
                if _status_token(domain.get("domain")) == "acl"
            ), {})
            if (
                _status_token(runtime_acl.get("status")) == "ready" and
                _status_token(runtime_acl.get("effective_action")) == "enforce"
            ):
                return True
        if runtime_by_port:
            return False

        for port in snapshot.get("ports") or []:
            if "acl" not in (port.get("managed_domains") or []):
                continue
            desired_acl = port.get("acl") or {}
            if (
                desired_acl.get("enabled") is True and
                _status_token(desired_acl.get("effective_action")) == "enforce"
            ):
                return True
        return False

    def _load_acl_index(self):
        if self.acl_source is not None:
            self.acl_index = self.acl_source.load_index()
        if self.acl_index is None and "acl" in self.managed_domains:
            self.acl_index = EffectiveAclIndex()
        return self.acl_index

    def _log_acl_delivery_profile(self, **fields):
        parts = []
        fields.setdefault("host", self.host)
        for key in sorted(fields):
            value = fields[key]
            if value is None:
                value = "-"
            parts.append("%s=%s" % (key, value))
        LOG.info("acl_delivery_profile %s", " ".join(parts))

    def safe_full_resync(self):
        try:
            return self.full_resync()
        except LocalApiContractError as exc:
            self.runtime_status.mark_degraded("local_api_contract_error", exc)
            heartbeat = self.report_status()
            LOG.warning(
                "full_resync_contract_error host=%s error=%s heartbeat_ok=%s",
                self.host,
                self.runtime_status.last_error,
                heartbeat is None or heartbeat.get("ok", False),
            )
            return {
                "snapshot": None,
                "response": None,
                "status": self.runtime_status.to_dict(),
                "heartbeat": heartbeat,
            }
        except LocalApiError as exc:
            preserves_pending_metadata_reason = (
                self.runtime_status.reason ==
                "pending_snapshot_metadata_invalid" and
                self.runtime_status.last_error == str(exc)
            )
            if (
                self.runtime_status.reason !=
                "stale_pending_snapshot_requires_operator" and
                not preserves_pending_metadata_reason
            ):
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

    def delete_port(self, port_id, reason=None):
        remote_status = self._pre_submit_remote_status("delete")
        pending_action = self._pre_submit_action_gate(
            "delete",
            {},
            remote_status,
            None,
        )
        if pending_action.get("action") == "force_full_resync":
            return self.safe_full_resync()
        try:
            self.state_store.prepare_delete(port_id, reason=reason)
        except RuntimeError as exc:
            self.runtime_status.mark_degraded(
                "pending_delete_unresolved",
                exc,
            )
            raise LocalApiError(str(exc))
        try:
            response = self.local_client.delete_port(port_id)
        except LocalApiTimeoutError as exc:
            response = self._recover_delete_timeout(port_id, exc)
        try:
            self._validate_delete_response(port_id, response)
            self.projection_index.remove(port_id)
            self.projected_port_ids.discard(port_id)
            self.runtime_status.update_projection_summary(
                self.projection_summary()
            )
            self.state_store.commit_delete(port_id)
            self.runtime_status.remove_port_status(port_id)
            self._remove_reported_port_status(port_id)
        except Exception as exc:
            self.runtime_status.mark_degraded(
                "pending_delete_unresolved",
                exc,
            )
            raise
        LOG.info(
            "delete_port_complete host=%s port_id=%s reason=%s projected_ports=%s",
            self.host,
            port_id,
            reason,
            len(self.projected_port_ids),
        )
        return response

    def _remove_reported_port_status(self, port_id):
        method = getattr(self.status_reporter, "remove_port_status", None)
        if method is None:
            return
        try:
            method(port_id)
        except Exception as exc:
            LOG.warning(
                "port_status_delete_failed host=%s port_id=%s error=%s",
                self.host,
                port_id,
                exc,
            )

    def recover_pending_state(self):
        recovered = []
        snapshot = self.state_store.pending_snapshot()
        if snapshot:
            metadata_reason = self._pending_restart_metadata_reason(snapshot)
            if metadata_reason is not None:
                self.runtime_status.mark_degraded(
                    "pending_snapshot_metadata_invalid",
                    metadata_reason,
                )
                LOG.warning(
                    "pending_snapshot_metadata_invalid host=%s "
                    "generation=%s error=%s",
                    self.host,
                    snapshot["generation"],
                    metadata_reason,
                )
                raise LocalApiError(metadata_reason)
            status = self.local_client.status()
            normalized_control = None
            normalized_control_keys = (
                "transaction_state",
                "overall_readiness",
                "required_action",
            )
            normalized_control_presence = tuple(
                key in status for key in normalized_control_keys
            )
            if any(normalized_control_presence):
                if not all(normalized_control_presence):
                    raise LocalApiError(
                        "normalized status control is incomplete"
                    )
                try:
                    normalized_control = tuple(
                        _status_token(_strict_scalar(status.get(key), "string"))
                        for key in normalized_control_keys
                    )
                except ValueError:
                    raise LocalApiError("normalized status control is invalid")
            pending_state, _, pending_reason = self._pending_generation_status(status)
            if pending_state == "failed":
                self.runtime_status.mark_degraded(
                    "pending_snapshot_unresolved",
                    pending_reason,
                )
                LOG.warning(
                    "pending_snapshot_status_invalid host=%s generation=%s "
                    "error=%s",
                    self.host,
                    snapshot["generation"],
                    pending_reason,
                )
                raise LocalApiError(pending_reason)
            if self._pending_snapshot_was_not_accepted(
                snapshot,
                status,
                normalized_control,
            ):
                cleared = self.state_store.clear_pending_snapshot(
                    reason="remote_never_accepted",
                )
                recovered.append("unaccepted_snapshot")
                LOG.warning(
                    "pending_snapshot_unaccepted_cleared host=%s "
                    "pending_generation=%s accepted_generation=%s "
                    "applied_generation=%s projected_ports=%s",
                    self.host,
                    cleared.get("generation") if cleared else None,
                    status.get("accepted_generation"),
                    status.get("applied_generation"),
                    len((cleared or {}).get("projected_port_ids") or []),
                )
                snapshot = None
            if (
                snapshot is not None and
                self._pending_snapshot_hash_mismatch(snapshot, status)
            ):
                if normalized_control not in (
                    None,
                    ("classified", "ready", "none"),
                    ("classified", "degraded", "none"),
                ):
                    self.runtime_status.mark_degraded(
                        "stale_pending_snapshot_requires_operator",
                        "normalized control %s/%s/%s cannot clear local pending" %
                        normalized_control,
                    )
                    raise LocalApiError(self.runtime_status.last_error)
                if self._pending_snapshot_is_stale(snapshot, status):
                    cleared = self.state_store.clear_pending_snapshot(
                        reason="remote_generation_advanced",
                    )
                    recovered.append("stale_snapshot")
                    LOG.warning(
                        "pending_snapshot_stale_cleared host=%s "
                        "pending_generation=%s remote_generation=%s "
                        "pending_hash=%s remote_hash=%s projected_ports=%s",
                        self.host,
                        cleared.get("generation") if cleared else None,
                        self._status_generation(
                            status,
                            "applied_generation",
                            status.get("generation"),
                        ),
                        cleared.get("desired_hash") if cleared else None,
                        status.get("applied_desired_hash") or status.get("desired_hash"),
                        len((cleared or {}).get("projected_port_ids") or []),
                    )
                    snapshot = None
                else:
                    self.runtime_status.mark_degraded(
                        "stale_pending_snapshot_requires_operator",
                        (
                            "pending snapshot hash mismatch: generation=%s "
                            "desired_hash=%s"
                        ) % (snapshot["generation"], snapshot["desired_hash"]),
                    )
                    LOG.warning(
                        "pending_snapshot_hash_mismatch_blocked host=%s "
                        "pending_generation=%s remote_generation=%s "
                        "pending_hash=%s remote_hash=%s",
                        self.host,
                        snapshot["generation"],
                        status.get("applied_generation") or status.get("generation"),
                        snapshot["desired_hash"],
                        status.get("applied_desired_hash") or status.get("desired_hash"),
                    )
                    raise LocalApiError(self.runtime_status.last_error)
            if snapshot is not None:
                restart_snapshot = {
                    "generation": snapshot["generation"],
                    "desired_hash": snapshot["desired_hash"],
                    "snapshot_ports": snapshot.get("snapshot_ports") or 0,
                    "scope": {
                        "type": "restart",
                        "pending_scope": snapshot.get("scope"),
                        "affected_port_ids": list(
                            snapshot.get("affected_port_ids") or []
                        ),
                    },
                    "ports": [],
                }
                verdict, reason = self._snapshot_status_verdict(
                    restart_snapshot,
                    set(snapshot.get("projected_port_ids") or []),
                    status,
                )
                if verdict in ("ready", "classified_degraded"):
                    managed_ports = self._finalize_snapshot_classification(
                        restart_snapshot,
                        set(snapshot.get("projected_port_ids") or []),
                        status,
                        {},
                        scope="restart",
                    )
                    recovered.append("snapshot")
                    LOG.warning(
                        "pending_snapshot_recovered host=%s generation=%s "
                        "classification=%s projected_ports=%s managed_ports=%s",
                        self.host,
                        snapshot["generation"],
                        verdict,
                        len(self.projected_port_ids),
                        managed_ports,
                    )
                else:
                    self.runtime_status.mark_degraded(
                        "pending_snapshot_unresolved",
                        reason or "generation %s has not converged" %
                        snapshot["generation"],
                    )
                    LOG.warning(
                        "pending_snapshot_unresolved host=%s generation=%s "
                        "verdict=%s reason=%s projected_ports=%s",
                        self.host,
                        snapshot["generation"],
                        verdict,
                        reason,
                        len(snapshot.get("projected_port_ids") or []),
                    )

        pending_delete = self.state_store.pending_delete()
        if pending_delete:
            status = self.local_client.status()
            if self._delete_status_converged(pending_delete["port_id"], status):
                self.projection_index.remove(pending_delete["port_id"])
                self.projected_port_ids.discard(pending_delete["port_id"])
                self.runtime_status.update_projection_summary(self.projection_summary())
                self.state_store.commit_delete(pending_delete["port_id"])
                recovered.append("delete")
                LOG.warning(
                    "pending_delete_recovered host=%s port_id=%s reason=%s",
                    self.host,
                    pending_delete["port_id"],
                    pending_delete.get("reason"),
                )
            else:
                self.runtime_status.mark_degraded(
                    "pending_delete_unresolved",
                    "port %s still appears managed" % pending_delete["port_id"],
                )
                LOG.warning(
                    "pending_delete_unresolved host=%s port_id=%s reason=%s",
                    self.host,
                    pending_delete["port_id"],
                    pending_delete.get("reason"),
                )

        return {"recovered": recovered}

    def has_projected_port(self, port_id):
        return port_id in self.projected_port_ids

    def decide_port_update(self, port_id, binding_host=None, revision_number=None):
        return self.projection_index.decide_port_update(
            port_id,
            self.host,
            binding_host=binding_host,
            revision_number=revision_number,
        )

    def decide_port_delete(self, port_id):
        return self.projection_index.decide_port_delete(port_id)

    def decide_network_update(self, network_id):
        return self.projection_index.decide_network_update(
            network_id,
            conservative=True,
        )

    def dry_run_port_scoped_snapshot(
        self,
        port_id,
        binding_host=None,
        revision_number=None,
        allow_revisionless=False,
    ):
        decision = self.decide_port_update(
            port_id,
            binding_host=binding_host,
            revision_number=revision_number,
        ).to_dict()
        result = {
            "submitted": False,
            "decision": decision,
            "snapshot": None,
        }
        if (
            decision.get("action") != ACTION_FULL_RESYNC or
            decision.get("reason") != REASON_LOCAL_PORT_UPDATE
        ):
            result["skipped_reason"] = "decision_not_port_scoped_candidate"
            return result
        if decision.get("revision_status") != REVISION_NEWER:
            if not (
                allow_revisionless and
                decision.get("revision_status") == REVISION_UNKNOWN
            ):
                result["skipped_reason"] = "revision_not_newer"
                return result
            result["revisionless_incremental_mode"] = "experimental"

        ports = self._list_ports()
        acl_index = self._load_acl_index()
        builder = PortScopedSnapshotBuilder(
            self.host,
            managed_domains=self.managed_domains,
            acl_index=acl_index,
        )
        snapshot = builder.build_port_snapshot(
            ports,
            port_id,
            generation=self._next_preview_generation(),
        )
        if not snapshot.get("ports"):
            result["skipped_reason"] = "port_not_available_for_host"
            return result

        result["snapshot"] = snapshot
        result["skipped_reason"] = None
        return result

    def apply_port_scoped_snapshot(
        self,
        port_id,
        binding_host=None,
        revision_number=None,
        allow_revisionless=False,
    ):
        profile_started = time.time()
        phase_started = time.time()
        preview = self.dry_run_port_scoped_snapshot(
            port_id,
            binding_host=binding_host,
            revision_number=revision_number,
            allow_revisionless=allow_revisionless,
        )
        dry_run_ms = _elapsed_ms(phase_started)
        if preview.get("skipped_reason"):
            self._log_acl_delivery_profile(
                phase="port_scoped_skipped",
                scope="port",
                port_id=port_id,
                skipped_reason=preview.get("skipped_reason"),
                dry_run_ms=dry_run_ms,
                total_ms=_elapsed_ms(profile_started),
            )
            return preview

        snapshot = preview["snapshot"]
        snapshot_acl_profile = _snapshot_acl_profile(snapshot)
        phase_started = time.time()
        remote_status = self._pre_submit_remote_status(
            "port-scoped snapshot"
        )
        remote_status_ms = _elapsed_ms(phase_started)
        pending_action = self._pre_submit_action_gate(
            "port-scoped snapshot",
            snapshot,
            remote_status,
            desired_snapshot_hash(snapshot),
        )
        if pending_action.get("action") == "force_full_resync":
            preview["submitted"] = False
            preview["skipped_reason"] = "remote_status_requires_full_resync"
            return preview
        if pending_action.get("action") == "retry_snapshot":
            snapshot = self._retry_snapshot_body(
                pending_action,
                expected_scope="port",
                port_id=port_id,
            )
        generation_floor = self._generation_floor_from_status(remote_status)

        phase_started = time.time()
        try:
            prepared = self.state_store.prepare_scoped_snapshot(
                snapshot,
                minimum_generation=generation_floor,
            )
        except RuntimeError as exc:
            self._mark_pending_snapshot_unresolved(exc)
            raise LocalApiError(str(exc))
        snapshot["generation"] = prepared["generation"]
        snapshot["desired_hash"] = prepared["desired_hash"]
        pending_snapshot = self.state_store.pending_snapshot()
        if pending_snapshot is not None:
            projected_port_ids = set(
                pending_snapshot.get("projected_port_ids") or []
            )
        else:
            projected_port_ids = set(self.projected_port_ids)
        prepare_ms = _elapsed_ms(phase_started)

        uds_submit_ms = 0
        timeout_recovery_ms = 0
        submit_mode = "new_snapshot"
        try:
            response = None
            if pending_action.get("action") == "retry_snapshot":
                self.state_store.record_snapshot_retry(
                    snapshot["generation"],
                    snapshot["desired_hash"],
                )
                submit_mode = "retry_snapshot"
            elif prepared.get("reused_pending"):
                response = self._maybe_recover_pending_before_submit(
                    snapshot,
                    projected_port_ids,
                )
                if response is not None:
                    submit_mode = "pending_recovered_before_submit"
            if response is None:
                if submit_mode != "retry_snapshot":
                    submit_mode = "put_port_snapshot"
                phase_started = time.time()
                response = self.local_client.put_port_snapshot(
                    port_id,
                    snapshot,
                    required_domains=self.managed_domains,
                )
                uds_submit_ms = _elapsed_ms(phase_started)
        except LocalApiTimeoutError as exc:
            uds_submit_ms = _elapsed_ms(phase_started)
            phase_started = time.time()
            try:
                response = self._recover_snapshot_timeout(
                    snapshot,
                    projected_port_ids,
                    exc,
                )
            except Exception as recovery_exc:
                self._mark_pending_snapshot_unresolved(recovery_exc)
                raise
            timeout_recovery_ms = _elapsed_ms(phase_started)
            submit_mode = "timeout_recovered"
        except Exception as exc:
            self._mark_pending_snapshot_unresolved(exc)
            raise

        try:
            self._raise_if_response_failed(response)
        except Exception as exc:
            self._mark_pending_snapshot_unresolved(exc)
            raise
        phase_started = time.time()
        try:
            apply_status = self._status_after_apply(
                snapshot,
                projected_port_ids,
                response,
            )
        except Exception as exc:
            self._mark_pending_snapshot_unresolved(exc)
            raise
        post_apply_status_ms = _elapsed_ms(phase_started)
        try:
            managed_ports = self._finalize_snapshot_classification(
                snapshot,
                projected_port_ids,
                apply_status,
                response,
                scope="port",
                port_id=port_id,
            )
        except Exception as exc:
            self._mark_pending_snapshot_unresolved(exc)
            raise
        phase_started = time.time()
        heartbeat = self.report_status()
        heartbeat_ms = _elapsed_ms(phase_started)
        LOG.info(
            "port_scoped_snapshot_complete host=%s port_id=%s generation=%s "
            "managed_ports=%s projected_ports=%s heartbeat_ok=%s",
            self.host,
            port_id,
            snapshot["generation"],
            managed_ports,
            len(self.projected_port_ids),
            heartbeat is None or heartbeat.get("ok", False),
        )
        self._log_acl_delivery_profile(
            phase="port_scoped_done",
            scope="port",
            port_id=port_id,
            generation=snapshot["generation"],
            desired_hash=snapshot.get("desired_hash"),
            generation_floor=generation_floor,
            submit_mode=submit_mode,
            snapshot_ports=len(snapshot["ports"]),
            projected_ports=len(self.projected_port_ids),
            managed_ports=managed_ports,
            dry_run_ms=dry_run_ms,
            remote_status_ms=remote_status_ms,
            prepare_ms=prepare_ms,
            uds_submit_ms=uds_submit_ms,
            timeout_recovery_ms=timeout_recovery_ms,
            post_apply_status_ms=post_apply_status_ms,
            heartbeat_ms=heartbeat_ms,
            total_ms=_elapsed_ms(profile_started),
            **snapshot_acl_profile
        )
        return {
            "submitted": True,
            "decision": preview.get("decision"),
            "skipped_reason": None,
            "snapshot": snapshot,
            "response": response,
            "status": self.runtime_status.to_dict(),
            "heartbeat": heartbeat,
        }

    def projected_ports_for_network(self, network_id):
        return self.projection_index.ports_for_network(network_id)

    def projection_summary(self):
        return self.projection_index.summary()

    def _list_ports(self):
        if hasattr(self.port_source, "list_ports_for_host"):
            return self.port_source.list_ports_for_host()
        return self.port_source.get_ports()

    def _find_port_by_id(self, ports, port_id):
        for port in ports or []:
            if (port.get("id") or port.get("port_id")) == port_id:
                return port
        return None

    def _projected_port_ids(self, snapshot):
        return set(
            port.get("port_id") for port in snapshot["ports"]
            if port.get("port_id") and (port.get("eligible") or port.get("managed_domains"))
        )

    def _next_preview_generation(self):
        values = [
            getattr(self.runtime_status, "last_generation", 0),
            getattr(self.runtime_status, "last_submitted_generation", 0),
        ]
        if hasattr(self.state_store, "to_dict"):
            state = self.state_store.to_dict()
            values.extend([
                state.get("last_generation"),
                state.get("last_classified_generation"),
                state.get("last_feature_ready_generation"),
                state.get("pending_generation"),
            ])
        generations = []
        for value in values:
            try:
                generations.append(int(value or 0))
            except (TypeError, ValueError):
                generations.append(0)
        return max(generations or [0]) + 1

    def _response_managed_count(self, response, status=None):
        if status and status.get("managed_ports") is not None:
            return len(status.get("managed_ports") or [])
        if response.get("managed_ports") is not None:
            return len(response.get("managed_ports") or [])
        return len(response.get("active_instances") or [])

    def _managed_ports_from_status(self, status):
        if not status:
            return []
        return list(status.get("managed_ports") or [])

    def _port_statuses_from_status(self, status, snapshot=None):
        if not status:
            return []
        statuses = list(status.get("port_statuses") or [])
        acl_metadata = self._acl_metadata_by_port(snapshot)
        if not acl_metadata:
            return statuses

        managed_port_ids = set(
            port.get("port_id") for port in status.get("managed_ports") or []
            if port.get("port_id")
        )
        status_by_port = {}
        enriched = []
        for status_row in statuses:
            payload = dict(status_row)
            metadata = acl_metadata.get(payload.get("port_id"))
            if metadata:
                self._apply_acl_metadata_to_status(
                    payload,
                    metadata,
                    status.get("generation"),
                )
            status_by_port[payload.get("port_id")] = payload
            enriched.append(payload)
        for port_id in sorted(acl_metadata):
            if port_id in status_by_port:
                continue
            if port_id not in managed_port_ids:
                continue
            payload = {"port_id": port_id}
            self._apply_acl_metadata_to_status(
                payload,
                acl_metadata[port_id],
                status.get("generation"),
            )
            enriched.append(payload)
        return enriched

    def _acl_metadata_by_port(self, snapshot):
        metadata = {}
        for port in (snapshot or {}).get("ports") or []:
            port_id = port.get("port_id")
            acl = port.get("acl") or {}
            if not port_id:
                continue
            policy_id = acl.get("policy_id")
            binding_id = acl.get("binding_id")
            if policy_id or binding_id:
                metadata[port_id] = {
                    "policy_id": policy_id,
                    "binding_id": binding_id,
                    "acl_enabled": bool(acl.get("enabled")),
                    "status": acl.get("status"),
                    "reason": acl.get("reason"),
                    "effective_action": acl.get("effective_action"),
                }
        return metadata

    def _apply_acl_metadata_to_status(self, payload, metadata, generation):
        self._setdefault_nonempty(
            payload,
            "policy_id",
            metadata.get("policy_id"),
        )
        self._setdefault_nonempty(
            payload,
            "binding_id",
            metadata.get("binding_id"),
        )
        if generation is not None:
            payload.setdefault("generation", generation)
        if not metadata.get("acl_enabled"):
            return

        acl_status = metadata.get("status") or "ready"
        acl_reason = metadata.get("reason") or "ready"
        acl_action = metadata.get("effective_action") or "enforce"
        if payload.get("status") in (None, ""):
            payload["status"] = acl_status
        if payload.get("effective_action") in (None, ""):
            payload["effective_action"] = acl_action
        if payload.get("reason") in (None, ""):
            payload["reason"] = acl_reason

        domains = list(payload.get("domains") or [])
        for domain_status in domains:
            if domain_status.get("domain") != "acl":
                continue
            if domain_status.get("status") in (None, ""):
                domain_status["status"] = acl_status
            if domain_status.get("effective_action") in (None, ""):
                domain_status["effective_action"] = acl_action
            if domain_status.get("reason") in (None, ""):
                domain_status["reason"] = acl_reason
            break
        else:
            domains.append({
                "domain": "acl",
                "status": acl_status,
                "effective_action": acl_action,
                "reason": acl_reason,
            })
        payload["domains"] = domains

    def _setdefault_nonempty(self, payload, key, value):
        if value and not payload.get(key):
            payload[key] = value

    def _status_generation(self, status, key, default):
        if not status:
            return default
        try:
            return int(status.get(key) or status.get("generation") or default)
        except (TypeError, ValueError):
            return default

    def _finalize_snapshot_classification(
        self,
        snapshot,
        projected_port_ids,
        status,
        response,
        scope="full_host",
        ports=None,
        port_id=None,
    ):
        verdict, reason = self._snapshot_status_verdict(
            snapshot,
            projected_port_ids,
            status,
        )
        if verdict not in ("ready", "classified_degraded"):
            raise LocalApiError(
                "snapshot status is not terminal classification: %s" % reason
            )

        projected_port_ids = set(projected_port_ids or [])
        managed_ports = self._response_managed_count(response, status)
        snapshot_ports = len(snapshot.get("ports") or [])
        if scope == "port":
            snapshot_ports = (
                getattr(self.runtime_status, "last_snapshot_ports", 0) or
                len(projected_port_ids)
            )
        elif scope == "restart":
            snapshot_ports = (
                snapshot.get("snapshot_ports") or len(projected_port_ids)
        )

        if scope == "full_host":
            self.projection_index.replace_from_resync(
                ports or [],
                snapshot,
                generation=snapshot["generation"],
            )
            self.projected_port_ids = projected_port_ids
        elif scope == "port":
            snapshot_port = (
                snapshot["ports"][0] if snapshot.get("ports") else {}
            )
            neutron_port = self._find_port_by_id(
                self._list_ports(),
                port_id,
            ) or {}
            self.projection_index.update_from_scoped_port(
                neutron_port,
                snapshot_port,
                generation=snapshot["generation"],
            )
            self.projected_port_ids = set(self.projection_index.port_ids())
        else:
            self.projected_port_ids = projected_port_ids
            self.projection_index.replace_projected_ids(
                self.projected_port_ids,
                generation=snapshot["generation"],
            )

        if verdict == "ready":
            if scope == "port":
                self.state_store.commit_scoped_snapshot(
                    snapshot["generation"],
                    snapshot.get("desired_hash"),
                    managed_ports=managed_ports,
                    feature_ready_domains=self.managed_domains,
                )
            else:
                self.state_store.commit_snapshot(
                    snapshot["generation"],
                    snapshot.get("desired_hash"),
                    snapshot_ports=snapshot_ports,
                    managed_ports=managed_ports,
                    feature_ready_domains=self.managed_domains,
                )
        elif scope == "port":
            self.state_store.commit_classified_scoped_snapshot(
                snapshot["generation"],
                snapshot.get("desired_hash"),
                managed_ports=managed_ports,
            )
        else:
            self.state_store.commit_classified_snapshot(
                snapshot["generation"],
                snapshot.get("desired_hash"),
                snapshot_ports=snapshot_ports,
                managed_ports=managed_ports,
            )

        runtime_arguments = {
            "desired_hash": snapshot.get("desired_hash"),
            "managed_ports_detail": self._managed_ports_from_status(status),
            "port_statuses": self._port_statuses_from_status(status, snapshot),
            "accepted_generation": self._status_generation(
                status,
                "accepted_generation",
                snapshot["generation"],
            ),
            "applied_generation": self._status_generation(
                status,
                "applied_generation",
                snapshot["generation"],
            ),
        }
        if verdict == "ready":
            history = self.state_store.feature_ready_history()
            runtime_arguments["feature_ready_generation_by_domain"] = (
                history.get("last_feature_ready_generation_by_domain") or {}
            )
            self.runtime_status.mark_ready(
                snapshot["generation"],
                snapshot_ports,
                managed_ports,
                **runtime_arguments
            )
        else:
            self.runtime_status.mark_classified_degraded(
                snapshot["generation"],
                snapshot_ports,
                managed_ports,
                **runtime_arguments
            )
        self.runtime_status.update_projection_summary(self.projection_summary())
        self.runtime_status.last_counters = status.get("counters")
        return managed_ports

    def _raise_if_response_failed(self, response):
        errors = [
            result for result in response.get("results") or []
            if result.get("status") == "error"
        ]
        if errors:
            raise LocalApiError(
                "snapshot apply returned port errors: %s" % errors
            )

    def _mark_pending_snapshot_unresolved(self, error):
        if self.state_store.pending_snapshot() is None:
            return
        self.runtime_status.mark_degraded(
            "pending_snapshot_unresolved",
            error,
        )

    def _validate_delete_response(self, port_id, response):
        if not isinstance(response, dict):
            raise LocalApiError("delete response is not an object")
        if response.get("port_id") != port_id:
            raise LocalApiError(
                "delete response port_id %r does not match %r" %
                (response.get("port_id"), port_id)
            )
        status = response.get("status")
        if status not in ("ok", "deleted", "not_found"):
            raise LocalApiError(
                "delete response is not successful: %s" % response
            )
        if response.get("error"):
            raise LocalApiError(
                "delete response contains error: %s" % response["error"]
            )
        if status == "ok" and response.get("detached") is False:
            raise LocalApiError(
                "delete response reports ok without detach"
            )

    def _maybe_recover_pending_before_submit(self, snapshot, projected_port_ids):
        try:
            status = self.local_client.status()
        except LocalApiContractError:
            raise
        except LocalApiError:
            return None
        verdict, reason = self._snapshot_status_verdict(
            snapshot,
            projected_port_ids,
            status,
        )
        if verdict == "failed":
            raise LocalApiError(
                "pending snapshot failed terminal-ready validation: %s" % reason
            )
        if verdict not in ("ready", "classified_degraded"):
            return None
        LOG.warning(
            "snapshot_pending_already_converged host=%s generation=%s "
            "projected_ports=%s managed_ports=%s",
            self.host,
            snapshot["generation"],
            len(projected_port_ids),
            len(status.get("managed_ports") or []),
        )
        return {
            "generation": snapshot["generation"],
            "desired_hash": snapshot.get("desired_hash"),
            "results": [],
            "active_instances": status.get("active_instances") or [],
            "managed_ports": status.get("managed_ports") or [],
            "port_statuses": status.get("port_statuses") or [],
            "recovered_before_submit": True,
        }

    def _recover_remote_pending_snapshot(self, pending_action):
        recover = getattr(self.local_client, "recover_pending_snapshot", None)
        if recover is None:
            return None
        try:
            response = recover(
                pending_action.get("generation"),
                pending_action.get("remote_desired_hash"),
            )
        except LocalApiContractError:
            raise
        except LocalApiError as exc:
            LOG.warning(
                "remote_pending_snapshot_recovery_failed host=%s "
                "remote_pending_generation=%s remote_desired_hash=%s error=%s",
                self.host,
                pending_action.get("generation"),
                pending_action.get("remote_desired_hash"),
                exc,
            )
            return None
        LOG.warning(
            "remote_pending_snapshot_recovered host=%s "
            "remote_pending_generation=%s remote_desired_hash=%s status=%s",
            self.host,
            pending_action.get("generation"),
            pending_action.get("remote_desired_hash"),
            response.get("status"),
        )
        return response

    def _legacy_recovery_baseline_ports(
        self,
        status,
        applied_generation,
        applied_hash,
    ):
        managed, reason = _unique_row_index(
            status.get("managed_ports"),
            "port_id",
            "Legacy recovery managed port evidence",
        )
        if reason is not None:
            raise LocalApiError(reason)
        port_statuses, reason = _unique_row_index(
            status.get("port_statuses"),
            "port_id",
            "Legacy recovery port status evidence",
        )
        if reason is not None:
            raise LocalApiError(reason)

        managed_domains_by_port = {}
        for port_id, row in managed.items():
            ifname = row.get("ifname")
            if (
                not isinstance(port_id, _STRING_TYPES) or
                not port_id.strip() or
                port_id.strip() != port_id
            ):
                raise LocalApiError(
                    "Legacy recovery managed port has invalid port_id"
                )
            if (
                not isinstance(ifname, _STRING_TYPES) or
                not ifname.strip() or
                ifname.strip() != ifname
            ):
                raise LocalApiError(
                    "Legacy recovery managed port %s has invalid ifname" %
                    port_id
                )
            domains, reason = self._normalized_domain_set(
                row.get("managed_domains"),
                "Legacy recovery managed port %s" % port_id,
            )
            if reason is not None:
                raise LocalApiError(reason)
            if any(
                not domain.strip() or domain.strip() != domain
                for domain in row.get("managed_domains") or []
            ):
                raise LocalApiError(
                    "Legacy recovery managed port %s has invalid domains" %
                    port_id
                )
            managed_domains_by_port[port_id] = domains

        for port_id, row in port_statuses.items():
            if (
                not isinstance(port_id, _STRING_TYPES) or
                not port_id.strip() or
                port_id.strip() != port_id
            ):
                raise LocalApiError(
                    "Legacy recovery port status has invalid port_id"
                )
            try:
                ifname = _strict_scalar(row.get("ifname"), "string")
                generation = _strict_scalar(
                    row.get("generation"),
                    "integer",
                )
                desired_hash = _strict_scalar(
                    row.get("desired_hash"),
                    "string",
                )
                _strict_scalar(row.get("status"), "string")
            except ValueError:
                raise LocalApiError(
                    "Legacy recovery port status %s has invalid identity" %
                    port_id
                )
            if not ifname.strip() or ifname.strip() != ifname:
                raise LocalApiError(
                    "Legacy recovery port status %s has invalid ifname" %
                    port_id
                )
            reason_value = row.get("reason")
            if (
                reason_value is not None and
                not isinstance(reason_value, _STRING_TYPES)
            ):
                raise LocalApiError(
                    "Legacy recovery port status %s has invalid reason" %
                    port_id
                )
            if (
                generation <= 0 or
                generation > applied_generation or
                not desired_hash.strip() or
                desired_hash.strip() != desired_hash or
                (
                    generation == applied_generation and
                    desired_hash != applied_hash
                )
            ):
                raise LocalApiError(
                    "Legacy recovery port status %s is outside the applied "
                    "baseline" % port_id
                )
            row_domains, reason = self._normalized_domain_set(
                row.get("managed_domains"),
                "Legacy recovery port status %s" % port_id,
            )
            if reason is not None:
                raise LocalApiError(reason)
            if any(
                not domain.strip() or domain.strip() != domain
                for domain in row.get("managed_domains") or []
            ):
                raise LocalApiError(
                    "Legacy recovery port status %s has invalid domains" %
                    port_id
                )
            domain_rows, reason = _unique_row_index(
                row.get("domains"),
                "domain",
                "Legacy recovery domain evidence for port %s" % port_id,
                normalize=_status_token,
            )
            if reason is not None:
                raise LocalApiError(reason)
            for domain_name, domain in domain_rows.items():
                raw_name = domain.get("domain")
                try:
                    _strict_scalar(domain.get("status"), "string")
                except ValueError:
                    raise LocalApiError(
                        "Legacy recovery domain %s for port %s has invalid "
                        "status" % (domain_name, port_id)
                    )
                if (
                    not isinstance(raw_name, _STRING_TYPES) or
                    not raw_name.strip() or
                    raw_name.strip() != raw_name
                ):
                    raise LocalApiError(
                        "Legacy recovery domain identity is invalid for port "
                        "%s" % port_id
                    )
                for field in ("reason", "effective_action"):
                    value = domain.get(field)
                    if value is not None and not isinstance(value, _STRING_TYPES):
                        raise LocalApiError(
                            "Legacy recovery domain %s for port %s has invalid "
                            "%s" % (domain_name, port_id, field)
                        )
            if row_domains != set(domain_rows):
                raise LocalApiError(
                    "Legacy recovery port status %s has mismatched domains" %
                    port_id
                )
            if port_id in managed:
                if ifname != managed[port_id].get("ifname"):
                    raise LocalApiError(
                        "Legacy recovery port %s has mismatched ifname" %
                        port_id
                    )
                if row_domains != managed_domains_by_port[port_id]:
                    raise LocalApiError(
                        "Legacy recovery port %s has mismatched managed "
                        "domains" % port_id
                    )
        missing_statuses = sorted(set(managed) - set(port_statuses))
        if missing_statuses:
            raise LocalApiError(
                "Legacy recovery baseline is missing port status for %s" %
                missing_statuses
            )
        return set(managed)

    def _validated_applied_baseline_identity(self, status):
        if not isinstance(status, dict):
            raise LocalApiError("applied baseline status is unavailable")
        pending_state, _, pending_reason = self._pending_generation_status(status)
        if pending_state != "none":
            raise LocalApiError(
                pending_reason or "applied baseline pending identity was not cleared"
            )
        try:
            applied_generation = _strict_scalar(
                status.get("applied_generation"), "integer"
            )
            accepted_generation = _strict_scalar(
                status.get("accepted_generation"), "integer"
            )
            alias_generation = _strict_scalar(
                status.get("generation"), "integer"
            )
            classified_generation = _strict_scalar(
                status.get("last_classified_generation"), "integer"
            )
        except ValueError:
            raise LocalApiError("applied baseline generation identity is invalid")
        if not (
            accepted_generation == applied_generation and
            alias_generation == applied_generation and
            classified_generation == applied_generation
        ):
            raise LocalApiError(
                "applied baseline generation identity does not match"
            )
        applied_hash = status.get("applied_desired_hash")
        desired_hash = status.get("desired_hash")
        managed_ports = status.get("managed_ports") or []
        port_statuses = status.get("port_statuses") or []
        if applied_generation == 0:
            if (
                applied_hash is not None or
                desired_hash is not None or
                managed_ports or
                port_statuses
            ):
                raise LocalApiError(
                    "generation-0 applied baseline is not empty"
                )
        else:
            try:
                applied_hash = _strict_scalar(applied_hash, "string")
                desired_hash = _strict_scalar(desired_hash, "string")
            except ValueError:
                raise LocalApiError(
                    "applied baseline desired hash identity is invalid"
                )
            if desired_hash != applied_hash:
                raise LocalApiError(
                    "desired hash does not match applied baseline"
                )
        return applied_generation, applied_hash, managed_ports

    def _validated_legacy_applied_baseline(self, status):
        applied_generation, applied_hash, _ = (
            self._validated_applied_baseline_identity(status)
        )
        projected_port_ids = self._legacy_recovery_baseline_ports(
            status,
            applied_generation,
            applied_hash,
        )
        return applied_generation, applied_hash, projected_port_ids

    def _realign_after_pending_recovery(self, pending_action, status):
        if not isinstance(status, dict):
            raise LocalApiError("pending recovery status is unavailable")
        try:
            control = tuple(
                _status_token(_strict_scalar(status.get(key), "string"))
                for key in (
                    "transaction_state",
                    "overall_readiness",
                    "required_action",
                )
            )
        except ValueError:
            raise LocalApiError("pending recovery control is invalid")
        if control != ("recovery", "degraded", "full_resync"):
            raise LocalApiError(
                "pending recovery did not reach recovery/degraded/full_resync"
            )
        if self._is_v1_status(status):
            applied_generation, applied_hash, managed_ports = (
                self._validated_applied_baseline_identity(status)
            )
            projected_port_ids = set(
                row.get("port_id") for row in managed_ports
                if isinstance(row, dict) and row.get("port_id")
            )
        else:
            (
                applied_generation,
                applied_hash,
                projected_port_ids,
            ) = self._validated_legacy_applied_baseline(
                status
            )
        self.state_store.realign_classified_snapshot(
            applied_generation,
            applied_hash,
            projected_port_ids,
            recovered_pending_generation=pending_action.get("generation"),
            recovered_pending_desired_hash=pending_action.get(
                "remote_desired_hash"
            ),
        )
        self.projected_port_ids = projected_port_ids
        self.projection_index.replace_projected_ids(
            projected_port_ids,
            generation=applied_generation,
        )
        if (
            hasattr(self.runtime_status, "hydrate_durable_history") and
            hasattr(self.state_store, "feature_ready_history")
        ):
            self.runtime_status.hydrate_durable_history(
                self.state_store.feature_ready_history()
            )
        self.runtime_status.update_projection_summary(self.projection_summary())

    def _remote_pending_action(self, snapshot, status, desired_hash):
        if status is None:
            return {}
        pending_state, pending_generation, reason = (
            self._pending_generation_status(status)
        )
        if pending_state == "failed":
            raise LocalApiError(reason)
        remote_hash = status.get("desired_hash")
        applied_hash = (
            status.get("applied_desired_hash") or
            status.get("desired_hash")
        )
        normalized_control_keys = (
            "transaction_state",
            "overall_readiness",
            "required_action",
        )
        normalized_control_presence = tuple(
            key in status for key in normalized_control_keys
        )
        if any(normalized_control_presence) and not all(
            normalized_control_presence
        ):
            raise LocalApiError("normalized status control is incomplete")
        has_normalized_control = all(normalized_control_presence)
        if has_normalized_control:
            status_contract = self._status_contract_mode(status)
            control = (
                _status_token(status.get("transaction_state")),
                _status_token(status.get("overall_readiness")),
                _status_token(status.get("required_action")),
            )
            required_action = control[2]
            if pending_state != "pending":
                if control in (
                    ("idle", "unknown", "full_resync"),
                    ("classified", "degraded", "full_resync"),
                    ("recovery", "degraded", "full_resync"),
                ):
                    if (
                        status_contract == "legacy_v0" and
                        control in (
                            ("classified", "degraded", "full_resync"),
                            ("recovery", "degraded", "full_resync"),
                        )
                    ):
                        self._validated_legacy_applied_baseline(status)
                    return {
                        "action": "force_full_resync",
                        "status_contract": status_contract,
                        "normalized_control": True,
                        "generation": self._generation_floor_from_status(status),
                        "desired_hash": desired_hash,
                        "remote_desired_hash": remote_hash,
                        "applied_desired_hash": applied_hash,
                    }
                if required_action in ("poll", "recover_pending", "operator"):
                    return {
                        "action": "block",
                        "status_contract": status_contract,
                        "normalized_control": True,
                        "generation": pending_generation,
                        "desired_hash": desired_hash,
                        "remote_desired_hash": remote_hash,
                        "applied_desired_hash": applied_hash,
                    }
                return {}

            common = {
                "status_contract": status_contract,
                "normalized_control": True,
                "generation": pending_generation,
                "desired_hash": desired_hash,
                "remote_desired_hash": remote_hash,
                "applied_desired_hash": applied_hash,
            }
            if required_action == "recover_pending":
                pending = self.state_store.pending_snapshot() or {}
                if (
                    self._status_requires_pending_recovery(status) and
                    pending.get("generation") == pending_generation and
                    pending.get("desired_hash") == remote_hash
                ):
                    common["action"] = "recover"
                else:
                    common["action"] = "block"
                return common
            if required_action == "poll":
                common["action"] = (
                    "wait"
                    if remote_hash and desired_hash and remote_hash == desired_hash
                    else "block"
                )
                return common
            if required_action == "retry_snapshot":
                pending = self.state_store.pending_snapshot() or {}
                exact_local_identity = bool(
                    pending.get("generation") == pending_generation and
                    pending.get("desired_hash") == remote_hash
                )
                if status_contract != "v2" or not exact_local_identity:
                    common.update({
                        "action": "block",
                        "reason": "operator",
                    })
                    return common
                if remote_hash and desired_hash == remote_hash:
                    if not pending.get("retryable") or not pending.get("request"):
                        common.update({
                            "action": "block",
                            "reason": "operator",
                        })
                        return common
                    common.update({
                        "action": "retry_snapshot",
                        "request": copy.deepcopy(pending["request"]),
                    })
                    return common
                try:
                    applied_generation = int(
                        status.get("applied_generation") or 0
                    )
                except (TypeError, ValueError):
                    applied_generation = 0
                if applied_generation > 0:
                    common["action"] = "recover"
                else:
                    common.update({
                        "action": "block",
                        "reason": "operator",
                    })
                return common
            common["action"] = "block"
            return common

        if pending_state != "pending":
            return {}
        try:
            _strict_scalar(status.get("authority_state"), "string")
        except ValueError:
            raise LocalApiError("authority_state is invalid")
        common = {
            "generation": pending_generation,
            "desired_hash": desired_hash,
            "remote_desired_hash": remote_hash,
            "applied_desired_hash": applied_hash,
        }
        if self._status_requires_pending_recovery(status):
            common["action"] = "recover"
        elif remote_hash and desired_hash and remote_hash == desired_hash:
            common["action"] = "wait"
        else:
            common["action"] = "block"
        return common

    def _retry_snapshot_body(
        self,
        pending_action,
        expected_scope,
        port_id=None,
    ):
        request = pending_action.get("request")
        if not isinstance(request, dict):
            raise LocalApiError("durable retry request is unavailable")
        scope = request.get("scope")
        body = request.get("body")
        if not isinstance(scope, dict) or not isinstance(body, dict):
            raise LocalApiError("durable retry request is invalid")
        if scope.get("type") != expected_scope:
            raise LocalApiError("durable retry request scope mismatch")
        if expected_scope == "port" and scope.get("port_id") != port_id:
            raise LocalApiError("durable retry request port mismatch")
        if (
            body.get("generation") != pending_action.get("generation") or
            body.get("desired_hash") != pending_action.get(
                "remote_desired_hash"
            ) or
            desired_snapshot_hash(body) != body.get("desired_hash")
        ):
            raise LocalApiError("durable retry request identity mismatch")
        return copy.deepcopy(body)

    def _pre_submit_action_gate(
        self,
        operation,
        snapshot,
        status,
        desired_hash,
    ):
        normalized_control_keys = (
            "transaction_state",
            "overall_readiness",
            "required_action",
        )
        if status is None:
            raise LocalApiError(
                "current status is unavailable before %s" % operation
            )
        if not any(key in status for key in normalized_control_keys):
            return {}
        pending_action = self._remote_pending_action(
            snapshot,
            status,
            desired_hash,
        )
        action = pending_action.get("action")
        if action in ("wait", "block", "recover"):
            raise LocalApiTimeoutError(
                "remote status action %s blocks direct %s" % (
                    action,
                    operation,
                )
            )
        return pending_action

    def _pre_submit_remote_status(self, operation):
        try:
            status = self.local_client.status()
            if status is None:
                raise LocalApiError(
                    "current status is unavailable before %s" % operation
                )
            return status
        except LocalApiContractError:
            raise
        except Exception as exc:
            LOG.warning(
                "pre_submit_status_unavailable host=%s operation=%s error=%s",
                self.host,
                operation,
                exc,
            )
            raise

    def _pending_restart_metadata_reason(self, pending):
        scope = pending.get("scope")
        affected_port_ids = pending.get("affected_port_ids")
        if scope not in ("full_host", "port"):
            return "pending snapshot scope metadata is missing or invalid"
        if not isinstance(affected_port_ids, list):
            return "pending affected port metadata is missing or invalid"
        normalized = []
        for port_id in affected_port_ids:
            if (
                not isinstance(port_id, _STRING_TYPES) or
                not port_id.strip() or
                port_id.strip() != port_id
            ):
                return "pending affected port metadata is invalid"
            normalized.append(port_id)
        if len(normalized) != len(set(normalized)):
            return "pending affected port metadata contains duplicates"
        projected_port_ids = set(
            port_id for port_id in pending.get("projected_port_ids") or []
            if port_id
        )
        affected = set(normalized)
        if scope == "full_host" and affected != projected_port_ids:
            return "full-host pending affected ports do not match projection"
        if scope == "port" and not affected:
            return "scoped pending affected ports are empty"
        return None

    def _status_requires_pending_recovery(self, status):
        if not isinstance(status, dict):
            return False
        if all(
            key in status for key in (
                "transaction_state",
                "overall_readiness",
                "required_action",
            )
        ):
            if (
                _status_token(status.get("transaction_state")),
                _status_token(status.get("overall_readiness")),
                _status_token(status.get("required_action")),
            ) != ("blocked", "blocked", "recover_pending"):
                return False
            recovery_cause = _status_token(status.get("recovery_cause"))
            if recovery_cause not in ("", "inventory_unavailable"):
                return False
            try:
                pending_generation = _strict_scalar(
                    status.get("pending_generation"), "integer"
                )
                accepted_generation = _strict_scalar(
                    status.get("accepted_generation"), "integer"
                )
                applied_generation = _strict_scalar(
                    status.get("applied_generation"), "integer"
                )
                last_classified_generation = _strict_scalar(
                    status.get("last_classified_generation"), "integer"
                )
                desired_hash = _strict_scalar(
                    status.get("desired_hash"), "string"
                )
            except ValueError:
                return False
            if (
                pending_generation <= 0 or
                accepted_generation < 0 or
                applied_generation < 0 or
                last_classified_generation < 0 or
                not desired_hash.strip()
            ):
                return False
            accepted_lineage_is_valid = bool(
                (
                    accepted_generation == applied_generation and
                    applied_generation <= pending_generation
                ) or
                (
                    accepted_generation == pending_generation and
                    pending_generation >= applied_generation
                )
            )
            if not accepted_lineage_is_valid:
                return False
            applied_hash = status.get("applied_desired_hash")
            if pending_generation == applied_generation:
                try:
                    applied_hash = _strict_scalar(applied_hash, "string")
                except ValueError:
                    return False
                if desired_hash != applied_hash:
                    return False
            if (
                recovery_cause == "inventory_unavailable" and
                accepted_generation != pending_generation
            ):
                return False
            if applied_generation == 0:
                return bool(
                    recovery_cause == "inventory_unavailable" and
                    applied_hash is None and
                    not (status.get("managed_ports") or []) and
                    not (status.get("port_statuses") or []) and
                    last_classified_generation == 0
                )
            try:
                applied_hash = _strict_scalar(applied_hash, "string")
            except ValueError:
                return False
            return bool(applied_hash.strip())
        try:
            authority_state = _strict_scalar(
                status.get("authority_state"),
                "string",
            )
        except ValueError:
            return False
        return bool(
            self._status_has_pending_generation(status) and
            authority_state in RECOVERY_REQUIRED_AUTHORITY_STATES
        )

    def _poll_snapshot_convergence(
        self,
        snapshot,
        projected_port_ids,
        success_phase,
        failure_phase,
        attempts=None,
    ):
        poll_started = time.time()
        last_error = None
        max_attempts = max(1, int(attempts or self.timeout_convergence_attempts))
        for attempt in range(1, max_attempts + 1):
            attempt_started = time.time()
            try:
                status = self.local_client.status()
            except LocalApiContractError:
                raise
            except LocalApiError as exc:
                last_error = exc
                LOG.warning(
                    "snapshot_convergence_status_check_failed host=%s "
                    "generation=%s attempt=%s attempts=%s error=%s",
                    self.host,
                    snapshot["generation"],
                    attempt,
                    max_attempts,
                    exc,
                )
            else:
                verdict, reason = self._snapshot_status_verdict(
                    snapshot,
                    projected_port_ids,
                    status,
                )
                if verdict in ("ready", "classified_degraded"):
                    LOG.warning(
                        "snapshot_convergence_reached host=%s generation=%s "
                        "attempt=%s projected_ports=%s managed_ports=%s "
                        "status_generation=%s",
                        self.host,
                        snapshot["generation"],
                        attempt,
                        len(projected_port_ids),
                        len(status.get("managed_ports") or []),
                        status.get("generation"),
                    )
                    self._log_acl_delivery_profile(
                        phase=success_phase,
                        scope=(snapshot.get("scope") or {}).get("type", "full_host"),
                        generation=snapshot["generation"],
                        desired_hash=snapshot.get("desired_hash"),
                        projected_ports=len(projected_port_ids),
                        managed_ports=len(status.get("managed_ports") or []),
                        status_generation=status.get("generation"),
                        attempt=attempt,
                        attempts=max_attempts,
                        status_poll_attempt_ms=_elapsed_ms(attempt_started),
                        status_poll_total_ms=_elapsed_ms(poll_started),
                    )
                    return status
                if verdict == "failed":
                    raise LocalApiError(
                        "snapshot status failed terminal-ready validation: %s" %
                        reason
                    )
                last_error = LocalApiTimeoutError(
                    "status did not converge for generation %s: %s" % (
                        snapshot["generation"],
                        reason,
                    )
                )
                LOG.warning(
                    "snapshot_convergence_not_reached host=%s generation=%s "
                    "attempt=%s attempts=%s projected_ports=%s managed_ports=%s "
                    "status_generation=%s pending_generation=%s",
                    self.host,
                    snapshot["generation"],
                    attempt,
                    max_attempts,
                    len(projected_port_ids),
                    len(status.get("managed_ports") or []),
                    status.get("generation"),
                    status.get("pending_generation"),
                )

            if attempt < max_attempts:
                self.sleeper(self.timeout_convergence_interval)

        self._log_acl_delivery_profile(
            phase=failure_phase,
            scope=(snapshot.get("scope") or {}).get("type", "full_host"),
            generation=snapshot["generation"],
            desired_hash=snapshot.get("desired_hash"),
            projected_ports=len(projected_port_ids),
            attempts=max_attempts,
            status_poll_total_ms=_elapsed_ms(poll_started),
            error=last_error,
        )
        raise LocalApiTimeoutError(
            "snapshot status did not converge: %s" % last_error
        )

    def _wait_for_snapshot_convergence(
        self,
        snapshot,
        projected_port_ids,
        response_flag,
        success_phase,
        failure_phase,
        attempts=None,
    ):
        status = self._poll_snapshot_convergence(
            snapshot,
            projected_port_ids,
            success_phase=success_phase,
            failure_phase=failure_phase,
            attempts=attempts,
        )
        return {
            "generation": snapshot["generation"],
            "desired_hash": snapshot.get("desired_hash"),
            "results": [],
            "active_instances": status.get("active_instances") or [],
            "managed_ports": status.get("managed_ports") or [],
            "port_statuses": status.get("port_statuses") or [],
            response_flag: True,
        }

    def _recover_snapshot_timeout(self, snapshot, projected_port_ids, timeout_error):
        recovery_started = time.time()
        last_error = timeout_error
        max_attempts = self._accepted_convergence_attempts()
        for attempt in range(1, max_attempts + 1):
            attempt_started = time.time()
            try:
                status = self.local_client.status()
            except LocalApiContractError:
                raise
            except LocalApiError as exc:
                last_error = exc
                LOG.warning(
                    "snapshot_timeout_status_check_failed host=%s generation=%s "
                    "attempt=%s attempts=%s error=%s",
                    self.host,
                    snapshot["generation"],
                    attempt,
                    max_attempts,
                    exc,
                )
            else:
                verdict, reason = self._snapshot_status_verdict(
                    snapshot,
                    projected_port_ids,
                    status,
                )
                if verdict in ("ready", "classified_degraded"):
                    LOG.warning(
                        "snapshot_timeout_converged host=%s generation=%s "
                        "attempt=%s projected_ports=%s managed_ports=%s",
                        self.host,
                        snapshot["generation"],
                        attempt,
                        len(projected_port_ids),
                        len(status.get("managed_ports") or []),
                    )
                    self._log_acl_delivery_profile(
                        phase="timeout_status_converged",
                        scope=(snapshot.get("scope") or {}).get("type", "full_host"),
                        generation=snapshot["generation"],
                        desired_hash=snapshot.get("desired_hash"),
                        projected_ports=len(projected_port_ids),
                        managed_ports=len(status.get("managed_ports") or []),
                        status_generation=status.get("generation"),
                        attempt=attempt,
                        attempts=max_attempts,
                        status_poll_attempt_ms=_elapsed_ms(attempt_started),
                        status_poll_total_ms=_elapsed_ms(recovery_started),
                    )
                    return {
                        "generation": snapshot["generation"],
                        "desired_hash": snapshot.get("desired_hash"),
                        "results": [],
                        "active_instances": status.get("active_instances") or [],
                        "managed_ports": status.get("managed_ports") or [],
                        "port_statuses": status.get("port_statuses") or [],
                        "recovered_after_timeout": True,
                    }
                if verdict == "failed":
                    if self._status_allows_unaccepted_snapshot_retry(
                        snapshot,
                        status,
                    ):
                        try:
                            response = self.local_client.put_snapshot(snapshot)
                        except LocalApiResponseError as exc:
                            if not self._is_restore_in_progress_error(exc):
                                raise
                            last_error = exc
                        except LocalApiTimeoutError as exc:
                            last_error = exc
                        else:
                            LOG.warning(
                                "snapshot_submit_retried_after_restore "
                                "host=%s generation=%s attempt=%s",
                                self.host,
                                snapshot["generation"],
                                attempt,
                            )
                            return response
                        if attempt < max_attempts:
                            self.sleeper(self.timeout_convergence_interval)
                        continue
                    raise LocalApiError(
                        "snapshot status failed terminal-ready validation: %s" %
                        reason
                    )
                last_error = LocalApiTimeoutError(
                    "status did not converge for generation %s: %s" % (
                        snapshot["generation"],
                        reason,
                    )
                )
                LOG.warning(
                    "snapshot_timeout_not_converged host=%s generation=%s "
                    "attempt=%s attempts=%s projected_ports=%s managed_ports=%s "
                    "status_generation=%s",
                    self.host,
                    snapshot["generation"],
                    attempt,
                    max_attempts,
                    len(projected_port_ids),
                    len(status.get("managed_ports") or []),
                    status.get("generation"),
                )

            if attempt < max_attempts:
                self.sleeper(self.timeout_convergence_interval)

        self._log_acl_delivery_profile(
            phase="timeout_status_failed",
            scope=(snapshot.get("scope") or {}).get("type", "full_host"),
            generation=snapshot["generation"],
            desired_hash=snapshot.get("desired_hash"),
            projected_ports=len(projected_port_ids),
            attempts=max_attempts,
            status_poll_total_ms=_elapsed_ms(recovery_started),
            error=last_error,
        )
        raise LocalApiTimeoutError(
            "snapshot submit timed out and status did not converge: %s" % last_error
        )

    def _is_restore_in_progress_error(self, error):
        return bool(
            isinstance(error, LocalApiResponseError) and
            error.status == 503 and
            isinstance(error.body, dict) and
            error.body.get("error") == "neutron_runtime_restore_in_progress"
        )

    def _status_allows_unaccepted_snapshot_retry(self, snapshot, status):
        pending_state, _, _ = self._pending_generation_status(status)
        if pending_state != "none":
            return False
        pending_action = self._remote_pending_action(
            snapshot,
            status,
            snapshot.get("desired_hash"),
        )
        if pending_action.get("action") != "force_full_resync":
            return False
        try:
            generation = _strict_scalar(snapshot.get("generation"), "integer")
        except ValueError:
            return False
        return self._generation_floor_from_status(status) < generation

    def _recover_delete_timeout(self, port_id, timeout_error):
        last_error = timeout_error
        for attempt in range(1, self.timeout_convergence_attempts + 1):
            try:
                status = self.local_client.status()
            except LocalApiContractError:
                raise
            except LocalApiError as exc:
                last_error = exc
                LOG.warning(
                    "delete_timeout_status_check_failed host=%s port_id=%s "
                    "attempt=%s attempts=%s error=%s",
                    self.host,
                    port_id,
                    attempt,
                    self.timeout_convergence_attempts,
                    exc,
                )
            else:
                if self._delete_status_converged(port_id, status):
                    LOG.warning(
                        "delete_timeout_converged host=%s port_id=%s "
                        "attempt=%s managed_ports=%s",
                        self.host,
                        port_id,
                        attempt,
                        len(status.get("managed_ports") or []),
                    )
                    return {
                        "port_id": port_id,
                        "status": "deleted",
                        "detached": True,
                        "recovered_after_timeout": True,
                    }
                last_error = LocalApiTimeoutError(
                    "delete status did not converge for port %s" % port_id
                )
                LOG.warning(
                    "delete_timeout_not_converged host=%s port_id=%s "
                    "attempt=%s attempts=%s managed_ports=%s",
                    self.host,
                    port_id,
                    attempt,
                    self.timeout_convergence_attempts,
                    len(status.get("managed_ports") or []),
                )

            if attempt < self.timeout_convergence_attempts:
                self.sleeper(self.timeout_convergence_interval)

        raise LocalApiTimeoutError(
            "port delete timed out and status did not converge: %s" % last_error
        )

    def _remote_status(self):
        try:
            return self.local_client.status()
        except LocalApiContractError:
            raise
        except LocalApiError as exc:
            LOG.warning(
                "remote_generation_floor_unavailable host=%s error=%s",
                self.host,
                exc,
            )
            return None

    def _remote_generation_floor(self):
        return self._generation_floor_from_status(self._remote_status())

    def _generation_floor_from_status(self, status):
        if status is None:
            return 0

        generations = []
        for key in (
            "accepted_generation",
            "applied_generation",
            "generation",
            "pending_generation",
            "last_classified_generation",
        ):
            try:
                generations.append(int(status.get(key) or 0))
            except (TypeError, ValueError):
                generations.append(0)
        return max(generations or [0])

    def _applied_generation_from_status(self, status):
        if not isinstance(status, dict):
            return None
        try:
            return _strict_scalar(status.get("applied_generation"), "integer")
        except ValueError:
            return None

    def _status_has_pending_generation(self, status):
        return self._pending_generation_status(status)[0] == "pending"

    def _pending_generation_status(self, status):
        if not isinstance(status, dict) or "pending_generation" not in status:
            return (
                "failed",
                None,
                "pending_generation (pending generation) is missing",
            )
        try:
            generation = _strict_scalar(
                status.get("pending_generation"),
                "integer",
                allow_none=True,
            )
        except ValueError:
            return (
                "failed",
                None,
                "pending_generation (pending generation) is invalid",
            )
        if generation is None:
            return "none", 0, None
        if generation == 0:
            return "none", 0, None
        return "pending", generation, None

    def _accepted_convergence_attempts(self):
        return max(self.timeout_convergence_attempts, 60)

    def _status_after_apply(self, snapshot, projected_port_ids, response):
        try:
            status = self.local_client.status()
        except LocalApiContractError:
            raise
        except LocalApiError as exc:
            LOG.warning(
                "post_apply_status_unavailable host=%s generation=%s error=%s",
                self.host,
                snapshot["generation"],
                exc,
            )
            raise LocalApiError(
                "post-apply status unavailable for generation %s: %s" % (
                    snapshot["generation"],
                    exc,
                )
            )
        verdict, reason = self._snapshot_status_verdict(
            snapshot,
            projected_port_ids,
            status,
        )
        if verdict in ("ready", "classified_degraded"):
            return status
        LOG.warning(
            "post_apply_status_not_converged host=%s generation=%s "
            "response_status=%s status_generation=%s verdict=%s reason=%s",
            self.host,
            snapshot["generation"],
            response.get("status"),
            status.get("generation"),
            verdict,
            reason,
        )
        if (
            verdict == "pending" and
            response.get("status") in ("accepted", "pending")
        ):
            return self._poll_snapshot_convergence(
                snapshot,
                projected_port_ids,
                success_phase="accepted_status_converged",
                failure_phase="accepted_status_failed",
                attempts=self._accepted_convergence_attempts(),
            )
        raise LocalApiError(
            "post-apply status failed terminal-ready validation: %s" % reason
        )

    def _pending_snapshot_converged(self, pending, status):
        if pending.get("projected_port_ids") and self.managed_domains:
            return False
        snapshot = {
            "generation": pending["generation"],
            "desired_hash": pending["desired_hash"],
        }
        return self._status_converged(
            snapshot,
            set(pending.get("projected_port_ids") or []),
            status,
        )

    def _pending_snapshot_hash_mismatch(self, pending, status):
        status_generation = self._applied_generation_from_status(status)
        if status_generation is None:
            return False
        try:
            pending_generation = _strict_scalar(
                pending.get("generation"),
                "integer",
            )
            status_hash = _strict_scalar(
                status.get("applied_desired_hash"),
                "string",
            )
            pending_hash = _strict_scalar(
                pending.get("desired_hash"),
                "string",
            )
        except ValueError:
            return False
        return bool(
            status_generation >= pending_generation and
            status_hash != pending_hash
        )

    def _pending_snapshot_was_not_accepted(
        self,
        pending,
        status,
        normalized_control,
    ):
        if normalized_control not in (
            ("classified", "degraded", "full_resync"),
            ("recovery", "degraded", "full_resync"),
            ("idle", "unknown", "full_resync"),
        ):
            return False
        if status.get("pending_generation") is not None:
            return False
        try:
            pending_generation = _strict_scalar(
                pending.get("generation"),
                "integer",
            )
            accepted_generation = _strict_scalar(
                status.get("accepted_generation"),
                "integer",
            )
            applied_generation = _strict_scalar(
                status.get("applied_generation"),
                "integer",
            )
        except ValueError:
            return False
        return bool(
            accepted_generation < pending_generation and
            applied_generation < pending_generation
        )

    def _pending_snapshot_is_stale(self, pending, status):
        try:
            status_generation = self._applied_generation_from_status(status)
            pending_generation = _strict_scalar(
                pending.get("generation"),
                "integer",
            )
            _strict_scalar(
                status.get("applied_desired_hash"),
                "string",
            )
            _strict_scalar(pending.get("desired_hash"), "string")
        except ValueError:
            return False
        if status_generation is None:
            return False
        if status_generation <= pending_generation:
            return False
        pending_state, _, _ = self._pending_generation_status(status)
        if pending_state != "none":
            return False
        return True

    def _status_converged(self, snapshot, projected_port_ids, status):
        return self._snapshot_status_verdict(
            snapshot, projected_port_ids, status,
        )[0] == "ready"

    def _is_v1_status(self, status):
        return bool(
            isinstance(status, dict) and
            (
                "status_schema_version" in status or
                "status_contract_hash" in status
            )
        )

    def _status_contract_mode(self, status):
        if not isinstance(status, dict):
            return "legacy_v0"
        identity = (
            status.get("status_schema_version"),
            status.get("status_contract_hash"),
        )
        if identity == (1, "v0.9-neutron-status-1"):
            return "v1"
        if identity == (2, "v0.9-neutron-status-2"):
            return "v2"
        if any(item is not None for item in identity):
            return "unknown"
        return "legacy_v0"

    def _normalized_domain_set(self, domains, collection_name):
        if not isinstance(domains, list):
            return None, "%s must be a list" % collection_name
        normalized = set()
        for domain in domains:
            try:
                domain_name = _strict_scalar(domain, "string")
            except ValueError:
                return None, "%s contains an invalid domain" % collection_name
            domain_name = _status_token(domain_name)
            if not domain_name:
                return None, "%s contains an invalid domain" % collection_name
            if domain_name in normalized:
                return None, "duplicate %s domain %s" % (
                    collection_name,
                    domain_name,
                )
            normalized.add(domain_name)
        return normalized, None

    def _v1_detached_tombstone_reason(
        self,
        port_id,
        row,
        applied_generation,
        applied_hash,
    ):
        if not isinstance(row, dict):
            return "port %s detached status is invalid" % port_id
        try:
            ifname = _strict_scalar(row.get("ifname"), "string")
            generation = _strict_scalar(row.get("generation"), "integer")
            desired_hash = _strict_scalar(
                row.get("desired_hash"),
                "string",
            )
        except ValueError:
            return "port %s detached identity is invalid" % port_id
        if not ifname.strip():
            return "port %s detached ifname is invalid" % port_id
        if generation <= 0 or generation > applied_generation:
            return "port %s detached identity is out of range" % port_id
        if not desired_hash.strip() or desired_hash.strip() != desired_hash:
            return "port %s detached desired hash is invalid" % port_id
        if generation == applied_generation and desired_hash != applied_hash:
            return "port %s detached desired hash does not match" % port_id
        if _status_token(row.get("status")) != "detached":
            return "port %s retains active runtime status" % port_id

        managed_domains, reason = self._normalized_domain_set(
            row.get("managed_domains"),
            "detached port status %s" % port_id,
        )
        if reason is not None:
            return reason
        domains, reason = _unique_row_index(
            row.get("domains"),
            "domain",
            "detached domain status evidence for port %s" % port_id,
            normalize=_status_token,
        )
        if reason is not None:
            return reason
        if managed_domains != set(domains):
            return "port %s detached domain identity does not match" % port_id
        for domain in domains.values():
            if (
                _status_token(domain.get("status")) != "not_requested" or
                _status_token(domain.get("effective_action")) != "cleanup" or
                _status_token(domain.get("support_disposition")) !=
                "not_applicable"
            ):
                return "port %s detached domain evidence is invalid" % port_id
        return None

    def _snapshot_status_verdict(self, snapshot, projected_port_ids, status):
        if status is None:
            return "pending", "status is unavailable"
        if not isinstance(status, dict):
            return "failed", "status payload is invalid"

        is_v1 = self._is_v1_status(status)
        classification = "ready"
        normalized_pending = False
        normalized_control_keys = (
            "transaction_state",
            "overall_readiness",
            "required_action",
        )
        normalized_control_presence = tuple(
            key in status for key in normalized_control_keys
        )
        has_normalized_control = all(normalized_control_presence)
        if any(normalized_control_presence) and not has_normalized_control:
            return "failed", "normalized status control is incomplete"
        if has_normalized_control:
            try:
                control = tuple(
                    _status_token(_strict_scalar(status.get(key), "string"))
                    for key in normalized_control_keys
                )
            except ValueError:
                return "failed", "normalized status control is invalid"
            if control == ("classified", "ready", "none"):
                classification = "ready"
            elif control == ("classified", "degraded", "none"):
                if not is_v1:
                    return (
                        "failed",
                        "decoded Legacy degraded classification is not "
                        "terminal-ready",
                    )
                classification = "classified_degraded"
            elif control == ("pending", "unknown", "poll"):
                normalized_pending = True
            else:
                return (
                    "failed",
                    "normalized status control %s/%s/%s is not a terminal "
                    "classification" % control,
                )

        try:
            expected_generation = _strict_scalar(
                snapshot.get("generation"),
                "integer",
            )
        except ValueError:
            return "failed", "snapshot generation is invalid"
        if not is_v1:
            try:
                authority_state = _strict_scalar(
                    status.get("authority_state"),
                    "string",
                )
            except ValueError:
                return "failed", "authority_state is invalid"
            if authority_state in TERMINAL_FAILURE_AUTHORITY_STATES:
                return (
                    "failed",
                    "authority_state is %s" % (authority_state or "missing"),
                )

        pending_state, _, pending_reason = self._pending_generation_status(status)
        if pending_state == "failed":
            return "failed", pending_reason
        if normalized_pending:
            if pending_state == "pending":
                return "pending", "pending generation remains"
            return "failed", "pending control has no pending generation"
        if pending_state == "pending":
            if has_normalized_control:
                return "failed", "classified status retains a pending generation"
            return "pending", "pending generation remains"

        try:
            applied_generation = _strict_scalar(
                status.get("applied_generation"),
                "integer",
            )
        except ValueError:
            return "failed", "applied_generation is invalid"
        if applied_generation < expected_generation:
            return "pending", "applied generation has not reached target"
        if applied_generation != expected_generation:
            return (
                "failed",
                "applied generation %s does not match %s" % (
                    applied_generation,
                    expected_generation,
                ),
            )
        try:
            accepted_generation = _strict_scalar(
                status.get("accepted_generation"),
                "integer",
            )
        except ValueError:
            return "failed", "accepted_generation is invalid"
        if accepted_generation != expected_generation:
            return (
                "failed",
                "accepted_generation %s does not match applied target %s" % (
                    accepted_generation,
                    expected_generation,
                ),
            )
        if is_v1:
            try:
                alias_generation = _strict_scalar(
                    status.get("generation"),
                    "integer",
                )
                classified_generation = _strict_scalar(
                    status.get("last_classified_generation"),
                    "integer",
                )
            except ValueError:
                return "failed", "classified generation identity is invalid"
            if alias_generation != expected_generation:
                return "failed", "generation alias does not match snapshot"
            if classified_generation != expected_generation:
                return "failed", "last classified generation does not match snapshot"

        try:
            expected_hash = _strict_scalar(
                snapshot.get("desired_hash"),
                "string",
            )
        except ValueError:
            return "failed", "snapshot desired_hash is invalid"
        try:
            status_hash = _strict_scalar(
                status.get("desired_hash"),
                "string",
            )
        except ValueError:
            return "failed", "desired_hash is invalid"
        if status_hash != expected_hash:
            return "failed", "desired_hash does not match snapshot"
        try:
            applied_hash = _strict_scalar(
                status.get("applied_desired_hash"),
                "string",
            )
        except ValueError:
            return "failed", "applied_desired_hash is invalid"
        if applied_hash != expected_hash:
            return "failed", "applied desired hash does not match snapshot"
        if not is_v1 and authority_state != "ready":
            return (
                "failed",
                "authority_state is %s, not ready" %
                (authority_state or "missing"),
            )

        projected_port_ids = set(
            port_id for port_id in projected_port_ids or [] if port_id
        )
        snapshot_ports = dict(
            (port.get("port_id"), port)
            for port in snapshot.get("ports") or []
            if port.get("port_id")
        )
        removed_scoped_port_ids = set()
        restart_affected_port_ids = set()
        scope = snapshot.get("scope") or {}
        if scope.get("type") == "port":
            if is_v1:
                affected_port_ids = set(snapshot_ports)
                scope_port_id = scope.get("port_id")
                if scope_port_id:
                    affected_port_ids.add(scope_port_id)
                removed_scoped_port_ids = (
                    affected_port_ids - projected_port_ids
                )
                validated_port_ids = (
                    affected_port_ids & projected_port_ids
                )
            else:
                affected_port_ids = set(
                    port_id for port_id, port in snapshot_ports.items()
                    if port.get("eligible") or port.get("managed_domains")
                )
                missing_projected = sorted(
                    affected_port_ids - projected_port_ids
                )
                if missing_projected:
                    return (
                        "failed",
                        "affected scoped ports are not projected: %s" %
                        missing_projected,
                    )
                validated_port_ids = affected_port_ids
        elif scope.get("type") == "restart":
            restart_affected_port_ids = set(
                port_id for port_id in scope.get("affected_port_ids") or []
                if port_id
            )
            if scope.get("pending_scope") == "port":
                removed_scoped_port_ids = (
                    restart_affected_port_ids - projected_port_ids
                )
            validated_port_ids = projected_port_ids
        else:
            validated_port_ids = projected_port_ids
        evidence_port_ids = projected_port_ids

        managed_ports, reason = _unique_row_index(
            status.get("managed_ports"),
            "port_id",
            "managed port evidence",
        )
        if reason is not None:
            return "failed", reason
        managed_port_ids = set(managed_ports)
        stale_managed = sorted(
            removed_scoped_port_ids & managed_port_ids
        )
        if stale_managed:
            return (
                "failed",
                "removed scoped ports remain managed: %s" % stale_managed,
            )
        missing_managed = sorted(evidence_port_ids - managed_port_ids)
        if missing_managed:
            return (
                "failed",
                "projected ports are not managed: %s" % missing_managed,
            )
        allows_unaffected_managed_ports = (
            scope.get("type") == "port" or
            (
                scope.get("type") == "restart" and
                scope.get("pending_scope") == "port"
            )
        )
        if not allows_unaffected_managed_ports:
            unexpected_managed = sorted(
                managed_port_ids - evidence_port_ids
            )
            if unexpected_managed:
                return (
                    "failed",
                    "full-host status retains unprojected managed ports: %s" %
                    unexpected_managed,
                )

        port_statuses, reason = _unique_row_index(
            status.get("port_statuses"),
            "port_id",
            "port status evidence",
        )
        if reason is not None:
            return "failed", reason
        restart_current_affected_port_ids = (
            restart_affected_port_ids & projected_port_ids
        )
        missing_affected_statuses = sorted(
            restart_current_affected_port_ids - set(port_statuses)
        )
        if missing_affected_statuses:
            return (
                "failed",
                "runtime status is missing for affected ports %s" %
                missing_affected_statuses,
            )
        for port_id in sorted(restart_current_affected_port_ids):
            runtime_port = port_statuses[port_id]
            try:
                port_generation = _strict_scalar(
                    runtime_port.get("generation"),
                    "integer",
                )
                port_hash = _strict_scalar(
                    runtime_port.get("desired_hash"),
                    "string",
                )
            except ValueError:
                return "failed", "port %s identity is invalid" % port_id
            if port_generation != expected_generation:
                return (
                    "failed",
                    "port %s generation %s does not match %s" % (
                        port_id,
                        port_generation,
                        expected_generation,
                    ),
                )
            if port_hash != expected_hash:
                return (
                    "failed",
                    "port %s desired hash does not match snapshot" % port_id,
                )
        for port_id in sorted(removed_scoped_port_ids):
            tombstone = port_statuses.get(port_id)
            if tombstone is None:
                continue
            reason = self._v1_detached_tombstone_reason(
                port_id,
                tombstone,
                applied_generation,
                applied_hash,
            )
            if reason is not None:
                return "failed", reason
        if not evidence_port_ids:
            if classification == "classified_degraded":
                return "failed", "degraded classification has no target evidence"
            return classification, None
        missing_statuses = sorted(evidence_port_ids - set(port_statuses))
        if missing_statuses:
            return (
                "failed",
                "runtime status is missing for ports %s" % missing_statuses,
            )
        runtime_domains_by_port = {}
        for port_id in sorted(evidence_port_ids):
            managed_port = managed_ports[port_id]
            runtime_port = port_statuses[port_id]
            runtime_domains, reason = _unique_row_index(
                runtime_port.get("domains"),
                "domain",
                "domain status evidence for port %s" % port_id,
                normalize=_status_token,
            )
            if reason is not None:
                return "failed", reason
            runtime_domains_by_port[port_id] = runtime_domains
            if is_v1:
                managed_ifname = managed_port.get("ifname")
                runtime_ifname = runtime_port.get("ifname")
                runtime_port_status = _status_token(
                    runtime_port.get("status")
                )
                if runtime_port_status in ("blocked", "error", "recovered"):
                    return (
                        "failed",
                        "port %s runtime status %s is unsafe" % (
                            port_id,
                            runtime_port_status,
                        ),
                    )
                if (
                    not isinstance(managed_ifname, _STRING_TYPES) or
                    not isinstance(runtime_ifname, _STRING_TYPES) or
                    managed_ifname != runtime_ifname
                ):
                    return (
                        "failed",
                        "port %s ifname identity does not match" % port_id,
                    )
                managed_domains, reason = self._normalized_domain_set(
                    managed_port.get("managed_domains"),
                    "managed port %s" % port_id,
                )
                if reason is not None:
                    return "failed", reason
                status_domains, reason = self._normalized_domain_set(
                    runtime_port.get("managed_domains"),
                    "port status %s" % port_id,
                )
                if reason is not None:
                    return "failed", reason
                if managed_domains != status_domains:
                    return (
                        "failed",
                        "port %s managed domain identity does not match" % port_id,
                    )
                if managed_domains != set(runtime_domains):
                    return (
                        "failed",
                        "port %s status domain identity does not match" % port_id,
                    )
                try:
                    port_generation = _strict_scalar(
                        runtime_port.get("generation"),
                        "integer",
                    )
                    port_hash = _strict_scalar(
                        runtime_port.get("desired_hash"),
                        "string",
                    )
                except ValueError:
                    return "failed", "port %s identity is invalid" % port_id
                if (
                    port_generation <= 0 or
                    port_generation > applied_generation
                ):
                    return "failed", "port %s identity is out of range" % port_id
                if not port_hash.strip() or port_hash.strip() != port_hash:
                    return "failed", "port %s desired hash is invalid" % port_id
                if (
                    port_generation == applied_generation and
                    port_hash != applied_hash
                ):
                    return (
                        "failed",
                        "port %s current desired hash does not match" % port_id,
                    )
        if not validated_port_ids:
            return classification, None
        saw_degraded = False
        for port_id in sorted(validated_port_ids):
            runtime_port = port_statuses.get(port_id)

            snapshot_port = snapshot_ports.get(port_id)
            requires_current_identity = (
                snapshot_port is not None or
                port_id in restart_affected_port_ids
            )
            if requires_current_identity:
                try:
                    port_generation = _strict_scalar(
                        runtime_port.get("generation"),
                        "integer",
                    )
                except ValueError:
                    return (
                        "failed",
                        "port %s generation is invalid" % port_id,
                    )
                if port_generation != expected_generation:
                    return (
                        "failed",
                        "port %s generation %s does not match %s" % (
                            port_id,
                            port_generation,
                            expected_generation,
                        ),
                    )
                try:
                    port_hash = _strict_scalar(
                        runtime_port.get("desired_hash"),
                        "string",
                    )
                except ValueError:
                    return (
                        "failed",
                        "port %s desired_hash is invalid" % port_id,
                    )
                if port_hash != expected_hash:
                    return (
                        "failed",
                        "port %s desired hash does not match snapshot" % port_id,
                    )
            if is_v1 and snapshot_port is not None:
                snapshot_ifname = snapshot_port.get("ifname")
                if (
                    not isinstance(snapshot_ifname, _STRING_TYPES) or
                    (
                        snapshot_ifname and
                        snapshot_ifname != managed_ports[port_id].get("ifname")
                    )
                ):
                    return (
                        "failed",
                        "port %s snapshot ifname does not match status" % port_id,
                    )
                snapshot_domains, reason = self._normalized_domain_set(
                    list(snapshot_port.get("managed_domains") or []),
                    "snapshot port %s" % port_id,
                )
                if reason is not None:
                    return "failed", reason
                managed_domains, reason = self._normalized_domain_set(
                    managed_ports[port_id].get("managed_domains"),
                    "managed port %s" % port_id,
                )
                if reason is not None:
                    return "failed", reason
                if snapshot_domains != managed_domains:
                    return (
                        "failed",
                        "port %s snapshot managed domains do not match status" %
                        port_id,
                    )
            if snapshot_port is None:
                required_domains = list(self.managed_domains)
            else:
                required_domains = list(
                    snapshot_port.get("managed_domains") or []
                )
            runtime_domains = runtime_domains_by_port[port_id]
            expects_not_requested = False
            port_degraded = False
            for domain in required_domains:
                domain_name = _status_token(domain)
                runtime_domain = runtime_domains.get(domain_name)
                if runtime_domain is None:
                    return (
                        "failed",
                        "runtime status is missing for port %s domain %s" % (
                            port_id,
                            domain_name,
                        ),
                    )
                domain_verdict, reason = self._domain_status_verdict(
                    domain_name,
                    snapshot_port,
                    runtime_domain,
                    classification=classification,
                    v1=is_v1,
                )
                if domain_verdict == "failed":
                    return "failed", "port %s %s" % (port_id, reason)
                if domain_verdict == "not_requested":
                    expects_not_requested = True
                elif domain_verdict == "degraded":
                    port_degraded = True
                    saw_degraded = True

            runtime_port_status = _status_token(runtime_port.get("status"))
            if port_degraded:
                expected_port_statuses = set(("degraded", "unsupported"))
            elif expects_not_requested:
                expected_port_statuses = set(("not_requested",))
            else:
                expected_port_statuses = set(("ready",))
            if runtime_port_status not in expected_port_statuses:
                return (
                    "failed",
                    "port %s runtime status %s does not match %s" % (
                        port_id,
                        runtime_port_status or "missing",
                        "/".join(sorted(expected_port_statuses)),
                    ),
                )

        if classification == "classified_degraded" and not saw_degraded:
            return "failed", "degraded classification has no degraded target domain"
        return classification, None

    def _domain_status_verdict(
        self,
        domain,
        snapshot_port,
        runtime_domain,
        classification="ready",
        v1=False,
    ):
        runtime_status = _status_token(runtime_domain.get("status"))
        runtime_action = _status_token(runtime_domain.get("effective_action"))
        runtime_support = _status_token(
            runtime_domain.get("support_disposition")
        )

        if domain != "acl":
            if runtime_status == "ready":
                if v1 and runtime_support != "supported":
                    return (
                        "failed",
                        "domain %s support disposition is %s" % (
                            domain,
                            runtime_support or "missing",
                        ),
                    )
                return "ready", None
            if (
                v1 and
                classification == "classified_degraded" and
                runtime_status == "degraded" and
                runtime_action in ("bypass", "unchanged", "no_op") and
                runtime_support in ("supported", "unsupported", "unknown")
            ):
                return "degraded", None
            return (
                "failed",
                "domain %s runtime status is %s" % (
                    domain,
                    runtime_status or "missing",
                ),
            )

        desired_acl = None
        if snapshot_port is not None and "acl" in snapshot_port:
            desired_acl = snapshot_port.get("acl") or {}
        if desired_acl is None and v1:
            if (
                runtime_status == "ready" and
                runtime_action == "enforce" and
                runtime_support == "supported"
            ):
                return "ready", None
            if (
                runtime_status == "not_requested" and
                runtime_action in ("bypass", "no_op") and
                runtime_support == "not_applicable"
            ):
                return "not_requested", None
            if (
                classification == "classified_degraded" and
                runtime_status == "degraded" and
                runtime_action in ("bypass", "unchanged", "no_op") and
                runtime_support in ("supported", "unsupported", "unknown")
            ):
                return "degraded", None
            return (
                "failed",
                "acl runtime status/action/support is %s/%s/%s" % (
                    runtime_status or "missing",
                    runtime_action or "missing",
                    runtime_support or "missing",
                ),
            )
        if desired_acl is None:
            return "failed", "desired acl evidence is missing"

        desired_status = _status_token(desired_acl.get("status") or "ready")
        desired_action = _status_token(desired_acl.get("effective_action"))
        desired_enabled = desired_acl.get("enabled") is not False
        if (
            desired_status == "not_requested" and
            not desired_enabled and
            desired_action in ("", "bypass", "no_op")
        ):
            allowed_actions = ("bypass", "no_op") if v1 else ("bypass",)
            if (
                runtime_status == "not_requested" and
                runtime_action in allowed_actions and
                (not v1 or runtime_support == "not_applicable")
            ):
                return "not_requested", None
            return (
                "failed",
                "acl runtime status/action is %s/%s for not-requested desired ACL" % (
                    runtime_status or "missing",
                    runtime_action or "missing",
                ),
            )

        if (
            desired_status == "ready" and
            desired_enabled and
            desired_action in ("", "enforce")
        ):
            if (
                runtime_status == "ready" and
                runtime_action == "enforce" and
                (not v1 or runtime_support == "supported")
            ):
                return "ready", None
            if (
                v1 and
                classification == "classified_degraded" and
                runtime_status == "degraded" and
                runtime_action in ("bypass", "unchanged", "no_op") and
                runtime_support in ("supported", "unsupported", "unknown")
            ):
                return "degraded", None
            return (
                "failed",
                "acl runtime status/action is %s/%s for ready desired ACL" % (
                    runtime_status or "missing",
                    runtime_action or "missing",
                ),
            )

        if (
            v1 and
            classification == "classified_degraded" and
            desired_status == "degraded" and
            not desired_enabled and
            desired_action in ("bypass", "unchanged", "no_op") and
            runtime_status == "degraded" and
            runtime_action in ("bypass", "unchanged", "no_op") and
            runtime_support in ("supported", "unsupported", "unknown")
        ):
            return "degraded", None

        return (
            "failed",
            "desired acl is not terminal-ready: %s/%s" % (
                desired_status or "missing",
                desired_action or "missing",
            ),
        )

    def _delete_status_converged(self, port_id, status):
        if not isinstance(status, dict):
            return False
        control_keys = (
            "transaction_state",
            "overall_readiness",
            "required_action",
        )
        control_presence = tuple(key in status for key in control_keys)
        if any(control_presence):
            if not all(control_presence):
                return False
            try:
                control = tuple(
                    _status_token(_strict_scalar(status.get(key), "string"))
                    for key in control_keys
                )
            except ValueError:
                return False
            if control not in (
                ("classified", "ready", "none"),
                ("classified", "degraded", "none"),
                ("classified", "degraded", "full_resync"),
            ):
                return False
        managed = status.get("managed_ports")
        if not isinstance(managed, list):
            return False
        managed_port_ids = set(
            port.get("port_id") for port in managed
            if isinstance(port, dict) and port.get("port_id")
        )
        return port_id not in managed_port_ids

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
