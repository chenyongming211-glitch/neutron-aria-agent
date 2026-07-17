from __future__ import absolute_import

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
from neutron_aria.agent.uds_client import LocalApiError
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
        remote_status = self._remote_status()
        remote_status_ms = _elapsed_ms(phase_started)
        generation_floor = self._generation_floor_from_status(remote_status)

        phase_started = time.time()
        pending_action = self._remote_pending_action(
            snapshot,
            remote_status,
            desired_snapshot_hash(snapshot),
        )
        if pending_action.get("action") == "wait":
            prepared = self.state_store.prepare_snapshot_at_generation(
                snapshot,
                pending_action["generation"],
                desired_hash=pending_action["desired_hash"],
            )
        elif pending_action.get("action") in ("block", "recover"):
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
            remote_status = self._remote_status()
            generation_floor = self._generation_floor_from_status(remote_status)
            pending_action = {}
            prepared = self.state_store.prepare_snapshot(
                snapshot,
                minimum_generation=generation_floor,
            )
        else:
            prepared = self.state_store.prepare_snapshot(
                snapshot,
                minimum_generation=generation_floor,
            )
        snapshot["generation"] = prepared["generation"]
        snapshot["desired_hash"] = prepared["desired_hash"]
        projected_port_ids = self._projected_port_ids(snapshot)
        if (
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
            if pending_action.get("action") == "wait":
                submit_mode = "remote_pending_same_hash"
                response = self._wait_for_snapshot_convergence(
                    snapshot,
                    projected_port_ids,
                    response_flag="recovered_remote_pending",
                    success_phase="remote_pending_converged",
                    failure_phase="remote_pending_not_converged",
                    attempts=self._accepted_convergence_attempts(),
                )
            elif prepared.get("reused_pending"):
                response = self._maybe_recover_pending_before_submit(
                    snapshot,
                    projected_port_ids,
                )
                if response is not None:
                    submit_mode = "pending_recovered_before_submit"
            if response is None:
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
        self._raise_if_response_failed(response)

        phase_started = time.time()
        apply_status = self._status_after_apply(snapshot, projected_port_ids, response)
        post_apply_status_ms = _elapsed_ms(phase_started)

        self.projected_port_ids = projected_port_ids
        self.projection_index.replace_from_resync(
            ports,
            snapshot,
            generation=snapshot["generation"],
        )
        managed_ports = self._response_managed_count(response, apply_status)
        self.state_store.commit_snapshot(
            snapshot["generation"],
            snapshot.get("desired_hash"),
            snapshot_ports=len(snapshot["ports"]),
            managed_ports=managed_ports,
        )
        self.runtime_status.mark_ready(
            snapshot["generation"],
            len(snapshot["ports"]),
            managed_ports,
            desired_hash=snapshot.get("desired_hash"),
            managed_ports_detail=self._managed_ports_from_status(apply_status),
            port_statuses=self._port_statuses_from_status(apply_status, snapshot),
            accepted_generation=self._status_generation(
                apply_status,
                "accepted_generation",
                snapshot["generation"],
            ),
            applied_generation=self._status_generation(
                apply_status,
                "applied_generation",
                snapshot["generation"],
            ),
        )
        self.runtime_status.update_projection_summary(self.projection_summary())

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
        except LocalApiError as exc:
            if self.runtime_status.reason != "stale_pending_snapshot_requires_operator":
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
        self.state_store.prepare_delete(port_id, reason=reason)
        try:
            response = self.local_client.delete_port(port_id)
        except LocalApiTimeoutError as exc:
            response = self._recover_delete_timeout(port_id, exc)
        self.projected_port_ids.discard(port_id)
        self.projection_index.remove(port_id)
        self.runtime_status.update_projection_summary(self.projection_summary())
        self.state_store.commit_delete(port_id)
        LOG.info(
            "delete_port_complete host=%s port_id=%s reason=%s projected_ports=%s",
            self.host,
            port_id,
            reason,
            len(self.projected_port_ids),
        )
        return response

    def recover_pending_state(self):
        recovered = []
        snapshot = self.state_store.pending_snapshot()
        if snapshot:
            status = self.local_client.status()
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
            if self._pending_snapshot_hash_mismatch(snapshot, status):
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
            if snapshot is None:
                pass
            elif self._pending_snapshot_converged(snapshot, status):
                managed_ports = len(status.get("managed_ports") or [])
                self.state_store.commit_snapshot(
                    snapshot["generation"],
                    snapshot["desired_hash"],
                    snapshot_ports=snapshot.get("snapshot_ports") or 0,
                    managed_ports=managed_ports,
                )
                self.projected_port_ids = set(snapshot.get("projected_port_ids") or [])
                self.projection_index.replace_projected_ids(
                    self.projected_port_ids,
                    generation=snapshot["generation"],
                )
                self.runtime_status.mark_ready(
                    snapshot["generation"],
                    snapshot.get("snapshot_ports") or 0,
                    managed_ports,
                    desired_hash=snapshot["desired_hash"],
                    managed_ports_detail=self._managed_ports_from_status(status),
                    port_statuses=self._port_statuses_from_status(status),
                    accepted_generation=self._status_generation(
                        status,
                        "accepted_generation",
                        snapshot["generation"],
                    ),
                    applied_generation=self._status_generation(
                        status,
                        "applied_generation",
                        snapshot["generation"],
                    ),
                )
                self.runtime_status.update_projection_summary(self.projection_summary())
                recovered.append("snapshot")
                LOG.warning(
                    "pending_snapshot_recovered host=%s generation=%s "
                    "projected_ports=%s managed_ports=%s",
                    self.host,
                    snapshot["generation"],
                    len(self.projected_port_ids),
                    managed_ports,
                )
            else:
                self.runtime_status.mark_degraded(
                    "pending_snapshot_unresolved",
                    "generation %s has not converged" % snapshot["generation"],
                )
                LOG.warning(
                    "pending_snapshot_unresolved host=%s generation=%s "
                    "projected_ports=%s",
                    self.host,
                    snapshot["generation"],
                    len(snapshot.get("projected_port_ids") or []),
                )

        pending_delete = self.state_store.pending_delete()
        if pending_delete:
            status = self.local_client.status()
            if self._delete_status_converged(pending_delete["port_id"], status):
                self.projected_port_ids.discard(pending_delete["port_id"])
                self.projection_index.remove(pending_delete["port_id"])
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
        remote_status = self._remote_status()
        remote_status_ms = _elapsed_ms(phase_started)
        generation_floor = self._generation_floor_from_status(remote_status)

        phase_started = time.time()
        prepared = self.state_store.prepare_scoped_snapshot(
            snapshot,
            minimum_generation=generation_floor,
        )
        snapshot["generation"] = prepared["generation"]
        snapshot["desired_hash"] = prepared["desired_hash"]
        projected_port_ids = set(
            self.state_store.pending_snapshot().get("projected_port_ids") or
            self.projected_port_ids
        )
        prepare_ms = _elapsed_ms(phase_started)

        uds_submit_ms = 0
        timeout_recovery_ms = 0
        submit_mode = "new_snapshot"
        try:
            response = None
            if prepared.get("reused_pending"):
                response = self._maybe_recover_pending_before_submit(
                    snapshot,
                    projected_port_ids,
                )
                if response is not None:
                    submit_mode = "pending_recovered_before_submit"
            if response is None:
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
            response = self._recover_snapshot_timeout(snapshot, projected_port_ids, exc)
            timeout_recovery_ms = _elapsed_ms(phase_started)
            submit_mode = "timeout_recovered"

        self._raise_if_response_failed(response)
        phase_started = time.time()
        apply_status = self._status_after_apply(snapshot, projected_port_ids, response)
        post_apply_status_ms = _elapsed_ms(phase_started)
        managed_ports = self._response_managed_count(response, apply_status)
        self.state_store.commit_scoped_snapshot(
            snapshot["generation"],
            snapshot.get("desired_hash"),
            managed_ports=managed_ports,
        )
        snapshot_port = snapshot["ports"][0] if snapshot.get("ports") else {}
        neutron_port = self._find_port_by_id(self._list_ports(), port_id) or {}
        self.projection_index.update_from_scoped_port(
            neutron_port,
            snapshot_port,
            generation=snapshot["generation"],
        )
        self.projected_port_ids = set(self.projection_index.port_ids())
        self.runtime_status.mark_ready(
            snapshot["generation"],
            getattr(self.runtime_status, "last_snapshot_ports", 0) or
            len(self.projected_port_ids),
            managed_ports,
            desired_hash=snapshot.get("desired_hash"),
            managed_ports_detail=self._managed_ports_from_status(apply_status),
            port_statuses=self._port_statuses_from_status(apply_status, snapshot),
            accepted_generation=self._status_generation(
                apply_status,
                "accepted_generation",
                snapshot["generation"],
            ),
            applied_generation=self._status_generation(
                apply_status,
                "applied_generation",
                snapshot["generation"],
            ),
        )
        self.runtime_status.update_projection_summary(self.projection_summary())
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

    def _raise_if_response_failed(self, response):
        errors = [
            result for result in response.get("results") or []
            if result.get("status") == "error"
        ]
        if errors:
            raise LocalApiError(
                "snapshot apply returned port errors: %s" % errors
            )

    def _maybe_recover_pending_before_submit(self, snapshot, projected_port_ids):
        try:
            status = self.local_client.status()
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
        if verdict != "ready":
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

    def _remote_pending_action(self, snapshot, status, desired_hash):
        if status is None:
            return {}
        pending_state, pending_generation, reason = (
            self._pending_generation_status(status)
        )
        if pending_state == "failed":
            raise LocalApiError(reason)
        if pending_state != "pending":
            return {}
        try:
            _strict_scalar(status.get("authority_state"), "string")
        except ValueError:
            raise LocalApiError("authority_state is invalid")

        remote_hash = status.get("desired_hash")
        applied_hash = (
            status.get("applied_desired_hash") or
            status.get("desired_hash")
        )
        if self._status_requires_pending_recovery(status):
            return {
                "action": "recover",
                "generation": pending_generation,
                "desired_hash": desired_hash,
                "remote_desired_hash": remote_hash,
                "applied_desired_hash": applied_hash,
            }
        if remote_hash and desired_hash and remote_hash == desired_hash:
            return {
                "action": "wait",
                "generation": pending_generation,
                "desired_hash": desired_hash,
                "remote_desired_hash": remote_hash,
                "applied_desired_hash": applied_hash,
            }
        return {
            "action": "block",
            "generation": pending_generation,
            "desired_hash": desired_hash,
            "remote_desired_hash": remote_hash,
            "applied_desired_hash": applied_hash,
        }

    def _status_requires_pending_recovery(self, status):
        if not isinstance(status, dict):
            return False
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
                if verdict == "ready":
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
        for attempt in range(1, self.timeout_convergence_attempts + 1):
            attempt_started = time.time()
            try:
                status = self.local_client.status()
            except LocalApiError as exc:
                last_error = exc
                LOG.warning(
                    "snapshot_timeout_status_check_failed host=%s generation=%s "
                    "attempt=%s attempts=%s error=%s",
                    self.host,
                    snapshot["generation"],
                    attempt,
                    self.timeout_convergence_attempts,
                    exc,
                )
            else:
                verdict, reason = self._snapshot_status_verdict(
                    snapshot,
                    projected_port_ids,
                    status,
                )
                if verdict == "ready":
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
                        attempts=self.timeout_convergence_attempts,
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
                    self.timeout_convergence_attempts,
                    len(projected_port_ids),
                    len(status.get("managed_ports") or []),
                    status.get("generation"),
                )

            if attempt < self.timeout_convergence_attempts:
                self.sleeper(self.timeout_convergence_interval)

        self._log_acl_delivery_profile(
            phase="timeout_status_failed",
            scope=(snapshot.get("scope") or {}).get("type", "full_host"),
            generation=snapshot["generation"],
            desired_hash=snapshot.get("desired_hash"),
            projected_ports=len(projected_port_ids),
            attempts=self.timeout_convergence_attempts,
            status_poll_total_ms=_elapsed_ms(recovery_started),
            error=last_error,
        )
        raise LocalApiTimeoutError(
            "snapshot submit timed out and status did not converge: %s" % last_error
        )

    def _recover_delete_timeout(self, port_id, timeout_error):
        last_error = timeout_error
        for attempt in range(1, self.timeout_convergence_attempts + 1):
            try:
                status = self.local_client.status()
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
        for key in ("accepted_generation", "applied_generation", "generation"):
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
        if verdict == "ready":
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

    def _snapshot_status_verdict(self, snapshot, projected_port_ids, status):
        if status is None:
            return "pending", "status is unavailable"
        if not isinstance(status, dict):
            return "failed", "status payload is invalid"

        try:
            expected_generation = _strict_scalar(
                snapshot.get("generation"),
                "integer",
            )
        except ValueError:
            return "failed", "snapshot generation is invalid"
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
        if pending_state == "pending":
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
        if authority_state != "ready":
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
        if (snapshot.get("scope") or {}).get("type") == "port":
            affected_port_ids = set(
                port_id for port_id, port in snapshot_ports.items()
                if port.get("eligible") or port.get("managed_domains")
            )
            missing_projected = sorted(affected_port_ids - projected_port_ids)
            if missing_projected:
                return (
                    "failed",
                    "affected scoped ports are not projected: %s" %
                    missing_projected,
                )
            validated_port_ids = affected_port_ids
        else:
            validated_port_ids = projected_port_ids
        evidence_port_ids = projected_port_ids
        if not evidence_port_ids:
            return "ready", None

        managed_ports, reason = _unique_row_index(
            status.get("managed_ports"),
            "port_id",
            "managed port evidence",
        )
        if reason is not None:
            return "failed", reason
        managed_port_ids = set(managed_ports)
        missing_managed = sorted(evidence_port_ids - managed_port_ids)
        if missing_managed:
            return (
                "failed",
                "projected ports are not managed: %s" % missing_managed,
            )

        port_statuses, reason = _unique_row_index(
            status.get("port_statuses"),
            "port_id",
            "port status evidence",
        )
        if reason is not None:
            return "failed", reason
        missing_statuses = sorted(evidence_port_ids - set(port_statuses))
        if missing_statuses:
            return (
                "failed",
                "runtime status is missing for ports %s" % missing_statuses,
            )
        runtime_domains_by_port = {}
        for port_id in sorted(evidence_port_ids):
            runtime_domains, reason = _unique_row_index(
                port_statuses[port_id].get("domains"),
                "domain",
                "domain status evidence for port %s" % port_id,
                normalize=_status_token,
            )
            if reason is not None:
                return "failed", reason
            runtime_domains_by_port[port_id] = runtime_domains
        if not validated_port_ids:
            return "ready", None
        for port_id in sorted(validated_port_ids):
            runtime_port = port_statuses.get(port_id)

            snapshot_port = snapshot_ports.get(port_id)
            if snapshot_port is not None:
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
            if snapshot_port is None:
                required_domains = list(self.managed_domains)
            else:
                required_domains = list(
                    snapshot_port.get("managed_domains") or []
                )
            runtime_domains = runtime_domains_by_port[port_id]
            expects_not_requested = False
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
                )
                if domain_verdict == "failed":
                    return "failed", "port %s %s" % (port_id, reason)
                if domain_verdict == "not_requested":
                    expects_not_requested = True

            runtime_port_status = _status_token(runtime_port.get("status"))
            expected_port_status = (
                "not_requested" if expects_not_requested else "ready"
            )
            if runtime_port_status != expected_port_status:
                return (
                    "failed",
                    "port %s runtime status %s does not match %s" % (
                        port_id,
                        runtime_port_status or "missing",
                        expected_port_status,
                    ),
                )

        return "ready", None

    def _domain_status_verdict(self, domain, snapshot_port, runtime_domain):
        runtime_status = _status_token(runtime_domain.get("status"))
        runtime_action = _status_token(runtime_domain.get("effective_action"))

        if domain != "acl":
            if runtime_status != "ready":
                return (
                    "failed",
                    "domain %s runtime status is %s" % (
                        domain,
                        runtime_status or "missing",
                    ),
                )
            return "ready", None

        desired_acl = None
        if snapshot_port is not None and "acl" in snapshot_port:
            desired_acl = snapshot_port.get("acl") or {}
        if desired_acl is None:
            return "failed", "desired acl evidence is missing"

        desired_status = _status_token(desired_acl.get("status") or "ready")
        desired_action = _status_token(desired_acl.get("effective_action"))
        desired_enabled = desired_acl.get("enabled") is not False
        if (
            desired_status == "not_requested" and
            not desired_enabled and
            desired_action in ("", "bypass")
        ):
            if runtime_status == "not_requested" and runtime_action == "bypass":
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
            if runtime_status == "ready" and runtime_action == "enforce":
                return "ready", None
            return (
                "failed",
                "acl runtime status/action is %s/%s for ready desired ACL" % (
                    runtime_status or "missing",
                    runtime_action or "missing",
                ),
            )

        return (
            "failed",
            "desired acl is not terminal-ready: %s/%s" % (
                desired_status or "missing",
                desired_action or "missing",
            ),
        )

    def _delete_status_converged(self, port_id, status):
        managed = status.get("managed_ports")
        if managed is None:
            return False
        managed_port_ids = set(
            port.get("port_id") for port in managed
            if port.get("port_id")
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
