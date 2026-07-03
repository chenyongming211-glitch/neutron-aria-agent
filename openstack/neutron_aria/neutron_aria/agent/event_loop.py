from __future__ import absolute_import

import logging
import time

from neutron_aria.agent.effective_acl import REVISION_NEWER
from neutron_aria.agent.effective_acl import REVISION_UNKNOWN
from neutron_aria.agent.inventory import PortCandidateBuilder
from neutron_aria.agent.inventory import PortScopedSnapshotBuilder
from neutron_aria.agent.projection import ACTION_FULL_RESYNC
from neutron_aria.agent.projection import ProjectedStateIndex
from neutron_aria.agent.projection import REASON_LOCAL_PORT_UPDATE
from neutron_aria.agent.state import InMemorySnapshotStateStore
from neutron_aria.agent.status import AgentRuntimeStatus
from neutron_aria.agent.uds_client import LocalApiError
from neutron_aria.agent.uds_client import LocalApiTimeoutError


LOG = logging.getLogger(__name__)


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
        self.check_capabilities()
        self.recover_pending_state()
        ports = self._list_ports()
        acl_index = self._load_acl_index()
        builder = PortCandidateBuilder(
            self.host,
            managed_domains=self.managed_domains,
            acl_index=acl_index,
        )
        snapshot = builder.build_snapshot(
            ports,
            generation=0,
        )
        remote_status = self._remote_status()
        generation_floor = self._generation_floor_from_status(remote_status)
        prepared = self.state_store.prepare_snapshot(
            snapshot,
            minimum_generation=generation_floor,
        )
        snapshot["generation"] = prepared["generation"]
        snapshot["desired_hash"] = prepared["desired_hash"]
        projected_port_ids = self._projected_port_ids(snapshot)
        if (
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
        try:
            response = None
            if prepared.get("reused_pending"):
                response = self._maybe_recover_pending_before_submit(
                    snapshot,
                    projected_port_ids,
                )
            if response is None:
                response = self.local_client.put_snapshot(snapshot)
        except LocalApiTimeoutError as exc:
            response = self._recover_snapshot_timeout(snapshot, projected_port_ids, exc)
        self._raise_if_response_failed(response)
        apply_status = self._status_after_apply(snapshot, projected_port_ids, response)
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
        heartbeat = self.report_status()
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
        return {
            "snapshot": snapshot,
            "response": response,
            "status": self.runtime_status.to_dict(),
            "heartbeat": heartbeat,
        }

    def _load_acl_index(self):
        if self.acl_source is not None:
            self.acl_index = self.acl_source.load_index()
        return self.acl_index

    def safe_full_resync(self):
        try:
            return self.full_resync()
        except LocalApiError as exc:
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
            if self._pending_snapshot_hash_mismatch(snapshot, status):
                raise LocalApiError(
                    "pending snapshot hash mismatch: generation=%s desired_hash=%s" %
                    (snapshot["generation"], snapshot["desired_hash"])
                )
            if self._pending_snapshot_converged(snapshot, status):
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
        preview = self.dry_run_port_scoped_snapshot(
            port_id,
            binding_host=binding_host,
            revision_number=revision_number,
            allow_revisionless=allow_revisionless,
        )
        if preview.get("skipped_reason"):
            return preview

        snapshot = preview["snapshot"]
        remote_status = self._remote_status()
        generation_floor = self._generation_floor_from_status(remote_status)
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
        try:
            response = None
            if prepared.get("reused_pending"):
                response = self._maybe_recover_pending_before_submit(
                    snapshot,
                    projected_port_ids,
                )
            if response is None:
                response = self.local_client.put_port_snapshot(
                    port_id,
                    snapshot,
                    required_domains=self.managed_domains,
                )
        except LocalApiTimeoutError as exc:
            response = self._recover_snapshot_timeout(snapshot, projected_port_ids, exc)

        self._raise_if_response_failed(response)
        apply_status = self._status_after_apply(snapshot, projected_port_ids, response)
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
        heartbeat = self.report_status()
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

        enriched = []
        for status_row in statuses:
            payload = dict(status_row)
            metadata = acl_metadata.get(payload.get("port_id"))
            if metadata:
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
                }
        return metadata

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
        if not self._status_converged(snapshot, projected_port_ids, status):
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

    def _recover_snapshot_timeout(self, snapshot, projected_port_ids, timeout_error):
        last_error = timeout_error
        for attempt in range(1, self.timeout_convergence_attempts + 1):
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
                if (
                    self._status_converged(snapshot, projected_port_ids, status) or
                    self._status_transaction_committed(snapshot, status)
                ):
                    LOG.warning(
                        "snapshot_timeout_converged host=%s generation=%s "
                        "attempt=%s projected_ports=%s managed_ports=%s",
                        self.host,
                        snapshot["generation"],
                        attempt,
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
                        "recovered_after_timeout": True,
                    }
                last_error = LocalApiTimeoutError(
                    "status did not converge for generation %s" % snapshot["generation"]
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
            return None
        if (
            self._status_converged(snapshot, projected_port_ids, status) or
            self._status_transaction_committed(snapshot, status)
        ):
            return status
        LOG.warning(
            "post_apply_status_not_converged host=%s generation=%s "
            "response_status=%s status_generation=%s",
            self.host,
            snapshot["generation"],
            response.get("status"),
            status.get("generation"),
        )
        return None

    def _pending_snapshot_converged(self, pending, status):
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
        try:
            status_generation = int(
                status.get("applied_generation") or status.get("generation") or 0
            )
        except (TypeError, ValueError):
            return False
        status_hash = (
            status.get("applied_desired_hash") or
            status.get("desired_hash")
        )
        return bool(
            status_generation >= int(pending["generation"]) and
            status_hash and
            pending.get("desired_hash") and
            status_hash != pending.get("desired_hash")
        )

    def _status_converged(self, snapshot, projected_port_ids, status):
        try:
            status_generation = int(
                status.get("applied_generation") or status.get("generation") or 0
            )
        except (TypeError, ValueError):
            return False
        if status_generation < int(snapshot["generation"]):
            return False
        status_hash = (
            status.get("applied_desired_hash") or
            status.get("desired_hash")
        )
        if status_hash and snapshot.get("desired_hash") and status_hash != snapshot.get("desired_hash"):
            return False

        if not projected_port_ids:
            return True

        managed = status.get("managed_ports")
        if managed is None:
            return False
        managed_port_ids = set(
            port.get("port_id") for port in managed
            if port.get("port_id")
        )
        return projected_port_ids.issubset(managed_port_ids)

    def _status_transaction_committed(self, snapshot, status):
        try:
            status_generation = int(
                status.get("applied_generation") or status.get("generation") or 0
            )
        except (TypeError, ValueError):
            return False
        if status_generation < int(snapshot["generation"]):
            return False
        expected_hash = snapshot.get("desired_hash")
        if not expected_hash:
            return False
        status_hash = (
            status.get("applied_desired_hash") or
            status.get("desired_hash")
        )
        return bool(status_hash and status_hash == expected_hash)

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
