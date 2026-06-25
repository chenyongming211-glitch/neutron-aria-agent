from __future__ import absolute_import

import logging
import time

from neutron_aria.agent.inventory import PortCandidateBuilder
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
        self.projected_port_ids = set()
        self.acl_index = acl_index
        self.timeout_convergence_attempts = max(1, int(timeout_convergence_attempts))
        self.timeout_convergence_interval = max(0.0, float(timeout_convergence_interval))
        self.sleeper = sleeper or time.sleep

    def check_capabilities(self):
        return self.local_client.capabilities(required_domains=self.managed_domains)

    def full_resync(self):
        self.check_capabilities()
        ports = self._list_ports()
        builder = PortCandidateBuilder(
            self.host,
            managed_domains=self.managed_domains,
            acl_index=self.acl_index,
        )
        snapshot = builder.build_snapshot(
            ports,
            generation=0,
        )
        generation_floor = self._remote_generation_floor()
        prepared = self.state_store.prepare_snapshot(
            snapshot,
            minimum_generation=generation_floor,
        )
        snapshot["generation"] = prepared["generation"]
        snapshot["desired_hash"] = prepared["desired_hash"]
        projected_port_ids = self._projected_port_ids(snapshot)
        try:
            response = self._maybe_recover_pending_before_submit(
                snapshot,
                projected_port_ids,
            )
            if response is None:
                response = self.local_client.put_snapshot(snapshot)
        except LocalApiTimeoutError as exc:
            response = self._recover_snapshot_timeout(snapshot, projected_port_ids, exc)
        self._raise_if_response_failed(response)
        self.projected_port_ids = projected_port_ids
        managed_ports = self._response_managed_count(response)
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
        )
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

    def delete_port(self, port_id):
        try:
            response = self.local_client.delete_port(port_id)
        except LocalApiTimeoutError as exc:
            response = self._recover_delete_timeout(port_id, exc)
        self.projected_port_ids.discard(port_id)
        LOG.info(
            "delete_port_complete host=%s port_id=%s projected_ports=%s",
            self.host,
            port_id,
            len(self.projected_port_ids),
        )
        return response

    def has_projected_port(self, port_id):
        return port_id in self.projected_port_ids

    def _list_ports(self):
        if hasattr(self.port_source, "list_ports_for_host"):
            return self.port_source.list_ports_for_host()
        return self.port_source.get_ports()

    def _projected_port_ids(self, snapshot):
        return set(
            port.get("port_id") for port in snapshot["ports"]
            if port.get("port_id") and (port.get("eligible") or port.get("managed_domains"))
        )

    def _response_managed_count(self, response):
        if response.get("managed_ports") is not None:
            return len(response.get("managed_ports") or [])
        return len(response.get("active_instances") or [])

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
                if self._status_converged(snapshot, projected_port_ids, status):
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

    def _remote_generation_floor(self):
        try:
            status = self.local_client.status()
        except LocalApiError as exc:
            LOG.warning(
                "remote_generation_floor_unavailable host=%s error=%s",
                self.host,
                exc,
            )
            return 0

        generations = []
        for key in ("accepted_generation", "applied_generation", "generation"):
            try:
                generations.append(int(status.get(key) or 0))
            except (TypeError, ValueError):
                generations.append(0)
        return max(generations or [0])

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
