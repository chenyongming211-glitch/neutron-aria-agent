from __future__ import absolute_import

import copy
import json
import os
import shutil
import tempfile
import unittest

from neutron_aria.agent.effective_acl import EffectiveAclIndex
from neutron_aria.agent.event_loop import SnapshotSynchronizer
from neutron_aria.agent.neutron_client import StaticPortSource
from neutron_aria.agent.ovsdb import OvsInterface
from neutron_aria.agent.state import InMemorySnapshotStateStore
from neutron_aria.agent.state import SnapshotStateStore
from neutron_aria.agent.status_reporter import StatusReportError
from neutron_aria.agent.uds_client import LocalApiContractError
from neutron_aria.agent.uds_client import LocalApiError
from neutron_aria.agent.uds_client import LocalApiTimeoutError
from neutron_aria.agent.uds_client import LocalApiTransportError
from neutron_aria.agent.uds_client import _decode_legacy_status_v0
from neutron_aria.tests.unit.status_contract_scenarios import status_scenario
from neutron_aria.tests.unit.status_contract_scenarios import status_scenario_negative_cases


def _terminal_status_for_snapshot(snapshot, authority_state="ready"):
    managed_ports = []
    port_statuses = []
    for port in snapshot.get("ports") or []:
        if not (port.get("eligible") or port.get("managed_domains")):
            continue

        port_id = port["port_id"]
        ifname = port.get("ifname") or "tap%s" % port_id[:11]
        managed_domains = list(port.get("managed_domains") or [])
        domains = []
        for domain in managed_domains:
            if domain == "acl":
                acl = port.get("acl") or {}
                domain_status = acl.get("status") or "ready"
                effective_action = acl.get("effective_action")
                if not effective_action:
                    effective_action = (
                        "enforce" if domain_status == "ready" else "bypass"
                    )
                reason = acl.get("reason")
            else:
                domain_status = "ready"
                effective_action = None
                reason = None
            domains.append({
                "domain": domain,
                "status": domain_status,
                "reason": reason,
                "effective_action": effective_action,
            })

        port_status = "ready"
        port_reason = None
        for terminal_status in (
            "error",
            "blocked",
            "degraded",
            "unsupported",
            "detached",
            "not_requested",
        ):
            matching = [
                domain for domain in domains
                if domain.get("status") == terminal_status
            ]
            if matching:
                port_status = terminal_status
                port_reason = matching[0].get("reason")
                break

        managed_ports.append({"port_id": port_id, "ifname": ifname})
        port_statuses.append({
            "port_id": port_id,
            "ifname": ifname,
            "generation": snapshot["generation"],
            "desired_hash": snapshot.get("desired_hash"),
            "status": port_status,
            "reason": port_reason,
            "managed_domains": managed_domains,
            "domains": domains,
        })

    return {
        "generation": snapshot["generation"],
        "accepted_generation": snapshot["generation"],
        "applied_generation": snapshot["generation"],
        "pending_generation": None,
        "desired_hash": snapshot.get("desired_hash"),
        "applied_desired_hash": snapshot.get("desired_hash"),
        "authority_state": authority_state,
        "managed_ports": managed_ports,
        "port_statuses": port_statuses,
        "active_instances": [port["ifname"] for port in managed_ports],
    }


def _ready_acl_snapshot(
    port_id="aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
    generation=1,
    desired_hash="hash-1",
    scope=None,
):
    snapshot = {
        "generation": generation,
        "desired_hash": desired_hash,
        "ports": [{
            "port_id": port_id,
            "eligible": True,
            "managed_domains": ["acl"],
            "acl": {
                "enabled": True,
                "status": "ready",
                "effective_action": "enforce",
            },
        }],
    }
    if scope is not None:
        snapshot["scope"] = scope
    return snapshot


class FakeOvsReader(object):
    def list_interfaces(self):
        return [
            OvsInterface(
                "tapaaaaaaaa-aa",
                external_ids={"iface-id": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"},
                ifindex=31,
                bridge="br-int",
            )
        ]


class FakeLocalClient(object):
    def __init__(self):
        self.capability_calls = []
        self.snapshots = []
        self.port_snapshots = []
        self.deleted_ports = []

    def capabilities(self, required_domains=None):
        self.capability_calls.append(list(required_domains or []))
        return {"api_version": "v1"}

    def put_snapshot(self, snapshot):
        self.snapshots.append(snapshot)
        return {"generation": snapshot["generation"], "results": []}

    def put_port_snapshot(self, port_id, snapshot, required_domains=None):
        self.port_snapshots.append({
            "port_id": port_id,
            "snapshot": snapshot,
            "required_domains": list(required_domains or []),
        })
        return {"generation": snapshot["generation"], "results": []}

    def delete_port(self, port_id):
        self.deleted_ports.append(port_id)
        return {"port_id": port_id, "status": "ok"}

    def status(self):
        if self.port_snapshots:
            scoped_snapshot = self.port_snapshots[-1]["snapshot"]
            aggregate = _terminal_status_for_snapshot(scoped_snapshot)
            managed_by_id = {}
            statuses_by_id = {}
            if self.snapshots:
                baseline = _terminal_status_for_snapshot(self.snapshots[-1])
                managed_by_id.update(dict(
                    (port["port_id"], port)
                    for port in baseline["managed_ports"]
                ))
                statuses_by_id.update(dict(
                    (port["port_id"], port)
                    for port in baseline["port_statuses"]
                ))
            for submitted in self.port_snapshots:
                snapshot = submitted["snapshot"]
                affected_ids = set(
                    port.get("port_id") for port in snapshot.get("ports") or []
                    if port.get("port_id")
                )
                for port_id in affected_ids:
                    managed_by_id.pop(port_id, None)
                    statuses_by_id.pop(port_id, None)
                scoped_status = _terminal_status_for_snapshot(snapshot)
                managed_by_id.update(dict(
                    (port["port_id"], port)
                    for port in scoped_status["managed_ports"]
                ))
                statuses_by_id.update(dict(
                    (port["port_id"], port)
                    for port in scoped_status["port_statuses"]
                ))
            aggregate["managed_ports"] = [
                managed_by_id[port_id] for port_id in sorted(managed_by_id)
            ]
            aggregate["port_statuses"] = [
                statuses_by_id[port_id] for port_id in sorted(statuses_by_id)
            ]
            aggregate["active_instances"] = [
                port["ifname"] for port in aggregate["managed_ports"]
            ]
            return aggregate
        if self.snapshots:
            return _terminal_status_for_snapshot(self.snapshots[-1])
        return {
            "generation": 0,
            "accepted_generation": 0,
            "applied_generation": 0,
            "pending_generation": None,
            "desired_hash": None,
            "applied_desired_hash": None,
            "authority_state": "idle",
            "managed_ports": [],
            "port_statuses": [],
            "active_instances": [],
        }


class TerminalIdentityMismatchLocalClient(FakeLocalClient):
    def __init__(self):
        FakeLocalClient.__init__(self)
        self.terminal_status_updates = {}
        self._terminal_status_mutation_armed = False

    def set_terminal_status_updates(self, **updates):
        self.terminal_status_updates = dict(updates)

    def put_snapshot(self, snapshot):
        response = FakeLocalClient.put_snapshot(self, snapshot)
        self._terminal_status_mutation_armed = bool(
            self.terminal_status_updates
        )
        return response

    def put_port_snapshot(self, port_id, snapshot, required_domains=None):
        response = FakeLocalClient.put_port_snapshot(
            self,
            port_id,
            snapshot,
            required_domains=required_domains,
        )
        self._terminal_status_mutation_armed = bool(
            self.terminal_status_updates
        )
        return response

    def status(self):
        status = FakeLocalClient.status(self)
        if self._terminal_status_mutation_armed:
            status.update(copy.deepcopy(self.terminal_status_updates))
        return status


class AdvancedGenerationLocalClient(FakeLocalClient):
    def status(self):
        if self.snapshots:
            return FakeLocalClient.status(self)
        return {
            "generation": 3,
            "accepted_generation": 3,
            "applied_generation": 3,
            "pending_generation": None,
            "managed_ports": [],
            "active_instances": [],
        }


class FailingLocalClient(FakeLocalClient):
    def capabilities(self, required_domains=None):
        raise LocalApiTransportError("socket unavailable")


class TimeoutThenConvergedLocalClient(FakeLocalClient):
    def put_snapshot(self, snapshot):
        self.snapshots.append(snapshot)
        raise LocalApiTimeoutError("timed out")

    def status(self):
        return FakeLocalClient.status(self)


class TimeoutThenCommittedWithPartialManagedClient(FakeLocalClient):
    def put_snapshot(self, snapshot):
        self.snapshots.append(snapshot)
        raise LocalApiTimeoutError("timed out")

    def status(self):
        if not self.snapshots:
            return FakeLocalClient.status(self)
        snapshot = self.snapshots[-1]
        managed_port_id = snapshot["ports"][0]["port_id"]
        status = _terminal_status_for_snapshot(snapshot)
        status["managed_ports"] = [status["managed_ports"][0]]
        status["port_statuses"] = [status["port_statuses"][0]]
        status["active_instances"] = ["tap%s" % managed_port_id[:11]]
        return status


class TimeoutNotConvergedLocalClient(FakeLocalClient):
    def put_snapshot(self, snapshot):
        self.snapshots.append(snapshot)
        raise LocalApiTimeoutError("timed out")

    def status(self):
        return {
            "generation": 0,
            "pending_generation": (
                self.snapshots[-1]["generation"] if self.snapshots else None
            ),
            "authority_state": "ready",
            "managed_ports": [],
            "active_instances": [],
        }


class ResponseErrorLocalClient(FakeLocalClient):
    def put_snapshot(self, snapshot):
        self.snapshots.append(snapshot)
        return {
            "generation": snapshot["generation"],
            "results": [{
                "port_id": "p1",
                "ifname": "tap-p1",
                "action": "attach",
                "status": "error",
                "reason": "boom",
            }],
        }


class ScopedResponseErrorLocalClient(FakeLocalClient):
    def put_port_snapshot(self, port_id, snapshot, required_domains=None):
        self.port_snapshots.append({
            "port_id": port_id,
            "snapshot": snapshot,
            "required_domains": list(required_domains or []),
        })
        return {
            "generation": snapshot["generation"],
            "results": [{
                "port_id": port_id,
                "ifname": "tap%s" % port_id[:11],
                "action": "update",
                "status": "error",
                "reason": "PORT_IFACE_NOT_FOUND",
            }],
        }


class StatusFromPortSnapshotLocalClient(FakeLocalClient):
    def status(self):
        if not self.port_snapshots:
            return FakeLocalClient.status(self)
        return _terminal_status_for_snapshot(
            self.port_snapshots[-1]["snapshot"]
        )


class RotatingAclSource(object):
    def __init__(self, indexes):
        self.indexes = list(indexes)
        self.calls = 0

    def load_index(self):
        index = self.indexes[min(self.calls, len(self.indexes) - 1)]
        self.calls += 1
        return index


class DeleteTimeoutThenConvergedLocalClient(FakeLocalClient):
    def delete_port(self, port_id):
        self.deleted_ports.append(port_id)
        raise LocalApiTimeoutError("timed out")

    def status(self):
        return {
            "generation": 1,
            "managed_ports": [],
            "active_instances": [],
        }


class DeleteTimeoutNotConvergedLocalClient(FakeLocalClient):
    def delete_port(self, port_id):
        self.deleted_ports.append(port_id)
        raise LocalApiTimeoutError("timed out")

    def status(self):
        if not self.deleted_ports:
            return FakeLocalClient.status(self)
        return {
            "generation": 1,
            "managed_ports": [{"port_id": self.deleted_ports[-1]}],
            "active_instances": [],
        }


class DeleteResponseErrorLocalClient(FakeLocalClient):
    def delete_port(self, port_id):
        self.deleted_ports.append(port_id)
        return {
            "port_id": port_id,
            "status": "error",
            "detached": False,
            "error": "purge failed",
        }


class DeleteWrongPortLocalClient(FakeLocalClient):
    def delete_port(self, port_id):
        self.deleted_ports.append(port_id)
        return {
            "port_id": "different-port",
            "status": "ok",
            "detached": True,
        }


class StatusAfterApplyLocalClient(FakeLocalClient):
    def status(self):
        return FakeLocalClient.status(self)


class ConvergedMissingPortStatusLocalClient(FakeLocalClient):
    def status(self):
        if not self.snapshots:
            return FakeLocalClient.status(self)
        snapshot = self.snapshots[-1]
        status = _terminal_status_for_snapshot(snapshot)
        status["port_statuses"] = []
        return status


class ConvergedStalePortStatusLocalClient(FakeLocalClient):
    def status(self):
        if not self.snapshots:
            return FakeLocalClient.status(self)
        snapshot = self.snapshots[-1]
        status = _terminal_status_for_snapshot(snapshot)
        port_status = status["port_statuses"][0]
        port_status.update({
            "status": "not_requested",
            "reason": "no_enabled_binding",
            "domains": [{
                "domain": "acl",
                "status": "not_requested",
                "effective_action": "bypass",
                "reason": "no_enabled_binding",
            }],
        })
        return status


class ReadyAclActionLocalClient(FakeLocalClient):
    def __init__(self, effective_action):
        FakeLocalClient.__init__(self)
        self.effective_action = effective_action

    def status(self):
        status = FakeLocalClient.status(self)
        if not self.snapshots:
            return status
        port_status = status["port_statuses"][0]
        port_status.update({
            "status": "ready",
            "reason": None,
        })
        port_status["domains"][0].update({
            "status": "ready",
            "reason": None,
            "effective_action": self.effective_action,
        })
        return status


class FixedStatusLocalClient(FakeLocalClient):
    def __init__(self, status):
        FakeLocalClient.__init__(self)
        self.fixed_status = status

    def status(self):
        return self.fixed_status


class RecoveringRemotePendingClient(FakeLocalClient):
    def __init__(self, pending_status):
        FakeLocalClient.__init__(self)
        self.pending_status = pending_status
        self.recoveries = []
        self.recovered = False

    def recover_pending_snapshot(self, expected_generation, expected_desired_hash=None):
        self.recoveries.append({
            "expected_generation": expected_generation,
            "expected_desired_hash": expected_desired_hash,
        })
        self.recovered = True
        return {
            "status": "recovered",
            "recovered_generation": expected_generation,
            "applied_generation": self.pending_status.get("applied_generation"),
            "desired_hash": self.pending_status.get("applied_desired_hash"),
        }

    def status(self):
        if self.snapshots:
            return FakeLocalClient.status(self)
        if self.recovered:
            return {
                "generation": self.pending_status.get("applied_generation"),
                "accepted_generation": self.pending_status.get("applied_generation"),
                "applied_generation": self.pending_status.get("applied_generation"),
                "pending_generation": None,
                "desired_hash": self.pending_status.get("applied_desired_hash"),
                "applied_desired_hash": self.pending_status.get("applied_desired_hash"),
                "managed_ports": [],
                "active_instances": [],
            }
        return self.pending_status


class FailingRemotePendingRecoveryClient(RecoveringRemotePendingClient):
    def recover_pending_snapshot(self, expected_generation, expected_desired_hash=None):
        self.recoveries.append({
            "expected_generation": expected_generation,
            "expected_desired_hash": expected_desired_hash,
        })
        raise LocalApiError("pending recovery failed")


class StalePendingThenConvergedLocalClient(FakeLocalClient):
    def __init__(self, stale_status):
        FakeLocalClient.__init__(self)
        self.stale_status = stale_status

    def status(self):
        if not self.snapshots:
            return self.stale_status
        return FakeLocalClient.status(self)


class SameGenerationMissingManagedClient(FakeLocalClient):
    def __init__(self, generation, desired_hash):
        FakeLocalClient.__init__(self)
        self.generation = generation
        self.desired_hash = desired_hash

    def status(self):
        if self.snapshots:
            return FakeLocalClient.status(self)
        return {
            "generation": self.generation,
            "accepted_generation": self.generation,
            "applied_generation": self.generation,
            "pending_generation": None,
            "desired_hash": self.desired_hash,
            "applied_desired_hash": self.desired_hash,
            "managed_ports": [],
            "active_instances": [],
        }


class PendingThenConvergedLocalClient(FakeLocalClient):
    def __init__(self, pending_status, converged_status):
        FakeLocalClient.__init__(self)
        self.statuses = [pending_status, converged_status]
        self.status_calls = 0

    def status(self):
        status = self.statuses[min(self.status_calls, len(self.statuses) - 1)]
        self.status_calls += 1
        return status


class AcceptedThenConvergedLocalClient(StatusAfterApplyLocalClient):
    def put_snapshot(self, snapshot):
        self.snapshots.append(snapshot)
        return {
            "generation": snapshot["generation"],
            "desired_hash": snapshot.get("desired_hash"),
            "accepted_generation": snapshot["generation"],
            "applied_generation": 0,
            "status": "accepted",
            "results": [],
        }


class AcceptedThenStatusUnavailableLocalClient(FakeLocalClient):
    def put_snapshot(self, snapshot):
        self.snapshots.append(snapshot)
        return {
            "generation": snapshot["generation"],
            "desired_hash": snapshot.get("desired_hash"),
            "accepted_generation": snapshot["generation"],
            "applied_generation": 0,
            "status": "accepted",
            "results": [],
        }

    def status(self):
        if self.snapshots:
            raise LocalApiTransportError("post-apply status unavailable")
        return FakeLocalClient.status(self)


class ScopedStatusUnavailableLocalClient(FakeLocalClient):
    def status(self):
        if self.port_snapshots:
            raise LocalApiTransportError("scoped post-apply status unavailable")
        return FakeLocalClient.status(self)


class RuntimeDegradedAuthorityLocalClient(FakeLocalClient):
    def status(self):
        if not self.snapshots:
            return FakeLocalClient.status(self)
        return _terminal_status_for_snapshot(
            self.snapshots[-1],
            authority_state="runtime_degraded",
        )


class AcceptedNotConvergedLocalClient(FakeLocalClient):
    def put_snapshot(self, snapshot):
        self.snapshots.append(snapshot)
        return {
            "generation": snapshot["generation"],
            "desired_hash": snapshot.get("desired_hash"),
            "accepted_generation": snapshot["generation"],
            "applied_generation": 0,
            "status": "accepted",
            "results": [],
        }

    def status(self):
        if not self.snapshots:
            return {
                "generation": 0,
                "pending_generation": None,
                "managed_ports": [],
                "active_instances": [],
            }
        snapshot = self.snapshots[-1]
        return {
            "generation": snapshot["generation"],
            "accepted_generation": snapshot["generation"],
            "applied_generation": 0,
            "pending_generation": snapshot["generation"],
            "desired_hash": snapshot.get("desired_hash"),
            "applied_desired_hash": None,
            "authority_state": "ready",
            "managed_ports": [],
            "active_instances": [],
        }


class AcceptedSlowPendingThenConvergedLocalClient(FakeLocalClient):
    def __init__(self, pending_polls=3):
        FakeLocalClient.__init__(self)
        self.pending_polls = pending_polls
        self.status_calls = 0

    def put_snapshot(self, snapshot):
        self.snapshots.append(snapshot)
        return {
            "generation": snapshot["generation"],
            "desired_hash": snapshot.get("desired_hash"),
            "accepted_generation": snapshot["generation"],
            "applied_generation": 0,
            "status": "accepted",
            "results": [],
        }

    def status(self):
        if not self.snapshots:
            return {
                "generation": 0,
                "pending_generation": None,
                "managed_ports": [],
                "active_instances": [],
            }
        self.status_calls += 1
        snapshot = self.snapshots[-1]
        port_ids = [
            port["port_id"] for port in snapshot["ports"]
            if port.get("eligible") or port.get("managed_domains")
        ]
        if self.status_calls <= self.pending_polls:
            return {
                "generation": snapshot["generation"],
                "accepted_generation": snapshot["generation"],
                "applied_generation": 0,
                "pending_generation": snapshot["generation"],
                "desired_hash": snapshot.get("desired_hash"),
                "applied_desired_hash": None,
                "authority_state": "ready",
                "managed_ports": [],
                "active_instances": [],
            }
        return _terminal_status_for_snapshot(snapshot)


class FakeStatusReporter(object):
    def __init__(self):
        self.statuses = []

    def report(self, runtime_status):
        payload = runtime_status.heartbeat_payload()
        self.statuses.append(payload)
        return {
            "agent_type": payload["agent_type"],
            "host": payload["host"],
            "configurations": payload,
        }


class FailingStatusReporter(object):
    def report(self, runtime_status):
        raise StatusReportError("rabbit down")


class FixtureStatusLocalClient(FakeLocalClient):
    def __init__(self, scenario):
        FakeLocalClient.__init__(self)
        self.scenario = copy.deepcopy(scenario)

    def capabilities(self, required_domains=None):
        self.capability_calls.append(list(required_domains or []))
        return copy.deepcopy(self.scenario["capabilities"])

    def status(self):
        if self.snapshots or self.port_snapshots:
            return copy.deepcopy(self.scenario["status"])
        return copy.deepcopy(self.scenario.get("pre_status"))


class ContractErrorStatusLocalClient(FakeLocalClient):
    def __init__(self, scenario):
        FakeLocalClient.__init__(self)
        self.scenario = copy.deepcopy(scenario)
        self.recoveries = []

    def capabilities(self, required_domains=None):
        self.capability_calls.append(list(required_domains or []))
        return copy.deepcopy(self.scenario["capabilities"])

    def status(self):
        raise LocalApiContractError(
            "unsupported status contract scenario %s" % self.scenario["id"]
        )

    def recover_pending_snapshot(self, expected_generation, expected_desired_hash=None):
        self.recoveries.append({
            "expected_generation": expected_generation,
            "expected_desired_hash": expected_desired_hash,
        })
        return {"status": "recovered"}


class PublicV1ActionLocalClient(FakeLocalClient):
    def __init__(self, scenario, status=None):
        FakeLocalClient.__init__(self)
        self.capabilities_payload = copy.deepcopy(scenario["capabilities"])
        self.initial_status = copy.deepcopy(status or scenario["status"])
        self.recoveries = []
        self.mutating_calls = []
        self.recovered = False

    def capabilities(self, required_domains=None):
        self.capability_calls.append(list(required_domains or []))
        return copy.deepcopy(self.capabilities_payload)

    def status(self):
        if self.snapshots:
            status = _terminal_status_for_snapshot(self.snapshots[-1])
            status.update({
                "status_schema_version": 1,
                "status_contract_hash": "v0.9-neutron-status-1",
                "transaction_state": "classified",
                "overall_readiness": "ready",
                "required_action": "none",
                "recovery_cause": None,
                "last_classified_generation": self.snapshots[-1]["generation"],
                "wal_status": "diagnostic_after_apply",
                "wal_replay_failures": 0,
            })
            for port_status in status["port_statuses"]:
                for domain in port_status.get("domains") or []:
                    domain["support_disposition"] = (
                        "not_applicable"
                        if domain.get("status") == "not_requested"
                        else "supported"
                    )
            return status
        if self.recovered:
            applied_generation = self.initial_status["applied_generation"]
            applied_hash = self.initial_status.get("applied_desired_hash")
            return {
                "status_schema_version": 1,
                "status_contract_hash": "v0.9-neutron-status-1",
                "transaction_state": "recovery",
                "overall_readiness": "degraded",
                "required_action": "full_resync",
                "recovery_cause": None,
                "last_classified_generation": applied_generation,
                "generation": applied_generation,
                "accepted_generation": applied_generation,
                "applied_generation": applied_generation,
                "pending_generation": None,
                "desired_hash": applied_hash,
                "applied_desired_hash": applied_hash,
                "wal_status": "recovered_pending_full_resync_required",
                "wal_replay_failures": 0,
                "authority_state": "recovered_pending_full_resync_required",
                "managed_ports": copy.deepcopy(
                    self.initial_status.get("managed_ports") or []
                ),
                "port_statuses": copy.deepcopy(
                    self.initial_status.get("port_statuses") or []
                ),
                "active_instances": copy.deepcopy(
                    self.initial_status.get("active_instances") or []
                ),
            }
        return copy.deepcopy(self.initial_status)

    def recover_pending_snapshot(
        self,
        expected_generation,
        expected_desired_hash=None,
    ):
        call = {
            "expected_generation": expected_generation,
            "expected_desired_hash": expected_desired_hash,
        }
        self.recoveries.append(call)
        self.mutating_calls.append("recover_pending")
        self.recovered = True
        return {
            "status": "recovered",
            "recovered_generation": expected_generation,
            "applied_generation": self.initial_status["applied_generation"],
            "desired_hash": self.initial_status.get("applied_desired_hash"),
        }

    def put_snapshot(self, snapshot):
        self.mutating_calls.append("put_full_snapshot")
        return FakeLocalClient.put_snapshot(self, snapshot)

    def put_port_snapshot(self, port_id, snapshot, required_domains=None):
        self.mutating_calls.append("put_port_snapshot")
        return FakeLocalClient.put_port_snapshot(
            self,
            port_id,
            snapshot,
            required_domains=required_domains,
        )

    def delete_port(self, port_id):
        self.mutating_calls.append("delete_port")
        return FakeLocalClient.delete_port(self, port_id)


class PreSubmitStatusUnavailableLocalClient(PublicV1ActionLocalClient):
    def status(self):
        raise LocalApiTimeoutError("pre-submit status unavailable")


class PreSubmitNoneStatusLocalClient(PublicV1ActionLocalClient):
    def status(self):
        return None


class PostRecoveryStatusUnavailableLocalClient(PublicV1ActionLocalClient):
    def status(self):
        if self.recovered:
            raise LocalApiTimeoutError("post-recovery status unavailable")
        return copy.deepcopy(self.initial_status)


class EventLoopTestCase(unittest.TestCase):
    def test_full_resync_builds_and_submits_snapshot(self):
        port_source = StaticPortSource([{
            "id": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
            "network_id": "net-a",
            "revision_number": 8,
            "device_owner": "compute:nova",
            "binding:host_id": "ostack2",
            "binding:vif_type": "ovs",
            "binding:vnic_type": "normal",
        }, {
            "id": "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
            "device_owner": "network:dhcp",
            "binding:host_id": "ostack2",
            "binding:vif_type": "ovs",
            "binding:vnic_type": "normal",
        }])
        local_client = FakeLocalClient()
        sync = SnapshotSynchronizer(
            "ostack2",
            port_source,
            FakeOvsReader(),
            local_client,
            managed_domains=["acl"],
        )

        result = sync.full_resync()

        self.assertEqual([["acl"]], local_client.capability_calls)
        self.assertEqual(1, result["snapshot"]["generation"])
        self.assertTrue(result["snapshot"]["desired_hash"])
        self.assertTrue(result["status"]["ready"])
        self.assertFalse(result["status"]["degraded"])
        self.assertEqual(1, len(local_client.snapshots))
        port = local_client.snapshots[0]["ports"][0]
        self.assertTrue(port["eligible"])
        self.assertEqual("", port["ifname"])
        self.assertEqual("pending_local_validation", port["disposition"])
        self.assertEqual(
            set(["aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"]),
            sync.projected_port_ids,
        )
        self.assertEqual(
            ["aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"],
            sync.projected_ports_for_network("net-a"),
        )
        self.assertEqual(
            {
                "projected_ports": 1,
                "indexed_networks": 1,
                "ports_with_network": 1,
                "ports_with_revision": 1,
            },
            result["status"]["projection_index"],
        )
        decision = sync.decide_port_update(
            "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
            binding_host="ostack2",
            revision_number=9,
        ).to_dict()
        self.assertEqual("full_resync", decision["action"])
        self.assertEqual("newer", decision["revision_status"])

    def test_full_resync_allows_ineligible_port_without_runtime_status(self):
        port_id = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
        sync = SnapshotSynchronizer(
            "ostack2",
            StaticPortSource([{
                "id": port_id,
                "device_owner": "network:dhcp",
                "binding:host_id": "ostack2",
                "binding:vif_type": "ovs",
                "binding:vnic_type": "normal",
            }]),
            FakeOvsReader(),
            FakeLocalClient(),
            managed_domains=["acl"],
        )

        result = sync.full_resync()

        snapshot_port = result["snapshot"]["ports"][0]
        self.assertFalse(snapshot_port["eligible"])
        self.assertEqual([], snapshot_port["managed_domains"])
        self.assertTrue(result["status"]["ready"])
        self.assertEqual([], result["status"]["last_port_statuses"])
        self.assertEqual(set(), sync.projected_port_ids)

    def test_full_resync_reuses_generation_for_same_desired_state(self):
        port_source = StaticPortSource([{
            "id": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
            "device_owner": "compute:nova",
            "binding:host_id": "ostack2",
            "binding:vif_type": "ovs",
            "binding:vnic_type": "normal",
        }])
        local_client = FakeLocalClient()
        sync = SnapshotSynchronizer(
            "ostack2",
            port_source,
            FakeOvsReader(),
            local_client,
            managed_domains=["acl"],
        )

        first = sync.full_resync()
        second = sync.full_resync()

        self.assertEqual(1, first["snapshot"]["generation"])
        self.assertEqual(1, second["snapshot"]["generation"])
        self.assertEqual(
            first["snapshot"]["desired_hash"],
            second["snapshot"]["desired_hash"],
        )

    def test_full_resync_advances_beyond_remote_generation_floor(self):
        port_source = StaticPortSource([{
            "id": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
            "device_owner": "compute:nova",
            "binding:host_id": "ostack2",
            "binding:vif_type": "ovs",
            "binding:vnic_type": "normal",
        }])
        local_client = AdvancedGenerationLocalClient()
        sync = SnapshotSynchronizer(
            "ostack2",
            port_source,
            FakeOvsReader(),
            local_client,
            managed_domains=["acl"],
        )

        result = sync.full_resync()

        self.assertEqual(4, result["snapshot"]["generation"])
        self.assertEqual(4, local_client.snapshots[0]["generation"])

    def test_full_resync_bumps_generation_when_remote_same_hash_not_converged(self):
        state_dir = tempfile.mkdtemp()
        try:
            port_source = StaticPortSource([{
                "id": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
                "device_owner": "compute:nova",
                "binding:host_id": "ostack2",
                "binding:vif_type": "ovs",
                "binding:vnic_type": "normal",
            }])
            state_store = SnapshotStateStore(state_dir)
            first_client = StatusAfterApplyLocalClient()
            first = SnapshotSynchronizer(
                "ostack2",
                port_source,
                FakeOvsReader(),
                first_client,
                managed_domains=["acl"],
                state_store=state_store,
            )
            first_result = first.full_resync()

            second_client = SameGenerationMissingManagedClient(
                first_result["snapshot"]["generation"],
                first_result["snapshot"]["desired_hash"],
            )
            second = SnapshotSynchronizer(
                "ostack2",
                port_source,
                FakeOvsReader(),
                second_client,
                managed_domains=["acl"],
                state_store=SnapshotStateStore(state_dir),
            )
            second_result = second.full_resync()

            self.assertGreater(
                second_result["snapshot"]["generation"],
                first_result["snapshot"]["generation"],
            )
            self.assertEqual(
                second_result["snapshot"]["generation"],
                second_client.snapshots[0]["generation"],
            )
            self.assertEqual(
                first_result["snapshot"]["desired_hash"],
                second_result["snapshot"]["desired_hash"],
            )
        finally:
            shutil.rmtree(state_dir)


    def _target_port_source(self):
        return StaticPortSource([{
            "id": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
            "network_id": "net-a",
            "revision_number": 8,
            "device_owner": "compute:nova",
            "binding:host_id": "ostack2",
            "binding:vif_type": "ovs",
            "binding:vnic_type": "normal",
        }])

    def _baseline_snapshot(self):
        return {
            "host": "ostack2",
            "ports": [{
                "port_id": "port-old",
                "ifname": "tap-port-old",
                "eligible": True,
                "managed_domains": ["acl"],
            }],
        }

    def _red_contract_error_is_not_generation_floor_absence_or_continued_submit(self):
        scenario = status_scenario("unknown-v1-contract")
        local_client = ContractErrorStatusLocalClient(scenario)
        sync = SnapshotSynchronizer(
            "ostack2",
            self._target_port_source(),
            FakeOvsReader(),
            local_client,
            managed_domains=["acl"],
        )

        result = sync.safe_full_resync()

        self.assertEqual([], local_client.snapshots)
        self.assertEqual([], local_client.port_snapshots)
        self.assertEqual([], local_client.recoveries)
        self.assertEqual(None, sync.state_store.pending_snapshot())
        self.assertTrue(result["status"]["degraded"])
        self.assertIn("status contract", result["status"]["last_error"])

    def _red_classified_degraded_records_only_classification_and_ready_heartbeat_history(self):
        scenario = status_scenario("classified-degraded-terminal")
        state_dir = tempfile.mkdtemp()
        try:
            store = SnapshotStateStore(state_dir)
            baseline = store.prepare_snapshot_at_generation(
                self._baseline_snapshot(),
                scenario["request_context"]["feature_ready_generation_before"],
                desired_hash="ready-hash-43",
            )
            try:
                store.commit_snapshot(
                    baseline["generation"],
                    baseline["desired_hash"],
                    snapshot_ports=1,
                    managed_ports=1,
                    feature_ready_domains=["acl"],
                )
            except TypeError as exc:
                self.fail(
                    "commit_snapshot lacks feature_ready_domains: %s" % exc
                )
            local_client = FixtureStatusLocalClient(scenario)
            status_reporter = FakeStatusReporter()
            acl_index = EffectiveAclIndex(
                policies=[{
                    "id": "policy-degraded",
                    "default_action": "allow",
                }],
                bindings=[{
                    "id": "binding-degraded",
                    "policy_id": "policy-degraded",
                    "target_type": "port",
                    "target_id": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
                }],
            )
            sync = SnapshotSynchronizer(
                "ostack2",
                self._target_port_source(),
                FakeOvsReader(),
                local_client,
                managed_domains=["acl"],
                state_store=SnapshotStateStore(state_dir),
                status_reporter=status_reporter,
                acl_index=acl_index,
            )
            try:
                sync.runtime_status.mark_ready(
                    scenario["request_context"]["feature_ready_generation_before"],
                    1,
                    1,
                    desired_hash="ready-hash-43",
                    managed_ports_detail=scenario["pre_status"]["managed_ports"],
                    port_statuses=scenario["pre_status"]["port_statuses"],
                    feature_ready_generation_by_domain={"acl": 43},
                )
            except TypeError as exc:
                self.fail(
                    "mark_ready lacks feature-ready domain history: %s" % exc
                )

            result = sync.safe_full_resync()
            state = SnapshotStateStore(state_dir).to_dict()
            submitted = local_client.snapshots[0]
            submitted_acl = submitted["ports"][0]["acl"]

            self.assertEqual(
                scenario["request_context"]["expected_desired_hash"],
                submitted["desired_hash"],
            )
            self.assertEqual(True, submitted_acl["enabled"])
            self.assertEqual("ready", submitted_acl["status"])
            self.assertEqual("enforce", submitted_acl["effective_action"])
            self.assertEqual("policy-degraded", submitted_acl["policy_id"])
            self.assertEqual("binding-degraded", submitted_acl["binding_id"])
            self.assertEqual(
                scenario["status"]["last_classified_generation"],
                state.get("last_classified_generation"),
            )
            self.assertEqual(
                scenario["request_context"]["projected_port_ids"],
                state.get("last_classified_projected_port_ids"),
            )
            self.assertEqual(
                scenario["request_context"]["feature_ready_generation_before"],
                state.get("last_feature_ready_generation"),
            )
            self.assertEqual(
                scenario["request_context"]["feature_ready_projected_port_ids_before"],
                state.get("last_feature_ready_projected_port_ids"),
            )
            self.assertEqual(None, SnapshotStateStore(state_dir).pending_snapshot())
            self.assertEqual(
                scenario["request_context"]["feature_ready_generation_before"],
                sync.runtime_status.last_generation,
            )
            self.assertFalse(sync.runtime_status.ready)
            self.assertTrue(sync.runtime_status.degraded)
            self.assertEqual(1, len(status_reporter.statuses))
            self.assertEqual(
                scenario["request_context"]["feature_ready_generation_before"],
                status_reporter.statuses[0]["last_generation"],
            )
            self.assertEqual(
                {"acl": scenario["request_context"]["feature_ready_generation_before"]},
                status_reporter.statuses[0].get(
                    "last_feature_ready_generation_by_domain"
                ),
            )
            self.assertEqual("degraded", scenario["expected_python"]["publish_readiness"])
            self.assertTrue(result["status"]["degraded"])
        finally:
            shutil.rmtree(state_dir)

    def _red_restart_routes_from_classified_ids_without_changing_ready_history(self):
        scenario = status_scenario("restart-classified-routing")
        state_dir = tempfile.mkdtemp()
        try:
            path = os.path.join(state_dir, "snapshot-state.json")
            with open(path, "w") as stream:
                json.dump(scenario["durable_state"], stream, sort_keys=True)
                stream.write("\n")
            sync = SnapshotSynchronizer(
                "ostack2",
                StaticPortSource([]),
                FakeOvsReader(),
                FixtureStatusLocalClient(scenario),
                managed_domains=["acl"],
                state_store=SnapshotStateStore(state_dir),
            )
            context = scenario["request_context"]

            update = sync.decide_port_update(
                context["update_port_id"],
                binding_host="ostack2",
                revision_number=51,
            ).to_dict()
            delete = sync.decide_port_delete(
                context["delete_port_id"],
            ).to_dict()
            removed_delete = sync.decide_port_delete(
                context["removed_port_id"],
            ).to_dict()
            state = sync.state_store.to_dict()

            self.assertEqual(
                set(context["classified_projected_port_ids"]),
                sync.projected_port_ids,
            )
            self.assertEqual(
                scenario["expected_python"]["restart_routes"]["port-c-update"],
                update["reason"],
            )
            self.assertEqual(
                scenario["expected_python"]["restart_routes"]["port-c-delete"],
                delete["action"],
            )
            self.assertEqual(
                scenario["expected_python"]["restart_routes"]["port-b-delete"],
                removed_delete["action"],
            )
            self.assertEqual(
                context["feature_ready_projected_port_ids"],
                state["last_feature_ready_projected_port_ids"],
            )
            self.assertEqual(
                scenario["durable_state"]["last_feature_ready_generation_by_domain"],
                state["last_feature_ready_generation_by_domain"],
            )
        finally:
            shutil.rmtree(state_dir)

    def test_full_resync_resubmits_same_generation_when_remote_converged(self):
        state_dir = tempfile.mkdtemp()
        try:
            port_source = StaticPortSource([{
                "id": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
                "device_owner": "compute:nova",
                "binding:host_id": "ostack2",
                "binding:vif_type": "ovs",
                "binding:vnic_type": "normal",
            }])
            first_client = StatusAfterApplyLocalClient()
            first = SnapshotSynchronizer(
                "ostack2",
                port_source,
                FakeOvsReader(),
                first_client,
                managed_domains=["acl"],
                state_store=SnapshotStateStore(state_dir),
            )
            first_result = first.full_resync()
            converged_status = first_client.status()

            second_client = FixedStatusLocalClient(converged_status)
            second = SnapshotSynchronizer(
                "ostack2",
                port_source,
                FakeOvsReader(),
                second_client,
                managed_domains=["acl"],
                state_store=SnapshotStateStore(state_dir),
            )
            second_result = second.full_resync()

            self.assertEqual(
                first_result["snapshot"]["generation"],
                second_result["snapshot"]["generation"],
            )
            self.assertEqual(1, len(second_client.snapshots))
            self.assertFalse(second_result["response"].get("recovered_before_submit"))
        finally:
            shutil.rmtree(state_dir)

    def test_full_resync_waits_when_remote_pending_same_hash(self):
        state_dir = tempfile.mkdtemp()
        try:
            port_id = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
            port_source = StaticPortSource([{
                "id": port_id,
                "device_owner": "compute:nova",
                "binding:host_id": "ostack2",
                "binding:vif_type": "ovs",
                "binding:vnic_type": "normal",
            }])
            first_client = StatusAfterApplyLocalClient()
            first = SnapshotSynchronizer(
                "ostack2",
                port_source,
                FakeOvsReader(),
                first_client,
                managed_domains=["acl"],
                state_store=SnapshotStateStore(state_dir),
            )
            first_result = first.full_resync()
            converged_status = first_client.status()
            pending_status = dict(converged_status)
            pending_status.update({
                "applied_generation": 0,
                "applied_desired_hash": None,
                "pending_generation": first_result["snapshot"]["generation"],
                "managed_ports": [],
                "active_instances": [],
            })
            second_client = PendingThenConvergedLocalClient(
                pending_status,
                converged_status,
            )
            second = SnapshotSynchronizer(
                "ostack2",
                port_source,
                FakeOvsReader(),
                second_client,
                managed_domains=["acl"],
                state_store=SnapshotStateStore(state_dir),
                timeout_convergence_attempts=2,
                timeout_convergence_interval=0,
            )

            second_result = second.full_resync()

            self.assertEqual([], second_client.snapshots)
            self.assertTrue(second_result["response"]["recovered_remote_pending"])
            self.assertEqual(
                first_result["snapshot"]["generation"],
                second_result["snapshot"]["generation"],
            )
            self.assertTrue(second_result["status"]["ready"])
        finally:
            shutil.rmtree(state_dir)

    def test_remote_pending_action_recovers_blocked_same_hash(self):
        sync = SnapshotSynchronizer(
            "ostack2",
            StaticPortSource([]),
            FakeOvsReader(),
            FakeLocalClient(),
            managed_domains=["acl"],
        )
        for authority_state in (
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
        ):
            with self.subTest(authority_state=authority_state):
                status = {
                    "accepted_generation": 10,
                    "applied_generation": 10,
                    "pending_generation": 11,
                    "desired_hash": "hash-11",
                    "applied_desired_hash": "hash-10",
                    "authority_state": authority_state,
                }
                action = sync._remote_pending_action({}, status, "hash-11")

                self.assertEqual(
                    (True, "recover"),
                    (
                        sync._status_requires_pending_recovery(status),
                        action["action"],
                    ),
                )
                self.assertEqual(11, action["generation"])
                self.assertEqual("hash-11", action["remote_desired_hash"])

    def test_remote_pending_action_rejects_malformed_authority_state(self):
        sync = SnapshotSynchronizer(
            "ostack2",
            StaticPortSource([]),
            FakeOvsReader(),
            FakeLocalClient(),
            managed_domains=["acl"],
        )
        for authority_state in ([], {}, True, 1, "", None):
            with self.subTest(authority_state=authority_state):
                status = {
                    "accepted_generation": 10,
                    "applied_generation": 10,
                    "pending_generation": 11,
                    "desired_hash": "hash-11",
                    "applied_desired_hash": "hash-10",
                    "authority_state": authority_state,
                }
                try:
                    sync._remote_pending_action({}, status, "hash-11")
                except LocalApiError as exc:
                    self.assertIn("authority_state", str(exc))
                except TypeError as exc:
                    self.fail("malformed authority_state raised TypeError: %s" % exc)
                else:
                    self.fail("malformed authority_state did not fail closed")

    def test_pending_recovery_helper_rejects_malformed_authority_state(self):
        sync = SnapshotSynchronizer(
            "ostack2",
            StaticPortSource([]),
            FakeOvsReader(),
            FakeLocalClient(),
            managed_domains=["acl"],
        )
        invalid_values = ([], {}, True, 1, "", None)
        noncanonical_values = (
            "BLOCKED_RECOVERY_REQUIRED",
            " blocked_recovery_required",
            "blocked_recovery_required ",
        )
        for authority_state in invalid_values + noncanonical_values:
            with self.subTest(authority_state=authority_state):
                status = {
                    "pending_generation": 11,
                    "authority_state": authority_state,
                }
                try:
                    requires_recovery = sync._status_requires_pending_recovery(
                        status
                    )
                except TypeError as exc:
                    self.fail("malformed authority_state raised TypeError: %s" % exc)

                self.assertFalse(requires_recovery)

    def test_remote_pending_action_rejects_invalid_pending_generation(self):
        sync = SnapshotSynchronizer(
            "ostack2",
            StaticPortSource([]),
            FakeOvsReader(),
            FakeLocalClient(),
            managed_domains=["acl"],
        )
        missing = object()
        for pending_generation in (
            missing,
            "0",
            "11",
            True,
            False,
            0.0,
            11.0,
            -1,
            "malformed",
        ):
            with self.subTest(pending_generation=pending_generation):
                status = {
                    "accepted_generation": 10,
                    "applied_generation": 10,
                    "desired_hash": "hash-11",
                    "applied_desired_hash": "hash-10",
                    "authority_state": "ready",
                }
                if pending_generation is not missing:
                    status["pending_generation"] = pending_generation
                with self.assertRaises(LocalApiError) as ctx:
                    sync._remote_pending_action({}, status, "hash-11")

                self.assertIn("pending_generation", str(ctx.exception))

        for pending_generation in (None, 0):
            with self.subTest(pending_generation=pending_generation):
                action = sync._remote_pending_action({}, {
                    "accepted_generation": 10,
                    "applied_generation": 10,
                    "pending_generation": pending_generation,
                    "desired_hash": "hash-11",
                    "applied_desired_hash": "hash-10",
                    "authority_state": "ready",
                }, "hash-11")
                self.assertEqual({}, action)

        action = sync._remote_pending_action({}, {
            "accepted_generation": 10,
            "applied_generation": 10,
            "pending_generation": 11,
            "desired_hash": "hash-11",
            "applied_desired_hash": "hash-10",
            "authority_state": "ready",
        }, "hash-11")
        self.assertEqual("wait", action["action"])
        self.assertEqual(11, action["generation"])

    def test_full_resync_recovers_blocked_same_hash_before_submit(self):
        port_source = StaticPortSource([{
            "id": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
            "device_owner": "compute:nova",
            "binding:host_id": "ostack2",
            "binding:vif_type": "ovs",
            "binding:vnic_type": "normal",
        }])
        probe = SnapshotSynchronizer(
            "ostack2",
            port_source,
            FakeOvsReader(),
            FakeLocalClient(),
            managed_domains=["acl"],
        ).full_resync()
        desired_hash = probe["snapshot"]["desired_hash"]
        local_client = RecoveringRemotePendingClient({
            "generation": 11,
            "accepted_generation": 10,
            "applied_generation": 10,
            "pending_generation": 11,
            "desired_hash": desired_hash,
            "applied_desired_hash": "hash-10",
            "authority_state": "blocked_recovery_required",
            "managed_ports": [],
            "active_instances": [],
        })
        sync = SnapshotSynchronizer(
            "ostack2",
            port_source,
            FakeOvsReader(),
            local_client,
            managed_domains=["acl"],
            timeout_convergence_attempts=1,
            timeout_convergence_interval=0,
        )

        result = sync.full_resync()

        self.assertEqual([{
            "expected_generation": 11,
            "expected_desired_hash": desired_hash,
        }], local_client.recoveries)
        self.assertEqual(1, len(local_client.snapshots))
        self.assertGreater(result["snapshot"]["generation"], 10)
        self.assertTrue(result["status"]["ready"])

    def test_failed_blocked_same_hash_recovery_preserves_local_pending(self):
        state_dir = tempfile.mkdtemp()
        try:
            port_source = StaticPortSource([{
                "id": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
                "device_owner": "compute:nova",
                "binding:host_id": "ostack2",
                "binding:vif_type": "ovs",
                "binding:vnic_type": "normal",
            }])
            probe = SnapshotSynchronizer(
                "ostack2",
                port_source,
                FakeOvsReader(),
                FakeLocalClient(),
                managed_domains=["acl"],
            ).full_resync()
            desired_hash = probe["snapshot"]["desired_hash"]
            store = SnapshotStateStore(state_dir)
            store.prepare_snapshot_at_generation(
                probe["snapshot"],
                11,
                desired_hash=desired_hash,
            )
            local_client = FailingRemotePendingRecoveryClient({
                "generation": 11,
                "accepted_generation": 10,
                "applied_generation": 10,
                "pending_generation": 11,
                "desired_hash": desired_hash,
                "applied_desired_hash": "hash-10",
                "authority_state": "blocked_recovery_required",
                "managed_ports": [],
                "active_instances": [],
            })
            sync = SnapshotSynchronizer(
                "ostack2",
                port_source,
                FakeOvsReader(),
                local_client,
                managed_domains=["acl"],
                state_store=SnapshotStateStore(state_dir),
                timeout_convergence_attempts=1,
                timeout_convergence_interval=0,
            )

            result = sync.safe_full_resync()
            pending = SnapshotStateStore(state_dir).pending_snapshot()

            self.assertEqual([{
                "expected_generation": 11,
                "expected_desired_hash": desired_hash,
            }], local_client.recoveries)
            self.assertEqual([], local_client.snapshots)
            self.assertTrue(result["status"]["degraded"])
            self.assertEqual(11, pending["generation"])
            self.assertEqual(desired_hash, pending["desired_hash"])
        finally:
            shutil.rmtree(state_dir)

    def test_safe_full_resync_blocks_when_remote_pending_different_hash(self):
        port_source = StaticPortSource([{
            "id": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
            "device_owner": "compute:nova",
            "binding:host_id": "ostack2",
            "binding:vif_type": "ovs",
            "binding:vnic_type": "normal",
        }])
        local_client = FixedStatusLocalClient({
            "generation": 10,
            "accepted_generation": 10,
            "applied_generation": 9,
            "pending_generation": 10,
            "desired_hash": "different-hash",
            "applied_desired_hash": "old-hash",
            "authority_state": "ready",
            "managed_ports": [],
            "active_instances": [],
        })
        sync = SnapshotSynchronizer(
            "ostack2",
            port_source,
            FakeOvsReader(),
            local_client,
            managed_domains=["acl"],
            timeout_convergence_attempts=1,
            timeout_convergence_interval=0,
        )

        result = sync.safe_full_resync()

        self.assertEqual([], local_client.snapshots)
        self.assertTrue(result["status"]["degraded"])
        self.assertEqual("local_api_degraded", result["status"]["reason"])
        self.assertIn("still pending", result["status"]["last_error"])

    def test_full_resync_recovers_remote_pending_different_hash_when_supported(self):
        port_source = StaticPortSource([{
            "id": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
            "device_owner": "compute:nova",
            "binding:host_id": "ostack2",
            "binding:vif_type": "ovs",
            "binding:vnic_type": "normal",
        }])
        local_client = RecoveringRemotePendingClient({
            "generation": 10,
            "accepted_generation": 10,
            "applied_generation": 9,
            "pending_generation": 10,
            "desired_hash": "different-hash",
            "applied_desired_hash": "old-hash",
            "authority_state": "ready",
            "managed_ports": [],
            "active_instances": [],
        })
        sync = SnapshotSynchronizer(
            "ostack2",
            port_source,
            FakeOvsReader(),
            local_client,
            managed_domains=["acl"],
            timeout_convergence_attempts=1,
            timeout_convergence_interval=0,
        )

        result = sync.full_resync()

        self.assertEqual([{
            "expected_generation": 10,
            "expected_desired_hash": "different-hash",
        }], local_client.recoveries)
        self.assertEqual(1, len(local_client.snapshots))
        self.assertTrue(result["status"]["ready"])

    def test_full_resync_accepts_async_snapshot_after_status_converges(self):
        port_id = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
        port_source = StaticPortSource([{
            "id": port_id,
            "device_owner": "compute:nova",
            "binding:host_id": "ostack2",
            "binding:vif_type": "ovs",
            "binding:vnic_type": "normal",
        }])
        local_client = AcceptedThenConvergedLocalClient()
        sync = SnapshotSynchronizer(
            "ostack2",
            port_source,
            FakeOvsReader(),
            local_client,
            managed_domains=["acl"],
            timeout_convergence_attempts=1,
            timeout_convergence_interval=0,
        )

        result = sync.full_resync()

        self.assertEqual("accepted", result["response"]["status"])
        self.assertTrue(result["status"]["ready"])
        self.assertEqual(set([port_id]), sync.projected_port_ids)

    def test_full_resync_keeps_observing_slow_async_pending_snapshot(self):
        port_id = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
        port_source = StaticPortSource([{
            "id": port_id,
            "device_owner": "compute:nova",
            "binding:host_id": "ostack2",
            "binding:vif_type": "ovs",
            "binding:vnic_type": "normal",
        }])
        local_client = AcceptedSlowPendingThenConvergedLocalClient(pending_polls=3)
        sync = SnapshotSynchronizer(
            "ostack2",
            port_source,
            FakeOvsReader(),
            local_client,
            managed_domains=["acl"],
            timeout_convergence_attempts=1,
            timeout_convergence_interval=0,
        )

        result = sync.full_resync()

        self.assertEqual("accepted", result["response"]["status"])
        self.assertTrue(result["status"]["ready"])
        self.assertGreater(local_client.status_calls, 1)
        self.assertEqual(set([port_id]), sync.projected_port_ids)

    def test_full_resync_keeps_prior_state_when_accepted_generation_mismatches(self):
        state_dir = tempfile.mkdtemp()
        try:
            port_id = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
            neutron_ports = [{
                "id": port_id,
                "network_id": "net-1",
                "revision_number": 7,
                "device_owner": "compute:nova",
                "binding:host_id": "ostack2",
                "binding:vif_type": "ovs",
                "binding:vnic_type": "normal",
            }]
            local_client = TerminalIdentityMismatchLocalClient()
            sync = SnapshotSynchronizer(
                "ostack2",
                StaticPortSource(neutron_ports),
                FakeOvsReader(),
                local_client,
                managed_domains=["acl"],
                state_store=SnapshotStateStore(state_dir),
            )
            baseline = sync.full_resync()
            baseline_hash = baseline["snapshot"]["desired_hash"]
            local_client.set_terminal_status_updates(accepted_generation=3)
            neutron_ports[0]["binding:vif_type"] = "binding_failed"

            with self.assertRaises(LocalApiError) as ctx:
                sync.full_resync()

            state = SnapshotStateStore(state_dir).to_dict()
            self.assertIn("accepted_generation", str(ctx.exception))
            self.assertEqual(2, state["pending_generation"])
            self.assertEqual(1, state["last_generation"])
            self.assertEqual(baseline_hash, state["last_desired_hash"])
            self.assertEqual([port_id], state["last_projected_port_ids"])
            self.assertEqual(7, sync.projection_index.port(port_id).revision_number)
            self.assertEqual(1, sync.runtime_status.last_generation)
            self.assertEqual(baseline_hash, sync.runtime_status.last_desired_hash)
            self.assertEqual(1, sync.runtime_status.accepted_generation)
        finally:
            shutil.rmtree(state_dir)

    def test_full_resync_keeps_pending_when_post_apply_status_is_unavailable(self):
        state_dir = tempfile.mkdtemp()
        try:
            port_id = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
            local_client = AcceptedThenStatusUnavailableLocalClient()
            sync = SnapshotSynchronizer(
                "ostack2",
                StaticPortSource([{
                    "id": port_id,
                    "device_owner": "compute:nova",
                    "binding:host_id": "ostack2",
                    "binding:vif_type": "ovs",
                    "binding:vnic_type": "normal",
                }]),
                FakeOvsReader(),
                local_client,
                managed_domains=["acl"],
                state_store=SnapshotStateStore(state_dir),
                timeout_convergence_attempts=1,
                timeout_convergence_interval=0,
            )

            result = sync.safe_full_resync()
            state = SnapshotStateStore(state_dir).to_dict()

            self.assertTrue(result["status"]["degraded"])
            self.assertFalse(result["status"]["ready"])
            self.assertEqual(1, state["pending_generation"])
            self.assertEqual(0, state["last_generation"])
            self.assertEqual(None, state["last_desired_hash"])
            self.assertEqual([], state["last_projected_port_ids"])
            self.assertEqual(set(), sync.projected_port_ids)
        finally:
            shutil.rmtree(state_dir)

    def test_full_resync_rejects_matching_runtime_degraded_authority(self):
        state_dir = tempfile.mkdtemp()
        try:
            port_id = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
            sync = SnapshotSynchronizer(
                "ostack2",
                StaticPortSource([{
                    "id": port_id,
                    "device_owner": "compute:nova",
                    "binding:host_id": "ostack2",
                    "binding:vif_type": "ovs",
                    "binding:vnic_type": "normal",
                }]),
                FakeOvsReader(),
                RuntimeDegradedAuthorityLocalClient(),
                managed_domains=["acl"],
                state_store=SnapshotStateStore(state_dir),
            )

            result = sync.safe_full_resync()
            state = SnapshotStateStore(state_dir).to_dict()

            self.assertTrue(result["status"]["degraded"])
            self.assertFalse(result["status"]["ready"])
            self.assertEqual(1, state["pending_generation"])
            self.assertEqual(0, state["last_generation"])
            self.assertEqual(set(), sync.projected_port_ids)
        finally:
            shutil.rmtree(state_dir)

    def test_safe_full_resync_keeps_pending_when_async_snapshot_not_converged(self):
        port_source = StaticPortSource([{
            "id": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
            "device_owner": "compute:nova",
            "binding:host_id": "ostack2",
            "binding:vif_type": "ovs",
            "binding:vnic_type": "normal",
        }])
        local_client = AcceptedNotConvergedLocalClient()
        sync = SnapshotSynchronizer(
            "ostack2",
            port_source,
            FakeOvsReader(),
            local_client,
            managed_domains=["acl"],
            timeout_convergence_attempts=1,
            timeout_convergence_interval=0,
        )

        result = sync.safe_full_resync()

        self.assertEqual(1, len(local_client.snapshots))
        self.assertTrue(result["status"]["degraded"])
        self.assertEqual("local_api_degraded", result["status"]["reason"])
        self.assertIn("did not converge", result["status"]["last_error"])

    def test_pending_generation_survives_restart_after_degraded_resync(self):
        state_dir = tempfile.mkdtemp()
        try:
            port_source = StaticPortSource([{
                "id": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
                "device_owner": "compute:nova",
                "binding:host_id": "ostack2",
                "binding:vif_type": "ovs",
                "binding:vnic_type": "normal",
            }])
            first_client = TimeoutNotConvergedLocalClient()
            first = SnapshotSynchronizer(
                "ostack2",
                port_source,
                FakeOvsReader(),
                first_client,
                managed_domains=["acl"],
                state_store=SnapshotStateStore(state_dir),
                timeout_convergence_attempts=1,
                timeout_convergence_interval=0,
            )

            result = first.safe_full_resync()
            self.assertTrue(result["status"]["degraded"])
            self.assertEqual(1, first_client.snapshots[0]["generation"])

            second_client = FakeLocalClient()
            second = SnapshotSynchronizer(
                "ostack2",
                port_source,
                FakeOvsReader(),
                second_client,
                managed_domains=["acl"],
                state_store=SnapshotStateStore(state_dir),
            )
            second.full_resync()

            self.assertEqual(1, second_client.snapshots[0]["generation"])
        finally:
            shutil.rmtree(state_dir)

    def test_pending_snapshot_recovered_on_restart_then_resubmits(self):
        state_dir = tempfile.mkdtemp()
        try:
            port_id = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
            port_source = StaticPortSource([{
                "id": port_id,
                "device_owner": "compute:nova",
                "binding:host_id": "ostack2",
                "binding:vif_type": "ovs",
                "binding:vnic_type": "normal",
            }])
            first_client = TimeoutNotConvergedLocalClient()
            first = SnapshotSynchronizer(
                "ostack2",
                port_source,
                FakeOvsReader(),
                first_client,
                managed_domains=["acl"],
                acl_index=EffectiveAclIndex(),
                state_store=SnapshotStateStore(state_dir),
                timeout_convergence_attempts=1,
                timeout_convergence_interval=0,
            )
            first.safe_full_resync()
            pending = SnapshotStateStore(state_dir).pending_snapshot()
            status = _terminal_status_for_snapshot(first_client.snapshots[0])
            second_client = FixedStatusLocalClient(status)
            second = SnapshotSynchronizer(
                "ostack2",
                port_source,
                FakeOvsReader(),
                second_client,
                managed_domains=["acl"],
                acl_index=EffectiveAclIndex(),
                state_store=SnapshotStateStore(state_dir),
            )

            result = second.full_resync()
            state = SnapshotStateStore(state_dir).to_dict()

            self.assertEqual([], second_client.snapshots)
            self.assertTrue(result["response"]["recovered_before_submit"])
            self.assertEqual(None, state["pending_generation"])
            self.assertEqual(pending["generation"], state["last_generation"])
            self.assertEqual([port_id], state["last_projected_port_ids"])
            self.assertEqual(
                "not_requested",
                result["status"]["last_port_statuses"][0]["status"],
            )
        finally:
            shutil.rmtree(state_dir)

    def test_pending_snapshot_recovery_rejects_terminal_degraded_status(self):
        port_id = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
        for degraded_component in ("authority", "acl"):
            with self.subTest(degraded_component=degraded_component):
                state_dir = tempfile.mkdtemp()
                try:
                    snapshot = {
                        "generation": 0,
                        "host": "ostack2",
                        "ports": [{
                            "port_id": port_id,
                            "ifname": "",
                            "eligible": True,
                            "managed_domains": ["acl"],
                            "acl": {
                                "enabled": True,
                                "status": "ready",
                                "effective_action": "enforce",
                            },
                        }],
                    }
                    store = SnapshotStateStore(state_dir)
                    prepared = store.prepare_snapshot(snapshot)
                    snapshot["generation"] = prepared["generation"]
                    snapshot["desired_hash"] = prepared["desired_hash"]
                    status = _terminal_status_for_snapshot(snapshot)
                    if degraded_component == "authority":
                        status["authority_state"] = "runtime_degraded"
                    else:
                        status["port_statuses"][0].update({
                            "status": "degraded",
                            "reason": "acl_apply_failed",
                            "domains": [{
                                "domain": "acl",
                                "status": "degraded",
                                "reason": "acl_apply_failed",
                                "effective_action": "bypass",
                            }],
                        })
                    sync = SnapshotSynchronizer(
                        "ostack2",
                        StaticPortSource([]),
                        FakeOvsReader(),
                        FixedStatusLocalClient(status),
                        managed_domains=["acl"],
                        state_store=SnapshotStateStore(state_dir),
                    )

                    result = sync.recover_pending_state()
                    state = SnapshotStateStore(state_dir).to_dict()

                    self.assertEqual([], result["recovered"])
                    self.assertEqual(1, state["pending_generation"])
                    self.assertEqual(0, state["last_generation"])
                    self.assertTrue(sync.runtime_status.degraded)
                    self.assertFalse(sync.runtime_status.ready)
                finally:
                    shutil.rmtree(state_dir)

    def test_restart_requires_rehydrated_acl_before_pending_snapshot_commit(self):
        port_id = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
        port_source = StaticPortSource([{
            "id": port_id,
            "network_id": "net-1",
            "device_owner": "compute:nova",
            "binding:host_id": "ostack2",
            "binding:vif_type": "ovs",
            "binding:vnic_type": "normal",
        }])
        cases = (
            (
                "ready_enforce",
                EffectiveAclIndex(
                    policies=[{
                        "id": "acl-policy",
                        "default_action": "allow",
                    }],
                    bindings=[{
                        "id": "acl-binding",
                        "policy_id": "acl-policy",
                        "target_type": "port",
                        "target_id": port_id,
                    }],
                ),
                "ready",
                "enforce",
            ),
            (
                "not_requested_bypass",
                EffectiveAclIndex(),
                "not_requested",
                "bypass",
            ),
        )
        for label, acl_index, runtime_status, runtime_action in cases:
            with self.subTest(label=label):
                state_dir = tempfile.mkdtemp()
                try:
                    first_client = AcceptedThenStatusUnavailableLocalClient()
                    first = SnapshotSynchronizer(
                        "ostack2",
                        port_source,
                        FakeOvsReader(),
                        first_client,
                        managed_domains=["acl"],
                        acl_index=acl_index,
                        state_store=SnapshotStateStore(state_dir),
                    )
                    failed = first.safe_full_resync()
                    self.assertTrue(failed["status"]["degraded"])
                    pending = SnapshotStateStore(state_dir).pending_snapshot()
                    status = _terminal_status_for_snapshot(first_client.snapshots[0])
                    runtime_acl = status["port_statuses"][0]["domains"][0]
                    self.assertEqual(runtime_status, runtime_acl["status"])
                    self.assertEqual(runtime_action, runtime_acl["effective_action"])

                    second_client = FixedStatusLocalClient(status)
                    second = SnapshotSynchronizer(
                        "ostack2",
                        port_source,
                        FakeOvsReader(),
                        second_client,
                        managed_domains=["acl"],
                        acl_index=acl_index,
                        state_store=SnapshotStateStore(state_dir),
                    )

                    direct = second.recover_pending_state()
                    direct_state = SnapshotStateStore(state_dir).to_dict()

                    self.assertEqual([], direct["recovered"])
                    self.assertEqual(
                        pending["generation"],
                        direct_state["pending_generation"],
                    )
                    self.assertEqual(0, direct_state["last_generation"])
                    self.assertTrue(second.runtime_status.degraded)
                    self.assertFalse(second.runtime_status.ready)

                    result = second.full_resync()
                    final_state = SnapshotStateStore(state_dir).to_dict()

                    self.assertEqual([], second_client.snapshots)
                    self.assertTrue(result["response"]["recovered_before_submit"])
                    self.assertTrue(result["status"]["ready"])
                    self.assertEqual(None, final_state["pending_generation"])
                    self.assertEqual(
                        pending["generation"],
                        final_state["last_generation"],
                    )
                finally:
                    shutil.rmtree(state_dir)

    def test_restart_rejects_invalid_pending_before_stale_clear(self):
        port_id = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
        missing = object()
        for pending_generation in (
            missing,
            "0",
            "3",
            True,
            False,
            0.0,
            3.0,
            -1,
            "",
            "malformed",
        ):
            with self.subTest(pending_generation=pending_generation):
                state_dir = tempfile.mkdtemp()
                try:
                    snapshot = {
                        "generation": 0,
                        "host": "ostack2",
                        "ports": [{
                            "port_id": port_id,
                            "eligible": True,
                            "managed_domains": ["acl"],
                            "acl": {
                                "enabled": True,
                                "status": "ready",
                                "effective_action": "enforce",
                            },
                        }],
                    }
                    store = SnapshotStateStore(state_dir)
                    prepared = store.prepare_snapshot(snapshot)
                    status = {
                        "generation": prepared["generation"] + 1,
                        "accepted_generation": prepared["generation"] + 1,
                        "applied_generation": prepared["generation"] + 1,
                        "desired_hash": "different-hash",
                        "applied_desired_hash": "different-hash",
                        "authority_state": "ready",
                        "managed_ports": [],
                        "port_statuses": [],
                        "active_instances": [],
                    }
                    if pending_generation is not missing:
                        status["pending_generation"] = pending_generation
                    sync = SnapshotSynchronizer(
                        "ostack2",
                        StaticPortSource([]),
                        FakeOvsReader(),
                        FixedStatusLocalClient(status),
                        managed_domains=["acl"],
                        state_store=SnapshotStateStore(state_dir),
                    )

                    with self.assertRaises(LocalApiError) as ctx:
                        sync.recover_pending_state()
                    state = SnapshotStateStore(state_dir).to_dict()

                    self.assertIn("pending_generation", str(ctx.exception))
                    self.assertEqual(
                        prepared["generation"],
                        state["pending_generation"],
                    )
                    self.assertEqual(None, state["last_cleared_pending_generation"])
                    self.assertEqual(0, state["last_generation"])
                    self.assertTrue(sync.runtime_status.degraded)
                finally:
                    shutil.rmtree(state_dir)

    def test_stale_pending_snapshot_is_cleared_when_remote_advanced(self):
        state_dir = tempfile.mkdtemp()
        try:
            port_id = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
            port_source = StaticPortSource([{
                "id": port_id,
                "device_owner": "compute:nova",
                "binding:host_id": "ostack2",
                "binding:vif_type": "ovs",
                "binding:vnic_type": "normal",
            }])
            first_client = TimeoutNotConvergedLocalClient()
            first = SnapshotSynchronizer(
                "ostack2",
                port_source,
                FakeOvsReader(),
                first_client,
                managed_domains=["acl"],
                state_store=SnapshotStateStore(state_dir),
                timeout_convergence_attempts=1,
                timeout_convergence_interval=0,
            )
            first.safe_full_resync()
            pending = SnapshotStateStore(state_dir).pending_snapshot()
            second_client = StalePendingThenConvergedLocalClient({
                "generation": pending["generation"] + 2,
                "applied_generation": pending["generation"] + 2,
                "desired_hash": "different",
                "applied_desired_hash": "different",
                "pending_generation": None,
                "managed_ports": [],
                "active_instances": [],
            })
            second = SnapshotSynchronizer(
                "ostack2",
                port_source,
                FakeOvsReader(),
                second_client,
                managed_domains=["acl"],
                state_store=SnapshotStateStore(state_dir),
            )

            result = second.full_resync()
            state = SnapshotStateStore(state_dir).to_dict()

            self.assertEqual(1, len(second_client.snapshots))
            self.assertEqual(pending["generation"] + 3, result["snapshot"]["generation"])
            self.assertEqual(None, state["pending_generation"])
            self.assertEqual(
                pending["generation"],
                state["last_cleared_pending_generation"],
            )
            self.assertEqual(
                "remote_generation_advanced",
                state["last_cleared_pending_reason"],
            )
            self.assertTrue(result["status"]["ready"])
            self.assertFalse(result["status"]["degraded"])
        finally:
            shutil.rmtree(state_dir)

    def test_restart_stale_clear_rejects_malformed_applied_identity(self):
        port_id = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
        missing = object()
        cases = (
            ("generation_missing", missing, "different-hash"),
            ("generation_true", True, "different-hash"),
            ("generation_false", False, "different-hash"),
            ("generation_float", 2.0, "different-hash"),
            ("generation_fractional", 2.9, "different-hash"),
            ("generation_string", "2", "different-hash"),
            ("generation_negative", -1, "different-hash"),
            ("hash_missing", 2, missing),
            ("hash_none", 2, None),
            ("hash_empty", 2, ""),
            ("hash_dict", 2, {"hash": "different"}),
            ("hash_list", 2, ["different"]),
            ("hash_numeric", 2, 7),
        )
        for label, applied_generation, applied_hash in cases:
            with self.subTest(label=label):
                state_dir = tempfile.mkdtemp()
                try:
                    store = SnapshotStateStore(state_dir)
                    prepared = store.prepare_snapshot({
                        "generation": 0,
                        "host": "ostack2",
                        "ports": [{
                            "port_id": port_id,
                            "eligible": True,
                            "managed_domains": ["acl"],
                            "acl": {
                                "enabled": True,
                                "status": "ready",
                                "effective_action": "enforce",
                            },
                        }],
                    })
                    newer_generation = prepared["generation"] + 1
                    status = {
                        "generation": newer_generation,
                        "accepted_generation": newer_generation,
                        "pending_generation": None,
                        "desired_hash": "different-hash",
                        "authority_state": "ready",
                        "managed_ports": [],
                        "port_statuses": [],
                        "active_instances": [],
                    }
                    if applied_generation is not missing:
                        status["applied_generation"] = applied_generation
                    if applied_hash is not missing:
                        status["applied_desired_hash"] = applied_hash
                    sync = SnapshotSynchronizer(
                        "ostack2",
                        StaticPortSource([]),
                        FakeOvsReader(),
                        FixedStatusLocalClient(status),
                        managed_domains=["acl"],
                        state_store=SnapshotStateStore(state_dir),
                    )

                    result = sync.recover_pending_state()
                    state = SnapshotStateStore(state_dir).to_dict()

                    self.assertEqual([], result["recovered"])
                    self.assertEqual(
                        prepared["generation"],
                        state["pending_generation"],
                    )
                    self.assertEqual(None, state["last_cleared_pending_generation"])
                    self.assertEqual(0, state["last_generation"])
                    self.assertTrue(sync.runtime_status.degraded)
                    self.assertFalse(sync.runtime_status.ready)
                finally:
                    shutil.rmtree(state_dir)

    def test_restart_stale_clear_accepts_typed_newer_identity(self):
        state_dir = tempfile.mkdtemp()
        try:
            store = SnapshotStateStore(state_dir)
            prepared = store.prepare_snapshot({
                "generation": 0,
                "host": "ostack2",
                "ports": [],
            })
            newer_generation = prepared["generation"] + 1
            status = {
                "generation": newer_generation,
                "accepted_generation": newer_generation,
                "applied_generation": newer_generation,
                "pending_generation": None,
                "desired_hash": "different-hash",
                "applied_desired_hash": "different-hash",
                "authority_state": "ready",
                "managed_ports": [],
                "port_statuses": [],
                "active_instances": [],
            }
            sync = SnapshotSynchronizer(
                "ostack2",
                StaticPortSource([]),
                FakeOvsReader(),
                FixedStatusLocalClient(status),
                managed_domains=["acl"],
                state_store=SnapshotStateStore(state_dir),
            )

            result = sync.recover_pending_state()
            state = SnapshotStateStore(state_dir).to_dict()

            self.assertEqual(["stale_snapshot"], result["recovered"])
            self.assertEqual(None, state["pending_generation"])
            self.assertEqual(
                prepared["generation"],
                state["last_cleared_pending_generation"],
            )
            self.assertEqual(
                "remote_generation_advanced",
                state["last_cleared_pending_reason"],
            )
        finally:
            shutil.rmtree(state_dir)

    def test_pending_snapshot_hash_mismatch_blocks_restart_resync(self):
        state_dir = tempfile.mkdtemp()
        try:
            port_source = StaticPortSource([{
                "id": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
                "device_owner": "compute:nova",
                "binding:host_id": "ostack2",
                "binding:vif_type": "ovs",
                "binding:vnic_type": "normal",
            }])
            first_client = TimeoutNotConvergedLocalClient()
            first = SnapshotSynchronizer(
                "ostack2",
                port_source,
                FakeOvsReader(),
                first_client,
                managed_domains=["acl"],
                state_store=SnapshotStateStore(state_dir),
                timeout_convergence_attempts=1,
                timeout_convergence_interval=0,
            )
            first.safe_full_resync()
            pending = SnapshotStateStore(state_dir).pending_snapshot()
            second_client = FixedStatusLocalClient({
                "generation": pending["generation"],
                "applied_generation": pending["generation"],
                "pending_generation": None,
                "desired_hash": "different",
                "applied_desired_hash": "different",
                "managed_ports": [],
                "active_instances": [],
            })
            second = SnapshotSynchronizer(
                "ostack2",
                port_source,
                FakeOvsReader(),
                second_client,
                managed_domains=["acl"],
                state_store=SnapshotStateStore(state_dir),
            )

            result = second.safe_full_resync()

            self.assertTrue(result["status"]["degraded"])
            self.assertEqual(
                "stale_pending_snapshot_requires_operator",
                result["status"]["reason"],
            )
            self.assertIn("hash mismatch", result["status"]["last_error"])
            self.assertEqual([], second_client.snapshots)
        finally:
            shutil.rmtree(state_dir)

    def test_response_port_errors_keep_pending_state_and_degrade(self):
        state_dir = tempfile.mkdtemp()
        try:
            sync = SnapshotSynchronizer(
                "ostack2",
                StaticPortSource([{
                    "id": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
                    "device_owner": "compute:nova",
                    "binding:host_id": "ostack2",
                    "binding:vif_type": "ovs",
                    "binding:vnic_type": "normal",
                }]),
                FakeOvsReader(),
                ResponseErrorLocalClient(),
                managed_domains=["acl"],
                state_store=SnapshotStateStore(state_dir),
            )

            result = sync.safe_full_resync()
            state = SnapshotStateStore(state_dir).to_dict()

            self.assertTrue(result["status"]["degraded"])
            self.assertEqual(1, state["pending_generation"])
            self.assertEqual(None, state["last_desired_hash"])
        finally:
            shutil.rmtree(state_dir)

    def test_full_resync_carries_port_statuses_from_datapath_status(self):
        port_id = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
        sync = SnapshotSynchronizer(
            "ostack2",
            StaticPortSource([{
                "id": port_id,
                "device_owner": "compute:nova",
                "binding:host_id": "ostack2",
                "binding:vif_type": "ovs",
                "binding:vnic_type": "normal",
            }]),
            FakeOvsReader(),
            StatusAfterApplyLocalClient(),
            managed_domains=["acl"],
        )

        result = sync.full_resync()

        self.assertEqual(1, result["status"]["last_managed_ports"])
        self.assertEqual(port_id, result["status"]["last_managed_ports_detail"][0]["port_id"])
        self.assertEqual(port_id, result["status"]["last_port_statuses"][0]["port_id"])
        self.assertEqual(
            "not_requested",
            result["status"]["last_port_statuses"][0]["domains"][0]["status"],
        )
        self.assertEqual(
            "bypass",
            result["status"]["last_port_statuses"][0]["domains"][0][
                "effective_action"
            ],
        )
        self.assertEqual(
            result["snapshot"]["generation"],
            result["status"]["accepted_generation"],
        )
        self.assertEqual(
            result["snapshot"]["generation"],
            result["status"]["applied_generation"],
        )
        self.assertEqual(0, result["status"]["generation_lag"])

    def test_full_resync_includes_effective_acl_when_index_is_available(self):
        port_id = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
        port_source = StaticPortSource([{
            "id": port_id,
            "network_id": "net-1",
            "device_owner": "compute:nova",
            "binding:host_id": "ostack2",
            "binding:vif_type": "ovs",
            "binding:vnic_type": "normal",
        }])
        acl_index = EffectiveAclIndex(
            policies=[{"id": "acl-policy", "default_action": "allow"}],
            rules=[{
                "id": "drop-icmp",
                "policy_id": "acl-policy",
                "direction": "ingress",
                "priority": 100,
                "action": "drop",
                "ethertype": "IPv4",
                "protocol": "icmp",
                "src_cidr": "10.58.159.2/32",
            }],
            bindings=[{
                "id": "acl-binding",
                "policy_id": "acl-policy",
                "target_type": "port",
                "target_id": port_id,
            }],
        )
        local_client = FakeLocalClient()
        sync = SnapshotSynchronizer(
            "ostack2",
            port_source,
            FakeOvsReader(),
            local_client,
            managed_domains=["acl"],
            acl_index=acl_index,
        )

        sync.full_resync()

        port = local_client.snapshots[0]["ports"][0]
        self.assertEqual("acl-policy", port["acl"]["policy_id"])
        self.assertTrue(port["acl"]["enabled"])
        self.assertEqual("drop-icmp", port["acl"]["rules"][0]["id"])
        self.assertEqual(["10.58.159.2/32"], port["acl"]["rules"][0]["src_cidrs"])

    def test_full_resync_enriches_port_status_with_effective_acl_identity(self):
        port_id = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
        acl_index = EffectiveAclIndex(
            policies=[{"id": "acl-policy", "default_action": "allow"}],
            rules=[{
                "id": "drop-icmp",
                "policy_id": "acl-policy",
                "direction": "ingress",
                "priority": 100,
                "action": "drop",
                "ethertype": "IPv4",
                "protocol": "icmp",
                "src_cidr": "10.58.159.2/32",
            }],
            bindings=[{
                "id": "acl-binding",
                "policy_id": "acl-policy",
                "target_type": "port",
                "target_id": port_id,
            }],
        )
        sync = SnapshotSynchronizer(
            "ostack2",
            StaticPortSource([{
                "id": port_id,
                "network_id": "net-1",
                "device_owner": "compute:nova",
                "binding:host_id": "ostack2",
                "binding:vif_type": "ovs",
                "binding:vnic_type": "normal",
            }]),
            FakeOvsReader(),
            StatusAfterApplyLocalClient(),
            managed_domains=["acl"],
            acl_index=acl_index,
        )

        result = sync.full_resync()

        port_status = result["status"]["last_port_statuses"][0]
        self.assertEqual(port_id, port_status["port_id"])
        self.assertEqual("ready", port_status["status"])
        self.assertEqual("acl-policy", port_status["policy_id"])
        self.assertEqual("acl-binding", port_status["binding_id"])

    def test_full_resync_rejects_missing_runtime_acl_status(self):
        port_id = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
        acl_index = EffectiveAclIndex(
            policies=[{"id": "acl-policy", "default_action": "allow"}],
            rules=[{
                "id": "drop-icmp",
                "policy_id": "acl-policy",
                "direction": "ingress",
                "priority": 100,
                "action": "drop",
                "ethertype": "IPv4",
                "protocol": "icmp",
                "src_cidr": "10.58.159.2/32",
            }],
            bindings=[{
                "id": "acl-binding",
                "policy_id": "acl-policy",
                "target_type": "port",
                "target_id": port_id,
            }],
        )
        sync = SnapshotSynchronizer(
            "ostack2",
            StaticPortSource([{
                "id": port_id,
                "network_id": "net-1",
                "device_owner": "compute:nova",
                "binding:host_id": "ostack2",
                "binding:vif_type": "ovs",
                "binding:vnic_type": "normal",
            }]),
            FakeOvsReader(),
            ConvergedMissingPortStatusLocalClient(),
            managed_domains=["acl"],
            acl_index=acl_index,
        )

        result = sync.safe_full_resync()

        self.assertTrue(result["status"]["degraded"])
        self.assertFalse(result["status"]["ready"])
        self.assertEqual(1, sync.state_store.pending_snapshot()["generation"])
        self.assertEqual(0, sync.runtime_status.last_generation)
        self.assertEqual(set(), sync.projected_port_ids)

    def test_full_resync_rejects_not_requested_runtime_for_ready_acl(self):
        port_id = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
        acl_index = EffectiveAclIndex(
            policies=[{"id": "acl-policy", "default_action": "allow"}],
            rules=[{
                "id": "drop-icmp",
                "policy_id": "acl-policy",
                "direction": "ingress",
                "priority": 100,
                "action": "drop",
                "ethertype": "IPv4",
                "protocol": "icmp",
                "src_cidr": "10.58.159.2/32",
            }],
            bindings=[{
                "id": "acl-binding",
                "policy_id": "acl-policy",
                "target_type": "port",
                "target_id": port_id,
            }],
        )
        sync = SnapshotSynchronizer(
            "ostack2",
            StaticPortSource([{
                "id": port_id,
                "network_id": "net-1",
                "device_owner": "compute:nova",
                "binding:host_id": "ostack2",
                "binding:vif_type": "ovs",
                "binding:vnic_type": "normal",
            }]),
            FakeOvsReader(),
            ConvergedStalePortStatusLocalClient(),
            managed_domains=["acl"],
            acl_index=acl_index,
        )

        result = sync.safe_full_resync()

        self.assertTrue(result["status"]["degraded"])
        self.assertFalse(result["status"]["ready"])
        self.assertEqual(1, sync.state_store.pending_snapshot()["generation"])
        self.assertEqual(0, sync.runtime_status.last_generation)

    def test_full_resync_accepts_not_requested_runtime_for_unbound_acl(self):
        port_id = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
        sync = SnapshotSynchronizer(
            "ostack2",
            StaticPortSource([{
                "id": port_id,
                "network_id": "net-1",
                "device_owner": "compute:nova",
                "binding:host_id": "ostack2",
                "binding:vif_type": "ovs",
                "binding:vnic_type": "normal",
            }]),
            FakeOvsReader(),
            ConvergedStalePortStatusLocalClient(),
            managed_domains=["acl"],
            acl_index=EffectiveAclIndex(),
        )

        result = sync.full_resync()

        port_status = result["status"]["last_port_statuses"][0]
        self.assertTrue(result["status"]["ready"])
        self.assertEqual("not_requested", port_status["status"])
        self.assertEqual("not_requested", port_status["domains"][0]["status"])
        self.assertEqual("bypass", port_status["domains"][0]["effective_action"])

    def test_full_snapshot_rejects_stale_port_status_identity(self):
        port_id = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
        snapshot = {
            "generation": 2,
            "desired_hash": "hash-2",
            "ports": [{
                "port_id": port_id,
                "eligible": True,
                "managed_domains": ["acl"],
                "acl": {
                    "enabled": True,
                    "status": "ready",
                    "effective_action": "enforce",
                },
            }],
        }
        sync = SnapshotSynchronizer(
            "ostack2",
            StaticPortSource([]),
            FakeOvsReader(),
            FakeLocalClient(),
            managed_domains=["acl"],
        )
        for field, stale_value, reason_fragment in (
            ("generation", 1, "generation"),
            ("desired_hash", "hash-1", "desired hash"),
        ):
            with self.subTest(field=field):
                status = _terminal_status_for_snapshot(snapshot)
                status["port_statuses"][0][field] = stale_value

                verdict, reason = sync._snapshot_status_verdict(
                    snapshot,
                    set([port_id]),
                    status,
                )

                self.assertEqual("failed", verdict)
                self.assertIn(port_id, reason)
                self.assertIn(reason_fragment, reason)

    def test_terminal_status_requires_strict_global_applied_generation(self):
        snapshot = _ready_acl_snapshot()
        port_id = snapshot["ports"][0]["port_id"]
        sync = SnapshotSynchronizer(
            "ostack2",
            StaticPortSource([]),
            FakeOvsReader(),
            FakeLocalClient(),
            managed_domains=["acl"],
        )
        valid_status = _terminal_status_for_snapshot(snapshot)
        verdict, reason = sync._snapshot_status_verdict(
            snapshot,
            set([port_id]),
            valid_status,
        )
        self.assertEqual(("ready", None), (verdict, reason))

        missing = object()
        for value in (True, False, 1.0, 1.9, "1", -1, missing):
            with self.subTest(applied_generation=value):
                status = _terminal_status_for_snapshot(snapshot)
                if value is missing:
                    del status["applied_generation"]
                else:
                    status["applied_generation"] = value

                verdict, reason = sync._snapshot_status_verdict(
                    snapshot,
                    set([port_id]),
                    status,
                )

                self.assertEqual("failed", verdict)
                self.assertIn("applied_generation", reason)

    def test_terminal_status_requires_strict_accepted_generation(self):
        snapshot = _ready_acl_snapshot()
        port_id = snapshot["ports"][0]["port_id"]
        sync = SnapshotSynchronizer(
            "ostack2",
            StaticPortSource([]),
            FakeOvsReader(),
            FakeLocalClient(),
            managed_domains=["acl"],
        )
        missing = object()
        expected_generation = snapshot["generation"]
        for value in (
            True,
            False,
            1.0,
            1.9,
            "1",
            -1,
            expected_generation - 1,
            expected_generation + 1,
            missing,
        ):
            with self.subTest(accepted_generation=value):
                status = _terminal_status_for_snapshot(snapshot)
                if value is missing:
                    del status["accepted_generation"]
                else:
                    status["accepted_generation"] = value

                verdict, reason = sync._snapshot_status_verdict(
                    snapshot,
                    set([port_id]),
                    status,
                )

                self.assertEqual("failed", verdict)
                self.assertIn("accepted_generation", reason)

    def test_terminal_status_rejects_malformed_authority_state(self):
        snapshot = _ready_acl_snapshot()
        port_id = snapshot["ports"][0]["port_id"]
        sync = SnapshotSynchronizer(
            "ostack2",
            StaticPortSource([]),
            FakeOvsReader(),
            FakeLocalClient(),
            managed_domains=["acl"],
        )
        malformed_values = ([], {}, True, 1, "", None)
        noncanonical_values = ("READY", " ready", "ready ")
        for authority_state in malformed_values + noncanonical_values:
            with self.subTest(authority_state=authority_state):
                status = _terminal_status_for_snapshot(snapshot)
                status["authority_state"] = authority_state
                try:
                    verdict, reason = sync._snapshot_status_verdict(
                        snapshot,
                        set([port_id]),
                        status,
                    )
                except TypeError as exc:
                    self.fail("malformed authority_state raised TypeError: %s" % exc)

                self.assertEqual("failed", verdict)
                self.assertIn("authority_state", reason)

    def test_terminal_status_requires_strict_affected_port_generation(self):
        snapshot = _ready_acl_snapshot()
        port_id = snapshot["ports"][0]["port_id"]
        sync = SnapshotSynchronizer(
            "ostack2",
            StaticPortSource([]),
            FakeOvsReader(),
            FakeLocalClient(),
            managed_domains=["acl"],
        )
        missing = object()
        for value in (True, False, 1.0, 1.9, "1", -1, missing):
            with self.subTest(port_generation=value):
                status = _terminal_status_for_snapshot(snapshot)
                runtime_port = status["port_statuses"][0]
                if value is missing:
                    del runtime_port["generation"]
                else:
                    runtime_port["generation"] = value

                verdict, reason = sync._snapshot_status_verdict(
                    snapshot,
                    set([port_id]),
                    status,
                )

                self.assertEqual("failed", verdict)
                self.assertIn(port_id, reason)
                self.assertIn("generation", reason)

    def test_terminal_status_requires_string_hash_identity(self):
        port_id = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
        sync = SnapshotSynchronizer(
            "ostack2",
            StaticPortSource([]),
            FakeOvsReader(),
            FakeLocalClient(),
            managed_domains=["acl"],
        )
        invalid_hashes = (None, "", 1, True, {"hash": "bad"}, ["hash"])
        for value in invalid_hashes:
            with self.subTest(field="snapshot.desired_hash", value=value):
                snapshot = _ready_acl_snapshot(desired_hash=value)
                status = _terminal_status_for_snapshot(snapshot)

                verdict, reason = sync._snapshot_status_verdict(
                    snapshot,
                    set([port_id]),
                    status,
                )

                self.assertEqual("failed", verdict)
                self.assertIn("snapshot desired_hash", reason)

        snapshot = _ready_acl_snapshot()
        for field, path in (
            ("desired_hash", ()),
            ("applied_desired_hash", ()),
            ("desired_hash", ("port_statuses", 0)),
        ):
            for value in invalid_hashes:
                with self.subTest(field=field, value=value):
                    status = _terminal_status_for_snapshot(snapshot)
                    target = status
                    for part in path:
                        target = target[part]
                    target[field] = value

                    verdict, reason = sync._snapshot_status_verdict(
                        snapshot,
                        set([port_id]),
                        status,
                    )

                    self.assertEqual("failed", verdict)
                    self.assertIn("desired_hash", reason)

        missing_status_hash = _terminal_status_for_snapshot(snapshot)
        del missing_status_hash["desired_hash"]
        verdict, reason = sync._snapshot_status_verdict(
            snapshot,
            set([port_id]),
            missing_status_hash,
        )
        self.assertEqual("failed", verdict)
        self.assertIn("desired_hash", reason)

        mismatched_status_hash = _terminal_status_for_snapshot(snapshot)
        mismatched_status_hash["desired_hash"] = "different-hash"
        verdict, reason = sync._snapshot_status_verdict(
            snapshot,
            set([port_id]),
            mismatched_status_hash,
        )
        self.assertEqual("failed", verdict)
        self.assertIn("desired_hash", reason)

    def test_terminal_status_rejects_duplicate_port_rows_in_any_order(self):
        snapshot = _ready_acl_snapshot()
        port_id = snapshot["ports"][0]["port_id"]
        sync = SnapshotSynchronizer(
            "ostack2",
            StaticPortSource([]),
            FakeOvsReader(),
            FakeLocalClient(),
            managed_domains=["acl"],
        )
        base_status = _terminal_status_for_snapshot(snapshot)
        ready_row = copy.deepcopy(base_status["port_statuses"][0])
        degraded_row = copy.deepcopy(ready_row)
        degraded_row["status"] = "degraded"
        degraded_row["domains"][0]["status"] = "degraded"
        degraded_row["domains"][0]["effective_action"] = "bypass"

        for rows in (
            [degraded_row, ready_row],
            [ready_row, degraded_row],
        ):
            with self.subTest(order=[row["status"] for row in rows]):
                status = copy.deepcopy(base_status)
                status["port_statuses"] = copy.deepcopy(rows)

                verdict, reason = sync._snapshot_status_verdict(
                    snapshot,
                    set([port_id]),
                    status,
                )

                self.assertEqual("failed", verdict)
                self.assertIn("duplicate", reason)
                self.assertIn(port_id, reason)

    def test_terminal_status_rejects_duplicate_domain_rows_in_any_order(self):
        snapshot = _ready_acl_snapshot()
        port_id = snapshot["ports"][0]["port_id"]
        sync = SnapshotSynchronizer(
            "ostack2",
            StaticPortSource([]),
            FakeOvsReader(),
            FakeLocalClient(),
            managed_domains=["acl"],
        )
        base_status = _terminal_status_for_snapshot(snapshot)
        ready_domain = copy.deepcopy(
            base_status["port_statuses"][0]["domains"][0]
        )
        degraded_domain = copy.deepcopy(ready_domain)
        degraded_domain["status"] = "degraded"
        degraded_domain["effective_action"] = "bypass"

        for domains in (
            [degraded_domain, ready_domain],
            [ready_domain, degraded_domain],
        ):
            with self.subTest(order=[row["status"] for row in domains]):
                status = copy.deepcopy(base_status)
                status["port_statuses"][0]["domains"] = copy.deepcopy(domains)

                verdict, reason = sync._snapshot_status_verdict(
                    snapshot,
                    set([port_id]),
                    status,
                )

                self.assertEqual("failed", verdict)
                self.assertIn("duplicate", reason)
                self.assertIn("domain", reason)

    def test_terminal_status_rejects_malformed_runtime_collections(self):
        snapshot = _ready_acl_snapshot()
        port_id = snapshot["ports"][0]["port_id"]
        sync = SnapshotSynchronizer(
            "ostack2",
            StaticPortSource([]),
            FakeOvsReader(),
            FakeLocalClient(),
            managed_domains=["acl"],
        )
        base_status = _terminal_status_for_snapshot(snapshot)
        malformed_collections = (
            {"bad": "row"},
            "bad",
            (copy.deepcopy(base_status["port_statuses"][0]),),
            [None],
            [1],
            [[]],
        )
        for value in malformed_collections:
            with self.subTest(collection="port_statuses", value=value):
                status = copy.deepcopy(base_status)
                status["port_statuses"] = value

                verdict, reason = sync._snapshot_status_verdict(
                    snapshot,
                    set([port_id]),
                    status,
                )

                self.assertEqual("failed", verdict)
                self.assertIn("port status", reason)

        domain_collections = (
            {"bad": "row"},
            "bad",
            (copy.deepcopy(base_status["port_statuses"][0]["domains"][0]),),
            [None],
            [1],
            [[]],
        )
        for value in domain_collections:
            with self.subTest(collection="domains", value=value):
                status = copy.deepcopy(base_status)
                status["port_statuses"][0]["domains"] = value

                verdict, reason = sync._snapshot_status_verdict(
                    snapshot,
                    set([port_id]),
                    status,
                )

                self.assertEqual("failed", verdict)
                self.assertIn("domain", reason)

    def test_terminal_status_rejects_duplicate_or_malformed_managed_rows(self):
        snapshot = _ready_acl_snapshot()
        port_id = snapshot["ports"][0]["port_id"]
        sync = SnapshotSynchronizer(
            "ostack2",
            StaticPortSource([]),
            FakeOvsReader(),
            FakeLocalClient(),
            managed_domains=["acl"],
        )
        base_status = _terminal_status_for_snapshot(snapshot)
        managed_row = base_status["managed_ports"][0]
        values = (
            [copy.deepcopy(managed_row), copy.deepcopy(managed_row)],
            {"bad": "row"},
            "bad",
            (copy.deepcopy(managed_row),),
            [None],
        )
        for value in values:
            with self.subTest(managed_ports=value):
                status = copy.deepcopy(base_status)
                status["managed_ports"] = value

                verdict, reason = sync._snapshot_status_verdict(
                    snapshot,
                    set([port_id]),
                    status,
                )

                self.assertEqual("failed", verdict)
                self.assertIn("managed port", reason)

    def test_scoped_snapshot_rejects_stale_target_port_status_identity(self):
        port_id = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
        snapshot = {
            "generation": 2,
            "desired_hash": "hash-2",
            "scope": {"type": "port", "port_id": port_id},
            "ports": [{
                "port_id": port_id,
                "eligible": True,
                "managed_domains": ["acl"],
                "acl": {
                    "enabled": True,
                    "status": "ready",
                    "effective_action": "enforce",
                },
            }],
        }
        sync = SnapshotSynchronizer(
            "ostack2",
            StaticPortSource([]),
            FakeOvsReader(),
            FakeLocalClient(),
            managed_domains=["acl"],
        )
        for field, stale_value, reason_fragment in (
            ("generation", 1, "generation"),
            ("desired_hash", "hash-1", "desired hash"),
        ):
            with self.subTest(field=field):
                status = _terminal_status_for_snapshot(snapshot)
                status["port_statuses"][0][field] = stale_value

                verdict, reason = sync._snapshot_status_verdict(
                    snapshot,
                    set([port_id]),
                    status,
                )

                self.assertEqual("failed", verdict)
                self.assertIn(port_id, reason)
                self.assertIn(reason_fragment, reason)

    def test_scoped_snapshot_rejects_affected_target_missing_from_projection(self):
        port_id = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
        snapshot = {
            "generation": 2,
            "desired_hash": "hash-2",
            "scope": {"type": "port", "port_id": port_id},
            "ports": [{
                "port_id": port_id,
                "eligible": True,
                "managed_domains": ["acl"],
                "acl": {
                    "enabled": True,
                    "status": "ready",
                    "effective_action": "enforce",
                },
            }],
        }
        sync = SnapshotSynchronizer(
            "ostack2",
            StaticPortSource([]),
            FakeOvsReader(),
            FakeLocalClient(),
            managed_domains=["acl"],
        )

        verdict, reason = sync._snapshot_status_verdict(
            snapshot,
            set(),
            _terminal_status_for_snapshot(snapshot),
        )

        self.assertEqual("failed", verdict)
        self.assertIn(port_id, reason)
        self.assertIn("projected", reason)

    def test_scoped_snapshot_rejects_missing_unaffected_runtime_row(self):
        target_port = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
        unaffected_port = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
        snapshot = {
            "generation": 2,
            "desired_hash": "hash-2",
            "scope": {"type": "port", "port_id": target_port},
            "ports": [{
                "port_id": target_port,
                "eligible": True,
                "managed_domains": ["acl"],
                "acl": {
                    "enabled": True,
                    "status": "ready",
                    "effective_action": "enforce",
                },
            }],
        }
        sync = SnapshotSynchronizer(
            "ostack2",
            StaticPortSource([]),
            FakeOvsReader(),
            FakeLocalClient(),
            managed_domains=["acl"],
        )

        verdict, reason = sync._snapshot_status_verdict(
            snapshot,
            set([target_port, unaffected_port]),
            _terminal_status_for_snapshot(snapshot),
        )

        self.assertEqual("failed", verdict)
        self.assertIn(unaffected_port, reason)

    def test_snapshot_status_parses_pending_generation_fail_closed(self):
        snapshot = _ready_acl_snapshot(generation=2, desired_hash="hash-2")
        port_id = snapshot["ports"][0]["port_id"]
        sync = SnapshotSynchronizer(
            "ostack2",
            StaticPortSource([]),
            FakeOvsReader(),
            FakeLocalClient(),
            managed_domains=["acl"],
        )
        missing = object()
        cases = (
            (missing, "failed"),
            ("0", "failed"),
            ("3", "failed"),
            (True, "failed"),
            (False, "failed"),
            (0.0, "failed"),
            (3.0, "failed"),
            (-1, "failed"),
            ("malformed", "failed"),
            (None, "ready"),
            (0, "ready"),
            (3, "pending"),
        )
        for pending_generation, expected_verdict in cases:
            with self.subTest(pending_generation=pending_generation):
                status = _terminal_status_for_snapshot(snapshot)
                if pending_generation is missing:
                    del status["pending_generation"]
                else:
                    status["pending_generation"] = pending_generation

                verdict, reason = sync._snapshot_status_verdict(
                    snapshot,
                    set([port_id]),
                    status,
                )

                self.assertEqual(expected_verdict, verdict)
                if expected_verdict != "ready":
                    self.assertIn("pending generation", reason)

    def test_full_resync_materializes_not_requested_acl_without_source_or_index(self):
        port_id = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
        local_client = FakeLocalClient()
        sync = SnapshotSynchronizer(
            "ostack2",
            StaticPortSource([{
                "id": port_id,
                "network_id": "net-1",
                "device_owner": "compute:nova",
                "binding:host_id": "ostack2",
                "binding:vif_type": "ovs",
                "binding:vnic_type": "normal",
            }]),
            FakeOvsReader(),
            local_client,
            managed_domains=["acl"],
        )

        result = sync.full_resync()

        desired_acl = local_client.snapshots[0]["ports"][0].get("acl") or {}
        runtime_acl = result["status"]["last_port_statuses"][0]["domains"][0]
        self.assertEqual(False, desired_acl.get("enabled"))
        self.assertEqual("not_requested", desired_acl.get("status"))
        self.assertEqual("bypass", desired_acl.get("effective_action"))
        self.assertEqual("not_requested", runtime_acl["status"])
        self.assertEqual("bypass", runtime_acl["effective_action"])

    def test_full_resync_rejects_ready_acl_without_enforcing_action_for_missing_source(self):
        port_id = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
        for effective_action in (None, "unchanged"):
            with self.subTest(effective_action=effective_action):
                local_client = ReadyAclActionLocalClient(effective_action)
                sync = SnapshotSynchronizer(
                    "ostack2",
                    StaticPortSource([{
                        "id": port_id,
                        "network_id": "net-1",
                        "device_owner": "compute:nova",
                        "binding:host_id": "ostack2",
                        "binding:vif_type": "ovs",
                        "binding:vnic_type": "normal",
                    }]),
                    FakeOvsReader(),
                    local_client,
                    managed_domains=["acl"],
                )

                result = sync.safe_full_resync()

                desired_acl = local_client.snapshots[0]["ports"][0].get("acl") or {}
                self.assertEqual("not_requested", desired_acl.get("status"))
                self.assertEqual("bypass", desired_acl.get("effective_action"))
                self.assertTrue(result["status"]["degraded"])
                self.assertFalse(result["status"]["ready"])
                self.assertEqual(1, sync.state_store.pending_snapshot()["generation"])

    def test_dry_run_port_update_builds_scoped_snapshot_without_submit(self):
        port_id = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
        neutron_port = {
            "id": port_id,
            "network_id": "net-1",
            "revision_number": 7,
            "device_owner": "compute:nova",
            "binding:host_id": "ostack2",
            "binding:vif_type": "ovs",
            "binding:vnic_type": "normal",
        }
        port_source = StaticPortSource([neutron_port])
        acl_index = EffectiveAclIndex(
            policies=[{
                "id": "acl-policy",
                "default_action": "allow",
                "revision_number": 10,
            }],
            bindings=[{
                "id": "acl-binding",
                "policy_id": "acl-policy",
                "target_type": "port",
                "target_id": port_id,
                "revision_number": 11,
            }],
        )
        local_client = FakeLocalClient()
        sync = SnapshotSynchronizer(
            "ostack2",
            port_source,
            FakeOvsReader(),
            local_client,
            managed_domains=["acl"],
            acl_index=acl_index,
        )
        sync.full_resync()
        neutron_port["revision_number"] = 8

        preview = sync.dry_run_port_scoped_snapshot(
            port_id,
            binding_host="ostack2",
            revision_number=8,
        )

        self.assertFalse(preview["submitted"])
        self.assertEqual(None, preview["skipped_reason"])
        self.assertEqual("full_resync", preview["decision"]["action"])
        self.assertEqual("local_port_update", preview["decision"]["reason"])
        self.assertEqual("newer", preview["decision"]["revision_status"])
        self.assertEqual(2, preview["snapshot"]["generation"])
        self.assertEqual({"type": "port", "port_id": port_id}, preview["snapshot"]["scope"])
        self.assertEqual(1, len(preview["snapshot"]["ports"]))
        self.assertEqual("acl-policy", preview["snapshot"]["ports"][0]["acl"]["policy_id"])
        self.assertEqual(1, len(local_client.snapshots))
        self.assertEqual([], local_client.deleted_ports)

    def test_dry_run_port_update_skips_when_revision_is_not_newer(self):
        port_id = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
        port_source = StaticPortSource([{
            "id": port_id,
            "network_id": "net-1",
            "revision_number": 7,
            "device_owner": "compute:nova",
            "binding:host_id": "ostack2",
            "binding:vif_type": "ovs",
            "binding:vnic_type": "normal",
        }])
        local_client = FakeLocalClient()
        sync = SnapshotSynchronizer(
            "ostack2",
            port_source,
            FakeOvsReader(),
            local_client,
            managed_domains=["acl"],
        )
        sync.full_resync()

        same = sync.dry_run_port_scoped_snapshot(
            port_id,
            binding_host="ostack2",
            revision_number=7,
        )
        older = sync.dry_run_port_scoped_snapshot(
            port_id,
            binding_host="ostack2",
            revision_number=6,
        )

        self.assertEqual("revision_not_newer", same["skipped_reason"])
        self.assertEqual("same", same["decision"]["revision_status"])
        self.assertEqual(None, same["snapshot"])
        self.assertEqual("revision_not_newer", older["skipped_reason"])
        self.assertEqual("older", older["decision"]["revision_status"])
        self.assertEqual(None, older["snapshot"])
        self.assertEqual(1, len(local_client.snapshots))

    def test_dry_run_port_update_requires_explicit_allow_for_unknown_revision(self):
        port_id = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
        port_source = StaticPortSource([{
            "id": port_id,
            "network_id": "net-1",
            "device_owner": "compute:nova",
            "binding:host_id": "ostack2",
            "binding:vif_type": "ovs",
            "binding:vnic_type": "normal",
        }])
        local_client = FakeLocalClient()
        sync = SnapshotSynchronizer(
            "ostack2",
            port_source,
            FakeOvsReader(),
            local_client,
            managed_domains=["acl"],
        )
        sync.full_resync()

        default = sync.dry_run_port_scoped_snapshot(
            port_id,
            binding_host="ostack2",
        )
        allowed = sync.dry_run_port_scoped_snapshot(
            port_id,
            binding_host="ostack2",
            allow_revisionless=True,
        )

        self.assertEqual("revision_not_newer", default["skipped_reason"])
        self.assertEqual("unknown", default["decision"]["revision_status"])
        self.assertEqual(None, default["snapshot"])
        self.assertEqual(None, allowed["skipped_reason"])
        self.assertEqual("experimental", allowed["revisionless_incremental_mode"])
        self.assertEqual(1, len(allowed["snapshot"]["ports"]))
        self.assertEqual(1, len(local_client.snapshots))

    def test_dry_run_port_update_skips_foreign_or_unavailable_port(self):
        port_id = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
        neutron_port = {
            "id": port_id,
            "network_id": "net-1",
            "revision_number": 7,
            "device_owner": "compute:nova",
            "binding:host_id": "ostack2",
            "binding:vif_type": "ovs",
            "binding:vnic_type": "normal",
        }
        port_source = StaticPortSource([neutron_port])
        local_client = FakeLocalClient()
        sync = SnapshotSynchronizer(
            "ostack2",
            port_source,
            FakeOvsReader(),
            local_client,
            managed_domains=["acl"],
        )
        sync.full_resync()

        foreign = sync.dry_run_port_scoped_snapshot(
            port_id,
            binding_host="ostack3",
            revision_number=8,
        )
        neutron_port["binding:host_id"] = "ostack3"
        unavailable = sync.dry_run_port_scoped_snapshot(
            port_id,
            binding_host="ostack2",
            revision_number=8,
        )

        self.assertEqual(
            "decision_not_port_scoped_candidate",
            foreign["skipped_reason"],
        )
        self.assertEqual("delete_local", foreign["decision"]["action"])
        self.assertEqual(None, foreign["snapshot"])
        self.assertEqual("port_not_available_for_host", unavailable["skipped_reason"])
        self.assertEqual(None, unavailable["snapshot"])
        self.assertEqual([], local_client.deleted_ports)

    def test_apply_port_scoped_snapshot_submits_and_preserves_projection(self):
        port1 = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
        port2 = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
        neutron_ports = [{
            "id": port1,
            "network_id": "net-1",
            "revision_number": 7,
            "device_owner": "compute:nova",
            "binding:host_id": "ostack2",
            "binding:vif_type": "ovs",
            "binding:vnic_type": "normal",
        }, {
            "id": port2,
            "network_id": "net-2",
            "revision_number": 3,
            "device_owner": "compute:nova",
            "binding:host_id": "ostack2",
            "binding:vif_type": "ovs",
            "binding:vnic_type": "normal",
        }]
        port_source = StaticPortSource(neutron_ports)
        local_client = FakeLocalClient()
        sync = SnapshotSynchronizer(
            "ostack2",
            port_source,
            FakeOvsReader(),
            local_client,
            managed_domains=["acl"],
        )
        sync.full_resync()
        neutron_ports[0]["revision_number"] = 8

        result = sync.apply_port_scoped_snapshot(
            port1,
            binding_host="ostack2",
            revision_number=8,
        )

        self.assertTrue(result["submitted"])
        self.assertEqual(1, len(local_client.port_snapshots))
        submitted = local_client.port_snapshots[0]["snapshot"]
        self.assertEqual(2, submitted["generation"])
        self.assertEqual([port1], [port["port_id"] for port in submitted["ports"]])
        self.assertEqual(set([port1, port2]), sync.projected_port_ids)
        self.assertEqual([port1, port2], sync.state_store.last_projected_port_ids())
        self.assertEqual(8, sync.projection_index.port(port1).revision_number)
        self.assertEqual(3, sync.projection_index.port(port2).revision_number)
        self.assertEqual(2, result["status"]["last_generation"])

    def test_scoped_apply_accepts_old_unaffected_not_requested_status(self):
        target_port = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
        unaffected_port = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
        neutron_ports = [{
            "id": target_port,
            "network_id": "net-1",
            "revision_number": 7,
            "device_owner": "compute:nova",
            "binding:host_id": "ostack2",
            "binding:vif_type": "ovs",
            "binding:vnic_type": "normal",
        }, {
            "id": unaffected_port,
            "network_id": "net-2",
            "revision_number": 3,
            "device_owner": "compute:nova",
            "binding:host_id": "ostack2",
            "binding:vif_type": "ovs",
            "binding:vnic_type": "normal",
        }]
        local_client = FakeLocalClient()
        sync = SnapshotSynchronizer(
            "ostack2",
            StaticPortSource(neutron_ports),
            FakeOvsReader(),
            local_client,
            managed_domains=["acl"],
            acl_index=EffectiveAclIndex(),
        )
        baseline = sync.full_resync()
        baseline_generation = baseline["snapshot"]["generation"]
        baseline_hash = baseline["snapshot"]["desired_hash"]
        sync.acl_index = EffectiveAclIndex(
            policies=[{
                "id": "acl-policy",
                "default_action": "allow",
            }],
            bindings=[{
                "id": "acl-binding",
                "policy_id": "acl-policy",
                "target_type": "port",
                "target_id": target_port,
            }],
        )
        neutron_ports[0]["revision_number"] = 8

        try:
            result = sync.apply_port_scoped_snapshot(
                target_port,
                binding_host="ostack2",
                revision_number=8,
            )
        except LocalApiError as exc:
            self.fail(
                "scoped target was rejected because of the unaffected port: %s" %
                exc
            )
        aggregate_status = local_client.status()
        rows = dict(
            (row["port_id"], row)
            for row in aggregate_status["port_statuses"]
        )

        self.assertTrue(result["submitted"])
        self.assertTrue(result["status"]["ready"])
        self.assertEqual(
            result["snapshot"]["generation"],
            rows[target_port]["generation"],
        )
        self.assertEqual(
            result["snapshot"]["desired_hash"],
            rows[target_port]["desired_hash"],
        )
        self.assertEqual(baseline_generation, rows[unaffected_port]["generation"])
        self.assertEqual(baseline_hash, rows[unaffected_port]["desired_hash"])
        self.assertEqual("not_requested", rows[unaffected_port]["status"])
        self.assertEqual(
            "not_requested",
            rows[unaffected_port]["domains"][0]["status"],
        )
        self.assertEqual(
            "bypass",
            rows[unaffected_port]["domains"][0]["effective_action"],
        )

    def test_apply_port_scoped_snapshot_raises_on_port_error_without_false_ready(self):
        port_id = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
        neutron_ports = [{
            "id": port_id,
            "network_id": "net-1",
            "revision_number": 7,
            "device_owner": "compute:nova",
            "binding:host_id": "ostack2",
            "binding:vif_type": "ovs",
            "binding:vnic_type": "normal",
        }]
        local_client = ScopedResponseErrorLocalClient()
        sync = SnapshotSynchronizer(
            "ostack2",
            StaticPortSource(neutron_ports),
            FakeOvsReader(),
            local_client,
            managed_domains=["acl"],
        )
        sync.full_resync()
        neutron_ports[0]["revision_number"] = 8

        with self.assertRaises(LocalApiError) as ctx:
            sync.apply_port_scoped_snapshot(
                port_id,
                binding_host="ostack2",
                revision_number=8,
            )

        self.assertIn("PORT_IFACE_NOT_FOUND", str(ctx.exception))
        self.assertEqual(1, len(local_client.port_snapshots))
        self.assertEqual(1, sync.runtime_status.last_generation)
        self.assertEqual(7, sync.projection_index.port(port_id).revision_number)
        self.assertTrue(sync.runtime_status.degraded)
        self.assertFalse(sync.runtime_status.ready)
        self.assertEqual(
            "pending_snapshot_unresolved",
            sync.runtime_status.reason,
        )
        self.assertIsNotNone(sync.state_store.pending_snapshot())

    def test_scoped_snapshot_keeps_prior_state_when_status_hash_mismatches(self):
        state_dir = tempfile.mkdtemp()
        try:
            port_id = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
            neutron_ports = [{
                "id": port_id,
                "network_id": "net-1",
                "revision_number": 7,
                "device_owner": "compute:nova",
                "binding:host_id": "ostack2",
                "binding:vif_type": "ovs",
                "binding:vnic_type": "normal",
            }]
            local_client = TerminalIdentityMismatchLocalClient()
            sync = SnapshotSynchronizer(
                "ostack2",
                StaticPortSource(neutron_ports),
                FakeOvsReader(),
                local_client,
                managed_domains=["acl"],
                state_store=SnapshotStateStore(state_dir),
            )
            baseline = sync.full_resync()
            baseline_hash = baseline["snapshot"]["desired_hash"]
            local_client.set_terminal_status_updates(
                desired_hash="mismatched-status-hash",
            )
            neutron_ports[0]["revision_number"] = 8

            with self.assertRaises(LocalApiError) as ctx:
                sync.apply_port_scoped_snapshot(
                    port_id,
                    binding_host="ostack2",
                    revision_number=8,
                )

            state = SnapshotStateStore(state_dir).to_dict()
            self.assertIn("desired_hash", str(ctx.exception))
            self.assertEqual(2, state["pending_generation"])
            self.assertEqual(1, state["last_generation"])
            self.assertEqual(baseline_hash, state["last_desired_hash"])
            self.assertEqual([port_id], state["last_projected_port_ids"])
            self.assertEqual(7, sync.projection_index.port(port_id).revision_number)
            self.assertEqual(1, sync.runtime_status.last_generation)
            self.assertEqual(baseline_hash, sync.runtime_status.last_desired_hash)
            self.assertEqual(1, sync.runtime_status.accepted_generation)
            self.assertTrue(sync.runtime_status.degraded)
            self.assertFalse(sync.runtime_status.ready)
            self.assertEqual(
                "pending_snapshot_unresolved",
                sync.runtime_status.reason,
            )
        finally:
            shutil.rmtree(state_dir)

    def test_apply_port_scoped_snapshot_keeps_prior_state_when_status_fails(self):
        state_dir = tempfile.mkdtemp()
        try:
            port_id = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
            neutron_ports = [{
                "id": port_id,
                "network_id": "net-1",
                "revision_number": 7,
                "device_owner": "compute:nova",
                "binding:host_id": "ostack2",
                "binding:vif_type": "ovs",
                "binding:vnic_type": "normal",
            }]
            local_client = ScopedStatusUnavailableLocalClient()
            sync = SnapshotSynchronizer(
                "ostack2",
                StaticPortSource(neutron_ports),
                FakeOvsReader(),
                local_client,
                managed_domains=["acl"],
                state_store=SnapshotStateStore(state_dir),
            )
            baseline = sync.full_resync()
            baseline_hash = baseline["snapshot"]["desired_hash"]
            neutron_ports[0]["revision_number"] = 8

            with self.assertRaises(LocalApiError):
                sync.apply_port_scoped_snapshot(
                    port_id,
                    binding_host="ostack2",
                    revision_number=8,
                )

            state = SnapshotStateStore(state_dir).to_dict()
            self.assertEqual(2, state["pending_generation"])
            self.assertEqual(1, state["last_generation"])
            self.assertEqual(baseline_hash, state["last_desired_hash"])
            self.assertEqual(7, sync.projection_index.port(port_id).revision_number)
            self.assertEqual(1, sync.runtime_status.last_generation)
            self.assertFalse(sync.runtime_status.ready)
            self.assertTrue(sync.runtime_status.degraded)
            self.assertEqual(
                "pending_snapshot_unresolved",
                sync.runtime_status.reason,
            )
        finally:
            shutil.rmtree(state_dir)

    def test_apply_port_scoped_snapshot_rejects_acl_degraded_bypass_status(self):
        port_id = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
        neutron_ports = [{
            "id": port_id,
            "network_id": "net-1",
            "revision_number": 7,
            "device_owner": "compute:nova",
            "binding:host_id": "ostack2",
            "binding:vif_type": "ovs",
            "binding:vnic_type": "normal",
        }]
        ready_acl_index = EffectiveAclIndex(
            policies=[{
                "id": "acl-policy",
                "default_action": "allow",
                "revision_number": 7,
            }],
            rules=[{
                "id": "ready-rule",
                "policy_id": "acl-policy",
                "direction": "ingress",
                "priority": 100,
                "action": "allow",
                "ethertype": "IPv4",
                "revision_number": 8,
            }],
            bindings=[{
                "id": "acl-binding",
                "policy_id": "acl-policy",
                "target_type": "port",
                "target_id": port_id,
                "revision_number": 7,
            }],
        )
        local_client = StatusFromPortSnapshotLocalClient()
        sync = SnapshotSynchronizer(
            "ostack2",
            StaticPortSource(neutron_ports),
            FakeOvsReader(),
            local_client,
            managed_domains=["acl"],
            acl_index=ready_acl_index,
        )
        sync.full_resync()
        sync.acl_index = EffectiveAclIndex(
            policies=[{
                "id": "acl-policy",
                "default_action": "allow",
                "revision_number": 7,
            }],
            rules=[{
                "id": "bad-rule",
                "policy_id": "acl-policy",
                "direction": "ingress",
                "priority": "invalid",
                "revision_number": 9,
            }],
            bindings=[{
                "id": "acl-binding",
                "policy_id": "acl-policy",
                "target_type": "port",
                "target_id": port_id,
                "revision_number": 7,
            }],
        )
        neutron_ports[0]["revision_number"] = 8

        with self.assertRaises(LocalApiError) as ctx:
            sync.apply_port_scoped_snapshot(
                port_id,
                binding_host="ostack2",
                revision_number=8,
            )

        submitted = local_client.port_snapshots[0]["snapshot"]["ports"][0]
        acl = submitted["acl"]
        self.assertIn("acl", str(ctx.exception))
        self.assertEqual("degraded", acl["status"])
        self.assertEqual("bypass", acl["effective_action"])
        self.assertIn("invalid_acl_priority:bad-rule:invalid", acl["reason"])
        self.assertEqual(2, sync.state_store.pending_snapshot()["generation"])
        self.assertEqual(1, sync.runtime_status.last_generation)
        self.assertEqual(7, sync.projection_index.port(port_id).revision_number)

    def test_status_projection_never_overwrites_runtime_bypass(self):
        port_id = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
        sync = SnapshotSynchronizer(
            "ostack2",
            StaticPortSource([]),
            FakeOvsReader(),
            FakeLocalClient(),
            managed_domains=["acl"],
        )
        status = {
            "generation": 8,
            "managed_ports": [{"port_id": port_id}],
            "port_statuses": [{
                "port_id": port_id,
                "status": "degraded",
                "effective_action": "bypass",
                "reason": "acl_apply_failed",
                "domains": [{
                    "domain": "acl",
                    "status": "degraded",
                    "effective_action": "bypass",
                    "reason": "acl_apply_failed",
                }],
            }],
        }
        snapshot = {"ports": [{
            "port_id": port_id,
            "acl": {
                "enabled": True,
                "status": "ready",
                "effective_action": "enforce",
                "reason": "ready",
                "policy_id": "policy-1",
            },
        }]}

        row = sync._port_statuses_from_status(status, snapshot)[0]

        self.assertEqual("degraded", row["status"])
        self.assertEqual("bypass", row["effective_action"])
        self.assertEqual("acl_apply_failed", row["reason"])
        self.assertEqual("degraded", row["domains"][0]["status"])
        self.assertEqual("bypass", row["domains"][0]["effective_action"])
        self.assertEqual("acl_apply_failed", row["domains"][0]["reason"])

    def test_full_resync_reloads_acl_source_each_time(self):
        port_id = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
        port_source = StaticPortSource([{
            "id": port_id,
            "network_id": "net-1",
            "device_owner": "compute:nova",
            "binding:host_id": "ostack2",
            "binding:vif_type": "ovs",
            "binding:vnic_type": "normal",
        }])
        acl_source = RotatingAclSource([
            EffectiveAclIndex(
                policies=[{"id": "policy-v1", "default_action": "allow"}],
                bindings=[{
                    "id": "binding-v1",
                    "policy_id": "policy-v1",
                    "target_type": "port",
                    "target_id": port_id,
                }],
            ),
            EffectiveAclIndex(
                policies=[{"id": "policy-v2", "default_action": "allow"}],
                bindings=[{
                    "id": "binding-v2",
                    "policy_id": "policy-v2",
                    "target_type": "port",
                    "target_id": port_id,
                }],
            ),
        ])
        local_client = FakeLocalClient()
        sync = SnapshotSynchronizer(
            "ostack2",
            port_source,
            FakeOvsReader(),
            local_client,
            managed_domains=["acl"],
            acl_source=acl_source,
        )

        sync.full_resync()
        sync.full_resync()

        self.assertEqual(2, acl_source.calls)
        self.assertEqual("policy-v1", local_client.snapshots[0]["ports"][0]["acl"]["policy_id"])
        self.assertEqual("policy-v2", local_client.snapshots[1]["ports"][0]["acl"]["policy_id"])

    def test_full_resync_reports_ready_heartbeat(self):
        status_reporter = FakeStatusReporter()
        sync = SnapshotSynchronizer(
            "ostack2",
            StaticPortSource([]),
            FakeOvsReader(),
            FakeLocalClient(),
            managed_domains=["acl"],
            status_reporter=status_reporter,
        )

        result = sync.full_resync()

        self.assertTrue(result["heartbeat"]["ok"])
        self.assertEqual(1, len(status_reporter.statuses))
        self.assertTrue(status_reporter.statuses[0]["ready"])
        self.assertFalse(status_reporter.statuses[0]["degraded"])
        self.assertEqual("ready", status_reporter.statuses[0]["reason"])

    def test_full_resync_recovers_when_timed_out_snapshot_converged(self):
        port_id = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
        port_source = StaticPortSource([{
            "id": port_id,
            "device_owner": "compute:nova",
            "binding:host_id": "ostack2",
            "binding:vif_type": "ovs",
            "binding:vnic_type": "normal",
        }])
        local_client = TimeoutThenConvergedLocalClient()
        sync = SnapshotSynchronizer(
            "ostack2",
            port_source,
            FakeOvsReader(),
            local_client,
            managed_domains=["acl"],
            timeout_convergence_attempts=1,
            timeout_convergence_interval=0,
        )

        result = sync.full_resync()

        self.assertTrue(result["response"]["recovered_after_timeout"])
        self.assertTrue(result["status"]["ready"])
        self.assertFalse(result["status"]["degraded"])
        self.assertEqual(1, result["status"]["last_managed_ports"])
        self.assertEqual(set([port_id]), sync.projected_port_ids)

    def test_timeout_recovery_rejects_missing_projected_port_status(self):
        port_ids = [
            "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
            "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
        ]
        port_source = StaticPortSource([{
            "id": port_id,
            "device_owner": "compute:nova",
            "binding:host_id": "ostack2",
            "binding:vif_type": "ovs",
            "binding:vnic_type": "normal",
        } for port_id in port_ids])
        local_client = TimeoutThenCommittedWithPartialManagedClient()
        sync = SnapshotSynchronizer(
            "ostack2",
            port_source,
            FakeOvsReader(),
            local_client,
            managed_domains=["acl"],
            timeout_convergence_attempts=1,
            timeout_convergence_interval=0,
        )

        result = sync.safe_full_resync()

        self.assertTrue(result["status"]["degraded"])
        self.assertFalse(result["status"]["ready"])
        self.assertEqual(1, sync.state_store.pending_snapshot()["generation"])
        self.assertEqual(0, sync.runtime_status.last_generation)
        self.assertEqual(set(), sync.projected_port_ids)

    def test_safe_full_resync_degrades_when_timed_out_snapshot_not_converged(self):
        port_source = StaticPortSource([{
            "id": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
            "device_owner": "compute:nova",
            "binding:host_id": "ostack2",
            "binding:vif_type": "ovs",
            "binding:vnic_type": "normal",
        }])
        sync = SnapshotSynchronizer(
            "ostack2",
            port_source,
            FakeOvsReader(),
            TimeoutNotConvergedLocalClient(),
            managed_domains=["acl"],
            timeout_convergence_attempts=1,
            timeout_convergence_interval=0,
        )

        result = sync.safe_full_resync()

        self.assertEqual(None, result["snapshot"])
        self.assertEqual(None, result["response"])
        self.assertFalse(result["status"]["ready"])
        self.assertTrue(result["status"]["degraded"])
        self.assertEqual("local_api_degraded", result["status"]["reason"])
        self.assertIn("status did not converge", result["status"]["last_error"])

    def test_safe_full_resync_marks_local_api_degraded(self):
        sync = SnapshotSynchronizer(
            "ostack2",
            StaticPortSource([]),
            FakeOvsReader(),
            FailingLocalClient(),
            managed_domains=["acl"],
        )

        result = sync.safe_full_resync()

        self.assertEqual(None, result["snapshot"])
        self.assertEqual(None, result["response"])
        self.assertFalse(result["status"]["ready"])
        self.assertTrue(result["status"]["degraded"])
        self.assertEqual("local_api_degraded", result["status"]["reason"])
        self.assertIn("socket unavailable", result["status"]["last_error"])

    def test_safe_full_resync_reports_degraded_heartbeat(self):
        status_reporter = FakeStatusReporter()
        sync = SnapshotSynchronizer(
            "ostack2",
            StaticPortSource([]),
            FakeOvsReader(),
            FailingLocalClient(),
            managed_domains=["acl"],
            status_reporter=status_reporter,
        )

        result = sync.safe_full_resync()

        self.assertTrue(result["heartbeat"]["ok"])
        self.assertEqual(1, len(status_reporter.statuses))
        self.assertFalse(status_reporter.statuses[0]["ready"])
        self.assertTrue(status_reporter.statuses[0]["degraded"])
        self.assertEqual("local_api_degraded", status_reporter.statuses[0]["reason"])

    def test_heartbeat_failure_does_not_hide_resync_result(self):
        sync = SnapshotSynchronizer(
            "ostack2",
            StaticPortSource([]),
            FakeOvsReader(),
            FakeLocalClient(),
            managed_domains=["acl"],
            status_reporter=FailingStatusReporter(),
        )

        result = sync.full_resync()

        self.assertTrue(result["status"]["ready"])
        self.assertFalse(result["heartbeat"]["ok"])
        self.assertIn("rabbit down", result["heartbeat"]["error"])

    def test_delete_port_delegates_to_local_client(self):
        state_dir = tempfile.mkdtemp()
        local_client = FakeLocalClient()
        try:
            sync = SnapshotSynchronizer(
                "ostack2",
                StaticPortSource([]),
                FakeOvsReader(),
                local_client,
                state_store=SnapshotStateStore(state_dir),
            )

            sync.delete_port("port-1", reason="migration_source_cleanup")
            state = SnapshotStateStore(state_dir).to_dict()

            self.assertEqual(["port-1"], local_client.deleted_ports)
            self.assertEqual(None, state["pending_delete_port_id"])
            self.assertEqual("port-1", state["last_deleted_port_id"])
        finally:
            shutil.rmtree(state_dir)

    def test_delete_port_recovers_when_timed_out_delete_converged(self):
        local_client = DeleteTimeoutThenConvergedLocalClient()
        sync = SnapshotSynchronizer(
            "ostack2",
            StaticPortSource([]),
            FakeOvsReader(),
            local_client,
            timeout_convergence_attempts=1,
            timeout_convergence_interval=0,
        )
        sync.projected_port_ids.add("port-1")

        response = sync.delete_port("port-1")

        self.assertTrue(response["recovered_after_timeout"])
        self.assertEqual("deleted", response["status"])
        self.assertEqual(["port-1"], local_client.deleted_ports)
        self.assertFalse(sync.has_projected_port("port-1"))

    def test_delete_port_keeps_timeout_when_delete_not_converged(self):
        state_dir = tempfile.mkdtemp()
        try:
            sync = SnapshotSynchronizer(
                "ostack2",
                StaticPortSource([]),
                FakeOvsReader(),
                DeleteTimeoutNotConvergedLocalClient(),
                state_store=SnapshotStateStore(state_dir),
                timeout_convergence_attempts=1,
                timeout_convergence_interval=0,
            )

            self.assertRaises(
                LocalApiTimeoutError,
                sync.delete_port,
                "port-1",
            )
            pending = SnapshotStateStore(state_dir).pending_delete()

            self.assertEqual("port-1", pending["port_id"])
        finally:
            shutil.rmtree(state_dir)

    def test_delete_port_rejects_explicit_error_without_committing_projection(self):
        state_dir = tempfile.mkdtemp()
        try:
            store = SnapshotStateStore(state_dir)
            prepared = store.prepare_snapshot({
                "host": "ostack2",
                "ports": [{
                    "port_id": "port-1",
                    "ifname": "tap-port-1",
                    "eligible": True,
                    "managed_domains": ["acl"],
                }],
            })
            store.commit_snapshot(prepared["generation"], prepared["desired_hash"])
            sync = SnapshotSynchronizer(
                "ostack2",
                StaticPortSource([]),
                FakeOvsReader(),
                DeleteResponseErrorLocalClient(),
                state_store=SnapshotStateStore(state_dir),
            )

            with self.assertRaises(LocalApiError):
                sync.delete_port("port-1", reason="explicit-error")

            self.assertTrue(sync.has_projected_port("port-1"))
            self.assertEqual(
                "port-1",
                SnapshotStateStore(state_dir).pending_delete()["port_id"],
            )
            self.assertTrue(sync.runtime_status.degraded)
            self.assertEqual(
                "pending_delete_unresolved",
                sync.runtime_status.reason,
            )
        finally:
            shutil.rmtree(state_dir)

    def test_delete_port_rejects_mismatched_response_identity(self):
        sync = SnapshotSynchronizer(
            "ostack2",
            StaticPortSource([]),
            FakeOvsReader(),
            DeleteWrongPortLocalClient(),
        )
        sync.projected_port_ids.add("port-1")

        with self.assertRaises(LocalApiError):
            sync.delete_port("port-1", reason="wrong-response-port")

        self.assertTrue(sync.has_projected_port("port-1"))
        self.assertEqual("port-1", sync.state_store.pending_delete()["port_id"])
        self.assertTrue(sync.runtime_status.degraded)

    def test_delete_port_removes_cached_runtime_status_after_commit(self):
        sync = SnapshotSynchronizer(
            "ostack2",
            StaticPortSource([]),
            FakeOvsReader(),
            FakeLocalClient(),
        )
        sync.runtime_status.mark_ready(
            generation=4,
            snapshot_ports=2,
            managed_ports=2,
            port_statuses=[{
                "port_id": "port-1",
                "status": "ready",
                "domains": [{
                    "domain": "acl",
                    "status": "ready",
                    "effective_action": "enforce",
                }],
            }, {
                "port_id": "port-2",
                "status": "ready",
                "domains": [{
                    "domain": "acl",
                    "status": "ready",
                    "effective_action": "enforce",
                }],
            }],
        )
        sync.projected_port_ids.update(("port-1", "port-2"))

        sync.delete_port("port-1")

        self.assertEqual(
            ["port-2"],
            [
                status["port_id"]
                for status in sync.runtime_status.last_port_statuses
            ],
        )
        self.assertEqual(
            1,
            sum(
                item["count"]
                for item in sync.runtime_status.domain_counts
                if item["domain"] == "acl" and item["status"] == "ready"
            ),
        )

    def test_pending_delete_recovered_on_restart(self):
        state_dir = tempfile.mkdtemp()
        try:
            store = SnapshotStateStore(state_dir)
            prepared = store.prepare_snapshot({
                "host": "ostack2",
                "ports": [{
                    "port_id": "port-1",
                    "ifname": "tap-port-1",
                    "eligible": True,
                    "managed_domains": ["acl"],
                }],
            })
            store.commit_snapshot(prepared["generation"], prepared["desired_hash"])
            store.prepare_delete("port-1", reason="port_delete_event")
            sync = SnapshotSynchronizer(
                "ostack2",
                StaticPortSource([]),
                FakeOvsReader(),
                FixedStatusLocalClient({
                    "generation": 1,
                    "managed_ports": [],
                    "active_instances": [],
                }),
                state_store=SnapshotStateStore(state_dir),
            )

            recovered = sync.recover_pending_state()
            state = SnapshotStateStore(state_dir)

            self.assertEqual(["delete"], recovered["recovered"])
            self.assertEqual(None, state.pending_delete())
            self.assertFalse(sync.has_projected_port("port-1"))
        finally:
            shutil.rmtree(state_dir)


class StatusContractEventLoopRedTestCase(unittest.TestCase):
    _target_port_source = EventLoopTestCase._target_port_source
    _baseline_snapshot = EventLoopTestCase._baseline_snapshot
    test_contract_error_is_not_generation_floor_absence_or_continued_submit = (
        EventLoopTestCase._red_contract_error_is_not_generation_floor_absence_or_continued_submit
    )
    test_classified_degraded_records_only_classification_and_ready_heartbeat_history = (
        EventLoopTestCase._red_classified_degraded_records_only_classification_and_ready_heartbeat_history
    )
    test_restart_routes_from_classified_ids_without_changing_ready_history = (
        EventLoopTestCase._red_restart_routes_from_classified_ids_without_changing_ready_history
    )

    def _synchronizer(self, local_client=None, **overrides):
        options = {
            "timeout_convergence_attempts": 1,
            "timeout_convergence_interval": 0,
            "sleeper": lambda _seconds: None,
        }
        options.update(overrides)
        return SnapshotSynchronizer(
            "ostack2",
            StaticPortSource([]),
            FakeOvsReader(),
            local_client or FakeLocalClient(),
            managed_domains=["acl"],
            **options
        )

    def _assert_no_mutating_calls(self, local_client):
        self.assertEqual([], local_client.snapshots)
        self.assertEqual([], local_client.port_snapshots)
        self.assertEqual([], local_client.deleted_ports)
        self.assertEqual([], local_client.recoveries)
        self.assertEqual([], local_client.mutating_calls)

    def _state_store_with_expected_pending(self, scenario):
        context = scenario["request_context"]
        state_store = InMemorySnapshotStateStore()
        state_store.prepare_snapshot_at_generation(
            {"host": "ostack2", "ports": []},
            context["expected_pending_generation"],
            desired_hash=context["expected_desired_hash"],
        )
        return state_store

    def _v1_control_projection(self, status):
        return tuple(status.get(key) for key in (
            "transaction_state",
            "overall_readiness",
            "required_action",
            "recovery_cause",
        ))

    def test_full_and_scoped_ready_validate_exact_evidence(self):
        sync = self._synchronizer()
        for scenario_id in (
            "full-classified-ready",
            "scoped-classified-ready",
        ):
            scenario = status_scenario(scenario_id)
            context = scenario["request_context"]
            verdict, reason = sync._snapshot_status_verdict(
                context["snapshot"],
                context["projected_port_ids"],
                scenario["status"],
            )

            with self.subTest(scenario=scenario_id):
                self.assertEqual("ready", verdict, reason)
                self.assertEqual(
                    "feature_ready",
                    scenario["expected_python"]["decision"],
                )

        scoped = status_scenario("scoped-classified-ready")
        unaffected = [
            row for row in scoped["status"]["port_statuses"]
            if row["port_id"] == "port-b"
        ][0]
        self.assertLess(
            unaffected["generation"],
            scoped["request_context"]["expected_generation"],
        )
        self.assertEqual("hash-ready-42", unaffected["desired_hash"])

    def test_public_v1_poll_and_operator_are_diagnostic_independent_no_write(self):
        variants = [
            ("pending-poll", "fixture-diagnostics", {}),
            (
                "pending-poll",
                "recovery-looking-diagnostics",
                {
                    "authority_state": "blocked_recovery_required",
                    "wal_status": "inventory_barrier_pending",
                },
            ),
            ("blocked-operator", "fixture-diagnostics", {}),
            (
                "blocked-operator",
                "ready-looking-diagnostics",
                {
                    "authority_state": "ready",
                    "wal_status": "committed",
                },
            ),
        ]
        for scenario_id, variant, diagnostic_updates in variants:
            scenario = status_scenario(scenario_id)
            status = copy.deepcopy(scenario["status"])
            status.update(diagnostic_updates)
            local_client = PublicV1ActionLocalClient(scenario, status=status)
            sync = self._synchronizer(local_client)

            sync.safe_full_resync()

            with self.subTest(scenario=scenario_id, variant=variant):
                self.assertEqual(
                    self._v1_control_projection(scenario["status"]),
                    self._v1_control_projection(status),
                )
                if diagnostic_updates:
                    self.assertNotEqual(
                        (
                            scenario["status"].get("authority_state"),
                            scenario["status"].get("wal_status"),
                        ),
                        (status.get("authority_state"), status.get("wal_status")),
                    )
                self.assertIn(
                    scenario["expected_python"]["decision"],
                    ("poll", "blocked_operator"),
                )
                self.assertEqual(
                    [],
                    scenario["expected_python"]["public_mutating_calls"],
                )
                self._assert_no_mutating_calls(local_client)

    def test_public_v1_recovery_requires_local_exact_identity_then_fresh_newer_full_snapshot(self):
        for scenario_id in (
            "blocked-recoverable-inventory",
            "generation-zero-inventory-recovery",
        ):
            scenario = status_scenario(scenario_id)
            status = copy.deepcopy(scenario["status"])
            status.update({
                "authority_state": "ready",
                "wal_status": "diagnostic_only",
            })
            local_client = PublicV1ActionLocalClient(scenario, status=status)
            state_store = self._state_store_with_expected_pending(scenario)
            local_pending_before = copy.deepcopy(
                state_store.pending_snapshot()
            )
            sync = self._synchronizer(
                local_client,
                state_store=state_store,
            )

            result = sync.safe_full_resync()
            context = scenario["request_context"]
            expected_recovery = {
                "expected_generation": context["expected_pending_generation"],
                "expected_desired_hash": context["expected_desired_hash"],
            }

            with self.subTest(scenario=scenario_id):
                self.assertEqual(
                    self._v1_control_projection(scenario["status"]),
                    self._v1_control_projection(status),
                )
                self.assertNotEqual(
                    (
                        scenario["status"].get("authority_state"),
                        scenario["status"].get("wal_status"),
                    ),
                    (status.get("authority_state"), status.get("wal_status")),
                )
                self.assertFalse(hasattr(local_client, "scenario"))
                self.assertEqual(
                    context["expected_pending_generation"],
                    local_pending_before["generation"],
                )
                self.assertEqual(
                    context["expected_desired_hash"],
                    local_pending_before["desired_hash"],
                )
                self.assertEqual(
                    (
                        local_pending_before["generation"],
                        local_pending_before["desired_hash"],
                    ),
                    (status["pending_generation"], status["desired_hash"]),
                )
                self.assertEqual([expected_recovery], local_client.recoveries)
                self.assertEqual(
                    scenario["expected_python"]["public_mutating_calls"],
                    local_client.mutating_calls,
                )
                self.assertEqual(1, len(local_client.snapshots))
                self.assertEqual([], local_client.port_snapshots)
                self.assertEqual([], local_client.deleted_ports)
                fresh_generation = local_client.snapshots[0]["generation"]
                self.assertGreater(
                    fresh_generation,
                    max(
                        context["expected_pending_generation"],
                        status["last_classified_generation"],
                        status["applied_generation"],
                    ),
                )
                self.assertEqual(
                    fresh_generation,
                    (result.get("snapshot") or {}).get("generation"),
                )
                self.assertEqual(None, state_store.pending_snapshot())

    def test_generation_zero_recovery_rejects_each_missing_gate_without_write(self):
        scenario = status_scenario("generation-zero-inventory-recovery")
        for case in status_scenario_negative_cases(scenario["id"]):
            state_store = self._state_store_with_expected_pending(scenario)
            local_pending_before = copy.deepcopy(
                state_store.pending_snapshot()
            )
            local_client = PublicV1ActionLocalClient(
                scenario,
                status=case["status"],
            )
            sync = self._synchronizer(
                local_client,
                state_store=state_store,
            )

            sync.safe_full_resync()

            with self.subTest(case=case["id"], assertion="no-writes"):
                self.assertEqual(
                    "blocked_operator",
                    case["expected_python"]["decision"],
                )
                self.assertEqual([], case["expected_python"]["mutating_calls"])
                self._assert_no_mutating_calls(local_client)

            if case["id"] in (
                "mismatched-pending-generation",
                "mismatched-pending-hash",
            ):
                with self.subTest(
                    case=case["id"],
                    assertion="local-pending-preserved",
                ):
                    self.assertNotEqual(
                        (
                            local_pending_before["generation"],
                            local_pending_before["desired_hash"],
                        ),
                        (
                            case["status"].get("pending_generation"),
                            case["status"].get("desired_hash"),
                        ),
                    )
                    self.assertEqual(
                        local_pending_before,
                        state_store.pending_snapshot(),
                    )


class StatusContractPythonGreenFocusedEventLoopTestCase(unittest.TestCase):
    def _actual_decoded_legacy_status(
        self,
        case_id=None,
        clear_runtime_evidence=False,
    ):
        scenario = status_scenario("legacy-v0-ready")
        status = copy.deepcopy(scenario["status"])
        if case_id is not None:
            case = next(
                item for item in scenario["legacy_decoding_cases"]
                if item["id"] == case_id
            )
            status.update(copy.deepcopy(case["status_overrides"]))
        if clear_runtime_evidence:
            status.update({
                "managed_ports": [],
                "port_statuses": [],
                "active_instances": [],
            })
        return _decode_legacy_status_v0(status)

    def _decoded_legacy_status(self, case_id=None):
        scenario = status_scenario("legacy-v0-ready")
        status = copy.deepcopy(scenario["status"])
        projection = copy.deepcopy(scenario["expected_projection"])
        if case_id is not None:
            case = next(
                item for item in scenario["legacy_decoding_cases"]
                if item["id"] == case_id
            )
            status.update(copy.deepcopy(case["status_overrides"]))
            projection = copy.deepcopy(case["expected_projection"])
        status.update(projection)
        return status

    def _state_store_with_projected_port(
        self,
        port_id="aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
        generation=1,
        desired_hash="hash-ready-1",
    ):
        state_store = InMemorySnapshotStateStore()
        prepared = state_store.prepare_snapshot_at_generation(
            {
                "host": "ostack2",
                "ports": [{
                    "port_id": port_id,
                    "ifname": "tap%s" % port_id[:11],
                    "eligible": True,
                    "managed_domains": ["acl"],
                }],
            },
            generation,
            desired_hash=desired_hash,
        )
        state_store.commit_snapshot(
            prepared["generation"],
            prepared["desired_hash"],
            snapshot_ports=1,
            managed_ports=1,
            feature_ready_domains=["acl"],
        )
        return state_store

    def _terminal_degraded_snapshot(self, scenario):
        port_id = scenario["request_context"]["projected_port_ids"][0]
        return {
            "generation": scenario["request_context"]["expected_generation"],
            "desired_hash": scenario["request_context"]["expected_desired_hash"],
            "ports": [{
                "port_id": port_id,
                "ifname": "",
                "eligible": True,
                "managed_domains": ["acl"],
                "acl": {
                    "enabled": True,
                    "status": "ready",
                    "effective_action": "enforce",
                },
            }],
        }

    def _target_port_source(self):
        return StaticPortSource([{
            "id": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
            "network_id": "net-a",
            "revision_number": 8,
            "device_owner": "compute:nova",
            "binding:host_id": "ostack2",
            "binding:vif_type": "ovs",
            "binding:vnic_type": "normal",
        }])

    def _terminal_degraded_acl_index(self):
        return EffectiveAclIndex(
            policies=[{
                "id": "policy-degraded",
                "default_action": "allow",
            }],
            bindings=[{
                "id": "binding-degraded",
                "policy_id": "policy-degraded",
                "target_type": "port",
                "target_id": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
            }],
        )

    def test_real_terminal_degraded_with_ready_authority_classifies_without_ready_commit(self):
        scenario = status_scenario("classified-degraded-terminal")
        scenario["status"]["authority_state"] = "ready"
        state_store = InMemorySnapshotStateStore()
        baseline = state_store.prepare_snapshot_at_generation(
            {
                "host": "ostack2",
                "ports": [{
                    "port_id": "port-old",
                    "ifname": "tap-port-old",
                    "eligible": True,
                    "managed_domains": ["acl"],
                }],
            },
            scenario["request_context"]["feature_ready_generation_before"],
            desired_hash="ready-hash-43",
        )
        state_store.commit_snapshot(
            baseline["generation"],
            baseline["desired_hash"],
            snapshot_ports=1,
            managed_ports=1,
        )
        local_client = FixtureStatusLocalClient(scenario)
        status_reporter = FakeStatusReporter()
        sync = SnapshotSynchronizer(
            "ostack2",
            self._target_port_source(),
            FakeOvsReader(),
            local_client,
            managed_domains=["acl"],
            state_store=state_store,
            status_reporter=status_reporter,
            acl_index=self._terminal_degraded_acl_index(),
        )

        result = sync.safe_full_resync()
        state = state_store.to_dict()

        self.assertEqual(
            scenario["status"]["last_classified_generation"],
            state.get("last_classified_generation"),
        )
        self.assertEqual(
            scenario["request_context"]["feature_ready_generation_before"],
            state.get("last_feature_ready_generation"),
        )
        self.assertEqual("ready-hash-43", state.get("last_feature_ready_desired_hash"))
        self.assertEqual(None, state_store.pending_snapshot())
        self.assertFalse(result["status"]["ready"])
        self.assertTrue(result["status"]["degraded"])
        self.assertEqual(
            scenario["request_context"]["feature_ready_generation_before"],
            result["status"]["last_generation"],
        )
        self.assertEqual(1, len(local_client.snapshots))
        self.assertEqual([], local_client.port_snapshots)
        self.assertEqual([], local_client.deleted_ports)
        self.assertEqual([], getattr(local_client, "recoveries", []))
        self.assertEqual(1, len(status_reporter.statuses))

    def test_classified_degraded_none_ignores_all_diagnostic_reason_shapes(self):
        scenario = status_scenario("classified-degraded-terminal")
        snapshot = self._terminal_degraded_snapshot(scenario)
        sync = SnapshotSynchronizer(
            "ostack2",
            StaticPortSource([]),
            FakeOvsReader(),
            FakeLocalClient(),
            managed_domains=["acl"],
        )
        for label, reason in (
            ("contains-full-resync", "operator requested full_resync manually"),
            ("exact-rebuild-token", "runtime_rebuild_required"),
            ("unrelated", "diagnostic text only"),
        ):
            status = copy.deepcopy(scenario["status"])
            status["authority_state"] = "ready"
            status["wal_status"] = "diagnostic_only"
            status["port_statuses"][0]["reason"] = reason
            status["port_statuses"][0]["domains"][0]["reason"] = reason

            verdict, details = sync._snapshot_status_verdict(
                snapshot,
                set(scenario["request_context"]["projected_port_ids"]),
                status,
            )

            with self.subTest(label=label):
                self.assertEqual("classified_degraded", verdict, details)
                self.assertEqual("none", status["required_action"])

    def test_classified_degraded_full_resync_forces_newer_generation_independent_of_reason(self):
        scenario = status_scenario("classified-degraded-full-resync")
        status = copy.deepcopy(scenario["status"])
        status["wal_status"] = "diagnostic_only"
        status["port_statuses"][0]["reason"] = "unrelated diagnostic"
        status["port_statuses"][0]["domains"][0]["reason"] = (
            "unrelated diagnostic"
        )
        local_client = PublicV1ActionLocalClient(scenario, status=status)

        class SameGenerationUnlessForcedStateStore(InMemorySnapshotStateStore):
            def __init__(self, generation):
                InMemorySnapshotStateStore.__init__(self)
                self.generation = generation
                self.force_new_generation_requests = []

            def prepare_snapshot(
                self,
                snapshot,
                minimum_generation=0,
                force_new_generation=False,
            ):
                self.force_new_generation_requests.append(force_new_generation)
                generation = self.generation + 1 if force_new_generation else self.generation
                prepared = self.prepare_snapshot_at_generation(snapshot, generation)
                prepared["reused_pending"] = False
                return prepared

        state_store = SameGenerationUnlessForcedStateStore(
            status["last_classified_generation"]
        )
        sync = SnapshotSynchronizer(
            "ostack2",
            StaticPortSource([]),
            FakeOvsReader(),
            local_client,
            managed_domains=["acl"],
            state_store=state_store,
        )

        result = sync.safe_full_resync()

        self.assertEqual(["put_full_snapshot"], local_client.mutating_calls)
        self.assertGreater(
            result["snapshot"]["generation"],
            status["last_classified_generation"],
        )
        self.assertIn(True, state_store.force_new_generation_requests)

    def test_decoded_legacy_degraded_full_resync_forces_newer_generation(self):
        legacy_scenario = status_scenario("legacy-v0-ready")
        legacy_status = self._decoded_legacy_status(
            "runtime-degraded-baseline"
        )

        class SameGenerationUnlessForcedStateStore(InMemorySnapshotStateStore):
            def __init__(self, generation):
                InMemorySnapshotStateStore.__init__(self)
                self.generation = generation
                self.force_new_generation_requests = []

            def prepare_snapshot(
                self,
                snapshot,
                minimum_generation=0,
                force_new_generation=False,
            ):
                self.force_new_generation_requests.append(force_new_generation)
                generation = (
                    self.generation + 1
                    if force_new_generation else self.generation
                )
                prepared = self.prepare_snapshot_at_generation(
                    snapshot,
                    generation,
                )
                prepared["reused_pending"] = False
                return prepared

        local_client = PublicV1ActionLocalClient(
            legacy_scenario,
            status=legacy_status,
        )
        state_store = SameGenerationUnlessForcedStateStore(
            legacy_status["last_classified_generation"]
        )
        sync = SnapshotSynchronizer(
            "ostack2",
            StaticPortSource([]),
            FakeOvsReader(),
            local_client,
            managed_domains=["acl"],
            state_store=state_store,
        )

        result = sync.safe_full_resync()

        self.assertEqual(["put_full_snapshot"], local_client.mutating_calls)
        self.assertGreater(
            result["snapshot"]["generation"],
            legacy_status["last_classified_generation"],
        )
        self.assertIn(True, state_store.force_new_generation_requests)

    def test_rebuild_looking_reason_cannot_make_unsafe_port_status_classified(self):
        scenario = status_scenario("classified-degraded-terminal")
        snapshot = self._terminal_degraded_snapshot(scenario)
        sync = SnapshotSynchronizer(
            "ostack2",
            StaticPortSource([]),
            FakeOvsReader(),
            FakeLocalClient(),
            managed_domains=["acl"],
        )
        for port_status in ("blocked", "error", "recovered"):
            status = copy.deepcopy(scenario["status"])
            status["authority_state"] = "ready"
            status["port_statuses"][0]["status"] = port_status
            status["port_statuses"][0]["reason"] = "runtime_rebuild_required"
            status["port_statuses"][0]["domains"][0]["reason"] = (
                "runtime_rebuild_required"
            )

            verdict, details = sync._snapshot_status_verdict(
                snapshot,
                set(scenario["request_context"]["projected_port_ids"]),
                status,
            )

            with self.subTest(port_status=port_status):
                self.assertEqual("failed", verdict, details)

    def test_tombstones_are_diagnostic_only_and_cannot_replace_target_evidence(self):
        sync = SnapshotSynchronizer(
            "ostack2",
            StaticPortSource([]),
            FakeOvsReader(),
            FakeLocalClient(),
            managed_domains=["acl"],
        )
        v1_scenario = status_scenario("full-classified-ready")
        projected_port_ids = set(
            v1_scenario["request_context"]["projected_port_ids"]
        )
        v1_status = copy.deepcopy(v1_scenario["status"])
        tombstone = copy.deepcopy(v1_status["port_statuses"][0])
        tombstone.update({
            "port_id": "port-detached",
            "ifname": "tap-port-detached",
            "generation": v1_status["applied_generation"] - 1,
            "desired_hash": "hash-detached-history",
            "status": "detached",
            "reason": "port_removed",
        })
        for domain in tombstone["domains"]:
            domain.update({
                "status": "not_requested",
                "reason": "port_removed",
                "effective_action": "cleanup",
                "support_disposition": "not_applicable",
            })
        v1_status["port_statuses"].append(tombstone)

        verdict, details = sync._snapshot_status_verdict(
            v1_scenario["request_context"]["snapshot"],
            projected_port_ids,
            v1_status,
        )

        self.assertEqual("ready", verdict, details)

        self.assertEqual({"port-a"}, projected_port_ids)
        self.assertNotIn("port-detached", projected_port_ids)

        missing_target = copy.deepcopy(v1_status)
        missing_target["port_statuses"] = [tombstone]
        verdict, details = sync._snapshot_status_verdict(
            v1_scenario["request_context"]["snapshot"],
            projected_port_ids,
            missing_target,
        )
        self.assertEqual("failed", verdict)
        self.assertIn("port-a", details)

        legacy_scenario = status_scenario("legacy-v0-ready")
        legacy_status = copy.deepcopy(legacy_scenario["status"])
        raw_detached = copy.deepcopy(legacy_status["port_statuses"][0])
        raw_detached.update({
            "port_id": "legacy-detached",
            "ifname": "tap-legacy-detached",
            "generation": legacy_status["applied_generation"] - 1,
            "desired_hash": "legacy-hash-detached",
            "status": "detached",
            "reason": "port_removed",
        })
        for domain in raw_detached["domains"]:
            domain.update({
                "status": "detached",
                "reason": "port_removed",
                "effective_action": None,
            })
            domain.pop("support_disposition", None)
        legacy_status["port_statuses"].append(raw_detached)
        legacy_snapshot = {
            "generation": 40,
            "desired_hash": "legacy-hash-40",
            "ports": [{
                "port_id": "legacy-port",
                "ifname": "tap-legacy",
                "eligible": True,
                "managed_domains": ["acl"],
                "acl": {
                    "enabled": True,
                    "status": "ready",
                    "effective_action": "enforce",
                },
            }],
        }

        verdict, details = sync._snapshot_status_verdict(
            legacy_snapshot,
            set(legacy_scenario["request_context"]["projected_port_ids"]),
            legacy_status,
        )

        self.assertEqual("ready", verdict, details)

    def test_scoped_empty_projection_is_not_replaced_by_prior_classified_ids(self):
        for commit_method in (
            "commit_scoped_snapshot",
            "commit_classified_scoped_snapshot",
        ):
            state_store = InMemorySnapshotStateStore()
            baseline = state_store.prepare_snapshot_at_generation(
                {
                    "host": "ostack2",
                    "ports": [{
                        "port_id": "port-last",
                        "eligible": True,
                        "managed_domains": ["acl"],
                    }],
                },
                7,
                desired_hash="hash-ready-7",
            )
            state_store.commit_snapshot(
                baseline["generation"],
                baseline["desired_hash"],
            )
            scoped = state_store.prepare_scoped_snapshot({
                "host": "ostack2",
                "scope": {"type": "port", "port_id": "port-last"},
                "ports": [{
                    "port_id": "port-last",
                    "eligible": False,
                    "managed_domains": [],
                }],
            })

            getattr(state_store, commit_method)(
                scoped["generation"],
                scoped["desired_hash"],
            )

            with self.subTest(commit_method=commit_method):
                self.assertEqual(
                    [],
                    state_store.to_dict()[
                        "last_classified_projected_port_ids"
                    ],
                )

    def test_scoped_projection_failure_does_not_commit_or_clear_pending(self):
        scenario = status_scenario("scoped-classified-ready")
        state_store = InMemorySnapshotStateStore()
        baseline = state_store.prepare_snapshot_at_generation(
            {
                "host": "ostack2",
                "ports": [{
                    "port_id": "port-b",
                    "ifname": "tap-port-b",
                    "eligible": True,
                    "managed_domains": ["acl"],
                }],
            },
            42,
            desired_hash="hash-ready-42",
        )
        state_store.commit_snapshot(
            baseline["generation"],
            baseline["desired_hash"],
            feature_ready_domains=["acl"],
        )
        snapshot = copy.deepcopy(scenario["request_context"]["snapshot"])
        prepared = state_store.prepare_scoped_snapshot(snapshot)
        snapshot["generation"] = prepared["generation"]
        snapshot["desired_hash"] = prepared["desired_hash"]
        status = copy.deepcopy(scenario["status"])
        status.update({
            "last_classified_generation": prepared["generation"],
            "generation": prepared["generation"],
            "accepted_generation": prepared["generation"],
            "applied_generation": prepared["generation"],
            "desired_hash": prepared["desired_hash"],
            "applied_desired_hash": prepared["desired_hash"],
        })
        for row in status["port_statuses"]:
            if row["port_id"] == "port-a":
                row["generation"] = prepared["generation"]
                row["desired_hash"] = prepared["desired_hash"]

        class FailingPortSource(object):
            def list_ports_for_host(self):
                raise RuntimeError("neutron read failed")

        sync = SnapshotSynchronizer(
            "ostack2",
            FailingPortSource(),
            FakeOvsReader(),
            FakeLocalClient(),
            managed_domains=["acl"],
            state_store=state_store,
        )

        with self.assertRaises(RuntimeError):
            sync._finalize_snapshot_classification(
                snapshot,
                set(("port-a", "port-b")),
                status,
                {},
                scope="port",
                port_id="port-a",
            )

        durable = state_store.to_dict()
        self.assertEqual(42, durable["last_classified_generation"])
        self.assertEqual(["port-b"], durable["last_classified_projected_port_ids"])
        self.assertIsNotNone(state_store.pending_snapshot())
        self.assertEqual(set(("port-b",)), sync.projected_port_ids)

    def test_full_projection_failure_does_not_commit_or_clear_pending(self):
        scenario = status_scenario("full-classified-ready")
        state_store = self._state_store_with_projected_port(
            port_id="port-a",
            generation=41,
            desired_hash="hash-ready-41",
        )
        snapshot = copy.deepcopy(scenario["request_context"]["snapshot"])
        prepared = state_store.prepare_snapshot_at_generation(
            snapshot,
            scenario["request_context"]["expected_generation"],
            desired_hash=scenario["request_context"]["expected_desired_hash"],
        )
        snapshot["generation"] = prepared["generation"]
        snapshot["desired_hash"] = prepared["desired_hash"]
        sync = SnapshotSynchronizer(
            "ostack2",
            StaticPortSource([]),
            FakeOvsReader(),
            FakeLocalClient(),
            managed_domains=["acl"],
            state_store=state_store,
        )

        def fail_projection(*_args, **_kwargs):
            raise RuntimeError("full projection update failed")

        sync.projection_index.replace_from_resync = fail_projection

        with self.assertRaises(RuntimeError):
            sync._finalize_snapshot_classification(
                snapshot,
                set(("port-a",)),
                copy.deepcopy(scenario["status"]),
                {},
                scope="full_host",
                ports=[],
            )

        durable = state_store.to_dict()
        self.assertEqual(41, durable["last_classified_generation"])
        self.assertEqual(["port-a"], durable["last_classified_projected_port_ids"])
        pending = state_store.pending_snapshot()
        self.assertEqual(42, pending["generation"])
        self.assertEqual("hash-ready-42", pending["desired_hash"])
        self.assertEqual(set(("port-a",)), sync.projected_port_ids)

    def test_full_projection_failure_preserves_committed_projected_view(self):
        scenario = status_scenario("full-classified-ready")
        state_store = self._state_store_with_projected_port(
            port_id="port-old",
            generation=41,
            desired_hash="hash-ready-41",
        )
        snapshot = copy.deepcopy(scenario["request_context"]["snapshot"])
        prepared = state_store.prepare_snapshot_at_generation(
            snapshot,
            scenario["request_context"]["expected_generation"],
            desired_hash=scenario["request_context"]["expected_desired_hash"],
        )
        snapshot["generation"] = prepared["generation"]
        snapshot["desired_hash"] = prepared["desired_hash"]
        sync = SnapshotSynchronizer(
            "ostack2",
            StaticPortSource([]),
            FakeOvsReader(),
            FakeLocalClient(),
            managed_domains=["acl"],
            state_store=state_store,
        )
        committed_projected_port_ids = set(sync.projected_port_ids)
        next_projected_port_ids = set(("port-a",))
        self.assertNotEqual(
            committed_projected_port_ids,
            next_projected_port_ids,
        )

        def fail_projection(*_args, **_kwargs):
            raise RuntimeError("full projection update failed")

        sync.projection_index.replace_from_resync = fail_projection

        with self.assertRaises(RuntimeError):
            sync._finalize_snapshot_classification(
                snapshot,
                next_projected_port_ids,
                copy.deepcopy(scenario["status"]),
                {},
                scope="full_host",
                ports=[],
            )

        durable = state_store.to_dict()
        self.assertEqual(41, durable["last_classified_generation"])
        self.assertEqual(
            ["port-old"],
            durable["last_classified_projected_port_ids"],
        )
        pending = state_store.pending_snapshot()
        self.assertEqual(42, pending["generation"])
        self.assertEqual("hash-ready-42", pending["desired_hash"])
        self.assertEqual(
            committed_projected_port_ids,
            sync.projected_port_ids,
        )
        self.assertTrue(sync.has_projected_port("port-old"))
        self.assertFalse(sync.has_projected_port("port-a"))

    def test_direct_delete_projection_failure_preserves_committed_view(self):
        port_id = "port-direct-delete"
        state_store = self._state_store_with_projected_port(
            port_id=port_id,
            generation=41,
            desired_hash="hash-ready-41",
        )
        local_client = FakeLocalClient()
        sync = SnapshotSynchronizer(
            "ostack2",
            StaticPortSource([]),
            FakeOvsReader(),
            local_client,
            managed_domains=["acl"],
            state_store=state_store,
        )
        committed_projected_port_ids = set(sync.projected_port_ids)

        def fail_remove(*_args, **_kwargs):
            raise RuntimeError("delete projection removal failed")

        sync.projection_index.remove = fail_remove

        with self.assertRaises(RuntimeError):
            sync.delete_port(port_id, reason="atomicity-test")

        self.assertEqual([port_id], local_client.deleted_ports)
        pending_delete = state_store.pending_delete()
        self.assertEqual(port_id, pending_delete["port_id"])
        self.assertEqual("atomicity-test", pending_delete["reason"])
        durable = state_store.to_dict()
        self.assertEqual(41, durable["last_classified_generation"])
        self.assertEqual(
            [port_id],
            durable["last_classified_projected_port_ids"],
        )
        self.assertEqual(None, durable["last_deleted_port_id"])
        self.assertEqual(
            committed_projected_port_ids,
            sync.projected_port_ids,
        )
        self.assertTrue(sync.has_projected_port(port_id))

    def test_restart_delete_projection_failure_preserves_committed_view(self):
        port_id = "port-restart-delete"
        state_store = self._state_store_with_projected_port(
            port_id=port_id,
            generation=41,
            desired_hash="hash-ready-41",
        )
        state_store.prepare_delete(port_id, reason="restart-atomicity-test")
        pending_before = copy.deepcopy(state_store.pending_delete())
        local_client = FixedStatusLocalClient({
            "generation": 41,
            "managed_ports": [],
            "active_instances": [],
        })
        sync = SnapshotSynchronizer(
            "ostack2",
            StaticPortSource([]),
            FakeOvsReader(),
            local_client,
            managed_domains=["acl"],
            state_store=state_store,
        )
        committed_projected_port_ids = set(sync.projected_port_ids)

        def fail_remove(*_args, **_kwargs):
            raise RuntimeError("restart projection removal failed")

        sync.projection_index.remove = fail_remove

        with self.assertRaises(RuntimeError):
            sync.recover_pending_state()

        self.assertEqual(pending_before, state_store.pending_delete())
        durable = state_store.to_dict()
        self.assertEqual(41, durable["last_classified_generation"])
        self.assertEqual(
            [port_id],
            durable["last_classified_projected_port_ids"],
        )
        self.assertEqual(None, durable["last_deleted_port_id"])
        self.assertEqual(
            committed_projected_port_ids,
            sync.projected_port_ids,
        )
        self.assertTrue(sync.has_projected_port(port_id))

    def test_malformed_status_is_not_swallowed_before_snapshot_submit(self):
        from neutron_aria.agent.uds_client import LocalClient

        scenario = status_scenario("full-classified-ready")

        class Response(object):
            def __init__(self, body):
                self.status = 200
                self.reason = "OK"
                self.body = body

            def read(self, _size):
                if isinstance(self.body, str):
                    return self.body
                return json.dumps(self.body)

        class Connection(object):
            requests = []
            responses = [
                Response(copy.deepcopy(scenario["capabilities"])),
                Response("{bad-json"),
            ]

            def __init__(self, _socket_path, _timeout):
                pass

            def request(self, method, path, body=None, headers=None):
                self.requests.append({
                    "method": method,
                    "path": path,
                    "body": body,
                    "headers": headers or {},
                })

            def getresponse(self):
                return self.responses.pop(0)

            def close(self):
                pass

        local_client = LocalClient(
            "/tmp/aria-agent.sock",
            timeout=1.0,
            connection_factory=Connection,
        )
        sync = SnapshotSynchronizer(
            "ostack2",
            self._target_port_source(),
            FakeOvsReader(),
            local_client,
            managed_domains=["acl"],
            acl_index=self._terminal_degraded_acl_index(),
        )

        result = sync.safe_full_resync()

        self.assertEqual(
            [],
            [
                request for request in Connection.requests
                if request["method"] in ("PUT", "POST", "DELETE")
            ],
        )
        self.assertEqual(
            "local_api_contract_error",
            result["status"]["reason"],
        )

    def test_decoded_legacy_operator_status_never_uses_raw_recovery_fallback(self):
        scenario = status_scenario("blocked-operator")
        decoded_legacy = copy.deepcopy(scenario["status"])
        decoded_legacy.pop("status_schema_version", None)
        decoded_legacy.pop("status_contract_hash", None)
        local_client = PublicV1ActionLocalClient(
            scenario,
            status=decoded_legacy,
        )
        sync = SnapshotSynchronizer(
            "ostack2",
            StaticPortSource([]),
            FakeOvsReader(),
            local_client,
            managed_domains=["acl"],
            timeout_convergence_attempts=1,
            timeout_convergence_interval=0,
        )

        result = sync.safe_full_resync()

        self.assertTrue(result["status"]["degraded"])
        self.assertEqual([], local_client.mutating_calls)
        self.assertEqual([], local_client.recoveries)
        self.assertEqual([], local_client.snapshots)

    def test_decoded_legacy_operator_cannot_clear_local_pending_as_stale(self):
        state_store = InMemorySnapshotStateStore()
        state_store.prepare_snapshot_at_generation(
            {"host": "ostack2", "ports": []},
            42,
            desired_hash="hash-local-42",
        )
        pending_before = copy.deepcopy(state_store.pending_snapshot())
        decoded_legacy = self._decoded_legacy_status()
        decoded_legacy.update({
            "generation": 43,
            "accepted_generation": 43,
            "applied_generation": 43,
            "pending_generation": None,
            "desired_hash": "hash-remote-43",
            "applied_desired_hash": "hash-remote-43",
            "authority_state": "blocked",
            "transaction_state": "blocked",
            "overall_readiness": "blocked",
            "required_action": "operator",
            "last_classified_generation": 43,
        })
        local_client = PublicV1ActionLocalClient(
            status_scenario("legacy-v0-ready"),
            status=decoded_legacy,
        )
        sync = SnapshotSynchronizer(
            "ostack2",
            StaticPortSource([]),
            FakeOvsReader(),
            local_client,
            managed_domains=["acl"],
            state_store=state_store,
        )

        with self.assertRaises(LocalApiError):
            sync.recover_pending_state()

        self.assertEqual(pending_before, state_store.pending_snapshot())
        self.assertEqual([], local_client.mutating_calls)

    def test_decoded_legacy_operator_cannot_finalize_exact_pending_on_restart(self):
        state_store = InMemorySnapshotStateStore()
        state_store.prepare_snapshot_at_generation(
            {
                "host": "ostack2",
                "ports": [{
                    "port_id": "legacy-port",
                    "ifname": "tap-legacy",
                    "eligible": True,
                    "managed_domains": ["acl"],
                }],
            },
            40,
            desired_hash="legacy-hash-40",
        )
        pending_before = copy.deepcopy(state_store.pending_snapshot())
        raw_legacy = copy.deepcopy(
            status_scenario("legacy-v0-ready")["status"]
        )
        raw_legacy.update({
            "wal_replay_failures": 1,
            "managed_ports": [],
            "port_statuses": [],
            "active_instances": [],
        })
        decoded_legacy = _decode_legacy_status_v0(raw_legacy)
        self.assertEqual(
            ("blocked", "blocked", "operator"),
            (
                decoded_legacy["transaction_state"],
                decoded_legacy["overall_readiness"],
                decoded_legacy["required_action"],
            ),
        )
        local_client = PublicV1ActionLocalClient(
            status_scenario("legacy-v0-ready"),
            status=decoded_legacy,
        )
        sync = SnapshotSynchronizer(
            "ostack2",
            StaticPortSource([]),
            FakeOvsReader(),
            local_client,
            managed_domains=["acl"],
            state_store=state_store,
        )

        recovered = sync.recover_pending_state()

        self.assertEqual([], recovered["recovered"])
        self.assertEqual(pending_before, state_store.pending_snapshot())
        self.assertEqual([], local_client.mutating_calls)

    def test_scoped_detach_requires_remote_target_to_leave_managed_evidence(self):
        scenario = status_scenario("scoped-classified-ready")
        snapshot = copy.deepcopy(scenario["request_context"]["snapshot"])
        snapshot["ports"][0]["eligible"] = False
        snapshot["ports"][0]["managed_domains"] = []
        status = copy.deepcopy(scenario["status"])
        status["managed_ports"] = [
            row for row in status["managed_ports"]
            if row["port_id"] == "port-a"
        ]
        status["port_statuses"] = [
            row for row in status["port_statuses"]
            if row["port_id"] == "port-a"
        ]
        sync = SnapshotSynchronizer(
            "ostack2",
            StaticPortSource([]),
            FakeOvsReader(),
            FakeLocalClient(),
            managed_domains=["acl"],
        )

        verdict, details = sync._snapshot_status_verdict(
            snapshot,
            set(),
            status,
        )

        self.assertEqual("failed", verdict, details)
        self.assertIn("port-a", details)

        status["managed_ports"] = []
        tombstone = status["port_statuses"][0]
        tombstone["status"] = "detached"
        for domain in tombstone["domains"]:
            domain.update({
                "status": "not_requested",
                "effective_action": "cleanup",
                "support_disposition": "not_applicable",
            })

        verdict, details = sync._snapshot_status_verdict(
            snapshot,
            set(),
            status,
        )

        self.assertEqual("ready", verdict, details)

    def test_scoped_detach_accepts_absence_and_rejects_active_orphan(self):
        scenario = status_scenario("scoped-classified-ready")
        snapshot = copy.deepcopy(scenario["request_context"]["snapshot"])
        snapshot["ports"][0]["eligible"] = False
        snapshot["ports"][0]["managed_domains"] = []
        base_status = copy.deepcopy(scenario["status"])
        base_status["managed_ports"] = [
            row for row in base_status["managed_ports"]
            if row["port_id"] != "port-a"
        ]
        sync = SnapshotSynchronizer(
            "ostack2",
            StaticPortSource([]),
            FakeOvsReader(),
            FakeLocalClient(),
            managed_domains=["acl"],
        )

        absent = copy.deepcopy(base_status)
        absent["port_statuses"] = [
            row for row in absent["port_statuses"]
            if row["port_id"] != "port-a"
        ]
        verdict, reason = sync._snapshot_status_verdict(
            snapshot,
            set(("port-b",)),
            absent,
        )
        self.assertEqual("ready", verdict, reason)

        active_orphan = copy.deepcopy(base_status)
        verdict, reason = sync._snapshot_status_verdict(
            snapshot,
            set(("port-b",)),
            active_orphan,
        )
        self.assertEqual("failed", verdict, reason)
        self.assertIn("port-a", reason)

    def test_v1_operator_cannot_clear_local_pending_as_stale(self):
        state_store = InMemorySnapshotStateStore()
        state_store.prepare_snapshot_at_generation(
            {"host": "ostack2", "ports": []},
            42,
            desired_hash="hash-local-42",
        )
        scenario = status_scenario("blocked-operator")
        status = copy.deepcopy(scenario["status"])
        status.update({
            "last_classified_generation": 43,
            "generation": 43,
            "accepted_generation": 43,
            "applied_generation": 43,
            "pending_generation": None,
            "desired_hash": "hash-remote-43",
            "applied_desired_hash": "hash-remote-43",
            "managed_ports": [],
            "port_statuses": [],
            "active_instances": [],
        })

        class FixedOperatorClient(FakeLocalClient):
            def status(self):
                return copy.deepcopy(status)

        sync = SnapshotSynchronizer(
            "ostack2",
            StaticPortSource([]),
            FakeOvsReader(),
            FixedOperatorClient(),
            managed_domains=["acl"],
            state_store=state_store,
        )

        with self.assertRaises(LocalApiError):
            sync.recover_pending_state()

        pending = state_store.pending_snapshot()
        self.assertEqual(42, pending["generation"])
        self.assertEqual("hash-local-42", pending["desired_hash"])

    def test_v1_stale_pending_cleanup_requires_safe_terminal_control(self):
        full_resync = copy.deepcopy(
            status_scenario("classified-degraded-full-resync")["status"]
        )
        recovery = copy.deepcopy(
            status_scenario("recovery-full-resync")["status"]
        )
        for status in (full_resync, recovery):
            status.update({
                "last_classified_generation": 43,
                "generation": 43,
                "accepted_generation": 43,
                "applied_generation": 43,
                "pending_generation": None,
                "desired_hash": "hash-remote-43",
                "applied_desired_hash": "hash-remote-43",
            })
            for row in status.get("port_statuses") or []:
                row["generation"] = 43
                row["desired_hash"] = "hash-remote-43"

        unsafe_statuses = [
            copy.deepcopy(status_scenario("pending-poll")["status"]),
            copy.deepcopy(
                status_scenario("blocked-recoverable-inventory")["status"]
            ),
            full_resync,
            recovery,
        ]
        for status in unsafe_statuses:
            state_store = InMemorySnapshotStateStore()
            state_store.prepare_snapshot_at_generation(
                {"host": "ostack2", "ports": []},
                42,
                desired_hash="hash-local-42",
            )
            local_client = PublicV1ActionLocalClient(
                status_scenario("blocked-operator"),
                status=status,
            )
            sync = SnapshotSynchronizer(
                "ostack2",
                StaticPortSource([]),
                FakeOvsReader(),
                local_client,
                managed_domains=["acl"],
                state_store=state_store,
            )
            try:
                sync.recover_pending_state()
            except LocalApiError:
                pass
            pending = state_store.pending_snapshot()
            with self.subTest(control=status["required_action"]):
                self.assertIsNotNone(pending)
                self.assertEqual(42, pending["generation"])
                self.assertEqual("hash-local-42", pending["desired_hash"])

        safe_statuses = [
            copy.deepcopy(status_scenario("full-classified-ready")["status"]),
            copy.deepcopy(
                status_scenario("classified-degraded-terminal")["status"]
            ),
        ]
        for status in safe_statuses:
            state_store = InMemorySnapshotStateStore()
            state_store.prepare_snapshot_at_generation(
                {"host": "ostack2", "ports": []},
                1,
                desired_hash="hash-local-1",
            )
            local_client = PublicV1ActionLocalClient(
                status_scenario("blocked-operator"),
                status=status,
            )
            sync = SnapshotSynchronizer(
                "ostack2",
                StaticPortSource([]),
                FakeOvsReader(),
                local_client,
                managed_domains=["acl"],
                state_store=state_store,
            )

            sync.recover_pending_state()

            with self.subTest(safe_control=status["overall_readiness"]):
                self.assertEqual(None, state_store.pending_snapshot())

    def test_restart_accepts_bounded_historical_scoped_rows_without_write(self):
        scenario = status_scenario("scoped-classified-ready")
        state_store = InMemorySnapshotStateStore()
        baseline = state_store.prepare_snapshot_at_generation(
            {
                "host": "ostack2",
                "ports": [{
                    "port_id": "port-b",
                    "ifname": "tap-port-b",
                    "eligible": True,
                    "managed_domains": ["acl"],
                }],
            },
            42,
            desired_hash="hash-ready-42",
        )
        state_store.commit_snapshot(
            baseline["generation"],
            baseline["desired_hash"],
            snapshot_ports=1,
            managed_ports=1,
            feature_ready_domains=["acl"],
        )
        scoped = state_store.prepare_scoped_snapshot(
            copy.deepcopy(scenario["request_context"]["snapshot"]),
            minimum_generation=42,
        )
        self.assertEqual(
            scenario["request_context"]["expected_generation"],
            scoped["generation"],
        )
        status = copy.deepcopy(scenario["status"])
        status.update({
            "desired_hash": scoped["desired_hash"],
            "applied_desired_hash": scoped["desired_hash"],
        })
        affected = next(
            row for row in status["port_statuses"]
            if row["port_id"] == "port-a"
        )
        affected["desired_hash"] = scoped["desired_hash"]
        local_client = PublicV1ActionLocalClient(scenario, status=status)
        sync = SnapshotSynchronizer(
            "ostack2",
            StaticPortSource([]),
            FakeOvsReader(),
            local_client,
            managed_domains=["acl"],
            state_store=state_store,
        )

        result = sync.recover_pending_state()

        self.assertEqual(["snapshot"], result["recovered"])
        self.assertEqual(None, state_store.pending_snapshot())
        self.assertEqual(
            scenario["request_context"]["expected_generation"],
            state_store.to_dict()["last_classified_generation"],
        )
        self.assertEqual(
            set(("port-a", "port-b")),
            sync.projected_port_ids,
        )
        self.assertEqual([], local_client.mutating_calls)

    def test_restart_rejects_historical_identity_for_scoped_affected_port(self):
        scenario = status_scenario("scoped-classified-ready")
        state_store = self._state_store_with_projected_port(
            port_id="port-b",
            generation=42,
            desired_hash="hash-ready-42",
        )
        scoped = state_store.prepare_scoped_snapshot(
            copy.deepcopy(scenario["request_context"]["snapshot"]),
            minimum_generation=42,
        )
        stale_status = copy.deepcopy(scenario["status"])
        stale_status.update({
            "desired_hash": scoped["desired_hash"],
            "applied_desired_hash": scoped["desired_hash"],
        })
        affected = next(
            row for row in stale_status["port_statuses"]
            if row["port_id"] == "port-a"
        )
        affected["generation"] = 42
        affected["desired_hash"] = "hash-ready-42"
        pending_before = copy.deepcopy(state_store.pending_snapshot())
        feature_ready_before = copy.deepcopy(state_store.feature_ready_history())
        local_client = PublicV1ActionLocalClient(
            scenario,
            status=stale_status,
        )
        sync = SnapshotSynchronizer(
            "ostack2",
            StaticPortSource([]),
            FakeOvsReader(),
            local_client,
            managed_domains=["acl"],
            state_store=state_store,
        )

        result = sync.recover_pending_state()

        self.assertEqual([], result["recovered"])
        self.assertEqual(pending_before, state_store.pending_snapshot())
        self.assertEqual(feature_ready_before, state_store.feature_ready_history())
        self.assertFalse(sync.runtime_status.ready)
        self.assertEqual([], local_client.mutating_calls)

    def test_restart_scoped_removal_accepts_absent_target_tombstone(self):
        scenario = status_scenario("scoped-classified-ready")
        state_store = InMemorySnapshotStateStore()
        baseline = state_store.prepare_snapshot_at_generation(
            {
                "host": "ostack2",
                "ports": [{
                    "port_id": port_id,
                    "ifname": "tap-%s" % port_id,
                    "eligible": True,
                    "managed_domains": ["acl"],
                } for port_id in ("port-a", "port-b")],
            },
            42,
            desired_hash="hash-ready-42",
        )
        state_store.commit_snapshot(
            baseline["generation"],
            baseline["desired_hash"],
            snapshot_ports=2,
            managed_ports=2,
            feature_ready_domains=["acl"],
        )
        scoped = state_store.prepare_scoped_snapshot({
            "host": "ostack2",
            "scope": {"type": "port", "port_id": "port-a"},
            "ports": [{
                "port_id": "port-a",
                "ifname": "tap-port-a",
                "eligible": False,
                "managed_domains": [],
            }],
        })
        status = copy.deepcopy(scenario["status"])
        status.update({
            "desired_hash": scoped["desired_hash"],
            "applied_desired_hash": scoped["desired_hash"],
            "managed_ports": [
                row for row in status["managed_ports"]
                if row["port_id"] == "port-b"
            ],
            "port_statuses": [
                row for row in status["port_statuses"]
                if row["port_id"] == "port-b"
            ],
            "active_instances": ["tap-port-b"],
        })
        local_client = PublicV1ActionLocalClient(scenario, status=status)
        sync = SnapshotSynchronizer(
            "ostack2",
            StaticPortSource([]),
            FakeOvsReader(),
            local_client,
            managed_domains=["acl"],
            state_store=state_store,
        )

        result = sync.recover_pending_state()

        self.assertEqual(["snapshot"], result["recovered"])
        self.assertEqual(None, state_store.pending_snapshot())
        self.assertEqual(set(("port-b",)), sync.projected_port_ids)
        self.assertEqual([], local_client.mutating_calls)

    def test_restart_rejects_historical_identity_for_full_host_port(self):
        scenario = status_scenario("scoped-classified-ready")
        state_store = InMemorySnapshotStateStore()
        full_snapshot = copy.deepcopy(scenario["request_context"]["snapshot"])
        full_snapshot.pop("scope", None)
        full_snapshot["ports"].append({
            "port_id": "port-b",
            "ifname": "tap-port-b",
            "eligible": True,
            "managed_domains": ["acl"],
            "acl": {
                "enabled": True,
                "status": "ready",
                "effective_action": "enforce",
            },
        })
        state_store.prepare_snapshot_at_generation(
            full_snapshot,
            scenario["request_context"]["expected_generation"],
            desired_hash=scenario["request_context"]["expected_desired_hash"],
        )
        pending_before = copy.deepcopy(state_store.pending_snapshot())
        local_client = PublicV1ActionLocalClient(scenario)
        sync = SnapshotSynchronizer(
            "ostack2",
            StaticPortSource([]),
            FakeOvsReader(),
            local_client,
            managed_domains=["acl"],
            state_store=state_store,
        )

        result = sync.recover_pending_state()

        self.assertEqual([], result["recovered"])
        self.assertEqual(pending_before, state_store.pending_snapshot())
        self.assertFalse(sync.runtime_status.ready)
        self.assertEqual([], local_client.mutating_calls)

    def test_restart_full_host_rejects_historical_extra_managed_port(self):
        scenario = status_scenario("scoped-classified-ready")
        state_store = InMemorySnapshotStateStore()
        baseline = state_store.prepare_snapshot_at_generation(
            {
                "host": "ostack2",
                "ports": [{
                    "port_id": "port-b",
                    "ifname": "tap-port-b",
                    "eligible": True,
                    "managed_domains": ["acl"],
                }],
            },
            42,
            desired_hash="hash-ready-42",
        )
        state_store.commit_snapshot(
            baseline["generation"],
            baseline["desired_hash"],
            snapshot_ports=1,
            managed_ports=1,
            feature_ready_domains=["acl"],
        )
        state_store.prepare_snapshot_at_generation(
            copy.deepcopy(scenario["request_context"]["snapshot"]),
            scenario["request_context"]["expected_generation"],
            desired_hash=scenario["request_context"]["expected_desired_hash"],
        )
        pending_before = copy.deepcopy(state_store.pending_snapshot())
        feature_ready_before = copy.deepcopy(state_store.feature_ready_history())
        local_client = PublicV1ActionLocalClient(scenario)
        sync = SnapshotSynchronizer(
            "ostack2",
            StaticPortSource([]),
            FakeOvsReader(),
            local_client,
            managed_domains=["acl"],
            state_store=state_store,
        )

        result = sync.recover_pending_state()

        self.assertEqual([], result["recovered"])
        self.assertEqual(pending_before, state_store.pending_snapshot())
        self.assertEqual(feature_ready_before, state_store.feature_ready_history())
        self.assertFalse(sync.runtime_status.ready)
        self.assertEqual([], local_client.mutating_calls)

    def test_restart_legacy_pending_without_scope_metadata_fails_closed(self):
        scenario = status_scenario("full-classified-ready")
        state_store = InMemorySnapshotStateStore()
        state_store.prepare_snapshot_at_generation(
            copy.deepcopy(scenario["request_context"]["snapshot"]),
            scenario["request_context"]["expected_generation"],
            desired_hash=scenario["request_context"]["expected_desired_hash"],
        )
        state_store._state.pop("pending_scope", None)
        state_store._state.pop("pending_affected_port_ids", None)
        pending_before = copy.deepcopy(state_store.pending_snapshot())
        feature_ready_before = copy.deepcopy(state_store.feature_ready_history())
        local_client = PublicV1ActionLocalClient(scenario)
        sync = SnapshotSynchronizer(
            "ostack2",
            StaticPortSource([]),
            FakeOvsReader(),
            local_client,
            managed_domains=["acl"],
            state_store=state_store,
        )

        with self.assertRaises(LocalApiError):
            sync.recover_pending_state()

        self.assertEqual(pending_before, state_store.pending_snapshot())
        self.assertEqual(feature_ready_before, state_store.feature_ready_history())
        self.assertFalse(sync.runtime_status.ready)
        self.assertEqual([], local_client.mutating_calls)

    def test_full_resync_legacy_pending_without_metadata_makes_no_mutation(self):
        scenario = status_scenario("full-classified-ready")
        state_store = InMemorySnapshotStateStore()
        state_store.prepare_snapshot_at_generation(
            copy.deepcopy(scenario["request_context"]["snapshot"]),
            scenario["request_context"]["expected_generation"],
            desired_hash=scenario["request_context"]["expected_desired_hash"],
        )
        state_store._state.pop("pending_scope", None)
        state_store._state.pop("pending_affected_port_ids", None)
        pending_before = copy.deepcopy(state_store.pending_snapshot())
        feature_ready_before = copy.deepcopy(state_store.feature_ready_history())
        local_client = PublicV1ActionLocalClient(scenario)
        sync = SnapshotSynchronizer(
            "ostack2",
            StaticPortSource([]),
            FakeOvsReader(),
            local_client,
            managed_domains=["acl"],
            state_store=state_store,
        )

        with self.assertRaises(LocalApiError):
            sync.full_resync()

        self.assertEqual([], local_client.mutating_calls)
        self.assertEqual([], local_client.snapshots)
        self.assertEqual(pending_before, state_store.pending_snapshot())
        self.assertEqual(feature_ready_before, state_store.feature_ready_history())
        self.assertFalse(sync.runtime_status.ready)

    def test_safe_full_resync_legacy_pending_without_metadata_preserves_reason(self):
        scenario = status_scenario("full-classified-ready")
        state_store = InMemorySnapshotStateStore()
        state_store.prepare_snapshot_at_generation(
            copy.deepcopy(scenario["request_context"]["snapshot"]),
            scenario["request_context"]["expected_generation"],
            desired_hash=scenario["request_context"]["expected_desired_hash"],
        )
        state_store._state.pop("pending_scope", None)
        state_store._state.pop("pending_affected_port_ids", None)
        pending_before = copy.deepcopy(state_store.pending_snapshot())
        local_client = PublicV1ActionLocalClient(scenario)
        sync = SnapshotSynchronizer(
            "ostack2",
            StaticPortSource([]),
            FakeOvsReader(),
            local_client,
            managed_domains=["acl"],
            state_store=state_store,
        )

        result = sync.safe_full_resync()

        self.assertEqual([], local_client.mutating_calls)
        self.assertEqual([], local_client.snapshots)
        self.assertEqual(pending_before, state_store.pending_snapshot())
        self.assertEqual(
            "pending_snapshot_metadata_invalid",
            result["status"]["reason"],
        )
        self.assertEqual(
            "pending_snapshot_metadata_invalid",
            sync.runtime_status.reason,
        )
        self.assertEqual(
            "pending snapshot scope metadata is missing or invalid",
            result["status"]["last_error"],
        )
        self.assertEqual(
            result["status"]["last_error"],
            sync.runtime_status.last_error,
        )

    def test_restart_legacy_pending_metadata_cannot_be_cleared_as_stale(self):
        scenario = status_scenario("full-classified-ready")
        state_store = InMemorySnapshotStateStore()
        state_store.prepare_snapshot_at_generation(
            {"host": "ostack2", "ports": []},
            42,
            desired_hash="hash-local-42",
        )
        state_store._state.pop("pending_scope", None)
        state_store._state.pop("pending_affected_port_ids", None)
        pending_before = copy.deepcopy(state_store.pending_snapshot())
        advanced_status = copy.deepcopy(scenario["status"])
        advanced_status.update({
            "last_classified_generation": 43,
            "generation": 43,
            "accepted_generation": 43,
            "applied_generation": 43,
            "desired_hash": "hash-remote-43",
            "applied_desired_hash": "hash-remote-43",
            "managed_ports": [],
            "port_statuses": [],
            "active_instances": [],
        })
        local_client = PublicV1ActionLocalClient(
            scenario,
            status=advanced_status,
        )
        sync = SnapshotSynchronizer(
            "ostack2",
            StaticPortSource([]),
            FakeOvsReader(),
            local_client,
            managed_domains=["acl"],
            state_store=state_store,
        )

        with self.assertRaises(LocalApiError):
            sync.recover_pending_state()

        self.assertEqual(pending_before, state_store.pending_snapshot())
        self.assertFalse(sync.runtime_status.ready)
        self.assertEqual([], local_client.mutating_calls)

    def test_full_host_pre_submit_status_failure_makes_no_mutation(self):
        scenario = status_scenario("full-classified-ready")
        state_store = InMemorySnapshotStateStore()
        pending_before = copy.deepcopy(state_store.pending_snapshot())
        local_client = PreSubmitStatusUnavailableLocalClient(scenario)
        sync = SnapshotSynchronizer(
            "ostack2",
            StaticPortSource([]),
            FakeOvsReader(),
            local_client,
            managed_domains=["acl"],
            state_store=state_store,
        )

        error = None
        try:
            sync.full_resync()
        except LocalApiError as exc:
            error = exc

        self.assertIsInstance(error, LocalApiTimeoutError)
        self.assertEqual([], local_client.mutating_calls)
        self.assertEqual([], local_client.snapshots)
        self.assertEqual(pending_before, state_store.pending_snapshot())

    def test_scoped_pre_submit_status_failure_makes_no_mutation(self):
        target_port = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
        scenario = status_scenario("full-classified-ready")
        state_store = self._state_store_with_projected_port(target_port)
        pending_before = copy.deepcopy(state_store.pending_snapshot())
        projected_before = set(state_store.last_projected_port_ids())
        local_client = PreSubmitStatusUnavailableLocalClient(scenario)
        sync = SnapshotSynchronizer(
            "ostack2",
            self._target_port_source(),
            FakeOvsReader(),
            local_client,
            managed_domains=["acl"],
            state_store=state_store,
            acl_index=self._terminal_degraded_acl_index(),
        )

        error = None
        try:
            sync.apply_port_scoped_snapshot(
                target_port,
                binding_host="ostack2",
                revision_number=8,
                allow_revisionless=True,
            )
        except LocalApiError as exc:
            error = exc

        self.assertIsInstance(error, LocalApiTimeoutError)
        self.assertEqual([], local_client.mutating_calls)
        self.assertEqual([], local_client.port_snapshots)
        self.assertEqual(pending_before, state_store.pending_snapshot())
        self.assertEqual(projected_before, sync.projected_port_ids)

    def test_delete_pre_submit_status_failure_makes_no_mutation(self):
        target_port = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
        scenario = status_scenario("full-classified-ready")
        state_store = self._state_store_with_projected_port(target_port)
        pending_before = copy.deepcopy(state_store.pending_delete())
        projected_before = set(state_store.last_projected_port_ids())
        local_client = PreSubmitStatusUnavailableLocalClient(scenario)
        sync = SnapshotSynchronizer(
            "ostack2",
            StaticPortSource([]),
            FakeOvsReader(),
            local_client,
            managed_domains=["acl"],
            state_store=state_store,
        )

        with self.assertRaises(LocalApiTimeoutError):
            sync.delete_port(target_port, reason="status-unavailable")

        self.assertEqual([], local_client.mutating_calls)
        self.assertEqual([], local_client.deleted_ports)
        self.assertEqual(pending_before, state_store.pending_delete())
        self.assertEqual(projected_before, sync.projected_port_ids)

    def test_pre_submit_action_gate_rejects_missing_status_defensively(self):
        sync = SnapshotSynchronizer(
            "ostack2",
            StaticPortSource([]),
            FakeOvsReader(),
            FakeLocalClient(),
            managed_domains=["acl"],
        )

        with self.assertRaises(LocalApiError):
            sync._pre_submit_action_gate("snapshot", {}, None, None)

    def test_full_host_pre_submit_none_status_makes_no_mutation(self):
        scenario = status_scenario("full-classified-ready")
        state_store = InMemorySnapshotStateStore()
        pending_before = copy.deepcopy(state_store.pending_snapshot())
        local_client = PreSubmitNoneStatusLocalClient(scenario)
        sync = SnapshotSynchronizer(
            "ostack2",
            StaticPortSource([]),
            FakeOvsReader(),
            local_client,
            managed_domains=["acl"],
            state_store=state_store,
        )

        error = None
        try:
            sync.full_resync()
        except Exception as exc:
            error = exc

        self.assertEqual([], local_client.mutating_calls)
        self.assertEqual([], local_client.snapshots)
        self.assertEqual(pending_before, state_store.pending_snapshot())
        self.assertIsInstance(error, LocalApiError)

    def test_full_host_post_recovery_status_failure_prevents_new_write(self):
        scenario = status_scenario("blocked-recoverable-inventory")
        state_store = InMemorySnapshotStateStore()
        state_store.prepare_snapshot_at_generation(
            {"host": "ostack2", "ports": []},
            scenario["request_context"]["expected_pending_generation"],
            desired_hash=scenario["request_context"]["expected_desired_hash"],
        )
        pending_before = copy.deepcopy(state_store.pending_snapshot())
        local_client = PostRecoveryStatusUnavailableLocalClient(scenario)
        sync = SnapshotSynchronizer(
            "ostack2",
            StaticPortSource([]),
            FakeOvsReader(),
            local_client,
            managed_domains=["acl"],
            state_store=state_store,
        )

        error = None
        try:
            sync.full_resync()
        except LocalApiError as exc:
            error = exc

        self.assertIsInstance(error, LocalApiTimeoutError)
        self.assertIn("post-recovery status unavailable", str(error))
        self.assertEqual(["recover_pending"], local_client.mutating_calls)
        self.assertEqual([], local_client.snapshots)
        self.assertEqual(pending_before, state_store.pending_snapshot())

    def test_event_target_rejects_whitespace_padded_historical_hash(self):
        scenario = status_scenario("scoped-classified-ready")
        sync = SnapshotSynchronizer(
            "ostack2",
            StaticPortSource([]),
            FakeOvsReader(),
            FakeLocalClient(),
            managed_domains=["acl"],
        )
        positive_status = copy.deepcopy(scenario["status"])
        positive_verdict, positive_reason = sync._snapshot_status_verdict(
            scenario["request_context"]["snapshot"],
            set(scenario["request_context"]["projected_port_ids"]),
            positive_status,
        )
        self.assertEqual("ready", positive_verdict, positive_reason)

        padded_status = copy.deepcopy(scenario["status"])
        historical = next(
            row for row in padded_status["port_statuses"]
            if row["generation"] < padded_status["applied_generation"]
        )
        historical["desired_hash"] = " %s " % historical["desired_hash"]

        verdict, reason = sync._snapshot_status_verdict(
            scenario["request_context"]["snapshot"],
            set(scenario["request_context"]["projected_port_ids"]),
            padded_status,
        )

        self.assertEqual("failed", verdict, reason)
        self.assertIn("hash", reason)

    def test_delete_recovery_requires_safe_normalized_terminal_control(self):
        port_id = "port-a"
        operator_scenario = status_scenario("blocked-operator")
        operator_status = copy.deepcopy(operator_scenario["status"])
        operator_status["managed_ports"] = []
        operator_status["port_statuses"] = []
        operator_status["active_instances"] = []
        state_store = self._state_store_with_projected_port(
            port_id=port_id,
            generation=42,
            desired_hash="hash-ready-42",
        )
        state_store.prepare_delete(port_id, reason="restart-test")
        pending_before = copy.deepcopy(state_store.pending_delete())
        local_client = PublicV1ActionLocalClient(
            operator_scenario,
            status=operator_status,
        )
        sync = SnapshotSynchronizer(
            "ostack2",
            StaticPortSource([]),
            FakeOvsReader(),
            local_client,
            managed_domains=["acl"],
            state_store=state_store,
            timeout_convergence_attempts=1,
            timeout_convergence_interval=0,
        )

        recovered = sync.recover_pending_state()

        self.assertEqual([], recovered["recovered"])
        self.assertEqual(pending_before, state_store.pending_delete())
        self.assertIn(port_id, sync.projected_port_ids)
        with self.assertRaises(LocalApiTimeoutError):
            sync._recover_delete_timeout(
                port_id,
                LocalApiTimeoutError("delete timed out"),
            )
        self.assertEqual(pending_before, state_store.pending_delete())
        self.assertEqual([], local_client.mutating_calls)

        ready = copy.deepcopy(status_scenario("full-classified-ready")["status"])
        ready["managed_ports"] = []
        degraded = copy.deepcopy(
            status_scenario("classified-degraded-terminal")["status"]
        )
        degraded["managed_ports"] = []
        raw_legacy = {"managed_ports": []}
        self.assertTrue(sync._delete_status_converged(port_id, ready))
        self.assertTrue(sync._delete_status_converged(port_id, degraded))
        self.assertTrue(sync._delete_status_converged(port_id, raw_legacy))

    def test_scoped_pre_submit_routes_normalized_action_matrix_before_prepare(self):
        target_port = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
        legacy_scenario = status_scenario("legacy-v0-ready")
        cases = [
            (
                "v1-poll",
                status_scenario("pending-poll"),
                copy.deepcopy(status_scenario("pending-poll")["status"]),
                "blocked",
            ),
            (
                "v1-operator",
                status_scenario("blocked-operator"),
                copy.deepcopy(status_scenario("blocked-operator")["status"]),
                "blocked",
            ),
            (
                "v1-recover-pending",
                status_scenario("blocked-recoverable-inventory"),
                copy.deepcopy(
                    status_scenario("blocked-recoverable-inventory")["status"]
                ),
                "blocked",
            ),
            (
                "v1-full-resync",
                status_scenario("classified-degraded-full-resync"),
                copy.deepcopy(
                    status_scenario("classified-degraded-full-resync")["status"]
                ),
                "full_resync",
            ),
            (
                "decoded-legacy-poll",
                legacy_scenario,
                self._decoded_legacy_status("applying"),
                "blocked",
            ),
            (
                "decoded-legacy-operator",
                legacy_scenario,
                self._decoded_legacy_status("runtime-degraded-pending"),
                "blocked",
            ),
            (
                "decoded-legacy-recover-pending",
                legacy_scenario,
                self._decoded_legacy_status("partial-recoverable"),
                "blocked",
            ),
            (
                "decoded-legacy-full-resync",
                legacy_scenario,
                self._decoded_legacy_status("runtime-degraded-baseline"),
                "full_resync",
            ),
            (
                "decoded-legacy-ready",
                legacy_scenario,
                self._decoded_legacy_status(),
                "submit",
            ),
            (
                "raw-legacy-ready",
                legacy_scenario,
                copy.deepcopy(legacy_scenario["status"]),
                "submit",
            ),
        ]

        for label, scenario, status, expected in cases:
            state_store = self._state_store_with_projected_port(
                port_id=target_port,
            )
            pending_before = copy.deepcopy(state_store.pending_snapshot())
            projected_before = set(state_store.last_projected_port_ids())
            local_client = PublicV1ActionLocalClient(
                scenario,
                status=status,
            )
            sync = SnapshotSynchronizer(
                "ostack2",
                self._target_port_source(),
                FakeOvsReader(),
                local_client,
                managed_domains=["acl"],
                state_store=state_store,
                acl_index=self._terminal_degraded_acl_index(),
                timeout_convergence_attempts=1,
                timeout_convergence_interval=0,
            )
            result = None
            try:
                result = sync.apply_port_scoped_snapshot(
                    target_port,
                    binding_host="ostack2",
                    revision_number=8,
                    allow_revisionless=True,
                )
            except LocalApiError:
                pass

            with self.subTest(case=label):
                if expected == "submit":
                    self.assertEqual(
                        ["put_port_snapshot"],
                        local_client.mutating_calls,
                    )
                    self.assertEqual(1, len(local_client.port_snapshots))
                else:
                    self.assertEqual([], local_client.mutating_calls)
                    self.assertEqual([], local_client.port_snapshots)
                    self.assertEqual([], local_client.recoveries)
                    self.assertEqual(
                        pending_before,
                        state_store.pending_snapshot(),
                    )
                    self.assertEqual(projected_before, sync.projected_port_ids)
                if expected == "full_resync":
                    self.assertIsNotNone(result)
                    self.assertFalse(result.get("submitted"))
                    self.assertEqual(
                        "remote_status_requires_full_resync",
                        result.get("skipped_reason"),
                    )

    def test_delete_pre_submit_routes_normalized_action_matrix_before_prepare(self):
        target_port = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
        legacy_scenario = status_scenario("legacy-v0-ready")
        cases = [
            (
                "v1-poll",
                status_scenario("pending-poll"),
                copy.deepcopy(status_scenario("pending-poll")["status"]),
                "blocked",
            ),
            (
                "v1-operator",
                status_scenario("blocked-operator"),
                copy.deepcopy(status_scenario("blocked-operator")["status"]),
                "blocked",
            ),
            (
                "v1-recover-pending",
                status_scenario("blocked-recoverable-inventory"),
                copy.deepcopy(
                    status_scenario("blocked-recoverable-inventory")["status"]
                ),
                "blocked",
            ),
            (
                "v1-full-resync",
                status_scenario("classified-degraded-full-resync"),
                copy.deepcopy(
                    status_scenario("classified-degraded-full-resync")["status"]
                ),
                "full_resync",
            ),
            (
                "v1-ready",
                status_scenario("full-classified-ready"),
                copy.deepcopy(status_scenario("full-classified-ready")["status"]),
                "delete",
            ),
            (
                "v1-classified-degraded",
                status_scenario("classified-degraded-terminal"),
                copy.deepcopy(
                    status_scenario("classified-degraded-terminal")["status"]
                ),
                "delete",
            ),
            (
                "decoded-legacy-poll",
                legacy_scenario,
                self._decoded_legacy_status("applying"),
                "blocked",
            ),
            (
                "decoded-legacy-operator",
                legacy_scenario,
                self._decoded_legacy_status("runtime-degraded-pending"),
                "blocked",
            ),
            (
                "decoded-legacy-recover-pending",
                legacy_scenario,
                self._decoded_legacy_status("partial-recoverable"),
                "blocked",
            ),
            (
                "decoded-legacy-full-resync",
                legacy_scenario,
                self._decoded_legacy_status("runtime-degraded-baseline"),
                "full_resync",
            ),
            (
                "decoded-legacy-ready",
                legacy_scenario,
                self._decoded_legacy_status(),
                "delete",
            ),
            (
                "raw-legacy-ready",
                legacy_scenario,
                copy.deepcopy(legacy_scenario["status"]),
                "delete",
            ),
        ]

        for label, scenario, status, expected in cases:
            state_store = self._state_store_with_projected_port(
                port_id=target_port,
            )
            pending_before = copy.deepcopy(state_store.pending_delete())
            projected_before = set(state_store.last_projected_port_ids())
            local_client = PublicV1ActionLocalClient(
                scenario,
                status=status,
            )
            sync = SnapshotSynchronizer(
                "ostack2",
                StaticPortSource([]),
                FakeOvsReader(),
                local_client,
                managed_domains=["acl"],
                state_store=state_store,
                timeout_convergence_attempts=1,
                timeout_convergence_interval=0,
            )
            result = None
            try:
                result = sync.delete_port(target_port, reason="matrix")
            except LocalApiError:
                pass

            with self.subTest(case=label):
                if expected == "blocked":
                    self.assertEqual([], local_client.mutating_calls)
                    self.assertEqual(pending_before, state_store.pending_delete())
                    self.assertEqual(projected_before, sync.projected_port_ids)
                elif expected == "full_resync":
                    self.assertEqual(
                        ["put_full_snapshot"],
                        local_client.mutating_calls,
                    )
                    self.assertEqual([], local_client.deleted_ports)
                    self.assertIsNotNone(result)
                    self.assertEqual(None, state_store.pending_delete())
                else:
                    self.assertEqual(["delete_port"], local_client.mutating_calls)
                    self.assertEqual([target_port], local_client.deleted_ports)
                    self.assertEqual(None, state_store.pending_delete())
                    self.assertNotIn(target_port, sync.projected_port_ids)

    def test_exact_classified_degraded_repeat_finalizes_without_write(self):
        scenario = status_scenario("classified-degraded-terminal")
        snapshot = self._terminal_degraded_snapshot(scenario)
        state_store = InMemorySnapshotStateStore()
        prepared = state_store.prepare_snapshot_at_generation(
            snapshot,
            scenario["request_context"]["expected_generation"],
            desired_hash=scenario["request_context"]["expected_desired_hash"],
        )
        state_store.commit_classified_snapshot(
            prepared["generation"],
            prepared["desired_hash"],
            snapshot_ports=1,
            managed_ports=1,
        )
        local_client = PublicV1ActionLocalClient(scenario)
        sync = SnapshotSynchronizer(
            "ostack2",
            self._target_port_source(),
            FakeOvsReader(),
            local_client,
            managed_domains=["acl"],
            state_store=state_store,
            acl_index=self._terminal_degraded_acl_index(),
        )

        result = sync.safe_full_resync()

        self.assertEqual([], local_client.mutating_calls)
        self.assertEqual([], local_client.snapshots)
        self.assertEqual([], local_client.port_snapshots)
        self.assertEqual([], local_client.deleted_ports)
        self.assertEqual([], local_client.recoveries)
        self.assertEqual(
            scenario["request_context"]["expected_generation"],
            result["snapshot"]["generation"],
        )
        self.assertEqual(
            scenario["request_context"]["expected_desired_hash"],
            result["snapshot"]["desired_hash"],
        )
        self.assertTrue(result["status"]["degraded"])
        self.assertFalse(result["status"]["ready"])
        self.assertEqual(None, state_store.pending_snapshot())

    def test_exact_classified_ready_repeat_finalizes_without_write(self):
        scenario = status_scenario("full-classified-ready")
        state_store = InMemorySnapshotStateStore()
        prepared = state_store.prepare_snapshot_at_generation(
            {"host": "ostack2", "ports": []},
            42,
        )
        state_store.commit_snapshot(
            prepared["generation"],
            prepared["desired_hash"],
            snapshot_ports=0,
            managed_ports=0,
            feature_ready_domains=["acl"],
        )
        exact_ready = copy.deepcopy(scenario["status"])
        exact_ready.update({
            "last_classified_generation": prepared["generation"],
            "generation": prepared["generation"],
            "accepted_generation": prepared["generation"],
            "applied_generation": prepared["generation"],
            "pending_generation": None,
            "desired_hash": prepared["desired_hash"],
            "applied_desired_hash": prepared["desired_hash"],
            "managed_ports": [],
            "port_statuses": [],
            "active_instances": [],
        })
        local_client = PublicV1ActionLocalClient(
            scenario,
            status=exact_ready,
        )
        sync = SnapshotSynchronizer(
            "ostack2",
            StaticPortSource([]),
            FakeOvsReader(),
            local_client,
            managed_domains=["acl"],
            state_store=state_store,
        )

        result = sync.safe_full_resync()

        self.assertEqual([], local_client.mutating_calls)
        self.assertEqual([], local_client.snapshots)
        self.assertEqual([], local_client.port_snapshots)
        self.assertEqual([], local_client.deleted_ports)
        self.assertEqual([], local_client.recoveries)
        self.assertEqual(prepared["generation"], result["snapshot"]["generation"])
        self.assertEqual(prepared["desired_hash"], result["snapshot"]["desired_hash"])
        self.assertTrue(result["status"]["ready"])
        self.assertFalse(result["status"]["degraded"])
        self.assertEqual(None, state_store.pending_snapshot())

    def test_actual_decoded_legacy_control_owns_target_verdict(self):
        raw_status = copy.deepcopy(
            status_scenario("legacy-v0-ready")["status"]
        )
        raw_status["wal_replay_failures"] = 1
        decoded_status = _decode_legacy_status_v0(raw_status)
        self.assertEqual(
            ("blocked", "blocked", "operator"),
            tuple(decoded_status[key] for key in (
                "transaction_state",
                "overall_readiness",
                "required_action",
            )),
        )
        snapshot = {
            "generation": 40,
            "desired_hash": "legacy-hash-40",
            "host": "ostack2",
            "ports": [{
                "port_id": "legacy-port",
                "ifname": "tap-legacy",
                "eligible": True,
                "managed_domains": ["acl"],
                "acl": {
                    "enabled": True,
                    "status": "ready",
                    "effective_action": "enforce",
                },
            }],
        }
        state_store = InMemorySnapshotStateStore()
        state_store.prepare_snapshot_at_generation(
            snapshot,
            snapshot["generation"],
            desired_hash=snapshot["desired_hash"],
        )
        pending_before = copy.deepcopy(state_store.pending_snapshot())
        local_client = PublicV1ActionLocalClient(
            status_scenario("legacy-v0-ready"),
            status=decoded_status,
        )
        sync = SnapshotSynchronizer(
            "ostack2",
            StaticPortSource([]),
            FakeOvsReader(),
            local_client,
            managed_domains=["acl"],
            state_store=state_store,
        )

        verdict, reason = sync._snapshot_status_verdict(
            snapshot,
            set(("legacy-port",)),
            decoded_status,
        )

        with self.subTest(path="direct-verdict"):
            self.assertEqual("failed", verdict, reason)
        partial_control = copy.deepcopy(decoded_status)
        partial_control.pop("required_action")
        partial_verdict, partial_reason = sync._snapshot_status_verdict(
            snapshot,
            set(("legacy-port",)),
            partial_control,
        )
        with self.subTest(path="partial-control"):
            self.assertEqual("failed", partial_verdict, partial_reason)
        raw_legacy = copy.deepcopy(
            status_scenario("legacy-v0-ready")["status"]
        )
        raw_verdict, raw_reason = sync._snapshot_status_verdict(
            snapshot,
            set(("legacy-port",)),
            raw_legacy,
        )
        with self.subTest(path="raw-legacy-compatibility"):
            self.assertEqual("ready", raw_verdict, raw_reason)
        with self.assertRaises(LocalApiError):
            sync._status_after_apply(
                snapshot,
                set(("legacy-port",)),
                {"status": "ok"},
            )
        self.assertEqual(pending_before, state_store.pending_snapshot())
        self.assertFalse(sync.runtime_status.ready)
        self.assertEqual([], local_client.mutating_calls)

    def test_actual_decoded_legacy_actions_cannot_converge_delete(self):
        target_port = "legacy-port"
        sync = SnapshotSynchronizer(
            "ostack2",
            StaticPortSource([]),
            FakeOvsReader(),
            FakeLocalClient(),
            managed_domains=["acl"],
        )
        for case_id in (
            "applying",
            "runtime-degraded-pending",
            "partial-recoverable",
            "runtime-degraded-baseline",
        ):
            status = self._actual_decoded_legacy_status(
                case_id,
                clear_runtime_evidence=True,
            )
            with self.subTest(control=case_id):
                self.assertFalse(
                    sync._delete_status_converged(target_port, status)
                )

        ready = self._actual_decoded_legacy_status(
            clear_runtime_evidence=True,
        )
        self.assertTrue(sync._delete_status_converged(target_port, ready))
        self.assertTrue(sync._delete_status_converged(
            target_port,
            {"managed_ports": []},
        ))

        operator_status = self._actual_decoded_legacy_status(
            "runtime-degraded-pending",
            clear_runtime_evidence=True,
        )
        with self.subTest(path="restart"):
            state_store = self._state_store_with_projected_port(
                port_id=target_port,
                generation=40,
                desired_hash="legacy-hash-40",
            )
            state_store.prepare_delete(target_port, reason="restart")
            pending_before = copy.deepcopy(state_store.pending_delete())
            local_client = PublicV1ActionLocalClient(
                status_scenario("legacy-v0-ready"),
                status=operator_status,
            )
            restart_sync = SnapshotSynchronizer(
                "ostack2",
                StaticPortSource([]),
                FakeOvsReader(),
                local_client,
                managed_domains=["acl"],
                state_store=state_store,
            )

            recovered = restart_sync.recover_pending_state()

            self.assertEqual([], recovered["recovered"])
            self.assertEqual(pending_before, state_store.pending_delete())
            self.assertIn(target_port, restart_sync.projected_port_ids)
            self.assertEqual([], local_client.mutating_calls)

        with self.subTest(path="timeout"):
            state_store = self._state_store_with_projected_port(
                port_id=target_port,
                generation=40,
                desired_hash="legacy-hash-40",
            )
            state_store.prepare_delete(target_port, reason="timeout")
            pending_before = copy.deepcopy(state_store.pending_delete())
            local_client = PublicV1ActionLocalClient(
                status_scenario("legacy-v0-ready"),
                status=operator_status,
            )
            timeout_sync = SnapshotSynchronizer(
                "ostack2",
                StaticPortSource([]),
                FakeOvsReader(),
                local_client,
                managed_domains=["acl"],
                state_store=state_store,
                timeout_convergence_attempts=1,
                timeout_convergence_interval=0,
            )

            with self.assertRaises(LocalApiTimeoutError):
                timeout_sync._recover_delete_timeout(
                    target_port,
                    LocalApiTimeoutError("delete timed out"),
                )
            self.assertEqual(pending_before, state_store.pending_delete())
            self.assertIn(target_port, timeout_sync.projected_port_ids)
            self.assertEqual([], local_client.mutating_calls)

    def test_actual_decoded_legacy_recovery_requires_barrier_and_forces_new(self):
        empty_snapshot = {"host": "ostack2", "ports": []}
        baseline_hash = "hash-applied-40"

        class LegacyRecoveryClient(FakeLocalClient):
            def __init__(self, pre_status, post_status):
                FakeLocalClient.__init__(self)
                self.pre_status = copy.deepcopy(pre_status)
                self.post_status = copy.deepcopy(post_status)
                self.recoveries = []
                self.mutating_calls = []
                self.recovered = False

            def capabilities(self, required_domains=None):
                self.capability_calls.append(list(required_domains or []))
                return copy.deepcopy(
                    status_scenario("legacy-v0-ready")["capabilities"]
                )

            def status(self):
                if self.snapshots:
                    terminal = _terminal_status_for_snapshot(self.snapshots[-1])
                    terminal.update({
                        "wal_status": "committed",
                        "wal_replay_failures": 0,
                    })
                    return _decode_legacy_status_v0(terminal)
                if self.recovered:
                    return copy.deepcopy(self.post_status)
                return copy.deepcopy(self.pre_status)

            def recover_pending_snapshot(
                self,
                expected_generation,
                expected_desired_hash=None,
            ):
                self.recoveries.append({
                    "expected_generation": expected_generation,
                    "expected_desired_hash": expected_desired_hash,
                })
                self.mutating_calls.append("recover_pending")
                self.recovered = True
                return {"status": "recovered"}

            def put_snapshot(self, snapshot):
                self.mutating_calls.append("put_full_snapshot")
                return FakeLocalClient.put_snapshot(self, snapshot)

        def prepared_state():
            state_store = InMemorySnapshotStateStore()
            prepared = state_store.prepare_snapshot_at_generation(
                empty_snapshot,
                41,
            )
            return state_store, prepared

        def pre_recovery_status(pending_hash):
            return _decode_legacy_status_v0({
                "generation": 40,
                "accepted_generation": 41,
                "applied_generation": 40,
                "pending_generation": 41,
                "desired_hash": pending_hash,
                "applied_desired_hash": baseline_hash,
                "wal_status": "pending",
                "wal_replay_failures": 0,
                "authority_state": "partial",
                "managed_ports": [],
                "port_statuses": [],
                "active_instances": [],
            })

        valid_post_raw = {
            "generation": 40,
            "accepted_generation": 40,
            "applied_generation": 40,
            "pending_generation": None,
            "desired_hash": baseline_hash,
            "applied_desired_hash": baseline_hash,
            "wal_status": "recovered_pending_full_resync_required",
            "wal_replay_failures": 0,
            "authority_state": "recovered_pending_full_resync_required",
            "managed_ports": [],
            "port_statuses": [],
            "active_instances": [],
        }
        valid_post = _decode_legacy_status_v0(
            copy.deepcopy(valid_post_raw)
        )
        row_baseline_raw = copy.deepcopy(
            status_scenario("legacy-v0-ready")["status"]
        )
        row_baseline_raw.update({
            "authority_state": "recovered_pending_full_resync_required",
            "wal_status": "recovered_pending_full_resync_required",
        })
        row_baseline = _decode_legacy_status_v0(row_baseline_raw)
        row_baseline_sync = SnapshotSynchronizer(
            "ostack2",
            StaticPortSource([]),
            FakeOvsReader(),
            FakeLocalClient(),
            managed_domains=["acl"],
        )
        self.assertEqual(
            set(("legacy-port",)),
            row_baseline_sync._legacy_recovery_baseline_ports(
                row_baseline,
                40,
                "legacy-hash-40",
            ),
        )
        state_store, prepared = prepared_state()
        client = LegacyRecoveryClient(
            pre_recovery_status(prepared["desired_hash"]),
            valid_post,
        )
        sync = SnapshotSynchronizer(
            "ostack2",
            StaticPortSource([]),
            FakeOvsReader(),
            client,
            managed_domains=["acl"],
            state_store=state_store,
        )

        result = sync.safe_full_resync()

        with self.subTest(path="valid-barrier"):
            self.assertEqual(1, len(client.recoveries))
            self.assertEqual(1, len(client.snapshots))
            self.assertGreaterEqual(client.snapshots[0]["generation"], 42)
            self.assertEqual(
                ["recover_pending", "put_full_snapshot"],
                client.mutating_calls,
            )
            self.assertTrue(result["status"]["ready"])
            self.assertEqual(None, state_store.pending_snapshot())

        pending_post = self._actual_decoded_legacy_status(
            "applying",
            clear_runtime_evidence=True,
        )
        operator_raw = {
            "generation": 40,
            "accepted_generation": 40,
            "applied_generation": 40,
            "pending_generation": None,
            "desired_hash": baseline_hash,
            "applied_desired_hash": baseline_hash,
            "wal_status": "committed",
            "wal_replay_failures": 1,
            "authority_state": "ready",
            "managed_ports": [],
            "port_statuses": [],
            "active_instances": [],
        }
        invalid_posts = [
            ("pending", pending_post),
            ("operator", _decode_legacy_status_v0(operator_raw)),
            (
                "recover-pending",
                pre_recovery_status("hash-other-pending-41"),
            ),
        ]
        malformed_managed = copy.deepcopy(valid_post_raw)
        malformed_managed["managed_ports"] = [{}]
        invalid_posts.append((
            "malformed-managed-row",
            _decode_legacy_status_v0(malformed_managed),
        ))
        duplicate_managed = copy.deepcopy(valid_post_raw)
        managed_row = {
            "port_id": "legacy-port",
            "ifname": "tap-legacy",
            "managed_domains": ["acl"],
        }
        duplicate_managed["managed_ports"] = [
            copy.deepcopy(managed_row),
            copy.deepcopy(managed_row),
        ]
        invalid_posts.append((
            "duplicate-managed-row",
            _decode_legacy_status_v0(duplicate_managed),
        ))
        missing_managed_status = copy.deepcopy(valid_post_raw)
        missing_managed_status["managed_ports"] = [
            copy.deepcopy(managed_row),
        ]
        invalid_posts.append((
            "missing-managed-status",
            _decode_legacy_status_v0(missing_managed_status),
        ))
        for label, post_status in invalid_posts:
            state_store, prepared = prepared_state()
            pending_before = copy.deepcopy(state_store.pending_snapshot())
            client = LegacyRecoveryClient(
                pre_recovery_status(prepared["desired_hash"]),
                post_status,
            )
            sync = SnapshotSynchronizer(
                "ostack2",
                StaticPortSource([]),
                FakeOvsReader(),
                client,
                managed_domains=["acl"],
                state_store=state_store,
            )

            sync.safe_full_resync()

            with self.subTest(invalid_post=label):
                self.assertEqual(1, len(client.recoveries))
                self.assertEqual([], client.snapshots)
                self.assertEqual(
                    ["recover_pending"],
                    client.mutating_calls,
                )
                self.assertEqual(pending_before, state_store.pending_snapshot())

    def test_actual_decoded_legacy_recovery_rejects_untrimmed_row_identities(self):
        empty_snapshot = {"host": "ostack2", "ports": []}
        baseline_hash = "legacy-hash-40"
        legacy_scenario = status_scenario("legacy-v0-ready")

        class IdentityRecoveryClient(FakeLocalClient):
            def __init__(self, pre_status, post_status):
                FakeLocalClient.__init__(self)
                self.pre_status = copy.deepcopy(pre_status)
                self.post_status = copy.deepcopy(post_status)
                self.recoveries = []
                self.mutating_calls = []
                self.recovered = False

            def capabilities(self, required_domains=None):
                self.capability_calls.append(list(required_domains or []))
                return copy.deepcopy(legacy_scenario["capabilities"])

            def status(self):
                if self.snapshots:
                    terminal = _terminal_status_for_snapshot(self.snapshots[-1])
                    terminal.update({
                        "wal_status": "committed",
                        "wal_replay_failures": 0,
                    })
                    return _decode_legacy_status_v0(terminal)
                if self.recovered:
                    return copy.deepcopy(self.post_status)
                return copy.deepcopy(self.pre_status)

            def recover_pending_snapshot(
                self,
                expected_generation,
                expected_desired_hash=None,
            ):
                self.recoveries.append({
                    "expected_generation": expected_generation,
                    "expected_desired_hash": expected_desired_hash,
                })
                self.mutating_calls.append("recover_pending")
                self.recovered = True
                return {"status": "recovered"}

            def put_snapshot(self, snapshot):
                self.mutating_calls.append("put_full_snapshot")
                return FakeLocalClient.put_snapshot(self, snapshot)

        def seeded_state():
            state_store = self._state_store_with_projected_port(
                port_id="classified-before",
                generation=39,
                desired_hash="hash-classified-before-39",
            )
            prepared = state_store.prepare_snapshot_at_generation(
                empty_snapshot,
                41,
            )
            return state_store, prepared

        def pre_recovery_status(pending_hash):
            return _decode_legacy_status_v0({
                "generation": 40,
                "accepted_generation": 41,
                "applied_generation": 40,
                "pending_generation": 41,
                "desired_hash": pending_hash,
                "applied_desired_hash": baseline_hash,
                "wal_status": "pending",
                "wal_replay_failures": 0,
                "authority_state": "partial",
                "managed_ports": [],
                "port_statuses": [],
                "active_instances": [],
            })

        valid_post_raw = copy.deepcopy(legacy_scenario["status"])
        valid_post_raw.update({
            "authority_state": "recovered_pending_full_resync_required",
            "wal_status": "recovered_pending_full_resync_required",
        })
        bad_values = {
            "port_id": (
                ("non-string", 7),
                ("empty", ""),
                ("whitespace", "   "),
                ("padded", " legacy-port "),
            ),
            "ifname": (
                ("non-string", 7),
                ("empty", ""),
                ("whitespace", "   "),
                ("padded", " tap-legacy "),
            ),
        }
        targets = (
            ("managed", ("managed_ports",)),
            ("status", ("port_statuses",)),
            ("matching-both", ("managed_ports", "port_statuses")),
        )

        for field, values in bad_values.items():
            for value_label, value in values:
                for target_label, collections in targets:
                    post_raw = copy.deepcopy(valid_post_raw)
                    for collection in collections:
                        post_raw[collection][0][field] = value
                    post_status = _decode_legacy_status_v0(post_raw)
                    state_store, prepared = seeded_state()
                    pending_before = copy.deepcopy(
                        state_store.pending_snapshot()
                    )
                    durable_before = state_store.to_dict()
                    classified_before = {
                        key: copy.deepcopy(durable_before.get(key))
                        for key in (
                            "last_classified_generation",
                            "last_classified_desired_hash",
                            "last_classified_projected_port_ids",
                        )
                    }
                    client = IdentityRecoveryClient(
                        pre_recovery_status(prepared["desired_hash"]),
                        post_status,
                    )
                    sync = SnapshotSynchronizer(
                        "ostack2",
                        StaticPortSource([]),
                        FakeOvsReader(),
                        client,
                        managed_domains=["acl"],
                        state_store=state_store,
                    )
                    projected_before = set(sync.projected_port_ids)

                    result = sync.safe_full_resync()

                    durable_after = state_store.to_dict()
                    with self.subTest(
                        field=field,
                        value=value_label,
                        target=target_label,
                    ):
                        self.assertTrue(result["status"]["degraded"])
                        self.assertEqual(1, len(client.recoveries))
                        self.assertEqual([], client.snapshots)
                        self.assertEqual(
                            ["recover_pending"],
                            client.mutating_calls,
                        )
                        self.assertEqual(
                            pending_before,
                            state_store.pending_snapshot(),
                        )
                        self.assertEqual(
                            classified_before,
                            {
                                key: copy.deepcopy(durable_after.get(key))
                                for key in classified_before
                            },
                        )
                        self.assertEqual(
                            projected_before,
                            sync.projected_port_ids,
                        )

        state_store, prepared = seeded_state()
        valid_post = _decode_legacy_status_v0(
            copy.deepcopy(valid_post_raw)
        )
        self.assertTrue(all(
            "support_disposition" not in domain
            for row in valid_post["port_statuses"]
            for domain in row.get("domains") or []
        ))
        client = IdentityRecoveryClient(
            pre_recovery_status(prepared["desired_hash"]),
            valid_post,
        )
        sync = SnapshotSynchronizer(
            "ostack2",
            StaticPortSource([]),
            FakeOvsReader(),
            client,
            managed_domains=["acl"],
            state_store=state_store,
        )

        result = sync.safe_full_resync()

        with self.subTest(positive="ordinary-trimmed-legacy-identities"):
            self.assertEqual(
                ["recover_pending", "put_full_snapshot"],
                client.mutating_calls,
            )
            self.assertEqual(1, len(client.snapshots))
            self.assertGreaterEqual(client.snapshots[0]["generation"], 42)
            self.assertTrue(result["status"]["ready"])

    def test_actual_decoded_legacy_direct_full_resync_validates_applied_baseline(self):
        legacy_scenario = status_scenario("legacy-v0-ready")

        class DirectLegacyClient(FakeLocalClient):
            def __init__(self, raw_status, decode_status=True):
                FakeLocalClient.__init__(self)
                self.raw_status = copy.deepcopy(raw_status)
                self.decode_status = decode_status
                self.recoveries = []
                self.mutating_calls = []

            def capabilities(self, required_domains=None):
                self.capability_calls.append(list(required_domains or []))
                return copy.deepcopy(legacy_scenario["capabilities"])

            def status(self):
                if self.snapshots:
                    terminal = _terminal_status_for_snapshot(self.snapshots[-1])
                    terminal.update({
                        "wal_status": "committed",
                        "wal_replay_failures": 0,
                    })
                    if self.decode_status:
                        return _decode_legacy_status_v0(terminal)
                    return terminal
                if self.decode_status:
                    return _decode_legacy_status_v0(
                        copy.deepcopy(self.raw_status)
                    )
                return copy.deepcopy(self.raw_status)

            def recover_pending_snapshot(
                self,
                expected_generation,
                expected_desired_hash=None,
            ):
                self.recoveries.append({
                    "expected_generation": expected_generation,
                    "expected_desired_hash": expected_desired_hash,
                })
                self.mutating_calls.append("recover_pending")
                return {"status": "recovered"}

            def put_snapshot(self, snapshot):
                self.mutating_calls.append("put_full_snapshot")
                return FakeLocalClient.put_snapshot(self, snapshot)

        def seeded_state():
            return self._state_store_with_projected_port(
                port_id="classified-before",
                generation=38,
                desired_hash="hash-classified-before-38",
            )

        def control_raw(authority):
            raw = copy.deepcopy(legacy_scenario["status"])
            raw.update({
                "authority_state": authority,
                "wal_status": authority,
            })
            return raw

        controls = (
            (
                "recovery",
                "recovered_pending_full_resync_required",
                ("recovery", "degraded", "full_resync"),
            ),
            (
                "classified",
                "runtime_degraded",
                ("classified", "degraded", "full_resync"),
            ),
        )

        for control_label, authority, expected_control in controls:
            baseline = control_raw(authority)
            invalid_payloads = []

            malformed_managed = copy.deepcopy(baseline)
            malformed_managed["managed_ports"] = [{}]
            invalid_payloads.append(("malformed-managed", malformed_managed))

            malformed_status = copy.deepcopy(baseline)
            malformed_status["port_statuses"] = [{}]
            invalid_payloads.append(("malformed-status", malformed_status))

            duplicate_managed = copy.deepcopy(baseline)
            duplicate_managed["managed_ports"].append(copy.deepcopy(
                duplicate_managed["managed_ports"][0]
            ))
            invalid_payloads.append(("duplicate-managed", duplicate_managed))

            duplicate_status = copy.deepcopy(baseline)
            duplicate_status["port_statuses"].append(copy.deepcopy(
                duplicate_status["port_statuses"][0]
            ))
            invalid_payloads.append(("duplicate-status", duplicate_status))

            missing_status = copy.deepcopy(baseline)
            missing_status["port_statuses"] = []
            invalid_payloads.append(("missing-managed-status", missing_status))

            for invalid_label, raw_status in invalid_payloads:
                decoded = _decode_legacy_status_v0(
                    copy.deepcopy(raw_status)
                )
                self.assertEqual(
                    expected_control,
                    tuple(decoded[key] for key in (
                        "transaction_state",
                        "overall_readiness",
                        "required_action",
                    )),
                )
                state_store = seeded_state()
                self.assertEqual(None, state_store.pending_snapshot())
                durable_before = state_store.to_dict()
                classified_before = {
                    key: copy.deepcopy(durable_before.get(key))
                    for key in (
                        "last_classified_generation",
                        "last_classified_desired_hash",
                        "last_classified_projected_port_ids",
                    )
                }
                client = DirectLegacyClient(raw_status)
                sync = SnapshotSynchronizer(
                    "ostack2",
                    StaticPortSource([]),
                    FakeOvsReader(),
                    client,
                    managed_domains=["acl"],
                    state_store=state_store,
                )
                projected_before = set(sync.projected_port_ids)

                result = sync.safe_full_resync()

                durable_after = state_store.to_dict()
                with self.subTest(
                    control=control_label,
                    invalid=invalid_label,
                ):
                    self.assertTrue(result["status"]["degraded"])
                    self.assertEqual([], client.snapshots)
                    self.assertEqual([], client.recoveries)
                    self.assertEqual([], client.mutating_calls)
                    self.assertEqual(None, state_store.pending_snapshot())
                    self.assertEqual(
                        classified_before,
                        {
                            key: copy.deepcopy(durable_after.get(key))
                            for key in classified_before
                        },
                    )
                    self.assertEqual(
                        projected_before,
                        sync.projected_port_ids,
                    )

        for control_label, authority, expected_control in controls:
            raw_status = control_raw(authority)
            decoded = _decode_legacy_status_v0(copy.deepcopy(raw_status))
            self.assertEqual(
                expected_control,
                tuple(decoded[key] for key in (
                    "transaction_state",
                    "overall_readiness",
                    "required_action",
                )),
            )
            self.assertTrue(all(
                "support_disposition" not in domain
                for row in decoded["port_statuses"]
                for domain in row.get("domains") or []
            ))
            state_store = seeded_state()
            client = DirectLegacyClient(raw_status)
            sync = SnapshotSynchronizer(
                "ostack2",
                StaticPortSource([]),
                FakeOvsReader(),
                client,
                managed_domains=["acl"],
                state_store=state_store,
            )

            result = sync.safe_full_resync()

            with self.subTest(
                positive=control_label + "-ordinary-no-v1-support",
            ):
                self.assertEqual(
                    ["put_full_snapshot"],
                    client.mutating_calls,
                )
                self.assertEqual(1, len(client.snapshots))
                self.assertGreater(client.snapshots[0]["generation"], 40)
                self.assertTrue(result["status"]["ready"])

        idle_raw = {
            "generation": 0,
            "accepted_generation": 0,
            "applied_generation": 0,
            "pending_generation": None,
            "desired_hash": None,
            "applied_desired_hash": None,
            "wal_status": "idle",
            "wal_replay_failures": 0,
            "authority_state": "idle",
            "managed_ports": [],
            "port_statuses": [],
            "active_instances": [],
        }
        idle_decoded = _decode_legacy_status_v0(copy.deepcopy(idle_raw))
        self.assertEqual(
            ("idle", "unknown", "full_resync"),
            tuple(idle_decoded[key] for key in (
                "transaction_state",
                "overall_readiness",
                "required_action",
            )),
        )
        state_store = seeded_state()
        idle_client = DirectLegacyClient(idle_raw)
        idle_sync = SnapshotSynchronizer(
            "ostack2",
            StaticPortSource([]),
            FakeOvsReader(),
            idle_client,
            managed_domains=["acl"],
            state_store=state_store,
        )

        idle_result = idle_sync.safe_full_resync()

        with self.subTest(positive="decoded-legacy-idle-empty-baseline"):
            self.assertEqual(
                ["put_full_snapshot"],
                idle_client.mutating_calls,
            )
            self.assertEqual(1, len(idle_client.snapshots))
            self.assertTrue(idle_result["status"]["ready"])

        raw_unvalidated = control_raw(
            "recovered_pending_full_resync_required"
        )
        raw_unvalidated["managed_ports"] = [{}]
        state_store = seeded_state()
        raw_client = DirectLegacyClient(
            raw_unvalidated,
            decode_status=False,
        )
        raw_sync = SnapshotSynchronizer(
            "ostack2",
            StaticPortSource([]),
            FakeOvsReader(),
            raw_client,
            managed_domains=["acl"],
            state_store=state_store,
        )

        raw_result = raw_sync.safe_full_resync()

        with self.subTest(positive="completely-raw-legacy-is-isolated"):
            self.assertEqual(
                ["put_full_snapshot"],
                raw_client.mutating_calls,
            )
            self.assertEqual(1, len(raw_client.snapshots))
            self.assertTrue(raw_result["status"]["ready"])

    def test_actual_decoded_legacy_empty_full_host_restart_advances_ready_history(self):
        state_store = InMemorySnapshotStateStore()
        state_store.prepare_snapshot_at_generation(
            {"host": "ostack2", "ports": []},
            40,
            desired_hash="legacy-hash-40",
        )
        decoded_ready = self._actual_decoded_legacy_status(
            clear_runtime_evidence=True,
        )
        local_client = PublicV1ActionLocalClient(
            status_scenario("legacy-v0-ready"),
            status=decoded_ready,
        )
        sync = SnapshotSynchronizer(
            "ostack2",
            StaticPortSource([]),
            FakeOvsReader(),
            local_client,
            managed_domains=["acl"],
            state_store=state_store,
        )

        recovered = sync.recover_pending_state()

        self.assertEqual(["snapshot"], recovered["recovered"])
        self.assertEqual(None, state_store.pending_snapshot())
        self.assertEqual({
            "last_classified_generation": 40,
            "last_feature_ready_generation": 40,
            "last_feature_ready_desired_hash": "legacy-hash-40",
            "last_feature_ready_projected_port_ids": [],
            "last_feature_ready_generation_by_domain": {"acl": 40},
        }, state_store.feature_ready_history())
        self.assertTrue(sync.runtime_status.ready)
        self.assertEqual([], local_client.mutating_calls)

    def test_actual_decoded_legacy_ready_restart_with_managed_port_stays_pending(self):
        state_store = InMemorySnapshotStateStore()
        state_store.prepare_snapshot_at_generation(
            {
                "host": "ostack2",
                "ports": [{
                    "port_id": "legacy-port",
                    "ifname": "tap-legacy",
                    "eligible": True,
                    "managed_domains": ["acl"],
                    "acl": {
                        "enabled": True,
                        "status": "ready",
                        "effective_action": "enforce",
                    },
                }],
            },
            40,
            desired_hash="legacy-hash-40",
        )
        decoded_ready = self._actual_decoded_legacy_status()
        local_client = PublicV1ActionLocalClient(
            status_scenario("legacy-v0-ready"),
            status=decoded_ready,
        )
        sync = SnapshotSynchronizer(
            "ostack2",
            StaticPortSource([]),
            FakeOvsReader(),
            local_client,
            managed_domains=["acl"],
            state_store=state_store,
        )
        pending_before = copy.deepcopy(state_store.pending_snapshot())
        feature_ready_before = copy.deepcopy(state_store.feature_ready_history())

        recovered = sync.recover_pending_state()

        self.assertEqual([], recovered["recovered"])
        self.assertEqual(pending_before, state_store.pending_snapshot())
        self.assertEqual(feature_ready_before, state_store.feature_ready_history())
        self.assertFalse(sync.runtime_status.ready)
        self.assertEqual([], local_client.mutating_calls)


if __name__ == "__main__":
    unittest.main()
