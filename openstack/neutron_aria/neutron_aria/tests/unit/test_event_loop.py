from __future__ import absolute_import

import copy
import shutil
import tempfile
import unittest

from neutron_aria.agent.effective_acl import EffectiveAclIndex
from neutron_aria.agent.event_loop import SnapshotSynchronizer
from neutron_aria.agent.neutron_client import StaticPortSource
from neutron_aria.agent.ovsdb import OvsInterface
from neutron_aria.agent.state import SnapshotStateStore
from neutron_aria.agent.status_reporter import StatusReportError
from neutron_aria.agent.uds_client import LocalApiError
from neutron_aria.agent.uds_client import LocalApiTimeoutError
from neutron_aria.agent.uds_client import LocalApiTransportError


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
        return {
            "generation": 1,
            "managed_ports": [{"port_id": self.deleted_ports[-1]}],
            "active_instances": [],
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
            "pending_recovery_commit_failed",
        ):
            with self.subTest(authority_state=authority_state):
                action = sync._remote_pending_action({}, {
                    "accepted_generation": 10,
                    "applied_generation": 10,
                    "pending_generation": 11,
                    "desired_hash": "hash-11",
                    "applied_desired_hash": "hash-10",
                    "authority_state": authority_state,
                }, "hash-11")

                self.assertEqual("recover", action["action"])
                self.assertEqual(11, action["generation"])
                self.assertEqual("hash-11", action["remote_desired_hash"])

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
        self.assertFalse(sync.runtime_status.degraded)
        self.assertEqual("ready", sync.runtime_status.reason)

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
            self.assertTrue(sync.runtime_status.ready)
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


if __name__ == "__main__":
    unittest.main()
