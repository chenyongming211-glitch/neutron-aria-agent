from __future__ import absolute_import

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
        return {"generation": 0, "managed_ports": [], "active_instances": []}


class AdvancedGenerationLocalClient(FakeLocalClient):
    def status(self):
        return {
            "generation": 3,
            "accepted_generation": 3,
            "applied_generation": 3,
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
        if not self.snapshots:
            return {"generation": 0, "managed_ports": [], "active_instances": []}
        port_ids = [
            port["port_id"] for port in self.snapshots[-1]["ports"]
            if port.get("eligible") or port.get("managed_domains")
        ]
        return {
            "generation": self.snapshots[-1]["generation"],
            "managed_ports": [
                {"port_id": port_id, "ifname": "tap%s" % port_id[:11]}
                for port_id in port_ids
            ],
            "active_instances": ["tap%s" % port_id[:11] for port_id in port_ids],
        }


class TimeoutThenCommittedWithPartialManagedClient(FakeLocalClient):
    def put_snapshot(self, snapshot):
        self.snapshots.append(snapshot)
        raise LocalApiTimeoutError("timed out")

    def status(self):
        if not self.snapshots:
            return {"generation": 0, "managed_ports": [], "active_instances": []}
        snapshot = self.snapshots[-1]
        managed_port_id = snapshot["ports"][0]["port_id"]
        return {
            "generation": snapshot["generation"],
            "accepted_generation": snapshot["generation"],
            "applied_generation": snapshot["generation"],
            "desired_hash": snapshot.get("desired_hash"),
            "applied_desired_hash": snapshot.get("desired_hash"),
            "managed_ports": [{
                "port_id": managed_port_id,
                "ifname": "tap%s" % managed_port_id[:11],
            }],
            "port_statuses": [{
                "port_id": managed_port_id,
                "status": "ready",
                "domains": [{"domain": "acl", "status": "ready"}],
            }],
            "active_instances": ["tap%s" % managed_port_id[:11]],
        }


class TimeoutNotConvergedLocalClient(FakeLocalClient):
    def put_snapshot(self, snapshot):
        self.snapshots.append(snapshot)
        raise LocalApiTimeoutError("timed out")

    def status(self):
        return {
            "generation": 0,
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
            return {"generation": 0, "managed_ports": [], "active_instances": []}
        snapshot = self.port_snapshots[-1]["snapshot"]
        port = snapshot["ports"][0]
        acl = port.get("acl") or {}
        return {
            "generation": snapshot["generation"],
            "accepted_generation": snapshot["generation"],
            "applied_generation": snapshot["generation"],
            "desired_hash": snapshot.get("desired_hash"),
            "applied_desired_hash": snapshot.get("desired_hash"),
            "managed_ports": [{
                "port_id": port["port_id"],
                "ifname": "tap%s" % port["port_id"][:11],
            }],
            "port_statuses": [{
                "port_id": port["port_id"],
                "ifname": "tap%s" % port["port_id"][:11],
                "generation": snapshot["generation"],
                "desired_hash": snapshot.get("desired_hash"),
                "status": acl.get("status") or "ready",
                "managed_domains": port.get("managed_domains") or [],
                "domains": [{
                    "domain": "acl",
                    "status": acl.get("status") or "ready",
                    "reason": acl.get("reason"),
                    "effective_action": acl.get("effective_action") or "enforce",
                }],
            }],
            "active_instances": ["tap%s" % port["port_id"][:11]],
        }


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
        if not self.snapshots:
            return {"generation": 0, "managed_ports": [], "active_instances": []}
        snapshot = self.snapshots[-1]
        port_ids = [
            port["port_id"] for port in snapshot["ports"]
            if port.get("eligible") or port.get("managed_domains")
        ]
        managed_ports = [
            {"port_id": port_id, "ifname": "tap%s" % port_id[:11]}
            for port_id in port_ids
        ]
        return {
            "generation": snapshot["generation"],
            "accepted_generation": snapshot["generation"],
            "applied_generation": snapshot["generation"],
            "desired_hash": snapshot.get("desired_hash"),
            "applied_desired_hash": snapshot.get("desired_hash"),
            "managed_ports": managed_ports,
            "port_statuses": [{
                "port_id": port_id,
                "ifname": "tap%s" % port_id[:11],
                "generation": snapshot["generation"],
                "desired_hash": snapshot.get("desired_hash"),
                "status": "ready",
                "managed_domains": ["acl"],
                "domains": [{"domain": "acl", "status": "ready"}],
            } for port_id in port_ids],
            "active_instances": [port["ifname"] for port in managed_ports],
        }


class ConvergedMissingPortStatusLocalClient(FakeLocalClient):
    def status(self):
        if not self.snapshots:
            return {"generation": 0, "managed_ports": [], "active_instances": []}
        snapshot = self.snapshots[-1]
        port_ids = [
            port["port_id"] for port in snapshot["ports"]
            if port.get("eligible") or port.get("managed_domains")
        ]
        return {
            "generation": snapshot["generation"],
            "accepted_generation": snapshot["generation"],
            "applied_generation": snapshot["generation"],
            "desired_hash": snapshot.get("desired_hash"),
            "applied_desired_hash": snapshot.get("desired_hash"),
            "managed_ports": [
                {"port_id": port_id, "ifname": "tap%s" % port_id[:11]}
                for port_id in port_ids
            ],
            "port_statuses": [],
            "active_instances": ["tap%s" % port_id[:11] for port_id in port_ids],
        }


class ConvergedStalePortStatusLocalClient(FakeLocalClient):
    def status(self):
        if not self.snapshots:
            return {"generation": 0, "managed_ports": [], "active_instances": []}
        snapshot = self.snapshots[-1]
        port_ids = [
            port["port_id"] for port in snapshot["ports"]
            if port.get("eligible") or port.get("managed_domains")
        ]
        return {
            "generation": snapshot["generation"],
            "accepted_generation": snapshot["generation"],
            "applied_generation": snapshot["generation"],
            "desired_hash": snapshot.get("desired_hash"),
            "applied_desired_hash": snapshot.get("desired_hash"),
            "managed_ports": [
                {"port_id": port_id, "ifname": "tap%s" % port_id[:11]}
                for port_id in port_ids
            ],
            "port_statuses": [{
                "port_id": port_ids[0],
                "status": "not_requested",
                "effective_action": "bypass",
                "reason": "no_enabled_binding",
                "domains": [{
                    "domain": "acl",
                    "status": "not_requested",
                    "effective_action": "bypass",
                    "reason": "no_enabled_binding",
                }],
            }],
            "active_instances": ["tap%s" % port_id[:11] for port_id in port_ids],
        }


class FixedStatusLocalClient(FakeLocalClient):
    def __init__(self, status):
        FakeLocalClient.__init__(self)
        self.fixed_status = status

    def status(self):
        return self.fixed_status


class StalePendingThenConvergedLocalClient(FakeLocalClient):
    def __init__(self, stale_status):
        FakeLocalClient.__init__(self)
        self.stale_status = stale_status

    def status(self):
        if not self.snapshots:
            return self.stale_status
        snapshot = self.snapshots[-1]
        port_ids = [
            port["port_id"] for port in snapshot["ports"]
            if port.get("eligible") or port.get("managed_domains")
        ]
        return {
            "generation": snapshot["generation"],
            "accepted_generation": snapshot["generation"],
            "applied_generation": snapshot["generation"],
            "desired_hash": snapshot.get("desired_hash"),
            "applied_desired_hash": snapshot.get("desired_hash"),
            "managed_ports": [
                {"port_id": port_id, "ifname": "tap%s" % port_id[:11]}
                for port_id in port_ids
            ],
            "active_instances": ["tap%s" % port_id[:11] for port_id in port_ids],
        }


class SameGenerationMissingManagedClient(FakeLocalClient):
    def __init__(self, generation, desired_hash):
        FakeLocalClient.__init__(self)
        self.generation = generation
        self.desired_hash = desired_hash

    def status(self):
        if self.snapshots:
            snapshot = self.snapshots[-1]
            port_ids = [
                port["port_id"] for port in snapshot["ports"]
                if port.get("eligible") or port.get("managed_domains")
            ]
            return {
                "generation": snapshot["generation"],
                "accepted_generation": snapshot["generation"],
                "applied_generation": snapshot["generation"],
                "desired_hash": snapshot.get("desired_hash"),
                "applied_desired_hash": snapshot.get("desired_hash"),
                "managed_ports": [
                    {"port_id": port_id, "ifname": "tap%s" % port_id[:11]}
                    for port_id in port_ids
                ],
                "active_instances": ["tap%s" % port_id[:11] for port_id in port_ids],
            }
        return {
            "generation": self.generation,
            "accepted_generation": self.generation,
            "applied_generation": self.generation,
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
            return {"generation": 0, "managed_ports": [], "active_instances": []}
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
            return {"generation": 0, "managed_ports": [], "active_instances": []}
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
        return {
            "generation": snapshot["generation"],
            "accepted_generation": snapshot["generation"],
            "applied_generation": snapshot["generation"],
            "desired_hash": snapshot.get("desired_hash"),
            "applied_desired_hash": snapshot.get("desired_hash"),
            "managed_ports": [
                {"port_id": port_id, "ifname": "tap%s" % port_id[:11]}
                for port_id in port_ids
            ],
            "port_statuses": [{
                "port_id": port_id,
                "ifname": "tap%s" % port_id[:11],
                "generation": snapshot["generation"],
                "desired_hash": snapshot.get("desired_hash"),
                "status": "ready",
                "managed_domains": ["acl"],
                "domains": [{"domain": "acl", "status": "ready"}],
            } for port_id in port_ids],
            "active_instances": ["tap%s" % port_id[:11] for port_id in port_ids],
        }


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
                state_store=SnapshotStateStore(state_dir),
                timeout_convergence_attempts=1,
                timeout_convergence_interval=0,
            )
            first.safe_full_resync()
            pending = SnapshotStateStore(state_dir).pending_snapshot()
            status = {
                "generation": pending["generation"],
                "accepted_generation": pending["generation"],
                "applied_generation": pending["generation"],
                "desired_hash": pending["desired_hash"],
                "applied_desired_hash": pending["desired_hash"],
                "managed_ports": [{"port_id": port_id, "ifname": "tapaaaaaaaa-aa"}],
                "port_statuses": [{
                    "port_id": port_id,
                    "ifname": "tapaaaaaaaa-aa",
                    "generation": pending["generation"],
                    "desired_hash": pending["desired_hash"],
                    "status": "ready",
                    "managed_domains": ["acl"],
                    "domains": [{"domain": "acl", "status": "ready"}],
                }],
                "active_instances": ["tapaaaaaaaa-aa"],
            }
            second_client = FixedStatusLocalClient(status)
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
            self.assertFalse(result["response"].get("recovered_before_submit"))
            self.assertEqual(None, state["pending_generation"])
            self.assertEqual(pending["generation"], state["last_generation"])
            self.assertEqual([port_id], state["last_projected_port_ids"])
            self.assertEqual("ready", result["status"]["last_port_statuses"][0]["status"])
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
            "ready",
            result["status"]["last_port_statuses"][0]["domains"][0]["status"],
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

    def test_full_resync_synthesizes_acl_status_when_datapath_status_lags(self):
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

        result = sync.full_resync()

        port_status = result["status"]["last_port_statuses"][0]
        self.assertEqual(port_id, port_status["port_id"])
        self.assertEqual("ready", port_status["status"])
        self.assertEqual("enforce", port_status["effective_action"])
        self.assertEqual("ready", port_status["reason"])
        self.assertEqual("acl-policy", port_status["policy_id"])
        self.assertEqual("acl-binding", port_status["binding_id"])
        self.assertEqual("ready", port_status["domains"][0]["status"])

    def test_full_resync_refreshes_stale_not_requested_acl_status(self):
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

        result = sync.full_resync()

        port_status = result["status"]["last_port_statuses"][0]
        self.assertEqual("ready", port_status["status"])
        self.assertEqual("enforce", port_status["effective_action"])
        self.assertEqual("ready", port_status["reason"])
        self.assertEqual("ready", port_status["domains"][0]["status"])
        self.assertEqual("enforce", port_status["domains"][0]["effective_action"])

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

    def test_apply_port_scoped_snapshot_preserves_acl_degraded_bypass_status(self):
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
        acl_index = EffectiveAclIndex(
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
            acl_index=acl_index,
        )
        sync.full_resync()
        neutron_ports[0]["revision_number"] = 8

        result = sync.apply_port_scoped_snapshot(
            port_id,
            binding_host="ostack2",
            revision_number=8,
        )

        submitted = local_client.port_snapshots[0]["snapshot"]["ports"][0]
        acl = submitted["acl"]
        self.assertTrue(result["submitted"])
        self.assertEqual("degraded", acl["status"])
        self.assertEqual("bypass", acl["effective_action"])
        self.assertIn("invalid_rule_priority:bad-rule", acl["reason"])
        self.assertEqual(
            [{"reason": "invalid_rule_priority:bad-rule", "count": 1}],
            result["status"]["degraded_reasons"],
        )
        self.assertIn({
            "domain": "acl",
            "status": "degraded",
            "effective_action": "bypass",
            "count": 1,
        }, result["status"]["domain_counts"])

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
                policies=[{"id": "policy-v2", "default_action": "deny"}],
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

    def test_timeout_recovery_accepts_committed_hash_with_partial_managed_ports(self):
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

        result = sync.full_resync()

        self.assertTrue(result["response"]["recovered_after_timeout"])
        self.assertTrue(result["status"]["ready"])
        self.assertFalse(result["status"]["degraded"])
        self.assertEqual(2, result["status"]["last_snapshot_ports"])
        self.assertEqual(1, result["status"]["last_managed_ports"])
        self.assertEqual(1, len(result["status"]["last_port_statuses"]))
        self.assertEqual(set(port_ids), sync.projected_port_ids)

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
