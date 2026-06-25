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
        self.deleted_ports = []

    def capabilities(self, required_domains=None):
        self.capability_calls.append(list(required_domains or []))
        return {"api_version": "v1"}

    def put_snapshot(self, snapshot):
        self.snapshots.append(snapshot)
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


class FixedStatusLocalClient(FakeLocalClient):
    def __init__(self, status):
        FakeLocalClient.__init__(self)
        self.fixed_status = status

    def status(self):
        return self.fixed_status


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

    def test_pending_snapshot_recovered_on_restart_before_resubmit(self):
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

            self.assertEqual([], second_client.snapshots)
            self.assertTrue(result["response"]["recovered_before_submit"])
            self.assertEqual(None, state["pending_generation"])
            self.assertEqual(pending["generation"], state["last_generation"])
            self.assertEqual([port_id], state["last_projected_port_ids"])
            self.assertEqual("ready", result["status"]["last_port_statuses"][0]["status"])
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
