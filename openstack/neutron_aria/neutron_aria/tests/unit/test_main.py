from __future__ import absolute_import

import os
import shutil
import tempfile
import unittest

from neutron_aria.agent.config import AgentConfig
from neutron_aria.agent.config import ConfigError
from neutron_aria.agent import main as agent_main
from neutron_aria.agent.status_reporter import CompositeStatusReporter
from neutron_aria.agent.main import build_synchronizer
from neutron_aria.agent.neutron_client import StaticPortSource


class FakeRuntimeStatus(object):
    def to_dict(self):
        return {}


class FakeService(object):
    created = []

    def __init__(self, synchronizer, **kwargs):
        self.synchronizer = synchronizer
        self.kwargs = kwargs
        FakeService.created.append(self)

    def run_forever(self):
        raise KeyboardInterrupt()


class FakeLocalClient(object):
    def __init__(self):
        self.snapshots = []

    def capabilities(self, required_domains=None):
        return {"api_version": "v1"}

    def put_snapshot(self, snapshot):
        self.snapshots.append(snapshot)
        return {"generation": snapshot["generation"], "results": []}

    def status(self):
        if not self.snapshots:
            return {"generation": 0, "managed_ports": [], "active_instances": []}

        snapshot = self.snapshots[-1]
        managed_ports = []
        port_statuses = []
        for port in snapshot.get("ports") or []:
            if not (port.get("eligible") or port.get("managed_domains")):
                continue
            port_id = port["port_id"]
            ifname = port.get("ifname") or "tap%s" % port_id[:11]
            domains = []
            for domain in port.get("managed_domains") or []:
                if domain == "acl":
                    acl = port.get("acl") or {}
                    domain_status = acl.get("status") or "ready"
                    domain_reason = acl.get("reason")
                    effective_action = (
                        acl.get("effective_action") or
                        ("enforce" if domain_status == "ready" else "bypass")
                    )
                else:
                    domain_status = "ready"
                    domain_reason = None
                    effective_action = None
                domains.append({
                    "domain": domain,
                    "status": domain_status,
                    "reason": domain_reason,
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
                "managed_domains": list(port.get("managed_domains") or []),
                "domains": domains,
            })
        return {
            "generation": snapshot["generation"],
            "accepted_generation": snapshot["generation"],
            "applied_generation": snapshot["generation"],
            "pending_generation": None,
            "desired_hash": snapshot.get("desired_hash"),
            "applied_desired_hash": snapshot.get("desired_hash"),
            "wal_status": "commit_written",
            "wal_replay_failures": 0,
            "authority_state": "ready",
            "managed_ports": managed_ports,
            "port_statuses": port_statuses,
            "active_instances": [port["ifname"] for port in managed_ports],
        }


class FakeAriaAclClient(object):
    def __init__(self):
        self.calls = []

    def get_aria_acl_effective_payload(self):
        self.calls.append("get_aria_acl_effective_payload")
        return {
            "policies": [{
                "id": "policy-prod",
                "name": "production-acl",
                "default_action": "allow",
                "stateful": True,
            }],
            "rules": [{
                "id": "allow-ssh",
                "policy_id": "policy-prod",
                "direction": "ingress",
                "priority": 100,
                "action": "allow",
                "ethertype": "IPv4",
                "protocol": "tcp",
                "dst_port_min": 22,
                "dst_port_max": 22,
                "src_cidr": "10.58.159.2/32",
            }],
            "address_sets": [],
            "bindings": [{
                "id": "bind-prod",
                "policy_id": "policy-prod",
                "target_type": "network",
                "target_id": "net-prod",
            }],
        }


class MainBuildSynchronizerTestCase(unittest.TestCase):
    def _write_config(self, body):
        fd, path = tempfile.mkstemp()
        os.write(fd, body.encode("utf-8"))
        os.close(fd)
        return path

    def test_once_status_reporter_disabled_for_non_neutron_acl_source(self):
        self.assertEqual(
            None,
            agent_main.build_once_status_reporter(AgentConfig(acl_source="disabled")),
        )

    def test_cli_rpc_enable_respects_runtime_config_gate(self):
        path = self._write_config("""
[agent]
full_resync_enabled = false

[neutron]
port_source = neutronclient
""")
        try:
            self.assertRaises(
                ConfigError,
                agent_main.main,
                ["-c", path, "--enable-rpc-events", "--report-once"],
            )
        finally:
            os.unlink(path)

    def test_rpc_main_enables_eventlet_before_consumers(self):
        path = self._write_config("""
[agent]
full_resync_enabled = true

[neutron]
port_source = neutronclient
rpc_events_enabled = true
""")
        calls = []
        original_enable_eventlet = agent_main.enable_eventlet_for_rpc
        original_initialize = agent_main.initialize_neutron_runtime
        original_build_connection = agent_main.build_rpc_connection
        original_start_consumers = agent_main.start_rpc_consumers
        original_build_synchronizer = agent_main.build_synchronizer
        original_build_reporter = agent_main.build_neutron_status_reporter
        original_service = agent_main.AgentService
        try:
            def fake_enable_eventlet():
                calls.append("eventlet")
                return True

            def fake_initialize(config_files=None):
                calls.append("initialize")
                return True

            def fake_build_connection(callback, start_listening=False):
                calls.append("build_connection")
                return object()

            def fake_start_consumers(connection):
                calls.append("start_consumers")
                return []

            def fake_build_synchronizer(config, status_reporter=None):
                calls.append("build_synchronizer")
                return object()

            def fake_build_reporter(host, config):
                calls.append("build_reporter")
                return None

            FakeService.created = []
            agent_main.enable_eventlet_for_rpc = fake_enable_eventlet
            agent_main.initialize_neutron_runtime = fake_initialize
            agent_main.build_rpc_connection = fake_build_connection
            agent_main.start_rpc_consumers = fake_start_consumers
            agent_main.build_synchronizer = fake_build_synchronizer
            agent_main.build_neutron_status_reporter = fake_build_reporter
            agent_main.AgentService = FakeService

            result = agent_main.main(["-c", path])

            self.assertEqual(0, result)
            self.assertTrue(
                calls.index("eventlet") < calls.index("initialize")
            )
            self.assertTrue(
                calls.index("eventlet") < calls.index("start_consumers")
            )
            self.assertEqual(1, len(FakeService.created))
            self.assertTrue(FakeService.created[0].kwargs["full_resync_enabled"])
        finally:
            agent_main.enable_eventlet_for_rpc = original_enable_eventlet
            agent_main.initialize_neutron_runtime = original_initialize
            agent_main.build_rpc_connection = original_build_connection
            agent_main.start_rpc_consumers = original_start_consumers
            agent_main.build_synchronizer = original_build_synchronizer
            agent_main.build_neutron_status_reporter = original_build_reporter
            agent_main.AgentService = original_service
            os.unlink(path)

    def test_once_status_reporter_enabled_for_neutron_acl_source(self):
        calls = []
        original_init = agent_main.initialize_neutron_runtime
        original_builder = agent_main.build_neutron_status_reporter
        try:
            def fake_initialize(config_files=None):
                calls.append(("initialize", list(config_files or [])))
                return True

            def fake_build(host, config):
                calls.append(("build", host, config.acl_source))
                return CompositeStatusReporter()

            agent_main.initialize_neutron_runtime = fake_initialize
            agent_main.build_neutron_status_reporter = fake_build

            reporter = agent_main.build_once_status_reporter(
                AgentConfig(host="ostack2", acl_source="neutron"),
                neutron_config_files=["/etc/neutron/neutron.conf"],
            )

            self.assertIsInstance(reporter, CompositeStatusReporter)
            self.assertEqual([
                ("initialize", ["/etc/neutron/neutron.conf"]),
                ("build", "ostack2", "neutron"),
            ], calls)
        finally:
            agent_main.initialize_neutron_runtime = original_init
            agent_main.build_neutron_status_reporter = original_builder

    def test_neutron_acl_source_builds_datapath_snapshot(self):
        state_dir = tempfile.mkdtemp()
        try:
            local_client = FakeLocalClient()
            acl_client = FakeAriaAclClient()
            config = AgentConfig(
                host="ostack2",
                managed_domains=["acl"],
                acl_source="neutron",
                state_dir=state_dir,
            )
            port_source = StaticPortSource([{
                "id": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
                "network_id": "net-prod",
                "device_owner": "compute:nova",
                "binding:host_id": "ostack2",
                "binding:vif_type": "ovs",
                "binding:vnic_type": "normal",
            }])

            sync = build_synchronizer(
                config,
                neutron_port_source=port_source,
                neutron_acl_client=acl_client,
                local_client=local_client,
            )
            sync.full_resync()

            self.assertEqual(["get_aria_acl_effective_payload"], acl_client.calls)
            port = local_client.snapshots[0]["ports"][0]
            self.assertEqual("policy-prod", port["acl"]["policy_id"])
            self.assertEqual("production-acl", port["acl"]["policy_name"])
            self.assertEqual("enforce", port["acl"]["effective_action"])
            self.assertEqual("allow-ssh", port["acl"]["rules"][0]["id"])
        finally:
            shutil.rmtree(state_dir)


if __name__ == "__main__":
    unittest.main()
