from __future__ import absolute_import

import shutil
import tempfile
import unittest

from neutron_aria.agent.config import AgentConfig
from neutron_aria.agent import main as agent_main
from neutron_aria.agent.status_reporter import CompositeStatusReporter
from neutron_aria.agent.main import build_synchronizer
from neutron_aria.agent.neutron_client import StaticPortSource


class FakeLocalClient(object):
    def __init__(self):
        self.snapshots = []

    def capabilities(self, required_domains=None):
        return {"api_version": "v1"}

    def put_snapshot(self, snapshot):
        self.snapshots.append(snapshot)
        return {"generation": snapshot["generation"], "results": []}

    def status(self):
        return {"generation": 0, "managed_ports": [], "active_instances": []}


class FakeAriaAclClient(object):
    def __init__(self):
        self.calls = []

    def get_aria_acl_effective_payload(self):
        self.calls.append("get_aria_acl_effective_payload")
        return {
            "policies": [{
                "id": "policy-prod",
                "name": "production-acl",
                "default_action": "deny",
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
    def test_once_status_reporter_disabled_for_non_neutron_acl_source(self):
        self.assertEqual(
            None,
            agent_main.build_once_status_reporter(AgentConfig(acl_source="disabled")),
        )

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
