from __future__ import absolute_import

import json
import os
import tempfile
import unittest

from neutron_aria.agent.acl_source import AclSourceError
from neutron_aria.agent.acl_source import DisabledAclSource
from neutron_aria.agent.acl_source import FixtureAclSource
from neutron_aria.agent.acl_source import NeutronAclSource
from neutron_aria.agent.acl_source import build_acl_index
from neutron_aria.agent.acl_source import build_acl_source
from neutron_aria.agent.config import AgentConfig


class AclSourceTestCase(unittest.TestCase):
    def test_disabled_source_returns_no_index(self):
        source = build_acl_source(AgentConfig(acl_source="disabled"))

        self.assertIsInstance(source, DisabledAclSource)
        self.assertEqual(None, source.load_index())

    def test_fixture_source_loads_effective_index(self):
        fd, path = tempfile.mkstemp()
        try:
            payload = {
                "policies": [{"id": "policy-1", "default_action": "allow"}],
                "rules": [{
                    "id": "rule-1",
                    "policy_id": "policy-1",
                    "direction": "ingress",
                    "priority": 100,
                    "action": "drop",
                    "protocol": "icmp",
                    "src_cidr": "10.58.159.2/32",
                }],
                "bindings": [{
                    "id": "binding-1",
                    "policy_id": "policy-1",
                    "target_type": "port",
                    "target_id": "port-1",
                }],
            }
            os.write(fd, json.dumps(payload).encode("utf-8"))
            os.close(fd)
            fd = None

            source = build_acl_source(AgentConfig(acl_fixture_path=path))
            index = source.load_index()
            result = index.effective_for_port({"id": "port-1"}, {"eligible": True})

            self.assertIsInstance(source, FixtureAclSource)
            self.assertTrue(result["enabled"])
            self.assertEqual("policy-1", result["policy_id"])
            self.assertEqual("rule-1", result["rules"][0]["id"])
        finally:
            if fd is not None:
                os.close(fd)
            os.unlink(path)

    def test_build_acl_index_keeps_fixture_compatibility(self):
        fd, path = tempfile.mkstemp()
        try:
            os.write(fd, b'{"policies": [], "rules": [], "bindings": []}')
            os.close(fd)
            fd = None

            self.assertIsNotNone(build_acl_index(AgentConfig(acl_fixture_path=path)))
        finally:
            if fd is not None:
                os.close(fd)
            os.unlink(path)

    def test_neutron_source_is_explicitly_not_ready_without_server_extension(self):
        source = build_acl_source(AgentConfig(acl_source="neutron"))

        self.assertIsInstance(source, NeutronAclSource)
        self.assertRaises(AclSourceError, source.load_index)

    def test_unknown_source_fails_fast(self):
        self.assertRaises(
            AclSourceError,
            build_acl_source,
            AgentConfig(acl_source="unknown"),
        )


if __name__ == "__main__":
    unittest.main()
