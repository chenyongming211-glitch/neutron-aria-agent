from __future__ import absolute_import

import os
import tempfile
import unittest

from neutron_aria.agent.config import ConfigError
from neutron_aria.agent.config import load_config
from neutron_aria.agent.config import sync_mode


class ConfigTestCase(unittest.TestCase):
    def _write_config(self, body):
        fd, path = tempfile.mkstemp()
        os.write(fd, body.encode("utf-8"))
        os.close(fd)
        return path

    def test_loads_service_loop_options(self):
        fd, path = tempfile.mkstemp()
        try:
            os.write(fd, b"""
[agent]
host = ostack2.bj159.net
managed_domains = acl,qos
resync_interval = 120
report_interval = 15
full_resync_enabled = true
resync_backoff_initial = 7
resync_backoff_max = 77
state_dir = /tmp/neutron-aria-state

[ovs]
bridge = br-int

[aria]
socket_path = /run/aria/aria-agent.sock
request_timeout = 2.5
timeout_convergence_attempts = 4
timeout_convergence_interval = 0.4

[neutron]
port_source = neutronclient
port_page_size = 50
rpc_events_enabled = true
incremental_rpc_enabled = false
revisionless_incremental_mode = disabled
event_merge_interval = 0.3
event_queue_max_ports = 42
event_queue_max_networks = 7

[acl]
fixture_path = /tmp/aria-acl-fixture.json
""")
            os.close(fd)
            fd = None

            config = load_config(path)

            self.assertEqual("ostack2.bj159.net", config.host)
            self.assertEqual(["acl", "qos"], config.managed_domains)
            self.assertEqual(120, config.resync_interval)
            self.assertEqual(15, config.report_interval)
            self.assertTrue(config.full_resync_enabled)
            self.assertEqual(7, config.resync_backoff_initial)
            self.assertEqual(77, config.resync_backoff_max)
            self.assertEqual("/tmp/neutron-aria-state", config.state_dir)
            self.assertEqual("neutronclient", config.port_source)
            self.assertEqual(50, config.port_page_size)
            self.assertTrue(config.rpc_events_enabled)
            self.assertFalse(config.incremental_rpc_enabled)
            self.assertEqual("disabled", config.revisionless_incremental_mode)
            self.assertEqual(0.3, config.event_merge_interval)
            self.assertEqual(42, config.event_queue_max_ports)
            self.assertEqual(7, config.event_queue_max_networks)
            self.assertEqual("fixture", config.acl_source)
            self.assertEqual("/tmp/aria-acl-fixture.json", config.acl_fixture_path)
            self.assertEqual("br-int", config.ovs_bridge)
            self.assertEqual("/run/aria/aria-agent.sock", config.socket_path)
            self.assertEqual(2.5, config.request_timeout)
            self.assertEqual(4, config.timeout_convergence_attempts)
            self.assertEqual(0.4, config.timeout_convergence_interval)
        finally:
            if fd is not None:
                os.close(fd)
            os.unlink(path)

    def test_defaults_acl_source_to_disabled_without_fixture(self):
        fd, path = tempfile.mkstemp()
        try:
            os.close(fd)
            fd = None

            config = load_config(path)

            self.assertEqual("disabled", config.acl_source)
            self.assertEqual("", config.acl_fixture_path)
        finally:
            if fd is not None:
                os.close(fd)
            os.unlink(path)

    def test_loads_target_ovs_integration_bridge_key(self):
        path = self._write_config("""
[ovs]
integration_bridge = br-int-target
""")
        try:
            config = load_config(path)

            self.assertEqual("br-int-target", config.ovs_bridge)
        finally:
            os.unlink(path)

    def test_normalizes_and_deduplicates_managed_domains(self):
        path = self._write_config("""
[agent]
managed_domains = ACL, qos, acl
""")
        try:
            config = load_config(path)

            self.assertEqual(["acl", "qos"], config.managed_domains)
        finally:
            os.unlink(path)

    def test_rejects_unknown_managed_domain(self):
        path = self._write_config("""
[agent]
managed_domains = acl,ssl
""")
        try:
            self.assertRaises(ConfigError, load_config, path)
        finally:
            os.unlink(path)

    def test_rejects_integration_mode_in_ini(self):
        path = self._write_config("""
[aria]
integration_mode = coexist
""")
        try:
            self.assertRaises(ConfigError, load_config, path)
        finally:
            os.unlink(path)

    def test_rejects_integration_mode_in_default_section(self):
        path = self._write_config("""
[DEFAULT]
integration_mode = coexist
""")
        try:
            self.assertRaises(ConfigError, load_config, path)
        finally:
            os.unlink(path)

    def test_rejects_fixture_acl_source_without_path(self):
        path = self._write_config("""
[acl]
source = fixture
""")
        try:
            self.assertRaises(ConfigError, load_config, path)
        finally:
            os.unlink(path)

    def test_rejects_full_resync_with_disabled_port_source(self):
        path = self._write_config("""
[agent]
full_resync_enabled = true

[neutron]
port_source = disabled
""")
        try:
            self.assertRaises(ConfigError, load_config, path)
        finally:
            os.unlink(path)

    def test_rejects_invalid_full_resync_boolean(self):
        path = self._write_config("""
[agent]
full_resync_enabled = ture
""")
        try:
            with self.assertRaises(ConfigError) as ctx:
                load_config(path)
            self.assertIn("agent.full_resync_enabled", str(ctx.exception))
            self.assertIn("ture", str(ctx.exception))
        finally:
            os.unlink(path)

    def test_rejects_invalid_rpc_events_boolean(self):
        path = self._write_config("""
[agent]
full_resync_enabled = true

[neutron]
port_source = neutronclient
rpc_events_enabled = maybe
""")
        try:
            with self.assertRaises(ConfigError) as ctx:
                load_config(path)
            self.assertIn("neutron.rpc_events_enabled", str(ctx.exception))
            self.assertIn("maybe", str(ctx.exception))
        finally:
            os.unlink(path)

    def test_rejects_invalid_incremental_rpc_boolean(self):
        path = self._write_config("""
[agent]
full_resync_enabled = true

[neutron]
port_source = neutronclient
rpc_events_enabled = true
incremental_rpc_enabled = enable
""")
        try:
            with self.assertRaises(ConfigError) as ctx:
                load_config(path)
            self.assertIn("neutron.incremental_rpc_enabled", str(ctx.exception))
            self.assertIn("enable", str(ctx.exception))
        finally:
            os.unlink(path)

    def test_rejects_rpc_events_without_full_resync(self):
        path = self._write_config("""
[agent]
full_resync_enabled = false

[neutron]
port_source = neutronclient
rpc_events_enabled = true
""")
        try:
            self.assertRaises(ConfigError, load_config, path)
        finally:
            os.unlink(path)

    def test_rejects_rpc_events_without_neutronclient_port_source(self):
        path = self._write_config("""
[agent]
full_resync_enabled = true

[neutron]
port_source = disabled
rpc_events_enabled = true
""")
        try:
            self.assertRaises(ConfigError, load_config, path)
        finally:
            os.unlink(path)

    def test_allows_incremental_rpc_when_p3_dependencies_are_enabled(self):
        path = self._write_config("""
[agent]
full_resync_enabled = true

[neutron]
port_source = neutronclient
rpc_events_enabled = true
incremental_rpc_enabled = true
""")
        try:
            config = load_config(path)

            self.assertTrue(config.incremental_rpc_enabled)
        finally:
            os.unlink(path)

    def test_allows_revisionless_incremental_experimental_when_incremental_enabled(self):
        path = self._write_config("""
[agent]
full_resync_enabled = true

[neutron]
port_source = neutronclient
rpc_events_enabled = true
incremental_rpc_enabled = true
revisionless_incremental_mode = experimental
""")
        try:
            config = load_config(path)

            self.assertTrue(config.incremental_rpc_enabled)
            self.assertEqual("experimental", config.revisionless_incremental_mode)
        finally:
            os.unlink(path)

    def test_rejects_revisionless_incremental_without_incremental_rpc(self):
        path = self._write_config("""
[agent]
full_resync_enabled = true

[neutron]
port_source = neutronclient
rpc_events_enabled = true
incremental_rpc_enabled = false
revisionless_incremental_mode = experimental
""")
        try:
            self.assertRaises(ConfigError, load_config, path)
        finally:
            os.unlink(path)

    def test_rejects_unknown_revisionless_incremental_mode(self):
        path = self._write_config("""
[agent]
full_resync_enabled = true

[neutron]
port_source = neutronclient
rpc_events_enabled = true
incremental_rpc_enabled = true
revisionless_incremental_mode = optimistic
""")
        try:
            self.assertRaises(ConfigError, load_config, path)
        finally:
            os.unlink(path)

    def test_sync_mode_reports_heartbeat_only(self):
        path = self._write_config("""
[agent]
full_resync_enabled = false
""")
        try:
            config = load_config(path)

            self.assertEqual("heartbeat_only", sync_mode(config))
        finally:
            os.unlink(path)

    def test_sync_mode_reports_polling_full_resync(self):
        path = self._write_config("""
[agent]
full_resync_enabled = true

[neutron]
port_source = neutronclient
rpc_events_enabled = false
""")
        try:
            config = load_config(path)

            self.assertEqual("polling_full_resync", sync_mode(config))
        finally:
            os.unlink(path)

    def test_sync_mode_reports_rpc_full_resync(self):
        path = self._write_config("""
[agent]
full_resync_enabled = true

[neutron]
port_source = neutronclient
rpc_events_enabled = true
incremental_rpc_enabled = false
""")
        try:
            config = load_config(path)

            self.assertEqual("rpc_full_resync", sync_mode(config))
        finally:
            os.unlink(path)

    def test_sync_mode_reports_rpc_port_scoped(self):
        path = self._write_config("""
[agent]
full_resync_enabled = true

[neutron]
port_source = neutronclient
rpc_events_enabled = true
incremental_rpc_enabled = true
revisionless_incremental_mode = disabled
""")
        try:
            config = load_config(path)

            self.assertEqual("rpc_port_scoped", sync_mode(config))
        finally:
            os.unlink(path)

    def test_sync_mode_reports_revisionless_experimental(self):
        path = self._write_config("""
[agent]
full_resync_enabled = true

[neutron]
port_source = neutronclient
rpc_events_enabled = true
incremental_rpc_enabled = true
revisionless_incremental_mode = experimental
""")
        try:
            config = load_config(path)

            self.assertEqual(
                "rpc_port_scoped_revisionless_experimental",
                sync_mode(config),
            )
        finally:
            os.unlink(path)

    def test_rejects_incremental_rpc_without_rpc_events(self):
        path = self._write_config("""
[agent]
full_resync_enabled = true

[neutron]
port_source = neutronclient
rpc_events_enabled = false
incremental_rpc_enabled = true
""")
        try:
            self.assertRaises(ConfigError, load_config, path)
        finally:
            os.unlink(path)

    def test_rejects_unknown_acl_source(self):
        path = self._write_config("""
[acl]
source = other
""")
        try:
            self.assertRaises(ConfigError, load_config, path)
        finally:
            os.unlink(path)

    def test_rejects_non_positive_request_timeout(self):
        path = self._write_config("""
[aria]
request_timeout = 0
""")
        try:
            self.assertRaises(ConfigError, load_config, path)
        finally:
            os.unlink(path)

    def test_rejects_request_timeout_above_stage_one_contract(self):
        path = self._write_config("""
[aria]
request_timeout = 5
""")
        try:
            self.assertRaises(ConfigError, load_config, path)
        finally:
            os.unlink(path)


if __name__ == "__main__":
    unittest.main()
