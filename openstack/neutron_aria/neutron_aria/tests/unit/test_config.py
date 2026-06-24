from __future__ import absolute_import

import os
import tempfile
import unittest

from neutron_aria.agent.config import load_config


class ConfigTestCase(unittest.TestCase):
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

[ovs]
bridge = br-int

[aria]
socket_path = /run/aria/aria-agent.sock
request_timeout = 2.5

[neutron]
port_source = neutronclient
port_page_size = 50
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
            self.assertEqual("neutronclient", config.port_source)
            self.assertEqual(50, config.port_page_size)
            self.assertEqual("br-int", config.ovs_bridge)
            self.assertEqual("/run/aria/aria-agent.sock", config.socket_path)
            self.assertEqual(2.5, config.request_timeout)
        finally:
            if fd is not None:
                os.close(fd)
            os.unlink(path)


if __name__ == "__main__":
    unittest.main()
