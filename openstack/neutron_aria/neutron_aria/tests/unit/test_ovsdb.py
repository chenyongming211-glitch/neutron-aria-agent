from __future__ import absolute_import

import json
import unittest

from neutron_aria.agent.ovsdb import parse_ovs_interfaces_json


class OvsdbParserTestCase(unittest.TestCase):
    def test_parse_ovs_interfaces_json_decodes_external_ids(self):
        payload = json.dumps({
            "headings": ["name", "ofport", "external_ids"],
            "data": [[
                "tape607e86b-9e",
                3,
                ["map", [
                    ["iface-id", "e607e86b-9e5f-4c63-a5df-3dc8986a1b0f"],
                    ["attached-mac", "fa:16:3e:00:00:01"],
                ]],
            ]],
        })

        interfaces = parse_ovs_interfaces_json(
            payload,
            ifindex_lookup=lambda _name: 27,
            bridge_name="br-int",
            bridge_port_names=["tape607e86b-9e"],
        )

        self.assertEqual(1, len(interfaces))
        self.assertEqual("tape607e86b-9e", interfaces[0].name)
        self.assertEqual(3, interfaces[0].ofport)
        self.assertEqual(27, interfaces[0].ifindex)
        self.assertEqual("br-int", interfaces[0].bridge)
        self.assertEqual(
            "e607e86b-9e5f-4c63-a5df-3dc8986a1b0f",
            interfaces[0].external_ids["iface-id"],
        )

    def test_parse_ovs_interfaces_marks_non_bridge_member(self):
        payload = json.dumps({
            "headings": ["name", "ofport", "external_ids"],
            "data": [[
                "tap-not-br-int",
                4,
                ["map", [["iface-id", "port-1"]]],
            ]],
        })

        interfaces = parse_ovs_interfaces_json(
            payload,
            bridge_name="br-int",
            bridge_port_names=["other-port"],
        )

        self.assertEqual(None, interfaces[0].bridge)


if __name__ == "__main__":
    unittest.main()
