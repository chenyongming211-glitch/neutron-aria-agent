from __future__ import absolute_import

import unittest

from neutron_aria.agent.inventory import ELIGIBLE_OVS_TAP
from neutron_aria.agent.inventory import OVS_BRIDGE_MISMATCH
from neutron_aria.agent.inventory import PortInventoryBuilder
from neutron_aria.agent.inventory import TAP_NOT_FOUND
from neutron_aria.agent.ovsdb import OvsInterface


VM_PORT = "e607e86b-9e5f-4c63-a5df-3dc8986a1b0f"
DHCP_PORT = "11111111-2222-3333-4444-555555555555"
SRIOV_PORT = "22222222-3333-4444-5555-666666666666"
REMOTE_PORT = "33333333-4444-5555-6666-777777777777"
MISSING_TAP_PORT = "44444444-5555-6666-7777-888888888888"


def neutron_port(port_id, host="ostack2", owner="compute:nova", vif_type="ovs", vnic_type="normal"):
    return {
        "id": port_id,
        "device_owner": owner,
        "binding:host_id": host,
        "binding:vif_type": vif_type,
        "binding:vnic_type": vnic_type,
    }


class AgentInventoryTestCase(unittest.TestCase):
    def test_snapshot_marks_only_regular_ovs_vm_tap_eligible(self):
        interfaces = [
            OvsInterface(
                "tape607e86b-9e",
                external_ids={"iface-id": VM_PORT},
                ifindex=27,
                bridge="br-int",
            ),
            OvsInterface(
                "tap11111111-22",
                external_ids={"iface-id": DHCP_PORT},
                ifindex=28,
                bridge="br-int",
            ),
        ]
        ports = [
            neutron_port(VM_PORT),
            neutron_port(DHCP_PORT, owner="network:dhcp"),
            neutron_port(SRIOV_PORT, vif_type="hw_veb", vnic_type="direct"),
            neutron_port(REMOTE_PORT, host="ostack3"),
            neutron_port(MISSING_TAP_PORT),
        ]

        builder = PortInventoryBuilder(
            "ostack2",
            managed_domains=["acl"],
            ifindex_lookup=lambda _name: 99,
        )
        snapshot = builder.build_snapshot(ports, interfaces, generation=7)
        by_port = dict((entry["port_id"], entry) for entry in snapshot["ports"])

        self.assertEqual(7, snapshot["generation"])
        self.assertEqual("ostack2", snapshot["host"])
        self.assertNotIn(REMOTE_PORT, by_port)

        vm_entry = by_port[VM_PORT]
        self.assertTrue(vm_entry["eligible"])
        self.assertEqual(ELIGIBLE_OVS_TAP, vm_entry["disposition"])
        self.assertEqual("tape607e86b-9e", vm_entry["ifname"])
        self.assertEqual(27, vm_entry["ifindex"])
        self.assertEqual(["acl"], vm_entry["managed_domains"])

        dhcp_entry = by_port[DHCP_PORT]
        self.assertFalse(dhcp_entry["eligible"])
        self.assertEqual("not_applicable_device_owner:network:dhcp", dhcp_entry["disposition"])
        self.assertEqual([], dhcp_entry["managed_domains"])

        sriov_entry = by_port[SRIOV_PORT]
        self.assertFalse(sriov_entry["eligible"])
        self.assertEqual("unsupported_vif_type:hw_veb", sriov_entry["disposition"])

        missing_entry = by_port[MISSING_TAP_PORT]
        self.assertFalse(missing_entry["eligible"])
        self.assertEqual(TAP_NOT_FOUND, missing_entry["disposition"])
        self.assertEqual("tap44444444-55", missing_entry["ifname"])

    def test_snapshot_rejects_iface_id_not_on_br_int(self):
        interfaces = [
            OvsInterface(
                "tape607e86b-9e",
                external_ids={"iface-id": VM_PORT},
                ifindex=27,
                bridge=None,
            ),
        ]
        builder = PortInventoryBuilder(
            "ostack2",
            managed_domains=["acl"],
            ifindex_lookup=lambda _name: 27,
            ovs_bridge="br-int",
        )

        snapshot = builder.build_snapshot([neutron_port(VM_PORT)], interfaces, generation=8)
        port = snapshot["ports"][0]

        self.assertFalse(port["eligible"])
        self.assertEqual(OVS_BRIDGE_MISMATCH + ":br-int", port["disposition"])
        self.assertEqual([], port["managed_domains"])


if __name__ == "__main__":
    unittest.main()
