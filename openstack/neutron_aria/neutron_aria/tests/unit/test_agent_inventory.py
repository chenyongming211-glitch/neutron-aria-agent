from __future__ import absolute_import

import unittest

from neutron_aria.agent.inventory import ELIGIBLE_OVS_TAP
from neutron_aria.agent.inventory import OVS_BRIDGE_MISMATCH
from neutron_aria.agent.inventory import PENDING_LOCAL_VALIDATION
from neutron_aria.agent.inventory import PortCandidateBuilder
from neutron_aria.agent.inventory import PortInventoryBuilder
from neutron_aria.agent.inventory import PortScopedSnapshotBuilder
from neutron_aria.agent.inventory import TAP_NOT_FOUND
from neutron_aria.agent.ovsdb import OvsInterface
from neutron_aria.agent.effective_acl import EffectiveAclIndex
from neutron_aria.agent.effective_qos import EffectiveQosIndex


VM_PORT = "e607e86b-9e5f-4c63-a5df-3dc8986a1b0f"
DHCP_PORT = "11111111-2222-3333-4444-555555555555"
SRIOV_PORT = "22222222-3333-4444-5555-666666666666"
REMOTE_PORT = "33333333-4444-5555-6666-777777777777"
MISSING_TAP_PORT = "44444444-5555-6666-7777-888888888888"


def neutron_port(port_id, host="compute-1", owner="compute:nova", vif_type="ovs", vnic_type="normal"):
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
            neutron_port(REMOTE_PORT, host="compute-2"),
            neutron_port(MISSING_TAP_PORT),
        ]

        builder = PortInventoryBuilder(
            "compute-1",
            managed_domains=["acl"],
            ifindex_lookup=lambda _name: 99,
        )
        snapshot = builder.build_snapshot(ports, interfaces, generation=7)
        by_port = dict((entry["port_id"], entry) for entry in snapshot["ports"])

        self.assertEqual(7, snapshot["generation"])
        self.assertEqual("compute-1", snapshot["host"])
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
            "compute-1",
            managed_domains=["acl"],
            ifindex_lookup=lambda _name: 27,
            ovs_bridge="br-int",
        )

        snapshot = builder.build_snapshot([neutron_port(VM_PORT)], interfaces, generation=8)
        port = snapshot["ports"][0]

        self.assertFalse(port["eligible"])
        self.assertEqual(OVS_BRIDGE_MISMATCH + ":br-int", port["disposition"])
        self.assertEqual([], port["managed_domains"])

    def test_snapshot_can_include_effective_acl_and_qos_extensions(self):
        interfaces = [
            OvsInterface(
                "tape607e86b-9e",
                external_ids={"iface-id": VM_PORT},
                ifindex=27,
                bridge="br-int",
            ),
        ]
        port = neutron_port(VM_PORT)
        port["network_id"] = "net-1"
        port["qos_policy_id"] = "qos-port"
        acl_index = EffectiveAclIndex(
            policies=[{"id": "acl-port", "default_action": "allow"}],
            bindings=[
                {
                    "id": "acl-binding",
                    "policy_id": "acl-port",
                    "target_type": "port",
                    "target_id": VM_PORT,
                },
            ],
        )
        qos_index = EffectiveQosIndex(
            policies=[
                {
                    "id": "qos-port",
                    "rules": [{"id": "qos-rule", "max_kbps": 100000}],
                },
            ],
        )
        builder = PortInventoryBuilder(
            "compute-1",
            managed_domains=["acl", "qos"],
            ifindex_lookup=lambda _name: 27,
            acl_index=acl_index,
            qos_index=qos_index,
        )

        snapshot = builder.build_snapshot([port], interfaces, generation=9)
        vm_entry = snapshot["ports"][0]

        self.assertEqual(["acl", "qos"], vm_entry["managed_domains"])
        self.assertEqual("acl-port", vm_entry["acl"]["policy_id"])
        self.assertEqual("qos-port", vm_entry["qos"]["policy_id"])
        self.assertEqual(100000, vm_entry["qos"]["rules"][0]["max_kbps"])

    def test_candidate_snapshot_defers_local_tap_validation_to_datapath(self):
        ports = [
            neutron_port(VM_PORT),
            neutron_port(DHCP_PORT, owner="network:dhcp"),
            neutron_port(SRIOV_PORT, vif_type="hw_veb", vnic_type="direct"),
            neutron_port(REMOTE_PORT, host="compute-2"),
        ]
        builder = PortCandidateBuilder("compute-1", managed_domains=["acl"])

        snapshot = builder.build_snapshot(ports, generation=10)
        by_port = dict((entry["port_id"], entry) for entry in snapshot["ports"])

        self.assertEqual(10, snapshot["generation"])
        self.assertNotIn(REMOTE_PORT, by_port)

        vm_entry = by_port[VM_PORT]
        self.assertTrue(vm_entry["eligible"])
        self.assertEqual(PENDING_LOCAL_VALIDATION, vm_entry["disposition"])
        self.assertEqual("", vm_entry["ifname"])
        self.assertEqual(None, vm_entry["ifindex"])
        self.assertEqual(None, vm_entry["ovs_iface_id"])
        self.assertEqual(["acl"], vm_entry["managed_domains"])

        dhcp_entry = by_port[DHCP_PORT]
        self.assertFalse(dhcp_entry["eligible"])
        self.assertEqual("not_applicable_device_owner:network:dhcp", dhcp_entry["disposition"])

        sriov_entry = by_port[SRIOV_PORT]
        self.assertFalse(sriov_entry["eligible"])
        self.assertEqual("unsupported_vif_type:hw_veb", sriov_entry["disposition"])

    def test_candidate_snapshot_claims_acl_domain_but_bypasses_without_binding(self):
        builder = PortCandidateBuilder(
            "compute-1",
            managed_domains=["acl"],
            acl_index=EffectiveAclIndex(),
        )

        snapshot = builder.build_snapshot([neutron_port(VM_PORT)], generation=11)
        vm_entry = snapshot["ports"][0]

        self.assertTrue(vm_entry["eligible"])
        self.assertEqual(["acl"], vm_entry["managed_domains"])
        self.assertEqual("not_requested", vm_entry["acl"]["status"])
        self.assertEqual("bypass", vm_entry["acl"]["effective_action"])
        self.assertEqual("no_enabled_binding", vm_entry["acl"]["reason"])

    def test_port_scoped_snapshot_builds_single_local_port_candidate(self):
        vm_port = neutron_port(VM_PORT)
        vm_port["network_id"] = "net-1"
        other_port = neutron_port(MISSING_TAP_PORT)
        other_port["network_id"] = "net-1"
        acl_index = EffectiveAclIndex(
            policies=[
                {
                    "id": "acl-port",
                    "default_action": "allow",
                    "revision_number": 5,
                },
            ],
            bindings=[
                {
                    "id": "acl-binding",
                    "policy_id": "acl-port",
                    "target_type": "port",
                    "target_id": VM_PORT,
                    "revision_number": 6,
                },
            ],
        )
        builder = PortScopedSnapshotBuilder(
            "compute-1",
            managed_domains=["acl"],
            acl_index=acl_index,
        )

        snapshot = builder.build_port_snapshot(
            [vm_port, other_port, neutron_port(REMOTE_PORT, host="compute-2")],
            VM_PORT,
            generation=12,
        )

        self.assertEqual(12, snapshot["generation"])
        self.assertEqual("compute-1", snapshot["host"])
        self.assertEqual({"type": "port", "port_id": VM_PORT}, snapshot["scope"])
        self.assertEqual(1, len(snapshot["ports"]))

        vm_entry = snapshot["ports"][0]
        self.assertEqual(VM_PORT, vm_entry["port_id"])
        self.assertTrue(vm_entry["eligible"])
        self.assertEqual(PENDING_LOCAL_VALIDATION, vm_entry["disposition"])
        self.assertEqual(["acl"], vm_entry["managed_domains"])
        self.assertEqual("acl-port", vm_entry["acl"]["policy_id"])
        self.assertEqual("enforce", vm_entry["acl"]["effective_action"])

    def test_port_scoped_snapshot_returns_empty_for_foreign_or_missing_port(self):
        builder = PortScopedSnapshotBuilder("compute-1", managed_domains=["acl"])

        foreign_snapshot = builder.build_port_snapshot(
            [neutron_port(REMOTE_PORT, host="compute-2")],
            REMOTE_PORT,
            generation=13,
        )
        missing_snapshot = builder.build_port_snapshot(
            [neutron_port(VM_PORT)],
            REMOTE_PORT,
            generation=14,
        )

        self.assertEqual({"type": "port", "port_id": REMOTE_PORT}, foreign_snapshot["scope"])
        self.assertEqual([], foreign_snapshot["ports"])
        self.assertEqual([], missing_snapshot["ports"])

    def test_port_scoped_snapshot_preserves_ineligible_target_disposition(self):
        builder = PortScopedSnapshotBuilder(
            "compute-1",
            managed_domains=["acl"],
            acl_index=EffectiveAclIndex(),
        )

        snapshot = builder.build_port_snapshot(
            [neutron_port(DHCP_PORT, owner="network:dhcp")],
            DHCP_PORT,
            generation=15,
        )
        port = snapshot["ports"][0]

        self.assertEqual(DHCP_PORT, port["port_id"])
        self.assertFalse(port["eligible"])
        self.assertEqual("not_applicable_device_owner:network:dhcp", port["disposition"])
        self.assertEqual([], port["managed_domains"])
        self.assertEqual("unsupported", port["acl"]["status"])
        self.assertEqual("bypass", port["acl"]["effective_action"])


if __name__ == "__main__":
    unittest.main()
