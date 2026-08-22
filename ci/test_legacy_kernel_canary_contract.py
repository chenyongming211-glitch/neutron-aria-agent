#!/usr/bin/env python3

from __future__ import print_function

import os
import unittest


ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir))
CANARY = os.path.join(
    ROOT,
    "deploy",
    "kolla",
    "smoke",
    "neutron_aria_legacy_kernel_loader_canary.sh",
)
STANDALONE = os.path.join(
    ROOT,
    "deploy",
    "smoke",
    "aria_standalone_acl_tc_datapath_smoke.sh",
)
INSTANCE = os.path.join(ROOT, "agent", "src", "instance.rs")
SYSTEM_MANAGER = os.path.join(ROOT, "agent", "src", "system_manager.rs")
ABI = os.path.join(ROOT, "abi", "src", "lib.rs")
CORE_RUNTIME = os.path.join(ROOT, "core", "src", "ebpf_ops", "runtime.rs")
EBPF_RUNTIME = os.path.join(ROOT, "ebpf", "src", "runtime.rs")
EBPF_CT_CONTRACT = os.path.join(ROOT, "ebpf", "src", "ct_contract.rs")
CORE_SCRUB = os.path.join(ROOT, "core", "src", "ebpf_ops", "scrub.rs")


class LegacyKernelCanaryContractTest(unittest.TestCase):
    def setUp(self):
        with open(CANARY, "r", encoding="utf-8") as handle:
            self.source = handle.read()
        with open(STANDALONE, "r", encoding="utf-8") as handle:
            self.standalone_source = handle.read()
        with open(INSTANCE, "r", encoding="utf-8") as handle:
            self.instance_source = handle.read()
        with open(SYSTEM_MANAGER, "r", encoding="utf-8") as handle:
            self.system_manager_source = handle.read()
        with open(ABI, "r", encoding="utf-8") as handle:
            self.abi_source = handle.read()
        with open(CORE_RUNTIME, "r", encoding="utf-8") as handle:
            self.core_runtime_source = handle.read()
        with open(EBPF_RUNTIME, "r", encoding="utf-8") as handle:
            self.ebpf_runtime_source = handle.read()
        with open(EBPF_CT_CONTRACT, "r", encoding="utf-8") as handle:
            self.ebpf_ct_contract_source = handle.read()
        with open(CORE_SCRUB, "r", encoding="utf-8") as handle:
            self.core_scrub_source = handle.read()

    def test_requires_exact_kernel_and_artifact_hashes(self):
        self.assertIn("4.18.0-553.5.1.el8_10.x86_64", self.source)
        self.assertIn(': "${ARIA_AGENT_SHA256:?', self.source)
        self.assertIn(': "${EBPF_SHA256:?', self.source)
        self.assertIn("sha256sum", self.source)

    def test_reuses_isolated_tap_smoke_and_removes_state(self):
        self.assertIn("aria_standalone_acl_tc_datapath_smoke.sh", self.source)
        self.assertIn("MODE=tap", self.source)
        self.assertIn('rm -rf -- "${WORK_DIR}"', self.source)
        self.assertIn("ip netns", self.source)
        self.assertIn("tc qdisc", self.source)
        self.assertIn('for diagnostic in agent.stdout agent.log', self.source)

    def test_does_not_manage_ovs_lifecycle(self):
        lowered = self.source.lower()
        for command in (
            "systemctl restart",
            "docker restart",
            "podman restart",
            "ovs-vsctl",
            "neutron-openvswitch-agent",
        ):
            self.assertNotIn(command, lowered)

    def test_dual_tc_readiness_accepts_exact_legacy_filters_without_link_pins(self):
        self.assertIn('TC_ATTACH_MODE="legacy"', self.standalone_source)
        self.assertIn('"tc_ingress"', self.standalone_source)
        self.assertIn('"tc_egress"', self.standalone_source)
        self.assertIn("assert_exact_legacy_tc_filter", self.standalone_source)
        dual_tc_body = self.standalone_source.split("assert_dual_tc_ready() {", 1)[1]
        dual_tc_body = dual_tc_body.split("capture_acl_counters() {", 1)[0]
        self.assertNotIn('assert item["xdp_ready"] is True', dual_tc_body)
        health_body = self.standalone_source.split("assert_health_poll_degrades() {", 1)[1]
        health_body = health_body.split("recover_missing_legacy_tc_runtime() {", 1)[0]
        self.assertNotIn('assert item["xdp_ready"] is True', health_body)

    def test_legacy_tc_ownership_uses_kernel_program_identity_not_object_local_state(self):
        self.assertIn("LegacyTcAttachmentObservation", self.instance_source)
        self.assertIn('args(["-j", "filter", "show"', self.instance_source)
        self.assertIn("pinned_tc_program_identity", self.instance_source)
        self.assertIn("classify_legacy_tc_filter_text", self.instance_source)
        self.assertIn("info.tag()", self.instance_source)
        self.assertIn('args(["filter", "show"', self.instance_source)
        self.assertNotIn("legacy_tc_ingress_attached: AtomicBool", self.instance_source)

    def test_legacy_tc_smoke_falls_back_when_tc_json_is_unavailable(self):
        self.assertIn('-tc-ingress.txt', self.standalone_source)
        self.assertIn('-tc-egress.txt', self.standalone_source)
        self.assertIn('program.get("tag")', self.standalone_source)

    def test_old_bpftool_lookup_falls_back_to_exact_map_dump_key(self):
        self.assertIn("bpftool_map_lookup_json()", self.standalone_source)
        self.assertIn('bpftool -j map dump pinned "${map}"', self.standalone_source)
        self.assertIn('decode(row.get("key",[]))==expected', self.standalone_source)

    def test_system_mode_accepts_and_owns_legacy_tc_links(self):
        source = self.system_manager_source
        attach = source.split("fn attach_tc_program(", 1)[1]
        attach = attach.split("#[cfg(test)]", 1)[0]
        self.assertIn("SystemTcAttachOutcome", source)
        self.assertIn("LinkError::InvalidLink", attach)
        self.assertIn("std::mem::forget(tc_link)", attach)
        self.assertIn("DetachOwnedLegacyTc", source)

    def test_system_mode_reuses_dual_exact_legacy_runtime(self):
        source = self.system_manager_source
        self.assertIn("preexisting_system_tc_runtime_is_healthy", source)
        self.assertIn("preexisting_health.ingress", source)
        self.assertIn("preexisting_health.egress", source)
        self.assertIn("preexisting_health.acl_ready()", source)

    def test_system_stop_uses_identity_verified_legacy_detach(self):
        stop = self.system_manager_source.split("pub async fn system_stop(", 1)[1]
        stop = stop.split("fn attach_tc_program(", 1)[0]
        self.assertIn("detach_owned_legacy_tc_program", stop)
        self.assertIn('"tc_ingress"', stop)
        self.assertIn('"tc_egress"', stop)

    def test_system_mode_uses_abi_stable_global_acl_bank(self):
        firewall_config = self.abi_source.split("pub struct FirewallConfig", 1)[1]
        firewall_config = firewall_config.split("pub const TAP_ID_UNASSIGNED", 1)[0]
        self.assertIn("pub acl_active_bank: u8", firewall_config)
        self.assertNotIn("pub _pad: [u8; 1]", firewall_config)
        self.assertIn(
            "core::mem::offset_of!(FirewallConfig, acl_active_bank), 9",
            self.abi_source,
        )

        set_bank = self.core_runtime_source.split("pub fn set_acl_active_bank", 1)[1]
        set_bank = set_bank.split("pub fn read_acl_active_bank", 1)[0]
        self.assertIn("firewall_config_with_acl_bank", set_bank)
        self.assertNotIn("only supported for per-tap runtime config", set_bank)

        read_bank = self.core_runtime_source.split("pub fn read_acl_active_bank", 1)[1]
        read_bank = read_bank.split("pub fn update_acl_runtime_gate", 1)[0]
        self.assertIn("read_firewall_config", read_bank)
        self.assertIn("cfg.acl_active_bank", read_bank)

        ebpf_sample = self.ebpf_runtime_source.split(
            "pub fn sample_acl_ct_packet_state", 1
        )[1]
        ebpf_sample = ebpf_sample.split("pub fn apply_per_tap_acl_ct_state", 1)[0]
        self.assertIn("config.acl_active_bank", ebpf_sample)
        ebpf_per_tap = self.ebpf_runtime_source.split(
            "pub fn apply_per_tap_acl_ct_state", 1
        )[1]
        ebpf_per_tap = ebpf_per_tap.split("pub fn monitoring_enabled", 1)[0]
        self.assertIn("config.acl_active_bank", ebpf_per_tap)
        self.assertNotIn("read_global_config", ebpf_per_tap)

        scrub_bank = self.core_scrub_source.split("pub fn scrub_acl_bank", 1)[1]
        scrub_bank = scrub_bank.split("fn scrub_runtime_state", 1)[0]
        self.assertNotIn("tap_id == TAP_ID_UNASSIGNED", scrub_bank)
        self.assertIn("acl_banked_tap_id(tap_id, bank)", scrub_bank)

        self.assertNotIn(
            "args.tap_id == TAP_ID_UNASSIGNED",
            self.ebpf_ct_contract_source,
        )
        self.assertIn("tap_id: args.tap_id", self.ebpf_ct_contract_source)

    def test_system_restart_replays_into_maps_owned_by_preexisting_tc(self):
        source = self.system_manager_source
        self.assertIn("if reuse_preexisting_tc", source)
        self.assertIn(
            "replay_standalone_state_to_pinned_maps_from_snapshot",
            source,
        )
        self.assertIn(
            "replay_state_from_snapshot(&mut bpf, pin_path, state_path, &quiesced_desired)",
            source,
        )


if __name__ == "__main__":
    unittest.main()
