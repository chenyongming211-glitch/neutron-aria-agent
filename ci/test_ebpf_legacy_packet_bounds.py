#!/usr/bin/env python3
"""Regression contracts for packet bounds accepted by legacy BPF verifiers."""

from __future__ import print_function

import os
import re
import unittest

from ci.check_tc_acl_datapath import _block_after
from ci.check_tc_acl_datapath import function_body


ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir))
PARSER = os.path.join(ROOT, "ebpf", "src", "parser.rs")
FRAGMENT = os.path.join(ROOT, "ebpf", "src", "fragment.rs")
LIB = os.path.join(ROOT, "ebpf", "src", "lib.rs")
MAPS = os.path.join(ROOT, "ebpf", "src", "maps.rs")
TCPRT = os.path.join(ROOT, "ebpf", "src", "tcprt.rs")
POLICY = os.path.join(ROOT, "ebpf", "src", "policy.rs")
INVENTORY = os.path.join(ROOT, "core", "src", "ebpf_ops", "inventory.rs")


class LegacyPacketBoundsTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with open(PARSER, "r", encoding="utf-8") as handle:
            cls.source = handle.read()
        with open(FRAGMENT, "r", encoding="utf-8") as handle:
            cls.fragment_source = handle.read()
        with open(LIB, "r", encoding="utf-8") as handle:
            cls.lib_source = handle.read()
        with open(MAPS, "r", encoding="utf-8") as handle:
            cls.maps_source = handle.read()
        with open(TCPRT, "r", encoding="utf-8") as handle:
            cls.tcprt_source = handle.read()
        with open(POLICY, "r", encoding="utf-8") as handle:
            cls.policy_source = handle.read()
        with open(INVENTORY, "r", encoding="utf-8") as handle:
            cls.inventory_source = handle.read()

    def test_ipv4_wire_length_is_not_added_to_packet_pointer(self):
        body = function_body(self.source, "parse_eth_ipv4")
        self.assertNotRegex(
            body,
            re.compile(r"ip_offset\s*\+\s*ip_total_len"),
            "kernel 4.18 cannot reliably prove the range of this packet pointer",
        )

    def test_ipv6_wire_length_is_not_added_to_packet_pointer(self):
        body = function_body(self.source, "parse_eth_ipv6")
        self.assertNotRegex(
            body,
            re.compile(r"ip_offset\s*\+\s*40\s*\+\s*ipv6_payload_len"),
            "kernel 4.18 cannot reliably prove the range of this packet pointer",
        )

    def test_fragment_resolve_outcome_has_no_conditional_payload(self):
        self.assertIn("#[repr(u8)]\npub enum ResolveOutcome", self.fragment_source)
        self.assertNotRegex(
            self.fragment_source,
            re.compile(r"ResolveOutcome::Resolved\s*\("),
            "kernel 4.18 may treat a conditional enum payload as uninitialized stack",
        )

    def test_fragment_hot_paths_do_not_forward_conditional_option_payloads(self):
        for name in (
            "resolve_v4",
            "resolve_v6",
            "install_allowed_v4",
            "install_allowed_v6",
        ):
            body = function_body(self.fragment_source, name)
            self.assertNotRegex(
                body,
                re.compile(r"\b(?:config|epoch|value)\.as_ref\(\)"),
                "%s must unwrap map values before forwarding their references" % name,
            )

    def test_fragment_hot_paths_borrow_large_map_values_in_place(self):
        for name in (
            "resolve_v4",
            "resolve_v6",
            "install_allowed_v4",
            "install_allowed_v6",
        ):
            body = function_body(self.fragment_source, name)
            self.assertNotRegex(
                body,
                re.compile(r"(?:FRAGMENT_CONFIG|FRAG_CONTEXT_V[46])\.get\([^;]+\)\.copied\(\)"),
                "%s must not copy large map values onto the legacy verifier stack" % name,
            )

    def test_tc_connection_keys_use_per_cpu_scratch(self):
        self.assertIn('map(name = "CT_KEY4_SCRATCH")', self.maps_source)
        self.assertIn('map(name = "CT_KEY6_SCRATCH")', self.maps_source)
        self.assertNotRegex(
            self.lib_source,
            re.compile(r"let\s+ct_key\s*=\s*CtKey[46]\s*\{"),
            "TC connection keys must not remain live on the BPF stack",
        )
        self.assertEqual(
            self.lib_source.count("CT_KEY4_SCRATCH.get_ptr_mut(maps::CT_KEY_PRIMARY_SLOT)"),
            2,
        )
        self.assertEqual(
            self.lib_source.count("CT_KEY6_SCRATCH.get_ptr_mut(maps::CT_KEY_PRIMARY_SLOT)"),
            2,
        )

    def test_ct_key_scratch_is_not_persistent_inventory(self):
        for name in ("CT_KEY4_SCRATCH", "CT_KEY6_SCRATCH"):
            self.assertNotIn(
                '"%s"' % name,
                self.inventory_source,
                "%s is packet scratch, not persistent runtime state" % name,
            )

    def test_tcprt_derived_keys_use_the_second_scratch_slot(self):
        self.assertIn("CT_KEY_PRIMARY_SLOT: u32 = 0", self.maps_source)
        self.assertIn("CT_KEY_DERIVED_SLOT: u32 = 1", self.maps_source)
        self.assertIn("PerCpuArray::with_max_entries(2, 0)", self.maps_source)
        self.assertNotRegex(
            self.tcprt_source,
            re.compile(r"let\s+(?:fwd|rev)_key\s*=\s*CtKey[46]\s*\{"),
            "TCPRT derived connection keys must not remain on the BPF stack",
        )
        self.assertEqual(
            self.tcprt_source.count("CT_KEY4_SCRATCH.get_ptr_mut(CT_KEY_DERIVED_SLOT)"),
            2,
        )
        self.assertEqual(
            self.tcprt_source.count("CT_KEY6_SCRATCH.get_ptr_mut(CT_KEY_DERIVED_SLOT)"),
            2,
        )
        self.assertNotIn("track_tcp_rt_v4_rev(tap_id", self.tcprt_source)
        self.assertNotIn("track_tcp_rt_v6_rev(tap_id", self.tcprt_source)

    def test_tc_policy_uses_map_backed_pipeline_state(self):
        self.assertNotIn("pub struct PolicyArgs", self.policy_source)
        self.assertIn(
            "pub unsafe fn evaluate_policy(p: &mut PipelineCtx, dst_port: u16) -> u32",
            self.policy_source,
        )
        self.assertIn("p.matched_src_id = s;", self.policy_source)
        self.assertIn("p.flags |= FLAG_POLICY_HIT;", self.policy_source)
        self.assertNotIn("let args = policy::PolicyArgs", self.lib_source)
        self.assertIn(
            "let result = policy::evaluate_policy(p, info.dst_port);",
            self.lib_source,
        )

    def test_tc_parse_uncertainty_is_fail_open(self):
        for direction in ("ingress", "egress"):
            body = function_body(self.lib_source, "tc_%s" % direction)
            failure = _block_after(body, "if !parse_tc_packet")
            self.assertIsNotNone(failure, direction)
            failure_body = failure[0]
            self.assertIn("return TC_ACT_OK;", failure_body, direction)
            self.assertNotIn("TC_ACT_SHOT", failure_body, direction)
            self.assertNotIn("record_malformed_ip_drop_tc", failure_body, direction)
            self.assertNotIn("record_invalid_l4_drop_tc", failure_body, direction)


if __name__ == "__main__":
    unittest.main()
