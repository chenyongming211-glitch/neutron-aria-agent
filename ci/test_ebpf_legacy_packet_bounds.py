#!/usr/bin/env python3
"""Regression contracts for packet bounds accepted by legacy BPF verifiers."""

from __future__ import print_function

import os
import re
import unittest

from ci.check_tc_acl_datapath import function_body


ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir))
PARSER = os.path.join(ROOT, "ebpf", "src", "parser.rs")
FRAGMENT = os.path.join(ROOT, "ebpf", "src", "fragment.rs")
EBPF_LIB = os.path.join(ROOT, "ebpf", "src", "lib.rs")


class LegacyPacketBoundsTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with open(PARSER, "r", encoding="utf-8") as handle:
            cls.source = handle.read()
        with open(FRAGMENT, "r", encoding="utf-8") as handle:
            cls.fragment_source = handle.read()
        with open(EBPF_LIB, "r", encoding="utf-8") as handle:
            cls.lib_source = handle.read()

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

    def test_ct_miss_fallbacks_are_inlined_for_legacy_stack_budget(self):
        for direction in ("ingress", "egress"):
            for family in ("v4", "v6"):
                name = "phase_ct_miss_tc_%s_%s" % (direction, family)
                self.assertRegex(
                    self.lib_source,
                    re.compile(r"#\[inline\(always\)\]\s*unsafe fn %s\b" % name),
                    "%s must share its caller frame on kernels with a 512-byte call-chain budget"
                    % name,
                )


if __name__ == "__main__":
    unittest.main()
