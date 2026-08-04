#!/usr/bin/env python3
"""Regression contracts for packet bounds accepted by legacy BPF verifiers."""

from __future__ import print_function

import os
import re
import unittest

from ci.check_tc_acl_datapath import function_body


ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir))
PARSER = os.path.join(ROOT, "ebpf", "src", "parser.rs")


class LegacyPacketBoundsTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with open(PARSER, "r", encoding="utf-8") as handle:
            cls.source = handle.read()

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


if __name__ == "__main__":
    unittest.main()
