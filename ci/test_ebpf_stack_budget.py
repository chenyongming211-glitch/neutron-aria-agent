#!/usr/bin/env python3

from __future__ import print_function

import unittest

from ci.check_ebpf_stack_budget import (
    BudgetExceeded,
    decode_uleb128,
    longest_path,
    validate_budget,
)


class EbpfStackBudgetTest(unittest.TestCase):
    def test_decode_uleb128(self):
        value, next_offset = decode_uleb128(bytes([0xE5, 0x8E, 0x26]), 0)
        self.assertEqual(value, 624485)
        self.assertEqual(next_offset, 3)

    def test_longest_path_sums_nested_frames(self):
        frames = {"tc_ingress": 32, "parse": 96, "policy": 80, "short": 16}
        calls = {
            "tc_ingress": {"parse", "short"},
            "parse": {"policy"},
            "policy": set(),
            "short": set(),
        }

        total, path = longest_path("tc_ingress", frames, calls)

        self.assertEqual(total, 208)
        self.assertEqual(path, ["tc_ingress", "parse", "policy"])

    def test_longest_path_rejects_recursive_call_graph(self):
        with self.assertRaisesRegex(ValueError, "recursive BPF call graph"):
            longest_path("tc_ingress", {"tc_ingress": 32}, {"tc_ingress": {"tc_ingress"}})

    def test_longest_path_rejects_unknown_target(self):
        with self.assertRaisesRegex(ValueError, "missing stack frame"):
            longest_path("tc_ingress", {"tc_ingress": 32}, {"tc_ingress": {"missing"}})

    def test_validate_budget_rejects_oversized_path(self):
        frames = {"tc_ingress": 32, "parse": 96, "policy": 80}
        calls = {"tc_ingress": {"parse"}, "parse": {"policy"}, "policy": set()}

        with self.assertRaisesRegex(BudgetExceeded, "208 bytes exceeds 192"):
            validate_budget(("tc_ingress",), frames, calls, 192)

    def test_validate_budget_returns_entry_report(self):
        reports = validate_budget(
            ("tc_egress",),
            {"tc_egress": 32, "policy": 80},
            {"tc_egress": {"policy"}, "policy": set()},
            448,
        )

        self.assertEqual(
            reports,
            {
                "tc_egress": {
                    "total_bytes": 112,
                    "path": [
                        {"function": "tc_egress", "frame_bytes": 32},
                        {"function": "policy", "frame_bytes": 80},
                    ],
                }
            },
        )


if __name__ == "__main__":
    unittest.main()
