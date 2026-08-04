#!/usr/bin/env python3

from __future__ import print_function

import unittest

from ci.check_ebpf_stack_budget import (
    BudgetExceeded,
    analyze_function_stack,
    longest_path,
    validate_budget,
)


class EbpfStackBudgetTest(unittest.TestCase):
    def test_longest_path_sums_nested_frames(self):
        frames = {"tc_ingress": 32, "parse": 96, "policy": 80, "short": 16}
        calls = {
            "tc_ingress": {"parse", "short"},
            "parse": {"policy"},
            "policy": set(),
            "short": set(),
        }

        total, path = longest_path("tc_ingress", frames, calls)

        self.assertEqual(total, 224)
        self.assertEqual(path, ["tc_ingress", "parse", "policy"])

    def test_function_stack_tracks_frame_pointer_arithmetic(self):
        instructions = b"".join(
            (
                self._instruction(0xBF, dst=2, src=10),
                self._instruction(0x07, dst=2, imm=-208),
                self._instruction(0x95),
            )
        )

        self.assertEqual(analyze_function_stack(instructions, "frame_pointer"), 208)

    def test_function_stack_tracks_direct_stack_access(self):
        instructions = b"".join(
            (
                self._instruction(0x7B, dst=10, src=1, offset=-96),
                self._instruction(0x95),
            )
        )

        self.assertEqual(analyze_function_stack(instructions, "direct_store"), 96)

    def test_longest_path_rejects_recursive_call_graph(self):
        with self.assertRaisesRegex(ValueError, "recursive BPF call graph"):
            longest_path("tc_ingress", {"tc_ingress": 32}, {"tc_ingress": {"tc_ingress"}})

    def test_longest_path_rejects_unknown_target(self):
        with self.assertRaisesRegex(ValueError, "missing stack frame"):
            longest_path("tc_ingress", {"tc_ingress": 32}, {"tc_ingress": {"missing"}})

    def test_validate_budget_rejects_oversized_path(self):
        frames = {"tc_ingress": 32, "parse": 96, "policy": 80}
        calls = {"tc_ingress": {"parse"}, "parse": {"policy"}, "policy": set()}

        with self.assertRaisesRegex(BudgetExceeded, "224 bytes exceeds 192"):
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
                    "total_bytes": 128,
                    "path": [
                        {
                            "function": "tc_egress",
                            "frame_bytes": 32,
                            "verifier_bytes": 32,
                        },
                        {
                            "function": "policy",
                            "frame_bytes": 80,
                            "verifier_bytes": 96,
                        },
                    ],
                }
            },
        )

    @staticmethod
    def _instruction(opcode, dst=0, src=0, offset=0, imm=0):
        import struct

        return struct.pack("<BBhi", opcode, dst | (src << 4), offset, imm)


if __name__ == "__main__":
    unittest.main()
