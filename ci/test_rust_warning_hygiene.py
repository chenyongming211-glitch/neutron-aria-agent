#!/usr/bin/env python3
"""Focused mutation tests for the Rust/eBPF warning hygiene guard."""

import unittest

from ci.check_rust_warning_hygiene import read, verify_pod_layouts


class PodLayoutGuardTests(unittest.TestCase):
    def test_current_pod_declarations_pass(self):
        verify_pod_layouts(read("abi/src/lib.rs"))

    def test_removing_repr_c_from_pod_declaration_fails(self):
        source = read("abi/src/lib.rs")
        declaration = (
            "#[repr(C)]\n"
            "#[derive(Copy, Clone, Debug)]\n"
            "pub struct PolicyKey"
        )
        mutated = source.replace(
            declaration,
            "#[derive(Copy, Clone, Debug)]\npub struct PolicyKey",
            1,
        )
        self.assertNotEqual(source, mutated, "test mutation did not change PolicyKey")

        with self.assertRaisesRegex(
            AssertionError,
            r"aya::Pod type PolicyKey must have adjacent #\[repr\(C\)\]",
        ):
            verify_pod_layouts(mutated)

    def test_final_pod_without_trailing_comma_still_requires_repr_c(self):
        source = read("abi/src/lib.rs")
        mutated = source.replace(
            "#[repr(C)]\n"
            "#[derive(Copy, Clone, Debug)]\n"
            "pub struct TraceStreamEvent",
            "#[derive(Copy, Clone, Debug)]\npub struct TraceStreamEvent",
            1,
        ).replace(
            "        TraceStreamEvent,\n    );",
            "        TraceStreamEvent\n    );",
            1,
        )
        self.assertNotEqual(source, mutated, "test mutation did not change final Pod")

        with self.assertRaisesRegex(
            AssertionError,
            r"aya::Pod type TraceStreamEvent must have adjacent #\[repr\(C\)\]",
        ):
            verify_pod_layouts(mutated)


if __name__ == "__main__":
    unittest.main()
