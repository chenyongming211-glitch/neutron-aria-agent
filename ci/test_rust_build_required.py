#!/usr/bin/env python3
"""Focused unit tests for the Build workflow's Rust/eBPF change detector."""

import importlib.util
import unittest
from pathlib import Path


DETECTOR = Path(__file__).with_name("rust_build_required.py")


class RustBuildRequiredTests(unittest.TestCase):
    def _load_detector(self):
        if not DETECTOR.is_file():
            self.fail(f"missing workflow detector: {DETECTOR}")
        spec = importlib.util.spec_from_file_location("rust_build_required", DETECTOR)
        self.assertIsNotNone(spec)
        self.assertIsNotNone(spec.loader)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def test_change_detector_table(self):
        detector = self._load_detector()
        cases = (
            ("Rust source", ["core/src/lib.rs"], True),
            ("workflow input", [".github/workflows/build.yml"], True),
            ("CI input", ["ci/check_blocked_terms.py"], True),
            (
                "Python-only input",
                ["openstack/neutron_aria/neutron_aria/agent.py"],
                False,
            ),
            (
                "OpenStack requirements input",
                ["openstack/neutron_aria/requirements.txt"],
                False,
            ),
            (
                "OpenStack unknown input fails closed",
                ["openstack/unclassified/new-input.xyz"],
                True,
            ),
            (
                "OpenStack nested Rust source requires Rust",
                ["openstack/neutron_aria/native/src/lib.rs"],
                True,
            ),
            (
                "OpenStack nested Cargo manifest requires Rust",
                ["openstack/neutron_aria/native/Cargo.toml"],
                True,
            ),
            ("docs-only input", ["docs/operator-guide.md"], False),
            ("empty input fails closed", [], True),
            ("unknown input fails closed", ["unclassified/new-input.xyz"], True),
            ("leading-space path fails closed", [" docs/operator-guide.md"], True),
            ("trailing-space path fails closed", ["docs/operator-guide.md "], True),
            (
                "multiple safe paths",
                ["docs/operator-guide.md", "openstack/neutron_aria/setup.cfg"],
                False,
            ),
            (
                "multiple paths with Rust source",
                ["docs/operator-guide.md", "ebpf/src/lib.rs"],
                True,
            ),
        )

        for name, paths, expected in cases:
            with self.subTest(name=name):
                self.assertIs(detector.rust_build_required(paths), expected)


if __name__ == "__main__":
    unittest.main()
