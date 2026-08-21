#!/usr/bin/env python3
"""Unit contracts for the read-only Aria runtime-upgrade classifier."""

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CONTROL_PATH = ROOT / "deploy" / "kolla" / "package" / "aria_upgrade_control.py"
COMPATIBILITY = {
    "schema_version": 1,
    "uds_schema_min": 1,
    "uds_schema_max": 1,
    "snapshot_schema_version": 1,
    "ebpf_abi_version": 1,
    "map_schema_version": 1,
    "wal_schema_version": 1,
    "runtime_state_schema_version": 1,
    "minimum_kernel_profile": "rhel8-4.18",
    "managed_domain_contract_version": "2026-06-v0.9",
    "maintenance_gate_capable": False,
    "ebpf_abi_hash": "a" * 64,
    "map_schema_hash": "b" * 64,
}


def manifest(agent_suffix="1", datapath_suffix="2"):
    return {
        "runtime_compatibility": dict(COMPATIBILITY),
        "images": [
            {
                "name": "neutron-aria-agent",
                "identity": "neutron-aria-agent:v0.9@sha256:" + agent_suffix * 64,
            },
            {
                "name": "aria-datapath",
                "identity": "aria-datapath:v0.9@sha256:" + datapath_suffix * 64,
            },
        ],
    }


class AriaUpgradeControlTest(unittest.TestCase):
    def control(self):
        self.assertTrue(CONTROL_PATH.is_file(), "runtime upgrade classifier is required")
        spec = importlib.util.spec_from_file_location("aria_upgrade_control", CONTROL_PATH)
        module = importlib.util.module_from_spec(spec)
        assert spec.loader is not None
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        return module

    def test_agent_identity_only_change_is_hot_agent(self):
        control = self.control()
        result = control.classify_upgrade(manifest("1"), manifest("3"))
        self.assertEqual("hot_agent", result.path)
        self.assertEqual(("agent_only",), result.reasons)

    def test_map_schema_change_requires_planned_maintenance(self):
        control = self.control()
        current = manifest()
        candidate = manifest()
        candidate["runtime_compatibility"]["map_schema_hash"] = "c" * 64
        result = control.classify_upgrade(current, candidate)
        self.assertEqual("planned_maintenance", result.path)
        self.assertEqual(("map_schema_hash",), result.reasons)

    def test_unknown_manifest_is_never_hot_replacement(self):
        control = self.control()
        candidate = manifest()
        candidate["images"] = candidate["images"][1:]
        result = control.classify_upgrade(manifest(), candidate)
        self.assertEqual("planned_maintenance", result.path)
        self.assertEqual(("unknown_compatibility",), result.reasons)

    def test_force_maintenance_overrides_compatible_manifests(self):
        control = self.control()
        result = control.classify_upgrade(manifest(), manifest(), force_maintenance=True)
        self.assertEqual("planned_maintenance", result.path)
        self.assertEqual(("operator_forced",), result.reasons)

    def test_classify_command_prints_bounded_json_without_docker(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir)
            current = temp / "current.json"
            candidate = temp / "candidate.json"
            current.write_text(json.dumps(manifest()), encoding="utf-8")
            candidate.write_text(json.dumps(manifest("3")), encoding="utf-8")
            result = subprocess.run(
                [
                    sys.executable,
                    str(CONTROL_PATH),
                    "classify",
                    "--current",
                    str(current),
                    "--candidate",
                    str(candidate),
                ],
                check=True,
                capture_output=True,
                text=True,
            )
        self.assertEqual(
            {"path": "hot_agent", "reasons": ["agent_only"]},
            json.loads(result.stdout),
        )
        self.assertNotIn("docker", CONTROL_PATH.read_text(encoding="utf-8").lower())


if __name__ == "__main__":
    unittest.main()
