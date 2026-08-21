#!/usr/bin/env python3
"""Unit contracts for the read-only Aria runtime-upgrade classifier."""

import importlib.util
import json
import os
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


def image_identity(name, suffix):
    return name + ":v0.9@sha256:" + suffix * 64


def manifest(agent_suffix="1", datapath_suffix="2"):
    return {
        "runtime_compatibility": dict(COMPATIBILITY),
        "images": [
            {
                "name": "neutron-aria-agent",
                "identity": image_identity("neutron-aria-agent", agent_suffix),
            },
            {
                "name": "aria-datapath",
                "identity": image_identity("aria-datapath", datapath_suffix),
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

    def test_datapath_identity_only_change_is_hot_datapath(self):
        control = self.control()
        result = control.classify_upgrade(manifest(), manifest(datapath_suffix="3"))
        self.assertEqual("hot_datapath", result.path)
        self.assertEqual(("compatible_datapath",), result.reasons)

    def test_unchanged_manifests_are_no_runtime_change(self):
        control = self.control()
        result = control.classify_upgrade(manifest(), manifest())
        self.assertEqual("hot_agent", result.path)
        self.assertEqual(("no_runtime_change",), result.reasons)

    def test_joint_agent_and_datapath_change_requires_planned_maintenance(self):
        control = self.control()
        result = control.classify_upgrade(manifest(), manifest("3", "4"))
        self.assertEqual("planned_maintenance", result.path)
        self.assertEqual(("joint_agent_datapath_change",), result.reasons)

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

    def test_unsupported_runtime_schema_requires_planned_maintenance(self):
        control = self.control()
        candidate = manifest()
        candidate["runtime_compatibility"]["schema_version"] = 2
        result = control.classify_upgrade(manifest(), candidate)
        self.assertEqual("planned_maintenance", result.path)
        self.assertEqual(("unknown_compatibility",), result.reasons)

    def test_invalid_uds_range_requires_planned_maintenance(self):
        control = self.control()
        candidate = manifest()
        candidate["runtime_compatibility"]["uds_schema_min"] = 2
        candidate["runtime_compatibility"]["uds_schema_max"] = 1
        result = control.classify_upgrade(manifest(), candidate)
        self.assertEqual("planned_maintenance", result.path)
        self.assertEqual(("unknown_compatibility",), result.reasons)

    def test_disjoint_uds_ranges_require_planned_maintenance(self):
        control = self.control()
        current = manifest()
        candidate = manifest("3")
        candidate["runtime_compatibility"]["uds_schema_min"] = 2
        candidate["runtime_compatibility"]["uds_schema_max"] = 2
        result = control.classify_upgrade(current, candidate)
        self.assertEqual("planned_maintenance", result.path)
        self.assertEqual(("uds_schema_incompatible",), result.reasons)

    def test_overlapping_uds_ranges_keep_agent_hot_path(self):
        control = self.control()
        current = manifest()
        candidate = manifest("3")
        current["runtime_compatibility"]["uds_schema_max"] = 2
        candidate["runtime_compatibility"]["uds_schema_min"] = 2
        candidate["runtime_compatibility"]["uds_schema_max"] = 3
        result = control.classify_upgrade(current, candidate)
        self.assertEqual("hot_agent", result.path)
        self.assertEqual(("agent_only",), result.reasons)

    def test_maintenance_gate_capability_transition_requires_maintenance(self):
        control = self.control()
        candidate = manifest("3")
        candidate["runtime_compatibility"]["maintenance_gate_capable"] = True
        result = control.classify_upgrade(manifest(), candidate)
        self.assertEqual("planned_maintenance", result.path)
        self.assertEqual(("maintenance_gate_capability_changed",), result.reasons)

    def test_every_datapath_key_reports_its_sorted_stable_reason(self):
        control = self.control()
        for key in control.DATAPATH_KEYS:
            with self.subTest(key=key):
                candidate = manifest()
                value = candidate["runtime_compatibility"][key]
                candidate["runtime_compatibility"][key] = (
                    "c" * 64 if key.endswith("_hash") else
                    value + "-next" if isinstance(value, str) else value + 1
                )
                result = control.classify_upgrade(manifest(), candidate)
                self.assertEqual("planned_maintenance", result.path)
                self.assertEqual((key,), result.reasons)

    def test_multiple_datapath_keys_have_sorted_reasons(self):
        control = self.control()
        candidate = manifest()
        compatibility = candidate["runtime_compatibility"]
        compatibility["wal_schema_version"] += 1
        compatibility["minimum_kernel_profile"] = "rhel9-5.14"
        compatibility["ebpf_abi_hash"] = "c" * 64
        result = control.classify_upgrade(manifest(), candidate)
        self.assertEqual("planned_maintenance", result.path)
        self.assertEqual(
            tuple(sorted(("wal_schema_version", "minimum_kernel_profile", "ebpf_abi_hash"))),
            result.reasons,
        )

    def test_malformed_missing_extra_negative_and_current_side_compatibility_are_unknown(self):
        control = self.control()
        cases = []
        missing = manifest()
        del missing["runtime_compatibility"]["wal_schema_version"]
        cases.append(missing)
        extra = manifest()
        extra["runtime_compatibility"]["unexpected"] = 1
        cases.append(extra)
        negative = manifest()
        negative["runtime_compatibility"]["map_schema_version"] = -1
        cases.append(negative)
        malformed = manifest()
        malformed["runtime_compatibility"]["minimum_kernel_profile"] = ""
        cases.append(malformed)
        for current in cases:
            with self.subTest(current=current):
                result = control.classify_upgrade(current, manifest())
                self.assertEqual("planned_maintenance", result.path)
                self.assertEqual(("unknown_compatibility",), result.reasons)

    def test_missing_or_malformed_image_identity_is_unknown(self):
        control = self.control()
        cases = []
        missing = manifest()
        missing["images"] = missing["images"][1:]
        cases.append(missing)
        for invalid in (
            ":@sha256:" + "a" * 64,
            "UPPERCASE:v0.9@sha256:" + "a" * 64,
            "agent@sha256:" + "A" * 64,
            "agent@sha256:" + "a" * 63,
        ):
            malformed = manifest()
            malformed["images"][0]["identity"] = invalid
            cases.append(malformed)
        for candidate in cases:
            with self.subTest(candidate=candidate):
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
            poison = temp / "poison"
            poison.mkdir()
            marker = temp / "docker-was-called"
            docker = poison / "docker"
            docker.write_text(
                "#!/usr/bin/env sh\n"
                "touch \"%s\"\n"
                "exit 47\n" % marker,
                encoding="utf-8",
            )
            docker.chmod(0o755)
            environment = dict(os.environ)
            environment["PATH"] = str(poison) + os.pathsep + environment["PATH"]
            candidate_payload = manifest("3")
            for key in (
                "snapshot_schema_version",
                "wal_schema_version",
                "runtime_state_schema_version",
                "minimum_kernel_profile",
                "managed_domain_contract_version",
            ):
                value = candidate_payload["runtime_compatibility"][key]
                candidate_payload["runtime_compatibility"][key] = (
                    value + "-next" if isinstance(value, str) else value + 1
                )
            candidate.write_text(json.dumps(candidate_payload), encoding="utf-8")
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
                env=environment,
            )
        self.assertEqual(
            {
                "path": "planned_maintenance",
                "reasons": [
                    "managed_domain_contract_version",
                    "minimum_kernel_profile",
                    "runtime_state_schema_version",
                    "snapshot_schema_version",
                    "wal_schema_version",
                ],
            },
            json.loads(result.stdout),
        )
        self.assertEqual(1, result.stdout.count("\n"))
        self.assertLess(len(result.stdout), 1024)
        self.assertFalse(marker.exists(), "dry-run must not execute Docker")

    def test_invalid_missing_and_deep_cli_manifests_are_bounded_unknown_json(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir)
            invalid = temp / "invalid.json"
            deep = temp / "deep.json"
            invalid.write_text("{not-json", encoding="utf-8")
            deep.write_text("{\"nested\":" * 2000 + "0" + "}" * 2000, encoding="utf-8")
            for path in (invalid, deep, temp / "missing.json"):
                with self.subTest(path=path.name):
                    result = subprocess.run(
                        [
                            sys.executable,
                            str(CONTROL_PATH),
                            "classify",
                            "--current",
                            str(path),
                            "--candidate",
                            str(path),
                        ],
                        check=True,
                        capture_output=True,
                        text=True,
                    )
                    self.assertEqual(
                        {"path": "planned_maintenance", "reasons": ["unknown_compatibility"]},
                        json.loads(result.stdout),
                    )
                    self.assertEqual(1, result.stdout.count("\n"))
                    self.assertLess(len(result.stdout), 1024)
                    self.assertNotIn("Traceback", result.stderr)

    def test_missing_command_is_bounded_unknown_json_and_source_is_python36_compatible(self):
        result = subprocess.run(
            [sys.executable, str(CONTROL_PATH)],
            check=True,
            capture_output=True,
            text=True,
        )
        self.assertEqual(
            {"path": "planned_maintenance", "reasons": ["unknown_compatibility"]},
            json.loads(result.stdout),
        )
        source = CONTROL_PATH.read_text(encoding="utf-8")
        self.assertNotIn("from __future__ import annotations", source)
        self.assertNotIn("add_subparsers(dest=\"command\", required=True)", source)


if __name__ == "__main__":
    unittest.main()
