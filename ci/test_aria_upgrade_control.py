#!/usr/bin/env python3
"""Unit contracts for the read-only Aria runtime-upgrade classifier."""

import importlib.util
import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest
import uuid
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
CONTROL_PATH = ROOT / "deploy" / "kolla" / "package" / "aria_upgrade_control.py"
AGENT_STATE_PATH = (
    ROOT / "openstack" / "neutron_aria" / "neutron_aria" / "agent" / "state.py"
)
COMPATIBILITY = {
    "schema_version": 1,
    "uds_schema_min": 1,
    "uds_schema_max": 1,
    "snapshot_schema_version": 1,
    "ebpf_abi_version": 2,
    "map_schema_version": 2,
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

    def test_joint_change_precedes_datapath_compatibility_reasons(self):
        control = self.control()
        candidate = manifest("3", "4")
        candidate["runtime_compatibility"]["map_schema_hash"] = "c" * 64
        result = control.classify_upgrade(manifest(), candidate)
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

    def test_disjoint_uds_range_precedes_datapath_compatibility_reasons(self):
        control = self.control()
        candidate = manifest()
        candidate["runtime_compatibility"]["uds_schema_min"] = 2
        candidate["runtime_compatibility"]["uds_schema_max"] = 2
        candidate["runtime_compatibility"]["map_schema_hash"] = "c" * 64
        result = control.classify_upgrade(manifest(), candidate)
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
        current = manifest()
        current["runtime_compatibility"]["maintenance_gate_capable"] = False
        candidate = manifest("3")
        result = control.classify_upgrade(current, candidate)
        self.assertEqual("planned_maintenance", result.path)
        self.assertEqual(("maintenance_gate_capability_changed",), result.reasons)

    def test_maintenance_gate_transition_precedes_datapath_compatibility_reasons(self):
        control = self.control()
        current = manifest()
        current["runtime_compatibility"]["maintenance_gate_capable"] = False
        candidate = manifest()
        candidate["runtime_compatibility"]["wal_schema_version"] += 1
        result = control.classify_upgrade(current, candidate)
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

    def test_abi_and_map_version_only_bumps_require_planned_maintenance(self):
        control = self.control()
        for key in ("ebpf_abi_version", "map_schema_version"):
            with self.subTest(key=key):
                candidate = manifest()
                candidate["runtime_compatibility"][key] += 1
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
            "registry.example:5000/repo..name/image:tag@sha256:" + "a" * 64,
            "registry.example:5000/repo___name/image:tag@sha256:" + "a" * 64,
            "registry.example:5000/repo._name/image:tag@sha256:" + "a" * 64,
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

    def test_force_maintenance_precedes_joint_uds_gate_and_datapath_changes(self):
        control = self.control()
        candidate = manifest("3", "4")
        candidate["runtime_compatibility"]["uds_schema_min"] = 2
        candidate["runtime_compatibility"]["uds_schema_max"] = 2
        candidate["runtime_compatibility"]["maintenance_gate_capable"] = True
        candidate["runtime_compatibility"]["map_schema_hash"] = "c" * 64
        result = control.classify_upgrade(manifest(), candidate, force_maintenance=True)
        self.assertEqual("planned_maintenance", result.path)
        self.assertEqual(("operator_forced",), result.reasons)

    def test_duplicate_manifest_members_are_unknown_for_loader_and_cli(self):
        control = self.control()
        payload = json.dumps(manifest())
        duplicate_runtime = payload.replace(
            '"schema_version": 1', '"schema_version": 1, "schema_version": 1', 1
        )
        duplicate_images = payload.replace(
            '"identity": "neutron-aria-agent:v0.9@sha256:' + "1" * 64 + '"',
            '"identity": "neutron-aria-agent:v0.9@sha256:' + "1" * 64
            + '", "identity": "neutron-aria-agent:v0.9@sha256:' + "1" * 64 + '"',
            1,
        )
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir).resolve()
            for name, text in (("runtime.json", duplicate_runtime), ("images.json", duplicate_images)):
                with self.subTest(name=name):
                    path = temp / name
                    path.write_text(text, encoding="utf-8")
                    with self.assertRaisesRegex(ValueError, "duplicate JSON object member"):
                        control.load_manifest(path)
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

    def test_classify_command_prints_bounded_json_without_docker(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir).resolve()
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
            self.assertFalse(marker.exists(), "dry-run must not execute Docker")
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

    def test_invalid_missing_and_deep_cli_manifests_are_bounded_unknown_json(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir).resolve()
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


class UpgradeLedgerTest(unittest.TestCase):
    def control(self):
        spec = importlib.util.spec_from_file_location("aria_upgrade_control", CONTROL_PATH)
        module = importlib.util.module_from_spec(spec)
        assert spec.loader is not None
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        return module

    def agent_state(self):
        spec = importlib.util.spec_from_file_location(
            "neutron_aria_agent_state_for_ledger_test", AGENT_STATE_PATH
        )
        module = importlib.util.module_from_spec(spec)
        assert spec.loader is not None
        spec.loader.exec_module(module)
        return module

    def new_ledger(self, control, temp, audit=None):
        return control.UpgradeLedger(
            operations_dir=temp / "operations",
            lock_path=temp / "aria-release.lock",
            owner_uid=os.getuid(),
            audit_sink=audit,
        )

    def operation(self, suffix="1"):
        return str(uuid.UUID(suffix * 32))

    def evidence(self):
        return {
            "affected_domains": ["acl"],
            "old_image_ids": {"aria-datapath": "sha256:" + "1" * 64},
            "candidate_image_ids": {"aria-datapath": "sha256:" + "2" * 64},
            "old_manifest_hash": "sha256:" + "3" * 64,
            "candidate_manifest_hash": "sha256:" + "4" * 64,
            "old_config_hash": "sha256:" + "5" * 64,
            "candidate_config_hash": "sha256:" + "6" * 64,
            "pre_accepted_generation": 10,
            "pre_applied_generation": 9,
            "pre_desired_hash": "sha256:" + "7" * 64,
            "pre_managed_port_ids": ["port-a"],
            "maintenance_token": "maintenance-secret",
            "ovs_vswitchd_pid": 101,
            "ovs_agent_container_id": "ovs-agent-id",
            "ovs_agent_started_at": "2026-08-21T00:00:00Z",
            "br_int_uuid": "br-int-uuid",
        }

    def begin(self, ledger, operation_id=None):
        return ledger.begin(
            operation_id or self.operation(),
            host="compute-1",
            upgrade_class="planned_maintenance",
            evidence=self.evidence(),
        )

    def read_ledger(self, temp, operation_id=None):
        path = temp / "operations" / ((operation_id or self.operation()) + ".json")
        return json.loads(path.read_text(encoding="utf-8"))

    def write_ledger(self, temp, state, operation_id=None):
        path = temp / "operations" / ((operation_id or self.operation()) + ".json")
        path.write_text(
            json.dumps(state, sort_keys=True, separators=(",", ":")) + "\n",
            encoding="utf-8",
        )
        path.chmod(0o600)

    def directory_name_for_fd(self, fd, directories):
        descriptor_stat = os.fstat(fd)
        if not stat.S_ISDIR(descriptor_stat.st_mode):
            return None
        for name, path in directories:
            if not path.exists():
                continue
            path_stat = path.stat()
            if (path_stat.st_dev, path_stat.st_ino) == (
                descriptor_stat.st_dev, descriptor_stat.st_ino,
            ):
                return name
        return None

    def test_allowed_transition_table_is_the_reviewed_contract(self):
        control = self.control()
        self.assertEqual(
            {
                "preflight": ("quiescing", "failed_before_mutation"),
                "quiescing": ("bypass_preparing",),
                "bypass_preparing": ("bypass_confirmed",),
                "bypass_confirmed": ("datapath_upgrading", "maintenance_bypass"),
                "datapath_upgrading": ("datapath_live", "maintenance_bypass"),
                "datapath_live": ("agent_upgrading", "maintenance_bypass"),
                "agent_upgrading": ("agent_buffering", "maintenance_bypass"),
                "agent_buffering": ("full_resync", "maintenance_bypass"),
                "full_resync": ("shadow_apply", "maintenance_bypass"),
                "shadow_apply": ("activating", "maintenance_bypass"),
                "activating": ("verifying", "maintenance_bypass"),
                "verifying": ("committed", "maintenance_bypass"),
                "maintenance_bypass": ("full_resync", "rollback"),
                "rollback": ("full_resync", "maintenance_bypass"),
            },
            control.ALLOWED,
        )

    def test_every_authoritative_edge_persists_and_every_other_edge_is_rejected(self):
        control = self.control()
        authoritative = {
            "preflight": ("quiescing", "failed_before_mutation"),
            "quiescing": ("bypass_preparing",),
            "bypass_preparing": ("bypass_confirmed",),
            "bypass_confirmed": ("datapath_upgrading", "maintenance_bypass"),
            "datapath_upgrading": ("datapath_live", "maintenance_bypass"),
            "datapath_live": ("agent_upgrading", "maintenance_bypass"),
            "agent_upgrading": ("agent_buffering", "maintenance_bypass"),
            "agent_buffering": ("full_resync", "maintenance_bypass"),
            "full_resync": ("shadow_apply", "maintenance_bypass"),
            "shadow_apply": ("activating", "maintenance_bypass"),
            "activating": ("verifying", "maintenance_bypass"),
            "verifying": ("committed", "maintenance_bypass"),
            "maintenance_bypass": ("full_resync", "rollback"),
            "rollback": ("full_resync", "maintenance_bypass"),
        }
        phases = sorted(
            frozenset(authoritative)
            | frozenset(
                phase
                for destinations in authoritative.values()
                for phase in destinations
            )
        )
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir).resolve()
            ledger = self.new_ledger(control, temp)
            self.begin(ledger)
            for old_phase, destinations in authoritative.items():
                for next_phase in destinations:
                    with self.subTest(kind="positive", edge=(old_phase, next_phase)):
                        state = self.read_ledger(temp)
                        state["phase"] = old_phase
                        self.write_ledger(temp, state)
                        result = ledger.transition(old_phase, next_phase, {})
                        self.assertEqual(next_phase, result["phase"])
            for old_phase in phases:
                for next_phase in phases:
                    if next_phase == old_phase or next_phase in authoritative.get(
                        old_phase, ()
                    ):
                        continue
                    with self.subTest(kind="negative", edge=(old_phase, next_phase)):
                        state = self.read_ledger(temp)
                        state["phase"] = old_phase
                        self.write_ledger(temp, state)
                        with self.assertRaises(control.UpgradeLedgerTransitionError):
                            ledger.transition(old_phase, next_phase, {})
                        self.assertEqual(old_phase, self.read_ledger(temp)["phase"])
            ledger.close()

    def test_begin_persists_complete_root_trusted_mode_0600_ledger(self):
        control = self.control()
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir).resolve()
            ledger = self.new_ledger(control, temp)
            state = self.begin(ledger)
            path = temp / "operations" / (self.operation() + ".json")
            self.assertEqual(state, self.read_ledger(temp))
            self.assertEqual("preflight", state["phase"])
            self.assertEqual(1, state["schema_version"])
            self.assertEqual(0o600, path.stat().st_mode & 0o777)
            for field in (
                "schema_version", "operation_id", "host", "phase", "started_at",
                "last_progress_at", "upgrade_class", "affected_domains", "old_image_ids",
                "candidate_image_ids", "old_manifest_hash", "candidate_manifest_hash",
                "old_config_hash", "candidate_config_hash", "pre_accepted_generation",
                "pre_applied_generation", "pre_desired_hash", "pre_managed_port_ids",
                "maintenance_token", "ovs_vswitchd_pid", "ovs_agent_container_id",
                "ovs_agent_started_at", "br_int_uuid", "last_error", "recovery_action",
            ):
                self.assertIn(field, state)
            ledger.close()

    def test_first_begin_fsyncs_created_directory_parents_in_order(self):
        control = self.control()
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir).resolve()
            release = temp / "aria-release"
            operations = release / "operations"
            directories = (
                ("workspace", temp),
                ("aria-release", release),
                ("operations", operations),
            )
            directory_fsyncs = []
            real_fsync = control.os.fsync

            def record_fsync(fd):
                name = self.directory_name_for_fd(fd, directories)
                if name is not None:
                    directory_fsyncs.append(name)
                return real_fsync(fd)

            ledger = control.UpgradeLedger(
                operations_dir=operations,
                lock_path=temp / "aria-release.lock",
                owner_uid=os.getuid(),
            )
            with mock.patch.object(control.os, "fsync", side_effect=record_fsync):
                self.begin(ledger)
            self.assertEqual(
                ["workspace", "aria-release", "operations"], directory_fsyncs
            )
            self.assertEqual("preflight", json.loads(
                (operations / (self.operation() + ".json")).read_text(encoding="utf-8")
            )["phase"])
            ledger.close()

    def test_first_begin_directory_fsync_failures_never_leave_partial_ledger(self):
        control = self.control()
        for failed_directory in ("workspace", "aria-release", "operations"):
            with self.subTest(failed_directory=failed_directory):
                with tempfile.TemporaryDirectory() as temp_dir:
                    temp = Path(temp_dir).resolve()
                    release = temp / "aria-release"
                    operations = release / "operations"
                    directories = (
                        ("workspace", temp),
                        ("aria-release", release),
                        ("operations", operations),
                    )
                    real_fsync = control.os.fsync

                    def fail_selected_directory(fd):
                        name = self.directory_name_for_fd(fd, directories)
                        if name == failed_directory:
                            raise OSError("directory fsync crash: " + name)
                        return real_fsync(fd)

                    ledger = control.UpgradeLedger(
                        operations_dir=operations,
                        lock_path=temp / "aria-release.lock",
                        owner_uid=os.getuid(),
                    )
                    with mock.patch.object(
                        control.os, "fsync", side_effect=fail_selected_directory
                    ):
                        with self.assertRaisesRegex(
                            OSError, "directory fsync crash: " + failed_directory
                        ):
                            self.begin(ledger)
                    ledger_path = operations / (self.operation() + ".json")
                    if ledger_path.exists():
                        state = json.loads(ledger_path.read_text(encoding="utf-8"))
                        self.assertEqual(self.operation(), state["operation_id"])
                        self.assertEqual("preflight", state["phase"])
                    else:
                        self.assertFalse(ledger_path.exists())
                    ledger.close()

    def test_retry_after_directory_fsync_failure_reestablishes_durability(self):
        control = self.control()
        for failed_directory in ("workspace", "aria-release", "operations"):
            with self.subTest(failed_directory=failed_directory):
                with tempfile.TemporaryDirectory() as temp_dir:
                    temp = Path(temp_dir).resolve()
                    release = temp / "aria-release"
                    operations = release / "operations"
                    directories = (
                        ("workspace", temp),
                        ("aria-release", release),
                        ("operations", operations),
                    )
                    real_fsync = control.os.fsync
                    failure_injected = [False]

                    def fail_selected_directory_once(fd):
                        name = self.directory_name_for_fd(fd, directories)
                        if name == failed_directory and not failure_injected[0]:
                            failure_injected[0] = True
                            raise OSError("directory fsync crash: " + name)
                        return real_fsync(fd)

                    first = control.UpgradeLedger(
                        operations_dir=operations,
                        lock_path=temp / "aria-release.lock",
                        owner_uid=os.getuid(),
                    )
                    with mock.patch.object(
                        control.os, "fsync", side_effect=fail_selected_directory_once
                    ):
                        with self.assertRaisesRegex(
                            OSError, "directory fsync crash: " + failed_directory
                        ):
                            self.begin(first)
                    first.close()

                    retry_fsyncs = []

                    def record_retry_fsync(fd):
                        name = self.directory_name_for_fd(fd, directories)
                        if name is not None:
                            retry_fsyncs.append(name)
                        return real_fsync(fd)

                    retry = control.UpgradeLedger(
                        operations_dir=operations,
                        lock_path=temp / "aria-release.lock",
                        owner_uid=os.getuid(),
                    )
                    with mock.patch.object(
                        control.os, "fsync", side_effect=record_retry_fsync
                    ):
                        state = self.begin(retry)
                    self.assertEqual("preflight", state["phase"])
                    self.assertIn(
                        failed_directory,
                        retry_fsyncs,
                        "retry must durably reestablish the failed directory entry",
                    )
                    retry.close()

    def test_existing_release_symlink_redirect_is_rejected(self):
        control = self.control()
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir).resolve()
            target = temp / "trusted-target"
            operations = target / "operations"
            operations.mkdir(parents=True, mode=0o700)
            target.chmod(0o700)
            (temp / "aria-release").symlink_to(target, target_is_directory=True)
            ledger = control.UpgradeLedger(
                operations_dir=temp / "aria-release" / "operations",
                lock_path=temp / "aria-release.lock",
                owner_uid=os.getuid(),
            )
            try:
                with self.assertRaises(control.UpgradeLedgerTrustError):
                    self.begin(ledger)
                self.assertFalse(
                    (operations / (self.operation() + ".json")).exists()
                )
            finally:
                ledger.close()

    def test_release_component_replacement_does_not_follow_redirect(self):
        control = self.control()
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir).resolve()
            release = temp / "aria-release"
            release.mkdir(mode=0o700)
            displaced = temp / "aria-release.displaced"
            target = temp / "redirect-target"
            target.mkdir(mode=0o700)
            operations = release / "operations"
            real_mkdir = control.os.mkdir
            real_path_mkdir = Path.mkdir
            replaced = [False]

            def replace_release(path):
                if Path(path).name == "operations" and not replaced[0]:
                    release.rename(displaced)
                    release.symlink_to(target, target_is_directory=True)
                    replaced[0] = True

            def replace_before_os_mkdir(path, mode=0o777, **kwargs):
                replace_release(path)
                return real_mkdir(path, mode, **kwargs)

            def replace_before_path_mkdir(path, mode=0o777, parents=False, exist_ok=False):
                replace_release(path)
                return real_path_mkdir(path, mode, parents, exist_ok)

            ledger = control.UpgradeLedger(
                operations_dir=operations,
                lock_path=temp / "aria-release.lock",
                owner_uid=os.getuid(),
            )
            try:
                with mock.patch.object(
                    control.os,
                    "mkdir",
                    side_effect=replace_before_os_mkdir,
                ), mock.patch.object(
                    Path, "mkdir", side_effect=replace_before_path_mkdir, autospec=True
                ), mock.patch.object(
                    control.os, "rmdir", side_effect=OSError("cleanup crash")
                ), mock.patch.object(
                    Path, "rmdir", side_effect=OSError("cleanup crash"), autospec=True
                ):
                    with self.assertRaises(control.UpgradeLedgerTrustError):
                        self.begin(ledger)
                self.assertFalse(
                    (target / "operations").exists(),
                    "a replaced release component must never redirect child creation",
                )
            finally:
                ledger.close()

    def test_lock_directory_intermediate_symlink_redirect_is_rejected(self):
        control = self.control()
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir).resolve()
            target = temp / "lock-target"
            locks = target / "locks"
            locks.mkdir(parents=True, mode=0o700)
            target.chmod(0o700)
            (temp / "redirect").symlink_to(target, target_is_directory=True)
            ledger = control.UpgradeLedger(
                operations_dir=temp / "operations",
                lock_path=temp / "redirect" / "locks" / "aria-release.lock",
                owner_uid=os.getuid(),
            )
            try:
                with self.assertRaises(control.UpgradeLedgerTrustError):
                    self.begin(ledger)
                self.assertFalse((locks / "aria-release.lock").exists())
            finally:
                ledger.close()

    def test_earlier_state_anchor_symlink_component_is_rejected(self):
        control = self.control()
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir).resolve()
            target = temp / "target"
            state_root = target / "state-root"
            operations = state_root / "aria-release" / "operations"
            operations.mkdir(parents=True, mode=0o700)
            state_root.chmod(0o700)
            (state_root / "aria-release").chmod(0o700)
            target.chmod(0o700)
            (temp / "earlier").symlink_to(target, target_is_directory=True)
            ledger = control.UpgradeLedger(
                operations_dir=(
                    temp / "earlier" / "state-root" / "aria-release" / "operations"
                ),
                lock_path=temp / "aria-release.lock",
                owner_uid=os.getuid(),
            )
            try:
                with self.assertRaises(control.UpgradeLedgerTrustError):
                    self.begin(ledger)
            finally:
                ledger.close()

    def test_earlier_lock_anchor_symlink_component_is_rejected(self):
        control = self.control()
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir).resolve()
            target = temp / "lock-target"
            locks = target / "lock-root" / "locks"
            locks.mkdir(parents=True, mode=0o700)
            (target / "lock-root").chmod(0o700)
            target.chmod(0o700)
            (temp / "earlier").symlink_to(target, target_is_directory=True)
            ledger = control.UpgradeLedger(
                operations_dir=temp / "operations",
                lock_path=(
                    temp / "earlier" / "lock-root" / "locks" / "aria-release.lock"
                ),
                owner_uid=os.getuid(),
            )
            try:
                with self.assertRaises(control.UpgradeLedgerTrustError):
                    self.begin(ledger)
            finally:
                ledger.close()

    def test_group_writable_lock_directory_requires_the_trusted_group(self):
        control = self.control()
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir).resolve()
            locks = temp / "locks"
            locks.mkdir(mode=0o770)
            locks.chmod(0o770)
            trusted = control.UpgradeLedger(
                operations_dir=temp / "operations",
                lock_path=locks / "aria-release.lock",
                owner_uid=os.getuid(),
                trusted_gid=os.getgid(),
            )
            self.begin(trusted)
            trusted.close()

            rejected = control.UpgradeLedger(
                operations_dir=temp / "operations",
                lock_path=locks / "aria-release.lock",
                owner_uid=os.getuid(),
                trusted_gid=os.getgid() + 1,
            )
            with self.assertRaises(control.UpgradeLedgerTrustError):
                self.begin(rejected)
            rejected.close()

    def test_lock_parent_replacement_after_flock_is_rejected(self):
        control = self.control()
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir).resolve()
            locks = temp / "locks"
            locks.mkdir(mode=0o700)
            displaced = temp / "locks.displaced"
            real_flock = control.fcntl.flock
            replaced = [False]

            def replace_parent_after_flock(fd, operation):
                result = real_flock(fd, operation)
                if operation & control.fcntl.LOCK_EX and not replaced[0]:
                    locks.rename(displaced)
                    locks.mkdir(mode=0o700)
                    replaced[0] = True
                return result

            ledger = control.UpgradeLedger(
                operations_dir=temp / "operations",
                lock_path=locks / "aria-release.lock",
                owner_uid=os.getuid(),
            )
            try:
                with mock.patch.object(
                    control.fcntl, "flock", side_effect=replace_parent_after_flock
                ):
                    with self.assertRaises(control.UpgradeLedgerTrustError):
                        self.begin(ledger)
            finally:
                ledger.close()

    def test_anchor_and_child_fstat_failures_close_every_opened_descriptor(self):
        control = self.control()
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir).resolve()
            ledger = self.new_ledger(control, temp)
            real_open = control.os.open
            real_fstat = control.os.fstat
            opened = []

            def record_open(*args, **kwargs):
                fd = real_open(*args, **kwargs)
                opened.append(fd)
                return fd

            def fail_anchor_fstat(fd):
                if opened and fd == opened[0]:
                    raise OSError("anchor fstat crash")
                return real_fstat(fd)

            with mock.patch.object(control.os, "open", side_effect=record_open), mock.patch.object(
                control.os, "fstat", side_effect=fail_anchor_fstat
            ):
                with self.assertRaisesRegex(
                    control.UpgradeLedgerTrustError, "anchor fstat crash"
                ):
                    self.begin(ledger)
            self.assertTrue(opened)
            for fd in opened:
                with self.assertRaises(OSError):
                    os.fstat(fd)
            ledger.close()

        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir).resolve()
            release = temp / "aria-release"
            release.mkdir(mode=0o700)
            ledger = control.UpgradeLedger(
                operations_dir=release / "operations",
                lock_path=temp / "aria-release.lock",
                owner_uid=os.getuid(),
            )
            ledger._acquire_lock()
            real_open = control.os.open
            real_fstat = control.os.fstat
            opened = []
            fstat_count = [0]

            def record_child_open(*args, **kwargs):
                fd = real_open(*args, **kwargs)
                opened.append(fd)
                return fd

            def fail_child_fstat(fd):
                if fd in opened:
                    fstat_count[0] += 1
                    if fstat_count[0] == 2:
                        raise OSError("child fstat crash")
                return real_fstat(fd)

            with mock.patch.object(
                control.os, "open", side_effect=record_child_open
            ), mock.patch.object(control.os, "fstat", side_effect=fail_child_fstat):
                with self.assertRaisesRegex(
                    control.UpgradeLedgerTrustError, "child fstat crash"
                ):
                    ledger._ensure_operations_dir()
            for fd in opened:
                with self.assertRaises(OSError):
                    os.fstat(fd)
            ledger.close()

    def test_cleanup_failed_retry_fsyncs_the_complete_managed_chain(self):
        control = self.control()
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir).resolve()
            release = temp / "aria-release"
            operations = release / "operations"
            directories = (
                ("workspace", temp),
                ("aria-release", release),
                ("operations", operations),
            )
            real_fsync = control.os.fsync

            def fail_workspace_fsync(fd):
                if self.directory_name_for_fd(fd, directories) == "workspace":
                    raise OSError("workspace fsync crash")
                return real_fsync(fd)

            first = control.UpgradeLedger(
                operations_dir=operations,
                lock_path=temp / "aria-release.lock",
                owner_uid=os.getuid(),
            )
            with mock.patch.object(
                control.os, "fsync", side_effect=fail_workspace_fsync
            ), mock.patch.object(
                control.os, "rmdir", side_effect=OSError("cleanup crash")
            ), mock.patch.object(
                Path, "rmdir", side_effect=OSError("cleanup crash"), autospec=True
            ):
                with self.assertRaisesRegex(OSError, "workspace fsync crash"):
                    self.begin(first)
            first.close()
            self.assertTrue(release.is_dir())

            confirmed = []

            def record_fsync(fd):
                name = self.directory_name_for_fd(fd, directories)
                if name is not None:
                    confirmed.append(name)
                return real_fsync(fd)

            retry = control.UpgradeLedger(
                operations_dir=operations,
                lock_path=temp / "aria-release.lock",
                owner_uid=os.getuid(),
            )
            with mock.patch.object(control.os, "fsync", side_effect=record_fsync):
                self.begin(retry)
            retry.close()
            self.assertTrue(
                all(name in confirmed for name in ("workspace", "aria-release", "operations")),
                "retry must confirm every managed directory entry: %r" % confirmed,
            )

    def test_successful_directory_cleanup_is_parent_fsynced(self):
        control = self.control()
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir).resolve()
            release = temp / "aria-release"
            operations = release / "operations"
            directories = (("workspace", temp), ("aria-release", release))
            real_fsync = control.os.fsync
            workspace_attempts = [0]

            def fail_first_workspace_fsync(fd):
                if self.directory_name_for_fd(fd, directories) == "workspace":
                    workspace_attempts[0] += 1
                    if workspace_attempts[0] == 1:
                        raise OSError("workspace fsync crash")
                return real_fsync(fd)

            ledger = control.UpgradeLedger(
                operations_dir=operations,
                lock_path=temp / "aria-release.lock",
                owner_uid=os.getuid(),
            )
            with mock.patch.object(
                control.os, "fsync", side_effect=fail_first_workspace_fsync
            ):
                with self.assertRaisesRegex(OSError, "workspace fsync crash"):
                    self.begin(ledger)
            ledger.close()
            self.assertFalse(release.exists())
            self.assertGreaterEqual(
                workspace_attempts[0], 2,
                "removing an unconfirmed directory must fsync its parent",
            )

    def test_duplicate_operation_is_idempotent_and_conflicting_operation_is_rejected(self):
        control = self.control()
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir).resolve()
            first = self.new_ledger(control, temp)
            original = self.begin(first)
            duplicate = self.begin(first)
            self.assertEqual(original, duplicate)
            first.close()

            replay = self.new_ledger(control, temp)
            self.assertEqual(original, self.begin(replay))
            replay.close()

            conflict = self.new_ledger(control, temp)
            with self.assertRaises(control.UpgradeLedgerConflict):
                self.begin(conflict, self.operation("2"))
            conflict.close()
            self.assertFalse(
                (temp / "operations" / (self.operation("2") + ".json")).exists()
            )

    def test_reacquired_closed_instance_discards_stale_cached_operation(self):
        control = self.control()
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir).resolve()
            reused = self.new_ledger(control, temp)
            cached = self.begin(reused)
            reused.close()

            finisher = self.new_ledger(control, temp)
            finisher.recover(self.operation())
            finisher.fail("preflight", "finished before mutation")
            finisher.close()

            pending = self.new_ledger(control, temp)
            self.begin(pending, self.operation("2"))
            pending.close()

            with self.assertRaises(control.UpgradeLedgerConflict):
                self.begin(reused)
            self.assertNotEqual(
                cached,
                self.read_ledger(temp),
                "the first operation must have been durably advanced",
            )
            fresh = self.new_ledger(control, temp)
            fresh.recover(self.operation("2"))
            fresh.close()
            reused.close()

    def test_host_lock_is_exclusive_and_nonblocking(self):
        control = self.control()
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir).resolve()
            owner = self.new_ledger(control, temp)
            self.begin(owner)
            contender = self.new_ledger(control, temp)
            with self.assertRaises(control.UpgradeLedgerLocked):
                self.begin(contender, self.operation("2"))
            contender.close()
            owner.close()

    def test_failed_begin_workflows_release_the_host_lock(self):
        control = self.control()
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir).resolve()
            failed = self.new_ledger(control, temp)
            with self.assertRaises(ValueError):
                failed.begin(
                    self.operation(), host="", upgrade_class="planned_maintenance"
                )
            fresh = self.new_ledger(control, temp)
            self.begin(fresh)
            fresh.close()
            failed.close()

        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir).resolve()
            owner = self.new_ledger(control, temp)
            self.begin(owner)
            owner.close()
            failed = self.new_ledger(control, temp)
            with self.assertRaises(control.UpgradeLedgerConflict):
                self.begin(failed, self.operation("2"))
            fresh = self.new_ledger(control, temp)
            self.begin(fresh)
            fresh.close()
            failed.close()

        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir).resolve()
            operations = temp / "operations"
            operations.mkdir()
            target = temp / "target.json"
            target.write_text("{}", encoding="utf-8")
            poisoned = operations / (self.operation() + ".json")
            poisoned.symlink_to(target)
            failed = self.new_ledger(control, temp)
            with self.assertRaises(control.UpgradeLedgerTrustError):
                self.begin(failed)
            poisoned.unlink()
            fresh = self.new_ledger(control, temp)
            self.begin(fresh)
            fresh.close()
            failed.close()

    def test_failed_recover_workflows_release_the_host_lock(self):
        control = self.control()
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir).resolve()
            failed = self.new_ledger(control, temp)
            with self.assertRaises(control.UpgradeLedgerError):
                failed.recover(self.operation())
            fresh = self.new_ledger(control, temp)
            self.begin(fresh)
            fresh.close()
            failed.close()

        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir).resolve()
            owner = self.new_ledger(control, temp)
            self.begin(owner)
            owner.close()
            failed = self.new_ledger(control, temp)
            with self.assertRaises(control.UpgradeLedgerConflict):
                failed.recover(self.operation("2"))
            fresh = self.new_ledger(control, temp)
            fresh.recover(self.operation())
            fresh.close()
            failed.close()

        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir).resolve()
            owner = self.new_ledger(control, temp)
            self.begin(owner)
            owner.close()
            path = temp / "operations" / (self.operation() + ".json")
            path.chmod(0o644)
            failed = self.new_ledger(control, temp)
            with self.assertRaises(control.UpgradeLedgerTrustError):
                failed.recover(self.operation())
            path.chmod(0o600)
            fresh = self.new_ledger(control, temp)
            fresh.recover(self.operation())
            fresh.close()
            failed.close()

    def test_nested_failed_workflows_do_not_release_a_preowned_lock(self):
        control = self.control()
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir).resolve()
            owner = self.new_ledger(control, temp)
            self.begin(owner)

            with self.assertRaises(control.UpgradeLedgerConflict):
                self.begin(owner, self.operation("2"))
            contender = self.new_ledger(control, temp)
            with self.assertRaises(control.UpgradeLedgerLocked):
                self.begin(contender, self.operation("2"))
            contender.close()

            with self.assertRaises(control.UpgradeLedgerConflict):
                owner.recover(self.operation("2"))
            contender = self.new_ledger(control, temp)
            with self.assertRaises(control.UpgradeLedgerLocked):
                self.begin(contender, self.operation("2"))
            contender.close()

            owner.close()
            released = self.new_ledger(control, temp)
            released.recover(self.operation())
            released.close()

    def test_hard_linked_lock_file_is_rejected(self):
        control = self.control()
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir).resolve()
            lock_path = temp / "aria-release.lock"
            lock_path.write_text("", encoding="utf-8")
            lock_path.chmod(0o600)
            os.link(str(lock_path), str(temp / "aria-release.lock.alias"))
            ledger = self.new_ledger(control, temp)
            try:
                with self.assertRaises(control.UpgradeLedgerTrustError):
                    self.begin(ledger)
            finally:
                ledger.close()

    def test_transition_is_compare_and_swap_and_rejects_skips_and_backwards_edges(self):
        control = self.control()
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir).resolve()
            ledger = self.new_ledger(control, temp)
            self.begin(ledger)
            with self.assertRaises(control.UpgradeLedgerTransitionError):
                ledger.transition("bypass_preparing", "bypass_confirmed", {})
            with self.assertRaises(control.UpgradeLedgerTransitionError):
                ledger.transition("preflight", "bypass_confirmed", {})
            state = ledger.transition("preflight", "quiescing", {"generation": 11})
            self.assertEqual("quiescing", state["phase"])
            state = ledger.transition("quiescing", "bypass_preparing", {})
            self.assertEqual("bypass_preparing", state["phase"])
            with self.assertRaises(control.UpgradeLedgerTransitionError):
                ledger.transition("bypass_preparing", "preflight", {})
            self.assertEqual("bypass_preparing", self.read_ledger(temp)["phase"])
            ledger.close()

    def test_transition_compare_and_swap_checks_the_durable_phase(self):
        control = self.control()
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir).resolve()
            ledger = self.new_ledger(control, temp)
            self.begin(ledger)
            path = temp / "operations" / (self.operation() + ".json")
            changed = self.read_ledger(temp)
            changed["phase"] = "bypass_preparing"
            path.write_text(
                json.dumps(changed, sort_keys=True, separators=(",", ":")) + "\n",
                encoding="utf-8",
            )
            path.chmod(0o600)
            with self.assertRaises(control.UpgradeLedgerTransitionError):
                ledger.transition("preflight", "quiescing", {})
            self.assertEqual("bypass_preparing", self.read_ledger(temp)["phase"])
            ledger.close()

    def test_fail_compare_and_swap_checks_the_durable_phase(self):
        control = self.control()
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir).resolve()
            ledger = self.new_ledger(control, temp)
            self.begin(ledger)
            ledger.transition("preflight", "quiescing", {})
            ledger.transition("quiescing", "bypass_preparing", {})
            durable = self.read_ledger(temp)
            durable["phase"] = "bypass_confirmed"
            self.write_ledger(temp, durable)
            with self.assertRaises(control.UpgradeLedgerTransitionError):
                ledger.fail("bypass_preparing", "stale failure")
            self.assertEqual(durable, self.read_ledger(temp))
            ledger.close()

    def test_fail_rejects_terminal_ledgers_without_mutation(self):
        control = self.control()
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir).resolve()
            ledger = self.new_ledger(control, temp)
            self.begin(ledger)
            ledger.fail("preflight", "preflight rejected")
            terminal = self.read_ledger(temp)
            with self.assertRaises(control.UpgradeLedgerTransitionError):
                ledger.fail("failed_before_mutation", "must not change")
            self.assertEqual(terminal, self.read_ledger(temp))
            ledger.close()

        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir).resolve()
            ledger = self.new_ledger(control, temp)
            self.begin(ledger)
            for old, new in (
                ("preflight", "quiescing"),
                ("quiescing", "bypass_preparing"),
                ("bypass_preparing", "bypass_confirmed"),
                ("bypass_confirmed", "datapath_upgrading"),
                ("datapath_upgrading", "datapath_live"),
                ("datapath_live", "agent_upgrading"),
                ("agent_upgrading", "agent_buffering"),
                ("agent_buffering", "full_resync"),
                ("full_resync", "shadow_apply"),
                ("shadow_apply", "activating"),
                ("activating", "verifying"),
            ):
                ledger.transition(old, new, {})
            ledger.commit({})
            terminal = self.read_ledger(temp)
            with self.assertRaises(control.UpgradeLedgerTransitionError):
                ledger.fail("committed", "must not change")
            self.assertEqual(terminal, self.read_ledger(temp))
            ledger.close()

    def test_design_quiescing_and_agent_buffering_edges_are_persistable(self):
        control = self.control()
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir).resolve()
            ledger = self.new_ledger(control, temp)
            self.begin(ledger)
            self.assertEqual(
                "quiescing", ledger.transition("preflight", "quiescing", {})["phase"]
            )
            self.assertEqual(
                "bypass_preparing",
                ledger.transition("quiescing", "bypass_preparing", {})["phase"],
            )
            ledger.transition("bypass_preparing", "bypass_confirmed", {})
            ledger.transition("bypass_confirmed", "datapath_upgrading", {})
            ledger.transition("datapath_upgrading", "datapath_live", {})
            ledger.transition("datapath_live", "agent_upgrading", {})
            self.assertEqual(
                "agent_buffering",
                ledger.transition("agent_upgrading", "agent_buffering", {})["phase"],
            )
            self.assertEqual(
                "full_resync",
                ledger.transition("agent_buffering", "full_resync", {})["phase"],
            )
            ledger.close()

    def test_recover_resumes_design_pause_phases_without_activation(self):
        control = self.control()
        for stale_phase in ("quiescing", "agent_buffering"):
            with self.subTest(stale_phase=stale_phase):
                with tempfile.TemporaryDirectory() as temp_dir:
                    temp = Path(temp_dir).resolve()
                    first = self.new_ledger(control, temp)
                    self.begin(first)
                    stale = self.read_ledger(temp)
                    stale["phase"] = stale_phase
                    self.write_ledger(temp, stale)
                    first.close()
                    recovered = self.new_ledger(control, temp)
                    state = recovered.recover(self.operation())
                    self.assertEqual(stale_phase, state["phase"])
                    self.assertEqual("resume_exact_phase", state["recovery_action"])
                    self.assertNotEqual("committed", state["phase"])
                    recovered.close()

    def test_fail_commit_and_rollback_apis_use_legal_edges(self):
        control = self.control()
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir).resolve()
            early = self.new_ledger(control, temp)
            self.begin(early)
            failed = early.fail("preflight", "preflight rejected")
            self.assertEqual("failed_before_mutation", failed["phase"])
            self.assertEqual("preflight rejected", failed["last_error"])
            early.close()

        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir).resolve()
            ledger = self.new_ledger(control, temp)
            self.begin(ledger)
            for old, new in (
                ("preflight", "quiescing"),
                ("quiescing", "bypass_preparing"),
                ("bypass_preparing", "bypass_confirmed"),
                ("bypass_confirmed", "datapath_upgrading"),
            ):
                ledger.transition(old, new, {})
            failed = ledger.fail("datapath_upgrading", "candidate failed")
            self.assertEqual("maintenance_bypass", failed["phase"])
            rolled_back = ledger.transition("maintenance_bypass", "rollback", {})
            self.assertEqual("rollback", rolled_back["phase"])
            ledger.close()

        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir).resolve()
            ledger = self.new_ledger(control, temp)
            self.begin(ledger)
            for old, new in (
                ("preflight", "quiescing"),
                ("quiescing", "bypass_preparing"),
                ("bypass_preparing", "bypass_confirmed"),
                ("bypass_confirmed", "datapath_upgrading"),
                ("datapath_upgrading", "datapath_live"),
                ("datapath_live", "agent_upgrading"),
                ("agent_upgrading", "agent_buffering"),
                ("agent_buffering", "full_resync"),
                ("full_resync", "shadow_apply"),
                ("shadow_apply", "activating"),
                ("activating", "verifying"),
            ):
                ledger.transition(old, new, {})
            self.assertEqual("committed", ledger.commit({"generation": 12})["phase"])
            ledger.close()

    def test_recover_never_activates_stale_state_and_keeps_unsafe_state_in_bypass(self):
        control = self.control()
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir).resolve()
            first = self.new_ledger(control, temp)
            self.begin(first)
            first.transition("preflight", "quiescing", {})
            first.transition("quiescing", "bypass_preparing", {})
            first.transition("bypass_preparing", "bypass_confirmed", {})
            first.close()

            recovered = self.new_ledger(control, temp)
            state = recovered.recover(self.operation())
            self.assertEqual("maintenance_bypass", state["phase"])
            self.assertEqual("operator_action_required", state["recovery_action"])
            self.assertNotEqual("committed", state["phase"])
            recovered.close()

    def test_failure_before_rename_preserves_previous_parseable_ledger(self):
        control = self.control()
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir).resolve()
            ledger = self.new_ledger(control, temp)
            self.begin(ledger)
            previous = self.read_ledger(temp)
            with mock.patch.object(control.os, "rename", side_effect=OSError("crash")):
                with self.assertRaisesRegex(OSError, "crash"):
                    ledger.transition("preflight", "quiescing", {})
            self.assertEqual(previous, self.read_ledger(temp))
            self.assertEqual([], list((temp / "operations").glob(".*.tmp")))
            ledger.close()

    def test_directory_fsync_failure_leaves_a_complete_parseable_ledger(self):
        control = self.control()
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir).resolve()
            ledger = self.new_ledger(control, temp)
            self.begin(ledger)
            real_fsync = control.os.fsync

            def fail_directory_fsync(fd):
                if stat.S_ISDIR(os.fstat(fd).st_mode):
                    raise OSError("directory fsync crash")
                return real_fsync(fd)

            with mock.patch.object(control.os, "fsync", side_effect=fail_directory_fsync):
                with self.assertRaisesRegex(OSError, "directory fsync crash"):
                    ledger.transition("preflight", "quiescing", {})
            state = self.read_ledger(temp)
            self.assertIn(state["phase"], ("preflight", "quiescing"))
            self.assertEqual(self.operation(), state["operation_id"])
            ledger.close()

    def test_cached_begin_repairs_post_rename_directory_fsync_failure(self):
        control = self.control()
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir).resolve()
            ledger = self.new_ledger(control, temp)
            self.begin(ledger)
            real_fsync = control.os.fsync
            failed = [False]

            def fail_first_directory_fsync(fd):
                if stat.S_ISDIR(os.fstat(fd).st_mode) and not failed[0]:
                    failed[0] = True
                    raise OSError("post-rename directory fsync crash")
                return real_fsync(fd)

            with mock.patch.object(
                control.os, "fsync", side_effect=fail_first_directory_fsync
            ):
                with self.assertRaisesRegex(
                    OSError, "post-rename directory fsync crash"
                ):
                    ledger.transition("preflight", "quiescing", {})
            self.assertEqual("quiescing", ledger.state["phase"])
            self.assertEqual("quiescing", self.read_ledger(temp)["phase"])

            directory_fsyncs = []

            def record_directory_fsync(fd):
                if stat.S_ISDIR(os.fstat(fd).st_mode):
                    directory_fsyncs.append(os.fstat(fd).st_ino)
                return real_fsync(fd)

            with mock.patch.object(
                control.os, "fsync", side_effect=record_directory_fsync
            ):
                reopened = self.begin(ledger)
            self.assertEqual("quiescing", reopened["phase"])
            self.assertTrue(
                directory_fsyncs,
                "cached begin must repair uncertain post-rename durability",
            )
            ledger.close()

    def test_cached_begin_rereads_after_compound_post_rename_failure(self):
        control = self.control()
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir).resolve()
            ledger = self.new_ledger(control, temp)
            self.begin(ledger)
            real_fsync = control.os.fsync
            real_read = ledger._read_ledger
            directory_failed = [False]
            read_count = [0]

            def fail_directory_fsync(fd):
                if stat.S_ISDIR(os.fstat(fd).st_mode) and not directory_failed[0]:
                    directory_failed[0] = True
                    raise OSError("post-rename directory fsync crash")
                return real_fsync(fd)

            def fail_refresh_read(*args, **kwargs):
                read_count[0] += 1
                if read_count[0] == 3:
                    raise control.UpgradeLedgerTrustError("transient refresh read")
                return real_read(*args, **kwargs)

            with mock.patch.object(
                control.os, "fsync", side_effect=fail_directory_fsync
            ), mock.patch.object(
                ledger, "_read_ledger", side_effect=fail_refresh_read
            ):
                with self.assertRaisesRegex(
                    OSError, "post-rename directory fsync crash"
                ):
                    ledger.transition("preflight", "quiescing", {})

            self.assertEqual("preflight", ledger.state["phase"])
            self.assertEqual("quiescing", self.read_ledger(temp)["phase"])
            fsyncs = []

            def record_directory_fsync(fd):
                if stat.S_ISDIR(os.fstat(fd).st_mode):
                    fsyncs.append(fd)
                return real_fsync(fd)

            with mock.patch.object(
                control.os, "fsync", side_effect=record_directory_fsync
            ):
                reopened = self.begin(ledger)
            self.assertEqual("quiescing", reopened["phase"])
            self.assertTrue(fsyncs)
            ledger.close()

    def test_hard_linked_temporary_ledger_is_rejected_before_rename(self):
        control = self.control()
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir).resolve()
            ledger = self.new_ledger(control, temp)
            self.begin(ledger)
            previous = self.read_ledger(temp)
            real_fsync = control.os.fsync
            linked = [False]

            def link_temporary_after_file_fsync(fd):
                result = real_fsync(fd)
                if not stat.S_ISDIR(os.fstat(fd).st_mode) and not linked[0]:
                    temporary = next((temp / "operations").glob(".*.tmp"))
                    os.link(str(temporary), str(temp / "temporary-ledger.alias"))
                    linked[0] = True
                return result

            with mock.patch.object(
                control.os, "fsync", side_effect=link_temporary_after_file_fsync
            ):
                with self.assertRaises(control.UpgradeLedgerTrustError):
                    ledger.transition("preflight", "quiescing", {})
            self.assertEqual(previous, self.read_ledger(temp))
            ledger.close()

    def test_final_ledger_is_revalidated_after_directory_fsync(self):
        control = self.control()
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir).resolve()
            ledger = self.new_ledger(control, temp)
            self.begin(ledger)
            path = temp / "operations" / (self.operation() + ".json")
            real_fsync_operations = ledger._fsync_operations_dir
            changed = [False]

            def corrupt_final_mode_after_fsync():
                result = real_fsync_operations()
                if not changed[0]:
                    path.chmod(0o644)
                    changed[0] = True
                return result

            with mock.patch.object(
                ledger,
                "_fsync_operations_dir",
                side_effect=corrupt_final_mode_after_fsync,
            ):
                with self.assertRaises(control.UpgradeLedgerTrustError):
                    ledger.transition("preflight", "quiescing", {})
            self.assertEqual("quiescing", json.loads(
                path.read_text(encoding="utf-8")
            )["phase"])
            ledger.close()

    def test_existing_symlink_wrong_owner_and_wrong_mode_are_rejected(self):
        control = self.control()
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir).resolve()
            operations = temp / "operations"
            operations.mkdir()
            target = temp / "target.json"
            target.write_text("{}", encoding="utf-8")
            (operations / (self.operation() + ".json")).symlink_to(target)
            ledger = self.new_ledger(control, temp)
            with self.assertRaises(control.UpgradeLedgerTrustError):
                self.begin(ledger)
            ledger.close()

        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir).resolve()
            ledger = self.new_ledger(control, temp)
            self.begin(ledger)
            ledger.close()
            path = temp / "operations" / (self.operation() + ".json")
            path.chmod(0o644)
            reopened = self.new_ledger(control, temp)
            with self.assertRaises(control.UpgradeLedgerTrustError):
                reopened.recover(self.operation())
            reopened.close()

        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir).resolve()
            ledger = self.new_ledger(control, temp)
            self.begin(ledger)
            ledger.close()
            path = temp / "operations" / (self.operation() + ".json")
            real_stat = control.os.stat

            def ledger_with_untrusted_owner(candidate, *args, **kwargs):
                result = real_stat(candidate, *args, **kwargs)
                if (
                    candidate == path.name
                    and kwargs.get("dir_fd") is not None
                    and kwargs.get("follow_symlinks") is False
                ):
                    values = list(result)
                    values[4] = os.getuid() + 1
                    return os.stat_result(values)
                return result

            reopened = self.new_ledger(control, temp)
            with mock.patch.object(
                control.os, "stat", side_effect=ledger_with_untrusted_owner
            ):
                with self.assertRaises(control.UpgradeLedgerTrustError):
                    reopened.recover(self.operation())
            reopened.close()

    def test_duplicate_ledger_json_members_are_rejected(self):
        control = self.control()
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir).resolve()
            ledger = self.new_ledger(control, temp)
            self.begin(ledger)
            ledger.close()
            path = temp / "operations" / (self.operation() + ".json")
            text = path.read_text(encoding="utf-8")
            path.write_text(
                text.replace('"phase":"preflight"',
                             '"phase":"preflight","phase":"preflight"', 1),
                encoding="utf-8",
            )
            path.chmod(0o600)
            reopened = self.new_ledger(control, temp)
            try:
                with self.assertRaisesRegex(
                    control.UpgradeLedgerTrustError, "duplicate JSON object member"
                ):
                    reopened.recover(self.operation())
            finally:
                reopened.close()

    def test_external_evidence_cannot_overwrite_coordinator_owned_fields(self):
        control = self.control()
        owned = {
            "schema_version": 99,
            "operation_id": self.operation("2"),
            "host": "attacker.invalid",
            "phase": "committed",
            "started_at": -1,
            "last_progress_at": -2,
            "upgrade_class": "attacker-controlled",
            "last_error": "attacker error",
            "recovery_action": "activate_without_checks",
        }
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir).resolve()
            ledger = self.new_ledger(control, temp)
            evidence = self.evidence()
            evidence.update(owned)
            state = ledger.begin(
                self.operation(),
                host="compute-1",
                upgrade_class="planned_maintenance",
                evidence=evidence,
            )
            self.assertEqual(1, state["schema_version"])
            self.assertEqual(self.operation(), state["operation_id"])
            self.assertEqual("compute-1", state["host"])
            self.assertEqual("preflight", state["phase"])
            self.assertEqual(state["started_at"], state["last_progress_at"])
            self.assertEqual("planned_maintenance", state["upgrade_class"])
            self.assertIsNone(state["last_error"])
            self.assertIsNone(state["recovery_action"])

            previous_started = state["started_at"]
            state = ledger.transition("preflight", "quiescing", owned)
            self.assertEqual(1, state["schema_version"])
            self.assertEqual(self.operation(), state["operation_id"])
            self.assertEqual("compute-1", state["host"])
            self.assertEqual("quiescing", state["phase"])
            self.assertEqual(previous_started, state["started_at"])
            self.assertGreaterEqual(state["last_progress_at"], previous_started)
            self.assertEqual("planned_maintenance", state["upgrade_class"])
            self.assertIsNone(state["last_error"])
            self.assertIsNone(state["recovery_action"])
            ledger.close()

    def test_external_evidence_fields_have_specific_schemas(self):
        control = self.control()
        invalid_values = {
            "affected_domains": "acl",
            "old_image_ids": {"unknown-component": "sha256:" + "1" * 64},
            "candidate_image_ids": {"aria-datapath": "latest"},
            "old_manifest_hash": "not-a-digest",
            "candidate_manifest_hash": 7,
            "old_config_hash": "sha256:" + "A" * 64,
            "candidate_config_hash": "secret-token",
            "pre_accepted_generation": True,
            "pre_applied_generation": -1,
            "pre_desired_hash": "snapshot-body-secret",
            "pre_managed_port_ids": [None],
            "maintenance_token": {"token": "nested"},
            "ovs_vswitchd_pid": False,
            "ovs_agent_container_id": "",
            "ovs_agent_started_at": {"time": 1},
            "br_int_uuid": "bad uuid with spaces",
            "generation": "12",
            "desired_hash": "password-secret",
        }
        for field, value in invalid_values.items():
            with self.subTest(field=field):
                with tempfile.TemporaryDirectory() as temp_dir:
                    temp = Path(temp_dir).resolve()
                    ledger = self.new_ledger(control, temp)
                    evidence = self.evidence()
                    evidence[field] = value
                    with self.assertRaises(ValueError):
                        ledger.begin(
                            self.operation(),
                            host="compute-1",
                            upgrade_class="planned_maintenance",
                            evidence=evidence,
                        )
                    self.assertFalse(
                        (temp / "operations" / (self.operation() + ".json")).exists()
                    )
                    ledger.close()

        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir).resolve()
            ledger = self.new_ledger(control, temp)
            with self.assertRaises(ValueError):
                ledger.begin(
                    self.operation(),
                    host="compute-1",
                    upgrade_class="unrecognized",
                    evidence=self.evidence(),
                )
            ledger.close()

    def test_actual_agent_desired_hash_is_accepted_and_audited_verbatim(self):
        control = self.control()
        agent_state = self.agent_state()
        desired_hash = agent_state.desired_snapshot_hash(
            {
                "schema_version": 1,
                "generation": 19,
                "ports": [
                    {"port_id": "port-b", "ifname": "tap-b"},
                    {"port_id": "port-a", "ifname": "tap-a"},
                ],
            }
        )
        self.assertRegex(desired_hash, r"^[0-9a-f]{64}$")
        records = []
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir).resolve()
            ledger = self.new_ledger(control, temp, records.append)
            evidence = self.evidence()
            evidence["pre_desired_hash"] = desired_hash
            state = ledger.begin(
                self.operation(),
                host="compute-1",
                upgrade_class="planned_maintenance",
                evidence=evidence,
            )
            self.assertEqual(desired_hash, state["pre_desired_hash"])
            state = ledger.transition(
                "preflight",
                "quiescing",
                {"desired_hash": desired_hash, "generation": 19},
            )
            self.assertEqual(desired_hash, state["desired_hash"])
            self.assertEqual(desired_hash, json.loads(records[-1])["desired_hash"])
            ledger.close()

    def test_transition_derives_recovery_metadata_from_destination_phase(self):
        control = self.control()
        for destination in ("full_resync", "rollback"):
            with self.subTest(destination=destination):
                with tempfile.TemporaryDirectory() as temp_dir:
                    temp = Path(temp_dir).resolve()
                    ledger = self.new_ledger(control, temp)
                    self.begin(ledger)
                    ledger.transition("preflight", "quiescing", {})
                    ledger.transition("quiescing", "bypass_preparing", {})
                    ledger.transition("bypass_preparing", "bypass_confirmed", {})
                    bypass = ledger.transition(
                        "bypass_confirmed", "maintenance_bypass", {}
                    )
                    self.assertEqual(
                        "operator_action_required", bypass["recovery_action"]
                    )
                    failed = ledger.fail("maintenance_bypass", "candidate failed")
                    self.assertEqual(
                        "operator_action_required", failed["recovery_action"]
                    )
                    self.assertEqual("candidate failed", failed["last_error"])
                    progressed = ledger.transition(
                        "maintenance_bypass", destination, {}
                    )
                    self.assertIsNone(progressed["recovery_action"])
                    self.assertIsNone(progressed["last_error"])
                    ledger.close()

    def test_leaving_recovered_exact_phases_clears_recovery_metadata(self):
        control = self.control()
        edges = (
            ("quiescing", "bypass_preparing"),
            ("agent_buffering", "full_resync"),
        )
        for stale_phase, next_phase in edges:
            with self.subTest(stale_phase=stale_phase):
                with tempfile.TemporaryDirectory() as temp_dir:
                    temp = Path(temp_dir).resolve()
                    first = self.new_ledger(control, temp)
                    self.begin(first)
                    stale = self.read_ledger(temp)
                    stale["phase"] = stale_phase
                    stale["last_error"] = "stale failure"
                    self.write_ledger(temp, stale)
                    first.close()

                    recovered = self.new_ledger(control, temp)
                    state = recovered.recover(self.operation())
                    self.assertEqual("resume_exact_phase", state["recovery_action"])
                    self.assertEqual("stale failure", state["last_error"])
                    progressed = recovered.transition(stale_phase, next_phase, {})
                    self.assertIsNone(progressed["recovery_action"])
                    self.assertIsNone(progressed["last_error"])
                    recovered.close()

    def test_bypass_preparing_failure_metadata_clears_on_progress(self):
        control = self.control()
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir).resolve()
            ledger = self.new_ledger(control, temp)
            self.begin(ledger)
            ledger.transition("preflight", "quiescing", {})
            ledger.transition("quiescing", "bypass_preparing", {})
            failed = ledger.fail("bypass_preparing", "preparation paused")
            self.assertEqual("bypass_preparing", failed["phase"])
            self.assertEqual("resume_exact_phase", failed["recovery_action"])
            self.assertEqual("preparation paused", failed["last_error"])
            progressed = ledger.transition(
                "bypass_preparing", "bypass_confirmed", {}
            )
            self.assertIsNone(progressed["recovery_action"])
            self.assertIsNone(progressed["last_error"])
            ledger.close()

    def test_recovered_preflight_metadata_clears_on_progress(self):
        control = self.control()
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir).resolve()
            first = self.new_ledger(control, temp)
            self.begin(first)
            first.close()

            recovered = self.new_ledger(control, temp)
            state = recovered.recover(self.operation())
            self.assertEqual("preflight", state["phase"])
            self.assertEqual("resume_exact_phase", state["recovery_action"])
            progressed = recovered.transition("preflight", "quiescing", {})
            self.assertIsNone(progressed["recovery_action"])
            self.assertIsNone(progressed["last_error"])
            recovered.close()

    def test_recovered_preflight_failure_preserves_fresh_error(self):
        control = self.control()
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir).resolve()
            first = self.new_ledger(control, temp)
            self.begin(first)
            first.close()

            recovered = self.new_ledger(control, temp)
            state = recovered.recover(self.operation())
            self.assertEqual("resume_exact_phase", state["recovery_action"])
            failed = recovered.fail("preflight", "preflight rejected")
            self.assertEqual("failed_before_mutation", failed["phase"])
            self.assertIsNone(failed["recovery_action"])
            self.assertEqual("preflight rejected", failed["last_error"])
            self.assertEqual(failed, self.read_ledger(temp))
            recovered.close()

    def test_any_durable_exact_resume_directive_clears_on_legal_progress(self):
        control = self.control()
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir).resolve()
            ledger = self.new_ledger(control, temp)
            self.begin(ledger)
            state = self.read_ledger(temp)
            state["phase"] = "rollback"
            state["recovery_action"] = "resume_exact_phase"
            state["last_error"] = "stale rollback failure"
            self.write_ledger(temp, state)
            progressed = ledger.transition("rollback", "full_resync", {})
            self.assertIsNone(progressed["recovery_action"])
            self.assertIsNone(progressed["last_error"])
            ledger.close()

    def test_commit_clears_stale_recovery_metadata(self):
        control = self.control()
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir).resolve()
            ledger = self.new_ledger(control, temp)
            self.begin(ledger)
            stale = self.read_ledger(temp)
            stale["phase"] = "verifying"
            stale["last_error"] = "old verification failure"
            stale["recovery_action"] = "resume_exact_phase"
            self.write_ledger(temp, stale)
            committed = ledger.commit({})
            self.assertEqual("committed", committed["phase"])
            self.assertIsNone(committed["last_error"])
            self.assertIsNone(committed["recovery_action"])
            ledger.close()

    def test_falsey_non_object_evidence_is_rejected_without_mutation(self):
        control = self.control()
        for method, evidence in (
            ("transition", []),
            ("transition", ""),
            ("fail", []),
            ("fail", ""),
            ("commit", 0),
        ):
            with self.subTest(method=method, evidence=evidence):
                with tempfile.TemporaryDirectory() as temp_dir:
                    temp = Path(temp_dir).resolve()
                    ledger = self.new_ledger(control, temp)
                    self.begin(ledger)
                    if method == "commit":
                        state = self.read_ledger(temp)
                        state["phase"] = "verifying"
                        self.write_ledger(temp, state)
                    before = self.read_ledger(temp)
                    with self.assertRaises(ValueError):
                        if method == "transition":
                            ledger.transition("preflight", "quiescing", evidence)
                        elif method == "fail":
                            ledger.fail("preflight", "failed", evidence)
                        else:
                            ledger.commit(evidence)
                    self.assertEqual(before, self.read_ledger(temp))
                    ledger.close()

    def test_second_failure_in_maintenance_bypass_preserves_operator_action(self):
        control = self.control()
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir).resolve()
            ledger = self.new_ledger(control, temp)
            self.begin(ledger)
            ledger.transition("preflight", "quiescing", {})
            ledger.transition("quiescing", "bypass_preparing", {})
            ledger.transition("bypass_preparing", "bypass_confirmed", {})
            first = ledger.fail("bypass_confirmed", "candidate failed")
            self.assertEqual("maintenance_bypass", first["phase"])
            self.assertEqual(
                "operator_action_required", first["recovery_action"]
            )
            second = ledger.fail("maintenance_bypass", "candidate failed again")
            self.assertEqual("maintenance_bypass", second["phase"])
            self.assertEqual(
                "operator_action_required", second["recovery_action"]
            )
            self.assertEqual("candidate failed again", second["last_error"])
            ledger.close()

    def test_audit_records_are_bounded_and_exclude_secrets_and_snapshot_bodies(self):
        control = self.control()
        records = []
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir).resolve()
            ledger = self.new_ledger(control, temp, records.append)
            self.begin(ledger)
            state = self.read_ledger(temp)
            state["desired_hash"] = "sha256:" + "8" * 10000
            self.write_ledger(temp, state)
            ledger.transition(
                "preflight",
                "quiescing",
                {
                    "generation": 11,
                    "environment": {"OS_TOKEN": "do-not-log"},
                    "auth_token": "do-not-log",
                    "snapshot_body": "x" * 10000,
                },
            )
            ledger.close()
        record = json.loads(records[-1])
        self.assertEqual(
            {
                "operation_id", "host", "old_phase", "new_phase", "elapsed_ms",
                "generation", "desired_hash", "old_image_ids", "candidate_image_ids",
                "result",
            },
            set(record),
        )
        self.assertEqual("preflight", record["old_phase"])
        self.assertEqual("quiescing", record["new_phase"])
        self.assertEqual(11, record["generation"])
        self.assertLessEqual(len(records[-1]), control.MAX_AUDIT_BYTES)
        self.assertNotIn("do-not-log", records[-1])
        self.assertNotIn("snapshot", records[-1])

    def test_audit_absolute_bound_handles_oversized_integer_values(self):
        control = self.control()
        records = []
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir).resolve()
            ledger = self.new_ledger(control, temp, records.append)
            self.begin(ledger)
            state = self.read_ledger(temp)
            state["generation"] = int("9" * 4000)
            self.write_ledger(temp, state)
            ledger.transition("preflight", "quiescing", {})
            ledger.close()
        self.assertTrue(records)
        for line in records:
            record = json.loads(line)
            self.assertEqual(
                {
                    "operation_id", "host", "old_phase", "new_phase", "elapsed_ms",
                    "generation", "desired_hash", "old_image_ids",
                    "candidate_image_ids", "result",
                },
                set(record),
            )
            self.assertLessEqual(len(line.encode("utf-8")), control.MAX_AUDIT_BYTES)
            self.assertNotIn("do-not-log", line)

    def test_audit_redacts_nested_secrets_and_snapshot_bodies_from_image_fields(self):
        control = self.control()
        records = []
        secret_values = (
            "old-auth-secret",
            "old-password-secret",
            "old-snapshot-secret",
            "candidate-authorization-secret",
            "candidate-maintenance-secret",
            "candidate-body-secret",
        )
        nested_old = {
            "aria-datapath": {
                "auth_token": secret_values[0],
                "password": secret_values[1],
                "snapshot": {"body": secret_values[2]},
            },
        }
        nested_candidate = {
            "neutron-aria-agent": {
                "authorization": secret_values[3],
                "maintenance_token": secret_values[4],
                "snapshot_body": secret_values[5],
            },
        }
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir).resolve()
            ledger = self.new_ledger(control, temp, records.append)
            self.begin(ledger)
            state = self.read_ledger(temp)
            state["old_image_ids"] = nested_old
            state["candidate_image_ids"] = nested_candidate
            self.write_ledger(temp, state)
            ledger.transition("preflight", "quiescing", {})
            ledger.close()
        self.assertTrue(records)
        for line in records:
            record = json.loads(line)
            self.assertEqual(
                {
                    "operation_id", "host", "old_phase", "new_phase", "elapsed_ms",
                    "generation", "desired_hash", "old_image_ids",
                    "candidate_image_ids", "result",
                },
                set(record),
            )
            self.assertLessEqual(len(line.encode("utf-8")), control.MAX_AUDIT_BYTES)
            lowered = line.lower()
            for secret in secret_values:
                self.assertNotIn(secret, line)
            for sensitive_name in (
                "auth_token", "password", "authorization", "maintenance_token",
                "snapshot", "snapshot_body", "body",
            ):
                self.assertNotIn(sensitive_name, lowered)

    def test_audit_filters_unknown_image_keys_before_bounding(self):
        control = self.control()
        records = []
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir).resolve()
            ledger = self.new_ledger(control, temp, records.append)
            self.begin(ledger)
            state = self.read_ledger(temp)
            junk = {
                "aaa-auth-token-%02d" % index: "sha256:" + "%x" % index * 64
                for index in range(1, 21)
            }
            state["old_image_ids"].update(junk)
            state["candidate_image_ids"].update(junk)
            self.write_ledger(temp, state)
            ledger.transition("preflight", "quiescing", {})
            ledger.close()
        record = json.loads(records[-1])
        self.assertEqual(
            {"aria-datapath"}, set(record["old_image_ids"])
        )
        self.assertEqual(
            {"aria-datapath"}, set(record["candidate_image_ids"])
        )
        self.assertNotIn("auth-token", records[-1])

    def test_oversized_audit_preserves_required_key_types(self):
        control = self.control()
        records = []
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir).resolve()
            ledger = self.new_ledger(control, temp, records.append)
            self.begin(ledger)
            state = self.read_ledger(temp)
            state["old_image_ids"] = {
                "aria-datapath": "registry.example/" + "a" * 6000,
                "password-shaped-secret-key": "sha256:" + "a" * 64,
            }
            state["candidate_image_ids"] = {
                "neutron-aria-agent": "registry.example/" + "b" * 6000,
                "snapshot-body-secret-key": "sha256:" + "b" * 64,
            }
            state["generation"] = "token-generation"
            state["desired_hash"] = "body-secret"
            self.write_ledger(temp, state)
            ledger.transition("preflight", "quiescing", {})
            ledger.close()
        record = json.loads(records[-1])
        self.assertEqual(
            {
                "operation_id", "host", "old_phase", "new_phase", "elapsed_ms",
                "generation", "desired_hash", "old_image_ids",
                "candidate_image_ids", "result",
            },
            set(record),
        )
        self.assertIsInstance(record["old_image_ids"], dict)
        self.assertIsInstance(record["candidate_image_ids"], dict)
        self.assertIsNone(record["generation"])
        self.assertIsNone(record["desired_hash"])
        self.assertLessEqual(
            len(records[-1].encode("utf-8")), control.MAX_AUDIT_BYTES
        )
        self.assertNotIn("password", records[-1])
        self.assertNotIn("snapshot", records[-1])
        self.assertNotIn("body-secret", records[-1])

    def test_audit_results_distinguish_transition_fail_and_recover(self):
        control = self.control()
        records = []
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir).resolve()
            ledger = self.new_ledger(control, temp, records.append)
            self.begin(ledger)
            ledger.transition("preflight", "quiescing", {})
            ledger.close()
        self.assertEqual("success", json.loads(records[-1])["result"])

        records = []
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir).resolve()
            ledger = self.new_ledger(control, temp, records.append)
            self.begin(ledger)
            ledger.fail("preflight", "rejected")
            ledger.close()
        self.assertEqual("failed", json.loads(records[-1])["result"])

        records = []
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir).resolve()
            first = self.new_ledger(control, temp)
            self.begin(first)
            first.transition("preflight", "quiescing", {})
            first.transition("quiescing", "bypass_preparing", {})
            first.transition("bypass_preparing", "bypass_confirmed", {})
            first.close()
            recovered = self.new_ledger(control, temp, records.append)
            recovered.recover(self.operation())
            recovered.close()
        self.assertEqual("recovered", json.loads(records[-1])["result"])

    def test_audit_scalar_fields_use_strict_field_specific_schemas(self):
        control = self.control()
        records = []
        secrets = (
            "token-generation-secret",
            "password-desired-secret",
            "snapshot-pre-desired-secret",
            "authorization: bearer host-secret",
            "body-next-phase-secret",
        )
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir).resolve()
            ledger = self.new_ledger(control, temp, records.append)
            ledger.begin(
                self.operation(), host=secrets[3],
                upgrade_class="planned_maintenance", evidence=self.evidence()
            )
            state = self.read_ledger(temp)
            state["pre_desired_hash"] = secrets[2]
            state["generation"] = secrets[0]
            self.write_ledger(temp, state)
            ledger.transition("preflight", "quiescing", {})
            with self.assertRaises(control.UpgradeLedgerTransitionError):
                ledger.transition(
                    "quiescing",
                    secrets[4],
                    {"desired_hash": secrets[1]},
                )
            ledger.close()

        self.assertGreaterEqual(len(records), 2)
        fallback_record = json.loads(records[-2])
        invalid_record = json.loads(records[-1])
        self.assertIsNone(fallback_record["host"])
        self.assertIsNone(fallback_record["generation"])
        self.assertIsNone(fallback_record["desired_hash"])
        self.assertEqual("preflight", fallback_record["old_phase"])
        self.assertEqual("quiescing", fallback_record["new_phase"])
        self.assertEqual("success", fallback_record["result"])
        self.assertIsNone(invalid_record["host"])
        self.assertIsNone(invalid_record["desired_hash"])
        self.assertIsNone(invalid_record["new_phase"])
        self.assertEqual("invalid_transition", invalid_record["result"])
        for line in records:
            record = json.loads(line)
            self.assertEqual(
                {
                    "operation_id", "host", "old_phase", "new_phase", "elapsed_ms",
                    "generation", "desired_hash", "old_image_ids",
                    "candidate_image_ids", "result",
                },
                set(record),
            )
            self.assertLessEqual(len(line.encode("utf-8")), control.MAX_AUDIT_BYTES)
            for secret in secrets:
                self.assertNotIn(secret, line)

    def test_audit_hostname_requires_valid_dns_labels(self):
        control = self.control()
        records = []
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir).resolve()
            ledger = self.new_ledger(control, temp, records.append)
            ledger.begin(
                self.operation(),
                host="bad..host",
                upgrade_class="planned_maintenance",
                evidence=self.evidence(),
            )
            ledger.transition("preflight", "quiescing", {})
            ledger.close()
        self.assertIsNone(json.loads(records[-1])["host"])


if __name__ == "__main__":
    unittest.main()
