#!/usr/bin/env python3
"""Contracts for the minimal v0.9 RC delivery surface."""

import hashlib
import importlib.util
import json
import os
import struct
import subprocess
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PRODUCT_VERSION = "0.9.0-rc.1"
COMPATIBILITY_FIELDS = {
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
}


def load_manifest_generator():
    path = ROOT / "ci" / "create_release_manifest.py"
    spec = importlib.util.spec_from_file_location("create_release_manifest", path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class ReleaseGovernanceTest(unittest.TestCase):
    def test_product_version_and_license_are_explicit(self):
        version_path = ROOT / "VERSION"
        self.assertTrue(version_path.is_file(), "VERSION must be the release authority")
        self.assertEqual(PRODUCT_VERSION, version_path.read_text(encoding="utf-8").strip())

        license_path = ROOT / "LICENSE"
        self.assertTrue(license_path.is_file(), "declared MIT license needs its text")
        license_text = license_path.read_text(encoding="utf-8")
        self.assertIn("MIT License", license_text)
        self.assertIn("Permission is hereby granted", license_text)

        cargo = (ROOT / "Cargo.toml").read_text(encoding="utf-8")
        self.assertNotIn("Your Name <email@example.com>", cargo)
        self.assertIn('license = "MIT"', cargo)
        changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
        self.assertIn("0.9.0-rc.1", changelog)

    def test_support_matrix_is_machine_readable_and_bounded(self):
        path = ROOT / "release" / "support-matrix.json"
        self.assertTrue(path.is_file())
        payload = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(1, payload["schema_version"])
        self.assertEqual("v0.9", payload["product_line"])
        self.assertEqual("x86_64", payload["architecture"])
        self.assertEqual("legacy-kolla-python2", payload["openstack_profile"])
        self.assertEqual(["acl"], payload["neutron_managed_domains"])
        self.assertFalse(payload["production_defaults"]["incremental_rpc_enabled"])
        self.assertFalse(payload["production_defaults"]["rpc_events_enabled"])
        self.assertEqual("deferred", payload["features"]["qos"])
        self.assertEqual("deferred", payload["features"]["mirror"])

    def test_manifest_generator_hashes_only_declared_assets(self):
        generator = ROOT / "ci" / "create_release_manifest.py"
        self.assertTrue(generator.is_file())
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir)
            artifact = temp / "aria-agent"
            artifact.write_bytes(b"candidate")
            output = temp / "release-manifest.json"
            checksums = temp / "SHA256SUMS"
            subprocess.check_call(
                [
                    sys.executable,
                    str(generator),
                    "--repo-root",
                    str(ROOT),
                    "--source-commit",
                    "7" * 40,
                    "--artifact",
                    "aria-agent=" + str(artifact),
                    "--image",
                    "aria-datapath=aria-datapath:rc-test@sha256:" + "9" * 64,
                    "--output",
                    str(output),
                    "--checksums-output",
                    str(checksums),
                ]
            )
            payload = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(1, payload["schema_version"])
            self.assertEqual(PRODUCT_VERSION, payload["product_version"])
            self.assertEqual("7" * 40, payload["source_commit"])
            self.assertEqual(
                hashlib.sha256(b"candidate").hexdigest(),
                payload["artifacts"][0]["sha256"],
            )
            self.assertEqual("aria-agent", payload["artifacts"][0]["name"])
            self.assertEqual(
                "0.1.0", payload["component_versions"]["python_neutron_client"]
            )
            self.assertEqual(
                "aria-datapath:rc-test@sha256:" + "9" * 64,
                payload["images"][0]["identity"],
            )
            self.assertEqual(
                "%s  aria-agent\n" % hashlib.sha256(b"candidate").hexdigest(),
                checksums.read_text(encoding="utf-8"),
            )

    def test_manifest_generator_embeds_validated_runtime_compatibility(self):
        generator = ROOT / "ci" / "create_release_manifest.py"
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir)
            artifact = temp / "aria-agent"
            artifact.write_bytes(b"candidate")
            output = temp / "release-manifest.json"
            checksums = temp / "SHA256SUMS"
            subprocess.check_call(
                [
                    sys.executable,
                    str(generator),
                    "--repo-root",
                    str(ROOT),
                    "--source-commit",
                    "7" * 40,
                    "--artifact",
                    "aria-agent=" + str(artifact),
                    "--output",
                    str(output),
                    "--checksums-output",
                    str(checksums),
                ]
            )
            payload = json.loads(output.read_text(encoding="utf-8"))
            compatibility_path = ROOT / "release" / "runtime-compatibility.json"
            abi_path = ROOT / "abi" / "src" / "lib.rs"
            maps_path = ROOT / "ebpf" / "src" / "maps.rs"
            abi_bytes = abi_path.read_bytes()
            maps_bytes = maps_path.read_bytes()
            map_hasher = hashlib.sha256()
            for content in (abi_bytes, maps_bytes):
                map_hasher.update(struct.pack(">Q", len(content)))
                map_hasher.update(content)

            self.assertEqual(COMPATIBILITY_FIELDS, json.loads(
                compatibility_path.read_text(encoding="utf-8")
            ))
            self.assertEqual(COMPATIBILITY_FIELDS, {
                key: payload["runtime_compatibility"][key]
                for key in COMPATIBILITY_FIELDS
            })
            self.assertEqual("v" + PRODUCT_VERSION, payload["release_version"])
            self.assertEqual(
                hashlib.sha256(abi_bytes).hexdigest(),
                payload["runtime_compatibility"]["ebpf_abi_hash"],
            )
            self.assertEqual(
                map_hasher.hexdigest(),
                payload["runtime_compatibility"]["map_schema_hash"],
            )
            self.assertEqual(
                hashlib.sha256(compatibility_path.read_bytes()).hexdigest(),
                payload["contracts"]["runtime_compatibility_sha256"],
            )

    def test_runtime_compatibility_rejects_invalid_required_fields(self):
        generator = load_manifest_generator()
        invalid_payloads = []
        missing = dict(COMPATIBILITY_FIELDS)
        del missing["wal_schema_version"]
        invalid_payloads.append(missing)
        boolean_integer = dict(COMPATIBILITY_FIELDS)
        boolean_integer["schema_version"] = True
        invalid_payloads.append(boolean_integer)
        negative = dict(COMPATIBILITY_FIELDS)
        negative["map_schema_version"] = -1
        invalid_payloads.append(negative)
        unknown = dict(COMPATIBILITY_FIELDS)
        unknown["unrecognized_schema"] = 1
        invalid_payloads.append(unknown)

        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "runtime-compatibility.json"
            for payload in invalid_payloads:
                path.write_text(json.dumps(payload), encoding="utf-8")
                with self.assertRaises(ValueError):
                    generator.load_runtime_compatibility(path)

    def test_manifest_generator_and_classifier_share_conservative_image_contract(self):
        generator = load_manifest_generator()
        control_path = ROOT / "deploy" / "kolla" / "package" / "aria_upgrade_control.py"
        spec = importlib.util.spec_from_file_location("aria_upgrade_control", control_path)
        control = importlib.util.module_from_spec(spec)
        assert spec.loader is not None
        spec.loader.exec_module(control)
        valid = "registry.example/aria-datapath:v0.9@sha256:" + "a" * 64
        invalid = (
            ":@sha256:" + "a" * 64,
            "UPPERCASE:v0.9@sha256:" + "a" * 64,
            "aria-datapath@sha256:" + "A" * 64,
            "aria-datapath@sha256:" + "a" * 63,
        )
        self.assertTrue(generator.is_valid_image_identity(valid))
        self.assertTrue(control.is_valid_image_identity(valid))
        for identity in invalid:
            with self.subTest(identity=identity):
                self.assertFalse(generator.is_valid_image_identity(identity))
                self.assertFalse(control.is_valid_image_identity(identity))

    def test_stage2_bundle_stages_all_manifest_hash_sources(self):
        builder = ROOT / "deploy/kolla/package/build_stage2_acl_bundle.sh"
        runtime_bin = Path(sys.executable).parent
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir)
            wheel = temp / "netaddr.whl"
            wheel.write_bytes(b"offline test wheel")
            shims = temp / "shims"
            shims.mkdir()
            date_shim = shims / "date"
            date_shim.write_text(
                "#!/usr/bin/env python3\n"
                "import datetime\n"
                "import sys\n"
                "if sys.argv[1:3] != ['-u', '-d'] or not sys.argv[3].startswith('@'):\n"
                "    raise SystemExit(2)\n"
                "timestamp = int(sys.argv[3][1:])\n"
                "print(datetime.datetime.fromtimestamp(\n"
                "    timestamp, datetime.timezone.utc\n"
                ").strftime(sys.argv[4]))\n",
                encoding="utf-8",
            )
            date_shim.chmod(0o755)
            touch_shim = shims / "touch"
            touch_shim.write_text(
                "#!/usr/bin/env bash\n"
                "if [ \"$1\" = \"-h\" ] && [ \"$2\" = \"-d\" ]; then\n"
                "  shift 3\n"
                "fi\n"
                "exec /usr/bin/touch \"$@\"\n",
                encoding="utf-8",
            )
            touch_shim.chmod(0o755)
            tar_shim = shims / "tar"
            tar_shim.write_text(
                "#!/usr/bin/env bash\n"
                "for argument in \"$@\"; do\n"
                "  if [ \"${argument}\" = \"--sort=name\" ]; then\n"
                "    exec /usr/bin/tar -cf - .\n"
                "  fi\n"
                "done\n"
                "exec /usr/bin/tar \"$@\"\n",
                encoding="utf-8",
            )
            tar_shim.chmod(0o755)
            environment = dict(os.environ)
            environment.update(
                {
                    "OUT_DIR": str(temp / "out"),
                    "NETADDR_WHEEL_PATH": str(wheel),
                    "NETADDR_WHEEL_SHA256": hashlib.sha256(wheel.read_bytes()).hexdigest(),
                    "AGENT_IMAGE_IDENTITY": "neutron-aria-agent:v0.9@sha256:" + "1" * 64,
                    "DATAPATH_IMAGE_IDENTITY": "aria-datapath:v0.9@sha256:" + "2" * 64,
                    "PATH": os.pathsep.join((str(shims), str(runtime_bin), environment["PATH"])),
                }
            )
            missing_identity_environment = dict(environment)
            del missing_identity_environment["AGENT_IMAGE_IDENTITY"]
            del missing_identity_environment["DATAPATH_IMAGE_IDENTITY"]
            missing_identity_result = subprocess.run(
                ["bash", str(builder)],
                cwd=str(ROOT),
                env=missing_identity_environment,
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(0, missing_identity_result.returncode)
            self.assertIn(
                "AGENT_IMAGE_IDENTITY and DATAPATH_IMAGE_IDENTITY",
                missing_identity_result.stderr,
            )
            result = subprocess.run(
                ["bash", str(builder)],
                cwd=str(ROOT),
                env=environment,
                capture_output=True,
                text=True,
            )
            self.assertEqual(0, result.returncode, result.stdout + result.stderr)
            manifest = temp / "out" / "stage2-acl-bundle" / "release-manifest.json"
            self.assertTrue(manifest.is_file())
            payload = json.loads(manifest.read_text(encoding="utf-8"))
            self.assertIn("ebpf_abi_hash", payload["runtime_compatibility"])
            self.assertIn("map_schema_hash", payload["runtime_compatibility"])
            self.assertEqual(
                [
                    {
                        "identity": environment["DATAPATH_IMAGE_IDENTITY"],
                        "name": "aria-datapath",
                    },
                    {
                        "identity": environment["AGENT_IMAGE_IDENTITY"],
                        "name": "neutron-aria-agent",
                    },
                ],
                sorted(payload["images"], key=lambda image: image["name"]),
            )
            bundle = temp / "out" / "neutron-aria-stage2-acl-kolla-bundle.tgz"
            self.assertTrue(bundle.is_file())
            with tarfile.open(bundle, "r:gz") as archive:
                members = {member.name.lstrip("./"): member for member in archive.getmembers()}
                for required in (
                    "deploy/kolla/package/aria_upgrade_control.py",
                    "release/runtime-compatibility.json",
                    "abi/src/lib.rs",
                    "ebpf/src/maps.rs",
                    "release-manifest.json",
                    "SHA256SUMS",
                ):
                    self.assertIn(required, members)
                def read_member(name):
                    handle = archive.extractfile(members[name])
                    self.assertIsNotNone(handle)
                    return handle.read()
                packaged_manifest = json.loads(read_member("release-manifest.json"))
                packaged_compatibility = read_member("release/runtime-compatibility.json")
                packaged_abi = read_member("abi/src/lib.rs")
                packaged_maps = read_member("ebpf/src/maps.rs")
            self.assertEqual(
                payload["images"],
                packaged_manifest["images"],
            )
            self.assertEqual(
                hashlib.sha256(packaged_compatibility).hexdigest(),
                packaged_manifest["contracts"]["runtime_compatibility_sha256"],
            )
            self.assertEqual(
                hashlib.sha256(packaged_abi).hexdigest(),
                packaged_manifest["runtime_compatibility"]["ebpf_abi_hash"],
            )
            map_hasher = hashlib.sha256()
            for content in (packaged_abi, packaged_maps):
                map_hasher.update(struct.pack(">Q", len(content)))
                map_hasher.update(content)
            self.assertEqual(
                map_hasher.hexdigest(),
                packaged_manifest["runtime_compatibility"]["map_schema_hash"],
            )

    def test_manifest_generator_rejects_invalid_source_commit(self):
        generator = ROOT / "ci" / "create_release_manifest.py"
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir)
            artifact = temp / "asset"
            artifact.write_bytes(b"x")
            result = subprocess.run(
                [
                    sys.executable,
                    str(generator),
                    "--repo-root",
                    str(ROOT),
                    "--source-commit",
                    "not-a-commit",
                    "--artifact",
                    "asset=" + str(artifact),
                    "--output",
                    str(temp / "manifest.json"),
                    "--checksums-output",
                    str(temp / "SHA256SUMS"),
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertNotEqual(0, result.returncode)
            self.assertIn("source commit", result.stderr.lower())

    def test_manifest_generator_accepts_safe_nested_artifact_name(self):
        generator = ROOT / "ci" / "create_release_manifest.py"
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir)
            artifact = temp / "asset"
            artifact.write_bytes(b"nested")
            output = temp / "release-manifest.json"
            checksums = temp / "SHA256SUMS"
            subprocess.check_call(
                [
                    sys.executable,
                    str(generator),
                    "--repo-root",
                    str(ROOT),
                    "--source-commit",
                    "7" * 40,
                    "--artifact",
                    "dist/kolla/asset=" + str(artifact),
                    "--output",
                    str(output),
                    "--checksums-output",
                    str(checksums),
                ]
            )
            self.assertEqual(
                "dist/kolla/asset",
                json.loads(output.read_text(encoding="utf-8"))["artifacts"][0]["name"],
            )
            self.assertTrue(checksums.read_text(encoding="utf-8").endswith(
                "  dist/kolla/asset\n"
            ))

    def test_manifest_generator_rejects_artifact_path_traversal(self):
        generator = ROOT / "ci" / "create_release_manifest.py"
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir)
            artifact = temp / "asset"
            artifact.write_bytes(b"x")
            result = subprocess.run(
                [
                    sys.executable,
                    str(generator),
                    "--repo-root",
                    str(ROOT),
                    "--source-commit",
                    "7" * 40,
                    "--artifact",
                    "../asset=" + str(artifact),
                    "--output",
                    str(temp / "manifest.json"),
                    "--checksums-output",
                    str(temp / "SHA256SUMS"),
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertNotEqual(0, result.returncode)
            self.assertIn("invalid artifact", result.stderr.lower())

    def test_manifest_generator_rejects_duplicate_asset_name(self):
        generator = ROOT / "ci" / "create_release_manifest.py"
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir)
            artifact = temp / "asset"
            artifact.write_bytes(b"x")
            result = subprocess.run(
                [
                    sys.executable,
                    str(generator),
                    "--repo-root",
                    str(ROOT),
                    "--source-commit",
                    "7" * 40,
                    "--artifact",
                    "asset=" + str(artifact),
                    "--artifact",
                    "asset=" + str(artifact),
                    "--output",
                    str(temp / "manifest.json"),
                    "--checksums-output",
                    str(temp / "SHA256SUMS"),
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertNotEqual(0, result.returncode)
            self.assertIn("duplicate artifact name", result.stderr.lower())

    def test_manifest_generator_rejects_malformed_image_identity(self):
        generator = ROOT / "ci" / "create_release_manifest.py"
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir)
            result = subprocess.run(
                [
                    sys.executable,
                    str(generator),
                    "--repo-root",
                    str(ROOT),
                    "--source-commit",
                    "7" * 40,
                    "--image",
                    "aria-datapath=latest-sha256:not-a-digest",
                    "--output",
                    str(temp / "manifest.json"),
                    "--checksums-output",
                    str(temp / "SHA256SUMS"),
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertNotEqual(0, result.returncode)
            self.assertIn("@sha256:<64 lowercase hex>", result.stderr)

    def test_kolla_bundle_and_workflow_publish_governance_files(self):
        builder = (ROOT / "deploy/kolla/package/build_stage2_acl_bundle.sh").read_text(
            encoding="utf-8"
        )
        for term in (
            "VERSION",
            "release/support-matrix.json",
            "release/runtime-compatibility.json",
            "create_release_manifest.py",
            "aria_upgrade_control.py",
            "AGENT_IMAGE_IDENTITY",
            "DATAPATH_IMAGE_IDENTITY",
            '--image "neutron-aria-agent=${AGENT_IMAGE_IDENTITY}"',
            '--image "aria-datapath=${DATAPATH_IMAGE_IDENTITY}"',
            "SHA256SUMS",
            "release-manifest.json",
            "install_aria_datapath_rc_image.sh",
            "SOURCE_DATE_EPOCH",
            "--sort=name",
            "gzip -n",
            "-name '*.sh' -exec chmod 0755",
        ):
            self.assertIn(term, builder)
        self.assertIn("git archive --format=tar", builder)
        self.assertIn(
            'git -C "${REPO_ROOT}" show "${SOURCE_COMMIT}:VERSION"', builder
        )
        self.assertNotIn(
            'PRODUCT_VERSION="$(tr -d \'[:space:]\' <"${REPO_ROOT}/VERSION")"',
            builder,
        )
        self.assertIn('RELEASE_VERSION="v${PRODUCT_VERSION}"', builder)
        self.assertNotIn('RELEASE_VERSION="${RELEASE_VERSION:-', builder)
        self.assertIn(
            'python3 "${STAGING_DIR}/ci/create_release_manifest.py"', builder
        )
        self.assertNotIn("git ls-files -z", builder)
        self.assertNotIn(
            'cp -a "${REPO_ROOT}/deploy/kolla/smoke"', builder
        )

        workflow = (ROOT / ".github/workflows/build.yml").read_text(encoding="utf-8")
        for term in (
            "ci.test_release_governance",
            "create_release_manifest.py",
            "release-manifest.json",
            "SHA256SUMS",
            "ci/check_release_reproducibility.sh",
            'cp VERSION LICENSE CHANGELOG.md release/',
            '--artifact "firewall-binaries-x86_64.zip=firewall-binaries-x86_64.zip"',
            "Build Neutron stage-two ACL Kolla bundle",
            'AGENT_IMAGE_IDENTITY="${agent_tag}@${agent_id}"',
            'DATAPATH_IMAGE_IDENTITY="${datapath_tag}@${datapath_id}"',
        ):
            self.assertIn(term, workflow)
        self.assertNotIn('RELEASE_VERSION="${GITHUB_REF_NAME', workflow)
        self.assertIn("Validate release tag against manifest", workflow)
        self.assertIn('release_version="v$(tr -d', workflow)
        self.assertLess(
            workflow.index("- name: Create release archive"),
            workflow.index("- name: Create release manifest and checksums"),
        )
        release_block = workflow[workflow.index("  release:") : workflow.index("  deep-audit:")]
        for required_job in (
            "fast-contracts",
            "neutron-agent-clean-install",
            "neutron-db-contracts",
            "rust-behavior",
            "rust-build",
            "deep-audit",
        ):
            self.assertIn("- " + required_job, release_block)
        deep_audit = workflow[workflow.index("  deep-audit:") :]
        self.assertIn("startsWith(github.ref, 'refs/tags/v')", deep_audit)

    def test_datapath_installer_has_bounded_lifecycle_contract(self):
        path = ROOT / "deploy/kolla/package/install_aria_datapath_rc_image.sh"
        self.assertTrue(path.is_file())
        source = path.read_text(encoding="utf-8")
        for term in (
            "install|check|rollback",
            "EXPECTED_IMAGE_ID",
            "EXPECTED_ARIA_SHA256",
            "EXPECTED_EBPF_SHA256",
            "docker load",
            "docker rename",
            "PENDING_STATE_FILE",
            "lifecycle.lock",
            "flock -n",
            "RUNTIME_MIGRATION_REQUIRED",
            "LIFECYCLE_PHASE",
            "runtime_migration_required",
            "stop_agent_writer",
            "detach_all_managed_ports",
            "run_runtime_migration_sequence",
            "run_hash_aware_rollback_sequence",
            "restore_stopped_original",
            "BACKUP_IMAGE_ID",
            "BACKUP_EBPF_SHA256",
            "BACKUP_DATAPATH_STATE_SOURCE",
            "CANDIDATE_DATAPATH_STATE_SOURCE",
            "PIN_BACKUP_PATH",
            "PERSISTENT_RUNTIME_PREPARED",
            "CANDIDATE_PIN_QUARANTINE",
            "preserve_persistent_runtime",
            "restore_persistent_runtime",
            "cp -a --",
            "release state must have mode 0600",
            "rollback restored an unexpected image",
            "rollback container image ID mismatch",
            "Automatic recovery failed; state retained",
            "Python writer remains stopped",
            "accepted_generation",
            "applied_generation",
            "overall_readiness",
            "neutron_openvswitch_agent",
            "ovs-vswitchd",
            "rollback",
        ):
            self.assertIn(term, source)
        self.assertNotIn("docker restart neutron_openvswitch_agent", source)
        self.assertNotIn("docker stop neutron_openvswitch_agent", source)
        self.assertNotIn("systemctl restart openvswitch", source)
        self.assertNotIn("rm -rf -- /sys/fs/bpf", source)
        mode = subprocess.check_output(
            ["git", "ls-files", "-s", str(path.relative_to(ROOT))],
            cwd=str(ROOT),
            text=True,
        ).split()[0]
        self.assertEqual("100755", mode)


if __name__ == "__main__":
    unittest.main()
