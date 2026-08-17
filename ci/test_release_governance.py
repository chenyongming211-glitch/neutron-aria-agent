#!/usr/bin/env python3
"""Contracts for the minimal v0.9 RC delivery surface."""

import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PRODUCT_VERSION = "0.9.0-rc.1"


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
            "create_release_manifest.py",
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
            "mutation_phase=stopped",
            "mutation_phase=renamed",
            "restore_stopped_original",
            "BACKUP_IMAGE_ID",
            "release state must have mode 0600",
            "rollback restored an unexpected image",
            "rollback container image ID mismatch",
            "Automatic recovery failed; state retained",
            "overall_readiness",
            "neutron_openvswitch_agent",
            "ovs-vswitchd",
            "rollback",
        ):
            self.assertIn(term, source)
        self.assertNotIn("docker restart neutron_openvswitch_agent", source)
        self.assertNotIn("systemctl restart openvswitch", source)
        mode = subprocess.check_output(
            ["git", "ls-files", "-s", str(path.relative_to(ROOT))],
            cwd=str(ROOT),
            text=True,
        ).split()[0]
        self.assertEqual("100755", mode)


if __name__ == "__main__":
    unittest.main()
