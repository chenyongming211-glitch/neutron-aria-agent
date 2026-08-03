#!/usr/bin/env python3
"""Behavior contracts for current-tree and release-payload hygiene."""

import io
import os
import tarfile
import tempfile
import unittest
import zipfile
from contextlib import redirect_stderr
from pathlib import Path

from ci import check_blocked_terms
from ci import check_payload_terms
from ci import public_release_policy


NEW_RULE_HEX = (
    "6368656e796f6e676d696e673231312d676c69746368",
    "6368656e796f6e676d696e6732313140676d61696c2e636f6d",
    "6e65746d6f75736572",
    "2f55736572732f6368656e",
    "626a3135392e6e6574",
    "6f737461636b32",
    "6f737461636b33",
    "6f737461636b34",
    "31302e35382e3135392e",
)
REPOSITORY_URL = bytes.fromhex(
    "68747470733a2f2f6769746875622e636f6d2f"
    "6368656e796f6e676d696e673231312d676c697463682f"
    "617269612d6669726577616c6c"
)


class PublicReleasePolicyTest(unittest.TestCase):
    def test_new_identifier_classes_are_blocked_without_plaintext_fixtures(self):
        for encoded in NEW_RULE_HEX:
            with self.subTest(encoded=encoded):
                self.assertTrue(
                    public_release_policy.find_rule_ids(bytes.fromhex(encoded))
                )

    def test_ascii_rules_are_case_insensitive(self):
        value = bytes.fromhex(NEW_RULE_HEX[4]).upper()
        self.assertTrue(public_release_policy.find_rule_ids(value))

    def test_canonical_repository_and_actions_urls_are_the_only_owner_allowance(self):
        self.assertEqual([], public_release_policy.find_rule_ids(REPOSITORY_URL))
        self.assertEqual(
            [],
            public_release_policy.find_rule_ids(
                REPOSITORY_URL
                + bytes.fromhex("2f616374696f6e732f72756e732f313233")
            ),
        )
        owner = bytes.fromhex(NEW_RULE_HEX[0])
        self.assertTrue(public_release_policy.find_rule_ids(b"owner=" + owner))
        self.assertTrue(public_release_policy.find_rule_ids(REPOSITORY_URL + b"-copy"))

    def test_path_names_are_scanned(self):
        label = os.fsdecode(bytes.fromhex(NEW_RULE_HEX[5])) + "/summary.md"
        self.assertTrue(public_release_policy.scan_path(label))

    def test_zip_member_name_and_nested_content_are_scanned(self):
        outer = io.BytesIO()
        inner = io.BytesIO()
        with zipfile.ZipFile(inner, "w") as archive:
            archive.writestr("safe.txt", bytes.fromhex(NEW_RULE_HEX[4]))
        with zipfile.ZipFile(outer, "w") as archive:
            archive.writestr("nested.zip", inner.getvalue())
            archive.writestr(
                os.fsdecode(bytes.fromhex(NEW_RULE_HEX[5])) + "/x",
                b"safe",
            )
        hits = public_release_policy.scan_payload("fixture.zip", outer.getvalue())
        self.assertGreaterEqual(len(hits), 2)

    def test_tar_member_name_and_content_are_scanned(self):
        payload = bytes.fromhex(NEW_RULE_HEX[8])
        outer = io.BytesIO()
        with tarfile.open(fileobj=outer, mode="w") as archive:
            info = tarfile.TarInfo("safe.txt")
            info.size = len(payload)
            archive.addfile(info, io.BytesIO(payload))
        self.assertTrue(
            public_release_policy.scan_payload("fixture.tar", outer.getvalue())
        )

    def test_diagnostics_do_not_echo_decoded_values(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path_token = bytes.fromhex(NEW_RULE_HEX[5]).decode("ascii")
            path = Path(temp_dir, path_token + "-fixture.txt")
            prohibited = bytes.fromhex(NEW_RULE_HEX[1])
            path.write_bytes(prohibited)
            stderr = io.StringIO()
            with redirect_stderr(stderr):
                hits = check_blocked_terms.collect_blocked([str(path)])
                check_blocked_terms.report_blocked(hits)
            self.assertTrue(hits)
            self.assertNotIn(prohibited.decode("ascii"), stderr.getvalue())
            self.assertNotIn(path_token, stderr.getvalue())

    def test_malformed_named_archive_fails_closed(self):
        with self.assertRaisesRegex(ValueError, "malformed public archive"):
            public_release_policy.scan_payload("fixture.zip", b"not a zip")

    def test_elf_machine_code_is_not_treated_as_public_text(self):
        data = b"\x7fELF\0" + bytes.fromhex(NEW_RULE_HEX[4])
        self.assertEqual([], public_release_policy.scan_payload("fixture.so", data))

    def test_payload_entry_point_scans_relative_names_and_archive_content(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir, "payload")
            root.mkdir()
            archive_path = root / "fixture.zip"
            with zipfile.ZipFile(str(archive_path), "w") as archive:
                archive.writestr("safe.txt", bytes.fromhex(NEW_RULE_HEX[4]))
            checked, hits = check_payload_terms.collect_payload_hits([str(root)])
            self.assertEqual(1, checked)
            self.assertTrue(hits)

    def test_migration_is_idempotent_on_a_temporary_tree(self):
        from ci import anonymize_public_tree

        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source = bytes.fromhex(NEW_RULE_HEX[5]).decode("ascii")
            path = root / (source + "-summary.md")
            path.write_text(source, encoding="utf-8")
            anonymize_public_tree.migrate_paths([path], root=root)
            first = sorted(str(item.relative_to(root)) for item in root.rglob("*"))
            anonymize_public_tree.migrate_paths(list(root.rglob("*")), root=root)
            second = sorted(str(item.relative_to(root)) for item in root.rglob("*"))
            self.assertEqual(first, second)
            self.assertFalse(
                any(public_release_policy.scan_path(item) for item in second)
            )


if __name__ == "__main__":
    unittest.main()
