#!/usr/bin/env python3
"""Deterministically anonymize current tracked public-tree identifiers."""

from __future__ import print_function

import os
import re
import stat
import subprocess
import tarfile
import tempfile
import zipfile
from pathlib import Path

try:
    from .public_release_policy import PUBLIC_REPOSITORY_URL_RE
except ImportError:
    from public_release_policy import PUBLIC_REPOSITORY_URL_RE


REPLACEMENTS = (
    (
        bytes.fromhex("6f737461636b322e626a3135392e6e6574"),
        b"compute-1.example.test",
    ),
    (
        bytes.fromhex("6f737461636b332e626a3135392e6e6574"),
        b"compute-2.example.test",
    ),
    (
        bytes.fromhex("6f737461636b342e626a3135392e6e6574"),
        b"compute-3.example.test",
    ),
    (bytes.fromhex("6f737461636b32"), b"compute-1"),
    (bytes.fromhex("6f737461636b33"), b"compute-2"),
    (bytes.fromhex("6f737461636b34"), b"compute-3"),
    (bytes.fromhex("31302e35382e3135392e"), b"192.0.2."),
    (
        bytes.fromhex(
            "6368656e796f6e676d696e6732313140676d61696c2e636f6d"
        ),
        b"maintainers@example.invalid",
    ),
    (bytes.fromhex("6e65746d6f75736572"), b"repository-maintainer"),
    (bytes.fromhex("2f55736572732f6368656e"), b"/home/developer"),
)
_OWNER = bytes.fromhex("6368656e796f6e676d696e673231312d676c69746368")
_OWNER_REPLACEMENT = b"example-org"


def _replace_folded(data, source, replacement):
    return re.sub(re.escape(source), lambda _match: replacement, data, flags=re.I)


def _replace_owner_outside_provenance(data):
    pieces = []
    cursor = 0
    for match in PUBLIC_REPOSITORY_URL_RE.finditer(data):
        pieces.append(
            _replace_folded(
                data[cursor : match.start()],
                _OWNER,
                _OWNER_REPLACEMENT,
            )
        )
        pieces.append(match.group(0))
        cursor = match.end()
    pieces.append(_replace_folded(data[cursor:], _OWNER, _OWNER_REPLACEMENT))
    return b"".join(pieces)


def anonymize_bytes(data, preserve_provenance=True):
    updated = data
    for source, replacement in REPLACEMENTS:
        updated = _replace_folded(updated, source, replacement)
    if preserve_provenance:
        return _replace_owner_outside_provenance(updated)
    return _replace_folded(updated, _OWNER, _OWNER_REPLACEMENT)


def _is_archive(path):
    try:
        return zipfile.is_zipfile(str(path)) or tarfile.is_tarfile(str(path))
    except (OSError, tarfile.TarError):
        return False


def _rewrite_file(path):
    if _is_archive(path):
        return False
    original = path.read_bytes()
    updated = anonymize_bytes(original)
    if updated == original:
        return False
    mode = stat.S_IMODE(path.stat().st_mode)
    descriptor, temp_name = tempfile.mkstemp(
        prefix=path.name + ".",
        dir=str(path.parent),
    )
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(updated)
        os.chmod(temp_name, mode)
        os.replace(temp_name, str(path))
    except BaseException:
        try:
            os.unlink(temp_name)
        except FileNotFoundError:
            pass
        raise
    return True


def _anonymized_relative_path(path, root):
    relative = os.fsencode(str(path.relative_to(root)))
    return Path(os.fsdecode(anonymize_bytes(relative, preserve_provenance=False)))


def migrate_paths(paths, root):
    root = Path(root).resolve()
    resolved = []
    rewritten = 0
    for item in paths:
        path = Path(item)
        if not path.is_absolute():
            path = root / path
        path = path.resolve()
        try:
            path.relative_to(root)
        except ValueError:
            raise ValueError("migration path is outside root: %s" % path)
        resolved.append(path)
        if path.is_file() and _rewrite_file(path):
            rewritten += 1

    renamed = 0
    for source in sorted(set(resolved), key=lambda item: len(item.parts), reverse=True):
        if not source.exists():
            continue
        destination = root / _anonymized_relative_path(source, root)
        if destination == source:
            continue
        if destination.exists():
            raise RuntimeError("migration destination already exists: %s" % destination)
        destination.parent.mkdir(parents=True, exist_ok=True)
        source.rename(destination)
        renamed += 1
    return rewritten, renamed


def tracked_paths(root):
    output = subprocess.check_output(["git", "ls-files", "-z"], cwd=str(root))
    return [root / os.fsdecode(item) for item in output.split(b"\0") if item]


def main():
    root = Path(__file__).resolve().parents[1]
    rewritten, renamed = migrate_paths(tracked_paths(root), root=root)
    print("public tree anonymization complete")
    print("rewritten_files=%d" % rewritten)
    print("renamed_paths=%d" % renamed)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
