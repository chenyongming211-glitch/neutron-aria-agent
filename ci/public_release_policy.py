#!/usr/bin/env python3
"""Shared encoded policy for tracked files and generated release payloads."""

from __future__ import print_function

import io
import os
import re
import tarfile
import zipfile


_BINARY_STRING_MIN_LEN = 6
_MAX_ARCHIVE_DEPTH = 3

# Keep the original four entries first so existing diagnostic IDs stay stable.
RULES = (
    (bytes.fromhex("716178"), True),
    (bytes.fromhex("7169616e78696e"), True),
    (bytes.fromhex("e9bd90e5ae89e4bfa1"), False),
    (bytes.fromhex("63736d70"), True),
    (bytes.fromhex("6368656e796f6e676d696e673231312d676c69746368"), True),
    (
        bytes.fromhex(
            "6368656e796f6e676d696e6732313140676d61696c2e636f6d"
        ),
        True,
    ),
    (bytes.fromhex("6e65746d6f75736572"), True),
    (bytes.fromhex("2f75736572732f6368656e"), True),
    (bytes.fromhex("626a3135392e6e6574"), True),
    (bytes.fromhex("6f737461636b32"), True),
    (bytes.fromhex("6f737461636b33"), True),
    (bytes.fromhex("6f737461636b34"), True),
    (bytes.fromhex("31302e35382e3135392e"), True),
)

_OWNER = RULES[4][0]
_REPOSITORY = bytes.fromhex("617269612d6669726577616c6c")
PUBLIC_REPOSITORY_URL_RE = re.compile(
    rb"https://github[.]com/"
    + re.escape(_OWNER)
    + rb"/"
    + _REPOSITORY
    + rb"(?=$|[/#? \t\r\n)\]>'\"])",
    re.IGNORECASE,
)


def mask_allowed_provenance(data):
    """Hide the one allowed public-repository URL shape before rule matching."""

    return PUBLIC_REPOSITORY_URL_RE.sub(
        b"https://github.com/public/aria-firewall",
        data,
    )


def find_rule_ids(data, allow_provenance=True):
    """Return stable one-based rule IDs present in *data*."""

    candidate = mask_allowed_provenance(data) if allow_provenance else data
    lowered = candidate.lower()
    return [
        index
        for index, (needle, ascii_fold) in enumerate(RULES, 1)
        if needle in (lowered if ascii_fold else candidate)
    ]


def scan_path(label):
    """Return policy hits found in a public path or archive member name."""

    return [
        (label, rule_id)
        for rule_id in find_rule_ids(os.fsencode(label), allow_provenance=False)
    ]


def redact_label(label):
    """Redact prohibited path fragments before emitting diagnostics."""

    redacted = os.fsencode(label)
    for rule_id, (needle, ascii_fold) in enumerate(RULES, 1):
        replacement = ("[rule-%d]" % rule_id).encode("ascii")
        if ascii_fold:
            redacted = re.sub(
                re.escape(needle),
                lambda _match, value=replacement: value,
                redacted,
                flags=re.IGNORECASE,
            )
        else:
            redacted = redacted.replace(needle, replacement)
    return os.fsdecode(redacted)


def _is_elf(data):
    return data.startswith(b"\x7fELF")


def _is_probably_text(data):
    if not data:
        return True
    sample = data[:4096]
    if b"\0" in sample:
        return False
    try:
        sample.decode("utf-8")
        return True
    except UnicodeDecodeError:
        pass
    printable = sum(
        1 for byte in sample if byte in (9, 10, 13) or 32 <= byte <= 126
    )
    return float(printable) / float(len(sample)) > 0.95


def _ascii_strings(data):
    current = bytearray()
    for byte in data:
        if 32 <= byte <= 126:
            current.append(byte)
            continue
        if len(current) >= _BINARY_STRING_MIN_LEN:
            yield bytes(current)
        current = bytearray()
    if len(current) >= _BINARY_STRING_MIN_LEN:
        yield bytes(current)


def _scan_regular_bytes(label, data):
    if _is_elf(data):
        # Machine code can contain accidental short-byte collisions. Generated
        # ELF policy is enforced through the tracked source and extracted
        # human-readable payloads instead.
        return []
    if _is_probably_text(data):
        candidate = data
    else:
        candidate = b"\n".join(_ascii_strings(data))
    return [(label, rule_id) for rule_id in find_rule_ids(candidate)]


def _scan_zip(label, data, depth):
    hits = []
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        for member in archive.infolist():
            member_label = "%s!%s" % (label, member.filename)
            hits.extend(scan_path(member_label))
            if member.is_dir():
                continue
            hits.extend(scan_payload(member_label, archive.read(member), depth + 1))
    return hits


def _scan_tar(label, data, depth):
    hits = []
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as archive:
        for member in archive.getmembers():
            member_label = "%s!%s" % (label, member.name)
            hits.extend(scan_path(member_label))
            if not member.isfile():
                continue
            extracted = archive.extractfile(member)
            if extracted is not None:
                hits.extend(scan_payload(member_label, extracted.read(), depth + 1))
    return hits


def _is_zip(data):
    return zipfile.is_zipfile(io.BytesIO(data))


def _is_tar(data):
    try:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:*"):
            return True
    except (tarfile.TarError, EOFError, OSError):
        return False


def scan_payload(label, data, depth=0):
    """Scan regular or recursively archived bytes under a stable label."""

    lower_label = label.rsplit("!", 1)[-1].lower()
    expects_zip = lower_label.endswith(".zip")
    expects_tar = lower_label.endswith(
        (".tar", ".tgz", ".tar.gz", ".tar.bz2", ".tar.xz")
    )
    is_zip = _is_zip(data)
    is_tar = False if is_zip else _is_tar(data)
    if (expects_zip and not is_zip) or (expects_tar and not is_tar):
        raise ValueError("malformed public archive: %s" % redact_label(label))
    if depth <= _MAX_ARCHIVE_DEPTH and is_zip:
        return _scan_zip(label, data, depth)
    if depth <= _MAX_ARCHIVE_DEPTH and is_tar:
        return _scan_tar(label, data, depth)
    return _scan_regular_bytes(label, data)
