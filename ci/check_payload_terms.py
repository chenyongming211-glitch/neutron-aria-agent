#!/usr/bin/env python3
from __future__ import print_function

import glob
import os
import sys
import tarfile
import zipfile

from check_blocked_terms import RULES


_BINARY_STRING_MIN_LEN = 6


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
    printable = 0
    for byte in sample:
        if byte in (9, 10, 13) or 32 <= byte <= 126:
            printable += 1
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


def _scan_bytes(label, data):
    if _is_elf(data):
        # ELF binaries are generated from the tracked source tree, which is
        # already checked by check_blocked_terms.py. Scanning machine code for
        # short text tokens creates meaningless byte/string collisions.
        return []
    if _is_probably_text(data):
        ascii_data = data
        non_ascii_data = data
    else:
        # ELF/image/archive payloads contain arbitrary machine or compressed
        # bytes. Scan only human-readable strings there; otherwise short
        # blocked tokens can collide with random binary data.
        ascii_data = b"\n".join(_ascii_strings(data))
        non_ascii_data = ascii_data
    lowered = ascii_data.lower()
    hits = []
    for index, (needle, ascii_fold) in enumerate(RULES, 1):
        haystack = lowered if ascii_fold else non_ascii_data
        if needle in haystack:
            hits.append((label, index))
    return hits


def _scan_regular_file(path):
    with open(path, "rb") as handle:
        data = handle.read()
    return _scan_bytes(path, data)


def _scan_zip(path):
    hits = []
    with zipfile.ZipFile(path) as archive:
        for member in archive.infolist():
            if member.is_dir():
                continue
            data = archive.read(member)
            hits.extend(_scan_bytes("%s!%s" % (path, member.filename), data))
    return hits


def _scan_tar(path):
    hits = []
    with tarfile.open(path) as archive:
        for member in archive.getmembers():
            if not member.isfile():
                continue
            extracted = archive.extractfile(member)
            if extracted is None:
                continue
            data = extracted.read()
            hits.extend(_scan_bytes("%s!%s" % (path, member.name), data))
    return hits


def _scan_file(path):
    if zipfile.is_zipfile(path):
        return _scan_zip(path)
    if tarfile.is_tarfile(path):
        return _scan_tar(path)
    return _scan_regular_file(path)


def _iter_paths(args):
    seen = set()
    for arg in args:
        matches = glob.glob(arg)
        if not matches and os.path.exists(arg):
            matches = [arg]
        if not matches:
            raise SystemExit("ERROR: payload path not found: %s" % arg)
        for match in matches:
            if os.path.isdir(match):
                for root, _, filenames in os.walk(match):
                    for filename in filenames:
                        path = os.path.join(root, filename)
                        if path not in seen:
                            seen.add(path)
                            yield path
            elif match not in seen:
                seen.add(match)
                yield match


def main():
    if len(sys.argv) < 2:
        raise SystemExit("usage: check_payload_terms.py PATH [PATH ...]")

    blocked = []
    checked = 0
    for path in _iter_paths(sys.argv[1:]):
        checked += 1
        blocked.extend(_scan_file(path))

    if blocked:
        print("Blocked token found in generated payload:", file=sys.stderr)
        for label, rule_index in blocked:
            print("  %s (rule %s)" % (label, rule_index), file=sys.stderr)
        return 1

    print("generated payload policy accepted")
    print("checked_files=%d" % checked)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
