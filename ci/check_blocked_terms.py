#!/usr/bin/env python3
from __future__ import print_function

import os
import subprocess
import sys


RULES = [
    (bytes.fromhex("716178"), True),
    (bytes.fromhex("7169616e78696e"), True),
    (bytes.fromhex("e9bd90e5ae89e4bfa1"), False),
    (bytes.fromhex("63736d70"), True),
]


def tracked_files():
    output = subprocess.check_output(["git", "ls-files", "-z"])
    for raw_path in output.split(b"\0"):
        if raw_path:
            yield os.fsdecode(raw_path)


def scan_file(path):
    with open(path, "rb") as handle:
        data = handle.read()
    lowered = data.lower()
    hits = []
    for index, (needle, ascii_fold) in enumerate(RULES, 1):
        haystack = lowered if ascii_fold else data
        if needle in haystack:
            hits.append(index)
    return hits


def main():
    blocked = []
    for path in tracked_files():
        hits = scan_file(path)
        for rule_index in hits:
            blocked.append((path, rule_index))

    if blocked:
        print("Blocked token found in tracked files:", file=sys.stderr)
        for path, rule_index in blocked:
            print("  %s (rule %s)" % (path, rule_index), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
