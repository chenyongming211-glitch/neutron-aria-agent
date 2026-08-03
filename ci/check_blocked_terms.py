#!/usr/bin/env python3
from __future__ import print_function

import os
import subprocess
import sys

try:
    from .public_release_policy import redact_label, scan_path, scan_payload
except ImportError:
    from public_release_policy import redact_label, scan_path, scan_payload


def tracked_files():
    output = subprocess.check_output(["git", "ls-files", "-z"])
    for raw_path in output.split(b"\0"):
        if raw_path:
            yield os.fsdecode(raw_path)


def collect_blocked(paths):
    blocked = []
    for path in paths:
        blocked.extend(scan_path(path))
        with open(path, "rb") as handle:
            blocked.extend(scan_payload(path, handle.read()))
    return blocked


def report_blocked(blocked):
    if not blocked:
        return
    print("Blocked token found in tracked files:", file=sys.stderr)
    for path, rule_index in blocked:
        print("  %s (rule %s)" % (redact_label(path), rule_index), file=sys.stderr)


def main():
    blocked = collect_blocked(tracked_files())
    if blocked:
        report_blocked(blocked)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
