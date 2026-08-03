#!/usr/bin/env python3
from __future__ import print_function

import glob
import os
import sys

try:
    from .public_release_policy import redact_label, scan_path, scan_payload
except ImportError:
    from public_release_policy import redact_label, scan_path, scan_payload


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
                            label = os.path.join(
                                os.path.basename(os.path.normpath(match)),
                                os.path.relpath(path, match),
                            )
                            yield path, label
            elif match not in seen:
                seen.add(match)
                yield match, os.path.basename(match)


def collect_payload_hits(args):
    blocked = []
    checked = 0
    for path, label in _iter_paths(args):
        checked += 1
        blocked.extend(scan_path(label))
        with open(path, "rb") as handle:
            blocked.extend(scan_payload(label, handle.read()))
    return checked, blocked


def main():
    if len(sys.argv) < 2:
        raise SystemExit("usage: check_payload_terms.py PATH [PATH ...]")

    checked, blocked = collect_payload_hits(sys.argv[1:])

    if blocked:
        print("Blocked token found in generated payload:", file=sys.stderr)
        for label, rule_index in blocked:
            print(
                "  %s (rule %s)" % (redact_label(label), rule_index),
                file=sys.stderr,
            )
        return 1

    print("generated payload policy accepted")
    print("checked_files=%d" % checked)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
