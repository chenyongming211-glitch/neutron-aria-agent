#!/usr/bin/env python3
from __future__ import print_function

import argparse
import os
import sys


ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir))
DEFAULT_EVIDENCE = os.path.join(
    ROOT,
    "docs",
    "evidence",
    "openstack-n05-lite",
    "2026-06-30-stage3-n3-summary.md",
)


REQUIRED_GATES = [
    "S3-1 release-ci",
    "S3-2 uds-rollout",
    "S3-3 no-binding",
    "S3-3 missing-policy",
    "S3-3 apply-failure",
    "S3-3 uds-timeout-crash",
    "S3-3 rollback-connectivity",
    "S3-4 ovs-restart",
    "S3-4 tap-recreate",
    "S3-4 vm-migration",
    "S3-4 same-host-vm",
]

ALLOWED_DISPOSITIONS = set([
    "pass",
    "degraded",
    "unsupported",
    "not_applicable",
    "pending",
])

INCOMPLETE_MARKERS = set(["", "-", "tbd", "todo", "none", "n/a"])


def _read(path):
    if not os.path.exists(path):
        raise SystemExit("ERROR: missing stage-three N3 evidence file: %s" % path)
    with open(path, "r", encoding="utf-8") as handle:
        return handle.read()


def _split_table_row(line):
    stripped = line.strip()
    if not stripped.startswith("|") or not stripped.endswith("|"):
        return None
    cells = [cell.strip() for cell in stripped.strip("|").split("|")]
    if not cells:
        return None
    if all(set(cell.replace(" ", "")) <= set("-:") for cell in cells):
        return None
    return cells


def _normalize(value):
    return " ".join(value.strip().strip("`").lower().split())


def _parse_matrix(text):
    rows = {}
    header = None
    for line in text.splitlines():
        cells = _split_table_row(line)
        if not cells:
            continue
        normalized = [_normalize(cell) for cell in cells]
        if "gate" in normalized and "disposition" in normalized:
            header = normalized
            continue
        if header is None:
            continue
        if len(cells) < len(header):
            cells = cells + [""] * (len(header) - len(cells))
        row = dict(zip(header, cells))
        gate = row.get("gate", "").strip().strip("`")
        if gate:
            rows[_normalize(gate)] = row
    return rows


def _value(row, key):
    return row.get(key, "").strip()


def _is_incomplete(value):
    return _normalize(value) in INCOMPLETE_MARKERS


def _check_gate(gate, row, require_complete):
    disposition = _normalize(_value(row, "disposition"))
    evidence = _value(row, "evidence")
    notes = _value(row, "notes")
    next_action = _value(row, "next action") or _value(row, "next_action")

    if disposition not in ALLOWED_DISPOSITIONS:
        return "invalid disposition %r" % disposition
    if require_complete and disposition == "pending":
        return "pending is not allowed with --require-complete"
    if disposition == "pending":
        if _is_incomplete(next_action):
            return "pending gate requires a next action"
        return None
    if _is_incomplete(evidence):
        return "%s gate requires evidence" % disposition
    if disposition in ("degraded", "unsupported", "not_applicable"):
        if _is_incomplete(notes):
            return "%s gate requires notes explaining the disposition" % disposition
    return None


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--evidence-file",
        default=DEFAULT_EVIDENCE,
        help="stage-three N3 evidence summary markdown file",
    )
    parser.add_argument(
        "--require-complete",
        action="store_true",
        help="fail if any required N3 gate is still pending",
    )
    args = parser.parse_args(argv)

    text = _read(args.evidence_file)
    rows = _parse_matrix(text)
    errors = []
    counts = dict((disposition, 0) for disposition in ALLOWED_DISPOSITIONS)

    for gate in REQUIRED_GATES:
        normalized_gate = _normalize(gate)
        row = rows.get(normalized_gate)
        if row is None:
            errors.append("missing gate row: %s" % gate)
            continue
        disposition = _normalize(_value(row, "disposition"))
        if disposition in counts:
            counts[disposition] += 1
        error = _check_gate(gate, row, args.require_complete)
        if error:
            errors.append("%s: %s" % (gate, error))

    if errors:
        print("ERROR: stage-three N3 evidence is not accepted:", file=sys.stderr)
        for error in errors:
            print("  %s" % error, file=sys.stderr)
        return 1

    print("stage-three N3 evidence accepted")
    print("checked_gates=%d" % len(REQUIRED_GATES))
    for disposition in sorted(counts):
        print("%s=%d" % (disposition, counts[disposition]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
