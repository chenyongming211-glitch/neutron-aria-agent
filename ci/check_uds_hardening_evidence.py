#!/usr/bin/env python3
from __future__ import print_function

import argparse
import os
import re


ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir))
DEFAULT_EVIDENCE_ROOT = os.path.join(
    ROOT, "docs", "evidence", "openstack-n05-lite"
)

REQUIRED_FACTS = [
    "Container peer identities",
    "UDS directory and socket permissions",
    "World-writable socket check",
    "Peercred allow-list candidates",
    "Audit log path",
    "Hardened enforcement gate",
]

EVIDENCE_ONLY_ALLOWED_NONPASS = {
    "World-writable socket check": {"degraded"},
    "Audit log path": {"not_applicable"},
    "Hardened enforcement gate": {"not_applicable"},
}


def _read(path):
    with open(path, "r", encoding="utf-8") as handle:
        return handle.read()


def _is_uds_hardening_dir(path):
    summary_path = os.path.join(path, "summary.md")
    if not os.path.exists(summary_path):
        return False
    return "UDS Hardening Evidence" in _read(summary_path)[:512]


def _latest_evidence_dirs(root):
    by_host = {}
    if not os.path.isdir(root):
        return []
    for name in os.listdir(root):
        path = os.path.join(root, name)
        if not os.path.isdir(path) or not _is_uds_hardening_dir(path):
            continue
        match = re.match(r"^(\d{14})-(.+)$", name)
        if not match:
            continue
        timestamp, host = match.groups()
        previous = by_host.get(host)
        if previous is None or timestamp > previous[0]:
            by_host[host] = (timestamp, path)
    return [path for _, path in sorted(by_host.values())]


def _host_name(path):
    name = os.path.basename(os.path.normpath(path))
    match = re.match(r"^\d{14}-(.+)$", name)
    return match.group(1) if match else name


def _parse_facts(path):
    facts_path = os.path.join(path, "facts.tsv")
    if not os.path.exists(facts_path):
        raise SystemExit("ERROR: missing facts.tsv in %s" % path)
    facts = {}
    with open(facts_path, "r", encoding="utf-8") as handle:
        for line in handle:
            line = line.rstrip("\n")
            if not line:
                continue
            parts = line.split("\t")
            if len(parts) != 6:
                raise SystemExit(
                    "ERROR: malformed facts.tsv line in %s: %r" % (path, line)
                )
            fact, expected, command, actual, evidence, disposition = parts
            facts[fact] = {
                "expected": expected,
                "command": command,
                "actual": actual,
                "evidence": evidence,
                "disposition": disposition,
            }
    return facts


def _require_text(path, filename, needle):
    text_path = os.path.join(path, filename)
    if not os.path.exists(text_path):
        raise SystemExit("ERROR: missing %s in %s" % (filename, path))
    text = _read(text_path)
    if needle not in text:
        raise SystemExit("ERROR: %s in %s missing %r" % (filename, path, needle))


def check_evidence_dirs(paths, min_hosts, require_hardened):
    if len(paths) < min_hosts:
        raise SystemExit(
            "ERROR: expected at least %d UDS hardening evidence hosts, got %d: %s"
            % (min_hosts, len(paths), ", ".join(paths))
        )

    degraded = []
    not_applicable = []

    for path in paths:
        host = _host_name(path)
        facts = _parse_facts(path)
        missing = [fact for fact in REQUIRED_FACTS if fact not in facts]
        if missing:
            raise SystemExit(
                "ERROR: %s missing required facts: %s" % (host, ", ".join(missing))
            )

        _require_text(path, "peercred-allow-list.txt", "neutron_aria_agent_neutron_uid=")
        _require_text(path, "peercred-allow-list.txt", "neutron_aria_agent_neutron_gid=")
        _require_text(path, "socket-permissions.txt", "/run/aria")

        for fact, row in sorted(facts.items()):
            disposition = row["disposition"]
            if disposition == "pass":
                continue
            if disposition == "fail":
                raise SystemExit("ERROR: %s has fail disposition for %s" % (host, fact))

            if require_hardened:
                raise SystemExit(
                    "ERROR: %s has non-pass disposition for %s while --require-hardened: %s"
                    % (host, fact, disposition)
                )

            allowed = EVIDENCE_ONLY_ALLOWED_NONPASS.get(fact, set())
            if disposition not in allowed:
                raise SystemExit(
                    "ERROR: %s has unexpected non-pass disposition for %s: %s"
                    % (host, fact, disposition)
                )
            if disposition == "degraded":
                degraded.append("%s:%s" % (host, fact))
            elif disposition == "not_applicable":
                not_applicable.append("%s:%s" % (host, fact))

    print("UDS hardening historical field evidence contract passed")
    print("evidence_class=historical_field_evidence")
    print("head_bound=false")
    print("hosts=%d" % len(paths))
    print("require_hardened=%s" % ("true" if require_hardened else "false"))
    print("degraded=%d" % len(degraded))
    if degraded:
        print("degraded_items=%s" % ",".join(degraded))
    print("not_applicable=%d" % len(not_applicable))
    if not_applicable:
        print("not_applicable_items=%s" % ",".join(not_applicable))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--evidence-root",
        default=DEFAULT_EVIDENCE_ROOT,
        help="directory containing UDS hardening evidence subdirectories",
    )
    parser.add_argument(
        "--evidence-dir",
        action="append",
        default=[],
        help="specific evidence directory to check; repeat for multiple hosts",
    )
    parser.add_argument("--min-hosts", type=int, default=3)
    parser.add_argument("--require-hardened", action="store_true")
    args = parser.parse_args()

    paths = args.evidence_dir or _latest_evidence_dirs(args.evidence_root)
    paths = [os.path.abspath(path) for path in paths]
    check_evidence_dirs(paths, args.min_hosts, args.require_hardened)


if __name__ == "__main__":
    main()
