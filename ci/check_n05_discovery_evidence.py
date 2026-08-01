#!/usr/bin/env python3
from __future__ import print_function

import argparse
import os
import re
import sys


ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir))
DEFAULT_EVIDENCE_ROOT = os.path.join(
    ROOT, "docs", "evidence", "openstack-n05-lite"
)

REQUIRED_FACTS = [
    "OS and kernel",
    "Neutron ML2 mechanism drivers",
    "Neutron agents",
    "Aria ACL agent heartbeat",
    "Neutron extensions",
    "aria-acl extension",
    "QoS extension",
    "Trunk extension",
    "OVS topology",
    "Tap and OVS interface inventory",
    "No qvo/qvb hybrid plug",
    "OVS iface-id external_ids",
    "BTF and bpffs",
    "tc capability",
    "XDP tap status",
    "/run/aria and socket permissions",
    "Container state and mounts",
    "UDS capabilities/status",
    "Neutron port source for host",
    "Neutron port class disposition",
    "aria_acl API read counts",
]

ALLOWED_NONPASS = {
    "QoS extension": {"unsupported"},
    "Trunk extension": {"unsupported"},
    "tc capability": {"unsupported"},
    "OVS iface-id external_ids": {"not_applicable"},
    "XDP tap status": {"not_applicable"},
    "Neutron port class disposition": {"unsupported"},
}


def _read(path):
    with open(path, "r", encoding="utf-8") as handle:
        return handle.read()


def _latest_evidence_dirs(root):
    by_host = {}
    if not os.path.isdir(root):
        return []
    for name in os.listdir(root):
        path = os.path.join(root, name)
        if not os.path.isdir(path):
            continue
        if not _is_n05_discovery_dir(path):
            continue
        match = re.match(r"^(\d{14})-(.+)$", name)
        if not match:
            continue
        timestamp, host = match.groups()
        previous = by_host.get(host)
        if previous is None or timestamp > previous[0]:
            by_host[host] = (timestamp, path)
    return [path for _, path in sorted(by_host.values())]


def _is_n05_discovery_dir(path):
    summary_path = os.path.join(path, "summary.md")
    if not os.path.exists(summary_path):
        return False
    with open(summary_path, "r", encoding="utf-8") as handle:
        return "N0.5 Discovery Evidence" in handle.read(512)


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
                raise SystemExit("ERROR: malformed facts.tsv line in %s: %r" % (
                    path, line,
                ))
            fact, expected, command, actual, evidence, disposition = parts
            facts[fact] = {
                "expected": expected,
                "command": command,
                "actual": actual,
                "evidence": evidence,
                "disposition": disposition,
            }
    return facts


def _host_name(path):
    name = os.path.basename(os.path.normpath(path))
    match = re.match(r"^\d{14}-(.+)$", name)
    return match.group(1) if match else name


def _compute_port_count(path):
    source_path = os.path.join(path, "neutron-port-source.txt")
    if not os.path.exists(source_path):
        return 0
    text = _read(source_path)
    match = re.search(r"\bcompute_ports=(\d+)\b", text)
    return int(match.group(1)) if match else 0


def check_evidence_dirs(paths, min_hosts):
    if len(paths) < min_hosts:
        raise SystemExit(
            "ERROR: expected at least %d evidence hosts, got %d: %s"
            % (min_hosts, len(paths), ", ".join(paths))
        )

    hosts_with_compute_iface_id = []
    unsupported = []
    not_applicable = []

    for path in paths:
        host = _host_name(path)
        facts = _parse_facts(path)
        missing = [fact for fact in REQUIRED_FACTS if fact not in facts]
        if missing:
            raise SystemExit("ERROR: %s missing required facts: %s" % (
                host, ", ".join(missing),
            ))

        compute_ports = _compute_port_count(path)
        if compute_ports > 0:
            iface_disposition = facts["OVS iface-id external_ids"]["disposition"]
            if iface_disposition == "pass":
                hosts_with_compute_iface_id.append(host)
            else:
                raise SystemExit(
                    "ERROR: %s has compute_ports=%d but iface-id disposition=%s"
                    % (host, compute_ports, iface_disposition)
                )

        for fact, row in sorted(facts.items()):
            disposition = row["disposition"]
            if disposition == "pass":
                continue
            if disposition == "fail":
                raise SystemExit("ERROR: %s has fail disposition for %s" % (host, fact))
            allowed = ALLOWED_NONPASS.get(fact, set())
            if disposition not in allowed:
                raise SystemExit(
                    "ERROR: %s has unexpected non-pass disposition for %s: %s"
                    % (host, fact, disposition)
                )
            if fact in ("OVS iface-id external_ids", "XDP tap status"):
                if compute_ports != 0:
                    raise SystemExit(
                        "ERROR: %s marks %s not_applicable with compute_ports=%d"
                        % (host, fact, compute_ports)
                    )
            if disposition == "unsupported":
                unsupported.append("%s:%s" % (host, fact))
            elif disposition == "not_applicable":
                not_applicable.append("%s:%s" % (host, fact))

    if not hosts_with_compute_iface_id:
        raise SystemExit(
            "ERROR: no evidence host has both compute ports and OVS iface-id data"
        )

    print("G4 N0.5 historical field evidence contract passed")
    print("evidence_class=historical_field_evidence")
    print("head_bound=false")
    print("hosts=%d" % len(paths))
    print("hosts_with_compute_iface_id=%s" % ",".join(hosts_with_compute_iface_id))
    print("unsupported=%d" % len(unsupported))
    if unsupported:
        print("unsupported_items=%s" % ",".join(unsupported))
    print("not_applicable=%d" % len(not_applicable))
    if not_applicable:
        print("not_applicable_items=%s" % ",".join(not_applicable))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--evidence-root",
        default=DEFAULT_EVIDENCE_ROOT,
        help="directory containing N0.5 evidence subdirectories",
    )
    parser.add_argument(
        "--evidence-dir",
        action="append",
        default=[],
        help="specific evidence directory to check; repeat for multiple hosts",
    )
    parser.add_argument("--min-hosts", type=int, default=3)
    args = parser.parse_args()

    paths = args.evidence_dir or _latest_evidence_dirs(args.evidence_root)
    paths = [os.path.abspath(path) for path in paths]
    check_evidence_dirs(paths, args.min_hosts)


if __name__ == "__main__":
    main()
