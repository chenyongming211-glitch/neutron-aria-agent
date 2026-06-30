#!/usr/bin/env python3
from __future__ import print_function

import os
import re
import sys


ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir))
EVIDENCE_ROOT = os.path.join(ROOT, "docs", "evidence", "openstack-n05-lite")


FILES = {
    "stage2_acl": os.path.join(EVIDENCE_ROOT, "2026-06-29-stage2-acl", "summary.md"),
    "discovery": os.path.join(EVIDENCE_ROOT, "2026-06-30-discovery-summary.md"),
    "g7": os.path.join(EVIDENCE_ROOT, "2026-06-30-g7-rollback-summary.md"),
    "active": os.path.join(EVIDENCE_ROOT, "2026-06-30-active-direction-summary.md"),
    "guest": os.path.join(
        EVIDENCE_ROOT,
        "20260630155334-ostack2.bj159.net-guest-bypass-probe",
        "summary.md",
    ),
    "guest_logs": os.path.join(
        EVIDENCE_ROOT,
        "20260630155334-ostack2.bj159.net-guest-bypass-probe",
        "service-logs.txt",
    ),
    "guest_cleanup": os.path.join(
        EVIDENCE_ROOT,
        "20260630155334-ostack2.bj159.net-guest-bypass-probe",
        "cleanup-final.txt",
    ),
    "uds": os.path.join(EVIDENCE_ROOT, "2026-06-30-uds-hardening-summary.md"),
    "runbook": os.path.join(
        ROOT, "docs", "openstack-neutron-aria-details", "06-deployment-n05-runbook.md"
    ),
    "acceptance": os.path.join(
        EVIDENCE_ROOT, "2026-06-30-stage2-acceptance-summary.md"
    ),
}


REQUIRED_MARKERS = {
    "stage2_acl": [
        "stage-two ACL gate ok",
        "aria_acl_source policies=1 rules=1 bindings=1",
        "MANAGED_COUNT=5",
        "MANAGED_COUNT=0",
        "heartbeat_summary_fields=ok host=ostack2.bj159.net",
        "heartbeat_summary_fields=ok host=ostack3.bj159.net",
        "does not enable QoS/Mirror",
    ],
    "discovery": [
        "G4 discovery accepted",
        "hosts=3",
        "0 fail",
        "DHCP initial request/lease passed",
        "target metadata service degraded",
        "IPv6 ND is `not_applicable`",
    ],
    "g7": [
        "ICMP from `10.58.159.2/32`",
        "was blocked by the smoke ACL",
        "Post-rollback status",
        "`managed_ports=[]`",
        "VM -> external active direction evidence is covered",
        "DHCP initial lease passed",
        "Persistent hardened rollout is still a release/operations gate",
    ],
    "active": [
        "external/host-to-VM and VM-to-external active ACL directions are",
        "generation `85` reached UDS `ready`",
        "no matching ICMP packet",
        "captured during the check window",
        "metadata service degraded",
    ],
    "guest": [
        "DHCP initial request/lease: pass",
        "DHCP renew command: not_applicable",
        "Metadata network path: pass/degraded",
        "backend Unix socket (`ENOENT`)",
        "IPv6 ND: not_applicable",
    ],
    "guest_logs": [
        "DHCPOFFER",
        "DHCPREQUEST",
        "DHCPACK",
        "accepted ('10.58.159.40'",
        "error: [Errno 2] ENOENT",
    ],
    "guest_cleanup": [
        "servers",
        "images",
        "keypairs",
        '"managed_ports":[]',
        '"active_instances":[]',
    ],
    "uds": [
        "Site enforcement gate: accepted for three-node reversible proof",
        "ostack2.bj159.net",
        "ostack3.bj159.net",
        "ostack4.bj159.net",
        "REQUIRE_HARDENED=true",
        "root:42435 0660",
        "peercred_allow_list_match",
    ],
    "runbook": [
        "| G0 image/config packaged | pass for MVP |",
        "| G5 production ACL source | pass for MVP |",
        "| G6 full resync | pass for ACL MVP |",
        "| G4 environment discovery | pass for discovery + reversible hardened proof + bounded guest disposition |",
        "| G7 rollback | pass for active ACL rollback evidence |",
        "| QoS/Mirror | not in scope |",
    ],
    "acceptance": [
        "Status: stage-two ACL MVP acceptance passed.",
        "| G5 production ACL source | pass |",
        "| G6 full resync | pass |",
        "| G7 rollback/connectivity | pass |",
        "| Active traffic direction | pass |",
        "| UDS hardening gate | pass for reversible field proof |",
        "| QoS/Mirror boundary | pass |",
        "Full product N0.5/N3 items outside the stage-two ACL MVP",
    ],
}


STALE_PATTERNS = [
    r"guest-side DHCP",
    r"metadata endpoint probes? (remain|still)",
    r"pending because new temporary",
    r"still missing",
    r"仍需恢复",
    r"仍被 Nova",
]


def _read(path):
    if not os.path.exists(path):
        raise SystemExit("ERROR: missing required evidence file: %s" % path)
    for encoding in ("utf-8", "utf-8-sig", "utf-16"):
        try:
            with open(path, "r", encoding=encoding) as handle:
                return handle.read()
        except UnicodeDecodeError:
            continue
    raise SystemExit("ERROR: cannot decode evidence file: %s" % path)


def _check_markers():
    for key, markers in REQUIRED_MARKERS.items():
        text = _read(FILES[key])
        for marker in markers:
            if marker not in text:
                raise SystemExit(
                    "ERROR: %s missing marker %r in %s" % (key, marker, FILES[key])
                )


def _check_no_stale_pending_text():
    search_paths = [
        os.path.join(ROOT, "docs", "openstack-target-env-discovery.md"),
        os.path.join(ROOT, "docs", "openstack-neutron-aria-details", "README.md"),
        FILES["runbook"],
        FILES["discovery"],
        FILES["g7"],
        FILES["active"],
    ]
    for path in search_paths:
        text = _read(path)
        for pattern in STALE_PATTERNS:
            if re.search(pattern, text, re.IGNORECASE):
                raise SystemExit(
                    "ERROR: stale stage-two pending text matched %r in %s"
                    % (pattern, path)
                )


def _check_no_partial_guest_probe_dirs():
    if not os.path.isdir(EVIDENCE_ROOT):
        raise SystemExit("ERROR: missing evidence root: %s" % EVIDENCE_ROOT)
    bad = []
    for name in os.listdir(EVIDENCE_ROOT):
        if re.search(r"guest-bypass-probe-partial|bounded-bypass-probe-failed", name):
            bad.append(name)
        if name == "20260630155013-ostack2.bj159.net-guest-bypass-probe":
            bad.append(name)
    if bad:
        raise SystemExit("ERROR: stale partial guest evidence directories: %s" % (
            ", ".join(sorted(bad)),
        ))


def main():
    _check_markers()
    _check_no_stale_pending_text()
    _check_no_partial_guest_probe_dirs()
    print("stage-two acceptance evidence accepted")
    print("checked_files=%d" % len(FILES))


if __name__ == "__main__":
    main()
