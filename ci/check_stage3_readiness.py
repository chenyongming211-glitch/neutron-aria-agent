#!/usr/bin/env python3
from __future__ import print_function

import os
import sys


ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir))


REQUIRED_FILES = [
    ".github/workflows/build.yml",
    "ci/check_payload_terms.py",
    "ci/check_stage2_acceptance_evidence.py",
    "ci/check_n05_discovery_evidence.py",
    "ci/check_uds_hardening_evidence.py",
    "docs/evidence/openstack-n05-lite/2026-06-30-stage2-acceptance-summary.md",
    "docs/openstack-neutron-aria-details/08-stage3-acl-production-hardening.md",
    "deploy/kolla/smoke/neutron_aria_acl_fault_injection_smoke.sh",
    "deploy/kolla/smoke/neutron_aria_crash_injection_smoke.sh",
    "deploy/kolla/smoke/neutron_aria_delete_fault_injection_smoke.sh",
    "deploy/kolla/smoke/neutron_aria_tap_recreate_smoke.sh",
    "deploy/kolla/smoke/neutron_aria_vm_migration_smoke.sh",
    "deploy/kolla/smoke/neutron_aria_uds_hardened_rollout_smoke.sh",
    "deploy/kolla/smoke/neutron_aria_uds_hardening_smoke.sh",
]


MARKERS = {
    ".github/workflows/build.yml": [
        "check_stage2_acceptance_evidence.py",
        "check_n05_discovery_evidence.py",
        "check_uds_hardening_evidence.py",
        "check_stage3_readiness.py",
        "check_payload_terms.py",
        "--require-rust --rust-toolchain stable",
        "workflow_dispatch",
        "Check Rust binary release payload policy",
    ],
    "docs/openstack-neutron-aria-details/README.md": [
        "08-stage3-acl-production-hardening.md",
        "Stage-Three ACL Production Hardening",
    ],
    "docs/openstack-neutron-aria-details/08-stage3-acl-production-hardening.md": [
        "Do not expand QoS/Mirror",
        "Persistent UDS hardening rollout",
        "ACL N3 fault and lifecycle gates",
        "Release/CI gate",
        "Full-resync first",
    ],
    "docs/stage2-acl-release-governance.md": [
        "check_stage2_acceptance_evidence.py",
        "check_n05_discovery_evidence.py",
        "check_uds_hardening_evidence.py",
    ],
    "docs/openstack-target-env-discovery.md": [
        "`aria_acl` binding 缺失",
        "`aria_acl` policy 缺失或不可访问",
        "ACL apply 失败注入",
        "OVS agent / ovs-vswitchd / ovsdb-server 重启行为",
        "VM -> same host VM",
        "port update event source",
    ],
}


def _path(relpath):
    return os.path.join(ROOT, relpath)


def _read(relpath):
    path = _path(relpath)
    if not os.path.exists(path):
        raise SystemExit("ERROR: missing file: %s" % relpath)
    for encoding in ("utf-8", "utf-8-sig", "utf-16"):
        try:
            with open(path, "r", encoding=encoding) as handle:
                return handle.read()
        except UnicodeDecodeError:
            continue
    raise SystemExit("ERROR: cannot decode file: %s" % relpath)


def _check_files():
    missing = [relpath for relpath in REQUIRED_FILES if not os.path.exists(_path(relpath))]
    if missing:
        raise SystemExit("ERROR: missing required stage-three files: %s" % (
            ", ".join(missing),
        ))


def _check_markers():
    for relpath, markers in sorted(MARKERS.items()):
        text = _read(relpath)
        for marker in markers:
            if marker not in text:
                raise SystemExit(
                    "ERROR: %s missing marker %r" % (relpath, marker)
                )


def main():
    _check_files()
    _check_markers()
    print("stage-three readiness plan accepted")
    print("checked_files=%d" % len(REQUIRED_FILES))


if __name__ == "__main__":
    main()
