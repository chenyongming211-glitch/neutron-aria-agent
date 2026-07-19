#!/usr/bin/env python3
"""Public entrypoint and evidence-schema checks for the managed TC ACL smoke."""

from __future__ import print_function

import os
import shutil
import subprocess
import sys


ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir))
SMOKE = os.path.join(ROOT, "deploy", "kolla", "smoke", "neutron_aria_acl_tc_datapath_smoke.sh")
DELETE_FAULT_SMOKE = os.path.join(
    ROOT,
    "deploy",
    "kolla",
    "smoke",
    "neutron_aria_delete_fault_injection_smoke.sh",
)
SUMMARY_FIELDS = (
    '"result"', '"failure_reason"', '"body_succeeded"', '"cleanup_errors"',
    '"work_dir"', '"real_tap"', '"ip_family"', '"checks"',
    '"selector_isolation"',
)
TRANSACTION_SUMMARY_FIELDS = (
    '"result"', '"failure_reason"', '"cleanup_errors"', '"work_dir"',
    '"transaction_boundary"', '"complete"', '"detach_ordering"',
    '"purge_failure_atomicity"', '"strict_flush_rollback"', '"retry_detach"',
)


def main():
    args = sys.argv[1:]
    if any(arg != "--self-test" for arg in args):
        print("usage: %s [--self-test]" % sys.argv[0])
        return 2
    if not os.path.isfile(SMOKE):
        print("ERROR: TC ACL smoke is missing: %s" % os.path.relpath(SMOKE, ROOT))
        return 1
    if not os.path.isfile(DELETE_FAULT_SMOKE):
        print("ERROR: delete fault smoke is missing: %s" % os.path.relpath(DELETE_FAULT_SMOKE, ROOT))
        return 1
    bash = shutil.which("bash")
    if not bash:
        print("ERROR: bash is required to validate the TC ACL smoke")
        return 1
    if subprocess.call([bash, "-n", SMOKE]) != 0:
        return 1
    if subprocess.call([bash, "-n", DELETE_FAULT_SMOKE]) != 0:
        return 1
    with open(SMOKE, encoding="utf-8") as handle:
        source = handle.read()
    required = ("write_summary() {", "summary.json.tmp", 'mv "${WORK_DIR}/summary.json.tmp" "${WORK_DIR}/summary.json"', "counter-deltas.json") + SUMMARY_FIELDS
    missing = [term for term in required if term not in source]
    if missing:
        print("ERROR: TC ACL smoke evidence schema missing %s" % ", ".join(missing))
        return 1
    with open(DELETE_FAULT_SMOKE, encoding="utf-8") as handle:
        delete_fault_source = handle.read()
    transaction_required = (
        "summary.json.tmp",
        'mv "${WORK_DIR}/summary.json.tmp" "${WORK_DIR}/summary.json"',
    ) + TRANSACTION_SUMMARY_FIELDS
    transaction_missing = [term for term in transaction_required if term not in delete_fault_source]
    if transaction_missing:
        print("ERROR: delete fault smoke evidence schema missing %s" % ", ".join(transaction_missing))
        return 1
    print("TC ACL smoke entrypoint and evidence schema: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
