#!/usr/bin/env python3
"""Public entrypoint and evidence-schema checks for standalone TC ACL smoke."""

from __future__ import print_function

import os
import shutil
import subprocess
import sys


ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir))
SMOKE = os.path.join(ROOT, "deploy", "smoke", "aria_standalone_acl_tc_datapath_smoke.sh")
SUMMARY_FIELDS = (
    '"mode"', '"dual_tc_ready"', '"xdp_neutral"', '"missing_tc_rejected"',
    '"health_poll_degraded"', '"recovery_verified"', '"healthy_pinned_restart"',
    '"incomplete_pinned_quiesced"', '"cleanup_errors"', '"result"',
    '"failure_reason"', '"work_dir"', '"run_id"', '"host_if"', '"netns"',
    '"http_addr"',
)
FIELD_CASES = (
    "CASE_IPV4_ONLY", "CASE_IPV6_ONLY", "CASE_DUAL_STACK",
    "CASE_WILDCARD_ISOLATION", "CASE_FRAGMENT", "CASE_STATEFUL_REPLY",
    "CASE_UPGRADE", "CASE_ROLLBACK",
)
FIELD_EVIDENCE_FIELDS = (
    '"command"', '"expected_verdict"', '"observed_verdict"', '"interface"',
    '"ifindex"', '"kernel"', '"agent_version"', '"datapath_version"',
    '"status_snapshot"', '"counter_snapshot"', '"status"',
)


def main():
    args = sys.argv[1:]
    if any(arg != "--self-test" for arg in args):
        print("usage: %s [--self-test]" % sys.argv[0])
        return 2
    if not os.path.isfile(SMOKE):
        print("ERROR: standalone TC ACL smoke is missing: %s" % os.path.relpath(SMOKE, ROOT))
        return 1
    bash = shutil.which("bash")
    if not bash:
        print("ERROR: bash is required to validate standalone TC ACL smoke")
        return 1
    smoke_path = os.path.relpath(SMOKE, ROOT).replace(os.sep, "/")
    if subprocess.call([bash, "-n", smoke_path], cwd=ROOT) != 0:
        return 1
    with open(SMOKE, encoding="utf-8") as handle:
        source = handle.read()
    required = (
        'MODE="${MODE:-system}"', 'case "${MODE}" in system|tap)', "write_summary() {",
        "curl() {", 'command curl -q "$@"',
        "summary.json.tmp", 'mv "${WORK_DIR}/summary.json.tmp" "${WORK_DIR}/summary.json"',
        "record_field_case()", "record_deferred_field_cases()", "run_ethertype_any_expansion_smoke()",
        "ethertype=any expansion", "FIELD_EVIDENCE_STATUS=\"${FIELD_EVIDENCE_STATUS:-deferred/pending}\"",
    ) + SUMMARY_FIELDS + FIELD_CASES + FIELD_EVIDENCE_FIELDS
    missing = [term for term in required if term not in source]
    if missing:
        print("ERROR: standalone TC ACL smoke public contract missing %s" % ", ".join(missing))
        return 1
    if "--fail-with-body" in source:
        print("ERROR: standalone TC ACL smoke requires curl newer than the legacy target")
        return 1
    print("Standalone TC ACL smoke entrypoint and static field-evidence schema: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
