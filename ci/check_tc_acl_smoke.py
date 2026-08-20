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
DATAPATH_CONTAINER_SMOKE = os.path.join(
    ROOT,
    "deploy",
    "kolla",
    "smoke",
    "aria_datapath_container_smoke.sh",
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


def _bash_repo_path(path):
    return os.path.relpath(path, ROOT).replace(os.sep, "/")


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
    if not os.path.isfile(DATAPATH_CONTAINER_SMOKE):
        print("ERROR: datapath container smoke is missing: %s" % os.path.relpath(DATAPATH_CONTAINER_SMOKE, ROOT))
        return 1
    bash = shutil.which("bash")
    if not bash:
        print("ERROR: bash is required to validate the TC ACL smoke")
        return 1
    if subprocess.call([bash, "-n", _bash_repo_path(SMOKE)], cwd=ROOT) != 0:
        return 1
    if subprocess.call(
        [bash, "-n", _bash_repo_path(DELETE_FAULT_SMOKE)], cwd=ROOT
    ) != 0:
        return 1
    if subprocess.call(
        [bash, "-n", _bash_repo_path(DATAPATH_CONTAINER_SMOKE)], cwd=ROOT
    ) != 0:
        return 1
    with open(SMOKE, encoding="utf-8") as handle:
        source = handle.read()
    required = (
        "write_summary() {",
        "summary.json.tmp",
        'mv "${WORK_DIR}/summary.json.tmp" "${WORK_DIR}/summary.json"',
        "counter-deltas.json",
        "capture_tc_filter() {",
        "assert_tc_attachment_ready() {",
        'DATAPATH_LOG_FILE="${DATAPATH_LOG_FILE:-}"',
        'NEUTRON_CONFIG_FILE="${NEUTRON_CONFIG_FILE:-/etc/neutron/neutron.conf}"',
        'OVS_AGENT_CONFIG_FILE="${OVS_AGENT_CONFIG_FILE:-/etc/neutron/plugins/ml2/openvswitch_agent.ini}"',
        '--neutron-config-file "${NEUTRON_CONFIG_FILE}"',
        '--neutron-config-file "${OVS_AGENT_CONFIG_FILE}"',
        '"mode":"legacy"',
        "run_live_legacy_selector_repair() {",
        "LEGACY_REPAIR_MODE=\"background\"",
        "LEGACY_REPAIR_MODE=\"observed_bank_repair\"",
        "run_captured_selector_flow legacy-background-repaired-deny 2 deny",
        'if repair_mode=="background":',
        'elif repair_mode=="observed_bank_repair":',
        "uds_get() {",
        "wait_resync_quiesced() {",
        "wait_resync_quiesced || return 1",
        "wait_baseline_inventory_reattached() {",
        'datapath_get "/api/v1/${EXPECTED_IFNAME}/config"',
        'assert runtime.get("acl") is True,runtime',
        'item.get("readiness_reason") in (None,"xdp_ddos_hook_unavailable")',
        'baseline_names.issubset(active_names)',
        '2>"${WORK_DIR}/restart-reattach-${attempt}.assert.err"',
        '"legacy_restart_repair_gate":"not_applicable"',
        "assert_exact_selector_state() {",
        "assert_more_specific_selector_state() {",
        'SELECTOR_FIXTURE_SCOPE="${SELECTOR_FIXTURE_SCOPE:-all}"',
        '"requested_scope":os.environ["SELECTOR_FIXTURE_SCOPE"]',
        'EXACT_SELECTOR_FIXTURE_STATUS="not_requested"',
        'LEGACY_SELECTOR_REPAIR_FIXTURE_STATUS="not_requested"',
        'LEGACY_POLLUTION_GROUP_CIDR="${LEGACY_POLLUTION_GROUP_CIDR:-192.0.2.1/32}"',
        "assert exact_acl_entries[selector_cidr]==selector_group_id",
        "assert new_acl_entries[selector_cidr]==selector_group_id",
        "def decode_bpftool_bytes(values):",
        '"legacy_tc": True',
    ) + SUMMARY_FIELDS
    missing = [term for term in required if term not in source]
    if missing:
        print("ERROR: TC ACL smoke evidence schema missing %s" % ", ".join(missing))
        return 1
    if "--fail-with-body" in source:
        print("ERROR: managed TC ACL smoke requires curl newer than the legacy target")
        return 1
    if '--unix-socket "${NEUTRON_UDS}"' in source:
        print("ERROR: managed TC ACL smoke bypasses the enforced UDS peer identity")
        return 1
    restart_bank_invariants = (
        "assert equal_bank==restart_bank",
        "assert second_repair_switch is False",
    )
    if any(term in source for term in restart_bank_invariants):
        print("ERROR: managed TC ACL smoke treats the bank slot as restart-persistent")
        return 1
    selector_prepare = source.index("prepare_owned_selector_fixture", source.index('case "${SELECTOR_FIXTURE_SCOPE}" in'))
    selector_none = source.index("none)", selector_prepare)
    if not selector_prepare < selector_none:
        print("ERROR: selector fixture preparation is not scoped away from ACL-only smoke")
        return 1
    legacy_delete = source.index('delete_selector_fixture_group "${LEGACY_LOCAL_GROUP_NAME}"')
    legacy_repaired = source.index("LEGACY_POLLUTION_INJECTED=false", legacy_delete)
    legacy_restart = source.index("restart_managed_datapath ready", legacy_delete)
    if not legacy_delete < legacy_repaired < legacy_restart:
        print("ERROR: legacy selector cleanup state is not cleared before restart")
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
    isolated_transaction_required = (
        'DIRECT_SNAPSHOT_MODE="${DIRECT_SNAPSHOT_MODE:-false}"',
        "submit_direct_acl_snapshot() {",
        "from neutron_aria.agent.state import desired_snapshot_hash",
        'snapshot["desired_hash"] = desired_snapshot_hash(snapshot)',
        "direct_snapshot_settled",
        "capture_tc_filter() {",
        '"${directory}/bpftool-net-status.json"',
        '"${directory}/bpftool-link-status.json"',
        "def decode_bpftool_bytes(values):",
        "def decode_bpftool_int(value):",
        'bpftool map pin id "${expected_id}" "${source}"',
        'attach_mode="legacy"',
        '"legacy_tc": True',
        'DIRECT_SNAPSHOT_MODE}" = "true" ] && [ "${body_rc}" -ne 0',
        'DATAPATH_PIN_PATH="${DATAPATH_PIN_PATH:-}"',
        'DATAPATH_LISTEN_ADDR="${DATAPATH_LISTEN_ADDR:-}"',
        "def target_port_and_status(status):",
        'assert after_row.get("status")=="blocked"',
        'assert after_acl.get("effective_action")=="bypass"',
        '"blocked_status_visible":True',
    )
    isolated_transaction_missing = [
        term for term in isolated_transaction_required
        if term not in delete_fault_source
    ]
    if isolated_transaction_missing:
        print("ERROR: isolated transaction smoke contract missing %s" % ", ".join(isolated_transaction_missing))
        return 1
    with open(DATAPATH_CONTAINER_SMOKE, encoding="utf-8") as handle:
        datapath_container_source = handle.read()
    isolated_datapath_required = (
        'PIN_PATH="${PIN_PATH:-}"',
        'LISTEN_ADDR="${LISTEN_ADDR:-}"',
        'neutron_socket_path = \\"${SOCKET_PATH}\\"',
        'v0.9-neutron-capabilities-6',
        'for domain in ("attach", "acl"):',
        "wait_for_snapshot_generation() {",
        'json_check missing_port_status "${settled_status}" "${snapshot_generation}"',
    )
    isolated_datapath_missing = [
        term for term in isolated_datapath_required
        if term not in datapath_container_source
    ]
    if isolated_datapath_missing:
        print("ERROR: isolated datapath smoke contract missing %s" % ", ".join(isolated_datapath_missing))
        return 1
    print("TC ACL smoke entrypoint and evidence schema: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
