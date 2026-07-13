#!/usr/bin/env python3
"""Structure and mutation contracts for the destructive real-tap ACL smoke."""

from __future__ import print_function

import os
import re
import sys


ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir))
SMOKE = os.path.join(
    ROOT, "deploy", "kolla", "smoke", "neutron_aria_acl_tc_datapath_smoke.sh"
)
BACKLOG = os.path.join(
    ROOT, "docs", "openstack-neutron-aria-details", "12-review-bug-backlog.md"
)


def function_body(source, name):
    lines = source.splitlines()
    start = None
    for index, line in enumerate(lines):
        if re.match(r"^%s\(\) \{$" % re.escape(name), line):
            start = index + 1
            break
    if start is None:
        raise KeyError(name)
    for index in range(start, len(lines)):
        if lines[index] == "}":
            return "\n".join(lines[start:index])
    raise ValueError("unterminated shell function %s" % name)


def ordered(body, terms):
    position = -1
    for term in terms:
        position = body.find(term, position + 1)
        if position < 0:
            return False
    return True


def check_source(source):
    errors = []

    required_functions = (
        "record_cleanup_error",
        "capture_runtime_compatibility",
        "flow_conntrack_totals",
        "metric_sum",
        "rule_counter_sum",
        "run_observed_flow",
        "assert_stateful_evidence",
        "run_stateful_evidence",
        "assert_bank_evidence",
        "run_bank_evidence",
        "assert_stateless_evidence",
        "run_stateless_evidence",
        "assert_deny_evidence",
        "run_deny_evidence",
        "verify_cleanup_restored",
        "cleanup",
        "write_summary",
    )
    bodies = {}
    for name in required_functions:
        try:
            bodies[name] = function_body(source, name)
        except (KeyError, ValueError) as exc:
            errors.append("missing structured smoke helper %s (%s)" % (name, exc))
    if errors:
        return errors

    if "capture_runtime_mode" in source or "runtime-mode" in source:
        errors.append("TapConfig byte 7 must be reported as compatibility, not runtime authority")
    compatibility = bodies["capture_runtime_compatibility"]
    for term in (
        "TAP_CONFIG_MAP",
        "len(v)==8",
        "v[7]==int(sys.argv[2])",
        '"compatibility_byte"',
    ):
        if term not in compatibility:
            errors.append("TapConfig migration compatibility evidence missing %s" % term)
    if 'capture_runtime_compatibility "${label}" >"${WORK_DIR}/${label}-runtime-compatibility.txt"' not in source:
        errors.append("capture must preserve TapConfig migration compatibility evidence")

    cleanup = bodies["cleanup"]
    if not all(
        term in cleanup
        for term in (
            "trap - EXIT",
            "cleanup_errors",
            "record_cleanup_error",
            "cleanup-delete-rule-",
            "cleanup-delete-binding",
            "cleanup-delete-policy",
            "cleanup-full-resync",
            'record_cleanup_error "cleanup-full-resync failed"',
            "verify_cleanup_restored",
            "BODY_SUCCEEDED",
            "write_summary",
            'record_cleanup_error "write_summary failed"',
            'RESULT="fail"',
            'RESULT="pass"',
        )
    ):
        errors.append("cleanup must be fail-closed and verify rollback before final result")
    if not ordered(
        cleanup,
        (
            "trap - EXIT",
            "cleanup-delete-rule-",
            "cleanup-delete-binding",
            "cleanup-delete-policy",
            "cleanup-full-resync",
            "verify_cleanup_restored",
            'RESULT="fail"',
            'RESULT="pass"',
            "write_summary",
        ),
    ):
        errors.append("cleanup result/summary order is not fail-closed")
    outside_cleanup = source.replace(cleanup, "", 1)
    if 'RESULT="pass"' in outside_cleanup:
        errors.append("main body must not mark pass before cleanup verification")
    summary = bodies["write_summary"]
    if (
        "cleanup_errors" not in summary
        or '"cleanup_errors"' not in summary
        or summary.count("|| return 1") < 4
    ):
        errors.append("summary.json must contain cleanup_errors")
    restore = bodies["verify_cleanup_restored"]
    if (
        "run_controlled_traffic" in restore
        or "cleanup-baseline-traffic.log" not in restore
        or "capture cleanup-restored || return 1" not in restore
    ):
        errors.append("cleanup restore checks must return failures without exiting before summary")

    flow = bodies["flow_conntrack_totals"]
    for term in (
        "SOURCE_IP",
        "VM_IP",
        "CT_PROTOCOL",
        "IP_FAMILY",
        'row.get("src_ip")',
        'row.get("dst_ip")',
        "forward or reverse",
        "ipaddress.ip_address",
    ):
        if term not in flow:
            errors.append("flow CT evidence missing %s" % term)
    metric = bodies["metric_sum"]
    if 'labels.get("family")==family' not in metric or 'local family="$4"' not in metric:
        errors.append("CT contract metric deltas must require the selected IP family")
    rule = bodies["rule_counter_sum"]
    for term in ('row.get("proto")', 'row.get("direction")', "packets_field"):
        if term not in rule:
            errors.append("ACL rule counter evidence missing %s" % term)
    if '/stats/rules' not in source:
        errors.append("smoke must capture the real rule-stats API")

    observed = bodies["run_observed_flow"]
    if not ordered(
        observed,
        ("set_trace_filter", "capture \"${label}-before\"", "run_controlled_traffic", "capture \"${label}-after\""),
    ):
        errors.append("Trace filter must be active before before/traffic/after evidence")

    phase_contracts = {
        "run_stateful_evidence": ("run_full_resync", "run_observed_flow", "assert_stateful_evidence"),
        "run_bank_evidence": ("run_full_resync", "run_observed_flow", "assert_bank_evidence"),
        "run_stateless_evidence": ("run_full_resync", "run_observed_flow", "assert_stateless_evidence"),
        "run_deny_evidence": ("run_full_resync", "run_observed_flow", "assert_deny_evidence"),
    }
    for name, terms in phase_contracts.items():
        if not ordered(bodies[name], terms):
            errors.append("%s must resync, generate controlled traffic, and assert evidence" % name)

    for term in (
        'IP_FAMILY="ipv4"',
        'IP_FAMILY="ipv6"',
        'IP_FAMILY_LABEL="ipv6-icmp"',
        'ACL_PROTOCOL="58"',
        'TRACE_PROTOCOL="58"',
        'CT_PROTOCOL="58"',
        "PING_ARGS=(-6)",
    ):
        if term not in source:
            errors.append("IPv4/IPv6 controlled-flow selection missing %s" % term)
    for forbidden in ("unknown_hook_delta", "hook\") not in"):
        if forbidden in source:
            errors.append("XDP proof must not rely on unknown-hook absence")
    stateful_assert = bodies["assert_stateful_evidence"]
    for term in (
        "NO_INGRESS_DOUBLE_COUNT",
        "XDP_NO_ACL_CT",
        "rule_counter_sum",
        "flow_conntrack_totals",
        "packet_delta",
        "byte_delta",
        "rule_packet_delta",
        "authoritative TC observations",
    ):
        if term not in stateful_assert:
            errors.append("XDP single-authority proof missing %s" % term)

    main_body = source.split("trap cleanup EXIT\n", 1)[-1]
    if not ordered(
        main_body,
        (
            "run_stateful_evidence",
            "capture bank-pre-resync",
            "create_rule ingress allow tcp 200",
            "run_bank_evidence",
        ),
    ):
        errors.append("bank proof must capture the live controlled CT before Neutron resync")

    bank_assert = bodies["assert_bank_evidence"]
    for term in (
        "stateful-egress-after-conntrack.json",
        "bank-pre-resync-conntrack.json",
        "bank-before-conntrack.json",
        "bank-after-conntrack.json",
        "reference_ct_count",
        "reference_ct_packets",
        "reference_ct_bytes",
        "pre_resync_ct_count",
        "before_ct_count",
        'before_ct_count}" -eq 0',
        'bank_miss_delta}" -ge 1',
        "bank_stale_delta=",
        'reference_ct_packets}" -eq "${expected}',
        'ct_packets}" -eq "${expected}',
        'ct_bytes}" -eq "${reference_ct_bytes}',
        "exact byte reference",
        "strict CT flush",
        "recreated after strict flush",
    ):
        if term not in bank_assert:
            errors.append("bank strict-flush revalidation proof missing %s" % term)
    if 'bank_stale_delta}" -ge' in bank_assert:
        errors.append("Neutron bank smoke must not require stale_bank after strict CT flush")

    return errors


def mutate_remove(source, needle, label):
    if needle not in source:
        raise ValueError("mutation anchor missing: %s" % label)
    return source.replace(needle, "", 1)


def mutate_early_pass(source, _needle, label):
    anchor = 'BODY_SUCCEEDED=true\n'
    if anchor not in source:
        raise ValueError("mutation anchor missing: %s" % label)
    return source.replace(anchor, 'RESULT="pass"\n' + anchor, 1)


def mutate_degrade_bank_bytes(source, _needle, label):
    anchor = '[ "${ct_bytes}" -eq "${reference_ct_bytes}" ]'
    if anchor not in source:
        raise ValueError("mutation anchor missing: %s" % label)
    return source.replace(anchor, '[ "${ct_bytes}" -gt 0 ]', 1)


def mutate_add_unknown_hook_proof(source, _needle, label):
    anchor = "assert_stateful_evidence() {\n"
    if anchor not in source:
        raise ValueError("mutation anchor missing: %s" % label)
    return source.replace(anchor, anchor + "    unknown_hook_delta=0\n", 1)


def mutate_add_hook_selector_proof(source, _needle, label):
    anchor = "assert_stateful_evidence() {\n"
    if anchor not in source:
        raise ValueError("mutation anchor missing: %s" % label)
    return source.replace(anchor, anchor + '    if row.get("hook") not in observed: return 1\n', 1)


def run_mutation_self_tests(source, verbose=False):
    specs = [
        ("cleanup error false-pass", mutate_remove, 'record_cleanup_error "cleanup-full-resync', "cleanup must"),
        ("cleanup restore early exit", mutate_remove, "capture cleanup-restored || return 1", "cleanup restore checks"),
        ("flow address filter", mutate_remove, 'row.get("src_ip")', "flow CT evidence"),
        ("metric family filter", mutate_remove, 'labels.get("family")==family', "selected IP family"),
        ("trace-before-evidence order", mutate_remove, '    set_trace_filter "${trace_src}" "${trace_dst}"', "Trace filter must"),
        ("stateful resync", mutate_remove, "run_full_resync | tee \"${WORK_DIR}/stateful-full-resync.log\"", "run_stateful_evidence"),
        ("stateless resync", mutate_remove, "run_full_resync | tee \"${WORK_DIR}/stateless-full-resync.log\"", "run_stateless_evidence"),
        ("deny resync", mutate_remove, "run_full_resync | tee \"${WORK_DIR}/deny-full-resync.log\"", "run_deny_evidence"),
        ("bank resync", mutate_remove, "run_full_resync | tee \"${WORK_DIR}/bank-full-resync.log\"", "run_bank_evidence"),
        ("bank pre-resync CT capture", mutate_remove, "capture bank-pre-resync", "bank proof must capture"),
        ("bank strict-flush zero CT", mutate_remove, '[ "${before_ct_count}" -eq 0 ]', "bank strict-flush revalidation proof"),
        ("bank miss proof", mutate_remove, '[ "${bank_miss_delta}" -ge 1 ]', "bank strict-flush revalidation proof"),
        ("bank exact byte reference", mutate_degrade_bank_bytes, "", "bank strict-flush revalidation proof"),
        ("summary before cleanup result", mutate_early_pass, "", "main body must not mark pass"),
        ("unknown hook proof", mutate_add_unknown_hook_proof, "", "unknown-hook absence"),
        ("hook selector proof", mutate_add_hook_selector_proof, "", "unknown-hook absence"),
    ]
    failures = []
    for label, mutate, needle, expected in specs:
        try:
            mutant = mutate(source, needle, label)
        except ValueError as exc:
            failures.append(str(exc))
            continue
        mutant_errors = check_source(mutant)
        if not any(expected in error for error in mutant_errors):
            failures.append("mutation %s was accepted" % label)
        elif verbose:
            print("PASS: rejected mutation %s" % label)
    return failures


def main():
    args = sys.argv[1:]
    if any(arg != "--self-test" for arg in args):
        print("usage: %s [--self-test]" % sys.argv[0])
        return 2
    with open(SMOKE, "r", encoding="utf-8") as handle:
        source = handle.read()
    errors = check_source(source)
    with open(BACKLOG, "r", encoding="utf-8") as handle:
        backlog = handle.read()
    if "unique tracking-item total remains 69" in backlog:
        errors.append("backlog still says the unique tracking-item total remains 69")
    if "unique tracking-item total is now 71" not in backlog:
        errors.append("backlog must state the corrected unique tracking-item total is 71")
    if not errors:
        errors.extend(run_mutation_self_tests(source, verbose="--self-test" in args))
    if errors:
        for error in errors:
            print("ERROR: %s" % error)
        return 1
    print("TC ACL real-tap smoke structure and mutation self-tests: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
