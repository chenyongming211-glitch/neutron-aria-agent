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
        "flow_conntrack_totals",
        "metric_sum",
        "rule_counter_sum",
        "run_observed_flow",
        "run_stateful_evidence",
        "run_bank_evidence",
        "run_stateless_evidence",
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
            "verify_cleanup_restored",
            "BODY_SUCCEEDED",
            "write_summary",
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
    if "cleanup_errors" not in summary or '"cleanup_errors"' not in summary:
        errors.append("summary.json must contain cleanup_errors")

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
    for term in ("NO_INGRESS_DOUBLE_COUNT", "XDP_NO_ACL_CT", "rule_counter_sum", "flow_conntrack_totals"):
        if term not in bodies["run_stateful_evidence"] and term not in source:
            errors.append("XDP single-authority proof missing %s" % term)

    if "remains 69" in source:
        errors.append("stale backlog count marker remains in smoke source")
    return errors


def mutate_remove(source, needle, label):
    if needle not in source:
        raise ValueError("mutation anchor missing: %s" % label)
    return source.replace(needle, "", 1)


def run_mutation_self_tests(source, verbose=False):
    specs = [
        ("cleanup error false-pass", 'record_cleanup_error "cleanup-full-resync', "cleanup must"),
        ("flow address filter", 'row.get("src_ip")', "flow CT evidence"),
        ("metric family filter", 'labels.get("family")==family', "selected IP family"),
        ("trace-before-evidence order", "set_trace_filter", "Trace filter must"),
        ("stateful resync", "run_full_resync | tee \"${WORK_DIR}/stateful-full-resync.log\"", "run_stateful_evidence"),
        ("summary after cleanup", 'RESULT="pass"', "cleanup must"),
    ]
    failures = []
    for label, needle, expected in specs:
        try:
            mutant = mutate_remove(source, needle, label)
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
