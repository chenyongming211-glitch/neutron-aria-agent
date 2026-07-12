#!/usr/bin/env python3
"""Static contracts for the TC-unified ACL/conntrack datapath.

The checks intentionally inspect individual Rust function bodies.  Keeping the
extractor here avoids accepting a marker that happens to exist elsewhere in
the eBPF source while a live packet path remains unwired.
"""

from __future__ import print_function

import os
import re
import sys


ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir))
EBPF_LIB = os.path.join(ROOT, "ebpf", "src", "lib.rs")


def _matching_brace(source, opening):
    """Return the matching closing brace, ignoring comments and strings."""
    depth = 0
    index = opening
    state = "code"
    block_depth = 0
    while index < len(source):
        char = source[index]
        nxt = source[index + 1] if index + 1 < len(source) else ""
        if state == "line_comment":
            if char == "\n":
                state = "code"
        elif state == "block_comment":
            if char == "/" and nxt == "*":
                block_depth += 1
                index += 1
            elif char == "*" and nxt == "/":
                block_depth -= 1
                index += 1
                if block_depth == 0:
                    state = "code"
        elif state == "string":
            if char == "\\":
                index += 1
            elif char == '"':
                state = "code"
        elif state == "char":
            if char == "\\":
                index += 1
            elif char == "'":
                state = "code"
        else:
            if char == "/" and nxt == "/":
                state = "line_comment"
                index += 1
            elif char == "/" and nxt == "*":
                state = "block_comment"
                block_depth = 1
                index += 1
            elif char == '"':
                state = "string"
            elif char == "'" and (
                (index + 2 < len(source) and source[index + 2] == "'")
                or (
                    nxt == "\\"
                    and index + 3 < len(source)
                    and source[index + 3] == "'"
                )
            ):
                state = "char"
            elif char == "{":
                depth += 1
            elif char == "}":
                depth -= 1
                if depth == 0:
                    return index
        index += 1
    raise ValueError("unbalanced Rust function body")


def function_body_span(source, name):
    pattern = re.compile(
        r"(?:^|\n)\s*(?:pub\s+)?(?:unsafe\s+)?fn\s+%s\s*\(" % re.escape(name)
    )
    match = pattern.search(source)
    if not match:
        raise KeyError(name)
    opening = source.find("{", match.end())
    if opening < 0:
        raise ValueError("function %s has no body" % name)
    closing = _matching_brace(source, opening)
    return opening + 1, closing


def function_body(source, name):
    start, end = function_body_span(source, name)
    return source[start:end]


def _body_or_error(source, name, errors, path):
    try:
        return function_body(source, name)
    except (KeyError, ValueError) as exc:
        errors.append("%s: missing extractable helper %s (%s)" % (path, name, exc))
        return None


def _block_after(body, marker, start=0):
    """Extract the first brace-balanced block following marker."""
    marker_at = body.find(marker, start)
    if marker_at < 0:
        return None
    opening = body.find("{", marker_at + len(marker))
    if opening < 0:
        return None
    try:
        closing = _matching_brace(body, opening)
    except ValueError:
        return None
    return body[opening + 1 : closing], marker_at, opening, closing


def _drop_guard_after(body, phase_marker, start=0):
    phase_at = body.find(phase_marker, start)
    if phase_at < 0:
        return None
    return _block_after(body, "if p.action == TC_ACT_SHOT as u32", phase_at)


def check_xdp(source, errors):
    body = _body_or_error(source, "try_xdp_firewall", errors, "XDP")
    if body is None:
        return
    hook = body.find("runtime::acl_ingress_hook(p.tap_id) == ACL_INGRESS_HOOK_TC")
    forbidden = [
        "load_feature_flags_xdp(p, info)",
        "CtKey4 {",
        "CtKey6 {",
        "phase_ct_v4(",
        "phase_ct_v6(",
        "load_acl_packet_ids_",
        "phase_policy_xdp(",
        "phase_post_accept_xdp_",
        "conntrack::ct_create_",
    ]
    first_acl_ct = min((body.find(term) for term in forbidden if term in body), default=-1)
    resolve = body.find("load_runtime_ctx_xdp(ctx, p)")
    hook_block_ok = False
    if hook >= 0:
        opening = body.find("{", hook)
        if opening >= 0:
            closing = _matching_brace(body, opening)
            hook_block_ok = "return Ok(XDP_PASS)" in body[opening + 1 : closing]
    if (
        resolve < 0
        or hook <= resolve
        or not hook_block_ok
        or (first_acl_ct >= 0 and hook > first_acl_ct)
    ):
        errors.append(
            "XDP: try_xdp_firewall must return PASS for TC hook mode before ACL/CT work"
        )


def check_live_path(source, errors, direction, family):
    bits = "4" if family == "v4" else "6"
    key = "CtKey%s {" % bits
    phase = "phase_ct_v%s(" % bits
    wrapper = "try_tc_%s_%s" % (direction, family)
    body = _body_or_error(source, wrapper, errors, "TC %s %s" % (direction, family))
    if body is None:
        return

    required = [key, phase, "FLAG_CT_HIT"]
    wrong_bits = "6" if bits == "4" else "4"
    forbidden = ["CtKey%s {" % wrong_bits, "phase_ct_v%s(" % wrong_bits, "ct_state"]
    if direction == "ingress":
        hook_term = "runtime::acl_ingress_hook(p.tap_id) == ACL_INGRESS_HOOK_TC"
        hit = "phase_ct_fastpath_tc_ingress_%s(" % family
        miss = "phase_ct_miss_tc_ingress_%s(" % family
        legacy = "phase_legacy_tc_ingress_%s(" % family
        required.extend([hook_term, hit, miss, legacy])
        hook = body.find(hook_term)
        tc_block = ""
        if hook >= 0:
            opening = body.find("{", hook)
            if opening >= 0:
                closing = _matching_brace(body, opening)
                tc_block = body[opening + 1 : closing]
        if any(term not in tc_block for term in (phase, "FLAG_CT_HIT", hit, miss)):
            forbidden.append("TC_LOOKUP_OUTSIDE_HOOK_BLOCK")
        if legacy in tc_block:
            forbidden.append("LEGACY_INSIDE_TC_HOOK_BLOCK")
    else:
        required.extend(
            [
                "phase_ct_fastpath_tc_egress_%s(" % family,
                "phase_ct_miss_tc_egress_%s(" % family,
            ]
        )
    has_structural_error = any(term.startswith(("TC_", "LEGACY_")) for term in forbidden)
    has_wrong_family = any(term in body for term in forbidden if not term.startswith(("TC_", "LEGACY_")))
    if any(term not in body for term in required) or has_structural_error or has_wrong_family:
        errors.append(
            "TC %s %s: live path must use a family-correct CT key, CT phase, and FLAG_CT_HIT decision"
            % (direction, family)
        )


def check_legacy_ingress(source, errors, family):
    name = "phase_legacy_tc_ingress_%s" % family
    path = "TC ingress %s legacy" % family
    body = _body_or_error(source, name, errors, path)
    if body is None:
        return
    forbidden = ("phase_ct_", "ct_lookup_", "load_acl_packet_ids_", "phase_policy_tc(", "ct_create_")
    if any(term in body for term in forbidden):
        errors.append("%s: legacy post-processing must not execute ACL or conntrack" % path)


def check_hit_helper(source, errors, direction, family):
    name = "phase_ct_fastpath_tc_%s_%s" % (direction, family)
    path = "TC %s %s hit" % (direction, family)
    body = _body_or_error(source, name, errors, path)
    if body is None:
        return
    forbidden = ("load_acl_packet_ids_", "phase_policy_tc(", "ct_create_")
    qos = "phase_qos_ingress_tc(" if direction == "ingress" else "phase_qos_egress_tc("
    flow = "stats::update_flow_stats_v%s(" % ("4" if family == "v4" else "6")
    post = "phase_post_accept_tc_%s(" % direction
    monitoring_policy_hit = re.search(
        r"stats::monitoring_enabled\(p\.tap_id\)\s*&&\s*\(p\.flags\s*&\s*FLAG_POLICY_HIT\)\s*!=\s*0",
        body,
    )
    qos_at = body.find(qos)
    drop_guard = _drop_guard_after(body, qos)
    flow_at = body.find(flow)
    post_at = body.find(post)
    drop_returns = drop_guard is not None and "return;" in drop_guard[0]
    passed_order = (
        drop_guard is not None
        and qos_at >= 0
        and qos_at < drop_guard[1] < drop_guard[3] < flow_at < post_at
    )
    if (
        any(term in body for term in forbidden)
        or not monitoring_policy_hit
        or not drop_returns
        or not passed_order
    ):
        errors.append(
            "%s: cached hit must skip ACL/create, reapply QoS, and account only passed traffic"
            % path
        )


def check_miss_helper(source, errors, direction, family):
    name = "phase_ct_miss_tc_%s_%s" % (direction, family)
    path = "TC %s %s miss" % (direction, family)
    body = _body_or_error(source, name, errors, path)
    if body is None:
        return
    bits = "4" if family == "v4" else "6"
    qos = "phase_qos_ingress_tc(" if direction == "ingress" else "phase_qos_egress_tc("
    post = "phase_post_accept_tc_%s(" % direction
    tcp_rt = "tcprt::track_tcp_rt_v%s_auto(" % bits
    acl_load = "load_acl_packet_ids_v%s(" % bits
    policy = "phase_policy_tc("
    flow = "stats::update_flow_stats_v%s(" % bits
    create = "conntrack::ct_create_v%s(" % bits
    create_statement = (
        "conntrack::ct_create_v%s(ct_key, p.now, p.pkt_len, &matched);" % bits
    )
    ct_guard_marker = "if runtime::conntrack_enabled(p.tap_id)"

    acl_at = body.find(acl_load)
    policy_at = body.find(policy, acl_at + 1)
    acl_drop = _drop_guard_after(body, policy, acl_at + 1)
    qos_at = body.find(qos, acl_drop[3] + 1 if acl_drop else 0)
    qos_drop = _drop_guard_after(body, qos, qos_at if qos_at >= 0 else 0)
    flow_at = body.find(flow, qos_drop[3] + 1 if qos_drop else 0)
    post_at = body.find(post, flow_at + 1 if flow_at >= 0 else 0)
    tcp_rt_at = body.find(tcp_rt, post_at + 1 if post_at >= 0 else 0)
    ct_guard = _block_after(body, ct_guard_marker, tcp_rt_at + 1 if tcp_rt_at >= 0 else 0)

    drop_blocks_return = (
        acl_drop is not None
        and "return;" in acl_drop[0]
        and qos_drop is not None
        and "return;" in qos_drop[0]
    )
    ordered = (
        acl_drop is not None
        and qos_drop is not None
        and ct_guard is not None
        and 0 <= acl_at < policy_at < acl_drop[1] < acl_drop[3]
        and acl_drop[3] < qos_at < qos_drop[1] < qos_drop[3]
        and qos_drop[3] < flow_at < post_at < tcp_rt_at < ct_guard[1]
    )
    guarded_final_create = (
        ct_guard is not None
        and create_statement in ct_guard[0]
        and ct_guard[0].strip().endswith(create_statement)
        and body[ct_guard[3] + 1 :].strip() == ""
        and body.count(create) == 1
        and body.count("conntrack::ct_create_") == 1
    )
    if not drop_blocks_return or not ordered or not guarded_final_create:
        errors.append(
            "%s: require ACL drop -> QoS drop -> passed post-processing -> CT create last"
            % path
        )


def check_source(source):
    errors = []
    check_xdp(source, errors)
    for direction in ("ingress", "egress"):
        for family in ("v4", "v6"):
            check_live_path(source, errors, direction, family)
            check_hit_helper(source, errors, direction, family)
            check_miss_helper(source, errors, direction, family)
    for family in ("v4", "v6"):
        check_legacy_ingress(source, errors, family)
    return errors


def _mutate_function(source, name, mutate):
    start, end = function_body_span(source, name)
    body = source[start:end]
    mutated = mutate(body)
    if mutated == body:
        raise ValueError("mutation did not alter %s" % name)
    return source[:start] + mutated + source[end:]


def _move_xdp_feature_flags_before_bypass(body):
    feature = "    load_feature_flags_xdp(p, info);\n"
    anchor = "    load_runtime_ctx_xdp(ctx, p);\n"
    if body.count(feature) != 1 or body.count(anchor) != 1:
        raise ValueError("XDP feature-flag mutation anchors drifted")
    body = body.replace(feature, "", 1)
    return body.replace(anchor, anchor + feature, 1)


def _remove_drop_return_after(body, phase_marker, label):
    drop_guard = _drop_guard_after(body, phase_marker)
    if drop_guard is None or drop_guard[0].count("return;") != 1:
        raise ValueError("%s mutation anchor drifted" % label)
    mutated_block = drop_guard[0].replace("return;", "", 1)
    return body[: drop_guard[2] + 1] + mutated_block + body[drop_guard[3] :]


def _remove_egress_v4_hit_qos_return(body):
    return _remove_drop_return_after(
        body, "phase_qos_egress_tc(", "egress v4 hit QoS drop"
    )


def _remove_ingress_v4_miss_acl_return(body):
    return _remove_drop_return_after(
        body, "phase_policy_tc(", "ingress v4 miss ACL drop"
    )


def _remove_ingress_v4_miss_qos_return(body):
    return _remove_drop_return_after(
        body, "phase_qos_ingress_tc(", "ingress v4 miss QoS drop"
    )


def _remove_egress_v4_miss_ct_guard(body):
    guard = _block_after(body, "if runtime::conntrack_enabled(p.tap_id)")
    if guard is None:
        raise ValueError("egress v4 miss CT-guard mutation anchor drifted")
    return body[: guard[1]] + guard[0] + body[guard[3] + 1 :]


def run_mutation_self_tests(source, verbose=False):
    specs = [
        (
            "XDP feature flags before TC bypass",
            "try_xdp_firewall",
            _move_xdp_feature_flags_before_bypass,
            "XDP:",
        ),
        (
            "egress v4 hit QoS drop without return",
            "phase_ct_fastpath_tc_egress_v4",
            _remove_egress_v4_hit_qos_return,
            "TC egress v4 hit:",
        ),
        (
            "ingress v4 miss ACL drop without return",
            "phase_ct_miss_tc_ingress_v4",
            _remove_ingress_v4_miss_acl_return,
            "TC ingress v4 miss:",
        ),
        (
            "ingress v4 miss QoS drop without return",
            "phase_ct_miss_tc_ingress_v4",
            _remove_ingress_v4_miss_qos_return,
            "TC ingress v4 miss:",
        ),
        (
            "egress v4 miss CT create without runtime guard",
            "phase_ct_miss_tc_egress_v4",
            _remove_egress_v4_miss_ct_guard,
            "TC egress v4 miss:",
        ),
    ]
    failures = []
    for label, function, mutate, expected_prefix in specs:
        try:
            mutant = _mutate_function(source, function, mutate)
        except (KeyError, ValueError) as exc:
            failures.append("mutation %s could not run (%s)" % (label, exc))
            continue
        mutant_errors = check_source(mutant)
        matching = [error for error in mutant_errors if error.startswith(expected_prefix)]
        if not matching:
            failures.append("mutation %s was accepted" % label)
        elif verbose:
            print("PASS: rejected mutation %s" % label)
    return failures


def main():
    args = sys.argv[1:]
    if any(arg != "--self-test" for arg in args):
        print("usage: %s [--self-test]" % sys.argv[0])
        return 2
    verbose_mutations = "--self-test" in args
    with open(EBPF_LIB, "r", encoding="utf-8") as handle:
        source = handle.read()

    errors = check_source(source)
    if not errors:
        errors.extend(run_mutation_self_tests(source, verbose=verbose_mutations))

    if errors:
        for error in errors:
            print("ERROR: %s" % error)
        return 1
    print("TC ACL datapath source contracts and mutation self-tests: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
