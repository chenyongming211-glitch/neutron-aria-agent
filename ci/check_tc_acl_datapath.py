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
            elif char == "'" and nxt and nxt != "s":
                # Target functions have no lifetime parameters.  This still
                # handles ordinary Rust character literals without allowing a
                # brace inside one to affect the function boundary.
                state = "char"
            elif char == "{":
                depth += 1
            elif char == "}":
                depth -= 1
                if depth == 0:
                    return index
        index += 1
    raise ValueError("unbalanced Rust function body")


def function_body(source, name):
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
    return source[opening + 1 : closing]


def _body_or_error(source, name, errors, path):
    try:
        return function_body(source, name)
    except (KeyError, ValueError) as exc:
        errors.append("%s: missing extractable helper %s (%s)" % (path, name, exc))
        return None


def _contains_in_order(body, markers):
    cursor = -1
    for marker in markers:
        cursor = body.find(marker, cursor + 1)
        if cursor < 0:
            return False
    return True


def check_xdp(source, errors):
    body = _body_or_error(source, "try_xdp_firewall", errors, "XDP")
    if body is None:
        return
    hook = body.find("runtime::acl_ingress_hook(p.tap_id) == ACL_INGRESS_HOOK_TC")
    forbidden = [
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
    pass_after_hook = body.find("return Ok(XDP_PASS)", hook + 1) if hook >= 0 else -1
    if hook < 0 or pass_after_hook < 0 or (first_acl_ct >= 0 and hook > first_acl_ct):
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
    if direction == "ingress":
        required.extend(
            [
                "runtime::acl_ingress_hook(p.tap_id) == ACL_INGRESS_HOOK_TC",
                "phase_ct_fastpath_tc_ingress_%s(" % family,
                "phase_ct_miss_tc_ingress_%s(" % family,
                "phase_legacy_tc_ingress_%s(" % family,
            ]
        )
    else:
        required.extend(
            [
                "phase_ct_fastpath_tc_egress_%s(" % family,
                "phase_ct_miss_tc_egress_%s(" % family,
            ]
        )
    if any(term not in body for term in required) or "ct_state >= 2" in body:
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
    required = ("FLAG_POLICY_HIT", "stats::monitoring_enabled", qos, flow, post)
    if any(term in body for term in forbidden) or any(term not in body for term in required):
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
    markers = [
        "load_acl_packet_ids_v%s(" % bits,
        "phase_policy_tc(",
        "TC_ACT_SHOT",
        qos,
        "TC_ACT_SHOT",
        "stats::update_flow_stats_v%s(" % bits,
        post,
        tcp_rt,
        "conntrack::ct_create_v%s(" % bits,
    ]
    if not _contains_in_order(body, markers):
        errors.append(
            "%s: require ACL drop -> QoS drop -> passed post-processing -> CT create last"
            % path
        )


def main():
    with open(EBPF_LIB, "r", encoding="utf-8") as handle:
        source = handle.read()

    errors = []
    check_xdp(source, errors)
    for direction in ("ingress", "egress"):
        for family in ("v4", "v6"):
            check_live_path(source, errors, direction, family)
            check_hit_helper(source, errors, direction, family)
            check_miss_helper(source, errors, direction, family)
    for family in ("v4", "v6"):
        check_legacy_ingress(source, errors, family)

    if errors:
        for error in errors:
            print("ERROR: %s" % error)
        return 1
    print("TC ACL datapath source contracts: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
