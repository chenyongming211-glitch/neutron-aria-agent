#!/usr/bin/env python3
"""Static contracts for the TC-unified ACL/conntrack datapath.

The checks intentionally inspect individual Rust function bodies.  Keeping the
extractor here avoids accepting a marker that happens to exist elsewhere in
the eBPF source while a live packet path remains unwired.
"""

from __future__ import print_function

from functools import lru_cache
import os
import re
import sys


ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir))
EBPF_LIB = os.path.join(ROOT, "ebpf", "src", "lib.rs")
MANAGED_SMOKE = os.path.join(
    ROOT, "deploy", "kolla", "smoke", "neutron_aria_acl_tc_datapath_smoke.sh"
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
    code = _blank_non_code(source)
    pattern = re.compile(
        r"(?:^|\n)\s*(?:pub\s+)?(?:unsafe\s+)?fn\s+%s\s*\(" % re.escape(name)
    )
    match = pattern.search(code)
    if not match:
        raise KeyError(name)
    opening = code.find("{", match.end())
    if opening < 0:
        raise ValueError("function %s has no body" % name)
    closing = _matching_brace(code, opening)
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


@lru_cache(maxsize=32)
def _blank_non_code(text):
    """Blank Rust comments and literals while preserving code and newlines."""
    output = []
    index = 0
    while index < len(text):
        if text.startswith("//", index):
            end = text.find("\n", index + 2)
            if end < 0:
                output.extend(" " for _ in text[index:])
                break
            output.extend(" " for _ in text[index:end])
            output.append("\n")
            index = end + 1
            continue

        if text.startswith("/*", index):
            depth = 1
            end = index + 2
            while end < len(text) and depth:
                if text.startswith("/*", end):
                    depth += 1
                    end += 2
                elif text.startswith("*/", end):
                    depth -= 1
                    end += 2
                else:
                    end += 1
            output.extend("\n" if char == "\n" else " " for char in text[index:end])
            index = end
            continue

        raw = re.match(r'(?:b|c)?r(?P<hashes>#{0,32})"', text[index:])
        if raw:
            delimiter = '"' + raw.group("hashes")
            content_start = index + raw.end()
            close = text.find(delimiter, content_start)
            end = len(text) if close < 0 else close + len(delimiter)
            output.extend("\n" if char == "\n" else " " for char in text[index:end])
            index = end
            continue

        if text[index] == '"':
            end = index + 1
            while end < len(text):
                if text[end] == "\\":
                    end += 2
                    continue
                end += 1
                if text[end - 1] == '"':
                    break
            output.extend("\n" if char == "\n" else " " for char in text[index:end])
            index = end
            continue

        char_literal = re.match(r"'(?:\\.|[^\\'\n])'", text[index:])
        if char_literal:
            end = index + char_literal.end()
            output.extend(" " for _ in text[index:end])
            index = end
            continue

        output.append(text[index])
        index += 1
    return "".join(output)


RUST_TOKEN = re.compile(
    r"r#[A-Za-z_][A-Za-z0-9_]*|[A-Za-z_][A-Za-z0-9_]*|[0-9]+|"
    r"::|->|=>|==|!=|<=|>=|&&|\|\||<<|>>|\.\.=|\.\.|"
    r"[{}()\[\];,.&*=:<>!+\-/|]|\S"
)


def _rust_tokens(text):
    return RUST_TOKEN.findall(_blank_non_code(text))


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
    prefix = "let p = &mut *pipe; p.action = XDP_PASS;"
    permitted = (
        _rust_tokens(prefix + " return Ok(XDP_PASS);"),
        _rust_tokens(prefix + " Ok(XDP_PASS)"),
    )
    if _rust_tokens(body) not in permitted:
        errors.append("XDP: all runtime modes must return PASS without ACL/CT work")


def _tc_wrapper_tokens(direction, family, explicit_return=False):
    bits = "4" if family == "v4" else "6"
    ip_fields = (
        "src_ip: info.src_ip, dst_ip: info.dst_ip,"
        if family == "v4"
        else "src_ip: info.src_ip_v6, dst_ip: info.dst_ip_v6,"
    )
    tail = "return p.action as i32;" if explicit_return else "p.action as i32"
    return _rust_tokens(
        """
        let ct_key = CtKey%s {
            tap_id: p.tap_id,
            %s
            src_port: info.src_port,
            dst_port: info.dst_port,
            proto: info.proto,
            pad: [0; 3],
        };
        let miss_reason = phase_ct_v%s(info, p, &ct_key);
        if (p.flags & FLAG_CT_HIT) != 0 {
            phase_ct_fastpath_tc_%s_%s(ctx, info, p, &ct_key);
        } else {
            phase_ct_miss_tc_%s_%s(ctx, info, p, &ct_key, miss_reason);
        }
        %s
        """
        % (bits, ip_fields, bits, direction, family, direction, family, tail)
    )


def check_live_path(source, errors, direction, family):
    wrapper = "try_tc_%s_%s" % (direction, family)
    body = _body_or_error(source, wrapper, errors, "TC %s %s" % (direction, family))
    if body is None:
        return
    # The current ACL-only artifact resolves fragments before the CT/policy
    # branch and owns CT creation after fragment-context installation.  Its
    # wrapper is intentionally no longer the old exact CT-only shape.
    if "fragment::resolve_v%s" % ("4" if family == "v4" else "6") in body:
        required = (
            "CT_KEY%s_SCRATCH" % ("4" if family == "v4" else "6"),
            "phase_ct_v%s(" % ("4" if family == "v4" else "6"),
            "phase_ct_fastpath_tc_%s_%s(" % (direction, family),
            "phase_ct_miss_tc_%s_%s(" % (direction, family),
            "fragment::install_allowed_v%s(" % ("4" if family == "v4" else "6"),
        )
        ct_branch = re.search(
            r"let\s+create_point\s*=\s*fragment_ct_create_point\(info\.fragment_kind\);"
            r"\s*if\s+ct_hit\s*\{\s*phase_ct_fastpath_tc_%s_%s\("
            r".*?\}\s*else\s*\{\s*phase_ct_miss_tc_%s_%s\(" % (
                re.escape(direction), re.escape(family),
                re.escape(direction), re.escape(family),
            ),
            body,
            re.DOTALL,
        )
        if (any(term not in body for term in required)
                or body.count("phase_ct_v%s(" % ("4" if family == "v4" else "6")) != 1
                or ct_branch is None):
            errors.append(
                "TC %s %s: require fragment-aware CT hit/miss branch after resolution and before context install"
                % (direction, family)
            )
        return
    permitted = (
        _tc_wrapper_tokens(direction, family),
        _tc_wrapper_tokens(direction, family, explicit_return=True),
    )
    if _rust_tokens(body) not in permitted:
        errors.append(
            "TC %s %s: require exactly one family CT lookup and one mutually exclusive FLAG_CT_HIT hit/miss branch"
            % (direction, family)
        )


def check_hit_helper(source, errors, direction, family):
    name = "phase_ct_fastpath_tc_%s_%s" % (direction, family)
    path = "TC %s %s hit" % (direction, family)
    body = _body_or_error(source, name, errors, path)
    if body is None:
        return
    body = _blank_non_code(body)
    if "record_tc_ct_contract" in body:
        if any(term in body for term in ("load_acl_packet_ids_", "phase_policy_tc_v", "ct_create_")):
            errors.append("%s: cached hit must not re-evaluate ACL or create CT" % path)
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
    body = _blank_non_code(body)
    if "record_tc_ct_contract" in body:
        policy = "phase_policy_tc_v%s(" % ("4" if family == "v4" else "6")
        qos = "phase_qos_ingress_tc(" if direction == "ingress" else "phase_qos_egress_tc("
        if policy not in body or qos not in body or "ct_create_" in body:
            errors.append("%s: miss must evaluate family policy and QoS without early CT creation" % path)
        return
    bits = "4" if family == "v4" else "6"
    qos = "phase_qos_ingress_tc(" if direction == "ingress" else "phase_qos_egress_tc("
    post = "phase_post_accept_tc_%s(" % direction
    tcp_rt = "tcprt::track_tcp_rt_v%s_auto(" % bits
    acl_load = "load_acl_packet_ids_v%s(" % bits
    policy = "phase_policy_tc("
    flow = "stats::update_flow_stats_v%s(" % bits
    create = "conntrack::ct_create_v%s(" % bits
    create_tokens = _rust_tokens(
        "conntrack::ct_create_v%s("
        "ct_key, p.now, p.pkt_len, &matched, (p.flags & FLAG_ACL_ON) != 0,);" % bits
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
    ct_guard_tokens = _rust_tokens(ct_guard[0]) if ct_guard is not None else []
    guarded_final_create = (
        ct_guard is not None
        and ct_guard_tokens[-len(create_tokens) :] == create_tokens
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
    code = _blank_non_code(source)
    for family in ("v4", "v6"):
        legacy = "phase_legacy_tc_ingress_%s" % family
        if re.search(r"\bfn\s+%s\s*\(" % re.escape(legacy), code):
            errors.append("TC ingress %s: legacy helper must be removed" % family)
    return errors


def check_managed_smoke_entrypoint(errors):
    """Validate only the public field-smoke record shape, never traffic."""
    try:
        with open(MANAGED_SMOKE, encoding="utf-8") as handle:
            source = handle.read()
    except OSError as exc:
        errors.append("managed smoke: cannot read entrypoint (%s)" % exc)
        return
    required = (
        "record_field_case()", "run_dual_stack_field_smoke()",
        "zero managed ports is a field failure", "FIELD_DUAL_STACK_SMOKE",
        "FIELD_EVIDENCE_STATUS=\"${FIELD_EVIDENCE_STATUS:-deferred/pending}\"",
    ) + FIELD_CASES + FIELD_EVIDENCE_FIELDS
    missing = [term for term in required if term not in source]
    if missing:
        errors.append(
            "managed smoke: missing static case/evidence contract %s"
            % ", ".join(missing)
        )


def _mutate_function(source, name, mutate):
    start, end = function_body_span(source, name)
    body = source[start:end]
    mutated = mutate(body)
    if mutated == body:
        raise ValueError("mutation did not alter %s" % name)
    return source[:start] + mutated + source[end:]


def _insert_before_match(body, pattern, code, label):
    match = re.search(pattern, body, re.MULTILINE)
    if not match:
        raise ValueError("%s mutation anchor drifted" % label)
    indent = match.groupdict().get("indent", "")
    injected = "".join(
        indent + line + "\n" if line else "\n" for line in code.splitlines()
    )
    return body[: match.start()] + injected + body[match.start() :]


def _insert_before_xdp_pass(body, code, label):
    return _insert_before_match(
        body,
        r"^(?P<indent>[ \t]*)p\s*\.\s*action\s*=\s*XDP_PASS\s*;",
        code,
        label,
    )


def _inject_xdp_runtime_acl_read(body):
    return _insert_before_xdp_pass(
        body,
        "let _acl_enabled = runtime::acl_enabled(p.tap_id);",
        "XDP runtime ACL read",
    )


def _inject_xdp_ct_lookup(body):
    return _insert_before_xdp_pass(
        body,
        """let info = &*_info;
let ct_key = CtKey4
{
    tap_id: p.tap_id,
    src_ip: info.src_ip,
    dst_ip: info.dst_ip,
    src_port: info.src_port,
    dst_port: info.dst_port,
    proto: info.proto,
    pad: [0; 3],
};
let _ct_result = conntrack::ct_lookup_v4(&ct_key, p.now, p.pkt_len, 0, 0);""",
        "XDP CT lookup",
    )


def _inject_xdp_alternate_drop(body):
    return _insert_before_xdp_pass(
        body,
        """if p.tap_id == TAP_ID_UNASSIGNED {
    return Ok(1);
}""",
        "XDP alternate drop",
    )


def _format_xdp_pass_only(_body):
    return """
    /* runtime::acl_ingress_hook(p.tap_id) is forbidden code, not a comment. */
        let p = & mut * pipe ;
    // conntrack::ct_lookup_v4 must not execute here.
    p . action = XDP_PASS ;
    Ok ( XDP_PASS )
"""


def _insert_before_ingress_v4_tail(body, code, label):
    return _insert_before_match(
        body,
        r"^(?P<indent>[ \t]*)p\s*\.\s*action\s+as\s+i32\b",
        code,
        label,
    )


def _duplicate_ingress_v4_lookup(body):
    pattern = re.compile(
        r"^(?P<indent>[ \t]*)let\s+miss_reason\s*=\s*"
        r"phase_ct_v4\s*\([^;]*\)\s*;",
        re.MULTILINE,
    )
    match = pattern.search(body)
    if not match:
        raise ValueError("ingress v4 CT lookup mutation anchor drifted")
    duplicate = (
        "\n%slet _duplicate_miss_reason = phase_ct_v4(info, p, &ct_key);"
        % match.group("indent")
    )
    return body[: match.end()] + duplicate + body[match.end() :]


def _inject_ingress_v4_unconditional_hit(body):
    return _insert_before_ingress_v4_tail(
        body,
        "phase_ct_fastpath_tc_ingress_v4(ctx, info, p, &ct_key);",
        "ingress v4 unconditional hit",
    )


def _inject_ingress_v4_both_helpers_in_hit_arm(body):
    pattern = re.compile(
        r"^(?P<indent>[ \t]*)phase_ct_fastpath_tc_ingress_v4\s*"
        r"\(\s*ctx\s*,\s*info\s*,\s*p\s*,\s*&\s*ct_key\s*\)\s*;",
        re.MULTILINE,
    )
    match = pattern.search(body)
    if not match:
        raise ValueError("ingress v4 hit-arm mutation anchor drifted")
    miss = (
        "\n%sphase_ct_miss_tc_ingress_v4(ctx, info, p, &ct_key, miss_reason);"
        % match.group("indent")
    )
    return body[: match.end()] + miss + body[match.end() :]


def _duplicate_ingress_v4_hit_miss_branch(body):
    return _insert_before_ingress_v4_tail(
        body,
        """if (p.flags & FLAG_CT_HIT) != 0 {
    phase_ct_fastpath_tc_ingress_v4(ctx, info, p, &ct_key);
} else {
    phase_ct_miss_tc_ingress_v4(ctx, info, p, &ct_key, miss_reason);
}""",
        "ingress v4 duplicate hit/miss branch",
    )


def _inject_ingress_v4_selector(body):
    return _insert_before_ingress_v4_tail(
        body,
        "let _selector = runtime::acl_ingress_hook(p.tap_id);",
        "ingress v4 selector",
    )


def _inject_ingress_v4_legacy_call(body):
    return _insert_before_ingress_v4_tail(
        body,
        "phase_legacy_tc_ingress_v4(ctx, info, p, &ct_key);",
        "ingress v4 legacy call",
    )


def _format_ingress_v4(_body):
    return """
    // runtime::acl_ingress_hook(p.tap_id) is intentionally absent.
    let ct_key = CtKey4
    {
        tap_id : p . tap_id,
        src_ip : info . src_ip,
        dst_ip : info . dst_ip,
        src_port : info . src_port,
        dst_port : info . dst_port,
        proto : info . proto,
        pad : [ 0 ; 3 ],
    };
    let miss_reason=phase_ct_v4 ( info,p,& ct_key ) ;
    if(p.flags&FLAG_CT_HIT)!=0
    {
        phase_ct_fastpath_tc_ingress_v4 ( ctx, info, p, & ct_key ) ;
    }
    else
    {
        phase_ct_miss_tc_ingress_v4 ( ctx, info, p, & ct_key, miss_reason ) ;
    }
    p.action as i32
"""


def _add_legacy_helper_comment(source):
    return source + "\n/* fn phase_legacy_tc_ingress_v4() is forbidden. */\n"


def _add_fake_xdp_function_comment(source):
    return (
        """/*
fn try_xdp_firewall() {
    return Ok(1);
}
*/
"""
        + source
    )


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


def _replace_fragment_ct_hit_guard(body):
    return body.replace(
        "let create_point = fragment_ct_create_point(info.fragment_kind);\n    if ct_hit {",
        "let create_point = fragment_ct_create_point(info.fragment_kind);\n    if true {",
        1,
    )


def _remove_fragment_context_install(body):
    return body.replace(
        "let install = fragment::install_allowed_v4(info, p);",
        "let install = FragmentInstallDecision::Pass;",
        1,
    )


def _remove_fragment_miss_branch(body):
    return body.replace(
        "phase_ct_miss_tc_ingress_v4(ctx, info, p, miss_reason);",
        "phase_ct_fastpath_tc_ingress_v4(ctx, info, p, ct_key);",
        1,
    )


def run_mutation_self_tests(source, verbose=False):
    if "fragment::resolve_v4" in source:
        specs = (
            ("fragment-aware CT hit guard", "try_tc_ingress_v4", _replace_fragment_ct_hit_guard),
            ("fragment context install", "try_tc_ingress_v4", _remove_fragment_context_install),
            ("fragment-aware miss branch", "try_tc_ingress_v4", _remove_fragment_miss_branch),
        )
        failures = []
        for label, function, mutate in specs:
            mutant = _mutate_function(source, function, mutate)
            if not any(error.startswith("TC ingress v4:") for error in check_source(mutant)):
                failures.append("mutation %s was accepted" % label)
            elif verbose:
                print("PASS: rejected mutation %s" % label)
        return failures
    specs = [
        (
            "XDP direct runtime ACL read",
            "try_xdp_firewall",
            _inject_xdp_runtime_acl_read,
            "XDP:",
        ),
        (
            "XDP CT lookup",
            "try_xdp_firewall",
            _inject_xdp_ct_lookup,
            "XDP:",
        ),
        (
            "XDP alternate drop return",
            "try_xdp_firewall",
            _inject_xdp_alternate_drop,
            "XDP:",
        ),
        (
            "ingress v4 duplicate CT lookup",
            "try_tc_ingress_v4",
            _duplicate_ingress_v4_lookup,
            "TC ingress v4:",
        ),
        (
            "ingress v4 unconditional hit helper",
            "try_tc_ingress_v4",
            _inject_ingress_v4_unconditional_hit,
            "TC ingress v4:",
        ),
        (
            "ingress v4 both helpers in hit arm",
            "try_tc_ingress_v4",
            _inject_ingress_v4_both_helpers_in_hit_arm,
            "TC ingress v4:",
        ),
        (
            "ingress v4 duplicate FLAG_CT_HIT branch",
            "try_tc_ingress_v4",
            _duplicate_ingress_v4_hit_miss_branch,
            "TC ingress v4:",
        ),
        (
            "ingress v4 selector reintroduction",
            "try_tc_ingress_v4",
            _inject_ingress_v4_selector,
            "TC ingress v4:",
        ),
        (
            "ingress v4 legacy helper reintroduction",
            "try_tc_ingress_v4",
            _inject_ingress_v4_legacy_call,
            "TC ingress v4:",
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

    accepted_specs = [
        (
            "XDP comments, whitespace, and tail expression",
            "try_xdp_firewall",
            _format_xdp_pass_only,
        ),
        (
            "ingress v4 comments and whitespace",
            "try_tc_ingress_v4",
            _format_ingress_v4,
        ),
    ]
    for label, function, mutate in accepted_specs:
        try:
            mutant = _mutate_function(source, function, mutate)
        except (KeyError, ValueError) as exc:
            failures.append("harmless mutation %s could not run (%s)" % (label, exc))
            continue
        mutant_errors = check_source(mutant)
        if mutant_errors:
            failures.append(
                "harmless mutation %s was rejected (%s)"
                % (label, "; ".join(mutant_errors))
            )
        elif verbose:
            print("PASS: accepted harmless mutation %s" % label)

    accepted_source_specs = [
        ("legacy-helper comment", _add_legacy_helper_comment),
        ("commented fake XDP function", _add_fake_xdp_function_comment),
    ]
    for label, mutate in accepted_source_specs:
        harmless_source = mutate(source)
        harmless_errors = check_source(harmless_source)
        if harmless_errors:
            failures.append(
                "harmless mutation %s was rejected (%s)"
                % (label, "; ".join(harmless_errors))
            )
        elif verbose:
            print("PASS: accepted harmless mutation %s" % label)

    if verbose:
        print(
            "Mutation scenarios: %d rejection, %d acceptance"
            % (len(specs), len(accepted_specs) + len(accepted_source_specs))
        )
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
    check_managed_smoke_entrypoint(errors)
    if not errors:
        errors.extend(run_mutation_self_tests(source, verbose=verbose_mutations))

    if errors:
        for error in errors:
            print("ERROR: %s" % error)
        return 1
    print("TC ACL datapath source and managed-smoke structure contracts: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
