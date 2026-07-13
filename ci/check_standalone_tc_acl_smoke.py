#!/usr/bin/env python3
"""Structure and mutation contracts for the guarded standalone TC ACL smoke."""

from __future__ import print_function

import os
import re
import sys


ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir))
SMOKE = os.path.join(
    ROOT, "deploy", "smoke", "aria_standalone_acl_tc_datapath_smoke.sh"
)

REQUIRED_FUNCTIONS = (
    "cleanup",
    "write_summary",
    "derive_fixture_identity",
    "select_http_addr",
    "preflight_fixture",
    "create_netns_fixture",
    "start_agent",
    "stop_agent_bounded",
    "start_system_mode",
    "start_tap_mode",
    "capture_links",
    "capture_acl_counters",
    "set_trace_filter",
    "clear_trace_filter",
    "run_allowed_flow",
    "run_observed_allowed_flow",
    "run_denied_flow",
    "assert_xdp_neutral",
    "assert_dual_tc_ready",
    "assert_missing_tc_rejected",
    "assert_health_poll_degrades",
    "assert_recovery_verified",
)

REQUIRED_MARKERS = (
    'MODE="${MODE:-system}"',
    ': "${ARIA_AGENT_BIN:?ARIA_AGENT_BIN is required}"',
    ': "${EBPF_OBJECT:?EBPF_OBJECT is required}"',
    'TC_HEALTH_WAIT_SECS="${TC_HEALTH_WAIT_SECS:-12}"',
    'AGENT_STOP_TIMEOUT_SECS="${AGENT_STOP_TIMEOUT_SECS:-5}"',
    "ip netns add",
    "tc_ingress_link",
    "tc_egress_link",
    '"acl_ready"',
    '"xdp_ready"',
    "summary.json",
    "trap cleanup EXIT",
    "NETNS_CREATED=false",
    "VETH_CREATED=false",
    "PIN_ROOT_CREATED=false",
    "PRIVATE_BPFFS_MOUNTED=false",
    "RECOVERY_VERIFIED=false",
)


def _shell_code(line):
    """Blank shell strings/comments so braces in JSON and ${...} do not count."""
    output = []
    index = 0
    quote = None
    while index < len(line):
        char = line[index]
        if quote is not None:
            if quote == '"' and char == "\\":
                output.extend((" ", " "))
                index += 2
                continue
            if char == quote:
                quote = None
            output.append(" ")
            index += 1
            continue
        if char in ("'", '"'):
            quote = char
            output.append(" ")
            index += 1
            continue
        if char == "#" and (index == 0 or line[index - 1].isspace()):
            output.extend(" " for _ in line[index:])
            break
        output.append(char)
        index += 1
    return "".join(output)


def function_body(source, name):
    """Extract a shell function while honoring nested braces and heredocs."""
    lines = source.splitlines()
    start = None
    depth = 0
    heredoc = None
    pattern = re.compile(r"^\s*%s\(\)\s*\{" % re.escape(name))
    for index, line in enumerate(lines):
        if pattern.match(line):
            start = index
            depth = _shell_code(line).count("{") - _shell_code(line).count("}")
            break
    if start is None:
        raise KeyError(name)
    for index in range(start + 1, len(lines)):
        line = lines[index]
        if heredoc is not None:
            if line.strip() == heredoc:
                heredoc = None
            continue
        code = _shell_code(line)
        match = re.search(r"<<-?\s*['\"]?([A-Za-z_][A-Za-z0-9_]*)['\"]?", line)
        if match:
            heredoc = match.group(1)
        depth += code.count("{") - code.count("}")
        if depth == 0:
            return "\n".join(lines[start + 1:index])
    raise ValueError("unterminated shell function %s" % name)


def ordered(body, terms):
    position = -1
    for term in terms:
        position = body.find(term, position + 1)
        if position < 0:
            return False
    return True


def _parser_self_test_errors():
    fixture = r'''nested() {
    if true; then
        printf '%s\n' "${value:-{\"nested\":true}}"
        command || { echo "fallback"; return 1; }
    fi
    python3 <<'PY'
payload={"looks": "like a }"}
PY
    final_call
}
after() { :; }
'''
    errors = []
    try:
        body = function_body(fixture, "nested")
    except (KeyError, ValueError) as exc:
        return ["brace-aware parser rejected nested fixture: %s" % exc]
    if "final_call" not in body or "after()" in body:
        errors.append("brace-aware parser truncated or overran nested fixture")
    try:
        function_body("# hidden() { }", "hidden")
    except KeyError:
        pass
    else:
        errors.append("brace-aware parser accepted comment-only function")
    return errors


def check_source(source):
    errors = []
    bodies = {}
    for name in REQUIRED_FUNCTIONS:
        try:
            bodies[name] = function_body(source, name)
        except (KeyError, ValueError) as exc:
            errors.append("missing structured standalone smoke helper %s (%s)" % (name, exc))
    for marker in REQUIRED_MARKERS:
        if marker not in source:
            errors.append("standalone TC ACL smoke missing marker %s" % marker)
    if errors:
        return errors

    guard_terms = (
        ': "${ARIA_AGENT_BIN:?ARIA_AGENT_BIN is required}"',
        ': "${EBPF_OBJECT:?EBPF_OBJECT is required}"',
        'case "${MODE}" in system|tap)',
        '[ "${EUID}" -eq 0 ]',
    )
    first_mutation = source.find('mkdir -p "${WORK_DIR}"')
    if first_mutation < 0:
        errors.append("standalone smoke must create its work directory after hard guards")
    else:
        for term in guard_terms:
            position = source.find(term)
            if position < 0 or position > first_mutation:
                errors.append("hard guard must precede first mutation: %s" % term)

    identity = bodies["derive_fixture_identity"]
    for term in (
        "secrets.token_hex(5)",
        'HOST_IF="ah${FIXTURE_TOKEN}"',
        'PEER_IF="ap${FIXTURE_TOKEN}"',
        'NETNS="aria-tc-${FIXTURE_TOKEN}"',
    ):
        if term not in identity:
            errors.append("collision-resistant fixture identity missing %s" % term)

    port = bodies["select_http_addr"]
    for term in (
        'if [ -z "${HTTP_ADDR}" ]',
        'sock.bind(("127.0.0.1",0))',
        'HTTP="http://${HTTP_ADDR}"',
    ):
        if term not in port:
            errors.append("collision-resistant loopback port selection missing %s" % term)

    preflight = bodies["preflight_fixture"]
    for term in (
        '[ "${#HOST_IF}" -le 15 ]',
        '[ "${#PEER_IF}" -le 15 ]',
        '[ ! -e "${WORK_DIR}" ]',
        'grep -Fx "${NETNS}"',
        'ip link show dev "${HOST_IF}"',
        'ip link show dev "${PEER_IF}"',
        'sock.bind((host,port))',
    ):
        if term not in preflight:
            errors.append("fail-closed fixture preflight missing %s" % term)

    fixture = bodies["create_netns_fixture"]
    for term in (
        'ip netns add "${NETNS}"',
        'ip link add "${HOST_IF}" type veth peer name "${PEER_IF}"',
        'ip link set "${PEER_IF}" netns "${NETNS}"',
        'ip netns exec "${NETNS}"',
    ):
        if term not in fixture:
            errors.append("disposable netns fixture missing %s" % term)
    for term in (
        "NETNS_CREATED=true",
        "VETH_CREATED=true",
    ):
        if term not in fixture:
            errors.append("fixture ownership tracking missing %s" % term)
    if re.search(r"\b(eth|ens|eno|bond|br-ex)[0-9A-Za-z_.:-]*\b", fixture):
        errors.append("standalone smoke must not target a production-style host interface")

    start = bodies["start_agent"]
    for term in (
        'mode = "standalone"',
        "auto_attach = ${auto_attach}",
        'ebpf_path = "${EBPF_OBJECT}"',
        'pin_path = "${PIN_ROOT}"',
        'state_path = "${STATE_ROOT}"',
        'iface_pattern = "^${HOST_IF}$"',
        'listen_addr = "${HTTP_ADDR}"',
        'trace_backend = "legacy-map"',
        '"${ARIA_AGENT_BIN}" --config "${CONFIG_FILE}"',
    ):
        if term not in start:
            errors.append("scoped standalone agent config missing %s" % term)
    for term in (
        '[ ! -e "${PIN_ROOT}" ]',
        "PIN_ROOT_CREATED=true",
        "PRIVATE_BPFFS_MOUNTED=true",
    ):
        if term not in start:
            errors.append("private bpffs ownership tracking missing %s" % term)

    stop = bodies["stop_agent_bounded"]
    for term in (
        'sleep "${AGENT_STOP_TIMEOUT_SECS}"',
        'kill -KILL "${pid}"',
        'wait "${pid}"',
        "timed_out=true",
    ):
        if term not in stop:
            errors.append("bounded agent shutdown missing %s" % term)

    if '/api/v1/system/start' not in bodies["start_system_mode"]:
        errors.append("system standalone smoke must use /api/v1/system/start")
    if 'INSTANCE="${HOST_IF}"' not in bodies["start_tap_mode"]:
        errors.append("tap standalone smoke must wait for its fixture instance")

    links = bodies["capture_links"]
    for term in (
        '"${TC_INGRESS_LINK}"',
        '"${TC_EGRESS_LINK}"',
        'tc -j filter show dev "${HOST_IF}" ingress',
        'tc -j filter show dev "${HOST_IF}" egress',
        'bpftool -j net show',
    ):
        if term not in links:
            errors.append("dual-TC live evidence missing %s" % term)

    ready = bodies["assert_dual_tc_ready"]
    for term in (
        '[ -e "${TC_INGRESS_LINK}" ]',
        '[ -e "${TC_EGRESS_LINK}" ]',
        'item["acl_ready"] is True',
        'item["xdp_ready"] is True',
        '"tc_ingress"',
        '"tc_egress"',
        'ingress.get("prog_id")==ingress_prog.get("id")',
        'egress.get("prog_id")==egress_prog.get("id")',
    ):
        if term not in ready:
            errors.append("dual-TC readiness assertion missing %s" % term)

    capture = bodies["capture_acl_counters"]
    for term in (
        "/config",
        "/conntrack",
        "/stats/rules",
        "/metrics",
    ):
        if term not in capture:
            errors.append("ACL/CT counter capture missing %s" % term)

    trace = bodies["set_trace_filter"]
    for term in (
        "/trace/filter",
        '"proto":"icmp"',
        "TRACE_ARMED=true",
    ):
        if term not in trace:
            errors.append("controlled-flow trace arm missing %s" % term)
    clear_trace = bodies["clear_trace_filter"]
    if '-X DELETE "${HTTP}/api/v1/${INSTANCE}/trace/filter"' not in clear_trace:
        errors.append("controlled-flow trace disarm is missing")

    allowed = bodies["run_allowed_flow"]
    denied = bodies["run_denied_flow"]
    if 'ping -c "${ALLOWED_PACKETS}"' not in allowed:
        errors.append("allowed flow must use the exact controlled packet count")
    if 'DENIED_IP="10.203.0.6"' not in source:
        errors.append("denied flow must use a routable fixture-only /32 source")
    for term in (
        'ping -I "${DENIED_IP}" -c "${DENIED_PACKETS}"',
        'ping -I "${HOST_IF}" -c "${DENIED_PACKETS}"',
        "return 1",
    ):
        if term not in denied:
            errors.append("denied flow contract missing %s" % term)

    xdp = bodies["assert_xdp_neutral"]
    for term in (
        '${before}-conntrack.json',
        '${after}-conntrack.json',
        '${before}-rules.json',
        '${after}-rules.json',
        '${before}-metrics.prom',
        '${after}-metrics.prom',
        'row.get("packets")',
        'row.get("bytes")',
        'row.get("direction")',
        "expected_packets=packets*2",
        "expected_bytes=expected_packets*packet_bytes",
        'metric_delta("aria_ct_contract_packets_total","tc_ingress")',
        'metric_delta("aria_ct_contract_packets_total","tc_egress")',
        'metric_delta("aria_ct_contract_bytes_total","tc_ingress")',
        'metric_delta("aria_ct_contract_bytes_total","tc_egress")',
        "assert tc_ingress_packets==packets",
        "assert tc_egress_packets==packets",
        "assert tc_ingress_bytes==packets*packet_bytes",
        "assert tc_egress_bytes==packets*packet_bytes",
        "assert after_ct_packets-before_ct_packets==expected_packets",
        "assert after_ct_bytes-before_ct_bytes==expected_bytes",
        "assert ingress_delta==expected_packets",
        "assert egress_delta==0",
    ):
        if term not in xdp:
            errors.append("exact TC-only/XDP-neutral evidence missing %s" % term)
    for forbidden in (
        'labels.get("hook")=="xdp"',
        "unknown_hook",
        'hook not in ("tc_ingress","tc_egress")',
    ):
        if forbidden in xdp:
            errors.append("XDP neutrality must not be inferred from absent hook labels: %s" % forbidden)

    observed = bodies["run_observed_allowed_flow"]
    if not ordered(
        observed,
        (
            "set_trace_filter",
            'capture_acl_counters "${label}-before"',
            'run_allowed_flow "${label}"',
            'capture_acl_counters "${label}-after"',
            "clear_trace_filter",
            'assert_xdp_neutral "${label}-before" "${label}-after"',
        ),
    ):
        errors.append("allowed flow must be traced across exact before/after TC evidence")

    health = bodies["assert_health_poll_degrades"]
    for term in (
        'bpftool link detach pinned "${lost_link}"',
        '[ -e "${lost_link}" ]',
        'sleep "${TC_HEALTH_WAIT_SECS}"',
        'item["acl_ready"] is False',
        'item["xdp_ready"] is True',
        '"missing_tc_egress"',
        'config["acl"] is False',
        'config["conntrack"] is False',
    ):
        if term not in health:
            errors.append("detached-but-pinned TC health evidence missing %s" % term)
    if 'rm -f "${lost_link}"' in health:
        errors.append("health loss must detach the live TCX link while retaining its pin")

    rejected = bodies["assert_missing_tc_rejected"]
    for term in (
        "-X PUT",
        '"${code}" = 503',
        "not-ready",
    ):
        if term not in rejected:
            errors.append("missing-TC enable rejection missing %s" % term)

    recovery = bodies["assert_recovery_verified"]
    for term in (
        'config["acl"] is True',
        'config["conntrack"] is True',
        '"peer","host","denied"',
        "len(policies)==4",
        "run_observed_allowed_flow recovery-allowed",
        "run_denied_flow recovery-denied",
        "RECOVERY_VERIFIED=true",
    ):
        if term not in recovery:
            errors.append("post-restart full recovery proof missing %s" % term)

    if "exercise_legacy_zero_compatibility" not in source:
        errors.append("tap legacy-zero compatibility exercise is missing")
    else:
        try:
            legacy = function_body(source, "exercise_legacy_zero_compatibility")
        except (KeyError, ValueError) as exc:
            errors.append("missing structured legacy-zero helper (%s)" % exc)
        else:
            for term in (
                'v[7]=0',
                "len(value)==8",
                "value[7]==1",
                "assert_xdp_neutral legacy-zero-before legacy-zero-after",
                '-X PUT',
            ):
                if term not in legacy:
                    errors.append("tap legacy-zero compatibility missing %s" % term)

    cleanup = bodies["cleanup"]
    for term in (
        "trap - EXIT",
        'curl --fail-with-body -sS -X POST "${HTTP}/api/v1/system/stop"',
        "stop_agent_bounded",
        '[ "${PRIVATE_BPFFS_MOUNTED}" = true ]',
        'umount "${PIN_ROOT}"',
        '[ "${PIN_ROOT_CREATED}" = true ]',
        '[ "${VETH_CREATED}" = true ]',
        'ip netns del "${NETNS}"',
        'ip link del "${HOST_IF}"',
        '[ "${NETNS_CREATED}" = true ]',
        "verify_cleanup",
        "cleanup_errors",
        'RESULT="fail"',
        'RESULT="pass"',
        "write_summary",
    ):
        if term not in cleanup:
            errors.append("fail-closed cleanup missing %s" % term)
    if not ordered(
        cleanup,
        (
            "trap - EXIT",
            "stop_agent_bounded",
            'umount "${PIN_ROOT}"',
            'ip link del "${HOST_IF}"',
            'ip netns del "${NETNS}"',
            "verify_cleanup",
            'RESULT="fail"',
            'RESULT="pass"',
            "write_summary",
        ),
    ):
        errors.append("cleanup must verify rollback before selecting result and writing summary")

    summary = bodies["write_summary"]
    for term in (
        '"mode"',
        '"dual_tc_ready"',
        '"xdp_neutral"',
        '"missing_tc_rejected"',
        '"health_poll_degraded"',
        '"recovery_verified"',
        '"cleanup_errors"',
        '"result"',
        "summary.json.tmp",
        'mv "${WORK_DIR}/summary.json.tmp" "${WORK_DIR}/summary.json"',
    ):
        if term not in summary:
            errors.append("final standalone summary missing %s" % term)
    main_body = source.split("trap cleanup EXIT\n", 1)[-1]
    if "write_summary" in main_body or 'RESULT="pass"' in main_body:
        errors.append("main body must not write summary.json or select pass before cleanup")
    if not ordered(
        main_body,
        (
            "derive_fixture_identity",
            "select_http_addr",
            "preflight_fixture",
            'mkdir -p "${WORK_DIR}"',
            "run_observed_allowed_flow allowed",
            "exercise_legacy_zero_compatibility",
            "run_denied_flow",
            "assert_health_poll_degrades",
            "assert_missing_tc_rejected",
            "restore_runtime_after_tc_loss",
        ),
    ):
        errors.append("standalone smoke main body does not preserve the required evidence order")
    if "bpftool net detach" in source:
        errors.append("standalone smoke must use BPF link detach, not bpftool net detach")
    return errors


def mutate_remove(source, needle, label):
    if needle not in source:
        raise ValueError("mutation anchor missing: %s" % label)
    return source.replace(needle, "", 1)


def mutate_replace(source, needle, replacement, label):
    if needle not in source:
        raise ValueError("mutation anchor missing: %s" % label)
    return source.replace(needle, replacement, 1)


def mutate_remove_ingress_ready(source, _needle, _replacement, label):
    anchor = 'assert_dual_tc_ready() {\n    [ -e "${TC_INGRESS_LINK}" ]\n'
    if anchor not in source:
        raise ValueError("mutation anchor missing: %s" % label)
    return source.replace(anchor, "assert_dual_tc_ready() {\n", 1)


def mutate_remove_egress_ready(source, _needle, _replacement, label):
    anchor = '    [ -e "${TC_EGRESS_LINK}" ]\n    capture_links dual-tc-ready'
    if anchor not in source:
        raise ValueError("mutation anchor missing: %s" % label)
    return source.replace(anchor, "    capture_links dual-tc-ready", 1)


def run_mutation_self_tests(source, verbose=False):
    specs = (
        ("TC ingress pin assertion", mutate_remove_ingress_ready, "", "", "dual-TC readiness"),
        ("TC egress pin assertion", mutate_remove_egress_ready, "", "", "dual-TC readiness"),
        ("TC ingress live program identity", mutate_remove, 'ingress.get("prog_id")==ingress_prog.get("id")', "", "dual-TC readiness"),
        ("TC egress live program identity", mutate_remove, 'egress.get("prog_id")==egress_prog.get("id")', "", "dual-TC readiness"),
        ("unique fixture token", mutate_remove, "secrets.token_hex(5)", "", "fixture identity"),
        ("workdir collision preflight", mutate_remove, '[ ! -e "${WORK_DIR}" ]', "", "fixture preflight"),
        ("host interface ownership", mutate_remove, '[ "${VETH_CREATED}" = true ]', "", "fail-closed cleanup"),
        ("bpffs mount ownership", mutate_remove, '[ "${PRIVATE_BPFFS_MOUNTED}" = true ]', "", "fail-closed cleanup"),
        ("TC ingress packet evidence", mutate_remove, "assert tc_ingress_packets==packets", "", "TC-only/XDP-neutral"),
        ("TC egress packet evidence", mutate_remove, "assert tc_egress_packets==packets", "", "TC-only/XDP-neutral"),
        ("TC ingress byte evidence", mutate_remove, "assert tc_ingress_bytes==packets*packet_bytes", "", "TC-only/XDP-neutral"),
        ("TC egress byte evidence", mutate_remove, "assert tc_egress_bytes==packets*packet_bytes", "", "TC-only/XDP-neutral"),
        ("exact CT byte comparison", mutate_remove, "assert after_ct_bytes-before_ct_bytes==expected_bytes", "", "TC-only/XDP-neutral"),
        ("recovery ACL proof", mutate_remove, 'config["acl"] is True', "", "recovery proof"),
        ("recovery traffic proof", mutate_remove, "run_observed_allowed_flow recovery-allowed", "", "recovery proof"),
        ("recovery summary bit", mutate_remove, "RECOVERY_VERIFIED=true", "", "recovery proof"),
        ("bounded KILL fallback", mutate_remove, 'kill -KILL "${pid}"', "", "bounded agent shutdown"),
        ("detached pinned link", mutate_remove, 'bpftool link detach pinned "${lost_link}"', "", "detached-but-pinned"),
        ("detached pin retained", mutate_remove, '[ -e "${lost_link}" ]', "", "detached-but-pinned"),
        ("health poll wait", mutate_remove, 'sleep "${TC_HEALTH_WAIT_SECS}"', "", "TC health evidence"),
        ("health degraded assertion", mutate_remove, 'item["acl_ready"] is False', "", "TC health evidence"),
        ("live ACL gate off", mutate_remove, 'config["acl"] is False', "", "TC health evidence"),
        ("missing TC rejection", mutate_remove, '[ "${code}" = 503 ]', "", "enable rejection"),
        ("cleanup rollback verification", mutate_remove, "    if ! verify_cleanup", "", "fail-closed cleanup"),
        ("final summary write", mutate_remove, 'mv "${WORK_DIR}/summary.json.tmp" "${WORK_DIR}/summary.json"', "", "final standalone summary"),
        ("no early pass", mutate_replace, 'BODY_SUCCEEDED=true\n', 'RESULT="pass"\nBODY_SUCCEEDED=true\n', "main body must not"),
    )
    failures = []
    for label, mutate, needle, replacement, expected in specs:
        try:
            if mutate is mutate_remove:
                mutant = mutate(source, needle, label)
            else:
                mutant = mutate(source, needle, replacement, label)
        except ValueError as exc:
            failures.append(str(exc))
            continue
        mutation_errors = check_source(mutant)
        if not any(expected in error for error in mutation_errors):
            failures.append("mutation %s was accepted" % label)
        elif verbose:
            print("PASS: rejected mutation %s" % label)
    return failures


def main():
    args = sys.argv[1:]
    if any(arg != "--self-test" for arg in args):
        print("usage: %s [--self-test]" % sys.argv[0])
        return 2
    parser_errors = _parser_self_test_errors()
    if parser_errors:
        for error in parser_errors:
            print("ERROR: %s" % error)
        return 1
    if not os.path.isfile(SMOKE):
        print("ERROR: standalone TC ACL smoke is missing: %s" % os.path.relpath(SMOKE, ROOT))
        return 1
    with open(SMOKE, "r", encoding="utf-8") as handle:
        source = handle.read()
    errors = check_source(source)
    if not errors:
        errors.extend(run_mutation_self_tests(source, verbose="--self-test" in args))
    if errors:
        for error in errors:
            print("ERROR: %s" % error)
        return 1
    print("Standalone TC ACL smoke structure and mutation self-tests: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
