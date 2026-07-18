#!/usr/bin/env python3
"""Structure and mutation contracts for the guarded standalone TC ACL smoke."""

from __future__ import print_function

import ast
import json
import os
import re
import shlex
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
    "start_agent_process",
    "restart_agent_preserving_bpffs",
    "stop_agent_bounded",
    "crash_agent_bounded",
    "start_system_mode",
    "start_tap_mode",
    "install_fixture_policy",
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
    "assert_incomplete_pinned_runtime_quiesced",
    "restart_healthy_pinned_runtime",
    "recover_incomplete_pinned_runtime",
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
    "HEALTHY_PINNED_RESTART=false",
    "INCOMPLETE_PINNED_QUIESCED=false",
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
    heredocs = []
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
        if heredocs:
            if line.strip() == heredocs[0]:
                heredocs.pop(0)
            continue
        code = _shell_code(line)
        heredocs.extend(
            delimiter
            for _operator, _token, delimiter in _shell_heredoc_specs(line)
            if delimiter
        )
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


def _normalized_shell_json(body):
    """Normalize JSON quotes embedded in double-quoted shell strings."""
    return body.replace('\\"', '"')


def _strip_shell_comment(line):
    output = []
    quote = None
    escaped = False
    for index, char in enumerate(line):
        if escaped:
            output.append(char)
            escaped = False
            continue
        if char == "\\" and quote != "'":
            output.append(char)
            escaped = True
            continue
        if quote is not None:
            output.append(char)
            if char == quote:
                quote = None
            continue
        if char in ("'", '"'):
            quote = char
            output.append(char)
            continue
        if char == "#" and (index == 0 or line[index - 1].isspace()):
            break
        output.append(char)
    return "".join(output)


def _shell_function_declaration(code):
    return re.match(
        r"^(?:"
        r"[A-Za-z_][A-Za-z0-9_]*\s*\(\s*\)|"
        r"function\s+[A-Za-z_][A-Za-z0-9_]*(?:\s*\(\s*\))?"
        r")(?=\s|\{|\(|$)",
        code,
    )


def _shell_list_pipeline_parts(statement):
    """Split Bash list/pipeline operators while preserving quoted text."""
    parts = []
    operators = []
    current = []
    quote = None
    escaped = False
    index = 0
    while index < len(statement):
        char = statement[index]
        if escaped:
            current.append(char)
            escaped = False
            index += 1
            continue
        if char == "\\" and quote != "'":
            current.append(char)
            escaped = True
            index += 1
            continue
        if quote is not None:
            current.append(char)
            if char == quote:
                quote = None
            index += 1
            continue
        if char in ("'", '"'):
            quote = char
            current.append(char)
            index += 1
            continue

        operator = None
        for candidate in ("|&", "&&", "||"):
            if statement.startswith(candidate, index):
                operator = candidate
                break
        if operator is None and char in ";|&":
            previous = statement[index - 1] if index else ""
            following = statement[index + 1] if index + 1 < len(statement) else ""
            is_redirection = (char == "&" and (previous in "<>" or following == ">")) or (
                char == "|" and previous == ">"
            )
            if not is_redirection:
                operator = char
        if operator is None:
            current.append(char)
            index += 1
            continue
        parts.append("".join(current).strip())
        operators.append(operator)
        current = []
        index += len(operator)
    parts.append("".join(current).strip())
    return parts, operators


def _shell_heredoc_specs(statement):
    """Return raw token and decoded delimiter for every unquoted heredoc."""
    specs = []
    quote = None
    escaped = False
    index = 0
    while index < len(statement):
        char = statement[index]
        if escaped:
            escaped = False
            index += 1
            continue
        if quote == "'":
            if char == "'":
                quote = None
            index += 1
            continue
        if quote == '"':
            if char == "\\":
                escaped = True
            elif char == '"':
                quote = None
            index += 1
            continue
        if char == "#" and (index == 0 or statement[index - 1].isspace()):
            break
        if char == "\\":
            escaped = True
            index += 1
            continue
        if char in ("'", '"'):
            quote = char
            index += 1
            continue
        if statement.startswith("<<<", index):
            index += 3
            continue
        if not statement.startswith("<<", index):
            index += 1
            continue

        operator = "<<-" if statement.startswith("<<-", index) else "<<"
        token_start = index + len(operator)
        while token_start < len(statement) and statement[token_start].isspace():
            token_start += 1
        cursor = token_start
        token_quote = None
        decoded = []
        while cursor < len(statement):
            token_char = statement[cursor]
            if token_quote is not None:
                if token_char == token_quote:
                    token_quote = None
                elif token_char == "\\" and token_quote == '"' and cursor + 1 < len(statement):
                    cursor += 1
                    decoded.append(statement[cursor])
                else:
                    decoded.append(token_char)
                cursor += 1
                continue
            if token_char in ("'", '"'):
                token_quote = token_char
                cursor += 1
                continue
            if token_char == "\\" and cursor + 1 < len(statement):
                cursor += 1
                decoded.append(statement[cursor])
                cursor += 1
                continue
            if token_char.isspace() or token_char in ";|&<>(){}":
                break
            decoded.append(token_char)
            cursor += 1
        specs.append(
            (operator, statement[token_start:cursor], "".join(decoded))
        )
        index = max(cursor, token_start + 1)
    return specs


def _canonical_projection_python_command():
    return " ".join(
        (
            'python3 - "${WORK_DIR}/${label}-groups.json"',
            '"${WORK_DIR}/${label}-tap-config.json"',
            '"${WORK_DIR}/${label}-general-src.json"',
            '"${WORK_DIR}/${label}-general-dst.json"',
            '"${WORK_DIR}/${label}-acl-src.json"',
            '"${WORK_DIR}/${label}-acl-dst.json"',
            '"${MODE}"',
            "<<'PY'",
        )
    )


def _shell_prefixed_control_body(code):
    """Expose a control compound hidden behind Bash pipeline prefixes."""
    body = code
    while True:
        match = re.match(r"^(?:time(?:\s+-p)?|!)\s+", body)
        if match is None:
            break
        body = body[match.end() :].lstrip()
    coproc = re.match(r"^coproc(?:\s+|$)", body)
    if coproc is not None:
        body = body[coproc.end() :].lstrip()
        if re.match(
            r"^(?:if|for|while|until|case|select)(?:\s|$)|^[({]", body
        ) is None:
            named = re.match(r"^[A-Za-z_][A-Za-z0-9_]*\s+", body)
            if named is not None:
                body = body[named.end() :].lstrip()
    return body


def _shell_transition_contains_compound(code):
    transition = re.match(r"^(?:then|do|else|elif)(?:\s+|$)", code)
    if transition is None:
        return False
    nested = code[transition.end() :].lstrip()
    declaration = _shell_function_declaration(nested)
    if declaration is not None:
        nested = nested[declaration.end() :].lstrip()
        if not nested:
            return True
    nested = _shell_prefixed_control_body(nested)
    return re.match(
        r"^(?:if|for|while|until|case|select)(?:\s|$)|^\{(?:\s|$)|^\((?!\()",
        nested,
    ) is not None


def _cross_line_quote_errors(body, label):
    """Fail closed when shell evidence uses a quote across physical lines."""
    errors = []
    quote = None
    quote_reported = False
    heredocs = []
    for line_number, raw_line in enumerate(body.splitlines(), 1):
        if heredocs:
            if raw_line.strip() == heredocs[0]:
                heredocs.pop(0)
            continue

        escaped = False
        index = 0
        while index < len(raw_line):
            char = raw_line[index]
            if escaped:
                escaped = False
                index += 1
                continue
            if quote == "'":
                if char == "'":
                    quote = None
                index += 1
                continue
            if quote == '"':
                if char == "\\":
                    escaped = True
                elif char == '"':
                    quote = None
                index += 1
                continue
            if char == "#" and (index == 0 or raw_line[index - 1].isspace()):
                break
            if char == "\\":
                escaped = True
                index += 1
                continue
            if char in ("'", '"'):
                quote = char
            index += 1

        if quote is not None:
            if not quote_reported:
                errors.append(
                    "standalone evidence body %s forbids cross-line quote at line %d"
                    % (label, line_number)
                )
            quote_reported = True
            continue
        quote_reported = False
        heredocs.extend(
            delimiter
            for _operator, _token, delimiter in _shell_heredoc_specs(raw_line)
            if delimiter
        )
    return errors


def _evidence_heredoc_errors(body, label, canonical_command=None):
    found = []
    for statement, _depth in _shell_logical_commands(body):
        for spec in _shell_heredoc_specs(statement):
            found.append((statement, spec))
    if canonical_command is None:
        valid = not found
    else:
        valid = found == [(canonical_command, ("<<", "'PY'", "PY"))]
    if valid:
        return []
    return [
        "standalone evidence body %s forbids non-canonical heredoc" % label
    ]


def _uses_dynamic_shell_syntax(statement):
    quote = None
    escaped = False
    index = 0
    while index < len(statement):
        char = statement[index]
        if escaped:
            escaped = False
            index += 1
            continue
        if quote == "'":
            if char == "'":
                quote = None
            index += 1
            continue
        if char == "\\":
            escaped = True
            index += 1
            continue
        if quote == '"':
            if char == '"':
                quote = None
            elif char == "`" or statement.startswith("$(", index):
                return True
            index += 1
            continue
        if char == "'":
            quote = "'"
            index += 1
            continue
        if char == '"':
            quote = '"'
            index += 1
            continue
        if char == "`" or statement.startswith("$(", index):
            return True
        if statement.startswith("<(", index) or statement.startswith(">(", index):
            return True
        index += 1

    for part in _shell_list_pipeline_parts(statement)[0]:
        try:
            tokens = shlex.split(part, posix=True)
        except ValueError:
            return True
        if any(token in {"eval", "source"} for token in tokens):
            return True
        for position, token in enumerate(tokens):
            if os.path.basename(token) not in {"bash", "sh"}:
                continue
            if any(
                option.startswith("-") and "c" in option[1:]
                for option in tokens[position + 1 :]
            ):
                return True
    return False


def _evidence_body_contract_errors(body, label, canonical_heredoc=None):
    """Reject Bash constructs outside the closed evidence-command subset."""
    errors = _cross_line_quote_errors(body, label)
    errors.extend(
        _evidence_heredoc_errors(body, label, canonical_heredoc)
    )
    for statement, _depth in _shell_logical_commands(body):
        if _uses_dynamic_shell_syntax(statement):
            errors.append(
                "standalone evidence body %s forbids dynamic shell execution: %s"
                % (label, statement)
            )
        hidden = False
        multiple_transitions = False
        for part in _shell_list_pipeline_parts(statement)[0]:
            code = _shell_code(part).strip()
            if _shell_transition_contains_compound(code):
                multiple_transitions = True
            if _shell_function_declaration(code) is not None or re.match(
                r"^(?:time(?:\s+-p)?|!|coproc)(?:\s|$)", code
            ):
                hidden = True
        if multiple_transitions:
            errors.append(
                "standalone evidence body %s forbids multiple control transitions: %s"
                % (label, statement)
            )
        if hidden:
            errors.append(
                "standalone evidence body %s forbids hidden control syntax: %s"
                % (label, statement)
            )
    return errors


def _is_bare_shell_command(statement, executable):
    code = _shell_code(statement).strip()
    try:
        tokens = shlex.split(statement, posix=True)
    except ValueError:
        return False
    if not tokens or tokens[0] != executable:
        return False
    if _shell_list_pipeline_parts(statement)[1]:
        return False
    return re.search(r"[`(){}]", code) is None


def _shell_depth_changes(statement):
    """Return nesting closed before and opened after a logical statement."""
    unmatched_closes = 0
    open_depth = 0
    for part in _shell_list_pipeline_parts(statement)[0]:
        code = _shell_code(part).strip()
        if not code:
            continue
        closes = sum(
            (
                re.match(r"^(?:fi|done|esac)(?:\s|$)", code) is not None,
                re.match(r"^\}(?:\s|$)", code) is not None,
                re.match(r"^\)(?!\))(?:\s|$)", code) is not None,
            )
        )
        for _unused in range(closes):
            if open_depth:
                open_depth -= 1
            else:
                unmatched_closes += 1

        declaration = _shell_function_declaration(code)
        compound = code[declaration.end() :].lstrip() if declaration else code
        compound = _shell_prefixed_control_body(compound)
        opens = sum(
            (
                re.match(
                    r"^(?:if|for|while|until|case|select)(?:\s|$)", compound
                )
                is not None,
                re.match(r"^\{(?:\s|$)", compound) is not None,
                re.match(r"^\((?!\()", compound) is not None,
            )
        )
        open_depth += opens
    return unmatched_closes, open_depth


def _shell_logical_commands(body):
    commands = []
    parts = []
    heredocs = []
    depth = 0
    for raw_line in body.splitlines():
        if heredocs:
            if raw_line.strip() == heredocs[0]:
                heredocs.pop(0)
            continue
        line = _strip_shell_comment(raw_line).strip()
        if not line:
            continue
        continued = line.endswith("\\")
        parts.append(line[:-1].rstrip() if continued else line)
        if continued:
            continue
        statement = " ".join(" ".join(parts).split())
        parts = []
        closes_before, opens_after = _shell_depth_changes(statement)
        depth = max(0, depth - closes_before)
        commands.append((statement, depth))
        depth += opens_after
        heredocs.extend(
            delimiter
            for _operator, _token, delimiter in _shell_heredoc_specs(statement)
            if delimiter
        )
    if parts:
        commands.append((" ".join(" ".join(parts).split()), depth))
    return commands


def _shell_logical_statements(body):
    return [statement for statement, _depth in _shell_logical_commands(body)]


def _bare_depth_zero_call(body, command):
    return sum(
        statement == command and depth == 0
        for statement, depth in _shell_logical_commands(body)
    ) == 1


def _mode_projection_branch_present(body, mode, map_root):
    arms = re.findall(
        r"(?ms)^\s*%s\)(.*?);;" % re.escape(mode),
        body,
    )
    if len(arms) != 1:
        return False
    assignments = re.findall(r"(?m)^\s*map_root\s*=.*$", arms[0])
    if len(assignments) != 1:
        return False
    return re.fullmatch(
        r'\s*map_root\s*=\s*"%s"\s*' % re.escape(map_root), assignments[0]
    ) is not None


def _mode_tap_config_capture_present(body):
    arms = {
        mode: re.findall(r"(?ms)^\s*%s\)(.*?);;" % mode, body)
        for mode in ("system", "tap")
    }
    if any(len(matches) != 1 for matches in arms.values()):
        return False
    system_statements = _shell_logical_statements(arms["system"][0])
    tap_statements = _shell_logical_statements(arms["tap"][0])
    system_capture = (
        "printf '%s\\n' '[]' "
        '>"${WORK_DIR}/${label}-tap-config.json"'
    )
    tap_capture = (
        'bpftool -j map dump pinned "${map_root}/TAP_CONFIG_MAP" '
        '>"${WORK_DIR}/${label}-tap-config.json"'
    )
    return (
        system_statements.count(system_capture) == 1
        and tap_statements.count(tap_capture) == 1
        and tap_capture not in system_statements
        and system_capture not in tap_statements
    )


def _curl_json_posts(body, endpoint):
    posts = []
    for statement, depth in _shell_logical_commands(body):
        if depth != 0:
            continue
        if not _is_bare_shell_command(statement, "curl"):
            continue
        try:
            tokens = shlex.split(statement, posix=True)
        except ValueError:
            continue
        if not tokens or tokens[0] != "curl" or endpoint not in tokens:
            continue
        request_method = None
        for option in ("-X", "--request"):
            if option in tokens and tokens.index(option) + 1 < len(tokens):
                request_method = tokens[tokens.index(option) + 1].upper()
        if request_method not in (None, "POST"):
            continue
        payload = None
        for option in ("-d", "--data", "--data-raw"):
            if option in tokens and tokens.index(option) + 1 < len(tokens):
                payload = tokens[tokens.index(option) + 1]
                break
        if payload is None:
            continue
        try:
            decoded = json.loads(payload)
        except (TypeError, ValueError):
            continue
        if isinstance(decoded, dict):
            posts.append(decoded)
    return posts


def _extract_projection_python(body):
    lines = body.splitlines()
    candidates = []
    for start, line in enumerate(lines):
        if re.match(r"^\s*python3\s+-\s", line) is None:
            continue
        command = [line]
        end = start
        marker = re.search(
            r"<<-?\s*['\"]?([A-Za-z_][A-Za-z0-9_]*)['\"]?", line
        )
        while marker is None and end + 1 < len(lines) and lines[end].rstrip().endswith("\\"):
            end += 1
            command.append(lines[end])
            marker = re.search(
                r"<<-?\s*['\"]?([A-Za-z_][A-Za-z0-9_]*)['\"]?", lines[end]
            )
        if marker is None:
            continue
        delimiter = marker.group(1)
        closing = end + 1
        while closing < len(lines) and lines[closing].strip() != delimiter:
            closing += 1
        if closing >= len(lines):
            continue
        candidates.append(
            (
                " ".join(" ".join(command).replace("\\", " ").split()),
                "\n".join(lines[end + 1:closing]),
            )
        )
    return candidates


def _ast_expression(source):
    return ast.dump(ast.parse(source, mode="eval").body, include_attributes=False)


def _ast_import_binds(node, name):
    if isinstance(node, ast.Import):
        return any((alias.asname or alias.name.split(".", 1)[0]) == name for alias in node.names)
    if isinstance(node, ast.ImportFrom):
        return any((alias.asname or alias.name) == name for alias in node.names)
    return False


def _projection_python_safe_model():
    return r'''import ipaddress,json,sys
def decode_bytes(values):
    return bytes(int(value,16) if isinstance(value,str) else value for value in values)
def decode_u32(values):
    return int.from_bytes(decode_bytes(values),sys.byteorder)
def decode_lpm_entries(rows,expected_tap_id):
    entries=set()
    for row in rows:
        key=decode_bytes(row["key"])
        row_tap_id=int.from_bytes(key[4:8],"big")
        if row_tap_id!=expected_tap_id:
            continue
        prefix_len=decode_u32(key[:4])-32
        address=key[8:12]
        group_id=decode_u32(row["value"])
        entries.add((prefix_len,address,group_id))
    return entries
groups=json.load(open(sys.argv[1],encoding="utf-8"))["groups"]
tap_config_rows=json.load(open(sys.argv[2],encoding="utf-8"))
general_src_rows=json.load(open(sys.argv[3],encoding="utf-8"))
general_dst_rows=json.load(open(sys.argv[4],encoding="utf-8"))
acl_src_rows=json.load(open(sys.argv[5],encoding="utf-8"))
acl_dst_rows=json.load(open(sys.argv[6],encoding="utf-8"))
mode=sys.argv[7]
groups_by_name={row["name"]:row["id"] for row in groups}
referenced_id=groups_by_name["peer"]
unreferenced_id=groups_by_name["standalone-unreferenced"]
assert (mode=="system" and tap_config_rows==[]) or (mode=="tap" and len(tap_config_rows)==1)
tap_id=0 if mode=="system" else decode_u32(tap_config_rows[0]["key"])
active_bank=0 if mode=="system" else decode_bytes(tap_config_rows[0]["value"])[6]&1
active_acl_tap_id=tap_id*2|active_bank
expected_rows=[
    (network.version,network.prefixlen,network.network_address.packed,row["id"])
    for row in groups
    for cidr in row["cidrs"]
    for network in (ipaddress.ip_network(cidr,strict=False),)
]
assert all(version==4 for version,_,_,_ in expected_rows)
expected_entries={
    (prefix_len,address,group_id)
    for _,prefix_len,address,group_id in expected_rows
}
expected_ids={entry[2] for entry in expected_entries}
actual_general_src=decode_lpm_entries(general_src_rows,tap_id)
actual_general_dst=decode_lpm_entries(general_dst_rows,tap_id)
actual_acl_src=decode_lpm_entries(acl_src_rows,active_acl_tap_id)
actual_acl_dst=decode_lpm_entries(acl_dst_rows,active_acl_tap_id)
assert referenced_id in expected_ids
assert unreferenced_id in expected_ids
assert actual_general_src==expected_entries
assert actual_general_dst==expected_entries
assert actual_acl_src==expected_entries
assert actual_acl_dst==expected_entries
'''


def _projection_mutation_root(expression):
    while isinstance(expression, (ast.Attribute, ast.Subscript)):
        expression = expression.value
    return expression.id if isinstance(expression, ast.Name) else None


def _projection_protected_mutation_errors(tree):
    protected = {
        "groups",
        "tap_config_rows",
        "general_src_rows",
        "general_dst_rows",
        "acl_src_rows",
        "acl_dst_rows",
        "mode",
        "expected_entries",
        "expected_ids",
        "actual_general_src",
        "actual_general_dst",
        "actual_acl_src",
        "actual_acl_dst",
    }
    mutating_methods = {
        "add",
        "append",
        "clear",
        "difference_update",
        "discard",
        "extend",
        "insert",
        "intersection_update",
        "pop",
        "popitem",
        "remove",
        "reverse",
        "setdefault",
        "sort",
        "symmetric_difference_update",
        "update",
        "__delitem__",
        "__setitem__",
    }
    errors = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.Subscript, ast.Attribute)) and isinstance(
            node.ctx, (ast.Store, ast.Del)
        ):
            root = _projection_mutation_root(node)
            if root in protected:
                errors.append(
                    "standalone projection Python forbids mutation target rooted at %s"
                    % root
                )
        if isinstance(node, ast.AugAssign):
            root = _projection_mutation_root(node.target)
            if root in protected:
                errors.append(
                    "standalone projection Python forbids augmented mutation of %s"
                    % root
                )
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            root = _projection_mutation_root(node.func.value)
            if root in protected and node.func.attr in mutating_methods:
                errors.append(
                    "standalone projection Python forbids %s.%s() mutation"
                    % (root, node.func.attr)
                )
    return errors


def _projection_python_contract_errors(projection):
    candidates = _extract_projection_python(projection)
    if len(candidates) != 1:
        return ["standalone projection must contain exactly one executable Python heredoc"]
    command, python_source = candidates[0]
    expected_command = _canonical_projection_python_command()
    errors = []
    if command != expected_command:
        errors.append("standalone projection Python heredoc inputs are not exact")
    depth_zero_commands = [
        statement
        for statement, depth in _shell_logical_commands(projection)
        if depth == 0
    ]
    if depth_zero_commands.count(expected_command) != 1:
        errors.append(
            "standalone projection Python heredoc must execute exactly once at depth 0"
        )
    try:
        tree = ast.parse(python_source)
    except SyntaxError as exc:
        return errors + ["standalone projection Python heredoc is invalid: %s" % exc]

    safe_tree = ast.parse(_projection_python_safe_model())
    if ast.dump(tree, include_attributes=False) != ast.dump(
        safe_tree, include_attributes=False
    ):
        errors.append("standalone projection Python must match the canonical safe AST")
    errors.extend(_projection_protected_mutation_errors(tree))

    required_assignments = {
        "groups": 'json.load(open(sys.argv[1],encoding="utf-8"))["groups"]',
        "tap_config_rows": 'json.load(open(sys.argv[2],encoding="utf-8"))',
        "general_src_rows": 'json.load(open(sys.argv[3],encoding="utf-8"))',
        "general_dst_rows": 'json.load(open(sys.argv[4],encoding="utf-8"))',
        "acl_src_rows": 'json.load(open(sys.argv[5],encoding="utf-8"))',
        "acl_dst_rows": 'json.load(open(sys.argv[6],encoding="utf-8"))',
        "mode": "sys.argv[7]",
        "tap_id": '0 if mode=="system" else decode_u32(tap_config_rows[0]["key"])',
        "active_bank": '0 if mode=="system" else decode_bytes(tap_config_rows[0]["value"])[6]&1',
        "active_acl_tap_id": "tap_id*2|active_bank",
        "expected_entries": "{(prefix_len,address,group_id) for _,prefix_len,address,group_id in expected_rows}",
        "expected_ids": "{entry[2] for entry in expected_entries}",
        "actual_general_src": "decode_lpm_entries(general_src_rows,tap_id)",
        "actual_general_dst": "decode_lpm_entries(general_dst_rows,tap_id)",
        "actual_acl_src": "decode_lpm_entries(acl_src_rows,active_acl_tap_id)",
        "actual_acl_dst": "decode_lpm_entries(acl_dst_rows,active_acl_tap_id)",
    }
    required_functions = {
        node.name: node
        for node in safe_tree.body
        if isinstance(node, ast.FunctionDef)
        and node.name in {"decode_bytes", "decode_u32", "decode_lpm_entries"}
    }
    top_level_assignments = {}
    top_level_positions = {}
    for position, node in enumerate(tree.body):
        if (
            isinstance(node, ast.Assign)
            and len(node.targets) == 1
            and isinstance(node.targets[0], ast.Name)
        ):
            top_level_assignments.setdefault(node.targets[0].id, []).append(node.value)
            top_level_positions.setdefault(node.targets[0].id, []).append(position)

    function_positions = {}
    for name, expected_definition in required_functions.items():
        definitions = [
            node
            for node in ast.walk(tree)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            and node.name == name
        ]
        overwrites = [
            node
            for node in ast.walk(tree)
            if (
                isinstance(node, ast.Name)
                and isinstance(node.ctx, (ast.Store, ast.Del))
                and node.id == name
            )
            or (isinstance(node, ast.ClassDef) and node.name == name)
            or _ast_import_binds(node, name)
            or (isinstance(node, ast.ExceptHandler) and node.name == name)
        ]
        if len(definitions) != 1 or overwrites:
            errors.append(
                "standalone projection Python %s must have exactly one FunctionDef"
                % name
            )
            continue
        definition = definitions[0]
        if definition not in tree.body:
            errors.append(
                "standalone projection Python %s must be a top-level FunctionDef" % name
            )
            continue
        if ast.dump(definition, include_attributes=False) != ast.dump(
            expected_definition, include_attributes=False
        ):
            errors.append(
                "standalone projection Python %s FunctionDef has invalid data flow"
                % name
            )
            continue
        function_positions[name] = tree.body.index(definition)

    for name, rhs in required_assignments.items():
        bindings = [
            node
            for node in ast.walk(tree)
            if (
                isinstance(node, ast.Name)
                and isinstance(node.ctx, (ast.Store, ast.Del))
                and node.id == name
            )
            or (
                isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
                and node.name == name
            )
            or _ast_import_binds(node, name)
            or (isinstance(node, ast.ExceptHandler) and node.name == name)
        ]
        assignments = top_level_assignments.get(name, [])
        if len(bindings) != 1 or len(assignments) != 1:
            errors.append(
                "standalone projection Python %s must have exactly one assignment" % name
            )
            continue
        if ast.dump(assignments[0], include_attributes=False) != _ast_expression(rhs):
            errors.append(
                "standalone projection Python %s assignment must decode its artifact"
                % name
            )

    ordered_names = (
        "groups",
        "tap_config_rows",
        "general_src_rows",
        "general_dst_rows",
        "acl_src_rows",
        "acl_dst_rows",
        "mode",
        "tap_id",
        "active_bank",
        "active_acl_tap_id",
        "expected_entries",
        "expected_ids",
        "actual_general_src",
        "actual_general_dst",
        "actual_acl_src",
        "actual_acl_dst",
    )
    positions = [
        top_level_positions[name][0]
        for name in ordered_names
        if len(top_level_positions.get(name, [])) == 1
    ]
    if len(positions) != len(ordered_names) or positions != sorted(positions):
        errors.append(
            "standalone projection Python artifact and expected assignments are out of order"
        )
    if function_positions and any(
        position >= top_level_positions.get("groups", [position + 1])[0]
        for position in function_positions.values()
    ):
        errors.append(
            "standalone projection Python decoders must precede artifact loading"
        )

    required_assertions = (
        '(mode == "system" and tap_config_rows == []) or (mode == "tap" and len(tap_config_rows) == 1)',
        "referenced_id in expected_ids",
        "unreferenced_id in expected_ids",
        "actual_general_src == expected_entries",
        "actual_general_dst == expected_entries",
        "actual_acl_src == expected_entries",
        "actual_acl_dst == expected_entries",
    )
    top_level_assertions = {
        ast.dump(node.test, include_attributes=False)
        for node in tree.body
        if isinstance(node, ast.Assert)
    }
    for expression in required_assertions:
        if _ast_expression(expression) not in top_level_assertions:
            errors.append(
                "standalone projection Python assertion must directly consume %s"
                % expression
            )
    return errors


def _standalone_map_name_present(body, map_name):
    return (
        re.search(
            r"(?<![A-Z0-9_])%s(?![A-Z0-9_])" % re.escape(map_name), body
        )
        is not None
    )


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

    nested_shell = r'''never_name_form() {
    nested-name-command
}
function never_function_form {
    nested-function-command
}
{
    nested-brace-command
}
(
    nested-subshell-command
)
compound_name_form() if false; then
    nested-compound-name-command
fi
function compound_function_form for item in one; do
    nested-compound-function-command
done
time if false; then
    nested-time-command
fi
! while false; do
    nested-bang-command
done
time -p case value in
    value)
        nested-time-p-command
        ;;
esac
coproc if false; then
    nested-coproc-command
fi
false | if false; then
    nested-pipe-command
fi
false |& if false; then
    nested-pipe-stderr-command
fi
false && if false; then
    nested-and-command
fi
false || if false; then
    nested-or-command
fi
false; if false; then
    nested-list-command
fi
false & if false; then
    nested-background-command
fi
false || pipeline_function() if false; then
    nested-pipeline-function-command
fi
depth-zero-command
'''
    command_depths = {
        statement: depth
        for statement, depth in _shell_logical_commands(nested_shell)
    }
    for command in (
        "nested-name-command",
        "nested-function-command",
        "nested-brace-command",
        "nested-subshell-command",
        "nested-compound-name-command",
        "nested-compound-function-command",
        "nested-time-command",
        "nested-bang-command",
        "nested-time-p-command",
        "nested-coproc-command",
        "nested-pipe-command",
        "nested-pipe-stderr-command",
        "nested-and-command",
        "nested-or-command",
        "nested-list-command",
        "nested-background-command",
        "nested-pipeline-function-command",
    ):
        if command_depths.get(command, 0) == 0:
            errors.append("shell parser treated nested command as depth zero: %s" % command)
    if command_depths.get("depth-zero-command") != 0:
        errors.append("shell parser did not restore relative depth after nested constructs")
    forbidden = _evidence_body_contract_errors(nested_shell, "parser-self-test")
    for marker in (
        "compound_name_form() if",
        "function compound_function_form for",
        "time if",
        "! while",
        "time -p case",
        "coproc if",
    ):
        if not any(marker in error for error in forbidden):
            errors.append("evidence subset accepted hidden control syntax: %s" % marker)
    for transition in (
        "then if false",
        "do while false",
        "else case value in",
        "elif select value in one",
        "then {",
        "do (",
        "then nested_name() if false",
        "else function nested_keyword for value in one",
    ):
        if not _shell_transition_contains_compound(transition):
            errors.append(
                "evidence subset accepted multiple control transitions: %s"
                % transition
            )
    for transition in ("then run-proof", "do run-proof", "else run-proof", "elif test value"):
        if _shell_transition_contains_compound(transition):
            errors.append(
                "evidence subset rejected a canonical control transition: %s"
                % transition
            )
    if _is_bare_shell_command("curl example.invalid || true", "curl"):
        errors.append("bare shell command parser accepted a controlled curl")
    _parts, operators = _shell_list_pipeline_parts(
        "one | two |& three && four || five; six & seven"
    )
    if operators != ["|", "|&", "&&", "||", ";", "&"]:
        errors.append("shell operator tokenizer missed a list or pipeline operator")
    _parts, quoted_operators = _shell_list_pipeline_parts(
        "one '|' \"&&\" | two"
    )
    if quoted_operators != ["|"]:
        errors.append("shell operator tokenizer accepted an operator inside quotes")
    _parts, redirect_operators = _shell_list_pipeline_parts(
        "one 2>&1 &>redirected >|forced"
    )
    if redirect_operators:
        errors.append("shell operator tokenizer misclassified a redirection")
    if not _cross_line_quote_errors(": 'hidden\nproof\n'", "parser-self-test"):
        errors.append("evidence subset accepted a cross-line single quote")
    if not _cross_line_quote_errors(': "hidden\nproof\n"', "parser-self-test"):
        errors.append("evidence subset accepted a cross-line double quote")
    if _cross_line_quote_errors(
        "python3 <<'PY'\npayload=\"'quoted'\"\nPY\nproof-at-root",
        "parser-self-test",
    ):
        errors.append("evidence subset treated heredoc content as shell quoting")
    if _cross_line_quote_errors(
        "proof 'single-line' \"double-line\"", "parser-self-test"
    ):
        errors.append("evidence subset rejected quotes closed on one physical line")
    canonical_python = _canonical_projection_python_command()
    canonical_body = canonical_python + "\nignored-heredoc-command\nPY\nproof-at-root"
    canonical_statements = _shell_logical_statements(canonical_body)
    if (
        "ignored-heredoc-command" in canonical_statements
        or "proof-at-root" not in canonical_statements
    ):
        errors.append("shell parser did not fully skip the canonical Python heredoc")
    if _evidence_heredoc_errors(
        canonical_body, "parser-self-test", canonical_python
    ):
        errors.append("evidence subset rejected the canonical Python heredoc")
    numeric_body = ": <<'0'\nhidden\n0"
    if not _evidence_heredoc_errors(numeric_body, "parser-self-test"):
        errors.append("evidence subset accepted a numeric heredoc")
    non_py_body = canonical_python.replace("<<'PY'", "<<'ALT'") + "\nhidden\nALT"
    if not _evidence_heredoc_errors(
        non_py_body, "parser-self-test", canonical_python
    ):
        errors.append("evidence subset accepted a non-PY projection heredoc")
    double_body = (
        canonical_python.replace("<<'PY'", "<<'PY' <<'EXTRA'")
        + "\nhidden\nPY\nEXTRA"
    )
    if not _evidence_heredoc_errors(
        double_body, "parser-self-test", canonical_python
    ):
        errors.append("evidence subset accepted two heredocs on one command")
    for dynamic in (
        "eval proof",
        "source proof",
        "bash -c 'proof'",
        "/bin/sh -c 'proof'",
        "proof `hidden`",
        'proof "$(hidden)"',
        "proof <(hidden)",
        "proof >(hidden)",
    ):
        if not _uses_dynamic_shell_syntax(dynamic):
            errors.append("evidence subset accepted dynamic shell syntax: %s" % dynamic)
    for static in ('proof "${VAR}"', "proof '$(literal)'", "bash script.sh"):
        if _uses_dynamic_shell_syntax(static):
            errors.append("evidence subset rejected static shell syntax: %s" % static)
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
        'math.isfinite(timeout)',
        'timeout>0',
        're.fullmatch(r"(?:[0-9]+(?:\\.[0-9]*)?|\\.[0-9]+)"',
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
    if 'ip route add "${HOST_IP}/32" dev "${PEER_IF}" src "${DENIED_IP}"' in fixture:
        errors.append("fixture must not override the connected allowed route with DENIED_IP")

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

    start_process = bodies["start_agent_process"]
    for term in (
        '"${ARIA_AGENT_BIN}" --config "${CONFIG_FILE}"',
        'AGENT_PID=$!',
        'curl -fsS "${HTTP}/api/v1/health"',
    ):
        if term not in start_process:
            errors.append("standalone agent process launch missing %s" % term)

    stop = bodies["stop_agent_bounded"]
    for term in (
        'sleep "${AGENT_STOP_TIMEOUT_SECS}"',
        'kill -KILL "${pid}"',
        'wait "${pid}"',
        "timed_out=true",
    ):
        if term not in stop:
            errors.append("bounded agent shutdown missing %s" % term)

    crash = bodies["crash_agent_bounded"]
    for term in ('kill -KILL "${pid}"', 'wait "${pid}"', 'AGENT_PID=""'):
        if term not in crash:
            errors.append("pinned-runtime crash restart missing %s" % term)

    restart_process = bodies["restart_agent_preserving_bpffs"]
    for term in (
        '[ "${PRIVATE_BPFFS_MOUNTED}" = true ]',
        '[ -d "${PIN_ROOT}" ]',
        "start_agent_process",
    ):
        if term not in restart_process:
            errors.append("preserved-bpffs restart missing %s" % term)

    if '/api/v1/system/start' not in bodies["start_system_mode"]:
        errors.append("system standalone smoke must use /api/v1/system/start")
    if 'INSTANCE="${HOST_IF}"' not in bodies["start_tap_mode"]:
        errors.append("tap standalone smoke must wait for its fixture instance")

    fixture_policy = bodies["install_fixture_policy"]
    errors.extend(
        _evidence_body_contract_errors(fixture_policy, "install_fixture_policy")
    )
    group_posts = _curl_json_posts(
        fixture_policy, "${HTTP}/api/v1/${INSTANCE}/groups"
    )
    peer_posts = [
        post
        for post in group_posts
        if post == {"name": "peer", "cidr": "${PEER_IP}/32"}
    ]
    unreferenced_posts = [
        post
        for post in group_posts
        if post.get("name") == "standalone-unreferenced"
        and set(post) == {"name", "cidr"}
        and isinstance(post.get("cidr"), str)
        and bool(post["cidr"])
    ]
    policy_posts = _curl_json_posts(
        fixture_policy, "${HTTP}/api/v1/${INSTANCE}/policies"
    )
    if len(peer_posts) != 1 or not any(
        post.get("src_group") == "peer" or post.get("dst_group") == "peer"
        for post in policy_posts
    ):
        errors.append("standalone fixture missing referenced standalone group")
    if len(unreferenced_posts) != 1:
        errors.append("standalone fixture missing unreferenced standalone group")
    if any(
        post.get("src_group") == "standalone-unreferenced"
        or post.get("dst_group") == "standalone-unreferenced"
        for post in policy_posts
    ):
        errors.append("standalone-unreferenced group must remain unreferenced by ACL policies")

    projection = None
    try:
        projection = function_body(source, "assert_standalone_all_group_projection")
    except (KeyError, ValueError) as exc:
        errors.append(
            "missing structured standalone all-group projection helper "
            "assert_standalone_all_group_projection (%s)" % exc
        )
    if projection is not None:
        errors.extend(
            _evidence_body_contract_errors(
                projection,
                "assert_standalone_all_group_projection",
                _canonical_projection_python_command(),
            )
        )
        if not _mode_projection_branch_present(
            projection, "system", '${PIN_ROOT}/system'
        ):
            errors.append("standalone all-group projection missing MODE=system branch")
        if not _mode_projection_branch_present(
            projection, "tap", '${PIN_ROOT}/global-v2'
        ):
            errors.append("standalone all-group projection missing MODE=tap branch")
        if not _mode_tap_config_capture_present(projection):
            errors.append(
                "standalone all-group projection must use an empty MODE=system "
                "TAP_CONFIG baseline and dump the unique MODE=tap row"
            )
        for term in (
            "/api/v1/${INSTANCE}/groups",
            'row["name"]',
            'row["id"]',
            'groups_by_name["peer"]',
            'groups_by_name["standalone-unreferenced"]',
            "referenced_id",
            "unreferenced_id",
        ):
            if term not in projection:
                errors.append(
                    "standalone all-group projection missing dynamic group-id evidence %s"
                    % term
                )
        projection_statements = [
            statement
            for statement, depth in _shell_logical_commands(projection)
            if depth == 0
        ]
        capture_commands = (
            'curl -fsS "${HTTP}/api/v1/${INSTANCE}/groups" >"${WORK_DIR}/${label}-groups.json"',
            'bpftool -j map dump pinned "${map_root}/SRC_IPV4_TRIE" >"${WORK_DIR}/${label}-general-src.json"',
            'bpftool -j map dump pinned "${map_root}/DST_IPV4_TRIE" >"${WORK_DIR}/${label}-general-dst.json"',
            'bpftool -j map dump pinned "${map_root}/ACL_SRC_IPV4_TRIE" >"${WORK_DIR}/${label}-acl-src.json"',
            'bpftool -j map dump pinned "${map_root}/ACL_DST_IPV4_TRIE" >"${WORK_DIR}/${label}-acl-dst.json"',
        )
        for command in capture_commands:
            if projection_statements.count(command) != 1:
                errors.append(
                    "standalone all-group projection missing exact capture command %s"
                    % command
                )
        errors.extend(_projection_python_contract_errors(projection))
        for term in ("bpftool -j map dump pinned", "decode_lpm_entries"):
            if term not in projection:
                errors.append(
                    "standalone all-group projection missing pinned-map evidence %s"
                    % term
                )
        for map_name in (
            "SRC_IPV4_TRIE",
            "DST_IPV4_TRIE",
            "TAP_CONFIG_MAP",
            "ACL_SRC_IPV4_TRIE",
            "ACL_DST_IPV4_TRIE",
        ):
            if not _standalone_map_name_present(projection, map_name):
                errors.append(
                    "standalone all-group projection missing pinned-map evidence %s"
                    % map_name
                )
        for term in (
            "def decode_bytes(values):",
            "bytes(int(value,16) if isinstance(value,str) else value for value in values)",
            "def decode_u32(values):",
            "int.from_bytes(decode_bytes(values),sys.byteorder)",
            "def decode_lpm_entries(rows,expected_tap_id):",
            'key=decode_bytes(row["key"])',
            'row_tap_id=int.from_bytes(key[4:8],"big")',
            "if row_tap_id!=expected_tap_id:",
            "prefix_len=decode_u32(key[:4])-32",
            "address=key[8:12]",
            'group_id=decode_u32(row["value"])',
            "entries.add((prefix_len,address,group_id))",
            'groups=json.load(open(sys.argv[1],encoding="utf-8"))["groups"]',
            'tap_config_rows=json.load(open(sys.argv[2],encoding="utf-8"))',
            'general_src_rows=json.load(open(sys.argv[3],encoding="utf-8"))',
            'general_dst_rows=json.load(open(sys.argv[4],encoding="utf-8"))',
            'acl_src_rows=json.load(open(sys.argv[5],encoding="utf-8"))',
            'acl_dst_rows=json.load(open(sys.argv[6],encoding="utf-8"))',
            "mode=sys.argv[7]",
            'assert (mode=="system" and tap_config_rows==[]) or (mode=="tap" and len(tap_config_rows)==1)',
            'tap_id=0 if mode=="system" else decode_u32(tap_config_rows[0]["key"])',
            'active_bank=0 if mode=="system" else decode_bytes(tap_config_rows[0]["value"])[6]&1',
            "active_acl_tap_id=tap_id*2|active_bank",
            "expected_entries",
            "actual_general_src=decode_lpm_entries(general_src_rows,tap_id)",
            "actual_general_dst=decode_lpm_entries(general_dst_rows,tap_id)",
            "actual_acl_src=decode_lpm_entries(acl_src_rows,active_acl_tap_id)",
            "actual_acl_dst=decode_lpm_entries(acl_dst_rows,active_acl_tap_id)",
            "assert referenced_id in expected_ids",
            "assert unreferenced_id in expected_ids",
            "assert actual_general_src==expected_entries",
            "assert actual_general_dst==expected_entries",
            "assert actual_acl_src==expected_entries",
            "assert actual_acl_dst==expected_entries",
        ):
            if term not in projection:
                errors.append(
                    "standalone all-group projection missing decoded artifact proof %s"
                    % term
                )
        for pattern, label in (
            (r"(?m)^\s*active_bank\s*=\s*[01]\s*$", "hard-coded active bank"),
            (
                r"(?m)^\s*active_acl_tap_id\s*=\s*active_bank\s*$",
                "hard-coded active ACL tap id",
            ),
            (
                r"(?m)^\s*actual_(?:general|acl)(?:_src|_dst)?\s*=\s*expected",
                "actual map self-equality",
            ),
            (r"(?m)^\s*return\s+expected_entries\s*$", "expected map decoder"),
        ):
            if re.search(pattern, projection):
                errors.append(
                    "standalone all-group projection forbids %s" % label
                )

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
        "/trace",
        '"proto":"icmp"',
        "TRACE_ARMED=true",
    ):
        if term not in trace:
            errors.append("controlled-flow trace arm missing %s" % term)
    clear_trace = bodies["clear_trace_filter"]
    if '-X DELETE' not in clear_trace or '"${HTTP}/api/v1/${INSTANCE}/trace"' not in clear_trace:
        errors.append("controlled-flow trace disarm is missing")

    allowed = bodies["run_allowed_flow"]
    denied = bodies["run_denied_flow"]
    if 'ping -I "${PEER_IP}" -c "${ALLOWED_PACKETS}"' not in allowed:
        errors.append("allowed flow must bind PEER_IP and use the exact controlled packet count")
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
            'set_trace_filter "" ""',
            'capture_acl_counters "${label}-before"',
            'run_allowed_flow "${label}"',
            'capture_acl_counters "${label}-after"',
            "clear_trace_filter",
            'assert_xdp_neutral "${label}-before" "${label}-after"',
        ),
    ):
        errors.append("allowed flow must be traced across exact before/after TC evidence")
    if 'set_trace_filter "${PEER_IP}" "${HOST_IP}"' in observed:
        errors.append("allowed flow trace must be instance-scoped wildcard ICMP for both TC directions")

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

    main_body = source.split("trap cleanup EXIT\n", 1)[-1]
    healthy_restart = bodies["restart_healthy_pinned_runtime"]
    errors.extend(_evidence_body_contract_errors(main_body, "main"))
    errors.extend(
        _evidence_body_contract_errors(
            healthy_restart, "restart_healthy_pinned_runtime"
        )
    )
    for term in (
        "crash_agent_bounded",
        "restart_agent_preserving_bpffs",
        "assert_dual_tc_ready",
        "HEALTHY_PINNED_RESTART=true",
    ):
        if term not in healthy_restart:
            errors.append("healthy pinned-runtime restart proof missing %s" % term)
    if not ordered(
        healthy_restart,
        (
            "restart_agent_preserving_bpffs",
            'if [ "${MODE}" = system ]; then',
            "start_system_mode",
            "else",
        ),
    ):
        errors.append("healthy pinned-runtime restart missing MODE=system branch")
    if not ordered(
        healthy_restart, ("else", "start_tap_mode", "fi", "assert_dual_tc_ready")
    ):
        errors.append("healthy pinned-runtime restart missing MODE=tap branch")
    restart_projection_ordered = ordered(
        healthy_restart,
        (
            "restart_agent_preserving_bpffs",
            "assert_dual_tc_ready",
            "assert_standalone_all_group_projection after-restart",
            "run_observed_allowed_flow healthy-restart",
            "run_denied_flow healthy-restart-denied",
            "HEALTHY_PINNED_RESTART=true",
        ),
    ) and _bare_depth_zero_call(
        healthy_restart, "assert_standalone_all_group_projection after-restart"
    )

    incomplete = bodies["assert_incomplete_pinned_runtime_quiesced"]
    for term in (
        'item["acl_ready"] is False',
        'value[0]==0',
        "INCOMPLETE_PINNED_QUIESCED=true",
    ):
        if term not in incomplete:
            errors.append("incomplete pinned-runtime quiesce proof missing %s" % term)

    recover = bodies["recover_incomplete_pinned_runtime"]
    for forbidden in ('umount "${PIN_ROOT}"', 'rm -rf "${PIN_ROOT}"'):
        if forbidden in recover:
            errors.append("pinned-runtime recovery must not cold-delete bpffs: %s" % forbidden)
    for term in (
        "assert_incomplete_pinned_runtime_quiesced",
        "assert_dual_tc_ready",
        "assert_recovery_verified",
    ):
        if term not in recover:
            errors.append("incomplete pinned-runtime recovery proof missing %s" % term)

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
                'set_trace_filter "" ""',
                "assert_xdp_neutral legacy-zero-before legacy-zero-after",
                '-X PUT',
            ):
                if term not in legacy:
                    errors.append("tap legacy-zero compatibility missing %s" % term)

    cleanup = bodies["cleanup"]
    for term in (
        "trap - EXIT",
        '"${HTTP}/api/v1/system/stop"',
        '--max-time "${AGENT_STOP_TIMEOUT_SECS}"',
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
        '"healthy_pinned_restart"',
        '"incomplete_pinned_quiesced"',
        '"cleanup_errors"',
        '"result"',
        "summary.json.tmp",
        'mv "${WORK_DIR}/summary.json.tmp" "${WORK_DIR}/summary.json"',
    ):
        if term not in summary:
            errors.append("final standalone summary missing %s" % term)
    if "write_summary" in main_body or 'RESULT="pass"' in main_body:
        errors.append("main body must not write summary.json or select pass before cleanup")
    if not ordered(
        source,
        (
            "derive_fixture_identity",
            "select_http_addr",
            "preflight_fixture",
            'mkdir -p "${WORK_DIR}"',
        ),
    ):
        errors.append("standalone smoke must preflight unique resources before mutation")
    if not ordered(
        main_body,
        (
            "run_observed_allowed_flow allowed",
            "exercise_legacy_zero_compatibility",
            "run_denied_flow",
            "restart_healthy_pinned_runtime",
            "assert_health_poll_degrades",
            "assert_missing_tc_rejected",
            "recover_incomplete_pinned_runtime",
        ),
    ):
        errors.append("standalone smoke main body does not preserve the required evidence order")
    pre_restart_projection_ordered = ordered(
        main_body,
        (
            "install_fixture_policy",
            "assert_dual_tc_ready",
            "assert_standalone_all_group_projection before-restart",
            "run_observed_allowed_flow allowed",
            "run_denied_flow",
            "restart_healthy_pinned_runtime",
        ),
    ) and _bare_depth_zero_call(
        main_body, "assert_standalone_all_group_projection before-restart"
    )
    if not (pre_restart_projection_ordered and restart_projection_ordered):
        errors.append(
            "standalone group restart/replay verification must bracket healthy restart"
        )
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


def _mutate_function_once(source, function_name, needle, replacement, label):
    try:
        body = function_body(source, function_name)
    except (KeyError, ValueError) as exc:
        raise ValueError("mutation anchor missing: %s (%s)" % (label, exc))
    if needle not in body:
        raise ValueError("mutation anchor missing: %s" % label)
    mutated_body = body.replace(needle, replacement, 1)
    return source.replace(body, mutated_body, 1)


def _mutate_fixture_group_name(source, group_name, label):
    try:
        body = function_body(source, "install_fixture_policy")
    except (KeyError, ValueError) as exc:
        raise ValueError("mutation anchor missing: %s (%s)" % (label, exc))
    pattern = re.compile(
        r'((?:\\?")name(?:\\?")\s*:\s*(?:\\?"))%s((?:\\?"))'
        % re.escape(group_name)
    )
    mutated_body, count = pattern.subn(
        lambda match: "%sremoved-%s%s"
        % (match.group(1), group_name, match.group(2)),
        body,
        count=1,
    )
    if count != 1:
        raise ValueError("mutation anchor missing: %s" % label)
    return source.replace(body, mutated_body, 1)


def _mutate_fixture_group_decoy(source, group_name, comment, label):
    try:
        body = function_body(source, "install_fixture_policy")
    except (KeyError, ValueError) as exc:
        raise ValueError("mutation anchor missing: %s (%s)" % (label, exc))
    lines = body.splitlines()
    target = next(
        (
            index
            for index, line in enumerate(lines)
            if '"name":"%s"' % group_name in _normalized_shell_json(line)
        ),
        None,
    )
    if target is None:
        raise ValueError("mutation anchor missing: %s" % label)
    start = target
    while start >= 0 and not lines[start].lstrip().startswith("curl "):
        start -= 1
    end = target
    while end < len(lines) and "/api/v1/${INSTANCE}/groups" not in lines[end]:
        end += 1
    if start < 0 or end >= len(lines):
        raise ValueError("mutation anchor missing: %s" % label)
    if comment:
        for index in range(start, end + 1):
            indent = lines[index][: len(lines[index]) - len(lines[index].lstrip())]
            lines[index] = indent + "# " + lines[index].lstrip()
    else:
        indent = lines[start][: len(lines[start]) - len(lines[start].lstrip())]
        lines[start] = indent + ": " + lines[start].lstrip()[len("curl ") :]
    return source.replace(body, "\n".join(lines), 1)


def mutate_remove_referenced_group(source, _needle, _replacement, label):
    return _mutate_fixture_group_name(source, "peer", label)


def mutate_remove_unreferenced_group(source, _needle, _replacement, label):
    return _mutate_fixture_group_name(source, "standalone-unreferenced", label)


def mutate_noop_referenced_group_decoy(source, _needle, _replacement, label):
    return _mutate_fixture_group_decoy(source, "peer", False, label)


def mutate_comment_unreferenced_group_decoy(source, _needle, _replacement, label):
    return _mutate_fixture_group_decoy(
        source, "standalone-unreferenced", True, label
    )


def mutate_remove_restart_projection(source, _needle, _replacement, label):
    return _mutate_function_once(
        source,
        "restart_healthy_pinned_runtime",
        "assert_standalone_all_group_projection after-restart",
        "",
        label,
    )


def mutate_remove_projection_system_branch(source, _needle, _replacement, label):
    return _mutate_function_once(
        source,
        "assert_standalone_all_group_projection",
        '${PIN_ROOT}/system',
        '${PIN_ROOT}/removed-system',
        label,
    )


def mutate_remove_projection_tap_branch(source, _needle, _replacement, label):
    return _mutate_function_once(
        source,
        "assert_standalone_all_group_projection",
        '${PIN_ROOT}/global-v2',
        '${PIN_ROOT}/removed-global-v2',
        label,
    )


def mutate_noop_projection_system_branch(source, _needle, _replacement, label):
    return _mutate_function_once(
        source,
        "assert_standalone_all_group_projection",
        '            map_root="${PIN_ROOT}/system"',
        '            : \'map_root="${PIN_ROOT}/system"\'',
        label,
    )


def mutate_noop_projection_capture(source, _needle, _replacement, label):
    command = (
        'bpftool -j map dump pinned "${map_root}/SRC_IPV4_TRIE" '
        '>"${WORK_DIR}/${label}-general-src.json"'
    )
    return _mutate_function_once(
        source,
        "assert_standalone_all_group_projection",
        command,
        ": " + command,
        label,
    )


def mutate_hardcode_projection_bank(source, _needle, _replacement, label):
    return _mutate_function_once(
        source,
        "assert_standalone_all_group_projection",
        'active_bank=0 if mode=="system" else decode_bytes(tap_config_rows[0]["value"])[6]&1',
        "active_bank=0",
        label,
    )


def mutate_hardcode_projection_acl_tap_id(source, _needle, _replacement, label):
    return _mutate_function_once(
        source,
        "assert_standalone_all_group_projection",
        "active_acl_tap_id=tap_id*2|active_bank",
        "active_acl_tap_id=active_bank",
        label,
    )


def mutate_self_equal_general_projection(source, _needle, _replacement, label):
    return _mutate_function_once(
        source,
        "assert_standalone_all_group_projection",
        "actual_general_src=decode_lpm_entries(general_src_rows,tap_id)",
        "actual_general_src=expected_entries",
        label,
    )


def mutate_self_equal_acl_projection(source, _needle, _replacement, label):
    return _mutate_function_once(
        source,
        "assert_standalone_all_group_projection",
        "actual_acl_src=decode_lpm_entries(acl_src_rows,active_acl_tap_id)",
        "actual_acl_src=expected_entries",
        label,
    )


def mutate_alias_overwrite_projection_bank(source, _needle, _replacement, label):
    assignment = (
        'active_bank=0 if mode=="system" else '
        'decode_bytes(tap_config_rows[0]["value"])[6]&1'
    )
    return _mutate_function_once(
        source,
        "assert_standalone_all_group_projection",
        assignment,
        assignment + "\nactive_bank_alias=active_bank\nactive_bank=active_bank_alias",
        label,
    )


def mutate_alias_overwrite_acl_projection(source, _needle, _replacement, label):
    assignment = "actual_acl_src=decode_lpm_entries(acl_src_rows,active_acl_tap_id)"
    return _mutate_function_once(
        source,
        "assert_standalone_all_group_projection",
        assignment,
        assignment + "\nactual_acl_alias=actual_acl_src\nactual_acl_src=actual_acl_alias",
        label,
    )


def mutate_alias_projection_assertion(source, _needle, _replacement, label):
    assertion = "assert actual_general_src==expected_entries"
    return _mutate_function_once(
        source,
        "assert_standalone_all_group_projection",
        assertion,
        "actual_general_assert=actual_general_src\n"
        "assert actual_general_assert==expected_entries",
        label,
    )


def mutate_alias_general_src_artifact(source, _needle, _replacement, label):
    assignment = 'general_src_rows=json.load(open(sys.argv[3],encoding="utf-8"))'
    return _mutate_function_once(
        source,
        "assert_standalone_all_group_projection",
        assignment,
        assignment + "\ngeneral_src_rows=acl_src_rows",
        label,
    )


def mutate_hardcode_tap_config_artifact(source, _needle, _replacement, label):
    assignment = 'tap_config_rows=json.load(open(sys.argv[2],encoding="utf-8"))'
    return _mutate_function_once(
        source,
        "assert_standalone_all_group_projection",
        assignment,
        assignment + "\ntap_config_rows=[]",
        label,
    )


def mutate_overwrite_expected_entries(source, _needle, _replacement, label):
    assertion = "assert referenced_id in expected_ids"
    return _mutate_function_once(
        source,
        "assert_standalone_all_group_projection",
        assertion,
        "expected_entries=actual_general_src\n" + assertion,
        label,
    )


def mutate_redefine_lpm_decoder(source, _needle, _replacement, label):
    anchor = "    return entries\ngroups=json.load"
    replacement = (
        "    return entries\n"
        "def decode_lpm_entries(rows,expected_tap_id):\n"
        "    return set()\n"
        "groups=json.load"
    )
    return _mutate_function_once(
        source,
        "assert_standalone_all_group_projection",
        anchor,
        replacement,
        label,
    )


def mutate_tap_config_subscript_store(source, _needle, _replacement, label):
    assignment = (
        'active_bank=0 if mode=="system" else '
        'decode_bytes(tap_config_rows[0]["value"])[6]&1'
    )
    return _mutate_function_once(
        source,
        "assert_standalone_all_group_projection",
        assignment,
        assignment + '\ntap_config_rows[0]["value"][6]=0',
        label,
    )


def mutate_system_tap_id_reads_tap_config(source, _needle, _replacement, label):
    return _mutate_function_once(
        source,
        "assert_standalone_all_group_projection",
        'tap_id=0 if mode=="system" else decode_u32(tap_config_rows[0]["key"])',
        'tap_id=decode_u32(tap_config_rows[0]["key"])',
        label,
    )


def mutate_system_active_bank_reads_tap_config(
    source, _needle, _replacement, label
):
    return _mutate_function_once(
        source,
        "assert_standalone_all_group_projection",
        'active_bank=0 if mode=="system" else decode_bytes(tap_config_rows[0]["value"])[6]&1',
        'active_bank=decode_bytes(tap_config_rows[0]["value"])[6]&1',
        label,
    )


def mutate_system_dumps_tap_config(source, _needle, _replacement, label):
    return _mutate_function_once(
        source,
        "assert_standalone_all_group_projection",
        "printf '%s\\n' '[]' >\"${WORK_DIR}/${label}-tap-config.json\"",
        'bpftool -j map dump pinned "${map_root}/TAP_CONFIG_MAP" '
        '>"${WORK_DIR}/${label}-tap-config.json"',
        label,
    )


def _mutate_clear_projection_object(source, object_name, label):
    assertion = "assert referenced_id in expected_ids"
    return _mutate_function_once(
        source,
        "assert_standalone_all_group_projection",
        assertion,
        "%s.clear()\n%s" % (object_name, assertion),
        label,
    )


def mutate_clear_expected_entries(source, _needle, _replacement, label):
    return _mutate_clear_projection_object(source, "expected_entries", label)


def mutate_clear_actual_general_src(source, _needle, _replacement, label):
    return _mutate_clear_projection_object(source, "actual_general_src", label)


def mutate_clear_actual_general_dst(source, _needle, _replacement, label):
    return _mutate_clear_projection_object(source, "actual_general_dst", label)


def mutate_clear_actual_acl_src(source, _needle, _replacement, label):
    return _mutate_clear_projection_object(source, "actual_acl_src", label)


def mutate_clear_actual_acl_dst(source, _needle, _replacement, label):
    return _mutate_clear_projection_object(source, "actual_acl_dst", label)


def mutate_false_branch_unreferenced_group(source, _needle, _replacement, label):
    body = function_body(source, "install_fixture_policy")
    lines = body.splitlines()
    target = next(
        (
            index
            for index, line in enumerate(lines)
            if '"name":"standalone-unreferenced"'
            in _normalized_shell_json(line)
        ),
        None,
    )
    if target is None:
        raise ValueError("mutation anchor missing: %s" % label)
    start = target
    while start >= 0 and not lines[start].lstrip().startswith("curl "):
        start -= 1
    end = target
    while end < len(lines) and "/api/v1/${INSTANCE}/groups" not in lines[end]:
        end += 1
    if start < 0 or end >= len(lines):
        raise ValueError("mutation anchor missing: %s" % label)
    indent = lines[start][: len(lines[start]) - len(lines[start].lstrip())]
    wrapped = [indent + "if false; then"]
    wrapped.extend(indent + "    " + line.lstrip() for line in lines[start : end + 1])
    wrapped.append(indent + "fi")
    lines[start : end + 1] = wrapped
    return source.replace(body, "\n".join(lines), 1)


def mutate_false_branch_projection_capture(source, _needle, _replacement, label):
    command = (
        'bpftool -j map dump pinned "${map_root}/SRC_IPV4_TRIE" '
        '>"${WORK_DIR}/${label}-general-src.json"'
    )
    return _mutate_function_once(
        source,
        "assert_standalone_all_group_projection",
        "    " + command,
        "    if false; then\n        %s\n    fi" % command,
        label,
    )


def mutate_false_branch_before_restart_call(source, _needle, _replacement, label):
    main_body = source.split("trap cleanup EXIT\n", 1)[-1]
    call = "assert_standalone_all_group_projection before-restart"
    if "\n%s\n" % call not in "\n" + main_body:
        raise ValueError("mutation anchor missing: %s" % label)
    mutated = main_body.replace(
        call,
        "if false; then\n    %s\nfi" % call,
        1,
    )
    return source[: len(source) - len(main_body)] + mutated


def mutate_false_branch_after_restart_call(source, _needle, _replacement, label):
    call = "assert_standalone_all_group_projection after-restart"
    return _mutate_function_once(
        source,
        "restart_healthy_pinned_runtime",
        "    " + call,
        "    if false; then\n        %s\n    fi" % call,
        label,
    )


def mutate_hide_projection_in_uncalled_function(source, _needle, _replacement, label):
    body = function_body(source, "assert_standalone_all_group_projection")
    capture = (
        '    curl -fsS "${HTTP}/api/v1/${INSTANCE}/groups" '
        '>"${WORK_DIR}/${label}-groups.json"'
    )
    if capture not in body or "\nPY" not in body:
        raise ValueError("mutation anchor missing: %s" % label)
    mutated = body.replace(
        capture,
        "    never_run_projection() {\n" + capture,
        1,
    )
    mutated = mutated.replace("\nPY", "\nPY\n    }", 1)
    return source.replace(body, mutated, 1)


def mutate_hide_unreferenced_group_in_uncalled_function(
    source, _needle, _replacement, label
):
    body = function_body(source, "install_fixture_policy")
    lines = body.splitlines()
    target = next(
        (
            index
            for index, line in enumerate(lines)
            if '"name":"standalone-unreferenced"'
            in _normalized_shell_json(line)
        ),
        None,
    )
    if target is None:
        raise ValueError("mutation anchor missing: %s" % label)
    start = target
    while start >= 0 and not lines[start].lstrip().startswith("curl "):
        start -= 1
    end = target
    while end < len(lines) and "/api/v1/${INSTANCE}/groups" not in lines[end]:
        end += 1
    if start < 0 or end >= len(lines):
        raise ValueError("mutation anchor missing: %s" % label)
    indent = lines[start][: len(lines[start]) - len(lines[start].lstrip())]
    wrapped = [indent + "never_install_unreferenced_group() {"]
    wrapped.extend(indent + "    " + line.lstrip() for line in lines[start : end + 1])
    wrapped.append(indent + "}")
    lines[start : end + 1] = wrapped
    return source.replace(body, "\n".join(lines), 1)


def mutate_hide_restart_projection_calls_in_uncalled_functions(
    source, _needle, _replacement, label
):
    before = "assert_standalone_all_group_projection before-restart"
    main_body = source.split("trap cleanup EXIT\n", 1)[-1]
    if "\n%s\n" % before not in "\n" + main_body:
        raise ValueError("mutation anchor missing: %s" % label)
    mutated_main = main_body.replace(
        before,
        "never_run_before_projection() {\n    %s\n}" % before,
        1,
    )
    source = source[: len(source) - len(main_body)] + mutated_main

    after = "assert_standalone_all_group_projection after-restart"
    return _mutate_function_once(
        source,
        "restart_healthy_pinned_runtime",
        "    " + after,
        "    never_run_after_projection() {\n        %s\n    }" % after,
        label,
    )


def _mutate_wrap_projection_evidence(source, opening, closing, label):
    body = function_body(source, "assert_standalone_all_group_projection")
    capture = (
        '    curl -fsS "${HTTP}/api/v1/${INSTANCE}/groups" '
        '>"${WORK_DIR}/${label}-groups.json"'
    )
    if capture not in body or "\nPY" not in body:
        raise ValueError("mutation anchor missing: %s" % label)
    mutated = body.replace(capture, opening + capture, 1)
    mutated = mutated.replace("\nPY", "\nPY" + closing, 1)
    return source.replace(body, mutated, 1)


def mutate_hide_projection_in_compound_function(source, _needle, _replacement, label):
    return _mutate_wrap_projection_evidence(
        source,
        "    never_run_projection() if false; then\n",
        "\n    fi",
        label,
    )


def mutate_hide_projection_in_prefixed_control(source, _needle, _replacement, label):
    return _mutate_wrap_projection_evidence(
        source,
        "    time if false; then\n",
        "\n    fi",
        label,
    )


def _mutate_wrap_unreferenced_group(source, opening, closing, label):
    body = function_body(source, "install_fixture_policy")
    lines = body.splitlines()
    target = next(
        (
            index
            for index, line in enumerate(lines)
            if '"name":"standalone-unreferenced"'
            in _normalized_shell_json(line)
        ),
        None,
    )
    if target is None:
        raise ValueError("mutation anchor missing: %s" % label)
    start = target
    while start >= 0 and not lines[start].lstrip().startswith("curl "):
        start -= 1
    end = target
    while end < len(lines) and "/api/v1/${INSTANCE}/groups" not in lines[end]:
        end += 1
    if start < 0 or end >= len(lines):
        raise ValueError("mutation anchor missing: %s" % label)
    indent = lines[start][: len(lines[start]) - len(lines[start].lstrip())]
    wrapped = [indent + opening]
    wrapped.extend(lines[start : end + 1])
    wrapped.append(indent + closing)
    lines[start : end + 1] = wrapped
    return source.replace(body, "\n".join(lines), 1)


def mutate_hide_unreferenced_group_in_compound_function(
    source, _needle, _replacement, label
):
    return _mutate_wrap_unreferenced_group(
        source,
        "never_install_unreferenced_group() if false; then",
        "fi",
        label,
    )


def mutate_hide_unreferenced_group_in_prefixed_control(
    source, _needle, _replacement, label
):
    return _mutate_wrap_unreferenced_group(
        source,
        "! if false; then",
        "fi",
        label,
    )


def _mutate_wrap_restart_projection_calls(
    source, before_open, before_close, after_open, after_close, label
):
    before = "assert_standalone_all_group_projection before-restart"
    main_body = source.split("trap cleanup EXIT\n", 1)[-1]
    if "\n%s\n" % before not in "\n" + main_body:
        raise ValueError("mutation anchor missing: %s" % label)
    mutated_main = main_body.replace(
        before,
        "%s\n    %s\n%s" % (before_open, before, before_close),
        1,
    )
    source = source[: len(source) - len(main_body)] + mutated_main

    after = "assert_standalone_all_group_projection after-restart"
    return _mutate_function_once(
        source,
        "restart_healthy_pinned_runtime",
        "    " + after,
        "    %s\n        %s\n    %s" % (after_open, after, after_close),
        label,
    )


def mutate_hide_projection_calls_in_compound_functions(
    source, _needle, _replacement, label
):
    return _mutate_wrap_restart_projection_calls(
        source,
        "never_run_before_projection() if false; then",
        "fi",
        "never_run_after_projection() if false; then",
        "fi",
        label,
    )


def mutate_hide_projection_calls_in_prefixed_controls(
    source, _needle, _replacement, label
):
    return _mutate_wrap_restart_projection_calls(
        source,
        "time -p if false; then",
        "fi",
        "coproc if false; then",
        "fi",
        label,
    )


def mutate_hide_projection_in_pipeline_compound(
    source, _needle, _replacement, label
):
    return _mutate_wrap_projection_evidence(
        source,
        "    false | if false; then\n",
        "\n    fi",
        label,
    )


def mutate_hide_unreferenced_group_in_pipeline_compound(
    source, _needle, _replacement, label
):
    return _mutate_wrap_unreferenced_group(
        source,
        "false | if false; then",
        "fi",
        label,
    )


def mutate_hide_projection_calls_in_pipeline_compounds(
    source, _needle, _replacement, label
):
    return _mutate_wrap_restart_projection_calls(
        source,
        "false | if false; then",
        "fi",
        "false | if false; then",
        "fi",
        label,
    )


def mutate_hide_projection_in_double_control(source, _needle, _replacement, label):
    return _mutate_wrap_projection_evidence(
        source,
        "    if true; then if false; then :\n        fi\n",
        "\n    fi",
        label,
    )


def mutate_hide_unreferenced_group_in_double_control(
    source, _needle, _replacement, label
):
    return _mutate_wrap_unreferenced_group(
        source,
        "for item in one; do while false; do :\n        done",
        "done",
        label,
    )


def mutate_hide_projection_calls_in_double_controls(
    source, _needle, _replacement, label
):
    return _mutate_wrap_restart_projection_calls(
        source,
        "if true; then if false; then :\n    fi",
        "fi",
        "if true; then if false; then :\n        fi",
        "fi",
        label,
    )


def mutate_hide_projection_in_multiline_quote(source, _needle, _replacement, label):
    return _mutate_wrap_projection_evidence(
        source,
        "    : '\n",
        "\n    '",
        label,
    )


def mutate_hide_unreferenced_group_in_multiline_quote(
    source, _needle, _replacement, label
):
    return _mutate_wrap_unreferenced_group(
        source,
        ": '",
        "'",
        label,
    )


def mutate_hide_projection_calls_in_multiline_quotes(
    source, _needle, _replacement, label
):
    return _mutate_wrap_restart_projection_calls(
        source,
        ": '",
        "'",
        ": '",
        "'",
        label,
    )


def mutate_hide_projection_in_numeric_heredoc(source, _needle, _replacement, label):
    return _mutate_wrap_projection_evidence(
        source,
        "    : <<'0'\n",
        "\n0",
        label,
    )


def mutate_hide_unreferenced_group_in_numeric_heredoc(
    source, _needle, _replacement, label
):
    return _mutate_wrap_unreferenced_group(
        source,
        ": <<'0'",
        "\n0",
        label,
    )


def mutate_hide_projection_calls_in_numeric_heredocs(
    source, _needle, _replacement, label
):
    return _mutate_wrap_restart_projection_calls(
        source,
        ": <<'0'",
        "\n0",
        ": <<'0'",
        "\n0",
        label,
    )


def run_mutation_self_tests(source, verbose=False):
    specs = (
        (
            "referenced standalone group",
            mutate_remove_referenced_group,
            "",
            "",
            "referenced standalone group",
        ),
        (
            "unreferenced standalone group",
            mutate_remove_unreferenced_group,
            "",
            "",
            "unreferenced standalone group",
        ),
        (
            "referenced standalone group no-op decoy",
            mutate_noop_referenced_group_decoy,
            "",
            "",
            "referenced standalone group",
        ),
        (
            "unreferenced standalone group comment decoy",
            mutate_comment_unreferenced_group_decoy,
            "",
            "",
            "unreferenced standalone group",
        ),
        (
            "standalone restart/replay assertion",
            mutate_remove_restart_projection,
            "",
            "",
            "restart/replay",
        ),
        (
            "standalone projection MODE=system",
            mutate_remove_projection_system_branch,
            "",
            "",
            "MODE=system",
        ),
        (
            "standalone projection MODE=tap",
            mutate_remove_projection_tap_branch,
            "",
            "",
            "MODE=tap",
        ),
        (
            "standalone projection MODE=system no-op decoy",
            mutate_noop_projection_system_branch,
            "",
            "",
            "MODE=system",
        ),
        (
            "standalone projection capture no-op decoy",
            mutate_noop_projection_capture,
            "",
            "",
            "exact capture command",
        ),
        (
            "standalone projection hard-coded active bank",
            mutate_hardcode_projection_bank,
            "",
            "",
            "hard-coded active bank",
        ),
        (
            "standalone system tap id reads TAP_CONFIG row",
            mutate_system_tap_id_reads_tap_config,
            "",
            "",
            "tap_id assignment must decode its artifact",
        ),
        (
            "standalone system active bank reads TAP_CONFIG row",
            mutate_system_active_bank_reads_tap_config,
            "",
            "",
            "active_bank assignment must decode its artifact",
        ),
        (
            "standalone system dumps TAP_CONFIG row",
            mutate_system_dumps_tap_config,
            "",
            "",
            "empty MODE=system TAP_CONFIG baseline",
        ),
        (
            "standalone projection hard-coded ACL tap id",
            mutate_hardcode_projection_acl_tap_id,
            "",
            "",
            "hard-coded active ACL tap id",
        ),
        (
            "standalone general projection self-equality",
            mutate_self_equal_general_projection,
            "",
            "",
            "actual map self-equality",
        ),
        (
            "standalone ACL projection self-equality",
            mutate_self_equal_acl_projection,
            "",
            "",
            "actual map self-equality",
        ),
        (
            "standalone projection active-bank alias overwrite",
            mutate_alias_overwrite_projection_bank,
            "",
            "",
            "active_bank must have exactly one assignment",
        ),
        (
            "standalone ACL projection alias overwrite",
            mutate_alias_overwrite_acl_projection,
            "",
            "",
            "actual_acl_src must have exactly one assignment",
        ),
        (
            "standalone projection assertion alias",
            mutate_alias_projection_assertion,
            "",
            "",
            "assertion must directly consume actual_general_src == expected_entries",
        ),
        (
            "standalone general-src artifact alias overwrite",
            mutate_alias_general_src_artifact,
            "",
            "",
            "general_src_rows must have exactly one assignment",
        ),
        (
            "standalone tap-config artifact hard-coded overwrite",
            mutate_hardcode_tap_config_artifact,
            "",
            "",
            "tap_config_rows must have exactly one assignment",
        ),
        (
            "standalone expected entries overwritten by actual",
            mutate_overwrite_expected_entries,
            "",
            "",
            "expected_entries must have exactly one assignment",
        ),
        (
            "standalone LPM decoder redefinition",
            mutate_redefine_lpm_decoder,
            "",
            "",
            "decode_lpm_entries must have exactly one FunctionDef",
        ),
        (
            "standalone tap-config nested mutation",
            mutate_tap_config_subscript_store,
            "",
            "",
            "mutation target rooted at tap_config_rows",
        ),
        (
            "standalone expected entries clear mutation",
            mutate_clear_expected_entries,
            "",
            "",
            "forbids expected_entries.clear() mutation",
        ),
        (
            "standalone general-src projection clear mutation",
            mutate_clear_actual_general_src,
            "",
            "",
            "forbids actual_general_src.clear() mutation",
        ),
        (
            "standalone general-dst projection clear mutation",
            mutate_clear_actual_general_dst,
            "",
            "",
            "forbids actual_general_dst.clear() mutation",
        ),
        (
            "standalone ACL-src projection clear mutation",
            mutate_clear_actual_acl_src,
            "",
            "",
            "forbids actual_acl_src.clear() mutation",
        ),
        (
            "standalone ACL-dst projection clear mutation",
            mutate_clear_actual_acl_dst,
            "",
            "",
            "forbids actual_acl_dst.clear() mutation",
        ),
        (
            "standalone unreferenced group false branch",
            mutate_false_branch_unreferenced_group,
            "",
            "",
            "unreferenced standalone group",
        ),
        (
            "standalone projection capture false branch",
            mutate_false_branch_projection_capture,
            "",
            "",
            "exact capture command",
        ),
        (
            "standalone before-restart projection false branch",
            mutate_false_branch_before_restart_call,
            "",
            "",
            "restart/replay",
        ),
        (
            "standalone after-restart projection false branch",
            mutate_false_branch_after_restart_call,
            "",
            "",
            "restart/replay",
        ),
        (
            "standalone projection evidence in uncalled nested function",
            mutate_hide_projection_in_uncalled_function,
            "",
            "",
            "exact capture command",
        ),
        (
            "standalone unreferenced group in uncalled nested function",
            mutate_hide_unreferenced_group_in_uncalled_function,
            "",
            "",
            "unreferenced standalone group",
        ),
        (
            "standalone restart projection calls in uncalled nested functions",
            mutate_hide_restart_projection_calls_in_uncalled_functions,
            "",
            "",
            "restart/replay",
        ),
        (
            "standalone projection evidence in compound function",
            mutate_hide_projection_in_compound_function,
            "",
            "",
            "forbids hidden control syntax",
        ),
        (
            "standalone unreferenced group in compound function",
            mutate_hide_unreferenced_group_in_compound_function,
            "",
            "",
            "forbids hidden control syntax",
        ),
        (
            "standalone projection calls in compound functions",
            mutate_hide_projection_calls_in_compound_functions,
            "",
            "",
            "forbids hidden control syntax",
        ),
        (
            "standalone projection evidence in prefixed control",
            mutate_hide_projection_in_prefixed_control,
            "",
            "",
            "forbids hidden control syntax",
        ),
        (
            "standalone unreferenced group in prefixed control",
            mutate_hide_unreferenced_group_in_prefixed_control,
            "",
            "",
            "forbids hidden control syntax",
        ),
        (
            "standalone projection calls in prefixed controls",
            mutate_hide_projection_calls_in_prefixed_controls,
            "",
            "",
            "forbids hidden control syntax",
        ),
        (
            "standalone projection evidence in pipeline compound",
            mutate_hide_projection_in_pipeline_compound,
            "",
            "",
            "exact capture command",
        ),
        (
            "standalone unreferenced group in pipeline compound",
            mutate_hide_unreferenced_group_in_pipeline_compound,
            "",
            "",
            "unreferenced standalone group",
        ),
        (
            "standalone projection calls in pipeline compounds",
            mutate_hide_projection_calls_in_pipeline_compounds,
            "",
            "",
            "restart/replay",
        ),
        (
            "standalone projection evidence in double control",
            mutate_hide_projection_in_double_control,
            "",
            "",
            "forbids multiple control transitions",
        ),
        (
            "standalone unreferenced group in double control",
            mutate_hide_unreferenced_group_in_double_control,
            "",
            "",
            "forbids multiple control transitions",
        ),
        (
            "standalone projection calls in double controls",
            mutate_hide_projection_calls_in_double_controls,
            "",
            "",
            "forbids multiple control transitions",
        ),
        (
            "standalone projection evidence in multiline quote",
            mutate_hide_projection_in_multiline_quote,
            "",
            "",
            "forbids cross-line quote",
        ),
        (
            "standalone unreferenced group in multiline quote",
            mutate_hide_unreferenced_group_in_multiline_quote,
            "",
            "",
            "forbids cross-line quote",
        ),
        (
            "standalone projection calls in multiline quotes",
            mutate_hide_projection_calls_in_multiline_quotes,
            "",
            "",
            "forbids cross-line quote",
        ),
        (
            "standalone projection evidence in numeric heredoc",
            mutate_hide_projection_in_numeric_heredoc,
            "",
            "",
            "forbids non-canonical heredoc",
        ),
        (
            "standalone unreferenced group in numeric heredoc",
            mutate_hide_unreferenced_group_in_numeric_heredoc,
            "",
            "",
            "forbids non-canonical heredoc",
        ),
        (
            "standalone projection calls in numeric heredocs",
            mutate_hide_projection_calls_in_numeric_heredocs,
            "",
            "",
            "forbids non-canonical heredoc",
        ),
        ("TC ingress pin assertion", mutate_remove_ingress_ready, "", "", "dual-TC readiness"),
        ("TC egress pin assertion", mutate_remove_egress_ready, "", "", "dual-TC readiness"),
        ("TC ingress live program identity", mutate_remove, 'ingress.get("prog_id")==ingress_prog.get("id")', "", "dual-TC readiness"),
        ("TC egress live program identity", mutate_remove, 'egress.get("prog_id")==egress_prog.get("id")', "", "dual-TC readiness"),
        ("unique fixture token", mutate_remove, "secrets.token_hex(5)", "", "fixture identity"),
        ("unique host interface", mutate_remove, 'HOST_IF="ah${FIXTURE_TOKEN}"', "", "fixture identity"),
        ("free loopback port", mutate_remove, 'sock.bind(("127.0.0.1",0))', "", "loopback port selection"),
        ("workdir collision preflight", mutate_remove, '[ ! -e "${WORK_DIR}" ]', "", "fixture preflight"),
        ("positive finite shutdown timeout", mutate_remove, "math.isfinite(timeout)", "", "fixture preflight"),
        ("legal sleep duration", mutate_remove,
         're.fullmatch(r"(?:[0-9]+(?:\\.[0-9]*)?|\\.[0-9]+)"', "", "fixture preflight"),
        ("host interface ownership", mutate_remove, '[ "${VETH_CREATED}" = true ]', "", "fail-closed cleanup"),
        ("bpffs mount ownership", mutate_replace,
         '    if [ "${PRIVATE_BPFFS_MOUNTED}" = true ]; then\n        if ! umount',
         '    if true; then\n        if ! umount', "fail-closed cleanup"),
        ("TC ingress packet evidence", mutate_remove, "assert tc_ingress_packets==packets", "", "TC-only/XDP-neutral"),
        ("TC egress packet evidence", mutate_remove, "assert tc_egress_packets==packets", "", "TC-only/XDP-neutral"),
        ("TC ingress byte evidence", mutate_remove, "assert tc_ingress_bytes==packets*packet_bytes", "", "TC-only/XDP-neutral"),
        ("TC egress byte evidence", mutate_remove, "assert tc_egress_bytes==packets*packet_bytes", "", "TC-only/XDP-neutral"),
        ("allowed PEER_IP binding", mutate_remove, '-I "${PEER_IP}"', "", "allowed flow must bind PEER_IP"),
        ("denied source route override", mutate_replace,
         '    ip route add "${DENIED_IP}/32" dev "${HOST_IF}"',
         '    ip netns exec "${NETNS}" ip route add "${HOST_IP}/32" dev "${PEER_IF}" src "${DENIED_IP}"\n    ip route add "${DENIED_IP}/32" dev "${HOST_IF}"',
         "must not override the connected allowed route"),
        ("bidirectional wildcard trace", mutate_replace, 'set_trace_filter "" ""',
         'set_trace_filter "${PEER_IP}" "${HOST_IP}"', "wildcard ICMP"),
        ("exact CT byte comparison", mutate_remove, "assert after_ct_bytes-before_ct_bytes==expected_bytes", "", "TC-only/XDP-neutral"),
        ("unknown hook inference", mutate_replace, "expected_packets=packets*2",
         "unknown_hook=0\nexpected_packets=packets*2", "must not be inferred"),
        ("recovery ACL proof", mutate_remove, 'config["acl"] is True', "", "recovery proof"),
        ("recovery CT proof", mutate_remove, 'config["conntrack"] is True', "", "recovery proof"),
        ("recovery policy proof", mutate_remove, "len(policies)==4", "", "recovery proof"),
        ("recovery traffic proof", mutate_remove, "run_observed_allowed_flow recovery-allowed", "", "recovery proof"),
        ("recovery deny proof", mutate_remove, "run_denied_flow recovery-denied", "", "recovery proof"),
        ("recovery summary bit", mutate_remove, "RECOVERY_VERIFIED=true", "", "recovery proof"),
        ("bounded TERM wait", mutate_remove, 'sleep "${AGENT_STOP_TIMEOUT_SECS}"', "", "bounded agent shutdown"),
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


def _synthetic_projection_green_source(source):
    """Complete only the new standalone projection contract in memory."""
    fixture_policy = _normalized_shell_json(
        function_body(source, "install_fixture_policy")
    )
    if '"name":"standalone-unreferenced"' not in fixture_policy:
        policy_anchor = (
            "    curl --fail-with-body -sS -H 'Content-Type: application/json' \\\n"
            "        -d '{\"src_group\":\"peer\",\"dst_group\":\"host\","
            "\"proto\":\"icmp\",\"action\":\"allow\",\"direction\":"
            "\"ingress\",\"ports\":null}' \\\n"
            '        "${HTTP}/api/v1/${INSTANCE}/policies" >/dev/null'
        )
        unreferenced_group = (
            "    curl --fail-with-body -sS -H 'Content-Type: application/json' \\\n"
            "        -d '{\"name\":\"standalone-unreferenced\","
            "\"cidr\":\"10.203.0.7/32\"}' \\\n"
            '        "${HTTP}/api/v1/${INSTANCE}/groups" >/dev/null\n'
        )
        source = _mutate_function_once(
            source,
            "install_fixture_policy",
            policy_anchor,
            unreferenced_group + policy_anchor,
            "synthetic unreferenced standalone group",
        )

    try:
        function_body(source, "assert_standalone_all_group_projection")
    except KeyError:
        helper = r'''assert_standalone_all_group_projection() {
    local label="${1:?projection label is required}" map_root
    case "${MODE}" in
        system)
            map_root="${PIN_ROOT}/system"
            printf '%s\n' '[]' >"${WORK_DIR}/${label}-tap-config.json"
            ;;
        tap)
            map_root="${PIN_ROOT}/global-v2"
            bpftool -j map dump pinned "${map_root}/TAP_CONFIG_MAP" >"${WORK_DIR}/${label}-tap-config.json"
            ;;
    esac
    curl -fsS "${HTTP}/api/v1/${INSTANCE}/groups" >"${WORK_DIR}/${label}-groups.json"
    bpftool -j map dump pinned "${map_root}/SRC_IPV4_TRIE" >"${WORK_DIR}/${label}-general-src.json"
    bpftool -j map dump pinned "${map_root}/DST_IPV4_TRIE" >"${WORK_DIR}/${label}-general-dst.json"
    bpftool -j map dump pinned "${map_root}/ACL_SRC_IPV4_TRIE" >"${WORK_DIR}/${label}-acl-src.json"
    bpftool -j map dump pinned "${map_root}/ACL_DST_IPV4_TRIE" >"${WORK_DIR}/${label}-acl-dst.json"
    python3 - "${WORK_DIR}/${label}-groups.json" \
        "${WORK_DIR}/${label}-tap-config.json" \
        "${WORK_DIR}/${label}-general-src.json" \
        "${WORK_DIR}/${label}-general-dst.json" \
        "${WORK_DIR}/${label}-acl-src.json" \
        "${WORK_DIR}/${label}-acl-dst.json" \
        "${MODE}" <<'PY'
''' + _projection_python_safe_model().rstrip() + r'''
PY
}
'''
        anchor = "restart_healthy_pinned_runtime() {"
        if anchor not in source:
            raise ValueError("synthetic projection helper insertion anchor missing")
        source = source.replace(anchor, helper + "\n" + anchor, 1)
    except ValueError:
        raise

    main_body = source.split("trap cleanup EXIT\n", 1)[-1]
    if "assert_standalone_all_group_projection before-restart" not in main_body:
        anchor = "install_fixture_policy\nassert_dual_tc_ready\n"
        replacement = (
            "install_fixture_policy\nassert_dual_tc_ready\n"
            "assert_standalone_all_group_projection before-restart\n"
        )
        if anchor not in source:
            raise ValueError("synthetic pre-restart projection anchor missing")
        source = source.replace(anchor, replacement, 1)

    restart = function_body(source, "restart_healthy_pinned_runtime")
    if "assert_standalone_all_group_projection after-restart" not in restart:
        source = _mutate_function_once(
            source,
            "restart_healthy_pinned_runtime",
            "    assert_dual_tc_ready\n",
            "    assert_dual_tc_ready\n"
            "    assert_standalone_all_group_projection after-restart\n",
            "synthetic post-restart projection",
        )
    return source


def _projection_contract_self_test_errors(source):
    try:
        synthetic = _synthetic_projection_green_source(source)
    except (KeyError, ValueError) as exc:
        return ["synthetic standalone projection fixture failed: %s" % exc]
    errors = check_source(synthetic)
    if errors:
        return [
            "synthetic standalone projection fixture was rejected: %s" % error
            for error in errors
        ]
    return run_mutation_self_tests(synthetic)


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
    if "--self-test" in args:
        contract_errors = _projection_contract_self_test_errors(source)
        if contract_errors:
            for error in contract_errors:
                print("ERROR: %s" % error)
            return 1
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
