#!/usr/bin/env python3
"""Structure and mutation contracts for the destructive real-tap ACL smoke."""

from __future__ import print_function

import ast
import os
import re
import shlex
import sys


ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir))
SMOKE = os.path.join(
    ROOT, "deploy", "kolla", "smoke", "neutron_aria_acl_tc_datapath_smoke.sh"
)
BACKLOG = os.path.join(
    ROOT, "docs", "openstack-neutron-aria-details", "12-review-bug-backlog.md"
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
        if char == "#" and (
            index == 0
            or line[index - 1].isspace()
            or line[index - 1] in ";|&()<>"
        ):
            output.extend(" " for _ in line[index:])
            break
        output.append(char)
        index += 1
    return "".join(output)


def _heredoc_delimiters(line):
    """Return every heredoc delimiter on a shell logical command, in order."""
    code = _shell_code(line)
    delimiters = []
    for match in re.finditer(r"<<-?", code):
        index = match.end()
        while index < len(line) and line[index].isspace():
            index += 1
        if index >= len(line):
            continue
        if line[index] in ("'", '"'):
            quote = line[index]
            end = line.find(quote, index + 1)
            if end < 0:
                continue
            candidate = line[index + 1 : end]
        else:
            candidate_match = re.match(
                r"[A-Za-z_][A-Za-z0-9_]*", line[index:]
            )
            if candidate_match is None:
                continue
            candidate = candidate_match.group(0)
        if re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", candidate):
            delimiters.append(candidate)
    return delimiters


def _heredoc_delimiter(line):
    """Backward-compatible single-delimiter view used by older checks."""
    delimiters = _heredoc_delimiters(line)
    return delimiters[0] if delimiters else None


def _function_start_pattern(name=None):
    identifier = (
        re.escape(name)
        if name is not None
        else r"([A-Za-z_][A-Za-z0-9_]*)"
    )
    if name is not None:
        return re.compile(
            r"^\s*(?:function\s+%s(?:\s*\(\s*\))?|%s\s*\(\s*\))\s*\{"
            % (identifier, identifier)
        )
    return re.compile(
        r"^\s*(?:function\s+([A-Za-z_][A-Za-z0-9_]*)"
        r"(?:\s*\(\s*\))?|([A-Za-z_][A-Za-z0-9_]*)\s*\(\s*\))\s*\{"
    )


def function_body(source, name):
    """Extract a shell function while honoring nested braces and heredocs."""
    lines = source.splitlines()
    start = None
    depth = 0
    heredocs = []
    pattern = _function_start_pattern(name)
    for index, line in enumerate(lines):
        if heredocs:
            if line.strip() == heredocs[0]:
                heredocs.pop(0)
            continue
        code = _shell_code(line)
        function_match = pattern.match(code)
        if function_match:
            start = index
            depth = code.count("{") - code.count("}")
            if depth == 0:
                open_brace = line.find("{", function_match.start())
                close_brace = line.rfind("}")
                return line[open_brace + 1 : close_brace]
            break
        heredocs.extend(_heredoc_delimiters(line))
    if start is None:
        raise KeyError(name)
    for index in range(start + 1, len(lines)):
        line = lines[index]
        if heredocs:
            if line.strip() == heredocs[0]:
                heredocs.pop(0)
            continue
        code = _shell_code(line)
        heredocs.extend(_heredoc_delimiters(line))
        depth += code.count("{") - code.count("}")
        if depth == 0:
            return "\n".join(lines[start + 1 : index])
    raise ValueError("unterminated shell function %s" % name)


def top_level_shell(source):
    """Remove functions/heredoc payloads while preserving top-level shell."""
    output = []
    in_function = False
    depth = 0
    heredocs = []
    function_start = _function_start_pattern()
    for line in source.splitlines():
        if not in_function:
            if heredocs:
                if line.strip() == heredocs[0]:
                    heredocs.pop(0)
                    output.append(line)
                continue
            if not function_start.match(_shell_code(line)):
                output.append(line)
                heredocs.extend(_heredoc_delimiters(line))
                continue
            in_function = True
            code = _shell_code(line)
            depth = code.count("{") - code.count("}")
            if depth == 0:
                in_function = False
            continue
        if heredocs:
            if line.strip() == heredocs[0]:
                heredocs.pop(0)
            continue
        heredocs.extend(_heredoc_delimiters(line))
        code = _shell_code(line)
        depth += code.count("{") - code.count("}")
        if depth == 0:
            in_function = False
    return "\n".join(output)


def _strip_shell_comment(line):
    """Strip a shell comment while preserving quoted command arguments."""
    index = 0
    quote = None
    while index < len(line):
        char = line[index]
        if quote is not None:
            if quote == '"' and char == "\\":
                index += 2
                continue
            if char == quote:
                quote = None
            index += 1
            continue
        if char in ("'", '"'):
            quote = char
        elif char == "#" and (
            index == 0
            or line[index - 1].isspace()
            or line[index - 1] in ";|&()<>"
        ):
            return line[:index]
        index += 1
    return line


def _logical_shell_lines(body):
    """Yield logical shell commands, excluding all queued heredoc payloads."""
    heredocs = []
    pending = ""
    for raw_line in body.splitlines():
        if heredocs:
            if raw_line.strip() == heredocs[0]:
                heredocs.pop(0)
            continue
        line = _strip_shell_comment(raw_line)
        continued = bool(re.search(r"(?<!\\)\\\s*$", line))
        if continued:
            pending += re.sub(r"\\\s*$", " ", line)
            continue
        logical = pending + line
        pending = ""
        if logical.strip():
            yield logical
        heredocs.extend(_heredoc_delimiters(logical))
    if pending.strip():
        yield pending


def _shell_lines_with_depth(body):
    """Return logical commands annotated with simple shell control depth."""
    depth = 0
    for line in _logical_shell_lines(body):
        code = _shell_code(line).strip()
        leading_close = re.match(r"^(fi|done|esac)\b", code)
        if leading_close:
            depth = max(0, depth - 1)
        yield line, depth
        opens = len(
            re.findall(r"(?:^|[;&|]\s*)(?:if|for|while|until|case)\b", code)
        )
        closes = len(re.findall(r"\b(?:fi|done|esac)\b", code))
        if leading_close:
            closes -= 1
        depth = max(0, depth + opens - closes)


def _function_definition_counts(source):
    """Count real function definitions, ignoring comments, strings, heredocs."""
    counts = {}
    for line in _logical_shell_lines(source):
        code = _shell_code(line)
        match = _function_start_pattern().match(code)
        if match:
            name = match.group(1) or match.group(2)
            counts[name] = counts.get(name, 0) + 1
    return counts


def _depth_zero_bare_positions(body, command):
    """Return positions of exact bare calls at shell control depth zero."""
    positions = []
    offset = 0
    pattern = re.compile(r"^\s*%s\s*$" % re.escape(command))
    for line, depth in _shell_lines_with_depth(body):
        if depth == 0 and pattern.match(_shell_code(line)):
            positions.append(offset)
        offset += len(line) + 1
    return positions


def _command_tokens(line):
    """Tokenize a logical command and expose its first real executable."""
    text = _strip_shell_comment(line).strip()
    if not text:
        return []
    try:
        tokens = shlex.split(text, posix=True)
    except ValueError:
        return []
    while tokens and tokens[0] in ("if", "then", "!", "command"):
        tokens.pop(0)
    while tokens and re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", tokens[0]):
        tokens.pop(0)
    return tokens


def _real_command_lines(body, executable):
    """Return logical commands whose first executable is exactly executable."""
    matches = []
    for line in _logical_shell_lines(body):
        tokens = _command_tokens(line)
        command_substitution = re.match(
            r"^\s*[A-Za-z_][A-Za-z0-9_]*\s*=\s*[\"']?\$\(\s*%s\b"
            % re.escape(executable),
            _strip_shell_comment(line),
        )
        if (tokens and tokens[0] == executable) or command_substitution:
            matches.append(line)
    return matches


def _python_heredocs(body):
    """Extract Python heredoc payloads from one shell function body."""
    lines = body.splitlines()
    payloads = []
    index = 0
    while index < len(lines):
        command = lines[index]
        while re.search(r"(?<!\\)\\\s*$", command) and index + 1 < len(lines):
            command = re.sub(r"\\\s*$", " ", command) + lines[index + 1]
            index += 1
        delimiters = _heredoc_delimiters(command)
        tokens = _command_tokens(command)
        if delimiters and "python3" in tokens:
            delimiter = delimiters[0]
            payload = []
            index += 1
            while index < len(lines) and lines[index].strip() != delimiter:
                payload.append(lines[index])
                index += 1
            if index >= len(lines):
                raise ValueError("unterminated Python heredoc %s" % delimiter)
            payloads.append("\n".join(payload))
        index += 1
    return payloads


def _assignment_names(target):
    if isinstance(target, ast.Name):
        return [target.id]
    if isinstance(target, (ast.Tuple, ast.List)):
        names = []
        for element in target.elts:
            names.extend(_assignment_names(element))
        return names
    return []


def _ast_assignment_counts(tree):
    counts = {}
    for node in tree.body:
        targets = []
        if isinstance(node, ast.Assign):
            targets = node.targets
        elif isinstance(node, (ast.AnnAssign, ast.AugAssign)):
            targets = [node.target]
        for target in targets:
            for name in _assignment_names(target):
                counts[name] = counts.get(name, 0) + 1
    return counts


def _ast_assignment_sources(tree):
    sources = {}
    for node in tree.body:
        if isinstance(node, ast.Assign):
            targets = node.targets
            value = node.value
        elif isinstance(node, ast.AnnAssign):
            targets = [node.target]
            value = node.value
        elif isinstance(node, ast.AugAssign):
            targets = [node.target]
            value = node.value
        else:
            continue
        dumped = ast.dump(value, include_attributes=False)
        for target in targets:
            for name in _assignment_names(target):
                sources.setdefault(name, []).append(dumped)
    return sources


def _early_python_termination(tree, before_line):
    """Find explicit interpreter exits reachable before required evidence asserts."""
    forbidden = []
    for node in ast.walk(tree):
        if getattr(node, "lineno", before_line) >= before_line:
            continue
        if isinstance(node, ast.Raise):
            forbidden.append(node)
            continue
        if not isinstance(node, ast.Call):
            continue
        target = node.func
        if isinstance(target, ast.Name) and target.id in ("exit", "quit"):
            forbidden.append(node)
        elif (
            isinstance(target, ast.Attribute)
            and isinstance(target.value, ast.Name)
            and target.value.id in ("sys", "os")
            and target.attr in ("exit", "_exit")
        ):
            forbidden.append(node)
    return forbidden


def _nested_python_reader_errors(helper, tree):
    errors = []
    functions = {
        node.name: node
        for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    required = {}
    if helper in (
        "assert_exact_selector_state",
        "assert_more_specific_selector_state",
        "assert_legacy_repair_evidence",
        "assert_selector_cleanup_state",
    ):
        required["entries"] = (
            "id='load'", "id='scope'", "value='key'", "value='value'",
            "id='struct'", "id='ipaddress'",
        )
    if helper in ("assert_exact_selector_state", "assert_more_specific_selector_state"):
        required["bank"] = (
            "id='open'", "id='root'", "id='label'",
            "value='-runtime-compatibility.txt'", "id='int'",
        )
    if helper == "assert_legacy_repair_evidence":
        required["repair_counts"] = (
            "id='open'", "id='root'", "id='label'",
            "value='-datapath.log'", "value='neutron_acl_apply_profile'",
            "value='ifname='", "id='ifname'", "value='port_id='", "id='port_id'",
            "value='selector_repair_performed=true'",
            "value='selector_repair_performed=false'",
            "id='true_count'", "id='false_count'",
        )
        required["repair_required_count"] = (
            "id='open'", "id='root'", "id='label'",
            "value='-datapath.log'",
            "value='quiesced repairable preexisting ACL projection pending Neutron resync'",
            "value='instance='", "id='ifname'", "id='sum'",
        )
    for name, fragments in required.items():
        node = functions.get(name)
        dumped = ast.dump(node, include_attributes=False) if node is not None else ""
        if not dumped or not all(fragment in dumped for fragment in fragments):
            errors.append(
                "%s nested reader %s must decode its captured artifact" % (helper, name)
            )
            if helper == "assert_legacy_repair_evidence" and name == "repair_counts":
                errors.append(
                    "legacy repair profile counts must bind target ifname and port_id"
                )
            continue
        for child in ast.walk(node):
            if isinstance(child, ast.Return) and isinstance(child.value, (ast.Tuple, ast.List)):
                if any(isinstance(value, ast.Constant) for value in child.value.elts):
                    errors.append(
                        "%s nested reader %s must not return fabricated constants"
                        % (helper, name)
                    )
    return errors


def _top_level_assert_dumps(tree):
    return {
        ast.dump(node.test, include_attributes=False)
        for node in tree.body
        if isinstance(node, ast.Assert)
    }


def _assert_dump(expression):
    return ast.dump(ast.parse(expression, mode="eval").body, include_attributes=False)


def ordered(body, terms):
    position = -1
    for term in terms:
        position = body.find(term, position + 1)
        if position < 0:
            return False
    return True


def _parser_self_test_errors():
    fixture = r'''python3 <<'PY'
nested() {
    fake_heredoc_call
}
PY
nested() {
    if true; then
        printf '%s\n' "${value:-{\"nested\":true}}"
        printf '%s\n' "<<NOT_A_HEREDOC"
        command || {
            echo "fallback"
}
    fi
    python3 <<'PY'
payload={"looks": "like a }"}
PY
    command <<FIRST <<'SECOND'
first payload }
FIRST
second payload {
SECOND
    :;# } must remain a shell comment boundary
    final_call
}
after() { :; }
function keyword_style { keyword_call; }
function keyword_paren_style(){ keyword_paren_call; }
top_call
'''
    errors = []
    try:
        body = function_body(fixture, "nested")
    except (KeyError, ValueError) as exc:
        return ["brace-aware parser rejected nested fixture: %s" % exc]
    if (
        "final_call" not in body
        or "fake_heredoc_call" in body
        or "after()" in body
    ):
        errors.append("brace-aware parser truncated or overran nested fixture")
    logical_body = "\n".join(_logical_shell_lines(body))
    if "first payload" in logical_body or "second payload" in logical_body:
        errors.append("logical shell parser retained a queued heredoc payload")
    top_level = top_level_shell(fixture)
    if "top_call" not in top_level or "fake_heredoc_call" in top_level:
        errors.append("top-level shell parser retained a function/heredoc payload")
    main_fixture = r'''if python3 <<'PY'
first payload
PY
then
    :
fi
python3 <<'PY'
second payload
PY
run_deny_evidence
prepare_owned_selector_fixture
run_exact_selector_isolation_fixture
run_more_specific_selector_isolation_fixture
run_legacy_selector_repair_fixture
'''
    main_top_level = top_level_shell(main_fixture)
    fixture_calls = (
        "prepare_owned_selector_fixture",
        "run_exact_selector_isolation_fixture",
        "run_more_specific_selector_isolation_fixture",
        "run_legacy_selector_repair_fixture",
    )
    deny_positions = _depth_zero_bare_positions(
        main_top_level, "run_deny_evidence"
    )
    direct_positions = _ordered_unique_bare_calls(
        main_top_level, fixture_calls
    )
    if not (
        len(deny_positions) == 1
        and direct_positions
        and deny_positions[0] < direct_positions[0]
    ):
        errors.append(
            "top-level shell parser lost direct calls after queued heredocs"
        )
    try:
        inline = function_body("inline() { first; second; }", "inline")
    except (KeyError, ValueError) as exc:
        errors.append("brace-aware parser rejected inline fixture: %s" % exc)
    else:
        if not ordered(inline, ("first", "second")):
            errors.append("brace-aware parser lost inline function body")
    try:
        function_body("# hidden() { }", "hidden")
    except KeyError:
        pass
    else:
        errors.append("brace-aware parser accepted comment-only function")
    for name, call in (
        ("keyword_style", "keyword_call"),
        ("keyword_paren_style", "keyword_paren_call"),
    ):
        try:
            styled = function_body(fixture, name)
        except (KeyError, ValueError) as exc:
            errors.append("shell parser rejected %s definition: %s" % (name, exc))
        else:
            if call not in styled:
                errors.append("shell parser lost %s body" % name)
    counts = _function_definition_counts(fixture)
    if counts.get("nested") != 1 or counts.get("keyword_style") != 1 or counts.get("keyword_paren_style") != 1:
        errors.append("shell parser did not count all supported function definition forms")
    if _shell_code(":;# }").count("}"):
        errors.append("shell parser failed to recognize ;# comment boundary")
    return errors


SELECTOR_FIXTURE_FUNCTIONS = (
    "prepare_owned_selector_fixture",
    "cleanup_selector_rule_attempt",
    "capture_selector_projection",
    "run_unchecked_selector_traffic",
    "assert_selector_traffic_result",
    "run_captured_selector_flow",
    "reverify_selector_deny_baseline",
    "resolve_selector_group_id",
    "create_selector_fixture_group",
    "delete_selector_fixture_group",
    "cleanup_selector_group_attempt",
    "require_wider_owned_selector",
    "apply_owned_acl_semantic_delta",
    "remove_owned_acl_semantic_delta",
    "assert_selector_deny_drop_ct_zero",
    "assert_exact_selector_state",
    "assert_more_specific_selector_state",
    "inject_legacy_selector_pollution",
    "wait_neutron_uds",
    "wait_managed_port_reattached",
    "restart_managed_datapath",
    "capture_datapath_log_cursor",
    "capture_datapath_logs_since",
    "assert_projection_repair_required",
    "assert_legacy_pollution_evidence",
    "assert_legacy_repair_evidence",
    "assert_selector_cleanup_state",
    "cleanup_selector_fixture_state",
    "run_exact_selector_isolation_fixture",
    "run_more_specific_selector_isolation_fixture",
    "run_legacy_selector_repair_fixture",
)

SELECTOR_FIXTURE_STATUS_CONTRACTS = (
    (
        "run_exact_selector_isolation_fixture",
        "EXACT_SELECTOR_FIXTURE_STATUS",
        "exact",
        "reverify_selector_deny_baseline exact-cleanup",
    ),
    (
        "run_more_specific_selector_isolation_fixture",
        "MORE_SPECIFIC_SELECTOR_FIXTURE_STATUS",
        "more_specific",
        "reverify_selector_deny_baseline more-specific-cleanup",
    ),
    (
        "run_legacy_selector_repair_fixture",
        "LEGACY_SELECTOR_REPAIR_FIXTURE_STATUS",
        "legacy_repair",
        "reverify_selector_deny_baseline legacy-cleanup",
    ),
)


def _has_ipv4_only_guard(body):
    pattern = re.compile(
        r'^\s*\[\s+"\$\{IP_FAMILY\}"\s+=\s+ipv4\s+\]\s+'
        r'\|\|\s+return\s+0\s*$'
    )
    return any(pattern.match(_strip_shell_comment(line)) for line in _logical_shell_lines(body))


def _ordered_unique_bare_calls(body, commands):
    positions = []
    for command in commands:
        command_positions = _depth_zero_bare_positions(body, command)
        if len(command_positions) != 1:
            return None
        positions.append(command_positions[0])
    return positions if positions == sorted(positions) else None


def _alias_wrapper_call_position(main_body, wrapper_name):
    """Resolve a depth-zero immutable alias assignment followed by exact call."""
    lines = list(_shell_lines_with_depth(main_body))
    assignment = re.compile(
        r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*[\"']?"
        + re.escape(wrapper_name)
        + r"[\"']?\s*$"
    )
    for index, (line, depth) in enumerate(lines):
        if depth != 0:
            continue
        match = assignment.match(_strip_shell_comment(line))
        if not match:
            continue
        alias = match.group(1)
        reassignment = re.compile(
            r"^\s*(?:(?:export|readonly|local)\s+)?%s\s*(?:\+?=)|^\s*unset\s+%s\b"
            % (re.escape(alias), re.escape(alias))
        )
        invocation = re.compile(
            r'^\s*(?:"\$\{%s\}"|"\$%s"|\$\{%s\}|\$%s)\s*$'
            % tuple(re.escape(alias) for _ in range(4))
        )
        for later, (candidate, candidate_depth) in enumerate(
            lines[index + 1 :], start=index + 1
        ):
            text = _strip_shell_comment(candidate)
            if reassignment.match(text):
                break
            if candidate_depth == 0 and invocation.match(text):
                return sum(len(item[0]) + 1 for item in lines[:later])
    return None


def _selector_fixture_invocation_errors(source, bodies, definition_counts):
    fixture_calls = (
        "prepare_owned_selector_fixture",
        "run_exact_selector_isolation_fixture",
        "run_more_specific_selector_isolation_fixture",
        "run_legacy_selector_repair_fixture",
    )
    errors = []
    main_body = source.split("trap cleanup EXIT\n", 1)[-1]
    main_top_level = top_level_shell(main_body)
    deny_positions = _depth_zero_bare_positions(
        main_top_level, "run_deny_evidence"
    )
    direct_positions = _ordered_unique_bare_calls(
        main_top_level, fixture_calls
    )
    direct_ok = bool(
        len(deny_positions) == 1
        and direct_positions
        and deny_positions[0] < direct_positions[0]
    )
    if direct_ok:
        if not all(_has_ipv4_only_guard(bodies[name]) for name in fixture_calls):
            errors.append(
                "managed selector fixtures must be invoked directly or through one orchestration wrapper with explicit IPv4-only guards"
            )
        return errors

    wrapper_candidates = []
    for wrapper_name, count in definition_counts.items():
        if wrapper_name in SELECTOR_FIXTURE_FUNCTIONS or count != 1:
            continue
        try:
            wrapper_body = function_body(source, wrapper_name)
        except (KeyError, ValueError):
            continue
        positions = _ordered_unique_bare_calls(wrapper_body, fixture_calls)
        if positions is not None:
            wrapper_candidates.append((wrapper_name, wrapper_body))
    if len(wrapper_candidates) != 1:
        errors.append(
            "managed selector fixtures must be invoked directly or through one orchestration wrapper with one unique definition"
        )
        return errors

    wrapper_name, wrapper_body = wrapper_candidates[0]
    if not _has_ipv4_only_guard(wrapper_body):
        errors.append(
            "managed selector fixtures must be invoked directly or through one orchestration wrapper with an explicit IPv4-only guard"
        )
    direct_wrapper_positions = _depth_zero_bare_positions(
        main_top_level, wrapper_name
    )
    wrapper_call_position = (
        direct_wrapper_positions[0]
        if len(direct_wrapper_positions) == 1
        else _alias_wrapper_call_position(main_top_level, wrapper_name)
    )
    if not (
        len(deny_positions) == 1
        and wrapper_call_position is not None
        and deny_positions[0] < wrapper_call_position
    ):
        errors.append(
            "managed selector fixtures must be invoked directly or through one orchestration wrapper by one depth-zero bare call after deny evidence"
        )
    return errors


def _literal_shell_assignments(body, variable):
    """Return literal status assignments with their shell-control depth."""
    assignments = []
    pattern = re.compile(
        r'^\s*%s\s*=\s*(["\'])([^"\']+)\1\s*$'
        % re.escape(variable)
    )
    for line, depth in _shell_lines_with_depth(body):
        match = pattern.match(_strip_shell_comment(line))
        if match:
            assignments.append((match.group(2), depth))
    return assignments


def _top_level_assignment(tree, name):
    matches = []
    for node in tree.body:
        if not isinstance(node, ast.Assign):
            continue
        if any(
            isinstance(target, ast.Name) and target.id == name
            for target in node.targets
        ):
            matches.append(node.value)
    return matches


def _literal_dict(node):
    if not isinstance(node, ast.Dict):
        return None
    entries = {}
    for key, value in zip(node.keys, node.values):
        if not isinstance(key, ast.Constant) or not isinstance(key.value, str):
            return None
        if key.value in entries:
            return None
        entries[key.value] = value
    return entries


def _environment_lookup_name(node):
    if not isinstance(node, ast.Subscript):
        return None
    owner = node.value
    if not (
        isinstance(owner, ast.Attribute)
        and isinstance(owner.value, ast.Name)
        and owner.value.id == "os"
        and owner.attr == "environ"
    ):
        return None
    key = node.slice
    if isinstance(key, ast.Constant) and isinstance(key.value, str):
        return key.value
    return None


def _selector_fixture_status_contract_errors(source, bodies=None):
    """Require honest per-fixture lifecycle state and closure-safe summary."""
    errors = []
    bodies = {} if bodies is None else dict(bodies)
    for helper, _variable, _key, _anchor in SELECTOR_FIXTURE_STATUS_CONTRACTS:
        if helper not in bodies:
            try:
                bodies[helper] = function_body(source, helper)
            except (KeyError, ValueError) as exc:
                errors.append(
                    "selector fixture status contract missing %s (%s)"
                    % (helper, exc)
                )
    if "write_summary" not in bodies:
        try:
            bodies["write_summary"] = function_body(source, "write_summary")
        except (KeyError, ValueError) as exc:
            errors.append(
                "selector fixture status contract missing write_summary (%s)" % exc
            )
    if errors:
        return errors

    top_level = top_level_shell(source)
    expected_fixture_env = {}
    for helper, variable, key, completion_anchor in SELECTOR_FIXTURE_STATUS_CONTRACTS:
        expected_fixture_env[key] = variable
        initializers = _literal_shell_assignments(top_level, variable)
        if initializers != [("not_run", 0)]:
            errors.append(
                "%s global status must initialize exactly once to not_run"
                % helper
            )

        body = bodies.get(helper, "")
        assignments = _literal_shell_assignments(body, variable)
        if assignments != [
            ("skipped_ipv6", 1),
            ("failed", 0),
            ("pass", 0),
        ]:
            errors.append(
                "%s status must transition through conditional skipped_ipv6 or fail-closed failed before pass"
                % helper
            )
        if not ordered(
            body,
            (
                'if [ "${IP_FAMILY}" = ipv6 ]; then',
                '%s="skipped_ipv6"' % variable,
                "fi",
                '[ "${IP_FAMILY}" = ipv4 ] || return 0',
                '%s="failed"' % variable,
                completion_anchor,
                '%s="pass"' % variable,
            ),
        ):
            errors.append(
                "%s status must preserve the explicit IPv4 guard and mark pass only after its final proof"
                % helper
            )
        completion_commands = [
            (_strip_shell_comment(line).strip(), depth)
            for line, depth in _shell_lines_with_depth(body)
            if _strip_shell_comment(line).strip() == completion_anchor
        ]
        if completion_commands != [(completion_anchor, 0)]:
            errors.append(
                "%s final proof must be one depth-zero exact command"
                % helper
            )
        logical = list(_logical_shell_lines(body))
        if not logical or logical[-1].strip() != '%s="pass"' % variable:
            errors.append(
                "%s pass status must be the final successful fixture command"
                % helper
            )

    summary = bodies.get("write_summary", "")
    for variable in expected_fixture_env.values():
        binding = '%s="${%s}"' % (variable, variable)
        assignments = re.findall(
            r"(?<![A-Za-z0-9_])%s\s*=" % re.escape(variable), summary
        )
        if (
            summary.count(binding) != 1
            or len(assignments) != 1
            or summary.count(variable) != 3
        ):
            errors.append(
                "write_summary must export only the real %s value exactly once"
                % variable
            )

    try:
        payloads = _python_heredocs(summary)
    except ValueError as exc:
        errors.append("selector isolation summary Python is malformed: %s" % exc)
        return errors
    summary_trees = []
    for payload in payloads:
        try:
            tree = ast.parse(payload)
        except SyntaxError:
            continue
        if _top_level_assignment(tree, "out"):
            summary_trees.append(tree)
    if len(summary_trees) != 1:
        errors.append(
            "write_summary must contain one Python summary payload with selector isolation state"
        )
        return errors
    tree = summary_trees[0]

    imports = [node for node in tree.body if isinstance(node, ast.Import)]
    assignments = [node for node in tree.body if isinstance(node, ast.Assign)]
    expressions = [node for node in tree.body if isinstance(node, ast.Expr)]
    allowed_assignment_names = {
        "keys",
        "cleanup_errors",
        "selector_fixtures",
        "selector_isolation",
        "out",
    }
    assignment_names = []
    assignment_shape_ok = True
    for assignment in assignments:
        if (
            len(assignment.targets) != 1
            or not isinstance(assignment.targets[0], ast.Name)
        ):
            assignment_shape_ok = False
            continue
        assignment_names.append(assignment.targets[0].id)
    import_shape_ok = bool(
        len(imports) == 1
        and [(alias.name, alias.asname) for alias in imports[0].names]
        == [("json", None), ("os", None)]
    )
    if (
        any(
            not isinstance(node, (ast.Import, ast.Assign, ast.Expr))
            for node in tree.body
        )
        or not import_shape_ok
        or any(isinstance(node, ast.NamedExpr) for node in ast.walk(tree))
        or not assignment_shape_ok
        or len(assignment_names) != len(set(assignment_names))
        or not {"selector_fixtures", "selector_isolation", "out"}.issubset(
            assignment_names
        )
        or not set(assignment_names).issubset(allowed_assignment_names)
        or len(expressions) != 1
    ):
        errors.append(
            "selector isolation summary Python must use one json/os import, unique allowed assignments, and one output expression"
        )

    fixture_assignments = _top_level_assignment(tree, "selector_fixtures")
    fixture_entries = (
        _literal_dict(fixture_assignments[0])
        if len(fixture_assignments) == 1
        else None
    )
    if fixture_entries is None or set(fixture_entries) != set(expected_fixture_env):
        errors.append(
            "selector_isolation.fixtures must contain exact, more_specific, and legacy_repair"
        )
    else:
        for key, variable in expected_fixture_env.items():
            if _environment_lookup_name(fixture_entries[key]) != variable:
                errors.append(
                    "selector_isolation fixture %s must come from real env status %s"
                    % (key, variable)
                )

    isolation_assignments = _top_level_assignment(tree, "selector_isolation")
    isolation_entries = (
        _literal_dict(isolation_assignments[0])
        if len(isolation_assignments) == 1
        else None
    )
    if isolation_entries is None or set(isolation_entries) != {"fixtures", "complete"}:
        errors.append(
            "selector_isolation summary must contain fixtures and complete"
        )
    else:
        fixtures_value = isolation_entries["fixtures"]
        if not (
            isinstance(fixtures_value, ast.Name)
            and fixtures_value.id == "selector_fixtures"
        ):
            errors.append(
                "selector_isolation.fixtures must use the three real fixture statuses"
            )
        expected_complete = ast.dump(
            ast.parse(
                'all(status == "pass" for status in selector_fixtures.values())',
                mode="eval",
            ).body,
            include_attributes=False,
        )
        if ast.dump(
            isolation_entries["complete"], include_attributes=False
        ) != expected_complete:
            errors.append(
                "selector_isolation.complete must be all(status == 'pass') over real fixture statuses"
            )

    out_assignments = _top_level_assignment(tree, "out")
    out_entries = (
        _literal_dict(out_assignments[0]) if len(out_assignments) == 1 else None
    )
    isolation_value = (
        out_entries.get("selector_isolation") if out_entries is not None else None
    )
    if not (
        isinstance(isolation_value, ast.Name)
        and isolation_value.id == "selector_isolation"
    ):
        errors.append(
            "summary.json must publish selector_isolation from the validated fixture state"
        )
    expected_print = ast.dump(
        ast.parse(
            "print(json.dumps(out, sort_keys=True, indent=2))"
        ).body[0],
        include_attributes=False,
    )
    print_statements = [
        node
        for node in tree.body
        if isinstance(node, ast.Expr)
        and isinstance(node.value, ast.Call)
        and isinstance(node.value.func, ast.Name)
        and node.value.func.id == "print"
    ]
    if (
        len(print_statements) != 1
        or ast.dump(print_statements[0], include_attributes=False)
        != expected_print
    ):
        errors.append(
            "summary writer must print json.dumps(out) exactly once"
        )
    return errors


def _python_contract_errors(bodies):
    """Validate reachable Python evidence and single-source measurements."""
    contracts = {
        "assert_selector_traffic_result": (
            ("expectation in ('pass', 'deny')", "actual_pass is expected_pass"),
            ("traffic_rc", "expectation", "expected_pass", "actual_pass"),
        ),
        "assert_exact_selector_state": (
            (
                "exact_before_bank == exact_after_bank",
                "exact_before_groups != exact_after_groups",
                "exact_before_general != exact_after_general",
                "exact_before_acl_entries == exact_acl_entries",
                "exact_acl_entries[selector_cidr] == selector_group_id",
                "selector_group_id in exact_acl_ids",
                "local_group_id not in exact_acl_ids",
                "exact_cleanup_general_entries[selector_cidr] == selector_group_id",
                "selector_group_id in exact_cleanup_general_ids",
                "local_group_id not in exact_cleanup_general_ids",
            ),
            (
                "exact_before_bank", "exact_after_bank", "exact_before_groups",
                "exact_after_groups", "exact_before_general", "exact_after_general",
                "exact_before_acl_entries", "exact_acl_entries", "exact_acl_ids",
                "exact_cleanup_general_entries", "exact_cleanup_general_ids", "tap",
            ),
        ),
        "assert_more_specific_selector_state": (
            (
                "old_bank != new_bank",
                "new_general_entries[more_specific_key] == more_specific_group_id",
                "more_specific_group_id in new_general_ids",
                "more_specific_key not in new_acl_keys",
                "more_specific_group_id not in new_acl_ids",
                "new_acl_entries[selector_cidr] == selector_group_id",
                "selector_group_id in new_acl_ids",
            ),
            (
                "old_bank", "new_bank", "new_general_entries", "new_acl_entries",
                "new_general_ids", "new_acl_ids", "new_acl_keys", "tap",
            ),
        ),
        "assert_projection_repair_required": (
            (
                "item.get('name') == ifname",
                "target_port.get('port_id') == port_id",
                "target_port.get('ifname') == ifname",
                "tc_ingress_live is True",
                "tc_egress_live is True",
                "links_intact is True",
                "readiness_reason == 'recovery_required'",
                "projection_reason is not None",
                "expected_projection_reason in projection_reason",
                "('instance=' + ifname) in projection_reason",
                "repair_required is True",
                "acl_ready is False",
                "config['acl'] is False",
            ),
            (
                "instances", "config", "projection_log", "tc_ingress", "tc_egress",
                "link_text", "port_payload", "item", "port_rows", "target_port",
                "acl_ready", "readiness_reason", "projection_reason",
                "tc_ingress_live", "tc_egress_live", "links_intact", "repair_required",
                "ifname", "port_id",
            ),
        ),
        "assert_legacy_pollution_evidence": (
            (
                "polluted_acl_value == legacy_local_group_id",
                "bad_traffic_rc == 0", "bad_ct_count > 0",
                "bad_ct_packets > 0", "bad_ct_bytes > 0",
            ),
            (
                "polluted_acl_value", "payload", "bank", "iface", "tap_id",
                "bad_traffic_rc", "bad_ct_count", "bad_ct_packets", "bad_ct_bytes",
            ),
        ),
        "assert_legacy_repair_evidence": (
            (
                "injected_bank == polluted_bank", "polluted_bank != repaired_bank",
                "repaired_acl_value == selector_group_id", "repaired_ct_count == 0",
                "repaired_drop_delta > 0", "repaired_bank == equal_before_bank",
                "equal_before_bank == equal_bank", "repaired_bank == equal_bank",
                "equal_bank == restart_bank", "repair_true_count == 1",
                "equal_true_count == 0", "equal_false_count >= 1",
                "restart_true_count == 0", "restart_repair_required_count == 0",
                "clean_active_entries[selector_cidr] == selector_group_id",
                "legacy_local_group_id not in clean_general_ids",
                "legacy_local_group_id not in clean_bank_zero_ids",
                "legacy_local_group_id not in clean_bank_one_ids",
                "inventory_clean is True", "second_repair_switch is False",
            ),
            (
                "iface", "tap_id", "repaired_acl_value", "clean_general_entries",
                "clean_bank_zero_entries", "clean_bank_one_entries",
                "clean_general_ids", "clean_bank_zero_ids",
                "clean_bank_one_ids", "clean_active_entries", "repair_true_count",
                "repair_false_count",
                "equal_true_count", "equal_false_count", "restart_true_count",
                "restart_repair_required_count", "instances", "config", "item",
                "inventory_clean", "second_repair_switch", "ifname", "port_id",
            ),
        ),
        "assert_selector_cleanup_state": (
            (
                "polluted_group_id not in acl_bank_zero_ids",
                "polluted_group_id not in acl_bank_one_ids",
                "active_acl_entries[selector_cidr] == selector_group_id",
                "inactive_selector_value in allowed_inactive_selector_values",
                "selector_rule_id in live_rule_ids",
                "baseline_selector_rule.get('policy_id') == policy_id",
                "baseline_selector_rule.get('direction') == 'ingress'",
                "baseline_selector_rule.get('priority') == 100",
                "baseline_selector_rule.get('action') == 'drop'",
                "baseline_selector_rule.get('protocol') == protocol",
                "baseline_selector_rule.get('src_cidr') == selector_cidr",
                "len(semantic_delta_matches) == 0",
                "semantic_delta_rule_id not in live_rule_ids",
                "attempted_group_names.intersection(live_group_names) == expected_live_group_names",
                "local_cidrs.isdisjoint(general_keys)",
                "local_group_ids.isdisjoint(general_ids)",
                "local_group_ids.isdisjoint(acl_bank_zero_ids)",
                "local_group_ids.isdisjoint(acl_bank_one_ids)",
                "general_entries[selector_cidr] == expected_general_group_id",
                "acl_ready is True", "config['acl'] is True",
            ),
            (
                "iface", "tap_id", "live_rule_ids", "live_group_names",
                "general_entries", "acl_bank_zero_entries", "acl_bank_one_entries",
                "neutron_rules", "live_groups", "instances", "item",
                "general_keys", "general_ids",
                "acl_bank_zero_ids", "acl_bank_one_ids", "acl_ready", "config",
                "expected_general_group_id", "active_bank", "active_acl_entries",
                "inactive_acl_entries", "inactive_selector_value",
                "allowed_inactive_selector_values", "baseline_selector_rule",
                "semantic_delta_matches",
            ),
        ),
    }
    bindings = {
        "assert_selector_traffic_result": {
            "traffic_rc": ("id='int'", "id='traffic_rc_raw'"),
            "expectation": ("id='expectation_raw'",),
            "expected_pass": ("id='expectation'", "value='pass'"),
            "actual_pass": ("id='traffic_rc'", "value=0"),
        },
        "assert_exact_selector_state": {
            "exact_before_bank": ("id='bank'", "value='exact-before'"),
            "exact_after_bank": ("id='bank'", "value='exact-local'"),
            "exact_before_groups": ("id='load'", "value='exact-before-groups.json'"),
            "exact_after_groups": ("id='load'", "value='exact-local-groups.json'"),
            "exact_before_general": ("id='entries'", "value='exact-before'", "value='general-src'"),
            "exact_after_general": ("id='entries'", "value='exact-local'", "value='general-src'"),
            "exact_before_acl_entries": ("id='entries'", "value='exact-before'", "value='acl-src'"),
            "exact_acl_entries": ("id='entries'", "value='exact-local'", "value='acl-src'"),
            "exact_acl_ids": ("id='set'", "id='exact_acl_entries'"),
            "exact_cleanup_general_entries": ("id='entries'", "value='exact-cleanup'", "value='general-src'"),
            "exact_cleanup_general_ids": ("id='set'", "id='exact_cleanup_general_entries'"),
            "tap": ("id='tap_id'", "value='exact-local'"),
        },
        "assert_more_specific_selector_state": {
            "old_bank": ("id='bank'", "value='more-specific-before-delta'"),
            "new_bank": ("id='bank'", "value='more-specific-after-delta'"),
            "new_general_entries": ("id='entries'", "value='more-specific-after-delta'", "value='general-src'"),
            "new_acl_entries": ("id='entries'", "value='more-specific-after-delta'", "value='acl-src'"),
            "new_general_ids": ("id='set'", "id='new_general_entries'"),
            "new_acl_ids": ("id='set'", "id='new_acl_entries'"),
            "new_acl_keys": ("id='set'", "id='new_acl_entries'"),
            "tap": ("id='tap_id'", "value='more-specific-after-delta'"),
        },
        "assert_projection_repair_required": {
            "instances": ("id='json'", "id='open'", "id='sys'", "value=1", "value='instances'"),
            "config": ("id='json'", "id='open'", "id='sys'", "value=2"),
            "projection_log": ("id='open'", "id='sys'", "value=3", "attr='read'"),
            "tc_ingress": ("id='json'", "id='open'", "id='sys'", "value=4"),
            "tc_egress": ("id='json'", "id='open'", "id='sys'", "value=5"),
            "link_text": ("id='open'", "id='sys'", "value=6", "attr='read'"),
            "port_payload": ("id='json'", "id='open'", "id='sys'", "value=7"),
            "ifname": ("id='sys'", "value=8"),
            "port_id": ("id='sys'", "value=8"),
            "item": ("id='instances'", "id='ifname'"),
            "port_rows": ("id='port_payload'", "value='aria_acl_port_statuses'", "value='port_statuses'"),
            "target_port": ("id='port_rows'", "id='port_id'", "id='ifname'"),
            "readiness_reason": ("id='item'", "value='readiness_reason'"),
            "projection_reason": (
                "id='next'", "id='projection_log'", "id='expected_projection_reason'",
                "value='instance='", "id='ifname'",
            ),
            "tc_ingress_live": ("id='tc_ingress'", "value='bpf'"),
            "tc_egress_live": ("id='tc_egress'", "value='bpf'"),
            "links_intact": ("id='tc_ingress_live'", "id='tc_egress_live'", "id='link_text'", "id='ifname'"),
            "repair_required": (
                "id='acl_ready'", "id='config'", "id='readiness_reason'",
                "value='recovery_required'", "id='projection_reason'", "id='target_port'",
            ),
        },
        "assert_legacy_pollution_evidence": {
            "bad_traffic_rc": ("id='int'", "id='bad_traffic_rc_raw'"),
            "bad_ct_count": ("id='int'", "id='bad_ct_count_raw'"),
            "bad_ct_packets": ("id='int'", "id='bad_ct_packets_raw'"),
            "bad_ct_bytes": ("id='int'", "id='bad_ct_bytes_raw'"),
            "polluted_acl_value": ("id='lookup'", "id='payload'", "id='tap_id'", "id='bank'"),
            "bank": ("id='open'", "id='root'", "value='legacy-polluted-after-runtime-compatibility.txt'"),
            "iface": ("id='json'", "id='open'", "id='root'", "value='legacy-polluted-after-iface-ctx.json'"),
            "tap_id": ("id='struct'", "id='iface'", "value='value'"),
            "payload": ("id='json'", "id='open'", "id='root'", "value='legacy-polluted-after-acl-src-map.json'"),
        },
        "assert_legacy_repair_evidence": {
            "iface": ("id='json'", "id='open'", "id='root'", "value='legacy-repaired-iface-ctx.json'"),
            "tap_id": ("id='struct'", "id='iface'", "value='value'"),
            "repaired_acl_value": ("id='entries'", "value='legacy-repaired'", "id='repaired_bank'"),
            "clean_general_entries": ("id='entries'", "value='legacy-clean-restart'", "value='general-src'"),
            "clean_bank_zero_entries": ("id='entries'", "value='legacy-clean-restart'", "value='acl-src'", "id='tap_id'"),
            "clean_bank_one_entries": ("id='entries'", "value='legacy-clean-restart'", "value='acl-src'", "id='tap_id'", "value=1"),
            "clean_general_ids": ("id='set'", "id='clean_general_entries'"),
            "clean_bank_zero_ids": ("id='set'", "id='clean_bank_zero_entries'"),
            "clean_bank_one_ids": ("id='set'", "id='clean_bank_one_entries'"),
            "clean_active_entries": ("id='clean_bank_zero_entries'", "id='restart_bank'", "id='clean_bank_one_entries'"),
            "repair_true_count": ("id='repair_counts'", "value='legacy-repair'"),
            "repair_false_count": ("id='repair_counts'", "value='legacy-repair'"),
            "equal_true_count": ("id='repair_counts'", "value='legacy-equal'"),
            "equal_false_count": ("id='repair_counts'", "value='legacy-equal'"),
            "restart_true_count": ("id='repair_counts'", "value='legacy-clean-restart'", "value=0"),
            "restart_repair_required_count": ("id='repair_required_count'", "value='legacy-clean-restart'"),
            "ifname": ("id='sys'", "value=1"),
            "port_id": ("id='sys'", "value=1"),
            "instances": ("id='json'", "id='open'", "id='root'", "value='legacy-clean-restart-instances.json'"),
            "config": ("id='json'", "id='open'", "id='root'", "value='legacy-clean-restart-config.json'"),
            "item": ("id='instances'", "id='ifname'"),
            "inventory_clean": (
                "id='item'", "value='active'", "value='acl_ready'",
                "value='readiness_reason'", "value=None", "id='config'",
                "value='acl'",
            ),
            "second_repair_switch": ("id='equal_bank'", "id='restart_bank'"),
        },
        "assert_selector_cleanup_state": {
            "iface": ("id='load'", "id='label'", "value='-iface-ctx.json'"),
            "tap_id": ("id='struct'", "id='iface'", "value='value'"),
            "general_entries": ("id='entries'", "value='general-src'", "value='general-dst'", "id='tap_id'"),
            "acl_bank_zero_entries": ("id='entries'", "value='acl-src'", "value='acl-dst'", "id='tap_id'"),
            "acl_bank_one_entries": ("id='entries'", "value='acl-src'", "value='acl-dst'", "id='tap_id'", "value=1"),
            "neutron_rules": ("id='load'", "id='label'", "value='-neutron-rules.json'", "value='aria_acl_rules'"),
            "live_groups": ("id='load'", "id='label'", "value='-groups.json'", "value='groups'"),
            "instances": ("id='load'", "id='label'", "value='-instances.json'", "value='instances'"),
            "config": ("id='load'", "id='label'", "value='-config.json'"),
            "item": ("id='instances'", "id='ifname'"),
            "live_rule_ids": ("id='neutron_rules'", "value='id'"),
            "live_group_names": ("id='live_groups'", "value='name'"),
            "general_keys": ("id='set'", "id='general_entries'"),
            "general_ids": ("id='set'", "id='general_entries'"),
            "acl_bank_zero_ids": ("id='set'", "id='acl_bank_zero_entries'"),
            "acl_bank_one_ids": ("id='set'", "id='acl_bank_one_entries'"),
            "expected_general_group_id": ("id='int'", "id='expected_general_group_id_raw'"),
            "active_bank": ("id='open'", "id='label'", "value='-runtime-compatibility.txt'"),
            "active_acl_entries": ("id='acl_bank_zero_entries'", "id='active_bank'", "id='acl_bank_one_entries'"),
            "inactive_acl_entries": ("id='acl_bank_one_entries'", "id='active_bank'", "id='acl_bank_zero_entries'"),
            "inactive_selector_value": ("id='inactive_acl_entries'", "id='selector_cidr'"),
            "allowed_inactive_selector_values": ("id='selector_group_id'", "value=None"),
            "baseline_selector_rule": ("id='neutron_rules'", "id='selector_rule_id'"),
            "semantic_delta_matches": ("id='neutron_rules'", "id='policy_id'", "value='ingress'", "value=200", "value='allow'", "value='tcp'", "id='selector_cidr'"),
        },
    }
    errors = []
    for helper, (assertions, protected) in contracts.items():
        try:
            payloads = _python_heredocs(bodies[helper])
        except ValueError as exc:
            errors.append("%s Python evidence is malformed: %s" % (helper, exc))
            continue
        if len(payloads) != 1:
            errors.append("%s must contain exactly one Python evidence heredoc" % helper)
            continue
        try:
            tree = ast.parse(payloads[0])
        except SyntaxError as exc:
            errors.append("%s Python evidence is invalid: %s" % (helper, exc))
            continue
        reachable = _top_level_assert_dumps(tree)
        required_dumps = {_assert_dump(expression) for expression in assertions}
        for expression in assertions:
            if _assert_dump(expression) not in reachable:
                errors.append(
                    "%s requires reachable top-level assert %s" % (helper, expression)
                )
        counts = _ast_assignment_counts(tree)
        for name in protected:
            if counts.get(name, 0) != 1:
                errors.append(
                    "%s measurement %s must have one immutable source" % (helper, name)
                )
        sources = _ast_assignment_sources(tree)
        for name, fragments in bindings.get(helper, {}).items():
            values = sources.get(name, [])
            if len(values) != 1 or not all(fragment in values[0] for fragment in fragments):
                errors.append(
                    "%s measurement %s must bind its exact captured RHS" % (helper, name)
                )
        if helper == "assert_projection_repair_required":
            projection_sources = sources.get("projection_reason", [])
            if (
                len(projection_sources) != 1
                or "value='instance='" not in projection_sources[0]
                or "id='ifname'" not in projection_sources[0]
            ):
                errors.append(
                    "repair-required projection reason must bind target instance"
                )
            readiness_assert = _assert_dump(
                "readiness_reason == 'recovery_required'"
            )
            if readiness_assert not in reachable:
                errors.append(
                    "repair-required readiness reason must be exactly recovery_required"
                )
        if helper == "assert_legacy_repair_evidence":
            clean_restart_assert = _assert_dump(
                "restart_repair_required_count == 0"
            )
            if clean_restart_assert not in reachable:
                errors.append(
                    "legacy clean restart must reject target repair-required reason"
                )
        required_lines = [
            node.lineno
            for node in tree.body
            if isinstance(node, ast.Assert)
            and ast.dump(node.test, include_attributes=False) in required_dumps
        ]
        if required_lines and _early_python_termination(tree, max(required_lines)):
            errors.append(
                "%s must not exit or raise before required evidence asserts" % helper
            )
        errors.extend(_nested_python_reader_errors(helper, tree))
    return errors


def _line_has_fail_return(line):
    return bool(re.search(r"\|\|\s*return\s+1\s*$", _strip_shell_comment(line)))


def _managed_selector_semantic_errors(source, bodies):
    """P1/P2 semantic checks that reject decoys and fabricated evidence."""
    errors = []
    protected_commands = (
        "bpftool", "ping", "curl", "docker", "tc", "ip", "date", "awk",
        "python3", "sleep", "mv", "rm",
    )
    definition_counts = _function_definition_counts(source)
    shadowed = [name for name in protected_commands if definition_counts.get(name, 0)]
    alias_pattern = re.compile(
        r"^\s*alias\s+(%s)\s*=" % "|".join(map(re.escape, protected_commands))
    )
    for line in _logical_shell_lines(source):
        match = alias_pattern.match(_strip_shell_comment(line))
        if match:
            shadowed.append(match.group(1))
    if shadowed:
        errors.append(
            "managed selector evidence forbids shadowing real commands: %s"
            % ", ".join(sorted(set(shadowed)))
        )
    global_shell = top_level_shell(source.split("trap cleanup EXIT\n", 1)[0])
    arm_position = global_shell.find("SELECTOR_FIXTURES_STARTED=false")
    for variable in (
        "exact_local_group_id", "more_specific_group_id", "legacy_local_group_id",
        "semantic_delta_rule_id", "selector_rule_id", "selector_group_id",
    ):
        match = re.search(
            r"(?m)^\s*%s=\"\"\s*$" % re.escape(variable), global_shell
        )
        if match is None or arm_position < 0 or match.start() > arm_position:
            errors.append(
                "cleanup variable %s must be globally initialized before selector fixtures arm"
                % variable
            )
    local_ids_init = re.search(
        r"(?m)^\s*selector_local_group_ids=\(\)\s*$", global_shell
    )
    if local_ids_init is None or arm_position < 0 or local_ids_init.start() > arm_position:
        errors.append(
            "cleanup variable selector_local_group_ids must be globally initialized before selector fixtures arm"
        )
    prepare = bodies["prepare_owned_selector_fixture"].replace('\\"', '"')
    resolver = bodies["resolve_selector_group_id"]
    deny_ct = bodies["assert_selector_deny_drop_ct_zero"]
    repair = bodies["assert_legacy_repair_evidence"]
    if '"direction":"ingress"' not in prepare:
        errors.append("Neutron selector fixture must still create ingress rules")
    selector_rule_commit = (
        'created_selector_rule_id="$(curl_body POST aria-acl-rules '
        '"${selector_rule_body}" | json_field aria_acl_rule.id)" || return 1',
        '[ -n "${created_selector_rule_id}" ] || return 1',
        'selector_rule_id="${created_selector_rule_id}"',
        'rule_ids+=("${selector_rule_id}")',
        'created_rule_ids+=("${selector_rule_id}")',
    )
    direct_global_selector_post = re.search(
        r'(?m)^\s*selector_rule_id="\$\(curl_body POST aria-acl-rules',
        prepare,
    )
    local_created_selector_id = re.search(
        r'(?m)^\s*local\b[^\n]*\bcreated_selector_rule_id\b',
        prepare,
    )
    if (
        local_created_selector_id is None
        or direct_global_selector_post is not None
        or not ordered(prepare, selector_rule_commit)
    ):
        errors.append(
            "selector rule create must commit global ID only after successful local parse"
        )
    if 'row.get("direction")=="egress"' not in resolver or 'row.get("direction")=="ingress"' in resolver:
        errors.append("translated local selector resolver must use egress direction")
    for helper_name, body in (("deny", deny_ct), ("legacy repair", repair)):
        counter_lines = _real_command_lines(body, "rule_counter_sum")
        if len(counter_lines) != 2 or any(
            not re.search(r"\begress\s+dropped_packets\b", line)
            for line in counter_lines
        ):
            errors.append("%s rule counters must measure translated egress drops" % helper_name)

    try:
        base_capture = function_body(source, "capture")
    except (KeyError, ValueError):
        base_capture = ""
    tc_capture_lines = _real_command_lines(base_capture, "tc")
    ip_capture_lines = _real_command_lines(base_capture, "ip")
    if (
        len(tc_capture_lines) != 2
        or not any(" ingress " in line and "${label}-tc-ingress.json" in line for line in tc_capture_lines)
        or not any(" egress " in line and "${label}-tc-egress.json" in line for line in tc_capture_lines)
        or any(not _line_has_fail_return(line) for line in tc_capture_lines)
        or len(ip_capture_lines) != 1
        or "${label}-link.txt" not in ip_capture_lines[0]
        or not _line_has_fail_return(ip_capture_lines[0])
    ):
        errors.append(
            "base capture must persist real link and tc-ingress/tc-egress artifacts with failure propagation"
        )

    capture = bodies["capture_selector_projection"]
    capture_commands = ("capture", "datapath_get", "curl_body", "bpftool")
    expected_counts = {"capture": 1, "datapath_get": 2, "curl_body": 1, "bpftool": 4}
    for command in capture_commands:
        lines = _real_command_lines(capture, command)
        if len(lines) != expected_counts[command] or any(
            not _line_has_fail_return(line) for line in lines
        ):
            errors.append("selector capture requires real %s commands with || return 1" % command)

    restart = bodies["restart_managed_datapath"]
    for command in ("docker", "wait_neutron_uds", "wait_managed_port_reattached"):
        lines = _real_command_lines(restart, command)
        if len(lines) != 1 or not _line_has_fail_return(lines[0]):
            errors.append("datapath restart requires real %s with || return 1" % command)
    for wait_name in ("wait_neutron_uds", "wait_managed_port_reattached"):
        wait_body = bodies[wait_name]
        if not _real_command_lines(wait_body, "curl") or not _real_command_lines(wait_body, "sleep"):
            errors.append("%s must execute real curl and sleep commands" % wait_name)
        sleep_lines = _real_command_lines(wait_body, "sleep")
        if any(not _line_has_fail_return(line) for line in sleep_lines) or not re.search(
            r"(?m)^\s*return\s+1\s*$", wait_body
        ):
            errors.append("%s must explicitly propagate timeout and sleep failure" % wait_name)

    reattach = bodies["wait_managed_port_reattached"]
    reattach_curls = _real_command_lines(reattach, "curl")
    if (
        len(reattach_curls) != 2
        or not any(
            '--unix-socket "${NEUTRON_UDS}"' in line
            and "/api/v1/neutron/status" in line
            for line in reattach_curls
        )
        or not any(
            '"${DATAPATH_HTTP}/api/v1/instances"' in line
            for line in reattach_curls
        )
    ):
        errors.append(
            "managed port re-attach wait must converge UDS and datapath instance state"
        )
    if 'assert len(active_matches)==1' not in reattach:
        errors.append(
            "managed port re-attach wait must require unique active instance"
        )
    phase_terms = (
        'expected_phase in ("recovery_required","ready","active")',
        'if expected_phase=="recovery_required"',
        'item.get("acl_ready") is False',
        'item.get("readiness_reason")=="recovery_required"',
        'elif expected_phase=="ready"',
        'item.get("acl_ready") is True',
        'item.get("readiness_reason") is None',
    )
    if any(term not in reattach for term in phase_terms):
        errors.append(
            "managed port re-attach wait must enforce recovery and ready phases"
        )

    pollution = bodies["inject_legacy_selector_pollution"]
    if len(_real_command_lines(pollution, "bpftool")) != 1:
        errors.append("legacy pollution requires one real bpftool map update")
    traffic = bodies["run_unchecked_selector_traffic"]
    if len(_real_command_lines(traffic, "ping")) != 1:
        errors.append("selector traffic requires one real ping command")
    captured = bodies["run_captured_selector_flow"]
    assignments = re.findall(r"(?m)^\s*traffic_rc\s*=\s*([^\s;]+)\s*$", captured)
    if assignments != ["0", "$?"]:
        errors.append("traffic_rc must come only from the real traffic branch before persistence")

    create = bodies["create_selector_fixture_group"]
    delete_group = bodies["delete_selector_fixture_group"]
    group_cleanup = bodies["cleanup_selector_group_attempt"]
    if not ordered(
        create,
        (
            "selector-group-precheck-", "datapath_get", "assert len(matches)==0",
            "printf", "mv", "-X POST",
        ),
    ) or "selector-group-create-attempt-" not in create or 'case "${attempted_name}" in "${RUN_ID}"-*-local)' not in create:
        errors.append(
            "group create must reject create-or-extend collisions and persist a collision-resistant receipt before POST"
        )
    for group_body, phase in ((delete_group, "delete"), (group_cleanup, "cleanup")):
        if (
            "/groups/${attempted_name}" not in group_body
            or "/groups/${group_id}" in group_body
            or not _real_command_lines(group_body, "curl")
        ):
            errors.append("group %s must call the local endpoint by name, never numeric ID" % phase)
    create_command_counts = {
        "datapath_get": 1, "python3": 2, "printf": 1, "mv": 1, "curl": 1,
    }
    for command, expected_count in create_command_counts.items():
        lines = _real_command_lines(create, command)
        if len(lines) != expected_count or any(not _line_has_fail_return(line) for line in lines):
            errors.append("group create must propagate failure from real %s" % command)
    for group_body, phase, command_counts in (
        (delete_group, "delete", {"curl": 1, "rm": 1}),
        (group_cleanup, "cleanup", {"datapath_get": 1, "curl": 1, "rm": 1}),
    ):
        for command, expected_count in command_counts.items():
            lines = _real_command_lines(group_body, command)
            if len(lines) != expected_count or any(
                not _line_has_fail_return(line) for line in lines
            ):
                errors.append("group %s must propagate failure from real %s" % (phase, command))
    if len(_real_command_lines(group_cleanup, "python3")) != 1 or group_cleanup.count(')" || return 1') != 1:
        errors.append("group cleanup must propagate failure from its receipt lookup")
    if not ordered(
        group_cleanup,
        (
            "selector-group-create-attempt-", '[ -f "${receipt}" ] || return 0',
            "read -r attempted_name attempted_cidr", '[ "${attempted_name}" = "${requested_name}" ]',
            "datapath_get", "assert len(matches)<=1", "-X DELETE", 'rm -f "${receipt}"',
        ),
    ):
        errors.append(
            "group cleanup must honor its receipt, query exact name, delete by name, then clear receipt"
        )

    apply_delta = bodies["apply_owned_acl_semantic_delta"]
    remove_delta = bodies["remove_owned_acl_semantic_delta"]
    for body, phase in ((apply_delta, "create"), (remove_delta, "cleanup")):
        if not all(term in body for term in (
            "aria-acl-rules", "policy_id", "direction", "ingress",
            "priority", "200", "action", "allow", "protocol", "tcp", "ACL_SELECTOR_CIDR",
            "assert len(matches)<=1",
        )):
            errors.append("semantic delta %s requires a unique deterministic tuple lookup" % phase)
    if "semantic-delta-create-attempt.json" not in apply_delta or not ordered(
        apply_delta,
        ("semantic-delta-before-create-rules.json", "assert len(matches)<=1", "printf", "curl_body POST aria-acl-rules"),
    ):
        errors.append("semantic delta must persist its deterministic attempt before POST")
    if not ordered(
        remove_delta,
        (
            "semantic-delta-create-attempt.json", '[ -f "${attempt_file}" ] || return 0',
            "read -r receipt_body", '[ "${receipt_body}" = "${expected_body}" ] || return 1',
            "curl_body GET aria-acl-rules", "assert len(matches)<=1", "curl_body DELETE",
        ),
    ):
        errors.append("semantic delta cleanup must require the attempt then query/delete its unique tuple")
    for command, expected_count in (("curl_body", 2), ("printf", 1), ("mv", 1)):
        lines = _real_command_lines(apply_delta, command)
        if len(lines) != expected_count or any(not _line_has_fail_return(line) for line in lines):
            errors.append("semantic delta create must propagate failure from real %s" % command)
    if len(_real_command_lines(apply_delta, "python3")) != 2 or apply_delta.count(')" || return 1') != 2:
        errors.append("semantic delta create must propagate both Python lookup failures")
    if '[ -z "${existing}" ] || return 1' not in apply_delta:
        errors.append("semantic delta create must reject a pre-existing exact tuple before receipt")
    remove_commands = {
        "curl_body": _real_command_lines(remove_delta, "curl_body"),
        "rm": _real_command_lines(remove_delta, "rm"),
    }
    if (
        len(remove_commands["curl_body"]) != 2
        or any(not _line_has_fail_return(line) for line in remove_commands["curl_body"])
        or len(remove_commands["rm"]) != 1
        or not _line_has_fail_return(remove_commands["rm"][0])
        or remove_delta.count(')" || return 1') < 1
    ):
        errors.append(
            "semantic delta lookup, DELETE, and receipt removal must propagate failure"
        )

    for helper in ("reverify_selector_deny_baseline", "run_more_specific_selector_isolation_fixture", "run_legacy_selector_repair_fixture", "cleanup_selector_fixture_state"):
        if "run_full_resync" in bodies[helper] and not _real_command_lines(bodies[helper], "run_full_resync"):
            errors.append("%s contains only a run_full_resync decoy" % helper)

    repair_required = bodies["assert_projection_repair_required"]
    for term in (
        "readiness_reason", "recovery_required", "projection_reason", "instance=",
        "EXPECTED_IFNAME", "EXPECTED_PORT_ID",
        "legacy-repair-required-tc-ingress.json",
        "legacy-repair-required-tc-egress.json",
        "legacy-repair-required-link.txt",
        "legacy-repair-required-port-status.json",
    ):
        if term not in repair_required:
            errors.append("repair-required evidence missing %s" % term)
    legacy = bodies["run_legacy_selector_repair_fixture"]
    for term in (
        "capture_datapath_log_cursor legacy-repair", "capture_datapath_logs_since legacy-repair",
        "capture_datapath_log_cursor legacy-equal", "capture_datapath_logs_since legacy-equal",
        "capture_datapath_log_cursor legacy-clean-restart", "capture_datapath_logs_since legacy-clean-restart",
    ):
        if term not in legacy:
            errors.append("legacy selector log evidence missing %s" % term)
    log_cursor_lines = _real_command_lines(bodies["capture_datapath_log_cursor"], "docker")
    if len(log_cursor_lines) != 1 or "--timestamps" not in log_cursor_lines[0] or "--tail 1" not in log_cursor_lines[0]:
        errors.append("datapath log cursor must use real docker logs --timestamps --tail 1")
    log_capture_lines = _real_command_lines(bodies["capture_datapath_logs_since"], "docker")
    if (
        len(log_capture_lines) != 1
        or "--timestamps" not in log_capture_lines[0]
        or "--since" not in log_capture_lines[0]
        or "timestamp>cursor" not in bodies["capture_datapath_logs_since"]
    ):
        errors.append("datapath log evidence must use real docker logs --since")
    for term in (
        "neutron_acl_apply_profile", "selector_repair_performed=true",
        "selector_repair_performed=false",
    ):
        if term not in repair:
            errors.append("legacy repair evidence must parse structured profile log field %s" % term)

    bank_artifacts = {
        "injected_bank": "legacy-polluted-after-runtime-compatibility.txt",
        "polluted_bank": "legacy-before-repair-runtime-compatibility.txt",
        "repaired_bank": "legacy-repaired-runtime-compatibility.txt",
        "equal_before_bank": "legacy-before-equal-runtime-compatibility.txt",
        "equal_bank": "legacy-after-equal-runtime-compatibility.txt",
        "restart_bank": "legacy-clean-restart-runtime-compatibility.txt",
    }
    repair_shell = "\n".join(_logical_shell_lines(repair))
    for variable, artifact in bank_artifacts.items():
        assignments = re.findall(
            r"(?m)^\s*%s\s*=\s*([^\n]+)$" % re.escape(variable), repair_shell
        )
        if len(assignments) != 1 or artifact not in assignments[0] or "awk" not in assignments[0]:
            errors.append("legacy bank measurement %s must have one exact artifact source" % variable)

    cleanup = bodies["cleanup_selector_fixture_state"]
    cleanup_assert = bodies["assert_selector_cleanup_state"]
    for term in (
        "active_bank", "active_acl_entries[selector_cidr]==selector_group_id",
        "inactive_selector_value in allowed_inactive_selector_values",
        "selector_rule_id in live_rule_ids", "assert len(semantic_delta_matches)==0",
        "semantic_delta_rule_id not in live_rule_ids",
    ):
        if term not in cleanup_assert:
            errors.append("selector cleanup evidence missing %s" % term)
    if "created_rule_ids" in cleanup or "owned_rule_ids" in cleanup_assert:
        errors.append(
            "fixture-stage cleanup must retain the baseline selector rule and only remove its semantic delta"
        )
    cleanup_captures = _real_command_lines(cleanup, "capture_selector_projection")
    if not any("selector-pollution-clean" in line for line in cleanup_captures) or not any(
        "selector-failclosed-cleanup" in line for line in cleanup_captures
    ):
        errors.append("fail-closed cleanup requires real pollution and final capture commands")
    cleanup_command_counts = {
        "restart_managed_datapath": 1,
        "run_full_resync": 2,
        "capture_selector_projection": 2,
        "assert_selector_cleanup_state": 2,
    }
    for command, expected_count in cleanup_command_counts.items():
        lines = _real_command_lines(cleanup, command)
        if len(lines) != expected_count or any("cleanup_rc=1" not in line for line in lines):
            errors.append("fail-closed cleanup must explicitly record failure from %s" % command)
    pollution_repair = (
        "restart_managed_datapath active", "run_full_resync", "capture_selector_projection selector-pollution-clean",
        "assert_selector_cleanup_state selector-pollution-clean", "LEGACY_POLLUTION_INJECTED=false",
    )
    if not ordered(cleanup, pollution_repair):
        errors.append("legacy cleanup may disarm only after restart, resync, capture, and clean assertion")
    if not ordered(cleanup, (
        "capture_selector_projection selector-failclosed-cleanup",
        "assert_selector_cleanup_state selector-failclosed-cleanup",
        '[ "${cleanup_rc}" -eq 0 ]',
    )):
        errors.append("final cleanup must capture and assert rules/groups/maps/banks/health clean")

    errors.extend(_python_contract_errors(bodies))
    return errors


def _managed_selector_field_fixture_errors(source):
    errors = []
    definition_counts = _function_definition_counts(source)
    duplicate_helpers = [
        name
        for name in SELECTOR_FIXTURE_FUNCTIONS
        if definition_counts.get(name, 0) != 1
    ]
    if duplicate_helpers:
        return [
            "managed selector helpers must have one reachable definition: %s"
            % ", ".join(duplicate_helpers)
        ]
    bodies = {}
    missing = []
    for name in SELECTOR_FIXTURE_FUNCTIONS:
        try:
            bodies[name] = function_body(source, name)
        except (KeyError, ValueError):
            missing.append(name)
    if missing:
        return [
            "managed selector field fixtures missing structured helpers: %s"
            % ", ".join(missing)
        ]

    capture_projection = bodies["capture_selector_projection"]
    for term in (
        'capture "${label}"',
        "/api/v1/${EXPECTED_IFNAME}/groups",
        "/api/v1/${EXPECTED_IFNAME}/policies",
        "bpftool -j map dump pinned",
        "SRC_IPV4_TRIE",
        "DST_IPV4_TRIE",
        "ACL_SRC_IPV4_TRIE",
        "ACL_DST_IPV4_TRIE",
        "${label}-groups.json",
        "${label}-policies.json",
        "${label}-neutron-rules.json",
        "${label}-general-src-map.json",
        "${label}-general-dst-map.json",
        "${label}-acl-src-map.json",
        "${label}-acl-dst-map.json",
    ):
        if term not in capture_projection:
            errors.append("managed selector capture missing %s" % term)

    prepare_fixture = bodies["prepare_owned_selector_fixture"].replace(
        '\\"', '"'
    )
    for term in (
        "delete_rules_for_transition",
        "ipaddress.ip_address",
        "ipaddress.ip_network",
        "source.version==4",
        "strict=False",
        '"%s/24" % source',
        '"%s/32" % source',
        "ACL_SELECTOR_CIDR",
        "MORE_SPECIFIC_CIDR",
        '"direction":"ingress"',
        '"action":"drop"',
        '"protocol":"${CT_PROTOCOL}"',
        '"src_cidr":"${ACL_SELECTOR_CIDR}"',
        "curl_body POST aria-acl-rules",
        "created_selector_rule_id",
        '[ -n "${created_selector_rule_id}" ] || return 1',
        'selector_rule_id="${created_selector_rule_id}"',
        "selector_rule_id",
        'rule_ids+=("${selector_rule_id}")',
        'created_rule_ids+=("${selector_rule_id}")',
    ):
        if term not in prepare_fixture:
            errors.append("owned selector fixture preparation missing %s" % term)
    if not ordered(
        prepare_fixture,
        (
            "delete_rules_for_transition",
            "ACL_SELECTOR_CIDR",
            "MORE_SPECIFIC_CIDR",
            "curl_body POST aria-acl-rules",
            '[ -n "${created_selector_rule_id}" ] || return 1',
            'selector_rule_id="${created_selector_rule_id}"',
            'rule_ids+=("${selector_rule_id}")',
            'created_rule_ids+=("${selector_rule_id}")',
        ),
    ):
        errors.append(
            "owned selector fixture must replace generic rules with a real selector deny"
        )
    if not ordered(
        prepare_fixture,
        (
            'selector_rule_receipt="${WORK_DIR}/selector-rule-create-attempt.json"',
            "printf '%s\\n'",
            'mv "${selector_rule_receipt}.tmp" "${selector_rule_receipt}"',
            "curl_body POST aria-acl-rules",
            'selector_rule_id="${created_selector_rule_id}"',
            'rule_ids+=("${selector_rule_id}")',
            'created_rule_ids+=("${selector_rule_id}")',
            'rm -f "${selector_rule_receipt}"',
        ),
    ):
        errors.append(
            "selector rule create must persist its deterministic attempt before POST"
        )

    selector_rule_cleanup = bodies["cleanup_selector_rule_attempt"].replace(
        '\\"', '"'
    )
    cleanup_terms = (
        "selector-rule-create-attempt.json",
        '"direction":"ingress"',
        '"priority":100',
        '"action":"drop"',
        '"protocol":"${CT_PROTOCOL}"',
        '"src_cidr":"${ACL_SELECTOR_CIDR}"',
        'receipt_body',
        '[ -n "${selector_rule_id}" ]',
        "curl_body GET aria-acl-rules",
        'assert len(matches)<=1',
        'curl_body DELETE "aria-acl-rules/${matched}"',
    )
    if not all(term in selector_rule_cleanup for term in cleanup_terms):
        errors.append(
            "selector rule unknown-response cleanup must query/delete its exact tuple"
        )
    selector_cleanup_curls = _real_command_lines(
        bodies["cleanup_selector_rule_attempt"], "curl_body"
    )
    selector_cleanup_rms = _real_command_lines(
        bodies["cleanup_selector_rule_attempt"], "rm"
    )
    if (
        len(selector_cleanup_curls) != 2
        or any(not _line_has_fail_return(line) for line in selector_cleanup_curls)
        or len(selector_cleanup_rms) != 2
        or any(not _line_has_fail_return(line) for line in selector_cleanup_rms)
        or bodies["cleanup_selector_rule_attempt"].count(')" || return 1') < 1
    ):
        errors.append(
            "selector rule unknown-response cleanup must preserve its receipt on GET, DELETE, parse, or rm failure"
        )

    unchecked_traffic = bodies["run_unchecked_selector_traffic"]
    for term in ("ping", "${VM_IP}", "${label}-traffic.log"):
        if term not in unchecked_traffic:
            errors.append("unchecked selector traffic helper missing %s" % term)
    if "die " in unchecked_traffic or "expectation" in unchecked_traffic:
        errors.append(
            "unchecked selector traffic helper must return the raw traffic status"
        )

    captured_flow = bodies["run_captured_selector_flow"]
    if not ordered(
        captured_flow,
        (
            'capture_selector_projection "${label}-before"',
            "run_unchecked_selector_traffic",
            "traffic_rc=0",
            "traffic_rc=$?",
            "${label}-traffic-rc.txt",
            'capture_selector_projection "${label}-after"',
            "assert_selector_traffic_result",
        ),
    ):
        errors.append(
            "selector traffic must persist rc/maps/counters/bank/CT before assertion"
        )

    traffic_assert = bodies["assert_selector_traffic_result"]
    for term in ("traffic_rc", "expectation", "expected_pass", "actual_pass"):
        if term not in traffic_assert:
            errors.append("selector traffic result assertion missing %s" % term)

    baseline = bodies["reverify_selector_deny_baseline"]
    if not ordered(
        baseline,
        (
            "run_full_resync",
            "wait_port_enforced",
            "run_captured_selector_flow",
            "deny",
            "assert_selector_deny_drop_ct_zero",
        ),
    ):
        errors.append(
            "managed selector fixture baseline must full-resync and reverify deny/drop/CT"
        )

    resolve_selector = bodies["resolve_selector_group_id"]
    for term in (
        'row["src_group_id"]',
        'row.get("direction")=="egress"',
        'row.get("action")=="drop"',
        "ipaddress.ip_network",
        "assert len(candidates)==1",
    ):
        if term not in resolve_selector:
            errors.append("managed selector ID resolution missing %s" % term)

    create_group = bodies["create_selector_fixture_group"]
    normalized_create_group = create_group.replace('\\"', '"')
    for term in (
        "-X POST",
        "/api/v1/${EXPECTED_IFNAME}/groups",
        '"name":"${attempted_name}"',
        '"cidr":"${attempted_cidr}"',
        "group_id=json.load",
    ):
        if term not in normalized_create_group:
            errors.append("selector fixture group create missing %s" % term)
    delete_group = bodies["delete_selector_fixture_group"]
    if (
        "-X DELETE" not in delete_group
        or "/api/v1/${EXPECTED_IFNAME}/groups/${attempted_name}" not in delete_group
    ):
        errors.append("selector fixture group delete must use the local group API")

    wider_selector = bodies["require_wider_owned_selector"]
    for term in (
        "ipaddress.ip_network",
        "strict=False",
        "source in selector",
        "selector.version==4",
        "selector.prefixlen<32",
    ):
        if term not in wider_selector:
            errors.append("more-specific fixture wider selector guard missing %s" % term)
    if 'ACL_SELECTOR_CIDR=""' not in source or 'MORE_SPECIFIC_CIDR=""' not in source:
        errors.append("managed selector CIDRs must be derived from controlled traffic")

    semantic_delta = bodies["apply_owned_acl_semantic_delta"].replace('\\"', '"')
    for term in (
        "curl_body POST aria-acl-rules",
        "semantic_delta_rule_id",
        '"action":"allow"',
        '"protocol":"tcp"',
        '"src_cidr":"${ACL_SELECTOR_CIDR}"',
    ):
        if term not in semantic_delta:
            errors.append("owned ACL semantic delta missing %s" % term)
    remove_delta = bodies["remove_owned_acl_semantic_delta"]
    if not all(
        term in remove_delta
        for term in ("curl_body GET aria-acl-rules", "assert len(matches)<=1", "curl_body DELETE")
    ):
        errors.append("owned ACL semantic delta cleanup is missing")

    deny_ct = bodies["assert_selector_deny_drop_ct_zero"]
    for term in (
        "flow_conntrack_totals",
        "rule_counter_sum",
        '"${ct_count}" -eq 0',
        '"${ct_packets}" -eq 0',
        '"${ct_bytes}" -eq 0',
        '"${drop_after}" -gt "${drop_before}"',
    ):
        if term not in deny_ct:
            errors.append("selector deny/drop/CT proof missing %s" % term)

    exact_assert = bodies["assert_exact_selector_state"]
    for term in (
        "assert exact_before_bank==exact_after_bank",
        "assert exact_before_groups!=exact_after_groups",
        "assert exact_before_general!=exact_after_general",
        "assert exact_before_acl_entries==exact_acl_entries",
        "assert exact_acl_entries[selector_cidr]==selector_group_id",
        "assert selector_group_id in exact_acl_ids",
        "assert local_group_id not in exact_acl_ids",
        "assert exact_cleanup_general_entries[selector_cidr]==selector_group_id",
        "assert selector_group_id in exact_cleanup_general_ids",
        "assert local_group_id not in exact_cleanup_general_ids",
    ):
        if term not in exact_assert:
            errors.append("exact selector fixture assertion missing %s" % term)

    exact_fixture = bodies["run_exact_selector_isolation_fixture"]
    exact_sequence = (
        "reverify_selector_deny_baseline exact-baseline",
        "resolve_selector_group_id exact-baseline-deny-after",
        "SELECTOR_FIXTURES_STARTED=true",
        "capture_selector_projection exact-before",
        'create_selector_fixture_group "${EXACT_LOCAL_GROUP_NAME}" "${ACL_SELECTOR_CIDR}"',
        "capture_selector_projection exact-local",
        "run_captured_selector_flow exact-deny 2 deny",
        "assert_selector_deny_drop_ct_zero exact-deny",
        'delete_selector_fixture_group "${EXACT_LOCAL_GROUP_NAME}"',
        "capture_selector_projection exact-cleanup",
        "assert_exact_selector_state",
        'exact_local_group_id=""',
        "reverify_selector_deny_baseline exact-cleanup",
    )
    if not ordered(exact_fixture, exact_sequence):
        errors.append(
            "exact selector fixture must isolate baseline, mutation, deny evidence, and cleanup"
        )
    if not ordered(
        exact_fixture,
        (
            'delete_selector_fixture_group "${EXACT_LOCAL_GROUP_NAME}"',
            "capture_selector_projection exact-cleanup",
            "assert_exact_selector_state",
            'exact_local_group_id=""',
        ),
    ):
        errors.append(
            "exact selector fixture must retain local group ID through cleanup assertion"
        )

    more_assert = bodies["assert_more_specific_selector_state"]
    for term in (
        "assert old_bank!=new_bank",
        "assert new_general_entries[more_specific_key]==more_specific_group_id",
        "assert more_specific_group_id in new_general_ids",
        "assert more_specific_key not in new_acl_keys",
        "assert more_specific_group_id not in new_acl_ids",
        "assert new_acl_entries[selector_cidr]==selector_group_id",
        "assert selector_group_id in new_acl_ids",
    ):
        if term not in more_assert:
            errors.append("more-specific selector fixture assertion missing %s" % term)

    more_fixture = bodies["run_more_specific_selector_isolation_fixture"]
    more_sequence = (
        "reverify_selector_deny_baseline more-specific-baseline",
        "resolve_selector_group_id more-specific-baseline-deny-after",
        "SELECTOR_FIXTURES_STARTED=true",
        "require_wider_owned_selector",
        'create_selector_fixture_group "${MORE_SPECIFIC_GROUP_NAME}" "${MORE_SPECIFIC_CIDR}"',
        "capture_selector_projection more-specific-before-delta",
        "apply_owned_acl_semantic_delta",
        "run_full_resync",
        "capture_selector_projection more-specific-after-delta",
        "assert_more_specific_selector_state",
        "run_captured_selector_flow more-specific-deny 2 deny",
        "assert_selector_deny_drop_ct_zero more-specific-deny",
        "remove_owned_acl_semantic_delta",
        'semantic_delta_rule_id=""',
        'delete_selector_fixture_group "${MORE_SPECIFIC_GROUP_NAME}"',
        'more_specific_group_id=""',
        "run_full_resync",
        "capture_selector_projection more-specific-cleanup",
        "reverify_selector_deny_baseline more-specific-cleanup",
    )
    if not ordered(more_fixture, more_sequence):
        errors.append(
            "more-specific selector fixture must stage a real delta, switch, deny, and clean up"
        )

    pollution = bodies["inject_legacy_selector_pollution"]
    for term in (
        "bpftool map update pinned",
        "ACL_SRC_IPV4_TRIE",
        "active_selector_key_hex",
        "legacy_local_group_id_hex",
        "32+network.prefixlen",
        "tap_id*2+bank",
        "legacy-pollution-map-update-rc.txt",
    ):
        if term not in pollution:
            errors.append("legacy selector pollution helper missing %s" % term)

    restart = bodies["restart_managed_datapath"]
    wait_uds = bodies["wait_neutron_uds"]
    for term in (
        '--unix-socket "${NEUTRON_UDS}"',
        "/api/v1/neutron/status",
        "sleep 1",
        "return 1",
    ):
        if term not in wait_uds:
            errors.append("datapath restart UDS wait missing %s" % term)
    wait_reattach = bodies["wait_managed_port_reattached"]
    for term in (
        "/api/v1/instances",
        'payload.get("active_instances")',
        'payload.get("managed_ports")',
        'instances.get("instances")',
        'row.get("port_id")==port_id',
        'row.get("ifname")==ifname',
        'row.get("name")==ifname',
        'assert len(active_matches)==1',
        'assert len(managed_matches)==1',
        'assert len(instance_matches)==1',
        'item.get("active") is True',
        'expected_phase in ("recovery_required","ready","active")',
        'item.get("acl_ready") is False',
        'item.get("readiness_reason")=="recovery_required"',
        'item.get("acl_ready") is True',
        'item.get("readiness_reason") is None',
        "sleep 1",
        "return 1",
    ):
        if term not in wait_reattach:
            errors.append("managed port re-attach wait missing %s" % term)
    if not ordered(
        restart,
        (
            'local expected_phase="$1"',
            'docker restart "${DATAPATH_SERVICE_NAME}"',
            "wait_neutron_uds",
            'wait_managed_port_reattached "${expected_phase}"',
        ),
    ):
        errors.append(
            "legacy selector repair must restart the datapath and wait for re-attach"
        )

    repair_required = bodies["assert_projection_repair_required"]
    for term in (
        "repair_required",
        "acl_ready",
        "assert repair_required is True",
        "assert acl_ready is False",
        'assert config["acl"] is False',
    ):
        if term not in repair_required:
            errors.append("legacy repair-required gate proof missing %s" % term)

    pollution_assert = bodies["assert_legacy_pollution_evidence"]
    for term in (
        "assert polluted_acl_value==legacy_local_group_id",
        "assert bad_traffic_rc==0",
        "assert bad_ct_count>0",
        "assert bad_ct_packets>0",
        "assert bad_ct_bytes>0",
    ):
        if term not in pollution_assert:
            errors.append("legacy bad PASS/CT proof missing %s" % term)

    repair_assert = bodies["assert_legacy_repair_evidence"]
    final_inventory_terms = (
        'item["active"] is True',
        'item["acl_ready"] is True',
        'item["readiness_reason"] is None',
        'config["acl"] is True',
    )
    if any(term not in repair_assert for term in final_inventory_terms):
        errors.append(
            "legacy clean restart final evidence must require active ready state"
        )
    for term in (
        "assert injected_bank==polluted_bank",
        "assert polluted_bank!=repaired_bank",
        "assert repaired_acl_value==selector_group_id",
        "assert repaired_ct_count==0",
        "assert repaired_drop_delta>0",
        "assert repaired_bank==equal_before_bank",
        "assert equal_before_bank==equal_bank",
        "assert repaired_bank==equal_bank",
        "assert equal_bank==restart_bank",
        "assert restart_true_count==0",
        "assert restart_repair_required_count==0",
        "assert inventory_clean is True",
        "assert second_repair_switch is False",
    ):
        if term not in repair_assert:
            errors.append("legacy one-repair/no-op/restart proof missing %s" % term)

    legacy_fixture = bodies["run_legacy_selector_repair_fixture"]
    legacy_sequence = (
        "reverify_selector_deny_baseline legacy-baseline",
        "resolve_selector_group_id legacy-baseline-deny-after",
        "SELECTOR_FIXTURES_STARTED=true",
        'create_selector_fixture_group "${LEGACY_LOCAL_GROUP_NAME}" "${ACL_SELECTOR_CIDR}"',
        "capture_selector_projection legacy-before-pollution",
        "inject_legacy_selector_pollution",
        "run_captured_selector_flow legacy-polluted 2 pass",
        "assert_legacy_pollution_evidence",
        "capture_datapath_log_cursor legacy-repair-required",
        "restart_managed_datapath recovery_required",
        "capture_datapath_logs_since legacy-repair-required",
        "capture_selector_projection legacy-repair-required",
        "assert_projection_repair_required",
        "capture_selector_projection legacy-before-repair",
        "capture_datapath_log_cursor legacy-repair",
        "run_full_resync",
        "capture_datapath_logs_since legacy-repair",
        "capture_selector_projection legacy-repaired",
        "run_captured_selector_flow legacy-repaired-deny 2 deny",
        "assert_selector_deny_drop_ct_zero legacy-repaired-deny",
        "capture_selector_projection legacy-before-equal",
        "capture_datapath_log_cursor legacy-equal",
        "run_full_resync",
        "capture_datapath_logs_since legacy-equal",
        "capture_selector_projection legacy-after-equal",
        'delete_selector_fixture_group "${LEGACY_LOCAL_GROUP_NAME}"',
        "legacy-local-group-cleanup-resync.log",
        "capture_datapath_log_cursor legacy-clean-restart",
        "restart_managed_datapath ready",
        "wait_port_enforced",
        "capture_datapath_logs_since legacy-clean-restart",
        "capture_selector_projection legacy-clean-restart",
        "assert_legacy_repair_evidence",
        "LEGACY_POLLUTION_INJECTED=false",
        'legacy_local_group_id=""',
        "run_full_resync",
        "capture_selector_projection legacy-cleanup",
        "reverify_selector_deny_baseline legacy-cleanup",
    )
    if not ordered(legacy_fixture, legacy_sequence):
        errors.append(
            "legacy selector fixture must capture pollution before restart and repair exactly once"
        )
    if legacy_fixture.count("restart_managed_datapath") != 2:
        errors.append(
            "legacy selector fixture must prove repair restart and second clean restart"
        )

    for term in (
        'EXACT_LOCAL_GROUP_NAME="${RUN_ID}-exact-local"',
        'MORE_SPECIFIC_GROUP_NAME="${RUN_ID}-more-specific-local"',
        'LEGACY_LOCAL_GROUP_NAME="${RUN_ID}-legacy-local"',
        "SELECTOR_FIXTURES_STARTED=false",
        "LEGACY_POLLUTION_INJECTED=false",
        'exact_local_group_id=""',
        'more_specific_group_id=""',
        'legacy_local_group_id=""',
        'semantic_delta_rule_id=""',
    ):
        if term not in source:
            errors.append("managed selector fail-closed state missing %s" % term)

    if not ordered(
        pollution,
        (
            "bpftool map update pinned",
            "legacy-pollution-map-update-rc.txt",
            '[ "${injection_rc}" -eq 0 ]',
            "LEGACY_POLLUTION_INJECTED=true",
        ),
    ):
        errors.append(
            "legacy pollution must arm fail-closed repair only after a successful map update"
        )

    fixture_cleanup = bodies["cleanup_selector_fixture_state"]
    if not ordered(
        fixture_cleanup,
        (
            "cleanup_rc=0",
            '[ "${SELECTOR_FIXTURES_STARTED}" = true ] || return 0',
            '[ "${LEGACY_POLLUTION_INJECTED}" = true ]',
            "restart_managed_datapath active",
            "selector-cleanup-pollution-repair-resync.log",
            "capture_selector_projection selector-pollution-clean",
            "assert_selector_cleanup_state selector-pollution-clean",
            "LEGACY_POLLUTION_INJECTED=false",
            "remove_owned_acl_semantic_delta",
            'semantic_delta_rule_id=""',
            'cleanup_selector_group_attempt "${EXACT_LOCAL_GROUP_NAME}"',
            'exact_local_group_id=""',
            'cleanup_selector_group_attempt "${MORE_SPECIFIC_GROUP_NAME}"',
            'more_specific_group_id=""',
            '[ "${LEGACY_POLLUTION_INJECTED}" = false ]',
            'cleanup_selector_group_attempt "${LEGACY_LOCAL_GROUP_NAME}"',
            'legacy_local_group_id=""',
            "selector-cleanup-full-resync.log",
            "capture_selector_projection selector-failclosed-cleanup",
            "assert_selector_cleanup_state selector-failclosed-cleanup",
            '[ "${cleanup_rc}" -eq 0 ]',
        ),
    ):
        errors.append(
            "managed selector fixture cleanup must fail closed across rules, groups, pollution, resync, and evidence"
        )
    try:
        cleanup_body = function_body(source, "cleanup")
    except (KeyError, ValueError):
        cleanup_body = ""
    if not ordered(
        cleanup_body,
        (
            "set +e",
            "if ! cleanup_selector_fixture_state",
            'record_cleanup_error "cleanup-selector-fixture-state failed"',
        ),
    ):
        errors.append(
            "top-level cleanup must record managed selector fixture cleanup failure"
        )
    if not ordered(
        cleanup_body,
        (
            "if ! cleanup_selector_fixture_state",
            "if ! cleanup_selector_rule_attempt",
            'record_cleanup_error "cleanup-selector-rule-attempt failed"',
        ),
    ):
        errors.append(
            "top-level cleanup must invoke selector rule attempt recovery"
        )
    selector_cleanup_position = cleanup_body.find(
        "if ! cleanup_selector_fixture_state"
    )
    selector_rule_cleanup_position = cleanup_body.find(
        "if ! cleanup_selector_rule_attempt"
    )
    generic_rule_cleanup_position = cleanup_body.find(
        'for id in "${rule_ids[@]:-}"'
    )
    if (
        generic_rule_cleanup_position >= 0
        and (
            selector_cleanup_position > generic_rule_cleanup_position
            or selector_rule_cleanup_position < 0
            or selector_rule_cleanup_position > generic_rule_cleanup_position
        )
    ):
        errors.append(
            "managed selector cleanup must repair legacy pollution before deleting owned rules"
        )

    errors.extend(
        _selector_fixture_invocation_errors(
            source, bodies, definition_counts
        )
    )
    errors.extend(_managed_selector_semantic_errors(source, bodies))
    return errors


def _selector_fixture_self_test_source(main_body):
    return r'''
DATAPATH_SERVICE_NAME="${DATAPATH_SERVICE_NAME:-aria_datapath}"
ACL_SELECTOR_CIDR=""
MORE_SPECIFIC_CIDR=""
EXACT_LOCAL_GROUP_NAME="${RUN_ID}-exact-local"
MORE_SPECIFIC_GROUP_NAME="${RUN_ID}-more-specific-local"
LEGACY_LOCAL_GROUP_NAME="${RUN_ID}-legacy-local"
exact_local_group_id=""
more_specific_group_id=""
legacy_local_group_id=""
semantic_delta_rule_id=""
selector_rule_id=""
selector_group_id=""
selector_local_group_ids=()
SELECTOR_FIXTURES_STARTED=false
LEGACY_POLLUTION_INJECTED=false
EXACT_SELECTOR_FIXTURE_STATUS="not_run"
MORE_SPECIFIC_SELECTOR_FIXTURE_STATUS="not_run"
LEGACY_SELECTOR_REPAIR_FIXTURE_STATUS="not_run"

capture() {
    local label="$1"
    command ip -details link show dev "${EXPECTED_IFNAME}" >"${WORK_DIR}/${label}-link.txt" || return 1
    command tc -j filter show dev "${EXPECTED_IFNAME}" ingress >"${WORK_DIR}/${label}-tc-ingress.json" || return 1
    command tc -j filter show dev "${EXPECTED_IFNAME}" egress >"${WORK_DIR}/${label}-tc-egress.json" || return 1
}

prepare_owned_selector_fixture() {
    local selector_rule_body selector_rule_receipt created_selector_rule_id
    [ "${IP_FAMILY}" = ipv4 ] || return 0
    delete_rules_for_transition || return 1
    read -r ACL_SELECTOR_CIDR MORE_SPECIFIC_CIDR < <(
        python3 - "${SOURCE_IP}" <<'PY'
import ipaddress,sys
source=ipaddress.ip_address(sys.argv[1])
assert source.version==4,source
selector=ipaddress.ip_network("%s/24" % source,strict=False)
print(selector,"%s/32" % source)
PY
    ) || return 1
    selector_rule_body="{\"aria_acl_rule\":{\"policy_id\":\"${policy_id}\",\"direction\":\"ingress\",\"priority\":100,\"action\":\"drop\",\"protocol\":\"${CT_PROTOCOL}\",\"src_cidr\":\"${ACL_SELECTOR_CIDR}\"}}"
    selector_rule_receipt="${WORK_DIR}/selector-rule-create-attempt.json"
    printf '%s\n' "${selector_rule_body}" >"${selector_rule_receipt}.tmp" || return 1
    mv "${selector_rule_receipt}.tmp" "${selector_rule_receipt}" || return 1
    created_selector_rule_id="$(curl_body POST aria-acl-rules "${selector_rule_body}" | json_field aria_acl_rule.id)" || return 1
    [ -n "${created_selector_rule_id}" ] || return 1
    selector_rule_id="${created_selector_rule_id}"
    rule_ids+=("${selector_rule_id}")
    created_rule_ids+=("${selector_rule_id}")
    rm -f "${selector_rule_receipt}" || return 1
}

cleanup_selector_rule_attempt() {
    local attempt_file expected_body receipt_body lookup_file matched
    attempt_file="${WORK_DIR}/selector-rule-create-attempt.json"
    [ -f "${attempt_file}" ] || return 0
    expected_body="{\"aria_acl_rule\":{\"policy_id\":\"${policy_id}\",\"direction\":\"ingress\",\"priority\":100,\"action\":\"drop\",\"protocol\":\"${CT_PROTOCOL}\",\"src_cidr\":\"${ACL_SELECTOR_CIDR}\"}}"
    IFS= read -r receipt_body <"${attempt_file}" || return 1
    [ "${receipt_body}" = "${expected_body}" ] || return 1
    if [ -n "${selector_rule_id}" ]; then
        rm -f "${attempt_file}" || return 1
        return 0
    fi
    lookup_file="${WORK_DIR}/selector-rule-cleanup-rules.json"
    curl_body GET aria-acl-rules >"${lookup_file}" || return 1
    matched="$(python3 - "${lookup_file}" "${policy_id}" "${ACL_SELECTOR_CIDR}" "${CT_PROTOCOL}" <<'PY'
import ipaddress,json,sys
rows=json.load(open(sys.argv[1],encoding="utf-8")).get("aria_acl_rules") or []
target=str(ipaddress.ip_network(sys.argv[3],strict=False))
matches=[row for row in rows if row.get("policy_id")==sys.argv[2] and row.get("direction")=="ingress" and row.get("priority")==100 and row.get("action")=="drop" and str(row.get("protocol"))==sys.argv[4] and str(ipaddress.ip_network(row.get("src_cidr"),strict=False))==target]
assert len(matches)<=1,matches
print(matches[0]["id"] if matches else "")
PY
    )" || return 1
    if [ -n "${matched}" ]; then
        curl_body DELETE "aria-acl-rules/${matched}" \
            >"${WORK_DIR}/selector-rule-cleanup-delete.json" || return 1
    fi
    rm -f "${attempt_file}" || return 1
}

capture_selector_projection() {
    local label="$1"
    capture "${label}" || return 1
    datapath_get "/api/v1/${EXPECTED_IFNAME}/groups" >"${WORK_DIR}/${label}-groups.json" || return 1
    datapath_get "/api/v1/${EXPECTED_IFNAME}/policies" >"${WORK_DIR}/${label}-policies.json" || return 1
    curl_body GET aria-acl-rules >"${WORK_DIR}/${label}-neutron-rules.json" || return 1
    bpftool -j map dump pinned "${PIN_ROOT}/SRC_IPV4_TRIE" >"${WORK_DIR}/${label}-general-src-map.json" || return 1
    bpftool -j map dump pinned "${PIN_ROOT}/DST_IPV4_TRIE" >"${WORK_DIR}/${label}-general-dst-map.json" || return 1
    bpftool -j map dump pinned "${PIN_ROOT}/ACL_SRC_IPV4_TRIE" >"${WORK_DIR}/${label}-acl-src-map.json" || return 1
    bpftool -j map dump pinned "${PIN_ROOT}/ACL_DST_IPV4_TRIE" >"${WORK_DIR}/${label}-acl-dst-map.json" || return 1
}

run_unchecked_selector_traffic() {
    local label="$1" count="$2"
    command ping "${PING_ARGS[@]}" -c "${count}" -W 1 -s "${PING_PAYLOAD_BYTES}" "${VM_IP}" \
        >"${WORK_DIR}/${label}-traffic.log" 2>&1
}

assert_selector_traffic_result() {
    python3 - "$2" "$3" <<'PY'
import sys
traffic_rc_raw,expectation_raw=sys.argv[1:]
traffic_rc=int(traffic_rc_raw)
expectation=expectation_raw
expected_pass=(expectation=="pass")
actual_pass=(traffic_rc==0)
assert expectation in ("pass","deny")
assert actual_pass is expected_pass
PY
}

run_captured_selector_flow() {
    local label="$1" count="$2" expectation="$3" traffic_rc
    capture_selector_projection "${label}-before"
    if run_unchecked_selector_traffic "${label}" "${count}"; then
        traffic_rc=0
    else
        traffic_rc=$?
    fi
    printf '%s\n' "${traffic_rc}" >"${WORK_DIR}/${label}-traffic-rc.txt"
    capture_selector_projection "${label}-after"
    assert_selector_traffic_result "${label}" "${traffic_rc}" "${expectation}"
}

reverify_selector_deny_baseline() {
    local label="$1"
    run_full_resync >"${WORK_DIR}/${label}-full-resync.log"
    wait_port_enforced
    run_captured_selector_flow "${label}-deny" 2 deny
    assert_selector_deny_drop_ct_zero "${label}-deny"
}

resolve_selector_group_id() {
    python3 - "${WORK_DIR}/$1-groups.json" "${WORK_DIR}/$1-policies.json" \
        "${ACL_SELECTOR_CIDR}" "${CT_PROTOCOL}" <<'PY'
import ipaddress,json,sys
groups=json.load(open(sys.argv[1],encoding="utf-8"))["groups"]
policies=json.load(open(sys.argv[2],encoding="utf-8"))["policies"]
selector=str(ipaddress.ip_network(sys.argv[3],strict=False)); protocol=sys.argv[4]
group_ids={int(row["id"]) for row in groups if selector in {
    str(ipaddress.ip_network(cidr,strict=False)) for cidr in row.get("cidrs") or []}}
candidates={int(row["src_group_id"]) for row in policies
            if row.get("direction")=="egress" and row.get("action")=="drop"
            and str(row.get("proto"))==protocol and int(row.get("src_group_id") or 0) in group_ids}
assert len(candidates)==1,(groups,policies,selector,protocol)
print(candidates.pop())
PY
}

create_selector_fixture_group() {
    local attempted_name="$1" attempted_cidr="$2" precheck receipt response
    precheck="${WORK_DIR}/selector-group-precheck-${attempted_name}.json"
    receipt="${WORK_DIR}/selector-group-create-attempt-${attempted_name}.txt"
    response="${WORK_DIR}/selector-group-create-response-${attempted_name}.json"
    case "${attempted_name}" in "${RUN_ID}"-*-local) ;; *) return 1 ;; esac
    datapath_get "/api/v1/${EXPECTED_IFNAME}/groups" >"${precheck}" || return 1
    python3 - "${precheck}" "${attempted_name}" <<'PY' || return 1
import json,sys
rows=json.load(open(sys.argv[1],encoding="utf-8"))["groups"]
matches=[row for row in rows if row.get("name")==sys.argv[2]]
assert len(matches)==0,matches
PY
    printf '%s|%s\n' "${attempted_name}" "${attempted_cidr}" >"${receipt}.tmp" || return 1
    mv "${receipt}.tmp" "${receipt}" || return 1
    command curl --fail-with-body -sS -H 'Content-Type: application/json' -X POST \
        -d "{\"name\":\"${attempted_name}\",\"cidr\":\"${attempted_cidr}\"}" \
        "${DATAPATH_HTTP}/api/v1/${EXPECTED_IFNAME}/groups" >"${response}" || return 1
    python3 - "${response}" <<'PY' || return 1
import json,sys
group_id=json.load(open(sys.argv[1],encoding="utf-8")).get("id")
assert isinstance(group_id,int) and group_id>0,group_id
print(group_id)
PY
}

delete_selector_fixture_group() {
    local attempted_name="$1" receipt
    receipt="${WORK_DIR}/selector-group-create-attempt-${attempted_name}.txt"
    [ -f "${receipt}" ] || return 1
    command curl --fail-with-body -sS -X DELETE \
        "${DATAPATH_HTTP}/api/v1/${EXPECTED_IFNAME}/groups/${attempted_name}" || return 1
    rm -f "${receipt}" || return 1
}

cleanup_selector_group_attempt() {
    local requested_name="$1" attempted_name attempted_cidr payload receipt present
    receipt="${WORK_DIR}/selector-group-create-attempt-${requested_name}.txt"
    [ -f "${receipt}" ] || return 0
    IFS='|' read -r attempted_name attempted_cidr <"${receipt}" || return 1
    [ "${attempted_name}" = "${requested_name}" ] || return 1
    case "${attempted_name}" in "${RUN_ID}"-*-local) ;; *) return 1 ;; esac
    payload="${WORK_DIR}/selector-group-cleanup-${attempted_name}.json"
    datapath_get "/api/v1/${EXPECTED_IFNAME}/groups" >"${payload}" || return 1
    present="$(python3 - "${payload}" "${attempted_name}" "${attempted_cidr}" <<'PY'
import json,sys
attempted_name=sys.argv[2]
rows=json.load(open(sys.argv[1],encoding="utf-8"))["groups"]
matches=[row for row in rows if row.get("name")==attempted_name]
assert len(matches)<=1,matches
if matches:
    cidrs={str(value) for value in matches[0].get("cidrs") or []}
    assert sys.argv[3] in cidrs,(matches[0],sys.argv[3])
print("present" if matches else "absent")
PY
    )" || return 1
    if [ "${present}" = present ]; then
        command curl --fail-with-body -sS -X DELETE \
            "${DATAPATH_HTTP}/api/v1/${EXPECTED_IFNAME}/groups/${attempted_name}" || return 1
    fi
    rm -f "${receipt}" || return 1
}

require_wider_owned_selector() {
    python3 - "${ACL_SELECTOR_CIDR}" "${SOURCE_IP}" <<'PY'
import ipaddress,sys
selector=ipaddress.ip_network(sys.argv[1],strict=False)
source=ipaddress.ip_address(sys.argv[2])
assert source in selector
assert selector.version==4
assert selector.prefixlen<32
PY
}

apply_owned_acl_semantic_delta() {
    local body existing lookup_file attempt_file response_file
    body="{\"aria_acl_rule\":{\"policy_id\":\"${policy_id}\",\"direction\":\"ingress\",\"priority\":200,\"action\":\"allow\",\"protocol\":\"tcp\",\"src_cidr\":\"${ACL_SELECTOR_CIDR}\"}}"
    lookup_file="${WORK_DIR}/semantic-delta-before-create-rules.json"
    attempt_file="${WORK_DIR}/semantic-delta-create-attempt.json"
    curl_body GET aria-acl-rules >"${lookup_file}" || return 1
    existing="$(python3 - "${lookup_file}" "${policy_id}" "${ACL_SELECTOR_CIDR}" <<'PY'
import ipaddress,json,sys
rows=json.load(open(sys.argv[1],encoding="utf-8")).get("aria_acl_rules") or []
target=str(ipaddress.ip_network(sys.argv[3],strict=False))
matches=[row for row in rows if row.get("policy_id")==sys.argv[2] and row.get("direction")=="ingress" and row.get("priority")==200 and row.get("action")=="allow" and row.get("protocol")=="tcp" and str(ipaddress.ip_network(row.get("src_cidr"),strict=False))==target]
assert len(matches)<=1,matches
print(matches[0]["id"] if matches else "")
PY
    )" || return 1
    [ -z "${existing}" ] || return 1
    printf '%s\n' "${body}" >"${attempt_file}.tmp" || return 1
    mv "${attempt_file}.tmp" "${attempt_file}" || return 1
    response_file="${WORK_DIR}/semantic-delta-create-response.json"
    curl_body POST aria-acl-rules "${body}" >"${response_file}" || return 1
    semantic_delta_rule_id="$(python3 - "${response_file}" <<'PY'
import json,sys
rule_id=(json.load(open(sys.argv[1],encoding="utf-8")).get("aria_acl_rule") or {}).get("id")
assert rule_id,rule_id
print(rule_id)
PY
    )" || return 1
}

remove_owned_acl_semantic_delta() {
    local matched lookup_file attempt_file expected_body receipt_body
    lookup_file="${WORK_DIR}/semantic-delta-cleanup-rules.json"
    attempt_file="${WORK_DIR}/semantic-delta-create-attempt.json"
    [ -f "${attempt_file}" ] || return 0
    expected_body="{\"aria_acl_rule\":{\"policy_id\":\"${policy_id}\",\"direction\":\"ingress\",\"priority\":200,\"action\":\"allow\",\"protocol\":\"tcp\",\"src_cidr\":\"${ACL_SELECTOR_CIDR}\"}}"
    IFS= read -r receipt_body <"${attempt_file}" || return 1
    [ "${receipt_body}" = "${expected_body}" ] || return 1
    curl_body GET aria-acl-rules >"${lookup_file}" || return 1
    matched="$(python3 - "${lookup_file}" "${policy_id}" "${ACL_SELECTOR_CIDR}" <<'PY'
import ipaddress,json,sys
rows=json.load(open(sys.argv[1],encoding="utf-8")).get("aria_acl_rules") or []
target=str(ipaddress.ip_network(sys.argv[3],strict=False))
matches=[row for row in rows if row.get("policy_id")==sys.argv[2] and row.get("direction")=="ingress" and row.get("priority")==200 and row.get("action")=="allow" and row.get("protocol")=="tcp" and str(ipaddress.ip_network(row.get("src_cidr"),strict=False))==target]
assert len(matches)<=1,matches
print(matches[0]["id"] if matches else "")
PY
    )" || return 1
    if [ -n "${matched}" ]; then
        curl_body DELETE "aria-acl-rules/${matched}" \
            >"${WORK_DIR}/semantic-delta-delete-response.json" || return 1
    fi
    rm -f "${attempt_file}" || return 1
}

assert_selector_deny_drop_ct_zero() {
    local label="$1" ct_count ct_packets ct_bytes drop_before drop_after
    read -r ct_count ct_packets ct_bytes < <(
        flow_conntrack_totals "${WORK_DIR}/${label}-after-conntrack.json"
    )
    drop_before="$(rule_counter_sum "${WORK_DIR}/${label}-before-rules.json" egress dropped_packets)"
    drop_after="$(rule_counter_sum "${WORK_DIR}/${label}-after-rules.json" egress dropped_packets)"
    [ "${ct_count}" -eq 0 ]
    [ "${ct_packets}" -eq 0 ]
    [ "${ct_bytes}" -eq 0 ]
    [ "${drop_after}" -gt "${drop_before}" ]
}

assert_exact_selector_state() {
    python3 - "${WORK_DIR}" "${ACL_SELECTOR_CIDR}" "${selector_group_id}" \
        "${exact_local_group_id}" <<'PY'
import ipaddress,json,os,struct,sys
root,selector_cidr,selector_group_id,local_group_id=sys.argv[1:]
selector_cidr=str(ipaddress.ip_network(selector_cidr,strict=False))
selector_group_id=int(selector_group_id); local_group_id=int(local_group_id)
def load(name):
    return json.load(open(os.path.join(root,name),encoding="utf-8"))
def bank(label):
    return int(open(os.path.join(root,label+"-runtime-compatibility.txt"),encoding="utf-8").read().split()[0])
def tap_id(label):
    value=load(label+"-iface-ctx.json")["value"]
    return struct.unpack("=I",bytes(value[:4]))[0]
def entries(label,kind,scope):
    out={}
    for row in load(label+"-"+kind+"-map.json"):
        key=bytes(row["key"]); value=bytes(row["value"])
        prefix=struct.unpack("=I",key[:4])[0]-32
        if int.from_bytes(key[4:8],"big") != scope:
            continue
        network=str(ipaddress.ip_network(
            "%s/%d" % (ipaddress.IPv4Address(key[8:12]),prefix),strict=False))
        out[network]=struct.unpack("=I",value[:4])[0]
    return out
exact_before_bank=bank("exact-before")
exact_after_bank=bank("exact-local")
exact_before_groups=load("exact-before-groups.json")["groups"]
exact_after_groups=load("exact-local-groups.json")["groups"]
tap=tap_id("exact-local")
exact_before_general=entries("exact-before","general-src",tap)
exact_after_general=entries("exact-local","general-src",tap)
exact_before_acl_entries=entries("exact-before","acl-src",tap*2+exact_before_bank)
exact_acl_entries=entries("exact-local","acl-src",tap*2+exact_after_bank)
exact_acl_ids=set(exact_acl_entries.values())
exact_cleanup_general_entries=entries("exact-cleanup","general-src",tap)
exact_cleanup_general_ids=set(exact_cleanup_general_entries.values())
assert exact_before_bank==exact_after_bank
assert exact_before_groups!=exact_after_groups
assert exact_before_general!=exact_after_general
assert exact_before_acl_entries==exact_acl_entries
assert exact_after_general[selector_cidr]==local_group_id
assert exact_acl_entries[selector_cidr]==selector_group_id
assert selector_group_id in exact_acl_ids
assert local_group_id not in exact_acl_ids
assert exact_cleanup_general_entries[selector_cidr]==selector_group_id
assert selector_group_id in exact_cleanup_general_ids
assert local_group_id not in exact_cleanup_general_ids
PY
}

assert_more_specific_selector_state() {
    python3 - "${WORK_DIR}" "${ACL_SELECTOR_CIDR}" "${MORE_SPECIFIC_CIDR}" \
        "${selector_group_id}" "${more_specific_group_id}" <<'PY'
import ipaddress,json,os,struct,sys
root,selector_cidr,more_specific_key,selector_group_id,more_specific_group_id=sys.argv[1:]
selector_cidr=str(ipaddress.ip_network(selector_cidr,strict=False))
more_specific_key=str(ipaddress.ip_network(more_specific_key,strict=False))
selector_group_id=int(selector_group_id); more_specific_group_id=int(more_specific_group_id)
def load(name):
    return json.load(open(os.path.join(root,name),encoding="utf-8"))
def bank(label):
    return int(open(os.path.join(root,label+"-runtime-compatibility.txt"),encoding="utf-8").read().split()[0])
def tap_id(label):
    return struct.unpack("=I",bytes(load(label+"-iface-ctx.json")["value"][:4]))[0]
def entries(label,kind,scope):
    out={}
    for row in load(label+"-"+kind+"-map.json"):
        key=bytes(row["key"]); value=bytes(row["value"])
        prefix=struct.unpack("=I",key[:4])[0]-32
        if int.from_bytes(key[4:8],"big") != scope:
            continue
        network=str(ipaddress.ip_network(
            "%s/%d" % (ipaddress.IPv4Address(key[8:12]),prefix),strict=False))
        out[network]=struct.unpack("=I",value[:4])[0]
    return out
old_bank=bank("more-specific-before-delta")
new_bank=bank("more-specific-after-delta")
tap=tap_id("more-specific-after-delta")
new_general_entries=entries("more-specific-after-delta","general-src",tap)
new_acl_entries=entries("more-specific-after-delta","acl-src",tap*2+new_bank)
new_general_ids=set(new_general_entries.values())
new_acl_ids=set(new_acl_entries.values())
new_acl_keys=set(new_acl_entries)
assert old_bank!=new_bank
assert new_general_entries[more_specific_key]==more_specific_group_id
assert more_specific_group_id in new_general_ids
assert more_specific_key not in new_acl_keys
assert more_specific_group_id not in new_acl_ids
assert new_acl_entries[selector_cidr]==selector_group_id
assert selector_group_id in new_acl_ids
PY
}

inject_legacy_selector_pollution() {
    local active_selector_key_hex legacy_local_group_id_hex injection_rc
    IFS='|' read -r active_selector_key_hex legacy_local_group_id_hex < <(
        python3 - "${WORK_DIR}/legacy-before-pollution-iface-ctx.json" \
            "${WORK_DIR}/legacy-before-pollution-runtime-compatibility.txt" \
            "${ACL_SELECTOR_CIDR}" "${legacy_local_group_id}" <<'PY'
import ipaddress,json,struct,sys
iface=json.load(open(sys.argv[1],encoding="utf-8"))
tap_id=struct.unpack("=I",bytes(iface["value"][:4]))[0]
bank=int(open(sys.argv[2],encoding="utf-8").read().split()[0])
network=ipaddress.ip_network(sys.argv[3],strict=False)
lpm_tap_id=tap_id*2+bank
key=struct.pack("=I",32+network.prefixlen)+lpm_tap_id.to_bytes(4,"big")+network.network_address.packed
value=struct.pack("=I",int(sys.argv[4]))
print(" ".join("%02x" % byte for byte in key)+"|"+
      " ".join("%02x" % byte for byte in value))
PY
    )
    if command bpftool map update pinned "${PIN_ROOT}/ACL_SRC_IPV4_TRIE" \
        key hex ${active_selector_key_hex} value hex ${legacy_local_group_id_hex}; then
        injection_rc=0
    else
        injection_rc=$?
    fi
    printf '%s\n' "${injection_rc}" >"${WORK_DIR}/legacy-pollution-map-update-rc.txt"
    [ "${injection_rc}" -eq 0 ]
    LEGACY_POLLUTION_INJECTED=true
}

wait_neutron_uds() {
    local attempt
    for attempt in $(seq 1 45); do
        if command curl --fail-with-body -sS --unix-socket "${NEUTRON_UDS}" \
            http://localhost/api/v1/neutron/status \
            >"${WORK_DIR}/restart-uds-${attempt}.json" 2>/dev/null; then
            return 0
        fi
        command sleep 1 || return 1
    done
    return 1
}

wait_managed_port_reattached() {
    local expected_phase="$1" attempt payload instances_payload
    for attempt in $(seq 1 45); do
        payload="${WORK_DIR}/restart-reattach-${attempt}.json"
        instances_payload="${WORK_DIR}/restart-reattach-${attempt}-instances.json"
        if ! command curl --fail-with-body -sS --unix-socket "${NEUTRON_UDS}" \
            http://localhost/api/v1/neutron/status >"${payload}"; then
            command sleep 1 || return 1
            continue
        fi
        if ! command curl --fail-with-body -sS \
            "${DATAPATH_HTTP}/api/v1/instances" >"${instances_payload}"; then
            command sleep 1 || return 1
            continue
        fi
        if python3 - "${payload}" "${instances_payload}" "${EXPECTED_PORT_ID}" \
            "${EXPECTED_IFNAME}" "${expected_phase}" <<'PY'
import json,sys
payload=json.load(open(sys.argv[1],encoding="utf-8"))
instances=json.load(open(sys.argv[2],encoding="utf-8"))
port_id,ifname,expected_phase=sys.argv[3:]
active_matches=[value for value in payload.get("active_instances") or [] if value==ifname]
managed_matches=[row for row in payload.get("managed_ports") or []
                 if row.get("port_id")==port_id and row.get("ifname")==ifname]
instance_matches=[row for row in instances.get("instances") or []
                  if row.get("name")==ifname]
assert len(active_matches)==1,(ifname,active_matches,payload)
assert len(managed_matches)==1,(port_id,ifname,managed_matches)
assert len(instance_matches)==1,(ifname,instance_matches)
item=instance_matches[0]
assert item.get("active") is True,item
assert expected_phase in ("recovery_required","ready","active"),expected_phase
if expected_phase=="recovery_required":
    assert item.get("acl_ready") is False,item
    assert item.get("readiness_reason")=="recovery_required",item
elif expected_phase=="ready":
    assert item.get("acl_ready") is True,item
    assert item.get("readiness_reason") is None,item
PY
        then
            return 0
        fi
        command sleep 1 || return 1
    done
    return 1
}

restart_managed_datapath() {
    local expected_phase="$1"
    command docker restart "${DATAPATH_SERVICE_NAME}" || return 1
    wait_neutron_uds || return 1
    wait_managed_port_reattached "${expected_phase}" || return 1
}

capture_datapath_log_cursor() {
    local label="$1"
    command docker logs --timestamps --tail 1 "${DATAPATH_SERVICE_NAME}" \
        >"${WORK_DIR}/${label}-log-cursor.txt" 2>&1 || return 1
    [ -s "${WORK_DIR}/${label}-log-cursor.txt" ] || return 1
}

capture_datapath_logs_since() {
    local label="$1" since raw
    since="$(awk 'NR==1 {print $1}' "${WORK_DIR}/${label}-log-cursor.txt")" || return 1
    [ -n "${since}" ] || return 1
    raw="${WORK_DIR}/${label}-datapath-since-raw.log"
    command docker logs --timestamps --since "${since}" "${DATAPATH_SERVICE_NAME}" \
        >"${raw}" 2>&1 || return 1
    python3 - "${since}" "${raw}" >"${WORK_DIR}/${label}-datapath.log" <<'PY' || return 1
import sys
cursor,path=sys.argv[1:]
for line in open(path,encoding="utf-8"):
    timestamp=line.split(None,1)[0] if line.split(None,1) else ""
    if timestamp>cursor:
        print(line,end="")
PY
}

assert_projection_repair_required() {
    python3 - "${WORK_DIR}/legacy-repair-required-instances.json" \
        "${WORK_DIR}/legacy-repair-required-config.json" \
        "${WORK_DIR}/legacy-repair-required-datapath.log" \
        "${WORK_DIR}/legacy-repair-required-tc-ingress.json" \
        "${WORK_DIR}/legacy-repair-required-tc-egress.json" \
        "${WORK_DIR}/legacy-repair-required-link.txt" \
        "${WORK_DIR}/legacy-repair-required-port-status.json" \
        "${EXPECTED_IFNAME}" "${EXPECTED_PORT_ID}" <<'PY'
import json,sys
instances=json.load(open(sys.argv[1],encoding="utf-8"))["instances"]
config=json.load(open(sys.argv[2],encoding="utf-8"))
projection_log=open(sys.argv[3],encoding="utf-8").read()
tc_ingress=json.load(open(sys.argv[4],encoding="utf-8"))
tc_egress=json.load(open(sys.argv[5],encoding="utf-8"))
link_text=open(sys.argv[6],encoding="utf-8").read()
port_payload=json.load(open(sys.argv[7],encoding="utf-8"))
ifname,port_id=sys.argv[8:]
item=next(row for row in instances if row.get("name")==ifname)
port_rows=port_payload.get("aria_acl_port_statuses") or port_payload.get("port_statuses") or []
target_port=next(row for row in port_rows if row.get("port_id")==port_id and row.get("ifname")==ifname)
acl_ready=item["acl_ready"]
readiness_reason=item["readiness_reason"]
expected_projection_reason="quiesced repairable preexisting ACL projection pending Neutron resync"
projection_reason=next((line for line in projection_log.splitlines() if expected_projection_reason in line and ("instance="+ifname) in line),None)
tc_ingress_live=(isinstance(tc_ingress,list) and any(row.get("kind")=="bpf" for row in tc_ingress))
tc_egress_live=(isinstance(tc_egress,list) and any(row.get("kind")=="bpf" for row in tc_egress))
links_intact=(tc_ingress_live and tc_egress_live and ifname in link_text)
repair_required=(acl_ready is False and config["acl"] is False and readiness_reason=="recovery_required" and projection_reason is not None and target_port.get("port_id")==port_id)
assert item.get("name")==ifname
assert target_port.get("port_id")==port_id
assert target_port.get("ifname")==ifname
assert tc_ingress_live is True
assert tc_egress_live is True
assert links_intact is True
assert readiness_reason=="recovery_required"
assert projection_reason is not None
assert expected_projection_reason in projection_reason
assert ("instance="+ifname) in projection_reason
assert repair_required is True
assert acl_ready is False
assert config["acl"] is False
PY
}

assert_legacy_pollution_evidence() {
    local bad_traffic_rc bad_ct_count bad_ct_packets bad_ct_bytes
    bad_traffic_rc="$(cat "${WORK_DIR}/legacy-polluted-traffic-rc.txt")"
    read -r bad_ct_count bad_ct_packets bad_ct_bytes < <(
        flow_conntrack_totals "${WORK_DIR}/legacy-polluted-after-conntrack.json"
    )
    python3 - "${WORK_DIR}" "${ACL_SELECTOR_CIDR}" "${legacy_local_group_id}" \
        "${bad_traffic_rc}" "${bad_ct_count}" "${bad_ct_packets}" \
        "${bad_ct_bytes}" <<'PY'
import ipaddress,json,os,struct,sys
(root,selector_cidr,legacy_local_group_id,bad_traffic_rc_raw,bad_ct_count_raw,
 bad_ct_packets_raw,bad_ct_bytes_raw)=sys.argv[1:]
selector_cidr=str(ipaddress.ip_network(selector_cidr,strict=False))
legacy_local_group_id=int(legacy_local_group_id)
bad_traffic_rc=int(bad_traffic_rc_raw); bad_ct_count=int(bad_ct_count_raw)
bad_ct_packets=int(bad_ct_packets_raw); bad_ct_bytes=int(bad_ct_bytes_raw)
bank=int(open(os.path.join(root,"legacy-polluted-after-runtime-compatibility.txt"),encoding="utf-8").read().split()[0])
iface=json.load(open(os.path.join(root,"legacy-polluted-after-iface-ctx.json"),encoding="utf-8"))
tap_id=struct.unpack("=I",bytes(iface["value"][:4]))[0]
payload=json.load(open(os.path.join(root,"legacy-polluted-after-acl-src-map.json"),encoding="utf-8"))
def lookup(rows,scope,cidr):
    found=[]
    for row in rows:
        key=bytes(row["key"]); value=bytes(row["value"])
        prefix=struct.unpack("=I",key[:4])[0]-32
        if int.from_bytes(key[4:8],"big") != scope:
            continue
        network=str(ipaddress.ip_network(
            "%s/%d" % (ipaddress.IPv4Address(key[8:12]),prefix),strict=False))
        if network==cidr:
            found.append(struct.unpack("=I",value[:4])[0])
    assert len(found)==1,found
    return found[0]
polluted_acl_value=lookup(payload,tap_id*2+bank,selector_cidr)
assert polluted_acl_value==legacy_local_group_id
assert bad_traffic_rc==0
assert bad_ct_count>0
assert bad_ct_packets>0
assert bad_ct_bytes>0
PY
}

assert_legacy_repair_evidence() {
    local injected_bank polluted_bank repaired_bank equal_before_bank equal_bank restart_bank
    local repaired_ct_count repaired_ct_packets repaired_ct_bytes
    local repaired_drop_before repaired_drop_after repaired_drop_delta
    injected_bank="$(awk '{print $1}' "${WORK_DIR}/legacy-polluted-after-runtime-compatibility.txt")"
    polluted_bank="$(awk '{print $1}' "${WORK_DIR}/legacy-before-repair-runtime-compatibility.txt")"
    repaired_bank="$(awk '{print $1}' "${WORK_DIR}/legacy-repaired-runtime-compatibility.txt")"
    equal_before_bank="$(awk '{print $1}' "${WORK_DIR}/legacy-before-equal-runtime-compatibility.txt")"
    equal_bank="$(awk '{print $1}' "${WORK_DIR}/legacy-after-equal-runtime-compatibility.txt")"
    restart_bank="$(awk '{print $1}' "${WORK_DIR}/legacy-clean-restart-runtime-compatibility.txt")"
    read -r repaired_ct_count repaired_ct_packets repaired_ct_bytes < <(
        flow_conntrack_totals "${WORK_DIR}/legacy-repaired-deny-after-conntrack.json"
    )
    repaired_drop_before="$(rule_counter_sum "${WORK_DIR}/legacy-repaired-deny-before-rules.json" egress dropped_packets)"
    repaired_drop_after="$(rule_counter_sum "${WORK_DIR}/legacy-repaired-deny-after-rules.json" egress dropped_packets)"
    repaired_drop_delta=$((repaired_drop_after - repaired_drop_before))
    python3 - "${WORK_DIR}" "${ACL_SELECTOR_CIDR}" "${selector_group_id}" \
        "${injected_bank}" "${polluted_bank}" "${repaired_bank}" "${equal_bank}" "${restart_bank}" \
        "${equal_before_bank}" "${repaired_ct_count}" "${repaired_drop_delta}" \
        "${EXPECTED_IFNAME}" "${EXPECTED_PORT_ID}" "${legacy_local_group_id}" <<'PY'
import ipaddress,json,os,re,struct,sys
(root,selector_cidr,selector_group_id,injected_bank,polluted_bank,repaired_bank,equal_bank,
 restart_bank,equal_before_bank,repaired_ct_count,repaired_drop_delta,ifname,
 port_id,legacy_local_group_id)=sys.argv[1:]
selector_cidr=str(ipaddress.ip_network(selector_cidr,strict=False))
selector_group_id=int(selector_group_id)
legacy_local_group_id=int(legacy_local_group_id)
injected_bank=int(injected_bank); polluted_bank=int(polluted_bank)
repaired_bank=int(repaired_bank)
equal_bank=int(equal_bank); restart_bank=int(restart_bank)
equal_before_bank=int(equal_before_bank)
repaired_ct_count=int(repaired_ct_count); repaired_drop_delta=int(repaired_drop_delta)
iface=json.load(open(os.path.join(root,"legacy-repaired-iface-ctx.json"),encoding="utf-8"))
tap_id=struct.unpack("=I",bytes(iface["value"][:4]))[0]
def load(name):
    return json.load(open(os.path.join(root,name),encoding="utf-8"))
def entries(label,kind,scope):
    out={}
    for row in load(label+"-"+kind+"-map.json"):
        key=bytes(row["key"]); value=bytes(row["value"])
        prefix=struct.unpack("=I",key[:4])[0]-32
        if int.from_bytes(key[4:8],"big") != scope:
            continue
        network=str(ipaddress.ip_network(
            "%s/%d" % (ipaddress.IPv4Address(key[8:12]),prefix),strict=False))
        out[network]=struct.unpack("=I",value[:4])[0]
    return out
def repair_counts(label):
    text=open(os.path.join(root,label+"-datapath.log"),encoding="utf-8").read()
    profile=[line for line in text.splitlines()
        if "neutron_acl_apply_profile" in line
        and ("ifname="+ifname) in line
        and ("port_id="+port_id) in line]
    true_count=sum("selector_repair_performed=true" in line for line in profile)
    false_count=sum("selector_repair_performed=false" in line for line in profile)
    return true_count,false_count
def repair_required_count(label):
    text=open(os.path.join(root,label+"-datapath.log"),encoding="utf-8").read()
    reason="quiesced repairable preexisting ACL projection pending Neutron resync"
    return sum(reason in line and ("instance="+ifname) in line
        for line in text.splitlines())
repaired_acl_value=entries("legacy-repaired","acl-src",tap_id*2+repaired_bank).get(selector_cidr)
clean_general_entries=entries("legacy-clean-restart","general-src",tap_id)
clean_bank_zero_entries=entries("legacy-clean-restart","acl-src",tap_id*2)
clean_bank_one_entries=entries("legacy-clean-restart","acl-src",tap_id*2+1)
clean_active_entries=(clean_bank_zero_entries if restart_bank==0 else clean_bank_one_entries)
clean_general_ids=set(clean_general_entries.values())
clean_bank_zero_ids=set(clean_bank_zero_entries.values())
clean_bank_one_ids=set(clean_bank_one_entries.values())
repair_true_count,repair_false_count=repair_counts("legacy-repair")
equal_true_count,equal_false_count=repair_counts("legacy-equal")
restart_true_count=repair_counts("legacy-clean-restart")[0]
restart_repair_required_count=repair_required_count("legacy-clean-restart")
instances=json.load(open(os.path.join(root,"legacy-clean-restart-instances.json"),encoding="utf-8"))["instances"]
config=json.load(open(os.path.join(root,"legacy-clean-restart-config.json"),encoding="utf-8"))
item=next(row for row in instances if row["name"]==ifname)
inventory_clean=(item["active"] is True and item["acl_ready"] is True and
                 item["readiness_reason"] is None and config["acl"] is True)
second_repair_switch=(equal_bank!=restart_bank)
assert injected_bank==polluted_bank
assert polluted_bank!=repaired_bank
assert repaired_acl_value==selector_group_id
assert repaired_ct_count==0
assert repaired_drop_delta>0
assert repaired_bank==equal_before_bank
assert equal_before_bank==equal_bank
assert repaired_bank==equal_bank
assert equal_bank==restart_bank
assert repair_true_count==1
assert equal_true_count==0
assert equal_false_count>=1
assert restart_true_count==0
assert restart_repair_required_count==0
assert clean_active_entries[selector_cidr]==selector_group_id
assert legacy_local_group_id not in clean_general_ids
assert legacy_local_group_id not in clean_bank_zero_ids
assert legacy_local_group_id not in clean_bank_one_ids
assert inventory_clean is True
assert second_repair_switch is False
PY
}

assert_selector_cleanup_state() {
    local label="$1" polluted_group_id="${2:-0}" expected_general_group_id="${3}" semantic_delta_id="${4:-}" local_ids="${5:-}" local_cidrs_arg="${6:-}" expected_live_groups="${7:-}"
    python3 - "${WORK_DIR}" "${label}" "${EXPECTED_IFNAME}" \
        "${polluted_group_id}" "${expected_general_group_id}" "${semantic_delta_id}" "${local_ids}" \
        "${local_cidrs_arg}" "${expected_live_groups}" \
        "${EXACT_LOCAL_GROUP_NAME} ${MORE_SPECIFIC_GROUP_NAME} ${LEGACY_LOCAL_GROUP_NAME}" \
        "${ACL_SELECTOR_CIDR}" "${selector_rule_id}" "${selector_group_id}" \
        "${policy_id}" "${CT_PROTOCOL}" <<'PY'
import ipaddress,json,os,struct,sys
root,label,ifname,polluted_group_id,expected_general_group_id_raw,semantic_delta_rule_id,local_ids,local_cidrs,expected_live_groups,attempted_names,selector_cidr,selector_rule_id,selector_group_id,policy_id,protocol=sys.argv[1:]
polluted_group_id=int(polluted_group_id or 0)
expected_general_group_id=int(expected_general_group_id_raw)
selector_group_id=int(selector_group_id)
selector_cidr=str(ipaddress.ip_network(selector_cidr,strict=False))
local_group_ids={int(value) for value in local_ids.split() if value}
local_cidrs={str(ipaddress.ip_network(value,strict=False)) for value in local_cidrs.split(",") if value}
expected_live_group_names={value for value in expected_live_groups.split() if value}
attempted_group_names={value for value in attempted_names.split() if value}
def load(name):
    return json.load(open(os.path.join(root,name),encoding="utf-8"))
iface=load(label+"-iface-ctx.json")
tap_id=struct.unpack("=I",bytes(iface["value"][:4]))[0]
active_bank=int(open(os.path.join(root,label+"-runtime-compatibility.txt"),encoding="utf-8").read().split()[0])
def entries(kind,scope):
    out={}
    for row in load(label+"-"+kind+"-map.json"):
        key=bytes(row["key"]); value=bytes(row["value"])
        prefix=struct.unpack("=I",key[:4])[0]-32
        if int.from_bytes(key[4:8],"big") != scope:
            continue
        cidr=str(ipaddress.ip_network("%s/%d" % (ipaddress.IPv4Address(key[8:12]),prefix),strict=False))
        out[cidr]=struct.unpack("=I",value[:4])[0]
    return out
general_entries={**entries("general-src",tap_id),**entries("general-dst",tap_id)}
acl_bank_zero_entries={**entries("acl-src",tap_id*2),**entries("acl-dst",tap_id*2)}
acl_bank_one_entries={**entries("acl-src",tap_id*2+1),**entries("acl-dst",tap_id*2+1)}
neutron_rules=load(label+"-neutron-rules.json").get("aria_acl_rules") or []
live_groups=load(label+"-groups.json").get("groups") or []
instances=load(label+"-instances.json").get("instances") or []
config=load(label+"-config.json")
item=next(row for row in instances if row["name"]==ifname)
live_rule_ids={str(row["id"]) for row in neutron_rules}
live_group_names={str(row["name"]) for row in live_groups}
general_keys=set(general_entries)
general_ids=set(general_entries.values())
acl_bank_zero_ids=set(acl_bank_zero_entries.values())
acl_bank_one_ids=set(acl_bank_one_entries.values())
active_acl_entries=(acl_bank_zero_entries if active_bank==0 else acl_bank_one_entries)
inactive_acl_entries=(acl_bank_one_entries if active_bank==0 else acl_bank_zero_entries)
inactive_selector_value=inactive_acl_entries.get(selector_cidr)
allowed_inactive_selector_values={None,selector_group_id}
baseline_selector_rule=next(row for row in neutron_rules if str(row.get("id"))==selector_rule_id)
semantic_delta_matches=[row for row in neutron_rules if row.get("policy_id")==policy_id and row.get("direction")=="ingress" and row.get("priority")==200 and row.get("action")=="allow" and row.get("protocol")=="tcp" and row.get("src_cidr")==selector_cidr]
acl_ready=item["acl_ready"]
assert polluted_group_id not in acl_bank_zero_ids
assert polluted_group_id not in acl_bank_one_ids
assert active_acl_entries[selector_cidr]==selector_group_id
assert inactive_selector_value in allowed_inactive_selector_values
assert selector_rule_id in live_rule_ids
assert baseline_selector_rule.get("policy_id")==policy_id
assert baseline_selector_rule.get("direction")=="ingress"
assert baseline_selector_rule.get("priority")==100
assert baseline_selector_rule.get("action")=="drop"
assert baseline_selector_rule.get("protocol")==protocol
assert baseline_selector_rule.get("src_cidr")==selector_cidr
assert len(semantic_delta_matches)==0
assert semantic_delta_rule_id not in live_rule_ids
assert attempted_group_names.intersection(live_group_names)==expected_live_group_names
assert local_cidrs.isdisjoint(general_keys)
assert local_group_ids.isdisjoint(general_ids)
assert local_group_ids.isdisjoint(acl_bank_zero_ids)
assert local_group_ids.isdisjoint(acl_bank_one_ids)
assert general_entries[selector_cidr]==expected_general_group_id
assert acl_ready is True
assert config["acl"] is True
PY
}

cleanup_selector_fixture_state() {
    local cleanup_rc=0 cleanup_semantic_delta_rule_id cleanup_local_ids
    [ "${SELECTOR_FIXTURES_STARTED}" = true ] || return 0
    cleanup_semantic_delta_rule_id="${semantic_delta_rule_id:-}"
    cleanup_local_ids="${selector_local_group_ids[*]:-}"
    if [ "${LEGACY_POLLUTION_INJECTED}" = true ]; then
        restart_managed_datapath active || cleanup_rc=1
        if [ "${cleanup_rc}" -eq 0 ]; then
            run_full_resync >"${WORK_DIR}/selector-cleanup-pollution-repair-resync.log" || cleanup_rc=1
        fi
        if [ "${cleanup_rc}" -eq 0 ]; then
            capture_selector_projection selector-pollution-clean || cleanup_rc=1
        fi
        if [ "${cleanup_rc}" -eq 0 ]; then
            assert_selector_cleanup_state selector-pollution-clean "${legacy_local_group_id}" \
                "${legacy_local_group_id}" "${cleanup_semantic_delta_rule_id}" "" "" \
                "${LEGACY_LOCAL_GROUP_NAME}" || cleanup_rc=1
        fi
        if [ "${cleanup_rc}" -eq 0 ]; then
            LEGACY_POLLUTION_INJECTED=false
        fi
    fi
    if remove_owned_acl_semantic_delta >"${WORK_DIR}/selector-cleanup-semantic-delta.json" 2>&1; then
        semantic_delta_rule_id=""
    else
        cleanup_rc=1
    fi
    if cleanup_selector_group_attempt "${EXACT_LOCAL_GROUP_NAME}" >"${WORK_DIR}/selector-cleanup-exact-group.json" 2>&1; then
        exact_local_group_id=""
    else
        cleanup_rc=1
    fi
    if cleanup_selector_group_attempt "${MORE_SPECIFIC_GROUP_NAME}" >"${WORK_DIR}/selector-cleanup-more-specific-group.json" 2>&1; then
        more_specific_group_id=""
    else
        cleanup_rc=1
    fi
    if [ "${LEGACY_POLLUTION_INJECTED}" = false ]; then
        if cleanup_selector_group_attempt "${LEGACY_LOCAL_GROUP_NAME}" >"${WORK_DIR}/selector-cleanup-legacy-group.json" 2>&1; then
            legacy_local_group_id=""
        else
            cleanup_rc=1
        fi
    fi
    run_full_resync >"${WORK_DIR}/selector-cleanup-full-resync.log" || cleanup_rc=1
    capture_selector_projection selector-failclosed-cleanup || cleanup_rc=1
    assert_selector_cleanup_state selector-failclosed-cleanup 0 "${selector_group_id}" \
        "${cleanup_semantic_delta_rule_id}" "${cleanup_local_ids}" "${MORE_SPECIFIC_CIDR}" "" || cleanup_rc=1
    [ "${cleanup_rc}" -eq 0 ]
}

run_exact_selector_isolation_fixture() {
    if [ "${IP_FAMILY}" = ipv6 ]; then
        EXACT_SELECTOR_FIXTURE_STATUS="skipped_ipv6"
    fi
    [ "${IP_FAMILY}" = ipv4 ] || return 0
    EXACT_SELECTOR_FIXTURE_STATUS="failed"
    reverify_selector_deny_baseline exact-baseline
    selector_group_id="$(resolve_selector_group_id exact-baseline-deny-after)" || return 1
    [ -n "${selector_group_id}" ] || return 1
    SELECTOR_FIXTURES_STARTED=true
    capture_selector_projection exact-before
    exact_local_group_id="$(create_selector_fixture_group "${EXACT_LOCAL_GROUP_NAME}" "${ACL_SELECTOR_CIDR}")" || return 1
    [ -n "${exact_local_group_id}" ] || return 1
    selector_local_group_ids+=("${exact_local_group_id}")
    capture_selector_projection exact-local
    run_captured_selector_flow exact-deny 2 deny
    assert_selector_deny_drop_ct_zero exact-deny
    delete_selector_fixture_group "${EXACT_LOCAL_GROUP_NAME}"
    capture_selector_projection exact-cleanup
    assert_exact_selector_state
    exact_local_group_id=""
    reverify_selector_deny_baseline exact-cleanup
    EXACT_SELECTOR_FIXTURE_STATUS="pass"
}

run_more_specific_selector_isolation_fixture() {
    if [ "${IP_FAMILY}" = ipv6 ]; then
        MORE_SPECIFIC_SELECTOR_FIXTURE_STATUS="skipped_ipv6"
    fi
    [ "${IP_FAMILY}" = ipv4 ] || return 0
    MORE_SPECIFIC_SELECTOR_FIXTURE_STATUS="failed"
    reverify_selector_deny_baseline more-specific-baseline
    selector_group_id="$(resolve_selector_group_id more-specific-baseline-deny-after)" || return 1
    [ -n "${selector_group_id}" ] || return 1
    SELECTOR_FIXTURES_STARTED=true
    require_wider_owned_selector
    more_specific_group_id="$(create_selector_fixture_group "${MORE_SPECIFIC_GROUP_NAME}" "${MORE_SPECIFIC_CIDR}")" || return 1
    [ -n "${more_specific_group_id}" ] || return 1
    selector_local_group_ids+=("${more_specific_group_id}")
    capture_selector_projection more-specific-before-delta
    apply_owned_acl_semantic_delta
    run_full_resync >"${WORK_DIR}/more-specific-full-resync.log"
    capture_selector_projection more-specific-after-delta
    assert_more_specific_selector_state
    run_captured_selector_flow more-specific-deny 2 deny
    assert_selector_deny_drop_ct_zero more-specific-deny
    remove_owned_acl_semantic_delta
    semantic_delta_rule_id=""
    delete_selector_fixture_group "${MORE_SPECIFIC_GROUP_NAME}"
    more_specific_group_id=""
    run_full_resync >"${WORK_DIR}/more-specific-cleanup-resync.log"
    capture_selector_projection more-specific-cleanup
    reverify_selector_deny_baseline more-specific-cleanup
    MORE_SPECIFIC_SELECTOR_FIXTURE_STATUS="pass"
}

run_legacy_selector_repair_fixture() {
    if [ "${IP_FAMILY}" = ipv6 ]; then
        LEGACY_SELECTOR_REPAIR_FIXTURE_STATUS="skipped_ipv6"
    fi
    [ "${IP_FAMILY}" = ipv4 ] || return 0
    LEGACY_SELECTOR_REPAIR_FIXTURE_STATUS="failed"
    reverify_selector_deny_baseline legacy-baseline
    selector_group_id="$(resolve_selector_group_id legacy-baseline-deny-after)" || return 1
    [ -n "${selector_group_id}" ] || return 1
    SELECTOR_FIXTURES_STARTED=true
    legacy_local_group_id="$(create_selector_fixture_group "${LEGACY_LOCAL_GROUP_NAME}" "${ACL_SELECTOR_CIDR}")" || return 1
    [ -n "${legacy_local_group_id}" ] || return 1
    selector_local_group_ids+=("${legacy_local_group_id}")
    capture_selector_projection legacy-before-pollution
    inject_legacy_selector_pollution
    run_captured_selector_flow legacy-polluted 2 pass
    assert_legacy_pollution_evidence
    capture_datapath_log_cursor legacy-repair-required
    restart_managed_datapath recovery_required
    capture_datapath_logs_since legacy-repair-required
    capture_selector_projection legacy-repair-required
    assert_projection_repair_required
    capture_selector_projection legacy-before-repair
    capture_datapath_log_cursor legacy-repair
    run_full_resync >"${WORK_DIR}/legacy-repair-full-resync.log"
    capture_datapath_logs_since legacy-repair
    capture_selector_projection legacy-repaired
    run_captured_selector_flow legacy-repaired-deny 2 deny
    assert_selector_deny_drop_ct_zero legacy-repaired-deny
    capture_selector_projection legacy-before-equal
    capture_datapath_log_cursor legacy-equal
    run_full_resync >"${WORK_DIR}/legacy-equal-full-resync.log"
    capture_datapath_logs_since legacy-equal
    capture_selector_projection legacy-after-equal
    delete_selector_fixture_group "${LEGACY_LOCAL_GROUP_NAME}"
    run_full_resync >"${WORK_DIR}/legacy-local-group-cleanup-resync.log"
    capture_datapath_log_cursor legacy-clean-restart
    restart_managed_datapath ready
    wait_port_enforced
    capture_datapath_logs_since legacy-clean-restart
    capture_selector_projection legacy-clean-restart
    assert_legacy_repair_evidence
    LEGACY_POLLUTION_INJECTED=false
    legacy_local_group_id=""
    run_full_resync >"${WORK_DIR}/legacy-cleanup-resync.log"
    capture_selector_projection legacy-cleanup
    reverify_selector_deny_baseline legacy-cleanup
    LEGACY_SELECTOR_REPAIR_FIXTURE_STATUS="pass"
}

write_summary() {
    EXACT_SELECTOR_FIXTURE_STATUS="${EXACT_SELECTOR_FIXTURE_STATUS}" \
    MORE_SPECIFIC_SELECTOR_FIXTURE_STATUS="${MORE_SPECIFIC_SELECTOR_FIXTURE_STATUS}" \
    LEGACY_SELECTOR_REPAIR_FIXTURE_STATUS="${LEGACY_SELECTOR_REPAIR_FIXTURE_STATUS}" \
        python3 <<'PY'
import json,os
selector_fixtures={
    "exact":os.environ["EXACT_SELECTOR_FIXTURE_STATUS"],
    "more_specific":os.environ["MORE_SPECIFIC_SELECTOR_FIXTURE_STATUS"],
    "legacy_repair":os.environ["LEGACY_SELECTOR_REPAIR_FIXTURE_STATUS"],
}
selector_isolation={
    "fixtures":selector_fixtures,
    "complete":all(status=="pass" for status in selector_fixtures.values()),
}
out={"selector_isolation":selector_isolation}
print(json.dumps(out,sort_keys=True,indent=2))
PY
}

cleanup() {
    set +e
    if ! cleanup_selector_fixture_state; then
        record_cleanup_error "cleanup-selector-fixture-state failed"
    fi
    if ! cleanup_selector_rule_attempt; then
        record_cleanup_error "cleanup-selector-rule-attempt failed"
    fi
}
trap cleanup EXIT
''' + main_body


def _run_managed_selector_fixture_mutation_self_tests(verbose=False):
    direct_main = """
run_deny_evidence
prepare_owned_selector_fixture
run_exact_selector_isolation_fixture
run_more_specific_selector_isolation_fixture
run_legacy_selector_repair_fixture
"""
    safe = _selector_fixture_self_test_source(direct_main)
    failures = []
    direct_errors = _managed_selector_field_fixture_errors(safe)
    if direct_errors:
        failures.append(
            "managed selector fixture checker rejected direct safe fixture: %s"
            % direct_errors
        )
    status_errors = _selector_fixture_status_contract_errors(safe)
    if status_errors:
        failures.append(
            "selector fixture status checker rejected synthetic safe fixture: %s"
            % status_errors
        )
    status_specs = (
        (
            "exact status initialization missing",
            'EXACT_SELECTOR_FIXTURE_STATUS="not_run"\n',
            "",
            "global status must initialize exactly once to not_run",
        ),
        (
            "more-specific skipped state missing",
            '        MORE_SPECIFIC_SELECTOR_FIXTURE_STATUS="skipped_ipv6"\n',
            "",
            "status must transition through conditional skipped_ipv6",
        ),
        (
            "legacy failed state missing",
            '    LEGACY_SELECTOR_REPAIR_FIXTURE_STATUS="failed"\n',
            "",
            "status must transition through conditional skipped_ipv6",
        ),
        (
            "exact pass state missing",
            '    EXACT_SELECTOR_FIXTURE_STATUS="pass"\n',
            "",
            "status must transition through conditional skipped_ipv6",
        ),
        (
            "IPv6 skip fabricated outside guard",
            '    if [ "${IP_FAMILY}" = ipv6 ]; then\n'
            '        EXACT_SELECTOR_FIXTURE_STATUS="skipped_ipv6"\n'
            '    fi\n',
            '    EXACT_SELECTOR_FIXTURE_STATUS="skipped_ipv6"\n',
            "status must transition through conditional skipped_ipv6",
        ),
        (
            "exact pass before final proof",
            '    reverify_selector_deny_baseline exact-cleanup\n'
            '    EXACT_SELECTOR_FIXTURE_STATUS="pass"\n',
            '    EXACT_SELECTOR_FIXTURE_STATUS="pass"\n'
            '    reverify_selector_deny_baseline exact-cleanup\n',
            "mark pass only after its final proof",
        ),
        (
            "exact final proof failure masked",
            '    reverify_selector_deny_baseline exact-cleanup\n',
            '    reverify_selector_deny_baseline exact-cleanup || true\n',
            "final proof must be one depth-zero exact command",
        ),
        (
            "summary env status fabricated",
            'EXACT_SELECTOR_FIXTURE_STATUS="${EXACT_SELECTOR_FIXTURE_STATUS}"',
            'EXACT_SELECTOR_FIXTURE_STATUS="pass"',
            "must export only the real EXACT_SELECTOR_FIXTURE_STATUS",
        ),
        (
            "summary env status overridden",
            'EXACT_SELECTOR_FIXTURE_STATUS="${EXACT_SELECTOR_FIXTURE_STATUS}" \\\n',
            'EXACT_SELECTOR_FIXTURE_STATUS="${EXACT_SELECTOR_FIXTURE_STATUS}" \\\n'
            'EXACT_SELECTOR_FIXTURE_STATUS="pass" \\\n',
            "must export only the real EXACT_SELECTOR_FIXTURE_STATUS",
        ),
        (
            "summary env command override",
            "        python3 <<'PY'",
            '        env EXACT_SELECTOR_FIXTURE_STATUS="pass" python3 <<\'PY\'',
            "must export only the real EXACT_SELECTOR_FIXTURE_STATUS",
        ),
        (
            "summary exported status override",
            "write_summary() {\n",
            'write_summary() {\n    export EXACT_SELECTOR_FIXTURE_STATUS="pass"\n',
            "must export only the real EXACT_SELECTOR_FIXTURE_STATUS",
        ),
        (
            "summary printf status override",
            "write_summary() {\n",
            'write_summary() {\n    printf -v EXACT_SELECTOR_FIXTURE_STATUS %s pass\n',
            "must export only the real EXACT_SELECTOR_FIXTURE_STATUS",
        ),
        (
            "summary fixture status fabricated",
            'os.environ["MORE_SPECIFIC_SELECTOR_FIXTURE_STATUS"]',
            '"pass"',
            "fixture more_specific must come from real env status",
        ),
        (
            "summary fixture status missing",
            '    "legacy_repair":os.environ["LEGACY_SELECTOR_REPAIR_FIXTURE_STATUS"],\n',
            "",
            "fixtures must contain exact, more_specific, and legacy_repair",
        ),
        (
            "summary complete fabricated",
            'all(status=="pass" for status in selector_fixtures.values())',
            "True",
            "complete must be all(status == 'pass')",
        ),
        (
            "summary complete overwritten",
            'out={"selector_isolation":selector_isolation}',
            'selector_isolation["complete"]=True\n'
            'out={"selector_isolation":selector_isolation}',
            "must use one json/os import, unique allowed assignments",
        ),
        (
            "summary all builtin shadowed",
            'selector_isolation={\n',
            'all=lambda values: True\nselector_isolation={\n',
            "must use one json/os import, unique allowed assignments",
        ),
        (
            "summary all builtin shadowed by named expression",
            "selector_fixtures={\n",
            "keys=(all:=lambda values: True) and ()\nselector_fixtures={\n",
            "must use one json/os import, unique allowed assignments",
        ),
        (
            "summary selector isolation detached",
            'out={"selector_isolation":selector_isolation}',
            'out={"selector_isolation":{}}',
            "must publish selector_isolation from the validated fixture state",
        ),
        (
            "summary printed payload fabricated",
            'print(json.dumps(out,sort_keys=True,indent=2))',
            'print(json.dumps({},sort_keys=True,indent=2))',
            "must print json.dumps(out) exactly once",
        ),
    )
    for label, needle, replacement, expected in status_specs:
        if safe.count(needle) != 1:
            failures.append(
                "selector fixture status mutation anchor %s is not unique" % label
            )
            continue
        mutant = safe.replace(needle, replacement, 1)
        mutant_errors = _selector_fixture_status_contract_errors(mutant)
        if not any(expected in error for error in mutant_errors):
            failures.append(
                "selector fixture status mutation %s was accepted" % label
            )
        elif verbose:
            print(
                "PASS: rejected selector fixture status mutation %s" % label
            )

    wrapper_main = """
run_selector_fixture_suite() {
    [ "${IP_FAMILY}" = ipv4 ] || return 0
    prepare_owned_selector_fixture
    run_exact_selector_isolation_fixture
    run_more_specific_selector_isolation_fixture
    run_legacy_selector_repair_fixture
}
run_deny_evidence
run_selector_fixture_suite
"""
    wrapper_safe = _selector_fixture_self_test_source(wrapper_main)
    wrapper_errors = _managed_selector_field_fixture_errors(wrapper_safe)
    if wrapper_errors:
        failures.append(
            "managed selector fixture checker rejected one-layer wrapper: %s"
            % wrapper_errors
        )

    alias_main = """
run_selector_fixture_suite() {
    [ "${IP_FAMILY}" = ipv4 ] || return 0
    prepare_owned_selector_fixture
    run_exact_selector_isolation_fixture
    run_more_specific_selector_isolation_fixture
    run_legacy_selector_repair_fixture
}
run_deny_evidence
selector_fixture_runner=run_selector_fixture_suite
"${selector_fixture_runner}"
"""
    alias_safe = _selector_fixture_self_test_source(alias_main)
    alias_errors = _managed_selector_field_fixture_errors(alias_safe)
    if alias_errors:
        failures.append(
            "managed selector fixture checker rejected aliased wrapper: %s"
            % alias_errors
        )

    specs = (
        ("capture groups", safe, '${label}-groups.json', "managed selector capture"),
        ("capture policies", safe, '${label}-policies.json', "managed selector capture"),
        ("capture general source", safe, '${label}-general-src-map.json', "managed selector capture"),
        ("capture general destination", safe, '${label}-general-dst-map.json', "managed selector capture"),
        ("capture ACL source", safe, '${label}-acl-src-map.json', "managed selector capture"),
        ("capture ACL destination", safe, '${label}-acl-dst-map.json', "managed selector capture"),
        (
            "traffic rc artifact",
            safe,
            '${label}-traffic-rc.txt',
            "persist rc/maps/counters/bank/CT before assertion",
        ),
        (
            "traffic after-capture",
            safe,
            '    capture_selector_projection "${label}-after"\n',
            "persist rc/maps/counters/bank/CT before assertion",
        ),
        (
            "traffic post-capture assertion",
            safe,
            '    assert_selector_traffic_result "${label}" "${traffic_rc}" "${expectation}"\n',
            "persist rc/maps/counters/bank/CT before assertion",
        ),
        (
            "baseline full resync",
            safe,
            '    run_full_resync >"${WORK_DIR}/${label}-full-resync.log"\n',
            "baseline must full-resync",
        ),
        (
            "baseline CT assertion",
            safe,
            '    assert_selector_deny_drop_ct_zero "${label}-deny"\n',
            "baseline must full-resync",
        ),
        (
            "dynamic selector resolution",
            safe,
            'assert len(candidates)==1',
            "managed selector ID resolution",
        ),
        (
            "wider selector guard",
            safe,
            'assert selector.prefixlen<32',
            "wider selector guard",
        ),
        (
            "local /32 binding",
            safe,
            'print(selector,"%s/32" % source)',
            "owned selector fixture preparation",
        ),
        (
            "owned selector wider CIDR derivation",
            safe,
            'selector=ipaddress.ip_network("%s/24" % source,strict=False)',
            "owned selector fixture preparation",
        ),
        (
            "owned selector deny rule",
            safe,
            '    created_selector_rule_id="$(curl_body POST aria-acl-rules "${selector_rule_body}" | json_field aria_acl_rule.id)" || return 1\n',
            "owned selector fixture preparation",
        ),
        (
            "owned ACL semantic delta",
            safe,
            '    curl_body POST aria-acl-rules "${body}" >"${response_file}" || return 1\n',
            "semantic delta must persist",
        ),
        (
            "owned ACL semantic cleanup",
            safe,
            '        curl_body DELETE "aria-acl-rules/${matched}" \\\n'
            '            >"${WORK_DIR}/semantic-delta-delete-response.json" || return 1\n',
            "semantic delta cleanup",
        ),
        (
            "deny drop delta",
            safe,
            '[ "${drop_after}" -gt "${drop_before}" ]',
            "selector deny/drop/CT proof",
        ),
        (
            "deny CT zero",
            safe,
            '[ "${ct_count}" -eq 0 ]',
            "selector deny/drop/CT proof",
        ),
        (
            "exact bank unchanged",
            safe,
            'assert exact_before_bank==exact_after_bank',
            "exact selector fixture assertion",
        ),
        (
            "exact persisted state changed",
            safe,
            'assert exact_before_groups!=exact_after_groups',
            "exact selector fixture assertion",
        ),
        (
            "exact general state changed",
            safe,
            'assert exact_before_general!=exact_after_general',
            "exact selector fixture assertion",
        ),
        (
            "exact active ACL projection unchanged",
            safe,
            'assert exact_before_acl_entries==exact_acl_entries',
            "exact selector fixture assertion",
        ),
        (
            "exact ACL selector retained",
            safe,
            'assert exact_acl_entries[selector_cidr]==selector_group_id',
            "exact selector fixture assertion",
        ),
        (
            "exact local ID excluded from ACL",
            safe,
            'assert local_group_id not in exact_acl_ids',
            "exact selector fixture assertion",
        ),
        (
            "exact cleanup observability restored",
            safe,
            'assert exact_cleanup_general_entries[selector_cidr]==selector_group_id',
            "exact selector fixture assertion",
        ),
        (
            "exact local group creation",
            safe,
            '    exact_local_group_id="$(create_selector_fixture_group "${EXACT_LOCAL_GROUP_NAME}" "${ACL_SELECTOR_CIDR}")" || return 1\n',
            "exact selector fixture must isolate",
        ),
        (
            "exact local group cleanup",
            safe,
            '    delete_selector_fixture_group "${EXACT_LOCAL_GROUP_NAME}"\n',
            "exact selector fixture must isolate",
        ),
        (
            "more-specific bank switch",
            safe,
            'assert old_bank!=new_bank',
            "more-specific selector fixture assertion",
        ),
        (
            "more-specific general representation",
            safe,
            'assert new_general_entries[more_specific_key]==more_specific_group_id',
            "more-specific selector fixture assertion",
        ),
        (
            "more-specific ACL exclusion",
            safe,
            'assert more_specific_key not in new_acl_keys',
            "more-specific selector fixture assertion",
        ),
        (
            "more-specific selector retained",
            safe,
            'assert new_acl_entries[selector_cidr]==selector_group_id',
            "more-specific selector fixture assertion",
        ),
        (
            "more-specific semantic resync",
            safe,
            '    run_full_resync >"${WORK_DIR}/more-specific-full-resync.log"\n',
            "more-specific selector fixture must stage",
        ),
        (
            "more-specific deny traffic",
            safe,
            '    run_captured_selector_flow more-specific-deny 2 deny\n',
            "more-specific selector fixture must stage",
        ),
        (
            "more-specific local group creation",
            safe,
            '    more_specific_group_id="$(create_selector_fixture_group "${MORE_SPECIFIC_GROUP_NAME}" "${MORE_SPECIFIC_CIDR}")" || return 1\n',
            "more-specific selector fixture must stage",
        ),
        (
            "more-specific local cleanup",
            safe,
            '    delete_selector_fixture_group "${MORE_SPECIFIC_GROUP_NAME}"\n',
            "more-specific selector fixture must stage",
        ),
        (
            "legacy persisted local group",
            safe,
            '    legacy_local_group_id="$(create_selector_fixture_group "${LEGACY_LOCAL_GROUP_NAME}" "${ACL_SELECTOR_CIDR}")" || return 1\n',
            "legacy selector fixture must capture pollution",
        ),
        (
            "legacy active ACL pollution",
            safe,
            'bpftool map update pinned "${PIN_ROOT}/ACL_SRC_IPV4_TRIE"',
            "legacy selector pollution helper",
        ),
        (
            "legacy map update rc",
            safe,
            'legacy-pollution-map-update-rc.txt',
            "legacy selector pollution helper",
        ),
        (
            "legacy bad PASS",
            safe,
            'assert bad_traffic_rc==0',
            "legacy bad PASS/CT proof",
        ),
        (
            "legacy bad CT",
            safe,
            'assert bad_ct_count>0',
            "legacy bad PASS/CT proof",
        ),
        (
            "legacy bad CT packets",
            safe,
            'assert bad_ct_packets>0',
            "legacy bad PASS/CT proof",
        ),
        (
            "legacy bad CT bytes",
            safe,
            'assert bad_ct_bytes>0',
            "legacy bad PASS/CT proof",
        ),
        (
            "legacy repair-required gate",
            safe,
            'assert repair_required is True',
            "legacy repair-required gate proof",
        ),
        (
            "legacy restart stays repair-required",
            safe,
            'assert injected_bank==polluted_bank',
            "legacy one-repair/no-op/restart proof",
        ),
        (
            "legacy repair switch",
            safe,
            'assert polluted_bank!=repaired_bank',
            "legacy one-repair/no-op/restart proof",
        ),
        (
            "legacy repaired selector",
            safe,
            'assert repaired_acl_value==selector_group_id',
            "legacy one-repair/no-op/restart proof",
        ),
        (
            "legacy strict CT cleanup",
            safe,
            'assert repaired_ct_count==0',
            "legacy one-repair/no-op/restart proof",
        ),
        (
            "legacy restored deny",
            safe,
            'assert repaired_drop_delta>0',
            "legacy one-repair/no-op/restart proof",
        ),
        (
            "legacy equal baseline bank",
            safe,
            'assert repaired_bank==equal_before_bank',
            "legacy one-repair/no-op/restart proof",
        ),
        (
            "legacy equal snapshot no-switch",
            safe,
            'assert equal_before_bank==equal_bank',
            "legacy one-repair/no-op/restart proof",
        ),
        (
            "legacy equal no-switch",
            safe,
            'assert repaired_bank==equal_bank',
            "legacy one-repair/no-op/restart proof",
        ),
        (
            "legacy clean restart no-switch",
            safe,
            'assert equal_bank==restart_bank',
            "legacy one-repair/no-op/restart proof",
        ),
        (
            "legacy clean inventory",
            safe,
            'assert inventory_clean is True',
            "legacy one-repair/no-op/restart proof",
        ),
        (
            "legacy second repair absent",
            safe,
            'assert second_repair_switch is False',
            "legacy one-repair/no-op/restart proof",
        ),
        (
            "legacy bad flow before restart",
            safe,
            '    run_captured_selector_flow legacy-polluted 2 pass\n',
            "legacy selector fixture must capture pollution",
        ),
        (
            "legacy repair full resync",
            safe,
            '    run_full_resync >"${WORK_DIR}/legacy-repair-full-resync.log"\n',
            "legacy selector fixture must capture pollution",
        ),
        (
            "legacy next equal resync",
            safe,
            '    run_full_resync >"${WORK_DIR}/legacy-equal-full-resync.log"\n',
            "legacy selector fixture must capture pollution",
        ),
        (
            "legacy clean restart wait",
            safe,
            '    capture_datapath_log_cursor legacy-clean-restart\n    restart_managed_datapath ready\n    wait_port_enforced\n    capture_datapath_logs_since legacy-clean-restart\n    capture_selector_projection legacy-clean-restart\n',
            "legacy selector fixture must capture pollution",
        ),
        (
            "legacy local cleanup",
            safe,
            '    delete_selector_fixture_group "${LEGACY_LOCAL_GROUP_NAME}"\n',
            "legacy selector fixture must capture pollution",
        ),
        (
            "legacy successful pollution disarm",
            safe,
            '    assert_legacy_repair_evidence\n    LEGACY_POLLUTION_INJECTED=false\n',
            "legacy selector fixture must capture pollution",
        ),
        (
            "fail-closed cleanup errexit suppression",
            safe,
            '    set +e\n',
            "top-level cleanup must record",
        ),
        (
            "fail-closed cleanup invocation",
            safe,
            '    if ! cleanup_selector_fixture_state; then\n',
            "top-level cleanup must record",
        ),
        (
            "fail-closed cleanup error recording",
            safe,
            '        record_cleanup_error "cleanup-selector-fixture-state failed"\n',
            "top-level cleanup must record",
        ),
        (
            "fail-closed semantic delta cleanup",
            safe,
            '    if remove_owned_acl_semantic_delta >"${WORK_DIR}/selector-cleanup-semantic-delta.json" 2>&1; then\n',
            "fixture cleanup must fail closed",
        ),
        (
            "fail-closed exact group cleanup",
            safe,
            '    if cleanup_selector_group_attempt "${EXACT_LOCAL_GROUP_NAME}" >"${WORK_DIR}/selector-cleanup-exact-group.json" 2>&1; then\n',
            "fixture cleanup must fail closed",
        ),
        (
            "fail-closed more-specific group cleanup",
            safe,
            '    if cleanup_selector_group_attempt "${MORE_SPECIFIC_GROUP_NAME}" >"${WORK_DIR}/selector-cleanup-more-specific-group.json" 2>&1; then\n',
            "fixture cleanup must fail closed",
        ),
        (
            "fail-closed legacy group cleanup",
            safe,
            '        if cleanup_selector_group_attempt "${LEGACY_LOCAL_GROUP_NAME}" >"${WORK_DIR}/selector-cleanup-legacy-group.json" 2>&1; then\n',
            "fixture cleanup must fail closed",
        ),
        (
            "fail-closed pollution repair",
            safe,
            '            capture_selector_projection selector-pollution-clean || cleanup_rc=1\n',
            "fixture cleanup must fail closed",
        ),
        (
            "fail-closed polluted group preservation",
            safe,
            '    if [ "${LEGACY_POLLUTION_INJECTED}" = false ]; then\n',
            "fixture cleanup must fail closed",
        ),
        (
            "fail-closed cleanup resync",
            safe,
            '    run_full_resync >"${WORK_DIR}/selector-cleanup-full-resync.log" || cleanup_rc=1\n',
            "fixture cleanup must fail closed",
        ),
        (
            "fail-closed cleanup evidence",
            safe,
            '    capture_selector_projection selector-failclosed-cleanup || cleanup_rc=1\n',
            "fixture cleanup must fail closed",
        ),
        (
            "direct selector suite ordering",
            safe,
            '\nrun_deny_evidence\n',
            "must be invoked directly or through one orchestration wrapper",
        ),
        (
            "direct selector preparation invocation",
            safe,
            '\nprepare_owned_selector_fixture\n',
            "must be invoked directly or through one orchestration wrapper",
        ),
        (
            "direct exact invocation",
            safe,
            '\nrun_exact_selector_isolation_fixture\n',
            "must be invoked directly or through one orchestration wrapper",
        ),
        (
            "direct more-specific invocation",
            safe,
            '\nrun_more_specific_selector_isolation_fixture\n',
            "must be invoked directly or through one orchestration wrapper",
        ),
        (
            "direct legacy invocation",
            safe,
            '\nrun_legacy_selector_repair_fixture\n',
            "must be invoked directly or through one orchestration wrapper",
        ),
        (
            "wrapper selector suite ordering",
            wrapper_safe,
            '\nrun_deny_evidence\n',
            "must be invoked directly or through one orchestration wrapper",
        ),
        (
            "wrapper selector preparation invocation",
            wrapper_safe,
            '    prepare_owned_selector_fixture\n',
            "must be invoked directly or through one orchestration wrapper",
        ),
        (
            "wrapper exact invocation",
            wrapper_safe,
            '    run_exact_selector_isolation_fixture\n',
            "must be invoked directly or through one orchestration wrapper",
        ),
        (
            "wrapper more-specific invocation",
            wrapper_safe,
            '    run_more_specific_selector_isolation_fixture\n',
            "must be invoked directly or through one orchestration wrapper",
        ),
        (
            "wrapper legacy invocation",
            wrapper_safe,
            '    run_legacy_selector_repair_fixture\n',
            "must be invoked directly or through one orchestration wrapper",
        ),
        (
            "aliased wrapper selector suite ordering",
            alias_safe,
            '\nrun_deny_evidence\n',
            "must be invoked directly or through one orchestration wrapper",
        ),
        (
            "aliased wrapper selector preparation invocation",
            alias_safe,
            '    prepare_owned_selector_fixture\n',
            "must be invoked directly or through one orchestration wrapper",
        ),
        (
            "aliased wrapper exact invocation",
            alias_safe,
            '    run_exact_selector_isolation_fixture\n',
            "must be invoked directly or through one orchestration wrapper",
        ),
        (
            "aliased wrapper more-specific invocation",
            alias_safe,
            '    run_more_specific_selector_isolation_fixture\n',
            "must be invoked directly or through one orchestration wrapper",
        ),
        (
            "aliased wrapper legacy invocation",
            alias_safe,
            '    run_legacy_selector_repair_fixture\n',
            "must be invoked directly or through one orchestration wrapper",
        ),
        (
            "aliased wrapper assignment",
            alias_safe,
            'selector_fixture_runner=run_selector_fixture_suite\n',
            "must be invoked directly or through one orchestration wrapper",
        ),
        (
            "aliased wrapper call",
            alias_safe,
            '"${selector_fixture_runner}"\n',
            "must be invoked directly or through one orchestration wrapper",
        ),
    )
    for label, source, needle, expected in specs:
        if needle not in source:
            failures.append("managed selector mutation anchor missing: %s" % label)
            continue
        mutant = source.replace(needle, "", 1)
        mutant_errors = _managed_selector_field_fixture_errors(mutant)
        if not any(expected in error for error in mutant_errors):
            failures.append("managed selector mutation %s was accepted" % label)
        elif verbose:
            print("PASS: rejected managed selector mutation %s" % label)

    semantic_mutants = []

    def add_replacement(label, source, old, new, expected, count=1):
        if source.count(old) < count:
            failures.append("managed selector semantic mutation anchor missing: %s" % label)
            return
        semantic_mutants.append(
            (label, source.replace(old, new, count), expected)
        )

    add_replacement(
        "translated resolver ingress",
        safe,
        'row.get("direction")=="egress"',
        'row.get("direction")=="ingress"',
        "translated local selector resolver",
    )
    add_replacement(
        "translated deny counter ingress",
        safe,
        '"${WORK_DIR}/${label}-before-rules.json" egress dropped_packets',
        '"${WORK_DIR}/${label}-before-rules.json" ingress dropped_packets',
        "rule counters must measure translated egress",
    )
    direct_anchor = "\nrun_deny_evidence\nprepare_owned_selector_fixture\n"
    for operator in ("|| true", "&& true", "; true", "&"):
        add_replacement(
            "direct call operator %s" % operator,
            safe,
            direct_anchor,
            "\nrun_deny_evidence\nprepare_owned_selector_fixture %s\n" % operator,
            "must be invoked directly or through one orchestration wrapper",
        )
    add_replacement(
        "if-false fixture calls",
        safe,
        direct_anchor,
        "\nrun_deny_evidence\nif false; then\n    prepare_owned_selector_fixture\nfi\n",
        "must be invoked directly or through one orchestration wrapper",
    )
    add_replacement(
        "comment-only fixture call",
        safe,
        direct_anchor,
        "\nrun_deny_evidence\n# prepare_owned_selector_fixture\n",
        "must be invoked directly or through one orchestration wrapper",
    )
    add_replacement(
        "alias rebound before call",
        alias_safe,
        'selector_fixture_runner=run_selector_fixture_suite\n"${selector_fixture_runner}"\n',
        'selector_fixture_runner=run_selector_fixture_suite\nselector_fixture_runner=:\n"${selector_fixture_runner}"\n',
        "must be invoked directly or through one orchestration wrapper",
    )
    semantic_mutants.append(
        (
            "duplicate selected helper",
            safe + "\nprepare_owned_selector_fixture() { :; }\n",
            "one reachable definition",
        )
    )
    semantic_mutants.append(
        (
            "duplicate orchestration wrapper",
            wrapper_safe + "\nrun_selector_fixture_suite() { :; }\n",
            "must be invoked directly or through one orchestration wrapper",
        )
    )
    add_replacement(
        "nested unreachable evidence assert",
        safe,
        "assert exact_before_bank==exact_after_bank",
        "if False:\n    assert exact_before_bank==exact_after_bank",
        "reachable top-level assert",
    )
    add_replacement(
        "actual overwritten with expected",
        safe,
        "assert exact_before_bank==exact_after_bank",
        "exact_after_bank=exact_before_bank\nassert exact_before_bank==exact_after_bank",
        "immutable source",
    )
    add_replacement(
        "bpftool command decoy",
        safe,
        "if command bpftool map update pinned",
        "if : bpftool map update pinned",
        "one real bpftool",
    )
    add_replacement(
        "traffic command decoy",
        safe,
        '    command ping "${PING_ARGS[@]}"',
        '    : ping "${PING_ARGS[@]}"',
        "one real ping",
    )
    add_replacement(
        "traffic rc fabricated success",
        safe,
        "        traffic_rc=$?",
        "        traffic_rc=0",
        "traffic_rc must come only",
    )
    add_replacement(
        "legacy bad scalar fabricated",
        safe,
        "bad_ct_count=int(bad_ct_count_raw)",
        "bad_ct_count=int(bad_ct_count_raw)\nbad_ct_count=1",
        "immutable source",
    )
    add_replacement(
        "full resync command decoy",
        safe,
        '    run_full_resync >"${WORK_DIR}/${label}-full-resync.log"',
        '    : run_full_resync >"${WORK_DIR}/${label}-full-resync.log"',
        "run_full_resync decoy",
    )
    add_replacement(
        "cleanup capture command decoy",
        safe,
        "            capture_selector_projection selector-pollution-clean || cleanup_rc=1",
        "            : capture_selector_projection selector-pollution-clean || cleanup_rc=1",
        "real pollution and final capture",
    )
    add_replacement(
        "repair log field hidden",
        safe,
        '"selector_repair_performed=true"',
        '"selector_repair_performed=hidden"',
        "structured profile log field",
    )
    add_replacement(
        "repair count fabricated",
        safe,
        "assert repair_true_count==1",
        "repair_true_count=1\nassert repair_true_count==1",
        "immutable source",
    )
    add_replacement(
        "repair reason assert unreachable",
        safe,
        'assert readiness_reason=="recovery_required"',
        'if False:\n    assert readiness_reason=="recovery_required"',
        "reachable top-level assert",
    )
    add_replacement(
        "IPv4 guard removed",
        safe,
        '    [ "${IP_FAMILY}" = ipv4 ] || return 0\n',
        "",
        "explicit IPv4-only guards",
    )
    add_replacement(
        "exact bank RHS rebound",
        safe,
        'exact_after_bank=bank("exact-local")',
        "exact_after_bank=exact_before_bank",
        "must bind its exact captured RHS",
    )
    add_replacement(
        "legacy CT RHS constant",
        safe,
        "bad_ct_count=int(bad_ct_count_raw)",
        "bad_ct_count=1",
        "must bind its exact captured RHS",
    )
    add_replacement(
        "clean bank IDs constant",
        safe,
        "clean_bank_zero_ids=set(clean_bank_zero_entries.values())",
        "clean_bank_zero_ids=set()",
        "must bind its exact captured RHS",
    )
    add_replacement(
        "repair log counts constant",
        safe,
        'repair_true_count,repair_false_count=repair_counts("legacy-repair")',
        "repair_true_count,repair_false_count=1,0",
        "must bind its exact captured RHS",
    )
    add_replacement(
        "repair reader returns constants",
        safe,
        "    return true_count,false_count",
        "    return 1,0",
        "must not return fabricated constants",
    )
    add_replacement(
        "early successful SystemExit",
        safe,
        "assert exact_before_bank==exact_after_bank",
        "raise SystemExit(0)\nassert exact_before_bank==exact_after_bank",
        "must not exit or raise before required evidence asserts",
    )
    add_replacement(
        "nested reader successful SystemExit",
        safe,
        "    return true_count,false_count",
        "    raise SystemExit(0)\n    return true_count,false_count",
        "must not exit or raise before required evidence asserts",
    )
    semantic_mutants.extend(
        (
            (
                "duplicate helper function keyword",
                safe + "\nfunction prepare_owned_selector_fixture { :; }\n",
                "one reachable definition",
            ),
            (
                "duplicate helper function keyword paren",
                safe + "\nfunction prepare_owned_selector_fixture(){ :; }\n",
                "one reachable definition",
            ),
            (
                "shadow bpftool function",
                safe + "\nbpftool(){ :; }\n",
                "forbids shadowing real commands",
            ),
            (
                "shadow ping function keyword",
                safe + "\nfunction ping { :; }\n",
                "forbids shadowing real commands",
            ),
            (
                "shadow curl function keyword paren",
                safe + "\nfunction curl(){ :; }\n",
                "forbids shadowing real commands",
            ),
            (
                "shadow docker alias",
                safe + "\nalias docker=:\n",
                "forbids shadowing real commands",
            ),
        )
    )
    add_replacement(
        "projection condition removed",
        safe,
        " and readiness_reason==\"recovery_required\" and projection_reason is not None and target_port.get(\"port_id\")==port_id",
        " and readiness_reason==\"recovery_required\" and target_port.get(\"port_id\")==port_id",
        "must bind its exact captured RHS",
    )
    add_replacement(
        "exact local ID cleared before assertion",
        safe,
        '    delete_selector_fixture_group "${EXACT_LOCAL_GROUP_NAME}"\n'
        '    capture_selector_projection exact-cleanup\n'
        '    assert_exact_selector_state\n'
        '    exact_local_group_id=""\n',
        '    delete_selector_fixture_group "${EXACT_LOCAL_GROUP_NAME}"\n'
        '    exact_local_group_id=""\n'
        '    capture_selector_projection exact-cleanup\n'
        '    assert_exact_selector_state\n',
        "exact selector fixture must retain local group ID through cleanup assertion",
    )
    add_replacement(
        "clean restart target repair-required reason allowed",
        safe,
        "assert restart_repair_required_count==0",
        "assert restart_repair_required_count>=0",
        "legacy clean restart must reject target repair-required reason",
    )
    add_replacement(
        "clean restart final state omits active and readiness reason",
        safe,
        'inventory_clean=(item["active"] is True and item["acl_ready"] is True and\n'
        '                 item["readiness_reason"] is None and config["acl"] is True)',
        'inventory_clean=(item["acl_ready"] is True and config["acl"] is True)',
        "legacy clean restart final evidence must require active ready state",
    )
    add_replacement(
        "selector rule receipt written after POST",
        safe,
        '    printf \'%s\\n\' "${selector_rule_body}" >"${selector_rule_receipt}.tmp" || return 1\n'
        '    mv "${selector_rule_receipt}.tmp" "${selector_rule_receipt}" || return 1\n'
        '    created_selector_rule_id="$(curl_body POST aria-acl-rules "${selector_rule_body}" | json_field aria_acl_rule.id)" || return 1\n',
        '    created_selector_rule_id="$(curl_body POST aria-acl-rules "${selector_rule_body}" | json_field aria_acl_rule.id)" || return 1\n'
        '    printf \'%s\\n\' "${selector_rule_body}" >"${selector_rule_receipt}.tmp" || return 1\n'
        '    mv "${selector_rule_receipt}.tmp" "${selector_rule_receipt}" || return 1\n',
        "selector rule create must persist its deterministic attempt before POST",
    )
    add_replacement(
        "selector rule failed output assigned directly to global ID",
        safe,
        '    created_selector_rule_id="$(curl_body POST aria-acl-rules "${selector_rule_body}" | json_field aria_acl_rule.id)" || return 1\n'
        '    [ -n "${created_selector_rule_id}" ] || return 1\n'
        '    selector_rule_id="${created_selector_rule_id}"\n',
        '    selector_rule_id="$(curl_body POST aria-acl-rules "${selector_rule_body}" | json_field aria_acl_rule.id)" || return 1\n'
        '    [ -n "${selector_rule_id}" ] || return 1\n',
        "selector rule create must commit global ID only after successful local parse",
    )
    add_replacement(
        "selector rule unknown-response lookup removed",
        safe,
        '    curl_body GET aria-acl-rules >"${lookup_file}" || return 1\n',
        "",
        "selector rule unknown-response cleanup must query/delete its exact tuple",
    )
    add_replacement(
        "selector rule attempt cleanup invocation removed",
        safe,
        '    if ! cleanup_selector_rule_attempt; then\n'
        '        record_cleanup_error "cleanup-selector-rule-attempt failed"\n'
        '    fi\n',
        "",
        "top-level cleanup must invoke selector rule attempt recovery",
    )
    add_replacement(
        "reattach managed-ports only",
        safe,
        '        if ! command curl --fail-with-body -sS \\\n'
        '            "${DATAPATH_HTTP}/api/v1/instances" >"${instances_payload}"; then\n'
        '            command sleep 1 || return 1\n'
        '            continue\n'
        '        fi\n',
        "",
        "managed port re-attach wait must converge UDS and datapath instance state",
    )
    add_replacement(
        "reattach active-instances proof removed",
        safe,
        'assert len(active_matches)==1,(ifname,active_matches,payload)\n',
        "",
        "managed port re-attach wait must require unique active instance",
    )
    add_replacement(
        "reattach phase readiness proof removed",
        safe,
        'assert expected_phase in ("recovery_required","ready","active"),expected_phase\n'
        'if expected_phase=="recovery_required":\n'
        '    assert item.get("acl_ready") is False,item\n'
        '    assert item.get("readiness_reason")=="recovery_required",item\n'
        'elif expected_phase=="ready":\n'
        '    assert item.get("acl_ready") is True,item\n'
        '    assert item.get("readiness_reason") is None,item\n',
        "",
        "managed port re-attach wait must enforce recovery and ready phases",
    )
    add_replacement(
        "repair reason wrong instance",
        safe,
        'and ("instance="+ifname) in line),None)',
        'and "instance=foreign0" in line),None)',
        "repair-required projection reason must bind target instance",
    )
    add_replacement(
        "repair readiness unrelated reason",
        safe,
        'assert readiness_reason=="recovery_required"',
        'assert readiness_reason=="other_repair_reason"',
        "repair-required readiness reason must be exactly recovery_required",
    )
    add_replacement(
        "repair profile foreign port",
        safe,
        '        and ("ifname="+ifname) in line\n'
        '        and ("port_id="+port_id) in line]',
        '        and "ifname=foreign0" in line\n'
        '        and "port_id=foreign-port" in line]',
        "legacy repair profile counts must bind target ifname and port_id",
    )
    add_replacement(
        "links intact constant",
        safe,
        "links_intact=(tc_ingress_live and tc_egress_live and ifname in link_text)",
        "links_intact=True",
        "must bind its exact captured RHS",
    )
    add_replacement(
        "TC ingress live constant",
        safe,
        'tc_ingress_live=(isinstance(tc_ingress,list) and any(row.get("kind")=="bpf" for row in tc_ingress))',
        "tc_ingress_live=True",
        "must bind its exact captured RHS",
    )
    add_replacement(
        "wrong TC ingress capture filename",
        safe,
        "legacy-repair-required-tc-ingress.json",
        "legacy-repair-required-tc-ingress-link.json",
        "repair-required evidence missing",
    )
    add_replacement(
        "base TC ingress artifact renamed",
        safe,
        "${label}-tc-ingress.json",
        "${label}-tc-ingress-link.json",
        "base capture must persist real link",
    )
    add_replacement(
        "group create-or-extend allowed",
        safe,
        "assert len(matches)==0,matches",
        "assert len(matches)<=1,matches",
        "reject create-or-extend collisions",
    )
    add_replacement(
        "group receipt written after POST",
        safe,
        '    printf \'%s|%s\\n\' "${attempted_name}" "${attempted_cidr}" >"${receipt}.tmp" || return 1\n'
        '    mv "${receipt}.tmp" "${receipt}" || return 1\n'
        "    command curl --fail-with-body -sS -H 'Content-Type: application/json' -X POST \\\n"
        '        -d "{\\"name\\":\\"${attempted_name}\\",\\"cidr\\":\\"${attempted_cidr}\\"}" \\\n'
        '        "${DATAPATH_HTTP}/api/v1/${EXPECTED_IFNAME}/groups" >"${response}" || return 1\n',
        "    command curl --fail-with-body -sS -H 'Content-Type: application/json' -X POST \\\n"
        '        -d "{\\"name\\":\\"${attempted_name}\\",\\"cidr\\":\\"${attempted_cidr}\\"}" \\\n'
        '        "${DATAPATH_HTTP}/api/v1/${EXPECTED_IFNAME}/groups" >"${response}" || return 1\n'
        '    printf \'%s|%s\\n\' "${attempted_name}" "${attempted_cidr}" >"${receipt}.tmp" || return 1\n'
        '    mv "${receipt}.tmp" "${receipt}" || return 1\n',
        "receipt before POST",
    )
    add_replacement(
        "group cleanup receipt bypass",
        safe,
        '    [ -f "${receipt}" ] || return 0\n',
        "",
        "group cleanup must honor its receipt",
    )
    add_replacement(
        "group cleanup numeric ID endpoint",
        safe,
        "/groups/${attempted_name}",
        "/groups/${group_id}",
        "never numeric ID",
    )
    add_replacement(
        "group DELETE failure masked",
        safe,
        '        "${DATAPATH_HTTP}/api/v1/${EXPECTED_IFNAME}/groups/${attempted_name}" || return 1\n'
        '    rm -f "${receipt}" || return 1\n',
        '        "${DATAPATH_HTTP}/api/v1/${EXPECTED_IFNAME}/groups/${attempted_name}" || true\n'
        '    rm -f "${receipt}" || return 1\n',
        "group delete must propagate failure",
    )
    add_replacement(
        "group receipt removal failure masked",
        safe,
        '    rm -f "${receipt}" || return 1\n',
        '    rm -f "${receipt}" || true\n',
        "group delete must propagate failure",
    )
    add_replacement(
        "group collision-resistant guard removed",
        safe,
        '    case "${attempted_name}" in "${RUN_ID}"-*-local) ;; *) return 1 ;; esac\n',
        "",
        "collision-resistant receipt",
    )
    add_replacement(
        "group response parse failure masked",
        safe,
        '    python3 - "${response}" <<\'PY\' || return 1\n',
        '    python3 - "${response}" <<\'PY\' || true\n',
        "group create must propagate failure from real python3",
    )
    add_replacement(
        "semantic DELETE failure masked",
        safe,
        '>"${WORK_DIR}/semantic-delta-delete-response.json" || return 1',
        '>"${WORK_DIR}/semantic-delta-delete-response.json" || true',
        "must propagate failure",
    )
    add_replacement(
        "semantic lookup failure masked",
        safe,
        ')" || return 1\n'
        '    if [ -n "${matched}" ]; then\n'
        '        curl_body DELETE "aria-acl-rules/${matched}" \\\n'
        '            >"${WORK_DIR}/semantic-delta-delete-response.json"',
        ')"\n'
        '    if [ -n "${matched}" ]; then\n'
        '        curl_body DELETE "aria-acl-rules/${matched}" \\\n'
        '            >"${WORK_DIR}/semantic-delta-delete-response.json"',
        "must propagate failure",
    )
    add_replacement(
        "semantic receipt validation bypassed",
        safe,
        '    [ "${receipt_body}" = "${expected_body}" ] || return 1\n'
        '    curl_body GET aria-acl-rules >"${lookup_file}" || return 1\n',
        '    curl_body GET aria-acl-rules >"${lookup_file}" || return 1\n',
        "cleanup must require the attempt",
    )
    add_replacement(
        "fixture cleanup deletes all created rules",
        safe,
        'cleanup_semantic_delta_rule_id="${semantic_delta_rule_id:-}"',
        'cleanup_semantic_delta_rule_id="${created_rule_ids[*]:-}"',
        "must retain the baseline selector rule",
    )
    add_replacement(
        "baseline selector retention assert removed",
        safe,
        "assert selector_rule_id in live_rule_ids\n",
        "",
        "reachable top-level assert",
    )
    add_replacement(
        "semantic delta absence assert removed",
        safe,
        "assert len(semantic_delta_matches)==0\n",
        "",
        "reachable top-level assert",
    )
    add_replacement(
        "selector group global init removed",
        safe,
        'selector_group_id=""\n',
        "",
        "globally initialized before selector fixtures arm",
    )
    add_replacement(
        "active bank selector proof removed",
        safe,
        "assert active_acl_entries[selector_cidr]==selector_group_id\n",
        "",
        "reachable top-level assert",
    )
    add_replacement(
        "active bank selector RHS constant",
        safe,
        "active_acl_entries=(acl_bank_zero_entries if active_bank==0 else acl_bank_one_entries)",
        "active_acl_entries={selector_cidr:selector_group_id}",
        "must bind its exact captured RHS",
    )
    add_replacement(
        "dual bank allowed state fabricated",
        safe,
        "allowed_inactive_selector_values={None,selector_group_id}",
        "allowed_inactive_selector_values={}",
        "must bind its exact captured RHS",
    )
    add_replacement(
        "docker log cursor decoy",
        safe,
        "command docker logs --timestamps --tail 1",
        "date -u",
        "docker logs --timestamps --tail 1",
    )
    add_replacement(
        "docker log since removed",
        safe,
        "command docker logs --timestamps --since",
        "command docker logs --timestamps",
        "docker logs --since",
    )
    add_replacement(
        "wait sleep failure masked",
        safe,
        "command sleep 1 || return 1",
        "command sleep 1 || true",
        "propagate timeout and sleep failure",
    )
    for label, mutant, expected in semantic_mutants:
        mutant_errors = _managed_selector_field_fixture_errors(mutant)
        if not any(expected in error for error in mutant_errors):
            failures.append("managed selector semantic mutation %s was accepted" % label)
        elif verbose:
            print("PASS: rejected managed selector semantic mutation %s" % label)
    return failures


def check_source(source, require_selector_fixture_status=True):
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
    if require_selector_fixture_status:
        errors.extend(_selector_fixture_status_contract_errors(source, bodies))
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

    errors.extend(_managed_selector_field_fixture_errors(source))
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


def run_mutation_self_tests(
    source, verbose=False, require_selector_fixture_status=True
):
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
        mutant_errors = check_source(
            mutant,
            require_selector_fixture_status=require_selector_fixture_status,
        )
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
    self_test = "--self-test" in args
    errors = _parser_self_test_errors()
    errors.extend(
        _run_managed_selector_fixture_mutation_self_tests(
            verbose=self_test
        )
    )
    with open(SMOKE, "r", encoding="utf-8") as handle:
        source = handle.read()
    errors.extend(
        check_source(
            source,
            require_selector_fixture_status=not self_test,
        )
    )
    with open(BACKLOG, "r", encoding="utf-8") as handle:
        backlog = handle.read()
    if "unique tracking-item total remains 69" in backlog:
        errors.append("backlog still says the unique tracking-item total remains 69")
    if "unique tracking-item total is now 73" not in backlog:
        errors.append("backlog must state the corrected unique tracking-item total is 73")
    if "Engineering debt now" not in backlog or "five `DEBT-*` IDs" not in backlog:
        errors.append("backlog must state the corrected engineering-debt total is five")
    if "DEBT-ACL-001" not in backlog:
        errors.append("backlog must retain the legacy local ACL durability debt")
    if "REVIEW-OPS-036" not in backlog:
        errors.append("backlog must retain the independent XDP hook-health defect")
    if not errors:
        errors.extend(
            run_mutation_self_tests(
                source,
                verbose=self_test,
                require_selector_fixture_status=not self_test,
            )
        )
    if errors:
        for error in errors:
            print("ERROR: %s" % error)
        return 1
    print("TC ACL real-tap smoke structure and mutation self-tests: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
