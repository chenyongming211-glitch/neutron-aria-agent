#!/usr/bin/env python3
from __future__ import print_function

import argparse
import json
import os
import re
import shutil
import stat
import subprocess
import sys


ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir))


PYTHON_TEST_ROOT = os.path.join(
    "openstack", "neutron_aria", "neutron_aria", "tests", "unit"
)


RUST_TESTS = [
    ["test", "--locked", "-p", "aria-core", "acl_projection_"],
    ["test", "--locked", "-p", "aria-core", "managed_projection_replay_"],
    ["test", "--locked", "-p", "aria-core", "managed_projection_inventory_"],
    ["test", "--locked", "-p", "aria-agent", "managed_projection_replay_mode_"],
    [
        "test",
        "--locked",
        "-p",
        "aria-agent",
        "managed_projection_inventory_handoff_",
    ],
    ["test", "--locked", "-p", "aria-agent", "managed_projection_health_"],
    ["test", "--locked", "-p", "aria-agent", "managed_acl_shadow_"],
    ["test", "--locked", "-p", "aria-agent", "managed_general_delta_"],
    ["test", "--locked", "-p", "aria-agent", "managed_projection_repair_"],
    ["test", "--locked", "-p", "aria-agent", "managed_local_group_projection_"],
    ["test", "--locked", "-p", "aria-agent", "managed_dual_use_group_"],
    ["test", "--locked", "-p", "aria-agent", "managed_acl_ownership_"],
    ["test", "--locked", "-p", "aria-agent", "managed_projection_attach_repair_"],
    ["test", "--locked", "-p", "aria-agent", "managed_projection_outer_skip_"],
    ["test", "--locked", "-p", "aria-api", "neutron_contract"],
    ["test", "--locked", "-p", "aria-agent", "neutron_wal"],
    ["test", "--locked", "-p", "aria-agent", "neutron_snapshot_plan"],
    ["test", "--locked", "-p", "aria-agent", "neutron_snapshot_transaction"],
    ["test", "--locked", "-p", "aria-agent", "neutron_snapshot_preflight"],
    ["test", "--locked", "-p", "aria-agent", "neutron_snapshot_early_response"],
    ["test", "--locked", "-p", "aria-agent", "neutron_snapshot_port_route"],
    ["test", "--locked", "-p", "aria-agent", "neutron_snapshot"],
    ["test", "--locked", "-p", "aria-agent", "neutron_pending_recovery"],
    ["test", "--locked", "-p", "aria-agent", "domain_authority"],
    ["test", "--locked", "-p", "aria-agent", "peercred_policy"],
    ["test", "--locked", "-p", "aria-agent", "openapi_does_not_expose_neutron_uds_paths"],
]


SMOKE_DIR = os.path.join("deploy", "kolla", "smoke")
STANDALONE_TC_ACL_SMOKE_PATH = os.path.join(
    "deploy", "smoke", "aria_standalone_acl_tc_datapath_smoke.sh"
)
SMOKE_SYNTAX = sorted(
    os.path.join(SMOKE_DIR, name)
    for name in os.listdir(os.path.join(ROOT, SMOKE_DIR))
    if name.endswith(".sh")
) + [STANDALONE_TC_ACL_SMOKE_PATH]

UDS_CONTRACT_PATH = os.path.join("docs", "neutron-uds-contract.json")
STATUS_V1_SCENARIOS_PATH = "docs/neutron-status-contract-v1-scenarios.json"
EXPECTED_STATUS_V1_SCHEMA_VERSION = 1
EXPECTED_STATUS_V1_CONTRACT_HASH = "v0.9-neutron-status-1"
EXPECTED_STATUS_V1_VOCABULARY = (
    (
        "transaction_states",
        ("idle", "pending", "classified", "blocked", "recovery"),
    ),
    (
        "overall_readiness",
        ("ready", "degraded", "blocked", "unknown"),
    ),
    (
        "required_actions",
        ("none", "poll", "recover_pending", "full_resync", "operator"),
    ),
    ("recovery_causes", (None, "inventory_unavailable")),
    (
        "domain_statuses",
        ("ready", "not_requested", "degraded", "blocked"),
    ),
    (
        "effective_actions",
        ("enforce", "bypass", "unchanged", "cleanup", "no_op"),
    ),
    (
        "support_dispositions",
        ("supported", "unsupported", "unknown", "not_applicable"),
    ),
)
EXPECTED_STATUS_V1_TRIPLES = frozenset((
    ("idle", "unknown", "full_resync"),
    ("pending", "unknown", "poll"),
    ("classified", "ready", "none"),
    ("classified", "degraded", "none"),
    ("classified", "degraded", "full_resync"),
    ("blocked", "blocked", "recover_pending"),
    ("blocked", "blocked", "operator"),
    ("recovery", "degraded", "full_resync"),
))
EXPECTED_STATUS_V1_SCENARIO_IDS = (
    "full-classified-ready",
    "scoped-classified-ready",
    "classified-degraded-terminal",
    "classified-degraded-full-resync",
    "pending-poll",
    "blocked-recoverable-inventory",
    "blocked-operator",
    "recovery-full-resync",
    "generation-zero-inventory-recovery",
    "legacy-v0-ready",
    "legacy-v0-unknown-authority",
    "unknown-v1-contract",
    "ready-invalid-evidence",
    "restart-classified-routing",
)
EXPECTED_STATUS_V1_NULL_PROJECTION_IDS = frozenset((
    "legacy-v0-unknown-authority",
    "unknown-v1-contract",
    "ready-invalid-evidence",
))
EXPECTED_STATUS_V1_INVENTORY_RECOVERY_IDS = frozenset((
    "blocked-recoverable-inventory",
    "generation-zero-inventory-recovery",
))
EXPECTED_RUST_STATUS_V1_PRODUCER_IDS = (
    "full-classified-ready",
    "scoped-classified-ready",
    "classified-degraded-terminal",
    "classified-degraded-full-resync",
    "pending-poll",
    "blocked-recoverable-inventory",
    "blocked-operator",
    "recovery-full-resync",
    "generation-zero-inventory-recovery",
    "restart-classified-routing",
)
EXPECTED_STATUS_CAPABILITY_FIELDS = (
    "status_schema_version_min",
    "status_schema_version_max",
    "status_contract_hash",
)
EXPECTED_STATUS_RESPONSE_FIELDS = (
    "status_schema_version",
    "status_contract_hash",
)
STATUS_V1_RUST_ENUMS = (
    ("transaction_states", "NeutronStatusTransactionState"),
    ("overall_readiness", "NeutronStatusOverallReadiness"),
    ("required_actions", "NeutronStatusRequiredAction"),
    ("recovery_causes", "NeutronStatusRecoveryCause"),
    ("domain_statuses", "NeutronStatusDomainState"),
    ("effective_actions", "NeutronStatusEffectiveAction"),
    ("support_dispositions", "NeutronStatusSupportDisposition"),
)
P3_RUST_SCOPED_PLAN_PATH = os.path.join(
    "docs", "openstack-neutron-aria-details", "10-rust-scoped-apply.md"
)
RUST_API_PATH = os.path.join("api", "src", "lib.rs")
RUST_NEUTRON_API_PATH = os.path.join("agent", "src", "neutron_api.rs")
RUST_NEUTRON_WAL_PATH = os.path.join("agent", "src", "neutron_wal.rs")
RUST_OPENAPI_PATH = os.path.join("agent", "src", "openapi.rs")
CORE_COMMON_PATH = os.path.join("core", "src", "common.rs")
CORE_STATE_PATH = os.path.join("core", "src", "state.rs")
CORE_EBPF_OPS_PATH = os.path.join("core", "src", "ebpf_ops.rs")
CORE_EBPF_RUNTIME_PATH = os.path.join("core", "src", "ebpf_ops", "runtime.rs")
EBPF_ABI_PATH = os.path.join("abi", "src", "lib.rs")
EBPF_COMMON_PATH = os.path.join("ebpf", "src", "common.rs")
EBPF_CONNTRACK_PATH = os.path.join("ebpf", "src", "conntrack.rs")
EBPF_RUNTIME_PATH = os.path.join("ebpf", "src", "runtime.rs")
CORE_EBPF_NETWORK_PATH = os.path.join("core", "src", "ebpf_ops", "network.rs")
CORE_EBPF_POLICY_PATH = os.path.join("core", "src", "ebpf_ops", "policy.rs")
BUILD_WORKFLOW_PATH = os.path.join(".github", "workflows", "build.yml")
KOLLA_AGENT_INI_PATH = os.path.join("deploy", "kolla", "config", "neutron-aria-agent.ini")
KOLLA_DATAPATH_CONFIG_PATH = os.path.join(
    "deploy", "kolla", "config", "aria-agent-openstack.toml"
)
TC_ACL_DATAPATH_SMOKE_PATH = os.path.join(
    "deploy", "kolla", "smoke", "neutron_aria_acl_tc_datapath_smoke.sh"
)
PYTHON_UDS_CLIENT_PATH = os.path.join(
    "openstack", "neutron_aria", "neutron_aria", "agent", "uds_client.py"
)
PYTHON_UDS_CLIENT_TEST_PATH = os.path.join(
    "openstack", "neutron_aria", "neutron_aria", "tests", "unit", "test_uds_client.py"
)
DOC_INI_CONTRACT_PATHS = [
    "README.md",
    os.path.join("docs", "openstack-neutron-agent-mode.md"),
    os.path.join("docs", "aria-acl-neutron-extension-product-design.md"),
    os.path.join("docs", "openstack-neutron-aria-design-decisions.md"),
    os.path.join("docs", "openstack-deployment-runbook.md"),
    os.path.join("docs", "neutron-managed-domains-contract.md"),
    os.path.join("docs", "openstack-neutron-aria-details", "README.md"),
    os.path.join("docs", "openstack-neutron-aria-details", "01-ini-contract.md"),
]


def _read_repo_text(path):
    with open(os.path.join(ROOT, path), "r", encoding="utf-8") as handle:
        return handle.read()


def _blank_rust_non_code(text):
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


ABI_DECLARATIONS = (
    (
        "ACL_INGRESS_HOOK_XDP",
        re.compile(
            r"\bpub\s+const\s+ACL_INGRESS_HOOK_XDP\s*:\s*u8\s*=\s*0\s*;"
        ),
    ),
    (
        "ACL_INGRESS_HOOK_TC",
        re.compile(
            r"\bpub\s+const\s+ACL_INGRESS_HOOK_TC\s*:\s*u8\s*=\s*1\s*;"
        ),
    ),
    (
        "acl_ingress_hook field",
        re.compile(r"\bpub\s+acl_ingress_hook\s*:\s*u8\s*,"),
    ),
)


def _has_acl_ingress_hook_definition(source):
    return bool(
        re.search(r"\bfn\s+acl_ingress_hook\s*\(", _blank_rust_non_code(source))
    )


def _missing_acl_ingress_abi(source):
    code = _blank_rust_non_code(source)
    return [label for label, pattern in ABI_DECLARATIONS if not pattern.search(code)]


def _rust_function_body(source, function_name):
    """Extract a Rust function body after blanking comments and literals."""
    code = _blank_rust_non_code(source)
    match = re.search(
        r"\b(?:pub(?:\s*\([^)]*\))?\s+)?(?:async\s+)?fn\s+%s(?:\s*<[^>{}]*>)?\s*\("
        % re.escape(function_name),
        code,
    )
    if not match:
        return None
    opening = code.find("{", match.end())
    if opening < 0:
        return None
    depth = 1
    index = opening + 1
    while index < len(code) and depth:
        if code[index] == "{":
            depth += 1
        elif code[index] == "}":
            depth -= 1
        index += 1
    if depth:
        return None
    return code[opening + 1:index - 1]


def _rust_braced_body_at(code, opening):
    """Extract a braced Rust block from already blanked source code."""
    if opening < 0 or opening >= len(code) or code[opening] != "{":
        return None
    depth = 1
    index = opening + 1
    while index < len(code) and depth:
        if code[index] == "{":
            depth += 1
        elif code[index] == "}":
            depth -= 1
        index += 1
    if depth:
        return None
    return code[opening + 1:index - 1]


def _rust_item_body(source, item_kind, item_name):
    """Extract a Rust struct or enum body after blanking comments and literals."""
    code = _blank_rust_non_code(source)
    match = re.search(
        r"\b(?:pub(?:\s*\([^)]*\))?\s+)?%s\s+%s\b"
        % (re.escape(item_kind), re.escape(item_name)),
        code,
    )
    if not match:
        return None
    opening = code.find("{", match.end())
    if opening < 0:
        return None
    depth = 1
    index = opening + 1
    while index < len(code) and depth:
        if code[index] == "{":
            depth += 1
        elif code[index] == "}":
            depth -= 1
        index += 1
    if depth:
        return None
    return code[opening + 1:index - 1]


def _run_rust_function_body_parser_self_tests():
    formatted = """
        // async fn serialized_writer() { fake(); }
        pub(crate)
        async fn serialized_writer (
            enabled: bool,
        ) -> Result<(), String> {
            if enabled {
                nested_call();
            }
            let ignored = "}";
            Ok(())
        }
    """
    body = _rust_function_body(formatted, "serialized_writer")
    if body is None or "nested_call" not in body or "fake" in body:
        raise SystemExit("ERROR: Rust function parser rejected harmless formatting")
    if _rust_function_body("// fn missing() {}", "missing") is not None:
        raise SystemExit("ERROR: Rust function parser accepted a comment-only function")
    generic = "fn execute<T>(value: T) where T: Copy { nested_call(); }"
    generic_body = _rust_function_body(generic, "execute")
    if generic_body is None or "nested_call" not in generic_body:
        raise SystemExit("ERROR: Rust function parser rejected a generic function")


def _rust_function_body_raw(source, function_name):
    """Extract a Rust function body while retaining literals for sentinel checks."""
    code = _blank_rust_non_code(source)
    match = re.search(
        r"\b(?:pub(?:\s*\([^)]*\))?\s+)?(?:async\s+)?fn\s+%s(?:\s*<[^>{}]*>)?\s*\("
        % re.escape(function_name),
        code,
    )
    if not match:
        return None
    parameter_depth = 1
    header_index = match.end()
    while header_index < len(code) and parameter_depth:
        if code[header_index] == "(":
            parameter_depth += 1
        elif code[header_index] == ")":
            parameter_depth -= 1
        header_index += 1
    if parameter_depth:
        return None
    opening = code.find("{", header_index)
    if opening < 0:
        return None
    declaration_tail = code[header_index:opening]
    if ";" in declaration_tail or "}" in declaration_tail:
        return None
    depth = 1
    index = opening + 1
    while index < len(code) and depth:
        if code[index] == "{":
            depth += 1
        elif code[index] == "}":
            depth -= 1
        index += 1
    if depth:
        return None
    return source[opening + 1:index - 1]


def _rust_snake_case_unit_enum_values(source, enum_name):
    """Return proven snake-case wire values for a simple public unit enum."""
    code = _blank_rust_non_code(source)
    declarations = list(re.finditer(
        r"\bpub\s+enum\s+%s\b" % re.escape(enum_name), code
    ))
    if len(declarations) != 1:
        raise ValueError(
            "expected exactly one public Rust enum %s, found %s"
            % (enum_name, len(declarations))
        )

    declaration = declarations[0]
    opening = code.find("{", declaration.end())
    if opening < 0 or code[declaration.end():opening].strip():
        raise ValueError("Rust enum %s has an unsupported declaration" % enum_name)

    depth = 1
    index = opening + 1
    while index < len(code) and depth:
        if code[index] == "{":
            depth += 1
        elif code[index] == "}":
            depth -= 1
        index += 1
    if depth:
        raise ValueError("Rust enum %s has an unbalanced body" % enum_name)
    closing = index - 1

    attribute_region = re.search(
        r"(?P<attributes>(?:#\s*\[[^\[\]]*\]\s*)+)$",
        code[:declaration.start()],
        re.DOTALL,
    )
    if not attribute_region:
        raise ValueError("Rust enum %s has no contiguous outer attributes" % enum_name)
    attribute_start = attribute_region.start("attributes")
    attributes_code = attribute_region.group("attributes")
    serde_attribute_count = 0
    serde_attributes = 0
    for attribute in re.finditer(r"#\s*\[[^\[\]]*\]\s*", attributes_code, re.DOTALL):
        absolute_start = attribute_start + attribute.start()
        absolute_end = attribute_start + attribute.end()
        raw_attribute = source[absolute_start:absolute_end]
        if re.match(r"#\s*\[\s*serde\b", attribute.group(0)):
            serde_attribute_count += 1
        if re.fullmatch(
            r'#\s*\[\s*serde\s*\(\s*rename_all\s*=\s*"snake_case"\s*\)\s*\]\s*',
            raw_attribute,
            re.DOTALL,
        ):
            serde_attributes += 1
    if serde_attribute_count != 1 or serde_attributes != 1:
        raise ValueError(
            "Rust enum %s must have exactly one snake_case serde attribute"
            % enum_name
        )

    body = code[opening + 1:closing]
    entries = body.split(",")
    if entries and not entries[-1].strip():
        entries.pop()
    if not entries or any(not entry.strip() for entry in entries):
        raise ValueError("Rust enum %s has an empty or malformed variant" % enum_name)

    values = []
    for entry in entries:
        variant = entry.strip()
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", variant):
            raise ValueError(
                "Rust enum %s has a non-unit or unsupported variant %r"
                % (enum_name, variant)
            )
        value = "".join(
            ("_" if index and char.isupper() else "") + char.lower()
            for index, char in enumerate(variant)
        )
        values.append(value)
    if len(set(values)) != len(values):
        raise ValueError("Rust enum %s has duplicate wire values" % enum_name)
    return tuple(values)


def _rust_ordinary_string_literals(text):
    """Blank comments and return ordinary, unescaped Rust string literals."""
    output = []
    values = []
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
            if depth:
                raise ValueError("unterminated Rust block comment")
            output.extend("\n" if char == "\n" else " " for char in text[index:end])
            index = end
            continue
        if text[index] == '"':
            end = index + 1
            while end < len(text) and text[end] != '"':
                if text[end] == "\\" or text[end] == "\n":
                    raise ValueError("unsupported Rust string literal escape or newline")
                end += 1
            if end >= len(text):
                raise ValueError("unterminated Rust string literal")
            values.append(text[index + 1:end])
            output.append("__RUST_STRING__")
            index = end + 1
            continue
        output.append(text[index])
        index += 1
    return "".join(output), tuple(values)


def _rust_returned_string_slice(source, function_name):
    code = _blank_rust_non_code(source)
    declarations = re.findall(
        r"\b(?:pub(?:\s*\([^)]*\))?\s+)?(?:async\s+)?fn\s+%s\b"
        % re.escape(function_name),
        code,
    )
    if len(declarations) != 1:
        raise ValueError(
            "expected exactly one Rust function %s, found %s"
            % (function_name, len(declarations))
        )
    body = _rust_function_body_raw(source, function_name)
    if body is None:
        raise ValueError("Rust function %s was not found" % function_name)
    code, values = _rust_ordinary_string_literals(body)
    if not re.fullmatch(
        r"\s*&\s*\[\s*__RUST_STRING__"
        r"(?:\s*,\s*__RUST_STRING__)*\s*,?\s*\]\s*",
        code,
        re.DOTALL,
    ):
        raise ValueError(
            "Rust function %s must return one ordinary string slice literal"
            % function_name
        )
    if len(set(values)) != len(values):
        raise ValueError("Rust function %s returns duplicate strings" % function_name)
    return values


def _expect_status_parser_rejection(callback, description):
    try:
        callback()
    except ValueError:
        return
    raise SystemExit("ERROR: Status V1 parser accepted %s" % description)


def _run_status_v1_rust_parser_self_tests():
    formatted_enum = """
        // #[serde(rename_all = "snake_case")] pub enum Example { Fake }
        #[derive(Clone, Copy)]
        /* a harmless formatting comment */
        #[serde(rename_all = "snake_case")]
        pub enum Example {
            Ready,
            FullResync,
            NoOp,
        }
    """
    if _rust_snake_case_unit_enum_values(formatted_enum, "Example") != (
        "ready", "full_resync", "no_op",
    ):
        raise SystemExit("ERROR: Status V1 enum parser rejected harmless formatting")
    consecutive_capitals = _rust_snake_case_unit_enum_values(
        formatted_enum.replace("Ready,", "NOOp,", 1).replace(
            "NoOp,", "Other,", 1
        ),
        "Example",
    )
    if consecutive_capitals[0] != "n_o_op":
        raise SystemExit(
            "ERROR: Status V1 enum parser expected Serde wire value 'n_o_op', got %r"
            % consecutive_capitals[0]
        )
    _expect_status_parser_rejection(
        lambda: _rust_snake_case_unit_enum_values(
            "// #[serde(rename_all = \"snake_case\")] pub enum Example { Ready }",
            "Example",
        ),
        "a comment-only Rust enum",
    )
    _expect_status_parser_rejection(
        lambda: _rust_snake_case_unit_enum_values(
            formatted_enum.replace(
                '#[serde(rename_all = "snake_case")]\n        pub enum',
                '#[serde(rename_all = "camelCase")]\n        pub enum',
                1,
            ),
            "Example",
        ),
        "a changed serde rename_all mode",
    )
    _expect_status_parser_rejection(
        lambda: _rust_snake_case_unit_enum_values(
            formatted_enum.replace(
                '        #[serde(rename_all = "snake_case")]\n', "", 1
            ),
            "Example",
        ),
        "a missing serde rename_all attribute",
    )
    _expect_status_parser_rejection(
        lambda: _rust_snake_case_unit_enum_values(
            formatted_enum.replace("Ready,", "Ready(u8),", 1), "Example"
        ),
        "a tuple enum variant",
    )
    _expect_status_parser_rejection(
        lambda: _rust_snake_case_unit_enum_values(
            formatted_enum.replace("Ready,", '#[serde(rename = "ready_now")] Ready,', 1),
            "Example",
        ),
        "a per-variant serde rename",
    )

    formatted_slice = """
        fn rust_status_v1_scenario_ids() -> &'static [&'static str] {
            &[
                "full-classified-ready",
                // "comment-only-fake",
                /* "block-comment-fake", */
                "pending-poll",
            ]
        }
    """
    if _rust_returned_string_slice(
        formatted_slice, "rust_status_v1_scenario_ids"
    ) != ("full-classified-ready", "pending-poll"):
        raise SystemExit("ERROR: Status V1 string inventory parser rejected comments")
    array_parameter_slice = """
        fn rust_status_v1_scenario_ids(
            _marker: [u8; 4],
        ) -> &'static [&'static str] {
            &["full-classified-ready"]
        }
    """
    try:
        array_parameter_values = _rust_returned_string_slice(
            array_parameter_slice, "rust_status_v1_scenario_ids"
        )
    except ValueError:
        array_parameter_values = None
    if array_parameter_values != ("full-classified-ready",):
        raise SystemExit(
            "ERROR: Status V1 string inventory parser rejected array parameter syntax"
        )
    _expect_status_parser_rejection(
        lambda: _rust_returned_string_slice(
            "// fn rust_status_v1_scenario_ids() { &[\"fake\"] }",
            "rust_status_v1_scenario_ids",
        ),
        "a comment-only Rust producer inventory",
    )
    bodyless_inventory = """
        trait FakeInventory {
            fn rust_status_v1_scenario_ids() -> &'static [&'static str];
        }
        const UNRELATED: () = {
            &[
                "full-classified-ready",
                "scoped-classified-ready",
            ]
        };
    """
    _expect_status_parser_rejection(
        lambda: _rust_returned_string_slice(
            bodyless_inventory,
            "rust_status_v1_scenario_ids",
        ),
        "a bodyless Rust producer declaration followed by an unrelated block",
    )
    _expect_status_parser_rejection(
        lambda: _rust_returned_string_slice(
            formatted_slice.replace(
                '&[\n                "full-classified-ready",',
                'let ids = &["computed"];\n            &[\n                "full-classified-ready",',
                1,
            ),
            "rust_status_v1_scenario_ids",
        ),
        "a computed Rust producer inventory",
    )
    _expect_status_parser_rejection(
        lambda: _rust_ordinary_string_literals('/* unterminated'),
        "an unterminated Rust block comment",
    )
    print("Status V1 Rust parser mutation self-tests: OK (13 scenarios)")


def _status_v1_exact_integer_matches(value, expected):
    return type(value) is int and value == expected


def _run_status_v1_exact_integer_mutation_self_tests():
    if not _status_v1_exact_integer_matches(1, 1):
        raise SystemExit("ERROR: Status V1 checker rejected an exact integer")
    for label, value in (("boolean", True), ("float", 1.0)):
        if _status_v1_exact_integer_matches(value, 1):
            raise SystemExit(
                "ERROR: Status V1 checker accepted a %s as an exact integer"
                % label
            )
    print("Status V1 exact-integer mutation self-tests: OK (3 scenarios)")


def _status_v1_validated_fixture_path(
    declared_path,
    root=ROOT,
    realpath=os.path.realpath,
    isfile=os.path.isfile,
):
    if type(declared_path) is not str:
        return None, ["Status V1 scenario artifact path must be an exact string"]
    if declared_path != STATUS_V1_SCENARIOS_PATH:
        return None, [
            "Status V1 scenario artifact path expected %r, got %r"
            % (STATUS_V1_SCENARIOS_PATH, declared_path)
        ]

    root_realpath = realpath(root)
    declared_realpath = realpath(
        os.path.join(root, *declared_path.split("/"))
    )
    try:
        contained = os.path.commonpath(
            (root_realpath, declared_realpath)
        ) == root_realpath
    except ValueError:
        contained = False
    if not contained:
        return None, [
            "Status V1 scenario artifact must stay inside the repository"
        ]
    if not isfile(declared_realpath):
        return None, ["Status V1 scenario artifact does not exist as a regular file"]
    return declared_realpath, []


def _run_status_v1_fixture_path_mutation_self_tests():
    canonicalization_calls = []

    def forbidden_realpath(path):
        canonicalization_calls.append(path)
        raise AssertionError("wrong fixture paths must not be canonicalized")

    for declared_path in (True, "docs/not-the-status-fixture.json"):
        path, errors = _status_v1_validated_fixture_path(
            declared_path,
            root="/repo",
            realpath=forbidden_realpath,
            isfile=lambda unused: True,
        )
        if path is not None or not errors or canonicalization_calls:
            raise SystemExit(
                "ERROR: Status V1 checker canonicalized a wrong fixture path"
            )

    approved_joined_path = os.path.join(
        "/repo", *STATUS_V1_SCENARIOS_PATH.split("/")
    )

    def outside_realpath(path):
        if path == "/repo":
            return "/repo"
        if path == approved_joined_path:
            return "/outside/status-fixture.json"
        raise AssertionError("unexpected canonicalization path %r" % path)

    path, errors = _status_v1_validated_fixture_path(
        STATUS_V1_SCENARIOS_PATH,
        root="/repo",
        realpath=outside_realpath,
        isfile=lambda unused: True,
    )
    if path is not None or not errors:
        raise SystemExit(
            "ERROR: Status V1 checker accepted an outside-repository fixture"
        )

    path, errors = _status_v1_validated_fixture_path(
        STATUS_V1_SCENARIOS_PATH,
        root="/repo",
        realpath=lambda value: value,
        isfile=lambda unused: False,
    )
    if path is not None or not errors:
        raise SystemExit("ERROR: Status V1 checker accepted a missing fixture")

    path, errors = _status_v1_validated_fixture_path(
        STATUS_V1_SCENARIOS_PATH,
        root="/repo",
        realpath=lambda value: value,
        isfile=lambda unused: True,
    )
    if path != approved_joined_path or errors:
        raise SystemExit("ERROR: Status V1 checker rejected the approved fixture path")

    open_calls = []
    close_calls = []
    fstat_calls = []
    fdopen_calls = []
    nofollow_flag = 0x100000
    directory_flag = 0x200000

    def recording_open(path, flags, dir_fd=None):
        descriptor = 100 + len(open_calls)
        open_calls.append((path, flags, dir_fd, descriptor))
        return descriptor

    class FakeOpenedFile(object):
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc_value, traceback):
            return False

    def recording_fdopen(descriptor, mode, encoding=None):
        fdopen_calls.append((descriptor, mode, encoding))
        return FakeOpenedFile()

    class RegularFileStat(object):
        st_mode = stat.S_IFREG | 0o600

    def recording_fstat(descriptor):
        fstat_calls.append(descriptor)
        return RegularFileStat()

    with _status_v1_open_repo_relative(
        STATUS_V1_SCENARIOS_PATH,
        "r",
        encoding="utf-8",
        root="/repo",
        open_fn=recording_open,
        fdopen_fn=recording_fdopen,
        close_fn=close_calls.append,
        fstat_fn=recording_fstat,
        supports_dir_fd=True,
        nofollow_flag=nofollow_flag,
        directory_flag=directory_flag,
    ):
        pass
    expected_components = (
        ("/repo", None),
        ("docs", 100),
        ("neutron-status-contract-v1-scenarios.json", 101),
    )
    actual_components = tuple(
        (path, dir_fd) for path, unused_flags, dir_fd, unused_fd in open_calls
    )
    flags_are_safe = (
        len(open_calls) == 3
        and all(flags & nofollow_flag for unused, flags, unused_dir, unused_fd in open_calls)
        and all(open_calls[index][1] & directory_flag for index in (0, 1))
        and not open_calls[2][1] & directory_flag
    )
    if (
        actual_components != expected_components
        or not flags_are_safe
        or fstat_calls != [102]
        or fdopen_calls != [(102, "r", "utf-8")]
        or close_calls != [101, 100]
    ):
        raise SystemExit(
            "ERROR: Status V1 repository opener did not use anchored no-follow traversal"
        )

    try:
        _status_v1_open_repo_relative(
            STATUS_V1_SCENARIOS_PATH,
            "r",
            encoding="utf-8",
            root="/repo",
            open_fn=recording_open,
            fdopen_fn=recording_fdopen,
            close_fn=close_calls.append,
            fstat_fn=recording_fstat,
            supports_dir_fd=True,
            nofollow_flag=None,
            directory_flag=directory_flag,
        )
    except OSError:
        pass
    else:
        raise SystemExit(
            "ERROR: Status V1 repository opener accepted missing no-follow support"
        )

    class DirectoryStat(object):
        st_mode = stat.S_IFDIR | 0o700

    try:
        _status_v1_open_repo_relative(
            STATUS_V1_SCENARIOS_PATH,
            "r",
            encoding="utf-8",
            root="/repo",
            open_fn=lambda path, flags, dir_fd=None: 200,
            fdopen_fn=lambda descriptor, mode, encoding=None: FakeOpenedFile(),
            close_fn=lambda descriptor: None,
            fstat_fn=lambda descriptor: DirectoryStat(),
            supports_dir_fd=True,
            nofollow_flag=nofollow_flag,
            directory_flag=directory_flag,
        )
    except OSError:
        pass
    else:
        raise SystemExit(
            "ERROR: Status V1 repository opener accepted a non-regular descriptor"
        )
    print("Status V1 fixture-path mutation self-tests: OK (8 scenarios)")


def _status_v1_open_repo_relative(
    relative_path,
    mode,
    encoding=None,
    root=ROOT,
    open_fn=os.open,
    fdopen_fn=os.fdopen,
    close_fn=os.close,
    fstat_fn=os.fstat,
    supports_dir_fd=None,
    nofollow_flag=getattr(os, "O_NOFOLLOW", None),
    directory_flag=getattr(os, "O_DIRECTORY", None),
):
    if supports_dir_fd is None:
        supports_dir_fd = os.open in getattr(os, "supports_dir_fd", ())
    if (
        nofollow_flag is None
        or directory_flag is None
        or not supports_dir_fd
    ):
        raise OSError(
            "repository-relative no-follow file access is unavailable"
        )
    if type(relative_path) is not str:
        raise OSError("repository-relative path must be an exact string")
    components = relative_path.split("/")
    if not components or any(
        component in ("", ".", "..") for component in components
    ):
        raise OSError("repository-relative path contains an unsafe component")

    close_on_exec = getattr(os, "O_CLOEXEC", 0)
    read_flags = os.O_RDONLY | close_on_exec | nofollow_flag
    directory_flags = read_flags | directory_flag
    directory_descriptors = []
    file_descriptor = None
    try:
        current_descriptor = open_fn(root, directory_flags)
        directory_descriptors.append(current_descriptor)
        for component in components[:-1]:
            current_descriptor = open_fn(
                component,
                directory_flags,
                dir_fd=current_descriptor,
            )
            directory_descriptors.append(current_descriptor)
        file_descriptor = open_fn(
            components[-1],
            read_flags,
            dir_fd=current_descriptor,
        )
        if not stat.S_ISREG(fstat_fn(file_descriptor).st_mode):
            raise OSError("repository-relative descriptor is not a regular file")
        handle = fdopen_fn(file_descriptor, mode, encoding=encoding)
        file_descriptor = None
        return handle
    finally:
        if file_descriptor is not None:
            close_fn(file_descriptor)
        for descriptor in reversed(directory_descriptors):
            close_fn(descriptor)


class _StatusV1DuplicateJsonKey(ValueError):
    pass


def _status_v1_json_object_without_duplicate_keys(pairs):
    value = {}
    for key, member in pairs:
        if key in value:
            raise _StatusV1DuplicateJsonKey(
                "duplicate JSON object key %r" % key
            )
        value[key] = member
    return value


def _status_v1_load_json_object(path, label, opener=open, loader=None):
    try:
        with opener(path, "r", encoding="utf-8") as handle:
            if loader is None:
                value = json.load(
                    handle,
                    object_pairs_hook=_status_v1_json_object_without_duplicate_keys,
                )
            else:
                value = loader(handle)
    except (
        OSError,
        UnicodeError,
        json.JSONDecodeError,
        _StatusV1DuplicateJsonKey,
    ) as error:
        return {}, [
            "%s could not be loaded (%s): %s"
            % (label, type(error).__name__, error)
        ]
    if not isinstance(value, dict):
        return {}, ["%s root must be an object" % label]
    return value, []


def _run_status_v1_json_loading_mutation_self_tests():
    class FakeHandle(object):
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc_value, traceback):
            return False

    def fake_open(unused_path, unused_mode, encoding=None):
        return FakeHandle()

    class RawJsonHandle(FakeHandle):
        def read(self):
            return '{"status_contract":{"hash":"first","hash":"second"}}'

    def duplicate_json_open(unused_path, unused_mode, encoding=None):
        return RawJsonHandle()

    failures = (
        (
            "missing file",
            lambda unused_path, unused_mode, encoding=None: (_ for _ in ()).throw(
                FileNotFoundError("missing fixture")
            ),
            lambda unused_handle: {},
        ),
        (
            "invalid JSON",
            fake_open,
            lambda unused_handle: (_ for _ in ()).throw(
                json.JSONDecodeError("invalid JSON", "{", 1)
            ),
        ),
        (
            "invalid Unicode",
            fake_open,
            lambda unused_handle: (_ for _ in ()).throw(
                UnicodeDecodeError("utf-8", b"\xff", 0, 1, "invalid start byte")
            ),
        ),
    )
    for description, opener, loader in failures:
        value, errors = _status_v1_load_json_object(
            "/unused/status.json",
            "Status V1 mutation",
            opener=opener,
            loader=loader,
        )
        if value or not errors:
            raise SystemExit(
                "ERROR: Status V1 loader accepted %s" % description
            )

    value, errors = _status_v1_load_json_object(
        "/unused/status.json",
        "Status V1 mutation",
        opener=fake_open,
        loader=lambda unused_handle: [],
    )
    if value or not errors:
        raise SystemExit("ERROR: Status V1 loader accepted a non-object root")

    value, errors = _status_v1_load_json_object(
        "/unused/status.json",
        "Status V1 mutation",
        opener=duplicate_json_open,
    )
    if value or not errors:
        raise SystemExit("ERROR: Status V1 loader accepted a duplicate object key")

    expected = {"valid": True}
    value, errors = _status_v1_load_json_object(
        "/unused/status.json",
        "Status V1 mutation",
        opener=fake_open,
        loader=lambda unused_handle: expected,
    )
    if value != expected or errors:
        raise SystemExit("ERROR: Status V1 loader rejected an object root")
    print("Status V1 JSON-loading mutation self-tests: OK (6 scenarios)")


def _status_v1_has_duplicates(values):
    for index, value in enumerate(values):
        for previous in values[:index]:
            if value == previous:
                return True
    return False


def _status_v1_python_triples_contract_errors(
    python_triples,
    vocabulary,
    frozenset_factory=frozenset,
):
    if not isinstance(python_triples, (tuple, list, set, frozenset)):
        return ["Python Status V1 triples must be a collection"]

    triples = tuple(python_triples)
    malformed_triples = [
        triple
        for triple in triples
        if not (
            isinstance(triple, tuple)
            and len(triple) == 3
            and all(type(value) is str for value in triple)
        )
    ]
    if malformed_triples:
        return [
            "Python Status V1 contains malformed triples %r"
            % malformed_triples
        ]

    errors = []
    actual_triples = frozenset_factory(triples)
    if actual_triples != EXPECTED_STATUS_V1_TRIPLES:
        errors.append(
            "Python Status V1 triples expected %r, got %r"
            % (EXPECTED_STATUS_V1_TRIPLES, actual_triples)
        )
    for index, name in enumerate(
        ("transaction_states", "overall_readiness", "required_actions")
    ):
        actual = frozenset_factory(triple[index] for triple in triples)
        expected = frozenset(vocabulary[name])
        if actual != expected:
            errors.append(
                "Python Status V1 %s column expected %r, got %r"
                % (name, expected, actual)
            )
    return errors


def _status_v1_python_vocabulary_contract_errors(
    name,
    actual,
    expected_values,
    frozenset_factory=frozenset,
):
    if not isinstance(actual, (tuple, list, set, frozenset)):
        return ["Python Status V1 %s must be a collection" % name]

    values = tuple(actual)
    allow_none = None in expected_values
    malformed = [
        value
        for value in values
        if not (
            type(value) is str
            or (allow_none and value is None)
        )
    ]
    if malformed:
        return [
            "Python Status V1 %s contains malformed values %r"
            % (name, malformed)
        ]

    expected = frozenset(expected_values)
    actual_values = frozenset_factory(values)
    if actual_values != expected:
        return [
            "Python Status V1 %s expected %r, got %r"
            % (name, expected, actual_values)
        ]
    return []


def _status_v1_python_metadata_contract_errors(uds_client, vocabulary):
    errors = []
    schema_version = getattr(uds_client, "NEUTRON_STATUS_SCHEMA_VERSION", None)
    if not _status_v1_exact_integer_matches(
        schema_version,
        EXPECTED_STATUS_V1_SCHEMA_VERSION,
    ):
        errors.append(
            "Python Status V1 schema expected %r, got %r"
            % (
                EXPECTED_STATUS_V1_SCHEMA_VERSION,
                schema_version,
            )
        )
    contract_hash = getattr(uds_client, "NEUTRON_STATUS_CONTRACT_HASH", None)
    if (
        type(contract_hash) is not str
        or contract_hash != EXPECTED_STATUS_V1_CONTRACT_HASH
    ):
        errors.append(
            "Python Status V1 hash expected %r, got %r"
            % (
                EXPECTED_STATUS_V1_CONTRACT_HASH,
                contract_hash,
            )
        )
    capability_fields = getattr(
        uds_client, "_STATUS_CONTRACT_CAPABILITY_FIELDS", None
    )
    if (
        type(capability_fields) is not tuple
        or not all(type(field) is str for field in capability_fields)
    ):
        errors.append(
            "Python Status V1 capability fields must be an exact tuple of strings, got %r"
            % (capability_fields,)
        )
    elif capability_fields != EXPECTED_STATUS_CAPABILITY_FIELDS:
        errors.append(
            "Python Status V1 capability fields expected %r, got %r"
            % (
                EXPECTED_STATUS_CAPABILITY_FIELDS,
                capability_fields,
            )
        )
    response_fields = getattr(
        uds_client, "_STATUS_CONTRACT_RESPONSE_FIELDS", None
    )
    if (
        type(response_fields) is not tuple
        or not all(type(field) is str for field in response_fields)
    ):
        errors.append(
            "Python Status V1 response fields must be an exact tuple of strings, got %r"
            % (response_fields,)
        )
    elif response_fields != EXPECTED_STATUS_RESPONSE_FIELDS:
        errors.append(
            "Python Status V1 response fields expected %r, got %r"
            % (
                EXPECTED_STATUS_RESPONSE_FIELDS,
                response_fields,
            )
        )

    errors.extend(_status_v1_python_triples_contract_errors(
        getattr(uds_client, "_STATUS_V1_TRIPLES", None),
        vocabulary,
    ))
    python_vocabulary = (
        (
            "recovery_causes",
            getattr(uds_client, "_STATUS_V1_RECOVERY_CAUSES", None),
        ),
        (
            "domain_statuses",
            getattr(uds_client, "_STATUS_V1_DOMAIN_STATES", None),
        ),
        (
            "effective_actions",
            getattr(uds_client, "_STATUS_V1_EFFECTIVE_ACTIONS", None),
        ),
        (
            "support_dispositions",
            getattr(uds_client, "_STATUS_V1_SUPPORT_DISPOSITIONS", None),
        ),
    )
    for name, actual in python_vocabulary:
        errors.extend(_status_v1_python_vocabulary_contract_errors(
            name,
            actual,
            vocabulary[name],
        ))
    return errors


def _run_status_v1_shape_mutation_self_tests():
    vocabulary = dict(EXPECTED_STATUS_V1_VOCABULARY)
    duplicate_unhashable = [{"same": [1]}, {"same": [1]}]
    if not _status_v1_has_duplicates(duplicate_unhashable):
        raise SystemExit(
            "ERROR: Status V1 checker missed duplicate unhashable JSON values"
        )
    if _status_v1_has_duplicates([{"value": 1}, {"value": 2}]):
        raise SystemExit(
            "ERROR: Status V1 checker invented duplicate unhashable JSON values"
        )

    conversion_calls = []

    def forbidden_frozenset(values):
        conversion_calls.append(values)
        raise AssertionError("malformed values must not reach frozenset")

    triple_errors = _status_v1_python_triples_contract_errors(
        (("idle", "unknown", "full_resync"), {"invalid": "shape"}),
        dict(EXPECTED_STATUS_V1_VOCABULARY),
        frozenset_factory=forbidden_frozenset,
    )
    if not triple_errors or conversion_calls:
        raise SystemExit(
            "ERROR: Status V1 checker converted malformed Python triples"
        )

    vocabulary_errors = _status_v1_python_vocabulary_contract_errors(
        "domain_statuses",
        ["ready", {"invalid": "shape"}],
        dict(EXPECTED_STATUS_V1_VOCABULARY)["domain_statuses"],
        frozenset_factory=forbidden_frozenset,
    )
    if not vocabulary_errors or conversion_calls:
        raise SystemExit(
            "ERROR: Status V1 checker converted malformed Python vocabulary"
        )

    class PythonMetadata(object):
        pass

    def valid_python_metadata():
        metadata = PythonMetadata()
        metadata.NEUTRON_STATUS_SCHEMA_VERSION = EXPECTED_STATUS_V1_SCHEMA_VERSION
        metadata.NEUTRON_STATUS_CONTRACT_HASH = EXPECTED_STATUS_V1_CONTRACT_HASH
        metadata._STATUS_CONTRACT_CAPABILITY_FIELDS = (
            EXPECTED_STATUS_CAPABILITY_FIELDS
        )
        metadata._STATUS_CONTRACT_RESPONSE_FIELDS = EXPECTED_STATUS_RESPONSE_FIELDS
        metadata._STATUS_V1_TRIPLES = EXPECTED_STATUS_V1_TRIPLES
        metadata._STATUS_V1_RECOVERY_CAUSES = frozenset(
            vocabulary["recovery_causes"]
        )
        metadata._STATUS_V1_DOMAIN_STATES = frozenset(
            vocabulary["domain_statuses"]
        )
        metadata._STATUS_V1_EFFECTIVE_ACTIONS = frozenset(
            vocabulary["effective_actions"]
        )
        metadata._STATUS_V1_SUPPORT_DISPOSITIONS = frozenset(
            vocabulary["support_dispositions"]
        )
        return metadata

    metadata_mutations = []
    missing_capabilities = valid_python_metadata()
    del missing_capabilities._STATUS_CONTRACT_CAPABILITY_FIELDS
    metadata_mutations.append(("missing capability fields", missing_capabilities))
    none_responses = valid_python_metadata()
    none_responses._STATUS_CONTRACT_RESPONSE_FIELDS = None
    metadata_mutations.append(("None response fields", none_responses))
    list_capabilities = valid_python_metadata()
    list_capabilities._STATUS_CONTRACT_CAPABILITY_FIELDS = list(
        EXPECTED_STATUS_CAPABILITY_FIELDS
    )
    metadata_mutations.append(("non-tuple capability fields", list_capabilities))
    malformed_responses = valid_python_metadata()
    malformed_responses._STATUS_CONTRACT_RESPONSE_FIELDS = (
        "status_schema_version", {"invalid": "shape"},
    )
    metadata_mutations.append(("non-string response field", malformed_responses))
    missing_triples = valid_python_metadata()
    del missing_triples._STATUS_V1_TRIPLES
    metadata_mutations.append(("missing triple inventory", missing_triples))
    for description, metadata in metadata_mutations:
        try:
            metadata_errors = _status_v1_python_metadata_contract_errors(
                metadata,
                vocabulary,
            )
        except (AttributeError, TypeError) as error:
            raise SystemExit(
                "ERROR: Status V1 Python metadata checker raised %s for %s"
                % (type(error).__name__, description)
            )
        if not metadata_errors:
            raise SystemExit(
                "ERROR: Status V1 Python metadata checker accepted %s"
                % description
            )
    print("Status V1 shape mutation self-tests: OK (9 scenarios)")


def _status_v1_projection_contract_errors(scenario_id, projection, vocabulary):
    scenario_id_is_string = type(scenario_id) is str
    errors = []
    if not scenario_id_is_string:
        errors.append(
            "Status V1 scenario id must be an exact string, got %r" % scenario_id
        )
    if projection is None:
        if (
            scenario_id_is_string
            and scenario_id in EXPECTED_STATUS_V1_NULL_PROJECTION_IDS
        ):
            return errors
        errors.append(
            "Status V1 scenario %r must declare expected_projection"
            % scenario_id
        )
        return errors
    if not isinstance(projection, dict):
        errors.append(
            "Status V1 scenario %r expected_projection must be an object or null"
            % scenario_id
        )
        return errors

    if (
        scenario_id_is_string
        and scenario_id in EXPECTED_STATUS_V1_NULL_PROJECTION_IDS
    ):
        errors.append(
            "Status V1 scenario %r must keep expected_projection null"
            % scenario_id
        )
    projection_fields = (
        "transaction_state", "overall_readiness", "required_action",
    )
    projection_vocabularies = (
        vocabulary["transaction_states"],
        vocabulary["overall_readiness"],
        vocabulary["required_actions"],
    )
    present = tuple(field in projection for field in projection_fields)
    if not all(present):
        errors.append(
            "Status V1 scenario %r has an incomplete projection triple"
            % scenario_id
        )
    else:
        triple = tuple(projection[field] for field in projection_fields)
        triple_valid = True
        for field, actual, allowed in zip(
            projection_fields, triple, projection_vocabularies
        ):
            if not isinstance(actual, str) or actual not in allowed:
                triple_valid = False
                errors.append(
                    "Status V1 scenario %r projection %s has unknown value %r"
                    % (scenario_id, field, actual)
                )
        if triple_valid and triple not in EXPECTED_STATUS_V1_TRIPLES:
            errors.append(
                "Status V1 scenario %r has unapproved projection triple %r"
                % (scenario_id, triple)
            )
    if "recovery_cause" not in projection:
        errors.append(
            "Status V1 scenario %r projection is missing recovery_cause"
            % scenario_id
        )
    elif projection["recovery_cause"] not in vocabulary["recovery_causes"]:
        errors.append(
            "Status V1 scenario %r projection has unknown recovery_cause %r"
            % (scenario_id, projection["recovery_cause"])
        )
    else:
        expected_cause = (
            "inventory_unavailable"
            if (
                scenario_id_is_string
                and scenario_id in EXPECTED_STATUS_V1_INVENTORY_RECOVERY_IDS
            )
            else None
        )
        if projection["recovery_cause"] != expected_cause:
            errors.append(
                "Status V1 scenario %r projection recovery_cause expected %r, got %r"
                % (scenario_id, expected_cause, projection["recovery_cause"])
            )
    classified_generation = projection.get("last_classified_generation")
    if (
        type(classified_generation) is not int or
        classified_generation < 0
    ):
        errors.append(
            "Status V1 scenario %r last_classified_generation must be a non-negative integer"
            % scenario_id
        )
    return errors


def _status_v1_scenario_contract_errors(scenario, vocabulary):
    if "expected_projection" not in scenario:
        return [
            "Status V1 scenario %r is missing expected_projection"
            % scenario.get("id")
        ]
    return _status_v1_projection_contract_errors(
        scenario.get("id"),
        scenario["expected_projection"],
        vocabulary,
    )


def _run_status_v1_projection_mutation_self_tests():
    vocabulary = dict(EXPECTED_STATUS_V1_VOCABULARY)
    safe = {
        "transaction_state": "classified",
        "overall_readiness": "ready",
        "required_action": "none",
        "recovery_cause": None,
        "last_classified_generation": 42,
    }
    if _status_v1_projection_contract_errors("safe", safe, vocabulary):
        raise SystemExit("ERROR: Status V1 checker rejected a valid projection")
    if not _status_v1_projection_contract_errors(
        "full-classified-ready", None, vocabulary
    ):
        raise SystemExit(
            "ERROR: Status V1 checker accepted a missing required projection"
        )
    for scenario_id in (
        "legacy-v0-unknown-authority",
        "unknown-v1-contract",
        "ready-invalid-evidence",
    ):
        if _status_v1_projection_contract_errors(
            scenario_id, None, vocabulary
        ):
            raise SystemExit(
                "ERROR: Status V1 checker rejected an intentional null projection"
            )
    if not _status_v1_scenario_contract_errors(
        {"id": "legacy-v0-unknown-authority"},
        vocabulary,
    ):
        raise SystemExit(
            "ERROR: Status V1 checker accepted a missing expected_projection member"
        )
    if not _status_v1_projection_contract_errors(
        "missing-triple", {"recovery_cause": None}, vocabulary
    ):
        raise SystemExit("ERROR: Status V1 checker accepted a missing projection triple")
    unknown_cause = dict(safe)
    unknown_cause["recovery_cause"] = "operator_required"
    if not _status_v1_projection_contract_errors(
        "unknown-cause", unknown_cause, vocabulary
    ):
        raise SystemExit("ERROR: Status V1 checker accepted an unknown recovery cause")
    missing_inventory_cause = dict(safe)
    missing_inventory_cause.update({
        "transaction_state": "blocked",
        "overall_readiness": "blocked",
        "required_action": "recover_pending",
    })
    if not _status_v1_projection_contract_errors(
        "blocked-recoverable-inventory",
        missing_inventory_cause,
        vocabulary,
    ):
        raise SystemExit(
            "ERROR: Status V1 checker accepted missing inventory recovery cause"
        )
    unexpected_inventory_cause = dict(safe)
    unexpected_inventory_cause["recovery_cause"] = "inventory_unavailable"
    if not _status_v1_projection_contract_errors(
        "full-classified-ready",
        unexpected_inventory_cause,
        vocabulary,
    ):
        raise SystemExit(
            "ERROR: Status V1 checker accepted inventory cause on unrelated scenario"
        )
    for label, generation in (
        ("boolean", True),
        ("negative", -1),
    ):
        malformed_generation = dict(safe)
        malformed_generation["last_classified_generation"] = generation
        if not _status_v1_projection_contract_errors(
            "full-classified-ready",
            malformed_generation,
            vocabulary,
        ):
            raise SystemExit(
                "ERROR: Status V1 checker accepted %s classified generation"
                % label
            )
    missing_generation = dict(safe)
    missing_generation.pop("last_classified_generation")
    if not _status_v1_projection_contract_errors(
        "full-classified-ready", missing_generation, vocabulary
    ):
        raise SystemExit(
            "ERROR: Status V1 checker accepted missing classified generation"
        )
    generation_zero_recovery = dict(missing_inventory_cause)
    generation_zero_recovery["recovery_cause"] = "inventory_unavailable"
    generation_zero_recovery["last_classified_generation"] = 0
    if _status_v1_projection_contract_errors(
        "generation-zero-inventory-recovery",
        generation_zero_recovery,
        vocabulary,
    ):
        raise SystemExit(
            "ERROR: Status V1 checker rejected valid generation-zero projection"
        )
    unhashable_triple = dict(safe)
    unhashable_triple["transaction_state"] = {"invalid": "shape"}
    try:
        unhashable_errors = _status_v1_projection_contract_errors(
            "full-classified-ready", unhashable_triple, vocabulary
        )
    except TypeError:
        raise SystemExit(
            "ERROR: Status V1 projection checker raised TypeError for malformed shape"
        )
    if not unhashable_errors:
        raise SystemExit(
            "ERROR: Status V1 checker accepted an unhashable projection value"
        )
    unhashable_scenario_id = ["invalid", "scenario", "id"]
    try:
        unhashable_id_errors = _status_v1_projection_contract_errors(
            unhashable_scenario_id, safe, vocabulary
        )
    except TypeError:
        raise SystemExit(
            "ERROR: Status V1 projection checker raised TypeError for an unhashable scenario ID"
        )
    if not unhashable_id_errors:
        raise SystemExit(
            "ERROR: Status V1 checker accepted an unhashable scenario ID"
        )
    print("Status V1 projection mutation self-tests: OK (16 scenarios)")


def _acl_map_helper_contract_errors(source, function_name, required_map_openers):
    body = _rust_function_body_raw(source, function_name)
    if body is None:
        return ["missing low-level ACL map helper %s" % function_name]
    code = _blank_rust_non_code(body)
    errors = []
    if "xdp_firewall" in body or "Firewall not started" in body:
        errors.append(
            "%s must not use the XDP program pin as ACL/map readiness"
            % function_name
        )
    for tc_marker in ("tc_ingress_link", "tc_egress_link"):
        if tc_marker in body:
            errors.append(
                "%s must not duplicate agent TC lifecycle readiness via %s"
                % (function_name, tc_marker)
            )
    for opener in required_map_openers:
        if opener not in code:
            errors.append(
                "%s must fail closed by opening required map via %s"
                % (function_name, opener)
            )
    return errors


def _run_acl_map_helper_contract_mutation_self_tests():
    safe = "fn helper() { open_pinned_policy_table(pin_path)?; }"
    if _acl_map_helper_contract_errors(safe, "helper", ("open_pinned_policy_table",)):
        raise SystemExit("ERROR: ACL map helper contract rejected XDP-independent code")
    xdp_mutant = """
        fn helper() {
            let prog_path = format!("{}/xdp_firewall", pin_path);
            if !Path::new(&prog_path).exists() { return Ok(()); }
            open_pinned_policy_table(pin_path)?;
        }
    """
    xdp_errors = _acl_map_helper_contract_errors(
        xdp_mutant, "helper", ("open_pinned_policy_table",)
    )
    if not any("XDP program pin" in error for error in xdp_errors):
        raise SystemExit("ERROR: ACL map helper contract accepted XDP sentinel mutation")
    tc_mutant = "fn helper() { require_pin(tc_ingress_link); open_pinned_policy_table(pin_path)?; }"
    tc_errors = _acl_map_helper_contract_errors(
        tc_mutant, "helper", ("open_pinned_policy_table",)
    )
    if not any("agent TC lifecycle readiness" in error for error in tc_errors):
        raise SystemExit("ERROR: ACL map helper contract accepted TC-link sentinel mutation")
    missing_map = "fn helper() { do_nothing(); }"
    missing_errors = _acl_map_helper_contract_errors(
        missing_map, "helper", ("open_pinned_policy_table",)
    )
    if not any("opening required map" in error for error in missing_errors):
        raise SystemExit("ERROR: ACL map helper contract accepted missing-map mutation")
    print("ACL map helper XDP-independence mutation self-tests: OK (4 scenarios)")


def _acl_delete_semantics_contract_errors(source, function_name, required_seam):
    body = _rust_function_body_raw(source, function_name)
    if body is None:
        return ["missing ACL delete helper %s" % function_name]
    code = _blank_rust_non_code(body)
    errors = []
    if required_seam not in code:
        errors.append(
            "%s must use exact delete error seam %s"
            % (function_name, required_seam)
        )
    if re.search(r"\bErr\s*\(\s*_\s*\)", code):
        errors.append(
            "%s must not classify every map error as not-found" % function_name
        )
    if re.search(r"\blet\s+_\s*=\s*[^;]*\b(?:delete_|remove\s*\()", code):
        errors.append(
            "%s must not discard ACL delete/rollback failures" % function_name
        )
    return errors


def _run_acl_delete_semantics_mutation_self_tests():
    safe = "fn helper() { classify_map_delete(map.remove(&key), context)?; }"
    if _acl_delete_semantics_contract_errors(safe, "helper", "classify_map_delete"):
        raise SystemExit("ERROR: ACL delete contract rejected exact classifier use")
    wildcard = "fn helper() { match map.remove(&key) { Ok(()) => {}, Err(_) => {} } }"
    wildcard_errors = _acl_delete_semantics_contract_errors(
        wildcard, "helper", "classify_map_delete"
    )
    if not any("every map error" in error for error in wildcard_errors):
        raise SystemExit("ERROR: ACL delete contract accepted wildcard error mutation")
    discarded = "fn helper() { let _ = delete_port_set(idx); classify_map_delete(result, ctx)?; }"
    discarded_errors = _acl_delete_semantics_contract_errors(
        discarded, "helper", "classify_map_delete"
    )
    if not any("discard" in error for error in discarded_errors):
        raise SystemExit("ERROR: ACL delete contract accepted discarded rollback mutation")
    missing = "fn helper() { map.remove(&key)?; }"
    missing_errors = _acl_delete_semantics_contract_errors(
        missing, "helper", "classify_map_delete"
    )
    if not any("exact delete error seam" in error for error in missing_errors):
        raise SystemExit("ERROR: ACL delete contract accepted missing classifier mutation")
    print("ACL exact-delete mutation self-tests: OK (4 scenarios)")


def _owned_acl_release_quarantine_contract_errors(source):
    helper_body = _rust_function_body_raw(
        source, "quarantine_owned_acl_released_port_set"
    )
    replace_body = _rust_function_body_raw(source, "replace_owned_acl")
    errors = []
    if helper_body is None:
        errors.append("missing owned ACL released-port-set quarantine helper")
    else:
        helper_code = _blank_rust_non_code(helper_body)
        quarantine = helper_code.find("quarantine_bitmap_index")
        record = helper_code.find("released_port_sets.insert")
        if not (0 <= quarantine < record):
            errors.append(
                "owned ACL released index must be quarantined before cleanup recording"
            )

    if replace_body is None:
        errors.append("missing replace_owned_acl for immediate quarantine contract")
        return errors

    replace_code = _blank_rust_non_code(replace_body)
    calls = [
        match.start()
        for match in re.finditer(
            r"\bquarantine_owned_acl_released_port_set\s*\(", replace_code
        )
    ]
    add_rule = replace_code.find(".apply_add_rule(")
    remove_rule = replace_code.find(".apply_remove_rule(")
    brace_depth = lambda position: (
        replace_code[:position].count("{") - replace_code[:position].count("}")
    )
    if not (
        len(calls) == 2
        and 0 <= add_rule < calls[0] < remove_rule < calls[1]
        and brace_depth(add_rule) == brace_depth(calls[0])
        and brace_depth(remove_rule) == brace_depth(calls[1])
    ):
        errors.append(
            "replace_owned_acl must quarantine each add/remove release before the next mutation"
        )
    if re.search(r"\breleased_port_sets\s*\.\s*retain\s*\(", replace_code):
        errors.append(
            "replace_owned_acl must not permit same-diff released-index reuse via retain"
        )
    return errors


def _run_owned_acl_release_quarantine_mutation_self_tests():
    safe = """
        fn quarantine_owned_acl_released_port_set() {
            state.quarantine_bitmap_index(bitmap_idx)?;
            released_port_sets.insert(bitmap_idx, ports_normalized);
        }
        fn replace_owned_acl() {
            for policy in desired {
                final_state.apply_add_rule();
                quarantine_owned_acl_released_port_set();
            }
            for existing in deletes {
                final_state.apply_remove_rule();
                quarantine_owned_acl_released_port_set();
            }
        }
    """
    if _owned_acl_release_quarantine_contract_errors(safe):
        raise SystemExit("ERROR: owned ACL quarantine contract rejected safe ordering")

    record_first = safe.replace(
        "state.quarantine_bitmap_index(bitmap_idx)?;\n            released_port_sets.insert(bitmap_idx, ports_normalized);",
        "released_port_sets.insert(bitmap_idx, ports_normalized);\n            state.quarantine_bitmap_index(bitmap_idx)?;",
    )
    if not any(
        "before cleanup recording" in error
        for error in _owned_acl_release_quarantine_contract_errors(record_first)
    ):
        raise SystemExit("ERROR: owned ACL quarantine contract accepted record-first mutation")

    after_loop = safe.replace(
        "                quarantine_owned_acl_released_port_set();\n            }\n            for existing in deletes {",
        "            }\n            quarantine_owned_acl_released_port_set();\n            for existing in deletes {",
    )
    if not any(
        "before the next mutation" in error
        for error in _owned_acl_release_quarantine_contract_errors(after_loop)
    ):
        raise SystemExit("ERROR: owned ACL quarantine contract accepted after-loop mutation")

    retain_reuse = safe.replace(
        "            }\n        }\n    ",
        "            }\n            released_port_sets.retain(|_, _| true);\n        }\n    ",
    )
    if not any(
        "same-diff released-index reuse" in error
        for error in _owned_acl_release_quarantine_contract_errors(retain_reuse)
    ):
        raise SystemExit("ERROR: owned ACL quarantine contract accepted retain mutation")
    print("Owned ACL immediate-quarantine mutation self-tests: OK (4 scenarios)")


def _managed_acl_shadow_contract_errors(source, source_code=None):
    if source_code is None:
        stage_body = _rust_function_body_raw(source, "stage_acl_shadow_bank")
        plan_body = _rust_function_body_raw(
            source, "managed_acl_shadow_network_plan"
        )
        stage_code = (
            None if stage_body is None else _blank_rust_non_code(stage_body)
        )
        plan_code = None if plan_body is None else _blank_rust_non_code(plan_body)
    else:
        stage_code = _rust_function_body_from_blanked(
            source_code, "stage_acl_shadow_bank"
        )
        plan_code = _rust_function_body_from_blanked(
            source_code, "managed_acl_shadow_network_plan"
        )
    if stage_code is None or plan_code is None:
        return ["managed ACL shadow staging helper is missing"]

    errors = []
    if re.search(r"\bstate\s*\.\s*groups\b", stage_code) or re.search(
        r"\bstate\s*\.\s*groups\b", plan_code
    ):
        errors.append("managed ACL shadow staging still iterates the raw all-group state")

    for direction in ("acl_src", "acl_dst"):
        if not re.search(
            r"\bprojection\s*\.\s*%s\b" % direction,
            plan_code,
        ):
            errors.append(
                "managed ACL shadow plan is missing projection.%s" % direction
            )

    allowed_projection_fields_removed = re.sub(
        r"\bprojection\s*\.\s*(?:acl_src|acl_dst)\b",
        "ACL_DIRECTIONAL_PROJECTION",
        plan_code,
    )
    if re.search(r"\bprojection\b", allowed_projection_fields_removed):
        errors.append(
            "managed ACL shadow plan must not alias, delegate, or read non-ACL projection data"
        )
    if re.search(
        r"\.\s*(?:general|legacy_candidates|general_candidates)\b",
        plan_code,
    ):
        errors.append(
            "managed ACL shadow plan must not consume the general projection"
        )

    exact_projection_calls = re.findall(
        r"\bmanaged_acl_shadow_network_plan\s*"
        r"\(\s*projection\s*\)",
        stage_code,
        re.DOTALL,
    )
    exact_projection_loop = re.search(
        r"\bfor\s*\(\s*direction\s*,\s*cidr\s*,\s*group_id\s*\)\s+"
        r"in\s+managed_acl_shadow_network_plan\s*"
        r"\(\s*projection\s*\)\s*\{",
        stage_code,
        re.DOTALL,
    )
    if exact_projection_loop is None or len(exact_projection_calls) != 1:
        errors.append(
            "managed ACL shadow network writes must iterate only the compiled projection plan"
        )
    elif (
        stage_code[:exact_projection_loop.start()].count("{")
        - stage_code[:exact_projection_loop.start()].count("}")
        != 0
    ):
        errors.append(
            "managed ACL shadow projection loop must remain unconditional at function top level"
        )
    elif re.search(
        r"\b(?:if|match|return|break|continue|while|for|loop)\b",
        stage_code[:exact_projection_loop.start()],
    ):
        errors.append(
            "managed ACL shadow staging must not bypass the projection loop with pre-loop control flow"
        )
    if exact_projection_loop is not None:
        pre_loop = stage_code[:exact_projection_loop.start()]
        writer_inputs = r"(?:bank|runtime|ebpf_path)"
        input_rebound = re.search(
            r"\blet\b[^;]*\b%s\b" % writer_inputs,
            pre_loop,
            re.DOTALL,
        )
        input_assigned = re.search(
            r"\b%s\b\s*(?:(?:<<|>>|[+\-*/%%&|^])?=)(?!=)"
            % writer_inputs,
            pre_loop,
        )
        input_mutably_borrowed = re.search(
            r"&\s*mut\s+\b%s\b" % writer_inputs,
            pre_loop,
        )
        if input_rebound or input_assigned or input_mutably_borrowed:
            errors.append(
                "managed ACL shadow writer inputs must remain bound to stage parameters"
            )
    stage_without_projection_plan = re.sub(
        r"\bmanaged_acl_shadow_network_plan\s*"
        r"\(\s*projection\s*\)",
        "ACL_SHADOW_PLAN",
        stage_code,
        flags=re.DOTALL,
    )
    if re.search(r"\bprojection\b", stage_without_projection_plan):
        errors.append(
            "managed ACL shadow staging must not alias or delegate projection data"
        )
    if re.search(
        r"\.\s*(?:general|legacy_candidates|general_candidates)\b",
        stage_code,
    ):
        errors.append(
            "managed ACL shadow staging must not consume the general projection"
        )
    writer_call = re.compile(
        r"\baria_core\s*::\s*ebpf_ops\s*::\s*"
        r"add_acl_network_in_bank\s*\("
    )
    entry_writer_call = re.compile(
        r"\baria_core\s*::\s*ebpf_ops\s*::\s*"
        r"add_acl_network_in_bank\s*\(\s*"
        r"direction\s*,\s*&\s*cidr\s*,\s*group_id\s*,\s*"
        r"bank\s*,\s*runtime\s*,\s*ebpf_path\s*,?\s*\)"
    )
    stage_writer_count = len(writer_call.findall(stage_code))
    loop_body = None
    if exact_projection_loop is not None:
        loop_body = _rust_braced_body_at(
            stage_code, exact_projection_loop.end() - 1
        )
    loop_writer_count = (
        len(writer_call.findall(loop_body)) if loop_body is not None else 0
    )
    if stage_writer_count != 1:
        errors.append(
            "managed ACL shadow staging must have exactly one direct ACL network writer"
        )
    elif loop_writer_count != 1:
        errors.append(
            "managed ACL shadow network writer must remain inside the compiled projection loop"
        )
    elif len(entry_writer_call.findall(loop_body)) != 1:
        errors.append(
            "managed ACL shadow writer must publish the current entry to the requested bank"
        )
    else:
        entry_writer = entry_writer_call.search(loop_body)
        writer_prefix = loop_body[:entry_writer.start()]
        writer_depth = writer_prefix.count("{") - writer_prefix.count("}")
        if writer_prefix.strip() or writer_depth != 0:
            errors.append(
                "managed ACL shadow writer must be the unconditional first loop statement"
            )
        top_level_semicolons = []
        depth = 0
        for index, character in enumerate(loop_body):
            if character == "{":
                depth += 1
            elif character == "}":
                depth -= 1
            elif character == ";" and depth == 0:
                top_level_semicolons.append(index)
        last_token = len(loop_body.rstrip()) - 1
        if (
            len(top_level_semicolons) != 1
            or top_level_semicolons[0] != last_token
            or not loop_body.rstrip().endswith("?;")
        ):
            errors.append(
                "managed ACL shadow loop must contain only one fallible writer statement"
            )

    allowed_state_uses_removed = re.sub(
        r"\bstate\s*\.\s*rules\b",
        "STATE_RULES",
        stage_code,
    )
    allowed_state_uses_removed = re.sub(
        r"\bSelf\s*::\s*owned_acl_policy_key_from_rule\s*"
        r"\(\s*state\s*,\s*rule\s*\)",
        "POLICY_KEY_FROM_STATE",
        allowed_state_uses_removed,
    )
    if re.search(r"\bstate\b", allowed_state_uses_removed):
        errors.append(
            "managed ACL shadow staging must not alias or delegate raw state to a network plan"
        )
    return errors


def _run_managed_acl_shadow_mutation_self_tests():
    safe = """
        fn managed_acl_shadow_network_plan(projection: &Projection) {
            projection.acl_src.iter();
            projection.acl_dst.iter();
        }
        fn stage_acl_shadow_bank(state: &State, projection: &Projection) {
            for (direction, cidr, group_id) in managed_acl_shadow_network_plan(projection) {
                aria_core::ebpf_ops::add_acl_network_in_bank(
                    direction, &cidr, group_id, bank, runtime, ebpf_path,
                ).map_err(ControlPlaneError::KernelError)?;
            }
            for rule in &state.rules {
                let key = Self::owned_acl_policy_key_from_rule(state, rule);
                add_policy_in_bank(key);
            }
        }
    """
    if _managed_acl_shadow_contract_errors(safe):
        raise SystemExit("ERROR: managed ACL shadow checker rejected safe projection staging")

    safe_directional_alias = safe.replace(
        "projection.acl_src.iter();",
        "let general = &projection.acl_src;\n"
        "            general.iter();",
        1,
    )
    if _managed_acl_shadow_contract_errors(safe_directional_alias):
        raise SystemExit(
            "ERROR: managed ACL shadow checker rejected a safe directional alias"
        )
    safe_directional_delegation = safe.replace(
        "projection.acl_src.iter();\n            projection.acl_dst.iter();",
        "directional_plan(&projection.acl_src);\n"
        "            directional_plan(&projection.acl_dst);",
        1,
    )
    if _managed_acl_shadow_contract_errors(safe_directional_delegation):
        raise SystemExit(
            "ERROR: managed ACL shadow checker rejected safe directional delegation"
        )

    mutants = {
        "direct raw-group": (
            safe.replace(
                "managed_acl_shadow_network_plan(projection)",
                "state.groups.values()",
                1,
            ),
            "raw all-group state",
        ),
        "aliased raw-group": (
            safe.replace(
                "for (direction, cidr, group_id) in managed_acl_shadow_network_plan(projection) {",
                "let groups = &state.groups;\n"
                "            for (direction, cidr, group_id) in groups {",
                1,
            ),
            "raw all-group state",
        ),
        "delegated raw-group": (
            safe.replace(
                "managed_acl_shadow_network_plan(projection)",
                "raw_group_shadow_plan(state)",
                1,
            ),
            "raw state",
        ),
        "chained raw-group": (
            safe.replace(
                "managed_acl_shadow_network_plan(projection)",
                "managed_acl_shadow_network_plan(projection).chain(raw_group_shadow_plan(state))",
                1,
            ),
            "raw state",
        ),
        "plan general projection": (
            safe.replace(
                "projection.acl_dst.iter();",
                "projection.acl_dst.iter().chain(projection.general.iter());",
                1,
            ),
            "non-ACL projection data",
        ),
        "plan aliased projection": (
            safe.replace(
                "projection.acl_src.iter();",
                "let projection_alias = projection;\n"
                "            projection_alias.general.iter();\n"
                "            projection.acl_src.iter();",
                1,
            ),
            "non-ACL projection data",
        ),
        "plan delegated projection": (
            safe.replace(
                "projection.acl_dst.iter();",
                "projection.acl_dst.iter();\n"
                "            general_shadow_plan(projection);",
                1,
            ),
            "non-ACL projection data",
        ),
        "plan delegated general field": (
            safe.replace(
                "projection.acl_dst.iter();",
                "projection.acl_dst.iter();\n"
                "            general_shadow_plan(&projection.general);",
                1,
            ),
            "non-ACL projection data",
        ),
        "supplemental delegated writer": (
            safe.replace(
                "            for rule in &state.rules {",
                "            stage_general_projection(projection);\n"
                "            for rule in &state.rules {",
                1,
            ),
            "staging must not alias or delegate projection data",
        ),
        "stage direct general projection": (
            safe.replace(
                "            for rule in &state.rules {",
                "            for entry in &projection.general { delegated_add(entry); }\n"
                "            for rule in &state.rules {",
                1,
            ),
            "staging must not alias or delegate projection data",
        ),
        "writer moved outside projection loop": (
            safe.replace(
                "aria_core::ebpf_ops::add_acl_network_in_bank(\n"
                "                    direction, &cidr, group_id, bank, runtime, ebpf_path,\n"
                "                ).map_err(ControlPlaneError::KernelError)?;",
                "let _ = (direction, cidr, group_id);",
                1,
            ).replace(
                "            for rule in &state.rules {",
                "            aria_core::ebpf_ops::add_acl_network_in_bank(\n"
                "                \"src\", &cidr, group_id, bank, runtime, ebpf_path,\n"
                "            ).map_err(ControlPlaneError::KernelError)?;\n"
                "            for rule in &state.rules {",
                1,
            ),
            "writer must remain inside the compiled projection loop",
        ),
        "writer token spoof": (
            safe.replace(
                "aria_core::ebpf_ops::add_acl_network_in_bank(\n"
                "                    direction, &cidr, group_id, bank, runtime, ebpf_path,\n"
                "                ).map_err(ControlPlaneError::KernelError)?;",
                "delegated_writer(direction, cidr, group_id);\n"
                "                let add_acl_network_in_bank_marker = true;",
                1,
            ),
            "exactly one direct ACL network writer",
        ),
        "second direct writer": (
            safe.replace(
                "                ).map_err(ControlPlaneError::KernelError)?;",
                "                ).map_err(ControlPlaneError::KernelError)?;\n"
                "                aria_core::ebpf_ops::add_acl_network_in_bank(\n"
                "                    direction, &cidr, group_id, bank, runtime, ebpf_path,\n"
                "                ).map_err(ControlPlaneError::KernelError)?;",
                1,
            ),
            "exactly one direct ACL network writer",
        ),
        "conditional projection loop": (
            safe.replace(
                "            for (direction, cidr, group_id) in managed_acl_shadow_network_plan(projection) {",
                "            if bank == 0 {\n"
                "                for (direction, cidr, group_id) in managed_acl_shadow_network_plan(projection) {",
                1,
            ).replace(
                "            }\n            for rule in &state.rules {",
                "                }\n"
                "            }\n"
                "            for rule in &state.rules {",
                1,
            ),
            "projection loop must remain unconditional at function top level",
        ),
        "pre-loop early return": (
            safe.replace(
                "            for (direction, cidr, group_id) in managed_acl_shadow_network_plan(projection) {",
                "            if bank == 1 { return Ok(()); }\n"
                "            for (direction, cidr, group_id) in managed_acl_shadow_network_plan(projection) {",
                1,
            ),
            "must not bypass the projection loop with pre-loop control flow",
        ),
        "conditional writer": (
            safe.replace(
                "                aria_core::ebpf_ops::add_acl_network_in_bank(",
                "                if bank == 0 {\n"
                "                    aria_core::ebpf_ops::add_acl_network_in_bank(",
                1,
            ).replace(
                "                ).map_err(ControlPlaneError::KernelError)?;",
                "                    ).map_err(ControlPlaneError::KernelError)?;\n"
                "                }",
                1,
            ),
            "writer must be the unconditional first loop statement",
        ),
        "writer targets wrong bank": (
            safe.replace(
                "direction, &cidr, group_id, bank, runtime, ebpf_path,",
                "direction, &cidr, group_id, 0, runtime, ebpf_path,",
                1,
            ),
            "writer must publish the current entry to the requested bank",
        ),
        "writer result ignored": (
            safe.replace(
                ").map_err(ControlPlaneError::KernelError)?;",
                ");",
                1,
            ),
            "loop must contain only one fallible writer statement",
        ),
        "writer followed by break": (
            safe.replace(
                "                ).map_err(ControlPlaneError::KernelError)?;",
                "                ).map_err(ControlPlaneError::KernelError)?;\n"
                "                break;",
                1,
            ),
            "loop must contain only one fallible writer statement",
        ),
        "target bank shadowed": (
            safe.replace(
                "            for (direction, cidr, group_id) in managed_acl_shadow_network_plan(projection) {",
                "            let bank = bank & 0;\n"
                "            for (direction, cidr, group_id) in managed_acl_shadow_network_plan(projection) {",
                1,
            ),
            "writer inputs must remain bound to stage parameters",
        ),
        "runtime shadowed": (
            safe.replace(
                "            for (direction, cidr, group_id) in managed_acl_shadow_network_plan(projection) {",
                "            let runtime = remap(runtime);\n"
                "            for (direction, cidr, group_id) in managed_acl_shadow_network_plan(projection) {",
                1,
            ),
            "writer inputs must remain bound to stage parameters",
        ),
        "target bank mutably borrowed": (
            safe.replace(
                "            for (direction, cidr, group_id) in managed_acl_shadow_network_plan(projection) {",
                "            zero(&mut bank);\n"
                "            for (direction, cidr, group_id) in managed_acl_shadow_network_plan(projection) {",
                1,
            ),
            "writer inputs must remain bound to stage parameters",
        ),
    }
    for label, (mutant, expected_error) in mutants.items():
        errors = _managed_acl_shadow_contract_errors(mutant)
        if not any(expected_error in error for error in errors):
            raise SystemExit(
                "ERROR: managed ACL shadow checker accepted %s mutation: %s"
                % (label, errors)
            )
    print("Managed ACL shadow projection mutation self-tests: OK (25 scenarios)")


def _rust_function_body_from_blanked(code, function_name):
    """Extract a Rust function body from source already blanked by the caller."""
    match = re.search(
        r"\b(?:pub(?:\s*\([^)]*\))?\s+)?(?:async\s+)?fn\s+%s"
        r"(?:\s*<[^>{}]*>)?\s*\(" % re.escape(function_name),
        code,
    )
    if not match:
        return None
    opening = code.find("{", match.end())
    if opening < 0:
        return None
    return _rust_braced_body_at(code, opening)


def _rust_function_body_span_from_blanked(code, function_name):
    """Return an aligned body span for a Rust function in blanked source."""
    match = re.search(
        r"\b(?:pub(?:\s*\([^)]*\))?\s+)?(?:async\s+)?fn\s+%s"
        r"(?:\s*<[^>{}]*>)?\s*\(" % re.escape(function_name),
        code,
    )
    if not match:
        return None
    opening = code.find("{", match.end())
    closing = _rust_matching_brace_end(code, opening)
    if closing is None:
        return None
    return opening + 1, closing


def _rust_let_binding_count(code, binding):
    """Count Rust let patterns that bind a name before their initializer."""
    if not binding:
        return 0
    return len(
        re.findall(
            r"\blet\b[^;=]*\b%s\b[^;=]*=" % re.escape(binding),
            code,
            re.DOTALL,
        )
    )


def _rust_item_body_from_blanked(code, item_kind, item_name):
    """Extract a Rust struct or enum body from source already blanked."""
    match = re.search(
        r"\b(?:pub(?:\s*\([^)]*\))?\s+)?%s\s+%s\b"
        % (re.escape(item_kind), re.escape(item_name)),
        code,
    )
    if not match:
        return None
    opening = code.find("{", match.end())
    if opening < 0:
        return None
    return _rust_braced_body_at(code, opening)


def _rust_utoipa_attribute_prefix_from_blanked(code, function_name):
    """Return the nearest utoipa::path attribute before a Rust function."""
    function = re.search(
        r"\bpub\s+async\s+fn\s+%s\s*\(" % re.escape(function_name), code
    )
    if not function:
        return None
    marker = code.rfind("utoipa", 0, function.start())
    opening = code.rfind("#[", 0, marker)
    if marker < 0 or opening < 0:
        return None
    prefix = code[opening:function.start()]
    return None if re.search(r"\bpub\s+async\s+fn\b", prefix) else prefix


def _rust_parenthesized_body_at(code, opening):
    """Extract a parenthesized expression from already blanked source code."""
    if opening < 0 or opening >= len(code) or code[opening] != "(":
        return None
    depth = 1
    index = opening + 1
    while index < len(code) and depth:
        if code[index] == "(":
            depth += 1
        elif code[index] == ")":
            depth -= 1
        index += 1
    return None if depth else code[opening + 1:index - 1]


def _rust_split_top_level_arguments(arguments):
    """Split already-blanked Rust call arguments without splitting nested calls."""
    items = []
    start = 0
    delimiters = {"(": ")", "[": "]", "{": "}"}
    stack = []
    for index, char in enumerate(arguments):
        if char in delimiters:
            stack.append(delimiters[char])
        elif stack and char == stack[-1]:
            stack.pop()
        elif char == "," and not stack:
            item = arguments[start:index].strip()
            if item:
                items.append(item)
            start = index + 1
    tail = arguments[start:].strip()
    if tail:
        items.append(tail)
    return items


def _rust_position_is_inside_loop(code, position):
    """Return whether position is nested in a Rust for/while/loop block."""
    stack = []
    for index, char in enumerate(code[:position]):
        if char == "{":
            prefix = code[max(0, index - 240):index]
            stack.append(
                bool(
                    re.search(
                        r"(?:\bfor\s+[^{};]+\s+in\s+[^{};]+|"
                        r"\bwhile\s+[^{};]+|\bloop)\s*$",
                        prefix,
                    )
                )
            )
        elif char == "}" and stack:
            stack.pop()
    return any(stack)


def _rust_brace_depth_at(code, position):
    """Return lexical brace depth before a position in already blanked Rust."""
    depth = 0
    for char in code[:position]:
        if char == "{":
            depth += 1
        elif char == "}":
            depth = max(0, depth - 1)
    return depth


def _rust_matching_brace_end(code, opening):
    """Return the closing-brace index for a blanked Rust block."""
    if opening < 0 or opening >= len(code) or code[opening] != "{":
        return None
    depth = 1
    index = opening + 1
    while index < len(code) and depth:
        if code[index] == "{":
            depth += 1
        elif code[index] == "}":
            depth -= 1
        index += 1
    return None if depth else index - 1


def _rust_if_else_branch_spans(code):
    """Yield simple if/else branch spans from already blanked Rust."""
    spans = []
    for match in re.finditer(r"\bif\b[^;{}]*\{", code):
        then_open = code.find("{", match.start())
        then_close = _rust_matching_brace_end(code, then_open)
        if then_close is None:
            continue
        after_then = then_close + 1
        while after_then < len(code) and code[after_then].isspace():
            after_then += 1
        if not re.match(r"else\s*\{", code[after_then:]):
            continue
        else_open = code.find("{", after_then)
        else_close = _rust_matching_brace_end(code, else_open)
        if else_close is not None:
            spans.append((then_open + 1, then_close, else_open + 1, else_close))
    return spans


def _rust_function_parameters_from_blanked(code, function_name):
    """Return a named Rust function's parameters from already blanked source."""
    match = re.search(
        r"\b(?:pub(?:\s*\([^)]*\))?\s+)?(?:async\s+)?fn\s+%s"
        r"(?:\s*<[^>{}]*>)?\s*\(" % re.escape(function_name),
        code,
    )
    if not match:
        return None
    # The signature regex ends at the real parameter-list opener. Starting
    # from match.start() would mistake the visibility in `pub(crate)` for the
    # function parameters.
    opening = match.end() - 1
    return _rust_parenthesized_body_at(code, opening)


def _rust_named_for_loop_body(code, binding, iterable):
    """Extract a simple `for binding in iterable` body from blanked Rust."""
    match = re.search(
        r"\bfor\s+%s\s+in\s+&?\s*%s"
        r"(?:\s*\.\s*(?:iter|into_iter)\s*\(\s*\))?\s*\{"
        % (re.escape(binding), re.escape(iterable)),
        code,
    )
    if not match:
        return None
    opening = code.find("{", match.start())
    return _rust_braced_body_at(code, opening)


def _rust_named_call_arguments(code, function_name):
    """Return `(position, arguments)` for calls in an already blanked body."""
    calls = []
    for match in re.finditer(r"\b%s\s*\(" % re.escape(function_name), code):
        opening = code.find("(", match.start())
        arguments = _rust_parenthesized_body_at(code, opening)
        if arguments is not None:
            calls.append((match.start(), _rust_split_top_level_arguments(arguments)))
    return calls


def _rust_named_call_result_is_propagated(code, function_name, position):
    """Recognize tail, `?`, or explicit-Err propagation for one Rust call."""
    del function_name
    opening = code.find("(", position)
    if opening < 0:
        return False
    depth = 1
    closing = opening + 1
    while closing < len(code) and depth:
        if code[closing] == "(":
            depth += 1
        elif code[closing] == ")":
            depth -= 1
        closing += 1
    if depth:
        return False
    suffix = code[closing:]
    if re.match(r"^\s*\.\s*await\s*\?\s*(?:;|$)", suffix):
        return True
    if re.fullmatch(r"\s*\.\s*await\s*", suffix):
        return True
    statement_end = suffix.find(";")
    if statement_end >= 0 and suffix[:statement_end].rstrip().endswith("?"):
        return True
    if re.fullmatch(r"\s*", suffix):
        return True
    statement_start = max(
        code.rfind(";", 0, position),
        code.rfind("{", 0, position),
        code.rfind("}", 0, position),
    )
    prefix = code[statement_start + 1 : position]
    if not re.search(r"\bmatch\s*$", prefix):
        return False
    match_open = re.match(r"^\s*\.\s*await\s*\{", suffix)
    if match_open is None:
        return False
    opening_brace = suffix.find("{", match_open.start())
    match_body = _rust_braced_body_at(suffix, opening_brace)
    return bool(
        match_body
        and re.search(
            r"\bErr\s*\([^)]*\)\s*=>[^}]*\b(?:return\s+)?Err\s*\(",
            match_body,
            re.DOTALL,
        )
    )


def _managed_projection_path_contract_errors(replay_source, inventory_source):
    """Return Task 7 replay/inventory projection-boundary violations."""

    errors = []
    replay_code = _blank_rust_non_code(replay_source)
    inventory_code = _blank_rust_non_code(inventory_source)
    replay_bodies = {}
    inventory_bodies = {}
    approved_raw_group_boundaries = {
        "build_runtime_group_map_entries",
        "collect_standalone_runtime_group_map_entries",
    }

    def cached_function_body(code, cache, function_name):
        if function_name not in cache:
            cache[function_name] = _rust_function_body_from_blanked(
                code, function_name
            )
        return cache[function_name]

    def delegated_raw_group_helper(
        code, cache, entry_body, allow_direct_standalone_fallback=False
    ):
        pending = [("entry", entry_body)]
        visited = set()
        while pending:
            caller, body = pending.pop()
            aliases = {
                match.group("alias"): match.group("target")
                for match in re.finditer(
                    r"\blet\s+(?:mut\s+)?(?P<alias>[A-Za-z_]\w*)\s*=\s*"
                    r"(?P<target>[A-Za-z_]\w*)\s*;",
                    body,
                )
            }

            def resolve_alias(name):
                seen = set()
                while name in aliases and name not in seen:
                    seen.add(name)
                    name = aliases[name]
                return name

            calls = set(
                re.findall(r"(?<![.!])\b([A-Za-z_]\w*)\s*\(", body)
            )
            calls = {resolve_alias(callee) for callee in calls}
            for callee in calls:
                if callee == "collect_standalone_runtime_group_map_entries":
                    if allow_direct_standalone_fallback and caller == "entry":
                        continue
                    return "%s -> %s" % (caller, callee)
                if callee in approved_raw_group_boundaries or callee in visited:
                    continue
                callee_body = cached_function_body(code, cache, callee)
                if callee_body is None:
                    continue
                visited.add(callee)
                if re.search(
                    r"\b[A-Za-z_]\w*\s*\.\s*groups\b", callee_body
                ):
                    return "%s -> %s" % (caller, callee)
                pending.append((callee, callee_body))
        return None

    path_specs = (
        (
            "fresh replay",
            replay_code,
            replay_bodies,
            "replay_state_from_snapshot_with_mode",
            "write_fresh_runtime_group_entries",
        ),
        (
            "pinned replay",
            replay_code,
            replay_bodies,
            "replay_state_to_pinned_maps_from_snapshot_with_mode",
            "write_pinned_runtime_group_entries",
        ),
        (
            "managed inventory",
            inventory_code,
            inventory_bodies,
            "validate_pinned_runtime_state_with_mode",
            None,
        ),
    )
    for label, code, cache, function_name, writer in path_specs:
        body = cached_function_body(code, cache, function_name)
        if body is None:
            errors.append("%s projection entry point is missing" % label)
            continue
        builder = re.search(
            r"\blet\s+(?P<mutable>mut\s+)?(?P<binding>[A-Za-z_]\w*)\s*=\s*"
            r"(?:match\s+)?build_runtime_group_map_entries\s*"
            r"\(\s*state\s*,\s*mode\s*,?\s*\)",
            body,
        )
        if builder is None:
            errors.append(
                "%s must bind the shared runtime group projection builder" % label
            )
        if re.search(r"\b[A-Za-z_]\w*\s*\.\s*groups\b", body):
            errors.append("%s must not iterate raw state.groups" % label)
        delegated = delegated_raw_group_helper(
            code,
            cache,
            body,
            allow_direct_standalone_fallback=writer is not None,
        )
        if delegated is not None:
            errors.append(
                "%s must not delegate raw state.groups through %s"
                % (label, delegated)
            )
        if writer is not None:
            standalone_fallback = "collect_standalone_runtime_group_map_entries"
            standalone_calls = _rust_named_call_arguments(body, standalone_fallback)
            standalone_guard = re.search(
                r"\bErr\s*\([^)]*\)\s+if\s+mode\s*==\s*"
                r"GroupProjectionMode\s*::\s*StandaloneCompatibility\s*=>\s*\{",
                body,
            )
            standalone_guard_body = (
                None
                if standalone_guard is None
                else _rust_braced_body_at(
                    body, body.find("{", standalone_guard.start())
                )
            )
            aliases_standalone_fallback = re.search(
                r"\blet\s+(?:mut\s+)?[A-Za-z_]\w*\s*=\s*"
                r"collect_standalone_runtime_group_map_entries\s*;",
                body,
            )
            if (
                len(standalone_calls) != 1
                or standalone_guard_body is None
                or len(
                    _rust_named_call_arguments(
                        standalone_guard_body, standalone_fallback
                    )
                )
                != 1
                or aliases_standalone_fallback is not None
            ):
                errors.append(
                    "%s must confine raw standalone fallback to StandaloneCompatibility"
                    % label
                )
            calls = _rust_named_call_arguments(body, writer)
            binding = builder.group("binding") if builder is not None else ""
            if len(calls) != 1 or not any(
                re.search(r"&\s*%s\b" % re.escape(binding), argument)
                for argument in (calls[0][1] if len(calls) == 1 else ())
            ):
                errors.append(
                    "%s must publish only the bound projection through %s"
                    % (label, writer)
                )
            if (
                builder is not None
                and len(calls) == 1
                and (
                    builder.group("mutable") is not None
                    or _rust_let_binding_count(body, binding) != 1
                    or calls[0][0] <= builder.end()
                    or _rust_brace_depth_at(body, calls[0][0]) != 0
                )
            ):
                errors.append(
                    "%s must preserve the bound projection until %s"
                    % (label, writer)
                )

    shared_builder = cached_function_body(
        replay_code, replay_bodies, "build_runtime_group_map_entries"
    )
    managed_arm = None
    if shared_builder is not None:
        managed_marker = re.search(
            r"GroupProjectionMode\s*::\s*Managed\s*=>\s*\{", shared_builder
        )
        if managed_marker is not None:
            managed_arm = _rust_braced_body_at(
                shared_builder, shared_builder.find("{", managed_marker.start())
            )
    if (
        managed_arm is None
        or managed_arm.count("compile_managed_group_projection") != 1
        or not re.search(
            r"\bcompile_managed_group_projection\s*\(\s*state\s*\)",
            managed_arm or "",
        )
    ):
        errors.append(
            "managed runtime group builder must compile the managed projection"
        )
    if managed_arm is not None and (
        re.search(r"\b[A-Za-z_]\w*\s*\.\s*groups\b", managed_arm)
        or delegated_raw_group_helper(
            replay_code, replay_bodies, managed_arm
        )
        is not None
    ):
        errors.append(
            "managed runtime group builder must not iterate or delegate raw state.groups"
        )

    compiled_projection = (
        None
        if managed_arm is None
        else re.search(
            r"\blet\s+(?:mut\s+)?(?P<binding>[A-Za-z_]\w*)\s*=\s*"
            r"compile_managed_group_projection\s*\(\s*state\s*\)\s*\?\s*;",
            managed_arm,
        )
    )
    derived_bindings = {}
    if compiled_projection is not None:
        projection_binding = compiled_projection.group("binding")
        for field in ("general", "acl_src", "acl_dst"):
            derived = re.search(
                r"\blet\s+(?:mut\s+)?(?P<binding>[A-Za-z_]\w*)\s*=\s*"
                r"%s\s*\.\s*%s\s*\.\s*iter\s*\(\s*\)"
                r"[^;]*\.\s*collect(?:\s*::\s*<[^;]+>)?\s*\(\s*\)\s*;"
                % (re.escape(projection_binding), field),
                managed_arm,
                re.DOTALL,
            )
            if derived is not None:
                derived_bindings[field] = derived.group("binding")

    runtime_entries = (
        None
        if managed_arm is None
        else re.search(
            r"\bOk\s*\(\s*RuntimeGroupMapEntries\s*\{", managed_arm
        )
    )
    runtime_fields = {}
    runtime_entries_is_tail = False
    if runtime_entries is not None:
        opening = managed_arm.find("{", runtime_entries.start())
        closing = _rust_matching_brace_end(managed_arm, opening)
        if closing is not None:
            for item in _rust_split_top_level_arguments(
                managed_arm[opening + 1 : closing]
            ):
                if ":" in item:
                    name, value = item.split(":", 1)
                else:
                    name = value = item
                runtime_fields[re.sub(r"\s+", "", name)] = re.sub(
                    r"\s+", "", value
                )
            runtime_entries_is_tail = bool(
                re.fullmatch(r"\s*\)\s*", managed_arm[closing + 1 :])
            )

    expected_runtime_fields = {}
    if len(derived_bindings) == 3:
        general = derived_bindings["general"]
        expected_runtime_fields = {
            "general_src": "%s.clone()" % general,
            "general_dst": general,
            "acl_src": derived_bindings["acl_src"],
            "acl_dst": derived_bindings["acl_dst"],
        }
    bindings_are_not_reassigned = compiled_projection is not None
    if compiled_projection is not None:
        projection_binding = compiled_projection.group("binding")
        bindings_are_not_reassigned = not re.search(
            r"\b(?:let\s+(?:mut\s+)?%s\b|%s\s*=)"
            % (re.escape(projection_binding), re.escape(projection_binding)),
            managed_arm[compiled_projection.end() :],
        )
    for binding in derived_bindings.values():
        derived_assignment = re.search(
            r"\blet\s+(?:mut\s+)?%s\b[^;]*;" % re.escape(binding),
            managed_arm,
            re.DOTALL,
        )
        if derived_assignment is None or re.search(
            r"\b(?:let\s+(?:mut\s+)?%s\b|%s\s*=)"
            % (re.escape(binding), re.escape(binding)),
            managed_arm[derived_assignment.end() : runtime_entries.start()]
            if runtime_entries is not None
            else managed_arm[derived_assignment.end() :],
        ):
            bindings_are_not_reassigned = False
    if (
        compiled_projection is None
        or len(derived_bindings) != 3
        or not runtime_entries_is_tail
        or runtime_fields != expected_runtime_fields
        or not bindings_are_not_reassigned
    ):
        errors.append(
            "managed runtime group builder must return entries derived from the compiled managed projection"
        )

    managed_classifier = cached_function_body(
        inventory_code, inventory_bodies, "classify_managed_inventory_capture"
    )
    compiled = (
        None
        if managed_classifier is None
        else re.search(
            r"\blet\s+(?P<binding>[A-Za-z_]\w*)\s*=\s*match\s+"
            r"compile_managed_group_projection\s*\(\s*state\s*\)",
            managed_classifier,
        )
    )
    if compiled is None:
        errors.append(
            "managed inventory classifier must compile the committed managed projection"
        )
    drift_calls = (
        []
        if managed_classifier is None
        else _rust_named_call_arguments(managed_classifier, "plan_projection_drift")
    )
    compiled_binding = compiled.group("binding") if compiled is not None else ""
    expected_drift_arguments = [
        "captured",
        "&%s" % compiled_binding,
        "&%s" % compiled_binding,
    ]
    if len(drift_calls) != 1 or [
        re.sub(r"\s+", "", argument) for argument in drift_calls[0][1]
    ] != expected_drift_arguments:
        errors.append(
            "managed inventory classifier must plan drift from the compiled committed projection"
        )
    if len(drift_calls) == 1 and not _rust_named_call_result_is_propagated(
        managed_classifier,
        "plan_projection_drift",
        drift_calls[0][0],
    ):
        errors.append(
            "managed inventory classifier must return drift from the compiled committed projection"
        )
    if (
        compiled is not None
        and len(drift_calls) == 1
        and (
            _rust_let_binding_count(managed_classifier, compiled_binding) != 1
            or drift_calls[0][0] <= compiled.end()
            or _rust_brace_depth_at(
                managed_classifier, drift_calls[0][0]
            )
            != 0
        )
    ):
        errors.append(
            "managed inventory classifier must preserve the compiled committed projection until drift planning"
        )
    return errors


def _run_managed_projection_path_mutation_self_tests():
    safe_replay = r"""
        fn collect_standalone_runtime_group_map_entries(state: &State) {
            for group in state.groups.values() { collect(group); }
        }
        fn build_runtime_group_map_entries(state: &State, mode: Mode) {
            match mode {
                GroupProjectionMode::StandaloneCompatibility => {
                    collect_standalone_runtime_group_map_entries(state)
                }
                GroupProjectionMode::Managed => {
                    let projection = compile_managed_group_projection(state)?;
                    let general = projection.general.iter().cloned().collect::<Vec<_>>();
                    let acl_src = projection.acl_src.iter().cloned().collect();
                    let acl_dst = projection.acl_dst.iter().cloned().collect();
                    Ok(RuntimeGroupMapEntries {
                        general_src: general.clone(),
                        general_dst: general,
                        acl_src,
                        acl_dst,
                    })
                }
            }
        }
        fn write_fresh_runtime_group_entries(entries: &Entries) { publish(entries); }
        fn write_pinned_runtime_group_entries(entries: &Entries) { publish(entries); }

        fn replay_state_from_snapshot_with_mode(state: &State, mode: Mode) {
            let fresh_entries = match build_runtime_group_map_entries(state, mode) {
                Ok(entries) => entries,
                Err(error) if mode == GroupProjectionMode::StandaloneCompatibility => {
                    collect_standalone_runtime_group_map_entries(state)
                }
                Err(error) => return Err(error),
            };
            write_fresh_runtime_group_entries(&fresh_entries);
        }

        fn replay_state_to_pinned_maps_from_snapshot_with_mode(state: &State, mode: Mode) {
            let pinned_entries = match build_runtime_group_map_entries(state, mode) {
                Ok(entries) => entries,
                Err(error) if mode == GroupProjectionMode::StandaloneCompatibility => {
                    collect_standalone_runtime_group_map_entries(state)
                }
                Err(error) => return Err(error),
            };
            write_pinned_runtime_group_entries(&pinned_entries);
        }
    """
    safe_inventory = r"""
        fn build_runtime_group_map_entries(state: &State, mode: Mode) { compile(state, mode) }
        fn capture_runtime_group_map_entries() { capture() }
        fn validate_strict_pinned_runtime_state() { validate() }
        fn classify_standalone_inventory_capture() { classify() }
        fn classify_managed_inventory_capture(
            state: &State,
            captured: &Captured,
            strict_result: Result<(), String>,
        ) {
            if let Err(error) = strict_result {
                return ProjectionDrift::Fatal(error);
            }
            let committed = match compile_managed_group_projection(state) {
                Ok(projection) => projection,
                Err(error) => return ProjectionDrift::Fatal(error),
            };
            plan_projection_drift(captured, &committed, &committed)
        }

        fn validate_pinned_runtime_state_with_mode(state: &State, mode: Mode) {
            let expected_entries = match build_runtime_group_map_entries(state, mode) {
                Ok(entries) => entries,
                Err(error) => return ProjectionDrift::Fatal(error),
            };
            let captured = capture_runtime_group_map_entries();
            let strict_result = validate_strict_pinned_runtime_state();
            match mode {
                GroupProjectionMode::StandaloneCompatibility => {
                    classify_standalone_inventory_capture(&captured, &expected_entries, strict_result)
                }
                GroupProjectionMode::Managed => {
                    classify_managed_inventory_capture(state, &captured, strict_result)
                }
            }
        }
    """
    safe_errors = _managed_projection_path_contract_errors(
        safe_replay, safe_inventory
    )
    if safe_errors:
        raise SystemExit(
            "ERROR: managed projection path checker rejected safe source: %s"
            % safe_errors
        )

    def mutate_body(source, function_name, old, new):
        body = _rust_function_body_raw(source, function_name)
        if body is None or body.count(old) != 1:
            raise SystemExit(
                "ERROR: Task 7 projection mutation fixture anchor is missing: %s %s"
                % (function_name, old)
            )
        return source.replace(body, body.replace(old, new, 1), 1)

    path_specs = (
        (
            "fresh replay",
            "replay_state_from_snapshot_with_mode",
            "fresh_entries",
            "write_fresh_runtime_group_entries(&fresh_entries);",
            "replay",
        ),
        (
            "pinned replay",
            "replay_state_to_pinned_maps_from_snapshot_with_mode",
            "pinned_entries",
            "write_pinned_runtime_group_entries(&pinned_entries);",
            "replay",
        ),
        (
            "managed inventory",
            "validate_pinned_runtime_state_with_mode",
            "expected_entries",
            None,
            "inventory",
        ),
    )
    mutants = []
    delegated_helpers = r"""
        fn delegated_raw_group_projection(state: &State) {
            raw_group_projection(state);
        }
        fn raw_group_projection(snapshot: &State) {
            for group in snapshot.groups.values() { publish(group); }
        }
    """
    for label, function_name, binding, writer_call, source_kind in path_specs:
        replay = safe_replay
        inventory = safe_inventory
        selected = replay if source_kind == "replay" else inventory
        direct = mutate_body(
            selected,
            function_name,
            "\n            let %s" % binding,
            "\n            for group in state.groups.values() { publish(group); }"
            "\n            let %s" % binding,
        )
        mutants.append(
            (
                "%s direct raw-group" % label,
                direct if source_kind == "replay" else replay,
                direct if source_kind == "inventory" else inventory,
                "%s must not iterate raw state.groups" % label,
            )
        )
        delegated = mutate_body(
            selected + delegated_helpers,
            function_name,
            "\n            let %s" % binding,
            "\n            let raw_projection = delegated_raw_group_projection;"
            "\n            raw_projection(state);"
            "\n            let %s" % binding,
        )
        mutants.append(
            (
                "%s delegated raw-group alias" % label,
                delegated if source_kind == "replay" else replay,
                delegated if source_kind == "inventory" else inventory,
                "%s must not delegate raw state.groups" % label,
            )
        )
        multi_level_delegated = mutate_body(
            selected + delegated_helpers,
            function_name,
            "\n            let %s" % binding,
            "\n            let first_projection = delegated_raw_group_projection;"
            "\n            let second_projection = first_projection;"
            "\n            second_projection(state);"
            "\n            let %s" % binding,
        )
        mutants.append(
            (
                "%s multi-level delegated raw-group alias" % label,
                multi_level_delegated if source_kind == "replay" else replay,
                multi_level_delegated if source_kind == "inventory" else inventory,
                "%s must not delegate raw state.groups" % label,
            )
        )
        missing_builder = mutate_body(
            selected,
            function_name,
            "build_runtime_group_map_entries(state, mode)",
            "raw_runtime_group_map_entries(state)",
        )
        mutants.append(
            (
                "%s missing shared builder" % label,
                missing_builder if source_kind == "replay" else replay,
                missing_builder if source_kind == "inventory" else inventory,
                "%s must bind the shared runtime group projection builder" % label,
            )
        )
        if writer_call is not None:
            unguarded_fallback = mutate_body(
                selected,
                function_name,
                "\n            let %s" % binding,
                "\n            let raw_projection = "
                "collect_standalone_runtime_group_map_entries;"
                "\n            raw_projection(state);"
                "\n            let %s" % binding,
            )
            mutants.append(
                (
                    "%s aliases standalone raw fallback" % label,
                    unguarded_fallback,
                    inventory,
                    "%s must confine raw standalone fallback" % label,
                )
            )
            missing_writer = mutate_body(
                selected, function_name, writer_call, "let _ = &%s;" % binding
            )
            mutants.append(
                (
                    "%s missing projection writer" % label,
                    missing_writer,
                    inventory,
                    "%s must publish only the bound projection" % label,
                )
            )
            shadowed_writer_projection = mutate_body(
                selected,
                function_name,
                writer_call,
                "let %s = RuntimeGroupMapEntries::default();\n            %s"
                % (binding, writer_call),
            )
            mutants.append(
                (
                    "%s shadows the bound projection before writing" % label,
                    shadowed_writer_projection,
                    inventory,
                    "%s must preserve the bound projection until %s"
                    % (label, writer_call.split("(", 1)[0]),
                )
            )

    delegated_builder = mutate_body(
        safe_replay + delegated_helpers,
        "build_runtime_group_map_entries",
        "compile_managed_group_projection(state)",
        "delegated_raw_group_projection(state)",
    )
    mutants.append(
        (
            "managed shared builder delegates raw groups",
            delegated_builder,
            safe_inventory,
            "managed runtime group builder must compile the managed projection",
        )
    )
    discarded_builder_projection = mutate_body(
        safe_replay,
        "build_runtime_group_map_entries",
        """let projection = compile_managed_group_projection(state)?;
                    let general = projection.general.iter().cloned().collect::<Vec<_>>();
                    let acl_src = projection.acl_src.iter().cloned().collect();
                    let acl_dst = projection.acl_dst.iter().cloned().collect();
                    Ok(RuntimeGroupMapEntries {
                        general_src: general.clone(),
                        general_dst: general,
                        acl_src,
                        acl_dst,
                    })""",
        """let _projection = compile_managed_group_projection(state)?;
                    Ok(RuntimeGroupMapEntries::default())""",
    )
    mutants.append(
        (
            "managed shared builder discards compiled projection",
            discarded_builder_projection,
            safe_inventory,
            "managed runtime group builder must return entries derived from the compiled managed projection",
        )
    )
    missing_managed_compile = mutate_body(
        safe_inventory,
        "classify_managed_inventory_capture",
        "compile_managed_group_projection(state)",
        "raw_managed_projection(state)",
    )
    mutants.append(
        (
            "managed inventory classifier bypasses projection compiler",
            safe_replay,
            missing_managed_compile,
            "managed inventory classifier must compile the committed managed projection",
        )
    )
    discarded_managed_compile = mutate_body(
        safe_inventory,
        "classify_managed_inventory_capture",
        "plan_projection_drift(captured, &committed, &committed)",
        "plan_projection_drift(captured, &default_projection(), &default_projection())",
    )
    mutants.append(
        (
            "managed inventory discards compiled projection",
            safe_replay,
            discarded_managed_compile,
            "managed inventory classifier must plan drift from the compiled committed projection",
        )
    )
    ignored_managed_drift = mutate_body(
        safe_inventory,
        "classify_managed_inventory_capture",
        "plan_projection_drift(captured, &committed, &committed)",
        "let _drift = plan_projection_drift(captured, &committed, &committed);\n"
        "            ProjectionDrift::Clean",
    )
    mutants.append(
        (
            "managed inventory ignores compiled projection drift",
            safe_replay,
            ignored_managed_drift,
            "managed inventory classifier must return drift from the compiled committed projection",
        )
    )
    shadowed_managed_projection = mutate_body(
        safe_inventory,
        "classify_managed_inventory_capture",
        "plan_projection_drift(captured, &committed, &committed)",
        "let committed = ManagedGroupProjection::default();\n"
        "            plan_projection_drift(captured, &committed, &committed)",
    )
    mutants.append(
        (
            "managed inventory shadows the compiled projection",
            safe_replay,
            shadowed_managed_projection,
            "managed inventory classifier must preserve the compiled committed projection until drift planning",
        )
    )

    for label, replay, inventory, expected in mutants:
        errors = _managed_projection_path_contract_errors(replay, inventory)
        if not any(expected in error for error in errors):
            raise SystemExit(
                "ERROR: managed projection path checker accepted %s mutation: %s"
                % (label, errors)
            )
    print(
        "Managed replay/inventory projection mutation self-tests: OK (%d scenarios)"
        % (len(mutants) + 1)
    )


def _managed_replaced_compensation_contract_errors(
    control_plane_source, control_code=None
):
    """Return Task 7 complete-Replaced-compensation violations."""

    errors = []
    if control_code is None:
        control_code = _blank_rust_non_code(control_plane_source)
    mutation_body = _rust_item_body_from_blanked(
        control_code, "enum", "SharedNetworkMutation"
    )
    if mutation_body is None or not re.search(
        r"\bReplaced\s*\{[^{}]*\bold_group_id\s*:[^,}]+,"
        r"[^{}]*\bnew_group_id\s*:[^,}]+,?[^{}]*\}",
        mutation_body,
        re.DOTALL,
    ):
        errors.append(
            "managed general replacement must retain its complete old/new preimage"
        )

    compensation_body = _rust_function_body_from_blanked(
        control_code, "shared_network_compensation"
    )
    replaced_arm = (
        None
        if compensation_body is None
        else re.search(
            r"SharedNetworkMutation\s*::\s*Replaced\s*\{"
            r"(?P<input>[^{}]*)\}\s*=>\s*"
            r"SharedNetworkMutation\s*::\s*Replaced\s*\{"
            r"(?P<output>[^{}]*)\}",
            compensation_body,
            re.DOTALL,
        )
    )
    input_fields = (
        []
        if replaced_arm is None
        else [
            re.sub(r"\s+", "", field)
            for field in _rust_split_top_level_arguments(
                replaced_arm.group("input")
            )
        ]
    )
    if input_fields != [
        "direction",
        "cidr",
        "old_group_id",
        "new_group_id",
    ]:
        errors.append("Replaced compensation must bind its old/new preimage")
    output_fields = (
        []
        if replaced_arm is None
        else [
            re.sub(r"\s+", "", field)
            for field in _rust_split_top_level_arguments(
                replaced_arm.group("output")
            )
        ]
    )
    if output_fields[:2] != ["direction", "cidr:cidr.clone()"]:
        errors.append(
            "Replaced compensation must preserve direction and cidr exactly"
        )
    if output_fields[2:] != [
        "old_group_id:*new_group_id",
        "new_group_id:*old_group_id",
    ]:
        errors.append(
            "Replaced compensation must swap old_group_id and new_group_id exactly"
        )

    plan_body = _rust_function_body_from_blanked(
        control_code, "managed_acl_publication_compensations"
    )
    plan_parameters = _rust_function_parameters_from_blanked(
        control_code, "managed_acl_publication_compensations"
    )
    normalized_parameters = (
        []
        if plan_parameters is None
        else [
            re.sub(r"\s+", "", parameter)
            for parameter in _rust_split_top_level_arguments(plan_parameters)
        ]
    )
    plan_code = plan_body or ""
    restore_active_bank = re.search(
        r"\bif\s+phase\s*==\s*"
        r"ManagedAclPublicationFailurePhase\s*::\s*Persist\s*\{\s*"
        r"compensations\s*\.\s*push\s*\(\s*"
        r"ManagedAclPublicationCompensation\s*::\s*RestoreActiveBank"
        r"\s*\)\s*;\s*\}",
        plan_code,
        re.DOTALL,
    )
    parameters_are_original = (
        normalized_parameters
        == [
            "mutations:&[SharedNetworkMutation]",
            "phase:ManagedAclPublicationFailurePhase",
        ]
        and _rust_let_binding_count(plan_code, "mutations") == 0
        and _rust_let_binding_count(plan_code, "phase") == 0
        and not re.search(
            r"\b(?:mutations|phase)\s*=(?!=)", plan_code
        )
        and not re.search(r"&\s*mut\s+(?:mutations|phase)\b", plan_code)
        and restore_active_bank is not None
    )
    if not parameters_are_original:
        errors.append(
            "managed ACL failure compensation must consume the original mutations and phase parameters"
        )

    compensation_binding = re.search(
        r"\blet\s+mut\s+compensations\s*=\s*"
        r"Vec\s*::\s*new\s*\(\s*\)\s*;",
        plan_code,
    )
    compensation_binding_is_unique = (
        compensation_binding is not None
        and _rust_brace_depth_at(plan_code, compensation_binding.start()) == 0
        and _rust_let_binding_count(plan_code, "compensations") == 1
        and not re.search(
            r"\bcompensations\s*=(?!=)",
            plan_code[compensation_binding.end() :],
        )
        and not re.search(r"&\s*mut\s+compensations\b", plan_code)
    )
    if not compensation_binding_is_unique:
        errors.append(
            "managed ACL failure compensation must preserve one compensation vector through return"
        )

    general_plan = (
        None
        if plan_body is None
        else re.search(
            r"\bcompensations\s*\.\s*extend\s*\(\s*"
            r"mutations\s*\.\s*iter\s*\(\s*\)\s*\.\s*rev\s*\(\s*\)\s*"
            r"\.\s*map\s*\(\s*\|\s*mutation\s*\|\s*\{?\s*"
            r"ManagedAclPublicationCompensation\s*::\s*RestoreGeneral\s*\(\s*"
            r"shared_network_compensation\s*\(\s*mutation\s*\)\s*,?\s*\)\s*,?\s*"
            r"\}?\s*\)\s*\)\s*;",
            plan_body,
            re.DOTALL,
        )
    )
    if (
        general_plan is None
        or _rust_brace_depth_at(plan_body, general_plan.start()) != 0
        or plan_body.count("ManagedAclPublicationCompensation::RestoreGeneral") != 1
        or plan_body.count("shared_network_compensation") != 1
    ):
        errors.append(
            "managed ACL failure compensation must restore every general preimage in reverse order"
        )
    active_bank_is_preserved = False
    if (
        compensation_binding is not None
        and restore_active_bank is not None
        and general_plan is not None
        and compensation_binding.end()
        <= restore_active_bank.start()
        < restore_active_bank.end()
        <= general_plan.start()
    ):
        bank_prefix = plan_code[
            compensation_binding.end() : general_plan.start()
        ]
        bank_guard_start = (
            restore_active_bank.start() - compensation_binding.end()
        )
        bank_guard_end = restore_active_bank.end() - compensation_binding.end()
        active_bank_is_preserved = not (
            bank_prefix[:bank_guard_start] + bank_prefix[bank_guard_end:]
        ).strip()
    if not active_bank_is_preserved:
        errors.append(
            "managed ACL failure compensation must preserve RestoreActiveBank until general rollback"
        )
    if general_plan is not None and not re.fullmatch(
        r"\s*compensations\s*", plan_body[general_plan.end() :]
    ):
        errors.append(
            "managed ACL failure compensation must return the complete reverse-order plan unchanged"
        )
    if general_plan is not None and re.search(
        r"\b(?:return|break|continue)\b", plan_body[: general_plan.start()]
    ):
        errors.append(
            "managed ACL failure compensation must not bypass the general reverse-order plan"
        )
    return errors


def _run_managed_replaced_compensation_mutation_self_tests():
    general_plan = r"""        compensations.extend(mutations.iter().rev().map(|mutation| {
            ManagedAclPublicationCompensation::RestoreGeneral(
                shared_network_compensation(mutation),
            )
        }));"""
    safe = r"""
        enum SharedNetworkMutation {
            Added { direction: &'static str, cidr: String, group_id: u32 },
            Deleted { direction: &'static str, cidr: String, group_id: u32 },
            Replaced {
                direction: &'static str,
                cidr: String,
                old_group_id: u32,
                new_group_id: u32,
            },
        }
        enum ManagedAclPublicationCompensation {
            RestoreActiveBank,
            RestoreGeneral(SharedNetworkMutation),
        }
        enum ManagedAclPublicationFailurePhase { General, Persist }

        fn shared_network_compensation(
            mutation: &SharedNetworkMutation,
        ) -> SharedNetworkMutation {
            match mutation {
                SharedNetworkMutation::Replaced {
                    direction,
                    cidr,
                    old_group_id,
                    new_group_id,
                } => SharedNetworkMutation::Replaced {
                    direction,
                    cidr: cidr.clone(),
                    old_group_id: *new_group_id,
                    new_group_id: *old_group_id,
                },
                _ => mutation.clone(),
            }
        }

        fn managed_acl_publication_compensations(
            mutations: &[SharedNetworkMutation],
            phase: ManagedAclPublicationFailurePhase,
        ) -> Vec<ManagedAclPublicationCompensation> {
            let mut compensations = Vec::new();
            if phase == ManagedAclPublicationFailurePhase::Persist {
                compensations.push(ManagedAclPublicationCompensation::RestoreActiveBank);
            }
%s
            compensations
        }
    """ % general_plan
    safe_errors = _managed_replaced_compensation_contract_errors(safe)
    if safe_errors:
        raise SystemExit(
            "ERROR: Replaced compensation checker rejected safe source: %s"
            % safe_errors
        )

    mutants = (
        (
            "Replaced input preimage bindings are omitted",
            safe.replace(
                """direction,
                    cidr,
                    old_group_id,
                    new_group_id,""",
                "..",
                1,
            ),
            "Replaced compensation must bind its old/new preimage",
        ),
        (
            "Replaced direction is replaced with a constant",
            safe.replace(
                """direction,
                    cidr: cidr.clone(),""",
                """direction: "egress",
                    cidr: cidr.clone(),""",
                1,
            ),
            "Replaced compensation must preserve direction and cidr exactly",
        ),
        (
            "Replaced cidr is replaced with a constant",
            safe.replace(
                "cidr: cidr.clone(),",
                'cidr: "0.0.0.0/0".to_string(),',
                1,
            ),
            "Replaced compensation must preserve direction and cidr exactly",
        ),
        (
            "Replaced old preimage is not swapped",
            safe.replace(
                "old_group_id: *new_group_id,",
                "old_group_id: *old_group_id,",
                1,
            ),
            "must swap old_group_id and new_group_id",
        ),
        (
            "Replaced new preimage is not swapped",
            safe.replace(
                "new_group_id: *old_group_id,",
                "new_group_id: *new_group_id,",
                1,
            ),
            "must swap old_group_id and new_group_id",
        ),
        (
            "aliased compensation bypass",
            safe.replace(
                general_plan,
                r"""        let _required_marker = shared_network_compensation;
        let compensation_alias = passthrough_general;
        compensations.extend(mutations.iter().rev().map(|mutation| {
            ManagedAclPublicationCompensation::RestoreGeneral(compensation_alias(mutation))
        }));""",
                1,
            )
            + r"""
        fn passthrough_general(mutation: &SharedNetworkMutation) -> SharedNetworkMutation {
            mutation.clone()
        }
        """,
            "must restore every general preimage in reverse order",
        ),
        (
            "general preimage compensation removed",
            safe.replace(
                general_plan,
                "        let _required_marker = shared_network_compensation;\n"
                "        let _ = mutations;",
                1,
            ),
            "must restore every general preimage in reverse order",
        ),
        (
            "general preimage compensation is cleared before return",
            safe.replace(
                general_plan,
                general_plan + "\n        compensations.clear();",
                1,
            ),
            "managed ACL failure compensation must return the complete reverse-order plan unchanged",
        ),
        (
            "active-bank compensation is cleared before general planning",
            safe.replace(
                general_plan,
                "        compensations.clear();\n" + general_plan,
                1,
            ),
            "managed ACL failure compensation must preserve RestoreActiveBank until general rollback",
        ),
        (
            "active-bank compensation is popped before general planning",
            safe.replace(
                general_plan,
                "        let _ = compensations.pop();\n" + general_plan,
                1,
            ),
            "managed ACL failure compensation must preserve RestoreActiveBank until general rollback",
        ),
        (
            "general preimage compensation can return before planning",
            safe.replace(
                general_plan,
                "        if phase == ManagedAclPublicationFailurePhase::General {\n"
                "            return compensations;\n"
                "        }\n"
                + general_plan,
                1,
            ),
            "managed ACL failure compensation must not bypass the general reverse-order plan",
        ),
        (
            "general preimage mutations parameter is shadowed",
            safe.replace(
                general_plan,
                "        let mutations: &[SharedNetworkMutation] = &[];\n"
                + general_plan,
                1,
            ),
            "managed ACL failure compensation must consume the original mutations and phase parameters",
        ),
        (
            "general preimage phase parameter is shadowed",
            safe.replace(
                "        let mut compensations = Vec::new();",
                "        let mut compensations = Vec::new();\n"
                "        let phase = ManagedAclPublicationFailurePhase::General;",
                1,
            ),
            "managed ACL failure compensation must consume the original mutations and phase parameters",
        ),
        (
            "compensation vector is rebuilt before general planning",
            safe.replace(
                general_plan,
                "        let mut compensations = Vec::new();\n" + general_plan,
                1,
            ),
            "managed ACL failure compensation must preserve one compensation vector through return",
        ),
    )
    for label, mutant, expected in mutants:
        errors = _managed_replaced_compensation_contract_errors(mutant)
        if not any(expected in error for error in errors):
            raise SystemExit(
                "ERROR: Replaced compensation checker accepted %s mutation: %s"
                % (label, errors)
            )
    print(
        "Managed Replaced compensation mutation self-tests: OK (%d scenarios)"
        % (len(mutants) + 1)
    )


def _managed_acl_apply_profile_log_contract_errors(neutron_api_source):
    """Require exact repair evidence in both managed ACL profile logs."""

    code = _blank_rust_non_code(neutron_api_source)
    apply_span = _rust_function_body_span_from_blanked(
        code, "reconcile_neutron_acl"
    )
    if apply_span is None:
        return [
            "managed ACL apply profile logs must bind "
            "selector_repair_performed from replace_report exactly once "
            "in both bypass and enforced branches"
        ]
    apply_start, apply_end = apply_span
    apply_code = code[apply_start:apply_end]
    apply_source = neutron_api_source[apply_start:apply_end]
    initial_guard = re.match(
        r"\s*if\s+!\s*port_manages_acl\s*\(\s*port\s*\)\s*\{",
        apply_code,
    )
    initial_guard_end = None
    initial_guard_is_exact = False
    if initial_guard is not None:
        initial_guard_open = apply_code.find("{", initial_guard.start())
        initial_guard_close = _rust_matching_brace_end(
            apply_code, initial_guard_open
        )
        if initial_guard_close is not None:
            initial_guard_body = re.sub(
                r"\s+",
                "",
                apply_code[initial_guard_open + 1 : initial_guard_close],
            )
            initial_guard_is_exact = initial_guard_body == (
                "returnOk(NeutronAclReconcileOutcome::default());"
            )
            initial_guard_end = initial_guard_close + 1

    def has_top_level_control_exit(region_code):
        return any(
            _rust_brace_depth_at(region_code, control.start()) == 0
            for control in re.finditer(
                r"\b(?:return|break|continue)\b", region_code
            )
        )

    def profile_calls(region_code, region_source, direct_only=False):
        calls = []
        for invocation in re.finditer(r"\binfo\s*!\s*\(", region_code):
            if direct_only and _rust_brace_depth_at(
                region_code, invocation.start()
            ) != 0:
                continue
            if direct_only:
                prefix = region_code[: invocation.start()]
                if has_top_level_control_exit(prefix):
                    continue
            opening = region_code.find("(", invocation.start())
            call_code = _rust_parenthesized_body_at(region_code, opening)
            if call_code is None:
                continue
            closing = opening + 1 + len(call_code)
            call_source = region_source[opening + 1 : closing]
            if not re.search(
                r'(?:^|,)\s*"neutron_acl_apply_profile"\s*,?\s*$',
                call_source,
                re.DOTALL,
            ):
                continue
            calls.append((call_code, call_source))
        return calls

    def valid_profile_call(call, expected_status):
        call_code, call_source = call
        statuses = []
        for status in re.finditer(r"\bstatus\s*=", call_code):
            value = re.match(
                r'\s*"(?P<value>bypass|enforced)"\s*,',
                call_source[status.end() :],
            )
            if value is not None:
                statuses.append(value.group("value"))
        exact_binding = re.compile(
            r"\bselector_repair_performed\s*=\s*"
            r"replace_report\s*\.\s*selector_repair_performed\s*,"
        )
        any_binding = re.compile(r"\bselector_repair_performed\s*=")
        return (
            statuses == [expected_status]
            and len(exact_binding.findall(call_code)) == 1
            and len(any_binding.findall(call_code)) == 1
        )

    bypass_guards = [
        guard
        for guard in re.finditer(
            r"\bif\s+plan\s*\.\s*policies\s*\.\s*is_empty\s*"
            r"\(\s*\)\s*\{",
            apply_code,
        )
        if _rust_brace_depth_at(apply_code, guard.start()) == 0
    ]
    valid_candidates = []
    for guard in bypass_guards:
        if (
            not initial_guard_is_exact
            or initial_guard_end is None
            or guard.start() <= initial_guard_end
            or re.search(
                r"\b(?:return|break|continue)\b",
                apply_code[initial_guard_end : guard.start()],
            )
        ):
            continue
        if has_top_level_control_exit(apply_code[: guard.start()]):
            continue
        bypass_open = apply_code.find("{", guard.start())
        bypass_close = _rust_matching_brace_end(apply_code, bypass_open)
        after_bypass = None if bypass_close is None else bypass_close + 1
        while (
            after_bypass is not None
            and after_bypass < len(apply_code)
            and apply_code[after_bypass].isspace()
        ):
            after_bypass += 1
        enforced_open = (
            -1
            if after_bypass is None
            or re.match(r"else\s*\{", apply_code[after_bypass:]) is None
            else apply_code.find("{", after_bypass)
        )
        enforced_close = _rust_matching_brace_end(apply_code, enforced_open)
        if bypass_close is None or enforced_close is None:
            continue
        bypass_calls = profile_calls(
            apply_code[bypass_open + 1 : bypass_close],
            apply_source[bypass_open + 1 : bypass_close],
            direct_only=True,
        )
        enforced_calls = profile_calls(
            apply_code[enforced_open + 1 : enforced_close],
            apply_source[enforced_open + 1 : enforced_close],
            direct_only=True,
        )
        if (
            len(bypass_calls) == 1
            and len(enforced_calls) == 1
            and valid_profile_call(bypass_calls[0], "bypass")
            and valid_profile_call(enforced_calls[0], "enforced")
        ):
            valid_candidates.append(guard)
    all_profile_calls = profile_calls(apply_code, apply_source)
    valid = len(all_profile_calls) == 2 and len(valid_candidates) == 1
    source_bindings = list(
        re.finditer(
            r"\blet\s+(?P<mutable>mut\s+)?replace_report\s*=\s*"
            r"state\s*\.\s*control_plane\s*\.\s*replace_owned_acl\s*\(",
            apply_code,
        )
    )
    source_valid = (
        initial_guard_is_exact
        and len(source_bindings) == 1
        and len(valid_candidates) == 1
    )
    if source_valid:
        source_binding = source_bindings[0]
        call_open = source_binding.end() - 1
        call_body = _rust_parenthesized_body_at(apply_code, call_open)
        call_close = (
            None if call_body is None else call_open + 1 + len(call_body)
        )
        binding_end = None
        if call_close is not None:
            after_call = apply_code[call_close + 1 :]
            await_match = re.match(r"\s*\.\s*await\b", after_call)
            if await_match is not None:
                cursor = await_match.end()
                map_err = re.match(
                    r"\s*\.\s*map_err\s*\(", after_call[cursor:]
                )
                if map_err is not None:
                    map_err_open = cursor + map_err.end() - 1
                    map_err_body = _rust_parenthesized_body_at(
                        after_call, map_err_open
                    )
                    if map_err_body is not None:
                        cursor = map_err_open + 1 + len(map_err_body) + 1
                tail = re.match(r"\s*\?\s*;", after_call[cursor:])
                if tail is not None:
                    binding_end = (
                        call_close + 1 + cursor + tail.end()
                    )
        profile_guard = valid_candidates[0]
        between_binding_and_profile = (
            ""
            if binding_end is None or binding_end > profile_guard.start()
            else apply_code[binding_end : profile_guard.start()]
        )
        source_valid = (
            source_binding.group("mutable") is None
            and _rust_brace_depth_at(apply_code, source_binding.start()) == 0
            and initial_guard_end is not None
            and source_binding.start() > initial_guard_end
            and _rust_let_binding_count(apply_code, "replace_report") == 1
            and binding_end is not None
            and binding_end < profile_guard.start()
            and not re.search(
                r"\breplace_report\s*=(?!=)",
                between_binding_and_profile,
            )
            and not re.search(
                r"\b(?:return|break|continue)\b",
                between_binding_and_profile,
            )
        )
    valid = valid and source_valid
    if valid:
        return []
    return [
        "managed ACL apply profile logs must bind "
        "selector_repair_performed from replace_report exactly once "
        "in both bypass and enforced branches"
    ]


def _run_managed_acl_apply_profile_log_mutation_self_tests():
    checker = globals().get("_managed_acl_apply_profile_log_contract_errors")
    if checker is None:
        raise SystemExit(
            "ERROR: managed ACL apply-profile log contract checker is missing"
        )

    bypass_log = r'''            info!(
                status = "bypass",
                selector_repair_performed = replace_report.selector_repair_performed,
                "neutron_acl_apply_profile"
            );'''
    enforced_log = r'''            info!(
                status = "enforced",
                selector_repair_performed = replace_report.selector_repair_performed,
                "neutron_acl_apply_profile"
            );'''
    replace_report_binding = r'''            let replace_report = state
                .control_plane
                .replace_owned_acl(&plan)
                .await?;'''
    initial_guard = r'''            if !port_manages_acl(port) {
                return Ok(NeutronAclReconcileOutcome::default());
            }'''
    safe = r'''
        fn reconcile_neutron_acl(state: &State, port: &Port, plan: Plan) {
%s
%s
            let effective_reason = if plan.policies.is_empty() {
                "no_policies"
            } else {
                "policy_present"
            };
            let _ = effective_reason;
            if plan.policies.is_empty() {
%s
            } else {
%s
            }
        }
    ''' % (initial_guard, replace_report_binding, bypass_log, enforced_log)
    safe_errors = checker(safe)
    if safe_errors:
        raise SystemExit(
            "ERROR: managed ACL apply-profile log checker rejected safe source: %s"
            % safe_errors
        )

    exact_binding = (
        "selector_repair_performed = "
        "replace_report.selector_repair_performed"
    )
    mutants = (
        (
            "bypass profile branch is missing",
            safe.replace(
                bypass_log,
                bypass_log.replace(
                    '"neutron_acl_apply_profile"', '"other_profile"', 1
                ),
                1,
            ),
        ),
        (
            "enforced profile branch is missing",
            safe.replace(
                enforced_log,
                enforced_log.replace(
                    '"neutron_acl_apply_profile"', '"other_profile"', 1
                ),
                1,
            ),
        ),
        (
            "bypass repair marker is constant",
            safe.replace(exact_binding, "selector_repair_performed = true", 1),
        ),
        (
            "enforced repair marker is constant",
            safe.rsplit(exact_binding, 1)[0]
            + "selector_repair_performed = false"
            + safe.rsplit(exact_binding, 1)[1],
        ),
        (
            "bypass repair marker uses another report",
            safe.replace(
                exact_binding,
                "selector_repair_performed = "
                "other_report.selector_repair_performed",
                1,
            ),
        ),
        (
            "enforced repair marker uses another field",
            safe.rsplit(exact_binding, 1)[0]
            + "selector_repair_performed = replace_report.repair_performed"
            + safe.rsplit(exact_binding, 1)[1],
        ),
        (
            "bypass repair marker is duplicated",
            safe.replace(
                exact_binding + ",",
                exact_binding + ",\n                " + exact_binding + ",",
                1,
            ),
        ),
        (
            "duplicate bypass profile branch",
            safe.replace(bypass_log, bypass_log + "\n" + bypass_log, 1),
        ),
        (
            "profile logs are unreachable inside false branches",
            safe.replace(
                bypass_log,
                "            if false {\n" + bypass_log + "\n            }",
                1,
            ).replace(
                enforced_log,
                "            if false {\n" + enforced_log + "\n            }",
                1,
            ),
        ),
        (
            "replace report comes from another source",
            safe.replace(
                replace_report_binding,
                "            let replace_report = other_report;",
                1,
            ),
        ),
        (
            "replace report is shadowed before profile logs",
            safe.replace(
                replace_report_binding,
                replace_report_binding
                + "\n            let replace_report = other_report;",
                1,
            ),
        ),
        (
            "replace report can return before profile logs",
            safe.replace(
                replace_report_binding,
                replace_report_binding
                + "\n            if skip { return; }",
                1,
            ),
        ),
        (
            "replace report source can be skipped after the initial guard",
            safe.replace(
                replace_report_binding,
                "            if skip { return; }\n" + replace_report_binding,
                1,
            ),
        ),
    )
    expected = (
        "managed ACL apply profile logs must bind "
        "selector_repair_performed from replace_report exactly once "
        "in both bypass and enforced branches"
    )
    for label, mutant in mutants:
        errors = checker(mutant)
        if not any(expected in error for error in errors):
            raise SystemExit(
                "ERROR: managed ACL apply-profile log checker accepted %s mutation: %s"
                % (label, errors)
            )
    print(
        "Managed ACL apply-profile log mutation self-tests: OK (%d scenarios)"
        % (len(mutants) + 1)
    )


def _managed_projection_attach_migration_contract_errors(
    control_plane_source,
    tap_registry_source,
    neutron_api_source,
):
    """Return Task 6 production-wiring violations in dependency order."""
    control_code = _blank_rust_non_code(control_plane_source)
    tap_code = _blank_rust_non_code(tap_registry_source)
    neutron_code = _blank_rust_non_code(neutron_api_source)
    errors = []

    attach_body = _rust_function_body_from_blanked(tap_code, "attach_with_mode")
    ownership_name = "reconcile_managed_acl_ownership_serialized"
    ownership_call = (
        None
        if attach_body is None
        else re.search(r"\.\s*%s\s*\(" % ownership_name, attach_body)
    )
    ownership_body = _rust_function_body_from_blanked(control_code, ownership_name)
    if attach_body is None or ownership_call is None or ownership_body is None:
        errors.append(
            "attach_with_mode must delegate to the serialized managed ACL ownership reconciler"
        )
    else:
        lifecycle = attach_body.find("lock_runtime_lifecycle")
        if lifecycle < 0 or ownership_call.start() < lifecycle:
            errors.append(
                "managed ACL ownership reconcile must run after the lifecycle lock"
            )
        if "lock_runtime_lifecycle" in ownership_body:
            errors.append(
                "serialized managed ACL ownership reconcile must not reacquire the lifecycle lock"
            )

    demotion_body = None
    demotion_wiring = ""
    if ownership_body is not None:
        demote_variant = ownership_body.find("::Demote")
        demote_call = (
            None
            if demote_variant < 0
            else re.search(
                r"(?:\bself\s*\.\s*)?"
                r"(?P<name>[A-Za-z_]\w*demot\w*)\s*\(",
                ownership_body[demote_variant:],
            )
        )
        if demote_variant < 0 or demote_call is None:
            errors.append(
                "serialized managed ACL ownership reconcile must dispatch a Demote transaction"
            )
        else:
            demotion_wiring = ownership_body[demote_variant:]
            demotion_body = _rust_function_body_from_blanked(
                control_code, demote_call.group("name")
            )
            if demotion_body is None:
                errors.append("managed ACL demotion production helper is missing")

    if demotion_body is not None:
        if "lock_runtime_lifecycle" in demotion_body:
            errors.append(
                "managed ACL demotion helper must not reacquire the lifecycle lock"
            )
        demotion_scope = demotion_wiring + "\n" + demotion_body
        for pattern, label in (
            (r"\bpurge_neutron_acl\s*\(", "purge_neutron_acl"),
            (r"\.\s*detach\s*\(", "detach"),
            (
                r"\.\s*clear_neutron_port_authority\s*\(",
                "clear Neutron authority",
            ),
        ):
            if re.search(pattern, demotion_scope):
                errors.append("managed ACL demotion must not call %s" % label)

        target_name = "build_managed_acl_demotion_target"
        target_calls = _rust_named_call_arguments(demotion_body, target_name)
        executor_name = "execute_managed_acl_demotion_transaction"
        executor_calls = _rust_named_call_arguments(demotion_body, executor_name)
        if not target_calls:
            errors.append(
                "managed ACL demotion must call build_managed_acl_demotion_target"
            )
        if not executor_calls:
            errors.append(
                "managed ACL demotion must call execute_managed_acl_demotion_transaction"
            )
        elif not all(
            _rust_named_call_result_is_propagated(
                demotion_body, executor_name, position
            )
            for position, _ in executor_calls
        ):
            errors.append(
                "managed ACL demotion must propagate demotion transaction Result"
            )

        if target_calls and executor_calls and target_calls[0][0] > executor_calls[0][0]:
            errors.append(
                "managed ACL demotion must build its target before transaction execution"
            )

        if target_calls:
            before_target = demotion_body[: target_calls[0][0]]
            quiesced = re.search(
                r"\b(?:update_acl_runtime_gate|\w*quiesc\w*)\s*\(",
                before_target,
            )
            invalidated = re.search(
                r"\bmanaged_projection_health\s*=\s*"
                r"ManagedProjectionHealth\s*::\s*Unverified\b",
                before_target,
            )
            if quiesced is None or invalidated is None:
                errors.append(
                    "managed ACL demotion must quiesce and invalidate health before target validation"
                )

        if executor_calls:
            executor_arguments = executor_calls[0][1]

            def demotion_argument_index(predicate):
                return next(
                    (
                        index
                        for index, argument in enumerate(executor_arguments)
                        if predicate(re.sub(r"\s+", "", argument).lower())
                    ),
                    -1,
                )

            callback_order = [
                demotion_argument_index(lambda item: "quiesc" in item),
                demotion_argument_index(
                    lambda item: "projection_health" in item
                ),
                demotion_argument_index(
                    lambda item: "publish_acl_projection_locked" in item
                ),
                demotion_argument_index(
                    lambda item: "strict" in item and "flush" in item
                ),
                demotion_argument_index(
                    lambda item: "managed_acl_publication_mode" in item
                    and "neutronattachownedstandaloneacl" in item
                ),
                demotion_argument_index(
                    lambda item: "compensat" in item or "rollback" in item
                ),
                demotion_argument_index(
                    lambda item: "old_state" in item
                    and any(
                        marker in item
                        for marker in ("restore", "persist", "compact")
                    )
                ),
            ]
            if (
                any(index < 0 for index in callback_order)
                or callback_order != sorted(callback_order)
            ):
                errors.append(
                    "managed ACL demotion must wire quiesce, health, publish, flush, mode, compensation, and restore callbacks"
                )
            publish_index = callback_order[2]
            forced_shared_publish = False
            if publish_index >= 0:
                publish_calls = _rust_named_call_arguments(
                    executor_arguments[publish_index],
                    "publish_acl_projection_locked",
                )
                forced_shared_publish = any(
                    len(arguments) > 5
                    and re.sub(r"\s+", "", arguments[5]) == "true"
                    for _, arguments in publish_calls
                )
            if not forced_shared_publish:
                errors.append(
                    "managed ACL demotion must force the shared projection publisher"
                )

    required_mode_body = _rust_function_body_from_blanked(
        neutron_code, "required_neutron_publication_mode"
    )
    required_mode_valid = False
    if required_mode_body is not None:
        if_branch = re.search(
            r"\bif\b[^{}]+\{(?P<managed>[^{}]*)\}\s*else\s*"
            r"\{(?P<standalone>[^{}]*)\}",
            required_mode_body,
            re.DOTALL,
        )
        true_arm = re.search(
            r"\btrue\s*=>\s*(?P<managed>[^,}]+)", required_mode_body
        )
        false_arm = re.search(
            r"\bfalse\s*=>\s*(?P<standalone>[^,}]+)", required_mode_body
        )
        if if_branch is not None:
            managed = if_branch.group("managed")
            standalone = if_branch.group("standalone")
        elif true_arm is not None and false_arm is not None:
            managed = true_arm.group("managed")
            standalone = false_arm.group("standalone")
        else:
            managed = standalone = ""
        required_mode_valid = bool(
            managed
            and standalone
            and "ManagedAclPublicationMode::ManagedAcl" in managed
            and "ManagedAclPublicationMode::NeutronAttachOwnedStandaloneAcl"
            in standalone
            and "ManagedAclPublicationMode::StandaloneCompatibility"
            not in required_mode_body
        )
    if not required_mode_valid:
        errors.append(
            "required Neutron publication mode must map ACL to ManagedAcl and non-ACL to attach-owned standalone"
        )

    authority_parameters = _rust_function_parameters_from_blanked(
        control_code, "mark_neutron_port_authority_if_current"
    )
    if authority_parameters is None or not re.search(
        r"\brequired_publication_mode\s*:\s*ManagedAclPublicationMode\b",
        authority_parameters,
    ):
        errors.append(
            "Neutron authority confirmation must accept the exact required publication mode"
        )

    restore_body = _rust_function_body_from_blanked(
        neutron_code, "restore_neutron_authorities"
    )
    apply_body = _rust_function_body_from_blanked(
        neutron_code, "apply_snapshot_runtime_transaction"
    )
    update_body = (
        None
        if apply_body is None
        else _rust_named_for_loop_body(apply_body, "port", "update")
    )
    attach_loop_body = (
        None
        if apply_body is None
        else _rust_named_for_loop_body(apply_body, "port", "attach")
    )

    def check_authority_scope(label, body, minimum_calls, require_verified):
        if body is None or "required_neutron_publication_mode" not in body:
            errors.append("%s must derive the exact required publication mode" % label)
            return
        calls = _rust_named_call_arguments(
            body, "mark_neutron_port_authority_if_current"
        )
        if len(calls) < minimum_calls:
            errors.append("%s must confirm Neutron authority" % label)
            return
        for _, arguments in calls:
            mode_argument = (
                "" if len(arguments) < 5 else re.sub(r"\s+", "", arguments[4])
            )
            if mode_argument != "required_publication_mode":
                errors.append(
                    "%s must pass its exact required publication mode" % label
                )
                break

        health_arguments = [
            "" if len(arguments) < 6 else re.sub(r"\s+", "", arguments[5])
            for _, arguments in calls
        ]
        if not require_verified:
            if any(argument != "None" for argument in health_arguments):
                errors.append(
                    "restored authority must remain projection-health agnostic"
                )
            return

        derivation = re.search(
            r"\blet\s+required_projection_health\s*=\s*(?P<value>[^;]+);",
            body,
            re.DOTALL,
        )
        derivation_value = "" if derivation is None else derivation.group("value")
        if (
            "ManagedProjectionHealth::Verified" not in derivation_value
            or "then_some" not in derivation_value
            or not re.search(
                r"(?:manages_acl|managed_acl|port_manages_acl)",
                derivation_value,
            )
        ):
            errors.append("%s must derive ACL authority as Verified" % label)
        if any(
            argument not in (
                "required_projection_health",
                "Some(required_projection_health)",
            )
            for argument in health_arguments
        ):
            errors.append(
                "%s ACL authority commit must require Verified projection health"
                % label
            )

    check_authority_scope("restored authority", restore_body, 1, False)
    check_authority_scope("updated port", update_body, 2, True)
    check_authority_scope("attached port", attach_loop_body, 1, True)

    reconcile_body = _rust_function_body_from_blanked(
        neutron_code, "reconcile_neutron_acl"
    )
    completion_name = "execute_managed_acl_post_replace_completion"
    completion_calls = (
        []
        if reconcile_body is None
        else list(re.finditer(r"\b%s\s*\(" % completion_name, reconcile_body))
    )
    if reconcile_body is None or not completion_calls:
        errors.append(
            "managed ACL reconcile must call execute_managed_acl_post_replace_completion"
        )
    else:
        if not all(
            _rust_named_call_result_is_propagated(
                reconcile_body, completion_name, call.start()
            )
            for call in completion_calls
        ):
            errors.append(
                "managed ACL reconcile must propagate post-replace completion Result"
            )
        replace = reconcile_body.find("replace_owned_acl")
        first_completion = completion_calls[0].start()
        early_return = (
            None
            if replace < 0
            else re.search(
                r"\breturn\b", reconcile_body[replace:first_completion]
            )
        )
        top_level_completion = any(
            _rust_brace_depth_at(reconcile_body, call.start()) == 0
            for call in completion_calls
        )
        branch_completion = any(
            any(start <= call.start() < end for call in completion_calls)
            and any(
                else_start <= call.start() < else_end
                for call in completion_calls
            )
            for start, end, else_start, else_end in _rust_if_else_branch_spans(
                reconcile_body
            )
        )
        if (
            replace < 0
            or first_completion < replace
            or early_return is not None
            or not (top_level_completion or branch_completion)
        ):
            errors.append(
                "every managed ACL success path must reach post-replace completion"
            )

        for _, arguments in _rust_named_call_arguments(
            reconcile_body, completion_name
        ):
            compact = [
                re.sub(r"\s+", "", argument).lower()
                for argument in arguments
            ]

            def completion_index(predicate):
                return next(
                    (
                        index
                        for index, argument in enumerate(compact)
                        if predicate(argument)
                    ),
                    -1,
                )

            callback_order = [
                completion_index(
                    lambda item: ("strict" in item and "flush" in item)
                    or "flush_neutron_acl_conntrack" in item
                ),
                completion_index(
                    lambda item: ("publish" in item and "gate" in item)
                    or "update_neutron_acl_runtime_gate" in item
                ),
                completion_index(
                    lambda item: "precommit" in item
                    or "before_enable" in item
                ),
                completion_index(
                    lambda item: "verify" in item and "mark" in item
                ),
                completion_index(
                    lambda item: "requiesc" in item
                    or ("quiesc" in item and "gate" in item)
                ),
            ]
            if (
                any(index < 0 for index in callback_order)
                or callback_order != sorted(callback_order)
            ):
                errors.append(
                    "post-replace completion must wire flush, gate, precommit, verify, then requiesce"
                )
                break

    verify_body = _rust_function_body_from_blanked(
        control_code, "verify_and_mark_managed_projection"
    )
    completion_scope = "" if reconcile_body is None else reconcile_body
    if (
        verify_body is None
        or "verify_and_mark_managed_projection" not in completion_scope
    ):
        errors.append(
            "post-replace completion must call the production verify-and-mark helper"
        )
    else:
        lifecycle = re.search(
            r"\blet\s+(?P<guard>_?[A-Za-z_]\w*)\s*=\s*"
            r"self\s*\.\s*lock_runtime_lifecycle\s*\(\s*\)\s*"
            r"\.\s*await\s*;",
            verify_body,
        )
        instance = re.search(r"\bget_instance\s*\(", verify_body)
        write_lock = re.search(
            r"\.\s*write\s*\(\s*\)\s*\.\s*await", verify_body
        )
        mode_guard = re.search(
            r"\bmanaged_acl_publication_mode\b\s*!=\s*"
            r"ManagedAclPublicationMode\s*::\s*ManagedAcl\b|"
            r"!\s*matches\s*!\s*\([^)]*managed_acl_publication_mode"
            r"[^)]*ManagedAclPublicationMode\s*::\s*ManagedAcl\b",
            verify_body,
            re.DOTALL,
        )
        gate = re.search(
            r"\bvalidate_managed_projection_runtime_gate\s*\(",
            verify_body,
        )
        clean_inventory_calls = _rust_named_call_arguments(
            verify_body, "require_clean_managed_projection_inventory"
        )
        clean_inventory = next(
            (
                (position, arguments)
                for position, arguments in clean_inventory_calls
                if len(arguments) == 1
                and re.search(
                    r"\bvalidate_managed_pinned_runtime_state\s*\(",
                    arguments[0],
                )
            ),
            None,
        )
        inventory = re.search(
            r"\bvalidate_managed_pinned_runtime_state\s*\(",
            verify_body,
        )
        tc = re.search(
            r"\b(?:Self\s*::\s*)?require_tc_acl_ready_locked\s*\(",
            verify_body,
        )
        verified = re.search(
            r"\bmanaged_projection_health\s*=\s*"
            r"ManagedProjectionHealth\s*::\s*Verified\b",
            verify_body,
        )
        lock_positions = [
            -1 if marker is None else marker.start()
            for marker in (lifecycle, instance, write_lock)
        ]
        if (
            any(position < 0 for position in lock_positions)
            or lock_positions != sorted(lock_positions)
        ):
            errors.append(
                "verify-and-mark helper must acquire lifecycle then instance write lock"
            )
        mode_failure = (
            ""
            if mode_guard is None or gate is None
            else verify_body[mode_guard.start() : gate.start()]
        )
        if (
            mode_guard is None
            or write_lock is None
            or mode_guard.start() < write_lock.start()
            or not re.search(r"\breturn\s+Err\s*\(", mode_failure)
        ):
            errors.append(
                "verify-and-mark helper must require current ManagedAcl mode"
            )
        if (
            mode_guard is None
            or gate is None
            or clean_inventory is None
            or inventory is None
            or tc is None
            or verified is None
            or not (
                mode_guard.start()
                < gate.start()
                < clean_inventory[0]
                < inventory.start()
                < tc.start()
                < verified.start()
            )
        ):
            errors.append(
                "verify-and-mark helper must validate the exact gate, complete inventory, and TC before Verified"
            )
        validation_results_propagated = bool(
            gate is not None
            and clean_inventory is not None
            and tc is not None
            and _rust_named_call_result_is_propagated(
                verify_body,
                "validate_managed_projection_runtime_gate",
                gate.start(),
            )
            and _rust_named_call_result_is_propagated(
                verify_body,
                "require_clean_managed_projection_inventory",
                clean_inventory[0],
            )
            and _rust_named_call_result_is_propagated(
                verify_body,
                "require_tc_acl_ready_locked",
                tc.start(),
            )
        )
        if not validation_results_propagated:
            errors.append(
                "verify-and-mark helper must propagate exact gate, complete inventory, and TC validation failures"
            )
        if lifecycle is not None and verified is not None:
            before_verified = verify_body[lifecycle.end() : verified.start()]
            if re.search(
                r"\b(?:std\s*::\s*mem\s*::\s*)?drop\s*\(\s*%s\s*\)"
                % re.escape(lifecycle.group("guard")),
                before_verified,
            ):
                errors.append(
                    "verify-and-mark helper must hold the lifecycle guard through Verified"
                )
        if verified is not None:
            helper_tail = verify_body[verified.end() :]
            ok = re.search(r"\bOk\s*\(", helper_tail)
            before_ok = helper_tail if ok is None else helper_tail[: ok.start()]
            if ok is None or ".await" in before_ok or "?" in before_ok:
                errors.append(
                    "verify-and-mark helper must commit Verified as its final infallible action"
                )

    prepare_body = _rust_function_body_from_blanked(
        control_code, "prepare_managed_registration"
    )
    fresh_name = "persist_fresh_managed_registration_gate_state"
    fresh_calls = (
        []
        if prepare_body is None
        else _rust_named_call_arguments(prepare_body, fresh_name)
    )
    if prepare_body is None or not fresh_calls:
        errors.append(
            "fresh registration must call persist_fresh_managed_registration_gate_state"
        )
    else:
        fresh_position, fresh_arguments = fresh_calls[0]
        prepared = prepare_body.find("PreparedManagedInstance", fresh_position)
        if prepared < fresh_position:
            errors.append(
                "fresh gate persistence must complete before publishing the instance"
            )
        if not _rust_named_call_result_is_propagated(
            prepare_body, fresh_name, fresh_position
        ):
            errors.append(
                "fresh gate persistence Result must be propagated"
            )
        compact = [
            re.sub(r"\s+", "", argument)
            for argument in fresh_arguments
        ]
        fresh_argument = "" if len(compact) < 3 else compact[2]
        positive_fresh = bool(
            re.fullmatch(
                r"[A-Za-z_]\w*(?:fresh|new)\w*"
                r"(?:\([^()]*\))?",
                fresh_argument,
            )
            and not fresh_argument.startswith("!")
            and "==false" not in fresh_argument
        )
        if (
            len(compact) < 4
            or compact[0] != "&mutstate"
            or "mode" not in compact[1]
            or not positive_fresh
            or not any(
                marker in compact[3].lower()
                for marker in ("persist", "compact", "wal")
            )
        ):
            errors.append(
                "fresh helper must receive state, mode, a positive fresh value, and persistence callback"
            )

    gate_writer_body = _rust_function_body_from_blanked(
        control_code, "update_neutron_acl_runtime_gate_serialized"
    )
    health_invalidation = (
        None
        if gate_writer_body is None
        else re.search(
            r"\bstate\s*\.\s*managed_projection_health\s*=\s*"
            r"managed_projection_health_before_runtime_gate_write\s*\(",
            gate_writer_body,
        )
    )
    kernel_gate_write = (
        None
        if gate_writer_body is None
        else re.search(
            r"aria_core\s*::\s*ebpf_ops\s*::\s*"
            r"update_acl_runtime_gate\s*\(",
            gate_writer_body,
        )
    )
    if (
        health_invalidation is None
        or kernel_gate_write is None
        or health_invalidation.start() > kernel_gate_write.start()
    ):
        errors.append(
            "managed ACL runtime gate writes must invalidate projection health before kernel publication"
        )

    classifier_name = "unsupported_neutron_managed_domains"

    def check_preflight(label, loop_body):
        if loop_body is None:
            errors.append(
                "%s must reject unsupported domains before ownership sync"
                % label
            )
            return
        attach = re.search(r"\.\s*attach_neutron\s*\(", loop_body)
        classifier_calls = _rust_named_call_arguments(
            loop_body, classifier_name
        )
        if (
            attach is None
            or not classifier_calls
            or classifier_calls[0][0] > attach.start()
            or _rust_brace_depth_at(loop_body, classifier_calls[0][0]) != 0
        ):
            errors.append(
                "%s must run the exact classifier at top level before ownership sync"
                % label
            )
            return
        classifier_position = classifier_calls[0][0]
        prefix = loop_body[
            max(0, classifier_position - 240) : classifier_position
        ]
        binding = re.search(
            r"\blet\s+(?P<name>[A-Za-z_]\w*)\s*=\s*$", prefix
        )
        between = loop_body[classifier_position : attach.start()]
        guard = (
            None
            if binding is None
            else re.search(
                r"\bif\s+!\s*%s\s*\.\s*is_empty\s*\(\s*\)\s*\{"
                % re.escape(binding.group("name")),
                between,
            )
        )
        guard_body = None
        guard_absolute = -1
        if guard is not None:
            guard_absolute = classifier_position + guard.start()
            guard_open = between.find("{", guard.start())
            guard_body = _rust_braced_body_at(between, guard_open)
        if (
            guard is None
            or guard_absolute < classifier_position
            or _rust_brace_depth_at(loop_body, guard_absolute) != 0
            or guard_body is None
            or not re.search(r"\bcontinue\s*;", guard_body)
        ):
            errors.append(
                "%s must use a top-level nonempty classifier guard with continue"
                % label
            )

    check_preflight("updated port", update_body)
    check_preflight("attached port", attach_loop_body)
    reconcile_domains = _rust_function_body_from_blanked(
        neutron_code, "reconcile_neutron_domains"
    )
    if (
        reconcile_domains is None
        or not _rust_named_call_arguments(
            reconcile_domains, classifier_name
        )
    ):
        errors.append(
            "reconcile_neutron_domains must reuse unsupported_neutron_managed_domains"
        )

    return errors


def _run_managed_projection_attach_migration_mutation_self_tests():
    safe_tap = r"""
        async fn attach_with_mode(&self, iface: &str, mode: ManagedAttachMode) {
            let iface_lock = self.get_iface_lock(iface).await;
            let _guard = iface_lock.lock().await;
            let _runtime_guard = self.control_plane.lock_runtime_lifecycle().await;
            if already_attached {
                return self.control_plane
                    .reconcile_managed_acl_ownership_serialized(iface, mode)
                    .await;
            }
            self.finish_fresh_attach(iface, mode).await
        }
    """
    safe_control = r"""
        pub(crate) async fn mark_neutron_port_authority_if_current(
            &self,
            instance: &str,
            port_id: &str,
            managed_domains: &[String],
            generation: u64,
            required_publication_mode: ManagedAclPublicationMode,
            required_projection_health: Option<ManagedProjectionHealth>,
        ) -> bool {
            self.confirm_authority(required_publication_mode)
        }

        async fn update_neutron_acl_runtime_gate_serialized(
            &self,
            instance: &str,
            conntrack_enabled: bool,
            acl_enabled: bool,
        ) -> Result<(), String> {
            let mut state = self.get_instance(instance).await?.write().await;
            require_tc_acl_ready_locked(&state)?;
            state.managed_projection_health =
                managed_projection_health_before_runtime_gate_write(
                    state.managed_acl_publication_mode,
                    state.managed_projection_health,
                );
            aria_core::ebpf_ops::update_acl_runtime_gate(
                state.map_runtime(),
                conntrack_enabled,
                acl_enabled,
                ACL_INGRESS_HOOK_TC,
            )?;
            Ok(())
        }

        async fn reconcile_managed_acl_ownership_serialized(
            &self,
            instance: &str,
            requested_mode: ManagedAttachMode,
        ) -> Result<(), String> {
            match managed_acl_ownership_transition(requested_mode) {
                ManagedAclOwnershipTransition::Preserve => Ok(()),
                ManagedAclOwnershipTransition::Promote => self.promote(instance).await,
                ManagedAclOwnershipTransition::Demote => {
                    self.execute_managed_acl_demotion(instance).await
                }
            }
        }

        async fn execute_managed_acl_demotion(&self, instance: &str) {
            update_acl_runtime_gate(instance, false, false)?;
            state.managed_projection_health = ManagedProjectionHealth::Unverified;
            let old_state = state.state.clone();
            let (proposed_state, proposed_projection) =
                build_managed_acl_demotion_target(&old_state, owner_prefix)?;
            execute_managed_acl_demotion_transaction(
                || async { quiesce_acl_ct(instance).await?; Ok(()) },
                |health| state.managed_projection_health = health,
                || async {
                    self.publish_acl_projection_locked(
                        instance,
                        state,
                        &old_state,
                        &proposed_state,
                        &proposed_projection,
                        true,
                        false,
                        mutations,
                        current_bank,
                        next_bank,
                        port_sets,
                        created_port_sets,
                        released_port_sets,
                        report,
                    ).await
                },
                || async { flush_conntrack_strict_locked(instance).await?; Ok(()) },
                |mode| async {
                    state.managed_acl_publication_mode =
                        ManagedAclPublicationMode::NeutronAttachOwnedStandaloneAcl;
                    assert_eq!(mode, ManagedAclPublicationMode::NeutronAttachOwnedStandaloneAcl);
                    Ok(())
                },
                |receipt| async { compensate_shared_mutation(receipt).await },
                || async { state.compact_and_publish_state(old_state.clone()).await },
            ).await
        }

        async fn verify_and_mark_managed_projection(
            &self,
            instance_name: &str,
        ) -> Result<(), String> {
            let _runtime_guard = self.lock_runtime_lifecycle().await;
            let instance = self.get_instance(instance_name).await?;
            let mut state = instance.write().await;
            if state.managed_acl_publication_mode
                != ManagedAclPublicationMode::ManagedAcl
            {
                return Err("managed ACL mode changed before verification".to_string());
            }
            let actual_gate = read_runtime_config(state)?;
            validate_managed_projection_runtime_gate(state, &actual_gate)?;
            require_clean_managed_projection_inventory(
                validate_managed_pinned_runtime_state(state),
            )?;
            require_tc_acl_ready_locked(state)?;
            state.managed_projection_health = ManagedProjectionHealth::Verified;
            Ok(())
        }

        async fn prepare_managed_registration(
            &self,
            mode: ManagedAttachMode,
            pin_state: RuntimePinState,
        ) -> Result<PreparedManagedInstance, String> {
            let registration_is_fresh = registration_is_fresh(&pin_state);
            persist_fresh_managed_registration_gate_state(
                &mut state,
                mode,
                registration_is_fresh,
                |snapshot| state.compact_and_publish_state(snapshot),
            ).await?;
            Ok(PreparedManagedInstance { state })
        }
    """
    safe_neutron = r"""
        fn required_neutron_publication_mode(
            manages_acl: bool,
        ) -> ManagedAclPublicationMode {
            if manages_acl {
                ManagedAclPublicationMode::ManagedAcl
            } else {
                ManagedAclPublicationMode::NeutronAttachOwnedStandaloneAcl
            }
        }

        fn unsupported_neutron_managed_domains(domains: &[String]) -> Vec<String> {
            normalize_managed_domains(domains)
        }

        async fn restore_neutron_authorities(&self) {
            let required_publication_mode =
                required_neutron_publication_mode(port_manages_acl(&port));
            self.control_plane.mark_neutron_port_authority_if_current(
                &port.ifname,
                &port.port_id,
                &port.managed_domains,
                generation,
                required_publication_mode,
                None,
            ).await;
        }

        async fn apply_snapshot_runtime_transaction(state: &State) {
            for port in update {
                let unsupported =
                    unsupported_neutron_managed_domains(&port.managed_domains);
                if !unsupported.is_empty() {
                    record_unsupported(unsupported);
                    continue;
                }
                state.registry.attach_neutron(
                    &port.ifname,
                    port_manages_acl(&port),
                ).await?;
                let required_publication_mode =
                    required_neutron_publication_mode(port_manages_acl(&port));
                let required_projection_health = port_manages_acl(&port)
                    .then_some(ManagedProjectionHealth::Verified);
                if can_skip() {
                    state.control_plane.mark_neutron_port_authority_if_current(
                        &managed.ifname,
                        &managed.port_id,
                        &managed.managed_domains,
                        generation,
                        required_publication_mode,
                        required_projection_health,
                    ).await;
                    continue;
                }
                state.control_plane.mark_neutron_port_authority_if_current(
                    &managed.ifname,
                    &managed.port_id,
                    &managed.managed_domains,
                    generation,
                    required_publication_mode,
                    required_projection_health,
                ).await;
            }
            for port in &attach {
                let unsupported =
                    unsupported_neutron_managed_domains(&port.managed_domains);
                if !unsupported.is_empty() {
                    record_unsupported(unsupported);
                    continue;
                }
                state.registry.attach_neutron(
                    &port.ifname,
                    port_manages_acl(port),
                ).await?;
                let required_publication_mode =
                    required_neutron_publication_mode(port_manages_acl(port));
                let required_projection_health = port_manages_acl(port)
                    .then_some(ManagedProjectionHealth::Verified);
                state.control_plane.mark_neutron_port_authority_if_current(
                    &managed.ifname,
                    &managed.port_id,
                    &managed.managed_domains,
                    generation,
                    required_publication_mode,
                    required_projection_health,
                ).await;
            }
        }

        async fn reconcile_neutron_domains(port: &Port) {
            let unsupported =
                unsupported_neutron_managed_domains(&port.managed_domains);
            if !unsupported.is_empty() {
                return blocked_domains(unsupported);
            }
            reconcile_supported_domains(port).await
        }

        async fn reconcile_neutron_acl(state: &State) {
            state.control_plane.replace_owned_acl().await?;
            if plan.policies.is_empty() {
                record_bypass_outcome(&outcome);
            } else {
                record_enforced_outcome(&outcome);
            }
            execute_managed_acl_post_replace_completion(
                state,
                || strict_flush(),
                || publish_gate(),
                || precommit_fault(),
                || state.control_plane.verify_and_mark_managed_projection(),
                || requiesce_gate(),
            ).await?;
            Ok(outcome)
        }
    """

    def mutate(source, old, new, count=1):
        if source.count(old) < count:
            raise SystemExit(
                "ERROR: Task 6 mutation fixture anchor is missing: " + old
            )
        return source.replace(old, new, count)

    safe_errors = _managed_projection_attach_migration_contract_errors(
        safe_control, safe_tap, safe_neutron
    )
    if safe_errors:
        raise SystemExit(
            "ERROR: managed attach-migration checker rejected safe source: %s"
            % safe_errors
        )

    safe_false_first = mutate(
        safe_neutron,
        "            if manages_acl {\n"
        "                ManagedAclPublicationMode::ManagedAcl\n"
        "            } else {\n"
        "                ManagedAclPublicationMode::NeutronAttachOwnedStandaloneAcl\n"
        "            }",
        "            match manages_acl {\n"
        "                false => ManagedAclPublicationMode::NeutronAttachOwnedStandaloneAcl,\n"
        "                true => ManagedAclPublicationMode::ManagedAcl,\n"
        "            }",
    )
    false_first_errors = _managed_projection_attach_migration_contract_errors(
        safe_control, safe_tap, safe_false_first
    )
    if false_first_errors:
        raise SystemExit(
            "ERROR: checker rejected false-first required-mode mapping: %s"
            % false_first_errors
        )

    def case(
        label,
        expected,
        control=safe_control,
        tap=safe_tap,
        neutron=safe_neutron,
    ):
        return label, control, tap, neutron, expected

    mutants = [
        case(
            "Demote dispatch removed",
            "must dispatch a Demote transaction",
            control=mutate(
                safe_control,
                "ManagedAclOwnershipTransition::Demote",
                "ManagedAclOwnershipTransition::PreserveAgain",
            ),
        ),
        case(
            "serialized ownership relocks lifecycle",
            "must not reacquire the lifecycle lock",
            control=mutate(
                safe_control,
                "            match managed_acl_ownership_transition(requested_mode) {",
                "            let _again = self.lock_runtime_lifecycle().await;\n"
                "            match managed_acl_ownership_transition(requested_mode) {",
            ),
        ),
        case(
            "demotion validates target before fail-closed transition",
            "must quiesce and invalidate health before target validation",
            control=mutate(
                safe_control,
                "            update_acl_runtime_gate(instance, false, false)?;\n"
                "            state.managed_projection_health = ManagedProjectionHealth::Unverified;\n",
                "",
            ),
        ),
        case(
            "demotion uses item purge",
            "must not call purge_neutron_acl",
            control=mutate(
                safe_control,
                "            let old_state = state.state.clone();",
                "            purge_neutron_acl(instance).await?;\n"
                "            let old_state = state.state.clone();",
            ),
        ),
        case(
            "demotion detaches",
            "must not call detach",
            control=mutate(
                safe_control,
                "            let old_state = state.state.clone();",
                "            self.registry.detach(instance).await?;\n"
                "            let old_state = state.state.clone();",
            ),
        ),
        case(
            "demotion clears authority",
            "must not call clear Neutron authority",
            control=mutate(
                safe_control,
                "            let old_state = state.state.clone();",
                "            self.clear_neutron_port_authority(instance).await;\n"
                "            let old_state = state.state.clone();",
            ),
        ),
        case(
            "demotion bypasses exact target builder",
            "must call build_managed_acl_demotion_target",
            control=mutate(
                safe_control,
                "build_managed_acl_demotion_target(",
                "build_unchecked_demotion_target(",
            ),
        ),
        case(
            "demotion bypasses exact executor",
            "must call execute_managed_acl_demotion_transaction",
            control=mutate(
                safe_control,
                "execute_managed_acl_demotion_transaction(",
                "execute_unchecked_demotion_transaction(",
            ),
        ),
        case(
            "demotion publisher is not forced",
            "must force the shared projection publisher",
            control=mutate(
                safe_control,
                "                        &proposed_projection,\n"
                "                        true,",
                "                        &proposed_projection,\n"
                "                        false,",
            ),
        ),
        case(
            "demotion callback order swapped",
            "must wire quiesce, health, publish, flush, mode, compensation, and restore callbacks",
            control=mutate(
                safe_control,
                "                || async { quiesce_acl_ct(instance).await?; Ok(()) },\n"
                "                |health| state.managed_projection_health = health,",
                "                |health| state.managed_projection_health = health,\n"
                "                || async { quiesce_acl_ct(instance).await?; Ok(()) },",
            ),
        ),
        case(
            "demotion Result discarded",
            "must propagate demotion transaction Result",
            control=mutate(
                safe_control,
                "            ).await\n        }",
                "            ).await.ok()\n        }",
            ),
        ),
        case(
            "non-ACL required mode is wrong",
            "must map ACL to ManagedAcl and non-ACL to attach-owned standalone",
            neutron=mutate(
                safe_neutron,
                "ManagedAclPublicationMode::NeutronAttachOwnedStandaloneAcl",
                "ManagedAclPublicationMode::ManagedAcl",
            ),
        ),
        case(
            "authority required mode becomes optional",
            "must accept the exact required publication mode",
            control=mutate(
                safe_control,
                "required_publication_mode: ManagedAclPublicationMode",
                "required_publication_mode: Option<ManagedAclPublicationMode>",
            ),
            neutron=mutate(
                safe_neutron,
                "required_publication_mode,\n",
                "Some(required_publication_mode),\n",
                count=4,
            ),
        ),
        case(
            "updated authority omits Verified",
            "updated port ACL authority commit must require Verified projection health",
            neutron=mutate(
                safe_neutron,
                "                    continue;\n"
                "                }\n"
                "                state.control_plane.mark_neutron_port_authority_if_current(\n"
                "                    &managed.ifname,\n"
                "                    &managed.port_id,\n"
                "                    &managed.managed_domains,\n"
                "                    generation,\n"
                "                    required_publication_mode,\n"
                "                    required_projection_health,",
                "                    continue;\n"
                "                }\n"
                "                state.control_plane.mark_neutron_port_authority_if_current(\n"
                "                    &managed.ifname,\n"
                "                    &managed.port_id,\n"
                "                    &managed.managed_domains,\n"
                "                    generation,\n"
                "                    required_publication_mode,\n"
                "                    None,",
            ),
        ),
        case(
            "completion bypass return",
            "every managed ACL success path must reach post-replace completion",
            neutron=mutate(
                safe_neutron,
                "            state.control_plane.replace_owned_acl().await?;",
                "            state.control_plane.replace_owned_acl().await?;\n"
                "            if abort { return Err(rejected()); }",
            ),
        ),
        case(
            "completion callback order swapped",
            "must wire flush, gate, precommit, verify, then requiesce",
            neutron=mutate(
                safe_neutron,
                "                || strict_flush(),\n"
                "                || publish_gate(),",
                "                || publish_gate(),\n"
                "                || strict_flush(),",
            ),
        ),
        case(
            "completion Result discarded",
            "must propagate post-replace completion Result",
            neutron=mutate(
                safe_neutron,
                "            ).await?;\n            Ok(outcome)",
                "            ).await.ok();\n            Ok(outcome)",
            ),
        ),
        case(
            "verify helper omits lifecycle lock",
            "must acquire lifecycle then instance write lock",
            control=mutate(
                safe_control,
                "            let _runtime_guard = self.lock_runtime_lifecycle().await;\n",
                "",
            ),
        ),
        case(
            "verify helper accepts wrong mode",
            "must require current ManagedAcl mode",
            control=mutate(
                safe_control,
                "                != ManagedAclPublicationMode::ManagedAcl",
                "                != ManagedAclPublicationMode::NeutronAttachOwnedStandaloneAcl",
            ),
        ),
        case(
            "verify helper drops lifecycle early",
            "must hold the lifecycle guard through Verified",
            control=mutate(
                safe_control,
                "            validate_managed_projection_runtime_gate(state, &actual_gate)?;",
                "            drop(_runtime_guard);\n"
                "            validate_managed_projection_runtime_gate(state, &actual_gate)?;",
            ),
        ),
        case(
            "verify helper bypasses the exact runtime gate validator",
            "must validate the exact gate, complete inventory, and TC before Verified",
            control=mutate(
                safe_control,
                "validate_managed_projection_runtime_gate(state, &actual_gate)?;",
                "validate_runtime_gate(state)?;",
            ),
        ),
        case(
            "verify helper omits complete managed inventory",
            "must validate the exact gate, complete inventory, and TC before Verified",
            control=mutate(
                safe_control,
                "            require_clean_managed_projection_inventory(\n"
                "                validate_managed_pinned_runtime_state(state),\n"
                "            )?;\n",
                "",
            ),
        ),
        case(
            "verify helper replaces TC readiness with a name-only sentinel",
            "must validate the exact gate, complete inventory, and TC before Verified",
            control=mutate(
                safe_control,
                "            require_tc_acl_ready_locked(state)?;",
                "            if neutron_acl_gate_requires_tc(false, false) {}",
            ),
        ),
        case(
            "verify helper discards runtime gate validation failure",
            "must propagate exact gate, complete inventory, and TC validation failures",
            control=mutate(
                safe_control,
                "            validate_managed_projection_runtime_gate(state, &actual_gate)?;",
                "            drop(validate_managed_projection_runtime_gate(state, &actual_gate));",
            ),
        ),
        case(
            "verify helper discards complete inventory failure",
            "must propagate exact gate, complete inventory, and TC validation failures",
            control=mutate(
                safe_control,
                "            require_clean_managed_projection_inventory(\n"
                "                validate_managed_pinned_runtime_state(state),\n"
                "            )?;",
                "            drop(require_clean_managed_projection_inventory(\n"
                "                validate_managed_pinned_runtime_state(state),\n"
                "            ));",
            ),
        ),
        case(
            "verify helper discards TC readiness failure",
            "must propagate exact gate, complete inventory, and TC validation failures",
            control=mutate(
                safe_control,
                "            require_tc_acl_ready_locked(state)?;",
                "            drop(require_tc_acl_ready_locked(state));",
            ),
        ),
        case(
            "fresh exact helper renamed",
            "must call persist_fresh_managed_registration_gate_state",
            control=mutate(
                safe_control,
                "persist_fresh_managed_registration_gate_state(",
                "persist_unchecked_registration_gate(",
            ),
        ),
        case(
            "fresh argument negated",
            "must receive state, mode, a positive fresh value, and persistence callback",
            control=mutate(
                safe_control,
                "                registration_is_fresh,\n"
                "                |snapshot|",
                "                !registration_is_fresh,\n"
                "                |snapshot|",
            ),
        ),
        case(
            "fresh Result discarded",
            "fresh gate persistence Result must be propagated",
            control=mutate(
                safe_control,
                "            ).await?;\n"
                "            Ok(PreparedManagedInstance",
                "            ).await.ok();\n"
                "            Ok(PreparedManagedInstance",
            ),
        ),
        case(
            "runtime gate write preserves stale projection health",
            "must invalidate projection health before kernel publication",
            control=mutate(
                safe_control,
                "            state.managed_projection_health =\n"
                "                managed_projection_health_before_runtime_gate_write(\n"
                "                    state.managed_acl_publication_mode,\n"
                "                    state.managed_projection_health,\n"
                "                );\n",
                "",
            ),
        ),
        case(
            "update classifier runs after ownership",
            "must run the exact classifier at top level before ownership sync",
            neutron=mutate(
                safe_neutron,
                "                let unsupported =\n"
                "                    unsupported_neutron_managed_domains(&port.managed_domains);\n",
                "",
            ),
        ),
        case(
            "update nonempty guard inverted",
            "must use a top-level nonempty classifier guard with continue",
            neutron=mutate(
                safe_neutron,
                "                if !unsupported.is_empty() {",
                "                if unsupported.is_empty() {",
            ),
        ),
        case(
            "attach classifier nested under false",
            "must run the exact classifier at top level before ownership sync",
            neutron=mutate(
                safe_neutron,
                "            for port in &attach {\n"
                "                let unsupported =\n"
                "                    unsupported_neutron_managed_domains(&port.managed_domains);\n"
                "                if !unsupported.is_empty() {\n"
                "                    record_unsupported(unsupported);\n"
                "                    continue;\n"
                "                }",
                "            for port in &attach {\n"
                "                if false {\n"
                "                    let unsupported =\n"
                "                        unsupported_neutron_managed_domains(&port.managed_domains);\n"
                "                    if !unsupported.is_empty() {\n"
                "                        record_unsupported(unsupported);\n"
                "                        continue;\n"
                "                    }\n"
                "                }",
            ),
        ),
        case(
            "domain reconcile uses another classifier",
            "must reuse unsupported_neutron_managed_domains",
            neutron=mutate(
                safe_neutron,
                "        async fn reconcile_neutron_domains(port: &Port) {\n"
                "            let unsupported =\n"
                "                unsupported_neutron_managed_domains(&port.managed_domains);",
                "        async fn reconcile_neutron_domains(port: &Port) {\n"
                "            let unsupported =\n"
                "                unsupported_reconcile_domains(&port.managed_domains);",
            ),
        ),
    ]
    for label, control, tap, neutron, expected in mutants:
        errors = _managed_projection_attach_migration_contract_errors(
            control, tap, neutron
        )
        if not any(expected in error for error in errors):
            raise SystemExit(
                "ERROR: managed attach-migration checker accepted %s: %s"
                % (label, errors)
            )
    print(
        "Managed projection attach-migration self-tests: OK (%d scenarios)"
        % (len(mutants) + 2)
    )


def _managed_authoritative_write_admission_contract_errors(
    control_plane_source,
    groups_handler_source,
    neutron_api_source,
    other_agent_sources="",
):
    """Return serialized local-write admission violations in stable order."""
    control_code = _blank_rust_non_code(control_plane_source)
    groups_code = _blank_rust_non_code(groups_handler_source)
    neutron_code = _blank_rust_non_code(neutron_api_source)
    other_agent_code = _blank_rust_non_code(other_agent_sources)
    errors = []

    def without_cfg_test_modules(code):
        """Blank complete cfg(test) modules before production-only scans."""
        chars = list(code)
        cursor = 0
        pattern = re.compile(
            r"#\s*\[\s*cfg\s*\(\s*test\s*\)\s*\]\s*mod\s+\w+\s*\{"
        )
        while True:
            module = pattern.search(code, cursor)
            if module is None:
                break
            opening = code.find("{", module.start(), module.end())
            closing = _rust_matching_brace_end(code, opening)
            if closing is None:
                break
            for index in range(module.start(), closing + 1):
                if chars[index] != "\n":
                    chars[index] = " "
            cursor = closing + 1
        return "".join(chars)

    control_production_code = without_cfg_test_modules(control_code)
    neutron_production_code = without_cfg_test_modules(neutron_code)
    other_production_code = without_cfg_test_modules(other_agent_code)

    # All structural readers below intentionally select one declaration.  A
    # duplicate production declaration can otherwise act as a cfg-disabled
    # decoy in front of the real implementation, so reject duplicates before
    # trusting any extracted body.
    production_control_functions = (
        "local_write_block_reason",
        "ensure_serialized_local_write_allowed",
        "requested_local_config_write_domains",
        "local_group_write_block_reason",
        "ensure_serialized_local_group_write_allowed",
        "ensure_local_group_write_allowed",
        "update_config",
        "add_policy",
        "delete_policy",
        "delete_policy_locked",
        "add_group",
        "delete_group",
        "delete_group_locked",
        "delete_policy_for_neutron_purge",
        "delete_group_for_neutron_purge",
        "flush_conntrack",
        "flush_conntrack_strict",
    )
    for function_name in production_control_functions:
        declarations = re.findall(
            r"\b(?:pub(?:\s*\([^)]*\))?\s+)?(?:async\s+)?fn\s+%s\s*\("
            % re.escape(function_name),
            control_production_code,
        )
        if len(declarations) > 1:
            errors.append(
                "production authoritative function %s must have one declaration without cfg decoys"
                % function_name
            )
    if len(
        re.findall(
            r"\b(?:pub(?:\s*\([^)]*\))?\s+)?(?:async\s+)?fn\s+"
            r"purge_neutron_acl\s*\(",
            neutron_production_code,
        )
    ) > 1:
        errors.append(
            "production Neutron purge orchestrator must have one declaration without cfg decoys"
        )

    def raw_function_body(function_name, code=None):
        search_code = control_code if code is None else code
        declaration = re.search(
            r"\b(?:pub(?:\s*\([^)]*\))?\s+)?(?:async\s+)?fn\s+%s"
            r"(?:\s*<[^>{}]*>)?\s*\(" % re.escape(function_name),
            search_code,
        )
        if declaration is None:
            return None
        opening = search_code.find("{", declaration.end())
        closing = _rust_matching_brace_end(search_code, opening)
        if opening < 0 or closing is None:
            return None
        return control_plane_source[opening + 1:closing]

    # Check the privileged compatibility boundary first.  The production RED
    # must fail here before the general classifier so a future GREEN cannot
    # accidentally route Neutron recovery through a newly blocked local API.
    for entry_name, label in (
        (
            "delete_policy_for_neutron_purge",
            "purpose-limited Neutron policy purge entry is missing",
        ),
        (
            "delete_group_for_neutron_purge",
            "purpose-limited Neutron group purge entry is missing",
        ),
    ):
        if raw_function_body(entry_name, control_production_code) is None:
            errors.append(label)

    classifier_name = "local_write_block_reason"
    classifier_parameters = _rust_function_parameters_from_blanked(
        control_production_code, classifier_name
    )
    classifier_body = _rust_function_body_from_blanked(
        control_production_code, classifier_name
    )
    classifier_raw = raw_function_body(classifier_name, control_production_code)
    if classifier_parameters is None or classifier_body is None:
        errors.append("managed authoritative local-write classifier is missing")
    else:
        for pattern, label in (
            (
                r"\bdomain\s*:\s*LocalWriteDomain\b",
                "the requested local-write domain",
            ),
            (
                r"\bpublication_mode\s*:\s*Option\s*<\s*"
                r"ManagedAclPublicationMode\s*>",
                "the current optional publication mode",
            ),
            (
                r"\bauthority\s*:\s*Option\s*<\s*&\s*"
                r"NeutronPortAuthority\s*>",
                "the current optional authority",
            ),
        ):
            if not re.search(pattern, classifier_parameters):
                errors.append(
                    "managed authoritative local-write classifier must accept %s"
                    % label
                )
        if not re.search(
            r"\(\s*Some\s*\(\s*ManagedAclPublicationMode\s*::\s*ManagedAcl\s*\)\s*,"
            r"\s*LocalWriteDomain\s*::\s*Acl\s*\)\s*=>\s*Some\s*\(\s*None\s*\)",
            classifier_body,
        ):
            errors.append(
                "ManagedAcl mode must block ACL writes even before authority commits"
            )
        if not re.search(
            r"\(\s*Some\s*\(\s*ManagedAclPublicationMode\s*::\s*ManagedAcl\s*\)\s*,"
            r"\s*LocalWriteDomain\s*::\s*Conntrack\s*\)\s*=>"
            r"\s*(?:\{\s*)?Some\s*\(\s*Some\s*\(",
            classifier_body,
        ) or classifier_raw is None or '"acl"' not in classifier_raw:
            errors.append(
                "ManagedAcl mode must block conntrack as an ACL dependency before authority commits"
            )
        authority_region = (
            classifier_body[classifier_body.find("authority"):]
            if "authority" in classifier_body
            else ""
        )
        selected_domain_block = re.search(
            r"if\s+authority\s*\.\s*managed_domains\s*\.\s*contains\s*"
            r"\(\s*domain_name\s*\)\s*\{\s*Some\s*\(\s*None\s*\)",
            authority_region,
        )
        conntrack_dependency_block = re.search(
            r"else\s+if\s+domain\s*==\s*LocalWriteDomain\s*::\s*Conntrack"
            r"[\s\S]*?managed_domains\s*\.\s*contains\s*\([^)]*\)\s*\{"
            r"\s*Some\s*\(\s*Some\s*\(",
            authority_region,
        )
        if (
            "domain.as_str()" not in authority_region
            or selected_domain_block is None
            or conntrack_dependency_block is None
            or classifier_raw is None
            or 'contains("acl")' not in classifier_raw
        ):
            errors.append(
                "committed authority must still block selected domains and the ACL conntrack dependency"
            )
        if not re.search(r"_\s*=>\s*authority\s*\.\s*and_then\s*\(", classifier_body):
            errors.append(
                "standalone mode without authority must retain local-write access"
            )
        match_expression = re.search(
            r"\bmatch\s*\(\s*publication_mode\s*,\s*domain\s*\)\s*\{",
            classifier_body,
        )
        match_opening = (
            classifier_body.find("{", match_expression.start())
            if match_expression is not None
            else -1
        )
        match_closing = _rust_matching_brace_end(classifier_body, match_opening)
        if (
            match_expression is None
            or match_closing is None
            or classifier_body[:match_expression.start()].strip()
            or classifier_body[match_closing + 1:].strip()
        ):
            errors.append(
                "managed authoritative classifier match must be its unique tail expression"
            )

    admission_name = "ensure_serialized_local_write_allowed"
    admission_parameters = _rust_function_parameters_from_blanked(
        control_production_code, admission_name
    )
    admission_body = _rust_function_body_from_blanked(
        control_production_code, admission_name
    )
    if admission_parameters is None or admission_body is None:
        errors.append("serialized authoritative local-write admission helper is missing")
    else:
        for pattern, label in (
            (r"\binstance\s*:\s*&\s*str\b", "instance"),
            (r"\bdomain\s*:\s*LocalWriteDomain\b", "domain"),
            (
                r"\bpublication_mode\s*:\s*Option\s*<\s*"
                r"ManagedAclPublicationMode\s*>",
                "publication mode",
            ),
            (
                r"\bauthority\s*:\s*Option\s*<\s*&\s*"
                r"NeutronPortAuthority\s*>",
                "authority",
            ),
        ):
            if not re.search(pattern, admission_parameters):
                errors.append(
                    "serialized local-write admission must accept the exact %s input"
                    % label
                )
        calls = _rust_named_call_arguments(admission_body, classifier_name)
        normalized = (
            [re.sub(r"\s+", "", argument) for argument in calls[0][1]]
            if len(calls) == 1
            else []
        )
        if normalized != ["domain", "publication_mode", "authority"]:
            errors.append(
                "serialized local-write admission must use the exact mode and authority classifier inputs"
            )
        if not re.search(
            r"if\s+let\s+Some\s*\(\s*dependency_of\s*\)\s*=\s*"
            r"local_write_block_reason\s*\(",
            admission_body,
        ) or "Ok(())" not in admission_body:
            errors.append(
                "serialized local-write admission must reject only the classifier's block reason"
            )
        for marker in (
            "ControlPlaneError::LocalWriteBlocked",
            "instance: instance.to_string()",
            "domain: domain.as_str().to_string()",
            "dependency_of",
        ):
            if marker not in admission_body:
                errors.append(
                    "serialized local-write admission must return LocalWriteBlocked with complete context"
                )
                break

    config_domains_name = "requested_local_config_write_domains"
    config_domains_body = _rust_function_body_from_blanked(
        control_production_code, config_domains_name
    )
    config_domain_pairs = (
        ("conntrack", "Conntrack"),
        ("monitoring", "Config"),
        ("acl", "Acl"),
        ("qos", "Qos"),
        ("mirror", "Mirror"),
        ("tcprt", "Tcprt"),
        ("ssl", "Ssl"),
    )
    if config_domains_body is None:
        errors.append("requested config domains classifier is missing")
    else:
        for option, domain in config_domain_pairs:
            if not re.search(
                r"\b%s\s*\.\s*is_some\s*\(\s*\)\s*\{[^{}]*"
                r"LocalWriteDomain\s*::\s*%s\b"
                % (re.escape(option), re.escape(domain)),
                config_domains_body,
            ):
                errors.append(
                    "requested config domains must map %s to LocalWriteDomain::%s"
                    % (option, domain)
                )
        pushed_domains = re.findall(
            r"\bdomains\s*\.\s*push\s*\(\s*"
            r"LocalWriteDomain\s*::\s*(\w+)\s*\)",
            config_domains_body,
        )
        if pushed_domains != [domain for _, domain in config_domain_pairs] or not re.search(
            r"\bdomains\s*$", config_domains_body
        ):
            errors.append(
                "requested config domains classifier must contain only the seven conditional mappings"
            )

    group_classifier_name = "local_group_write_block_reason"
    group_classifier_parameters = _rust_function_parameters_from_blanked(
        control_production_code, group_classifier_name
    )
    group_classifier_body = _rust_function_body_from_blanked(
        control_production_code, group_classifier_name
    )
    group_classifier_raw = raw_function_body(
        group_classifier_name, control_production_code
    )
    if group_classifier_parameters is None or group_classifier_body is None:
        errors.append("reserved Neutron group namespace classifier is missing")
    else:
        for pattern, label in (
            (r"\bgroup_name\s*:\s*&\s*str\b", "group name"),
            (
                r"\bpublication_mode\s*:\s*Option\s*<\s*"
                r"ManagedAclPublicationMode\s*>",
                "publication mode",
            ),
            (
                r"\bauthority\s*:\s*Option\s*<\s*&\s*"
                r"NeutronPortAuthority\s*>",
                "authority",
            ),
        ):
            if not re.search(pattern, group_classifier_parameters):
                errors.append(
                    "reserved group classifier must accept the exact %s input" % label
                )
        if (
            group_classifier_raw is None
            or 'starts_with("neutron:")' not in group_classifier_raw
            or "trim()" not in group_classifier_body
            or "to_ascii_lowercase()" not in group_classifier_body
        ):
            errors.append(
                "reserved group classifier must normalize and match the neutron: namespace"
            )
        compact_group_classifier = re.sub(r"\s+", "", group_classifier_body)
        if not re.search(
            r"publication_mode==Some\(ManagedAclPublicationMode::ManagedAcl\)"
            r"\|\|authority\.is_some\(\)",
            compact_group_classifier,
        ):
            errors.append(
                "reserved neutron: namespace must survive ManagedAcl with no committed authority"
            )
        if compact_group_classifier != (
            "group_name.trim().to_ascii_lowercase().starts_with()"
            "&&(publication_mode==Some(ManagedAclPublicationMode::ManagedAcl)"
            "||authority.is_some())"
        ):
            errors.append(
                "reserved group classifier boolean must be its unique tail expression"
            )

    group_admission_name = "ensure_serialized_local_group_write_allowed"
    group_admission_parameters = _rust_function_parameters_from_blanked(
        control_production_code, group_admission_name
    )
    group_admission_body = _rust_function_body_from_blanked(
        control_production_code, group_admission_name
    )
    if group_admission_parameters is None or group_admission_body is None:
        errors.append("serialized reserved-group admission helper is missing")
    else:
        for pattern, label in (
            (r"\binstance\s*:\s*&\s*str\b", "instance"),
            (r"\bgroup_name\s*:\s*&\s*str\b", "group name"),
            (
                r"\bpublication_mode\s*:\s*Option\s*<\s*"
                r"ManagedAclPublicationMode\s*>",
                "publication mode",
            ),
            (
                r"\bauthority\s*:\s*Option\s*<\s*&\s*"
                r"NeutronPortAuthority\s*>",
                "authority",
            ),
        ):
            if not re.search(pattern, group_admission_parameters):
                errors.append(
                    "serialized reserved-group admission must accept the exact %s input"
                    % label
                )
        calls = _rust_named_call_arguments(
            group_admission_body, group_classifier_name
        )
        normalized = (
            [re.sub(r"\s+", "", argument) for argument in calls[0][1]]
            if len(calls) == 1
            else []
        )
        if normalized != ["group_name", "publication_mode", "authority"]:
            errors.append(
                "serialized reserved-group admission must use the exact name, mode, and authority"
            )
        if not re.search(
            r"if\s+local_group_write_block_reason\s*\(", group_admission_body
        ) or "Ok(())" not in group_admission_body:
            errors.append(
                "serialized reserved-group admission must reject only classified reserved names"
            )
        if not all(
            marker in group_admission_body
            for marker in (
                "ControlPlaneError::LocalWriteBlocked",
                "instance: instance.to_string()",
                "LocalWriteDomain::Acl.as_str().to_string()",
                "dependency_of: None",
            )
        ):
            errors.append(
                "serialized reserved-group admission must return an ACL LocalWriteBlocked conflict"
            )

    lifecycle_pattern = re.compile(
        r"\blet\s+(?P<guard>_?[A-Za-z][A-Za-z0-9_]*)\s*=\s*"
        r"self\s*\.\s*lock_runtime_lifecycle\s*\(\s*\)\s*\.\s*await\s*;"
    )
    write_lock_pattern = re.compile(r"\.\s*write\s*\(\s*\)\s*\.\s*await\b")
    authority_binding_pattern = re.compile(r"\blet\s+authority\s*=")

    def authoritative_call(body, function_name):
        calls = _rust_named_call_arguments(body, function_name)
        return calls[0] if len(calls) == 1 else None

    def authority_snapshot_is_exact(body, start, end):
        statement_end = body.find(";", start, end)
        if statement_end < 0:
            return False
        region = body[start:statement_end]
        return all(
            re.search(pattern, region)
            for pattern in (
                r"\bself\s*\.\s*neutron_authorities\b",
                r"\.\s*read\s*\(\s*\)\s*\.\s*await",
                r"\.\s*get\s*\(\s*instance\s*\)",
                r"\.\s*cloned\s*\(\s*\)",
            )
        )

    def check_locked_entry(
        name,
        call_name,
        expected_arguments,
        effect_markers,
        delegate_name=None,
        expected_delegate_arguments=None,
    ):
        body = _rust_function_body_from_blanked(control_production_code, name)
        if body is None:
            errors.append("authoritative write entry %s is missing" % name)
            return
        lifecycle = lifecycle_pattern.search(body)
        instance = re.search(
            r"\bget_instance\s*\(\s*instance\s*\)\s*\.\s*await", body
        )
        write_lock = write_lock_pattern.search(body)
        authority = authority_binding_pattern.search(body)
        authority_bindings = list(authority_binding_pattern.finditer(body))
        call = authoritative_call(body, call_name)
        call_position = call[0] if call else -1
        if (
            lifecycle is None
            or instance is None
            or write_lock is None
            or authority is None
            or len(authority_bindings) != 1
            or call is None
            or not lifecycle.start()
            < instance.start()
            < write_lock.start()
            < authority.start()
            < call_position
        ):
            errors.append(
                "%s must serialize lifecycle, instance write lock, authority snapshot, then admission"
                % name
            )
            return
        if any(
            _rust_brace_depth_at(body, position) != 0
            for position in (
                lifecycle.start(),
                instance.start(),
                write_lock.start(),
                authority.start(),
                call_position,
            )
        ):
            errors.append(
                "%s lifecycle, lock, authority, and admission must be unconditional top-level steps"
                % name
            )
        if not authority_snapshot_is_exact(body, authority.start(), call_position):
            errors.append("%s must pass a current authority snapshot" % name)
        normalized = [re.sub(r"\s+", "", argument) for argument in call[1]]
        if normalized != expected_arguments:
            errors.append("%s must pass exact instance, domain, mode, and authority" % name)
        if not _rust_named_call_result_is_propagated(body, call_name, call_position):
            errors.append("%s must propagate the admission result" % name)
        before_admission = body[write_lock.end():call_position]
        if any(marker in before_admission for marker in effect_markers) or re.search(
            r"\b(?:state\s*\.\s*state\b|apply_add_rule\s*\(|"
            r"apply_remove_rule\s*\(|delete_port_set\s*\(|"
            r"clear_\w+_stats\s*\()",
            before_admission,
        ):
            errors.append("%s must reject before maps, state, WAL, or kernel effects" % name)
        effect_body = body
        effect_boundary = call_position
        delegate_position = -1
        if delegate_name is not None:
            delegate = authoritative_call(body, delegate_name)
            delegate_position = delegate[0] if delegate else -1
            effect_body = _rust_function_body_from_blanked(
                control_production_code, delegate_name
            )
            declaration = re.search(
                r"\b(?P<visibility>pub(?:\s*\([^)]*\))?\s+)?"
                r"(?:async\s+)?fn\s+%s\s*\(" % re.escape(delegate_name),
                control_production_code,
            )
            if (
                delegate is None
                or effect_body is None
                or declaration is None
                or declaration.group("visibility") is not None
                or delegate_position <= call_position
                or _rust_brace_depth_at(body, delegate_position) != 0
                or not _rust_named_call_result_is_propagated(
                    body, delegate_name, delegate_position
                )
            ):
                errors.append(
                    "%s must delegate after admission to the private shared %s body"
                    % (name, delegate_name)
                )
                effect_body = ""
            elif [
                re.sub(r"\s+", "", argument) for argument in delegate[1]
            ] != expected_delegate_arguments:
                errors.append(
                    "%s must pass exact state and operation inputs to %s"
                    % (name, delegate_name)
                )
            elif any(
                marker in effect_body
                for marker in (
                    "lock_runtime_lifecycle",
                    "neutron_authorities",
                    "ensure_serialized_local_write_allowed",
                    "ensure_serialized_local_group_write_allowed",
                )
            ):
                errors.append(
                    "%s private shared body must not relock or perform local-authority admission"
                    % name
                )
            effect_boundary = delegate_position
        if any(effect_body.find(marker) < 0 for marker in effect_markers):
            errors.append("%s checker fixture is missing its post-admission effect" % name)
        if re.search(r"\breturn\s+Ok\s*\(", body[:effect_boundary]):
            errors.append(
                "%s must not return success before its admitted transaction effects" % name
            )
        lifecycle_drop = re.search(
            r"\b(?:std\s*::\s*mem\s*::\s*)?drop\s*\(\s*%s\s*\)"
            % re.escape(lifecycle.group("guard")),
            body[lifecycle.end():],
        )
        state_drop = re.search(
            r"\b(?:std\s*::\s*mem\s*::\s*)?drop\s*\(\s*state\s*\)",
            body[write_lock.end():],
        )
        effects_after_state_drop = (
            state_drop is not None
            and write_lock.end() + state_drop.end() < effect_boundary
        )
        if lifecycle_drop is not None:
            errors.append("%s must hold the lifecycle guard to return" % name)
        if effects_after_state_drop:
            errors.append("%s must hold the instance guard through transaction effects" % name)

    policy_arguments = [
        "instance",
        "LocalWriteDomain::Acl",
        "Some(state.managed_acl_publication_mode)",
        "authority.as_ref()",
    ]
    for policy_name in ("add_policy", "delete_policy"):
        check_locked_entry(
            policy_name,
            admission_name,
            policy_arguments,
            (
                "check_runtime_maps_ready",
                "aria_core::ebpf_ops",
                "wal_append",
            ),
            "delete_policy_locked" if policy_name == "delete_policy" else None,
            (
                ["&mutstate", "src_group", "dst_group", "proto", "direction"]
                if policy_name == "delete_policy"
                else None
            ),
        )

    group_arguments = [
        "instance",
        "name",
        "Some(state.managed_acl_publication_mode)",
        "authority.as_ref()",
    ]
    for group_name in ("add_group", "delete_group"):
        check_locked_entry(
            group_name,
            group_admission_name,
            group_arguments,
            (
                "managed_local_projection_admission",
                "check_runtime_maps_ready",
            ),
            "delete_group_locked" if group_name == "delete_group" else None,
            (
                ["instance", "&mutstate", "name", "owner_prefix"]
                if group_name == "delete_group"
                else None
            ),
        )

    def function_visibility(function_name):
        declaration = re.search(
            r"\b(?P<visibility>pub(?:\s*\([^)]*\))?\s+)?"
            r"(?:async\s+)?fn\s+%s\s*\(" % re.escape(function_name),
            control_production_code,
        )
        if declaration is None:
            return None
        return (declaration.group("visibility") or "private").strip()

    def check_private_delete_body(function_name, effect_markers, maximum_depths):
        body = _rust_function_body_from_blanked(
            control_production_code, function_name
        )
        if body is None:
            errors.append("shared private delete body %s is missing" % function_name)
            return
        if function_visibility(function_name) != "private":
            errors.append("shared delete body %s must remain private" % function_name)
        for forbidden in (
            "lock_runtime_lifecycle",
            "neutron_authorities",
            "ensure_serialized_local_write_allowed",
            "ensure_serialized_local_group_write_allowed",
        ):
            if forbidden in body:
                errors.append(
                    "shared delete body %s must not relock or perform local-authority admission"
                    % function_name
                )
                break
        call_positions = {}
        for marker in effect_markers:
            if marker == "WalEntry::RemoveRule":
                continue
            calls = _rust_named_call_arguments(body, marker.rsplit("::", 1)[-1])
            call_positions[marker] = [call[0] for call in calls]
        if any(not call_positions.get(marker) for marker in call_positions):
            errors.append(
                "shared delete body %s is missing its real state, kernel, or persistence calls"
                % function_name
            )
        for marker, maximum_depth in maximum_depths.items():
            positions = (
                [
                    match.start()
                    for match in re.finditer(re.escape(marker), body)
                ]
                if marker == "WalEntry::RemoveRule"
                else call_positions.get(marker, [])
            )
            if not positions or min(
                _rust_brace_depth_at(body, position) for position in positions
            ) > maximum_depth:
                errors.append(
                    "shared delete body %s must execute %s on its real control path"
                    % (function_name, marker)
                )
        for fallible_call in (
            "check_runtime_maps_ready",
            "resolve_group_id",
            "requested_directions",
            "read_acl_active_bank",
            "apply_remove_rule",
            "managed_local_projection_admission",
            "require_managed_local_owner_prefix",
            "managed_general_state_mutations",
            "execute_managed_local_projection_transaction",
        ):
            calls = _rust_named_call_arguments(body, fallible_call)
            if calls and not any(
                _rust_named_call_result_is_propagated(body, fallible_call, call[0])
                for call in calls
            ):
                errors.append(
                    "shared delete body %s must propagate %s on its real control path"
                    % (function_name, fallible_call)
                )
        if function_name == "delete_policy_locked":
            wal_calls = _rust_named_call_arguments(body, "wal_append")
            if not any(
                any("WalEntry::RemoveRule" in argument for argument in call[1])
                for call in wal_calls
            ):
                errors.append(
                    "shared delete body delete_policy_locked must persist each real RemoveRule effect"
                )
        if re.search(r"\breturn\s+Ok\s*\(", body):
            errors.append(
                "shared delete body %s must not return success before its real effects"
                % function_name
            )
        if re.search(r"\bstringify\s*!", body):
            errors.append(
                "shared delete body %s must not satisfy effects through token-string decoys"
                % function_name
            )
        if re.search(r"\bif\s+(?:false|0\s*==\s*1|1\s*==\s*0)\b", body):
            errors.append(
                "shared delete body %s must not hide effects behind a constant-false branch"
                % function_name
            )

    check_private_delete_body(
        "delete_policy_locked",
        (
            "check_runtime_maps_ready",
            "resolve_group_id",
            "requested_directions",
            "read_acl_active_bank",
            "delete_policy_in_bank",
            "apply_remove_rule",
            "WalEntry::RemoveRule",
        ),
        {
            "check_runtime_maps_ready": 0,
            "resolve_group_id": 0,
            "requested_directions": 0,
            "read_acl_active_bank": 0,
            "delete_policy_in_bank": 1,
            "apply_remove_rule": 1,
            "WalEntry::RemoveRule": 1,
        },
    )
    check_private_delete_body(
        "delete_group_locked",
        (
            "managed_local_projection_admission",
            "require_managed_local_owner_prefix",
            "check_runtime_maps_ready",
            "managed_general_state_mutations",
            "execute_managed_local_projection_transaction",
        ),
        {
            "managed_local_projection_admission": 0,
            "require_managed_local_owner_prefix": 0,
            "check_runtime_maps_ready": 0,
            "managed_general_state_mutations": 0,
            "execute_managed_local_projection_transaction": 0,
        },
    )

    def check_purge_entry(entry_name, delegate_name, expected_arguments):
        body = _rust_function_body_from_blanked(control_production_code, entry_name)
        if body is None:
            return
        lifecycle = lifecycle_pattern.search(body)
        instance = re.search(
            r"\bget_instance\s*\(\s*instance\s*\)\s*\.\s*await", body
        )
        write_lock = write_lock_pattern.search(body)
        delegate = authoritative_call(body, delegate_name)
        delegate_position = delegate[0] if delegate else -1
        if function_visibility(entry_name) != "pub(crate)":
            errors.append("%s must remain crate-private" % entry_name)
        if (
            lifecycle is None
            or instance is None
            or write_lock is None
            or delegate is None
            or not lifecycle.start()
            < instance.start()
            < write_lock.start()
            < delegate_position
        ):
            errors.append(
                "%s must serialize lifecycle, instance write lock, then the shared delete body"
                % entry_name
            )
            return
        if any(
            _rust_brace_depth_at(body, position) != 0
            for position in (
                lifecycle.start(),
                instance.start(),
                write_lock.start(),
                delegate_position,
            )
        ):
            errors.append("%s serialization steps must be unconditional" % entry_name)
        normalized = [re.sub(r"\s+", "", argument) for argument in delegate[1]]
        if normalized != expected_arguments:
            errors.append("%s must pass exact arguments to %s" % (entry_name, delegate_name))
        if not _rust_named_call_result_is_propagated(
            body, delegate_name, delegate_position
        ):
            errors.append("%s must propagate its shared delete result" % entry_name)
        if re.search(r"\breturn\s+Ok\s*\(", body[:delegate_position]):
            errors.append(
                "%s must not return success before its shared delete body" % entry_name
            )
        for forbidden in (
            "neutron_authorities",
            "ensure_serialized_local_write_allowed",
            "ensure_serialized_local_group_write_allowed",
            ".delete_policy(",
            ".delete_group(",
        ):
            if forbidden in body:
                errors.append(
                    "%s must bypass only through its shared private delete body"
                    % entry_name
                )
                break
        if re.search(
            r"\b(?:std\s*::\s*mem\s*::\s*)?drop\s*\(\s*%s\s*\)"
            % re.escape(lifecycle.group("guard")),
            body[lifecycle.end():],
        ):
            errors.append("%s must hold lifecycle serialization to return" % entry_name)

    check_purge_entry(
        "delete_policy_for_neutron_purge",
        "delete_policy_locked",
        ["&mutstate", "src_group", "dst_group", "proto", "direction"],
    )
    check_purge_entry(
        "delete_group_for_neutron_purge",
        "delete_group_locked",
        ["instance", "&mutstate", "name", "Some(owner_prefix)"],
    )

    purge_group_body = _rust_function_body_from_blanked(
        control_production_code, "delete_group_for_neutron_purge"
    )
    purge_group_raw = raw_function_body(
        "delete_group_for_neutron_purge", control_production_code
    )
    if purge_group_body is not None:
        owner_bindings = list(
            re.finditer(r"\blet\s+(?:mut\s+)?owner_prefix\s*=", purge_group_body)
        )
        owner_statement_end = (
            purge_group_body.find(";", owner_bindings[0].end())
            if len(owner_bindings) == 1
            else -1
        )
        owner_statement_raw = (
            purge_group_raw[owner_bindings[0].start():owner_statement_end + 1]
            if purge_group_raw is not None and owner_statement_end >= 0
            else ""
        )
        exact_owner_binding = (
            re.fullmatch(
                r"\blet\s+owner_prefix\s*=\s*format!\s*\(\s*"
                r'"neutron:\{\}:"\s*,\s*port_id\s*\)\s*;\s*',
                owner_statement_raw,
            )
            if owner_statement_raw
            else None
        )
        owner_validation = re.search(
            r"if\s*!\s*name\s*\.\s*starts_with\s*\(\s*&\s*owner_prefix\s*\)",
            purge_group_body,
        )
        lifecycle = lifecycle_pattern.search(purge_group_body)
        if (
            purge_group_raw is None
            or len(owner_bindings) != 1
            or exact_owner_binding is None
            or owner_validation is None
            or lifecycle is None
            or not owner_bindings[0].start()
            < owner_validation.start()
            < lifecycle.start()
            or "ControlPlaneError::ValidationError" not in purge_group_body
            or len(
                re.findall(
                    r"(?<!let\s)(?<!mut\s)\bowner_prefix\s*=",
                    purge_group_body,
                )
            )
            != 0
        ):
            errors.append(
                "Neutron group purge entry must reject every name outside its exact port owner prefix"
            )

    privileged_callsite_code = (
        control_production_code
        + "\n"
        + neutron_production_code
        + "\n"
        + other_production_code
    )
    for entry_name in (
        "delete_policy_for_neutron_purge",
        "delete_group_for_neutron_purge",
    ):
        callsites = re.findall(
            r"(?:\.|::)\s*%s\b" % re.escape(entry_name),
            privileged_callsite_code,
        )
        if len(callsites) != 1:
            errors.append(
                "%s must have exactly one production caller in purge_neutron_acl"
                % entry_name
            )

    purge_body = _rust_function_body_from_blanked(
        neutron_production_code, "purge_neutron_acl"
    )
    if purge_body is None:
        errors.append("Neutron ACL purge orchestrator is missing")
    else:
        def top_level_statement_end(body, start):
            for position in range(start, len(body)):
                if body[position] == ";" and _rust_brace_depth_at(body, position) == 0:
                    return position
            return -1

        policy_targets_binding = re.search(
            r"\blet\s+policy_delete_targets\s*=", purge_body
        )
        policy_targets_statement_end = (
            top_level_statement_end(purge_body, policy_targets_binding.end())
            if policy_targets_binding is not None
            else -1
        )
        policy_targets_statement = (
            purge_body[
                policy_targets_binding.start():policy_targets_statement_end + 1
            ]
            if policy_targets_statement_end >= 0
            else ""
        )
        target_builder_calls = _rust_named_call_arguments(
            policy_targets_statement,
            "acl_policy_delete_targets_for_neutron_domain",
        )
        target_builder = (
            target_builder_calls[0] if len(target_builder_calls) == 1 else None
        )
        target_builder_opening = (
            policy_targets_statement.find("(", target_builder[0])
            if target_builder is not None
            else -1
        )
        target_builder_arguments = (
            _rust_parenthesized_body_at(
                policy_targets_statement, target_builder_opening
            )
            if target_builder_opening >= 0
            else None
        )
        target_builder_closing = (
            target_builder_opening + len(target_builder_arguments) + 1
            if target_builder_arguments is not None
            else -1
        )
        target_builder_tail = (
            policy_targets_statement[target_builder_closing + 1:].strip()
            if target_builder_closing >= 0
            else ""
        )
        groups_binding = re.search(r"\blet\s+groups\s*=", purge_body)
        groups_statement_end = (
            top_level_statement_end(purge_body, groups_binding.end())
            if groups_binding is not None
            else -1
        )
        groups_statement = (
            purge_body[groups_binding.start():groups_statement_end + 1]
            if groups_statement_end >= 0
            else ""
        )
        list_group_calls = _rust_named_call_arguments(groups_statement, "list_groups")
        list_group_call = (
            list_group_calls[0] if len(list_group_calls) == 1 else None
        )
        list_group_opening = (
            groups_statement.find("(", list_group_call[0])
            if list_group_call is not None
            else -1
        )
        list_group_arguments = (
            _rust_parenthesized_body_at(groups_statement, list_group_opening)
            if list_group_opening >= 0
            else None
        )
        list_group_closing = (
            list_group_opening + len(list_group_arguments) + 1
            if list_group_arguments is not None
            else -1
        )
        list_group_tail = (
            groups_statement[list_group_closing + 1:].strip()
            if list_group_closing >= 0
            else ""
        )
        def exact_named_for_loop(binding_name, iterable_name):
            matches = list(
                re.finditer(
                    r"\bfor\s+%s\s+in\s+%s\s*\{"
                    % (re.escape(binding_name), re.escape(iterable_name)),
                    purge_body,
                )
            )
            if len(matches) != 1:
                return None, -1, None
            match = matches[0]
            opening = purge_body.find("{", match.start(), match.end())
            closing = _rust_matching_brace_end(purge_body, opening)
            if closing is None:
                return None, match.start(), None
            return purge_body[opening + 1:closing], match.start(), closing

        policy_loop, policy_loop_start, policy_loop_end = exact_named_for_loop(
            "target", "policy_delete_targets"
        )
        group_loop, group_loop_start, group_loop_end = exact_named_for_loop(
            "group", "groups"
        )
        policy_loop_calls = (
            _rust_named_call_arguments(
                policy_loop, "delete_policy_for_neutron_purge"
            )
            if policy_loop is not None
            else []
        )
        group_loop_calls = (
            _rust_named_call_arguments(
                group_loop, "delete_group_for_neutron_purge"
            )
            if group_loop is not None
            else []
        )
        policy_call = (
            policy_loop_calls[0] if len(policy_loop_calls) == 1 else None
        )
        group_call = group_loop_calls[0] if len(group_loop_calls) == 1 else None
        global_policy_calls = _rust_named_call_arguments(
            purge_body, "delete_policy_for_neutron_purge"
        )
        global_group_calls = _rust_named_call_arguments(
            purge_body, "delete_group_for_neutron_purge"
        )
        global_policy = (
            global_policy_calls[0] if len(global_policy_calls) == 1 else None
        )
        global_group = (
            global_group_calls[0] if len(global_group_calls) == 1 else None
        )
        list_groups = purge_body.find("list_groups")
        positive_filter = (
            re.search(
                r"\bif\s+is_neutron_acl_group\s*\(\s*port_id\s*,\s*"
                r"&\s*group\s*\.\s*name\s*\)\s*\{",
                group_loop,
            )
            if group_loop is not None
            else None
        )
        filter_block_opening = (
            group_loop.find("{", positive_filter.start())
            if positive_filter is not None
            else -1
        )
        filter_block_closing = (
            _rust_matching_brace_end(group_loop, filter_block_opening)
            if filter_block_opening >= 0
            else None
        )
        if (
            policy_targets_binding is None
            or len(
                re.findall(r"\blet\s+policy_delete_targets\s*=", purge_body)
            )
            != 1
            or target_builder is None
            or [re.sub(r"\s+", "", arg) for arg in target_builder[1]]
            != ["&rules", "&group_names_by_id"]
            or target_builder_tail != ";"
            or re.search(
                r"\bpolicy_delete_targets\s*\.\s*"
                r"(?:truncate|retain|pop|remove|drain|clear)\s*\(",
                purge_body[policy_targets_statement_end + 1:],
            )
            or groups_binding is None
            or len(re.findall(r"\blet\s+groups\s*=", purge_body)) != 1
            or list_group_call is None
            or [re.sub(r"\s+", "", arg) for arg in list_group_call[1]]
            != ["ifname"]
            or re.fullmatch(
                r"\.\s*await\s*(?:\.\s*map_err\s*\(\s*"
                r"\|\s*\w+\s*\|\s*\w+\s*\.\s*to_string\s*\(\s*\)\s*"
                r"\)\s*)?\?\s*;",
                list_group_tail,
            )
            is None
            or re.search(
                r"\.\s*(?:take|filter|truncate|retain|pop|remove|drain|clear)\s*\(",
                groups_statement,
            )
            or re.search(
                r"\bgroups\s*\.\s*"
                r"(?:truncate|retain|pop|remove|drain|clear)\s*\(",
                purge_body[groups_statement_end + 1:],
            )
            or policy_loop is None
            or group_loop is None
            or policy_loop_end is None
            or group_loop_end is None
            or _rust_brace_depth_at(purge_body, policy_loop_start) != 0
            or _rust_brace_depth_at(purge_body, group_loop_start) != 0
            or policy_call is None
            or group_call is None
            or global_policy is None
            or global_group is None
            or positive_filter is None
            or list_groups < 0
            or not global_policy[0] < list_groups < global_group[0]
            or filter_block_closing is None
            or not filter_block_opening < group_call[0] < filter_block_closing
            or _rust_brace_depth_at(policy_loop, policy_call[0]) != 0
            or _rust_brace_depth_at(group_loop, positive_filter.start()) != 0
            or _rust_brace_depth_at(group_loop, group_call[0]) != 1
            or re.search(
                r"\bif\s+(?:false|0\s*==\s*1|1\s*==\s*0)\b",
                purge_body,
            )
            or re.search(r"\breturn\b", purge_body)
            or re.search(r"\b(?:break|continue)\b", policy_loop)
            or re.search(r"\b(?:break|continue)\b", group_loop)
            or [re.sub(r"\s+", "", arg) for arg in policy_call[1]]
            != [
                "ifname",
                "&target.src_group",
                "&target.dst_group",
                "target.proto",
                "target.direction",
            ]
            or [re.sub(r"\s+", "", arg) for arg in group_call[1]]
            != ["ifname", "port_id", "&group.name"]
            or not _rust_named_call_result_is_propagated(
                policy_loop,
                "delete_policy_for_neutron_purge",
                policy_call[0] if policy_call else -1,
            )
            or not _rust_named_call_result_is_propagated(
                group_loop,
                "delete_group_for_neutron_purge",
                group_call[0] if group_call else -1,
            )
        ):
            errors.append(
                "purge_neutron_acl must preserve policy-first and exact-owner cleanup through privileged entries"
            )
        if (
            re.search(r"\.\s*delete_policy\s*\(", purge_body)
            or re.search(r"\.\s*delete_group\s*\(", purge_body)
            or "lock_runtime_lifecycle" in purge_body
        ):
            errors.append(
                "purge_neutron_acl must not call local delete APIs or acquire a reentrant lifecycle lock"
            )

    def check_conntrack_entry(function_name, strict):
        body = _rust_function_body_from_blanked(
            control_production_code, function_name
        )
        if body is None:
            errors.append("conntrack write entry %s is missing" % function_name)
            return
        lifecycle = lifecycle_pattern.search(body)
        instance = re.search(
            r"\bget_instance\s*\(\s*instance\s*\)\s*\.\s*await", body
        )
        instance_lock = re.search(
            r"\.\s*(?:read|write)\s*\(\s*\)\s*\.\s*await", body
        )
        effect_name = "scrub_ct_tables_strict" if strict else "ct_flush"
        effect = authoritative_call(body, effect_name)
        effect_position = effect[0] if effect else -1
        if (
            lifecycle is None
            or instance is None
            or instance_lock is None
            or effect is None
        ):
            errors.append(
                "%s must serialize lifecycle and instance access around its conntrack effect"
                % function_name
            )
            return
        effect_opening = body.find("(", effect_position)
        effect_arguments = _rust_parenthesized_body_at(body, effect_opening)
        effect_closing = (
            effect_opening + len(effect_arguments) + 1
            if effect_arguments is not None
            else -1
        )
        effect_tail = body[effect_closing + 1:].strip() if effect_closing >= 0 else ""
        propagated_tail = re.fullmatch(
            r"\.\s*map_err\s*\(\s*(?:"
            r"ControlPlaneError\s*::\s*KernelError|"
            r"\|\s*\w+\s*\|\s*ControlPlaneError\s*::\s*KernelError\s*"
            r"\(\s*\w+\s*\)"
            r")\s*\)\s*;?",
            effect_tail,
        )
        if [re.sub(r"\s+", "", argument) for argument in effect[1]] != [
            "state.map_runtime()"
        ] or propagated_tail is None:
            errors.append(
                "%s must propagate the exact tap-scoped conntrack effect"
                % function_name
            )
        if re.search(r"\breturn\s+Ok\s*\(", body[:effect_position]):
            errors.append(
                "%s must not return success before its conntrack effect"
                % function_name
            )
        if re.search(
            r"\bif\s+(?:false|0\s*==\s*1|1\s*==\s*0)\b|\bstringify\s*!",
            body,
        ):
            errors.append(
                "%s must keep its conntrack effect on the real control path"
                % function_name
            )
        if strict:
            if function_visibility(function_name) != "pub(crate)":
                errors.append("strict conntrack flush must remain crate-private")
            if any(
                marker in body
                for marker in (
                    "neutron_authorities",
                    "ensure_serialized_local_write_allowed",
                    "ensure_local_write_allowed",
                    "ct_flush(",
                )
            ):
                errors.append(
                    "strict conntrack flush must bypass local admission and use only strict scrub"
                )
            ordered = (
                lifecycle.start()
                < instance.start()
                < instance_lock.start()
                < effect_position
            )
        else:
            authority_bindings = list(authority_binding_pattern.finditer(body))
            authority = authority_bindings[0] if authority_bindings else None
            admission = authoritative_call(body, admission_name)
            admission_position = admission[0] if admission else -1
            ordered = (
                authority is not None
                and len(authority_bindings) == 1
                and admission is not None
                and lifecycle.start()
                < instance.start()
                < instance_lock.start()
                < authority.start()
                < admission_position
                < effect_position
            )
            if admission is not None and [
                re.sub(r"\s+", "", argument) for argument in admission[1]
            ] != [
                "instance",
                "LocalWriteDomain::Conntrack",
                "Some(state.managed_acl_publication_mode)",
                "authority.as_ref()",
            ]:
                errors.append(
                    "public conntrack flush must admit the exact CT dependency with current mode and authority"
                )
            if admission is not None and not _rust_named_call_result_is_propagated(
                body, admission_name, admission_position
            ):
                errors.append("public conntrack flush must propagate local admission")
            if (
                authority is not None
                and len(authority_bindings) == 1
                and admission is not None
                and not authority_snapshot_is_exact(
                    body, authority.start(), admission_position
                )
            ):
                errors.append(
                    "public conntrack flush must pass a current authority snapshot"
                )
            if (
                authority is not None
                and admission is not None
                and (
                    _rust_brace_depth_at(body, authority.start()) != 0
                    or _rust_brace_depth_at(body, admission_position) != 0
                )
            ):
                errors.append(
                    "public conntrack flush authority and admission must be unconditional"
                )
        if not ordered:
            errors.append(
                "%s must perform admission and effects in serialized order" % function_name
            )
        elif any(
            _rust_brace_depth_at(body, position) != 0
            for position in (
                lifecycle.start(),
                instance.start(),
                instance_lock.start(),
                effect_position,
            )
        ):
            errors.append(
                "%s serialization and conntrack effect must be unconditional"
                % function_name
            )
        if re.search(
            r"\b(?:std\s*::\s*mem\s*::\s*)?drop\s*\(\s*%s\s*\)"
            % re.escape(lifecycle.group("guard")),
            body[lifecycle.end():],
        ):
            errors.append("%s must hold lifecycle serialization to return" % function_name)

    check_conntrack_entry("flush_conntrack", strict=False)
    check_conntrack_entry("flush_conntrack_strict", strict=True)

    config_body = _rust_function_body_from_blanked(
        control_production_code, "update_config"
    )
    if config_body is None:
        errors.append("authoritative write entry update_config is missing")
    else:
        lifecycle = lifecycle_pattern.search(config_body)
        instance = re.search(
            r"\bget_instance\s*\(\s*instance\s*\)\s*\.\s*await", config_body
        )
        mode_bindings = list(
            re.finditer(r"\blet\s+publication_mode\s*=", config_body)
        )
        mode = mode_bindings[0] if mode_bindings else None
        authority_bindings = list(authority_binding_pattern.finditer(config_body))
        authority = authority_bindings[0] if authority_bindings else None
        requested_call = authoritative_call(config_body, config_domains_name)
        loop = re.search(r"\bfor\s+domain\s+in\s+requested_domains\s*\{", config_body)
        admission_call = authoritative_call(config_body, admission_name)
        admission_position = admission_call[0] if admission_call else -1
        if (
            lifecycle is None
            or instance is None
            or mode is None
            or len(mode_bindings) != 1
            or authority is None
            or len(authority_bindings) != 1
            or requested_call is None
            or loop is None
            or admission_call is None
            or not lifecycle.start()
            < instance.start()
            < mode.start()
            < authority.start()
            < requested_call[0]
            < loop.start()
            <= admission_position
        ):
            errors.append(
                "update_config must snapshot mode and authority under lifecycle before all requested-domain admissions"
            )
        else:
            if any(
                _rust_brace_depth_at(config_body, position) != 0
                for position in (
                    lifecycle.start(),
                    instance.start(),
                    mode.start(),
                    authority.start(),
                    requested_call[0],
                    loop.start(),
                )
            ):
                errors.append(
                    "update_config lifecycle, snapshots, and requested-domain loop must be top-level"
                )
            mode_region = config_body[mode.start():authority.start()]
            if not all(
                re.search(pattern, mode_region)
                for pattern in (
                    r"\.\s*read\s*\(\s*\)\s*\.\s*await",
                    r"\bmanaged_acl_publication_mode\b",
                )
            ):
                errors.append(
                    "update_config must snapshot the real publication mode before authority"
                )
            if not authority_snapshot_is_exact(
                config_body, authority.start(), requested_call[0]
            ):
                errors.append("update_config must pass a current authority snapshot")
            requested_arguments = [
                re.sub(r"\s+", "", argument) for argument in requested_call[1]
            ]
            if requested_arguments != [
                "conntrack",
                "monitoring",
                "acl",
                "qos",
                "mirror",
                "tcprt",
                "ssl",
            ]:
                errors.append(
                    "update_config must classify every requested config domain exactly once"
                )
            admission_arguments = [
                re.sub(r"\s+", "", argument) for argument in admission_call[1]
            ]
            if admission_arguments != [
                "instance",
                "domain",
                "Some(publication_mode)",
                "authority.as_ref()",
            ]:
                errors.append(
                    "update_config must admit each domain with exact instance, mode, and authority"
                )
            if not _rust_named_call_result_is_propagated(
                config_body, admission_name, admission_position
            ):
                errors.append("update_config must propagate every admission result")
            loop_body = _rust_named_for_loop_body(
                config_body, "domain", "requested_domains"
            )
            loop_admission_calls = (
                _rust_named_call_arguments(loop_body, admission_name)
                if loop_body is not None
                else []
            )
            loop_call_position = (
                loop_admission_calls[0][0]
                if len(loop_admission_calls) == 1
                else -1
            )
            loop_call_opening = (
                loop_body.find("(", loop_call_position)
                if loop_call_position >= 0
                else -1
            )
            loop_call_arguments = (
                _rust_parenthesized_body_at(loop_body, loop_call_opening)
                if loop_call_opening >= 0
                else None
            )
            loop_call_closing = (
                loop_call_opening + len(loop_call_arguments) + 1
                if loop_call_arguments is not None
                else -1
            )
            if (
                loop_body is None
                or len(loop_admission_calls) != 1
                or re.search(r"\b(?:break|continue|return)\b", loop_body)
                or _rust_brace_depth_at(loop_body, loop_call_position) != 0
                or loop_body[:loop_call_position].strip()
                or loop_body[loop_call_closing + 1:].strip() != "?;"
            ):
                errors.append(
                    "update_config must admit every requested domain without skipping"
                )
            write_effect = write_lock_pattern.search(config_body)
            first_effects = [
                position
                for position in (
                    config_body.find("set_ssl_global_config"),
                    write_effect.start() if write_effect is not None else -1,
                    config_body.find("check_runtime_maps_ready"),
                    config_body.find("aria_core::ebpf_ops::update_runtime_config"),
                    config_body.find("wal_append_strict"),
                )
                if position >= 0
            ]
            if not first_effects or min(first_effects) < admission_position:
                errors.append(
                    "update_config must reject every requested domain before SSL, maps, state, WAL, or kernel effects"
                )
        if lifecycle is not None and re.search(
            r"\b(?:std\s*::\s*mem\s*::\s*)?drop\s*\(\s*%s\s*\)"
            % re.escape(lifecycle.group("guard")),
            config_body[lifecycle.end():],
        ):
            errors.append("update_config must hold the lifecycle guard to return")

    for handler_name in ("add_group", "delete_group"):
        handler_body = _rust_function_body_from_blanked(groups_code, handler_name)
        preflight_calls = (
            _rust_named_call_arguments(
                handler_body, "ensure_local_group_write_allowed"
            )
            if handler_body is not None
            else []
        )
        preflight = preflight_calls[0][0] if len(preflight_calls) == 1 else -1
        control_call = (
            handler_body.find("cp.%s" % handler_name)
            if handler_body is not None
            else -1
        )
        propagated = (
            _rust_named_call_result_is_propagated(
                handler_body,
                "ensure_local_group_write_allowed",
                preflight,
            )
            if preflight >= 0
            else False
        )
        if not propagated and preflight >= 0:
            prefix = handler_body[max(0, preflight - 180):preflight]
            binding = re.search(
                r"\bif\s+let\s+Err\s*\(\s*(\w+)\s*\)\s*=\s*cp\s*\.\s*$",
                prefix,
            )
            call_opening = handler_body.find("(", preflight)
            call_arguments = _rust_parenthesized_body_at(
                handler_body, call_opening
            )
            call_closing = (
                call_opening + len(call_arguments) + 1
                if call_arguments is not None
                else -1
            )
            await_block = (
                re.match(r"\s*\.\s*await\s*\{", handler_body[call_closing + 1:])
                if call_closing >= 0
                else None
            )
            if binding is not None and await_block is not None:
                block_opening = handler_body.find("{", call_closing + 1)
                error_block = _rust_braced_body_at(handler_body, block_opening) or ""
                propagated = bool(
                    re.search(
                        r"\breturn\s+Err\s*\(\s*err_response\s*\(\s*%s\s*\)\s*\)"
                        % re.escape(binding.group(1)),
                        error_block,
                    )
                )
        if not 0 <= preflight < control_call or not propagated:
            errors.append(
                "%s handler must propagate its reserved-namespace preflight before the serialized second guard"
                % handler_name
            )

    test_specs = {
        "domain_authority_managed_acl_policy_write_add_blocks_before_authority_commit": {
            "calls": (
                (
                    "add_error",
                    "add_policy",
                    'self::assert_local_write_blocked(add_error,instance,"acl",None);',
                ),
            ),
            "raw": (),
        },
        "domain_authority_managed_acl_policy_write_delete_blocks_before_authority_commit": {
            "calls": (
                (
                    "delete_error",
                    "delete_policy",
                    'self::assert_local_write_blocked(delete_error,instance,"acl",None);',
                ),
            ),
            "raw": (),
        },
        "domain_authority_managed_acl_config_acl_blocks_before_authority_commit": {
            "calls": (
                (
                    "error",
                    "update_config",
                    'self::assert_local_write_blocked(error,instance,"acl",None);',
                ),
            ),
            "raw": ("Some(false)",),
        },
        "domain_authority_managed_acl_config_conntrack_blocks_before_authority_commit": {
            "calls": (
                (
                    "error",
                    "update_config",
                    'self::assert_local_write_blocked(error,instance,"conntrack",Some("acl"));',
                ),
            ),
            "raw": ("Some(false)",),
        },
        "domain_authority_managed_acl_config_monitoring_remains_local_before_authority_commit": {
            "calls": (
                (
                    "error",
                    "update_config",
                    "self::assert_not_local_write_blocked(error,503);",
                ),
            ),
            "raw": ("Some(false)",),
        },
        "domain_authority_managed_acl_group_namespace_survives_missing_authority": {
            "calls": (
                (
                    "add_error",
                    "add_group",
                    'self::assert_local_write_blocked(add_error,instance,"acl",None);',
                ),
                (
                    "delete_error",
                    "delete_group",
                    'self::assert_local_write_blocked(delete_error,instance,"acl",None);',
                ),
            ),
            "raw": ('"neutron:new"', '"neutron:owned"'),
        },
        "domain_authority_standalone_without_authority_preserves_policy_and_config_admission": {
            "calls": (
                (
                    "add_error",
                    "add_policy",
                    "self::assert_not_local_write_blocked(add_error,503);",
                ),
                (
                    "delete_error",
                    "delete_policy",
                    "self::assert_not_local_write_blocked(delete_error,503);",
                ),
                (
                    "acl_error",
                    "update_config",
                    "self::assert_not_local_write_blocked(acl_error,503);",
                ),
                (
                    "conntrack_error",
                    "update_config",
                    "self::assert_not_local_write_blocked(conntrack_error,503);",
                ),
            ),
            "raw": (
                "ManagedAclPublicationMode::StandaloneCompatibility",
                "ManagedProjectionHealth::Unverified",
            ),
        },
        "domain_authority_managed_acl_without_authority_allows_non_reserved_group_name": {
            "calls": (
                (
                    "error",
                    "add_group",
                    "self::assert_not_local_write_blocked(error,503);",
                ),
            ),
            "raw": ('"local:qos"',),
        },
        "domain_authority_committed_qos_blocks_config_at_real_entry": {
            "calls": (
                (
                    "error",
                    "update_config",
                    'self::assert_local_write_blocked(error,instance,"qos",None);',
                ),
            ),
            "raw": (
                "mark_neutron_port_authority",
                '"qos"',
                "Some(false)",
            ),
        },
    }
    tests_module = re.search(
        r"#\s*\[\s*cfg\s*\(\s*test\s*\)\s*\]\s*mod\s+tests\s*\{",
        control_code,
    )
    tests_body = None
    tests_module_prefix = ""
    if tests_module is not None:
        tests_module_prefix = control_code[:tests_module.start()].rstrip()
        tests_opening = control_code.find("{", tests_module.start())
        tests_body = _rust_braced_body_at(control_code, tests_opening)
    if (
        tests_module is None
        or not tests_module_prefix
        or tests_module_prefix[-1] not in "{}"
        or (tests_body or "").lstrip().startswith("#![")
    ):
        errors.append(
            "managed authoritative regression test module must have only its active cfg(test) gate"
        )

    blocked_assertion_name = "assert_local_write_blocked"
    blocked_assertion_parameters = (
        _rust_function_parameters_from_blanked(tests_body, blocked_assertion_name)
        if tests_body is not None
        else None
    )
    blocked_assertion_body = (
        _rust_function_body_from_blanked(tests_body, blocked_assertion_name)
        if tests_body is not None
        else None
    )
    blocked_status = (
        re.search(
            r"assert_eq!\s*\(\s*error\s*\.\s*status_code\s*\(\s*\)\s*,\s*409\s*\)",
            blocked_assertion_body or "",
        )
    )
    blocked_match = re.search(
        r"\bmatch\s+error\s*\{", blocked_assertion_body or ""
    )
    blocked_parameter_patterns = (
        r"\berror\s*:\s*ControlPlaneError\b",
        r"\bexpected_instance\s*:\s*&\s*str\b",
        r"\bexpected_domain\s*:\s*&\s*str\b",
        r"\bexpected_dependency\s*:\s*Option\s*<\s*&\s*str\s*>",
    )
    blocked_body_patterns = (
        r"ControlPlaneError\s*::\s*LocalWriteBlocked\s*\{[^}]*"
        r"\binstance\b[^}]*\bdomain\b[^}]*\bdependency_of\b[^}]*\}",
        r"assert_eq!\s*\(\s*instance\s*,\s*expected_instance\s*\)",
        r"assert_eq!\s*\(\s*domain\s*,\s*expected_domain\s*\)",
        r"assert_eq!\s*\(\s*dependency_of\s*\.\s*as_deref\s*\(\s*\)\s*,"
        r"\s*expected_dependency\s*\)",
        r"\bother\s*=>\s*panic!\s*\(",
    )
    blocked_variant = re.search(
        r"ControlPlaneError\s*::\s*LocalWriteBlocked\s*\{[^}]*\}"
        r"\s*=>\s*\{",
        blocked_assertion_body or "",
    )
    blocked_variant_opening = (
        (blocked_assertion_body or "").rfind(
            "{", blocked_variant.start(), blocked_variant.end()
        )
        if blocked_variant is not None
        else -1
    )
    blocked_variant_body = (
        _rust_braced_body_at(blocked_assertion_body, blocked_variant_opening)
        if blocked_assertion_body is not None and blocked_variant_opening >= 0
        else None
    )
    compact_blocked_variant_body = re.sub(
        r"\s+", "", blocked_variant_body or ""
    )
    expected_blocked_variant_body = (
        "assert_eq!(instance,expected_instance);"
        "assert_eq!(domain,expected_domain);"
        "assert_eq!(dependency_of.as_deref(),expected_dependency);"
    )
    if (
        tests_body is None
        or len(
            re.findall(
                r"\bfn\s+%s\s*\(" % blocked_assertion_name, tests_body
            )
        )
        != 1
        or blocked_assertion_parameters is None
        or not all(
            re.search(pattern, blocked_assertion_parameters)
            for pattern in blocked_parameter_patterns
        )
        or blocked_assertion_body is None
        or blocked_status is None
        or blocked_match is None
        or blocked_status.start() >= blocked_match.start()
        or _rust_brace_depth_at(blocked_assertion_body, blocked_status.start()) != 0
        or _rust_brace_depth_at(blocked_assertion_body, blocked_match.start()) != 0
        or not all(
            re.search(pattern, blocked_assertion_body)
            for pattern in blocked_body_patterns
        )
        or blocked_variant is None
        or _rust_brace_depth_at(
            blocked_assertion_body, blocked_variant.start()
        )
        != 1
        or compact_blocked_variant_body != expected_blocked_variant_body
        or re.search(r"\b(?:if|return)\b", blocked_assertion_body)
    ):
        errors.append(
            "managed authoritative blocked assertion helper must enforce status and exact LocalWriteBlocked context"
        )

    allowed_assertion_name = "assert_not_local_write_blocked"
    allowed_assertion_parameters = (
        _rust_function_parameters_from_blanked(tests_body, allowed_assertion_name)
        if tests_body is not None
        else None
    )
    allowed_assertion_body = (
        _rust_function_body_from_blanked(tests_body, allowed_assertion_name)
        if tests_body is not None
        else None
    )
    allowed_status = re.search(
        r"assert_eq!\s*\(\s*error\s*\.\s*status_code\s*\(\s*\)\s*,"
        r"\s*expected_status\s*\)",
        allowed_assertion_body or "",
    )
    allowed_match = re.search(
        r"assert!\s*\(\s*!\s*matches!\s*\(\s*error\s*,"
        r"\s*ControlPlaneError\s*::\s*LocalWriteBlocked\s*\{\s*\.\.\s*\}\s*\)",
        allowed_assertion_body or "",
    )
    if (
        tests_body is None
        or len(
            re.findall(
                r"\bfn\s+%s\s*\(" % allowed_assertion_name, tests_body
            )
        )
        != 1
        or allowed_assertion_parameters is None
        or not re.search(
            r"\berror\s*:\s*ControlPlaneError\b", allowed_assertion_parameters
        )
        or not re.search(
            r"\bexpected_status\s*:\s*u16\b", allowed_assertion_parameters
        )
        or allowed_assertion_body is None
        or allowed_status is None
        or allowed_match is None
        or allowed_status.start() >= allowed_match.start()
        or _rust_brace_depth_at(allowed_assertion_body, allowed_status.start()) != 0
        or _rust_brace_depth_at(allowed_assertion_body, allowed_match.start()) != 0
        or re.search(r"\b(?:if|return)\b|\|\||&&", allowed_assertion_body)
    ):
        errors.append(
            "managed authoritative allowed assertion helper must enforce status and reject LocalWriteBlocked"
        )

    fixture_name = "install_verified_managed_acl_instance_without_authority"
    fixture_parameters = (
        _rust_function_parameters_from_blanked(tests_body, fixture_name)
        if tests_body is not None
        else None
    )
    fixture_body = (
        _rust_function_body_from_blanked(tests_body, fixture_name)
        if tests_body is not None
        else None
    )
    fixture_load = re.search(
        r"\blet\s+mut\s+state\s*=\s*stopped_wal_instance_state\s*"
        r"\(\s*test_name\s*\)\s*\.\s*await\s*;",
        fixture_body or "",
    )
    fixture_mode = re.search(
        r"\bstate\s*\.\s*managed_acl_publication_mode\s*=\s*"
        r"ManagedAclPublicationMode\s*::\s*ManagedAcl\s*;",
        fixture_body or "",
    )
    fixture_health = re.search(
        r"\bstate\s*\.\s*managed_projection_health\s*=\s*"
        r"ManagedProjectionHealth\s*::\s*Verified\s*;",
        fixture_body or "",
    )
    fixture_insert = re.search(
        r"\bcp\s*\.\s*instances\s*\.\s*write\s*\(\s*\)\s*"
        r"\.\s*await\s*\.\s*insert\s*\(",
        fixture_body or "",
    )
    fixture_authority_none = re.search(
        r"assert!\s*\(\s*cp\s*\.\s*get_neutron_port_authority\s*"
        r"\(\s*instance\s*\)\s*\.\s*await\s*\.\s*is_none\s*\(\s*\)",
        fixture_body or "",
    )
    fixture_assert_calls = list(
        re.finditer(r"\bassert!\s*\(", fixture_body or "")
    )
    fixture_assert_arguments = None
    fixture_assert_closing = -1
    if len(fixture_assert_calls) == 1:
        fixture_assert_opening = (fixture_body or "").find(
            "(", fixture_assert_calls[0].start()
        )
        fixture_assert_arguments = _rust_parenthesized_body_at(
            fixture_body, fixture_assert_opening
        )
        fixture_assert_closing = (
            fixture_assert_opening + len(fixture_assert_arguments) + 1
            if fixture_assert_arguments is not None
            else -1
        )
    fixture_assert_items = (
        _rust_split_top_level_arguments(fixture_assert_arguments)
        if fixture_assert_arguments is not None
        else []
    )
    fixture_assert_first_argument = (
        re.sub(r"\s+", "", fixture_assert_items[0])
        if fixture_assert_items
        else ""
    )
    fixture_positions = (
        fixture_load,
        fixture_mode,
        fixture_health,
        fixture_insert,
        fixture_authority_none,
    )
    if (
        tests_body is None
        or len(re.findall(r"\basync\s+fn\s+%s\s*\(" % fixture_name, tests_body))
        != 1
        or fixture_parameters is None
        or not re.search(
            r"\bcp\s*:\s*&\s*ControlPlane\b", fixture_parameters
        )
        or not re.search(r"\binstance\s*:\s*&\s*str\b", fixture_parameters)
        or not re.search(r"\btest_name\s*:\s*&\s*str\b", fixture_parameters)
        or fixture_body is None
        or any(position is None for position in fixture_positions)
        or len(fixture_assert_calls) != 1
        or fixture_assert_first_argument
        != "cp.get_neutron_port_authority(instance).await.is_none()"
        or fixture_assert_closing < 0
        or fixture_body[fixture_assert_closing + 1:].strip() != ";"
        or not all(
            left.start() < right.start()
            for left, right in zip(fixture_positions, fixture_positions[1:])
        )
        or any(
            _rust_brace_depth_at(fixture_body, position.start()) != 0
            for position in fixture_positions
            if position is not None
        )
        or len(
            re.findall(
                r"\bstate\s*\.\s*managed_acl_publication_mode\s*=",
                fixture_body or "",
            )
        )
        != 1
        or len(
            re.findall(
                r"\bstate\s*\.\s*managed_projection_health\s*=",
                fixture_body or "",
            )
        )
        != 1
        or "mark_neutron_port_authority" in (fixture_body or "")
        or "neutron_authorities" in (fixture_body or "")
    ):
        errors.append(
            "managed authoritative fixture must uniquely install ManagedAcl Verified before proving authority is absent"
        )

    for test_name, spec in test_specs.items():
        active_declaration = (
            re.search(
            r"#\s*\[\s*tokio\s*::\s*test\s*\]\s*async\s+fn\s+%s\s*\("
            % re.escape(test_name),
            tests_body,
            )
            if tests_body is not None
            else None
        )
        declaration_prefix = (
            tests_body[:active_declaration.start()].rstrip()
            if active_declaration is not None
            else ""
        )
        if (
            active_declaration is None
            or not declaration_prefix
            or declaration_prefix[-1] not in "{}"
            or _rust_brace_depth_at(tests_body, active_declaration.start()) != 0
        ):
            errors.append(
                "managed authoritative write real-entry regression test must be active in cfg(test): %s"
                % test_name
            )
            continue
        test_body = _rust_function_body_from_blanked(tests_body, test_name)
        raw_test_body = raw_function_body(test_name)
        compact_raw_test = re.sub(r"\s+", "", raw_test_body or "")
        test_parameters = _rust_function_parameters_from_blanked(
            tests_body, test_name
        )
        cp_binding = re.search(
            r"\blet\s+cp\s*=\s*test_control_plane\s*\(\s*\)\s*;",
            test_body or "",
        )
        instance_binding = re.search(
            r'\blet\s+instance\s*=\s*"[^"\n]+"\s*;',
            raw_test_body or "",
        )

        def test_binding_count(binding_name):
            return len(
                re.findall(
                    r"\blet\b[^=;{}\n]*\b%s\b[^=;{}\n]*="
                    % re.escape(binding_name),
                    test_body or "",
                )
            )

        shadowed_test_names = any(
            test_binding_count(binding_name) != expected_count
            for binding_name, expected_count in (
                ("cp", 1),
                ("instance", 1),
                ("assert_local_write_blocked", 0),
                ("assert_not_local_write_blocked", 0),
                ("install_verified_managed_acl_instance_without_authority", 0),
            )
        ) or bool(
            re.search(
                r"\|[^|\n]*\b(?:cp|instance|assert_local_write_blocked|"
                r"assert_not_local_write_blocked|"
                r"install_verified_managed_acl_instance_without_authority)"
                r"\b[^|\n]*\|",
                test_body or "",
            )
        ) or bool(
            re.search(
                r"\buse\b[^;\n]*\b(?:assert_local_write_blocked|"
                r"assert_not_local_write_blocked|"
                r"install_verified_managed_acl_instance_without_authority)\b",
                test_body or "",
            )
        )
        fixture_call = (
            re.search(
                r"\bself\s*::\s*"
                r"install_verified_managed_acl_instance_without_authority\s*\("
                r"[\s\S]*?\)\s*\.\s*await\s*;",
                test_body,
            )
            if test_body is not None
            else None
        )
        if (
            test_parameters is None
            or test_parameters.strip()
            or cp_binding is None
            or instance_binding is None
            or fixture_call is None
            or not cp_binding.start() < instance_binding.start() < fixture_call.start()
            or _rust_brace_depth_at(test_body, cp_binding.start()) != 0
            or _rust_brace_depth_at(test_body, instance_binding.start()) != 0
            or shadowed_test_names
        ):
            errors.append(
                "managed authoritative regression test must bind real cp and instance once without shadowing helpers: %s"
                % test_name
            )
        if (
            test_body is None
            or raw_test_body is None
            or fixture_call is None
            or _rust_brace_depth_at(test_body, fixture_call.start()) != 0
            or re.search(
                r"\breturn\b|\bstd\s*::\s*process\s*::\s*exit\s*\(",
                test_body,
            )
        ):
            errors.append(
                "managed authoritative regression test must install the real authority-gap fixture and execute without early success: %s"
                % test_name
            )
            continue
        previous_position = fixture_call.start()
        for binding, method, assertion in spec["calls"]:
            result_binding_count = test_binding_count(binding)
            call = re.search(
                r"\blet\s+%s\s*=\s*cp\s*\.\s*%s\s*\("
                % (re.escape(binding), re.escape(method)),
                test_body,
            )
            call_arguments = None
            if call is not None:
                call_opening = test_body.find("(", call.start())
                call_arguments = _rust_parenthesized_body_at(
                    test_body, call_opening
                )
                call_closing = (
                    call_opening + len(call_arguments) + 1
                    if call_arguments is not None
                    else -1
                )
                call_suffix = (
                    test_body[call_closing + 1:]
                    if call_closing >= 0
                    else ""
                )
            else:
                call_suffix = ""
            if call is None or result_binding_count != 1 or not re.match(
                r"\s*\.\s*await\s*\.\s*expect_err\s*\(", call_suffix
            ) or (
                call is not None
                and (
                    _rust_brace_depth_at(test_body, call.start()) != 0
                    or call.start() <= previous_position
                )
            ):
                errors.append(
                    "managed authoritative regression test must exercise %s through the real entry: %s"
                    % (method, test_name)
                )
            assertion_name = assertion[:assertion.find("(")]
            assertion_position = -1
            for assertion_match in re.finditer(
                r"\b%s\s*\(" % re.escape(assertion_name), raw_test_body
            ):
                assertion_opening = raw_test_body.find("(", assertion_match.start())
                assertion_arguments = _rust_parenthesized_body_at(
                    raw_test_body, assertion_opening
                )
                if assertion_arguments is None:
                    continue
                assertion_closing = (
                    assertion_opening + len(assertion_arguments) + 1
                )
                actual_assertion = "%s(%s);" % (
                    assertion_name,
                    re.sub(r"\s+", "", assertion_arguments),
                )
                if (
                    actual_assertion == assertion
                    and re.match(r"\s*;", raw_test_body[assertion_closing + 1:])
                ):
                    assertion_position = assertion_match.start()
                    break
            if (
                assertion_position < 0
                or _rust_brace_depth_at(test_body, assertion_position) != 0
                or (call is not None and assertion_position <= call.start())
            ):
                errors.append(
                    "managed authoritative regression test must assert the exact %s outcome: %s"
                    % (method, test_name)
                )
            previous_position = max(
                previous_position,
                call.start() if call is not None else -1,
                assertion_position,
            )
        for raw_marker in spec["raw"]:
            if re.sub(r"\s+", "", raw_marker) not in compact_raw_test:
                errors.append(
                    "managed authoritative regression test is missing exact fixture marker %s: %s"
                    % (raw_marker, test_name)
                )

    amendment_test_specs = {
        "domain_authority_neutron_purge_policy_uses_privileged_serialized_entry": {
            "method": "delete_policy_for_neutron_purge",
            "timeout": True,
            "outcome": "missing_maps",
            "arguments": (
                "instance",
                '"policy-src"',
                '"policy-dst"',
                "libc::IPPROTO_TCPasu8",
                "0",
            ),
            "raw": ('"policy-src"', '"policy-dst"'),
        },
        "domain_authority_neutron_purge_group_uses_privileged_serialized_entry": {
            "method": "delete_group_for_neutron_purge",
            "timeout": True,
            "outcome": "missing_maps",
            "arguments": (
                "instance",
                '"purge-port"',
                '"neutron:purge-port:src:selector:0"',
            ),
            "raw": (
                '"purge-port"',
                '"neutron:purge-port:src:selector:0"',
            ),
        },
        "domain_authority_neutron_purge_group_rejects_foreign_owner_prefix": {
            "method": "delete_group_for_neutron_purge",
            "timeout": True,
            "outcome": "foreign_owner",
            "arguments": (
                "instance",
                '"purge-port"',
                '"neutron:foreign-port:src:selector:0"',
            ),
            "raw": (
                '"purge-port"',
                '"neutron:foreign-port:src:selector:0"',
                "expected owner prefix 'neutron:purge-port:'",
                "actual group 'neutron:foreign-port:src:selector:0'",
            ),
        },
        "domain_authority_managed_acl_public_flush_blocks_before_authority_commit": {
            "method": "flush_conntrack",
            "timeout": False,
            "outcome": "blocked",
            "arguments": ("instance",),
            "raw": ('"conntrack"', 'Some("acl")'),
        },
        "domain_authority_standalone_public_flush_preserves_lenient_missing_map_behavior": {
            "method": "flush_conntrack",
            "timeout": False,
            "outcome": "success_zero",
            "arguments": ("instance",),
            "raw": (),
        },
        "domain_authority_standalone_public_flush_blocks_committed_acl_dependency": {
            "method": "flush_conntrack",
            "timeout": False,
            "outcome": "blocked_committed",
            "arguments": ("instance",),
            "raw": ('"conntrack"', 'Some("acl")', '"acl".to_string()'),
        },
        "domain_authority_managed_acl_strict_flush_remains_privileged_and_strict": {
            "method": "flush_conntrack_strict",
            "timeout": False,
            "outcome": "strict_error",
            "arguments": ("instance",),
            "raw": ("open CT_TABLE_V4",),
        },
    }

    raw_tests_body = None
    if tests_module is not None:
        raw_tests_opening = control_code.find("{", tests_module.start())
        raw_tests_closing = _rust_matching_brace_end(
            control_code, raw_tests_opening
        )
        if raw_tests_opening >= 0 and raw_tests_closing is not None:
            raw_tests_body = control_plane_source[
                raw_tests_opening + 1:raw_tests_closing
            ]

    def amendment_binding_positions(body, binding):
        return [
            match.start()
            for match in re.finditer(
                r"\blet\s+(?:mut\s+)?%s\b(?:\s*:[^=;{}]+)?\s*="
                % re.escape(binding),
                body or "",
            )
        ]

    def amendment_statement_end(body, start):
        if body is None or start < 0:
            return -1
        target_depth = _rust_brace_depth_at(body, start)
        for position in range(start, len(body)):
            if (
                body[position] == ";"
                and _rust_brace_depth_at(body, position) == target_depth
            ):
                return position
        return -1

    def amendment_call_details(body, raw_body, call_name):
        details = []
        if body is None or raw_body is None:
            return details
        for position, _ in _rust_named_call_arguments(body, call_name):
            opening = body.find("(", position)
            blank_arguments = _rust_parenthesized_body_at(body, opening)
            if blank_arguments is None:
                continue
            closing = opening + len(blank_arguments) + 1
            raw_arguments = raw_body[opening + 1:closing]
            details.append(
                (
                    position,
                    tuple(
                        re.sub(r"\s+", "", argument)
                        for argument in _rust_split_top_level_arguments(
                            raw_arguments
                        )
                    ),
                    opening,
                    closing,
                )
            )
        return details

    def amendment_macro_details(body, raw_body, macro_name):
        details = []
        if body is None or raw_body is None:
            return details
        for match in re.finditer(
            r"\b%s\s*!\s*\(" % re.escape(macro_name), body
        ):
            opening = body.find("(", match.start())
            blank_arguments = _rust_parenthesized_body_at(body, opening)
            if blank_arguments is None:
                continue
            closing = opening + len(blank_arguments) + 1
            raw_arguments = raw_body[opening + 1:closing]
            details.append(
                (
                    match.start(),
                    tuple(
                        re.sub(r"\s+", "", argument)
                        for argument in _rust_split_top_level_arguments(
                            raw_arguments
                        )
                    ),
                    opening,
                    closing,
                )
            )
        return details

    def amendment_has_receiver(body, position, receiver, separator):
        prefix = (body or "")[max(0, position - 160):position]
        if separator == ".":
            return bool(
                re.search(
                    r"(?<![\w.])%s\s*\.\s*$" % re.escape(receiver),
                    prefix,
                )
            )
        return bool(
            re.search(
                r"(?<![\w:])%s\s*::\s*$" % re.escape(receiver),
                prefix,
            )
        )

    def amendment_enclosing_block(body, position):
        stack = []
        for index, character in enumerate((body or "")[:position]):
            if character == "{":
                stack.append(index)
            elif character == "}" and stack:
                stack.pop()
        if not stack:
            return None
        opening = stack[-1]
        closing = _rust_matching_brace_end(body, opening)
        return None if closing is None else (opening, closing)

    def amendment_state_setup_is_real(body, raw_body, before_position):
        instance_state_bindings = amendment_binding_positions(
            body, "instance_state"
        )
        state_bindings = amendment_binding_positions(body, "state")
        get_calls = amendment_call_details(body, raw_body, "get_instance")
        write_calls = amendment_call_details(body, raw_body, "write")
        mode_writes = list(
            re.finditer(
                r"\bstate\s*\.\s*managed_acl_publication_mode\s*=\s*"
                r"ManagedAclPublicationMode\s*::\s*StandaloneCompatibility\s*;",
                body or "",
            )
        )
        health_writes = list(
            re.finditer(
                r"\bstate\s*\.\s*managed_projection_health\s*=\s*"
                r"ManagedProjectionHealth\s*::\s*Unverified\s*;",
                body or "",
            )
        )
        if not (
            len(instance_state_bindings) == 1
            and len(state_bindings) == 1
            and len(get_calls) == 1
            and len(write_calls) == 1
            and len(mode_writes) == 1
            and len(health_writes) == 1
        ):
            return False
        instance_state = instance_state_bindings[0]
        state = state_bindings[0]
        get_call = get_calls[0]
        write_call = write_calls[0]
        block = amendment_enclosing_block(body, instance_state)
        if block is None:
            return False
        block_opening, block_closing = block
        instance_statement_end = amendment_statement_end(body, instance_state)
        state_statement_end = amendment_statement_end(body, state)
        get_suffix = (
            body[get_call[3] + 1:instance_statement_end]
            if instance_statement_end >= 0
            else ""
        )
        write_suffix = (
            body[write_call[3] + 1:state_statement_end]
            if state_statement_end >= 0
            else ""
        )
        positions = (
            instance_state,
            get_call[0],
            state,
            write_call[0],
            mode_writes[0].start(),
            health_writes[0].start(),
        )
        return bool(
            _rust_brace_depth_at(body, block_opening) == 0
            and all(
                block_opening < position < block_closing
                and _rust_brace_depth_at(body, position) == 1
                for position in positions
            )
            and positions == tuple(sorted(positions))
            and block_closing < before_position
            and amendment_has_receiver(body, get_call[0], "cp", ".")
            and get_call[1] == ("instance",)
            and amendment_has_receiver(
                body, write_call[0], "instance_state", "."
            )
            and write_call[1] == ()
            and re.fullmatch(r"\s*\.\s*await\s*\.\s*unwrap\s*\(\s*\)\s*", get_suffix)
            and re.fullmatch(r"\s*\.\s*await\s*", write_suffix)
            and re.fullmatch(
                r"\s*let\s+instance_state\s*=\s*cp\s*\.\s*",
                body[instance_state:get_call[0]],
            )
            and re.fullmatch(
                r"\s*let\s+mut\s+state\s*=\s*instance_state\s*\.\s*",
                body[state:write_call[0]],
            )
        )

    def amendment_match_parts(body, raw_body, binding):
        matches = list(
            re.finditer(r"\bmatch\s+%s\s*\{" % re.escape(binding), body or "")
        )
        if len(matches) != 1:
            return None
        match = matches[0]
        opening = body.find("{", match.start())
        closing = _rust_matching_brace_end(body, opening)
        if closing is None:
            return None
        return (
            match.start(),
            body[opening + 1:closing],
            raw_body[opening + 1:closing],
        )

    def amendment_arm_parts(match_body, raw_match_body, pattern):
        arm = re.search(pattern + r"\s*=>\s*\{", match_body or "")
        if arm is None or _rust_brace_depth_at(match_body, arm.start()) != 0:
            return None
        opening = match_body.find("{", arm.start())
        closing = _rust_matching_brace_end(match_body, opening)
        if closing is None:
            return None
        return (
            match_body[opening + 1:closing],
            raw_match_body[opening + 1:closing],
        )

    def amendment_exact_assert_macro(
        body, raw_body, macro_name, expected_arguments, depth, after
    ):
        matches = [
            detail
            for detail in amendment_macro_details(body, raw_body, macro_name)
            if detail[1][:len(expected_arguments)] == expected_arguments
            and _rust_brace_depth_at(body, detail[0]) == depth
            and detail[0] > after
        ]
        return len(matches) == 1

    for test_name, spec in amendment_test_specs.items():
        declarations = (
            list(
                re.finditer(
                    r"\basync\s+fn\s+%s\s*\(" % re.escape(test_name),
                    tests_body,
                )
            )
            if tests_body is not None
            else []
        )
        declaration = declarations[0] if len(declarations) == 1 else None
        body = None
        raw_body = None
        parameters = None
        attributes = ""
        if declaration is not None and raw_tests_body is not None:
            parameter_opening = tests_body.find("(", declaration.start())
            parameters = _rust_parenthesized_body_at(
                tests_body, parameter_opening
            )
            opening = tests_body.find("{", declaration.end())
            closing = _rust_matching_brace_end(tests_body, opening)
            attribute_match = re.search(
                r"((?:#\s*\[[^\]]+\]\s*)+)$",
                tests_body[:declaration.start()],
            )
            attributes = (
                re.sub(r"\s+", "", attribute_match.group(1))
                if attribute_match is not None
                else ""
            )
            if opening >= 0 and closing is not None:
                body = tests_body[opening + 1:closing]
                raw_body = raw_tests_body[opening + 1:closing]

        cp_bindings = amendment_binding_positions(body, "cp")
        instance_bindings = amendment_binding_positions(body, "instance")
        cp_binding = cp_bindings[0] if len(cp_bindings) == 1 else -1
        instance_binding = (
            instance_bindings[0] if len(instance_bindings) == 1 else -1
        )
        fixture_calls = amendment_call_details(
            body,
            raw_body,
            "install_verified_managed_acl_instance_without_authority",
        )
        fixture = fixture_calls[0] if len(fixture_calls) == 1 else None
        method_calls = amendment_call_details(
            body, raw_body, spec["method"]
        )
        method_call = method_calls[0] if len(method_calls) == 1 else None
        method_position = method_call[0] if method_call is not None else -1
        key_bindings = (
            ("result", "error")
            if spec["timeout"]
            else (
                ("flushed",)
                if spec["outcome"] == "success_zero"
                else ("error",)
            )
        )
        shadow_names = ("cp", "instance") + key_bindings
        shadow_pattern = "|".join(re.escape(name) for name in shadow_names)
        fixture_suffix = (
            body[fixture[3] + 1:]
            if fixture is not None and body is not None
            else ""
        )
        structural_error = bool(
            declaration is None
            or body is None
            or raw_body is None
            or parameters is None
            or parameters.strip()
            or attributes != "#[tokio::test]"
            or _rust_brace_depth_at(tests_body, declaration.start()) != 0
            or cp_binding < 0
            or instance_binding < 0
            or not re.match(
                r"let\s+cp\s*=\s*test_control_plane\s*\(\s*\)\s*;",
                body[cp_binding:],
            )
            or not re.match(
                r'let\s+instance\s*=\s*"(?:\\.|[^"\\\n])+"\s*;',
                raw_body[instance_binding:],
            )
            or _rust_brace_depth_at(body, cp_binding) != 0
            or _rust_brace_depth_at(body, instance_binding) != 0
            or fixture is None
            or fixture[1][:2] != ("&cp", "instance")
            or len(fixture[1]) != 3
            or re.fullmatch(r'"(?:\\.|[^"\\])*"', fixture[1][2]) is None
            or not amendment_has_receiver(body, fixture[0], "self", "::")
            or _rust_brace_depth_at(body, fixture[0]) != 0
            or not re.match(r"\s*\.\s*await\s*;", fixture_suffix)
            or method_call is None
            or method_call[1] != spec["arguments"]
            or not amendment_has_receiver(body, method_position, "cp", ".")
            or _rust_brace_depth_at(body, method_position) != 0
            or not cp_binding
            < instance_binding
            < (fixture[0] if fixture is not None else -1)
            < method_position
            or any(
                len(amendment_binding_positions(body, binding)) != 1
                for binding in key_bindings
            )
            or re.search(
                r"\|[^|\n]*\b(?:%s)\b[^|\n]*\|" % shadow_pattern,
                body or "",
            )
            or re.search(
                r"\bfor\s+(?:%s)\b|\bfn\s+\w+\s*\([^)]*\b(?:%s)\b"
                % (shadow_pattern, shadow_pattern),
                body or "",
            )
            or amendment_binding_positions(
                body,
                "install_verified_managed_acl_instance_without_authority",
            )
            or re.search(
                r"\breturn\b|\bstd\s*::\s*process\s*::\s*exit\s*\(",
                body or "",
            )
            or re.search(
                r"\bif\s+(?:false|!\s*true)\s*\{", body or ""
            )
        )

        error_binding_position = -1
        if not structural_error and spec["timeout"]:
            result_position = amendment_binding_positions(body, "result")[0]
            error_binding_position = amendment_binding_positions(
                body, "error"
            )[0]
            timeout_calls = amendment_call_details(body, raw_body, "timeout")
            timeout_call = timeout_calls[0] if len(timeout_calls) == 1 else None
            result_end = amendment_statement_end(body, result_position)
            error_end = amendment_statement_end(body, error_binding_position)
            expect_err_calls = amendment_call_details(
                body, raw_body, "expect_err"
            )
            result_expect_err = [
                call
                for call in expect_err_calls
                if amendment_has_receiver(body, call[0], "result", ".")
                and error_binding_position < call[0] < error_end
            ]
            timeout_suffix = (
                body[timeout_call[3] + 1:result_end]
                if timeout_call is not None and result_end >= 0
                else ""
            )
            structural_error = bool(
                timeout_call is None
                or not re.search(
                    r"(?<![\w:])tokio\s*::\s*time\s*::\s*$",
                    body[max(0, timeout_call[0] - 160):timeout_call[0]],
                )
                or _rust_brace_depth_at(body, timeout_call[0]) != 0
                or not result_position
                < timeout_call[0]
                < method_position
                < timeout_call[3]
                < result_end
                < error_binding_position
                or "std::time::Duration::from_secs(1)"
                not in timeout_call[1]
                or not re.fullmatch(
                    r"\s*\.\s*await\s*\.\s*expect\s*\([^)]*\)\s*",
                    timeout_suffix,
                )
                or not re.fullmatch(
                    r"\s*let\s+result\s*=\s*tokio\s*::\s*time\s*::\s*",
                    body[result_position:timeout_call[0]],
                )
                or _rust_brace_depth_at(body, result_position) != 0
                or _rust_brace_depth_at(body, error_binding_position) != 0
                or len(result_expect_err) != 1
                or not re.fullmatch(
                    r"\s*let\s+error\s*=\s*result\s*\.\s*",
                    body[error_binding_position:result_expect_err[0][0]],
                )
            )
        elif not structural_error:
            outcome_binding = key_bindings[0]
            outcome_position = amendment_binding_positions(
                body, outcome_binding
            )[0]
            outcome_end = amendment_statement_end(body, outcome_position)
            expected_terminal = (
                "expect" if spec["outcome"] == "success_zero" else "expect_err"
            )
            method_suffix = (
                body[method_call[3] + 1:outcome_end]
                if outcome_end >= 0
                else ""
            )
            structural_error = bool(
                _rust_brace_depth_at(body, outcome_position) != 0
                or not outcome_position < method_position < outcome_end
                or not re.fullmatch(
                    r"\s*let\s+%s\s*=\s*cp\s*\.\s*"
                    % re.escape(outcome_binding),
                    body[outcome_position:method_position],
                )
                or not re.match(
                    r"\s*\.\s*await\s*\.\s*%s\s*\("
                    % expected_terminal,
                    method_suffix,
                )
            )
            if outcome_binding == "error":
                error_binding_position = outcome_position

        if not structural_error:
            outcome = spec["outcome"]
            if outcome == "missing_maps":
                assertions = amendment_call_details(
                    body, raw_body, "assert_missing_runtime_maps"
                )
                structural_error = not (
                    len(assertions) == 1
                    and assertions[0][1] == ("error",)
                    and amendment_has_receiver(
                        body, assertions[0][0], "self", "::"
                    )
                    and _rust_brace_depth_at(body, assertions[0][0]) == 0
                    and assertions[0][0] > error_binding_position
                )
            elif outcome == "foreign_owner":
                match_parts = amendment_match_parts(body, raw_body, "error")
                validation_arm = (
                    amendment_arm_parts(
                        match_parts[1],
                        match_parts[2],
                        r"ControlPlaneError\s*::\s*ValidationError\s*"
                        r"\(\s*reason\s*\)",
                    )
                    if match_parts is not None
                    else None
                )
                expected_reason_assertions = (
                    (
                        'reason.contains("expectedownerprefix\'neutron:purge-port:\'")',
                        'reason.contains("actualgroup\'neutron:foreign-port:src:selector:0\'")',
                    )
                )
                arm_assertions = (
                    amendment_macro_details(
                        validation_arm[0], validation_arm[1], "assert"
                    )
                    if validation_arm is not None
                    else []
                )
                actual_reason_assertions = {
                    assertion[1][0]
                    for assertion in arm_assertions
                    if assertion[1]
                    and _rust_brace_depth_at(
                        validation_arm[0], assertion[0]
                    )
                    == 0
                }
                structural_error = bool(
                    not amendment_exact_assert_macro(
                        body,
                        raw_body,
                        "assert_eq",
                        ("error.status_code()", "400"),
                        0,
                        error_binding_position,
                    )
                    or match_parts is None
                    or match_parts[0] <= error_binding_position
                    or _rust_brace_depth_at(body, match_parts[0]) != 0
                    or validation_arm is None
                    or not set(expected_reason_assertions).issubset(
                        actual_reason_assertions
                    )
                )
            elif outcome in ("blocked", "blocked_committed"):
                assertions = amendment_call_details(
                    body, raw_body, "assert_local_write_blocked"
                )
                structural_error = not (
                    len(assertions) == 1
                    and assertions[0][1]
                    == (
                        "error",
                        "instance",
                        '"conntrack"',
                        'Some("acl")',
                    )
                    and amendment_has_receiver(
                        body, assertions[0][0], "self", "::"
                    )
                    and _rust_brace_depth_at(body, assertions[0][0]) == 0
                    and assertions[0][0] > method_position
                )
                if outcome == "blocked_committed" and not structural_error:
                    authority_calls = amendment_call_details(
                        body, raw_body, "mark_neutron_port_authority"
                    )
                    authority = (
                        authority_calls[0]
                        if len(authority_calls) == 1
                        else None
                    )
                    structural_error = bool(
                        authority is None
                        or authority[1]
                        != (
                            "instance",
                            '"port-ct"',
                            '&["acl".to_string()]',
                            "17",
                        )
                        or not amendment_has_receiver(
                            body, authority[0], "cp", "."
                        )
                        or _rust_brace_depth_at(body, authority[0]) != 0
                        or not fixture[0] < authority[0] < method_position
                        or not amendment_state_setup_is_real(
                            body, raw_body, authority[0]
                        )
                    )
            elif outcome == "success_zero":
                structural_error = bool(
                    not amendment_state_setup_is_real(
                        body, raw_body, method_position
                    )
                    or not amendment_exact_assert_macro(
                        body,
                        raw_body,
                        "assert_eq",
                        ("flushed", "0"),
                        0,
                        method_position,
                    )
                )
            elif outcome == "strict_error":
                match_parts = amendment_match_parts(body, raw_body, "error")
                kernel_arm = (
                    amendment_arm_parts(
                        match_parts[1],
                        match_parts[2],
                        r"ControlPlaneError\s*::\s*KernelError\s*"
                        r"\(\s*reason\s*\)",
                    )
                    if match_parts is not None
                    else None
                )
                blocked_arm = (
                    amendment_arm_parts(
                        match_parts[1],
                        match_parts[2],
                        r"ControlPlaneError\s*::\s*LocalWriteBlocked\s*"
                        r"\{\s*\.\s*\.\s*\}",
                    )
                    if match_parts is not None
                    else None
                )
                direct_blocked_panic = (
                    re.search(
                        r"ControlPlaneError\s*::\s*LocalWriteBlocked\s*"
                        r"\{\s*\.\s*\.\s*\}\s*=>\s*panic\s*!\s*\(",
                        match_parts[1],
                    )
                    if match_parts is not None
                    else None
                )
                kernel_assertions = (
                    amendment_macro_details(
                        kernel_arm[0], kernel_arm[1], "assert"
                    )
                    if kernel_arm is not None
                    else []
                )
                blocked_panics = (
                    amendment_macro_details(
                        blocked_arm[0], blocked_arm[1], "panic"
                    )
                    if blocked_arm is not None
                    else []
                )
                structural_error = bool(
                    not amendment_exact_assert_macro(
                        body,
                        raw_body,
                        "assert_eq",
                        ("error.status_code()", "500"),
                        0,
                        error_binding_position,
                    )
                    or match_parts is None
                    or match_parts[0] <= error_binding_position
                    or _rust_brace_depth_at(body, match_parts[0]) != 0
                    or kernel_arm is None
                    or not any(
                        assertion[1]
                        and assertion[1][0]
                        == 'reason.contains("openCT_TABLE_V4")'
                        and _rust_brace_depth_at(
                            kernel_arm[0], assertion[0]
                        )
                        == 0
                        for assertion in kernel_assertions
                    )
                    or not (
                        (
                            blocked_arm is not None
                            and len(blocked_panics) == 1
                            and _rust_brace_depth_at(
                                blocked_arm[0], blocked_panics[0][0]
                            )
                            == 0
                        )
                        or (
                            direct_blocked_panic is not None
                            and _rust_brace_depth_at(
                                match_parts[1], direct_blocked_panic.start()
                            )
                            == 0
                        )
                    )
                )

        if structural_error:
            errors.append(
                "managed authoritative amendment regression must actively exercise exact purge/conntrack behavior: %s"
                % test_name
            )
    return errors


def _run_managed_authoritative_write_admission_self_tests():
    safe_control = r'''
        enum ManagedAclPublicationMode { StandaloneCompatibility, ManagedAcl }
        enum LocalWriteDomain { Acl, Config, Conntrack, Qos, Mirror, Tcprt, Ssl }
        struct NeutronPortAuthority { managed_domains: Domains }

        fn local_write_block_reason(
            domain: LocalWriteDomain,
            publication_mode: Option<ManagedAclPublicationMode>,
            authority: Option<&NeutronPortAuthority>,
        ) -> Option<Option<String>> {
            match (publication_mode, domain) {
                (Some(ManagedAclPublicationMode::ManagedAcl), LocalWriteDomain::Acl) => Some(None),
                (Some(ManagedAclPublicationMode::ManagedAcl), LocalWriteDomain::Conntrack) => {
                    Some(Some("acl".to_string()))
                }
                _ => authority.and_then(|authority| {
                    let domain_name = domain.as_str();
                    if authority.managed_domains.contains(domain_name) {
                        Some(None)
                    } else if domain == LocalWriteDomain::Conntrack
                        && authority.managed_domains.contains("acl")
                    {
                        Some(Some("acl".to_string()))
                    } else {
                        None
                    }
                }),
            }
        }

        fn ensure_serialized_local_write_allowed(
            instance: &str,
            domain: LocalWriteDomain,
            publication_mode: Option<ManagedAclPublicationMode>,
            authority: Option<&NeutronPortAuthority>,
        ) -> Result<(), ControlPlaneError> {
            if let Some(dependency_of) =
                local_write_block_reason(domain, publication_mode, authority)
            {
                return Err(ControlPlaneError::LocalWriteBlocked {
                    instance: instance.to_string(),
                    domain: domain.as_str().to_string(),
                    dependency_of,
                });
            }
            Ok(())
        }

        fn requested_local_config_write_domains(
            conntrack: Option<bool>,
            monitoring: Option<bool>,
            acl: Option<bool>,
            qos: Option<bool>,
            mirror: Option<bool>,
            tcprt: Option<bool>,
            ssl: Option<bool>,
        ) -> Vec<LocalWriteDomain> {
            let mut domains = Vec::new();
            if conntrack.is_some() { domains.push(LocalWriteDomain::Conntrack); }
            if monitoring.is_some() { domains.push(LocalWriteDomain::Config); }
            if acl.is_some() { domains.push(LocalWriteDomain::Acl); }
            if qos.is_some() { domains.push(LocalWriteDomain::Qos); }
            if mirror.is_some() { domains.push(LocalWriteDomain::Mirror); }
            if tcprt.is_some() { domains.push(LocalWriteDomain::Tcprt); }
            if ssl.is_some() { domains.push(LocalWriteDomain::Ssl); }
            domains
        }

        fn local_group_write_block_reason(
            group_name: &str,
            publication_mode: Option<ManagedAclPublicationMode>,
            authority: Option<&NeutronPortAuthority>,
        ) -> bool {
            group_name.trim().to_ascii_lowercase().starts_with("neutron:")
                && (publication_mode == Some(ManagedAclPublicationMode::ManagedAcl)
                    || authority.is_some())
        }

        fn ensure_serialized_local_group_write_allowed(
            instance: &str,
            group_name: &str,
            publication_mode: Option<ManagedAclPublicationMode>,
            authority: Option<&NeutronPortAuthority>,
        ) -> Result<(), ControlPlaneError> {
            if local_group_write_block_reason(group_name, publication_mode, authority) {
                return Err(ControlPlaneError::LocalWriteBlocked {
                    instance: instance.to_string(),
                    domain: LocalWriteDomain::Acl.as_str().to_string(),
                    dependency_of: None,
                });
            }
            Ok(())
        }

        impl ControlPlane {
            async fn add_policy(&self, instance: &str) -> Result<(), ControlPlaneError> {
                let _lifecycle_guard = self.lock_runtime_lifecycle().await;
                let inst = self.get_instance(instance).await?;
                let mut state = inst.write().await;
                let authority = self.neutron_authorities.read().await
                    .get(instance).cloned();
                ensure_serialized_local_write_allowed(
                    instance,
                    LocalWriteDomain::Acl,
                    Some(state.managed_acl_publication_mode),
                    authority.as_ref(),
                )?;
                Self::check_runtime_maps_ready(&state.pin_path)?;
                aria_core::ebpf_ops::add_policy_in_bank();
                state.wal_append();
                Ok(())
            }

            async fn delete_policy_locked(
                &self,
                state: &mut InstanceState,
                src_group: &str,
                dst_group: &str,
                proto: u8,
                direction: u8,
            ) -> Result<(), ControlPlaneError> {
                Self::check_runtime_maps_ready(&state.pin_path)?;
                let src_id = self.resolve_group_id()?;
                let dst_id = self.resolve_group_id()?;
                let target_directions = Self::requested_directions()?;
                let acl_bank = aria_core::ebpf_ops::read_acl_active_bank()?;
                aria_core::ebpf_ops::delete_policy_in_bank();
                state.state.apply_remove_rule()?;
                state.wal_append(&WalEntry::RemoveRule {
                    src_id,
                    dst_id,
                    proto,
                    direction,
                }).await;
                Ok(())
            }

            async fn delete_policy(
                &self,
                instance: &str,
                src_group: &str,
                dst_group: &str,
                proto: u8,
                direction: u8,
            ) -> Result<(), ControlPlaneError> {
                let _lifecycle_guard = self.lock_runtime_lifecycle().await;
                let inst = self.get_instance(instance).await?;
                let mut state = inst.write().await;
                let authority = self.neutron_authorities.read().await
                    .get(instance).cloned();
                ensure_serialized_local_write_allowed(
                    instance,
                    LocalWriteDomain::Acl,
                    Some(state.managed_acl_publication_mode),
                    authority.as_ref(),
                )?;
                self.delete_policy_locked(
                    &mut state,
                    src_group,
                    dst_group,
                    proto,
                    direction,
                ).await
            }

            pub(crate) async fn delete_policy_for_neutron_purge(
                &self,
                instance: &str,
                src_group: &str,
                dst_group: &str,
                proto: u8,
                direction: u8,
            ) -> Result<(), ControlPlaneError> {
                let _lifecycle_guard = self.lock_runtime_lifecycle().await;
                let inst = self.get_instance(instance).await?;
                let mut state = inst.write().await;
                self.delete_policy_locked(
                    &mut state,
                    src_group,
                    dst_group,
                    proto,
                    direction,
                ).await
            }

            async fn add_group(&self, instance: &str, name: &str) -> Result<(), ControlPlaneError> {
                let _lifecycle_guard = self.lock_runtime_lifecycle().await;
                let inst = self.get_instance(instance).await?;
                let mut state = inst.write().await;
                let authority = self.neutron_authorities.read().await
                    .get(instance).cloned();
                ensure_serialized_local_group_write_allowed(
                    instance,
                    name,
                    Some(state.managed_acl_publication_mode),
                    authority.as_ref(),
                )?;
                managed_local_projection_admission();
                Self::check_runtime_maps_ready(&state.pin_path)?;
                Ok(())
            }

            async fn delete_group_locked(
                &self,
                instance: &str,
                state: &mut InstanceState,
                name: &str,
                owner_prefix: Option<String>,
            ) -> Result<(), ControlPlaneError> {
                managed_local_projection_admission()?;
                require_managed_local_owner_prefix(instance, owner_prefix)?;
                Self::check_runtime_maps_ready(&state.pin_path)?;
                let general_mutations = managed_general_state_mutations()?;
                execute_managed_local_projection_transaction(&general_mutations).await?;
                Ok(())
            }

            async fn delete_group(&self, instance: &str, name: &str) -> Result<(), ControlPlaneError> {
                let _lifecycle_guard = self.lock_runtime_lifecycle().await;
                let inst = self.get_instance(instance).await?;
                let mut state = inst.write().await;
                let authority = self.neutron_authorities.read().await
                    .get(instance).cloned();
                ensure_serialized_local_group_write_allowed(
                    instance,
                    name,
                    Some(state.managed_acl_publication_mode),
                    authority.as_ref(),
                )?;
                let owner_prefix = authority
                    .as_ref()
                    .map(|authority| format!("neutron:{}:", authority.port_id));
                self.delete_group_locked(instance, &mut state, name, owner_prefix).await
            }

            pub(crate) async fn delete_group_for_neutron_purge(
                &self,
                instance: &str,
                port_id: &str,
                name: &str,
            ) -> Result<(), ControlPlaneError> {
                let owner_prefix = format!("neutron:{}:", port_id);
                if !name.starts_with(&owner_prefix) {
                    return Err(ControlPlaneError::ValidationError(format!(
                        "Neutron purge group '{}' is outside expected owner prefix '{}'",
                        name, owner_prefix,
                    )));
                }
                let _lifecycle_guard = self.lock_runtime_lifecycle().await;
                let inst = self.get_instance(instance).await?;
                let mut state = inst.write().await;
                self.delete_group_locked(
                    instance,
                    &mut state,
                    name,
                    Some(owner_prefix),
                ).await
            }

            async fn update_config(
                &self,
                instance: &str,
                conntrack: Option<bool>,
                monitoring: Option<bool>,
                acl: Option<bool>,
                qos: Option<bool>,
                mirror: Option<bool>,
                tcprt: Option<bool>,
                ssl: Option<bool>,
            ) -> Result<(), ControlPlaneError> {
                let _lifecycle_guard = self.lock_runtime_lifecycle().await;
                let inst = self.get_instance(instance).await?;
                let publication_mode = {
                    let state = inst.read().await;
                    state.managed_acl_publication_mode
                };
                let authority = self.neutron_authorities.read().await
                    .get(instance).cloned();
                let requested_domains = requested_local_config_write_domains(
                    conntrack, monitoring, acl, qos, mirror, tcprt, ssl,
                );
                for domain in requested_domains {
                    ensure_serialized_local_write_allowed(
                        instance,
                        domain,
                        Some(publication_mode),
                        authority.as_ref(),
                    )?;
                }
                self.set_ssl_global_config();
                let mut state = inst.write().await;
                Self::check_runtime_maps_ready(&state.pin_path)?;
                aria_core::ebpf_ops::update_runtime_config();
                state.wal_append_strict();
                Ok(())
            }

            async fn flush_conntrack(&self, instance: &str) -> Result<u64, ControlPlaneError> {
                let _lifecycle_guard = self.lock_runtime_lifecycle().await;
                let inst = self.get_instance(instance).await?;
                let state = inst.read().await;
                let authority = self.neutron_authorities.read().await
                    .get(instance).cloned();
                ensure_serialized_local_write_allowed(
                    instance,
                    LocalWriteDomain::Conntrack,
                    Some(state.managed_acl_publication_mode),
                    authority.as_ref(),
                )?;
                aria_core::ct_ops::ct_flush(state.map_runtime())
                    .map_err(ControlPlaneError::KernelError)
            }

            pub(crate) async fn flush_conntrack_strict(
                &self,
                instance: &str,
            ) -> Result<u64, ControlPlaneError> {
                let _lifecycle_guard = self.lock_runtime_lifecycle().await;
                let inst = self.get_instance(instance).await?;
                let state = inst.read().await;
                aria_core::ct_ops::scrub_ct_tables_strict(state.map_runtime())
                    .map_err(ControlPlaneError::KernelError)
            }
        }

        #[cfg(test)]
        mod tests {
            async fn install_verified_managed_acl_instance_without_authority(
                cp: &ControlPlane,
                instance: &str,
                test_name: &str,
            ) {
                let mut state = stopped_wal_instance_state(test_name).await;
                state.managed_acl_publication_mode = ManagedAclPublicationMode::ManagedAcl;
                state.managed_projection_health = ManagedProjectionHealth::Verified;
                cp.instances.write().await.insert(
                    instance.to_string(),
                    Arc::new(tokio::sync::RwLock::new(state)),
                );
                assert!(
                    cp.get_neutron_port_authority(instance).await.is_none(),
                    "fixture authority must be absent",
                );
            }

            fn assert_local_write_blocked(
                error: ControlPlaneError,
                expected_instance: &str,
                expected_domain: &str,
                expected_dependency: Option<&str>,
            ) {
                assert_eq!(error.status_code(), 409);
                match error {
                    ControlPlaneError::LocalWriteBlocked {
                        instance,
                        domain,
                        dependency_of,
                    } => {
                        assert_eq!(instance, expected_instance);
                        assert_eq!(domain, expected_domain);
                        assert_eq!(dependency_of.as_deref(), expected_dependency);
                    }
                    other => panic!("unexpected {other}"),
                }
            }

            fn assert_not_local_write_blocked(
                error: ControlPlaneError,
                expected_status: u16,
            ) {
                assert_eq!(error.status_code(), expected_status);
                assert!(
                    !matches!(error, ControlPlaneError::LocalWriteBlocked { .. }),
                    "must remain allowed",
                );
            }

            fn assert_missing_runtime_maps(error: ControlPlaneError) {
                assert_eq!(error.status_code(), 503);
                match error {
                    ControlPlaneError::InstanceNotReady(reason) => {
                        assert_eq!(reason, "Pinned firewall maps not ready");
                    }
                    other => panic!("unexpected {other}"),
                }
            }

            #[tokio::test]
            async fn domain_authority_managed_acl_policy_write_add_blocks_before_authority_commit() {
                let cp = test_control_plane();
                let instance = "safe-add";
                self::install_verified_managed_acl_instance_without_authority(&cp, instance, "add").await;
                let add_error = cp.add_policy(instance).await.expect_err("blocked");
                self::assert_local_write_blocked(add_error, instance, "acl", None);
            }
            #[tokio::test]
            async fn domain_authority_managed_acl_policy_write_delete_blocks_before_authority_commit() {
                let cp = test_control_plane();
                let instance = "safe-delete";
                self::install_verified_managed_acl_instance_without_authority(&cp, instance, "delete").await;
                let delete_error = cp.delete_policy(instance).await.expect_err("blocked");
                self::assert_local_write_blocked(delete_error, instance, "acl", None);
            }
            #[tokio::test]
            async fn domain_authority_managed_acl_config_acl_blocks_before_authority_commit() {
                let cp = test_control_plane();
                let instance = "safe-acl";
                self::install_verified_managed_acl_instance_without_authority(&cp, instance, "acl").await;
                let error = cp.update_config(instance, Some(false)).await.expect_err("blocked");
                self::assert_local_write_blocked(error, instance, "acl", None);
            }
            #[tokio::test]
            async fn domain_authority_managed_acl_config_conntrack_blocks_before_authority_commit() {
                let cp = test_control_plane();
                let instance = "safe-ct";
                self::install_verified_managed_acl_instance_without_authority(&cp, instance, "ct").await;
                let error = cp.update_config(instance, Some(false)).await.expect_err("blocked");
                self::assert_local_write_blocked(error, instance, "conntrack", Some("acl"));
            }
            #[tokio::test]
            async fn domain_authority_managed_acl_config_monitoring_remains_local_before_authority_commit() {
                let cp = test_control_plane();
                let instance = "safe-monitoring";
                self::install_verified_managed_acl_instance_without_authority(&cp, instance, "monitoring").await;
                let error = cp.update_config(instance, Some(false)).await.expect_err("maps");
                self::assert_not_local_write_blocked(error, 503);
            }
            #[tokio::test]
            async fn domain_authority_managed_acl_group_namespace_survives_missing_authority() {
                let cp = test_control_plane();
                let instance = "safe-groups";
                self::install_verified_managed_acl_instance_without_authority(&cp, instance, "groups").await;
                let add_error = cp.add_group(instance, "neutron:new").await.expect_err("blocked");
                self::assert_local_write_blocked(add_error, instance, "acl", None);
                let delete_error = cp.delete_group(instance, "neutron:owned").await.expect_err("blocked");
                self::assert_local_write_blocked(delete_error, instance, "acl", None);
            }
            #[tokio::test]
            async fn domain_authority_standalone_without_authority_preserves_policy_and_config_admission() {
                let cp = test_control_plane();
                let instance = "safe-standalone";
                self::install_verified_managed_acl_instance_without_authority(&cp, instance, "standalone").await;
                let mode = ManagedAclPublicationMode::StandaloneCompatibility;
                let health = ManagedProjectionHealth::Unverified;
                let add_error = cp.add_policy(instance).await.expect_err("maps");
                self::assert_not_local_write_blocked(add_error, 503);
                let delete_error = cp.delete_policy(instance).await.expect_err("maps");
                self::assert_not_local_write_blocked(delete_error, 503);
                let acl_error = cp.update_config(instance, Some(false)).await.expect_err("maps");
                self::assert_not_local_write_blocked(acl_error, 503);
                let conntrack_error = cp.update_config(instance, Some(false)).await.expect_err("maps");
                self::assert_not_local_write_blocked(conntrack_error, 503);
            }
            #[tokio::test]
            async fn domain_authority_managed_acl_without_authority_allows_non_reserved_group_name() {
                let cp = test_control_plane();
                let instance = "safe-local-group";
                self::install_verified_managed_acl_instance_without_authority(&cp, instance, "local-group").await;
                let error = cp.add_group(instance, "local:qos").await.expect_err("authority");
                self::assert_not_local_write_blocked(error, 503);
            }
            #[tokio::test]
            async fn domain_authority_committed_qos_blocks_config_at_real_entry() {
                let cp = test_control_plane();
                let instance = "safe-qos";
                self::install_verified_managed_acl_instance_without_authority(&cp, instance, "qos").await;
                cp.mark_neutron_port_authority(instance, "port", &["qos"], 9).await;
                let error = cp.update_config(instance, Some(false)).await.expect_err("blocked");
                self::assert_local_write_blocked(error, instance, "qos", None);
            }
            #[tokio::test]
            async fn domain_authority_neutron_purge_policy_uses_privileged_serialized_entry() {
                let cp = test_control_plane();
                let instance = "safe-policy-purge";
                self::install_verified_managed_acl_instance_without_authority(&cp, instance, "policy-purge").await;
                let result = tokio::time::timeout(
                    std::time::Duration::from_secs(1),
                    cp.delete_policy_for_neutron_purge(
                        instance,
                        "policy-src",
                        "policy-dst",
                        libc::IPPROTO_TCP as u8,
                        0,
                    ),
                ).await.expect("no deadlock");
                let error = result.expect_err("maps");
                self::assert_missing_runtime_maps(error);
            }
            #[tokio::test]
            async fn domain_authority_neutron_purge_group_uses_privileged_serialized_entry() {
                let cp = test_control_plane();
                let instance = "safe-group-purge";
                self::install_verified_managed_acl_instance_without_authority(&cp, instance, "group-purge").await;
                let result = tokio::time::timeout(
                    std::time::Duration::from_secs(1),
                    cp.delete_group_for_neutron_purge(instance, "purge-port", "neutron:purge-port:src:selector:0"),
                ).await.expect("no deadlock");
                let error = result.expect_err("maps");
                self::assert_missing_runtime_maps(error);
            }
            #[tokio::test]
            async fn domain_authority_neutron_purge_group_rejects_foreign_owner_prefix() {
                let cp = test_control_plane();
                let instance = "safe-foreign-purge";
                self::install_verified_managed_acl_instance_without_authority(&cp, instance, "foreign-purge").await;
                let result = tokio::time::timeout(
                    std::time::Duration::from_secs(1),
                    cp.delete_group_for_neutron_purge(
                        instance,
                        "purge-port",
                        "neutron:foreign-port:src:selector:0",
                    ),
                ).await.expect("no deadlock");
                let error = result.expect_err("foreign");
                assert_eq!(error.status_code(), 400);
                match error {
                    ControlPlaneError::ValidationError(reason) => {
                        assert!(reason.contains("expected owner prefix 'neutron:purge-port:'"));
                        assert!(reason.contains("actual group 'neutron:foreign-port:src:selector:0'"));
                    }
                    other => panic!("unexpected {other}"),
                }
            }
            #[tokio::test]
            async fn domain_authority_managed_acl_public_flush_blocks_before_authority_commit() {
                let cp = test_control_plane();
                let instance = "safe-public-flush";
                self::install_verified_managed_acl_instance_without_authority(&cp, instance, "public-flush").await;
                let error = cp.flush_conntrack(instance).await.expect_err("blocked");
                self::assert_local_write_blocked(error, instance, "conntrack", Some("acl"));
            }
            #[tokio::test]
            async fn domain_authority_standalone_public_flush_preserves_lenient_missing_map_behavior() {
                let cp = test_control_plane();
                let instance = "safe-standalone-flush";
                self::install_verified_managed_acl_instance_without_authority(&cp, instance, "standalone-flush").await;
                {
                    let instance_state = cp.get_instance(instance).await.unwrap();
                    let mut state = instance_state.write().await;
                    state.managed_acl_publication_mode = ManagedAclPublicationMode::StandaloneCompatibility;
                    state.managed_projection_health = ManagedProjectionHealth::Unverified;
                }
                let flushed = cp.flush_conntrack(instance).await.expect("lenient");
                assert_eq!(flushed, 0);
            }
            #[tokio::test]
            async fn domain_authority_standalone_public_flush_blocks_committed_acl_dependency() {
                let cp = test_control_plane();
                let instance = "safe-authoritative-standalone-flush";
                self::install_verified_managed_acl_instance_without_authority(&cp, instance, "authoritative-standalone-flush").await;
                {
                    let instance_state = cp.get_instance(instance).await.unwrap();
                    let mut state = instance_state.write().await;
                    state.managed_acl_publication_mode = ManagedAclPublicationMode::StandaloneCompatibility;
                    state.managed_projection_health = ManagedProjectionHealth::Unverified;
                }
                cp.mark_neutron_port_authority(instance, "port-ct", &["acl".to_string()], 17).await;
                let error = cp.flush_conntrack(instance).await.expect_err("blocked");
                self::assert_local_write_blocked(error, instance, "conntrack", Some("acl"));
            }
            #[tokio::test]
            async fn domain_authority_managed_acl_strict_flush_remains_privileged_and_strict() {
                let cp = test_control_plane();
                let instance = "safe-strict-flush";
                self::install_verified_managed_acl_instance_without_authority(&cp, instance, "strict-flush").await;
                let error = cp.flush_conntrack_strict(instance).await.expect_err("strict");
                assert_eq!(error.status_code(), 500);
                match error {
                    ControlPlaneError::KernelError(reason) => {
                        assert!(reason.contains("open CT_TABLE_V4"));
                    }
                    ControlPlaneError::LocalWriteBlocked { .. } => panic!("blocked"),
                    other => panic!("unexpected {other}"),
                }
            }
        }
    '''
    safe_groups = r'''
        async fn add_group(cp: AppState, instance: String, req: Request) {
            cp.ensure_local_group_write_allowed(&instance, &req.name).await?;
            cp.add_group(&instance, &req.name).await
        }

        async fn delete_group(cp: AppState, instance: String, name: String) {
            cp.ensure_local_group_write_allowed(&instance, &name).await?;
            cp.delete_group(&instance, &name).await
        }
    '''
    safe_neutron = r'''
        async fn purge_neutron_acl(
            state: &NeutronApiState,
            ifname: &str,
            port_id: &str,
        ) -> Result<(), String> {
            let (rules, groups_by_name) = state.control_plane.list_policies(ifname).await?;
            let group_names_by_id = groups_by_name;
            let policy_delete_targets =
                acl_policy_delete_targets_for_neutron_domain(&rules, &group_names_by_id);
            for target in policy_delete_targets {
                state.control_plane.delete_policy_for_neutron_purge(
                    ifname,
                    &target.src_group,
                    &target.dst_group,
                    target.proto,
                    target.direction,
                ).await?;
            }
            let groups = state.control_plane.list_groups(ifname).await?;
            for group in groups {
                if is_neutron_acl_group(port_id, &group.name) {
                    state.control_plane.delete_group_for_neutron_purge(
                        ifname,
                        port_id,
                        &group.name,
                    ).await?;
                }
            }
            Ok(())
        }
    '''

    safe_errors = _managed_authoritative_write_admission_contract_errors(
        safe_control, safe_groups, safe_neutron
    )
    if safe_errors:
        raise SystemExit(
            "ERROR: managed authoritative admission checker rejected safe fixture: %s"
            % safe_errors
        )

    def mutate(source, old, new, occurrence=0):
        starts = [match.start() for match in re.finditer(re.escape(old), source)]
        if occurrence >= len(starts):
            raise SystemExit(
                "ERROR: authoritative admission self-test mutation source missing %r[%d]"
                % (old, occurrence)
            )
        start = starts[occurrence]
        return source[:start] + new + source[start + len(old):]

    def rewrite_function_body(source, function_name, rewrite):
        code = _blank_rust_non_code(source)
        declaration = re.search(
            r"\b(?:async\s+)?fn\s+%s\s*\(" % re.escape(function_name), code
        )
        if declaration is None:
            raise SystemExit(
                "ERROR: authoritative admission self-test function missing %s"
                % function_name
            )
        opening = code.find("{", declaration.end())
        closing = _rust_matching_brace_end(code, opening)
        if opening < 0 or closing is None:
            raise SystemExit(
                "ERROR: authoritative admission self-test function is malformed %s"
                % function_name
            )
        body = source[opening + 1:closing]
        return source[:opening + 1] + rewrite(body) + source[closing:]

    def wrap_test_in_cfg_module(source, test_name):
        code = _blank_rust_non_code(source)
        declaration = re.search(
            r"\basync\s+fn\s+%s\s*\(" % re.escape(test_name), code
        )
        if declaration is None:
            raise SystemExit(
                "ERROR: authoritative admission self-test declaration missing %s"
                % test_name
            )
        opening = code.find("{", declaration.end())
        closing = _rust_matching_brace_end(code, opening)
        attribute = code.rfind("#[tokio::test]", 0, declaration.start())
        if attribute < 0 or closing is None:
            raise SystemExit(
                "ERROR: authoritative admission self-test cannot wrap %s" % test_name
            )
        segment = source[attribute:closing + 1]
        replacement = (
            "#[cfg(any())]\n            mod hidden {\n"
            + segment
            + "\n            }"
        )
        return source[:attribute] + replacement + source[closing + 1:]

    commented_group_classifier = mutate(
        safe_control,
        "            group_name.trim().to_ascii_lowercase().starts_with(\"neutron:\")",
        "            // Reserved namespace comparison remains semantic.\n"
        "            group_name.trim().to_ascii_lowercase().starts_with(\"neutron:\")",
    )
    commented_errors = _managed_authoritative_write_admission_contract_errors(
        commented_group_classifier, safe_groups, safe_neutron
    )
    if commented_errors:
        raise SystemExit(
            "ERROR: managed authoritative admission checker rejected harmless classifier comment: %s"
            % commented_errors
        )

    cases = []

    def case(
        label,
        expected,
        control=safe_control,
        groups=safe_groups,
        neutron=safe_neutron,
    ):
        cases.append((label, control, groups, neutron, expected))

    case(
        "ManagedAcl ACL arm removed",
        "ManagedAcl mode must block ACL writes",
        mutate(
            safe_control,
            "(Some(ManagedAclPublicationMode::ManagedAcl), LocalWriteDomain::Acl) => Some(None),",
            "(Some(ManagedAclPublicationMode::StandaloneCompatibility), LocalWriteDomain::Acl) => Some(None),",
        ),
    )
    case(
        "ManagedAcl conntrack dependency removed",
        "ManagedAcl mode must block conntrack",
        mutate(
            safe_control,
            "(Some(ManagedAclPublicationMode::ManagedAcl), LocalWriteDomain::Conntrack) => {",
            "(Some(ManagedAclPublicationMode::StandaloneCompatibility), LocalWriteDomain::Conntrack) => {",
        ),
    )
    case(
        "classifier branches discarded before unconditional block",
        "classifier match must be its unique tail expression",
        rewrite_function_body(
            safe_control,
            "local_write_block_reason",
            lambda body: body + ";\n            Some(None)\n        ",
        ),
    )
    case(
        "add policy lifecycle removed",
        "add_policy must serialize lifecycle",
        mutate(
            safe_control,
            "                let _lifecycle_guard = self.lock_runtime_lifecycle().await;\n",
            "",
            0,
        ),
    )
    moved_lifecycle = mutate(
        safe_control,
        "                let _lifecycle_guard = self.lock_runtime_lifecycle().await;\n",
        "",
        0,
    )
    moved_lifecycle = mutate(
        moved_lifecycle,
        "                let mut state = inst.write().await;",
        "                let mut state = inst.write().await;\n"
        "                let _lifecycle_guard = self.lock_runtime_lifecycle().await;",
        0,
    )
    case(
        "add policy lifecycle moved after instance lock",
        "add_policy must serialize lifecycle",
        moved_lifecycle,
    )
    case(
        "add policy write lock weakened",
        "add_policy must serialize lifecycle",
        mutate(
            safe_control,
            "                let mut state = inst.write().await;",
            "                let state = inst.read().await;",
            0,
        ),
    )
    case(
        "add policy authority snapshot after admission",
        "add_policy must serialize lifecycle",
        mutate(
            safe_control,
            "                let authority = self.neutron_authorities.read().await\n"
            "                    .get(instance).cloned();\n"
            "                ensure_serialized_local_write_allowed(\n"
            "                    instance,\n"
            "                    LocalWriteDomain::Acl,\n"
            "                    Some(state.managed_acl_publication_mode),\n"
            "                    authority.as_ref(),\n"
            "                )?;",
            "                let authority = None;\n"
            "                ensure_serialized_local_write_allowed(\n"
            "                    instance,\n"
            "                    LocalWriteDomain::Acl,\n"
            "                    Some(state.managed_acl_publication_mode),\n"
            "                    authority.as_ref(),\n"
            "                )?;\n"
            "                let authority = self.neutron_authorities.read().await\n"
            "                    .get(instance).cloned();",
            0,
        ),
    )
    case(
        "add policy omits real mode",
        "add_policy must pass exact instance",
        mutate(
            safe_control,
            "                    Some(state.managed_acl_publication_mode),",
            "                    None,",
            0,
        ),
    )
    case(
        "delete policy omits authority",
        "delete_policy must pass exact instance",
        mutate(
            safe_control,
            "                    authority.as_ref(),",
            "                    None,",
            1,
        ),
    )
    case(
        "add policy drops admission error",
        "add_policy must propagate",
        mutate(safe_control, "                )?;", "                );", 0),
    )
    case(
        "add policy admission nested as a decoy",
        "unconditional top-level steps",
        mutate(
            safe_control,
            "                ensure_serialized_local_write_allowed(\n"
            "                    instance,\n"
            "                    LocalWriteDomain::Acl,\n"
            "                    Some(state.managed_acl_publication_mode),\n"
            "                    authority.as_ref(),\n"
            "                )?;",
            "                if true {\n"
            "                    ensure_serialized_local_write_allowed(\n"
            "                        instance,\n"
            "                        LocalWriteDomain::Acl,\n"
            "                        Some(state.managed_acl_publication_mode),\n"
            "                        authority.as_ref(),\n"
            "                    )?;\n"
            "                }",
            0,
        ),
    )
    case(
        "add policy state effect before admission",
        "add_policy must reject before maps",
        mutate(
            safe_control,
            "                ensure_serialized_local_write_allowed(\n",
            "                state.state.touch();\n"
            "                ensure_serialized_local_write_allowed(\n",
            0,
        ),
    )
    case(
        "delete policy effect before admission",
        "delete_policy must reject before maps",
        rewrite_function_body(
            safe_control,
            "delete_policy",
            lambda body: body.replace(
                "                ensure_serialized_local_write_allowed(\n",
                "                Self::check_runtime_maps_ready(&state.pin_path)?;\n"
                "                ensure_serialized_local_write_allowed(\n",
                1,
            ),
        ),
    )
    case(
        "delete policy drops lifecycle guard",
        "delete_policy must hold the lifecycle guard",
        rewrite_function_body(
            safe_control,
            "delete_policy",
            lambda body: body.replace(
                "                self.delete_policy_locked(\n",
                "                drop(_lifecycle_guard);\n"
                "                self.delete_policy_locked(\n",
                1,
            ),
        ),
    )
    case(
        "config monitoring domain omitted",
        "map monitoring to LocalWriteDomain::Config",
        mutate(
            safe_control,
            "            if monitoring.is_some() { domains.push(LocalWriteDomain::Config); }\n",
            "",
        ),
    )
    case(
        "config domains append an unconditional ACL domain",
        "only the seven conditional mappings",
        mutate(
            safe_control,
            "            domains\n        }\n\n        fn local_group_write_block_reason",
            "            domains.push(LocalWriteDomain::Acl);\n"
            "            domains\n        }\n\n        fn local_group_write_block_reason",
        ),
    )
    case(
        "config authority snapshot is shadowed before admission",
        "update_config must snapshot mode and authority",
        mutate(
            safe_control,
            "                let requested_domains = requested_local_config_write_domains(\n",
            "                let authority = None;\n"
            "                let requested_domains = requested_local_config_write_domains(\n",
        ),
    )
    case(
        "config admission is conditional inside the domain loop",
        "update_config must admit every requested domain",
        mutate(
            safe_control,
            "                for domain in requested_domains {\n"
            "                    ensure_serialized_local_write_allowed(\n"
            "                        instance,\n"
            "                        domain,\n"
            "                        Some(publication_mode),\n"
            "                        authority.as_ref(),\n"
            "                    )?;\n"
            "                }",
            "                for domain in requested_domains {\n"
            "                    if matches!(domain, LocalWriteDomain::Acl | LocalWriteDomain::Conntrack) {\n"
            "                        ensure_serialized_local_write_allowed(\n"
            "                            instance,\n"
            "                            domain,\n"
            "                            Some(publication_mode),\n"
            "                            authority.as_ref(),\n"
            "                        )?;\n"
            "                    }\n"
            "                }",
        ),
    )
    case(
        "config SSL effect before admission",
        "update_config must reject every requested domain before SSL",
        mutate(
            safe_control,
            "                for domain in requested_domains {\n",
            "                self.set_ssl_global_config();\n"
            "                for domain in requested_domains {\n",
        ),
    )
    case(
        "reserved namespace depends only on authority",
        "reserved neutron: namespace must survive ManagedAcl",
        mutate(
            safe_control,
            "                && (publication_mode == Some(ManagedAclPublicationMode::ManagedAcl)\n"
            "                    || authority.is_some())",
            "                && authority.is_some()",
        ),
    )
    case(
        "reserved namespace requires both mode and authority",
        "reserved neutron: namespace must survive ManagedAcl",
        mutate(
            safe_control,
            "                    || authority.is_some())",
            "                    && authority.is_some())",
        ),
    )
    case(
        "reserved classifier expression discarded before true",
        "reserved group classifier boolean must be its unique tail expression",
        rewrite_function_body(
            safe_control,
            "local_group_write_block_reason",
            lambda body: body + ";\n            true\n        ",
        ),
    )
    case(
        "add group second guard removed",
        "add_group must serialize lifecycle",
        mutate(
            safe_control,
            "                ensure_serialized_local_group_write_allowed(\n"
            "                    instance,\n"
            "                    name,\n"
            "                    Some(state.managed_acl_publication_mode),\n"
            "                    authority.as_ref(),\n"
            "                )?;\n",
            "",
            0,
        ),
    )
    case(
        "delete group second guard removed",
        "delete_group must serialize lifecycle",
        mutate(
            safe_control,
            "                ensure_serialized_local_group_write_allowed(\n"
            "                    instance,\n"
            "                    name,\n"
            "                    Some(state.managed_acl_publication_mode),\n"
            "                    authority.as_ref(),\n"
            "                )?;\n",
            "",
            1,
        ),
    )
    case(
        "add group handler preflight removed",
        "add_group handler must propagate",
        groups=mutate(
            safe_groups,
            "            cp.ensure_local_group_write_allowed(&instance, &req.name).await?;\n",
            "",
        ),
    )
    case(
        "add group handler preflight result swallowed",
        "add_group handler must propagate",
        groups=mutate(
            safe_groups,
            "            cp.ensure_local_group_write_allowed(&instance, &req.name).await?;",
            "            let _ = cp.ensure_local_group_write_allowed(&instance, &req.name).await;",
        ),
    )
    case(
        "purpose-limited policy purge entry removed",
        "purpose-limited Neutron policy purge entry is missing",
        control=mutate(
            safe_control,
            "delete_policy_for_neutron_purge",
            "removed_policy_for_neutron_purge",
            0,
        ),
    )
    case(
        "policy purge delegates through public local delete",
        "must serialize lifecycle, instance write lock, then the shared delete body",
        control=rewrite_function_body(
            safe_control,
            "delete_policy_for_neutron_purge",
            lambda body: body.replace(
                "self.delete_policy_locked(", "self.delete_policy("
            ),
        ),
    )
    case(
        "public group delete drops validated owner prefix",
        "must pass exact state and operation inputs",
        control=rewrite_function_body(
            safe_control,
            "delete_group",
            lambda body: body.replace(
                "self.delete_group_locked(instance, &mut state, name, owner_prefix)",
                "self.delete_group_locked(instance, &mut state, name, None)",
            ),
        ),
    )
    case(
        "shared policy delete body relocks lifecycle",
        "must not relock or perform local-authority admission",
        control=rewrite_function_body(
            safe_control,
            "delete_policy_locked",
            lambda body: "\n                let _again = self.lock_runtime_lifecycle().await;"
            + body,
        ),
    )
    case(
        "shared group delete effects hidden behind false",
        "must not hide effects behind a constant-false branch",
        control=rewrite_function_body(
            safe_control,
            "delete_group_locked",
            lambda body: "\n                if false {\n"
            + body
            + "\n                }\n                Ok(())\n            ",
        ),
    )
    case(
        "shared policy delete returns success before effects",
        "must not return success before its real effects",
        control=rewrite_function_body(
            safe_control,
            "delete_policy_locked",
            lambda body: body.replace(
                "                Self::check_runtime_maps_ready(&state.pin_path)?;",
                "                Self::check_runtime_maps_ready(&state.pin_path)?;\n"
                "                return Ok(());",
                1,
            ),
        ),
    )
    case(
        "shared group delete returns success before effects",
        "must not return success before its real effects",
        control=rewrite_function_body(
            safe_control,
            "delete_group_locked",
            lambda body: body.replace(
                "                managed_local_projection_admission()?;",
                "                managed_local_projection_admission()?;\n"
                "                return Ok(());",
                1,
            ),
        ),
    )
    case(
        "shared group delete effects are stringify tokens",
        "must not satisfy effects through token-string decoys",
        control=rewrite_function_body(
            safe_control,
            "delete_group_locked",
            lambda _body: r'''
                let _ = (self, instance, state, name, owner_prefix);
                let _ = stringify!(
                    managed_local_projection_admission()?;
                    require_managed_local_owner_prefix(instance, owner_prefix)?;
                    check_runtime_maps_ready(&state.pin_path)?;
                    managed_general_state_mutations()?;
                    execute_managed_local_projection_transaction()?;
                );
                Ok(())
            ''',
        ),
    )
    case(
        "group purge owner check widened to global namespace",
        "outside its exact port owner prefix",
        control=mutate(
            safe_control,
            "if !name.starts_with(&owner_prefix)",
            'if !name.starts_with("neutron:")',
        ),
    )
    case(
        "group purge exact prefix is only a comment decoy",
        "outside its exact port owner prefix",
        control=mutate(
            safe_control,
            '                let owner_prefix = format!("neutron:{}:", port_id);',
            '                // let owner_prefix = format!("neutron:{}:", port_id);\n'
            '                let owner_prefix = "neutron:".to_string();',
        ),
    )
    case(
        "Neutron purge calls public policy delete",
        "must preserve policy-first and exact-owner cleanup",
        neutron=mutate(
            safe_neutron,
            "delete_policy_for_neutron_purge",
            "delete_policy",
        ),
    )
    case(
        "Neutron purge negates exact group filter",
        "must preserve policy-first and exact-owner cleanup",
        neutron=mutate(
            safe_neutron,
            "                if is_neutron_acl_group(port_id, &group.name) {",
            "                if !is_neutron_acl_group(port_id, &group.name) {",
        ),
    )
    case(
        "Neutron purge processes only first policy",
        "must preserve policy-first and exact-owner cleanup",
        neutron=mutate(
            safe_neutron,
            "            for target in policy_delete_targets {",
            "            if let Some(target) = policy_delete_targets.first() {",
        ),
    )
    case(
        "Neutron purge hides policy cleanup behind false",
        "must preserve policy-first and exact-owner cleanup",
        neutron=mutate(
            safe_neutron,
            "            for target in policy_delete_targets {\n"
            "                state.control_plane.delete_policy_for_neutron_purge(",
            "            for target in policy_delete_targets {\n"
            "                if false {\n"
            "                    state.control_plane.delete_policy_for_neutron_purge(",
        ).replace(
            "                ).await?;\n            }\n            let groups",
            "                    ).await?;\n                }\n            }\n            let groups",
            1,
        ),
    )
    case(
        "Neutron purge hides the complete policy loop behind false",
        "must preserve policy-first and exact-owner cleanup",
        neutron=mutate(
            safe_neutron,
            "            for target in policy_delete_targets {",
            "            if false {\n"
            "            for target in policy_delete_targets {",
        ).replace(
            "            }\n            let groups",
            "            }\n            }\n            let groups",
            1,
        ),
    )
    case(
        "Neutron purge hides the complete group loop behind false",
        "must preserve policy-first and exact-owner cleanup",
        neutron=mutate(
            safe_neutron,
            "            for group in groups {",
            "            if false {\n"
            "            for group in groups {",
        ).replace(
            "            }\n            Ok(())",
            "            }\n            }\n            Ok(())",
            1,
        ),
    )
    case(
        "cfg-test Neutron purge decoy precedes unreachable real loops",
        "must preserve policy-first and exact-owner cleanup",
        neutron=r'''
            #[cfg(test)]
            mod purge_decoy {
                use super::*;

                #[cfg(any())]
                async fn purge_neutron_acl(
                    state: &NeutronApiState,
                    ifname: &str,
                    port_id: &str,
                ) -> Result<(), String> {
                    let (rules, groups_by_name) =
                        state.control_plane.list_policies(ifname).await?;
                    let group_names_by_id = groups_by_name;
                    let policy_delete_targets =
                        acl_policy_delete_targets_for_neutron_domain(
                            &rules,
                            &group_names_by_id,
                        );
                    for target in policy_delete_targets {
                        state.control_plane.delete_policy_for_neutron_purge(
                            ifname,
                            &target.src_group,
                            &target.dst_group,
                            target.proto,
                            target.direction,
                        ).await?;
                    }
                    let groups = state.control_plane.list_groups(ifname).await?;
                    for group in groups {
                        if is_neutron_acl_group(port_id, &group.name) {
                            state.control_plane.delete_group_for_neutron_purge(
                                ifname,
                                port_id,
                                &group.name,
                            ).await?;
                        }
                    }
                    Ok(())
                }
            }
        '''
        + mutate(
            mutate(
                safe_neutron,
                "            for target in policy_delete_targets {",
                "            if false {\n"
                "            for target in policy_delete_targets {",
            ).replace(
                "            }\n            let groups",
                "            }\n            }\n            let groups",
                1,
            ),
            "            for group in groups {",
            "            if false {\n"
            "            for group in groups {",
        ).replace(
            "            }\n            Ok(())",
            "            }\n            }\n            Ok(())",
            1,
        ),
    )
    case(
        "Neutron purge returns before inventory and cleanup",
        "must preserve policy-first and exact-owner cleanup",
        neutron=mutate(
            safe_neutron,
            "            let (rules, groups_by_name)",
            "            return Ok(());\n"
            "            let (rules, groups_by_name)",
        ),
    )
    case(
        "Neutron purge skips every policy loop item",
        "must preserve policy-first and exact-owner cleanup",
        neutron=mutate(
            safe_neutron,
            "            for target in policy_delete_targets {",
            "            for target in policy_delete_targets {\n"
            "                continue;",
        ),
    )
    case(
        "Neutron purge skips every group loop item",
        "must preserve policy-first and exact-owner cleanup",
        neutron=mutate(
            safe_neutron,
            "            for group in groups {",
            "            for group in groups {\n"
            "                continue;",
        ),
    )
    case(
        "Neutron purge truncates policy target collection",
        "must preserve policy-first and exact-owner cleanup",
        neutron=mutate(
            safe_neutron,
            "acl_policy_delete_targets_for_neutron_domain(&rules, &group_names_by_id);",
            "acl_policy_delete_targets_for_neutron_domain(&rules, &group_names_by_id)\n"
            "                    .into_iter().take(1).collect::<Vec<_>>();",
        ),
    )
    case(
        "Neutron purge shadows group collection with first item",
        "must preserve policy-first and exact-owner cleanup",
        neutron=mutate(
            safe_neutron,
            "            for group in groups {",
            "            let groups = groups.into_iter().take(1).collect::<Vec<_>>();\n"
            "            for group in groups {",
        ),
    )
    case(
        "Neutron purge discards direct group list result",
        "must preserve policy-first and exact-owner cleanup",
        neutron=mutate(
            safe_neutron,
            "            let groups = state.control_plane.list_groups(ifname).await?;",
            "            let groups = {\n"
            "                let _all = state.control_plane.list_groups(ifname).await?;\n"
            "                Vec::new()\n"
            "            };",
        ),
    )
    case(
        "Neutron purge acquires lifecycle outside privileged entries",
        "must not call local delete APIs or acquire a reentrant lifecycle lock",
        neutron=mutate(
            safe_neutron,
            "            let (rules, groups_by_name)",
            "            let _lifecycle_guard = state.control_plane.lock_runtime_lifecycle().await;\n"
            "            let (rules, groups_by_name)",
        ),
    )
    case(
        "privileged purge entry gains an unrelated caller",
        "must have exactly one production caller in purge_neutron_acl",
        neutron=safe_neutron
        + r'''
            async fn unrelated_bypass(cp: &ControlPlane, instance: &str) {
                cp.delete_policy_for_neutron_purge(instance, "a", "b", 6, 0).await?;
                cp.delete_group_for_neutron_purge(instance, "port", "neutron:port:g").await?;
            }
        ''',
    )
    case(
        "privileged purge entry is captured as a method item",
        "must have exactly one production caller in purge_neutron_acl",
        neutron=safe_neutron
        + r'''
            fn capture_bypass() {
                let _bypass = ControlPlane::delete_policy_for_neutron_purge;
            }
        ''',
    )
    case(
        "cfg-hidden duplicate production function precedes the real entry",
        "must have one declaration without cfg decoys",
        control=mutate(
            safe_control,
            "        impl ControlPlane {",
            "        #[cfg(any())]\n"
            "        impl ControlPlane {\n"
            "            async fn flush_conntrack(&self, instance: &str) -> Result<u64, ControlPlaneError> {\n"
            "                let _ = (self, instance);\n"
            "                Ok(0)\n"
            "            }\n"
            "        }\n\n"
            "        impl ControlPlane {",
        ),
    )
    case(
        "cfg-test module decoy precedes a weak real production entry",
        "must serialize lifecycle and instance access around its conntrack effect",
        control=mutate(
            rewrite_function_body(
                safe_control,
                "flush_conntrack",
                lambda _body: r'''
                let inst = self.get_instance(instance).await?;
                let state = inst.read().await;
                aria_core::ct_ops::ct_flush(state.map_runtime())
                    .map_err(ControlPlaneError::KernelError)
            ''',
            ),
            "        impl ControlPlane {",
            r'''
        #[cfg(test)]
        mod production_decoy {
            use super::*;

            #[cfg(any())]
            impl ControlPlane {
                async fn flush_conntrack(
                    &self,
                    instance: &str,
                ) -> Result<u64, ControlPlaneError> {
                    let _lifecycle_guard = self.lock_runtime_lifecycle().await;
                    let inst = self.get_instance(instance).await?;
                    let state = inst.read().await;
                    let authority = self.neutron_authorities.read().await
                        .get(instance).cloned();
                    ensure_serialized_local_write_allowed(
                        instance,
                        LocalWriteDomain::Conntrack,
                        Some(state.managed_acl_publication_mode),
                        authority.as_ref(),
                    )?;
                    aria_core::ct_ops::ct_flush(state.map_runtime())
                        .map_err(ControlPlaneError::KernelError)
                }
            }
        }

        impl ControlPlane {''',
        ),
    )
    case(
        "public conntrack flush runs effect before admission",
        "must serialize lifecycle and instance access around its conntrack effect",
        control=rewrite_function_body(
            safe_control,
            "flush_conntrack",
            lambda body: body.replace(
                "                ensure_serialized_local_write_allowed(\n",
                "                aria_core::ct_ops::ct_flush(state.map_runtime());\n"
                "                ensure_serialized_local_write_allowed(\n",
                1,
            ),
        ),
    )
    case(
        "public conntrack flush fabricates authority snapshot",
        "must pass a current authority snapshot",
        control=rewrite_function_body(
            safe_control,
            "flush_conntrack",
            lambda body: re.sub(
                r"let\s+authority\s*=\s*self\.neutron_authorities\.read\(\)\.await\s*"
                r"\.get\(instance\)\.cloned\(\);",
                "let authority = None;",
                body,
                count=1,
            ),
        ),
    )
    case(
        "public conntrack flush shadows exact authority snapshot",
        "must perform admission and effects in serialized order",
        control=rewrite_function_body(
            safe_control,
            "flush_conntrack",
            lambda body: body.replace(
                "                ensure_serialized_local_write_allowed(\n",
                "                let authority = None;\n"
                "                ensure_serialized_local_write_allowed(\n",
                1,
            ),
        ),
    )
    case(
        "public conntrack flush swallows kernel result",
        "must propagate the exact tap-scoped conntrack effect",
        control=rewrite_function_body(
            safe_control,
            "flush_conntrack",
            lambda body: body.replace(
                "                aria_core::ct_ops::ct_flush(state.map_runtime())\n"
                "                    .map_err(ControlPlaneError::KernelError)\n",
                "                let _ignored = aria_core::ct_ops::ct_flush(state.map_runtime());\n"
                "                Ok(0)\n",
            ),
        ),
    )
    case(
        "public conntrack flush returns success before kernel effect",
        "must not return success before its conntrack effect",
        control=rewrite_function_body(
            safe_control,
            "flush_conntrack",
            lambda body: body.replace(
                "                aria_core::ct_ops::ct_flush(state.map_runtime())",
                "                return Ok(0);\n"
                "                aria_core::ct_ops::ct_flush(state.map_runtime())",
                1,
            ),
        ),
    )
    case(
        "strict conntrack flush adds local admission",
        "must bypass local admission and use only strict scrub",
        control=rewrite_function_body(
            safe_control,
            "flush_conntrack_strict",
            lambda body: body.replace(
                "                aria_core::ct_ops::scrub_ct_tables_strict",
                "                ensure_local_write_allowed(instance)?;\n"
                "                aria_core::ct_ops::scrub_ct_tables_strict",
            ),
        ),
    )
    case(
        "strict conntrack flush uses lenient effect",
        "must serialize lifecycle and instance access around its conntrack effect",
        control=rewrite_function_body(
            safe_control,
            "flush_conntrack_strict",
            lambda body: body.replace(
                "scrub_ct_tables_strict", "ct_flush"
            ),
        ),
    )
    case(
        "strict conntrack flush returns success before strict scrub",
        "must not return success before its conntrack effect",
        control=rewrite_function_body(
            safe_control,
            "flush_conntrack_strict",
            lambda body: body.replace(
                "                aria_core::ct_ops::scrub_ct_tables_strict",
                "                if state.maps_ready() { return Ok(0); }\n"
                "                aria_core::ct_ops::scrub_ct_tables_strict",
                1,
            ),
        ),
    )
    case(
        "purge amendment test attribute removed",
        "amendment regression must actively exercise exact purge/conntrack behavior",
        control=mutate(
            safe_control,
            "            #[tokio::test]\n"
            "            async fn domain_authority_neutron_purge_policy_uses_privileged_serialized_entry",
            "            async fn domain_authority_neutron_purge_policy_uses_privileged_serialized_entry",
        ),
    )
    case(
        "public flush exact assertion is only a comment",
        "amendment regression must actively exercise exact purge/conntrack behavior",
        control=rewrite_function_body(
            safe_control,
            "domain_authority_managed_acl_public_flush_blocks_before_authority_commit",
            lambda body: body.replace(
                '                self::assert_local_write_blocked(error, instance, "conntrack", Some("acl"));',
                '                // self::assert_local_write_blocked(error, instance, "conntrack", Some("acl"));',
            ),
        ),
    )
    case(
        "standalone flush amendment loses compatibility marker",
        "amendment regression must actively exercise exact purge/conntrack behavior",
        control=rewrite_function_body(
            safe_control,
            "domain_authority_standalone_public_flush_preserves_lenient_missing_map_behavior",
            lambda body: body.replace(
                "ManagedAclPublicationMode::StandaloneCompatibility",
                "ManagedAclPublicationMode::ManagedAcl",
            ),
        ),
    )
    case(
        "committed-authority flush mutates disconnected state",
        "amendment regression must actively exercise exact purge/conntrack behavior",
        control=rewrite_function_body(
            safe_control,
            "domain_authority_standalone_public_flush_blocks_committed_acl_dependency",
            lambda body: re.sub(
                r"\{\s*let\s+instance_state\s*=\s*cp\.get_instance\(instance\)"
                r"\.await\.unwrap\(\);[\s\S]*?"
                r"state\.managed_projection_health\s*=\s*"
                r"ManagedProjectionHealth::Unverified;\s*\}",
                "{\n"
                "                    let mut state = disconnected_test_state();\n"
                "                    state.managed_acl_publication_mode = ManagedAclPublicationMode::StandaloneCompatibility;\n"
                "                    state.managed_projection_health = ManagedProjectionHealth::Unverified;\n"
                "                }",
                body,
                count=1,
            ),
        ),
    )
    case(
        "purge amendment is preceded by a same-name cfg-hidden decoy",
        "amendment regression must actively exercise exact purge/conntrack behavior",
        control=mutate(
            safe_control,
            "            #[tokio::test]\n"
            "            async fn domain_authority_neutron_purge_policy_uses_privileged_serialized_entry",
            "            #[cfg(any())]\n"
            "            #[tokio::test]\n"
            "            async fn domain_authority_neutron_purge_policy_uses_privileged_serialized_entry() {}\n"
            "            #[tokio::test]\n"
            "            async fn domain_authority_neutron_purge_policy_uses_privileged_serialized_entry",
        ),
    )
    case(
        "purge amendment fixture is hidden behind constant false",
        "amendment regression must actively exercise exact purge/conntrack behavior",
        control=rewrite_function_body(
            safe_control,
            "domain_authority_neutron_purge_policy_uses_privileged_serialized_entry",
            lambda body: body.replace(
                "                self::install_verified_managed_acl_instance_without_authority(&cp, instance, \"policy-purge\").await;",
                "                if false {\n"
                "                    self::install_verified_managed_acl_instance_without_authority(&cp, instance, \"policy-purge\").await;\n"
                "                }",
            ),
        ),
    )
    case(
        "purge amendment fixture uses other control plane",
        "amendment regression must actively exercise exact purge/conntrack behavior",
        control=rewrite_function_body(
            safe_control,
            "domain_authority_neutron_purge_policy_uses_privileged_serialized_entry",
            lambda body: body.replace(
                "(&cp, instance, \"policy-purge\")",
                "(&other_cp, instance, \"policy-purge\")",
            ),
        ),
    )
    case(
        "purge amendment fixture uses other instance",
        "amendment regression must actively exercise exact purge/conntrack behavior",
        control=rewrite_function_body(
            safe_control,
            "domain_authority_neutron_purge_group_uses_privileged_serialized_entry",
            lambda body: body.replace(
                "(&cp, instance, \"group-purge\")",
                "(&cp, other_instance, \"group-purge\")",
            ),
        ),
    )
    case(
        "purge amendment returns before fixture",
        "amendment regression must actively exercise exact purge/conntrack behavior",
        control=rewrite_function_body(
            safe_control,
            "domain_authority_neutron_purge_group_uses_privileged_serialized_entry",
            lambda body: "\n                if true { return; }\n" + body,
        ),
    )
    case(
        "purge amendment calls FakePurge receiver",
        "amendment regression must actively exercise exact purge/conntrack behavior",
        control=rewrite_function_body(
            safe_control,
            "domain_authority_neutron_purge_policy_uses_privileged_serialized_entry",
            lambda body: body.replace(
                "                let result = tokio::time::timeout(",
                "                let purge = FakePurge;\n"
                "                let result = tokio::time::timeout(",
            ).replace(
                "                    cp.delete_policy_for_neutron_purge(",
                "                    purge.delete_policy_for_neutron_purge(",
            ),
        ),
    )
    case(
        "public flush amendment shadows cp with FakePurge",
        "amendment regression must actively exercise exact purge/conntrack behavior",
        control=rewrite_function_body(
            safe_control,
            "domain_authority_managed_acl_public_flush_blocks_before_authority_commit",
            lambda body: body.replace(
                "                let error = cp.flush_conntrack",
                "                let cp = FakePurge;\n"
                "                let error = cp.flush_conntrack",
            ),
        ),
    )
    case(
        "purge amendment shadows result binding",
        "amendment regression must actively exercise exact purge/conntrack behavior",
        control=rewrite_function_body(
            safe_control,
            "domain_authority_neutron_purge_policy_uses_privileged_serialized_entry",
            lambda body: body.replace(
                "                let error = result.expect_err(\"maps\");",
                "                let result = fake_result;\n"
                "                let error = result.expect_err(\"maps\");",
            ),
        ),
    )
    case(
        "public flush amendment shadows error binding",
        "amendment regression must actively exercise exact purge/conntrack behavior",
        control=rewrite_function_body(
            safe_control,
            "domain_authority_managed_acl_public_flush_blocks_before_authority_commit",
            lambda body: body.replace(
                "                self::assert_local_write_blocked(error, instance, \"conntrack\", Some(\"acl\"));",
                "                let error = fabricated_error;\n"
                "                self::assert_local_write_blocked(error, instance, \"conntrack\", Some(\"acl\"));",
            ),
        ),
    )
    case(
        "standalone flush amendment shadows flushed binding",
        "amendment regression must actively exercise exact purge/conntrack behavior",
        control=rewrite_function_body(
            safe_control,
            "domain_authority_standalone_public_flush_preserves_lenient_missing_map_behavior",
            lambda body: body.replace(
                "                assert_eq!(flushed, 0);",
                "                let flushed = 0;\n"
                "                assert_eq!(flushed, 0);",
            ),
        ),
    )
    case(
        "public flush outcome assertion is hidden behind constant false",
        "amendment regression must actively exercise exact purge/conntrack behavior",
        control=rewrite_function_body(
            safe_control,
            "domain_authority_managed_acl_public_flush_blocks_before_authority_commit",
            lambda body: body.replace(
                "                self::assert_local_write_blocked(error, instance, \"conntrack\", Some(\"acl\"));",
                "                if false {\n"
                "                    self::assert_local_write_blocked(error, instance, \"conntrack\", Some(\"acl\"));\n"
                "                }",
            ),
        ),
    )
    case(
        "foreign-owner expected strings survive only in comments",
        "amendment regression must actively exercise exact purge/conntrack behavior",
        control=rewrite_function_body(
            safe_control,
            "domain_authority_neutron_purge_group_rejects_foreign_owner_prefix",
            lambda body: body.replace(
                "                        assert!(reason.contains(\"expected owner prefix 'neutron:purge-port:'\"));\n"
                "                        assert!(reason.contains(\"actual group 'neutron:foreign-port:src:selector:0'\"));",
                "                        // assert!(reason.contains(\"expected owner prefix 'neutron:purge-port:'\"));\n"
                "                        // assert!(reason.contains(\"actual group 'neutron:foreign-port:src:selector:0'\"));",
            ),
        ),
    )
    case(
        "strict expected kernel string survives only in a comment",
        "amendment regression must actively exercise exact purge/conntrack behavior",
        control=rewrite_function_body(
            safe_control,
            "domain_authority_managed_acl_strict_flush_remains_privileged_and_strict",
            lambda body: body.replace(
                "                        assert!(reason.contains(\"open CT_TABLE_V4\"));",
                "                        // assert!(reason.contains(\"open CT_TABLE_V4\"));",
            ),
        ),
    )
    case(
        "policy regression test removed",
        "real-entry regression test must be active",
        control=mutate(
            safe_control,
            "domain_authority_managed_acl_policy_write_add_blocks_before_authority_commit",
            "removed_policy_gap_test",
        ),
    )
    regression_test_names = (
        "domain_authority_managed_acl_policy_write_add_blocks_before_authority_commit",
        "domain_authority_managed_acl_policy_write_delete_blocks_before_authority_commit",
        "domain_authority_managed_acl_config_acl_blocks_before_authority_commit",
        "domain_authority_managed_acl_config_conntrack_blocks_before_authority_commit",
        "domain_authority_managed_acl_config_monitoring_remains_local_before_authority_commit",
        "domain_authority_managed_acl_group_namespace_survives_missing_authority",
        "domain_authority_standalone_without_authority_preserves_policy_and_config_admission",
        "domain_authority_managed_acl_without_authority_allows_non_reserved_group_name",
        "domain_authority_committed_qos_blocks_config_at_real_entry",
    )
    for test_name in regression_test_names:
        case(
            "%s test attribute removed" % test_name,
            "real-entry regression test must be active",
            control=mutate(
                safe_control,
                "            #[tokio::test]\n            async fn %s" % test_name,
                "            async fn %s" % test_name,
            ),
        )
        case(
            "%s test body emptied" % test_name,
            "must install the real authority-gap fixture",
            control=rewrite_function_body(
                safe_control, test_name, lambda body: ""
            ),
        )

    case(
        "exact regression test marked ignored",
        "real-entry regression test must be active",
        control=mutate(
            safe_control,
            "            #[tokio::test]\n"
            "            async fn domain_authority_managed_acl_policy_write_add_blocks_before_authority_commit",
            "            #[ignore]\n"
            "            #[tokio::test]\n"
            "            async fn domain_authority_managed_acl_policy_write_add_blocks_before_authority_commit",
        ),
    )
    case(
        "exact regression test hidden behind cfg",
        "real-entry regression test must be active",
        control=mutate(
            safe_control,
            "            #[tokio::test]\n"
            "            async fn domain_authority_managed_acl_policy_write_delete_blocks_before_authority_commit",
            "            #[cfg(any())]\n"
            "            #[tokio::test]\n"
            "            async fn domain_authority_managed_acl_policy_write_delete_blocks_before_authority_commit",
        ),
    )
    case(
        "blocked assertion helper emptied",
        "blocked assertion helper must enforce status",
        control=rewrite_function_body(
            safe_control, "assert_local_write_blocked", lambda body: ""
        ),
    )
    case(
        "blocked assertion helper always passes",
        "blocked assertion helper must enforce status",
        control=rewrite_function_body(
            safe_control,
            "assert_local_write_blocked",
            lambda body: "\n                let _ = (error, expected_instance, expected_domain, expected_dependency);\n            ",
        ),
    )
    case(
        "blocked assertion context hidden in unused closure",
        "blocked assertion helper must enforce status",
        control=rewrite_function_body(
            safe_control,
            "assert_local_write_blocked",
            lambda body: body.replace(
                "                        assert_eq!(instance, expected_instance);\n"
                "                        assert_eq!(domain, expected_domain);\n"
                "                        assert_eq!(dependency_of.as_deref(), expected_dependency);",
                "                        let _unused = || {\n"
                "                            assert_eq!(instance, expected_instance);\n"
                "                            assert_eq!(domain, expected_domain);\n"
                "                            assert_eq!(dependency_of.as_deref(), expected_dependency);\n"
                "                        };",
            ),
        ),
    )
    case(
        "allowed assertion helper emptied",
        "allowed assertion helper must enforce status",
        control=rewrite_function_body(
            safe_control, "assert_not_local_write_blocked", lambda body: ""
        ),
    )
    case(
        "allowed assertion helper always passes",
        "allowed assertion helper must enforce status",
        control=rewrite_function_body(
            safe_control,
            "assert_not_local_write_blocked",
            lambda body: "\n                let _ = (error, expected_status);\n            ",
        ),
    )
    case(
        "authority-gap fixture emptied",
        "fixture must uniquely install ManagedAcl Verified",
        control=rewrite_function_body(
            safe_control,
            "install_verified_managed_acl_instance_without_authority",
            lambda body: "",
        ),
    )
    case(
        "authority-gap fixture uses standalone mode",
        "fixture must uniquely install ManagedAcl Verified",
        control=mutate(
            safe_control,
            "state.managed_acl_publication_mode = ManagedAclPublicationMode::ManagedAcl;",
            "state.managed_acl_publication_mode = ManagedAclPublicationMode::StandaloneCompatibility;",
        ),
    )
    case(
        "authority-gap fixture uses unverified health",
        "fixture must uniquely install ManagedAcl Verified",
        control=mutate(
            safe_control,
            "state.managed_projection_health = ManagedProjectionHealth::Verified;",
            "state.managed_projection_health = ManagedProjectionHealth::Unverified;",
        ),
    )
    case(
        "authority-gap fixture drops authority-none proof",
        "fixture must uniquely install ManagedAcl Verified",
        control=mutate(
            safe_control,
            "                assert!(\n"
            "                    cp.get_neutron_port_authority(instance).await.is_none(),\n"
            "                    \"fixture authority must be absent\",\n"
            "                );\n",
            "",
        ),
    )
    case(
        "authority-gap fixture proof is tautological",
        "fixture must uniquely install ManagedAcl Verified",
        control=mutate(
            safe_control,
            "cp.get_neutron_port_authority(instance).await.is_none(),",
            "cp.get_neutron_port_authority(instance).await.is_none() || true,",
        ),
    )
    case(
        "authority-gap fixture rewrites authority after proof",
        "fixture must uniquely install ManagedAcl Verified",
        control=rewrite_function_body(
            safe_control,
            "install_verified_managed_acl_instance_without_authority",
            lambda body: body
            + "\n                cp.neutron_authorities.write().await.insert(instance.to_string(), authority);\n            ",
        ),
    )
    case(
        "regression test module hidden by outer cfg",
        "test module must have only its active cfg(test) gate",
        control=mutate(
            safe_control,
            "        #[cfg(test)]\n        mod tests {",
            "        #[cfg(any())]\n        #[cfg(test)]\n        mod tests {",
        ),
    )
    case(
        "regression test module hidden by inner cfg",
        "test module must have only its active cfg(test) gate",
        control=mutate(
            safe_control,
            "        mod tests {\n",
            "        mod tests {\n            #![cfg(any())]\n",
        ),
    )

    for test_name in (
        "domain_authority_managed_acl_policy_write_add_blocks_before_authority_commit",
        "domain_authority_standalone_without_authority_preserves_policy_and_config_admission",
        "domain_authority_managed_acl_group_namespace_survives_missing_authority",
    ):
        case(
            "%s body hidden behind false" % test_name,
            "must install the real authority-gap fixture",
            control=rewrite_function_body(
                safe_control,
                test_name,
                lambda body: "\n                if false {\n%s\n                }\n            "
                % body,
            ),
        )

    case(
        "blocked regression test returns before fixture",
        "must install the real authority-gap fixture",
        control=rewrite_function_body(
            safe_control,
            "domain_authority_managed_acl_policy_write_add_blocks_before_authority_commit",
            lambda body: "\n                return;\n" + body,
        ),
    )
    case(
        "allowed regression test conditionally returns before fixture",
        "must install the real authority-gap fixture",
        control=rewrite_function_body(
            safe_control,
            "domain_authority_standalone_without_authority_preserves_policy_and_config_admission",
            lambda body: "\n                if true { return; }\n" + body,
        ),
    )
    case(
        "group regression test exits process successfully",
        "must install the real authority-gap fixture",
        control=rewrite_function_body(
            safe_control,
            "domain_authority_managed_acl_group_namespace_survives_missing_authority",
            lambda body: "\n                std::process::exit(0);\n" + body,
        ),
    )
    case(
        "blocked regression shadows assertion helper",
        "bind real cp and instance once without shadowing helpers",
        control=rewrite_function_body(
            safe_control,
            "domain_authority_managed_acl_policy_write_add_blocks_before_authority_commit",
            lambda body: body.replace(
                "                let add_error = cp.add_policy(instance).await.expect_err(\"blocked\");",
                "                let assert_local_write_blocked = "
                "|_: ControlPlaneError, _: &str, _: &str, _: Option<&str>| {};\n"
                "                let add_error = cp.add_policy(instance).await.expect_err(\"blocked\");",
            ),
        ),
    )
    case(
        "blocked regression replaces qualified assertion with const function pointer",
        "must assert the exact add_policy outcome",
        control=rewrite_function_body(
            safe_control,
            "domain_authority_managed_acl_policy_write_add_blocks_before_authority_commit",
            lambda body: body.replace(
                "                self::assert_local_write_blocked(add_error, instance, \"acl\", None);",
                "                fn swallow_blocked(\n"
                "                    _: ControlPlaneError,\n"
                "                    _: &str,\n"
                "                    _: &str,\n"
                "                    _: Option<&str>,\n"
                "                ) {}\n"
                "                const assert_local_write_blocked: fn(\n"
                "                    ControlPlaneError,\n"
                "                    &str,\n"
                "                    &str,\n"
                "                    Option<&str>,\n"
                "                ) = swallow_blocked;\n"
                "                assert_local_write_blocked(add_error, instance, \"acl\", None);",
            ),
        ),
    )
    case(
        "blocked regression shadows authority-gap fixture helper",
        "bind real cp and instance once without shadowing helpers",
        control=rewrite_function_body(
            safe_control,
            "domain_authority_managed_acl_policy_write_add_blocks_before_authority_commit",
            lambda body: body.replace(
                "                self::install_verified_managed_acl_instance_without_authority(&cp, instance, \"add\").await;",
                "                let install_verified_managed_acl_instance_without_authority = "
                "|_: &ControlPlane, _: &str, _: &str| async {};\n"
                "                install_verified_managed_acl_instance_without_authority(&cp, instance, \"add\").await;",
            ),
        ),
    )
    case(
        "blocked regression rebinds control plane after fixture",
        "bind real cp and instance once without shadowing helpers",
        control=rewrite_function_body(
            safe_control,
            "domain_authority_managed_acl_policy_write_add_blocks_before_authority_commit",
            lambda body: body.replace(
                "                let add_error = cp.add_policy(instance).await.expect_err(\"blocked\");",
                "                let cp = FakeControlPlane;\n"
                "                let add_error = cp.add_policy(instance).await.expect_err(\"blocked\");",
            ),
        ),
    )
    case(
        "blocked regression fabricates result after real entry",
        "must exercise add_policy through the real entry",
        control=rewrite_function_body(
            safe_control,
            "domain_authority_managed_acl_policy_write_add_blocks_before_authority_commit",
            lambda body: body.replace(
                "                self::assert_local_write_blocked(add_error, instance, \"acl\", None);",
                "                let add_error = ControlPlaneError::LocalWriteBlocked {\n"
                "                    instance: instance.to_string(),\n"
                "                    domain: \"acl\".to_string(),\n"
                "                    dependency_of: None,\n"
                "                };\n"
                "                self::assert_local_write_blocked(add_error, instance, \"acl\", None);",
            ),
        ),
    )
    case(
        "exact regression nested in cfg-hidden module",
        "real-entry regression test must be active",
        control=wrap_test_in_cfg_module(
            safe_control,
            "domain_authority_managed_acl_policy_write_add_blocks_before_authority_commit",
        ),
    )

    case(
        "policy test real entry removed",
        "must exercise add_policy through the real entry",
        control=rewrite_function_body(
            safe_control,
            "domain_authority_managed_acl_policy_write_add_blocks_before_authority_commit",
            lambda body: body.replace(
                '                let add_error = cp.add_policy(instance).await.expect_err("blocked");\n',
                "",
            ),
        ),
    )
    case(
        "policy test exact assertion removed",
        "must assert the exact add_policy outcome",
        control=rewrite_function_body(
            safe_control,
            "domain_authority_managed_acl_policy_write_add_blocks_before_authority_commit",
            lambda body: body.replace(
                '                self::assert_local_write_blocked(add_error, instance, "acl", None);\n',
                "",
            ),
        ),
    )

    for label, control, groups, neutron, expected in cases:
        errors = _managed_authoritative_write_admission_contract_errors(
            control, groups, neutron
        )
        if not any(expected in error for error in errors):
            raise SystemExit(
                "ERROR: managed authoritative admission checker accepted %s: %s"
                % (label, errors)
            )
    print(
        "Managed authoritative write admission self-tests: OK (%d scenarios)"
        % (len(cases) + 2)
    )


def _managed_cross_domain_group_mutation_contract_errors(
    control_plane_source,
    groups_handler_source,
    qos_handler_source,
    mirror_handler_source,
):
    """Return Task 5 contract violations in stable, user-facing priority order."""
    control_code = _blank_rust_non_code(control_plane_source)
    handler_codes = {
        "groups": _blank_rust_non_code(groups_handler_source),
        "qos": _blank_rust_non_code(qos_handler_source),
        "mirror": _blank_rust_non_code(mirror_handler_source),
    }
    wrapper_specs = {
        "add_group": {
            "standalone": "add_group_standalone_locked",
            "order": "GeneralThenDomain",
            "planner": r"\blet\s+domain_operations\s*=\s*Vec\s*::\s*new\s*\(\s*\)",
            "final_uses_domain": False,
            "direction_source": None,
        },
        "delete_group": {
            "standalone": "delete_group_standalone_locked",
            "order": "GeneralThenDomain",
            "planner": r"\blet\s+domain_operations\s*=\s*Vec\s*::\s*new\s*\(\s*\)",
            "final_uses_domain": False,
            "direction_source": None,
        },
        "add_qos": {
            "standalone": "add_qos_standalone_locked",
            "order": "GeneralThenDomain",
            "planner": (
                r"\blet\s+domain_operations\s*=\s*"
                r"plan_managed_local_qos_upserts\s*\([^;]*"
                r"\bdirection_plans\b[^;]*\)"
            ),
            "final_uses_domain": True,
            "direction_source": (
                r"\blet\s+direction_plans\s*=\s*"
                r"managed_qos_direction_plans\s*\(\s*direction\s*,\s*mode\s*\)"
            ),
        },
        "delete_qos": {
            "standalone": "delete_qos_standalone_locked",
            "order": "DomainThenGeneral",
            "planner": (
                r"\blet\s+domain_operations\s*=\s*"
                r"plan_managed_local_qos_delete\s*\([^;]*\bdirections\b[^;]*\)"
            ),
            "final_uses_domain": True,
            "direction_source": (
                r"\blet\s+directions\s*=\s*requested_directions\s*"
                r"\(\s*direction\s*\)"
            ),
        },
        "add_mirror": {
            "standalone": "add_mirror_standalone_locked",
            "order": "GeneralThenDomain",
            "planner": (
                r"\blet\s+domain_operations\s*=\s*"
                r"plan_managed_local_mirror_upserts\s*\([^;]*\bdirections\b[^;]*\)"
            ),
            "final_uses_domain": True,
            "direction_source": (
                r"\blet\s+directions\s*=\s*requested_directions\s*"
                r"\(\s*direction\s*\)"
            ),
        },
        "delete_mirror": {
            "standalone": "delete_mirror_standalone_locked",
            "order": "DomainThenGeneral",
            "planner": (
                r"\blet\s+domain_operations\s*=\s*"
                r"plan_managed_local_mirror_delete\s*\([^;]*\bdirections\b[^;]*\)"
            ),
            "final_uses_domain": True,
            "direction_source": (
                r"\blet\s+directions\s*=\s*requested_directions\s*"
                r"\(\s*direction\s*\)"
            ),
        },
    }
    bodies = {
        name: _rust_function_body_from_blanked(control_code, name)
        for name in wrapper_specs
    }
    errors = []
    active_acl_access = re.compile(
        r"\b(?:read_acl_active_bank|add_acl_network_in_bank|"
        r"delete_acl_network_in_bank|set_acl_active_bank|stage_acl_shadow_bank)\s*\("
    )
    if any(
        bodies[name] and active_acl_access.search(bodies[name])
        for name in ("add_group", "delete_group")
    ):
        errors.append("managed local group add/delete still mutates the active ACL bank")

    missing = [name for name, body in bodies.items() if body is None]
    if missing:
        errors.append(
            "managed cross-domain mutation functions are missing: %s"
            % ", ".join(missing)
        )

    lifecycle_pattern = re.compile(
        r"\blet\s+(?P<guard>_?[A-Za-z][A-Za-z0-9_]*)\s*=\s*"
        r"self\s*\.\s*lock_runtime_lifecycle\s*\(\s*\)\s*\.\s*await\s*;"
    )
    write_lock_pattern = re.compile(r"\.\s*write\s*\(\s*\)\s*\.\s*await\b")
    plan_pattern = re.compile(
        r"\bmanaged_general_state_mutations\s*\(\s*&\s*old_state\s*,"
        r"\s*&\s*final_state\s*\)"
    )
    executor_pattern = re.compile(
        r"\bexecute_managed_local_projection_transaction\s*\("
    )
    direct_managed_write = re.compile(
        active_acl_access.pattern
        + r"|\baria_core\s*::\s*ebpf_ops\s*::\s*(?:add|delete)_network\s*\("
        + r"|\bapply_shared_network_mutation\s*\("
        + r"|\baria_core\s*::\s*(?:qos_ops|mirror_ops)\s*::\s*\w+\s*\("
    )
    delegated_helpers = {"apply": set(), "compensate": set()}
    snapshot_factories = {"persist": set(), "restore": set()}
    for name, spec in wrapper_specs.items():
        standalone_helper = spec["standalone"]
        body = bodies[name]
        if body is None:
            continue
        lifecycle = lifecycle_pattern.search(body)
        instance = body.find("get_instance")
        write_lock = write_lock_pattern.search(body)
        if (
            lifecycle is None
            or instance < 0
            or write_lock is None
            or not lifecycle.start() < instance < write_lock.start()
        ):
            errors.append(
                "managed %s must acquire lifecycle then instance write lock" % name
            )
        elif re.search(
            r"\b(?:std\s*::\s*mem\s*::\s*)?drop\s*\(\s*%s\s*\)"
            % re.escape(lifecycle.group("guard")),
            body[lifecycle.end():],
        ):
            errors.append("managed %s must hold the lifecycle guard to return" % name)

        standalone_call = body.find(standalone_helper)
        admission = body.find("managed_local_projection_admission")
        dispatch_region = body[:admission] if admission >= 0 else ""
        explicit_modes = all(
            marker in body
            for marker in (
                "managed_acl_publication_mode",
                "ManagedAclPublicationMode::StandaloneCompatibility",
                "ManagedAclPublicationMode::NeutronAttachOwnedStandaloneAcl",
                "ManagedAclPublicationMode::ManagedAcl",
            )
        )
        if (
            not explicit_modes
            or standalone_call < 0
            or admission < 0
            or standalone_call > admission
            or "ManagedAclPublicationMode::StandaloneCompatibility" not in dispatch_region
            or "ManagedAclPublicationMode::NeutronAttachOwnedStandaloneAcl" not in dispatch_region
        ):
            errors.append(
                "%s must explicitly dispatch both standalone modes before managed admission"
                % name
            )

        if admission >= 0 and write_lock is not None:
            before_admission = body[write_lock.end():admission]
            if (
                "state.state" in before_admission
                or re.search(r"\bwal_append\s*\(", before_admission)
                or direct_managed_write.search(before_admission)
                or re.search(
                    r"\b(?:compact_and_publish_state|persist_managed_local_projection_state)\s*\(",
                    before_admission,
                )
            ):
                errors.append(
                    "managed %s must reject before state, WAL, or kernel effects" % name
                )

        old_state = re.search(r"\blet\s+(?:mut\s+)?old_state\b", body)
        final_state = re.search(r"\blet\s+(?:mut\s+)?final_state\b", body)
        plans = list(plan_pattern.finditer(body))
        executors = list(executor_pattern.finditer(body))
        domain_planner = re.search(spec["planner"], body)
        direction_source = (
            re.search(spec["direction_source"], body)
            if spec["direction_source"] is not None
            else None
        )
        if spec["direction_source"] is not None:
            planner_statement_end = (
                body.find(";", domain_planner.start())
                if domain_planner is not None
                else -1
            )
            planner_statement = (
                body[domain_planner.start():planner_statement_end]
                if planner_statement_end >= 0
                else ""
            )
            if (
                direction_source is None
                or domain_planner is None
                or direction_source.start() > domain_planner.start()
                or "&old_state" not in re.sub(r"\s+", "", planner_statement)
            ):
                errors.append(
                    "managed %s must feed expanded directions and old_state to its full planner"
                    % name
                )
        order_pattern = re.compile(
            r"\blet\s+projection_order\s*=\s*"
            r"ManagedLocalProjectionOrder\s*::\s*%s\s*;"
            % spec["order"]
        )
        projection_order = order_pattern.search(body)
        merge_bindings = list(
            re.finditer(
                r"\blet\s+operations\s*=\s*"
                r"merge_managed_local_projection_operations\s*\(",
                body,
            )
        )
        merge_arguments = None
        if len(merge_bindings) == 1:
            opening = body.find("(", merge_bindings[0].start())
            merge_arguments = _rust_parenthesized_body_at(body, opening)
        merge_items = (
            _rust_split_top_level_arguments(merge_arguments)
            if merge_arguments is not None
            else []
        )
        normalized_merge_items = [re.sub(r"\s+", "", item) for item in merge_items]
        operations_assignments = re.findall(
            r"\b(?:let\s+(?:mut\s+)?)?operations\s*=", body
        )
        ordered = (
            admission >= 0
            and old_state is not None
            and final_state is not None
            and domain_planner is not None
            and projection_order is not None
            and len(plans) == 1
            and len(merge_bindings) == 1
            and len(executors) == 1
            and admission
            < old_state.start()
            < domain_planner.start()
            < final_state.start()
            < plans[0].start()
            < projection_order.start()
            < merge_bindings[0].start()
            < executors[0].start()
        )
        if not ordered:
            errors.append(
                "%s must plan old_state to final_state before one shared executor call"
                % name
            )
        if (
            len(merge_bindings) != 1
            or len(operations_assignments) != 1
            or normalized_merge_items
            != ["projection_order", "general_mutations", "domain_operations"]
        ):
            errors.append(
                "%s operations must come only from the ordered general/domain merge"
                % name
            )
        if spec["final_uses_domain"] and final_state is not None:
            final_statement_end = body.find(";", final_state.start())
            final_statement = body[
                final_state.start():
                final_statement_end if final_statement_end >= 0 else len(body)
            ]
            if "domain_operations" not in final_statement:
                errors.append(
                    "managed %s must build final_state from the planned domain operations"
                    % name
                )
        persist_binding = re.search(
            r"\blet\s+persist_final_state\s*=\s*"
            r"(?P<factory>[A-Za-z_][A-Za-z0-9_]*)\s*\(",
            body,
        )
        restore_binding = re.search(
            r"\blet\s+restore_old_state\s*=\s*"
            r"(?P<factory>[A-Za-z_][A-Za-z0-9_]*)\s*\(",
            body,
        )
        apply_binding = re.search(
            r"\blet\s+apply_projection_operation\s*=\s*"
            r"(?P<factory>[A-Za-z_][A-Za-z0-9_]*)\s*\(",
            body,
        )
        compensate_binding = re.search(
            r"\blet\s+compensate_projection_receipt\s*=\s*"
            r"(?P<factory>[A-Za-z_][A-Za-z0-9_]*)\s*\(",
            body,
        )
        health_binding = re.search(
            r"\blet\s+(?:mut\s+)?set_projection_health\s*=\s*"
            r"\|\s*health\s*\|\s*\{\s*"
            r"state\s*\.\s*managed_projection_health\s*=\s*health\s*;\s*\}\s*;",
            body,
        )
        health_assignments = re.findall(
            r"\bstate\s*\.\s*managed_projection_health\s*=", body
        )
        if (
            health_binding is None
            or len(health_assignments) != 1
            or not executors
            or health_binding.start() > executors[0].start()
        ):
            errors.append(
                "managed %s must bind its real projection-health setter" % name
            )
        operation_bindings_valid = (
            apply_binding is not None
            and compensate_binding is not None
            and executors
            and merge_bindings
            and merge_bindings[0].start()
            < apply_binding.start()
            < compensate_binding.start()
            < executors[0].start()
        )
        if operation_bindings_valid:
            delegated_helpers["apply"].add(apply_binding.group("factory"))
            delegated_helpers["compensate"].add(
                compensate_binding.group("factory")
            )
        else:
            errors.append(
                "%s must bind shared apply and compensation receipt closures"
                % name
            )

        snapshot_bindings_valid = False
        if persist_binding is not None and restore_binding is not None:
            persist_arguments = _rust_parenthesized_body_at(
                body, body.find("(", persist_binding.start())
            )
            restore_arguments = _rust_parenthesized_body_at(
                body, body.find("(", restore_binding.start())
            )
            snapshot_bindings_valid = (
                persist_arguments is not None
                and restore_arguments is not None
                and re.search(r"&\s*final_state\b", persist_arguments)
                and re.search(r"&\s*old_state\b", restore_arguments)
                and executors
                and merge_bindings
                and merge_bindings[0].start()
                < persist_binding.start()
                < restore_binding.start()
                < executors[0].start()
            )
            if snapshot_bindings_valid:
                snapshot_factories["persist"].add(
                    persist_binding.group("factory")
                )
                snapshot_factories["restore"].add(
                    restore_binding.group("factory")
                )
        if not snapshot_bindings_valid:
            errors.append(
                "%s persistence and restore closures must capture final_state and old_state"
                % name
            )

        if len(executors) != 1:
            errors.append("%s must call the shared executor exactly once" % name)
        else:
            executor_arguments = _rust_parenthesized_body_at(
                body, body.find("(", executors[0].start())
            )
            executor_items = (
                _rust_split_top_level_arguments(executor_arguments)
                if executor_arguments is not None
                else []
            )
            normalized_executor_items = [
                re.sub(r"\s+", "", item) for item in executor_items
            ]
            if (
                len(normalized_executor_items) != 6
                or normalized_executor_items[0] != "&operations"
                or normalized_executor_items[1] != "set_projection_health"
                or normalized_executor_items[2] != "apply_projection_operation"
                or normalized_executor_items[3] != "persist_final_state"
                or normalized_executor_items[4] != "compensate_projection_receipt"
                or normalized_executor_items[5] != "restore_old_state"
            ):
                errors.append(
                    "%s must pass planned operations and final/old snapshot closures to one executor"
                    % name
                )
            state_publish = re.search(
                r"\bstate\s*\.\s*state\s*=\s*final_state\s*;", body
            )
            executor_to_publish = (
                body[executors[0].start():state_publish.start()]
                if state_publish is not None
                and executors[0].start() < state_publish.start()
                else ""
            )
            if state_publish is None or not re.search(
                r"\.\s*await(?:\s*\.\s*map_err\s*\([^;]+\))?\s*\?\s*;",
                executor_to_publish,
            ):
                errors.append(
                    "managed %s must publish final_state only after executor success"
                    % name
                )

        if direct_managed_write.search(body):
            errors.append("managed %s must not bypass the shared executor" % name)
        if re.search(r"\bcompact_and_publish_state\s*\(", body):
            errors.append(
                "managed %s must leave persistence to the shared executor"
                % name
            )

        if name in ("add_group", "delete_group"):
            validation = body.find("validate_managed_group_mutation")
            if (
                old_state is None
                or not executors
                or validation < 0
                or not old_state.start() < validation < executors[0].start()
            ):
                errors.append(
                    "managed %s must validate ACL references before execution" % name
                )
        if name in ("delete_qos", "delete_mirror") and plans:
            retention = body.find("reconcile_retained_owned_groups")
            if final_state is None or not final_state.start() < retention < plans[0].start():
                errors.append(
                    "managed %s must reconcile retained groups before projection planning"
                    % name
                )

    admission_body = _rust_function_body_from_blanked(
        control_code, "managed_local_projection_admission"
    )
    if admission_body is None or not all(
        marker in admission_body
        for marker in (
            "ManagedAclPublicationMode::ManagedAcl",
            "ManagedProjectionHealth::Verified",
            "ManagedProjectionHealth::Unverified",
            "ManagedProjectionHealth::RepairRequired",
            "ControlPlaneError::InstanceNotReady",
        )
    ):
        errors.append(
            "managed admission must accept only Verified managed projection health"
        )

    validation_body = _rust_function_body_from_blanked(
        control_code, "validate_managed_group_mutation"
    )
    if validation_body is None or not all(
        marker in validation_body
        for marker in ("rules", "src_group_id", "dst_group_id", "GroupInUse")
    ):
        errors.append("managed group mutation must validate ACL references by group ID")

    projection_body = _rust_function_body_from_blanked(
        control_code, "managed_general_state_mutations"
    )
    projection_flow = re.search(
        r"\blet\s+(\w+)\s*=\s*compile_managed_group_projection\s*"
        r"\(\s*old_state\s*\)[\s\S]*?"
        r"\blet\s+(\w+)\s*=\s*compile_managed_group_projection\s*"
        r"\(\s*final_state\s*\)[\s\S]*?"
        r"\bmanaged_general_projection_mutations\s*"
        r"\(\s*&\s*\1\s*,\s*&\s*\2\s*,?\s*\)",
        projection_body or "",
    )
    if (
        projection_body is None
        or projection_body.count("compile_managed_group_projection") != 2
        or projection_flow is None
    ):
        errors.append(
            "managed projection delta must compare exact old_state and final_state projections"
        )

    directions_body = _rust_function_body_from_blanked(
        control_code, "requested_directions"
    )
    direction_two_expands = directions_body is not None and (
        re.search(
            r"\b2\s*=>[\s\S]{0,120}\bvec!\s*\[\s*0\s*,\s*1\s*\]",
            directions_body,
        )
        or re.search(
            r"\bdirection\s*==\s*2[\s\S]{0,120}"
            r"\bvec!\s*\[\s*0\s*,\s*1\s*\]",
            directions_body,
        )
    )
    if not direction_two_expands:
        errors.append("requested direction 2 must expand to ingress and egress")

    qos_plan_body = _rust_function_body_from_blanked(
        control_code, "managed_qos_direction_plans"
    )
    qos_plan_compact = re.sub(r"\s+", "", qos_plan_body or "")
    downgrade_markers = (
        "ifdirection==0&&mode==1{0}else{mode}",
        "ifmode==1&&direction==0{0}else{mode}",
        "(0,1)=>0",
    )
    if (
        qos_plan_body is None
        or not re.search(
            r"\brequested_directions\s*\(\s*direction\s*\)", qos_plan_body
        )
        or "effective_mode" not in qos_plan_body
        or not any(marker in qos_plan_compact for marker in downgrade_markers)
    ):
        errors.append(
            "QoS direction planning must preserve both-direction mode semantics"
        )
    qos_upsert_plan_body = _rust_function_body_from_blanked(
        control_code, "plan_managed_local_qos_upserts"
    )
    if (
        qos_upsert_plan_body is None
        or "old_state" not in qos_upsert_plan_body
        or "direction_plans" not in qos_upsert_plan_body
        or "ManagedLocalDomainOperation::EnsureFqQdisc" not in qos_upsert_plan_body
        or "ManagedLocalDomainOperation::QosUpsert" not in qos_upsert_plan_body
        or qos_upsert_plan_body.find("ManagedLocalDomainOperation::EnsureFqQdisc")
        > qos_upsert_plan_body.find("ManagedLocalDomainOperation::QosUpsert")
    ):
        errors.append(
            "QoS full planner must ensure qdisc before ordered domain upserts"
        )

    standalone_markers = {
        "add_group": ("add_network", "add_acl_network_in_bank", "wal_append"),
        "delete_group": ("delete_network", "delete_acl_network_in_bank", "wal_append"),
        "add_qos": ("qos_ops", "add_qos_rule", "wal_append"),
        "delete_qos": ("qos_ops", "delete_qos_rule", "wal_append"),
        "add_mirror": ("mirror_ops", "add_mirror", "wal_append"),
        "delete_mirror": ("mirror_ops", "delete_mirror", "wal_append"),
    }
    for name, spec in wrapper_specs.items():
        helper = spec["standalone"]
        helper_body = _rust_function_body_from_blanked(control_code, helper)
        if helper_body is None:
            errors.append("standalone helper %s is missing" % helper)
        else:
            if "execute_managed_local_projection_transaction" in helper_body:
                errors.append(
                    "standalone helper %s must not use the managed executor" % helper
                )
            if not all(marker in helper_body for marker in standalone_markers[name]):
                errors.append(
                    "standalone helper %s must retain legacy kernel and WAL writes"
                    % helper
                )

    def standalone_prior_rollback_is_safe(
        helper_body, kernel_deletes, wal_delete, require_mirror_branches=False
    ):
        loop = re.search(
            r"\bfor\s+\w+\s+in\s+applied\s*\.\s*iter\s*\(\s*\)"
            r"\s*\.\s*rev\s*\(\s*\)\s*\{",
            helper_body or "",
        )
        if loop is None:
            return False
        loop_body = _rust_braced_body_at(
            helper_body, helper_body.find("{", loop.start())
        )
        failure = re.search(
            r"\bif\s+let\s+Err\s*\(\s*(?P<error>\w+)\s*\)\s*="
            r"\s*[^;{]+\{",
            loop_body or "",
        )
        if failure is None:
            return False
        failure_body = _rust_braced_body_at(
            loop_body, loop_body.find("{", failure.start())
        )
        failure_opening = loop_body.find("{", failure.start())
        failure_end = (
            failure_opening + len(failure_body) + 2
            if failure_body is not None
            else -1
        )
        kernel_positions = [loop_body.find(marker) for marker in kernel_deletes]
        retain = loop_body.find("retain")
        wal = loop_body.find(wal_delete)
        mirror_branch_ordered = True
        if require_mirror_branches:
            global_branch = loop_body.find("previous.is_global")
            else_branch = loop_body.find("else", global_branch)
            mirror_branch_ordered = (
                0 <= global_branch
                < kernel_positions[0]
                < else_branch
                < kernel_positions[1]
                < failure_opening
            )
        return (
            failure_body is not None
            and all(0 <= position < failure_opening for position in kernel_positions)
            and mirror_branch_ordered
            and 0 <= failure_end < retain < wal
            and re.search(r"\berrors\s*\.\s*push\s*\(", failure_body)
            and failure.group("error") in failure_body
            and re.search(r"\bcontinue\s*;", failure_body)
            and not re.search(r"\breturn\s+Err\s*\(", failure_body)
            and "errors.join" in helper_body
        )

    for helper, kernel_deletes, wal_delete, label, mirror_branches in (
        (
            "add_qos_standalone_locked",
            ("delete_qos_rule",),
            "WalEntry::DeleteQos",
            "add_qos",
            False,
        ),
        (
            "add_mirror_standalone_locked",
            ("delete_global_mirror", "delete_mirror_rule"),
            "WalEntry::DeleteMirror",
            "add_mirror",
            True,
        ),
    ):
        if not standalone_prior_rollback_is_safe(
            _rust_function_body_from_blanked(control_code, helper),
            kernel_deletes,
            wal_delete,
            mirror_branches,
        ):
            errors.append(
                "standalone %s prior-direction rollback must retain RAM/WAL on "
                "kernel delete failure and aggregate the error" % label
            )

    def is_direct_function_body_statement(body, position):
        depth = 0
        for character in body[:position]:
            if character == "{":
                depth += 1
            elif character == "}":
                depth -= 1
        return depth == 0

    add_qos_body = bodies.get("add_qos") or ""
    add_qos_executor = add_qos_body.find("execute_managed_local_projection_transaction")
    add_qos_publish = add_qos_body.find("state.state = final_state")
    add_qos_fq_cleanups = list(
        re.finditer(r"\bcleanup_owned_fq_qdisc_if_unused\s*\(", add_qos_body)
    )
    add_qos_fq_cleanup = (
        add_qos_fq_cleanups[0].start() if len(add_qos_fq_cleanups) == 1 else -1
    )
    add_qos_fq_args = (
        _rust_parenthesized_body_at(
            add_qos_body, add_qos_body.find("(", add_qos_fq_cleanup)
        )
        if add_qos_fq_cleanup >= 0
        else None
    )
    if (
        not 0 <= add_qos_executor < add_qos_publish < add_qos_fq_cleanup
        or not is_direct_function_body_statement(add_qos_body, add_qos_fq_cleanup)
        or [
            re.sub(r"\s+", "", item)
            for item in _rust_split_top_level_arguments(add_qos_fq_args or "")
        ]
        != ["instance", "&state"]
    ):
        errors.append(
            "managed add_qos must clean an owned FQ qdisc after successful "
            "shaping-to-policing replacement"
        )

    executor_body = _rust_function_body_from_blanked(
        control_code, "execute_managed_local_projection_transaction"
    )
    compensation_name = "execute_managed_local_projection_compensations"
    if executor_body is None:
        errors.append("shared managed local projection executor is missing")
    else:
        health_transitions = list(
            re.finditer(
                r"\bset_health\s*\(\s*ManagedProjectionHealth\s*::\s*"
                r"(Unverified|Verified)\s*\)\s*;",
                executor_body,
            )
        )
        unverified_health = [
            transition
            for transition in health_transitions
            if transition.group(1) == "Unverified"
        ]
        verified_health = [
            transition
            for transition in health_transitions
            if transition.group(1) == "Verified"
        ]
        apply = re.search(r"\bapply\s*\(", executor_body)
        persist = re.search(r"\bpersist\s*\(\s*\)", executor_body)
        receipt_journal = re.search(
            r"\bOk\s*\(\s*(\w+)\s*\)\s*=>\s*(?:\{\s*)?"
            r"applied\s*\.\s*push\s*"
            r"\(\s*\1\s*\)",
            executor_body,
        )
        apply_failure = re.search(
            r"\bErr\s*\(\s*\w+\s*\)\s*=>\s*\{",
            executor_body,
        )
        apply_failure_body = None
        if apply_failure is not None:
            apply_failure_body = _rust_braced_body_at(
                executor_body, executor_body.find("{", apply_failure.start())
            )
        apply_failure_returns = list(
            re.finditer(
                r"\breturn\s+Err\s*\(\s*transaction_failure\s*\(",
                apply_failure_body or "",
            )
        )
        apply_failure_compensation = re.search(
            r"\b%s\s*\(" % compensation_name,
            apply_failure_body or "",
        )
        apply_failure_return_is_complete = False
        if len(apply_failure_returns) == 1:
            failure_return = apply_failure_returns[0]
            transaction_failure_open = (apply_failure_body or "").find(
                "(", failure_return.end() - 1
            )
            transaction_failure_arguments = _rust_parenthesized_body_at(
                apply_failure_body or "", transaction_failure_open
            )
            if transaction_failure_arguments is not None:
                transaction_failure_close = (
                    transaction_failure_open + len(transaction_failure_arguments) + 1
                )
                apply_failure_return_is_complete = bool(
                    re.match(
                        r"\s*\)\s*;",
                        (apply_failure_body or "")[transaction_failure_close + 1:],
                    )
                )
        apply_failure_terminates = (
            len(apply_failure_returns) == 1
            and apply_failure_return_is_complete
            and _rust_brace_depth_at(
                apply_failure_body or "", apply_failure_returns[0].start()
            )
            == 0
            and apply_failure_compensation is not None
            and apply_failure_compensation.start() < apply_failure_returns[0].start()
        )
        compensations = list(
            re.finditer(r"\b%s\s*\(" % compensation_name, executor_body)
        )
        persist_failure = re.search(
            r"\bif\s+let\s+Err\s*\(\s*\w+\s*\)\s*=\s*"
            r"persist\s*\(\s*\)\s*\.\s*await\s*\{",
            executor_body,
        )
        persist_failure_body = None
        if persist_failure is not None:
            persist_failure_body = _rust_braced_body_at(
                executor_body, executor_body.find("{", persist_failure.start())
            )
        persist_failure_open = (
            executor_body.find("{", persist_failure.start())
            if persist_failure is not None
            else -1
        )
        persist_failure_close = _rust_matching_brace_end(
            executor_body, persist_failure_open
        )
        durable_restores = list(
            re.finditer(r"\brestore_durable\s*\(\s*\)", executor_body)
        )
        durable_restore = re.search(
            r"\blet\s+(\w+)\s*=\s*restore_durable\s*\(\s*\)"
            r"\s*\.\s*await[^;]*;",
            persist_failure_body or "",
        )
        persist_failure_returns = list(
            re.finditer(
                r"\breturn\s+Err\s*\(\s*transaction_failure\s*\(",
                persist_failure_body or "",
            )
        )
        persist_failure_compensation = re.search(
            r"\b%s\s*\(" % compensation_name,
            persist_failure_body or "",
        )
        persist_failure_return_is_complete = False
        if len(persist_failure_returns) == 1:
            failure_return = persist_failure_returns[0]
            transaction_failure_open = (persist_failure_body or "").find(
                "(", failure_return.end() - 1
            )
            transaction_failure_arguments = _rust_parenthesized_body_at(
                persist_failure_body or "", transaction_failure_open
            )
            if transaction_failure_arguments is not None:
                transaction_failure_close = (
                    transaction_failure_open + len(transaction_failure_arguments) + 1
                )
                persist_failure_return_is_complete = bool(
                    re.match(
                        r"\s*\)\s*;",
                        (persist_failure_body or "")[transaction_failure_close + 1:],
                    )
                )
        persist_failure_terminates = (
            len(persist_failure_returns) == 1
            and persist_failure_return_is_complete
            and _rust_brace_depth_at(
                persist_failure_body or "", persist_failure_returns[0].start()
            )
            == 0
            and persist_failure_compensation is not None
            and durable_restore is not None
            and persist_failure_compensation.start()
            < durable_restore.start()
            < persist_failure_returns[0].start()
        )
        if (
            len(unverified_health) != 1
            or len(verified_health) != 1
            or apply is None
            or persist is None
            or persist_failure_close is None
            or not unverified_health[0].start() < apply.start() < persist.start()
            or not persist_failure_close < verified_health[0].start()
            or _rust_brace_depth_at(executor_body, unverified_health[0].start()) != 0
            or _rust_brace_depth_at(executor_body, verified_health[0].start()) != 0
        ):
            errors.append(
                "shared executor must set health exactly once to Unverified before apply "
                "and exactly once to Verified after successful persistence"
            )
        if (
            not unverified_health
            or apply is None
            or persist is None
            or not unverified_health[0].start() < apply.start() < persist.start()
            or not re.search(r"\bfor\s+\w+\s+in\s+operations\b", executor_body)
        ):
            errors.append(
                "shared executor must journal and apply the kernel plan before persistence"
            )
        if receipt_journal is None:
            errors.append(
                "shared executor must journal apply receipts rather than requested operations"
            )
        if (
            len(compensations) != 2
            or apply is None
            or persist is None
            or not apply.start() < compensations[0].start() < persist.start()
        ):
            errors.append(
                "kernel partial failure must compensate every applied operation"
            )
        if not apply_failure_terminates:
            errors.append(
                "kernel apply failure must return its transaction failure before persistence"
            )
        if (
            len(compensations) != 2
            or persist is None
            or persist_failure_body is None
            or durable_restore is None
            or compensation_name not in persist_failure_body
        ):
            errors.append(
                "persistence failure must restore durable old state after compensation"
            )
        compensation_arguments = []
        for compensation in compensations:
            arguments = _rust_parenthesized_body_at(
                executor_body, executor_body.find("(", compensation.start())
            )
            compensation_arguments.append(
                _rust_split_top_level_arguments(arguments or "")
            )
        if len(compensation_arguments) != 2 or any(
            not arguments
            or re.sub(r"\s+", "", arguments[0]) != "&applied"
            for arguments in compensation_arguments
        ):
            errors.append(
                "both rollback paths must compensate the applied receipt journal"
            )
        if (
            len(durable_restores) != 1
            or durable_restore is None
            or not re.search(
                r"\btransaction_failure\s*\([^;]*\b%s\b"
                % re.escape(durable_restore.group(1) if durable_restore else ""),
                (persist_failure_body or "")[durable_restore.start() if durable_restore else 0:],
            )
        ):
            errors.append("durable restore failure must remain visible to the caller")
        if not persist_failure_terminates:
            errors.append(
                "persistence failure must return its transaction failure before Verified restoration"
            )
        if direct_managed_write.search(executor_body):
            errors.append("shared executor must not mutate the active ACL bank directly")

    for kind in ("apply", "compensate"):
        helpers = delegated_helpers[kind]
        if len(helpers) != 1:
            errors.append("managed wrappers must share one %s receipt helper" % kind)
            continue
        helper = next(iter(helpers))
        helper_body = _rust_function_body_from_blanked(control_code, helper)
        if helper_body is None:
            errors.append("managed %s receipt helper %s is missing" % (kind, helper))
            continue
        if active_acl_access.search(helper_body):
            errors.append(
                "managed %s receipt helper must not mutate the active ACL bank" % kind
            )
        if kind == "apply" and not all(
            marker in helper_body
            for marker in (
                "ManagedLocalProjectionOperation::General",
                "ManagedLocalProjectionOperation::Domain",
                "ManagedLocalProjectionReceipt::General",
                "ManagedLocalProjectionReceipt::Domain",
                "apply_managed_local_domain_operation",
            )
        ):
            errors.append(
                "managed apply helper must return general or domain receipts"
            )
        if kind == "compensate" and not all(
            marker in helper_body
            for marker in (
                "ManagedLocalProjectionReceipt::General",
                "ManagedLocalProjectionReceipt::Domain",
                "compensate_managed_local_domain_receipt",
            )
        ):
            errors.append(
                "managed compensation helper must consume general or domain receipts"
            )

    for kind, state_name in (("persist", "final_state"), ("restore", "old_state")):
        factories = snapshot_factories[kind]
        if len(factories) != 1:
            errors.append("managed wrappers must share one %s snapshot factory" % kind)
            continue
        factory = next(iter(factories))
        factory_body = _rust_function_body_from_blanked(control_code, factory)
        if (
            factory_body is None
            or state_name not in factory_body
            or "serde_json" not in factory_body
            or not re.search(r"\bwal\s*\.\s*clone\s*\(", factory_body)
            or not re.search(r"\bwal\s*\.\s*compact\s*\(", factory_body)
        ):
            errors.append(
                "managed %s snapshot factory must serialize %s and compact a cloned WAL"
                % (kind, state_name)
            )

    fq_receipt_helper = "managed_local_fq_qdisc_apply_receipt"
    fq_receipt_body = _rust_function_body_from_blanked(
        control_code, fq_receipt_helper
    )
    fq_cleanup_derivation = re.search(
        r"\blet\s+(?P<derived>\w+)\s*=\s*(?P<requested>\w+)\s*&&\s*"
        r"matches!\s*\(\s*(?P<state>\w+)\s*,\s*"
        r"FqQdiscState\s*::\s*InstalledNow\s*\)\s*;",
        fq_receipt_body or "",
    )
    fq_receipt_fields = None
    if fq_receipt_body is not None:
        fq_receipt_marker = fq_receipt_body.find(
            "ManagedLocalDomainReceipt::FqQdisc"
        )
        fq_receipt_opening = fq_receipt_body.find("{", fq_receipt_marker)
        if fq_receipt_marker >= 0 and fq_receipt_opening >= 0:
            fq_receipt_fields = _rust_braced_body_at(
                fq_receipt_body, fq_receipt_opening
            )
    if fq_cleanup_derivation is None or fq_receipt_fields is None:
        errors.append(
            "managed FQ receipt cleanup must derive from the actual ensure result"
        )
    else:
        state_name = fq_cleanup_derivation.group("state")
        derived_name = fq_cleanup_derivation.group("derived")
        state_field = re.search(
            r"\bstate\s*(?::\s*(\w+))?\s*,", fq_receipt_fields
        )
        cleanup_field = re.search(
            r"\bcleanup_on_rollback\s*(?::\s*(\w+))?\s*,",
            fq_receipt_fields,
        )
        if (
            state_field is None
            or (state_field.group(1) or "state") != state_name
            or cleanup_field is None
            or (cleanup_field.group(1) or "cleanup_on_rollback") != derived_name
        ):
            errors.append(
                "managed FQ receipt cleanup must derive from the actual ensure result"
            )

    domain_apply_body = _rust_function_body_from_blanked(
        control_code, "apply_managed_local_domain_operation"
    )
    if domain_apply_body is None or not all(
        marker in domain_apply_body
        for marker in (
            "ManagedLocalDomainOperation",
            "ManagedLocalDomainReceipt",
            "EnsureFqQdisc",
            "cleanup_on_rollback",
            "FqQdiscState::InstalledNow",
            "build_managed_local_domain_receipt",
            "apply_managed_local_projection_operation_transactionally",
            fq_receipt_helper,
            "mark_owned_fq_qdisc",
            "rollback_installed_fq_qdisc",
        )
    ):
        errors.append(
            "managed domain apply must return QoS and qdisc ownership receipts"
        )
    elif active_acl_access.search(domain_apply_body):
        errors.append("managed domain apply must not mutate the active ACL bank")

    ensure_state = re.search(
        r"\blet\s+(?P<state>\w+)\s*=\s*ensure_fq_qdisc\s*"
        r"\([^;]*\)\s*\?\s*;",
        domain_apply_body or "",
    )
    fq_receipt_call = re.search(
        r"\b%s\s*\(" % re.escape(fq_receipt_helper),
        domain_apply_body or "",
    )
    fq_receipt_arguments = None
    if fq_receipt_call is not None:
        fq_receipt_arguments = _rust_parenthesized_body_at(
            domain_apply_body,
            domain_apply_body.find("(", fq_receipt_call.start()),
        )
    fq_receipt_items = _rust_split_top_level_arguments(
        fq_receipt_arguments or ""
    )
    if (
        ensure_state is None
        or len(fq_receipt_items) != 2
        or re.sub(r"\s+", "", fq_receipt_items[0])
        != ensure_state.group("state")
        or re.sub(r"\s+", "", fq_receipt_items[1])
        not in ("cleanup_on_rollback", "*cleanup_on_rollback")
    ):
        errors.append(
            "managed FQ receipt cleanup must derive from the actual ensure result"
        )

    marker_failure = re.search(
        r"\bif\s+let\s+Err\s*\(\s*(?P<error>\w+)\s*\)\s*=\s*"
        r"mark_owned_fq_qdisc\s*\([^;{]*\)\s*\{",
        domain_apply_body or "",
    )
    marker_failure_body = None
    if marker_failure is not None:
        marker_failure_body = _rust_braced_body_at(
            domain_apply_body,
            domain_apply_body.find("{", marker_failure.start()),
        )
    marker_rollback = re.search(
        r"\brollback_installed_fq_qdisc\s*\(", marker_failure_body or ""
    )
    marker_return = re.search(
        r"\breturn\s+Err\s*\(\s*%s\s*\)"
        % re.escape(marker_failure.group("error") if marker_failure else ""),
        marker_failure_body or "",
    )
    if (
        marker_failure_body is None
        or marker_rollback is None
        or marker_return is None
        or marker_rollback.start() > marker_return.start()
    ):
        errors.append(
            "managed FQ marker failure must roll back the installed qdisc before returning"
        )

    transactional_apply_body = _rust_function_body_from_blanked(
        control_code, "apply_managed_local_projection_operation_transactionally"
    )
    if transactional_apply_body is None:
        errors.append("managed domain current-operation rollback helper is missing")
    else:
        raw_apply_match = re.search(r"\braw_apply\s*\(", transactional_apply_body)
        apply_error_match = re.search(
            r"\bErr\s*\(\s*(?P<error>\w+)\s*\)\s*=>",
            transactional_apply_body,
        )
        compensation_binding = re.search(
            r"\blet\s+(?P<error>\w+)\s*=\s*compensate\s*"
            r"\(\s*&?\s*receipt\s*\)\s*"
            r"(?:\.\s*await\s*)?\.\s*err\s*\(\s*\)\s*;",
            transactional_apply_body,
        )
        failure_match = re.search(
            r"\bdomain_apply_failure\s*\(", transactional_apply_body
        )
        raw_apply = raw_apply_match.start() if raw_apply_match else -1
        apply_error = apply_error_match.start() if apply_error_match else -1
        compensate = compensation_binding.start() if compensation_binding else -1
        failure = failure_match.start() if failure_match else -1
        failure_arguments = None
        if failure_match is not None:
            failure_arguments = _rust_parenthesized_body_at(
                transactional_apply_body,
                transactional_apply_body.find("(", failure_match.start()),
            )
        normalized_failure_arguments = re.sub(
            r"\s+", "", failure_arguments or ""
        )
        apply_error_name = (
            apply_error_match.group("error") if apply_error_match else ""
        )
        compensation_error_name = (
            compensation_binding.group("error") if compensation_binding else ""
        )
        if (
            min(raw_apply, apply_error, compensate, failure) < 0
            or not raw_apply < apply_error < compensate < failure
            or "receipt" not in transactional_apply_body
            or transactional_apply_body.count("compensate(") != 1
            or apply_error_name not in normalized_failure_arguments
            or compensation_error_name not in normalized_failure_arguments
        ):
            errors.append(
                "managed domain apply failure must compensate its current receipt"
            )
        if active_acl_access.search(transactional_apply_body):
            errors.append(
                "managed domain transactional apply must not mutate the active ACL bank"
            )

    domain_raw_body = _rust_function_body_from_blanked(
        control_code, "apply_managed_local_domain_raw"
    )
    domain_receipt_body = _rust_function_body_from_blanked(
        control_code, "build_managed_local_domain_receipt"
    )
    if domain_raw_body is None or domain_receipt_body is None:
        errors.append("managed domain apply must separate preimage receipt from raw writes")
    elif active_acl_access.search(domain_raw_body) or active_acl_access.search(
        domain_receipt_body
    ):
        errors.append("managed domain delegated helpers must not mutate the active ACL bank")
    else:
        def operation_arm(marker, following_markers):
            start = domain_receipt_body.find(marker)
            if start < 0:
                return ""
            ends = [
                domain_receipt_body.find(next_marker, start + len(marker))
                for next_marker in following_markers
            ]
            ends = [end for end in ends if end >= 0]
            return domain_receipt_body[start:min(ends) if ends else None]

        def replacement_receipt_preserves_preimage(
            arm, receipt_marker, require_target_ifindex=False
        ):
            receipt = arm.find(receipt_marker)
            opening = arm.find("{", receipt)
            fields = (
                _rust_braced_body_at(arm, opening)
                if receipt >= 0 and opening >= 0
                else None
            )
            if fields is None:
                return False
            applied = re.search(r"\bapplied\s*:\s*([^,}\n]+)", fields)
            previous = re.search(r"\bprevious\s*:\s*([^,}\n]+)", fields)
            if applied is None or "rule" not in applied.group(1) or previous is None:
                return False
            previous_expression = re.sub(r"\s+", "", previous.group(1))
            if previous_expression.startswith("None") or previous_expression in (
                "Option::None",
                "Default::default()",
            ):
                return False
            return not require_target_ifindex or "target_ifindex" in arm

        qos_arm = operation_arm(
            "ManagedLocalDomainOperation::QosUpsert",
            (
                "ManagedLocalDomainOperation::QosDelete",
                "ManagedLocalDomainOperation::MirrorUpsert",
            ),
        )
        mirror_arm = operation_arm(
            "ManagedLocalDomainOperation::MirrorUpsert",
            ("ManagedLocalDomainOperation::MirrorDelete",),
        )
        if (
            not replacement_receipt_preserves_preimage(
                qos_arm, "ManagedLocalDomainReceipt::QosUpsert"
            )
            or not replacement_receipt_preserves_preimage(
                mirror_arm,
                "ManagedLocalDomainReceipt::MirrorUpsert",
                require_target_ifindex=True,
            )
            or "ManagedLocalDomainOperation::QosDelete" not in domain_receipt_body
            or "ManagedLocalDomainReceipt::QosDelete" not in domain_receipt_body
            or "ManagedLocalDomainOperation::MirrorDelete" not in domain_receipt_body
            or "ManagedLocalDomainReceipt::MirrorDelete" not in domain_receipt_body
        ):
            errors.append(
                "managed domain receipts must preserve QoS and Mirror preimages"
            )

    domain_compensation_body = _rust_function_body_from_blanked(
        control_code, "managed_local_domain_compensation_operations"
    )
    if domain_compensation_body is None or not all(
        marker in domain_compensation_body
        for marker in (
            "ManagedLocalDomainReceipt",
            "FqQdisc",
            "cleanup_on_rollback",
            "FqQdiscState::InstalledNow",
            "FqQdiscState::AlreadyPresent",
            "CleanupOwnedFqQdisc",
            "QosUpsert",
            "QosDelete",
            "MirrorUpsert",
            "MirrorDelete",
            "previous",
            "src_group_id",
            "dst_group_id",
            "target_ifindex",
        )
    ):
        errors.append(
            "managed domain compensation must derive qdisc cleanup from its receipt"
        )
    elif active_acl_access.search(domain_compensation_body):
        errors.append("managed domain compensation must not mutate the active ACL bank")

    compensation_body = _rust_function_body_from_blanked(
        control_code, compensation_name
    )
    compensation_collects_errors = re.search(
        r"\bErr\s*\(\s*(\w+)\s*\)[\s\S]*?"
        r"\b\w+\s*\.\s*push\s*\(\s*\1\s*\)",
        compensation_body or "",
    )
    if (
        compensation_body is None
        or not re.search(r"\.\s*iter\s*\(\s*\)\s*\.\s*rev\s*\(\s*\)", compensation_body)
        or compensation_collects_errors is None
        or re.search(r"\breturn\s+Err\s*\(", compensation_body or "")
        or re.search(
            r"\bcompensate\s*\([^;]*\)\s*(?:\.\s*await\s*)?\?",
            compensation_body or "",
        )
    ):
        errors.append(
            "compensation must run in reverse and attempt every applied operation"
        )
    retained_body = _rust_function_body_from_blanked(
        control_code, "reconcile_retained_owned_groups"
    )
    if retained_body is None or not all(
        marker in retained_body
        for marker in (
            "groups",
            "rules",
            "qos_rules",
            "mirror_rules",
            "src_group_id",
            "dst_group_id",
        )
    ):
        errors.append(
            "retained owned groups must follow ACL, QoS, and both Mirror references"
        )
    removed_ids = re.search(
        r"\blet\s+mut\s+(?P<ids>\w+)\s*=\s*Vec\s*::\s*new\s*\(\s*\)\s*;",
        retained_body or "",
    )
    removal_branch = re.search(
        r"\bif\b[^;{]*final_state\s*\.\s*groups\s*\.\s*remove\s*"
        r"\(\s*&\s*old_group\s*\.\s*name\s*\)\s*\.\s*is_some\s*"
        r"\(\s*\)\s*\{",
        retained_body or "",
    )
    removal_body = (
        _rust_braced_body_at(
            retained_body, retained_body.find("{", removal_branch.start())
        )
        if removal_branch is not None
        else None
    )
    removed_push_pattern = (
        r"\b%s\s*\.\s*push\s*\(\s*old_group\s*\.\s*id\s*\)"
        % re.escape(removed_ids.group("ids") if removed_ids else "")
    )
    if (
        removed_ids is None
        or removal_body is None
        or not re.search(removed_push_pattern, removal_body)
        or len(re.findall(removed_push_pattern, retained_body or "")) != 1
        or not re.search(
            r"\bOk\s*\(\s*%s\s*\)"
            % re.escape(removed_ids.group("ids") if removed_ids else ""),
            retained_body or "",
        )
    ):
        errors.append(
            "retained owned-group reconciliation must report removed group IDs"
        )

    removed_stats_helper = "clear_removed_retained_owned_group_stats"
    removed_stats_body = _rust_function_body_from_blanked(
        control_code, removed_stats_helper
    )
    removed_stats_calls = list(
        re.finditer(r"\bclear_group_stats_for_id\s*\(", removed_stats_body or "")
    )
    removed_stats_loop = re.search(
        r"\bfor\s+group_id\s+in\s+removed_group_ids\s*\{",
        removed_stats_body or "",
    )
    removed_stats_loop_body = (
        _rust_braced_body_at(
            removed_stats_body,
            removed_stats_body.find("{", removed_stats_loop.start()),
        )
        if removed_stats_loop is not None
        else None
    )
    removed_stats_error = re.search(
        r"\bif\s+let\s+Err\s*\(\s*\w+\s*\)\s*="
        r"\s*[^;{]*clear_group_stats_for_id\s*\([^;{]*\)\s*\{",
        removed_stats_loop_body or "",
    )
    removed_stats_error_body = (
        _rust_braced_body_at(
            removed_stats_loop_body,
            removed_stats_loop_body.find("{", removed_stats_error.start()),
        )
        if removed_stats_error is not None
        else None
    )
    removed_stats_args = (
        _rust_parenthesized_body_at(
            removed_stats_body,
            removed_stats_body.find("(", removed_stats_calls[0].start()),
        )
        if len(removed_stats_calls) == 1
        else None
    )
    if (
        removed_stats_body is None
        or "removed_group_ids" not in removed_stats_body
        or len(removed_stats_calls) != 1
        or removed_stats_loop_body is None
        or removed_stats_error_body is None
        or len(
            re.findall(
                r"\bclear_group_stats_for_id\s*\(", removed_stats_loop_body
            )
        )
        != 1
        or [
            re.sub(r"\s+", "", item)
            for item in _rust_split_top_level_arguments(removed_stats_args or "")
        ]
        != ["runtime", "*group_id"]
        or "warn!" not in removed_stats_body
        or re.search(r"clear_group_stats_for_id\s*\([^;]+\)\s*\?", removed_stats_body)
        or re.search(r"\breturn\s+Err\s*\(", removed_stats_body)
        or re.search(r"\b(?:break|return)\b|\?", removed_stats_loop_body)
        or re.search(r"\b(?:break|return)\b|\?", removed_stats_error_body)
    ):
        errors.append("removed retained-owned GROUP_STATS cleanup must be best-effort")

    for name in ("delete_qos", "delete_mirror"):
        body = bodies.get(name) or ""
        receipt = re.search(
            r"\blet\s+(?P<ids>\w+)\s*=\s*"
            r"reconcile_retained_owned_groups\s*\(",
            body,
        )
        publish = body.find("state.state = final_state")
        cleanup_calls = list(
            re.finditer(r"\b%s\s*\(" % removed_stats_helper, body)
        )
        cleanup = cleanup_calls[0].start() if len(cleanup_calls) == 1 else -1
        cleanup_args = (
            _rust_parenthesized_body_at(body, body.find("(", cleanup))
            if cleanup >= 0
            else None
        )
        normalized_cleanup_args = [
            re.sub(r"\s+", "", item)
            for item in _rust_split_top_level_arguments(cleanup_args or "")
        ]
        if (
            receipt is None
            or not 0 <= publish < cleanup
            or not is_direct_function_body_statement(body, cleanup)
            or normalized_cleanup_args
            != ["&" + receipt.group("ids"), "state.map_runtime()"]
        ):
            errors.append(
                "managed %s must best-effort clear GROUP_STATS for retained-owned "
                "groups removed after commit" % name
            )
    replace_body = _rust_function_body_from_blanked(control_code, "replace_owned_acl")
    if replace_body is None:
        errors.append("owned ACL replace function is missing")
    else:
        removal = replace_body.find("final_state.groups.remove")
        retention = replace_body.find("reconcile_retained_owned_groups")
        plan = plan_pattern.search(replace_body)
        if (
            removal < 0
            or retention < 0
            or plan is None
            or not removal < retention < plan.start()
        ):
            errors.append(
                "owned ACL replace must reconcile retention after removals and before projection"
            )

    status_body = _rust_function_body_from_blanked(control_code, "status_code")
    if status_body is None or not re.search(
        r"(?:GroupInUse[\s\S]*LocalWriteBlocked|LocalWriteBlocked[\s\S]*GroupInUse)"
        r"[\s\S]*=>\s*409\b",
        status_body,
    ):
        errors.append("managed local-write conflicts must retain HTTP 409 mapping")
    if status_body is None or not re.search(
        r"InstanceNotReady[\s\S]*=>\s*503\b", status_body
    ):
        errors.append("managed projection not-ready must retain HTTP 503 mapping")

    handler_specs = (
        ("groups", "add_group", None),
        ("groups", "delete_group", None),
        ("qos", "add_qos", "delete_qos"),
        ("qos", "delete_qos", None),
        ("mirror", "add_mirror", "delete_mirror"),
        ("mirror", "delete_mirror", None),
    )
    for kind, name, rollback in handler_specs:
        code = handler_codes[kind]
        body = _rust_function_body_from_blanked(code, name)
        if body is None:
            errors.append("managed mutation handler %s is missing" % name)
            continue
        calls = list(re.finditer(r"\bcp\s*\.\s*%s\s*\(" % name, body))
        error_branch_valid = False
        arguments = None
        if len(calls) == 1:
            call = calls[0]
            opening = body.find("(", call.start())
            arguments = _rust_parenthesized_body_at(body, opening)
            closing = opening + len(arguments) + 1 if arguments is not None else -1
            binding = re.search(
                r"\bif\s+let\s+Err\s*\(\s*(\w+)\s*\)\s*=\s*$",
                body[max(0, call.start() - 160):call.start()],
            )
            await_and_block = (
                re.match(r"\s*\.\s*await\s*\{", body[closing + 1:])
                if closing >= 0
                else None
            )
            if binding is not None and await_and_block is not None:
                block_opening = body.find("{", closing + 1)
                error_body = _rust_braced_body_at(body, block_opening) or ""
                error_branch_valid = bool(
                    re.search(
                        r"\breturn\s+Err\s*\(\s*err_response\s*\(\s*%s\s*\)\s*\)"
                        % re.escape(binding.group(1)),
                        error_body,
                    )
                )
            if not error_branch_valid and await_and_block is not None:
                match_binding = re.search(
                    r"\bmatch\s*$",
                    body[max(0, call.start() - 80):call.start()],
                )
                if match_binding is not None:
                    block_opening = body.find("{", closing + 1)
                    match_body = _rust_braced_body_at(body, block_opening) or ""
                    match_error = re.search(
                        r"\bErr\s*\(\s*(\w+)\s*\)\s*=>"
                        r"[\s\S]{0,240}?\berr_response\s*\(\s*\1\s*\)",
                        match_body,
                    )
                    error_branch_valid = match_error is not None
        if len(calls) != 1 or not error_branch_valid:
            errors.append(
                "managed mutation handler %s must return its exact ControlPlane error"
                % name
            )
        attribute = _rust_utoipa_attribute_prefix_from_blanked(code, name)
        for status in (409, 503):
            if attribute is None or not re.search(
                r"\bstatus\s*=\s*%d\b" % status, attribute
            ):
                errors.append(
                    "managed mutation handler %s must document HTTP %d" % (name, status)
                )
        if calls and _rust_position_is_inside_loop(body, calls[0].start()):
            errors.append(
                "managed %s handler must not loop around its ControlPlane call" % name
            )
        if kind in ("qos", "mirror") and calls:
            if (
                arguments is None
                or not re.search(r"\bdirection\b", arguments)
                or re.search(r"\*\s*dir\b", arguments)
                or (rollback and re.search(r"\bcp\s*\.\s*%s\s*\(" % rollback, body))
            ):
                errors.append(
                    "managed %s handler must submit one raw-direction ControlPlane transaction"
                    % name
                )
    return errors


def _run_managed_cross_domain_group_mutation_self_tests():
    def wrapper(name, standalone, parameters, order, planning, post_success=""):
        return r"""
        pub async fn %s(&self, instance: &str%s) {
            let _lifecycle_guard = self.lock_runtime_lifecycle().await;
            let instance = self.get_instance(instance).await?;
            let mut state = instance.write().await;
            match state.managed_acl_publication_mode {
                ManagedAclPublicationMode::StandaloneCompatibility
                | ManagedAclPublicationMode::NeutronAttachOwnedStandaloneAcl => {
                    return self.%s(&mut state).await;
                }
                ManagedAclPublicationMode::ManagedAcl => {}
            }
            managed_local_projection_admission(
                state.managed_acl_publication_mode,
                state.managed_projection_health,
            )?;
            let old_state = state.state.clone();
%s
            let general_mutations =
                managed_general_state_mutations(&old_state, &final_state)?;
            let projection_order = ManagedLocalProjectionOrder::%s;
            let operations = merge_managed_local_projection_operations(
                projection_order,
                general_mutations,
                domain_operations,
            );
            let apply_projection_operation =
                managed_local_projection_apply(runtime, ebpf_path);
            let compensate_projection_receipt =
                managed_local_projection_compensate(runtime, ebpf_path);
            let persist_final_state =
                managed_local_projection_persist(&state.wal, &final_state);
            let restore_old_state =
                managed_local_projection_restore(&state.wal, &old_state);
            let mut set_projection_health = |health| {
                state.managed_projection_health = health;
            };
            execute_managed_local_projection_transaction(
                &operations,
                set_projection_health,
                apply_projection_operation,
                persist_final_state,
                compensate_projection_receipt,
                restore_old_state,
            ).await?;
            state.state = final_state;
%s
            Ok(())
        }
        """ % (name, parameters, standalone, planning, order, post_success)

    shared = r"""
        fn managed_local_projection_admission(
            mode: ManagedAclPublicationMode,
            health: ManagedProjectionHealth,
        ) -> Result<(), ControlPlaneError> {
            if mode == ManagedAclPublicationMode::ManagedAcl {
                match health {
                    ManagedProjectionHealth::Verified => {}
                    ManagedProjectionHealth::Unverified
                    | ManagedProjectionHealth::RepairRequired => {
                        return Err(ControlPlaneError::InstanceNotReady("projection".into()));
                    }
                }
            }
            Ok(())
        }

        fn managed_general_state_mutations(old_state: &State, final_state: &State) {
            let committed_projection = compile_managed_group_projection(old_state)?;
            let proposed_projection = compile_managed_group_projection(final_state)?;
            managed_general_projection_mutations(
                &committed_projection,
                &proposed_projection,
            )
        }

        fn validate_managed_group_mutation(state: &State, group_id: u32) {
            if state.rules.iter().any(|rule| {
                rule.src_group_id == group_id || rule.dst_group_id == group_id
            }) {
                return Err(ControlPlaneError::GroupInUse("ACL reference".into()));
            }
            Ok(())
        }

        fn requested_directions(direction: u8) {
            match direction {
                0 => Ok(vec![0]),
                1 => Ok(vec![1]),
                2 => Ok(vec![0, 1]),
                _ => Err(ControlPlaneError::InvalidDirection(direction)),
            }
        }

        fn managed_qos_direction_plans(direction: u8, mode: u8) {
            requested_directions(direction)?
                .into_iter()
                .map(|direction| {
                    let effective_mode = if direction == 0 && mode == 1 { 0 } else { mode };
                    ManagedQosDirectionPlan { direction, effective_mode }
                })
                .collect()
        }

        fn plan_managed_local_qos_upserts(
            old_state: &State,
            direction_plans: &[ManagedQosDirectionPlan],
        ) {
            let mut operations = Vec::new();
            if direction_plans.iter().any(|plan| plan.effective_mode == 1) {
                operations.push(ManagedLocalDomainOperation::EnsureFqQdisc {
                    cleanup_on_rollback: !old_state.qos_rules.iter().any(|rule| rule.mode == 1),
                });
            }
            for plan in direction_plans {
                operations.push(ManagedLocalDomainOperation::QosUpsert(
                    materialize_qos_rule(old_state, plan),
                ));
            }
            operations
        }

        fn managed_local_projection_apply(runtime: Runtime, ebpf_path: Path) {
            move |operation: &ManagedLocalProjectionOperation| {
                match operation {
                    ManagedLocalProjectionOperation::General(mutation) => {
                        apply_shared_network_mutation(mutation, runtime, ebpf_path)?;
                        Ok(ManagedLocalProjectionReceipt::General(mutation.clone()))
                    }
                    ManagedLocalProjectionOperation::Domain(operation) => {
                        let receipt = apply_managed_local_domain_operation(operation)?;
                        Ok(ManagedLocalProjectionReceipt::Domain(receipt))
                    }
                }
            }
        }

        fn managed_local_fq_qdisc_apply_receipt(
            state: FqQdiscState,
            cleanup_on_rollback: bool,
        ) {
            let cleanup_on_rollback = cleanup_on_rollback
                && matches!(state, FqQdiscState::InstalledNow);
            ManagedLocalDomainReceipt::FqQdisc {
                state,
                cleanup_on_rollback,
            }
        }

        fn apply_managed_local_domain_operation(operation: &ManagedLocalDomainOperation) {
            if let ManagedLocalDomainOperation::EnsureFqQdisc {
                cleanup_on_rollback,
            } = operation {
                let state = ensure_fq_qdisc()?;
                if matches!(state, FqQdiscState::InstalledNow) {
                    if let Err(marker_error) = mark_owned_fq_qdisc() {
                        rollback_installed_fq_qdisc();
                        return Err(marker_error);
                    }
                }
                let receipt: ManagedLocalDomainReceipt =
                    managed_local_fq_qdisc_apply_receipt(
                        state,
                        *cleanup_on_rollback,
                    );
                return Ok(receipt);
            }
            let receipt = build_managed_local_domain_receipt(operation)?;
            apply_managed_local_projection_operation_transactionally(
                operation,
                receipt,
                apply_managed_local_domain_raw,
                compensate_managed_local_domain_receipt,
            )
        }

        fn apply_managed_local_projection_operation_transactionally(
            operation: &ManagedLocalDomainOperation,
            receipt: ManagedLocalDomainReceipt,
            mut raw_apply: impl RawApply,
            mut compensate: impl Compensation,
        ) {
            match raw_apply(operation, &receipt) {
                Ok(()) => Ok(receipt),
                Err(apply_error) => {
                    let compensation_error = compensate(&receipt).err();
                    Err(domain_apply_failure(apply_error, compensation_error))
                }
            }
        }

        fn build_managed_local_domain_receipt(operation: &ManagedLocalDomainOperation) {
            match operation {
                ManagedLocalDomainOperation::QosUpsert(rule) => {
                    Ok(ManagedLocalDomainReceipt::QosUpsert {
                        applied: rule.clone(), previous: previous_qos_rule,
                    })
                }
                ManagedLocalDomainOperation::QosDelete { group_id, direction } => {
                    Ok(ManagedLocalDomainReceipt::QosDelete { deleted: old_rule })
                }
                ManagedLocalDomainOperation::MirrorUpsert(rule) => {
                    let target_ifindex = rule.target_ifindex;
                    Ok(ManagedLocalDomainReceipt::MirrorUpsert {
                        applied: rule.clone(), previous: previous_rule_with_target_ifindex,
                    })
                }
                ManagedLocalDomainOperation::MirrorDelete {
                    src_group_id, dst_group_id, proto, direction, is_global,
                } => {
                    let _ = (src_group_id, dst_group_id, proto, direction, is_global);
                    Ok(ManagedLocalDomainReceipt::MirrorDelete {
                        deleted: old_mirror_rule,
                    })
                }
                _ => unreachable!(),
            }
        }

        fn apply_managed_local_domain_raw(
            operation: &ManagedLocalDomainOperation,
            receipt: &ManagedLocalDomainReceipt,
        ) {
            match operation {
                ManagedLocalDomainOperation::QosUpsert(rule) => aria_core::qos_ops::add_qos_rule(rule),
                ManagedLocalDomainOperation::QosDelete { group_id, direction } => {
                    aria_core::qos_ops::delete_qos_rule(group_id, direction)
                }
                ManagedLocalDomainOperation::MirrorUpsert(rule) => {
                    aria_core::mirror_ops::add_mirror_rule(rule)
                }
                ManagedLocalDomainOperation::MirrorDelete { .. } => {
                    aria_core::mirror_ops::delete_mirror_rule(receipt)
                }
                ManagedLocalDomainOperation::CleanupOwnedFqQdisc => cleanup_owned_fq_qdisc(),
                ManagedLocalDomainOperation::EnsureFqQdisc { .. } => unreachable!(),
            }
        }

        fn managed_local_domain_compensation_operations(receipt: &ManagedLocalDomainReceipt) {
            match receipt {
                ManagedLocalDomainReceipt::FqQdisc {
                    state: FqQdiscState::InstalledNow,
                    cleanup_on_rollback: true,
                } => vec![ManagedLocalDomainOperation::CleanupOwnedFqQdisc],
                ManagedLocalDomainReceipt::FqQdisc {
                    state: FqQdiscState::AlreadyPresent,
                    cleanup_on_rollback: false,
                } => Vec::new(),
                ManagedLocalDomainReceipt::QosUpsert { applied, previous } => previous
                    .clone()
                    .map(ManagedLocalDomainOperation::QosUpsert)
                    .into_iter()
                    .chain((previous.is_none()).then(|| ManagedLocalDomainOperation::QosDelete {
                        group_id: applied.group_id,
                        direction: applied.direction,
                    }))
                    .collect(),
                ManagedLocalDomainReceipt::QosDelete { deleted } => {
                    vec![ManagedLocalDomainOperation::QosUpsert(deleted.clone())]
                }
                ManagedLocalDomainReceipt::MirrorUpsert { applied, previous } => previous
                    .clone()
                    .map(ManagedLocalDomainOperation::MirrorUpsert)
                    .into_iter()
                    .chain((previous.is_none()).then(|| {
                        let _target_ifindex = applied.target_ifindex;
                        ManagedLocalDomainOperation::MirrorDelete {
                            src_group_id: applied.src_group_id,
                            dst_group_id: applied.dst_group_id,
                            proto: applied.proto,
                            direction: applied.direction,
                            is_global: applied.is_global,
                        }
                    }))
                    .collect(),
                ManagedLocalDomainReceipt::MirrorDelete { deleted } => {
                    vec![ManagedLocalDomainOperation::MirrorUpsert(deleted.clone())]
                }
                _ => Vec::new(),
            }
        }

        fn compensate_managed_local_domain_receipt(receipt: &ManagedLocalDomainReceipt) {
            for operation in managed_local_domain_compensation_operations(receipt) {
                apply_managed_local_domain_raw(&operation, receipt)?;
            }
            Ok(())
        }

        fn managed_local_projection_compensate(runtime: Runtime, ebpf_path: Path) {
            move |receipt: &ManagedLocalProjectionReceipt| {
                match receipt {
                    ManagedLocalProjectionReceipt::General(mutation) => {
                        apply_shared_network_mutation(
                            &shared_network_compensation(mutation), runtime, ebpf_path,
                        )
                    }
                    ManagedLocalProjectionReceipt::Domain(receipt) => {
                        compensate_managed_local_domain_receipt(receipt)
                    }
                }
            }
        }

        fn managed_local_projection_persist(wal: &Wal, final_state: &State) {
            let wal = wal.clone();
            let snapshot = serde_json::to_string_pretty(final_state)?;
            let durable_final_state = final_state.clone();
            move || wal.compact(snapshot.clone(), durable_final_state.clone())
        }

        fn managed_local_projection_restore(wal: &Wal, old_state: &State) {
            let wal = wal.clone();
            let snapshot = serde_json::to_string_pretty(old_state)?;
            let durable_old_state = old_state.clone();
            move || wal.compact(snapshot.clone(), durable_old_state.clone())
        }

        async fn execute_managed_local_projection_compensations(
            applied: &[Operation],
            mut compensate: impl Compensation,
        ) {
            let mut compensation_errors = Vec::new();
            for operation in applied.iter().rev() {
                if let Err(error) = compensate(operation).await {
                    compensation_errors.push(error);
                }
            }
            compensation_errors
        }

        async fn execute_managed_local_projection_transaction(
            operations: &[Operation],
            mut set_health: impl SetHealth,
            mut apply: impl Apply,
            mut persist: impl Persist,
            mut compensate: impl Compensation,
            mut restore_durable: impl RestoreDurable,
        ) {
            set_health(ManagedProjectionHealth::Unverified);
            let mut applied = Vec::new();
            for operation in operations {
                match apply(operation).await {
                    Ok(applied_operation) => applied.push(applied_operation),
                    Err(error) => {
                        let compensation_errors =
                            execute_managed_local_projection_compensations(
                                &applied,
                                &mut compensate,
                            ).await;
                        return Err(transaction_failure(error, compensation_errors));
                    }
                }
            }
            if let Err(error) = persist().await {
                let compensation_errors = execute_managed_local_projection_compensations(
                    &applied,
                    &mut compensate,
                ).await;
                let restore_error = restore_durable().await.err();
                return Err(transaction_failure(
                    error,
                    compensation_errors,
                    restore_error,
                ));
            }
            set_health(ManagedProjectionHealth::Verified);
            Ok(())
        }

        fn reconcile_retained_owned_groups(old_state: &State, final_state: &mut State) {
            let mut removed_group_ids = Vec::new();
            for old_group in old_state.groups.values() {
                let referenced = final_state.rules.iter().any(|rule| {
                    rule.src_group_id == old_group.id || rule.dst_group_id == old_group.id
                }) || final_state.qos_rules.iter().any(|rule| {
                    rule.group_id == old_group.id
                }) || final_state.mirror_rules.iter().any(|rule| {
                    rule.src_group_id == old_group.id || rule.dst_group_id == old_group.id
                });
                if !referenced && final_state.groups.remove(&old_group.name).is_some() {
                    removed_group_ids.push(old_group.id);
                }
            }
            Ok(removed_group_ids)
        }

        fn clear_removed_retained_owned_group_stats(
            removed_group_ids: &[u32],
            runtime: Runtime,
        ) {
            for group_id in removed_group_ids {
                if let Err(error) = clear_group_stats_for_id(runtime, *group_id) {
                    warn!(error = %error, group_id, "failed to clear retained-owned group stats");
                }
            }
        }

        async fn add_group_standalone_locked(state: &mut State) {
            aria_core::ebpf_ops::add_network();
            aria_core::ebpf_ops::add_acl_network_in_bank();
            state.wal_append(entry).await;
        }
        async fn delete_group_standalone_locked(state: &mut State) {
            aria_core::ebpf_ops::delete_network();
            aria_core::ebpf_ops::delete_acl_network_in_bank();
            state.wal_append(entry).await;
        }
        async fn add_qos_standalone_locked(state: &mut State) {
            aria_core::qos_ops::add_qos_rule();
            let mut errors = Vec::new();
            for previous in applied.iter().rev() {
                if let Err(rollback_error) = aria_core::qos_ops::delete_qos_rule(previous) {
                    errors.push(format!("rollback QoS direction: {}", rollback_error));
                    continue;
                }
                state.state.qos_rules.retain(|rule| rule != previous);
                state.wal_append(WalEntry::DeleteQos(previous)).await;
            }
            if !errors.is_empty() {
                return Err(errors.join("; "));
            }
            state.wal_append(entry).await;
        }
        async fn delete_qos_standalone_locked(state: &mut State) {
            aria_core::qos_ops::delete_qos_rule();
            state.wal_append(entry).await;
        }
        async fn add_mirror_standalone_locked(state: &mut State) {
            aria_core::mirror_ops::add_mirror_rule();
            let mut errors = Vec::new();
            for previous in applied.iter().rev() {
                let rollback = if previous.is_global {
                    aria_core::mirror_ops::delete_global_mirror(previous)
                } else {
                    aria_core::mirror_ops::delete_mirror_rule(previous)
                };
                if let Err(rollback_error) = rollback {
                    errors.push(format!("rollback Mirror direction: {}", rollback_error));
                    continue;
                }
                state.state.mirror_rules.retain(|rule| rule != previous);
                state.wal_append(WalEntry::DeleteMirror(previous)).await;
            }
            if !errors.is_empty() {
                return Err(errors.join("; "));
            }
            state.wal_append(entry).await;
        }
        async fn delete_mirror_standalone_locked(state: &mut State) {
            aria_core::mirror_ops::delete_mirror_rule();
            state.wal_append(entry).await;
        }
    """
    wrappers = (
        wrapper(
            "add_group",
            "add_group_standalone_locked",
            ", group_id: u32",
            "GeneralThenDomain",
            """            let domain_operations = Vec::new();
            let final_state = proposed_group_add(&old_state)?;
            validate_managed_group_mutation(&final_state, group_id)?;""",
        )
        + wrapper(
            "delete_group",
            "delete_group_standalone_locked",
            ", group_id: u32",
            "GeneralThenDomain",
            """            let domain_operations = Vec::new();
            let final_state = proposed_group_delete(&old_state)?;
            validate_managed_group_mutation(&final_state, group_id)?;""",
        )
        + wrapper(
            "add_qos",
            "add_qos_standalone_locked",
            ", direction: u8, mode: u8",
            "GeneralThenDomain",
            """            let direction_plans = managed_qos_direction_plans(direction, mode)?;
            let domain_operations = plan_managed_local_qos_upserts(
                &old_state, group_id, rate_bps, burst_bytes, priority, &direction_plans,
            )?;
            let final_state = proposed_qos_add(&old_state, &domain_operations)?;""",
            "            Self::cleanup_owned_fq_qdisc_if_unused(instance, &state);",
        )
        + wrapper(
            "delete_qos",
            "delete_qos_standalone_locked",
            ", direction: u8",
            "DomainThenGeneral",
            """            let directions = requested_directions(direction)?;
            let domain_operations = plan_managed_local_qos_delete(
                &old_state, group_id, &directions,
            )?;
            let mut final_state = proposed_qos_delete(&old_state, &domain_operations)?;
            let removed_retained_qos_group_ids =
                reconcile_retained_owned_groups(&old_state, &mut final_state)?;""",
            "            clear_removed_retained_owned_group_stats(&removed_retained_qos_group_ids, state.map_runtime());",
        )
        + wrapper(
            "add_mirror",
            "add_mirror_standalone_locked",
            ", direction: u8",
            "GeneralThenDomain",
            """            let directions = requested_directions(direction)?;
            let domain_operations = plan_managed_local_mirror_upserts(
                &old_state, src_id, dst_id, proto, target_ifindex, &directions,
            )?;
            let final_state = proposed_mirror_add(&old_state, &domain_operations)?;""",
        )
        + wrapper(
            "delete_mirror",
            "delete_mirror_standalone_locked",
            ", direction: u8",
            "DomainThenGeneral",
            """            let directions = requested_directions(direction)?;
            let domain_operations = plan_managed_local_mirror_delete(
                &old_state, src_id, dst_id, proto, &directions,
            )?;
            let mut final_state = proposed_mirror_delete(&old_state, &domain_operations)?;
            let removed_retained_mirror_group_ids =
                reconcile_retained_owned_groups(&old_state, &mut final_state)?;""",
            "            clear_removed_retained_owned_group_stats(&removed_retained_mirror_group_ids, state.map_runtime());",
        )
    )
    tail = r"""
        pub async fn replace_owned_acl(&self) {
            let old_state = state.state.clone();
            let mut final_state = proposed_owned_state(&old_state)?;
            for group in &group_deletes {
                final_state.groups.remove(&group.name);
            }
            reconcile_retained_owned_groups(&old_state, &mut final_state);
            let mutations = managed_general_state_mutations(&old_state, &final_state)?;
        }

        fn status_code(&self) -> u16 {
            match self {
                Self::GroupInUse(_) | Self::LocalWriteBlocked { .. } => 409,
                Self::InstanceNotReady(_) => 503,
                _ => 500,
            }
        }
    """
    safe_control = shared + wrappers + tail
    def handlers(specs):
        return "".join(
            r"""
        #[utoipa::path(responses((status = 409), (status = 503)))]
        pub async fn %s(State(cp): State<AppState>) {
            if let Err(e) = cp.%s(%s).await {
                return Err(err_response(e));
            }
            Ok(())
        }
        """ % (name, name, arguments)
            for name, arguments in specs
        )

    safe_groups = handlers((
        ("add_group", "&instance, group_id"),
        ("delete_group", "&instance, group_id"),
    ))
    safe_qos = handlers((
        ("add_qos", "&instance, direction, mode"),
        ("delete_qos", "&instance, direction"),
    ))
    safe_mirror = handlers((
        ("add_mirror", "&instance, direction"),
        ("delete_mirror", "&instance, direction"),
    ))
    def mutate(source, old, new, count=1):
        if source.count(old) < count:
            raise SystemExit("ERROR: Task 5 mutation fixture anchor is missing: " + old)
        return source.replace(old, new, count)

    safe_errors = _managed_cross_domain_group_mutation_contract_errors(
        safe_control, safe_groups, safe_qos, safe_mirror
    )
    if safe_errors:
        raise SystemExit(
            "ERROR: managed cross-domain checker rejected safe source: %s" % safe_errors
        )

    executor_call = """            execute_managed_local_projection_transaction(
                &operations,
                set_projection_health,
                apply_projection_operation,
                persist_final_state,
                compensate_projection_receipt,
                restore_old_state,
            ).await?;"""
    plan_call = """            let general_mutations =
                managed_general_state_mutations(&old_state, &final_state)?;"""
    kernel_compensation = """                        let compensation_errors =
                            execute_managed_local_projection_compensations(
                                &applied,
                                &mut compensate,
                            ).await;"""
    def case(label, expected, **changed):
        sources = dict(
            control=safe_control,
            groups=safe_groups,
            qos=safe_qos,
            mirror=safe_mirror,
        )
        sources.update(changed)
        return label, sources["control"], sources["groups"], sources["qos"], sources["mirror"], expected

    def control_case(label, expected, old, new):
        return case(label, expected, control=mutate(safe_control, old, new))

    kernel_error = "kernel partial failure must compensate every applied operation"
    plan_error = "add_group must plan old_state to final_state before one shared executor call"
    mutants = [
        control_case(
            "direct active ACL writer",
            "managed local group add/delete still mutates the active ACL bank",
            executor_call,
            "            add_acl_network_in_bank(direction, cidr)?;\n" + executor_call,
        ),
        control_case(
            "partial second-direction failure skips compensation",
            kernel_error,
            kernel_compensation,
            "                        let compensation_errors = Vec::new();",
        ),
        control_case(
            "kernel apply failure falls through to persistence",
            "kernel apply failure must return its transaction failure before persistence",
            "                        return Err(transaction_failure(error, compensation_errors));",
            "                        let _ignored = transaction_failure(error, compensation_errors);",
        ),
        control_case(
            "all kernel compensation removed",
            kernel_error,
            "execute_managed_local_projection_compensations(\n"
            "                                &applied,\n"
            "                                &mut compensate,\n"
            "                            ).await",
            "Vec::new()",
        ),
        control_case(
            "compensation stops at first error",
            "compensation must run in reverse and attempt every applied operation",
            "compensation_errors.push(error);",
            "return Err(error);",
        ),
        control_case(
            "apply receipt is discarded",
            "shared executor must journal apply receipts rather than requested operations",
            "Ok(applied_operation) => applied.push(applied_operation)",
            "Ok(_applied_operation) => applied.push(operation)",
        ),
        control_case(
            "persist rollback omits durable restore",
            "persistence failure must restore durable old state",
            "let restore_error = restore_durable().await.err();",
            "let restore_error = None;",
        ),
        control_case(
            "durable restore failure is swallowed",
            "durable restore failure must remain visible to the caller",
            "restore_error,\n                ));",
            "None,\n                ));",
        ),
        control_case(
            "persistence failure falls through to Verified",
            "persistence failure must return its transaction failure before Verified restoration",
            """                return Err(transaction_failure(
                    error,
                    compensation_errors,
                    restore_error,
                ));""",
            """                let _ignored = transaction_failure(
                    error,
                    compensation_errors,
                    restore_error,
                );""",
        ),
        control_case(
            "direction two is written directly",
            "requested direction 2 must expand to ingress and egress",
            "2 => Ok(vec![0, 1]),",
            "2 => Ok(vec![direction]),",
        ),
        control_case(
            "QoS ingress shaping downgrade lost",
            "QoS direction planning must preserve both-direction mode semantics",
            "let effective_mode = if direction == 0 && mode == 1 { 0 } else { mode };",
            "let effective_mode = mode;",
        ),
        control_case(
            "FQ receipt drops InstalledNow ownership",
            "managed FQ receipt cleanup must derive from the actual ensure result",
            """            let cleanup_on_rollback = cleanup_on_rollback
                && matches!(state, FqQdiscState::InstalledNow);""",
            "            let cleanup_on_rollback = false;",
        ),
        control_case(
            "FQ marker failure skips rollback",
            "managed FQ marker failure must roll back the installed qdisc before returning",
            """                    if let Err(marker_error) = mark_owned_fq_qdisc() {
                        rollback_installed_fq_qdisc();
                        return Err(marker_error);
                    }""",
            """                    if let Err(marker_error) = mark_owned_fq_qdisc() {
                        return Err(marker_error);
                    }
                    if matches!(state, FqQdiscState::AlreadyPresent) {
                        rollback_installed_fq_qdisc();
                    }""",
        ),
        control_case(
            "QoS replacement drops previous rule",
            "managed domain receipts must preserve QoS and Mirror preimages",
            "applied: rule.clone(), previous: previous_qos_rule,",
            "applied: rule.clone(), previous: None,",
        ),
        control_case(
            "Mirror replacement drops previous rule",
            "managed domain receipts must preserve QoS and Mirror preimages",
            "applied: rule.clone(), previous: previous_rule_with_target_ifindex,",
            "applied: rule.clone(), previous: None,",
        ),
        control_case(
            "current-operation compensation result is discarded",
            "managed domain apply failure must compensate its current receipt",
            "let compensation_error = compensate(&receipt).err();",
            "let compensation_error = None;\n"
            "                    let _ignored = compensate(&receipt);",
        ),
        control_case(
            "standalone dispatch missing",
            "add_group must explicitly dispatch both standalone modes before managed admission",
            "return self.add_group_standalone_locked(&mut state).await;",
            "return Ok(());",
        ),
        case(
            "projection plan runs after executor",
            plan_error,
            control=mutate(safe_control, plan_call, "").replace(
                executor_call, executor_call + "\n" + plan_call, 1
            ),
        ),
        control_case(
            "same-state projection delta",
            plan_error,
            "managed_general_state_mutations(&old_state, &final_state)?;",
            "managed_general_state_mutations(&old_state, &old_state)?;",
        ),
        control_case(
            "executor called twice",
            "add_group must call the shared executor exactly once",
            executor_call,
            executor_call + "\n" + executor_call,
        ),
        control_case(
            "executor omits Verified restoration",
            "shared executor must set health exactly once to Unverified before apply "
            "and exactly once to Verified after successful persistence",
            "            set_health(ManagedProjectionHealth::Verified);\n",
            "",
        ),
        case(
            "executor restores Verified before persistence",
            "shared executor must set health exactly once to Unverified before apply "
            "and exactly once to Verified after successful persistence",
            control=mutate(
                mutate(
                    safe_control,
                    "            set_health(ManagedProjectionHealth::Verified);\n",
                    "",
                ),
                "            if let Err(error) = persist().await {",
                "            set_health(ManagedProjectionHealth::Verified);\n"
                "            if let Err(error) = persist().await {",
            ),
            groups=safe_groups,
            qos=safe_qos,
            mirror=safe_mirror,
        ),
        control_case(
            "standalone helper uses managed executor",
            "standalone helper add_group_standalone_locked must not use the managed executor",
            "            aria_core::ebpf_ops::add_network();",
            "            execute_managed_local_projection_transaction(state).await;",
        ),
        control_case(
            "standalone QoS rollback deletes RAM/WAL after kernel cleanup failure",
            "standalone add_qos prior-direction rollback must retain RAM/WAL on "
            "kernel delete failure and aggregate the error",
            """                    errors.push(format!("rollback QoS direction: {}", rollback_error));
                    continue;""",
            """                    errors.push(format!("rollback QoS direction: {}", rollback_error));""",
        ),
        control_case(
            "standalone Mirror rollback deletes RAM/WAL after kernel cleanup failure",
            "standalone add_mirror prior-direction rollback must retain RAM/WAL on "
            "kernel delete failure and aggregate the error",
            """                    errors.push(format!("rollback Mirror direction: {}", rollback_error));
                    continue;""",
            """                    errors.push(format!("rollback Mirror direction: {}", rollback_error));""",
        ),
        control_case(
            "standalone QoS rollback mutates RAM/WAL before kernel outcome",
            "standalone add_qos prior-direction rollback must retain RAM/WAL on "
            "kernel delete failure and aggregate the error",
            """                if let Err(rollback_error) = aria_core::qos_ops::delete_qos_rule(previous) {
                    errors.push(format!("rollback QoS direction: {}", rollback_error));
                    continue;
                }
                state.state.qos_rules.retain(|rule| rule != previous);
                state.wal_append(WalEntry::DeleteQos(previous)).await;""",
            """                state.state.qos_rules.retain(|rule| rule != previous);
                state.wal_append(WalEntry::DeleteQos(previous)).await;
                if let Err(rollback_error) = aria_core::qos_ops::delete_qos_rule(previous) {
                    errors.push(format!("rollback QoS direction: {}", rollback_error));
                    continue;
                }""",
        ),
        control_case(
            "standalone Mirror rollback omits global kernel delete",
            "standalone add_mirror prior-direction rollback must retain RAM/WAL on "
            "kernel delete failure and aggregate the error",
            "                    aria_core::mirror_ops::delete_global_mirror(previous)",
            "                    aria_core::mirror_ops::delete_mirror_rule(previous)",
        ),
        control_case(
            "managed QoS replacement leaves owned FQ qdisc behind",
            "managed add_qos must clean an owned FQ qdisc after successful "
            "shaping-to-policing replacement",
            "            Self::cleanup_owned_fq_qdisc_if_unused(instance, &state);",
            "",
        ),
        control_case(
            "managed QoS replacement hides FQ cleanup in a dead branch",
            "managed add_qos must clean an owned FQ qdisc after successful "
            "shaping-to-policing replacement",
            "            Self::cleanup_owned_fq_qdisc_if_unused(instance, &state);",
            """            if false {
                Self::cleanup_owned_fq_qdisc_if_unused(instance, &state);
            }""",
        ),
        control_case(
            "retained reconciliation drops removed group IDs",
            "retained owned-group reconciliation must report removed group IDs",
            "                    removed_group_ids.push(old_group.id);",
            "                    let _ = old_group.id;",
        ),
        control_case(
            "retained reconciliation reports IDs without a successful removal",
            "retained owned-group reconciliation must report removed group IDs",
            """                if !referenced && final_state.groups.remove(&old_group.name).is_some() {
                    removed_group_ids.push(old_group.id);
                }""",
            """                if !referenced && final_state.groups.remove(&old_group.name).is_some() {
                }
                removed_group_ids.push(old_group.id);""",
        ),
        control_case(
            "retained group stats cleanup becomes fallible",
            "removed retained-owned GROUP_STATS cleanup must be best-effort",
            """                if let Err(error) = clear_group_stats_for_id(runtime, *group_id) {
                    warn!(error = %error, group_id, "failed to clear retained-owned group stats");
                }""",
            "                clear_group_stats_for_id(runtime, *group_id)?;",
        ),
        control_case(
            "retained group stats cleanup clears the wrong ID",
            "removed retained-owned GROUP_STATS cleanup must be best-effort",
            "clear_group_stats_for_id(runtime, *group_id)",
            "clear_group_stats_for_id(runtime, 0)",
        ),
        control_case(
            "retained group stats cleanup only visits the first ID",
            "removed retained-owned GROUP_STATS cleanup must be best-effort",
            "            for group_id in removed_group_ids {",
            "            if let Some(group_id) = removed_group_ids.first() {",
        ),
        control_case(
            "retained group stats cleanup stops after the first failure",
            "removed retained-owned GROUP_STATS cleanup must be best-effort",
            """                    warn!(error = %error, group_id, "failed to clear retained-owned group stats");""",
            """                    warn!(error = %error, group_id, "failed to clear retained-owned group stats");
                    break;""",
        ),
        control_case(
            "managed QoS delete skips retained group stats cleanup",
            "managed delete_qos must best-effort clear GROUP_STATS for retained-owned "
            "groups removed after commit",
            "            clear_removed_retained_owned_group_stats(&removed_retained_qos_group_ids, state.map_runtime());",
            "",
        ),
        control_case(
            "managed QoS delete hides retained stats cleanup in a dead branch",
            "managed delete_qos must best-effort clear GROUP_STATS for retained-owned "
            "groups removed after commit",
            "            clear_removed_retained_owned_group_stats(&removed_retained_qos_group_ids, state.map_runtime());",
            """            if false {
                clear_removed_retained_owned_group_stats(
                    &removed_retained_qos_group_ids,
                    state.map_runtime(),
                );
            }""",
        ),
        control_case(
            "managed QoS delete passes retained IDs by value",
            "managed delete_qos must best-effort clear GROUP_STATS for retained-owned "
            "groups removed after commit",
            "clear_removed_retained_owned_group_stats(&removed_retained_qos_group_ids, state.map_runtime())",
            "clear_removed_retained_owned_group_stats(removed_retained_qos_group_ids, state.map_runtime())",
        ),
        control_case(
            "managed Mirror delete skips retained group stats cleanup",
            "managed delete_mirror must best-effort clear GROUP_STATS for retained-owned "
            "groups removed after commit",
            "            clear_removed_retained_owned_group_stats(&removed_retained_mirror_group_ids, state.map_runtime());",
            "",
        ),
        control_case(
            "managed Mirror delete passes the wrong stats runtime",
            "managed delete_mirror must best-effort clear GROUP_STATS for retained-owned "
            "groups removed after commit",
            "clear_removed_retained_owned_group_stats(&removed_retained_mirror_group_ids, state.map_runtime())",
            "clear_removed_retained_owned_group_stats(&removed_retained_mirror_group_ids, old_state.map_runtime())",
        ),
        control_case(
            "QoS delete bypasses direction expansion",
            "managed delete_qos must feed expanded directions and old_state to its full planner",
            "let directions = requested_directions(direction)?;",
            "let directions = vec![direction];",
        ),
        control_case(
            "group-ID validation bypass",
            "managed add_group must validate ACL references before execution",
            "validate_managed_group_mutation(&final_state, group_id)?;",
            "let _ = group_id;",
        ),
        case(
            "retained helper ignores Mirror",
            "retained owned groups must follow ACL, QoS, and both Mirror references",
            control=mutate(
                safe_control, "mirror_rules", "ignored_mirrors", count=2
            ),
        ),
        control_case(
            "owned retention precedes removal",
            "owned ACL replace must reconcile retention after removals and before projection",
            """            for group in &group_deletes {
                final_state.groups.remove(&group.name);
            }
            reconcile_retained_owned_groups(&old_state, &mut final_state);""",
            """            reconcile_retained_owned_groups(&old_state, &mut final_state);
            for group in &group_deletes {
                final_state.groups.remove(&group.name);
            }""",
        ),
        case(
            "handler expands both directions itself",
            "managed add_qos handler must not loop around its ControlPlane call",
            qos=mutate(
                safe_qos,
                "            if let Err(e) = cp.add_qos(&instance, direction, mode).await {\n"
                "                return Err(err_response(e));\n"
                "            }",
                "            for direction in directions {\n"
                "                if let Err(e) = cp.add_qos(&instance, direction, mode).await {\n"
                "                    return Err(err_response(e));\n"
                "                }\n"
                "            }",
            ),
        ),
        case(
            "missing handler 409",
            "managed mutation handler add_group must document HTTP 409",
            groups=mutate(safe_groups, "(status = 409)", "(status = 500)"),
        ),
        case(
            "missing handler 503",
            "managed mutation handler add_group must document HTTP 503",
            groups=mutate(safe_groups, "(status = 503)", "(status = 500)"),
        ),
        case(
            "handler remaps ControlPlane error",
            "managed mutation handler add_group must return its exact ControlPlane error",
            groups=mutate(
                safe_groups,
                "return Err(err_response(e));",
                "return Err(err_response("
                "ControlPlaneError::KernelError(e.to_string())));",
            ),
        ),
    ]
    for wrapper_name in (
        "add_group",
        "delete_group",
        "add_qos",
        "delete_qos",
        "add_mirror",
        "delete_mirror",
    ):
        wrapper_body = _rust_function_body_raw(safe_control, wrapper_name)
        if wrapper_body is None or wrapper_body.count(plan_call) != 1:
            raise SystemExit(
                "ERROR: Task 7 managed wrapper fixture is missing projection plan: %s"
                % wrapper_name
            )
        mutants.append(
            (
                "%s omits general projection plan" % wrapper_name,
                safe_control.replace(
                    wrapper_body,
                    wrapper_body.replace(plan_call, "", 1),
                    1,
                ),
                safe_groups,
                safe_qos,
                safe_mirror,
                "%s must plan old_state to final_state before one shared executor call"
                % wrapper_name,
            )
        )
    for label, control, groups, qos, mirror, expected in mutants:
        errors = _managed_cross_domain_group_mutation_contract_errors(
            control, groups, qos, mirror
        )
        if not any(expected in error for error in errors):
            raise SystemExit(
                "ERROR: managed cross-domain checker accepted %s mutation: %s"
                % (label, errors)
            )
    print(
        "Managed cross-domain group mutation self-tests: OK (%d scenarios)"
        % (len(mutants) + 1)
    )


def _run_acl_ingress_parser_self_tests():
    comment_only = """
        // fn acl_ingress_hook(tap_id: u32) -> u8 { 0 }
        /* pub const ACL_INGRESS_HOOK_XDP: u8 = 0;
           pub const ACL_INGRESS_HOOK_TC: u8 = 1;
           pub acl_ingress_hook: u8, */
    """
    if _has_acl_ingress_hook_definition(comment_only):
        raise SystemExit("ERROR: eBPF boundary parser treated a comment as code")
    if len(_missing_acl_ingress_abi(comment_only)) != len(ABI_DECLARATIONS):
        raise SystemExit("ERROR: eBPF ABI parser accepted comment-only declarations")

    formatted_runtime = "pub\nunsafe fn acl_ingress_hook ( tap_id: u32 ) -> u8 { 0 }"
    if not _has_acl_ingress_hook_definition(formatted_runtime):
        raise SystemExit("ERROR: eBPF boundary parser missed a formatted definition")

    formatted_abi = """
        pub
        const ACL_INGRESS_HOOK_XDP : u8 = 0 ;
        pub const ACL_INGRESS_HOOK_TC:u8=1;
        pub acl_ingress_hook : u8 ,
    """
    if _missing_acl_ingress_abi(formatted_abi):
        raise SystemExit("ERROR: eBPF ABI parser rejected harmless formatting")
    print("eBPF ACL ingress parser self-tests: OK (4 scenarios)")


def _rust_string_const(source, name):
    pattern = r'pub const %s: &str = "([^"]+)";' % re.escape(name)
    match = re.search(pattern, source)
    if not match:
        raise SystemExit("ERROR: Rust string const %s not found" % name)
    return match.group(1)


def _rust_int_const(source, name):
    pattern = r"pub const %s: u(?:32|64) = ([0-9_]+);" % re.escape(name)
    match = re.search(pattern, source)
    if not match:
        raise SystemExit("ERROR: Rust int const %s not found" % name)
    return int(match.group(1).replace("_", ""))


def _rust_string_slice_const(source, name):
    pattern = r'pub const %s: &\[&str\] = &\[(.*?)\];' % re.escape(name)
    match = re.search(pattern, source, re.DOTALL)
    if not match:
        raise SystemExit("ERROR: Rust string slice const %s not found" % name)
    return re.findall(r'"([^"]+)"', match.group(1))


def run(cmd, cwd=ROOT, env=None):
    print("==> %s" % " ".join(cmd))
    subprocess.check_call(cmd, cwd=cwd, env=env)


def run_python_tests():
    env = os.environ.copy()
    pythonpath = os.path.join(ROOT, "openstack", "neutron_aria")
    if env.get("PYTHONPATH"):
        pythonpath = pythonpath + os.pathsep + env["PYTHONPATH"]
    env["PYTHONPATH"] = pythonpath
    run(
        [
            sys.executable,
            "-m",
            "unittest",
            "discover",
            "-s",
            PYTHON_TEST_ROOT,
            "-p",
            "test_*.py",
        ],
        env=env,
    )


def check_uds_contract_artifact():
    print("==> checking docs/neutron-uds-contract.json")
    sys.path.insert(0, os.path.join(ROOT, "openstack", "neutron_aria"))
    from neutron_aria.agent import uds_client

    with open(os.path.join(ROOT, UDS_CONTRACT_PATH), "r") as handle:
        contract = json.load(handle)

    expected = {
        "api_version": uds_client.NEUTRON_API_VERSION,
        "contract_version": uds_client.NEUTRON_CONTRACT_VERSION,
        "schema_version_min": uds_client.NEUTRON_SCHEMA_VERSION,
        "schema_version_max": uds_client.NEUTRON_SCHEMA_VERSION,
        "attach_authority": uds_client.NEUTRON_ATTACH_AUTHORITY,
        "supports_full_snapshot": True,
        "supports_port_scoped_snapshot": True,
        "supports_port_delete": True,
        "body_max_bytes": uds_client.NEUTRON_BODY_MAX_BYTES,
        "timeout_ms": uds_client.NEUTRON_TIMEOUT_MS,
        "error_codes_hash": uds_client.NEUTRON_ERROR_CODES_HASH,
        "capability_hash": uds_client.NEUTRON_CAPABILITY_HASH,
    }
    for key, value in expected.items():
        if contract.get(key) != value:
            raise SystemExit(
                "ERROR: %s expected %r, got %r"
                % (key, value, contract.get(key))
            )

    if not contract.get("peer_auth_policy"):
        raise SystemExit("ERROR: peer_auth_policy must be non-empty")

    domains = contract.get("supported_domains") or []
    if domains != ["attach", "acl"]:
        raise SystemExit(
            "ERROR: supported_domains must match implemented domains "
            "['attach', 'acl'], got %r" % domains
        )

    routes = {
        (route.get("method"), route.get("path"))
        for route in contract.get("routes") or []
    }
    required_routes = {
        ("GET", "/api/v1/neutron/capabilities"),
        ("GET", "/api/v1/neutron/status"),
        ("PUT", "/api/v1/neutron/snapshot"),
        ("PUT", "/api/v1/neutron/ports/{port_id}/snapshot"),
        ("DELETE", "/api/v1/neutron/ports/{port_id}"),
    }
    missing = sorted(required_routes - routes)
    if missing:
        raise SystemExit("ERROR: contract routes missing %r" % (missing,))

    errors = {error.get("code"): error for error in contract.get("error_codes") or []}
    required_errors = {
        "UDS_SCHEMA_MISMATCH": "rust_snapshot_apply",
        "UDS_BODY_TOO_LARGE": "python_client_http_413_mapping",
        "generation_hash_conflict": "rust_snapshot_apply",
        "stale_generation": "rust_snapshot_apply",
    }
    for code, owner in required_errors.items():
        if code not in errors:
            raise SystemExit("ERROR: contract error_codes missing %s" % code)
        if errors[code].get("owner") != owner:
            raise SystemExit(
                "ERROR: contract error %s owner expected %r, got %r"
                % (code, owner, errors[code].get("owner"))
            )
        if errors[code].get("phase") != "implemented":
            raise SystemExit("ERROR: contract error %s must be implemented" % code)

    p3_scoped = contract.get("p3_port_scoped_snapshot") or {}
    expected_p3_scoped = {
        "phase": "runtime_enablement_config_gated",
        "runtime_enabled": True,
        "route_enabled": True,
        "capability_advertised": True,
        "python_submitter_enabled": True,
        "incremental_rpc_enabled_default": False,
        "revisionless_incremental_mode_default": "disabled",
        "method": "PUT",
        "path": "/api/v1/neutron/ports/{port_id}/snapshot",
        "body_scope": "single_port",
        "body_max_bytes": uds_client.NEUTRON_BODY_MAX_BYTES,
        "timeout_ms": uds_client.NEUTRON_TIMEOUT_MS,
    }
    for key, value in expected_p3_scoped.items():
        if p3_scoped.get(key) != value:
            raise SystemExit(
                "ERROR: p3_port_scoped_snapshot %s expected %r, got %r"
                % (key, value, p3_scoped.get(key))
            )
    if "incremental_rpc_enabled=true" not in p3_scoped.get("enablement_gate", ""):
        raise SystemExit("ERROR: p3 port-scoped contract must name incremental gate")
    if "full resync" not in p3_scoped.get("fallback_rule", ""):
        raise SystemExit("ERROR: p3 port-scoped contract must keep full-resync fallback")
    planned_errors = set(p3_scoped.get("planned_error_codes") or [])
    for code in (
        "UDS_SCHEMA_MISMATCH",
        "UDS_BODY_TOO_LARGE",
        "generation_hash_conflict",
        "stale_generation",
        "PORT_SCOPE_MISMATCH",
        "PORT_IFACE_NOT_FOUND",
        "UDS_CONTRACT_DRIFT",
    ):
        if code not in planned_errors:
            raise SystemExit("ERROR: p3 port-scoped planned errors missing %s" % code)
    guardrails = set(p3_scoped.get("runtime_guardrails") or [])
    for guardrail in (
        "keep incremental_rpc_enabled=false in packaged defaults",
        "keep revisionless_incremental_mode=disabled in packaged defaults",
        "require rpc_events_enabled=true, full_resync_enabled=true, and port_source=neutronclient before incremental enablement",
        "only single local newer-revision port.update events may use scoped apply",
        "multi-port batches, delete events, network updates, overflow, unknown revision, and scoped submit failures fall back to full resync",
        "do not remove full-resync recovery",
    ):
        if guardrail not in guardrails:
            raise SystemExit("ERROR: p3 port-scoped guardrail missing %r" % guardrail)

    phase_status = contract.get("phase_status") or {}
    expected_phase_status = {
        "capabilities_metadata": "implemented",
        "python_client_validation": "implemented",
        "uds_body_limit": "implemented",
        "tcp_openapi_exclusion_test": "implemented",
        "peercred_enforcement": "implemented_config_gated",
        "peercred_audit": "implemented_connection_level",
    }
    for name, status in expected_phase_status.items():
        if phase_status.get(name) != status:
            raise SystemExit(
                "ERROR: phase_status %s expected %r, got %r"
                % (name, status, phase_status.get(name))
            )


def check_status_v1_contract():
    print("==> checking versioned Status V1 contract")
    _run_status_v1_rust_parser_self_tests()
    _run_status_v1_exact_integer_mutation_self_tests()
    _run_status_v1_fixture_path_mutation_self_tests()
    _run_status_v1_json_loading_mutation_self_tests()
    _run_status_v1_shape_mutation_self_tests()
    _run_status_v1_projection_mutation_self_tests()

    python_root = os.path.join(ROOT, "openstack", "neutron_aria")
    if python_root not in sys.path:
        sys.path.insert(0, python_root)
    from neutron_aria.agent import uds_client

    errors = []
    contract, contract_load_errors = _status_v1_load_json_object(
        UDS_CONTRACT_PATH,
        "UDS contract",
        opener=_status_v1_open_repo_relative,
    )
    errors.extend(contract_load_errors)
    fixture_path, fixture_path_errors = _status_v1_validated_fixture_path(
        contract.get("status_contract_scenarios_path")
    )
    errors.extend(fixture_path_errors)
    fixture = {}
    if fixture_path is not None:
        fixture, fixture_load_errors = _status_v1_load_json_object(
            STATUS_V1_SCENARIOS_PATH,
            "Status V1 fixture",
            opener=_status_v1_open_repo_relative,
        )
        errors.extend(fixture_load_errors)

    expected_contract_fields = {
        "status_schema_version_min": EXPECTED_STATUS_V1_SCHEMA_VERSION,
        "status_schema_version_max": EXPECTED_STATUS_V1_SCHEMA_VERSION,
        "status_contract_hash": EXPECTED_STATUS_V1_CONTRACT_HASH,
        "status_contract_scenarios_path": STATUS_V1_SCENARIOS_PATH,
    }
    for field, expected in expected_contract_fields.items():
        actual = contract.get(field)
        if field in (
            "status_schema_version_min", "status_schema_version_max",
        ):
            matches = _status_v1_exact_integer_matches(actual, expected)
        else:
            matches = actual == expected
        if not matches:
            errors.append(
                "UDS contract %s expected %r, got %r" % (field, expected, actual)
            )

    vocabulary = dict(EXPECTED_STATUS_V1_VOCABULARY)
    expected_fixture_root_keys = {
        "fixture_schema_version", "status_contract", "scenarios",
    }
    if not isinstance(fixture, dict):
        errors.append("Status V1 fixture root must be an object")
        fixture_status = {}
        scenarios = []
    else:
        if set(fixture) != expected_fixture_root_keys:
            errors.append(
                "Status V1 fixture root keys expected %r, got %r"
                % (sorted(expected_fixture_root_keys), sorted(fixture))
            )
        if not _status_v1_exact_integer_matches(
            fixture.get("fixture_schema_version"), 1
        ):
            errors.append(
                "Status V1 fixture_schema_version expected 1, got %r"
                % fixture.get("fixture_schema_version")
            )
        fixture_status = fixture.get("status_contract")
        scenarios = fixture.get("scenarios")

    expected_fixture_contract_keys = {"version", "hash"}.union(vocabulary)
    if not isinstance(fixture_status, dict):
        errors.append("Status V1 fixture status_contract must be an object")
        fixture_status = {}
    elif set(fixture_status) != expected_fixture_contract_keys:
        errors.append(
            "Status V1 fixture contract keys expected %r, got %r"
            % (sorted(expected_fixture_contract_keys), sorted(fixture_status))
        )

    if not _status_v1_exact_integer_matches(
        fixture_status.get("version"), EXPECTED_STATUS_V1_SCHEMA_VERSION
    ):
        errors.append(
            "Status V1 fixture version expected %r, got %r"
            % (
                EXPECTED_STATUS_V1_SCHEMA_VERSION,
                fixture_status.get("version"),
            )
        )
    if fixture_status.get("hash") != EXPECTED_STATUS_V1_CONTRACT_HASH:
        errors.append(
            "Status V1 fixture hash expected %r, got %r"
            % (EXPECTED_STATUS_V1_CONTRACT_HASH, fixture_status.get("hash"))
        )
    for name, expected in EXPECTED_STATUS_V1_VOCABULARY:
        actual = fixture_status.get(name)
        if not isinstance(actual, list):
            errors.append("Status V1 fixture %s must be an array" % name)
            continue
        if _status_v1_has_duplicates(actual):
            errors.append("Status V1 fixture %s contains duplicate values" % name)
        if tuple(actual) != expected:
            errors.append(
                "Status V1 fixture %s expected %r, got %r"
                % (name, expected, tuple(actual))
            )

    errors.extend(_status_v1_python_metadata_contract_errors(
        uds_client,
        vocabulary,
    ))

    api_source = _read_repo_text(RUST_API_PATH)
    neutron_api_source = _read_repo_text(RUST_NEUTRON_API_PATH)
    try:
        rust_min = _rust_int_const(api_source, "NEUTRON_STATUS_SCHEMA_VERSION_MIN")
        rust_max = _rust_int_const(api_source, "NEUTRON_STATUS_SCHEMA_VERSION_MAX")
        rust_hash = _rust_string_const(api_source, "NEUTRON_STATUS_CONTRACT_HASH")
    except SystemExit as error:
        errors.append(str(error))
    else:
        for name, actual, expected in (
            ("minimum schema version", rust_min, EXPECTED_STATUS_V1_SCHEMA_VERSION),
            ("maximum schema version", rust_max, EXPECTED_STATUS_V1_SCHEMA_VERSION),
            ("contract hash", rust_hash, EXPECTED_STATUS_V1_CONTRACT_HASH),
        ):
            if actual != expected:
                errors.append(
                    "Rust Status V1 %s expected %r, got %r"
                    % (name, expected, actual)
                )

    for vocabulary_name, enum_name in STATUS_V1_RUST_ENUMS:
        expected = vocabulary[vocabulary_name]
        if vocabulary_name == "recovery_causes":
            expected = tuple(value for value in expected if value is not None)
        try:
            actual = _rust_snake_case_unit_enum_values(api_source, enum_name)
        except ValueError as error:
            errors.append(str(error))
            continue
        if actual != expected:
            errors.append(
                "Rust enum %s expected %r, got %r"
                % (enum_name, expected, actual)
            )

    for source_name, source in (
        (RUST_API_PATH, api_source),
        (RUST_NEUTRON_API_PATH, neutron_api_source),
    ):
        try:
            actual = _rust_returned_string_slice(
                source, "rust_status_v1_scenario_ids"
            )
        except ValueError as error:
            errors.append("%s: %s" % (source_name, error))
            continue
        if actual != EXPECTED_RUST_STATUS_V1_PRODUCER_IDS:
            errors.append(
                "%s Rust producer IDs expected %r, got %r"
                % (source_name, EXPECTED_RUST_STATUS_V1_PRODUCER_IDS, actual)
            )

    if not isinstance(scenarios, list):
        errors.append("Status V1 fixture scenarios must be an array")
        scenarios = []
    scenario_ids = []
    minimum_scenarios = []
    for index, scenario in enumerate(scenarios):
        if not isinstance(scenario, dict):
            errors.append("Status V1 scenario %s must be an object" % (index + 1))
            continue
        scenario_ids.append(scenario.get("id"))
        minimum_scenario = scenario.get("minimum_scenario")
        minimum_scenarios.append(minimum_scenario)
        if not _status_v1_exact_integer_matches(minimum_scenario, index + 1):
            errors.append(
                "Status V1 scenario %r minimum_scenario expected exact integer %r, got %r"
                % (scenario.get("id"), index + 1, minimum_scenario)
            )
        errors.extend(_status_v1_scenario_contract_errors(
            scenario,
            vocabulary,
        ))

    if tuple(scenario_ids) != EXPECTED_STATUS_V1_SCENARIO_IDS:
        errors.append(
            "Status V1 scenario IDs expected %r, got %r"
            % (EXPECTED_STATUS_V1_SCENARIO_IDS, tuple(scenario_ids))
        )
    if _status_v1_has_duplicates(scenario_ids):
        errors.append("Status V1 scenario IDs must be unique")
    expected_minimums = tuple(range(1, len(EXPECTED_STATUS_V1_SCENARIO_IDS) + 1))
    if tuple(minimum_scenarios) != expected_minimums:
        errors.append(
            "Status V1 minimum_scenario values expected %r, got %r"
            % (expected_minimums, tuple(minimum_scenarios))
        )

    if errors:
        raise SystemExit(
            "ERROR: Status V1 contract drift:\n- " + "\n- ".join(errors)
        )
    print("Status V1 contract: OK (4 sources, 14 scenarios)")


def check_packaged_ini_contract():
    print("==> checking deploy/kolla/config/neutron-aria-agent.ini")
    sys.path.insert(0, os.path.join(ROOT, "openstack", "neutron_aria"))
    from neutron_aria.agent.config import load_config

    path = os.path.join(ROOT, KOLLA_AGENT_INI_PATH)
    config = load_config(path)
    expected = {
        "managed_domains": ["acl"],
        "ovs_bridge": "br-int",
        "request_timeout": 3.0,
        "acl_source": "disabled",
        "full_resync_enabled": False,
        "port_source": "disabled",
        "rpc_events_enabled": False,
        "incremental_rpc_enabled": False,
    }
    for name, value in expected.items():
        actual = getattr(config, name)
        if actual != value:
            raise SystemExit(
                "ERROR: %s expected %r, got %r in %s"
                % (name, value, actual, KOLLA_AGENT_INI_PATH)
            )

    contents = _read_repo_text(KOLLA_AGENT_INI_PATH)
    if "integration_mode" in contents:
        raise SystemExit("ERROR: packaged ini must not contain integration_mode")
    if "integration_bridge = br-int" not in contents:
        raise SystemExit("ERROR: packaged ini must use [ovs] integration_bridge")
    if any(line.strip() == "bridge = br-int" for line in contents.splitlines()):
        raise SystemExit("ERROR: packaged ini must not use legacy [ovs] bridge")

    datapath_config = _read_repo_text(KOLLA_DATAPATH_CONFIG_PATH)
    if "neutron_socket_mode = 432" not in datapath_config:
        raise SystemExit(
            "ERROR: packaged datapath OpenStack config must set neutron_socket_mode = 432"
        )
    if "neutron_socket_mode = 438" in datapath_config or "0666" in datapath_config:
        raise SystemExit(
            "ERROR: packaged datapath OpenStack config must not document/use a 0666 UDS"
        )
    for term in (
        "neutron_peercred_enforce = false",
        "neutron_peercred_allowed_uids = []",
        "neutron_peercred_allowed_gids = []",
        "neutron_audit_log_path",
    ):
        if term not in datapath_config:
            raise SystemExit(
                "ERROR: packaged datapath OpenStack config missing Neutron UDS peercred setting %r"
                % term
            )


def check_documented_ini_contract():
    print("==> checking documented ini examples")
    forbidden_lines = {
        "integration_mode = coexist",
        "full_resync_interval = 300",
        "acl_source = neutron",
        "local_api = unix:///run/aria/aria-agent.sock",
        "enable_acl = true",
        "enable_qos = true",
        "request_timeout = 5",
        "contract_file = /etc/neutron-aria-agent/neutron-uds-contract.json",
    }
    forbidden_terms = {
        "10485760",
        "`body_max_bytes`：第一阶段固定为 `10485760`",
        "`request_timeout_ms`",
        "`connect_timeout_ms`",
        "`SNAPSHOT_TOO_LARGE`",
        "agent/src/neutron_contract.rs",
        "agent/src/api_handlers/neutron.rs",
        "agent/src/control_plane/neutron_snapshot.rs",
    }
    for path in DOC_INI_CONTRACT_PATHS:
        contents = _read_repo_text(path)
        for term in forbidden_terms:
            if term in contents:
                raise SystemExit(
                    "ERROR: obsolete UDS/INI contract term %r in %s" % (term, path)
                )
        for lineno, line in enumerate(contents.splitlines(), 1):
            stripped = line.strip()
            if stripped in forbidden_lines:
                raise SystemExit(
                    "ERROR: forbidden ini example line %r in %s:%s"
                    % (stripped, path, lineno)
                )


def check_rust_uds_contract_source():
    print("==> checking Rust UDS contract source")
    api_source = _read_repo_text(RUST_API_PATH)
    neutron_api_source = _read_repo_text(RUST_NEUTRON_API_PATH)
    python_uds_source = _read_repo_text(PYTHON_UDS_CLIENT_PATH)
    python_uds_test_source = _read_repo_text(PYTHON_UDS_CLIENT_TEST_PATH)
    with open(os.path.join(ROOT, UDS_CONTRACT_PATH), "r", encoding="utf-8") as handle:
        contract = json.load(handle)

    expected = {
        "api_version": _rust_string_const(api_source, "NEUTRON_UDS_API_VERSION"),
        "contract_version": _rust_string_const(api_source, "NEUTRON_UDS_CONTRACT_VERSION"),
        "schema_version_min": _rust_int_const(api_source, "NEUTRON_UDS_SCHEMA_VERSION_MIN"),
        "schema_version_max": _rust_int_const(api_source, "NEUTRON_UDS_SCHEMA_VERSION_MAX"),
        "attach_authority": _rust_string_const(api_source, "NEUTRON_ATTACH_AUTHORITY"),
        "body_max_bytes": _rust_int_const(api_source, "NEUTRON_UDS_BODY_MAX_BYTES"),
        "timeout_ms": _rust_int_const(api_source, "NEUTRON_UDS_TIMEOUT_MS"),
        "error_codes_hash": _rust_string_const(api_source, "NEUTRON_UDS_ERROR_CODES_HASH"),
        "peer_auth_policy": _rust_string_const(api_source, "NEUTRON_UDS_PEER_AUTH_POLICY"),
        "capability_hash": _rust_string_const(api_source, "NEUTRON_UDS_CAPABILITY_HASH"),
    }
    for key, value in expected.items():
        if contract.get(key) != value:
            raise SystemExit(
                "ERROR: Rust %s expected %r, contract has %r"
                % (key, value, contract.get(key))
            )

    rust_domains = _rust_string_slice_const(api_source, "NEUTRON_SUPPORTED_DOMAINS")
    if contract.get("supported_domains") != rust_domains:
        raise SystemExit(
            "ERROR: Rust supported domains %r do not match contract %r"
            % (rust_domains, contract.get("supported_domains"))
        )

    if "DefaultBodyLimit::max(NEUTRON_UDS_BODY_MAX_BYTES as usize)" not in neutron_api_source:
        raise SystemExit(
            "ERROR: Neutron UDS router must bind DefaultBodyLimit to NEUTRON_UDS_BODY_MAX_BYTES"
        )
    if "UDS_SCHEMA_MISMATCH" not in neutron_api_source:
        raise SystemExit("ERROR: Neutron snapshot schema mismatch must return UDS_SCHEMA_MISMATCH")
    if "UDS_BODY_TOO_LARGE" not in python_uds_source:
        raise SystemExit("ERROR: Python UDS client must map HTTP 413 to UDS_BODY_TOO_LARGE")
    for term in (
        "pub supports_port_scoped_snapshot: bool",
        "supports_port_scoped_snapshot: true",
    ):
        if term not in api_source:
            raise SystemExit("ERROR: Rust capabilities missing P3 scoped term %s" % term)
    for term in (
        "def put_port_snapshot(",
        "local API does not advertise supports_port_scoped_snapshot",
        "def _validate_port_snapshot_request(",
    ):
        if term not in python_uds_source:
            raise SystemExit("ERROR: Python UDS client missing P3 gate term %s" % term)
    service_source = _read_repo_text(os.path.join(
        "openstack",
        "neutron_aria",
        "neutron_aria",
        "agent",
        "service.py",
    ))
    config_source = _read_repo_text(os.path.join(
        "openstack",
        "neutron_aria",
        "neutron_aria",
        "agent",
        "config.py",
    ))
    for term in (
        "incremental_rpc_enabled",
        "apply_port_scoped_snapshot",
        "ACTION_PORT_SCOPED_APPLY",
        "_single_port_incremental_allowed",
        "revisionless_incremental_mode",
        "_revision_allows_incremental",
    ):
        if term not in service_source:
            raise SystemExit("ERROR: service loop missing P3 runtime term %s" % term)
    for term in (
        "incremental_rpc_enabled=true requires [neutron] rpc_events_enabled=true",
        "incremental_rpc_enabled=true requires [agent] full_resync_enabled=true",
        "incremental_rpc_enabled=true requires [neutron] port_source=neutronclient",
        "revisionless_incremental_mode requires [neutron] incremental_rpc_enabled=true",
    ):
        if term not in config_source:
            raise SystemExit("ERROR: config missing P3 runtime gate term %s" % term)
    for test_name in (
        "test_put_port_snapshot_requires_scoped_capability_before_put",
        "test_put_port_snapshot_serializes_when_scoped_capability_is_advertised",
        "test_put_port_snapshot_rejects_path_body_mismatch_before_send",
    ):
        if test_name not in python_uds_test_source:
            raise SystemExit("ERROR: Python UDS client missing P3 gate test %s" % test_name)
    if "generation_hash_conflict" not in neutron_api_source:
        raise SystemExit("ERROR: Neutron snapshot hash conflict must return generation_hash_conflict")
    if "stale_generation" not in neutron_api_source:
        raise SystemExit("ERROR: Neutron stale generation path must report stale_generation")
    if "fn snapshot_schema_supports_absent_or_in_range_only(" not in neutron_api_source:
        raise SystemExit("ERROR: missing Rust snapshot schema range test")

    main_source = _read_repo_text(os.path.join("agent", "src", "main.rs"))
    if "other-user permissions are not allowed" not in main_source:
        raise SystemExit("ERROR: Neutron UDS bind path must reject other-user socket permissions")
    for term in (
        "neutron_peercred_enforce",
        "neutron_peercred_allowed_uids",
        "neutron_peercred_allowed_gids",
        "neutron_audit_log_path",
        "SO_PEERCRED",
        "UDS_PEER_UNAUTHORIZED",
        "UDS_PEERCRED_UNAVAILABLE",
        "neutron_uds_peer_auth",
    ):
        if term not in main_source:
            raise SystemExit("ERROR: Neutron UDS peercred source missing %s" % term)


def check_rust_stage_one_tests_present():
    print("==> checking Rust stage-one test sources")
    projection_tests = (
        ["test", "--locked", "-p", "aria-core", "acl_projection_"],
        ["test", "--locked", "-p", "aria-core", "managed_projection_replay_"],
        ["test", "--locked", "-p", "aria-core", "managed_projection_inventory_"],
        ["test", "--locked", "-p", "aria-agent", "managed_projection_replay_mode_"],
        [
            "test",
            "--locked",
            "-p",
            "aria-agent",
            "managed_projection_inventory_handoff_",
        ],
        ["test", "--locked", "-p", "aria-agent", "managed_projection_health_"],
        ["test", "--locked", "-p", "aria-agent", "managed_acl_shadow_"],
        ["test", "--locked", "-p", "aria-agent", "managed_general_delta_"],
        ["test", "--locked", "-p", "aria-agent", "managed_projection_repair_"],
        [
            "test",
            "--locked",
            "-p",
            "aria-agent",
            "managed_local_group_projection_",
        ],
        ["test", "--locked", "-p", "aria-agent", "managed_dual_use_group_"],
        ["test", "--locked", "-p", "aria-agent", "managed_acl_ownership_"],
        [
            "test",
            "--locked",
            "-p",
            "aria-agent",
            "managed_projection_attach_repair_",
        ],
        [
            "test",
            "--locked",
            "-p",
            "aria-agent",
            "managed_projection_outer_skip_",
        ],
    )
    for projection_test in projection_tests:
        if projection_test not in RUST_TESTS:
            raise SystemExit(
                "ERROR: managed ACL projection Rust test %s is not in Stage 1"
                % projection_test[-1]
            )
    projection_test_sources = (
        (
            _read_repo_text(os.path.join("core", "tests", "acl_projection_contract.rs")),
            "managed_projection_replay_",
            2,
        ),
        (
            _read_repo_text(os.path.join("core", "tests", "acl_projection_contract.rs")),
            "managed_projection_inventory_",
            3,
        ),
        (
            _read_repo_text(os.path.join("agent", "src", "control_plane.rs")),
            "managed_projection_replay_mode_",
            1,
        ),
        (
            _read_repo_text(os.path.join("agent", "src", "control_plane.rs")),
            "managed_projection_inventory_handoff_",
            1,
        ),
        (
            _read_repo_text(os.path.join("agent", "src", "control_plane.rs"))
            + _read_repo_text(os.path.join("agent", "src", "neutron_api.rs")),
            "managed_projection_health_",
            12,
        ),
        (
            _read_repo_text(os.path.join("agent", "src", "control_plane.rs")),
            "managed_acl_shadow_",
            3,
        ),
        (
            _read_repo_text(os.path.join("agent", "src", "control_plane.rs")),
            "managed_general_delta_",
            8,
        ),
        (
            _read_repo_text(os.path.join("agent", "src", "control_plane.rs"))
            + _read_repo_text(os.path.join("agent", "src", "neutron_api.rs")),
            "managed_projection_repair_",
            6,
        ),
        (
            _read_repo_text(os.path.join("agent", "src", "control_plane.rs")),
            "managed_local_group_projection_",
            6,
        ),
        (
            _read_repo_text(os.path.join("agent", "src", "control_plane.rs")),
            "managed_dual_use_group_",
            13,
        ),
        (
            _read_repo_text(os.path.join("agent", "src", "tap_registry.rs")),
            "managed_acl_ownership_",
            6,
        ),
        (
            (
                _read_repo_text(os.path.join("agent", "src", "control_plane.rs")),
                _read_repo_text(os.path.join("agent", "src", "tap_registry.rs")),
                _read_repo_text(os.path.join("agent", "src", "neutron_api.rs")),
            ),
            "managed_projection_attach_repair_",
            2,
        ),
        (
            (
                _read_repo_text(os.path.join("agent", "src", "control_plane.rs")),
                _read_repo_text(os.path.join("agent", "src", "tap_registry.rs")),
                _read_repo_text(os.path.join("agent", "src", "neutron_api.rs")),
            ),
            "managed_projection_outer_skip_",
            2,
        ),
    )
    _run_managed_projection_attach_migration_mutation_self_tests()
    projection_code_cache = {}
    for projection_test_source, prefix, minimum in projection_test_sources:
        sources = (
            projection_test_source
            if isinstance(projection_test_source, tuple)
            else (projection_test_source,)
        )
        count = 0
        for source in sources:
            projection_test_code = projection_code_cache.get(source)
            if projection_test_code is None:
                projection_test_code = _blank_rust_non_code(source)
                projection_code_cache[source] = projection_test_code
            count += len(
                re.findall(
                    r"#\s*\[\s*(?:tokio\s*::\s*)?test\s*\]\s*"
                    r"(?:async\s+)?fn\s+%s" % re.escape(prefix),
                    projection_test_code,
                )
            )
        if count < minimum:
            raise SystemExit(
                "ERROR: Stage 1 Rust filter %s has %d tests, expected at least %d"
                % (prefix, count, minimum)
            )
    _run_rust_function_body_parser_self_tests()
    _run_acl_map_helper_contract_mutation_self_tests()
    _run_acl_delete_semantics_mutation_self_tests()
    _run_owned_acl_release_quarantine_mutation_self_tests()
    _run_managed_acl_shadow_mutation_self_tests()
    _run_managed_projection_path_mutation_self_tests()
    _run_managed_replaced_compensation_mutation_self_tests()
    _run_managed_acl_apply_profile_log_mutation_self_tests()
    _run_managed_cross_domain_group_mutation_self_tests()
    neutron_api_source = _read_repo_text(RUST_NEUTRON_API_PATH)
    wal_source = _read_repo_text(RUST_NEUTRON_WAL_PATH)
    openapi_source = _read_repo_text(RUST_OPENAPI_PATH)
    abi_common_source = _read_repo_text(EBPF_ABI_PATH)
    ebpf_conntrack_source = _read_repo_text(EBPF_CONNTRACK_PATH)
    build_workflow_source = _read_repo_text(BUILD_WORKFLOW_PATH)
    if (
        "python3 ci/check_neutron_stage1.py --require-rust --rust-toolchain stable"
        not in build_workflow_source
    ):
        raise SystemExit("ERROR: hosted Stage 1 Rust entry point is missing")
    control_plane_source = _read_repo_text(os.path.join("agent", "src", "control_plane.rs"))
    instance_source = _read_repo_text(os.path.join("agent", "src", "instance.rs"))
    main_source = _read_repo_text(os.path.join("agent", "src", "main.rs"))
    system_manager_source = _read_repo_text(os.path.join("agent", "src", "system_manager.rs"))
    replay_source = _read_repo_text(os.path.join("core", "src", "ebpf_ops", "replay.rs"))
    inventory_source = _read_repo_text(
        os.path.join("core", "src", "ebpf_ops", "inventory.rs")
    )
    ebpf_ops_source = _read_repo_text(CORE_EBPF_OPS_PATH)
    ebpf_runtime_source = _read_repo_text(CORE_EBPF_RUNTIME_PATH)
    state_source = _read_repo_text(CORE_STATE_PATH)
    network_source = _read_repo_text(CORE_EBPF_NETWORK_PATH)
    policy_source = _read_repo_text(CORE_EBPF_POLICY_PATH)
    tap_registry_source = _read_repo_text(os.path.join("agent", "src", "tap_registry.rs"))

    apply_profile_log_errors = _managed_acl_apply_profile_log_contract_errors(
        neutron_api_source
    )
    if apply_profile_log_errors:
        raise SystemExit("ERROR: " + apply_profile_log_errors[0])

    instance_state_body = _rust_item_body(
        control_plane_source, "struct", "InstanceState"
    )
    if instance_state_body is None or not all(
        re.search(pattern, instance_state_body)
        for pattern in (
            r"\b\w+\s*:\s*ManagedAclPublicationMode\b",
            r"\b\w+\s*:\s*ManagedProjectionHealth\b",
        )
    ):
        raise SystemExit(
            "ERROR: managed ACL lifecycle state must be stored in InstanceState"
        )

    skip_body = _rust_function_body(
        neutron_api_source, "can_skip_neutron_domain_reconcile"
    )
    if skip_body is None or "ManagedProjectionHealth::Verified" not in skip_body:
        raise SystemExit(
            "ERROR: managed ACL reconcile skip must require verified projection health"
        )

    apply_body = _rust_function_body(
        neutron_api_source, "apply_snapshot_runtime_transaction"
    )
    update_index = -1 if apply_body is None else apply_body.find("for port in update")
    update_body = "" if update_index < 0 else apply_body[update_index:]
    attach_index = update_body.find(".attach_neutron")
    health_match = re.search(
        r"\.\s*\w*projection_health\w*\s*\(", update_body
    )
    skip_index = update_body.find("can_skip_neutron_domain_reconcile")
    if (
        attach_index < 0
        or health_match is None
        or skip_index < 0
        or not attach_index < health_match.start() < skip_index
    ):
        raise SystemExit(
            "ERROR: managed update must synchronize ownership and projection health before skip"
        )

    attach_body = _rust_function_body(tap_registry_source, "attach_with_mode")
    iface_lock_index = -1 if attach_body is None else attach_body.find("get_iface_lock")
    iface_guard_match = (
        None
        if attach_body is None or iface_lock_index < 0
        else re.search(
            r"\.\s*lock\s*\(\s*\)\s*\.\s*await\b",
            attach_body[iface_lock_index:],
        )
    )
    iface_guard_index = (
        -1
        if iface_guard_match is None
        else iface_lock_index + iface_guard_match.start()
    )
    lifecycle_lock_index = (
        -1 if attach_body is None else attach_body.find("lock_runtime_lifecycle")
    )
    ownership_reconcile_match = (
        None
        if attach_body is None
        else re.search(
            r"\b(?:promote|reconcile)_managed_acl_ownership_serialized\s*\(",
            attach_body,
        )
    )
    if (
        attach_body is None
        or iface_lock_index < 0
        or iface_guard_index < iface_lock_index
        or lifecycle_lock_index < iface_guard_index
        or "return Ok(())" in attach_body[:iface_lock_index]
        or ownership_reconcile_match is None
        or ownership_reconcile_match.start() < lifecycle_lock_index
    ):
        raise SystemExit(
            "ERROR: idempotent managed attach must serialize ownership reconciliation after iface/lifecycle locks"
        )

    detach_body = _rust_function_body(tap_registry_source, "detach")
    unregister_body = _rust_function_body(control_plane_source, "unregister_instance")
    authority_clear_index = (
        -1
        if unregister_body is None
        else unregister_body.find("clear_neutron_port_authority")
    )
    instance_remove_index = (
        -1 if unregister_body is None else unregister_body.find("instances.remove")
    )
    early_return_index = (
        -1 if unregister_body is None else unregister_body.find("return")
    )
    if (
        detach_body is None
        or re.search(
            r"\bif\s+instance_exists\s*\{\s*self\s*\.\s*control_plane\s*\.\s*unregister_instance\s*\(",
            detach_body,
        )
        or unregister_body is None
        or authority_clear_index < 0
        or instance_remove_index < 0
        or (early_return_index >= 0 and early_return_index < authority_clear_index)
    ):
        raise SystemExit(
            "ERROR: managed detach must clear attach state and ACL authority unconditionally"
        )

    authority_confirmation_body = _rust_function_body(
        control_plane_source, "mark_neutron_port_authority_if_current"
    )
    authority_confirmation_policy_body = _rust_function_body(
        control_plane_source, "managed_neutron_authority_confirmation_allowed"
    )
    if authority_confirmation_body is None or not all(
        marker in authority_confirmation_body
        for marker in (
            "lock_runtime_lifecycle",
            "managed_neutron_authority_confirmation_allowed",
            "mark_neutron_port_authority",
            "required_publication_mode",
        )
    ):
        raise SystemExit(
            "ERROR: Neutron authority publication must revalidate current attach under lifecycle lock"
        )
    if authority_confirmation_policy_body is None or not all(
        marker in authority_confirmation_policy_body
        for marker in (
            "Some(ManagedAclPublicationMode::NeutronAttachOwnedStandaloneAcl)",
            "Some(ManagedAclPublicationMode::ManagedAcl)",
        )
    ):
        raise SystemExit(
            "ERROR: Neutron authority publication must reject standalone-compatible replacement instances"
        )
    update_skip_index = update_body.find("can_skip_neutron_domain_reconcile")
    authority_confirmation_index = update_body.find(
        "mark_neutron_port_authority_if_current"
    )
    if (
        update_skip_index < 0
        or authority_confirmation_index < update_skip_index
        or update_body.count("mark_neutron_port_authority_if_current") < 3
        or re.search(
            r"\.\s*mark_neutron_port_authority\s*\(",
            _blank_rust_non_code(neutron_api_source),
        )
    ):
        raise SystemExit(
            "ERROR: managed apply must confirm current authority after evaluating projection health"
        )
    if "clear_neutron_port_authority" in _blank_rust_non_code(neutron_api_source):
        raise SystemExit(
            "ERROR: Neutron detach must use the registry's serialized authority cleanup"
        )

    projection_path_errors = _managed_projection_path_contract_errors(
        replay_source, inventory_source
    )
    if projection_path_errors:
        raise SystemExit("ERROR: " + projection_path_errors[0])

    for source, function_name, binding in (
        (replay_source, "replay_state_from_snapshot_with_mode", "group_entries"),
        (
            replay_source,
            "replay_state_to_pinned_maps_from_snapshot_with_mode",
            "group_entries",
        ),
        (inventory_source, "validate_pinned_runtime_state_with_mode", "expected_entries"),
    ):
        body = _rust_function_body(source, function_name)
        if body is None or not re.search(
            r"\blet\s+%s\s*=\s*(?:match\s+)?build_runtime_group_map_entries\s*\(\s*state\s*,\s*mode\s*,?\s*\)"
            % re.escape(binding),
            body,
        ):
            raise SystemExit(
                "ERROR: %s must bind the shared runtime group projection builder"
                % function_name
            )
        if source == replay_source:
            writer = (
                "write_fresh_runtime_group_entries"
                if function_name == "replay_state_from_snapshot_with_mode"
                else "write_pinned_runtime_group_entries"
            )
            if writer not in body or "&%s" % binding not in body:
                raise SystemExit(
                    "ERROR: %s must publish the bound projection through %s"
                    % (function_name, writer)
                )
            if "state.groups" in body:
                raise SystemExit(
                    "ERROR: mode-aware replay must not publish groups outside the shared projection"
                )
            if (
                "GroupProjectionMode::StandaloneCompatibility" not in body
                or "collect_standalone_runtime_group_map_entries" not in body
                or "projection_errors" not in body
            ):
                raise SystemExit(
                    "ERROR: mode-aware replay must preserve standalone valid-entry replay when persisted CIDRs are invalid"
                )
        elif "state.groups" in body:
            raise SystemExit(
                "ERROR: mode-aware inventory must not rebuild network expectations directly from groups"
            )

    fresh_writer_body_raw = _rust_function_body_raw(
        replay_source, "write_fresh_runtime_group_entries"
    )
    for field, ipv4_map, ipv6_map, tap_scope in (
        ("general_src", "SRC_IPV4_TRIE", "SRC_IPV6_TRIE", "tap_id"),
        ("general_dst", "DST_IPV4_TRIE", "DST_IPV6_TRIE", "tap_id"),
        ("acl_src", "ACL_SRC_IPV4_TRIE", "ACL_SRC_IPV6_TRIE", "acl_tap_id"),
        ("acl_dst", "ACL_DST_IPV4_TRIE", "ACL_DST_IPV6_TRIE", "acl_tap_id"),
    ):
        if fresh_writer_body_raw is None or not re.search(
            r"write_fresh_group_maps\s*\(\s*bpf\s*,\s*\"%s\"\s*,\s*\"%s\"\s*,\s*%s\s*,\s*&group_entries\.%s"
            % (ipv4_map, ipv6_map, tap_scope, field),
            fresh_writer_body_raw,
        ):
            raise SystemExit(
                "ERROR: fresh replay field %s must publish to %s/%s at %s"
                % (field, ipv4_map, ipv6_map, tap_scope)
            )

    pinned_writer_body_raw = _rust_function_body_raw(
        replay_source, "write_pinned_runtime_group_entries"
    )
    for field, direction, acl in (
        ("general_src", "src", "false"),
        ("general_dst", "dst", "false"),
        ("acl_src", "src", "true"),
        ("acl_dst", "dst", "true"),
    ):
        if pinned_writer_body_raw is None or not re.search(
            r"write_pinned_group_entries\s*\(\s*runtime\s*,\s*&group_entries\.%s\s*,\s*\"%s\"\s*,\s*%s"
            % (field, direction, acl),
            pinned_writer_body_raw,
        ):
            raise SystemExit(
                "ERROR: pinned replay field %s must publish direction=%s acl=%s"
                % (field, direction, acl)
            )
    for source, function_name, delegate, mode in (
        (
            replay_source,
            "replay_state_from_snapshot",
            "replay_state_from_snapshot_with_mode",
            "GroupProjectionMode::StandaloneCompatibility",
        ),
        (
            replay_source,
            "replay_state_to_pinned_maps",
            "replay_state_to_pinned_maps_from_snapshot_with_mode",
            "GroupProjectionMode::StandaloneCompatibility",
        ),
        (
            replay_source,
            "replay_managed_state_to_pinned_maps",
            "replay_state_to_pinned_maps_from_snapshot_with_mode",
            "GroupProjectionMode::Managed",
        ),
        (
            inventory_source,
            "validate_pinned_runtime_state",
            "validate_pinned_runtime_state_with_mode",
            "GroupProjectionMode::StandaloneCompatibility",
        ),
        (
            inventory_source,
            "validate_managed_pinned_runtime_state",
            "validate_pinned_runtime_state_with_mode",
            "GroupProjectionMode::Managed",
        ),
    ):
        body = _rust_function_body(source, function_name)
        if body is None or not re.search(
            r"\b%s\s*\([^;{}]*%s\s*,?\s*\)" % (re.escape(delegate), re.escape(mode)),
            body,
        ):
            raise SystemExit(
                "ERROR: %s must delegate through %s with %s"
                % (function_name, delegate, mode)
            )

    inventory_mode_body = _rust_function_body(
        inventory_source, "validate_pinned_runtime_state_with_mode"
    )
    for required_call in (
        "capture_runtime_group_map_entries",
        "validate_strict_pinned_runtime_state",
        "classify_managed_inventory_capture",
    ):
        if inventory_mode_body is None or required_call not in inventory_mode_body:
            raise SystemExit(
                "ERROR: mode-aware inventory must preserve %s" % required_call
            )
    strict_index = inventory_mode_body.find("validate_strict_pinned_runtime_state")
    classify_index = inventory_mode_body.find("classify_managed_inventory_capture")
    if strict_index < 0 or classify_index < 0 or strict_index > classify_index:
        raise SystemExit(
            "ERROR: strict non-projection inventory must be captured before drift classification"
        )
    if not re.search(
        r"\blet\s+strict_result\s*=\s*validate_strict_pinned_runtime_state\s*\(",
        inventory_mode_body,
    ) or not re.search(
        r"\bclassify_managed_inventory_capture\s*\(\s*state\s*,\s*&captured\s*,\s*strict_result\s*,?\s*\)",
        inventory_mode_body,
    ):
        raise SystemExit(
            "ERROR: mode-aware inventory must pass the real strict result into drift classification"
        )
    for mode, classifier, arguments in (
        (
            "GroupProjectionMode::StandaloneCompatibility",
            "classify_standalone_inventory_capture",
            r"&captured\s*,\s*&expected_entries\s*,\s*strict_result",
        ),
        (
            "GroupProjectionMode::Managed",
            "classify_managed_inventory_capture",
            r"state\s*,\s*&captured\s*,\s*strict_result",
        ),
    ):
        if not re.search(
            r"\b%s\s*=>\s*\{?\s*%s\s*\(\s*%s\s*,?\s*\)\s*\}?"
            % (re.escape(mode), classifier, arguments),
            inventory_mode_body,
        ):
            raise SystemExit(
                "ERROR: inventory mode %s must select %s" % (mode, classifier)
            )

    standalone_classifier_body = _rust_function_body(
        inventory_source, "classify_standalone_inventory_capture"
    )
    for field in ("general_src", "general_dst", "acl_src", "acl_dst"):
        if (
            standalone_classifier_body is None
            or "expected_entries.%s" % field not in standalone_classifier_body
            or "captured.%s" % field not in standalone_classifier_body
        ):
            raise SystemExit(
                "ERROR: standalone inventory must compare expected and captured field %s"
                % field
            )
    if standalone_classifier_body is None or "strict_result" not in standalone_classifier_body:
        raise SystemExit(
            "ERROR: standalone inventory must preserve strict validation failures"
        )

    capture_inventory_body = _rust_function_body(
        inventory_source, "capture_runtime_group_map_entries"
    )
    capture_inventory_body_raw = _rust_function_body_raw(
        inventory_source, "capture_runtime_group_map_entries"
    )
    if (
        capture_inventory_body is None
        or "actual_tap_config.acl_active_bank" not in capture_inventory_body
        or "ACL_BANK_SHADOW" not in capture_inventory_body
        or "normalize_acl_bank" in capture_inventory_body
    ):
        raise SystemExit(
            "ERROR: runtime projection capture must reject invalid raw ACL bank values"
        )
    if not re.search(
        r"\blet\s+active_acl_lpm_tap_id\s*=\s*acl_banked_tap_id\s*\(\s*tap_id\s*,\s*actual_tap_config\.acl_active_bank\s*,?\s*\)",
        capture_inventory_body,
    ):
        raise SystemExit(
            "ERROR: runtime projection capture must scope ACL reads to the active bank"
        )
    for field, ipv4_map, ipv6_map, tap_scope in (
        ("general_src", "SRC_IPV4_TRIE", "SRC_IPV6_TRIE", "tap_id"),
        ("general_dst", "DST_IPV4_TRIE", "DST_IPV6_TRIE", "tap_id"),
        (
            "acl_src",
            "ACL_SRC_IPV4_TRIE",
            "ACL_SRC_IPV6_TRIE",
            "active_acl_lpm_tap_id",
        ),
        (
            "acl_dst",
            "ACL_DST_IPV4_TRIE",
            "ACL_DST_IPV6_TRIE",
            "active_acl_lpm_tap_id",
        ),
    ):
        if capture_inventory_body_raw is None or not re.search(
            r"\b%s\s*:\s*collect_runtime_network_entries\s*\(\s*pin_path\s*,\s*\"%s\"\s*,\s*\"%s\"\s*,\s*%s\s*,?\s*\)"
            % (field, ipv4_map, ipv6_map, tap_scope),
            capture_inventory_body_raw,
        ):
            raise SystemExit(
                "ERROR: runtime projection field %s must read %s and %s at %s"
                % (field, ipv4_map, ipv6_map, tap_scope)
            )

    strict_inventory_body = _rust_function_body(
        inventory_source, "validate_strict_pinned_runtime_state"
    )
    for required_call in (
        "open_pinned_tap_config",
        "classify_runtime_gate_state",
        "acl_active_bank",
        "acl_ingress_hook",
        "open_pinned_policy_table",
        "open_pinned_port_pool",
        "list_qos_rules",
        "list_mirror_rules",
        "list_global_mirrors",
    ):
        if strict_inventory_body is None or required_call not in strict_inventory_body:
            raise SystemExit(
                "ERROR: strict runtime inventory must validate %s" % required_call
            )
    if not re.search(
        r"actual_tap_config\.acl_active_bank\s*>\s*ACL_BANK_SHADOW",
        strict_inventory_body or "",
    ) or not re.search(
        r"actual_tap_config\.acl_ingress_hook\s*!=\s*expected_tap_config\.acl_ingress_hook",
        strict_inventory_body or "",
    ):
        raise SystemExit(
            "ERROR: strict TAP_CONFIG inventory must reject invalid bank and ingress-hook drift"
        )
    strict_inventory_body_raw = _rust_function_body_raw(
        inventory_source, "validate_strict_pinned_runtime_state"
    )
    for map_name, expected, actual in (
        ("POLICY_TABLE", "expected_policy", "actual_policy"),
        ("PORT_BITMAP_POOL", "expected_ports", "actual_ports"),
        ("QOS_CONFIG", "expected_qos", "actual_qos"),
        ("MIRROR_POLICY", "expected_policy_mirror", "actual_policy_mirror"),
        ("MIRROR_GLOBAL", "expected_global_mirror", "actual_global_mirror"),
    ):
        if strict_inventory_body_raw is None or not re.search(
            r"validate_entry_set\s*\(\s*\"%s\"\s*,[\s\S]{0,240}?\b%s\s*,\s*%s\s*,?\s*\)\s*\?"
            % (map_name, expected, actual),
            strict_inventory_body_raw,
        ):
            raise SystemExit(
                "ERROR: strict runtime inventory must propagate %s comparison" % map_name
            )

    validate_live_body = _rust_function_body(
        control_plane_source, "validate_preexisting_live_runtime"
    )
    if (
        validate_live_body is None
        or "validate_managed_pinned_runtime_state" not in validate_live_body
        or "validate_pinned_runtime_state" not in validate_live_body
    ):
        raise SystemExit(
            "ERROR: preexisting runtime validation must preserve standalone and managed inventory"
        )
    validate_live_code = _blank_rust_non_code(validate_live_body or "")
    if "classify_runtime_gate_state" not in validate_live_code:
        raise SystemExit(
            "ERROR: preexisting runtime validation must classify desired versus managed-quiesced gate"
        )
    if not re.search(r"\bmatch\s+projection_mode\b", validate_live_code):
        raise SystemExit(
            "ERROR: preexisting runtime inventory must select validator by projection mode"
        )
    for mode, validator in (
        (
            "GroupProjectionMode::StandaloneCompatibility",
            "validate_pinned_runtime_state",
        ),
        (
            "GroupProjectionMode::Managed",
            "validate_managed_pinned_runtime_state",
        ),
    ):
        if not re.search(
            r"\b%s\s*=>\s*\{?\s*%s\s*\(" % (re.escape(mode), validator),
            validate_live_code,
        ):
            raise SystemExit(
                "ERROR: projection mode %s must select %s" % (mode, validator)
            )
    validation_steps = (
        "preexisting_tc_acl_runtime_is_healthy",
        "read_iface_ctx",
        "read_runtime_config",
        "validate_managed_pinned_runtime_state",
    )
    validation_positions = [validate_live_body.find(step) for step in validation_steps]
    if any(position < 0 for position in validation_positions) or validation_positions != sorted(
        validation_positions
    ):
        raise SystemExit(
            "ERROR: preexisting runtime validation order must be tc-link, iface, config, inventory"
        )
    prepare_managed_body = _rust_function_body(
        control_plane_source, "prepare_managed_registration"
    )
    for replay_entrypoint in (
        "replay_state_to_pinned_maps",
        "replay_managed_state_to_pinned_maps",
    ):
        if prepare_managed_body is None or replay_entrypoint not in prepare_managed_body:
            raise SystemExit(
                "ERROR: managed registration must select replay entry point %s"
                % replay_entrypoint
            )
    prepare_managed_code = _blank_rust_non_code(prepare_managed_body or "")
    if not re.search(
        r"\blet\s+projection_mode\s*=\s*managed_group_projection_mode\s*\(\s*mode\s*\)",
        prepare_managed_code,
    ) or not re.search(
        r"\bmatch\s+projection_mode\b",
        prepare_managed_code,
    ):
        raise SystemExit(
            "ERROR: managed registration must select replay through attach-mode projection mapping"
        )
    if not re.search(
        r"\bvalidate_preexisting_live_runtime\s*\([\s\S]*?projection_mode\s*,?\s*\)",
        prepare_managed_code,
    ):
        raise SystemExit(
            "ERROR: preexisting runtime validation must receive the selected projection mode"
        )
    if not re.search(
        r"\blet\s+preexisting_validation\s*=\s*self\.validate_preexisting_live_runtime\s*\([\s\S]*?projection_mode\s*,?\s*\)",
        prepare_managed_code,
    ) or not re.search(
        r"\blet\s+gate_disposition\s*=\s*preexisting_validation\.gate_disposition\s*;",
        prepare_managed_code,
    ) or not re.search(
        r"\blet\s+projection_drift\s*=\s*preexisting_validation\.projection_drift\s*;",
        prepare_managed_code,
    ) or not re.search(
        r"\bpreexisting_live_verified\s*=\s*match\s+preexisting_projection_verification\s*\(\s*projection_drift\s*\)",
        prepare_managed_code,
    ) or not re.search(
        r"gate_disposition\s*==\s*Some\s*\(\s*RuntimeGateDisposition::Desired\s*\)",
        prepare_managed_code,
    ):
        raise SystemExit(
            "ERROR: managed registration must preserve structured inventory into verification"
        )
    if not re.search(
        r"managed_runtime_activation\s*\(\s*mode\s*,\s*preexisting_live_verified\s*,",
        prepare_managed_code,
    ):
        raise SystemExit(
            "ERROR: managed activation must consume structured preexisting verification"
        )
    for mode, replay_entrypoint in (
        (
            "GroupProjectionMode::StandaloneCompatibility",
            "replay_state_to_pinned_maps",
        ),
        ("GroupProjectionMode::Managed", "replay_managed_state_to_pinned_maps"),
    ):
        if not re.search(
            r"\b%s\s*=>\s*\{?\s*%s\s*\(" % (re.escape(mode), replay_entrypoint),
            prepare_managed_code,
        ):
            raise SystemExit(
                "ERROR: projection mode %s must select %s" % (mode, replay_entrypoint)
            )

    for term in (
        "const TC_ACL_HEALTH_INTERVAL_SECS: u64 = 10;",
        "MissedTickBehavior::Skip",
        "reconcile_tc_acl_health().await",
        "tc_acl_health_task.abort()",
    ):
        if term not in main_source:
            raise SystemExit("ERROR: TC ACL health loop missing %s" % term)

    for term in (
        "tc_acl_link_lost",
        "runtime_degraded",
        "effective_action",
        "bypass",
        "fn project_tc_acl_link_loss(",
        "append_snapshot_commit(next_runtime.to_wal_state())",
    ):
        if term not in neutron_api_source:
            raise SystemExit("ERROR: Neutron TC health status missing %s" % term)

    health_projection_body = _rust_function_body(
        neutron_api_source, "project_tc_acl_health"
    )
    if health_projection_body is None:
        raise SystemExit("ERROR: Neutron TC health projection function missing")
    health_projection_lock = health_projection_body.find("self.apply_lock.lock().await")
    health_projection_snapshot = health_projection_body.find(
        "self.control_plane.list_instance_runtime_health().await"
    )
    if (
        health_projection_lock < 0
        or health_projection_snapshot < 0
        or health_projection_snapshot < health_projection_lock
    ):
        raise SystemExit(
            "ERROR: Neutron TC health snapshot must be read under apply_lock"
        )

    for term in (
        "runtime_health: RuntimeHealthState",
        "pub async fn reconcile_tc_acl_health(&self)",
        "acl_quiesce_failed:",
        "recovery_required",
        "allow_recovery_publication",
        "tc_acl_full_resync_required",
    ):
        if term not in control_plane_source:
            raise SystemExit("ERROR: TC ACL runtime health contract missing %s" % term)

    for term in (
        "SchedClassifier::from_pin",
        "SchedClassifier::query_tcx",
        "PinnedLink::from_pin",
        "SchedClassifierLink",
        "tcx_query_contains_expected_program",
        "tcx_attachment_query_requires_the_expected_program_id",
        "preexisting_tc_acl_runtime_is_healthy",
        "preexisting_acl_runtime_requires_exact_dual_tcx_identity",
    ):
        if term not in instance_source:
            raise SystemExit("ERROR: live TCX attachment health contract missing %s" % term)

    for term in (
        "fn required_firewall_config(",
        "global_runtime_partial_update_requires_an_existing_config",
        "global_runtime_full_initialization_only_accepts_key_not_found",
        "let global = read_firewall_config(runtime)?;",
    ):
        if term not in ebpf_runtime_source:
            raise SystemExit("ERROR: strict FIREWALL_CONFIG read contract missing %s" % term)
    update_firewall_body = _rust_function_body(
        ebpf_runtime_source, "update_firewall_config"
    )
    if update_firewall_body is None or ".get(&0u32, 0).ok()" in update_firewall_body:
        raise SystemExit(
            "ERROR: FIREWALL_CONFIG partial update must propagate map read failures"
        )

    for term in (
        "CT_FLAG_ACL_EVALUATED",
        "ct_acl_cache_is_current",
        "tc_ct_cache_requires_acl_evaluation_when_acl_turns_on",
    ):
        if term not in abi_common_source:
            raise SystemExit("ERROR: CT-only to ACL enable guard missing %s" % term)
    if ebpf_conntrack_source.count("ct_acl_cache_is_current(") != 4:
        raise SystemExit(
            "ERROR: IPv4/IPv6 forward/reverse CT lookups must reject entries not evaluated by ACL"
        )

    tc_health_candidate_body = _rust_function_body(
        control_plane_source, "reconcile_tc_acl_health_candidate"
    )
    if tc_health_candidate_body is None:
        raise SystemExit("ERROR: per-candidate TC ACL health reconcile function missing")
    candidate_contract = (
        "self.lock_runtime_lifecycle().await",
        "self.instances.read().await",
        "Arc::ptr_eq",
        "if !is_current",
        "instance.write().await",
    )
    candidate_positions = [
        tc_health_candidate_body.find(term) for term in candidate_contract
    ]
    if any(position < 0 for position in candidate_positions) or candidate_positions != sorted(
        candidate_positions
    ):
        raise SystemExit(
            "ERROR: TC health candidate must lock lifecycle, validate current Arc, skip stale handles, then lock instance"
        )
    desired_position = tc_health_candidate_body.find("let desired_enforcement")
    xdp_only_position = tc_health_candidate_body.find("runtime_xdp_health_locked")
    full_health_position = tc_health_candidate_body.find("runtime_link_health_locked")
    if (
        desired_position < 0
        or xdp_only_position < 0
        or full_health_position < 0
        or not desired_position < xdp_only_position < full_health_position
    ):
        raise SystemExit(
            "ERROR: disabled TC health reconcile must read desired state and use XDP-only health before any TCX query"
        )

    projection_guard_body = _rust_function_body_raw(
        neutron_api_source, "neutron_tc_health_projection_blocked"
    )
    if projection_guard_body is None:
        raise SystemExit("ERROR: structured Neutron TC health projection guard missing")
    for term in (
        "pending_generation.is_some()",
        '"blocked_recovery_required"',
        '"recovered_pending_full_resync_required"',
        '"recovered_pending_full_resync"',
        '"wal_recovery_commit_failed"',
        '"pending_recovery_commit_failed"',
        '"runtime_reconcile_requires_full_resync"',
    ):
        if term not in projection_guard_body:
            raise SystemExit(
                "ERROR: structured Neutron TC health projection guard missing %s" % term
            )
    projection_body = _rust_function_body(neutron_api_source, "project_tc_acl_link_loss")
    projection_guard = (projection_body or "").find(
        "neutron_tc_health_projection_blocked(runtime)"
    )
    projection_inventory = (projection_body or "").find("health_by_instance")
    if (
        projection_guard < 0
        or projection_inventory < 0
        or projection_guard > projection_inventory
    ):
        raise SystemExit(
            "ERROR: structured recovery guard must precede Neutron TC health projection work"
        )

    neutron_router_body = _rust_function_body(neutron_api_source, "build_router")
    for term in (
        "struct NeutronRouterRuntime",
        "struct NeutronBackgroundTasks",
        "restore_task",
        "health_task",
        "fn abort(self)",
    ):
        if term not in neutron_api_source:
            raise SystemExit("ERROR: Neutron background task ownership missing %s" % term)
    if neutron_router_body is None or "NeutronRouterRuntime" not in neutron_router_body:
        raise SystemExit("ERROR: Neutron router must return owned background task handles")
    for term in (
        "restore_task.abort()",
        "health_task.abort()",
        "restore_task.await",
        "health_task.await",
        "background.abort().await",
    ):
        source = (
            main_source if term == "background.abort().await" else neutron_api_source
        )
        if term not in source:
            raise SystemExit("ERROR: Neutron shutdown ownership missing %s" % term)

    apply_scope_body = _rust_function_body(
        neutron_api_source, "apply_neutron_snapshot_for_scope"
    )
    if apply_scope_body is None:
        raise SystemExit("ERROR: Neutron snapshot apply function missing")
    if ".mark_tc_acl_runtime_ready(" in apply_scope_body:
        raise SystemExit(
            "ERROR: FullHost readiness must be committed by the serialized gate publication, not after global WAL commit"
        )

    helper_contracts = (
        (network_source, "add_network_impl", ("open_pinned_lpm_v4", "open_pinned_lpm_v6")),
        (
            network_source,
            "delete_network_impl",
            ("open_pinned_lpm_v4", "open_pinned_lpm_v6"),
        ),
        (
            policy_source,
            "add_policy_in_bank",
            ("open_pinned_port_pool", "open_pinned_policy_table"),
        ),
        (policy_source, "delete_policy_in_bank", ("open_pinned_policy_table",)),
        (policy_source, "delete_port_set", ("open_pinned_port_pool",)),
    )
    helper_errors = []
    for source, function_name, required_openers in helper_contracts:
        helper_errors.extend(
            _acl_map_helper_contract_errors(source, function_name, required_openers)
        )
    if helper_errors:
        raise SystemExit("ERROR: " + "; ".join(helper_errors))

    delete_semantics_contracts = (
        (network_source, "delete_network_impl", "classify_map_delete"),
        (policy_source, "delete_policy_in_bank", "classify_map_delete"),
        (policy_source, "delete_port_set", "execute_map_delete_batch"),
        (policy_source, "add_policy_in_bank", "cleanup_error"),
        (
            control_plane_source,
            "add_group_standalone_locked",
            "cleanup_error",
        ),
    )
    delete_semantics_errors = []
    for source, function_name, required_seam in delete_semantics_contracts:
        delete_semantics_errors.extend(
            _acl_delete_semantics_contract_errors(
                source, function_name, required_seam
            )
        )
    if delete_semantics_errors:
        raise SystemExit("ERROR: " + "; ".join(delete_semantics_errors))

    release_quarantine_errors = _owned_acl_release_quarantine_contract_errors(
        control_plane_source
    )
    if release_quarantine_errors:
        raise SystemExit("ERROR: " + "; ".join(release_quarantine_errors))

    for term in (
        "Err(aya::maps::MapError::KeyNotFound)",
        "fn execute_map_delete_batch",
        "map_delete_classifier_only_treats_key_not_found_as_idempotent_success",
        "map_delete_batch_attempts_every_key_and_aggregates_non_missing_errors",
    ):
        if term not in ebpf_ops_source:
            raise SystemExit("ERROR: exact ACL map delete seam missing %s" % term)

    for term in (
        "BITMAP_QUARANTINE_PREFIX",
        "pub fn quarantine_bitmap_index",
        "pub fn release_quarantined_bitmap_index",
        "pub fn is_bitmap_index_quarantined",
        "quarantined_bitmap_survives_restart_and_is_not_reused",
        "quarantined_fresh_bitmap_advances_next_cursor_across_restart",
        "confirmed_bitmap_cleanup_releases_only_the_successful_quarantine",
    ):
        if term not in state_source:
            raise SystemExit("ERROR: durable bitmap quarantine contract missing %s" % term)

    for term in (
        "struct PortSetCleanupFailure",
        "struct PortSetCleanupReport",
        "persist transaction-created bitmap quarantine before ACL staging",
        "released port set remains durably quarantined after cleanup failure",
        "standalone_review_failed_cleanup_quarantine_survives_retry_and_restart",
        "standalone_review_rollback_recovery_persists_only_failed_cleanup_quarantine",
    ):
        if term not in control_plane_source:
            raise SystemExit("ERROR: owned ACL cleanup quarantine contract missing %s" % term)

    replace_owned_acl_body = _rust_function_body(control_plane_source, "replace_owned_acl")
    if replace_owned_acl_body is None:
        raise SystemExit("ERROR: replace_owned_acl source missing")
    publication_body = _rust_function_body(
        control_plane_source, "publish_acl_projection_locked"
    )
    if publication_body is None:
        raise SystemExit("ERROR: publish_acl_projection_locked source missing")
    guard_compact = re.search(
        r"compact_and_publish_state\s*\(\s*allocator_guard_state\s*\)",
        publication_body,
    )
    first_kernel_mutation = publication_body.find("apply_shared_network_mutation")
    durable_final_compact = re.search(
        r"compact_and_publish_state\s*\(\s*durable_final_state\s*\)",
        publication_body,
    )
    publication_call = replace_owned_acl_body.find(".publish_acl_projection_locked(")
    released_cleanup = replace_owned_acl_body.find("released_cleanup_targets")
    if (
        guard_compact is None
        or first_kernel_mutation < 0
        or guard_compact.start() > first_kernel_mutation
    ):
        raise SystemExit(
            "ERROR: created bitmap quarantine must be durable before owned ACL kernel mutation"
        )
    if (
        durable_final_compact is None
        or publication_call < 0
        or released_cleanup < publication_call
    ):
        raise SystemExit(
            "ERROR: released bitmap quarantine must be durable before cleanup"
        )

    required_wal_tests = [
        "replay_reports_intent_without_commit",
        "replay_delete_intent_without_commit_preserves_committed_state",
        "replay_snapshot_intent_without_commit_preserves_previous_commit",
        "replay_snapshot_intent_after_domain_half_apply_preserves_committed_runtime",
        "snapshot_intent_records_affected_domains",
        "commit_records_status_hash",
        "delete_commit_records_status_hash",
        "replay_rejects_commit_with_mismatched_status_hash",
        "replay_skips_tampered_latest_commit_and_keeps_previous_good_commit",
    ]
    for test_name in required_wal_tests:
        if "fn %s(" % test_name not in wal_source:
            raise SystemExit("ERROR: missing Rust WAL test %s" % test_name)

    required_wal_terms = [
        "intent_without_commit",
        "affected_domains",
        "status_hash",
        "replayed_with_errors",
    ]
    for term in required_wal_terms:
        if term not in wal_source:
            raise SystemExit("ERROR: Rust WAL tests/source missing %s" % term)

    required_recovery_terms = [
        'fault_injection::check("neutron.snapshot.after_intent")',
        'fault_injection::check("neutron.snapshot.before_commit")',
        'fault_injection::check("neutron.snapshot.after_commit")',
        'fault_injection::check("neutron.delete.after_intent")',
        'fault_injection::check("neutron.delete.after_detach_before_commit")',
        "recover_incomplete_wal_intent",
        "wal_intent_recovered_pending_full_resync",
        "intent_recovery_blocked",
    ]
    for term in required_recovery_terms:
        if term not in neutron_api_source:
            raise SystemExit("ERROR: Rust snapshot recovery source missing %s" % term)

    recovery_attach_body = _rust_function_body(neutron_api_source, "recover_intent_port")
    snapshot_attach_body = _rust_function_body(
        neutron_api_source, "apply_snapshot_runtime_transaction"
    )
    committed_runtime_body = _rust_function_body(
        neutron_api_source, "reconcile_committed_runtime"
    )
    if recovery_attach_body is None or not re.search(
        r"\blet\s+acl_managed\s*=\s*domains\s*\.\s*iter\s*\(\s*\)\s*\.\s*any\s*\(\s*\|\s*domain\s*\|\s*domain\s*==\s*[^;]+\s*\)\s*;",
        recovery_attach_body,
    ):
        raise SystemExit("ERROR: WAL recovery must derive Neutron ACL attach authority")
    if recovery_attach_body is None or not re.search(
        r"self\s*\.\s*registry\s*\.\s*attach_neutron\s*\(\s*&\s*port\s*\.\s*ifname\s*,\s*acl_managed\s*\)\s*\.\s*await",
        recovery_attach_body,
    ):
        raise SystemExit("ERROR: WAL recovery must use Neutron attach mode")
    if snapshot_attach_body is None or not re.search(
        r"state\s*\.\s*registry\s*\.\s*attach_neutron\s*\(\s*&\s*port\s*\.\s*ifname\s*,\s*port_manages_acl\s*\(\s*port\s*\)\s*\)\s*\.\s*await",
        snapshot_attach_body,
    ):
        raise SystemExit("ERROR: snapshot attach must use Neutron ACL authority")
    if committed_runtime_body is None or not re.search(
        r"self\s*\.\s*registry\s*\.\s*reconcile_neutron_runtime\s*\(\s*&\s*committed_ifaces\s*\)\s*\.\s*await",
        committed_runtime_body,
    ):
        raise SystemExit("ERROR: committed runtime recovery must use registry reconciliation")

    required_acl_conntrack_terms = [
        "fn neutron_acl_translator_carries_conntrack_intent(",
        "fn neutron_acl_runtime_transition_is_atomic(",
        "acl_runtime_transition(&plan, preserved_conntrack_enabled)",
        "transition.quiesce.conntrack_enabled",
        "transition.publish.conntrack_enabled",
        "acl_ingress_hook: aria_core::common::ACL_INGRESS_HOOK_TC",
    ]
    for term in required_acl_conntrack_terms:
        if term not in neutron_api_source:
            raise SystemExit("ERROR: Rust ACL conntrack contract missing %s" % term)

    acl_reconcile_start = neutron_api_source.find("async fn reconcile_neutron_acl(")
    acl_reconcile_end = neutron_api_source.find(
        "\n#[allow(dead_code)]\nfn build_snapshot_plan(", acl_reconcile_start
    )
    if acl_reconcile_start < 0 or acl_reconcile_end < 0:
        raise SystemExit("ERROR: Rust Neutron ACL reconcile source not found")
    acl_reconcile_body = neutron_api_source[acl_reconcile_start:acl_reconcile_end]
    readiness = acl_reconcile_body.find(".require_tc_acl_ready(&port.ifname)")
    first_gate_write = acl_reconcile_body.find(".update_neutron_acl_runtime_gate(")
    if readiness < 0 or first_gate_write < 0 or readiness > first_gate_write:
        raise SystemExit(
            "ERROR: Neutron TC ACL readiness must be checked before quiesce"
        )
    target_tc_requirement = acl_reconcile_body.find(
        "let require_tc_acl_links = acl_runtime_feature_requires_tc(transition.publish);"
    )
    target_tc_guard = acl_reconcile_body.find(
        "if require_tc_acl_links {", target_tc_requirement
    )
    if not (
        0 <= target_tc_requirement < target_tc_guard < readiness < first_gate_write
    ):
        raise SystemExit(
            "ERROR: Neutron TC ACL readiness must follow the target publish state"
        )
    if ".update_config(" in acl_reconcile_body:
        raise SystemExit(
            "ERROR: Neutron ACL gate writes must use update_neutron_acl_runtime_gate"
        )
    if acl_reconcile_body.count(".update_neutron_acl_runtime_gate(") != 2:
        raise SystemExit(
            "ERROR: Neutron ACL quiesce and shared publication must use atomic gate writes"
        )

    requiesce_body = _rust_function_body(
        neutron_api_source, "requiesce_managed_acl_runtime_gate"
    )
    if (
        requiesce_body is None
        or requiesce_body.count(".update_neutron_acl_runtime_gate(") != 1
        or not re.search(
            r"\.\s*update_neutron_acl_runtime_gate\s*\(\s*"
            r"ifname\s*,\s*false\s*,\s*false\s*,\s*false\s*\)",
            requiesce_body,
        )
    ):
        raise SystemExit(
            "ERROR: Neutron ACL shared compensation must atomically requiesce both gates"
        )

    neutron_api_code = _blank_rust_non_code(neutron_api_source)
    if re.search(
        r"state\s*\.\s*control_plane\s*\.\s*update_neutron_acl_runtime_gate\s*\(",
        neutron_api_code,
    ):
        raise SystemExit(
            "ERROR: Neutron ACL gate writes must use TapRegistry lifecycle serialization"
        )
    registry_gate_calls = re.findall(
        r"state\s*\.\s*registry\s*\.\s*update_neutron_acl_runtime_gate\s*\(",
        neutron_api_code,
    )
    if len(registry_gate_calls) != 3:
        raise SystemExit(
            "ERROR: all Neutron ACL gate writes must use TapRegistry lifecycle serialization"
        )

    registry_gate_body = _rust_function_body(
        tap_registry_source, "update_neutron_acl_runtime_gate"
    )
    if registry_gate_body is None:
        raise SystemExit("ERROR: TapRegistry serialized ACL gate writer missing")
    lifecycle_lock = re.search(
        r"let\s+_runtime_guard\s*=\s*self\s*\.\s*control_plane\s*\.\s*lock_runtime_lifecycle\s*\(\s*\)\s*\.\s*await\s*;",
        registry_gate_body,
    )
    serialized_call = re.search(
        r"self\s*\.\s*control_plane\s*\.\s*update_neutron_acl_runtime_gate_serialized\s*\(",
        registry_gate_body,
    )
    if (
        lifecycle_lock is None
        or serialized_call is None
        or lifecycle_lock.end() > serialized_call.start()
        or re.search(
            r"drop\s*\(\s*_runtime_guard\s*\)",
            registry_gate_body[lifecycle_lock.end():serialized_call.start()],
        )
    ):
        raise SystemExit(
            "ERROR: TapRegistry ACL gate writer must hold the shared lifecycle lock across the serialized control-plane call"
        )

    for lifecycle_function in ("attach_with_mode", "detach"):
        lifecycle_body = _rust_function_body(tap_registry_source, lifecycle_function)
        if lifecycle_body is None or not re.search(
            r"self\s*\.\s*control_plane\s*\.\s*lock_runtime_lifecycle\s*\(\s*\)\s*\.\s*await",
            lifecycle_body,
        ):
            raise SystemExit(
                "ERROR: managed lifecycle function %s must use shared lifecycle lock"
                % lifecycle_function
            )
    reconcile_runtime_body = _rust_function_body(
        tap_registry_source, "reconcile_neutron_runtime"
    )
    orphan_lock = re.search(
        r"let\s+_runtime_guard\s*=\s*self\s*\.\s*control_plane\s*\.\s*lock_runtime_lifecycle\s*\(\s*\)\s*\.\s*await\s*;",
        reconcile_runtime_body or "",
    )
    orphan_remove = re.search(
        r"self\s*\.\s*remove_orphaned_managed_link_pins\s*\(",
        reconcile_runtime_body or "",
    )
    if (
        orphan_lock is None
        or orphan_remove is None
        or orphan_lock.end() > orphan_remove.start()
        or re.search(
            r"drop\s*\(\s*_runtime_guard\s*\)",
            (reconcile_runtime_body or "")[orphan_lock.end():orphan_remove.start()],
        )
    ):
        raise SystemExit(
            "ERROR: orphaned managed link removal must use shared lifecycle lock"
        )

    serialized_gate_body = _rust_function_body(
        control_plane_source, "update_neutron_acl_runtime_gate_serialized"
    )
    if serialized_gate_body is None:
        raise SystemExit("ERROR: serialized control-plane ACL gate writer missing")
    readiness_match = re.search(
        r"Self\s*::\s*require_tc_acl_ready_locked\s*\(", serialized_gate_body
    )
    gate_write_match = re.search(
        r"aria_core\s*::\s*ebpf_ops\s*::\s*update_acl_runtime_gate\s*\(",
        serialized_gate_body,
    )
    if (
        readiness_match is None
        or gate_write_match is None
        or readiness_match.start() > gate_write_match.start()
    ):
        raise SystemExit(
            "ERROR: serialized enabling ACL gate writer must use lock-safe TC readiness immediately before the map write"
        )
    readiness_window = serialized_gate_body[
        readiness_match.start():gate_write_match.start()
    ]
    if ".await" in readiness_window or re.search(r"\bdrop\s*\(", readiness_window):
        raise SystemExit(
            "ERROR: await or unlock window exists between serialized TC readiness and ACL gate write"
        )
    for term in (
        "NeutronGateHealthCommitAction::ClearDisabled",
        "NeutronGateHealthCommitAction::VerifyRecoveryPublication",
        "NeutronGateHealthCommitAction::Preserve",
        "neutron_gate_health_commit_action(",
    ):
        if term not in serialized_gate_body:
            raise SystemExit(
                "ERROR: serialized ACL gate post-persistence health commit missing %s" % term
            )
    strict_wal_position = serialized_gate_body.find("wal_append_strict")
    health_commit_position = serialized_gate_body.find(
        "neutron_gate_health_commit_action("
    )
    ready_commit_position = serialized_gate_body.find(
        "Self::mark_tc_acl_runtime_ready_locked("
    )
    disabled_clear_position = serialized_gate_body.find(
        "state.runtime_health.acl_ready = true"
    )
    if (
        strict_wal_position < 0
        or health_commit_position < 0
        or ready_commit_position < 0
        or disabled_clear_position < 0
        or not strict_wal_position < health_commit_position
        or not health_commit_position < ready_commit_position
        or not health_commit_position < disabled_clear_position
    ):
        raise SystemExit(
            "ERROR: Neutron ACL health may change only after strict gate persistence, with recovery readiness revalidated before return"
        )
    recovery_failure_position = serialized_gate_body.find(
        "if let Err(readiness_error) ="
    )
    recovery_failure_tail = (
        serialized_gate_body[recovery_failure_position:]
        if recovery_failure_position >= 0
        else ""
    )
    recovery_failure_mark_position = recovery_failure_tail.find(
        "Self::mark_tc_acl_runtime_ready_locked("
    )
    recovery_failure_quiesce_position = recovery_failure_tail.find(
        "Self::quiesce_tc_acl_runtime_locked("
    )
    recovery_failure_health_result_position = recovery_failure_tail.find(
        "apply_recovery_publication_quiesce_result("
    )
    recovery_failure_health_assignment_position = recovery_failure_tail.find(
        "state.runtime_health = health"
    )
    recovery_failure_return_position = recovery_failure_tail.find("return Err(")
    if (
        recovery_failure_position < 0
        or recovery_failure_mark_position < 0
        or recovery_failure_quiesce_position < 0
        or recovery_failure_health_result_position < 0
        or recovery_failure_health_assignment_position < 0
        or recovery_failure_return_position < 0
        or not recovery_failure_mark_position < recovery_failure_quiesce_position
        or not recovery_failure_quiesce_position
        < recovery_failure_health_result_position
        or not recovery_failure_health_result_position
        < recovery_failure_health_assignment_position
        or not recovery_failure_health_assignment_position
        < recovery_failure_return_position
    ):
        raise SystemExit(
            "ERROR: failed recovery readiness publication must quiesce the live ACL gate before returning"
        )
    mark_ready_body = _rust_function_body(
        control_plane_source, "mark_tc_acl_runtime_ready_locked"
    )
    for term in (
        "missing_tc_reason(",
        "state.runtime_health.acl_ready = false",
        "state.runtime_health.acl_error = Some(",
    ):
        if mark_ready_body is None or term not in mark_ready_body:
            raise SystemExit(
                "ERROR: failed recovery readiness publication must project non-ready runtime health: %s"
                % term
            )
    for function_name in (
        "neutron_acl_gate_requires_tc",
        "neutron_acl_gate_serialization_requires_tc_only_for_enabling_writes",
    ):
        if not re.search(
            r"\bfn\s+%s\s*\(" % re.escape(function_name),
            _blank_rust_non_code(control_plane_source),
        ):
            raise SystemExit(
                "ERROR: serialized ACL gate contract missing Rust function %s"
                % function_name
            )
    if not re.search(
        r"cargo\s+\+stable\s+test\s+--locked\s+-p\s+aria-agent\s+neutron_acl_gate_serialization_",
        build_workflow_source,
    ):
        raise SystemExit("ERROR: serialized ACL gate Rust test filter missing")
    for test_filter in (
        "tc_health_reconcile_",
        "tcx_attachment_",
        "preexisting_acl_runtime_",
    ):
        if not re.search(
            r"cargo\s+\+stable\s+test\s+--locked\s+-p\s+aria-agent\s+%s"
            % re.escape(test_filter),
            build_workflow_source,
        ):
            raise SystemExit(
                "ERROR: hosted TC health Rust test filter missing %s" % test_filter
            )

    instance_source = _read_repo_text(os.path.join("agent", "src", "instance.rs"))
    rollback_plan_body = _rust_function_body(
        instance_source, "rollback_link_cleanup_plan"
    )
    if rollback_plan_body is None:
        raise SystemExit("ERROR: ownership-specific rollback cleanup plan missing")
    if "LinkOwnership::ClaimedExisting" not in rollback_plan_body:
        raise SystemExit(
            "ERROR: rollback cleanup plan must preserve runtime pins for claimed links"
        )
    rollback_execute_body = _rust_function_body(
        instance_source, "execute_rollback_cleanup_plan"
    )
    if rollback_execute_body is None:
        raise SystemExit("ERROR: best-effort rollback cleanup executor missing")
    rollback_body = _rust_function_body(instance_source, "rollback_attached_links")
    if rollback_body is None or not re.search(
        r"rollback_link_cleanup_plan\s*\(", rollback_body
    ) or not re.search(r"execute_rollback_cleanup_plan\s*\(", rollback_body):
        raise SystemExit("ERROR: rollback must execute the ownership cleanup plan")
    if re.search(r"\bdetach_tc_egress\s*\(", rollback_body):
        raise SystemExit("ERROR: transaction rollback must not delete the shared clsact qdisc")

    xdp_attach_body = _rust_function_body(instance_source, "attach_xdp_from_pin")
    xdp_detach_body = _rust_function_body(instance_source, "detach_xdp_with_ip")
    xdp_pin_recovery_body = _rust_function_body(
        instance_source, "recover_unpinned_xdp_attachment"
    )
    if xdp_detach_body is None or xdp_pin_recovery_body is None:
        raise SystemExit("ERROR: checked XDP detach recovery seam missing")
    if xdp_attach_body is None or not re.search(
        r"recover_unpinned_xdp_attachment\s*\(", xdp_attach_body
    ):
        raise SystemExit("ERROR: XDP pin failure must detach before returning attach error")
    attach_links_body = _rust_function_body(
        instance_source, "attach_links_from_pinned_runtime"
    )
    if attach_links_body is None or not re.search(
        r"attachment_may_remain\s*\(", attach_links_body
    ):
        raise SystemExit("ERROR: unresolved XDP detach failure must fail link transaction")
    if not re.search(r"detach_xdp_with_ip\s*\(", rollback_body):
        raise SystemExit("ERROR: XDP rollback must propagate fallback detach failure")

    tc_attach_body = _rust_function_body(instance_source, "try_attach_tc_from_pin")
    if tc_attach_body is None or not re.search(
        r"fd_link\s*\.\s*pin\s*\([^;]+\)\s*\.\s*map_err\s*\([^;]+\)\s*\?",
        tc_attach_body,
    ):
        raise SystemExit("ERROR: TC link pin failure must fail the attach transaction")

    strict_wal_body = _rust_function_body(control_plane_source, "wal_append_strict")
    if strict_wal_body is None:
        raise SystemExit("ERROR: strict managed gate WAL persistence missing")
    persistence_recovery_body = _rust_function_body(
        control_plane_source, "recover_gate_persistence_failure"
    )
    if persistence_recovery_body is None:
        raise SystemExit("ERROR: managed gate persistence fail-closed recovery missing")
    if not re.search(r"\.\s*wal_append_strict\s*\(", serialized_gate_body):
        raise SystemExit("ERROR: serialized managed gate must use strict WAL persistence")
    if not re.search(
        r"\.\s*recover_gate_persistence_failure\s*\(", serialized_gate_body
    ):
        raise SystemExit("ERROR: serialized managed gate must recover persistence failure")

    attach_body = _rust_function_body(tap_registry_source, "attach_with_mode")
    registration_transaction_body = _rust_function_body(
        tap_registry_source, "complete_managed_registration_transaction"
    )
    if registration_transaction_body is None or not re.search(
        r"complete_managed_registration_transaction\s*\(", attach_body or ""
    ):
        raise SystemExit("ERROR: managed publication must use the tested transaction seam")

    for source, function_name in (
        (instance_source, "managed_failure_path_cleanup_plan_preserves_claimed_direction"),
        (instance_source, "managed_failure_path_cleanup_continues_after_error"),
        (instance_source, "managed_failure_path_xdp_pin_failure_is_never_acknowledged"),
        (instance_source, "managed_failure_path_xdp_detach_command_failure_propagates"),
        (control_plane_source, "managed_failure_path_strict_wal_failure_propagates"),
        (control_plane_source, "managed_failure_path_enabling_persistence_failure_quiesces"),
        (control_plane_source, "managed_failure_path_disabling_persistence_failure_stays_disabled"),
        (control_plane_source, "managed_failure_path_kernel_quiesce_failure_stays_disabled"),
        (tap_registry_source, "managed_failure_path_activation_failure_leaves_real_registries_empty"),
    ):
        if _rust_function_body(source, function_name) is None:
            raise SystemExit("ERROR: managed failure-path Rust test missing %s" % function_name)
    if not re.search(
        r"cargo\s+\+stable\s+test\s+--locked\s+-p\s+aria-agent\s+managed_failure_path_",
        build_workflow_source,
    ):
        raise SystemExit("ERROR: managed failure-path Rust test filter missing")

    system_activation_body = _rust_function_body(
        system_manager_source, "system_acl_activation"
    )
    if system_activation_body is None or not all(
        marker in system_activation_body
        for marker in ("health.acl_ready()", "health.missing_tc()")
    ):
        raise SystemExit("ERROR: standalone dual-TC activation decision missing")
    system_start_body = _rust_function_body(system_manager_source, "system_start")
    if system_start_body is None:
        raise SystemExit("ERROR: standalone system_start body missing")
    desired_load = system_start_body.find("aria_core::wal::load_with_wal(state_path)")
    replay = system_start_body.find(
        "replay_state_from_snapshot(&mut bpf, state_path, &quiesced_desired)"
    )
    quiesce = system_start_body.find("aria_core::ebpf_ops::update_firewall_config(")
    scrub = system_start_body.find("scrub_standalone_runtime_state(pin_path)")
    xdp_attach = system_start_body.find("attach_xdp_program(&mut bpf, iface, pin_path)")
    activation = system_start_body.find("system_acl_activation(")
    registration = system_start_body.find(".register_system_instance(")
    if not (
        0 <= desired_load < quiesce < scrub < replay < xdp_attach < activation < registration
    ):
        raise SystemExit(
            "ERROR: standalone startup must load desired, quiesce old links, replay a disabled gate, attach/claim TC, decide, then register"
        )
    if system_start_body.count("aria_core::wal::load_with_wal(state_path)") != 1:
        raise SystemExit("ERROR: standalone startup must approve exactly one WAL snapshot")
    if "replay_state(&mut bpf, state_path)" in system_start_body:
        raise SystemExit("ERROR: standalone startup must not replay from a second path load")
    for marker in (
        "quiesced_desired.conntrack_enabled = false",
        "quiesced_desired.acl_enabled = false",
        "preexisting_tc_acl_runtime_is_healthy(",
        "reuse_preexisting_tc",
    ):
        if marker not in system_start_body:
            raise SystemExit("ERROR: standalone pinned-runtime boundary missing %s" % marker)
    replay_snapshot_body = _rust_function_body(
        replay_source, "replay_state_from_snapshot"
    )
    if replay_snapshot_body is None or "load_with_wal" in replay_snapshot_body:
        raise SystemExit("ERROR: snapshot replay must consume the caller-approved state object")
    replay_wrapper_body = _rust_function_body(replay_source, "replay_state")
    if replay_wrapper_body is None or not all(
        marker in replay_wrapper_body
        for marker in ("load_with_wal", "replay_state_from_snapshot")
    ):
        raise SystemExit("ERROR: path-based replay compatibility wrapper is missing")
    if not re.search(
        r"TapMapRuntime\s*::\s*new\s*\(\s*pin_path\s*,\s*aria_core\s*::\s*common\s*::\s*TAP_ID_UNASSIGNED\s*\)\s*,\s*Some\s*\(\s*false\s*\)\s*,\s*None\s*,\s*Some\s*\(\s*false\s*\)",
        system_start_body[quiesce:scrub],
    ):
        raise SystemExit(
            "ERROR: standalone startup must quiesce preexisting live ACL/CT before map scrub/replay"
        )
    if not re.search(r"match\s+attach_xdp_program", system_start_body):
        raise SystemExit("ERROR: standalone XDP attach must be independent best-effort health")
    for marker in (
        "ownership.tc_egress_link = true",
        "ownership.tc_ingress_link = true",
        "pin_runtime_programs(",
        "&mut ownership",
        "unbacked_program_link_cleanup_plan(&ownership, program_health)",
    ):
        if marker not in system_start_body:
            raise SystemExit("ERROR: standalone TC readiness missing %s" % marker)
    activation_window = system_start_body[activation:registration]
    if "start_error_with_cleanup(" not in activation_window:
        raise SystemExit("ERROR: standalone required-TC failure must clean startup state")
    lifecycle_lock = system_start_body.find("lock_runtime_lifecycle().await")
    if not (0 <= lifecycle_lock < desired_load):
        raise SystemExit("ERROR: standalone startup must hold the shared lifecycle lock")
    register_body = _rust_function_body(
        control_plane_source, "register_system_instance"
    )
    if register_body is None or "load_with_wal" in register_body:
        raise SystemExit("ERROR: system publication must not reload a drifting snapshot")
    for marker in ("approved_state", "prepare_system_publication_state"):
        if marker not in register_body:
            raise SystemExit("ERROR: system publication missing approved snapshot handoff")
    system_live_health = register_body.find("runtime_instance.tc_acl_link_health()")
    system_gate_restore = register_body.find("aria_core::ebpf_ops::update_runtime_config(")
    if not (0 <= system_live_health < system_gate_restore):
        raise SystemExit(
            "ERROR: system publication must validate exact live TCX before restoring ACL/CT"
        )
    preexisting_validation = _rust_function_body(
        control_plane_source, "validate_preexisting_live_runtime"
    )
    if preexisting_validation is None or not all(
        marker in preexisting_validation
        for marker in ("tc_acl_link_health()", "preexisting_tc_acl_runtime_is_healthy")
    ):
        raise SystemExit(
            "ERROR: managed preexisting runtime must validate exact live TCX identity"
        )
    managed_quiesce = _rust_function_body(
        control_plane_source, "quiesce_managed_registration"
    )
    if managed_quiesce is None or "update_acl_runtime_gate(" not in managed_quiesce:
        raise SystemExit(
            "ERROR: managed attach failure paths must expose an explicit ACL/CT quiesce transaction"
        )
    if tap_registry_source.count(".quiesce_managed_registration(&prepared)") < 4:
        raise SystemExit(
            "ERROR: all managed post-prepare failure paths must quiesce surviving ACL/CT links"
        )
    cleanup_plan_body = _rust_function_body(
        system_manager_source, "failed_start_cleanup_plan"
    )
    cleanup_execute_body = _rust_function_body(
        system_manager_source, "execute_system_cleanup_plan"
    )
    if cleanup_plan_body is None or cleanup_execute_body is None:
        raise SystemExit("ERROR: standalone ownership cleanup plan/executor missing")
    if "ClsactOwnership::Created" not in cleanup_plan_body:
        raise SystemExit("ERROR: standalone cleanup must remove only owned clsact")
    for marker in (
        "owned_map_pins",
        "owned_program_pins",
        "owned_link_pins",
        "RemoveOwnedPin",
        "owned_runtime_dirs",
    ):
        if marker not in system_manager_source:
            raise SystemExit("ERROR: standalone per-resource ownership missing %s" % marker)
    partial_dir_body = _rust_function_body(
        system_manager_source, "create_runtime_pin_directories_with"
    )
    if partial_dir_body is None or "cleanup_empty_runtime_directories" not in partial_dir_body:
        raise SystemExit("ERROR: partial runtime directory creation must be rolled back")
    system_stop_body = _rust_function_body(system_manager_source, "system_stop")
    if system_stop_body is None or "lock_runtime_lifecycle().await" not in system_stop_body:
        raise SystemExit("ERROR: standalone stop must hold the shared lifecycle lock")
    for forbidden in ("detach_tc_egress(", '"xdp", "off"'):
        if forbidden in system_stop_body:
            raise SystemExit("ERROR: standalone stop contains unowned teardown %s" % forbidden)

    control_code = _blank_rust_non_code(control_plane_source)
    for function_name in (
        "config_update_requires_tc",
        "local_config_enable_requires_dual_tc_but_disable_does_not",
        "require_tc_acl_ready_locked",
        "check_runtime_maps_ready",
    ):
        if not re.search(r"\bfn\s+%s\s*\(" % function_name, control_code):
            raise SystemExit("ERROR: local standalone TC contract missing %s" % function_name)
    if re.search(r"\bfn\s+check_xdp_ready\s*\(", control_code):
        raise SystemExit("ERROR: runtime map readiness must not imply an XDP link dependency")
    locked_readiness_body = _rust_function_body(
        control_plane_source, "require_tc_acl_ready_locked"
    )
    shared_tc_health_body = _rust_function_body(
        control_plane_source, "tc_acl_link_health_locked"
    )
    if (
        locked_readiness_body is None
        or "Self::tc_acl_link_health_locked(instance, state, trace_map_mode)"
        not in locked_readiness_body
        or "health.acl_ready()" not in locked_readiness_body
        or shared_tc_health_body is None
        or not all(
            marker in shared_tc_health_body
            for marker in (
                "runtime_iface_name(instance, state)",
                "instance !=",
                ".tc_acl_link_health()",
            )
        )
    ):
        raise SystemExit("ERROR: lock-safe shared dual-TC readiness helper missing")
    update_config_body = _rust_function_body(control_plane_source, "update_config")
    local_guard = update_config_body.find("config_update_requires_tc(conntrack, acl)")
    local_readiness = update_config_body.find(
        "require_tc_acl_ready_locked(instance, &state, self.trace_map_mode())"
    )
    local_write = update_config_body.find("aria_core::ebpf_ops::update_runtime_config(")
    if not (0 <= local_guard < local_readiness < local_write):
        raise SystemExit(
            "ERROR: local ACL/CT enable must require dual TC under the instance lock before map write"
        )
    for marker in (
        "lock_runtime_lifecycle().await",
        ".wal_append_strict(",
        ".recover_local_config_persistence_failure(",
    ):
        if marker not in update_config_body:
            raise SystemExit("ERROR: local config strict lifecycle contract missing %s" % marker)
    replace_acl_body = _rust_function_body(control_plane_source, "replace_owned_acl")
    publication_body = _rust_function_body(
        control_plane_source, "publish_acl_projection_locked"
    )
    if replace_acl_body is None or publication_body is None:
        raise SystemExit("ERROR: ACL replace publication helpers missing")
    shadow_stage = publication_body.find("Self::stage_acl_shadow_bank(")
    first_bank_readiness = replace_acl_body.find(
        "Self::require_tc_acl_ready_locked(instance, &state, self.trace_map_mode())"
    )
    publication_call = replace_acl_body.find(".publish_acl_projection_locked(")
    shared_mutation = publication_body.find("apply_shared_network_mutation(")
    bank_readiness = publication_body.find(
        "Self::require_tc_acl_ready_locked(",
        shadow_stage,
    )
    bank_publish = publication_body.find("aria_core::ebpf_ops::set_acl_active_bank(")
    if not (
        0 <= first_bank_readiness < publication_call
        and 0 <= shared_mutation < shadow_stage < bank_readiness < bank_publish
    ):
        raise SystemExit(
            "ERROR: ACL replace must preflight TC before shared maps and recheck after staging"
        )
    readiness_prefix = publication_body[shadow_stage:bank_readiness]
    if not re.search(
        r"if\s+require_tc_acl_links\b",
        readiness_prefix,
    ):
        raise SystemExit(
            "ERROR: ACL bank TC gate must use the target publication requirement"
        )
    for marker in ("lock_runtime_lifecycle().await", "transaction_created_port_sets("):
        if marker not in replace_acl_body:
            raise SystemExit("ERROR: ACL bank rollback/lifecycle contract missing %s" % marker)
    for marker in (
        "rollback_owned_acl_prepublication(",
        "managed_acl_publication_compensations(",
        "execute_managed_acl_publication_compensations(",
        "cleanup_transaction_created_port_sets(",
    ):
        if marker not in publication_body:
            raise SystemExit("ERROR: ACL bank rollback/lifecycle contract missing %s" % marker)
    persistence_cleanup = publication_body.find(
        "cleanup_transaction_created_port_sets(", bank_publish
    )
    allocation_restore = publication_body.find(
        "restore_durable_old_state_after_failed_persistence(", bank_publish
    )
    if not (bank_publish < persistence_cleanup < allocation_restore):
        raise SystemExit(
            "ERROR: ACL persistence rollback must clean created port sets before restoring allocation metadata"
        )
    tap_code = _blank_rust_non_code(tap_registry_source)
    if re.search(r"\bruntime_lock\s*:", tap_code):
        raise SystemExit("ERROR: TapRegistry must use the ControlPlane lifecycle lock")
    for function_name in ("attach_with_mode", "detach", "update_neutron_acl_runtime_gate"):
        body = _rust_function_body(tap_registry_source, function_name)
        if body is None or "lock_runtime_lifecycle().await" not in body:
            raise SystemExit("ERROR: managed lifecycle path missing shared lock: %s" % function_name)
    for test_name in (
        "standalone_review_cleanup_plan_preserves_preexisting_clsact",
        "standalone_review_cleanup_attempts_every_owned_resource",
        "standalone_review_partial_tc_cleanup_removes_only_owned_pins",
        "standalone_review_xdp_program_pin_failure_rolls_back_owned_link",
        "standalone_review_program_pin_completeness_requires_links_and_programs",
        "standalone_review_publication_uses_approved_snapshot_not_reload",
        "standalone_review_lifecycle_serializes_detach_and_enable",
        "standalone_review_local_persistence_failure_is_fail_closed",
        "standalone_review_bank_rollback_attempts_all_shared_mutations",
        "standalone_review_start_replays_exact_approved_snapshot",
        "standalone_review_preexisting_pin_dir_cleans_only_transaction_pins",
        "standalone_review_program_pin_without_link_is_cleaned_for_retry",
        "standalone_review_partial_runtime_dir_creation_is_rolled_back",
        "standalone_review_port_set_rollback_cleans_recycled_bitmap",
        "standalone_review_port_set_cleanup_attempts_every_created_set",
        "standalone_review_failed_cleanup_quarantine_survives_retry_and_restart",
        "standalone_review_rollback_recovery_persists_only_failed_cleanup_quarantine",
        "standalone_review_same_diff_release_is_quarantined_before_later_allocation",
        "standalone_review_same_diff_normalized_port_dedup_keeps_release_quarantined",
        "standalone_review_bank_map_helpers_use_required_maps_without_xdp_sentinel",
        "standalone_review_bank_rollback_port_set_cleanup_requires_map_without_xdp",
    ):
        if test_name not in system_manager_source + instance_source + control_plane_source:
            raise SystemExit("ERROR: standalone review behavior test missing %s" % test_name)
    if not re.search(
        r"cargo\s+\+stable\s+test\s+--locked\s+-p\s+aria-agent\s+standalone_review_",
        build_workflow_source,
    ):
        raise SystemExit("ERROR: standalone review Rust test filter missing")
    if not re.search(
        r"cargo\s+\+stable\s+test\s+--locked\s+-p\s+aria-agent\s+standalone_acl_activation_",
        build_workflow_source,
    ):
        raise SystemExit("ERROR: standalone activation Rust test filter missing")
    for core_filter in (
        "map_delete_",
        "quarantined_",
        "confirmed_bitmap_cleanup_",
    ):
        if not re.search(
            r"(?m)^\s*cargo\s+\+stable\s+test\s+--locked\s+-p\s+aria-core\s+%s\s*$"
            % re.escape(core_filter),
            build_workflow_source,
        ):
            raise SystemExit(
                "ERROR: aria-core ACL allocator Rust test filter missing %s"
                % core_filter
            )

    restart_runtime_match = re.search(
        r"async fn reconcile_committed_runtime\(&self\) \{(?P<body>.*?)\n    async fn recover_incomplete_wal_intent",
        neutron_api_source,
        re.DOTALL,
    )
    if not restart_runtime_match:
        raise SystemExit("ERROR: Rust committed-runtime restart path not found")
    restart_runtime_body = restart_runtime_match.group("body")
    restart_acl_invalidation = restart_runtime_body.find(
        "let acl_requires_full_resync = invalidate_restarted_acl_runtime("
    )
    restart_ready_transition = restart_runtime_body.find(
        'next_runtime.authority_state = "ready".to_string()'
    )
    if (
        restart_acl_invalidation < 0
        or restart_ready_transition < 0
        or restart_acl_invalidation > restart_ready_transition
    ):
        raise SystemExit(
            "ERROR: restart path must invalidate managed ACL runtime before ready"
        )

    required_acl_priority_terms = [
        "const MAX_ACL_RULES_PER_POLICY: usize = 1000;",
        "const MAX_ACL_SELECTOR_MEMBERS: usize = 2048;",
        "struct AclIpv4Cidr {",
        "enum AclValidatedTemplate {",
        "struct AclValidationCacheKey {",
        "struct AclValidationCache {",
        "fn translate_neutron_acl_with_cache(",
        "force_bypass_reason: Option<String>",
        "fn neutron_acl_translator_force_bypasses_nested_cidrs(",
        "fn neutron_acl_translator_reuses_canonical_cidr_groups(",
        "fn neutron_acl_translator_force_bypasses_priority_fallback_conflict(",
        "fn neutron_acl_force_bypass_outcome_overrides_optimistic_snapshot(",
        "NeutronAclReconcileOutcome::from_plan(&plan)",
        "fn neutron_acl_reconcile_failure_phase_reports_the_proven_effective_action(",
        "unsupported_acl_cidr_overlap:",
        "unsupported_acl_priority_overlap:",
    ]
    for term in required_acl_priority_terms:
        if term not in neutron_api_source:
            raise SystemExit("ERROR: Rust ACL priority guard missing %s" % term)

    policy_key_match = re.search(
        r"(?:pub\s+)?struct\s+PolicyKey\s*\{(?P<body>.*?)\n\}",
        abi_common_source,
        re.DOTALL,
    )
    if not policy_key_match:
        raise SystemExit("ERROR: eBPF PolicyKey block not found")
    if re.search(r"\bpriority\s*:", policy_key_match.group("body")):
        raise SystemExit("ERROR: eBPF PolicyKey must not contain priority")

    acl_test_command = "cargo +stable test --locked -p aria-agent neutron_acl_"
    acl_test_pattern = r"(?m)^[ \t]+%s[ \t]*$" % re.escape(acl_test_command)
    if not re.search(acl_test_pattern, build_workflow_source):
        raise SystemExit("ERROR: Build workflow missing active %s" % acl_test_command)

    required_domain_authority_terms = [
        "fn domain_authority_blocks_only_selected_domains(",
        "fn domain_authority_blocks_conntrack_as_acl_dependency(",
        "LOCAL_WRITE_BLOCKED_FOR_NEUTRON_MANAGED_DOMAIN",
        "dependency of '{}'",
        "Self::GroupInUse(_) | Self::LocalWriteBlocked { .. } => 409",
        "ensure_local_write_allowed(\"tap-vm\", LocalWriteDomain::Acl)",
        "ensure_local_write_allowed(\"tap-vm\", LocalWriteDomain::Mirror)",
        "ensure_local_write_allowed(\"tap-vm\", LocalWriteDomain::Qos)",
        "ensure_local_write_allowed(\"tap-vm\", LocalWriteDomain::Trace)",
        "ensure_local_group_write_allowed(\"tap-vm\", \"neutron:acl-source\")",
        "ensure_local_group_write_allowed(\"tap-vm\", \"local-qos-group\")",
    ]
    for term in required_domain_authority_terms:
        if term not in control_plane_source:
            raise SystemExit("ERROR: Rust domain authority source missing %s" % term)

    main_source = _read_repo_text(os.path.join("agent", "src", "main.rs"))
    required_peercred_tests = [
        "fn startup_config_accepts_neutron_socket_and_peercred_settings(",
        "fn peercred_policy_requires_allow_list_when_enforced(",
        "fn peercred_policy_allows_configured_uid_or_gid(",
        "fn peercred_policy_audit_only_allows_without_credentials(",
    ]
    for test_name in required_peercred_tests:
        if test_name not in main_source:
            raise SystemExit("ERROR: missing Rust Neutron peercred test %s" % test_name)

    if "fn openapi_does_not_expose_neutron_uds_paths(" not in openapi_source:
        raise SystemExit("ERROR: missing Rust OpenAPI Neutron UDS exclusion test")
    for path in (
        "~1api~1v1~1neutron~1capabilities",
        "~1api~1v1~1neutron~1status",
        "~1api~1v1~1neutron~1snapshot",
        "~1api~1v1~1neutron~1ports~1{port_id}~1snapshot",
        "~1api~1v1~1neutron~1ports~1{port_id}",
    ):
        if path not in openapi_source:
            raise SystemExit("ERROR: OpenAPI exclusion test missing %s" % path)


def check_managed_acl_publication_transaction_contract():
    print("==> checking managed ACL publication transaction contract")
    control_plane_source = _read_repo_text(
        os.path.join("agent", "src", "control_plane.rs")
    )
    control_plane_code = _blank_rust_non_code(control_plane_source)
    inventory_source = _read_repo_text(
        os.path.join("core", "src", "ebpf_ops", "inventory.rs")
    )

    shadow_errors = _managed_acl_shadow_contract_errors(
        control_plane_source, source_code=control_plane_code
    )
    if shadow_errors:
        raise SystemExit("ERROR: " + "; ".join(shadow_errors))

    replaced_errors = _managed_replaced_compensation_contract_errors(
        control_plane_source, control_code=control_plane_code
    )
    if replaced_errors:
        raise SystemExit("ERROR: " + "; ".join(replaced_errors))

    mutation_body = _rust_item_body(
        control_plane_source, "enum", "SharedNetworkMutation"
    )
    if mutation_body is None or not all(
        marker in mutation_body
        for marker in (
            "Replaced",
            "direction",
            "cidr",
            "old_group_id",
            "new_group_id",
        )
    ):
        raise SystemExit(
            "ERROR: managed general replacement must retain its complete old/new preimage"
        )
    apply_body = _rust_function_body(
        control_plane_source, "apply_shared_network_mutation"
    )
    compensation_body = _rust_function_body(
        control_plane_source, "shared_network_compensation"
    )
    replaced_apply_start = (
        apply_body.find("SharedNetworkMutation::Replaced") if apply_body else -1
    )
    replaced_apply_end = (
        apply_body.find("SharedNetworkMutation::", replaced_apply_start + 1)
        if replaced_apply_start >= 0 else -1
    )
    replaced_apply = (
        apply_body[replaced_apply_start:]
        if replaced_apply_start >= 0 and replaced_apply_end < 0
        else apply_body[replaced_apply_start:replaced_apply_end]
        if replaced_apply_start >= 0
        else ""
    )
    if (
        apply_body is None
        or "add_network" not in replaced_apply
        or "new_group_id" not in replaced_apply
        or "delete_network" in replaced_apply
        or compensation_body is None
        or not all(
            marker in compensation_body
            for marker in ("SharedNetworkMutation::Replaced", "old_group_id", "new_group_id")
        )
    ):
        raise SystemExit(
            "ERROR: managed general replacement apply/rollback must upsert new then restore old"
        )

    compensation_item = _rust_item_body(
        control_plane_source, "enum", "ManagedAclPublicationCompensation"
    )
    failure_phase_item = _rust_item_body(
        control_plane_source, "enum", "ManagedAclPublicationFailurePhase"
    )
    compensation_plan_body = _rust_function_body(
        control_plane_source, "managed_acl_publication_compensations"
    )
    compensation_execute_body = _rust_function_body(
        control_plane_source, "execute_managed_acl_publication_compensations"
    )
    if (
        compensation_item is None
        or not all(
            marker in compensation_item
            for marker in ("RestoreActiveBank", "RestoreGeneral")
        )
        or failure_phase_item is None
        or not all(
            marker in failure_phase_item
            for marker in ("General", "Shadow", "VerifyTc", "SwitchBank", "Persist")
        )
        or compensation_plan_body is None
        or not all(
            marker in compensation_plan_body
            for marker in (
                "ManagedAclPublicationFailurePhase::Persist",
                "mutations.iter().rev()",
                "shared_network_compensation",
            )
        )
        or compensation_execute_body is None
        or ".iter()" not in compensation_execute_body
    ):
        raise SystemExit(
            "ERROR: managed ACL failure compensation must restore bank and every general preimage"
        )

    group_rollback_body = _rust_function_body(
        control_plane_source, "rollback_group_deletes"
    )
    if (
        group_rollback_body is None
        or "group_delete_rollback_restores_acl_bank" not in group_rollback_body
    ):
        raise SystemExit(
            "ERROR: managed group-delete rollback must not restore the active ACL bank"
        )

    decision_body = _rust_function_body(
        control_plane_source, "managed_acl_publication_decision"
    )
    if decision_body is None or not all(
        marker in decision_body
        for marker in (
            "ProjectionDrift::Clean",
            "ProjectionDrift::RepairRequired",
            "ProjectionDrift::Fatal",
            "ManagedProjectionHealth::Unverified",
        )
    ):
        raise SystemExit(
            "ERROR: managed projection publication decision must distinguish clean, repair, and fatal drift"
        )

    step_item = _rust_item_body(
        control_plane_source, "enum", "ManagedAclPublicationStep"
    )
    step_plan_body = _rust_function_body(
        control_plane_source, "managed_acl_publication_steps"
    )
    if step_item is None or not all(
        marker in step_item
        for marker in (
            "InvalidateProjectionHealth",
            "ApplyGeneral",
            "StageShadow",
            "VerifyTc",
            "SwitchBank",
            "Persist",
        )
    ):
        raise SystemExit("ERROR: managed ACL publication step vocabulary is incomplete")
    if step_plan_body is None:
        raise SystemExit("ERROR: managed ACL publication step planner is missing")
    projection_conversion_body = _rust_function_body(
        control_plane_source, "shared_network_mutation_from_projection"
    )
    if projection_conversion_body is None or not all(
        marker in projection_conversion_body
        for marker in (
            "ProjectionMutation::Added",
            "ProjectionMutation::Deleted",
            "ProjectionMutation::Replaced",
            "old_group_id",
            "new_group_id",
        )
    ):
        raise SystemExit(
            "ERROR: proposed projection mutations must retain complete shared-map preimages"
        )
    planned_step_positions = [
        step_plan_body.find(marker)
        for marker in (
            "ManagedAclPublicationStep::InvalidateProjectionHealth",
            "ManagedAclPublicationStep::ApplyGeneral",
            "ManagedAclPublicationStep::StageShadow",
            "ManagedAclPublicationStep::VerifyTc",
            "ManagedAclPublicationStep::SwitchBank",
            "ManagedAclPublicationStep::Persist",
        )
    ]
    if (
        "ManagedAclPublicationDecision::Noop" not in step_plan_body
        or "repair_plan" not in step_plan_body
        or "shared_network_mutation_from_projection" not in step_plan_body
        or any(position < 0 for position in planned_step_positions)
        or planned_step_positions != sorted(planned_step_positions)
    ):
        raise SystemExit(
            "ERROR: managed ACL publication steps must order health, general, shadow, verify, switch, persist"
        )

    proposed_drift_body = _rust_function_body(
        inventory_source, "plan_managed_pinned_projection"
    )
    if proposed_drift_body is None or not all(
        marker in proposed_drift_body
        for marker in (
            "capture_runtime_group_map_entries",
            "validate_strict_pinned_runtime_state",
            "compile_managed_group_projection",
            "plan_projection_drift",
            "proposed",
        )
    ):
        raise SystemExit(
            "ERROR: pinned managed drift planning must classify committed capture directly to proposed projection"
        )
    if not re.search(
        r"plan_projection_drift\s*\([^;]*\bproposed\b",
        proposed_drift_body,
        re.DOTALL,
    ):
        raise SystemExit(
            "ERROR: pinned managed drift planner must pass proposed projection as its third input"
        )

    replace_body = _rust_function_body(control_plane_source, "replace_owned_acl")
    publication_body = _rust_function_body(
        control_plane_source, "publish_acl_projection_locked"
    )
    if (
        replace_body is None
        or "publish_acl_projection_locked" not in replace_body
        or publication_body is None
    ):
        raise SystemExit(
            "ERROR: owned ACL replace must use one locked projection publication helper"
        )
    if "lock_runtime_lifecycle" in publication_body:
        raise SystemExit(
            "ERROR: locked projection publication helper must not reacquire the lifecycle lock"
        )
    if "ManagedProjectionHealth::Verified" in publication_body:
        raise SystemExit(
            "ERROR: projection publication must remain unverified until the caller's strict flush"
        )
    drift_check = publication_body.find("plan_managed_pinned_projection")
    decision = publication_body.find("managed_acl_publication_decision")
    no_op = publication_body.find("ManagedAclPublicationDecision::Noop")
    step_plan = publication_body.find("managed_acl_publication_steps")
    if not (0 <= drift_check < decision < no_op < step_plan):
        raise SystemExit(
            "ERROR: managed projection drift and no-op decision must precede one publication step plan"
        )
    for marker in (
        "ManagedAclPublicationStep::InvalidateProjectionHealth",
        "managed_projection_health = ManagedProjectionHealth::Unverified",
        "ManagedAclPublicationStep::ApplyGeneral",
        "apply_shared_network_mutation",
        "ManagedAclPublicationStep::StageShadow",
        "Self::stage_acl_shadow_bank",
        "ManagedAclPublicationStep::VerifyTc",
        "Self::require_tc_acl_ready_locked",
        "ManagedAclPublicationStep::SwitchBank",
        "aria_core::ebpf_ops::set_acl_active_bank",
        "ManagedAclPublicationStep::Persist",
    ):
        if marker not in publication_body:
            raise SystemExit(
                "ERROR: locked managed ACL publication helper is missing %s" % marker
            )
    prepublication_rollback_body = _rust_function_body(
        control_plane_source, "rollback_owned_acl_prepublication"
    )
    if (
        prepublication_rollback_body is None
        or "managed_acl_publication_compensations" not in prepublication_rollback_body
        or "managed_acl_publication_compensations" not in publication_body
    ):
        raise SystemExit(
            "ERROR: shadow and persistence failures must use the shared complete compensation plan"
        )
    general_arm_start = publication_body.find("ManagedAclPublicationStep::ApplyGeneral")
    shadow_arm_start = publication_body.find("ManagedAclPublicationStep::StageShadow")
    shadow_arm_end = publication_body.find(
        "ManagedAclPublicationStep::VerifyTc", shadow_arm_start + 1
    )
    verify_arm_start = shadow_arm_end
    switch_arm_start = publication_body.find(
        "ManagedAclPublicationStep::SwitchBank", verify_arm_start + 1
    )
    persist_arm_start = publication_body.find("ManagedAclPublicationStep::Persist")
    general_arm = (
        publication_body[general_arm_start:shadow_arm_start]
        if 0 <= general_arm_start < shadow_arm_start
        else ""
    )
    shadow_arm = (
        publication_body[shadow_arm_start:shadow_arm_end]
        if 0 <= shadow_arm_start < shadow_arm_end
        else ""
    )
    verify_arm = (
        publication_body[verify_arm_start:switch_arm_start]
        if 0 <= verify_arm_start < switch_arm_start
        else ""
    )
    switch_arm = (
        publication_body[switch_arm_start:persist_arm_start]
        if 0 <= switch_arm_start < persist_arm_start
        else ""
    )
    persist_arm = publication_body[persist_arm_start:] if persist_arm_start >= 0 else ""
    for arm, phase, label in (
        (general_arm, "General", "general-map"),
        (shadow_arm, "Shadow", "shadow"),
        (verify_arm, "VerifyTc", "TC verification"),
        (switch_arm, "SwitchBank", "bank switch"),
    ):
        if (
            "ManagedAclPublicationFailurePhase::%s" % phase not in arm
            or "rollback_owned_acl_prepublication" not in arm
        ):
            raise SystemExit(
                "ERROR: %s failure must dispatch the pre-switch compensation phase"
                % label
            )
    if "require_tc_acl_links" not in verify_arm:
        raise SystemExit(
            "ERROR: TC verification must use the target publication requirement after quiesce"
        )
    durable_restore_body = _rust_function_body(
        control_plane_source, "restore_durable_old_state_after_failed_persistence"
    )
    if durable_restore_body is None:
        raise SystemExit(
            "ERROR: persistence failure must unconditionally restore the old durable snapshot"
        )
    if (
        "created_port_sets" in durable_restore_body
        or ".is_empty()" in durable_restore_body
        or "failed_persistence_recovery_state" not in durable_restore_body
        or "compact_and_publish_state" not in durable_restore_body
    ):
        raise SystemExit(
            "ERROR: failed persistence recovery must not skip an empty created-port-set transaction"
        )
    persistence_cleanup = persist_arm.find("cleanup_transaction_created_port_sets")
    durable_restore = persist_arm.find(
        "restore_durable_old_state_after_failed_persistence"
    )
    if not (0 <= persistence_cleanup < durable_restore):
        raise SystemExit(
            "ERROR: persistence compensation must clean created port sets before restoring the old durable snapshot"
        )
    cleanup_depth = (
        persist_arm[:persistence_cleanup].count("{")
        - persist_arm[:persistence_cleanup].count("}")
    )
    restore_depth = (
        persist_arm[:durable_restore].count("{")
        - persist_arm[:durable_restore].count("}")
    )
    if cleanup_depth != restore_depth:
        raise SystemExit(
            "ERROR: old durable snapshot restore must be unconditional after persistence cleanup"
        )
    if not all(
        marker in persist_arm
        for marker in (
            "ManagedAclPublicationFailurePhase::Persist",
            "managed_acl_publication_compensations",
            "execute_managed_acl_publication_compensations",
        )
    ):
        raise SystemExit(
            "ERROR: persistence failure must restore the old bank and every general preimage"
        )
    if (
        "fn managed_general_delta_persistence_failure_restores_old_snapshot_without_created_port_sets("
        not in control_plane_source
    ):
        raise SystemExit(
            "ERROR: missing empty-created-set persistence compensation regression test"
        )

    neutron_api_source = _read_repo_text(
        os.path.join("agent", "src", "neutron_api.rs")
    )
    if (
        "fn managed_projection_repair_quiesced_replace_uses_publish_tc_requirement("
        not in neutron_api_source
    ):
        raise SystemExit(
            "ERROR: managed ACL publication is missing the quiesced target-TC regression test"
        )
    reconcile_body = _rust_function_body(neutron_api_source, "reconcile_neutron_acl")
    replace = reconcile_body.find(".replace_owned_acl(") if reconcile_body else -1
    target_tc_requirement = (
        reconcile_body.find("acl_runtime_feature_requires_tc(transition.publish)")
        if reconcile_body
        else -1
    )
    strict_flush = (
        reconcile_body.find("flush_neutron_acl_conntrack", replace)
        if reconcile_body else -1
    )
    gate_publish = (
        reconcile_body.find(".update_neutron_acl_runtime_gate(", strict_flush)
        if reconcile_body else -1
    )
    replace_await = reconcile_body.find(".await", replace) if reconcile_body else -1
    replace_call = (
        reconcile_body[replace:replace_await]
        if 0 <= replace < replace_await
        else ""
    )
    if (
        not (0 <= target_tc_requirement < replace < strict_flush < gate_publish)
        or "require_tc_acl_links" not in replace_call
    ):
        raise SystemExit(
            "ERROR: managed ACL publication must derive target TC readiness before replace, strict flush, and gate publish"
        )


def check_managed_cross_domain_group_mutation_contract():
    print("==> checking managed cross-domain group mutation contract")
    errors = _managed_cross_domain_group_mutation_contract_errors(
        _read_repo_text(os.path.join("agent", "src", "control_plane.rs")),
        _read_repo_text(os.path.join("agent", "src", "api_handlers", "groups.rs")),
        _read_repo_text(os.path.join("agent", "src", "api_handlers", "qos.rs")),
        _read_repo_text(os.path.join("agent", "src", "api_handlers", "mirror.rs")),
    )
    if errors:
        raise SystemExit("ERROR: " + errors[0])


def check_managed_authoritative_write_admission_contract():
    print("==> checking managed authoritative write admission contract")
    _run_managed_authoritative_write_admission_self_tests()
    other_agent_sources = []
    agent_source_root = os.path.join(ROOT, "agent", "src")
    excluded = {
        os.path.join(agent_source_root, "control_plane.rs"),
        os.path.join(agent_source_root, "neutron_api.rs"),
    }
    for current_root, _, files in os.walk(agent_source_root):
        for filename in sorted(files):
            path = os.path.join(current_root, filename)
            if filename.endswith(".rs") and path not in excluded:
                with open(path, "r", encoding="utf-8") as source_file:
                    other_agent_sources.append(source_file.read())
    errors = _managed_authoritative_write_admission_contract_errors(
        _read_repo_text(os.path.join("agent", "src", "control_plane.rs")),
        _read_repo_text(os.path.join("agent", "src", "api_handlers", "groups.rs")),
        _read_repo_text(os.path.join("agent", "src", "neutron_api.rs")),
        "\n".join(other_agent_sources),
    )
    if errors:
        raise SystemExit("ERROR: " + errors[0])


def check_managed_projection_attach_migration_contract():
    print("==> checking managed projection attach-migration contract")
    errors = _managed_projection_attach_migration_contract_errors(
        _read_repo_text(os.path.join("agent", "src", "control_plane.rs")),
        _read_repo_text(os.path.join("agent", "src", "tap_registry.rs")),
        _read_repo_text(os.path.join("agent", "src", "neutron_api.rs")),
    )
    if errors:
        raise SystemExit("ERROR: " + errors[0])


def check_ebpf_acl_ingress_boundary():
    print("==> checking eBPF ACL ingress boundary")
    _run_acl_ingress_parser_self_tests()
    runtime_source = _read_repo_text(EBPF_RUNTIME_PATH)
    if _has_acl_ingress_hook_definition(runtime_source):
        raise SystemExit("ERROR: eBPF runtime must not expose acl_ingress_hook")

    abi_source = _read_repo_text(EBPF_ABI_PATH)
    missing = _missing_acl_ingress_abi(abi_source)
    if missing:
        raise SystemExit(
            "ERROR: %s compatibility ABI missing %s"
            % (EBPF_ABI_PATH, ", ".join(missing))
        )

    expected_reexports = {
        CORE_COMMON_PATH: "pub use aria_ebpf_abi::userspace::*;",
        EBPF_COMMON_PATH: "pub use aria_ebpf_abi::*;",
    }
    for path, expected in expected_reexports.items():
        if expected not in _read_repo_text(path):
            raise SystemExit("ERROR: %s must re-export the shared eBPF ABI" % path)


def check_p3_rust_scoped_plan_boundary():
    print("==> checking P3 Rust scoped-apply design boundary")
    plan = _read_repo_text(P3_RUST_SCOPED_PLAN_PATH)
    neutron_api_source = _read_repo_text(RUST_NEUTRON_API_PATH)
    required_markers = [
        "Status: P3-3 implementation design package",
        "SinglePort",
        "Port-scoped UDS route is implemented and advertised",
        "Keep `incremental_rpc_enabled=false` in packaged defaults",
        "`incremental_rpc_enabled=true` requires `rpc_events_enabled=true`",
        "requested_port_ids=[port_id]",
        "preserve unrelated `runtime.ports` and `runtime.port_statuses`",
        "scoped planner updates target only",
        "same generation different scoped hash",
        "No batch scoped apply",
    ]
    for marker in required_markers:
        if marker not in plan:
            raise SystemExit(
                "ERROR: P3 Rust scoped-apply plan missing marker %r" % marker
            )

    linked_docs = {
        os.path.join("docs", "openstack-neutron-aria-details", "README.md"):
            "10-rust-scoped-apply.md",
        os.path.join("docs", "openstack-neutron-aria-details", "09-aria-rpc-incremental-sync.md"):
            "10-rust-scoped-apply.md",
        os.path.join("docs", "openstack-neutron-aria-design-decisions.md"):
            "10-rust-scoped-apply.md",
    }
    for path, marker in linked_docs.items():
        if marker not in _read_repo_text(path):
            raise SystemExit(
                "ERROR: %s must link P3 Rust scoped-apply plan %s" % (path, marker)
            )

    required_source_terms = [
        "enum ApplyScope",
        "ApplyScope::FullHost",
        "ApplyScope::SinglePort",
        "struct SnapshotApplyTransaction",
        "struct SnapshotRuntimeApplyOutcome",
        "enum SnapshotScopeError",
        "fn build_snapshot_plan_for_scope(",
        "fn build_snapshot_apply_transaction(",
        "fn build_snapshot_transaction_from_plan(",
        "fn port_status_seed_for_scope(",
        "fn build_snapshot_commit_runtime(",
        "fn validate_snapshot_preflight(",
        "fn snapshot_early_response_for_scope(",
        "fn snapshot_has_runtime_drift_for_scope(",
        ".route(\n            \"/api/v1/neutron/ports/{port_id}/snapshot\"",
        "async fn put_neutron_port_snapshot(",
        "async fn apply_neutron_snapshot_for_scope(",
        "async fn apply_snapshot_runtime_transaction(",
        "fn neutron_snapshot_plan_scoped_updates_target_only(",
        "fn neutron_snapshot_plan_scoped_attaches_target_without_detaching_unrelated_ports(",
        "fn neutron_snapshot_plan_scoped_detaches_changed_target_binding_only(",
        "fn neutron_snapshot_plan_scoped_detaches_ineligible_target_only(",
        "fn neutron_snapshot_plan_scoped_ignores_non_target_body_without_mutation(",
        "fn neutron_snapshot_transaction_scoped_records_only_target_intent(",
        "fn neutron_snapshot_transaction_scoped_rejects_zero_ports_before_wal(",
        "fn neutron_snapshot_transaction_scoped_rejects_multiple_ports_before_wal(",
        "fn neutron_snapshot_transaction_scoped_rejects_path_body_mismatch_before_wal(",
        "fn neutron_snapshot_transaction_scoped_rejects_scope_widening_before_wal(",
        "fn neutron_snapshot_transaction_full_host_preserves_existing_wal_intent_shape(",
        "fn neutron_snapshot_transaction_scoped_success_preserves_unrelated_statuses(",
        "fn neutron_snapshot_transaction_scoped_failure_keeps_pending_generation(",
        "async fn neutron_snapshot_transaction_runtime_scoped_error_uses_shared_apply_body(",
        "fn neutron_snapshot_preflight_scoped_rejects_mismatch_before_idempotency(",
        "fn neutron_snapshot_preflight_schema_error_wins_before_scope_error(",
        "fn neutron_snapshot_early_response_scoped_stale_generation(",
        "fn neutron_snapshot_early_response_scoped_noop_ignores_unrelated_host_drift(",
        "fn neutron_snapshot_early_response_scoped_hash_conflict(",
        "async fn neutron_snapshot_port_route_rejects_path_body_mismatch(",
        "async fn neutron_snapshot_port_route_returns_stale_generation(",
        "async fn neutron_snapshot_port_route_returns_hash_conflict(",
        "async fn neutron_snapshot_submit_persists_intent_before_pending_response(",
        "async fn neutron_snapshot_submit_wal_intent_failure_keeps_runtime_unaccepted(",
        "fn neutron_snapshot_commit_failure_builds_blocked_bypass_runtime(",
        "async fn neutron_snapshot_background_error_preserves_blocked_recovery(",
        "async fn neutron_snapshot_post_commit_error_keeps_durable_runtime(",
        "async fn neutron_snapshot_pending_recovery_keeps_newer_wal_commit(",
        "async fn neutron_pending_recovery_rejects_mismatch_with_newer_wal_commit(",
    ]
    for term in required_source_terms:
        if term not in neutron_api_source:
            raise SystemExit(
                "ERROR: P3 Rust scoped planner source missing %s" % term
            )


def run_smoke_syntax():
    bash = shutil.which("bash")
    if not bash:
        print("SKIP: bash not found; cannot syntax-check shell smoke scripts")
        return
    for script in SMOKE_SYNTAX:
        run([bash, "-n", script.replace(os.sep, "/")])


def check_smoke_timeout_contract():
    print("==> checking smoke timeout contract")
    forbidden_terms = [
        'REQUEST_TIMEOUT_OVERRIDE="${REQUEST_TIMEOUT_OVERRIDE:-10.0}"',
        'REQUEST_TIMEOUT_OVERRIDE="${REQUEST_TIMEOUT_OVERRIDE:-20.0}"',
        "timeout=10.0",
        "request_timeout = 5",
        "request_timeout = 10",
        "request_timeout = 20",
    ]
    for script in SMOKE_SYNTAX:
        contents = _read_repo_text(script)
        for term in forbidden_terms:
            if term in contents:
                raise SystemExit(
                    "ERROR: smoke script %s uses timeout outside stage-one contract: %s"
                    % (script, term)
                )

    datapath_smoke = _read_repo_text(
        os.path.join("deploy", "kolla", "smoke", "aria_datapath_container_smoke.sh")
    )
    for term in (
        'assert int(payload.get("body_max_bytes") or 0) == 1048576',
        'assert int(payload.get("timeout_ms") or 0) == 3000',
    ):
        if term not in datapath_smoke:
            raise SystemExit(
                "ERROR: aria_datapath_container_smoke.sh must assert %s" % term
            )


def check_tc_acl_datapath_smoke_contract():
    print("==> checking TC-unified ACL real-tap smoke contract")
    if not os.path.isfile(os.path.join(ROOT, TC_ACL_DATAPATH_SMOKE_PATH)):
        raise SystemExit(
            "ERROR: TC ACL real-tap smoke is missing: %s"
            % TC_ACL_DATAPATH_SMOKE_PATH
        )
    smoke_source = _read_repo_text(TC_ACL_DATAPATH_SMOKE_PATH)
    for marker in (
        "ACL_INGRESS_HOOK_TC",
        "aria_ct_contract_packets_total",
        "ct_hit", "ct_miss", "ct_disabled", "stale_bank",
        "TRACE_FILTER",
        "XDP_NO_ACL_CT",
        "TC_INGRESS_HIT", "TC_EGRESS_HIT",
        "STATELESS_ZERO_CT",
        "NO_INGRESS_DOUBLE_COUNT",
        "TC_LINK_REQUIRED",
        "summary.json",
    ):
        if marker not in smoke_source:
            raise SystemExit("ERROR: TC ACL smoke missing %s" % marker)
    for guard in (
        ': "${EXPECTED_IFNAME:?EXPECTED_IFNAME is required}"',
        ': "${VM_IP:?VM_IP is required}"',
        'ADMIN_RC_FILE="${ADMIN_RC_FILE:-/etc/kolla/.adminrc}"',
        "trap cleanup EXIT",
    ):
        if guard not in smoke_source:
            raise SystemExit("ERROR: TC ACL smoke missing hard guard %s" % guard)
    mkdir_pos = smoke_source.index('mkdir -p "${WORK_DIR}"')
    for guard in (
        ': "${EXPECTED_IFNAME:?EXPECTED_IFNAME is required}"',
        ': "${VM_IP:?VM_IP is required}"',
    ):
        if smoke_source.index(guard) > mkdir_pos:
            raise SystemExit("ERROR: TC ACL smoke guard must precede WORK_DIR mutation")


def run_rust_tests(require_rust, toolchain):
    if not require_rust:
        print("SKIP: Rust stage-one contract tests require --require-rust")
        return
    cargo = shutil.which("cargo")
    if not cargo:
        message = "cargo not found; Rust 04/07 contract tests were not executed"
        raise SystemExit("ERROR: %s" % message)
    for cmd in RUST_TESTS:
        prefix = [cargo]
        if toolchain:
            prefix.append("+%s" % toolchain)
        run(prefix + cmd)


def main():
    parser = argparse.ArgumentParser(
        description="Run v0.9 Neutron stage-one checks for INI, UDS, and WAL contracts.",
    )
    parser.add_argument(
        "--require-rust",
        action="store_true",
        help="run Rust checks and fail when cargo is unavailable",
    )
    parser.add_argument(
        "--rust-toolchain",
        default=None,
        help="optional cargo toolchain name, for example stable",
    )
    args = parser.parse_args()

    run_python_tests()
    check_packaged_ini_contract()
    check_documented_ini_contract()
    check_uds_contract_artifact()
    check_rust_uds_contract_source()
    check_status_v1_contract()
    check_rust_stage_one_tests_present()
    check_managed_acl_publication_transaction_contract()
    check_managed_authoritative_write_admission_contract()
    check_managed_cross_domain_group_mutation_contract()
    check_managed_projection_attach_migration_contract()
    check_p3_rust_scoped_plan_boundary()
    run([sys.executable, os.path.join("ci", "check_tc_acl_datapath.py")])
    check_ebpf_acl_ingress_boundary()
    run([sys.executable, os.path.join("ci", "check_tc_acl_smoke.py")])
    run([sys.executable, os.path.join("ci", "check_standalone_tc_acl_smoke.py")])
    check_smoke_timeout_contract()
    check_tc_acl_datapath_smoke_contract()
    run_smoke_syntax()
    run_rust_tests(args.require_rust, args.rust_toolchain)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
