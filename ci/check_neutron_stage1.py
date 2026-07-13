#!/usr/bin/env python3
from __future__ import print_function

import argparse
import json
import os
import re
import shutil
import subprocess
import sys


ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir))


PYTHON_TEST_ROOT = os.path.join(
    "openstack", "neutron_aria", "neutron_aria", "tests", "unit"
)


RUST_TESTS = [
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
SMOKE_SYNTAX = sorted(
    os.path.join(SMOKE_DIR, name)
    for name in os.listdir(os.path.join(ROOT, SMOKE_DIR))
    if name.endswith(".sh")
)

UDS_CONTRACT_PATH = os.path.join("docs", "neutron-uds-contract.json")
P3_RUST_SCOPED_PLAN_PATH = os.path.join(
    "docs", "openstack-neutron-aria-details", "10-rust-scoped-apply.md"
)
RUST_API_PATH = os.path.join("api", "src", "lib.rs")
RUST_NEUTRON_API_PATH = os.path.join("agent", "src", "neutron_api.rs")
RUST_NEUTRON_WAL_PATH = os.path.join("agent", "src", "neutron_wal.rs")
RUST_OPENAPI_PATH = os.path.join("agent", "src", "openapi.rs")
CORE_COMMON_PATH = os.path.join("core", "src", "common.rs")
EBPF_COMMON_PATH = os.path.join("ebpf", "src", "common.rs")
EBPF_RUNTIME_PATH = os.path.join("ebpf", "src", "runtime.rs")
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
    _run_rust_function_body_parser_self_tests()
    neutron_api_source = _read_repo_text(RUST_NEUTRON_API_PATH)
    wal_source = _read_repo_text(RUST_NEUTRON_WAL_PATH)
    openapi_source = _read_repo_text(RUST_OPENAPI_PATH)
    ebpf_common_source = _read_repo_text(EBPF_COMMON_PATH)
    build_workflow_source = _read_repo_text(BUILD_WORKFLOW_PATH)
    control_plane_source = _read_repo_text(os.path.join("agent", "src", "control_plane.rs"))
    tap_registry_source = _read_repo_text(os.path.join("agent", "src", "tap_registry.rs"))

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
    if "if !plan.policies.is_empty() {" not in acl_reconcile_body[:readiness]:
        raise SystemExit(
            "ERROR: Neutron TC ACL readiness must be conditional on non-empty policies"
        )
    if ".update_config(" in acl_reconcile_body:
        raise SystemExit(
            "ERROR: Neutron ACL gate writes must use update_neutron_acl_runtime_gate"
        )
    if acl_reconcile_body.count(".update_neutron_acl_runtime_gate(") != 4:
        raise SystemExit(
            "ERROR: Neutron ACL quiesce, publish, and compensation must use atomic gate writes"
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
    if len(registry_gate_calls) != 4:
        raise SystemExit(
            "ERROR: all four Neutron ACL gate writes must use TapRegistry lifecycle serialization"
        )

    registry_gate_body = _rust_function_body(
        tap_registry_source, "update_neutron_acl_runtime_gate"
    )
    if registry_gate_body is None:
        raise SystemExit("ERROR: TapRegistry serialized ACL gate writer missing")
    lifecycle_lock = re.search(
        r"let\s+_runtime_guard\s*=\s*self\s*\.\s*runtime_lock\s*\.\s*lock\s*\(\s*\)\s*\.\s*await\s*;",
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
            "ERROR: TapRegistry ACL gate writer must hold runtime_lock across the serialized control-plane call"
        )

    for lifecycle_function in ("attach_with_mode", "detach"):
        lifecycle_body = _rust_function_body(tap_registry_source, lifecycle_function)
        if lifecycle_body is None or not re.search(
            r"self\s*\.\s*runtime_lock\s*\.\s*lock\s*\(\s*\)\s*\.\s*await",
            lifecycle_body,
        ):
            raise SystemExit(
                "ERROR: managed lifecycle function %s must use runtime_lock"
                % lifecycle_function
            )
    reconcile_runtime_body = _rust_function_body(
        tap_registry_source, "reconcile_neutron_runtime"
    )
    orphan_lock = re.search(
        r"let\s+_runtime_guard\s*=\s*self\s*\.\s*runtime_lock\s*\.\s*lock\s*\(\s*\)\s*\.\s*await\s*;",
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
            "ERROR: orphaned managed link removal must use runtime_lock"
        )

    serialized_gate_body = _rust_function_body(
        control_plane_source, "update_neutron_acl_runtime_gate_serialized"
    )
    if serialized_gate_body is None:
        raise SystemExit("ERROR: serialized control-plane ACL gate writer missing")
    readiness_match = re.search(
        r"\.\s*require_tc_acl_links\s*\(", serialized_gate_body
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
            "ERROR: serialized enabling ACL gate writer must recheck TC immediately before the map write"
        )
    readiness_window = serialized_gate_body[
        readiness_match.start():gate_write_match.start()
    ]
    if ".await" in readiness_window or re.search(r"\bdrop\s*\(", readiness_window):
        raise SystemExit(
            "ERROR: await or unlock window exists between serialized TC readiness and ACL gate write"
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
        ebpf_common_source,
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


def check_ebpf_acl_ingress_boundary():
    print("==> checking eBPF ACL ingress boundary")
    _run_acl_ingress_parser_self_tests()
    runtime_source = _read_repo_text(EBPF_RUNTIME_PATH)
    if _has_acl_ingress_hook_definition(runtime_source):
        raise SystemExit("ERROR: eBPF runtime must not expose acl_ingress_hook")

    for path in (CORE_COMMON_PATH, EBPF_COMMON_PATH):
        common_source = _read_repo_text(path)
        missing = _missing_acl_ingress_abi(common_source)
        if missing:
            raise SystemExit(
                "ERROR: %s compatibility ABI missing %s"
                % (path, ", ".join(missing))
            )


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
    cargo = shutil.which("cargo")
    if not cargo:
        message = "cargo not found; Rust 04/07 contract tests were not executed"
        if require_rust:
            raise SystemExit("ERROR: %s" % message)
        print("SKIP: %s" % message)
        return
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
        help="fail when cargo is unavailable instead of skipping Rust checks",
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
    check_rust_stage_one_tests_present()
    check_p3_rust_scoped_plan_boundary()
    run([sys.executable, os.path.join("ci", "check_tc_acl_datapath.py")])
    check_ebpf_acl_ingress_boundary()
    run([sys.executable, os.path.join("ci", "check_tc_acl_smoke.py")])
    check_smoke_timeout_contract()
    check_tc_acl_datapath_smoke_contract()
    run_smoke_syntax()
    run_rust_tests(args.require_rust, args.rust_toolchain)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
