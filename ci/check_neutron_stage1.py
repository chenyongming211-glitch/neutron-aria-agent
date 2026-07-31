#!/usr/bin/env python3
"""Public Neutron Stage 1 contracts and CI wiring.

Rust behavior is proved by the filters in ``RUST_TESTS`` and privileged smoke
is its own evidence producer.  This checker deliberately avoids prescribing
private Rust delegation, helper layout, or local implementation spelling.
"""

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
    ["test", "--locked", "-p", "aria-core", "acl_projection_"],
    ["test", "--locked", "-p", "aria-core", "managed_projection_replay_"],
    ["test", "--locked", "-p", "aria-core", "managed_projection_inventory_"],
    ["test", "--locked", "-p", "aria-agent", "managed_projection_replay_mode_"],
    ["test", "--locked", "-p", "aria-agent", "managed_projection_inventory_handoff_"],
    ["test", "--locked", "-p", "aria-agent", "managed_projection_health_"],
    ["test", "--locked", "-p", "aria-agent", "managed_acl_shadow_"],
    ["test", "--locked", "-p", "aria-agent", "managed_general_delta_"],
    ["test", "--locked", "-p", "aria-agent", "managed_projection_repair_"],
    ["test", "--locked", "-p", "aria-agent", "managed_local_group_projection_"],
    ["test", "--locked", "-p", "aria-agent", "managed_dual_use_group_"],
    ["test", "--locked", "-p", "aria-agent", "managed_acl_ownership_"],
    ["test", "--locked", "-p", "aria-agent", "managed_projection_attach_repair_"],
    ["test", "--locked", "-p", "aria-agent", "managed_projection_outer_skip_"],
    ["test", "--locked", "-p", "aria-agent", "managed_owned_acl_strict_flush_"],
    ["test", "--locked", "-p", "aria-agent", "neutron_acl_detach_"],
    ["test", "--locked", "-p", "aria-agent", "neutron_acl_purge_failure_"],
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
    ["test", "--locked", "-p", "aria-ebpf-abi", "--features", "aya-pod"],
    ["test", "--locked", "-p", "aria-ebpf-abi", "--features", "aya-pod", "fragment_"],
    ["test", "--locked", "-p", "aria-agent", "neutron_acl_"],
    ["test", "--locked", "-p", "aria-agent", "neutron_tc_acl_"],
    ["test", "--locked", "-p", "aria-agent", "neutron_acl_runtime_transition_is_atomic"],
    ["test", "--locked", "-p", "aria-agent", "managed_runtime_activation_"],
    ["test", "--locked", "-p", "aria-agent", "neutron_acl_gate_serialization_"],
    ["test", "--locked", "-p", "aria-agent", "managed_failure_path_"],
    ["test", "--locked", "-p", "aria-agent", "standalone_acl_activation_"],
    ["test", "--locked", "-p", "aria-agent", "standalone_acl_publication_"],
    ["test", "--locked", "-p", "aria-agent", "standalone_group_transaction_"],
    ["test", "--locked", "-p", "aria-agent", "standalone_review_"],
    ["test", "--locked", "-p", "aria-agent", "tc_health_loss_"],
    ["test", "--locked", "-p", "aria-agent", "tc_health_reconcile_"],
    ["test", "--locked", "-p", "aria-agent", "tcx_attachment_"],
    ["test", "--locked", "-p", "aria-agent", "preexisting_acl_runtime_"],
    ["test", "--locked", "-p", "aria-api", "instance_info_reports_"],
    ["test", "--locked", "-p", "aria-agent", "tc_ct_contract_metric_labels_are_exact"],
    ["test", "--locked", "-p", "aria-core", "acl_ingress_hook_"],
    ["test", "--locked", "-p", "aria-core", "tap_runtime_config_"],
    ["test", "--locked", "-p", "aria-core", "fragment_epoch_"],
    ["test", "--locked", "-p", "aria-core", "fragment_observability_"],
    ["test", "--locked", "-p", "aria-agent", "fragment_loader_"],
    ["test", "--locked", "-p", "aria-ebpf-abi", "tc_ct_"],
    ["test", "--locked", "-p", "aria-core", "map_delete_"],
    ["test", "--locked", "-p", "aria-core", "quarantined_"],
    ["test", "--locked", "-p", "aria-core", "confirmed_bitmap_cleanup_"],
    ["test", "-p", "aria-agent", "startup_mode"],
]

UDS_CONTRACT_PATH = os.path.join("docs", "neutron-uds-contract.json")
STATUS_FIXTURE_PATH = os.path.join("docs", "neutron-status-contract-v1-scenarios.json")
RUST_API_PATH = os.path.join("api", "src", "lib.rs")
RUST_NEUTRON_API_PATH = os.path.join("agent", "src", "neutron_api.rs")
RUST_MAIN_PATH = os.path.join("agent", "src", "main.rs")
EBPF_ABI_PATH = os.path.join("abi", "src", "lib.rs")
EBPF_RUNTIME_PATH = os.path.join("ebpf", "src", "runtime.rs")
CORE_COMMON_PATH = os.path.join("core", "src", "common.rs")
EBPF_COMMON_PATH = os.path.join("ebpf", "src", "common.rs")
KOLLA_AGENT_INI_PATH = os.path.join("deploy", "kolla", "config", "neutron-aria-agent.ini")
KOLLA_DATAPATH_CONFIG_PATH = os.path.join("deploy", "kolla", "config", "aria-agent-openstack.toml")
TC_ACL_DATAPATH_SMOKE_PATH = os.path.join("deploy", "kolla", "smoke", "neutron_aria_acl_tc_datapath_smoke.sh")
STANDALONE_TC_ACL_SMOKE_PATH = os.path.join("deploy", "smoke", "aria_standalone_acl_tc_datapath_smoke.sh")
FRAGMENT_TRACKING_FIELD_DRIVER_PATH = os.path.join("deploy", "smoke", "lib", "fragment_tracking_field_driver.py")
SMOKE_DIR = os.path.join("deploy", "kolla", "smoke")
DOC_INI_CONTRACT_PATHS = (
    "README.md", os.path.join("docs", "openstack-neutron-agent-mode.md"),
    os.path.join("docs", "aria-acl-neutron-extension-product-design.md"),
    os.path.join("docs", "openstack-neutron-aria-design-decisions.md"),
    os.path.join("docs", "openstack-deployment-runbook.md"),
    os.path.join("docs", "neutron-managed-domains-contract.md"),
    os.path.join("docs", "openstack-neutron-aria-details", "README.md"),
    os.path.join("docs", "openstack-neutron-aria-details", "01-ini-contract.md"),
)
STATUS_VOCABULARY = {
    "transaction_states": ("idle", "pending", "classified", "blocked", "recovery"),
    "overall_readiness": ("ready", "degraded", "blocked", "unknown"),
    "required_actions": ("none", "poll", "recover_pending", "full_resync", "operator"),
    "recovery_causes": (None, "inventory_unavailable"),
    "domain_statuses": ("ready", "not_requested", "degraded", "blocked"),
    "effective_actions": ("enforce", "bypass", "unchanged", "cleanup", "no_op"),
    "support_dispositions": ("supported", "unsupported", "unknown", "not_applicable"),
}
STATUS_SCENARIOS = (
    "full-classified-ready", "scoped-classified-ready", "classified-degraded-terminal",
    "classified-degraded-full-resync", "pending-poll", "blocked-recoverable-inventory",
    "blocked-operator", "recovery-full-resync", "generation-zero-inventory-recovery",
    "legacy-v0-ready", "legacy-v0-unknown-authority", "unknown-v1-contract",
    "ready-invalid-evidence", "restart-classified-routing",
)
STATUS_PRODUCER_SCENARIOS = STATUS_SCENARIOS[:9] + ("restart-classified-routing",)


def read_text(path):
    with open(os.path.join(ROOT, path), encoding="utf-8") as handle:
        return handle.read()


def read_json(path):
    with open(os.path.join(ROOT, path), encoding="utf-8") as handle:
        return json.load(handle)


def run(command, cwd=ROOT, env=None):
    print("==> %s" % " ".join(command))
    subprocess.check_call(command, cwd=cwd, env=env)


def python_client():
    root = os.path.join(ROOT, "openstack", "neutron_aria")
    if root not in sys.path:
        sys.path.insert(0, root)
    from neutron_aria.agent import uds_client
    return uds_client


def run_python_tests():
    env = os.environ.copy()
    root = os.path.join(ROOT, "openstack", "neutron_aria")
    env["PYTHONPATH"] = root + (os.pathsep + env["PYTHONPATH"] if env.get("PYTHONPATH") else "")
    run([sys.executable, "-m", "unittest", "discover", "-s", PYTHON_TEST_ROOT, "-p", "test_*.py"], env=env)


def run_neutronclient_extension_tests():
    env = os.environ.copy()
    root = os.path.join(ROOT, "openstack", "neutronclient_aria")
    env["PYTHONPATH"] = root + (
        os.pathsep + env["PYTHONPATH"] if env.get("PYTHONPATH") else ""
    )
    run([
        sys.executable,
        "-m",
        "unittest",
        "neutronclient_aria.tests.test_aria_acl_cli",
    ], env=env)


def rust_test_filter(command):
    package = command.index("-p") + 2
    tail = command[package:]
    if not tail or tail[0].startswith("--"):
        return None
    return tail[0]


def discovered_rust_test_names():
    names = set()
    pattern = re.compile(
        r"#\s*\[\s*(?:tokio\s*::\s*)?test\s*\]"
        r"(?:\s*#\s*\[[^\]]+\])*\s*"
        r"(?:pub\s+)?(?:async\s+)?fn\s+([A-Za-z_][A-Za-z0-9_]*)",
        re.MULTILINE,
    )
    for current, directories, files in os.walk(ROOT):
        directories[:] = [name for name in directories if name not in {".git", "target", ".downloads"}]
        for filename in files:
            if filename.endswith(".rs"):
                with open(os.path.join(current, filename), encoding="utf-8") as handle:
                    names.update(pattern.findall(handle.read()))
    return names


def check_rust_test_discovery():
    """Ensure every configured Cargo filter selects a real Rust test name."""
    print("==> checking Rust behavior-test discovery")
    names = discovered_rust_test_names()
    missing = []
    for command in RUST_TESTS:
        test_filter = rust_test_filter(command)
        if test_filter and not any(test_filter in name for name in names):
            missing.append(test_filter)
    if missing:
        raise SystemExit("ERROR: Rust behavior filters match no test function: %s" % ", ".join(missing))


def check_uds_contract_artifact():
    print("==> checking public Neutron UDS contract")
    uds = python_client()
    contract = read_json(UDS_CONTRACT_PATH)
    expected = {
        "api_version": uds.NEUTRON_API_VERSION,
        "contract_version": uds.NEUTRON_CONTRACT_VERSION,
        "schema_version_min": uds.NEUTRON_SCHEMA_VERSION,
        "schema_version_max": uds.NEUTRON_SCHEMA_VERSION,
        "attach_authority": uds.NEUTRON_ATTACH_AUTHORITY,
        "supports_full_snapshot": True,
        "supports_port_scoped_snapshot": True,
        "supports_port_delete": True,
        "body_max_bytes": uds.NEUTRON_BODY_MAX_BYTES,
        "timeout_ms": uds.NEUTRON_TIMEOUT_MS,
        "error_codes_hash": uds.NEUTRON_ERROR_CODES_HASH,
        "capability_hash": uds.NEUTRON_CAPABILITY_HASH,
    }
    for name, value in expected.items():
        if contract.get(name) != value:
            raise SystemExit("ERROR: UDS contract %s expected %r, got %r" % (name, value, contract.get(name)))
    if contract.get("supported_domains") != ["attach", "acl"] or not contract.get("peer_auth_policy"):
        raise SystemExit("ERROR: UDS contract must retain supported attach/acl domains and peer auth policy")
    routes = {(item.get("method"), item.get("path")) for item in contract.get("routes", [])}
    required_routes = {
        ("GET", "/api/v1/neutron/capabilities"), ("GET", "/api/v1/neutron/status"),
        ("PUT", "/api/v1/neutron/snapshot"), ("PUT", "/api/v1/neutron/ports/{port_id}/snapshot"),
        ("DELETE", "/api/v1/neutron/ports/{port_id}"),
    }
    if not required_routes.issubset(routes):
        raise SystemExit("ERROR: UDS contract routes are incomplete")
    errors = {item.get("code"): item for item in contract.get("error_codes", [])}
    for code in ("UDS_SCHEMA_MISMATCH", "UDS_BODY_TOO_LARGE", "generation_hash_conflict", "stale_generation"):
        if errors.get(code, {}).get("phase") != "implemented":
            raise SystemExit("ERROR: UDS contract error %s must be implemented" % code)


def rust_const(source, name):
    match = re.search(r"\bpub\s+const\s+%s\s*:[^=]+?=\s*([^;]+);" % re.escape(name), source)
    if not match:
        raise SystemExit("ERROR: public Rust constant %s is missing" % name)
    return match.group(1).strip().strip('"')


def check_rust_uds_contract_source():
    print("==> checking public Rust UDS wire constants")
    contract = read_json(UDS_CONTRACT_PATH)
    source = read_text(RUST_API_PATH)
    constants = {
        "api_version": "NEUTRON_UDS_API_VERSION", "contract_version": "NEUTRON_UDS_CONTRACT_VERSION",
        "schema_version_min": "NEUTRON_UDS_SCHEMA_VERSION_MIN", "schema_version_max": "NEUTRON_UDS_SCHEMA_VERSION_MAX",
        "attach_authority": "NEUTRON_ATTACH_AUTHORITY", "body_max_bytes": "NEUTRON_UDS_BODY_MAX_BYTES",
        "timeout_ms": "NEUTRON_UDS_TIMEOUT_MS", "error_codes_hash": "NEUTRON_UDS_ERROR_CODES_HASH",
        "peer_auth_policy": "NEUTRON_UDS_PEER_AUTH_POLICY", "capability_hash": "NEUTRON_UDS_CAPABILITY_HASH",
    }
    for field, constant in constants.items():
        value = rust_const(source, constant)
        try:
            value = int(value)
        except ValueError:
            pass
        if contract.get(field) != value:
            raise SystemExit("ERROR: Rust UDS constant %s does not match contract field %s" % (constant, field))
    if contract.get("supported_domains") != ["attach", "acl"]:
        raise SystemExit("ERROR: public UDS domain schema drifted")
    router = read_text(RUST_NEUTRON_API_PATH)
    for route in (
        '"/api/v1/neutron/capabilities"', '"/api/v1/neutron/status"',
        '"/api/v1/neutron/snapshot/recover-pending"', '"/api/v1/neutron/snapshot"',
        '"/api/v1/neutron/ports/{port_id}/snapshot"', '"/api/v1/neutron/ports/{port_id}"',
    ):
        if route not in router:
            raise SystemExit("ERROR: public Neutron UDS route is missing: %s" % route)
    for wire_term in (
        "DefaultBodyLimit::max(NEUTRON_UDS_BODY_MAX_BYTES as usize)",
        "UDS_SCHEMA_MISMATCH", "supports_port_scoped_snapshot: bool",
        "supports_port_scoped_snapshot: true",
    ):
        if wire_term not in router and wire_term not in source:
            raise SystemExit("ERROR: public Neutron UDS wire contract missing %s" % wire_term)
    client = read_text(os.path.join("openstack", "neutron_aria", "neutron_aria", "agent", "uds_client.py"))
    if "UDS_BODY_TOO_LARGE" not in client:
        raise SystemExit("ERROR: Python UDS client must expose UDS_BODY_TOO_LARGE")
    peercred = read_text(RUST_MAIN_PATH)
    for term in ("neutron_peercred_enforce", "neutron_peercred_allowed_uids", "neutron_peercred_allowed_gids", "SO_PEERCRED", "UDS_PEER_UNAUTHORIZED", "UDS_PEERCRED_UNAVAILABLE", "neutron_uds_peer_auth"):
        if term not in peercred:
            raise SystemExit("ERROR: public UDS peercred contract missing %s" % term)


def public_enum_variants(source, name):
    match = re.search(r"#\[serde\(rename_all = \"snake_case\"\)\]\s*pub enum %s\s*\{(?P<body>.*?)\}" % re.escape(name), source, re.DOTALL)
    if not match:
        raise SystemExit("ERROR: public Status enum %s is missing snake_case wire schema" % name)
    return tuple(re.findall(r"^\s*([A-Za-z][A-Za-z0-9_]*)\s*,", match.group("body"), re.MULTILINE))


def producer_scenario_ids(source):
    match = re.search(r"fn\s+rust_status_v1_scenario_ids\s*\([^)]*\)\s*->[^\{]*\{\s*&\[(?P<ids>.*?)\]\s*\}", source, re.DOTALL)
    if not match:
        raise SystemExit("ERROR: Status V1 producer scenario inventory is missing")
    return tuple(re.findall(r'"([^"]+)"', match.group("ids")))


def check_status_v1_contract():
    print("==> checking Status V1 schema")
    contract = read_json(UDS_CONTRACT_PATH)
    fixture = read_json(STATUS_FIXTURE_PATH)
    expected_contract = {
        "status_schema_version_min": 1, "status_schema_version_max": 1,
        "status_contract_hash": "v0.9-neutron-status-1", "status_contract_scenarios_path": STATUS_FIXTURE_PATH,
    }
    for field, value in expected_contract.items():
        if contract.get(field) != value:
            raise SystemExit("ERROR: Status V1 contract field %s drifted" % field)
    if set(fixture) != {"fixture_schema_version", "status_contract", "scenarios"} or fixture.get("fixture_schema_version") != 1:
        raise SystemExit("ERROR: Status V1 fixture root schema drifted")
    schema = fixture.get("status_contract")
    if not isinstance(schema, dict) or schema.get("version") != 1 or schema.get("hash") != "v0.9-neutron-status-1":
        raise SystemExit("ERROR: Status V1 fixture contract metadata drifted")
    for name, values in STATUS_VOCABULARY.items():
        if tuple(schema.get(name, ())) != values:
            raise SystemExit("ERROR: Status V1 vocabulary %s drifted" % name)
    scenarios = fixture.get("scenarios")
    if not isinstance(scenarios, list) or tuple(item.get("id") for item in scenarios if isinstance(item, dict)) != STATUS_SCENARIOS:
        raise SystemExit("ERROR: Status V1 scenario inventory drifted")
    for index, scenario in enumerate(scenarios, 1):
        if not isinstance(scenario, dict) or scenario.get("minimum_scenario") != index:
            raise SystemExit("ERROR: Status V1 scenario ordering drifted")
        status = scenario.get("status")
        if isinstance(status, dict) and status.get("status_schema_version") not in (None, 1):
            raise SystemExit("ERROR: Status V1 scenario status schema drifted")
    api = read_text(RUST_API_PATH)
    for constant, expected in (("NEUTRON_STATUS_SCHEMA_VERSION_MIN", "1"), ("NEUTRON_STATUS_SCHEMA_VERSION_MAX", "1"), ("NEUTRON_STATUS_CONTRACT_HASH", "v0.9-neutron-status-1")):
        if rust_const(api, constant) != expected:
            raise SystemExit("ERROR: public Rust Status constant %s drifted" % constant)
    expected_enums = {
        "NeutronStatusTransactionState": ("Idle", "Pending", "Classified", "Blocked", "Recovery"),
        "NeutronStatusOverallReadiness": ("Ready", "Degraded", "Blocked", "Unknown"),
        "NeutronStatusRequiredAction": ("None", "Poll", "RecoverPending", "FullResync", "Operator"),
        "NeutronStatusRecoveryCause": ("InventoryUnavailable",),
        "NeutronStatusDomainState": ("Ready", "NotRequested", "Degraded", "Blocked"),
        "NeutronStatusEffectiveAction": ("Enforce", "Bypass", "Unchanged", "Cleanup", "NoOp"),
        "NeutronStatusSupportDisposition": ("Supported", "Unsupported", "Unknown", "NotApplicable"),
    }
    for name, expected in expected_enums.items():
        if public_enum_variants(api, name) != expected:
            raise SystemExit("ERROR: public Rust Status enum %s drifted" % name)
    for path in (RUST_API_PATH, RUST_NEUTRON_API_PATH):
        if producer_scenario_ids(read_text(path)) != STATUS_PRODUCER_SCENARIOS:
            raise SystemExit("ERROR: Status V1 producer scenarios drifted in %s" % path)


def check_packaged_ini_contract():
    print("==> checking packaged Neutron agent configuration")
    uds = python_client()
    del uds
    from neutron_aria.agent.config import load_config
    config = load_config(os.path.join(ROOT, KOLLA_AGENT_INI_PATH))
    expected = {"managed_domains": ["acl"], "ovs_bridge": "br-int", "request_timeout": 3.0,
                "acl_source": "disabled", "full_resync_enabled": False, "port_source": "disabled",
                "rpc_events_enabled": False, "incremental_rpc_enabled": False}
    for name, value in expected.items():
        if getattr(config, name) != value:
            raise SystemExit("ERROR: packaged configuration %s drifted" % name)
    contents = read_text(KOLLA_AGENT_INI_PATH)
    if "integration_mode" in contents or "integration_bridge = br-int" not in contents:
        raise SystemExit("ERROR: packaged OVS configuration drifted")
    datapath = read_text(KOLLA_DATAPATH_CONFIG_PATH)
    for term in ("neutron_socket_mode = 432", "neutron_peercred_enforce = false", "neutron_peercred_allowed_uids = []", "neutron_peercred_allowed_gids = []", "neutron_audit_log_path"):
        if term not in datapath:
            raise SystemExit("ERROR: packaged datapath configuration missing %s" % term)


def check_documented_ini_contract():
    print("==> checking documented public configuration")
    forbidden_lines = {"integration_mode = coexist", "full_resync_interval = 300", "acl_source = neutron",
                       "local_api = unix:///run/aria/aria-agent.sock", "enable_acl = true", "enable_qos = true",
                       "request_timeout = 5", "contract_file = /etc/neutron-aria-agent/neutron-uds-contract.json"}
    forbidden_terms = {"`body_max_bytes`：第一阶段固定为 `10485760`", "`request_timeout_ms`",
                       "`connect_timeout_ms`", "`SNAPSHOT_TOO_LARGE`", "agent/src/neutron_contract.rs",
                       "agent/src/api_handlers/neutron.rs", "agent/src/control_plane/neutron_snapshot.rs"}
    for path in DOC_INI_CONTRACT_PATHS:
        contents = read_text(path)
        if any(term in contents for term in forbidden_terms) or any(
            line.strip() in forbidden_lines for line in contents.splitlines()
        ):
            raise SystemExit("ERROR: obsolete public configuration contract in %s" % path)


def check_ebpf_abi_contract():
    print("==> checking public eBPF ACL ABI")
    abi = read_text(EBPF_ABI_PATH)
    required = (
        r"pub\s+const\s+ACL_INGRESS_HOOK_XDP\s*:\s*u8\s*=\s*0\s*;",
        r"pub\s+const\s+ACL_INGRESS_HOOK_TC\s*:\s*u8\s*=\s*1\s*;",
        r"pub\s+acl_ingress_hook\s*:\s*u8\s*,",
    )
    if any(not re.search(pattern, abi) for pattern in required):
        raise SystemExit("ERROR: public eBPF ACL ABI drifted")
    if re.search(r"\bfn\s+acl_ingress_hook\s*\(", read_text(EBPF_RUNTIME_PATH)):
        raise SystemExit("ERROR: eBPF runtime must not expose acl_ingress_hook")
    if "pub use aria_ebpf_abi::userspace::*;" not in read_text(CORE_COMMON_PATH) or "pub use aria_ebpf_abi::*;" not in read_text(EBPF_COMMON_PATH):
        raise SystemExit("ERROR: shared eBPF ABI re-export drifted")


def smoke_scripts():
    scripts = sorted(os.path.join(SMOKE_DIR, name) for name in os.listdir(os.path.join(ROOT, SMOKE_DIR)) if name.endswith(".sh"))
    return scripts + [STANDALONE_TC_ACL_SMOKE_PATH]


def check_public_smoke_entrypoints():
    print("==> checking public smoke entrypoints")
    for path in (TC_ACL_DATAPATH_SMOKE_PATH, STANDALONE_TC_ACL_SMOKE_PATH):
        if not os.path.isfile(os.path.join(ROOT, path)):
            raise SystemExit("ERROR: public smoke entrypoint is missing: %s" % path)


def run_smoke_syntax():
    bash = shutil.which("bash")
    if not bash:
        print("SKIP: bash not found; cannot syntax-check smoke scripts")
        return
    for path in smoke_scripts():
        run([bash, "-n", path])

def run_fragment_tracking_field_driver_self_test():
    print("==> checking fragment tracking field driver")
    run([sys.executable, FRAGMENT_TRACKING_FIELD_DRIVER_PATH, "--self-test"])


def run_fast_contracts():
    run_python_tests()
    run_neutronclient_extension_tests()
    check_packaged_ini_contract()
    check_documented_ini_contract()
    check_uds_contract_artifact()
    check_public_smoke_entrypoints()
    run_smoke_syntax()
    run_fragment_tracking_field_driver_self_test()


def run_rust_tests(toolchain):
    check_rust_test_discovery()
    cargo = shutil.which("cargo")
    if not cargo:
        raise SystemExit("ERROR: cargo not found; Rust behavior tests were not executed")
    for cmd in RUST_TESTS:
        prefix = [cargo] + (["+%s" % toolchain] if toolchain else [])
        run(prefix + cmd)


def main():
    parser = argparse.ArgumentParser(description="Run public v0.9 Neutron Stage 1 contracts.")
    parser.add_argument("--require-rust", action="store_true", help="also run Rust behavior-test discovery")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--fast-contracts", action="store_true", help="run public Python, config, UDS, and smoke-entrypoint contracts")
    mode.add_argument("--rust-tests-only", action="store_true", help="run only the configured Rust behavior tests")
    parser.add_argument("--rust-toolchain", default=None, help="optional cargo toolchain name")
    args = parser.parse_args()
    if args.fast_contracts:
        run_fast_contracts()
        return 0
    if args.rust_tests_only:
        run_rust_tests(args.rust_toolchain)
        return 0
    run_fast_contracts()
    check_rust_test_discovery()
    check_rust_uds_contract_source()
    check_status_v1_contract()
    check_ebpf_abi_contract()
    run([sys.executable, os.path.join("ci", "check_tc_acl_smoke.py")])
    run([sys.executable, os.path.join("ci", "check_standalone_tc_acl_smoke.py")])
    if args.require_rust:
        run_rust_tests(args.rust_toolchain)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
