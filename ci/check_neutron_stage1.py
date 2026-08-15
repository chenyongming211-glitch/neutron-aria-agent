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
import unittest


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
    ["test", "--locked", "-p", "aria-agent", "snapshot_generation_retry_"],
    ["test", "--locked", "-p", "aria-agent", "neutron_snapshot"],
    ["test", "--locked", "-p", "aria-agent", "neutron_pending_recovery"],
    ["test", "--locked", "-p", "aria-agent", "domain_authority"],
    ["test", "--locked", "-p", "aria-agent", "peercred_policy"],
    ["test", "--locked", "-p", "aria-agent", "management_listener_"],
    ["test", "--locked", "-p", "aria-agent", "neutron_readiness_"],
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
    ["test", "--locked", "-p", "aria-agent", "xdp_link_identity_"],
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
    ["test", "--locked", "-p", "aria-core", "local_projection_recovery_"],
    ["test", "--locked", "-p", "aria-core", "atomic_state_file_"],
    ["test", "--locked", "-p", "aria-core", "wal_checkpoint_"],
    ["test", "--locked", "-p", "aria-core", "scrub_iteration_"],
    ["test", "--locked", "-p", "aria-core", "ct_contract_stats_iteration_"],
    ["test", "--locked", "-p", "aria-core", "port_counters_"],
    ["test", "--locked", "-p", "aria-core", "wal_inventory_"],
    ["test", "--locked", "-p", "aria-agent", "local_projection_"],
    ["test", "--locked", "-p", "aria-agent", "standalone_qos_both_"],
    ["test", "--locked", "-p", "aria-agent", "standalone_mirror_both_"],
    ["test", "--locked", "-p", "aria-agent", "managed_startup_recovery_"],
    ["test", "--locked", "-p", "aria-agent", "standalone_start_clears_"],
    ["test", "--locked", "-p", "ariactl", "api_client_path_segment_"],
    ["test", "--locked", "-p", "aria-agent", "startup_config_"],
    ["test", "-p", "aria-agent", "startup_mode"],
]

REQUIRED_PYTHON_BEHAVIORS = (
    "neutron_aria.tests.unit.test_agent_inventory.AgentInventoryTestCase."
    "test_snapshot_marks_only_regular_ovs_vm_tap_eligible",
    "neutron_aria.tests.unit.test_config.ConfigTestCase."
    "test_rejects_unimplemented_qos_and_mirror_managed_domains",
    "neutron_aria.tests.unit.test_config.ConfigTestCase."
    "test_counters_report_enabled_defaults_false",
    "neutron_aria.tests.unit.test_counter_sampler.CounterSamplerTestCase."
    "test_first_snapshot_has_no_rates",
    "neutron_aria.tests.unit.test_counter_sampler.CounterSamplerTestCase."
    "test_negative_delta_is_reset_and_rates_are_none",
    "neutron_aria.tests.unit.test_event_loop.EventLoopTestCase."
    "test_full_resync_builds_and_submits_snapshot",
    "neutron_aria.tests.unit.test_event_loop.EventLoopTestCase."
    "test_full_resync_rejects_missing_runtime_acl_status",
    "neutron_aria.tests.unit.test_event_merge.EventMergerTestCase."
    "test_aria_acl_domain_update_requests_full_resync",
    "neutron_aria.tests.unit.test_service.AgentServiceTestCase."
    "test_heartbeat_only_initialize_reports_degraded_without_resync",
    "neutron_aria.tests.unit.test_state.SnapshotStateStoreTestCase."
    "test_pending_generation_survives_restart",
    "neutron_aria.tests.unit.test_status_reporter.StatusReporterTestCase."
    "test_global_degraded_rewrites_cached_acl_rows_to_bypass",
    "neutron_aria.tests.unit.test_uds_client.UdsClientTestCase."
    "test_capabilities_validates_required_domains",
    "neutron_aria.tests.unit.test_uds_client.UdsClientTestCase."
    "test_capabilities_rejects_missing_domain",
    "neutron_aria.tests.unit.test_uds_client.UdsClientTestCase."
    "test_status_v3_counters_section_is_preserved",
    "neutron_aria.tests.unit.test_uds_client.UdsClientTestCase."
    "test_status_v3_without_counters_still_decodes",
    "neutron_aria.tests.unit.test_aria_acl_plugin.AriaAclPluginTestCase."
    "test_legacy_port_read_wrapper_batches_projection_and_preserves_fields",
    "neutron_aria.tests.unit.test_aria_acl_plugin.AriaAclPluginTestCase."
    "test_legacy_port_show_wrapper_projects_before_field_selection",
    "neutron_aria.tests.unit.test_aria_acl_plugin.AriaAclPluginTestCase."
    "test_port_projection_failure_does_not_break_core_port_show",
)

UDS_CONTRACT_PATH = os.path.join("docs", "neutron-uds-contract.json")
STATUS_FIXTURE_PATH = "docs/neutron-status-contract-v1-scenarios.json"
STATUS_V2_FIXTURE_PATH = "docs/neutron-status-contract-v2-scenarios.json"
STATUS_V3_FIXTURE_PATH = "docs/neutron-status-contract-v3-scenarios.json"
DOMAIN_STATUS_DOC_PATH = os.path.join(
    "docs", "openstack-neutron-aria-details", "05-domain-status-heartbeat.md"
)
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
PUBLIC_UDS_ROUTES = (
    ("GET", "/readyz", "get", "/readyz"),
    ("GET", "/api/v1/neutron/capabilities", "get", "/api/v1/neutron/capabilities"),
    ("GET", "/api/v1/neutron/status", "get", "/api/v1/neutron/status"),
    (
        "POST",
        "/api/v1/neutron/snapshot/recover-pending",
        "post",
        "/api/v1/neutron/snapshot/recover-pending",
    ),
    ("PUT", "/api/v1/neutron/snapshot", "put", "/api/v1/neutron/snapshot"),
    (
        "PUT",
        "/api/v1/neutron/ports/{port_id}/snapshot",
        "put",
        "/api/v1/neutron/ports/%s/snapshot",
    ),
    (
        "DELETE",
        "/api/v1/neutron/ports/{port_id}",
        "delete",
        "/api/v1/neutron/ports/%s",
    ),
)
RECOVER_PENDING_RESPONSE_FIELDS = {
    "status", "recovered_generation", "desired_hash", "applied_generation",
    "applied_desired_hash", "authority_state", "wal_status",
}
RECOVER_PENDING_ERROR_STATUS = {
    "unsupported_pending_recovery_mode": 400,
    "no_applied_snapshot_to_restore": 409,
    "pending_snapshot_still_active": 409,
    "no_pending_snapshot": 409,
    "pending_generation_mismatch": 409,
    "pending_desired_hash_mismatch": 409,
    "pending_recovery_commit_failed": 500,
}


def read_text(path):
    with open(os.path.join(ROOT, path), encoding="utf-8") as handle:
        return handle.read()


def read_json(path):
    with open(os.path.join(ROOT, path), encoding="utf-8") as handle:
        return json.load(handle)


def run(command, cwd=ROOT, env=None):
    print("==> %s" % " ".join(command))
    subprocess.check_call(command, cwd=cwd, env=env)


def bash_path(*parts):
    return os.path.join(*parts).replace(os.sep, "/")


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


def _iter_test_cases(suite):
    for item in suite:
        if isinstance(item, unittest.TestSuite):
            for nested in _iter_test_cases(item):
                yield nested
        else:
            yield item


def discovered_python_test_ids():
    """Return IDs discovered by the same public test tree used by CI."""
    top_level = os.path.join(ROOT, "openstack", "neutron_aria")
    suite = unittest.defaultTestLoader.discover(
        os.path.join(ROOT, PYTHON_TEST_ROOT),
        pattern="test_*.py",
        top_level_dir=top_level,
    )
    return set(test.id() for test in _iter_test_cases(suite))


def check_required_python_behaviors():
    print("==> checking required Neutron Python behavior discovery")
    missing = set(REQUIRED_PYTHON_BEHAVIORS) - discovered_python_test_ids()
    if missing:
        raise SystemExit(
            "ERROR: required Python behaviors are absent from full discovery: %s"
            % ", ".join(sorted(missing))
        )


def _normalized_domain_set(values, label):
    if not isinstance(values, (list, tuple)):
        raise SystemExit("ERROR: %s domains must be a list" % label)
    normalized = []
    for value in values:
        if not isinstance(value, str) or not value.strip():
            raise SystemExit("ERROR: %s contains an invalid domain" % label)
        domain = value.strip().lower()
        if domain in normalized:
            raise SystemExit("ERROR: %s contains duplicate domain %s" % (label, domain))
        normalized.append(domain)
    return set(normalized)


def validate_python_managed_domain_contract(advertised, python_supported, requested):
    advertised_set = _normalized_domain_set(advertised, "advertised")
    python_set = _normalized_domain_set(python_supported, "Python supported")
    requested_set = _normalized_domain_set(requested, "requested")
    unsupported_python = python_set - advertised_set
    if unsupported_python:
        raise SystemExit(
            "ERROR: Python managed domains are not advertised: %s"
            % ", ".join(sorted(unsupported_python))
        )
    unsupported_requested = requested_set - python_set
    if unsupported_requested:
        raise SystemExit(
            "ERROR: packaged requested domains are not Python-supported: %s"
            % ", ".join(sorted(unsupported_requested))
        )


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
        "error_codes_hash": uds.NEUTRON_ERROR_CODES_HASH_V2,
        "capability_hash": uds.NEUTRON_CAPABILITY_HASH_V3,
        "counters_v1": True,
    }
    for name, value in expected.items():
        if contract.get(name) != value:
            raise SystemExit("ERROR: UDS contract %s expected %r, got %r" % (name, value, contract.get(name)))
    if contract.get("supported_domains") != ["attach", "acl"] or not contract.get("peer_auth_policy"):
        raise SystemExit("ERROR: UDS contract must retain supported attach/acl domains and peer auth policy")
    from neutron_aria.agent.config import SUPPORTED_MANAGED_DOMAINS, load_config
    packaged = load_config(os.path.join(ROOT, KOLLA_AGENT_INI_PATH))
    validate_python_managed_domain_contract(
        contract.get("supported_domains"),
        SUPPORTED_MANAGED_DOMAINS,
        packaged.managed_domains,
    )
    route_rows = contract.get("routes", [])
    route_index = {
        (item.get("method"), item.get("path")): item
        for item in route_rows
        if isinstance(item, dict)
    }
    expected_routes = {(method, path) for method, path, _verb, _client in PUBLIC_UDS_ROUTES}
    if len(route_index) != len(route_rows) or set(route_index) != expected_routes:
        raise SystemExit("ERROR: UDS contract route inventory drifted")
    recover_key = ("POST", "/api/v1/neutron/snapshot/recover-pending")
    recover = route_index[recover_key]
    request = recover.get("request_schema", {})
    request_fields = request.get("properties", {})
    success = recover.get("success_schema", {})
    error = recover.get("error_schema", {})
    compatibility = recover.get("compatibility", {})
    if (
        request.get("type") != "object"
        or request.get("required") != ["expected_pending_generation"]
        or set(request_fields) != {
            "expected_pending_generation", "expected_desired_hash", "mode",
        }
        or request_fields.get("mode", {}).get("default") != "rollback_to_last_applied"
        or success.get("http_status") != 200
        or set(success.get("status_values", [])) != {"recovered", "already_committed"}
        or set(success.get("required", [])) != RECOVER_PENDING_RESPONSE_FIELDS
        or error.get("required") != ["error", "details"]
        or error.get("status_by_code") != RECOVER_PENDING_ERROR_STATUS
        or set(compatibility) != {
            "mode_omitted_or_null", "identity_guard", "already_committed", "versioning",
        }
    ):
        raise SystemExit("ERROR: recover-pending request/response/error contract drifted")

    router = read_text(RUST_NEUTRON_API_PATH)
    client = read_text(
        os.path.join("openstack", "neutron_aria", "neutron_aria", "agent", "uds_client.py")
    )
    for method, path, rust_verb, client_path in PUBLIC_UDS_ROUTES:
        rust_route = re.compile(
            r'\.route\(\s*"%s"\s*,\s*%s\('
            % (re.escape(path), rust_verb)
        )
        python_route = re.compile(
            r'_request\(\s*"%s"\s*,\s*"%s"'
            % (method, re.escape(client_path))
        )
        if not rust_route.search(router) or not python_route.search(client):
            raise SystemExit(
                "ERROR: public UDS route parity drifted for %s %s" % (method, path)
            )
    errors = {item.get("code"): item for item in contract.get("error_codes", [])}
    for code in (
        "UDS_SCHEMA_MISMATCH",
        "UDS_BODY_TOO_LARGE",
        "generation_hash_conflict",
        "stale_generation",
        "INVALID_SNAPSHOT_GENERATION",
        "snapshot_apply_in_progress",
        "snapshot_retry_not_safe",
    ):
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
    print("==> checking versioned Status schemas")
    contract = read_json(UDS_CONTRACT_PATH)
    fixture = read_json(STATUS_FIXTURE_PATH)
    fixture_v2 = read_json(STATUS_V2_FIXTURE_PATH)
    fixture_v3 = read_json(STATUS_V3_FIXTURE_PATH)
    expected_contract = {
        "status_schema_version_min": 2, "status_schema_version_max": 3,
        "status_contract_hash": "v0.9-neutron-status-3", "status_contract_scenarios_path": STATUS_V3_FIXTURE_PATH,
        "status_v1_compatibility_scenarios_path": STATUS_FIXTURE_PATH,
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
    for constant, expected in (("NEUTRON_STATUS_SCHEMA_VERSION_MIN", "2"), ("NEUTRON_STATUS_SCHEMA_VERSION_MAX", "3"), ("NEUTRON_STATUS_CONTRACT_HASH", "v0.9-neutron-status-3")):
        if rust_const(api, constant) != expected:
            raise SystemExit("ERROR: public Rust Status constant %s drifted" % constant)
    schema_v2 = fixture_v2.get("status_contract")
    if (
        not isinstance(schema_v2, dict)
        or schema_v2.get("version") != 2
        or schema_v2.get("hash") != "v0.9-neutron-status-2"
        or schema_v2.get("error_codes_hash") != "v0.9-neutron-errors-3"
        or schema_v2.get("capability_hash") != "v0.9-neutron-capabilities-4"
        or schema_v2.get("new_required_action") != "retry_snapshot"
    ):
        raise SystemExit("ERROR: Status V2 fixture contract metadata drifted")
    if set(fixture_v3) != {"fixture_schema_version", "status_contract", "scenarios"} or fixture_v3.get("fixture_schema_version") != 1:
        raise SystemExit("ERROR: Status V3 fixture root schema drifted")
    schema_v3 = fixture_v3.get("status_contract")
    if (
        not isinstance(schema_v3, dict)
        or schema_v3.get("version") != 3
        or schema_v3.get("hash") != "v0.9-neutron-status-3"
        or schema_v3.get("error_codes_hash") != "v0.9-neutron-errors-3"
        or schema_v3.get("capability_hash") != "v0.9-neutron-capabilities-5"
        or schema_v3.get("new_required_action") != "retry_snapshot"
    ):
        raise SystemExit("ERROR: Status V3 fixture contract metadata drifted")
    v3_scenarios = fixture_v3.get("scenarios")
    if not isinstance(v3_scenarios, list) or len(v3_scenarios) < 7:
        raise SystemExit("ERROR: Status V3 scenario inventory drifted")
    if tuple(item.get("id") for item in v3_scenarios if isinstance(item, dict))[-2:] != (
        "counters-present-single-port", "counters-absent-legacy-datapath",
    ):
        raise SystemExit("ERROR: Status V3 counters scenarios drifted")
    for scenario in v3_scenarios:
        status = scenario.get("status")
        if not isinstance(status, dict) or status.get("status_schema_version") != 3:
            raise SystemExit("ERROR: Status V3 scenario status schema drifted")
        if status.get("status_contract_hash") != "v0.9-neutron-status-3":
            raise SystemExit("ERROR: Status V3 scenario status hash drifted")
    expected_enums = {
        "NeutronStatusTransactionState": ("Idle", "Pending", "Classified", "Blocked", "Recovery"),
        "NeutronStatusOverallReadiness": ("Ready", "Degraded", "Blocked", "Unknown"),
        "NeutronStatusRequiredAction": ("None", "Poll", "RetrySnapshot", "RecoverPending", "FullResync", "Operator"),
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


def check_documented_status_contract():
    print("==> checking documented Status V1 contract")
    contents = read_text(DOMAIN_STATUS_DOC_PATH)
    obsolete = (
        "Status: partial implementation; richer Rust/domain DTO remains planned.",
        "Current Rust `NeutronDomainStatus` is still mostly:",
        "Rich Rust per-domain DTO fields such as `effective_action` and",
    )
    required = (
        "## Implemented Status V1 Contract",
        "`NeutronStatusV1Response`",
        "`NeutronStatusDomainEvidence`",
        "`docs/neutron-status-contract-v1-scenarios.json`",
    )
    if any(term in contents for term in obsolete):
        raise SystemExit("ERROR: obsolete planned Status V1 claim remains documented")
    if any(term not in contents for term in required):
        raise SystemExit("ERROR: implemented Status V1 public contract is undocumented")


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
        run([bash, "-n", bash_path(path)])

def run_fragment_tracking_field_driver_self_test():
    print("==> checking fragment tracking field driver")
    run([sys.executable, os.path.join(
        "ci", "test_fragment_tracking_field_driver_compat.py"
    )])
    run([sys.executable, FRAGMENT_TRACKING_FIELD_DRIVER_PATH, "--self-test"])


def run_readiness_endpoint_smoke_contract_test():
    print("==> checking readiness endpoint smoke contract")
    run([sys.executable, "-m", "unittest",
         "ci.test_neutron_aria_readiness_endpoint_smoke"])


def run_heartbeat_v2_smoke_contract_test():
    bash = shutil.which("bash")
    if not bash:
        print("SKIP: bash not found; cannot test Heartbeat V2 smoke")
        return
    print("==> checking Heartbeat V2 smoke contract")
    run([bash, bash_path("ci", "test_neutron_aria_heartbeat_v2_smoke.sh")])


def run_agent_package_installer_test():
    bash = shutil.which("bash")
    if not bash:
        print("SKIP: bash not found; cannot test agent package rollback")
        return
    print("==> checking agent package first-install rollback")
    run([bash, bash_path("ci", "test_neutron_agent_package_installer.sh")])

    print("==> checking UDS peercred production profile")
    run([bash, bash_path("ci", "test_aria_uds_peercred_profile.sh")])


def run_acl_enforcement_gap_smoke_test():
    bash = shutil.which("bash")
    if not bash:
        print("SKIP: bash not found; cannot test ACL enforcement-gap smoke")
        return
    print("==> checking ACL enforcement-gap alert boundary")
    run([bash, bash_path(
        "ci", "test_neutron_aria_acl_enforcement_gap_smoke.sh"
    )])


def run_plugin_policy_rollback_test():
    bash = shutil.which("bash")
    if not bash:
        print("SKIP: bash not found; cannot test plugin policy rollback")
        return
    print("==> checking plugin policy first-install rollback")
    run([bash, bash_path(
        "ci", "test_neutron_acl_plugin_policy_rollback.sh"
    )])


def run_transaction_state_smoke_test():
    bash = shutil.which("bash")
    if not bash:
        print("SKIP: bash not found; cannot test transaction smoke coverage")
        return
    print("==> checking transaction smoke port coverage")
    run([bash, bash_path("ci", "test_neutron_transaction_state_smoke.sh")])


def run_db_crud_adminrc_test():
    bash = shutil.which("bash")
    if not bash:
        print("SKIP: bash not found; cannot test DB CRUD adminrc routing")
        return
    print("==> checking DB CRUD adminrc routing")
    run([bash, bash_path("ci", "test_neutron_acl_db_crud_adminrc.sh")])
    print("==> checking neutronclient CLI adminrc routing")
    run([bash, bash_path("ci", "test_neutronclient_aria_cli_adminrc.sh")])


def run_fast_contracts():
    check_required_python_behaviors()
    run_python_tests()
    run_neutronclient_extension_tests()
    check_packaged_ini_contract()
    check_documented_ini_contract()
    check_documented_status_contract()
    check_uds_contract_artifact()
    check_public_smoke_entrypoints()
    run_smoke_syntax()
    run_readiness_endpoint_smoke_contract_test()
    run_heartbeat_v2_smoke_contract_test()
    run_fragment_tracking_field_driver_self_test()
    run_agent_package_installer_test()
    run_acl_enforcement_gap_smoke_test()
    run_plugin_policy_rollback_test()
    run_transaction_state_smoke_test()
    run_db_crud_adminrc_test()


def run_rust_behavior_command(command):
    print("==> %s" % " ".join(command))
    completed = subprocess.run(
        command,
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        universal_newlines=True,
    )
    output = completed.stdout or ""
    sys.stdout.write(output)
    if completed.returncode:
        raise subprocess.CalledProcessError(
            completed.returncode,
            command,
            output=output,
        )
    executed = sum(
        int(match)
        for match in re.findall(r"(?m)^running (\d+) tests?\s*$", output)
    )
    if executed == 0:
        raise SystemExit(
            "ERROR: Cargo behavior filter executed zero tests: %s"
            % " ".join(command)
        )
    return executed


def run_rust_tests(toolchain):
    cargo = shutil.which("cargo")
    if not cargo:
        raise SystemExit("ERROR: cargo not found; Rust behavior tests were not executed")
    for cmd in RUST_TESTS:
        prefix = [cargo] + (["+%s" % toolchain] if toolchain else [])
        run_rust_behavior_command(prefix + cmd)


def main():
    parser = argparse.ArgumentParser(description="Run public v0.9 Neutron Stage 1 contracts.")
    parser.add_argument("--require-rust", action="store_true", help="also run configured Rust behavior tests")
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
