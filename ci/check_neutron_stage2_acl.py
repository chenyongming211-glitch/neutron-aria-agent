#!/usr/bin/env python3
from __future__ import print_function

import os
import subprocess
import sys


ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir))

PYTHONPATH = os.path.join(ROOT, "openstack", "neutron_aria")

STAGE2_TESTS = [
    "neutron_aria.tests.unit.test_aria_acl_plugin",
    "neutron_aria.tests.unit.test_acl_source",
    "neutron_aria.tests.unit.test_effective_acl",
    "neutron_aria.tests.unit.test_event_loop",
    "neutron_aria.tests.unit.test_main",
    "neutron_aria.tests.unit.test_status_reporter",
]

BOUNDARY_PATHS = [
    os.path.join("openstack", "neutron_aria", "neutron_aria", "agent", "acl_source.py"),
    os.path.join("openstack", "neutron_aria", "neutron_aria", "agent", "neutron_client.py"),
    os.path.join("openstack", "neutron_aria", "neutron_aria", "services", "aria_acl", "plugin.py"),
    os.path.join("openstack", "neutron_aria", "neutron_aria", "db", "aria_acl", "api.py"),
    os.path.join("openstack", "neutron_aria", "neutron_aria", "extensions", "aria_acl.py"),
    os.path.join("openstack", "neutron_aria", "neutron_aria", "policies", "aria_acl.py"),
]


def _read(path):
    with open(os.path.join(ROOT, path), "r", encoding="utf-8") as handle:
        return handle.read()


def run_stage2_tests():
    env = os.environ.copy()
    env["PYTHONPATH"] = PYTHONPATH + (
        os.pathsep + env["PYTHONPATH"] if env.get("PYTHONPATH") else ""
    )
    cmd = [sys.executable, "-m", "unittest"] + STAGE2_TESTS
    print("==> %s" % " ".join(cmd))
    subprocess.check_call(cmd, cwd=ROOT, env=env)


def check_acl_source_contract():
    print("==> checking stage-two ACL source contract")
    source = _read(os.path.join(
        "openstack", "neutron_aria", "neutron_aria", "agent", "acl_source.py"
    ))
    required = [
        "get_aria_acl_effective_payload",
        "list_aria_acl_policies",
        "list_aria_acl_rules",
        "list_aria_acl_address_sets",
        "list_aria_acl_bindings",
        "EffectiveAclIndex.from_payload",
        "build_aria_acl_client_from_env",
        "ACL_PAYLOAD_COLLECTIONS",
        "_validated_payload",
        "_validate_collection",
        "missing collection",
        "neutron acl source failed",
    ]
    for term in required:
        if term not in source:
            raise SystemExit("ERROR: NeutronAclSource missing %s" % term)

    neutron_client = _read(os.path.join(
        "openstack", "neutron_aria", "neutron_aria", "agent", "neutron_client.py"
    ))
    for term in (
        "class AriaAclRestClient",
        "/aria-acl-policies",
        "/aria-acl-rules",
        "/aria-acl-address-sets",
        "/aria-acl-bindings",
        "/aria-acl-port-statuses",
        "list_aria_acl_port_statuses",
        "report_aria_acl_port_status",
        "_has_next_link",
        "marker",
        "missing collection",
        "repeated pagination marker",
        "pagination params",
    ):
        if term not in neutron_client:
            raise SystemExit("ERROR: aria_acl REST client missing %s" % term)


def check_no_forbidden_production_inputs():
    print("==> checking stage-two ACL production-input boundaries")
    forbidden = [
        "security_group",
        "security-groups",
        "remote_group",
        "allowed_address_pair",
        "port_security",
        "tag_mapping",
        "aria:acl",
        "aria_qos",
        "aria_mirror",
    ]
    for path in BOUNDARY_PATHS:
        contents = _read(path).lower()
        for term in forbidden:
            if term in contents:
                raise SystemExit(
                    "ERROR: forbidden production ACL input %r in %s" % (term, path)
                )


def check_plugin_entrypoint():
    print("==> checking aria_acl service plugin entry point")
    setup_py = _read(os.path.join("openstack", "neutron_aria", "setup.py"))
    plugin = _read(os.path.join(
        "openstack", "neutron_aria", "neutron_aria", "services", "aria_acl", "plugin.py"
    ))
    if "neutron.service_plugins" not in setup_py:
        raise SystemExit("ERROR: missing neutron.service_plugins entry point group")
    if "aria_acl=neutron_aria.services.aria_acl.plugin:AriaAclPlugin" not in setup_py:
        raise SystemExit("ERROR: missing aria_acl service plugin entry point")
    if "neutron.api_extensions" not in setup_py:
        raise SystemExit("ERROR: missing neutron.api_extensions entry point group")
    if "aria_acl=neutron_aria.extensions.aria_acl:Aria_acl" not in setup_py:
        raise SystemExit("ERROR: missing aria_acl API extension entry point")
    main_py = _read(os.path.join(
        "openstack", "neutron_aria", "neutron_aria", "agent", "main.py"
    ))
    for term in (
        "build_once_status_reporter",
        'config.acl_source != "neutron"',
        "status_reporter=build_once_status_reporter",
        "build_acl_source",
        "acl_source=build_acl_source",
    ):
        if term not in main_py:
            raise SystemExit("ERROR: neutron --once ACL source path missing %s" % term)
    event_loop = _read(os.path.join(
        "openstack", "neutron_aria", "neutron_aria", "agent", "event_loop.py"
    ))
    for term in (
        "acl_source=None",
        "self.acl_source = acl_source",
        "def _load_acl_index",
        "self.acl_source.load_index",
    ):
        if term not in event_loop:
            raise SystemExit("ERROR: neutron ACL source refresh path missing %s" % term)
    for term in (
        "get_plugin_type",
        "get_plugin_description",
        "supported_extension_aliases",
        "create_aria_acl_port_status",
        "update_aria_acl_port_status",
        "get_aria_acl_port_statuses",
        "delete_aria_acl_port_status",
    ):
        if term not in plugin:
            raise SystemExit("ERROR: aria_acl service plugin missing %s" % term)
    if "get_aria_acl_effective_for_port_id" not in plugin:
        raise SystemExit("ERROR: aria_acl service plugin missing port-id effective ACL read")

    status_reporter = _read(os.path.join(
        "openstack", "neutron_aria", "neutron_aria", "agent", "status_reporter.py"
    ))
    for term in (
        "class AriaAclPortStatusReporter",
        "class CompositeStatusReporter",
        "report_aria_acl_port_status",
        'acl_source", None) != "neutron"',
    ):
        if term not in status_reporter:
            raise SystemExit("ERROR: aria_acl status reporter missing %s" % term)


def check_minimum_db_contract():
    print("==> checking aria_acl minimum DB contract")
    db_api = _read(os.path.join(
        "openstack", "neutron_aria", "neutron_aria", "db", "aria_acl", "api.py"
    ))
    required = [
        "class SqliteAriaAclRepository",
        "aria_acl_policies",
        "aria_acl_rules",
        "aria_acl_address_sets",
        "aria_acl_bindings",
        "aria_acl_port_statuses",
        "update_policy",
        "update_rule",
        "update_address_set",
        "update_binding",
        "delete_rule",
        "delete_address_set",
        "delete_port_status",
        "_matches_filters",
        "_stamp_create",
        "_stamp_update",
        "_stamp_status",
        "to_effective_payload",
    ]
    for term in required:
        if term not in db_api:
            raise SystemExit("ERROR: aria_acl DB contract missing %s" % term)


def check_neutron_server_contract_files():
    print("==> checking aria_acl neutron-server contract files")
    extension = _read(os.path.join(
        "openstack", "neutron_aria", "neutron_aria", "extensions", "aria_acl.py"
    ))
    migration = _read(os.path.join(
        "openstack", "neutron_aria", "neutron_aria", "db", "migration", "aria_acl_initial.py"
    ))
    migration_version = _read(os.path.join(
        "openstack", "neutron_aria", "neutron_aria", "db", "aria_acl",
        "migration", "versions", "8b9c2d1e4f60_add_aria_acl_tables.py",
    ))
    policy = _read(os.path.join(
        "openstack", "neutron_aria", "neutron_aria", "policies", "aria_acl.py"
    ))

    for term in (
        "RESOURCE_ATTRIBUTE_MAP",
        "API_RESOURCE_ATTRIBUTE_MAP",
        "aria_acl_enabled",
        "aria_acl_effective_policy_id",
        "aria_acl_runtime_status",
        "effective_action",
        "last_reported_at",
        "runtime_status",
        "stale",
        "aria_acl_address_sets",
        "aria_acl_bindings",
        "aria_acl_port_statuses",
        '"members"',
        '"target_type"',
        "get_extended_resources",
        "class Aria_acl",
        "resource_helper.build_resource_info",
    ):
        if term not in extension:
            raise SystemExit("ERROR: aria_acl extension contract missing %s" % term)
    resources_fn = extension.split("def get_resources():", 1)[1].split(
        "def get_extended_resources", 1
    )[0]
    if "RESOURCE_ATTRIBUTE_MAP" in resources_fn.replace("API_RESOURCE_ATTRIBUTE_MAP", ""):
        raise SystemExit("ERROR: get_resources must not expose port extension attrs as resources")

    for table in (
        "aria_acl_policies",
        "aria_acl_rules",
        "aria_acl_address_sets",
        "aria_acl_address_set_members",
        "aria_acl_bindings",
        "aria_acl_rbac",
        "aria_acl_port_statuses",
    ):
        if table not in migration:
            raise SystemExit("ERROR: aria_acl migration contract missing %s" % table)
    for term in (
        'revision = "8b9c2d1e4f60"',
        'down_revision = ("4af11ca47297", "2948f8b16a0c")',
        '"effective_action"',
        "create_table",
        "create_index",
        "drop_table",
    ):
        if term not in migration:
            raise SystemExit("ERROR: aria_acl migration operation missing %s" % term)
    for term in ("revision", "down_revision", "upgrade", "downgrade"):
        if term not in migration_version:
            raise SystemExit("ERROR: aria_acl migration version file missing %s" % term)

    required_policy_terms = (
        '"create_aria_acl_policy": ADMIN_ONLY',
        '"create_aria_acl_binding": ADMIN_ONLY',
        '"update_aria_acl_binding": ADMIN_ONLY',
        '"get_aria_acl_effective": ADMIN_OR_AGENT',
        '"report_aria_acl_port_status": ADMIN_OR_AGENT',
        '"create_aria_acl_port_status": ADMIN_OR_AGENT',
        '"update_aria_acl_port_status": ADMIN_OR_AGENT',
        '"get_aria_acl_port_statuses": ADMIN_OR_AGENT',
        '"get_aria_acl_port_status:runtime_status": ADMIN_OR_AGENT',
        '"get_aria_acl_port_status:stale": ADMIN_OR_AGENT',
        '"get_aria_acl_port_status:last_reported_at": ADMIN_OR_AGENT',
        '"delete_aria_acl_port_status": ADMIN_OR_AGENT',
    )
    for term in required_policy_terms:
        if term not in policy:
            raise SystemExit("ERROR: aria_acl RBAC contract missing %s" % term)


def check_production_acl_smoke():
    print("==> checking production aria_acl smoke contract")
    smoke = _read(os.path.join(
        "deploy", "kolla", "smoke", "neutron_aria_acl_neutron_source_smoke.sh"
    ))
    full_resync_smoke = _read(os.path.join(
        "deploy", "kolla", "smoke", "neutron_aria_full_resync_smoke.sh"
    ))
    migration_smoke = _read(os.path.join(
        "deploy", "kolla", "smoke", "neutron_aria_acl_db_migration_smoke.sh"
    ))
    stage2_gate = _read(os.path.join(
        "deploy", "kolla", "smoke", "neutron_aria_acl_stage2_gate_smoke.sh"
    ))
    agent_installer = _read(os.path.join(
        "deploy", "kolla", "package", "install_neutron_aria_agent_egg.sh"
    ))
    egg_builder = _read(os.path.join(
        "deploy", "kolla", "package", "build_neutron_aria_egg.sh"
    ))
    bundle_builder = _read(os.path.join(
        "deploy", "kolla", "package", "build_stage2_acl_bundle.sh"
    ))
    image_builder = _read(os.path.join(
        "deploy", "kolla", "package", "build_neutron_aria_agent_image.sh"
    ))
    datapath_image_builder = _read(os.path.join(
        "deploy", "kolla", "package", "build_aria_datapath_image.sh"
    ))
    workflow = _read(os.path.join(".github", "workflows", "build.yml"))
    release_governance = _read(os.path.join(
        "docs", "stage2-acl-release-governance.md"
    ))
    for term in (
        "neutron ext-list",
        "ACL_SOURCE=neutron",
        "neutron_aria_full_resync_smoke.sh",
        "MIN_ACL_POLICIES=1",
        "MIN_ACL_RULES=1",
        "MIN_ACL_BINDINGS=1",
        "aria_acl_port_statuses",
        "list_aria_acl_port_statuses",
        "Checking aria_acl port-status reportback",
        "last_reported_at",
        "runtime_status",
        "stale",
    ):
        if term not in smoke and term not in full_resync_smoke:
            raise SystemExit("ERROR: production aria_acl smoke missing %s" % term)
    for term in (
        "upgrade",
        "check",
        "downgrade",
        "NeutronDbAriaAclRepository(ctx, auto_create=False)",
        "ensure_schema",
        "drop(bind=bind, checkfirst=True)",
    ):
        if term not in migration_smoke:
            raise SystemExit("ERROR: aria_acl DB migration smoke missing %s" % term)
    for term in (
        "Installing neutron-server aria_acl plugin",
        "Applying/checking aria_acl DB migration",
        "Installing neutron-aria-agent package",
        "neutron_aria_acl_db_crud_smoke.sh",
        "neutron_aria_acl_neutron_source_smoke.sh",
        "ROLLBACK_DB_ON_ROLLBACK",
    ):
        if term not in stage2_gate:
            raise SystemExit("ERROR: stage-two ACL gate missing %s" % term)
    for term in (
        "build_neutron_aria_egg.sh",
        "neutron_aria-0.1.0-py2.7.egg",
        "backup_current_egg",
        "rollback",
        "neutron-aria-agent --help",
        "chmod 0644",
    ):
        if term not in agent_installer:
            raise SystemExit("ERROR: agent package installer missing %s" % term)
    for term in (
        "POLICY_FILE",
        "install_policy_rules",
        "policy.json.latest.bak",
        "from neutron_aria.policies.aria_acl import list_rules",
    ):
        if term not in _read(os.path.join(
            "deploy", "kolla", "smoke", "neutron_aria_acl_plugin_load_smoke.sh"
        )):
            raise SystemExit("ERROR: plugin loader missing policy install term %s" % term)
    for term in (
        "EGG-INFO/PKG-INFO",
        "EGG-INFO/entry_points.txt",
        "neutron-aria-agent = neutron_aria.agent.main:main",
        "aria_acl = neutron_aria.services.aria_acl.plugin:AriaAclPlugin",
        "replace(os.sep, \"/\")",
    ):
        if term not in egg_builder:
            raise SystemExit("ERROR: agent egg builder missing %s" % term)
    for term in (
        "neutron-aria-stage2-acl-kolla-bundle.tgz",
        "README-stage2-acl-kolla.md",
        "MANIFEST.txt",
        "recommended_image_tag",
        "image_tar_policy=optional_requires_KOLLA_NEUTRON_AGENT_BASE_IMAGE",
        "datapath_image_builder=deploy/kolla/package/build_aria_datapath_image.sh",
        "uds_hardened_rollout=deploy/kolla/smoke/neutron_aria_uds_hardened_rollout_smoke.sh",
        "datapath_image_tar_policy=optional_requires_KOLLA_ARIA_DATAPATH_BASE_IMAGE_or_onsite_BASE_IMAGE",
        "neutron_aria_uds_hardening_smoke.sh",
        "neutron_aria_uds_hardened_rollout_smoke.sh",
        "REQUIRE_HARDENED=true",
        "build_neutron_aria_egg.sh",
        "neutron_aria_acl_stage2_gate_smoke.sh",
        "build_neutron_aria_agent_image.sh",
        "build_aria_datapath_image.sh",
        "deploy/kolla/aria-datapath",
        "tar -czf",
    ):
        if term not in bundle_builder:
            raise SystemExit("ERROR: stage-two ACL bundle builder missing %s" % term)
    for term in (
        "BASE_IMAGE",
        "IMAGE_TAG",
        "SAVE_IMAGE",
        "docker build",
        "docker save",
        "image_imports=ok",
    ):
        if term not in image_builder:
            raise SystemExit("ERROR: neutron-aria-agent image builder missing %s" % term)
    for term in (
        "BASE_IMAGE",
        "IMAGE_TAG",
        "ARTIFACT_DIR",
        "ARIA_AGENT_BINARY",
        "libebpf_firewall.so",
        "libebpf_firewall_perf.so",
        "docker build",
        "docker save",
        "start-aria-datapath",
    ):
        if term not in datapath_image_builder:
            raise SystemExit("ERROR: aria-datapath image builder missing %s" % term)
    for term in (
        "Build Neutron stage-two ACL Kolla bundle",
        "deploy/kolla/package/build_stage2_acl_bundle.sh",
        "Upload Neutron stage-two ACL Kolla bundle",
        "dist/kolla/neutron-aria-stage2-acl-kolla-bundle.tgz",
        "KOLLA_NEUTRON_AGENT_BASE_IMAGE",
        "KOLLA_ARIA_DATAPATH_BASE_IMAGE",
        "Build optional Neutron Aria agent image tar",
        "dist/kolla/neutron-aria-agent-*-stage2-acl-image.tar",
        "Build optional Aria datapath image tar",
        "dist/kolla/aria-datapath-*-stage2-acl-image.tar",
        "fail_on_unmatched_files: false",
    ):
        if term not in workflow:
            raise SystemExit("ERROR: workflow missing stage-two ACL bundle term %s" % term)
    for term in (
        "neutron-aria==0.1.0",
        "neutron-aria-stage2-acl-kolla-bundle.tgz",
        "<registry>/neutron-aria-agent:<repo-version>-stage2-acl",
        "<registry>/aria-datapath:<repo-version>-stage2-acl",
        "KOLLA_NEUTRON_AGENT_BASE_IMAGE",
        "KOLLA_ARIA_DATAPATH_BASE_IMAGE",
        "Image tar is optional",
        "Do not build the production image from a generic Python image",
        "build_aria_datapath_image.sh",
        "REQUIRE_HARDENED=true",
    ):
        if term not in release_governance:
            raise SystemExit("ERROR: stage-two release governance missing %s" % term)


def main():
    run_stage2_tests()
    check_acl_source_contract()
    check_no_forbidden_production_inputs()
    check_plugin_entrypoint()
    check_minimum_db_contract()
    check_neutron_server_contract_files()
    check_production_acl_smoke()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
