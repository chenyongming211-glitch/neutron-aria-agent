#!/usr/bin/env python3
from __future__ import print_function

import os


ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir))

def _read(path):
    with open(os.path.join(ROOT, path), "r", encoding="utf-8") as handle:
        return handle.read()


def check_plugin_entrypoint():
    print("==> checking aria_acl service plugin entry point")
    setup_py = _read(os.path.join("openstack", "neutron_aria", "setup.py"))
    if "neutron.service_plugins" not in setup_py:
        raise SystemExit("ERROR: missing neutron.service_plugins entry point group")
    if "aria_acl=neutron_aria.services.aria_acl.plugin:AriaAclPlugin" not in setup_py:
        raise SystemExit("ERROR: missing aria_acl service plugin entry point")
    if "neutron.api_extensions" not in setup_py:
        raise SystemExit("ERROR: missing neutron.api_extensions entry point group")
    if "aria_acl=neutron_aria.extensions.aria_acl:Aria_acl" not in setup_py:
        raise SystemExit("ERROR: missing aria_acl API extension entry point")


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
    counter_migration = _read(os.path.join(
        "openstack", "neutron_aria", "neutron_aria", "db", "migration",
        "aria_acl_counters.py",
    ))
    counter_migration_version = _read(os.path.join(
        "openstack", "neutron_aria", "neutron_aria", "db", "aria_acl",
        "migration", "versions", "a4e7c2d9b610_add_acl_counter_schema.py",
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
    for term in (
        'revision = "a4e7c2d9b610"',
        'down_revision = "f61a2c4e7b90"',
        '"aria_acl_port_counters"',
        '"counters_sampled_at"',
        '"counters_policy_packets"',
        '"counters_truncated"',
        '"counters_group_map"',
        '"uq_aria_acl_port_counters_natural"',
        "upgrade_existing_schema",
    ):
        if term not in counter_migration:
            raise SystemExit(
                "ERROR: aria_acl counter migration operation missing %s" % term
            )
    for term in ("revision", "down_revision", "upgrade", "downgrade"):
        if term not in migration_version:
            raise SystemExit("ERROR: aria_acl migration version file missing %s" % term)
        if term not in counter_migration_version:
            raise SystemExit(
                "ERROR: aria_acl counter migration version file missing %s" % term
            )

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
    active_traffic_smoke = _read(os.path.join(
        "deploy", "kolla", "smoke", "neutron_aria_acl_active_traffic_smoke.sh"
    ))
    rpc_p2_soak_smoke = _read(os.path.join(
        "deploy", "kolla", "smoke", "neutron_aria_rpc_p2_soak_smoke.sh"
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
    agent_dockerfile = _read(os.path.join(
        "deploy", "kolla", "neutron-aria-agent", "Dockerfile"
    ))
    agent_rc_installer = _read(os.path.join(
        "deploy", "kolla", "package", "install_neutron_aria_agent_rc_image.sh"
    ))
    datapath_image_builder = _read(os.path.join(
        "deploy", "kolla", "package", "build_aria_datapath_image.sh"
    ))
    legacy_cli = _read(os.path.join(
        "openstack", "neutronclient_aria", "neutronclient_aria", "v2_0",
        "aria_acl.py",
    ))
    legacy_cli_installer = _read(os.path.join(
        "deploy", "kolla", "package", "install_neutronclient_aria_cli.sh"
    ))
    workflow = _read(os.path.join(".github", "workflows", "build.yml"))
    release_governance = _read(os.path.join(
        "docs", "stage2-acl-release-governance.md"
    ))
    for term in (
        '"--with-rules"',
        'policy["rule_count"]',
        'policy["rule_ids"]',
        'policy_id=parsed_args.id',
    ):
        if term not in legacy_cli:
            raise SystemExit("ERROR: legacy policy-with-rules CLI missing %s" % term)
    for term in (
        "aria-acl-policy-show --help",
        "--with-rules",
    ):
        if term not in legacy_cli_installer:
            raise SystemExit("ERROR: legacy CLI installer smoke missing %s" % term)
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
        "expected_port_id = sys.argv[6]",
        "port_ids = [expected_port_id]",
    ):
        if term not in smoke and term not in full_resync_smoke:
            raise SystemExit("ERROR: production aria_acl smoke missing %s" % term)
    for term in (
        "upgrade",
        "check",
        "downgrade",
        "NeutronDbAriaAclRepository(ctx, auto_create=False)",
        "upgrade_counter_family_existing_schema",
        "upgrade_acl_priority_family",
        "priority_family_index=pass",
        "missing aria_acl columns",
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
        "RUN_ACTIVE_TRAFFIC_SMOKE",
        "neutron_aria_acl_active_traffic_smoke.sh",
        "ROLLBACK_DB_ON_ROLLBACK",
    ):
        if term not in stage2_gate:
            raise SystemExit("ERROR: stage-two ACL gate missing %s" % term)
    for term in (
        "build_neutron_aria_egg.sh",
        "neutron_aria-0.1.0-py2.7.egg",
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
        "policy.json.latest.meta",
        "from neutron_aria.policies.aria_acl import merge_policy_file",
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
        "install_neutron_aria_agent_rc_image.sh",
        "agent_rc_installer=deploy/kolla/package/install_neutron_aria_agent_rc_image.sh",
        "build_aria_datapath_image.sh",
        "deploy/kolla/aria-datapath",
        "NETADDR_WHEEL_PATH",
        "NETADDR_WHEEL_NAME",
        "netaddr-0.7.19-py2.py3-none-any.whl",
        "dist/kolla/python2-wheels",
        "56b3558bd71f3f6999e4c52e349f38660e54a7a8a9943335f73dfc96883e08ca",
        '--artifact "dist/kolla/${EGG_NAME}=',
        '--artifact "dist/kolla/python2-wheels/${NETADDR_WHEEL_NAME}=',
        "tar --sort=name",
        "gzip -n",
    ):
        if term not in bundle_builder:
            raise SystemExit("ERROR: stage-two ACL bundle builder missing %s" % term)
    for term in (
        "BASE_IMAGE",
        "IMAGE_TAG",
        "SAVE_IMAGE",
        "docker build",
        "docker save",
        "docker run --rm -i --entrypoint python",
        "image_imports=ok",
        "neutron-aria-agent --help",
    ):
        if term not in image_builder:
            raise SystemExit("ERROR: neutron-aria-agent image builder missing %s" % term)
    for term in (
        "neutron_aria-0.1.0-py2.7.egg",
        "install-neutron-aria-egg-image.sh",
        "neutron-aria-agent-entrypoint.py",
        "netaddr-0.7.19-py2.py3-none-any.whl",
        "python3 -m pip install",
        "--no-deps --upgrade",
        "/usr/lib/python2.7/site-packages",
        "neutron-aria-agent --help",
    ):
        if term not in agent_dockerfile:
            raise SystemExit("ERROR: neutron-aria-agent Dockerfile missing %s" % term)
    if "python setup.py install" in agent_dockerfile:
        raise SystemExit(
            "ERROR: neutron-aria-agent Dockerfile must not rebuild an active zipped egg"
        )
    for term in (
        "install|check|rollback",
        "EXPECTED_IMAGE_ID",
        "CANDIDATE_CONFIG_SOURCE",
        "ROLLBACK_CONFIG_SOURCE",
        "container.env",
        "Aria datapath container identity changed",
        "Neutron OVS agent container identity changed",
        "heartbeat_detail_mode == \"summary_only\"",
        "netaddr.__version__ == \"0.7.19\"",
        "--entrypoint neutron-aria-agent",
        "--help",
    ):
        if term not in agent_rc_installer:
            raise SystemExit("ERROR: agent RC image installer missing %s" % term)
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
    joint_publish_condition = (
        "${{ env.PUBLISH_BUILD_ARTIFACTS == 'true' && "
        "vars.KOLLA_NEUTRON_AGENT_BASE_IMAGE != '' && "
        "vars.KOLLA_ARIA_DATAPATH_BASE_IMAGE != '' }}"
    )
    for step in (
        "Build Neutron stage-two ACL Kolla bundle",
        "Check Neutron stage-two ACL Kolla bundle payload policy",
        "Upload Neutron stage-two ACL Kolla bundle",
    ):
        step_start = workflow.find("- name: " + step)
        step_end = workflow.find("\n      - name:", step_start + 1)
        if step_start < 0 or joint_publish_condition not in workflow[step_start:step_end]:
            raise SystemExit("ERROR: workflow joint bundle step lacks both-base publish condition: %s" % step)
    inputs_step = workflow.find("- name: Prepare Neutron Aria agent image inputs")
    agent_step = workflow.find("- name: Build optional Neutron Aria agent image tar")
    if inputs_step < 0 or agent_step < 0 or inputs_step >= agent_step:
        raise SystemExit("ERROR: workflow must prepare agent image inputs before image build")
    agent_inputs = workflow[inputs_step:agent_step]
    for term in ("build_neutron_aria_egg.sh", "netaddr==0.7.19", "sha256sum --check --strict"):
        if term not in agent_inputs:
            raise SystemExit("ERROR: workflow agent image input preparation missing %s" % term)
    bundle_step = workflow.find("- name: Build Neutron stage-two ACL Kolla bundle")
    bundle_check_step = workflow.find("- name: Check Neutron stage-two ACL Kolla bundle payload policy")
    bundle_step_source = workflow[bundle_step:bundle_check_step]
    if "pip download" in bundle_step_source:
        raise SystemExit("ERROR: workflow bundle build must not prepare netaddr late")
    for term in (
        "OBSERVATION_SECONDS",
        "rpc_events_enabled",
        "incremental_rpc_enabled",
        "revisionless_incremental_mode",
        "sync_mode=rpc_full_resync",
        "full_resync_complete",
        "event_batch_drained",
        "pending_generation",
        "BAD_LOG_PATTERN",
        "STARTUP_BAD_LOG_PATTERN",
        "observation_log_cursor_reset",
        "status_health_signature",
        "baseline_health_signature",
        "KEEP_ENABLED",
        "config_restored",
        "rpc_p2_soak=pass",
    ):
        if term not in rpc_p2_soak_smoke:
            raise SystemExit("ERROR: RPC P2 soak smoke missing %s" % term)
    for term in (
        "active_traffic_started",
        "active-downlink-ping.log",
        "aria-acl-policies",
        "aria-acl-rules",
        "aria-acl-bindings",
        "aria-acl-port-statuses",
        "run_full_resync",
        "wait_datapath_drop",
        "wait_datapath_clear",
        "observe_blocked_traffic",
        "acl_active_traffic_smoke=pass",
    ):
        if term not in active_traffic_smoke:
            raise SystemExit("ERROR: active traffic ACL smoke missing %s" % term)
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
    for document_path in (
        os.path.join("docs", "stage2-acl-release-governance.md"),
        os.path.join("docs", "openstack-deployment-runbook.md"),
        os.path.join("docs", "openstack-neutron-aria-details", "08-stage3-acl-production-hardening.md"),
    ):
        document = _read(document_path)
        for term in ("AGENT_IMAGE_IDENTITY=", "DATAPATH_IMAGE_IDENTITY="):
            if term not in document:
                raise SystemExit("ERROR: bundle documentation missing %s in %s" % (term, document_path))
        if "bash deploy/kolla/package/build_stage2_acl_bundle.sh" in document:
            raise SystemExit("ERROR: bundle documentation must provide both immutable identities in %s" % document_path)


def check_datapath_apply_error_observability():
    print("==> checking datapath apply error observability")
    neutron_api = _read(os.path.join("agent", "src", "neutron_api.rs"))
    if "reason = %attach_error_reason" not in neutron_api:
        raise SystemExit(
            "ERROR: Neutron attach failure log must include the concrete reason"
        )
    if "reason = %domain_error_reason" not in neutron_api:
        raise SystemExit(
            "ERROR: Neutron domain reconcile failure log must include the concrete reason"
        )


def check_active_matrix_contract():
    print("==> checking bidirectional active ACL matrix contract")
    required = {
        os.path.join("deploy", "kolla", "smoke", "neutron_aria_acl_nonce_echo.py"): (
            "serve", "probe", "MAX_NONCE_BYTES",
        ),
        os.path.join("deploy", "kolla", "smoke", "neutron_aria_acl_active_matrix_case.sh"): (
            "effective_policy_id", "binding_id", "generation_lag",
            "matching_drop", "nonmatching_allow", "cleanup_complete",
        ),
        os.path.join("deploy", "kolla", "smoke", "neutron_aria_acl_active_matrix_soak.sh"): (
            "systemd-run", "Type=simple", "scheduler.lock", "checkpoint.json",
            "skipped_active_tick", "single:1", "65535",
            "owned_resources_remaining", "no_automatic_restart",
        ),
    }
    for path, terms in required.items():
        source = _read(path)
        for term in terms:
            if term not in source:
                raise SystemExit("ERROR: active ACL matrix %s missing %s" % (path, term))

def main():
    # Executable behavior is owned by the required full Python discovery in
    # check_neutron_stage1.py.  This script intentionally checks only artifacts
    # whose structure is itself the public contract.
    check_plugin_entrypoint()
    check_neutron_server_contract_files()
    check_production_acl_smoke()
    check_datapath_apply_error_observability()
    check_active_matrix_contract()
    print("stage-two static/artifact contract passed")
    print("evidence_class=static_artifact")
    print("runtime_evidence=not_evaluated")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
