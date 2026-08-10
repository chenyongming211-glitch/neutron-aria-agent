#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="${REPO_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)}"
SERVICE_NAME="${SERVICE_NAME:-neutron_aria_agent}"
NEUTRON_SERVER="${NEUTRON_SERVER:-neutron_server}"
ROLLBACK_DB_ON_ROLLBACK="${ROLLBACK_DB_ON_ROLLBACK:-false}"

usage() {
    cat <<EOF
Usage: $0 install|smoke|rollback

install   Install neutron-server aria_acl package, run DB migration check,
          install neutron-aria-agent and legacy neutron CLI packages, then run
          CRUD and ACL-source smokes.
smoke     Run non-mutating package smokes plus CRUD/source gates.
rollback  Roll back agent egg and neutron-server plugin/config. DB downgrade is
          skipped unless ROLLBACK_DB_ON_ROLLBACK=true is set explicitly.
EOF
}

log() {
    printf '[neutron-aria-acl-stage2-gate] %s\n' "$*"
}

require_root_host() {
    if [ "$(id -u)" != "0" ]; then
        echo "This gate must run as root on the OpenStack/Kolla host." >&2
        exit 1
    fi
}

install() {
    require_root_host
    log "Installing neutron-server aria_acl plugin"
    bash "${REPO_ROOT}/deploy/kolla/smoke/neutron_aria_acl_plugin_load_smoke.sh" install

    log "Applying/checking aria_acl DB migration"
    bash "${REPO_ROOT}/deploy/kolla/smoke/neutron_aria_acl_db_migration_smoke.sh" upgrade

    log "Installing neutron-aria-agent package"
    RESTART_AGENT_AFTER_INSTALL="${RESTART_AGENT_AFTER_INSTALL:-true}" \
        bash "${REPO_ROOT}/deploy/kolla/package/install_neutron_aria_agent_egg.sh" install

    log "Installing legacy neutron aria-acl CLI package"
    bash "${REPO_ROOT}/deploy/kolla/package/install_neutronclient_aria_cli.sh" install

    smoke
}

smoke() {
    require_root_host
    log "Checking neutron-server plugin visibility"
    bash "${REPO_ROOT}/deploy/kolla/smoke/neutron_aria_acl_plugin_load_smoke.sh" smoke

    log "Checking aria_acl DB schema"
    bash "${REPO_ROOT}/deploy/kolla/smoke/neutron_aria_acl_db_migration_smoke.sh" check

    log "Checking neutron-aria-agent package"
    bash "${REPO_ROOT}/deploy/kolla/package/install_neutron_aria_agent_egg.sh" smoke

    log "Checking legacy neutron aria-acl CLI package"
    bash "${REPO_ROOT}/deploy/kolla/package/install_neutronclient_aria_cli.sh" smoke

    log "Running aria_acl DB/REST CRUD smoke"
    bash "${REPO_ROOT}/deploy/kolla/smoke/neutron_aria_acl_db_crud_smoke.sh"

    log "Running aria_acl API/CLI consistency smoke"
    bash "${REPO_ROOT}/deploy/kolla/smoke/neutron_aria_acl_cli_consistency_smoke.sh"

    log "Running NeutronAclSource/full-resync smoke"
    bash "${REPO_ROOT}/deploy/kolla/smoke/neutron_aria_acl_neutron_source_smoke.sh"

    if [ "${RUN_LIVE_DOWNLINK_SMOKE:-false}" = "true" ]; then
        log "Running live downlink ACL smoke"
        bash "${REPO_ROOT}/deploy/kolla/smoke/neutron_aria_acl_live_downlink_smoke.sh"
    fi

    if [ "${RUN_ACTIVE_TRAFFIC_SMOKE:-false}" = "true" ]; then
        log "Running active traffic ACL smoke"
        bash "${REPO_ROOT}/deploy/kolla/smoke/neutron_aria_acl_active_traffic_smoke.sh"
    fi

    if [ "${RUN_LIVE_EGRESS_SMOKE:-false}" = "true" ]; then
        log "Running live egress ACL smoke"
        bash "${REPO_ROOT}/deploy/kolla/smoke/neutron_aria_acl_live_egress_smoke.sh"
    fi

    log "Checking neutron-aria-agent heartbeat summary"
    EXPECTED_HOSTS="${HOST_FQDN:-$(hostname -f)}" \
        REQUIRE_HEARTBEAT_SUMMARY_FIELDS=true \
        bash "${REPO_ROOT}/deploy/kolla/smoke/neutron_aria_heartbeat_smoke.sh"

    log "Checking enabled ACL ports for enforcement gaps"
    bash "${REPO_ROOT}/deploy/kolla/smoke/neutron_aria_acl_enforcement_gap_smoke.sh"

    log "Checking container health"
    docker ps --filter "name=${NEUTRON_SERVER}" --filter "name=${SERVICE_NAME}" \
        --format 'table {{.Names}}\t{{.Status}}'

    log "stage-two ACL gate ok"
}

rollback() {
    require_root_host
    log "Rolling back neutron-aria-agent package"
    bash "${REPO_ROOT}/deploy/kolla/package/install_neutron_aria_agent_egg.sh" rollback || true

    log "Rolling back legacy neutron aria-acl CLI package"
    bash "${REPO_ROOT}/deploy/kolla/package/install_neutronclient_aria_cli.sh" rollback || true

    log "Rolling back neutron-server aria_acl plugin/config"
    bash "${REPO_ROOT}/deploy/kolla/smoke/neutron_aria_acl_plugin_load_smoke.sh" rollback

    if [ "${ROLLBACK_DB_ON_ROLLBACK}" = "true" ]; then
        log "Downgrading aria_acl DB schema because ROLLBACK_DB_ON_ROLLBACK=true"
        bash "${REPO_ROOT}/deploy/kolla/smoke/neutron_aria_acl_db_migration_smoke.sh" downgrade
    else
        log "Skipping DB downgrade; set ROLLBACK_DB_ON_ROLLBACK=true to drop aria_acl tables"
    fi

    log "stage-two ACL rollback complete"
}

case "${1:-}" in
    install)
        install
        ;;
    smoke)
        smoke
        ;;
    rollback)
        rollback
        ;;
    *)
        usage
        exit 2
        ;;
esac
