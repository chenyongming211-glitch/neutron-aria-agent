#!/usr/bin/env bash
set -euo pipefail

SERVICE_NAME="${SERVICE_NAME:-neutron_aria_agent}"
IMAGE="${IMAGE:-}"
REPO_ROOT="${REPO_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)}"
HOST_FQDN="${HOST_FQDN:-$(hostname -f)}"
ADMINRC="${ADMINRC:-/root/adminrc}"
RUN_ARIA_DIR="${RUN_ARIA_DIR:-/run/aria}"
SOCKET_PATH="${SOCKET_PATH:-/run/aria/aria-agent.sock}"
OVS_BRIDGE="${OVS_BRIDGE:-br-int}"
SMOKE_CONFIG="${SMOKE_CONFIG:-/tmp/neutron-aria-agent-full-resync.ini}"
EXEC_USER="${EXEC_USER:-neutron}"
AUTO_RESTART_WITH_RUN_ARIA="${AUTO_RESTART_WITH_RUN_ARIA:-true}"
FIX_UDS_PERMISSIONS="${FIX_UDS_PERMISSIONS:-false}"
LEGACY_VALIDATE_OVSDB_IN_NEUTRON_AGENT="${LEGACY_VALIDATE_OVSDB_IN_NEUTRON_AGENT:-false}"
ROLLBACK="${ROLLBACK:-true}"
MIN_MANAGED_PORTS="${MIN_MANAGED_PORTS:-0}"
EXPECTED_PORT_ID="${EXPECTED_PORT_ID:-}"
EXPECTED_IFNAME="${EXPECTED_IFNAME:-}"
ACL_FIXTURE_JSON="${ACL_FIXTURE_JSON:-}"
ACL_FIXTURE_FILE="${ACL_FIXTURE_FILE:-}"
CONTAINER_ACL_FIXTURE="${CONTAINER_ACL_FIXTURE:-/tmp/neutron-aria-acl-fixture.json}"

die() {
    echo "ERROR: $*" >&2
    exit 1
}

need_command() {
    command -v "$1" >/dev/null 2>&1 || die "missing command: $1"
}

source_adminrc() {
    if [ -r "${ADMINRC}" ]; then
        # shellcheck disable=SC1090
        source "${ADMINRC}"
    fi
}

require_openstack_env() {
    [ -n "${OS_AUTH_URL:-}" ] || die "OS_AUTH_URL is not set"
    [ -n "${OS_USERNAME:-}" ] || die "OS_USERNAME is not set"
    [ -n "${OS_PASSWORD:-}" ] || die "OS_PASSWORD is not set"
    if [ -z "${OS_TENANT_NAME:-}" ] && [ -z "${OS_PROJECT_NAME:-}" ]; then
        die "OS_TENANT_NAME or OS_PROJECT_NAME is not set"
    fi
}

docker_exec_env() {
    docker exec \
        -i \
        -u "${EXEC_USER}" \
        -e OS_AUTH_URL="${OS_AUTH_URL:-}" \
        -e OS_USERNAME="${OS_USERNAME:-}" \
        -e OS_PASSWORD="${OS_PASSWORD:-}" \
        -e OS_TENANT_NAME="${OS_TENANT_NAME:-}" \
        -e OS_PROJECT_NAME="${OS_PROJECT_NAME:-}" \
        -e OS_REGION_NAME="${OS_REGION_NAME:-}" \
        -e OS_ENDPOINT_TYPE="${OS_ENDPOINT_TYPE:-}" \
        -e OS_INTERFACE="${OS_INTERFACE:-}" \
        -e OS_CACERT="${OS_CACERT:-}" \
        -e OS_INSECURE="${OS_INSECURE:-}" \
        -e OS_NO_CACHE="${OS_NO_CACHE:-true}" \
        -e OS_AUTH_STRATEGY="${OS_AUTH_STRATEGY:-keystone}" \
        -e NEUTRON_ENDPOINT_TYPE="${NEUTRON_ENDPOINT_TYPE:-publicURL}" \
        "${SERVICE_NAME}" "$@"
}

container_has_run_aria_mount() {
    docker inspect "${SERVICE_NAME}" \
        --format '{{range .Mounts}}{{if eq .Destination "/run/aria"}}yes{{end}}{{end}}' \
        2>/dev/null | grep -q yes
}

ensure_container_running() {
    if ! docker ps --format '{{.Names}}' | grep -qx "${SERVICE_NAME}"; then
        die "${SERVICE_NAME} is not running; run neutron_aria_container_smoke.sh first"
    fi
}

ensure_run_aria_mount() {
    if container_has_run_aria_mount; then
        return
    fi

    if [ "${AUTO_RESTART_WITH_RUN_ARIA}" != "true" ]; then
        die "${SERVICE_NAME} does not mount /run/aria"
    fi

    if [ -z "${IMAGE}" ]; then
        IMAGE="$(docker inspect "${SERVICE_NAME}" --format '{{.Config.Image}}')"
    fi

    echo "Restarting ${SERVICE_NAME} with ${RUN_ARIA_DIR} mounted"
    MOUNT_RUN_ARIA=true \
        RUN_ARIA_DIR="${RUN_ARIA_DIR}" \
        BUILD_IMAGE=false \
        STOP_EMBEDDED_SMOKE=false \
        SERVICE_NAME="${SERVICE_NAME}" \
        IMAGE="${IMAGE}" \
        bash "${REPO_ROOT}/deploy/kolla/smoke/neutron_aria_container_smoke.sh"
}

fix_uds_permissions() {
    if [ "${FIX_UDS_PERMISSIONS}" != "true" ]; then
        return
    fi

    exec_gid="$(docker exec "${SERVICE_NAME}" id -g "${EXEC_USER}")"
    chown "root:${exec_gid}" "${RUN_ARIA_DIR}" "${SOCKET_PATH}"
    chmod 0770 "${RUN_ARIA_DIR}"
    chmod 0660 "${SOCKET_PATH}"
}

prepare_full_resync_config() {
    docker exec -u root "${SERVICE_NAME}" sh -c "
        cp /etc/neutron-aria-agent/neutron-aria-agent.ini '${SMOKE_CONFIG}' &&
        sed -i 's/^host =.*/host = ${HOST_FQDN}/' '${SMOKE_CONFIG}' &&
        sed -i 's/^full_resync_enabled =.*/full_resync_enabled = true/' '${SMOKE_CONFIG}' &&
        sed -i 's/^port_source =.*/port_source = neutronclient/' '${SMOKE_CONFIG}' &&
        sed -i 's/^rpc_events_enabled =.*/rpc_events_enabled = false/' '${SMOKE_CONFIG}' &&
        chmod 0644 '${SMOKE_CONFIG}'
    "
    if [ -n "${ACL_FIXTURE_JSON}" ] || [ -n "${ACL_FIXTURE_FILE}" ]; then
        if [ -n "${ACL_FIXTURE_FILE}" ]; then
            [ -r "${ACL_FIXTURE_FILE}" ] || die "ACL_FIXTURE_FILE is not readable: ${ACL_FIXTURE_FILE}"
            docker cp "${ACL_FIXTURE_FILE}" "${SERVICE_NAME}:${CONTAINER_ACL_FIXTURE}"
        else
            printf '%s' "${ACL_FIXTURE_JSON}" | docker exec -i -u root "${SERVICE_NAME}" \
                sh -c "cat > '${CONTAINER_ACL_FIXTURE}'"
        fi
        docker exec -u root "${SERVICE_NAME}" sh -c "
            grep -q '^\[acl\]' '${SMOKE_CONFIG}' || printf '\n[acl]\n' >> '${SMOKE_CONFIG}'
            if grep -q '^fixture_path =' '${SMOKE_CONFIG}'; then
                sed -i 's#^fixture_path =.*#fixture_path = ${CONTAINER_ACL_FIXTURE}#' '${SMOKE_CONFIG}'
            else
                printf 'fixture_path = ${CONTAINER_ACL_FIXTURE}\n' >> '${SMOKE_CONFIG}'
            fi
            chmod 0644 '${CONTAINER_ACL_FIXTURE}' '${SMOKE_CONFIG}'
        "
    fi
}

rollback_managed_ports() {
    docker_exec_env python - "${SOCKET_PATH}" <<'PY'
from __future__ import print_function

import sys

from neutron_aria.agent.uds_client import LocalClient

socket_path = sys.argv[1]
client = LocalClient(socket_path, timeout=3.0)
status = client.status()
managed = status.get("managed_ports") or []
for port in managed:
    port_id = port.get("port_id")
    if port_id:
        response = client.delete_port(port_id)
        print("rollback_delete port_id=%s status=%s detached=%s" % (
            port_id,
            response.get("status"),
            response.get("detached"),
        ))
after = client.status()
remaining = after.get("managed_ports") or []
print("rollback_remaining_managed_ports=%d" % len(remaining))
if remaining:
    raise SystemExit(1)
PY
}

cleanup() {
    if [ "${ROLLBACK}" = "true" ] && [ "${ROLLBACK_ARMED:-false}" = "true" ]; then
        echo "Rolling back managed ports through ${SOCKET_PATH}"
        rollback_managed_ports || true
    fi
}

trap cleanup EXIT

need_command docker
source_adminrc
require_openstack_env

[ -d "${RUN_ARIA_DIR}" ] || die "missing ${RUN_ARIA_DIR}"
[ -S "${SOCKET_PATH}" ] || die "missing UDS socket ${SOCKET_PATH}"

if [ "${LEGACY_VALIDATE_OVSDB_IN_NEUTRON_AGENT}" = "true" ]; then
    need_command ovs-vsctl
    [ -S /run/openvswitch/db.sock ] || die "missing /run/openvswitch/db.sock"
    ovs-vsctl --timeout=5 br-exists "${OVS_BRIDGE}" || die "missing OVS bridge ${OVS_BRIDGE}"
fi

ensure_container_running
ensure_run_aria_mount
ensure_container_running
fix_uds_permissions

docker exec "${SERVICE_NAME}" test -S "${SOCKET_PATH}" || die "${SOCKET_PATH} is not visible in ${SERVICE_NAME}"
if [ "${LEGACY_VALIDATE_OVSDB_IN_NEUTRON_AGENT}" = "true" ]; then
    docker exec -u "${EXEC_USER}" "${SERVICE_NAME}" ovs-vsctl --timeout=5 br-exists "${OVS_BRIDGE}" || die "${OVS_BRIDGE} is not visible in ${SERVICE_NAME}"
fi

echo "Checking UDS capabilities and initial status"
docker_exec_env python - "${SOCKET_PATH}" <<'PY'
from __future__ import print_function

import json
import sys

from neutron_aria.agent.uds_client import LocalClient

socket_path = sys.argv[1]
client = LocalClient(socket_path, timeout=3.0)
capabilities = client.capabilities(required_domains=["acl"])
status = client.status()
managed = status.get("managed_ports") or []
print("capabilities=%s" % json.dumps(capabilities, sort_keys=True))
print("initial_generation=%s initial_managed_ports=%d" % (
    status.get("generation"),
    len(managed),
))
if managed:
    raise SystemExit("refusing full-resync smoke with existing managed ports")
PY

prepare_full_resync_config

echo "Checking neutronclient port source for ${HOST_FQDN}"
docker_exec_env python - "${SMOKE_CONFIG}" "${HOST_FQDN}" <<'PY'
from __future__ import print_function

import sys

from neutron_aria.agent.config import load_config
from neutron_aria.agent.neutron_client import build_port_source

config = load_config(sys.argv[1])
ports = build_port_source(config, sys.argv[2]).list_ports_for_host()
compute_ports = [
    port for port in ports
    if (port.get("device_owner") or "").startswith("compute:")
]
print("neutron_ports_for_host=%d compute_ports=%d" % (len(ports), len(compute_ports)))
PY

ROLLBACK_ARMED=true

echo "Submitting one full-resync snapshot"
docker_exec_env neutron-aria-agent \
    --config-file "${SMOKE_CONFIG}" \
    --neutron-config-file /etc/neutron/neutron.conf \
    --neutron-config-file /etc/neutron/plugins/ml2/openvswitch_agent.ini \
    --once \
    --enable-full-resync

echo "Checking post-snapshot status"
managed_count="$(
    docker_exec_env python - "${SOCKET_PATH}" "${EXPECTED_PORT_ID}" "${EXPECTED_IFNAME}" <<'PY'
from __future__ import print_function

import json
import sys

from neutron_aria.agent.uds_client import LocalClient

client = LocalClient(sys.argv[1], timeout=3.0)
expected_port_id = sys.argv[2]
expected_ifname = sys.argv[3]
status = client.status()
managed = status.get("managed_ports") or []
print(json.dumps(status, sort_keys=True))
print("MANAGED_COUNT=%d" % len(managed))
if expected_port_id:
    matches = [
        port for port in managed
        if port.get("port_id") == expected_port_id
        and (not expected_ifname or port.get("ifname") == expected_ifname)
    ]
    if not matches:
        raise SystemExit(
            "expected managed port not found: port_id=%s ifname=%s" % (
                expected_port_id,
                expected_ifname,
            )
        )
    matched = matches[0]
    print("EXPECTED_PORT_FOUND port_id=%s ifname=%s ifindex=%s domains=%s" % (
        matched.get("port_id"),
        matched.get("ifname"),
        matched.get("ifindex"),
        ",".join(matched.get("managed_domains") or []),
    ))
PY
)"
echo "${managed_count}"
managed_count="$(echo "${managed_count}" | awk -F= '/^MANAGED_COUNT=/{print $2}' | tail -1)"
managed_count="${managed_count:-0}"
if [ "${managed_count}" -lt "${MIN_MANAGED_PORTS}" ]; then
    die "managed port count ${managed_count} is below MIN_MANAGED_PORTS=${MIN_MANAGED_PORTS}"
fi

if [ "${ROLLBACK}" = "true" ]; then
    echo "Rolling back full-resync snapshot"
    rollback_managed_ports
    ROLLBACK_ARMED=false
fi

docker ps --filter "name=${SERVICE_NAME}" --format 'table {{.Names}}\t{{.Image}}\t{{.Status}}'
echo "neutron-aria-agent full-resync smoke passed on ${HOST_FQDN}"
