#!/usr/bin/env bash
set -euo pipefail

SERVICE_NAME="${SERVICE_NAME:-neutron_aria_agent}"
EXEC_USER="${EXEC_USER:-neutron}"
ADMINRC="${ADMINRC:-/root/adminrc}"
HOST_FQDN="${HOST_FQDN:-$(hostname -f)}"
SOCKET_PATH="${SOCKET_PATH:-/run/aria/aria-agent.sock}"
AGENT_TIMEOUT="${AGENT_TIMEOUT:-35}"
STARTUP_WAIT="${STARTUP_WAIT:-8}"
WORK_DIR="${WORK_DIR:-/tmp/neutron-aria-rpc-fanout-agent-$(date +%Y%m%d%H%M%S)}"
TARGET_PORT_ID="${TARGET_PORT_ID:-}"

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

neutron_cli() {
    if command -v neutron >/dev/null 2>&1; then
        neutron "$@"
        return
    fi
    docker exec \
        -u root \
        -e OS_USERNAME="${OS_USERNAME:-}" \
        -e OS_PASSWORD="${OS_PASSWORD:-}" \
        -e OS_TENANT_NAME="${OS_TENANT_NAME:-}" \
        -e OS_PROJECT_NAME="${OS_PROJECT_NAME:-}" \
        -e OS_AUTH_URL="${OS_AUTH_URL:-}" \
        -e OS_NO_CACHE="${OS_NO_CACHE:-true}" \
        -e OS_AUTH_STRATEGY="${OS_AUTH_STRATEGY:-keystone}" \
        -e OS_REGION_NAME="${OS_REGION_NAME:-}" \
        -e NEUTRON_ENDPOINT_TYPE="${NEUTRON_ENDPOINT_TYPE:-publicURL}" \
        openstack_client neutron "$@"
}

docker_exec_agent_env() {
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

rollback_managed_ports() {
    docker exec -i -u "${EXEC_USER}" "${SERVICE_NAME}" python - "${SOCKET_PATH}" <<'PY'
from __future__ import print_function

import sys

from neutron_aria.agent.uds_client import LocalClient

client = LocalClient(sys.argv[1], timeout=3.0)
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

write_temp_config() {
    local mode="$1"
    local cfg="/tmp/neutron-aria-rpc-fanout-${mode}.ini"
    local state_dir="/tmp/neutron-aria-rpc-fanout-state-${mode}"
    docker exec -i -u root "${SERVICE_NAME}" python - \
        "${cfg}" \
        "${HOST_FQDN}" \
        "${mode}" \
        "${state_dir}" <<'PY'
from __future__ import print_function

import os
import sys

try:
    import ConfigParser as configparser
except ImportError:
    import configparser

cfg, host, mode, state_dir = sys.argv[1:5]
src = "/etc/neutron-aria-agent/neutron-aria-agent.ini"

parser_class = getattr(configparser, "SafeConfigParser", configparser.ConfigParser)
parser = parser_class()
parser.read(src)

for section in ("agent", "neutron", "acl"):
    if not parser.has_section(section):
        parser.add_section(section)

parser.set("agent", "host", host)
parser.set("agent", "full_resync_enabled", "true")
parser.set("agent", "resync_interval", "3600")
parser.set("agent", "report_interval", "3600")
parser.set("agent", "state_dir", state_dir)
parser.set("neutron", "port_source", "neutronclient")
parser.set("neutron", "rpc_events_enabled", mode)
parser.set("neutron", "event_merge_interval", "0.2")
parser.set("acl", "source", "disabled")

if not os.path.exists(state_dir):
    os.makedirs(state_dir)
with open(cfg, "w") as stream:
    parser.write(stream)
os.chmod(cfg, 0o644)
PY
    docker exec -u root "${SERVICE_NAME}" chown -R "${EXEC_USER}:${EXEC_USER}" "${state_dir}"
    echo "${cfg}"
}

first_bound_port_id() {
    neutron_cli port-list -- --binding:host_id="${HOST_FQDN}" |
        awk -F"|" '/[0-9a-f-]{36}/ {gsub(/ /, "", $2); print $2; exit}'
}

trigger_port_update() {
    local label="$1"
    local port_id="${TARGET_PORT_ID}"

    if [ -z "${port_id}" ]; then
        port_id="$(first_bound_port_id)"
    fi
    [ -n "${port_id}" ] || die "no port bound to ${HOST_FQDN} for RPC fanout smoke"

    echo "target_port_${label}=${port_id}"
    docker_exec_agent_env python - \
        "${HOST_FQDN}" \
        "${port_id}" \
        "${label}" <<'PY'
from __future__ import print_function

import sys
import time

from neutron.common import config as common_config

common_config.init([
    "--config-file",
    "/etc/neutron/neutron.conf",
    "--config-file",
    "/etc/neutron/plugins/ml2/openvswitch_agent.ini",
])
try:
    common_config.setup_logging()
except Exception:
    pass

from neutron import context
from neutron.common import topics
from neutron.plugins.ml2.rpc import AgentNotifierApi

host, port_id, label = sys.argv[1:4]
port = {
    "id": port_id,
    "binding:host_id": host,
    "revision_number": int(time.time()),
}
AgentNotifierApi(topics.AGENT).port_update(
    context.get_admin_context(),
    port,
    None,
    None,
    None,
)
print("rpc_port_update_sent_%s=%s" % (label, port_id))
PY
}

run_agent_case() {
    local label="$1"
    local mode="$2"
    local cfg log trigger_log rc

    cfg="$(write_temp_config "${mode}")"
    log="${WORK_DIR}/${label}-agent.log"
    trigger_log="${WORK_DIR}/${label}-trigger.log"

    echo "== ${label} mode=${mode} cfg=${cfg} =="
    docker_exec_agent_env timeout "${AGENT_TIMEOUT}" \
        neutron-aria-agent \
        --config-file "${cfg}" \
        --neutron-config-file /etc/neutron/neutron.conf \
        --neutron-config-file /etc/neutron/plugins/ml2/openvswitch_agent.ini \
        >"${log}" 2>&1 &
    local pid=$!

    sleep "${STARTUP_WAIT}"
    trigger_port_update "${label}" >"${trigger_log}" 2>&1

    set +e
    wait "${pid}"
    rc=$?
    set -e
    echo "agent_rc_${label}=${rc}"
    if [ "${rc}" != "0" ] && [ "${rc}" != "124" ]; then
        tail -120 "${log}" || true
        die "${label} agent exited with rc=${rc}"
    fi

    tail -120 "${log}" || true
    tail -20 "${trigger_log}" || true
    rollback_managed_ports | tee "${WORK_DIR}/${label}-rollback.log"

    if [ "${mode}" = "false" ] && grep -q "event_batch_drained" "${log}"; then
        die "disabled case unexpectedly processed an event batch"
    fi
    if [ "${mode}" = "true" ]; then
        grep -q "event_batch_drained" "${log}" || \
            die "enabled case did not process an event batch"
        grep -q "port_updates=1" "${log}" || \
            die "enabled case did not process the port update"
    fi
}

need_command docker
source_adminrc
mkdir -p "${WORK_DIR}"

docker ps --format '{{.Names}}' | grep -qx "${SERVICE_NAME}" || \
    die "${SERVICE_NAME} is not running"
docker exec "${SERVICE_NAME}" test -S "${SOCKET_PATH}" || \
    die "${SOCKET_PATH} is not visible in ${SERVICE_NAME}"

echo "work=${WORK_DIR} host=${HOST_FQDN}"
rollback_managed_ports | tee "${WORK_DIR}/pre-rollback.log"
run_agent_case disabled false
run_agent_case enabled true

echo "rpc_fanout_agent_ab=pass work=${WORK_DIR}"
