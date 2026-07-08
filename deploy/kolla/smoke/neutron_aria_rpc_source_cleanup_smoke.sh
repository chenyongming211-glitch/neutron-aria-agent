#!/usr/bin/env bash
set -euo pipefail

SERVICE_NAME="${SERVICE_NAME:-neutron_aria_agent}"
EXEC_USER="${EXEC_USER:-neutron}"
ADMINRC="${ADMINRC:-/root/adminrc}"
HOST_FQDN="${HOST_FQDN:-$(hostname -f)}"
SOCKET_PATH="${SOCKET_PATH:-/run/aria/aria-agent.sock}"
AGENT_TIMEOUT="${AGENT_TIMEOUT:-45}"
STARTUP_WAIT="${STARTUP_WAIT:-10}"
STARTUP_CONVERGENCE_TIMEOUT="${STARTUP_CONVERGENCE_TIMEOUT:-60}"
ROLLBACK_CONVERGENCE_ATTEMPTS="${ROLLBACK_CONVERGENCE_ATTEMPTS:-8}"
ROLLBACK_CONVERGENCE_INTERVAL="${ROLLBACK_CONVERGENCE_INTERVAL:-1.0}"
WORK_DIR="${WORK_DIR:-/tmp/neutron-aria-rpc-source-cleanup-$(date +%Y%m%d%H%M%S)}"
EVENT_PORT_ID="${EVENT_PORT_ID:-}"
EVENT_BINDING_HOST="${EVENT_BINDING_HOST:-}"

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
    docker exec -i -u "${EXEC_USER}" "${SERVICE_NAME}" python - \
        "${SOCKET_PATH}" \
        "${ROLLBACK_CONVERGENCE_ATTEMPTS}" \
        "${ROLLBACK_CONVERGENCE_INTERVAL}" <<'PY'
from __future__ import print_function

import sys
import time

from neutron_aria.agent.uds_client import LocalApiTimeoutError
from neutron_aria.agent.uds_client import LocalClient

client = LocalClient(sys.argv[1], timeout=3.0)
attempts = int(sys.argv[2])
interval = float(sys.argv[3])

def managed_ids():
    status = client.status()
    return sorted([
        port.get("port_id") for port in status.get("managed_ports") or []
        if port.get("port_id")
    ])

def delete_with_convergence(port_id):
    last_error = None
    for attempt in range(1, attempts + 1):
        try:
            response = client.delete_port(port_id)
            print("rollback_delete port_id=%s status=%s detached=%s attempt=%s" % (
                port_id,
                response.get("status"),
                response.get("detached"),
                attempt,
            ))
            return
        except LocalApiTimeoutError as exc:
            last_error = exc
            print("rollback_delete_timeout port_id=%s attempt=%s error=%s" % (
                port_id,
                attempt,
                exc,
            ))
        time.sleep(interval)
        if port_id not in managed_ids():
            print("rollback_delete_converged port_id=%s attempt=%s" % (
                port_id,
                attempt,
            ))
            return
    raise SystemExit("rollback delete did not converge for %s: %s" % (
        port_id,
        last_error,
    ))

status = client.status()
managed = status.get("managed_ports") or []
for port in managed:
    port_id = port.get("port_id")
    if port_id:
        delete_with_convergence(port_id)

remaining = managed_ids()
print("rollback_remaining_managed_ports=%d" % len(remaining))
if remaining:
    print("rollback_remaining_port_ids=%s" % ",".join(remaining))
    raise SystemExit(1)
PY
}

wait_for_initial_convergence() {
    local log="$1"
    local waited=0
    while [ "${waited}" -lt "${STARTUP_CONVERGENCE_TIMEOUT}" ]; do
        if grep -q "full_resync_complete" "${log}"; then
            echo "initial_full_resync_converged=true waited=${waited}"
            return 0
        fi
        sleep 1
        waited=$((waited + 1))
    done
    tail -160 "${log}" || true
    die "initial full-resync did not converge within ${STARTUP_CONVERGENCE_TIMEOUT}s"
}

write_temp_config() {
    local cfg="/tmp/neutron-aria-rpc-source-cleanup.ini"
    local state_dir="/tmp/neutron-aria-rpc-source-cleanup-state"
    docker exec -i -u root "${SERVICE_NAME}" python - \
        "${cfg}" \
        "${HOST_FQDN}" \
        "${state_dir}" <<'PY'
from __future__ import print_function

import os
import sys

try:
    import ConfigParser as configparser
except ImportError:
    import configparser

cfg, host, state_dir = sys.argv[1:4]
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
parser.set("neutron", "rpc_events_enabled", "true")
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

managed_port_count() {
    docker exec -i -u "${EXEC_USER}" "${SERVICE_NAME}" python - "${SOCKET_PATH}" <<'PY'
from __future__ import print_function

import sys

from neutron_aria.agent.uds_client import LocalClient

client = LocalClient(sys.argv[1], timeout=3.0)
status = client.status()
print(len(status.get("managed_ports") or []))
PY
}

first_managed_port_id() {
    docker exec -i -u "${EXEC_USER}" "${SERVICE_NAME}" python - "${SOCKET_PATH}" <<'PY'
from __future__ import print_function

import sys

from neutron_aria.agent.uds_client import LocalClient

client = LocalClient(sys.argv[1], timeout=3.0)
status = client.status()
managed = status.get("managed_ports") or []
ids = sorted([port.get("port_id") for port in managed if port.get("port_id")])
if ids:
    print(ids[0])
PY
}

assert_not_managed() {
    local port_id="$1"
    docker exec -i -u "${EXEC_USER}" "${SERVICE_NAME}" python - \
        "${SOCKET_PATH}" \
        "${port_id}" <<'PY'
from __future__ import print_function

import sys

from neutron_aria.agent.uds_client import LocalClient

socket_path, expected_absent = sys.argv[1:3]
client = LocalClient(socket_path, timeout=3.0)
status = client.status()
managed = status.get("managed_ports") or []
ids = sorted([port.get("port_id") for port in managed if port.get("port_id")])
print("managed_port_ids=%s" % ",".join(ids))
if expected_absent in ids:
    raise SystemExit(1)
PY
}

send_migration_source_update() {
    local port_id="$1"
    local binding_host="$2"

    docker_exec_agent_env python - \
        "${binding_host}" \
        "${port_id}" <<'PY'
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

binding_host, port_id = sys.argv[1:3]
port = {
    "id": port_id,
    "binding:host_id": binding_host,
    "revision_number": int(time.time()),
}
AgentNotifierApi(topics.AGENT).port_update(
    context.get_admin_context(),
    port,
    None,
    None,
    None,
)
print("rpc_source_cleanup_update_sent port_id=%s binding_host=%s" % (
    port_id,
    binding_host,
))
PY
}

run_source_cleanup_case() {
    local cfg log trigger_log rc initial_managed final_managed expected_after
    local full_resync_count

    [ -n "${EVENT_BINDING_HOST}" ] || die "EVENT_BINDING_HOST is required"
    [ "${EVENT_BINDING_HOST}" != "${HOST_FQDN}" ] || \
        die "EVENT_BINDING_HOST must differ from HOST_FQDN"

    cfg="$(write_temp_config)"
    log="${WORK_DIR}/agent.log"
    trigger_log="${WORK_DIR}/trigger.log"

    echo "host=${HOST_FQDN} new_binding_host=${EVENT_BINDING_HOST}"
    docker_exec_agent_env timeout "${AGENT_TIMEOUT}" \
        neutron-aria-agent \
        --config-file "${cfg}" \
        --neutron-config-file /etc/neutron/neutron.conf \
        --neutron-config-file /etc/neutron/plugins/ml2/openvswitch_agent.ini \
        >"${log}" 2>&1 &
    local pid=$!

    wait_for_initial_convergence "${log}"
    initial_managed="$(managed_port_count)"
    echo "initial_managed_ports=${initial_managed}"
    [ "${initial_managed}" -gt 0 ] || die "source-cleanup smoke needs at least one locally managed port"
    if [ -z "${EVENT_PORT_ID}" ]; then
        EVENT_PORT_ID="$(first_managed_port_id)"
    fi
    [ -n "${EVENT_PORT_ID}" ] || die "no local managed port available"
    echo "source_cleanup_port=${EVENT_PORT_ID}"

    send_migration_source_update "${EVENT_PORT_ID}" "${EVENT_BINDING_HOST}" \
        >"${trigger_log}" 2>&1

    set +e
    wait "${pid}"
    rc=$?
    set -e
    echo "agent_rc=${rc}"
    if [ "${rc}" != "0" ] && [ "${rc}" != "124" ]; then
        tail -140 "${log}" || true
        die "agent exited with rc=${rc}"
    fi

    tail -160 "${log}" || true
    tail -20 "${trigger_log}" || true

    grep -q "event_batch_drained" "${log}" || \
        die "source cleanup event did not reach the event merger"
    grep -q "port_updates=1" "${log}" || \
        die "source cleanup event did not include one port update"
    grep -q "delete_port_complete .*reason=migration_source_cleanup" "${log}" || \
        die "source cleanup did not call migration_source_cleanup delete"
    grep -q "service_result action=event_batch" "${log}" || \
        die "source cleanup event was not processed by the service loop"

    full_resync_count="$(grep -c "full_resync_complete" "${log}" || true)"
    echo "full_resync_complete_count=${full_resync_count}"
    if [ "${full_resync_count}" != "1" ]; then
        die "source cleanup event triggered an unexpected full resync"
    fi

    assert_not_managed "${EVENT_PORT_ID}" | tee "${WORK_DIR}/source-cleanup-managed-check.log"
    final_managed="$(managed_port_count)"
    echo "final_managed_ports_before_rollback=${final_managed}"
    expected_after=$((initial_managed - 1))
    if [ "${final_managed}" != "${expected_after}" ]; then
        die "source cleanup managed port count mismatch: expected ${expected_after}, got ${final_managed}"
    fi
}

need_command docker
source_adminrc
mkdir -p "${WORK_DIR}"

docker ps --format '{{.Names}}' | grep -qx "${SERVICE_NAME}" || \
    die "${SERVICE_NAME} is not running"
docker exec "${SERVICE_NAME}" test -S "${SOCKET_PATH}" || \
    die "${SOCKET_PATH} is not visible in ${SERVICE_NAME}"

echo "work=${WORK_DIR}"
rollback_managed_ports | tee "${WORK_DIR}/pre-rollback.log"
run_source_cleanup_case
rollback_managed_ports | tee "${WORK_DIR}/post-rollback.log"

echo "rpc_source_cleanup=pass work=${WORK_DIR}"
