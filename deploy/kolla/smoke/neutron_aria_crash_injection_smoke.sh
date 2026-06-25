#!/usr/bin/env bash
set -euo pipefail

SERVICE_NAME="${SERVICE_NAME:-neutron_aria_agent}"
DATAPATH_SERVICE_NAME="${DATAPATH_SERVICE_NAME:-aria_datapath}"
REPO_ROOT="${REPO_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)}"
HOST_FQDN="${HOST_FQDN:-$(hostname -f)}"
ADMINRC="${ADMINRC:-/root/adminrc}"
SOCKET_PATH="${SOCKET_PATH:-/run/aria/aria-agent.sock}"
SMOKE_CONFIG="${SMOKE_CONFIG:-/tmp/neutron-aria-agent-crash-smoke.ini}"
STATE_DIR="${STATE_DIR:-/var/lib/neutron-aria-agent/state}"
STATE_FILE="${STATE_FILE:-${STATE_DIR}/snapshot-state.json}"
EXEC_USER="${EXEC_USER:-neutron}"
ROLLBACK="${ROLLBACK:-true}"
MIN_MANAGED_PORTS="${MIN_MANAGED_PORTS:-0}"
RESTART_DATAPATH="${RESTART_DATAPATH:-true}"
REQUEST_TIMEOUT_OVERRIDE="${REQUEST_TIMEOUT_OVERRIDE:-10.0}"

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

prepare_full_resync_config() {
    docker exec -u root "${SERVICE_NAME}" sh -c "
        cp /etc/neutron-aria-agent/neutron-aria-agent.ini '${SMOKE_CONFIG}' &&
        sed -i 's/^host =.*/host = ${HOST_FQDN}/' '${SMOKE_CONFIG}' &&
        sed -i 's/^full_resync_enabled =.*/full_resync_enabled = true/' '${SMOKE_CONFIG}' &&
        sed -i 's/^port_source =.*/port_source = neutronclient/' '${SMOKE_CONFIG}' &&
        sed -i 's/^rpc_events_enabled =.*/rpc_events_enabled = false/' '${SMOKE_CONFIG}' &&
        if grep -q '^request_timeout =' '${SMOKE_CONFIG}'; then
            sed -i 's/^request_timeout =.*/request_timeout = ${REQUEST_TIMEOUT_OVERRIDE}/' '${SMOKE_CONFIG}';
        else
            printf '\n[aria]\nrequest_timeout = ${REQUEST_TIMEOUT_OVERRIDE}\n' >> '${SMOKE_CONFIG}';
        fi &&
        chmod 0644 '${SMOKE_CONFIG}'
    "
}

run_agent_once() {
    docker_exec_env neutron-aria-agent \
        --config-file "${SMOKE_CONFIG}" \
        --neutron-config-file /etc/neutron/neutron.conf \
        --neutron-config-file /etc/neutron/plugins/ml2/openvswitch_agent.ini \
        --once \
        --enable-full-resync
}

rollback_managed_ports() {
    docker_exec_env python - "${SOCKET_PATH}" <<'PY'
from __future__ import print_function

import sys

from neutron_aria.agent.uds_client import LocalClient

client = LocalClient(sys.argv[1], timeout=10.0)
status = client.status()
for port in status.get("managed_ports") or []:
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
    if [ "${ROLLBACK_ARMED:-false}" = "true" ] && [ "${ROLLBACK}" = "true" ]; then
        echo "Rolling back crash injection smoke managed ports"
        rollback_managed_ports || true
    fi
}

trap cleanup EXIT

managed_count() {
    docker_exec_env python - "${SOCKET_PATH}" <<'PY'
from __future__ import print_function

import sys

from neutron_aria.agent.uds_client import LocalClient

print(len(LocalClient(sys.argv[1], timeout=10.0).status().get("managed_ports") or []))
PY
}

first_managed_port() {
    docker_exec_env python - "${SOCKET_PATH}" <<'PY'
from __future__ import print_function

import sys

from neutron_aria.agent.uds_client import LocalClient

for port in LocalClient(sys.argv[1], timeout=10.0).status().get("managed_ports") or []:
    if port.get("port_id"):
        print(port.get("port_id"))
        break
PY
}

kill_after_prepare_snapshot() {
    set +e
    docker_exec_env python - "${STATE_FILE}" <<'PY'
from __future__ import print_function

import json
import os
import signal
import sys
import time

state_file = sys.argv[1]
with open(state_file, "r") as fh:
    state = json.load(fh)
last_generation = int(state.get("last_generation") or 0)
last_hash = state.get("last_desired_hash")
if not last_generation or not last_hash:
    raise SystemExit("cannot inject prepare crash without committed state")
state["pending_generation"] = last_generation
state["pending_desired_hash"] = last_hash
state["pending_snapshot_ports"] = int(state.get("last_snapshot_ports") or 0)
state["pending_projected_port_ids"] = list(state.get("last_projected_port_ids") or [])
state["pending_since"] = time.time()
state["updated_at"] = time.time()
tmp = "%s.tmp.%s" % (state_file, os.getpid())
with open(tmp, "w") as fh:
    json.dump(state, fh, sort_keys=True)
    fh.write("\n")
    fh.flush()
    os.fsync(fh.fileno())
os.rename(tmp, state_file)
print("prepared_pending_snapshot_then_sigkill generation=%s" % last_generation)
os.kill(os.getpid(), signal.SIGKILL)
PY
    rc=$?
    set -e
    if [ "${rc}" -ne 137 ] && [ "${rc}" -ne 247 ]; then
        die "prepare crash process exited with unexpected rc=${rc}"
    fi
}

kill_after_datapath_delete_before_commit() {
    set +e
    docker_exec_env python - "${SOCKET_PATH}" "${STATE_FILE}" "$1" <<'PY'
from __future__ import print_function

import json
import os
import signal
import sys
import time

from neutron_aria.agent.uds_client import LocalClient

socket_path, state_file, port_id = sys.argv[1:4]
with open(state_file, "r") as fh:
    state = json.load(fh)
state["pending_delete_port_id"] = port_id
state["pending_delete_reason"] = "crash_injection_delete_before_commit"
state["pending_delete_since"] = time.time()
state["updated_at"] = time.time()
tmp = "%s.tmp.%s" % (state_file, os.getpid())
with open(tmp, "w") as fh:
    json.dump(state, fh, sort_keys=True)
    fh.write("\n")
    fh.flush()
    os.fsync(fh.fileno())
os.rename(tmp, state_file)
response = LocalClient(socket_path, timeout=10.0).delete_port(port_id)
print("datapath_delete_done_then_sigkill port_id=%s response=%s" % (
    port_id,
    json.dumps(response, sort_keys=True),
))
os.kill(os.getpid(), signal.SIGKILL)
PY
    rc=$?
    set -e
    if [ "${rc}" -ne 137 ] && [ "${rc}" -ne 247 ]; then
        die "delete crash process exited with unexpected rc=${rc}"
    fi
}

assert_state_clean() {
    docker_exec_env python - "${STATE_FILE}" <<'PY'
from __future__ import print_function

import json
import sys

with open(sys.argv[1], "r") as fh:
    state = json.load(fh)
print("crash_smoke_state=%s" % json.dumps(state, sort_keys=True))
if state.get("pending_generation") or state.get("pending_desired_hash"):
    raise SystemExit("pending snapshot was not recovered")
if state.get("pending_delete_port_id"):
    raise SystemExit("pending delete was not recovered")
PY
}

wait_for_datapath_socket() {
    for _ in $(seq 1 30); do
        if docker exec "${SERVICE_NAME}" test -S "${SOCKET_PATH}" 2>/dev/null; then
            return 0
        fi
        sleep 1
    done
    die "timed out waiting for ${SOCKET_PATH}"
}

check_datapath_status() {
    docker_exec_env python - "${SOCKET_PATH}" <<'PY'
from __future__ import print_function

import json
import sys

from neutron_aria.agent.uds_client import LocalClient

status = LocalClient(sys.argv[1], timeout=10.0).status()
print("datapath_status=%s" % json.dumps(status, sort_keys=True))
if status.get("status") == "blocked":
    raise SystemExit("datapath status is blocked")
PY
}

need_command docker
source_adminrc
require_openstack_env

docker ps --format '{{.Names}}' | grep -qx "${SERVICE_NAME}" || \
    die "${SERVICE_NAME} is not running"
docker ps --format '{{.Names}}' | grep -qx "${DATAPATH_SERVICE_NAME}" || \
    die "${DATAPATH_SERVICE_NAME} is not running"
docker exec "${SERVICE_NAME}" test -S "${SOCKET_PATH}" || \
    die "${SOCKET_PATH} is not visible in ${SERVICE_NAME}"

prepare_full_resync_config

echo "Cleaning existing managed ports before crash injection smoke"
rollback_managed_ports

echo "Applying baseline full-resync snapshot"
run_agent_once
ROLLBACK_ARMED=true

count="$(managed_count)"
echo "baseline_managed_ports=${count}"
if [ "${count}" -lt "${MIN_MANAGED_PORTS}" ]; then
    die "managed port count ${count} is below MIN_MANAGED_PORTS=${MIN_MANAGED_PORTS}"
fi

echo "Injecting agent crash after local snapshot prepare"
kill_after_prepare_snapshot
docker restart "${SERVICE_NAME}" >/dev/null
sleep "${SMOKE_WAIT_SECONDS:-6}"
run_agent_once
assert_state_clean

port_id="$(first_managed_port)"
if [ -z "${port_id}" ]; then
    echo "No managed port on ${HOST_FQDN}; skipping delete crash cut-point"
else
    echo "Injecting agent crash after datapath delete and before local delete commit for ${port_id}"
    kill_after_datapath_delete_before_commit "${port_id}"
    docker restart "${SERVICE_NAME}" >/dev/null
    sleep "${SMOKE_WAIT_SECONDS:-6}"
    run_agent_once
    assert_state_clean
fi

if [ "${RESTART_DATAPATH}" = "true" ]; then
    echo "Restarting datapath container to verify replay/status recovery"
    docker restart "${DATAPATH_SERVICE_NAME}" >/dev/null
    wait_for_datapath_socket
    check_datapath_status
    run_agent_once
    assert_state_clean
fi

if [ "${ROLLBACK}" = "true" ]; then
    echo "Rolling back crash injection smoke managed ports"
    rollback_managed_ports
    ROLLBACK_ARMED=false
fi

docker ps --filter "name=${SERVICE_NAME}" --format 'table {{.Names}}\t{{.Image}}\t{{.Status}}'
docker ps --filter "name=${DATAPATH_SERVICE_NAME}" --format 'table {{.Names}}\t{{.Image}}\t{{.Status}}'
echo "neutron-aria-agent crash injection smoke passed on ${HOST_FQDN}"
