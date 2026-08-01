#!/usr/bin/env bash
set -euo pipefail

SERVICE_NAME="${SERVICE_NAME:-neutron_aria_agent}"
DATAPATH_SERVICE_NAME="${DATAPATH_SERVICE_NAME:-aria_datapath}"
REPO_ROOT="${REPO_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)}"
HOST_FQDN="${HOST_FQDN:-$(hostname -f)}"
ADMINRC="${ADMINRC:-/root/adminrc}"
SOCKET_PATH="${SOCKET_PATH:-/run/aria/aria-agent.sock}"
SMOKE_CONFIG="${SMOKE_CONFIG:-/tmp/neutron-aria-agent-transaction-smoke.ini}"
STATE_DIR="${STATE_DIR:-/var/lib/neutron-aria-agent/state}"
STATE_FILE="${STATE_FILE:-${STATE_DIR}/snapshot-state.json}"
EXEC_USER="${EXEC_USER:-neutron}"
ROLLBACK="${ROLLBACK:-true}"
MIN_MANAGED_PORTS="${MIN_MANAGED_PORTS:-1}"
REQUEST_TIMEOUT_OVERRIDE="${REQUEST_TIMEOUT_OVERRIDE:-3.0}"

die() {
    echo "ERROR: $*" >&2
    exit 1
}

need_command() {
    command -v "$1" >/dev/null 2>&1 || die "missing command: $1"
}

require_positive_min_managed_ports() {
    case "${MIN_MANAGED_PORTS}" in
        ''|*[!0-9]*)
            die "MIN_MANAGED_PORTS must be an integer greater than or equal to 1"
            ;;
    esac
    [ "${MIN_MANAGED_PORTS}" -ge 1 ] || \
        die "MIN_MANAGED_PORTS must be an integer greater than or equal to 1"
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

client = LocalClient(sys.argv[1], timeout=3.0)
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
        echo "Rolling back transaction smoke managed ports"
        rollback_managed_ports || true
    fi
}

trap cleanup EXIT

managed_count() {
    docker_exec_env python - "${SOCKET_PATH}" <<'PY'
from __future__ import print_function

import sys

from neutron_aria.agent.uds_client import LocalClient

client = LocalClient(sys.argv[1], timeout=3.0)
print(len(client.status().get("managed_ports") or []))
PY
}

first_managed_port() {
    docker_exec_env python - "${SOCKET_PATH}" <<'PY'
from __future__ import print_function

import sys

from neutron_aria.agent.uds_client import LocalClient

client = LocalClient(sys.argv[1], timeout=3.0)
for port in client.status().get("managed_ports") or []:
    if port.get("port_id"):
        print(port.get("port_id"))
        break
PY
}

inject_pending_snapshot() {
    docker_exec_env python - "${SOCKET_PATH}" "${STATE_FILE}" <<'PY'
from __future__ import print_function

import json
import os
import sys
import time

from neutron_aria.agent.uds_client import LocalClient

socket_path, state_file = sys.argv[1:3]
client = LocalClient(socket_path, timeout=3.0)
status = client.status()
try:
    with open(state_file, "r") as fh:
        state = json.load(fh)
except IOError:
    state = {}

generation = int(
    status.get("applied_generation") or
    status.get("generation") or
    state.get("last_generation") or
    0
)
desired_hash = (
    status.get("applied_desired_hash") or
    status.get("desired_hash") or
    state.get("last_desired_hash")
)
if not generation or not desired_hash:
    raise SystemExit("cannot inject pending snapshot without generation and desired_hash")

managed = status.get("managed_ports") or []
projected = sorted([
    port.get("port_id") for port in managed
    if port.get("port_id")
])
state.setdefault("schema_version", 1)
state["pending_generation"] = generation
state["pending_desired_hash"] = desired_hash
state["pending_snapshot_ports"] = len(projected)
state["pending_projected_port_ids"] = projected
state["pending_since"] = time.time()
state["updated_at"] = time.time()
parent = os.path.dirname(state_file)
if parent and not os.path.isdir(parent):
    os.makedirs(parent)
tmp = "%s.tmp.%s" % (state_file, os.getpid())
with open(tmp, "w") as fh:
    json.dump(state, fh, sort_keys=True)
    fh.write("\n")
    fh.flush()
    os.fsync(fh.fileno())
os.rename(tmp, state_file)
print("injected_pending_snapshot generation=%s projected_ports=%s" % (
    generation,
    len(projected),
))
PY
}

assert_no_pending_snapshot() {
    docker_exec_env python - "${STATE_FILE}" <<'PY'
from __future__ import print_function

import json
import sys

with open(sys.argv[1], "r") as fh:
    state = json.load(fh)
print("state_after_pending_snapshot=%s" % json.dumps(state, sort_keys=True))
if state.get("pending_generation") or state.get("pending_desired_hash"):
    raise SystemExit("pending snapshot was not cleared")
PY
}

inject_pending_delete_after_datapath_delete() {
    docker_exec_env python - "${SOCKET_PATH}" "${STATE_FILE}" "$1" <<'PY'
from __future__ import print_function

import json
import os
import sys
import time

from neutron_aria.agent.uds_client import LocalClient

socket_path, state_file, port_id = sys.argv[1:4]
with open(state_file, "r") as fh:
    state = json.load(fh)
state["pending_delete_port_id"] = port_id
state["pending_delete_reason"] = "transaction_smoke_pending_delete"
state["pending_delete_since"] = time.time()
state["updated_at"] = time.time()
tmp = "%s.tmp.%s" % (state_file, os.getpid())
with open(tmp, "w") as fh:
    json.dump(state, fh, sort_keys=True)
    fh.write("\n")
    fh.flush()
    os.fsync(fh.fileno())
os.rename(tmp, state_file)
response = LocalClient(socket_path, timeout=3.0).delete_port(port_id)
print("injected_pending_delete port_id=%s response=%s" % (
    port_id,
    json.dumps(response, sort_keys=True),
))
PY
}

assert_no_pending_delete() {
    docker_exec_env python - "${STATE_FILE}" <<'PY'
from __future__ import print_function

import json
import sys

with open(sys.argv[1], "r") as fh:
    state = json.load(fh)
print("state_after_pending_delete=%s" % json.dumps(state, sort_keys=True))
if state.get("pending_delete_port_id"):
    raise SystemExit("pending delete was not cleared")
PY
}

run_migration_source_cleanup_delete() {
    docker_exec_env python - "${SOCKET_PATH}" "${STATE_DIR}" "${HOST_FQDN}" "$1" <<'PY'
from __future__ import print_function

import json
import sys

from neutron_aria.agent.event_loop import SnapshotSynchronizer
from neutron_aria.agent.state import SnapshotStateStore
from neutron_aria.agent.uds_client import LocalClient

socket_path, state_dir, host, port_id = sys.argv[1:5]

class EmptyPortSource(object):
    def get_ports(self):
        return []

sync = SnapshotSynchronizer(
    host,
    EmptyPortSource(),
    None,
    LocalClient(socket_path, timeout=3.0),
    state_store=SnapshotStateStore(state_dir),
)
response = sync.delete_port(port_id, reason="migration_source_cleanup")
print("migration_source_cleanup_delete=%s" % json.dumps(response, sort_keys=True))
PY
}

assert_last_deleted_port() {
    docker_exec_env python - "${STATE_FILE}" "$1" <<'PY'
from __future__ import print_function

import json
import sys

with open(sys.argv[1], "r") as fh:
    state = json.load(fh)
print("state_after_migration_cleanup=%s" % json.dumps(state, sort_keys=True))
if state.get("pending_delete_port_id"):
    raise SystemExit("migration cleanup left pending delete")
if state.get("last_deleted_port_id") != sys.argv[2]:
    raise SystemExit("migration cleanup did not record last_deleted_port_id")
PY
}

require_positive_min_managed_ports
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

echo "Cleaning existing managed ports before transaction smoke"
rollback_managed_ports

echo "Applying baseline full-resync snapshot"
run_agent_once
ROLLBACK_ARMED=true

count="$(managed_count)"
echo "baseline_managed_ports=${count}"
if [ "${count}" -lt "${MIN_MANAGED_PORTS}" ]; then
    die "managed port count ${count} is below MIN_MANAGED_PORTS=${MIN_MANAGED_PORTS}"
fi

echo "Testing pending snapshot restart recovery"
inject_pending_snapshot
docker restart "${SERVICE_NAME}" >/dev/null
sleep "${SMOKE_WAIT_SECONDS:-6}"
run_agent_once
assert_no_pending_snapshot

port_id="$(first_managed_port)"
[ -n "${port_id}" ] || \
    die "no managed port with port_id available for pending delete recovery"

echo "Testing pending delete restart recovery for ${port_id}"
inject_pending_delete_after_datapath_delete "${port_id}"
docker restart "${SERVICE_NAME}" >/dev/null
sleep "${SMOKE_WAIT_SECONDS:-6}"
run_agent_once
assert_no_pending_delete

port_id="$(first_managed_port)"
[ -n "${port_id}" ] || \
    die "no managed port with port_id available for migration-source cleanup"

echo "Testing migration-source cleanup delete transaction for ${port_id}"
run_migration_source_cleanup_delete "${port_id}"
assert_last_deleted_port "${port_id}"
run_agent_once

if [ "${ROLLBACK}" = "true" ]; then
    echo "Rolling back transaction smoke managed ports"
    rollback_managed_ports
    ROLLBACK_ARMED=false
fi

docker ps --filter "name=${SERVICE_NAME}" --format 'table {{.Names}}\t{{.Image}}\t{{.Status}}'
echo "neutron-aria-agent transaction state smoke passed on ${HOST_FQDN}"
