#!/usr/bin/env bash
set -euo pipefail

SERVICE_NAME="${SERVICE_NAME:-neutron_aria_agent}"
REPO_ROOT="${REPO_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)}"
HOST_FQDN="${HOST_FQDN:-$(hostname -f)}"
CLI_CONTAINER="${CLI_CONTAINER:-openstack_client}"
ADMINRC="${ADMINRC:-/root/adminrc}"
SOCKET_PATH="${SOCKET_PATH:-/run/aria/aria-agent.sock}"
SMOKE_CONFIG="${SMOKE_CONFIG:-/tmp/neutron-aria-agent-vm-migration.ini}"
EXEC_USER="${EXEC_USER:-neutron}"
PHASE="${PHASE:-source}"
ROLLBACK="${ROLLBACK:-true}"
ALLOW_VM_MIGRATE="${ALLOW_VM_MIGRATE:-false}"
DEST_HOST="${DEST_HOST:-}"
MIGRATION_WAIT_SECONDS="${MIGRATION_WAIT_SECONDS:-600}"
REQUEST_TIMEOUT_OVERRIDE="${REQUEST_TIMEOUT_OVERRIDE:-3.0}"
PING_COUNT="${PING_COUNT:-2}"
PING_TIMEOUT="${PING_TIMEOUT:-1}"
BLOCK_MIGRATE="${BLOCK_MIGRATE:-false}"
WAL_REPLAY_FAILURE_MAX_DELTA="${WAL_REPLAY_FAILURE_MAX_DELTA:-0}"
WAL_REPLAY_FAILURE_BASELINE="${WAL_REPLAY_FAILURE_BASELINE:-}"
PYTHON_BIN="${PYTHON_BIN:-}"

VM_IP="${VM_IP:-}"
SERVER_ID="${SERVER_ID:-}"
EXPECTED_PORT_ID="${EXPECTED_PORT_ID:-}"
EXPECTED_IFNAME="${EXPECTED_IFNAME:-}"

die() {
    echo "ERROR: $*" >&2
    exit 1
}

need_command() {
    command -v "$1" >/dev/null 2>&1 || die "missing command: $1"
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

openstack_cli() {
    docker exec "${CLI_CONTAINER}" bash -lc \
        "source '${ADMINRC}' >/dev/null 2>&1 || true; $*"
}

load_openstack_env() {
    while IFS='=' read -r key value; do
        case "${key}" in
            OS_AUTH_URL|OS_USERNAME|OS_PASSWORD|OS_TENANT_NAME|OS_PROJECT_NAME|OS_REGION_NAME|OS_ENDPOINT_TYPE|OS_INTERFACE|OS_CACERT|OS_INSECURE|OS_NO_CACHE|OS_AUTH_STRATEGY|NEUTRON_ENDPOINT_TYPE)
                export "${key}=${value}"
                ;;
        esac
    done < <(
        docker exec "${CLI_CONTAINER}" bash -lc \
            "source '${ADMINRC}' >/dev/null 2>&1 || true; env | grep -E '^OS_|^NEUTRON_ENDPOINT_TYPE='"
    )
}

port_field() {
    local port_id="$1"
    local field="$2"
    openstack_cli "neutron port-show '${port_id}' -f json" |
        FIELD="${field}" "${PYTHON_BIN}" -c '
from __future__ import print_function

import json
import os
import sys

field = os.environ["FIELD"]
payload = json.load(sys.stdin)
value = None
if isinstance(payload, list):
    for item in payload:
        if item.get("Field") == field:
            value = item.get("Value")
            break
else:
    value = payload.get(field)
if value is not None:
    print(value)
'
}

server_field() {
    local server_id="$1"
    local field="$2"
    openstack_cli "nova show '${server_id}'" |
        FIELD="${field}" awk -F'|' '
            function trim(value) {
                gsub(/^[ \t]+|[ \t]+$/, "", value)
                return value
            }
            NF >= 3 && trim($2) == ENVIRON["FIELD"] {
                print trim($3)
                exit
            }
        '
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

status_json() {
    docker_exec_env python - "${SOCKET_PATH}" <<'PY'
from __future__ import print_function

import json
import sys

from neutron_aria.agent.uds_client import LocalClient

status = LocalClient(sys.argv[1], timeout=3.0).status()
print(json.dumps(status, sort_keys=True))
PY
}

current_wal_replay_failures() {
    status_json | "${PYTHON_BIN}" -c '
from __future__ import print_function

import json
import sys

payload = json.load(sys.stdin)
print(int(payload.get("wal_replay_failures") or 0))
'
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
        echo "Rolling back migration smoke managed ports"
        rollback_managed_ports || true
    fi
}

trap cleanup EXIT

ifindex_of() {
    ip -o link show dev "${EXPECTED_IFNAME}" | awk -F: '{print $1}' | tr -d ' '
}

assert_xdp_attached() {
    ip -d link show dev "${EXPECTED_IFNAME}" | grep -q 'xdp' || \
        die "expected XDP attachment on ${EXPECTED_IFNAME}"
}

assert_target_managed() {
    local expected_ifindex="$1"
    STATUS_PAYLOAD="$(status_json)" EXPECTED_PORT_ID="${EXPECTED_PORT_ID}" \
        EXPECTED_IFNAME="${EXPECTED_IFNAME}" EXPECTED_IFINDEX="${expected_ifindex}" \
        WAL_REPLAY_FAILURE_BASELINE="${WAL_REPLAY_FAILURE_BASELINE}" \
        WAL_REPLAY_FAILURE_MAX_DELTA="${WAL_REPLAY_FAILURE_MAX_DELTA}" \
        "${PYTHON_BIN}" - <<'PY'
from __future__ import print_function

import json
import os

payload = json.loads(os.environ["STATUS_PAYLOAD"])
expected_port_id = os.environ["EXPECTED_PORT_ID"]
expected_ifname = os.environ["EXPECTED_IFNAME"]
expected_ifindex = int(os.environ["EXPECTED_IFINDEX"])
managed = payload.get("managed_ports") or []
for port in managed:
    if port.get("port_id") == expected_port_id:
        if port.get("ifname") != expected_ifname:
            raise SystemExit("ifname mismatch: %s" % payload)
        if int(port.get("ifindex") or -1) != expected_ifindex:
            raise SystemExit("ifindex mismatch: %s" % payload)
        print("target_managed_ok port_id=%s ifname=%s ifindex=%s" % (
            expected_port_id,
            expected_ifname,
            expected_ifindex,
        ))
        break
else:
    raise SystemExit("target port is not managed: %s" % payload)
if payload.get("authority_state") != "ready":
    raise SystemExit("authority_state is not ready: %s" % payload)
current = int(payload.get("wal_replay_failures") or 0)
baseline = int(os.environ["WAL_REPLAY_FAILURE_BASELINE"] or 0)
max_delta = int(os.environ["WAL_REPLAY_FAILURE_MAX_DELTA"] or 0)
if current > baseline + max_delta:
    raise SystemExit(
        "wal_replay_failures increased: baseline=%d current=%d max_delta=%d payload=%s" %
        (baseline, current, max_delta, payload)
    )
PY
}

assert_target_not_managed() {
    STATUS_PAYLOAD="$(status_json)" EXPECTED_PORT_ID="${EXPECTED_PORT_ID}" \
        WAL_REPLAY_FAILURE_BASELINE="${WAL_REPLAY_FAILURE_BASELINE}" \
        WAL_REPLAY_FAILURE_MAX_DELTA="${WAL_REPLAY_FAILURE_MAX_DELTA}" \
        "${PYTHON_BIN}" - <<'PY'
from __future__ import print_function

import json
import os

payload = json.loads(os.environ["STATUS_PAYLOAD"])
expected_port_id = os.environ["EXPECTED_PORT_ID"]
if any(port.get("port_id") == expected_port_id for port in (payload.get("managed_ports") or [])):
    raise SystemExit("target port is still managed on source host: %s" % payload)
if payload.get("authority_state") != "ready":
    raise SystemExit("authority_state is not ready: %s" % payload)
current = int(payload.get("wal_replay_failures") or 0)
baseline = int(os.environ["WAL_REPLAY_FAILURE_BASELINE"] or 0)
max_delta = int(os.environ["WAL_REPLAY_FAILURE_MAX_DELTA"] or 0)
if current > baseline + max_delta:
    raise SystemExit(
        "wal_replay_failures increased: baseline=%d current=%d max_delta=%d payload=%s" %
        (baseline, current, max_delta, payload)
    )
print("target_not_managed_ok port_id=%s" % expected_port_id)
PY
}

wait_port_host() {
    local wanted="$1"
    local host
    for _ in $(seq 1 "${MIGRATION_WAIT_SECONDS}"); do
        host="$(port_field "${EXPECTED_PORT_ID}" binding:host_id || true)"
        if [ "${host}" = "${wanted}" ]; then
            return 0
        fi
        sleep 1
    done
    die "port ${EXPECTED_PORT_ID} did not bind to ${wanted}"
}

wait_server_host() {
    local wanted="$1"
    local host status
    for _ in $(seq 1 "${MIGRATION_WAIT_SECONDS}"); do
        status="$(server_field "${SERVER_ID}" status || true)"
        host="$(server_field "${SERVER_ID}" OS-EXT-SRV-ATTR:host || true)"
        if [ "${status}" = "ACTIVE" ] && [ "${host}" = "${wanted}" ]; then
            return 0
        fi
        sleep 1
    done
    openstack_cli "nova show '${SERVER_ID}'" || true
    die "server ${SERVER_ID} did not become ACTIVE on ${wanted}"
}

wait_tap() {
    for _ in $(seq 1 "${MIGRATION_WAIT_SECONDS}"); do
        if ip link show dev "${EXPECTED_IFNAME}" >/dev/null 2>&1; then
            return 0
        fi
        sleep 1
    done
    die "tap ${EXPECTED_IFNAME} did not appear on ${HOST_FQDN}"
}

wait_tap_absent() {
    for _ in $(seq 1 "${MIGRATION_WAIT_SECONDS}"); do
        if ! ip link show dev "${EXPECTED_IFNAME}" >/dev/null 2>&1; then
            return 0
        fi
        sleep 1
    done
    die "tap ${EXPECTED_IFNAME} still exists on source host ${HOST_FQDN}"
}

wait_ping() {
    for _ in $(seq 1 "${MIGRATION_WAIT_SECONDS}"); do
        if ping -c "${PING_COUNT}" -W "${PING_TIMEOUT}" "${VM_IP}" >/dev/null 2>&1; then
            return 0
        fi
        sleep 1
    done
    die "VM ${VM_IP} did not become reachable"
}

run_live_migration() {
    local block_arg=""
    [ "${BLOCK_MIGRATE}" = "true" ] && block_arg="--block-migrate"
    echo "Starting live migration server=${SERVER_ID} dest=${DEST_HOST} block=${BLOCK_MIGRATE}"
    openstack_cli "nova live-migration ${block_arg} '${SERVER_ID}' '${DEST_HOST}'"
}

need_command docker
need_command ip
need_command ping
if [ -z "${PYTHON_BIN}" ]; then
    PYTHON_BIN="$(command -v python3 || command -v python || true)"
fi
[ -n "${PYTHON_BIN}" ] || die "missing command: python3 or python"

docker ps --format '{{.Names}}' | grep -qx "${SERVICE_NAME}" || \
    die "${SERVICE_NAME} is not running"
docker ps --format '{{.Names}}' | grep -qx "${CLI_CONTAINER}" || \
    die "${CLI_CONTAINER} is not running"
[ -S "${SOCKET_PATH}" ] || die "missing UDS socket ${SOCKET_PATH}"

[ -n "${EXPECTED_PORT_ID}" ] || die "EXPECTED_PORT_ID is required"
[ -n "${EXPECTED_IFNAME}" ] || die "EXPECTED_IFNAME is required"
[ -n "${VM_IP}" ] || die "VM_IP is required"
if [ -z "${SERVER_ID}" ]; then
    SERVER_ID="$(port_field "${EXPECTED_PORT_ID}" device_id)"
fi
[ -n "${SERVER_ID}" ] || die "SERVER_ID is required or port device_id must be set"

load_openstack_env
prepare_full_resync_config

if [ -z "${WAL_REPLAY_FAILURE_BASELINE}" ]; then
    WAL_REPLAY_FAILURE_BASELINE="$(current_wal_replay_failures)"
fi
echo "wal_replay_failure_baseline=${WAL_REPLAY_FAILURE_BASELINE} max_delta=${WAL_REPLAY_FAILURE_MAX_DELTA}"

case "${PHASE}" in
    source)
        [ -n "${DEST_HOST}" ] || die "DEST_HOST is required for source phase"
        current_host="$(port_field "${EXPECTED_PORT_ID}" binding:host_id)"
        [ "${current_host}" = "${HOST_FQDN}" ] || \
            die "source phase must run on current binding host ${current_host}, not ${HOST_FQDN}"

        echo "Cleaning existing managed ports before migration source smoke"
        rollback_managed_ports

        echo "Applying baseline full-resync on source ${HOST_FQDN}"
        run_agent_once
        ROLLBACK_ARMED=true
        wait_tap
        assert_target_managed "$(ifindex_of)"
        assert_xdp_attached
        wait_ping

        if [ "${ALLOW_VM_MIGRATE}" != "true" ]; then
            die "set ALLOW_VM_MIGRATE=true to migrate ${SERVER_ID} to ${DEST_HOST}"
        fi
        run_live_migration
        wait_server_host "${DEST_HOST}"
        wait_port_host "${DEST_HOST}"
        wait_tap_absent

        echo "Running source cleanup full-resync after migration away"
        run_agent_once
        assert_target_not_managed
        wait_ping
        ROLLBACK_ARMED=false
        ;;
    destination)
        current_host="$(port_field "${EXPECTED_PORT_ID}" binding:host_id)"
        [ "${current_host}" = "${HOST_FQDN}" ] || \
            die "destination phase must run on current binding host ${current_host}, not ${HOST_FQDN}"

        echo "Cleaning existing managed ports before migration destination smoke"
        rollback_managed_ports

        echo "Applying full-resync on destination ${HOST_FQDN}"
        run_agent_once
        ROLLBACK_ARMED=true
        wait_tap
        assert_target_managed "$(ifindex_of)"
        assert_xdp_attached
        wait_ping
        ;;
    *)
        die "PHASE must be source or destination"
        ;;
esac

if [ "${ROLLBACK}" = "true" ]; then
    echo "Rolling back migration smoke managed ports"
    rollback_managed_ports
    ROLLBACK_ARMED=false
fi

echo "neutron-aria-agent VM migration ${PHASE} smoke passed for ${EXPECTED_PORT_ID} on ${HOST_FQDN}"
