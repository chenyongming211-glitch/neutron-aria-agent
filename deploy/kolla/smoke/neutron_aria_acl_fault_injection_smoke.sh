#!/usr/bin/env bash
set -euo pipefail

SERVICE_NAME="${SERVICE_NAME:-neutron_aria_agent}"
DATAPATH_SERVICE_NAME="${DATAPATH_SERVICE_NAME:-aria_datapath}"
DATAPATH_IMAGE="${DATAPATH_IMAGE:-aria-datapath:smoke}"
BUILD_DATAPATH_IMAGE="${BUILD_DATAPATH_IMAGE:-false}"
REPO_ROOT="${REPO_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)}"
ARTIFACT_DIR="${ARTIFACT_DIR:-${REPO_ROOT}/release}"
SOCKET_PATH="${SOCKET_PATH:-/run/aria/aria-agent.sock}"
FAULT_ONCE_DIR="${FAULT_ONCE_DIR:-/run/aria}"
FAULT_ACTION="${FAULT_ACTION:-sigkill}"
FAULT_AFTER_HITS="${FAULT_AFTER_HITS:-1}"
FAULT_POINTS="${FAULT_POINTS:-neutron.acl.after_purge neutron.acl.after_group_write neutron.acl.after_policy_write neutron.acl.before_enable}"
WAIT_SECONDS="${WAIT_SECONDS:-45}"
REQUEST_TIMEOUT_OVERRIDE="${REQUEST_TIMEOUT_OVERRIDE:-20.0}"
REQUIRE_NO_ACTIVE_INSTANCES="${REQUIRE_NO_ACTIVE_INSTANCES:-false}"
EXEC_USER="${EXEC_USER:-neutron}"
VM_IP="${VM_IP:-}"
EXPECTED_PORT_ID="${EXPECTED_PORT_ID:-}"
EXPECTED_IFNAME="${EXPECTED_IFNAME:-}"
BLOCK_SRC_CIDR="${BLOCK_SRC_CIDR:-}"
ACL_DIRECTION="${ACL_DIRECTION:-ingress}"
ACL_PROTOCOL="${ACL_PROTOCOL:-icmp}"
PING_COUNT="${PING_COUNT:-2}"
PING_TIMEOUT="${PING_TIMEOUT:-1}"
PYTHON_BIN="${PYTHON_BIN:-}"

die() {
    echo "ERROR: $*" >&2
    exit 1
}

need_command() {
    command -v "$1" >/dev/null 2>&1 || die "missing command: $1"
}

sanitize_point() {
    printf '%s' "$1" | tr -c 'A-Za-z0-9_.-' '_'
}

docker_agent_exec() {
    docker exec -i -u "${EXEC_USER}" "${SERVICE_NAME}" "$@"
}

rollback_managed_ports() {
    docker_agent_exec python - "${SOCKET_PATH}" <<'PY'
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
    if [ "${ROLLBACK_ARMED:-false}" = "true" ]; then
        echo "Cleaning up ACL fault-injection smoke managed ports"
        rollback_managed_ports || true
    fi
    if [ "${RESTORE_DATAPATH_ON_EXIT:-true}" = "true" ]; then
        start_datapath_without_fault >/dev/null || true
    fi
}

trap cleanup EXIT

wait_for_uds() {
    local attempt
    for attempt in $(seq 1 "${WAIT_SECONDS}"); do
        if curl --silent --show-error --fail \
            --unix-socket "${SOCKET_PATH}" \
            "http://localhost/api/v1/neutron/status" >/dev/null 2>&1; then
            return 0
        fi
        sleep 1
    done
    docker ps --filter "name=${DATAPATH_SERVICE_NAME}" \
        --format 'table {{.Names}}\t{{.Image}}\t{{.Status}}' >&2 || true
    docker logs --tail 120 "${DATAPATH_SERVICE_NAME}" >&2 || true
    die "timed out waiting for ${SOCKET_PATH}"
}

status_json() {
    curl --silent --show-error --fail \
        --unix-socket "${SOCKET_PATH}" \
        "http://localhost/api/v1/neutron/status"
}

assert_fault_status() {
    local point="$1"
    local status="$2"
    STATUS_PAYLOAD="${status}" FAULT_POINT_NAME="${point}" "${PYTHON_BIN}" - <<'PY'
from __future__ import print_function

import json
import os

payload = json.loads(os.environ["STATUS_PAYLOAD"])
point = os.environ["FAULT_POINT_NAME"]
managed = payload.get("managed_ports") or []
if managed:
    raise SystemExit("fault %s left managed ports: %s" % (point, managed))
if payload.get("pending_generation") is None:
    raise SystemExit("fault %s did not leave pending_generation: %s" % (point, payload))
if payload.get("wal_status") != "intent_without_commit":
    raise SystemExit("fault %s expected wal_status=intent_without_commit: %s" % (point, payload))
if payload.get("authority_state") != "wal_intent_without_commit":
    raise SystemExit("fault %s expected authority_state=wal_intent_without_commit: %s" % (point, payload))
if int(payload.get("wal_replay_failures") or 0) != 0:
    raise SystemExit("fault %s had WAL replay failures: %s" % (point, payload))
print("fault_status_ok point=%s pending_generation=%s" % (
    point,
    payload.get("pending_generation"),
))
PY
}

assert_final_status() {
    local status="$1"
    STATUS_PAYLOAD="${status}" "${PYTHON_BIN}" - <<'PY'
from __future__ import print_function

import json
import os

payload = json.loads(os.environ["STATUS_PAYLOAD"])
if payload.get("authority_state") != "ready":
    raise SystemExit("authority_state is not ready: %s" % payload)
if payload.get("pending_generation") is not None:
    raise SystemExit("pending_generation was not cleared: %s" % payload)
if payload.get("managed_ports") or []:
    raise SystemExit("managed_ports were not rolled back: %s" % payload)
if int(payload.get("wal_replay_failures") or 0) != 0:
    raise SystemExit("wal_replay_failures is non-zero: %s" % payload)
print("final_status_ok generation=%s wal_status=%s" % (
    payload.get("generation"),
    payload.get("wal_status"),
))
PY
}

start_datapath_with_fault() {
    local point="$1"
    local marker="$2"

    IMAGE="${DATAPATH_IMAGE}" \
        BUILD_IMAGE="${BUILD_DATAPATH_IMAGE}" \
        SERVICE_NAME="${DATAPATH_SERVICE_NAME}" \
        REPO_ROOT="${REPO_ROOT}" \
        ARTIFACT_DIR="${ARTIFACT_DIR}" \
        REQUIRE_NO_ACTIVE_INSTANCES="${REQUIRE_NO_ACTIVE_INSTANCES}" \
        FAULT_INJECTION_ENABLED=1 \
        FAULT_POINT="${point}" \
        FAULT_ACTION="${FAULT_ACTION}" \
        FAULT_AFTER_HITS="${FAULT_AFTER_HITS}" \
        FAULT_ONCE_FILE="${marker}" \
        bash "${REPO_ROOT}/deploy/kolla/smoke/aria_datapath_container_smoke.sh"
}

start_datapath_without_fault() {
    IMAGE="${DATAPATH_IMAGE}" \
        BUILD_IMAGE=false \
        SERVICE_NAME="${DATAPATH_SERVICE_NAME}" \
        REPO_ROOT="${REPO_ROOT}" \
        ARTIFACT_DIR="${ARTIFACT_DIR}" \
        REQUIRE_NO_ACTIVE_INSTANCES="${REQUIRE_NO_ACTIVE_INSTANCES}" \
        bash "${REPO_ROOT}/deploy/kolla/smoke/aria_datapath_container_smoke.sh"
}

run_acl_smoke() {
    REPO_ROOT="${REPO_ROOT}" \
        VM_IP="${VM_IP}" \
        EXPECTED_PORT_ID="${EXPECTED_PORT_ID}" \
        EXPECTED_IFNAME="${EXPECTED_IFNAME}" \
        BLOCK_SRC_CIDR="${BLOCK_SRC_CIDR}" \
        ACL_DIRECTION="${ACL_DIRECTION}" \
        ACL_PROTOCOL="${ACL_PROTOCOL}" \
        PING_COUNT="${PING_COUNT}" \
        PING_TIMEOUT="${PING_TIMEOUT}" \
        REQUEST_TIMEOUT_OVERRIDE="${REQUEST_TIMEOUT_OVERRIDE}" \
        bash "${REPO_ROOT}/deploy/kolla/smoke/neutron_aria_acl_full_resync_smoke.sh"
}

need_command docker
need_command curl
need_command ping
if [ -z "${PYTHON_BIN}" ]; then
    PYTHON_BIN="$(command -v python3 || command -v python || true)"
fi
[ -n "${PYTHON_BIN}" ] || die "missing command: python3 or python"

docker ps --format '{{.Names}}' | grep -qx "${SERVICE_NAME}" || \
    die "${SERVICE_NAME} is not running"

[ -n "${VM_IP}" ] || die "VM_IP is required"
[ -n "${EXPECTED_PORT_ID}" ] || die "EXPECTED_PORT_ID is required"
[ -n "${EXPECTED_IFNAME}" ] || die "EXPECTED_IFNAME is required"

mkdir -p "${FAULT_ONCE_DIR}"

echo "Cleaning existing managed ports before ACL fault-injection smoke"
rollback_managed_ports
ROLLBACK_ARMED=true

for point in ${FAULT_POINTS}; do
    marker="${FAULT_ONCE_DIR}/aria-fault-$(sanitize_point "${point}").once"
    echo
    echo "=== ACL fault point: ${point} ==="
    rm -f "${marker}"

    echo "Starting datapath with one-shot fault marker ${marker}"
    start_datapath_with_fault "${point}" "${marker}"

    echo "Triggering first ACL full-resync; failure is expected"
    set +e
    run_acl_smoke
    first_rc=$?
    set -e
    if [ "${first_rc}" -eq 0 ]; then
        die "fault point ${point} did not interrupt the first ACL full-resync"
    fi
    echo "first_acl_run_rc=${first_rc}"

    wait_for_uds
    [ -f "${marker}" ] || die "fault marker was not created: ${marker}"
    echo "fault_marker=$(cat "${marker}")"

    fault_status="$(status_json)"
    echo "fault_status=${fault_status}"
    assert_fault_status "${point}" "${fault_status}"

    echo "Checking VM reachability after interrupted apply"
    ping -c "${PING_COUNT}" -W "${PING_TIMEOUT}" "${VM_IP}" >/dev/null

    echo "Running second ACL full-resync; recovery and rollback must succeed"
    run_acl_smoke

    final_status="$(status_json)"
    echo "post_recovery_status=${final_status}"
    assert_final_status "${final_status}"
done

echo
echo "Restoring datapath without fault injection"
start_datapath_without_fault
RESTORE_DATAPATH_ON_EXIT=false

final_status="$(status_json)"
echo "final_status=${final_status}"
assert_final_status "${final_status}"

ROLLBACK_ARMED=false
echo "neutron-aria-agent ACL fault-injection smoke passed"
