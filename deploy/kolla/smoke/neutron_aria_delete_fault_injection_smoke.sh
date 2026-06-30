#!/usr/bin/env bash
set -euo pipefail

SERVICE_NAME="${SERVICE_NAME:-neutron_aria_agent}"
DATAPATH_SERVICE_NAME="${DATAPATH_SERVICE_NAME:-aria_datapath}"
DATAPATH_IMAGE="${DATAPATH_IMAGE:-aria-datapath:smoke}"
BUILD_DATAPATH_IMAGE="${BUILD_DATAPATH_IMAGE:-false}"
REPO_ROOT="${REPO_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)}"
ARTIFACT_DIR="${ARTIFACT_DIR:-${REPO_ROOT}/release}"
SOCKET_PATH="${SOCKET_PATH:-/run/aria/aria-agent.sock}"
DATAPATH_HTTP="${DATAPATH_HTTP:-http://127.0.0.1:8080}"
FAULT_ONCE_DIR="${FAULT_ONCE_DIR:-/run/aria}"
FAULT_ACTION="${FAULT_ACTION:-sigkill}"
FAULT_AFTER_HITS="${FAULT_AFTER_HITS:-1}"
DELETE_FAULT_POINTS="${DELETE_FAULT_POINTS:-neutron.delete.after_detach_before_commit}"
WAIT_SECONDS="${WAIT_SECONDS:-45}"
REQUEST_TIMEOUT_OVERRIDE="${REQUEST_TIMEOUT_OVERRIDE:-3.0}"
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

route_source_cidr() {
    local route_line source_ip
    route_line="$(ip route get "${VM_IP}" 2>/dev/null | head -1 || true)"
    source_ip="$(printf '%s\n' "${route_line}" | awk '{
        for (i = 1; i <= NF; i++) {
            if ($i == "src") {
                print $(i + 1)
                exit
            }
        }
    }')"
    [ -n "${source_ip}" ] || return 1
    printf '%s/32\n' "${source_ip}"
}

build_acl_fixture() {
    local port_id="$1"
    local source_cidr="$2"
    local direction="$3"
    local protocol="$4"
    "${PYTHON_BIN}" - "${port_id}" "${source_cidr}" "${direction}" "${protocol}" <<'PY'
from __future__ import print_function

import json
import sys

port_id, source_cidr, direction, protocol = sys.argv[1:5]
print(json.dumps({
    "policies": [{
        "id": "delete-fault-policy",
        "name": "delete-fault-policy",
        "default_action": "allow",
        "stateful": True,
        "revision_number": 1,
    }],
    "rules": [{
        "id": "delete-fault-drop-%s" % protocol,
        "policy_id": "delete-fault-policy",
        "direction": direction,
        "priority": 100,
        "action": "drop",
        "ethertype": "IPv4",
        "protocol": protocol,
        "src_cidr": source_cidr,
        "enabled": True,
        "revision_number": 1,
    }],
    "address_sets": [],
    "bindings": [{
        "id": "delete-fault-binding",
        "policy_id": "delete-fault-policy",
        "target_type": "port",
        "target_id": port_id,
        "enabled": True,
        "revision_number": 1,
    }],
}, sort_keys=True))
PY
}

rollback_managed_ports() {
    docker_agent_exec python - "${SOCKET_PATH}" <<'PY'
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
    if [ "${ROLLBACK_ARMED:-false}" = "true" ]; then
        echo "Cleaning up delete fault-injection smoke managed ports"
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

assert_target_managed() {
    local status="$1"
    STATUS_PAYLOAD="${status}" EXPECTED_PORT_ID="${EXPECTED_PORT_ID}" \
        EXPECTED_IFNAME="${EXPECTED_IFNAME}" "${PYTHON_BIN}" - <<'PY'
from __future__ import print_function

import json
import os

payload = json.loads(os.environ["STATUS_PAYLOAD"])
expected_port_id = os.environ["EXPECTED_PORT_ID"]
expected_ifname = os.environ["EXPECTED_IFNAME"]
managed = payload.get("managed_ports") or []
for port in managed:
    if port.get("port_id") == expected_port_id and port.get("ifname") == expected_ifname:
        print("target_managed_ok port_id=%s ifname=%s" % (expected_port_id, expected_ifname))
        break
else:
    raise SystemExit("expected managed port not found: %s/%s in %s" % (
        expected_port_id,
        expected_ifname,
        managed,
    ))
if payload.get("authority_state") != "ready":
    raise SystemExit("authority_state is not ready before delete fault: %s" % payload)
if int(payload.get("wal_replay_failures") or 0) != 0:
    raise SystemExit("wal_replay_failures is non-zero before delete fault: %s" % payload)
PY
}

assert_fault_status() {
    local point="$1"
    local status="$2"
    STATUS_PAYLOAD="${status}" FAULT_POINT_NAME="${point}" \
        EXPECTED_PORT_ID="${EXPECTED_PORT_ID}" "${PYTHON_BIN}" - <<'PY'
from __future__ import print_function

import json
import os

payload = json.loads(os.environ["STATUS_PAYLOAD"])
point = os.environ["FAULT_POINT_NAME"]
expected_port_id = os.environ["EXPECTED_PORT_ID"]
wal_status = payload.get("wal_status")
authority_state = payload.get("authority_state")
if int(payload.get("wal_replay_failures") or 0) != 0:
    raise SystemExit("fault %s had WAL replay failures: %s" % (point, payload))
if (wal_status, authority_state) == ("intent_without_commit", "wal_intent_without_commit"):
    print("delete_fault_status_ok point=%s wal_status=%s pending_generation=%s managed_ports=%d" % (
        point,
        wal_status,
        payload.get("pending_generation"),
        len(payload.get("managed_ports") or []),
    ))
elif (wal_status, authority_state) == ("intent_recovered", "recovered_pending_full_resync"):
    managed = payload.get("managed_ports") or []
    if any(port.get("port_id") == expected_port_id for port in managed):
        raise SystemExit("fault %s recovered but target port is still managed: %s" % (point, payload))
    recovered_statuses = [
        port for port in (payload.get("port_statuses") or [])
        if port.get("port_id") == expected_port_id and port.get("status") == "recovered"
    ]
    if not recovered_statuses:
        raise SystemExit("fault %s recovered without target recovered status: %s" % (point, payload))
    print("delete_fault_recovered_ok point=%s pending_generation=%s managed_ports=%d" % (
        point,
        payload.get("pending_generation"),
        len(managed),
    ))
else:
    raise SystemExit("fault %s expected WAL intent or recovery state: %s" % (point, payload))
PY
}

assert_target_not_managed() {
    local status="$1"
    STATUS_PAYLOAD="${status}" EXPECTED_PORT_ID="${EXPECTED_PORT_ID}" "${PYTHON_BIN}" - <<'PY'
from __future__ import print_function

import json
import os

payload = json.loads(os.environ["STATUS_PAYLOAD"])
expected_port_id = os.environ["EXPECTED_PORT_ID"]
managed = payload.get("managed_ports") or []
if any(port.get("port_id") == expected_port_id for port in managed):
    raise SystemExit("target port is still managed after retry delete: %s" % payload)
if payload.get("authority_state") not in ("ready", "recovered_pending_full_resync"):
    raise SystemExit("unexpected authority_state after retry delete: %s" % payload)
if payload.get("wal_status") not in ("commit_written", "intent_recovered", "runtime_reconciled"):
    raise SystemExit("unexpected wal_status after retry delete: %s" % payload)
if int(payload.get("wal_replay_failures") or 0) != 0:
    raise SystemExit("wal_replay_failures is non-zero after retry delete: %s" % payload)
print("target_not_managed_ok port_id=%s remaining_managed=%d" % (
    expected_port_id,
    len(managed),
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

delete_target_port() {
    docker_agent_exec python - "${SOCKET_PATH}" "${EXPECTED_PORT_ID}" <<'PY'
from __future__ import print_function

import json
import sys

from neutron_aria.agent.uds_client import LocalClient

socket_path, port_id = sys.argv[1:3]
try:
    response = LocalClient(socket_path, timeout=3.0).delete_port(port_id)
except Exception as exc:
    print("delete_error=%s: %s" % (exc.__class__.__name__, exc), file=sys.stderr)
    raise SystemExit(1)
print("delete_response=%s" % json.dumps(response, sort_keys=True))
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

apply_acl_snapshot_without_rollback() {
    local acl_fixture_json="$1"

    ACL_FIXTURE_JSON="${acl_fixture_json}" \
        ROLLBACK=false \
        MIN_MANAGED_PORTS=1 \
        EXPECTED_PORT_ID="${EXPECTED_PORT_ID}" \
        EXPECTED_IFNAME="${EXPECTED_IFNAME}" \
        REQUEST_TIMEOUT_OVERRIDE="${REQUEST_TIMEOUT_OVERRIDE}" \
        REPO_ROOT="${REPO_ROOT}" \
        bash "${REPO_ROOT}/deploy/kolla/smoke/neutron_aria_full_resync_smoke.sh"
}

need_command docker
need_command curl
need_command ping
need_command ip
if [ -z "${PYTHON_BIN}" ]; then
    PYTHON_BIN="$(command -v python3 || command -v python || true)"
fi
[ -n "${PYTHON_BIN}" ] || die "missing command: python3 or python"

docker ps --format '{{.Names}}' | grep -qx "${SERVICE_NAME}" || \
    die "${SERVICE_NAME} is not running"

[ -n "${VM_IP}" ] || die "VM_IP is required"
[ -n "${EXPECTED_PORT_ID}" ] || die "EXPECTED_PORT_ID is required"
[ -n "${EXPECTED_IFNAME}" ] || die "EXPECTED_IFNAME is required"

if [ -z "${BLOCK_SRC_CIDR}" ]; then
    BLOCK_SRC_CIDR="$(route_source_cidr)" || die "failed to infer source IP for ${VM_IP}; set BLOCK_SRC_CIDR"
fi

mkdir -p "${FAULT_ONCE_DIR}"

echo "Cleaning existing managed ports before delete fault-injection smoke"
rollback_managed_ports
ROLLBACK_ARMED=true

echo "Pre-check: VM ${VM_IP} must be reachable before delete fault smoke"
ping -c "${PING_COUNT}" -W "${PING_TIMEOUT}" "${VM_IP}" >/dev/null

acl_fixture_json="$(build_acl_fixture \
    "${EXPECTED_PORT_ID}" \
    "${BLOCK_SRC_CIDR}" \
    "${ACL_DIRECTION}" \
    "${ACL_PROTOCOL}")"

for point in ${DELETE_FAULT_POINTS}; do
    marker="${FAULT_ONCE_DIR}/aria-fault-$(sanitize_point "${point}").once"
    echo
    echo "=== Delete fault point: ${point} ==="
    rm -f "${marker}"

    echo "Starting datapath with one-shot delete fault marker ${marker}"
    start_datapath_with_fault "${point}" "${marker}"

    echo "Applying ACL snapshot without rollback before delete fault"
    apply_acl_snapshot_without_rollback "${acl_fixture_json}"
    status_before_delete="$(status_json)"
    echo "status_before_delete=${status_before_delete}"
    assert_target_managed "${status_before_delete}"

    echo "Triggering first delete; failure is expected"
    set +e
    delete_target_port
    first_rc=$?
    set -e
    if [ "${first_rc}" -eq 0 ]; then
        die "fault point ${point} did not interrupt the first delete"
    fi
    echo "first_delete_rc=${first_rc}"

    wait_for_uds
    [ -f "${marker}" ] || die "fault marker was not created: ${marker}"
    echo "fault_marker=$(cat "${marker}")"

    fault_status="$(status_json)"
    echo "fault_status=${fault_status}"
    assert_fault_status "${point}" "${fault_status}"

    echo "Checking VM reachability after interrupted delete"
    ping -c "${PING_COUNT}" -W "${PING_TIMEOUT}" "${VM_IP}" >/dev/null

    echo "Retrying delete; one-shot marker should prevent another fault"
    delete_target_port
    post_delete_status="$(status_json)"
    echo "post_delete_status=${post_delete_status}"
    assert_target_not_managed "${post_delete_status}"

    echo "Rolling back remaining managed ports"
    rollback_managed_ports
    echo "Restarting datapath without fault injection to complete recovery"
    start_datapath_without_fault
    final_loop_status="$(status_json)"
    echo "post_loop_status=${final_loop_status}"
    assert_final_status "${final_loop_status}"

    echo "Post-check: VM ${VM_IP} must remain reachable after delete cleanup"
    ping -c "${PING_COUNT}" -W "${PING_TIMEOUT}" "${VM_IP}" >/dev/null
done

echo
echo "Restoring datapath without fault injection"
start_datapath_without_fault
RESTORE_DATAPATH_ON_EXIT=false

final_status="$(status_json)"
echo "final_status=${final_status}"
assert_final_status "${final_status}"

ROLLBACK_ARMED=false
echo "neutron-aria-agent delete fault-injection smoke passed"
