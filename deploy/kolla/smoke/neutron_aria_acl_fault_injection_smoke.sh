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
WAL_REPLAY_FAILURE_MAX_DELTA="${WAL_REPLAY_FAILURE_MAX_DELTA:-0}"
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
        echo "Cleaning up ACL fault-injection smoke managed ports"
        rollback_managed_ports || true
    fi
    if [ "${RESTORE_DATAPATH_ON_EXIT:-true}" = "true" ]; then
        start_datapath_without_fault >/dev/null || true
    fi
}

trap cleanup EXIT

wait_for_uds() {
    for _ in $(seq 1 "${WAIT_SECONDS}"); do
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

wal_replay_failures_from_status() {
    local status="$1"
    STATUS_PAYLOAD="${status}" "${PYTHON_BIN}" - <<'PY'
from __future__ import print_function

import json
import os

payload = json.loads(os.environ["STATUS_PAYLOAD"])
print(int(payload.get("wal_replay_failures") or 0))
PY
}

assert_no_new_wal_replay_failures() {
    local point="$1"
    local status="$2"
    local baseline="$3"
    STATUS_PAYLOAD="${status}" \
        FAULT_POINT_NAME="${point}" \
        WAL_REPLAY_FAILURE_BASELINE="${baseline}" \
        WAL_REPLAY_FAILURE_MAX_DELTA="${WAL_REPLAY_FAILURE_MAX_DELTA}" \
        "${PYTHON_BIN}" - <<'PY'
from __future__ import print_function

import json
import os

payload = json.loads(os.environ["STATUS_PAYLOAD"])
point = os.environ["FAULT_POINT_NAME"]
baseline = int(os.environ["WAL_REPLAY_FAILURE_BASELINE"])
max_delta = int(os.environ["WAL_REPLAY_FAILURE_MAX_DELTA"])
current = int(payload.get("wal_replay_failures") or 0)
if current > baseline + max_delta:
    raise SystemExit(
        "fault %s added WAL replay failures: baseline=%d current=%d max_delta=%d payload=%s"
        % (point, baseline, current, max_delta, payload)
    )
print("wal_replay_failures_ok point=%s baseline=%d current=%d" % (
    point,
    baseline,
    current,
))
PY
}

assert_fault_status() {
    local point="$1"
    local status="$2"
    local wal_replay_baseline="$3"
    STATUS_PAYLOAD="${status}" \
        FAULT_POINT_NAME="${point}" \
        EXPECTED_PORT_ID="${EXPECTED_PORT_ID}" \
        "${PYTHON_BIN}" - <<'PY'
from __future__ import print_function

import json
import os

payload = json.loads(os.environ["STATUS_PAYLOAD"])
point = os.environ["FAULT_POINT_NAME"]
expected_port_id = os.environ["EXPECTED_PORT_ID"]
managed = payload.get("managed_ports") or []
if payload.get("pending_generation") is None:
    raise SystemExit("fault %s did not leave pending_generation: %s" % (point, payload))
wal_status = payload.get("wal_status")
authority_state = payload.get("authority_state")
if (wal_status, authority_state) == ("intent_without_commit", "wal_intent_without_commit"):
    pass
elif authority_state == "partial" and wal_status in ("commit_written", "intent_without_commit"):
    pass
else:
    raise SystemExit("fault %s expected WAL intent or partial state: %s" % (point, payload))

for port in managed:
    if port.get("port_id") == expected_port_id:
        raise SystemExit("fault %s left target port managed: %s" % (point, payload))

target_status = None
for port_status in payload.get("port_statuses") or []:
    for domain in port_status.get("domains") or []:
        if domain.get("effective_action") == "enforce":
            raise SystemExit("fault %s left an enforced ACL domain: %s" % (point, payload))
    if port_status.get("port_id") == expected_port_id:
        target_status = port_status

if target_status is None:
    if (wal_status, authority_state) != ("intent_without_commit", "wal_intent_without_commit"):
        raise SystemExit("fault %s did not report target port status: %s" % (point, payload))
else:
    if target_status.get("status") not in ("error", "degraded"):
        raise SystemExit("fault %s target status was not error/degraded: %s" % (point, payload))
    reason = target_status.get("reason") or ""
    if "acl_apply_failed" not in reason and "fault injection" not in reason:
        raise SystemExit("fault %s target reason did not describe ACL apply failure: %s" % (
            point,
            payload,
        ))

print("fault_status_ok point=%s pending_generation=%s managed_ports=%d target_status=%s" % (
    point,
    payload.get("pending_generation"),
    len(managed),
    None if target_status is None else target_status.get("status"),
))
PY
    assert_no_new_wal_replay_failures "${point}" "${status}" "${wal_replay_baseline}"
}

assert_final_status() {
    local status="$1"
    local wal_replay_baseline="$2"
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
print("final_status_ok generation=%s wal_status=%s" % (
    payload.get("generation"),
    payload.get("wal_status"),
))
PY
    assert_no_new_wal_replay_failures "final" "${status}" "${wal_replay_baseline}"
}

start_datapath_with_fault() {
    local point="$1"
    local marker="$2"
    local smoke_script="${REPO_ROOT}/deploy/kolla/smoke/aria_datapath_container_smoke.sh"

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
        bash "${smoke_script}"
}

start_datapath_without_fault() {
    local smoke_script="${REPO_ROOT}/deploy/kolla/smoke/aria_datapath_container_smoke.sh"
    IMAGE="${DATAPATH_IMAGE}" \
        BUILD_IMAGE=false \
        SERVICE_NAME="${DATAPATH_SERVICE_NAME}" \
        REPO_ROOT="${REPO_ROOT}" \
        ARTIFACT_DIR="${ARTIFACT_DIR}" \
        REQUIRE_NO_ACTIVE_INSTANCES="${REQUIRE_NO_ACTIVE_INSTANCES}" \
        bash "${smoke_script}"
}

run_acl_smoke() {
    local smoke_script="${REPO_ROOT}/deploy/kolla/smoke/neutron_aria_acl_full_resync_smoke.sh"
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
        ALLOW_EXISTING_MANAGED_PORTS="${ALLOW_EXISTING_MANAGED_PORTS:-false}" \
        bash "${smoke_script}"
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
    wait_for_uds
    point_baseline_status="$(status_json)"
    point_wal_replay_baseline="$(wal_replay_failures_from_status "${point_baseline_status}")"
    echo "fault_point_baseline_status=${point_baseline_status}"
    echo "fault_point_wal_replay_failures_baseline=${point_wal_replay_baseline} max_delta=${WAL_REPLAY_FAILURE_MAX_DELTA}"

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
    assert_fault_status "${point}" "${fault_status}" "${point_wal_replay_baseline}"

    echo "Checking VM reachability after interrupted apply"
    ping -c "${PING_COUNT}" -W "${PING_TIMEOUT}" "${VM_IP}" >/dev/null

    echo "Running second ACL full-resync; recovery and rollback must succeed"
    ALLOW_EXISTING_MANAGED_PORTS=true run_acl_smoke

    final_status="$(status_json)"
    echo "post_recovery_status=${final_status}"
    assert_final_status "${final_status}" "${point_wal_replay_baseline}"
done

echo
echo "Restoring datapath without fault injection"
start_datapath_without_fault
RESTORE_DATAPATH_ON_EXIT=false

final_status="$(status_json)"
echo "final_status=${final_status}"
final_wal_replay_baseline="$(wal_replay_failures_from_status "${final_status}")"
assert_final_status "${final_status}" "${final_wal_replay_baseline}"

ROLLBACK_ARMED=false
echo "neutron-aria-agent ACL fault-injection smoke passed"
