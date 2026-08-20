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
PIN_ROOT="${PIN_ROOT:-/sys/fs/bpf/aria/global-v2}"
NEUTRON_STATE_PATH="${NEUTRON_STATE_PATH:-/var/lib/aria-agent}"
MANAGED_TRANSACTION_SMOKE="${MANAGED_TRANSACTION_SMOKE:-false}"
DIRECT_SNAPSHOT_MODE="${DIRECT_SNAPSHOT_MODE:-false}"
DATAPATH_CONFIG_DIR="${DATAPATH_CONFIG_DIR:-}"
DATAPATH_RUN_ARIA_DIR="${DATAPATH_RUN_ARIA_DIR:-}"
DATAPATH_STATE_DIR="${DATAPATH_STATE_DIR:-}"
DATAPATH_PIN_PATH="${DATAPATH_PIN_PATH:-}"
DATAPATH_LISTEN_ADDR="${DATAPATH_LISTEN_ADDR:-}"
WORK_DIR="${WORK_DIR:-/tmp/neutron-aria-delete-transaction-$(date +%Y%m%d%H%M%S)-$(hostname -s)}"

RESULT="fail"
FAILURE_REASON="smoke did not complete"
TRANSACTION_BODY_SUCCEEDED=false
DETACH_ORDERING_STATUS="not_run"
PURGE_FAILURE_ATOMICITY_STATUS="not_run"
STRICT_FLUSH_ROLLBACK_STATUS="not_run"
RETRY_DETACH_STATUS="not_run"
cleanup_errors=()
renamed_pin_records=()
DEDICATED_GUARD_ESTABLISHED=false
GUARD_REFUSED=false
TARGET_ROLLBACK_ARMED=false
DATAPATH_RESTORE_ARMED=false

die() {
    if [ "${MANAGED_TRANSACTION_SMOKE}" = "true" ]; then
        FAILURE_REASON="$*"
    fi
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
    if [ "${DIRECT_SNAPSHOT_MODE}" = "true" ]; then
        if [ "$1" = "python" ]; then
            shift
            PYTHONPATH="${REPO_ROOT}/openstack/neutron_aria${PYTHONPATH:+:${PYTHONPATH}}" \
                "${PYTHON_BIN:-python3}" "$@"
            return
        fi
        "$@"
        return
    fi
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
    local body_rc=$?
    if [ "${MANAGED_TRANSACTION_SMOKE}" = "true" ]; then
        cleanup_managed_transaction_smoke "${body_rc}"
        return
    fi
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
    local smoke_script="${REPO_ROOT}/deploy/kolla/smoke/aria_datapath_container_smoke.sh"

    IMAGE="${DATAPATH_IMAGE}" \
        BUILD_IMAGE="${BUILD_DATAPATH_IMAGE}" \
        SERVICE_NAME="${DATAPATH_SERVICE_NAME}" \
        REPO_ROOT="${REPO_ROOT}" \
        ARTIFACT_DIR="${ARTIFACT_DIR}" \
        REQUIRE_NO_ACTIVE_INSTANCES="${REQUIRE_NO_ACTIVE_INSTANCES}" \
        CONFIG_DIR="${DATAPATH_CONFIG_DIR:-/etc/kolla/aria-datapath}" \
        RUN_ARIA_DIR="${DATAPATH_RUN_ARIA_DIR:-/run/aria}" \
        SOCKET_PATH="${SOCKET_PATH}" \
        STATE_DIR="${DATAPATH_STATE_DIR:-/var/lib/aria-agent-smoke}" \
        PIN_PATH="${DATAPATH_PIN_PATH}" \
        LISTEN_ADDR="${DATAPATH_LISTEN_ADDR}" \
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
        CONFIG_DIR="${DATAPATH_CONFIG_DIR:-/etc/kolla/aria-datapath}" \
        RUN_ARIA_DIR="${DATAPATH_RUN_ARIA_DIR:-/run/aria}" \
        SOCKET_PATH="${SOCKET_PATH}" \
        STATE_DIR="${DATAPATH_STATE_DIR:-/var/lib/aria-agent-smoke}" \
        PIN_PATH="${DATAPATH_PIN_PATH}" \
        LISTEN_ADDR="${DATAPATH_LISTEN_ADDR}" \
        bash "${smoke_script}"
}

submit_direct_acl_snapshot() {
    local acl_fixture_json="$1" ifindex
    ifindex="$(cat "/sys/class/net/${EXPECTED_IFNAME}/ifindex")"
    docker_agent_exec python - \
        "${SOCKET_PATH}" "${EXPECTED_PORT_ID}" "${EXPECTED_IFNAME}" "${ifindex}" \
        "${acl_fixture_json}" <<'PY'
from __future__ import print_function

import json
import sys
import time

from neutron_aria.agent.uds_client import LocalClient
from neutron_aria.agent.state import desired_snapshot_hash

socket_path, port_id, ifname, ifindex, fixture_json = sys.argv[1:6]
fixture = json.loads(fixture_json)
policy = fixture["policies"][0]
binding = fixture["bindings"][0]
rules = []
for rule in fixture.get("rules") or []:
    rules.append({
        "id": rule.get("id"),
        "direction": rule.get("direction"),
        "priority": int(rule.get("priority") or 0),
        "action": rule.get("action"),
        "ethertype": rule.get("ethertype"),
        "protocol": rule.get("protocol"),
        "src_cidrs": [rule["src_cidr"]] if rule.get("src_cidr") else [],
        "dst_cidrs": [rule["dst_cidr"]] if rule.get("dst_cidr") else [],
        "src_port_min": rule.get("src_port_min"),
        "src_port_max": rule.get("src_port_max"),
        "dst_port_min": rule.get("dst_port_min"),
        "dst_port_max": rule.get("dst_port_max"),
    })

client = LocalClient(socket_path, timeout=3.0)
client.capabilities(required_domains=["acl"])
status = client.status()
generation = max(
    int(status.get("generation") or 0),
    int(status.get("accepted_generation") or 0),
    int(status.get("applied_generation") or 0),
) + 1
snapshot = {
    "schema_version": 1,
    "generation": generation,
    "host": "isolated-transaction-smoke",
    "ports": [{
        "port_id": port_id,
        "ifname": ifname,
        "ifindex": int(ifindex),
        "eligible": True,
        "disposition": "eligible_ovs_tap",
        "device_owner": "compute:nova",
        "vif_type": "ovs",
        "vnic_type": "normal",
        "network_backend": "openvswitch",
        "ovs_iface_id": port_id,
        "managed_domains": ["acl"],
        "acl": {
            "enabled": True,
            "status": "ready",
            "reason": "ready",
            "effective_action": "enforce",
            "policy_id": policy.get("id"),
            "policy_name": policy.get("name"),
            "binding_id": binding.get("id"),
            "source": "port",
            "default_action": policy.get("default_action") or "allow",
            "stateful": bool(policy.get("stateful")),
            "revision": max(
                int(policy.get("revision_number") or 0),
                int(binding.get("revision_number") or 0),
            ),
            "rules": rules,
        },
    }],
}
snapshot["desired_hash"] = desired_snapshot_hash(snapshot)
response = client.put_snapshot(snapshot)
print("direct_snapshot_response=%s" % json.dumps(response, sort_keys=True))
deadline = time.time() + 15.0
while True:
    settled = client.status()
    applied = int(settled.get("applied_generation") or 0)
    pending = settled.get("pending_generation")
    if applied >= generation and pending is None:
        break
    if time.time() >= deadline:
        raise SystemExit(
            "direct snapshot generation %s did not settle: %s" % (
                generation,
                json.dumps(settled, sort_keys=True),
            )
        )
    time.sleep(0.05)
print("direct_snapshot_settled=%s" % json.dumps(settled, sort_keys=True))
PY
}

apply_acl_snapshot_without_rollback() {
    local acl_fixture_json="$1"
    local smoke_script="${REPO_ROOT}/deploy/kolla/smoke/neutron_aria_full_resync_smoke.sh"

    if [ "${DIRECT_SNAPSHOT_MODE}" = "true" ]; then
        submit_direct_acl_snapshot "${acl_fixture_json}"
        return
    fi

    ACL_FIXTURE_JSON="${acl_fixture_json}" \
        ROLLBACK=false \
        MIN_MANAGED_PORTS=1 \
        EXPECTED_PORT_ID="${EXPECTED_PORT_ID}" \
        EXPECTED_IFNAME="${EXPECTED_IFNAME}" \
        REQUEST_TIMEOUT_OVERRIDE="${REQUEST_TIMEOUT_OVERRIDE}" \
        REPO_ROOT="${REPO_ROOT}" \
        bash "${smoke_script}"
}

record_cleanup_error() {
    cleanup_errors+=("$*")
    echo "CLEANUP_ERROR: $*" >&2
}

restore_renamed_pins() {
    local index record source destination expected_id actual_id rc=0 separator=$'\x1f'
    for ((index=${#renamed_pin_records[@]}-1; index>=0; index--)); do
        record="${renamed_pin_records[index]}"
        source="${record%%"${separator}"*}"
        destination="${record#*"${separator}"}"
        if [ "${source}" = "${record}" ] || [ -z "${source}" ] || [ -z "${destination}" ]; then
            echo "invalid pin restoration record" >&2
            rc=1
            continue
        fi
        if [[ "${destination}" == id:* ]]; then
            expected_id="${destination#id:}"
            if [ -e "${source}" ]; then
                actual_id="$(bpftool -j map show pinned "${source}" | "${PYTHON_BIN}" -c \
                    'import json,sys; value=json.load(sys.stdin); value=value[0] if isinstance(value,list) else value; print(value["id"])')" || rc=1
                if [ "${actual_id:-}" != "${expected_id}" ]; then
                    echo "pin restoration identity mismatch: ${source}" >&2
                    rc=1
                fi
            elif ! bpftool map pin id "${expected_id}" "${source}"; then
                echo "failed to restore map id ${expected_id} to ${source}" >&2
                rc=1
            fi
        elif [ -e "${destination}" ]; then
            if [ -e "${source}" ]; then
                echo "pin restoration collision: ${source} and ${destination} both exist" >&2
                rc=1
            elif ! mv -- "${destination}" "${source}"; then
                echo "failed to restore pin ${destination} to ${source}" >&2
                rc=1
            fi
        elif [ ! -e "${source}" ]; then
            echo "pin restoration lost both ${source} and ${destination}" >&2
            rc=1
        fi
    done
    if [ "${rc}" -eq 0 ]; then
        renamed_pin_records=()
    fi
    return "${rc}"
}

hold_pin_for_fault() {
    local map_name="$1" label="$2" source destination map_id separator=$'\x1f'
    source="${PIN_ROOT}/${map_name}"
    destination="${PIN_ROOT}/.${map_name}.acl046-transaction-held"
    [ -e "${source}" ] || die "required pin is missing before fault fixture: ${source}"
    [ ! -e "${destination}" ] || die "pin fault destination already exists: ${destination}"
    guard_dedicated_host "${label}-pre-pin-rename" target
    if mv -- "${source}" "${destination}" 2>/dev/null; then
        renamed_pin_records+=("${source}${separator}${destination}")
        return
    fi
    map_id="$(bpftool -j map show pinned "${source}" | "${PYTHON_BIN}" -c \
        'import json,sys; value=json.load(sys.stdin); value=value[0] if isinstance(value,list) else value; print(value["id"])')" \
        || die "failed to resolve map id for ${source}"
    rm -- "${source}" || die "failed to unpin ${source}"
    renamed_pin_records+=("${source}${separator}id:${map_id}")
}

capture_wal() {
    local output="$1"
    if [ "${DIRECT_SNAPSHOT_MODE}" = "true" ]; then
        docker exec "${DATAPATH_SERVICE_NAME}" cat \
            "${NEUTRON_STATE_PATH}/neutron-snapshot.wal" >"${output}"
        return
    fi
    docker_agent_exec cat "${NEUTRON_STATE_PATH}/neutron-snapshot.wal" >"${output}"
}

capture_instance_state() {
    local output="$1"
    if [ "${DIRECT_SNAPSHOT_MODE}" = "true" ]; then
        docker exec "${DATAPATH_SERVICE_NAME}" cat \
            "${NEUTRON_STATE_PATH}/${EXPECTED_IFNAME}/state.json" >"${output}"
        return
    fi
    docker_agent_exec cat "${NEUTRON_STATE_PATH}/${EXPECTED_IFNAME}/state.json" >"${output}"
}

rollback_transaction_managed_target() {
    docker_agent_exec python - "${SOCKET_PATH}" "${EXPECTED_PORT_ID}" "${EXPECTED_IFNAME}" <<'PY'
from __future__ import print_function

import sys

from neutron_aria.agent.uds_client import LocalClient

socket_path, expected_port_id, expected_ifname = sys.argv[1:4]
client = LocalClient(socket_path, timeout=3.0)
client.capabilities()
status = client.status()
managed = status.get("managed_ports") or []
foreign = [port for port in managed if
           port.get("port_id") != expected_port_id or port.get("ifname") != expected_ifname]
if foreign or len(managed) > 1:
    raise SystemExit("refusing transaction rollback with foreign managed ports: %s" % managed)
if managed:
    response = client.delete_port(expected_port_id)
    print("transaction_rollback status=%s detached=%s" % (
        response.get("status"), response.get("detached")))
after = client.status()
remaining = after.get("managed_ports") or []
if remaining:
    raise SystemExit("transaction rollback left managed ports: %s" % remaining)
PY
}

capture_tc_filter() {
    local direction="$1" output="$2" temporary error_file
    temporary="${output}.tmp"
    error_file="${output}.err"
    if tc -j filter show dev "${EXPECTED_IFNAME}" "${direction}" \
            >"${temporary}" 2>"${error_file}" && \
            "${PYTHON_BIN}" -m json.tool "${temporary}" >/dev/null 2>&1; then
        mv "${temporary}" "${output}"
        return
    fi
    rm -f "${temporary}"
    tc filter show dev "${EXPECTED_IFNAME}" "${direction}" | \
        "${PYTHON_BIN}" -c \
        'import json,sys; print(json.dumps([{"raw": line.rstrip()} for line in sys.stdin if line.rstrip()]))' \
        >"${output}"
}

capture_tc_identity() {
    local directory="$1" ifindex ingress_link egress_link direction net_rc=0
    ifindex="$(cat "/sys/class/net/${EXPECTED_IFNAME}/ifindex")" || return 1
    ip -details link show dev "${EXPECTED_IFNAME}" >"${directory}/link.txt" || return 1
    capture_tc_filter ingress "${directory}/tc-ingress.json" || return 1
    capture_tc_filter egress "${directory}/tc-egress.json" || return 1
    bpftool -j net show >"${directory}/bpftool-net.json" \
        2>"${directory}/bpftool-net.err" || net_rc=$?
    printf '{"available":%s,"exit_code":%s}\n' \
        "$([ "${net_rc}" -eq 0 ] && printf true || printf false)" "${net_rc}" \
        >"${directory}/bpftool-net-status.json"
    ingress_link="${PIN_ROOT}/${EXPECTED_IFNAME}_tc_ingress_link"
    egress_link="${PIN_ROOT}/${EXPECTED_IFNAME}_tc_egress_link"
    if [ -e "${ingress_link}" ] && [ -e "${egress_link}" ]; then
        bpftool -j link show pinned "${ingress_link}" \
            >"${directory}/pinned-ingress-link.json" || return 1
        bpftool -j link show pinned "${egress_link}" \
            >"${directory}/pinned-egress-link.json" || return 1
    elif [ ! -e "${ingress_link}" ] && [ ! -e "${egress_link}" ]; then
        for direction in ingress egress; do
            bpftool -j prog show pinned "${PIN_ROOT}/tc_${direction}" \
                >"${directory}/pinned-${direction}-prog.json" || return 1
            "${PYTHON_BIN}" - \
                "${directory}/pinned-${direction}-prog.json" \
                "${directory}/tc-${direction}.json" \
                "${ifindex}" "${direction}" \
                >"${directory}/pinned-${direction}-link.json" <<'PY' || return 1
from __future__ import print_function

import json
import sys

program_path, filters_path, ifindex, direction = sys.argv[1:]
program = json.load(open(program_path, encoding="utf-8"))
if isinstance(program, list):
    assert len(program) == 1, program
    program = program[0]
assert isinstance(program, dict), program
program_id = int(program.get("id") or 0)
program_tag = str(program.get("tag") or "").lower()
program_name = "tc_%s" % direction
assert program_id > 0 and program_tag, program
filters = json.load(open(filters_path, encoding="utf-8"))
rendered = json.dumps(filters, sort_keys=True).lower()
assert program_name in rendered, (program_name, filters)
assert program_tag in rendered or str(program_id) in rendered, (
    program_name,
    program_id,
    program_tag,
    filters,
)
print(json.dumps({
    "ifindex": int(ifindex),
    "prog_id": program_id,
    "attach_type": "legacy_tc_%s" % direction,
    "legacy_tc": True,
    "tag": program_tag,
}, sort_keys=True))
PY
        done
    else
        echo "mixed TC attachment state for ${EXPECTED_IFNAME}" >&2
        return 1
    fi
    "${PYTHON_BIN}" - "${directory}" "${ifindex}" <<'PY'
from __future__ import print_function

import json
import os
import sys

root, expected_ifindex = sys.argv[1], int(sys.argv[2])

def one(name):
    payload = json.load(open(os.path.join(root, name), encoding="utf-8"))
    if isinstance(payload, list):
        if len(payload) != 1:
            raise AssertionError((name, payload))
        payload = payload[0]
    if not isinstance(payload, dict):
        raise AssertionError((name, payload))
    return payload

evidence = {}
for direction in ("ingress", "egress"):
    link = one("pinned-%s-link.json" % direction)
    if int(link.get("ifindex") or 0) != expected_ifindex:
        raise AssertionError((direction, expected_ifindex, link))
    if int(link.get("prog_id") or 0) <= 0:
        raise AssertionError((direction, "missing prog_id", link))
    rendered = json.dumps(link, sort_keys=True).lower()
    if direction not in rendered:
        raise AssertionError((direction, "wrong attach type", link))
    attach_mode="legacy" if bool(link.get("legacy_tc")) else "tcx"
    evidence[direction] = {
        "ifindex": int(link["ifindex"]),
        "prog_id": int(link["prog_id"]),
        "attach_mode": attach_mode,
        "attach_type": link.get("attach_type"),
        "legacy_tc": bool(link.get("legacy_tc")),
    }
print(json.dumps(evidence, sort_keys=True))
PY
}

capture_transaction_state() {
    local label="$1" directory ifindex key_hex tap_id config_hex map_name
    directory="${WORK_DIR}/${label}"
    mkdir -p "${directory}" || return 1
    status_json >"${directory}/status.json" || return 1
    curl --silent --show-error --fail "${DATAPATH_HTTP}/api/v1/instances" \
        >"${directory}/instances.json" || return 1
    curl --silent --show-error --fail "${DATAPATH_HTTP}/api/v1/${EXPECTED_IFNAME}/config" \
        >"${directory}/config.json" || return 1
    curl --silent --show-error --fail "${DATAPATH_HTTP}/api/v1/${EXPECTED_IFNAME}/groups" \
        >"${directory}/groups.json" || return 1
    curl --silent --show-error --fail "${DATAPATH_HTTP}/api/v1/${EXPECTED_IFNAME}/policies" \
        >"${directory}/policies.json" || return 1
    capture_tc_identity "${directory}" >"${directory}/link-identity-assertion.json" || return 1
    for map_name in POLICY_TABLE SRC_IPV4_TRIE DST_IPV4_TRIE SRC_IPV6_TRIE DST_IPV6_TRIE \
            ACL_SRC_IPV4_TRIE ACL_DST_IPV4_TRIE ACL_SRC_IPV6_TRIE ACL_DST_IPV6_TRIE; do
        bpftool -j map dump pinned "${PIN_ROOT}/${map_name}" \
            >"${directory}/${map_name}.json" || return 1
    done
    ifindex="$(cat "/sys/class/net/${EXPECTED_IFNAME}/ifindex")" || return 1
    key_hex="$("${PYTHON_BIN}" - "${ifindex}" <<'PY'
from __future__ import print_function
import struct,sys
print(" ".join("%02x" % b for b in struct.pack("=I", int(sys.argv[1]))))
PY
    )" || return 1
    # Hex bytes must be separate bpftool argv entries.
    # shellcheck disable=SC2086
    bpftool -j map lookup pinned "${PIN_ROOT}/IFACE_CTX_MAP" key hex ${key_hex} \
        >"${directory}/iface-ctx.json" || return 1
    tap_id="$("${PYTHON_BIN}" - "${directory}/iface-ctx.json" <<'PY'
from __future__ import print_function
import json,struct,sys

def decode_bpftool_bytes(values):
    return bytes(bytearray(
        int(value, 16) if isinstance(value, (str, type(u""))) else value
        for value in values
    ))

value=json.load(open(sys.argv[1],encoding="utf-8"))["value"]
print(struct.unpack("=I",decode_bpftool_bytes(value[:4]))[0])
PY
    )" || return 1
    config_hex="$("${PYTHON_BIN}" - "${tap_id}" <<'PY'
from __future__ import print_function
import struct,sys
print(" ".join("%02x" % b for b in struct.pack("=I", int(sys.argv[1]))))
PY
    )" || return 1
    # Hex bytes must be separate bpftool argv entries.
    # shellcheck disable=SC2086
    bpftool -j map lookup pinned "${PIN_ROOT}/TAP_CONFIG_MAP" key hex ${config_hex} \
        >"${directory}/tap-config.json" || return 1
    "${PYTHON_BIN}" - "${directory}/tap-config.json" "${tap_id}" >"${directory}/bank.json" <<'PY' || return 1
from __future__ import print_function
import json,sys

def decode_bpftool_int(value):
    if isinstance(value, (str, type(u""))):
        return int(value, 0)
    return int(value)

value=json.load(open(sys.argv[1],encoding="utf-8"))["value"]
print(json.dumps({
    "tap_id": int(sys.argv[2]),
    "tap_config": value,
    "active_bank": decode_bpftool_int(value[6]),
}, sort_keys=True))
PY
    capture_wal "${directory}/neutron-snapshot.wal" || return 1
    capture_instance_state "${directory}/state.json" || return 1
}

write_delete_request() {
    local directory="$1"
    EXPECTED_PORT_ID="${EXPECTED_PORT_ID}" EXPECTED_IFNAME="${EXPECTED_IFNAME}" \
        "${PYTHON_BIN}" >"${directory}/request.json" <<'PY'
from __future__ import print_function
import json,os
print(json.dumps({"method":"DELETE","port_id":os.environ["EXPECTED_PORT_ID"],
                  "ifname":os.environ["EXPECTED_IFNAME"]},sort_keys=True))
PY
}

delete_target_port_evidence() {
    local directory="$1"
    write_delete_request "${directory}" || return 2
    docker_agent_exec python - "${SOCKET_PATH}" "${EXPECTED_PORT_ID}" \
        >"${directory}/response.json.tmp" <<'PY'
from __future__ import print_function

import json
import sys

from neutron_aria.agent.uds_client import LocalApiResponseError, LocalClient

socket_path, port_id = sys.argv[1:3]
client = LocalClient(socket_path, timeout=3.0)
client.capabilities()
client.status()
try:
    body = client.delete_port(port_id)
except LocalApiResponseError as exc:
    print(json.dumps({"http_status":exc.status,"reason":exc.reason,"body":exc.body},sort_keys=True))
    raise SystemExit(1)
print(json.dumps({"http_status":200,"reason":"OK","body":body},sort_keys=True))
PY
    local rc=$?
    mv "${directory}/response.json.tmp" "${directory}/response.json" || return 2
    return "${rc}"
}

guard_dedicated_host() {
    local label="$1" mode="$2" directory
    directory="${WORK_DIR}/guards/${label}"
    if ! mkdir -p "${directory}"; then
        GUARD_REFUSED=true
        return 1
    fi
    if ! status_json >"${directory}/status.json"; then
        GUARD_REFUSED=true
        return 1
    fi
    if ! curl --silent --show-error --fail "${DATAPATH_HTTP}/api/v1/instances" \
            >"${directory}/instances.json"; then
        GUARD_REFUSED=true
        return 1
    fi
    if ! "${PYTHON_BIN}" - "${directory}" "${EXPECTED_PORT_ID}" "${EXPECTED_IFNAME}" "${mode}" \
            >"${directory}/assertion.json" <<'PY'
from __future__ import print_function

import json
import os
import sys

root, port_id, ifname, mode = sys.argv[1:]
status=json.load(open(os.path.join(root,"status.json"),encoding="utf-8"))
instances=json.load(open(os.path.join(root,"instances.json"),encoding="utf-8"))
managed=status.get("managed_ports") or []
status_active=set(status.get("active_instances") or [])
api_active={row.get("name") for row in instances.get("instances") or []}
assert None not in api_active,instances
assert status_active==api_active,{"uds":sorted(status_active),"api":sorted(api_active)}
expected_managed=[row for row in managed if row.get("port_id")==port_id and row.get("ifname")==ifname]
assert len(expected_managed)==len(managed),{"managed_ports":managed}
assert len(managed)<=1,managed
assert status_active.issubset({ifname}),sorted(status_active)
if mode=="empty":
    assert not managed,managed
    assert not status_active,sorted(status_active)
elif mode=="target":
    assert len(expected_managed)==1,managed
    assert status_active=={ifname},sorted(status_active)
elif mode=="empty_or_target":
    assert len(status_active)<=1,sorted(status_active)
else:
    raise AssertionError("unsupported guard mode %s" % mode)
print(json.dumps({"mode":mode,"managed_ports":managed,
                  "active_instances":sorted(status_active)},sort_keys=True))
PY
    then
        GUARD_REFUSED=true
        return 1
    fi
    DEDICATED_GUARD_ESTABLISHED=true
}

restart_datapath_clean_guarded() {
    local label="$1" mode="$2" log_file="$3"
    guard_dedicated_host "${label}-pre-clean-restart" "${mode}"
    DATAPATH_RESTORE_ARMED=true
    start_datapath_without_fault >"${log_file}" 2>&1
    DATAPATH_RESTORE_ARMED=false
}

restart_datapath_with_fault_guarded() {
    local label="$1" mode="$2" point="$3" marker="$4" log_file="$5"
    guard_dedicated_host "${label}-pre-fault-restart" "${mode}"
    DATAPATH_RESTORE_ARMED=true
    FAULT_ACTION=return_error start_datapath_with_fault "${point}" "${marker}" \
        >"${log_file}" 2>&1
}

assert_ready_enforced_baseline() {
    local directory="$1"
    DIRECTORY="${directory}" PORT_ID="${EXPECTED_PORT_ID}" \
    OWNER_PREFIX="neutron:${EXPECTED_PORT_ID}:" "${PYTHON_BIN}" - <<'PY'
from __future__ import print_function
import json,os

def decode_bpftool_int(value):
    if isinstance(value, (str, type(u""))):
        return int(value, 0)
    return int(value)

root=os.environ["DIRECTORY"]
port_id=os.environ["PORT_ID"]
status=json.load(open(os.path.join(root,"status.json"),encoding="utf-8"))
rows=[row for row in status.get("port_statuses") or [] if row.get("port_id")==port_id]
assert len(rows)==1,(port_id,status)
row=rows[0]
domains=[domain for domain in row.get("domains") or [] if domain.get("domain")=="acl"]
assert len(domains)==1,row
assert domains[0].get("status")=="ready",domains[0]
assert domains[0].get("effective_action")=="enforce",domains[0]
tap_config=json.load(open(os.path.join(root,"tap-config.json"),encoding="utf-8"))["value"]
assert decode_bpftool_int(tap_config[0])==1,tap_config
assert decode_bpftool_int(tap_config[2])==1,tap_config
prefix=os.environ["OWNER_PREFIX"]
groups=json.load(open(os.path.join(root,"groups.json"),encoding="utf-8")).get("groups") or []
owned_groups=[group for group in groups if str(group.get("name") or "").startswith(prefix)]
assert owned_groups,groups
policies=json.load(open(os.path.join(root,"policies.json"),encoding="utf-8")).get("policies") or []
assert any(str(policy.get("src_group") or "").startswith(prefix) or
           str(policy.get("dst_group") or "").startswith(prefix)
           for policy in policies),policies
print(json.dumps({"acl":"ready/enforce","gate":"published",
                  "owned_groups":len(owned_groups),"owned_policies":len(policies)},sort_keys=True))
PY
}

assert_failed_transaction() {
    local fixture="$1" before="$2" after="$3" expected_error="$4" require_equal="$5"
    FIXTURE="${fixture}" BEFORE="${WORK_DIR}/${before}" AFTER="${WORK_DIR}/${after}" \
    PORT_ID="${EXPECTED_PORT_ID}" IFNAME="${EXPECTED_IFNAME}" \
    OWNER_PREFIX="neutron:${EXPECTED_PORT_ID}:" EXPECTED_ERROR="${expected_error}" \
    REQUIRE_EQUAL="${require_equal}" "${PYTHON_BIN}" - <<'PY'
from __future__ import print_function

import json
import os

def decode_bpftool_int(value):
    if isinstance(value, (str, type(u""))):
        return int(value, 0)
    return int(value)

before=os.environ["BEFORE"]
after=os.environ["AFTER"]
port_id=os.environ["PORT_ID"]
ifname=os.environ["IFNAME"]
owner_prefix=os.environ["OWNER_PREFIX"]

def load(root,name):
    return json.load(open(os.path.join(root,name),encoding="utf-8"))

def canonical(value):
    if isinstance(value,list):
        return sorted((canonical(item) for item in value),key=lambda item:json.dumps(item,sort_keys=True))
    if isinstance(value,dict):
        return {key:canonical(value[key]) for key in sorted(value)}
    return value

def target_port_and_status(status):
    ports=[row for row in status.get("managed_ports") or [] if row.get("port_id")==port_id]
    statuses=[row for row in status.get("port_statuses") or [] if row.get("port_id")==port_id]
    assert len(ports)==1,(port_id,status)
    assert len(statuses)==1,(port_id,status)
    assert ports[0].get("ifname")==ifname,ports
    return ports[0],statuses[0]

def domain(row,name):
    domains=[item for item in row.get("domains") or [] if item.get("domain")==name]
    assert len(domains)==1,(name,row)
    return domains[0]

def committed_identity(path):
    committed=None
    entries=[]
    for line in open(path,encoding="utf-8"):
        line=line.strip()
        if not line:
            continue
        entry=json.loads(line)
        entries.append(entry)
        if isinstance(entry.get("state"),dict):
            committed=entry["state"]
    assert committed is not None,path
    ports=committed.get("ports") or {}
    statuses=committed.get("port_statuses") or {}
    assert port_id in ports,(port_id,committed)
    return canonical({"port":ports[port_id],"port_status":statuses.get(port_id)}),entries

def owned(root):
    groups=load(root,"groups.json").get("groups") or []
    policies=load(root,"policies.json").get("policies") or []
    owned_groups=[row for row in groups if str(row.get("name") or "").startswith(owner_prefix)]
    owned_ids={row.get("id") for row in owned_groups}
    owned_policies=[row for row in policies if
                    str(row.get("src_group") or "").startswith(owner_prefix) or
                    str(row.get("dst_group") or "").startswith(owner_prefix) or
                    row.get("src_group_id") in owned_ids or row.get("dst_group_id") in owned_ids]
    return canonical({"groups":owned_groups,"policies":owned_policies})

response=load(after,"response.json")
body=response.get("body") or {}
assert int(response.get("http_status") or 0)>=400,response
assert body.get("status")=="error",response
assert body.get("detached") is False,response
assert os.environ["EXPECTED_ERROR"] in str(body.get("error") or ""),response

before_status=load(before,"status.json")
after_status=load(after,"status.json")
before_port,before_row=target_port_and_status(before_status)
after_port,after_row=target_port_and_status(after_status)
before_acl=domain(before_row,"acl")
after_acl=domain(after_row,"acl")
assert canonical(before_port)==canonical(after_port),(before_port,after_port)
assert before_row.get("status")=="ready",before_row
assert before_acl.get("status")=="ready",before_acl
assert before_acl.get("effective_action")=="enforce",before_acl
assert after_row.get("status")=="blocked",after_row
assert after_row.get("reason"),after_row
assert after_row.get("desired_hash")==before_row.get("desired_hash"),(before_row,after_row)
assert after_row.get("desired_hash")==after_status.get("applied_desired_hash"),after_status
assert int(after_row.get("generation"))==int(after_status.get("applied_generation")),after_status
assert canonical(after_row.get("managed_domains") or [])==canonical(before_row.get("managed_domains") or []),(before_row,after_row)
assert after_acl.get("status")=="blocked",after_acl
assert after_acl.get("effective_action")=="bypass",after_acl
assert not (after_row.get("status")=="ready" and after_acl.get("effective_action")=="enforce"),after_row
assert after_status.get("transaction_state")=="blocked",after_status
assert after_status.get("overall_readiness")=="blocked",after_status
assert after_status.get("required_action")=="operator",after_status
assert after_status.get("authority_state")=="blocked_recovery_required",after_status
assert after_status.get("desired_hash") is None,after_status
assert after_status.get("pending_generation") is not None,after_status
assert after_status.get("applied_desired_hash")==before_status.get("applied_desired_hash"),(before_status,after_status)
before_durable,before_entries=committed_identity(os.path.join(before,"neutron-snapshot.wal"))
after_durable,after_entries=committed_identity(os.path.join(after,"neutron-snapshot.wal"))
assert before_durable==after_durable,(before_durable,after_durable)
assert after_entries[-1].get("type")=="delete_intent",after_entries[-1]
assert after_entries[-1].get("port_id")==port_id,after_entries[-1]

tap_config=load(after,"tap-config.json")["value"]
assert decode_bpftool_int(tap_config[0])==0,tap_config
assert decode_bpftool_int(tap_config[2])==0,tap_config

after_owned=owned(after)
if os.environ["REQUIRE_EQUAL"]=="true":
    assert load(before,"bank.json")["active_bank"]==load(after,"bank.json")["active_bank"]
    for name in ("POLICY_TABLE.json","SRC_IPV4_TRIE.json","DST_IPV4_TRIE.json",
                 "SRC_IPV6_TRIE.json","DST_IPV6_TRIE.json","ACL_SRC_IPV4_TRIE.json",
                 "ACL_DST_IPV4_TRIE.json","ACL_SRC_IPV6_TRIE.json","ACL_DST_IPV6_TRIE.json"):
        assert canonical(load(before,name))==canonical(load(after,name)),name
    assert owned(before)==after_owned,(owned(before),after_owned)
else:
    assert after_owned=={"groups":[],"policies":[]},after_owned
    tap_id=int(load(after,"bank.json")["tap_id"])
    policy_rows=load(after,"POLICY_TABLE.json")
    assert not any(int.from_bytes(bytes(row["key"][:4]),byteorder="little")==tap_id for row in policy_rows),policy_rows
    def lpm_tap_id(row):
        key=bytes(row["key"])
        assert len(key)>=8,key
        return int.from_bytes(key[4:8],byteorder="big")
    for name in ("SRC_IPV4_TRIE.json","DST_IPV4_TRIE.json",
                 "SRC_IPV6_TRIE.json","DST_IPV6_TRIE.json"):
        rows=load(after,name)
        assert not any(lpm_tap_id(row)==tap_id for row in rows),name
    banked_tap_ids={tap_id*2,tap_id*2+1}
    for name in ("ACL_SRC_IPV4_TRIE.json","ACL_DST_IPV4_TRIE.json",
                 "ACL_SRC_IPV6_TRIE.json","ACL_DST_IPV6_TRIE.json"):
        rows=load(after,name)
        assert not any(lpm_tap_id(row) in banked_tap_ids for row in rows),name

print(json.dumps({"fixture":os.environ["FIXTURE"],"detached":False,
                  "links_attached":True,"gate_quiesced":True,
                  "owned_projection":after_owned,"durable_identity_equal":True,
                  "managed_port_identity_equal":True,"blocked_status_visible":True,
                  "publication_equal":os.environ["REQUIRE_EQUAL"]=="true"},
                 sort_keys=True))
PY
}

capture_optional_map() {
    local directory="$1" map_name="$2" path="${PIN_ROOT}/${map_name}"
    if [ -e "${path}" ]; then
        printf 'present %s\n' "${path}" >"${directory}/${map_name}.observation.txt"
        bpftool -j map dump pinned "${path}" >"${directory}/${map_name}.json" || return 1
    else
        [ ! -e "${path}" ] || return 1
        printf 'absent %s\n' "${path}" >"${directory}/${map_name}.observation.txt"
    fi
}

capture_api_outcome() {
    local url="$1" body_file="$2" status_file="$3" status
    status="$(curl --silent --show-error --output "${body_file}" --write-out '%{http_code}' "${url}")" || return 1
    printf '%s\n' "${status}" >"${status_file}"
}

capture_detached_state() {
    local label="$1" tap_id="$2" directory map_name ifindex net_rc=0 link_rc=0
    directory="${WORK_DIR}/${label}"
    mkdir -p "${directory}" || return 1
    printf '%s\n' "${tap_id}" >"${directory}/pre-delete-tap-id.txt" || return 1
    ifindex="$(cat "/sys/class/net/${EXPECTED_IFNAME}/ifindex")" || return 1
    printf '%s\n' "${ifindex}" >"${directory}/expected-ifindex.txt" || return 1
    status_json >"${directory}/status.json" || return 1
    curl --silent --show-error --fail "${DATAPATH_HTTP}/api/v1/instances" \
        >"${directory}/instances.json" || return 1
    ip -details link show dev "${EXPECTED_IFNAME}" >"${directory}/link.txt" || return 1
    capture_tc_filter ingress "${directory}/tc-ingress.json" || return 1
    capture_tc_filter egress "${directory}/tc-egress.json" || return 1
    bpftool -j net show >"${directory}/bpftool-net.json" \
        2>"${directory}/bpftool-net.err" || net_rc=$?
    printf '{"available":%s,"exit_code":%s}\n' \
        "$([ "${net_rc}" -eq 0 ] && printf true || printf false)" "${net_rc}" \
        >"${directory}/bpftool-net-status.json"
    bpftool -j link show >"${directory}/bpftool-link.json" \
        2>"${directory}/bpftool-link.err" || link_rc=$?
    printf '{"available":%s,"exit_code":%s}\n' \
        "$([ "${link_rc}" -eq 0 ] && printf true || printf false)" "${link_rc}" \
        >"${directory}/bpftool-link-status.json"
    for map_name in POLICY_TABLE SRC_IPV4_TRIE DST_IPV4_TRIE SRC_IPV6_TRIE DST_IPV6_TRIE \
            ACL_SRC_IPV4_TRIE ACL_DST_IPV4_TRIE ACL_SRC_IPV6_TRIE ACL_DST_IPV6_TRIE; do
        capture_optional_map "${directory}" "${map_name}" || return 1
    done
    capture_api_outcome "${DATAPATH_HTTP}/api/v1/${EXPECTED_IFNAME}/groups" \
        "${directory}/groups-response.json" "${directory}/groups-http-status.txt" || return 1
    capture_api_outcome "${DATAPATH_HTTP}/api/v1/${EXPECTED_IFNAME}/policies" \
        "${directory}/policies-response.json" "${directory}/policies-http-status.txt" || return 1
    capture_wal "${directory}/neutron-snapshot.wal" || return 1
    docker_agent_exec python - "${NEUTRON_STATE_PATH}/${EXPECTED_IFNAME}/state.json" \
        >"${directory}/state-observation.json" <<'PY' || return 1
from __future__ import print_function
import json,os,sys
path=sys.argv[1]
exists=os.path.exists(path)
content=open(path,encoding="utf-8").read() if exists else None
print(json.dumps({"path":path,"exists":exists,"content":content},sort_keys=True))
PY
}

assert_retry_detached() {
    local directory="$1" tap_id="$2"
    DIRECTORY="${directory}" TAP_ID="${tap_id}" PORT_ID="${EXPECTED_PORT_ID}" \
    IFNAME="${EXPECTED_IFNAME}" OWNER_PREFIX="neutron:${EXPECTED_PORT_ID}:" \
    PIN_ROOT="${PIN_ROOT}" "${PYTHON_BIN}" - <<'PY'
from __future__ import print_function

import json
import os

root=os.environ["DIRECTORY"]
tap_id=int(os.environ["TAP_ID"])
port_id=os.environ["PORT_ID"]
ifname=os.environ["IFNAME"]
owner_prefix=os.environ["OWNER_PREFIX"]
pin_root=os.environ["PIN_ROOT"]
expected_ifindex=int(open(os.path.join(root,"expected-ifindex.txt"),encoding="utf-8").read())

def load(name):
    return json.load(open(os.path.join(root,name),encoding="utf-8"))

response=load("response.json")
body=response.get("body") or {}
assert response.get("http_status")==200,response
assert body.get("status")=="ok",response
assert body.get("detached") is True,response
status=load("status.json")
assert not any(row.get("port_id")==port_id for row in status.get("managed_ports") or []),status
assert ifname not in set(status.get("active_instances") or []),status
instances=load("instances.json").get("instances") or []
assert not any(row.get("name")==ifname for row in instances),instances
for direction in ("ingress","egress"):
    assert not os.path.exists(os.path.join(pin_root,"%s_tc_%s_link"%(ifname,direction)))

def nested_dicts(value):
    if isinstance(value,dict):
        yield value
        for child in value.values():
            for row in nested_dicts(child):
                yield row
    elif isinstance(value,list):
        for child in value:
            for row in nested_dicts(child):
                yield row

def int_field(row,name):
    try:
        return int(row.get(name) or 0)
    except (TypeError,ValueError):
        return 0

def tc_program_id(row):
    return int_field(row,"prog_id") or int_field(row,"id")

baseline_prog_ids={}
for direction in ("ingress","egress"):
    link=load("pre-delete-pinned-%s-link.json"%direction)
    if isinstance(link,list):
        assert len(link)==1,(direction,link)
        link=link[0]
    assert int_field(link,"ifindex")==expected_ifindex,(direction,expected_ifindex,link)
    prog_id=int_field(link,"prog_id")
    assert prog_id>0,(direction,link)
    assert direction in json.dumps(link,sort_keys=True).lower(),(direction,link)
    baseline_prog_ids[direction]=prog_id

# The direction-specific tc inventory is scoped to the exact target interface.
# Reject only the pre-delete Aria program for that direction; unrelated filters
# are retained in the evidence and do not fail this assertion.
for direction,prog_id in baseline_prog_ids.items():
    target_tc=load("tc-%s.json"%direction)
    assert not any(tc_program_id(row)==prog_id
                   for row in nested_dicts(target_tc)),(direction,prog_id,target_tc)

# TCX link objects carry ifindex, prog_id, and attach direction. Prove that no
# exact pre-delete target link remains, while allowing other links/programs.
all_links=load("bpftool-link.json")
for direction,prog_id in baseline_prog_ids.items():
    matches=[]
    for row in nested_dicts(all_links):
        if int_field(row,"ifindex") != expected_ifindex:
            continue
        if int_field(row,"prog_id") != prog_id:
            continue
        if direction not in json.dumps(row,sort_keys=True).lower():
            continue
        matches.append(row)
    assert not matches,(direction,expected_ifindex,prog_id,matches)

# bpftool net is a second, independent inventory. Its TC rows do not always
# expose direction, so match only the exact ifindex plus pre-delete prog_id.
net_inventory=load("bpftool-net.json")
tc_inventory=[]
for row in nested_dicts(net_inventory):
    tc_rows=row.get("tc")
    if isinstance(tc_rows,list):
        tc_inventory.extend(tc_rows)
for direction,prog_id in baseline_prog_ids.items():
    matches=[row for row in nested_dicts(tc_inventory)
             if int_field(row,"ifindex")==expected_ifindex and
                tc_program_id(row)==prog_id]
    assert not matches,(direction,expected_ifindex,prog_id,matches)

def observed_map(name):
    observation=open(os.path.join(root,name+".observation.txt"),encoding="utf-8").read().strip()
    path=os.path.join(pin_root,name)
    if observation=="absent "+path:
        assert not os.path.exists(path),(name,observation)
        return None
    assert observation=="present "+path,(name,observation)
    assert os.path.exists(path),(name,observation)
    return load(name+".json")

policy_rows=observed_map("POLICY_TABLE")
if policy_rows is not None:
    assert not any(int.from_bytes(bytes(row["key"][:4]),byteorder="little")==tap_id
                   for row in policy_rows),policy_rows
banked_tap_ids={tap_id*2,tap_id*2+1}
def lpm_tap_id(row):
    key=bytes(row["key"])
    assert len(key)>=8,key
    return int.from_bytes(key[4:8],byteorder="big")
for name in ("ACL_SRC_IPV4_TRIE","ACL_DST_IPV4_TRIE",
             "ACL_SRC_IPV6_TRIE","ACL_DST_IPV6_TRIE"):
    rows=observed_map(name)
    if rows is not None:
        assert not any(lpm_tap_id(row) in banked_tap_ids for row in rows),name
for name in ("SRC_IPV4_TRIE","DST_IPV4_TRIE","SRC_IPV6_TRIE","DST_IPV6_TRIE"):
    rows=observed_map(name)
    if rows is not None:
        assert not any(lpm_tap_id(row)==tap_id for row in rows),name

for resource in ("groups","policies"):
    code=int(open(os.path.join(root,resource+"-http-status.txt"),encoding="utf-8").read())
    payload=open(os.path.join(root,resource+"-response.json"),encoding="utf-8").read()
    assert code==404,(resource,code,payload)
    assert owner_prefix not in payload,(resource,payload)
state=load("state-observation.json")
assert owner_prefix not in (state.get("content") or ""),state
print(json.dumps({"detached":True,"managed_runtime_absent":True,
                  "owned_projection_absent":True,"pinned_tc_links_absent":True,
                  "tap_id":tap_id},sort_keys=True))
PY
}

apply_and_capture_transaction_fixture() {
    local label="$1"
    guard_dedicated_host "${label}-pre-snapshot" empty
    TARGET_ROLLBACK_ARMED=true
    apply_acl_snapshot_without_rollback "${acl_fixture_json}" \
        >"${WORK_DIR}/${label}-apply-snapshot.log" 2>&1
    capture_transaction_state "${label}-before"
    guard_dedicated_host "${label}-ready-baseline" target
    assert_ready_enforced_baseline "${WORK_DIR}/${label}-before" \
        >"${WORK_DIR}/${label}-baseline-assertion.json"
}

retry_transaction_delete() {
    local label="$1" before_directory="$2" retry_directory tap_id retry_rc
    retry_directory="${WORK_DIR}/${label}-retry"
    mkdir -p "${retry_directory}"
    tap_id="$("${PYTHON_BIN}" - "${WORK_DIR}/${before_directory}/bank.json" <<'PY'
import json,sys
print(json.load(open(sys.argv[1],encoding="utf-8"))["tap_id"])
PY
    )"
    set +e
    delete_target_port_evidence "${retry_directory}"
    retry_rc=$?
    set -e
    [ "${retry_rc}" -eq 0 ] || die "${label} retry delete failed rc=${retry_rc}"
    capture_detached_state "${label}-retry" "${tap_id}"
    cp "${WORK_DIR}/${before_directory}/pinned-ingress-link.json" \
        "${retry_directory}/pre-delete-pinned-ingress-link.json"
    cp "${WORK_DIR}/${before_directory}/pinned-egress-link.json" \
        "${retry_directory}/pre-delete-pinned-egress-link.json"
    assert_retry_detached "${retry_directory}" "${tap_id}" >"${retry_directory}/assertion.json"
    cp "${WORK_DIR}/${before_directory}/bank.json" "${retry_directory}/pre-retry-bank.json"
    cp "${WORK_DIR}/${before_directory}/groups.json" "${retry_directory}/pre-retry-groups.json"
    cp "${WORK_DIR}/${before_directory}/policies.json" "${retry_directory}/pre-retry-policies.json"
    TARGET_ROLLBACK_ARMED=false
}

run_detach_ordering_fixture() {
    local label="detach-ordering" marker first_rc
    marker="${FAULT_ONCE_DIR}/aria-fault-$(sanitize_point neutron.delete.after_acl_purge).once"
    rm -f "${marker}"
    restart_datapath_with_fault_guarded "${label}" empty neutron.delete.after_acl_purge \
        "${marker}" "${WORK_DIR}/${label}-fault-start.log"
    wait_for_uds
    apply_and_capture_transaction_fixture "${label}"
    mkdir -p "${WORK_DIR}/${label}-after"
    set +e
    delete_target_port_evidence "${WORK_DIR}/${label}-after"
    first_rc=$?
    set -e
    [ "${first_rc}" -ne 0 ] || die "detach ordering fault did not fail the first delete"
    [ -f "${marker}" ] || die "detach ordering one-shot fault marker was not created"
    capture_transaction_state "${label}-after"
    assert_failed_transaction detach_ordering "${label}-before" "${label}-after" \
        neutron.delete.after_acl_purge false >"${WORK_DIR}/${label}-after/assertion.json"
    DETACH_ORDERING_STATUS="pass"
    retry_transaction_delete "${label}" "${label}-before"
}

run_pin_failure_fixture() {
    local label="$1" map_name="$2" fixture_name="$3" clean_restart="$4"
    local first_rc restore_rc
    if [ "${clean_restart}" = "true" ]; then
        restart_datapath_clean_guarded "${label}" empty "${WORK_DIR}/${label}-start-clean.log"
        wait_for_uds
    fi
    apply_and_capture_transaction_fixture "${label}"
    mkdir -p "${WORK_DIR}/${label}-after"
    hold_pin_for_fault "${map_name}" "${label}"
    set +e
    delete_target_port_evidence "${WORK_DIR}/${label}-after"
    first_rc=$?
    restore_renamed_pins
    restore_rc=$?
    set -e
    [ "${restore_rc}" -eq 0 ] || die "${label} failed to restore ${map_name} immediately"
    [ "${first_rc}" -ne 0 ] || die "${label} pin fault did not fail the first delete"
    capture_transaction_state "${label}-after"
    assert_failed_transaction "${fixture_name}" "${label}-before" "${label}-after" \
        "${map_name}" true >"${WORK_DIR}/${label}-after/assertion.json"
    retry_transaction_delete "${label}" "${label}-before"
}

write_summary() {
    printf '%s\n' "${cleanup_errors[@]:-}" >"${WORK_DIR}/cleanup-errors.txt" || return 1
    RESULT="${RESULT}" FAILURE_REASON="${FAILURE_REASON}" WORK_DIR="${WORK_DIR}" \
    DETACH_ORDERING_STATUS="${DETACH_ORDERING_STATUS}" \
    PURGE_FAILURE_ATOMICITY_STATUS="${PURGE_FAILURE_ATOMICITY_STATUS}" \
    STRICT_FLUSH_ROLLBACK_STATUS="${STRICT_FLUSH_ROLLBACK_STATUS}" \
    RETRY_DETACH_STATUS="${RETRY_DETACH_STATUS}" \
        "${PYTHON_BIN}" >"${WORK_DIR}/summary.json.tmp" <<'PY' || return 1
from __future__ import print_function
import json,os
cleanup_errors=[line.rstrip("\n") for line in open(os.path.join(os.environ["WORK_DIR"],"cleanup-errors.txt"),encoding="utf-8") if line.rstrip("\n")]
fixtures={
    "detach_ordering":os.environ["DETACH_ORDERING_STATUS"],
    "purge_failure_atomicity":os.environ["PURGE_FAILURE_ATOMICITY_STATUS"],
    "strict_flush_rollback":os.environ["STRICT_FLUSH_ROLLBACK_STATUS"],
    "retry_detach":os.environ["RETRY_DETACH_STATUS"],
}
out={"result":os.environ["RESULT"],"failure_reason":os.environ["FAILURE_REASON"],
     "cleanup_errors":cleanup_errors,"work_dir":os.environ["WORK_DIR"],
     "transaction_boundary":{"fixtures":fixtures,
                             "complete":all(value=="pass" for value in fixtures.values())}}
print(json.dumps(out,sort_keys=True,indent=2))
PY
    mv "${WORK_DIR}/summary.json.tmp" "${WORK_DIR}/summary.json" || return 1
}

cleanup_managed_transaction_smoke() {
    local body_rc="$1" final_rc=1 pin_restoration_succeeded=true
    trap - EXIT
    set +e
    if ! restore_renamed_pins; then
        pin_restoration_succeeded=false
        record_cleanup_error "restore-renamed-pins failed"
    fi
    if [ "${DIRECT_SNAPSHOT_MODE}" = "true" ] && [ "${body_rc}" -ne 0 ]; then
        # The outer isolated runner owns all synthetic state. Stop the faulted
        # process and let that runner remove its private pins/state atomically.
        docker rm -f "${DATAPATH_SERVICE_NAME}" >/dev/null 2>&1 || true
        TARGET_ROLLBACK_ARMED=false
        DATAPATH_RESTORE_ARMED=false
    fi
    if [ "${pin_restoration_succeeded}" = "true" ] && \
            [ "${GUARD_REFUSED}" = "false" ] && \
            [ "${DEDICATED_GUARD_ESTABLISHED}" = "true" ] && \
            [ "${TARGET_ROLLBACK_ARMED}" = "true" ]; then
        if guard_dedicated_host cleanup-pre-rollback empty_or_target; then
            if rollback_transaction_managed_target >"${WORK_DIR}/cleanup-rollback.log" 2>&1; then
                TARGET_ROLLBACK_ARMED=false
            else
                record_cleanup_error "rollback-managed-target failed"
            fi
        else
            record_cleanup_error "cleanup rollback guard refused mutation"
        fi
    fi
    if [ "${pin_restoration_succeeded}" = "true" ] && \
            [ "${GUARD_REFUSED}" = "false" ] && \
            [ "${DEDICATED_GUARD_ESTABLISHED}" = "true" ] && \
            [ "${DATAPATH_RESTORE_ARMED}" = "true" ]; then
        if guard_dedicated_host cleanup-pre-restart empty_or_target; then
            if start_datapath_without_fault >"${WORK_DIR}/cleanup-start-clean.log" 2>&1; then
                DATAPATH_RESTORE_ARMED=false
            else
                record_cleanup_error "restore-datapath-without-fault failed"
            fi
        else
            record_cleanup_error "cleanup restart guard refused mutation"
        fi
    fi
    RESULT="fail"
    if [ "${body_rc}" -ne 0 ] && [ "${FAILURE_REASON}" = "smoke did not complete" ]; then
        FAILURE_REASON="body failed rc=${body_rc}"
    fi
    if [ "${TRANSACTION_BODY_SUCCEEDED}" = "true" ] && [ "${body_rc}" -eq 0 ] && \
            [ "${#cleanup_errors[@]}" -eq 0 ]; then
        RESULT="pass"
        FAILURE_REASON=""
        final_rc=0
    elif [ "${#cleanup_errors[@]}" -gt 0 ]; then
        FAILURE_REASON="${FAILURE_REASON:-cleanup failed}; cleanup verification failed"
    fi
    if ! write_summary; then
        record_cleanup_error "write_summary failed"
        RESULT="fail"
        final_rc=1
        write_summary || echo "CLEANUP_ERROR: summary retry failed" >&2
    fi
    exit "${final_rc}"
}

run_managed_transaction_smoke() {
    mkdir -p "${WORK_DIR}"
    [ "${MANAGED_TRANSACTION_SMOKE}" = "true" ] || die "managed transaction fixtures require MANAGED_TRANSACTION_SMOKE=true"
    need_command bpftool
    need_command tc
    ip link show dev "${EXPECTED_IFNAME}" >/dev/null 2>&1 || die "EXPECTED_IFNAME does not exist"
    mkdir -p "${FAULT_ONCE_DIR}"
    guard_dedicated_host initial-preflight empty_or_target
    TARGET_ROLLBACK_ARMED=true
    rollback_transaction_managed_target >"${WORK_DIR}/initial-rollback.log" 2>&1
    TARGET_ROLLBACK_ARMED=false
    run_detach_ordering_fixture
    run_pin_failure_fixture purge-failure-atomicity POLICY_TABLE purge_failure_atomicity true
    PURGE_FAILURE_ATOMICITY_STATUS="pass"
    run_pin_failure_fixture strict-flush-rollback CT_TABLE_V4 strict_flush_rollback false
    STRICT_FLUSH_ROLLBACK_STATUS="pass"
    RETRY_DETACH_STATUS="pass"
    TRANSACTION_BODY_SUCCEEDED=true
    FAILURE_REASON=""
    echo "managed ACL transaction smoke wiring passed; evidence is in ${WORK_DIR}/summary.json"
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

acl_fixture_json="$(build_acl_fixture \
    "${EXPECTED_PORT_ID}" \
    "${BLOCK_SRC_CIDR}" \
    "${ACL_DIRECTION}" \
    "${ACL_PROTOCOL}")"

if [ "${MANAGED_TRANSACTION_SMOKE}" = "true" ]; then
    run_managed_transaction_smoke
    exit 0
fi

echo "Cleaning existing managed ports before delete fault-injection smoke"
rollback_managed_ports
ROLLBACK_ARMED=true

echo "Pre-check: VM ${VM_IP} must be reachable before delete fault smoke"
ping -c "${PING_COUNT}" -W "${PING_TIMEOUT}" "${VM_IP}" >/dev/null

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
