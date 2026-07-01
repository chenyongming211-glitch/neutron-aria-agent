#!/usr/bin/env bash
set -euo pipefail

SERVICE_NAME="${SERVICE_NAME:-neutron_aria_agent}"
REPO_ROOT="${REPO_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)}"
HOST_FQDN="${HOST_FQDN:-$(hostname -f)}"
CLI_CONTAINER="${CLI_CONTAINER:-openstack_client}"
ADMINRC="${ADMINRC:-/root/adminrc}"
SOCKET_PATH="${SOCKET_PATH:-/run/aria/aria-agent.sock}"
DATAPATH_HTTP="${DATAPATH_HTTP:-http://127.0.0.1:8080}"
SMOKE_CONFIG="${SMOKE_CONFIG:-/tmp/neutron-aria-agent-ovs-restart.ini}"
EXEC_USER="${EXEC_USER:-neutron}"
OVS_BRIDGE="${OVS_BRIDGE:-br-int}"
OVS_STATUS_UNIT="${OVS_STATUS_UNIT:-ovs-vswitchd.service}"
TEST_TRIGGER_OVS_RESTART="${TEST_TRIGGER_OVS_RESTART:-false}"
ROLLBACK="${ROLLBACK:-true}"
REQUEST_TIMEOUT_OVERRIDE="${REQUEST_TIMEOUT_OVERRIDE:-3.0}"
POST_RESTART_SETTLE_SECONDS="${POST_RESTART_SETTLE_SECONDS:-2}"
WAIT_OVS_SECONDS="${WAIT_OVS_SECONDS:-60}"
WAIT_FOR_EXTERNAL_OVS_RESTART="${WAIT_FOR_EXTERNAL_OVS_RESTART:-false}"
WAIT_EXTERNAL_OVS_RESTART_SECONDS="${WAIT_EXTERNAL_OVS_RESTART_SECONDS:-300}"
WAIT_TAP_SECONDS="${WAIT_TAP_SECONDS:-120}"
WAIT_FORWARDING_SECONDS="${WAIT_FORWARDING_SECONDS:-30}"
PING_COUNT="${PING_COUNT:-2}"
PING_TIMEOUT="${PING_TIMEOUT:-1}"
TRAFFIC_CHECK_CMD="${TRAFFIC_CHECK_CMD:-}"
REQUIRE_BASELINE_FORWARDING="${REQUIRE_BASELINE_FORWARDING:-true}"
REQUIRE_POST_RESTART_FORWARDING="${REQUIRE_POST_RESTART_FORWARDING:-false}"
REQUIRE_FINAL_FORWARDING="${REQUIRE_FINAL_FORWARDING:-false}"
WAIT_FOR_TAP_AFTER_MISSING="${WAIT_FOR_TAP_AFTER_MISSING:-true}"
WAL_REPLAY_FAILURE_MAX_DELTA="${WAL_REPLAY_FAILURE_MAX_DELTA:-0}"
WAL_REPLAY_FAILURE_BASELINE="${WAL_REPLAY_FAILURE_BASELINE:-}"
PYTHON_BIN="${PYTHON_BIN:-}"

VM_IP="${VM_IP:-}"
EXPECTED_PORT_ID="${EXPECTED_PORT_ID:-}"
EXPECTED_IFNAME="${EXPECTED_IFNAME:-}"
BLOCK_SRC_CIDR="${BLOCK_SRC_CIDR:-198.51.100.1/32}"
BLOCK_DST_CIDR="${BLOCK_DST_CIDR:-198.51.100.2/32}"
ACL_DIRECTION="${ACL_DIRECTION:-ingress}"
ACL_PROTOCOL="${ACL_PROTOCOL:-icmp}"

ROLLBACK_ARMED=false

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
    if [ "${ROLLBACK_ARMED}" = "true" ] && [ "${ROLLBACK}" = "true" ]; then
        echo "Cleaning up ovs-restart smoke managed ports"
        rollback_managed_ports || true
    fi
}

trap cleanup EXIT

tap_exists() {
    ip link show dev "${EXPECTED_IFNAME}" >/dev/null 2>&1
}

ifindex_of() {
    ip -o link show dev "${EXPECTED_IFNAME}" | awk -F: '{print $1}' | tr -d ' '
}

xdp_attached() {
    ip -d link show dev "${EXPECTED_IFNAME}" 2>/dev/null | grep -q 'xdp'
}

assert_xdp_attached() {
    xdp_attached || die "expected XDP attachment on ${EXPECTED_IFNAME}"
}

traffic_check() {
    if [ -n "${TRAFFIC_CHECK_CMD}" ]; then
        bash -c "${TRAFFIC_CHECK_CMD}"
    else
        ping -c "${PING_COUNT}" -W "${PING_TIMEOUT}" "${VM_IP}"
    fi
}

record_forwarding_observation() {
    local label="$1"
    set +e
    traffic_check >/dev/null 2>&1
    local rc=$?
    set -e
    if [ "${rc}" -eq 0 ]; then
        echo "ovs_forwarding_observation label=${label} result=pass"
    else
        echo "ovs_forwarding_observation label=${label} result=fail rc=${rc}"
    fi
    return "${rc}"
}

wait_forwarding() {
    local label="$1"
    local attempt
    for attempt in $(seq 1 "${WAIT_FORWARDING_SECONDS}"); do
        if record_forwarding_observation "${label}-attempt-${attempt}" >/dev/null; then
            echo "ovs_forwarding_observation label=${label} result=pass after_seconds=${attempt}"
            return 0
        fi
        sleep 1
    done
    echo "ovs_forwarding_observation label=${label} result=fail after_seconds=${WAIT_FORWARDING_SECONDS}"
    return 1
}

build_acl_fixture() {
    "${PYTHON_BIN}" - \
        "${EXPECTED_PORT_ID}" \
        "${BLOCK_SRC_CIDR}" \
        "${BLOCK_DST_CIDR}" \
        "${ACL_DIRECTION}" \
        "${ACL_PROTOCOL}" <<'PY'
from __future__ import print_function

import json
import sys

port_id, source_cidr, dest_cidr, direction, protocol = sys.argv[1:6]
rule = {
    "id": "drop-ovs-restart-%s" % protocol,
    "policy_id": "acl-ovs-restart-policy",
    "direction": direction,
    "priority": 100,
    "action": "drop",
    "ethertype": "IPv4",
    "protocol": protocol,
    "enabled": True,
    "revision_number": 1,
}
if source_cidr:
    rule["src_cidr"] = source_cidr
if dest_cidr:
    rule["dst_cidr"] = dest_cidr
print(json.dumps({
    "policies": [{
        "id": "acl-ovs-restart-policy",
        "name": "acl-ovs-restart-policy",
        "default_action": "allow",
        "stateful": True,
        "revision_number": 1,
    }],
    "rules": [rule],
    "address_sets": [],
    "bindings": [{
        "id": "acl-ovs-restart-binding",
        "policy_id": "acl-ovs-restart-policy",
        "target_type": "port",
        "target_id": port_id,
        "enabled": True,
        "revision_number": 1,
    }],
}, sort_keys=True))
PY
}

show_acl_state() {
    "${PYTHON_BIN}" - "${DATAPATH_HTTP}" "${EXPECTED_IFNAME}" <<'PY'
from __future__ import print_function

import json
import sys

try:
    from urllib import quote as urlquote
    from urllib2 import urlopen
except ImportError:
    from urllib.parse import quote as urlquote
    from urllib.request import urlopen

base = sys.argv[1].rstrip("/")
ifname = sys.argv[2]
encoded = urlquote(ifname, safe="")
groups = json.loads(urlopen("%s/api/v1/%s/groups" % (base, encoded)).read()).get("groups") or []
policies = json.loads(urlopen("%s/api/v1/%s/policies" % (base, encoded)).read()).get("policies") or []
print("acl_groups=%s" % json.dumps(groups, sort_keys=True))
print("acl_policies=%s" % json.dumps(policies, sort_keys=True))
if not policies:
    raise SystemExit("expected at least one ACL policy")
if not any(policy.get("action") == "drop" for policy in policies):
    raise SystemExit("expected a drop ACL policy")
PY
}

assert_target_attach_healthy() {
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
target = None
for port in payload.get("managed_ports") or []:
    if port.get("port_id") == expected_port_id:
        target = port
        break
if target is None:
    raise SystemExit("target port is not managed: %s" % payload)
if target.get("ifname") != expected_ifname:
    raise SystemExit("ifname mismatch: %s" % payload)
if int(target.get("ifindex") or -1) != expected_ifindex:
    raise SystemExit("ifindex mismatch: %s" % payload)
if payload.get("authority_state") != "ready":
    raise SystemExit("authority_state is not ready: %s" % payload)
target_status = None
for port_status in payload.get("port_statuses") or []:
    if port_status.get("port_id") == expected_port_id:
        target_status = port_status
        break
if target_status is None:
    raise SystemExit("target port status is missing: %s" % payload)
acl_status = None
for domain in target_status.get("domains") or []:
    if domain.get("domain") == "acl":
        acl_status = domain
        break
if acl_status is None:
    raise SystemExit("target ACL domain status is missing: %s" % payload)
if acl_status.get("status") != "ready":
    raise SystemExit("target ACL status is not ready: %s" % payload)
if acl_status.get("effective_action") != "enforce":
    raise SystemExit("target ACL effective_action is not enforce: %s" % payload)
current = int(payload.get("wal_replay_failures") or 0)
baseline = int(os.environ["WAL_REPLAY_FAILURE_BASELINE"] or 0)
max_delta = int(os.environ["WAL_REPLAY_FAILURE_MAX_DELTA"] or 0)
if current > baseline + max_delta:
    raise SystemExit(
        "wal_replay_failures increased: baseline=%d current=%d max_delta=%d payload=%s" %
        (baseline, current, max_delta, payload)
    )
print("acl_attach_healthy port_id=%s ifname=%s ifindex=%s generation=%s" % (
    expected_port_id,
    expected_ifname,
    expected_ifindex,
    payload.get("generation"),
))
PY
}

assert_final_no_managed_ports() {
    STATUS_PAYLOAD="$(status_json)" \
        WAL_REPLAY_FAILURE_BASELINE="${WAL_REPLAY_FAILURE_BASELINE}" \
        WAL_REPLAY_FAILURE_MAX_DELTA="${WAL_REPLAY_FAILURE_MAX_DELTA}" \
        "${PYTHON_BIN}" - <<'PY'
from __future__ import print_function

import json
import os

payload = json.loads(os.environ["STATUS_PAYLOAD"])
managed = payload.get("managed_ports") or []
if managed:
    raise SystemExit("managed ports remain after rollback: %s" % payload)
if payload.get("pending_generation") is not None:
    raise SystemExit("pending_generation remains after rollback: %s" % payload)
if payload.get("authority_state") != "ready":
    raise SystemExit("authority_state is not ready after rollback: %s" % payload)
current = int(payload.get("wal_replay_failures") or 0)
baseline = int(os.environ["WAL_REPLAY_FAILURE_BASELINE"] or 0)
max_delta = int(os.environ["WAL_REPLAY_FAILURE_MAX_DELTA"] or 0)
if current > baseline + max_delta:
    raise SystemExit(
        "wal_replay_failures increased: baseline=%d current=%d max_delta=%d payload=%s" %
        (baseline, current, max_delta, payload)
    )
print("final_no_managed_ports generation=%s wal_replay_failures=%s" % (
    payload.get("generation"),
    payload.get("wal_replay_failures"),
))
PY
}

wait_ovs_ready() {
    local attempt
    for attempt in $(seq 1 "${WAIT_OVS_SECONDS}"); do
        if systemctl is-active --quiet "${OVS_STATUS_UNIT}" && \
            ovs-vsctl --timeout=5 br-exists "${OVS_BRIDGE}" >/dev/null 2>&1; then
            return 0
        fi
        sleep 1
    done
    systemctl status "${OVS_STATUS_UNIT}" --no-pager || true
    ovs-vsctl show || true
    die "OVS did not become ready"
}

ovs_restart_marker() {
    systemctl show "${OVS_STATUS_UNIT}" \
        --property=MainPID \
        --property=ActiveEnterTimestampMonotonic \
        --value | tr '\n' ':' | sed 's/:$//'
}

wait_external_ovs_restart() {
    local before="$1"
    local attempt current
    echo "waiting_for_external_ovs_restart unit=${OVS_STATUS_UNIT} before_marker=${before}"
    for attempt in $(seq 1 "${WAIT_EXTERNAL_OVS_RESTART_SECONDS}"); do
        current="$(ovs_restart_marker || true)"
        if [ -n "${current}" ] && [ "${current}" != "${before}" ]; then
            echo "external_ovs_restart_observed=true after_seconds=${attempt} after_marker=${current}"
            return 0
        fi
        sleep 1
    done
    echo "external_ovs_restart_observed=false waited_seconds=${WAIT_EXTERNAL_OVS_RESTART_SECONDS}"
    return 1
}

wait_tap() {
    local attempt
    for attempt in $(seq 1 "${WAIT_TAP_SECONDS}"); do
        if tap_exists; then
            return 0
        fi
        sleep 1
    done
    die "tap ${EXPECTED_IFNAME} did not appear"
}

need_command docker
need_command ip
need_command ping
need_command systemctl
need_command ovs-vsctl
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
load_openstack_env
prepare_full_resync_config

if [ -z "${WAL_REPLAY_FAILURE_BASELINE}" ]; then
    WAL_REPLAY_FAILURE_BASELINE="$(current_wal_replay_failures)"
fi
echo "wal_replay_failure_baseline=${WAL_REPLAY_FAILURE_BASELINE} max_delta=${WAL_REPLAY_FAILURE_MAX_DELTA}"

if [ "${REQUIRE_BASELINE_FORWARDING}" = "true" ]; then
    wait_forwarding baseline >/dev/null || die "baseline forwarding check failed"
else
    record_forwarding_observation baseline || true
fi

echo "Cleaning existing managed ports before ovs-restart smoke"
rollback_managed_ports

acl_fixture_json="$(build_acl_fixture)"

echo "Applying ACL full-resync fixture for ovs-restart attach smoke"
ACL_FIXTURE_JSON="${acl_fixture_json}" \
    ROLLBACK=false \
    MIN_MANAGED_PORTS=1 \
    EXPECTED_PORT_ID="${EXPECTED_PORT_ID}" \
    EXPECTED_IFNAME="${EXPECTED_IFNAME}" \
    REQUEST_TIMEOUT_OVERRIDE="${REQUEST_TIMEOUT_OVERRIDE}" \
    bash "${REPO_ROOT}/deploy/kolla/smoke/neutron_aria_full_resync_smoke.sh"

ROLLBACK_ARMED=true
wait_tap
before_ifindex="$(ifindex_of)"
assert_xdp_attached
assert_target_attach_healthy "${before_ifindex}"
show_acl_state
record_forwarding_observation managed-before-restart || true
before_ovs_marker="$(ovs_restart_marker || true)"

if [ "${TEST_TRIGGER_OVS_RESTART}" = "true" ]; then
    echo "ovs_restart_trigger=test_smoke_explicit unit=${OVS_STATUS_UNIT} before_marker=${before_ovs_marker}"
    systemctl restart "${OVS_STATUS_UNIT}"
elif [ "${WAIT_FOR_EXTERNAL_OVS_RESTART}" = "true" ]; then
    echo "ovs_restart_trigger=external_wait script_will_not_restart_ovs=true before_marker=${before_ovs_marker}"
    wait_external_ovs_restart "${before_ovs_marker}" || \
        die "external OVS restart was not observed; this smoke never restarts OVS itself"
else
    echo "ovs_restart_trigger=none script_will_not_restart_ovs=true before_marker=${before_ovs_marker}"
    echo "external_ovs_restart_observed=not_required"
fi

wait_ovs_ready
after_ovs_marker="$(ovs_restart_marker || true)"
echo "ovs_restart_after_marker=${after_ovs_marker}"
sleep "${POST_RESTART_SETTLE_SECONDS}"

if tap_exists; then
    after_ifindex="$(ifindex_of)"
    if [ "${after_ifindex}" = "${before_ifindex}" ] && xdp_attached; then
        echo "ovs_restart_attach_case=tap_exists_same_ifindex_xdp_attached"
        assert_target_attach_healthy "${after_ifindex}"
        show_acl_state
    else
        if [ "${after_ifindex}" != "${before_ifindex}" ]; then
            echo "ovs_restart_attach_case=tap_ifindex_changed before=${before_ifindex} after=${after_ifindex}"
        else
            echo "ovs_restart_attach_case=xdp_missing_repairing"
        fi
        run_agent_once
        wait_tap
        repaired_ifindex="$(ifindex_of)"
        assert_xdp_attached
        assert_target_attach_healthy "${repaired_ifindex}"
        show_acl_state
    fi
else
    echo "ovs_restart_attach_case=tap_missing"
    if [ "${WAIT_FOR_TAP_AFTER_MISSING}" != "true" ]; then
        die "tap ${EXPECTED_IFNAME} missing after OVS observation"
    fi
    wait_tap
    run_agent_once
    repaired_ifindex="$(ifindex_of)"
    assert_xdp_attached
    assert_target_attach_healthy "${repaired_ifindex}"
    show_acl_state
fi

if [ "${REQUIRE_POST_RESTART_FORWARDING}" = "true" ]; then
    wait_forwarding post-restart >/dev/null || die "post-restart forwarding did not recover"
else
    wait_forwarding post-restart || true
fi

if [ "${ROLLBACK}" = "true" ]; then
    echo "Rolling back ovs-restart smoke managed ports"
    rollback_managed_ports
    ROLLBACK_ARMED=false
fi

assert_final_no_managed_ports

if [ "${REQUIRE_FINAL_FORWARDING}" = "true" ]; then
    wait_forwarding final >/dev/null || die "final forwarding did not recover"
else
    wait_forwarding final || true
fi

echo "neutron-aria-agent ovs-restart ACL attach smoke passed for ${EXPECTED_PORT_ID} on ${HOST_FQDN}"
