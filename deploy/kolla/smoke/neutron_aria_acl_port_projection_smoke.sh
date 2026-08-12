#!/usr/bin/env bash
set -euo pipefail

OPENSTACK_CLIENT="${OPENSTACK_CLIENT:-openstack_client}"
ADMIN_RC_FILE="${ADMIN_RC_FILE:-/etc/kolla/.adminrc}"
LOCAL_NEUTRON_URL="${LOCAL_NEUTRON_URL:-http://127.0.0.1:9696/v2.0}"
NEUTRON_ARIA_AGENT="${NEUTRON_ARIA_AGENT:-neutron_aria_agent}"
TARGET_PORT_ID="${TARGET_PORT_ID:-}"
TARGET_HOST="${TARGET_HOST:-}"
TARGET_IP="${TARGET_IP:-}"
TEST_STALE="${TEST_STALE:-false}"
ALLOW_AGENT_RESTART="${ALLOW_AGENT_RESTART:-false}"
STATUS_STALE_TIMEOUT="${STATUS_STALE_TIMEOUT:-120}"
CONVERGENCE_TIMEOUT="${CONVERGENCE_TIMEOUT:-90}"
EVIDENCE_DIR="${EVIDENCE_DIR:-/var/tmp/neutron-aria-acl-port-projection-$(date +%Y%m%d%H%M%S)}"

policy_id=""
binding_id=""
status_id=""
foreign_status_id=""
agent_stopped=0
ping_pid=""

log() {
    printf '[neutron-aria-acl-port-projection-smoke] %s\n' "$*"
}

die() {
    echo "ERROR: $*" >&2
    exit 1
}

is_true() {
    case "${1:-}" in
        1|true|TRUE|yes|YES|on|ON) return 0 ;;
        *) return 1 ;;
    esac
}

require_root_host() {
    [ "$(id -u)" = "0" ] || die "This smoke must run as root on the Kolla host."
}

need_command() {
    command -v "$1" >/dev/null 2>&1 || die "missing command: $1"
}

neutron_cli() {
    docker exec -u root --env-file "${ADMIN_RC_FILE}" \
        "${OPENSTACK_CLIENT}" neutron "$@"
}

port_field() {
    neutron_cli port-show "${TARGET_PORT_ID}" -f value -c "$1" | tail -1
}

status_field() {
    local status_resource="${status_id:-${TARGET_PORT_ID}}"
    neutron_cli aria-acl-port-status-show "${status_resource}" \
        -f value -c "$1" 2>/dev/null | tail -1
}

json_field() {
    "${PYTHON_BIN}" -c 'from __future__ import print_function
import json
import sys

value = json.load(sys.stdin)
for part in sys.argv[1].split("."):
    value = value.get(part) if isinstance(value, dict) else None
print(value or "")' "$1"
}

api_json() {
    local method="$1"
    local path="$2"
    local data="${3:-}"
    if [ -n "${data}" ]; then
        curl -fsS -H "X-Auth-Token: ${TOKEN}" \
            -H 'Content-Type: application/json' \
            -X "${method}" -d "${data}" \
            "${LOCAL_NEUTRON_URL}/${path}"
    else
        curl -fsS -H "X-Auth-Token: ${TOKEN}" \
            -X "${method}" "${LOCAL_NEUTRON_URL}/${path}"
    fi
}

status_body() {
    local host="$1"
    local policy="$2"
    local binding="$3"
    local status="$4"
    local reason="$5"
    local action="$6"
    local generation="$7"
    printf '%s' \
        "{\"aria_acl_port_status\":{\"port_id\":\"${TARGET_PORT_ID}\",\"host\":\"${host}\",\"effective_policy_id\":\"${policy}\",\"binding_id\":\"${binding}\",\"status\":\"${status}\",\"reason\":\"${reason}\",\"effective_action\":\"${action}\",\"generation\":${generation}}}"
}

status_update_body() {
    local policy="$1"
    local binding="$2"
    local status="$3"
    local reason="$4"
    local action="$5"
    local generation="$6"
    printf '%s' \
        "{\"aria_acl_port_status\":{\"effective_policy_id\":\"${policy}\",\"binding_id\":\"${binding}\",\"status\":\"${status}\",\"reason\":\"${reason}\",\"effective_action\":\"${action}\",\"generation\":${generation}}}"
}

wait_for_status() {
    local expected_status="$1"
    local expected_action="$2"
    local expected_stale="$3"
    local i status action stale
    for i in $(seq 1 "${CONVERGENCE_TIMEOUT}"); do
        status="$(status_field status || true)"
        action="$(status_field effective_action || true)"
        stale="$(status_field stale || true)"
        if [ "${status}:${action}:${stale}" = \
             "${expected_status}:${expected_action}:${expected_stale}" ]; then
            return 0
        fi
        sleep 1
    done
    die "status did not converge: status=${status} action=${action} stale=${stale}"
}

wait_for_projection() {
    local expected_status="$1"
    local expected_reason="$2"
    local i status reason
    for i in $(seq 1 "${CONVERGENCE_TIMEOUT}"); do
        status="$(port_field aria_acl_runtime_status)"
        reason="$(port_field aria_acl_runtime_reason)"
        if [ "${status}" = "${expected_status}" ] && \
           { [ "${expected_reason}" = "*" ] || [ "${reason}" = "${expected_reason}" ]; }; then
            return 0
        fi
        sleep 1
    done
    die "port projection did not converge: status=${status} reason=${reason}"
}

restore_ready_status() {
    [ -n "${status_id}" ] || return 0
    api_json PUT "aria-acl-port-statuses/${status_id}" \
        "$(status_update_body "${policy_id}" "${binding_id}" ready ready enforce 990001)" \
        >/dev/null
}

stop_canary() {
    [ -n "${ping_pid}" ] || return 0
    kill -INT "${ping_pid}" >/dev/null 2>&1 || true
    wait "${ping_pid}" >/dev/null 2>&1 || true
    ping_pid=""
}

cleanup() {
    set +e
    stop_canary
    if [ "${agent_stopped}" = "1" ]; then
        docker start "${NEUTRON_ARIA_AGENT}" >/dev/null 2>&1 || true
        agent_stopped=0
    fi
    if [ -n "${foreign_status_id}" ]; then
        api_json DELETE "aria-acl-port-statuses/${foreign_status_id}" \
            >/dev/null 2>&1 || true
    fi
    if [ -n "${binding_id}" ]; then
        neutron_cli aria-acl-binding-delete "${binding_id}" >/dev/null 2>&1 || true
    fi
    if [ -n "${policy_id}" ]; then
        neutron_cli aria-acl-policy-delete "${policy_id}" >/dev/null 2>&1 || true
    fi
}

exit_on_signal() {
    exit 130
}

require_root_host
need_command curl
need_command docker
need_command ping
[ -n "${TARGET_PORT_ID}" ] || die "TARGET_PORT_ID is required"
[ -n "${TARGET_HOST}" ] || die "TARGET_HOST is required"
if is_true "${TEST_STALE}" && ! is_true "${ALLOW_AGENT_RESTART}"; then
    die "TEST_STALE=true requires ALLOW_AGENT_RESTART=true"
fi
if [ -z "${PYTHON_BIN:-}" ]; then
    PYTHON_BIN="$(command -v python3 || command -v python || true)"
fi
[ -n "${PYTHON_BIN}" ] || die "missing command: python3 or python"

mkdir -p "${EVIDENCE_DIR}"
summary="${EVIDENCE_DIR}/summary.txt"
: >"${summary}"
trap cleanup EXIT
trap exit_on_signal INT TERM HUP

TOKEN="$(docker exec -u root --env-file "${ADMIN_RC_FILE}" \
    "${OPENSTACK_CLIENT}" openstack token issue -f value -c id | tail -1)"
[ -n "${TOKEN}" ] || die "failed to obtain OpenStack token"

ovs_pid_before="$(pidof ovs-vswitchd || true)"
[ -n "${ovs_pid_before}" ] || die "ovs-vswitchd host process is missing"
ovs_agent_started_before="$(docker inspect -f '{{.State.StartedAt}}' neutron_openvswitch_agent)"
project_id="$(neutron_cli port-show "${TARGET_PORT_ID}" -f value -c tenant_id | tail -1)"
[ -n "${project_id}" ] || die "target port project is missing"

if [ -n "${TARGET_IP}" ]; then
    ping -c 3 -W 1 "${TARGET_IP}" >/dev/null || die "baseline ping failed"
fi

run_id="acl013-$(date +%Y%m%d%H%M%S)"
policy_id="$(neutron_cli aria-acl-policy-create \
    --project-id "${project_id}" --name "${run_id}" \
    --default-action allow --enabled true -f value -c id | tail -1)"
[ -n "${policy_id}" ] || die "policy create returned no id"
binding_id="$(neutron_cli aria-acl-binding-create \
    --project-id "${project_id}" --policy-id "${policy_id}" \
    --port "${TARGET_PORT_ID}" --enabled true -f value -c id | tail -1)"
[ -n "${binding_id}" ] || die "binding create returned no id"

wait_for_status ready enforce False
status_id="$(status_field id)"
[ -n "${status_id}" ] || die "runtime status id is missing"
[ "$(port_field aria_acl_enabled)" = "True" ] || die "desired projection is not enabled"
[ "$(port_field aria_acl_effective_policy_id)" = "${policy_id}" ] || die "policy projection mismatch"
[ "$(port_field aria_acl_binding_id)" = "${binding_id}" ] || die "binding projection mismatch"
[ "$(port_field aria_acl_runtime_status)" = "applied" ] || die "ready status did not map to applied"
[ "$(port_field aria_acl_runtime_host)" = "${TARGET_HOST}" ] || die "runtime host mismatch"
printf 'ready_projection=pass port=%s host=%s\n' \
    "${TARGET_PORT_ID}" "${TARGET_HOST}" >>"${summary}"

if [ -n "${TARGET_IP}" ]; then
    ping -i 0.2 -c 900 -W 1 "${TARGET_IP}" \
        >"${EVIDENCE_DIR}/traffic-canary.txt" 2>&1 &
    ping_pid="$!"
fi

if is_true "${TEST_STALE}"; then
    docker stop "${NEUTRON_ARIA_AGENT}" >/dev/null
    agent_stopped=1
fi

foreign_payload="$(api_json POST aria-acl-port-statuses \
    "$(status_body acl013-foreign.invalid "${policy_id}" "${binding_id}" ready ready enforce 990002)")"
foreign_status_id="$(printf '%s' "${foreign_payload}" | json_field aria_acl_port_status.id)"
[ -n "${foreign_status_id}" ] || die "foreign status create returned no id"
[ "$(port_field aria_acl_runtime_status)" = "applied" ] || die "foreign host changed runtime status"
[ "$(port_field aria_acl_runtime_host)" = "${TARGET_HOST}" ] || die "foreign host displaced current host"
printf 'wrong_host_ignored=pass\n' >>"${summary}"

api_json PUT "aria-acl-port-statuses/${status_id}" \
    "$(status_update_body "${policy_id}" \
        00000000-0000-0000-0000-000000000013 ready ready enforce 990003)" \
    >/dev/null
wait_for_projection pending status_projection_mismatch
printf 'old_binding_conservative=pass\n' >>"${summary}"

restore_ready_status
wait_for_projection applied '*'
api_json PUT "aria-acl-port-statuses/${status_id}" \
    "$(status_update_body "${policy_id}" "${binding_id}" \
        degraded acl013_forced_degraded bypass 990004)" >/dev/null
wait_for_projection degraded acl013_forced_degraded
printf 'degraded_bypass_projection=pass\n' >>"${summary}"

restore_ready_status
wait_for_projection applied '*'

if is_true "${TEST_STALE}"; then
    stale="False"
    for _ in $(seq 1 "${STATUS_STALE_TIMEOUT}"); do
        stale="$(status_field stale || true)"
        [ "${stale}" = "True" ] && break
        sleep 1
    done
    [ "${stale}" = "True" ] || die "runtime status did not become stale"
    wait_for_projection unknown status_stale
    printf 'stale_conservative=pass\n' >>"${summary}"

    docker start "${NEUTRON_ARIA_AGENT}" >/dev/null
    agent_stopped=0
    wait_for_status ready enforce False
    wait_for_projection applied '*'
    printf 'agent_recovery_projection=pass\n' >>"${summary}"
fi

stop_canary
if [ -n "${TARGET_IP}" ]; then
    grep -q '0% packet loss' "${EVIDENCE_DIR}/traffic-canary.txt" || \
        die "traffic canary recorded packet loss"
fi

ovs_pid_after="$(pidof ovs-vswitchd || true)"
ovs_agent_started_after="$(docker inspect -f '{{.State.StartedAt}}' neutron_openvswitch_agent)"
[ "${ovs_pid_before}" = "${ovs_pid_after}" ] || die "ovs-vswitchd identity changed"
[ "${ovs_agent_started_before}" = "${ovs_agent_started_after}" ] || \
    die "neutron-openvswitch-agent restart identity changed"
printf 'ovs_non_interference=pass ovs_pid=%s\n' "${ovs_pid_after}" >>"${summary}"

api_json DELETE "aria-acl-port-statuses/${foreign_status_id}" >/dev/null
foreign_status_id=""
neutron_cli aria-acl-binding-delete "${binding_id}" >/dev/null
binding_id=""
neutron_cli aria-acl-policy-delete "${policy_id}" >/dev/null
policy_id=""

for _ in $(seq 1 "${CONVERGENCE_TIMEOUT}"); do
    if [ "$(port_field aria_acl_enabled):$(port_field aria_acl_runtime_status)" = \
         "False:not_requested" ]; then
        break
    fi
    sleep 1
done
[ "$(port_field aria_acl_enabled):$(port_field aria_acl_runtime_status)" = \
  "False:not_requested" ] || die "cleanup projection did not converge"
printf 'cleanup=pass\nacl013_port_projection=pass\n' >>"${summary}"

trap - EXIT INT TERM HUP
cat "${summary}"
log "evidence_dir=${EVIDENCE_DIR}"
