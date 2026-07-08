#!/usr/bin/env bash
set -euo pipefail

SERVICE_NAME="${SERVICE_NAME:-neutron_aria_agent}"
EXEC_USER="${EXEC_USER:-neutron}"
ADMIN_RC_FILE="${ADMIN_RC_FILE:-/etc/kolla/.adminrc}"
LOCAL_NEUTRON_URL="${LOCAL_NEUTRON_URL:-http://127.0.0.1:9696/v2.0}"
DATAPATH_HTTP="${DATAPATH_HTTP:-http://127.0.0.1:8080}"
AGENT_CONFIG="${AGENT_CONFIG:-/etc/neutron-aria-agent/neutron-aria-agent.ini}"
WORK_DIR="${WORK_DIR:-/tmp/neutron-aria-acl-active-traffic-$(date +%Y%m%d%H%M%S)-$(hostname -s)}"
RUN_ID="${RUN_ID:-acl-active-traffic-$(date +%Y%m%d%H%M%S)-$(hostname -s)}"
VM_IP="${VM_IP:-}"
EXPECTED_PORT_ID="${EXPECTED_PORT_ID:-}"
EXPECTED_IFNAME="${EXPECTED_IFNAME:-}"
ACL_PROTOCOL="${ACL_PROTOCOL:-icmp}"
ACL_DIRECTION="${ACL_DIRECTION:-ingress}"
BLOCK_SRC_CIDR="${BLOCK_SRC_CIDR:-}"
BLOCK_DST_CIDR="${BLOCK_DST_CIDR:-}"
PING_COUNT="${PING_COUNT:-1}"
PING_TIMEOUT="${PING_TIMEOUT:-1}"
ACTIVE_INTERVAL="${ACTIVE_INTERVAL:-1}"
BASELINE_TIMEOUT="${BASELINE_TIMEOUT:-30}"
BLOCK_OBSERVE_SECONDS="${BLOCK_OBSERVE_SECONDS:-8}"
RECOVERY_TIMEOUT="${RECOVERY_TIMEOUT:-30}"
MIN_BLOCK_FAILURES="${MIN_BLOCK_FAILURES:-2}"
REQUIRE_STATUS_IDENTITY="${REQUIRE_STATUS_IDENTITY:-true}"

die() {
    echo "ERROR: $*" >&2
    exit 1
}

log() {
    printf '[neutron-aria-acl-active-traffic-smoke] %s\n' "$*" | tee -a "${WORK_DIR}/run.log"
}

need_command() {
    command -v "$1" >/dev/null 2>&1 || die "missing command: $1"
}

select_python() {
    if [ -n "${PYTHON_BIN:-}" ]; then
        command -v "${PYTHON_BIN}" >/dev/null 2>&1 || \
            die "missing configured PYTHON_BIN: ${PYTHON_BIN}"
        return
    fi
    if command -v python3 >/dev/null 2>&1; then
        PYTHON_BIN="$(command -v python3)"
        return
    fi
    if command -v python >/dev/null 2>&1; then
        PYTHON_BIN="$(command -v python)"
        return
    fi
    die "missing command: python3 or python"
}

json_field() {
    "${PYTHON_BIN}" -c 'from __future__ import print_function
import json
import sys
field = sys.argv[1]
payload = json.load(sys.stdin)
value = payload
for part in field.split("."):
    value = value.get(part) if isinstance(value, dict) else None
print(value or "")' "$1"
}

curl_body() {
    local method="$1"
    local path="$2"
    local data="${3:-}"
    if [ -n "${data}" ]; then
        curl -sS -H "X-Auth-Token: ${TOKEN}" -H 'Content-Type: application/json' \
            -X "${method}" -d "${data}" "${LOCAL_NEUTRON_URL}/${path}"
    else
        curl -sS -H "X-Auth-Token: ${TOKEN}" -X "${method}" \
            "${LOCAL_NEUTRON_URL}/${path}"
    fi
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

run_full_resync() {
    docker exec -u "${EXEC_USER}" "${SERVICE_NAME}" \
        neutron-aria-agent \
        --config-file "${AGENT_CONFIG}" \
        --once \
        --enable-full-resync
}

datapath_policies() {
    curl -sS "${DATAPATH_HTTP}/api/v1/${EXPECTED_IFNAME}/policies"
}

wait_datapath_drop() {
    local i policies
    for i in $(seq 1 15); do
        policies="$(datapath_policies || true)"
        printf '%s\n' "${policies}" >"${WORK_DIR}/datapath-policies-drop-${i}.json"
        if printf '%s\n' "${policies}" | grep -q '"action":"drop"'; then
            printf '%s\n' "${policies}"
            return 0
        fi
        sleep 1
    done
    cat "${WORK_DIR}"/datapath-policies-drop-*.json 2>/dev/null || true
    die "datapath policy for ${EXPECTED_IFNAME} does not contain a drop rule"
}

wait_datapath_clear() {
    local i policies
    for i in $(seq 1 15); do
        policies="$(datapath_policies || true)"
        printf '%s\n' "${policies}" >"${WORK_DIR}/datapath-policies-clear-${i}.json"
        if ! printf '%s\n' "${policies}" | grep -q '"action":"drop"'; then
            printf '%s\n' "${policies}"
            return 0
        fi
        sleep 1
    done
    cat "${WORK_DIR}"/datapath-policies-clear-*.json 2>/dev/null || true
    die "datapath policy for ${EXPECTED_IFNAME} still contains a drop rule"
}

wait_port_status_identity() {
    [ "${REQUIRE_STATUS_IDENTITY}" = "true" ] || return 0
    local i status_payload
    for i in $(seq 1 15); do
        status_payload="$(curl_body GET aria-acl-port-statuses)"
        if STATUS_PAYLOAD="${status_payload}" "${PYTHON_BIN}" - \
            "${EXPECTED_PORT_ID}" "${policy_id}" "${binding_id}" \
            >"${WORK_DIR}/aria-acl-port-status-${i}.json" 2>"${WORK_DIR}/aria-acl-port-status-${i}.err" <<'PY'; then
from __future__ import print_function

import json
import os
import sys

port_id, expected_policy_id, expected_binding_id = sys.argv[1:4]
payload = json.loads(os.environ["STATUS_PAYLOAD"])
rows = [
    row for row in payload.get("aria_acl_port_statuses") or []
    if row.get("port_id") == port_id and row.get("status") == "ready"
]
if not rows:
    raise SystemExit("missing ready aria_acl_port_status for %s" % port_id)
row = rows[0]
print("aria_acl_port_status=%s" % json.dumps(row, sort_keys=True))
if row.get("effective_policy_id") != expected_policy_id:
    raise SystemExit(
        "effective_policy_id mismatch: %r != %r" %
        (row.get("effective_policy_id"), expected_policy_id)
    )
if row.get("binding_id") != expected_binding_id:
    raise SystemExit(
        "binding_id mismatch: %r != %r" %
        (row.get("binding_id"), expected_binding_id)
    )
PY
            cat "${WORK_DIR}/aria-acl-port-status-${i}.json"
            return 0
        fi
        sleep 1
    done
    cat "${WORK_DIR}"/aria-acl-port-status-*.err 2>/dev/null || true
    die "missing ready aria_acl_port_status identity for ${EXPECTED_PORT_ID}"
}

traffic_check() {
    ping -c "${PING_COUNT}" -W "${PING_TIMEOUT}" "${VM_IP}"
}

traffic_counts() {
    if [ ! -f "${TRAFFIC_LOG}" ]; then
        printf '0 0\n'
        return
    fi
    awk '
        /^sample=/ {
            for (i = 1; i <= NF; i++) {
                if ($i ~ /^rc=/) {
                    rc=$i
                    sub(/^rc=/, "", rc)
                    if (rc == "0") {
                        success++
                    } else {
                        failure++
                    }
                }
            }
        }
        END { printf "%d %d\n", success + 0, failure + 0 }
    ' "${TRAFFIC_LOG}"
}

start_active_traffic() {
    TRAFFIC_LOG="${WORK_DIR}/active-downlink-ping.log"
    TRAFFIC_STOP_FILE="${WORK_DIR}/active-downlink.stop"
    rm -f "${TRAFFIC_STOP_FILE}"
    (
        set +e
        sample=0
        while [ ! -f "${TRAFFIC_STOP_FILE}" ]; do
            sample=$((sample + 1))
            ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
            output="$(ping -c "${PING_COUNT}" -W "${PING_TIMEOUT}" "${VM_IP}" 2>&1)"
            rc=$?
            {
                printf 'sample=%s ts=%s rc=%s\n' "${sample}" "${ts}" "${rc}"
                printf '%s\n' "${output}" | sed 's/^/  /'
            } >>"${TRAFFIC_LOG}"
            sleep "${ACTIVE_INTERVAL}"
        done
    ) &
    TRAFFIC_PID=$!
    log "active_traffic_started pid=${TRAFFIC_PID} log=${TRAFFIC_LOG}"
}

stop_active_traffic() {
    set +e
    if [ -n "${TRAFFIC_PID:-}" ]; then
        touch "${TRAFFIC_STOP_FILE}"
        wait "${TRAFFIC_PID}" >/dev/null 2>&1 || true
        log "active_traffic_stopped pid=${TRAFFIC_PID}"
        TRAFFIC_PID=""
    fi
}

wait_success_delta() {
    local start_success start_failure current_success current_failure waited label
    label="$1"
    read -r start_success start_failure < <(traffic_counts)
    waited=0
    while [ "${waited}" -lt "${2}" ]; do
        read -r current_success current_failure < <(traffic_counts)
        if [ "$((current_success - start_success))" -ge 1 ]; then
            log "${label}_success_delta=$((current_success - start_success)) failures=${current_failure}"
            return 0
        fi
        sleep 1
        waited=$((waited + 1))
    done
    tail -80 "${TRAFFIC_LOG}" || true
    die "${label} did not observe successful active traffic within ${2}s"
}

observe_blocked_traffic() {
    local start_success start_failure current_success current_failure failure_delta
    read -r start_success start_failure < <(traffic_counts)
    sleep "${BLOCK_OBSERVE_SECONDS}"
    read -r current_success current_failure < <(traffic_counts)
    failure_delta=$((current_failure - start_failure))
    log "blocked_window_success_delta=$((current_success - start_success)) failure_delta=${failure_delta}"
    if [ "${failure_delta}" -lt "${MIN_BLOCK_FAILURES}" ]; then
        tail -120 "${TRAFFIC_LOG}" || true
        die "active traffic did not record enough blocked samples"
    fi
}

cleanup_acl() {
    set +e
    if [ -n "${binding_id:-}" ]; then
        curl_body DELETE "aria-acl-bindings/${binding_id}" >/dev/null 2>&1
    fi
    if [ -n "${rule_id:-}" ]; then
        curl_body DELETE "aria-acl-rules/${rule_id}" >/dev/null 2>&1
    fi
    if [ -n "${policy_id:-}" ]; then
        curl_body DELETE "aria-acl-policies/${policy_id}" >/dev/null 2>&1
    fi
    if [ "${RESYNC_ROLLBACK_ARMED:-false}" = "true" ]; then
        run_full_resync >/dev/null 2>&1 || true
    fi
}

cleanup_all() {
    cleanup_acl
    stop_active_traffic
}

need_command docker
need_command curl
need_command ip
need_command ping
select_python
mkdir -p "${WORK_DIR}"

[ "${ACL_DIRECTION}" = "ingress" ] || \
    die "active traffic smoke currently supports ACL_DIRECTION=ingress; use live egress smoke for guest-originated direction"
[ -n "${VM_IP}" ] || die "VM_IP is required"
[ -n "${EXPECTED_PORT_ID}" ] || die "EXPECTED_PORT_ID is required"
[ -n "${EXPECTED_IFNAME}" ] || die "EXPECTED_IFNAME is required"

if [ -z "${BLOCK_SRC_CIDR}" ]; then
    BLOCK_SRC_CIDR="$(route_source_cidr)" || \
        die "failed to infer source IP for ${VM_IP}; set BLOCK_SRC_CIDR"
fi
if [ -z "${BLOCK_DST_CIDR}" ]; then
    BLOCK_DST_CIDR="${VM_IP}/32"
fi

TOKEN="$(docker exec -u root --env-file "${ADMIN_RC_FILE}" \
    openstack_client openstack token issue -f value -c id | tail -1)"
[ -n "${TOKEN}" ] || die "failed to obtain OpenStack token"

policy_id=""
rule_id=""
binding_id=""
RESYNC_ROLLBACK_ARMED=false
TRAFFIC_PID=""
trap cleanup_all EXIT

log "work_dir=${WORK_DIR}"
log "target vm_ip=${VM_IP} port=${EXPECTED_PORT_ID} ifname=${EXPECTED_IFNAME}"
log "block src=${BLOCK_SRC_CIDR} dst=${BLOCK_DST_CIDR} protocol=${ACL_PROTOCOL}"

log "pre_check=one_shot_ping"
traffic_check >"${WORK_DIR}/baseline-one-shot-ping.txt"

start_active_traffic
wait_success_delta baseline "${BASELINE_TIMEOUT}"

policy_body="$(printf '{"aria_acl_policy":{"name":"%s-policy","default_action":"allow"}}' "${RUN_ID}")"
policy_id="$(curl_body POST aria-acl-policies "${policy_body}" | tee "${WORK_DIR}/policy-create.json" | json_field aria_acl_policy.id)"
[ -n "${policy_id}" ] || die "failed to create aria_acl policy"

rule_body="$(printf '{"aria_acl_rule":{"policy_id":"%s","direction":"ingress","priority":100,"action":"drop","protocol":"%s","src_cidr":"%s","dst_cidr":"%s"}}' \
    "${policy_id}" "${ACL_PROTOCOL}" "${BLOCK_SRC_CIDR}" "${BLOCK_DST_CIDR}")"
rule_id="$(curl_body POST aria-acl-rules "${rule_body}" | tee "${WORK_DIR}/rule-create.json" | json_field aria_acl_rule.id)"
[ -n "${rule_id}" ] || die "failed to create aria_acl rule"

binding_body="$(printf '{"aria_acl_binding":{"policy_id":"%s","target_type":"port","target_id":"%s"}}' \
    "${policy_id}" "${EXPECTED_PORT_ID}")"
binding_id="$(curl_body POST aria-acl-bindings "${binding_body}" | tee "${WORK_DIR}/binding-create.json" | json_field aria_acl_binding.id)"
[ -n "${binding_id}" ] || die "failed to create aria_acl binding"

log "applying_acl=full_resync"
run_full_resync | tee "${WORK_DIR}/apply-full-resync.log"
RESYNC_ROLLBACK_ARMED=true

log "checking_datapath_drop=true"
wait_datapath_drop | tee "${WORK_DIR}/datapath-drop.json"

log "checking_port_status_identity=true"
wait_port_status_identity

log "checking_one_shot_block=true"
if traffic_check >"${WORK_DIR}/blocked-one-shot-ping.txt" 2>&1; then
    die "ACL did not block one-shot ${ACL_PROTOCOL} traffic to ${VM_IP}"
fi
observe_blocked_traffic

log "rollback=delete_acl_objects_and_full_resync"
cleanup_acl
RESYNC_ROLLBACK_ARMED=false
policy_id=""
rule_id=""
binding_id=""

log "checking_datapath_clear=true"
wait_datapath_clear | tee "${WORK_DIR}/datapath-clear.json"

log "checking_recovery=true"
traffic_check >"${WORK_DIR}/recovery-one-shot-ping.txt"
wait_success_delta recovery "${RECOVERY_TIMEOUT}"

stop_active_traffic
trap - EXIT
log "acl_active_traffic_smoke=pass port=${EXPECTED_PORT_ID} work=${WORK_DIR}"
