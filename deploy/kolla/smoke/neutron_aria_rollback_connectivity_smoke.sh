#!/usr/bin/env bash
set -euo pipefail

SERVICE_NAME="${SERVICE_NAME:-neutron_aria_agent}"
DATAPATH_SERVICE_NAME="${DATAPATH_SERVICE_NAME:-aria_datapath}"
REPO_ROOT="${REPO_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)}"
SOCKET_PATH="${SOCKET_PATH:-/run/aria/aria-agent.sock}"
EXEC_USER="${EXEC_USER:-neutron}"
HOST_FQDN="${HOST_FQDN:-$(hostname -f 2>/dev/null || hostname)}"
EVIDENCE_ROOT="${EVIDENCE_ROOT:-/var/tmp/neutron-aria-rollback-connectivity}"
EVIDENCE_DIR="${EVIDENCE_DIR:-${EVIDENCE_ROOT}/$(date +%Y%m%d%H%M%S)-${HOST_FQDN}}"
VM_IP="${VM_IP:-}"
EXPECTED_PORT_ID="${EXPECTED_PORT_ID:-}"
EXPECTED_IFNAME="${EXPECTED_IFNAME:-}"
BLOCK_SRC_CIDR="${BLOCK_SRC_CIDR:-}"
BLOCK_DST_CIDR="${BLOCK_DST_CIDR:-}"
ACL_DIRECTION="${ACL_DIRECTION:-ingress}"
ACL_PROTOCOL="${ACL_PROTOCOL:-icmp}"
PING_COUNT="${PING_COUNT:-2}"
PING_TIMEOUT="${PING_TIMEOUT:-1}"
TRAFFIC_CHECK_CMD="${TRAFFIC_CHECK_CMD:-}"
CHECK_AGENT_STOP="${CHECK_AGENT_STOP:-false}"
CHECK_DATAPATH_STOP="${CHECK_DATAPATH_STOP:-false}"
WAIT_AGENT_SECONDS="${WAIT_AGENT_SECONDS:-30}"
WAIT_DATAPATH_SECONDS="${WAIT_DATAPATH_SECONDS:-30}"

mkdir -p "${EVIDENCE_DIR}"
COMMANDS_LOG="${EVIDENCE_DIR}/commands.log"
FACTS_TSV="${EVIDENCE_DIR}/facts.tsv"
SUMMARY_MD="${EVIDENCE_DIR}/summary.md"
: > "${COMMANDS_LOG}"
: > "${FACTS_TSV}"

AGENT_STOPPED=false
DATAPATH_STOPPED=false
FAILED_CAPTURES=0

die() {
    echo "ERROR: $*" >&2
    exit 1
}

need_command() {
    command -v "$1" >/dev/null 2>&1 || die "missing command: $1"
}

escape_md() {
    printf '%s' "$1" | tr '\n' ' ' | sed 's/|/\\|/g'
}

cleanup() {
    if [ "${AGENT_STOPPED}" = "true" ]; then
        docker start "${SERVICE_NAME}" >/dev/null 2>&1 || true
    fi
    if [ "${DATAPATH_STOPPED}" = "true" ]; then
        docker start "${DATAPATH_SERVICE_NAME}" >/dev/null 2>&1 || true
    fi
}

trap cleanup EXIT

docker_agent_exec() {
    docker exec -i -u "${EXEC_USER}" "${SERVICE_NAME}" "$@"
}

capture() {
    local fact="$1"
    local expected="$2"
    local output_name="$3"
    shift 3

    local output_path="${EVIDENCE_DIR}/${output_name}"
    local command_text="$*"
    {
        printf '## %s\n' "${fact}"
        printf 'expected: %s\n' "${expected}"
        printf 'command: %s\n\n' "${command_text}"
    } >> "${COMMANDS_LOG}"

    set +e
    "$@" > "${output_path}" 2>&1
    local rc=$?
    set -e

    local disposition="pass"
    if [ "${rc}" -ne 0 ]; then
        disposition="fail"
    fi

    printf '%s\t%s\t%s\texit=%s\t%s\t%s\n' \
        "${fact}" \
        "${expected}" \
        "${command_text}" \
        "${rc}" \
        "${output_name}" \
        "${disposition}" >> "${FACTS_TSV}"
    printf 'exit=%s disposition=%s output=%s\n\n' \
        "${rc}" "${disposition}" "${output_path}" >> "${COMMANDS_LOG}"

    if [ "${rc}" -ne 0 ]; then
        FAILED_CAPTURES=$((FAILED_CAPTURES + 1))
    fi
    return 0
}

status_no_managed_ports() {
    docker_agent_exec python - "${SOCKET_PATH}" <<'PY'
from __future__ import print_function

import json
import sys

from neutron_aria.agent.uds_client import LocalClient

client = LocalClient(sys.argv[1], timeout=3.0)
status = client.status()
print(json.dumps(status, sort_keys=True))
managed = status.get("managed_ports") or []
if managed:
    raise SystemExit("expected no managed ports, got %s" % managed)
if int(status.get("wal_replay_failures") or 0) != 0:
    raise SystemExit("wal_replay_failures is non-zero: %s" % status)
PY
}

ping_vm() {
    ping -c "${PING_COUNT}" -W "${PING_TIMEOUT}" "${VM_IP}"
}

acl_rollback_drill() {
    VM_IP="${VM_IP}" \
        EXPECTED_PORT_ID="${EXPECTED_PORT_ID}" \
        EXPECTED_IFNAME="${EXPECTED_IFNAME}" \
        BLOCK_SRC_CIDR="${BLOCK_SRC_CIDR}" \
        BLOCK_DST_CIDR="${BLOCK_DST_CIDR}" \
        ACL_DIRECTION="${ACL_DIRECTION}" \
        ACL_PROTOCOL="${ACL_PROTOCOL}" \
        PING_COUNT="${PING_COUNT}" \
        PING_TIMEOUT="${PING_TIMEOUT}" \
        TRAFFIC_CHECK_CMD="${TRAFFIC_CHECK_CMD}" \
        REPO_ROOT="${REPO_ROOT}" \
        SERVICE_NAME="${SERVICE_NAME}" \
        SOCKET_PATH="${SOCKET_PATH}" \
        EXEC_USER="${EXEC_USER}" \
        bash "${REPO_ROOT}/deploy/kolla/smoke/neutron_aria_acl_full_resync_smoke.sh"
}

wait_agent_running() {
    local attempt
    for attempt in $(seq 1 "${WAIT_AGENT_SECONDS}"); do
        if docker ps --format '{{.Names}}' | grep -qx "${SERVICE_NAME}"; then
            return 0
        fi
        sleep 1
    done
    docker ps --format 'table {{.Names}}\t{{.Status}}' >&2 || true
    return 1
}

wait_datapath_ready() {
    local attempt
    for attempt in $(seq 1 "${WAIT_DATAPATH_SECONDS}"); do
        if docker ps --format '{{.Names}}' | grep -qx "${DATAPATH_SERVICE_NAME}" && \
            [ -S "${SOCKET_PATH}" ]; then
            return 0
        fi
        sleep 1
    done
    docker ps --format 'table {{.Names}}\t{{.Status}}' >&2 || true
    docker logs --tail 80 "${DATAPATH_SERVICE_NAME}" >&2 || true
    return 1
}

agent_stop_connectivity() {
    echo "Stopping ${SERVICE_NAME}"
    docker stop "${SERVICE_NAME}"
    AGENT_STOPPED=true

    echo "Checking VM connectivity while ${SERVICE_NAME} is stopped"
    ping_vm

    echo "Restarting ${SERVICE_NAME}"
    docker start "${SERVICE_NAME}"
    AGENT_STOPPED=false
    wait_agent_running

    echo "Checking VM connectivity after ${SERVICE_NAME} restart"
    ping_vm
}

datapath_stop_connectivity() {
    echo "Stopping ${DATAPATH_SERVICE_NAME}"
    docker stop "${DATAPATH_SERVICE_NAME}"
    DATAPATH_STOPPED=true

    echo "Checking VM connectivity while ${DATAPATH_SERVICE_NAME} is stopped"
    ping_vm

    echo "Restarting ${DATAPATH_SERVICE_NAME}"
    docker start "${DATAPATH_SERVICE_NAME}"
    DATAPATH_STOPPED=false
    wait_datapath_ready

    echo "Checking VM connectivity after ${DATAPATH_SERVICE_NAME} restart"
    ping_vm
    echo "Checking datapath status after ${DATAPATH_SERVICE_NAME} restart"
    status_no_managed_ports
}

write_summary() {
    local pass_count=0
    local fail_count=0

    {
        echo "# Rollback Connectivity Smoke Evidence"
        echo
        echo "Host: \`${HOST_FQDN}\`"
        echo
        echo "VM IP: \`${VM_IP}\`"
        echo
        echo "Port: \`${EXPECTED_PORT_ID}\` / \`${EXPECTED_IFNAME}\`"
        echo
        echo "Generated at: \`$(date -u '+%Y-%m-%dT%H:%M:%SZ')\`"
        echo
        echo "This smoke verifies rollback connectivity only. It does not enable"
        echo "QoS, Mirror, or RabbitMQ event consumption."
        echo
        echo "| Fact | Expected | Command | Actual | Evidence | Disposition |"
        echo "| --- | --- | --- | --- | --- | --- |"
    } > "${SUMMARY_MD}"

    while IFS=$'\t' read -r fact expected command actual evidence disposition; do
        [ -n "${fact}" ] || continue
        if [ "${disposition}" = "pass" ]; then
            pass_count=$((pass_count + 1))
        else
            fail_count=$((fail_count + 1))
        fi
        printf '| %s | %s | `%s` | %s | `%s` | %s |\n' \
            "$(escape_md "${fact}")" \
            "$(escape_md "${expected}")" \
            "$(escape_md "${command}")" \
            "$(escape_md "${actual}")" \
            "$(escape_md "${evidence}")" \
            "$(escape_md "${disposition}")" >> "${SUMMARY_MD}"
    done < "${FACTS_TSV}"

    {
        echo
        echo "## Result"
        echo
        echo "- pass: ${pass_count}"
        echo "- fail: ${fail_count}"
    } >> "${SUMMARY_MD}"

    [ "${fail_count}" -eq 0 ]
}

need_command docker
need_command ping

[ -n "${VM_IP}" ] || die "VM_IP is required"
[ -n "${EXPECTED_PORT_ID}" ] || die "EXPECTED_PORT_ID is required"
[ -n "${EXPECTED_IFNAME}" ] || die "EXPECTED_IFNAME is required"
docker ps --format '{{.Names}}' | grep -qx "${SERVICE_NAME}" || \
    die "${SERVICE_NAME} is not running"
if [ "${CHECK_DATAPATH_STOP}" = "true" ]; then
    docker ps --format '{{.Names}}' | grep -qx "${DATAPATH_SERVICE_NAME}" || \
        die "${DATAPATH_SERVICE_NAME} is not running"
fi

capture "Baseline VM connectivity" \
    "VM is reachable before rollback smoke" \
    "baseline-ping.txt" ping_vm
capture "Initial datapath status" \
    "UDS status is readable and has no managed ports before rollback drill" \
    "initial-status.txt" status_no_managed_ports
capture "ACL rollback drill" \
    "ACL blocks test traffic, UDS rollback deletes managed port, and ping recovers" \
    "acl-rollback-drill.log" acl_rollback_drill
capture "Post-rollback datapath status" \
    "UDS status has no managed ports after rollback drill" \
    "post-rollback-status.txt" status_no_managed_ports
capture "Post-rollback VM connectivity" \
    "VM remains reachable after rollback drill" \
    "post-rollback-ping.txt" ping_vm

if [ "${CHECK_AGENT_STOP}" = "true" ]; then
    capture "neutron-aria-agent stop connectivity" \
        "Stopping neutron-aria-agent does not break baseline OVS connectivity, and restart recovers the service" \
        "agent-stop-connectivity.log" agent_stop_connectivity
fi
if [ "${CHECK_DATAPATH_STOP}" = "true" ]; then
    capture "aria-datapath stop connectivity" \
        "Stopping aria-datapath does not break baseline OVS connectivity, and restart recovers UDS/status" \
        "datapath-stop-connectivity.log" datapath_stop_connectivity
fi

if write_summary && [ "${FAILED_CAPTURES}" -eq 0 ]; then
    echo "rollback connectivity evidence written to ${EVIDENCE_DIR}"
else
    echo "rollback connectivity evidence written with failures to ${EVIDENCE_DIR}" >&2
    exit 1
fi
