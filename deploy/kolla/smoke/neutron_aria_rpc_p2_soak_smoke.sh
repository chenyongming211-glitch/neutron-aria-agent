#!/usr/bin/env bash
set -euo pipefail

SERVICE_NAME="${SERVICE_NAME:-neutron_aria_agent}"
EXEC_USER="${EXEC_USER:-neutron}"
ADMINRC="${ADMINRC:-/root/adminrc}"
HOST_FQDN="${HOST_FQDN:-$(hostname -f)}"
CONFIG_PATH="${CONFIG_PATH:-/etc/kolla/neutron-aria-agent/neutron-aria-agent.ini}"
AGENT_LOG_PATH="${AGENT_LOG_PATH:-/var/log/kolla/neutron/neutron-aria-agent.log}"
SOCKET_PATH="${SOCKET_PATH:-/run/aria/aria-agent.sock}"
WORK_DIR="${WORK_DIR:-/tmp/neutron-aria-rpc-p2-soak-$(date +%Y%m%d%H%M%S)}"
OBSERVATION_SECONDS="${OBSERVATION_SECONDS:-1800}"
SAMPLE_INTERVAL="${SAMPLE_INTERVAL:-30}"
STARTUP_CONVERGENCE_TIMEOUT="${STARTUP_CONVERGENCE_TIMEOUT:-120}"
EVENT_CONVERGENCE_TIMEOUT="${EVENT_CONVERGENCE_TIMEOUT:-90}"
SEND_LOCAL_EVENT="${SEND_LOCAL_EVENT:-true}"
EVENT_PORT_ID="${EVENT_PORT_ID:-}"
EXPECTED_MANAGED_PORTS="${EXPECTED_MANAGED_PORTS:-}"
KEEP_ENABLED="${KEEP_ENABLED:-false}"
BAD_LOG_PATTERN="${BAD_LOG_PATTERN:-degraded=True|overflowed=True|Traceback|ERROR|local_api_degraded|pending_snapshot_hash_mismatch_blocked|stale_pending_snapshot_requires_operator|heartbeat_ok=False}"
PYTHON_BIN="${PYTHON_BIN:-}"

die() {
    echo "ERROR: $*" >&2
    exit 1
}

log() {
    echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) $*" | tee -a "${WORK_DIR}/soak.log"
}

need_command() {
    command -v "$1" >/dev/null 2>&1 || die "missing command: $1"
}

select_python() {
    if [ -n "${PYTHON_BIN}" ]; then
        command -v "${PYTHON_BIN}" >/dev/null 2>&1 || \
            die "missing configured PYTHON_BIN: ${PYTHON_BIN}"
        return
    fi
    if command -v python3 >/dev/null 2>&1; then
        PYTHON_BIN="$(command -v python3)"
        return
    fi
    if command -v python2 >/dev/null 2>&1; then
        PYTHON_BIN="$(command -v python2)"
        return
    fi
    if command -v python >/dev/null 2>&1; then
        PYTHON_BIN="$(command -v python)"
        return
    fi
    die "missing command: python3/python2/python"
}

source_adminrc() {
    if [ -r "${ADMINRC}" ]; then
        # shellcheck disable=SC1090
        source "${ADMINRC}"
    fi
}

docker_exec_agent_env() {
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

backup_config() {
    BACKUP_PATH="${CONFIG_PATH}.rpc-p2-soak-$(date +%Y%m%d%H%M%S).bak"
    cp -a "${CONFIG_PATH}" "${BACKUP_PATH}"
    log "config_backup=${BACKUP_PATH}"
}

set_rpc_p2_config() {
    "${PYTHON_BIN}" - "${CONFIG_PATH}" <<'PY'
from __future__ import print_function

import os
import sys

try:
    import ConfigParser as configparser
except ImportError:
    import configparser

path = sys.argv[1]
parser_class = getattr(configparser, "SafeConfigParser", configparser.ConfigParser)
parser = parser_class()
parser.read(path)

for section in ("agent", "neutron"):
    if not parser.has_section(section):
        parser.add_section(section)

parser.set("agent", "full_resync_enabled", "true")
parser.set("neutron", "port_source", "neutronclient")
parser.set("neutron", "rpc_events_enabled", "true")
parser.set("neutron", "incremental_rpc_enabled", "false")
parser.set("neutron", "revisionless_incremental_mode", "disabled")

tmp = path + ".tmp"
with open(tmp, "w") as stream:
    parser.write(stream)
os.rename(tmp, path)
print("rpc_p2_config_written=%s" % path)
PY
}

restore_config() {
    if [ -z "${BACKUP_PATH:-}" ] || [ ! -f "${BACKUP_PATH}" ]; then
        return
    fi
    if [ "${KEEP_ENABLED}" = "true" ]; then
        log "keep_enabled=true skip_config_restore backup=${BACKUP_PATH}"
        return
    fi
    cp -a "${BACKUP_PATH}" "${CONFIG_PATH}"
    docker restart "${SERVICE_NAME}" >/dev/null
    log "config_restored=${BACKUP_PATH}"
}

on_exit() {
    local rc=$?
    set +e
    restore_config
    if [ "${rc}" -eq 0 ]; then
        log "rpc_p2_soak=pass work=${WORK_DIR}"
    else
        log "rpc_p2_soak=fail rc=${rc} work=${WORK_DIR}"
    fi
    exit "${rc}"
}

agent_status_json() {
    docker exec -i -u "${EXEC_USER}" "${SERVICE_NAME}" python - "${SOCKET_PATH}" <<'PY'
from __future__ import print_function

import json
import sys

from neutron_aria.agent.uds_client import LocalClient

status = LocalClient(sys.argv[1], timeout=3.0).status()
print(json.dumps(status, sort_keys=True))
PY
}

status_summary() {
    local file="$1"
    "${PYTHON_BIN}" - "${file}" <<'PY'
from __future__ import print_function

import json
import sys

with open(sys.argv[1]) as stream:
    status = json.load(stream)

managed = status.get("managed_ports") or []
pending = status.get("pending_generation")
if pending in (None, "", 0):
    pending = "none"
accepted = status.get("accepted_generation") or "none"
applied = status.get("applied_generation") or "none"
print("%s\t%s\t%s\t%s\t%s" % (
    len(managed),
    status.get("generation") or "",
    pending,
    accepted,
    applied,
))
PY
}

agent_log_line_count() {
    if [ -r "${AGENT_LOG_PATH}" ]; then
        wc -l <"${AGENT_LOG_PATH}"
        return
    fi
    echo 0
}

agent_logs_since() {
    if [ -r "${AGENT_LOG_PATH}" ]; then
        tail -n +"$((LOG_START_LINE + 1))" "${AGENT_LOG_PATH}" 2>/dev/null || true
        return
    fi
    docker logs --since "${START_TS}" "${SERVICE_NAME}" 2>&1 || true
}

log_count() {
    local pattern="$1"
    agent_logs_since | grep -c "${pattern}" || true
}

bad_log_count() {
    { agent_logs_since | grep -E "${BAD_LOG_PATTERN}" || true; } | wc -l
}

restart_count() {
    docker inspect -f '{{.RestartCount}}' "${SERVICE_NAME}"
}

wait_for_startup_convergence() {
    local waited=0
    while [ "${waited}" -lt "${STARTUP_CONVERGENCE_TIMEOUT}" ]; do
        if agent_logs_since | grep -q "sync_mode=rpc_full_resync" &&
            agent_logs_since | grep -q "full_resync_complete"; then
            agent_status_json >"${WORK_DIR}/status-startup.json"
            IFS=$'\t' read -r BASELINE_MANAGED BASELINE_GENERATION _pending _accepted _applied < <(
                status_summary "${WORK_DIR}/status-startup.json"
            )
            if [ -n "${EXPECTED_MANAGED_PORTS}" ] &&
                [ "${BASELINE_MANAGED}" != "${EXPECTED_MANAGED_PORTS}" ]; then
                die "managed port count ${BASELINE_MANAGED} != expected ${EXPECTED_MANAGED_PORTS}"
            fi
            log "startup_converged=true waited=${waited} managed_ports=${BASELINE_MANAGED} generation=${BASELINE_GENERATION}"
            return
        fi
        sleep 1
        waited=$((waited + 1))
    done
    agent_logs_since | tail -160 || true
    die "startup did not converge within ${STARTUP_CONVERGENCE_TIMEOUT}s"
}

first_bound_port_id() {
    if [ -n "${EVENT_PORT_ID}" ]; then
        echo "${EVENT_PORT_ID}"
        return
    fi

    docker_exec_agent_env python - "${HOST_FQDN}" <<'PY'
from __future__ import print_function

import sys

from neutron_aria.agent.neutron_client import build_neutronclient_from_env

host = sys.argv[1]
client = build_neutronclient_from_env()
ports = client.list_ports(**{"binding:host_id": host}).get("ports", [])
for port in ports:
    port_id = port.get("id")
    if port_id:
        print(port_id)
        break
PY
}

send_port_update() {
    local port_id="$1"
    docker_exec_agent_env python - "${HOST_FQDN}" "${port_id}" <<'PY'
from __future__ import print_function

import sys
import time

from neutron.common import config as common_config

common_config.init([
    "--config-file",
    "/etc/neutron/neutron.conf",
    "--config-file",
    "/etc/neutron/plugins/ml2/openvswitch_agent.ini",
])
try:
    common_config.setup_logging()
except Exception:
    pass

from neutron import context
from neutron.common import topics
from neutron.plugins.ml2.rpc import AgentNotifierApi

host, port_id = sys.argv[1:3]
port = {
    "id": port_id,
    "binding:host_id": host,
    "revision_number": int(time.time()),
}
AgentNotifierApi(topics.AGENT).port_update(
    context.get_admin_context(),
    port,
    None,
    None,
    None,
)
print("rpc_port_update_sent=%s host=%s" % (port_id, host))
PY
}

trigger_and_wait_for_event() {
    if [ "${SEND_LOCAL_EVENT}" != "true" ]; then
        log "send_local_event=false"
        return
    fi
    local port_id before after waited
    port_id="$(first_bound_port_id || true)"
    if [ -z "${port_id}" ]; then
        log "local_event_skipped=no_bound_port host=${HOST_FQDN}"
        return
    fi
    before="$(log_count "event_batch_drained")"
    send_port_update "${port_id}" | tee "${WORK_DIR}/event-send.log"
    waited=0
    while [ "${waited}" -lt "${EVENT_CONVERGENCE_TIMEOUT}" ]; do
        after="$(log_count "event_batch_drained")"
        if [ "${after}" -gt "${before}" ]; then
            log "event_converged=true waited=${waited} port_id=${port_id} event_batches_before=${before} event_batches_after=${after}"
            return
        fi
        sleep 1
        waited=$((waited + 1))
    done
    agent_logs_since | tail -160 || true
    die "RPC event did not converge within ${EVENT_CONVERGENCE_TIMEOUT}s"
}

observe_window() {
    local end_ts sample now status_file managed generation pending accepted applied current_restart bad full_resync_count event_count
    end_ts=$(( $(date +%s) + OBSERVATION_SECONDS ))
    sample=0
    BASE_RESTART_COUNT="$(restart_count)"
    while true; do
        now="$(date +%s)"
        if [ "${now}" -ge "${end_ts}" ]; then
            break
        fi
        sample=$((sample + 1))
        status_file="${WORK_DIR}/status-sample-${sample}.json"
        agent_status_json >"${status_file}"
        IFS=$'\t' read -r managed generation pending accepted applied < <(status_summary "${status_file}")
        current_restart="$(restart_count)"
        bad="$(bad_log_count | tr -d ' ')"
        full_resync_count="$(log_count "full_resync_complete" | tr -d ' ')"
        event_count="$(log_count "event_batch_drained" | tr -d ' ')"
        log "sample=${sample} managed_ports=${managed} generation=${generation} pending_generation=${pending:-none} accepted_generation=${accepted:-none} applied_generation=${applied:-none} restarts=${current_restart} bad_logs=${bad} full_resync_count=${full_resync_count} event_batch_count=${event_count}"

        if [ "${managed}" != "${BASELINE_MANAGED}" ]; then
            die "managed port count drifted from ${BASELINE_MANAGED} to ${managed}"
        fi
        if [ "${pending}" != "none" ]; then
            die "pending_generation is not empty: ${pending}"
        fi
        if [ "${current_restart}" != "${BASE_RESTART_COUNT}" ]; then
            die "container restart count changed from ${BASE_RESTART_COUNT} to ${current_restart}"
        fi
        if [ "${bad}" != "0" ]; then
            agent_logs_since | grep -E "${BAD_LOG_PATTERN}" | tail -80 || true
            die "bad log pattern observed: count=${bad}"
        fi
        sleep "${SAMPLE_INTERVAL}"
    done
}

need_command docker
select_python
mkdir -p "${WORK_DIR}"
trap on_exit EXIT

source_adminrc
docker ps --format '{{.Names}}' | grep -qx "${SERVICE_NAME}" || \
    die "${SERVICE_NAME} is not running"
docker exec "${SERVICE_NAME}" test -S "${SOCKET_PATH}" || \
    die "${SOCKET_PATH} is not visible in ${SERVICE_NAME}"
[ -f "${CONFIG_PATH}" ] || die "missing config: ${CONFIG_PATH}"

START_TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
LOG_START_LINE="$(agent_log_line_count)"
log "host=${HOST_FQDN} observation_seconds=${OBSERVATION_SECONDS} sample_interval=${SAMPLE_INTERVAL} keep_enabled=${KEEP_ENABLED}"
backup_config
set_rpc_p2_config | tee -a "${WORK_DIR}/soak.log"
docker restart "${SERVICE_NAME}" >/dev/null
log "agent_restarted=${SERVICE_NAME}"
wait_for_startup_convergence
trigger_and_wait_for_event
observe_window
