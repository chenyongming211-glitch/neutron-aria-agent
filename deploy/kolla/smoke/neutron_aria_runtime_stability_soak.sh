#!/usr/bin/env bash
set -euo pipefail

AGENT_SERVICE="${AGENT_SERVICE:-neutron_aria_agent}"
DATAPATH_SERVICE="${DATAPATH_SERVICE:-aria_datapath}"
OVS_AGENT_SERVICE="${OVS_AGENT_SERVICE:-neutron_openvswitch_agent}"
EXEC_USER="${EXEC_USER:-neutron}"
SOCKET_PATH="${SOCKET_PATH:-/run/aria/aria-agent.sock}"
STATE_DIR="${STATE_DIR:-/var/lib/aria-agent-smoke}"
PIN_ROOT="${PIN_ROOT:-/sys/fs/bpf/aria/global-v2}"
WORK_DIR="${WORK_DIR:-/tmp/neutron-aria-runtime-soak-$(date +%Y%m%d%H%M%S)}"
OBSERVATION_SECONDS="${OBSERVATION_SECONDS:-86400}"
SAMPLE_INTERVAL="${SAMPLE_INTERVAL:-300}"
EXPECTED_MANAGED_PORTS="${EXPECTED_MANAGED_PORTS:-}"
MAX_AGENT_RSS_GROWTH_KB="${MAX_AGENT_RSS_GROWTH_KB:-0}"
MAX_DATAPATH_RSS_GROWTH_KB="${MAX_DATAPATH_RSS_GROWTH_KB:-0}"
MAX_FD_GROWTH="${MAX_FD_GROWTH:-0}"
MAX_WAL_GROWTH_BYTES="${MAX_WAL_GROWTH_BYTES:-0}"
BAD_AGENT_LOG_PATTERN="${BAD_AGENT_LOG_PATTERN:-Traceback|ERROR|local_api_degraded|pending_snapshot_hash_mismatch_blocked|stale_pending_snapshot_requires_operator|heartbeat_ok=False}"
BAD_DATAPATH_LOG_PATTERN="${BAD_DATAPATH_LOG_PATTERN:-ERROR|panicked at|fatal runtime error|pending_snapshot_hash_mismatch_blocked}"
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
    local candidate
    if [ -n "${PYTHON_BIN}" ]; then
        need_command "${PYTHON_BIN}"
        return
    fi
    for candidate in python3 python2 python; do
        if command -v "${candidate}" >/dev/null 2>&1; then
            PYTHON_BIN="$(command -v "${candidate}")"
            return
        fi
    done
    die "missing command: python3/python2/python"
}

require_positive_integer() {
    local name="$1" value="$2"
    case "${value}" in
        ''|*[!0-9]*|0) die "${name} must be a positive integer" ;;
    esac
}

container_field() {
    local service="$1" template="$2"
    docker inspect -f "${template}" "${service}"
}

container_pid() {
    container_field "$1" '{{.State.Pid}}'
}

workload_pid() {
    local service="$1" init_pid child_pid
    init_pid="$(container_pid "${service}")"
    child_pid="$(docker top "${service}" -eo pid,ppid 2>/dev/null | \
        awk -v parent="${init_pid}" 'NR > 1 && $2 == parent { print $1; exit }')"
    echo "${child_pid:-${init_pid}}"
}

proc_metric() {
    local pid="$1" key="$2"
    awk -v key="${key}:" '$1 == key { print $2; found=1 } END { if (!found) print 0 }' \
        "/proc/${pid}/status"
}

fd_count() {
    local pid="$1"
    find "/proc/${pid}/fd" -mindepth 1 -maxdepth 1 -printf '.' 2>/dev/null | wc -c
}

tree_file_count() {
    local root="$1"
    [ -d "${root}" ] || { echo 0; return; }
    find "${root}" -type f -printf '.' 2>/dev/null | wc -c
}

wal_metrics() {
    if [ ! -d "${STATE_DIR}" ]; then
        printf '0\t0\n'
        return
    fi
    find "${STATE_DIR}" -type f -name '*.wal' -printf '%s\n' 2>/dev/null | \
        awk '{ bytes += $1; files += 1 } END { printf "%d\t%d\n", bytes, files }'
}

map_entry_count() {
    local path="$1"
    if [ ! -e "${path}" ] || ! command -v bpftool >/dev/null 2>&1; then
        echo na
        return
    fi
    bpftool -j map dump pinned "${path}" 2>/dev/null | "${PYTHON_BIN}" -c \
        'from __future__ import print_function; import json,sys; print(len(json.load(sys.stdin)))' \
        2>/dev/null || echo na
}

agent_status_json() {
    docker exec -i -u "${EXEC_USER}" "${AGENT_SERVICE}" python - "${SOCKET_PATH}" <<'PY'
from __future__ import print_function

import json
import sys

from neutron_aria.agent.uds_client import LocalClient

print(json.dumps(LocalClient(sys.argv[1], timeout=3.0).status(), sort_keys=True))
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

pending = status.get("pending_generation")
if pending in (None, "", 0):
    pending = "none"
print("%s\t%s\t%s\t%s\t%s\t%s" % (
    len(status.get("managed_ports") or []),
    status.get("generation") or "none",
    status.get("accepted_generation") or "none",
    status.get("applied_generation") or "none",
    pending,
    status.get("overall_readiness") or "unknown",
))
PY
}

assert_runtime_identity() {
    [ "$(container_field "${AGENT_SERVICE}" '{{.Id}}')" = "${BASE_AGENT_ID}" ] || \
        die "${AGENT_SERVICE} container identity changed"
    [ "$(container_field "${DATAPATH_SERVICE}" '{{.Id}}')" = "${BASE_DATAPATH_ID}" ] || \
        die "${DATAPATH_SERVICE} container identity changed"
    [ "$(container_pid "${AGENT_SERVICE}")" = "${BASE_AGENT_INIT_PID}" ] || \
        die "${AGENT_SERVICE} container init process restarted"
    [ "$(container_pid "${DATAPATH_SERVICE}")" = "${BASE_DATAPATH_INIT_PID}" ] || \
        die "${DATAPATH_SERVICE} container init process restarted"
    [ "$(workload_pid "${AGENT_SERVICE}")" = "${BASE_AGENT_PID}" ] || \
        die "${AGENT_SERVICE} process restarted"
    [ "$(workload_pid "${DATAPATH_SERVICE}")" = "${BASE_DATAPATH_PID}" ] || \
        die "${DATAPATH_SERVICE} process restarted"
    [ "$(pgrep -xo ovs-vswitchd)" = "${BASE_OVS_PID}" ] || \
        die "ovs-vswitchd PID changed"
    [ "$(container_field "${OVS_AGENT_SERVICE}" '{{.Id}}')" = "${BASE_OVS_AGENT_ID}" ] || \
        die "${OVS_AGENT_SERVICE} container identity changed"
    [ "$(container_field "${OVS_AGENT_SERVICE}" '{{.State.StartedAt}}')" = "${BASE_OVS_AGENT_STARTED}" ] || \
        die "${OVS_AGENT_SERVICE} start time changed"
}

assert_logs_clean() {
    local agent_bad datapath_bad
    agent_bad="$(docker logs --since "${START_TS}" "${AGENT_SERVICE}" 2>&1 | \
        grep -Ec "${BAD_AGENT_LOG_PATTERN}" || true)"
    datapath_bad="$(docker logs --since "${START_TS}" "${DATAPATH_SERVICE}" 2>&1 | \
        grep -Ec "${BAD_DATAPATH_LOG_PATTERN}" || true)"
    [ "${agent_bad}" = 0 ] || die "agent bad log count=${agent_bad}"
    [ "${datapath_bad}" = 0 ] || die "datapath bad log count=${datapath_bad}"
}

check_growth_thresholds() {
    "${PYTHON_BIN}" - "${WORK_DIR}/metrics.tsv" \
        "${MAX_AGENT_RSS_GROWTH_KB}" "${MAX_DATAPATH_RSS_GROWTH_KB}" \
        "${MAX_FD_GROWTH}" "${MAX_WAL_GROWTH_BYTES}" <<'PY'
from __future__ import print_function

import csv
import sys

path = sys.argv[1]
limits = [int(value) for value in sys.argv[2:]]
with open(path) as stream:
    rows = list(csv.DictReader(stream, delimiter="\t"))
if not rows:
    raise SystemExit("no stability samples")

fields = (
    "agent_rss_kb",
    "datapath_rss_kb",
    "agent_fds",
    "datapath_fds",
    "agent_threads",
    "datapath_threads",
    "wal_bytes",
)
deltas = dict((field, int(rows[-1][field]) - int(rows[0][field])) for field in fields)
print("stability_samples=%d" % len(rows))
for field in fields:
    values = [int(row[field]) for row in rows]
    print("%s first=%d last=%d max=%d delta=%d" % (
        field, values[0], values[-1], max(values), deltas[field]
    ))

checks = (
    ("agent_rss_kb", limits[0]),
    ("datapath_rss_kb", limits[1]),
    ("agent_fds", limits[2]),
    ("datapath_fds", limits[2]),
    ("wal_bytes", limits[3]),
)
for field, limit in checks:
    if limit > 0 and deltas[field] > limit:
        raise SystemExit("%s growth %d exceeds limit %d" % (
            field, deltas[field], limit
        ))
PY
}

need_command docker
need_command pgrep
need_command awk
select_python
require_positive_integer OBSERVATION_SECONDS "${OBSERVATION_SECONDS}"
require_positive_integer SAMPLE_INTERVAL "${SAMPLE_INTERVAL}"
mkdir -p "${WORK_DIR}"

for service in "${AGENT_SERVICE}" "${DATAPATH_SERVICE}" "${OVS_AGENT_SERVICE}"; do
    [ "$(container_field "${service}" '{{.State.Running}}')" = true ] || \
        die "${service} is not running"
done

START_TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
BASE_AGENT_ID="$(container_field "${AGENT_SERVICE}" '{{.Id}}')"
BASE_DATAPATH_ID="$(container_field "${DATAPATH_SERVICE}" '{{.Id}}')"
BASE_AGENT_INIT_PID="$(container_pid "${AGENT_SERVICE}")"
BASE_DATAPATH_INIT_PID="$(container_pid "${DATAPATH_SERVICE}")"
BASE_AGENT_PID="$(workload_pid "${AGENT_SERVICE}")"
BASE_DATAPATH_PID="$(workload_pid "${DATAPATH_SERVICE}")"
BASE_OVS_PID="$(pgrep -xo ovs-vswitchd)"
BASE_OVS_AGENT_ID="$(container_field "${OVS_AGENT_SERVICE}" '{{.Id}}')"
BASE_OVS_AGENT_STARTED="$(container_field "${OVS_AGENT_SERVICE}" '{{.State.StartedAt}}')"

printf '%s\n' \
    $'timestamp\tsample\tmanaged_ports\tgeneration\taccepted_generation\tapplied_generation\tpending_generation\toverall_readiness\tagent_rss_kb\tdatapath_rss_kb\tagent_fds\tdatapath_fds\tagent_threads\tdatapath_threads\twal_bytes\twal_files\tpin_files\tct_v4_entries\tct_v6_entries\tiface_entries' \
    >"${WORK_DIR}/metrics.tsv"

log "runtime_stability_soak=start host=$(hostname -f) observation_seconds=${OBSERVATION_SECONDS} sample_interval=${SAMPLE_INTERVAL} read_only=true"
end_ts=$(( $(date +%s) + OBSERVATION_SECONDS ))
sample=0
baseline_managed=""

while [ "$(date +%s)" -lt "${end_ts}" ]; do
    sample=$((sample + 1))
    assert_runtime_identity
    status_file="${WORK_DIR}/status-${sample}.json"
    agent_status_json >"${status_file}"
    IFS=$'\t' read -r managed generation accepted applied pending readiness < <(
        status_summary "${status_file}"
    )
    [ "${readiness}" = ready ] || die "overall_readiness=${readiness}"
    [ "${pending}" = none ] || die "pending_generation=${pending}"
    [ "${accepted}" = "${applied}" ] || \
        die "accepted_generation=${accepted} applied_generation=${applied}"
    if [ -z "${baseline_managed}" ]; then
        baseline_managed="${managed}"
        if [ -n "${EXPECTED_MANAGED_PORTS}" ] && \
            [ "${managed}" != "${EXPECTED_MANAGED_PORTS}" ]; then
            die "managed_ports=${managed} expected=${EXPECTED_MANAGED_PORTS}"
        fi
    fi
    [ "${managed}" = "${baseline_managed}" ] || \
        die "managed_ports drifted from ${baseline_managed} to ${managed}"
    assert_logs_clean

    agent_rss="$(proc_metric "${BASE_AGENT_PID}" VmRSS)"
    datapath_rss="$(proc_metric "${BASE_DATAPATH_PID}" VmRSS)"
    agent_fds="$(fd_count "${BASE_AGENT_PID}" | tr -d ' ')"
    datapath_fds="$(fd_count "${BASE_DATAPATH_PID}" | tr -d ' ')"
    agent_threads="$(proc_metric "${BASE_AGENT_PID}" Threads)"
    datapath_threads="$(proc_metric "${BASE_DATAPATH_PID}" Threads)"
    IFS=$'\t' read -r wal_bytes wal_files < <(wal_metrics)
    pin_files="$(tree_file_count "${PIN_ROOT}" | tr -d ' ')"
    ct_v4="$(map_entry_count "${PIN_ROOT}/CT_TABLE_V4")"
    ct_v6="$(map_entry_count "${PIN_ROOT}/CT_TABLE_V6")"
    iface_entries="$(map_entry_count "${PIN_ROOT}/IFACE_CTX_MAP")"
    timestamp="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        "${timestamp}" "${sample}" "${managed}" "${generation}" "${accepted}" \
        "${applied}" "${pending}" "${readiness}" "${agent_rss}" "${datapath_rss}" \
        "${agent_fds}" "${datapath_fds}" "${agent_threads}" "${datapath_threads}" \
        "${wal_bytes}" "${wal_files}" \
        "${pin_files}" "${ct_v4}" "${ct_v6}" "${iface_entries}" \
        >>"${WORK_DIR}/metrics.tsv"
    log "sample=${sample} managed_ports=${managed} generation=${generation} rss_kb=${agent_rss}/${datapath_rss} fds=${agent_fds}/${datapath_fds} threads=${agent_threads}/${datapath_threads} wal_bytes=${wal_bytes} pin_files=${pin_files} ct_entries=${ct_v4}/${ct_v6} iface_entries=${iface_entries}"
    sleep "${SAMPLE_INTERVAL}"
done

assert_runtime_identity
assert_logs_clean
check_growth_thresholds | tee "${WORK_DIR}/trend-summary.txt"
log "runtime_stability_soak=pass work=${WORK_DIR}"
