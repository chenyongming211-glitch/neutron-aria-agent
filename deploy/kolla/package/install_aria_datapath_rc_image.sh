#!/usr/bin/env bash
set -euo pipefail

SERVICE_NAME="${SERVICE_NAME:-aria_datapath}"
AGENT_SERVICE="${AGENT_SERVICE:-neutron_aria_agent}"
OVS_AGENT_SERVICE="${OVS_AGENT_SERVICE:-neutron_openvswitch_agent}"
IMAGE_REF="${IMAGE_REF:-}"
IMAGE_TAR="${IMAGE_TAR:-}"
EXPECTED_IMAGE_ID="${EXPECTED_IMAGE_ID:-}"
EXPECTED_ARIA_SHA256="${EXPECTED_ARIA_SHA256:-}"
EXPECTED_EBPF_SHA256="${EXPECTED_EBPF_SHA256:-}"
EXPECTED_EBPF_PERF_SHA256="${EXPECTED_EBPF_PERF_SHA256:-}"
STATE_DIR="${STATE_DIR:-/var/lib/aria-datapath-release}"
STATE_FILE="${STATE_FILE:-${STATE_DIR}/active.env}"
PENDING_STATE_FILE="${PENDING_STATE_FILE:-${STATE_FILE}.pending}"
READY_TIMEOUT="${READY_TIMEOUT:-120}"
SOCKET_PATH="${SOCKET_PATH:-/run/aria/aria-agent.sock}"
HEALTH_URL="${HEALTH_URL:-http://127.0.0.1:8080/api/v1/health}"
DATAPATH_STATE_SOURCE="${DATAPATH_STATE_SOURCE:-}"
BACKUP_DATAPATH_STATE_SOURCE="${BACKUP_DATAPATH_STATE_SOURCE:-}"
CANDIDATE_DATAPATH_STATE_SOURCE="${CANDIDATE_DATAPATH_STATE_SOURCE:-}"
MANAGED_PIN_PATH="${MANAGED_PIN_PATH:-}"
PIN_BACKUP_PATH="${PIN_BACKUP_PATH:-}"
PIN_BACKUP_PRESENT="${PIN_BACKUP_PRESENT:-false}"
PERSISTENT_RUNTIME_PREPARED="${PERSISTENT_RUNTIME_PREPARED:-false}"
CANDIDATE_PIN_QUARANTINE="${CANDIDATE_PIN_QUARANTINE:-}"
AGENT_RUNTIME_USER="${AGENT_RUNTIME_USER:-neutron}"
DETACH_ATTEMPTS="${DETACH_ATTEMPTS:-30}"
DETACH_INTERVAL="${DETACH_INTERVAL:-1.0}"
FORCE_RUNTIME_MIGRATION="${FORCE_RUNTIME_MIGRATION:-false}"
JOINT_MAINTENANCE_MODE="${JOINT_MAINTENANCE_MODE:-false}"
OPERATION_ID="${OPERATION_ID:-}"

usage() {
    cat <<'EOF'
Usage: install_aria_datapath_rc_image.sh install|check|rollback

install requires IMAGE_REF, EXPECTED_IMAGE_ID, EXPECTED_ARIA_SHA256,
EXPECTED_EBPF_SHA256, and EXPECTED_EBPF_PERF_SHA256. IMAGE_TAR is optional.
The installer validates all identities before replacing aria_datapath, keeps
the previous container stopped as the rollback point, and automatically
quiesces/detaches/rebuilds managed ports when the eBPF hash changes. It never
restarts OVS or the Neutron OVS agent.

check validates the active container against the recorded install state.
rollback restores the recorded previous container and retires the RC state.
EOF
}

log() {
    printf '[aria-datapath-rc] %s\n' "$*"
}

die() {
    echo "ERROR: $*" >&2
    exit 1
}

require_root() {
    [ "$(id -u)" = "0" ] || die "must run as root on the Kolla host"
}

require_command() {
    command -v "$1" >/dev/null 2>&1 || die "missing command: $1"
}

validate_name() {
    case "$1" in
        ''|*[!A-Za-z0-9_.-]*) die "invalid container name: $1" ;;
    esac
}

validate_image_ref() {
    case "$1" in
        ''|*[!A-Za-z0-9_./:@-]*) die "invalid IMAGE_REF" ;;
    esac
}

validate_sha256() {
    local value="$1" label="$2"
    case "${value}" in
        sha256:[0-9a-f][0-9a-f]*) value="${value#sha256:}" ;;
    esac
    [ "${#value}" -eq 64 ] || die "${label} must be a SHA-256 value"
    case "${value}" in
        *[!0-9a-f]*) die "${label} must be lowercase hex" ;;
    esac
}

validate_image_id() {
    case "$1" in
        sha256:*) validate_sha256 "${1#sha256:}" "$2" ;;
        *) die "$2 must use sha256:<lowercase-hex>" ;;
    esac
}

container_exists() {
    docker container inspect "$1" >/dev/null 2>&1
}

container_running() {
    [ "$(docker inspect -f '{{.State.Running}}' "$1" 2>/dev/null || true)" = "true" ]
}

candidate_image_has_healthcheck() {
    [ -n "$(docker image inspect -f '{{if .Config.Healthcheck}}{{json .Config.Healthcheck.Test}}{{end}}' "$1" 2>/dev/null || true)" ]
}

container_health_status() {
    docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}missing{{end}}' \
        "$1" 2>/dev/null || true
}

wait_container_healthy() {
    local status
    for _ in $(seq 1 "${READY_TIMEOUT}"); do
        status="$(container_health_status "${SERVICE_NAME}")"
        [ "${status}" = "healthy" ] && return 0
        sleep 1
    done
    docker inspect -f '{{json .State.Health}}' "${SERVICE_NAME}" >&2 || true
    return 1
}

image_file_hash() {
    docker run --rm --entrypoint sha256sum "${IMAGE_REF}" "$1" | awk '{print $1}'
}

container_file_hash() {
    local container="${2:-${SERVICE_NAME}}"
    docker exec "${container}" sha256sum "$1" | awk '{print $1}'
}

image_ref_file_hash() {
    local image="$1" path="$2"
    docker run --rm --entrypoint sha256sum "${image}" "${path}" | awk '{print $1}'
}

record_ovs_identity() {
    OVS_PID_BASELINE="$(pgrep -xo ovs-vswitchd)"
    OVS_AGENT_ID_BASELINE="$(docker inspect -f '{{.Id}}' "${OVS_AGENT_SERVICE}")"
    OVS_AGENT_STARTED_BASELINE="$(docker inspect -f '{{.State.StartedAt}}' "${OVS_AGENT_SERVICE}")"
}

check_ovs_identity() {
    [ "$(pgrep -xo ovs-vswitchd)" = "${OVS_PID_BASELINE}" ] ||
        { log "ovs-vswitchd identity changed during Aria lifecycle operation"; return 1; }
    [ "$(docker inspect -f '{{.Id}}' "${OVS_AGENT_SERVICE}")" = "${OVS_AGENT_ID_BASELINE}" ] ||
        { log "Neutron OVS agent container identity changed"; return 1; }
    [ "$(docker inspect -f '{{.State.StartedAt}}' "${OVS_AGENT_SERVICE}")" = "${OVS_AGENT_STARTED_BASELINE}" ] ||
        { log "Neutron OVS agent start time changed"; return 1; }
}

wait_ready() {
    for _ in $(seq 1 "${READY_TIMEOUT}"); do
        if container_running "${SERVICE_NAME}" &&
            curl -fsS "${HEALTH_URL}" >/dev/null 2>&1 &&
            docker exec -u "${AGENT_RUNTIME_USER}" "${AGENT_SERVICE}" curl -fsS \
                --unix-socket "${SOCKET_PATH}" http://localhost/readyz 2>/dev/null |
                grep -q '"overall_readiness":"ready"'; then
            return 0
        fi
        sleep 1
    done
    log "aria-datapath did not reach overall_readiness=ready"
    return 1
}

wait_agent_healthy() {
    local status
    for _ in $(seq 1 "${READY_TIMEOUT}"); do
        status="$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}missing{{end}}' \
            "${AGENT_SERVICE}" 2>/dev/null || true)"
        [ "${status}" = "healthy" ] && return 0
        sleep 1
    done
    docker inspect -f '{{json .State.Health}}' "${AGENT_SERVICE}" >&2 || true
    return 1
}

verify_generation_convergence() {
    docker exec -u "${AGENT_RUNTIME_USER}" "${AGENT_SERVICE}" \
        python - "${SOCKET_PATH}" <<'PY'
from __future__ import print_function

import sys

from neutron_aria.agent.uds_client import LocalClient

client = LocalClient(sys.argv[1], timeout=3.0)
client.capabilities(required_domains=["acl"])
status = client.status()
accepted = int(status.get("accepted_generation") or 0)
applied = int(status.get("applied_generation") or 0)
pending = status.get("pending_generation")
if pending not in (None, "", 0):
    raise SystemExit("pending_generation=%s" % pending)
if accepted != applied:
    raise SystemExit(
        "accepted_generation=%s applied_generation=%s" % (accepted, applied)
    )
if status.get("overall_readiness") != "ready":
    raise SystemExit("overall_readiness=%s" % status.get("overall_readiness"))
print("generation_converged=%s" % applied)
PY
}

verify_expected_files_in_image() {
    local actual
    actual="$(image_file_hash /usr/local/bin/aria-agent)"
    [ "${actual}" = "${EXPECTED_ARIA_SHA256}" ] || die "aria-agent image hash mismatch"
    actual="$(image_file_hash /usr/local/lib/libebpf_firewall.so)"
    [ "${actual}" = "${EXPECTED_EBPF_SHA256}" ] || die "eBPF image hash mismatch"
    actual="$(image_file_hash /usr/local/lib/libebpf_firewall_perf.so)"
    [ "${actual}" = "${EXPECTED_EBPF_PERF_SHA256}" ] || die "eBPF perf image hash mismatch"
}

verify_running_candidate() {
    local actual_image_id actual
    candidate_image_has_healthcheck "${IMAGE_REF}" ||
        die "candidate image does not declare a Docker healthcheck"
    container_running "${SERVICE_NAME}" || die "${SERVICE_NAME} is not running"
    actual_image_id="$(docker inspect -f '{{.Image}}' "${SERVICE_NAME}")"
    [ "${actual_image_id}" = "${EXPECTED_IMAGE_ID}" ] || die "running image ID mismatch"
    actual="$(container_file_hash /usr/local/bin/aria-agent)"
    [ "${actual}" = "${EXPECTED_ARIA_SHA256}" ] || die "running aria-agent hash mismatch"
    actual="$(container_file_hash /usr/local/lib/libebpf_firewall.so)"
    [ "${actual}" = "${EXPECTED_EBPF_SHA256}" ] || die "running eBPF hash mismatch"
    actual="$(container_file_hash /usr/local/lib/libebpf_firewall_perf.so)"
    [ "${actual}" = "${EXPECTED_EBPF_PERF_SHA256}" ] || die "running eBPF perf hash mismatch"
    wait_ready || die "aria-datapath did not reach overall_readiness=ready"
    verify_generation_convergence || die "Neutron generation did not converge"
    wait_container_healthy || die "aria-datapath Docker health did not become healthy"
    wait_agent_healthy || die "neutron-aria-agent Docker health did not become healthy"
    check_ovs_identity || die "OVS identity changed during candidate verification"
}

verify_backup_available() {
    local actual_image_id
    container_exists "${BACKUP_CONTAINER}" || die "rollback container is missing"
    actual_image_id="$(docker inspect -f '{{.Image}}' "${BACKUP_CONTAINER}")"
    [ "${actual_image_id}" = "${BACKUP_IMAGE_ID}" ] ||
        die "rollback container image ID mismatch"
}

write_state() {
    local path="$1" tmp="${1}.tmp.$$"
    umask 077
    mkdir -p "${STATE_DIR}"
    chmod 0700 "${STATE_DIR}"
    cat >"${tmp}" <<EOF
IMAGE_REF=${IMAGE_REF}
EXPECTED_IMAGE_ID=${EXPECTED_IMAGE_ID}
EXPECTED_ARIA_SHA256=${EXPECTED_ARIA_SHA256}
EXPECTED_EBPF_SHA256=${EXPECTED_EBPF_SHA256}
EXPECTED_EBPF_PERF_SHA256=${EXPECTED_EBPF_PERF_SHA256}
BACKUP_CONTAINER=${BACKUP_CONTAINER}
BACKUP_IMAGE_ID=${BACKUP_IMAGE_ID}
BACKUP_EBPF_SHA256=${BACKUP_EBPF_SHA256}
RUNTIME_MIGRATION_REQUIRED=${RUNTIME_MIGRATION_REQUIRED}
LIFECYCLE_PHASE=${LIFECYCLE_PHASE}
AGENT_IMAGE_ID=${AGENT_IMAGE_ID}
AGENT_UID=${AGENT_UID}
AGENT_GID=${AGENT_GID}
PRE_MANAGED_PORT_IDS=${PRE_MANAGED_PORT_IDS}
DATAPATH_STATE_SOURCE=${DATAPATH_STATE_SOURCE}
BACKUP_DATAPATH_STATE_SOURCE=${BACKUP_DATAPATH_STATE_SOURCE}
CANDIDATE_DATAPATH_STATE_SOURCE=${CANDIDATE_DATAPATH_STATE_SOURCE}
MANAGED_PIN_PATH=${MANAGED_PIN_PATH}
PIN_BACKUP_PATH=${PIN_BACKUP_PATH}
PIN_BACKUP_PRESENT=${PIN_BACKUP_PRESENT}
PERSISTENT_RUNTIME_PREPARED=${PERSISTENT_RUNTIME_PREPARED}
CANDIDATE_PIN_QUARANTINE=${CANDIDATE_PIN_QUARANTINE}
OVS_PID_BASELINE=${OVS_PID_BASELINE}
OVS_AGENT_ID_BASELINE=${OVS_AGENT_ID_BASELINE}
OVS_AGENT_STARTED_BASELINE=${OVS_AGENT_STARTED_BASELINE}
EOF
    chmod 0600 "${tmp}"
    mv "${tmp}" "${path}"
}

write_pending_phase() {
    LIFECYCLE_PHASE="$1"
    write_state "${PENDING_STATE_FILE}"
}

read_state_path() {
    local path="$1"
    [ -f "${path}" ] || die "release state not found: ${path}"
    [ "$(stat -c '%u' "${path}")" = "0" ] || die "release state must be root-owned"
    [ "$(stat -c '%a' "${path}")" = "600" ] || die "release state must have mode 0600"
    # The file is generated by this script from validated tokens and mode 0600.
    # shellcheck disable=SC1090
    . "${path}"
    BACKUP_EBPF_SHA256="${BACKUP_EBPF_SHA256:-}"
    RUNTIME_MIGRATION_REQUIRED="${RUNTIME_MIGRATION_REQUIRED:-false}"
    LIFECYCLE_PHASE="${LIFECYCLE_PHASE:-committed}"
    AGENT_IMAGE_ID="${AGENT_IMAGE_ID:-}"
    AGENT_UID="${AGENT_UID:-}"
    AGENT_GID="${AGENT_GID:-}"
    PRE_MANAGED_PORT_IDS="${PRE_MANAGED_PORT_IDS:-}"
    DATAPATH_STATE_SOURCE="${DATAPATH_STATE_SOURCE:-}"
    BACKUP_DATAPATH_STATE_SOURCE="${BACKUP_DATAPATH_STATE_SOURCE:-}"
    CANDIDATE_DATAPATH_STATE_SOURCE="${CANDIDATE_DATAPATH_STATE_SOURCE:-}"
    MANAGED_PIN_PATH="${MANAGED_PIN_PATH:-}"
    PIN_BACKUP_PATH="${PIN_BACKUP_PATH:-}"
    PIN_BACKUP_PRESENT="${PIN_BACKUP_PRESENT:-false}"
    PERSISTENT_RUNTIME_PREPARED="${PERSISTENT_RUNTIME_PREPARED:-false}"
    CANDIDATE_PIN_QUARANTINE="${CANDIDATE_PIN_QUARANTINE:-}"
    validate_name "${BACKUP_CONTAINER}"
    validate_image_ref "${IMAGE_REF}"
    validate_image_id "${EXPECTED_IMAGE_ID}" EXPECTED_IMAGE_ID
    validate_image_id "${BACKUP_IMAGE_ID}" BACKUP_IMAGE_ID
    validate_sha256 "${EXPECTED_ARIA_SHA256}" EXPECTED_ARIA_SHA256
    validate_sha256 "${EXPECTED_EBPF_SHA256}" EXPECTED_EBPF_SHA256
    validate_sha256 "${EXPECTED_EBPF_PERF_SHA256}" EXPECTED_EBPF_PERF_SHA256
    if [ -n "${BACKUP_EBPF_SHA256}" ]; then
        validate_sha256 "${BACKUP_EBPF_SHA256}" BACKUP_EBPF_SHA256
    fi
    case "${RUNTIME_MIGRATION_REQUIRED}" in
        true|false) ;;
        *) die "invalid RUNTIME_MIGRATION_REQUIRED" ;;
    esac
    case "${LIFECYCLE_PHASE}" in
        preflight|writer_stopped|runtime_detached|runtime_preserved|persistent_restored|backup_created|candidate_started|writer_resumed|committed) ;;
        *) die "invalid LIFECYCLE_PHASE" ;;
    esac
    case "${PRE_MANAGED_PORT_IDS}" in
        *[!A-Za-z0-9,_.:-]*) die "invalid PRE_MANAGED_PORT_IDS" ;;
    esac
    case "${PIN_BACKUP_PRESENT}" in
        true|false) ;;
        *) die "invalid PIN_BACKUP_PRESENT" ;;
    esac
    case "${PERSISTENT_RUNTIME_PREPARED}" in
        true|false) ;;
        *) die "invalid PERSISTENT_RUNTIME_PREPARED" ;;
    esac
    validate_runtime_paths
}

read_state() {
    read_state_path "${STATE_FILE}"
}

runtime_migration_required() {
    local active_hash="$1" candidate_hash="$2" force="${3:-false}"
    [ "${force}" = "true" ] || [ "${active_hash}" != "${candidate_hash}" ]
}

validate_runtime_paths() {
    local path
    for path in \
        "${DATAPATH_STATE_SOURCE:-}" \
        "${BACKUP_DATAPATH_STATE_SOURCE:-}" \
        "${CANDIDATE_DATAPATH_STATE_SOURCE:-}"; do
        [ -z "${path}" ] && continue
        case "${path}" in
            /*) ;;
            *) die "datapath state path must be absolute: ${path}" ;;
        esac
        case "${path}" in
            /|*/../*|*/..|*[!A-Za-z0-9_./:-]*) die "unsafe datapath state path: ${path}" ;;
        esac
    done
    for path in \
        "${MANAGED_PIN_PATH:-}" \
        "${PIN_BACKUP_PATH:-}" \
        "${CANDIDATE_PIN_QUARANTINE:-}"; do
        [ -z "${path}" ] && continue
        case "${path}" in
            /sys/fs/bpf/*) ;;
            *) die "managed pin path must remain below /sys/fs/bpf: ${path}" ;;
        esac
        case "${path}" in
            *[!A-Za-z0-9_./:-]*) die "unsafe managed pin path: ${path}" ;;
        esac
    done
    if [ -n "${MANAGED_PIN_PATH:-}" ]; then
        case "${MANAGED_PIN_PATH}" in
            */shared) ;;
            *) die "managed pin path must identify the Aria shared namespace" ;;
        esac
    fi
}

discover_managed_pin_path() {
    local pin_root
    pin_root="$(docker exec "${SERVICE_NAME}" sh -c \
        'awk -F= '\''/^[[:space:]]*pin_path[[:space:]]*=/ { value=$2; gsub(/[[:space:]\"]/, "", value); print value; exit }'\'' /etc/aria-agent/config.toml')"
    [ -n "${pin_root}" ] || die "cannot discover pin_path from active datapath config"
    MANAGED_PIN_PATH="${pin_root%/}/shared"
    validate_runtime_paths
}

preserve_persistent_runtime() {
    [ "${RUNTIME_MIGRATION_REQUIRED:-false}" = "true" ] || return 0
    [ -d "${BACKUP_DATAPATH_STATE_SOURCE}" ] ||
        die "backup datapath state source is unavailable"
    [ ! -e "${CANDIDATE_DATAPATH_STATE_SOURCE}" ] ||
        die "candidate datapath state path already exists"
    cp -a -- "${BACKUP_DATAPATH_STATE_SOURCE}" "${CANDIDATE_DATAPATH_STATE_SOURCE}"
    DATAPATH_STATE_SOURCE="${CANDIDATE_DATAPATH_STATE_SOURCE}"
    if [ -e "${MANAGED_PIN_PATH}" ]; then
        [ -d "${MANAGED_PIN_PATH}" ] || die "managed pin path is not a directory"
        [ ! -e "${PIN_BACKUP_PATH}" ] || die "managed pin backup already exists"
        mv "${MANAGED_PIN_PATH}" "${PIN_BACKUP_PATH}"
        PIN_BACKUP_PRESENT=true
    fi
    PERSISTENT_RUNTIME_PREPARED=true
    lifecycle_checkpoint runtime_preserved
}

restore_persistent_runtime() {
    [ "${RUNTIME_MIGRATION_REQUIRED:-false}" = "true" ] || return 0
    if [ "${LIFECYCLE_PHASE:-}" = "persistent_restored" ]; then
        return 0
    fi
    if container_running "${SERVICE_NAME}"; then
        docker stop "${SERVICE_NAME}" >/dev/null || return 1
    fi
    if [ "${PERSISTENT_RUNTIME_PREPARED}" = "true" ]; then
        if [ -e "${MANAGED_PIN_PATH}" ] && [ ! -e "${CANDIDATE_PIN_QUARANTINE}" ]; then
            [ -d "${MANAGED_PIN_PATH}" ] || return 1
            mv "${MANAGED_PIN_PATH}" "${CANDIDATE_PIN_QUARANTINE}" || return 1
        fi
        if [ -e "${PIN_BACKUP_PATH}" ]; then
            [ ! -e "${MANAGED_PIN_PATH}" ] || return 1
            mv "${PIN_BACKUP_PATH}" "${MANAGED_PIN_PATH}" || return 1
            PIN_BACKUP_PRESENT=false
        elif [ "${PIN_BACKUP_PRESENT}" = "true" ]; then
            if [ -e "${MANAGED_PIN_PATH}" ] && [ -e "${CANDIDATE_PIN_QUARANTINE}" ]; then
                PIN_BACKUP_PRESENT=false
            else
                log "recorded old managed pin backup is missing"
                return 1
            fi
        fi
    elif [ -e "${PIN_BACKUP_PATH}" ]; then
        [ ! -e "${MANAGED_PIN_PATH}" ] || return 1
        mv "${PIN_BACKUP_PATH}" "${MANAGED_PIN_PATH}" || return 1
        PIN_BACKUP_PRESENT=false
    fi
    PERSISTENT_RUNTIME_PREPARED=false
    DATAPATH_STATE_SOURCE="${BACKUP_DATAPATH_STATE_SOURCE}"
    lifecycle_checkpoint persistent_restored
}

cleanup_failed_candidate_persistence() {
    if [ -n "${CANDIDATE_PIN_QUARANTINE:-}" ] && \
        [ -d "${CANDIDATE_PIN_QUARANTINE}" ]; then
        rm -rf -- "${CANDIDATE_PIN_QUARANTINE}"
    fi
    if [ -n "${CANDIDATE_DATAPATH_STATE_SOURCE:-}" ] && \
        [ "${CANDIDATE_DATAPATH_STATE_SOURCE}" != "${DATAPATH_STATE_SOURCE}" ] && \
        [ -d "${CANDIDATE_DATAPATH_STATE_SOURCE}" ]; then
        rm -rf -- "${CANDIDATE_DATAPATH_STATE_SOURCE}"
    fi
}

capture_agent_identity() {
    AGENT_IMAGE_ID="$(docker inspect -f '{{.Image}}' "${AGENT_SERVICE}")"
    AGENT_UID="$(docker exec "${AGENT_SERVICE}" id -u "${AGENT_RUNTIME_USER}")"
    AGENT_GID="$(docker exec "${AGENT_SERVICE}" id -g "${AGENT_RUNTIME_USER}")"
    validate_image_id "${AGENT_IMAGE_ID}" AGENT_IMAGE_ID
    if [ -z "${AGENT_UID}" ] || [ -z "${AGENT_GID}" ]; then
        die "missing neutron-aria-agent UID/GID"
    fi
    case "${AGENT_UID}${AGENT_GID}" in
        *[!0-9]*) die "invalid neutron-aria-agent UID/GID" ;;
    esac
}

ensure_agent_identity() {
    if [ -z "${AGENT_IMAGE_ID:-}" ] || [ -z "${AGENT_UID:-}" ] || [ -z "${AGENT_GID:-}" ]; then
        container_running "${AGENT_SERVICE}" ||
            die "cannot recover missing agent identity while the writer is stopped"
        capture_agent_identity
    fi
    validate_image_id "${AGENT_IMAGE_ID}" AGENT_IMAGE_ID
    if [ -z "${AGENT_UID}" ] || [ -z "${AGENT_GID}" ]; then
        die "missing recorded neutron-aria-agent UID/GID"
    fi
    case "${AGENT_UID}${AGENT_GID}" in
        *[!0-9]*) die "invalid recorded neutron-aria-agent UID/GID" ;;
    esac
}

capture_managed_port_ids() {
    PRE_MANAGED_PORT_IDS="$(
        docker exec -u "${AGENT_RUNTIME_USER}" "${AGENT_SERVICE}" \
            python - "${SOCKET_PATH}" <<'PY'
from __future__ import print_function

import sys

from neutron_aria.agent.uds_client import LocalClient

client = LocalClient(sys.argv[1], timeout=3.0)
client.capabilities(required_domains=["acl"])
status = client.status()
print(",".join(sorted(set(
    row.get("port_id")
    for row in (status.get("managed_ports") or [])
    if row.get("port_id")
))))
PY
    )"
    case "${PRE_MANAGED_PORT_IDS}" in
        *[!A-Za-z0-9,_.:-]*) die "invalid managed-port identity from status" ;;
    esac
}

stop_agent_writer() {
    if container_running "${AGENT_SERVICE}"; then
        docker stop "${AGENT_SERVICE}" >/dev/null
    fi
    ! container_running "${AGENT_SERVICE}"
}

start_agent_writer() {
    if ! container_running "${AGENT_SERVICE}"; then
        docker start "${AGENT_SERVICE}" >/dev/null
    fi
    container_running "${AGENT_SERVICE}"
}

uds_socket_available() {
    [ -S "${SOCKET_PATH}" ]
}

detach_all_managed_ports() {
    local socket_dir
    socket_dir="$(dirname "${SOCKET_PATH}")"
    [ -n "${AGENT_IMAGE_ID:-}" ] || die "missing agent image identity for detach"
    [ -n "${AGENT_UID:-}" ] || die "missing agent UID for detach"
    [ -n "${AGENT_GID:-}" ] || die "missing agent GID for detach"
    uds_socket_available || die "Neutron UDS socket is unavailable for detach"

    docker run --rm \
        --network none \
        --security-opt label=disable \
        --user "${AGENT_UID}:${AGENT_GID}" \
        --entrypoint python \
        -v "${socket_dir}:${socket_dir}:rw" \
        "${AGENT_IMAGE_ID}" - \
        "${SOCKET_PATH}" "${DETACH_ATTEMPTS}" "${DETACH_INTERVAL}" <<'PY'
from __future__ import print_function

import sys
import time

from neutron_aria.agent.uds_client import LocalClient

socket_path = sys.argv[1]
attempts = int(sys.argv[2])
interval = float(sys.argv[3])
client = LocalClient(socket_path, timeout=3.0)
client.capabilities(required_domains=["acl"])
status = client.status()
port_ids = sorted(set(
    row.get("port_id")
    for row in (status.get("managed_ports") or [])
    if row.get("port_id")
))
print("pre_detach_managed_ports=%s" % len(port_ids))
for port_id in port_ids:
    last_error = None
    for attempt in range(1, attempts + 1):
        remaining = set(
            row.get("port_id")
            for row in (client.status().get("managed_ports") or [])
            if row.get("port_id")
        )
        if port_id not in remaining:
            print("detached_port=%s attempt=%s status=already_absent" % (
                port_id, attempt
            ))
            break
        try:
            response = client.delete_port(port_id)
        except Exception as exc:
            last_error = exc
            response = {}
        remaining = set(
            row.get("port_id")
            for row in (client.status().get("managed_ports") or [])
            if row.get("port_id")
        )
        if port_id not in remaining:
            print(
                "detached_port=%s attempt=%s status=%s" % (
                    port_id, attempt, response.get("status") or "absent"
                )
            )
            break
        if attempt < attempts:
            time.sleep(interval)
    else:
        raise SystemExit(
            "detach did not converge for %s: %s" % (port_id, last_error)
        )
remaining = sorted(
    row.get("port_id")
    for row in (client.status().get("managed_ports") or [])
    if row.get("port_id")
)
print("post_detach_managed_ports=%s" % len(remaining))
if remaining:
    raise SystemExit("managed ports remain after detach: %s" % ",".join(remaining))
PY
}

create_candidate_container() {
    docker create \
        --name "${SERVICE_NAME}" \
        --hostname "$(hostname -f 2>/dev/null || hostname)" \
        --restart unless-stopped \
        --privileged \
        --network host \
        --pid host \
        --security-opt label=disable \
        --log-driver json-file \
        --log-opt max-file=30 \
        --log-opt max-size=10m \
        -e KOLLA_CONFIG_STRATEGY=COPY_ALWAYS \
        -e KOLLA_SERVICE_NAME=aria-datapath \
        -e container=docker \
        -v "${DATAPATH_STATE_SOURCE}:/var/lib/aria-agent:rw" \
        -v /sys/kernel/btf/vmlinux:/sys/kernel/btf/vmlinux:ro \
        -v /etc/kolla/aria-datapath/:/var/lib/kolla/config_files/:ro \
        -v /etc/localtime:/etc/localtime:ro \
        -v kolla_logs:/var/log/kolla/:rw \
        -v /run/aria:/run/aria:rw \
        -v /run/openvswitch:/run/openvswitch:shared \
        -v /sys/fs/bpf:/sys/fs/bpf:shared \
        "${IMAGE_REF}" kolla_start >/dev/null
}

restore_backup_container() {
    local failed=0
    if container_exists "${SERVICE_NAME}"; then
        docker rm -f "${SERVICE_NAME}" >/dev/null 2>&1 || failed=1
    fi
    if ! container_exists "${BACKUP_CONTAINER}"; then
        log "Rollback container is missing: ${BACKUP_CONTAINER}"
        return 1
    fi
    if [ "${failed}" -eq 0 ]; then
        docker rename "${BACKUP_CONTAINER}" "${SERVICE_NAME}" >/dev/null 2>&1 || failed=1
    fi
    if [ "${failed}" -eq 0 ]; then
        docker start "${SERVICE_NAME}" >/dev/null 2>&1 || failed=1
    fi
    if [ "${failed}" -eq 0 ] && ! container_running "${SERVICE_NAME}"; then
        failed=1
    fi
    return "${failed}"
}

restore_stopped_original() {
    if container_exists "${SERVICE_NAME}"; then
        if ! container_running "${SERVICE_NAME}"; then
            docker start "${SERVICE_NAME}" >/dev/null 2>&1 || return 1
        fi
        container_running "${SERVICE_NAME}" || return 1
    fi
}

lifecycle_checkpoint() {
    if [ "${LIFECYCLE_TRACKING_ENABLED:-false}" = "true" ]; then
        write_pending_phase "$1"
    fi
}

switch_to_candidate() {
    docker stop "${SERVICE_NAME}" >/dev/null
    preserve_persistent_runtime
    docker rename "${SERVICE_NAME}" "${BACKUP_CONTAINER}"
    lifecycle_checkpoint backup_created
    [ ! -S "${SOCKET_PATH}" ] || rm -f "${SOCKET_PATH}"
    create_candidate_container
    docker start "${SERVICE_NAME}" >/dev/null
    lifecycle_checkpoint candidate_started
}

verify_candidate_convergence() {
    if [ "${JOINT_MAINTENANCE_MODE}" = "true" ]; then
        curl -fsS "${HEALTH_URL%/api/v1/health}/livez" >/dev/null || return 1
        docker exec -u "${AGENT_RUNTIME_USER}" "${AGENT_SERVICE}" curl -fsS \
            --unix-socket /run/aria/aria-admin.sock \
            http://localhost/api/v1/admin/maintenance | \
            grep -q "\"operation_id\":\"${OPERATION_ID}\""
        return $?
    fi
    verify_running_candidate
}

verify_rollback_convergence() {
    local restored_image_id
    restored_image_id="$(docker inspect -f '{{.Image}}' "${SERVICE_NAME}")"
    [ "${restored_image_id}" = "${BACKUP_IMAGE_ID}" ] || {
        log "rollback restored an unexpected image"
        return 1
    }
    if [ "${JOINT_MAINTENANCE_MODE}" = "true" ]; then
        verify_candidate_convergence || return 1
        return 0
    fi
    wait_ready || return 1
    verify_generation_convergence || return 1
    wait_agent_healthy || return 1
    check_ovs_identity
}

run_runtime_migration_sequence() {
    stop_agent_writer || return $?
    lifecycle_checkpoint writer_stopped
    detach_all_managed_ports || return $?
    lifecycle_checkpoint runtime_detached
    switch_to_candidate || return $?
    start_agent_writer || return $?
    lifecycle_checkpoint writer_resumed
    verify_candidate_convergence
}

run_hash_aware_rollback_sequence() {
    stop_agent_writer || return $?
    lifecycle_checkpoint writer_stopped
    detach_all_managed_ports || return $?
    lifecycle_checkpoint runtime_detached
    restore_persistent_runtime || return $?
    restore_backup_container || return $?
    start_agent_writer || return $?
    lifecycle_checkpoint writer_resumed
    verify_rollback_convergence
}

recover_failed_install() {
    local candidate_running=false
    stop_agent_writer || return 1
    if container_exists "${BACKUP_CONTAINER}"; then
        if container_running "${SERVICE_NAME}"; then
            candidate_running=true
        fi
        if [ "${candidate_running}" = "true" ]; then
            if ! uds_socket_available; then
                return 1
            fi
            detach_all_managed_ports || return 1
        elif container_exists "${SERVICE_NAME}" && \
            { [ "${LIFECYCLE_PHASE}" = "candidate_started" ] || \
              [ "${LIFECYCLE_PHASE}" = "writer_resumed" ]; }; then
            log "candidate previously started but UDS cleanup cannot be proven"
            return 1
        fi
    fi
    restore_persistent_runtime || return 1
    if container_exists "${BACKUP_CONTAINER}"; then
        restore_backup_container || return 1
    else
        restore_stopped_original || return 1
    fi
    start_agent_writer || return 1
    wait_ready && verify_generation_convergence && check_ovs_identity
    local rc=$?
    if [ "${rc}" -ne 0 ]; then
        stop_agent_writer || true
    else
        cleanup_failed_candidate_persistence
    fi
    return "${rc}"
}

install_candidate() {
    [ -n "${IMAGE_REF}" ] || die "IMAGE_REF is required"
    [ -n "${EXPECTED_IMAGE_ID}" ] || die "EXPECTED_IMAGE_ID is required"
    [ -n "${EXPECTED_ARIA_SHA256}" ] || die "EXPECTED_ARIA_SHA256 is required"
    [ -n "${EXPECTED_EBPF_SHA256}" ] || die "EXPECTED_EBPF_SHA256 is required"
    [ -n "${EXPECTED_EBPF_PERF_SHA256}" ] || die "EXPECTED_EBPF_PERF_SHA256 is required"
    validate_image_ref "${IMAGE_REF}"
    validate_image_id "${EXPECTED_IMAGE_ID}" EXPECTED_IMAGE_ID
    validate_sha256 "${EXPECTED_ARIA_SHA256}" EXPECTED_ARIA_SHA256
    validate_sha256 "${EXPECTED_EBPF_SHA256}" EXPECTED_EBPF_SHA256
    validate_sha256 "${EXPECTED_EBPF_PERF_SHA256}" EXPECTED_EBPF_PERF_SHA256
    [ ! -e "${STATE_FILE}" ] || die "active release state already exists; check or rollback first"
    [ ! -e "${PENDING_STATE_FILE}" ] || die "pending release state exists; rollback it before install"
    container_running "${SERVICE_NAME}" || die "${SERVICE_NAME} must be running before install"
    container_running "${AGENT_SERVICE}" || die "${AGENT_SERVICE} must be running before install"
    container_running "${OVS_AGENT_SERVICE}" || die "${OVS_AGENT_SERVICE} must be running before install"

    if [ -n "${IMAGE_TAR}" ]; then
        [ -f "${IMAGE_TAR}" ] || die "IMAGE_TAR is missing: ${IMAGE_TAR}"
        docker load -i "${IMAGE_TAR}" >/dev/null
    fi
    docker image inspect "${IMAGE_REF}" >/dev/null
    [ "$(docker image inspect -f '{{.Id}}' "${IMAGE_REF}")" = "${EXPECTED_IMAGE_ID}" ] ||
        die "loaded image ID mismatch"
    candidate_image_has_healthcheck "${IMAGE_REF}" ||
        die "candidate image does not declare a Docker healthcheck"
    verify_expected_files_in_image
    record_ovs_identity
    capture_agent_identity
    capture_managed_port_ids
    if [ -z "${DATAPATH_STATE_SOURCE}" ]; then
        DATAPATH_STATE_SOURCE="$(docker inspect -f '{{range .Mounts}}{{if eq .Destination "/var/lib/aria-agent"}}{{.Source}}{{end}}{{end}}' "${SERVICE_NAME}")"
    fi
    [ -n "${DATAPATH_STATE_SOURCE}" ] || die "current container has no /var/lib/aria-agent mount"
    [ -d "${DATAPATH_STATE_SOURCE}" ] || die "datapath state source is not a directory"
    discover_managed_pin_path

    RELEASE_STAMP="$(date +%Y%m%d%H%M%S)"
    BACKUP_DATAPATH_STATE_SOURCE="${DATAPATH_STATE_SOURCE}"
    CANDIDATE_DATAPATH_STATE_SOURCE="${DATAPATH_STATE_SOURCE}.aria_rc_${RELEASE_STAMP}"
    PIN_BACKUP_PATH="${MANAGED_PIN_PATH}.pre_rc_${RELEASE_STAMP}"
    CANDIDATE_PIN_QUARANTINE="${MANAGED_PIN_PATH}.failed_rc_${RELEASE_STAMP}"
    PIN_BACKUP_PRESENT=false
    PERSISTENT_RUNTIME_PREPARED=false
    validate_runtime_paths
    BACKUP_CONTAINER="${SERVICE_NAME}_pre_rc_${RELEASE_STAMP}"
    BACKUP_IMAGE_ID="$(docker inspect -f '{{.Image}}' "${SERVICE_NAME}")"
    BACKUP_EBPF_SHA256="$(container_file_hash /usr/local/lib/libebpf_firewall.so)"
    validate_name "${BACKUP_CONTAINER}"
    validate_image_id "${BACKUP_IMAGE_ID}" BACKUP_IMAGE_ID
    validate_sha256 "${BACKUP_EBPF_SHA256}" BACKUP_EBPF_SHA256
    container_exists "${BACKUP_CONTAINER}" && die "backup container already exists"
    case "${FORCE_RUNTIME_MIGRATION}" in
        true|false) ;;
        *) die "FORCE_RUNTIME_MIGRATION must be true or false" ;;
    esac
    if runtime_migration_required \
        "${BACKUP_EBPF_SHA256}" "${EXPECTED_EBPF_SHA256}" \
        "${FORCE_RUNTIME_MIGRATION}"; then
        RUNTIME_MIGRATION_REQUIRED=true
    else
        RUNTIME_MIGRATION_REQUIRED=false
    fi
    LIFECYCLE_PHASE=preflight
    LIFECYCLE_TRACKING_ENABLED=true
    write_state "${PENDING_STATE_FILE}"

    on_install_exit() {
        rc=$?
        recovery_ok=true
        if [ "${rc}" -ne 0 ]; then
            log "Install failed in phase ${LIFECYCLE_PHASE}; recovering previous runtime"
            if [ "${RUNTIME_MIGRATION_REQUIRED}" = "true" ]; then
                recover_failed_install || recovery_ok=false
            elif container_exists "${BACKUP_CONTAINER}"; then
                restore_backup_container || recovery_ok=false
            else
                restore_stopped_original || recovery_ok=false
            fi
        fi
        if [ "${recovery_ok}" = true ]; then
            rm -f "${PENDING_STATE_FILE}"
        else
            stop_agent_writer || true
            log "Automatic recovery failed; state retained at ${PENDING_STATE_FILE}"
            log "Python writer remains stopped; run rollback after correcting the recorded phase"
        fi
        exit "${rc}"
    }
    trap on_install_exit EXIT

    if [ "${RUNTIME_MIGRATION_REQUIRED}" = "true" ]; then
        log "eBPF runtime hash changed; using quiesce/detach/full-resync migration"
        run_runtime_migration_sequence
    else
        log "eBPF runtime hash unchanged; using fast container replacement"
        switch_to_candidate
        verify_candidate_convergence
    fi
    LIFECYCLE_PHASE=committed
    write_state "${PENDING_STATE_FILE}"
    mv "${PENDING_STATE_FILE}" "${STATE_FILE}"
    LIFECYCLE_TRACKING_ENABLED=false
    trap - EXIT
    log "Install passed; rollback container=${BACKUP_CONTAINER}"
}

check_candidate() {
    [ ! -f "${PENDING_STATE_FILE}" ] ||
        die "pending release state exists; recover or rollback before check"
    if [ -f "${STATE_FILE}" ]; then
        read_state
        verify_backup_available
    else
        [ -n "${IMAGE_REF}" ] || die "IMAGE_REF is required when no release state exists"
        [ -n "${EXPECTED_IMAGE_ID}" ] || die "EXPECTED_IMAGE_ID is required when no release state exists"
        [ -n "${EXPECTED_ARIA_SHA256}" ] || die "EXPECTED_ARIA_SHA256 is required when no release state exists"
        [ -n "${EXPECTED_EBPF_SHA256}" ] || die "EXPECTED_EBPF_SHA256 is required when no release state exists"
        [ -n "${EXPECTED_EBPF_PERF_SHA256}" ] || die "EXPECTED_EBPF_PERF_SHA256 is required when no release state exists"
        validate_image_ref "${IMAGE_REF}"
        validate_image_id "${EXPECTED_IMAGE_ID}" EXPECTED_IMAGE_ID
        validate_sha256 "${EXPECTED_ARIA_SHA256}" EXPECTED_ARIA_SHA256
        validate_sha256 "${EXPECTED_EBPF_SHA256}" EXPECTED_EBPF_SHA256
        validate_sha256 "${EXPECTED_EBPF_PERF_SHA256}" EXPECTED_EBPF_PERF_SHA256
    fi
    record_ovs_identity
    verify_running_candidate
    log "Candidate check passed: ${IMAGE_REF}"
}

rollback_candidate() {
    local source_state migration_required=false
    if [ -f "${PENDING_STATE_FILE}" ]; then
        source_state="${PENDING_STATE_FILE}"
    else
        source_state="${STATE_FILE}"
    fi
    read_state_path "${source_state}"
    record_ovs_identity
    ensure_agent_identity
    if ! container_exists "${BACKUP_CONTAINER}"; then
        if container_exists "${SERVICE_NAME}" && \
            [ "$(docker inspect -f '{{.Image}}' "${SERVICE_NAME}")" = "${BACKUP_IMAGE_ID}" ]; then
            start_agent_writer || die "failed to restart Python writer"
            wait_ready || die "original runtime did not recover"
            rm -f "${PENDING_STATE_FILE}"
            log "Interrupted pre-switch install rolled back; original runtime retained"
            return
        fi
        die "rollback container is missing"
    fi
    verify_backup_available
    if [ -z "${BACKUP_EBPF_SHA256}" ]; then
        BACKUP_EBPF_SHA256="$(image_ref_file_hash \
            "${BACKUP_IMAGE_ID}" /usr/local/lib/libebpf_firewall.so)"
    fi
    validate_sha256 "${BACKUP_EBPF_SHA256}" BACKUP_EBPF_SHA256
    if container_running "${SERVICE_NAME}"; then
        active_hash="$(container_file_hash /usr/local/lib/libebpf_firewall.so)"
    else
        active_hash="${EXPECTED_EBPF_SHA256}"
    fi
    if [ "${RUNTIME_MIGRATION_REQUIRED}" = "true" ] || \
        runtime_migration_required "${active_hash}" "${BACKUP_EBPF_SHA256}" false; then
        migration_required=true
    fi
    RUNTIME_MIGRATION_REQUIRED="${migration_required}"
    LIFECYCLE_TRACKING_ENABLED=true
    write_pending_phase preflight

    on_rollback_exit() {
        rc=$?
        if [ "${rc}" -ne 0 ] && [ "${migration_required}" = "true" ]; then
            stop_agent_writer || true
            log "Rollback failed; Python writer remains stopped and state is retained at ${PENDING_STATE_FILE}"
        fi
        exit "${rc}"
    }
    trap on_rollback_exit EXIT

    if [ "${migration_required}" = "true" ]; then
        log "Rollback crosses eBPF runtime hash; using detach/full-resync migration"
        run_hash_aware_rollback_sequence
        cleanup_failed_candidate_persistence
    else
        restore_backup_container
        wait_ready || die "restored datapath did not reach readiness"
        check_ovs_identity
    fi
    LIFECYCLE_TRACKING_ENABLED=false
    trap - EXIT
    if [ -f "${STATE_FILE}" ]; then
        mv "${STATE_FILE}" "${STATE_FILE}.rolled-back-$(date +%Y%m%d%H%M%S)"
    fi
    rm -f "${PENDING_STATE_FILE}"
    log "Rollback passed; restored ${BACKUP_CONTAINER} as ${SERVICE_NAME}"
}

main() {
    require_root
    for command in docker curl grep awk pgrep stat dirname mv cp rm flock; do
        require_command "${command}"
    done
    umask 077
    mkdir -p "${STATE_DIR}"
    chmod 0700 "${STATE_DIR}"
    exec 9>"${STATE_DIR}/lifecycle.lock"
    flock -n 9 || die "another Aria datapath lifecycle operation is active"
    validate_name "${SERVICE_NAME}"
    validate_name "${AGENT_SERVICE}"
    validate_name "${OVS_AGENT_SERVICE}"

    case "${1:-}" in
        prepare)
            [ -n "${IMAGE_REF}" ] || die "IMAGE_REF is required"
            [ -n "${EXPECTED_IMAGE_ID}" ] || die "EXPECTED_IMAGE_ID is required"
            docker image inspect "${IMAGE_REF}" >/dev/null
            [ "$(docker image inspect -f '{{.Id}}' "${IMAGE_REF}")" = "${EXPECTED_IMAGE_ID}" ] ||
                die "loaded image ID mismatch"
            ;;
        replace) install_candidate ;;
        verify) verify_candidate_convergence ;;
        restore) rollback_candidate ;;
        install) install_candidate ;;
        check) check_candidate ;;
        rollback) rollback_candidate ;;
        -h|--help) usage ;;
        *) usage; exit 2 ;;
    esac
}

if [ "${ARIA_INSTALLER_LIBRARY_ONLY:-false}" != "true" ]; then
    main "$@"
fi
