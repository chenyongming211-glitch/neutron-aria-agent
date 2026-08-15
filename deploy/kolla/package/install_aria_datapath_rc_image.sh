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
READY_TIMEOUT="${READY_TIMEOUT:-120}"
SOCKET_PATH="${SOCKET_PATH:-/run/aria/aria-agent.sock}"
HEALTH_URL="${HEALTH_URL:-http://127.0.0.1:8080/api/v1/health}"
DATAPATH_STATE_SOURCE="${DATAPATH_STATE_SOURCE:-}"

usage() {
    cat <<'EOF'
Usage: install_aria_datapath_rc_image.sh install|check|rollback

install requires IMAGE_REF, EXPECTED_IMAGE_ID, EXPECTED_ARIA_SHA256,
EXPECTED_EBPF_SHA256, and EXPECTED_EBPF_PERF_SHA256. IMAGE_TAR is optional.
The installer validates all identities before replacing aria_datapath, keeps
the previous container stopped as the rollback point, and never restarts OVS
or the Neutron OVS agent.

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

image_file_hash() {
    docker run --rm --entrypoint sha256sum "${IMAGE_REF}" "$1" | awk '{print $1}'
}

container_file_hash() {
    docker exec "${SERVICE_NAME}" sha256sum "$1" | awk '{print $1}'
}

record_ovs_identity() {
    OVS_PID_BASELINE="$(pgrep -xo ovs-vswitchd)"
    OVS_AGENT_ID_BASELINE="$(docker inspect -f '{{.Id}}' "${OVS_AGENT_SERVICE}")"
    OVS_AGENT_STARTED_BASELINE="$(docker inspect -f '{{.State.StartedAt}}' "${OVS_AGENT_SERVICE}")"
}

check_ovs_identity() {
    [ "$(pgrep -xo ovs-vswitchd)" = "${OVS_PID_BASELINE}" ] ||
        die "ovs-vswitchd identity changed during Aria lifecycle operation"
    [ "$(docker inspect -f '{{.Id}}' "${OVS_AGENT_SERVICE}")" = "${OVS_AGENT_ID_BASELINE}" ] ||
        die "Neutron OVS agent container identity changed"
    [ "$(docker inspect -f '{{.State.StartedAt}}' "${OVS_AGENT_SERVICE}")" = "${OVS_AGENT_STARTED_BASELINE}" ] ||
        die "Neutron OVS agent start time changed"
}

wait_ready() {
    for _ in $(seq 1 "${READY_TIMEOUT}"); do
        if container_running "${SERVICE_NAME}" &&
            curl -fsS "${HEALTH_URL}" >/dev/null 2>&1 &&
            docker exec -u neutron "${AGENT_SERVICE}" curl -fsS \
                --unix-socket "${SOCKET_PATH}" http://localhost/readyz 2>/dev/null |
                grep -q '"overall_readiness":"ready"'; then
            return 0
        fi
        sleep 1
    done
    die "aria-datapath did not reach overall_readiness=ready"
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
    container_running "${SERVICE_NAME}" || die "${SERVICE_NAME} is not running"
    actual_image_id="$(docker inspect -f '{{.Image}}' "${SERVICE_NAME}")"
    [ "${actual_image_id}" = "${EXPECTED_IMAGE_ID}" ] || die "running image ID mismatch"
    actual="$(container_file_hash /usr/local/bin/aria-agent)"
    [ "${actual}" = "${EXPECTED_ARIA_SHA256}" ] || die "running aria-agent hash mismatch"
    actual="$(container_file_hash /usr/local/lib/libebpf_firewall.so)"
    [ "${actual}" = "${EXPECTED_EBPF_SHA256}" ] || die "running eBPF hash mismatch"
    actual="$(container_file_hash /usr/local/lib/libebpf_firewall_perf.so)"
    [ "${actual}" = "${EXPECTED_EBPF_PERF_SHA256}" ] || die "running eBPF perf hash mismatch"
    wait_ready
    check_ovs_identity
}

verify_backup_available() {
    local actual_image_id
    container_exists "${BACKUP_CONTAINER}" || die "rollback container is missing"
    actual_image_id="$(docker inspect -f '{{.Image}}' "${BACKUP_CONTAINER}")"
    [ "${actual_image_id}" = "${BACKUP_IMAGE_ID}" ] ||
        die "rollback container image ID mismatch"
}

write_state() {
    local path="$1"
    umask 077
    mkdir -p "${STATE_DIR}"
    chmod 0700 "${STATE_DIR}"
    cat >"${path}" <<EOF
IMAGE_REF=${IMAGE_REF}
EXPECTED_IMAGE_ID=${EXPECTED_IMAGE_ID}
EXPECTED_ARIA_SHA256=${EXPECTED_ARIA_SHA256}
EXPECTED_EBPF_SHA256=${EXPECTED_EBPF_SHA256}
EXPECTED_EBPF_PERF_SHA256=${EXPECTED_EBPF_PERF_SHA256}
BACKUP_CONTAINER=${BACKUP_CONTAINER}
BACKUP_IMAGE_ID=${BACKUP_IMAGE_ID}
OVS_PID_BASELINE=${OVS_PID_BASELINE}
OVS_AGENT_ID_BASELINE=${OVS_AGENT_ID_BASELINE}
OVS_AGENT_STARTED_BASELINE=${OVS_AGENT_STARTED_BASELINE}
EOF
    chmod 0600 "${path}"
}

read_state() {
    [ -f "${STATE_FILE}" ] || die "release state not found: ${STATE_FILE}"
    [ "$(stat -c '%u' "${STATE_FILE}")" = "0" ] || die "release state must be root-owned"
    [ "$(stat -c '%a' "${STATE_FILE}")" = "600" ] || die "release state must have mode 0600"
    # The file is generated by this script from validated tokens and mode 0600.
    # shellcheck disable=SC1090
    . "${STATE_FILE}"
    validate_name "${BACKUP_CONTAINER}"
    validate_image_ref "${IMAGE_REF}"
    validate_image_id "${EXPECTED_IMAGE_ID}" EXPECTED_IMAGE_ID
    validate_image_id "${BACKUP_IMAGE_ID}" BACKUP_IMAGE_ID
    validate_sha256 "${EXPECTED_ARIA_SHA256}" EXPECTED_ARIA_SHA256
    validate_sha256 "${EXPECTED_EBPF_SHA256}" EXPECTED_EBPF_SHA256
    validate_sha256 "${EXPECTED_EBPF_PERF_SHA256}" EXPECTED_EBPF_PERF_SHA256
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

restore_backup() {
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
        docker start "${SERVICE_NAME}" >/dev/null 2>&1 || return 1
        container_running "${SERVICE_NAME}" || return 1
    fi
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
    verify_expected_files_in_image
    record_ovs_identity
    if [ -z "${DATAPATH_STATE_SOURCE}" ]; then
        DATAPATH_STATE_SOURCE="$(docker inspect -f '{{range .Mounts}}{{if eq .Destination "/var/lib/aria-agent"}}{{.Source}}{{end}}{{end}}' "${SERVICE_NAME}")"
    fi
    [ -n "${DATAPATH_STATE_SOURCE}" ] || die "current container has no /var/lib/aria-agent mount"
    [ -d "${DATAPATH_STATE_SOURCE}" ] || die "datapath state source is not a directory"

    BACKUP_CONTAINER="${SERVICE_NAME}_pre_rc_$(date +%Y%m%d%H%M%S)"
    BACKUP_IMAGE_ID="$(docker inspect -f '{{.Image}}' "${SERVICE_NAME}")"
    validate_name "${BACKUP_CONTAINER}"
    validate_image_id "${BACKUP_IMAGE_ID}" BACKUP_IMAGE_ID
    container_exists "${BACKUP_CONTAINER}" && die "backup container already exists"
    pending="${STATE_FILE}.pending"
    write_state "${pending}"

    mutation_phase=none
    on_install_exit() {
        rc=$?
        recovery_ok=true
        if [ "${rc}" -ne 0 ]; then
            case "${mutation_phase}" in
                stopped)
                    log "Install failed after stop; restarting the original container"
                    restore_stopped_original || recovery_ok=false
                    ;;
                renamed)
                    log "Install failed after rename; restoring the rollback container"
                    restore_backup || recovery_ok=false
                    ;;
            esac
        fi
        if [ "${recovery_ok}" = true ]; then
            rm -f "${pending}"
        else
            log "Automatic recovery failed; state retained at ${pending}"
            log "Manual recovery: restore ${BACKUP_CONTAINER} as ${SERVICE_NAME} and start it"
        fi
        exit "${rc}"
    }
    trap on_install_exit EXIT

    mutation_phase=stopped
    docker stop "${SERVICE_NAME}" >/dev/null
    docker rename "${SERVICE_NAME}" "${BACKUP_CONTAINER}"
    mutation_phase=renamed
    [ ! -S "${SOCKET_PATH}" ] || rm -f "${SOCKET_PATH}"
    create_candidate_container
    docker start "${SERVICE_NAME}" >/dev/null
    verify_running_candidate
    mv "${pending}" "${STATE_FILE}"
    mutation_phase=none
    trap - EXIT
    log "Install passed; rollback container=${BACKUP_CONTAINER}"
}

check_candidate() {
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
    local restored_image_id
    read_state
    verify_backup_available
    record_ovs_identity
    restore_backup
    restored_image_id="$(docker inspect -f '{{.Image}}' "${SERVICE_NAME}")"
    [ "${restored_image_id}" = "${BACKUP_IMAGE_ID}" ] ||
        die "rollback restored an unexpected image"
    wait_ready
    check_ovs_identity
    mv "${STATE_FILE}" "${STATE_FILE}.rolled-back-$(date +%Y%m%d%H%M%S)"
    log "Rollback passed; restored ${BACKUP_CONTAINER} as ${SERVICE_NAME}"
}

require_root
for command in docker curl grep awk pgrep stat; do
    require_command "${command}"
done
validate_name "${SERVICE_NAME}"
validate_name "${AGENT_SERVICE}"
validate_name "${OVS_AGENT_SERVICE}"

case "${1:-}" in
    install) install_candidate ;;
    check) check_candidate ;;
    rollback) rollback_candidate ;;
    -h|--help) usage ;;
    *) usage; exit 2 ;;
esac
