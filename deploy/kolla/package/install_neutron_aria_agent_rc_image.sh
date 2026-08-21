#!/usr/bin/env bash
set -euo pipefail

SERVICE_NAME="${SERVICE_NAME:-neutron_aria_agent}"
DATAPATH_SERVICE="${DATAPATH_SERVICE:-aria_datapath}"
OVS_AGENT_SERVICE="${OVS_AGENT_SERVICE:-neutron_openvswitch_agent}"
IMAGE_REF="${IMAGE_REF:-}"
IMAGE_TAR="${IMAGE_TAR:-}"
EXPECTED_IMAGE_ID="${EXPECTED_IMAGE_ID:-}"
STATE_DIR="${STATE_DIR:-/var/lib/neutron-aria-agent-release}"
STATE_FILE="${STATE_FILE:-${STATE_DIR}/active.env}"
CONFIG_PATH="${CONFIG_PATH:-/etc/kolla/neutron-aria-agent/neutron-aria-agent.ini}"
CANDIDATE_CONFIG_SOURCE="${CANDIDATE_CONFIG_SOURCE:-}"
ROLLBACK_CONFIG_SOURCE="${ROLLBACK_CONFIG_SOURCE:-}"
READY_TIMEOUT="${READY_TIMEOUT:-90}"
RUNTIME_STATE_SOURCE="${RUNTIME_STATE_SOURCE:-/var/lib/neutron-aria-agent/state}"
CONTAINER_STATE_DIR="${CONTAINER_STATE_DIR:-/var/lib/neutron-aria-agent/state}"
RUNTIME_STATE_NEEDS_SEED=false

log() {
    printf '[neutron-aria-agent-rc] %s\n' "$*"
}

die() {
    echo "ERROR: $*" >&2
    exit 1
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

validate_name() {
    case "$1" in
        ''|*[!A-Za-z0-9_.-]*) die "invalid container name: $1" ;;
    esac
}

validate_image_ref() {
    case "$1" in
        ''|*[!A-Za-z0-9_./:@-]*) die "invalid image reference" ;;
    esac
}

validate_image_id() {
    case "$1" in
        sha256:[0-9a-f][0-9a-f]*) ;;
        *) die "$2 must use sha256:<lowercase-hex>" ;;
    esac
    [ "${#1}" -eq 71 ] || die "$2 has an invalid length"
    case "${1#sha256:}" in
        *[!0-9a-f]*) die "$2 must use lowercase hexadecimal" ;;
    esac
}

validate_absolute_path() {
    case "$1" in
        /*) ;;
        *) die "$2 must be an absolute path" ;;
    esac
    case "$1" in
        *$'\n'*|*$'\r'*) die "$2 contains an invalid newline" ;;
    esac
}

discover_runtime_state() {
    local mounted_source
    mounted_source="$(docker inspect -f \
        '{{range .Mounts}}{{if eq .Destination "/var/lib/neutron-aria-agent/state"}}{{.Source}}{{end}}{{end}}' \
        "${SERVICE_NAME}")"
    if [ -n "${mounted_source}" ]; then
        RUNTIME_STATE_SOURCE="${mounted_source}"
        RUNTIME_STATE_NEEDS_SEED=false
    else
        RUNTIME_STATE_NEEDS_SEED=true
    fi
    validate_absolute_path "${RUNTIME_STATE_SOURCE}" RUNTIME_STATE_SOURCE
    validate_absolute_path "${CONTAINER_STATE_DIR}" CONTAINER_STATE_DIR
}

seed_runtime_state() {
    local parent_dir staging_dir
    [ "${RUNTIME_STATE_NEEDS_SEED}" = "true" ] || return 0
    [ ! -e "${RUNTIME_STATE_SOURCE}" ] || {
        log "refusing to replace unowned runtime state: ${RUNTIME_STATE_SOURCE}"
        return 1
    }
    parent_dir="$(dirname "${RUNTIME_STATE_SOURCE}")"
    staging_dir="${RUNTIME_STATE_SOURCE}.candidate.$$"
    mkdir -p "${parent_dir}"
    mkdir "${staging_dir}"
    if ! docker cp "${SERVICE_NAME}:${CONTAINER_STATE_DIR}/." "${staging_dir}"; then
        rm -rf -- "${staging_dir}"
        return 1
    fi
    chown -R "${AGENT_UID}:${AGENT_GID}" "${staging_dir}"
    chmod 0700 "${staging_dir}"
    mv "${staging_dir}" "${RUNTIME_STATE_SOURCE}"
}

record_non_interference_baseline() {
    DATAPATH_ID="$(docker inspect -f '{{.Id}}' "${DATAPATH_SERVICE}")"
    DATAPATH_STARTED="$(docker inspect -f '{{.State.StartedAt}}' "${DATAPATH_SERVICE}")"
    OVS_AGENT_ID="$(docker inspect -f '{{.Id}}' "${OVS_AGENT_SERVICE}")"
    OVS_AGENT_STARTED="$(docker inspect -f '{{.State.StartedAt}}' "${OVS_AGENT_SERVICE}")"
}

check_non_interference() {
    [ "$(docker inspect -f '{{.Id}}' "${DATAPATH_SERVICE}")" = "${DATAPATH_ID}" ] ||
        die "Aria datapath container identity changed"
    [ "$(docker inspect -f '{{.State.StartedAt}}' "${DATAPATH_SERVICE}")" = "${DATAPATH_STARTED}" ] ||
        die "Aria datapath start time changed"
    [ "$(docker inspect -f '{{.Id}}' "${OVS_AGENT_SERVICE}")" = "${OVS_AGENT_ID}" ] ||
        die "Neutron OVS agent container identity changed"
    [ "$(docker inspect -f '{{.State.StartedAt}}' "${OVS_AGENT_SERVICE}")" = "${OVS_AGENT_STARTED}" ] ||
        die "Neutron OVS agent start time changed"
}

validate_image_runtime() {
    docker run --rm --entrypoint python "${IMAGE_REF}" -c '
import netaddr
from neutron_aria.agent.config import DEFAULT_HEARTBEAT_DETAIL_MODE
from neutron_aria.agent.status_reporter import HEARTBEAT_SCHEMA_VERSION
assert HEARTBEAT_SCHEMA_VERSION == 2
assert DEFAULT_HEARTBEAT_DETAIL_MODE == "summary_only"
assert netaddr.__version__ == "0.7.19"
' >/dev/null
    docker run --rm --entrypoint neutron-aria-agent "${IMAGE_REF}" --help >/dev/null
}

wait_candidate_ready() {
    for _ in $(seq 1 "${READY_TIMEOUT}"); do
        if container_running "${SERVICE_NAME}" &&
            docker exec "${SERVICE_NAME}" python -c '
from neutron_aria.agent.config import load_config
from neutron_aria.agent.status_reporter import HEARTBEAT_SCHEMA_VERSION
config = load_config("/etc/neutron-aria-agent/neutron-aria-agent.ini")
assert HEARTBEAT_SCHEMA_VERSION == 2
assert config.heartbeat_detail_mode == "summary_only"
' >/dev/null 2>&1; then
            wait_container_healthy
            return $?
        fi
        sleep 1
    done
    return 1
}

create_service_container() {
    local name="$1" image="$2"
    docker create \
        --name "${name}" \
        --hostname "${SERVICE_HOSTNAME}" \
        --restart unless-stopped \
        --network host \
        --log-driver json-file \
        --log-opt max-file=30 \
        --log-opt max-size=10m \
        --env-file "${STATE_DIR}/container.env" \
        -v /etc/kolla/neutron-aria-agent/:/var/lib/kolla/config_files/:ro \
        -v /etc/localtime:/etc/localtime:ro \
        -v kolla_logs:/var/log/kolla/:rw \
        -v /run/aria:/run/aria:rw \
        -v "${RUNTIME_STATE_SOURCE}:${CONTAINER_STATE_DIR}:rw" \
        "${image}" kolla_start >/dev/null
}

write_state() {
    local path="$1"
    umask 077
    cat >"${path}" <<EOF
IMAGE_REF=${IMAGE_REF}
EXPECTED_IMAGE_ID=${EXPECTED_IMAGE_ID}
BACKUP_CONTAINER=${BACKUP_CONTAINER}
BACKUP_IMAGE_ID=${BACKUP_IMAGE_ID}
BACKUP_IMAGE_REF=${BACKUP_IMAGE_REF}
SERVICE_HOSTNAME=${SERVICE_HOSTNAME}
DATAPATH_ID=${DATAPATH_ID}
DATAPATH_STARTED=${DATAPATH_STARTED}
OVS_AGENT_ID=${OVS_AGENT_ID}
OVS_AGENT_STARTED=${OVS_AGENT_STARTED}
RUNTIME_STATE_SOURCE=${RUNTIME_STATE_SOURCE}
CONTAINER_STATE_DIR=${CONTAINER_STATE_DIR}
EOF
    chmod 0600 "${path}"
}

read_state() {
    [ -f "${STATE_FILE}" ] || die "release state not found: ${STATE_FILE}"
    [ "$(stat -c '%u' "${STATE_FILE}")" = "0" ] || die "release state must be root-owned"
    [ "$(stat -c '%a' "${STATE_FILE}")" = "600" ] || die "release state must have mode 0600"
    # This file contains only values validated before it is written.
    # shellcheck disable=SC1090
    . "${STATE_FILE}"
    validate_image_ref "${IMAGE_REF}"
    validate_image_id "${EXPECTED_IMAGE_ID}" EXPECTED_IMAGE_ID
    validate_image_id "${BACKUP_IMAGE_ID}" BACKUP_IMAGE_ID
    validate_name "${BACKUP_CONTAINER}"
    validate_name "${SERVICE_HOSTNAME}"
    validate_absolute_path "${RUNTIME_STATE_SOURCE}" RUNTIME_STATE_SOURCE
    validate_absolute_path "${CONTAINER_STATE_DIR}" CONTAINER_STATE_DIR
}

restore_failed_install() {
    local failed=0
    if container_exists "${SERVICE_NAME}"; then
        docker rm -f "${SERVICE_NAME}" >/dev/null 2>&1 || failed=1
    fi
    if container_exists "${BACKUP_CONTAINER}"; then
        docker rm "${BACKUP_CONTAINER}" >/dev/null 2>&1 || failed=1
        cp -a "${STATE_DIR}/config.before" "${CONFIG_PATH}" || failed=1
        create_service_container "${SERVICE_NAME}" "${BACKUP_IMAGE_ID}" || failed=1
        docker start "${SERVICE_NAME}" >/dev/null 2>&1 || failed=1
    else
        failed=1
    fi
    return "${failed}"
}

install_candidate() {
    [ "$(id -u)" = "0" ] || die "must run as root"
    command -v docker >/dev/null 2>&1 || die "docker is required"
    [ -n "${IMAGE_REF}" ] || die "IMAGE_REF is required"
    [ -n "${EXPECTED_IMAGE_ID}" ] || die "EXPECTED_IMAGE_ID is required"
    validate_image_ref "${IMAGE_REF}"
    validate_image_id "${EXPECTED_IMAGE_ID}" EXPECTED_IMAGE_ID
    [ ! -e "${STATE_FILE}" ] || die "active release state already exists"
    container_running "${SERVICE_NAME}" || die "${SERVICE_NAME} must be running"
    container_running "${DATAPATH_SERVICE}" || die "${DATAPATH_SERVICE} must be running"
    container_running "${OVS_AGENT_SERVICE}" || die "${OVS_AGENT_SERVICE} must be running"
    [ -f "${CONFIG_PATH}" ] || die "missing Kolla agent config"

    if [ -n "${IMAGE_TAR}" ]; then
        [ -f "${IMAGE_TAR}" ] || die "missing IMAGE_TAR"
        case "${IMAGE_TAR}" in
            *.gz) gzip -dc "${IMAGE_TAR}" | docker load >/dev/null ;;
            *) docker load -i "${IMAGE_TAR}" >/dev/null ;;
        esac
    fi
    docker image inspect "${IMAGE_REF}" >/dev/null
    [ "$(docker image inspect -f '{{.Id}}' "${IMAGE_REF}")" = "${EXPECTED_IMAGE_ID}" ] ||
        die "candidate image ID mismatch"
    candidate_image_has_healthcheck "${IMAGE_REF}" ||
        die "candidate image does not declare a Docker healthcheck"
    validate_image_runtime

    umask 077
    mkdir -p "${STATE_DIR}"
    chmod 0700 "${STATE_DIR}"
    docker inspect -f '{{range .Config.Env}}{{println .}}{{end}}' "${SERVICE_NAME}" \
        >"${STATE_DIR}/container.env"
    chmod 0600 "${STATE_DIR}/container.env"
    cp -a "${CONFIG_PATH}" "${STATE_DIR}/config.before"
    cp -a "${CANDIDATE_CONFIG_SOURCE:-${CONFIG_PATH}}" "${STATE_DIR}/config.candidate"
    cp -a "${ROLLBACK_CONFIG_SOURCE:-${CONFIG_PATH}}" "${STATE_DIR}/config.rollback"

    SERVICE_HOSTNAME="$(docker inspect -f '{{.Config.Hostname}}' "${SERVICE_NAME}")"
    BACKUP_IMAGE_ID="$(docker inspect -f '{{.Image}}' "${SERVICE_NAME}")"
    BACKUP_IMAGE_REF="$(docker inspect -f '{{.Config.Image}}' "${SERVICE_NAME}")"
    BACKUP_CONTAINER="${SERVICE_NAME}_pre_rc_$(date +%Y%m%d%H%M%S)"
    AGENT_UID="$(docker exec "${SERVICE_NAME}" id -u neutron)"
    AGENT_GID="$(docker exec "${SERVICE_NAME}" id -g neutron)"
    validate_name "${SERVICE_HOSTNAME}"
    validate_image_id "${BACKUP_IMAGE_ID}" BACKUP_IMAGE_ID
    validate_image_ref "${BACKUP_IMAGE_REF}"
    validate_name "${BACKUP_CONTAINER}"
    discover_runtime_state
    record_non_interference_baseline
    write_state "${STATE_FILE}.pending"

    docker stop "${SERVICE_NAME}" >/dev/null
    if ! seed_runtime_state; then
        docker start "${SERVICE_NAME}" >/dev/null 2>&1 || true
        rm -f "${STATE_FILE}.pending"
        die "failed to preserve neutron-aria-agent runtime state"
    fi
    docker rename "${SERVICE_NAME}" "${BACKUP_CONTAINER}" >/dev/null
    if ! cp -a "${STATE_DIR}/config.candidate" "${CONFIG_PATH}" ||
       ! create_service_container "${SERVICE_NAME}" "${IMAGE_REF}" ||
       ! docker start "${SERVICE_NAME}" >/dev/null ||
       ! wait_candidate_ready; then
        log "candidate failed; restoring previous container"
        restore_failed_install || die "candidate failed and automatic restore was incomplete"
        rm -f "${STATE_FILE}.pending"
        die "candidate did not become ready"
    fi

    check_non_interference
    mv "${STATE_FILE}.pending" "${STATE_FILE}"
    log "install passed image=${IMAGE_REF} id=${EXPECTED_IMAGE_ID}"
}

check_candidate() {
    [ "$(id -u)" = "0" ] || die "must run as root"
    read_state
    container_running "${SERVICE_NAME}" || die "candidate container is not running"
    [ "$(docker inspect -f '{{.Image}}' "${SERVICE_NAME}")" = "${EXPECTED_IMAGE_ID}" ] ||
        die "running image ID mismatch"
    wait_candidate_ready || die "candidate runtime is not Heartbeat V2 ready"
    container_running "${DATAPATH_SERVICE}" || die "Aria datapath is not running"
    container_running "${OVS_AGENT_SERVICE}" || die "Neutron OVS agent is not running"
    log "check passed image=${IMAGE_REF}"
}

rollback_candidate() {
    [ "$(id -u)" = "0" ] || die "must run as root"
    read_state
    record_non_interference_baseline
    rollback_name="${SERVICE_NAME}_rollback_$(date +%Y%m%d%H%M%S)"
    validate_name "${rollback_name}"
    container_exists "${rollback_name}" && die "rollback candidate already exists"
    create_service_container "${rollback_name}" "${BACKUP_IMAGE_ID}"

    docker stop "${SERVICE_NAME}" >/dev/null
    docker rm "${SERVICE_NAME}" >/dev/null
    if container_exists "${BACKUP_CONTAINER}"; then
        docker rm "${BACKUP_CONTAINER}" >/dev/null
    fi
    cp -a "${STATE_DIR}/config.rollback" "${CONFIG_PATH}"
    docker rename "${rollback_name}" "${SERVICE_NAME}" >/dev/null
    docker start "${SERVICE_NAME}" >/dev/null

    for _attempt in $(seq 1 "${READY_TIMEOUT}"); do
        if container_running "${SERVICE_NAME}"; then
            break
        fi
        sleep 1
    done
    container_running "${SERVICE_NAME}" || die "rollback container did not start"
    [ "$(docker inspect -f '{{.Image}}' "${SERVICE_NAME}")" = "${BACKUP_IMAGE_ID}" ] ||
        die "rollback image ID mismatch"
    check_non_interference
    mv "${STATE_FILE}" "${STATE_DIR}/last-rollback.env"
    log "rollback passed image=${BACKUP_IMAGE_REF}"
}

case "${1:-}" in
    install) install_candidate ;;
    check) check_candidate ;;
    rollback) rollback_candidate ;;
    *) echo "Usage: $0 install|check|rollback" >&2; exit 2 ;;
esac
