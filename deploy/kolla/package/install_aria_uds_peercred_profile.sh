#!/usr/bin/env bash
set -euo pipefail

DATAPATH_SERVICE="${DATAPATH_SERVICE:-aria_datapath}"
AGENT_SERVICE="${AGENT_SERVICE:-neutron_aria_agent}"
CONFIG_PATH="${CONFIG_PATH:-/etc/kolla/aria-datapath/aria-agent-openstack.toml}"
OUTPUT_PATH="${OUTPUT_PATH:-}"
RUN_ARIA_DIR="${RUN_ARIA_DIR:-/run/aria}"
SOCKET_PATH="${SOCKET_PATH:-/run/aria/aria-agent.sock}"
STATE_DIR="${STATE_DIR:-/var/tmp/aria-uds-peercred-profile}"
AUDIT_LOG_VALUE="${AUDIT_LOG_VALUE:-/var/log/kolla/aria-datapath/neutron-uds-audit.log}"
WAIT_SECONDS="${WAIT_SECONDS:-45}"
NEUTRON_UID="${NEUTRON_UID:-}"
NEUTRON_GID="${NEUTRON_GID:-}"
TMPFILES_PATH="${TMPFILES_PATH:-/etc/tmpfiles.d/aria.conf}"
HOST_GROUP_NAME="${HOST_GROUP_NAME:-aria-neutron}"

PROFILE_BEGIN="# BEGIN aria UDS peercred production profile"
PROFILE_END="# END aria UDS peercred production profile"

log() {
    printf '[aria-uds-peercred-profile] %s\n' "$*"
}

usage() {
    cat <<EOF
Usage: $0 render|check-config|apply|check|rollback

render       Render a hardened config to OUTPUT_PATH using explicit
             NEUTRON_UID and NEUTRON_GID.
check-config Verify CONFIG_PATH contains exactly the expected hardened keys.
apply        Discover the Neutron container identity, atomically install the
             hardened profile and persistent runtime-directory ownership,
             restart only aria-datapath, and verify it.
check        Verify config, socket permissions, authorized access, denied
             unauthorized access, and audit records without restarting.
rollback     Restore the latest config/directory preimage and restart only
             aria-datapath.
EOF
}

require_numeric_identity() {
    case "${NEUTRON_UID}" in
        ''|*[!0-9]*) echo "NEUTRON_UID must be numeric" >&2; return 1 ;;
    esac
    case "${NEUTRON_GID}" in
        ''|*[!0-9]*) echo "NEUTRON_GID must be numeric" >&2; return 1 ;;
    esac
    if [ "${NEUTRON_UID}" = "0" ] || [ "${NEUTRON_GID}" = "0" ]; then
        echo "Neutron peer UID/GID must be non-root" >&2
        return 1
    fi
}

require_root_host() {
    if [ "$(id -u)" != "0" ]; then
        echo "This profile installer must run as root on the Kolla host." >&2
        exit 1
    fi
}

container_running() {
    docker ps --format '{{.Names}}' | grep -qx "$1"
}

discover_identity() {
    container_running "${AGENT_SERVICE}" || {
        echo "${AGENT_SERVICE} must be running" >&2
        return 1
    }
    NEUTRON_UID="$(docker exec -u root "${AGENT_SERVICE}" id -u neutron)"
    NEUTRON_GID="$(docker exec -u root "${AGENT_SERVICE}" id -g neutron)"
    require_numeric_identity
}

find_host_group() {
    local existing_name
    existing_name="$(getent group "${NEUTRON_GID}" | cut -d: -f1 || true)"
    if [ -n "${existing_name}" ]; then
        HOST_GROUP_NAME="${existing_name}"
        return 0
    fi

    return 1
}

ensure_host_group() {
    local existing_gid
    if find_host_group; then
        return 0
    fi

    existing_gid="$(getent group "${HOST_GROUP_NAME}" | cut -d: -f3 || true)"
    if [ -n "${existing_gid}" ] && [ "${existing_gid}" != "${NEUTRON_GID}" ]; then
        echo "host group ${HOST_GROUP_NAME} already uses GID ${existing_gid}" >&2
        return 1
    fi
    groupadd --system --gid "${NEUTRON_GID}" "${HOST_GROUP_NAME}"
    find_host_group
}

expected_tmpfiles_line() {
    printf 'd %s 0770 root %s -\n' "${RUN_ARIA_DIR}" "${HOST_GROUP_NAME}"
}

install_runtime_directory_profile() {
    ensure_host_group || return 1
    command -v systemd-tmpfiles >/dev/null 2>&1 || {
        echo "missing command: systemd-tmpfiles" >&2
        return 1
    }

    local temp_path
    mkdir -p "$(dirname "${TMPFILES_PATH}")"
    temp_path="$(mktemp "${TMPFILES_PATH}.XXXXXX")"
    expected_tmpfiles_line >"${temp_path}"
    chown root:root "${temp_path}"
    chmod 0644 "${temp_path}"
    mv -f "${temp_path}" "${TMPFILES_PATH}"
    systemd-tmpfiles --create "${TMPFILES_PATH}"
}

check_runtime_directory_profile() {
    find_host_group || {
        echo "no host group maps Neutron GID ${NEUTRON_GID}" >&2
        return 1
    }
    [ -f "${TMPFILES_PATH}" ] || {
        echo "missing tmpfiles profile: ${TMPFILES_PATH}" >&2
        return 1
    }
    [ "$(cat "${TMPFILES_PATH}")" = "$(expected_tmpfiles_line)" ] || {
        echo "unexpected tmpfiles profile in ${TMPFILES_PATH}" >&2
        return 1
    }
}

render_config() {
    require_numeric_identity
    [ -f "${CONFIG_PATH}" ] || {
        echo "missing config: ${CONFIG_PATH}" >&2
        return 1
    }
    [ -n "${OUTPUT_PATH}" ] || {
        echo "OUTPUT_PATH is required for render" >&2
        return 1
    }
    local config_absolute output_absolute
    config_absolute="$(cd "$(dirname "${CONFIG_PATH}")" && pwd -P)/$(basename "${CONFIG_PATH}")"
    output_absolute="$(cd "$(dirname "${OUTPUT_PATH}")" && pwd -P)/$(basename "${OUTPUT_PATH}")"
    [ "${config_absolute}" != "${output_absolute}" ] || {
        echo "OUTPUT_PATH must differ from CONFIG_PATH" >&2
        return 1
    }

    awk \
        -v begin="${PROFILE_BEGIN}" \
        -v end="${PROFILE_END}" '
        $0 == begin { in_profile = 1; next }
        $0 == end { in_profile = 0; next }
        in_profile { next }
        /^[[:space:]]*(neutron_socket_mode|neutron_peercred_enforce|neutron_peercred_allowed_uids|neutron_peercred_allowed_gids|neutron_audit_log_path)[[:space:]]*=/ { next }
        /^[[:space:]]*$/ { pending = pending "\n"; next }
        {
            printf "%s", pending
            pending = ""
            print
        }
    ' "${CONFIG_PATH}" >"${OUTPUT_PATH}"

    cat >>"${OUTPUT_PATH}" <<EOF

${PROFILE_BEGIN}
# Decimal 432 is octal 0660. Values are generated from the running
# neutron-aria-agent container identity; do not copy them between sites.
neutron_socket_mode = 432
neutron_peercred_enforce = true
neutron_peercred_allowed_uids = [${NEUTRON_UID}]
neutron_peercred_allowed_gids = [${NEUTRON_GID}]
neutron_audit_log_path = "${AUDIT_LOG_VALUE}"
${PROFILE_END}
EOF
}

require_exact_line() {
    local expected="$1"
    local key="${expected%% *}"
    if [ "$(grep -Ec "^[[:space:]]*${key}[[:space:]]*=" "${CONFIG_PATH}")" != "1" ]; then
        echo "expected exactly one ${key} entry in ${CONFIG_PATH}" >&2
        return 1
    fi
    grep -Fx "${expected}" "${CONFIG_PATH}" >/dev/null || {
        echo "unexpected ${key} value in ${CONFIG_PATH}" >&2
        return 1
    }
}

check_config() {
    require_numeric_identity
    [ -f "${CONFIG_PATH}" ] || {
        echo "missing config: ${CONFIG_PATH}" >&2
        return 1
    }
    require_exact_line 'neutron_socket_mode = 432' || return 1
    require_exact_line 'neutron_peercred_enforce = true' || return 1
    require_exact_line "neutron_peercred_allowed_uids = [${NEUTRON_UID}]" || return 1
    require_exact_line "neutron_peercred_allowed_gids = [${NEUTRON_GID}]" || return 1
    require_exact_line "neutron_audit_log_path = \"${AUDIT_LOG_VALUE}\"" || return 1
}

wait_for_socket() {
    for _ in $(seq 1 "${WAIT_SECONDS}"); do
        if container_running "${DATAPATH_SERVICE}" &&
            [ -S "${SOCKET_PATH}" ] &&
            [ "$(stat -c '%a' "${SOCKET_PATH}" 2>/dev/null || true)" = "660" ] &&
            [ "$(stat -c '%g' "${SOCKET_PATH}" 2>/dev/null || true)" = "${NEUTRON_GID}" ] &&
            authorized_probe >/dev/null 2>&1; then
            return 0
        fi
        sleep 1
    done
    echo "${DATAPATH_SERVICE} did not create hardened socket ${SOCKET_PATH}" >&2
    return 1
}

wait_for_authorized_uds() {
    for _ in $(seq 1 "${WAIT_SECONDS}"); do
        if container_running "${DATAPATH_SERVICE}" &&
            [ -S "${SOCKET_PATH}" ] &&
            authorized_probe >/dev/null 2>&1; then
            return 0
        fi
        sleep 1
    done
    echo "${DATAPATH_SERVICE} did not restore authorized UDS access" >&2
    return 1
}

authorized_probe() {
    docker exec -i -u neutron "${AGENT_SERVICE}" python - "${SOCKET_PATH}" <<'PY'
from __future__ import print_function

import socket
import sys

client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
client.settimeout(5.0)
client.connect(sys.argv[1])
client.sendall(b"GET /api/v1/neutron/status HTTP/1.1\r\nHost: neutron\r\nConnection: close\r\n\r\n")
data = client.recv(4096)
client.close()
if b"HTTP/1.1 200" not in data and b"HTTP/1.0 200" not in data:
    raise SystemExit("authorized UDS probe did not receive HTTP 200")
PY
}

unauthorized_probe() {
    local datapath_python
    datapath_python="$(docker exec -u root "${DATAPATH_SERVICE}" sh -c \
        'command -v python3 || command -v python2 || command -v python')"
    [ -n "${datapath_python}" ] || {
        echo "no Python interpreter in ${DATAPATH_SERVICE} for negative probe" >&2
        return 1
    }
    docker exec -i -u root "${DATAPATH_SERVICE}" "${datapath_python}" - \
        "${SOCKET_PATH}" <<'PY'
from __future__ import print_function

import socket
import sys

client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
client.settimeout(5.0)
try:
    client.connect(sys.argv[1])
    client.sendall(b"GET /api/v1/neutron/status HTTP/1.1\r\nHost: unauthorized\r\nConnection: close\r\n\r\n")
    data = client.recv(4096)
except (IOError, OSError, socket.error):
    data = b""
finally:
    client.close()
if data:
    raise SystemExit("unauthorized UDS peer received a response")
PY
}

resolve_audit_log() {
    local log_mount
    log_mount="$(docker inspect "${DATAPATH_SERVICE}" --format \
        '{{range .Mounts}}{{if eq .Destination "/var/log/kolla"}}{{.Source}}{{end}}{{end}}')"
    [ -n "${log_mount}" ] || {
        echo "cannot resolve /var/log/kolla mount for ${DATAPATH_SERVICE}" >&2
        return 1
    }
    printf '%s/aria-datapath/neutron-uds-audit.log\n' "${log_mount}"
}

check_runtime() {
    require_root_host
    discover_identity || return 1
    check_config || return 1
    check_runtime_directory_profile || return 1
    container_running "${DATAPATH_SERVICE}" || {
        echo "${DATAPATH_SERVICE} must be running" >&2
        return 1
    }
    [ "$(stat -c '%a' "${RUN_ARIA_DIR}")" = "770" ] || {
        echo "${RUN_ARIA_DIR} must have mode 0770" >&2
        return 1
    }
    [ "$(stat -c '%g' "${RUN_ARIA_DIR}")" = "${NEUTRON_GID}" ] || {
        echo "${RUN_ARIA_DIR} has the wrong group" >&2
        return 1
    }
    wait_for_socket || return 1
    authorized_probe || return 1
    unauthorized_probe || return 1

    local audit_log
    audit_log="$(resolve_audit_log)"
    [ -f "${audit_log}" ] || {
        echo "missing UDS audit log: ${audit_log}" >&2
        return 1
    }
    tail -n 100 "${audit_log}" | grep -Eq \
        '"reason"[[:space:]]*:[[:space:]]*"peercred_allow_list_match"' || {
        echo "missing authorized peer audit record" >&2
        return 1
    }
    tail -n 100 "${audit_log}" | grep -Eq \
        '"reason"[[:space:]]*:[[:space:]]*"UDS_PEER_UNAUTHORIZED"' || {
        echo "missing unauthorized peer audit record" >&2
        return 1
    }
    log "production profile check passed uid=${NEUTRON_UID} gid=${NEUTRON_GID}"
}

timestamp() {
    printf '%s-%s\n' "$(date +%Y%m%d%H%M%S)" "$$"
}

backup_preimage() {
    mkdir -p "${STATE_DIR}"
    local stamp config_backup metadata tmpfiles_backup tmpfiles_present
    stamp="$(timestamp)"
    config_backup="${STATE_DIR}/aria-agent-openstack.${stamp}.bak"
    metadata="${STATE_DIR}/run-aria.${stamp}.meta"
    tmpfiles_backup="${STATE_DIR}/aria-tmpfiles.${stamp}.bak"
    cp -p "${CONFIG_PATH}" "${config_backup}"
    tmpfiles_present=0
    if [ -f "${TMPFILES_PATH}" ]; then
        cp -p "${TMPFILES_PATH}" "${tmpfiles_backup}"
        tmpfiles_present=1
    else
        : >"${tmpfiles_backup}"
    fi
    {
        echo "uid=$(stat -c '%u' "${RUN_ARIA_DIR}")"
        echo "gid=$(stat -c '%g' "${RUN_ARIA_DIR}")"
        echo "mode=$(stat -c '%a' "${RUN_ARIA_DIR}")"
        echo "tmpfiles_present=${tmpfiles_present}"
        echo "tmpfiles_backup=${tmpfiles_backup}"
    } >"${metadata}"
    ln -sfn "${config_backup}" "${STATE_DIR}/aria-agent-openstack.latest.bak"
    ln -sfn "${metadata}" "${STATE_DIR}/run-aria.latest.meta"
}

restart_datapath() {
    docker restart "${DATAPATH_SERVICE}" >/dev/null || return 1
    wait_for_socket || return 1
}

restore_latest() {
    local config_link="${STATE_DIR}/aria-agent-openstack.latest.bak"
    local metadata_link="${STATE_DIR}/run-aria.latest.meta"
    if [ ! -e "${config_link}" ] || [ ! -e "${metadata_link}" ]; then
        echo "missing rollback preimage in ${STATE_DIR}" >&2
        return 1
    fi
    local config_backup metadata uid gid mode temp_config
    local tmpfiles_present tmpfiles_backup temp_tmpfiles
    config_backup="$(readlink -f "${config_link}")"
    metadata="$(readlink -f "${metadata_link}")"
    uid="$(sed -n 's/^uid=//p' "${metadata}")"
    gid="$(sed -n 's/^gid=//p' "${metadata}")"
    mode="$(sed -n 's/^mode=//p' "${metadata}")"
    tmpfiles_present="$(sed -n 's/^tmpfiles_present=//p' "${metadata}")"
    tmpfiles_backup="$(sed -n 's/^tmpfiles_backup=//p' "${metadata}")"
    temp_config="$(mktemp "${CONFIG_PATH}.rollback.XXXXXX")"
    cp -p "${config_backup}" "${temp_config}" || return 1
    mv -f "${temp_config}" "${CONFIG_PATH}" || return 1
    if [ "${tmpfiles_present:-0}" = "1" ]; then
        [ -f "${tmpfiles_backup}" ] || return 1
        temp_tmpfiles="$(mktemp "${TMPFILES_PATH}.rollback.XXXXXX")"
        cp -p "${tmpfiles_backup}" "${temp_tmpfiles}" || return 1
        mv -f "${temp_tmpfiles}" "${TMPFILES_PATH}" || return 1
    else
        rm -f "${TMPFILES_PATH}"
    fi
    chown "${uid}:${gid}" "${RUN_ARIA_DIR}" || return 1
    chmod "${mode}" "${RUN_ARIA_DIR}" || return 1
    docker restart "${DATAPATH_SERVICE}" >/dev/null || return 1
    wait_for_authorized_uds || return 1
    log "restored latest config and runtime-directory preimage"
}

apply_profile() {
    require_root_host
    discover_identity
    if check_config >/dev/null 2>&1 &&
        check_runtime_directory_profile >/dev/null 2>&1 &&
        [ "$(stat -c '%a' "${RUN_ARIA_DIR}")" = "770" ] &&
        [ "$(stat -c '%g' "${RUN_ARIA_DIR}")" = "${NEUTRON_GID}" ]; then
        if check_runtime; then
            log "profile already installed; no restart required"
            return
        fi
        log "profile is installed but runtime verification failed; reloading datapath once"
        restart_datapath
        check_runtime
        return
    fi

    backup_preimage
    local temp_config config_uid config_gid config_mode
    temp_config="$(mktemp "${CONFIG_PATH}.hardened.XXXXXX")"
    config_uid="$(stat -c '%u' "${CONFIG_PATH}")"
    config_gid="$(stat -c '%g' "${CONFIG_PATH}")"
    config_mode="$(stat -c '%a' "${CONFIG_PATH}")"
    OUTPUT_PATH="${temp_config}" render_config
    chown "${config_uid}:${config_gid}" "${temp_config}"
    chmod "${config_mode}" "${temp_config}"
    mv -f "${temp_config}" "${CONFIG_PATH}"
    install_runtime_directory_profile

    if ! restart_datapath || ! check_runtime; then
        log "hardened apply failed; restoring the preimage"
        restore_latest || true
        exit 1
    fi
    log "production profile applied"
}

rollback_profile() {
    require_root_host
    discover_identity
    restore_latest
    container_running "${DATAPATH_SERVICE}" || {
        echo "${DATAPATH_SERVICE} failed to restart during rollback" >&2
        exit 1
    }
}

main() {
    case "${1:-}" in
        render)
            render_config
            ;;
        check-config)
            check_config
            ;;
        apply)
            apply_profile
            ;;
        check)
            check_runtime
            ;;
        rollback)
            rollback_profile
            ;;
        *)
            usage
            return 2
            ;;
    esac
}

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
    main "$@"
fi
