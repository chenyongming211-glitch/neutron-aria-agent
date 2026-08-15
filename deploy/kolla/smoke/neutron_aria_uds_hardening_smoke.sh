#!/usr/bin/env bash
set -euo pipefail

HOST_FQDN="${HOST_FQDN:-$(hostname -f 2>/dev/null || hostname)}"
SERVICE_NAME="${SERVICE_NAME:-neutron_aria_agent}"
DATAPATH_SERVICE="${DATAPATH_SERVICE:-aria_datapath}"
SOCKET_PATH="${SOCKET_PATH:-/run/aria/aria-agent.sock}"
RUN_ARIA_DIR="${RUN_ARIA_DIR:-/run/aria}"
AUDIT_LOG_PATH="${AUDIT_LOG_PATH:-/var/log/kolla/aria-datapath/neutron-uds-audit.log}"
EVIDENCE_ROOT="${EVIDENCE_ROOT:-/var/tmp/neutron-aria-uds-hardening}"
EVIDENCE_DIR="${EVIDENCE_DIR:-${EVIDENCE_ROOT}/$(date +%Y%m%d%H%M%S)-${HOST_FQDN}}"
REQUIRE_HARDENED="${REQUIRE_HARDENED:-false}"

mkdir -p "${EVIDENCE_DIR}"
COMMANDS_LOG="${EVIDENCE_DIR}/commands.log"
FACTS_TSV="${EVIDENCE_DIR}/facts.tsv"
SUMMARY_MD="${EVIDENCE_DIR}/summary.md"

log() {
    printf '[neutron-aria-uds-hardening] %s\n' "$*"
}

escape_md() {
    printf '%s' "$1" | tr '\n' ' ' | sed 's/|/\\|/g'
}

docker_has_container() {
    command -v docker >/dev/null 2>&1 || return 1
    docker ps --format '{{.Names}}' 2>/dev/null | grep -qx "$1"
}

capture() {
    local fact="$1"
    local expected="$2"
    local fail_disposition="$3"
    local output_name="$4"
    shift 4

    local output_path="${EVIDENCE_DIR}/${output_name}"
    local command_text="$*"
    log "Collecting ${fact}"
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
    local actual="exit=0"
    if [ "${rc}" -ne 0 ]; then
        case "${rc}" in
            2)
                disposition="not_applicable"
                ;;
            3)
                disposition="unsupported"
                ;;
            4)
                disposition="degraded"
                ;;
            *)
                disposition="${fail_disposition}"
                ;;
        esac
        actual="exit=${rc}"
    fi

    printf '%s\t%s\t%s\t%s\t%s\t%s\n' \
        "${fact}" \
        "${expected}" \
        "${command_text}" \
        "${actual}" \
        "${output_name}" \
        "${disposition}" >> "${FACTS_TSV}"

    printf 'exit=%s disposition=%s output=%s\n\n' \
        "${rc}" "${disposition}" "${output_path}" >> "${COMMANDS_LOG}"
    return 0
}

collect_identity() {
    echo "host=${HOST_FQDN}"
    echo "require_hardened=${REQUIRE_HARDENED}"
    echo "run_aria_dir=${RUN_ARIA_DIR}"
    echo "socket_path=${SOCKET_PATH}"
    echo "audit_log_path=${AUDIT_LOG_PATH}"
    echo
    for name in "${DATAPATH_SERVICE}" "${SERVICE_NAME}"; do
        echo "## container ${name}"
        if ! docker_has_container "${name}"; then
            echo "container ${name} is not running"
            continue
        fi
        docker inspect "${name}" \
            --format 'name={{.Name}} image={{.Config.Image}} user={{.Config.User}} pid={{.State.Pid}} mounts={{range .Mounts}}{{.Source}}:{{.Destination}}:{{.Mode}};{{end}}'
        docker exec -u root "${name}" sh -c '
            echo "root_identity=$(id)"
            if id neutron >/dev/null 2>&1; then
                echo "neutron_identity=$(id neutron)"
            fi
            if command -v getent >/dev/null 2>&1; then
                getent passwd root neutron 2>/dev/null || true
                getent group root neutron neutron-aria aria-datapath 2>/dev/null || true
            fi
        '
        echo
    done
}

collect_permissions() {
    echo "## host permissions"
    stat -c "%n %U %G %u %g %a %F" "${RUN_ARIA_DIR}"
    stat -c "%n %U %G %u %g %a %F" "${SOCKET_PATH}"
    echo
    echo "## inside ${SERVICE_NAME}"
    if docker_has_container "${SERVICE_NAME}"; then
        docker exec -u root "${SERVICE_NAME}" sh -c "
            stat -c '%n %U %G %u %g %a %F' '${RUN_ARIA_DIR}' '${SOCKET_PATH}'
        "
        docker exec -u neutron "${SERVICE_NAME}" sh -c "
            test -S '${SOCKET_PATH}' && test -r '${SOCKET_PATH}' && test -w '${SOCKET_PATH}' &&
            echo 'neutron user can read/write socket path'
        "
    fi
}

check_socket_not_world_writable() {
    local dir_mode
    local socket_mode
    dir_mode="$(stat -c '%a' "${RUN_ARIA_DIR}")"
    socket_mode="$(stat -c '%a' "${SOCKET_PATH}")"
    echo "run_aria_mode=${dir_mode}"
    echo "socket_mode=${socket_mode}"
    if [ $((8#${dir_mode} & 0007)) -ne 0 ]; then
        echo "${RUN_ARIA_DIR} has other-user permission bits"
        return 4
    fi
    if [ $((8#${socket_mode} & 0007)) -ne 0 ]; then
        echo "${SOCKET_PATH} has other-user permission bits"
        return 4
    fi
}

collect_peercred_allow_list() {
    echo "## recommended peercred allow-list inputs"
    if docker_has_container "${SERVICE_NAME}"; then
        echo "neutron_aria_agent_config_user=$(docker inspect "${SERVICE_NAME}" --format '{{.Config.User}}')"
        echo "neutron_aria_agent_neutron_uid=$(docker exec -u root "${SERVICE_NAME}" id -u neutron 2>/dev/null || true)"
        echo "neutron_aria_agent_neutron_gid=$(docker exec -u root "${SERVICE_NAME}" id -g neutron 2>/dev/null || true)"
        echo "neutron_aria_agent_neutron_groups=$(docker exec -u root "${SERVICE_NAME}" id -G neutron 2>/dev/null || true)"
    fi
    if docker_has_container "${DATAPATH_SERVICE}"; then
        echo "aria_datapath_config_user=$(docker inspect "${DATAPATH_SERVICE}" --format '{{.Config.User}}')"
        echo "aria_datapath_root_uid=$(docker exec -u root "${DATAPATH_SERVICE}" id -u 2>/dev/null || true)"
        echo "aria_datapath_root_gid=$(docker exec -u root "${DATAPATH_SERVICE}" id -g 2>/dev/null || true)"
    fi
    echo
    echo "Set neutron_peercred_allowed_uids/gids only after confirming which process opens the UDS."
    echo "For the current Python agent path, the expected peer is the ${SERVICE_NAME} process user."
}

collect_audit_log_path() {
    echo "audit_log_path=${AUDIT_LOG_PATH}"
    if [ -e "${AUDIT_LOG_PATH}" ]; then
        stat -c "%n %U %G %u %g %a %F" "${AUDIT_LOG_PATH}"
        tail -n 20 "${AUDIT_LOG_PATH}" || true
    else
        echo "audit log does not exist yet"
        if [ "${REQUIRE_HARDENED}" = "true" ]; then
            return 1
        fi
        return 2
    fi
}

check_hardened_required() {
    if [ "${REQUIRE_HARDENED}" != "true" ]; then
        echo "REQUIRE_HARDENED=false; recording evidence only"
        return 2
    fi
    check_socket_not_world_writable || return 1
    if [ ! -e "${AUDIT_LOG_PATH}" ]; then
        echo "audit log missing while REQUIRE_HARDENED=true"
        return 1
    fi
}

write_summary() {
    local pass_count=0
    local nonpass_count=0
    local fail_count=0

    {
        echo "# UDS Hardening Evidence"
        echo
        echo "Host: \`${HOST_FQDN}\`"
        echo
        echo "Generated at: \`$(date -u '+%Y-%m-%dT%H:%M:%SZ')\`"
        echo
        echo "This smoke records the UDS hardening gate for stage-two ACL MVP."
        echo "It does not enable QoS, Mirror, RabbitMQ event consumption, or tenant features."
        echo
        echo "| Fact | Expected | Command | Actual | Evidence | Disposition |"
        echo "| --- | --- | --- | --- | --- | --- |"
    } > "${SUMMARY_MD}"

    while IFS=$'\t' read -r fact expected command actual evidence disposition; do
        [ -n "${fact}" ] || continue
        if [ "${disposition}" = "pass" ]; then
            pass_count=$((pass_count + 1))
        else
            nonpass_count=$((nonpass_count + 1))
        fi
        if [ "${disposition}" = "fail" ]; then
            fail_count=$((fail_count + 1))
        fi
        # Backticks are literal Markdown delimiters, not command substitution.
        # shellcheck disable=SC2016
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
        echo "- non-pass: ${nonpass_count}"
        echo "- fail: ${fail_count}"
        echo "- require_hardened: ${REQUIRE_HARDENED}"
    } >> "${SUMMARY_MD}"

    if [ "${fail_count}" -gt 0 ]; then
        return 1
    fi
    return 0
}

: > "${COMMANDS_LOG}"
: > "${FACTS_TSV}"

capture "Container peer identities" "Record uid/gid/group inputs for peercred allow-list" "fail" \
    "peer-identities.txt" collect_identity
capture "UDS directory and socket permissions" "Record host and container view of /run/aria and socket permissions" "degraded" \
    "socket-permissions.txt" collect_permissions
capture "World-writable socket check" "Socket and parent directory have no other-user permission bits" "degraded" \
    "world-writable-check.txt" check_socket_not_world_writable
capture "Peercred allow-list candidates" "Record candidate uid/gid values before enabling enforcement" "fail" \
    "peercred-allow-list.txt" collect_peercred_allow_list
capture "Audit log path" "Audit log path is known; required only when hardened mode is enforced" "degraded" \
    "audit-log.txt" collect_audit_log_path
capture "Hardened enforcement gate" "When REQUIRE_HARDENED=true, socket and audit requirements must pass" "fail" \
    "hardened-required.txt" check_hardened_required

write_summary
log "UDS hardening evidence written to ${EVIDENCE_DIR}"
