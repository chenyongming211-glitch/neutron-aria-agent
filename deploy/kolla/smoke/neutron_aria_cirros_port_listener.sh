#!/usr/bin/env bash
set -euo pipefail

GUEST_IP="${GUEST_IP:-}"
GUEST_SSH_USER="${GUEST_SSH_USER:-cirros}"
GUEST_SSH_PASSWORD="${GUEST_SSH_PASSWORD:-}"
GUEST_SSH_PORT="${GUEST_SSH_PORT:-22}"
PROTO="${PROTO:-tcp}"
PORT="${PORT:-}"
REMOTE_HELPER="${REMOTE_HELPER:-/tmp/aria-cirros-port-listener.sh}"
REMOTE_STATE_DIR="${REMOTE_STATE_DIR:-/tmp/aria-port-listeners}"
PROBE_TIMEOUT="${PROBE_TIMEOUT:-3}"

usage() {
    cat <<'EOF'
Usage:
  GUEST_IP=<vm-ip> PORT=<port> [PROTO=tcp|udp|both] [GUEST_SSH_PASSWORD=...] \
    bash deploy/kolla/smoke/neutron_aria_cirros_port_listener.sh start

  GUEST_IP=<vm-ip> PORT=<port> [PROTO=tcp|udp|both] bash ... stop
  GUEST_IP=<vm-ip> bash ... list
  GUEST_IP=<vm-ip> PORT=<port> [PROTO=tcp|udp] bash ... probe

Examples:
  GUEST_IP=192.0.2.10 PORT=8080 PROTO=tcp GUEST_SSH_PASSWORD='<guest-password>' bash \
    deploy/kolla/smoke/neutron_aria_cirros_port_listener.sh start

  GUEST_IP=192.0.2.10 PORT=5353 PROTO=udp GUEST_SSH_PASSWORD='<guest-password>' bash \
    deploy/kolla/smoke/neutron_aria_cirros_port_listener.sh start

  GUEST_IP=192.0.2.10 PORT=8080 PROTO=tcp bash \
    deploy/kolla/smoke/neutron_aria_cirros_port_listener.sh probe
EOF
}

die() {
    echo "ERROR: $*" >&2
    exit 1
}

need_command() {
    command -v "$1" >/dev/null 2>&1 || die "missing command: $1"
}

validate_proto() {
    case "$1" in
        tcp|udp|both) ;;
        *) die "PROTO must be tcp, udp, or both" ;;
    esac
}

validate_port() {
    [ -n "${PORT}" ] || die "PORT is required for this action"
    case "${PORT}" in
        *[!0-9]*|"") die "PORT must be numeric" ;;
    esac
    if [ "${PORT}" -lt 1 ] || [ "${PORT}" -gt 65535 ]; then
        die "PORT must be in range 1..65535"
    fi
}

ssh_base_args() {
    printf '%s\n' \
        -p "${GUEST_SSH_PORT}" \
        -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null \
        -o ConnectTimeout=8 \
        -o ServerAliveInterval=5 \
        -o ServerAliveCountMax=1
}

guest_ssh() {
    [ -n "${GUEST_IP}" ] || die "GUEST_IP is required"
    if [ -n "${GUEST_SSH_PASSWORD}" ]; then
        need_command sshpass
        # shellcheck disable=SC2046
        sshpass -p "${GUEST_SSH_PASSWORD}" ssh $(ssh_base_args) \
            "${GUEST_SSH_USER}@${GUEST_IP}" "$@"
    else
        # shellcheck disable=SC2046
        ssh $(ssh_base_args) "${GUEST_SSH_USER}@${GUEST_IP}" "$@"
    fi
}

install_remote_helper() {
    # The state/helper paths are deliberately expanded locally into remote assignments.
    # shellcheck disable=SC2029
    guest_ssh "STATE_DIR='${REMOTE_STATE_DIR}' HELPER='${REMOTE_HELPER}' sh -s" <<'REMOTE'
set -eu
mkdir -p "${STATE_DIR}"
cat > "${HELPER}" <<'HELPER_EOF'
#!/bin/sh
set -eu

STATE_DIR="${ARIA_LISTENER_STATE_DIR:-/tmp/aria-port-listeners}"
mkdir -p "${STATE_DIR}"

usage() {
    echo "usage: $0 start|stop|list tcp|udp|both [port]" >&2
}

pid_file() {
    echo "${STATE_DIR}/$1_$2.pid"
}

log_file() {
    echo "${STATE_DIR}/$1_$2.log"
}

is_running() {
    _pid_file="$1"
    [ -f "${_pid_file}" ] || return 1
    _pid="$(cat "${_pid_file}" 2>/dev/null || true)"
    [ -n "${_pid}" ] || return 1
    kill -0 "${_pid}" >/dev/null 2>&1
}

nc_supports_exec() {
    nc -h 2>&1 | grep -Eq '(^|[[:space:]])-e([[:space:],]|$)|exec'
}

listen_once() {
    _proto="$1"
    _port="$2"
    if nc_supports_exec; then
        if [ "${_proto}" = "tcp" ]; then
            nc -l -p "${_port}" -e /bin/cat
        else
            nc -u -l -p "${_port}" -e /bin/cat
        fi
        return
    fi

    # Fallback for minimal netcat builds without -e. TCP returns a banner so
    # connect tests can still prove reachability; UDP may not echo on all nc
    # variants, but it still keeps a userspace listener alive for ACL tests.
    if [ "${_proto}" = "tcp" ]; then
        printf 'aria-cirros tcp listener port=%s\n' "${_port}" | nc -l -p "${_port}"
    else
        printf 'aria-cirros udp listener port=%s\n' "${_port}" | nc -u -l -p "${_port}"
    fi
}

start_one() {
    _proto="$1"
    _port="$2"
    command -v nc >/dev/null 2>&1 || {
        echo "ERROR: nc not found in guest" >&2
        exit 1
    }
    _pid_file="$(pid_file "${_proto}" "${_port}")"
    _log_file="$(log_file "${_proto}" "${_port}")"
    if is_running "${_pid_file}"; then
        echo "already running proto=${_proto} port=${_port} pid=$(cat "${_pid_file}")"
        return
    fi
    (
        trap 'exit 0' INT TERM
        while true; do
            listen_once "${_proto}" "${_port}" >>"${_log_file}" 2>&1 || true
            sleep 0.2
        done
    ) >/dev/null 2>&1 &
    echo "$!" > "${_pid_file}"
    echo "started proto=${_proto} port=${_port} pid=$!"
}

stop_one() {
    _proto="$1"
    _port="$2"
    _pid_file="$(pid_file "${_proto}" "${_port}")"
    if ! is_running "${_pid_file}"; then
        rm -f "${_pid_file}"
        echo "not running proto=${_proto} port=${_port}"
        return
    fi
    _pid="$(cat "${_pid_file}")"
    kill "${_pid}" >/dev/null 2>&1 || true
    sleep 0.2
    kill -9 "${_pid}" >/dev/null 2>&1 || true
    rm -f "${_pid_file}"
    echo "stopped proto=${_proto} port=${_port} pid=${_pid}"
}

list_all() {
    found=0
    for f in "${STATE_DIR}"/*.pid; do
        [ -e "${f}" ] || continue
        found=1
        base="$(basename "${f}" .pid)"
        proto="$(echo "${base}" | awk -F_ '{print $1}')"
        port="$(echo "${base}" | awk -F_ '{print $2}')"
        if is_running "${f}"; then
            echo "running proto=${proto} port=${port} pid=$(cat "${f}")"
        else
            echo "stale proto=${proto} port=${port}"
        fi
    done
    [ "${found}" -eq 1 ] || echo "no listeners"
}

action="${1:-}"
proto="${2:-}"
port="${3:-}"

case "${action}" in
    start)
        [ -n "${proto}" ] && [ -n "${port}" ] || { usage; exit 1; }
        case "${proto}" in
            tcp|udp) start_one "${proto}" "${port}" ;;
            both) start_one tcp "${port}"; start_one udp "${port}" ;;
            *) usage; exit 1 ;;
        esac
        ;;
    stop)
        [ -n "${proto}" ] && [ -n "${port}" ] || { usage; exit 1; }
        case "${proto}" in
            tcp|udp) stop_one "${proto}" "${port}" ;;
            both) stop_one tcp "${port}"; stop_one udp "${port}" ;;
            *) usage; exit 1 ;;
        esac
        ;;
    list)
        list_all
        ;;
    *)
        usage
        exit 1
        ;;
esac
HELPER_EOF
chmod +x "${HELPER}"
REMOTE
}

probe_one() {
    local proto="$1"
    need_command nc
    need_command timeout
    if [ "${proto}" = "tcp" ]; then
        printf 'aria-probe tcp port=%s\n' "${PORT}" | \
            timeout "${PROBE_TIMEOUT}" nc -w "${PROBE_TIMEOUT}" "${GUEST_IP}" "${PORT}"
    else
        printf 'aria-probe udp port=%s\n' "${PORT}" | \
            timeout "${PROBE_TIMEOUT}" nc -u -w "${PROBE_TIMEOUT}" "${GUEST_IP}" "${PORT}"
    fi
}

action="${1:-}"
[ -n "${action}" ] || { usage; exit 1; }

case "${action}" in
    start)
        validate_proto "${PROTO}"
        validate_port
        install_remote_helper
        guest_ssh "'${REMOTE_HELPER}' start '${PROTO}' '${PORT}'"
        ;;
    stop)
        validate_proto "${PROTO}"
        validate_port
        install_remote_helper
        guest_ssh "'${REMOTE_HELPER}' stop '${PROTO}' '${PORT}'"
        ;;
    list)
        install_remote_helper
        guest_ssh "'${REMOTE_HELPER}' list"
        ;;
    probe)
        validate_proto "${PROTO}"
        validate_port
        [ "${PROTO}" != "both" ] || die "probe requires PROTO=tcp or PROTO=udp"
        probe_one "${PROTO}"
        ;;
    -h|--help|help)
        usage
        ;;
    *)
        usage
        exit 1
        ;;
esac
