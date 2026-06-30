#!/usr/bin/env bash
set -euo pipefail

TEST_IMAGE="${TEST_IMAGE:?TEST_IMAGE is required, for example aria-datapath:peercred-test}"
SERVICE_NAME="${SERVICE_NAME:-aria_datapath}"
AGENT_SERVICE="${AGENT_SERVICE:-neutron_aria_agent}"
CONFIG_PATH="${CONFIG_PATH:-/etc/kolla/aria-datapath/aria-agent-openstack.toml}"
SOCKET_PATH="${SOCKET_PATH:-/run/aria/aria-agent.sock}"
RUN_ARIA_DIR="${RUN_ARIA_DIR:-/run/aria}"
HARDENING_SMOKE_SCRIPT="${HARDENING_SMOKE_SCRIPT:-}"
RESTORE_AFTER_TEST="${RESTORE_AFTER_TEST:-true}"
EVIDENCE_ROOT="${EVIDENCE_ROOT:-/var/tmp/neutron-aria-uds-hardened-rollout}"
HOST_FQDN="${HOST_FQDN:-$(hostname -f 2>/dev/null || hostname)}"
STAMP="$(date +%Y%m%d%H%M%S)"
EVIDENCE_DIR="${EVIDENCE_DIR:-${EVIDENCE_ROOT}/${STAMP}-${HOST_FQDN}}"

mkdir -p "${EVIDENCE_DIR}"
exec > >(tee -a "${EVIDENCE_DIR}/rollout.log") 2>&1

log() {
    printf '[neutron-aria-uds-hardened-rollout] %s\n' "$*"
}

container_exists() {
    docker ps -a --format '{{.Names}}' | grep -qx "$1"
}

container_running() {
    docker ps --format '{{.Names}}' | grep -qx "$1"
}

backup_container=""
config_backup=""
run_aria_owner=""
run_aria_mode=""

restore_original() {
    set +e
    log "Restoring original aria datapath container and config"
    if [ -n "${config_backup}" ] && [ -f "${config_backup}" ]; then
        cp "${config_backup}" "${CONFIG_PATH}"
    fi
    if [ -n "${run_aria_owner}" ]; then
        chown "${run_aria_owner}" "${RUN_ARIA_DIR}" 2>/dev/null || true
    fi
    if [ -n "${run_aria_mode}" ]; then
        chmod "${run_aria_mode}" "${RUN_ARIA_DIR}" 2>/dev/null || true
    fi
    if container_exists "${SERVICE_NAME}"; then
        docker rm -f "${SERVICE_NAME}" >/dev/null 2>&1 || true
    fi
    if [ -n "${backup_container}" ] && container_exists "${backup_container}"; then
        docker rename "${backup_container}" "${SERVICE_NAME}" >/dev/null 2>&1 || true
        docker start "${SERVICE_NAME}" >/dev/null 2>&1 || true
    fi
}

on_exit() {
    rc=$?
    if [ "${RESTORE_AFTER_TEST}" = "true" ]; then
        restore_original
    else
        log "RESTORE_AFTER_TEST=false; leaving ${SERVICE_NAME} on ${TEST_IMAGE}"
    fi
    log "Result rc=${rc}; evidence=${EVIDENCE_DIR}"
    exit "${rc}"
}
trap on_exit EXIT

command -v docker >/dev/null 2>&1 || {
    echo "docker is required" >&2
    exit 1
}

if ! container_running "${SERVICE_NAME}"; then
    echo "${SERVICE_NAME} must be running before rollout smoke" >&2
    exit 1
fi
if ! container_running "${AGENT_SERVICE}"; then
    echo "${AGENT_SERVICE} must be running before rollout smoke" >&2
    exit 1
fi
if [ ! -f "${CONFIG_PATH}" ]; then
    echo "missing config: ${CONFIG_PATH}" >&2
    exit 1
fi

log "Recording pre-rollout evidence"
docker inspect "${SERVICE_NAME}" >"${EVIDENCE_DIR}/${SERVICE_NAME}-inspect-before.json"
docker inspect "${AGENT_SERVICE}" >"${EVIDENCE_DIR}/${AGENT_SERVICE}-inspect-before.json"
cp "${CONFIG_PATH}" "${EVIDENCE_DIR}/aria-agent-openstack-before.toml"
stat -c "%n %U %G %u %g %a %F" "${RUN_ARIA_DIR}" >"${EVIDENCE_DIR}/run-aria-before.txt"
stat -c "%n %U %G %u %g %a %F" "${SOCKET_PATH}" >>"${EVIDENCE_DIR}/run-aria-before.txt" 2>/dev/null || true

config_backup="${CONFIG_PATH}.bak-${STAMP}"
cp "${CONFIG_PATH}" "${config_backup}"
run_aria_owner="$(stat -c '%u:%g' "${RUN_ARIA_DIR}")"
run_aria_mode="$(stat -c '%a' "${RUN_ARIA_DIR}")"

neutron_uid="$(docker exec -u root "${AGENT_SERVICE}" id -u neutron)"
neutron_gid="$(docker exec -u root "${AGENT_SERVICE}" id -g neutron)"
neutron_groups="$(docker exec -u root "${AGENT_SERVICE}" id -G neutron)"
{
    echo "neutron_uid=${neutron_uid}"
    echo "neutron_gid=${neutron_gid}"
    echo "neutron_groups=${neutron_groups}"
} >"${EVIDENCE_DIR}/peercred-allow-list-inputs.txt"

log "Writing hardened datapath config"
tmp_config="${CONFIG_PATH}.tmp-${STAMP}"
grep -Ev '^[[:space:]]*(neutron_socket_mode|neutron_peercred_enforce|neutron_peercred_allowed_uids|neutron_peercred_allowed_gids|neutron_audit_log_path)[[:space:]]*=' \
    "${config_backup}" >"${tmp_config}"
cat >>"${tmp_config}" <<EOF

# Stage-two G4 hardened UDS rollout smoke.
neutron_socket_mode = 432
neutron_peercred_enforce = true
neutron_peercred_allowed_uids = [${neutron_uid}]
neutron_peercred_allowed_gids = [${neutron_gid}]
neutron_audit_log_path = "/var/log/kolla/aria-datapath/neutron-uds-audit.log"
EOF
mv "${tmp_config}" "${CONFIG_PATH}"
cp "${CONFIG_PATH}" "${EVIDENCE_DIR}/aria-agent-openstack-hardened.toml"

chgrp "${neutron_gid}" "${RUN_ARIA_DIR}"
chmod 0770 "${RUN_ARIA_DIR}"

backup_container="${SERVICE_NAME}_pre_hardened_${STAMP}"
if container_exists "${backup_container}"; then
    docker rm -f "${backup_container}" >/dev/null 2>&1 || true
fi

log "Replacing ${SERVICE_NAME} with ${TEST_IMAGE}"
docker stop "${SERVICE_NAME}" >/dev/null
docker rename "${SERVICE_NAME}" "${backup_container}"
if [ -S "${SOCKET_PATH}" ]; then
    rm -f "${SOCKET_PATH}"
fi
docker run -d \
    --name "${SERVICE_NAME}" \
    --restart unless-stopped \
    --network host \
    --pid host \
    --cgroupns host \
    --privileged \
    --security-opt label=disable \
    -e KOLLA_CONFIG_STRATEGY=COPY_ALWAYS \
    -e KOLLA_SERVICE_NAME=aria-datapath \
    -v /sys/fs/cgroup \
    -v /var/lib/aria-agent-smoke:/var/lib/aria-agent:rw \
    -v /sys/kernel/btf/vmlinux:/sys/kernel/btf/vmlinux:ro \
    -v /etc/kolla/aria-datapath/:/var/lib/kolla/config_files/:ro \
    -v /etc/localtime:/etc/localtime:ro \
    -v kolla_logs:/var/log/kolla/:rw \
    -v /run/aria:/run/aria:rw \
    -v /run/openvswitch:/run/openvswitch:shared \
    -v /sys/fs/bpf:/sys/fs/bpf:shared \
    --entrypoint dumb-init \
    "${TEST_IMAGE}" --single-child -- kolla_start >/dev/null

for _ in $(seq 1 45); do
    if container_running "${SERVICE_NAME}" &&
        docker exec "${SERVICE_NAME}" test -S "${SOCKET_PATH}" &&
        [ "$(stat -c '%a' "${SOCKET_PATH}" 2>/dev/null || true)" = "660" ] &&
        [ "$(stat -c '%g' "${SOCKET_PATH}" 2>/dev/null || true)" = "${neutron_gid}" ]; then
        break
    fi
    sleep 1
done

docker ps --filter "name=${SERVICE_NAME}" >"${EVIDENCE_DIR}/docker-ps-hardened.txt"
docker logs --tail 120 "${SERVICE_NAME}" >"${EVIDENCE_DIR}/datapath-log-hardened.txt" 2>&1 || true
stat -c "%n %U %G %u %g %a %F" "${RUN_ARIA_DIR}" >"${EVIDENCE_DIR}/run-aria-hardened.txt"
stat -c "%n %U %G %u %g %a %F" "${SOCKET_PATH}" >>"${EVIDENCE_DIR}/run-aria-hardened.txt"

socket_mode="$(stat -c '%a' "${SOCKET_PATH}")"
socket_gid="$(stat -c '%g' "${SOCKET_PATH}")"
if [ "${socket_mode}" != "660" ]; then
    echo "expected ${SOCKET_PATH} mode 660, got ${socket_mode}" >&2
    exit 1
fi
if [ "${socket_gid}" != "${neutron_gid}" ]; then
    echo "expected ${SOCKET_PATH} gid ${neutron_gid}, got ${socket_gid}" >&2
    exit 1
fi

log "Probing UDS from ${AGENT_SERVICE} as neutron user"
docker exec -u neutron "${AGENT_SERVICE}" python -c '
import socket
import sys

sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
sock.settimeout(5)
sock.connect("/run/aria/aria-agent.sock")
sock.sendall(b"GET /api/v1/neutron/status HTTP/1.1\r\nHost: neutron\r\nConnection: close\r\n\r\n")
data = sock.recv(4096)
sys.stdout.write(repr(data[:512]) + "\n")
sock.close()
' >"${EVIDENCE_DIR}/authorized-uds-probe.txt" 2>&1

log_mount="$(docker inspect "${SERVICE_NAME}" --format '{{range .Mounts}}{{if eq .Destination "/var/log/kolla"}}{{.Source}}{{end}}{{end}}')"
audit_log_path="${log_mount}/aria-datapath/neutron-uds-audit.log"
if [ ! -f "${audit_log_path}" ]; then
    echo "audit log missing at ${audit_log_path}" >&2
    exit 1
fi
tail -n 50 "${audit_log_path}" >"${EVIDENCE_DIR}/audit-tail.txt"
grep -Eq '"result"[[:space:]]*:[[:space:]]*"allowed"' "${EVIDENCE_DIR}/audit-tail.txt"
grep -Eq '"reason"[[:space:]]*:[[:space:]]*"peercred_allow_list_match"' "${EVIDENCE_DIR}/audit-tail.txt"

if [ -n "${HARDENING_SMOKE_SCRIPT}" ]; then
    log "Running hardening evidence smoke with REQUIRE_HARDENED=true"
    REQUIRE_HARDENED=true \
        AUDIT_LOG_PATH="${audit_log_path}" \
        "${HARDENING_SMOKE_SCRIPT}" >"${EVIDENCE_DIR}/hardening-smoke.log" 2>&1
fi

log "Hardened rollout smoke passed"
