#!/usr/bin/env sh
set -eu

LOG_DIR="${NEUTRON_ARIA_LOG_DIR:-/var/log/kolla/neutron}"
LOG_FILE="${NEUTRON_ARIA_LOG_FILE:-${LOG_DIR}/neutron-aria-agent.log}"

mkdir -p "${LOG_DIR}"
touch "${LOG_FILE}"
chmod 0640 "${LOG_FILE}" 2>/dev/null || true

echo "$(date -u '+%Y-%m-%dT%H:%M:%SZ') starting neutron-aria-agent $*" >>"${LOG_FILE}"
exec neutron-aria-agent "$@" >>"${LOG_FILE}" 2>&1
