#!/usr/bin/env sh
set -eu

LOG_DIR="${ARIA_DATAPATH_LOG_DIR:-/var/log/kolla/aria-datapath}"
LOG_FILE="${ARIA_DATAPATH_LOG_FILE:-${LOG_DIR}/aria-datapath.log}"
CONFIG_FILE="${ARIA_DATAPATH_CONFIG_FILE:-/etc/aria-agent/config.toml}"

mkdir -p "${LOG_DIR}"
touch "${LOG_FILE}"
chmod 0640 "${LOG_FILE}" 2>/dev/null || true

echo "$(date -u '+%Y-%m-%dT%H:%M:%SZ') starting aria-datapath --config ${CONFIG_FILE}" >>"${LOG_FILE}"
exec aria-agent --config "${CONFIG_FILE}" >>"${LOG_FILE}" 2>&1
