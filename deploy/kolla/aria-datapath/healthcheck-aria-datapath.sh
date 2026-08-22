#!/bin/sh
set -eu

socket_path="${ARIA_HEALTH_SOCKET_PATH:-/run/aria/aria-agent.sock}"
tcp_livez_url="${ARIA_HEALTH_TCP_LIVEZ_URL:-http://127.0.0.1:8080/api/v1/livez}"
uds_livez_url="${ARIA_HEALTH_UDS_LIVEZ_URL:-http://localhost/livez}"
ready_url="${ARIA_HEALTH_READY_URL:-http://localhost/readyz}"

test -S "${socket_path}"
curl -fsS --max-time 4 "${tcp_livez_url}" >/dev/null
sudo -u neutron curl -fsS --max-time 4 \
    --unix-socket "${socket_path}" "${uds_livez_url}" >/dev/null
# /livez is diagnostic only; Docker health authority remains /readyz.
sudo -u neutron curl -fsS --max-time 4 \
    --unix-socket "${socket_path}" "${ready_url}" >/dev/null
