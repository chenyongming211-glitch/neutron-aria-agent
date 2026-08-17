#!/bin/sh
set -eu

socket_path="${ARIA_HEALTH_SOCKET_PATH:-/run/aria/aria-agent.sock}"
tcp_health_url="${ARIA_HEALTH_TCP_URL:-http://127.0.0.1:8080/api/v1/health}"
ready_url="${ARIA_HEALTH_READY_URL:-http://localhost/readyz}"

test -S "${socket_path}"
curl -fsS --max-time 4 "${tcp_health_url}" >/dev/null
sudo -u neutron curl -fsS --max-time 4 \
    --unix-socket "${socket_path}" "${ready_url}" >/dev/null
