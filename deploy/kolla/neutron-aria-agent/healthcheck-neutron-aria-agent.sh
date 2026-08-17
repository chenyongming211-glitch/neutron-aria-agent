#!/bin/sh
set -eu

socket_path="${ARIA_HEALTH_SOCKET_PATH:-/run/aria/aria-agent.sock}"
ready_url="${ARIA_HEALTH_READY_URL:-http://localhost/readyz}"

test -S "${socket_path}"
curl -fsS --max-time 4 \
    --unix-socket "${socket_path}" "${ready_url}" >/dev/null
