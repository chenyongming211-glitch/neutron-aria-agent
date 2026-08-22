#!/bin/sh
set -eu

socket_path="${ARIA_HEALTH_SOCKET_PATH:-/run/aria/aria-agent.sock}"
liveness_record="${ARIA_SERVICE_LIVENESS_RECORD:-/var/lib/neutron-aria-agent/state/service-liveness.json}"
service_pid="${ARIA_SERVICE_PID:-1}"
python_bin="${ARIA_HEALTH_PYTHON_BIN:-python}"
livez_url="${ARIA_HEALTH_LIVEZ_URL:-http://localhost/livez}"
ready_url="${ARIA_HEALTH_READY_URL:-http://localhost/readyz}"

"${python_bin}" -m neutron_aria.agent.liveness \
    --record "${liveness_record}" --expected-pid "${service_pid}"
test -S "${socket_path}"
curl -fsS --max-time 4 \
    --unix-socket "${socket_path}" "${livez_url}" >/dev/null
# /livez is diagnostic only; Docker health authority remains /readyz.
curl -fsS --max-time 4 \
    --unix-socket "${socket_path}" "${ready_url}" >/dev/null
