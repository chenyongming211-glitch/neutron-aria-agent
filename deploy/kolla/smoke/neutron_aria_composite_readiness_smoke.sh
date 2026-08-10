#!/usr/bin/env bash
set -euo pipefail

AGENT_HOST="${AGENT_HOST:-$(hostname -f)}"
ADMINRC="${ADMINRC:-/root/adminrc}"
ARIA_PROBE_CONTAINER="${ARIA_PROBE_CONTAINER:-neutron_aria_agent}"
ARIA_PROBE_USER="${ARIA_PROBE_USER:-neutron}"
ARIA_SOCKET="${ARIA_SOCKET:-/run/aria/aria-agent.sock}"
REQUIRE_COMPOSITE_READY="${REQUIRE_COMPOSITE_READY:-true}"

if [ -r "${ADMINRC}" ]; then
    # shellcheck disable=SC1090
    source "${ADMINRC}"
fi

if ! command -v neutron >/dev/null 2>&1; then
    neutron() {
        docker exec \
            -u root \
            -e OS_USERNAME="${OS_USERNAME:-}" \
            -e OS_PASSWORD="${OS_PASSWORD:-}" \
            -e OS_TENANT_NAME="${OS_TENANT_NAME:-}" \
            -e OS_AUTH_URL="${OS_AUTH_URL:-}" \
            -e OS_NO_CACHE="${OS_NO_CACHE:-true}" \
            -e OS_AUTH_STRATEGY="${OS_AUTH_STRATEGY:-keystone}" \
            -e OS_REGION_NAME="${OS_REGION_NAME:-}" \
            -e NEUTRON_ENDPOINT_TYPE="${NEUTRON_ENDPOINT_TYPE:-publicURL}" \
            openstack_client neutron "$@"
    }
fi

if ! command -v docker >/dev/null 2>&1; then
    echo "missing command: docker" >&2
    exit 1
fi

HOST_PYTHON=""
for candidate in python3 python2 python; do
    if command -v "${candidate}" >/dev/null 2>&1; then
        HOST_PYTHON="${candidate}"
        break
    fi
done
if [ -z "${HOST_PYTHON}" ]; then
    echo "missing host Python interpreter" >&2
    exit 1
fi

uds_probe() {
    local endpoint="$1"
    docker exec -i -u "${ARIA_PROBE_USER}" "${ARIA_PROBE_CONTAINER}" \
        python - "${ARIA_SOCKET}" "${endpoint}" <<'PY'
from __future__ import print_function

import base64
import json
import socket
import sys

socket_path, endpoint = sys.argv[1:3]
client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
client.settimeout(5.0)
client.connect(socket_path)
request = "GET %s HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n" % endpoint
if sys.version_info[0] >= 3:
    request = request.encode("ascii")
client.sendall(request)
chunks = []
while True:
    chunk = client.recv(65536)
    if not chunk:
        break
    chunks.append(chunk)
client.close()

response = b"".join(chunks)
headers, body = response.split(b"\r\n\r\n", 1)
status_code = int(headers.split(b"\r\n", 1)[0].split()[1])
encoded_body = base64.b64encode(body)
if sys.version_info[0] >= 3:
    encoded_body = encoded_body.decode("ascii")
print(json.dumps({"http_status": status_code, "body_b64": encoded_body}))
PY
}

agent_line="$(neutron agent-list | grep "Aria ACL agent" | grep " ${AGENT_HOST} " || true)"
if [ -z "${agent_line}" ]; then
    echo "missing Aria ACL agent heartbeat row on ${AGENT_HOST}" >&2
    exit 1
fi

agent_id="$(echo "${agent_line}" | awk '{print $2}')"
heartbeat_alive=false
if echo "${agent_line}" | grep -F ':-)' >/dev/null; then
    heartbeat_alive=true
fi

status_result="$(uds_probe /api/v1/neutron/status)"
ready_result="$(uds_probe /readyz)"
agent_details="$(neutron agent-show "${agent_id}" -f json)"

STATUS_RESULT="${status_result}" \
READY_RESULT="${ready_result}" \
AGENT_DETAILS="${agent_details}" \
HEARTBEAT_ALIVE="${heartbeat_alive}" \
AGENT_HOST="${AGENT_HOST}" \
REQUIRE_COMPOSITE_READY="${REQUIRE_COMPOSITE_READY}" \
"${HOST_PYTHON}" - <<'PY'
from __future__ import print_function

import base64
import json
import os
import sys

try:
    string_types = (basestring,)
except NameError:
    string_types = (str,)


def decode_probe(name):
    result = json.loads(os.environ[name])
    body = base64.b64decode(result["body_b64"])
    if sys.version_info[0] >= 3:
        body = body.decode("utf-8")
    return int(result["http_status"]), json.loads(body)


def decode_agent_details():
    value = json.loads(os.environ["AGENT_DETAILS"])
    if isinstance(value, list):
        value = dict((row["Field"], row["Value"]) for row in value)
    configurations = value.get("configurations") or {}
    if isinstance(configurations, string_types):
        configurations = json.loads(configurations)
    return value, configurations


status_code, status_body = decode_probe("STATUS_RESULT")
ready_code, ready_body = decode_probe("READY_RESULT")
agent, configurations = decode_agent_details()
heartbeat_alive = os.environ["HEARTBEAT_ALIVE"] == "true"
require_ready = os.environ["REQUIRE_COMPOSITE_READY"] == "true"
overall_readiness = status_body.get("overall_readiness")
uds_ready = overall_readiness == "ready"
expected_ready_code = 200 if uds_ready else 503
errors = []

if status_code != 200:
    errors.append("status endpoint returned HTTP %s" % status_code)
if status_body != ready_body:
    errors.append("/readyz body differs from Status V1")
if ready_code != expected_ready_code:
    errors.append("/readyz returned HTTP %s for readiness=%s" % (ready_code, overall_readiness))
if bool(configurations.get("ready")) != uds_ready:
    errors.append("heartbeat ready=%r differs from UDS readiness=%s" % (
        configurations.get("ready"), overall_readiness))

composite_ready = uds_ready and heartbeat_alive
if require_ready and not composite_ready:
    errors.append("composite readiness is false")

print("agent_host=%s" % os.environ["AGENT_HOST"])
print("agent_id=%s" % agent.get("id", "unknown"))
print("heartbeat_alive=%s" % str(heartbeat_alive).lower())
print("heartbeat_timestamp=%s" % agent.get("heartbeat_timestamp", "unknown"))
print("uds_overall_readiness=%s" % overall_readiness)
print("uds_status_http=%s" % status_code)
print("uds_readyz_http=%s" % ready_code)
print("status_bodies_equal=%s" % str(status_body == ready_body).lower())
print("accepted_generation=%s" % status_body.get("accepted_generation"))
print("applied_generation=%s" % status_body.get("applied_generation"))
print("composite_ready=%s" % str(composite_ready).lower())

if errors:
    for error in errors:
        print("ERROR: %s" % error, file=sys.stderr)
    sys.exit(1)
PY
