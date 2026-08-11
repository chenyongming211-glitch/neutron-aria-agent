#!/usr/bin/env bash
set -euo pipefail

ARIA_PROBE_CONTAINER="${ARIA_PROBE_CONTAINER:-neutron_aria_agent}"
ARIA_PROBE_USER="${ARIA_PROBE_USER:-neutron}"
ARIA_SOCKET="${ARIA_SOCKET:-/run/aria/aria-agent.sock}"
EXPECTED_TRANSACTION_STATE="${EXPECTED_TRANSACTION_STATE:-}"
EXPECTED_OVERALL_READINESS="${EXPECTED_OVERALL_READINESS:-}"
EXPECTED_REQUIRED_ACTION="${EXPECTED_REQUIRED_ACTION:-}"

die() {
    echo "ERROR: $*" >&2
    exit 1
}

command -v docker >/dev/null 2>&1 || die "missing command: docker"
docker ps --format '{{.Names}}' | grep -Fx "${ARIA_PROBE_CONTAINER}" >/dev/null || \
    die "probe container is not running: ${ARIA_PROBE_CONTAINER}"
[ -n "${EXPECTED_TRANSACTION_STATE}" ] || die "EXPECTED_TRANSACTION_STATE is required"
[ -n "${EXPECTED_OVERALL_READINESS}" ] || die "EXPECTED_OVERALL_READINESS is required"
[ -n "${EXPECTED_REQUIRED_ACTION}" ] || die "EXPECTED_REQUIRED_ACTION is required"

docker exec -i -u "${ARIA_PROBE_USER}" "${ARIA_PROBE_CONTAINER}" \
    python - "${ARIA_SOCKET}" "${EXPECTED_TRANSACTION_STATE}" \
    "${EXPECTED_OVERALL_READINESS}" "${EXPECTED_REQUIRED_ACTION}" <<'PY'
from __future__ import print_function

import json
import socket
import sys


socket_path, expected_transaction, expected_readiness, expected_action = sys.argv[1:5]


def probe(endpoint):
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
    if sys.version_info[0] >= 3:
        body = body.decode("utf-8")
    return status_code, json.loads(body)


status_code, status_body = probe("/api/v1/neutron/status")
ready_code, ready_body = probe("/readyz")
expected_ready_code = 200 if expected_readiness == "ready" else 503
errors = []

if status_code != 200:
    errors.append("status endpoint returned HTTP %s" % status_code)
if status_body != ready_body:
    errors.append("/readyz body differs from Status V1")
if ready_code != expected_ready_code:
    errors.append("/readyz returned HTTP %s; expected %s" % (
        ready_code, expected_ready_code))
if status_body.get("transaction_state") != expected_transaction:
    errors.append("transaction_state=%r; expected %r" % (
        status_body.get("transaction_state"), expected_transaction))
if status_body.get("overall_readiness") != expected_readiness:
    errors.append("overall_readiness=%r; expected %r" % (
        status_body.get("overall_readiness"), expected_readiness))
if status_body.get("required_action") != expected_action:
    errors.append("required_action=%r; expected %r" % (
        status_body.get("required_action"), expected_action))

print("transaction_state=%s" % status_body.get("transaction_state"))
print("overall_readiness=%s" % status_body.get("overall_readiness"))
print("required_action=%s" % status_body.get("required_action"))
print("status_http=%s" % status_code)
print("readyz_http=%s" % ready_code)
print("status_bodies_equal=%s" % str(status_body == ready_body).lower())
print("accepted_generation=%s" % status_body.get("accepted_generation"))
print("applied_generation=%s" % status_body.get("applied_generation"))
print("pending_generation=%s" % status_body.get("pending_generation"))

if errors:
    for error in errors:
        print("ERROR: %s" % error, file=sys.stderr)
    raise SystemExit(1)
PY
