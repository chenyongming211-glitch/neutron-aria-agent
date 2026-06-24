#!/usr/bin/env bash
set -euo pipefail

SERVICE_NAME="${SERVICE_NAME:-neutron_aria_agent}"
REPO_ROOT="${REPO_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)}"
SOCKET_PATH="${SOCKET_PATH:-/run/aria/aria-agent.sock}"
DATAPATH_HTTP="${DATAPATH_HTTP:-http://127.0.0.1:8080}"
EXEC_USER="${EXEC_USER:-neutron}"
VM_IP="${VM_IP:-}"
EXPECTED_PORT_ID="${EXPECTED_PORT_ID:-}"
EXPECTED_IFNAME="${EXPECTED_IFNAME:-}"
BLOCK_SRC_CIDR="${BLOCK_SRC_CIDR:-}"
ACL_DIRECTION="${ACL_DIRECTION:-ingress}"
ACL_PROTOCOL="${ACL_PROTOCOL:-icmp}"
PING_COUNT="${PING_COUNT:-2}"
PING_TIMEOUT="${PING_TIMEOUT:-1}"

die() {
    echo "ERROR: $*" >&2
    exit 1
}

need_command() {
    command -v "$1" >/dev/null 2>&1 || die "missing command: $1"
}

docker_agent_exec() {
    docker exec -i -u "${EXEC_USER}" "${SERVICE_NAME}" "$@"
}

route_source_cidr() {
    local route_line source_ip
    route_line="$(ip route get "${VM_IP}" 2>/dev/null | head -1 || true)"
    source_ip="$(printf '%s\n' "${route_line}" | awk '{
        for (i = 1; i <= NF; i++) {
            if ($i == "src") {
                print $(i + 1)
                exit
            }
        }
    }')"
    [ -n "${source_ip}" ] || return 1
    printf '%s/32\n' "${source_ip}"
}

build_acl_fixture() {
    local port_id="$1"
    local source_cidr="$2"
    local direction="$3"
    local protocol="$4"
    "${PYTHON_BIN}" - "${port_id}" "${source_cidr}" "${direction}" "${protocol}" <<'PY'
from __future__ import print_function

import json
import sys

port_id, source_cidr, direction, protocol = sys.argv[1:5]
print(json.dumps({
    "policies": [{
        "id": "acl-smoke-policy",
        "name": "acl-smoke-policy",
        "default_action": "allow",
        "stateful": True,
        "revision_number": 1,
    }],
    "rules": [{
        "id": "drop-smoke-%s" % protocol,
        "policy_id": "acl-smoke-policy",
        "direction": direction,
        "priority": 100,
        "action": "drop",
        "ethertype": "IPv4",
        "protocol": protocol,
        "src_cidr": source_cidr,
        "enabled": True,
        "revision_number": 1,
    }],
    "address_sets": [],
    "bindings": [{
        "id": "acl-smoke-binding",
        "policy_id": "acl-smoke-policy",
        "target_type": "port",
        "target_id": port_id,
        "enabled": True,
        "revision_number": 1,
    }],
}, sort_keys=True))
PY
}

rollback_managed_ports() {
    docker_agent_exec python - "${SOCKET_PATH}" <<'PY'
from __future__ import print_function

import sys

from neutron_aria.agent.uds_client import LocalClient

client = LocalClient(sys.argv[1], timeout=3.0)
status = client.status()
for port in status.get("managed_ports") or []:
    port_id = port.get("port_id")
    if port_id:
        response = client.delete_port(port_id)
        print("rollback_delete port_id=%s status=%s detached=%s" % (
            response.get("port_id"),
            response.get("status"),
            response.get("detached"),
        ))
after = client.status()
remaining = after.get("managed_ports") or []
print("rollback_remaining_managed_ports=%d" % len(remaining))
if remaining:
    raise SystemExit(1)
PY
}

show_acl_state() {
    "${PYTHON_BIN}" - "${DATAPATH_HTTP}" "${EXPECTED_IFNAME}" <<'PY'
from __future__ import print_function

import json
import sys

try:
    from urllib import quote as urlquote
    from urllib2 import urlopen
except ImportError:
    from urllib.parse import quote as urlquote
    from urllib.request import urlopen

base = sys.argv[1].rstrip("/")
ifname = sys.argv[2]
encoded = urlquote(ifname, safe="")
groups = json.loads(urlopen("%s/api/v1/%s/groups" % (base, encoded)).read()).get("groups") or []
policies = json.loads(urlopen("%s/api/v1/%s/policies" % (base, encoded)).read()).get("policies") or []
print("acl_groups=%s" % json.dumps(groups, sort_keys=True))
print("acl_policies=%s" % json.dumps(policies, sort_keys=True))
if not policies:
    raise SystemExit("expected at least one ACL policy")
if not any(policy.get("action") == "drop" for policy in policies):
    raise SystemExit("expected a drop ACL policy")
PY
}

cleanup() {
    if [ "${ROLLBACK_ARMED:-false}" = "true" ]; then
        echo "Cleaning up ACL smoke managed port"
        rollback_managed_ports || true
    fi
}

trap cleanup EXIT

need_command docker
need_command ping
need_command ip
if [ -z "${PYTHON_BIN:-}" ]; then
    PYTHON_BIN="$(command -v python3 || command -v python || true)"
fi
[ -n "${PYTHON_BIN}" ] || die "missing command: python3 or python"

[ -n "${VM_IP}" ] || die "VM_IP is required"
[ -n "${EXPECTED_PORT_ID}" ] || die "EXPECTED_PORT_ID is required"
[ -n "${EXPECTED_IFNAME}" ] || die "EXPECTED_IFNAME is required"

if [ -z "${BLOCK_SRC_CIDR}" ]; then
    BLOCK_SRC_CIDR="$(route_source_cidr)" || die "failed to infer source IP for ${VM_IP}; set BLOCK_SRC_CIDR"
fi

echo "Pre-check: VM ${VM_IP} must be reachable before ACL is applied"
ping -c "${PING_COUNT}" -W "${PING_TIMEOUT}" "${VM_IP}" >/dev/null

acl_fixture_json="$(build_acl_fixture "${EXPECTED_PORT_ID}" "${BLOCK_SRC_CIDR}" "${ACL_DIRECTION}" "${ACL_PROTOCOL}")"

echo "Applying ACL full-resync fixture port=${EXPECTED_PORT_ID} ifname=${EXPECTED_IFNAME} src=${BLOCK_SRC_CIDR} direction=${ACL_DIRECTION} protocol=${ACL_PROTOCOL}"
ACL_FIXTURE_JSON="${acl_fixture_json}" \
    ROLLBACK=false \
    MIN_MANAGED_PORTS=1 \
    EXPECTED_PORT_ID="${EXPECTED_PORT_ID}" \
    EXPECTED_IFNAME="${EXPECTED_IFNAME}" \
    bash "${REPO_ROOT}/deploy/kolla/smoke/neutron_aria_full_resync_smoke.sh"

ROLLBACK_ARMED=true

echo "Checking datapath ACL policy state"
show_acl_state

echo "Checking that ACL blocks ${ACL_PROTOCOL} traffic"
if ping -c "${PING_COUNT}" -W "${PING_TIMEOUT}" "${VM_IP}" >/dev/null; then
    die "ACL did not block ping to ${VM_IP}"
fi

echo "Rolling back ACL smoke managed port"
rollback_managed_ports
ROLLBACK_ARMED=false

echo "Post-check: VM ${VM_IP} must recover after rollback"
ping -c "${PING_COUNT}" -W "${PING_TIMEOUT}" "${VM_IP}" >/dev/null

echo "neutron-aria-agent ACL full-resync smoke passed for ${EXPECTED_PORT_ID}"
