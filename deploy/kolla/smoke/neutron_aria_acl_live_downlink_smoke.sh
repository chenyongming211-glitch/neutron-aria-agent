#!/usr/bin/env bash
set -euo pipefail

SERVICE_NAME="${SERVICE_NAME:-neutron_aria_agent}"
EXEC_USER="${EXEC_USER:-neutron}"
ADMIN_RC_FILE="${ADMIN_RC_FILE:-/etc/kolla/.adminrc}"
LOCAL_NEUTRON_URL="${LOCAL_NEUTRON_URL:-http://127.0.0.1:9696/v2.0}"
DATAPATH_HTTP="${DATAPATH_HTTP:-http://127.0.0.1:8080}"
AGENT_CONFIG="${AGENT_CONFIG:-/etc/neutron-aria-agent/neutron-aria-agent.ini}"
ACL_PROTOCOL="${ACL_PROTOCOL:-icmp}"
ACL_DIRECTION="${ACL_DIRECTION:-ingress}"
PING_COUNT="${PING_COUNT:-3}"
PING_TIMEOUT="${PING_TIMEOUT:-1}"
REQUIRE_STATUS_IDENTITY="${REQUIRE_STATUS_IDENTITY:-true}"
VM_IP="${VM_IP:-}"
EXPECTED_PORT_ID="${EXPECTED_PORT_ID:-}"
EXPECTED_IFNAME="${EXPECTED_IFNAME:-}"
BLOCK_SRC_CIDR="${BLOCK_SRC_CIDR:-}"
BLOCK_DST_CIDR="${BLOCK_DST_CIDR:-}"

die() {
    echo "ERROR: $*" >&2
    exit 1
}

need_command() {
    command -v "$1" >/dev/null 2>&1 || die "missing command: $1"
}

json_field() {
    "${PYTHON_BIN}" -c 'from __future__ import print_function
import json
import sys
field = sys.argv[1]
payload = json.load(sys.stdin)
value = payload
for part in field.split("."):
    value = value.get(part) if isinstance(value, dict) else None
print(value or "")' "$1"
}

curl_body() {
    local method="$1"
    local path="$2"
    local data="${3:-}"
    if [ -n "${data}" ]; then
        curl -sS -H "X-Auth-Token: ${TOKEN}" -H 'Content-Type: application/json' \
            -X "${method}" -d "${data}" "${LOCAL_NEUTRON_URL}/${path}"
    else
        curl -sS -H "X-Auth-Token: ${TOKEN}" -X "${method}" \
            "${LOCAL_NEUTRON_URL}/${path}"
    fi
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

traffic_check() {
    ping -c "${PING_COUNT}" -W "${PING_TIMEOUT}" "${VM_IP}"
}

run_full_resync() {
    docker exec -u "${EXEC_USER}" "${SERVICE_NAME}" \
        neutron-aria-agent \
        --config-file "${AGENT_CONFIG}" \
        --once \
        --enable-full-resync
}

datapath_policies() {
    curl -sS "${DATAPATH_HTTP}/api/v1/${EXPECTED_IFNAME}/policies"
}

assert_datapath_drop() {
    local policies
    policies="$(datapath_policies)"
    printf '%s\n' "${policies}"
    printf '%s\n' "${policies}" | grep -q '"action":"drop"' || \
        die "datapath policy for ${EXPECTED_IFNAME} does not contain a drop rule"
}

assert_datapath_clear() {
    local policies
    policies="$(datapath_policies)"
    printf '%s\n' "${policies}"
    if printf '%s\n' "${policies}" | grep -q '"action":"drop"'; then
        die "datapath policy for ${EXPECTED_IFNAME} still contains a drop rule"
    fi
}

assert_port_status_identity() {
    [ "${REQUIRE_STATUS_IDENTITY}" = "true" ] || return 0
    local status_payload
    status_payload="$(curl_body GET aria-acl-port-statuses)"
    STATUS_PAYLOAD="${status_payload}" "${PYTHON_BIN}" - \
        "${EXPECTED_PORT_ID}" "${policy_id}" "${binding_id}" <<'PY'
from __future__ import print_function

import json
import os
import sys

port_id, expected_policy_id, expected_binding_id = sys.argv[1:4]
payload = json.loads(os.environ["STATUS_PAYLOAD"])
rows = [
    row for row in payload.get("aria_acl_port_statuses") or []
    if row.get("port_id") == port_id and row.get("status") == "ready"
]
if not rows:
    raise SystemExit("missing ready aria_acl_port_status for %s" % port_id)
row = rows[0]
print("aria_acl_port_status=%s" % json.dumps(row, sort_keys=True))
if row.get("effective_policy_id") != expected_policy_id:
    raise SystemExit(
        "effective_policy_id mismatch: %r != %r" %
        (row.get("effective_policy_id"), expected_policy_id)
    )
if row.get("binding_id") != expected_binding_id:
    raise SystemExit(
        "binding_id mismatch: %r != %r" %
        (row.get("binding_id"), expected_binding_id)
    )
PY
}

cleanup_acl() {
    set +e
    if [ -n "${binding_id:-}" ]; then
        curl_body DELETE "aria-acl-bindings/${binding_id}" >/dev/null 2>&1
    fi
    if [ -n "${rule_id:-}" ]; then
        curl_body DELETE "aria-acl-rules/${rule_id}" >/dev/null 2>&1
    fi
    if [ -n "${policy_id:-}" ]; then
        curl_body DELETE "aria-acl-policies/${policy_id}" >/dev/null 2>&1
    fi
    if [ "${RESYNC_ROLLBACK_ARMED:-false}" = "true" ]; then
        run_full_resync >/dev/null 2>&1 || true
    fi
}

need_command docker
need_command curl
need_command ip
need_command ping
if [ -z "${PYTHON_BIN:-}" ]; then
    PYTHON_BIN="$(command -v python3 || command -v python || true)"
fi
[ -n "${PYTHON_BIN}" ] || die "missing command: python3 or python"

[ -n "${VM_IP}" ] || die "VM_IP is required"
[ -n "${EXPECTED_PORT_ID}" ] || die "EXPECTED_PORT_ID is required"
[ -n "${EXPECTED_IFNAME}" ] || die "EXPECTED_IFNAME is required"

if [ -z "${BLOCK_SRC_CIDR}" ] && [ "${ACL_DIRECTION}" = "ingress" ]; then
    BLOCK_SRC_CIDR="$(route_source_cidr)" || \
        die "failed to infer source IP for ${VM_IP}; set BLOCK_SRC_CIDR"
fi
if [ -z "${BLOCK_SRC_CIDR}" ] && [ -z "${BLOCK_DST_CIDR}" ]; then
    die "BLOCK_SRC_CIDR or BLOCK_DST_CIDR is required for direction=${ACL_DIRECTION}"
fi

TOKEN="$(docker exec -u root --env-file "${ADMIN_RC_FILE}" \
    openstack_client openstack token issue -f value -c id | tail -1)"
[ -n "${TOKEN}" ] || die "failed to obtain OpenStack token"

policy_id=""
rule_id=""
binding_id=""
RESYNC_ROLLBACK_ARMED=false
trap cleanup_acl EXIT

echo "Pre-check: ${VM_IP} must be reachable before ACL apply"
traffic_check >/dev/null

policy_body='{"aria_acl_policy":{"name":"acl-live-downlink-smoke","default_action":"allow"}}'
policy_id="$(curl_body POST aria-acl-policies "${policy_body}" | json_field aria_acl_policy.id)"
[ -n "${policy_id}" ] || die "failed to create aria_acl policy"

rule_body="$(printf '{"aria_acl_rule":{"policy_id":"%s","direction":"%s","priority":100,"action":"drop","protocol":"%s"' \
    "${policy_id}" "${ACL_DIRECTION}" "${ACL_PROTOCOL}")"
if [ -n "${BLOCK_SRC_CIDR}" ]; then
    rule_body="${rule_body},\"src_cidr\":\"${BLOCK_SRC_CIDR}\""
fi
if [ -n "${BLOCK_DST_CIDR}" ]; then
    rule_body="${rule_body},\"dst_cidr\":\"${BLOCK_DST_CIDR}\""
fi
rule_body="${rule_body}}}"
rule_id="$(curl_body POST aria-acl-rules "${rule_body}" | json_field aria_acl_rule.id)"
[ -n "${rule_id}" ] || die "failed to create aria_acl rule"

binding_body="$(printf '{"aria_acl_binding":{"policy_id":"%s","target_type":"port","target_id":"%s"}}' \
    "${policy_id}" "${EXPECTED_PORT_ID}")"
binding_id="$(curl_body POST aria-acl-bindings "${binding_body}" | json_field aria_acl_binding.id)"
[ -n "${binding_id}" ] || die "failed to create aria_acl binding"

echo "Applying ACL through Neutron source: port=${EXPECTED_PORT_ID} ifname=${EXPECTED_IFNAME}"
run_full_resync
RESYNC_ROLLBACK_ARMED=true

echo "Checking datapath drop policy"
assert_datapath_drop

echo "Checking aria_acl port status identity"
assert_port_status_identity

echo "Checking that downlink traffic is blocked"
if traffic_check >/dev/null 2>&1; then
    die "ACL did not block ${ACL_PROTOCOL} traffic to ${VM_IP}"
fi

echo "Deleting temporary ACL objects and rolling back"
cleanup_acl
RESYNC_ROLLBACK_ARMED=false
policy_id=""
rule_id=""
binding_id=""

echo "Checking datapath policy is clear after rollback"
assert_datapath_clear

echo "Post-check: ${VM_IP} must recover after rollback"
traffic_check >/dev/null

trap - EXIT
echo "neutron-aria-agent ACL live downlink smoke passed for ${EXPECTED_PORT_ID}"
