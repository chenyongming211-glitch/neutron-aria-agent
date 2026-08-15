#!/usr/bin/env bash
set -euo pipefail

SERVICE_NAME="${SERVICE_NAME:-neutron_aria_agent}"
EXEC_USER="${EXEC_USER:-neutron}"
ADMIN_RC_FILE="${ADMIN_RC_FILE:-/etc/kolla/.adminrc}"
LOCAL_NEUTRON_URL="${LOCAL_NEUTRON_URL:-http://127.0.0.1:9696/v2.0}"
DATAPATH_HTTP="${DATAPATH_HTTP:-http://127.0.0.1:8080}"
AGENT_CONFIG="${AGENT_CONFIG:-/etc/neutron-aria-agent/neutron-aria-agent.ini}"
ACL_PROTOCOL="${ACL_PROTOCOL:-icmp}"
PING_COUNT="${PING_COUNT:-3}"
PING_TIMEOUT="${PING_TIMEOUT:-1}"
GUEST_READY_ATTEMPTS="${GUEST_READY_ATTEMPTS:-180}"
GUEST_READY_INTERVAL="${GUEST_READY_INTERVAL:-2}"
REQUIRE_STATUS_IDENTITY="${REQUIRE_STATUS_IDENTITY:-true}"
USE_TEMP_VM="${USE_TEMP_VM:-false}"
VM_IP="${VM_IP:-}"
EXPECTED_PORT_ID="${EXPECTED_PORT_ID:-}"
EXPECTED_IFNAME="${EXPECTED_IFNAME:-}"
EGRESS_TARGET_IP="${EGRESS_TARGET_IP:-}"
GUEST_SSH_USER="${GUEST_SSH_USER:-cirros}"
GUEST_SSH_PASSWORD="${GUEST_SSH_PASSWORD:-}"
CIRROS_IMAGE_FILE="${CIRROS_IMAGE_FILE:-}"
CIRROS_IMAGE_DISK_FORMAT="${CIRROS_IMAGE_DISK_FORMAT:-raw}"
NETWORK_ID="${NETWORK_ID:-}"
FLAVOR_ID="${FLAVOR_ID:-1}"
BOOT_AZ="${BOOT_AZ:-nova:$(hostname -f)}"
TEMP_RUN_ID="${TEMP_RUN_ID:-acl-live-egress-$(date +%Y%m%d%H%M%S)-$(hostname -s)}"

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

table_field() {
    local field="$1"
    awk -F'|' -v field="${field}" '
        NF >= 4 {
            key=$2
            val=$3
            gsub(/^ +| +$/, "", key)
            gsub(/^ +| +$/, "", val)
            if (key == field) {
                print val
                exit
            }
        }'
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

route_source_ip() {
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
    printf '%s\n' "${source_ip}"
}

guest_ping() {
    "${PYTHON_BIN}" - \
        "${VM_IP}" \
        "${GUEST_SSH_USER}" \
        "${GUEST_SSH_PASSWORD}" \
        "${EGRESS_TARGET_IP}" \
        "${PING_COUNT}" \
        "${PING_TIMEOUT}" <<'PY'
from __future__ import print_function

import os
import pty
import select
import sys
import time

ip, user, password, target, count, timeout = sys.argv[1:7]
cmd = [
    "ssh",
    "-o", "StrictHostKeyChecking=no",
    "-o", "UserKnownHostsFile=/dev/null",
    "-o", "ConnectTimeout=5",
    "%s@%s" % (user, ip),
    "ping -c %s -W %s %s; echo PING_RC=$?" % (count, timeout, target),
]

pid, fd = pty.fork()
if pid == 0:
    os.execvp(cmd[0], cmd)

out = b""
sent_password = False
deadline = time.time() + 45
while time.time() < deadline:
    readable, _, _ = select.select([fd], [], [], 0.5)
    if not readable:
        continue
    try:
        chunk = os.read(fd, 4096)
    except OSError:
        break
    if not chunk:
        break
    out += chunk
    lowered = out.lower()
    if b"password:" in lowered and not sent_password:
        os.write(fd, (password + "\n").encode("utf-8"))
        sent_password = True
    if b"ping_rc=" in lowered:
        break

try:
    os.waitpid(pid, os.WNOHANG)
except OSError:
    pass

text = out.decode("utf-8", "replace")
print(text)
if "PING_RC=" not in text:
    raise SystemExit(4)
PY
}

wait_guest_ping_ready() {
    local i output
    for i in $(seq 1 "${GUEST_READY_ATTEMPTS}"); do
        if output="$(guest_ping 2>/dev/null)"; then
            printf '%s\n' "${output}"
            return 0
        fi
        sleep "${GUEST_READY_INTERVAL}"
    done
    die "guest SSH/ping did not become ready for ${VM_IP}"
}

guest_ping_blocked() {
    local output
    output="$(guest_ping)"
    printf '%s\n' "${output}"
    printf '%s\n' "${output}" | grep -E '100% packet loss| 0 received|PING_RC=1' >/dev/null
}

guest_ping_passed() {
    local output
    output="$(guest_ping)"
    printf '%s\n' "${output}"
    printf '%s\n' "${output}" | grep -q 'PING_RC=0'
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

create_temp_vm() {
    [ -n "${CIRROS_IMAGE_FILE}" ] || die "CIRROS_IMAGE_FILE is required when USE_TEMP_VM=true"
    [ -n "${NETWORK_ID}" ] || die "NETWORK_ID is required when USE_TEMP_VM=true"
    [ -f "${CIRROS_IMAGE_FILE}" ] || die "missing CIRROS_IMAGE_FILE: ${CIRROS_IMAGE_FILE}"
    [ -n "${GUEST_SSH_PASSWORD}" ] || GUEST_SSH_PASSWORD="gocubsgo"

    docker cp "${CIRROS_IMAGE_FILE}" "openstack_client:/tmp/${TEMP_RUN_ID}.img"
    image_create="$(docker exec -u root --env-file "${ADMIN_RC_FILE}" \
        openstack_client glance image-create \
        --name "${TEMP_RUN_ID}" \
        --disk-format "${CIRROS_IMAGE_DISK_FORMAT}" \
        --container-format bare \
        --visibility private \
        --file "/tmp/${TEMP_RUN_ID}.img")"
    image_id="$(printf '%s\n' "${image_create}" | table_field id)"
    [ -n "${image_id}" ] || die "failed to create temporary image"

    boot_output="$(docker exec -u root --env-file "${ADMIN_RC_FILE}" \
        openstack_client nova boot \
        --flavor "${FLAVOR_ID}" \
        --image "${image_id}" \
        --nic "net-id=${NETWORK_ID}" \
        --availability-zone "${BOOT_AZ}" \
        "${TEMP_RUN_ID}")"
    server_id="$(printf '%s\n' "${boot_output}" | table_field id)"
    [ -n "${server_id}" ] || die "failed to create temporary VM"

    local status host ip port
    for _ in $(seq 1 100); do
        show_output="$(docker exec -u root --env-file "${ADMIN_RC_FILE}" \
            openstack_client nova show "${server_id}" || true)"
        status="$(printf '%s\n' "${show_output}" | table_field status)"
        host="$(printf '%s\n' "${show_output}" | table_field OS-EXT-SRV-ATTR:host)"
        ip="$(printf '%s\n' "${show_output}" | awk -F'|' '/ flat_mgt network /{gsub(/^ +| +$/,"",$3); print $3; exit}' | awk -F, '{print $1}')"
        echo "waiting for temp VM: status=${status} host=${host} ip=${ip}"
        if [ "${status}" = "ACTIVE" ] && [ -n "${ip}" ]; then
            break
        fi
        [ "${status}" = "ERROR" ] && die "temporary VM entered ERROR state"
        sleep 3
    done
    [ "${status}" = "ACTIVE" ] || die "temporary VM did not become ACTIVE"
    [ -n "${ip}" ] || die "temporary VM has no flat_mgt IP"

    port="$(docker exec -u root --env-file "${ADMIN_RC_FILE}" \
        openstack_client neutron port-list --device_id "${server_id}" |
        awk '/fa:|[0-9a-f][0-9a-f]:/{print $2; exit}')"
    [ -n "${port}" ] || die "failed to resolve temporary VM port"

    VM_IP="${ip}"
    EXPECTED_PORT_ID="${port}"
    EXPECTED_IFNAME="tap${port:0:11}"
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

cleanup_temp_vm() {
    set +e
    if [ -n "${server_id:-}" ]; then
        docker exec -u root --env-file "${ADMIN_RC_FILE}" \
            openstack_client nova delete "${server_id}" >/dev/null 2>&1 || true
        sleep 8
        docker exec -u root --env-file "${ADMIN_RC_FILE}" \
            openstack_client nova force-delete "${server_id}" >/dev/null 2>&1 || true
        sleep 3
    fi
    if [ -n "${image_id:-}" ]; then
        docker exec -u root --env-file "${ADMIN_RC_FILE}" \
            openstack_client glance image-delete "${image_id}" >/dev/null 2>&1 || true
    fi
    docker exec -u root openstack_client \
        rm -f "/tmp/${TEMP_RUN_ID}.img" >/dev/null 2>&1 || true
}

cleanup_all() {
    cleanup_acl
    if [ "${USE_TEMP_VM}" = "true" ]; then
        cleanup_temp_vm
    fi
}

need_command docker
need_command curl
need_command ip
need_command ssh
if [ -z "${PYTHON_BIN:-}" ]; then
    PYTHON_BIN="$(command -v python3 || command -v python || true)"
fi
[ -n "${PYTHON_BIN}" ] || die "missing command: python3 or python"

TOKEN="$(docker exec -u root --env-file "${ADMIN_RC_FILE}" \
    openstack_client openstack token issue -f value -c id | tail -1)"
[ -n "${TOKEN}" ] || die "failed to obtain OpenStack token"

policy_id=""
rule_id=""
binding_id=""
image_id=""
server_id=""
RESYNC_ROLLBACK_ARMED=false
trap cleanup_all EXIT

if [ "${USE_TEMP_VM}" = "true" ]; then
    create_temp_vm
else
    [ -n "${VM_IP}" ] || die "VM_IP is required"
    [ -n "${EXPECTED_PORT_ID}" ] || die "EXPECTED_PORT_ID is required"
    [ -n "${EXPECTED_IFNAME}" ] || die "EXPECTED_IFNAME is required"
    [ -n "${GUEST_SSH_PASSWORD}" ] || die "GUEST_SSH_PASSWORD is required unless USE_TEMP_VM=true"
fi

if [ -z "${EGRESS_TARGET_IP}" ]; then
    EGRESS_TARGET_IP="$(route_source_ip)" || \
        die "failed to infer EGRESS_TARGET_IP for ${VM_IP}"
fi

echo "Waiting for guest-originated baseline traffic: vm=${VM_IP} target=${EGRESS_TARGET_IP}"
wait_guest_ping_ready >/dev/null
guest_ping_passed >/dev/null || die "guest baseline ping did not pass"

policy_body='{"aria_acl_policy":{"name":"acl-live-egress-smoke","default_action":"allow"}}'
policy_id="$(curl_body POST aria-acl-policies "${policy_body}" | json_field aria_acl_policy.id)"
[ -n "${policy_id}" ] || die "failed to create aria_acl policy"

rule_body="$(printf '{"aria_acl_rule":{"policy_id":"%s","direction":"egress","priority":100,"action":"drop","protocol":"%s","src_cidr":"%s/32","dst_cidr":"%s/32"}}' \
    "${policy_id}" "${ACL_PROTOCOL}" "${VM_IP}" "${EGRESS_TARGET_IP}")"
rule_id="$(curl_body POST aria-acl-rules "${rule_body}" | json_field aria_acl_rule.id)"
[ -n "${rule_id}" ] || die "failed to create aria_acl rule"

binding_body="$(printf '{"aria_acl_binding":{"policy_id":"%s","target_type":"port","target_id":"%s"}}' \
    "${policy_id}" "${EXPECTED_PORT_ID}")"
binding_id="$(curl_body POST aria-acl-bindings "${binding_body}" | json_field aria_acl_binding.id)"
[ -n "${binding_id}" ] || die "failed to create aria_acl binding"

echo "Applying egress ACL through Neutron source: port=${EXPECTED_PORT_ID} ifname=${EXPECTED_IFNAME}"
run_full_resync
RESYNC_ROLLBACK_ARMED=true

echo "Checking datapath drop policy"
assert_datapath_drop

echo "Checking aria_acl port status identity"
assert_port_status_identity

echo "Checking that guest-originated traffic is blocked"
if ! guest_ping_blocked >/dev/null; then
    die "ACL did not block guest ${ACL_PROTOCOL} traffic from ${VM_IP} to ${EGRESS_TARGET_IP}"
fi

echo "Deleting temporary ACL objects and rolling back"
cleanup_acl
RESYNC_ROLLBACK_ARMED=false
policy_id=""
rule_id=""
binding_id=""

echo "Checking datapath policy is clear after rollback"
assert_datapath_clear

echo "Post-check: guest-originated traffic must recover"
guest_ping_passed >/dev/null || die "guest ping did not recover after rollback"

if [ "${USE_TEMP_VM}" = "true" ]; then
    cleanup_temp_vm
    server_id=""
    image_id=""
fi

trap - EXIT
echo "neutron-aria-agent ACL live egress smoke passed for ${EXPECTED_PORT_ID}"
