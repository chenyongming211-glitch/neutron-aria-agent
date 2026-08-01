#!/usr/bin/env bash
set -euo pipefail

CONTAINER="${CONTAINER:-neutron_server}"
LOCAL_NEUTRON_URL="${LOCAL_NEUTRON_URL:-http://127.0.0.1:9696/v2.0}"
ADMIN_RC_FILE="${ADMIN_RC_FILE:-}"

log() {
    printf '[neutron-aria-acl-db-crud-smoke] %s\n' "$*"
}

if [ "$(id -u)" != "0" ]; then
    echo "This smoke must run as root on the OpenStack/Kolla host." >&2
    exit 1
fi

if [ -z "${ADMIN_RC_FILE}" ]; then
    if [ -r /root/adminrc ]; then
        ADMIN_RC_FILE=/root/adminrc
    elif [ -r /etc/kolla/.adminrc ]; then
        ADMIN_RC_FILE=/etc/kolla/.adminrc
    fi
fi
[ -n "${ADMIN_RC_FILE}" ] && [ -r "${ADMIN_RC_FILE}" ] || {
    echo "No readable adminrc found for Neutron API smoke." >&2
    exit 1
}
# shellcheck disable=SC1090
. "${ADMIN_RC_FILE}"

log "Checking plugin-level DB CRUD in ${CONTAINER}"
docker exec -i "${CONTAINER}" python <<'PY'
from oslo_config import cfg
cfg.CONF(args=[
    '--config-file', '/etc/neutron/neutron.conf',
    '--config-file', '/etc/neutron/plugins/ml2/ml2_conf.ini',
    '--config-file', '/etc/neutron/plugins/ml2/ml2_conf_sriov.ini',
], project='neutron')

from neutron import context
from neutron_aria.services.aria_acl.plugin import AriaAclPlugin
import hashlib
import socket

ctx = context.get_admin_context()
plugin = AriaAclPlugin()
suffix = hashlib.md5(socket.gethostname()).hexdigest()[:8]
policy_id = 'aria-pol-db-' + suffix
rule_id = 'aria-rule-db-' + suffix
binding_id = 'aria-bind-db-' + suffix
port_id = '00000000-0000-0000-0000-' + hashlib.md5('port-' + socket.gethostname()).hexdigest()[:12]

for func, args in (
    (plugin.delete_aria_acl_binding, (ctx, binding_id)),
    (plugin.delete_aria_acl_rule, (ctx, rule_id)),
    (plugin.delete_aria_acl_policy, (ctx, policy_id)),
    (plugin.delete_aria_acl_port_status, (ctx, port_id)),
):
    try:
        func(*args)
    except Exception:
        pass

for binding in list(plugin.get_aria_acl_bindings(ctx)):
    if binding.get('target_id') == port_id:
        try:
            plugin.delete_aria_acl_binding(ctx, binding['id'])
        except Exception:
            pass
for rule in list(plugin.get_aria_acl_rules(ctx)):
    if rule.get('policy_id') == policy_id:
        try:
            plugin.delete_aria_acl_rule(ctx, rule['id'])
        except Exception:
            pass
for policy in list(plugin.get_aria_acl_policies(ctx)):
    if policy.get('id') == policy_id or policy.get('name') == 'db-smoke':
        try:
            plugin.delete_aria_acl_policy(ctx, policy['id'])
        except Exception:
            pass

plugin.create_aria_acl_policy(ctx, {'aria_acl_policy': {
    'id': policy_id,
    'project_id': 'admin',
    'name': 'db-smoke',
    'default_action': 'allow',
}})
plugin.create_aria_acl_rule(ctx, {'aria_acl_rule': {
    'id': rule_id,
    'project_id': 'admin',
    'policy_id': policy_id,
    'direction': 'ingress',
    'priority': 100,
    'action': 'drop',
    'protocol': 'icmp',
    'src_cidr': '10.58.159.2/32',
}})
plugin.create_aria_acl_binding(ctx, {'aria_acl_binding': {
    'id': binding_id,
    'project_id': 'admin',
    'policy_id': policy_id,
    'target_type': 'port',
    'target_id': port_id,
}})
plugin.create_aria_acl_port_status(ctx, {'aria_acl_port_status': {
    'port_id': port_id,
    'host': 'ostack2.bj159.net',
    'effective_policy_id': policy_id,
    'binding_id': binding_id,
    'status': 'ready',
    'effective_action': 'enforce',
    'generation': 1,
}})
effective = plugin.get_aria_acl_effective_for_port(ctx, {
    'id': port_id,
    'network_id': 'net-smoke',
})
assert effective['effective_action'] == 'enforce'
assert effective['policy_id'] == policy_id
assert len(effective['rules']) == 1

plugin.delete_aria_acl_port_status(ctx, port_id, host='ostack2.bj159.net')
plugin.delete_aria_acl_binding(ctx, binding_id)
plugin.delete_aria_acl_rule(ctx, rule_id)
plugin.delete_aria_acl_policy(ctx, policy_id)
print('plugin_db_crud=ok')
PY

log "Checking REST ACL CRUD through local neutron-server"
TOKEN="$(docker exec -u root --env-file "${ADMIN_RC_FILE}" \
    openstack_client openstack token issue -f value -c id | tail -1)"
REST_PORT_SUFFIX="$(hostname | md5sum | awk '{print substr($1, 1, 12)}')"
REST_PORT_ID="${REST_PORT_ID:-00000000-0000-0000-0000-${REST_PORT_SUFFIX}}"
policy_id=""
rule_id=""
binding_id=""

cleanup_rest() {
    set +e
    if [ -n "${REST_PORT_ID}" ]; then
        curl_body DELETE "${LOCAL_NEUTRON_URL}/aria-acl-port-statuses/${REST_PORT_ID}" >/dev/null 2>&1
    fi
    if [ -n "${binding_id}" ]; then
        curl_body DELETE "${LOCAL_NEUTRON_URL}/aria-acl-bindings/${binding_id}" >/dev/null 2>&1
    fi
    if [ -n "${rule_id}" ]; then
        curl_body DELETE "${LOCAL_NEUTRON_URL}/aria-acl-rules/${rule_id}" >/dev/null 2>&1
    fi
    if [ -n "${policy_id}" ]; then
        curl_body DELETE "${LOCAL_NEUTRON_URL}/aria-acl-policies/${policy_id}" >/dev/null 2>&1
    fi
}

trap cleanup_rest EXIT

curl_body() {
    local method="$1"
    local url="$2"
    local data="${3:-}"
    if [ -n "${data}" ]; then
        curl -sS -H "X-Auth-Token: ${TOKEN}" -H 'Content-Type: application/json' \
            -X "${method}" -d "${data}" "${url}"
    else
        curl -sS -H "X-Auth-Token: ${TOKEN}" -X "${method}" "${url}"
    fi
}

json_id() {
    sed -n 's/.*"id": "\([^"]*\)".*/\1/p' | head -1
}

require_body_contains() {
    local body="$1"
    local needle="$2"
    local label="$3"
    if ! printf '%s' "${body}" | grep -q "${needle}"; then
        echo "${label} failed, response: ${body}" >&2
        exit 1
    fi
}

policy_create="$(curl_body POST "${LOCAL_NEUTRON_URL}/aria-acl-policies" \
    '{"aria_acl_policy":{"name":"rest-smoke","default_action":"allow"}}')"
policy_id="$(printf '%s' "${policy_create}" | json_id)"
if [ -z "${policy_id}" ]; then
    echo "Failed to parse policy id from: ${policy_create}" >&2
    exit 1
fi

rule_create="$(curl_body POST "${LOCAL_NEUTRON_URL}/aria-acl-rules" \
    "{\"aria_acl_rule\":{\"policy_id\":\"${policy_id}\",\"direction\":\"ingress\",\"priority\":100,\"action\":\"drop\",\"protocol\":\"icmp\",\"src_cidr\":\"10.58.159.2/32\"}}")"
rule_id="$(printf '%s' "${rule_create}" | json_id)"
if [ -z "${rule_id}" ]; then
    echo "Failed to parse rule id from: ${rule_create}" >&2
    exit 1
fi

binding_create="$(curl_body POST "${LOCAL_NEUTRON_URL}/aria-acl-bindings" \
    "{\"aria_acl_binding\":{\"policy_id\":\"${policy_id}\",\"target_type\":\"port\",\"target_id\":\"${REST_PORT_ID}\"}}")"
binding_id="$(printf '%s' "${binding_create}" | json_id)"
if [ -z "${binding_id}" ]; then
    echo "Failed to parse binding id from: ${binding_create}" >&2
    exit 1
fi

status_create="$(curl_body POST "${LOCAL_NEUTRON_URL}/aria-acl-port-statuses" \
    "{\"aria_acl_port_status\":{\"port_id\":\"${REST_PORT_ID}\",\"host\":\"$(hostname)\",\"effective_policy_id\":\"${policy_id}\",\"binding_id\":\"${binding_id}\",\"status\":\"ready\",\"effective_action\":\"enforce\",\"generation\":2}}")"
require_body_contains "${status_create}" 'aria_acl_port_status' 'status create'

require_body_contains "$(curl_body GET "${LOCAL_NEUTRON_URL}/aria-acl-policies/${policy_id}")" "${policy_id}" 'policy show'
require_body_contains "$(curl_body GET "${LOCAL_NEUTRON_URL}/aria-acl-rules/${rule_id}")" "${rule_id}" 'rule show'
require_body_contains "$(curl_body GET "${LOCAL_NEUTRON_URL}/aria-acl-bindings/${binding_id}")" "${binding_id}" 'binding show'
require_body_contains "$(curl_body GET "${LOCAL_NEUTRON_URL}/aria-acl-port-statuses/${REST_PORT_ID}")" 'ready' 'status show'

cleanup_rest
trap - EXIT
curl_body GET "${LOCAL_NEUTRON_URL}/aria-acl-policies" | grep -q 'aria_acl_policies'

log "rest_acl_crud=ok"
