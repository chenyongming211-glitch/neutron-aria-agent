#!/usr/bin/env bash
set -euo pipefail

OPENSTACK_CLIENT="${OPENSTACK_CLIENT:-openstack_client}"
LOCAL_NEUTRON_URL="${LOCAL_NEUTRON_URL:-http://127.0.0.1:9696/v2.0}"
ADMIN_RC_FILE="${ADMIN_RC_FILE:-/etc/kolla/.adminrc}"

log() {
    printf '[neutron-aria-acl-cli-consistency-smoke] %s\n' "$*"
}

die() {
    echo "ERROR: $*" >&2
    exit 1
}

require_root_host() {
    if [ "$(id -u)" != "0" ]; then
        die "This smoke must run as root on the OpenStack/Kolla host."
    fi
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

table_has_field() {
    local field="$1"
    awk -F'|' -v field="${field}" '
        NF >= 4 {
            key=$2
            gsub(/^ +| +$/, "", key)
            if (key == field) {
                found=1
            }
        }
        END { exit found ? 0 : 1 }'
}

api_json() {
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

neutron_cli() {
    docker exec -u root --env-file "${ADMIN_RC_FILE}" "${OPENSTACK_CLIENT}" \
        neutron "$@"
}

cleanup() {
    set +e
    for id in ${cli_binding_id:-} ${api_binding_id:-}; do
        [ -n "${id}" ] && neutron_cli aria-acl-binding-delete "${id}" >/dev/null 2>&1
    done
    for id in ${cli_rule_id:-} ${api_rule_id:-}; do
        [ -n "${id}" ] && neutron_cli aria-acl-rule-delete "${id}" >/dev/null 2>&1
    done
    for id in ${cli_set_id:-} ${api_set_id:-}; do
        [ -n "${id}" ] && neutron_cli aria-acl-address-set-delete "${id}" >/dev/null 2>&1
    done
    for id in ${cli_policy_id:-} ${api_policy_id:-}; do
        [ -n "${id}" ] && neutron_cli aria-acl-policy-delete "${id}" >/dev/null 2>&1
    done
}

require_root_host
need_command docker
need_command curl
if [ -z "${PYTHON_BIN:-}" ]; then
    PYTHON_BIN="$(command -v python3 || command -v python || true)"
fi
[ -n "${PYTHON_BIN}" ] || die "missing command: python3 or python"

help_output="$(neutron_cli help 2>&1)"
printf '%s\n' "${help_output}" | grep -q 'aria-acl-policy-create' || \
    die "aria-acl CLI commands are not installed in ${OPENSTACK_CLIENT}"
printf '%s\n' "${help_output}" | grep -q 'aria-acl-binding-create' || \
    die "aria-acl binding CLI command is not installed in ${OPENSTACK_CLIENT}"
log "cli command discovery ok"

TOKEN="$(docker exec -u root --env-file "${ADMIN_RC_FILE}" \
    "${OPENSTACK_CLIENT}" openstack token issue -f value -c id | tail -1)"
[ -n "${TOKEN}" ] || die "failed to obtain OpenStack token"

run_id="cli-consistency-$(date +%Y%m%d%H%M%S)"
api_policy_id=""
api_rule_id=""
api_set_id=""
api_binding_id=""
cli_policy_id=""
cli_rule_id=""
cli_set_id=""
cli_binding_id=""
trap cleanup EXIT

api_policy_payload="$(api_json POST aria-acl-policies \
    "{\"aria_acl_policy\":{\"name\":\"${run_id}-api\",\"default_action\":\"allow\"}}")"
api_policy_id="$(printf '%s' "${api_policy_payload}" | json_field aria_acl_policy.id)"
[ -n "${api_policy_id}" ] || die "API policy create failed: ${api_policy_payload}"
neutron_cli aria-acl-policy-show "${api_policy_id}" | grep -q "${run_id}-api" || \
    die "CLI could not read API-created policy"
log "cli_reads_api_policy=pass"

api_rule_payload="$(api_json POST aria-acl-rules \
    "{\"aria_acl_rule\":{\"policy_id\":\"${api_policy_id}\",\"direction\":\"ingress\",\"priority\":201,\"action\":\"drop\",\"protocol\":\"icmp\",\"src_cidr\":\"198.51.100.201/32\"}}")"
api_rule_id="$(printf '%s' "${api_rule_payload}" | json_field aria_acl_rule.id)"
[ -n "${api_rule_id}" ] || die "API rule create failed: ${api_rule_payload}"
neutron_cli aria-acl-rule-show "${api_rule_id}" | grep -q "${api_policy_id}" || \
    die "CLI could not read API-created rule"
log "cli_reads_api_rule=pass"

api_set_payload="$(api_json POST aria-acl-address-sets \
    "{\"aria_acl_address_set\":{\"name\":\"${run_id}-api-set\",\"members\":[\"198.51.100.0/24\"]}}")"
api_set_id="$(printf '%s' "${api_set_payload}" | json_field aria_acl_address_set.id)"
[ -n "${api_set_id}" ] || die "API address-set create failed: ${api_set_payload}"
neutron_cli aria-acl-address-set-show "${api_set_id}" | grep -q "${run_id}-api-set" || \
    die "CLI could not read API-created address set"
log "cli_reads_api_address_set=pass"

cli_policy_create="$(neutron_cli aria-acl-policy-create \
    --name "${run_id}-cli" --default-action allow)"
cli_policy_id="$(printf '%s\n' "${cli_policy_create}" | table_field id)"
[ -n "${cli_policy_id}" ] || die "CLI policy create failed: ${cli_policy_create}"
[ "$(api_json GET "aria-acl-policies/${cli_policy_id}" | json_field aria_acl_policy.name)" = "${run_id}-cli" ] || \
    die "API could not read CLI-created policy"
log "api_reads_cli_policy=pass"

cli_rule_create="$(neutron_cli aria-acl-rule-create \
    --policy-id "${cli_policy_id}" \
    --direction egress \
    --priority 202 \
    --action drop \
    --protocol tcp \
    --dst-port 3306 \
    --dst-cidr 203.0.113.10/32)"
cli_rule_id="$(printf '%s\n' "${cli_rule_create}" | table_field id)"
[ -n "${cli_rule_id}" ] || die "CLI rule create failed: ${cli_rule_create}"
[ "$(api_json GET "aria-acl-rules/${cli_rule_id}" | json_field aria_acl_rule.policy_id)" = "${cli_policy_id}" ] || \
    die "API could not read CLI-created rule"
log "api_reads_cli_rule=pass"

cli_set_create="$(neutron_cli aria-acl-address-set-create \
    --name "${run_id}-cli-set" \
    --member 203.0.113.0/24)"
cli_set_id="$(printf '%s\n' "${cli_set_create}" | table_field id)"
[ -n "${cli_set_id}" ] || die "CLI address-set create failed: ${cli_set_create}"
[ "$(api_json GET "aria-acl-address-sets/${cli_set_id}" | json_field aria_acl_address_set.name)" = "${run_id}-cli-set" ] || \
    die "API could not read CLI-created address set"
log "api_reads_cli_address_set=pass"

port_id="$(api_json GET 'ports?limit=1' | "${PYTHON_BIN}" -c 'from __future__ import print_function
import json
import sys
ports = json.load(sys.stdin).get("ports") or []
print(ports[0].get("id") if ports else "")')"
if [ -n "${port_id}" ]; then
    cli_binding_create="$(neutron_cli aria-acl-binding-create \
        --policy-id "${cli_policy_id}" \
        --port "${port_id}" \
        --enabled false)"
    cli_binding_id="$(printf '%s\n' "${cli_binding_create}" | table_field id)"
    [ -n "${cli_binding_id}" ] || die "CLI binding create failed: ${cli_binding_create}"
    [ "$(api_json GET "aria-acl-bindings/${cli_binding_id}" | json_field aria_acl_binding.target_id)" = "${port_id}" ] || \
        die "API could not read CLI-created binding"
    log "api_reads_cli_binding=pass"

    api_binding_payload="$(api_json POST aria-acl-bindings \
        "{\"aria_acl_binding\":{\"policy_id\":\"${api_policy_id}\",\"target_type\":\"port\",\"target_id\":\"${port_id}\",\"enabled\":false}}")"
    api_binding_id="$(printf '%s' "${api_binding_payload}" | json_field aria_acl_binding.id)"
    [ -n "${api_binding_id}" ] || die "API binding create failed: ${api_binding_payload}"
    neutron_cli aria-acl-binding-show "${api_binding_id}" | grep -q "${port_id}" || \
        die "CLI could not read API-created binding"
    log "cli_reads_api_binding=pass"

    port_projection_payload="$(api_json GET "ports/${port_id}")"
    printf '%s' "${port_projection_payload}" | "${PYTHON_BIN}" -c '
from __future__ import print_function
import json
import sys

port = (json.load(sys.stdin).get("port") or {})
expected_fields = (
    "aria_acl_enabled",
    "aria_acl_effective_policy_id",
    "aria_acl_effective_policy_name",
    "aria_acl_effective_source",
    "aria_acl_binding_id",
    "aria_acl_effective_revision",
    "aria_acl_runtime_status",
    "aria_acl_runtime_host",
    "aria_acl_runtime_reason",
)
missing = [field for field in expected_fields if field not in port]
if missing:
    raise SystemExit("port projection fields missing: %s" % ",".join(missing))
if port.get("aria_acl_enabled") is not False:
    raise SystemExit("disabled bindings must project aria_acl_enabled=false")
if port.get("aria_acl_runtime_status") != "not_requested":
    raise SystemExit("disabled bindings must project runtime_status=not_requested")
'
    port_show="$(neutron_cli port-show "${port_id}")"
    for field in \
        aria_acl_enabled \
        aria_acl_effective_policy_id \
        aria_acl_effective_policy_name \
        aria_acl_effective_source \
        aria_acl_binding_id \
        aria_acl_effective_revision \
        aria_acl_runtime_status \
        aria_acl_runtime_host \
        aria_acl_runtime_reason; do
        printf '%s\n' "${port_show}" | table_has_field "${field}" || \
            die "neutron port-show omitted ${field}: ${port_show}"
    done
    log "port_show_projection=pass"
else
    log "binding_cross_check=skipped reason=no-port"
    log "port_show_projection=skipped reason=no-port"
fi

neutron_cli aria-acl-port-status-list >/dev/null
log "cli_status_list=pass"

cleanup
trap - EXIT
remaining="$(RUN_ID="${run_id}" api_json GET aria-acl-policies |
    RUN_ID="${run_id}" "${PYTHON_BIN}" -c 'from __future__ import print_function
import json
import os
import sys

run_id = os.environ["RUN_ID"]
payload = json.load(sys.stdin)
print(sum(1 for row in payload.get("aria_acl_policies", [])
          if (row.get("name") or "").startswith(run_id)))')"
[ "${remaining}" = "0" ] || die "cleanup left ${remaining} test policies"
log "cleanup_remaining_policies=0"
log "api_cli_consistency=pass"
