#!/usr/bin/env bash
set -euo pipefail

SERVICE_NAME="${SERVICE_NAME:-neutron_aria_agent}"
ADMINRC="${ADMINRC:-/root/adminrc}"
REPO_ROOT="${REPO_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)}"
LOCAL_NEUTRON_URL="${LOCAL_NEUTRON_URL:-http://127.0.0.1:9696/v2.0}"
SMOKE_TARGET_TYPE="${SMOKE_TARGET_TYPE:-network}"
SMOKE_TARGET_ID="${SMOKE_TARGET_ID:-00000000-0000-0000-0000-ac1ac1ac1ac1}"

die() {
    echo "ERROR: $*" >&2
    exit 1
}

if [ -r "${ADMINRC}" ]; then
    # shellcheck disable=SC1090
    source "${ADMINRC}"
fi
ADMIN_RC_FILE="${ADMIN_RC_FILE:-/etc/kolla/.adminrc}"

if ! command -v neutron >/dev/null 2>&1; then
    neutron() {
        docker exec \
            -u root \
            -e OS_USERNAME="${OS_USERNAME:-}" \
            -e OS_PASSWORD="${OS_PASSWORD:-}" \
            -e OS_TENANT_NAME="${OS_TENANT_NAME:-}" \
            -e OS_PROJECT_NAME="${OS_PROJECT_NAME:-}" \
            -e OS_AUTH_URL="${OS_AUTH_URL:-}" \
            -e OS_NO_CACHE="${OS_NO_CACHE:-true}" \
            -e OS_AUTH_STRATEGY="${OS_AUTH_STRATEGY:-keystone}" \
            -e OS_REGION_NAME="${OS_REGION_NAME:-}" \
            -e NEUTRON_ENDPOINT_TYPE="${NEUTRON_ENDPOINT_TYPE:-publicURL}" \
            openstack_client neutron "$@"
    }
fi

TOKEN=""
policy_id=""
rule_id=""
binding_id=""

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

cleanup_acl() {
    set +e
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

echo "Checking aria_acl Neutron extension visibility"
extensions="$(neutron ext-list)"
printf '%s\n' "${extensions}" | grep -E 'aria[-_]acl|aria-acl|Aria ACL' >/dev/null || \
    die "aria_acl extension is not visible in neutron ext-list"

echo "Checking neutron-aria-agent container is running"
docker ps --format '{{.Names}}' | grep -qx "${SERVICE_NAME}" || \
    die "${SERVICE_NAME} is not running"

echo "Creating temporary aria_acl policy/rule/binding through Neutron API"
TOKEN="$(docker exec -u root --env-file "${ADMIN_RC_FILE}" \
    openstack_client openstack token issue -f value -c id | tail -1)"

policy_create="$(curl_body POST "${LOCAL_NEUTRON_URL}/aria-acl-policies" \
    '{"aria_acl_policy":{"name":"neutron-source-smoke","default_action":"allow"}}')"
policy_id="$(printf '%s' "${policy_create}" | json_id)"
[ -n "${policy_id}" ] || die "failed to create aria_acl policy: ${policy_create}"

rule_create="$(curl_body POST "${LOCAL_NEUTRON_URL}/aria-acl-rules" \
    "{\"aria_acl_rule\":{\"policy_id\":\"${policy_id}\",\"direction\":\"ingress\",\"priority\":100,\"action\":\"drop\",\"protocol\":\"icmp\",\"src_cidr\":\"192.0.2.2/32\"}}")"
rule_id="$(printf '%s' "${rule_create}" | json_id)"
[ -n "${rule_id}" ] || die "failed to create aria_acl rule: ${rule_create}"

binding_create="$(curl_body POST "${LOCAL_NEUTRON_URL}/aria-acl-bindings" \
    "{\"aria_acl_binding\":{\"policy_id\":\"${policy_id}\",\"target_type\":\"${SMOKE_TARGET_TYPE}\",\"target_id\":\"${SMOKE_TARGET_ID}\"}}")"
binding_id="$(printf '%s' "${binding_create}" | json_id)"
[ -n "${binding_id}" ] || die "failed to create aria_acl binding: ${binding_create}"

trap cleanup_acl EXIT

echo "Checking aria_acl API can be read by neutron-aria-agent"
ACL_SOURCE=neutron \
MIN_ACL_POLICIES=1 \
MIN_ACL_RULES=1 \
MIN_ACL_BINDINGS=1 \
ROLLBACK="${ROLLBACK:-true}" \
MIN_MANAGED_PORTS="${MIN_MANAGED_PORTS:-0}" \
bash "${REPO_ROOT}/deploy/kolla/smoke/neutron_aria_full_resync_smoke.sh"

cleanup_acl
trap - EXIT
echo "neutron-aria-agent aria_acl Neutron source smoke passed"
