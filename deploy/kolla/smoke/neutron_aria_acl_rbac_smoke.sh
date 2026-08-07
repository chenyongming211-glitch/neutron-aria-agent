#!/usr/bin/env bash
set -euo pipefail

OPENSTACK_CLIENT="${OPENSTACK_CLIENT:-openstack_client}"
ADMIN_RC_FILE="${ADMIN_RC_FILE:-/etc/kolla/.adminrc}"
NEUTRON_URL="${NEUTRON_URL:-http://127.0.0.1:9696/v2.0}"

log() {
    printf '[neutron-aria-acl-rbac-smoke] %s\n' "$*"
}

die() {
    echo "ERROR: $*" >&2
    exit 1
}

need_command() {
    command -v "$1" >/dev/null 2>&1 || die "missing command: $1"
}

os_admin() {
    docker exec --env-file "${ADMIN_RC_FILE}" "${OPENSTACK_CLIENT}" openstack "$@"
}

cleanup() {
    set +e
    if [ -n "${user_id:-}" ]; then
        os_admin user delete "${user_id}" >/dev/null 2>&1
    fi
    if [ -n "${project_id:-}" ]; then
        os_admin project delete "${project_id}" >/dev/null 2>&1
    fi
    if [ -n "${response_dir:-}" ]; then
        rm -rf "${response_dir}"
    fi
}

assert_forbidden() {
    local label="$1"
    local method="$2"
    local path="$3"
    local data="${4:-}"
    local output_file="${response_dir}/${label}.json"
    local http_code

    if [ -n "${data}" ]; then
        http_code="$(curl --silent --show-error \
            -o "${output_file}" -w '%{http_code}' \
            -H "X-Auth-Token: ${member_token}" \
            -H 'Content-Type: application/json' \
            -X "${method}" --data "${data}" \
            "${NEUTRON_URL}/${path}")"
    else
        http_code="$(curl --silent --show-error \
            -o "${output_file}" -w '%{http_code}' \
            -H "X-Auth-Token: ${member_token}" \
            -X "${method}" "${NEUTRON_URL}/${path}")"
    fi

    if [ "${http_code}" != "403" ]; then
        cat "${output_file}" >&2
        die "${label} returned HTTP ${http_code}; expected 403"
    fi
    log "${label}=pass http=403"
}

if [ "$(id -u)" != "0" ]; then
    die "This smoke must run as root on the OpenStack/Kolla host."
fi
need_command docker
need_command curl
need_command mktemp

run_id="aria-rbac-$(date +%Y%m%d%H%M%S)-$$"
project_name="${run_id}-project"
user_name="${run_id}-user"
user_password="$(cat /proc/sys/kernel/random/uuid)Aa1"
project_id=""
user_id=""
response_dir="$(mktemp -d "/var/tmp/${run_id}.XXXXXX")"
trap cleanup EXIT

auth_url="$(docker exec --env-file "${ADMIN_RC_FILE}" \
    "${OPENSTACK_CLIENT}" printenv OS_AUTH_URL)"
[ -n "${auth_url}" ] || die "OS_AUTH_URL is empty"

project_id="$(os_admin project create "${project_name}" -f value -c id)"
[ -n "${project_id}" ] || die "failed to create temporary project"
user_id="$(os_admin user create --project "${project_id}" \
    --password "${user_password}" "${user_name}" -f value -c id)"
[ -n "${user_id}" ] || die "failed to create temporary member user"

member_token="$(docker exec "${OPENSTACK_CLIENT}" openstack \
    --os-auth-url "${auth_url}" \
    --os-identity-api-version 2 \
    --os-username "${user_name}" \
    --os-password "${user_password}" \
    --os-project-name "${project_name}" \
    token issue -f value -c id)"
[ -n "${member_token}" ] || die "failed to obtain temporary member token"

assert_forbidden list_policies GET aria-acl-policies
assert_forbidden list_rules GET aria-acl-rules
assert_forbidden list_address_sets GET aria-acl-address-sets
assert_forbidden list_bindings GET aria-acl-bindings
assert_forbidden list_port_statuses GET aria-acl-port-statuses
assert_forbidden create_policy POST aria-acl-policies \
    "{\"aria_acl_policy\":{\"name\":\"${run_id}\",\"default_action\":\"allow\"}}"

log "result=pass temporary_identity_cleanup=armed"
