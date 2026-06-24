#!/usr/bin/env bash
set -euo pipefail

EXPECTED_HOSTS="${EXPECTED_HOSTS:-ostack2.bj159.net ostack3.bj159.net ostack4.bj159.net}"
ADMINRC="${ADMINRC:-/root/adminrc}"

if [ -r "${ADMINRC}" ]; then
    # Source OpenStack credentials when the script is run on a host shell.
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

echo "Checking neutron-aria-agent heartbeat..."
neutron agent-list | grep -i "Aria ACL agent"

for host in ${EXPECTED_HOSTS}; do
    line="$(neutron agent-list | grep "Aria ACL agent" | grep " ${host} " || true)"
    if [ -z "${line}" ]; then
        echo "missing Aria ACL agent on ${host}" >&2
        exit 1
    fi
    echo "${line}" | grep ":-)" >/dev/null
    agent_id="$(echo "${line}" | awk '{print $2}')"
    echo "Inspecting ${host} (${agent_id})"
    neutron agent-show "${agent_id}" -f json | grep "neutron-aria-agent" >/dev/null
done

echo "neutron-aria-agent heartbeat smoke passed"
