#!/usr/bin/env bash
set -euo pipefail

EXPECTED_HOSTS="${EXPECTED_HOSTS:-ostack2.bj159.net ostack3.bj159.net ostack4.bj159.net}"
ADMINRC="${ADMINRC:-/root/adminrc}"
REQUIRE_HEARTBEAT_SUMMARY_FIELDS="${REQUIRE_HEARTBEAT_SUMMARY_FIELDS:-false}"
REQUIRE_P3_PROJECTION_FIELDS="${REQUIRE_P3_PROJECTION_FIELDS:-false}"
HEARTBEAT_SUMMARY_TIMEOUT="${HEARTBEAT_SUMMARY_TIMEOUT:-45}"

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

summary_fields_present() {
    local details="$1"
    for field in \
        last_submitted_generation \
        accepted_generation \
        applied_generation \
        generation_lag \
        domain_counts \
        degraded_reasons; do
        echo "${details}" | grep "${field}" >/dev/null || return 1
    done
}

p3_projection_fields_present() {
    local details="$1"
    for field in \
        projection_index \
        last_event_decision_counts \
        last_event_decisions \
        last_event_decision_updated_at; do
        echo "${details}" | grep "${field}" >/dev/null || return 1
    done
}

for host in ${EXPECTED_HOSTS}; do
    line="$(neutron agent-list | grep "Aria ACL agent" | grep " ${host} " || true)"
    if [ -z "${line}" ]; then
        echo "missing Aria ACL agent on ${host}" >&2
        exit 1
    fi
    echo "${line}" | grep ":-)" >/dev/null
    agent_id="$(echo "${line}" | awk '{print $2}')"
    echo "Inspecting ${host} (${agent_id})"
    details="$(neutron agent-show "${agent_id}" -f json)"
    echo "${details}" | grep "neutron-aria-agent" >/dev/null

    if [ "${REQUIRE_HEARTBEAT_SUMMARY_FIELDS}" = "true" ]; then
        deadline=$((SECONDS + HEARTBEAT_SUMMARY_TIMEOUT))
        while ! summary_fields_present "${details}"; do
            if [ "${SECONDS}" -ge "${deadline}" ]; then
                echo "missing neutron-aria-agent heartbeat summary fields on ${host}" >&2
                echo "${details}" >&2
                exit 1
            fi
            sleep 3
            details="$(neutron agent-show "${agent_id}" -f json)"
        done
        echo "heartbeat_summary_fields=ok host=${host}"
    fi

    if [ "${REQUIRE_P3_PROJECTION_FIELDS}" = "true" ]; then
        deadline=$((SECONDS + HEARTBEAT_SUMMARY_TIMEOUT))
        while ! p3_projection_fields_present "${details}"; do
            if [ "${SECONDS}" -ge "${deadline}" ]; then
                echo "missing neutron-aria-agent P3 projection heartbeat fields on ${host}" >&2
                echo "${details}" >&2
                exit 1
            fi
            sleep 3
            details="$(neutron agent-show "${agent_id}" -f json)"
        done
        echo "p3_projection_fields=ok host=${host}"
    fi
done

echo "neutron-aria-agent heartbeat smoke passed"
