#!/usr/bin/env bash
set -euo pipefail

EXPECTED_HOSTS="${EXPECTED_HOSTS:-compute-1.example.test compute-2.example.test compute-3.example.test}"
ADMINRC="${ADMINRC:-/root/adminrc}"
REQUIRE_HEARTBEAT_SUMMARY_FIELDS="${REQUIRE_HEARTBEAT_SUMMARY_FIELDS:-false}"
REQUIRE_P3_PROJECTION_FIELDS="${REQUIRE_P3_PROJECTION_FIELDS:-false}"
REQUIRE_HEARTBEAT_V2="${REQUIRE_HEARTBEAT_V2:-false}"
HEARTBEAT_SUMMARY_TIMEOUT="${HEARTBEAT_SUMMARY_TIMEOUT:-45}"
HEARTBEAT_MAX_PAYLOAD_BYTES="${HEARTBEAT_MAX_PAYLOAD_BYTES:-16384}"
HEARTBEAT_PORT_STATUS_ID="${HEARTBEAT_PORT_STATUS_ID:-}"

case "${HEARTBEAT_MAX_PAYLOAD_BYTES}" in
    ''|*[!0-9]*|0)
        echo "HEARTBEAT_MAX_PAYLOAD_BYTES must be a positive integer" >&2
        exit 2
        ;;
esac

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
        status_reason_counts \
        degraded_reasons; do
        echo "${details}" | grep "${field}" >/dev/null || return 1
    done
}

p3_projection_fields_present() {
    local details="$1"
    for field in \
        heartbeat_schema_version \
        heartbeat_detail_mode \
        projection_index \
        last_event_decision_counts \
        last_event_decision_updated_at; do
        echo "${details}" | grep "${field}" >/dev/null || return 1
    done
}

heartbeat_v2_summary_present() {
    local details="$1"
    local payload_bytes
    local forbidden

    echo "${details}" | grep -E 'heartbeat_schema_version[^0-9]*2' >/dev/null || return 1
    echo "${details}" | grep -E 'heartbeat_detail_mode[^a-z_]*summary_only' >/dev/null || return 1
    for forbidden in \
        last_managed_ports_detail \
        last_port_statuses \
        last_event_decisions; do
        if echo "${details}" | grep "${forbidden}" >/dev/null; then
            return 1
        fi
    done
    payload_bytes="$(printf '%s' "${details}" | wc -c | tr -d ' ')"
    [ "${payload_bytes}" -le "${HEARTBEAT_MAX_PAYLOAD_BYTES}" ]
}

port_status_fields_present() {
    local details="$1"
    local field

    for field in port_id status runtime_status effective_action; do
        echo "${details}" | grep "${field}" >/dev/null || return 1
    done
    echo "${details}" | grep "${HEARTBEAT_PORT_STATUS_ID}" >/dev/null
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

    if [ "${REQUIRE_HEARTBEAT_V2}" = "true" ]; then
        deadline=$((SECONDS + HEARTBEAT_SUMMARY_TIMEOUT))
        while ! heartbeat_v2_summary_present "${details}"; do
            if [ "${SECONDS}" -ge "${deadline}" ]; then
                echo "heartbeat V2 summary-only contract failed on ${host}" >&2
                echo "payload_bytes=$(printf '%s' "${details}" | wc -c | tr -d ' ') max_bytes=${HEARTBEAT_MAX_PAYLOAD_BYTES}" >&2
                echo "${details}" >&2
                exit 1
            fi
            sleep 3
            details="$(neutron agent-show "${agent_id}" -f json)"
        done
        echo "heartbeat_v2_summary=ok host=${host}"
    fi
done

if [ -n "${HEARTBEAT_PORT_STATUS_ID}" ]; then
    port_status="$(
        neutron aria-acl-port-status-show "${HEARTBEAT_PORT_STATUS_ID}" -f json
    )"
    if ! port_status_fields_present "${port_status}"; then
        echo "dedicated ACL port-status projection failed for ${HEARTBEAT_PORT_STATUS_ID}" >&2
        echo "${port_status}" >&2
        exit 1
    fi
    echo "heartbeat_port_status_api=ok port_id=${HEARTBEAT_PORT_STATUS_ID}"
fi

echo "neutron-aria-agent heartbeat smoke passed"
