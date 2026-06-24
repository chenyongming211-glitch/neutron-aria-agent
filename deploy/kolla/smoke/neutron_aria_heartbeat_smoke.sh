#!/usr/bin/env bash
set -euo pipefail

EXPECTED_HOSTS="${EXPECTED_HOSTS:-ostack2.bj159.net ostack3.bj159.net ostack4.bj159.net}"

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
