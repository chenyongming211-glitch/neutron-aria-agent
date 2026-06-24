#!/usr/bin/env bash
set -euo pipefail

SERVICE_NAME="${SERVICE_NAME:-neutron_aria_agent}"
REQUIRE_RUN_ARIA="${REQUIRE_RUN_ARIA:-true}"

die() {
    echo "ERROR: $*" >&2
    exit 1
}

docker ps --format '{{.Names}}' | grep -qx "${SERVICE_NAME}" || die "${SERVICE_NAME} is not running"

privileged="$(docker inspect "${SERVICE_NAME}" --format '{{.HostConfig.Privileged}}')"
[ "${privileged}" = "false" ] || die "${SERVICE_NAME} must not be privileged"

user="$(docker inspect "${SERVICE_NAME}" --format '{{.Config.User}}')"
[ "${user}" = "neutron" ] || die "${SERVICE_NAME} must run as neutron, got '${user}'"

mounts="$(docker inspect "${SERVICE_NAME}" --format '{{range .Mounts}}{{println .Destination}}{{end}}')"
echo "${mounts}" | grep -qx '/run/openvswitch' && die "${SERVICE_NAME} must not mount /run/openvswitch"
echo "${mounts}" | grep -qx '/sys/fs/bpf' && die "${SERVICE_NAME} must not mount /sys/fs/bpf"
echo "${mounts}" | grep -qx '/lib/modules' && die "${SERVICE_NAME} must not mount /lib/modules"

if [ "${REQUIRE_RUN_ARIA}" = "true" ]; then
    echo "${mounts}" | grep -qx '/run/aria' || die "${SERVICE_NAME} must mount /run/aria"
    docker exec -u neutron "${SERVICE_NAME}" test -S /run/aria/aria-agent.sock || \
        die "/run/aria/aria-agent.sock is not visible to neutron user"
fi

echo "neutron-aria-agent boundary smoke passed"
