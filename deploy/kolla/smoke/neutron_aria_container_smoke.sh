#!/usr/bin/env bash
set -euo pipefail

SERVICE_NAME="${SERVICE_NAME:-neutron_aria_agent}"
BASE_CONTAINER="${BASE_CONTAINER:-neutron_openvswitch_agent}"
BASE_IMAGE="${BASE_IMAGE:-}"
IMAGE="${IMAGE:-neutron-aria-agent:smoke}"
CONFIG_DIR="${CONFIG_DIR:-/etc/kolla/neutron-aria-agent}"
REPO_ROOT="${REPO_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)}"
HOST_FQDN="${HOST_FQDN:-$(hostname -f)}"
ADMINRC="${ADMINRC:-/root/adminrc}"
STOP_EMBEDDED_SMOKE="${STOP_EMBEDDED_SMOKE:-true}"
BUILD_IMAGE="${BUILD_IMAGE:-true}"
DOCKER_BUILD_NO_CACHE="${DOCKER_BUILD_NO_CACHE:-false}"
MOUNT_RUN_ARIA="${MOUNT_RUN_ARIA:-false}"
RUN_ARIA_DIR="${RUN_ARIA_DIR:-/run/aria}"
PRIVILEGED="${PRIVILEGED:-false}"
MOUNT_OVSDB="${MOUNT_OVSDB:-false}"
MOUNT_LIB_MODULES="${MOUNT_LIB_MODULES:-false}"

echo "Building service image: ${IMAGE}"

if [ "${BUILD_IMAGE}" = "true" ]; then
    if [ "${BASE_IMAGE}" = "" ]; then
        BASE_IMAGE="$(docker inspect "${BASE_CONTAINER}" --format '{{.Config.Image}}')"
    fi
    echo "Using base image: ${BASE_IMAGE}"
    docker_build_args=()
    if [ "${DOCKER_BUILD_NO_CACHE}" = "true" ]; then
        docker_build_args+=(--no-cache)
    fi
    docker build \
        "${docker_build_args[@]}" \
        --build-arg BASE_IMAGE="${BASE_IMAGE}" \
        -f "${REPO_ROOT}/deploy/kolla/neutron-aria-agent/Dockerfile" \
        -t "${IMAGE}" \
        "${REPO_ROOT}"
else
    echo "Skipping image build; using existing image: ${IMAGE}"
fi

echo "Preparing Kolla config directory: ${CONFIG_DIR}"
mkdir -p "${CONFIG_DIR}"
cp /etc/kolla/neutron-openvswitch-agent/neutron.conf "${CONFIG_DIR}/neutron.conf"
cp /etc/kolla/neutron-openvswitch-agent/openvswitch_agent.ini "${CONFIG_DIR}/openvswitch_agent.ini"
cp "${REPO_ROOT}/deploy/kolla/neutron-aria-agent/config.json" "${CONFIG_DIR}/config.json"
sed "s/^host =.*/host = ${HOST_FQDN}/" \
    "${REPO_ROOT}/deploy/kolla/config/neutron-aria-agent.ini" \
    > "${CONFIG_DIR}/neutron-aria-agent.ini"

if [ "${STOP_EMBEDDED_SMOKE}" = "true" ] && docker ps --format '{{.Names}}' | grep -qx "${BASE_CONTAINER}"; then
    echo "Stopping temporary embedded neutron-aria-agent process in ${BASE_CONTAINER}"
    docker exec -u root "${BASE_CONTAINER}" pkill -f '[n]eutron_aria.agent.main' || true
    docker exec -u root "${BASE_CONTAINER}" pkill -f '[n]eutron-aria-agent.ini' || true
fi

echo "Starting independent container: ${SERVICE_NAME}"
docker rm -f "${SERVICE_NAME}" >/dev/null 2>&1 || true
docker_run_args=(
    -d
    --name "${SERVICE_NAME}"
    --net=host
    --restart unless-stopped
    -e KOLLA_CONFIG_STRATEGY=COPY_ALWAYS
    -e KOLLA_SERVICE_NAME=neutron-aria-agent
    -v "${CONFIG_DIR}/:/var/lib/kolla/config_files/:ro"
    -v /etc/localtime:/etc/localtime:ro
    -v kolla_logs:/var/log/kolla/:rw
)

if [ "${PRIVILEGED}" = "true" ]; then
    docker_run_args+=(--privileged)
fi

if [ "${MOUNT_OVSDB}" = "true" ]; then
    docker_run_args+=(-v /run/openvswitch:/run/openvswitch:shared)
fi

if [ "${MOUNT_LIB_MODULES}" = "true" ]; then
    docker_run_args+=(-v /lib/modules:/lib/modules:ro)
fi

if [ "${MOUNT_RUN_ARIA}" = "true" ]; then
    if [ ! -d "${RUN_ARIA_DIR}" ]; then
        echo "missing ${RUN_ARIA_DIR}; cannot mount Aria UDS directory" >&2
        exit 1
    fi
    docker_run_args+=(-v "${RUN_ARIA_DIR}:${RUN_ARIA_DIR}:rw")
fi

docker run "${docker_run_args[@]}" "${IMAGE}"

sleep "${SMOKE_WAIT_SECONDS:-8}"

echo "Container status:"
docker ps --filter "name=${SERVICE_NAME}" --format 'table {{.Names}}\t{{.Image}}\t{{.Status}}'

echo "Agent log tail:"
docker exec "${SERVICE_NAME}" sh -c 'tail -n 30 /var/log/kolla/neutron/neutron-aria-agent.log'

if [ -r "${ADMINRC}" ]; then
    # shellcheck disable=SC1090
    source "${ADMINRC}"
fi

if command -v neutron >/dev/null 2>&1; then
    echo "Neutron agent-list entry:"
    neutron agent-list | grep "Aria ACL agent" | grep " ${HOST_FQDN} "
elif docker ps --format '{{.Names}}' | grep -qx openstack_client; then
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
    echo "Neutron agent-list entry:"
    neutron agent-list | grep "Aria ACL agent" | grep " ${HOST_FQDN} "
else
    echo "neutron command not found; skipping control-plane list check"
fi

echo "neutron-aria-agent independent container smoke passed on ${HOST_FQDN}"
