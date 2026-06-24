#!/usr/bin/env bash
set -euo pipefail

SERVICE_NAME="${SERVICE_NAME:-aria_datapath}"
BASE_CONTAINER="${BASE_CONTAINER:-neutron_openvswitch_agent}"
BASE_IMAGE="${BASE_IMAGE:-}"
IMAGE="${IMAGE:-aria-datapath:smoke}"
CONFIG_DIR="${CONFIG_DIR:-/etc/kolla/aria-datapath}"
REPO_ROOT="${REPO_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)}"
ARTIFACT_DIR="${ARTIFACT_DIR:-${REPO_ROOT}/release}"
ARIA_AGENT_BINARY="${ARIA_AGENT_BINARY:-${ARTIFACT_DIR}/aria-agent}"
EBPF_SO="${EBPF_SO:-${ARTIFACT_DIR}/libebpf_firewall.so}"
EBPF_PERF_SO="${EBPF_PERF_SO:-${ARTIFACT_DIR}/libebpf_firewall_perf.so}"
RUN_ARIA_DIR="${RUN_ARIA_DIR:-/run/aria}"
SOCKET_PATH="${SOCKET_PATH:-/run/aria/aria-agent.sock}"
STATE_DIR="${STATE_DIR:-/var/lib/aria-agent-smoke}"
OVS_BRIDGE="${OVS_BRIDGE:-br-int}"
BUILD_IMAGE="${BUILD_IMAGE:-true}"
START_CONTAINER="${START_CONTAINER:-true}"
PRIVILEGED="${PRIVILEGED:-true}"
HOST_PID="${HOST_PID:-true}"
WAIT_SECONDS="${WAIT_SECONDS:-20}"
UDS_READY_RETRIES="${UDS_READY_RETRIES:-20}"
UDS_READY_INTERVAL="${UDS_READY_INTERVAL:-1}"
REQUIRE_NO_ACTIVE_INSTANCES="${REQUIRE_NO_ACTIVE_INSTANCES:-true}"
PYTHON_BIN="${PYTHON_BIN:-}"

die() {
    echo "ERROR: $*" >&2
    exit 1
}

need_command() {
    command -v "$1" >/dev/null 2>&1 || die "missing command: $1"
}

require_file() {
    [ -f "$1" ] || die "missing file: $1"
}

require_dir() {
    [ -d "$1" ] || die "missing directory: $1"
}

json_check() {
    local name="$1"
    local value="$2"
    REQUIRE_NO_ACTIVE_INSTANCES="${REQUIRE_NO_ACTIVE_INSTANCES:-}" \
        JSON_PAYLOAD="${value}" \
        JSON_NAME="${name}" \
        "${PYTHON_BIN}" - <<'PY'
from __future__ import print_function

import json
import os
import sys

name = os.environ["JSON_NAME"]
payload = json.loads(os.environ["JSON_PAYLOAD"])

if name == "capabilities":
    assert payload.get("api_version") == "v1", payload
    assert payload.get("attach_authority") == "neutron_snapshot", payload
    assert payload.get("supports_full_snapshot") is True, payload
    domains = set(payload.get("supported_domains") or [])
    for domain in ("attach", "acl", "qos", "mirror"):
        assert domain in domains, payload
elif name == "initial_status":
    assert payload.get("managed_ports") == [], payload
    if os.environ.get("REQUIRE_NO_ACTIVE_INSTANCES") == "true":
        assert payload.get("active_instances") == [], payload
elif name == "missing_port_snapshot":
    results = payload.get("results") or []
    assert len(results) == 1, payload
    result = results[0]
    assert result.get("action") == "ignore", payload
    assert result.get("status") == "ignored", payload
    assert result.get("reason") == "ovs_iface_id_not_found", payload
elif name == "final_status":
    assert payload.get("managed_ports") == [], payload
else:
    raise AssertionError("unknown check %s" % name)

print("%s ok" % name)
PY
}

build_image() {
    if [ "${BUILD_IMAGE}" != "true" ]; then
        echo "Skipping image build; using existing image: ${IMAGE}"
        return
    fi

    require_file "${ARIA_AGENT_BINARY}"
    require_file "${EBPF_SO}"
    if [ ! -f "${EBPF_PERF_SO}" ]; then
        echo "missing ${EBPF_PERF_SO}; reusing ${EBPF_SO} for perf path"
        EBPF_PERF_SO="${EBPF_SO}"
    fi

    if [ "${BASE_IMAGE}" = "" ]; then
        BASE_IMAGE="$(docker inspect "${BASE_CONTAINER}" --format '{{.Config.Image}}')"
    fi

    tmpdir="$(mktemp -d)"
    trap 'rm -rf "${tmpdir:-}"' EXIT
    cp "${ARIA_AGENT_BINARY}" "${tmpdir}/aria-agent"
    cp "${EBPF_SO}" "${tmpdir}/libebpf_firewall.so"
    cp "${EBPF_PERF_SO}" "${tmpdir}/libebpf_firewall_perf.so"
    cp "${REPO_ROOT}/deploy/kolla/aria-datapath/start-aria-datapath.sh" \
        "${tmpdir}/start-aria-datapath"

    cat >"${tmpdir}/Dockerfile" <<'EOF'
ARG BASE_IMAGE
FROM ${BASE_IMAGE}

USER root

COPY aria-agent /usr/local/bin/aria-agent
COPY libebpf_firewall.so /usr/local/lib/libebpf_firewall.so
COPY libebpf_firewall_perf.so /usr/local/lib/libebpf_firewall_perf.so
COPY start-aria-datapath /usr/local/bin/start-aria-datapath

RUN chmod 0755 /usr/local/bin/aria-agent /usr/local/bin/start-aria-datapath && \
    chmod 0644 /usr/local/lib/libebpf_firewall.so /usr/local/lib/libebpf_firewall_perf.so

USER root
EOF

    echo "Building service image: ${IMAGE}"
    echo "Using base image: ${BASE_IMAGE}"
    docker build --build-arg BASE_IMAGE="${BASE_IMAGE}" -t "${IMAGE}" "${tmpdir}"
}

prepare_config() {
    echo "Preparing Kolla config directory: ${CONFIG_DIR}"
    mkdir -p "${CONFIG_DIR}"
    cp "${REPO_ROOT}/deploy/kolla/aria-datapath/config.json" "${CONFIG_DIR}/config.json"
    cp "${REPO_ROOT}/deploy/kolla/config/aria-agent-openstack.toml" \
        "${CONFIG_DIR}/aria-agent-openstack.toml"
    sed -i "s#^ovs_bridge =.*#ovs_bridge = \"${OVS_BRIDGE}\"#" \
        "${CONFIG_DIR}/aria-agent-openstack.toml"
}

start_container() {
    if [ "${START_CONTAINER}" != "true" ]; then
        echo "Skipping container start; checking existing ${SERVICE_NAME}"
        return
    fi

    require_dir /run/openvswitch
    require_dir /sys/fs/bpf
    mkdir -p "${RUN_ARIA_DIR}" "${STATE_DIR}"

    docker rm -f "${SERVICE_NAME}" >/dev/null 2>&1 || true

    docker_run_args=(
        -d
        --name "${SERVICE_NAME}"
        --net=host
        --restart unless-stopped
        -e KOLLA_CONFIG_STRATEGY=COPY_ALWAYS
        -e KOLLA_SERVICE_NAME=aria-datapath
        -v "${CONFIG_DIR}/:/var/lib/kolla/config_files/:ro"
        -v /etc/localtime:/etc/localtime:ro
        -v kolla_logs:/var/log/kolla/:rw
        -v "${RUN_ARIA_DIR}:${RUN_ARIA_DIR}:rw"
        -v /run/openvswitch:/run/openvswitch:shared
        -v /sys/fs/bpf:/sys/fs/bpf:shared
        -v "${STATE_DIR}:/var/lib/aria-agent:rw"
    )

    if [ -f /sys/kernel/btf/vmlinux ]; then
        docker_run_args+=(-v /sys/kernel/btf/vmlinux:/sys/kernel/btf/vmlinux:ro)
    fi

    if [ "${PRIVILEGED}" = "true" ]; then
        docker_run_args+=(--privileged)
    fi

    if [ "${HOST_PID}" = "true" ]; then
        docker_run_args+=(--pid=host)
    fi

    echo "Starting independent container: ${SERVICE_NAME}"
    docker run "${docker_run_args[@]}" "${IMAGE}"
}

wait_for_socket() {
    echo "Waiting for ${SOCKET_PATH}"
    for _ in $(seq 1 "${WAIT_SECONDS}"); do
        if [ -S "${SOCKET_PATH}" ]; then
            return
        fi
        sleep 1
    done
    docker ps --filter "name=${SERVICE_NAME}" --format 'table {{.Names}}\t{{.Image}}\t{{.Status}}' >&2 || true
    docker logs --tail 80 "${SERVICE_NAME}" >&2 || true
    die "UDS socket did not appear: ${SOCKET_PATH}"
}

assert_container_boundary() {
    docker ps --format '{{.Names}}' | grep -qx "${SERVICE_NAME}" || die "${SERVICE_NAME} is not running"

    privileged="$(docker inspect "${SERVICE_NAME}" --format '{{.HostConfig.Privileged}}')"
    [ "${privileged}" = "${PRIVILEGED}" ] || die "unexpected privileged=${privileged}"

    mounts="$(docker inspect "${SERVICE_NAME}" --format '{{range .Mounts}}{{println .Destination}}{{end}}')"
    echo "${mounts}" | grep -qx '/run/aria' || die "${SERVICE_NAME} must mount /run/aria"
    echo "${mounts}" | grep -qx '/run/openvswitch' || die "${SERVICE_NAME} must mount /run/openvswitch"
    echo "${mounts}" | grep -qx '/sys/fs/bpf' || die "${SERVICE_NAME} must mount /sys/fs/bpf"

    docker exec "${SERVICE_NAME}" test -x /usr/local/bin/aria-agent || die "aria-agent binary missing"
    docker exec "${SERVICE_NAME}" test -f /usr/local/lib/libebpf_firewall.so || die "eBPF artifact missing"
    docker exec "${SERVICE_NAME}" test -S "${SOCKET_PATH}" || die "${SOCKET_PATH} is not visible in container"
    docker exec "${SERVICE_NAME}" ovs-vsctl --timeout=5 br-exists "${OVS_BRIDGE}" || \
        die "${OVS_BRIDGE} is not visible in ${SERVICE_NAME}"
}

curl_uds() {
    local attempt
    local output
    for attempt in $(seq 1 "${UDS_READY_RETRIES}"); do
        if output="$(curl --silent --show-error --fail --unix-socket "${SOCKET_PATH}" "$@" 2>&1)"; then
            printf '%s' "${output}"
            return 0
        fi
        if [ "${attempt}" -lt "${UDS_READY_RETRIES}" ]; then
            sleep "${UDS_READY_INTERVAL}"
        fi
    done
    printf '%s\n' "${output}" >&2
    return 1
}

check_uds_contract() {
    echo "Checking UDS capabilities"
    capabilities="$(curl_uds "http://localhost/api/v1/neutron/capabilities")"
    echo "${capabilities}"
    json_check capabilities "${capabilities}"

    echo "Checking initial status"
    status="$(curl_uds "http://localhost/api/v1/neutron/status")"
    echo "${status}"
    json_check initial_status "${status}"

    fake_port_id="00000000-0000-4000-8000-000000000001"
    snapshot="$(
        "${PYTHON_BIN}" - "${fake_port_id}" <<'PY'
from __future__ import print_function

import json
import sys

port_id = sys.argv[1]
print(json.dumps({
    "generation": 1,
    "host": "aria-datapath-smoke",
    "ports": [{
        "port_id": port_id,
        "ifname": "",
        "eligible": True,
        "disposition": "pending_local_validation",
        "device_owner": "compute:nova",
        "vif_type": "ovs",
        "vnic_type": "normal",
        "network_backend": "openvswitch",
        "managed_domains": ["acl"],
    }],
}))
PY
    )"

    echo "Submitting missing-port validation snapshot"
    response="$(curl_uds \
        -X PUT \
        -H 'Content-Type: application/json' \
        --data "${snapshot}" \
        "http://localhost/api/v1/neutron/snapshot")"
    echo "${response}"
    json_check missing_port_snapshot "${response}"

    curl_uds -X DELETE "http://localhost/api/v1/neutron/ports/${fake_port_id}" >/dev/null || true

    final_status="$(curl_uds "http://localhost/api/v1/neutron/status")"
    echo "${final_status}"
    json_check final_status "${final_status}"
}

need_command docker
need_command curl
if [ -z "${PYTHON_BIN}" ]; then
    PYTHON_BIN="$(command -v python3 || command -v python || true)"
fi
[ -n "${PYTHON_BIN}" ] || die "missing command: python3 or python"

build_image
prepare_config
start_container
wait_for_socket
assert_container_boundary
check_uds_contract

docker ps --filter "name=${SERVICE_NAME}" --format 'table {{.Names}}\t{{.Image}}\t{{.Status}}'
docker exec "${SERVICE_NAME}" sh -c 'tail -n 40 /var/log/kolla/aria-datapath/aria-datapath.log' || true
echo "aria-datapath independent container smoke passed"
