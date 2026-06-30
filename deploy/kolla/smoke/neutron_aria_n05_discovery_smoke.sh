#!/usr/bin/env bash
set -euo pipefail

ADMINRC="${ADMINRC:-/root/adminrc}"
HOST_FQDN="${HOST_FQDN:-$(hostname -f 2>/dev/null || hostname)}"
OVS_BRIDGE="${OVS_BRIDGE:-br-int}"
SERVICE_NAME="${SERVICE_NAME:-neutron_aria_agent}"
NEUTRON_SERVER="${NEUTRON_SERVER:-neutron_server}"
OVS_AGENT="${OVS_AGENT:-neutron_openvswitch_agent}"
OPENSTACK_CLIENT="${OPENSTACK_CLIENT:-openstack_client}"
SOCKET_PATH="${SOCKET_PATH:-/run/aria/aria-agent.sock}"
RUN_ARIA_DIR="${RUN_ARIA_DIR:-/run/aria}"
EVIDENCE_ROOT="${EVIDENCE_ROOT:-/var/tmp/neutron-aria-n05-discovery}"
EVIDENCE_DIR="${EVIDENCE_DIR:-${EVIDENCE_ROOT}/$(date +%Y%m%d%H%M%S)-${HOST_FQDN}}"
FAIL_ON_REQUIRED="${FAIL_ON_REQUIRED:-false}"

mkdir -p "${EVIDENCE_DIR}"
COMMANDS_LOG="${EVIDENCE_DIR}/commands.log"
FACTS_TSV="${EVIDENCE_DIR}/facts.tsv"
SUMMARY_MD="${EVIDENCE_DIR}/summary.md"

if [ -r "${ADMINRC}" ]; then
    # shellcheck disable=SC1090
    source "${ADMINRC}"
fi

log() {
    printf '[neutron-aria-n05-discovery] %s\n' "$*"
}

escape_md() {
    printf '%s' "$1" | tr '\n' ' ' | sed 's/|/\\|/g'
}

docker_has_container() {
    command -v docker >/dev/null 2>&1 || return 1
    docker ps --format '{{.Names}}' 2>/dev/null | grep -qx "$1"
}

docker_exec_openstack_client() {
    docker exec \
        -u root \
        -e OS_AUTH_URL="${OS_AUTH_URL:-}" \
        -e OS_USERNAME="${OS_USERNAME:-}" \
        -e OS_PASSWORD="${OS_PASSWORD:-}" \
        -e OS_TENANT_NAME="${OS_TENANT_NAME:-}" \
        -e OS_PROJECT_NAME="${OS_PROJECT_NAME:-}" \
        -e OS_REGION_NAME="${OS_REGION_NAME:-}" \
        -e OS_ENDPOINT_TYPE="${OS_ENDPOINT_TYPE:-}" \
        -e OS_INTERFACE="${OS_INTERFACE:-}" \
        -e OS_CACERT="${OS_CACERT:-}" \
        -e OS_INSECURE="${OS_INSECURE:-}" \
        -e OS_NO_CACHE="${OS_NO_CACHE:-true}" \
        -e OS_AUTH_STRATEGY="${OS_AUTH_STRATEGY:-keystone}" \
        -e NEUTRON_ENDPOINT_TYPE="${NEUTRON_ENDPOINT_TYPE:-publicURL}" \
        "${OPENSTACK_CLIENT}" "$@"
}

openstack_cli() {
    if command -v openstack >/dev/null 2>&1; then
        openstack "$@"
    elif docker_has_container "${OPENSTACK_CLIENT}"; then
        docker_exec_openstack_client openstack "$@"
    else
        echo "openstack CLI unavailable and ${OPENSTACK_CLIENT} is not running" >&2
        return 127
    fi
}

neutron_cli() {
    if command -v neutron >/dev/null 2>&1; then
        neutron "$@"
    elif docker_has_container "${OPENSTACK_CLIENT}"; then
        docker_exec_openstack_client neutron "$@"
    else
        echo "neutron CLI unavailable and ${OPENSTACK_CLIENT} is not running" >&2
        return 127
    fi
}

neutron_extension_list() {
    neutron_cli extension-list || neutron_cli ext-list
}

neutron_agent_list() {
    neutron_cli agent-list
}

first_tap() {
    ip -o link show 2>/dev/null \
        | sed -n 's/^[0-9]\+: \(tap[^:@]*\).*/\1/p' \
        | head -1
}

capture() {
    local fact="$1"
    local expected="$2"
    local fail_disposition="$3"
    local output_name="$4"
    shift 4

    local output_path="${EVIDENCE_DIR}/${output_name}"
    local command_text="$*"
    log "Collecting ${fact}"
    {
        printf '## %s\n' "${fact}"
        printf 'expected: %s\n' "${expected}"
        printf 'command: %s\n\n' "${command_text}"
    } >> "${COMMANDS_LOG}"

    set +e
    "$@" > "${output_path}" 2>&1
    local rc=$?
    set -e

    local disposition="pass"
    local actual="exit=0"
    if [ "${rc}" -ne 0 ]; then
        case "${rc}" in
            2)
                disposition="not_applicable"
                ;;
            3)
                disposition="unsupported"
                ;;
            4)
                disposition="degraded"
                ;;
            *)
                disposition="${fail_disposition}"
                ;;
        esac
        actual="exit=${rc}"
    fi

    printf '%s\t%s\t%s\t%s\t%s\t%s\n' \
        "${fact}" \
        "${expected}" \
        "${command_text}" \
        "${actual}" \
        "${output_name}" \
        "${disposition}" >> "${FACTS_TSV}"

    printf 'exit=%s disposition=%s output=%s\n\n' \
        "${rc}" "${disposition}" "${output_path}" >> "${COMMANDS_LOG}"
    return 0
}

collect_versions() {
    echo "host=${HOST_FQDN}"
    echo
    uname -a
    echo
    if [ -r /etc/os-release ]; then
        cat /etc/os-release
    fi
    echo
    (openstack_cli --version || true)
    (neutron_cli --version || true)
}

collect_ml2_config() {
    local found=1
    if [ -d /etc/neutron/plugins/ml2 ]; then
        echo "## host /etc/neutron/plugins/ml2"
        grep -R "mechanism_drivers\|tenant_network_types\|type_drivers" \
            /etc/neutron/plugins/ml2 2>/dev/null || true
        found=0
    fi
    if docker_has_container "${NEUTRON_SERVER}"; then
        echo
        echo "## ${NEUTRON_SERVER} /etc/neutron/plugins/ml2"
        docker exec -u root "${NEUTRON_SERVER}" sh -c \
            'grep -R "mechanism_drivers\|tenant_network_types\|type_drivers" /etc/neutron/plugins/ml2 2>/dev/null || true'
        found=0
    fi
    if docker_has_container "${OVS_AGENT}"; then
        echo
        echo "## ${OVS_AGENT} /etc/neutron/plugins/ml2"
        docker exec -u root "${OVS_AGENT}" sh -c \
            'grep -R "mechanism_drivers\|tenant_network_types\|type_drivers" /etc/neutron/plugins/ml2 2>/dev/null || true'
        found=0
    fi
    return "${found}"
}

collect_ovs_topology() {
    ovs-vsctl --version
    echo
    ovs-vsctl show
    echo
    echo "## bridges"
    ovs-vsctl list-br
    echo
    echo "## ${OVS_BRIDGE} ports"
    ovs-vsctl list-ports "${OVS_BRIDGE}"
}

collect_tap_inventory() {
    echo "## ip link tap/qvo/qvb/veth"
    ip -o link show | grep -E 'tap|qvo|qvb|veth' || true
    echo
    echo "## OVS interface external_ids"
    ovs-vsctl --columns=name,ofport,external_ids list Interface
}

check_no_hybrid_plug() {
    if ip -o link show | grep -E 'qvo|qvb' >/dev/null; then
        ip -o link show | grep -E 'qvo|qvb'
        return 1
    fi
    echo "No qvo/qvb links found on ${HOST_FQDN}"
}

check_ovs_iface_id() {
    if [ -z "$(first_tap || true)" ]; then
        echo "No local tap interface found; iface-id evidence is not applicable on this host at this time"
        return 2
    fi
    ovs-vsctl --columns=name,external_ids list Interface | tee /dev/stderr \
        | grep -q 'iface-id'
}

collect_bpf_capability() {
    echo "## BTF"
    test -r /sys/kernel/btf/vmlinux
    ls -l /sys/kernel/btf/vmlinux
    echo
    echo "## bpffs"
    if mount | grep -q ' /sys/fs/bpf '; then
        mount | grep ' /sys/fs/bpf '
    else
        grep -w '/sys/fs/bpf' /proc/mounts
    fi
}

collect_tc_capability() {
    command -v tc
    echo
    local tap
    tap="$(first_tap || true)"
    if [ -n "${tap}" ]; then
        echo "## tc qdisc for ${tap}"
        tc qdisc show dev "${tap}"
    else
        echo "No tap interface found; showing global qdisc sample"
        tc qdisc show | sed -n '1,120p'
    fi
}

collect_xdp_status() {
    local tap
    tap="$(first_tap || true)"
    if [ -z "${tap}" ]; then
        echo "No tap interface found"
        return 2
    fi
    ip -d link show "${tap}"
}

collect_run_aria_permissions() {
    echo "## ${RUN_ARIA_DIR}"
    stat -c "%n %U %G %a %F" "${RUN_ARIA_DIR}"
    echo
    echo "## ${SOCKET_PATH}"
    stat -c "%n %U %G %a %F" "${SOCKET_PATH}"
}

collect_container_state() {
    docker ps --format 'table {{.Names}}\t{{.Image}}\t{{.Status}}'
    echo
    for name in "${NEUTRON_SERVER}" "${OVS_AGENT}" "${SERVICE_NAME}" "${OPENSTACK_CLIENT}"; do
        if docker_has_container "${name}"; then
            echo "## inspect ${name}"
            docker inspect "${name}" \
                --format 'name={{.Name}} image={{.Config.Image}} user={{.Config.User}} mounts={{range .Mounts}}{{.Source}}:{{.Destination}}:{{.Mode}};{{end}}'
            echo
        fi
    done
}

collect_neutron_aria_agent_status() {
    if ! docker_has_container "${SERVICE_NAME}"; then
        echo "${SERVICE_NAME} is not running" >&2
        return 1
    fi
    docker exec -i -u neutron "${SERVICE_NAME}" python - "${SOCKET_PATH}" <<'PY'
from __future__ import print_function

import json
import sys

from neutron_aria.agent.uds_client import LocalClient

socket_path = sys.argv[1]
client = LocalClient(socket_path, timeout=3.0)
print("capabilities=%s" % json.dumps(client.capabilities(), sort_keys=True))
print("status=%s" % json.dumps(client.status(), sort_keys=True))
PY
}

collect_neutron_port_source() {
    if ! docker_has_container "${SERVICE_NAME}"; then
        echo "${SERVICE_NAME} is not running" >&2
        return 1
    fi
    docker exec \
        -i \
        -u neutron \
        -e OS_AUTH_URL="${OS_AUTH_URL:-}" \
        -e OS_USERNAME="${OS_USERNAME:-}" \
        -e OS_PASSWORD="${OS_PASSWORD:-}" \
        -e OS_TENANT_NAME="${OS_TENANT_NAME:-}" \
        -e OS_PROJECT_NAME="${OS_PROJECT_NAME:-}" \
        -e OS_REGION_NAME="${OS_REGION_NAME:-}" \
        -e OS_ENDPOINT_TYPE="${OS_ENDPOINT_TYPE:-}" \
        -e OS_INTERFACE="${OS_INTERFACE:-}" \
        -e OS_CACERT="${OS_CACERT:-}" \
        -e OS_INSECURE="${OS_INSECURE:-}" \
        -e OS_NO_CACHE="${OS_NO_CACHE:-true}" \
        -e OS_AUTH_STRATEGY="${OS_AUTH_STRATEGY:-keystone}" \
        -e NEUTRON_ENDPOINT_TYPE="${NEUTRON_ENDPOINT_TYPE:-publicURL}" \
        "${SERVICE_NAME}" python - "${HOST_FQDN}" <<'PY'
from __future__ import print_function

import sys

from neutron_aria.agent.neutron_client import NeutronPortSource
from neutron_aria.agent.neutron_client import build_neutronclient_from_env

host = sys.argv[1]
ports = NeutronPortSource(build_neutronclient_from_env(), host).list_ports_for_host()
compute = [
    port for port in ports
    if port.get("device_owner", "").startswith("compute:")
]
print("host=%s ports=%d compute_ports=%d" % (host, len(ports), len(compute)))
for port in compute[:20]:
    print("compute_port id=%s device_owner=%s binding_host=%s status=%s" % (
        port.get("id"),
        port.get("device_owner"),
        port.get("binding:host_id"),
        port.get("status"),
    ))
PY
}

collect_neutron_port_classes() {
    if ! docker_has_container "${SERVICE_NAME}"; then
        echo "${SERVICE_NAME} is not running" >&2
        return 1
    fi
    docker exec \
        -i \
        -u neutron \
        -e OS_AUTH_URL="${OS_AUTH_URL:-}" \
        -e OS_USERNAME="${OS_USERNAME:-}" \
        -e OS_PASSWORD="${OS_PASSWORD:-}" \
        -e OS_TENANT_NAME="${OS_TENANT_NAME:-}" \
        -e OS_PROJECT_NAME="${OS_PROJECT_NAME:-}" \
        -e OS_REGION_NAME="${OS_REGION_NAME:-}" \
        -e OS_ENDPOINT_TYPE="${OS_ENDPOINT_TYPE:-}" \
        -e OS_INTERFACE="${OS_INTERFACE:-}" \
        -e OS_CACERT="${OS_CACERT:-}" \
        -e OS_INSECURE="${OS_INSECURE:-}" \
        -e OS_NO_CACHE="${OS_NO_CACHE:-true}" \
        -e OS_AUTH_STRATEGY="${OS_AUTH_STRATEGY:-keystone}" \
        -e NEUTRON_ENDPOINT_TYPE="${NEUTRON_ENDPOINT_TYPE:-publicURL}" \
        "${SERVICE_NAME}" python - "${HOST_FQDN}" <<'PY'
from __future__ import print_function

import sys

from neutron_aria.agent.neutron_client import build_neutronclient_from_env

host = sys.argv[1]
unsupported_vnic_types = set([
    "baremetal",
    "direct",
    "direct-physical",
    "macvtap",
    "virtio-forwarder",
])

client = build_neutronclient_from_env()
ports = client.list_ports().get("ports") or []
host_ports = [
    port for port in ports
    if port.get("binding:host_id") == host
]
compute_ports = [
    port for port in host_ports
    if (port.get("device_owner") or "").startswith("compute:")
]

counts = {}
unsupported = []
for port in host_ports:
    vnic_type = port.get("binding:vnic_type") or "normal"
    counts[vnic_type] = counts.get(vnic_type, 0) + 1
    if vnic_type in unsupported_vnic_types:
        unsupported.append(port)

print("host=%s host_ports=%d compute_ports=%d" % (
    host, len(host_ports), len(compute_ports),
))
print("vnic_type_counts=%s" % ",".join(
    "%s:%s" % (key, counts[key]) for key in sorted(counts)
))
print("unsupported_vnic_types=%s" % ",".join(sorted(unsupported_vnic_types)))
for port in unsupported[:20]:
    print("unsupported_port id=%s vnic_type=%s device_owner=%s status=%s" % (
        port.get("id"),
        port.get("binding:vnic_type"),
        port.get("device_owner"),
        port.get("status"),
    ))
if unsupported:
    raise SystemExit(3)
PY
}

collect_aria_acl_api() {
    if ! docker_has_container "${SERVICE_NAME}"; then
        echo "${SERVICE_NAME} is not running" >&2
        return 1
    fi
    docker exec \
        -i \
        -u neutron \
        -e OS_AUTH_URL="${OS_AUTH_URL:-}" \
        -e OS_USERNAME="${OS_USERNAME:-}" \
        -e OS_PASSWORD="${OS_PASSWORD:-}" \
        -e OS_TENANT_NAME="${OS_TENANT_NAME:-}" \
        -e OS_PROJECT_NAME="${OS_PROJECT_NAME:-}" \
        -e OS_REGION_NAME="${OS_REGION_NAME:-}" \
        -e OS_ENDPOINT_TYPE="${OS_ENDPOINT_TYPE:-}" \
        -e OS_INTERFACE="${OS_INTERFACE:-}" \
        -e OS_CACERT="${OS_CACERT:-}" \
        -e OS_INSECURE="${OS_INSECURE:-}" \
        -e OS_NO_CACHE="${OS_NO_CACHE:-true}" \
        -e OS_AUTH_STRATEGY="${OS_AUTH_STRATEGY:-keystone}" \
        -e NEUTRON_ENDPOINT_TYPE="${NEUTRON_ENDPOINT_TYPE:-publicURL}" \
        "${SERVICE_NAME}" python - <<'PY'
from __future__ import print_function

from neutron_aria.agent.neutron_client import build_aria_acl_client_from_env

api = build_aria_acl_client_from_env()
for collection, loader in (
    ("aria_acl_policies", api.list_aria_acl_policies),
    ("aria_acl_rules", api.list_aria_acl_rules),
    ("aria_acl_bindings", api.list_aria_acl_bindings),
    ("aria_acl_port_statuses", api.list_aria_acl_port_statuses),
):
    payload = loader()
    rows = payload.get(collection) or []
    print("%s=%d" % (collection, len(rows)))
    if rows:
        print("%s_first_keys=%s" % (collection, ",".join(sorted(rows[0].keys()))))
PY
}

check_qos_extension() {
    neutron_extension_list | tee /dev/stderr | grep -i 'qos'
}

check_trunk_extension() {
    neutron_extension_list | tee /dev/stderr | grep -i 'trunk'
}

check_aria_acl_extension() {
    neutron_extension_list | tee /dev/stderr | grep -i 'aria-acl'
}

check_aria_agent_heartbeat() {
    neutron_agent_list | tee /dev/stderr | grep -i 'Aria ACL agent'
}

write_summary() {
    local pass_count=0
    local nonpass_count=0
    local fail_count=0

    {
        echo "# N0.5 Discovery Evidence"
        echo
        echo "Host: \`${HOST_FQDN}\`"
        echo
        echo "Generated at: \`$(date -u '+%Y-%m-%dT%H:%M:%SZ')\`"
        echo
        echo "This is a read-only discovery record. It does not enable ACL, QoS,"
        echo "Mirror, RPC event consumption, or datapath mutation."
        echo
        echo "| Fact | Expected | Command | Actual | Evidence | Disposition |"
        echo "| --- | --- | --- | --- | --- | --- |"
    } > "${SUMMARY_MD}"

    while IFS=$'\t' read -r fact expected command actual evidence disposition; do
        [ -n "${fact}" ] || continue
        if [ "${disposition}" = "pass" ]; then
            pass_count=$((pass_count + 1))
        else
            nonpass_count=$((nonpass_count + 1))
        fi
        if [ "${disposition}" = "fail" ]; then
            fail_count=$((fail_count + 1))
        fi
        printf '| %s | %s | `%s` | %s | `%s` | %s |\n' \
            "$(escape_md "${fact}")" \
            "$(escape_md "${expected}")" \
            "$(escape_md "${command}")" \
            "$(escape_md "${actual}")" \
            "$(escape_md "${evidence}")" \
            "$(escape_md "${disposition}")" >> "${SUMMARY_MD}"
    done < "${FACTS_TSV}"

    {
        echo
        echo "## Result"
        echo
        echo "- pass: ${pass_count}"
        echo "- non-pass: ${nonpass_count}"
        echo "- fail: ${fail_count}"
        echo
        echo "Non-pass entries must be copied back into"
        echo "\`docs/openstack-target-env-discovery.md\` with their disposition."
    } >> "${SUMMARY_MD}"

    if [ "${FAIL_ON_REQUIRED}" = "true" ] && [ "${fail_count}" -gt 0 ]; then
        return 1
    fi
    return 0
}

: > "${COMMANDS_LOG}"
: > "${FACTS_TSV}"

capture "OS and kernel" "Record host OS and kernel" "fail" \
    "os-kernel.txt" collect_versions
capture "Neutron ML2 mechanism drivers" "Record OVS/ML2 mechanism driver state" "fail" \
    "ml2-config.txt" collect_ml2_config
capture "Neutron agents" "Record target Neutron agents and Aria agent heartbeat rows" "fail" \
    "neutron-agents.txt" neutron_agent_list
capture "Aria ACL agent heartbeat" "At least one Aria ACL agent heartbeat is visible" "fail" \
    "aria-agent-heartbeat.txt" check_aria_agent_heartbeat
capture "Neutron extensions" "Record Neutron extension set" "fail" \
    "neutron-extensions.txt" neutron_extension_list
capture "aria-acl extension" "aria-acl extension is visible when production ACL gate is enabled" "fail" \
    "aria-acl-extension.txt" check_aria_acl_extension
capture "QoS extension" "Record QoS support disposition; unsupported is acceptable for ACL MVP" "unsupported" \
    "qos-extension.txt" check_qos_extension
capture "Trunk extension" "Record trunk support disposition; unsupported is acceptable for ACL MVP" "unsupported" \
    "trunk-extension.txt" check_trunk_extension
capture "OVS topology" "OVS bridge and ${OVS_BRIDGE} ports are visible" "fail" \
    "ovs-topology.txt" collect_ovs_topology
capture "Tap and OVS interface inventory" "Tap naming and OVS external_ids are recorded" "fail" \
    "tap-inventory.txt" collect_tap_inventory
capture "No qvo/qvb hybrid plug" "Current MVP expects no qvo/qvb hybrid-plug path" "unsupported" \
    "hybrid-plug.txt" check_no_hybrid_plug
capture "OVS iface-id external_ids" "OVS interfaces expose external_ids:iface-id" "fail" \
    "ovs-iface-id.txt" check_ovs_iface_id
capture "BTF and bpffs" "BTF and bpffs capability are known" "degraded" \
    "bpf.txt" collect_bpf_capability
capture "tc capability" "tc availability is known for QoS disposition" "unsupported" \
    "tc.txt" collect_tc_capability
capture "XDP tap status" "Record current tap XDP status without attaching anything" "not_applicable" \
    "xdp-status.txt" collect_xdp_status
capture "/run/aria and socket permissions" "Record UDS directory/socket owner and mode" "degraded" \
    "run-aria.txt" collect_run_aria_permissions
capture "Container state and mounts" "Record Kolla containers and relevant mounts" "fail" \
    "containers.txt" collect_container_state
capture "UDS capabilities/status" "Record local datapath UDS capabilities/status" "degraded" \
    "uds-status.txt" collect_neutron_aria_agent_status
capture "Neutron port source for host" "Record host-bound Neutron ports and compute port count" "fail" \
    "neutron-port-source.txt" collect_neutron_port_source
capture "Neutron port class disposition" "Record local vnic_type counts and unsupported port classes" "unsupported" \
    "port-classes.txt" collect_neutron_port_classes
capture "aria_acl API read counts" "Record production ACL API read path counts and status fields" "fail" \
    "aria-acl-api.txt" collect_aria_acl_api

write_summary
log "N0.5 discovery evidence written to ${EVIDENCE_DIR}"
