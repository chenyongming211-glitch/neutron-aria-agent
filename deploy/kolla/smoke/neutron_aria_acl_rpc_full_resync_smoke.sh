#!/usr/bin/env bash
set -euo pipefail

TARGET_PORT_ID="${TARGET_PORT_ID:-}"
TARGET_VM_IP="${TARGET_VM_IP:-}"
TARGET_HOST="${TARGET_HOST:-$(hostname -f)}"
TARGET_LABEL="${TARGET_LABEL:-${TARGET_HOST}}"
CONFIG_PATH="${CONFIG_PATH:-/etc/kolla/neutron-aria-agent/neutron-aria-agent.ini}"
AGENT_LOG_PATH="${AGENT_LOG_PATH:-/var/log/kolla/neutron/neutron-aria-agent.log}"
ADMINRC="${ADMINRC:-/root/adminrc}"
OPENSTACK_CLIENT_CONTAINER="${OPENSTACK_CLIENT_CONTAINER:-openstack_client}"
PING_TIMEOUT="${PING_TIMEOUT:-1}"
POLL_INTERVAL="${POLL_INTERVAL:-0.5}"
CONVERGENCE_ATTEMPTS="${CONVERGENCE_ATTEMPTS:-20}"
REQUIRE_RPC_CONFIG="${REQUIRE_RPC_CONFIG:-true}"
ALLOW_EXISTING_BINDINGS="${ALLOW_EXISTING_BINDINGS:-false}"

die() {
    echo "ERROR: $*" >&2
    exit 1
}

need_command() {
    command -v "$1" >/dev/null 2>&1 || die "missing command: $1"
}

source_adminrc() {
    if [ -r "${ADMINRC}" ]; then
        # shellcheck disable=SC1090
        source "${ADMINRC}"
    fi
}

neutron_cli() {
    if command -v neutron >/dev/null 2>&1; then
        neutron "$@"
        return
    fi
    need_command docker
    docker exec \
        -i \
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
        "${OPENSTACK_CLIENT_CONTAINER}" neutron "$@"
}

now_ms() {
    date +%s%3N
}

id_from_value() {
    awk 'NF {value = $NF} END {print value}'
}

ping_ok() {
    ping -c 1 -W "${PING_TIMEOUT}" "${TARGET_VM_IP}" >/dev/null 2>&1
}

status_brief() {
    neutron_cli aria-acl-port-status-show "${TARGET_PORT_ID}" |
        grep -E 'binding_id|effective_policy_id|effective_action|generation|runtime_status|status|reason|updated_at|host' ||
        true
}

wait_ping_state() {
    local want="$1"
    local label="$2"
    local start elapsed i state
    start="$(now_ms)"
    i=0
    while [ "${i}" -lt "${CONVERGENCE_ATTEMPTS}" ]; do
        if ping_ok; then
            state="allow"
        else
            state="drop"
        fi
        elapsed=$(( $(now_ms) - start ))
        echo "${label} poll=${i} state=${state} elapsed_ms=${elapsed}"
        if [ "${state}" = "${want}" ]; then
            echo "${label} result=pass elapsed_ms=${elapsed}"
            return 0
        fi
        i=$((i + 1))
        sleep "${POLL_INTERVAL}"
    done
    echo "${label} result=timeout want=${want}"
    return 1
}

agent_log_line_count() {
    if [ -r "${AGENT_LOG_PATH}" ]; then
        wc -l <"${AGENT_LOG_PATH}"
        return
    fi
    echo 0
}

agent_logs_since_start() {
    if [ -r "${AGENT_LOG_PATH}" ]; then
        tail -n +"$((LOG_START_LINE + 1))" "${AGENT_LOG_PATH}" 2>/dev/null || true
    fi
}

assert_rpc_p2_config() {
    [ "${REQUIRE_RPC_CONFIG}" = "true" ] || return 0
    [ -r "${CONFIG_PATH}" ] || die "missing config: ${CONFIG_PATH}"
    grep -Eq '^[[:space:]]*full_resync_enabled[[:space:]]*=[[:space:]]*true[[:space:]]*$' "${CONFIG_PATH}" ||
        die "full_resync_enabled must be true in ${CONFIG_PATH}"
    grep -Eq '^[[:space:]]*rpc_events_enabled[[:space:]]*=[[:space:]]*true[[:space:]]*$' "${CONFIG_PATH}" ||
        die "rpc_events_enabled must be true in ${CONFIG_PATH}"
    grep -Eq '^[[:space:]]*incremental_rpc_enabled[[:space:]]*=[[:space:]]*false[[:space:]]*$' "${CONFIG_PATH}" ||
        die "incremental_rpc_enabled must remain false in ${CONFIG_PATH}"
}

assert_no_existing_binding() {
    [ "${ALLOW_EXISTING_BINDINGS}" = "true" ] && return 0
    if neutron_cli aria-acl-binding-list --port "${TARGET_PORT_ID}" 2>/dev/null |
        grep -q "${TARGET_PORT_ID}"; then
        die "target port already has an aria_acl binding; set ALLOW_EXISTING_BINDINGS=true only for controlled tests"
    fi
}

cleanup_acl() {
    set +e
    if [ -n "${BINDING_ID:-}" ]; then
        neutron_cli aria-acl-binding-delete "${BINDING_ID}" >/dev/null 2>&1
    fi
    if [ -n "${RULE_ID:-}" ]; then
        neutron_cli aria-acl-rule-delete "${RULE_ID}" >/dev/null 2>&1
    fi
    if [ -n "${POLICY_ID:-}" ]; then
        neutron_cli aria-acl-policy-delete "${POLICY_ID}" >/dev/null 2>&1
    fi
}

need_command ping
source_adminrc

[ -n "${TARGET_PORT_ID}" ] || die "TARGET_PORT_ID is required"
[ -n "${TARGET_VM_IP}" ] || die "TARGET_VM_IP is required"

POLICY_ID=""
RULE_ID=""
BINDING_ID=""
LOG_START_LINE="$(agent_log_line_count)"
trap cleanup_acl EXIT

assert_rpc_p2_config
assert_no_existing_binding

echo "target_label=${TARGET_LABEL}"
echo "target_host=${TARGET_HOST}"
echo "target_port_id=${TARGET_PORT_ID}"
echo "target_vm_ip=${TARGET_VM_IP}"
echo "mode=rpc_triggered_full_resync"
echo "incremental_rpc_enabled=false"

if ! ping_ok; then
    die "baseline ping to ${TARGET_VM_IP} failed before ACL apply"
fi
echo "baseline_ping=allow"
echo "baseline_status:"
status_brief

POLICY_ID="$(
    neutron_cli aria-acl-policy-create \
        --name "p25-rpc-full-resync-${TARGET_LABEL}-$(date +%H%M%S)" \
        --default-action allow \
        --stateful true \
        --enabled true \
        -f value -c id | id_from_value
)"
[ -n "${POLICY_ID}" ] || die "failed to create aria_acl policy"
echo "policy_id=${POLICY_ID}"

RULE_ID="$(
    neutron_cli aria-acl-rule-create \
        --policy-id "${POLICY_ID}" \
        --direction ingress \
        --priority 100 \
        --action drop \
        --protocol icmp \
        --dst-cidr "${TARGET_VM_IP}/32" \
        --enabled true \
        -f value -c id | id_from_value
)"
[ -n "${RULE_ID}" ] || die "failed to create aria_acl rule"
echo "rule_id=${RULE_ID}"

start_binding_create="$(now_ms)"
BINDING_ID="$(
    neutron_cli aria-acl-binding-create \
        --policy-id "${POLICY_ID}" \
        --port "${TARGET_PORT_ID}" \
        --enabled true \
        -f value -c id | id_from_value
)"
[ -n "${BINDING_ID}" ] || die "failed to create aria_acl binding"
echo "binding_id=${BINDING_ID}"
wait_ping_state drop binding_create_drop
echo "binding_create_total_ms=$(( $(now_ms) - start_binding_create ))"
echo "after_binding_create_status:"
status_brief

start_rule_disable="$(now_ms)"
neutron_cli aria-acl-rule-update "${RULE_ID}" --enabled false >/dev/null
wait_ping_state allow rule_disable_allow
echo "rule_disable_total_ms=$(( $(now_ms) - start_rule_disable ))"
echo "after_rule_disable_status:"
status_brief

start_rule_enable="$(now_ms)"
neutron_cli aria-acl-rule-update "${RULE_ID}" --enabled true >/dev/null
wait_ping_state drop rule_enable_drop
echo "rule_enable_total_ms=$(( $(now_ms) - start_rule_enable ))"
echo "after_rule_enable_status:"
status_brief

start_binding_disable="$(now_ms)"
neutron_cli aria-acl-binding-update "${BINDING_ID}" --enabled false >/dev/null
wait_ping_state allow binding_disable_allow
echo "binding_disable_total_ms=$(( $(now_ms) - start_binding_disable ))"
echo "after_binding_disable_status:"
status_brief

start_policy_disable="$(now_ms)"
neutron_cli aria-acl-binding-update "${BINDING_ID}" --enabled true >/dev/null
neutron_cli aria-acl-policy-update "${POLICY_ID}" --enabled false >/dev/null
wait_ping_state allow policy_disable_allow
echo "policy_disable_total_ms=$(( $(now_ms) - start_policy_disable ))"
echo "after_policy_disable_status:"
status_brief

cleanup_acl
trap - EXIT
sleep 3
if ! ping_ok; then
    die "cleanup did not restore ping to ${TARGET_VM_IP}"
fi
echo "cleanup_ping=allow"
echo "final_status:"
status_brief

echo "agent_event_evidence:"
agent_logs_since_start |
    grep -E 'event_batch_drained|service_result action=event_batch|full_resync_complete|acl_delivery_profile' |
    tail -n 80 || true

echo "neutron_aria_acl_rpc_full_resync_smoke=pass"
