#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ACTION="${1:-}"
ENV_FILE="${2:-}"
CURRENT_CYCLE=0

die() { echo "ERROR: $*" >&2; exit 1; }
log() { printf '[acl-active-matrix] %s %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*"; }

load_env() {
    [ -n "${ENV_FILE}" ] || die "runtime env file is required"
    [ -f "${ENV_FILE}" ] || die "missing runtime env file: ${ENV_FILE}"
    local mode
    mode="$(stat -c '%a' "${ENV_FILE}")"
    [ "${mode}" = 600 ] || die "runtime env file must have mode 0600, got ${mode}"
    set -a
    # shellcheck disable=SC1090
    source "${ENV_FILE}"
    set +a
}

select_python() {
    if command -v python3 >/dev/null 2>&1; then
        PYTHON_BIN="$(command -v python3)"
    elif command -v python >/dev/null 2>&1; then
        PYTHON_BIN="$(command -v python)"
    else
        die "missing python3 or python"
    fi
}

require_runtime() {
    local name
    for name in RUN_ID WORK_DIR TARGETS_FILE GUEST_PASSWORD_FILE IMAGE_ID NETWORK_ID \
        FLAVOR_ID DEADLINE_EPOCH OVS_CANARY_IP EGRESS_TARGET_IP; do
        [ -n "${!name:-}" ] || die "${name} is required"
    done
    case "${RUN_ID}" in *[!A-Za-z0-9_.-]*) die "unsafe RUN_ID" ;; esac
    [ -f "${TARGETS_FILE}" ] || die "missing TARGETS_FILE"
    [ -f "${GUEST_PASSWORD_FILE}" ] || die "missing GUEST_PASSWORD_FILE"
    [ "$(stat -c '%a' "${GUEST_PASSWORD_FILE}")" = 600 ] || \
        die "GUEST_PASSWORD_FILE must have mode 0600"
    [ "${DEADLINE_EPOCH}" -gt "$(date +%s)" ] || die "deadline is not in the future"
    SCHEDULER_INTERVAL="${SCHEDULER_INTERVAL:-60}"
    CASE_TIMEOUT="${CASE_TIMEOUT:-420}"
    OPENSTACK_CLIENT="${OPENSTACK_CLIENT:-openstack_client}"
    ADMIN_RC_FILE="${ADMIN_RC_FILE:-/etc/kolla/.adminrc}"
    CASE_RUNNER="${CASE_RUNNER:-${SCRIPT_DIR}/neutron_aria_acl_active_matrix_case.sh}"
    NONCE_ECHO="${NONCE_ECHO:-${SCRIPT_DIR}/neutron_aria_acl_nonce_echo.py}"
    GUEST_EXEC="${GUEST_EXEC:-${SCRIPT_DIR}/neutron_aria_cirros_guest_exec.py}"
    LISTENER_TOOL="${LISTENER_TOOL:-/usr/local/bin/neutron_aria_cirros_port_listener}"
    [ -x "${CASE_RUNNER}" ] || die "case runner is not executable"
    [ -f "${NONCE_ECHO}" ] || die "nonce helper missing"
    [ -f "${GUEST_EXEC}" ] || die "guest exec helper missing"
    [ -x "${LISTENER_TOOL}" ] || die "CirrOS listener tool missing"
}

neutron_cli() {
    docker exec -u root --env-file "${ADMIN_RC_FILE}" "${OPENSTACK_CLIENT}" neutron "$@"
}

nova_cli() {
    docker exec -u root --env-file "${ADMIN_RC_FILE}" "${OPENSTACK_CLIENT}" nova "$@"
}

table_field() {
    local field="$1"
    awk -F'|' -v wanted="${field}" 'NF >= 4 {
        key=$2; value=$3; gsub(/^ +| +$/, "", key); gsub(/^ +| +$/, "", value)
        if (key == wanted) { print value; exit }
    }'
}

event() {
    printf '%s\t%s\t%s\t%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$1" "$2" "${3:-}" \
        >>"${WORK_DIR}/events.tsv"
}

checkpoint() {
    local phase="$1" node_alias="${2:-}" case_id="${3:-}" last_result="${4:-}"
    PHASE="${phase}" NODE_ALIAS="${node_alias}" CASE_ID_VALUE="${case_id}" \
        LAST_RESULT="${last_result}" CYCLE_VALUE="${CURRENT_CYCLE}" \
        "${PYTHON_BIN}" - "${WORK_DIR}/checkpoint.json" <<'PY'
from __future__ import print_function
import json
import os
import time
import sys
path = sys.argv[1]
payload = {
    "updated_at": int(time.time()),
    "phase": os.environ["PHASE"],
    "node_alias": os.environ["NODE_ALIAS"],
    "case_id": os.environ["CASE_ID_VALUE"],
    "last_result": os.environ["LAST_RESULT"],
    "cycle": int(os.environ["CYCLE_VALUE"]),
}
with open(path + ".tmp", "w") as handle:
    json.dump(payload, handle, sort_keys=True)
    handle.write("\n")
os.rename(path + ".tmp", path)
PY
}

record_owned() { printf '%s\t%s\t%s\n' "$1" "$2" "${3:-}" >>"${WORK_DIR}/owned.tsv"; }

stop_owned_processes() {
    set +e
    [ -f "${WORK_DIR}/pids.tsv" ] || return 0
    tac "${WORK_DIR}/pids.tsv" | while IFS=$'\t' read -r kind pid detail; do
        [ -n "${pid}" ] || continue
        kill "${pid}" >/dev/null 2>&1 || true
        sleep 0.1
        kill -9 "${pid}" >/dev/null 2>&1 || true
        event process_stop pass "${kind}:${pid}:${detail}"
    done
}

cleanup_case_objects() {
    set +e
    local owned object_type object_id command
    find "${WORK_DIR}/cases" -type f -name owned.tsv 2>/dev/null | while read -r owned; do
        for object_type in binding rule policy; do
            case "${object_type}" in
                binding) command=aria-acl-binding-delete ;;
                rule) command=aria-acl-rule-delete ;;
                policy) command=aria-acl-policy-delete ;;
            esac
            tac "${owned}" | while IFS=$'\t' read -r recorded_type object_id; do
                [ "${recorded_type}" = "${object_type}" ] || continue
                [ -n "${object_id}" ] || continue
                neutron_cli "${command}" "${object_id}" >/dev/null 2>&1 || true
            done
        done
    done
}

cleanup_vms() {
    set +e
    [ -f "${WORK_DIR}/vms.tsv" ] || return 0
    tac "${WORK_DIR}/vms.tsv" | while IFS=$'\t' read -r alias server_id port_id ip host ifname; do
        [ -n "${server_id}" ] || continue
        nova_cli force-delete "${server_id}" >/dev/null 2>&1 || \
            nova_cli delete "${server_id}" >/dev/null 2>&1 || true
        event vm_delete pass "${alias}:${server_id}:${port_id}"
    done
}

cleanup_owned_vms() {
    set +e
    [ -f "${WORK_DIR}/owned.tsv" ] || return 0
    local object_type server_id _detail
    tac "${WORK_DIR}/owned.tsv" | while IFS=$'\t' read -r object_type server_id _detail; do
        [ "${object_type}" = vm ] || continue
        [ -n "${server_id}" ] || continue
        if [ -f "${WORK_DIR}/vms.tsv" ] && \
            awk -F '\t' -v wanted="${server_id}" '$2 == wanted { found=1 } END { exit !found }' \
                "${WORK_DIR}/vms.tsv"; then
            continue
        fi
        nova_cli force-delete "${server_id}" >/dev/null 2>&1 || \
            nova_cli delete "${server_id}" >/dev/null 2>&1 || true
        event vm_delete pass "owned-journal:${server_id}"
    done
}

stop_guest_listeners() {
    set +e
    [ -f "${WORK_DIR}/vms.tsv" ] || return 0
    local password
    password="$(cat "${GUEST_PASSWORD_FILE}")"
    while IFS=$'\t' read -r _alias _server _port ip _host _ifname; do
        for endpoint in tcp:8080 tcp:8081 tcp:8082 tcp:65535 udp:1080 udp:1081; do
            CIRROS_PASSWORD="${password}" "${LISTENER_TOOL}" "${ip}" "${endpoint}" stop >/dev/null 2>&1 || true
        done
    done <"${WORK_DIR}/vms.tsv"
}

cleanup_all() {
    set +e
    checkpoint cleanup "" "" start
    stop_owned_processes
    stop_guest_listeners
    cleanup_case_objects
    cleanup_vms
    cleanup_owned_vms
    checkpoint cleanup "" "" "done"
}

owned_vm_ids() {
    { [ ! -f "${WORK_DIR}/vms.tsv" ] || awk -F '\t' 'NF >= 2 {print $2}' "${WORK_DIR}/vms.tsv"
      [ ! -f "${WORK_DIR}/owned.tsv" ] || awk -F '\t' '$1 == "vm" {print $2}' "${WORK_DIR}/owned.tsv"
    } | awk 'NF' | sort -u
}

nova_server_is_cleaned() {
    local server_id="$1" output status
    output="$(nova_cli show "${server_id}" 2>/dev/null)" || return 0
    status="$(printf '%s\n' "${output}" | table_field status)"
    [ "${status}" = SOFT_DELETED ] || [ "${status}" = DELETED ]
}

finalize_run() {
    local rc="$?"
    trap - EXIT INT TERM
    cleanup_all
    local remaining=0
    if [ -f "${WORK_DIR}/vms.tsv" ] || [ -f "${WORK_DIR}/owned.tsv" ]; then
        local server_id all_gone
        for _ in $(seq 1 30); do
            all_gone=true
            while read -r server_id; do
                if ! nova_server_is_cleaned "${server_id}"; then
                    all_gone=false
                fi
            done < <(owned_vm_ids)
            [ "${all_gone}" = true ] && break
            sleep 2
        done
        while read -r server_id; do
            nova_server_is_cleaned "${server_id}" || remaining=$((remaining + 1))
        done < <(owned_vm_ids)
    fi
    [ "${remaining}" -eq 0 ] || rc=1
    printf '%s\n' "${rc}" >"${WORK_DIR}/exit-code"
    SUMMARY_RESULT=fail
    [ "${rc}" -eq 0 ] && [ "${remaining}" -eq 0 ] && SUMMARY_RESULT=pass
    SUMMARY_RESULT="${SUMMARY_RESULT}" REMAINING="${remaining}" "${PYTHON_BIN}" - \
        "${WORK_DIR}/summary.json" <<'PY'
from __future__ import print_function
import json
import os
import sys
payload = {
    "active_matrix": os.environ["SUMMARY_RESULT"],
    "runtime_soak": "external",
    "fixed_policy_soak": "external",
    "control_plane_churn": "external",
    "owned_resources_remaining": int(os.environ["REMAINING"]),
}
with open(sys.argv[1], "w") as handle:
    json.dump(payload, handle, sort_keys=True)
    handle.write("\n")
PY
    if [ "${SUMMARY_RESULT}" = pass ]; then
        touch "${WORK_DIR}/complete"
    fi
    checkpoint finished "" "" "${SUMMARY_RESULT}"
    exit "${rc}"
}

validate_targets() {
    "${PYTHON_BIN}" - "${TARGETS_FILE}" <<'PY'
from __future__ import print_function
import sys
rows = []
with open(sys.argv[1]) as handle:
    for line in handle:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split("\t")
        if len(parts) != 2:
            raise SystemExit("target row must be: alias<TAB>nova-host")
        rows.append(parts)
if len(rows) != 3:
    raise SystemExit("exactly three target rows are required")
if len(set(row[0] for row in rows)) != 3 or len(set(row[1] for row in rows)) != 3:
    raise SystemExit("target aliases and hosts must be unique")
PY
}

assert_cluster_heartbeat() {
    local alias host line agent_id details
    while IFS=$'\t' read -r alias host; do
        [ -n "${alias}" ] || continue
        line="$(neutron_cli agent-list | grep 'Aria ACL agent' | grep " ${host} " || true)"
        [ -n "${line}" ] || die "missing Aria agent for ${alias}/${host}"
        printf '%s\n' "${line}" | grep ':-)' >/dev/null || die "dead Aria agent on ${host}"
        agent_id="$(printf '%s\n' "${line}" | awk '{print $2; exit}')"
        details="$(neutron_cli agent-show "${agent_id}" -f json)"
        DETAILS="${details}" "${PYTHON_BIN}" - <<'PY'
from __future__ import print_function
import ast
import json
import os
row = json.loads(os.environ["DETAILS"])
if isinstance(row, list) and all(isinstance(item, dict) for item in row):
    row = dict((item.get("Field"), item.get("Value")) for item in row)
cfg = row.get("configurations") or {}
if isinstance(cfg, str):
    try: cfg = json.loads(cfg)
    except ValueError: cfg = ast.literal_eval(cfg)
if cfg.get("ready") is not True or cfg.get("degraded") is True:
    raise SystemExit("agent heartbeat is not ready/non-degraded")
if int(cfg.get("generation_lag") or 0) != 0:
    raise SystemExit("agent generation lag is nonzero")
PY
        event heartbeat_preflight pass "${alias}:${host}"
    done <"${TARGETS_FILE}"
}

preflight() {
    command -v docker >/dev/null || die "missing docker"
    command -v systemd-run >/dev/null || die "missing systemd-run"
    command -v flock >/dev/null || die "missing flock"
    command -v timeout >/dev/null || die "missing timeout"
    validate_targets
    nova_cli image-show "${IMAGE_ID}" >/dev/null
    neutron_cli net-show "${NETWORK_ID}" >/dev/null
    nova_cli flavor-show "${FLAVOR_ID}" >/dev/null
    assert_cluster_heartbeat
    for port in 1 28080 28081 28082; do
        if ss -lntu "sport = :${port}" 2>/dev/null | grep -q ":${port}"; then
            die "host target port ${port} is already in use"
        fi
    done
    event preflight pass
}

port_identity() {
    local server_id="$1"
    local payload
    payload="$(neutron_cli port-list --device_id "${server_id}" -f json)"
    PORT_PAYLOAD="${payload}" "${PYTHON_BIN}" - <<'PY'
from __future__ import print_function
import json
import os
import sys
rows = json.loads(os.environ["PORT_PAYLOAD"])
if len(rows) != 1:
    raise SystemExit("expected one VM port")
row = rows[0]
fixed = row.get("fixed_ips") or []
if isinstance(fixed, str):
    fixed = json.loads(fixed.replace("'", '"'))
if isinstance(fixed, dict):
    fixed = [fixed]
ip = fixed[0].get("ip_address") if fixed else ""
print("%s\t%s" % (row.get("id") or row.get("ID"), ip))
PY
}

provision_vms() {
    : >"${WORK_DIR}/vms.tsv"
    local alias host name output server_id status actual_host identity port_id ip ifname
    while IFS=$'\t' read -r alias host; do
        [ -n "${alias}" ] || continue
        name="aria-acl-matrix-${RUN_ID}-${alias}"
        output="$(nova_cli boot --flavor "${FLAVOR_ID}" --image "${IMAGE_ID}" \
            --nic "net-id=${NETWORK_ID}" --availability-zone "nova:${host}" "${name}")"
        server_id="$(printf '%s\n' "${output}" | table_field id)"
        [ -n "${server_id}" ] || die "failed to create ${name}"
        record_owned vm "${server_id}" "${alias}"
        for _ in $(seq 1 120); do
            output="$(nova_cli show "${server_id}" || true)"
            status="$(printf '%s\n' "${output}" | table_field status)"
            actual_host="$(printf '%s\n' "${output}" | table_field OS-EXT-SRV-ATTR:host)"
            [ "${status}" = ERROR ] && die "${name} entered ERROR"
            if [ "${status}" = ACTIVE ] && [ "${actual_host}" = "${host}" ]; then break; fi
            sleep 3
        done
        [ "${status}" = ACTIVE ] || die "${name} did not become ACTIVE"
        [ "${actual_host}" = "${host}" ] || die "${name} scheduled on wrong host"
        identity="$(port_identity "${server_id}")"
        port_id="${identity%%$'\t'*}"
        ip="${identity#*$'\t'}"
        if [ -z "${port_id}" ] || [ -z "${ip}" ]; then
            die "failed to resolve VM port/IP"
        fi
        ifname="tap${port_id:0:11}"
        printf '%s\t%s\t%s\t%s\t%s\t%s\n' \
            "${alias}" "${server_id}" "${port_id}" "${ip}" "${host}" "${ifname}" \
            >>"${WORK_DIR}/vms.tsv"
        event vm_ready pass "${alias}:${server_id}:${port_id}:${ip}:${host}"
        checkpoint provisioning "${alias}" "" pass
    done <"${TARGETS_FILE}"
}

wait_guest_ssh() {
    local ip="$1"
    for _ in $(seq 1 120); do
        if CIRROS_PASSWORD_FILE="${GUEST_PASSWORD_FILE}" "${PYTHON_BIN}" "${GUEST_EXEC}" \
            "${ip}" true >/dev/null 2>&1; then return 0; fi
        sleep 2
    done
    return 1
}

prepare_guest_listeners() {
    local password alias port_id ip host ifname endpoint
    password="$(cat "${GUEST_PASSWORD_FILE}")"
    while IFS=$'\t' read -r alias _server port_id ip host ifname; do
        wait_guest_ssh "${ip}" || die "guest SSH did not become ready: ${alias}/${ip}"
        for endpoint in tcp:8080 tcp:8081 tcp:8082 tcp:65535 udp:1080 udp:1081; do
            CIRROS_PASSWORD="${password}" "${LISTENER_TOOL}" "${ip}" "${endpoint}" start \
                >>"${WORK_DIR}/guest-listeners.log"
        done
        event guest_listeners pass "${alias}:${ip}"
    done <"${WORK_DIR}/vms.tsv"
}

start_host_listener() {
    local protocol="$1" port="$2" ready
    ready="${WORK_DIR}/host-${protocol}-${port}.ready"
    "${PYTHON_BIN}" "${NONCE_ECHO}" serve "${protocol}" 0.0.0.0 "${port}" "${ready}" \
        >>"${WORK_DIR}/host-listeners.log" 2>&1 &
    local pid=$!
    printf 'host-listener\t%s\t%s:%s\n' "${pid}" "${protocol}" "${port}" >>"${WORK_DIR}/pids.tsv"
    for _ in $(seq 1 40); do [ -f "${ready}" ] && return 0; sleep 0.1; done
    die "host ${protocol}/${port} listener did not become ready"
}

start_host_listeners() {
    start_host_listener tcp 1
    start_host_listener udp 1
    start_host_listener tcp 28080
    start_host_listener tcp 28081
    start_host_listener tcp 28082
    start_host_listener udp 28080
    start_host_listener udp 28081
    start_host_listener udp 28082
}

start_ovs_canary() {
    (
        set +e
        sample=0
        while [ "$(date +%s)" -lt "${DEADLINE_EPOCH}" ]; do
            sample=$((sample + 1))
            if ping -c 1 -W 1 "${OVS_CANARY_IP}" >/dev/null 2>&1; then rc=0; else rc=1; fi
            printf '%s\t%s\t%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "${sample}" "${rc}" \
                >>"${WORK_DIR}/ovs-canary.tsv"
            sleep 5
        done
    ) &
    printf 'ovs-canary\t%s\t%s\n' "$!" "${OVS_CANARY_IP}" >>"${WORK_DIR}/pids.tsv"
}

matrix_rows() {
    # The final row is the required egress TCP single:1 boundary case.
    cat <<'EOF'
ingress	icmp	true	none	8080	8080	8081
egress	icmp	true	none	28081	28081	28080
ingress	tcp	true	single	8080	8080	8081
egress	tcp	true	single	28081	28081	28080
ingress	udp	true	single	1080	1080	1081
egress	udp	true	single	28082	28082	28080
ingress	tcp	false	range	8080	8082	65535
egress	udp	false	range	28080	28082	1
ingress	tcp	false	single	65535	65535	8081
egress	tcp	false	single	1	1	28081
EOF
}

run_matrix() {
    local direction protocol stateful selector min_port max_port nonmatch
    local alias port_id ip host ifname case_id case_dir start_tick elapsed crossed tick
    while [ "$(date +%s)" -lt "${DEADLINE_EPOCH}" ]; do
        CURRENT_CYCLE=$((CURRENT_CYCLE + 1))
        checkpoint cycle_start "" "" pass
        while IFS=$'\t' read -r direction protocol stateful selector min_port max_port nonmatch; do
            while IFS=$'\t' read -r alias _server port_id ip host ifname; do
                if [ "$(date +%s)" -ge "${DEADLINE_EPOCH}" ]; then
                    event deadline pass "before_next_case"
                    return 0
                fi
                case_id="cycle${CURRENT_CYCLE}-${alias}-${direction}-${protocol}-${stateful}-${selector}-${min_port}-${max_port}"
                case_dir="${WORK_DIR}/cases/${case_id}"
                mkdir -p "${case_dir}"
                checkpoint case_running "${alias}" "${case_id}" start
                start_tick="$(date +%s)"
                if ! timeout "${CASE_TIMEOUT}" env \
                    CASE_ID="${case_id}" VM_IP="${ip}" PORT_ID="${port_id}" IFNAME="${ifname}" \
                    EXPECTED_HOST="${host}" DIRECTION="${direction}" PROTOCOL="${protocol}" \
                    STATEFUL="${stateful}" SELECTOR_KIND="${selector}" \
                    MATCH_PORT_MIN="${min_port}" MATCH_PORT_MAX="${max_port}" NONMATCH_PORT="${nonmatch}" \
                    EGRESS_TARGET_IP="${EGRESS_TARGET_IP}" GUEST_EXEC_FILE="${GUEST_EXEC}" \
                    CIRROS_PASSWORD_FILE="${GUEST_PASSWORD_FILE}" WORK_DIR="${case_dir}" \
                    NONCE_ECHO="${NONCE_ECHO}" bash "${CASE_RUNNER}" run \
                    >"${case_dir}/stdout.log" 2>&1; then
                    checkpoint case_failed "${alias}" "${case_id}" fail
                    event case fail "${case_id}"
                    return 1
                fi
                checkpoint case_complete "${alias}" "${case_id}" pass
                event case pass "${case_id}"
                elapsed=$(( $(date +%s) - start_tick ))
                crossed=$(( elapsed / SCHEDULER_INTERVAL ))
                tick=0
                while [ "${tick}" -lt "${crossed}" ]; do
                    event skipped_active_tick pass "${case_id}"
                    tick=$((tick + 1))
                done
                if [ "${elapsed}" -lt "${SCHEDULER_INTERVAL}" ]; then
                    sleep "$((SCHEDULER_INTERVAL - elapsed))"
                fi
            done <"${WORK_DIR}/vms.tsv"
        done < <(matrix_rows)
        event cycle_complete pass "cycle=${CURRENT_CYCLE}"
    done
}

run_gate() {
    mkdir -p "${WORK_DIR}/cases"
    : >"${WORK_DIR}/events.tsv"
    : >"${WORK_DIR}/owned.tsv"
    : >"${WORK_DIR}/pids.tsv"
    trap finalize_run EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM
    checkpoint starting
    preflight
    provision_vms
    prepare_guest_listeners
    start_host_listeners
    start_ovs_canary
    checkpoint matrix_ready
    run_matrix
    checkpoint matrix_complete
}

launch_gate() {
    command -v systemd-run >/dev/null || die "missing systemd-run"
    command -v flock >/dev/null || die "missing flock"
    local unit="aria-acl-active-matrix-${RUN_ID}"
    local wrapper="${WORK_DIR}/run-detached.sh"
    mkdir -p "${WORK_DIR}"
    cat >"${wrapper}" <<EOF
#!/usr/bin/env bash
set -euo pipefail
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
exec /bin/bash '${SCRIPT_DIR}/neutron_aria_acl_active_matrix_soak.sh' run '${ENV_FILE}' >>'${WORK_DIR}/service.log' 2>&1
EOF
    chmod 700 "${wrapper}"
    # no_automatic_restart: assertion failures remain visible and are never hidden by retries.
    systemd-run --unit="${unit}" --property=Type=simple \
        --property=WorkingDirectory="${SCRIPT_DIR}" \
        /usr/bin/flock -n "${WORK_DIR}/scheduler.lock" /bin/bash "${wrapper}"
    sleep 2
    systemctl is-active "${unit}" >/dev/null || die "transient unit did not become active"
    printf '%s\n' "${unit}" >"${WORK_DIR}/unit-name"
    log "launched unit=${unit} work_dir=${WORK_DIR}"
}

status_gate() {
    local unit="aria-acl-active-matrix-${RUN_ID}"
    systemctl status "${unit}" --no-pager || true
    [ -f "${WORK_DIR}/checkpoint.json" ] && cat "${WORK_DIR}/checkpoint.json"
    [ -f "${WORK_DIR}/exit-code" ] && cat "${WORK_DIR}/exit-code"
}

collect_gate() {
    status_gate
    for file in checkpoint.json summary.json exit-code events.tsv ovs-canary.tsv service.log; do
        if [ -f "${WORK_DIR}/${file}" ]; then
            echo "=== ${file} ==="
            tail -n 200 "${WORK_DIR}/${file}"
        fi
    done
}

select_python
case "${ACTION}" in
    preflight)
        load_env; require_runtime
        mkdir -p "${WORK_DIR}"
        : >"${WORK_DIR}/events.tsv"
        preflight
        checkpoint preflight "" "" pass
        log "preflight=pass work_dir=${WORK_DIR}" ;;
    launch)
        load_env; require_runtime; launch_gate ;;
    run)
        load_env; require_runtime; run_gate ;;
    status)
        load_env; require_runtime; status_gate ;;
    collect)
        load_env; require_runtime; collect_gate ;;
    *)
        die "usage: $0 preflight|launch|run|status|collect <runtime.env>" ;;
esac
