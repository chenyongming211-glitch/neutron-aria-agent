#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ADMIN_RC_FILE="${ADMIN_RC_FILE:-/etc/kolla/.adminrc}"
OPENSTACK_CLIENT="${OPENSTACK_CLIENT:-openstack_client}"
CONVERGENCE_TIMEOUT="${CONVERGENCE_TIMEOUT:-30}"
PROBE_TIMEOUT="${PROBE_TIMEOUT:-2}"
NONCE_ECHO="${NONCE_ECHO:-${SCRIPT_DIR}/neutron_aria_acl_nonce_echo.py}"
CASE_ID="${CASE_ID:-}"
VM_IP="${VM_IP:-}"
PORT_ID="${PORT_ID:-}"
IFNAME="${IFNAME:-}"
EXPECTED_HOST="${EXPECTED_HOST:-}"
DIRECTION="${DIRECTION:-}"
PROTOCOL="${PROTOCOL:-}"
STATEFUL="${STATEFUL:-}"
SELECTOR_KIND="${SELECTOR_KIND:-}"
MATCH_PORT_MIN="${MATCH_PORT_MIN:-}"
MATCH_PORT_MAX="${MATCH_PORT_MAX:-}"
NONMATCH_PORT="${NONMATCH_PORT:-}"
EGRESS_TARGET_IP="${EGRESS_TARGET_IP:-}"
GUEST_EXEC_FILE="${GUEST_EXEC_FILE:-}"
WORK_DIR="${WORK_DIR:-}"

PYTHON_BIN="${PYTHON_BIN:-}"
POLICY_ID=""
RULE_ID=""
BINDING_ID=""
FINALIZED=false

die() {
    echo "ERROR: $*" >&2
    exit 1
}

need_value() {
    local name="$1"
    [ -n "${!name:-}" ] || die "${name} is required"
}

validate_enum() {
    local name="$1"
    local value="${!name}"
    shift
    local candidate
    for candidate in "$@"; do
        [ "${value}" = "${candidate}" ] && return 0
    done
    die "${name} has unsupported value: ${value}"
}

validate_port() {
    local name="$1"
    local value="${!name}"
    case "${value}" in
        ''|*[!0-9]*) die "${name} must be numeric" ;;
    esac
    [ "${value}" -ge 1 ] && [ "${value}" -le 65535 ] || \
        die "${name} must be in range 1..65535"
}

select_python() {
    if [ -n "${PYTHON_BIN}" ]; then
        command -v "${PYTHON_BIN}" >/dev/null 2>&1 || die "missing PYTHON_BIN"
    elif command -v python3 >/dev/null 2>&1; then
        PYTHON_BIN="$(command -v python3)"
    elif command -v python >/dev/null 2>&1; then
        PYTHON_BIN="$(command -v python)"
    else
        die "missing python3 or python"
    fi
}

validate_ipv4() {
    "${PYTHON_BIN}" - "$1" <<'PY'
from __future__ import print_function
import socket
import sys
try:
    socket.inet_aton(sys.argv[1])
except socket.error:
    raise SystemExit(1)
PY
}

validate_inputs() {
    local name
    for name in CASE_ID VM_IP PORT_ID IFNAME EXPECTED_HOST DIRECTION PROTOCOL \
        STATEFUL SELECTOR_KIND MATCH_PORT_MIN MATCH_PORT_MAX NONMATCH_PORT \
        EGRESS_TARGET_IP GUEST_EXEC_FILE WORK_DIR; do
        need_value "${name}"
    done
    case "${CASE_ID}" in
        *[!A-Za-z0-9_.-]*) die "CASE_ID contains unsafe characters" ;;
    esac
    validate_enum DIRECTION ingress egress
    validate_enum PROTOCOL icmp tcp udp
    validate_enum STATEFUL true false
    validate_enum SELECTOR_KIND none single range
    validate_port MATCH_PORT_MIN
    validate_port MATCH_PORT_MAX
    validate_port NONMATCH_PORT
    [ "${MATCH_PORT_MIN}" -le "${MATCH_PORT_MAX}" ] || die "reversed port range"
    if [ "${SELECTOR_KIND}" = "single" ]; then
        [ "${MATCH_PORT_MIN}" -eq "${MATCH_PORT_MAX}" ] || \
            die "single selector requires equal min/max ports"
    fi
    validate_ipv4 "${VM_IP}" || die "VM_IP must be IPv4"
    validate_ipv4 "${EGRESS_TARGET_IP}" || die "EGRESS_TARGET_IP must be IPv4"
    [ -x "${GUEST_EXEC_FILE}" ] || die "GUEST_EXEC_FILE must be executable"
    [ -f "${NONCE_ECHO}" ] || die "missing nonce helper: ${NONCE_ECHO}"
    case "${CONVERGENCE_TIMEOUT}" in
        ''|*[!0-9]*|0) die "CONVERGENCE_TIMEOUT must be positive" ;;
    esac
}

now_iso() {
    date -u +%Y-%m-%dT%H:%M:%SZ
}

now_ms() {
    "${PYTHON_BIN}" - <<'PY'
from __future__ import print_function
import time
print(int(time.time() * 1000))
PY
}

event() {
    local name="$1"
    local result="$2"
    local detail="${3:-}"
    printf '%s\t%s\t%s\t%s\n' "$(now_iso)" "${name}" "${result}" "${detail}" \
        >>"${WORK_DIR}/events.tsv"
}

neutron_cli() {
    if [ -n "${NEUTRON_CLI_BIN:-}" ]; then
        "${NEUTRON_CLI_BIN}" "$@"
    else
        docker exec -u root --env-file "${ADMIN_RC_FILE}" \
            "${OPENSTACK_CLIENT}" neutron "$@"
    fi
}

id_from_value() {
    "${PYTHON_BIN}" -c '
from __future__ import print_function
import re
import sys

uuid_re = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
payload = sys.stdin.read()
match = uuid_re.search(payload)
if match:
    print(match.group(0))
'
}

record_owned() {
    local object_type="$1"
    local object_id="$2"
    printf '%s\t%s\n' "${object_type}" "${object_id}" >>"${WORK_DIR}/owned.tsv"
}

reverse_owned_ids() {
    local object_type="$1"
    "${PYTHON_BIN}" - "${WORK_DIR}/owned.tsv" "${object_type}" <<'PY'
from __future__ import print_function
import sys
path, wanted = sys.argv[1:3]
rows = []
try:
    with open(path) as handle:
        for line in handle:
            parts = line.rstrip("\n").split("\t", 1)
            if len(parts) == 2 and parts[0] == wanted:
                rows.append(parts[1])
except IOError:
    pass
for value in reversed(rows):
    print(value)
PY
}

delete_owned_type() {
    local object_type="$1"
    local command=""
    case "${object_type}" in
        binding) command=aria-acl-binding-delete ;;
        rule) command=aria-acl-rule-delete ;;
        policy) command=aria-acl-policy-delete ;;
        *) return 1 ;;
    esac
    local object_id
    while read -r object_id; do
        [ -n "${object_id}" ] || continue
        neutron_cli "${command}" "${object_id}" >/dev/null 2>&1 || true
    done < <(reverse_owned_ids "${object_type}")
}

assert_owned_gone() {
    local object_type command object_id
    for object_type in binding rule policy; do
        case "${object_type}" in
            binding) command=aria-acl-binding-show ;;
            rule) command=aria-acl-rule-show ;;
            policy) command=aria-acl-policy-show ;;
        esac
        while read -r object_id; do
            [ -n "${object_id}" ] || continue
            if neutron_cli "${command}" "${object_id}" >/dev/null 2>&1; then
                event cleanup_object fail "${object_type}:${object_id}"
                return 1
            fi
        done < <(reverse_owned_ids "${object_type}")
    done
}

cleanup_owned() {
    set +e
    delete_owned_type binding
    delete_owned_type rule
    delete_owned_type policy
    if assert_owned_gone; then
        event cleanup_complete pass
        return 0
    fi
    event cleanup_complete fail
    return 1
}

write_result() {
    local result="$1"
    local exit_code="$2"
    RESULT="${result}" EXIT_CODE="${exit_code}" "${PYTHON_BIN}" - \
        "${WORK_DIR}/result.json" "${CASE_ID}" "${DIRECTION}" "${PROTOCOL}" \
        "${STATEFUL}" <<'PY'
from __future__ import print_function
import json
import os
import sys
path, case_id, direction, protocol, stateful = sys.argv[1:6]
payload = {
    "case_id": case_id,
    "direction": direction,
    "protocol": protocol,
    "stateful": stateful == "true",
    "result": os.environ["RESULT"],
    "exit_code": int(os.environ["EXIT_CODE"]),
}
with open(path + ".tmp", "w") as handle:
    json.dump(payload, handle, sort_keys=True)
    handle.write("\n")
os.rename(path + ".tmp", path)
PY
}

finalize() {
    local original_rc="$?"
    [ "${FINALIZED}" = false ] || return
    FINALIZED=true
    trap - EXIT INT TERM
    local cleanup_rc=0
    cleanup_owned || cleanup_rc=$?
    if [ "${cleanup_rc}" -ne 0 ]; then
        original_rc=1
    fi
    if [ "${original_rc}" -eq 0 ]; then
        write_result pass 0
    else
        write_result fail "${original_rc}"
    fi
    printf '%s\n' "${original_rc}" >"${WORK_DIR}/exit-code"
    exit "${original_rc}"
}

guest_exec() {
    "${PYTHON_BIN}" "${GUEST_EXEC_FILE}" "${VM_IP}" "$1"
}

nonce_value() {
    printf '%s-%s-%s\n' "${CASE_ID}" "$1" "$(now_ms)"
}

last_nonempty_line() {
    "${PYTHON_BIN}" -c '
from __future__ import print_function
import sys

lines = [line.strip() for line in sys.stdin.read().replace("\r", "\n").split("\n")]
lines = [line for line in lines if line]
if lines:
    print(lines[-1])
'
}

probe_once() {
    local protocol="$1"
    local direction="$2"
    local port="$3"
    local label="$4"
    local nonce output command
    if [ "${protocol}" = "icmp" ]; then
        if [ "${direction}" = "ingress" ]; then
            ping -c 1 -W "${PROBE_TIMEOUT}" "${VM_IP}" >/dev/null 2>&1
        else
            guest_exec "ping -c 1 -W ${PROBE_TIMEOUT} ${EGRESS_TARGET_IP}" >/dev/null 2>&1
        fi
        return
    fi
    nonce="$(nonce_value "${label}")"
    if [ "${direction}" = "ingress" ]; then
        "${PYTHON_BIN}" "${NONCE_ECHO}" probe "${protocol}" "${VM_IP}" \
            "${port}" "${nonce}" "${PROBE_TIMEOUT}" >/dev/null
        return
    fi
    if [ "${protocol}" = "tcp" ]; then
        command="printf '%s' '${nonce}' | nc -w ${PROBE_TIMEOUT} '${EGRESS_TARGET_IP}' '${port}'"
    else
        command="printf '%s' '${nonce}' | nc -u -w ${PROBE_TIMEOUT} '${EGRESS_TARGET_IP}' '${port}'"
    fi
    output="$(guest_exec "${command}" 2>/dev/null | last_nonempty_line || true)"
    [ "${output}" = "${nonce}" ]
}

wait_verdict() {
    local expected="$1"
    local protocol="$2"
    local port="$3"
    local label="$4"
    local deadline=$((SECONDS + CONVERGENCE_TIMEOUT))
    local consecutive=0
    local started="$(now_ms)"
    while [ "${SECONDS}" -lt "${deadline}" ]; do
        if probe_once "${protocol}" "${DIRECTION}" "${port}" "${label}"; then
            if [ "${expected}" = allow ]; then
                event "${label}" pass "verdict=allow latency_ms=$(( $(now_ms) - started ))"
                return 0
            fi
            consecutive=0
        else
            if [ "${expected}" = drop ]; then
                consecutive=$((consecutive + 1))
                if [ "${consecutive}" -ge 3 ]; then
                    event "${label}" pass "verdict=drop samples=${consecutive} latency_ms=$(( $(now_ms) - started ))"
                    return 0
                fi
            fi
        fi
        sleep 1
    done
    event "${label}" fail "expected=${expected}"
    return 1
}

wait_status() {
    local expected="$1"
    local label="$2"
    local deadline=$((SECONDS + CONVERGENCE_TIMEOUT))
    local output_file="${WORK_DIR}/status-${label}.json"
    while [ "${SECONDS}" -lt "${deadline}" ]; do
        if neutron_cli aria-acl-port-status-show "${PORT_ID}" -f json \
            >"${output_file}.tmp" 2>/dev/null; then
            mv "${output_file}.tmp" "${output_file}"
            if "${PYTHON_BIN}" - "${output_file}" "${expected}" "${PORT_ID}" \
                "${EXPECTED_HOST}" "${POLICY_ID}" "${BINDING_ID}" <<'PY'
from __future__ import print_function
import json
import sys
path, expected, port_id, host, policy_id, binding_id = sys.argv[1:7]
with open(path) as handle:
    row = json.load(handle)
if isinstance(row, list) and all(isinstance(item, dict) for item in row):
    row = dict((item.get("Field"), item.get("Value")) for item in row)
if row.get("port_id") != port_id or row.get("host") != host or row.get("stale") is True:
    raise SystemExit(1)
if expected == "ready":
    checks = (
        row.get("effective_policy_id") == policy_id,
        row.get("binding_id") == binding_id,
        row.get("status") == "ready",
        row.get("runtime_status") == "ready",
        row.get("effective_action") == "enforce",
    )
else:
    checks = (
        row.get("effective_action") == "bypass",
        row.get("status") != "ready" or row.get("runtime_status") != "ready",
    )
if not all(checks):
    raise SystemExit(1)
PY
            then
                event "status_${label}" pass "expected=${expected}"
                return 0
            fi
        fi
        sleep 1
    done
    event "status_${label}" fail "expected=${expected}"
    return 1
}

capture_heartbeat() {
    local label="$1"
    local list agent_id details
    list="$(neutron_cli agent-list)"
    agent_id="$(printf '%s\n' "${list}" | grep 'Aria ACL agent' | grep " ${EXPECTED_HOST} " | awk '{print $2; exit}')"
    [ -n "${agent_id}" ] || { event heartbeat fail "missing_agent"; return 1; }
    details="${WORK_DIR}/heartbeat-${label}.json"
    neutron_cli agent-show "${agent_id}" -f json >"${details}"
    "${PYTHON_BIN}" - "${details}" <<'PY'
from __future__ import print_function
import ast
import json
import sys
with open(sys.argv[1]) as handle:
    row = json.load(handle)
if isinstance(row, list) and all(isinstance(item, dict) for item in row):
    row = dict((item.get("Field"), item.get("Value")) for item in row)
if not row.get("alive"):
    raise SystemExit("agent is not alive")
cfg = row.get("configurations") or {}
if isinstance(cfg, str):
    try:
        cfg = json.loads(cfg)
    except ValueError:
        cfg = ast.literal_eval(cfg)
if cfg.get("ready") is not True or cfg.get("degraded") is True:
    raise SystemExit("heartbeat is not ready/non-degraded")
if int(cfg.get("generation_lag") or 0) != 0:
    raise SystemExit("generation_lag is nonzero")
PY
    event heartbeat pass "label=${label} generation_lag=0"
}

create_policy() {
    POLICY_ID="$(neutron_cli aria-acl-policy-create \
        --name "matrix-${CASE_ID}" --default-action allow --stateful "${STATEFUL}" \
        --enabled true -f value -c id | id_from_value)"
    [ -n "${POLICY_ID}" ] || die "failed to create policy"
    record_owned policy "${POLICY_ID}"
    event policy_create pass "policy_id=${POLICY_ID}"
}

rule_port_args() {
    local protocol="$1"
    local min_port="$2"
    local max_port="$3"
    if [ "${protocol}" != icmp ]; then
        printf '%s\n' --dst-port-min "${min_port}" --dst-port-max "${max_port}"
    fi
}

create_rule() {
    local args=(
        aria-acl-rule-create --policy-id "${POLICY_ID}" --direction "${DIRECTION}"
        --priority 100 --action drop --protocol "${PROTOCOL}" --enabled true
    )
    if [ "${DIRECTION}" = ingress ]; then
        args+=(--dst-cidr "${VM_IP}/32")
    else
        args+=(--src-cidr "${VM_IP}/32" --dst-cidr "${EGRESS_TARGET_IP}/32")
    fi
    if [ "${PROTOCOL}" != icmp ]; then
        args+=(--dst-port-min "${MATCH_PORT_MIN}" --dst-port-max "${MATCH_PORT_MAX}")
    fi
    RULE_ID="$(neutron_cli "${args[@]}" -f value -c id | id_from_value)"
    [ -n "${RULE_ID}" ] || die "failed to create rule"
    record_owned rule "${RULE_ID}"
    event rule_create pass "rule_id=${RULE_ID}"
}

create_binding() {
    BINDING_ID="$(neutron_cli aria-acl-binding-create --policy-id "${POLICY_ID}" \
        --port "${PORT_ID}" --enabled true -f value -c id | id_from_value)"
    [ -n "${BINDING_ID}" ] || die "failed to create binding"
    record_owned binding "${BINDING_ID}"
    event binding_create pass "binding_id=${BINDING_ID}"
}

assert_drop_with_control() {
    local protocol="$1"
    local drop_port="$2"
    local allow_port="$3"
    local label="$4"
    wait_verdict drop "${protocol}" "${drop_port}" "${label}_matching_drop"
    if [ "${protocol}" = icmp ]; then
        wait_verdict allow tcp "${allow_port}" "${label}_nonmatching_allow"
    else
        wait_verdict allow "${protocol}" "${allow_port}" "${label}_nonmatching_allow"
    fi
}

run_case() {
    mkdir -p "${WORK_DIR}"
    : >"${WORK_DIR}/events.tsv"
    : >"${WORK_DIR}/owned.tsv"
    trap finalize EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM

    capture_heartbeat before
    wait_verdict allow "${PROTOCOL}" "${MATCH_PORT_MIN}" baseline_matching_allow
    wait_verdict allow "${PROTOCOL}" "${NONMATCH_PORT}" baseline_nonmatching_allow

    create_policy
    create_rule
    create_binding
    wait_status ready initial
    assert_drop_with_control "${PROTOCOL}" "${MATCH_PORT_MIN}" "${NONMATCH_PORT}" initial

    local active_protocol="${PROTOCOL}"
    local active_port="${NONMATCH_PORT}"
    local old_port="${MATCH_PORT_MIN}"
    if [ "${PROTOCOL}" = icmp ]; then
        active_protocol=tcp
        neutron_cli aria-acl-rule-update "${RULE_ID}" --protocol tcp \
            --dst-port "${NONMATCH_PORT}" >/dev/null
    else
        neutron_cli aria-acl-rule-update "${RULE_ID}" --dst-port "${NONMATCH_PORT}" >/dev/null
    fi
    event rule_selector_update pass "protocol=${active_protocol} port=${active_port}"
    wait_verdict allow "${PROTOCOL}" "${old_port}" selector_old_allow
    assert_drop_with_control "${active_protocol}" "${active_port}" "${old_port}" selector_new

    neutron_cli aria-acl-rule-update "${RULE_ID}" --enabled false >/dev/null
    event rule_disable pass
    wait_verdict allow "${active_protocol}" "${active_port}" rule_disabled_allow
    neutron_cli aria-acl-rule-update "${RULE_ID}" --enabled true >/dev/null
    event rule_enable pass
    assert_drop_with_control "${active_protocol}" "${active_port}" "${old_port}" rule_enabled

    neutron_cli aria-acl-binding-update "${BINDING_ID}" --enabled false >/dev/null
    event binding_disable pass
    wait_status bypass binding_disabled
    wait_verdict allow "${active_protocol}" "${active_port}" binding_disabled_allow
    neutron_cli aria-acl-binding-update "${BINDING_ID}" --enabled true >/dev/null
    event binding_enable pass
    wait_status ready binding_enabled
    assert_drop_with_control "${active_protocol}" "${active_port}" "${old_port}" binding_enabled

    neutron_cli aria-acl-policy-update "${POLICY_ID}" --enabled false >/dev/null
    event policy_disable pass
    wait_status bypass policy_disabled
    wait_verdict allow "${active_protocol}" "${active_port}" policy_disabled_allow
    neutron_cli aria-acl-policy-update "${POLICY_ID}" --enabled true >/dev/null
    event policy_enable pass
    wait_status ready policy_enabled
    assert_drop_with_control "${active_protocol}" "${active_port}" "${old_port}" policy_enabled

    delete_owned_type binding
    delete_owned_type rule
    delete_owned_type policy
    wait_verdict allow "${active_protocol}" "${active_port}" rollback_active_allow
    wait_verdict allow "${PROTOCOL}" "${old_port}" rollback_original_allow
    capture_heartbeat after
    event case_complete pass
}

select_python
validate_inputs

if [ "${1:-run}" = validate ]; then
    echo "active matrix case validation passed"
    exit 0
fi
[ "${1:-run}" = run ] || die "usage: $0 [validate|run]"
run_case
