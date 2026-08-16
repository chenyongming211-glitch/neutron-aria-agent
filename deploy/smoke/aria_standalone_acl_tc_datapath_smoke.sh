#!/usr/bin/env bash
set -euo pipefail

MODE="${MODE:-system}"
: "${ARIA_AGENT_BIN:?ARIA_AGENT_BIN is required}"
: "${EBPF_OBJECT:?EBPF_OBJECT is required}"
case "${MODE}" in system|tap) ;; *) echo "ERROR: MODE must be system or tap" >&2; exit 2 ;; esac
[ "${EUID}" -eq 0 ] || { echo "ERROR: root is required" >&2; exit 2; }

# These names and records are a field-matrix interface.  They do not claim
# traffic success: absent prerequisites use status="deferred/pending".
FIELD_EVIDENCE_STATUS="deferred/pending"
STANDALONE_ETHERTYPE_ANY_SMOKE="${STANDALONE_ETHERTYPE_ANY_SMOKE:-0}"
CASE_IPV4_ONLY="ipv4-only"
CASE_IPV6_ONLY="ipv6-only"
CASE_DUAL_STACK="dual-stack"
CASE_WILDCARD_ISOLATION="wildcard-isolation"
CASE_FRAGMENT="fragment"
CASE_STATEFUL_REPLY="stateful-reply"
CASE_UPGRADE="upgrade"
CASE_ROLLBACK="rollback"
FIELD_CASES=("${CASE_IPV4_ONLY}" "${CASE_IPV6_ONLY}" "${CASE_DUAL_STACK}" "${CASE_WILDCARD_ISOLATION}" "${CASE_FRAGMENT}" "${CASE_STATEFUL_REPLY}" "${CASE_UPGRADE}" "${CASE_ROLLBACK}")

RUN_ID="${RUN_ID:-standalone-tc-acl-$(date +%Y%m%d%H%M%S)-$$-${RANDOM}-${RANDOM}}"
WORK_DIR="${WORK_DIR:-/tmp/${RUN_ID}}"
TC_HEALTH_WAIT_SECS="${TC_HEALTH_WAIT_SECS:-12}"
AGENT_STOP_TIMEOUT_SECS="${AGENT_STOP_TIMEOUT_SECS:-5}"
HTTP_ADDR="${HTTP_ADDR:-}"
HTTP=""
FIXTURE_TOKEN=""
NETNS="${NETNS:-}"
HOST_IF="${HOST_IF:-}"
PEER_IF="${PEER_IF:-}"
SECOND_HOST_IF="${SECOND_HOST_IF:-}"
SECOND_PEER_IF="${SECOND_PEER_IF:-}"
HOST_IP="10.203.0.1"
PEER_IP="10.203.0.2"
DENIED_IP="10.203.0.6"
PIN_ROOT="${WORK_DIR}/bpffs"
STATE_ROOT="${WORK_DIR}/state"
CONFIG_FILE="${WORK_DIR}/agent.toml"
ALLOWED_PACKETS="${ALLOWED_PACKETS:-4}"
DENIED_PACKETS="${DENIED_PACKETS:-2}"
PING_PAYLOAD_BYTES="${PING_PAYLOAD_BYTES:-56}"
PACKET_BYTES=$((PING_PAYLOAD_BYTES + 42))
FRAGMENT_TRACKING_SMOKE="${FRAGMENT_TRACKING_SMOKE:-0}"
XDP_IDENTITY_SMOKE="${XDP_IDENTITY_SMOKE:-0}"
FRAGMENT_DRIVER="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/fragment_tracking_field_driver.py"
FRAGMENT_VLAN_A="${FRAGMENT_VLAN_A:-203}"
FRAGMENT_VLAN_B="${FRAGMENT_VLAN_B:-204}"
FRAGMENT_IPV4_HOST="${FRAGMENT_IPV4_HOST:-10.203.2.1}"
FRAGMENT_IPV4_PEER="${FRAGMENT_IPV4_PEER:-10.203.2.2}"
FRAGMENT_IPV6_HOST="${FRAGMENT_IPV6_HOST:-2001:db8:205::1}"
FRAGMENT_IPV6_PEER="${FRAGMENT_IPV6_PEER:-2001:db8:205::2}"
FRAGMENT_BASE_IPV6_HOST="${FRAGMENT_BASE_IPV6_HOST:-2001:db8:203::1}"
FRAGMENT_BASE_IPV6_PEER="${FRAGMENT_BASE_IPV6_PEER:-2001:db8:203::2}"
FRAGMENT_CAPACITY=8
HOST_VLAN_A_IF=""
PEER_VLAN_A_IF=""
HOST_VLAN_B_IF=""
PEER_VLAN_B_IF=""

INSTANCE=""
AGENT_PID=""
TC_INGRESS_LINK=""
TC_EGRESS_LINK=""
TC_INGRESS_PROG=""
TC_EGRESS_PROG=""
TC_ATTACH_MODE=""
PRIVATE_BPFFS_MOUNTED=false
PIN_ROOT_CREATED=false
NETNS_CREATED=false
VETH_CREATED=false
SECOND_VETH_CREATED=false
HOST_VLAN_A_CREATED=false
PEER_VLAN_A_CREATED=false
HOST_VLAN_B_CREATED=false
PEER_VLAN_B_CREATED=false
SYSTEM_STARTED=false
TRACE_ARMED=false
BODY_SUCCEEDED=false
RESULT="fail"
FAILURE_REASON="smoke did not complete"
DUAL_TC_READY=false
XDP_NEUTRAL=false
MISSING_TC_REJECTED=false
HEALTH_POLL_DEGRADED=false
RECOVERY_VERIFIED=false
HEALTHY_PINNED_RESTART=false
INCOMPLETE_PINNED_QUIESCED=false
FRAGMENT_BODY_SUCCEEDED=false
FRAGMENT_TRANSITIONS_VERIFIED=false
XDP_DETACHED_PIN_RETAINED=false
XDP_REPORTED_NOT_READY=false
XDP_STALE_PIN_NOT_CLAIMED=false
XDP_TC_ACL_INDEPENDENT=false
cleanup_errors=()

record_field_case() {
    local case_name="$1" command="$2" expected_verdict="$3" observed_verdict="$4" status="$5" ifindex="unknown"
    local interface="${HOST_IF:-unknown}" status_snapshot="${FIELD_STATUS_SNAPSHOT:-pending capture}" counter_snapshot="${FIELD_COUNTER_SNAPSHOT:-pending capture}"
    [ -n "${HOST_IF}" ] && [ -r "/sys/class/net/${HOST_IF}/ifindex" ] && ifindex="$(cat "/sys/class/net/${HOST_IF}/ifindex")"
    CASE_NAME="${case_name}" CASE_COMMAND="${command}" EXPECTED_VERDICT="${expected_verdict}" \
    OBSERVED_VERDICT="${observed_verdict}" CASE_STATUS="${status}" CASE_IFINDEX="${ifindex}" \
    CASE_INTERFACE="${interface}" STATUS_SNAPSHOT="${status_snapshot}" COUNTER_SNAPSHOT="${counter_snapshot}" \
    CASE_AGENT_VERSION="${AGENT_VERSION:-unknown}" CASE_DATAPATH_VERSION="${DATAPATH_VERSION:-unknown}" \
    python3 - <<'PY' >>"${WORK_DIR}/field-case-results.jsonl"
import json,os,platform
status=os.environ["CASE_STATUS"]
if status == "pass":
    for name in ("CASE_INTERFACE", "CASE_IFINDEX", "CASE_AGENT_VERSION", "CASE_DATAPATH_VERSION", "STATUS_SNAPSHOT", "COUNTER_SNAPSHOT"):
        value=os.environ[name]
        assert value not in ("", "unknown", "pending capture"),(name,value)
    assert os.path.isfile(os.environ["STATUS_SNAPSHOT"])
    assert os.path.isfile(os.environ["COUNTER_SNAPSHOT"])
    observed_verdict=os.environ["OBSERVED_VERDICT"].strip().lower()
    assert observed_verdict != "not run"
    assert observed_verdict
    assert "prerequisite" not in os.environ["CASE_COMMAND"].lower()
    with open(os.environ["STATUS_SNAPSHOT"], encoding="utf-8") as handle:
        assert isinstance(json.load(handle), (dict, list))
    with open(os.environ["COUNTER_SNAPSHOT"], encoding="utf-8") as handle:
        assert handle.read().strip()
print(json.dumps({
    "case": os.environ["CASE_NAME"], "command": os.environ["CASE_COMMAND"],
    "expected_verdict": os.environ["EXPECTED_VERDICT"], "observed_verdict": os.environ["OBSERVED_VERDICT"],
    "interface": os.environ["CASE_INTERFACE"], "ifindex": os.environ["CASE_IFINDEX"],
    "kernel": platform.release(), "agent_version": os.environ["CASE_AGENT_VERSION"],
    "datapath_version": os.environ["CASE_DATAPATH_VERSION"],
    "status_snapshot": os.environ["STATUS_SNAPSHOT"], "counter_snapshot": os.environ["COUNTER_SNAPSHOT"],
    "status": os.environ["CASE_STATUS"],
}, sort_keys=True))
PY
}

record_deferred_field_cases() {
    local case_name
    for case_name in "${FIELD_CASES[@]}"; do
        record_field_case "${case_name}" "ethertype=any expansion and field topology prerequisite" "traffic verdict" "not run" "${FIELD_EVIDENCE_STATUS}"
    done
}

run_ethertype_any_expansion_smoke() {
    case "${STANDALONE_ETHERTYPE_ANY_SMOKE}" in
        0)
            record_deferred_field_cases
            return 0
            ;;
        1) ;;
        *) die "STANDALONE_ETHERTYPE_ANY_SMOKE must be 0 or 1" ;;
    esac
    # Exercise the product's public standalone API directly.  A caller cannot
    # substitute a command or a hand-written result for this expansion check.
    curl --fail -sS -H 'Content-Type: application/json' \
        -d '{"src_group":"any","dst_group":"any","proto":"tcp","action":"allow","direction":"ingress","ports":null,"ethertype":"any"}' \
        "${HTTP}/api/v1/${INSTANCE}/policies" >"${WORK_DIR}/ethertype-any-create.json"
    curl -fsS "${HTTP}/api/v1/${INSTANCE}/policies" >"${WORK_DIR}/ethertype-any-expansion.json"
    python3 - "${WORK_DIR}/ethertype-any-expansion.json" <<'PY' || die "ethertype=any did not expand to both families"
import json,sys
payload=json.load(open(sys.argv[1],encoding="utf-8"))
rows=payload["policies"]
assert isinstance(rows,list),payload
created=[row for row in rows if (row.get("src_group"),row.get("dst_group"),row.get("proto"),row.get("action"),row.get("direction")) == ("any","any","tcp","allow","ingress")]
assert {row.get("ethertype") for row in created}=={"IPv4","IPv6"},created
assert sum(row.get("ethertype")=="IPv4" for row in created)==1,created
assert sum(row.get("ethertype")=="IPv6" for row in created)==1,created
PY
    for ethertype in IPv4 IPv6; do
        curl --fail -sS -X DELETE -H 'Content-Type: application/json' \
            -d "{\"src_group\":\"any\",\"dst_group\":\"any\",\"proto\":\"tcp\",\"direction\":\"ingress\",\"ethertype\":\"${ethertype}\"}" \
            "${HTTP}/api/v1/${INSTANCE}/policies" >"${WORK_DIR}/ethertype-any-delete-${ethertype}.json"
    done
    curl -fsS "${HTTP}/api/v1/${INSTANCE}/policies" >"${WORK_DIR}/ethertype-any-deleted.json"
    python3 - "${WORK_DIR}/ethertype-any-deleted.json" <<'PY' || die "ethertype=any explicit family deletes left a policy behind"
import json,sys
payload=json.load(open(sys.argv[1],encoding="utf-8"))
rows=payload["policies"]
left=[row for row in rows if (row.get("src_group"),row.get("dst_group"),row.get("proto"),row.get("action"),row.get("direction")) == ("any","any","tcp","allow","ingress")]
assert not left,left
PY
    curl -fsS "${HTTP}/api/v1/instances" >"${WORK_DIR}/ethertype-any-instances.json"
    capture_acl_counters ethertype-any
    FIELD_STATUS_SNAPSHOT="${WORK_DIR}/ethertype-any-instances.json"
    FIELD_COUNTER_SNAPSHOT="${WORK_DIR}/ethertype-any-metrics.prom"
    record_field_case "${CASE_DUAL_STACK}" "POST/GET/DELETE /api/v1/${INSTANCE}/policies ethertype=any" "one IPv4 and one IPv6 family-qualified rule" "two exact created rules observed then deleted" "pass"
    record_field_case "${CASE_WILDCARD_ISOLATION}" "field topology prerequisite" "opposite family remains isolated" "not run" "${FIELD_EVIDENCE_STATUS}"
    record_field_case "${CASE_IPV4_ONLY}" "standalone IPv4 fixture traffic" "allow" "not run" "${FIELD_EVIDENCE_STATUS}"
    record_field_case "${CASE_IPV6_ONLY}" "standalone IPv6 fixture traffic" "allow" "not run" "${FIELD_EVIDENCE_STATUS}"
    record_field_case "${CASE_DUAL_STACK}" "standalone dual-stack fixture traffic" "allow" "not run" "${FIELD_EVIDENCE_STATUS}"
    record_field_case "${CASE_FRAGMENT}" "field topology prerequisite" "fragment verdict" "not run" "${FIELD_EVIDENCE_STATUS}"
    record_field_case "${CASE_STATEFUL_REPLY}" "field topology prerequisite" "stateful reply verdict" "not run" "${FIELD_EVIDENCE_STATUS}"
    record_field_case "${CASE_UPGRADE}" "field topology prerequisite" "upgrade verdict" "not run" "${FIELD_EVIDENCE_STATUS}"
    record_field_case "${CASE_ROLLBACK}" "field topology prerequisite" "rollback verdict" "not run" "${FIELD_EVIDENCE_STATUS}"
}

die() {
    FAILURE_REASON="$*"
    echo "ERROR: $*" >&2
    exit 1
}

need_command() {
    command -v "$1" >/dev/null 2>&1 || die "missing command: $1"
}

curl() {
    command curl -q "$@"
}

bpftool_map_lookup_json() {
    local map="$1" output dump
    shift
    output="$(bpftool -j map lookup pinned "${map}" key hex "$@" 2>/dev/null || true)"
    if printf '%s' "${output}" | python3 -c \
        'import json,sys; value=json.load(sys.stdin); raise SystemExit(0 if isinstance(value,dict) and "value" in value else 1)'; then
        printf '%s\n' "${output}"
        return 0
    fi

    dump="$(bpftool -j map dump pinned "${map}")"
    python3 -c '
import json,sys
expected=[int(value,16) for value in sys.argv[1:]]
rows=json.load(sys.stdin)
def decode(raw):
    return [item if isinstance(item,int) else int(item,0) for item in raw]
matches=[row for row in rows if decode(row.get("key",[]))==expected]
assert len(matches)==1,(expected,matches)
print(json.dumps(matches[0],separators=(",",":")))
' "$@" <<<"${dump}"
}

record_cleanup_error() {
    cleanup_errors+=("$*")
    echo "CLEANUP_ERROR: $*" >&2
}

derive_fixture_identity() {
    FIXTURE_TOKEN="$(python3 -c 'import secrets; print(secrets.token_hex(5))')"
    [ -n "${HOST_IF}" ] || HOST_IF="ah${FIXTURE_TOKEN}"
    [ -n "${PEER_IF}" ] || PEER_IF="ap${FIXTURE_TOKEN}"
    [ -n "${SECOND_HOST_IF}" ] || SECOND_HOST_IF="bh${FIXTURE_TOKEN}"
    [ -n "${SECOND_PEER_IF}" ] || SECOND_PEER_IF="bp${FIXTURE_TOKEN}"
    [ -n "${NETNS}" ] || NETNS="aria-tc-${FIXTURE_TOKEN}"
    HOST_VLAN_A_IF="vha${FIXTURE_TOKEN}"
    PEER_VLAN_A_IF="vpa${FIXTURE_TOKEN}"
    HOST_VLAN_B_IF="vhb${FIXTURE_TOKEN}"
    PEER_VLAN_B_IF="vpb${FIXTURE_TOKEN}"
}

select_http_addr() {
    if [ -z "${HTTP_ADDR}" ]; then
        HTTP_ADDR="$(python3 - <<'PY'
import socket
with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as sock:
    sock.bind(("127.0.0.1",0))
    print("127.0.0.1:%d" % sock.getsockname()[1])
PY
        )"
    fi
    HTTP="http://${HTTP_ADDR}"
}

preflight_fixture() {
    case "${XDP_IDENTITY_SMOKE}" in
        0|1) ;;
        *) die "XDP_IDENTITY_SMOKE must be 0 or 1" ;;
    esac
    [ "${#HOST_IF}" -le 15 ] || die "HOST_IF exceeds Linux interface-name limit: ${HOST_IF}"
    [ "${#PEER_IF}" -le 15 ] || die "PEER_IF exceeds Linux interface-name limit: ${PEER_IF}"
    [ "${#SECOND_HOST_IF}" -le 15 ] || die "SECOND_HOST_IF exceeds Linux interface-name limit"
    [ "${#SECOND_PEER_IF}" -le 15 ] || die "SECOND_PEER_IF exceeds Linux interface-name limit"
    for vlan_if in "${HOST_VLAN_A_IF}" "${PEER_VLAN_A_IF}" "${HOST_VLAN_B_IF}" "${PEER_VLAN_B_IF}"; do
        [ "${#vlan_if}" -le 15 ] || die "generated VLAN interface name exceeds Linux limit: ${vlan_if}"
        ip link show dev "${vlan_if}" >/dev/null 2>&1 && die "generated VLAN interface already exists: ${vlan_if}"
    done
    [ ! -e "${WORK_DIR}" ] || die "work directory already exists: ${WORK_DIR}"
    if ip netns list | awk '{print $1}' | grep -Fx "${NETNS}" >/dev/null; then
        die "network namespace already exists: ${NETNS}"
    fi
    if ip link show dev "${HOST_IF}" >/dev/null 2>&1; then
        die "host fixture interface already exists: ${HOST_IF}"
    fi
    if ip link show dev "${PEER_IF}" >/dev/null 2>&1; then
        die "peer fixture interface already exists: ${PEER_IF}"
    fi
    if [ "${FRAGMENT_TRACKING_SMOKE}" = 1 ]; then
        [ -r "${FRAGMENT_DRIVER}" ] || die "fragment tracking field driver is missing"
        python3 - "${FRAGMENT_VLAN_A}" "${FRAGMENT_VLAN_B}" \
            "${FRAGMENT_IPV4_HOST}" "${FRAGMENT_IPV4_PEER}" \
            "${FRAGMENT_IPV6_HOST}" "${FRAGMENT_IPV6_PEER}" \
            "${FRAGMENT_BASE_IPV6_HOST}" "${FRAGMENT_BASE_IPV6_PEER}" <<'PY' || die "invalid fragment fixture VLAN/address contract"
import ipaddress,sys
vlan_a,vlan_b=map(int,sys.argv[1:3])
assert 1 <= vlan_a <= 4094 and 1 <= vlan_b <= 4094 and vlan_a != vlan_b
addresses=[ipaddress.ip_address(value) for value in sys.argv[3:]]
assert [value.version for value in addresses] == [4,4,6,6,6,6]
assert len(set(addresses)) == len(addresses)
PY
    fi
    python3 - "${AGENT_STOP_TIMEOUT_SECS}" <<'PY' || die "AGENT_STOP_TIMEOUT_SECS must be a finite positive number"
import math,re,sys
raw=sys.argv[1]
assert re.fullmatch(r"(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)",raw),raw
timeout=float(raw)
assert math.isfinite(timeout) and timeout>0,timeout
PY
    python3 - "${HTTP_ADDR}" <<'PY' || die "loopback listen address is unavailable: ${HTTP_ADDR}"
import ipaddress,socket,sys
host,raw_port=sys.argv[1].rsplit(":",1)
port=int(raw_port)
assert ipaddress.ip_address(host).is_loopback,(host,port)
with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as sock:
    sock.bind((host,port))
PY
}

create_fragment_vlan_fixture() {
        ip link add link "${HOST_IF}" name "${HOST_VLAN_A_IF}" type vlan id "${FRAGMENT_VLAN_A}"
        HOST_VLAN_A_CREATED=true
        ip addr add "${FRAGMENT_IPV4_HOST}/30" dev "${HOST_VLAN_A_IF}"
        ip -6 addr add "${FRAGMENT_IPV6_HOST}/64" dev "${HOST_VLAN_A_IF}"
        ip link set "${HOST_VLAN_A_IF}" up
        ip netns exec "${NETNS}" ip link add link "${PEER_IF}" name "${PEER_VLAN_A_IF}" type vlan id "${FRAGMENT_VLAN_A}"
        PEER_VLAN_A_CREATED=true
        ip netns exec "${NETNS}" ip addr add "${FRAGMENT_IPV4_PEER}/30" dev "${PEER_VLAN_A_IF}"
        ip netns exec "${NETNS}" ip -6 addr add "${FRAGMENT_IPV6_PEER}/64" dev "${PEER_VLAN_A_IF}"
        ip netns exec "${NETNS}" ip link set "${PEER_VLAN_A_IF}" up
        ip link add link "${HOST_IF}" name "${HOST_VLAN_B_IF}" type vlan id "${FRAGMENT_VLAN_B}"
        HOST_VLAN_B_CREATED=true
        ip link set "${HOST_VLAN_B_IF}" up
        ip netns exec "${NETNS}" ip link add link "${PEER_IF}" name "${PEER_VLAN_B_IF}" type vlan id "${FRAGMENT_VLAN_B}"
        PEER_VLAN_B_CREATED=true
        ip netns exec "${NETNS}" ip link set "${PEER_VLAN_B_IF}" up
}

create_second_tap_fixture() {
        ip link add "${SECOND_HOST_IF}" type veth peer name "${SECOND_PEER_IF}"
        SECOND_VETH_CREATED=true
        ip link set "${SECOND_PEER_IF}" netns "${NETNS}"
        ip addr add "10.203.1.1/30" dev "${SECOND_HOST_IF}"
        ip -6 addr add "2001:db8:204::1/64" dev "${SECOND_HOST_IF}"
        ip link set "${SECOND_HOST_IF}" up
        ip netns exec "${NETNS}" ip addr add "10.203.1.2/30" dev "${SECOND_PEER_IF}"
        ip netns exec "${NETNS}" ip -6 addr add "2001:db8:204::2/64" dev "${SECOND_PEER_IF}"
        ip netns exec "${NETNS}" ip link set "${SECOND_PEER_IF}" up
}

create_primary_veth_fixture() {
    ip link add "${HOST_IF}" type veth peer name "${PEER_IF}"
    VETH_CREATED=true
    ip link set "${PEER_IF}" netns "${NETNS}"
    ip addr add "${HOST_IP}/30" dev "${HOST_IF}"
    if [ "${FRAGMENT_TRACKING_SMOKE}" = 1 ]; then
        ip -6 addr add "${FRAGMENT_BASE_IPV6_HOST}/64" dev "${HOST_IF}"
    fi
    ip link set "${HOST_IF}" up
    ip netns exec "${NETNS}" ip addr add "${PEER_IP}/30" dev "${PEER_IF}"
    if [ "${FRAGMENT_TRACKING_SMOKE}" = 1 ]; then
        ip netns exec "${NETNS}" ip -6 addr add "${FRAGMENT_BASE_IPV6_PEER}/64" dev "${PEER_IF}"
    fi
    ip netns exec "${NETNS}" ip addr add "${DENIED_IP}/32" dev "${PEER_IF}"
    ip route add "${DENIED_IP}/32" dev "${HOST_IF}"
    ip netns exec "${NETNS}" ip link set "${PEER_IF}" up
}

create_netns_fixture() {
    ip netns add "${NETNS}"
    NETNS_CREATED=true
    ip netns exec "${NETNS}" ip link set lo up
    create_primary_veth_fixture
    if [ "${FRAGMENT_TRACKING_SMOKE}" = 1 ]; then
        create_fragment_vlan_fixture
    fi
    if [ "${FRAGMENT_TRACKING_SMOKE}" = 1 ] && [ "${MODE}" = tap ]; then
        create_second_tap_fixture
    fi
}

start_agent_process() {
    "${ARIA_AGENT_BIN}" --config "${CONFIG_FILE}" >>"${WORK_DIR}/agent.stdout" 2>&1 &
    AGENT_PID=$!
    for _ in $(seq 1 100); do
        curl -fsS "${HTTP}/api/v1/health" >/dev/null && return 0
        kill -0 "${AGENT_PID}" 2>/dev/null || return 1
        sleep 0.1
    done
    return 1
}

start_agent() {
    local auto_attach=false
    [ "${MODE}" = tap ] && auto_attach=true
    [ ! -e "${PIN_ROOT}" ] || die "private pin root already exists: ${PIN_ROOT}"
    mkdir -p "${PIN_ROOT}"
    PIN_ROOT_CREATED=true
    mkdir -p "${STATE_ROOT}"
    mount -t bpf bpf "${PIN_ROOT}"
    PRIVATE_BPFFS_MOUNTED=true
    local fixture_pattern="^${HOST_IF}$"
    if [ "${FRAGMENT_TRACKING_SMOKE}" = 1 ] && [ "${MODE}" = tap ]; then fixture_pattern="^(${HOST_IF}|${SECOND_HOST_IF})$"; fi
    cat >"${CONFIG_FILE}" <<EOF
mode = "standalone"
auto_attach = ${auto_attach}
ebpf_path = "${EBPF_OBJECT}"
pin_path = "${PIN_ROOT}"
state_path = "${STATE_ROOT}"
iface_pattern = "${fixture_pattern}"
listen_addr = "${HTTP_ADDR}"
trace_backend = "legacy-map"
log_file_path = "${WORK_DIR}/agent.log"
EOF
    if [ "${FRAGMENT_TRACKING_SMOKE}" = 1 ]; then
        cat >>"${CONFIG_FILE}" <<EOF
fragment_tracking_field_verified = true
[fragment_tracking]
enabled = true
max_entries = ${FRAGMENT_CAPACITY}
ipv4_timeout_seconds = 30
ipv6_timeout_seconds = 30
EOF
    fi
    start_agent_process
}

next_fragment_identity() {
    FRAGMENT_ID_COUNTER=$((FRAGMENT_ID_COUNTER + 1))
    FRAGMENT_TOKEN="aria-fragment-${FIXTURE_TOKEN}-${FRAGMENT_ID_COUNTER}-0123456789"
    FRAGMENT_IDENT=$((1000 + FRAGMENT_ID_COUNTER))
}

fragment_driver() {
    local label="$1" family="$2" direction="$3" vlan="$4" operation="$5"
    local token="$6" ident="$7" iface_override="$8" source destination iface
    shift 8
    if [ "${family}" = ipv4 ]; then
        source="${FRAGMENT_IPV4_HOST}"
        destination="${FRAGMENT_IPV4_PEER}"
    else
        source="${FRAGMENT_IPV6_HOST}"
        destination="${FRAGMENT_IPV6_PEER}"
    fi
    if [ "${direction}" = host-to-peer ]; then
        iface="${iface_override:-${HOST_IF}}"
        FRAGMENT_ARGS=(--run --operation "${operation}" --iface "${iface}"
            --source "${source}" --destination "${destination}"
            --destination-mac "${FRAGMENT_PEER_MAC}" --family "${family}"
            --vlan "${vlan}" --metrics-url "${HTTP}/metrics"
            --pin-path "${FRAGMENT_PIN_PATH}" --receiver-netns "${NETNS}"
            --token "${token}" --ident "${ident}")
    else
        FRAGMENT_ARGS=(--run --operation "${operation}" --iface "${PEER_IF}"
            --send-netns "${NETNS}" --source "${destination}" --destination "${source}"
            --source-mac "${FRAGMENT_PEER_MAC}" --destination-mac "${FRAGMENT_HOST_MAC}"
            --family "${family}" --vlan "${vlan}" --metrics-url "${HTTP}/metrics"
            --pin-path "${FRAGMENT_PIN_PATH}" --token "${token}" --ident "${ident}")
    fi
    FRAGMENT_ARGS+=("$@")
    python3 "${FRAGMENT_DRIVER}" "${FRAGMENT_ARGS[@]}" >"${WORK_DIR}/${label}.log"
}

observe_fragment_occupancy() {
    local family="$1" label="$2"
    python3 "${FRAGMENT_DRIVER}" --run --operation observe --family "${family}" \
        --metrics-url "${HTTP}/metrics" --pin-path "${FRAGMENT_PIN_PATH}" \
        --expected-occupancy 0 --expected-capacity "${FRAGMENT_CAPACITY}" \
        >"${WORK_DIR}/${label}.log"
}

publish_fragment_epoch_policy() {
    curl --fail -sS -H 'Content-Type: application/json' \
        -d '{"src_group":"standalone-unreferenced","dst_group":"fragment-host-v4","proto":"udp","action":"allow","direction":"ingress","ports":"54"}' \
        "${HTTP}/api/v1/${INSTANCE}/policies" >"${WORK_DIR}/fragment-epoch-policy-update.json"
}

run_fragment_tracking_field_smoke() {
    local family direction scenario token ident
    if [ "${FRAGMENT_TRACKING_SMOKE}" != 1 ]; then
        echo "SKIP: fragment tracking field smoke disabled"
        return 0
    fi
    FRAGMENT_PEER_MAC="$(ip netns exec "${NETNS}" cat "/sys/class/net/${PEER_IF}/address")"
    FRAGMENT_HOST_MAC="$(cat "/sys/class/net/${HOST_IF}/address")"
    FRAGMENT_PIN_PATH="${PIN_ROOT}/system"
    [ "${MODE}" = tap ] && FRAGMENT_PIN_PATH="${PIN_ROOT}/global-v2"
    FRAGMENT_ID_COUNTER=0
    for family in ipv4 ipv6; do
        for scenario in ordered post-first-reorder; do
            for direction in host-to-peer peer-to-host; do
                next_fragment_identity
                token="${FRAGMENT_TOKEN}"; ident="${FRAGMENT_IDENT}"
                fragment_driver "fragment-${family}-${direction}-${scenario}" "${family}" \
                    "${direction}" "${FRAGMENT_VLAN_A}" complete "${token}" "${ident}" "" \
                    --scenario "${scenario}"
            done
        done
        for direction in host-to-peer peer-to-host; do
            next_fragment_identity
            token="${FRAGMENT_TOKEN}"; ident="${FRAGMENT_IDENT}"
            fragment_driver "fragment-${family}-${direction}-later-before-first" "${family}" \
                "${direction}" "${FRAGMENT_VLAN_A}" complete "${token}" "${ident}" "" \
                --scenario later-before-first
        done
    done

    next_fragment_identity
    token="${FRAGMENT_TOKEN}"; ident="${FRAGMENT_IDENT}"
    fragment_driver fragment-vlan-establish ipv4 host-to-peer "${FRAGMENT_VLAN_A}" \
        establish "${token}" "${ident}" ""
    fragment_driver fragment-vlan-isolation-probe ipv4 host-to-peer "${FRAGMENT_VLAN_B}" \
        probe-old "${token}" "${ident}" "" --expected-probe-event miss --reuse-reason isolation
    fragment_driver fragment-vlan-continue ipv4 host-to-peer "${FRAGMENT_VLAN_A}" \
        continue "${token}" "${ident}" ""

    if [ "${MODE}" = tap ]; then
        next_fragment_identity
        token="${FRAGMENT_TOKEN}"; ident="${FRAGMENT_IDENT}"
        fragment_driver fragment-tap-establish ipv4 host-to-peer "${FRAGMENT_VLAN_A}" \
            establish "${token}" "${ident}" ""
        fragment_driver fragment-tap-isolation-probe ipv4 host-to-peer "${FRAGMENT_VLAN_A}" \
            probe-old "${token}" "${ident}" "${SECOND_HOST_IF}" \
            --expected-probe-event miss --reuse-reason isolation
        fragment_driver fragment-tap-continue ipv4 host-to-peer "${FRAGMENT_VLAN_A}" \
            continue "${token}" "${ident}" ""
    fi

    next_fragment_identity
    token="${FRAGMENT_TOKEN}"; ident="${FRAGMENT_IDENT}"
    fragment_driver fragment-epoch-establish ipv4 host-to-peer "${FRAGMENT_VLAN_A}" \
        establish "${token}" "${ident}" ""
    publish_fragment_epoch_policy
    fragment_driver fragment-epoch-stale-probe ipv4 host-to-peer "${FRAGMENT_VLAN_A}" \
        probe-old "${token}" "${ident}" "" --expected-probe-event stale --reuse-reason epoch

    next_fragment_identity
    token="${FRAGMENT_TOKEN}"; ident="${FRAGMENT_IDENT}"
    fragment_driver fragment-restart-establish ipv4 host-to-peer "${FRAGMENT_VLAN_A}" \
        establish "${token}" "${ident}" ""
    stop_agent_bounded || die "fragment restart pre-stop failed"
    SYSTEM_STARTED=false
    restart_agent_preserving_bpffs || die "fragment preserving-pins restart failed"
    if [ "${MODE}" = system ]; then
        start_system_mode || die "fragment restart system readiness failed"
    else
        start_tap_mode || die "fragment restart tap readiness failed"
    fi
    assert_dual_tc_ready
    observe_fragment_occupancy ipv4 fragment-restart-ipv4-empty
    observe_fragment_occupancy ipv6 fragment-restart-ipv6-empty
    fragment_driver fragment-restart-miss-probe ipv4 host-to-peer "${FRAGMENT_VLAN_A}" \
        probe-old "${token}" "${ident}" "" --expected-probe-event miss --reuse-reason restart

    next_fragment_identity
    fragment_driver fragment-pressure ipv4 host-to-peer "${FRAGMENT_VLAN_A}" pressure \
        "${FRAGMENT_TOKEN}" "${FRAGMENT_IDENT}" "" --capacity "${FRAGMENT_CAPACITY}" \
        --reuse-reason eviction
    FRAGMENT_TRANSITIONS_VERIFIED=true
    FRAGMENT_BODY_SUCCEEDED=true
}

restart_agent_preserving_bpffs() {
    [ "${PRIVATE_BPFFS_MOUNTED}" = true ]
    [ -d "${PIN_ROOT}" ]
    [ -r "${CONFIG_FILE}" ]
    start_agent_process
}

stop_agent_bounded() {
    local pid="${AGENT_PID}" watchdog="" wait_rc=0 timed_out=false
    local timeout_marker="${WORK_DIR}/agent-stop-timeout-${pid:-none}"
    [ -n "${pid}" ] || return 0
    if ! kill -0 "${pid}" 2>/dev/null; then
        wait "${pid}" 2>/dev/null || true
        AGENT_PID=""
        return 0
    fi
    rm -f "${timeout_marker}"
    kill -TERM "${pid}" 2>/dev/null || true
    (
        trap - EXIT
        sleep "${AGENT_STOP_TIMEOUT_SECS}"
        if kill -0 "${pid}" 2>/dev/null; then
            printf '%s\n' timeout >"${timeout_marker}"
            kill -KILL "${pid}" 2>/dev/null || true
        fi
    ) &
    watchdog=$!
    wait "${pid}" 2>/dev/null || wait_rc=$?
    if kill -0 "${watchdog}" 2>/dev/null; then
        kill "${watchdog}" 2>/dev/null || true
    fi
    wait "${watchdog}" 2>/dev/null || true
    [ ! -e "${timeout_marker}" ] || timed_out=true
    AGENT_PID=""
    if [ "${timed_out}" = true ]; then
        return 124
    fi
    case "${wait_rc}" in 0|143) return 0 ;; *) return "${wait_rc}" ;; esac
}

crash_agent_bounded() {
    local pid="${AGENT_PID}" wait_rc=0
    [ -n "${pid}" ] || return 0
    if ! kill -0 "${pid}" 2>/dev/null; then
        wait "${pid}" 2>/dev/null || true
        AGENT_PID=""
        return 0
    fi
    kill -KILL "${pid}" 2>/dev/null || true
    wait "${pid}" 2>/dev/null || wait_rc=$?
    AGENT_PID=""
    case "${wait_rc}" in 0|137) return 0 ;; *) return "${wait_rc}" ;; esac
}

start_system_mode() {
    curl --fail -sS -H 'Content-Type: application/json' \
        -d "{\"iface\":\"${HOST_IF}\",\"max_port_policies\":16384}" \
        "${HTTP}/api/v1/system/start" >"${WORK_DIR}/system-start.json"
    INSTANCE="system"
    SYSTEM_STARTED=true
    TC_INGRESS_LINK="${PIN_ROOT}/system/tc_ingress_link"
    TC_EGRESS_LINK="${PIN_ROOT}/system/tc_egress_link"
    TC_INGRESS_PROG="${PIN_ROOT}/system/tc_ingress"
    TC_EGRESS_PROG="${PIN_ROOT}/system/tc_egress"
}

wait_tap_instance() {
    local name="$1"
    for _ in $(seq 1 100); do
        curl -fsS "${HTTP}/api/v1/instances" | \
            python3 -c 'import json,sys; n=sys.argv[1]; p=json.load(sys.stdin); raise SystemExit(0 if any(i["name"]==n for i in p["instances"]) else 1)' \
            "${name}" && return 0
        sleep 0.1
    done
    return 1
}

start_tap_mode() {
    INSTANCE="${HOST_IF}"
    TC_INGRESS_LINK="${PIN_ROOT}/global-v2/${HOST_IF}_tc_ingress_link"
    TC_EGRESS_LINK="${PIN_ROOT}/global-v2/${HOST_IF}_tc_egress_link"
    TC_INGRESS_PROG="${PIN_ROOT}/global-v2/tc_ingress"
    TC_EGRESS_PROG="${PIN_ROOT}/global-v2/tc_egress"
    wait_tap_instance "${INSTANCE}" || return 1
    if [ "${FRAGMENT_TRACKING_SMOKE}" = 1 ]; then
        wait_tap_instance "${SECOND_HOST_IF}" || return 1
    fi
}

install_fixture_policy() {
    curl --fail -sS -H 'Content-Type: application/json' \
        -d "{\"name\":\"peer\",\"cidr\":\"${PEER_IP}/32\"}" \
        "${HTTP}/api/v1/${INSTANCE}/groups" >/dev/null
    curl --fail -sS -H 'Content-Type: application/json' \
        -d "{\"name\":\"host\",\"cidr\":\"${HOST_IP}/32\"}" \
        "${HTTP}/api/v1/${INSTANCE}/groups" >/dev/null
    curl --fail -sS -H 'Content-Type: application/json' \
        -d "{\"name\":\"denied\",\"cidr\":\"${DENIED_IP}/32\"}" \
        "${HTTP}/api/v1/${INSTANCE}/groups" >/dev/null
    curl --fail -sS -H 'Content-Type: application/json' \
        -d '{"name":"standalone-unreferenced","cidr":"10.203.0.7/32"}' \
        "${HTTP}/api/v1/${INSTANCE}/groups" >/dev/null
    curl --fail -sS -H 'Content-Type: application/json' \
        -d '{"src_group":"peer","dst_group":"host","proto":"icmp","action":"allow","direction":"ingress","ports":null}' \
        "${HTTP}/api/v1/${INSTANCE}/policies" >/dev/null
    curl --fail -sS -H 'Content-Type: application/json' \
        -d '{"src_group":"host","dst_group":"peer","proto":"icmp","action":"allow","direction":"egress","ports":null}' \
        "${HTTP}/api/v1/${INSTANCE}/policies" >/dev/null
    curl --fail -sS -H 'Content-Type: application/json' \
        -d '{"src_group":"denied","dst_group":"host","proto":"icmp","action":"drop","direction":"ingress","ports":null}' \
        "${HTTP}/api/v1/${INSTANCE}/policies" >/dev/null
    curl --fail -sS -H 'Content-Type: application/json' \
        -d '{"src_group":"host","dst_group":"denied","proto":"icmp","action":"drop","direction":"egress","ports":null}' \
        "${HTTP}/api/v1/${INSTANCE}/policies" >/dev/null
    if [ "${FRAGMENT_TRACKING_SMOKE}" = 1 ]; then
        curl --fail -sS -H 'Content-Type: application/json' \
            -d "{\"name\":\"fragment-host-v4\",\"cidr\":\"${FRAGMENT_IPV4_HOST}/32\"}" \
            "${HTTP}/api/v1/${INSTANCE}/groups" >/dev/null
        curl --fail -sS -H 'Content-Type: application/json' \
            -d "{\"name\":\"fragment-peer-v4\",\"cidr\":\"${FRAGMENT_IPV4_PEER}/32\"}" \
            "${HTTP}/api/v1/${INSTANCE}/groups" >/dev/null
        curl --fail -sS -H 'Content-Type: application/json' \
            -d "{\"name\":\"fragment-host-v6\",\"cidr\":\"${FRAGMENT_IPV6_HOST}/128\"}" \
            "${HTTP}/api/v1/${INSTANCE}/groups" >/dev/null
        curl --fail -sS -H 'Content-Type: application/json' \
            -d "{\"name\":\"fragment-peer-v6\",\"cidr\":\"${FRAGMENT_IPV6_PEER}/128\"}" \
            "${HTTP}/api/v1/${INSTANCE}/groups" >/dev/null
        curl --fail -sS -H 'Content-Type: application/json' \
            -d '{"src_group":"fragment-peer-v4","dst_group":"fragment-host-v4","proto":"udp","action":"allow","direction":"ingress","ports":"53"}' \
            "${HTTP}/api/v1/${INSTANCE}/policies" >/dev/null
        curl --fail -sS -H 'Content-Type: application/json' \
            -d '{"src_group":"fragment-host-v4","dst_group":"fragment-peer-v4","proto":"udp","action":"allow","direction":"egress","ports":"53"}' \
            "${HTTP}/api/v1/${INSTANCE}/policies" >/dev/null
        curl --fail -sS -H 'Content-Type: application/json' \
            -d '{"src_group":"fragment-peer-v6","dst_group":"fragment-host-v6","proto":"udp","action":"allow","direction":"ingress","ports":"53"}' \
            "${HTTP}/api/v1/${INSTANCE}/policies" >/dev/null
        curl --fail -sS -H 'Content-Type: application/json' \
            -d '{"src_group":"fragment-host-v6","dst_group":"fragment-peer-v6","proto":"udp","action":"allow","direction":"egress","ports":"53"}' \
            "${HTTP}/api/v1/${INSTANCE}/policies" >/dev/null
    fi
    curl --fail -sS -H 'Content-Type: application/json' -X PUT \
        -d '{"conntrack":true,"monitoring":true,"acl":true,"qos":null,"mirror":null,"tcprt":null,"ssl":null}' \
        "${HTTP}/api/v1/${INSTANCE}/config" >/dev/null
    curl --fail -sS -X DELETE \
        "${HTTP}/api/v1/${INSTANCE}/conntrack" >"${WORK_DIR}/initial-conntrack-flush.json"
}

capture_links() {
    local label="${1:-links}" net_rc=0
    [ -e "${TC_INGRESS_LINK}" ] && bpftool -j link show pinned "${TC_INGRESS_LINK}" \
        >"${WORK_DIR}/${label}-tc-ingress-link.json"
    [ -e "${TC_EGRESS_LINK}" ] && bpftool -j link show pinned "${TC_EGRESS_LINK}" \
        >"${WORK_DIR}/${label}-tc-egress-link.json"
    bpftool -j prog show pinned "${TC_INGRESS_PROG}" \
        >"${WORK_DIR}/${label}-tc-ingress-prog.json"
    bpftool -j prog show pinned "${TC_EGRESS_PROG}" \
        >"${WORK_DIR}/${label}-tc-egress-prog.json"
    if tc -j filter show dev "${HOST_IF}" ingress \
        >"${WORK_DIR}/${label}-tc-ingress.json" 2>"${WORK_DIR}/${label}-tc-ingress-json.err"; then
        rm -f "${WORK_DIR}/${label}-tc-ingress.txt"
    else
        rm -f "${WORK_DIR}/${label}-tc-ingress.json"
        tc filter show dev "${HOST_IF}" ingress >"${WORK_DIR}/${label}-tc-ingress.txt"
    fi
    if tc -j filter show dev "${HOST_IF}" egress \
        >"${WORK_DIR}/${label}-tc-egress.json" 2>"${WORK_DIR}/${label}-tc-egress-json.err"; then
        rm -f "${WORK_DIR}/${label}-tc-egress.txt"
    else
        rm -f "${WORK_DIR}/${label}-tc-egress.json"
        tc filter show dev "${HOST_IF}" egress >"${WORK_DIR}/${label}-tc-egress.txt"
    fi
    bpftool -j net show >"${WORK_DIR}/${label}-bpftool-net.json" \
        2>"${WORK_DIR}/${label}-bpftool-net.err" || net_rc=$?
    if [ "${net_rc}" -eq 0 ]; then
        printf '{"available":true,"exit_code":0}\n' \
            >"${WORK_DIR}/${label}-bpftool-net-status.json"
    else
        printf '{"available":false,"exit_code":%s}\n' "${net_rc}" \
            >"${WORK_DIR}/${label}-bpftool-net-status.json"
    fi
}

assert_exact_legacy_tc_filter() {
    local filter_json="$1" filter_text="$2" program_json="$3" expected_name="$4"
    python3 - "${filter_json}" "${filter_text}" "${program_json}" "${expected_name}" <<'PY'
import json,sys

filter_json,filter_text,program_json,expected_name=sys.argv[1:]
program=json.load(open(program_json,encoding="utf-8"))

def contains_exact_program(value):
    if isinstance(value,dict):
        if value.get("name")==expected_name and value.get("id")==expected_id:
            return True
        return any(contains_exact_program(child) for child in value.values())
    if isinstance(value,list):
        return any(contains_exact_program(child) for child in value)
    return False

try:
    filters=json.load(open(filter_json,encoding="utf-8"))
except FileNotFoundError:
    expected_tag=program.get("tag")
    assert isinstance(expected_tag,str) and expected_tag,(expected_name,program)
    matches=[]
    for line in open(filter_text,encoding="utf-8"):
        fields=line.split()
        if expected_name not in fields:
            continue
        matches.append(fields[fields.index("tag") + 1] if "tag" in fields else None)
    assert len(matches)==1 and matches[0].lower()==expected_tag.lower(),(
        expected_name,expected_tag,matches
    )
else:
    expected_id=program.get("id")
    assert isinstance(expected_id,int),(expected_name,program)
    assert contains_exact_program(filters),(expected_name,expected_id,filters)
PY
}

assert_dual_tc_ready() {
    if [ -e "${TC_INGRESS_LINK}" ] && [ -e "${TC_EGRESS_LINK}" ]; then
        TC_ATTACH_MODE="tcx"
    elif [ ! -e "${TC_INGRESS_LINK}" ] && [ ! -e "${TC_EGRESS_LINK}" ]; then
        TC_ATTACH_MODE="legacy"
    else
        die "mixed TC attachment state: exactly one link pin exists"
    fi
    capture_links dual-tc-ready
    if [ "${TC_ATTACH_MODE}" = tcx ]; then
        python3 - "${WORK_DIR}/dual-tc-ready-tc-ingress-link.json" \
            "${WORK_DIR}/dual-tc-ready-tc-egress-link.json" \
            "${WORK_DIR}/dual-tc-ready-tc-ingress-prog.json" \
            "${WORK_DIR}/dual-tc-ready-tc-egress-prog.json" <<'PY'
import json,sys
ingress=json.load(open(sys.argv[1],encoding="utf-8"))
egress=json.load(open(sys.argv[2],encoding="utf-8"))
ingress_prog=json.load(open(sys.argv[3],encoding="utf-8"))
egress_prog=json.load(open(sys.argv[4],encoding="utf-8"))
assert ingress.get("prog_id")==ingress_prog.get("id"),(ingress,ingress_prog,"tc_ingress")
assert egress.get("prog_id")==egress_prog.get("id"),(egress,egress_prog,"tc_egress")
PY
    else
        assert_exact_legacy_tc_filter \
            "${WORK_DIR}/dual-tc-ready-tc-ingress.json" \
            "${WORK_DIR}/dual-tc-ready-tc-ingress.txt" \
            "${WORK_DIR}/dual-tc-ready-tc-ingress-prog.json" \
            "tc_ingress"
        assert_exact_legacy_tc_filter \
            "${WORK_DIR}/dual-tc-ready-tc-egress.json" \
            "${WORK_DIR}/dual-tc-ready-tc-egress.txt" \
            "${WORK_DIR}/dual-tc-ready-tc-egress-prog.json" \
            "tc_egress"
    fi
    curl -fsS "${HTTP}/api/v1/instances" | python3 -c '
import json,sys
name=sys.argv[1]
item=next(i for i in json.load(sys.stdin)["instances"] if i["name"]==name)
assert item["acl_ready"] is True,item
' "${INSTANCE}"
    DUAL_TC_READY=true
}

capture_acl_counters() {
    local label="$1"
    curl -fsS "${HTTP}/api/v1/${INSTANCE}/config" \
        >"${WORK_DIR}/${label}-config.json"
    curl -fsS "${HTTP}/api/v1/${INSTANCE}/conntrack" \
        >"${WORK_DIR}/${label}-conntrack.json"
    curl -fsS "${HTTP}/api/v1/${INSTANCE}/stats/rules" \
        >"${WORK_DIR}/${label}-rules.json"
    curl -fsS "${HTTP}/metrics" >"${WORK_DIR}/${label}-metrics.prom"
}

set_trace_filter() {
    local src_ip="${1:-}" dst_ip="${2:-}" body
    body="$(printf '{"src_ip":"%s","dst_ip":"%s","src_port":0,"dst_port":0,"proto":"icmp"}' \
        "${src_ip}" "${dst_ip}")"
    curl --fail -sS -H 'Content-Type: application/json' \
        -X POST -d "${body}" "${HTTP}/api/v1/${INSTANCE}/trace" \
        >"${WORK_DIR}/trace-start-$(date +%s%N).json"
    TRACE_ARMED=true
}

clear_trace_filter() {
    [ "${TRACE_ARMED}" = true ] || return 0
    curl --max-time "${AGENT_STOP_TIMEOUT_SECS}" --fail -sS -X DELETE \
        "${HTTP}/api/v1/${INSTANCE}/trace" \
        >"${WORK_DIR}/trace-stop-$(date +%s%N).json"
    TRACE_ARMED=false
}

run_allowed_flow() {
    local label="${1:-allowed}"
    ip netns exec "${NETNS}" ping -I "${PEER_IP}" -c "${ALLOWED_PACKETS}" -W 1 \
        -s "${PING_PAYLOAD_BYTES}" "${HOST_IP}" >"${WORK_DIR}/${label}-flow.log"
}

run_observed_allowed_flow() {
    local label="$1"
    set_trace_filter "" ""
    capture_acl_counters "${label}-before"
    run_allowed_flow "${label}"
    capture_acl_counters "${label}-after"
    clear_trace_filter
    assert_xdp_neutral "${label}-before" "${label}-after" "${ALLOWED_PACKETS}"
}

run_denied_flow() {
    local label="${1:-denied}" ingress_rc=0 egress_rc=0
    set_trace_filter "" ""
    capture_acl_counters "${label}-before"
    ip netns exec "${NETNS}" ping -I "${DENIED_IP}" -c "${DENIED_PACKETS}" \
        -W 1 -s "${PING_PAYLOAD_BYTES}" "${HOST_IP}" \
        >"${WORK_DIR}/${label}-ingress-flow.log" 2>&1 || ingress_rc=$?
    ping -I "${HOST_IF}" -c "${DENIED_PACKETS}" -W 1 \
        -s "${PING_PAYLOAD_BYTES}" "${DENIED_IP}" \
        >"${WORK_DIR}/${label}-egress-flow.log" 2>&1 || egress_rc=$?
    [ "${ingress_rc}" -ne 0 ] || return 1
    [ "${egress_rc}" -ne 0 ] || return 1
    capture_acl_counters "${label}-after"
    clear_trace_filter
    python3 - "${WORK_DIR}/${label}-before-conntrack.json" \
        "${WORK_DIR}/${label}-after-conntrack.json" \
        "${WORK_DIR}/${label}-before-rules.json" \
        "${WORK_DIR}/${label}-after-rules.json" \
        "${DENIED_PACKETS}" "${PACKET_BYTES}" "${DENIED_IP}" "${HOST_IP}" <<'PY'
import json,sys
before_ct=json.load(open(sys.argv[1],encoding="utf-8"))["connections"]
after_ct=json.load(open(sys.argv[2],encoding="utf-8"))["connections"]
before=json.load(open(sys.argv[3],encoding="utf-8"))["rules"]
after=json.load(open(sys.argv[4],encoding="utf-8"))["rules"]
packets=int(sys.argv[5]); packet_bytes=int(sys.argv[6]); denied=sys.argv[7]; host=sys.argv[8]
def denied_connections(rows):
    return [row for row in rows if {row.get("src_ip"),row.get("dst_ip")}=={denied,host}
            and row.get("proto")=="icmp"]
assert denied_connections(before_ct)==denied_connections(after_ct),(before_ct,after_ct)
def dropped(rows,direction,src,dst,field):
    return sum(int(row.get(field) or 0) for row in rows
               if row.get("direction")==direction and row.get("src_group")==src
               and row.get("dst_group")==dst and row.get("proto")=="icmp")
ingress_packets=dropped(after,"ingress","denied","host","dropped_packets")-dropped(before,"ingress","denied","host","dropped_packets")
egress_packets=dropped(after,"egress","host","denied","dropped_packets")-dropped(before,"egress","host","denied","dropped_packets")
ingress_bytes=dropped(after,"ingress","denied","host","dropped_bytes")-dropped(before,"ingress","denied","host","dropped_bytes")
egress_bytes=dropped(after,"egress","host","denied","dropped_bytes")-dropped(before,"egress","host","denied","dropped_bytes")
assert ingress_packets>=packets,(ingress_packets,packets,before,after)
assert egress_packets>=packets,(egress_packets,packets,before,after)
assert ingress_bytes>=packets*packet_bytes,(ingress_bytes,packets*packet_bytes,before,after)
assert egress_bytes>=packets*packet_bytes,(egress_bytes,packets*packet_bytes,before,after)
PY
}

assert_xdp_neutral() {
    local before="$1" after="$2" packets="$3"
    python3 - "${WORK_DIR}/${before}-conntrack.json" \
        "${WORK_DIR}/${after}-conntrack.json" \
        "${WORK_DIR}/${before}-rules.json" \
        "${WORK_DIR}/${after}-rules.json" \
        "${WORK_DIR}/${before}-metrics.prom" \
        "${WORK_DIR}/${after}-metrics.prom" \
        "${packets}" "${PACKET_BYTES}" "${PEER_IP}" "${HOST_IP}" "${INSTANCE}" <<'PY'
import json,re,sys
before_ct=json.load(open(sys.argv[1],encoding="utf-8"))["connections"]
after_ct=json.load(open(sys.argv[2],encoding="utf-8"))["connections"]
before_rules=json.load(open(sys.argv[3],encoding="utf-8"))["rules"]
after_rules=json.load(open(sys.argv[4],encoding="utf-8"))["rules"]
before_metrics=open(sys.argv[5],encoding="utf-8").read().splitlines()
after_metrics=open(sys.argv[6],encoding="utf-8").read().splitlines()
packets=int(sys.argv[7]); packet_bytes=int(sys.argv[8]); peer=sys.argv[9]; host=sys.argv[10]; instance=sys.argv[11]
expected_packets=packets*2
expected_bytes=expected_packets*packet_bytes
def ct_totals(rows):
    selected=[row for row in rows if {row.get("src_ip"),row.get("dst_ip")}=={peer,host}
              and row.get("proto")=="icmp"]
    return (sum(int(row.get("packets") or 0) for row in selected),
            sum(int(row.get("bytes") or 0) for row in selected))
before_ct_packets,before_ct_bytes=ct_totals(before_ct)
after_ct_packets,after_ct_bytes=ct_totals(after_ct)
def rule_totals(rows,direction,src,dst):
    selected=[row for row in rows if row.get("direction")==direction
              and row.get("proto")=="icmp" and row.get("src_group")==src
              and row.get("dst_group")==dst]
    return (sum(int(row.get("packets") or 0) for row in selected),
            sum(int(row.get("bytes") or 0) for row in selected))
before_ingress,before_ingress_bytes=rule_totals(before_rules,"ingress","peer","host")
after_ingress,after_ingress_bytes=rule_totals(after_rules,"ingress","peer","host")
before_egress,before_egress_bytes=rule_totals(before_rules,"egress","host","peer")
after_egress,after_egress_bytes=rule_totals(after_rules,"egress","host","peer")
ingress_delta=after_ingress-before_ingress
egress_delta=after_egress-before_egress
def metric_total(lines,name,hook):
    total=0
    for line in lines:
        if not line.startswith(name+"{"):
            continue
        labels=dict(re.findall(r'(\w+)="([^"]*)"',line))
        if (labels.get("instance")==instance and labels.get("hook")==hook
                and labels.get("family")=="ipv4"):
            total += int(float(line.rsplit(None,1)[1]))
    return total
def metric_delta(name,hook):
    return metric_total(after_metrics,name,hook)-metric_total(before_metrics,name,hook)
tc_ingress_packets=metric_delta("aria_ct_contract_packets_total","tc_ingress")
tc_egress_packets=metric_delta("aria_ct_contract_packets_total","tc_egress")
tc_ingress_bytes=metric_delta("aria_ct_contract_bytes_total","tc_ingress")
tc_egress_bytes=metric_delta("aria_ct_contract_bytes_total","tc_egress")
assert tc_ingress_packets==packets,(tc_ingress_packets,packets)
assert tc_egress_packets==packets,(tc_egress_packets,packets)
assert tc_ingress_bytes==packets*packet_bytes,(tc_ingress_bytes,packets*packet_bytes)
assert tc_egress_bytes==packets*packet_bytes,(tc_egress_bytes,packets*packet_bytes)
assert after_ct_packets-before_ct_packets==expected_packets,(before_ct_packets,after_ct_packets)
assert after_ct_bytes-before_ct_bytes==expected_bytes,(before_ct_bytes,after_ct_bytes)
assert ingress_delta==expected_packets,(before_ingress,after_ingress)
assert egress_delta==0,(before_egress,after_egress)
assert after_ingress_bytes-before_ingress_bytes==expected_bytes
assert after_egress_bytes-before_egress_bytes==0
PY
    XDP_NEUTRAL=true
}

exercise_legacy_zero_compatibility() {
    [ "${MODE}" = tap ] || return 0
    local map="${PIN_ROOT}/global-v2/TAP_CONFIG_MAP" ifindex ifindex_key tap_id key value
    ifindex="$(cat "/sys/class/net/${HOST_IF}/ifindex")"
    ifindex_key="$(python3 -c 'import struct,sys; print(" ".join("%02x"%b for b in struct.pack("=I",int(sys.argv[1]))))' "${ifindex}")"
    # Encoded keys intentionally expand into one helper argv entry per byte.
    # shellcheck disable=SC2086
    tap_id="$(bpftool_map_lookup_json "${PIN_ROOT}/global-v2/IFACE_CTX_MAP" \
        ${ifindex_key} | python3 -c 'import json,struct,sys; v=json.load(sys.stdin)["value"]; print(struct.unpack("=I",bytes(int(x,0) if isinstance(x,str) else x for x in v[:4]))[0])')"
    key="$(python3 -c 'import struct,sys; print(" ".join("%02x"%b for b in struct.pack("=I",int(sys.argv[1]))))' "${tap_id}")"
    # Encoded keys intentionally expand into one helper argv entry per byte.
    # shellcheck disable=SC2086
    bpftool_map_lookup_json "${map}" ${key} >"${WORK_DIR}/tap-config-original.json"
    value="$(python3 - "${WORK_DIR}/tap-config-original.json" <<'PY'
import json,sys
v=[int(x,0) if isinstance(x,str) else x for x in json.load(open(sys.argv[1],encoding="utf-8"))["value"]]
assert len(v)==8,v
v[7]=0
print(" ".join("%02x"%b for b in v))
PY
    )"
    # Encoded keys/values intentionally expand into one bpftool argv entry per byte.
    # shellcheck disable=SC2086
    bpftool map update pinned "${map}" key hex ${key} value hex ${value}
    set_trace_filter "" ""
    capture_acl_counters legacy-zero-before
    run_allowed_flow legacy-zero
    capture_acl_counters legacy-zero-after
    clear_trace_filter
    assert_xdp_neutral legacy-zero-before legacy-zero-after "${ALLOWED_PACKETS}"
    curl --fail -sS -H 'Content-Type: application/json' -X PUT \
        -d '{"conntrack":true,"monitoring":true,"acl":true,"qos":null,"mirror":null,"tcprt":null,"ssl":null}' \
        "${HTTP}/api/v1/${INSTANCE}/config" >/dev/null
    # Encoded keys intentionally expand into one helper argv entry per byte.
    # shellcheck disable=SC2086
    bpftool_map_lookup_json "${map}" ${key} | python3 -c '
import json,sys
value=[int(x,0) if isinstance(x,str) else x for x in json.load(sys.stdin)["value"]]
assert len(value)==8 and value[7]==1,value
'
}

assert_health_poll_degrades() {
    if [ "${TC_ATTACH_MODE}" = legacy ]; then
        tc filter del dev "${HOST_IF}" egress
        tc filter show dev "${HOST_IF}" egress \
            >"${WORK_DIR}/detached-legacy-egress-filter.txt"
    else
        local lost_link="${TC_EGRESS_LINK}"
        bpftool link detach pinned "${lost_link}"
        [ -e "${lost_link}" ]
        bpftool -j link show pinned "${lost_link}" >"${WORK_DIR}/detached-but-pinned-link.json"
    fi
    sleep "${TC_HEALTH_WAIT_SECS}"
    curl -fsS "${HTTP}/api/v1/instances" >"${WORK_DIR}/health-degraded-instances.json"
    curl -fsS "${HTTP}/api/v1/${INSTANCE}/config" >"${WORK_DIR}/health-degraded-config.json"
    python3 - "${WORK_DIR}/health-degraded-instances.json" \
        "${WORK_DIR}/health-degraded-config.json" "${INSTANCE}" <<'PY'
import json,sys
item=next(i for i in json.load(open(sys.argv[1],encoding="utf-8"))["instances"] if i["name"]==sys.argv[3])
config=json.load(open(sys.argv[2],encoding="utf-8"))
assert item["acl_ready"] is False,item
assert item.get("readiness_reason")=="missing_tc_egress",item
assert config["acl"] is False,config
assert config["conntrack"] is False,config
PY
    HEALTH_POLL_DEGRADED=true
}

recover_missing_legacy_tc_runtime() {
    crash_agent_bounded || die "legacy TC recovery crash did not terminate cleanly"
    SYSTEM_STARTED=false
    restart_agent_preserving_bpffs || die "legacy TC recovery agent restart failed"
    if [ "${MODE}" = system ]; then
        start_system_mode
    else
        start_tap_mode
    fi
    assert_dual_tc_ready
    [ "${TC_ATTACH_MODE}" = legacy ] || die "legacy TC recovery changed attachment mode"
    assert_recovery_verified
}

assert_missing_tc_rejected() {
    local code
    code="$(curl -sS -o "${WORK_DIR}/missing-tc-enable.json" -w '%{http_code}' \
        -H 'Content-Type: application/json' -X PUT \
        -d '{"conntrack":true,"monitoring":null,"acl":true,"qos":null,"mirror":null,"tcprt":null,"ssl":null}' \
        "${HTTP}/api/v1/${INSTANCE}/config")"
    [ "${code}" = 503 ]
    python3 - "${WORK_DIR}/missing-tc-enable.json" <<'PY'
import json,sys
payload=json.load(open(sys.argv[1],encoding="utf-8"))
text=json.dumps(payload).lower()
assert "not ready" in text or "not-ready" in text,payload
PY
    echo "not-ready enable request rejected with HTTP 503" >"${WORK_DIR}/missing-tc-rejected.txt"
    MISSING_TC_REJECTED=true
}

assert_incomplete_pinned_runtime_quiesced() {
    local map key ifindex ifindex_key tap_id
    curl -fsS "${HTTP}/api/v1/instances" >"${WORK_DIR}/incomplete-restart-instances.json"
    python3 - "${WORK_DIR}/incomplete-restart-instances.json" "${INSTANCE}" <<'PY'
import json,sys
items=json.load(open(sys.argv[1],encoding="utf-8"))["instances"]
item=next((row for row in items if row["name"]==sys.argv[2]),{"acl_ready":False})
assert item["acl_ready"] is False,item
PY
    if [ "${MODE}" = system ]; then
        map="${PIN_ROOT}/system/FIREWALL_CONFIG"
        key="00 00 00 00"
    else
        map="${PIN_ROOT}/global-v2/TAP_CONFIG_MAP"
        ifindex="$(cat "/sys/class/net/${HOST_IF}/ifindex")"
        ifindex_key="$(python3 -c 'import struct,sys; print(" ".join("%02x"%b for b in struct.pack("=I",int(sys.argv[1]))))' "${ifindex}")"
        # Encoded keys intentionally expand into one helper argv entry per byte.
        # shellcheck disable=SC2086
        tap_id="$(bpftool_map_lookup_json "${PIN_ROOT}/global-v2/IFACE_CTX_MAP" \
            ${ifindex_key} | python3 -c 'import json,struct,sys; v=json.load(sys.stdin)["value"]; print(struct.unpack("=I",bytes(int(x,0) if isinstance(x,str) else x for x in v[:4]))[0])')"
        key="$(python3 -c 'import struct,sys; print(" ".join("%02x"%b for b in struct.pack("=I",int(sys.argv[1]))))' "${tap_id}")"
    fi
    # Encoded keys intentionally expand into one helper argv entry per byte.
    # shellcheck disable=SC2086
    bpftool_map_lookup_json "${map}" ${key} >"${WORK_DIR}/incomplete-restart-gate.json"
    python3 - "${WORK_DIR}/incomplete-restart-gate.json" "${MODE}" <<'PY'
import json,sys
value=[int(x,0) if isinstance(x,str) else x for x in json.load(open(sys.argv[1],encoding="utf-8"))["value"]]
acl_index=5 if sys.argv[2]=="system" else 2
assert value[0]==0,value
assert value[acl_index]==0,value
PY
    INCOMPLETE_PINNED_QUIESCED=true
}

assert_standalone_all_group_projection() {
    local label="${1:?projection label is required}" map_root expected_tap_id=0 ifindex ifindex_key
    case "${MODE}" in
        system)
            map_root="${PIN_ROOT}/system"
            printf '%s\n' '[]' >"${WORK_DIR}/${label}-tap-config.json"
            ;;
        tap)
            map_root="${PIN_ROOT}/global-v2"
            bpftool -j map dump pinned "${map_root}/TAP_CONFIG_MAP" >"${WORK_DIR}/${label}-tap-config.json"
            ifindex="$(cat "/sys/class/net/${HOST_IF}/ifindex")"
            ifindex_key="$(python3 -c 'import struct,sys; print(" ".join("%02x"%b for b in struct.pack("=I",int(sys.argv[1]))))' "${ifindex}")"
            # Encoded keys intentionally expand into one helper argv entry per byte.
            # shellcheck disable=SC2086
            expected_tap_id="$(bpftool_map_lookup_json "${map_root}/IFACE_CTX_MAP" \
                ${ifindex_key} | python3 -c 'import json,struct,sys; v=json.load(sys.stdin)["value"]; print(struct.unpack("=I",bytes(int(x,0) if isinstance(x,str) else x for x in v[:4]))[0])')"
            ;;
    esac
    curl -fsS "${HTTP}/api/v1/${INSTANCE}/groups" >"${WORK_DIR}/${label}-groups.json"
    bpftool -j map dump pinned "${map_root}/SRC_IPV4_TRIE" >"${WORK_DIR}/${label}-general-src.json"
    bpftool -j map dump pinned "${map_root}/DST_IPV4_TRIE" >"${WORK_DIR}/${label}-general-dst.json"
    bpftool -j map dump pinned "${map_root}/ACL_SRC_IPV4_TRIE" >"${WORK_DIR}/${label}-acl-src.json"
    bpftool -j map dump pinned "${map_root}/ACL_DST_IPV4_TRIE" >"${WORK_DIR}/${label}-acl-dst.json"
    python3 - "${WORK_DIR}/${label}-groups.json" \
        "${WORK_DIR}/${label}-tap-config.json" \
        "${WORK_DIR}/${label}-general-src.json" \
        "${WORK_DIR}/${label}-general-dst.json" \
        "${WORK_DIR}/${label}-acl-src.json" \
        "${WORK_DIR}/${label}-acl-dst.json" \
        "${MODE}" "${expected_tap_id}" <<'PY'
import ipaddress,json,sys
def decode_bytes(values):
    return bytes(int(value,16) if isinstance(value,str) else value for value in values)
def decode_u32(values):
    return int.from_bytes(decode_bytes(values),sys.byteorder)
def decode_lpm_entries(rows,expected_tap_id):
    entries=set()
    for row in rows:
        key=decode_bytes(row["key"])
        row_tap_id=int.from_bytes(key[4:8],"big")
        if row_tap_id!=expected_tap_id:
            continue
        prefix_len=decode_u32(key[:4])-32
        address=key[8:12]
        group_id=decode_u32(row["value"])
        entries.add((prefix_len,address,group_id))
    return entries
groups=json.load(open(sys.argv[1],encoding="utf-8"))["groups"]
tap_config_rows=json.load(open(sys.argv[2],encoding="utf-8"))
general_src_rows=json.load(open(sys.argv[3],encoding="utf-8"))
general_dst_rows=json.load(open(sys.argv[4],encoding="utf-8"))
acl_src_rows=json.load(open(sys.argv[5],encoding="utf-8"))
acl_dst_rows=json.load(open(sys.argv[6],encoding="utf-8"))
mode=sys.argv[7]
expected_tap_id=int(sys.argv[8])
groups_by_name={row["name"]:row["id"] for row in groups}
referenced_id=groups_by_name["peer"]
unreferenced_id=groups_by_name["standalone-unreferenced"]
if mode=="system":
    assert tap_config_rows==[],tap_config_rows
    tap_id=0; active_bank=0
else:
    rows=[row for row in tap_config_rows if decode_u32(row["key"])==expected_tap_id]
    assert len(rows)==1,(expected_tap_id,tap_config_rows)
    tap_id=expected_tap_id
    active_bank=decode_bytes(rows[0]["value"])[6]&1
active_acl_tap_id=tap_id*2|active_bank
expected_rows=[
    (network.version,network.prefixlen,network.network_address.packed,row["id"])
    for row in groups
    for cidr in row["cidrs"]
    for network in (ipaddress.ip_network(cidr,strict=False),)
    if network.version==4
]
expected_entries={
    (prefix_len,address,group_id)
    for _,prefix_len,address,group_id in expected_rows
}
expected_ids={entry[2] for entry in expected_entries}
actual_general_src=decode_lpm_entries(general_src_rows,tap_id)
actual_general_dst=decode_lpm_entries(general_dst_rows,tap_id)
actual_acl_src=decode_lpm_entries(acl_src_rows,active_acl_tap_id)
actual_acl_dst=decode_lpm_entries(acl_dst_rows,active_acl_tap_id)
assert referenced_id in expected_ids
assert unreferenced_id in expected_ids
assert actual_general_src==expected_entries
assert actual_general_dst==expected_entries
assert actual_acl_src==expected_entries
assert actual_acl_dst==expected_entries
PY
}

restart_healthy_pinned_runtime() {
    crash_agent_bounded || die "healthy pinned-runtime crash did not terminate cleanly"
    SYSTEM_STARTED=false
    restart_agent_preserving_bpffs || die "healthy pinned-runtime agent restart failed"
    if [ "${MODE}" = system ]; then
        start_system_mode
    else
        start_tap_mode
    fi
    assert_dual_tc_ready
    assert_standalone_all_group_projection after-restart
    run_observed_allowed_flow healthy-restart
    run_denied_flow healthy-restart-denied
    HEALTHY_PINNED_RESTART=true
}

assert_recovery_verified() {
    curl -fsS "${HTTP}/api/v1/${INSTANCE}/config" >"${WORK_DIR}/recovery-config.json"
    curl -fsS "${HTTP}/api/v1/${INSTANCE}/groups" >"${WORK_DIR}/recovery-groups.json"
    curl -fsS "${HTTP}/api/v1/${INSTANCE}/policies" >"${WORK_DIR}/recovery-policies.json"
    python3 - "${WORK_DIR}/recovery-config.json" "${WORK_DIR}/recovery-groups.json" \
        "${WORK_DIR}/recovery-policies.json" "${FRAGMENT_TRACKING_SMOKE}" <<'PY'
import json,sys
config=json.load(open(sys.argv[1],encoding="utf-8"))
groups=json.load(open(sys.argv[2],encoding="utf-8"))["groups"]
policies=json.load(open(sys.argv[3],encoding="utf-8"))["policies"]
assert config["acl"] is True,config
assert config["conntrack"] is True,config
assert {"peer","host","denied"}.issubset({row["name"] for row in groups}),groups
expected={("peer","host","allow","ingress"),("host","peer","allow","egress"),
          ("denied","host","drop","ingress"),("host","denied","drop","egress")}
if sys.argv[4]=="1":
    assert {"fragment-host-v4","fragment-peer-v4","fragment-host-v6","fragment-peer-v6"}.issubset(
        {row["name"] for row in groups}),groups
    expected.update({
        ("fragment-peer-v4","fragment-host-v4","allow","ingress"),
        ("fragment-host-v4","fragment-peer-v4","allow","egress"),
        ("fragment-peer-v6","fragment-host-v6","allow","ingress"),
        ("fragment-host-v6","fragment-peer-v6","allow","egress"),
    })
actual={(row["src_group"],row["dst_group"],row["action"],row["direction"]) for row in policies}
assert actual==expected,(actual,expected)
PY
    curl --fail -sS -X DELETE "${HTTP}/api/v1/${INSTANCE}/conntrack" \
        >"${WORK_DIR}/recovery-conntrack-flush.json"
    run_observed_allowed_flow recovery-allowed
    run_denied_flow recovery-denied
    RECOVERY_VERIFIED=true
}

recover_incomplete_pinned_runtime() {
    local code
    crash_agent_bounded || die "incomplete pinned-runtime crash did not terminate cleanly"
    SYSTEM_STARTED=false
    restart_agent_preserving_bpffs || die "agent restart failed with incomplete pinned runtime"
    if [ "${MODE}" = system ]; then
        INSTANCE="system"
        TC_INGRESS_LINK="${PIN_ROOT}/system/tc_ingress_link"
        TC_EGRESS_LINK="${PIN_ROOT}/system/tc_egress_link"
        TC_INGRESS_PROG="${PIN_ROOT}/system/tc_ingress"
        TC_EGRESS_PROG="${PIN_ROOT}/system/tc_egress"
        code="$(curl -sS -o "${WORK_DIR}/incomplete-system-start.json" -w '%{http_code}' \
            -H 'Content-Type: application/json' \
            -d "{\"iface\":\"${HOST_IF}\",\"max_port_policies\":16384}" \
            "${HTTP}/api/v1/system/start")"
        case "${code}" in 2*) die "incomplete system pinned runtime was incorrectly accepted" ;; esac
    else
        INSTANCE="${HOST_IF}"
        TC_INGRESS_LINK="${PIN_ROOT}/global-v2/${HOST_IF}_tc_ingress_link"
        TC_EGRESS_LINK="${PIN_ROOT}/global-v2/${HOST_IF}_tc_egress_link"
        TC_INGRESS_PROG="${PIN_ROOT}/global-v2/tc_ingress"
        TC_EGRESS_PROG="${PIN_ROOT}/global-v2/tc_egress"
        sleep 1
    fi
    assert_incomplete_pinned_runtime_quiesced

    if [ "${MODE}" = system ]; then
        curl --fail -sS -X POST "${HTTP}/api/v1/system/stop" \
            >"${WORK_DIR}/incomplete-system-stop.json"
        start_system_mode
    else
        if [ "${FRAGMENT_TRACKING_SMOKE}" = 1 ]; then
            ip netns exec "${NETNS}" ip link del "${PEER_VLAN_B_IF}" || die "incomplete recovery peer VLAN B removal failed"
            PEER_VLAN_B_CREATED=false
            ip link del "${HOST_VLAN_B_IF}" || die "incomplete recovery host VLAN B removal failed"
            HOST_VLAN_B_CREATED=false
            ip netns exec "${NETNS}" ip link del "${PEER_VLAN_A_IF}" || die "incomplete recovery peer VLAN A removal failed"
            PEER_VLAN_A_CREATED=false
            ip link del "${HOST_VLAN_A_IF}" || die "incomplete recovery host VLAN A removal failed"
            HOST_VLAN_A_CREATED=false
            ip link del "${SECOND_HOST_IF}" || die "incomplete recovery second tap removal failed"
            SECOND_VETH_CREATED=false
        fi
        ip link del "${HOST_IF}"
        VETH_CREATED=false
        for _ in $(seq 1 100); do
            [ ! -e "${PIN_ROOT}/global-v2" ] && break
            sleep 0.1
        done
        [ ! -e "${PIN_ROOT}/global-v2" ] || die "tap delete did not clean incomplete shared runtime"
        create_primary_veth_fixture
        if [ "${FRAGMENT_TRACKING_SMOKE}" = 1 ]; then
            create_fragment_vlan_fixture
            create_second_tap_fixture
        fi
        start_tap_mode
    fi
    assert_dual_tc_ready
    assert_recovery_verified
}

run_xdp_link_identity_field_smoke() {
    local xdp_link
    if [ "${XDP_IDENTITY_SMOKE}" != 1 ]; then
        echo "SKIP: XDP link identity field smoke disabled"
        return 0
    fi

    case "${MODE}" in
        system) xdp_link="${PIN_ROOT}/system/xdp_link" ;;
        tap) xdp_link="${PIN_ROOT}/global-v2/${HOST_IF}_xdp_link" ;;
    esac
    [ -e "${xdp_link}" ] || die "XDP identity smoke requires a pinned XDP link"

    curl -fsS "${HTTP}/api/v1/instances" >"${WORK_DIR}/xdp-identity-before.json"
    python3 - "${WORK_DIR}/xdp-identity-before.json" "${INSTANCE}" <<'PY' || die "XDP identity smoke requires initial XDP and TC ACL readiness"
import json,sys
item=next(i for i in json.load(open(sys.argv[1],encoding="utf-8"))["instances"]
          if i["name"]==sys.argv[2])
assert item["xdp_ready"] is True,item
assert item["acl_ready"] is True,item
PY

    bpftool link detach pinned "${xdp_link}" \
        || die "failed to detach pinned XDP link"
    [ -e "${xdp_link}" ] || die "detached XDP link pin disappeared"
    bpftool -j link show pinned "${xdp_link}" \
        >"${WORK_DIR}/xdp-detached-but-pinned.json" \
        || die "detached XDP link pin is no longer readable"
    XDP_DETACHED_PIN_RETAINED=true

    sleep "${TC_HEALTH_WAIT_SECS}"
    curl -fsS "${HTTP}/api/v1/instances" \
        >"${WORK_DIR}/xdp-identity-detached.json"
    python3 - "${WORK_DIR}/xdp-identity-detached.json" "${INSTANCE}" <<'PY' || die "detached XDP link did not degrade independently"
import json,sys
item=next(i for i in json.load(open(sys.argv[1],encoding="utf-8"))["instances"]
          if i["name"]==sys.argv[2])
assert item["xdp_ready"] is False,item
assert item["acl_ready"] is True,item
PY
    XDP_REPORTED_NOT_READY=true

    crash_agent_bounded || die "XDP identity restart crash did not terminate cleanly"
    SYSTEM_STARTED=false
    restart_agent_preserving_bpffs || die "XDP identity agent restart failed"
    if [ "${MODE}" = system ]; then
        start_system_mode
    else
        start_tap_mode
    fi
    [ -e "${xdp_link}" ] || die "restart removed the unverified XDP pin"
    sleep "${TC_HEALTH_WAIT_SECS}"
    curl -fsS "${HTTP}/api/v1/instances" \
        >"${WORK_DIR}/xdp-identity-after-restart.json"
    python3 - "${WORK_DIR}/xdp-identity-after-restart.json" "${INSTANCE}" <<'PY' || die "restart claimed or replaced the detached XDP pin"
import json,sys
item=next(i for i in json.load(open(sys.argv[1],encoding="utf-8"))["instances"]
          if i["name"]==sys.argv[2])
assert item["xdp_ready"] is False,item
assert item["acl_ready"] is True,item
PY
    XDP_STALE_PIN_NOT_CLAIMED=true

    run_observed_allowed_flow xdp-identity-allowed \
        || die "TC allowed flow failed after XDP identity degradation"
    run_denied_flow xdp-identity-denied \
        || die "TC denied flow failed after XDP identity degradation"
    XDP_TC_ACL_INDEPENDENT=true
}

verify_cleanup() {
    if [ -n "${AGENT_PID}" ] && kill -0 "${AGENT_PID}" 2>/dev/null; then
        return 1
    fi
    [ "${PRIVATE_BPFFS_MOUNTED}" = false ] || return 1
    [ "${PIN_ROOT_CREATED}" = false ] || return 1
    [ "${VETH_CREATED}" = false ] || return 1
    [ "${SECOND_VETH_CREATED}" = false ] || return 1
    [ "${HOST_VLAN_A_CREATED}" = false ] || return 1
    [ "${PEER_VLAN_A_CREATED}" = false ] || return 1
    [ "${HOST_VLAN_B_CREATED}" = false ] || return 1
    [ "${PEER_VLAN_B_CREATED}" = false ] || return 1
    [ "${NETNS_CREATED}" = false ] || return 1
    mountpoint -q "${PIN_ROOT}" && return 1
    ip netns list | awk '{print $1}' | grep -Fx "${NETNS}" >/dev/null && return 1
    ip link show dev "${HOST_IF}" >/dev/null 2>&1 && return 1
    ip link show dev "${SECOND_HOST_IF}" >/dev/null 2>&1 && return 1
    ip link show dev "${HOST_VLAN_A_IF}" >/dev/null 2>&1 && return 1
    ip link show dev "${HOST_VLAN_B_IF}" >/dev/null 2>&1 && return 1
    tc qdisc show dev "${HOST_IF}" >/dev/null 2>&1 && return 1
    [ ! -e "${PIN_ROOT}" ] || return 1
    return 0
}

write_summary() {
    printf '%s\n' "${cleanup_errors[@]:-}" >"${WORK_DIR}/cleanup-errors.txt" || return 1
    MODE="${MODE}" RESULT="${RESULT}" FAILURE_REASON="${FAILURE_REASON}" \
    TC_ATTACH_MODE="${TC_ATTACH_MODE}" \
    WORK_DIR="${WORK_DIR}" DUAL_TC_READY="${DUAL_TC_READY}" \
    XDP_NEUTRAL="${XDP_NEUTRAL}" MISSING_TC_REJECTED="${MISSING_TC_REJECTED}" \
    HEALTH_POLL_DEGRADED="${HEALTH_POLL_DEGRADED}" RECOVERY_VERIFIED="${RECOVERY_VERIFIED}" \
    HEALTHY_PINNED_RESTART="${HEALTHY_PINNED_RESTART}" \
    INCOMPLETE_PINNED_QUIESCED="${INCOMPLETE_PINNED_QUIESCED}" \
    FRAGMENT_TRACKING_SMOKE="${FRAGMENT_TRACKING_SMOKE}" \
    FRAGMENT_BODY_SUCCEEDED="${FRAGMENT_BODY_SUCCEEDED}" \
    FRAGMENT_TRANSITIONS_VERIFIED="${FRAGMENT_TRANSITIONS_VERIFIED}" \
    XDP_IDENTITY_SMOKE="${XDP_IDENTITY_SMOKE}" \
    XDP_DETACHED_PIN_RETAINED="${XDP_DETACHED_PIN_RETAINED}" \
    XDP_REPORTED_NOT_READY="${XDP_REPORTED_NOT_READY}" \
    XDP_STALE_PIN_NOT_CLAIMED="${XDP_STALE_PIN_NOT_CLAIMED}" \
    XDP_TC_ACL_INDEPENDENT="${XDP_TC_ACL_INDEPENDENT}" \
    RUN_ID="${RUN_ID}" HOST_IF="${HOST_IF}" NETNS="${NETNS}" HTTP_ADDR="${HTTP_ADDR}" \
        python3 >"${WORK_DIR}/summary.json.tmp" <<'PY' || return 1
import json,os
cleanup_errors=[line.rstrip("\n") for line in open(os.path.join(os.environ["WORK_DIR"],"cleanup-errors.txt"),encoding="utf-8") if line.rstrip("\n")]
if os.environ["FRAGMENT_TRACKING_SMOKE"] != "1":
    fragment_status="skipped"
elif (os.environ["FRAGMENT_BODY_SUCCEEDED"].lower()=="true" and
      os.environ["FRAGMENT_TRANSITIONS_VERIFIED"].lower()=="true" and
      os.environ["RESULT"]=="pass" and not cleanup_errors):
    fragment_status="pass"
else:
    fragment_status="fail"
if os.environ["XDP_IDENTITY_SMOKE"] != "1":
    xdp_identity_status="skipped"
elif (os.environ["XDP_DETACHED_PIN_RETAINED"].lower()=="true" and
      os.environ["XDP_REPORTED_NOT_READY"].lower()=="true" and
      os.environ["XDP_STALE_PIN_NOT_CLAIMED"].lower()=="true" and
      os.environ["XDP_TC_ACL_INDEPENDENT"].lower()=="true" and
      os.environ["RESULT"]=="pass" and not cleanup_errors):
    xdp_identity_status="passed"
else:
    xdp_identity_status="failed"
out={"mode":os.environ["MODE"],"tc_attach_mode":os.environ["TC_ATTACH_MODE"],
     "dual_tc_ready":os.environ["DUAL_TC_READY"].lower()=="true",
     "xdp_neutral":os.environ["XDP_NEUTRAL"].lower()=="true",
     "missing_tc_rejected":os.environ["MISSING_TC_REJECTED"].lower()=="true",
     "health_poll_degraded":os.environ["HEALTH_POLL_DEGRADED"].lower()=="true",
     "recovery_verified":os.environ["RECOVERY_VERIFIED"].lower()=="true",
     "healthy_pinned_restart":os.environ["HEALTHY_PINNED_RESTART"].lower()=="true",
     "incomplete_pinned_quiesced":os.environ["INCOMPLETE_PINNED_QUIESCED"].lower()=="true",
     "fragment_tracking":{"status":fragment_status,
                          "enabled":os.environ["FRAGMENT_TRACKING_SMOKE"]=="1",
                          "body_succeeded":os.environ["FRAGMENT_BODY_SUCCEEDED"].lower()=="true",
                          "transitions_verified":os.environ["FRAGMENT_TRANSITIONS_VERIFIED"].lower()=="true"},
     "xdp_link_identity":{"status":xdp_identity_status,
                          "enabled":os.environ["XDP_IDENTITY_SMOKE"]=="1",
                          "detached_pin_retained":os.environ["XDP_DETACHED_PIN_RETAINED"].lower()=="true",
                          "reported_not_ready":os.environ["XDP_REPORTED_NOT_READY"].lower()=="true",
                          "stale_pin_not_claimed":os.environ["XDP_STALE_PIN_NOT_CLAIMED"].lower()=="true",
                          "tc_acl_independent":os.environ["XDP_TC_ACL_INDEPENDENT"].lower()=="true"},
     "cleanup_errors":cleanup_errors,"result":os.environ["RESULT"],
     "failure_reason":os.environ["FAILURE_REASON"],"work_dir":os.environ["WORK_DIR"],
     "run_id":os.environ["RUN_ID"],"host_if":os.environ["HOST_IF"],
     "netns":os.environ["NETNS"],"http_addr":os.environ["HTTP_ADDR"]}
print(json.dumps(out,sort_keys=True,indent=2))
PY
    mv "${WORK_DIR}/summary.json.tmp" "${WORK_DIR}/summary.json" || return 1
}

cleanup() {
    local body_rc=$? final_rc=1
    trap - EXIT
    set +e
    if [ "${TRACE_ARMED}" = true ] && [ -n "${AGENT_PID}" ] && kill -0 "${AGENT_PID}" 2>/dev/null; then
        clear_trace_filter || record_cleanup_error "trace filter cleanup failed"
    fi
    if [ "${MODE}" = system ] && [ "${SYSTEM_STARTED}" = true ]; then
        if ! curl --max-time "${AGENT_STOP_TIMEOUT_SECS}" --fail -sS -X POST \
            "${HTTP}/api/v1/system/stop" >"${WORK_DIR}/cleanup-system-stop.json" 2>&1; then
            record_cleanup_error "system stop failed"
        fi
        SYSTEM_STARTED=false
    fi
    if ! stop_agent_bounded; then
        record_cleanup_error "agent shutdown exceeded ${AGENT_STOP_TIMEOUT_SECS}s"
    fi
    if [ "${PRIVATE_BPFFS_MOUNTED}" = true ]; then
        if ! umount "${PIN_ROOT}"; then
            record_cleanup_error "private bpffs unmount failed"
        else
            PRIVATE_BPFFS_MOUNTED=false
        fi
    fi
    if [ "${PIN_ROOT_CREATED}" = true ] && [ "${PRIVATE_BPFFS_MOUNTED}" = false ]; then
        if rm -rf "${PIN_ROOT}"; then
            PIN_ROOT_CREATED=false
        else
            record_cleanup_error "temporary pin root removal failed"
        fi
    fi
    if [ "${PEER_VLAN_B_CREATED}" = true ]; then
        if ip netns exec "${NETNS}" ip link del "${PEER_VLAN_B_IF}"; then PEER_VLAN_B_CREATED=false; else record_cleanup_error "peer VLAN B removal failed"; fi
    fi
    if [ "${HOST_VLAN_B_CREATED}" = true ]; then
        if ip link del "${HOST_VLAN_B_IF}"; then HOST_VLAN_B_CREATED=false; else record_cleanup_error "host VLAN B removal failed"; fi
    fi
    if [ "${PEER_VLAN_A_CREATED}" = true ]; then
        if ip netns exec "${NETNS}" ip link del "${PEER_VLAN_A_IF}"; then PEER_VLAN_A_CREATED=false; else record_cleanup_error "peer VLAN A removal failed"; fi
    fi
    if [ "${HOST_VLAN_A_CREATED}" = true ]; then
        if ip link del "${HOST_VLAN_A_IF}"; then HOST_VLAN_A_CREATED=false; else record_cleanup_error "host VLAN A removal failed"; fi
    fi
    if [ "${VETH_CREATED}" = true ]; then
        if ip link del "${HOST_IF}"; then
            VETH_CREATED=false
        else
            record_cleanup_error "fixture veth removal failed"
        fi
    fi
    if [ "${SECOND_VETH_CREATED}" = true ]; then
        if ip link del "${SECOND_HOST_IF}"; then SECOND_VETH_CREATED=false; else record_cleanup_error "second fixture veth removal failed"; fi
    fi
    if [ "${NETNS_CREATED}" = true ]; then
        if ip netns del "${NETNS}"; then
            NETNS_CREATED=false
        else
            record_cleanup_error "network namespace removal failed"
        fi
    fi
    if ! verify_cleanup; then
        record_cleanup_error "cleanup rollback verification failed"
    fi

    RESULT="fail"
    if [ "${body_rc}" -ne 0 ] && [ "${FAILURE_REASON}" = "smoke did not complete" ]; then
        FAILURE_REASON="body failed rc=${body_rc}"
    fi
    if [ "${BODY_SUCCEEDED}" = true ] && [ "${body_rc}" -eq 0 ] && [ "${#cleanup_errors[@]}" -eq 0 ]; then
        RESULT="pass"
        FAILURE_REASON=""
        final_rc=0
    elif [ "${#cleanup_errors[@]}" -gt 0 ]; then
        FAILURE_REASON="${FAILURE_REASON:-cleanup failed}; cleanup verification failed"
    fi
    if ! write_summary; then
        record_cleanup_error "write_summary failed"
        RESULT="fail"
        final_rc=1
        write_summary || echo "CLEANUP_ERROR: summary retry failed" >&2
    fi
    exit "${final_rc}"
}

need_command bpftool
need_command curl
need_command ip
need_command mount
need_command mountpoint
need_command ping
need_command python3
need_command sleep
need_command tc
need_command umount
[ -x "${ARIA_AGENT_BIN}" ] || die "ARIA_AGENT_BIN is not executable: ${ARIA_AGENT_BIN}"
[ -r "${EBPF_OBJECT}" ] || die "EBPF_OBJECT is not readable: ${EBPF_OBJECT}"
# A standalone fixture has no managed ports; zero managed ports is a failure
# in managed smoke, never a PASS.

derive_fixture_identity
select_http_addr
preflight_fixture
trap cleanup EXIT
mkdir -p "${WORK_DIR}"

create_netns_fixture
start_agent || die "agent did not become healthy"
if [ "${MODE}" = system ]; then
    start_system_mode
else
    start_tap_mode
fi
install_fixture_policy
assert_dual_tc_ready
assert_standalone_all_group_projection before-restart
run_observed_allowed_flow allowed
exercise_legacy_zero_compatibility
run_denied_flow denied
restart_healthy_pinned_runtime
assert_health_poll_degrades
assert_missing_tc_rejected
if [ "${TC_ATTACH_MODE}" = legacy ]; then
    recover_missing_legacy_tc_runtime
else
    recover_incomplete_pinned_runtime
fi
run_fragment_tracking_field_smoke
run_xdp_link_identity_field_smoke
run_ethertype_any_expansion_smoke

BODY_SUCCEEDED=true
FAILURE_REASON=""
echo "Standalone ${MODE} TC ACL smoke body passed; cleanup determines ${WORK_DIR}/summary.json"
