#!/usr/bin/env bash
set -euo pipefail

MODE="${MODE:-system}"
: "${ARIA_AGENT_BIN:?ARIA_AGENT_BIN is required}"
: "${EBPF_OBJECT:?EBPF_OBJECT is required}"
case "${MODE}" in system|tap) ;; *) echo "ERROR: MODE must be system or tap" >&2; exit 2 ;; esac
[ "${EUID}" -eq 0 ] || { echo "ERROR: root is required" >&2; exit 2; }

RUN_ID="${RUN_ID:-standalone-tc-acl-$(date +%Y%m%d%H%M%S)}"
WORK_DIR="${WORK_DIR:-/tmp/${RUN_ID}}"
NETNS="${NETNS:-aria-tc-${RUN_ID}}"
TC_HEALTH_WAIT_SECS="${TC_HEALTH_WAIT_SECS:-12}"
HTTP_ADDR="${HTTP_ADDR:-127.0.0.1:18080}"
HTTP="http://${HTTP_ADDR}"
HOST_IF="ariah-${RUN_ID:0:8}"
PEER_IF="ariap-${RUN_ID:0:8}"
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

INSTANCE=""
AGENT_PID=""
TC_INGRESS_LINK=""
TC_EGRESS_LINK=""
TC_INGRESS_PROG=""
TC_EGRESS_PROG=""
PRIVATE_BPFFS_MOUNTED=false
SYSTEM_STARTED=false
BODY_SUCCEEDED=false
RESULT="fail"
FAILURE_REASON="smoke did not complete"
DUAL_TC_READY=false
XDP_NEUTRAL=false
MISSING_TC_REJECTED=false
HEALTH_POLL_DEGRADED=false
cleanup_errors=()

die() {
    FAILURE_REASON="$*"
    echo "ERROR: $*" >&2
    exit 1
}

need_command() {
    command -v "$1" >/dev/null 2>&1 || die "missing command: $1"
}

record_cleanup_error() {
    cleanup_errors+=("$*")
    echo "CLEANUP_ERROR: $*" >&2
}

create_netns_fixture() {
    ip netns add "${NETNS}"
    ip link add "${HOST_IF}" type veth peer name "${PEER_IF}"
    ip link set "${PEER_IF}" netns "${NETNS}"
    ip addr add "${HOST_IP}/30" dev "${HOST_IF}"
    ip link set "${HOST_IF}" up
    ip netns exec "${NETNS}" ip addr add "${PEER_IP}/30" dev "${PEER_IF}"
    ip netns exec "${NETNS}" ip addr add "${DENIED_IP}/32" dev "${PEER_IF}"
    ip netns exec "${NETNS}" ip route add "${HOST_IP}/32" dev "${PEER_IF}" src "${DENIED_IP}"
    ip route add "${DENIED_IP}/32" dev "${HOST_IF}"
    ip netns exec "${NETNS}" ip link set lo up
    ip netns exec "${NETNS}" ip link set "${PEER_IF}" up
}

start_agent() {
    local auto_attach=false
    [ "${MODE}" = tap ] && auto_attach=true
    mkdir -p "${PIN_ROOT}" "${STATE_ROOT}"
    if ! mountpoint -q "${PIN_ROOT}"; then
        mount -t bpf bpf "${PIN_ROOT}"
        PRIVATE_BPFFS_MOUNTED=true
    fi
    cat >"${CONFIG_FILE}" <<EOF
mode = "standalone"
auto_attach = ${auto_attach}
ebpf_path = "${EBPF_OBJECT}"
pin_path = "${PIN_ROOT}"
state_path = "${STATE_ROOT}"
iface_pattern = "^${HOST_IF}$"
listen_addr = "${HTTP_ADDR}"
trace_backend = "legacy-map"
log_file_path = "${WORK_DIR}/agent.log"
EOF
    "${ARIA_AGENT_BIN}" --config "${CONFIG_FILE}" >"${WORK_DIR}/agent.stdout" 2>&1 &
    AGENT_PID=$!
    for _ in $(seq 1 100); do
        curl -fsS "${HTTP}/api/v1/health" >/dev/null && return 0
        kill -0 "${AGENT_PID}" 2>/dev/null || return 1
        sleep 0.1
    done
    return 1
}

start_system_mode() {
    curl --fail-with-body -sS -H 'Content-Type: application/json' \
        -d "{\"iface\":\"${HOST_IF}\",\"max_port_policies\":16384}" \
        "${HTTP}/api/v1/system/start" >"${WORK_DIR}/system-start.json"
    INSTANCE="system"
    SYSTEM_STARTED=true
    TC_INGRESS_LINK="${PIN_ROOT}/system/tc_ingress_link"
    TC_EGRESS_LINK="${PIN_ROOT}/system/tc_egress_link"
    TC_INGRESS_PROG="${PIN_ROOT}/system/tc_ingress"
    TC_EGRESS_PROG="${PIN_ROOT}/system/tc_egress"
}

start_tap_mode() {
    INSTANCE="${HOST_IF}"
    TC_INGRESS_LINK="${PIN_ROOT}/global-v2/${HOST_IF}_tc_ingress_link"
    TC_EGRESS_LINK="${PIN_ROOT}/global-v2/${HOST_IF}_tc_egress_link"
    TC_INGRESS_PROG="${PIN_ROOT}/global-v2/tc_ingress"
    TC_EGRESS_PROG="${PIN_ROOT}/global-v2/tc_egress"
    for _ in $(seq 1 100); do
        curl -fsS "${HTTP}/api/v1/instances" | \
            python3 -c 'import json,sys; n=sys.argv[1]; p=json.load(sys.stdin); raise SystemExit(0 if any(i["name"]==n for i in p["instances"]) else 1)' \
            "${INSTANCE}" && return 0
        sleep 0.1
    done
    return 1
}

install_fixture_policy() {
    curl --fail-with-body -sS -H 'Content-Type: application/json' \
        -d "{\"name\":\"peer\",\"cidr\":\"${PEER_IP}/32\"}" \
        "${HTTP}/api/v1/${INSTANCE}/groups" >/dev/null
    curl --fail-with-body -sS -H 'Content-Type: application/json' \
        -d "{\"name\":\"host\",\"cidr\":\"${HOST_IP}/32\"}" \
        "${HTTP}/api/v1/${INSTANCE}/groups" >/dev/null
    curl --fail-with-body -sS -H 'Content-Type: application/json' \
        -d "{\"name\":\"denied\",\"cidr\":\"${DENIED_IP}/32\"}" \
        "${HTTP}/api/v1/${INSTANCE}/groups" >/dev/null
    curl --fail-with-body -sS -H 'Content-Type: application/json' \
        -d '{"src_group":"peer","dst_group":"host","proto":"icmp","action":"allow","direction":"ingress","ports":null}' \
        "${HTTP}/api/v1/${INSTANCE}/policies" >/dev/null
    curl --fail-with-body -sS -H 'Content-Type: application/json' \
        -d '{"src_group":"host","dst_group":"peer","proto":"icmp","action":"allow","direction":"egress","ports":null}' \
        "${HTTP}/api/v1/${INSTANCE}/policies" >/dev/null
    curl --fail-with-body -sS -H 'Content-Type: application/json' \
        -d '{"src_group":"denied","dst_group":"host","proto":"icmp","action":"drop","direction":"ingress","ports":null}' \
        "${HTTP}/api/v1/${INSTANCE}/policies" >/dev/null
    curl --fail-with-body -sS -H 'Content-Type: application/json' \
        -d '{"src_group":"host","dst_group":"denied","proto":"icmp","action":"drop","direction":"egress","ports":null}' \
        "${HTTP}/api/v1/${INSTANCE}/policies" >/dev/null
    curl --fail-with-body -sS -H 'Content-Type: application/json' -X PUT \
        -d '{"conntrack":true,"monitoring":true,"acl":true,"qos":null,"mirror":null,"tcprt":null,"ssl":null}' \
        "${HTTP}/api/v1/${INSTANCE}/config" >/dev/null
    curl --fail-with-body -sS -X DELETE \
        "${HTTP}/api/v1/${INSTANCE}/conntrack" >"${WORK_DIR}/initial-conntrack-flush.json"
}

capture_links() {
    local label="${1:-links}"
    [ -e "${TC_INGRESS_LINK}" ] && bpftool -j link show pinned "${TC_INGRESS_LINK}" \
        >"${WORK_DIR}/${label}-tc-ingress-link.json"
    [ -e "${TC_EGRESS_LINK}" ] && bpftool -j link show pinned "${TC_EGRESS_LINK}" \
        >"${WORK_DIR}/${label}-tc-egress-link.json"
    bpftool -j prog show pinned "${TC_INGRESS_PROG}" \
        >"${WORK_DIR}/${label}-tc-ingress-prog.json"
    bpftool -j prog show pinned "${TC_EGRESS_PROG}" \
        >"${WORK_DIR}/${label}-tc-egress-prog.json"
    tc -j filter show dev "${HOST_IF}" ingress >"${WORK_DIR}/${label}-tc-ingress.json"
    tc -j filter show dev "${HOST_IF}" egress >"${WORK_DIR}/${label}-tc-egress.json"
    bpftool -j net show >"${WORK_DIR}/${label}-bpftool-net.json"
}

assert_dual_tc_ready() {
    [ -e "${TC_INGRESS_LINK}" ]
    [ -e "${TC_EGRESS_LINK}" ]
    capture_links dual-tc-ready
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
    curl -fsS "${HTTP}/api/v1/instances" | python3 -c '
import json,sys
name=sys.argv[1]
item=next(i for i in json.load(sys.stdin)["instances"] if i["name"]==name)
assert item["acl_ready"] is True,item
assert item["xdp_ready"] is True,item
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

run_allowed_flow() {
    local label="${1:-allowed}"
    ip netns exec "${NETNS}" ping -c "${ALLOWED_PACKETS}" -W 1 \
        -s "${PING_PAYLOAD_BYTES}" "${HOST_IP}" >"${WORK_DIR}/${label}-flow.log"
}

run_denied_flow() {
    local ingress_rc=0 egress_rc=0
    capture_acl_counters denied-before
    ip netns exec "${NETNS}" ping -I "${DENIED_IP}" -c "${DENIED_PACKETS}" \
        -W 1 -s "${PING_PAYLOAD_BYTES}" "${HOST_IP}" \
        >"${WORK_DIR}/denied-ingress-flow.log" 2>&1 || ingress_rc=$?
    ping -I "${HOST_IF}" -c "${DENIED_PACKETS}" -W 1 \
        -s "${PING_PAYLOAD_BYTES}" "${DENIED_IP}" \
        >"${WORK_DIR}/denied-egress-flow.log" 2>&1 || egress_rc=$?
    [ "${ingress_rc}" -ne 0 ] || return 1
    [ "${egress_rc}" -ne 0 ] || return 1
    capture_acl_counters denied-after
    python3 - "${WORK_DIR}/denied-before-conntrack.json" \
        "${WORK_DIR}/denied-after-conntrack.json" \
        "${WORK_DIR}/denied-before-rules.json" \
        "${WORK_DIR}/denied-after-rules.json" \
        "${DENIED_PACKETS}" "${PACKET_BYTES}" <<'PY'
import json,sys
before_ct=json.load(open(sys.argv[1],encoding="utf-8"))["connections"]
after_ct=json.load(open(sys.argv[2],encoding="utf-8"))["connections"]
assert before_ct==after_ct,(before_ct,after_ct)
before=json.load(open(sys.argv[3],encoding="utf-8"))["rules"]
after=json.load(open(sys.argv[4],encoding="utf-8"))["rules"]
packets=int(sys.argv[5]); packet_bytes=int(sys.argv[6])
def dropped(rows,direction,src,dst,field):
    return sum(int(row.get(field) or 0) for row in rows
               if row.get("direction")==direction and row.get("src_group")==src
               and row.get("dst_group")==dst and row.get("proto")=="icmp")
assert dropped(after,"ingress","denied","host","dropped_packets")-dropped(before,"ingress","denied","host","dropped_packets")==packets,(before,after)
assert dropped(after,"egress","host","denied","dropped_packets")-dropped(before,"egress","host","denied","dropped_packets")==packets,(before,after)
assert dropped(after,"ingress","denied","host","dropped_bytes")-dropped(before,"ingress","denied","host","dropped_bytes")==packets*packet_bytes,(before,after)
assert dropped(after,"egress","host","denied","dropped_bytes")-dropped(before,"egress","host","denied","dropped_bytes")==packets*packet_bytes,(before,after)
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
        "${packets}" "${PACKET_BYTES}" "${PEER_IP}" "${HOST_IP}" <<'PY'
import json,re,sys
before_ct=json.load(open(sys.argv[1],encoding="utf-8"))["connections"]
after_ct=json.load(open(sys.argv[2],encoding="utf-8"))["connections"]
before_rules=json.load(open(sys.argv[3],encoding="utf-8"))["rules"]
after_rules=json.load(open(sys.argv[4],encoding="utf-8"))["rules"]
before_metrics=open(sys.argv[5],encoding="utf-8").read().splitlines()
after_metrics=open(sys.argv[6],encoding="utf-8").read().splitlines()
packets=int(sys.argv[7]); packet_bytes=int(sys.argv[8]); peer=sys.argv[9]; host=sys.argv[10]
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
def xdp_total(lines):
    total=0
    for line in lines:
        if not line.startswith(("aria_ct_contract_packets_total{","aria_ct_contract_bytes_total{")):
            continue
        labels=dict(re.findall(r'(\w+)="([^"]*)"',line))
        if labels.get("hook")=="xdp":
            total += int(float(line.rsplit(None,1)[1]))
    return total
before_xdp=xdp_total(before_metrics); after_xdp=xdp_total(after_metrics)
assert after_xdp-before_xdp==0,(before_xdp,after_xdp)
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
    tap_id="$(bpftool -j map lookup pinned "${PIN_ROOT}/global-v2/IFACE_CTX_MAP" \
        key hex ${ifindex_key} | python3 -c 'import json,struct,sys; v=json.load(sys.stdin)["value"]; print(struct.unpack("=I",bytes(v[:4]))[0])')"
    key="$(python3 -c 'import struct,sys; print(" ".join("%02x"%b for b in struct.pack("=I",int(sys.argv[1]))))' "${tap_id}")"
    bpftool -j map lookup pinned "${map}" key hex ${key} >"${WORK_DIR}/tap-config-original.json"
    value="$(python3 - "${WORK_DIR}/tap-config-original.json" <<'PY'
import json,sys
v=json.load(open(sys.argv[1],encoding="utf-8"))["value"]
assert len(v)==8,v
v[7]=0
print(" ".join("%02x"%b for b in v))
PY
    )"
    bpftool map update pinned "${map}" key hex ${key} value hex ${value}
    capture_acl_counters legacy-zero-before
    run_allowed_flow legacy-zero
    capture_acl_counters legacy-zero-after
    assert_xdp_neutral legacy-zero-before legacy-zero-after "${ALLOWED_PACKETS}"
    curl --fail-with-body -sS -H 'Content-Type: application/json' -X PUT \
        -d '{"conntrack":true,"monitoring":true,"acl":true,"qos":null,"mirror":null,"tcprt":null,"ssl":null}' \
        "${HTTP}/api/v1/${INSTANCE}/config" >/dev/null
    bpftool -j map lookup pinned "${map}" key hex ${key} | python3 -c '
import json,sys
value=json.load(sys.stdin)["value"]
assert len(value)==8 and value[7]==1,value
'
}

assert_health_poll_degrades() {
    local lost_link="${TC_EGRESS_LINK}"
    bpftool link detach pinned "${lost_link}"
    [ -e "${lost_link}" ]
    bpftool -j link show pinned "${lost_link}" >"${WORK_DIR}/detached-but-pinned-link.json"
    sleep "${TC_HEALTH_WAIT_SECS}"
    curl -fsS "${HTTP}/api/v1/instances" >"${WORK_DIR}/health-degraded-instances.json"
    curl -fsS "${HTTP}/api/v1/${INSTANCE}/config" >"${WORK_DIR}/health-degraded-config.json"
    python3 - "${WORK_DIR}/health-degraded-instances.json" \
        "${WORK_DIR}/health-degraded-config.json" "${INSTANCE}" <<'PY'
import json,sys
item=next(i for i in json.load(open(sys.argv[1],encoding="utf-8"))["instances"] if i["name"]==sys.argv[3])
config=json.load(open(sys.argv[2],encoding="utf-8"))
assert item["acl_ready"] is False,item
assert item["xdp_ready"] is True,item
assert item.get("readiness_reason")=="missing_tc_egress",item
assert config["acl"] is False,config
assert config["conntrack"] is False,config
PY
    HEALTH_POLL_DEGRADED=true
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

restore_runtime_after_tc_loss() {
    if [ -n "${AGENT_PID}" ] && kill -0 "${AGENT_PID}" 2>/dev/null; then
        kill "${AGENT_PID}"
        wait "${AGENT_PID}" || true
        AGENT_PID=""
    fi
    if mountpoint -q "${PIN_ROOT}"; then
        umount "${PIN_ROOT}"
        PRIVATE_BPFFS_MOUNTED=false
    fi
    rm -rf "${PIN_ROOT}"
    start_agent || die "agent restart failed after detached TCX link"
    if [ "${MODE}" = system ]; then
        SYSTEM_STARTED=false
        start_system_mode
    else
        start_tap_mode
    fi
    assert_dual_tc_ready
}

verify_cleanup() {
    if [ -n "${AGENT_PID}" ] && kill -0 "${AGENT_PID}" 2>/dev/null; then
        return 1
    fi
    mountpoint -q "${PIN_ROOT}" && return 1
    ip netns list | awk '{print $1}' | grep -Fx "${NETNS}" >/dev/null && return 1
    ip link show dev "${HOST_IF}" >/dev/null 2>&1 && return 1
    tc qdisc show dev "${HOST_IF}" >/dev/null 2>&1 && return 1
    [ ! -e "${PIN_ROOT}" ] || return 1
    return 0
}

write_summary() {
    printf '%s\n' "${cleanup_errors[@]:-}" >"${WORK_DIR}/cleanup-errors.txt" || return 1
    MODE="${MODE}" RESULT="${RESULT}" FAILURE_REASON="${FAILURE_REASON}" \
    WORK_DIR="${WORK_DIR}" DUAL_TC_READY="${DUAL_TC_READY}" \
    XDP_NEUTRAL="${XDP_NEUTRAL}" MISSING_TC_REJECTED="${MISSING_TC_REJECTED}" \
    HEALTH_POLL_DEGRADED="${HEALTH_POLL_DEGRADED}" \
        python3 >"${WORK_DIR}/summary.json.tmp" <<'PY' || return 1
import json,os
cleanup_errors=[line.rstrip("\n") for line in open(os.path.join(os.environ["WORK_DIR"],"cleanup-errors.txt"),encoding="utf-8") if line.rstrip("\n")]
out={"mode":os.environ["MODE"],"dual_tc_ready":os.environ["DUAL_TC_READY"].lower()=="true",
     "xdp_neutral":os.environ["XDP_NEUTRAL"].lower()=="true",
     "missing_tc_rejected":os.environ["MISSING_TC_REJECTED"].lower()=="true",
     "health_poll_degraded":os.environ["HEALTH_POLL_DEGRADED"].lower()=="true",
     "cleanup_errors":cleanup_errors,"result":os.environ["RESULT"],
     "failure_reason":os.environ["FAILURE_REASON"],"work_dir":os.environ["WORK_DIR"]}
print(json.dumps(out,sort_keys=True,indent=2))
PY
    mv "${WORK_DIR}/summary.json.tmp" "${WORK_DIR}/summary.json" || return 1
}

cleanup() {
    local body_rc=$? final_rc=1
    trap - EXIT
    set +e
    if [ "${MODE}" = system ] && [ "${SYSTEM_STARTED}" = true ]; then
        if ! curl --fail-with-body -sS -X POST "${HTTP}/api/v1/system/stop" >"${WORK_DIR}/cleanup-system-stop.json" 2>&1; then
            record_cleanup_error "system stop failed"
        fi
        SYSTEM_STARTED=false
    fi
    if [ -n "${AGENT_PID}" ] && kill -0 "${AGENT_PID}" 2>/dev/null; then
        kill "${AGENT_PID}"
        if ! wait "${AGENT_PID}"; then
            record_cleanup_error "agent wait failed"
        fi
    fi
    AGENT_PID=""
    if mountpoint -q "${PIN_ROOT}"; then
        if ! umount "${PIN_ROOT}"; then
            record_cleanup_error "private bpffs unmount failed"
        fi
    fi
    PRIVATE_BPFFS_MOUNTED=false
    rm -rf "${PIN_ROOT}" || record_cleanup_error "temporary pin root removal failed"
    if ip netns list | awk '{print $1}' | grep -Fx "${NETNS}" >/dev/null; then
        ip netns del "${NETNS}" || record_cleanup_error "network namespace removal failed"
    fi
    if ip link show dev "${HOST_IF}" >/dev/null 2>&1; then
        ip link del "${HOST_IF}" || record_cleanup_error "fixture veth removal failed"
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

trap cleanup EXIT
mkdir -p "${WORK_DIR}"

need_command bpftool
need_command curl
need_command ip
need_command mount
need_command mountpoint
need_command ping
need_command python3
need_command tc
need_command umount
[ -x "${ARIA_AGENT_BIN}" ] || die "ARIA_AGENT_BIN is not executable: ${ARIA_AGENT_BIN}"
[ -r "${EBPF_OBJECT}" ] || die "EBPF_OBJECT is not readable: ${EBPF_OBJECT}"

create_netns_fixture
start_agent || die "agent did not become healthy"
if [ "${MODE}" = system ]; then
    start_system_mode
else
    start_tap_mode
fi
install_fixture_policy
assert_dual_tc_ready
capture_acl_counters allowed-before
run_allowed_flow
capture_acl_counters allowed-after
assert_xdp_neutral allowed-before allowed-after "${ALLOWED_PACKETS}"
exercise_legacy_zero_compatibility
run_denied_flow
assert_health_poll_degrades
assert_missing_tc_rejected
restore_runtime_after_tc_loss

BODY_SUCCEEDED=true
FAILURE_REASON=""
echo "Standalone ${MODE} TC ACL smoke body passed; cleanup determines ${WORK_DIR}/summary.json"
