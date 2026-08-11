#!/usr/bin/env bash
set -euo pipefail

DATAPATH_HTTP="${DATAPATH_HTTP:-http://127.0.0.1:8080}"
WORK_DIR="${WORK_DIR:-/tmp/neutron-aria-acl-tc-$(date +%Y%m%d%H%M%S)-$(hostname -s)}"
TRAFFIC_PACKETS="${TRAFFIC_PACKETS:-12}"
MIN_HIT_PACKETS="${MIN_HIT_PACKETS:-8}"
: "${EXPECTED_IFNAME:?EXPECTED_IFNAME is required}"
: "${VM_IP:?VM_IP is required}"
mkdir -p "${WORK_DIR}"

SERVICE_NAME="${SERVICE_NAME:-neutron_aria_agent}"
EXEC_USER="${EXEC_USER:-neutron}"
ADMIN_RC_FILE="${ADMIN_RC_FILE:-/etc/kolla/.adminrc}"
LOCAL_NEUTRON_URL="${LOCAL_NEUTRON_URL:-http://127.0.0.1:9696/v2.0}"
NEUTRON_UDS="${NEUTRON_UDS:-/run/aria/aria-agent.sock}"
PIN_ROOT="${PIN_ROOT:-/sys/fs/bpf/aria/global-v2}"
AGENT_CONFIG="${AGENT_CONFIG:-/etc/neutron-aria-agent/neutron-aria-agent.ini}"
NEUTRON_CONFIG_FILE="${NEUTRON_CONFIG_FILE:-/etc/neutron/neutron.conf}"
OVS_AGENT_CONFIG_FILE="${OVS_AGENT_CONFIG_FILE:-/etc/neutron/plugins/ml2/openvswitch_agent.ini}"
EXPECTED_PORT_ID="${EXPECTED_PORT_ID:-}"
PING_PAYLOAD_BYTES="${PING_PAYLOAD_BYTES:-56}"
RUN_ID="${RUN_ID:-acl-tc-datapath-$(date +%Y%m%d%H%M%S)-$(hostname -s)}"
DATAPATH_SERVICE_NAME="${DATAPATH_SERVICE_NAME:-aria_datapath}"
DATAPATH_LOG_FILE="${DATAPATH_LOG_FILE:-}"
RESYNC_QUIET_SAMPLES="${RESYNC_QUIET_SAMPLES:-5}"
RESYNC_QUIET_ATTEMPTS="${RESYNC_QUIET_ATTEMPTS:-60}"
FRAGMENT_TRACKING_SMOKE="${FRAGMENT_TRACKING_SMOKE:-0}"
FRAGMENT_DRIVER="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../smoke/lib" 2>/dev/null && pwd)/fragment_tracking_field_driver.py"
FRAGMENT_PEER_NETNS="${FRAGMENT_PEER_NETNS:-}"
FRAGMENT_PEER_IFNAME="${FRAGMENT_PEER_IFNAME:-}"
FRAGMENT_IPV4_HOST="${FRAGMENT_IPV4_HOST:-}"
FRAGMENT_IPV4_PEER="${FRAGMENT_IPV4_PEER:-}"
FRAGMENT_IPV6_HOST="${FRAGMENT_IPV6_HOST:-}"
FRAGMENT_IPV6_PEER="${FRAGMENT_IPV6_PEER:-}"
FRAGMENT_VLAN_A="${FRAGMENT_VLAN_A:-}"
FRAGMENT_VLAN_B="${FRAGMENT_VLAN_B:-}"
FRAGMENT_HOST_VLAN_A_IFNAME="${FRAGMENT_HOST_VLAN_A_IFNAME:-}"
FRAGMENT_PEER_VLAN_A_IFNAME="${FRAGMENT_PEER_VLAN_A_IFNAME:-}"
FRAGMENT_HOST_VLAN_B_IFNAME="${FRAGMENT_HOST_VLAN_B_IFNAME:-}"
FRAGMENT_PEER_VLAN_B_IFNAME="${FRAGMENT_PEER_VLAN_B_IFNAME:-}"
FRAGMENT_EXPECTED_CAPACITY="${FRAGMENT_EXPECTED_CAPACITY:-8192}"

ACL_INGRESS_HOOK_TC=1
TRACE_FILTER="controlled_icmp_flow"
XDP_NO_ACL_CT=false
TC_INGRESS_HIT=false
TC_EGRESS_HIT=false
STATELESS_ZERO_CT=false
NO_INGRESS_DOUBLE_COUNT=false
TC_LINK_REQUIRED=false
BANK_REVALIDATED=false
DENY_ZERO_CT=false
RESULT="fail"
BODY_SUCCEEDED=false
BASELINE_CAPTURED=false
RESYNC_ROLLBACK_ARMED=false
TRACE_ARMED=false
FAILURE_REASON="smoke did not complete"
TOKEN=""
policy_id=""
binding_id=""
rule_ids=()
created_rule_ids=()
cleanup_errors=()
PING_ARGS=()
ACL_SELECTOR_CIDR=""
MORE_SPECIFIC_CIDR=""
LEGACY_POLLUTION_GROUP_CIDR="${LEGACY_POLLUTION_GROUP_CIDR:-192.0.2.1/32}"
EXACT_LOCAL_GROUP_NAME="${RUN_ID}-exact-local"
MORE_SPECIFIC_GROUP_NAME="${RUN_ID}-more-specific-local"
LEGACY_LOCAL_GROUP_NAME="${RUN_ID}-legacy-local"
exact_local_group_id=""
more_specific_group_id=""
legacy_local_group_id=""
semantic_delta_rule_id=""
selector_rule_id=""
selector_group_id=""
selector_local_group_ids=()
SELECTOR_FIXTURES_STARTED=false
LEGACY_POLLUTION_INJECTED=false
EXACT_SELECTOR_FIXTURE_STATUS="not_run"
MORE_SPECIFIC_SELECTOR_FIXTURE_STATUS="not_run"
LEGACY_SELECTOR_REPAIR_FIXTURE_STATUS="not_run"
SELECTOR_FIXTURE_SCOPE="${SELECTOR_FIXTURE_SCOPE:-all}"
LEGACY_RESTART_REPAIR_GATE="not_run"
LEGACY_REPAIR_MODE="not_run"
TC_ATTACHMENT_MODE="unknown"
FRAGMENT_BODY_SUCCEEDED=false
FRAGMENT_TRANSITIONS_VERIFIED=false

IP_FAMILY=""
IP_FAMILY_LABEL=""
ACL_PROTOCOL=""
TRACE_PROTOCOL=""
CT_PROTOCOL=""
METRIC_FAMILY=""
SOURCE_IP=""

egress_miss_delta=0
egress_hit_delta=0
ingress_hit_delta=0
packet_delta=0
byte_delta=0
rule_packet_delta=0
bank_stale_delta=0
bank_miss_delta=0
bank_hit_delta=0
stateless_hit_delta=0
stateless_disabled_delta=0
deny_drop_delta=0

die() {
    FAILURE_REASON="$*"
    echo "ERROR: $*" >&2
    exit 1
}

need_command() {
    command -v "$1" >/dev/null 2>&1 || die "missing command: $1"
}

capture_tc_filter() {
    local direction="$1" output="$2" temporary error_file
    temporary="${output}.tmp"
    error_file="${output}.err"
    if tc -j filter show dev "${EXPECTED_IFNAME}" "${direction}" \
            >"${temporary}" 2>"${error_file}" && \
            python3 -m json.tool "${temporary}" >/dev/null 2>&1; then
        mv "${temporary}" "${output}"
        return
    fi
    rm -f "${temporary}"
    tc filter show dev "${EXPECTED_IFNAME}" "${direction}" | python3 -c '
import json,sys
rows=[]
for line in sys.stdin:
    line=line.rstrip()
    if line:
        rows.append({"kind":"bpf" if " bpf " in (" "+line+" ") else "raw","raw":line})
print(json.dumps(rows))
' >"${output}"
}

assert_tc_attachment_ready() {
    local ingress_link="${PIN_ROOT}/${EXPECTED_IFNAME}_tc_ingress_link"
    local egress_link="${PIN_ROOT}/${EXPECTED_IFNAME}_tc_egress_link"
    if [ -e "${ingress_link}" ] && [ -e "${egress_link}" ]; then
        printf '{"mode":"tcx","legacy_tc":false}\n'
        return
    fi
    if [ -e "${ingress_link}" ] || [ -e "${egress_link}" ]; then
        die "mixed TC attachment state for ${EXPECTED_IFNAME}"
    fi
    capture_tc_filter ingress "${WORK_DIR}/tc-attachment-ingress.json"
    capture_tc_filter egress "${WORK_DIR}/tc-attachment-egress.json"
    bpftool -j prog show pinned "${PIN_ROOT}/tc_ingress" \
        >"${WORK_DIR}/tc-attachment-ingress-prog.json"
    bpftool -j prog show pinned "${PIN_ROOT}/tc_egress" \
        >"${WORK_DIR}/tc-attachment-egress-prog.json"
    python3 - "${WORK_DIR}" <<'PY'
import json,os,sys
root=sys.argv[1]
for direction in ("ingress","egress"):
    filters=json.load(open(os.path.join(root,"tc-attachment-%s.json"%direction),encoding="utf-8"))
    program=json.load(open(os.path.join(root,"tc-attachment-%s-prog.json"%direction),encoding="utf-8"))
    if isinstance(program,list):
        assert len(program)==1,program
        program=program[0]
    rendered=json.dumps(filters,sort_keys=True).lower()
    assert "tc_%s"%direction in rendered,(direction,filters)
    assert str(program.get("tag") or "").lower() in rendered,(direction,program,filters)
print(json.dumps({"mode":"legacy","legacy_tc": True},sort_keys=True))
PY
}

record_cleanup_error() {
    cleanup_errors+=("$*")
    echo "CLEANUP_ERROR: $*" >&2
}

json_field() {
    python3 -c 'import json,sys
value=json.load(sys.stdin)
for part in sys.argv[1].split("."):
    value=value.get(part) if isinstance(value,dict) else None
print("" if value is None else value)' "$1"
}

curl_body() {
    local method="$1" path="$2" data="${3:-}"
    if [ -n "${data}" ]; then
        curl --fail -sS -H "X-Auth-Token: ${TOKEN}" \
            -H 'Content-Type: application/json' -X "${method}" -d "${data}" \
            "${LOCAL_NEUTRON_URL}/${path}"
    else
        curl --fail -sS -H "X-Auth-Token: ${TOKEN}" \
            -X "${method}" "${LOCAL_NEUTRON_URL}/${path}"
    fi
}

datapath_get() {
    curl --fail -sS "${DATAPATH_HTTP}$1"
}

uds_get() {
    local endpoint="$1"
    docker exec -i -u "${EXEC_USER}" "${SERVICE_NAME}" \
        python - "${NEUTRON_UDS}" "${endpoint}" <<'PY'
from __future__ import print_function

import socket
import sys

socket_path, endpoint = sys.argv[1:3]
client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
client.settimeout(5.0)
client.connect(socket_path)
request = "GET %s HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n" % endpoint
if sys.version_info[0] >= 3:
    request = request.encode("ascii")
client.sendall(request)
chunks = []
while True:
    chunk = client.recv(65536)
    if not chunk:
        break
    chunks.append(chunk)
client.close()
response = b"".join(chunks)
headers, body = response.split(b"\r\n\r\n", 1)
status_code = int(headers.split(b"\r\n", 1)[0].split()[1])
if status_code < 200 or status_code >= 300:
    if sys.version_info[0] >= 3:
        body = body.decode("utf-8", "replace")
    sys.stderr.write(body)
    raise SystemExit(22)
if sys.version_info[0] >= 3:
    body = body.decode("utf-8")
sys.stdout.write(body)
PY
}

wait_resync_quiesced() {
    local attempt payload generation previous_generation="" stable_samples=0
    for attempt in $(seq 1 "${RESYNC_QUIET_ATTEMPTS}"); do
        payload="${WORK_DIR}/resync-quiesce-${attempt}-$(date +%s%N).json"
        generation=""
        if uds_get /api/v1/neutron/status >"${payload}" 2>/dev/null; then
            generation="$(python3 - "${payload}" <<'PY'
import json,sys
status=json.load(open(sys.argv[1],encoding="utf-8"))
generation=status.get("generation")
values=(status.get("last_classified_generation"),status.get("accepted_generation"),
        status.get("applied_generation"))
ready=(status.get("overall_readiness")=="ready" and
       status.get("pending_generation") is None and
       generation is not None and all(value==generation for value in values))
if ready:
    print(generation)
PY
            )"
        fi
        if [ -n "${generation}" ]; then
            if [ "${generation}" = "${previous_generation}" ]; then
                stable_samples=$((stable_samples + 1))
            else
                previous_generation="${generation}"
                stable_samples=1
            fi
            if [ "${stable_samples}" -ge "${RESYNC_QUIET_SAMPLES}" ]; then
                echo "resync quiesced at generation ${generation}"
                return 0
            fi
        else
            previous_generation=""
            stable_samples=0
        fi
        sleep 1
    done
    echo "resync did not quiesce after ${RESYNC_QUIET_ATTEMPTS} attempts" >&2
    return 1
}

run_full_resync() {
    local attempt_id stdout_file stderr_file rc
    wait_resync_quiesced || return 1
    attempt_id="$(date +%s%N)"
    stdout_file="${WORK_DIR}/full-resync-${attempt_id}.stdout"
    stderr_file="${WORK_DIR}/full-resync-${attempt_id}.stderr"
    set +e
    docker exec -u "${EXEC_USER}" "${SERVICE_NAME}" neutron-aria-agent \
        --config-file "${AGENT_CONFIG}" \
        --neutron-config-file "${NEUTRON_CONFIG_FILE}" \
        --neutron-config-file "${OVS_AGENT_CONFIG_FILE}" \
        --once --enable-full-resync \
        >"${stdout_file}" 2>"${stderr_file}"
    rc=$?
    set -e
    cat "${stdout_file}"
    if [ "${rc}" -ne 0 ]; then
        printf 'full-resync failed rc=%s stdout=%s stderr=%s\n' \
            "${rc}" "${stdout_file}" "${stderr_file}" >&2
        cat "${stderr_file}" >&2
    fi
    return "${rc}"
}

set_trace_filter() {
    local src_ip="$1" dst_ip="$2" body
    body="$(printf '{"src_ip":"%s","dst_ip":"%s","src_port":0,"dst_port":0,"proto":"%s"}' \
        "${src_ip}" "${dst_ip}" "${TRACE_PROTOCOL}")"
    curl --fail -sS -H 'Content-Type: application/json' \
        -X POST -d "${body}" "${DATAPATH_HTTP}/api/v1/${EXPECTED_IFNAME}/trace" \
        >"${WORK_DIR}/trace-filter-$(date +%s%N).json"
    TRACE_ARMED=true
}

stop_trace_filter() {
    [ "${TRACE_ARMED}" = true ] || return 0
    curl --fail -sS -X DELETE \
        "${DATAPATH_HTTP}/api/v1/${EXPECTED_IFNAME}/trace" \
        >"${WORK_DIR}/trace-filter-stop-$(date +%s%N).json"
    TRACE_ARMED=false
}

metric_sum() {
    local file="$1" hook="$2" reason="$3"
    local family="$4"
    python3 - "${file}" "${EXPECTED_IFNAME}" "${hook}" "${reason}" "${family}" <<'PY'
import re,sys
path,instance,hook,reason,family=sys.argv[1:]
total=0
for line in open(path,encoding="utf-8"):
    if not line.startswith("aria_ct_contract_packets_total{"):
        continue
    labels=dict(re.findall(r'(\w+)="([^"]*)"',line))
    if (labels.get("instance")==instance and labels.get("hook")==hook and
            labels.get("reason")==reason and labels.get("family")==family):
        total += int(float(line.rsplit(None,1)[1]))
print(total)
PY
}

flow_conntrack_totals() {
    local file="$1"
    python3 - "${file}" "${SOURCE_IP}" "${VM_IP}" "${CT_PROTOCOL}" "${IP_FAMILY}" <<'PY'
import ipaddress,json,sys
path,source_ip,vm_ip,protocol,ip_family=sys.argv[1:]
version=4 if ip_family=="ipv4" else 6
source_ip=str(ipaddress.ip_address(source_ip))
vm_ip=str(ipaddress.ip_address(vm_ip))
rows=[]
for row in json.load(open(path,encoding="utf-8")).get("connections") or []:
    try:
        src=str(ipaddress.ip_address(row.get("src_ip")))
        dst=str(ipaddress.ip_address(row.get("dst_ip")))
    except ValueError:
        continue
    if ipaddress.ip_address(src).version != version or ipaddress.ip_address(dst).version != version:
        continue
    # The authoritative entry may have been created in forward or reverse orientation.
    forward=(src==source_ip and dst==vm_ip)
    reverse=(src==vm_ip and dst==source_ip)
    if not (forward or reverse):
        continue
    if str(row.get("proto")) != protocol:
        continue
    if int(row.get("src_port") or 0) != 0 or int(row.get("dst_port") or 0) != 0:
        continue
    rows.append(row)
print(len(rows),sum(int(x.get("packets") or 0) for x in rows),
      sum(int(x.get("bytes") or 0) for x in rows))
PY
}

rule_counter_sum() {
    local file="$1" direction="$2" packets_field="$3"
    python3 - "${file}" "${direction}" "${CT_PROTOCOL}" "${packets_field}" <<'PY'
import json,sys
path,direction,protocol,packets_field=sys.argv[1:]
total=0
for row in json.load(open(path,encoding="utf-8")).get("rules") or []:
    if row.get("direction")==direction and str(row.get("proto"))==protocol:
        total += int(row.get(packets_field) or 0)
print(total)
PY
}

assert_port_enforced() {
    local payload="$1"
    python3 - "${payload}" "${EXPECTED_PORT_ID}" "${EXPECTED_IFNAME}" \
        "${binding_id}" "${policy_id}" <<'PY'
import json,sys
p=json.load(open(sys.argv[1],encoding="utf-8"))
port_id,ifname,binding_id,policy_id=sys.argv[2:]
rows=p.get("aria_acl_port_statuses") or p.get("port_statuses") or []
row=next((r for r in rows if r.get("port_id")==port_id),None)
assert row is not None,(port_id,rows)
if row.get("ifname") is not None:
    assert row.get("ifname")==ifname,row
assert row.get("status") in ("ready","enforced"),row
assert row.get("binding_id")==binding_id,row
assert row.get("effective_policy_id")==policy_id,row
action=row.get("effective_action")
if action is None:
    action=next((d for d in row.get("domains",[]) if d.get("domain")=="acl"),{}).get("effective_action")
assert action in ("enforce","enforced"),row
PY
}

wait_port_enforced() {
    local i payload runtime_payload
    for i in $(seq 1 30); do
        payload="${WORK_DIR}/wait-port-enforced-${i}.json"
        runtime_payload="${WORK_DIR}/wait-port-enforced-${i}-runtime.json"
        curl_body GET aria-acl-port-statuses >"${payload}"
        if assert_port_enforced "${payload}" 2>"${WORK_DIR}/wait-port-enforced-${i}.err" &&
           datapath_get "/api/v1/${EXPECTED_IFNAME}/config" >"${runtime_payload}" &&
           python3 - "${runtime_payload}" 2>"${WORK_DIR}/wait-port-enforced-${i}-runtime.err" <<'PY'
import json,sys
runtime=json.load(open(sys.argv[1],encoding="utf-8"))
assert runtime.get("acl") is True,runtime
PY
        then
            return 0
        fi
        sleep 1
    done
    return 1
}

capture_runtime_compatibility() {
    local label="$1" ifindex key_hex tap_id config_hex
    ifindex="$(cat "/sys/class/net/${EXPECTED_IFNAME}/ifindex")" || return 1
    key_hex="$(python3 - "${ifindex}" <<'PY'
import struct,sys
print(" ".join("%02x"%b for b in struct.pack("=I",int(sys.argv[1]))))
PY
    )" || return 1
    bpftool -j map lookup pinned "${PIN_ROOT}/IFACE_CTX_MAP" key hex ${key_hex} \
        >"${WORK_DIR}/${label}-iface-ctx.json" || return 1
    tap_id="$(python3 - "${WORK_DIR}/${label}-iface-ctx.json" <<'PY'
import json,struct,sys
def decode_bpftool_bytes(values):
    return bytes(int(value,16) if isinstance(value,str) else value for value in values)
v=json.load(open(sys.argv[1]))["value"]
print(struct.unpack("=I",decode_bpftool_bytes(v[:4]))[0])
PY
    )" || return 1
    config_hex="$(python3 - "${tap_id}" <<'PY'
import struct,sys
print(" ".join("%02x"%b for b in struct.pack("=I",int(sys.argv[1]))))
PY
    )" || return 1
    bpftool -j map lookup pinned "${PIN_ROOT}/TAP_CONFIG_MAP" key hex ${config_hex} \
        >"${WORK_DIR}/${label}-tap-config.json" || return 1
    python3 - "${WORK_DIR}/${label}-tap-config.json" "${ACL_INGRESS_HOOK_TC}" <<'PY'
import json,sys
def decode_bpftool_int(value):
    return int(value,0) if isinstance(value,str) else int(value)
v=json.load(open(sys.argv[1]))["value"]
assert len(v)==8,v
assert decode_bpftool_int(v[7])==int(sys.argv[2]),{"compatibility_byte":v[7],"expected":int(sys.argv[2])}
print(decode_bpftool_int(v[6]),decode_bpftool_int(v[7]))
PY
}

capture() {
    local label="$1" net_rc=0
    datapath_get /api/v1/instances >"${WORK_DIR}/${label}-instances.json" || return 1
    datapath_get "/api/v1/${EXPECTED_IFNAME}/config" >"${WORK_DIR}/${label}-config.json" || return 1
    datapath_get "/api/v1/${EXPECTED_IFNAME}/conntrack" >"${WORK_DIR}/${label}-conntrack.json" || return 1
    datapath_get "/api/v1/${EXPECTED_IFNAME}/stats/rules" >"${WORK_DIR}/${label}-rules.json" || return 1
    datapath_get /metrics >"${WORK_DIR}/${label}-metrics.prom" || return 1
    uds_get /api/v1/neutron/status >"${WORK_DIR}/${label}-neutron-status.json" || return 1
    curl_body GET aria-acl-port-statuses >"${WORK_DIR}/${label}-port-status.json" || return 1
    ip -details link show dev "${EXPECTED_IFNAME}" >"${WORK_DIR}/${label}-link.txt" || return 1
    capture_tc_filter ingress "${WORK_DIR}/${label}-tc-ingress.json" || return 1
    capture_tc_filter egress "${WORK_DIR}/${label}-tc-egress.json" || return 1
    bpftool -j net show >"${WORK_DIR}/${label}-bpftool-net.json" \
        2>"${WORK_DIR}/${label}-bpftool-net.err" || net_rc=$?
    printf '{"available":%s,"exit_code":%s}\n' \
        "$([ "${net_rc}" -eq 0 ] && printf true || printf false)" "${net_rc}" \
        >"${WORK_DIR}/${label}-bpftool-net-status.json"
    bpftool -j map dump pinned "${PIN_ROOT}/CT_CONTRACT_STATS" \
        >"${WORK_DIR}/${label}-ct-contract-map.json" || return 1
    capture_runtime_compatibility "${label}" >"${WORK_DIR}/${label}-runtime-compatibility.txt" || return 1
}

run_controlled_traffic() {
    local label="$1" count="$2" expectation="$3" rc=0
    ping "${PING_ARGS[@]}" -c "${count}" -W 1 -s "${PING_PAYLOAD_BYTES}" "${VM_IP}" \
        >"${WORK_DIR}/${label}-traffic.log" 2>&1 || rc=$?
    if [ "${expectation}" = pass ] && [ "${rc}" -ne 0 ]; then
        die "${label} controlled traffic failed rc=${rc}"
    fi
    if [ "${expectation}" = deny ] && [ "${rc}" -eq 0 ]; then
        die "${label} controlled traffic unexpectedly passed"
    fi
}

run_observed_flow() {
    local label="$1" trace_src="$2" trace_dst="$3" count="$4" expectation="$5"
    set_trace_filter "${trace_src}" "${trace_dst}"
    capture "${label}-before"
    run_controlled_traffic "${label}" "${count}" "${expectation}"
    capture "${label}-after"
}

create_rule() {
    local direction="$1" action="$2" protocol="${3:-${ACL_PROTOCOL}}" priority="${4:-100}" body id
    body="$(printf '{"aria_acl_rule":{"policy_id":"%s","direction":"%s","priority":%s,"action":"%s","protocol":"%s"}}' \
        "${policy_id}" "${direction}" "${priority}" "${action}" "${protocol}")"
    id="$(curl_body POST aria-acl-rules "${body}" | tee "${WORK_DIR}/rule-${direction}-${action}-${protocol}-$(date +%s%N).json" | json_field aria_acl_rule.id)"
    [ -n "${id}" ] || die "failed to create ${direction} ${action} rule"
    rule_ids+=("${id}")
    created_rule_ids+=("${id}")
}

delete_rules_for_transition() {
    local id output
    for id in "${rule_ids[@]:-}"; do
        [ -n "${id}" ] || continue
        output="${WORK_DIR}/transition-delete-rule-${id}.txt"
        if ! curl_body DELETE "aria-acl-rules/${id}" >"${output}" 2>&1; then
            die "failed to delete transition rule ${id}; see ${output}"
        fi
    done
    rule_ids=()
}

update_policy_stateful() {
    local value="$1" body
    body="$(printf '{"aria_acl_policy":{"stateful":%s}}' "${value}")"
    curl_body PUT "aria-acl-policies/${policy_id}" "${body}" \
        >"${WORK_DIR}/policy-stateful-${value}.json"
}

assert_stateful_evidence() {
    local expected_per_batch expected_total initial_count initial_packets initial_bytes first_count first_packets first_bytes final_count egress_rule_before egress_rule_after ingress_rule_before ingress_rule_after
    egress_miss_delta=$(( $(metric_sum "${WORK_DIR}/stateful-egress-after-metrics.prom" tc_egress ct_miss "${METRIC_FAMILY}") - $(metric_sum "${WORK_DIR}/stateful-egress-before-metrics.prom" tc_egress ct_miss "${METRIC_FAMILY}") ))
    egress_hit_delta=$(( $(metric_sum "${WORK_DIR}/stateful-egress-after-metrics.prom" tc_egress ct_hit "${METRIC_FAMILY}") - $(metric_sum "${WORK_DIR}/stateful-egress-before-metrics.prom" tc_egress ct_hit "${METRIC_FAMILY}") ))
    ingress_hit_delta=$(( $(metric_sum "${WORK_DIR}/stateful-ingress-after-metrics.prom" tc_ingress ct_hit "${METRIC_FAMILY}") - $(metric_sum "${WORK_DIR}/stateful-ingress-before-metrics.prom" tc_ingress ct_hit "${METRIC_FAMILY}") ))
    [ "${egress_miss_delta}" -ge 1 ] || die "stateful egress did not record controlled ct_miss"
    [ "${egress_hit_delta}" -ge "${MIN_HIT_PACKETS}" ] || die "stateful egress hit delta too small"
    [ "${ingress_hit_delta}" -ge "${MIN_HIT_PACKETS}" ] || die "stateful ingress hit delta too small"

    expected_per_batch=$((TRAFFIC_PACKETS * 2))
    expected_total=$((expected_per_batch * 2))
    read -r initial_count initial_packets initial_bytes < <(flow_conntrack_totals "${WORK_DIR}/stateful-ready-conntrack.json")
    read -r first_count first_packets first_bytes < <(flow_conntrack_totals "${WORK_DIR}/stateful-egress-after-conntrack.json")
    read -r final_count packet_delta byte_delta < <(flow_conntrack_totals "${WORK_DIR}/stateful-ingress-after-conntrack.json")
    [ "${initial_count}" -eq 0 ] && [ "${initial_packets}" -eq 0 ] && [ "${initial_bytes}" -eq 0 ] || die "stateful transition did not start with zero controlled-flow CT"
    [ "${first_count}" -eq 1 ] && [ "${first_packets}" -eq "${expected_per_batch}" ] || die "first controlled batch has duplicate CT observations"
    [ "${first_bytes}" -gt 0 ] && [ $((first_bytes % expected_per_batch)) -eq 0 ] || die "first controlled batch CT byte observations are inconsistent"
    [ "${final_count}" -eq 1 ] && [ "${packet_delta}" -eq "${expected_total}" ] || die "NO_INGRESS_DOUBLE_COUNT expected flow packets=${expected_total}, got ${packet_delta}"
    [ "${byte_delta}" -eq $((first_bytes * 2)) ] || die "controlled CT byte observations are not exactly one TC observation per packet"

    egress_rule_before="$(rule_counter_sum "${WORK_DIR}/stateful-egress-before-rules.json" egress packets)"
    egress_rule_after="$(rule_counter_sum "${WORK_DIR}/stateful-ingress-after-rules.json" egress packets)"
    ingress_rule_before="$(rule_counter_sum "${WORK_DIR}/stateful-egress-before-rules.json" ingress packets)"
    ingress_rule_after="$(rule_counter_sum "${WORK_DIR}/stateful-ingress-after-rules.json" ingress packets)"
    rule_packet_delta=$((egress_rule_after - egress_rule_before + ingress_rule_after - ingress_rule_before))
    [ "${rule_packet_delta}" -eq "${expected_total}" ] || die "XDP_NO_ACL_CT ACL rule delta ${rule_packet_delta} != authoritative TC observations ${expected_total}"
    [ $((ingress_rule_after - ingress_rule_before)) -eq 0 ] || die "XDP_NO_ACL_CT found duplicate ingress ACL accounting"

    TC_EGRESS_HIT=true
    TC_INGRESS_HIT=true
    NO_INGRESS_DOUBLE_COUNT=true
    XDP_NO_ACL_CT=true
}

run_stateful_evidence() {
    run_full_resync | tee "${WORK_DIR}/stateful-full-resync.log"
    wait_port_enforced || die "managed port did not report ready/enforce"
    capture stateful-ready
    run_observed_flow stateful-egress "${SOURCE_IP}" "${VM_IP}" "${TRAFFIC_PACKETS}" pass
    run_observed_flow stateful-ingress "${VM_IP}" "${SOURCE_IP}" "${TRAFFIC_PACKETS}" pass
    assert_stateful_evidence
}

assert_bank_evidence() {
    local old_bank new_bank reference_ct_count reference_ct_packets reference_ct_bytes pre_resync_ct_count pre_resync_ct_packets pre_resync_ct_bytes before_ct_count before_ct_packets before_ct_bytes ct_count ct_packets ct_bytes rule_before rule_after expected
    old_bank="$(awk '{print $1}' "${WORK_DIR}/bank-pre-resync-runtime-compatibility.txt")"
    new_bank="$(awk '{print $1}' "${WORK_DIR}/bank-before-runtime-compatibility.txt")"
    [ "${new_bank}" != "${old_bank}" ] || die "ACL bank did not transition"
    bank_stale_delta=$(( $(metric_sum "${WORK_DIR}/bank-after-metrics.prom" tc_egress stale_bank "${METRIC_FAMILY}") - $(metric_sum "${WORK_DIR}/bank-before-metrics.prom" tc_egress stale_bank "${METRIC_FAMILY}") ))
    bank_miss_delta=$(( $(metric_sum "${WORK_DIR}/bank-after-metrics.prom" tc_egress ct_miss "${METRIC_FAMILY}") - $(metric_sum "${WORK_DIR}/bank-before-metrics.prom" tc_egress ct_miss "${METRIC_FAMILY}") ))
    bank_hit_delta=$(( $(metric_sum "${WORK_DIR}/bank-after-metrics.prom" tc_egress ct_hit "${METRIC_FAMILY}") - $(metric_sum "${WORK_DIR}/bank-before-metrics.prom" tc_egress ct_hit "${METRIC_FAMILY}") ))
    [ "${bank_miss_delta}" -ge 1 ] || die "controlled bank-transition flow did not miss after strict CT flush"
    [ "${bank_hit_delta}" -ge "${MIN_HIT_PACKETS}" ] || die "controlled bank-transition flow did not return to hits"
    read -r reference_ct_count reference_ct_packets reference_ct_bytes < <(flow_conntrack_totals "${WORK_DIR}/stateful-egress-after-conntrack.json")
    read -r pre_resync_ct_count pre_resync_ct_packets pre_resync_ct_bytes < <(flow_conntrack_totals "${WORK_DIR}/bank-pre-resync-conntrack.json")
    read -r before_ct_count before_ct_packets before_ct_bytes < <(flow_conntrack_totals "${WORK_DIR}/bank-before-conntrack.json")
    read -r ct_count ct_packets ct_bytes < <(flow_conntrack_totals "${WORK_DIR}/bank-after-conntrack.json")
    expected=$((TRAFFIC_PACKETS * 2))
    [ "${reference_ct_count}" -eq 1 ] && [ "${reference_ct_packets}" -eq "${expected}" ] && [ "${reference_ct_bytes}" -gt 0 ] || die "stateful first batch did not provide an exact byte reference for bank traffic"
    [ "${pre_resync_ct_count}" -eq 1 ] && [ "${pre_resync_ct_packets}" -gt 0 ] && [ "${pre_resync_ct_bytes}" -gt 0 ] || die "bank transition did not capture the live controlled-flow CT before resync"
    [ "${before_ct_count}" -eq 0 ] && [ "${before_ct_packets}" -eq 0 ] && [ "${before_ct_bytes}" -eq 0 ] || die "Neutron strict CT flush did not clear the controlled flow before bank traffic"
    [ "${ct_count}" -eq 1 ] && [ "${ct_packets}" -eq "${expected}" ] && [ "${ct_bytes}" -eq "${reference_ct_bytes}" ] || die "bank flow was not recreated after strict flush with exact controlled-flow packet/byte counters"
    rule_before="$(rule_counter_sum "${WORK_DIR}/bank-before-rules.json" egress packets)"
    rule_after="$(rule_counter_sum "${WORK_DIR}/bank-after-rules.json" egress packets)"
    [ $((rule_after - rule_before)) -eq "${expected}" ] || die "bank ACL rule evidence does not match controlled TC observations"
    BANK_REVALIDATED=true
}

run_bank_evidence() {
    run_full_resync | tee "${WORK_DIR}/bank-full-resync.log"
    run_observed_flow bank "${SOURCE_IP}" "${VM_IP}" "${TRAFFIC_PACKETS}" pass
    assert_bank_evidence
}

assert_stateless_evidence() {
    local ct_count ct_packets ct_bytes egress_before egress_after ingress_before ingress_after
    read -r ct_count ct_packets ct_bytes < <(flow_conntrack_totals "${WORK_DIR}/stateless-after-conntrack.json")
    stateless_hit_delta=$(( $(metric_sum "${WORK_DIR}/stateless-after-metrics.prom" tc_egress ct_hit "${METRIC_FAMILY}") - $(metric_sum "${WORK_DIR}/stateless-before-metrics.prom" tc_egress ct_hit "${METRIC_FAMILY}") ))
    stateless_disabled_delta=$(( $(metric_sum "${WORK_DIR}/stateless-after-metrics.prom" tc_egress ct_disabled "${METRIC_FAMILY}") - $(metric_sum "${WORK_DIR}/stateless-before-metrics.prom" tc_egress ct_disabled "${METRIC_FAMILY}") ))
    [ "${ct_count}" -eq 0 ] && [ "${ct_packets}" -eq 0 ] && [ "${ct_bytes}" -eq 0 ] || die "STATELESS_ZERO_CT controlled flow retained CT"
    [ "${stateless_hit_delta}" -eq 0 ] && [ "${stateless_disabled_delta}" -ge "${TRAFFIC_PACKETS}" ] || die "stateless CT contract evidence is invalid"
    egress_before="$(rule_counter_sum "${WORK_DIR}/stateless-before-rules.json" egress packets)"
    egress_after="$(rule_counter_sum "${WORK_DIR}/stateless-after-rules.json" egress packets)"
    ingress_before="$(rule_counter_sum "${WORK_DIR}/stateless-before-rules.json" ingress packets)"
    ingress_after="$(rule_counter_sum "${WORK_DIR}/stateless-after-rules.json" ingress packets)"
    [ $((egress_after - egress_before)) -eq "${TRAFFIC_PACKETS}" ] || die "stateless egress ACL count is not one per controlled packet"
    [ $((ingress_after - ingress_before)) -eq "${TRAFFIC_PACKETS}" ] || die "stateless ingress ACL count is not one per controlled reply"
    STATELESS_ZERO_CT=true
}

run_stateless_evidence() {
    run_full_resync | tee "${WORK_DIR}/stateless-full-resync.log"
    run_observed_flow stateless "${SOURCE_IP}" "${VM_IP}" "${TRAFFIC_PACKETS}" pass
    assert_stateless_evidence
}

assert_deny_evidence() {
    local ct_count ct_packets ct_bytes drop_before drop_after deny_packets=2
    read -r ct_count ct_packets ct_bytes < <(flow_conntrack_totals "${WORK_DIR}/deny-after-conntrack.json")
    [ "${ct_count}" -eq 0 ] && [ "${ct_packets}" -eq 0 ] && [ "${ct_bytes}" -eq 0 ] || die "deny ACL created controlled-flow CT"
    drop_before="$(rule_counter_sum "${WORK_DIR}/deny-before-rules.json" egress dropped_packets)"
    drop_after="$(rule_counter_sum "${WORK_DIR}/deny-after-rules.json" egress dropped_packets)"
    deny_drop_delta=$((drop_after - drop_before))
    [ "${deny_drop_delta}" -eq "${deny_packets}" ] || die "deny ACL drop counter ${deny_drop_delta} != controlled packets ${deny_packets}"
    DENY_ZERO_CT=true
}

run_deny_evidence() {
    run_full_resync | tee "${WORK_DIR}/deny-full-resync.log"
    run_observed_flow deny "${SOURCE_IP}" "${VM_IP}" 2 deny
    assert_deny_evidence
}

prepare_owned_selector_fixture() {
    local selector_rule_body selector_rule_receipt created_selector_rule_id
    [ "${IP_FAMILY}" = ipv4 ] || return 0
    delete_rules_for_transition || return 1
    read -r ACL_SELECTOR_CIDR MORE_SPECIFIC_CIDR < <(
        python3 - "${SOURCE_IP}" <<'PY'
import ipaddress,sys
source=ipaddress.ip_address(sys.argv[1])
assert source.version==4,source
selector=ipaddress.ip_network("%s/24" % source,strict=False)
print(selector,"%s/32" % source)
PY
    ) || return 1
    selector_rule_body="{\"aria_acl_rule\":{\"policy_id\":\"${policy_id}\",\"direction\":\"ingress\",\"priority\":100,\"action\":\"drop\",\"protocol\":\"${CT_PROTOCOL}\",\"src_cidr\":\"${ACL_SELECTOR_CIDR}\"}}"
    selector_rule_receipt="${WORK_DIR}/selector-rule-create-attempt.json"
    printf '%s\n' "${selector_rule_body}" >"${selector_rule_receipt}.tmp" || return 1
    mv "${selector_rule_receipt}.tmp" "${selector_rule_receipt}" || return 1
    created_selector_rule_id="$(curl_body POST aria-acl-rules "${selector_rule_body}" | json_field aria_acl_rule.id)" || return 1
    [ -n "${created_selector_rule_id}" ] || return 1
    selector_rule_id="${created_selector_rule_id}"
    rule_ids+=("${selector_rule_id}")
    created_rule_ids+=("${selector_rule_id}")
    rm -f "${selector_rule_receipt}" || return 1
}

cleanup_selector_rule_attempt() {
    local attempt_file expected_body receipt_body lookup_file matched
    attempt_file="${WORK_DIR}/selector-rule-create-attempt.json"
    [ -f "${attempt_file}" ] || return 0
    expected_body="{\"aria_acl_rule\":{\"policy_id\":\"${policy_id}\",\"direction\":\"ingress\",\"priority\":100,\"action\":\"drop\",\"protocol\":\"${CT_PROTOCOL}\",\"src_cidr\":\"${ACL_SELECTOR_CIDR}\"}}"
    IFS= read -r receipt_body <"${attempt_file}" || return 1
    [ "${receipt_body}" = "${expected_body}" ] || return 1
    if [ -n "${selector_rule_id}" ]; then
        rm -f "${attempt_file}" || return 1
        return 0
    fi
    lookup_file="${WORK_DIR}/selector-rule-cleanup-rules.json"
    curl_body GET aria-acl-rules >"${lookup_file}" || return 1
    matched="$(python3 - "${lookup_file}" "${policy_id}" "${ACL_SELECTOR_CIDR}" "${CT_PROTOCOL}" <<'PY'
import ipaddress,json,sys
rows=json.load(open(sys.argv[1],encoding="utf-8")).get("aria_acl_rules") or []
target=str(ipaddress.ip_network(sys.argv[3],strict=False))
matches=[row for row in rows if row.get("policy_id")==sys.argv[2] and row.get("direction")=="ingress" and row.get("priority")==100 and row.get("action")=="drop" and str(row.get("protocol"))==sys.argv[4] and str(ipaddress.ip_network(row.get("src_cidr"),strict=False))==target]
assert len(matches)<=1,matches
print(matches[0]["id"] if matches else "")
PY
    )" || return 1
    if [ -n "${matched}" ]; then
        curl_body DELETE "aria-acl-rules/${matched}" \
            >"${WORK_DIR}/selector-rule-cleanup-delete.json" || return 1
    fi
    rm -f "${attempt_file}" || return 1
}

capture_selector_projection() {
    local label="$1"
    capture "${label}" || return 1
    datapath_get "/api/v1/${EXPECTED_IFNAME}/groups" >"${WORK_DIR}/${label}-groups.json" || return 1
    datapath_get "/api/v1/${EXPECTED_IFNAME}/policies" >"${WORK_DIR}/${label}-policies.json" || return 1
    curl_body GET aria-acl-rules >"${WORK_DIR}/${label}-neutron-rules.json" || return 1
    bpftool -j map dump pinned "${PIN_ROOT}/SRC_IPV4_TRIE" >"${WORK_DIR}/${label}-general-src-map.json" || return 1
    bpftool -j map dump pinned "${PIN_ROOT}/DST_IPV4_TRIE" >"${WORK_DIR}/${label}-general-dst-map.json" || return 1
    bpftool -j map dump pinned "${PIN_ROOT}/ACL_SRC_IPV4_TRIE" >"${WORK_DIR}/${label}-acl-src-map.json" || return 1
    bpftool -j map dump pinned "${PIN_ROOT}/ACL_DST_IPV4_TRIE" >"${WORK_DIR}/${label}-acl-dst-map.json" || return 1
}

run_unchecked_selector_traffic() {
    local label="$1" count="$2"
    command ping "${PING_ARGS[@]}" -c "${count}" -W 1 -s "${PING_PAYLOAD_BYTES}" "${VM_IP}" \
        >"${WORK_DIR}/${label}-traffic.log" 2>&1
}

assert_selector_traffic_result() {
    python3 - "$2" "$3" <<'PY'
import sys
traffic_rc_raw,expectation_raw=sys.argv[1:]
traffic_rc=int(traffic_rc_raw)
expectation=expectation_raw
expected_pass=(expectation=="pass")
actual_pass=(traffic_rc==0)
assert expectation in ("pass","deny")
assert actual_pass is expected_pass
PY
}

run_captured_selector_flow() {
    local label="$1" count="$2" expectation="$3" traffic_rc
    capture_selector_projection "${label}-before"
    if run_unchecked_selector_traffic "${label}" "${count}"; then
        traffic_rc=0
    else
        traffic_rc=$?
    fi
    printf '%s\n' "${traffic_rc}" >"${WORK_DIR}/${label}-traffic-rc.txt"
    capture_selector_projection "${label}-after"
    assert_selector_traffic_result "${label}" "${traffic_rc}" "${expectation}"
}

reverify_selector_deny_baseline() {
    local label="$1"
    run_full_resync >"${WORK_DIR}/${label}-full-resync.log"
    wait_port_enforced
    run_captured_selector_flow "${label}-deny" 2 deny
    assert_selector_deny_drop_ct_zero "${label}-deny"
}

resolve_selector_group_id() {
    python3 - "${WORK_DIR}/$1-groups.json" "${WORK_DIR}/$1-policies.json" \
        "${ACL_SELECTOR_CIDR}" "${CT_PROTOCOL}" <<'PY'
import ipaddress,json,sys
groups=json.load(open(sys.argv[1],encoding="utf-8"))["groups"]
policies=json.load(open(sys.argv[2],encoding="utf-8"))["policies"]
selector=str(ipaddress.ip_network(sys.argv[3],strict=False)); protocol=sys.argv[4]
group_ids={int(row["id"]) for row in groups if selector in {
    str(ipaddress.ip_network(cidr,strict=False)) for cidr in row.get("cidrs") or []}}
candidates={int(row["src_group_id"]) for row in policies
            if row.get("direction")=="egress" and row.get("action")=="drop"
            and str(row.get("proto"))==protocol and int(row.get("src_group_id") or 0) in group_ids}
assert len(candidates)==1,(groups,policies,selector,protocol)
print(candidates.pop())
PY
}

create_selector_fixture_group() {
    local attempted_name="$1" attempted_cidr="$2" precheck receipt response
    precheck="${WORK_DIR}/selector-group-precheck-${attempted_name}.json"
    receipt="${WORK_DIR}/selector-group-create-attempt-${attempted_name}.txt"
    response="${WORK_DIR}/selector-group-create-response-${attempted_name}.json"
    case "${attempted_name}" in "${RUN_ID}"-*-local) ;; *) return 1 ;; esac
    datapath_get "/api/v1/${EXPECTED_IFNAME}/groups" >"${precheck}" || return 1
    python3 - "${precheck}" "${attempted_name}" <<'PY' || return 1
import json,sys
rows=json.load(open(sys.argv[1],encoding="utf-8"))["groups"]
matches=[row for row in rows if row.get("name")==sys.argv[2]]
assert len(matches)==0,matches
PY
    printf '%s|%s\n' "${attempted_name}" "${attempted_cidr}" >"${receipt}.tmp" || return 1
    mv "${receipt}.tmp" "${receipt}" || return 1
    command curl --fail -sS -H 'Content-Type: application/json' -X POST \
        -d "{\"name\":\"${attempted_name}\",\"cidr\":\"${attempted_cidr}\"}" \
        "${DATAPATH_HTTP}/api/v1/${EXPECTED_IFNAME}/groups" >"${response}" || return 1
    python3 - "${response}" <<'PY' || return 1
import json,sys
group_id=json.load(open(sys.argv[1],encoding="utf-8")).get("id")
assert isinstance(group_id,int) and group_id>0,group_id
print(group_id)
PY
}

delete_selector_fixture_group() {
    local attempted_name="$1" receipt
    receipt="${WORK_DIR}/selector-group-create-attempt-${attempted_name}.txt"
    [ -f "${receipt}" ] || return 1
    command curl --fail -sS -X DELETE \
        "${DATAPATH_HTTP}/api/v1/${EXPECTED_IFNAME}/groups/${attempted_name}" || return 1
    rm -f "${receipt}" || return 1
}

cleanup_selector_group_attempt() {
    local requested_name="$1" attempted_name attempted_cidr payload receipt present
    receipt="${WORK_DIR}/selector-group-create-attempt-${requested_name}.txt"
    [ -f "${receipt}" ] || return 0
    IFS='|' read -r attempted_name attempted_cidr <"${receipt}" || return 1
    [ "${attempted_name}" = "${requested_name}" ] || return 1
    case "${attempted_name}" in "${RUN_ID}"-*-local) ;; *) return 1 ;; esac
    payload="${WORK_DIR}/selector-group-cleanup-${attempted_name}.json"
    datapath_get "/api/v1/${EXPECTED_IFNAME}/groups" >"${payload}" || return 1
    present="$(python3 - "${payload}" "${attempted_name}" "${attempted_cidr}" <<'PY'
import json,sys
attempted_name=sys.argv[2]
rows=json.load(open(sys.argv[1],encoding="utf-8"))["groups"]
matches=[row for row in rows if row.get("name")==attempted_name]
assert len(matches)<=1,matches
if matches:
    cidrs={str(value) for value in matches[0].get("cidrs") or []}
    assert sys.argv[3] in cidrs,(matches[0],sys.argv[3])
print("present" if matches else "absent")
PY
    )" || return 1
    if [ "${present}" = present ]; then
        command curl --fail -sS -X DELETE \
            "${DATAPATH_HTTP}/api/v1/${EXPECTED_IFNAME}/groups/${attempted_name}" || return 1
    fi
    rm -f "${receipt}" || return 1
}

require_wider_owned_selector() {
    python3 - "${ACL_SELECTOR_CIDR}" "${SOURCE_IP}" <<'PY'
import ipaddress,sys
selector=ipaddress.ip_network(sys.argv[1],strict=False)
source=ipaddress.ip_address(sys.argv[2])
assert source in selector
assert selector.version==4
assert selector.prefixlen<32
PY
}

apply_owned_acl_semantic_delta() {
    local body existing lookup_file attempt_file response_file
    body="{\"aria_acl_rule\":{\"policy_id\":\"${policy_id}\",\"direction\":\"ingress\",\"priority\":200,\"action\":\"allow\",\"protocol\":\"tcp\",\"src_cidr\":\"${ACL_SELECTOR_CIDR}\"}}"
    lookup_file="${WORK_DIR}/semantic-delta-before-create-rules.json"
    attempt_file="${WORK_DIR}/semantic-delta-create-attempt.json"
    curl_body GET aria-acl-rules >"${lookup_file}" || return 1
    existing="$(python3 - "${lookup_file}" "${policy_id}" "${ACL_SELECTOR_CIDR}" <<'PY'
import ipaddress,json,sys
rows=json.load(open(sys.argv[1],encoding="utf-8")).get("aria_acl_rules") or []
target=str(ipaddress.ip_network(sys.argv[3],strict=False))
matches=[row for row in rows if row.get("policy_id")==sys.argv[2] and row.get("direction")=="ingress" and row.get("priority")==200 and row.get("action")=="allow" and row.get("protocol")=="tcp" and str(ipaddress.ip_network(row.get("src_cidr"),strict=False))==target]
assert len(matches)<=1,matches
print(matches[0]["id"] if matches else "")
PY
    )" || return 1
    [ -z "${existing}" ] || return 1
    printf '%s\n' "${body}" >"${attempt_file}.tmp" || return 1
    mv "${attempt_file}.tmp" "${attempt_file}" || return 1
    response_file="${WORK_DIR}/semantic-delta-create-response.json"
    curl_body POST aria-acl-rules "${body}" >"${response_file}" || return 1
    semantic_delta_rule_id="$(python3 - "${response_file}" <<'PY'
import json,sys
rule_id=(json.load(open(sys.argv[1],encoding="utf-8")).get("aria_acl_rule") or {}).get("id")
assert rule_id,rule_id
print(rule_id)
PY
    )" || return 1
}

remove_owned_acl_semantic_delta() {
    local matched lookup_file attempt_file expected_body receipt_body
    lookup_file="${WORK_DIR}/semantic-delta-cleanup-rules.json"
    attempt_file="${WORK_DIR}/semantic-delta-create-attempt.json"
    [ -f "${attempt_file}" ] || return 0
    expected_body="{\"aria_acl_rule\":{\"policy_id\":\"${policy_id}\",\"direction\":\"ingress\",\"priority\":200,\"action\":\"allow\",\"protocol\":\"tcp\",\"src_cidr\":\"${ACL_SELECTOR_CIDR}\"}}"
    IFS= read -r receipt_body <"${attempt_file}" || return 1
    [ "${receipt_body}" = "${expected_body}" ] || return 1
    curl_body GET aria-acl-rules >"${lookup_file}" || return 1
    matched="$(python3 - "${lookup_file}" "${policy_id}" "${ACL_SELECTOR_CIDR}" <<'PY'
import ipaddress,json,sys
rows=json.load(open(sys.argv[1],encoding="utf-8")).get("aria_acl_rules") or []
target=str(ipaddress.ip_network(sys.argv[3],strict=False))
matches=[row for row in rows if row.get("policy_id")==sys.argv[2] and row.get("direction")=="ingress" and row.get("priority")==200 and row.get("action")=="allow" and row.get("protocol")=="tcp" and str(ipaddress.ip_network(row.get("src_cidr"),strict=False))==target]
assert len(matches)<=1,matches
print(matches[0]["id"] if matches else "")
PY
    )" || return 1
    if [ -n "${matched}" ]; then
        curl_body DELETE "aria-acl-rules/${matched}" \
            >"${WORK_DIR}/semantic-delta-delete-response.json" || return 1
    fi
    rm -f "${attempt_file}" || return 1
}

assert_selector_deny_drop_ct_zero() {
    local label="$1" ct_count ct_packets ct_bytes drop_before drop_after
    read -r ct_count ct_packets ct_bytes < <(
        flow_conntrack_totals "${WORK_DIR}/${label}-after-conntrack.json"
    )
    drop_before="$(rule_counter_sum "${WORK_DIR}/${label}-before-rules.json" egress dropped_packets)"
    drop_after="$(rule_counter_sum "${WORK_DIR}/${label}-after-rules.json" egress dropped_packets)"
    [ "${ct_count}" -eq 0 ]
    [ "${ct_packets}" -eq 0 ]
    [ "${ct_bytes}" -eq 0 ]
    [ "${drop_after}" -gt "${drop_before}" ]
}

assert_exact_selector_state() {
    python3 - "${WORK_DIR}" "${ACL_SELECTOR_CIDR}" "${selector_group_id}" \
        "${exact_local_group_id}" <<'PY'
import ipaddress,json,os,struct,sys
def decode_bpftool_bytes(values):
    return bytes(int(value,16) if isinstance(value,str) else value for value in values)
root,selector_cidr,selector_group_id,local_group_id=sys.argv[1:]
selector_cidr=str(ipaddress.ip_network(selector_cidr,strict=False))
selector_group_id=int(selector_group_id); local_group_id=int(local_group_id)
def load(name):
    return json.load(open(os.path.join(root,name),encoding="utf-8"))
def bank(label):
    return int(open(os.path.join(root,label+"-runtime-compatibility.txt"),encoding="utf-8").read().split()[0])
def tap_id(label):
    value=load(label+"-iface-ctx.json")["value"]
    return struct.unpack("=I",decode_bpftool_bytes(value[:4]))[0]
def entries(label,kind,scope):
    out={}
    for row in load(label+"-"+kind+"-map.json"):
        key=decode_bpftool_bytes(row["key"]); value=decode_bpftool_bytes(row["value"])
        prefix=struct.unpack("=I",key[:4])[0]-32
        if int.from_bytes(key[4:8],"big") != scope:
            continue
        network=str(ipaddress.ip_network(
            "%s/%d" % (ipaddress.IPv4Address(key[8:12]),prefix),strict=False))
        out[network]=struct.unpack("=I",value[:4])[0]
    return out
exact_before_bank=bank("exact-before")
exact_after_bank=bank("exact-local")
exact_before_groups=load("exact-before-groups.json")["groups"]
exact_after_groups=load("exact-local-groups.json")["groups"]
tap=tap_id("exact-local")
exact_before_general=entries("exact-before","general-src",tap)
exact_after_general=entries("exact-local","general-src",tap)
exact_before_acl_entries=entries("exact-before","acl-src",tap*2+exact_before_bank)
exact_acl_entries=entries("exact-local","acl-src",tap*2+exact_after_bank)
exact_acl_ids=set(exact_acl_entries.values())
exact_cleanup_general_entries=entries("exact-cleanup","general-src",tap)
exact_cleanup_general_ids=set(exact_cleanup_general_entries.values())
assert exact_before_bank==exact_after_bank
assert exact_before_groups!=exact_after_groups
assert exact_before_general!=exact_after_general
assert exact_before_acl_entries==exact_acl_entries
assert exact_after_general[selector_cidr]==local_group_id
assert exact_acl_entries[selector_cidr]==selector_group_id
assert selector_group_id in exact_acl_ids
assert local_group_id not in exact_acl_ids
assert exact_cleanup_general_entries[selector_cidr]==selector_group_id
assert selector_group_id in exact_cleanup_general_ids
assert local_group_id not in exact_cleanup_general_ids
PY
}

assert_more_specific_selector_state() {
    python3 - "${WORK_DIR}" "${ACL_SELECTOR_CIDR}" "${MORE_SPECIFIC_CIDR}" \
        "${selector_group_id}" "${more_specific_group_id}" <<'PY'
import ipaddress,json,os,struct,sys
def decode_bpftool_bytes(values):
    return bytes(int(value,16) if isinstance(value,str) else value for value in values)
root,selector_cidr,more_specific_key,selector_group_id,more_specific_group_id=sys.argv[1:]
selector_cidr=str(ipaddress.ip_network(selector_cidr,strict=False))
more_specific_key=str(ipaddress.ip_network(more_specific_key,strict=False))
selector_group_id=int(selector_group_id); more_specific_group_id=int(more_specific_group_id)
def load(name):
    return json.load(open(os.path.join(root,name),encoding="utf-8"))
def bank(label):
    return int(open(os.path.join(root,label+"-runtime-compatibility.txt"),encoding="utf-8").read().split()[0])
def tap_id(label):
    return struct.unpack("=I",decode_bpftool_bytes(load(label+"-iface-ctx.json")["value"][:4]))[0]
def entries(label,kind,scope):
    out={}
    for row in load(label+"-"+kind+"-map.json"):
        key=decode_bpftool_bytes(row["key"]); value=decode_bpftool_bytes(row["value"])
        prefix=struct.unpack("=I",key[:4])[0]-32
        if int.from_bytes(key[4:8],"big") != scope:
            continue
        network=str(ipaddress.ip_network(
            "%s/%d" % (ipaddress.IPv4Address(key[8:12]),prefix),strict=False))
        out[network]=struct.unpack("=I",value[:4])[0]
    return out
old_bank=bank("more-specific-before-delta")
new_bank=bank("more-specific-after-delta")
tap=tap_id("more-specific-after-delta")
new_general_entries=entries("more-specific-after-delta","general-src",tap)
new_acl_entries=entries("more-specific-after-delta","acl-src",tap*2+new_bank)
new_general_ids=set(new_general_entries.values())
new_acl_ids=set(new_acl_entries.values())
new_acl_keys=set(new_acl_entries)
assert old_bank!=new_bank
assert new_general_entries[more_specific_key]==more_specific_group_id
assert more_specific_group_id in new_general_ids
assert more_specific_key not in new_acl_keys
assert more_specific_group_id not in new_acl_ids
assert new_acl_entries[selector_cidr]==selector_group_id
assert selector_group_id in new_acl_ids
PY
}

inject_legacy_selector_pollution() {
    local active_selector_key_hex legacy_local_group_id_hex injection_rc
    IFS='|' read -r active_selector_key_hex legacy_local_group_id_hex < <(
        python3 - "${WORK_DIR}/legacy-before-pollution-iface-ctx.json" \
            "${WORK_DIR}/legacy-before-pollution-runtime-compatibility.txt" \
            "${ACL_SELECTOR_CIDR}" "${legacy_local_group_id}" <<'PY'
import ipaddress,json,struct,sys
def decode_bpftool_bytes(values):
    return bytes(int(value,16) if isinstance(value,str) else value for value in values)
iface=json.load(open(sys.argv[1],encoding="utf-8"))
tap_id=struct.unpack("=I",decode_bpftool_bytes(iface["value"][:4]))[0]
bank=int(open(sys.argv[2],encoding="utf-8").read().split()[0])
network=ipaddress.ip_network(sys.argv[3],strict=False)
lpm_tap_id=tap_id*2+bank
key=struct.pack("=I",32+network.prefixlen)+lpm_tap_id.to_bytes(4,"big")+network.network_address.packed
value=struct.pack("=I",int(sys.argv[4]))
print(" ".join("%02x" % byte for byte in key)+"|"+
      " ".join("%02x" % byte for byte in value))
PY
    )
    if command bpftool map update pinned "${PIN_ROOT}/ACL_SRC_IPV4_TRIE" \
        key hex ${active_selector_key_hex} value hex ${legacy_local_group_id_hex}; then
        injection_rc=0
    else
        injection_rc=$?
    fi
    printf '%s\n' "${injection_rc}" >"${WORK_DIR}/legacy-pollution-map-update-rc.txt"
    [ "${injection_rc}" -eq 0 ]
    LEGACY_POLLUTION_INJECTED=true
}

wait_neutron_uds() {
    local attempt
    for attempt in $(seq 1 45); do
        if uds_get /api/v1/neutron/status \
            >"${WORK_DIR}/restart-uds-${attempt}.json" 2>/dev/null; then
            return 0
        fi
        command sleep 1 || return 1
    done
    return 1
}

wait_managed_port_reattached() {
    local expected_phase="$1" attempt payload instances_payload
    for attempt in $(seq 1 45); do
        payload="${WORK_DIR}/restart-reattach-${attempt}.json"
        instances_payload="${WORK_DIR}/restart-reattach-${attempt}-instances.json"
        if ! uds_get /api/v1/neutron/status >"${payload}"; then
            command sleep 1 || return 1
            continue
        fi
        if ! command curl --fail -sS \
            "${DATAPATH_HTTP}/api/v1/instances" >"${instances_payload}"; then
            command sleep 1 || return 1
            continue
        fi
        if python3 - "${payload}" "${instances_payload}" "${EXPECTED_PORT_ID}" \
            "${EXPECTED_IFNAME}" "${expected_phase}" \
            2>"${WORK_DIR}/restart-reattach-${attempt}.assert.err" <<'PY'
import json,sys
payload=json.load(open(sys.argv[1],encoding="utf-8"))
instances=json.load(open(sys.argv[2],encoding="utf-8"))
port_id,ifname,expected_phase=sys.argv[3:]
active_matches=[value for value in payload.get("active_instances") or [] if value==ifname]
managed_matches=[row for row in payload.get("managed_ports") or []
                 if row.get("port_id")==port_id and row.get("ifname")==ifname]
instance_matches=[row for row in instances.get("instances") or []
                  if row.get("name")==ifname]
assert len(active_matches)==1,(ifname,active_matches,payload)
assert len(managed_matches)==1,(port_id,ifname,managed_matches)
assert len(instance_matches)==1,(ifname,instance_matches)
item=instance_matches[0]
assert item.get("active") is True,item
assert expected_phase in ("recovery_required","ready","active"),expected_phase
if expected_phase=="recovery_required":
    assert item.get("acl_ready") is False,item
    assert item.get("readiness_reason")=="recovery_required",item
elif expected_phase=="ready":
    assert item.get("acl_ready") is True,item
    assert item.get("readiness_reason") in (None,"xdp_ddos_hook_unavailable"),item
PY
        then
            return 0
        fi
        command sleep 1 || return 1
    done
    return 1
}

wait_baseline_inventory_reattached() {
    local attempt payload
    for attempt in $(seq 1 45); do
        payload="${WORK_DIR}/restart-inventory-${attempt}.json"
        if ! command curl --fail -sS \
            "${DATAPATH_HTTP}/api/v1/instances" >"${payload}"; then
            command sleep 1 || return 1
            continue
        fi
        if python3 - "${WORK_DIR}/baseline-instances.json" "${payload}" \
            2>"${WORK_DIR}/restart-inventory-${attempt}.assert.err" <<'PY'
import json,sys
baseline=json.load(open(sys.argv[1],encoding="utf-8"))
current=json.load(open(sys.argv[2],encoding="utf-8"))
baseline_names={row.get("name") for row in baseline.get("instances") or []
                if row.get("active") is True}
active_names={row.get("name") for row in current.get("instances") or []
              if row.get("active") is True}
assert baseline_names,baseline_names
assert baseline_names.issubset(active_names),(baseline_names-active_names)
PY
        then
            return 0
        fi
        command sleep 1 || return 1
    done
    return 1
}

restart_managed_datapath() {
    local expected_phase="$1"
    command docker restart "${DATAPATH_SERVICE_NAME}" || return 1
    wait_neutron_uds || return 1
    wait_managed_port_reattached "${expected_phase}" || return 1
    wait_baseline_inventory_reattached || return 1
}

validate_fragment_vlan_endpoint() {
    local namespace="$1" iface="$2" parent="$3" vlan="$4" payload
    if [ -n "${namespace}" ]; then
        payload="$(ip netns exec "${namespace}" ip -d -j link show dev "${iface}")" \
            || die "fragment peer VLAN endpoint is unavailable: ${iface}"
    else
        payload="$(ip -d -j link show dev "${iface}")" \
            || die "fragment host VLAN endpoint is unavailable: ${iface}"
    fi
    python3 -c 'import json,sys
rows=json.load(sys.stdin); assert len(rows)==1,rows
info=rows[0].get("linkinfo") or {}
assert info.get("info_kind")=="vlan",info
assert rows[0].get("link")==sys.argv[1],rows[0]
assert int((info.get("info_data") or {}).get("id"))==int(sys.argv[2]),info' \
        "${parent}" "${vlan}" <<<"${payload}" \
        || die "fragment VLAN endpoint ${iface} does not match ${parent}/VLAN ${vlan}"
}

validate_fragment_endpoint_addresses() {
    local namespace="$1" iface="$2" expected_v4="$3" expected_v6="$4" payload
    if [ -n "${namespace}" ]; then
        payload="$(ip netns exec "${namespace}" ip -j addr show dev "${iface}")" \
            || die "cannot inspect fragment peer addresses on ${iface}"
    else
        payload="$(ip -j addr show dev "${iface}")" \
            || die "cannot inspect fragment host addresses on ${iface}"
    fi
    python3 -c 'import ipaddress,json,sys
rows=json.load(sys.stdin); assert len(rows)==1,rows
actual={ipaddress.ip_address(item["local"]) for item in rows[0].get("addr_info") or []}
expected={ipaddress.ip_address(sys.argv[1]),ipaddress.ip_address(sys.argv[2])}
assert expected <= actual,(expected,actual)' "${expected_v4}" "${expected_v6}" <<<"${payload}" \
        || die "fragment VLAN A endpoint ${iface} lacks the exact dual-stack contract"
}

managed_fragment_preflight() {
    local value candidate
    [ -r "${FRAGMENT_DRIVER}" ] || die "fragment tracking field driver is missing"
    for value in FRAGMENT_PEER_NETNS FRAGMENT_PEER_IFNAME FRAGMENT_IPV4_HOST FRAGMENT_IPV4_PEER FRAGMENT_IPV6_HOST FRAGMENT_IPV6_PEER FRAGMENT_VLAN_A FRAGMENT_VLAN_B FRAGMENT_HOST_VLAN_A_IFNAME FRAGMENT_PEER_VLAN_A_IFNAME FRAGMENT_HOST_VLAN_B_IFNAME FRAGMENT_PEER_VLAN_B_IFNAME; do
        [ -n "${!value}" ] || die "${value} is required when FRAGMENT_TRACKING_SMOKE=1"
    done
    for value in FRAGMENT_PEER_IFNAME FRAGMENT_HOST_VLAN_A_IFNAME FRAGMENT_PEER_VLAN_A_IFNAME FRAGMENT_HOST_VLAN_B_IFNAME FRAGMENT_PEER_VLAN_B_IFNAME; do
        candidate="${!value}"
        [ "${#candidate}" -le 15 ] || die "${value} exceeds the Linux interface-name limit"
    done
    ip netns exec "${FRAGMENT_PEER_NETNS}" ip link show dev "${FRAGMENT_PEER_IFNAME}" >/dev/null 2>&1 \
        || die "fragment peer interface is unavailable"
    python3 - "${FRAGMENT_VLAN_A}" "${FRAGMENT_VLAN_B}" "${FRAGMENT_EXPECTED_CAPACITY}" \
        "${FRAGMENT_IPV4_HOST}" "${FRAGMENT_IPV4_PEER}" \
        "${FRAGMENT_IPV6_HOST}" "${FRAGMENT_IPV6_PEER}" <<'PY' || die "invalid managed fragment VLAN/address contract"
import ipaddress,sys
vlan_a,vlan_b,capacity=map(int,sys.argv[1:4])
assert 1 <= vlan_a <= 4094 and 1 <= vlan_b <= 4094 and vlan_a != vlan_b
assert capacity > 0
addresses=[ipaddress.ip_address(value) for value in sys.argv[4:]]
assert [value.version for value in addresses] == [4,4,6,6]
assert len(set(addresses)) == 4
PY
    validate_fragment_vlan_endpoint "" "${FRAGMENT_HOST_VLAN_A_IFNAME}" "${EXPECTED_IFNAME}" "${FRAGMENT_VLAN_A}"
    validate_fragment_vlan_endpoint "${FRAGMENT_PEER_NETNS}" "${FRAGMENT_PEER_VLAN_A_IFNAME}" "${FRAGMENT_PEER_IFNAME}" "${FRAGMENT_VLAN_A}"
    validate_fragment_vlan_endpoint "" "${FRAGMENT_HOST_VLAN_B_IFNAME}" "${EXPECTED_IFNAME}" "${FRAGMENT_VLAN_B}"
    validate_fragment_vlan_endpoint "${FRAGMENT_PEER_NETNS}" "${FRAGMENT_PEER_VLAN_B_IFNAME}" "${FRAGMENT_PEER_IFNAME}" "${FRAGMENT_VLAN_B}"
    validate_fragment_endpoint_addresses "" "${FRAGMENT_HOST_VLAN_A_IFNAME}" \
        "${FRAGMENT_IPV4_HOST}" "${FRAGMENT_IPV6_HOST}"
    validate_fragment_endpoint_addresses "${FRAGMENT_PEER_NETNS}" "${FRAGMENT_PEER_VLAN_A_IFNAME}" \
        "${FRAGMENT_IPV4_PEER}" "${FRAGMENT_IPV6_PEER}"
}

create_fragment_rule() {
    local direction="$1" port="$2" priority="$3" label="$4" body id
    body="$(printf '{\"aria_acl_rule\":{\"policy_id\":\"%s\",\"direction\":\"%s\",\"priority\":%s,\"action\":\"allow\",\"protocol\":\"udp\",\"dst_port_min\":%s,\"dst_port_max\":%s}}' \
        "${policy_id}" "${direction}" "${priority}" "${port}" "${port}")"
    id="$(curl_body POST aria-acl-rules "${body}" | tee "${WORK_DIR}/${label}.json" | json_field aria_acl_rule.id)"
    [ -n "${id}" ] || die "failed to create fragment ${direction} UDP/${port} rule"
    rule_ids+=("${id}")
    created_rule_ids+=("${id}")
}

next_fragment_identity() {
    FRAGMENT_ID_COUNTER=$((FRAGMENT_ID_COUNTER + 1))
    FRAGMENT_TOKEN="aria-fragment-${FRAGMENT_TOKEN_SEED}-${FRAGMENT_ID_COUNTER}-0123456789"
    FRAGMENT_IDENT=$((1000 + FRAGMENT_ID_COUNTER))
}

fragment_driver() {
    local label="$1" family="$2" direction="$3" vlan="$4" operation="$5"
    local token="$6" ident="$7" source destination
    shift 7
    if [ "${family}" = ipv4 ]; then
        source="${FRAGMENT_IPV4_HOST}"; destination="${FRAGMENT_IPV4_PEER}"
    else
        source="${FRAGMENT_IPV6_HOST}"; destination="${FRAGMENT_IPV6_PEER}"
    fi
    if [ "${direction}" = host-to-peer ]; then
        FRAGMENT_ARGS=(--run --operation "${operation}" --iface "${EXPECTED_IFNAME}"
            --source "${source}" --destination "${destination}"
            --destination-mac "${FRAGMENT_PEER_MAC}" --family "${family}"
            --vlan "${vlan}" --metrics-url "${DATAPATH_HTTP}/metrics"
            --pin-path "${PIN_ROOT}" --receiver-netns "${FRAGMENT_PEER_NETNS}"
            --token "${token}" --ident "${ident}")
    else
        FRAGMENT_ARGS=(--run --operation "${operation}" --iface "${FRAGMENT_PEER_IFNAME}"
            --send-netns "${FRAGMENT_PEER_NETNS}" --source "${destination}"
            --destination "${source}" --source-mac "${FRAGMENT_PEER_MAC}"
            --destination-mac "${FRAGMENT_HOST_MAC}" --family "${family}"
            --vlan "${vlan}" --metrics-url "${DATAPATH_HTTP}/metrics"
            --pin-path "${PIN_ROOT}" --token "${token}" --ident "${ident}")
    fi
    FRAGMENT_ARGS+=("$@")
    python3 "${FRAGMENT_DRIVER}" "${FRAGMENT_ARGS[@]}" >"${WORK_DIR}/${label}.log"
}

observe_fragment_occupancy() {
    local family="$1" label="$2"
    python3 "${FRAGMENT_DRIVER}" --run --operation observe --family "${family}" \
        --metrics-url "${DATAPATH_HTTP}/metrics" --pin-path "${PIN_ROOT}" \
        --expected-occupancy 0 --expected-capacity "${FRAGMENT_EXPECTED_CAPACITY}" \
        >"${WORK_DIR}/${label}.log"
}

run_fragment_tracking_field_smoke() {
    local family direction scenario token ident
    if [ "${FRAGMENT_TRACKING_SMOKE}" != 1 ]; then
        echo "SKIP: fragment tracking field smoke disabled"
        return 0
    fi
    managed_fragment_preflight
    FRAGMENT_PEER_MAC="$(ip netns exec "${FRAGMENT_PEER_NETNS}" cat "/sys/class/net/${FRAGMENT_PEER_IFNAME}/address")"
    FRAGMENT_HOST_MAC="$(cat "/sys/class/net/${EXPECTED_IFNAME}/address")"
    FRAGMENT_TOKEN_SEED="$(python3 -c 'import secrets; print(secrets.token_hex(8))')"
    FRAGMENT_ID_COUNTER=0
    create_fragment_rule ingress 53 300 fragment-rule-ingress-udp53
    create_fragment_rule egress 53 300 fragment-rule-egress-udp53
    run_full_resync >"${WORK_DIR}/fragment-policy-full-resync.log"
    wait_port_enforced || die "fragment UDP/53 policy did not become enforced"
    for family in ipv4 ipv6; do
        for scenario in ordered post-first-reorder; do
            for direction in host-to-peer peer-to-host; do
                next_fragment_identity
                token="${FRAGMENT_TOKEN}"; ident="${FRAGMENT_IDENT}"
                fragment_driver "fragment-${family}-${direction}-${scenario}" "${family}" \
                    "${direction}" "${FRAGMENT_VLAN_A}" complete "${token}" "${ident}" \
                    --scenario "${scenario}"
            done
        done
        for direction in host-to-peer peer-to-host; do
            next_fragment_identity
            token="${FRAGMENT_TOKEN}"; ident="${FRAGMENT_IDENT}"
            fragment_driver "fragment-${family}-${direction}-later-before-first" "${family}" \
                "${direction}" "${FRAGMENT_VLAN_A}" complete "${token}" "${ident}" \
                --scenario later-before-first
        done
    done

    next_fragment_identity
    token="${FRAGMENT_TOKEN}"; ident="${FRAGMENT_IDENT}"
    fragment_driver fragment-vlan-establish ipv4 host-to-peer "${FRAGMENT_VLAN_A}" establish "${token}" "${ident}"
    fragment_driver fragment-vlan-isolation-probe ipv4 host-to-peer "${FRAGMENT_VLAN_B}" probe-old "${token}" "${ident}" \
        --expected-probe-event miss --reuse-reason isolation
    fragment_driver fragment-vlan-continue ipv4 host-to-peer "${FRAGMENT_VLAN_A}" continue "${token}" "${ident}"

    next_fragment_identity
    token="${FRAGMENT_TOKEN}"; ident="${FRAGMENT_IDENT}"
    fragment_driver fragment-epoch-establish ipv4 host-to-peer "${FRAGMENT_VLAN_A}" establish "${token}" "${ident}"
    create_fragment_rule ingress 54 310 fragment-rule-epoch-udp54
    run_full_resync >"${WORK_DIR}/fragment-epoch-full-resync.log"
    wait_port_enforced || die "fragment epoch policy publication did not become enforced"
    fragment_driver fragment-epoch-stale-probe ipv4 host-to-peer "${FRAGMENT_VLAN_A}" probe-old "${token}" "${ident}" \
        --expected-probe-event stale --reuse-reason epoch

    next_fragment_identity
    token="${FRAGMENT_TOKEN}"; ident="${FRAGMENT_IDENT}"
    fragment_driver fragment-restart-establish ipv4 host-to-peer "${FRAGMENT_VLAN_A}" establish "${token}" "${ident}"
    restart_managed_datapath ready >"${WORK_DIR}/fragment-restart.log"
    observe_fragment_occupancy ipv4 fragment-restart-ipv4-empty
    observe_fragment_occupancy ipv6 fragment-restart-ipv6-empty
    fragment_driver fragment-restart-miss-probe ipv4 host-to-peer "${FRAGMENT_VLAN_A}" probe-old "${token}" "${ident}" \
        --expected-probe-event miss --reuse-reason restart
    FRAGMENT_TRANSITIONS_VERIFIED=true
    FRAGMENT_BODY_SUCCEEDED=true
}

capture_datapath_log_cursor() {
    local label="$1" size
    if [ -n "${DATAPATH_LOG_FILE}" ] && [ -r "${DATAPATH_LOG_FILE}" ]; then
        size="$(wc -c <"${DATAPATH_LOG_FILE}")" || return 1
        printf 'file:%s\n' "${size}" >"${WORK_DIR}/${label}-log-cursor.txt"
        return 0
    fi
    printf 'docker:' >"${WORK_DIR}/${label}-log-cursor.txt"
    command docker logs --timestamps --tail 1 "${DATAPATH_SERVICE_NAME}" \
        >>"${WORK_DIR}/${label}-log-cursor.txt" 2>&1 || return 1
    [ -s "${WORK_DIR}/${label}-log-cursor.txt" ] || return 1
}

capture_datapath_logs_since() {
    local label="$1" cursor mode since raw current_size
    cursor="$(cat "${WORK_DIR}/${label}-log-cursor.txt")" || return 1
    raw="${WORK_DIR}/${label}-datapath-since-raw.log"
    case "${cursor}" in
        file:*)
            mode="file"
            since="${cursor#file:}"
            current_size="$(wc -c <"${DATAPATH_LOG_FILE}")" || return 1
            [ "${current_size}" -ge "${since}" ] || return 1
            command tail -c "+$((since + 1))" "${DATAPATH_LOG_FILE}" >"${raw}" || return 1
            ;;
        docker:*)
            mode="docker"
            since="$(printf '%s\n' "${cursor#docker:}" | awk 'NR==1 {print $1}')" || return 1
            [ -n "${since}" ] || return 1
            command docker logs --timestamps --since "${since}" "${DATAPATH_SERVICE_NAME}" \
                >"${raw}" 2>&1 || return 1
            ;;
        *) return 1 ;;
    esac
    python3 - "${mode}" "${since}" "${raw}" >"${WORK_DIR}/${label}-datapath.log" <<'PY' || return 1
import re,sys
mode,cursor,path=sys.argv[1:]
ansi=re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
previous=None
for raw in open(path,encoding="utf-8"):
    line=ansi.sub("",raw)
    timestamp=line.split(None,1)[0] if line.split(None,1) else ""
    if mode=="docker" and timestamp<=cursor:
        continue
    if line==previous:
        continue
    print(line,end="")
    previous=line
PY
}

run_live_legacy_selector_repair() {
    local injected_bank current_bank
    LEGACY_RESTART_REPAIR_GATE="not_applicable"
    printf '{"legacy_restart_repair_gate":"not_applicable","reason":"legacy_tc_links_do_not_survive_process_restart"}\n' \
        >"${WORK_DIR}/legacy-repair-required-status.json"
    capture_selector_projection legacy-before-repair
    injected_bank="$(awk '{print $1}' "${WORK_DIR}/legacy-polluted-after-runtime-compatibility.txt")"
    current_bank="$(awk '{print $1}' "${WORK_DIR}/legacy-before-repair-runtime-compatibility.txt")"
    if [ "${injected_bank}" != "${current_bank}" ]; then
        LEGACY_REPAIR_MODE="background"
        run_captured_selector_flow legacy-background-repaired-deny 2 deny
        assert_selector_deny_drop_ct_zero legacy-background-repaired-deny
    else
        LEGACY_REPAIR_MODE="explicit"
    fi
}

assert_projection_repair_required() {
    python3 - "${WORK_DIR}/legacy-repair-required-instances.json" \
        "${WORK_DIR}/legacy-repair-required-config.json" \
        "${WORK_DIR}/legacy-repair-required-datapath.log" \
        "${WORK_DIR}/legacy-repair-required-tc-ingress.json" \
        "${WORK_DIR}/legacy-repair-required-tc-egress.json" \
        "${WORK_DIR}/legacy-repair-required-link.txt" \
        "${WORK_DIR}/legacy-repair-required-port-status.json" \
        "${EXPECTED_IFNAME}" "${EXPECTED_PORT_ID}" <<'PY'
import json,sys
instances=json.load(open(sys.argv[1],encoding="utf-8"))["instances"]
config=json.load(open(sys.argv[2],encoding="utf-8"))
projection_log=open(sys.argv[3],encoding="utf-8").read()
tc_ingress=json.load(open(sys.argv[4],encoding="utf-8"))
tc_egress=json.load(open(sys.argv[5],encoding="utf-8"))
link_text=open(sys.argv[6],encoding="utf-8").read()
port_payload=json.load(open(sys.argv[7],encoding="utf-8"))
ifname,port_id=sys.argv[8:]
item=next(row for row in instances if row.get("name")==ifname)
port_rows=port_payload.get("aria_acl_port_statuses") or port_payload.get("port_statuses") or []
target_port=next(row for row in port_rows if row.get("port_id")==port_id and row.get("ifname")==ifname)
acl_ready=item["acl_ready"]
readiness_reason=item["readiness_reason"]
expected_projection_reason="quiesced repairable preexisting ACL projection pending Neutron resync"
projection_reason=next((line for line in projection_log.splitlines() if expected_projection_reason in line and ("instance="+ifname) in line),None)
tc_ingress_live=(isinstance(tc_ingress,list) and any(row.get("kind")=="bpf" for row in tc_ingress))
tc_egress_live=(isinstance(tc_egress,list) and any(row.get("kind")=="bpf" for row in tc_egress))
links_intact=(tc_ingress_live and tc_egress_live and ifname in link_text)
repair_required=(acl_ready is False and config["acl"] is False and readiness_reason=="recovery_required" and projection_reason is not None and target_port.get("port_id")==port_id)
assert item.get("name")==ifname
assert target_port.get("port_id")==port_id
assert target_port.get("ifname")==ifname
assert tc_ingress_live is True
assert tc_egress_live is True
assert links_intact is True
assert readiness_reason=="recovery_required"
assert projection_reason is not None
assert expected_projection_reason in projection_reason
assert ("instance="+ifname) in projection_reason
assert repair_required is True
assert acl_ready is False
assert config["acl"] is False
PY
}

assert_legacy_pollution_evidence() {
    local bad_traffic_rc bad_ct_count bad_ct_packets bad_ct_bytes
    bad_traffic_rc="$(cat "${WORK_DIR}/legacy-polluted-traffic-rc.txt")"
    read -r bad_ct_count bad_ct_packets bad_ct_bytes < <(
        flow_conntrack_totals "${WORK_DIR}/legacy-polluted-after-conntrack.json"
    )
    python3 - "${WORK_DIR}" "${ACL_SELECTOR_CIDR}" "${legacy_local_group_id}" \
        "${bad_traffic_rc}" "${bad_ct_count}" "${bad_ct_packets}" \
        "${bad_ct_bytes}" <<'PY'
import ipaddress,json,os,struct,sys
def decode_bpftool_bytes(values):
    return bytes(int(value,16) if isinstance(value,str) else value for value in values)
(root,selector_cidr,legacy_local_group_id,bad_traffic_rc_raw,bad_ct_count_raw,
 bad_ct_packets_raw,bad_ct_bytes_raw)=sys.argv[1:]
selector_cidr=str(ipaddress.ip_network(selector_cidr,strict=False))
legacy_local_group_id=int(legacy_local_group_id)
bad_traffic_rc=int(bad_traffic_rc_raw); bad_ct_count=int(bad_ct_count_raw)
bad_ct_packets=int(bad_ct_packets_raw); bad_ct_bytes=int(bad_ct_bytes_raw)
bank=int(open(os.path.join(root,"legacy-polluted-after-runtime-compatibility.txt"),encoding="utf-8").read().split()[0])
iface=json.load(open(os.path.join(root,"legacy-polluted-after-iface-ctx.json"),encoding="utf-8"))
tap_id=struct.unpack("=I",decode_bpftool_bytes(iface["value"][:4]))[0]
payload=json.load(open(os.path.join(root,"legacy-polluted-after-acl-src-map.json"),encoding="utf-8"))
def lookup(rows,scope,cidr):
    found=[]
    for row in rows:
        key=decode_bpftool_bytes(row["key"]); value=decode_bpftool_bytes(row["value"])
        prefix=struct.unpack("=I",key[:4])[0]-32
        if int.from_bytes(key[4:8],"big") != scope:
            continue
        network=str(ipaddress.ip_network(
            "%s/%d" % (ipaddress.IPv4Address(key[8:12]),prefix),strict=False))
        if network==cidr:
            found.append(struct.unpack("=I",value[:4])[0])
    assert len(found)==1,found
    return found[0]
polluted_acl_value=lookup(payload,tap_id*2+bank,selector_cidr)
assert polluted_acl_value==legacy_local_group_id
assert bad_traffic_rc==0
assert bad_ct_count>0
assert bad_ct_packets>0
assert bad_ct_bytes>0
PY
}

assert_legacy_repair_evidence() {
    local injected_bank polluted_bank repaired_bank equal_before_bank equal_bank restart_bank
    local repaired_ct_count repaired_ct_packets repaired_ct_bytes
    local repaired_drop_before repaired_drop_after repaired_drop_delta
    injected_bank="$(awk '{print $1}' "${WORK_DIR}/legacy-polluted-after-runtime-compatibility.txt")"
    polluted_bank="$(awk '{print $1}' "${WORK_DIR}/legacy-before-repair-runtime-compatibility.txt")"
    repaired_bank="$(awk '{print $1}' "${WORK_DIR}/legacy-repaired-runtime-compatibility.txt")"
    equal_before_bank="$(awk '{print $1}' "${WORK_DIR}/legacy-before-equal-runtime-compatibility.txt")"
    equal_bank="$(awk '{print $1}' "${WORK_DIR}/legacy-after-equal-runtime-compatibility.txt")"
    restart_bank="$(awk '{print $1}' "${WORK_DIR}/legacy-clean-restart-runtime-compatibility.txt")"
    read -r repaired_ct_count repaired_ct_packets repaired_ct_bytes < <(
        flow_conntrack_totals "${WORK_DIR}/legacy-repaired-deny-after-conntrack.json"
    )
    repaired_drop_before="$(rule_counter_sum "${WORK_DIR}/legacy-repaired-deny-before-rules.json" egress dropped_packets)"
    repaired_drop_after="$(rule_counter_sum "${WORK_DIR}/legacy-repaired-deny-after-rules.json" egress dropped_packets)"
    repaired_drop_delta=$((repaired_drop_after - repaired_drop_before))
    python3 - "${WORK_DIR}" "${ACL_SELECTOR_CIDR}" "${selector_group_id}" \
        "${injected_bank}" "${polluted_bank}" "${repaired_bank}" "${equal_bank}" "${restart_bank}" \
        "${equal_before_bank}" "${repaired_ct_count}" "${repaired_drop_delta}" \
        "${EXPECTED_IFNAME}" "${EXPECTED_PORT_ID}" "${legacy_local_group_id}" \
        "${LEGACY_REPAIR_MODE}" <<'PY'
import ipaddress,json,os,re,struct,sys
def decode_bpftool_bytes(values):
    return bytes(int(value,16) if isinstance(value,str) else value for value in values)
(root,selector_cidr,selector_group_id,injected_bank,polluted_bank,repaired_bank,equal_bank,
 restart_bank,equal_before_bank,repaired_ct_count,repaired_drop_delta,ifname,
 port_id,legacy_local_group_id,repair_mode)=sys.argv[1:]
selector_cidr=str(ipaddress.ip_network(selector_cidr,strict=False))
selector_group_id=int(selector_group_id)
legacy_local_group_id=int(legacy_local_group_id)
injected_bank=int(injected_bank); polluted_bank=int(polluted_bank)
repaired_bank=int(repaired_bank)
equal_bank=int(equal_bank); restart_bank=int(restart_bank)
equal_before_bank=int(equal_before_bank)
repaired_ct_count=int(repaired_ct_count); repaired_drop_delta=int(repaired_drop_delta)
iface=json.load(open(os.path.join(root,"legacy-repaired-iface-ctx.json"),encoding="utf-8"))
tap_id=struct.unpack("=I",decode_bpftool_bytes(iface["value"][:4]))[0]
def load(name):
    return json.load(open(os.path.join(root,name),encoding="utf-8"))
def entries(label,kind,scope):
    out={}
    for row in load(label+"-"+kind+"-map.json"):
        key=decode_bpftool_bytes(row["key"]); value=decode_bpftool_bytes(row["value"])
        prefix=struct.unpack("=I",key[:4])[0]-32
        if int.from_bytes(key[4:8],"big") != scope:
            continue
        network=str(ipaddress.ip_network(
            "%s/%d" % (ipaddress.IPv4Address(key[8:12]),prefix),strict=False))
        out[network]=struct.unpack("=I",value[:4])[0]
    return out
def repair_counts(label):
    text=open(os.path.join(root,label+"-datapath.log"),encoding="utf-8").read()
    profile=[line for line in text.splitlines()
        if "neutron_acl_apply_profile" in line
        and ("ifname="+ifname) in line
        and ("port_id="+port_id) in line]
    true_count=sum("selector_repair_performed=true" in line for line in profile)
    false_count=sum("selector_repair_performed=false" in line for line in profile)
    return true_count,false_count
def repair_required_count(label):
    text=open(os.path.join(root,label+"-datapath.log"),encoding="utf-8").read()
    reason="quiesced repairable preexisting ACL projection pending Neutron resync"
    return sum(reason in line and ("instance="+ifname) in line
        for line in text.splitlines())
repaired_acl_value=entries("legacy-repaired","acl-src",tap_id*2+repaired_bank).get(selector_cidr)
before_repair_acl_value=entries("legacy-before-repair","acl-src",tap_id*2+polluted_bank).get(selector_cidr)
clean_general_entries=entries("legacy-clean-restart","general-src",tap_id)
clean_bank_zero_entries=entries("legacy-clean-restart","acl-src",tap_id*2)
clean_bank_one_entries=entries("legacy-clean-restart","acl-src",tap_id*2+1)
clean_active_entries=(clean_bank_zero_entries if restart_bank==0 else clean_bank_one_entries)
clean_general_ids=set(clean_general_entries.values())
clean_bank_zero_ids=set(clean_bank_zero_entries.values())
clean_bank_one_ids=set(clean_bank_one_entries.values())
repair_true_count,repair_false_count=repair_counts("legacy-repair")
equal_true_count,equal_false_count=repair_counts("legacy-equal")
restart_true_count=repair_counts("legacy-clean-restart")[0]
restart_repair_required_count=repair_required_count("legacy-clean-restart")
instances=json.load(open(os.path.join(root,"legacy-clean-restart-instances.json"),encoding="utf-8"))["instances"]
config=json.load(open(os.path.join(root,"legacy-clean-restart-config.json"),encoding="utf-8"))
item=next(row for row in instances if row["name"]==ifname)
inventory_clean=(item["active"] is True and item["acl_ready"] is True and
                 item.get("readiness_reason") in (None,"xdp_ddos_hook_unavailable") and
                 config["acl"] is True)
if repair_mode=="background":
    assert injected_bank!=polluted_bank
    assert polluted_bank==repaired_bank
    assert before_repair_acl_value==selector_group_id
    assert repair_true_count==0
elif repair_mode=="observed_bank_repair":
    assert injected_bank==polluted_bank
    assert polluted_bank!=repaired_bank
    assert repair_true_count==0
else:
    assert repair_mode=="explicit"
    assert injected_bank==polluted_bank
    assert polluted_bank!=repaired_bank
    assert repair_true_count==1
assert repaired_acl_value==selector_group_id
assert repaired_ct_count==0
assert repaired_drop_delta>0
assert repaired_bank==equal_before_bank
assert equal_before_bank==equal_bank
assert repaired_bank==equal_bank
assert equal_true_count==0
assert restart_true_count==0
assert restart_repair_required_count==0
assert clean_active_entries[selector_cidr]==selector_group_id
assert legacy_local_group_id not in clean_general_ids
assert legacy_local_group_id not in clean_bank_zero_ids
assert legacy_local_group_id not in clean_bank_one_ids
assert inventory_clean is True
PY
}

assert_selector_cleanup_state() {
    local label="$1" polluted_group_id="${2:-0}" expected_general_group_id="${3}" semantic_delta_id="${4:-}" local_ids="${5:-}" local_cidrs_arg="${6:-}" expected_live_groups="${7:-}"
    python3 - "${WORK_DIR}" "${label}" "${EXPECTED_IFNAME}" \
        "${polluted_group_id}" "${expected_general_group_id}" "${semantic_delta_id}" "${local_ids}" \
        "${local_cidrs_arg}" "${expected_live_groups}" \
        "${EXACT_LOCAL_GROUP_NAME} ${MORE_SPECIFIC_GROUP_NAME} ${LEGACY_LOCAL_GROUP_NAME}" \
        "${ACL_SELECTOR_CIDR}" "${selector_rule_id}" "${selector_group_id}" \
        "${policy_id}" "${CT_PROTOCOL}" <<'PY'
import ipaddress,json,os,struct,sys
def decode_bpftool_bytes(values):
    return bytes(int(value,16) if isinstance(value,str) else value for value in values)
root,label,ifname,polluted_group_id,expected_general_group_id_raw,semantic_delta_rule_id,local_ids,local_cidrs,expected_live_groups,attempted_names,selector_cidr,selector_rule_id,selector_group_id,policy_id,protocol=sys.argv[1:]
polluted_group_id=int(polluted_group_id or 0)
expected_general_group_id=int(expected_general_group_id_raw)
selector_group_id=int(selector_group_id)
selector_cidr=str(ipaddress.ip_network(selector_cidr,strict=False))
local_group_ids={int(value) for value in local_ids.split() if value}
local_cidrs={str(ipaddress.ip_network(value,strict=False)) for value in local_cidrs.split(",") if value}
expected_live_group_names={value for value in expected_live_groups.split() if value}
attempted_group_names={value for value in attempted_names.split() if value}
def load(name):
    return json.load(open(os.path.join(root,name),encoding="utf-8"))
iface=load(label+"-iface-ctx.json")
tap_id=struct.unpack("=I",decode_bpftool_bytes(iface["value"][:4]))[0]
active_bank=int(open(os.path.join(root,label+"-runtime-compatibility.txt"),encoding="utf-8").read().split()[0])
def entries(kind,scope):
    out={}
    for row in load(label+"-"+kind+"-map.json"):
        key=decode_bpftool_bytes(row["key"]); value=decode_bpftool_bytes(row["value"])
        prefix=struct.unpack("=I",key[:4])[0]-32
        if int.from_bytes(key[4:8],"big") != scope:
            continue
        cidr=str(ipaddress.ip_network("%s/%d" % (ipaddress.IPv4Address(key[8:12]),prefix),strict=False))
        out[cidr]=struct.unpack("=I",value[:4])[0]
    return out
general_entries={**entries("general-src",tap_id),**entries("general-dst",tap_id)}
acl_bank_zero_entries={**entries("acl-src",tap_id*2),**entries("acl-dst",tap_id*2)}
acl_bank_one_entries={**entries("acl-src",tap_id*2+1),**entries("acl-dst",tap_id*2+1)}
neutron_rules=load(label+"-neutron-rules.json").get("aria_acl_rules") or []
live_groups=load(label+"-groups.json").get("groups") or []
instances=load(label+"-instances.json").get("instances") or []
config=load(label+"-config.json")
item=next(row for row in instances if row["name"]==ifname)
live_rule_ids={str(row["id"]) for row in neutron_rules}
live_group_names={str(row["name"]) for row in live_groups}
general_keys=set(general_entries)
general_ids=set(general_entries.values())
acl_bank_zero_ids=set(acl_bank_zero_entries.values())
acl_bank_one_ids=set(acl_bank_one_entries.values())
active_acl_entries=(acl_bank_zero_entries if active_bank==0 else acl_bank_one_entries)
inactive_acl_entries=(acl_bank_one_entries if active_bank==0 else acl_bank_zero_entries)
inactive_selector_value=inactive_acl_entries.get(selector_cidr)
allowed_inactive_selector_values={None,selector_group_id}
baseline_selector_rule=next(row for row in neutron_rules if str(row.get("id"))==selector_rule_id)
semantic_delta_matches=[row for row in neutron_rules if row.get("policy_id")==policy_id and row.get("direction")=="ingress" and row.get("priority")==200 and row.get("action")=="allow" and row.get("protocol")=="tcp" and row.get("src_cidr")==selector_cidr]
acl_ready=item["acl_ready"]
assert polluted_group_id not in acl_bank_zero_ids
assert polluted_group_id not in acl_bank_one_ids
assert active_acl_entries[selector_cidr]==selector_group_id
assert inactive_selector_value in allowed_inactive_selector_values
assert selector_rule_id in live_rule_ids
assert baseline_selector_rule.get("policy_id")==policy_id
assert baseline_selector_rule.get("direction")=="ingress"
assert baseline_selector_rule.get("priority")==100
assert baseline_selector_rule.get("action")=="drop"
assert baseline_selector_rule.get("protocol")==protocol
assert baseline_selector_rule.get("src_cidr")==selector_cidr
assert len(semantic_delta_matches)==0
assert semantic_delta_rule_id not in live_rule_ids
assert attempted_group_names.intersection(live_group_names)==expected_live_group_names
assert local_cidrs.isdisjoint(general_keys)
assert local_group_ids.isdisjoint(general_ids)
assert local_group_ids.isdisjoint(acl_bank_zero_ids)
assert local_group_ids.isdisjoint(acl_bank_one_ids)
assert general_entries[selector_cidr]==expected_general_group_id
assert acl_ready is True
assert config["acl"] is True
PY
}

cleanup_selector_fixture_state() {
    local cleanup_rc=0 cleanup_semantic_delta_rule_id cleanup_local_ids
    [ "${SELECTOR_FIXTURES_STARTED}" = true ] || return 0
    cleanup_semantic_delta_rule_id="${semantic_delta_rule_id:-}"
    cleanup_local_ids="${selector_local_group_ids[*]:-}"
    if [ "${LEGACY_POLLUTION_INJECTED}" = true ]; then
        restart_managed_datapath active || cleanup_rc=1
        if [ "${cleanup_rc}" -eq 0 ]; then
            run_full_resync >"${WORK_DIR}/selector-cleanup-pollution-repair-resync.log" || cleanup_rc=1
        fi
        if [ "${cleanup_rc}" -eq 0 ]; then
            capture_selector_projection selector-pollution-clean || cleanup_rc=1
        fi
        if [ "${cleanup_rc}" -eq 0 ]; then
            assert_selector_cleanup_state selector-pollution-clean "${legacy_local_group_id}" \
                "${legacy_local_group_id}" "${cleanup_semantic_delta_rule_id}" "" "" \
                "${LEGACY_LOCAL_GROUP_NAME}" || cleanup_rc=1
        fi
        if [ "${cleanup_rc}" -eq 0 ]; then
            LEGACY_POLLUTION_INJECTED=false
        fi
    fi
    if remove_owned_acl_semantic_delta >"${WORK_DIR}/selector-cleanup-semantic-delta.json" 2>&1; then
        semantic_delta_rule_id=""
    else
        cleanup_rc=1
    fi
    if cleanup_selector_group_attempt "${EXACT_LOCAL_GROUP_NAME}" >"${WORK_DIR}/selector-cleanup-exact-group.json" 2>&1; then
        exact_local_group_id=""
    else
        cleanup_rc=1
    fi
    if cleanup_selector_group_attempt "${MORE_SPECIFIC_GROUP_NAME}" >"${WORK_DIR}/selector-cleanup-more-specific-group.json" 2>&1; then
        more_specific_group_id=""
    else
        cleanup_rc=1
    fi
    if [ "${LEGACY_POLLUTION_INJECTED}" = false ]; then
        if cleanup_selector_group_attempt "${LEGACY_LOCAL_GROUP_NAME}" >"${WORK_DIR}/selector-cleanup-legacy-group.json" 2>&1; then
            legacy_local_group_id=""
        else
            cleanup_rc=1
        fi
    fi
    run_full_resync >"${WORK_DIR}/selector-cleanup-full-resync.log" || cleanup_rc=1
    capture_selector_projection selector-failclosed-cleanup || cleanup_rc=1
    assert_selector_cleanup_state selector-failclosed-cleanup 0 "${selector_group_id}" \
        "${cleanup_semantic_delta_rule_id}" "${cleanup_local_ids}" "${MORE_SPECIFIC_CIDR}" "" || cleanup_rc=1
    [ "${cleanup_rc}" -eq 0 ]
}

run_exact_selector_isolation_fixture() {
    if [ "${IP_FAMILY}" = ipv6 ]; then
        EXACT_SELECTOR_FIXTURE_STATUS="skipped_ipv6"
    fi
    [ "${IP_FAMILY}" = ipv4 ] || return 0
    EXACT_SELECTOR_FIXTURE_STATUS="failed"
    reverify_selector_deny_baseline exact-baseline
    selector_group_id="$(resolve_selector_group_id exact-baseline-deny-after)" || return 1
    [ -n "${selector_group_id}" ] || return 1
    SELECTOR_FIXTURES_STARTED=true
    capture_selector_projection exact-before
    exact_local_group_id="$(create_selector_fixture_group \
        "${EXACT_LOCAL_GROUP_NAME}" "${ACL_SELECTOR_CIDR}")" || return 1
    [ -n "${exact_local_group_id}" ] || return 1
    selector_local_group_ids+=("${exact_local_group_id}")
    capture_selector_projection exact-local
    run_captured_selector_flow exact-deny 2 deny
    assert_selector_deny_drop_ct_zero exact-deny
    delete_selector_fixture_group "${EXACT_LOCAL_GROUP_NAME}"
    capture_selector_projection exact-cleanup
    assert_exact_selector_state
    exact_local_group_id=""
    reverify_selector_deny_baseline exact-cleanup
    EXACT_SELECTOR_FIXTURE_STATUS="pass"
}

run_more_specific_selector_isolation_fixture() {
    if [ "${IP_FAMILY}" = ipv6 ]; then
        MORE_SPECIFIC_SELECTOR_FIXTURE_STATUS="skipped_ipv6"
    fi
    [ "${IP_FAMILY}" = ipv4 ] || return 0
    MORE_SPECIFIC_SELECTOR_FIXTURE_STATUS="failed"
    reverify_selector_deny_baseline more-specific-baseline
    selector_group_id="$(resolve_selector_group_id more-specific-baseline-deny-after)" || return 1
    [ -n "${selector_group_id}" ] || return 1
    SELECTOR_FIXTURES_STARTED=true
    require_wider_owned_selector
    more_specific_group_id="$(create_selector_fixture_group \
        "${MORE_SPECIFIC_GROUP_NAME}" "${MORE_SPECIFIC_CIDR}")" || return 1
    [ -n "${more_specific_group_id}" ] || return 1
    selector_local_group_ids+=("${more_specific_group_id}")
    capture_selector_projection more-specific-before-delta
    apply_owned_acl_semantic_delta
    run_full_resync >"${WORK_DIR}/more-specific-full-resync.log"
    capture_selector_projection more-specific-after-delta
    assert_more_specific_selector_state
    run_captured_selector_flow more-specific-deny 2 deny
    assert_selector_deny_drop_ct_zero more-specific-deny
    remove_owned_acl_semantic_delta
    semantic_delta_rule_id=""
    delete_selector_fixture_group "${MORE_SPECIFIC_GROUP_NAME}"
    more_specific_group_id=""
    run_full_resync >"${WORK_DIR}/more-specific-cleanup-resync.log"
    capture_selector_projection more-specific-cleanup
    reverify_selector_deny_baseline more-specific-cleanup
    MORE_SPECIFIC_SELECTOR_FIXTURE_STATUS="pass"
}

run_legacy_selector_repair_fixture() {
    local polluted_bank repaired_bank
    if [ "${IP_FAMILY}" = ipv6 ]; then
        LEGACY_SELECTOR_REPAIR_FIXTURE_STATUS="skipped_ipv6"
    fi
    [ "${IP_FAMILY}" = ipv4 ] || return 0
    LEGACY_SELECTOR_REPAIR_FIXTURE_STATUS="failed"
    LEGACY_REPAIR_MODE="explicit"
    reverify_selector_deny_baseline legacy-baseline
    selector_group_id="$(resolve_selector_group_id legacy-baseline-deny-after)" || return 1
    [ -n "${selector_group_id}" ] || return 1
    SELECTOR_FIXTURES_STARTED=true
    legacy_local_group_id="$(create_selector_fixture_group \
        "${LEGACY_LOCAL_GROUP_NAME}" "${LEGACY_POLLUTION_GROUP_CIDR}")" || return 1
    [ -n "${legacy_local_group_id}" ] || return 1
    selector_local_group_ids+=("${legacy_local_group_id}")
    capture_selector_projection legacy-before-pollution
    run_captured_selector_flow legacy-disjoint-deny 2 deny
    assert_selector_deny_drop_ct_zero legacy-disjoint-deny
    inject_legacy_selector_pollution
    run_captured_selector_flow legacy-polluted 2 pass
    assert_legacy_pollution_evidence
    if [ "${TC_ATTACHMENT_MODE}" = "tcx" ]; then
        LEGACY_RESTART_REPAIR_GATE="pass"
        capture_datapath_log_cursor legacy-repair-required
        restart_managed_datapath recovery_required
        capture_datapath_logs_since legacy-repair-required
        capture_selector_projection legacy-repair-required
        assert_projection_repair_required
        capture_selector_projection legacy-before-repair
    else
        run_live_legacy_selector_repair
    fi
    capture_datapath_log_cursor legacy-repair
    run_full_resync >"${WORK_DIR}/legacy-repair-full-resync.log"
    capture_datapath_logs_since legacy-repair
    capture_selector_projection legacy-repaired
    polluted_bank="$(awk '{print $1}' "${WORK_DIR}/legacy-before-repair-runtime-compatibility.txt")"
    repaired_bank="$(awk '{print $1}' "${WORK_DIR}/legacy-repaired-runtime-compatibility.txt")"
    if [ "${LEGACY_REPAIR_MODE}" = "explicit" ] && \
       [ "${polluted_bank}" != "${repaired_bank}" ] && \
       ! grep -F "selector_repair_performed=true" "${WORK_DIR}/legacy-repair-datapath.log" >/dev/null 2>&1; then
        LEGACY_REPAIR_MODE="observed_bank_repair"
    fi
    run_captured_selector_flow legacy-repaired-deny 2 deny
    assert_selector_deny_drop_ct_zero legacy-repaired-deny
    capture_selector_projection legacy-before-equal
    capture_datapath_log_cursor legacy-equal
    run_full_resync >"${WORK_DIR}/legacy-equal-full-resync.log"
    capture_datapath_logs_since legacy-equal
    capture_selector_projection legacy-after-equal
    delete_selector_fixture_group "${LEGACY_LOCAL_GROUP_NAME}"
    LEGACY_POLLUTION_INJECTED=false
    run_full_resync >"${WORK_DIR}/legacy-local-group-cleanup-resync.log"
    capture_datapath_log_cursor legacy-clean-restart
    restart_managed_datapath ready
    wait_port_enforced
    capture_datapath_logs_since legacy-clean-restart
    capture_selector_projection legacy-clean-restart
    assert_legacy_repair_evidence
    legacy_local_group_id=""
    run_full_resync >"${WORK_DIR}/legacy-cleanup-resync.log"
    capture_selector_projection legacy-cleanup
    reverify_selector_deny_baseline legacy-cleanup
    LEGACY_SELECTOR_REPAIR_FIXTURE_STATUS="pass"
}

verify_cleanup_restored() {
    curl_body GET aria-acl-policies >"${WORK_DIR}/cleanup-policies.json" || return 1
    curl_body GET aria-acl-rules >"${WORK_DIR}/cleanup-rules.json" || return 1
    curl_body GET aria-acl-bindings >"${WORK_DIR}/cleanup-bindings.json" || return 1
    capture cleanup-restored || return 1
    ping "${PING_ARGS[@]}" -c 2 -W 1 -s "${PING_PAYLOAD_BYTES}" "${VM_IP}" \
        >"${WORK_DIR}/cleanup-baseline-traffic.log" 2>&1 || return 1
    python3 - "${WORK_DIR}" "${policy_id}" "${binding_id}" "${EXPECTED_PORT_ID}" <<'PY'
import json,os,sys
root,policy_id,binding_id,port_id=sys.argv[1:]
def load(name):
    return json.load(open(os.path.join(root,name),encoding="utf-8"))
for name,key,obj_id in (("cleanup-policies.json","aria_acl_policies",policy_id),
                        ("cleanup-bindings.json","aria_acl_bindings",binding_id)):
    assert not any(str(row.get("id"))==obj_id for row in load(name).get(key) or []),(name,obj_id)
expected_rules=[line.strip() for line in open(os.path.join(root,"created-rule-ids.txt"),encoding="utf-8") if line.strip()]
remaining={str(row.get("id")) for row in load("cleanup-rules.json").get("aria_acl_rules") or []}
assert not (set(expected_rules) & remaining),(expected_rules,remaining)
before=load("baseline-config.json"); after=load("cleanup-restored-config.json")
assert before==after,(before,after)
before_tap=load("baseline-tap-config.json")["value"]
after_tap=load("cleanup-restored-tap-config.json")["value"]
assert before_tap[:6]+before_tap[7:]==after_tap[:6]+after_tap[7:],(before_tap,after_tap)
def status(payload):
    rows=payload.get("aria_acl_port_statuses") or []
    row=next((x for x in rows if x.get("port_id")==port_id),None)
    if row is None:
        return None
    return {k:row.get(k) for k in ("status","effective_action","effective_policy_id","binding_id")}
assert status(load("baseline-port-status.json"))==status(load("cleanup-restored-port-status.json")),(
    status(load("baseline-port-status.json")),status(load("cleanup-restored-port-status.json")))
PY
}

write_summary() {
    printf '%s\n' "${cleanup_errors[@]:-}" >"${WORK_DIR}/cleanup-errors.txt" || return 1
    RESULT="${RESULT}" FAILURE_REASON="${FAILURE_REASON}" WORK_DIR="${WORK_DIR}" \
    BODY_SUCCEEDED="${BODY_SUCCEEDED}" XDP_NO_ACL_CT="${XDP_NO_ACL_CT}" \
    TC_INGRESS_HIT="${TC_INGRESS_HIT}" TC_EGRESS_HIT="${TC_EGRESS_HIT}" \
    STATELESS_ZERO_CT="${STATELESS_ZERO_CT}" NO_INGRESS_DOUBLE_COUNT="${NO_INGRESS_DOUBLE_COUNT}" \
    TC_LINK_REQUIRED="${TC_LINK_REQUIRED}" BANK_REVALIDATED="${BANK_REVALIDATED}" \
    DENY_ZERO_CT="${DENY_ZERO_CT}" IP_FAMILY="${IP_FAMILY}" \
    EXACT_SELECTOR_FIXTURE_STATUS="${EXACT_SELECTOR_FIXTURE_STATUS}" \
    MORE_SPECIFIC_SELECTOR_FIXTURE_STATUS="${MORE_SPECIFIC_SELECTOR_FIXTURE_STATUS}" \
    LEGACY_SELECTOR_REPAIR_FIXTURE_STATUS="${LEGACY_SELECTOR_REPAIR_FIXTURE_STATUS}" \
    LEGACY_RESTART_REPAIR_GATE="${LEGACY_RESTART_REPAIR_GATE}" \
    LEGACY_REPAIR_MODE="${LEGACY_REPAIR_MODE}" \
    SELECTOR_FIXTURE_SCOPE="${SELECTOR_FIXTURE_SCOPE}" \
    TC_ATTACHMENT_MODE="${TC_ATTACHMENT_MODE}" \
    FRAGMENT_TRACKING_SMOKE="${FRAGMENT_TRACKING_SMOKE}" \
    FRAGMENT_BODY_SUCCEEDED="${FRAGMENT_BODY_SUCCEEDED}" \
    FRAGMENT_TRANSITIONS_VERIFIED="${FRAGMENT_TRANSITIONS_VERIFIED}" \
        python3 >"${WORK_DIR}/summary.json.tmp" <<'PY' || return 1
import json,os
keys=("XDP_NO_ACL_CT","TC_INGRESS_HIT","TC_EGRESS_HIT","STATELESS_ZERO_CT",
      "NO_INGRESS_DOUBLE_COUNT","TC_LINK_REQUIRED","BANK_REVALIDATED","DENY_ZERO_CT")
cleanup_errors=[line.rstrip("\n") for line in open(os.path.join(os.environ["WORK_DIR"],"cleanup-errors.txt"),encoding="utf-8") if line.rstrip("\n")]
selector_fixtures={
    "exact":os.environ["EXACT_SELECTOR_FIXTURE_STATUS"],
    "more_specific":os.environ["MORE_SPECIFIC_SELECTOR_FIXTURE_STATUS"],
    "legacy_repair":os.environ["LEGACY_SELECTOR_REPAIR_FIXTURE_STATUS"],
}
selector_isolation={
    "requested_scope":os.environ["SELECTOR_FIXTURE_SCOPE"],
    "fixtures":selector_fixtures,
    "tc_attachment_mode":os.environ["TC_ATTACHMENT_MODE"],
    "legacy_restart_repair_gate":os.environ["LEGACY_RESTART_REPAIR_GATE"],
    "legacy_repair_mode":os.environ["LEGACY_REPAIR_MODE"],
    "complete":all(status=="pass" for status in selector_fixtures.values()),
}
if os.environ["FRAGMENT_TRACKING_SMOKE"] != "1":
    fragment_status="skipped"
elif (os.environ["FRAGMENT_BODY_SUCCEEDED"].lower()=="true" and
      os.environ["FRAGMENT_TRANSITIONS_VERIFIED"].lower()=="true" and
      os.environ["RESULT"]=="pass" and not cleanup_errors):
    fragment_status="pass"
else:
    fragment_status="fail"
out={"result":os.environ["RESULT"],"failure_reason":os.environ["FAILURE_REASON"],
     "body_succeeded":os.environ["BODY_SUCCEEDED"].lower()=="true",
     "cleanup_errors":cleanup_errors,"work_dir":os.environ["WORK_DIR"],
     "real_tap":True,"ip_family":os.environ["IP_FAMILY"],
     "checks":{k:os.environ[k].lower()=="true" for k in keys},
     "selector_isolation":selector_isolation,
     "fragment_tracking":{"status":fragment_status,
                          "enabled":os.environ["FRAGMENT_TRACKING_SMOKE"]=="1",
                          "body_succeeded":os.environ["FRAGMENT_BODY_SUCCEEDED"].lower()=="true",
                          "transitions_verified":os.environ["FRAGMENT_TRANSITIONS_VERIFIED"].lower()=="true"}}
print(json.dumps(out,sort_keys=True,indent=2))
PY
    mv "${WORK_DIR}/summary.json.tmp" "${WORK_DIR}/summary.json" || return 1
    EGRESS_MISS_DELTA="${egress_miss_delta}" EGRESS_HIT_DELTA="${egress_hit_delta}" \
    INGRESS_HIT_DELTA="${ingress_hit_delta}" PACKET_DELTA="${packet_delta}" \
    BYTE_DELTA="${byte_delta}" RULE_PACKET_DELTA="${rule_packet_delta}" \
    BANK_STALE_DELTA="${bank_stale_delta}" BANK_MISS_DELTA="${bank_miss_delta}" \
    BANK_HIT_DELTA="${bank_hit_delta}" STATELESS_HIT_DELTA="${stateless_hit_delta}" \
    STATELESS_DISABLED_DELTA="${stateless_disabled_delta}" DENY_DROP_DELTA="${deny_drop_delta}" \
        python3 >"${WORK_DIR}/counter-deltas.json" <<'PY' || return 1
import json,os
print(json.dumps({k.lower():int(v) for k,v in os.environ.items() if k.endswith("_DELTA")},sort_keys=True,indent=2))
PY
}

cleanup() {
    local body_rc=$? final_rc=1 id output
    trap - EXIT
    set +e
    if ! cleanup_selector_fixture_state; then
        record_cleanup_error "cleanup-selector-fixture-state failed"
    fi
    if ! cleanup_selector_rule_attempt; then
        record_cleanup_error "cleanup-selector-rule-attempt failed"
    fi
    printf '%s\n' "${created_rule_ids[@]:-}" >"${WORK_DIR}/created-rule-ids.txt"
    if ! stop_trace_filter >"${WORK_DIR}/cleanup-trace-stop.log" 2>&1; then
        record_cleanup_error "cleanup-trace-stop failed"
    fi
    for id in "${rule_ids[@]:-}"; do
        [ -n "${id}" ] || continue
        output="${WORK_DIR}/cleanup-delete-rule-${id}.txt"
        if ! curl_body DELETE "aria-acl-rules/${id}" >"${output}" 2>&1; then
            record_cleanup_error "cleanup-delete-rule-${id} failed"
        fi
    done
    if [ -n "${binding_id}" ]; then
        if ! curl_body DELETE "aria-acl-bindings/${binding_id}" >"${WORK_DIR}/cleanup-delete-binding.txt" 2>&1; then
            record_cleanup_error "cleanup-delete-binding failed"
        fi
    fi
    if [ -n "${policy_id}" ]; then
        if ! curl_body DELETE "aria-acl-policies/${policy_id}" >"${WORK_DIR}/cleanup-delete-policy.txt" 2>&1; then
            record_cleanup_error "cleanup-delete-policy failed"
        fi
    fi
    if [ "${RESYNC_ROLLBACK_ARMED}" = true ]; then
        if ! run_full_resync >"${WORK_DIR}/cleanup-full-resync.log" 2>&1; then
            record_cleanup_error "cleanup-full-resync failed"
        fi
    fi
    if [ "${BASELINE_CAPTURED}" = true ]; then
        if ! verify_cleanup_restored >"${WORK_DIR}/cleanup-verify.log" 2>&1; then
            record_cleanup_error "verify_cleanup_restored failed"
        fi
    elif [ "${BODY_SUCCEEDED}" = true ]; then
        record_cleanup_error "successful body has no baseline for cleanup verification"
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

need_command bpftool
need_command curl
need_command docker
need_command ip
need_command ping
need_command tc
[ -n "${EXPECTED_PORT_ID}" ] || die "EXPECTED_PORT_ID is required"
[ -r "${ADMIN_RC_FILE}" ] || die "Kolla credentials file is not readable: ${ADMIN_RC_FILE}"
[ -S "${NEUTRON_UDS}" ] || die "Neutron UDS is not available: ${NEUTRON_UDS}"
ip link show dev "${EXPECTED_IFNAME}" >/dev/null 2>&1 || die "EXPECTED_IFNAME does not exist"

if python3 - "${VM_IP}" <<'PY'
import ipaddress,sys
raise SystemExit(0 if ipaddress.ip_address(sys.argv[1]).version==4 else 1)
PY
then
    IP_FAMILY="ipv4"
    IP_FAMILY_LABEL="icmp"
    ACL_PROTOCOL="icmp"
    TRACE_PROTOCOL="icmp"
    CT_PROTOCOL="icmp"
    METRIC_FAMILY="ipv4"
    PING_ARGS=()
else
    IP_FAMILY="ipv6"
    IP_FAMILY_LABEL="ipv6-icmp"
    ACL_PROTOCOL="58"
    TRACE_PROTOCOL="58"
    CT_PROTOCOL="58"
    METRIC_FAMILY="ipv6"
    PING_ARGS=(-6)
fi

route_line="$(ip "${PING_ARGS[@]}" route get "${VM_IP}" | head -1)"
SOURCE_IP="$(printf '%s\n' "${route_line}" | awk '{for(i=1;i<=NF;i++) if($i=="src"){print $(i+1);exit}}')"
[ -n "${SOURCE_IP}" ] || die "cannot resolve controlled ${IP_FAMILY_LABEL} source IP for ${VM_IP}"

TOKEN="$(docker exec -u root --env-file "${ADMIN_RC_FILE}" openstack_client \
    openstack token issue -f value -c id | tail -1)"
[ -n "${TOKEN}" ] || die "failed to obtain token from existing Kolla credentials"

assert_tc_attachment_ready >"${WORK_DIR}/tc-attachment-mode.json"
TC_ATTACHMENT_MODE="$(json_field mode <"${WORK_DIR}/tc-attachment-mode.json")"
[ "${TC_ATTACHMENT_MODE}" = "tcx" ] || [ "${TC_ATTACHMENT_MODE}" = "legacy" ] \
    || die "unsupported TC attachment mode: ${TC_ATTACHMENT_MODE}"
TC_LINK_REQUIRED=true

capture baseline
python3 - "${WORK_DIR}/baseline-config.json" <<'PY'
import json,sys
payload=json.load(open(sys.argv[1],encoding="utf-8"))
assert payload.get("monitoring") is True,"ACL rule-counter authority proof requires monitoring=true"
PY
run_controlled_traffic baseline 2 pass
BASELINE_CAPTURED=true

policy_body="$(printf '{"aria_acl_policy":{"name":"%s","default_action":"allow","stateful":true}}' "${RUN_ID}")"
policy_id="$(curl_body POST aria-acl-policies "${policy_body}" | tee "${WORK_DIR}/policy-create.json" | json_field aria_acl_policy.id)"
[ -n "${policy_id}" ] || die "failed to create stateful policy"
create_rule ingress allow
create_rule egress allow
binding_body="$(printf '{"aria_acl_binding":{"policy_id":"%s","target_type":"port","target_id":"%s"}}' \
    "${policy_id}" "${EXPECTED_PORT_ID}")"
binding_id="$(curl_body POST aria-acl-bindings "${binding_body}" | tee "${WORK_DIR}/binding-create.json" | json_field aria_acl_binding.id)"
[ -n "${binding_id}" ] || die "failed to create binding"
RESYNC_ROLLBACK_ARMED=true

run_stateful_evidence
capture bank-pre-resync
create_rule ingress allow tcp 200
run_bank_evidence
update_policy_stateful false
run_stateless_evidence
delete_rules_for_transition
update_policy_stateful true
create_rule ingress drop
create_rule egress drop
run_deny_evidence
case "${SELECTOR_FIXTURE_SCOPE}" in
    all)
        prepare_owned_selector_fixture
        run_exact_selector_isolation_fixture
        run_more_specific_selector_isolation_fixture
        run_legacy_selector_repair_fixture
        ;;
    legacy_repair)
        prepare_owned_selector_fixture
        EXACT_SELECTOR_FIXTURE_STATUS="covered_by_prior_evidence"
        MORE_SPECIFIC_SELECTOR_FIXTURE_STATUS="covered_by_prior_evidence"
        run_legacy_selector_repair_fixture
        ;;
    none)
        EXACT_SELECTOR_FIXTURE_STATUS="not_requested"
        MORE_SPECIFIC_SELECTOR_FIXTURE_STATUS="not_requested"
        LEGACY_SELECTOR_REPAIR_FIXTURE_STATUS="not_requested"
        LEGACY_RESTART_REPAIR_GATE="not_requested"
        LEGACY_REPAIR_MODE="not_requested"
        ;;
    *) die "unsupported SELECTOR_FIXTURE_SCOPE: ${SELECTOR_FIXTURE_SCOPE}" ;;
esac
run_fragment_tracking_field_smoke

BODY_SUCCEEDED=true
FAILURE_REASON=""
echo "TC ACL smoke body passed; cleanup verification will determine final result in ${WORK_DIR}/summary.json"
