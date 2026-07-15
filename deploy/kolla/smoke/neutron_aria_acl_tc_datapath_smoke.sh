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
EXPECTED_PORT_ID="${EXPECTED_PORT_ID:-}"
PING_PAYLOAD_BYTES="${PING_PAYLOAD_BYTES:-56}"
RUN_ID="${RUN_ID:-acl-tc-datapath-$(date +%Y%m%d%H%M%S)-$(hostname -s)}"

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
        curl --fail-with-body -sS -H "X-Auth-Token: ${TOKEN}" \
            -H 'Content-Type: application/json' -X "${method}" -d "${data}" \
            "${LOCAL_NEUTRON_URL}/${path}"
    else
        curl --fail-with-body -sS -H "X-Auth-Token: ${TOKEN}" \
            -X "${method}" "${LOCAL_NEUTRON_URL}/${path}"
    fi
}

datapath_get() {
    curl --fail-with-body -sS "${DATAPATH_HTTP}$1"
}

run_full_resync() {
    docker exec -u "${EXEC_USER}" "${SERVICE_NAME}" neutron-aria-agent \
        --config-file "${AGENT_CONFIG}" --once --enable-full-resync
}

set_trace_filter() {
    local src_ip="$1" dst_ip="$2" body
    body="$(printf '{"src_ip":"%s","dst_ip":"%s","src_port":0,"dst_port":0,"proto":"%s"}' \
        "${src_ip}" "${dst_ip}" "${TRACE_PROTOCOL}")"
    curl --fail-with-body -sS -H 'Content-Type: application/json' \
        -X POST -d "${body}" "${DATAPATH_HTTP}/api/v1/${EXPECTED_IFNAME}/trace" \
        >"${WORK_DIR}/trace-filter-$(date +%s%N).json"
    TRACE_ARMED=true
}

stop_trace_filter() {
    [ "${TRACE_ARMED}" = true ] || return 0
    curl --fail-with-body -sS -X DELETE \
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
    python3 - "${payload}" "${EXPECTED_PORT_ID}" "${EXPECTED_IFNAME}" <<'PY'
import json,sys
p=json.load(open(sys.argv[1],encoding="utf-8")); port_id=sys.argv[2]; ifname=sys.argv[3]
rows=p.get("aria_acl_port_statuses") or p.get("port_statuses") or []
row=next((r for r in rows if r.get("port_id")==port_id),None)
assert row is not None,(port_id,rows)
assert row.get("ifname")==ifname,row
assert row.get("status") in ("ready","enforced"),row
action=row.get("effective_action")
if action is None:
    action=next((d for d in row.get("domains",[]) if d.get("domain")=="acl"),{}).get("effective_action")
assert action in ("enforce","enforced"),row
PY
}

wait_port_enforced() {
    local i payload
    for i in $(seq 1 15); do
        payload="${WORK_DIR}/wait-port-enforced-${i}.json"
        curl_body GET aria-acl-port-statuses >"${payload}"
        if assert_port_enforced "${payload}" 2>"${WORK_DIR}/wait-port-enforced-${i}.err"; then
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
v=json.load(open(sys.argv[1]))["value"]
print(struct.unpack("=I",bytes(v[:4]))[0])
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
v=json.load(open(sys.argv[1]))["value"]
assert len(v)==8,v
assert v[7]==int(sys.argv[2]),{"compatibility_byte":v[7],"expected":int(sys.argv[2])}
print(v[6],v[7])
PY
}

capture() {
    local label="$1"
    datapath_get /api/v1/instances >"${WORK_DIR}/${label}-instances.json" || return 1
    datapath_get "/api/v1/${EXPECTED_IFNAME}/config" >"${WORK_DIR}/${label}-config.json" || return 1
    datapath_get "/api/v1/${EXPECTED_IFNAME}/conntrack" >"${WORK_DIR}/${label}-conntrack.json" || return 1
    datapath_get "/api/v1/${EXPECTED_IFNAME}/stats/rules" >"${WORK_DIR}/${label}-rules.json" || return 1
    datapath_get /metrics >"${WORK_DIR}/${label}-metrics.prom" || return 1
    curl --fail-with-body -sS --unix-socket "${NEUTRON_UDS}" \
        http://localhost/api/v1/neutron/status >"${WORK_DIR}/${label}-neutron-status.json" || return 1
    curl_body GET aria-acl-port-statuses >"${WORK_DIR}/${label}-port-status.json" || return 1
    ip -details link show dev "${EXPECTED_IFNAME}" >"${WORK_DIR}/${label}-link.txt" || return 1
    tc -j filter show dev "${EXPECTED_IFNAME}" ingress >"${WORK_DIR}/${label}-tc-ingress.json" || return 1
    tc -j filter show dev "${EXPECTED_IFNAME}" egress >"${WORK_DIR}/${label}-tc-egress.json" || return 1
    bpftool -j net show >"${WORK_DIR}/${label}-bpftool-net.json" || return 1
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
        python3 >"${WORK_DIR}/summary.json.tmp" <<'PY' || return 1
import json,os
keys=("XDP_NO_ACL_CT","TC_INGRESS_HIT","TC_EGRESS_HIT","STATELESS_ZERO_CT",
      "NO_INGRESS_DOUBLE_COUNT","TC_LINK_REQUIRED","BANK_REVALIDATED","DENY_ZERO_CT")
cleanup_errors=[line.rstrip("\n") for line in open(os.path.join(os.environ["WORK_DIR"],"cleanup-errors.txt"),encoding="utf-8") if line.rstrip("\n")]
out={"result":os.environ["RESULT"],"failure_reason":os.environ["FAILURE_REASON"],
     "body_succeeded":os.environ["BODY_SUCCEEDED"].lower()=="true",
     "cleanup_errors":cleanup_errors,"work_dir":os.environ["WORK_DIR"],
     "real_tap":True,"ip_family":os.environ["IP_FAMILY"],
     "checks":{k:os.environ[k].lower()=="true" for k in keys}}
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

for link in "${PIN_ROOT}/${EXPECTED_IFNAME}_tc_ingress_link" "${PIN_ROOT}/${EXPECTED_IFNAME}_tc_egress_link"; do
    [ -e "${link}" ] || die "TC_LINK_REQUIRED missing ${link}"
done
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

BODY_SUCCEEDED=true
FAILURE_REASON=""
echo "TC ACL smoke body passed; cleanup verification will determine final result in ${WORK_DIR}/summary.json"
