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

# Stable evidence markers consumed by Stage 1 and by operators reviewing summary.json.
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
RESULT=fail
FAILURE_REASON="smoke did not complete"
egress_miss_delta=0
egress_hit_delta=0
ingress_hit_delta=0
packet_delta=0
byte_delta=0
bank_stale_delta=0
bank_miss_delta=0
bank_hit_delta=0
stateless_hit_delta=0
stateless_disabled_delta=0

policy_id=""
binding_id=""
rule_ids=()
RESYNC_ROLLBACK_ARMED=false
TRACE_ARMED=false
TOKEN=""

die() {
    FAILURE_REASON="$*"
    echo "ERROR: $*" >&2
    exit 1
}

need_command() {
    command -v "$1" >/dev/null 2>&1 || die "missing command: $1"
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
    local src_ip="$1" dst_ip="$2"
    local body
    body="$(printf '{"src_ip":"%s","dst_ip":"%s","src_port":0,"dst_port":0,"proto":"icmp"}' \
        "${src_ip}" "${dst_ip}")"
    curl --fail-with-body -sS -H 'Content-Type: application/json' \
        -X POST -d "${body}" "${DATAPATH_HTTP}/api/v1/${EXPECTED_IFNAME}/trace" \
        >"${WORK_DIR}/trace-filter-$(date +%s%N).json"
    TRACE_ARMED=true
}

stop_trace_filter() {
    [ "${TRACE_ARMED}" = true ] || return 0
    curl -sS -X DELETE "${DATAPATH_HTTP}/api/v1/${EXPECTED_IFNAME}/trace" \
        >"${WORK_DIR}/trace-filter-stop.json" 2>&1 || true
    TRACE_ARMED=false
}

metric_sum() {
    local file="$1" hook="$2" reason="$3"
    python3 - "${file}" "${EXPECTED_IFNAME}" "${hook}" "${reason}" <<'PY'
import re,sys
path,instance,hook,reason=sys.argv[1:]
total=0
for line in open(path,encoding="utf-8"):
    if not line.startswith("aria_ct_contract_packets_total{"):
        continue
    labels=dict(re.findall(r'(\w+)="([^"]*)"',line))
    if labels.get("instance")==instance and labels.get("hook")==hook and labels.get("reason")==reason:
        total += int(float(line.rsplit(None,1)[1]))
print(total)
PY
}

conntrack_totals() {
    local file="$1"
    python3 - "${file}" <<'PY'
import json,sys
p=json.load(open(sys.argv[1],encoding="utf-8"))
rows=p.get("connections") or []
print(len(rows),sum(int(x.get("packets") or 0) for x in rows),sum(int(x.get("bytes") or 0) for x in rows))
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
    acl=next((d for d in row.get("domains",[]) if d.get("domain")=="acl"),{})
    action=acl.get("effective_action")
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
    cat "${WORK_DIR}"/wait-port-enforced-*.err >&2 2>/dev/null || true
    die "managed port did not report ready/enforce"
}

capture_runtime_mode() {
    local label="$1" ifindex key_hex tap_id config_hex
    ifindex="$(cat "/sys/class/net/${EXPECTED_IFNAME}/ifindex")"
    key_hex="$(python3 - "${ifindex}" <<'PY'
import struct,sys
print(" ".join("%02x"%b for b in struct.pack("=I",int(sys.argv[1]))))
PY
)"
    bpftool -j map lookup pinned "${PIN_ROOT}/IFACE_CTX_MAP" key hex ${key_hex} \
        >"${WORK_DIR}/${label}-iface-ctx.json"
    tap_id="$(python3 - "${WORK_DIR}/${label}-iface-ctx.json" <<'PY'
import json,struct,sys
v=json.load(open(sys.argv[1]))["value"]
print(struct.unpack("=I",bytes(v[:4]))[0])
PY
)"
    config_hex="$(python3 - "${tap_id}" <<'PY'
import struct,sys
print(" ".join("%02x"%b for b in struct.pack("=I",int(sys.argv[1]))))
PY
)"
    bpftool -j map lookup pinned "${PIN_ROOT}/TAP_CONFIG_MAP" key hex ${config_hex} \
        >"${WORK_DIR}/${label}-tap-config.json"
    python3 - "${WORK_DIR}/${label}-tap-config.json" "${ACL_INGRESS_HOOK_TC}" <<'PY'
import json,sys
v=json.load(open(sys.argv[1]))["value"]
assert len(v)==8,v
assert v[7]==int(sys.argv[2]),{"acl_ingress_hook":v[7],"expected":int(sys.argv[2])}
print(v[6],v[7])
PY
}

capture() {
    local label="$1"
    datapath_get /api/v1/instances >"${WORK_DIR}/${label}-instances.json"
    datapath_get "/api/v1/${EXPECTED_IFNAME}/config" >"${WORK_DIR}/${label}-config.json"
    datapath_get "/api/v1/${EXPECTED_IFNAME}/conntrack" >"${WORK_DIR}/${label}-conntrack.json"
    datapath_get /metrics >"${WORK_DIR}/${label}-metrics.prom"
    curl --fail-with-body -sS --unix-socket "${NEUTRON_UDS}" \
        http://localhost/api/v1/neutron/status >"${WORK_DIR}/${label}-neutron-status.json"
    curl_body GET aria-acl-port-statuses >"${WORK_DIR}/${label}-port-status.json"
    ip -details link show dev "${EXPECTED_IFNAME}" >"${WORK_DIR}/${label}-link.txt"
    tc -j filter show dev "${EXPECTED_IFNAME}" ingress >"${WORK_DIR}/${label}-tc-ingress.json"
    tc -j filter show dev "${EXPECTED_IFNAME}" egress >"${WORK_DIR}/${label}-tc-egress.json"
    bpftool -j net show >"${WORK_DIR}/${label}-bpftool-net.json"
    bpftool -j map dump pinned "${PIN_ROOT}/CT_CONTRACT_STATS" \
        >"${WORK_DIR}/${label}-ct-contract-map.json"
    capture_runtime_mode "${label}" >"${WORK_DIR}/${label}-runtime-mode.txt"
}

create_rule() {
    local direction="$1" action="$2" protocol="${3:-icmp}" priority="${4:-100}" body id
    body="$(printf '{"aria_acl_rule":{"policy_id":"%s","direction":"%s","priority":%s,"action":"%s","protocol":"%s"}}' \
        "${policy_id}" "${direction}" "${priority}" "${action}" "${protocol}")"
    id="$(curl_body POST aria-acl-rules "${body}" | tee "${WORK_DIR}/rule-${direction}-${action}-${protocol}-$(date +%s%N).json" | json_field aria_acl_rule.id)"
    [ -n "${id}" ] || die "failed to create ${direction} ${action} rule"
    rule_ids+=("${id}")
}

delete_rules() {
    local id
    for id in "${rule_ids[@]:-}"; do
        [ -n "${id}" ] && curl_body DELETE "aria-acl-rules/${id}" >/dev/null
    done
    rule_ids=()
}

update_policy_stateful() {
    local value="$1" body
    body="$(printf '{"aria_acl_policy":{"stateful":%s}}' "${value}")"
    curl_body PUT "aria-acl-policies/${policy_id}" "${body}" \
        >"${WORK_DIR}/policy-stateful-${value}.json"
}

write_summary() {
    RESULT="${RESULT}" FAILURE_REASON="${FAILURE_REASON}" \
    XDP_NO_ACL_CT="${XDP_NO_ACL_CT}" TC_INGRESS_HIT="${TC_INGRESS_HIT}" \
    TC_EGRESS_HIT="${TC_EGRESS_HIT}" STATELESS_ZERO_CT="${STATELESS_ZERO_CT}" \
    NO_INGRESS_DOUBLE_COUNT="${NO_INGRESS_DOUBLE_COUNT}" TC_LINK_REQUIRED="${TC_LINK_REQUIRED}" \
    BANK_REVALIDATED="${BANK_REVALIDATED}" DENY_ZERO_CT="${DENY_ZERO_CT}" \
    WORK_DIR="${WORK_DIR}" python3 - <<'PY' >"${WORK_DIR}/summary.json.tmp"
import json,os
keys=("XDP_NO_ACL_CT","TC_INGRESS_HIT","TC_EGRESS_HIT","STATELESS_ZERO_CT",
      "NO_INGRESS_DOUBLE_COUNT","TC_LINK_REQUIRED","BANK_REVALIDATED","DENY_ZERO_CT")
out={"result":os.environ["RESULT"],"failure_reason":os.environ["FAILURE_REASON"],
     "work_dir":os.environ["WORK_DIR"],"real_tap":True,
     "checks":{k:os.environ[k].lower()=="true" for k in keys}}
print(json.dumps(out,sort_keys=True,indent=2))
PY
    mv "${WORK_DIR}/summary.json.tmp" "${WORK_DIR}/summary.json"
    EGRESS_MISS_DELTA="${egress_miss_delta}" EGRESS_HIT_DELTA="${egress_hit_delta}" \
    INGRESS_HIT_DELTA="${ingress_hit_delta}" PACKET_DELTA="${packet_delta}" \
    BYTE_DELTA="${byte_delta}" BANK_STALE_DELTA="${bank_stale_delta}" \
    BANK_MISS_DELTA="${bank_miss_delta}" BANK_HIT_DELTA="${bank_hit_delta}" \
    STATELESS_HIT_DELTA="${stateless_hit_delta}" \
    STATELESS_DISABLED_DELTA="${stateless_disabled_delta}" \
        python3 >"${WORK_DIR}/counter-deltas.json" <<'PY'
import json,os
print(json.dumps({k.lower():int(v) for k,v in os.environ.items() if k.endswith("_DELTA")},
                 sort_keys=True,indent=2))
PY
}

cleanup() {
    local rc=$? id
    set +e
    stop_trace_filter
    for id in "${rule_ids[@]:-}"; do
        [ -n "${id}" ] && curl_body DELETE "aria-acl-rules/${id}" >/dev/null 2>&1
    done
    [ -n "${binding_id}" ] && curl_body DELETE "aria-acl-bindings/${binding_id}" >/dev/null 2>&1
    [ -n "${policy_id}" ] && curl_body DELETE "aria-acl-policies/${policy_id}" >/dev/null 2>&1
    [ "${RESYNC_ROLLBACK_ARMED}" = true ] && run_full_resync >"${WORK_DIR}/cleanup-full-resync.log" 2>&1
    if [ "${RESULT}" != pass ] && [ "${FAILURE_REASON}" = "smoke did not complete" ]; then
        FAILURE_REASON="command failed with rc=${rc}"
    fi
    write_summary
    exit "${rc}"
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
route_line="$(ip route get "${VM_IP}" | head -1)"
SOURCE_IP="$(printf '%s\n' "${route_line}" | awk '{for(i=1;i<=NF;i++) if($i=="src"){print $(i+1);exit}}')"
[ -n "${SOURCE_IP}" ] || die "cannot resolve controlled source IP for ${VM_IP}"

TOKEN="$(docker exec -u root --env-file "${ADMIN_RC_FILE}" openstack_client \
    openstack token issue -f value -c id | tail -1)"
[ -n "${TOKEN}" ] || die "failed to obtain token from existing Kolla credentials"

for link in "${PIN_ROOT}/${EXPECTED_IFNAME}_tc_ingress_link" "${PIN_ROOT}/${EXPECTED_IFNAME}_tc_egress_link"; do
    [ -e "${link}" ] || die "TC_LINK_REQUIRED missing ${link}"
done
TC_LINK_REQUIRED=true

capture before

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
run_full_resync | tee "${WORK_DIR}/stateful-full-resync.log"
wait_port_enforced
capture stateful-ready
assert_port_enforced "${WORK_DIR}/stateful-ready-port-status.json"

# Egress controlled-flow evidence: first request is a miss, later requests hit.
set_trace_filter "${SOURCE_IP}" "${VM_IP}"
capture egress-before
ping -c "${TRAFFIC_PACKETS}" -s "${PING_PAYLOAD_BYTES}" "${VM_IP}" \
    >"${WORK_DIR}/stateful-egress-traffic.log" 2>&1
capture egress-after
egress_miss_delta=$(( $(metric_sum "${WORK_DIR}/egress-after-metrics.prom" tc_egress ct_miss) - $(metric_sum "${WORK_DIR}/egress-before-metrics.prom" tc_egress ct_miss) ))
egress_hit_delta=$(( $(metric_sum "${WORK_DIR}/egress-after-metrics.prom" tc_egress ct_hit) - $(metric_sum "${WORK_DIR}/egress-before-metrics.prom" tc_egress ct_hit) ))
[ "${egress_miss_delta}" -ge 1 ] || die "stateful egress did not record initial ct_miss"
[ "${egress_hit_delta}" -ge "${MIN_HIT_PACKETS}" ] || die "stateful egress ct_hit delta ${egress_hit_delta} is below ${MIN_HIT_PACKETS}"
TC_EGRESS_HIT=true

# Reverse controlled-flow evidence proves the authoritative ingress hook hits CT.
set_trace_filter "${VM_IP}" "${SOURCE_IP}"
capture ingress-before
ping -c "${TRAFFIC_PACKETS}" -s "${PING_PAYLOAD_BYTES}" "${VM_IP}" \
    >"${WORK_DIR}/stateful-ingress-traffic.log" 2>&1
capture ingress-after
ingress_hit_delta=$(( $(metric_sum "${WORK_DIR}/ingress-after-metrics.prom" tc_ingress ct_hit) - $(metric_sum "${WORK_DIR}/ingress-before-metrics.prom" tc_ingress ct_hit) ))
[ "${ingress_hit_delta}" -ge "${MIN_HIT_PACKETS}" ] || die "stateful ingress ct_hit delta ${ingress_hit_delta} is below ${MIN_HIT_PACKETS}"
TC_INGRESS_HIT=true

read -r _ before_packets before_bytes < <(conntrack_totals "${WORK_DIR}/stateful-ready-conntrack.json")
read -r stateful_ct stateful_packets stateful_bytes < <(conntrack_totals "${WORK_DIR}/ingress-after-conntrack.json")
expected_observations=$((TRAFFIC_PACKETS * 4))
min_bytes=$((expected_observations * (PING_PAYLOAD_BYTES + 28)))
max_bytes=$((expected_observations * (PING_PAYLOAD_BYTES + 60)))
packet_delta=$((stateful_packets - before_packets))
byte_delta=$((stateful_bytes - before_bytes))
[ "${stateful_ct}" -ge 1 ] || die "stateful traffic created no CT entry"
[ "${packet_delta}" -eq "${expected_observations}" ] || die "NO_INGRESS_DOUBLE_COUNT expected ${expected_observations} observations, got ${packet_delta}"
[ "${byte_delta}" -ge "${min_bytes}" ] && [ "${byte_delta}" -le "${max_bytes}" ] || \
    die "CT byte delta ${byte_delta} is outside generated-traffic bounds ${min_bytes}..${max_bytes}"
NO_INGRESS_DOUBLE_COUNT=true
unknown_hook_delta="$(python3 - "${WORK_DIR}/egress-before-metrics.prom" "${WORK_DIR}/ingress-after-metrics.prom" "${EXPECTED_IFNAME}" <<'PY'
import re,sys
def total(path):
    n=0
    for line in open(path):
        if line.startswith("aria_ct_contract_packets_total{"):
            labels=dict(re.findall(r'(\w+)="([^"]*)"',line))
            if labels.get("instance")==sys.argv[3] and labels.get("hook") not in ("tc_ingress","tc_egress"):
                n += int(float(line.rsplit(None,1)[1]))
    return n
print(total(sys.argv[2])-total(sys.argv[1]))
PY
)"
[ "${unknown_hook_delta}" -eq 0 ] || die "XDP_NO_ACL_CT found non-TC contract events"
XDP_NO_ACL_CT=true

# A real bank transition must revalidate with stale_bank or ct_miss before hits.
old_bank="$(awk '{print $1}' "${WORK_DIR}/ingress-after-runtime-mode.txt")"
create_rule ingress allow tcp 200
run_full_resync | tee "${WORK_DIR}/bank-transition-full-resync.log"
set_trace_filter "${SOURCE_IP}" "${VM_IP}"
capture bank-before
new_bank="$(awk '{print $1}' "${WORK_DIR}/bank-before-runtime-mode.txt")"
[ "${new_bank}" != "${old_bank}" ] || die "ACL bank did not transition"
ping -c "${TRAFFIC_PACKETS}" -s "${PING_PAYLOAD_BYTES}" "${VM_IP}" \
    >"${WORK_DIR}/bank-transition-traffic.log" 2>&1
capture bank-after
bank_stale_delta=$(( $(metric_sum "${WORK_DIR}/bank-after-metrics.prom" tc_egress stale_bank) - $(metric_sum "${WORK_DIR}/bank-before-metrics.prom" tc_egress stale_bank) ))
bank_miss_delta=$(( $(metric_sum "${WORK_DIR}/bank-after-metrics.prom" tc_egress ct_miss) - $(metric_sum "${WORK_DIR}/bank-before-metrics.prom" tc_egress ct_miss) ))
bank_hit_delta=$(( $(metric_sum "${WORK_DIR}/bank-after-metrics.prom" tc_egress ct_hit) - $(metric_sum "${WORK_DIR}/bank-before-metrics.prom" tc_egress ct_hit) ))
[ $((bank_stale_delta + bank_miss_delta)) -ge 1 ] || die "bank transition did not record stale/miss revalidation"
[ "${bank_hit_delta}" -ge "${MIN_HIT_PACKETS}" ] || die "bank transition did not return to CT hits"
BANK_REVALIDATED=true

# Stateless publication must keep ACL active while producing no CT entry or hit.
update_policy_stateful false
run_full_resync | tee "${WORK_DIR}/stateless-full-resync.log"
set_trace_filter "${SOURCE_IP}" "${VM_IP}"
capture stateless-before
ping -c "${TRAFFIC_PACKETS}" -s "${PING_PAYLOAD_BYTES}" "${VM_IP}" \
    >"${WORK_DIR}/stateless-traffic.log" 2>&1
capture stateless-after
read -r stateless_ct _ _ < <(conntrack_totals "${WORK_DIR}/stateless-after-conntrack.json")
stateless_hit_delta=$(( $(metric_sum "${WORK_DIR}/stateless-after-metrics.prom" tc_egress ct_hit) - $(metric_sum "${WORK_DIR}/stateless-before-metrics.prom" tc_egress ct_hit) ))
stateless_disabled_delta=$(( $(metric_sum "${WORK_DIR}/stateless-after-metrics.prom" tc_egress ct_disabled) - $(metric_sum "${WORK_DIR}/stateless-before-metrics.prom" tc_egress ct_disabled) ))
[ "${stateless_ct}" -eq 0 ] && [ "${stateless_hit_delta}" -eq 0 ] && [ "${stateless_disabled_delta}" -ge 1 ] || \
    die "STATELESS_ZERO_CT failed ct=${stateless_ct} hit=${stateless_hit_delta} disabled=${stateless_disabled_delta}"
STATELESS_ZERO_CT=true

# Deny traffic must never create CT. Replace allow rules to avoid overlap ambiguity.
delete_rules
update_policy_stateful true
create_rule ingress drop
create_rule egress drop
run_full_resync | tee "${WORK_DIR}/deny-full-resync.log"
set_trace_filter "${SOURCE_IP}" "${VM_IP}"
capture deny-before
if ping -c 2 -s "${PING_PAYLOAD_BYTES}" "${VM_IP}" >"${WORK_DIR}/deny-traffic.log" 2>&1; then
    die "deny ACL allowed controlled traffic"
fi
capture deny-after
read -r deny_ct _ _ < <(conntrack_totals "${WORK_DIR}/deny-after-conntrack.json")
[ "${deny_ct}" -eq 0 ] || die "deny ACL created ${deny_ct} CT entries"
DENY_ZERO_CT=true

RESULT=pass
FAILURE_REASON=""
echo "TC ACL real-tap smoke passed; evidence=${WORK_DIR} summary=${WORK_DIR}/summary.json"
