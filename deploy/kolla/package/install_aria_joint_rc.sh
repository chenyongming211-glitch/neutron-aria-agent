#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
UPGRADE_CONTROL="${UPGRADE_CONTROL:-${SCRIPT_DIR}/aria_upgrade_control.py}"
DATAPATH_INSTALLER="${DATAPATH_INSTALLER:-${SCRIPT_DIR}/install_aria_datapath_rc_image.sh}"
AGENT_INSTALLER="${AGENT_INSTALLER:-${SCRIPT_DIR}/install_neutron_aria_agent_rc_image.sh}"
CURRENT_MANIFEST="${CURRENT_MANIFEST:-}"
CANDIDATE_MANIFEST="${CANDIDATE_MANIFEST:-}"
CURRENT_ARTIFACT_ROOT="${CURRENT_ARTIFACT_ROOT:-}"
CANDIDATE_ARTIFACT_ROOT="${CANDIDATE_ARTIFACT_ROOT:-}"
OPERATION_ID="${OPERATION_ID:-}"
JOINT_STATE_DIR="${JOINT_STATE_DIR:-/var/lib/aria-release}"
JOINT_LOCK_PATH="${JOINT_LOCK_PATH:-/run/lock/aria-joint-release.lock}"
LEDGER_LOCK_PATH="${LEDGER_LOCK_PATH:-${JOINT_LOCK_PATH}.ledger}"
ADMIN_SOCKET="${ADMIN_SOCKET:-/run/aria/aria-admin.sock}"
NEUTRON_SOCKET="${NEUTRON_SOCKET:-/run/aria/aria-agent.sock}"
OVS_CANARY_COMMAND="${OVS_CANARY_COMMAND:-}"
DATAPATH_IMAGE_REF="${DATAPATH_IMAGE_REF:-}"
DATAPATH_EXPECTED_IMAGE_ID="${DATAPATH_EXPECTED_IMAGE_ID:-}"
AGENT_IMAGE_REF="${AGENT_IMAGE_REF:-}"
AGENT_EXPECTED_IMAGE_ID="${AGENT_EXPECTED_IMAGE_ID:-}"
MIN_FREE_KIB="${MIN_FREE_KIB:-1048576}"
CURRENT_PHASE=preflight
UPGRADE_CLASS=planned_maintenance

usage() { echo "Usage: $0 dry-run|install|status|resume|rollback|check" >&2; }
die() { echo "ERROR: $*" >&2; exit 1; }
json_field() { python3 -c 'import json,sys; print(json.load(sys.stdin).get(sys.argv[1], ""))' "$1"; }
file_sha256() { python3 -c 'import hashlib,sys; print(hashlib.sha256(open(sys.argv[1],"rb").read()).hexdigest())' "$1"; }
config_pair_sha256() { python3 -c 'import hashlib,sys;h=hashlib.sha256();[(h.update(open(p,"rb").read()),h.update(b"\0")) for p in sys.argv[1:]];print(h.hexdigest())' "$@"; }

manifest_query() {
    python3 - "$1" "$2" "${3-}" <<'PY'
import json,re,sys
path, action, name = sys.argv[1:4]
m=json.load(open(path)); sha=re.compile(r"^[0-9a-f]{64}$")
if action=="validate":
    required={"schema_version","product","product_version","release_version","source_commit","artifacts","contracts","images","runtime_compatibility"}
    assert required.issubset(m) and m["schema_version"]==1
    assert re.match(r"^[0-9a-f]{40}$",m["source_commit"])
    required_contracts={"neutron_uds_sha256","runtime_compatibility_sha256","support_matrix_sha256"}
    assert isinstance(m["contracts"],dict) and required_contracts.issubset(m["contracts"])
    assert all(sha.match(str(m["contracts"][key])) for key in required_contracts)
    assert isinstance(m["artifacts"],list) and m["artifacts"]
    for item in m["artifacts"]:
        assert isinstance(item,dict) and isinstance(item.get("name"),str) and item["name"]
        assert not item["name"].startswith("/") and ".." not in item["name"].split("/")
        assert sha.match(str(item.get("sha256","")))
        assert type(item.get("size_bytes")) is int and item["size_bytes"]>=0
    for item in m["images"]:
        assert re.match(r"^[A-Za-z0-9._/:@-]+@sha256:[0-9a-f]{64}$",str(item.get("identity","")))
    print("valid")
elif action=="image":
    values=[x["identity"] for x in m["images"] if x.get("name")==name]; assert len(values)==1
    print("sha256:"+values[0].rsplit("@sha256:",1)[1])
elif action=="artifact":
    values=[x["sha256"] for x in m["artifacts"] if x.get("name")==name]; assert len(values)==1
    print(values[0])
PY
}

validate_manifest_artifacts() {
    local manifest="$1" root="$2" name expected recorded_size actual size
    [ -d "${root}" ] || return 1
    manifest_query "${manifest}" validate >/dev/null || return 1
    while IFS=$'\t' read -r name expected recorded_size; do
        [ -f "${root}/${name}" ] && [ ! -L "${root}/${name}" ] || return 1
        actual="$(file_sha256 "${root}/${name}")"; [ "${actual}" = "${expected}" ] || return 1
        size="$(python3 -c 'import os,sys;print(os.path.getsize(sys.argv[1]))' "${root}/${name}")"; [ "${size}" = "${recorded_size}" ] || return 1
    done < <(python3 - "${manifest}" <<'PY'
import json,sys
for item in json.load(open(sys.argv[1]))["artifacts"]: print("%s\t%s\t%s"%(item["name"],item["sha256"],item["size_bytes"]))
PY
)
}

ledger() {
    ARIA_RELEASE_OPERATIONS_DIR="${JOINT_STATE_DIR}/operations" ARIA_RELEASE_LOCK_PATH="${LEDGER_LOCK_PATH}" "${UPGRADE_CONTROL}" ledger "$@"
}
transition() {
    local evidence="${2-}"; [ -n "${evidence}" ] || evidence='{}'
    ledger transition "${CURRENT_PHASE}" "$1" "${OPERATION_ID}" "${evidence}" >/dev/null
    CURRENT_PHASE="$1"
}
fail_operation() {
    local message="$1"
    if ledger fail "${CURRENT_PHASE}" "${OPERATION_ID}" "${message}" >/dev/null; then
        echo "ERROR: ${message}; failure durably recorded" >&2; return 1
    fi
    echo "BLOCKED: ${message}; durability unknown" >&2; return 70
}
run_phase() { local label="$1"; shift; if ! "$@"; then fail_operation "${label} failed"; return $?; fi; }
admin_curl() { curl -fsS --unix-socket "${ADMIN_SOCKET}" "$@"; }
agent_curl() { curl -fsS --unix-socket "${NEUTRON_SOCKET}" "$@"; }

verify_ovs_identity() {
    [ "$(pgrep -xo ovs-vswitchd)" = "${OVS_PID}" ] || return 1
    [ "$(docker inspect -f '{{.Id}}' neutron_openvswitch_agent)" = "${OVS_AGENT_ID}" ] || return 1
    [ "$(docker inspect -f '{{.State.StartedAt}}' neutron_openvswitch_agent)" = "${OVS_AGENT_STARTED}" ] || return 1
    [ "$(docker exec neutron_openvswitch_agent ovs-vsctl --no-wait get bridge br-int _uuid)" = "${BR_INT_UUID}" ]
}
verify_live_canary() {
    [ -n "${OVS_CANARY_COMMAND}" ] && [ -x "${OVS_CANARY_COMMAND}" ] || return 1
    verify_ovs_identity || return 1
    "${OVS_CANARY_COMMAND}" "${OPERATION_ID}"
}
component() {
    local which="$1" action="$2"; verify_live_canary || return 1
    if [ "${which}" = datapath ]; then
        IMAGE_REF="${DATAPATH_IMAGE_REF}" EXPECTED_IMAGE_ID="${DATAPATH_EXPECTED_IMAGE_ID}" \
        EXPECTED_ARIA_SHA256="${DATAPATH_EXPECTED_ARIA_SHA256:-}" EXPECTED_EBPF_SHA256="${DATAPATH_EXPECTED_EBPF_SHA256:-}" \
        EXPECTED_EBPF_PERF_SHA256="${DATAPATH_EXPECTED_EBPF_PERF_SHA256:-}" OPERATION_ID="${OPERATION_ID}" \
        ADMIN_SOCKET="${ADMIN_SOCKET}" JOINT_MAINTENANCE_MODE=true FORCE_RUNTIME_MIGRATION=true "${DATAPATH_INSTALLER}" "${action}" || return 1
    else
        IMAGE_REF="${AGENT_IMAGE_REF}" EXPECTED_IMAGE_ID="${AGENT_EXPECTED_IMAGE_ID}" \
        CANDIDATE_CONFIG_SOURCE="${CANDIDATE_AGENT_CONFIG:-}" ROLLBACK_CONFIG_SOURCE="${ROLLBACK_AGENT_CONFIG:-}" \
        OPERATION_ID="${OPERATION_ID}" JOINT_MAINTENANCE_MODE=true "${AGENT_INSTALLER}" "${action}" || return 1
    fi
    verify_live_canary
}
classify() {
    UPGRADE_CLASS="$("${UPGRADE_CONTROL}" classify --current "${CURRENT_MANIFEST}" --candidate "${CANDIDATE_MANIFEST}" | json_field path)"
    case "${UPGRADE_CLASS}" in hot_agent|planned_maintenance) ;; *) UPGRADE_CLASS=planned_maintenance ;; esac
}
validate_socket() {
    python3 - "$1" "$2" <<'PY'
import os,stat,sys
item=os.lstat(sys.argv[1]); expected=sys.argv[2]
actual="%s:%s:%o"%(item.st_uid,item.st_gid,stat.S_IMODE(item.st_mode))
assert stat.S_ISSOCK(item.st_mode) and actual==expected
PY
}

capture_baseline_status() {
    BASELINE_STATUS="$(agent_curl http://localhost/status)" || return 1
    read -r PRE_ACCEPTED PRE_APPLIED PRE_HASH PRE_PORTS < <(python3 -c 'import json,sys
s=json.load(sys.stdin);a=s.get("accepted_generation");p=s.get("applied_generation");h=s.get("last_desired_hash");ports=s.get("last_managed_ports_detail")
assert type(a)is int and type(p)is int and isinstance(h,str) and len(h)==64 and s.get("pending_generation") is None
assert isinstance(ports,list) and ports and s.get("last_managed_ports")==len(ports)
ids=[x.get("port_id") for x in ports];assert all(isinstance(x,str) and x for x in ids) and len(ids)==len(set(ids));print(a,p,h,",".join(sorted(ids)))' <<<"${BASELINE_STATUS}")
}

preflight() {
    [ -f "${CURRENT_MANIFEST}" ] || die "CURRENT_MANIFEST is required"
    [ -f "${CANDIDATE_MANIFEST}" ] || die "CANDIDATE_MANIFEST is required"
    validate_manifest_artifacts "${CURRENT_MANIFEST}" "${CURRENT_ARTIFACT_ROOT}" || die "current manifest/artifacts are invalid"
    validate_manifest_artifacts "${CANDIDATE_MANIFEST}" "${CANDIDATE_ARTIFACT_ROOT}" || die "candidate manifest/artifacts are invalid"
    for value in DATAPATH_IMAGE_REF DATAPATH_EXPECTED_IMAGE_ID AGENT_IMAGE_REF AGENT_EXPECTED_IMAGE_ID; do [ -n "${!value}" ] || die "${value} is required"; done
    for path in "${ROLLBACK_DATAPATH_CONFIG:-}" "${ROLLBACK_AGENT_CONFIG:-}" "${CANDIDATE_DATAPATH_CONFIG:-}" "${CANDIDATE_AGENT_CONFIG:-}"; do
        [ -f "${path}" ] && [ ! -L "${path}" ] || die "required config evidence is invalid: ${path}"
    done
    if [ "${ARIA_JOINT_ALLOW_UNPRIVILEGED:-false}" != true ]; then
        [ "$(id -u)" = 0 ] || die "must run as root"
        validate_socket "${ADMIN_SOCKET}" "0:0:600" || die "admin socket must be root:root mode 0600"
        neutron_gid="$(docker exec neutron_aria_agent id -g neutron)"
        validate_socket "${NEUTRON_SOCKET}" "0:${neutron_gid}:660" || die "Neutron socket owner/mode mismatch"
    fi
    [ "$(docker image inspect -f '{{.Id}}' "${DATAPATH_IMAGE_REF}")" = "${DATAPATH_EXPECTED_IMAGE_ID}" ] || die "datapath image ID mismatch"
    [ "$(docker image inspect -f '{{.Id}}' "${AGENT_IMAGE_REF}")" = "${AGENT_EXPECTED_IMAGE_ID}" ] || die "agent image ID mismatch"
    [ "$(manifest_query "${CANDIDATE_MANIFEST}" image aria-datapath)" = "${DATAPATH_EXPECTED_IMAGE_ID}" ] || die "datapath manifest identity mismatch"
    [ "$(manifest_query "${CANDIDATE_MANIFEST}" image neutron-aria-agent)" = "${AGENT_EXPECTED_IMAGE_ID}" ] || die "agent manifest identity mismatch"
    OLD_DP="$(docker inspect -f '{{.Image}}' aria_datapath)"; OLD_AGENT="$(docker inspect -f '{{.Image}}' neutron_aria_agent)"
    [ "$(manifest_query "${CURRENT_MANIFEST}" image aria-datapath)" = "${OLD_DP}" ] || die "live datapath is not the current manifest"
    [ "$(manifest_query "${CURRENT_MANIFEST}" image neutron-aria-agent)" = "${OLD_AGENT}" ] || die "live agent is not the current manifest"
    docker image inspect "${OLD_DP}" >/dev/null || die "rollback datapath image unavailable"
    docker image inspect "${OLD_AGENT}" >/dev/null || die "rollback agent image unavailable"
    OVS_PID="$(pgrep -xo ovs-vswitchd)"; OVS_AGENT_ID="$(docker inspect -f '{{.Id}}' neutron_openvswitch_agent)"
    OVS_AGENT_STARTED="$(docker inspect -f '{{.State.StartedAt}}' neutron_openvswitch_agent)"
    BR_INT_UUID="$(docker exec neutron_openvswitch_agent ovs-vsctl --no-wait get bridge br-int _uuid)"; [ -n "${BR_INT_UUID}" ] || die "br-int UUID unavailable"
    free_kib="$(df -Pk "${JOINT_STATE_DIR%/*}" | awk 'NR==1&&NF==1{value=$1} NR>1{value=$4} END{print value}')"
    case "${free_kib}" in ''|*[!0-9]*) die "df Available column is invalid" ;; esac
    [ "${free_kib}" -ge "${MIN_FREE_KIB}" ] || die "insufficient release-state disk space"
    capture_baseline_status || die "baseline generation/port status is incomplete"
    OLD_MANIFEST_HASH="$(file_sha256 "${CURRENT_MANIFEST}")"; CANDIDATE_MANIFEST_HASH="$(file_sha256 "${CANDIDATE_MANIFEST}")"
    OLD_CONFIG_HASH="$(config_pair_sha256 "${ROLLBACK_DATAPATH_CONFIG}" "${ROLLBACK_AGENT_CONFIG}")"
    CANDIDATE_CONFIG_HASH="$(config_pair_sha256 "${CANDIDATE_DATAPATH_CONFIG}" "${CANDIDATE_AGENT_CONFIG}")"
    DATAPATH_EXPECTED_ARIA_SHA256="$(manifest_query "${CANDIDATE_MANIFEST}" artifact aria-agent)"
    DATAPATH_EXPECTED_EBPF_SHA256="$(manifest_query "${CANDIDATE_MANIFEST}" artifact libebpf_firewall.so)"
    DATAPATH_EXPECTED_EBPF_PERF_SHA256="$(manifest_query "${CANDIDATE_MANIFEST}" artifact libebpf_firewall_perf.so)"
    classify; verify_live_canary || die "initial OVS canary failed"
}

begin_ledger() {
    local evidence host; host="$(hostname -f 2>/dev/null || hostname)"
    evidence="$(python3 - "${OLD_DP}" "${OLD_AGENT}" "${DATAPATH_EXPECTED_IMAGE_ID}" "${AGENT_EXPECTED_IMAGE_ID}" "${PRE_ACCEPTED}" "${PRE_APPLIED}" "${PRE_HASH}" "${OVS_PID}" "${OVS_AGENT_ID}" "${OVS_AGENT_STARTED}" "${BR_INT_UUID}" "${OLD_MANIFEST_HASH}" "${CANDIDATE_MANIFEST_HASH}" "${OLD_CONFIG_HASH}" "${CANDIDATE_CONFIG_HASH}" "${PRE_PORTS}" <<'PY'
import json,sys
print(json.dumps({"affected_domains":["acl"],"old_image_ids":{"aria-datapath":sys.argv[1],"neutron-aria-agent":sys.argv[2]},"candidate_image_ids":{"aria-datapath":sys.argv[3],"neutron-aria-agent":sys.argv[4]},"pre_accepted_generation":int(sys.argv[5]),"pre_applied_generation":int(sys.argv[6]),"pre_desired_hash":sys.argv[7],"pre_managed_port_ids":sys.argv[16].split(","),"ovs_vswitchd_pid":int(sys.argv[8]),"ovs_agent_container_id":sys.argv[9],"ovs_agent_started_at":sys.argv[10],"br_int_uuid":sys.argv[11],"old_manifest_hash":sys.argv[12],"candidate_manifest_hash":sys.argv[13],"old_config_hash":sys.argv[14],"candidate_config_hash":sys.argv[15]}))
PY
)"
    ledger begin "${OPERATION_ID}" "${host}" "${UPGRADE_CLASS}" "${evidence}" >/dev/null
}

prove_bypass() {
    local admin status; admin="$(admin_curl http://localhost/api/v1/admin/maintenance)" || return 1
    verify_live_canary || return 1; status="$(agent_curl http://localhost/status)" || return 1
    python3 - "${OPERATION_ID}" "${PRE_APPLIED}" "${PRE_HASH}" "${admin}" "${status}" <<'PY'
import json,sys
op,generation,desired=sys.argv[1],int(sys.argv[2]),sys.argv[3];admin,status=json.loads(sys.argv[4]),json.loads(sys.argv[5]);state=admin.get("state")
assert admin.get("accepted") is True and isinstance(state,dict) and state.get("operation_id")==op and state.get("phase")=="maintenance_bypass"
assert state.get("active_domains")==["acl"] and state.get("expected_applied_generation")==generation and state.get("expected_desired_hash")==desired
assert status.get("maintenance_operation_id")==op and status.get("maintenance_phase")=="maintenance_bypass" and status.get("acl_enforcement")=="bypass"
assert status.get("pending_generation") is None and status.get("ingress_bypass") is True and status.get("egress_bypass") is True
assert status.get("conntrack_mode") in ("neutral","bypass")
PY
}

validate_complete_pair() {
    python3 - "${OPERATION_ID}" "${PRE_PORTS}" "${UPGRADE_CLASS}" "$1" "$2" <<'PY'
import json,sys
op,expected,upgrade_class=sys.argv[1],set(filter(None,sys.argv[2].split(','))),sys.argv[3];one,two=json.loads(sys.argv[4]),json.loads(sys.argv[5])
keys=("accepted_generation","applied_generation","pending_generation","last_desired_hash","stable_read_attempts","stable_desired_hash","maintenance_operation_id","buffer_overflow","unsupported_ports","foreign_host_ports","last_managed_ports_detail")
assert all(one.get(k)==two.get(k) for k in keys)
if upgrade_class=="planned_maintenance":
 assert two.get("maintenance_operation_id")==op and two.get("maintenance_phase")=="maintenance_bypass" and two.get("acl_enforcement")=="bypass"
else:
 assert two.get("maintenance_operation_id") is None and two.get("maintenance_phase") is None and two.get("acl_enforcement")=="enforce"
accepted,applied=two.get("accepted_generation"),two.get("applied_generation");assert type(accepted)is int and accepted==applied
desired=two.get("last_desired_hash");assert isinstance(desired,str) and len(desired)==64 and two.get("stable_desired_hash")==desired and two.get("stable_read_attempts",0)>=2
assert two.get("pending_generation") is None and two.get("buffer_overflow") is False and two.get("unsupported_ports")==[] and two.get("foreign_host_ports")==[]
ports=two.get("last_managed_ports_detail");assert isinstance(ports,list) and {p.get("port_id") for p in ports}==expected
for port in ports:
 acl=[d for d in port.get("domains",[]) if d.get("domain")=="acl"];assert len(acl)==1 and acl[0].get("status")=="complete" and acl[0].get("ingress_complete") is True and acl[0].get("egress_complete") is True
print(accepted,desired)
PY
}
validate_admin_convergence() {
    python3 - "${OPERATION_ID}" "$1" "$2" "$3" <<'PY'
import json,sys
op,g,d=sys.argv[1],int(sys.argv[2]),sys.argv[3];b=json.loads(sys.argv[4]);s=b.get("state")
assert b.get("accepted") is True and isinstance(s,dict) and s.get("operation_id")==op and s.get("phase")=="maintenance_bypass" and s.get("active_domains")==["acl"] and s.get("applied_generation")==g and s.get("applied_desired_hash")==d
PY
}
validate_exit_response() {
    python3 - "${OPERATION_ID}" "$1" "$2" "$3" <<'PY'
import json,sys
op,g,d=sys.argv[1],int(sys.argv[2]),sys.argv[3];b=json.loads(sys.argv[4]);s=b.get("state")
assert b.get("accepted") is True and b.get("status")=="committed" and isinstance(s,dict) and s.get("operation_id")==op and s.get("phase")=="committed" and s.get("active_domains")==[] and s.get("applied_generation")==g and s.get("applied_desired_hash")==d
PY
}

full_resync_and_activate() {
    local first second pair generation desired admin response
    first="$(agent_curl http://localhost/status)" || { fail_operation "full-resync status unavailable"; return $?; }
    second="$(agent_curl http://localhost/status)" || { fail_operation "stable second read unavailable"; return $?; }
    if ! pair="$(validate_complete_pair "${first}" "${second}")"; then fail_operation "full-resync not exact/stable/complete"; return $?; fi
    read -r generation desired <<<"${pair}"; transition shadow_apply "{\"generation\":${generation},\"desired_hash\":\"${desired}\"}"
    if [ "${UPGRADE_CLASS}" = planned_maintenance ]; then
        admin="$(admin_curl http://localhost/api/v1/admin/maintenance)" || { fail_operation "maintenance status unavailable"; return $?; }
        if ! validate_admin_convergence "${generation}" "${desired}" "${admin}"; then fail_operation "maintenance convergence mismatch"; return $?; fi
    fi
    transition activating "{\"generation\":${generation},\"desired_hash\":\"${desired}\"}"
    if [ "${UPGRADE_CLASS}" = planned_maintenance ]; then
        response="$(admin_curl -X POST -H 'Content-Type: application/json' --data "{\"operation_id\":\"${OPERATION_ID}\",\"expected_applied_generation\":${generation},\"expected_applied_desired_hash\":\"${desired}\"}" http://localhost/api/v1/admin/maintenance/exit)" || { fail_operation "activation failed"; return $?; }
        if ! validate_exit_response "${generation}" "${desired}" "${response}"; then fail_operation "activation response mismatch"; return $?; fi
    fi
    transition verifying "{\"generation\":${generation},\"desired_hash\":\"${desired}\"}"
    curl -fsS http://127.0.0.1:8080/api/v1/livez >/dev/null || { fail_operation "datapath liveness failed"; return $?; }
    agent_curl http://localhost/livez >/dev/null || { fail_operation "agent liveness failed"; return $?; }
    agent_curl http://localhost/readyz >/dev/null || { fail_operation "agent readiness failed"; return $?; }
    [ "$(docker inspect -f '{{.State.Health.Status}}' aria_datapath)" = healthy ] || { fail_operation "datapath Docker health failed"; return $?; }
    [ "$(docker inspect -f '{{.State.Health.Status}}' neutron_aria_agent)" = healthy ] || { fail_operation "agent Docker health failed"; return $?; }
    verify_live_canary || { fail_operation "OVS canary changed"; return $?; }; transition committed '{}'
}

planned_install() {
    transition quiescing; transition bypass_preparing
    verify_live_canary || { fail_operation "pre-bypass OVS canary failed"; return $?; }
    admin_curl -X POST -H 'Content-Type: application/json' --data "{\"operation_id\":\"${OPERATION_ID}\",\"domains\":[\"acl\"],\"reason\":\"planned_upgrade\",\"expected_applied_generation\":${PRE_APPLIED},\"expected_desired_hash\":\"${PRE_HASH}\"}" http://localhost/api/v1/admin/maintenance/enter >/dev/null || { fail_operation "maintenance enter not accepted"; return $?; }
    if ! prove_bypass; then fail_operation "maintenance bypass gate not proven"; return $?; fi
    transition bypass_confirmed; transition datapath_upgrading
    run_phase "datapath replacement" component datapath replace || return $?; run_phase "datapath verification" component datapath verify || return $?
    transition datapath_live; transition agent_upgrading
    run_phase "agent replacement" component agent replace || return $?; run_phase "agent verification" component agent verify || return $?
    transition agent_buffering; transition full_resync; full_resync_and_activate
}
hot_agent_install() {
    transition agent_upgrading; run_phase "agent replacement" component agent replace || return $?; run_phase "agent verification" component agent verify || return $?
    transition agent_buffering; transition full_resync; full_resync_and_activate
}
do_install() {
    preflight; begin_ledger; run_phase "datapath preparation" component datapath prepare || return $?; run_phase "agent preparation" component agent prepare || return $?
    if [ "${UPGRADE_CLASS}" = hot_agent ]; then hot_agent_install; else planned_install; fi
}

recover_bound_operation() {
    local state="$1" expected="$2" expected_dp expected_agent
    UPGRADE_CLASS="$(printf '%s' "${state}"|json_field upgrade_class)"; [ "${UPGRADE_CLASS}" = planned_maintenance ] || die "recovered class mismatch"
    [ "$(printf '%s' "${state}"|json_field operation_id)" = "${OPERATION_ID}" ] || die "recovered operation mismatch"
    [ "$(file_sha256 "${CURRENT_MANIFEST}")" = "$(printf '%s' "${state}"|json_field old_manifest_hash)" ] || die "recovered current manifest mismatch"
    [ "$(file_sha256 "${CANDIDATE_MANIFEST}")" = "$(printf '%s' "${state}"|json_field candidate_manifest_hash)" ] || die "recovered candidate manifest mismatch"
    [ "$(config_pair_sha256 "${ROLLBACK_DATAPATH_CONFIG}" "${ROLLBACK_AGENT_CONFIG}")" = "$(printf '%s' "${state}"|json_field old_config_hash)" ] || die "recovered rollback config mismatch"
    [ "$(config_pair_sha256 "${CANDIDATE_DATAPATH_CONFIG}" "${CANDIDATE_AGENT_CONFIG}")" = "$(printf '%s' "${state}"|json_field candidate_config_hash)" ] || die "recovered candidate config mismatch"
    OVS_PID="$(printf '%s' "${state}"|json_field ovs_vswitchd_pid)"; OVS_AGENT_ID="$(printf '%s' "${state}"|json_field ovs_agent_container_id)"
    OVS_AGENT_STARTED="$(printf '%s' "${state}"|json_field ovs_agent_started_at)"; BR_INT_UUID="$(printf '%s' "${state}"|json_field br_int_uuid)"
    PRE_PORTS="$(printf '%s' "${state}"|python3 -c 'import json,sys;print(",".join(sorted(json.load(sys.stdin)["pre_managed_port_ids"])))')"
    BOUND_OLD_DP="$(printf '%s' "${state}"|python3 -c 'import json,sys;print(json.load(sys.stdin)["old_image_ids"]["aria-datapath"])')"
    BOUND_OLD_AGENT="$(printf '%s' "${state}"|python3 -c 'import json,sys;print(json.load(sys.stdin)["old_image_ids"]["neutron-aria-agent"])')"
    if [ "${expected}" = candidate ]; then
        expected_dp="$(printf '%s' "${state}"|python3 -c 'import json,sys;print(json.load(sys.stdin)["candidate_image_ids"]["aria-datapath"])')"
        expected_agent="$(printf '%s' "${state}"|python3 -c 'import json,sys;print(json.load(sys.stdin)["candidate_image_ids"]["neutron-aria-agent"])')"
        [ "$(docker inspect -f '{{.Image}}' aria_datapath)" = "${expected_dp}" ] || die "recovered datapath image mismatch"
        [ "$(docker inspect -f '{{.Image}}' neutron_aria_agent)" = "${expected_agent}" ] || die "recovered agent image mismatch"
    fi
    verify_live_canary || die "recovered OVS identity/canary mismatch"
}
do_resume() {
    local state; state="$(ledger recover "${OPERATION_ID}")" || return 1; CURRENT_PHASE="$(printf '%s' "${state}"|json_field phase)"
    [ "${CURRENT_PHASE}" = maintenance_bypass ] || die "resume blocked outside proven maintenance_bypass"
    recover_bound_operation "${state}" candidate; transition full_resync; full_resync_and_activate
}
do_rollback() {
    local state status generation desired
    state="$(ledger recover "${OPERATION_ID}")" || return 1; CURRENT_PHASE="$(printf '%s' "${state}"|json_field phase)"
    [ "${CURRENT_PHASE}" = maintenance_bypass ] || die "rollback requires proven maintenance_bypass"
    recover_bound_operation "${state}" candidate; status="$(agent_curl http://localhost/status)" || die "rollback status unavailable"
    read -r generation desired < <(python3 -c 'import json,sys;s=json.load(sys.stdin);g=s.get("applied_generation");h=s.get("last_desired_hash");assert type(g)is int and isinstance(h,str);print(g,h)' <<<"${status}")
    transition rollback
    admin_curl -X POST -H 'Content-Type: application/json' --data "{\"operation_id\":\"${OPERATION_ID}\",\"domains\":[\"acl\"],\"reason\":\"same_operation_rollback\",\"expected_applied_generation\":${generation},\"expected_desired_hash\":\"${desired}\"}" http://localhost/api/v1/admin/maintenance/enter >/dev/null || { fail_operation "rollback bypass confirmation failed"; return $?; }
    run_phase "datapath restore" component datapath restore || return $?
    [ "$(docker inspect -f '{{.Image}}' aria_datapath)" = "${BOUND_OLD_DP}" ] || { fail_operation "restored datapath identity mismatch"; return $?; }
    run_phase "agent restore" component agent restore || return $?
    [ "$(docker inspect -f '{{.Image}}' neutron_aria_agent)" = "${BOUND_OLD_AGENT}" ] || { fail_operation "restored agent identity mismatch"; return $?; }
    verify_live_canary || { fail_operation "rollback OVS canary failed"; return $?; }
    transition full_resync; full_resync_and_activate
}

main() {
    local action="${1:-}"; case "${action}" in dry-run|install|status|resume|rollback|check) ;; *) usage; exit 2 ;; esac
    mkdir -p "${JOINT_STATE_DIR}" "$(dirname "${JOINT_LOCK_PATH}")"; exec 8>"${JOINT_LOCK_PATH}"; flock -n 8 || die "another joint upgrade owns the host"
    if [ -z "${OPERATION_ID}" ] && [ "${action}" != install ] && [ "${action}" != dry-run ]; then die "OPERATION_ID is required for ${action}"; fi
    if [ -z "${OPERATION_ID}" ]; then OPERATION_ID="$(python3 -c 'import uuid;print(uuid.uuid4())')"; fi
    [ "${action}" != install ] || echo "operation_id=${OPERATION_ID}"
    case "${action}" in
        dry-run) preflight; component datapath prepare; component agent prepare ;;
        install) do_install ;; status) ledger status "${OPERATION_ID}" ;; resume) do_resume ;; rollback) do_rollback ;;
        check) state="$(ledger status "${OPERATION_ID}")"; recover_bound_operation "${state}" candidate ;;
    esac
}
main "$@"
