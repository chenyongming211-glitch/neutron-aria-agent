#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
UPGRADE_CONTROL="${UPGRADE_CONTROL:-${SCRIPT_DIR}/aria_upgrade_control.py}"
DATAPATH_INSTALLER="${DATAPATH_INSTALLER:-${SCRIPT_DIR}/install_aria_datapath_rc_image.sh}"
AGENT_INSTALLER="${AGENT_INSTALLER:-${SCRIPT_DIR}/install_neutron_aria_agent_rc_image.sh}"
CURRENT_MANIFEST="${CURRENT_MANIFEST:-}"
CANDIDATE_MANIFEST="${CANDIDATE_MANIFEST:-}"
OPERATION_ID="${OPERATION_ID:-}"
JOINT_STATE_DIR="${JOINT_STATE_DIR:-/var/lib/aria-release}"
JOINT_LOCK_PATH="${JOINT_LOCK_PATH:-/run/lock/aria-joint-release.lock}"
ADMIN_SOCKET="${ADMIN_SOCKET:-/run/aria/aria-admin.sock}"
NEUTRON_SOCKET="${NEUTRON_SOCKET:-/run/aria/aria-agent.sock}"
DATAPATH_IMAGE_REF="${DATAPATH_IMAGE_REF:-}"
DATAPATH_EXPECTED_IMAGE_ID="${DATAPATH_EXPECTED_IMAGE_ID:-}"
AGENT_IMAGE_REF="${AGENT_IMAGE_REF:-}"
AGENT_EXPECTED_IMAGE_ID="${AGENT_EXPECTED_IMAGE_ID:-}"
MIN_FREE_KIB="${MIN_FREE_KIB:-1048576}"
CURRENT_PHASE=preflight
UPGRADE_CLASS=planned_maintenance

usage() {
    echo "Usage: $0 dry-run|install|status|resume|rollback|check" >&2
}

die() { echo "ERROR: $*" >&2; exit 1; }

json_field() {
    python3 -c 'import json,sys; value=json.load(sys.stdin); print(value.get(sys.argv[1], ""))' "$1"
}

file_sha256() {
    python3 -c 'import hashlib,sys; print(hashlib.sha256(open(sys.argv[1], "rb").read()).hexdigest())' "$1"
}

config_pair_sha256() {
    python3 -c 'import hashlib,sys; h=hashlib.sha256(); [(h.update(open(p,"rb").read()),h.update(b"\0")) for p in sys.argv[1:]]; print(h.hexdigest())' "$@"
}

manifest_image_id() {
    python3 -c 'import json,sys; m=json.load(open(sys.argv[1])); i=next(x["identity"] for x in m["images"] if x["name"] == sys.argv[2]); print("sha256:" + i.rsplit("@sha256:",1)[1])' "$1" "$2"
}

ledger() {
    ARIA_RELEASE_OPERATIONS_DIR="${JOINT_STATE_DIR}/operations" \
    ARIA_RELEASE_LOCK_PATH="${JOINT_LOCK_PATH}" \
        "${UPGRADE_CONTROL}" ledger "$@"
}

transition() {
    local evidence="${2-}"
    [ -n "${evidence}" ] || evidence='{}'
    ledger transition "${CURRENT_PHASE}" "$1" "${OPERATION_ID}" "${evidence}" >/dev/null
    CURRENT_PHASE="$1"
}

fail_operation() {
    local message="$1"
    ledger fail "${CURRENT_PHASE}" "${OPERATION_ID}" "${message}" >/dev/null 2>&1 || true
    echo "ERROR: ${message}" >&2
    return 1
}

run_phase() {
    local label="$1"
    shift
    "$@" || fail_operation "${label} failed"
}

admin_curl() {
    curl -fsS --unix-socket "${ADMIN_SOCKET}" "$@"
}

agent_curl() {
    curl -fsS --unix-socket "${NEUTRON_SOCKET}" "$@"
}

verify_ovs_identity() {
    [ "$(pgrep -xo ovs-vswitchd)" = "${OVS_PID}" ] || return 1
    [ "$(docker inspect -f '{{.Id}}' neutron_openvswitch_agent)" = "${OVS_AGENT_ID}" ] || return 1
    [ "$(docker inspect -f '{{.State.StartedAt}}' neutron_openvswitch_agent)" = "${OVS_AGENT_STARTED}" ]
}

component() {
    local which="$1" action="$2"
    if [ "${which}" = datapath ]; then
        IMAGE_REF="${DATAPATH_IMAGE_REF}" EXPECTED_IMAGE_ID="${DATAPATH_EXPECTED_IMAGE_ID}" \
        EXPECTED_ARIA_SHA256="${DATAPATH_EXPECTED_ARIA_SHA256:-}" \
        EXPECTED_EBPF_SHA256="${DATAPATH_EXPECTED_EBPF_SHA256:-}" \
        EXPECTED_EBPF_PERF_SHA256="${DATAPATH_EXPECTED_EBPF_PERF_SHA256:-}" \
        OPERATION_ID="${OPERATION_ID}" JOINT_MAINTENANCE_MODE=true \
            "${DATAPATH_INSTALLER}" "${action}"
    else
        IMAGE_REF="${AGENT_IMAGE_REF}" EXPECTED_IMAGE_ID="${AGENT_EXPECTED_IMAGE_ID}" \
        CANDIDATE_CONFIG_SOURCE="${CANDIDATE_AGENT_CONFIG:-}" \
        ROLLBACK_CONFIG_SOURCE="${ROLLBACK_AGENT_CONFIG:-}" \
        OPERATION_ID="${OPERATION_ID}" JOINT_MAINTENANCE_MODE=true \
            "${AGENT_INSTALLER}" "${action}"
    fi
}

classify() {
    UPGRADE_CLASS="$("${UPGRADE_CONTROL}" classify --current "${CURRENT_MANIFEST}" \
        --candidate "${CANDIDATE_MANIFEST}" | json_field path)"
    case "${UPGRADE_CLASS}" in
        hot_agent|planned_maintenance) ;;
        *) UPGRADE_CLASS=planned_maintenance ;;
    esac
}

preflight() {
    [ -f "${CURRENT_MANIFEST}" ] || die "CURRENT_MANIFEST is required"
    [ -f "${CANDIDATE_MANIFEST}" ] || die "CANDIDATE_MANIFEST is required"
    [ -n "${DATAPATH_IMAGE_REF}" ] || die "DATAPATH_IMAGE_REF is required"
    [ -n "${AGENT_IMAGE_REF}" ] || die "AGENT_IMAGE_REF is required"
    [ -n "${DATAPATH_EXPECTED_IMAGE_ID}" ] || die "DATAPATH_EXPECTED_IMAGE_ID is required"
    [ -n "${AGENT_EXPECTED_IMAGE_ID}" ] || die "AGENT_EXPECTED_IMAGE_ID is required"
    for path in "${ADMIN_SOCKET}" "${NEUTRON_SOCKET}" \
        "${ROLLBACK_DATAPATH_CONFIG:-}" "${ROLLBACK_AGENT_CONFIG:-}" \
        "${CANDIDATE_DATAPATH_CONFIG:-}" "${CANDIDATE_AGENT_CONFIG:-}"; do
        [ -e "${path}" ] || die "required rollback/socket/config evidence is missing: ${path}"
    done
    if [ "${ARIA_JOINT_ALLOW_UNPRIVILEGED:-false}" != true ]; then
        [ "$(id -u)" = 0 ] || die "must run as root"
        [ "$(stat -c '%u:%g:%a' "${ADMIN_SOCKET}")" = "0:0:600" ] ||
            die "admin socket must be root:root mode 0600"
        stat -c '%u:%g:%a' "${NEUTRON_SOCKET}" >/dev/null
        [ -n "${BR_INT_UUID:-}" ] || die "BR_INT_UUID evidence is required"
    fi
    [ "$(docker image inspect -f '{{.Id}}' "${DATAPATH_IMAGE_REF}")" = "${DATAPATH_EXPECTED_IMAGE_ID}" ] ||
        die "datapath image ID mismatch"
    [ "$(docker image inspect -f '{{.Id}}' "${AGENT_IMAGE_REF}")" = "${AGENT_EXPECTED_IMAGE_ID}" ] ||
        die "agent image ID mismatch"
    [ "$(manifest_image_id "${CANDIDATE_MANIFEST}" aria-datapath)" = "${DATAPATH_EXPECTED_IMAGE_ID}" ] ||
        die "datapath manifest identity mismatch"
    [ "$(manifest_image_id "${CANDIDATE_MANIFEST}" neutron-aria-agent)" = "${AGENT_EXPECTED_IMAGE_ID}" ] ||
        die "agent manifest identity mismatch"
    OLD_DP="$(docker inspect -f '{{.Image}}' aria_datapath)"
    OLD_AGENT="$(docker inspect -f '{{.Image}}' neutron_aria_agent)"
    OVS_PID="$(pgrep -xo ovs-vswitchd)"
    OVS_AGENT_ID="$(docker inspect -f '{{.Id}}' neutron_openvswitch_agent)"
    OVS_AGENT_STARTED="$(docker inspect -f '{{.State.StartedAt}}' neutron_openvswitch_agent)"
    free_kib="$(df -Pk "${JOINT_STATE_DIR%/*}" | awk 'NF {value=$NF} END {print value}')"
    [ "${free_kib:-0}" -ge "${MIN_FREE_KIB}" ] || die "insufficient release-state disk space"
    BASELINE_STATUS="$(agent_curl http://localhost/status)"
    PRE_ACCEPTED="$(printf '%s' "${BASELINE_STATUS}" | json_field accepted_generation)"
    PRE_APPLIED="$(printf '%s' "${BASELINE_STATUS}" | json_field applied_generation)"
    PRE_HASH="$(printf '%s' "${BASELINE_STATUS}" | json_field desired_hash)"
    PRE_PORTS="$(printf '%s' "${BASELINE_STATUS}" | python3 -c 'import json,sys; print(json.dumps(json.load(sys.stdin).get("managed_port_ids", []), separators=(",",":")))')"
    OLD_MANIFEST_HASH="$(file_sha256 "${CURRENT_MANIFEST}")"
    CANDIDATE_MANIFEST_HASH="$(file_sha256 "${CANDIDATE_MANIFEST}")"
    OLD_CONFIG_HASH="$(config_pair_sha256 "${ROLLBACK_DATAPATH_CONFIG}" "${ROLLBACK_AGENT_CONFIG}")"
    CANDIDATE_CONFIG_HASH="$(config_pair_sha256 "${CANDIDATE_DATAPATH_CONFIG}" "${CANDIDATE_AGENT_CONFIG}")"
    classify
}

begin_ledger() {
    local evidence host
    host="$(hostname -f 2>/dev/null || hostname)"
    evidence="$(python3 - "${OLD_DP}" "${OLD_AGENT}" "${DATAPATH_EXPECTED_IMAGE_ID}" \
        "${AGENT_EXPECTED_IMAGE_ID}" "${PRE_ACCEPTED}" "${PRE_APPLIED}" "${PRE_HASH}" \
        "${OVS_PID}" "${OVS_AGENT_ID}" "${OVS_AGENT_STARTED}" "${BR_INT_UUID:-br-int-test}" \
        "${OLD_MANIFEST_HASH}" "${CANDIDATE_MANIFEST_HASH}" "${OLD_CONFIG_HASH}" \
        "${CANDIDATE_CONFIG_HASH}" "${PRE_PORTS}" <<'PY'
import json,sys
print(json.dumps({"affected_domains":["acl"],"old_image_ids":{"aria-datapath":sys.argv[1],"neutron-aria-agent":sys.argv[2]},"candidate_image_ids":{"aria-datapath":sys.argv[3],"neutron-aria-agent":sys.argv[4]},"pre_accepted_generation":int(sys.argv[5] or 0),"pre_applied_generation":int(sys.argv[6] or 0),"pre_desired_hash":sys.argv[7],"pre_managed_port_ids":json.loads(sys.argv[16]),"ovs_vswitchd_pid":int(sys.argv[8]),"ovs_agent_container_id":sys.argv[9],"ovs_agent_started_at":sys.argv[10],"br_int_uuid":sys.argv[11],"old_manifest_hash":sys.argv[12],"candidate_manifest_hash":sys.argv[13],"old_config_hash":sys.argv[14],"candidate_config_hash":sys.argv[15]}))
PY
)"
    ledger begin "${OPERATION_ID}" "${host}" "${UPGRADE_CLASS}" "${evidence}" >/dev/null
    CURRENT_PHASE=preflight
}

full_resync_and_activate() {
    local result status generation desired_hash
    result="$(agent_curl -X POST -H 'Content-Type: application/json' \
        --data "{\"operation_id\":\"${OPERATION_ID}\"}" http://localhost/api/v1/admin/full-resync)" ||
        fail_operation "authoritative full-resync failed"
    generation="$(printf '%s' "${result}" | json_field generation)"
    desired_hash="$(printf '%s' "${result}" | json_field desired_hash)"
    [ "$(printf '%s' "${result}" | json_field stable)" = True ] || fail_operation "full-resync was not stable"
    transition shadow_apply "{\"generation\":${generation},\"desired_hash\":\"${desired_hash}\"}"
    status="$(admin_curl http://localhost/api/v1/admin/maintenance)" || fail_operation "shadow status failed"
    [ "$(printf '%s' "${status}" | json_field accepted_generation)" = "${generation}" ] || fail_operation "accepted generation mismatch"
    [ "$(printf '%s' "${status}" | json_field applied_generation)" = "${generation}" ] || fail_operation "applied generation mismatch"
    [ "$(printf '%s' "${status}" | json_field desired_hash)" = "${desired_hash}" ] || fail_operation "desired hash mismatch"
    [ "$(printf '%s' "${status}" | json_field pending_generation)" = None ] || fail_operation "generation still pending"
    transition activating "{\"generation\":${generation},\"desired_hash\":\"${desired_hash}\"}"
    if [ "${UPGRADE_CLASS}" = planned_maintenance ]; then
        admin_curl -X POST -H 'Content-Type: application/json' \
            --data "{\"operation_id\":\"${OPERATION_ID}\",\"generation\":${generation},\"desired_hash\":\"${desired_hash}\"}" \
            http://localhost/api/v1/admin/maintenance/exit >/dev/null || fail_operation "activation failed"
    fi
    transition verifying "{\"generation\":${generation},\"desired_hash\":\"${desired_hash}\"}"
    if [ "${UPGRADE_CLASS}" = planned_maintenance ]; then
        admin_curl http://localhost/livez >/dev/null || fail_operation "datapath liveness failed"
        admin_curl http://localhost/readyz >/dev/null || fail_operation "datapath readiness failed"
    fi
    [ "$(docker inspect -f '{{.State.Health.Status}}' aria_datapath)" = healthy ] || fail_operation "datapath Docker health failed"
    [ "$(docker inspect -f '{{.State.Health.Status}}' neutron_aria_agent)" = healthy ] || fail_operation "agent Docker health failed"
    verify_ovs_identity || fail_operation "OVS identity changed"
    transition committed '{}'
}

planned_install() {
    transition quiescing
    transition bypass_preparing
    admin_curl -X POST -H 'Content-Type: application/json' \
        --data "{\"operation_id\":\"${OPERATION_ID}\",\"domains\":[\"acl\"],\"reason\":\"planned_upgrade\",\"expected_applied_generation\":${PRE_APPLIED},\"expected_desired_hash\":\"${PRE_HASH}\"}" \
        http://localhost/api/v1/admin/maintenance/enter >/dev/null || fail_operation "maintenance enter failed"
    status="$(admin_curl http://localhost/api/v1/admin/maintenance)" || fail_operation "maintenance bypass verification failed"
    [ "$(printf '%s' "${status}" | json_field acl_enforcement)" = bypass ] || fail_operation "ACL bypass was not proven"
    transition bypass_confirmed
    transition datapath_upgrading
    run_phase "datapath replacement" component datapath replace
    run_phase "datapath verification" component datapath verify
    transition datapath_live
    transition agent_upgrading
    run_phase "agent replacement" component agent replace
    run_phase "agent verification" component agent verify
    transition agent_buffering
    transition full_resync
    full_resync_and_activate
}

hot_agent_install() {
    transition agent_upgrading
    run_phase "agent replacement" component agent replace
    run_phase "agent verification" component agent verify
    transition agent_buffering
    transition full_resync
    full_resync_and_activate
}

do_install() {
    preflight
    begin_ledger
    run_phase "datapath preparation" component datapath prepare
    run_phase "agent preparation" component agent prepare
    if [ "${UPGRADE_CLASS}" = hot_agent ]; then hot_agent_install; else planned_install; fi
}

do_resume() {
    state="$(ledger recover "${OPERATION_ID}")" || return 1
    CURRENT_PHASE="$(printf '%s' "${state}" | json_field phase)"
    [ "${CURRENT_PHASE}" = maintenance_bypass ] || die "resume requires maintenance_bypass"
    UPGRADE_CLASS=planned_maintenance
    transition full_resync
    preflight
    full_resync_and_activate
}

do_rollback() {
    state="$(ledger recover "${OPERATION_ID}")" || return 1
    CURRENT_PHASE="$(printf '%s' "${state}" | json_field phase)"
    [ "${CURRENT_PHASE}" = maintenance_bypass ] || die "rollback requires maintenance_bypass"
    UPGRADE_CLASS=planned_maintenance
    preflight
    transition rollback
    admin_curl -X POST -H 'Content-Type: application/json' --data "{\"operation_id\":\"${OPERATION_ID}\"}" \
        http://localhost/api/v1/admin/maintenance/enter >/dev/null || fail_operation "rollback bypass confirmation failed"
    run_phase "datapath restore" component datapath restore
    run_phase "datapath rollback verification" component datapath verify
    run_phase "agent restore" component agent restore
    run_phase "agent rollback verification" component agent verify
    transition full_resync
    full_resync_and_activate
}

main() {
    action="${1:-}"
    case "${action}" in dry-run|install|status|resume|rollback|check) ;; *) usage; exit 2 ;; esac
    mkdir -p "${JOINT_STATE_DIR}"
    lock_dir="${JOINT_LOCK_PATH}.held"
    mkdir "${lock_dir}" 2>/dev/null || die "another joint upgrade owns the host"
    trap 'rmdir "${lock_dir}" 2>/dev/null || true' EXIT
    if [ -z "${OPERATION_ID}" ]; then
        OPERATION_ID="$(python3 -c 'import uuid; print(uuid.uuid4())')"
    fi
    case "${action}" in
        dry-run) preflight; component datapath prepare; component agent prepare ;;
        install) do_install ;;
        status) ledger status "${OPERATION_ID}" ;;
        resume) do_resume ;;
        rollback) do_rollback ;;
        check) ledger status "${OPERATION_ID}" >/dev/null; preflight; verify_ovs_identity ;;
    esac
}

main "$@"
