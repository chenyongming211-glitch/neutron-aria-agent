#!/usr/bin/env bash
set -euo pipefail

EXPECTED_KERNEL="${EXPECTED_KERNEL:-4.18.0-553.5.1.el8_10.x86_64}"
: "${ARIA_AGENT_BIN:?ARIA_AGENT_BIN is required}"
: "${EBPF_OBJECT:?EBPF_OBJECT is required}"
: "${ARIA_AGENT_SHA256:?ARIA_AGENT_SHA256 is required}"
: "${EBPF_SHA256:?EBPF_SHA256 is required}"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
STANDALONE_SMOKE="${STANDALONE_SMOKE:-${REPO_ROOT}/deploy/smoke/aria_standalone_acl_tc_datapath_smoke.sh}"
RUN_TOKEN="${RUN_TOKEN:-$(printf '%06x' "$(( (RANDOM << 1) ^ RANDOM ^ $$ ))")}"
RUN_ID="legacy-kernel-${RUN_TOKEN}"
WORK_DIR="${WORK_DIR:-/var/tmp/aria-legacy-kernel-${RUN_TOKEN}}"
EVIDENCE_DIR="${EVIDENCE_DIR:-/var/tmp/aria-legacy-kernel-evidence-${RUN_TOKEN}}"
NETNS="aria-lk-${RUN_TOKEN}"
HOST_IF="alh${RUN_TOKEN}"
PEER_IF="alp${RUN_TOKEN}"
SECOND_HOST_IF="blh${RUN_TOKEN}"
SECOND_PEER_IF="blp${RUN_TOKEN}"
SMOKE_SUMMARY="${WORK_DIR}/summary.json"

die() {
    echo "ERROR: $*" >&2
    exit 1
}

need_command() {
    command -v "$1" >/dev/null 2>&1 || die "missing command: $1"
}

cleanup_fixture() {
    local rc=$?
    trap - EXIT
    set +e
    if mountpoint -q "${WORK_DIR}/bpffs"; then
        umount "${WORK_DIR}/bpffs"
    fi
    if ip link show dev "${HOST_IF}" >/dev/null 2>&1; then
        tc qdisc del dev "${HOST_IF}" clsact >/dev/null 2>&1
        ip link del "${HOST_IF}"
    fi
    if ip link show dev "${SECOND_HOST_IF}" >/dev/null 2>&1; then
        ip link del "${SECOND_HOST_IF}"
    fi
    if ip netns list | awk '{print $1}' | grep -Fx "${NETNS}" >/dev/null; then
        ip netns del "${NETNS}"
    fi
    rm -rf -- "${WORK_DIR}"
    exit "${rc}"
}

verify_hash() {
    local path="$1" expected="$2" label="$3" actual
    actual="$(sha256sum "${path}" | awk '{print tolower($1)}')"
    [ "${actual}" = "${expected,,}" ] || die "${label} SHA-256 mismatch"
}

[ "${EUID}" -eq 0 ] || die "root is required"
for command in awk grep ip mountpoint python3 sha256sum tc umount; do
    need_command "${command}"
done
[ "$(uname -r)" = "${EXPECTED_KERNEL}" ] || \
    die "kernel mismatch: expected ${EXPECTED_KERNEL}, got $(uname -r)"
[ -x "${ARIA_AGENT_BIN}" ] || die "aria-agent is not executable"
[ -r "${EBPF_OBJECT}" ] || die "eBPF object is not readable"
[ -x "${STANDALONE_SMOKE}" ] || die "standalone smoke is not executable"
case "${WORK_DIR}" in
    /var/tmp/aria-legacy-kernel-*) ;;
    *) die "unsafe WORK_DIR: ${WORK_DIR}" ;;
esac
for iface in "${HOST_IF}" "${PEER_IF}" "${SECOND_HOST_IF}" "${SECOND_PEER_IF}"; do
    case "${iface}" in
        tap*|qvo*|qvb*|qbr*|br-*|ovs*) die "refusing live-network interface pattern: ${iface}" ;;
    esac
    ip link show dev "${iface}" >/dev/null 2>&1 && die "interface already exists: ${iface}"
done
ip netns list | awk '{print $1}' | grep -Fx "${NETNS}" >/dev/null && \
    die "network namespace already exists: ${NETNS}"
[ ! -e "${WORK_DIR}" ] || die "work directory already exists: ${WORK_DIR}"

verify_hash "${ARIA_AGENT_BIN}" "${ARIA_AGENT_SHA256}" "aria-agent"
verify_hash "${EBPF_OBJECT}" "${EBPF_SHA256}" "eBPF object"
mkdir -p "${EVIDENCE_DIR}"
trap cleanup_fixture EXIT

set +e
MODE=tap \
ARIA_AGENT_BIN="${ARIA_AGENT_BIN}" \
EBPF_OBJECT="${EBPF_OBJECT}" \
RUN_ID="${RUN_ID}" \
WORK_DIR="${WORK_DIR}" \
NETNS="${NETNS}" \
HOST_IF="${HOST_IF}" \
PEER_IF="${PEER_IF}" \
SECOND_HOST_IF="${SECOND_HOST_IF}" \
SECOND_PEER_IF="${SECOND_PEER_IF}" \
FRAGMENT_TRACKING_SMOKE=0 \
XDP_IDENTITY_SMOKE=0 \
    "${STANDALONE_SMOKE}"
smoke_rc=$?
set -e

[ -r "${SMOKE_SUMMARY}" ] || die "standalone smoke did not produce summary.json"
cp "${SMOKE_SUMMARY}" "${EVIDENCE_DIR}/standalone-summary.json"

mountpoint -q "${WORK_DIR}/bpffs" && die "private bpffs remains mounted"
ip link show dev "${HOST_IF}" >/dev/null 2>&1 && die "primary canary veth remains"
ip link show dev "${SECOND_HOST_IF}" >/dev/null 2>&1 && die "secondary canary veth remains"
ip netns list | awk '{print $1}' | grep -Fx "${NETNS}" >/dev/null && \
    die "canary network namespace remains"

python3 - \
    "${EVIDENCE_DIR}/standalone-summary.json" \
    "${EVIDENCE_DIR}/canary-summary.json" \
    "${EXPECTED_KERNEL}" "${ARIA_AGENT_SHA256,,}" "${EBPF_SHA256,,}" \
    "${smoke_rc}" <<'PY'
import datetime
import json
import sys

source, destination, kernel, agent_hash, ebpf_hash, raw_rc = sys.argv[1:]
with open(source, encoding="utf-8") as handle:
    smoke = json.load(handle)
rc = int(raw_rc)
passed = (
    rc == 0
    and smoke.get("result") == "pass"
    and smoke.get("dual_tc_ready") is True
    and smoke.get("cleanup_errors") == []
)
summary = {
    "aria_agent_sha256": agent_hash,
    "ebpf_sha256": ebpf_hash,
    "kernel": kernel,
    "result": "pass" if passed else "fail",
    "smoke": smoke,
    "timestamp_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
}
with open(destination, "w", encoding="utf-8") as handle:
    json.dump(summary, handle, indent=2, sort_keys=True)
    handle.write("\n")
if not passed:
    raise SystemExit(1)
PY

echo "Legacy-kernel eBPF canary passed"
echo "Evidence: ${EVIDENCE_DIR}/canary-summary.json"
