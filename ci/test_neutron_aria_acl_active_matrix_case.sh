#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CASE_SCRIPT="${ROOT}/deploy/kolla/smoke/neutron_aria_acl_active_matrix_case.sh"

fail() {
    echo "ERROR: $*" >&2
    exit 1
}

[ -f "${CASE_SCRIPT}" ] || fail "missing active matrix case runner"
bash -n "${CASE_SCRIPT}"

base_env=(
    CASE_ID=contract-case
    VM_IP=192.0.2.10
    PORT_ID=11111111-1111-4111-8111-111111111111
    IFNAME=tap11111111-11
    EXPECTED_HOST=compute-a.example.test
    DIRECTION=ingress
    PROTOCOL=tcp
    STATEFUL=true
    SELECTOR_KIND=single
    MATCH_PORT_MIN=8080
    MATCH_PORT_MAX=8080
    NONMATCH_PORT=8081
    EGRESS_TARGET_IP=192.0.2.1
    GUEST_EXEC_FILE=/bin/true
    WORK_DIR=/tmp/aria-active-matrix-contract
)

if env "${base_env[@]}" DIRECTION=sideways bash "${CASE_SCRIPT}" validate >/dev/null 2>&1; then
    fail "invalid direction passed validation"
fi
if env "${base_env[@]}" PROTOCOL=gre bash "${CASE_SCRIPT}" validate >/dev/null 2>&1; then
    fail "unsupported protocol passed validation"
fi
if env "${base_env[@]}" MATCH_PORT_MIN=8082 MATCH_PORT_MAX=8080 bash "${CASE_SCRIPT}" validate >/dev/null 2>&1; then
    fail "reversed port range passed validation"
fi
env "${base_env[@]}" bash "${CASE_SCRIPT}" validate >/dev/null

for marker in \
    effective_policy_id \
    binding_id \
    generation_lag \
    cleanup_complete \
    matching_drop \
    nonmatching_allow \
    policy_disable \
    binding_disable; do
    grep -q "${marker}" "${CASE_SCRIPT}" || fail "missing contract marker: ${marker}"
done
grep -q 'item.get("Field")' "${CASE_SCRIPT}" || fail "missing legacy neutron JSON adapter"
# This contract searches for literal generated shell source, including `$1`.
# shellcheck disable=SC2016
if grep -Fq 'awk '\''NF {print $1; exit}'\''' "${CASE_SCRIPT}"; then
    fail "legacy create output must extract a UUID instead of its first word"
fi
grep -q 'uuid_re' "${CASE_SCRIPT}" || \
    fail "resource ID parser must recognize UUIDs in legacy create messages"
# This contract searches for literal generated shell variable references.
# shellcheck disable=SC2016
grep -Fq '"${PYTHON_BIN}" "${GUEST_EXEC_FILE}" "${VM_IP}" "$1"' "${CASE_SCRIPT}" || \
    fail "guest execution must use the selected Python interpreter"
grep -q 'last_nonempty_line' "${CASE_SCRIPT}" || \
    fail "egress nonce checks must normalize SSH PTY framing"
grep -Fq 'sleep 1) | nc -u -w' "${CASE_SCRIPT}" || \
    fail "egress UDP probe must keep stdin open long enough to receive the echo"

binding_line="$(grep -n 'delete_owned_type binding' "${CASE_SCRIPT}" | head -1 | cut -d: -f1)"
rule_line="$(grep -n 'delete_owned_type rule' "${CASE_SCRIPT}" | head -1 | cut -d: -f1)"
policy_line="$(grep -n 'delete_owned_type policy' "${CASE_SCRIPT}" | head -1 | cut -d: -f1)"
if [ -z "${binding_line}" ] || [ -z "${rule_line}" ] || [ -z "${policy_line}" ]; then
    fail "cleanup order calls are missing"
fi
if [ "${binding_line}" -ge "${rule_line}" ] || [ "${rule_line}" -ge "${policy_line}" ]; then
    fail "cleanup must delete binding, then rule, then policy"
fi

echo "neutron aria ACL active matrix case contract passed"
