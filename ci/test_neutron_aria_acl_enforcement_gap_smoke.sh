#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="${REPO_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
SMOKE="${REPO_ROOT}/deploy/kolla/smoke/neutron_aria_acl_enforcement_gap_smoke.sh"
WORK_DIR="$(mktemp -d)"

cleanup() {
    rm -rf "${WORK_DIR}"
}
trap cleanup EXIT

cat >"${WORK_DIR}/policies.json" <<'JSON'
{"aria_acl_policies":[
  {"id":"policy-ready","enabled":true},
  {"id":"policy-disabled","enabled":false}
]}
JSON

cat >"${WORK_DIR}/bindings.json" <<'JSON'
{"aria_acl_bindings":[
  {"id":"binding-ready","policy_id":"policy-ready","target_type":"port","target_id":"port-ready","enabled":true},
  {"id":"binding-disabled","policy_id":"policy-ready","target_type":"port","target_id":"port-disabled","enabled":false},
  {"id":"binding-unbound","policy_id":"policy-ready","target_type":"port","target_id":"port-unbound","enabled":true}
]}
JSON

cat >"${WORK_DIR}/ports.json" <<'JSON'
{"ports":[
  {"id":"port-ready","network_id":"network-a","binding:host_id":"compute-1.example.test"},
  {"id":"port-disabled","network_id":"network-a","binding:host_id":"compute-1.example.test"},
  {"id":"port-unbound","network_id":"network-a","binding:host_id":""}
]}
JSON

cat >"${WORK_DIR}/statuses.json" <<'JSON'
{"aria_acl_port_statuses":[
  {"port_id":"port-ready","host":"compute-1.example.test","status":"ready","runtime_status":"ready","effective_action":"enforce","effective_policy_id":"policy-ready","binding_id":"binding-ready","stale":false}
]}
JSON

run_smoke() {
    POLICIES_JSON_FILE="${WORK_DIR}/policies.json" \
    BINDINGS_JSON_FILE="${WORK_DIR}/bindings.json" \
    PORTS_JSON_FILE="${WORK_DIR}/ports.json" \
    PORT_STATUSES_JSON_FILE="${WORK_DIR}/statuses.json" \
        bash "${SMOKE}"
}

healthy_output="$(run_smoke)"
printf '%s\n' "${healthy_output}" | grep -q 'enforcement_gap_count=0'
printf '%s\n' "${healthy_output}" | grep -q 'expected_enforced_ports=1'
printf '%s\n' "${healthy_output}" | grep -q 'ignored_unbound_ports=1'

cat >"${WORK_DIR}/bindings.json" <<'JSON'
{"aria_acl_bindings":[
  {"id":"binding-ready","policy_id":"policy-ready","target_type":"port","target_id":"port-ready","enabled":true},
  {"id":"binding-policy-disabled","policy_id":"policy-disabled","target_type":"port","target_id":"port-policy-disabled","enabled":true},
  {"id":"binding-network","policy_id":"policy-ready","target_type":"network","target_id":"network-b","enabled":true}
]}
JSON

cat >"${WORK_DIR}/ports.json" <<'JSON'
{"ports":[
  {"id":"port-ready","network_id":"network-a","binding:host_id":"compute-1.example.test"},
  {"id":"port-policy-disabled","network_id":"network-a","binding:host_id":"compute-1.example.test"},
  {"id":"port-degraded","network_id":"network-b","binding:host_id":"compute-2.example.test"},
  {"id":"port-stale","network_id":"network-b","binding:host_id":"compute-2.example.test"},
  {"id":"port-missing","network_id":"network-b","binding:host_id":"compute-2.example.test"}
]}
JSON

cat >"${WORK_DIR}/statuses.json" <<'JSON'
{"aria_acl_port_statuses":[
  {"port_id":"port-ready","host":"compute-1.example.test","status":"ready","runtime_status":"ready","effective_action":"enforce","effective_policy_id":"policy-ready","binding_id":"binding-ready","stale":false},
  {"port_id":"port-policy-disabled","host":"compute-1.example.test","status":"degraded","runtime_status":"degraded","effective_action":"bypass","effective_policy_id":"policy-disabled","binding_id":"binding-policy-disabled","reason":"policy_missing_or_disabled","stale":false},
  {"port_id":"port-degraded","host":"compute-2.example.test","status":"degraded","runtime_status":"degraded","effective_action":"bypass","effective_policy_id":"policy-ready","binding_id":"binding-network","reason":"apply_failed","stale":false},
  {"port_id":"port-stale","host":"compute-2.example.test","status":"ready","runtime_status":"stale","effective_action":"enforce","effective_policy_id":"policy-ready","binding_id":"binding-network","stale":true}
]}
JSON

set +e
gap_output="$(run_smoke 2>&1)"
gap_status=$?
set -e
[ "${gap_status}" -eq 2 ]
printf '%s\n' "${gap_output}" | grep -q 'enforcement_gap_count=4'
printf '%s\n' "${gap_output}" | grep -q 'port_id=port-policy-disabled.*status=degraded.*effective_action=bypass.*reason=policy_missing_or_disabled'
printf '%s\n' "${gap_output}" | grep -q 'port_id=port-degraded.*reason=apply_failed'
printf '%s\n' "${gap_output}" | grep -q 'port_id=port-stale.*reason=status_stale'
printf '%s\n' "${gap_output}" | grep -q 'port_id=port-missing.*reason=status_missing'

cat >"${WORK_DIR}/statuses.json" <<'JSON'
{"aria_acl_port_statuses":[
  {"port_id":"port-ready","host":"compute-1.example.test","status":"ready","runtime_status":"ready","effective_action":"enforce","effective_policy_id":"wrong-policy","binding_id":"wrong-binding","stale":false},
  {"port_id":"port-degraded","host":"compute-2.example.test","status":"ready","runtime_status":"ready","effective_action":"enforce","effective_policy_id":"policy-ready","binding_id":"binding-network","stale":false},
  {"port_id":"port-stale","host":"compute-2.example.test","status":"ready","runtime_status":"ready","effective_action":"enforce","effective_policy_id":"policy-ready","binding_id":"binding-network","stale":false},
  {"port_id":"port-missing","host":"compute-2.example.test","status":"ready","runtime_status":"ready","effective_action":"enforce","effective_policy_id":"policy-ready","binding_id":"binding-network","stale":false}
]}
JSON

set +e
identity_output="$(run_smoke 2>&1)"
identity_status=$?
set -e
[ "${identity_status}" -eq 2 ]
printf '%s\n' "${identity_output}" | grep -q 'enforcement_gap_count=2'
printf '%s\n' "${identity_output}" | grep -q 'port_id=port-ready.*reason=status_identity_mismatch'
printf '%s\n' "${identity_output}" | grep -q 'port_id=port-policy-disabled.*reason=policy_missing_or_disabled'

mkdir -p "${WORK_DIR}/fake-bin"
touch "${WORK_DIR}/adminrc"
cat >"${WORK_DIR}/fake-bin/docker" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
case "$*" in
  *"openstack token issue"*)
    echo fake-token
    ;;
  *"openstack endpoint list"*)
    echo '[{"ID":"endpoint-network","Service Name":"neutron","Service Type":"network"}]'
    ;;
  *"openstack endpoint show endpoint-network"*)
    echo '[{"Field":"publicurl","Value":"http://network.example.test:9696/v2.0"}]'
    ;;
  *)
    echo "unexpected docker invocation: $*" >&2
    exit 1
    ;;
esac
SH
cat >"${WORK_DIR}/fake-bin/curl" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
url="${*: -1}"
echo "${url}" >>"${CURL_LOG}"
case "${url}" in
  */aria-acl-policies) echo '{"aria_acl_policies":[]}' ;;
  */aria-acl-bindings) echo '{"aria_acl_bindings":[]}' ;;
  */ports\?*) echo '{"ports":[]}' ;;
  */aria-acl-port-statuses) echo '{"aria_acl_port_statuses":[]}' ;;
  *) echo "unexpected URL: ${url}" >&2; exit 1 ;;
esac
SH
chmod +x "${WORK_DIR}/fake-bin/docker" "${WORK_DIR}/fake-bin/curl"

catalog_output="$(
    env -u POLICIES_JSON_FILE \
        -u BINDINGS_JSON_FILE \
        -u PORTS_JSON_FILE \
        -u PORT_STATUSES_JSON_FILE \
        LOCAL_NEUTRON_URL= \
        ADMIN_RC_FILE="${WORK_DIR}/adminrc" \
        OPENSTACK_CLIENT=fake-openstack-client \
        CURL_LOG="${WORK_DIR}/curl.log" \
        PATH="${WORK_DIR}/fake-bin:${PATH}" \
        bash "${SMOKE}"
)"
printf '%s\n' "${catalog_output}" | grep -q 'enforcement_gap_count=0'
grep -q '^http://network.example.test:9696/v2.0/aria-acl-policies$' \
    "${WORK_DIR}/curl.log"
grep -q 'neutron_aria_acl_enforcement_gap_smoke.sh' \
    "${REPO_ROOT}/deploy/kolla/smoke/neutron_aria_acl_stage2_gate_smoke.sh"

echo "ACL enforcement-gap smoke contract passed"
