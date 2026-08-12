#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SMOKE="${REPO_ROOT}/deploy/kolla/smoke/neutron_aria_heartbeat_smoke.sh"
STAGE2_GATE="${REPO_ROOT}/deploy/kolla/smoke/neutron_aria_acl_stage2_gate_smoke.sh"
ROOT="$(mktemp -d)"
trap 'rm -rf "${ROOT}"' EXIT

mkdir -p "${ROOT}/bin"
cat >"${ROOT}/bin/neutron" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

case "${1:-}" in
    agent-list)
        printf '%s\n' '| agent-1 | Aria ACL agent | compute-1.example.test | :-) | True |'
        ;;
    agent-show)
        cat "${FAKE_AGENT_DETAILS}"
        ;;
    aria-acl-port-status-show)
        cat "${FAKE_PORT_STATUS}"
        ;;
    *)
        echo "unsupported fake neutron command: $*" >&2
        exit 1
        ;;
esac
EOF
chmod +x "${ROOT}/bin/neutron"

cat >"${ROOT}/summary.json" <<'EOF'
{"binary":"neutron-aria-agent","configurations":{"heartbeat_schema_version":2,"heartbeat_detail_mode":"summary_only","last_submitted_generation":7,"accepted_generation":7,"applied_generation":7,"generation_lag":0,"domain_counts":[],"status_reason_counts":[],"degraded_reasons":[],"projection_index":{},"last_event_decision_counts":[],"last_event_decision_updated_at":null}}
EOF
cat >"${ROOT}/legacy.json" <<'EOF'
{"binary":"neutron-aria-agent","configurations":{"heartbeat_schema_version":2,"heartbeat_detail_mode":"legacy_sample","last_submitted_generation":7,"accepted_generation":7,"applied_generation":7,"generation_lag":0,"domain_counts":[],"status_reason_counts":[],"degraded_reasons":[],"projection_index":{},"last_event_decision_counts":[],"last_event_decision_updated_at":null,"last_port_statuses":[]}}
EOF
cat >"${ROOT}/port-status.json" <<'EOF'
{"port_id":"port-1","status":"ready","runtime_status":"ready","effective_action":"enforce"}
EOF

run_smoke() {
    env \
        PATH="${ROOT}/bin:${PATH}" \
        ADMINRC="${ROOT}/missing-adminrc" \
        EXPECTED_HOSTS="compute-1.example.test" \
        REQUIRE_HEARTBEAT_SUMMARY_FIELDS=true \
        REQUIRE_HEARTBEAT_V2=true \
        HEARTBEAT_SUMMARY_TIMEOUT=0 \
        HEARTBEAT_MAX_PAYLOAD_BYTES=4096 \
        HEARTBEAT_PORT_STATUS_ID=port-1 \
        FAKE_AGENT_DETAILS="$1" \
        FAKE_PORT_STATUS="${ROOT}/port-status.json" \
        bash "${SMOKE}"
}

run_smoke "${ROOT}/summary.json" >/dev/null

grep -Fq 'REQUIRE_HEARTBEAT_V2=true' "${STAGE2_GATE}" || {
    echo "stage-two gate does not enforce the Heartbeat V2 contract" >&2
    exit 1
}

if run_smoke "${ROOT}/legacy.json" >"${ROOT}/legacy.out" 2>&1; then
    echo "heartbeat V2 smoke accepted legacy per-port samples" >&2
    exit 1
fi

padding="$(printf '%05000d' 0 | tr '0' 'x')"
printf '%s' \
    "{\"binary\":\"neutron-aria-agent\",\"configurations\":{\"heartbeat_schema_version\":2,\"heartbeat_detail_mode\":\"summary_only\",\"last_submitted_generation\":7,\"accepted_generation\":7,\"applied_generation\":7,\"generation_lag\":0,\"domain_counts\":[],\"status_reason_counts\":[],\"degraded_reasons\":[],\"projection_index\":{},\"last_event_decision_counts\":[],\"last_event_decision_updated_at\":null,\"unexpected_padding\":\"${padding}\"}}" \
    >"${ROOT}/oversized.json"

if run_smoke "${ROOT}/oversized.json" >"${ROOT}/oversized.out" 2>&1; then
    echo "heartbeat V2 smoke accepted an oversized agent-show payload" >&2
    exit 1
fi

echo "Heartbeat V2 smoke contract passed"
