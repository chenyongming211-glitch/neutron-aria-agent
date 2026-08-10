#!/usr/bin/env bash
set -euo pipefail

OPENSTACK_CLIENT="${OPENSTACK_CLIENT:-openstack_client}"
ADMIN_RC_FILE="${ADMIN_RC_FILE:-/etc/kolla/.adminrc}"
LOCAL_NEUTRON_URL="${LOCAL_NEUTRON_URL:-}"
NEUTRON_ENDPOINT_INTERFACE="${NEUTRON_ENDPOINT_INTERFACE:-public}"
POLICIES_JSON_FILE="${POLICIES_JSON_FILE:-}"
BINDINGS_JSON_FILE="${BINDINGS_JSON_FILE:-}"
PORTS_JSON_FILE="${PORTS_JSON_FILE:-}"
PORT_STATUSES_JSON_FILE="${PORT_STATUSES_JSON_FILE:-}"
WORK_DIR=""

die() {
    echo "ERROR: $*" >&2
    exit 1
}

need_command() {
    command -v "$1" >/dev/null 2>&1 || die "missing command: $1"
}

cleanup() {
    if [ -n "${WORK_DIR}" ] && [ -d "${WORK_DIR}" ]; then
        rm -rf "${WORK_DIR}"
    fi
}
trap cleanup EXIT

if [ -z "${PYTHON_BIN:-}" ]; then
    PYTHON_BIN="$(command -v python3 || command -v python2 || command -v python || true)"
fi
[ -n "${PYTHON_BIN}" ] || die "missing command: python3, python2, or python"

fixture_count=0
for fixture in \
    "${POLICIES_JSON_FILE}" \
    "${BINDINGS_JSON_FILE}" \
    "${PORTS_JSON_FILE}" \
    "${PORT_STATUSES_JSON_FILE}"
do
    if [ -n "${fixture}" ]; then
        fixture_count=$((fixture_count + 1))
    fi
done

if [ "${fixture_count}" -ne 0 ] && [ "${fixture_count}" -ne 4 ]; then
    die "fixture mode requires all four JSON file variables"
fi

if [ "${fixture_count}" -eq 4 ]; then
    for fixture in \
        "${POLICIES_JSON_FILE}" \
        "${BINDINGS_JSON_FILE}" \
        "${PORTS_JSON_FILE}" \
        "${PORT_STATUSES_JSON_FILE}"
    do
        [ -r "${fixture}" ] || die "fixture is not readable: ${fixture}"
    done
else
    need_command curl
    need_command docker
    [ -r "${ADMIN_RC_FILE}" ] || die "admin rc is not readable: ${ADMIN_RC_FILE}"

    TOKEN="${TOKEN:-$(
        docker exec -u root --env-file "${ADMIN_RC_FILE}" \
            "${OPENSTACK_CLIENT}" openstack token issue -f value -c id |
            tail -1
    )}"
    [ -n "${TOKEN}" ] || die "failed to obtain OpenStack token"

    if [ -z "${LOCAL_NEUTRON_URL}" ]; then
        endpoint_list="$(
            docker exec -u root --env-file "${ADMIN_RC_FILE}" \
                "${OPENSTACK_CLIENT}" openstack endpoint list -f json
        )"
        endpoint_id="$(ENDPOINT_LIST="${endpoint_list}" "${PYTHON_BIN}" - <<'PY'
from __future__ import print_function

import json
import os

rows = json.loads(os.environ["ENDPOINT_LIST"])
for row in rows:
    service_type = row.get("Service Type") or row.get("service_type")
    service_name = row.get("Service Name") or row.get("service_name")
    if service_type == "network" or service_name in ("neutron", "network"):
        print(row.get("ID") or row.get("id") or "")
        break
PY
        )"
        [ -n "${endpoint_id}" ] || die "network endpoint is absent from OpenStack catalog"
        endpoint_show="$(
            docker exec -u root --env-file "${ADMIN_RC_FILE}" \
                "${OPENSTACK_CLIENT}" openstack endpoint show \
                "${endpoint_id}" -f json
        )"
        LOCAL_NEUTRON_URL="$(
            ENDPOINT_SHOW="${endpoint_show}" \
            ENDPOINT_INTERFACE="${NEUTRON_ENDPOINT_INTERFACE}" \
                "${PYTHON_BIN}" - <<'PY'
from __future__ import print_function

import json
import os

payload = json.loads(os.environ["ENDPOINT_SHOW"])
if isinstance(payload, list):
    payload = dict(
        (str(row.get("Field") or "").lower(), row.get("Value"))
        for row in payload
    )
preferred = str(os.environ.get("ENDPOINT_INTERFACE") or "public").lower() + "url"
for key in (preferred, "publicurl", "internalurl", "adminurl", "url"):
    value = payload.get(key)
    if value:
        print(value)
        break
PY
        )"
    fi
    LOCAL_NEUTRON_URL="${LOCAL_NEUTRON_URL%/}"
    case "${LOCAL_NEUTRON_URL}" in
        http://*|https://*) ;;
        *) die "failed to discover a valid Neutron network endpoint" ;;
    esac
    case "${LOCAL_NEUTRON_URL}" in
        */v2.0) ;;
        *) LOCAL_NEUTRON_URL="${LOCAL_NEUTRON_URL}/v2.0" ;;
    esac

    WORK_DIR="$(mktemp -d)"
    POLICIES_JSON_FILE="${WORK_DIR}/policies.json"
    BINDINGS_JSON_FILE="${WORK_DIR}/bindings.json"
    PORTS_JSON_FILE="${WORK_DIR}/ports.json"
    PORT_STATUSES_JSON_FILE="${WORK_DIR}/port-statuses.json"

    curl -fsS -H "X-Auth-Token: ${TOKEN}" \
        "${LOCAL_NEUTRON_URL}/aria-acl-policies" >"${POLICIES_JSON_FILE}"
    curl -fsS -H "X-Auth-Token: ${TOKEN}" \
        "${LOCAL_NEUTRON_URL}/aria-acl-bindings" >"${BINDINGS_JSON_FILE}"
    curl -fsS -H "X-Auth-Token: ${TOKEN}" \
        "${LOCAL_NEUTRON_URL}/ports?fields=id&fields=network_id&fields=binding%3Ahost_id" \
        >"${PORTS_JSON_FILE}"
    curl -fsS -H "X-Auth-Token: ${TOKEN}" \
        "${LOCAL_NEUTRON_URL}/aria-acl-port-statuses" \
        >"${PORT_STATUSES_JSON_FILE}"
fi

"${PYTHON_BIN}" - \
    "${POLICIES_JSON_FILE}" \
    "${BINDINGS_JSON_FILE}" \
    "${PORTS_JSON_FILE}" \
    "${PORT_STATUSES_JSON_FILE}" <<'PY'
from __future__ import print_function

import json
import sys


def load_collection(path, key):
    with open(path, "r") as stream:
        payload = json.load(stream)
    rows = payload.get(key) if isinstance(payload, dict) else payload
    if not isinstance(rows, list):
        raise ValueError("%s does not contain a list" % key)
    return rows


def enabled(row):
    value = row.get("enabled", True)
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() not in ("0", "false", "no", "off", "none", "")


def truthy(value):
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in ("1", "true", "yes", "on")


def token(value, default="unknown"):
    value = default if value in (None, "") else str(value)
    return "_".join(value.split())


def gap(port, binding, reason, status=None):
    status = status or {}
    return {
        "port_id": port.get("id") or binding.get("target_id") or "unknown",
        "host": port.get("binding:host_id") or "unbound",
        "policy_id": binding.get("policy_id") or "unknown",
        "binding_id": binding.get("id") or "unknown",
        "status": status.get("runtime_status") or status.get("status") or "missing",
        "effective_action": status.get("effective_action") or "unknown",
        "reason": reason,
    }


policy_rows = load_collection(sys.argv[1], "aria_acl_policies")
binding_rows = load_collection(sys.argv[2], "aria_acl_bindings")
port_rows = load_collection(sys.argv[3], "ports")
status_rows = load_collection(sys.argv[4], "aria_acl_port_statuses")

policies = dict((row.get("id"), row) for row in policy_rows if row.get("id"))
ports = dict((row.get("id"), row) for row in port_rows if row.get("id"))
enabled_bindings = [row for row in binding_rows if enabled(row)]
port_bindings = {}
network_bindings = {}
gaps = []

for binding in enabled_bindings:
    target_type = binding.get("target_type")
    target_id = binding.get("target_id")
    if target_type == "port":
        port_bindings.setdefault(target_id, []).append(binding)
        if target_id not in ports:
            gaps.append(gap({}, binding, "target_port_missing"))
    elif target_type == "network":
        network_bindings.setdefault(target_id, []).append(binding)
    else:
        gaps.append(gap({}, binding, "unsupported_binding_target_type"))

statuses_by_port_host = {}
for status in status_rows:
    key = (status.get("port_id"), status.get("host"))
    statuses_by_port_host.setdefault(key, []).append(status)

expected = 0
enforced = 0
ignored_unbound = 0

for port_id in sorted(ports):
    port = ports[port_id]
    selected = port_bindings.get(port_id) or []
    duplicate_reason = None
    if len(selected) > 1:
        duplicate_reason = "multiple_enabled_port_bindings"
    elif not selected:
        selected = network_bindings.get(port.get("network_id")) or []
        if len(selected) > 1:
            duplicate_reason = "multiple_enabled_network_bindings"
    if not selected:
        continue

    binding = selected[0]
    host = port.get("binding:host_id") or ""
    if not host:
        ignored_unbound += 1
        continue

    expected += 1
    if duplicate_reason:
        gaps.append(gap(port, binding, duplicate_reason))
        continue

    candidates = statuses_by_port_host.get((port_id, host)) or []
    exact = [
        row for row in candidates
        if row.get("binding_id") == binding.get("id") and
        row.get("effective_policy_id") == binding.get("policy_id")
    ]
    observed = exact[0] if exact else (candidates[0] if candidates else None)

    policy = policies.get(binding.get("policy_id"))
    if policy is None or not enabled(policy):
        gaps.append(gap(
            port,
            binding,
            "policy_missing_or_disabled",
            observed,
        ))
        continue

    if not candidates:
        gaps.append(gap(port, binding, "status_missing"))
        continue

    if not exact:
        gaps.append(gap(port, binding, "status_identity_mismatch", candidates[0]))
        continue

    status = exact[0]
    runtime_status = status.get("runtime_status") or status.get("status")
    effective_action = status.get("effective_action")
    if truthy(status.get("stale")) or runtime_status == "stale":
        gaps.append(gap(port, binding, "status_stale", status))
        continue
    if runtime_status != "ready" or effective_action != "enforce":
        reason = status.get("reason") or "runtime_%s_%s" % (
            runtime_status or "missing",
            effective_action or "missing",
        )
        gaps.append(gap(port, binding, reason, status))
        continue
    enforced += 1

gaps.sort(key=lambda item: (
    item.get("port_id") or "",
    item.get("host") or "",
    item.get("binding_id") or "",
))

print("acl_enforcement_gap_check=%s" % ("fail" if gaps else "pass"))
print("enabled_bindings=%s" % len(enabled_bindings))
print("expected_enforced_ports=%s" % expected)
print("enforced_ports=%s" % enforced)
print("ignored_unbound_ports=%s" % ignored_unbound)
print("enforcement_gap_count=%s" % len(gaps))
for item in gaps:
    print(
        "ALERT port_id=%s host=%s policy_id=%s binding_id=%s "
        "status=%s effective_action=%s reason=%s" % (
            token(item.get("port_id")),
            token(item.get("host")),
            token(item.get("policy_id")),
            token(item.get("binding_id")),
            token(item.get("status")),
            token(item.get("effective_action")),
            token(item.get("reason")),
        )
    )

if gaps:
    sys.exit(2)
PY
