#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SOAK="${ROOT}/deploy/kolla/smoke/neutron_aria_acl_active_matrix_soak.sh"
GUEST_EXEC="${ROOT}/deploy/kolla/smoke/neutron_aria_cirros_guest_exec.py"

fail() { echo "ERROR: $*" >&2; exit 1; }

[ -f "${SOAK}" ] || fail "missing active matrix scheduler"
[ -f "${GUEST_EXEC}" ] || fail "missing guest execution helper"
bash -n "${SOAK}"
PYTHON_BIN="$(command -v python3 || command -v python || command -v python.exe || true)"
[ -n "${PYTHON_BIN}" ] || fail "missing Python interpreter"
"${PYTHON_BIN}" -m py_compile "${GUEST_EXEC}"

for marker in \
    systemd-run \
    Type=simple \
    scheduler.lock \
    checkpoint.json \
    skipped_active_tick \
    65535 \
    'single:1' \
    owned_resources_remaining \
    no_automatic_restart; do
    grep -q "${marker}" "${SOAK}" || fail "missing scheduler marker: ${marker}"
done
grep -q 'preflight)' "${SOAK}" || fail "missing non-mutating preflight action"
grep -q 'item.get("Field")' "${SOAK}" || fail "missing legacy neutron JSON adapter"

launch_line="$(grep -n 'systemd-run' "${SOAK}" | head -1 | cut -d: -f1)"
[ -n "${launch_line}" ] || fail "systemd launcher is missing"
if grep -q -- '--property=Restart' "${SOAK}"; then
    fail "scheduler must not automatically restart a failed gate"
fi

echo "neutron aria ACL active matrix scheduler contract passed"
