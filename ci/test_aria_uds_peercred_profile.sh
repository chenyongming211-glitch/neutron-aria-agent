#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="${REPO_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
INSTALLER="${REPO_ROOT}/deploy/kolla/package/install_aria_uds_peercred_profile.sh"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "${TMP_DIR}"' EXIT

SOURCE_CONFIG="${TMP_DIR}/aria-agent-openstack.toml"
FIRST_RENDER="${TMP_DIR}/hardened-first.toml"
SECOND_RENDER="${TMP_DIR}/hardened-second.toml"

cat >"${SOURCE_CONFIG}" <<'EOF'
mode = "neutron_managed"
neutron_socket_path = "/run/aria/aria-agent.sock"
neutron_socket_mode = 438
neutron_peercred_enforce = false
neutron_peercred_allowed_uids = []
neutron_peercred_allowed_gids = [999]
neutron_audit_log_path = "/tmp/old-audit.log"
ovs_bridge = "br-int"
EOF

CONFIG_PATH="${SOURCE_CONFIG}" \
OUTPUT_PATH="${FIRST_RENDER}" \
NEUTRON_UID=42435 \
NEUTRON_GID=42435 \
    bash "${INSTALLER}" render

grep -Fx 'mode = "neutron_managed"' "${FIRST_RENDER}" >/dev/null
grep -Fx 'ovs_bridge = "br-int"' "${FIRST_RENDER}" >/dev/null
grep -Fx 'neutron_socket_mode = 432' "${FIRST_RENDER}" >/dev/null
grep -Fx 'neutron_peercred_enforce = true' "${FIRST_RENDER}" >/dev/null
grep -Fx 'neutron_peercred_allowed_uids = [42435]' "${FIRST_RENDER}" >/dev/null
grep -Fx 'neutron_peercred_allowed_gids = [42435]' "${FIRST_RENDER}" >/dev/null
grep -Fx 'neutron_audit_log_path = "/var/log/kolla/aria-datapath/neutron-uds-audit.log"' \
    "${FIRST_RENDER}" >/dev/null

for key in \
    neutron_socket_mode \
    neutron_peercred_enforce \
    neutron_peercred_allowed_uids \
    neutron_peercred_allowed_gids \
    neutron_audit_log_path; do
    [ "$(grep -Ec "^[[:space:]]*${key}[[:space:]]*=" "${FIRST_RENDER}")" = "1" ]
done

CONFIG_PATH="${FIRST_RENDER}" \
OUTPUT_PATH="${SECOND_RENDER}" \
NEUTRON_UID=42435 \
NEUTRON_GID=42435 \
    bash "${INSTALLER}" render
cmp "${FIRST_RENDER}" "${SECOND_RENDER}"

CONFIG_PATH="${FIRST_RENDER}" \
NEUTRON_UID=42435 \
NEUTRON_GID=42435 \
    bash "${INSTALLER}" check-config

MIDDLE_FIELD_MISMATCH="${TMP_DIR}/middle-field-mismatch.toml"
cp "${FIRST_RENDER}" "${MIDDLE_FIELD_MISMATCH}"
sed -i 's/^neutron_peercred_allowed_gids = \[42435\]$/neutron_peercred_allowed_gids = []/' \
    "${MIDDLE_FIELD_MISMATCH}"
bash -c 'source "$1"; type check_config >/dev/null' _ "${INSTALLER}"
if CONFIG_PATH="${MIDDLE_FIELD_MISMATCH}" \
    NEUTRON_UID=42435 \
    NEUTRON_GID=42435 \
        bash "${INSTALLER}" check-config >/dev/null 2>&1; then
    echo "check-config ignored a middle-field mismatch" >&2
    exit 1
fi
if CONFIG_PATH="${MIDDLE_FIELD_MISMATCH}" \
    NEUTRON_UID=42435 \
    NEUTRON_GID=42435 \
    INSTALLER="${INSTALLER}" \
        bash -c 'source "${INSTALLER}"; if check_config; then exit 0; else exit 1; fi' \
        >/dev/null 2>&1; then
    echo "conditional check-config ignored a middle-field mismatch" >&2
    exit 1
fi

if CONFIG_PATH="${SOURCE_CONFIG}" \
    OUTPUT_PATH="${TMP_DIR}/invalid.toml" \
    NEUTRON_UID=not-a-number \
    NEUTRON_GID=42435 \
        bash "${INSTALLER}" render >/dev/null 2>&1; then
    echo "render accepted a non-numeric Neutron UID" >&2
    exit 1
fi

if CONFIG_PATH="${SOURCE_CONFIG}" \
    OUTPUT_PATH="${TMP_DIR}/root-identity.toml" \
    NEUTRON_UID=0 \
    NEUTRON_GID=0 \
        bash "${INSTALLER}" render >/dev/null 2>&1; then
    echo "render accepted root as the Neutron peer identity" >&2
    exit 1
fi

SAME_PATH_CONFIG="${TMP_DIR}/same-path.toml"
cp "${SOURCE_CONFIG}" "${SAME_PATH_CONFIG}"
if CONFIG_PATH="${SAME_PATH_CONFIG}" \
    OUTPUT_PATH="${SAME_PATH_CONFIG}" \
    NEUTRON_UID=42435 \
    NEUTRON_GID=42435 \
        bash "${INSTALLER}" render >/dev/null 2>&1; then
    echo "render accepted the source path as OUTPUT_PATH" >&2
    exit 1
fi
cmp "${SOURCE_CONFIG}" "${SAME_PATH_CONFIG}"

if CONFIG_PATH="${SOURCE_CONFIG}" \
    NEUTRON_UID=42435 \
    NEUTRON_GID=42435 \
        bash "${INSTALLER}" check-config >/dev/null 2>&1; then
    echo "check-config accepted the audit-only profile" >&2
    exit 1
fi

tmpfiles_line="$({
    RUN_ARIA_DIR=/run/aria \
    HOST_GROUP_NAME=aria-neutron \
    INSTALLER="${INSTALLER}" \
        bash -c 'source "${INSTALLER}"; expected_tmpfiles_line'
})"
[ "${tmpfiles_line}" = 'd /run/aria 0770 root aria-neutron -' ] || {
    echo "unexpected runtime-directory tmpfiles profile: ${tmpfiles_line}" >&2
    exit 1
}

echo "aria_uds_peercred_profile_contract=pass"
