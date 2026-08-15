#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
INSTALLER="${REPO_ROOT}/deploy/kolla/package/install_neutronclient_aria_cli.sh"
ROOT="$(mktemp -d)"
trap 'rm -rf "${ROOT}"' EXIT

mkdir -p "${ROOT}/bin"
ADMIN_RC_FILE="${ROOT}/custom-adminrc"
ADMINRC_RECORD="${ROOT}/adminrc-record"
printf 'OS_AUTH_URL=http://keystone.invalid/v3\n' >"${ADMIN_RC_FILE}"

cat >"${ROOT}/bin/id" <<'EOF'
#!/usr/bin/env bash
if [ "${1:-}" = "-u" ]; then
    printf '0\n'
    exit 0
fi
exec /usr/bin/id "$@"
EOF

cat >"${ROOT}/bin/docker" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

[ "$1" = "exec" ] || exit 41
shift
env_file=""
while [[ "${1:-}" == -* ]]; do
    case "$1" in
        -i) shift ;;
        -u) shift 2 ;;
        --env-file) env_file="$2"; shift 2 ;;
        *) exit 42 ;;
    esac
done
shift
case "${1:-}" in
    python)
        cat >/dev/null
        printf 'neutronclient_aria_imports=ok\n'
        ;;
    neutron)
        [ "${env_file}" = "${EXPECTED_ADMIN_RC}" ] || exit 43
        printf '%s\n' "${env_file}" >"${ADMINRC_RECORD}"
        if [ "${2:-}" = "aria-acl-policy-show" ]; then
            printf '%s\n' '--with-rules'
        else
            printf 'aria-acl-policy-create\naria-acl-binding-create\n'
        fi
        ;;
    *) exit 44 ;;
esac
EOF
chmod +x "${ROOT}/bin/id" "${ROOT}/bin/docker"

admin_rc_file="${ADMIN_RC_FILE}"
set +e
PATH="${ROOT}/bin:${PATH}" \
    ADMIN_RC_FILE="${admin_rc_file}" \
    EXPECTED_ADMIN_RC="${admin_rc_file}" \
    ADMINRC_RECORD="${ADMINRC_RECORD}" \
    bash "${INSTALLER}" smoke >"${ROOT}/smoke.log" 2>&1
smoke_rc=$?
set -e

if [ "${smoke_rc}" -ne 0 ] || [ ! -f "${ADMINRC_RECORD}" ] || \
    [ "$(cat "${ADMINRC_RECORD}")" != "${ADMIN_RC_FILE}" ]; then
    echo "CLI smoke did not forward the custom ADMIN_RC_FILE" >&2
    exit 1
fi

set +e
missing_output="$(PATH="${ROOT}/bin:${PATH}" \
    ADMIN_RC_FILE="${ROOT}/missing-adminrc" \
    bash "${INSTALLER}" smoke 2>&1)"
missing_rc=$?
set -e
if [ "${missing_rc}" -eq 0 ] || \
    ! printf '%s\n' "${missing_output}" | grep -Fq 'not readable'; then
    echo "CLI smoke did not reject a missing ADMIN_RC_FILE clearly" >&2
    exit 1
fi

printf 'neutronclient_cli_adminrc_contract=pass\n'
