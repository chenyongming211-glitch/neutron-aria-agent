#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SMOKE="${REPO_ROOT}/deploy/kolla/smoke/neutron_aria_acl_db_crud_smoke.sh"
ROOT="$(mktemp -d)"
trap 'rm -rf "${ROOT}"' EXIT

mkdir -p "${ROOT}/bin"
ADMIN_RC_FILE="${ROOT}/custom-adminrc"
ADMINRC_RECORD="${ROOT}/adminrc-record"
cat >"${ADMIN_RC_FILE}" <<'EOF'
export ADMINRC_SOURCE_MARKER=loaded
EOF

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
while [ "$#" -gt 0 ]; do
    case "$1" in
        -i) shift ;;
        -u) shift 2 ;;
        --env-file) env_file="$2"; shift 2 ;;
        *) break ;;
    esac
done
container="$1"
shift
case "${container}:${1:-}" in
    neutron_server:python)
        cat >/dev/null
        printf 'plugin_db_crud=ok\n'
        ;;
    openstack_client:openstack)
        [ "${env_file}" = "${EXPECTED_ADMIN_RC}" ] || exit 42
        [ "${ADMINRC_SOURCE_MARKER:-}" = "loaded" ] || exit 43
        printf '%s\n' "${env_file}" >"${ADMINRC_RECORD}"
        printf 'test-token\n'
        ;;
    *)
        exit 44
        ;;
esac
EOF

cat >"${ROOT}/bin/curl" <<'EOF'
#!/usr/bin/env bash
exit 77
EOF
chmod +x "${ROOT}/bin/id" "${ROOT}/bin/docker" "${ROOT}/bin/curl"

set +e
output="$(PATH="${ROOT}/bin:${PATH}" \
    ADMIN_RC_FILE="${ADMIN_RC_FILE}" \
    EXPECTED_ADMIN_RC="${ADMIN_RC_FILE}" \
    ADMINRC_RECORD="${ADMINRC_RECORD}" \
    bash "${SMOKE}" 2>&1)"
rc=$?
set -e

if [ "${rc}" -ne 77 ]; then
    echo "DB CRUD smoke did not reach the expected downstream boundary" >&2
    echo "${output}" >&2
    exit 1
fi
if [ ! -f "${ADMINRC_RECORD}" ] || \
    [ "$(cat "${ADMINRC_RECORD}")" != "${ADMIN_RC_FILE}" ]; then
    echo "DB CRUD smoke did not source and forward the same ADMIN_RC_FILE" >&2
    exit 1
fi

printf 'db_crud_adminrc_contract=pass\n'
