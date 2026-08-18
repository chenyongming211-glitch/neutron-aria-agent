#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
INSTALLER="${REPO_ROOT}/deploy/kolla/smoke/neutron_aria_acl_plugin_load_smoke.sh"
ROOT="$(mktemp -d)"
trap 'rm -rf "${ROOT}"' EXIT

FAKE_BIN="${ROOT}/bin"
CONTAINER_ROOT="${ROOT}/container"
STATE_DIR="${ROOT}/state"
NEUTRON_CONF="${ROOT}/neutron.conf"
PACKAGE_SRC="${ROOT}/package/neutron_aria"
SITE_PACKAGES="/site-packages"
EGG_NAME="neutron_aria-0.1.0-py2.7.egg"
POLICY_FILE="/etc/neutron/policy.json"
mkdir -p "${FAKE_BIN}" "${CONTAINER_ROOT}${SITE_PACKAGES}" "${PACKAGE_SRC}"
printf '[DEFAULT]\nservice_plugins = router\n' >"${NEUTRON_CONF}"
printf 'package\n' >"${PACKAGE_SRC}/__init__.py"
printf 'old-egg\n' >"${CONTAINER_ROOT}${SITE_PACKAGES}/${EGG_NAME}"
printf './%s\n' "${EGG_NAME}" \
    >"${CONTAINER_ROOT}${SITE_PACKAGES}/easy-install.pth"

cat >"${FAKE_BIN}/id" <<'EOF'
#!/usr/bin/env bash
if [ "${1:-}" = "-u" ]; then
    printf '0\n'
    exit 0
fi
exec /usr/bin/id "$@"
EOF

cat >"${FAKE_BIN}/date" <<'EOF'
#!/usr/bin/env bash
printf '20260801000000\n'
EOF

cat >"${FAKE_BIN}/sleep" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF

cat >"${FAKE_BIN}/docker" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

command_name="$1"
shift
case "${command_name}" in
    inspect)
        if [ "${1:-}" = "-f" ]; then
            printf 'true\n'
        fi
        ;;
    restart)
        if [ ! -e "${FAKE_RESTART_RECORD}" ]; then
            : >"${FAKE_RESTART_RECORD}"
            exit 75
        fi
        ;;
    cp)
        source_path="$1"
        target_path="$2"
        if [[ "${source_path}" == *:* ]]; then
            source_path="${FAKE_CONTAINER_ROOT}${source_path#*:}"
        else
            target_path="${FAKE_CONTAINER_ROOT}${target_path#*:}"
            mkdir -p "$(dirname "${target_path}")"
        fi
        command cp -a "${source_path}" "${target_path}"
        ;;
    exec)
        while [[ "${1:-}" == -* ]]; do
            if [ "$1" = "-u" ]; then
                shift 2
            else
                shift
            fi
        done
        shift
        case "${1:-}" in
            test)
                test "$2" "${FAKE_CONTAINER_ROOT}$3"
                ;;
            rm)
                shift
                option=""
                if [[ "${1:-}" == -* ]]; then
                    option="$1"
                    shift
                fi
                command rm ${option:+"${option}"} "${FAKE_CONTAINER_ROOT}$1"
                ;;
            chmod)
                ;;
            sed)
                pth="${FAKE_CONTAINER_ROOT}${!#}"
                grep -Fv "${EGG_NAME}" "${pth}" >"${pth}.tmp" 2>/dev/null || true
                mv "${pth}.tmp" "${pth}"
                ;;
            sh)
                rm -rf "${FAKE_CONTAINER_ROOT}${SITE_PACKAGES}/neutron_aria"
                cp -a "${FAKE_CONTAINER_ROOT}/tmp/neutron_aria.smoke" \
                    "${FAKE_CONTAINER_ROOT}${SITE_PACKAGES}/neutron_aria"
                rm -rf "${FAKE_CONTAINER_ROOT}/tmp/neutron_aria.smoke"
                ;;
            python)
                cat >/dev/null
                policy="${FAKE_CONTAINER_ROOT}${POLICY_FILE}"
                mkdir -p "$(dirname "${policy}")"
                printf '{"aria_acl:get": "rule:admin_only"}\n' >"${policy}"
                ;;
            *)
                echo "unsupported fake docker exec: $*" >&2
                exit 1
                ;;
        esac
        ;;
    *)
        echo "unsupported fake docker command: ${command_name}" >&2
        exit 1
        ;;
esac
EOF
chmod +x "${FAKE_BIN}"/*

export FAKE_CONTAINER_ROOT="${CONTAINER_ROOT}"
export FAKE_RESTART_RECORD="${ROOT}/restart-record"
export EGG_NAME NEUTRON_CONF PACKAGE_SRC POLICY_FILE SITE_PACKAGES STATE_DIR
export PATH="${FAKE_BIN}:${PATH}"

set +e
/bin/bash "${INSTALLER}" install >"${ROOT}/install.log" 2>&1
install_rc=$?
set -e
if [ "${install_rc}" -ne 75 ]; then
    echo "plugin install did not reach the injected post-policy failure" >&2
    cat "${ROOT}/install.log" >&2
    exit 1
fi
LATEST="${STATE_DIR}/policy.json.latest.bak"
if [ ! -e "${LATEST}" ]; then
    echo "first plugin install did not create a policy rollback marker" >&2
    exit 1
fi
case "$(python3 -c 'import os,sys; print(os.path.realpath(sys.argv[1]))' "${LATEST}")" in
    *.none) ;;
    *)
        echo "first plugin install policy marker is not a .none marker" >&2
        exit 1
        ;;
esac
test -f "${CONTAINER_ROOT}${POLICY_FILE}"
if [ -e "${CONTAINER_ROOT}${SITE_PACKAGES}/${EGG_NAME}" ]; then
    echo "plugin install left a stale egg shadowing the copied package" >&2
    exit 1
fi
if grep -Fq "${EGG_NAME}" \
    "${CONTAINER_ROOT}${SITE_PACKAGES}/easy-install.pth"; then
    echo "plugin install left the stale egg active in easy-install.pth" >&2
    exit 1
fi

/bin/bash "${INSTALLER}" rollback >"${ROOT}/rollback.log"
if [ -e "${CONTAINER_ROOT}${POLICY_FILE}" ]; then
    echo "first-install rollback left the smoke-created policy file" >&2
    exit 1
fi
grep -Fqx 'old-egg' \
    "${CONTAINER_ROOT}${SITE_PACKAGES}/${EGG_NAME}"
grep -Fqx "./${EGG_NAME}" \
    "${CONTAINER_ROOT}${SITE_PACKAGES}/easy-install.pth"

printf 'plugin_policy_first_install_rollback=pass\n'
