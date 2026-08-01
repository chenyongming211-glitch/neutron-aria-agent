#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
INSTALLER="${REPO_ROOT}/deploy/kolla/package/install_neutron_aria_agent_egg.sh"
ROOT="$(mktemp -d)"
trap 'rm -rf "${ROOT}"' EXIT

FAKE_BIN="${ROOT}/bin"
CONTAINER_ROOT="${ROOT}/container"
STATE_DIR="${ROOT}/state"
SITE_PACKAGES="/site-packages"
EGG_NAME="neutron_aria-0.1.0-py2.7.egg"
EGG_PATH="${ROOT}/${EGG_NAME}"
ENTRYPOINT_PATH="/usr/local/bin/neutron-aria-agent"
mkdir -p "${FAKE_BIN}" "${CONTAINER_ROOT}${SITE_PACKAGES}"
printf 'new-agent-egg\n' >"${EGG_PATH}"

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

cat >"${FAKE_BIN}/docker" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

command_name="$1"
shift
case "${command_name}" in
    inspect)
        exit 0
        ;;
    cp)
        source_path="$1"
        target_path="$2"
        if [[ "${source_path}" == *:* ]]; then
            source_path="${FAKE_CONTAINER_ROOT}${source_path#*:}"
            command cp "${source_path}" "${target_path}"
        else
            target_path="${FAKE_CONTAINER_ROOT}${target_path#*:}"
            mkdir -p "$(dirname "${target_path}")"
            command cp "${source_path}" "${target_path}"
        fi
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
                [ "$2" = "-f" ]
                test -f "${FAKE_CONTAINER_ROOT}$3"
                ;;
            rm)
                shift
                rm "$1" "${FAKE_CONTAINER_ROOT}$2"
                ;;
            chmod)
                command chmod "$2" "${FAKE_CONTAINER_ROOT}$3"
                ;;
            python)
                cat >/dev/null
                if [ "$2" = "-" ] && [ "$#" -ge 4 ]; then
                    pth="${FAKE_CONTAINER_ROOT}$3/easy-install.pth"
                    mkdir -p "$(dirname "${pth}")"
                    grep -Fvx "$4" "${pth}" >"${pth}.tmp" 2>/dev/null || true
                    printf '%s\n' "$4" >>"${pth}.tmp"
                    mv "${pth}.tmp" "${pth}"
                fi
                ;;
            sed)
                pth="${FAKE_CONTAINER_ROOT}${!#}"
                grep -Fv "${EGG_NAME}" "${pth}" >"${pth}.tmp" 2>/dev/null || true
                mv "${pth}.tmp" "${pth}"
                ;;
            sh)
                target="${FAKE_CONTAINER_ROOT}${!#}"
                mkdir -p "$(dirname "${target}")"
                cat >"${target}"
                ;;
            neutron-aria-agent)
                test -x "${FAKE_CONTAINER_ROOT}${ENTRYPOINT_PATH}"
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
chmod +x "${FAKE_BIN}/id" "${FAKE_BIN}/date" "${FAKE_BIN}/docker"

export EGG_NAME EGG_PATH ENTRYPOINT_PATH SITE_PACKAGES STATE_DIR
export FAKE_CONTAINER_ROOT="${CONTAINER_ROOT}"
export PATH="${FAKE_BIN}:${PATH}"

bash "${INSTALLER}" install >"${ROOT}/install.log"
LATEST="${STATE_DIR}/${EGG_NAME}.latest.bak"
if [ ! -e "${LATEST}" ]; then
    echo "first install did not create a rollback marker" >&2
    exit 1
fi
case "$(python3 -c 'import os,sys; print(os.path.realpath(sys.argv[1]))' "${LATEST}")" in
    *.none) ;;
    *)
        echo "first install rollback marker is not a .none marker" >&2
        exit 1
        ;;
esac

test -f "${CONTAINER_ROOT}${SITE_PACKAGES}/${EGG_NAME}"
test -x "${CONTAINER_ROOT}${ENTRYPOINT_PATH}"
grep -Fqx "./${EGG_NAME}" \
    "${CONTAINER_ROOT}${SITE_PACKAGES}/easy-install.pth"

bash "${INSTALLER}" rollback >"${ROOT}/rollback.log"
test ! -e "${CONTAINER_ROOT}${SITE_PACKAGES}/${EGG_NAME}"
test ! -e "${CONTAINER_ROOT}${ENTRYPOINT_PATH}"
if grep -Fq "${EGG_NAME}" \
    "${CONTAINER_ROOT}${SITE_PACKAGES}/easy-install.pth"; then
    echo "first-install rollback left an easy-install.pth entry" >&2
    exit 1
fi

printf 'old-agent-egg\n' >"${CONTAINER_ROOT}${SITE_PACKAGES}/${EGG_NAME}"
mkdir -p "$(dirname "${CONTAINER_ROOT}${ENTRYPOINT_PATH}")"
cat >"${CONTAINER_ROOT}${ENTRYPOINT_PATH}" <<'EOF'
#!/usr/bin/env bash
printf 'old-agent-entrypoint\n'
EOF
chmod 0755 "${CONTAINER_ROOT}${ENTRYPOINT_PATH}"

bash "${INSTALLER}" install >"${ROOT}/upgrade.log"
grep -Fqx 'new-agent-egg' \
    "${CONTAINER_ROOT}${SITE_PACKAGES}/${EGG_NAME}"
grep -Fq 'from neutron_aria.agent.main import main' \
    "${CONTAINER_ROOT}${ENTRYPOINT_PATH}"

bash "${INSTALLER}" rollback >"${ROOT}/upgrade-rollback.log"
grep -Fqx 'old-agent-egg' \
    "${CONTAINER_ROOT}${SITE_PACKAGES}/${EGG_NAME}"
grep -Fq 'old-agent-entrypoint' \
    "${CONTAINER_ROOT}${ENTRYPOINT_PATH}"

printf 'agent_first_install_rollback=pass\n'
