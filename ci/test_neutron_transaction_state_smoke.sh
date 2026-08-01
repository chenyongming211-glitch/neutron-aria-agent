#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SMOKE="${REPO_ROOT}/deploy/kolla/smoke/neutron_aria_transaction_state_smoke.sh"
ROOT="$(mktemp -d)"
trap 'rm -rf "${ROOT}"' EXIT

mkdir -p "${ROOT}/bin" "${ROOT}/state"
cat >"${ROOT}/bin/docker" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

command_name="$1"
shift
case "${command_name}" in
    ps)
        printf '%s\n' neutron_aria_agent aria_datapath
        ;;
    restart)
        ;;
    exec)
        while [ "$#" -gt 0 ]; do
            case "$1" in
                -i) shift ;;
                -u|-e) shift 2 ;;
                *) break ;;
            esac
        done
        shift
        case "${1:-}" in
            test|sh|neutron-aria-agent)
                ;;
            python)
                body="$(cat)"
                if grep -Fq 'print(len(client.status().get("managed_ports") or []))' <<<"${body}"; then
                    case "${FAKE_SCENARIO}" in
                        zero-count) printf '0\n' ;;
                        *) printf '1\n' ;;
                    esac
                elif grep -Fq 'for port in client.status().get("managed_ports") or []:' <<<"${body}"; then
                    counter_file="${FAKE_STATE_DIR}/first-port-count"
                    count=0
                    [ ! -f "${counter_file}" ] || count="$(cat "${counter_file}")"
                    count=$((count + 1))
                    printf '%s\n' "${count}" >"${counter_file}"
                    case "${FAKE_SCENARIO}:${count}" in
                        missing-first-id:*) ;;
                        missing-second-id:1) printf 'port-1\n' ;;
                    esac
                fi
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
chmod +x "${ROOT}/bin/docker"

run_case() {
    local scenario="$1"
    local expected="$2"
    local output rc
    rm -f "${ROOT}/state/first-port-count"
    set +e
    output="$(env -u MIN_MANAGED_PORTS \
        PATH="${ROOT}/bin:${PATH}" \
        REPO_ROOT="${REPO_ROOT}" \
        HOST_FQDN="test-host" \
        ADMINRC="${ROOT}/missing-adminrc" \
        OS_AUTH_URL="http://keystone.invalid" \
        OS_USERNAME="test" \
        OS_PASSWORD="test" \
        OS_PROJECT_NAME="test" \
        ROLLBACK=false \
        SMOKE_WAIT_SECONDS=0 \
        FAKE_SCENARIO="${scenario}" \
        FAKE_STATE_DIR="${ROOT}/state" \
        bash "${SMOKE}" 2>&1)"
    rc=$?
    set -e
    if [ "${rc}" -eq 0 ]; then
        echo "${scenario}: transaction smoke reported success without full port coverage" >&2
        return 1
    fi
    if ! grep -Fq "${expected}" <<<"${output}"; then
        echo "${scenario}: unexpected failure output" >&2
        echo "${output}" >&2
        return 1
    fi
}

failures=0
run_case zero-count \
    'managed port count 0 is below MIN_MANAGED_PORTS=1' || failures=$((failures + 1))
run_case missing-first-id \
    'no managed port with port_id available for pending delete recovery' || failures=$((failures + 1))
run_case missing-second-id \
    'no managed port with port_id available for migration-source cleanup' || failures=$((failures + 1))

[ "${failures}" -eq 0 ] || exit 1
printf 'transaction_state_port_coverage=pass\n'
