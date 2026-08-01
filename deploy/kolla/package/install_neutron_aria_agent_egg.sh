#!/usr/bin/env bash
set -euo pipefail

SERVICE_NAME="${SERVICE_NAME:-neutron_aria_agent}"
EGG_PATH="${EGG_PATH:-}"
SITE_PACKAGES="${SITE_PACKAGES:-/usr/lib/python2.7/site-packages}"
EGG_NAME="${EGG_NAME:-neutron_aria-0.1.0-py2.7.egg}"
STATE_DIR="${STATE_DIR:-/var/tmp/neutron-aria-agent-package}"
REPO_ROOT="${REPO_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)}"
RESTART_AGENT_AFTER_INSTALL="${RESTART_AGENT_AFTER_INSTALL:-false}"
RESTART_AGENT_AFTER_ROLLBACK="${RESTART_AGENT_AFTER_ROLLBACK:-false}"

usage() {
    cat <<EOF
Usage: $0 install|smoke|rollback

install   Build or use an egg, backup current agent egg, copy it into
          ${SERVICE_NAME}, fix permissions, optionally restart the container,
          and validate imports/entrypoint.
smoke     Validate the current ${SERVICE_NAME} egg can import production ACL
          source code and run the neutron-aria-agent console entry point.
rollback  Restore the latest backed-up agent egg, or remove the agent egg if
          no previous installation existed.
EOF
}

restart_agent_if_requested() {
    local enabled="$1"
    [ "${enabled}" = "true" ] || return 0
    log "Restarting ${SERVICE_NAME} to load installed agent egg"
    docker restart "${SERVICE_NAME}" >/dev/null
    local i
    for i in $(seq 1 30); do
        if docker ps --format '{{.Names}}' | grep -qx "${SERVICE_NAME}"; then
            return 0
        fi
        sleep 1
    done
    echo "${SERVICE_NAME} did not become running after restart" >&2
    exit 1
}

log() {
    printf '[neutron-aria-agent-package] %s\n' "$*"
}

require_root_host() {
    if [ "$(id -u)" != "0" ]; then
        echo "This package installer must run as root on the Kolla host." >&2
        exit 1
    fi
}

timestamp() {
    date +%Y%m%d%H%M%S
}

container_egg_path() {
    printf '%s/%s' "${SITE_PACKAGES}" "${EGG_NAME}"
}

resolve_egg() {
    if [ -n "${EGG_PATH}" ]; then
        [ -f "${EGG_PATH}" ] || {
            echo "Missing EGG_PATH: ${EGG_PATH}" >&2
            exit 1
        }
        printf '%s\n' "${EGG_PATH}"
        return
    fi
    EGG_PATH="${REPO_ROOT}/dist/kolla/${EGG_NAME}" \
        bash "${REPO_ROOT}/deploy/kolla/package/build_neutron_aria_egg.sh" >/dev/null
    printf '%s\n' "${REPO_ROOT}/dist/kolla/${EGG_NAME}"
}

backup_current_egg() {
    mkdir -p "${STATE_DIR}"
    local ts backup marker
    ts="$(timestamp)"
    marker="${STATE_DIR}/${EGG_NAME}.${ts}.none"
    backup="${STATE_DIR}/${EGG_NAME}.${ts}.bak"
    if docker exec -u 0 "${SERVICE_NAME}" test -f "$(container_egg_path)"; then
        docker cp "${SERVICE_NAME}:$(container_egg_path)" "${backup}"
        ln -sfn "${backup}" "${STATE_DIR}/${EGG_NAME}.latest.bak"
        log "Backed up current agent egg to ${backup}"
    else
        : > "${marker}"
        ln -sfn "${marker}" "${STATE_DIR}/${EGG_NAME}.latest.bak"
        log "No existing agent egg found; rollback will remove the installation"
    fi
}

refresh_easy_install_pth() {
    local target_entry="./${EGG_NAME}"
    docker exec -i -u 0 "${SERVICE_NAME}" python - "${SITE_PACKAGES}" "${target_entry}" <<'PY'
from __future__ import print_function

import os
import sys

site_packages = sys.argv[1]
target_entry = sys.argv[2]
pth = os.path.join(site_packages, "easy-install.pth")
start = "import sys; sys.__plen = len(sys.path)\n"
end = (
    "import sys; new=sys.path[sys.__plen:]; "
    "del sys.path[sys.__plen:]; p=getattr(sys,'__egginsert',0); "
    "sys.path[p:p]=new; sys.__egginsert = p+len(new)\n"
)

try:
    with open(pth, "r") as fh:
        lines = fh.readlines()
except IOError:
    lines = [start, end]

lines = [
    line for line in lines
    if "neutron_aria-0.1.0-py2.7" not in line
]
if not lines or lines[0] != start:
    lines.insert(0, start)
if end not in lines:
    lines.append(end)

insert_at = lines.index(end) if end in lines else len(lines)
lines.insert(insert_at, target_entry + "\n")

with open(pth, "w") as fh:
    fh.writelines(lines)
PY
}

install_egg() {
    require_root_host
    docker inspect "${SERVICE_NAME}" >/dev/null
    local egg
    egg="$(resolve_egg)"
    backup_current_egg
    log "Installing ${egg} into ${SERVICE_NAME}:$(container_egg_path)"
    docker exec -u 0 "${SERVICE_NAME}" rm -rf "$(container_egg_path)"
    docker cp "${egg}" "${SERVICE_NAME}:$(container_egg_path)"
    docker exec -u 0 "${SERVICE_NAME}" chmod 0644 "$(container_egg_path)"
    refresh_easy_install_pth
    restart_agent_if_requested "${RESTART_AGENT_AFTER_INSTALL}"
    smoke
}

smoke() {
    require_root_host
    docker exec -i -u neutron "${SERVICE_NAME}" python - <<'PY'
from __future__ import print_function

from neutron_aria.agent.acl_source import NeutronAclSource
from neutron_aria.agent.neutron_client import build_aria_acl_client_from_env
from neutron_aria.agent.uds_client import LocalClient

print("agent_imports=ok")
PY
    docker exec -u neutron "${SERVICE_NAME}" neutron-aria-agent --help >/dev/null
    log "agent egg smoke ok"
}

rollback() {
    require_root_host
    local backup="${STATE_DIR}/${EGG_NAME}.latest.bak"
    if [ ! -e "${backup}" ]; then
        echo "No agent egg backup marker found at ${backup}" >&2
        exit 1
    fi
    local target
    target="$(readlink -f "${backup}")"
    if [ -f "${target}" ] && [ "${target##*.}" = "bak" ]; then
        log "Restoring agent egg from ${backup}"
        docker cp "${target}" "${SERVICE_NAME}:$(container_egg_path)"
        docker exec -u 0 "${SERVICE_NAME}" chmod 0644 "$(container_egg_path)"
        restart_agent_if_requested "${RESTART_AGENT_AFTER_ROLLBACK}"
        smoke
    else
        log "Removing agent egg from ${SERVICE_NAME}"
        docker exec -u 0 "${SERVICE_NAME}" rm -f "$(container_egg_path)"
        docker exec -u 0 "${SERVICE_NAME}" \
            sed -i "\\|${EGG_NAME}|d" "${SITE_PACKAGES}/easy-install.pth" || true
        restart_agent_if_requested "${RESTART_AGENT_AFTER_ROLLBACK}"
    fi
    log "agent egg rollback complete"
}

case "${1:-}" in
    install)
        install_egg
        ;;
    smoke)
        smoke
        ;;
    rollback)
        rollback
        ;;
    *)
        usage
        exit 2
        ;;
esac
