#!/usr/bin/env bash
set -euo pipefail

SERVICE_NAME="${SERVICE_NAME:-openstack_client}"
REPO_ROOT="${REPO_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)}"
SOURCE_DIR="${SOURCE_DIR:-${REPO_ROOT}/openstack/neutronclient_aria}"
STATE_DIR="${STATE_DIR:-/var/tmp/neutronclient-aria-package}"
SITE_PACKAGES="${SITE_PACKAGES:-/usr/lib/python2.7/site-packages}"
EGG_NAME="${EGG_NAME:-neutronclient_aria-0.1.0-py2.7.egg}"

usage() {
    cat <<EOF
Usage: $0 install|smoke|rollback

install   Install the legacy neutronclient aria-acl command extension into
          ${SERVICE_NAME}, then validate command discovery.
smoke     Validate that ${SERVICE_NAME} exposes aria-acl neutron commands.
rollback  Restore the latest backed-up extension egg, or remove the extension
          if no previous egg existed.
EOF
}

log() {
    printf '[neutronclient-aria-package] %s\n' "$*"
}

require_root_host() {
    if [ "$(id -u)" != "0" ]; then
        echo "This CLI package installer must run as root on the Kolla host." >&2
        exit 1
    fi
}

timestamp() {
    date +%Y%m%d%H%M%S
}

container_egg_path() {
    printf '%s/%s' "${SITE_PACKAGES}" "${EGG_NAME}"
}

backup_current_egg() {
    mkdir -p "${STATE_DIR}"
    local ts backup marker
    ts="$(timestamp)"
    marker="${STATE_DIR}/${EGG_NAME}.${ts}.none"
    if docker exec -u 0 "${SERVICE_NAME}" test -f "$(container_egg_path)"; then
        backup="${STATE_DIR}/${EGG_NAME}.${ts}.bak"
        docker cp "${SERVICE_NAME}:$(container_egg_path)" "${backup}"
        ln -sfn "${backup}" "${STATE_DIR}/${EGG_NAME}.latest.bak"
        log "Backed up current CLI egg to ${backup}"
    else
        : > "${marker}"
        ln -sfn "${marker}" "${STATE_DIR}/${EGG_NAME}.latest.bak"
        log "No existing CLI egg found; rollback will remove the extension"
    fi
}

install_cli() {
    require_root_host
    docker inspect "${SERVICE_NAME}" >/dev/null
    [ -d "${SOURCE_DIR}" ] || {
        echo "Missing SOURCE_DIR: ${SOURCE_DIR}" >&2
        exit 1
    }
    backup_current_egg
    log "Installing neutronclient aria-acl commands into ${SERVICE_NAME}"
    docker exec -u 0 "${SERVICE_NAME}" rm -rf /tmp/neutronclient_aria
    docker cp "${SOURCE_DIR}" "${SERVICE_NAME}:/tmp/neutronclient_aria"
    docker exec -u 0 "${SERVICE_NAME}" bash -lc \
        'cd /tmp/neutronclient_aria && python setup.py install'
    smoke
}

smoke() {
    require_root_host
    docker exec -i -u 0 "${SERVICE_NAME}" python - <<'PY'
from __future__ import print_function

from neutronclient_aria.v2_0 import aria_acl

assert hasattr(aria_acl, "AriaAclPolicyCreate")
assert hasattr(aria_acl, "AriaAclBindingCreate")
print("neutronclient_aria_imports=ok")
PY
    local help_output
    help_output="$(docker exec -u 0 --env-file /etc/kolla/.adminrc \
        "${SERVICE_NAME}" neutron help 2>&1)"
    printf '%s\n' "${help_output}" | grep -q 'aria-acl-policy-create' || {
        printf '%s\n' "${help_output}" >&2
        echo "aria-acl CLI commands are not visible in neutron help" >&2
        exit 1
    }
    printf '%s\n' "${help_output}" | grep -q 'aria-acl-binding-create' || {
        printf '%s\n' "${help_output}" >&2
        echo "aria-acl binding CLI command is not visible in neutron help" >&2
        exit 1
    }
    log "neutronclient aria-acl CLI smoke ok"
}

rollback() {
    require_root_host
    local backup="${STATE_DIR}/${EGG_NAME}.latest.bak"
    if [ ! -e "${backup}" ]; then
        echo "No CLI extension backup marker found at ${backup}" >&2
        exit 1
    fi
    local target
    target="$(readlink -f "${backup}")"
    if [ -f "${target}" ] && [ "${target##*.}" = "bak" ]; then
        log "Restoring CLI egg from ${backup}"
        docker cp "${target}" "${SERVICE_NAME}:$(container_egg_path)"
    else
        log "Removing CLI egg from ${SERVICE_NAME}"
        docker exec -u 0 "${SERVICE_NAME}" rm -f "$(container_egg_path)"
        docker exec -u 0 "${SERVICE_NAME}" \
            sed -i '/neutronclient_aria-0.1.0-py2.7.egg/d' \
            "${SITE_PACKAGES}/easy-install.pth" || true
    fi
    log "CLI extension rollback complete"
}

case "${1:-}" in
    install)
        install_cli
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
