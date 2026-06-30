#!/usr/bin/env bash
set -euo pipefail

CONTAINER="${CONTAINER:-neutron_server}"
NEUTRON_CONF="${NEUTRON_CONF:-/etc/kolla/neutron-server/neutron.conf}"
SITE_PACKAGES="${SITE_PACKAGES:-/usr/lib/python2.7/site-packages}"
PLUGIN_PROVIDER="${PLUGIN_PROVIDER:-neutron_aria.services.aria_acl.plugin.AriaAclPlugin}"
EXTENSION_PATH="${EXTENSION_PATH:-${SITE_PACKAGES}/neutron_aria/extensions}"
POLICY_FILE="${POLICY_FILE:-/etc/neutron/policy.json}"
STATE_DIR="${STATE_DIR:-/var/tmp/neutron-aria-acl-plugin-smoke}"
REPO_ROOT="${REPO_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)}"
PACKAGE_SRC="${PACKAGE_SRC:-${REPO_ROOT}/openstack/neutron_aria/neutron_aria}"

usage() {
    cat <<EOF
Usage: $0 install|smoke|rollback

install   Backup neutron.conf/package, copy neutron_aria into ${CONTAINER},
          add the aria_acl service plugin provider, and restart neutron-server.
smoke     Check that neutron-server exposes the aria-acl extension.
rollback  Restore the latest backup and restart neutron-server.

This smoke intentionally validates plugin loading only. Persistent aria_acl DB
repository wiring is a separate stage-two gate.
EOF
}

log() {
    printf '[neutron-aria-acl-plugin-smoke] %s\n' "$*"
}

require_root_host() {
    if [ "$(id -u)" != "0" ]; then
        echo "This smoke must run as root on the OpenStack/Kolla host." >&2
        exit 1
    fi
}

require_inputs() {
    if [ ! -d "${PACKAGE_SRC}" ]; then
        echo "Missing PACKAGE_SRC: ${PACKAGE_SRC}" >&2
        exit 1
    fi
    if [ ! -f "${NEUTRON_CONF}" ]; then
        echo "Missing NEUTRON_CONF: ${NEUTRON_CONF}" >&2
        exit 1
    fi
    docker inspect "${CONTAINER}" >/dev/null
}

timestamp() {
    date +%Y%m%d%H%M%S
}

backup_current_state() {
    mkdir -p "${STATE_DIR}"
    local ts
    ts="$(timestamp)"
    local conf_backup="${STATE_DIR}/neutron.conf.${ts}.bak"
    local package_backup="${STATE_DIR}/neutron_aria.${ts}.tgz"
    local policy_backup="${STATE_DIR}/policy.json.${ts}.bak"

    cp -a "${NEUTRON_CONF}" "${conf_backup}"
    ln -sfn "${conf_backup}" "${STATE_DIR}/neutron.conf.latest.bak"

    if docker exec -u 0 "${CONTAINER}" test -f "${POLICY_FILE}"; then
        docker cp "${CONTAINER}:${POLICY_FILE}" "${policy_backup}"
        ln -sfn "${policy_backup}" "${STATE_DIR}/policy.json.latest.bak"
    else
        rm -f "${STATE_DIR}/policy.json.latest.bak"
    fi

    if docker exec -u 0 "${CONTAINER}" test -d "${SITE_PACKAGES}/neutron_aria"; then
        docker exec -u 0 "${CONTAINER}" tar -C "${SITE_PACKAGES}" -czf \
            "/tmp/neutron_aria.${ts}.tgz" neutron_aria
        docker cp "${CONTAINER}:/tmp/neutron_aria.${ts}.tgz" "${package_backup}"
        docker exec -u 0 "${CONTAINER}" rm -f "/tmp/neutron_aria.${ts}.tgz"
        ln -sfn "${package_backup}" "${STATE_DIR}/neutron_aria.latest.tgz"
    else
        rm -f "${STATE_DIR}/neutron_aria.latest.tgz"
    fi

    log "Backed up neutron.conf to ${conf_backup}"
}

copy_package_into_container() {
    log "Copying neutron_aria package into ${CONTAINER}:${SITE_PACKAGES}"
    docker exec -u 0 "${CONTAINER}" rm -rf /tmp/neutron_aria.smoke
    docker cp "${PACKAGE_SRC}" "${CONTAINER}:/tmp/neutron_aria.smoke"
    docker exec -u 0 "${CONTAINER}" sh -c "
        rm -rf '${SITE_PACKAGES}/neutron_aria' &&
        cp -a /tmp/neutron_aria.smoke '${SITE_PACKAGES}/neutron_aria' &&
        chmod -R a+rX '${SITE_PACKAGES}/neutron_aria' &&
        rm -rf /tmp/neutron_aria.smoke
    "
}

enable_service_plugin() {
    log "Adding aria_acl plugin provider to ${NEUTRON_CONF}"
    local python_bin
    python_bin="$(command -v python || command -v python3 || true)"
    if [ -z "${python_bin}" ]; then
        echo "Neither python nor python3 is available on the host." >&2
        exit 1
    fi
    "${python_bin}" - "$NEUTRON_CONF" "$PLUGIN_PROVIDER" "$EXTENSION_PATH" <<'PY'
from __future__ import print_function
import sys

path, provider, extension_path = sys.argv[1], sys.argv[2], sys.argv[3]
with open(path, "r") as fh:
    lines = fh.readlines()

changed = False
found_plugins = False
extension_paths = []
for line in lines:
    stripped = line.strip()
    if stripped.startswith("api_extensions_path"):
        _key, value = line.split("=", 1)
        for item in [item.strip() for item in value.split(":") if item.strip()]:
            if item not in extension_paths:
                extension_paths.append(item)

out = []
for line in lines:
    stripped = line.strip()
    if stripped.startswith("service_plugins"):
        found_plugins = True
        key, value = line.split("=", 1)
        plugins = [item.strip() for item in value.split(",") if item.strip()]
        if provider not in plugins and "aria_acl" not in plugins:
            plugins.append(provider)
            changed = True
        line = "%s= %s\n" % (key.rstrip(), ",".join(plugins))
        out.append(line)
        if extension_path not in extension_paths:
            extension_paths.append(extension_path)
            changed = True
        out.append("api_extensions_path = %s\n" % ":".join(extension_paths))
        continue
    elif stripped.startswith("api_extensions_path"):
        changed = True
        continue
    out.append(line)

if not found_plugins:
    out.append("service_plugins = %s\n" % provider)
    if extension_path not in extension_paths:
        extension_paths.append(extension_path)
    out.append("api_extensions_path = %s\n" % ":".join(extension_paths))
    changed = True

if changed:
    with open(path, "w") as fh:
        fh.writelines(out)
print("changed=%s" % changed)
PY
}

install_policy_rules() {
    log "Merging aria_acl policy rules into ${CONTAINER}:${POLICY_FILE}"
    docker exec -i -u 0 "${CONTAINER}" python - "${POLICY_FILE}" <<'PY'
from __future__ import print_function

import json
import os
import sys

from neutron_aria.policies.aria_acl import list_rules

path = sys.argv[1]
if os.path.exists(path):
    with open(path, "r") as handle:
        try:
            data = json.load(handle)
        except ValueError:
            data = {}
else:
    data = {}

changed = False
for key, value in list_rules().items():
    if data.get(key) != value:
        data[key] = value
        changed = True

if changed or not os.path.exists(path):
    tmp = "%s.tmp" % path
    with open(tmp, "w") as handle:
        json.dump(data, handle, indent=4, sort_keys=True)
        handle.write("\n")
    os.rename(tmp, path)

print("policy_changed=%s" % changed)
PY
}

restart_neutron_server() {
    log "Restarting ${CONTAINER}"
    docker restart "${CONTAINER}" >/dev/null
    log "Waiting for ${CONTAINER} to become running"
    for _ in $(seq 1 60); do
        if [ "$(docker inspect -f '{{.State.Running}}' "${CONTAINER}")" = "true" ]; then
            sleep 3
            return 0
        fi
        sleep 2
    done
    echo "${CONTAINER} did not become running" >&2
    docker logs --tail 120 "${CONTAINER}" >&2 || true
    exit 1
}

smoke_extension() {
    log "Checking aria-acl extension through Neutron CLI"
    if [ -f /root/adminrc ]; then
        bash -lc ". /root/adminrc && neutron ext-list" | tee "${STATE_DIR}/ext-list.latest.txt"
    elif [ -f /etc/kolla/.adminrc ]; then
        bash -lc ". /etc/kolla/.adminrc && neutron ext-list" | tee "${STATE_DIR}/ext-list.latest.txt"
    else
        echo "No adminrc found for Neutron CLI smoke." >&2
        exit 1
    fi
    grep -Eq '(^|\|)[[:space:]]*aria-acl[[:space:]]*(\||$)' \
        "${STATE_DIR}/ext-list.latest.txt"
    log "aria-acl extension is visible"
}

rollback() {
    require_root_host
    mkdir -p "${STATE_DIR}"
    local conf_backup="${STATE_DIR}/neutron.conf.latest.bak"
    if [ ! -e "${conf_backup}" ]; then
        echo "No neutron.conf backup found at ${conf_backup}" >&2
        exit 1
    fi

    log "Restoring ${NEUTRON_CONF}"
    cp -a "$(readlink -f "${conf_backup}")" "${NEUTRON_CONF}"

    if [ -e "${STATE_DIR}/neutron_aria.latest.tgz" ]; then
        log "Restoring previous neutron_aria package"
        docker cp "$(readlink -f "${STATE_DIR}/neutron_aria.latest.tgz")" \
            "${CONTAINER}:/tmp/neutron_aria.restore.tgz"
        docker exec -u 0 "${CONTAINER}" sh -c "
            rm -rf '${SITE_PACKAGES}/neutron_aria' &&
            tar -C '${SITE_PACKAGES}' -xzf /tmp/neutron_aria.restore.tgz &&
            chmod -R a+rX '${SITE_PACKAGES}/neutron_aria' &&
            rm -f /tmp/neutron_aria.restore.tgz
        "
    else
        log "Removing smoke-installed neutron_aria package"
        docker exec -u 0 "${CONTAINER}" rm -rf "${SITE_PACKAGES}/neutron_aria"
    fi

    if [ -e "${STATE_DIR}/policy.json.latest.bak" ]; then
        log "Restoring ${POLICY_FILE}"
        docker cp "$(readlink -f "${STATE_DIR}/policy.json.latest.bak")" \
            "${CONTAINER}:${POLICY_FILE}"
        docker exec -u 0 "${CONTAINER}" chmod 0640 "${POLICY_FILE}" || true
    fi

    restart_neutron_server
    log "Rollback complete"
}

install() {
    require_root_host
    require_inputs
    backup_current_state
    copy_package_into_container
    install_policy_rules
    enable_service_plugin
    restart_neutron_server
    smoke_extension
}

case "${1:-}" in
    install)
        install
        ;;
    smoke)
        require_root_host
        mkdir -p "${STATE_DIR}"
        smoke_extension
        ;;
    rollback)
        rollback
        ;;
    *)
        usage
        exit 2
        ;;
esac
