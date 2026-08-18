#!/usr/bin/env bash
set -euo pipefail

CONTAINER="${CONTAINER:-neutron_server}"
NEUTRON_CONF="${NEUTRON_CONF:-/etc/kolla/neutron-server/neutron.conf}"
SITE_PACKAGES="${SITE_PACKAGES:-/usr/lib/python2.7/site-packages}"
EGG_NAME="${EGG_NAME:-neutron_aria-0.1.0-py2.7.egg}"
EGG_PATH="${EGG_PATH:-${SITE_PACKAGES}/${EGG_NAME}}"
EASY_INSTALL_PTH="${EASY_INSTALL_PTH:-${SITE_PACKAGES}/easy-install.pth}"
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
    local policy_meta="${STATE_DIR}/policy.json.${ts}.meta"
    local policy_marker="${STATE_DIR}/policy.json.${ts}.none"

    cp -a "${NEUTRON_CONF}" "${conf_backup}"
    ln -sfn "${conf_backup}" "${STATE_DIR}/neutron.conf.latest.bak"

    if docker exec -u 0 "${CONTAINER}" test -f "${POLICY_FILE}"; then
        docker cp "${CONTAINER}:${POLICY_FILE}" "${policy_backup}"
        docker exec -u 0 "${CONTAINER}" stat -c '%u:%g %a' "${POLICY_FILE}" \
            > "${policy_meta}"
        ln -sfn "${policy_backup}" "${STATE_DIR}/policy.json.latest.bak"
        ln -sfn "${policy_meta}" "${STATE_DIR}/policy.json.latest.meta"
    else
        : > "${policy_marker}"
        ln -sfn "${policy_marker}" "${STATE_DIR}/policy.json.latest.bak"
        rm -f "${STATE_DIR}/policy.json.latest.meta"
        log "No existing policy file found; rollback will remove the installation"
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

    backup_optional_container_file \
        "${EGG_PATH}" \
        "${STATE_DIR}/${EGG_NAME}.${ts}" \
        "${STATE_DIR}/${EGG_NAME}.latest.bak"
    backup_optional_container_file \
        "${EASY_INSTALL_PTH}" \
        "${STATE_DIR}/easy-install.pth.${ts}" \
        "${STATE_DIR}/easy-install.pth.latest.bak"

    log "Backed up neutron.conf to ${conf_backup}"
}

backup_optional_container_file() {
    local container_path="$1" backup_prefix="$2" latest="$3"
    local backup="${backup_prefix}.bak" marker="${backup_prefix}.none"
    if docker exec -u 0 "${CONTAINER}" test -f "${container_path}"; then
        docker cp "${CONTAINER}:${container_path}" "${backup}"
        ln -sfn "${backup}" "${latest}"
    else
        : >"${marker}"
        ln -sfn "${marker}" "${latest}"
    fi
}

copy_package_into_container() {
    log "Copying neutron_aria package into ${CONTAINER}:${SITE_PACKAGES}"
    docker exec -u 0 "${CONTAINER}" rm -f "${EGG_PATH}"
    docker exec -u 0 "${CONTAINER}" \
        sed -i "\\|${EGG_NAME}|d" "${EASY_INSTALL_PTH}" 2>/dev/null || true
    docker exec -u 0 "${CONTAINER}" rm -rf /tmp/neutron_aria.smoke
    docker cp "${PACKAGE_SRC}" "${CONTAINER}:/tmp/neutron_aria.smoke"
    docker exec -u 0 "${CONTAINER}" sh -c "
        rm -rf '${SITE_PACKAGES}/neutron_aria' &&
        cp -a /tmp/neutron_aria.smoke '${SITE_PACKAGES}/neutron_aria' &&
        chmod -R a+rX '${SITE_PACKAGES}/neutron_aria' &&
        rm -rf /tmp/neutron_aria.smoke
    "
}

restore_optional_container_file() {
    local latest="$1" container_path="$2" mode="$3"
    [ -e "${latest}" ] || return 0
    local source
    source="$(readlink -f "${latest}")"
    case "${source}" in
        *.bak)
            docker cp "${source}" "${CONTAINER}:${container_path}"
            docker exec -u 0 "${CONTAINER}" chmod "${mode}" "${container_path}"
            ;;
        *.none)
            docker exec -u 0 "${CONTAINER}" rm -f "${container_path}"
            ;;
        *)
            echo "Unknown package rollback marker: ${source}" >&2
            exit 1
            ;;
    esac
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

import sys

from neutron_aria.policies.aria_acl import merge_policy_file

path = sys.argv[1]
changed = merge_policy_file(path)
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

    restore_optional_container_file \
        "${STATE_DIR}/${EGG_NAME}.latest.bak" "${EGG_PATH}" 0644
    restore_optional_container_file \
        "${STATE_DIR}/easy-install.pth.latest.bak" "${EASY_INSTALL_PTH}" 0644

    local policy_backup="${STATE_DIR}/policy.json.latest.bak"
    if [ -e "${policy_backup}" ]; then
        local policy_target
        policy_target="$(readlink -f "${policy_backup}")"
        case "${policy_target}" in
            *.bak)
                log "Restoring ${POLICY_FILE}"
                docker cp "${policy_target}" "${CONTAINER}:${POLICY_FILE}"
                local policy_meta="${STATE_DIR}/policy.json.latest.meta"
                if [ -e "${policy_meta}" ]; then
                    local policy_owner policy_mode
                    read -r policy_owner policy_mode < "$(readlink -f "${policy_meta}")"
                    docker exec -u 0 "${CONTAINER}" chown \
                        "${policy_owner}" "${POLICY_FILE}"
                    docker exec -u 0 "${CONTAINER}" chmod \
                        "${policy_mode}" "${POLICY_FILE}"
                fi
                ;;
            *.none)
                log "Removing smoke-installed ${POLICY_FILE}"
                docker exec -u 0 "${CONTAINER}" rm -f "${POLICY_FILE}"
                ;;
            *)
                echo "Unknown policy rollback marker: ${policy_target}" >&2
                exit 1
                ;;
        esac
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
