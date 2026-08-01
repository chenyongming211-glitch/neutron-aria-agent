#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
INSTALLER="${REPO_ROOT}/deploy/kolla/package/install_neutron_aria_agent_egg.sh"
BUILDER="${REPO_ROOT}/deploy/kolla/package/build_neutron_aria_egg.sh"
PYTHON_IMAGE="${PYTHON_IMAGE:-python:2.7.18-slim-buster}"
ROOT="$(mktemp -d)"
SERVICE_NAME="neutron-aria-clean-install-${RANDOM}-$$"
SITE_PACKAGES=""
EGG_NAME="neutron_aria-0.1.0-py2.7.egg"
EGG_PATH="${ROOT}/${EGG_NAME}"
STATE_DIR="${ROOT}/state"

cleanup() {
    docker rm -f "${SERVICE_NAME}" >/dev/null 2>&1 || true
    rm -rf "${ROOT}"
}
trap cleanup EXIT

if [ "$(id -u)" != "0" ]; then
    echo "clean-container package test must run as root" >&2
    exit 1
fi
command -v docker >/dev/null 2>&1 || {
    echo "docker is required for the clean-container package test" >&2
    exit 1
}

OUT_EGG="${EGG_PATH}" bash "${BUILDER}" >/dev/null

docker pull "${PYTHON_IMAGE}" >/dev/null
docker run --detach --name "${SERVICE_NAME}" --entrypoint sh \
    "${PYTHON_IMAGE}" -c '
        set -eu
        printf "%s\n" "neutron:x:42435:" >> /etc/group
        printf "%s\n" "neutron:x:42435:42435:Neutron:/tmp:/bin/sh" >> /etc/passwd
        exec sleep 600
    ' >/dev/null

SITE_PACKAGES="$(
    docker exec "${SERVICE_NAME}" python -c \
        'from distutils.sysconfig import get_python_lib; print(get_python_lib())'
)"

docker exec "${SERVICE_NAME}" test ! -e "${SITE_PACKAGES}/${EGG_NAME}"
docker exec "${SERVICE_NAME}" test ! -e "${SITE_PACKAGES}/easy-install.pth"
if docker exec "${SERVICE_NAME}" sh -c \
    'command -v neutron-aria-agent >/dev/null 2>&1'; then
    echo "clean fixture unexpectedly contains neutron-aria-agent" >&2
    exit 1
fi

SERVICE_NAME="${SERVICE_NAME}" \
EGG_PATH="${EGG_PATH}" \
EGG_NAME="${EGG_NAME}" \
SITE_PACKAGES="${SITE_PACKAGES}" \
STATE_DIR="${STATE_DIR}" \
RESTART_AGENT_AFTER_INSTALL=false \
RESTART_AGENT_AFTER_ROLLBACK=false \
    bash "${INSTALLER}" install

docker exec -i -u neutron "${SERVICE_NAME}" python - <<'PY'
from __future__ import print_function

from neutron_aria.agent.acl_source import NeutronAclSource
from neutron_aria.agent.neutron_client import build_aria_acl_client_from_env
from neutron_aria.agent.uds_client import LocalClient

print("clean_agent_imports=ok")
PY
docker exec -u neutron "${SERVICE_NAME}" neutron-aria-agent --help >/dev/null

SERVICE_NAME="${SERVICE_NAME}" \
EGG_NAME="${EGG_NAME}" \
SITE_PACKAGES="${SITE_PACKAGES}" \
STATE_DIR="${STATE_DIR}" \
RESTART_AGENT_AFTER_ROLLBACK=false \
    bash "${INSTALLER}" rollback

docker exec "${SERVICE_NAME}" test ! -e "${SITE_PACKAGES}/${EGG_NAME}"
if docker exec "${SERVICE_NAME}" grep -Fq "${EGG_NAME}" \
    "${SITE_PACKAGES}/easy-install.pth"; then
    echo "clean rollback left an easy-install.pth entry" >&2
    exit 1
fi
if docker exec "${SERVICE_NAME}" sh -c \
    'command -v neutron-aria-agent >/dev/null 2>&1'; then
    echo "clean rollback left the neutron-aria-agent entrypoint" >&2
    exit 1
fi

printf 'agent_clean_container_install=pass\n'
