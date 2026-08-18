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

# Compile the complete target package with the target Python runtime before
# testing selected imports. This catches Python 2 syntax and source-encoding
# failures that Python 3 packaging alone cannot detect.
docker cp \
    "${REPO_ROOT}/openstack/neutron_aria/neutron_aria" \
    "${SERVICE_NAME}:/tmp/neutron_aria-source"
docker exec "${SERVICE_NAME}" python -m compileall -q \
    /tmp/neutron_aria-source

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

docker exec "${SERVICE_NAME}" sh -c '
    printf "%s\n" "[agent" "host = broken" > /tmp/neutron-aria-malformed.ini
    printf "%s\n" "[agent]" "host = unreadable" > /tmp/neutron-aria-unreadable.ini
    chmod 000 /tmp/neutron-aria-unreadable.ini
    : > /tmp/neutron-aria-empty.ini
'

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

import json

from neutron_aria.agent.acl_source import NeutronAclSource
from neutron_aria.agent.config import ConfigError
from neutron_aria.agent.config import load_config
from neutron_aria.agent.neutron_client import build_aria_acl_client_from_env
from neutron_aria.agent.status import AgentRuntimeStatus
from neutron_aria.agent.uds_client import LocalClient
from neutron_aria.services.aria_acl.port_projection import install_legacy_port_projection


def assert_config_rejected(path, reason):
    try:
        load_config(path)
    except ConfigError:
        return
    raise AssertionError("%s config was accepted: %s" % (reason, path))


class FakeCorePlugin(object):
    def get_port(self, context, port_id, fields=None):
        return {"id": port_id}

    def get_ports(
        self, context, filters=None, fields=None, sorts=None, limit=None,
        marker=None, page_reverse=False,
    ):
        return [{"id": "port-1"}]


class FakeProjectionPlugin(object):
    def extend_aria_acl_port_dicts(self, context, ports):
        for port in ports:
            port["aria_acl_runtime_status"] = "not_requested"
        return ports


core = FakeCorePlugin()
assert install_legacy_port_projection(
    FakeProjectionPlugin(),
    core_plugin=core,
)
assert core.get_port(None, "port-1")["aria_acl_runtime_status"] == "not_requested"
assert core.get_ports(None)[0]["aria_acl_runtime_status"] == "not_requested"

history = json.loads(
    '{"last_feature_ready_generation_by_domain":{"acl":"42"}}'
)
domain_generations = history["last_feature_ready_generation_by_domain"]
domain_key = next(iter(domain_generations))
assert isinstance(domain_key, unicode)

runtime_status = AgentRuntimeStatus("clean-python27")
runtime_status.hydrate_durable_history(history)
assert runtime_status.last_feature_ready_generation_by_domain == {"acl": 42}

assert_config_rejected("/tmp/neutron-aria-missing.ini", "missing")
assert_config_rejected("/tmp/neutron-aria-unreadable.ini", "unreadable")
assert_config_rejected("/tmp/neutron-aria-malformed.ini", "malformed")
assert load_config("/tmp/neutron-aria-empty.ini").full_resync_enabled is False

print("clean_agent_imports=ok")
print("clean_python27_port_projection=ok")
print("clean_python27_unicode_domain_history=ok")
print("clean_python27_explicit_config_fail_closed=ok")
PY
docker exec -u neutron "${SERVICE_NAME}" neutron-aria-agent --help >/dev/null
if docker exec -u neutron "${SERVICE_NAME}" neutron-aria-agent \
    -c /tmp/neutron-aria-missing.ini --report-once >/dev/null 2>&1; then
    echo "daemon accepted a missing explicit config" >&2
    exit 1
fi
if docker exec -u neutron "${SERVICE_NAME}" neutron-aria-agent \
    -c /tmp/neutron-aria-missing.ini --once >/dev/null 2>&1; then
    echo "--once accepted a missing explicit config" >&2
    exit 1
fi

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
