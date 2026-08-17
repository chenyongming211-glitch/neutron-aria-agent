#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="${REPO_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)}"
BASE_IMAGE="${BASE_IMAGE:-}"
IMAGE_TAG="${IMAGE_TAG:-neutron-aria-agent:stage2-acl}"
OUT_DIR="${OUT_DIR:-${REPO_ROOT}/dist/kolla}"
SAVE_IMAGE="${SAVE_IMAGE:-false}"
IMAGE_TAR="${IMAGE_TAR:-${OUT_DIR}/neutron-aria-agent-stage2-acl-image.tar}"
NETADDR_WHEEL="${REPO_ROOT}/dist/kolla/python2-wheels/netaddr-0.7.19-py2.py3-none-any.whl"
NETADDR_WHEEL_SHA256="${NETADDR_WHEEL_SHA256:-56b3558bd71f3f6999e4c52e349f38660e54a7a8a9943335f73dfc96883e08ca}"

usage() {
    cat <<EOF
Usage:
  BASE_IMAGE=<onsite-neutron-agent-image> [IMAGE_TAG=name:tag] $0

Options:
  SAVE_IMAGE=true  Also docker-save the image to ${IMAGE_TAR}.

The base image must come from the onsite Kolla/Neutron image family so it has
Python 2.7, legacy Neutron, oslo libraries, and python-neutronclient.
EOF
}

log() {
    printf '[neutron-aria-agent-image-build] %s\n' "$*"
}

if [ "${1:-}" = "-h" ] || [ "${1:-}" = "--help" ]; then
    usage
    exit 0
fi

if [ -z "${BASE_IMAGE}" ]; then
    usage >&2
    exit 1
fi

command -v docker >/dev/null 2>&1 || {
    echo "docker is required to build the neutron-aria-agent image." >&2
    exit 1
}
[ -f "${NETADDR_WHEEL}" ] || {
    echo "Missing offline Python 2 dependency: ${NETADDR_WHEEL}" >&2
    exit 1
}
[ "$(sha256sum "${NETADDR_WHEEL}" | awk '{print $1}')" = "${NETADDR_WHEEL_SHA256}" ] || {
    echo "Offline netaddr wheel SHA-256 mismatch" >&2
    exit 1
}

log "Building ${IMAGE_TAG} from BASE_IMAGE=${BASE_IMAGE}"
docker build \
    --build-arg "BASE_IMAGE=${BASE_IMAGE}" \
    -f "${REPO_ROOT}/deploy/kolla/neutron-aria-agent/Dockerfile" \
    -t "${IMAGE_TAG}" \
    "${REPO_ROOT}"

log "Validating image entrypoint import"
docker run --rm -i --entrypoint python "${IMAGE_TAG}" - <<'PY'
from __future__ import print_function

from neutron_aria.agent.neutron_client import build_aria_acl_client_from_env
from neutron_aria.agent.uds_client import LocalClient
import netaddr

assert netaddr.__version__ == "0.7.19"
print("image_imports=ok")
PY
docker run --rm --entrypoint neutron-aria-agent "${IMAGE_TAG}" --help >/dev/null
log "Validated neutron-aria-agent --help"

if [ "${SAVE_IMAGE}" = "true" ]; then
    mkdir -p "${OUT_DIR}"
    log "Saving ${IMAGE_TAG} to ${IMAGE_TAR}"
    docker save -o "${IMAGE_TAR}" "${IMAGE_TAG}"
fi

log "Image build ok: ${IMAGE_TAG}"
