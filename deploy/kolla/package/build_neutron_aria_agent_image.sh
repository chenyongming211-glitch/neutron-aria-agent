#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="${REPO_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)}"
BASE_IMAGE="${BASE_IMAGE:-}"
IMAGE_TAG="${IMAGE_TAG:-neutron-aria-agent:stage2-acl}"
OUT_DIR="${OUT_DIR:-${REPO_ROOT}/dist/kolla}"
SAVE_IMAGE="${SAVE_IMAGE:-false}"
IMAGE_TAR="${IMAGE_TAR:-${OUT_DIR}/neutron-aria-agent-stage2-acl-image.tar}"

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

print("image_imports=ok")
PY

if [ "${SAVE_IMAGE}" = "true" ]; then
    mkdir -p "${OUT_DIR}"
    log "Saving ${IMAGE_TAG} to ${IMAGE_TAR}"
    docker save -o "${IMAGE_TAR}" "${IMAGE_TAG}"
fi

log "Image build ok: ${IMAGE_TAG}"
