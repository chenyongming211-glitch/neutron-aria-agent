#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="${REPO_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)}"
BASE_IMAGE="${BASE_IMAGE:-}"
BASE_CONTAINER="${BASE_CONTAINER:-neutron_openvswitch_agent}"
IMAGE_TAG="${IMAGE_TAG:-aria-datapath:stage2-acl}"
OUT_DIR="${OUT_DIR:-${REPO_ROOT}/dist/kolla}"
SAVE_IMAGE="${SAVE_IMAGE:-false}"
IMAGE_TAR="${IMAGE_TAR:-${OUT_DIR}/aria-datapath-stage2-acl-image.tar}"
ARTIFACT_DIR="${ARTIFACT_DIR:-${REPO_ROOT}/release}"
ARIA_AGENT_BINARY="${ARIA_AGENT_BINARY:-${ARTIFACT_DIR}/aria-agent}"
EBPF_SO="${EBPF_SO:-${ARTIFACT_DIR}/libebpf_firewall.so}"
EBPF_PERF_SO="${EBPF_PERF_SO:-${ARTIFACT_DIR}/libebpf_firewall_perf.so}"

usage() {
    cat <<EOF
Usage:
  BASE_IMAGE=<onsite-kolla-base-image> [IMAGE_TAG=name:tag] $0

Options:
  BASE_CONTAINER=<container>  Infer BASE_IMAGE from an onsite container when BASE_IMAGE is empty.
  ARTIFACT_DIR=<dir>          Directory containing aria-agent and eBPF release artifacts.
  SAVE_IMAGE=true             Also docker-save the image to ${IMAGE_TAR}.

Required artifacts:
  \${ARTIFACT_DIR}/aria-agent
  \${ARTIFACT_DIR}/libebpf_firewall.so
  \${ARTIFACT_DIR}/libebpf_firewall_perf.so

This builder is for the privileged aria-datapath image. It layers the compiled
Rust aria-agent binary and eBPF artifacts into the onsite Kolla image family and
keeps neutron-aria-agent separate/non-privileged.
EOF
}

log() {
    printf '[aria-datapath-image-build] %s\n' "$*"
}

require_file() {
    if [ ! -f "$1" ]; then
        echo "Missing required file: $1" >&2
        exit 1
    fi
}

if [ "${1:-}" = "-h" ] || [ "${1:-}" = "--help" ]; then
    usage
    exit 0
fi

command -v docker >/dev/null 2>&1 || {
    echo "docker is required to build the aria-datapath image." >&2
    exit 1
}

if [ -z "${BASE_IMAGE}" ]; then
    if docker ps --format '{{.Names}}' | grep -qx "${BASE_CONTAINER}"; then
        BASE_IMAGE="$(docker inspect "${BASE_CONTAINER}" --format '{{.Config.Image}}')"
    fi
fi

if [ -z "${BASE_IMAGE}" ]; then
    usage >&2
    exit 1
fi

require_file "${ARIA_AGENT_BINARY}"
require_file "${EBPF_SO}"
if [ ! -f "${EBPF_PERF_SO}" ]; then
    log "Missing ${EBPF_PERF_SO}; reusing ${EBPF_SO} for perf path"
    EBPF_PERF_SO="${EBPF_SO}"
fi

tmpdir="$(mktemp -d)"
trap 'rm -rf "${tmpdir:-}"' EXIT

cp "${ARIA_AGENT_BINARY}" "${tmpdir}/aria-agent"
cp "${EBPF_SO}" "${tmpdir}/libebpf_firewall.so"
cp "${EBPF_PERF_SO}" "${tmpdir}/libebpf_firewall_perf.so"
cp "${REPO_ROOT}/deploy/kolla/aria-datapath/start-aria-datapath.sh" \
    "${tmpdir}/start-aria-datapath"
cp "${REPO_ROOT}/deploy/kolla/aria-datapath/healthcheck-aria-datapath.sh" \
    "${tmpdir}/healthcheck-aria-datapath"

cat > "${tmpdir}/Dockerfile" <<'EOF'
ARG BASE_IMAGE
FROM ${BASE_IMAGE}

USER root

COPY aria-agent /usr/local/bin/aria-agent
COPY libebpf_firewall.so /usr/local/lib/libebpf_firewall.so
COPY libebpf_firewall_perf.so /usr/local/lib/libebpf_firewall_perf.so
COPY start-aria-datapath /usr/local/bin/start-aria-datapath
COPY healthcheck-aria-datapath /usr/local/bin/healthcheck-aria-datapath

RUN chmod 0755 /usr/local/bin/aria-agent /usr/local/bin/start-aria-datapath \
        /usr/local/bin/healthcheck-aria-datapath && \
    chmod 0644 /usr/local/lib/libebpf_firewall.so /usr/local/lib/libebpf_firewall_perf.so

HEALTHCHECK --interval=30s --timeout=5s --start-period=60s --retries=3 \
    CMD ["/usr/local/bin/healthcheck-aria-datapath"]

USER root
EOF

log "Building ${IMAGE_TAG} from BASE_IMAGE=${BASE_IMAGE}"
docker build --build-arg "BASE_IMAGE=${BASE_IMAGE}" -t "${IMAGE_TAG}" "${tmpdir}"

log "Validating image contains datapath artifacts"
docker run --rm --entrypoint sh "${IMAGE_TAG}" -c '
    test -x /usr/local/bin/aria-agent &&
    test -x /usr/local/bin/start-aria-datapath &&
    test -x /usr/local/bin/healthcheck-aria-datapath &&
    test -f /usr/local/lib/libebpf_firewall.so &&
    test -f /usr/local/lib/libebpf_firewall_perf.so &&
    /usr/local/bin/aria-agent --help >/dev/null
'

if [ "${SAVE_IMAGE}" = "true" ]; then
    mkdir -p "${OUT_DIR}"
    log "Saving ${IMAGE_TAG} to ${IMAGE_TAR}"
    docker save -o "${IMAGE_TAR}" "${IMAGE_TAG}"
fi

log "Image build ok: ${IMAGE_TAG}"
