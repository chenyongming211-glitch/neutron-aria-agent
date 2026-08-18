#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ROOT="$(mktemp -d)"
FIXTURE_IMAGE="neutron-aria-upgrade-fixture:${RANDOM}-$$"
INSTALLED_IMAGE="neutron-aria-upgrade-installed:${RANDOM}-$$"
UPGRADED_IMAGE="neutron-aria-upgrade-candidate:${RANDOM}-$$"
EGG_NAME="neutron_aria-0.1.0-py2.7.egg"
WHEEL_DIR="${REPO_ROOT}/dist/kolla/python2-wheels"

cleanup() {
    docker image rm -f \
        "${UPGRADED_IMAGE}" "${INSTALLED_IMAGE}" "${FIXTURE_IMAGE}" \
        >/dev/null 2>&1 || true
    rm -rf "${ROOT}"
}
trap cleanup EXIT

command -v docker >/dev/null 2>&1 || {
    echo "docker is required for the agent image upgrade test" >&2
    exit 1
}

mkdir -p "${WHEEL_DIR}"
python3 -m pip download --disable-pip-version-check --no-deps \
    --only-binary=:all: --dest "${WHEEL_DIR}" netaddr==0.7.19 >/dev/null
bash "${REPO_ROOT}/deploy/kolla/package/build_neutron_aria_egg.sh" >/dev/null

cat >"${ROOT}/Dockerfile" <<'EOF'
FROM python:2.7.18-slim-buster
RUN ln -s /usr/local/bin/python /usr/local/bin/python3 && \
    groupadd -g 42435 neutron && \
    useradd -u 42435 -g 42435 -d /var/lib/neutron -s /bin/sh neutron && \
    printf "%s\n" \
        "import site" \
        "site.addsitedir('/usr/lib/python2.7/site-packages')" \
        > /usr/local/lib/python2.7/site-packages/sitecustomize.py
EOF
docker build -t "${FIXTURE_IMAGE}" "${ROOT}" >/dev/null

BASE_IMAGE="${FIXTURE_IMAGE}" IMAGE_TAG="${INSTALLED_IMAGE}" \
    bash "${REPO_ROOT}/deploy/kolla/package/build_neutron_aria_agent_image.sh"

# This second build reproduces the field upgrade boundary: the base image
# already exposes the same zipped egg through easy-install.pth.
BASE_IMAGE="${INSTALLED_IMAGE}" IMAGE_TAG="${UPGRADED_IMAGE}" \
    bash "${REPO_ROOT}/deploy/kolla/package/build_neutron_aria_agent_image.sh"

expected_sha="$(sha256sum "${REPO_ROOT}/dist/kolla/${EGG_NAME}" | awk '{print $1}')"
actual_sha="$(
    docker run --rm --user 0 --entrypoint sha256sum "${UPGRADED_IMAGE}" \
        "/usr/lib/python2.7/site-packages/${EGG_NAME}" | awk '{print $1}'
)"
[ "${actual_sha}" = "${expected_sha}" ] || {
    echo "upgraded image egg SHA-256 mismatch" >&2
    exit 1
}

entry_count="$(
    docker run --rm --user 0 --entrypoint sh "${UPGRADED_IMAGE}" -c \
        "grep -c '^./${EGG_NAME}$' /usr/lib/python2.7/site-packages/easy-install.pth"
)"
[ "${entry_count}" = "1" ] || {
    echo "upgraded image must contain exactly one active neutron_aria egg entry" >&2
    exit 1
}

printf 'neutron_agent_same_name_egg_upgrade=pass\n'
