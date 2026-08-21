#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="${REPO_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
tmpdir="$(mktemp -d)"
trap 'rm -rf "${tmpdir}"' EXIT

wheel_dir="${REPO_ROOT}/dist/kolla/python2-wheels"
wheel="${wheel_dir}/netaddr-0.7.19-py2.py3-none-any.whl"
if [ ! -f "${wheel}" ]; then
    mkdir -p "${wheel_dir}"
    python3 -m pip download --disable-pip-version-check --no-deps \
        --only-binary=:all: --dest "${wheel_dir}" netaddr==0.7.19 >/dev/null
fi

# Stable synthetic immutable identities exercise the manifest contract without
# requiring Docker during this byte-for-byte reproducibility check.
agent_image_identity="neutron-aria-agent:reproducibility@sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
datapath_image_identity="aria-datapath:reproducibility@sha256:ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb"

for run in first second; do
    OUT_DIR="${tmpdir}/${run}" \
        NETADDR_WHEEL_PATH="${wheel}" \
        SOURCE_TREEISH="${SOURCE_TREEISH:-HEAD}" \
        AGENT_IMAGE_IDENTITY="${agent_image_identity}" \
        DATAPATH_IMAGE_IDENTITY="${datapath_image_identity}" \
        bash "${REPO_ROOT}/deploy/kolla/package/build_stage2_acl_bundle.sh" >/dev/null
done

first="${tmpdir}/first/neutron-aria-stage2-acl-kolla-bundle.tgz"
second="${tmpdir}/second/neutron-aria-stage2-acl-kolla-bundle.tgz"
cmp "${first}" "${second}"
printf 'release_bundle_reproducibility=pass sha256=%s\n' \
    "$(sha256sum "${first}" | awk '{print $1}')"
