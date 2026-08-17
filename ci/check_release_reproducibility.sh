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

for run in first second; do
    OUT_DIR="${tmpdir}/${run}" \
        NETADDR_WHEEL_PATH="${wheel}" \
        SOURCE_TREEISH="${SOURCE_TREEISH:-HEAD}" \
        bash "${REPO_ROOT}/deploy/kolla/package/build_stage2_acl_bundle.sh" >/dev/null
done

first="${tmpdir}/first/neutron-aria-stage2-acl-kolla-bundle.tgz"
second="${tmpdir}/second/neutron-aria-stage2-acl-kolla-bundle.tgz"
cmp "${first}" "${second}"
printf 'release_bundle_reproducibility=pass sha256=%s\n' \
    "$(sha256sum "${first}" | awk '{print $1}')"
