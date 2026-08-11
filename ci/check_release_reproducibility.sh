#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="${REPO_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
tmpdir="$(mktemp -d)"
trap 'rm -rf "${tmpdir}"' EXIT

for run in first second; do
    OUT_DIR="${tmpdir}/${run}" \
        SOURCE_TREEISH="${SOURCE_TREEISH:-HEAD}" \
        bash "${REPO_ROOT}/deploy/kolla/package/build_stage2_acl_bundle.sh" >/dev/null
done

first="${tmpdir}/first/neutron-aria-stage2-acl-kolla-bundle.tgz"
second="${tmpdir}/second/neutron-aria-stage2-acl-kolla-bundle.tgz"
cmp "${first}" "${second}"
printf 'release_bundle_reproducibility=pass sha256=%s\n' \
    "$(sha256sum "${first}" | awk '{print $1}')"
