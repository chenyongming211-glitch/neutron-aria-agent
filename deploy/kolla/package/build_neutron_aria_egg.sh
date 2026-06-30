#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="${REPO_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)}"
PACKAGE_ROOT="${PACKAGE_ROOT:-${REPO_ROOT}/openstack/neutron_aria}"
OUT_DIR="${OUT_DIR:-${REPO_ROOT}/dist/kolla}"
EGG_NAME="${EGG_NAME:-neutron_aria-0.1.0-py2.7.egg}"
OUT_EGG="${OUT_EGG:-${OUT_DIR}/${EGG_NAME}}"

log() {
    printf '[neutron-aria-egg-build] %s\n' "$*"
}

if [ ! -d "${PACKAGE_ROOT}/neutron_aria" ]; then
    echo "Missing neutron_aria package root: ${PACKAGE_ROOT}/neutron_aria" >&2
    exit 1
fi

mkdir -p "${OUT_DIR}"

PYTHON_BIN="${PYTHON_BIN:-$(command -v python3 || command -v python || true)}"
if [ -z "${PYTHON_BIN}" ]; then
    echo "Neither python3 nor python is available for egg packaging." >&2
    exit 1
fi

log "Building ${OUT_EGG}"
"${PYTHON_BIN}" - "${PACKAGE_ROOT}" "${OUT_EGG}" <<'PY'
from __future__ import print_function

import os
import sys
import zipfile

package_root = os.path.abspath(sys.argv[1])
out_egg = os.path.abspath(sys.argv[2])
source_root = os.path.join(package_root, "neutron_aria")

metadata = {
    "EGG-INFO/PKG-INFO": (
        "Metadata-Version: 1.1\n"
        "Name: neutron-aria\n"
        "Version: 0.1.0\n"
        "Summary: OpenStack Neutron adapter for Aria datapath\n"
    ),
    "EGG-INFO/top_level.txt": "neutron_aria\n",
    "EGG-INFO/dependency_links.txt": "\n",
    "EGG-INFO/requires.txt": "\n",
    "EGG-INFO/entry_points.txt": (
        "[console_scripts]\n"
        "neutron-aria-agent = neutron_aria.agent.main:main\n"
        "\n"
        "[neutron.service_plugins]\n"
        "aria_acl = neutron_aria.services.aria_acl.plugin:AriaAclPlugin\n"
        "\n"
        "[neutron.api_extensions]\n"
        "aria_acl = neutron_aria.extensions.aria_acl:Aria_acl\n"
    ),
}

if os.path.exists(out_egg):
    os.remove(out_egg)

sources = []
with zipfile.ZipFile(out_egg, "w", zipfile.ZIP_DEFLATED) as archive:
    for current, dirs, files in os.walk(source_root):
        dirs[:] = [name for name in dirs if name != "__pycache__"]
        for name in files:
            if name.endswith((".pyc", ".pyo")):
                continue
            path = os.path.join(current, name)
            arcname = os.path.relpath(path, package_root).replace(os.sep, "/")
            archive.write(path, arcname)
            sources.append(arcname)
    metadata["EGG-INFO/SOURCES.txt"] = "\n".join(sorted(sources)) + "\n"
    for arcname, content in metadata.items():
        archive.writestr(arcname, content)

print(out_egg)
PY

log "Built ${OUT_EGG}"
