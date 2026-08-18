#!/usr/bin/env sh
set -eu

egg_path="${1:?egg path is required}"
site_packages="${2:-/usr/lib/python2.7/site-packages}"
egg_name="$(basename "${egg_path}")"
target="${site_packages}/${egg_name}"
pth="${site_packages}/easy-install.pth"
tmp_pth="${pth}.neutron-aria.$$"

mkdir -p "${site_packages}"
if [ -f "${pth}" ]; then
    sed "\\|neutron_aria-0.1.0-py2.7.egg|d" "${pth}" >"${tmp_pth}"
else
    : >"${tmp_pth}"
fi
printf './%s\n' "${egg_name}" >>"${tmp_pth}"
mv -f "${tmp_pth}" "${pth}"

# The installer is a shell process, so no Python zipimporter can retain offsets
# into the old zipped egg while this same-name replacement is performed.
install -m 0644 "${egg_path}" "${target}"
