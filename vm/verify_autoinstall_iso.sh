#!/usr/bin/env bash
set -euo pipefail

ISO="/mnt/d/KICBA-Lab/iso/ubuntu-22.04.5-kicba-autoinstall-amd64.iso"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
TEMP_ROOT="$(mktemp -d)"
cleanup() {
    local resolved
    resolved="$(readlink -f -- "${TEMP_ROOT}")"
    if [[ "${resolved}" == /tmp/* ]]; then
        rm -rf -- "${resolved}"
    fi
}
trap cleanup EXIT

xorriso -osirrox on -indev "${ISO}" \
    -extract /boot/grub/grub.cfg "${TEMP_ROOT}/grub.cfg" \
    -extract /nocloud/user-data "${TEMP_ROOT}/user-data" \
    -extract /nocloud/meta-data "${TEMP_ROOT}/meta-data"

grep -q '^set default=1$' "${TEMP_ROOT}/grub.cfg"
[[ "$(grep -c 'autoinstall ds=nocloud' "${TEMP_ROOT}/grub.cfg")" -eq 2 ]]
cmp --silent "${TEMP_ROOT}/user-data" \
    "${SCRIPT_DIR}/autoinstall/user-data"
cmp --silent "${TEMP_ROOT}/meta-data" \
    "${SCRIPT_DIR}/autoinstall/meta-data"
xorriso -indev "${ISO}" -report_el_torito plain
sha256sum "${ISO}"
echo "AUTOINSTALL_ISO_VERIFIED"
