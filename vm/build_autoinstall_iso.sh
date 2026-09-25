#!/usr/bin/env bash
set -euo pipefail

SOURCE_ISO="/mnt/d/KICBA-Lab/iso/ubuntu-22.04.5-live-server-amd64.iso"
OUTPUT_ISO="/mnt/d/KICBA-Lab/iso/ubuntu-22.04.5-kicba-autoinstall-amd64.iso"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
USER_DATA="${SCRIPT_DIR}/autoinstall/user-data"
META_DATA="${SCRIPT_DIR}/autoinstall/meta-data"

for required in "${SOURCE_ISO}" "${USER_DATA}" "${META_DATA}"; do
    if [[ ! -f "${required}" ]]; then
        echo "Required input is missing: ${required}" >&2
        exit 2
    fi
done

if [[ -e "${OUTPUT_ISO}" ]]; then
    echo "Refusing to overwrite existing output: ${OUTPUT_ISO}" >&2
    exit 2
fi

TEMP_ROOT="$(mktemp -d)"
cleanup() {
    local resolved
    resolved="$(readlink -f -- "${TEMP_ROOT}")"
    if [[ "${resolved}" == /tmp/* ]]; then
        rm -rf -- "${resolved}"
    else
        echo "Refusing to remove unexpected temporary path: ${resolved}" >&2
    fi
}
trap cleanup EXIT

GRUB_CFG="${TEMP_ROOT}/grub.cfg"
xorriso -osirrox on -indev "${SOURCE_ISO}" \
    -extract /boot/grub/grub.cfg "${GRUB_CFG}"

sed -i 's/^set timeout=.*/set timeout=1\nset default=1/' "${GRUB_CFG}"
sed -i '/^[[:space:]]*linux[[:space:]]/ s|[[:space:]]*---| autoinstall ds=nocloud\\;s=/cdrom/nocloud/ ---|' "${GRUB_CFG}"

if [[ "$(grep -c 'autoinstall ds=nocloud' "${GRUB_CFG}")" -ne 2 ]]; then
    echo "Expected to modify exactly two GRUB Linux entries." >&2
    exit 2
fi

xorriso -indev "${SOURCE_ISO}" -outdev "${OUTPUT_ISO}" \
    -map "${GRUB_CFG}" /boot/grub/grub.cfg \
    -map "${USER_DATA}" /nocloud/user-data \
    -map "${META_DATA}" /nocloud/meta-data \
    -boot_image any replay

xorriso -indev "${OUTPUT_ISO}" -find /nocloud -type f -exec lsdl
xorriso -osirrox on -indev "${OUTPUT_ISO}" \
    -extract /boot/grub/grub.cfg "${TEMP_ROOT}/verify-grub.cfg"
sed -n '1,160p' "${TEMP_ROOT}/verify-grub.cfg"
sha256sum "${OUTPUT_ISO}"
