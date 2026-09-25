#!/usr/bin/env bash
set -euo pipefail

if ip route show default | grep -q .; then
    echo "SHAM_Q0_FAIL default_route_present" >&2
    exit 1
fi
if [[ -d /sys/module/caraxes || -d /sys/module/caraxes_sham ]]; then
    echo "SHAM_Q0_FAIL module_already_loaded" >&2
    exit 1
fi

audit_dir="$(mktemp -d /tmp/kicba-sham-q0.XXXXXX)"
cleanup() {
    sudo rmmod caraxes_sham 2>/dev/null || true
    rm -f -- \
        "${audit_dir}/visible_before" \
        "${audit_dir}/sample_caraxes_hidden" \
        "${audit_dir}/visible_after"
    rmdir -- "${audit_dir}" 2>/dev/null || true
}
trap cleanup EXIT

touch \
    "${audit_dir}/visible_before" \
    "${audit_dir}/sample_caraxes_hidden" \
    "${audit_dir}/visible_after"
normal="$(LC_ALL=C ls -a1U -- "${audit_dir}" | LC_ALL=C sort)"
sudo insmod /home/kicba/caraxes_sham/caraxes_sham.ko
sham="$(LC_ALL=C ls -a1U -- "${audit_dir}" | LC_ALL=C sort)"
sudo rmmod caraxes_sham

if [[ "${normal}" != "${sham}" ]]; then
    echo "SHAM_Q0_FAIL output_changed" >&2
    diff -u <(printf '%s\n' "${normal}") <(printf '%s\n' "${sham}") || true
    exit 1
fi
if [[ -d /sys/module/caraxes_sham ]]; then
    echo "SHAM_Q0_FAIL module_remained_loaded" >&2
    exit 1
fi

echo "SHAM_Q0_PASS"
echo "module_sha256=$(sha256sum /home/kicba/caraxes_sham/caraxes_sham.ko | awk '{print $1}')"
exit 0
