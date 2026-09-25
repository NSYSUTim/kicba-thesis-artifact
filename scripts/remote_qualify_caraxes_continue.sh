#!/usr/bin/env bash
set -euo pipefail

module_path="/home/kicba/caraxes_continue/caraxes.ko"

if ip route show default | grep -q .; then
    echo "Q0_FAIL default_route_present" >&2
    exit 1
fi
if [[ -d /sys/module/caraxes ]]; then
    echo "Q0_FAIL caraxes_already_loaded" >&2
    exit 1
fi
if [[ ! -f "${module_path}" ]]; then
    echo "Q0_FAIL missing_module" >&2
    exit 1
fi

audit_dir="$(mktemp -d /tmp/kicba-q0.XXXXXX)"
cleanup() {
    sudo rmmod caraxes 2>/dev/null || true
    rm -f -- \
        "${audit_dir}/00_visible_before" \
        "${audit_dir}/10_sample_caraxes_hidden" \
        "${audit_dir}/20_visible_after" \
        "${audit_dir}/30_visible_tail"
    rmdir -- "${audit_dir}" 2>/dev/null || true
}
trap cleanup EXIT

touch \
    "${audit_dir}/00_visible_before" \
    "${audit_dir}/10_sample_caraxes_hidden" \
    "${audit_dir}/20_visible_after" \
    "${audit_dir}/30_visible_tail"

normal="$(LC_ALL=C ls -a1 -- "${audit_dir}" | LC_ALL=C sort)"
expected_normal="$(printf '%s\n' . .. 00_visible_before 10_sample_caraxes_hidden 20_visible_after 30_visible_tail | LC_ALL=C sort)"
if [[ "${normal}" != "${expected_normal}" ]]; then
    echo "Q0_FAIL normal_output_mismatch" >&2
    diff -u <(printf '%s\n' "${expected_normal}") <(printf '%s\n' "${normal}") || true
    exit 1
fi

sudo insmod "${module_path}"
attack="$(LC_ALL=C ls -a1 -- "${audit_dir}" | LC_ALL=C sort)"
expected_attack="$(printf '%s\n' . .. 00_visible_before 20_visible_after 30_visible_tail | LC_ALL=C sort)"
sudo rmmod caraxes

if [[ "${attack}" != "${expected_attack}" ]]; then
    echo "Q0_FAIL attack_output_mismatch" >&2
    diff -u <(printf '%s\n' "${expected_attack}") <(printf '%s\n' "${attack}") || true
    exit 1
fi
if [[ -d /sys/module/caraxes ]]; then
    echo "Q0_FAIL module_remained_loaded" >&2
    exit 1
fi

echo "Q0_PASS"
echo "module_sha256=$(sha256sum "${module_path}" | awk '{print $1}')"
echo "normal_entries=$(printf '%s\n' "${normal}" | wc -l)"
echo "attack_entries=$(printf '%s\n' "${attack}" | wc -l)"
exit 0
