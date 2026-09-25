#!/usr/bin/env bash
set -euo pipefail

if ip route show default | grep -q .; then
    echo "refusing diagnostic: VM has a default route" >&2
    exit 1
fi
if [[ -d /sys/module/caraxes ]]; then
    echo "refusing diagnostic: CARAXES already loaded" >&2
    exit 1
fi

audit_dir="$(mktemp -d /tmp/kicba-callflow.XXXXXX)"
cleanup() {
    sudo rmmod caraxes 2>/dev/null || true
    rm -f -- \
        "${audit_dir}/visible_before" \
        "${audit_dir}/sample_caraxes_hidden" \
        "${audit_dir}/visible_after"
    rmdir -- "${audit_dir}"
}
trap cleanup EXIT

touch \
    "${audit_dir}/visible_before" \
    "${audit_dir}/sample_caraxes_hidden" \
    "${audit_dir}/visible_after"

echo "NORMAL"
ls -a1 -- "${audit_dir}"
sudo insmod /opt/kicba/caraxes/caraxes.ko
echo "ROOTKIT"
ls -a1 -- "${audit_dir}"
sudo rmmod caraxes

if [[ -d /sys/module/caraxes ]]; then
    echo "CARAXES remained loaded" >&2
    exit 1
fi
