#!/usr/bin/env bash
set -euo pipefail

module_dir=${D7_MODULE_DIR:-/home/kicba/kicba/attack_variants/d7_controls}
fixture=${D7_SMOKE_FIXTURE:-/home/kicba/d7_smoke_fixture}
modules=(kicba_d7_pass kicba_d7_active kicba_d7_hiding)

cleanup() {
    local module
    for module in "${modules[@]}" caraxes caraxes_sham; do
        if grep -q "^${module} " /proc/modules; then
            rmmod "$module" || true
        fi
    done
}
trap cleanup EXIT

if ip route show default | grep -q .; then
    echo "FAIL: default route present" >&2
    exit 1
fi
cleanup
if [[ -e "$fixture" ]]; then
    echo "FAIL: refusing to reuse smoke fixture: $fixture" >&2
    exit 1
fi
mkdir "$fixture"
touch "$fixture/visible_entry" "$fixture/caraxes_hidden_entry"

for module in "${modules[@]}"; do
    insmod "$module_dir/$module.ko"
    mapfile -t listing < <(/bin/ls -1 "$fixture")
    echo "STATE=$module"
    printf 'LISTING=%s\n' "${listing[*]}"
    for counter in \
        fillonedir_calls filldir_calls filldir64_calls \
        compat_fillonedir_calls compat_filldir_calls \
        filter_checks filter_matches; do
        printf '%s=' "$counter"
        tr -d '\n' < "/sys/module/$module/parameters/$counter"
        printf '\n'
    done
    if [[ "$module" == kicba_d7_hiding ]]; then
        if printf '%s\n' "${listing[@]}" | grep -Fxq caraxes_hidden_entry; then
            echo "FAIL: hiding module exposed hidden entry" >&2
            exit 1
        fi
    elif ! printf '%s\n' "${listing[@]}" | grep -Fxq caraxes_hidden_entry; then
        echo "FAIL: control module hid the entry" >&2
        exit 1
    fi
    rmmod "$module"
done

echo "D7_SMOKE_PASS"
