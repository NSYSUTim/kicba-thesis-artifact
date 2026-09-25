#!/usr/bin/env bash
set -euo pipefail

# Provision a disposable native Ubuntu x86-64 VM for KICBA data collection.
# This script builds CARAXES but deliberately never loads the module.

UPSTREAM_COMMIT="269d9b0bc6aafb403cba209bb47b8bdb902ba10e"
CARAXES_COMMIT="899e8be6b5f6c7236bd23b52aa65051de757e0b3"
INSTALL_ROOT="/opt/kicba"

if [[ "$(id -u)" -ne 0 ]]; then
    echo "Run as root inside the disposable Ubuntu VM." >&2
    exit 2
fi

if [[ "$(uname -m)" != "x86_64" ]]; then
    echo "This preregistered D2 phase requires x86_64." >&2
    exit 2
fi

if grep -qi microsoft /proc/sys/kernel/osrelease; then
    echo "Refusing WSL: D2 requires a native Linux VM or host." >&2
    exit 2
fi

if [[ -e "${INSTALL_ROOT}/rootkit-detection-ebpf-time-trace" || -e "${INSTALL_ROOT}/caraxes" ]]; then
    echo "${INSTALL_ROOT} already contains a study checkout; refusing to overwrite it." >&2
    exit 2
fi

apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y \
    build-essential bison flex gcc-12 git linux-headers-"$(uname -r)" \
    python3-bpfcc bpfcc-tools python3-pip stress-ng

install -d -m 0755 "${INSTALL_ROOT}"
git clone https://github.com/ait-aecid/rootkit-detection-ebpf-time-trace.git \
    "${INSTALL_ROOT}/rootkit-detection-ebpf-time-trace"
git -C "${INSTALL_ROOT}/rootkit-detection-ebpf-time-trace" checkout --detach \
    "${UPSTREAM_COMMIT}"

git clone https://github.com/ait-aecid/caraxes.git "${INSTALL_ROOT}/caraxes"
git -C "${INSTALL_ROOT}/caraxes" checkout --detach "${CARAXES_COMMIT}"

# Match the Trace of the Times experiment's filldir hook selection.
cp "${INSTALL_ROOT}/rootkit-detection-ebpf-time-trace/hooks.h" \
    "${INSTALL_ROOT}/caraxes/hooks.h"
# CARAXES' historical Makefile uses $(PWD) as Kbuild's M= path.  GNU make's
# -C flag does not rewrite an inherited PWD environment variable, so enter the
# checkout explicitly.  Use the same GCC major version as Ubuntu's HWE kernel.
(
    cd "${INSTALL_ROOT}/caraxes"
    make CC=gcc-12
)

sha256sum "${INSTALL_ROOT}/caraxes/caraxes.ko"
echo "Provisioning complete. CARAXES was built but NOT loaded."
echo "Copy this KICBA project into the VM, then run:"
echo "  sudo bash collector/diagnose_kprobes.sh"
echo "Only continue if every target function reports hits during ls."
