# KICBA Hyper-V setup

These scripts implement the Windows-host part of `docs/native_vm_runbook.md`.

1. `enable_hyperv.ps1` enables the complete Hyper-V feature without initiating
   a reboot. It must run elevated and returns exit code 3010 when a reboot is
   required.
2. `create_kicba_vm.ps1` refuses to overwrite an existing VM and creates
   `KICBA-Lab` in `D:\KICBA-Lab` with 4 vCPU, 8 GB fixed RAM, a 60 GB VHDX, Ubuntu installation
   media, secure boot for Microsoft UEFI CA, and automatic checkpoints off.

The VM initially has an internal/default network switch so Ubuntu packages can
be installed. Before CARAXES is loaded, create a clean checkpoint and disconnect
the virtual network adapter.

`build_autoinstall_iso.sh` creates a second, non-overwriting ISO containing a
NoCloud configuration. It selects Ubuntu's HWE kernel, creates only the local
`kicba` account, disables SSH password login, authorizes the dedicated key at
`D:\KICBA-Lab\ssh\kicba_ed25519`, and grants passwordless sudo for unattended
research automation. The identity password is a one-time random value whose
plaintext was discarded; access is by the dedicated key only.
