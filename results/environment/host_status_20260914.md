# KICBA-Lab host status

Updated: 2026-09-14

- Windows edition: Professional, build 26200 (25H2).
- Host memory: approximately 32 GB.
- Storage decision: use `D:\KICBA-Lab` (approximately 252.7 GB free when audited),
  not C: (approximately 36.6 GB free).
- `Microsoft-Hyper-V-All`: Enabled.
- `Microsoft-Hyper-V-Management-PowerShell`: Enabled.
- After reboot, VMMS, the Hyper-V PowerShell module and VMConnect are available.
- Pending reboot indicators cleared.
- Ubuntu ISO: `D:\KICBA-Lab\iso\ubuntu-22.04.5-live-server-amd64.iso`.
- ISO size: 2,136,926,208 bytes.
- ISO SHA-256: `9BC6028870AEF3F74F4E16B900008179E78B130E6B0B9A140635434A46AA98B0`.
- Official checksum match: yes.
- VM: `KICBA-Lab`, Generation 2, 4 vCPU, 8 GiB fixed RAM, 60 GiB dynamic VHDX.
- Guest: Ubuntu 22.04.5 LTS, kernel `6.8.0-138-generic`, x86-64.
- Guest disk: `D:\KICBA-Lab\vm\KICBA-Lab.vhdx`.
- Autoinstall completed successfully; Hyper-V KVP did not report an IPv4, but
  the guest was discovered at `172.17.86.134` and verified by SSH host key.
- D2 exact-collector smoke gate: passed for all four target functions, zero
  perf-buffer losses.
- Host-only switch: `KICBA-Isolated`; guest address `192.168.77.2`; no guest
  default route.
- Repaired clean checkpoint: `Clean-Repaired-Isolated-20260914-212429`.
- Current CARAXES SHA-256:
  `a4edd4a2bd79d01677af8e95cf7da5511539e87a90fb89143bf49215a868f390`.
- D2-r1 pilot: 16/16 100-iteration batches valid, zero perf losses and zero
  target entry/return mismatches.

Current action: the guest `kicba-multiboot.service` is collecting the five
formal boot campaigns. No host launcher or maintenance network is required.
