# D9 實驗環境追溯紀錄

正式實驗日期為 2026-09-24 至 09-25。本紀錄於 2026-10-04 從原實驗 VM
`KICBA-Lab` 唯讀取得；當前 boot ID 為
`6048e21a-6cd7-492e-8ca4-4b6888574b24`，不是正式實驗的 boot ID。
歷史建置檔、正式分析鎖與 apt/dpkg 紀錄用於判斷哪些事後讀數可回溯到實驗前。

## VM、宿主與儲存

| 項目 | 查得內容 | 證據與時間界線 |
|---|---|---|
| 虛擬化平台 | Microsoft Hyper-V，Generation 2 VM | 2026-09-14 的 [VM 建置紀錄](../results/environment/vm_created_20260914.json)；當前客體 `lscpu` 的 hypervisor vendor 亦為 Microsoft。 |
| 平台版本 | 宿主建置紀錄為 Windows Professional 25H2、build 26200；2026-10-04 讀得 `vmms.exe` file version `10.0.26100.8115`，該檔最後修改於 2026-09-09 | 前者來自[2026-09-14 宿主狀態紀錄](../results/environment/host_status_20260914.md)；後者是 Hyper-V 管理服務**檔案版本**，不是另行查得的 VM configuration version。當前帳號查 `Get-VM` 遭系統拒絕，故無法讀取 VM configuration version。 |
| 宿主 CPU／記憶體 | 13th Gen Intel Core i7-1355U；約 32 GB RAM | CPU 型號於 2026-10-04 由宿主處理器登錄資訊及客體 `lscpu` 一致核對；記憶體為[2026-09-14 宿主狀態紀錄](../results/environment/host_status_20260914.md)的近似值。沒有實驗當日的宿主負載快照。 |
| VM CPU／記憶體 | 4 vCPU；固定 8 GiB，未啟用動態記憶體 | 建置檔與建立腳本一致；當前客體 `lscpu` 顯示 4 CPU，`free -b` 顯示可用於 Linux 的總記憶體 8,326,762,496 bytes。 |
| 虛擬磁碟 | 60 GiB 動態 VHDX | [2026-09-14 建置後宿主狀態紀錄](../results/environment/host_status_20260914.md)；路徑為 `D:\KICBA-Lab\vm\KICBA-Lab.vhdx`。當前帳號的 `Get-VHD` 查詢遭系統拒絕，型態依建置紀錄。 |
| 測試目錄掛載 | 正式 runner 以 `/home/kicba/d9_campaign_*` 建立 fixture。2026-10-04 對 `/home/kicba` 執行 `findmnt -T`，得 `/dev/sda2`、ext4、`rw,relatime` | `collector/run_d9_campaign.py` 指定 `dir="/home/kicba"`；Decloaker 紀錄亦記有 ext4／`/dev/sda2`。`rw,relatime` 是**事後讀數**，D9 正式批次沒有保存當時的 mount options。 |

## 客體作業系統與工具鏈

2026-10-04 先以 `uname -r` 確認客體仍為 `6.8.0-138-generic`。
[原樣保存的 `/etc/os-release`](../results/environment/os-release_20261004.txt)
顯示 `PRETTY_NAME="Ubuntu 22.04.5 LTS"` 與 `VERSION_ID="22.04"`。
該檔在客體的建立／狀態變更時間是 2026-09-14 19:51（Asia/Taipei）；
建置紀錄也指定 Ubuntu 22.04.5 ISO。這使 22.04.5 作為實驗客體版本有
可追溯的支持，但正式九開機資料本身沒有逐 boot 保存 `os-release`。

| 項目 | 版本與驗證 | 安裝時間／來源 |
|---|---|---|
| BCC | `bpfcc-tools`、`python3-bpfcc`、`libbpfcc` 均為 `0.18.0+ds-2` | 客體 `dpkg-query -W`；apt history 顯示 2026-09-14 20:14 安裝。 |
| eBPF 編譯函式庫 | `libclang-cpp11`、`libllvm11` 均為 `1:11.1.0-6`；`ldd libbcc.so.0` 連到 `libclang-cpp.so.11` 與 `libLLVM-11.so.1` | 同次 apt 安裝。客體沒有獨立的 `clang` 或 `llvm-config` 命令，故不把「clang 命令版本」寫成已量得的值。 |
| C／模組編譯器 | `/home/kicba/d9_enum_probe` 的 ELF `.comment` 為 GCC `11.4.0`；正式 D7、D8、D9 `.ko` 的 `.comment` 為 GCC `12.3.0` | 探針與八個正式 `.ko` 的 SHA-256 均與 `results/d9_formal/analysis_lock.json` 的 `runtime_source_hashes` 一致；`gcc-11` 與 `gcc-12` 已於 2026-09-14 安裝。原始 CARAXES 建置腳本明確使用 `make CC=gcc-12`。 |
| Python | `python3 --version` 為 `3.10.12`；套件 `python3.10` 為 `3.10.12-1~22.04.18` | apt history 顯示 2026-09-14 12:04 升級。 |
| stress-ng | `stress-ng --version` 為 `0.13.12`；套件 `0.13.12-2ubuntu1` | apt history 顯示 2026-09-14 20:14 安裝。 |

已將相關安裝／升級條目整理為
[apt 套件事件摘要](../results/environment/apt_package_events_20261004.json)。
原 VM 的 `/var/log/apt/history.log.1.gz` 的 SHA-256 為
`82b3ee03c7f1ca3b2f0e1aa82a46a38e0f0c2835ace44297e9558c0c9977bc82`；
最後一筆 `Start-Date` 是 2026-09-14 21:22（Asia/Taipei）。
當前 `/var/log/apt/history.log` 和 `/var/log/dpkg.log` 都是 0 bytes，
保留的 `dpkg.log.1` 最後修改於 2026-09-14 21:22。**現存** apt/dpkg
紀錄沒有 09-24／09-25 或其後的套件安裝與升級；因此上表套件版本
有實驗前安裝紀錄及事後相同版本的交叉佐證，而非僅靠現在環境猜測。
此結論不涵蓋未經 apt/dpkg 管理的手動替換。

## 編譯設定與第三方來源

- 三組正式模組的 `Makefile` 都設定 `KBUILD_CFLAGS += -DDEBUG=1`，並以
  `/lib/modules/$(uname -r)/build` 執行 Kbuild。保存的
  [D9 substitution `.o.cmd` 編譯命令](../results/environment/d9_substitute_kbuild_command_20260924.txt)
  於 2026-09-24 產生，顯示 `gcc-12 -std=gnu11 -O2 -DDEBUG=1`；
  其餘核心旗標由該核心的 Kbuild 加入。
- 正式 runner 以 BCC `BPF(src_file=..., cflags=["-I<collector 路徑>"])`
  編譯 eBPF 原始碼。`d9_enum_probe` 的原始 GCC 命令列旗標未保存於
  倉庫或 ELF；只能由匹配鎖定雜湊的二進位確認 GCC 11.4.0。
- `pyproject.toml` 指定 Python `>=3.10`、建置需求 `setuptools>=68`，
  `dependencies = []`。這不是完整套件鎖；BCC 與 stress-ng 依上述
  Ubuntu 套件及實驗鎖定資料追溯。
- 原始 CARAXES 的 VM checkout 與 2026-09-14 provision 腳本均固定在
  `899e8be6b5f6c7236bd23b52aa65051de757e0b3`。該 checkout 的
  `hooks.h` 依當時 Trace 實驗設定替換；D9 正式矩陣則使用本研究在
  `attack_variants/` 的自製精簡控制模組，不能把 CARAXES upstream commit
  說成八個正式模組的逐位元原始碼版本。
- 本機保存的 Decloaker 官方 checkout 中，`v0.0.9` tag 解析為 commit
  `5a2ca88e3f715a221720a0330ae65ca845a3032d`；正式鎖另記錄
  release archive SHA-256 `417f15eeb6e374c43ea12c7037e72711dbb06bd2c4e7d42d2f67ed859add162b`。

## 使用這些數值的界線

九開機正式成效可依當時保存的 boot ID、核心、原始資料及來源／二進位雜湊稽核。
本次補查提高了硬體與工具鏈的可追溯性；宿主 CPU 型號、Hyper-V 服務版本
及 mount options 仍主要是事後讀數，沒有每次量測當日的完整主機快照。
耗時數字應限定於上述單一 VM／宿主配置，不能當作跨硬體的效能估計。
