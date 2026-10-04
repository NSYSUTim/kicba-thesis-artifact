# 2026-09-24 實驗工作紀錄摘錄

時間均為 Asia/Taipei。以下只摘出與環境追溯有關的命令及輸出；原始 Codex
session JSONL 仍存於執行實驗的本機，沒有整份公開。

| 原始 session 識別尾碼 | JSONL SHA-256 |
|---|---|
| `01a0d209-ab46-7a10-b92a-a8ffc24da0d6` | `e2f113449ba6c7b232b2e128f875687209bb2887783a61b3da1f3ab61877dc19` |
| `01a0d31a-c4c4-7531-97fc-a0b4126c6ad6` | `5217a55089fa1a820ca571274b1d07ff737e4c8764803359da46531b033bfadf` |

- **14:11，第一份 session 第 36／39 行：**對 `KICBA-Lab` 執行
  `Get-VM -Name 'KICBA-Lab' | Select-Object Name,State,Status,Uptime,CPUUsage,MemoryAssigned`
  及 `Get-VMNetworkAdapter`，兩者都回覆 `Access denied`。這次呼叫沒有
  留下 VM `CPUUsage`／`MemoryAssigned` 數值；原工作紀錄亦沒有宿主總負載
  或 VM configuration version 的量測值。
- **14:18–14:19，第一份 session 第 163／166 行：**在原 VM 執行
  `cd /home/kicba/kicba && gcc -O2 -Wall -Wextra -Werror -Icollector collector/d9_enum_probe.c -o /home/kicba/d9_enum_probe`，
  然後執行 BPF smoke。原 VM 該執行檔的 mtime 為 14:19:04，SHA-256
  `5b94e255341476faedf1a08b25fe16fa8955cf9c0ad53275907ba8fe9cf29dbd`，
  與[正式分析鎖](../d9_formal/analysis_lock.json)的 `runtime_source_hashes.probe`
  相同。這是正式探針的完整 GCC 指令。
- **15:16，第一份 session 第 1201／1204 行：**
  `findmnt -no SOURCE,FSTYPE /` 輸出 `/dev/sda2 ext4`。
- **19:54，第二份 session 第 252／255 行：**
  `findmnt -no SOURCE,FSTYPE,OPTIONS /` 輸出 `/dev/sda2 ext4 rw,relatime`；
  同次 `lsb_release -ds` 輸出 `Ubuntu 22.04.5 LTS`，`clang --version`
  回覆 `command not found`，`dpkg -s python3-bpfcc stress-ng` 分別顯示
  `0.18.0+ds-2`、`0.13.12-2ubuntu1`。

[九開機正式資料](../d9_formal/raw/)的 boot 01 與 boot 09 分別於
16:17 與 17:26 完成。2026-10-04 回查原 VM 的 `journalctl -k`，
可找到正式 boot 05–09 的 boot ID；這五次開機的核心日誌均記錄
`EXT4-fs (sda2)` 先以唯讀掛載、隨即重新掛為可寫。`relatime` 有當日
19:54 的 `findmnt` 輸出佐證，但正式 runner 沒有在每個 batch
同步記錄完整 mount options。

當日工作紀錄沒有宿主 CPU／記憶體負載的可用數值；建置紀錄則已保存
宿主與 VM 的硬體規格。沒有獨立記錄 VM configuration version。
