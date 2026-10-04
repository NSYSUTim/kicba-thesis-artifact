# D9 目錄項 reconciliation：開發期結果

狀態：**開發證據，不可當成正式確認實驗**  
日期：2026-09-24

## 已實作的方法

同一次完整列舉中，eBPF 在外層 `filldir64` 返回時只納入 callback 已接受的
項目；使用者 probe 解析所有 `getdents64` 回傳頁。兩側用相同 seed、名稱
bytes、inode 與 d_type 建立 multiset fingerprint 與 IBLT。Fingerprint 先
判斷是否不同；IBLT 再嘗試還原 upstream-only / downstream-only token。

這項 callback-return 規則很重要：分頁時 `filldir64` 會因 buffer-full 對
部分項目返回 false。D9 pagination smoke 中共觀察 599 個外層 callback，
其中 514 個 accepted、85 個 rejected；使用者也收到 514 項。若像舊 D8
直接把所有 callback 都算入，正常分頁本身就會製造假差異。

## 開發歷程（失敗亦保留）

1. `mechanism_pilot_r1`：24 格中 3 格 oracle 錯誤。原因是先載入
   `filldir_hiding` 後才用同一個受影響的目錄列舉建立 oracle，使 oracle
   自己看不到隱藏檔。這不是方法失敗，也不能刪除；r2 改為載入任何模組前
   凍結 oracle。
2. `mechanism_pilot_r2`：8 狀態 × 3 次，共 24/24 格符合預期。
3. `mechanism_pilot_r3`：加入等量替換，共 9 狀態 × 3 次，27/27 格符合
   預期。替換格的上下游筆數相同，D8 count 不警報，D9 還原一進一出。
4. `boundary_quick_r1`：71 格中 2 格被原驗證器判錯。原因是測試
   `getdents64` 過濾器可能把整頁清空並回傳 0，使用者把它當 EOF；後面的
   檔案根本未走過本研究邊界。舊 oracle 卻要求還原磁碟上所有目標檔。
5. `boundary_quick_r2`：以模組獨立 audit counter 驗證實際移除／改寫數，
   並要求回復 token 屬於事先凍結的目標集合。71/71 格符合規約。
6. `boundary_full_r1`：依規約執行完整 219 格單開機開發 suite。

## 219 格 boundary suite

資料：`results/d9_development/boundary_full_r1/boundary_suite.json`

| 指標 | 開發觀察 |
|---|---:|
| 總格數／量測有效 | 219 / 219 |
| 有實際邊界差異 | 128 |
| fingerprint 正確觸發 | 128 / 128 |
| 無差異控制 | 91 |
| 無差異控制警報 | 0 / 91 |
| IBLT decode success | 210 / 219 |
| decode success 且 oracle 驗證正確 | 210 / 210 |
| decode success 但答案錯 | 0 |
| 刻意低容量造成 decode failure | 9 |
| D8 count 對等量替換漏報 | 39 / 39 |

9 個 decode failure 全部位於 `capacity_boundary`：

- 純移除：difference 16/64/256、cells 與 difference 相同時失敗。
- 等量替換：symmetric difference 是移除數的兩倍；cells = 1× 或 2×
  移除數的六格失敗。
- 所有失敗仍由 fingerprint 正確報 mismatch，且沒有輸出錯誤名單。
- 8× symmetric-difference 的獨立模擬涵蓋差異 1–512，每格 128 次；
  2,560/2,560 次正確解碼。整個 1×/2×/4×/8×、10,240 次掃描沒有
  fingerprint 假相等或錯誤成功解碼。這支持候選容量，不構成數學保證。

## 覆蓋面

- 9 個狀態：unloaded、兩個 ftrace controls、兩個 active-logic controls、
  `filldir64` suppression、`getdents64` suppression、等量替換、授權政策
  過濾。
- buffer：128、256、4,096、65,536 bytes。
- 負載：baseline、CPU、memory、mixed；core factorial 各 36 格，全部有效。
- 目錄規模：0、1、16、512、8,192、65,536 個一般項目（fixture 另含
  anchor 與各目標 prefix）。65,536 規模的觀察 scan time 約 143–168 ms。
- 實際移除／改寫量：1、4、16、64、256、512。
- 名稱與型態：UTF-8、255-byte 名稱、一般檔、目錄、symbolic link、hard
  link。
- 檔案系統：ext4、tmpfs。

## 必須如實解讀的結果

1. `getdents64` 過濾器若把一頁全部清空，可能回傳 0 造成提早 EOF。D9 能
   找出該次 syscall 已經過 `filldir64`、之後被移除的項目，但不能列出 EOF
   後從未經過 callback 的磁碟項目。這是研究邊界，不是漏寫在限制裡的小事。
2. 授權政策過濾也會警報。這正好證明 D9 判斷的是結構性不一致，不能單獨
   推論惡意。
3. 目前 token 是機率式 64-bit 摘要；random seed 降低偶然／預先構造碰撞，
   但不能防止能讀取核心狀態的適應性攻擊者。
4. 219 格來自同一次開機。仍須跨開機確認，且尚未完成 overlayfs 與所有外部
   方法的同資料比較。

## Robustness pilot

資料：`results/d9_development/robustness_r1/robustness_pilot.json`

- 正常 churn：5 狀態 × 2 buffer，共 10/10 格通過；每次列舉期間實際完成
  465–825 組 create/rename/delete 操作。unloaded 仍無差異；四個 suppression /
  substitution / policy 狀態維持正確偵測與還原。
- 多 PID：4 狀態 × 2/4/8/16 個同時列舉程序，共 16/16 格通過；每個 PID
  量測有效，合計還原數與模組 audit counter 相同。
- fail-closed：4/4 通過。錯誤 cell count 與 controller/kernel seed mismatch
  均標為 `measurement_valid=false`；未註冊 PID 與被 SIGKILL 中斷的列舉均
  被 collector 拒絕，沒有被算成陰性。

## 成本結果

資料：

- `results/d9_development/overhead_full_r2_branch8/overhead.json`
- `results/d9_development/exact_trace_full_r1/exact_trace_baseline.json`

Paired overhead 以相同目錄與負載、隨機模式順序比較 raw count、只做使用者端
sketch，以及完整 D9。以下為每次列舉的三次重複平均：

| 項目數 | 負載 | Raw count | Userspace sketch | Full D9 |
|---:|---|---:|---:|---:|
| 512 | baseline | 2.25 ms | 2.98 ms | 12.91 ms |
| 8,192 | baseline | 8.05 ms | 8.91 ms | 29.93 ms |
| 65,536 | baseline | 38.16 ms | 45.59 ms | 181.51 ms |
| 65,536 | mixed | 47.25 ms | 58.08 ms | 220.27 ms |

在這 12 個項目數與負載組合中，full D9 約為 raw count 的 3.72–7.94 倍；
65,536 項 baseline 為 4.76 倍。這仍是明顯成本，不能只報「固定大小」而省略時間。D9 probe 的
稀疏 IBLT JSON 約 15 KiB，未隨目錄大小線性增加。

另實作 accepted-entry exact map trace 作資源基線。它保存每個名稱，並由
Python 逐項讀回；不是 Synacktiv 工具的逐行復現，也不是完整分類器，因此只
能比較時間與資料尺度：

| 項目數 | 負載 | Full D9 | Exact per-entry trace | D9 logical payload | Exact logical payload |
|---:|---|---:|---:|---:|---:|
| 512 | baseline | 12.83 ms | 19.57 ms | 12.02 KiB | 140.55 KiB |
| 8,192 | baseline | 40.72 ms | 243.07 ms | 12.02 KiB | 2,240.55 KiB |
| 65,536 | baseline | 221.62 ms | 2,480.72 ms | 12.02 KiB | 17,920.55 KiB |
| 65,536 | mixed | 234.35 ms | 2,522.88 ms | 12.02 KiB | 17,920.55 KiB |

此結果支持 D9 相對完整逐項保存的縮減效果，但 exact baseline 的功能更完整、
且 Python map iteration 是其成本之一；不可宣稱所有 exact tracing 工具必然慢
相同比例。

## 外部工具復現可行性

- Trace of the Times：官方程式 snapshot 與 1,250 批公開資料已在專案中；
  seed-42 結果復現 499 TP、9 FP、491 TN、1 FN。跨情境結果另外顯示明顯
  normal FPR，兩者需一起報告。此資料不是 D9 新實驗，不能混入 D9 成效分母。
- rkchk snapshot `a9f4e496e61c65d4787365b883e4b21d74689e49`：官方要求
  `rkchk-linux-next` 自訂核心與擴充 Rust kernel API；目前 Ubuntu 6.8 generic
  VM 不能在保持同一環境下直接復現。
- Decloaker snapshot `5a2ca88e3f715a221720a0330ae65ca845a3032d`：磁碟直讀
  路徑只支援 ext4、不支援 tmpfs；目前程式要求 Go 1.25.7，而隔離 VM 無 Go，
  Ubuntu 套件候選僅 1.18。未執行前不得把概念性 raw-disk 對照寫成 Decloaker
  實測結果。

## 下一個 gate

只有在完成下列項目後，才建立 `results/d9_formal/`：

1. overlayfs 與 namespace 邊界；
2. 決定是否優化約 3.72–7.94× raw count 的整體成本；若修改，
   所有新結果另開 revision，舊結果不得混用；
3. 固定容量、seed 產生規則、case schedule、主要指標與分析程式；
4. source snapshot/hash 後進行多次獨立開機確認實驗；
5. 外部工具只納入可在相同環境公平執行者，其餘列為 scope/compatibility 比較。
