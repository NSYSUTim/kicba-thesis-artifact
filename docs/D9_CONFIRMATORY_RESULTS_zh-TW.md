# D9 目錄項身分 reconciliation：九開機正式驗證結果

日期：2026-09-24  
證據狀態：正式、鎖定後一次性分析  
分析結果：**PASS（12/12 事前條件成立）**

## 1. 這次實驗回答什麼

D9 比較同一次完整目錄列舉中：

1. `filldir64` 已接受的上游目錄項 multiset fingerprint；
2. 使用者程式從全部 `getdents64` 分頁實際解析到的下游 fingerprint。

兩者不同即回報此邊界存在項目身分差異，再以相減 IBLT 還原少量的
upstream-only／downstream-only token。本方法不根據執行時間判斷，也不把
「項目差異」直接解讀為惡意 rootkit。

## 2. 正式設計與完整性

- 9 個不同 boot ID；每次開機均確認實際斷線後取得新 boot ID。
- 9 種狀態 × 4 種背景負載 × 4 種 `getdents64` buffer × 1 batch ×
  20 次列舉。
- 合計 1,296 批、25,920 次列舉。
- 九次開機以 cyclic rotation 讓每個狀態各自在九個 episode 位置出現一次。
- 每 boot 使用不同的兩個 64-bit hash seed。
- 240 批／4,800 次的 timing calibration 明確排除於正式成效結果之外。
- 1,296/1,296 批通過 runner treatment 與 transaction audit；
  25,920/25,920 次 measurement valid。
- 九份正式資料的 runner、eBPF、hash header、probe 與八個受控模組 SHA-256
  均與正式 lock 完全一致。

## 3. 主要批次層級結果

正類是四個會造成此邊界身分差異的狀態：`filldir_hiding`、
`getdents_hiding`、`getdents_substitution` 與明確授權的 `policy_filter`。
其餘五個狀態為不造成項目差異的控制。

| 方法 | TP | FN | FP | TN | Recall | FPR | Precision | F1 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| D9 fingerprint + IBLT | 576 | 0 | 0 | 720 | 100% | 0% | 100% | 100% |
| D8 count | 432 | 144 | 0 | 720 | 75.00% | 0% | 100% | 85.71% |
| Timing：MAD | 28 | 548 | 51 | 669 | 4.86% | 7.08% | 35.44% | 8.55% |
| Timing：upper envelope | 9 | 567 | 17 | 703 | 1.56% | 2.36% | 34.62% | 2.99% |

D9 recall 的 batch-level Wilson 95% CI 為 99.34%–100%；控制 FPR 的
Wilson 95% CI 為 0%–0.53%。點估計的 100%／0% 只描述本次受測矩陣，
不代表所有環境的真實率必然完美。

兩個 timing comparator 都在正式資料前由相同 240 個非差異控制批次凍結：

- MAD：每個 `(負載, buffer)` 分層使用
  `median + 3 × 1.4826 × MAD`；
- upper envelope：每個分層使用全部控制校準值的最大值再加 0.01
  log-unit。

兩者都照實報告，沒有在正式結果後只挑較差的一個與 D9 比較。它們是本文的
簡單固定時序對照，不是 Trace of the Times 或所有統計／機器學習時序方法的
完整復現。

## 4. 各狀態結果

每個狀態有 144 批；括號為 Wilson 95% CI。

| 狀態 | D9 | D8 count | Timing MAD | Timing envelope |
|---|---:|---:|---:|---:|
| unloaded | 0% (0–2.60) | 0% | 0% | 0% |
| filldir pass | 0% (0–2.60) | 0% | 17.36% | 2.78% |
| filldir active | 0% (0–2.60) | 0% | 18.06% | 9.03% |
| filldir hiding | 100% (97.40–100) | 100% | 19.44% | 6.25% |
| getdents pass | 0% (0–2.60) | 0% | 0% | 0% |
| getdents active | 0% (0–2.60) | 0% | 0% | 0% |
| getdents hiding | 100% (97.40–100) | 100% | 0% | 0% |
| 等量 substitution | 100% (97.40–100) | 0% | 0% | 0% |
| authorized policy filter | 100% (97.40–100) | 100% | 0% | 0% |

D8 count 對純移除有效，但等量替換保持 count 不變，因此 144/144 批未觸發。
D9 比較的是項目身分 multiset，所以 144/144 批均辨識。這是 D9 相對 D8
count 的核心增益，不是靠增加相同 count 訊號的門檻調整。

Timing 警報幾乎集中在 filldir ftrace 路徑；正常 pass、正常字串比對 active
與 hiding 的 alert rate 相近，而三個 getdents 差異狀態均未被辨識。這支持
「時間改變較能反映掛接路徑與額外處理，未必直接對應項目是否消失」的限定
解釋，但不能推論所有更複雜的 timing 方法都會有相同結果。

## 5. IBLT 還原與失效語意

- 差異交易：11,520 次。
- IBLT decode success：11,520/11,520（100%；Wilson 95% CI
  99.967%–100%）。
- 與受控 oracle 完全相符：11,520/11,520。
- 解碼成功但答案錯：0/25,920（95% CI 上界約 0.0148%）。
- measurement invalid：0/25,920（95% CI 上界約 0.0148%）。

這不表示 IBLT 永遠成功。開發期 boundary suite 已保留 9 個刻意不足容量的
案例；正確行為是 fingerprint mismatch 仍成立、IBLT 回報 decode failure，
而不是產生錯誤項目清單。正式矩陣的 256 cells 對最大 32 個 symmetric
difference token 使用事前凍結的 8×容量。

## 6. 為何 100% 不等於題目太簡單或資料造假

本次完美點估計有明確機制原因：在受測靜態交易中，若項目已被最外層
`filldir64` 接受，卻未出現在完整 `getdents64` 輸出，兩端 multiset 依定義
就不同；非差異控制則應相同。D9 直接量測這個研究問題本身，而不是從不穩定
代理訊號推測。

為避免只測容易情況，正式矩陣同時保留：

- 128、256、4,096、65,536-byte buffer；
- baseline、CPU、memory、mixed 負載；
- ftrace pass、字串比對不隱藏、兩個不同 suppression layer、等量替換與
  授權政策過濾；
- 9 次獨立開機、完整 cyclic order；
- 兩個不利於 timing 的公平凍結比較器。

正式矩陣外的開發／邊界證據另包含 219 個分頁、差異量、名稱、型態與容量
案例，30 個 churn／concurrency／fault-injection 案例，24 個檔案系統／
namespace 案例，以及到 65,536 項的成本量測。失敗的 oracle 污染、namespace
路徑與第一次 pagination-audit revision 也保留，沒有刪除後假裝不存在。

## 7. 開發期邊界與成本結果

這些結果不併入上述正式 recall/FPR，但用來回答正式核心矩陣沒有涵蓋的
容量、極端條件與成本問題：

- IBLT 容量模擬共 10,240 trials；8× cells 組合為 2,560/2,560 正確，
  全部組合沒有 fingerprint false-equal，也沒有錯誤的 successful decode。
- 完整 boundary suite：219/219 measurement valid；128/128 真差異被偵測，
  0/91 控制警報；210 次可解碼案例全部精確，9 次失敗全部是刻意容量不足。
- Robustness：30/30 通過，含列舉期間 465–825 次 create/rename/delete churn、
  2/4/8/16 個同步 PID，以及 invalid cells、seed mismatch、未註冊 PID 與程序
  中止等 fault injection。
- 檔案系統／namespace：ext4 與 overlayfs 的 host、mount、user+mount 組合
  18/18 通過；`/proc`、`/sys`、`/dev` 動態 pseudo-fs 控制 6/6 通過。

成本不是「免費」。在開發期 paired-overhead protocol 的 65,536 項 baseline 測量中，
raw probe 平均約 38.16 ms，userspace sketch 約 45.59 ms，完整 D9 約
181.51 ms；完整 D9 約為 raw 的 4.76 倍。這組數值由
`results/d9_development/overhead_full_r2_branch8/overhead.json` 的三次 repeat
各自除以 10 次列舉後取平均；不併入九開機正式成效矩陣。另一方面，在另一個 iteration 數與
runner 不同的 exact-trace protocol 中：

| 目錄項數 | D9 完整方法 | 逐項 exact trace | D9 輸出 | Exact trace 輸出 |
|---:|---:|---:|---:|---:|
| 8,192 | 40.72 ms | 243.07 ms | 12.02 KiB | 2,240.55 KiB |
| 65,536 | 221.62 ms | 2,480.72 ms | 12.02 KiB | 17,920.55 KiB |

這個 exact trace 是本文實作的 accepted-entry map baseline，不是 Synacktiv 工具
的完整復現。結果支持的只是：當預期差異量固定且遠小於目錄大小時，D9 的
輸出大小可隨 IBLT cells 固定，而逐項紀錄的資料量隨項目數成長；它不表示
D9 比未插樁的原始列舉更快。

## 8. 限制與可成立的結論

### 可以成立

在本次 Ubuntu VM、Linux `6.8.0-138-generic`、受控 probe、受測 ftrace `filldir64`
short-circuit、`getdents64` buffer removal、等量 substitution 與 policy filter
機制下，D9 能可靠辨識 `filldir64` 接受後至 `getdents64` 輸出前的項目身分
差異，並在差異量落於容量時還原差異 token。它相較只比 count 能辨識等量
替換，且相較本文兩個固定 timing comparator 更直接對應是否真的發生項目
差異。

### 不能成立

- 不能由警報判定惡意；authorized policy filter 同樣 100% 觸發。
- 不能偵測發生在 `filldir64` 之前、使用者 probe 之後或完全不同視圖邊界的
  所有檔案隱藏。
- 未證明可抵抗能竄改 eBPF、probe、seed 或主動構造 hash collision 的核心
  攻擊者。
- 九開機正式矩陣仍是單一 VM／kernel，正式 factorial 使用靜態 512+差異項目
  fixture；其他檔案系統、namespace、churn 與大型目錄主要屬開發 boundary
  證據，而非多開機正式泛化證據。
- 未在相同 VM 公平執行 rkchk 與 Decloaker：前者要求其 Rust-for-Linux
  自訂核心，後者的 raw-disk/ext4 與 Go toolchain 前提不同。不得填入推測成效。

## 9. 可稽核檔案

- 環境追溯：本次已從原 VM 補取 `/etc/os-release`，並對照實驗前 apt
  安裝紀錄、正式二進位雜湊、VM 建置設定與掛載資訊；詳見
  [`D9_ENVIRONMENT_AUDIT_20261004_zh-TW.md`](D9_ENVIRONMENT_AUDIT_20261004_zh-TW.md)。
  另由[2026-09-24 工作紀錄](../results/environment/experiment_day_record_excerpt_20260924.md)
  補得同日 `lsb_release -ds` 的 Ubuntu 22.04.5 輸出、探針完整 GCC
  指令及正式批次前後的掛載資訊。原九開機批次仍沒有
  逐 boot 的發行版、宿主負載及完整 mount options 快照；耗時數字
  只適用於該 VM／宿主配置。
- 正式 lock：`results/d9_formal/analysis_lock.json`
- timing model：`results/d9_formal/timing_model.json`
- 九開機原始證據：`results/d9_formal/raw/boot_01` 至 `boot_09`
- 回收 manifest：`results/d9_formal/raw/retrieval_manifest.json`
- 鎖定分析輸出：`results/d9_formal/analysis_r1/results.json`
- 校準證據：`results/d9_development/timing_calibration_r2/`
- 開發結果總結：`docs/D9_RECONCILIATION_DEVELOPMENT_RESULTS_zh-TW.md`

本文件是鎖定分析後的結果報告；它沒有回頭修改正式 protocol、model、runner
或分析核心。
