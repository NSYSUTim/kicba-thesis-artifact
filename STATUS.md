# KICBA 專題目前狀態

> **2026-09-21 最新狀態（優先於全文舊進度）：** D7-r1 八開機正式確認已完成：
> 384 batches、7,680 listings，修正後完整性 audit PASS。Nesting invariant 的
> hiding recall、precision、F1 均為 100%，unloaded/pass/active FPR 均為 0%；
> 八個 boot 各自皆為 100% recall、0% control FPR，13 條鎖定功效規則全部 PASS。
> Frozen timing comparator 為 0% hiding recall、1.04% active FPR、F1=0。
> 週期診斷成本規則 PASS，但連續監控的舊 5% 操作延遲規則 FAIL（baseline mean
> +21.26%）。首次 audit 曾因 `boot_XX_fixture` 被誤認為正式 boot 而 FAIL；
> 成效分析前只建立 byte-identical canonical view，原 raw、首次 FAIL 與鎖定
> 程式／規則均保留。D6-r2 的 timing／online-update 結果仍是方向 B 的正式證據：
> 15 條規則只通過 9 條、attack update 6.25%、最大污染 47.92%，不得寫成安全
> 自適應成功。最新論文分成
> [方向 A：結構型 suppression 偵測](docs/papers/TRACK_A_LOW_FALSE_POSITIVE_ROOTKIT_zh-TW.md)與
> [方向 B：安全線上自適應](docs/papers/TRACK_B_SAFE_ONLINE_ADAPTATION_zh-TW.md)；
> 下文保留歷史演進，不得覆蓋此最新狀態。D1–D7 完整證據角色見
> [資料與證據總表](docs/DATASET_AND_EVIDENCE_MAP_zh-TW.md)。

更新日期：2026-09-21

## D4 修正後 benchmark：目前已實際完成的部分

- 建立 `CARAXES-continue` 受控變體（模組 SHA-256
  `574fbd9ad7926b1eff0cc8f8452052df246ff8a9aabfddfb59f15c9c289b6445`）：
  遇到指定 hidden entry 時跳過輸出但繼續列舉，不再截斷其他可見檔案。
- D4-Q1-r2 在隔離、無 default route 的 VM 完成 72 批／36 個正常-攻擊因素配對：
  72/72 精確輸出正確、0 lost events、36/36 配對的 `iterate_dir` 呼叫角色分布相同；
  目錄大小與檔名長度會使每次列舉有 2、3 或 7 次 `iterate_dir` 呼叫，故仍須依角色建模。
- 一個 1,024 個長檔名條件曾造成舊 D4 collector 的 stdout pipe deadlock；
  失敗 `r1` 完整保留。修正為暫存檔接收輸出及單次列舉逾時後，`r2` 成功；原始資料、
  manifest 與實際用到的 collector/runner snapshot 已匯出。
- 角色對齊的探索性分析發現首個 `iterate_dir` timing 在 36/36 因素格較大，
  但攻擊狀態 `filldir64` 探針命中約是正常兩倍。這可能是 ftrace hook 與 eBPF probe
  的交互量測效應，**尚不得解釋為攻擊特有訊號或宣稱方法較好**。
- 已編譯且通過精確正常輸出檢查的 pass-through sham ftrace 模組
  （SHA-256 `0c36b9a40d30b4778fc304be5bc2b4d4a65c65f382982c59f7eef1bf93cbd2b2`），
  完成 unloaded／sham／hiding 三方對照：36/36 批精確輸出與品質均通過。
  `first_raw_median` 的 sham/unloaded 中位比值為 1.838，hiding/sham 僅 1.042，且
  只有 9/12 格 hiding 大於 sham；`first_oncpu_median` 分別為 1.805、1.059，
  10/12 格同方向。這表示原先約 1.9 倍的主要 signal 是掛鉤/探針交互效應，
  不是可支持藏檔辨識的特異性證據。
- 已建立只量 `iterate_dir`、不掛 `filldir64` 也不掛 scheduler/IRQ tracepoints 的
  minimal BPF 配置；三狀態 36/36 品質通過。其 `first_raw_q10` 在 hiding/sham 的
  12 格中 11 格增加，中位比值 1.205；但 sham/unloaded 也有 11/12 格增加、
  中位比值 1.099。這仍只是一個 boot、每格一批的候選訊號，非 detector 成效。
- D4 paired overhead 第一輪（每格 2 pair）顯示完整收集流程的額外 wall time 遠高於
  5%：不同因素/配置平均約 +50% 至 +241%。主要疑因是每次 `ls` 後的 userspace
  perf-buffer 輪詢等待。已建立只用於低事件量 `role_minimal` 的 `wait_drain` 政策，
  大目錄三狀態 smoke 3/3 品質通過；重新配對成本測試進行中。原高成本結果保留。

D4 目前是開發／機制資料，不是最終確認；D5 的新 boot、新目錄 seeds、鎖定方法與
overhead 測試仍不可省略。

## 重要狀態更正（優先於下方舊進度）

D2/D3 完成後的 raw invocation-composition audit 找到一個會阻止目前方法主張成立的
benchmark confound：每個 100-iteration batch 中，normal 固定有 200 次 `iterate_dir`
（每個 `ls` 兩次），CARAXES 固定只有 100 次（每個 `ls` 一次），D2 與 D3 的所有
1,200-batch test set 都完全相同。

角色對齊後的結果與未對齊結果方向相反：

- 混合所有呼叫的 `iterate_dir q10`：Rootkit 較大，D2 mean AUC 0.9967、D3 AUC 1.0；
- 每個 `ls` 只比較第一個 `iterate_dir`：Rootkit 反而較小，D2 mean AUC 0.0083、
  D3 AUC 0.0。

CARAXES `hooks_filldir.h` 在 magic name 時設定 `-ENOENT` 並 `return false`，實際效果是
提早終止列舉。隔離 VM 控制實驗也顯示，正常目錄的多個可見項目在 Rootkit 狀態只剩一個；
舊 collector 只驗證 magic file 消失，沒有驗證其他可見項目保持存在。

因此：

## 2026-09-19：D4 修正基準與 D5 狀態

- 已修正上游 CARAXES 提前停止列舉的 confound；受控 variant 只略過 hidden entry 並繼續列舉。
- 三個獨立 D4 boot 的 sham 對照顯示，hiding 的首呼叫時間相對 pass-through sham 幾何平均約高 25%，但跨目錄單一全域門檻不可用。
- 新的 BPF map aggregate collector 只保留每次 listing 的 first/last `iterate_dir` 時間，478 批 r6 全部 exact-output、role-aligned、lost=0。
- D4-r6 的 context clean-to-sham axis + 單一 W20 長序列結果：Fixed FPR 71.6%／recall 98.89%；Blind FPR 6.8%／recall 15.56%／180 個攻擊更新；Guarded FPR 10.4%／recall 98.89%／9 個攻擊更新／249 個正常更新。
- W20、W50、W100 是三個獨立 replay；W20 因最低 guarded FPR 且 recall 相同而被選定，沒有做多視窗共識。
- D5-r1 已在收集前鎖定程式與分析 hash、W20、成功規則；五開機自動收集已開始，state 位於 guest `/home/kicba/d5_formal/r1_state.json`。
- 部署成本仍未達標：目前 aggregate collector 對目標操作的相對延遲約 11%–47%，原 ≤5% 規則仍為 FAIL，與方法 efficacy 分開判定。

1. D2/D3 仍可證明「盲目更新會吸收此攻擊分布」及描述原始 CARAXES 的控制流程效應；
2. 不可再把其主要 separation 解釋成「Rootkit 額外程式碼使同一函式呼叫變慢」；
3. 目前 KICBA、視窗敏感度與低分位候選都不能升格為正式成功方法；
4. 下一步必須先建立 D4 benchmark correction：精確驗證輸出集合、按 PID/呼叫序位對齊、
   控制目錄 cardinality/order，並使用不截斷正常輸出的受控攻擊或獨立變體；完成後才研究
   context、safe update 與單一 window size。

錯誤的多視窗 consensus 分支及其程式、鎖定檔、輸出已刪除。D2/D3 raw data 保留作
post-hoc failure analysis，不會覆寫或假裝成新的 confirmatory evidence。

下方內容保留為 2026-09-14 的歷史規劃；凡與本節衝突者均已被本節取代。

## 結論先講

本專題的程式、公開資料實驗與 D2 蒐集管線已完成；原生 Hyper-V Ubuntu 實驗 VM、
乾淨 checkpoint 與無 default route 的 host-only 網路均已建成並驗證。CARAXES 已在
隔離 VM 中完成載入、隱藏行為與卸載測試。正式五 boot D2 收集現正自動執行；在
1,200 batches 收完並完成 leave-one-boot-out 分析前，仍不得宣稱 proposed method 有效。

## 你實際要做的事

一句話版本：

> 當 eBPF 量到核心函式變慢時，不直接把新資料當正常，也不一律報警；先用同步的
> scheduler、IRQ/SoftIRQ 與 CPU 脈絡判斷這個變慢能否由正常核心干擾解釋。只有
> 「干擾可解釋且扣除干擾後仍像正常」的批次，才准許更新 normal baseline。

這不是要發明新的通用 Rootkit classifier，而是要解決一個較窄、可以驗證的問題：
**eBPF 核心時序偵測器在線上適應時，如何同時減少正常漂移誤報與攻擊資料污染。**

## 已完成

- 讀取並固定上游程式版本與官方公開資料。
- 將 3.4 GB 原始 CSV 串流轉成 1,250 個 batch-level 分位數特徵。
- 精確復現上游 seed-42 結果：TP=499、FP=9、TN=491、FN=1、F1=0.9901。
- 補做不使用 test attack labels 選 threshold 的 same-scenario 評估。
- 完成 default-trained cross-scenario 評估。
- 完成固定、Blind-50、Score-gated、Dual-anchor 的線上 replay。
- 實作 OAS covariance、normal-only calibration 與 prequential predict-then-update。
- 實作 eBPF/BCC D2 collector、scheduler/IRQ interval accounting、品質拒判、CARAXES
  campaign runner、leave-one-boot-out 評估器及 KICBA v0。
- 建立 Ubuntu 22.04.5、kernel 6.8.0-138、4 vCPU／8 GiB 的原生 Hyper-V VM。
- 固定上游 commits 並成功編譯 CARAXES；module SHA-256 為
  `a4edd4a2bd79d01677af8e95cf7da5511539e87a90fb89143bf49215a868f390`。
- D2 smoke batch 四個目標皆有完整 entry/return、lost events 為 0；原始證據已取回
  `results/d2_smoke/`。
- 單元測試全部通過，所有 Python 檔案可編譯。
- 建立 `Clean-Repaired-Isolated-20260914-212429` checkpoint；VM 位於
  `192.168.77.0/24` host-only 網路，guest 無 default route。
- 正式前 pilot 8/8 batches 通過；發現 CARAXES 下 `verify_dirent_name` 穩定零命中，
  因此在正式收集前凍結 D2-r1 規約：主要分析只用三個共同可觀察 timing 函式，第四個
  probe 仍完整記錄但不作分類捷徑。
- 修正 PID 加入監控邊界可能產生 return-only 事件的收集器競態；100-iteration 壓力
  pilot 16/16 batches 通過、lost=0、target entry/return mismatch=0。12 個單元測試通過。

## D1 已經證明什麼

1. 在同一情境且使用上游 oracle threshold 時，原方法可以得到很高分。
2. threshold 嚴格只用 normal calibration 後，`system_load` 的平均 recall 明顯下降，
   表示結果對切分與 covariance 很敏感。
3. Default model 遇到 `file_count`、`ls_basic`、`system_load` normal 時，平均 FPR
   分別為 100%、100%、99.1%。也就是正常環境改變足以讓 timing-only detector 幾乎
   全部報警。
4. Blind-50 的 normal FPR 降到 12.4%，但 persistent-rootkit recall 只剩 15.1%，
   且更新內容的污染率為 66.7%。
5. Score-gated 與 Dual-anchor 維持 100% recall、零污染，卻有 99% normal FPR，
   幾乎不接受 benign drift 更新。

因此 D1 支持的是「存在三難與需要額外證據」，不是「KICBA 已經比前人好」。

## 尚缺且不可省略

- 至少 5 個獨立 boot IDs、每個 boot 240 batches，共至少 1,200 valid batches。
- RQ4：context 對 timing-only 是否有 held-out incremental value。
- RQ5：KICBA 是否同時降低 FPR 與污染、維持 recall，且不是靠大量 unknown。
- 消融、bootstrap confidence intervals、Holm correction 與 overhead 實測。

## 完成判準

只有 D2 leave-one-boot-out 結果同時符合預先規定的標準，論文才可主張 KICBA 有效：

- normal drift FPR 相較 Fixed 絕對降低至少 5 個百分點，95% CI 不跨 0；
- 污染率相較 Blind-50 相對降低至少 50%；
- rootkit recall 相較 Fixed 下降不超過 2 個百分點；
- unknown 不超過 20%；
- CPU overhead 目標不超過 5%。

若沒達標，專題仍可誠實改寫為「eBPF timing detector 的跨情境穩健性與可歸因性研究」，
不能倒過來調標準或隱藏負面結果。

## 正式 D2 執行狀態

- 規約：`D2-r1-2026-09-14`。
- 預先固定 seeds：1001、1002、1003、1004、1005。
- 每個新 boot 先確認 CARAXES 未載入且無 default route，再執行 240 batches；成功才
  更新 state 並重新開機。任何品質失敗立即停止，不自動重跑或覆寫。
- guest state：`/home/kicba/d2_formal/r1_state.json`。
- guest raw output：`/home/kicba/d2_formal/r1/boot_01` 至 `boot_05`。
- 正式 boot 1 已啟動；完成數須以 state 與 campaign manifest 為準。
