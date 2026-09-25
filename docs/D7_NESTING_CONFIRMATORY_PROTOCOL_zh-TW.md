# D7 核心呼叫巢狀不變量：正式確認實驗規格

## 1. 研究問題與修正理由

D5/D6 的時間偵測器會把 pass-through hook 或只執行字串比對、但不隱藏
檔案的 active control 誤判為 Rootkit。D7 開發資料進一步顯示，舊 timing
gate 在 active control 的警報率為 75%，對真正 hiding 的 recall 僅 58.3%。
因此「時間變長」主要反映額外 hook／filter 運算，不能單獨支持「偵測到
隱藏行為」的因果主張。

D7 改檢查控制流程結構，而非耗時大小。對本研究的 CARAXES-like ftrace
wrapper：

- 未掛鉤：每個最外層 `filldir64` 沒有同名內層呼叫；
- pass／active：每個最外層呼叫都轉送到原函式，因此都有同名內層呼叫；
- hiding：一般項目會轉送，命中隱藏條件的項目會短路，因此同一列舉同時
  出現「有內層」與「無內層」的最外層呼叫。

鎖定規則為：

> 一次目錄列舉中，`forwarded_top_calls > 0` 且
> `short_circuit_top_calls > 0` 時警報。

規則不讀取檔名、magic word、`ls` 輸出數量、模組名稱、狀態標籤、時間
threshold 或 sliding window。

## 2. 範圍與威脅模型

主要主張限於「選擇性短路同名 callback 的 CARAXES-like ftrace 檔案隱藏
路徑」。不主張涵蓋 DKOM、完全不同的 hook 點、在原函式之後才修改 buffer
的 Rootkit，或能停用／欺騙 eBPF 的主動對手。合法的選擇性 kernel filter
也可能呈現相同結構，因此警報語意是「未授權的選擇性 directory-entry
suppression 候選」，須配合部署政策判讀。

此方法不同於傳統 cross-view：主要規則不比較已知檔案清單與使用者輸出；
輸出內容只作 ground-truth 與資料品質稽核。

## 3. 實驗設計

- 8 個全新且互異的 VM boot ID。
- 四種狀態：unloaded、五-hook pass、相同字串比對但不隱藏的 active、
  真正 hiding。
- 四種負載：baseline、CPU、memory、mixed。
- 每個 boot 的每個 state × workload cell 為 3 batches；每 batch 20 次列舉。
- 每 boot 48 batches；總計 384 batches、7,680 次列舉。
- 四狀態 episode 使用四列 balanced Latin square，完整重複兩次；episode
  內的 workload/replicate 由預先鎖定 seed 隨機排列。
- 每個狀態模組均由同一 wrapper 原始碼建置並掛同五個 callback；active 與
  hiding 的差異只在命中後是否呼叫原函式。
- VM 必須無 default route；每個 episode／boot 結束必須卸載模組。

## 4. 比較方法

同一批正式資料同時收集 `iterate_dir` first/last wall timing。時間比較器在
D7 正式資料開始前，僅用單開機 development matched-control 的 unloaded
與 pass 資料固定 origin、axis 與 threshold；正式資料不得重新 fit。

主要方法是 nesting invariant；timing comparator 只用來檢驗「結構訊號是否
比額外運算耗時更能區分 active 與 hiding」。

## 5. 主要指標與成功規則

正式分析以 boot 為 cluster，另報 batch-level Wilson 95% CI。

- hiding recall ≥ 95%，且每 boot recall ≥ 90%；
- unloaded、pass、active FPR 各 ≤ 5%；
- 任一 boot／control 的 FPR ≤ 10%；
- hiding recall − active FPR 的行為分離度 ≥ 0.90；
- 相較 frozen timing，行為分離度至少提高 0.30，且 boot-cluster paired
  difference 的 95% CI 下界大於 0；
- active FPR 相較 timing 的非劣界值為 0.05（paired difference CI 上界 ≤ 0.05），
  且 recall 相較 timing 不劣（paired difference CI 下界 ≥ 0）；
- F1 相較 timing 至少提高 0.20。

所有規則必須同時通過，才宣稱 D7 在此威脅模型下通過。失敗結果原樣保留，
不得依正式結果修改規則後重算。

## 6. 成本端點

舊的「單次受監控操作相對延遲 ≤ 5%」仍獨立報告，不以新指標取代。D7 的
擬定用途為週期性診斷，因此另在收集前鎖定：每分鐘一次、每次 20 次列舉；
各負載最慢整次掃描 ≤ 1 秒，且平均正向新增 wall time 攤提至 60 秒後
≤ 0.1%。development overhead 只決定部署描述，不參與正式 efficacy 判斷。

## 7. 鎖定與分析順序

1. 收集前建立 `results/d7_formal/analysis_lock.json`，記錄所有程式、模組、
   timing model、overhead evidence 與本文件 hash。
2. 完成 8 boot 後先執行 `scripts/audit_d7_nesting_formal.py`。
3. audit PASS 後，`scripts/run_d7_nesting_locked_analysis.py` 只能執行一次。
4. 不得因 D7 結果修改 feature、規則、state order、分母或成功門檻。
