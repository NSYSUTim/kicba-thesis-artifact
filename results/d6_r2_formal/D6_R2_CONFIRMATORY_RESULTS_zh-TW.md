# D6-r2 五開機確認性實驗結果

## 結論摘要

D6-r2 的提出方法 `proposed_factorized_guard_w50` 在五次獨立開機、800 個
Rootkit 測試批次、900 個 unloaded normal 批次與 100 個 sham 批次中，得到：

- Rootkit recall：93.75%；
- unloaded normal FPR：0%；
- sham FPR：1%；
- non-attack FPR：0.1%；
- F1：0.9671；
- attack update rate：6.25%；
- unloaded update rate：100%；
- sham update rate：99%；
- 最大視窗攻擊比例：47.92%；
- unknown rate：0%。

這些結果顯示，在本次受控 benchmark 中，含 pass-through `filldir64`
負控制校正、per-boot threshold、context split 與新 feature 的整體系統，觀察到低
unloaded／sham FPR 與高整體 Rootkit recall。但現有比較尚無法將改善單獨
歸因於 factorization，而且預先鎖定的全部成功規則沒有同時通過，
正式 `method_efficacy_pass = false`。不可將 D6-r2 報告成「方法已
全面驗證成功」或「已辨識惡意隱藏語義」。

## 資料完整性

- 五個獨立 boot ID；
- 每個 boot 460 批，共 2,300 批；
- 2,300 批全部有效、lost events 為 0；
- 每個正式 boot 均為 460 個 batches 與一個 complete manifest；
- 五個 episode 在五個 ordinal 上各出現一次；但每個 sequence 僅一個
  boot，不能分開 sequence effect 與 boot effect；
- collector、BPF、campaign runner、module、分析與 protocol hashes 均吻合；
- generic audit 與勘誤後使用原封不動的 locked audit 均 PASS。

原始 locked audit 的 FAIL 與第一次正式分析輸出失敗均永久保留。前者源自
`boot_NN_fixture` 被錯認為 boot；後者源自歷史 CSV writer 無法輸出異質診斷
欄位。兩次勘誤均在任何正式成效數字可見以前完成，且沒有改變資料、模型、
門檻、W50、指標或成功規則。

## 五種方法比較

| 方法 | Attack recall | Unloaded normal FPR | Sham FPR | Non-attack FPR | F1 | Attack updates | Unloaded updates | Sham updates | 最大視窗攻擊比例 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Fixed public empirical | 88.88% | 23.00% | 69.00% | 27.60% | 0.7957 | 0% | 0% | 0% | 0% |
| Fixed public OAS（主要 fixed 比較） | 47.38% | 6.22% | 11.00% | 6.70% | 0.6083 | 0% | 0% | 0% | 0% |
| Blind public empirical W50 | 90.00% | 89.44% | 100.00% | 90.50% | 0.5938 | 100% | 100% | 100% | 100% |
| Blind public OAS W50（主要 blind 比較） | 95.75% | 94.00% | 94.00% | 94.00% | 0.6113 | 100% | 100% | 100% | 100% |
| Proposed factorized guard W50 | **93.75%** | **0%** | **1.00%** | **0.10%** | **0.9671** | 6.25% | 100% | 99% | 47.92% |

相較主要 fixed OAS，提出方法在五個 boot 的差異方向一致，並得到：

- recall 增加 46.38 percentage points；paired bootstrap 95% CI 為
  [+24.13, +66.38] points；
- unloaded normal FPR 減少 6.22 points；paired bootstrap 95% CI 為
  [-9.00, -3.44] points；
- F1 增加 0.3588。

這些 CI 是預設的 boot-paired percentile bootstrap，最高層獨立重複僅
`n=5` boots。因此應描述為「五個 boot 的改善方向一致，並有預設
paired interval」，不應擴大為已普遍統計顯著。

相較主要 blind OAS W50，提出方法的 recall 低 2.00 points，但 non-attack
FPR 從 94.00% 降至 0.10%、F1 從 0.6113 增至 0.9671，最大視窗攻擊比例從
100% 降至 47.92%。

## 預先鎖定成功規則

### PASS（9/15）

1. 五個不同 boot；
2. unloaded normal FPR <= 5%（實際 0%）；
3. sham FPR <= 20%（實際 1%）；
4. 每 boot 最大 sham FPR <= 30%（實際 5%）；
5. unloaded update rate >= 95%（實際 100%）；
6. unknown rate = 0；
7. F1 比 fixed OAS 至少高 0.05（實際高 0.3588）；
8. paired recall CI 下界 >= -5 points（實際 +24.13 points）；
9. 相較 blind OAS 的最大污染降低至少 50 points（實際降低 52.08 points）。

### FAIL（6/15）

1. 整體 recall >= 95%：實際 93.75%；
2. 每 boot recall >= 90%：最差 boot 為 83.75%；
3. attack update rate <= 5%：實際 6.25%；
4. 最大視窗攻擊比例 <= 20%：實際 47.92%；
5. unloaded FPR 比 fixed OAS 至少降低 10 points：實際降低 6.22 points；
6. paired unloaded-FPR CI 上界 <= -5 points：實際上界為 -3.44 points。

## Boot 穩定性與失敗機制

提出方法五個 boot 的 attack recall 分別為 98.13%、91.25%、83.75%、
96.25% 與 99.38%。最差 boot 的 attack update rate 為 16.25%，最大視窗攻擊
比例為 47.92%。

漏報主要集中在高 context stratum：最差 boot 的 CPU attack recall 為
67.5%，mixed attack recall 為 75%。該 boot 的高-context security threshold
約為 0.554，而 CPU／mixed attack 的平均 security score 約為 0.596，分布
重疊導致部分攻擊未越過 security gate。因 guarded update 規則允許所有
security-negative 批次更新 operational window，漏報的攻擊也會進入視窗，
所以 attack update 與污染同時上升。

這表示目前已觀察到的直接失敗機制，是 timing gate 對不同 boot 與
高負載 context 的 attack／negative-control separation 不夠穩定。這不代表
normal/sham specificity 已在一般情境解決；現有 sham 狀態與 workload cells 仍有限。

## Operational detector 與部署成本

Operational detector 是次要指標，不決定 Rootkit 警報：

- workload-drift recall：6.83%；
- baseline-drift FPR：11.67%。

因此 D6-r2 沒有證明 operational branch 能可靠辨認正常漂移；主要良好結果
來自 operational branch 以外的負控制校正 timing gate 與相關系統設計。由於
缺少等資訊消融，還不能將改善單獨歸因於 factorization。

## 方法學限制與因果解釋

1. D6-r2 sham 只安裝 pass-through `filldir64` hook；hiding CARAXES 安裝
   `fillonedir`、`filldir`、`filldir64`、`compat_fillonedir` 與
   `compat_filldir` 五個 hooks。現有 audit 未計數各 callback 是否觸發。
2. Hiding callback 每個 directory entry 執行 `strstr(name, MAGIC_WORD)` 與
   branch，sham 則直接調用原函式。所以當前計分可能偵測過濾計算
   成本，不是獨特的惡意隱藏語義。
3. Proposed 使用 per-boot 50 clean+50 sham、context split、專用 feature 與
   per-boot threshold；public-style comparator 使用 50 clean 與 D5 frozen thresholds。
   當前是系統級比較，不是單一 factorization 元件的公平消融。
4. 900 個 unloaded batches 的 0% FPR 僅適用於本 VM／kernel／目錄／工作
   負載範圍。Test sham 只含 baseline 與 CPU，無 sham×memory 與 sham×mixed。
5. `max(clean+sham)+0.01` 門檻會受 calibration sample size、極端值與
   boot noise 影響；最差 boot 的結果與這項敏感性一致。

因此下一輪應優先做 matched five-hook pass-through sham、相同
`strstr`／branch 但永不隱藏的 active-logic sham、sham×memory／mixed，以及
equal-information ablation，而不是重跑相同 D6 或單純調整 W50。

部署 overhead 仍為 FAIL。既有 role-aggregate collector 的操作延遲增加範圍
為 11.30% 至 47.30%，高於預定的 5% 上限；D6-r2 沒有重新量測或解決此項。

## 可支持與不可支持的論文主張

可以支持：

> 在單一 VM／kernel、CARAXES-like `filldir` hiding 與受控工作負載中，
> pass-through `filldir64` 負控制校正系統於 D6-r2 觀察到 93.75% hiding
> recall、0% unloaded FPR 與 1% sham FPR；五個 boot 的差異方向一致，
> 並有預設 paired bootstrap interval。此結果是部分預設低誤報 endpoint
> 的正向證據，不是整體 method-efficacy PASS。

不可支持：

> 方法已達到所有預註冊成功標準、已完全阻止攻擊污染、已可靠解決正常漂移，
> 或已達到可部署的低 overhead。

最合理的研究結論是：D6-r2 在受測 benchmark 中，為負控制校正與
security／operational 警報分離提供低誤報正向證據；但現有 sham 不完全
matched，比較資訊不對等，且 boot-stable attack separation、污染控制、
operational drift detection 與低成本部署均未解決。
