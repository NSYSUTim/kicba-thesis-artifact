# KICBA 外部 AI 審查包

建立日期：2026-09-21

> 本包由工作區 canonical sources 自動生成。請勿編輯包內副本；
> 任何修正都應回到原工作區後重建審查包。

## 建議審查順序

1. `DATASET_AND_CODE_MANIFEST.md`：D1–D7 完整資料生命週期、schema、證據用途與封裝範圍。
2. `docs/papers/README.md`：兩條研究方向與不可互換的證據邊界。
3. `docs/papers/TRACK_A_LOW_FALSE_POSITIVE_ROOTKIT_zh-TW.md`：D7-r1 結構型 suppression detector 主稿。
4. `docs/D7_R1_CONFIRMATORY_RESULTS_zh-TW.md`：D7-r1 正式數字與主張邊界。
5. `docs/D7_R1_INPUT_LAYOUT_ERRATUM_zh-TW.md`：首次 audit FAIL 與 canonical-view 修正。
6. `results/d7_formal/analysis_lock.json`、`audit_r1/audit.json`、
   `analysis_amendment_01.json`、`audit_r1_canonical/audit.json`、
   `confirmatory_r1/report.json`：鎖定、失敗、勘誤、稽核與結果鏈。
7. `docs/papers/TRACK_B_SAFE_ONLINE_ADAPTATION_zh-TW.md`：D6-r2 線上更新的負面結果與後續方向。
8. `REPRODUCE.md`：取得 raw 後重跑 D6-r2／D7-r1 audit 與 locked analysis。

## 當前結論

- D7-r1 是最新主要確認資料：8 個互異 boots、384 batches、7,680 listings。
- Nesting invariant 為 TP=96、FN=0、FP=0、TN=288；hiding recall、precision、
  F1 均 100%，unloaded/pass/active FPR 各 0%。八個 boot 各自結果一致。
- Hiding recall 的 batch-level Wilson 95% CI 為 96.15%–100%；三種 controls
  各 96 批零誤報的 FPR CI 約 0%–3.85%，所以「觀察值 0%」不等於母體必為零。
- Frozen timing comparator 的 hiding recall 0%、active FPR 1.04%、F1 0；
  nesting method 的 13 條鎖定功效規則全部 PASS。
- 首次 audit 因 `boot_XX_fixture` 被 `startswith("boot_")` 誤選而 FAIL，當時
  未跑成效分析。修正只建立逐檔 SHA-256 一致的 canonical view；原 raw、首次
  FAIL、程式、規則與門檻均保留。
- 週期診斷成本規則 PASS；連續套用時 baseline 平均相對操作延遲 +21.26%，
  舊 ≤5% 規則 FAIL。成本證據只來自單一 boot development pilot。
- 主張只限受測 CARAXES-like selective same-symbol callback short-circuit。
  合法選擇性 kernel filter 也可能觸發，因此警報只能稱 suppression candidate。
- D6-r2 仍是方向 B 的最新 adaptive evidence：attack update 6.25%、最大視窗污染
  47.92%、operational drift recall 6.83%，安全線上自適應仍未成功。

## 完整性與資料政策

- `PACKAGE_PROVENANCE.json`：生成器與 raw exclusion policy。
- `FILE_SHA256.csv`：包內每個檔案的 SHA-256。
- `REPRODUCTION_VERIFICATION.md`：已實際完成的 D6-r2 與 D7-r1 重現驗證。
- 本包不重複封裝 D1 archive、NPZ、`batch_*.json.gz` 或 fixture payload；它包含
  足以理解資料設計與證據鏈的 protocol、schema 說明、lock、state、manifest、
  audit、reports、predictions、程式與 tests。單獨本包不能重跑 raw→report。
