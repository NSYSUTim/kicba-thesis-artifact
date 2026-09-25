# D6-r2 正式分析輸出勘誤

## 原始執行失敗

formal boot view 通過原封不動的鎖定稽核器後，第一次執行鎖定正式分析器
時，所有計算完成至輸出階段，但 `predictions.csv` 寫入中止：歷史函式
`analyze_d4_qualification._write_csv` 只使用第一列的 keys 建立 CSV 欄位，
而 D6-r2 合併的 proposed prediction 額外包含 `context_stratum` 等診斷欄位，
因而觸發 `ValueError: dict contains fields not in fieldnames`。

失敗執行留下的部分輸出永久保留於
`results/d6_r2_formal/confirmatory_r1`，不得作為結果使用。當次沒有建立
`report.json`、`overall_metrics.csv` 或 `per_boot_metrics.csv`，也沒有輸出
任何 recall、FPR 或 F1。

## 修正範圍

新增 `scripts/run_d6_r2_locked_analysis_output_erratum.py`。它只把 CSV writer
替換為所有列 keys 的聯集，缺少的診斷欄位輸出為空白；接著呼叫原封不動
的 `scripts/run_d6_r2_locked_analysis.py` 主程式。

下列項目完全不變：

- 輸入 raw batches、manifest、state 與通過的 integrity audit；
- 特徵、模型、門檻、W50、更新規則及分類；
- 所有 metric 計算、paired bootstrap、成功規則與 overhead 判定；
- 鎖定分析器本身及其 SHA-256。

修正後輸出使用新的 `confirmatory_r1_output_erratum` 目錄，不覆寫第一次失敗
的部分輸出。此錯誤與修正均發生在任何正式效能結果可見以前。
