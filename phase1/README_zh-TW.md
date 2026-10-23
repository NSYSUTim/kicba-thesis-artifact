# 第一階段資料索引

先讀 [結果與意義](REPORT_zh-TW.md)，再按需要查看下列資料。

| 內容 | 位置 |
|---|---|
| 執行前規約 | [PROTOCOL_zh-TW.md](PROTOCOL_zh-TW.md) |
| 先導結果與確認版決定 | [PILOT_REVIEW_zh-TW.md](PILOT_REVIEW_zh-TW.md) |
| 三次確認彙整、開機身分與分母 | [analysis/summary.json](analysis/summary.json) |
| 每開機／條件／模式的時間 | [analysis/costs.csv](analysis/costs.csv) |
| 隨機配對增量及變異，保留負值 | [analysis/paired_increments.csv](analysis/paired_increments.csv) |
| 原追蹤檔案完整性 | [analysis/original_integrity.json](analysis/original_integrity.json) |
| 新環境前後核對及清理 | [final_verification.json](final_verification.json) |
| 歸檔 SHA-256 核對 | [evidence/EXPORT_VERIFICATION.json](evidence/EXPORT_VERIFICATION.json) |
| 全六份歸檔與補充試驗後的收尾核對 | [evidence/FINAL_VERIFICATION.json](evidence/FINAL_VERIFICATION.json)、[final_environment_after_supplements.json](final_environment_after_supplements.json) |
| 來源及種子鎖 | [LOCK.json](LOCK.json)、[CONFIRMATION_LOCK.json](CONFIRMATION_LOCK.json) |
| 額外故障對照 | [FAULT_CHECK_PROTOCOL_zh-TW.md](FAULT_CHECK_PROTOCOL_zh-TW.md)、[evidence/fault_checks_attempt1](evidence/fault_checks_attempt1) |
| 判讀旗標的更正及未修改原版對照 | [CORRECTIONS_zh-TW.md](CORRECTIONS_zh-TW.md)、[evidence/original_gate_reference_attempt1/summary.json](evidence/original_gate_reference_attempt1/summary.json) |
| 全域 map 配置稽核 | [evidence/map_memory_audit.json](evidence/map_memory_audit.json) |

完整原始列舉、實收名稱、失敗與時間紀錄封存在 evidence/downloads/ 的三份 confirmation_boot 歸檔和 phase1_pilot_and_faults.tar.gz。已驗證 5 份歸檔與 37 個凍結來源檔案的 SHA-256。phase1_frozen_sources.tar.gz 包含當時實際使用的原始碼位元組、Linux 二進位與既有受控模組；早期先導版本另留在先導歸檔的部署 tar 中。

未修改原版的補充對照另外封存在 original_gate_reference.tar.gz，附獨立 SHA-256；不加入三次確認的樣本數。確認原始資料的 original_valid 是新增全域門檻前的診斷版旗標，不等同未修改原版，詳見更正文件。

原始展開資料保留在本機，但 Git 不重複收錄大型 JSONL 和大量個別 dump；可由上述完整歸檔還原。這些腳本僅針對指定受保護 VM，不是可直接部署到任意主機的工具。不要把確認資料和先導資料合併成同一個正式樣本數。

核對歸檔及必要時展開先導資料：`python phase1/verify_exports.py`。一般 Python 測試為 `python -m unittest phase1.tests.test_coverage phase1.tests.test_runner_contract phase1.tests.test_summarize -v`。Linux C／BPF 整合檢查及故障對照必須在受保護 VM 依規約執行；故障證據目錄已存在時會拒絕覆寫，不能用測試重跑替換原始結果。

圖表只用本機隔離的 Matplotlib 3.10.7 及 render_requirements.txt 所列版本；不曾安裝到原 VM。重畫可執行 `python phase1/plot_costs.py`，其輸入是已保存的 analysis/summary.json。

本輪保留獨立分支，不合併 main、不推送 GitHub、不修改論文或簡報，也不自動開始第二階段。
