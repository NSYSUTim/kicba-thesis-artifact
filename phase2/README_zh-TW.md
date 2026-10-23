# 第二階段資料索引

結果完成後先讀 [報告](REPORT_zh-TW.md)。本輪的研究問題、分母與採用條件見 [執行前規約](PROTOCOL_zh-TW.md)，先導判斷及相容性修改見 [先導核對](PILOT_REVIEW_zh-TW.md)。

| 內容 | 位置 |
|---|---|
| 兩個環境各自的正式來源鎖 | [locks/](locks/) |
| 每開機確認與品質／成本 | [evidence/](evidence/) |
| 原始資料及實際來源封存 | [evidence/downloads/](evidence/downloads/) |
| 逐開機總表、時間與配對比值 | [analysis/](analysis/) |
| 原版與第一階段完整性基準 | [LOCK.json](LOCK.json) |
| 第三方原始碼、固定提交、授權及移植差異 | [third_party/xcellerator/](third_party/xcellerator/) |
| 對照檢查點與 Hyper-V 複本證據 | [host/evidence/](host/evidence/) |

原始 attempt JSONL、大量逐次實收檔名及動態操作時間紀錄保留於完整歸檔，Git 不重複收錄展開的大量資料。正式資料、先導與原生故障檢查分開保存，不能混成單一確認樣本數。

先執行 `python phase2/analysis/verify_archives.py --unpack` 核對封存 SHA-256 並安全展開，再重新產生分析。已有同名資料時必須逐位元組相符，不能覆寫不同內容。

純 Python 核對：`python -m unittest phase2.tests.test_oracle phase2.tests.test_summary -v`。原生核心測試僅能在規約指定的隔離 VM 執行；故障證據目錄已存在時會拒絕覆寫，不要用重跑取代已保留的失敗。

`analysis/make_report.py` 從歸檔展開的原始列舉重新核對摘要、每筆實收身分、判讀及解碼，產生衍生 JSON／CSV／報告。`analysis/plot_costs.py` 用第一階段已隔離安裝的 Matplotlib 套件重畫獨立 PNG；原 VM 沒有安裝繪圖套件。

核心及模組的建置／掛接限研究 VM，新版路徑為 `/home/kicba/research_phase2_20261023/`。請勿把這組針對單一試驗環境的腳本當成可直接佈署到任意主機的工具。

本輪保留本機分支 `research/phase2-applicability-cost`，從第一階段 `cb0a27a` 延伸，第一階段分支仍保留。未修改論文與簡報，未合併或推送 GitHub 主分支，也不自動開始第三階段。
