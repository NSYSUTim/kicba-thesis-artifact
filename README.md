# D9：filldir64 → getdents64 目錄項身分差異偵測

本儲存庫是論文〈以 eBPF 與 IBLT 偵測 filldir64 至 getdents64 間的目錄項身分差異〉的精簡研究成品。內容只涵蓋 D9 方向：論文、核心實作、實驗控制模組、正式資料、驗證結果與重現腳本；不包含其他 D1–D8 方向、快速測試、早期 pilot、中間文件或外部專案的完整副本。

## 研究方法與主要結果

D9 在 `filldir64` 已接受的目錄項與 `getdents64` 回傳給使用者空間的完整分頁列舉之間，比對固定大小的 multiset fingerprint；發現差異時再以 IBLT 嘗試還原兩側的身分差集。

九次獨立開機的正式矩陣共有 1,296 個 batch、25,920 次列舉。D9 對 576 個差異 batch 全數告警、對 720 個控制 batch 均未告警，recall、precision 與 F1 皆為 100%，FPR 為 0%；11,520 次正例 transaction 的 IBLT 差集亦全數正確還原。這些結果只表示觀測邊界兩側存在身分差異，不直接判定惡意意圖。

## 儲存庫內容

| 路徑 | 內容 |
|---|---|
| `paper/` | 本方向的繁體中文會議論文 `.docx` |
| `src/kicba/reconciliation.py` | multiset fingerprint、IBLT 與 token 實作 |
| `collector/` | eBPF 程式、列舉 probe、D9 收集器與成本量測程式 |
| `attack_variants/` | 正式矩陣實際需要的自製 filldir/getdents 控制模組 |
| `scripts/` | 正式分析、timing calibration、IBLT 容量與多開機控制腳本 |
| `results/d9_formal/` | 九次開機的壓縮正式資料、分析鎖定檔、timing model 與結果 |
| `results/d9_development/` | 論文引用的邊界、容量、穩健性、namespace 與成本證據；早期 quick/pilot 已排除 |
| `results/d9_external_comparison/` | D9 原始比較資料，以及 Trace of the Times / Decloaker 的必要摘要與驗證紀錄 |
| `results/environment/` | VM 建置紀錄、宿主狀態、客體發行版輸出、相關 apt 事件摘要與實際 Kbuild 命令 |
| `docs/` | 研究協定、正式結果、外部比較鎖定與偏差紀錄 |
| `tools/external_baselines/` | 本研究撰寫的最小驗證/轉接腳本；不含外部專案本體或二進位 |

完整收錄/排除原則見 [`ARTIFACT_SCOPE.md`](ARTIFACT_SCOPE.md)，外部方法與固定版本見 [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md)。實驗 VM、工具鏈、apt 歷史與事後讀數的界線見 [`D9 環境追溯紀錄`](docs/D9_ENVIRONMENT_AUDIT_20261004_zh-TW.md)。

## 快速驗證

分析程式只使用 Python 標準函式庫；正式收集需在隔離的原生 Linux VM 內使用 root、BCC/eBPF、編譯器與對應 kernel headers。請勿在日常使用的主機載入研究用 kernel module。

```bash
python -m pip install -e .
python -m unittest discover -s tests -v

python scripts/analyze_d9_formal.py \
  --input results/d9_formal/raw \
  --timing-model results/d9_formal/timing_model.json \
  --lock results/d9_formal/analysis_lock.json \
  --output reproduced/d9_formal_results.json
```

分析應通過全部預先指定條件，並產生與 `results/d9_formal/analysis_r1/results.json` 相同的統計結果。正式收集的完整設計、VM 條件與指令參數以 [`docs/D9_RECONCILIATION_RESEARCH_PROTOCOL_zh-TW.md`](docs/D9_RECONCILIATION_RESEARCH_PROTOCOL_zh-TW.md) 為準。

## 資料完整性

`FILE_SHA256.csv` 列出儲存庫內研究檔案的 SHA-256。正式執行另由 `results/d9_formal/analysis_lock.json`、各 `campaign.sha256` 及外部比較鎖定檔約束來源與資料版本。
