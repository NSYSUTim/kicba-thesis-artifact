# KICBA：以 eBPF 偵測核心層選擇性目錄項抑制

本儲存庫是論文書面審查用的可重現研究附件，保存 KICBA 專題的必要程式、鎖定分析設定、正式輸入視圖、機器可讀結果與論文稿。快取、編譯產物、Word/PDF 暫存、虛擬機映像與重複封裝檔均未納入。

## 研究摘要

研究分成兩個證據互不取代的方向：

1. **方向 A：回呼巢狀結構偵測。** 在受測 CARAXES-like 同名回呼短路路徑中，以 eBPF 觀察 `filldir64` 最外層呼叫的轉送與短路結構。D7-r1 使用 8 次獨立開機、384 批、7,680 次目錄列舉；結果為 TP=96、FN=0、FP=0、TN=288，隱藏狀態召回率與 F1 皆為 1.000，三種控制狀態的觀察誤報率皆為 0%。13 項事前鎖定的功效規則全部通過。
2. **方向 B：污染受控線上基準更新。** D6-r2 使用 5 次獨立開機、2,300 批資料；雙分支 W50 得到 93.75% 隱藏狀態召回率、0% 未載入誤報率與 1% 負控制誤報率，但 15 項鎖定規則只通過 9 項。此方向屬部分改善與負面結果，不能宣稱已完成安全且有效的線上自適應。

上述數字是本實驗條件下的觀察結果，不代表能偵測所有 rootkit，也不能單憑警報判定惡意性。完整限制與信賴區間見[方向 A 論文稿](docs/papers/TRACK_A_LOW_FALSE_POSITIVE_ROOTKIT_zh-TW.md)、[方向 B 論文稿](docs/papers/TRACK_B_SAFE_ONLINE_ADAPTATION_zh-TW.md)及[資料與證據地圖](DATASET_AND_CODE_MANIFEST.md)。

## 儲存庫內容

| 路徑 | 內容 |
|---|---|
| `src/kicba/` | 特徵、偵測器、指標與共用分析程式 |
| `collector/` | eBPF 探針、資料收集器與多開機排程 |
| `attack_variants/` | CARAXES 衍生實驗模組及 pass/active/hiding 控制 |
| `scripts/` | 完整性稽核、鎖定分析與結果產生程式 |
| `results/` | 正式輸入視圖、分析鎖、稽核紀錄、預測與報告 |
| `tests/` | 單元與重現性測試 |
| `docs/` | 論文稿、實驗規格、勘誤與方法來源稽核 |
| `vm/` | 隔離 Hyper-V/Linux 實驗環境腳本；不含映像檔 |
| `FILE_SHA256.csv` | 發佈檔案的 SHA-256 清單 |

若只想檢閱論文證據，建議依序閱讀 `START_HERE.md`、`DATASET_AND_CODE_MANIFEST.md`、兩份論文稿與 `REPRODUCTION_VERIFICATION.md`。

## 快速驗證

需求：Python 3.10 以上；分析相依套件由 `pyproject.toml` 安裝。原生 eBPF 收集另需隔離的 x86-64 Linux VM、相符的 kernel headers 與 BCC，請勿在日常使用或生產主機載入實驗模組。

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e .
$env:PYTHONPATH = "$(Resolve-Path src);$(Resolve-Path scripts);$(Resolve-Path collector)"
python -m unittest discover -s tests -p "test_*.py" -v
```

D6-r2 與 D7-r1 的逐步稽核及鎖定分析命令見 [`REPRODUCE.md`](REPRODUCE.md)。所有重跑結果應寫入新的輸出目錄，避免覆寫本儲存庫保存的正式結果。

## 資料集與封裝範圍

- D1 公開資料來自 Landauer 等人的 Zenodo 資料集：[Kernel Function Time Measurement Data Set for Anomaly-based Rootkit Detection](https://doi.org/10.5281/zenodo.14679675)，本地原始壓縮檔的既有 MD5 紀錄為 `bf5e9024c2954d51dd061e3c942b42f7`。為避免重複散布，本儲存庫不收錄該大型壓縮檔。
- 儲存庫收錄 D6-r2 的 `results/d6_r2_formal/formal_boot_view_r1` 與 D7-r1 的 `results/d7_formal/raw_r1_canonical` 精簡 canonical 正式輸入視圖，以及分析鎖、稽核、預測與報告；大型逐批 VM 原始封包、虛擬機映像與可由程式重建的中間產物不收錄。
- 各資料階段 D1–D7 的用途、規模、schema、可支持與不可支持的主張，統一記錄於 [`DATASET_AND_CODE_MANIFEST.md`](DATASET_AND_CODE_MANIFEST.md)。

## 上游專案與本研究修改

本儲存庫不是從零撰寫的獨立 rootkit 專案。研究起點為 AIT Austrian Institute of Technology 的 [Trace of the Times 實作](https://github.com/ait-aecid/rootkit-detection-ebpf-time-trace)（研究固定版本 `269d9b0bc6aafb403cba209bb47b8bdb902ba10e`）及其 [CARAXES](https://github.com/ait-aecid/caraxes) 學術測試 rootkit。

本研究新增或修改的主要部分包括：continue-enumeration 修正版、pass-through／active-logic 控制、回呼巢狀 eBPF 探針、多開機收集與稽核流程、D6-r2/D7-r1 鎖定分析，以及完整的實驗證據鏈。逐項來源與修改範圍見 [`docs/method_provenance_audit_2026-09-20.md`](docs/method_provenance_audit_2026-09-20.md)及 [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md)。第三方檔案保留其原授權與著作權聲明；本儲存庫未另行宣告整體授權。

## 引用

論文書面引用本研究時，請使用最終論文定稿中的作者、校名、系所、題名與年份。本儲存庫使用的上游研究請引用：

> M. Landauer et al., “Trace of the Times: Rootkit Detection through Temporal Anomalies in Kernel Activity,” *Digital Threats: Research and Practice*, 2025. https://doi.org/10.1145/3770085

## 研究與安全聲明

`attack_variants/` 只供隔離、可還原的學術實驗環境使用。請勿在未獲授權的系統或生產設備執行、載入或部署其中的核心模組。
