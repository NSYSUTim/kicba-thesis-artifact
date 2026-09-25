# D6-r2 與 D7-r1 分析重現指引

## 環境與 raw-data 邊界

- Windows PowerShell；
- Python 3.11/3.12；
- `numpy`、`scipy`、`matplotlib`（可由根目錄 `pyproject.toml` 安裝）。

AI 審查包不重複複製大型 raw batches。下列指令須先由 canonical workspace
取得：

- D6-r2：`results/d6_r2_formal/formal_boot_view_r1/`；
- D7-r1：`results/d7_formal/raw_r1/`，或已驗證的
  `results/d7_formal/raw_r1_canonical/`。

資料規模、schema、用途與限制見 `DATASET_AND_CODE_MANIFEST.md`。所有範例寫入
新的 `reproduction_fresh/`，不覆寫附帶的正式結果。

## 1. 測試程式依賴

```powershell
$env:PYTHONPATH = "$(Resolve-Path src);$(Resolve-Path scripts);$(Resolve-Path collector)"
python -m unittest discover -s tests -v
```

## 2. D6-r2 重現

### 2.1 Generic raw audit

```powershell
python scripts/audit_d4_raw.py `
  --input results/d6_r2_formal/formal_boot_view_r1 `
  --output reproduction_fresh/d6_generic_audit
```

預期 `all_valid=true`、`role_composition_match=true`、`batches=2300`、`boots=5`。

### 2.2 Protocol/hash audit

```powershell
python scripts/audit_d6_r2.py `
  --input results/d6_r2_formal/formal_boot_view_r1 `
  --state results/d6_r2_formal/r1_state.json `
  --lock results/d6_r2_formal/analysis_lock.json `
  --generic-audit reproduction_fresh/d6_generic_audit/audit.json `
  --output reproduction_fresh/d6_audit
```

預期 `reproduction_fresh/d6_audit/audit.json` 的 `status="PASS"`。

### 2.3 Frozen analysis

```powershell
python scripts/run_d6_r2_locked_analysis_output_erratum.py `
  --input results/d6_r2_formal/formal_boot_view_r1 `
  --state results/d6_r2_formal/r1_state.json `
  --lock results/d6_r2_formal/analysis_lock.json `
  --audit reproduction_fresh/d6_audit/audit.json `
  --output reproduction_fresh/d6_confirmatory
```

`report.json` 與三份 CSV 應和
`results/d6_r2_formal/confirmatory_r1_output_erratum/` 逐位元一致。

## 3. D7-r1 重現

### 3.1 由原始收集版面建立 canonical view

這一步只選入精確的 `boot_01` 至 `boot_08`，排除同層 `boot_XX_fixture`，並
逐檔驗證來源／副本 SHA-256 inventory：

```powershell
python scripts/prepare_d7_canonical_view.py `
  --source results/d7_formal/raw_r1 `
  --output reproduction_fresh/d7_raw_canonical `
  --manifest reproduction_fresh/d7_canonical_view_manifest.json
```

若已直接取得 canonical raw view，可略過建立步驟，但仍應先核對附帶的
`results/d7_formal/canonical_view_manifest.json`。

### 3.2 Locked audit

```powershell
python scripts/audit_d7_nesting_formal.py `
  --input reproduction_fresh/d7_raw_canonical `
  --state results/d7_formal/r1_state.json `
  --lock results/d7_formal/analysis_lock.json `
  --output reproduction_fresh/d7_audit
```

預期 `status="PASS"`、`boots=8`、`batches=384`，且四狀態各 96 batches。

### 3.3 Locked analysis

```powershell
python scripts/run_d7_nesting_locked_analysis.py `
  --input reproduction_fresh/d7_raw_canonical `
  --state results/d7_formal/r1_state.json `
  --lock results/d7_formal/analysis_lock.json `
  --audit reproduction_fresh/d7_audit/audit.json `
  --output reproduction_fresh/d7_confirmatory
```

`report.json` 與 `predictions.json` 應和
`results/d7_formal/confirmatory_r1/` 逐位元一致。正式預期為 TP=96、FN=0、
FP=0、TN=288，`method_efficacy_pass=true`。

## 4. 解讀範圍

重現成功只證明同一鎖定 pipeline 可由 canonical raw records 得到相同輸出；
不會消除外部效度限制。D6-r2 不因 D7 成功而變成完整 PASS；D7-r1 也不能支持
通用 Rootkit、惡意歸因或安全線上更新。D7 的成本端點來自另外的單 boot
development overhead evidence，並非八開機效能資料直接估計。
