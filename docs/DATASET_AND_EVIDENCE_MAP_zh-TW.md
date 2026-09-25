# KICBA 資料集、證據與程式總表

更新日期：2026-09-21

本文件是 D1–D7 資料用途與證據邊界的唯一總索引。`D` 代表 dataset，
不代表互相獨立或都可作為最終成效證據的演算法版本。

## 1. 資料生命週期

| 資料 | 性質與狀態 | 對研究推導的實際作用 | 可支持的主張 | 不可支持的主張 | 主要路徑 |
|---|---|---|---|---|---|
| D1 | Trace of the Times 公開 1,250 批資料 | 復現前人、cross-scenario FPR、blind-window 污染 replay | timing detector 會受情境變化與 blind update 影響 | KICBA context gate 有效 | `data/raw/intervals_fun.zip`、`results/public_phase/` |
| D2 | 五開機早期同步 context 資料；已知混淆 | 暴露 percentile aggregation、collector overhead、invocation composition 問題 | 失敗機制與為何不採用 v0 | residual/context v0 成功 | `results/d2_formal/`、`results/invocation_composition_audit/` |
| D3 | 早期 calibration/test 資料；同樣受目錄截斷混淆 | 證實 D2 confound 不是單一開機偶發；拒絕缺乏理論依據的多視窗共識 | benchmark failure analysis | 確認性 detector 成功 | `results/d3_formal/`、`results/factor_study_d2_d3_development/` |
| D4 | benchmark correction 與開發／機制資料 | 修正 CARAXES 提前截斷、建立 role alignment、pass-through sham、aggregate collector 與 overhead 估計 | 量測混淆、負控制必要性、開發決策 | 最終多開機成效 | `results/d4_*`、`docs/d4_benchmark_correction_protocol.md` |
| D5 | 五開機、事前鎖定的正式 FAIL | 暴露 `operational OR security` 造成 73% sham FPR；驅動 D6 redesign；提供 D6 public-style comparator 事前凍結門檻 | D5 方法失敗、redesign provenance | D6 方法成功 | `results/d5_formal/` |
| D6-r1 | 在看成效前中止 | 發現文件／實作不一致、固定 episode order、FPR 分母與 audit 缺失 | protocol correction 與研究完整性 | 任何成效估計 | `results/d6_formal/`、`docs/D6_R2_CONFIRMATORY_PROTOCOL_zh-TW.md` |
| D6-r2 | 五開機、2,300 批的最新確認性資料 | 提供當前主要 recall、FPR、F1、update contamination 與 per-boot 結果 | 指定 benchmark 的系統級觀察；整體 9/15 規則通過、efficacy FAIL | malware-specific semantics、通用 detector、全面成功 | `results/d6_r2_formal/` |
| D7 development | D6 後單開機機制／composition／nesting／overhead pilots | 加入 active-logic control；證明 D6 timing gate 對 filtering computation 不特異；形成並凍結 nesting 規則與成本模型 | 機制資格、候選特徵與 protocol provenance | 多開機確認性成效 | `results/d7_development/`、`attack_variants/d7_controls*/` |
| D7-r1 formal | 八開機、384 批、事前鎖定的一次性正式確認；方法功效 PASS | 以 matched unloaded/pass/active/hiding controls 驗證同名 callback nesting invariant，並與 frozen timing comparator 配對比較 | 受測 selective same-symbol callback short-circuit 路徑的 suppression 候選偵測；13/13 功效規則 PASS | 通用 Rootkit／惡意歸因／其他 hook 技術／安全線上自適應已完成 | `results/d7_formal/`、`docs/D7_R1_CONFIRMATORY_RESULTS_zh-TW.md` |

## 2. 目前必須一起閱讀的結果

### 2.1 D5 為何不能省略

D5 是正式失敗資料，不是無關的前測。它找出 final OR fusion 將一般
timing shift 升級為 Rootkit alert，使 sham FPR 達 73%。D6-r2 因此將 Rootkit alert
與 operational branch 分離。D6-r2 四個 public-style baseline thresholds 也是由 D5
development data 選定後於收集前凍結。

### 2.2 D4 overhead 與負控制

D6-r2 未重測 overhead；論文中 11.30%–47.30% 來自 D4 role-aggregate
operation-latency 測量。D4 也首次顯示 unloaded→sham 的主要 timing 增加
可大於 sham→hiding，因此直接導出 D6 的 negative-control design。

### 2.3 D7 的機制轉折與正式結果

D7 mechanism-r2 單開機探索用 pass-through 校正的 timing axis 測得：

- unloaded alert rate 0%；
- pass-through alert rate 0%；
- active-logic false-positive rate 75%；
- hiding recall 58.33%。

依預先寫入 report 的 interpretation rule，高 active alert rate 表示這個 timing
axis 回應 filtering computation，而非特異回應實際 suppression。這不會改寫
D6-r2 的觀察指標，但強化其因果解讀限制。

後續 composition 與 nesting pilot 在同一個開機各用 12 批／狀態，對受測
CARAXES-like callback path 觀察到 100% hiding recall 與 0%
unloaded/pass/active FPR。這些 pilot 只用來形成候選與凍結正式 protocol。

D7-r1 formal 隨後用 8 個全新且互異 boot、384 batches（每狀態 96）、
7,680 次 listings 與完整 baseline／CPU／memory／mixed cells 一次性確認。
Nesting invariant 為 TP=96、FN=0、FP=0、TN=288；八個 boot 各自皆為
100% hiding recall 與三種 control 0% FPR。Frozen timing comparator 為
0% hiding recall、1.04% active FPR 與 0% F1。預先鎖定的 13 條方法功效規則
全部 PASS。

首次 D7 audit 因鎖定程式以 `startswith("boot_")` 把 `boot_XX_fixture`
工作目錄誤認為正式 boots 而 FAIL，且未執行成效分析。後續修正只建立精確
包含 `boot_01` 至 `boot_08` 的 byte-identical canonical view，逐檔核對
SHA-256；原 raw、首次 FAIL、程式、features、規則、timing model 與門檻均未改。
修正後 audit PASS，才執行一次正式分析。這不是忽略失敗，而是有保留紀錄的
輸入版面勘誤。

## 3. D6-r2 與 D7-r1 原始資料、schema 與邊界

### 3.1 D6-r2

- 正式分析路徑：`results/d6_r2_formal/formal_boot_view_r1/`。
- 5 個獨立 boot，每 boot 460 batches，共 2,300。
- Calibration：每 boot 50 unloaded + 50 sham，共 500。
- Test：unloaded 900、hiding 800、sham 100，共 1,800。
- 每 batch 20 次 listing；128 個可見檔案；filename length 32；hidden slot middle。
- 2,300 批均 valid、exact-output PASS、lost events=0。
- 只涵蓋單一 Hyper-V VM／kernel／CARAXES family。
- Test sham 只含 baseline 與 CPU，無 memory／mixed。
- 每個 episode sequence 只有一個 boot。
- D6-r2 sham 與 hiding 的 hook 數量及 filtering logic 不完全 matched。

### 3.2 D7-r1 formal

- 原始收集路徑：`results/d7_formal/raw_r1/`；正式分析的 byte-identical view：
  `results/d7_formal/raw_r1_canonical/`。
- 8 個互異 boot，每 boot 48 batches，共 384；每 batch 20 listings。
- 四狀態 unloaded、pass、active、hiding 各 96 batches；四負載 baseline、CPU、
  memory、mixed；每個 boot 的每個 state × workload cell 3 batches。
- 每一狀態在四個 episode positions 各出現兩次，workload／replicate 由鎖定 seed 排序。
- Batch 頂層保存 schema/protocol、batch ID、evidence role、truth、environment、
  collection、directory factor、listing audit、module-counter audit、quality 與
  20 筆 transactions。
- 每筆 transaction 保存 `forwarded_top_calls`、`short_circuit_top_calls`、
  `top_level_calls`、`max_depth`、`return_underflows`、`iterate_dir_calls`、
  `first_raw_wall_ns`、`last_raw_wall_ns` 與 `structural_alert`。
- Nesting detector 只使用前兩個結構計數；檔名、magic word、輸出數量、模組名稱、
  state label 與 timing 都不進入決策。輸出與 module counters 只作 ground-truth／品質稽核。
- Batch alert 為 20 listings 中任一次同時有 forwarded 與 short-circuit top calls。
- 384 批全數通過修正後 integrity audit；正式 `predictions.json` 有 768 rows，
  即每 batch 各一筆 nesting 與 frozen timing prediction。
- 方法範圍只涵蓋受測 CARAXES-like selective same-symbol callback short-circuit。
  合法的選擇性 kernel filter 可能有相同結構，不能僅憑此訊號作惡意歸因。
- 成本證據來自單一 boot development overhead pilot：連續監控的舊 5% 規則 FAIL；
  每分鐘一次、每次 20 listings 的 periodic diagnostic rule PASS。

## 4. 程式與正式輸出

| 功能 | 路徑 |
|---|---|
| D6-r2 method／metric core | `scripts/d6_r2_analysis_core.py` |
| Feature extractor | `scripts/analyze_d4_qualification.py` |
| Context-axis implementation | `scripts/d4_context_axis.py` |
| Locked analysis | `scripts/run_d6_r2_locked_analysis.py` |
| CSV-only output erratum | `scripts/run_d6_r2_locked_analysis_output_erratum.py` |
| Generic raw audit | `scripts/audit_d4_raw.py` |
| D6-r2 integrity audit | `scripts/audit_d6_r2.py` |
| D7 mechanism/composition/nesting audits | `scripts/audit_d7_*.py` |
| D7-r1 canonical-view preparation | `scripts/prepare_d7_canonical_view.py` |
| D7-r1 locked analysis | `scripts/run_d7_nesting_locked_analysis.py` |
| D7-r1 eBPF／campaign／multiboot | `collector/bpf_d7_nesting_formal.c`、`collector/run_d7_nesting_formal_campaign.py`、`collector/run_d7_nesting_multiboot.py` |
| Campaign/collector | `collector/` |
| Public-style detector | `src/kicba/detector.py` |
| Tests | `tests/` |
| Hiding/sham/D7 controls | `attack_variants/` |

| 內容 | 路徑 |
|---|---|
| D6-r2 analysis lock | `results/d6_r2_formal/analysis_lock.json` |
| D6-r2 collection state | `results/d6_r2_formal/r1_state.json` |
| D6-r2 generic audit | `results/d6_r2_formal/generic_audit_r1/audit.json` |
| D6-r2 integrity audit | `results/d6_r2_formal/audit_erratum_r1/audit.json` |
| D6-r2 formal report | `results/d6_r2_formal/confirmatory_r1_output_erratum/report.json` |
| D7 timing mechanism analysis | `results/d7_development/mechanism_r2_analysis/report.json` |
| D7 composition pilot | `results/d7_development/composition_pilot_r1_audit/report.json` |
| D7 nesting pilot | `results/d7_development/nesting_pilot_r1_reaudit/report.json` |
| D7-r1 protocol／lock／state | `docs/D7_NESTING_CONFIRMATORY_PROTOCOL_zh-TW.md`、`results/d7_formal/analysis_lock.json`、`r1_state.json` |
| D7-r1 first FAIL／amendment／canonical manifest | `results/d7_formal/audit_r1/audit.json`、`analysis_amendment_01.json`、`canonical_view_manifest.json` |
| D7-r1 corrected PASS audit | `results/d7_formal/audit_r1_canonical/audit.json` |
| D7-r1 formal report／predictions | `results/d7_formal/confirmatory_r1/report.json`、`predictions.json` |
| D7-r1 result／erratum narrative | `docs/D7_R1_CONFIRMATORY_RESULTS_zh-TW.md`、`docs/D7_R1_INPUT_LAYOUT_ERRATUM_zh-TW.md` |

## 5. AI 審查包政策

AI 審查包的目的是讓審查者完整理解研究設計、證據鏈、失敗、限制與
正式輸出，不是複製整個資料倉庫。因此包內包含：

- D1–D7 的精確用途、規模、設計、schema 摘要、可／不可支持主張與 canonical 路徑；
- protocol、analysis lock、state、campaign manifest、audit、摘要與正式 reports／metrics／predictions；
- 會影響研究推導的程式、collector、attack/control source 與 tests；
- D1 公開資料 DOI `10.5281/zenodo.14679675` 與本地 archive MD5
  `bf5e9024c2954d51dd061e3c942b42f7`。

包內刻意不包含 D1 archive、NPZ、`batch_*.json.gz` 或其他 raw batch payload。
需要重跑 raw→feature→report 時，由上表 canonical 路徑或 DOI 另行取得。
審查包永遠由 canonical sources 生成，不另維護副本。
