# D6-r2 確認性實驗規格（收集前鎖定）

鎖定日期：2026-09-20

## 為什麼另建 r2

D6-r1 在完成兩個 boot、第三個 boot 尚未完成時，發現下列設計／實作不一致，因此在未執行成效分析的情況下主動中止：

1. 文件描述 operational detector 與 `attack/drift/normal`，分析實作卻只有 security gate；
2. 五個 boot 使用相同的「正常→攻擊→sham」順序，使攻擊狀態與實驗時間混雜；
3. `normal_fpr` 實際混合 unloaded 與 sham；
4. 缺少 D6 專用測試及完整的 raw/state/manifest hash audit。

D6-r1 原始資料、state 與 log 已保留在 `results/d6_formal/aborted_r1*`，不得用作確認性成效證據，也未用其結果調整 r2 threshold 或 feature。D6-r2 使用新程式、新 seeds、新輸出目錄及五個新 boot。

## 研究問題

在相同的 eBPF `iterate_dir` 時序量測下，負控制校正的行為 security gate 是否能比一般固定或 blind-W50 時序 shift detector：

1. 維持較高的 file-hiding Rootkit recall；
2. 降低真正 unloaded normal 與 pass-through sham 的誤報；
3. 阻止 attack batches 污染 operational W50；
4. 將 Rootkit security alert 與一般 operational drift 分開。

## 提出方法

每個 boot 的 calibration 包含：

- unloaded clean：baseline 25 批、CPU 25 批；
- pass-through sham：baseline 25 批、CPU 25 批。

以校正資料 `cpu_busy_fraction` 的最大間隙區分 low/high context，間隙須至少 0.20。各 context 在以下二維 log feature space 建立 clean centroid 指向 sham centroid 的單位軸：

1. `first_raw_median`；
2. `first_div_last_raw_median`。

Security threshold 是該 context 所有 clean+sham calibration projection 的最大值加 0.01 log-unit。Security threshold 固定，不做線上更新。

Operational detector 在各 context 個別維護單一 W50，feature 為 `first_raw_median`。校正門檻是 clean calibration 相對其中位數的最大 ratio 再乘 1.01。每個測試批次遵守 prequential 順序：

1. 先用更新前的 security 與 operational model 預測；
2. security 陽性 → `attack`，發出 Rootkit alert，拒絕更新；
3. security 陰性且 operational 陽性 → `drift`，不發 Rootkit alert，允許更新；
4. 兩者皆陰性 → `normal`，允許更新。

沒有 `unknown`。Rootkit alert 只由 security gate 決定，禁止 `operational OR security`。

W50 是唯一正式視窗，理由是對應前人公開 online setting；不同 context 的 W50 彼此獨立，不採多視窗投票。

## Counterbalanced test schedule

每 boot 360 個 test batches 分成五個 episode：

| Episode | 內容 | 批數 |
|---|---|---:|
| `normal_early` | unloaded baseline 20 + CPU 40 | 60 |
| `normal_workloads` | unloaded memory 40 + mixed 40 | 80 |
| `attack` | hiding baseline/CPU/memory/mixed，各 40 | 160 |
| `recovery` | unloaded baseline | 40 |
| `sham_control` | sham baseline 10 + CPU 10 | 20 |

五個 boot 使用五個 episode 的循環 Latin-square：第 k 個 boot 將基本順序循環位移 k−1。結果是每個 episode 在第 1–5 個 ordinal position 各出現一次。Attack episode 在每個 boot 均維持連續 160 批，保留 blind adaptation／contamination 壓力測試。Episode 內的 attack conditions 循環位移，兩元素 normal/sham blocks 在偶數 boot 反轉。

這能消除「攻擊永遠位於相同實驗時間」的完全混雜；但五次 boot 仍不足以估計所有高階 order interaction，因此 order effect 只作設計控制，不宣稱完全消除所有時間效應。

## 比較方法

1. `fixed_public_empirical`：q10–q90、first/last interval、empirical covariance；
2. `blind_public_empirical_w50`：相同核心，每批無條件進 W50；
3. `fixed_public_oas`：OAS shrinkage covariance 的強化固定基準；
4. `blind_public_oas_w50`：OAS 強化 blind W50；
5. `proposed_factorized_guard_w50`：本研究方法。

四個 public-style baseline thresholds 已由 D5 development data 選定並在 r2 收集前凍結；D6-r2 結果不得重調。這些基準重現公開方法的 q9 Mahalanobis shift core 與 W50 更新邏輯，但輸入是本研究 role-aggregate collector 的 first/last intervals，不宣稱是原作者完整 event grouping 的逐位元重現。

## 指標定義

- `attack_recall`：只以 `state=hiding` 為分母；
- `unloaded_normal_fpr`：只以 `state=unloaded` 為分母；
- `sham_fpr`：只以 `state=sham` 為分母；
- `non_attack_fpr`：unloaded+sham 合併，僅作補充；
- `attack_update_rate`：hiding 批次被放入 operational window 的比例；
- `unloaded_update_rate`、`sham_update_rate` 分開報告；
- `max_window_attack_fraction`：任一 context W50 的最大 attack label 比例；
- operational workload-drift recall 與 baseline-drift FPR 是次要描述性 endpoint，不列入主要成功判定。

## 資料規模與結論邊界

- 五次獨立 boot；每 boot 460 批，總計 2,300 批；
- 每 boot：100 calibration + 360 test；
- 每批 20 次 listing；128 個可見檔案；檔名長度 32；hidden slot 為 middle；
- 工作負載：baseline、CPU、memory、mixed；
- 原生隔離 VM 必須沒有 default route；boot 開始及實驗結束不得殘留 `caraxes`/`caraxes_sham`。

結論限於單一 VM/kernel 配置、修正版 CARAXES 類 file-hiding Rootkit、指定目錄因素與四種 workload，不外推到所有 Rootkit 或硬體。

## 主要成功規則

- 5 個 unique boot；
- proposed overall recall ≥ 95%；每 boot 最低 recall ≥ 90%；
- proposed unloaded normal FPR ≤ 5%；
- proposed overall sham FPR ≤ 20%，每 boot最大 sham FPR ≤ 30%；
- attack update rate ≤ 5%；
- unloaded update rate ≥ 95%；
- max W50 attack fraction ≤ 20%；
- unknown rate = 0；
- proposed F1 至少比 `fixed_public_oas` 高 0.05；
- proposed unloaded FPR 至少比 `fixed_public_oas` 低 0.10；
- boot-paired unloaded FPR difference 95% bootstrap CI 上界 ≤ −0.05；
- boot-paired recall difference 95% bootstrap CI 下界 ≥ −0.05；
- 相較 `blind_public_oas_w50`，最大污染至少降低 0.50。

任一規則失敗即判定 method efficacy FAIL。不得依 D6-r2 結果修改 feature、threshold、W50、fusion、episode order、指標分母或成功規則，也不得覆寫唯一一次正式輸出。

## 完整性門檻

正式分析前必須依序通過：

1. generic raw audit：2,300 批、五 boot、exact output、lost events=0、role composition match；
2. D6-r2 audit：state complete、五個 unique boot、episode Latin-square、每 boot 460 批；
3. 本機 collector/BPF/campaign/multiboot/core/audit/analysis/test/service/protocol hashes；
4. 每個 manifest 的 collector、BPF、campaign runner、hiding module、sham module hashes；
5. state 中的 campaign/multiboot runner hashes；
6. audit 後 state 與 manifest 不得改變。

任一 audit 失敗即停止，不執行成效分析。

## Overhead

部署成本是獨立 endpoint。現有 role-aggregate operation-latency overhead 為 11.3%–47.3%，仍高於 ≤5% 規則，D6-r2 不重測 overhead，因此 deployment overhead 預先維持 FAIL。D6-r2 即使 method efficacy PASS，也不能宣稱已是低成本部署系統。
