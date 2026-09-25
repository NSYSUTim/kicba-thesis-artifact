# KICBA D5-r1 鎖定式正式驗證摘要

## 完整性與隔離

- 五個獨立開機，共 2,040 個正式批次；audit 全數有效，lost events = 0。
- 正式分析前，五份 manifest、收集器、BPF、campaign/multiboot runner、特徵擷取、context axis、analysis 與 audit 程式雜湊皆符合 `analysis_lock.json`。
- 分析完成後 VM service 為 inactive 且 disabled，`caraxes` / `caraxes_sham` 未載入，無 default route。
- 方法、特徵、threshold、W20、fusion 與成功規則皆未依 D5 結果修改。

## 整體結果

| 方法 | Rootkit recall | Normal FPR | Sham FPR | Unknown | Attack updates | Normal updates | 最大視窗攻擊比例 |
|---|---:|---:|---:|---:|---:|---:|---:|
| Fixed | 100.0% | 59.7% | 79.0% | 0% | 0% | 0% | 0% |
| Blind W20 | 16.5% | 12.0% | 68.0% | 0% | 100.0% | 100.0% | 100.0% |
| Guarded W20 | 100.0% | 14.1% | 73.0% | 0% | 1.0% | 99.0% | 30.0% |

Guarded 相對 fixed 的每開機配對 Normal FPR 差為 -45.6 percentage points，boot-cluster bootstrap 95% CI 為 [-52.8, -38.4] percentage points。

## 預先鎖定規則

- PASS：五個獨立 boot。
- PASS：Guarded recall >= 95%（實際 100%）。
- PASS：相對 fixed 的 recall 降幅 <= 2 pp（實際 0 pp）。
- PASS：相對 fixed 的 FPR 絕對下降 >= 20 pp（實際 45.6 pp）。
- PASS：配對 FPR 差的 95% CI 上界 <= -5 pp（實際 -38.4 pp）。
- PASS：attack update rate <= 10%（實際 1%）。
- PASS：normal update rate >= 90%（實際 99%）。
- PASS：最大視窗攻擊比例 <= 30%（實際 30%）。
- PASS：unknown rate = 0（實際 0%）。
- **FAIL：Sham FPR <= 20%（實際 73%）。**

因此 `method_efficacy_pass = false`。Guarded 的**最終 OR 融合輸出**在此資料上無法把不隱藏檔案的 sham 模組可靠地視為非攻擊。正式結果完成後所做的診斷性拆解顯示：100 個 sham 中，operational branch 告警 72 個、security branch 告警 10 個、兩者同時告警 9 個，OR 後共告警 73 個；800 個 hiding 批次中 security branch 告警 792 個。這項事後拆解不改變 D5 的 FAIL 判定，但修正了「security gate 本身只是在辨識 hook」的過度推論：主要失敗來源是把一般 timing shift 與 security evidence 用 OR 合併成同一種 Rootkit 警報。此替代解釋必須由新的預先鎖定實驗驗證，不能回頭把 D5 改稱成功。

## 部署成本

**FAIL（獨立規則）**：既有 D4 operation-latency overhead 約 11%–47%，高於預先設定的 5% 上限。此項不因 D5 的方法效果而改判。
