# D7-r1 八開機正式確認結果（方向 A）

## 研究主張

D7 僅驗證方向 A：在受測 CARAXES-like ftrace 檔案隱藏路徑中，使用核心
同名 callback 的巢狀結構，區分「真正選擇性略過 directory entry」與未載入、
pass-through hook、以及執行相同字串判斷但不略過 entry 的 active control。

決策規則在收集前鎖定為：一次目錄列舉中同時出現
`forwarded_top_calls > 0` 與 `short_circuit_top_calls > 0` 才警報。規則不使用
檔名、magic word、使用者空間輸出數量、模組名稱、攻擊標籤、時間門檻、
訓練模型或 sliding window。一個 batch 的 20 次列舉中，只要任一次符合即為
batch-level structural alert。

## 資料與稽核

- 8 個互異 VM boot ID。
- 4 狀態 × 4 負載 × 每格 3 batches × 8 boots，共 384 batches。
- 每 batch 20 次列舉，共 7,680 次列舉。
- unloaded、pass、active、hiding 各 96 batches。
- balanced Latin-square state order；每一狀態在四個位置各出現兩次。
- 修正後 audit PASS；所有原鎖定程式、模型、manifest、資料品質與 boot
  identity 檢查均通過。

首次 audit 因把 `boot_XX_fixture` 誤認為正式 boot 而 FAIL，且當時未執行
成效分析。修正採 byte-identical canonical input view；原始資料、第一次 FAIL、
原 audit、原 analysis 與成功規則皆保留未改。詳見
`D7_R1_INPUT_LAYOUT_ERRATUM_zh-TW.md` 與
`results/d7_formal/analysis_amendment_01.json`。

## 主要結果

| 方法 | Hiding recall | Unloaded FPR | Pass FPR | Active FPR | Non-attack FPR | Precision | F1 |
|---|---:|---:|---:|---:|---:|---:|---:|
| Nesting invariant | 100% | 0% | 0% | 0% | 0% | 100% | 100% |
| Frozen timing comparator | 0% | 0% | 0% | 1.04% | 0.35% | 0% | 0% |

Nesting invariant 的 confusion matrix 為 TP=96、FN=0、FP=0、TN=288；八個
boot 各自都是 hiding recall 100% 且三種 control FPR 0%。Hiding recall 的
batch-level Wilson 95% CI 為 96.15%–100%；三種各 96 批且零誤報的 FPR
Wilson 95% CI 均約為 0%–3.85%。

與 frozen timing 進行 boot-cluster paired comparison：

- hiding recall 差：+100 percentage points，95% CI [100, 100]；
- active FPR 差：−1.04 points，95% CI [−3.125, 0]；
- non-attack FPR 差：−0.35 points，95% CI [−1.04, 0]；
- behavior separation 差：+101.04 points，95% CI [100, 103.125]；
- F1 差：+100 points，95% CI [100, 100]。

預先鎖定的 13 條方法效能成功規則全部 PASS，`method_efficacy_pass=true`。

## 成本結果

若把探針視為持續套用在每次操作上的監控，baseline 平均相對操作延遲增加
21.26%，因此舊的「相對操作延遲 ≤5%」規則仍為 FAIL。

若依預先指定的週期診斷用途，每分鐘執行一次、每次 20 次列舉：最慢一次
scan 為 323.71 ms，小於 1 秒；各負載攤提至 60 秒後的平均新增 wall-time
fraction 均小於 0.1%，因此 periodic diagnostic deployment rule PASS。

上述成本數字來自收集前鎖定的單一 boot development overhead pilot，不是八開機
正式 efficacy batches 直接估計；因此只能支持此受控環境下的部署模型資格，不能
外推為其他硬體／kernel 的成本保證。

## 可支持與不可支持的結論

結果支持：在本研究的 CARAXES-like selective callback short-circuit 威脅模型、
四種負載與 matched controls 下，nesting invariant 比本實驗預先固定的 timing
comparator 更能辨識實際 suppression 行為，並避免把單純 hook 或 filter 計算
誤報為 hiding。

結果不支持：偵測所有 Linux Rootkit、所有檔案隱藏技術、DKOM、不同 hook
位置、在原函式返回後修改 buffer 的攻擊、可停用或欺騙 eBPF 的主動對手，
或把本實驗的 frozen timing 結果概括為所有既有 timing-based 方法的表現。
合法的選擇性 kernel filter 也可能產生相同結構，因此部署語意應是「選擇性
directory-entry suppression 候選」，而非單憑此訊號完成攻擊歸因。
