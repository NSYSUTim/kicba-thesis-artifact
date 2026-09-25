# Trace of the Times 完整復現與 D9 四情境比較結果

## 結論

Trace of the Times 已依原作者公開的 `evaluate.py` 完整執行 `offline shift`，並分別使用 `fun` 與 `seq` grouping；不是以簡化 timing 門檻代替。四情境 head-to-head 只排除使用 legacy `getdents/filldir` 的 `ls_basic`，因其不屬於本研究的 `filldir64 → getdents64` 範圍。

| 評估矩陣 | Recall | FPR | Precision | F1 | Accuracy |
|---|---:|---:|---:|---:|---:|
| 四情境 fun（100 runs） | 93.89% | 15.20% | 86.20% | 89.83% | 89.35% |
| 四情境 seq（100 runs） | 98.00% | 27.18% | 78.43% | 87.08% | 85.41% |
| 五情境 fun（100 runs） | 90.81% | 18.89% | 83.10% | 86.60% | 85.96% |
| 五情境 seq（100 runs） | 96.22% | 30.20% | 76.22% | 85.01% | 83.01% |

同一四情境矩陣下，D9 的 1,000 個批次為 TP=400、FN=0、FP=0、TN=600，即 recall、precision、F1 皆為 100%，FPR 為 0%。這項 D9 外部矩陣與 Trace 收集位於同一 VM boot；但只有一個 boot，泛化強度低於 D9 九開機主矩陣。

## 重要限制

原作者的 offline evaluator 會在每個 run 的測試標籤上選取 F1 最大的門檻，因此上述 Trace 指標是偏樂觀的復現估計。D9 與 Trace 量測的證據不同：D9 直接比較上下游目錄項身分，Trace 由函式時間分布推測異常；結果只支持共同威脅模型內的偵測率比較，不能解讀為 D9 全面取代 timing 方法。

## 正式矩陣與參數

- 四情境：`default`、`file_count`、`system_load`、`filename_length`。
- 每情境：150 個正常批次、100 個隱藏批次；每批 100 次列舉。
- 評估：`seed=42`、`train_ratio=0.333`、`quantiles=9`、`repeat=100`、`mode=offline`、`approach=shift`。
- 驗證：兩種 grouping 均有 100 個完整 run、四情境及全部必要輸出；SHA-256 記錄於驗證檔。

## 證據位置

- 四情境 fun/seq：`results/d9_external_comparison/trace_of_times/formal_20260924/evaluation_four_fun/` 與 `evaluation_four_seq/`
- 五情境完整復現：同目錄下 `evaluation_fun/` 與 `evaluation_seq/`
- 獨立驗證：`results/d9_external_comparison/trace_of_times/formal_20260924/four_scenario_validation.json`
- D9 四情境驗證：`results/d9_external_comparison/d9/formal_20260925/d9_external_formal_20260925/validation.json`
- 排除與重跑理由：`docs/D9_EXTERNAL_METHOD_COMPARISON_DEVIATIONS_zh-TW.md`
