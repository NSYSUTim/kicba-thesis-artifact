# D9 與 Decloaker 正式比較結果

## 結論

在本研究的 `filldir64 → getdents64` 列舉隱藏模型下，Decloaker v0.0.9 九次開機共 720 次掃描皆完成，但 180 次真正隱藏均未告警：TP=0、FN=180、FP=0、TN=540，recall=0%、F1=0%、FPR=0%；因沒有任何陽性預測，precision 未定義（N/A）。此結果只適用於本模型，不能外推為 Decloaker 對其他 rootkit 或隱藏方式無效。

從既有 D9 九開機正式資料中，事後依預先存在的實驗因子抽出相同四狀態、baseline、65,536-byte buffer、512 個可見項目與 16 個差異項目的 720 次交易；D9 為 TP=180、FN=0、FP=0、TN=540，recall、precision、F1 皆為 100%，FPR 為 0%。此匹配不改動任何偵測輸出，但兩方法是在不同九次開機分別執行，不能解讀為逐次配對延遲比較。

## 實驗設計

- 環境：單一隔離 Ubuntu VM，Linux `6.8.0-138-generic`，ext4，裝置 `/dev/sda2`，無預設網路路由。
- 工具：Decloaker v0.0.9，官方發行檔 SHA-256 `417f15eeb6e374c43ea12c7037e72711dbb06bd2c4e7d42d2f67ed859add162b`；二進位 SHA-256 `a275fea94173b48bb15bab215965cbf2cce76e12137f27248bb60696864428ca`。
- 重複：9 個不同 boot ID；每次開機測試 `unloaded`、`filldir_pass`、`filldir_active`、`filldir_hiding` 四狀態，各 20 次，共 720 次。
- 真值：僅 `filldir_hiding` 為陽性；fixture 有 512 個可見項目與 16 個在列舉輸出中被隱藏的項目。每個狀態切換後均以可見數驗證處置成功。
- 判定：依 Decloaker `disk ls --compare` 的正式輸出；輸出含 `HIDDEN` 為告警。所有執行 return code 均為 0，沒有 timeout 或處置失敗。

## 為何未告警

Decloaker 的 ext4 `disk ls --compare` 先從 raw ext4 列出每個路徑，再對每個完整路徑執行 `find <path> -maxdepth 0`；只有完整路徑查不到時才輸出 `HIDDEN`。本研究的模組只從父目錄的 `getdents64` 列舉結果移除名稱，並未阻止已知完整路徑的 `stat`／`find` 存取。因此 Decloaker 能在 raw ext4 看見 16 個項目，但完整路徑仍可解析，沒有輸出告警。這是觀測語意與威脅模型不相同，不是以簡化替代品代替 Decloaker。

## 完整性與封存

- 獨立驗證：`tools/external_baselines/decloaker_v0.0.9/validate_formal.py`
- 驗證結果：`results/d9_external_comparison/decloaker/formal_20260925/validation.json`
- D9 匹配子集：`results/d9_external_comparison/decloaker/formal_20260925/matching_d9_subset.json`
- 原始封存：`results/d9_external_comparison/decloaker/formal_20260925/decloaker_formal_20260925.tar`
- 封存 SHA-256：`8ad7db868e81edbb111152bfa0fcb1c0dfa5f93d1955c44f70f430fb5b435389`
- 第一次啟動的中繼資料查詢失敗整批排除並完整重跑，理由與修正記於 `docs/D9_EXTERNAL_METHOD_COMPARISON_DEVIATIONS_zh-TW.md`。
