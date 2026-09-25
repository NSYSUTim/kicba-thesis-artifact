# D6-r2 與 D7-r1 重現驗證記錄

驗證日期：2026-09-21

D6-r2 R2 分析包曾在封裝相對路徑上實際執行完整重現流程：

1. D6-r2 專用單元測試：7/7 PASS。
2. Generic raw audit：PASS；2,300 batches、5 boots、2,300 exact-output pass、
   lost events 0、role-composition match。
3. D6-r2 integrity/hash audit：PASS；14 個 lock 所列本機檔案雜湊均相符。
4. Frozen analysis + CSV-only output erratum：完成。
5. 重現檔與正式檔逐位元 SHA-256 相同：

| 檔案 | SHA-256 | 比對 |
|---|---|---|
| `report.json` | `5644d450602853d1fc78f85415471e52baac6ea633cd35b5ae9432fb8772c80d` | identical |
| `overall_metrics.csv` | `3cc6807d670987a65b826e2c45aabfa48418aa46f864952f859576ce235b472e` | identical |
| `per_boot_metrics.csv` | `c0334aa5cd752572900ecbaf2c006d47c9515f389f095aab2f8d7d6c696afaa3` | identical |
| `predictions.csv` | `f771778e614f7617d11bcfe66cede120a943432ad3dbbc8b80dc9de6fb95f71c` | identical |

## D7-r1 本次重現

2026-09-21 另由原 `results/d7_formal/raw_r1/` 實際執行完整流程：

1. Canonical-view preparation：PASS；只納入 `boot_01` 至 `boot_08`，排除八個
   `boot_XX_fixture`，逐檔 inventory 共 392 files。
2. 新產生的 `canonical_manifest.json` 與正式 manifest 逐位元相同。
3. D7 locked audit：PASS；8 unique boots、384 batches，四狀態各 96 batches。
4. D7 locked analysis：完成；重現 `report.json` 與 `predictions.json` 和正式檔
   逐位元相同。

| 檔案 | SHA-256 | 比對 |
|---|---|---|
| `canonical_view_manifest.json` | `edb28062d2e88d81c133cc110c413234a33fb16adafb281b317a6824c72aa933` | identical |
| `report.json` | `b55c4fc0d4e20592979c626e4c7ebe8cffebbf60bc0a8670b1ab02b36a898f62` | identical |
| `predictions.json` | `bb68348b9adf7d2c65cf75dd0d56d3b501a5f2249c57a194e60005f7c6e450b3` | identical |

D6-r2 段是 frozen timing／online-update 分析的歷史重現；D7-r1 段是本次結構型
正式分析的實際重現。每次重建 AI 審查包會另外重新計算 `FILE_SHA256.csv` 並
比對 canonical papers，但不會假裝每次打包都重新執行 raw analysis。
