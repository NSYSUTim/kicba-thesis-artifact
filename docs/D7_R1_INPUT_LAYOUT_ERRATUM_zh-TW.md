# D7-r1 正式分析輸入版面修正紀錄

## 問題

D7 收集器將每次開機的正式輸出存於 `boot_XX`，並將被列舉的測試目錄存於
同層的 `boot_XX_fixture`。收集完成後，預先鎖定的稽核器與分析器使用
`startswith("boot_")` 選擇正式開機目錄，因此把八個 fixture 目錄誤認為
另外八次開機。首次稽核依規定保留為 FAIL，且未執行成效分析。

## 修正邊界

本修正不修改原始資料、原稽核器、原分析器、偵測特徵、決策規則、frozen
timing model、指標、門檻或成功條件。新增的準備程式只建立一個正式分析
輸入視圖，其中包含精確符合 `boot_[0-9]{2}` 的 `boot_01` 至 `boot_08`；
`boot_XX_fixture` 是 workload 測試檔案，不是量測紀錄，因此不納入輸入視圖。

準備程式會逐檔比較來源與副本的 SHA-256 inventory；任何檔案缺漏、內容改變、
非預期 boot-like 目錄或既有輸出都會使程序失敗。原始 `raw_r1` 與第一次
`audit_r1` 均不得刪除或覆寫。

## 修正後分析順序

1. 執行新增的 canonical-view 回歸測試。
2. 在未執行 D7 成效分析前，建立 amendment lock，記錄原 lock、原始 state、
   首次 FAIL audit、準備程式、測試與本文件雜湊。
3. 建立 byte-identical canonical view 與完整 inventory manifest。
4. 以原先鎖定且未修改的 audit 程式稽核 canonical view。
5. 只有修正後 audit PASS，才以原先鎖定且未修改的 analysis 程式執行一次
   正式分析。

此修正只處理輸入目錄選取錯誤，不提供依正式結果調整方法的機會。
