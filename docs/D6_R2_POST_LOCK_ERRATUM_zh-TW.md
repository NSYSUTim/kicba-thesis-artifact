# D6-r2 分析前稽核勘誤

## 狀態與範圍

D6-r2 五次開機資料收集完成後、任何方法效能分析執行前，原先鎖定的
`scripts/audit_d6_r2.py` 專用稽核器回報 FAIL。原始 FAIL 報告永久保留於
`results/d6_r2_formal/audit_r1/audit.json`。

原因是資料收集器按設計在正式目錄 `boot_NN` 旁建立工作目錄
`boot_NN_fixture`，但鎖定稽核器與分析器以 `startswith("boot_")` 選取
正式目錄，因而把五個 fixture 工作目錄誤認為五次額外開機。排序後的
fixture 也使後續正式 boot 的 sequence 與 episode-order 檢查錯位。

## 勘誤處理

不修改下列任何已鎖定項目：

- 原始資料與 manifest；
- 特徵、門檻、W50、分類、融合及更新規則；
- 指標分母與成功標準；
- 鎖定的稽核器與唯一一次正式分析器。

新增 `scripts/prepare_d6_r2_formal_view.py`，只將預先指定的
`boot_01` 至 `boot_05` 複製到新的 formal-view 目錄。程式逐檔比較來源與
formal view 的相對路徑、大小及 SHA-256，並輸出 provenance。五個
`boot_NN_fixture` 只包含被測目錄內容，不包含正式 batch 或 manifest，故不
屬於任何一次開機的分析單位。

修正後的執行順序為：

1. 永久保留原始 raw data、原始 generic audit 與原始專用 audit FAIL；
2. 建立 byte-identical formal boot view 與 provenance；
3. 對 formal view 執行原封不動的鎖定專用稽核器；
4. 僅在修正版呼叫的稽核 PASS 時，對同一 formal view 執行原封不動的
   鎖定正式分析器一次；
5. 不因結果調整任何方法、門檻或成功規則。

此勘誤只修正輸入目錄的結構歧義，並於查看 recall、FPR、F1 等效能數字
以前完成。
