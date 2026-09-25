# D9 外部方法比較擴充實驗偏差紀錄

## 2026-09-24：正式收集器第一次啟動前驗證失敗

- 範圍：Trace of the Times 共同矩陣。
- 現象：第一個 `default/normal` 批次已完成，但收集器在驗證事件 JSON 時讀取不存在的 `file_name_length` 欄位，觸發 `KeyError` 並停止。
- 原因：原作者 `Experiment` 建構子接受 `file_name_length`，但沒有把它存入輸出物件；外加的中繼資料驗證誤認為輸出一定含該欄位。
- 處理：該批移至 `excluded_preformal_runner_failure_20260924`，不納入訓練、測試或正式樣本數；收集器刪除這項欄位檢查，重新計算雜湊並更新鎖定檔，再從空的 `events` 目錄開始。
- 對演算法的影響：未改動原作者的探針、事件格式、異常偵測、門檻搜尋、資料切分或任何 D9 邏輯。

## 2026-09-24：D9 head-to-head 排除 `ls-basic`

- 發現時點：Trace 正式資料收集中、D9 外部矩陣尚未收集前，且尚未查看任何 Trace 分類結果。
- 原因：原作者的 `ls-basic.c` 呼叫 syscall 217（舊式 `getdents`），對應 `filldir`；本研究問題與目前 D9 實作明確是 `filldir64 → getdents64`。把新寫的 legacy-filldir 版本稱為既有 D9 會改變方法範圍。
- 處理：Trace 仍依原規約完整收集與報告五種情境；D9 只在四個 `getdents64` 相容情境作直接比較。`ls-basic` 結果列為 Trace 的復現／泛化資料，不列入「D9 優於或劣於 Trace」的共同矩陣。
- 其他控制：四個共同情境維持 150 正常批次、100 隱藏批次、每批 100 次列舉；fixture 規則、攻擊模組、負載與標籤相同。

## 2026-09-24：排除與主機核心編譯重疊的時序批次

- 發現時點：Trace 正式資料仍在收集、尚未執行 `evaluate.py`，也尚未查看任何分類結果。
- 現象：在同一實體主機的 WSL 編譯 rkchk 自訂核心期間，研究 VM 的 `file_count/normal` 批次時間由約 9–11 秒升至 16–19 秒；停止編譯後恢復為約 9–10 秒。雖然 WSL 與 VM 是不同客體，仍共用實體 CPU，因此不能視為互不干擾。
- 保守處理：不以觀察到的延遲挑選個別批次，而是將當時已收集的全部 122 個 `file_count/normal` 批次（index 0–121）整組排除並從 index 0 重收。`default` 250 批在核心編譯開始前已完成，因此保留。
- 證據保存：事件檔並未刪除；原始 log、122 筆排除紀錄、逐檔 SHA-256 與理由保存在 VM 的 `excluded_host_cpu_contention_20260924_file_count_normal_r2`。使用的排除工具 SHA-256 為 `6671dcf4194edfe7429ae128583ac01bf1f96f07ace47ddfdc25b42bd4be894c`。
- 執行註記：第一次以一般帳號執行時，在第一個檔案即因 root 所有權被拒，沒有搬動事件檔；該失敗目錄保留。第二次以 `sudo -n` 執行成功。
- 後續隔離：Trace 時序矩陣完成前，不再同時執行核心編譯、D9、Decloaker 或其他高負載工作。

## 2026-09-25：Decloaker 第一次正式啟動於環境紀錄階段失敗

- 範圍：Decloaker v0.0.9 九開機比較的第 1 次開機。
- 現象：四種狀態各 20 次掃描已執行，但收集器最後以 `findmnt -no FSTYPE /home` 記錄檔案系統時失敗；本 VM 的 `/home` 並非獨立掛載點，故未寫出 `campaign.json.gz`，沒有可納入分析的測量紀錄。
- 處理：保留空輸出目錄與 traceback log 並整批標記為排除；在任何可分析結果產生前，將查詢改為 `findmnt -T /home -n -o FSTYPE`，以取得包含 `/home` 的實際掛載檔案系統。更新收集器雜湊後，第 1 次開機從四種狀態各 20 次掃描完整重跑。
- 對演算法的影響：只修正環境中繼資料的取得方式；未改動 Decloaker 二進位、偵測輸出、攻擊模組、狀態順序、樣本數、標籤或判定規則。

## 2026-09-25：Trace 四情境評估第一次啟動誤讀 manifest

- 範圍：排除 legacy `ls_basic` 後的 Trace of the Times 四情境 head-to-head 評估。
- 現象：符號連結檢視內另放了 `four_scenario_manifest.json`；原作者 `evaluate.py` 會把指定目錄的所有檔案當成 gzip 事件檔，故在任何重複 run 開始前以 `BadGzipFile` 中止。
- 處理：完整保留 stdout 與 resource log；將 manifest 移到事件目錄外，修正檢視建立腳本，並從新的空評估目錄重跑。
- 對演算法的影響：沒有修改原作者 `evaluate.py`、事件資料、四情境選取、seed、切分、門檻搜尋或評估參數。

## 2026-09-25：Decloaker 結果後增加 D9 匹配子集分析

- 性質：次要、事後指定的比較分析，不取代事前凍結的 D9 主矩陣或 Decloaker 矩陣。
- 作法：從既有且未修改的 D9 九開機正式資料抽出四個相同狀態、`baseline`、65,536-byte buffer、512 個可見項目與 16 個差異項目，共 720 次交易；未重新執行或調整偵測器。
- 理由：讓 D9 與 Decloaker 的樣本數、fixture、狀態與負載更接近，避免以完整 D9 多負載矩陣直接對照 Decloaker 單一負載矩陣。
- 限制：兩方法使用不同的九次 boot，不能作逐次配對延遲比較；本文只比較偵測率，並標明此子集為事後匹配分析。
