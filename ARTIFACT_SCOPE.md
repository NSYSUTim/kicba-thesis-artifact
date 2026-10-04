# D9 artifact 收錄範圍

## 已收錄

- 指定的 D9 繁體中文會議論文。
- D9 fingerprint/IBLT 核心實作、單元測試、eBPF 收集器與列舉 probe。
- 正式實驗使用的三組自製控制模組：filldir 控制、getdents 控制與等基數替換。
- 九開機 confirmatory matrix 的壓縮資料、鎖定檔、timing model 與正式分析輸出。
- 論文實際引用的 boundary、IBLT capacity、robustness、filesystem/namespace 與 overhead 結果。
- D9 外部比較的自製資料；Trace of the Times 與 Decloaker 僅保留論文採用的摘要、manifest、驗證紀錄及本研究撰寫的轉接/驗證腳本。
- D9 實驗 VM 的建置紀錄、宿主狀態摘要、客體發行版輸出、相關 apt 事件摘要、Kbuild 命令及環境追溯說明。

## 刻意排除

- D1–D8 的論文、資料、圖表、程式與成品。
- D9 的 smoke、quick、早期 pilot、重複修訂與文件產生中間檔。
- `_docx_work`、rendered pages、暫存目錄、cache、編譯產物與 VM/SSH 憑證。
- 重複封存用 `.tar`、Trace of the Times 約 400 MB 的逐事件副本，以及可由摘要/manifest 驗證但論文不需直接散布的衍生表格。
- Trace of the Times、Decloaker、rkchk 的完整 upstream source、release archive 或 binary；取得方式與固定版本改以 `THIRD_PARTY_NOTICES.md` 說明。

這個範圍的目的，是讓書面論文所需的程式與證據可查核，同時避免把其他研究方向、暫存物或第三方完整專案混入提交版本。
