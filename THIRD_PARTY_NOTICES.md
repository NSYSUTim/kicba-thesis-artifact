# 第三方方法與來源

本儲存庫未複製下列第三方專案的完整原始碼或執行檔。重現外部比較時，請由原作者儲存庫取得並 checkout 指定版本；本研究自己的轉接與驗證腳本位於 `tools/external_baselines/`。

2026-10-24 另公開兩輪補充研究。下表的四個專案仍只保留原先限定內容；新增 xcellerator 的部分範例來源及授權列於後段，並非第三方專案整包匯入。

| 方法 | 原作者來源 | 本研究固定版本 | 本儲存庫狀態 |
|---|---|---|---|
| Trace of the Times | <https://github.com/ait-aecid/rootkit-detection-ebpf-time-trace> | `269d9b0bc6aafb403cba209bb47b8bdb902ba10e` | 不含 upstream 專案；保留比較摘要、manifest 與本研究 helper |
| Decloaker | <https://github.com/gustavo-iniguez-goya/decloaker> | v0.0.9，source commit `5a2ca88e3f715a221720a0330ae65ca845a3032d` | 不含 release archive、binary 或完整 source；保留九開機結果摘要與驗證器 |
| rkchk | <https://github.com/thalium/rkchk> | `a9f4e496e61c65d4787365b883e4b21d74689e49` | 因需作者指定的 Rust-for-Linux 自訂核心，本論文未執行 head-to-head，未收錄其專案 |
| CARAXES | <https://github.com/ait-aecid/caraxes> | 原始 VM checkout commit `899e8be6b5f6c7236bd23b52aa65051de757e0b3`；受控模組的雜湊另由正式鎖記錄 | 未收錄完整 upstream；filldir 控制參照其掛接模式縮減實作，位於 `attack_variants/d7_controls_r2/`；getdents 控制與等量替換由本研究自行撰寫 |

第三方專案的授權與使用條件以各自 upstream 為準。本研究的比較範圍與限制詳見[比較規約](docs/D9_EXTERNAL_METHOD_COMPARISON_PROTOCOL_zh-TW.md)與[偏差紀錄](docs/D9_EXTERNAL_METHOD_COMPARISON_DEVIATIONS_zh-TW.md)。

## 比較結果的解讀

- Trace of the Times 與本方法在同一 VM 環境分開收集，不能確認同一次開機；目前只有一次四情境受控比較。逐事件資料未收錄，完整重算需自行收集。
- Decloaker 的受測指令為 v0.0.9 的 `disk ls --compare`。依本研究檢視，它檢查原始磁碟列出的完整路徑能否解析；受測隱藏只改變父目錄列舉，因此未警報反映觀測目標差異，不代表其他功能無效。
- 論文的逐項追蹤比較器由本研究自行實作，不是 Synacktiv 示範或工具的復現。其資料量是欄位大小加總的邏輯資料量，不是實測傳輸流量。
- rkchk 尚未在所需核心重現，不列未量得的成效。

## 補充研究的目錄過濾來源

第二輪採 [xcellerator/linux_kernel_hacking](https://github.com/xcellerator/linux_kernel_hacking) 提交 `15304817e912a526ce57336011a1cc71aea953b2` 的 `3_RootkitTechniques/3.4_hiding_directories`。收錄原始 Makefile、README、rootkit.c、ftrace_helper.h 及 LICENSE，並保留移植版與 compatibility.patch。

原作者的過濾函式及 boogaloo 前綴保留；更換相容 ftrace helper、HOOK 巨集與模組名稱。helper 與原研究共用，因此只提供另一作者過濾實作下的證據，不是完全獨立的掛接家族。各檔雜湊、原始 URL 與授權見 [來源清單](phase2/third_party/xcellerator/PROVENANCE.json)、[移植說明](phase2/third_party/xcellerator/PORTING_zh-TW.md)及[LICENSE](phase2/third_party/xcellerator/upstream/LICENSE)。

新來源沒有改變原 Trace of the Times／Decloaker 的成效數字或比較規約。本輪未新增 rkchk 實驗，也不承諾為增加工具數而必然重跑它。
