# 第三方方法與來源

本儲存庫未複製下列第三方專案的完整原始碼或執行檔。重現外部比較時，請由原作者儲存庫取得並 checkout 指定版本；本研究自己的轉接與驗證腳本位於 `tools/external_baselines/`。

| 方法 | 原作者來源 | 本研究固定版本 | 本儲存庫狀態 |
|---|---|---|---|
| Trace of the Times | <https://github.com/ait-aecid/rootkit-detection-ebpf-time-trace> | `269d9b0bc6aafb403cba209bb47b8bdb902ba10e` | 不含 upstream 專案；保留比較摘要、manifest 與本研究 helper |
| Decloaker | <https://github.com/gustavo-iniguez-goya/decloaker> | v0.0.9，source commit `5a2ca88e3f715a221720a0330ae65ca845a3032d` | 不含 release archive、binary 或完整 source；保留九開機結果摘要與驗證器 |
| rkchk | <https://github.com/thalium/rkchk> | `a9f4e496e61c65d4787365b883e4b21d74689e49` | 因需作者指定的 Rust-for-Linux 自訂核心，本論文未執行 head-to-head，未收錄其專案 |
| CARAXES | <https://github.com/ait-aecid/caraxes> | 原始 VM checkout commit `899e8be6b5f6c7236bd23b52aa65051de757e0b3`；D9 控制模組的雜湊另由正式鎖記錄 | 未收錄完整 upstream；正式矩陣使用的最小自製控制版本位於 `attack_variants/d7_controls_r2/` |

第三方專案的授權與使用條件以各自 upstream 為準。本研究的比較範圍與限制詳見 `docs/D9_EXTERNAL_METHOD_COMPARISON_PROTOCOL_zh-TW.md` 與 `docs/D9_EXTERNAL_METHOD_COMPARISON_DEVIATIONS_zh-TW.md`。
