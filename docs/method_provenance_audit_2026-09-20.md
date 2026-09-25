# KICBA 方法來源與研究狀態稽核（2026-09-20）

## 來源邊界

| 元件 | 來源 | 性質 | 目前判定 |
|---|---|---|---|
| eBPF kernel-function timing、batch distribution、統計 shift detector | Landauer et al., *Trace of the Times* 與公開程式 | 前人方法／起點 | 保留為比較基準 |
| CARAXES、filldir ftrace hook framework | AIT AECID 公開 CARAXES | 前人公開測試 Rootkit | 保留；本研究只限此受控威脅模型 |
| Blind recent-window update | Trace-of-the-Times online experiment | 前人方法 | 作污染基準；不是本文貢獻 |
| Selective update 問題設定 | online poisoning／concept-drift 文獻；Le et al. 的 normal/normal-drift/attack 分流 | 借用問題設定 | 本文需提出 kernel-specific evidence，不能宣稱 selective update 本身為新 |
| 修正後的 CARAXES continue-enumeration variant | 本專題新增 | benchmark correction | 因原分支會截斷 enumeration；必須明載，不冒充上游原碼 |
| `caraxes_sham.c` pass-through hook | 本專題新增 | 人工負控制 | 合理用途是隔離「安裝 hook」與「執行隱藏 branch」；不是公開論文原元件，也不是一般 production benign module |
| first/last `iterate_dir` role aggregation | 本專題新增 | measurement redesign | 用來避免把不同 invocation role 混成同一分布 |
| clean→sham context-stratified security axis | 本專題新增 | 候選 kernel-specific admission evidence | D5 顯示 security branch 的診斷性結果為 hiding 792/800、sham 10/100、unloaded 0/900；仍需獨立確認其泛化 |
| `final alert = operational OR security` | 本專題新增 | D5 鎖定候選融合 | **拒絕作為後續主方法**：它把 generic timing shift 升級成 Rootkit alert，造成 sham FPR 73% |

## 為何 sham 在研究上可以成立

Sham 刪除 CARAXES 的關鍵處置成分（遇到目標名稱時跳過原始 `filldir64`），但保留相同類型的 ftrace hook 與一次 pass-through wrapper。若 unloaded 與 hiding 的 timing 差在 sham 也出現，便表示差異至少部分來自 hook／measurement interaction，而不能全歸因於隱藏行為。這是負控制的用途：揭露非因果、混淆或量測偏差；它不能單獨證明方法正確。

## D1–D5 不是五個可互換的最終資料集

- D1：前人公開資料，只回答重現與 blind-window 污染現象。
- D2：第一版自收同步資料；context aggregation 與 collector overhead 暴露失敗，只能保留為失敗紀錄。
- D3：曾出現缺乏理論依據的多視窗共識設計；不得作論文證據。
- D4：benchmark correction 與方法開發資料；用來修正 enumeration、invocation-role、負控制與低成本 collector，不能作最後確認。
- D5：方法與規則事前凍結後的五開機確認資料；是目前唯一對 D5 方法有效的 confirmatory 結果。結果為 method efficacy FAIL（sham final-alert rule 未通過）且 deployment overhead FAIL。

## 後續唯一允許的研究主線

在任何新資料收集前，必須先把下列內容寫成不可變 protocol：

1. 研究問題仍是「在 timing baseline 需要適應正常漂移時，如何限制攻擊資料進入更新」。
2. generic operational anomaly、kernel-specific security evidence、update eligibility 必須是三個明確 endpoint，不得再把名稱與用途混用。
3. 新融合／狀態機必須由 D5 failure mechanism 與文獻推導，並列出 truth table；不能只為讓 D5 數字變好。
4. D5 只能作 redesign/development evidence。若方法更改，只能再收一次結構相同、全新 boot/seed 的 final confirmation；無論成功或失敗都停止，不再以 D7、D8 追結果。
5. 所有失敗資料、程式 hash、規則與分析輸出原樣保留；不得刪除不理想的正式結果。

目前尚未批准或執行新的確認實驗。
