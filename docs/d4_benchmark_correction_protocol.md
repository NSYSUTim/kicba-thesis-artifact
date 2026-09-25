# D4 Benchmark Correction 與後續確認規約草案

狀態：依 D2/D3 invocation-composition audit 建立的開發規約。D4 用於修正與選擇方法，
不得同時當最終 confirmation；最終鎖定方法須另收 D5。

## 1. 為什麼不能直接調 window

原始資料中 normal 與 CARAXES 的 `iterate_dir` 呼叫角色不相同：normal 每個 `ls` 有
productive call 與 EOF call，CARAXES 因提早停止只有一次。任何把全部呼叫混成 quantile
vector 的模型，都可能只是在辨認 mixture proportion。window size 只會改變模型記住這個
mixture 的速度，不能消除 confound。

因此 D4 的第一個研究單位不是 detector，而是「一次完整的 directory-listing
transaction」。

## 2. Qualification gates

候選攻擊／受控變體必須依序通過，未通過就不得進 timing-overhead 主分析。

### Gate Q0：輸出語意

- normal 輸出必須精確等於預期集合；
- attack 輸出必須精確等於預期集合減去指定 hidden entry；
- 不接受「hidden 不見了，但其他可見檔也不見」；
- 每批保存 expected、observed、missing-visible、unexpected 四個摘要與 hash。

原始 CARAXES-filldir-stop 明確無法通過 Q0，保留為 control-flow corruption case，不能作
「只增加隱藏邏輯成本」的 timing case。

### Gate Q1：transaction/call-role 對齊

- 以 PID/TGID 將 target invocations 歸到每次 `ls`；
- 記錄第 1 次 productive、第 2 次 EOF 與其他 ordinal；
- normal/attack 每種角色的 presence rate 必須相同，否則分開建模，不得混成一個分布；
- invocation count 可當獨立 control-flow 結果，但不得暗中進 timing classifier。

### Gate Q2：探針位於攻擊成本之內

先畫出 hook 與 probe 的呼叫關係。只有 probe interval 包含受控攻擊邏輯，才能把 shift
解釋為額外 execution cost。若攻擊在 `iterate_dir` 返回後才處理 user buffer，
`iterate_dir` timing 沒看到攻擊成本是預期結果，不得因結果不好任意換說法。

2026-09-19 補充：修正後的 `filldir64` hook 位於 `iterate_dir` 首次 productive call
內，故該 interval 能量到整體列舉行為變化；但跳過一筆 user-buffer 複製同時也減少工作量，
所以即使 timing shift 顯著，也只能稱為「攻擊造成的整體執行時間差」，不能單憑此
宣稱「額外 Rootkit 程式碼的純成本」。`filldir64` 命中數與逐次角色需另報告，且不能
暗中用檔案數已知的先驗條件當部署時可用的偵測特徵。

### Gate Q3：觀察者成本

分別量：no probe、單一 target timing、timing + scheduler、完整 context。報告 wall time、
process CPU、events/iteration、lost events。任何主要配置都必須先預定可接受 overhead；
超標就只能是 instrumentation study，不能宣稱可部署。

目前 D4 資格蒐集使用 `iterate_dir` + `filldir64` 以及原 BPF 程式的排程/IRQ tracepoints，
用途是查清量測機制，並非已達低成本配置。原始 D4 收集器的大目錄輸出曾因 pipe 容量
造成 userspace deadlock；失敗的 `r1` 保留，修正版以暫存檔接收 `ls` 輸出並加逾時。

三狀態 sham 對照已顯示 pass-through ftrace hook 就能產生多數 `iterate_dir` timing shift：
原完整探針下 `first_raw_median` sham/unloaded 中位約 1.84，真正藏檔/sham 僅約 1.04。
這屬 probe-hook interaction 的強烈警訊。方法候選必須在不探測 `filldir64` 的
`iterate_dir`-only minimal BPF 配置下重做三狀態對照，並把 sham 當 normal negative
control。若對 sham 的誤報仍高，不得把 unloaded vs hiding 的分離稱為 Rootkit 偵測。

## 3. D4 development factors

### 3.1 Directory/workload factors

- visible-entry cardinality：至少 small、medium、large 三級；
- filename length：短與長；
- hidden entry 在實際 filesystem enumeration 中的位置；
- baseline、CPU、memory、mixed 背景負載；
- 每次 boot 重新建立目錄並保存實際 normal enumeration order。

這些因素用來測試 detector 是否只記住某一個兩檔目錄，而不是用來挑最好看的 cell。

### 3.2 Measurement factors

- target function/probe position；
- invocation role；
- raw wall、on-CPU、IRQ-adjusted、accounted execution；
- central/tail/lower quantile，但只有在角色對齊後才可比較；
- event sampling/aggregation 方式及 overhead。

每個候選先比較「同 boot、同 workload、同 role」的 normal/attack shift，再比較 normal
跨 workload/boot shift。攻擊效果若小於正常狀態變化，不適合當 immutable security anchor。

### 3.3 Model factors

順序固定如下：

1. static role-aware baseline；
2. blind single-window update；
3. safe single-window update；
4. bounded-influence 或 quarantine update；
5. context-conditioned decision。

每一步只有在相較前一步解決一個已觀察、可重現的 failure mode 時才保留。不得先做多模型
consensus 再事後找理由。

### 3.4 Window sensitivity

W20、W50、W100 一次只啟用一個，使用完全相同 feature、threshold、guard 與資料順序。
比較：

- workload 轉換後多少批恢復；
- steady-state FPR；
- persistent-attack recall；
- attack update acceptance 與最大 window attack fraction；
- per-boot variance。

window 不是方法本體。若三者都不好，回到 feature/gate，不新增任意融合。

## 4. D4 後的候選方法方向

最合理的候選不是目前的高維全函式 q10–q90 Mahalanobis，而是：

```text
一次 directory-listing transaction
        ↓
依 invocation role 分流
        ↓
每個 role 的低維 timing score
        ↓
immutable、normal-only admission guard
        ↓
單一 adaptive reference（一次只用一個 W）
```

若 batch context 對目標 timing 的 leave-one-boot-out R² 不穩定，就不強行使用 linear
conditional residual。可以改用 context-stratified reference、nearest-context normal
reference，或承認目前 context 不足並新增可解釋量；每個新增量都需 overhead ablation。

## 5. D5 confirmatory 規則

D4 結束後必須凍結：rootkit/variant hashes、collector hash、probe、role definition、features、
threshold、window、guard、success rules。D5 使用全新 boots、未參與 D4 的目錄 seeds 與至少
一個未見 workload 強度。

Primary outcomes：

- per-boot Rootkit recall；
- normal FPR（整體與 workload-transition/steady-state 分開）；
- unknown rate；
- attack/benign update acceptance；
- 最大 window 污染；
- safe-update vs no-update 的 paired FPR 差；
- collector/detector overhead。

統計單位是 boot，不是 invocation 或 batch。報告 per-boot 數字與 boot-cluster bootstrap CI。
不得在 D5 後改 threshold/window/features 再稱同一份 D5 為確認結果。

## 6. 可能的論文貢獻

依結果有兩條誠實路線：

1. **方法論文**：role-aligned、contamination-resistant adaptation 在 D5 同時維持 recall、
   降低 FPR、避免污染且成本可接受。
2. **測量／benchmark 論文**：證明 all-call timing distribution 會受 invocation composition
   與 rootkit control-flow semantics 混淆，提出 qualification gates 與 role-aligned protocol，
   並量化既有結論在修正前後的差異。

第二條不是失敗版本；前提是結果跨 boot、跨 directory factors 重現，且不誇稱涵蓋所有
Rootkit。

## 7. D4 最終候選與 D5 鎖定（2026-09-19）

D4 發現單一 pooled timing gate 會被 CPU 負載上界拉高。最終候選不使用實驗 condition
標籤，而以每批 `/proc/stat` 的 CPU busy 將 clean/sham calibration 分成低／高 context，
再於 log(`first_raw_median`, `first_div_last_raw_median`) 空間建立 clean centroid 指向
pass-through sham centroid 的單位軸。超過該層所有 benign projection 加 0.01 log-unit 才
觸發 immutable security gate；operational median 則使用單一 W20 predict-then-update。

D4-r6 長序列中，guarded W20 相較 fixed 將 FPR 由 71.6% 降至 10.4%，recall 同為
98.89%；相較 blind W20 的 180/180 attack updates，guarded 接受 9/180，並接受
249/250 normal updates。這些數字只用於方法選擇。D5-r1 已凍結於
`results/d5_formal/analysis_lock.json`，以五個全新 boot 與未見 memory/mixed workload 作
唯一 confirmatory analysis；結果不得回頭修改 D5 方法或 success rules。
