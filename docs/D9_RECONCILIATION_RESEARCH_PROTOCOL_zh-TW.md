# D9 目錄項跨邊界 reconciliation：開發與正式驗證規約

狀態：**已鎖定**  
日期：2026-09-24

## 一句話方法

對同一次完整 `getdents64` 列舉，在 `filldir64` 已接受的上游項目與
使用者實際收到的下游項目各自建立固定大小 multiset fingerprint；兩者
不同時，再相減 IBLT 以還原少量的「只在上游／只在下游」項目。量測不完整
時輸出 invalid，不把量測錯誤當成隱藏。

本方法辨識的是 **`filldir64` 接受之後、`getdents64` 輸出之前的項目身分
不一致**，不是判斷模組的惡意意圖，也不是涵蓋所有檔案隱藏技術。

## 研究問題

1. 在目錄很大但差異很小時，能否以固定大小摘要偵測不一致，並以與差異量
   而非目錄大小成長的 IBLT 還原差異項目？
2. 相較只比數量，能否抓到「移除一項、換入一項」的等量替換？
3. 分頁、callback buffer-full、背景負載、檔案系統、名稱長度、檔案型態與
   正常目錄變動下，是否維持正確且能辨識量測失效？
4. 與 timing、完整逐項追蹤、syscall-buffer integrity 與磁碟／VFS 跨視圖
   方法相比，準確度、定位能力、成本與適用邊界為何？

## 方法判定

- fingerprint 相同：本次未觀察到此邊界的項目差異；這不是「系統沒有
  rootkit」的證明。
- fingerprint 不同且 IBLT 解碼成功：回報 upstream-only 與
  downstream-only token。
- fingerprint 不同但 IBLT 解碼失敗：回報「差異存在但超出目前還原能力」；
  不猜測項目，也不直接標成惡意。
- callback pairing、名稱讀取、map 更新、列舉完成性或其他量測檢核失敗：
  回報 invalid，不納入陰性或陽性。

Fingerprint 保留 count 與兩個 64-bit 加總；IBLT 使用三個位置與
key/inode/type/check 欄位。seed 每個正式 campaign 隨機產生並寫入證據。
它是機率式摘要，不宣稱零碰撞，也不抵抗能讀取 seed 並主動構造碰撞的核心
攻擊者。

## 容量規則

開發期模擬比較 IBLT cells / 真實 symmetric difference = 1、2、4、8。
目前候選規則為將預期 symmetric difference 的 8 倍向上取成 2 的冪；
正式規則只可依開發資料凍結，不能查看正式結果後再修改。超出容量是必須
保留的壓力情境，正確輸出應是 mismatch + decode failure，而不是錯誤名單。

## 對照方法

### 外部相關方法（主要比較）

| 類別 | 代表 | 能回答的問題 | 主要限制 |
|---|---|---|---|
| eBPF timing | Trace of the Times | 相關核心路徑的時間分布是否偏移 | 間接；易受掛接、正常邏輯、排程與負載影響，不能指出消失項目 |
| syscall buffer integrity | rkchk | `getdents64` 等輸出緩衝區是否遭異常操作 | 偵測面與支援的 hook／核心版本受工具實作限制 |
| 完整 `filldir64` trace | Synacktiv LinkPro 分析所示的 tracing | 核心曾枚舉哪些名稱 | 每項事件成本與資料量隨目錄大小成長；仍須與下游視圖配對 |
| 磁碟／VFS 跨視圖 | Decloaker 類 | 原始檔案系統視圖與 VFS 視圖是否不一致 | 權限高、檔案系統相依，且比較的是另一個邊界 |

### 本文內部消融（不能冒充前人方法）

- D7：CARAXES 類同名巢狀／非巢狀 callback 結構；只適用該包裝形態。
- D8 count：比較此邊界兩側數量；能抓純移除，但抓不到等量替換，也必須
  正確處理 callback 因 buffer-full 返回 false 的分頁語意。
- D9 fingerprint only：只知道不一致，不能定位項目。
- D9 fingerprint + IBLT：本文完整方法。

## 測試面向

正式資料前先完成開發期 boundary suite；其設計與結果分開保存。

| 面向 | 預定值／情境 | 目的 |
|---|---|---|
| 模組狀態 | unloaded、ftrace pass、相同比對不隱藏、filldir suppression、getdents suppression、等量替換、授權政策過濾 | 分離掛接、比對、抑制、替換與意圖 |
| 差異量 | 0、1、4、16、64、256、512，另含超容量 | 小差異還原與失敗語意 |
| 目錄規模 | 0、1、16、512、8,192、65,536 項 | 成本是否主要隨 N 成長；準確度是否受大型目錄影響 |
| buffer／分頁 | 128、256、4,096、65,536 bytes；長名稱另用可容納的最小值 | 驗證多次 `getdents64` 與 buffer-full callback |
| 負載 | baseline、CPU、memory、mixed | 排程與背景活動 |
| 名稱與型態 | ASCII、UTF-8、接近 255-byte、hard link、directory、symlink | token 與解析邊界 |
| 檔案系統／視圖 | ext4、tmpfs、可行時 overlayfs；動態 pseudo-fs 另列 | 避免只對單一檔案系統成立 |
| 正常變動 | 列舉期間 create/delete/rename churn | 正常競爭下的量測與解讀 |
| 併發 | 多 PID 同時列舉 | PID 配對與 map 隔離 |
| 失效注入 | map 容量、callback pairing、截斷列舉／程序失敗 | 必須 fail closed 為 invalid |

核心 factorial 不與所有壓力軸做笛卡兒乘積；另以 one-factor boundary tests
涵蓋極端值，避免既無統計意義又耗費大量資源。所有預定格皆要保留，包括
失敗與不利結果。

## 主要結果與成功條件（正式資料前凍結）

1. suppression / substitution 的 mismatch recall、非差異控制的誤報率，附
   95% Wilson interval。
2. IBLT exact recovery rate、decode failure rate、incorrect-success rate；
   「解碼成功但答案錯」獨立列為嚴重錯誤。
3. 授權政策過濾預期產生結構警報，但分類為 authorized difference；用來
   證明本方法不能自行推論惡意。
4. measurement invalid rate 與每種失效原因；invalid 不得併入 true negative。
5. wall time、CPU、BPF map memory、事件／輸出 bytes，並與完整逐項 trace、
   count 與可復現的外部方法比較。
6. 等量替換案例中 D8 count 預期不觸發；此預期由定義導出，不以觀察結果
   反向設定。

不得保證結果「漂亮」。可保證的是：規約先於正式資料、負面結果保留、方法
與內部消融／外部基線分開、結論只涵蓋實際測到的邊界與環境。

## 校準與正式核心矩陣

時序比較器的校準資料與正式資料分離。校準只包含五個不造成項目差異的
控制狀態（unloaded、兩種 pass、兩種 active），採 4 種背景負載、4 種
`getdents64` buffer、每格 3 repeats、每批 20 次列舉，共 240 批／4,800 次。
每個 `(負載, buffer)` 分層以 15 個控制批次的
`log(median(scan_ns))` 事前固定兩個門檻：(a) `median + 3 × 1.4826 × MAD`；
(b) 全部控制校準值的 `max + 0.01 log-unit` upper envelope。兩者均在正式
資料前凍結，正式報告不得事後擇優只呈現其中一個。它們只是簡單 timing
對照，不代表 Trace of the Times 等所有時序方法。

正式核心矩陣包含九個狀態：上述五個控制、`filldir_hiding`、
`getdents_hiding`、等量名稱替換與明確授權的 policy filter。每次開機包含
9 × 4 負載 × 4 buffer × 1 repeat × 20 次列舉，即 144 批／2,880 次；
共 9 個唯一 boot ID，合計 1,296 批／25,920 次列舉。九次開機以 cyclic
rotation 讓每個狀態各自在九個 episode 位置出現一次；episode 內的負載與
buffer 組合依固定 seed 隨機化。每次開機另產生不同 fingerprint／IBLT seed。

正式資料開始後不得修改 detector、oracle、timing 門檻、狀態定義、排除規則
或成功條件。任何失敗 boot／batch 必須保留；若 integrity audit 失敗，整體
正式驗證標為失敗，不以刪除該資料重算。

### 事前成功條件

1. 9 個唯一 boot ID、1,296 批與 25,920 次交易完整，且 source hash 與 lock
   一致；
2. 四個差異狀態合併的 batch recall ≥ 0.95，五個控制狀態合併 FPR ≤ 0.05；
3. 每一差異狀態 recall ≥ 0.95，每一控制狀態 FPR ≤ 0.05，每 boot 控制 FPR
   ≤ 0.10；
4. 差異交易的 IBLT exact recovery ≥ 0.95，incorrect successful decode = 0；
5. measurement invalid = 0；
6. 等量替換下 D9 相對 D8 count 的 recall 優勢 ≥ 0.90；
7. authorized policy filter 的 alert rate ≥ 0.95，用以實證警報不等於惡意
   判定。

Timing 與外部方法的結果照實報告，不以「D9 必須勝過所有方法」作為通過
條件。外部工具若因核心版本、Rust-for-Linux 或 raw-ext4 等前提無法在同一
VM 公平執行，必須報告為不可直接比較，不得填入推測數值。

## 開發證據與正式證據隔離

- `results/d9_development/`：演算法容量探索、單開機機制與 boundary pilots；
  只用來修正程式與凍結規約。
- `results/d9_formal/`：凍結 source hash、seed 規則、排程與分析後才建立；
  不覆寫、不挑選批次。
- 開發中若發現 oracle 污染、程式錯誤或規約變更，保留原結果並另開 revision，
  不把失敗資料刪除後假裝未發生。

## 主要來源

- Goodrich & Mitzenmacher, *Invertible Bloom Lookup Tables*, 2011:
  https://arxiv.org/abs/1101.2245
- Trace of the Times 論文與公開實作:
  https://arxiv.org/abs/2503.02402
  https://github.com/ait-aecid/rootkit-detection-ebpf-time-trace
- rkchk: https://github.com/thalium/rkchk
- Decloaker: https://github.com/gustavo-iniguez-goya/decloaker
- Synacktiv LinkPro eBPF 分析:
  https://www.synacktiv.com/sites/default/files/2026-04/synacktiv-coriin_2026-analyse_linkpro_ebpf_aws.pdf
