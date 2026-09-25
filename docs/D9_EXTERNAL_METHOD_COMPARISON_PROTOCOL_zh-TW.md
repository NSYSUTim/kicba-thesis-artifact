# D9 外部方法比較擴充實驗規約

狀態：在新增正式資料前凍結  
目的：補足 D9 與可執行前人方法的同情境量化比較；不改寫既有九開機確認性結果。

## 1. 比較原則

1. 準確率比較須使用相同攻擊語意、資料與標籤；版本差異另列於實驗環境。
2. 方法若必須使用不同核心，D9 也要在該核心重跑；跨核心數字只列為分環境結果，不直接歸因於方法。
3. 完整公開實作優先；必要的介接改動只限於載入共同攻擊模組、輸入輸出轉接，不改偵測演算法。
4. 所有門檻、資料切分、排除條件與主要指標在正式資料前固定。
5. 既有 D9 九開機結果維持原樣；本規約產生的是外部方法比較擴充證據。

## 2. 納入方法與可比範圍

| 方法 | 執行形式 | 共同可比範圍 | 結論限制 |
|---|---|---|---|
| D9 fingerprint + IBLT | 本研究完整實作 | filldir/getdents 隱藏與替換 | 主要方法 |
| Trace of the Times | 原作者五函式追蹤與 `evaluate.py` shift 法 | filldir 隱藏 | 不外推至其未支援的 getdents 後處理 |
| Decloaker v0.0.9 | 作者官方 amd64 release，ext4 raw-disk compare | ext4 上的檔案隱藏 | tmpfs、overlayfs 不列入 raw-disk 準確率比較 |
| rkchk | 原作者模組與指定 Rust-for-Linux 核心 | getdents buffer tampering／rootkit 行為 | 必須在自訂核心中同時重跑 D9 才作比較 |
| D8 count-only | 本研究已凍結基線 | 數量改變 | 無法處理等量替換是設計限制 |
| exact per-entry trace | 本研究完整逐項基線 | 精確差異與成本 | 不是外部 detector，只比較成本與輸出量 |

## 3. 第一階段：Trace of the Times 完整共同矩陣

### 3.1 情境與樣本數

沿用原作者公開腳本的五種情境：

- `default`：固定檔案數與一般負載。
- `file_count`：可見與隱藏檔案數各自於 10–100 間抽樣。
- `system_load`：`stress-ng --cpu 10`。
- `ls_basic`：使用作者提供的 `ls-basic`。
- `filename_length`：檔名長度於 20–60 間抽樣。

每個情境收集 150 個正常批次與 100 個隱藏批次；每批執行 100 次列舉。正常資料的 1/3 作訓練，其餘正常資料與全部隱藏資料作測試。固定亂數種子 42、9 個 quantiles，分別執行 `fun` 與 `seq` grouping，並報告原作者主要的 shift 方法。

### 3.2 共同攻擊與標籤

- 正類：同一 filldir 隱藏模組實際移除名稱含 `caraxes` 的目錄項。
- 負類：未載入模組。
- 每批須驗證處置成功；隱藏批次若仍看得到目標，或正常批次缺項，該批標記為無效而不補成有利結果。

### 3.3 D9 對照

D9 使用其中四個 `getdents64` 相容情境（`default`、`file_count`、`system_load`、`filename_length`）、相同批次數、相同每批列舉次數與相同正負標籤另行收集。作者的 `ls-basic` 直接呼叫舊式 `getdents`／`filldir`，不在目前 D9 的 `filldir64 → getdents64` 研究範圍，因此 Trace 仍完整報告該情境，但不把它放進 D9 head-to-head 數字。

為避免 D9 探針改變 timing 分布，兩方法不在同一次列舉同時插樁。D9 使用既有 raw `getdents64` probe（buffer 65,536 bytes），而非解析 `ls` 已經過濾的文字輸出；fixture 生成規則、攻擊模組、CPU 負載、批次數、每批列舉次數與標籤一致。D9 的 batch-level 判定為該批 100 次列舉中至少一次 fingerprint 不一致；同時另報 per-listing 結果，避免只看彙整後數字。

## 4. 第二階段：Decloaker ext4 共同矩陣

- 使用作者官方 `v0.0.9` Linux amd64 release。
- release archive SHA-256：`417f15eeb6e374c43ea12c7037e72711dbb06bd2c4e7d42d2f67ed859add162b`。
- 只測 ext4 fixture，執行官方 `disk ls --dev=/dev/sda2 --compare PATH`。
- 九次獨立開機；每次包含未載入、pass、active、hiding 四狀態，各 20 次掃描。
- 正類只有 `hiding`；其他三狀態為負類。記錄 TP、FP、TN、FN、recall、precision、F1、FPR、掃描時間及輸出量。

## 5. 第三階段：rkchk 自訂核心矩陣

此階段須先建立原作者指定的 `rkchk-linux-next` Rust-for-Linux 核心與使用者程式。建立成功後，在該核心執行：

- rkchk 載入前／後兩種順序；
- getdents hiding 與 substitution；
- 對應 unloaded、pass、active 負類；
- D9 在同一核心、相同狀態與相同 fixture 重跑。

若原始碼無法在作者指定版本建置，須保存完整編譯錯誤、commit、toolchain 與 kernel config；不得以自行簡化版本冒充 rkchk。

## 6. 主要指標與宣稱規則

主要指標：batch-level recall、precision、F1、FPR，以及 95% Wilson 信賴區間。次要指標：每次掃描延遲、批次處理時間、事件或輸出量。

- 只有同一共同矩陣內才寫「D9 高於／低於某方法」。
- 僅成功跑原作者公開資料或不同攻擊時，寫「復現成功」，不寫成 head-to-head 優劣。
- 方法適用範圍不同時，分開報告，不把不支援視為演算法錯誤；但共同威脅模型內的漏報仍計為 FN。
