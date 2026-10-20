# 跨層目錄項一致性檢查

本儲存庫對應論文〈跨層目錄項一致性檢查：以 eBPF 指紋與 IBLT 偵測 filldir64 與 getdents64 間的身分差異〉，保存原始碼、受控實驗模組、資料與重現工具。

本方法比較同一次完整目錄列舉中，核心端 `filldir64` 已接受的目錄項，與使用者端從全部 `getdents64` 分頁收到的目錄項。兩端各自建立固定大小的多重集合指紋與 IBLT：指紋判斷是否有差異，IBLT 在容量足夠時還原差異項目的識別值、inode 與型態。

目前結果支持單一虛擬機、單一核心版本、ext4 與靜態目錄下的量測流程正確性。警報表示這段觀測範圍內的身分不一致；授權政策過濾也會警報，尚不能由此判定惡意或推論對未知 rootkit 的偵測率。

- [目前論文](paper/cross_layer_directory_entry_consistency_zhTW.docx)
- [目前方法與下一步](docs/METHOD_AND_NEXT_STEPS_zh-TW.md)
- [收錄範圍](ARTIFACT_SCOPE.md)
- [第三方來源與比較範圍](THIRD_PARTY_NOTICES.md)

本說明於 2026-10-20 依使用者提供的 `eBPF_最終繳交.docx` 更新；論文檔為該版本的原樣副本。

## 方法流程

1. **配對同一次列舉。** 控制程式先登記量測行程的 PID，再讓 C 語言量測程式反覆呼叫 `getdents64`，直到回傳 0。
2. **記錄核心端已接受項目。** eBPF 觀測 `filldir64` 進入與返回，只計入回傳 `true` 的最外層呼叫，避免巢狀呼叫重複計算，也避免把緩衝區不足而回傳 `false` 的正常重送計入。
3. **在兩端建立摘要。** 以名稱位元組、inode 與 `d_type` 建立識別值；指紋保存項目數及兩個 64 位元雜湊總和，IBLT 同步累計各項目。指紋與列舉順序無關，能辨識數量不變但身分改變的替換。
4. **先檢查量測有效性，再比較。** 名稱讀取、資料表更新、呼叫配對或量測行程等檢查失敗時，不產生一致或差異判定。量測有效且指紋不同時警報；IBLT 解碼失敗只表示無法完整定位，警報仍成立。

IBLT 還原的是識別值、inode 與型態，不含原始名稱。正式設定為 256 個儲存格，對應最多 32 個差異項目的八倍預留容量。固定大小指的是容量固定時的摘要資料量；逐項讀取名稱、雜湊與更新 IBLT 的時間仍隨目錄項數增加。

## 目前證據

### 九次開機主實驗

環境為 Ubuntu 22.04.5、Linux `6.8.0-138-generic`、x86-64、ext4，使用 Hyper-V 虛擬機、4 vCPU 與固定 8 GiB 記憶體。九種模組狀態、四種背景負載及四種緩衝區大小，在九次開機中共產生 1,296 批、25,920 次完整列舉，每批 20 次。

| 方法 | 差異批次檢出數 | 對照批次誤報數 | 召回率 | 誤報率 |
|---|---:|---:|---:|---:|
| 多重集合指紋與 IBLT | 576 / 576 | 0 / 720 | 100% | 0% |
| 只比較項目數 | 432 / 576 | 0 / 720 | 75.00% | 0% |
| 固定 MAD 時序門檻 | 28 / 576 | 51 / 720 | 4.86% | 7.08% |
| 固定時序上界門檻 | 9 / 576 | 17 / 720 | 1.56% | 2.36% |

全部 144 個等量替換批次均被指紋檢出，均未被項目數基線檢出。11,520 次差異列舉的 IBLT 差集全部正確還原，正式資料未出現無效列舉或錯誤的成功解碼。兩個時序門檻只是整次列舉耗時的簡單對照，不能代表 Trace of the Times。

批次層級 Wilson 95% 信賴區間為召回率 99.34%–100%、誤報率 0%–0.53%，計算假設批次獨立。同批 20 次列舉不當成獨立樣本；九次開機全部達成差異全檢出、對照零誤報，其開機層級成功率區間為 70.09%–100%。完美點估計只描述受測矩陣。各批次是否應有差異由受控模組事先決定，因此主要驗證量測、完整列舉、配對與差異還原流程。

### 執行成本

單次開機、無背景負載、65,536 個項目時，原始列舉平均 38.16 ms，只在使用者端建立摘要為 45.59 ms，完整方法為 181.51 ms，約為原始列舉的 4.76 倍。12 種項目數與負載組合的倍率範圍為 3.72–7.94；各項成本尚未拆分。

另一個分開執行的逐項追蹤比較流程中，完整方法為 221.62 ms，逐項追蹤為 2,480.72 ms；核心端資料結構的邏輯資料量分別為 12.02 KiB 與 17,920.55 KiB。這是欄位大小加總，不含配置額外開銷，也不是實測輸出流量。逐項追蹤為本研究自行實作，不能代表 Synacktiv 等工具；兩個流程的時間不合併計算倍率。

### 外部方法比較

- **Trace of the Times：** 同一虛擬機環境中分開收集的一次四情境比較。原作者依測試標籤選 F1 最大門檻時，函式分組的召回率／誤報率為 93.89%／15.20%，序列分組為 98.00%／27.18%；本方法在另外收集的 1,000 批為 100%／0%。無法確認兩方法位於同一次開機，也不是逐次列舉配對；尚需共同設計的多開機重複驗證。
- **Decloaker v0.0.9：** 九次開機、720 次掃描中，180 次受測隱藏皆未輸出 `HIDDEN`，540 次對照也未警報。依本研究檢視，`disk ls --compare` 比較原始磁碟列出的完整路徑能否解析；受測隱藏針對父目錄列舉，保留已知完整路徑的存取。此結果反映觀測目標不同，不能寫成工具整體失效；其他功能未測試。
- **rkchk：** 尚未在其要求的 Rust for Linux 自訂核心重現，不提供未量得的比較數值。

Trace of the Times 的逐事件資料及第三方專案本體未收錄；本套件能查核摘要與驗證紀錄，完整重算需取得固定版本並重新收集資料。外部比較的排除、重跑與事後分析另有紀錄。

## 適用範圍與限制

- 只涵蓋 `filldir64` 接受之後到 `getdents64` 輸出之前的身分差異。項目在觀測點之前被排除，或因提早回傳 0 而根本未走訪，均不在範圍內。
- 假設 eBPF、使用者量測程式與控制程式未被攻擊者控制。正式實驗先掛 eBPF，再載入 ftrace 模組；反向載入順序與其他掛接技術尚未驗證。
- 現有 FNV-1a 與混合函式不提供密碼學保證。正式種子由固定起始值與開機編號產生並記錄，可重現而非祕密金鑰；尚未驗證已知種子、主動碰撞或辨識量測程式後選擇性放行的攻擊。
- 正式泛化證據仍限單一核心、ext4 與靜態目錄。動態目錄、其他檔案系統及 namespace 雖有開發期檢查，尚未完成相同強度的正式驗證。
- 更底層的 kretprobe `nmissed` 尚未納入完整性模型。`/proc` 行程隱藏、PID 重用與行程生命週期的時間一致性仍待研究。

## 下一步

1. **先補量測邊界。** 將 kretprobe 遺失納入有效性檢查，測試模組先載入及其他掛接方式；保留無效與未覆蓋情況。
2. **建立跨環境正式驗證。** 固定規則後，增加核心與檔案系統、動態目錄，以及至少一個不共用 CARAXES 程式碼的隱藏模組；與 Trace of the Times 在共同環境重複多次開機。
3. **拆解成本並驗證容量選擇。** 分量 eBPF 掛接、使用者端量測、名稱讀取、雜湊、IBLT 更新與解碼成本，比較 4 倍、8 倍與動態容量。
4. **測試進階攻擊者。** 評估有金鑰雜湊與金鑰保護的可行性，實測種子外洩、主動碰撞與量測程式選擇性放行。
5. **延伸至 `/proc`。** 加入獨立的行程建立與結束事件，處理 PID 重用及觀測時間差，再由靜態行程逐步增加短生命週期負載。

各項問題、交付內容與完成判準見[目前方法與下一步](docs/METHOD_AND_NEXT_STEPS_zh-TW.md)。這些是後續建議，尚未完成，也未取代既有實驗鎖定規約。

## 程式與證據位置

原始檔名與資料目錄沿用實驗時的名稱，供既有分析鎖與雜湊核對；閱讀時以下表的功能名稱為準。

| 功能 | 位置 |
|---|---|
| 識別值、指紋與 IBLT | `src/kicba/reconciliation.py` |
| 核心端 eBPF 與共用雜湊規則 | `collector/bpf_d9_reconciliation.c`、`collector/d9_reconciliation_hash.h` |
| 使用者端完整列舉 | `collector/d9_enum_probe.c` |
| 正式收集與多開機排程 | `collector/run_d9_campaign.py`、`scripts/run_d9_multiboot.py` |
| 鎖定分析 | `scripts/analyze_d9_formal.py` |
| 正式原始資料、分析鎖及報告 | `results/d9_formal/` |
| 容量、邊界、穩健性與成本 | `results/d9_development/` |
| 外部比較摘要、清單與驗證 | `results/d9_external_comparison/` |
| 實驗規約 | [原始鎖定規約](docs/D9_RECONCILIATION_RESEARCH_PROTOCOL_zh-TW.md) |
| 正式結果 | [原始結果紀錄](docs/D9_CONFIRMATORY_RESULTS_zh-TW.md) |
| 外部比較與排除紀錄 | [時序比較](docs/D9_TRACE_FORMAL_RESULTS_zh-TW.md)、[磁碟視圖比較](docs/D9_DECLOAKER_FORMAL_RESULTS_zh-TW.md)、[偏差紀錄](docs/D9_EXTERNAL_METHOD_COMPARISON_DEVIATIONS_zh-TW.md) |
| 環境與工具鏈 | [環境追溯紀錄](docs/D9_ENVIRONMENT_AUDIT_20261004_zh-TW.md)、`results/environment/` |

原始規約與結果紀錄保留實驗當時的描述。種子性質、外部比較是否已完成、資料量定義與目前證據範圍，以目前論文及上述更新說明解讀。

## 快速重現

以下是讀取既有資料的離線分析，不需載入核心模組。從儲存庫根目錄執行，使用 Python 3.10 或更新版本。分析只使用標準函式庫；單元測試需讓 Python 找到 `src`。

Linux / macOS：

```bash
PYTHONPATH=src python -m unittest discover -s tests -v
python scripts/analyze_d9_formal.py --input results/d9_formal/raw --timing-model results/d9_formal/timing_model.json --lock results/d9_formal/analysis_lock.json --output reproduced/formal_results.json
```

Windows PowerShell：

```powershell
$env:PYTHONPATH = "src"
python -m unittest discover -s tests -v
python scripts/analyze_d9_formal.py --input results/d9_formal/raw --timing-model results/d9_formal/timing_model.json --lock results/d9_formal/analysis_lock.json --output reproduced/formal_results.json
```

預期得到 `passed: true`、1,296 批、25,920 次列舉、空的完整性錯誤清單與全部 12 項判準通過。核對 `methods`、`transaction_counts`、`criteria` 等統計欄位與 `results/d9_formal/analysis_r1/results.json` 一致；輸入路徑字串會依作業系統而異。輸出檔已存在時程式會拒絕覆寫，請換用新檔名。

重新收集需隔離、可還原的原生 Linux 虛擬機、root、BCC/eBPF、編譯器與相符 kernel headers；步驟以原始鎖定規約為準。

## 資料完整性

`FILE_SHA256.csv` 列出研究檔案的相對路徑、SHA-256 與位元組數，不包含清單本身及 Git 內部檔案。正式實驗另以分析鎖、各 `campaign.sha256` 及外部比較鎖定檔約束原始資料和實作版本。文件更新後重新產生的是套件檔案清單，既有正式資料、分析程式與實驗鎖維持原樣。
