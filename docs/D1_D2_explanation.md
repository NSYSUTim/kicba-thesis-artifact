# D1 與 D2 是什麼

`D` 只是 dataset（資料集）的縮寫，不是演算法名稱。

| 名稱 | 從哪裡來 | 有什麼欄位 | 用來回答什麼 | 不能回答什麼 |
|---|---|---|---|---|
| D1 | Trace of the Times 官方公開資料 | 正常／Rootkit 的核心函式 timing 與情境標籤 | 能否復現前人、既有方法是否跨情境誤報、滑動視窗是否污染 | scheduler／IRQ context 能否幫助 KICBA |
| D2 | 本研究在隔離原生 Linux VM 自行蒐集 | timing 加上同步 sched、hard IRQ、SoftIRQ、CPU migration、frequency、品質與 boot ID | KICBA 是否真的能分辨可解釋正常干擾與 Rootkit residual、是否降低誤報和污染 | 所有其他 Rootkit／ARM／真實生產環境的泛化 |

整個證據鏈是：

```text
D1：確認前人結果與找出問題
    timing-only 在新正常環境幾乎全誤報
    blind update 又可能吸收持續攻擊
                    |
                    v
提出 KICBA：更新前先要求同步核心干擾證據
                    |
                    v
D2：真正檢驗提出的方法
    五個獨立 boots、至少 1,200 batches
    leave-one-boot-out + ablation + overhead
                    |
          +---------+---------+
          |                   |
        達標                未達標
          |                   |
  主張安全更新有效     縮小為穩健性／可歸因研究
```

D1 很重要，但它只建立「為什麼需要研究」；D2 才決定「我們的方法是否成立」。把 D1 的
高 F1 當成 KICBA 成果，或用合成 context 冒充 D2，都會造成論文證據錯置。
