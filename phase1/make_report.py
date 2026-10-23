"""Create the first-phase report from retained confirmation evidence."""

import csv
import hashlib
import json
import os
import re
import statistics
import subprocess
import sys
from pathlib import Path

from summarize import load

ROOT = Path(__file__).resolve().parents[1]
PHASE = ROOT / "phase1"
OUTPUT = PHASE / "analysis"
OUTPUT.mkdir(exist_ok=True)  # Only derived analyses may be regenerated.
boots = []
for index in (1, 2, 3):
    directory = PHASE / f"evidence/confirmation/boot_{index:02d}"
    record = json.loads((directory / "summary.json").read_text())
    if not record["completed"] or not record["environment_unchanged"] or not record["timers_restored"]:
        raise RuntimeError("incomplete or changed confirmation boot")
    rows = load(directory / "coverage/attempts.jsonl")
    transactions = [tx for row in rows if row.get("kind") == "concurrent_loss"
                    and row["maxactive"] == 1 for tx in row["transactions"]]
    record["pre_global_diagnostic_gate_in_loss"] = {
        "transactions": len(transactions),
        "historical_gate_not_directly_measured": True,
        "already_invalid": sum(tx.get("original_valid") is not True for tx in transactions),
        "new_global_invalid_only": sum(tx.get("original_valid") is True and tx["verdict"] == "invalid"
                                       for tx in transactions),
    }
    boots.append(record)
if len({boot["boot_id"] for boot in boots}) != 3:
    raise RuntimeError("confirmation boots are not distinct")

initial_lock = json.loads((PHASE / "LOCK.json").read_text())
published = ROOT.parent / "kicba-thesis-artifact"
integrity = {"original_files": len(initial_lock["original_tracked_sha256"]), "worktree_mismatch": [], "published_mismatch": []}
for name, digest in initial_lock["original_tracked_sha256"].items():
    for directory, key in ((ROOT, "worktree_mismatch"), (published, "published_mismatch")):
        path = directory / name
        if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            integrity[key].append(name)
integrity["published_git_status"] = subprocess.run(["git", "status", "--porcelain"], cwd=published,
                                                    capture_output=True, text=True, check=True).stdout
with (OUTPUT / "original_integrity.json").open("w", encoding="utf-8") as stream:
    json.dump(integrity, stream, indent=2)
if integrity["worktree_mismatch"] or integrity["published_mismatch"] or integrity["published_git_status"]:
    raise RuntimeError("original artifact was changed")

with (OUTPUT / "summary.json").open("w", encoding="utf-8") as stream:
    json.dump({"boots": boots, "original_integrity": integrity}, stream, indent=2)

metrics = ("wall_ns", "wall_with_coverage_ns", "scan_ns", "readback_ns", "decode_ns", "cleanup_ns")
with (OUTPUT / "costs.csv").open("w", newline="", encoding="utf-8-sig") as stream:
    writer = csv.writer(stream)
    writer.writerow(["boot", "boot_id", "cardinality", "condition", "mode", "n",
                     *[name.replace("_ns", "_median_ms") for name in metrics]])
    for boot in boots:
        for key, values in boot["cost"]["groups"].items():
            count, condition, mode = key.split("/")
            writer.writerow([boot["boot_index"], boot["boot_id"], count, condition, mode,
                             values["wall_ns"]["n"], *[values[name]["median"] / 1e6 for name in metrics]])
with (OUTPUT / "paired_increments.csv").open("w", newline="", encoding="utf-8-sig") as stream:
    writer = csv.writer(stream)
    writer.writerow(["boot", "comparison", "n", "median_ms", "q1_ms", "q3_ms", "min_ms", "max_ms"])
    for boot in boots:
        for key, values in boot["cost"]["paired_differences_ns"].items():
            writer.writerow([boot["boot_index"], key, values["n"],
                             *[values[name] / 1e6 for name in ("median", "q1", "q3", "min", "max")]])

labels = {
    "parse": "使用者解析／計數", "user_fp": "使用者指紋", "user_iblt": "使用者指紋＋IBLT",
    "empty": "加空探針", "bookkeeping": "加核心配對／計數", "names": "加名稱讀取",
    "kernel_fp": "加核心指紋", "kernel_iblt": "加核心 IBLT", "readback": "加表格讀回", "decode": "加解碼",
}
table = []
for mode, label in labels.items():
    groups = [boot["cost"]["groups"]["65536/baseline/" + mode] for boot in boots]
    values = [group["wall_ns"]["median"] / 1e6 for group in groups]
    table.append((mode, label, values))

plot_error = None
try:
    sys.path.insert(0, str(PHASE / ".render_deps"))
    os.environ.setdefault("MPLCONFIGDIR", str(PHASE / ".mpl_cache"))
    import matplotlib
    matplotlib.use("Agg")
    from matplotlib import pyplot as plt, font_manager
    font = Path("C:/Windows/Fonts/msjh.ttc")
    if font.exists():
        font_manager.fontManager.addfont(str(font))
        plt.rcParams["font.family"] = font_manager.FontProperties(fname=str(font)).get_name()
    fig, ax = plt.subplots(figsize=(12.5, 5.4))
    positions = list(range(len(table)))
    for index, boot in enumerate(boots):
        ax.plot(positions, [row[2][index] for row in table], marker="o", alpha=0.75,
                label="確認開機 " + str(boot["boot_index"]))
    ax.set_xticks(positions, [row[1] for row in table], rotation=27, ha="right")
    ax.set_ylabel("端到端時間中位數（毫秒）")
    ax.set_title("65,536 項、baseline：各開機每模式 10 次主要試驗")
    ax.grid(axis="y", alpha=0.25)
    ax.legend()
    fig.tight_layout()
    fig.savefig(OUTPUT / "cost_breakdown_65536_baseline.png", dpi=160)
    plt.close(fig)
except Exception as error:
    plot_error = repr(error)

miss_windows = sum(boot["coverage"]["maxactive_1"]["missed_windows"] for boot in boots)
loss_trials = sum(boot["coverage"]["maxactive_1"]["transactions"] for boot in boots)
false_valid = sum(boot["coverage"]["maxactive_1"]["false_valid_when_missed"] for boot in boots)
pre_global_invalid = sum(boot["pre_global_diagnostic_gate_in_loss"]["already_invalid"] for boot in boots)
normal = sum(boot["coverage"]["normal"]["windows"] for boot in boots)
fidelity = sum(boot["fidelity"]["trials"] for boot in boots)
full_fidelity = sum(boot["fidelity"]["full_trials"] for boot in boots)
cost_attempts = sum(boot["cost"]["attempts"] for boot in boots)
cost_primary = sum(boot["cost"]["primary"] for boot in boots)
cost_excluded = sum(boot["cost"]["excluded_primary"] for boot in boots)
decode_ms = [boot["cost"]["groups"]["65536/baseline/decode"]["decode_ns"]["median"] / 1e6 for boot in boots]
cleanup_ms = [boot["cost"]["groups"]["65536/baseline/decode"]["cleanup_ns"]["median"] / 1e6 for boot in boots]
readback_ms = [boot["cost"]["groups"]["65536/baseline/decode"]["readback_ns"]["median"] / 1e6 for boot in boots]
full_ms = [boot["cost"]["groups"]["65536/baseline/decode"]["wall_ns"]["median"] / 1e6 for boot in boots]
full_quality_ms = [boot["cost"]["groups"]["65536/baseline/decode"]["wall_with_coverage_ns"]["median"] / 1e6 for boot in boots]

report = ["# 第一階段結果：量測完整性、觀測干擾與成本\n",
          "日期：2026-10-23（Asia/Taipei）。本報告只涵蓋已核准的第一階段，未進入第二階段，論文及簡報未修改。\n",
          "## 完成情形\n",
          f"一個先導開機後，完成三個不同 boot ID 的確認收集。原鎖定分析重現 1,296 批，7 項原測試通過；新增實作的 34 項先導測試通過。確認包含 {fidelity:,} 次實收輸出核對、{full_fidelity:,} 次完整判讀／還原核對、{cost_attempts:,} 次成本試驗（其中 {cost_primary:,} 次主要分析、其餘為預先指定暖機）。\n",
          "| 開機 | boot ID | 三組試驗耗時 | 環境及計時器 |\n|---|---|---:|---|\n"]
for boot in boots:
    report.append(f"| {boot['boot_index']} | `{boot['boot_id']}` | {boot['elapsed_seconds']:.1f} 秒 | 核心／套件未變，計時器已恢復 |\n")
report += ["\n耗時不含重新開機、資料匯出、程式實作與人工核對。每 boot 的成本表與成對增量見 [costs.csv](analysis/costs.csv)、[paired_increments.csv](analysis/paired_increments.csv)。\n",
           "## 漏失統計：可用，但保證範圍有限\n",
           "BCC 0.18.0 設定正數 maxactive 的返回探針實際透過 tracefs 建立，可讀到精確事件的 profile；本輪沒有更換掛接方式。原入口探針經 perf PMU，沒有出現在同一份 profile，不能宣稱所有入口／eBPF 執行漏失都已排除。核心 profile 的 missed 是返回探針內部 kprobe 與返回實例漏失的總和，亦不是某個 PID 的個別計數。\n",
           f"確認中，maxactive=1 的 {miss_windows} 個窗口誘發實際 missed，{loss_trials:,} 次相關列舉全部保守判為無效，false-valid 為 {false_valid}。maxactive=256 的併發窗口結果逐 boot 見 [summary.json](analysis/summary.json)；{normal} 個循序對照皆有效一致並完整解碼。缺少統計、解析錯誤、計數重設或事件身分不符不能預設為零。\n",
           f"**新增證據的實際意義：**原始資料中的 original_valid 是新增全域漏失門檻前的診斷版旗標，含一項新增的計數收支檢查。此旗標已拒判 {pre_global_invalid:,} 次，但不能直接當成未修改舊版的結果。另用未修改的原判定函式做獨立回放：maxactive=1 的 3 個漏失窗口、56 次列舉全被原版拒判（40 次缺少必要紀錄而停止、16 次回報無效）；maxactive=256 的 56 次對照全有效。本輪沒有展示舊版誤判被修復，增加的是可直接觀察的漏失來源與保守拒判依據。舊正式資料未記錄的 missed 也無法事後補成零。回放不混入確認分母，見 [原版判讀對照](evidence/original_gate_reference_attempt1/manifest.json)。\n",
           "來源：[BCC v0.18.0 的附掛實作](https://github.com/iovisor/bcc/blob/v0.18.0/src/cc/libbpf.c)、[Linux 6.8 的 profile 定義](https://github.com/torvalds/linux/blob/v6.8/kernel/trace/trace_kprobe.c)、[Kprobes 文件](https://www.kernel.org/doc/html/v6.8/trace/kprobes.html)。\n",
           "## 掛接先後與觀測干擾\n",
           f"六種既有狀態，涵蓋兩種隱藏位置及等量改名；比較無探針、空探針、完整量測，後兩種再分探針先掛與模組先載入。buffer 為 256／65,536 bytes。{fidelity:,} 次實收名稱位元組、inode、型態均符合預期；完整量測 {full_fidelity:,} 次的指紋判讀與差異還原均正確。沒有觀察到這些組合中探針改變實收輸出的現象。\n",
           "這補充先前未測的反向載入順序，不代表所有 rootkit、掛接技術或核心版本都不受觀測干擾。已知清單只作受控實驗 oracle，沒有加入第三視圖偵測架構。\n",
           "## 成本：主要時間在逐項核心路徑，解碼不是最大部分\n",
           "以下為 65,536 項、baseline；各數字先取每 boot 10 次主要試驗的中位數，再列三個 boot 的中位數範圍。暖機和無效資料的分母分開，沒有把負增量截為零。\n",
           "| 模式 | 三個開機的中位數（ms） | 範圍（ms） |\n|---|---|---:|\n"]
for _, label, values in table:
    report.append(f"| {label} | {'、'.join(f'{value:.2f}' for value in values)} | {min(values):.2f}–{max(values):.2f} |\n")
if plot_error is None:
    report.append("\n![三次開機的成本拆分](analysis/cost_breakdown_65536_baseline.png)\n")
else:
    report.append("\n圖形未產生，錯誤已記錄：`" + plot_error + "`。數據表不受影響。\n")
report += [f"\n在完整模式，表格／品質資料讀回約 {min(readback_ms):.2f}–{max(readback_ms):.2f} ms，解碼 {min(decode_ms):.2f}–{max(decode_ms):.2f} ms，清理 {min(cleanup_ms):.2f}–{max(cleanup_ms):.2f} ms；整體為 {min(full_ms):.2f}–{max(full_ms):.2f} ms。包含前後 profile／身分查詢的總時間為 {min(full_quality_ms):.2f}–{max(full_quality_ms):.2f} ms。主要成本不是只在 Python 解碼。\n",
           "空探針、逐項配對／狀態維護、名稱讀取、指紋及 IBLT 各有條件增量；IBLT 有可量測代價，但不宜把它當唯一瓶頸。原清理流程本身會掃描表格，故『省略明確讀回』也不等於完全沒有表格搬移。變體間有快取、排程、頻率與記憶體交互影響，模式差不硬換成加總必為 100% 的精確占比。每組隨機配對及其變異保留在 CSV。\n",
           f"成本主要分析共 {cost_primary:,} 次，無效／品質排除 {cost_excluded} 次。這是新增診斷分支及控制器的成本，不覆寫舊實作 4.76 倍數值；若要主張新舊實作速度優劣，仍須同規約橋接。固定摘要 bytes 亦不等於全部實際配置記憶體，本輪沒有測得完整核心配置記憶體。\n",
           "## 保留環境與可追溯性\n",
           f"已驗證新 Hyper-V 檢查點；原 main 保持乾淨，原 {integrity['original_files']:,} 個追蹤檔案在原 checkout 及工作副本的 SHA-256 均未變。三次確認逐次檢查來源、核心與套件，更新計時器均已恢復。詳細資料見 [完整性核對](analysis/original_integrity.json)、[確認來源鎖](CONFIRMATION_LOCK.json)、[初始鎖](LOCK.json)。\n",
           "原實驗 VM 本輪沒有執行 apt update、upgrade 或安裝新套件。這不是永久禁止升級；update 更新套件資訊，upgrade 改變已安裝套件。升級後可以作另一個環境比較，只是不能把同時改了環境的時間差全歸因於程式改良。[APT 官方手冊](https://manpages.debian.org/bookworm/apt/apt.8.en.html)\n",
           "## 限制與下一個決策\n",
           "只有原 VM、核心 6.8、ext4、靜態目錄及既有受控模組。三個開機不是三個獨立硬體或核心環境，零錯誤觀察不等於普遍保證。宿主 CPU／記憶體採樣約秒級，不能分解每次毫秒級呼叫的所有干擾。BCC 及舊模組的編譯／deprecation／BTF 警告留在原始紀錄；未升級工具消除它們。本輪由主代理核對實作與證據，額外代理因使用額度未完成獨立審查，未將其列為已通過的審查。\n",
           "下一階段若繼續，優先考慮減少逐項核心探針與狀態更新的成本，再評估 IBLT 建表；單純延後解碼可省的時間有限。正式跨環境、獨立隱藏實作及動態目錄仍屬第二階段。第 4、5 項、一般程序監控與 /proc 延伸均未開始。本輪到此停止，不自動進入第二階段。\n"]
fault_root = PHASE / "evidence/fault_checks_attempt1"
if fault_root.is_dir():
    fault_results = {path.name: json.loads(path.read_text()) for path in fault_root.glob("*.json")
                     if path.name != "manifest.json"}
    report += ["## 補充故障對照\n",
               "五項故障對照獨立保存，沒有混入確認樣本。非法容量設定、兩端種子不符、刪除核心統計、注入未配對 depth 都判為無效。後兩項屬受控狀態注入，沒有冒充真正的排程漏失。\n"]
    small = fault_results["valid_small_capacity.json"]
    report.append(f"兩端合法設成 8 個儲存格、既有隱藏模組造成 16 個差異的本次對照：量測{'有效' if small['original_valid'] else '無效'}，IBLT 還原{'成功' if small['decode_success'] else '失敗'}，判讀為{'差異警報' if small['verdict'] == 'different' else small['verdict']}。此案例確認合法容量不足沒有抹掉指紋警報，並非一般解碼容量保證。\n")
    report.append("詳細結果見 [故障對照資料](evidence/fault_checks_attempt1/manifest.json)、[故障對照規約](FAULT_CHECK_PROTOCOL_zh-TW.md)。\n")
memory_path = PHASE / "evidence/map_memory_audit.json"
if memory_path.exists():
    memory = json.loads(memory_path.read_text())
    total = sum(int(row["fields"]["memlock"]) for row in memory["maps"].values())
    iblt = memory["maps"]["kernel_iblt"]["fields"]
    report += ["## 資料量與核心資料表配置\n",
               f"另作未附掛探針的靜態稽核：單一診斷 BPF 物件的九張 map，fdinfo 的 memlock 欄位合計 {total:,} bytes（{total / 2**20:.2f} MiB）；其中 IBLT map 為 {int(iblt['memlock']):,} bytes，max_entries={iblt['max_entries']}。這是全域資料表的核心回報值，不是每次列舉配置一份，也不是整個工具常駐／峰值記憶體的完整量測。\n",
               "每次設定 256 個儲存格的邏輯摘要資料約 12.02 KiB，和全域 map 預留配置是不同指標，不能混稱實體記憶體。現有資料量比較不因此改寫成實體記憶體比較。後續若改良記憶體，可以研究全域 map 容量與宣告併發上限如何對齊；本輪沒有更改容量。見 [原始 fdinfo](evidence/map_memory_audit.json)。\n"]
text = "\n".join(report)
text = re.sub(r"(?m)(^\|[^\n]*\|)\n\n(?=\|)", r"\1\n", text)
(PHASE / "REPORT_zh-TW.md").write_text(text, encoding="utf-8")
print(json.dumps({"boots": len(boots), "fidelity_trials": fidelity, "cost_primary": cost_primary,
                  "loss_trials": loss_trials, "pre_global_diagnostic_invalid": pre_global_invalid,
                  "full_ms": full_ms, "decode_ms": decode_ms,
                  "report": str(PHASE / "REPORT_zh-TW.md"), "plot_error": plot_error}))
