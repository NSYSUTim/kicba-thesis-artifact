"""Render the retained per-boot medians; no experimental data is modified."""

import json
import os
import sys
from pathlib import Path

PHASE = Path(__file__).resolve().parent
sys.path.insert(0, str(PHASE / ".render_deps"))
os.environ.setdefault("MPLCONFIGDIR", str(PHASE / ".mpl_cache"))
import matplotlib
matplotlib.use("Agg")
from matplotlib import pyplot as plt, font_manager

font = Path("C:/Windows/Fonts/msjh.ttc")
if font.exists():
    font_manager.fontManager.addfont(str(font))
    plt.rcParams["font.family"] = font_manager.FontProperties(fname=str(font)).get_name()
labels = {
    "parse": "使用者解析／計數", "user_fp": "使用者指紋", "user_iblt": "使用者指紋＋IBLT",
    "empty": "加空探針", "bookkeeping": "加核心配對／計數", "names": "加名稱讀取",
    "kernel_fp": "加核心指紋", "kernel_iblt": "加核心 IBLT", "readback": "加表格讀回", "decode": "加解碼",
}
boots = json.loads((PHASE / "analysis/summary.json").read_text())["boots"]
fig, ax = plt.subplots(figsize=(12.5, 5.4))
for boot in boots:
    values = [boot["cost"]["groups"]["65536/baseline/" + mode]["wall_ns"]["median"] / 1e6 for mode in labels]
    ax.plot(range(len(labels)), values, marker="o", alpha=0.8, label="確認開機 " + str(boot["boot_index"]))
ax.set_xticks(range(len(labels)), list(labels.values()), rotation=27, ha="right")
ax.set_ylabel("端到端時間中位數（毫秒）")
ax.set_title("65,536 項、baseline：各開機每模式 10 次主要試驗")
ax.grid(axis="y", alpha=0.25)
ax.legend()
fig.tight_layout()
output = PHASE / "analysis/cost_breakdown_65536_baseline.png"
fig.savefig(output, dpi=160)
plt.close(fig)
report = PHASE / "REPORT_zh-TW.md"
text = report.read_text(encoding="utf-8")
text = text.replace('圖形未產生，錯誤已記錄：`ModuleNotFoundError("No module named \'matplotlib\'")`。數據表不受影響。',
                    '![三次開機的成本拆分](analysis/cost_breakdown_65536_baseline.png)')
text = text.replace("本輪沒有執行 apt update、upgrade 或安裝新套件。", "原實驗 VM 本輪沒有執行 apt update、upgrade 或安裝新套件。")
report.write_text(text, encoding="utf-8")
print(json.dumps({"figure": str(output), "matplotlib": matplotlib.__version__}))
