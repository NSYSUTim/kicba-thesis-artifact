#!/usr/bin/env python3
"""Summarize Trace offline-shift results at a label-blind fixed alpha.

The upstream evaluator writes one row per run and searched threshold.  This
script deliberately does not maximize F1.  For each run it selects the largest
available threshold not exceeding ``alpha`` and reports both mean per-run
metrics and pooled confusion counts.
"""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
from statistics import mean


METRICS = ("tpr", "fpr", "p", "fone", "acc")
COUNTS = ("tp", "fp", "tn", "fn")


def summarize(path: Path, alpha: float) -> dict:
    with path.open(newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    by_run: dict[int, list[dict[str, str]]] = {}
    for row in rows:
        by_run.setdefault(int(row["run"]), []).append(row)
    if not by_run:
        raise ValueError(f"no rows in {path}")

    selected: list[dict[str, str]] = []
    for run, candidates in sorted(by_run.items()):
        eligible = [row for row in candidates if float(row["thresh"]) <= alpha]
        if not eligible:
            raise ValueError(f"run {run} has no threshold <= {alpha}")
        selected.append(max(eligible, key=lambda row: float(row["thresh"])))

    thresholds = {float(row["thresh"]) for row in selected}
    if len(thresholds) != 1:
        raise ValueError(f"selected thresholds differ across runs: {thresholds}")

    pooled = {name: sum(int(row[name]) for row in selected) for name in COUNTS}
    tp, fp, tn, fn = (pooled[name] for name in COUNTS)
    recall = tp / (tp + fn)
    fpr = fp / (fp + tn)
    precision = tp / (tp + fp)
    f1 = 2 * precision * recall / (precision + recall)
    return {
        "source_csv": str(path),
        "runs": len(selected),
        "selection_rule": "largest available searched threshold <= alpha; no test-label optimization",
        "requested_alpha": alpha,
        "selected_threshold": thresholds.pop(),
        "mean_per_run": {name: mean(float(row[name]) for row in selected) for name in METRICS},
        "pooled": {
            **pooled,
            "recall": recall,
            "fpr": fpr,
            "precision": precision,
            "f1": f1,
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--fun", required=True, type=Path)
    parser.add_argument("--seq", required=True, type=Path)
    parser.add_argument("--alpha", type=float, default=0.05)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()

    result = {
        "schema_version": 1,
        "analysis_role": "post_hoc_label_blind_sensitivity_analysis",
        "interpretation": (
            "The upstream offline training split contains only normal batches, so it cannot select an "
            "F1-optimal labeled threshold. This analysis uses a conventional fixed alpha and does not "
            "inspect test labels when choosing the threshold."
        ),
        "fun": summarize(args.fun, args.alpha),
        "seq": summarize(args.seq, args.alpha),
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
