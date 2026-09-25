#!/usr/bin/env python3
"""Summarize the untouched upstream offline evaluator CSV outputs."""

from __future__ import annotations

import argparse
import csv
import json
import math
import statistics
from collections import defaultdict
from pathlib import Path


METRICS = ("fone", "tpr", "fpr", "p", "acc", "tp", "fp", "tn", "fn")


def percentile(values: list[float], fraction: float) -> float:
    ordered = sorted(values)
    position = (len(ordered) - 1) * fraction
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return ordered[lower]
    weight = position - lower
    return ordered[lower] * (1 - weight) + ordered[upper] * weight


def distribution(values: list[float]) -> dict[str, float]:
    return {
        "mean": statistics.fmean(values),
        "median": statistics.median(values),
        "sample_sd": statistics.stdev(values) if len(values) > 1 else 0.0,
        "p2_5": percentile(values, 0.025),
        "p97_5": percentile(values, 0.975),
        "min": min(values),
        "max": max(values),
    }


def metrics(tp: int, fp: int, tn: int, fn: int) -> dict[str, float | int]:
    recall = tp / (tp + fn) if tp + fn else 0.0
    fpr = fp / (fp + tn) if fp + tn else 0.0
    precision = tp / (tp + fp) if tp + fp else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    accuracy = (tp + tn) / (tp + fp + tn + fn)
    return {
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "recall": recall,
        "fpr": fpr,
        "precision": precision,
        "f1": f1,
        "accuracy": accuracy,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--best", required=True, type=Path)
    parser.add_argument("--confusion", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()

    with args.best.open(newline="", encoding="utf-8") as stream:
        best_rows = list(csv.DictReader(stream))
    if len(best_rows) != 100:
        raise SystemExit(f"expected 100 best-result rows, found {len(best_rows)}")
    run_ids = [int(row["run"]) for row in best_rows]
    if sorted(run_ids) != list(range(1, 101)):
        raise SystemExit("run identifiers are not exactly 1..100")

    overall = {
        metric: distribution([float(row[metric]) for row in best_rows])
        for metric in METRICS
    }
    pooled = metrics(
        sum(int(row["tp"]) for row in best_rows),
        sum(int(row["fp"]) for row in best_rows),
        sum(int(row["tn"]) for row in best_rows),
        sum(int(row["fn"]) for row in best_rows),
    )

    per_run_scenario: dict[tuple[int, str], dict[str, int]] = defaultdict(
        lambda: {"tp": 0, "fp": 0, "tn": 0, "fn": 0}
    )
    with args.confusion.open(newline="", encoding="utf-8") as stream:
        confusion_rows = list(csv.DictReader(stream))
    for row in confusion_rows:
        if row["pred"] != row["actual"]:
            continue
        key = (int(row["run"]), row["actual"])
        pair = (row["pred_class"], row["actual_class"])
        field = {
            ("Pos", "Pos"): "tp",
            ("Neg", "Pos"): "fn",
            ("Pos", "Neg"): "fp",
            ("Neg", "Neg"): "tn",
        }[pair]
        per_run_scenario[key][field] += int(row["cnt"])

    scenarios = sorted({scenario for _, scenario in per_run_scenario})
    by_scenario = {}
    for scenario in scenarios:
        rows = [metrics(**per_run_scenario[(run, scenario)]) for run in range(1, 101)]
        for row in rows:
            if row["tp"] + row["fn"] != 100 or row["fp"] + row["tn"] != 100:
                raise SystemExit(f"unexpected test size for {scenario}")
        by_scenario[scenario] = {
            metric: distribution([float(row[metric]) for row in rows])
            for metric in ("recall", "fpr", "precision", "f1", "accuracy")
        }

    report = {
        "source_best": str(args.best),
        "source_confusion": str(args.confusion),
        "runs": 100,
        "note": (
            "Upstream offline evaluation selects the threshold with maximum F1 "
            "on each run's test labels; these are optimistic reproduction metrics."
        ),
        "overall": overall,
        "pooled_counts_and_metrics": pooled,
        "by_same_scenario": by_scenario,
    }
    args.output.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
