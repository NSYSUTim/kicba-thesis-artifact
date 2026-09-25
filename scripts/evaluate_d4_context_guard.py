#!/usr/bin/env python3
"""Exploratory normal-only CPU-context-conditioned security guard."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import numpy as np

from analyze_d4_qualification import _extract, _write_csv


FEATURE = "first_raw_median"


def _fit(rows: list[dict]) -> tuple[float, float, float]:
    x = np.asarray([row["cpu_busy_fraction"] for row in rows], dtype=float)
    y = np.log(np.asarray([row[FEATURE] for row in rows], dtype=float))
    if not np.all(np.isfinite(x)) or np.ptp(x) < 0.05:
        raise ValueError("CPU context is missing or has insufficient range")
    design = np.column_stack((np.ones(len(x)), x))
    intercept, slope = np.linalg.lstsq(design, y, rcond=None)[0]
    residual = y - (intercept + slope * x)
    # A fixed 5% multiplicative uncertainty margin is selected in D4 after
    # the max-residual rule under-covered future benign batches.  D5 must not
    # tune it further, whether successful or not.
    threshold = float(np.max(residual) + np.log(1.05))
    return float(intercept), float(slope), threshold


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    manifest_path = next(args.input.glob("campaign_*.json"))
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    rows = [_extract(path) for path in sorted(args.input.glob("batch_*.json.gz"))]
    by_position = {row["campaign_position"]: row for row in rows}
    calibration, test = [], []
    for item in manifest["schedule"]:
        row = by_position[item["position"]]
        if row["cpu_busy_fraction"] is None:
            raise ValueError("dataset lacks /proc/stat context")
        if item["phase"] == "calibration":
            if item["state"] not in {"unloaded", "sham"}:
                raise ValueError("attack data in calibration")
            calibration.append(row)
        else:
            test.append((item, row))
    intercept, slope, threshold = _fit(calibration)
    predictions = []
    for item, row in test:
        residual = float(np.log(row[FEATURE]) - (
            intercept + slope * row["cpu_busy_fraction"]
        ))
        predictions.append({
            "position": item["position"], "state": item["state"],
            "condition_for_audit_only": item["condition"],
            "cpu_busy_fraction": row["cpu_busy_fraction"],
            "raw_timing_ns": row[FEATURE], "log_residual": residual,
            "threshold": threshold, "alert": residual > threshold,
        })
    summary = []
    for state in ("unloaded", "sham", "hiding"):
        subset = [row for row in predictions if row["state"] == state]
        summary.append({
            "state": state, "n": len(subset),
            "alerts": sum(row["alert"] for row in subset),
            "alert_rate": sum(row["alert"] for row in subset) / len(subset),
        })
    args.output.mkdir(parents=True, exist_ok=False)
    _write_csv(args.output / "predictions.csv", predictions)
    _write_csv(args.output / "summary.csv", summary)
    status = {
        "status": "D4_exploratory_proc_stat_context_guard",
        "warning": "D4 development only; 5% margin must be frozen before D5.",
        "feature": FEATURE,
        "context": "cpu_busy_fraction from /proc/stat",
        "fit": {"intercept": intercept, "slope": slope, "threshold": threshold},
        "attack_labels_used_for_fit_or_threshold": False,
        "experimental_condition_label_used_for_prediction": False,
    }
    (args.output / "status.json").write_text(json.dumps(status, indent=2), encoding="utf-8")
    print(json.dumps(status, indent=2))


if __name__ == "__main__":
    main()
