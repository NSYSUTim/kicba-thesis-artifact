#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path

from analyze_d4_qualification import _extract, _write_csv
from d4_context_axis import AXIS_FEATURES, fit_context_axis, score_context_axis


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    manifest = json.loads(next(args.input.glob("campaign_*.json")).read_text())
    rows = [_extract(path) for path in sorted(args.input.glob("batch_*.json.gz"))]
    by_position = {row["campaign_position"]: row for row in rows}
    clean, sham, test = [], [], []
    for item in manifest["schedule"]:
        row = by_position[item["position"]]
        if row["cpu_busy_fraction"] is None:
            raise ValueError("missing /proc/stat context")
        if item["phase"] == "calibration":
            (clean if item["state"] == "unloaded" else sham).append(row)
        else:
            test.append((item, row))
    model = fit_context_axis(clean, sham)
    predictions = []
    for item, row in test:
        stratum, score, threshold, alert = score_context_axis(model, row)
        predictions.append({
            "position": item["position"], "state": item["state"],
            "condition_for_audit_only": item["condition"], "stratum": stratum,
            "cpu_busy_fraction": row["cpu_busy_fraction"], "score": score,
            "threshold": threshold, "alert": alert,
        })
    summary = []
    for state in ("unloaded", "sham", "hiding"):
        subset = [row for row in predictions if row["state"] == state]
        summary.append({"state": state, "n": len(subset),
                        "alerts": sum(row["alert"] for row in subset),
                        "alert_rate": sum(row["alert"] for row in subset) / len(subset)})
    args.output.mkdir(parents=True, exist_ok=False)
    _write_csv(args.output / "predictions.csv", predictions)
    _write_csv(args.output / "summary.csv", summary)
    status = {
        "status": "D4_exploratory_context_clean_to_sham_axis",
        "warning": "D4 development result; the rule is not D5-confirmed.",
        "axis_features": list(AXIS_FEATURES), "model": model,
        "attack_labels_used_for_fit_or_threshold": False,
        "experimental_condition_label_used_for_prediction": False,
    }
    (args.output / "status.json").write_text(json.dumps(status, indent=2), encoding="utf-8")
    print(json.dumps(status, indent=2))


if __name__ == "__main__":
    main()
