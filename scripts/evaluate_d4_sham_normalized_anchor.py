#!/usr/bin/env python3
"""Exploratory immutable anchor normalized with a benign ftrace-hook control."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import numpy as np

from analyze_d4_qualification import _extract, _write_csv


FEATURES = ("first_raw_q10", "first_raw_median", "first_div_last_raw_median")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    manifests = list(args.input.glob("campaign_*.json"))
    if len(manifests) != 1:
        raise ValueError("expected one campaign manifest")
    manifest = json.loads(manifests[0].read_text(encoding="utf-8"))
    rows = [_extract(path) for path in sorted(args.input.glob("batch_*.json.gz"))]
    by_position = {row["campaign_position"]: row for row in rows}
    calibration: dict[str, list[dict]] = {"unloaded": [], "sham": []}
    test = []
    for item in manifest["schedule"]:
        row = by_position[item["position"]]
        expected_phase = item["phase"] + ":" + item["state"]
        if row["campaign_phase"] != expected_phase:
            raise ValueError("schedule metadata mismatch")
        if item["phase"] == "calibration":
            if item["state"] not in calibration:
                raise ValueError("attack state in calibration")
            calibration[item["state"]].append(row)
        elif item["phase"] == "test":
            test.append(row)
    if not calibration["unloaded"] or not calibration["sham"]:
        raise ValueError("both unloaded and sham calibration are required")

    predictions = []
    thresholds = []
    for feature in FEATURES:
        for mode in ("pooled", "condition_stratified"):
            anchors = {}
            limits = {}
            for condition in ("baseline", "cpu"):
                unloaded = [
                    row[feature] for row in calibration["unloaded"]
                    if mode == "pooled" or row["condition"] == condition
                ]
                anchor = float(np.median(unloaded))
                benign = [
                    row[feature] / anchor
                    for state in ("unloaded", "sham")
                    for row in calibration[state]
                    if mode == "pooled" or row["condition"] == condition
                ]
                # Development rule: maximum benign control plus 1% guard band.
                # This is intentionally conservative and must be frozen before D5.
                limit = float(max(benign) * 1.01)
                anchors[condition] = anchor
                limits[condition] = limit
                thresholds.append({
                    "feature": feature, "mode": mode, "condition": condition,
                    "anchor": anchor, "max_benign_normalized": max(benign),
                    "threshold": limit, "benign_calibration_n": len(benign),
                })
            for row in test:
                state = row["campaign_phase"].split(":", 1)[1]
                condition = row["condition"]
                score = float(row[feature] / anchors[condition])
                predictions.append({
                    "feature": feature, "mode": mode,
                    "batch_id": row["batch_id"], "position": row["campaign_position"],
                    "state": state, "condition": condition,
                    "raw_value": float(row[feature]), "anchor": anchors[condition],
                    "normalized_score": score, "threshold": limits[condition],
                    "alert": score > limits[condition],
                })
    summary = []
    for feature in FEATURES:
        for mode in ("pooled", "condition_stratified"):
            for state in ("unloaded", "sham", "hiding"):
                subset = [item for item in predictions
                          if item["feature"] == feature and item["mode"] == mode
                          and item["state"] == state]
                summary.append({
                    "feature": feature, "mode": mode, "state": state,
                    "n": len(subset), "alerts": sum(item["alert"] for item in subset),
                    "alert_rate": sum(item["alert"] for item in subset) / len(subset),
                })
    args.output.mkdir(parents=True, exist_ok=False)
    _write_csv(args.output / "thresholds.csv", thresholds)
    _write_csv(args.output / "predictions.csv", predictions)
    _write_csv(args.output / "summary.csv", summary)
    status = {
        "status": "D4_exploratory_sham_normalized_anchor",
        "warning": "Same boot/object development data; max+1% rule is not confirmed.",
        "attack_labels_used_for_threshold": False,
        "benign_sham_used_for_threshold": True,
        "features_scanned": list(FEATURES),
        "primary_candidate": "first_raw_q10 / clean-anchor, pooled benign max + 1%",
    }
    (args.output / "status.json").write_text(json.dumps(status, indent=2), encoding="utf-8")
    print(json.dumps(status, indent=2))


if __name__ == "__main__":
    main()
