#!/usr/bin/env python3
"""Normal-only calibrated evaluation of one D4 same-inode development pilot."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import numpy as np

from analyze_d4_qualification import _extract, _write_csv


FEATURES = ("first_raw_q10", "first_raw_median")
THRESHOLD_QUANTILE = 0.95


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    manifest_paths = list(args.input.glob("campaign_*.json"))
    if len(manifest_paths) != 1:
        raise ValueError("expected one campaign manifest")
    manifest = json.loads(manifest_paths[0].read_text(encoding="utf-8"))
    if manifest["status"] != "complete":
        raise ValueError("incomplete campaign")
    paths = sorted(args.input.glob("batch_*.json.gz"))
    rows = [_extract(path) for path in paths]
    if len(rows) != len(manifest["schedule"]):
        raise ValueError("batch count differs from schedule")
    if len({row["batch_id"] for row in rows}) != len(rows):
        raise ValueError("duplicate batch ID")
    if len({row["boot_id"] for row in rows}) != 1:
        raise ValueError("multiple boots in stable pilot")
    if len({(row["visible_cardinality"], row["filename_length"]) for row in rows}) != 1:
        raise ValueError("multiple directory factors in stable pilot")
    fixtures = {
        (row["fixture_mode"], row["fixture_device"], row["fixture_inode"])
        for row in rows
    }
    if fixtures != {("persistent", manifest["fixture_device"], manifest["fixture_inode"])}:
        raise ValueError("not all batches used the same persistent fixture")
    by_position = {row["campaign_position"]: row for row in rows}
    if set(by_position) != set(range(len(rows))):
        raise ValueError("campaign positions incomplete")
    calibration = []
    test = []
    for item in manifest["schedule"]:
        row = by_position[item["position"]]
        if row["campaign_phase"] != item["phase"] + ":" + item["state"]:
            raise ValueError("phase/state mismatch")
        if row["condition"] != item["condition"]:
            raise ValueError("condition mismatch")
        if item["phase"] == "calibration":
            if item["state"] != "unloaded" or row["label"] != "normal":
                raise ValueError("calibration is not clean normal")
            calibration.append(row)
        elif item["phase"] == "test":
            test.append(row)
        else:
            raise ValueError("unexpected phase")

    predictions = []
    summary = []
    for feature in FEATURES:
        for mode in ("pooled", "condition_oracle"):
            thresholds = {}
            for condition in ("baseline", "cpu"):
                samples = [
                    row[feature] for row in calibration
                    if mode == "pooled" or row["condition"] == condition
                ]
                thresholds[condition] = float(np.quantile(samples, THRESHOLD_QUANTILE))
            for row in test:
                state = row["campaign_phase"].split(":", 1)[1]
                threshold = thresholds[row["condition"]]
                predictions.append({
                    "feature": feature,
                    "mode": mode,
                    "batch_id": row["batch_id"],
                    "position": row["campaign_position"],
                    "state": state,
                    "condition": row["condition"],
                    "score": float(row[feature]),
                    "threshold": threshold,
                    "alert": float(row[feature]) > threshold,
                })
            for state in ("unloaded", "sham", "hiding"):
                for condition in ("baseline", "cpu", "all"):
                    subset = [
                        item for item in predictions
                        if item["feature"] == feature and item["mode"] == mode
                        and item["state"] == state
                        and (condition == "all" or item["condition"] == condition)
                    ]
                    summary.append({
                        "feature": feature,
                        "mode": mode,
                        "state": state,
                        "condition": condition,
                        "n": len(subset),
                        "alerts": sum(item["alert"] for item in subset),
                        "alert_rate": sum(item["alert"] for item in subset) / len(subset),
                    })

    args.output.mkdir(parents=True, exist_ok=False)
    _write_csv(args.output / "predictions.csv", predictions)
    _write_csv(args.output / "summary.csv", summary)
    report = {
        "status": "D4_exploratory_same_inode_pilot",
        "warning": "One fixture and one boot; condition_oracle uses experimental load labels.",
        "boot_id": rows[0]["boot_id"],
        "batches": len(rows),
        "calibration_batches": len(calibration),
        "test_batches": len(test),
        "normal_only_calibration": True,
        "threshold_quantile": THRESHOLD_QUANTILE,
        "features": list(FEATURES),
        "primary_mode": "pooled",
    }
    (args.output / "status.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
