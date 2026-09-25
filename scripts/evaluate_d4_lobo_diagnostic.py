#!/usr/bin/env python3
"""Exploratory leave-one-boot-out screening, not a locked detector evaluation.

Thresholds use only normal (unloaded + sham) training batches. Directory
cardinality and filename length are never model inputs. The tiny 3-boot sample
is diagnostic only; no feature is selected as confirmatory by this script.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import numpy as np

from analyze_d4_qualification import _extract, _write_csv


FEATURES = ("first_raw_q10", "first_raw_median", "first_div_last_raw_median")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", action="append", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    rows = []
    for root in args.input:
        paths = sorted(root.rglob("batch_*.json.gz"))
        if not paths:
            raise ValueError(f"no batches in {root}")
        rows.extend(_extract(path) for path in paths)
    boots = sorted({row["boot_id"] for row in rows})
    if len(boots) < 3:
        raise ValueError("need at least three independent boots")
    if len(rows) != len({row["batch_id"] for row in rows}):
        raise ValueError("duplicate batch ID")
    if {row["campaign_phase"] for row in rows} != {"unloaded", "sham", "hiding"}:
        raise ValueError("missing or unexpected state")
    if len({(row["probe_profile"], row["poll_policy"]) for row in rows}) != 1:
        raise ValueError("mixed probe profiles")

    predictions = []
    folds = []
    for feature in FEATURES:
        for held_boot in boots:
            train = [row for row in rows if row["boot_id"] != held_boot]
            test = [row for row in rows if row["boot_id"] == held_boot]
            normal_train = [
                row[feature] for row in train
                if row["campaign_phase"] in {"unloaded", "sham"}
            ]
            threshold = float(np.quantile(normal_train, 0.95))
            for row in test:
                predictions.append({
                    "feature": feature,
                    "held_boot": held_boot,
                    "batch_id": row["batch_id"],
                    "state": row["campaign_phase"],
                    "condition": row["condition"],
                    "visible_cardinality": row["visible_cardinality"],
                    "filename_length": row["filename_length"],
                    "score": float(row[feature]),
                    "threshold": threshold,
                    "alert": float(row[feature]) > threshold,
                })
            fold_rows = [
                item for item in predictions
                if item["feature"] == feature and item["held_boot"] == held_boot
            ]
            for state in ("unloaded", "sham", "hiding"):
                state_rows = [item for item in fold_rows if item["state"] == state]
                folds.append({
                    "feature": feature,
                    "held_boot": held_boot,
                    "state": state,
                    "threshold": threshold,
                    "batches": len(state_rows),
                    "alert_rate": sum(item["alert"] for item in state_rows) / len(state_rows),
                })

    args.output.mkdir(parents=True, exist_ok=False)
    _write_csv(args.output / "predictions.csv", predictions)
    _write_csv(args.output / "folds.csv", folds)
    report = {
        "status": "D4_exploratory_lobo_diagnostic",
        "warning": "Feature scan and tiny normal calibration; do not claim D5 confirmation.",
        "boots": boots,
        "features": list(FEATURES),
        "normal_quantile_threshold": 0.95,
        "uses_attack_labels_for_threshold": False,
        "uses_directory_factors_for_threshold": False,
        "sham_treated_as_normal": True,
    }
    (args.output / "status.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
