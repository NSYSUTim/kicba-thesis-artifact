#!/usr/bin/env python3
"""Exploratory D4 replay of fixed, blind, and guarded single-window methods."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import numpy as np

from analyze_d4_qualification import _extract, _write_csv
from d4_context_axis import AXIS_FEATURES, fit_context_axis, score_context_axis


WINDOWS = (20, 50, 100)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    manifests = list(args.input.glob("campaign_*.json"))
    if len(manifests) != 1:
        raise ValueError("expected one campaign manifest")
    manifest = json.loads(manifests[0].read_text(encoding="utf-8"))
    if manifest["status"] != "complete" or manifest.get("schedule_mode") != "blocks":
        raise ValueError("requires a complete blocks campaign")
    rows = [_extract(path) for path in sorted(args.input.glob("batch_*.json.gz"))]
    by_position = {row["campaign_position"]: row for row in rows}
    clean_cal, sham_cal, test = [], [], []
    for item in manifest["schedule"]:
        row = by_position[item["position"]]
        if row["campaign_phase"] != item["phase"] + ":" + item["state"]:
            raise ValueError("schedule mismatch")
        if item["phase"] == "calibration":
            (clean_cal if item["state"] == "unloaded" else sham_cal).append(row)
        else:
            test.append((item, row))
    if not clean_cal or not sham_cal:
        raise ValueError("clean and sham calibration are required")
    if any(row["cpu_busy_fraction"] is None for row in clean_cal + sham_cal):
        raise ValueError("context-axis replay requires /proc/stat context")
    security_model = fit_context_axis(clean_cal, sham_cal)
    # Low-context clean calibration defines the original operational state.
    # This selection uses measured CPU busy, not the experimental condition label.
    operational_cal = [
        row for row in clean_cal
        if row["cpu_busy_fraction"] < security_model["context_split"]
    ]
    operational_anchor = float(np.median(
        [row["first_raw_median"] for row in operational_cal]
    ))
    operational_threshold = float(max(
        row["first_raw_median"] / operational_anchor for row in operational_cal
    ) * 1.01)

    predictions = []
    for window in WINDOWS:
        for method in ("fixed", "blind", "guarded"):
            reference = [
                (row["first_raw_median"], "unloaded") for row in operational_cal
            ][-window:]
            attack_updates = 0
            normal_updates = 0
            for item, row in test:
                state = item["state"]
                stratum, security_score, security_threshold, security_alert = (
                    score_context_axis(security_model, row)
                )
                adaptive_anchor = (
                    operational_anchor if method == "fixed"
                    else float(np.median([value for value, _state in reference]))
                )
                operational_score = float(row["first_raw_median"] / adaptive_anchor)
                operational_alert = operational_score > operational_threshold
                alert = (
                    operational_alert if method in {"fixed", "blind"}
                    else operational_alert or security_alert
                )
                accept = (
                    method == "blind" or (method == "guarded" and not security_alert)
                )
                if method != "fixed" and accept:
                    reference = (reference + [(row["first_raw_median"], state)])[-window:]
                    if state == "hiding":
                        attack_updates += 1
                    else:
                        normal_updates += 1
                predictions.append({
                    "window": window, "method": method,
                    "position": item["position"], "segment": item["segment"],
                    "segment_offset": item["segment_offset"],
                    "state": state, "condition": item["condition"],
                    "context_stratum": stratum,
                    "security_score": security_score,
                    "security_threshold": security_threshold,
                    "security_alert": security_alert,
                    "operational_score": operational_score,
                    "operational_threshold": operational_threshold,
                    "operational_alert": operational_alert,
                    "alert": alert, "accepted_update": method != "fixed" and accept,
                    "attack_updates_so_far": attack_updates,
                    "normal_updates_so_far": normal_updates,
                    "window_attack_fraction": (
                        sum(ref_state == "hiding" for _value, ref_state in reference)
                        / len(reference) if method != "fixed" else 0.0
                    ),
                })
    summary = []
    for window in WINDOWS:
        for method in ("fixed", "blind", "guarded"):
            subset = [row for row in predictions
                      if row["window"] == window and row["method"] == method]
            normal = [row for row in subset if row["state"] != "hiding"]
            attack = [row for row in subset if row["state"] == "hiding"]
            summary.append({
                "window": window, "method": method,
                "normal_batches": len(normal),
                "normal_fpr": sum(row["alert"] for row in normal) / len(normal),
                "attack_batches": len(attack),
                "attack_recall": sum(row["alert"] for row in attack) / len(attack),
                "attack_updates": sum(row["accepted_update"] for row in attack),
                "normal_updates": sum(row["accepted_update"] for row in normal),
                "max_window_attack_fraction": max(
                    row["window_attack_fraction"] for row in subset
                ),
            })
    segment_summary = []
    for window in WINDOWS:
        for method in ("fixed", "blind", "guarded"):
            for segment in dict.fromkeys(item["segment"] for item, _ in test):
                subset = [row for row in predictions if row["window"] == window
                          and row["method"] == method and row["segment"] == segment]
                segment_summary.append({
                    "window": window, "method": method, "segment": segment,
                    "state": subset[0]["state"], "condition": subset[0]["condition"],
                    "batches": len(subset),
                    "alert_rate": sum(row["alert"] for row in subset) / len(subset),
                    "last_20_alert_rate": sum(row["alert"] for row in subset[-20:])
                    / len(subset[-20:]),
                    "accepted_updates": sum(row["accepted_update"] for row in subset),
                })
    args.output.mkdir(parents=True, exist_ok=False)
    _write_csv(args.output / "predictions.csv", predictions)
    _write_csv(args.output / "summary.csv", summary)
    _write_csv(args.output / "segment_summary.csv", segment_summary)
    status = {
        "status": "D4_exploratory_dual_timescale_replay",
        "warning": "Development campaign; W20/W50/W100 are separate sensitivity runs.",
        "security_feature": "context-stratified clean-to-sham projection",
        "security_axis_features": list(AXIS_FEATURES),
        "security_model": security_model,
        "operational_feature": "first_raw_median / fixed-or-window median",
        "attack_labels_used_for_thresholds": False,
        "security_threshold_rule": "max benign clean+sham projection + 0.01 log-unit",
        "operational_threshold_rule": "max baseline-clean ratio * 1.01",
        "windows": list(WINDOWS),
        "experimental_condition_label_used_for_prediction": False,
    }
    (args.output / "status.json").write_text(json.dumps(status, indent=2), encoding="utf-8")
    print(json.dumps(status, indent=2))


if __name__ == "__main__":
    main()
