#!/usr/bin/env python3
"""Post-D5 development of a bounded robust adaptive security threshold.

For each CPU-context stratum, the clean-to-sham axis remains fixed.  The
one-sided security threshold is decomposed into:

    recent accepted-clean median + calibrated benign-hook allowance

The median is robust while fewer than half of a window are contaminated.  Its
movement is additionally clipped to at most one calibrated benign-hook
allowance from the boot-local clean center.  Window sizes are evaluated as
independent sensitivity conditions; they never vote or form a consensus.

No attack label is used to fit an axis, allowance, center, or threshold.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import numpy as np

from analyze_d4_qualification import _write_csv
from d4_context_axis import AXIS_FEATURES, fit_context_axis, score_context_axis
from develop_d6_factorized_method import LOG_MARGIN, _load_boot


WINDOWS = (10, 20, 50)


def _projection(model: dict, row: dict) -> tuple[str, float]:
    stratum = (
        "low" if row["cpu_busy_fraction"] < model["context_split"] else "high"
    )
    params = model["strata"][stratum]
    value = np.log(np.asarray([row[name] for name in AXIS_FEATURES], dtype=float))
    score = float(
        (value - np.asarray(params["origin"])) @ np.asarray(params["axis"])
    )
    return stratum, score


def _calibration(model: dict, clean: list[dict], sham: list[dict]) -> dict:
    output = {}
    for stratum in ("low", "high"):
        clean_scores = [
            _projection(model, row)[1] for row in clean
            if _projection(model, row)[0] == stratum
        ]
        sham_scores = [
            _projection(model, row)[1] for row in sham
            if _projection(model, row)[0] == stratum
        ]
        clean_center = float(np.median(clean_scores))
        # Exactly reproduces the original static threshold before adaptation.
        allowance = float(
            max(clean_scores + sham_scores) + LOG_MARGIN - clean_center
        )
        output[stratum] = {
            "clean_center": clean_center,
            "allowance": allowance,
            "clean_scores": clean_scores,
        }
    return output


def _replay(manifest, clean, sham, test, window: int) -> list[dict]:
    model = fit_context_axis(clean, sham)
    calibration = _calibration(model, clean, sham)
    references = {
        stratum: values["clean_scores"][-window:]
        for stratum, values in calibration.items()
    }
    state_windows = {"low": [], "high": []}
    predictions = []
    for item, row in test:
        stratum, score = _projection(model, row)
        params = calibration[stratum]
        raw_center = float(np.median(references[stratum]))
        center = float(np.clip(
            raw_center,
            params["clean_center"] - params["allowance"],
            params["clean_center"] + params["allowance"],
        ))
        threshold = center + params["allowance"]
        alert = score > threshold
        accepted = not alert
        if accepted:
            references[stratum] = (references[stratum] + [score])[-window:]
            state_windows[stratum] = (
                state_windows[stratum] + [item["state"]]
            )[-window:]
        max_fraction = max(
            (
                sum(value == "hiding" for value in values) / len(values)
                if values else 0.0
            )
            for values in state_windows.values()
        )
        predictions.append({
            "boot_id": manifest["boot_id"],
            "window": window,
            "position": item["position"],
            "segment": item["segment"],
            "truth_state": item["state"],
            "condition": item["condition"],
            "context_stratum": stratum,
            "security_score": score,
            "adaptive_center": center,
            "benign_hook_allowance": params["allowance"],
            "security_threshold": threshold,
            "security_alert": alert,
            "accepted_update": accepted,
            "max_window_attack_fraction": max_fraction,
        })
    return predictions


def _metrics(predictions: list[dict]) -> tuple[list[dict], list[dict]]:
    per_boot = []
    for boot_id, window in sorted({
        (row["boot_id"], row["window"]) for row in predictions
    }):
        rows = [row for row in predictions
                if row["boot_id"] == boot_id and row["window"] == window]
        attack = [row for row in rows if row["truth_state"] == "hiding"]
        normal = [row for row in rows if row["truth_state"] != "hiding"]
        sham = [row for row in rows if row["truth_state"] == "sham"]
        unloaded = [row for row in rows if row["truth_state"] == "unloaded"]
        per_boot.append({
            "boot_id": boot_id,
            "window": window,
            "attack_recall": float(np.mean([
                row["security_alert"] for row in attack
            ])),
            "normal_fpr": float(np.mean([
                row["security_alert"] for row in normal
            ])),
            "sham_fpr": float(np.mean([
                row["security_alert"] for row in sham
            ])),
            "unloaded_fpr": float(np.mean([
                row["security_alert"] for row in unloaded
            ])),
            "attack_update_rate": float(np.mean([
                row["accepted_update"] for row in attack
            ])),
            "normal_update_rate": float(np.mean([
                row["accepted_update"] for row in normal
            ])),
            "max_window_attack_fraction": float(max(
                row["max_window_attack_fraction"] for row in rows
            )),
        })
    overall = []
    for window in WINDOWS:
        rows = [row for row in predictions if row["window"] == window]
        attack = [row for row in rows if row["truth_state"] == "hiding"]
        normal = [row for row in rows if row["truth_state"] != "hiding"]
        sham = [row for row in rows if row["truth_state"] == "sham"]
        unloaded = [row for row in rows if row["truth_state"] == "unloaded"]
        boots = [row for row in per_boot if row["window"] == window]
        overall.append({
            "window": window,
            "attack_recall": float(np.mean([
                row["security_alert"] for row in attack
            ])),
            "min_boot_attack_recall": min(row["attack_recall"] for row in boots),
            "normal_fpr": float(np.mean([
                row["security_alert"] for row in normal
            ])),
            "max_boot_normal_fpr": max(row["normal_fpr"] for row in boots),
            "sham_fpr": float(np.mean([
                row["security_alert"] for row in sham
            ])),
            "max_boot_sham_fpr": max(row["sham_fpr"] for row in boots),
            "unloaded_fpr": float(np.mean([
                row["security_alert"] for row in unloaded
            ])),
            "attack_update_rate": float(np.mean([
                row["accepted_update"] for row in attack
            ])),
            "normal_update_rate": float(np.mean([
                row["accepted_update"] for row in normal
            ])),
            "max_window_attack_fraction": max(
                row["max_window_attack_fraction"] for row in rows
            ),
        })
    return per_boot, overall


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if args.output.exists():
        raise FileExistsError(args.output)
    roots = sorted(
        path for path in args.input.iterdir()
        if path.is_dir() and path.name.startswith("boot_")
        and path.name[5:].isdigit()
    )
    if len(roots) != 5:
        raise ValueError(f"expected five boot directories, got {len(roots)}")
    predictions = []
    for root in roots:
        manifest, clean, sham, test = _load_boot(root)
        for window in WINDOWS:
            predictions.extend(_replay(
                manifest, clean, sham, test, window
            ))
    per_boot, overall = _metrics(predictions)
    args.output.mkdir(parents=True)
    _write_csv(args.output / "predictions.csv", predictions)
    _write_csv(args.output / "per_boot_metrics.csv", per_boot)
    _write_csv(args.output / "overall_metrics.csv", overall)
    report = {
        "status": "D6_post_D5_method_development_only",
        "warning": "Sensitivity analysis on D5; not independent confirmation.",
        "fit": {
            "axis_and_allowance": "boot-local clean/sham calibration only",
            "adaptive_center": "median of accepted scores in one context-specific window",
            "movement_bound": "plus/minus one calibrated benign-hook allowance",
            "attack_labels_used_for_fit_or_threshold": False,
            "windows_are_independent_sensitivity_conditions": list(WINDOWS),
        },
        "overall": overall,
    }
    (args.output / "report.json").write_text(
        json.dumps(report, indent=2), encoding="utf-8"
    )
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
