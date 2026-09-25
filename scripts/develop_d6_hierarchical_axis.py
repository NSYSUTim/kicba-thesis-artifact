#!/usr/bin/env python3
"""Leave-one-boot-out development of a hierarchical negative-control axis.

The security direction is learned from clean-versus-sham calibration effects in
the *other* boots.  The held-out boot contributes only its benign clean/sham
calibration rows to estimate a local origin and a one-sided benign envelope.
Attack labels are used solely for evaluation.

This is post-D5 method development, not an independent confirmation.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import numpy as np

from analyze_d4_qualification import _write_csv
from d4_context_axis import AXIS_FEATURES, fit_context_axis, score_context_axis
from develop_d6_factorized_method import LOG_MARGIN, WINDOW, _load_boot


def _rows_in_stratum(rows: list[dict], split: float, stratum: str) -> list[dict]:
    if stratum == "low":
        return [row for row in rows if row["cpu_busy_fraction"] < split]
    return [row for row in rows if row["cpu_busy_fraction"] >= split]


def _unit_effect(clean: list[dict], sham: list[dict], split: float,
                 stratum: str) -> np.ndarray:
    clean_rows = _rows_in_stratum(clean, split, stratum)
    sham_rows = _rows_in_stratum(sham, split, stratum)
    clean_x = np.log(np.asarray([
        [row[name] for name in AXIS_FEATURES] for row in clean_rows
    ], dtype=float))
    sham_x = np.log(np.asarray([
        [row[name] for name in AXIS_FEATURES] for row in sham_rows
    ], dtype=float))
    effect = np.mean(sham_x, axis=0) - np.mean(clean_x, axis=0)
    norm = float(np.linalg.norm(effect))
    if norm <= 1e-9:
        raise ValueError(f"degenerate {stratum} clean-to-sham effect")
    return effect / norm


def _fit_hierarchical_axis(training: list[tuple], clean: list[dict],
                           sham: list[dict]) -> dict:
    local = fit_context_axis(clean, sham)
    target_split = float(local["context_split"])
    model = {"context_split": target_split, "strata": {}}
    for stratum in ("low", "high"):
        effects = []
        for _, train_clean, train_sham, _ in training:
            train_model = fit_context_axis(train_clean, train_sham)
            effects.append(_unit_effect(
                train_clean, train_sham,
                float(train_model["context_split"]), stratum,
            ))
        axis = np.mean(np.asarray(effects), axis=0)
        norm = float(np.linalg.norm(axis))
        if norm <= 1e-9:
            raise ValueError(f"pooled {stratum} effects cancel")
        axis /= norm

        clean_rows = _rows_in_stratum(clean, target_split, stratum)
        sham_rows = _rows_in_stratum(sham, target_split, stratum)
        clean_x = np.log(np.asarray([
            [row[name] for name in AXIS_FEATURES] for row in clean_rows
        ], dtype=float))
        sham_x = np.log(np.asarray([
            [row[name] for name in AXIS_FEATURES] for row in sham_rows
        ], dtype=float))
        origin = np.mean(clean_x, axis=0)
        benign = np.vstack((clean_x, sham_x))
        projections = (benign - origin) @ axis
        model["strata"][stratum] = {
            "origin": origin.tolist(),
            "axis": axis.tolist(),
            "threshold": float(np.max(projections) + LOG_MARGIN),
            "training_boots": len(training),
            "target_clean_n": len(clean_rows),
            "target_sham_n": len(sham_rows),
        }
    return model


def _score(model: dict, row: dict) -> tuple[str, float, float, bool]:
    stratum = (
        "low" if row["cpu_busy_fraction"] < model["context_split"] else "high"
    )
    params = model["strata"][stratum]
    value = np.log(np.asarray([row[name] for name in AXIS_FEATURES], dtype=float))
    score = float(
        (value - np.asarray(params["origin"])) @ np.asarray(params["axis"])
    )
    threshold = float(params["threshold"])
    return stratum, score, threshold, score > threshold


def _evaluate(loaded: list[tuple]) -> tuple[list[dict], list[dict]]:
    predictions: list[dict] = []
    models: list[dict] = []
    for target_index, (manifest, clean, sham, test) in enumerate(loaded):
        local_model = fit_context_axis(clean, sham)
        training = [item for index, item in enumerate(loaded) if index != target_index]
        hierarchical_model = _fit_hierarchical_axis(training, clean, sham)
        for gate, model in (
            ("local_axis", local_model),
            ("lobo_hierarchical_axis", hierarchical_model),
        ):
            models.append({
                "boot_id": manifest["boot_id"],
                "gate": gate,
                "model": json.dumps(model, sort_keys=True),
            })
            windows = {"low": [], "high": []}
            for item, row in test:
                if gate == "local_axis":
                    stratum, score, threshold, alert = score_context_axis(model, row)
                else:
                    stratum, score, threshold, alert = _score(model, row)
                accepted = not alert
                if accepted:
                    windows[stratum] = (
                        windows[stratum] + [item["state"]]
                    )[-WINDOW:]
                max_fraction = max(
                    (
                        sum(value == "hiding" for value in values) / len(values)
                        if values else 0.0
                    )
                    for values in windows.values()
                )
                predictions.append({
                    "boot_id": manifest["boot_id"],
                    "gate": gate,
                    "position": item["position"],
                    "segment": item["segment"],
                    "truth_state": item["state"],
                    "condition": item["condition"],
                    "context_stratum": stratum,
                    "security_score": score,
                    "security_threshold": threshold,
                    "security_alert": alert,
                    "accepted_update": accepted,
                    "max_window_attack_fraction": max_fraction,
                })
    return predictions, models


def _metrics(predictions: list[dict]) -> tuple[list[dict], list[dict]]:
    per_boot = []
    for boot_id, gate in sorted({
        (row["boot_id"], row["gate"]) for row in predictions
    }):
        rows = [row for row in predictions
                if row["boot_id"] == boot_id and row["gate"] == gate]
        attack = [row for row in rows if row["truth_state"] == "hiding"]
        normal = [row for row in rows if row["truth_state"] != "hiding"]
        sham = [row for row in rows if row["truth_state"] == "sham"]
        unloaded = [row for row in rows if row["truth_state"] == "unloaded"]
        per_boot.append({
            "boot_id": boot_id,
            "gate": gate,
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
    for gate in sorted({row["gate"] for row in predictions}):
        rows = [row for row in predictions if row["gate"] == gate]
        attack = [row for row in rows if row["truth_state"] == "hiding"]
        normal = [row for row in rows if row["truth_state"] != "hiding"]
        sham = [row for row in rows if row["truth_state"] == "sham"]
        unloaded = [row for row in rows if row["truth_state"] == "unloaded"]
        boot = [row for row in per_boot if row["gate"] == gate]
        overall.append({
            "gate": gate,
            "attack_recall": float(np.mean([
                row["security_alert"] for row in attack
            ])),
            "min_boot_attack_recall": min(row["attack_recall"] for row in boot),
            "normal_fpr": float(np.mean([
                row["security_alert"] for row in normal
            ])),
            "max_boot_normal_fpr": max(row["normal_fpr"] for row in boot),
            "sham_fpr": float(np.mean([
                row["security_alert"] for row in sham
            ])),
            "max_boot_sham_fpr": max(row["sham_fpr"] for row in boot),
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
    loaded = [_load_boot(root) for root in roots]
    predictions, models = _evaluate(loaded)
    per_boot, overall = _metrics(predictions)
    args.output.mkdir(parents=True)
    _write_csv(args.output / "predictions.csv", predictions)
    _write_csv(args.output / "models.csv", models)
    _write_csv(args.output / "per_boot_metrics.csv", per_boot)
    _write_csv(args.output / "overall_metrics.csv", overall)
    report = {
        "status": "D6_post_D5_method_development_only",
        "warning": (
            "Leave-one-boot-out development on D5; not independent confirmation."
        ),
        "fit": (
            "Security direction from clean-vs-sham effects in four training boots; "
            "held-out boot supplies only benign clean/sham origin and threshold; "
            "attack labels are evaluation-only."
        ),
        "overall": overall,
    }
    (args.output / "report.json").write_text(
        json.dumps(report, indent=2), encoding="utf-8"
    )
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
