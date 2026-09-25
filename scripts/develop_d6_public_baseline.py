#!/usr/bin/env python3
"""Develop and freeze Trace-of-the-Times-style baselines on D5.

The public baseline core is reproduced as batch quantiles followed by a
Mahalanobis shift detector.  ``fixed_public_core`` retains its initial normal
model; ``blind_public_w50`` refits on the most recent 50 batches and accepts
every observation.  Thresholds are optimized on D5 only and are intended to be
frozen before D6.  Consequently, this file reports development results, never
independent confirmation.

The public paper/code optimizes a threshold on evaluated labels.  Here that
optimization is confined to D5 so the eventual D6 comparison can be genuinely
out of sample.
"""

from __future__ import annotations

import argparse
import gzip
import json
from pathlib import Path

import numpy as np

from analyze_d4_qualification import _extract, _write_csv
from d4_context_axis import fit_context_axis, score_context_axis
from kicba.detector import ShiftDetector


WINDOW = 50
QUANTILES = np.arange(0.1, 1.0, 0.1)
METHODS = (
    "fixed_public_empirical",
    "blind_public_empirical_w50",
    "fixed_public_oas",
    "blind_public_oas_w50",
)


def _batch_values(record: dict) -> np.ndarray:
    transactions = record["transaction_durations"]
    first = np.asarray([
        item["first_raw_wall_ns"] for item in transactions
    ], dtype=float)
    last = np.asarray([
        item["last_raw_wall_ns"] for item in transactions
    ], dtype=float)
    if len(first) < len(QUANTILES) or len(last) < len(QUANTILES):
        raise ValueError("not enough transaction durations for q9")
    return np.stack((
        np.quantile(first, QUANTILES),
        np.quantile(last, QUANTILES),
    ))


def _load(root: Path):
    manifests = list(root.glob("campaign_*.json"))
    if len(manifests) != 1:
        raise ValueError(f"manifest count in {root}")
    manifest = json.loads(manifests[0].read_text(encoding="utf-8"))
    raw_by_position = {}
    extracted_by_position = {}
    for path in root.glob("batch_*.json.gz"):
        with gzip.open(path, "rt", encoding="utf-8") as handle:
            record = json.load(handle)
        position = int(record["collection"]["campaign_position"])
        raw_by_position[position] = _batch_values(record)
        extracted_by_position[position] = _extract(path)
    initial = []
    clean = []
    sham = []
    test = []
    for item in manifest["schedule"]:
        position = int(item["position"])
        if item["phase"] == "calibration":
            if item["state"] == "unloaded":
                initial.append(raw_by_position[position])
                clean.append(extracted_by_position[position])
            else:
                sham.append(extracted_by_position[position])
        else:
            test.append((
                item, raw_by_position[position], extracted_by_position[position]
            ))
    return manifest, np.stack(initial), clean, sham, test


def _replay_public(manifest: dict, initial: np.ndarray, test: list) -> list[dict]:
    predictions = []
    for method in METHODS:
        covariance = "oas" if "_oas" in method else "empirical"
        blind = method.startswith("blind_")
        fixed = ShiftDetector(covariance=covariance).fit(initial)
        window = [row.copy() for row in initial[-WINDOW:]]
        labels = ["unloaded"] * len(window)
        for item, values, _ in test:
            model = (
                ShiftDetector(covariance=covariance).fit(np.stack(window))
                if blind else fixed
            )
            score = model.max_distance_squared(values)
            if blind:
                window = (window + [values.copy()])[-WINDOW:]
                labels = (labels + [item["state"]])[-WINDOW:]
            predictions.append({
                "boot_id": manifest["boot_id"],
                "method": method,
                "position": item["position"],
                "segment": item["segment"],
                "truth_state": item["state"],
                "condition": item["condition"],
                "score": score,
                "updated": blind,
                "window_attack_fraction": (
                    sum(value == "hiding" for value in labels) / len(labels)
                ),
            })
    return predictions


def _replay_proposed(manifest: dict, clean: list[dict], sham: list[dict],
                     test: list) -> list[dict]:
    model = fit_context_axis(clean, sham)
    windows = {"low": [], "high": []}
    predictions = []
    for item, _, row in test:
        stratum, score, threshold, alert = score_context_axis(model, row)
        accepted = not alert
        if accepted:
            windows[stratum] = (windows[stratum] + [item["state"]])[-WINDOW:]
        predictions.append({
            "boot_id": manifest["boot_id"],
            "method": "proposed_static_security_gate",
            "position": item["position"],
            "segment": item["segment"],
            "truth_state": item["state"],
            "condition": item["condition"],
            "score": score,
            "threshold": threshold,
            "alert": alert,
            "updated": accepted,
            "window_attack_fraction": max(
                (
                    sum(value == "hiding" for value in values) / len(values)
                    if values else 0.0
                )
                for values in windows.values()
            ),
        })
    return predictions


def _classification(truth: np.ndarray, predicted: np.ndarray) -> dict:
    tp = int(np.sum(truth & predicted))
    fn = int(np.sum(truth & ~predicted))
    fp = int(np.sum(~truth & predicted))
    tn = int(np.sum(~truth & ~predicted))
    recall = tp / (tp + fn) if tp + fn else float("nan")
    fpr = fp / (fp + tn) if fp + tn else float("nan")
    precision = tp / (tp + fp) if tp + fp else 0.0
    f1 = (
        2 * precision * recall / (precision + recall)
        if precision + recall else 0.0
    )
    return {"tp": tp, "fn": fn, "fp": fp, "tn": tn,
            "recall": recall, "fpr": fpr, "precision": precision, "f1": f1}


def _optimize(rows: list[dict]) -> tuple[float, dict]:
    scores = np.asarray([row["score"] for row in rows], dtype=float)
    truth = np.asarray([
        row["truth_state"] == "hiding" for row in rows
    ], dtype=bool)
    finite = np.unique(scores[np.isfinite(scores)])
    candidates = np.concatenate((
        [np.nextafter(finite[0], -np.inf)],
        (finite[:-1] + finite[1:]) / 2,
        [np.nextafter(finite[-1], np.inf)],
    ))
    best = None
    best_threshold = float("nan")
    for threshold in candidates:
        metrics = _classification(truth, ~np.isfinite(scores) | (scores > threshold))
        key = (metrics["f1"], -metrics["fpr"], metrics["recall"])
        if best is None or key > best[0]:
            best = (key, metrics)
            best_threshold = float(threshold)
    return best_threshold, best[1]


def _metrics(predictions: list[dict]) -> list[dict]:
    output = []
    for method in sorted({row["method"] for row in predictions}):
        rows = [row for row in predictions if row["method"] == method]
        attack = [row for row in rows if row["truth_state"] == "hiding"]
        normal = [row for row in rows if row["truth_state"] != "hiding"]
        sham = [row for row in rows if row["truth_state"] == "sham"]
        output.append({
            "method": method,
            "attack_recall": float(np.mean([row["alert"] for row in attack])),
            "normal_fpr": float(np.mean([row["alert"] for row in normal])),
            "sham_fpr": float(np.mean([row["alert"] for row in sham])),
            "attack_update_rate": float(np.mean([
                row["updated"] for row in attack
            ])),
            "normal_update_rate": float(np.mean([
                row["updated"] for row in normal
            ])),
            "max_window_attack_fraction": float(max(
                row["window_attack_fraction"] for row in rows
            )),
        })
    return output


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
        raise ValueError(f"expected five boots, got {len(roots)}")
    public_rows = []
    proposed_rows = []
    for root in roots:
        manifest, initial, clean, sham, test = _load(root)
        # D5 collected 24 clean calibration batches, whereas the frozen D6
        # protocol collects 50.  Complete the D5 development initialization
        # with the earliest pre-attack unloaded batches, then exclude those
        # rows from every method's development score.  This matches the D6
        # model sample size without using any attack observation.
        needed = WINDOW - len(initial)
        initial_positions = {
            item[0]["position"] for item in test
            if item[0]["state"] == "unloaded"
        }
        selected_positions = set(sorted(initial_positions)[:needed])
        if len(selected_positions) != needed:
            raise ValueError("not enough pre-attack normal rows for W50")
        extra_initial = np.stack([
            values for item, values, _ in test
            if item["position"] in selected_positions
        ])
        initial_w50 = np.concatenate((initial, extra_initial), axis=0)
        evaluation_test = [
            item for item in test if item[0]["position"] not in selected_positions
        ]
        public_rows.extend(_replay_public(manifest, initial_w50, evaluation_test))
        proposed_rows.extend(_replay_proposed(
            manifest, clean, sham, evaluation_test
        ))

    thresholds = {}
    optimized = {}
    for method in METHODS:
        rows = [row for row in public_rows if row["method"] == method]
        threshold, development_metrics = _optimize(rows)
        thresholds[method] = threshold
        optimized[method] = development_metrics
        for row in rows:
            row["threshold"] = threshold
            row["alert"] = (not np.isfinite(row["score"])) or row["score"] > threshold

    predictions = public_rows + proposed_rows
    overall = _metrics(predictions)
    args.output.mkdir(parents=True)
    _write_csv(args.output / "predictions.csv", predictions)
    _write_csv(args.output / "overall_metrics.csv", overall)
    lock_candidate = {
        "source": "D5 development only",
        "public_core": {
            "quantiles": QUANTILES.tolist(),
            "intervals": ["first_iterate_dir", "last_iterate_dir"],
            "covariance_variants": ["empirical_public", "oas_strengthened"],
            "distance": "maximum interval Mahalanobis squared distance",
            "blind_window": WINDOW,
            "D5_development_initialization": (
                "24 clean calibration plus earliest 26 pre-attack unloaded; "
                "those 26 are excluded from all D5 development scores"
            ),
            "thresholds_selected_on_D5_then_frozen_for_D6": thresholds,
        },
        "optimized_D5_metrics": optimized,
    }
    (args.output / "baseline_lock_candidate.json").write_text(
        json.dumps(lock_candidate, indent=2), encoding="utf-8"
    )
    report = {
        "status": "D6_post_D5_method_development_only",
        "warning": (
            "Baseline thresholds were optimized on D5. Only a future frozen "
            "D6 evaluation is confirmatory."
        ),
        "relationship_to_public_code": (
            "Reproduces q9 Mahalanobis shift core and blind W50 update; D5 role "
            "aggregate provides first/last iterate_dir intervals rather than the "
            "public repository's full event grouping."
        ),
        "thresholds": thresholds,
        "overall": overall,
    }
    (args.output / "report.json").write_text(
        json.dumps(report, indent=2), encoding="utf-8"
    )
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
