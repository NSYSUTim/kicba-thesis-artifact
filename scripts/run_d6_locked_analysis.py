#!/usr/bin/env python3
"""Locked one-shot D6 confirmatory comparison."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

import numpy as np

from analyze_d4_qualification import _write_csv
from develop_d6_public_baseline import (
    METHODS,
    _load,
    _metrics,
    _replay_proposed,
    _replay_public,
)


PROTOCOL = "D6-r1-2026-09-20"
BASELINE_THRESHOLDS = {
    "fixed_public_empirical": 28.17319410417818,
    "blind_public_empirical_w50": 2.6102339930684484,
    "fixed_public_oas": 20.146773583634662,
    "blind_public_oas_w50": 0.8825466351416513,
}
PRIMARY_BASELINE = "fixed_public_oas"
BLIND_BASELINE = "blind_public_oas_w50"


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _f1(rows: list[dict]) -> float:
    truth = np.asarray([
        row["truth_state"] == "hiding" for row in rows
    ], dtype=bool)
    predicted = np.asarray([row["alert"] for row in rows], dtype=bool)
    true_positive = int(np.sum(truth & predicted))
    false_positive = int(np.sum(~truth & predicted))
    false_negative = int(np.sum(truth & ~predicted))
    precision = (
        true_positive / (true_positive + false_positive)
        if true_positive + false_positive else 0.0
    )
    recall = (
        true_positive / (true_positive + false_negative)
        if true_positive + false_negative else 0.0
    )
    return (
        2 * precision * recall / (precision + recall)
        if precision + recall else 0.0
    )


def _per_boot(predictions: list[dict]) -> list[dict]:
    output = []
    for boot_id, method in sorted({
        (row["boot_id"], row["method"]) for row in predictions
    }):
        rows = [row for row in predictions
                if row["boot_id"] == boot_id and row["method"] == method]
        attack = [row for row in rows if row["truth_state"] == "hiding"]
        normal = [row for row in rows if row["truth_state"] != "hiding"]
        sham = [row for row in rows if row["truth_state"] == "sham"]
        output.append({
            "boot_id": boot_id,
            "method": method,
            "attack_n": len(attack),
            "attack_recall": float(np.mean([row["alert"] for row in attack])),
            "normal_n": len(normal),
            "normal_fpr": float(np.mean([row["alert"] for row in normal])),
            "sham_n": len(sham),
            "sham_fpr": float(np.mean([row["alert"] for row in sham])),
            "f1": _f1(rows),
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


def _bootstrap_ci(values: np.ndarray, seed: int = 20260920) -> list[float]:
    rng = np.random.default_rng(seed)
    draws = rng.choice(values, size=(10_000, len(values)), replace=True).mean(1)
    return [
        float(np.quantile(draws, 0.025)),
        float(np.quantile(draws, 0.975)),
    ]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--lock", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if args.output.exists():
        raise FileExistsError(args.output)
    lock = json.loads(args.lock.read_text(encoding="utf-8"))
    if lock.get("protocol_revision") != PROTOCOL:
        raise RuntimeError("analysis lock protocol mismatch")
    for name, item in lock["files"].items():
        actual = _sha256(Path(item["path"]))
        if actual != item["sha256"]:
            raise RuntimeError(f"hash mismatch {name}: {actual}")

    roots = sorted(
        path for path in args.input.iterdir()
        if path.is_dir() and path.name.startswith("boot_")
        and path.name[5:].isdigit()
    )
    if len(roots) != 5:
        raise ValueError(f"expected five boots, got {len(roots)}")
    public_rows = []
    proposed_rows = []
    manifests = []
    for root in roots:
        manifest, initial, clean, sham, test = _load(root)
        if (
            manifest.get("protocol_revision") != PROTOCOL
            or manifest.get("status") != "complete"
            or len(manifest.get("schedule", [])) != 460
        ):
            raise RuntimeError(f"invalid D6 manifest in {root}")
        if (
            manifest.get("hiding_sha256") != lock["module_hashes"]["hiding"]
            or manifest.get("sham_sha256") != lock["module_hashes"]["sham"]
        ):
            raise RuntimeError(f"module hash mismatch in {root}")
        manifests.append(manifest)
        public_rows.extend(_replay_public(manifest, initial, test))
        proposed_rows.extend(_replay_proposed(manifest, clean, sham, test))
    if len({manifest["boot_id"] for manifest in manifests}) != 5:
        raise RuntimeError("boot IDs are not unique")

    for row in public_rows:
        threshold = BASELINE_THRESHOLDS[row["method"]]
        row["threshold"] = threshold
        row["alert"] = (
            not np.isfinite(row["score"]) or row["score"] > threshold
        )
    predictions = public_rows + proposed_rows
    per_boot = _per_boot(predictions)
    overall = _metrics(predictions)
    for row in overall:
        method_rows = [item for item in predictions if item["method"] == row["method"]]
        row["f1"] = _f1(method_rows)
        row["min_boot_attack_recall"] = min(
            item["attack_recall"] for item in per_boot
            if item["method"] == row["method"]
        )
        row["max_boot_sham_fpr"] = max(
            item["sham_fpr"] for item in per_boot
            if item["method"] == row["method"]
        )
        row["unknown_rate"] = 0.0

    by_method = {row["method"]: row for row in overall}
    proposed = by_method["proposed_static_security_gate"]
    primary = by_method[PRIMARY_BASELINE]
    blind = by_method[BLIND_BASELINE]
    per_boot_by_method = {
        method: {
            row["boot_id"]: row for row in per_boot if row["method"] == method
        }
        for method in {PRIMARY_BASELINE, BLIND_BASELINE,
                       "proposed_static_security_gate"}
    }
    boot_ids = sorted(per_boot_by_method["proposed_static_security_gate"])
    fpr_differences = np.asarray([
        per_boot_by_method["proposed_static_security_gate"][boot]["normal_fpr"]
        - per_boot_by_method[PRIMARY_BASELINE][boot]["normal_fpr"]
        for boot in boot_ids
    ])
    recall_differences = np.asarray([
        per_boot_by_method["proposed_static_security_gate"][boot]["attack_recall"]
        - per_boot_by_method[PRIMARY_BASELINE][boot]["attack_recall"]
        for boot in boot_ids
    ])
    fpr_ci = _bootstrap_ci(fpr_differences)
    recall_ci = _bootstrap_ci(recall_differences, seed=20260921)

    rules = {
        "five_unique_boots": True,
        "proposed_recall_ge_0_95": proposed["attack_recall"] >= 0.95,
        "min_boot_recall_ge_0_90": proposed["min_boot_attack_recall"] >= 0.90,
        "proposed_normal_fpr_le_0_05": proposed["normal_fpr"] <= 0.05,
        "proposed_sham_fpr_le_0_20": proposed["sham_fpr"] <= 0.20,
        "max_boot_sham_fpr_le_0_30": proposed["max_boot_sham_fpr"] <= 0.30,
        "attack_update_rate_le_0_05": proposed["attack_update_rate"] <= 0.05,
        "normal_update_rate_ge_0_95": proposed["normal_update_rate"] >= 0.95,
        "max_window_attack_fraction_le_0_20": (
            proposed["max_window_attack_fraction"] <= 0.20
        ),
        "unknown_rate_eq_0": proposed["unknown_rate"] == 0.0,
        "f1_margin_vs_fixed_oas_ge_0_05": proposed["f1"] - primary["f1"] >= 0.05,
        "fpr_reduction_vs_fixed_oas_ge_0_10": (
            primary["normal_fpr"] - proposed["normal_fpr"] >= 0.10
        ),
        "paired_fpr_ci_upper_le_minus_0_05": fpr_ci[1] <= -0.05,
        "paired_recall_ci_lower_ge_minus_0_05": recall_ci[0] >= -0.05,
        "contamination_reduction_vs_blind_oas_ge_0_50": (
            blind["max_window_attack_fraction"]
            - proposed["max_window_attack_fraction"] >= 0.50
        ),
    }
    report = {
        "protocol": PROTOCOL,
        "status": "one_shot_confirmatory",
        "boots": 5,
        "baseline_thresholds_frozen_from_D5": BASELINE_THRESHOLDS,
        "primary_baseline": PRIMARY_BASELINE,
        "blind_baseline": BLIND_BASELINE,
        "overall": overall,
        "paired_proposed_minus_fixed_oas": {
            "normal_fpr_mean": float(np.mean(fpr_differences)),
            "normal_fpr_bootstrap_95_ci": fpr_ci,
            "attack_recall_mean": float(np.mean(recall_differences)),
            "attack_recall_bootstrap_95_ci": recall_ci,
        },
        "rules": rules,
        "method_efficacy_pass": all(rules.values()),
        "deployment_overhead": {
            "status": "separate_FAIL_until_remeasured",
            "rule": "operation latency overhead <= 0.05",
            "existing_role_aggregate_range": [0.113038, 0.473043],
        },
    }
    args.output.mkdir(parents=True)
    _write_csv(args.output / "predictions.csv", predictions)
    _write_csv(args.output / "per_boot_metrics.csv", per_boot)
    _write_csv(args.output / "overall_metrics.csv", overall)
    (args.output / "report.json").write_text(
        json.dumps(report, indent=2), encoding="utf-8"
    )
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
