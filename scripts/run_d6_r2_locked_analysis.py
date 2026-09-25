#!/usr/bin/env python3
"""One-shot locked D6-r2 confirmatory analysis."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

import numpy as np

from analyze_d4_qualification import _write_csv
from d6_r2_analysis_core import (
    PROPOSED,
    PROTOCOL,
    load_boot,
    overall_metrics,
    per_boot_metrics,
    replay_proposed,
    replay_public,
)


PRIMARY_FIXED = "fixed_public_oas"
PRIMARY_BLIND = "blind_public_oas_w50"


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _bootstrap_ci(values: np.ndarray, seed: int) -> list[float]:
    rng = np.random.default_rng(seed)
    draws = rng.choice(values, size=(10_000, len(values)), replace=True).mean(1)
    return [
        float(np.quantile(draws, 0.025)),
        float(np.quantile(draws, 0.975)),
    ]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--state", required=True, type=Path)
    parser.add_argument("--lock", required=True, type=Path)
    parser.add_argument("--audit", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if args.output.exists():
        raise FileExistsError(args.output)
    lock = json.loads(args.lock.read_text(encoding="utf-8"))
    state = json.loads(args.state.read_text(encoding="utf-8"))
    audit = json.loads(args.audit.read_text(encoding="utf-8"))
    if lock.get("protocol_revision") != PROTOCOL:
        raise RuntimeError("lock protocol mismatch")
    if state.get("protocol_revision") != PROTOCOL or state.get("status") != "complete":
        raise RuntimeError("state is not complete D6-r2")
    if audit.get("protocol") != PROTOCOL or audit.get("status") != "PASS":
        raise RuntimeError("D6-r2 integrity audit did not pass")
    if audit.get("state_sha256") != _sha256(args.state):
        raise RuntimeError("state changed after D6-r2 integrity audit")

    roots = sorted(
        path for path in args.input.iterdir()
        if path.is_dir() and path.name.startswith("boot_")
    )
    if len(roots) != 5:
        raise ValueError(f"expected five boots, got {len(roots)}")
    predictions = []
    manifests = []
    for root in roots:
        manifest_paths = list(root.glob("campaign_*.json"))
        if (
            len(manifest_paths) != 1
            or audit.get("manifest_sha256", {}).get(root.name)
            != _sha256(manifest_paths[0])
        ):
            raise RuntimeError(f"manifest changed after audit: {root.name}")
        manifest, initial, clean, sham, test = load_boot(root)
        manifests.append(manifest)
        predictions.extend(replay_public(manifest, initial, test))
        predictions.extend(replay_proposed(manifest, clean, sham, test))
    if len({manifest["boot_id"] for manifest in manifests}) != 5:
        raise RuntimeError("boot IDs are not unique")

    per_boot = per_boot_metrics(predictions)
    overall = overall_metrics(predictions)
    overall_by_method = {row["method"]: row for row in overall}
    per_boot_by_method = {
        method: {
            row["boot_id"]: row for row in per_boot if row["method"] == method
        }
        for method in {PROPOSED, PRIMARY_FIXED, PRIMARY_BLIND}
    }
    boot_ids = sorted(per_boot_by_method[PROPOSED])
    for row in overall:
        method_boots = [item for item in per_boot if item["method"] == row["method"]]
        row["min_boot_attack_recall"] = min(
            item["attack_recall"] for item in method_boots
        )
        row["max_boot_sham_fpr"] = max(item["sham_fpr"] for item in method_boots)

    proposed = overall_by_method[PROPOSED]
    fixed = overall_by_method[PRIMARY_FIXED]
    blind = overall_by_method[PRIMARY_BLIND]
    fpr_differences = np.asarray([
        per_boot_by_method[PROPOSED][boot]["unloaded_normal_fpr"]
        - per_boot_by_method[PRIMARY_FIXED][boot]["unloaded_normal_fpr"]
        for boot in boot_ids
    ], dtype=float)
    recall_differences = np.asarray([
        per_boot_by_method[PROPOSED][boot]["attack_recall"]
        - per_boot_by_method[PRIMARY_FIXED][boot]["attack_recall"]
        for boot in boot_ids
    ], dtype=float)
    fpr_ci = _bootstrap_ci(fpr_differences, 20260920)
    recall_ci = _bootstrap_ci(recall_differences, 20260921)

    rules = {
        "five_unique_boots": True,
        "proposed_recall_ge_0_95": proposed["attack_recall"] >= 0.95,
        "min_boot_recall_ge_0_90": proposed["min_boot_attack_recall"] >= 0.90,
        "unloaded_normal_fpr_le_0_05": proposed["unloaded_normal_fpr"] <= 0.05,
        "sham_fpr_le_0_20": proposed["sham_fpr"] <= 0.20,
        "max_boot_sham_fpr_le_0_30": proposed["max_boot_sham_fpr"] <= 0.30,
        "attack_update_rate_le_0_05": proposed["attack_update_rate"] <= 0.05,
        "unloaded_update_rate_ge_0_95": proposed["unloaded_update_rate"] >= 0.95,
        "max_window_attack_fraction_le_0_20": (
            proposed["max_window_attack_fraction"] <= 0.20
        ),
        "unknown_rate_eq_0": proposed["unknown_rate"] == 0.0,
        "f1_margin_vs_fixed_oas_ge_0_05": proposed["f1"] - fixed["f1"] >= 0.05,
        "unloaded_fpr_reduction_vs_fixed_oas_ge_0_10": (
            fixed["unloaded_normal_fpr"]
            - proposed["unloaded_normal_fpr"] >= 0.10
        ),
        "paired_unloaded_fpr_ci_upper_le_minus_0_05": fpr_ci[1] <= -0.05,
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
        "metric_definitions": {
            "unloaded_normal_fpr": "alerts among state=unloaded only",
            "sham_fpr": "alerts among state=sham only",
            "non_attack_fpr": "alerts among unloaded+sham",
            "rootkit_alert": "security gate only for proposed method",
            "operational_metrics": "secondary descriptive endpoints",
        },
        "overall": overall,
        "paired_proposed_minus_fixed_oas": {
            "unloaded_normal_fpr_mean": float(np.mean(fpr_differences)),
            "unloaded_normal_fpr_bootstrap_95_ci": fpr_ci,
            "attack_recall_mean": float(np.mean(recall_differences)),
            "attack_recall_bootstrap_95_ci": recall_ci,
        },
        "rules": rules,
        "method_efficacy_pass": all(rules.values()),
        "deployment_overhead": {
            "status": "FAIL",
            "rule": "operation latency overhead <= 0.05",
            "existing_role_aggregate_range": [0.113038, 0.473043],
            "interpretation": "separate deployment endpoint; not remeasured in D6-r2",
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
