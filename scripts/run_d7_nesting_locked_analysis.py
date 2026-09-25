#!/usr/bin/env python3
"""One-shot locked analysis for D7 nesting confirmation."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import math
import statistics
from pathlib import Path

import numpy as np


PROTOCOL = "D7-nesting-confirmatory-r1-2026-09-21"
STRUCTURAL = "nesting_invariant"
TIMING = "frozen_pass_calibrated_timing"
STATES = ("unloaded", "pass", "active", "hiding")


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _timing_features(transactions: list[dict]) -> tuple[float, float]:
    first = np.asarray(
        [row["first_raw_wall_ns"] for row in transactions], dtype=float
    )
    last = np.asarray(
        [row["last_raw_wall_ns"] for row in transactions], dtype=float
    )
    return float(np.median(first)), float(np.median(first / last))


def _score_timing(model: dict, transactions: list[dict]) -> tuple[float, bool]:
    values = np.log(np.asarray(_timing_features(transactions), dtype=float))
    origin = np.asarray(model["origin"], dtype=float)
    axis = np.asarray(model["axis"], dtype=float)
    score = float((values - origin) @ axis)
    return score, score > float(model["threshold"])


def _metrics(rows: list[dict], method: str) -> dict:
    alerts = [row for row in rows if row["method"] == method]
    by_state = {
        state: [row for row in alerts if row["state"] == state]
        for state in STATES
    }
    rates = {
        state: sum(row["alert"] for row in state_rows) / len(state_rows)
        for state, state_rows in by_state.items()
    }
    tp = sum(row["alert"] for row in by_state["hiding"])
    fn = len(by_state["hiding"]) - tp
    controls = [
        row for state in ("unloaded", "pass", "active")
        for row in by_state[state]
    ]
    fp = sum(row["alert"] for row in controls)
    tn = len(controls) - fp
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {
        "method": method,
        "n": len(alerts),
        "tp": tp, "fn": fn, "fp": fp, "tn": tn,
        "hiding_recall": recall,
        "unloaded_fpr": rates["unloaded"],
        "pass_fpr": rates["pass"],
        "active_fpr": rates["active"],
        "hiding_active_separation": recall - rates["active"],
        "non_attack_fpr": fp / len(controls),
        "precision": precision,
        "f1": f1,
    }


def _bootstrap_ci(values: list[float], seed: int) -> list[float]:
    array = np.asarray(values, dtype=float)
    rng = np.random.default_rng(seed)
    draws = rng.choice(array, size=(20_000, len(array)), replace=True).mean(1)
    return [float(np.quantile(draws, 0.025)), float(np.quantile(draws, 0.975))]


def _wilson(successes: int, total: int) -> list[float]:
    z = 1.959963984540054
    p = successes / total
    denominator = 1 + z * z / total
    center = (p + z * z / (2 * total)) / denominator
    half = z * math.sqrt(p * (1 - p) / total + z * z / (4 * total * total))
    half /= denominator
    return [max(0.0, center - half), min(1.0, center + half)]


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
        raise RuntimeError("state is not complete D7")
    if audit.get("protocol") != PROTOCOL or audit.get("status") != "PASS":
        raise RuntimeError("D7 audit did not pass")
    if audit.get("state_sha256") != _sha256(args.state):
        raise RuntimeError("state changed after audit")
    model_path = Path(lock["timing_comparator"]["path"])
    if _sha256(model_path) != lock["timing_comparator"]["sha256"]:
        raise RuntimeError("timing model hash mismatch")
    model = json.loads(model_path.read_text(encoding="utf-8"))
    rows = []
    boot_dirs = sorted(
        path for path in args.input.iterdir()
        if path.is_dir() and path.name.startswith("boot_")
    )
    if len(boot_dirs) != 8:
        raise ValueError(f"expected eight boots, got {len(boot_dirs)}")
    for root in boot_dirs:
        manifest_path = next(root.glob("campaign_*.json"))
        if audit["manifest_sha256"].get(root.name) != _sha256(manifest_path):
            raise RuntimeError(f"manifest changed after audit: {root.name}")
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        boot_id = manifest["boot_id"]
        for path in sorted(root.glob("batch_*.json.gz")):
            with gzip.open(path, "rt", encoding="utf-8") as handle:
                record = json.load(handle)
            truth = record["truth"]
            transactions = record["transactions"]
            structural = any(
                row["forwarded_top_calls"] > 0
                and row["short_circuit_top_calls"] > 0
                for row in transactions
            )
            timing_score, timing_alert = _score_timing(model, transactions)
            common = {
                "boot_id": boot_id,
                "batch_id": record["batch_id"],
                "state": truth["state"],
                "condition": truth["condition"],
            }
            rows.append({
                **common, "method": STRUCTURAL, "alert": structural,
                "score": None, "threshold": None,
            })
            rows.append({
                **common, "method": TIMING, "alert": timing_alert,
                "score": timing_score, "threshold": model["threshold"],
            })
    overall = [_metrics(rows, method) for method in (STRUCTURAL, TIMING)]
    by_method = {row["method"]: row for row in overall}
    boot_ids = sorted({row["boot_id"] for row in rows})
    per_boot = []
    for boot_id in boot_ids:
        subset = [row for row in rows if row["boot_id"] == boot_id]
        per_boot.extend(_metrics(subset, method) for method in (STRUCTURAL, TIMING))
        per_boot[-2]["boot_id"] = boot_id
        per_boot[-1]["boot_id"] = boot_id
    boot_metric = {
        method: {
            row["boot_id"]: row
            for row in per_boot if row["method"] == method
        }
        for method in (STRUCTURAL, TIMING)
    }
    differences = {}
    for metric, seed in (
        ("hiding_recall", 202609211),
        ("active_fpr", 202609212),
        ("non_attack_fpr", 202609213),
        ("f1", 202609214),
        ("hiding_active_separation", 202609215),
    ):
        values = [
            boot_metric[STRUCTURAL][boot_id][metric]
            - boot_metric[TIMING][boot_id][metric]
            for boot_id in boot_ids
        ]
        differences[metric] = {
            "proposed_minus_timing_per_boot": values,
            "mean": statistics.fmean(values),
            "boot_cluster_bootstrap_95_ci": _bootstrap_ci(values, seed),
        }
    proposed = by_method[STRUCTURAL]
    timing = by_method[TIMING]
    proposed["hiding_recall_wilson_95_ci"] = _wilson(
        proposed["tp"], proposed["tp"] + proposed["fn"]
    )
    for key, state_name in (
        ("unloaded_fpr_wilson_95_ci", "unloaded"),
        ("pass_fpr_wilson_95_ci", "pass"),
        ("active_fpr_wilson_95_ci", "active"),
    ):
        state_rows = [
            row for row in rows
            if row["method"] == STRUCTURAL and row["state"] == state_name
        ]
        proposed[key] = _wilson(
            sum(row["alert"] for row in state_rows), len(state_rows)
        )
    max_boot_fpr = max(
        max(
            row[metric] for metric in (
                "unloaded_fpr", "pass_fpr", "active_fpr"
            )
        )
        for row in per_boot if row["method"] == STRUCTURAL
    )
    min_boot_recall = min(
        row["hiding_recall"]
        for row in per_boot if row["method"] == STRUCTURAL
    )
    rules = {
        "eight_unique_boots": len(boot_ids) == 8,
        "hiding_recall_ge_0_95": proposed["hiding_recall"] >= 0.95,
        "min_boot_hiding_recall_ge_0_90": min_boot_recall >= 0.90,
        "unloaded_fpr_le_0_05": proposed["unloaded_fpr"] <= 0.05,
        "pass_fpr_le_0_05": proposed["pass_fpr"] <= 0.05,
        "active_fpr_le_0_05": proposed["active_fpr"] <= 0.05,
        "max_boot_control_fpr_le_0_10": max_boot_fpr <= 0.10,
        "hiding_active_separation_ge_0_90": (
            proposed["hiding_active_separation"] >= 0.90
        ),
        "separation_margin_vs_timing_ge_0_30": (
            proposed["hiding_active_separation"]
            - timing["hiding_active_separation"] >= 0.30
        ),
        "paired_separation_difference_ci_lower_gt_0": (
            differences["hiding_active_separation"][
                "boot_cluster_bootstrap_95_ci"
            ][0] > 0
        ),
        "paired_active_fpr_noninferiority_ci_upper_le_0_05": (
            differences["active_fpr"]["boot_cluster_bootstrap_95_ci"][1]
            <= 0.05
        ),
        "paired_recall_difference_ci_lower_ge_0": (
            differences["hiding_recall"]["boot_cluster_bootstrap_95_ci"][0] >= 0
        ),
        "f1_margin_vs_timing_ge_0_20": proposed["f1"] - timing["f1"] >= 0.20,
    }
    overhead_path = Path(lock["overhead_evidence"]["path"])
    if _sha256(overhead_path) != lock["overhead_evidence"]["sha256"]:
        raise RuntimeError("overhead evidence hash mismatch")
    overhead = json.loads(overhead_path.read_text(encoding="utf-8"))
    report = {
        "protocol": PROTOCOL,
        "status": "one_shot_confirmatory",
        "method_scope": (
            "Selective same-symbol callback short-circuiting in the tested "
            "CARAXES-like ftrace path; not universal rootkit detection."
        ),
        "boots": len(boot_ids),
        "batches": len(rows) // 2,
        "decision_rule": (
            "alert iff forwarded_top_calls > 0 and "
            "short_circuit_top_calls > 0 in one listing"
        ),
        "overall": overall,
        "per_boot": per_boot,
        "paired_proposed_minus_timing": differences,
        "min_boot_hiding_recall": min_boot_recall,
        "max_boot_control_fpr": max_boot_fpr,
        "rules": rules,
        "method_efficacy_pass": all(rules.values()),
        "deployment": {
            "periodic_diagnostic_rule": overhead["deployment_rule"],
            "relative_operation_latency": overhead["summary"],
            "legacy_continuous_operation_latency_rule": (
                "FAIL: baseline mean relative overhead exceeds 5%"
            ),
        },
    }
    args.output.mkdir(parents=True)
    (args.output / "predictions.json").write_text(
        json.dumps(rows, indent=2), encoding="utf-8"
    )
    (args.output / "report.json").write_text(
        json.dumps(report, indent=2), encoding="utf-8"
    )
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
