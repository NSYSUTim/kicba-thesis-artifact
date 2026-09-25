from __future__ import annotations

import argparse
import csv
import json
import time
from collections import defaultdict
from pathlib import Path
from typing import Iterable

import numpy as np

from .context import ContextBatchDataset
from .d2_experiments import (
    _binary_method,
    _bootstrap_direction_p,
    _bootstrap_mean_ci,
    _decision_metrics,
    _kicba_method,
    _validate_design,
)
from .kicba import CONTEXT_FEATURES, RAW_FEATURES, RESIDUAL_FEATURES, feature_view
from .v1 import ConditionalResidualGuard, FixedResidualGate, SafeAdaptiveDetector
from .v1_features import V1BatchContextDataset


METHODS = (
    "fixed_raw",
    "blind_50_raw",
    "fixed_residual",
    "v0_kicba",
    "v1_residual_gate_w50",
    "v1_safe_adaptive_w20",
    "v1_safe_adaptive_w50",
    "v1_safe_adaptive_w100",
    "v1_update_all_w50",
    "v1_no_updates_w50",
    "v1_union_alert_w50",
)


def _write_csv(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not rows:
        raise ValueError(f"No rows for {path}")
    fields = list(rows[0])
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def _align_context(
    dataset: ContextBatchDataset, context: V1BatchContextDataset
) -> np.ndarray:
    context.validate()
    index = {batch_id: idx for idx, batch_id in enumerate(context.batch_ids.tolist())}
    if set(index) != set(dataset.batch_ids.tolist()):
        missing = set(dataset.batch_ids.tolist()) - set(index)
        extra = set(index) - set(dataset.batch_ids.tolist())
        raise ValueError(f"V1/base batch mismatch: missing={len(missing)}, extra={len(extra)}")
    order = np.asarray([index[batch_id] for batch_id in dataset.batch_ids], dtype=int)
    for base_values, context_values, name in (
        (dataset.boot_ids, context.boot_ids[order], "boot_id"),
        (dataset.labels, context.labels[order], "label"),
        (dataset.conditions, context.conditions[order], "condition"),
        (dataset.campaign_ids, context.campaign_ids[order], "campaign_id"),
        (
            dataset.campaign_positions,
            context.campaign_positions[order],
            "campaign_position",
        ),
    ):
        if not np.array_equal(base_values, context_values):
            raise ValueError(f"V1/base {name} metadata mismatch")
    if not np.array_equal(dataset.quality_valid, context.quality_valid[order]):
        raise ValueError("V1/base quality flags mismatch")
    return context.values[order]


def _chronological(indices: np.ndarray, dataset: ContextBatchDataset) -> np.ndarray:
    return np.asarray(
        sorted(
            indices.tolist(),
            key=lambda idx: (
                str(dataset.batch_ids[idx]),
                int(dataset.campaign_positions[idx]),
            ),
        ),
        dtype=int,
    )


def _campaign_order(indices: np.ndarray, dataset: ContextBatchDataset) -> np.ndarray:
    return np.asarray(
        sorted(
            indices.tolist(),
            key=lambda idx: (
                int(dataset.campaign_positions[idx]),
                str(dataset.batch_ids[idx]),
            ),
        ),
        dtype=int,
    )


def _safe_adaptive_method(
    raw_fit: np.ndarray,
    raw_calibration: np.ndarray,
    calibration_eligible: np.ndarray,
    raw_test: np.ndarray,
    test_eligible: np.ndarray,
    quality_test: np.ndarray,
    truth: np.ndarray,
    *,
    window_size: int,
    guard_alert: np.ndarray | None = None,
    union_alert: bool = False,
) -> tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray, np.ndarray]:
    model = SafeAdaptiveDetector(window_size=window_size).fit(
        raw_fit, raw_calibration, calibration_eligible
    )
    steps = []
    latencies = []
    alerts = (
        np.zeros(len(raw_test), dtype=bool)
        if guard_alert is None
        else np.asarray(guard_alert, dtype=bool)
    )
    for position in range(len(raw_test)):
        started = time.perf_counter_ns()
        step = model.step(
            raw_test[position],
            quality_valid=bool(quality_test[position]),
            update_guard_accepted=bool(test_eligible[position]),
            guard_alert_for_union=bool(alerts[position]),
            union_alert=union_alert,
            evaluation_is_attack=bool(truth[position]),
        )
        latencies.append(time.perf_counter_ns() - started)
        steps.append(step)
    return (
        np.asarray([step.decision for step in steps], dtype=str),
        np.asarray([step.updated for step in steps], dtype=bool),
        np.asarray([step.adaptive_score for step in steps], dtype=float),
        np.asarray([step.window_attack_fraction for step in steps], dtype=float),
        np.asarray(latencies, dtype=float),
    )


def _v1_metrics(
    truth: np.ndarray,
    decisions: np.ndarray,
    updated: np.ndarray,
    decision_latency_ns: np.ndarray,
    window_attack_fraction: np.ndarray,
) -> dict[str, float | int]:
    metrics = _decision_metrics(truth, decisions, updated, decision_latency_ns)
    attack_count = int(np.sum(truth))
    metrics["attack_update_acceptance"] = (
        float(np.sum(updated & truth) / attack_count)
        if attack_count
        else float("nan")
    )
    metrics["max_window_attack_fraction"] = (
        float(np.max(window_attack_fraction))
        if len(window_attack_fraction)
        else float("nan")
    )
    return metrics


def run_leave_one_boot_out(
    dataset: ContextBatchDataset, batch_context: np.ndarray
) -> tuple[list[dict], list[dict]]:
    dataset.validate()
    boots = _validate_design(dataset)
    raw = feature_view(dataset, RAW_FEATURES)
    residual = feature_view(dataset, RESIDUAL_FEATURES)
    v0_context = feature_view(dataset, CONTEXT_FEATURES)
    fold_rows: list[dict] = []
    detail_rows: list[dict] = []

    for fold, test_boot in enumerate(boots):
        calibration_boot = boots[(fold - 1) % len(boots)]
        fit_boots = [boot for boot in boots if boot not in {test_boot, calibration_boot}]
        fit_idx = np.flatnonzero(
            dataset.quality_valid
            & (dataset.labels == "normal")
            & np.isin(dataset.boot_ids, fit_boots)
        )
        calibration_idx = np.flatnonzero(
            dataset.quality_valid
            & (dataset.labels == "normal")
            & (dataset.boot_ids == calibration_boot)
        )
        test_idx = np.flatnonzero(dataset.quality_valid & (dataset.boot_ids == test_boot))
        fit_idx = _chronological(fit_idx, dataset)
        calibration_idx = _campaign_order(calibration_idx, dataset)
        test_idx = _campaign_order(test_idx, dataset)
        truth = dataset.labels[test_idx] == "rootkit"

        fixed_gate = FixedResidualGate().fit(
            residual[fit_idx], residual[calibration_idx]
        )
        residual_test_eligible = fixed_gate.accepts(residual[test_idx])

        conditional = ConditionalResidualGuard(ridge_lambda=1.0).fit(
            batch_context[fit_idx],
            residual[fit_idx],
            batch_context[calibration_idx],
            residual[calibration_idx],
        )
        conditional_test_eligible = conditional.accepts(
            batch_context[test_idx], residual[test_idx]
        )
        all_normal_calibration_eligible = np.ones(len(calibration_idx), dtype=bool)

        outputs: dict[
            str, tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray, np.ndarray]
        ] = {}
        outputs["fixed_raw"] = _binary_method(
            "fixed", raw[fit_idx], raw[calibration_idx], raw[test_idx], truth
        )
        outputs["blind_50_raw"] = _binary_method(
            "blind_50", raw[fit_idx], raw[calibration_idx], raw[test_idx], truth
        )
        outputs["fixed_residual"] = _binary_method(
            "fixed",
            residual[fit_idx],
            residual[calibration_idx],
            residual[test_idx],
            truth,
        )
        outputs["v0_kicba"] = _kicba_method(
            raw[fit_idx],
            residual[fit_idx],
            v0_context[fit_idx],
            raw[calibration_idx],
            residual[calibration_idx],
            v0_context[calibration_idx],
            raw[test_idx],
            residual[test_idx],
            v0_context[test_idx],
            dataset.quality_valid[test_idx],
            truth,
        )
        outputs["v1_residual_gate_w50"] = _safe_adaptive_method(
            raw[fit_idx],
            raw[calibration_idx],
            all_normal_calibration_eligible,
            raw[test_idx],
            residual_test_eligible,
            dataset.quality_valid[test_idx],
            truth,
            window_size=50,
        )
        for window_size in (20, 50, 100):
            outputs[f"v1_safe_adaptive_w{window_size}"] = _safe_adaptive_method(
                raw[fit_idx],
                raw[calibration_idx],
                all_normal_calibration_eligible,
                raw[test_idx],
                conditional_test_eligible,
                dataset.quality_valid[test_idx],
                truth,
                window_size=window_size,
            )
        outputs["v1_update_all_w50"] = _safe_adaptive_method(
            raw[fit_idx],
            raw[calibration_idx],
            all_normal_calibration_eligible,
            raw[test_idx],
            np.ones(len(test_idx), dtype=bool),
            dataset.quality_valid[test_idx],
            truth,
            window_size=50,
        )
        outputs["v1_no_updates_w50"] = _safe_adaptive_method(
            raw[fit_idx],
            raw[calibration_idx],
            np.zeros(len(calibration_idx), dtype=bool),
            raw[test_idx],
            np.zeros(len(test_idx), dtype=bool),
            dataset.quality_valid[test_idx],
            truth,
            window_size=50,
        )
        outputs["v1_union_alert_w50"] = _safe_adaptive_method(
            raw[fit_idx],
            raw[calibration_idx],
            all_normal_calibration_eligible,
            raw[test_idx],
            conditional_test_eligible,
            dataset.quality_valid[test_idx],
            truth,
            window_size=50,
            guard_alert=~conditional_test_eligible,
            union_alert=True,
        )

        conditions = sorted(set(dataset.conditions[test_idx].tolist()))
        scopes = [("all", np.ones(len(test_idx), dtype=bool))]
        scopes.append(("drift", dataset.conditions[test_idx] != "baseline"))
        scopes.extend(
            (condition, dataset.conditions[test_idx] == condition)
            for condition in conditions
        )
        for method in METHODS:
            decisions, updated, scores, attack_fraction, latency = outputs[method]
            for scope, mask in scopes:
                fold_rows.append(
                    {
                        "fold": fold,
                        "test_boot": test_boot,
                        "calibration_boot": calibration_boot,
                        "fit_boots": ";".join(fit_boots),
                        "scope": scope,
                        "method": method,
                        **_v1_metrics(
                            truth[mask],
                            decisions[mask],
                            updated[mask],
                            latency[mask],
                            attack_fraction[mask],
                        ),
                    }
                )
            for position, idx in enumerate(test_idx):
                detail_rows.append(
                    {
                        "fold": fold,
                        "test_boot": test_boot,
                        "method": method,
                        "position": position,
                        "batch_id": dataset.batch_ids[idx],
                        "condition": dataset.conditions[idx],
                        "label": dataset.labels[idx],
                        "decision": decisions[position],
                        "updated": int(updated[position]),
                        "detector_score": scores[position],
                        "window_attack_fraction": attack_fraction[position],
                        "decision_latency_ns": latency[position],
                    }
                )
    return fold_rows, detail_rows


def _aggregate(fold_rows: list[dict]) -> list[dict]:
    grouped: dict[tuple[str, str], list[dict]] = defaultdict(list)
    for row in fold_rows:
        grouped[(str(row["scope"]), str(row["method"]))].append(row)
    metrics = (
        "recall",
        "fpr",
        "f1",
        "mcc",
        "abstention_rate",
        "contamination_rate",
        "attack_update_acceptance",
        "max_window_attack_fraction",
        "benign_update_acceptance",
        "first_detection_delay",
        "decision_latency_ns",
    )
    rows: list[dict] = []
    for scope in sorted({key[0] for key in grouped}):
        for method in METHODS:
            values = grouped[(scope, method)]
            row: dict[str, object] = {
                "scope": scope,
                "method": method,
                "folds": len(values),
                "ci_unit": "boot",
            }
            for metric in metrics:
                array = np.asarray([float(value[metric]) for value in values])
                mean, lo, hi = _bootstrap_mean_ci(array)
                row[f"{metric}_mean"] = mean
                row[f"{metric}_ci_lo"] = lo
                row[f"{metric}_ci_hi"] = hi
            rows.append(row)
    return rows


def _primary_comparison(fold_rows: list[dict]) -> list[dict]:
    lookup = {
        (str(row["scope"]), str(row["method"]), int(row["fold"])): row
        for row in fold_rows
    }
    rows: list[dict] = []
    for scope in sorted({str(row["scope"]) for row in fold_rows}):
        folds = sorted(
            int(row["fold"])
            for row in fold_rows
            if row["scope"] == scope and row["method"] == "v1_safe_adaptive_w50"
        )
        fpr_reduction = []
        recall_loss = []
        contamination = []
        attack_update_acceptance = []
        acceptance = []
        no_update_fpr_gap = []
        for fold in folds:
            primary = lookup[(scope, "v1_safe_adaptive_w50", fold)]
            fixed = lookup[(scope, "fixed_residual", fold)]
            no_updates = lookup[(scope, "v1_no_updates_w50", fold)]
            fpr_reduction.append(float(fixed["fpr"]) - float(primary["fpr"]))
            recall_loss.append(float(fixed["recall"]) - float(primary["recall"]))
            contamination.append(float(primary["contamination_rate"]))
            attack_update_acceptance.append(
                float(primary["attack_update_acceptance"])
            )
            acceptance.append(float(primary["benign_update_acceptance"]))
            no_update_fpr_gap.append(float(no_updates["fpr"]) - float(primary["fpr"]))

        def stats(values: list[float]) -> tuple[float, float, float]:
            return _bootstrap_mean_ci(np.asarray(values, dtype=float))

        fpr_mean, fpr_lo, fpr_hi = stats(fpr_reduction)
        recall_mean, recall_lo, recall_hi = stats(recall_loss)
        contamination_mean, contamination_lo, contamination_hi = stats(contamination)
        attack_update_mean, attack_update_lo, attack_update_hi = stats(
            attack_update_acceptance
        )
        acceptance_mean, acceptance_lo, acceptance_hi = stats(acceptance)
        gap_mean, gap_lo, gap_hi = stats(no_update_fpr_gap)
        recall_primary = np.mean(
            [float(lookup[(scope, "v1_safe_adaptive_w50", fold)]["recall"]) for fold in folds]
        )
        row = {
            "scope": scope,
            "folds": len(folds),
            "fpr_reduction_vs_fixed_residual_mean": fpr_mean,
            "fpr_reduction_ci_lo": fpr_lo,
            "fpr_reduction_ci_hi": fpr_hi,
            "fpr_reduction_p": _bootstrap_direction_p(np.asarray(fpr_reduction)),
            "recall_mean": float(recall_primary),
            "recall_loss_mean": recall_mean,
            "recall_loss_ci_lo": recall_lo,
            "recall_loss_ci_hi": recall_hi,
            "contamination_mean": contamination_mean,
            "contamination_ci_lo": contamination_lo,
            "contamination_ci_hi": contamination_hi,
            "attack_update_acceptance_mean": attack_update_mean,
            "attack_update_acceptance_ci_lo": attack_update_lo,
            "attack_update_acceptance_ci_hi": attack_update_hi,
            "benign_update_acceptance_mean": acceptance_mean,
            "benign_update_acceptance_ci_lo": acceptance_lo,
            "benign_update_acceptance_ci_hi": acceptance_hi,
            "no_update_fpr_gap_mean": gap_mean,
            "no_update_fpr_gap_ci_lo": gap_lo,
            "no_update_fpr_gap_ci_hi": gap_hi,
            "passes_recall": bool(recall_primary >= 0.98),
            "passes_contamination": bool(contamination_mean <= 0.01),
            "passes_attack_update_acceptance": bool(attack_update_mean <= 0.01),
            "passes_fpr": bool(fpr_mean >= 0.05),
            "passes_acceptance": bool(acceptance_mean >= 0.50),
            "passes_adaptive_necessity": bool(gap_mean >= 0.02),
        }
        row["passes_all_exploratory_rules"] = bool(
            row["passes_recall"]
            and row["passes_contamination"]
            and row["passes_attack_update_acceptance"]
            and row["passes_fpr"]
            and row["passes_acceptance"]
            and row["passes_adaptive_necessity"]
        )
        rows.append(row)
    return rows


def main(argv: Iterable[str] | None = None) -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--data", required=True, type=Path)
    parser.add_argument("--batch-context", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    dataset = ContextBatchDataset.load(args.data)
    context_dataset = V1BatchContextDataset.load(args.batch_context)
    aligned_context = _align_context(dataset, context_dataset)
    fold_rows, detail_rows = run_leave_one_boot_out(dataset, aligned_context)
    summary_rows = _aggregate(fold_rows)
    comparison_rows = _primary_comparison(fold_rows)
    args.output.mkdir(parents=True, exist_ok=True)
    _write_csv(args.output / "fold_results.csv", fold_rows)
    _write_csv(args.output / "decisions.csv", detail_rows)
    _write_csv(args.output / "summary.csv", summary_rows)
    _write_csv(args.output / "primary_comparison.csv", comparison_rows)
    design = {
        "schema_version": 1,
        "status": "exploratory_after_d2_v0",
        "data": str(args.data),
        "batch_context": str(args.batch_context),
        "valid_batches": int(np.sum(dataset.quality_valid)),
        "boot_ids": sorted(set(dataset.boot_ids[dataset.quality_valid].tolist())),
        "methods": list(METHODS),
        "primary_method": "v1_safe_adaptive_w50",
        "ridge_lambda": 1.0,
        "target_fpr": 0.05,
        "context_features": context_dataset.feature_names.tolist(),
    }
    (args.output / "design.json").write_text(
        json.dumps(design, indent=2), encoding="utf-8"
    )
    print(json.dumps(design))


if __name__ == "__main__":
    main()
