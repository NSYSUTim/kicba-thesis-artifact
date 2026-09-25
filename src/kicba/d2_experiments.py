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
from .detector import ShiftDetector, calibrate_distance_threshold
from .kicba import CONTEXT_FEATURES, RAW_FEATURES, RESIDUAL_FEATURES, KICBA, feature_view
from .metrics import classification_metrics, first_detection_delay
from .online import run_replay


METHODS = (
    "fixed_raw",
    "blind_50_raw",
    "score_gated_raw",
    "dual_anchor_raw",
    "scenario_oracle_fixed_raw",
    "fixed_residual",
    "kicba",
    "kicba_no_context",
    "kicba_no_irq",
    "kicba_no_offcpu",
    "kicba_no_accounting",
    "kicba_no_fixed_anchor",
)
ABLATION_METHODS = (
    "kicba_no_context",
    "kicba_no_irq",
    "kicba_no_offcpu",
    "kicba_no_accounting",
    "kicba_no_fixed_anchor",
)
EXPECTED_CONDITIONS = ("baseline", "cpu", "memory", "mixed")
EXPECTED_LABELS = ("normal", "rootkit")
MIN_BOOTS = 5
MIN_BATCHES_PER_CELL = 30
MIN_ITERATIONS_PER_BATCH = 100
BOOTSTRAP_SAMPLES = 10_000
BOOTSTRAP_SEED = 20260914


def _write_csv(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not rows:
        raise ValueError(f"No rows for {path}")
    fields: list[str] = []
    for row in rows:
        for field in row:
            if field not in fields:
                fields.append(field)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def _decision_metrics(
    truth: np.ndarray,
    decisions: np.ndarray,
    updated: np.ndarray,
    decision_latency_ns: np.ndarray,
) -> dict[str, float | int]:
    truth = np.asarray(truth, dtype=bool)
    decisions = np.asarray(decisions, dtype=str)
    updated = np.asarray(updated, dtype=bool)
    decision_latency_ns = np.asarray(decision_latency_ns, dtype=float)
    suspicious = decisions == "suspicious"
    unknown = decisions == "unknown"
    metrics = classification_metrics(truth, suspicious)
    normal_count = int(np.sum(~truth))
    attack_count = int(np.sum(truth))
    attack_updates = int(np.sum(updated & truth))
    normal_updates = int(np.sum(updated & ~truth))
    total_updates = attack_updates + normal_updates
    metrics.update(
        {
            "abstention_rate": float(np.mean(unknown)) if len(unknown) else float("nan"),
            "normal_abstention_rate": float(np.sum(unknown & ~truth) / normal_count)
            if normal_count
            else float("nan"),
            "attack_abstention_rate": float(np.sum(unknown & truth) / attack_count)
            if attack_count
            else float("nan"),
            "normal_non_normal_rate": float(
                np.sum((suspicious | unknown) & ~truth) / normal_count
            )
            if normal_count
            else float("nan"),
            "attack_miss_or_unknown_rate": float(
                np.sum((~suspicious) & truth) / attack_count
            )
            if attack_count
            else float("nan"),
            "attack_updates": attack_updates,
            "normal_updates": normal_updates,
            "contamination_rate": attack_updates / total_updates
            if total_updates
            else float("nan"),
            "benign_update_acceptance": normal_updates / normal_count
            if normal_count
            else float("nan"),
            "first_detection_delay": first_detection_delay(truth, suspicious),
            "decision_latency_ns": float(np.mean(decision_latency_ns))
            if len(decision_latency_ns)
            else float("nan"),
        }
    )
    return metrics


def _binary_method(
    method: str,
    fit_values: np.ndarray,
    calibration_values: np.ndarray,
    test_values: np.ndarray,
    truth: np.ndarray,
) -> tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray, np.ndarray]:
    anchor = ShiftDetector(covariance="oas").fit(fit_values)
    threshold = calibrate_distance_threshold(anchor, calibration_values)
    started_ns = time.perf_counter_ns()
    if method == "fixed":
        scores = np.asarray(
            [anchor.max_distance_squared(batch) for batch in test_values]
        )
        predicted = ~np.isfinite(scores) | (scores > threshold)
        updated = np.zeros(len(test_values), dtype=bool)
        attack_fraction = np.zeros(len(test_values), dtype=float)
    else:
        replay = run_replay(
            initial_values=fit_values,
            initial_is_attack=np.zeros(len(fit_values), dtype=bool),
            replay_values=test_values,
            replay_is_attack=truth,
            threshold=threshold,
            method=method,
            window_size=50,
            score_kind="distance",
            covariance="oas",
        )
        scores = replay.scores
        predicted = replay.predicted
        updated = replay.updated
        attack_fraction = replay.window_attack_fraction
    elapsed_ns = time.perf_counter_ns() - started_ns
    decision_latency_ns = np.full(
        len(test_values), elapsed_ns / max(1, len(test_values)), dtype=float
    )
    decisions = np.where(predicted, "suspicious", "normal")
    return decisions, updated, scores, attack_fraction, decision_latency_ns


def _kicba_method(
    raw_fit: np.ndarray,
    guard_fit: np.ndarray,
    context_fit: np.ndarray,
    raw_calibration: np.ndarray,
    guard_calibration: np.ndarray,
    context_calibration: np.ndarray,
    raw_test: np.ndarray,
    guard_test: np.ndarray,
    context_test: np.ndarray,
    quality_test: np.ndarray,
    truth: np.ndarray,
    *,
    use_residual_anchor: bool = True,
    use_context_envelope: bool = True,
    use_adaptive_alert_without_anchor: bool = False,
) -> tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray, np.ndarray]:
    model = KICBA(
        window_size=50,
        use_residual_anchor=use_residual_anchor,
        use_context_envelope=use_context_envelope,
        use_adaptive_alert_without_anchor=use_adaptive_alert_without_anchor,
    ).fit(
        raw_fit,
        guard_fit,
        context_fit,
        raw_calibration,
        guard_calibration,
        context_calibration,
    )
    steps = []
    latencies = []
    for position in range(len(raw_test)):
        started_ns = time.perf_counter_ns()
        step = model.step(
            raw_test[position],
            guard_test[position],
            context_test[position],
            bool(quality_test[position]),
            evaluation_is_attack=bool(truth[position]),
        )
        latencies.append(time.perf_counter_ns() - started_ns)
        steps.append(step)
    scores = (
        [step.residual_anchor_score for step in steps]
        if use_residual_anchor
        else [step.raw_adaptive_score for step in steps]
    )
    return (
        np.asarray([step.decision for step in steps], dtype=str),
        np.asarray([step.updated for step in steps], dtype=bool),
        np.asarray(scores, dtype=float),
        np.asarray([step.window_attack_fraction for step in steps], dtype=float),
        np.asarray(latencies, dtype=float),
    )


def _scenario_oracle_fixed(
    fit_values: np.ndarray,
    fit_conditions: np.ndarray,
    calibration_values: np.ndarray,
    calibration_conditions: np.ndarray,
    test_values: np.ndarray,
    test_conditions: np.ndarray,
) -> tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray, np.ndarray]:
    decisions = np.full(len(test_values), "unknown", dtype="<U10")
    scores = np.full(len(test_values), np.nan, dtype=float)
    latencies = np.full(len(test_values), np.nan, dtype=float)
    for condition in sorted(set(test_conditions.tolist())):
        fit_mask = fit_conditions == condition
        calibration_mask = calibration_conditions == condition
        test_mask = test_conditions == condition
        if np.sum(fit_mask) < 2 or not np.any(calibration_mask):
            raise ValueError(f"Insufficient oracle-normal data for condition {condition}")
        detector = ShiftDetector(covariance="oas").fit(fit_values[fit_mask])
        threshold = calibrate_distance_threshold(
            detector, calibration_values[calibration_mask]
        )
        indices = np.flatnonzero(test_mask)
        started_ns = time.perf_counter_ns()
        condition_scores = np.asarray(
            [detector.max_distance_squared(test_values[index]) for index in indices],
            dtype=float,
        )
        elapsed_ns = time.perf_counter_ns() - started_ns
        condition_suspicious = ~np.isfinite(condition_scores) | (
            condition_scores > threshold
        )
        scores[indices] = condition_scores
        decisions[indices] = np.where(condition_suspicious, "suspicious", "normal")
        latencies[indices] = elapsed_ns / max(1, len(indices))
    return (
        decisions,
        np.zeros(len(test_values), dtype=bool),
        scores,
        np.zeros(len(test_values), dtype=float),
        latencies,
    )


def _validate_design(dataset: ContextBatchDataset) -> list[str]:
    valid = dataset.quality_valid
    boots = sorted(set(dataset.boot_ids[valid].tolist()) - {"", "unknown"})
    if len(boots) < MIN_BOOTS:
        raise ValueError(
            f"D2 evaluation needs at least {MIN_BOOTS} valid, known boot IDs "
            "under the preregistered design; found " + str(len(boots))
        )
    if set(dataset.function_names.tolist()) != {
        "iterate_dir",
        "filldir64",
        "touch_atime",
    }:
        raise ValueError(
            "D2 dataset must contain the three protocol-r1 primary timing functions; found "
            + ", ".join(dataset.function_names.tolist())
        )
    for boot in boots:
        boot_mask = valid & (dataset.boot_ids == boot)
        labels = set(dataset.labels[boot_mask].tolist())
        if labels != set(EXPECTED_LABELS):
            raise ValueError(f"Boot {boot} does not contain both normal and rootkit batches")
        campaign_ids = set(dataset.campaign_ids[boot_mask].tolist()) - {"", "unknown"}
        if len(campaign_ids) != 1:
            raise ValueError(
                f"Boot {boot} must contain exactly one known campaign ID; found "
                + str(len(campaign_ids))
            )
        campaign_id = next(iter(campaign_ids))
        campaign_mask = boot_mask & (dataset.campaign_ids == campaign_id)
        positions = dataset.campaign_positions[campaign_mask]
        if np.any(positions < 0) or len(set(positions.tolist())) != len(positions):
            raise ValueError(f"Boot {boot} has missing or duplicate campaign positions")
        if np.any(dataset.iterations[boot_mask] < MIN_ITERATIONS_PER_BATCH):
            raise ValueError(
                f"Boot {boot} contains a batch with fewer than "
                f"{MIN_ITERATIONS_PER_BATCH} directory-listing iterations"
            )
        for condition in EXPECTED_CONDITIONS:
            for label in EXPECTED_LABELS:
                count = int(
                    np.sum(
                        boot_mask
                        & (dataset.conditions == condition)
                        & (dataset.labels == label)
                    )
                )
                if count < MIN_BATCHES_PER_CELL:
                    raise ValueError(
                        f"Boot {boot} has only {count} valid {condition}/{label} "
                        f"batches; need at least {MIN_BATCHES_PER_CELL}"
                    )
    return boots


def run_leave_one_boot_out(
    dataset: ContextBatchDataset,
) -> tuple[list[dict], list[dict]]:
    dataset.validate()
    boots = _validate_design(dataset)
    raw = feature_view(dataset, RAW_FEATURES)
    residual = feature_view(dataset, RESIDUAL_FEATURES)
    no_irq_residual = feature_view(dataset, ("oncpu_ns",))
    no_offcpu_residual = feature_view(dataset, ("irq_adjusted_wall_ns",))
    context = feature_view(dataset, CONTEXT_FEATURES)
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
        test_idx = np.flatnonzero(
            dataset.quality_valid & (dataset.boot_ids == test_boot)
        )
        test_idx = np.asarray(
            sorted(
                test_idx.tolist(),
                key=lambda idx: (
                    int(dataset.campaign_positions[idx]),
                    str(dataset.batch_ids[idx]),
                ),
            ),
            dtype=int,
        )
        if min(len(fit_idx), len(calibration_idx), len(test_idx)) == 0:
            raise ValueError(f"Empty fit/calibration/test partition for test boot {test_boot}")
        truth = dataset.labels[test_idx] == "rootkit"

        outputs: dict[
            str, tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray, np.ndarray]
        ] = {}
        outputs["fixed_raw"] = _binary_method(
            "fixed", raw[fit_idx], raw[calibration_idx], raw[test_idx], truth
        )
        outputs["blind_50_raw"] = _binary_method(
            "blind_50", raw[fit_idx], raw[calibration_idx], raw[test_idx], truth
        )
        outputs["score_gated_raw"] = _binary_method(
            "score_gated", raw[fit_idx], raw[calibration_idx], raw[test_idx], truth
        )
        outputs["dual_anchor_raw"] = _binary_method(
            "dual_anchor", raw[fit_idx], raw[calibration_idx], raw[test_idx], truth
        )
        outputs["scenario_oracle_fixed_raw"] = _scenario_oracle_fixed(
            raw[fit_idx],
            dataset.conditions[fit_idx],
            raw[calibration_idx],
            dataset.conditions[calibration_idx],
            raw[test_idx],
            dataset.conditions[test_idx],
        )
        outputs["fixed_residual"] = _binary_method(
            "fixed",
            residual[fit_idx],
            residual[calibration_idx],
            residual[test_idx],
            truth,
        )

        common_kicba = (
            raw[fit_idx],
            residual[fit_idx],
            context[fit_idx],
            raw[calibration_idx],
            residual[calibration_idx],
            context[calibration_idx],
            raw[test_idx],
            residual[test_idx],
            context[test_idx],
            dataset.quality_valid[test_idx],
            truth,
        )
        outputs["kicba"] = _kicba_method(*common_kicba)
        outputs["kicba_no_context"] = _kicba_method(
            *common_kicba, use_context_envelope=False
        )
        outputs["kicba_no_irq"] = _kicba_method(
            raw[fit_idx],
            no_irq_residual[fit_idx],
            context[fit_idx],
            raw[calibration_idx],
            no_irq_residual[calibration_idx],
            context[calibration_idx],
            raw[test_idx],
            no_irq_residual[test_idx],
            context[test_idx],
            dataset.quality_valid[test_idx],
            truth,
        )
        outputs["kicba_no_offcpu"] = _kicba_method(
            raw[fit_idx],
            no_offcpu_residual[fit_idx],
            context[fit_idx],
            raw[calibration_idx],
            no_offcpu_residual[calibration_idx],
            context[calibration_idx],
            raw[test_idx],
            no_offcpu_residual[test_idx],
            context[test_idx],
            dataset.quality_valid[test_idx],
            truth,
        )
        outputs["kicba_no_accounting"] = _kicba_method(
            raw[fit_idx],
            raw[fit_idx],
            context[fit_idx],
            raw[calibration_idx],
            raw[calibration_idx],
            context[calibration_idx],
            raw[test_idx],
            raw[test_idx],
            context[test_idx],
            dataset.quality_valid[test_idx],
            truth,
        )
        outputs["kicba_no_fixed_anchor"] = _kicba_method(
            *common_kicba,
            use_residual_anchor=False,
            use_adaptive_alert_without_anchor=True,
        )

        conditions = sorted(set(dataset.conditions[test_idx].tolist()))
        scopes = [("all", np.ones(len(test_idx), dtype=bool))]
        scopes.append(("drift", dataset.conditions[test_idx] != "baseline"))
        scopes.extend(
            (condition, dataset.conditions[test_idx] == condition)
            for condition in conditions
        )

        for method in METHODS:
            decisions, updated, scores, attack_fraction, decision_latency_ns = outputs[
                method
            ]
            for scope, mask in scopes:
                if not np.any(mask):
                    continue
                fold_rows.append(
                    {
                        "fold": fold,
                        "test_boot": test_boot,
                        "calibration_boot": calibration_boot,
                        "fit_boots": ";".join(fit_boots),
                        "scope": scope,
                        "method": method,
                        **_decision_metrics(
                            truth[mask],
                            decisions[mask],
                            updated[mask],
                            decision_latency_ns[mask],
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
                        "decision_latency_ns": decision_latency_ns[position],
                    }
                )
    return fold_rows, detail_rows


def _bootstrap_mean_ci(values: np.ndarray) -> tuple[float, float, float]:
    values = np.asarray(values, dtype=float)
    values = values[np.isfinite(values)]
    if not len(values):
        return float("nan"), float("nan"), float("nan")
    rng = np.random.default_rng(BOOTSTRAP_SEED)
    samples = rng.choice(values, size=(BOOTSTRAP_SAMPLES, len(values)), replace=True)
    means = np.mean(samples, axis=1)
    return (
        float(np.mean(values)),
        float(np.quantile(means, 0.025)),
        float(np.quantile(means, 0.975)),
    )


def _bootstrap_direction_p(values: np.ndarray) -> float:
    values = np.asarray(values, dtype=float)
    values = values[np.isfinite(values)]
    if not len(values):
        return float("nan")
    rng = np.random.default_rng(BOOTSTRAP_SEED + 1)
    samples = rng.choice(values, size=(BOOTSTRAP_SAMPLES, len(values)), replace=True)
    means = np.mean(samples, axis=1)
    lower = (np.sum(means <= 0) + 1) / (BOOTSTRAP_SAMPLES + 1)
    upper = (np.sum(means >= 0) + 1) / (BOOTSTRAP_SAMPLES + 1)
    return float(min(1.0, 2.0 * min(lower, upper)))


def _aggregate(fold_rows: list[dict]) -> list[dict]:
    groups: dict[tuple[str, str], list[dict]] = defaultdict(list)
    for row in fold_rows:
        groups[(str(row["scope"]), str(row["method"]))].append(row)
    metrics = (
        "recall",
        "fpr",
        "f1",
        "mcc",
        "abstention_rate",
        "normal_non_normal_rate",
        "attack_miss_or_unknown_rate",
        "contamination_rate",
        "benign_update_acceptance",
        "first_detection_delay",
        "decision_latency_ns",
    )
    rows: list[dict] = []
    for scope in sorted({key[0] for key in groups}):
        for method in METHODS:
            values = groups[(scope, method)]
            if not values:
                continue
            row: dict[str, float | int | str] = {
                "scope": scope,
                "method": method,
                "folds": len(values),
                "ci_unit": "boot",
                "bootstrap_samples": BOOTSTRAP_SAMPLES,
            }
            for metric in metrics:
                array = np.asarray([item[metric] for item in values], dtype=float)
                mean, lo, hi = _bootstrap_mean_ci(array)
                row[f"{metric}_mean"] = mean
                row[f"{metric}_ci_lo"] = lo
                row[f"{metric}_ci_hi"] = hi
            rows.append(row)
    return rows


def _holm_adjust(rows: list[dict]) -> None:
    candidates = [
        (index, float(row["fpr_reduction_p"]))
        for index, row in enumerate(rows)
        if row["scope"] not in {"all", "drift"}
        and np.isfinite(float(row["fpr_reduction_p"]))
    ]
    candidates.sort(key=lambda item: item[1])
    adjusted = 0.0
    count = len(candidates)
    for rank, (index, p_value) in enumerate(candidates):
        adjusted = max(adjusted, min(1.0, (count - rank) * p_value))
        rows[index]["fpr_reduction_holm_p"] = adjusted


def _comparisons(fold_rows: list[dict]) -> list[dict]:
    by_key = {
        (str(row["scope"]), str(row["method"]), int(row["fold"])): row
        for row in fold_rows
    }
    scopes = sorted({str(row["scope"]) for row in fold_rows})
    rows: list[dict] = []
    for scope in scopes:
        folds = sorted(
            int(row["fold"])
            for row in fold_rows
            if row["scope"] == scope and row["method"] == "kicba"
        )
        fpr_reduction: list[float] = []
        recall_loss: list[float] = []
        contamination_reduction: list[float] = []
        abstention: list[float] = []
        for fold in folds:
            fixed = by_key[(scope, "fixed_raw", fold)]
            blind = by_key[(scope, "blind_50_raw", fold)]
            proposed = by_key[(scope, "kicba", fold)]
            fpr_reduction.append(float(fixed["fpr"]) - float(proposed["fpr"]))
            recall_loss.append(float(fixed["recall"]) - float(proposed["recall"]))
            blind_contamination = float(blind["contamination_rate"])
            proposed_contamination = float(proposed["contamination_rate"])
            if np.isfinite(blind_contamination) and blind_contamination > 0:
                contamination_reduction.append(
                    1.0 - proposed_contamination / blind_contamination
                )
            abstention.append(float(proposed["abstention_rate"]))

        fpr_mean, fpr_lo, fpr_hi = _bootstrap_mean_ci(np.asarray(fpr_reduction))
        recall_mean, recall_lo, recall_hi = _bootstrap_mean_ci(
            np.asarray(recall_loss)
        )
        contamination_mean, contamination_lo, contamination_hi = _bootstrap_mean_ci(
            np.asarray(contamination_reduction)
        )
        abstention_mean, abstention_lo, abstention_hi = _bootstrap_mean_ci(
            np.asarray(abstention)
        )
        rows.append(
            {
                "scope": scope,
                "folds": len(folds),
                "fpr_reduction_mean": fpr_mean,
                "fpr_reduction_ci_lo": fpr_lo,
                "fpr_reduction_ci_hi": fpr_hi,
                "fpr_reduction_p": _bootstrap_direction_p(
                    np.asarray(fpr_reduction)
                ),
                "fpr_reduction_holm_p": float("nan"),
                "recall_loss_mean": recall_mean,
                "recall_loss_ci_lo": recall_lo,
                "recall_loss_ci_hi": recall_hi,
                "contamination_relative_reduction_mean": contamination_mean,
                "contamination_relative_reduction_ci_lo": contamination_lo,
                "contamination_relative_reduction_ci_hi": contamination_hi,
                "abstention_rate_mean": abstention_mean,
                "abstention_rate_ci_lo": abstention_lo,
                "abstention_rate_ci_hi": abstention_hi,
                "passes_fpr_rule": bool(fpr_mean >= 0.05 and fpr_lo > 0),
                "passes_contamination_rule": bool(contamination_mean >= 0.50),
                "passes_recall_rule": bool(recall_mean <= 0.02),
                "passes_abstention_rule": bool(abstention_mean <= 0.20),
            }
        )
    _holm_adjust(rows)
    return rows


def _ablation_comparisons(fold_rows: list[dict]) -> list[dict]:
    by_key = {
        (str(row["scope"]), str(row["method"]), int(row["fold"])): row
        for row in fold_rows
    }
    metrics = (
        "fpr",
        "recall",
        "contamination_rate",
        "benign_update_acceptance",
        "abstention_rate",
    )
    scopes = sorted({str(row["scope"]) for row in fold_rows})
    rows: list[dict] = []
    for scope in scopes:
        folds = sorted(
            int(row["fold"])
            for row in fold_rows
            if row["scope"] == scope and row["method"] == "kicba"
        )
        for ablation in ABLATION_METHODS:
            for metric in metrics:
                differences = np.asarray(
                    [
                        float(by_key[(scope, "kicba", fold)][metric])
                        - float(by_key[(scope, ablation, fold)][metric])
                        for fold in folds
                    ],
                    dtype=float,
                )
                mean, lo, hi = _bootstrap_mean_ci(differences)
                rows.append(
                    {
                        "scope": scope,
                        "ablation": ablation,
                        "metric": metric,
                        "difference": "kicba_minus_ablation",
                        "folds": int(np.sum(np.isfinite(differences))),
                        "mean": mean,
                        "ci_lo": lo,
                        "ci_hi": hi,
                    }
                )
    return rows


def main(argv: Iterable[str] | None = None) -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--data", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    dataset = ContextBatchDataset.load(args.data)
    try:
        fold_rows, detail_rows = run_leave_one_boot_out(dataset)
    except ValueError as exc:
        parser.error(str(exc))
    summary_rows = _aggregate(fold_rows)
    comparison_rows = _comparisons(fold_rows)
    ablation_rows = _ablation_comparisons(fold_rows)
    args.output.mkdir(parents=True, exist_ok=True)
    _write_csv(args.output / "fold_results.csv", fold_rows)
    _write_csv(args.output / "decisions.csv", detail_rows)
    _write_csv(args.output / "summary.csv", summary_rows)
    _write_csv(args.output / "comparisons.csv", comparison_rows)
    _write_csv(args.output / "ablations.csv", ablation_rows)
    design = {
        "valid_batches": int(np.sum(dataset.quality_valid)),
        "boot_ids": sorted(set(dataset.boot_ids[dataset.quality_valid].tolist())),
        "conditions": sorted(set(dataset.conditions[dataset.quality_valid].tolist())),
        "campaign_ids": sorted(set(dataset.campaign_ids[dataset.quality_valid].tolist())),
        "minimum_iterations": int(np.min(dataset.iterations[dataset.quality_valid])),
        "functions": dataset.function_names.tolist(),
        "features": dataset.feature_names.tolist(),
    }
    (args.output / "design.json").write_text(json.dumps(design, indent=2), encoding="utf-8")
    print(json.dumps(design, indent=2))


if __name__ == "__main__":
    main()
