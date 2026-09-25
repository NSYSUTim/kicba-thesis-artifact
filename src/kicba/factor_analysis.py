from __future__ import annotations

import argparse
import csv
import json
from collections import defaultdict
from pathlib import Path
from typing import Iterable

import numpy as np
from scipy.stats import rankdata

from .context import ContextBatchDataset
from .v1_features import V1BatchContextDataset


TIMING_FEATURES = (
    "raw_wall_ns",
    "oncpu_ns",
    "irq_adjusted_wall_ns",
    "accounted_exec_ns",
)


def _write_csv(path: Path, rows: list[dict]) -> None:
    if not rows:
        raise ValueError(f"No rows generated for {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def rank_auc(negative: np.ndarray, positive: np.ndarray) -> float:
    """Probability that a positive observation exceeds a negative one."""

    negative = np.asarray(negative, dtype=float)
    positive = np.asarray(positive, dtype=float)
    negative = negative[np.isfinite(negative)]
    positive = positive[np.isfinite(positive)]
    if not len(negative) or not len(positive):
        return float("nan")
    combined = np.concatenate([negative, positive])
    ranks = rankdata(combined, method="average")
    positive_rank_sum = float(np.sum(ranks[len(negative) :]))
    u_statistic = positive_rank_sum - len(positive) * (len(positive) + 1) / 2.0
    return float(u_statistic / (len(negative) * len(positive)))


def _channel_rows(dataset_name: str, dataset: ContextBatchDataset) -> list[dict]:
    rows: list[dict] = []
    valid = dataset.quality_valid
    for boot in sorted(set(dataset.boot_ids[valid].tolist())):
        boot_mask = valid & (dataset.boot_ids == boot)
        for condition in sorted(set(dataset.conditions[boot_mask].tolist())):
            normal_mask = (
                boot_mask
                & (dataset.conditions == condition)
                & (dataset.labels == "normal")
            )
            attack_mask = (
                boot_mask
                & (dataset.conditions == condition)
                & (dataset.labels == "rootkit")
            )
            if not np.any(normal_mask) or not np.any(attack_mask):
                continue
            for function_idx, function in enumerate(dataset.function_names):
                for feature_idx, feature in enumerate(dataset.feature_names):
                    for quantile_idx, quantile in enumerate(dataset.quantile_probs):
                        normal = dataset.values[
                            normal_mask, function_idx, feature_idx, quantile_idx
                        ]
                        attack = dataset.values[
                            attack_mask, function_idx, feature_idx, quantile_idx
                        ]
                        auc = rank_auc(normal, attack)
                        rows.append(
                            {
                                "dataset": dataset_name,
                                "boot": str(boot),
                                "condition": str(condition),
                                "function": str(function),
                                "feature": str(feature),
                                "quantile": float(quantile),
                                "normal_n": int(np.sum(np.isfinite(normal))),
                                "rootkit_n": int(np.sum(np.isfinite(attack))),
                                "normal_median": float(np.nanmedian(normal)),
                                "rootkit_median": float(np.nanmedian(attack)),
                                "rootkit_auc": auc,
                                "rootkit_strength": float(abs(2.0 * auc - 1.0)),
                                "rootkit_direction": (
                                    "up" if auc > 0.5 else "down" if auc < 0.5 else "tie"
                                ),
                            }
                        )
    return rows


def _normal_drift_rows(dataset_name: str, dataset: ContextBatchDataset) -> list[dict]:
    rows: list[dict] = []
    valid_normal = dataset.quality_valid & (dataset.labels == "normal")
    for boot in sorted(set(dataset.boot_ids[valid_normal].tolist())):
        boot_mask = valid_normal & (dataset.boot_ids == boot)
        baseline_mask = boot_mask & (dataset.conditions == "baseline")
        if not np.any(baseline_mask):
            continue
        for condition in sorted(set(dataset.conditions[boot_mask].tolist())):
            if condition == "baseline":
                continue
            condition_mask = boot_mask & (dataset.conditions == condition)
            for function_idx, function in enumerate(dataset.function_names):
                for feature_idx, feature in enumerate(dataset.feature_names):
                    for quantile_idx, quantile in enumerate(dataset.quantile_probs):
                        baseline = dataset.values[
                            baseline_mask, function_idx, feature_idx, quantile_idx
                        ]
                        changed = dataset.values[
                            condition_mask, function_idx, feature_idx, quantile_idx
                        ]
                        auc = rank_auc(baseline, changed)
                        rows.append(
                            {
                                "dataset": dataset_name,
                                "boot": str(boot),
                                "condition": str(condition),
                                "function": str(function),
                                "feature": str(feature),
                                "quantile": float(quantile),
                                "baseline_n": int(np.sum(np.isfinite(baseline))),
                                "condition_n": int(np.sum(np.isfinite(changed))),
                                "baseline_median": float(np.nanmedian(baseline)),
                                "condition_median": float(np.nanmedian(changed)),
                                "normal_drift_auc": auc,
                                "normal_drift_strength": float(abs(2.0 * auc - 1.0)),
                            }
                        )
    return rows


def _mean(values: Iterable[float]) -> float:
    array = np.asarray(list(values), dtype=float)
    return float(np.nanmean(array)) if len(array) else float("nan")


def _min(values: Iterable[float]) -> float:
    array = np.asarray(list(values), dtype=float)
    return float(np.nanmin(array)) if len(array) else float("nan")


def _max(values: Iterable[float]) -> float:
    array = np.asarray(list(values), dtype=float)
    return float(np.nanmax(array)) if len(array) else float("nan")


def aggregate_channels(
    attack_rows: list[dict], drift_rows: list[dict]
) -> list[dict]:
    attacks: dict[tuple, list[dict]] = defaultdict(list)
    drifts: dict[tuple, list[dict]] = defaultdict(list)
    for row in attack_rows:
        key = (
            row["dataset"], row["function"], row["feature"], row["quantile"]
        )
        attacks[key].append(row)
    for row in drift_rows:
        key = (
            row["dataset"], row["function"], row["feature"], row["quantile"]
        )
        drifts[key].append(row)

    output: list[dict] = []
    for key in sorted(attacks):
        values = attacks[key]
        normal_drifts = drifts.get(key, [])
        attack_strength = _mean(row["rootkit_strength"] for row in values)
        max_normal_drift = _max(
            row["normal_drift_strength"] for row in normal_drifts
        )
        output.append(
            {
                "dataset": key[0],
                "function": key[1],
                "feature": key[2],
                "quantile": key[3],
                "attack_groups": len(values),
                "rootkit_auc_mean": _mean(row["rootkit_auc"] for row in values),
                "rootkit_auc_min": _min(row["rootkit_auc"] for row in values),
                "rootkit_strength_mean": attack_strength,
                "rootkit_up_fraction": _mean(
                    1.0 if row["rootkit_auc"] > 0.5 else 0.0 for row in values
                ),
                "normal_drift_groups": len(normal_drifts),
                "normal_drift_strength_mean": _mean(
                    row["normal_drift_strength"] for row in normal_drifts
                ),
                "normal_drift_strength_max": max_normal_drift,
                "specificity_margin_vs_worst_normal_drift": (
                    attack_strength - max_normal_drift
                ),
            }
        )
    return output


def _align_context(
    dataset: ContextBatchDataset, context: V1BatchContextDataset
) -> np.ndarray:
    index = {str(batch): idx for idx, batch in enumerate(context.batch_ids)}
    if set(index) != set(dataset.batch_ids.tolist()):
        raise ValueError("Timing and batch-context data do not contain identical batches")
    order = np.asarray([index[str(batch)] for batch in dataset.batch_ids], dtype=int)
    if not np.array_equal(dataset.labels, context.labels[order]):
        raise ValueError("Timing and batch-context labels do not align")
    if not np.array_equal(dataset.boot_ids, context.boot_ids[order]):
        raise ValueError("Timing and batch-context boot IDs do not align")
    return np.asarray(context.values[order], dtype=float)


def _ridge_predict(
    x_train: np.ndarray,
    y_train: np.ndarray,
    x_test: np.ndarray,
    ridge_lambda: float = 1.0,
) -> tuple[np.ndarray, float]:
    x_mean = np.mean(x_train, axis=0)
    x_scale = np.std(x_train, axis=0)
    x_scale = np.where(x_scale > 0, x_scale, 1.0)
    y_mean = float(np.mean(y_train))
    y_scale = float(np.std(y_train))
    if not np.isfinite(y_scale) or y_scale <= 0:
        return np.full(len(x_test), y_mean), y_mean
    train = (x_train - x_mean) / x_scale
    test = (x_test - x_mean) / x_scale
    target = (y_train - y_mean) / y_scale
    gram = train.T @ train + ridge_lambda * np.eye(train.shape[1])
    coefficients = np.linalg.solve(gram, train.T @ target)
    return (test @ coefficients) * y_scale + y_mean, y_mean


def context_explainability(
    dataset_name: str,
    dataset: ContextBatchDataset,
    context: V1BatchContextDataset,
    ridge_lambda: float = 1.0,
) -> list[dict]:
    batch_context = _align_context(dataset, context)
    valid_normal = dataset.quality_valid & (dataset.labels == "normal")
    boots = sorted(set(dataset.boot_ids[valid_normal].tolist()))
    feature_index = {str(name): idx for idx, name in enumerate(dataset.feature_names)}
    rows: list[dict] = []
    for function_idx, function in enumerate(dataset.function_names):
        for feature in TIMING_FEATURES:
            feature_idx = feature_index[feature]
            for quantile_idx, quantile in enumerate(dataset.quantile_probs):
                squared_error = 0.0
                baseline_squared_error = 0.0
                observations = 0
                fold_r2: list[float] = []
                for boot in boots:
                    test = valid_normal & (dataset.boot_ids == boot)
                    train = valid_normal & (dataset.boot_ids != boot)
                    y_train = np.log1p(
                        dataset.values[train, function_idx, feature_idx, quantile_idx]
                    )
                    y_test = np.log1p(
                        dataset.values[test, function_idx, feature_idx, quantile_idx]
                    )
                    x_train = batch_context[train]
                    x_test = batch_context[test]
                    finite_train = np.isfinite(y_train) & np.all(
                        np.isfinite(x_train), axis=1
                    )
                    finite_test = np.isfinite(y_test) & np.all(
                        np.isfinite(x_test), axis=1
                    )
                    if np.sum(finite_train) < 2 or not np.any(finite_test):
                        continue
                    prediction, train_mean = _ridge_predict(
                        x_train[finite_train], y_train[finite_train], x_test[finite_test], ridge_lambda
                    )
                    target = y_test[finite_test]
                    fold_sse = float(np.sum((target - prediction) ** 2))
                    fold_baseline = float(np.sum((target - train_mean) ** 2))
                    squared_error += fold_sse
                    baseline_squared_error += fold_baseline
                    observations += len(target)
                    fold_r2.append(
                        1.0 - fold_sse / fold_baseline
                        if fold_baseline > 0
                        else float("nan")
                    )
                rows.append(
                    {
                        "dataset": dataset_name,
                        "function": str(function),
                        "feature": feature,
                        "quantile": float(quantile),
                        "boots": len(boots),
                        "observations": observations,
                        "pooled_out_of_boot_r2": (
                            1.0 - squared_error / baseline_squared_error
                            if baseline_squared_error > 0
                            else float("nan")
                        ),
                        "mean_fold_r2": _mean(fold_r2),
                        "min_fold_r2": _min(fold_r2),
                    }
                )
    return rows


def _dataset_summary(name: str, dataset: ContextBatchDataset) -> dict:
    valid = dataset.quality_valid
    return {
        "dataset": name,
        "batches": int(len(dataset.batch_ids)),
        "valid_batches": int(np.sum(valid)),
        "boots": len(set(dataset.boot_ids[valid].tolist())),
        "labels": {
            str(label): int(np.sum(valid & (dataset.labels == label)))
            for label in sorted(set(dataset.labels[valid].tolist()))
        },
        "conditions": {
            str(condition): int(np.sum(valid & (dataset.conditions == condition)))
            for condition in sorted(set(dataset.conditions[valid].tolist()))
        },
        "functions": dataset.function_names.tolist(),
        "features": dataset.feature_names.tolist(),
        "quantiles": dataset.quantile_probs.tolist(),
    }


def run_factor_analysis(
    datasets: dict[str, ContextBatchDataset],
    contexts: dict[str, V1BatchContextDataset],
    output: Path,
) -> dict:
    attack_rows: list[dict] = []
    drift_rows: list[dict] = []
    context_rows: list[dict] = []
    for name, dataset in datasets.items():
        dataset.validate()
        attack_rows.extend(_channel_rows(name, dataset))
        drift_rows.extend(_normal_drift_rows(name, dataset))
        context_rows.extend(context_explainability(name, dataset, contexts[name]))
    aggregate_rows = aggregate_channels(attack_rows, drift_rows)

    output.mkdir(parents=True, exist_ok=True)
    _write_csv(output / "attack_separation_by_boot_condition.csv", attack_rows)
    _write_csv(output / "normal_drift_by_boot_condition.csv", drift_rows)
    _write_csv(output / "channel_summary.csv", aggregate_rows)
    _write_csv(output / "context_out_of_boot_r2.csv", context_rows)

    summaries = [_dataset_summary(name, dataset) for name, dataset in datasets.items()]
    candidate_rows = [
        row
        for row in aggregate_rows
        if row["feature"] in TIMING_FEATURES
        and row["rootkit_auc_min"] >= 0.90
        and row["rootkit_up_fraction"] == 1.0
        and row["specificity_margin_vs_worst_normal_drift"] > 0
    ]
    context_positive = [
        row for row in context_rows if row["pooled_out_of_boot_r2"] > 0
    ]
    report = {
        "schema_version": 1,
        "status": "posthoc_development_factor_audit",
        "warning": (
            "D2 and D3 labels are used to diagnose mechanisms. Results may guide a "
            "future method but cannot serve as its confirmatory validation. These "
            "channel statistics also precede invocation-role alignment; the separate "
            "composition audit proved that all-call iterate_dir quantiles are confounded."
        ),
        "datasets": summaries,
        "channels": len(aggregate_rows),
        "statistical_candidate_channels_before_invocation_alignment": len(candidate_rows),
        "context_targets": len(context_rows),
        "context_targets_positive_pooled_r2": len(context_positive),
        "context_positive_fraction": (
            len(context_positive) / len(context_rows) if context_rows else float("nan")
        ),
    }
    (output / "audit_summary.json").write_text(
        json.dumps(report, indent=2), encoding="utf-8"
    )
    return report


def main(argv: Iterable[str] | None = None) -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--d2", required=True, type=Path)
    parser.add_argument("--d2-context", required=True, type=Path)
    parser.add_argument("--d3", required=True, type=Path)
    parser.add_argument("--d3-context", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    report = run_factor_analysis(
        {
            "D2": ContextBatchDataset.load(args.d2),
            "D3-r1-test": ContextBatchDataset.load(args.d3),
        },
        {
            "D2": V1BatchContextDataset.load(args.d2_context),
            "D3-r1-test": V1BatchContextDataset.load(args.d3_context),
        },
        args.output,
    )
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
