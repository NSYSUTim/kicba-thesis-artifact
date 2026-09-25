from __future__ import annotations

import argparse
import csv
import json
from collections import defaultdict
from pathlib import Path
from typing import Iterable

import numpy as np

from .context import ContextBatchDataset
from .d2_experiments import _bootstrap_mean_ci
from .detector import ShiftDetector, calibrate_distance_threshold, predict_distance
from .kicba import RAW_FEATURES, feature_view
from .v1 import SafeAdaptiveDetector


WINDOWS = (20, 50, 100)


def _read_rows(path: Path) -> list[dict]:
    with path.open(newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    for row in rows:
        for field in ("first_q10_ns", "first_median_ns", "first_q90_ns"):
            row[field] = float(row[field])
        for field in (
            "iterations",
            "pids_with_one_call",
            "pids_with_two_calls",
            "pids_with_other_call_count",
        ):
            row[field] = int(row[field])
    return rows


def _role_values(rows: list[dict]) -> np.ndarray:
    matrix = np.asarray(
        [
            [row["first_q10_ns"], row["first_median_ns"], row["first_q90_ns"]]
            for row in rows
        ],
        dtype=float,
    )
    return np.log1p(matrix)[:, np.newaxis, :]


def _ordered(rows: list[dict]) -> list[dict]:
    return sorted(rows, key=lambda row: str(row["batch_id"]))


def _structure_normal(row: dict) -> bool:
    return bool(
        row["pids_with_two_calls"] == row["iterations"]
        and row["pids_with_one_call"] == 0
        and row["pids_with_other_call_count"] == 0
    )


def _metrics(
    rows: list[dict], decisions: np.ndarray, updates: np.ndarray, fractions: np.ndarray
) -> dict:
    truth = np.asarray([row["label"] == "rootkit" for row in rows], dtype=bool)
    suspicious = decisions == "suspicious"
    attacks = int(np.sum(truth))
    normal = int(np.sum(~truth))
    return {
        "batches": len(rows),
        "attack_batches": attacks,
        "normal_batches": normal,
        "recall": float(np.sum(suspicious & truth) / attacks),
        "fpr": float(np.sum(suspicious & ~truth) / normal),
        "attack_update_acceptance": float(np.sum(updates & truth) / attacks),
        "benign_update_acceptance": float(np.sum(updates & ~truth) / normal),
        "max_window_attack_fraction": float(np.max(fractions)) if len(fractions) else 0.0,
    }


def _fixed_role(fit: list[dict], calibration: list[dict], test: list[dict]):
    detector = ShiftDetector(covariance="oas").fit(_role_values(fit))
    threshold = calibrate_distance_threshold(
        detector, _role_values(calibration), target_fpr=0.05
    )
    predicted = predict_distance(detector, _role_values(test), threshold)
    decisions = np.where(predicted, "suspicious", "normal")
    return decisions, np.zeros(len(test), dtype=bool), np.zeros(len(test), dtype=float)


def _adaptive(
    fit: list[dict],
    calibration: list[dict],
    test: list[dict],
    window: int,
    update_policy: str,
):
    fit = _ordered(fit)
    calibration = _ordered(calibration)
    test = _ordered(test)
    model = SafeAdaptiveDetector(window_size=window).fit(
        _role_values(fit),
        _role_values(calibration),
        np.ones(len(calibration), dtype=bool),
    )
    steps = []
    for row, batch in zip(test, _role_values(test)):
        if update_policy == "blind":
            eligible = True
        elif update_policy == "structure":
            eligible = _structure_normal(row)
        elif update_policy == "none":
            eligible = False
        else:
            raise ValueError(update_policy)
        steps.append(
            model.step(
                batch,
                quality_valid=True,
                update_guard_accepted=eligible,
                evaluation_is_attack=row["label"] == "rootkit",
            )
        )
    return (
        np.asarray([step.decision for step in steps], dtype=str),
        np.asarray([step.updated for step in steps], dtype=bool),
        np.asarray([step.window_attack_fraction for step in steps], dtype=float),
        test,
    )


def _fixed_all_call(
    fit_ids: list[str],
    calibration_ids: list[str],
    test_ids: list[str],
    dataset: ContextBatchDataset,
):
    index = {str(batch): idx for idx, batch in enumerate(dataset.batch_ids)}
    raw = feature_view(dataset, RAW_FEATURES)
    fit = raw[np.asarray([index[batch] for batch in fit_ids])]
    calibration = raw[np.asarray([index[batch] for batch in calibration_ids])]
    test = raw[np.asarray([index[batch] for batch in test_ids])]
    detector = ShiftDetector(covariance="oas").fit(fit)
    threshold = calibrate_distance_threshold(detector, calibration, target_fpr=0.05)
    return np.where(predict_distance(detector, test, threshold), "suspicious", "normal")


def _append_fold(
    output: list[dict],
    dataset_name: str,
    fold: int,
    boot: str,
    method: str,
    rows: list[dict],
    decisions: np.ndarray,
    updates: np.ndarray,
    fractions: np.ndarray,
) -> None:
    output.append(
        {
            "dataset": dataset_name,
            "fold": fold,
            "test_boot": boot,
            "method": method,
            **_metrics(rows, decisions, updates, fractions),
        }
    )


def run_experiments(
    rows: list[dict],
    d2_timing: ContextBatchDataset,
    d3_cal_timing: ContextBatchDataset,
    d3_test_timing: ContextBatchDataset,
) -> list[dict]:
    output: list[dict] = []
    d2 = [row for row in rows if row["dataset"] == "D2"]
    d2_boots = sorted({row["boot"] for row in d2})
    for fold, test_boot in enumerate(d2_boots):
        calibration_boot = d2_boots[(fold - 1) % len(d2_boots)]
        fit = [
            row
            for row in d2
            if row["label"] == "normal"
            and row["boot"] not in {test_boot, calibration_boot}
        ]
        calibration = [
            row
            for row in d2
            if row["label"] == "normal" and row["boot"] == calibration_boot
        ]
        test = _ordered([row for row in d2 if row["boot"] == test_boot])
        decisions, updates, fractions = _fixed_role(fit, calibration, test)
        _append_fold(
            output, "D2", fold, test_boot, "fixed_role_aligned", test,
            decisions, updates, fractions,
        )
        all_call = _fixed_all_call(
            [row["batch_id"] for row in fit],
            [row["batch_id"] for row in calibration],
            [row["batch_id"] for row in test],
            d2_timing,
        )
        _append_fold(
            output, "D2", fold, test_boot, "fixed_all_call", test,
            all_call, np.zeros(len(test), dtype=bool), np.zeros(len(test)),
        )
        for window in WINDOWS:
            for policy in ("none", "blind", "structure"):
                decisions, updates, fractions, ordered_test = _adaptive(
                    fit, calibration, test, window, policy
                )
                _append_fold(
                    output, "D2", fold, test_boot,
                    f"{policy}_update_w{window}", ordered_test,
                    decisions, updates, fractions,
                )

    fit = [row for row in d2 if row["label"] == "normal"]
    calibration = [row for row in rows if row["dataset"] == "D3-r1-calibration"]
    d3_test = [row for row in rows if row["dataset"] == "D3-r1-test"]
    d3_boots = sorted({row["boot"] for row in d3_test})
    for fold, test_boot in enumerate(d3_boots):
        test = _ordered([row for row in d3_test if row["boot"] == test_boot])
        decisions, updates, fractions = _fixed_role(fit, calibration, test)
        _append_fold(
            output, "D3-r1-test", fold, test_boot, "fixed_role_aligned", test,
            decisions, updates, fractions,
        )
        all_call = _fixed_all_call(
            [row["batch_id"] for row in fit],
            [row["batch_id"] for row in calibration],
            [row["batch_id"] for row in test],
            _CombinedTimingView(d2_timing, d3_cal_timing, d3_test_timing),
        )
        _append_fold(
            output, "D3-r1-test", fold, test_boot, "fixed_all_call", test,
            all_call, np.zeros(len(test), dtype=bool), np.zeros(len(test)),
        )
        for window in WINDOWS:
            for policy in ("none", "blind", "structure"):
                decisions, updates, fractions, ordered_test = _adaptive(
                    fit, calibration, test, window, policy
                )
                _append_fold(
                    output, "D3-r1-test", fold, test_boot,
                    f"{policy}_update_w{window}", ordered_test,
                    decisions, updates, fractions,
                )
    return output


class _CombinedTimingView:
    """Minimal ContextBatchDataset-compatible view for cross-campaign fixed tests."""

    def __init__(self, *datasets: ContextBatchDataset):
        first = datasets[0]
        self.batch_ids = np.concatenate([dataset.batch_ids for dataset in datasets])
        self.function_names = first.function_names
        self.feature_names = first.feature_names
        self.quantile_probs = first.quantile_probs
        self.values = np.concatenate([dataset.values for dataset in datasets], axis=0)


def aggregate(folds: list[dict]) -> list[dict]:
    grouped: dict[tuple[str, str], list[dict]] = defaultdict(list)
    for row in folds:
        grouped[(row["dataset"], row["method"])].append(row)
    output: list[dict] = []
    metrics = (
        "recall", "fpr", "attack_update_acceptance",
        "benign_update_acceptance", "max_window_attack_fraction",
    )
    for (dataset, method), rows in sorted(grouped.items()):
        result: dict[str, object] = {
            "dataset": dataset,
            "method": method,
            "folds": len(rows),
            "ci_unit": "boot",
        }
        for metric in metrics:
            values = np.asarray([float(row[metric]) for row in rows])
            mean, lo, hi = _bootstrap_mean_ci(values)
            result[f"{metric}_mean"] = mean
            result[f"{metric}_ci_lo"] = lo
            result[f"{metric}_ci_hi"] = hi
        output.append(result)
    return output


def comparisons(folds: list[dict]) -> list[dict]:
    index = {
        (row["dataset"], row["test_boot"], row["method"]): row for row in folds
    }
    output: list[dict] = []
    for dataset in sorted({row["dataset"] for row in folds}):
        boots = sorted({row["test_boot"] for row in folds if row["dataset"] == dataset})
        for window in WINDOWS:
            primary = f"structure_update_w{window}"
            for comparator in (
                f"blind_update_w{window}", f"none_update_w{window}",
                "fixed_role_aligned", "fixed_all_call",
            ):
                recall_difference = np.asarray([
                    float(index[(dataset, boot, primary)]["recall"])
                    - float(index[(dataset, boot, comparator)]["recall"])
                    for boot in boots
                ])
                fpr_reduction = np.asarray([
                    float(index[(dataset, boot, comparator)]["fpr"])
                    - float(index[(dataset, boot, primary)]["fpr"])
                    for boot in boots
                ])
                attack_update_reduction = np.asarray([
                    float(index[(dataset, boot, comparator)]["attack_update_acceptance"])
                    - float(index[(dataset, boot, primary)]["attack_update_acceptance"])
                    for boot in boots
                ])
                rec = _bootstrap_mean_ci(recall_difference)
                fpr = _bootstrap_mean_ci(fpr_reduction)
                update = _bootstrap_mean_ci(attack_update_reduction)
                output.append({
                    "dataset": dataset,
                    "primary": primary,
                    "comparator": comparator,
                    "folds": len(boots),
                    "recall_difference_mean": rec[0],
                    "recall_difference_ci_lo": rec[1],
                    "recall_difference_ci_hi": rec[2],
                    "fpr_reduction_mean": fpr[0],
                    "fpr_reduction_ci_lo": fpr[1],
                    "fpr_reduction_ci_hi": fpr[2],
                    "attack_update_reduction_mean": update[0],
                    "attack_update_reduction_ci_lo": update[1],
                    "attack_update_reduction_ci_hi": update[2],
                })
    return output


def _write_csv(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def main(argv: Iterable[str] | None = None) -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--composition", required=True, type=Path)
    parser.add_argument("--d2-timing", required=True, type=Path)
    parser.add_argument("--d3-cal-timing", required=True, type=Path)
    parser.add_argument("--d3-test-timing", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    folds = run_experiments(
        _read_rows(args.composition),
        ContextBatchDataset.load(args.d2_timing),
        ContextBatchDataset.load(args.d3_cal_timing),
        ContextBatchDataset.load(args.d3_test_timing),
    )
    summary = aggregate(folds)
    paired = comparisons(folds)
    args.output.mkdir(parents=True, exist_ok=True)
    _write_csv(args.output / "fold_results.csv", folds)
    _write_csv(args.output / "summary.csv", summary)
    _write_csv(args.output / "paired_comparisons.csv", paired)
    design = {
        "schema_version": 1,
        "status": "posthoc_role_aligned_development",
        "warning": (
            "The role representation and structure guard were designed after D2/D3 "
            "inspection. These results are developmental and require new confirmation."
        ),
        "role_features": ["first_q10_ns", "first_median_ns", "first_q90_ns"],
        "structure_update_rule": (
            "Every monitored listing PID has exactly two iterate_dir calls; the rule "
            "controls updates only and is not ORed into the alert decision."
        ),
        "windows": list(WINDOWS),
        "windows_are_independent": True,
        "test_boots": {
            dataset: len({row["test_boot"] for row in folds if row["dataset"] == dataset})
            for dataset in sorted({row["dataset"] for row in folds})
        },
    }
    (args.output / "design.json").write_text(
        json.dumps(design, indent=2), encoding="utf-8"
    )
    print(json.dumps(design, indent=2))


if __name__ == "__main__":
    main()
