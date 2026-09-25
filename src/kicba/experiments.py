from __future__ import annotations

import argparse
import csv
import json
import math
import random
from collections import defaultdict
from pathlib import Path
from typing import Iterable, Sequence

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

from .data import BatchDataset, dataset_manifest
from .detector import (
    ShiftDetector,
    calibrate_distance_threshold,
    predict_distance,
)
from .metrics import classification_metrics
from .online import ReplayResult, run_replay


SCENARIO_ORDER = ["default", "file_count", "filename_length", "ls_basic", "system_load"]
METHOD_ORDER = ["fixed", "blind_50", "score_gated", "dual_anchor"]
METRIC_COLUMNS = [
    "tp",
    "fp",
    "tn",
    "fn",
    "recall",
    "fpr",
    "precision",
    "f1",
    "accuracy",
    "mcc",
]


def _scenario_names(dataset: BatchDataset) -> list[str]:
    observed = set(dataset.descriptions.tolist())
    ordered = [name for name in SCENARIO_ORDER if name in observed]
    return ordered + sorted(observed - set(ordered))


def _upstream_scenario_order(dataset: BatchDataset) -> list[str]:
    """Recover dict insertion order produced by upstream's sorted file scan."""

    order: list[str] = []
    for idx in sorted(range(len(dataset.batch_ids)), key=lambda i: dataset.batch_ids[i]):
        if dataset.labels[idx] != "normal":
            continue
        scenario = str(dataset.descriptions[idx])
        if scenario not in order:
            order.append(scenario)
    return order


def _indices(dataset: BatchDataset, description: str, label: str) -> np.ndarray:
    return np.flatnonzero(
        (dataset.descriptions == description) & (dataset.labels == label)
    )


def _split_normal(
    dataset: BatchDataset,
    description: str,
    seed: int,
    fit_size: int = 50,
    calibration_size: int = 25,
) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    indices = _indices(dataset, description, "normal").copy()
    rng = np.random.default_rng(seed)
    rng.shuffle(indices)
    required = fit_size + calibration_size + 1
    if len(indices) < required:
        raise ValueError(
            f"{description} has {len(indices)} normal batches; at least {required} required"
        )
    return (
        indices[:fit_size],
        indices[fit_size : fit_size + calibration_size],
        indices[fit_size + calibration_size :],
    )


def _p_values(detector: ShiftDetector, values: np.ndarray) -> np.ndarray:
    return np.asarray([detector.min_p_value(batch) for batch in values], dtype=float)


def _oracle_threshold(
    detector: ShiftDetector, normal_values: np.ndarray, attack_values: np.ndarray
) -> tuple[float, dict[str, float | int]]:
    all_values = np.concatenate([normal_values, attack_values], axis=0)
    truth = np.concatenate(
        [np.zeros(len(normal_values), dtype=bool), np.ones(len(attack_values), dtype=bool)]
    )
    p_values = _p_values(detector, all_values)
    best_threshold = float("nan")
    best_metrics: dict[str, float | int] | None = None
    best_f1 = -1.0
    for threshold in np.logspace(-30, 0, num=100):
        metrics = classification_metrics(truth, p_values < threshold)
        f1 = float(metrics["f1"])
        candidate = f1 if np.isfinite(f1) else -1.0
        if candidate > best_f1:
            best_f1 = candidate
            best_threshold = float(threshold)
            best_metrics = metrics
    assert best_metrics is not None
    return best_threshold, best_metrics


def run_same_scenario(
    dataset: BatchDataset, seeds: Sequence[int]
) -> list[dict[str, float | int | str]]:
    rows: list[dict[str, float | int | str]] = []
    for seed in seeds:
        for scenario in _scenario_names(dataset):
            fit_idx, calibration_idx, normal_test_idx = _split_normal(
                dataset, scenario, seed
            )
            attack_idx = _indices(dataset, scenario, "rootkit")
            detector = ShiftDetector().fit(dataset.values[fit_idx])
            calibrated_threshold = calibrate_distance_threshold(
                detector, dataset.values[calibration_idx]
            )
            values = np.concatenate(
                [dataset.values[normal_test_idx], dataset.values[attack_idx]], axis=0
            )
            truth = np.concatenate(
                [
                    np.zeros(len(normal_test_idx), dtype=bool),
                    np.ones(len(attack_idx), dtype=bool),
                ]
            )
            calibrated_metrics = classification_metrics(
                truth, predict_distance(detector, values, calibrated_threshold)
            )
            rows.append(
                {
                    "seed": seed,
                    "scenario": scenario,
                    "threshold_policy": "normal_calibration_95pct_distance",
                    "threshold": calibrated_threshold,
                    **calibrated_metrics,
                }
            )

            # Exploratory robustness baseline added after empirical-covariance
            # split instability was observed. It uses only fit/calibration
            # normal data, but must not be presented as preregistered evidence.
            oas_detector = ShiftDetector(covariance="oas").fit(
                dataset.values[fit_idx]
            )
            oas_threshold = calibrate_distance_threshold(
                oas_detector, dataset.values[calibration_idx]
            )
            oas_metrics = classification_metrics(
                truth, predict_distance(oas_detector, values, oas_threshold)
            )
            rows.append(
                {
                    "seed": seed,
                    "scenario": scenario,
                    "threshold_policy": "exploratory_oas_normal_calibration_95pct_distance",
                    "threshold": oas_threshold,
                    **oas_metrics,
                }
            )

            oracle_threshold, oracle_metrics = _oracle_threshold(
                detector, dataset.values[normal_test_idx], dataset.values[attack_idx]
            )
            rows.append(
                {
                    "seed": seed,
                    "scenario": scenario,
                    "threshold_policy": "oracle_test_f1_upstream_style",
                    "threshold": oracle_threshold,
                    **oracle_metrics,
                }
            )
    return rows


def run_upstream_reproduction(
    dataset: BatchDataset, seed: int = 42, train_ratio: float = 0.333
) -> dict[str, float | int]:
    """Mirror the upstream seed-42, test-label-optimized offline evaluation.

    Each scenario has its own normal model. A single global threshold is then
    selected to maximize F1 on the combined test labels, matching the upstream
    source code's evaluation policy. This is reproduction evidence, not the
    leakage-free primary analysis.
    """

    rng = random.Random(seed)
    truth_parts: list[np.ndarray] = []
    p_value_parts: list[np.ndarray] = []
    # Upstream uses one global ``random`` generator and shuffles scenarios in
    # dictionary insertion order. That order comes from its sorted filename
    # scan and is not alphabetical/semantic, so it affects the exact seed-42
    # split and must be reconstructed for bit-for-bit reproduction.
    for scenario in _upstream_scenario_order(dataset):
        normal_idx = sorted(
            _indices(dataset, scenario, "normal").tolist(),
            key=lambda idx: dataset.batch_ids[idx],
        )
        rng.shuffle(normal_idx)
        split_point = int(math.ceil(len(normal_idx) * train_ratio))
        fit_idx = np.asarray(normal_idx[:split_point], dtype=int)
        normal_test_idx = np.asarray(normal_idx[split_point:], dtype=int)
        attack_idx = np.asarray(
            sorted(
                _indices(dataset, scenario, "rootkit").tolist(),
                key=lambda idx: dataset.batch_ids[idx],
            ),
            dtype=int,
        )
        detector = ShiftDetector().fit(dataset.values[fit_idx])
        p_value_parts.extend(
            [
                _p_values(detector, dataset.values[normal_test_idx]),
                _p_values(detector, dataset.values[attack_idx]),
            ]
        )
        truth_parts.extend(
            [
                np.zeros(len(normal_test_idx), dtype=bool),
                np.ones(len(attack_idx), dtype=bool),
            ]
        )
    truth = np.concatenate(truth_parts)
    p_values = np.concatenate(p_value_parts)
    best_threshold = float("nan")
    best_metrics: dict[str, float | int] | None = None
    best_f1 = -1.0
    for threshold in np.logspace(-30, 0, num=100):
        metrics = classification_metrics(truth, p_values < threshold)
        f1 = float(metrics["f1"])
        if np.isfinite(f1) and f1 > best_f1:
            best_f1 = f1
            best_threshold = float(threshold)
            best_metrics = metrics
    assert best_metrics is not None
    return {"seed": seed, "threshold": best_threshold, **best_metrics}


def run_cross_scenario(
    dataset: BatchDataset, seeds: Sequence[int], source_scenario: str = "default"
) -> list[dict[str, float | int | str]]:
    rows: list[dict[str, float | int | str]] = []
    for seed in seeds:
        fit_idx, calibration_idx, source_test_idx = _split_normal(
            dataset, source_scenario, seed
        )
        detector = ShiftDetector().fit(dataset.values[fit_idx])
        threshold = calibrate_distance_threshold(detector, dataset.values[calibration_idx])
        for target in _scenario_names(dataset):
            normal_idx = (
                source_test_idx
                if target == source_scenario
                else _indices(dataset, target, "normal")
            )
            attack_idx = _indices(dataset, target, "rootkit")
            values = np.concatenate(
                [dataset.values[normal_idx], dataset.values[attack_idx]], axis=0
            )
            truth = np.concatenate(
                [
                    np.zeros(len(normal_idx), dtype=bool),
                    np.ones(len(attack_idx), dtype=bool),
                ]
            )
            metrics = classification_metrics(
                truth, predict_distance(detector, values, threshold)
            )
            rows.append(
                {
                    "seed": seed,
                    "source_scenario": source_scenario,
                    "target_scenario": target,
                    "threshold": threshold,
                    **metrics,
                }
            )
    return rows


def _ordered_segment(
    dataset: BatchDataset,
    scenario: str,
    label: str,
    rng: np.random.Generator,
    limit: int | None = None,
) -> np.ndarray:
    indices = _indices(dataset, scenario, label).copy()
    rng.shuffle(indices)
    return indices if limit is None else indices[:limit]


def _replay_definitions(
    dataset: BatchDataset, seed: int
) -> tuple[np.ndarray, np.ndarray, float, dict[str, np.ndarray]]:
    fit_idx, calibration_idx, _ = _split_normal(dataset, "default", seed)
    detector = ShiftDetector().fit(dataset.values[fit_idx])
    threshold = calibrate_distance_threshold(detector, dataset.values[calibration_idx])
    rng = np.random.default_rng(seed + 10_000)
    definitions = {
        "normal_drift_system_load": _ordered_segment(
            dataset, "system_load", "normal", rng, 100
        ),
        "persistent_rootkit_default": _ordered_segment(
            dataset, "default", "rootkit", rng, 100
        ),
        "persistent_rootkit_system_load": _ordered_segment(
            dataset, "system_load", "rootkit", rng, 100
        ),
        "drift_then_rootkit": np.concatenate(
            [
                _ordered_segment(dataset, "system_load", "normal", rng, 50),
                _ordered_segment(dataset, "system_load", "rootkit", rng, 100),
            ]
        ),
    }
    return fit_idx, calibration_idx, threshold, definitions


def run_online_replays(
    dataset: BatchDataset, seeds: Sequence[int]
) -> tuple[list[dict[str, float | int | str]], list[dict[str, float | int | str]]]:
    summary_rows: list[dict[str, float | int | str]] = []
    detail_rows: list[dict[str, float | int | str]] = []
    for seed in seeds:
        fit_idx, _calibration_idx, threshold, definitions = _replay_definitions(
            dataset, seed
        )
        initial_values = dataset.values[fit_idx]
        initial_labels = np.zeros(len(fit_idx), dtype=bool)
        for replay_name, replay_idx in definitions.items():
            replay_truth = dataset.labels[replay_idx] == "rootkit"
            for method in METHOD_ORDER:
                result = run_replay(
                    initial_values=initial_values,
                    initial_is_attack=initial_labels,
                    replay_values=dataset.values[replay_idx],
                    replay_is_attack=replay_truth,
                    threshold=threshold,
                    method=method,
                    window_size=50,
                    score_kind="distance",
                )
                summary_rows.append(
                    {
                        "seed": seed,
                        "replay": replay_name,
                        "threshold": threshold,
                        **result.metrics(),
                    }
                )
                if seed == seeds[0]:
                    for step, batch_idx in enumerate(replay_idx, start=1):
                        detail_rows.append(
                            {
                                "seed": seed,
                                "replay": replay_name,
                                "method": method,
                                "step": step,
                                "batch_id": dataset.batch_ids[batch_idx],
                                "scenario": dataset.descriptions[batch_idx],
                                "label": dataset.labels[batch_idx],
                                "detector_score": result.scores[step - 1],
                                "anomaly_score": result.scores[step - 1],
                                "predicted_anomaly": int(result.predicted[step - 1]),
                                "updated": int(result.updated[step - 1]),
                                "window_attack_fraction": result.window_attack_fraction[
                                    step - 1
                                ],
                            }
                        )
    return summary_rows, detail_rows


def _write_csv(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not rows:
        raise ValueError(f"No rows for {path}")
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)


def _finite(values: Iterable[float]) -> np.ndarray:
    array = np.asarray(list(values), dtype=float)
    return array[np.isfinite(array)]


def _aggregate(
    rows: list[dict], group_fields: Sequence[str], metric_fields: Sequence[str]
) -> list[dict]:
    groups: dict[tuple, list[dict]] = defaultdict(list)
    for row in rows:
        groups[tuple(row[field] for field in group_fields)].append(row)
    output: list[dict] = []
    for key, group_rows in sorted(groups.items()):
        record = dict(zip(group_fields, key))
        record["runs"] = len(group_rows)
        for metric in metric_fields:
            values = _finite(float(row[metric]) for row in group_rows)
            record[f"{metric}_mean"] = float(np.mean(values)) if len(values) else float("nan")
            record[f"{metric}_lo"] = (
                float(np.quantile(values, 0.025)) if len(values) else float("nan")
            )
            record[f"{metric}_hi"] = (
                float(np.quantile(values, 0.975)) if len(values) else float("nan")
            )
        output.append(record)
    return output


def _plot_same_scenario(aggregate_rows: list[dict], figures_dir: Path) -> None:
    rows = [
        row
        for row in aggregate_rows
        if row["threshold_policy"] == "normal_calibration_95pct_distance"
    ]
    rows.sort(key=lambda row: SCENARIO_ORDER.index(row["scenario"]))
    x = np.arange(len(rows))
    width = 0.36
    fig, ax = plt.subplots(figsize=(8.2, 4.2))
    ax.bar(x - width / 2, [r["recall_mean"] for r in rows], width, label="Rootkit recall", color="0.25")
    ax.bar(x + width / 2, [r["fpr_mean"] for r in rows], width, label="Normal FPR", color="0.75", edgecolor="black")
    ax.set_xticks(x, [r["scenario"] for r in rows], rotation=20, ha="right")
    ax.set_ylim(0, 1.05)
    ax.set_ylabel("Rate")
    ax.legend(frameon=False)
    ax.spines[["top", "right"]].set_visible(False)
    fig.tight_layout()
    fig.savefig(figures_dir / "same_scenario_calibrated.png", dpi=180)
    plt.close(fig)


def _plot_cross_scenario(aggregate_rows: list[dict], figures_dir: Path) -> None:
    rows = sorted(
        aggregate_rows, key=lambda row: SCENARIO_ORDER.index(row["target_scenario"])
    )
    fig, ax = plt.subplots(figsize=(7.8, 4.0))
    x = np.arange(len(rows))
    ax.bar(x, [r["fpr_mean"] for r in rows], color="0.65", edgecolor="black")
    ax.errorbar(
        x,
        [r["fpr_mean"] for r in rows],
        yerr=[
            [r["fpr_mean"] - r["fpr_lo"] for r in rows],
            [r["fpr_hi"] - r["fpr_mean"] for r in rows],
        ],
        fmt="none",
        color="black",
        capsize=3,
    )
    ax.set_xticks(x, [r["target_scenario"] for r in rows], rotation=20, ha="right")
    ax.set_ylim(0, 1.05)
    ax.set_ylabel("Normal false-positive rate")
    ax.set_title("Model trained/calibrated on Default normal only")
    ax.spines[["top", "right"]].set_visible(False)
    fig.tight_layout()
    fig.savefig(figures_dir / "cross_scenario_fpr.png", dpi=180)
    plt.close(fig)


def _plot_replay(detail_rows: list[dict], figures_dir: Path) -> None:
    replay_name = "drift_then_rootkit"
    rows = [row for row in detail_rows if row["replay"] == replay_name]
    fig, axes = plt.subplots(2, 1, figsize=(9.0, 6.0), sharex=True)
    for method in METHOD_ORDER:
        method_rows = [row for row in rows if row["method"] == method]
        axes[0].plot(
            [row["step"] for row in method_rows],
            [row["anomaly_score"] for row in method_rows],
            label=method,
            linewidth=1.2,
        )
        axes[1].plot(
            [row["step"] for row in method_rows],
            [row["window_attack_fraction"] for row in method_rows],
            label=method,
            linewidth=1.2,
        )
    axes[0].axvline(50.5, color="black", linestyle="--", linewidth=1)
    axes[0].set_ylabel("Anomaly score (max Mahalanobis d²)")
    axes[0].legend(frameon=False, ncol=2)
    axes[1].axvline(50.5, color="black", linestyle="--", linewidth=1)
    axes[1].set_ylabel("Attack fraction in\nadaptive window")
    axes[1].set_xlabel("Replay batch (rootkit begins after batch 50)")
    axes[1].set_ylim(-0.02, 1.02)
    for ax in axes:
        ax.spines[["top", "right"]].set_visible(False)
    fig.tight_layout()
    fig.savefig(figures_dir / "replay_drift_then_rootkit.png", dpi=180)
    plt.close(fig)


def _format_rate(value: float) -> str:
    return "NA" if not np.isfinite(value) else f"{100 * value:.1f}%"


def _write_report(
    output_dir: Path,
    manifest: dict,
    same_agg: list[dict],
    cross_agg: list[dict],
    replay_agg: list[dict],
    repetitions: int,
    upstream_reproduction: dict,
) -> None:
    calibrated = {
        row["scenario"]: row
        for row in same_agg
        if row["threshold_policy"] == "normal_calibration_95pct_distance"
    }
    oracle = {
        row["scenario"]: row
        for row in same_agg
        if row["threshold_policy"] == "oracle_test_f1_upstream_style"
    }
    oas = {
        row["scenario"]: row
        for row in same_agg
        if row["threshold_policy"]
        == "exploratory_oas_normal_calibration_95pct_distance"
    }
    cross = {row["target_scenario"]: row for row in cross_agg}
    replay_lookup = {
        (row["replay"], row["method"]): row for row in replay_agg
    }
    lines = [
        "# Public-data phase results",
        "",
        f"Dataset: {manifest['batches']} batches; {len(manifest['intervals'])} function intervals; {repetitions} split/order seeds.",
        "",
        "> These are D1 public-data reproduction and replay results. They do not validate kernel-context gating, because D1 has no synchronized scheduler/IRQ/frequency context.",
        "",
        "## Upstream-style seed-42 reproduction",
        "",
        f"Combined TP={upstream_reproduction['tp']}, FP={upstream_reproduction['fp']}, TN={upstream_reproduction['tn']}, FN={upstream_reproduction['fn']}, F1={upstream_reproduction['f1']:.4f}.",
        "",
        "This mirrors the source code policy that selects the threshold on test labels and is reported only as a reproduction check.",
        "",
        "## Same-scenario detection",
        "",
        "| Scenario | Empirical recall | Empirical FPR | Exploratory OAS recall | OAS FPR | Oracle-test F1 |",
        "|---|---:|---:|---:|---:|---:|",
    ]
    for scenario in _scenario_names_from_manifest(manifest):
        c = calibrated[scenario]
        o = oracle[scenario]
        s = oas[scenario]
        lines.append(
            f"| {scenario} | {_format_rate(c['recall_mean'])} | {_format_rate(c['fpr_mean'])} | {_format_rate(s['recall_mean'])} | {_format_rate(s['fpr_mean'])} | {_format_rate(o['f1_mean'])} |"
        )
    lines.extend(
        [
            "",
            "The oracle threshold is selected on test labels to mirror the upstream evaluation style; it is optimistic and is not the primary result.",
            "OAS covariance shrinkage was added after observing split instability. It is a labeled exploratory robustness baseline even though its fit and threshold use normal data only.",
            "",
            "## Default-trained cross-scenario test",
            "",
            "| Target scenario | Normal FPR | Rootkit recall |",
            "|---|---:|---:|",
        ]
    )
    for scenario in _scenario_names_from_manifest(manifest):
        row = cross[scenario]
        lines.append(
            f"| {scenario} | {_format_rate(row['fpr_mean'])} | {_format_rate(row['recall_mean'])} |"
        )
    lines.extend(
        [
            "",
            "## Online replay: drift then persistent rootkit",
            "",
            "| Method | Recall | Normal FPR | Update contamination | Benign update acceptance |",
            "|---|---:|---:|---:|---:|",
        ]
    )
    for method in METHOD_ORDER:
        row = replay_lookup[("drift_then_rootkit", method)]
        lines.append(
            f"| {method} | {_format_rate(row['recall_mean'])} | {_format_rate(row['fpr_mean'])} | {_format_rate(row['contamination_rate_mean'])} | {_format_rate(row['benign_update_acceptance_mean'])} |"
        )
    lines.extend(
        [
            "",
            "## Interpretation boundary",
            "",
            "- Blind-window contamination is a model-state result, not proof that an alerting system forgets an already latched incident.",
            "- Score-gated and dual-anchor are generic timing-only baselines, not the proposed kernel-context method.",
            "- Seed intervals here quantify split/order sensitivity on one public collection, not population confidence across independent machines or days.",
            "- RQ4/RQ5 remain pending until D2 live-kernel data are collected.",
            "",
        ]
    )
    (output_dir / "RESULTS.md").write_text("\n".join(lines), encoding="utf-8")


def _scenario_names_from_manifest(manifest: dict) -> list[str]:
    observed = set(manifest["counts"])
    return [name for name in SCENARIO_ORDER if name in observed] + sorted(
        observed - set(SCENARIO_ORDER)
    )


def main(argv: Iterable[str] | None = None) -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--data", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--repetitions", default=30, type=int)
    args = parser.parse_args(argv)
    if args.repetitions < 1:
        raise ValueError("repetitions must be positive")

    dataset = BatchDataset.load(args.data)
    dataset.validate()
    output_dir = args.output
    figures_dir = output_dir / "figures"
    figures_dir.mkdir(parents=True, exist_ok=True)
    seeds = list(range(args.repetitions))

    manifest = dataset_manifest(dataset)
    (output_dir / "dataset_manifest.json").write_text(
        json.dumps(manifest, indent=2), encoding="utf-8"
    )

    upstream_reproduction = run_upstream_reproduction(dataset)
    (output_dir / "upstream_reproduction_seed42.json").write_text(
        json.dumps(upstream_reproduction, indent=2), encoding="utf-8"
    )
    same_rows = run_same_scenario(dataset, seeds)
    cross_rows = run_cross_scenario(dataset, seeds)
    replay_rows, replay_detail = run_online_replays(dataset, seeds)
    _write_csv(output_dir / "same_scenario.csv", same_rows)
    _write_csv(output_dir / "cross_scenario.csv", cross_rows)
    _write_csv(output_dir / "online_replay.csv", replay_rows)
    _write_csv(output_dir / "online_replay_detail_seed0.csv", replay_detail)

    same_agg = _aggregate(
        same_rows, ["scenario", "threshold_policy"], ["recall", "fpr", "precision", "f1", "accuracy", "mcc"]
    )
    cross_agg = _aggregate(
        cross_rows, ["source_scenario", "target_scenario"], ["recall", "fpr", "precision", "f1", "accuracy", "mcc"]
    )
    replay_agg = _aggregate(
        replay_rows,
        ["replay", "method"],
        [
            "recall",
            "fpr",
            "precision",
            "f1",
            "accuracy",
            "mcc",
            "contamination_rate",
            "benign_update_acceptance",
            "first_detection_delay",
        ],
    )
    _write_csv(output_dir / "same_scenario_aggregate.csv", same_agg)
    _write_csv(output_dir / "cross_scenario_aggregate.csv", cross_agg)
    _write_csv(output_dir / "online_replay_aggregate.csv", replay_agg)

    _plot_same_scenario(same_agg, figures_dir)
    _plot_cross_scenario(cross_agg, figures_dir)
    _plot_replay(replay_detail, figures_dir)
    _write_report(
        output_dir,
        manifest,
        same_agg,
        cross_agg,
        replay_agg,
        args.repetitions,
        upstream_reproduction,
    )
    print(f"Wrote results to {output_dir}")


if __name__ == "__main__":
    main()
