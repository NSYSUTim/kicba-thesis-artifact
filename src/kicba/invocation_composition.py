from __future__ import annotations

import argparse
import csv
import gzip
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Iterable, Sequence

import numpy as np

from .factor_analysis import rank_auc


def _pair_iterate_dir(events: Sequence[dict]) -> list[tuple[int, int, int]]:
    """Return (pid, start, duration) for complete iterate_dir calls."""

    stacks: dict[int, list[int]] = defaultdict(list)
    pairs: list[tuple[int, int, int]] = []
    for event in sorted(events, key=lambda item: int(item["ts"])):
        if event.get("function") != "iterate_dir":
            continue
        pid = int(event.get("pid", -1))
        timestamp = int(event["ts"])
        if event.get("kind") == "target_enter":
            stacks[pid].append(timestamp)
        elif event.get("kind") == "target_return" and stacks[pid]:
            start = stacks[pid].pop()
            if timestamp >= start:
                pairs.append((pid, start, timestamp - start))
    if any(stacks.values()):
        raise ValueError("Unmatched iterate_dir entry in audited batch")
    return pairs


def _quantile(values: list[int], probability: float) -> float:
    if not values:
        return float("nan")
    return float(np.quantile(np.asarray(values, dtype=float), probability))


def audit_record(record: dict, dataset_name: str, path: Path) -> dict:
    pairs = _pair_iterate_dir(record.get("events", []))
    by_pid: dict[int, list[tuple[int, int]]] = defaultdict(list)
    for pid, start, duration in pairs:
        by_pid[pid].append((start, duration))
    ordered = {
        pid: [duration for _start, duration in sorted(values)]
        for pid, values in by_pid.items()
    }
    first = [values[0] for values in ordered.values() if values]
    second = [values[1] for values in ordered.values() if len(values) > 1]
    truth = record.get("truth", {})
    collection = record.get("collection", {})
    environment = record.get("environment", {})
    counts = Counter(len(values) for values in ordered.values())
    return {
        "dataset": dataset_name,
        "path": str(path),
        "batch_id": str(record.get("batch_id")),
        "boot": str(environment.get("boot_id", "unknown")),
        "label": str(truth.get("label", "unknown")),
        "condition": str(truth.get("condition", "unknown")),
        "iterations": int(collection.get("iterations", 0)),
        "iterate_calls": len(pairs),
        "unique_pids": len(ordered),
        "pids_with_one_call": int(counts.get(1, 0)),
        "pids_with_two_calls": int(counts.get(2, 0)),
        "pids_with_other_call_count": int(
            sum(count for calls, count in counts.items() if calls not in {1, 2})
        ),
        "all_q10_ns": _quantile([duration for _pid, _start, duration in pairs], 0.1),
        "first_q10_ns": _quantile(first, 0.1),
        "first_median_ns": _quantile(first, 0.5),
        "first_q90_ns": _quantile(first, 0.9),
        "second_q10_ns": _quantile(second, 0.1),
        "second_median_ns": _quantile(second, 0.5),
        "second_q90_ns": _quantile(second, 0.9),
    }


def _paths(root: Path) -> list[Path]:
    paths = sorted(root.rglob("batch_*.json.gz"))
    if not paths:
        raise ValueError(f"No raw batch files under {root}")
    return paths


def audit_dataset(name: str, root: Path) -> list[dict]:
    rows: list[dict] = []
    paths = _paths(root)
    for position, path in enumerate(paths, start=1):
        with gzip.open(path, "rt", encoding="utf-8") as handle:
            rows.append(audit_record(json.load(handle), name, path))
        if position % 100 == 0 or position == len(paths):
            print(f"{name}: audited {position}/{len(paths)}", flush=True)
    return rows


def separation_rows(rows: list[dict]) -> list[dict]:
    grouped: dict[tuple[str, str, str], list[dict]] = defaultdict(list)
    for row in rows:
        grouped[(row["dataset"], row["boot"], row["condition"])].append(row)
    output: list[dict] = []
    for (dataset, boot, condition), values in sorted(grouped.items()):
        normal = [row for row in values if row["label"] == "normal"]
        rootkit = [row for row in values if row["label"] == "rootkit"]
        if not normal or not rootkit:
            continue
        for feature in ("all_q10_ns", "first_q10_ns", "first_median_ns", "first_q90_ns"):
            auc = rank_auc(
                np.asarray([row[feature] for row in normal]),
                np.asarray([row[feature] for row in rootkit]),
            )
            output.append(
                {
                    "dataset": dataset,
                    "boot": boot,
                    "condition": condition,
                    "feature": feature,
                    "normal_n": len(normal),
                    "rootkit_n": len(rootkit),
                    "rootkit_auc": auc,
                    "rootkit_strength": abs(2.0 * auc - 1.0),
                    "direction": "up" if auc > 0.5 else "down" if auc < 0.5 else "tie",
                }
            )
    return output


def _write_csv(path: Path, rows: list[dict]) -> None:
    if not rows:
        raise ValueError(f"No rows for {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def summarize(rows: list[dict], separated: list[dict]) -> dict:
    call_patterns: dict[str, dict[str, dict]] = defaultdict(dict)
    for dataset in sorted({row["dataset"] for row in rows}):
        for label in ("normal", "rootkit"):
            subset = [
                row for row in rows if row["dataset"] == dataset and row["label"] == label
            ]
            call_patterns[dataset][label] = {
                "batches": len(subset),
                "iterate_calls_per_iteration": sorted(
                    {
                        row["iterate_calls"] / row["iterations"]
                        for row in subset
                        if row["iterations"]
                    }
                ),
                "pids_with_one_call": sorted({row["pids_with_one_call"] for row in subset}),
                "pids_with_two_calls": sorted({row["pids_with_two_calls"] for row in subset}),
            }
    auc_summary: dict[str, dict[str, dict]] = defaultdict(dict)
    for dataset in sorted({row["dataset"] for row in separated}):
        for feature in sorted({row["feature"] for row in separated}):
            values = [
                float(row["rootkit_auc"])
                for row in separated
                if row["dataset"] == dataset and row["feature"] == feature
            ]
            auc_summary[dataset][feature] = {
                "groups": len(values),
                "mean_auc": float(np.mean(values)),
                "min_auc": float(np.min(values)),
                "max_auc": float(np.max(values)),
                "up_fraction": float(np.mean(np.asarray(values) > 0.5)),
            }
    return {
        "schema_version": 1,
        "status": "posthoc_invocation_composition_audit",
        "call_patterns": call_patterns,
        "within_boot_condition_separation": auc_summary,
        "interpretation_guardrail": (
            "A difference between all-call quantiles and first-call-only quantiles "
            "indicates invocation-composition confounding. All-call timing must not "
            "be interpreted as pure per-invocation execution overhead."
        ),
    }


def main(argv: Iterable[str] | None = None) -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--input", action="append", nargs=2, metavar=("NAME", "ROOT"), required=True
    )
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    rows: list[dict] = []
    for name, root in args.input:
        rows.extend(audit_dataset(name, Path(root)))
    separated = separation_rows(rows)
    args.output.mkdir(parents=True, exist_ok=True)
    _write_csv(args.output / "batches.csv", rows)
    _write_csv(args.output / "separation_by_boot_condition.csv", separated)
    report = summarize(rows, separated)
    (args.output / "summary.json").write_text(
        json.dumps(report, indent=2), encoding="utf-8"
    )
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
