#!/usr/bin/env python3
"""Exploratory, role-aligned analysis of D4 qualification batches.

This script does not train a detector or use its output as confirmatory data.
It checks whether attack timing shifts survive exact-output and call-role gates.
"""

from __future__ import annotations

import argparse
import csv
import gzip
import json
from collections import defaultdict
from pathlib import Path
from types import SimpleNamespace

import numpy as np

from kicba.context import process_record
from kicba.invocation_composition import _pair_iterate_dir


FEATURES = (
    "first_raw_q10",
    "first_raw_median",
    "first_raw_q90",
    "first_oncpu_median",
    "first_accounted_median",
    "last_raw_median",
    "last_oncpu_median",
    "last_accounted_median",
    "first_minus_last_raw_median",
    "first_div_last_raw_median",
    "first_minus_last_oncpu_median",
    "first_div_last_oncpu_median",
)


def _quantile(values: list[float], q: float) -> float:
    return float(np.quantile(np.asarray(values, dtype=float), q))


def _median(values: list[float]) -> float:
    return _quantile(values, 0.5)


def _extract(path: Path) -> dict:
    with gzip.open(path, "rt", encoding="utf-8") as handle:
        record = json.load(handle)
    collection = record["collection"]
    if not record["quality"]["valid_for_analysis"]:
        raise ValueError(f"collector quality gate failed in {path}")
    context_available = collection.get("context_tracepoints_enabled", True)
    by_pid: dict[int, list] = defaultdict(list)
    filldir_by_pid: dict[int, list] = defaultdict(list)
    if context_available:
        batch = process_record(record)
        if not batch.quality["valid_for_analysis"]:
            raise ValueError(f"context accounting gate failed in {path}: {batch.quality}")
        for invocation in batch.invocations:
            if invocation.function == "iterate_dir":
                by_pid[invocation.pid].append(invocation)
            elif invocation.function == "filldir64":
                filldir_by_pid[invocation.pid].append(invocation)
    elif record["schema_version"] == 4:
        # BPF maps retain role durations and counts, not an event stream.
        # The first/last role is defined by kernel return order per ls PID.
        for item in record["transaction_durations"]:
            if (item["call_count"] is None or item["call_count"] < 2
                    or item["first_raw_wall_ns"] is None
                    or item["last_raw_wall_ns"] is None
                    or item["incomplete_start"]):
                raise ValueError(f"incomplete aggregate transaction in {path}")
            pid = int(item["pid"])
            first_ns = int(item["first_raw_wall_ns"])
            last_ns = int(item["last_raw_wall_ns"])
            by_pid[pid] = [
                SimpleNamespace(start_ns=0, end_ns=first_ns,
                    raw_wall_ns=first_ns, oncpu_ns=float("nan"),
                    accounted_exec_ns=float("nan")),
                SimpleNamespace(start_ns=1, end_ns=last_ns + 1,
                    raw_wall_ns=last_ns, oncpu_ns=float("nan"),
                    accounted_exec_ns=float("nan")),
            ]
        aggregate_call_counts = [
            int(item["call_count"]) for item in record["transaction_durations"]
        ]
    else:
        # The minimal program intentionally has no scheduler/IRQ events.
        # Context accounting would invent on-CPU values from incomplete data;
        # use only matched raw entry/return timestamps for this profile.
        pairs = _pair_iterate_dir(record["events"])
        counts = record["quality"]["target_function_counts"]["iterate_dir"]
        if len(pairs) != counts["enter"] or len(pairs) != counts["return"]:
            raise ValueError(f"unpaired raw iterate_dir events in {path}")
        for pid, start, duration in pairs:
            by_pid[pid].append(
                SimpleNamespace(
                    start_ns=start,
                    end_ns=start + duration,
                    raw_wall_ns=duration,
                    oncpu_ns=float("nan"),
                    accounted_exec_ns=float("nan"),
                )
            )
    for values in by_pid.values():
        values.sort(key=lambda item: item.start_ns)
    first = [values[0] for values in by_pid.values() if values]
    last = [values[-1] for values in by_pid.values() if values]
    paired = [(values[0], values[-1]) for values in by_pid.values() if len(values) >= 2]
    iterations = int(collection["iterations"])
    if len(first) != iterations or len(paired) != iterations:
        raise ValueError(f"missing iterate_dir transaction roles in {path}")
    if not record["listing_validation"]["exact_output_pass"]:
        raise ValueError(f"exact-output gate failed in {path}")
    factor = record["directory_factor"]
    first_raw = [item.raw_wall_ns for item in first]
    first_oncpu = [item.oncpu_ns for item in first]
    first_accounted = [item.accounted_exec_ns for item in first]
    last_raw = [item.raw_wall_ns for item in last]
    last_oncpu = [item.oncpu_ns for item in last]
    last_accounted = [item.accounted_exec_ns for item in last]
    nested_filldir = sum(
        any(
            iterate.start_ns <= call.start_ns
            and call.end_ns <= iterate.end_ns
            for iterate in by_pid.get(pid, [])
        )
        for pid, calls in filldir_by_pid.items()
        for call in calls
    )
    filldir_calls = sum(map(len, filldir_by_pid.values()))
    return {
        "batch_id": record["batch_id"],
        "boot_id": record["environment"]["boot_id"],
        "campaign_position": collection["campaign_position"],
        "campaign_phase": collection.get("campaign_phase"),
        "probe_profile": collection.get("probe_profile"),
        "poll_policy": collection.get("poll_policy", "continuous"),
        "context_tracepoints_enabled": collection.get(
            "context_tracepoints_enabled", True
        ),
        "label": record["truth"]["label"],
        "condition": record["truth"]["condition"],
        "visible_cardinality": factor["visible_cardinality"],
        "filename_length": factor["filename_length"],
        "hidden_slot": factor["hidden_slot"],
        "fixture_mode": factor.get("fixture_mode", "ephemeral"),
        "fixture_device": factor.get("fixture_device"),
        "fixture_inode": factor.get("fixture_inode"),
        "cpu_busy_fraction": record.get("batch_context", {}).get("cpu_busy_fraction"),
        "context_switches_per_second": record.get("batch_context", {}).get(
            "context_switches_per_second"
        ),
        "interrupts_per_second": record.get("batch_context", {}).get(
            "interrupts_per_second"
        ),
        "softirqs_per_second": record.get("batch_context", {}).get(
            "softirqs_per_second"
        ),
        "actual_normal_hidden_index": record["listing_validation"][
            "first_observed_hidden_index"
        ],
        "iterate_calls_per_listing": (
            sum(aggregate_call_counts) if record["schema_version"] == 4
            else sum(len(values) for values in by_pid.values())
        ) / iterations,
        "filldir64_calls_per_listing": filldir_calls / iterations,
        "filldir64_nested_fraction": (
            nested_filldir / filldir_calls if filldir_calls else float("nan")
        ),
        "first_raw_q10": _quantile(first_raw, 0.1),
        "first_raw_median": _median(first_raw),
        "first_raw_q90": _quantile(first_raw, 0.9),
        "first_oncpu_median": _median(first_oncpu),
        "first_accounted_median": _median(first_accounted),
        "last_raw_median": _median(last_raw),
        "last_oncpu_median": _median(last_oncpu),
        "last_accounted_median": _median(last_accounted),
        "first_minus_last_raw_median": _median(
            [left.raw_wall_ns - right.raw_wall_ns for left, right in paired]
        ),
        "first_div_last_raw_median": _median(
            [left.raw_wall_ns / max(1, right.raw_wall_ns) for left, right in paired]
        ),
        "first_minus_last_oncpu_median": _median(
            [left.oncpu_ns - right.oncpu_ns for left, right in paired]
        ),
        "first_div_last_oncpu_median": _median(
            [left.oncpu_ns / max(1, right.oncpu_ns) for left, right in paired]
        ),
    }


def _write_csv(path: Path, rows: list[dict]) -> None:
    if not rows:
        raise ValueError(f"no rows for {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def _compare(rows: list[dict]) -> tuple[list[dict], list[dict]]:
    grouped: dict[tuple, dict[str, list[dict]]] = defaultdict(
        lambda: defaultdict(list)
    )
    for row in rows:
        cell = (
            row["visible_cardinality"],
            row["filename_length"],
            row["hidden_slot"],
            row["condition"],
        )
        grouped[cell][row["label"]].append(row)
    comparisons = []
    for cell, labels in sorted(grouped.items()):
        normal = labels.get("normal", [])
        attack = labels.get("rootkit", [])
        if not normal or not attack:
            raise ValueError(f"unpaired factor cell {cell}")
        for feature in FEATURES:
            normal_value = float(np.mean([row[feature] for row in normal]))
            attack_value = float(np.mean([row[feature] for row in attack]))
            comparisons.append(
                {
                    "visible_cardinality": cell[0],
                    "filename_length": cell[1],
                    "hidden_slot": cell[2],
                    "condition": cell[3],
                    "feature": feature,
                    "normal_batches": len(normal),
                    "rootkit_batches": len(attack),
                    "normal_value": normal_value,
                    "rootkit_value": attack_value,
                    "attack_minus_normal": attack_value - normal_value,
                    "attack_over_normal": attack_value / max(normal_value, 1e-12),
                }
            )
    summary = []
    for feature in FEATURES:
        subset = [row for row in comparisons if row["feature"] == feature]
        shifts = np.asarray([row["attack_minus_normal"] for row in subset])
        ratios = np.asarray([row["attack_over_normal"] for row in subset])
        summary.append(
            {
                "feature": feature,
                "factor_cells": len(subset),
                "attack_higher_fraction": float(np.mean(shifts > 0)),
                "median_attack_over_normal": float(np.median(ratios)),
                "min_attack_over_normal": float(np.min(ratios)),
                "max_attack_over_normal": float(np.max(ratios)),
                "median_attack_minus_normal": float(np.median(shifts)),
            }
        )
    return comparisons, summary


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    paths = sorted(args.input.rglob("batch_*.json.gz"))
    if not paths:
        raise ValueError("no raw batches found")
    rows = [_extract(path) for path in paths]
    comparisons, summary = _compare(rows)
    args.output.mkdir(parents=True, exist_ok=True)
    _write_csv(args.output / "role_aligned_batches.csv", rows)
    _write_csv(args.output / "factor_cell_comparisons.csv", comparisons)
    _write_csv(args.output / "feature_direction_summary.csv", summary)
    report = {
        "status": "D4_posthoc_development_qualification",
        "warning": "One boot and an exploratory feature scan cannot confirm detector performance.",
        "batches": len(rows),
        "factor_cells": len(comparisons) // len(FEATURES),
        "features_scanned": list(FEATURES),
        "role_counts_by_cardinality": {
            str(cardinality): sorted(
                {
                    row["iterate_calls_per_listing"]
                    for row in rows
                    if row["visible_cardinality"] == cardinality
                }
            )
            for cardinality in sorted({row["visible_cardinality"] for row in rows})
        },
    }
    (args.output / "analysis_status.json").write_text(
        json.dumps(report, indent=2), encoding="utf-8"
    )
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
