#!/usr/bin/env python3
from __future__ import annotations

import argparse
import gzip
import json
import statistics
from collections import defaultdict
from pathlib import Path


EVENTS = (
    "sched_switch",
    "hardirq_enter",
    "softirq_enter",
    "cpu_frequency",
)


def _percentile(values: list[int], probability: float) -> float:
    ordered = sorted(values)
    if not ordered:
        return float("nan")
    position = probability * (len(ordered) - 1)
    lower = int(position)
    upper = min(lower + 1, len(ordered) - 1)
    fraction = position - lower
    return ordered[lower] * (1.0 - fraction) + ordered[upper] * fraction


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    paths = sorted(args.root.glob("boot_*/batch_*.json.gz"))
    grouped: dict[tuple[str, str], dict[str, list[int]]] = defaultdict(
        lambda: defaultdict(list)
    )
    for path in paths:
        with gzip.open(path, "rt", encoding="utf-8") as handle:
            record = json.load(handle)
        truth = record["truth"]
        key = (truth["label"], truth["condition"])
        event_counts = record["quality"]["event_counts"]
        for event in EVENTS:
            grouped[key][event].append(int(event_counts[event]))

    cells: dict[str, dict] = {}
    for key, event_values in sorted(grouped.items()):
        cell: dict[str, object] = {"batches": len(next(iter(event_values.values())))}
        for event, values in event_values.items():
            cell[event] = {
                "mean_per_batch": statistics.fmean(values),
                "median_per_batch": statistics.median(values),
                "p95_per_batch": _percentile(values, 0.95),
                "max_per_batch": max(values),
                "nonzero_batch_fraction": sum(value > 0 for value in values) / len(values),
            }
        cells[f"{key[0]}/{key[1]}"] = cell
    report = {
        "batches": len(paths),
        "note": (
            "These are raw per-batch event counts. The preregistered 0.1-0.9 "
            "invocation quantiles can still be all zero when events are sparse."
        ),
        "cells": cells,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
