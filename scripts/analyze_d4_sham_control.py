#!/usr/bin/env python3
"""Compare unloaded, pass-through-hook, and hiding states on matched cells."""

from __future__ import annotations

import argparse
import csv
import gzip
import json
from collections import defaultdict
from pathlib import Path

import numpy as np

from analyze_d4_qualification import FEATURES, _extract, _write_csv


STATES = ("unloaded", "sham", "hiding")
DIAGNOSTICS = ("filldir64_calls_per_listing", "iterate_calls_per_listing")
RAW_FEATURES = tuple(feature for feature in FEATURES if "raw" in feature)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    paths = sorted(args.input.rglob("batch_*.json.gz"))
    if not paths:
        raise ValueError("no raw batches found")
    rows = [_extract(path) for path in paths]
    context_available = all(row["context_tracepoints_enabled"] for row in rows)
    selected_features = FEATURES if context_available else RAW_FEATURES
    diagnostics = (
        ("iterate_calls_per_listing",)
        if all(row["probe_profile"] == "role_aggregate" for row in rows)
        else DIAGNOSTICS
    )
    grouped: dict[tuple, dict[str, dict]] = defaultdict(dict)
    for row in rows:
        state = row["campaign_phase"]
        if state not in STATES:
            raise ValueError(f"unrecognized three-state phase {state!r}")
        cell = (
            row["visible_cardinality"],
            row["filename_length"],
            row["condition"],
        )
        if state in grouped[cell]:
            raise ValueError(f"duplicate state {state} in {cell}")
        grouped[cell][state] = row

    comparisons = []
    for cell, states in sorted(grouped.items()):
        if set(states) != set(STATES):
            raise ValueError(f"missing state in {cell}: {set(STATES) - set(states)}")
        for feature in (*selected_features, *diagnostics):
            unloaded = float(states["unloaded"][feature])
            sham = float(states["sham"][feature])
            hiding = float(states["hiding"][feature])
            comparisons.append(
                {
                    "visible_cardinality": cell[0],
                    "filename_length": cell[1],
                    "condition": cell[2],
                    "feature": feature,
                    "unloaded": unloaded,
                    "sham": sham,
                    "hiding": hiding,
                    "sham_minus_unloaded": sham - unloaded,
                    "hiding_minus_sham": hiding - sham,
                    "hiding_minus_unloaded": hiding - unloaded,
                    "sham_over_unloaded": sham / max(unloaded, 1e-12),
                    "hiding_over_sham": hiding / max(sham, 1e-12),
                }
            )
    summary = []
    for feature in (*selected_features, *diagnostics):
        subset = [row for row in comparisons if row["feature"] == feature]
        sham_shift = np.asarray([row["sham_minus_unloaded"] for row in subset])
        hiding_shift = np.asarray([row["hiding_minus_sham"] for row in subset])
        summary.append(
            {
                "feature": feature,
                "factor_cells": len(subset),
                "sham_higher_than_unloaded_fraction": float(np.mean(sham_shift > 0)),
                "hiding_higher_than_sham_fraction": float(np.mean(hiding_shift > 0)),
                "median_sham_over_unloaded": float(
                    np.median([row["sham_over_unloaded"] for row in subset])
                ),
                "median_hiding_over_sham": float(
                    np.median([row["hiding_over_sham"] for row in subset])
                ),
            }
        )

    args.output.mkdir(parents=True, exist_ok=True)
    _write_csv(args.output / "role_aligned_batches.csv", rows)
    _write_csv(args.output / "three_state_cell_comparisons.csv", comparisons)
    _write_csv(args.output / "three_state_feature_summary.csv", summary)
    report = {
        "status": "D4_posthoc_sham_control",
        "warning": (
            "One boot and one batch per state/cell are mechanism diagnostics, not "
            "a confirmatory detector evaluation."
        ),
        "batches": len(rows),
        "factor_cells": len(grouped),
        "states": list(STATES),
        "context_tracepoints_enabled": context_available,
        "features_analyzed": list(selected_features),
    }
    (args.output / "analysis_status.json").write_text(
        json.dumps(report, indent=2), encoding="utf-8"
    )
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
