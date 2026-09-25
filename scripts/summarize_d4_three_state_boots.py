#!/usr/bin/env python3
"""Boot-cluster exploratory summary for identical D4 three-state protocols."""

from __future__ import annotations

import argparse
import csv
import gzip
import json
from collections import defaultdict
from pathlib import Path

import numpy as np

from analyze_d4_qualification import _extract, _write_csv


FEATURES = ("first_raw_q10", "first_raw_median")
STATES = {"unloaded", "sham", "hiding"}


def _bootstrap_boot_mean(values: np.ndarray, seed: int = 20260919):
    rng = np.random.default_rng(seed)
    draws = rng.choice(values, size=(10_000, len(values)), replace=True)
    means = np.mean(draws, axis=1)
    return (
        float(np.mean(values)),
        float(np.quantile(means, 0.025)),
        float(np.quantile(means, 0.975)),
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", action="append", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    rows = []
    seen_boots = set()
    for root in args.input:
        paths = sorted(root.rglob("batch_*.json.gz"))
        if not paths:
            raise ValueError(f"no batches below {root}")
        source_rows = [_extract(path) for path in paths]
        boots = {row["boot_id"] for row in source_rows}
        if len(boots) != 1 or seen_boots & boots:
            raise ValueError("each input root must be one distinct boot")
        seen_boots.update(boots)
        rows.extend(source_rows)
    profiles = {(row["probe_profile"], row["poll_policy"]) for row in rows}
    if len(profiles) != 1:
        raise ValueError(f"mixed collector configurations: {profiles}")

    grouped = defaultdict(dict)
    for row in rows:
        cell = (
            row["boot_id"],
            row["visible_cardinality"],
            row["filename_length"],
            row["condition"],
        )
        state = row["campaign_phase"]
        if state not in STATES or state in grouped[cell]:
            raise ValueError(f"invalid or duplicate state {state!r} in {cell}")
        grouped[cell][state] = row
    paired = []
    for cell, states in sorted(grouped.items()):
        if set(states) != STATES:
            raise ValueError(f"incomplete cell {cell}")
        for feature in FEATURES:
            unloaded = float(states["unloaded"][feature])
            sham = float(states["sham"][feature])
            hiding = float(states["hiding"][feature])
            paired.append(
                {
                    "boot_id": cell[0],
                    "visible_cardinality": cell[1],
                    "filename_length": cell[2],
                    "condition": cell[3],
                    "feature": feature,
                    "unloaded": unloaded,
                    "sham": sham,
                    "hiding": hiding,
                    "sham_over_unloaded": sham / unloaded,
                    "hiding_over_sham": hiding / sham,
                    "hiding_higher_than_sham": hiding > sham,
                }
            )
    per_boot = []
    for boot in sorted(seen_boots):
        for feature in FEATURES:
            subset = [
                row for row in paired
                if row["boot_id"] == boot and row["feature"] == feature
            ]
            per_boot.append(
                {
                    "boot_id": boot,
                    "feature": feature,
                    "cells": len(subset),
                    "geometric_sham_over_unloaded": float(
                        np.exp(np.mean(np.log([row["sham_over_unloaded"] for row in subset])))
                    ),
                    "geometric_hiding_over_sham": float(
                        np.exp(np.mean(np.log([row["hiding_over_sham"] for row in subset])))
                    ),
                    "hiding_higher_than_sham_fraction": float(
                        np.mean([row["hiding_higher_than_sham"] for row in subset])
                    ),
                }
            )
    summary = []
    for feature in FEATURES:
        values = np.asarray(
            [
                np.log(row["geometric_hiding_over_sham"])
                for row in per_boot
                if row["feature"] == feature
            ],
            dtype=float,
        )
        mean, lo, hi = _bootstrap_boot_mean(values)
        summary.append(
            {
                "feature": feature,
                "boots": len(values),
                "geometric_hiding_over_sham": float(np.exp(mean)),
                "boot_bootstrap_ci_lo": float(np.exp(lo)),
                "boot_bootstrap_ci_hi": float(np.exp(hi)),
                "min_boot_hiding_higher_fraction": min(
                    row["hiding_higher_than_sham_fraction"]
                    for row in per_boot if row["feature"] == feature
                ),
            }
        )
    args.output.mkdir(parents=True, exist_ok=True)
    _write_csv(args.output / "paired_cells.csv", paired)
    _write_csv(args.output / "per_boot.csv", per_boot)
    _write_csv(args.output / "summary.csv", summary)
    report = {
        "status": "D4_multiboot_exploratory_mechanism",
        "warning": (
            "Bootstrap unit is boot; these data were used during method development "
            "and cannot be relabeled as D5 confirmation."
        ),
        "boots": len(seen_boots),
        "configuration": list(next(iter(profiles))),
        "paired_cells": len(paired) // len(FEATURES),
    }
    (args.output / "analysis_status.json").write_text(
        json.dumps(report, indent=2), encoding="utf-8"
    )
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
