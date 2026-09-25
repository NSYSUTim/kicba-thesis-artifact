#!/usr/bin/env python3
"""Exploratory D7 analysis after matched-control qualification.

This is deliberately not a confirmatory detector analysis.  It answers two
mechanism questions on the single qualification boot:

1. Does the D6-style unloaded-to-pass timing axis also flag an active-logic
   control that performs the same name test but never hides an entry?
2. After matching hook and filter logic, is the hiding-minus-active timing
   contrast directionally stable across the four workloads?
"""

from __future__ import annotations

import argparse
import csv
import gzip
import json
from collections import defaultdict
from pathlib import Path

import numpy as np

from analyze_d4_qualification import _extract
from d4_context_axis import AXIS_FEATURES


PROTOCOL = "D7-mechanism-r2-2026-09-21"
STATES = ("unloaded", "pass", "active", "hiding")
FEATURES = (
    "first_raw_q10",
    "first_raw_median",
    "first_raw_q90",
    "last_raw_median",
    "first_minus_last_raw_median",
    "first_div_last_raw_median",
)


def _write_csv(path: Path, rows: list[dict]) -> None:
    if not rows:
        raise ValueError(f"no rows for {path}")
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def _load(root: Path) -> list[dict]:
    rows = []
    for path in sorted(root.glob("batch_*.json.gz")):
        with gzip.open(path, "rt", encoding="utf-8") as handle:
            record = json.load(handle)
        if record.get("protocol_revision") != PROTOCOL:
            raise ValueError(f"protocol mismatch: {path}")
        row = _extract(path)
        row["state"] = record["d7_control"]["state"]
        rows.append(row)
    if len(rows) != 48:
        raise ValueError(f"expected 48 batches, got {len(rows)}")
    return rows


def _fit_pass_axis(rows: list[dict]) -> dict:
    groups = {
        state: [row for row in rows if row["state"] == state]
        for state in STATES
    }
    if any(len(group) != 12 for group in groups.values()):
        raise ValueError("expected 12 batches per state")
    unloaded = np.log(np.asarray([
        [row[name] for name in AXIS_FEATURES] for row in groups["unloaded"]
    ], dtype=float))
    passed = np.log(np.asarray([
        [row[name] for name in AXIS_FEATURES] for row in groups["pass"]
    ], dtype=float))
    origin = np.mean(unloaded, axis=0)
    axis = np.mean(passed, axis=0) - origin
    norm = float(np.linalg.norm(axis))
    if norm <= 1e-9:
        raise ValueError("degenerate unloaded-to-pass axis")
    axis /= norm
    threshold = float(np.max((np.vstack((unloaded, passed)) - origin) @ axis) + 0.01)
    return {
        "origin": origin,
        "axis": axis,
        "threshold": threshold,
    }


def _score(model: dict, row: dict) -> float:
    values = np.log(np.asarray([row[name] for name in AXIS_FEATURES], dtype=float))
    return float((values - model["origin"]) @ model["axis"])


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--audit", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if args.output.exists():
        raise FileExistsError(args.output)
    audit = json.loads(args.audit.read_text(encoding="utf-8"))
    if audit.get("protocol") != PROTOCOL or audit.get("status") != "PASS":
        raise RuntimeError("matched-control audit did not pass")
    rows = _load(args.input)
    model = _fit_pass_axis(rows)

    scored = []
    for row in rows:
        score = _score(model, row)
        scored.append({
            "batch_id": row["batch_id"],
            "state": row["state"],
            "condition": row["condition"],
            "score": score,
            "threshold": model["threshold"],
            "alert": score > model["threshold"],
            **{name: row[name] for name in FEATURES},
        })

    metrics = []
    for condition in ("ALL", "baseline", "cpu", "memory", "mixed"):
        subset = scored if condition == "ALL" else [
            row for row in scored if row["condition"] == condition
        ]
        for state in STATES:
            state_rows = [row for row in subset if row["state"] == state]
            metrics.append({
                "condition": condition,
                "state": state,
                "n": len(state_rows),
                "alert_rate": float(np.mean([row["alert"] for row in state_rows])),
                "score_mean": float(np.mean([row["score"] for row in state_rows])),
                "score_min": float(np.min([row["score"] for row in state_rows])),
                "score_max": float(np.max([row["score"] for row in state_rows])),
            })

    contrasts = []
    by_cell: dict[tuple[str, str], list[float]] = defaultdict(list)
    for row in scored:
        for feature in FEATURES:
            by_cell[(row["condition"], row["state"], feature)].append(
                float(row[feature])
            )
    for condition in ("baseline", "cpu", "memory", "mixed"):
        for feature in FEATURES:
            means = {
                state: float(np.mean(by_cell[(condition, state, feature)]))
                for state in STATES
            }
            contrasts.append({
                "condition": condition,
                "feature": feature,
                **{f"{state}_mean": value for state, value in means.items()},
                "active_over_pass": means["active"] / max(means["pass"], 1e-12),
                "hiding_over_active": means["hiding"] / max(means["active"], 1e-12),
                "hiding_minus_active": means["hiding"] - means["active"],
            })

    hiding_direction = {}
    for feature in FEATURES:
        values = [row for row in contrasts if row["feature"] == feature]
        hiding_direction[feature] = {
            "workloads_hiding_higher_than_active": int(sum(
                row["hiding_minus_active"] > 0 for row in values
            )),
            "workloads_total": len(values),
            "median_hiding_over_active": float(np.median([
                row["hiding_over_active"] for row in values
            ])),
        }

    overall = {
        row["state"]: row for row in metrics if row["condition"] == "ALL"
    }
    report = {
        "status": "single_boot_exploratory_mechanism_analysis",
        "protocol": PROTOCOL,
        "warning": (
            "The same qualification boot is used to fit and inspect the axis; "
            "these values are not confirmatory detector performance."
        ),
        "axis_features": list(AXIS_FEATURES),
        "pass_calibrated_axis_threshold": model["threshold"],
        "overall_alert_rate": {
            state: overall[state]["alert_rate"] for state in STATES
        },
        "active_logic_false_positive_rate": overall["active"]["alert_rate"],
        "hiding_recall": overall["hiding"]["alert_rate"],
        "hiding_minus_active_direction": hiding_direction,
        "interpretation_rule": (
            "High active alert rate means the pass-calibrated timing gate is "
            "responding to filtering computation, not specifically to hiding."
        ),
    }
    args.output.mkdir(parents=True)
    _write_csv(args.output / "scored_batches.csv", scored)
    _write_csv(args.output / "state_metrics.csv", metrics)
    _write_csv(args.output / "matched_contrasts.csv", contrasts)
    (args.output / "report.json").write_text(
        json.dumps(report, indent=2), encoding="utf-8"
    )
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
