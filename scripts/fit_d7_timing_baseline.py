#!/usr/bin/env python3
"""Freeze the D7 timing comparator from same-instrumentation development data."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
from pathlib import Path

import numpy as np


PROTOCOL = "D7-nesting-confirmatory-r1-2026-09-21"
FEATURES = ("first_raw_median", "first_div_last_raw_median")


def _tree_hash(root: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(root.glob("batch_*.json.gz")):
        digest.update(path.name.encode())
        digest.update(hashlib.sha256(path.read_bytes()).digest())
    return digest.hexdigest()


def _features(record: dict) -> list[float]:
    first = np.asarray([
        row["first_raw_wall_ns"] for row in record["transactions"]
    ], dtype=float)
    last = np.asarray([
        row["last_raw_wall_ns"] for row in record["transactions"]
    ], dtype=float)
    return [float(np.median(first)), float(np.median(first / last))]


def _load(root: Path) -> list[dict]:
    rows = []
    for path in sorted(root.glob("batch_*.json.gz")):
        with gzip.open(path, "rt", encoding="utf-8") as handle:
            record = json.load(handle)
        if (
            record.get("protocol_revision") != PROTOCOL
            or not record.get("quality", {}).get("valid_for_analysis")
        ):
            raise ValueError(f"invalid development batch: {path}")
        rows.append({
            "state": record["truth"]["state"],
            "condition": record["truth"]["condition"],
            "features": _features(record),
        })
    if len(rows) != 48:
        raise ValueError(f"expected 48 development batches, got {len(rows)}")
    return rows


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if args.output.exists():
        raise FileExistsError(args.output)
    rows = _load(args.input)
    fit = [row for row in rows if row["state"] in {"unloaded", "pass"}]
    if len(fit) != 24:
        raise ValueError("expected 24 unloaded+pass fitting batches")
    unloaded = np.log(np.asarray([
        row["features"] for row in fit if row["state"] == "unloaded"
    ], dtype=float))
    passed = np.log(np.asarray([
        row["features"] for row in fit if row["state"] == "pass"
    ], dtype=float))
    origin = np.mean(unloaded, axis=0)
    axis = np.mean(passed, axis=0) - origin
    norm = float(np.linalg.norm(axis))
    if norm <= 1e-9:
        raise ValueError("degenerate unloaded-to-pass timing axis")
    axis /= norm
    threshold = float(
        np.max((np.vstack((unloaded, passed)) - origin) @ axis) + 0.01
    )
    development_rates = {}
    for state in ("unloaded", "pass", "active", "hiding"):
        state_rows = [row for row in rows if row["state"] == state]
        alerts = [
            float((np.log(np.asarray(row["features"])) - origin) @ axis)
            > threshold
            for row in state_rows
        ]
        development_rates[state] = sum(alerts) / len(alerts)
    output = {
        "role": "frozen_development_timing_comparator",
        "not_primary_proposed_method": True,
        "fit_protocol": PROTOCOL,
        "fit_evidence_role": "excluded_formal_pipeline_smoke_same_instrumentation",
        "features": list(FEATURES),
        "transform": "natural_log",
        "origin": origin.tolist(),
        "axis": axis.tolist(),
        "threshold": threshold,
        "fit_states": ["unloaded", "pass"],
        "fit_batches": 24,
        "development_only_alert_rates": development_rates,
        "input_tree_sha256": _tree_hash(args.input),
        "script_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "warning": (
            "This comparator is frozen from one excluded development boot "
            "using the same combined collector; D7 formal data are not used "
            "for fitting or threshold selection."
        ),
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(output, indent=2), encoding="utf-8")
    print(json.dumps(output, indent=2))


if __name__ == "__main__":
    main()
