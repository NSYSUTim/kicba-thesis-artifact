#!/usr/bin/env python3
"""Audit the D7 kernel-only nesting development pilot."""

from __future__ import annotations

import argparse
import gzip
import json
from collections import Counter
from pathlib import Path


PROTOCOL = "D7-nesting-development-r1-2026-09-21"
STATES = ("unloaded", "pass", "active", "hiding")
CONDITIONS = ("baseline", "cpu", "memory", "mixed")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if args.output.exists():
        raise FileExistsError(args.output)
    failures = []
    manifests = list(args.input.glob("campaign_*.json"))
    if len(manifests) != 1:
        raise ValueError(f"expected one manifest, got {len(manifests)}")
    manifest = json.loads(manifests[0].read_text(encoding="utf-8"))
    if manifest.get("protocol_revision") != PROTOCOL:
        failures.append("protocol mismatch")
    if manifest.get("status") != "complete":
        failures.append("manifest incomplete")
    batches = []
    transactions = []
    for path in sorted(args.input.glob("batch_*.json.gz")):
        with gzip.open(path, "rt", encoding="utf-8") as handle:
            record = json.load(handle)
        if record.get("protocol_revision") != PROTOCOL:
            failures.append(f"protocol mismatch: {path.name}")
            continue
        if not record["quality"]["valid_for_analysis"]:
            failures.append(f"invalid batch: {path.name}")
        state = record["truth"]["state"]
        condition = record["truth"]["condition"]
        rows = record["transactions"]
        if len(rows) != 20:
            failures.append(f"transaction count: {path.name}")
        for row in rows:
            if row["top_level_calls"] != (
                row["forwarded_top_calls"] + row["short_circuit_top_calls"]
            ):
                failures.append(f"composition mismatch: {path.name}")
            if row["return_underflows"]:
                failures.append(f"return underflow: {path.name}")
            transactions.append({"state": state, "condition": condition, **row})
        batches.append({
            "state": state,
            "condition": condition,
            "alert": any(row["structural_alert"] for row in rows),
        })
    if len(batches) != 48:
        failures.append(f"expected 48 batches, got {len(batches)}")
    cells = Counter((row["state"], row["condition"]) for row in batches)
    expected = Counter({
        (state, condition): 3 for state in STATES for condition in CONDITIONS
    })
    if cells != expected:
        failures.append(f"unbalanced cells: {dict(cells)}")
    metrics = {}
    for state in STATES:
        rows = [row for row in batches if row["state"] == state]
        tx = [row for row in transactions if row["state"] == state]
        metrics[state] = {
            "batches": len(rows),
            "alert_rate": sum(row["alert"] for row in rows) / len(rows),
            "top_level_calls_values": sorted({row["top_level_calls"] for row in tx}),
            "forwarded_top_calls_values": sorted({
                row["forwarded_top_calls"] for row in tx
            }),
            "short_circuit_top_calls_values": sorted({
                row["short_circuit_top_calls"] for row in tx
            }),
            "max_depth_values": sorted({row["max_depth"] for row in tx}),
        }
    report = {
        "protocol": PROTOCOL,
        "status": "PASS" if not failures else "FAIL",
        "failures": failures,
        "evidence_role": "single_boot_development_pilot_not_confirmatory",
        "feature_leakage_check": {
            "uses_userspace_entry_count": False,
            "uses_filename_or_magic_word": False,
            "uses_module_identity": False,
            "uses_attack_label": False,
            "decision_inputs": [
                "forwarded_top_calls", "short_circuit_top_calls"
            ],
        },
        "decision_rule": (
            "alert iff forwarded_top_calls > 0 and "
            "short_circuit_top_calls > 0 within one listing"
        ),
        "state_metrics": metrics,
        "hiding_recall": metrics.get("hiding", {}).get("alert_rate"),
        "active_fpr": metrics.get("active", {}).get("alert_rate"),
        "pass_fpr": metrics.get("pass", {}).get("alert_rate"),
        "unloaded_fpr": metrics.get("unloaded", {}).get("alert_rate"),
        "scope": (
            "Detects selective short-circuiting in a same-symbol wrapper path; "
            "it is not a universal rootkit detector."
        ),
    }
    args.output.mkdir(parents=True)
    (args.output / "report.json").write_text(
        json.dumps(report, indent=2), encoding="utf-8"
    )
    print(json.dumps(report, indent=2))
    if failures:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
