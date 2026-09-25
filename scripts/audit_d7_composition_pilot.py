#!/usr/bin/env python3
"""Audit and summarize the one-boot D7 call-composition pilot."""

from __future__ import annotations

import argparse
import csv
import gzip
import json
from collections import Counter
from pathlib import Path


PROTOCOL = "D7-composition-pilot-r1-2026-09-21"
STATES = ("unloaded", "pass", "active", "hiding")
EXPECTED_CALLS = {
    "unloaded": 131,
    "pass": 262,
    "active": 262,
    "hiding": 261,
}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if args.output.exists():
        raise FileExistsError(args.output)
    manifests = list(args.input.glob("campaign_*.json"))
    if len(manifests) != 1:
        raise ValueError(f"expected one manifest, got {len(manifests)}")
    manifest = json.loads(manifests[0].read_text(encoding="utf-8"))
    failures = []
    if manifest.get("protocol_revision") != PROTOCOL:
        failures.append("protocol mismatch")
    if manifest.get("status") != "complete":
        failures.append("manifest incomplete")
    if len(manifest.get("schedule", [])) != 48:
        failures.append("schedule length is not 48")

    batches = []
    transactions = []
    for path in sorted(args.input.glob("batch_*.json.gz")):
        with gzip.open(path, "rt", encoding="utf-8") as handle:
            record = json.load(handle)
        state = record["d7_control"]["state"]
        condition = record["truth"]["condition"]
        position = int(record["collection"]["campaign_position"])
        observed_entries = int(
            record["listing_validation"]["first_observed_entry_count"]
        )
        if not record["quality"]["valid_for_analysis"]:
            failures.append(f"quality failure at {position}")
        state_transactions = []
        for item in record["transaction_durations"]:
            calls = int(item["filldir64_call_count"])
            if calls == observed_entries:
                hook_multiplicity = "unhooked"
                suppression_residual = 0
            elif calls >= 2 * observed_entries:
                hook_multiplicity = "double_path"
                suppression_residual = calls - 2 * observed_entries
            else:
                hook_multiplicity = "unclassified"
                suppression_residual = -1
            suppression_alert = (
                hook_multiplicity == "double_path"
                and suppression_residual > 0
            )
            row = {
                "position": position,
                "state": state,
                "condition": condition,
                "iteration": int(item["iteration"]),
                "observed_entries": observed_entries,
                "filldir64_calls": calls,
                "hook_multiplicity": hook_multiplicity,
                "suppression_residual": suppression_residual,
                "suppression_alert": suppression_alert,
            }
            state_transactions.append(row)
            transactions.append(row)
            if calls != EXPECTED_CALLS[state]:
                failures.append(
                    f"unexpected composition at {position}/{item['iteration']}: "
                    f"{state} calls={calls}"
                )
        if len(state_transactions) != 20:
            failures.append(f"transaction count mismatch at {position}")
        alerts = sum(row["suppression_alert"] for row in state_transactions)
        batches.append({
            "position": position,
            "state": state,
            "condition": condition,
            "transactions": len(state_transactions),
            "observed_entries": observed_entries,
            "filldir64_calls_values": ";".join(map(str, sorted({
                row["filldir64_calls"] for row in state_transactions
            }))),
            "suppression_residual_values": ";".join(map(str, sorted({
                row["suppression_residual"] for row in state_transactions
            }))),
            "alert": alerts > 0,
            "alerted_transactions": alerts,
        })

    if len(batches) != 48:
        failures.append(f"expected 48 batches, got {len(batches)}")
    cell_counts = Counter((row["state"], row["condition"]) for row in batches)
    expected_cells = Counter({
        (state, condition): 3
        for state in STATES
        for condition in ("baseline", "cpu", "memory", "mixed")
    })
    if cell_counts != expected_cells:
        failures.append(f"cell balance mismatch: {dict(cell_counts)}")
    if {row["position"] for row in batches} != set(range(48)):
        failures.append("campaign positions are not 0..47")

    by_state = {}
    for state in STATES:
        rows = [row for row in batches if row["state"] == state]
        by_state[state] = {
            "batches": len(rows),
            "alert_rate": sum(row["alert"] for row in rows) / len(rows),
            "filldir64_calls_values": sorted({
                value
                for row in transactions if row["state"] == state
                for value in (row["filldir64_calls"],)
            }),
            "suppression_residual_values": sorted({
                value
                for row in transactions if row["state"] == state
                for value in (row["suppression_residual"],)
            }),
        }
    report = {
        "protocol": PROTOCOL,
        "status": "PASS" if not failures else "FAIL",
        "failures": failures,
        "evidence_role": "single_boot_development_pilot_not_confirmatory",
        "batches": len(batches),
        "transactions": len(transactions),
        "state_metrics": by_state,
        "pilot_hiding_recall": by_state.get("hiding", {}).get("alert_rate"),
        "pilot_active_fpr": by_state.get("active", {}).get("alert_rate"),
        "pilot_pass_fpr": by_state.get("pass", {}).get("alert_rate"),
        "pilot_unloaded_fpr": by_state.get("unloaded", {}).get("alert_rate"),
        "decision_rule": (
            "For a double-path listing, suppression_residual = filldir64_calls "
            "- 2 * user_visible_entries; alert iff residual > 0."
        ),
        "scope_warning": (
            "The invariant is specific to the tested CARAXES-like ftrace "
            "callback path and this kernel/probe ordering."
        ),
    }
    args.output.mkdir(parents=True)
    for name, rows in (("batches.csv", batches), ("transactions.csv", transactions)):
        with (args.output / name).open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
            writer.writeheader()
            writer.writerows(sorted(rows, key=lambda row: (
                row["position"], row.get("iteration", -1)
            )))
    (args.output / "report.json").write_text(
        json.dumps(report, indent=2), encoding="utf-8"
    )
    print(json.dumps(report, indent=2))
    if failures:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
