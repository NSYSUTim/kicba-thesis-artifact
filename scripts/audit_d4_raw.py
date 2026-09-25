#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import gzip
import json
from collections import Counter, defaultdict
from pathlib import Path


def _pairs(events: list[dict], function: str) -> dict[int, list[int]]:
    stacks: dict[int, list[int]] = defaultdict(list)
    durations: dict[int, list[int]] = defaultdict(list)
    for event in sorted(events, key=lambda row: int(row["ts"])):
        if event.get("function") != function:
            continue
        pid = int(event["pid"])
        timestamp = int(event["ts"])
        if event["kind"] == "target_enter":
            stacks[pid].append(timestamp)
        elif event["kind"] == "target_return" and stacks[pid]:
            durations[pid].append(timestamp - stacks[pid].pop())
    if any(stacks.values()):
        raise ValueError(f"unmatched {function} entries")
    return durations


def audit(root: Path) -> tuple[list[dict], dict]:
    paths = sorted(root.rglob("batch_*.json.gz"))
    if not paths:
        raise ValueError(f"no batches below {root}")
    rows: list[dict] = []
    for path in paths:
        with gzip.open(path, "rt", encoding="utf-8") as handle:
            record = json.load(handle)
        quality = record["quality"]
        validation = record["listing_validation"]
        collection = record["collection"]
        factor = record["directory_factor"]
        if record["schema_version"] == 4:
            transactions = record["transaction_durations"]
            iterate = {
                int(item["pid"]): [item["first_raw_wall_ns"]] * int(item["call_count"])
                for item in transactions
                if item["call_count"] is not None
                and item["first_raw_wall_ns"] is not None
                and item["last_raw_wall_ns"] is not None
                and not item["incomplete_start"]
            }
            if len(iterate) != len(transactions):
                iterate = {}
        else:
            iterate = _pairs(record["events"], "iterate_dir")
        call_counts = Counter(len(values) for values in iterate.values())
        rows.append(
            {
                "path": str(path),
                "batch_id": record["batch_id"],
                "schema_version": record["schema_version"],
                "boot_id": record["environment"]["boot_id"],
                "campaign_id": collection.get("campaign_id"),
                "campaign_position": collection.get("campaign_position"),
                "campaign_phase": collection.get("campaign_phase"),
                "label": record["truth"]["label"],
                "condition": record["truth"]["condition"],
                "probe_profile": collection["probe_profile"],
                "iterations": collection["iterations"],
                "visible_cardinality": factor["visible_cardinality"],
                "filename_length": factor["filename_length"],
                "hidden_slot": factor["hidden_slot"],
                "valid": quality["valid_for_analysis"],
                "exact_output_pass": validation["exact_output_pass"],
                "lost_events": collection["lost_events"],
                "iterate_pid_count": len(iterate),
                "iterate_calls": sum(map(len, iterate.values())),
                "iterate_call_count_distribution": json.dumps(
                    {str(key): value for key, value in sorted(call_counts.items())},
                    sort_keys=True,
                ),
                "pids_one_call": call_counts[1],
                "pids_two_calls": call_counts[2],
                "pids_other_calls": sum(
                    count for calls, count in call_counts.items() if calls not in {1, 2}
                ),
                "hidden_visible_iterations": validation["hidden_visible_iterations"],
                "normal_hidden_observed_index": validation[
                    "first_observed_hidden_index"
                ],
            }
        )
    failures = [
        row
        for row in rows
        if not row["valid"]
        or not row["exact_output_pass"]
        or row["lost_events"] != 0
        or row["iterate_pid_count"] != row["iterations"]
    ]
    by_cell: dict[tuple, dict[str, list[dict]]] = defaultdict(
        lambda: defaultdict(list)
    )
    for row in rows:
        cell = (
            row["visible_cardinality"],
            row["filename_length"],
            row["hidden_slot"],
            row["condition"],
        )
        by_cell[cell][row["label"]].append(row)
    role_mismatches = []
    for cell, labels in sorted(by_cell.items()):
        normal = labels.get("normal", [])
        rootkit = labels.get("rootkit", [])
        if not normal or not rootkit:
            role_mismatches.append({"cell": cell, "reason": "missing_label"})
            continue
        normal_patterns = {
            row["iterate_call_count_distribution"] for row in normal
        }
        rootkit_patterns = {
            row["iterate_call_count_distribution"] for row in rootkit
        }
        if normal_patterns != rootkit_patterns:
            role_mismatches.append(
                {
                    "cell": cell,
                    "reason": "iterate_role_presence_differs",
                    "normal_patterns": sorted(normal_patterns),
                    "rootkit_patterns": sorted(rootkit_patterns),
                }
            )
    report = {
        "schema_version": 1,
        "batches": len(rows),
        "boots": len({row["boot_id"] for row in rows}),
        "labels": dict(Counter(row["label"] for row in rows)),
        "conditions": dict(Counter(row["condition"] for row in rows)),
        "all_valid": not failures,
        "failure_count": len(failures),
        "exact_output_pass_count": sum(row["exact_output_pass"] for row in rows),
        "lost_events_total": sum(row["lost_events"] for row in rows),
        "iterate_calls_per_iteration": sorted(
            {
                row["iterate_calls"] / row["iterations"]
                for row in rows
                if row["iterations"]
            }
        ),
        "factor_cells": len(by_cell),
        "role_composition_match": not role_mismatches,
        "role_composition_mismatches": role_mismatches,
        "failure_batch_ids": [row["batch_id"] for row in failures],
    }
    return rows, report


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    rows, report = audit(args.input)
    args.output.mkdir(parents=True, exist_ok=True)
    with (args.output / "batches.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    (args.output / "audit.json").write_text(
        json.dumps(report, indent=2), encoding="utf-8"
    )
    print(json.dumps(report, indent=2))
    if not report["all_valid"] or not report["role_composition_match"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
