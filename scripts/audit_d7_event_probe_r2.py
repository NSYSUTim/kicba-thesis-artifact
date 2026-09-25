#!/usr/bin/env python3
"""Integrity audit for the small D7 event-path diagnostic."""

from __future__ import annotations

import argparse
import csv
import gzip
import json
from collections import Counter
from pathlib import Path


PROTOCOL = "D7-event-probe-r2-2026-09-21"
STATES = ("unloaded", "pass", "active", "hiding")


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
    if len(manifest.get("schedule", [])) != 12:
        failures.append("schedule length is not 12")
    rows = []
    for path in sorted(args.input.glob("batch_*.json.gz")):
        with gzip.open(path, "rt", encoding="utf-8") as handle:
            record = json.load(handle)
        state = record["d7_control"]["state"]
        counts = record["quality"]["target_function_counts"]
        deltas = record["d7_control"]["counter_deltas"]
        row = {
            "position": int(record["collection"]["campaign_position"]),
            "state": state,
            "valid": bool(record["quality"]["valid_for_analysis"]),
            "exact_output": bool(record["listing_validation"]["exact_output_pass"]),
            "hidden_visible_iterations": int(record["listing_validation"]["hidden_visible_iterations"]),
            "lost_events": int(record["collection"]["lost_events"]),
            "iterate_enter": int(counts["iterate_dir"]["enter"]),
            "iterate_return": int(counts["iterate_dir"]["return"]),
            "filldir_enter": int(counts["filldir64"]["enter"]),
            "filldir_return": int(counts["filldir64"]["return"]),
            "wrapper_callbacks": int(record["d7_control"]["total_callback_calls"]),
            "filter_checks": int(deltas["filter_checks"]),
            "filter_matches": int(deltas["filter_matches"]),
        }
        rows.append(row)
        if not row["valid"] or not row["exact_output"] or row["lost_events"]:
            failures.append(f"quality failure at {row['position']}")
        if row["iterate_enter"] != 40 or row["iterate_return"] != 40:
            failures.append(f"iterate count mismatch at {row['position']}")
        if row["filldir_enter"] != row["filldir_return"]:
            failures.append(f"unpaired filldir event at {row['position']}")
        expected_visible = 0 if state == "hiding" else 20
        if row["hidden_visible_iterations"] != expected_visible:
            failures.append(f"output mismatch at {row['position']}")
        if state == "unloaded":
            if any(row[key] for key in ("wrapper_callbacks", "filter_checks", "filter_matches")):
                failures.append(f"unloaded counters nonzero at {row['position']}")
        else:
            if row["wrapper_callbacks"] != 2620:
                failures.append(f"target callback mismatch at {row['position']}")
            if state == "pass":
                if row["filter_checks"] or row["filter_matches"]:
                    failures.append(f"pass filtering counters nonzero at {row['position']}")
            elif row["filter_checks"] != 2620 or row["filter_matches"] != 20:
                failures.append(f"filter counter mismatch at {row['position']}")
    if len(rows) != 12:
        failures.append(f"expected 12 batches, got {len(rows)}")
    state_counts = Counter(row["state"] for row in rows)
    if state_counts != Counter({state: 3 for state in STATES}):
        failures.append(f"state balance mismatch: {dict(state_counts)}")
    if {row["position"] for row in rows} != set(range(12)):
        failures.append("campaign positions are not 0..11")
    report = {
        "protocol": PROTOCOL,
        "status": "PASS" if not failures else "FAIL",
        "failures": failures,
        "batches": len(rows),
        "state_counts": dict(state_counts),
        "bpf_filldir_counts_by_state": {
            state: sorted({row["filldir_enter"] for row in rows if row["state"] == state})
            for state in STATES
        },
        "interpretation": (
            "This audit validates event-path data only; it is not detector efficacy evidence."
        ),
    }
    args.output.mkdir(parents=True)
    with (args.output / "batches.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(sorted(rows, key=lambda row: row["position"]))
    (args.output / "report.json").write_text(
        json.dumps(report, indent=2), encoding="utf-8"
    )
    print(json.dumps(report, indent=2))
    if failures:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
