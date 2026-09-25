#!/usr/bin/env python3
"""Audit D7 matched-control mechanism qualification."""

from __future__ import annotations

import argparse
import csv
import gzip
import json
from collections import Counter, defaultdict
from pathlib import Path


PROTOCOL = "D7-mechanism-r1-2026-09-21"
STATES = ("unloaded", "pass", "active", "hiding")
CONDITIONS = ("baseline", "cpu", "memory", "mixed")
CALL_COUNTERS = (
    "fillonedir_calls",
    "filldir_calls",
    "filldir64_calls",
    "compat_fillonedir_calls",
    "compat_filldir_calls",
)


def audit(root: Path) -> tuple[list[dict], dict]:
    manifests = list(root.glob("campaign_*.json"))
    if len(manifests) != 1:
        raise ValueError(f"expected one manifest, got {len(manifests)}")
    manifest = json.loads(manifests[0].read_text(encoding="utf-8"))
    failures: list[str] = []
    if manifest.get("protocol_revision") != PROTOCOL:
        failures.append("protocol mismatch")
    if manifest.get("status") != "complete":
        failures.append("manifest incomplete")
    schedule = manifest.get("schedule", [])
    if len(schedule) != 48 or any(
        item.get("status") != "complete" for item in schedule
    ):
        failures.append("schedule is not 48 complete batches")

    rows = []
    by_position = {}
    for path in root.glob("batch_*.json.gz"):
        with gzip.open(path, "rt", encoding="utf-8") as handle:
            record = json.load(handle)
        position = int(record["collection"]["campaign_position"])
        state = record["d7_control"]["state"]
        deltas = record["d7_control"]["counter_deltas"]
        row = {
            "position": position,
            "state": state,
            "condition": record["truth"]["condition"],
            "valid": bool(record["quality"]["valid_for_analysis"]),
            "exact_output": bool(record["listing_validation"]["exact_output_pass"]),
            "hidden_visible_iterations": int(
                record["listing_validation"]["hidden_visible_iterations"]
            ),
            "total_callback_calls": int(
                record["d7_control"]["total_callback_calls"]
            ),
            "filter_checks": int(deltas["filter_checks"]),
            "filter_matches": int(deltas["filter_matches"]),
            **{name: int(deltas[name]) for name in CALL_COUNTERS},
        }
        rows.append(row)
        if position in by_position:
            failures.append(f"duplicate position {position}")
        by_position[position] = row
    if len(rows) != 48 or set(by_position) != set(range(48)):
        failures.append(f"raw batch/position mismatch: {len(rows)}")

    cell_counts = Counter((row["state"], row["condition"]) for row in rows)
    expected_cells = {
        (state, condition): 3 for state in STATES for condition in CONDITIONS
    }
    if dict(cell_counts) != expected_cells:
        failures.append(f"cell count mismatch: {dict(cell_counts)}")
    for row in rows:
        if not row["valid"] or not row["exact_output"]:
            failures.append(f"invalid batch at position {row['position']}")
        expected_hidden = 0 if row["state"] == "hiding" else 20
        if row["hidden_visible_iterations"] != expected_hidden:
            failures.append(
                f"output semantics mismatch at position {row['position']}"
            )
        if row["state"] == "unloaded":
            if any(row[name] != 0 for name in (*CALL_COUNTERS, "filter_checks", "filter_matches")):
                failures.append(f"unloaded counter nonzero at {row['position']}")
            continue
        if row["total_callback_calls"] <= 0:
            failures.append(f"no callback observed at {row['position']}")
        if row["state"] == "pass":
            if row["filter_checks"] != 0 or row["filter_matches"] != 0:
                failures.append(f"pass filter counter nonzero at {row['position']}")
        else:
            if row["filter_checks"] != row["total_callback_calls"]:
                failures.append(f"filter/callback mismatch at {row['position']}")
            if row["filter_matches"] != 20:
                failures.append(f"expected 20 matches at {row['position']}")

    state_counter_patterns = {
        state: sorted({
            tuple(row[name] for name in CALL_COUNTERS)
            for row in rows if row["state"] == state
        })
        for state in STATES
    }
    invoked_functions = {
        state: [
            name for name in CALL_COUNTERS
            if any(row[name] > 0 for row in rows if row["state"] == state)
        ]
        for state in STATES
    }
    module_patterns = {
        state: state_counter_patterns[state]
        for state in ("pass", "active", "hiding")
    }
    if not (
        module_patterns["pass"]
        == module_patterns["active"]
        == module_patterns["hiding"]
    ):
        failures.append("callback-count patterns differ across module states")

    by_cell: dict[tuple, list[dict]] = defaultdict(list)
    for row in rows:
        by_cell[(row["condition"], row["state"])].append(row)
    cell_summary = {
        f"{condition}:{state}": {
            "batches": len(cell_rows),
            "total_callback_calls": sorted({
                row["total_callback_calls"] for row in cell_rows
            }),
            "filter_checks": sorted({row["filter_checks"] for row in cell_rows}),
            "filter_matches": sorted({row["filter_matches"] for row in cell_rows}),
        }
        for (condition, state), cell_rows in sorted(by_cell.items())
    }
    report = {
        "protocol": PROTOCOL,
        "status": "PASS" if not failures else "FAIL",
        "failures": failures,
        "batches": len(rows),
        "boot_id": manifest.get("boot_id"),
        "cell_counts": {f"{key[0]}:{key[1]}": value for key, value in sorted(cell_counts.items())},
        "invoked_functions": invoked_functions,
        "callback_count_patterns": state_counter_patterns,
        "cell_summary": cell_summary,
        "interpretation": (
            "PASS qualifies callback-path and output-semantic matching only; "
            "it is not detector efficacy evidence"
        ),
    }
    return sorted(rows, key=lambda row: row["position"]), report


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if args.output.exists():
        raise FileExistsError(args.output)
    rows, report = audit(args.input)
    args.output.mkdir(parents=True)
    with (args.output / "batches.csv").open(
        "w", newline="", encoding="utf-8"
    ) as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    (args.output / "report.json").write_text(
        json.dumps(report, indent=2), encoding="utf-8"
    )
    print(json.dumps(report, indent=2))
    if report["status"] != "PASS":
        raise SystemExit(1)


if __name__ == "__main__":
    main()

