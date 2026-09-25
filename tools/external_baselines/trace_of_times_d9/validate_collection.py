#!/usr/bin/env python3
"""Validate the frozen Trace of the Times formal collection artifact."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
from collections import Counter, defaultdict
from pathlib import Path


EXPECTED = {
    (scenario, label): count
    for scenario in (
        "default",
        "file_count",
        "system_load",
        "ls_basic",
        "filename_length",
    )
    for label, count in (("normal", 150), ("rootkit", 100))
}


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def fail(message: str) -> None:
    raise SystemExit(f"INVALID: {message}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--events", type=Path, required=True)
    parser.add_argument("--log", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    records = []
    with args.log.open("r", encoding="utf-8") as stream:
        for line_number, line in enumerate(stream, 1):
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError as error:
                fail(f"malformed JSONL record {line_number}: {error}")

    expected_total = sum(EXPECTED.values())
    if len(records) != expected_total:
        fail(f"log has {len(records)} records; expected {expected_total}")

    disk_files = {
        path.name: path for path in args.events.glob("events_*.json.gz") if path.is_file()
    }
    record_names = [record.get("file") for record in records]
    duplicate_names = sorted(
        name for name, count in Counter(record_names).items() if count != 1
    )
    if duplicate_names:
        fail(f"duplicate filenames in log: {duplicate_names[:5]}")
    if set(record_names) != set(disk_files):
        missing = sorted(set(record_names) - set(disk_files))
        extra = sorted(set(disk_files) - set(record_names))
        fail(f"log/disk mismatch; missing={missing[:5]}, extra={extra[:5]}")

    indices: dict[tuple[str, str], list[int]] = defaultdict(list)
    counts: Counter[tuple[str, str]] = Counter()
    total_events = 0
    elapsed_seconds = 0.0

    for position, record in enumerate(records, 1):
        scenario = record.get("scenario")
        label = record.get("label")
        key = (scenario, label)
        if key not in EXPECTED:
            fail(f"record {position} has unexpected group {key}")

        path = disk_files[record["file"]]
        actual_hash = sha256(path)
        if record.get("sha256") != actual_hash:
            fail(f"hash mismatch for {path.name}")

        try:
            with gzip.open(path, "rt", encoding="utf-8") as stream:
                payload = json.load(stream)
        except Exception as error:
            fail(f"cannot decode {path.name}: {error}")

        events = payload.get("events")
        metadata = record.get("metadata", {})
        if not isinstance(events, list) or not events:
            fail(f"{path.name} has no event samples")
        checks = {
            "label": payload.get("label"),
            "description": payload.get("description"),
            "iterations": payload.get("iterations"),
            "events": len(events),
        }
        expected_metadata = {
            "label": label,
            "description": scenario,
            "iterations": 100,
            "events": len(events),
        }
        if checks != expected_metadata:
            fail(f"payload metadata mismatch for {path.name}: {checks}")
        if any(metadata.get(name) != value for name, value in expected_metadata.items()):
            fail(f"log metadata mismatch for {path.name}")

        command = record.get("command")
        treatment_flag = "--normal" if label == "normal" else "--rootkit"
        if (
            not isinstance(command, list)
            or treatment_flag not in command
            or command[:2] != ["python3", "probing.py"]
            or "--iterations" not in command
            or "100" not in command
        ):
            fail(f"unexpected collection command for record {position}: {command}")

        index = record.get("index")
        if not isinstance(index, int):
            fail(f"record {position} has a non-integer index")
        try:
            elapsed = float(record.get("elapsed_seconds"))
        except (TypeError, ValueError):
            fail(f"record {position} has invalid elapsed time")
        if elapsed <= 0:
            fail(f"record {position} has non-positive elapsed time")

        indices[key].append(index)
        counts[key] += 1
        total_events += len(events)
        elapsed_seconds += elapsed

    for key, expected_count in EXPECTED.items():
        if counts[key] != expected_count:
            fail(f"{key} has {counts[key]} batches; expected {expected_count}")
        expected_indices = list(range(expected_count))
        if sorted(indices[key]) != expected_indices:
            fail(f"{key} indices are not exactly 0..{expected_count - 1}")

    report = {
        "status": "valid",
        "log_sha256": sha256(args.log),
        "records": len(records),
        "files": len(disk_files),
        "listings": len(records) * 100,
        "events": total_events,
        "elapsed_seconds_sum": elapsed_seconds,
        "counts": {
            f"{scenario}/{label}": counts[(scenario, label)]
            for scenario, label in EXPECTED
        },
    }
    encoded = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(encoded, encoding="utf-8")
    print(encoded, end="")


if __name__ == "__main__":
    main()
